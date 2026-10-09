package securitysource

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

// BuildInvestigationSearch generates only a bounded, read-only historical
// search. Its values never become SPL commands or search-language wildcards.
// Time bounds are submitted separately to the export endpoint by the fetcher.
func BuildInvestigationSearch(c Config, scope investigation.Scope, mapping investigation.Mapping, sourcetypes []string) (string, error) {
	c, err := Validate(c)
	if err != nil {
		return "", err
	}
	if err = investigation.ValidateScope(scope, time.Now().UTC()); err != nil {
		return "", err
	}
	if err = investigation.ValidateMapping(mapping); err != nil {
		return "", err
	}
	effectiveMapping := mapping
	effectiveMapping.Timestamp = "_time"
	if err = investigation.ValidateMapping(effectiveMapping); err != nil {
		return "", err
	}
	if mapping.Target == "" || (scope.PathPrefix != "" && mapping.Path == "") {
		return "", fmt.Errorf("%w: Splunk 대상 필드와 경로 범위에 필요한 경로 필드를 매핑해 주세요", ErrInvalid)
	}
	if len(sourcetypes) == 0 {
		sourcetypes = []string{c.AuditSourcetype, c.AlertSourcetype}
	}
	if len(sourcetypes) > 8 {
		return "", fmt.Errorf("%w: 조사 sourcetype은 최대 8개까지 선택할 수 있습니다", ErrInvalid)
	}
	parts := make([]string, 0, len(sourcetypes))
	seen := make(map[string]bool)
	for _, st := range sourcetypes {
		if !sourceName.MatchString(st) || seen[st] {
			return "", fmt.Errorf("%w: 중복 없는 sourcetype 이름을 입력해 주세요", ErrInvalid)
		}
		seen[st] = true
		parts = append(parts, "sourcetype="+investigationLiteral(st))
	}

	// A hostname scope includes all its ports; an explicitly supplied port is
	// retained. The bounded regexp is generated from literal validated values.
	// Hostnames inside full HTTP URLs and ordinary host fields are supported.
	parsedTarget, _ := url.Parse("//" + scope.Target) // Scope validation succeeded.
	host := strings.TrimSuffix(strings.ToLower(parsedTarget.Hostname()), ".")
	port := parsedTarget.Port()
	if port != "" {
		number, _ := strconv.Atoi(port)
		port = strconv.Itoa(number)
	}
	authority := regexp.QuoteMeta(host)
	if strings.Contains(host, ":") {
		authority = `\[` + authority + `\]`
	} else {
		authority += `\.?`
	}
	httpAuthority, httpsAuthority, bareAuthority := authority, authority, authority
	if port == "" {
		httpAuthority += `(?::[0-9]+)?`
		httpsAuthority = httpAuthority
		bareAuthority = httpAuthority
	} else {
		portPattern := `:0*` + port
		bareAuthority += portPattern
		httpAuthority += portPattern
		httpsAuthority += portPattern
		if port == "80" {
			httpAuthority = authority + `(?::0*80)?`
		}
		if port == "443" {
			httpsAuthority = authority + `(?::0*443)?`
		}
	}
	targetPattern := `(?i)^(?:http://` + httpAuthority + `(?:[/?#].*)?|https://` + httpsAuthority + `(?:[/?#].*)?|` + bareAuthority + `)$`
	search := "search index=" + investigationLiteral(c.Index) + " (" + strings.Join(parts, " OR ") + ") | spath | where match(trim(tostring('" + mapping.Target + "')), " + investigationLiteral(targetPattern) + ")"
	if scope.PathPrefix != "" && scope.PathPrefix != "/" {
		prefix := strings.TrimRight(scope.PathPrefix, "/")
		// Decode once, remove URL query/fragment, and compare at a path boundary.
		// Protect literal '+' before urldecode because that function applies
		// query-style decoding whereas the domain parser uses PathUnescape.
		pathExpression := "urldecode(replace(replace(replace(tostring('" + mapping.Path + "'), \"(?i)^https?://[^/?#]*\", \"\"), \"[?#].*$\", \"\"), \"[+]\", \"%2B\"))"
		search += " | where (" + pathExpression + " = " + investigationLiteral(prefix) + " OR substr(" + pathExpression + ", 1, " + strconv.Itoa(len([]rune(prefix))+1) + ") = " + investigationLiteral(prefix+"/") + ")"
	}
	return search + " | head " + strconv.Itoa(investigation.MaxRows+1), nil
}

// SPL eval string literals use backslash escapes. Unlike search terms, regex
// patterns here are built exclusively from quoted values, and substr equality
// treats asterisks, percent signs, and underscores literally.
func investigationLiteral(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\r", `\r`, "\n", `\n`, "\t", `\t`).Replace(value) + `"`
}

// FetchInvestigation performs no writes in Splunk. Existing connection TLS and
// credential restrictions also apply to historical queries; unlike verification
// searches these never require an ARTEX execution UUID.
func FetchInvestigation(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, mapping investigation.Mapping, sourcetypes, knownVerificationIDs []string) (investigation.Collection, error) {
	var empty investigation.Collection
	var err error
	c, err = Validate(c)
	if err != nil {
		return empty, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return empty, err
	}
	search, err := BuildInvestigationSearch(c, scope, mapping, sourcetypes)
	if err != nil {
		return empty, err
	}
	return fetchInvestigationQuery(ctx, c, auth, scope, mapping, knownVerificationIDs, search)
}

// Only locally generated, validated queries reach this private transport helper.
func fetchInvestigationQuery(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, mapping investigation.Mapping, knownVerificationIDs []string, search string) (investigation.Collection, error) {
	var empty investigation.Collection
	// request limits the exact export body to 4 MiB. Keeping both that body and
	// its result-only JSONL remains within the shared 8 MiB evidence bound.
	body, err := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{
		"search": {search}, "output_mode": {"json"}, "preview": {"false"},
		"earliest_time": {investigationEpoch(scope.Start)}, "latest_time": {investigationEpoch(scope.End)},
	})
	if err != nil {
		return empty, err
	}
	results, rows, complete, warnings, err := parseInvestigationExport(body)
	if err != nil {
		return empty, err
	}
	// Splunk's selected time window refers to _time, not arbitrary timestamps
	// inside _raw. Keep the exact returned event and its time/metadata together.
	mapping.Timestamp = "_time"
	out, err := investigation.ParseFiles([]investigation.InputFile{{Name: "splunk-events.jsonl", Content: string(results)}}, scope, mapping, complete, false, knownVerificationIDs)
	if err != nil {
		return empty, err
	}
	out.SourceKind = "splunk"
	out.Query = search
	out.CollectedAt = time.Now().UTC()
	out.CoverageConfirmed = complete
	out.Complete = out.Complete && complete
	for i, warning := range out.Warnings {
		switch warning {
		case "파일의 출처·조회 범위는 업로더의 확인에 의존합니다. 원본 시스템의 검색 조건과 파일을 보관하세요.":
			out.Warnings[i] = "저장된 Splunk 연결에 생성된 검색식을 실행한 결과입니다. 조회 완료가 원본 로그의 보존 기간·수집기 범위까지 보증하지는 않습니다."
		case "조사 시간·대상의 전체 조회 결과를 빠짐없이 수집했다는 확인이 없습니다.":
			out.Warnings[i] = "Splunk 검색 응답의 전체 수집을 확인하지 못했습니다. 검색 진단·결과 한도를 확인하세요."
		}
	}
	out.Warnings = append(out.Warnings, warnings...)
	if rows > investigation.MaxRows {
		out.Stats.Truncated += rows - investigation.MaxRows
	}
	sum := sha256.Sum256(body)
	out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-export.jsonl", SHA256: hex.EncodeToString(sum[:]), Bytes: len(body), Rows: rows, Content: string(body)})
	return out, nil
}

func investigationEpoch(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10) + "." + fmt.Sprintf("%09d", t.Nanosecond())
}

// The exact stream is retained separately. We extract RawMessage result bytes
// without decoding and re-encoding numbers or rewriting upstream field values.
func parseInvestigationExport(body []byte) ([]byte, int, bool, []string, error) {
	var result bytes.Buffer
	rows, complete := 0, true
	warnings := []string{}
	warn := func(message string) {
		complete = false
		for _, existing := range warnings {
			if existing == message {
				return
			}
		}
		warnings = append(warnings, message)
	}
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	lastResultComplete, sawTerminal := false, false
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 {
			continue
		}
		var row struct {
			Result   json.RawMessage `json:"result"`
			Preview  bool            `json:"preview"`
			LastRow  bool            `json:"lastrow"`
			Messages []struct {
				Type string `json:"type"`
			} `json:"messages"`
			Error json.RawMessage `json:"error"`
		}
		if err := decodeInvestigationEnvelope(line, &row); err != nil {
			return nil, 0, false, nil, errors.New("Splunk 과거 로그 응답 형식이 올바르지 않습니다")
		}
		if len(row.Error) != 0 && string(row.Error) != "null" {
			return nil, 0, false, nil, errors.New("Splunk 과거 로그 검색에 실패했습니다")
		}
		for _, message := range row.Messages {
			switch strings.ToUpper(message.Type) {
			case "ERROR", "FATAL":
				return nil, 0, false, nil, errors.New("Splunk 과거 로그 검색이 완료되지 않았습니다")
			case "WARN", "WARNING":
				warn("Splunk가 검색 경고를 반환했습니다. 조회 누락·검색 한도를 확인하세요")
			case "INFO", "DEBUG":
			default:
				warn("Splunk 검색 진단의 종류를 확인하지 못했습니다")
			}
		}
		if row.Preview {
			warn("Splunk가 미리보기 결과를 반환하여 전체 수집을 확인할 수 없습니다")
			continue
		}
		if len(row.Result) == 0 || string(row.Result) == "null" {
			if row.LastRow {
				sawTerminal = true
			} else if len(row.Messages) == 0 {
				warn("Splunk 검색 결과 형식을 확인하지 못한 항목이 있습니다")
			}
			continue
		}
		if row.Result[0] != '{' {
			return nil, 0, false, nil, errors.New("Splunk 과거 로그 이벤트 형식이 올바르지 않습니다")
		}
		rows++
		sawTerminal = false
		lastResultComplete = row.LastRow
		if rows > investigation.MaxRows {
			warn("Splunk 조회가 10,000건을 초과했습니다. 기간 또는 경로를 좁혀 다시 조회하세요")
			continue
		}
		if len(row.Result) > investigation.MaxRecordBytes {
			warn("보존 한도 128 KiB를 초과한 Splunk 이벤트가 분석에서 제외됐습니다")
			continue
		}
		result.Write(row.Result)
		result.WriteByte('\n')
	}
	if err := scan.Err(); err != nil {
		return nil, 0, false, nil, errors.New("Splunk 과거 로그 검색 응답이 잘렸습니다")
	}
	if rows > 0 && !lastResultComplete && !sawTerminal {
		warn("Splunk 검색의 마지막 결과 표시가 없어 조회 완료를 확인하지 못했습니다")
	}
	// A successful empty export is a valid zero-result search. It is not a
	// claim about retained logs, sensor coverage, or whether compromise occurred.
	return result.Bytes(), rows, complete, warnings, nil
}

func decodeInvestigationEnvelope(data []byte, value any) error {
	// Reject ambiguous duplicate envelope keys before normal decoding; source
	// event duplicate-field handling is the shared domain parser's job.
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("invalid envelope")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return errors.New("duplicate envelope key")
		}
		seen[name] = true
		var raw json.RawMessage
		if err = d.Decode(&raw); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("trailing response")
	}
	return json.Unmarshal(data, value)
}
