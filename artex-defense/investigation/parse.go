package investigation

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrInvalid = errors.New("침해 조사 입력이 올바르지 않습니다")
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var hostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func invalid(s string) error { return fmt.Errorf("%w: %s", ErrInvalid, s) }
func ValidateScope(s Scope, now time.Time) error {
	if s.Target != strings.TrimSpace(s.Target) || strings.ContainsAny(s.Target, "/?#@\\\r\n\t ") {
		return invalid("대상은 URL 경로 없이 호스트 이름 또는 호스트:포트로 입력하세요")
	}
	if _, _, ok := targetParts(s.Target); !ok {
		return invalid("대상 호스트·포트를 확인하세요")
	}
	if len(s.PathPrefix) > 2048 || (s.PathPrefix != "" && (!strings.HasPrefix(s.PathPrefix, "/") || strings.ContainsAny(s.PathPrefix, "?#%\\\r\n\t\x00"))) {
		return invalid("경로 범위는 /로 시작하는 디코딩된 경로로 입력하세요 (쿼리·프래그먼트 제외)")
	}
	if !utf8.ValidString(s.PathPrefix) {
		return invalid("경로는 UTF-8이어야 합니다")
	}
	if s.Start.IsZero() || !s.End.After(s.Start) || s.End.Sub(s.Start) > 31*24*time.Hour || s.End.After(now) {
		return invalid("조사 구간은 과거의 시작·종료 시각으로 최대 31일입니다")
	}
	return nil
}
func ValidateMapping(m Mapping) error {
	if m.Timestamp == "" {
		return invalid("시각 필드 매핑이 필요합니다")
	}
	seen := map[string]bool{}
	for _, f := range []string{m.Timestamp, m.EventID, m.Target, m.Path, m.SourceIP, m.User, m.Session, m.Action, m.Status, m.Bytes, m.VerificationID, m.EventKind, m.ResponseComplete} {
		if f == "" {
			continue
		}
		if !fieldName.MatchString(f) {
			return invalid("필드 이름은 영문·숫자·밑줄·점·하이픈으로 128자 이내여야 합니다")
		}
		if seen[f] {
			return invalid("서로 다른 의미의 필드를 같은 원본 필드에 매핑할 수 없습니다")
		}
		seen[f] = true
	}
	return nil
}
func targetParts(value string) (string, string, bool) {
	if strings.ContainsAny(value, "\r\n\t \\") || len(value) > 1024 {
		return "", "", false
	}
	u, err := url.Parse("//" + value)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	p := u.Port()
	if net.ParseIP(h) == nil && (!hostName.MatchString(h) || strings.Contains(h, "..")) {
		return "", "", false
	}
	if p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return "", "", false
		}
		p = strconv.Itoa(n)
	}
	if strings.HasSuffix(value, ":") {
		return "", "", false
	}
	return h, p, true
}

// MatchTarget accepts a host/authority or HTTP(S) URL in an event. An explicit
// scope port must also be present (or implied by an event URL's scheme).
func MatchTarget(eventTarget, scopeTarget string) bool {
	h, p, ok := targetParts(scopeTarget)
	if !ok {
		return false
	}
	eh, ep, eok := eventTargetParts(eventTarget)
	return eok && eh == h && (p == "" || ep == p)
}
func eventTargetParts(eventTarget string) (string, string, bool) {
	v := strings.TrimSpace(eventTarget)
	scheme := ""
	if strings.Contains(v, "://") {
		u, e := url.Parse(v)
		if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", "", false
		}
		v = u.Host
		scheme = u.Scheme
	}
	eh, ep, eok := targetParts(v)
	if !eok {
		return "", "", false
	}
	if ep == "" {
		if scheme == "http" {
			ep = "80"
		}
		if scheme == "https" {
			ep = "443"
		}
	}
	return eh, ep, true
}
func normalizedPath(path string) (string, bool) {
	if strings.Contains(path, "://") {
		u, e := url.Parse(path)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", false
		}
		path = u.EscapedPath()
	}
	path = strings.SplitN(strings.SplitN(path, "?", 2)[0], "#", 2)[0]
	p, e := url.PathUnescape(path)
	if e != nil || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n") {
		return "", false
	}
	return p, true
}
func MatchPath(path, prefix string) bool {
	p, ok := normalizedPath(path)
	if !ok {
		return false
	}
	prefix = strings.TrimRight(prefix, "/")
	return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

// ParseFiles keeps original bytes and stable file+row references. Invalid rows
// cannot silently turn a search into "not observed"; limits are explicit errors
// or mark the selected collection incomplete.
func ParseFiles(files []InputFile, s Scope, m Mapping, coverageConfirmed, targetScopeConfirmed bool, knownVerificationIDs []string) (Collection, error) {
	out := Collection{SourceKind: "file", CollectedAt: time.Now().UTC(), Scope: s, Mapping: m, CoverageConfirmed: coverageConfirmed, TargetScopeConfirmed: targetScopeConfirmed, Events: []Event{}, Files: []FileEvidence{}, Complete: coverageConfirmed, Warnings: []string{}}
	if err := ValidateScope(s, out.CollectedAt); err != nil {
		return out, err
	}
	if err := ValidateMapping(m); err != nil {
		return out, err
	}
	if len(files) < 1 || len(files) > 20 {
		return out, invalid("파일은 1~20개를 선택하세요")
	}
	if !coverageConfirmed {
		out.Warnings = append(out.Warnings, "조사 시간·대상의 전체 조회 결과를 빠짐없이 수집했다는 확인이 없습니다.")
	}
	out.Warnings = append(out.Warnings, "파일의 출처·조회 범위는 업로더의 확인에 의존합니다. 원본 시스템의 검색 조건과 파일을 보관하세요.")
	known := map[string]bool{}
	for _, id := range knownVerificationIDs {
		if id != "" {
			known[strings.ToLower(id)] = true
		}
	}
	total := 0
	names := map[string]bool{}
	hashes := map[string]bool{}
	warn := func(message string) {
		out.Complete = false
		if len(out.Warnings) < 25 {
			out.Warnings = append(out.Warnings, message)
		}
	}
	bad := func(file string, line int, reason string) {
		out.Stats.InvalidEvents++
		warn(fmt.Sprintf("%s:%d %s", file, line, reason))
	}
	for _, f := range files {
		total += len(f.Content)
		if total > MaxUploadBytes {
			return out, invalid("파일 원문 합계는 8 MiB 이하여야 합니다")
		}
		if strings.TrimSpace(f.Name) == "" || len(f.Name) > 255 || !utf8.ValidString(f.Name) || strings.ContainsAny(f.Name, "\x00\r\n") {
			return out, invalid("파일 이름을 확인하세요")
		}
		if names[f.Name] {
			return out, invalid("같은 이름의 파일을 중복 선택할 수 없습니다")
		}
		names[f.Name] = true
		if !utf8.ValidString(f.Content) || strings.ContainsRune(f.Content, 0) {
			return out, invalid("파일은 NUL 문자가 없는 UTF-8 텍스트여야 합니다")
		}
		sum := sha256.Sum256([]byte(f.Content))
		hash := hex.EncodeToString(sum[:])
		if hashes[hash] && strings.TrimSpace(f.Content) != "" {
			return out, invalid("동일한 원문 파일이 중복되었습니다")
		}
		hashes[hash] = true
		fe := FileEvidence{Name: f.Name, SHA256: hash, Bytes: len(f.Content), Content: f.Content}
		err := readRows(f, func(fields map[string]any, raw string, line int) error {
			fe.Rows++
			out.Stats.TotalRows++
			if out.Stats.TotalRows > MaxRows {
				return invalid("파일 이벤트 합계는 10000개 이하여야 합니다")
			}
			// Splunk _raw is evidence, never instructions. A JSON object inside it
			// can supply missing extracted fields, with the same strict parser.
			var fallback map[string]any
			if rawValue, ok := fields["_raw"].(string); ok && strings.HasPrefix(strings.TrimSpace(rawValue), "{") {
				var er error
				fallback, er = decodeObject(rawValue)
				if er != nil {
					bad(f.Name, line, "_raw JSON을 해석할 수 없습니다: "+er.Error())
					return nil
				}
			}
			get := func(key string) any {
				if key == "" {
					return nil
				}
				if v, ok := lookup(fields, key); ok {
					return v
				}
				v, _ := lookup(fallback, key)
				return v
			}
			when, er := parseTime(get(m.Timestamp))
			if er != nil {
				bad(f.Name, line, "시각 필드를 RFC 3339 또는 Unix 초로 해석할 수 없습니다")
				return nil
			}
			if when.Before(s.Start) || !when.Before(s.End) {
				out.Stats.OutsideWindow++
				return nil
			}
			target, ok := textField(get(m.Target))
			if !ok {
				bad(f.Name, line, "대상 필드가 문자열이 아닙니다")
				return nil
			}
			if target == "" {
				out.Stats.MissingTarget++
				if !targetScopeConfirmed {
					bad(f.Name, line, "대상 필드가 없으며 해당 자산만 내보냈다는 확인이 없습니다")
					return nil
				}
			} else {
				if _, _, valid := eventTargetParts(target); !valid {
					bad(f.Name, line, "대상 호스트·URL 형식을 해석할 수 없습니다")
					return nil
				}
				if !MatchTarget(target, s.Target) {
					out.Stats.UnrelatedTarget++
					return nil
				}
			}
			path, ok := textField(get(m.Path))
			if !ok {
				bad(f.Name, line, "요청 경로가 문자열이 아닙니다")
				return nil
			}
			if path == "" && s.PathPrefix != "" {
				bad(f.Name, line, "경로 범위 확인에 필요한 요청 경로가 없습니다")
				return nil
			}
			if path != "" {
				if _, valid := normalizedPath(path); !valid {
					bad(f.Name, line, "요청 경로를 해석할 수 없습니다")
					return nil
				}
				if !MatchPath(path, s.PathPrefix) {
					out.Stats.UnrelatedPath++
					return nil
				}
			}
			fieldsText := []string{m.EventID, m.SourceIP, m.User, m.Session, m.Action, m.Status, m.VerificationID, m.EventKind}
			values := make([]string, len(fieldsText))
			for i, key := range fieldsText {
				values[i], ok = scalar(get(key))
				if !ok || len(values[i]) > 4096 {
					bad(f.Name, line, "선택 필드 "+key+" 값을 해석할 수 없습니다")
					return nil
				}
			}
			ref := fmt.Sprintf("%s:%d", hash, fe.Rows)
			id := values[0]
			if id == "" {
				id = ref
			}
			st, stOK := textField(fields["sourcetype"])
			src, srcOK := textField(fields["source"])
			host, hostOK := textField(fields["host"])
			index, indexOK := textField(fields["index"])
			if !stOK || !srcOK || !hostOK || !indexOK {
				bad(f.Name, line, "로그 출처 메타데이터가 문자열이 아닙니다")
				return nil
			}
			sourceKey, _ := json.Marshal([]string{f.Name, st, src, host, index})
			source := string(sourceKey)
			e := Event{Ref: ref, ID: id, Timestamp: when, Target: target, Path: path, SourceIP: values[1], User: values[2], Session: values[3], Action: values[4], Status: values[5], VerificationID: values[6], EventKind: strings.ToLower(values[7]), FileName: f.Name, Source: source, Line: line, Raw: raw}
			if b := get(m.Bytes); b != nil && b != "" {
				bv, valid := scalar(b)
				n, er := strconv.ParseInt(bv, 10, 64)
				if !valid || er != nil || n < 0 {
					bad(f.Name, line, "전송 바이트 필드가 음이 아닌 정수가 아닙니다")
					return nil
				}
				e.Bytes = &n
			}
			if b := get(m.ResponseComplete); b != nil && b != "" {
				var val bool
				switch v := b.(type) {
				case bool:
					val = v
				case string:
					var er error
					val, er = strconv.ParseBool(v)
					if er != nil {
						bad(f.Name, line, "응답 완료 필드를 불리언으로 해석할 수 없습니다")
						return nil
					}
				default:
					bad(f.Name, line, "응답 완료 필드를 불리언으로 해석할 수 없습니다")
					return nil
				}
				e.ResponseComplete = &val
			}
			if e.VerificationID != "" {
				if known[strings.ToLower(e.VerificationID)] {
					e.KnownARTEX = true
					out.Stats.KnownARTEX++
				} else {
					out.Stats.UnrecognizedMarkers++
				}
			}
			if len(out.Events) >= MaxEvents {
				out.Stats.Truncated++
				out.Complete = false
				return nil
			}
			out.Events = append(out.Events, e)
			out.Stats.Selected++
			return nil
		})
		if err != nil {
			return out, fmt.Errorf("%w (%s)", err, f.Name)
		}
		out.Files = append(out.Files, fe)
	}
	if out.Stats.Truncated > 0 {
		warn(fmt.Sprintf("선택 이벤트 한도 2000건을 초과해 %d건은 분석에 포함되지 않았습니다. 기간·경로를 좁혀 다시 수집하세요.", out.Stats.Truncated))
	}
	if out.Stats.MissingTarget > 0 && targetScopeConfirmed {
		out.Warnings = append(out.Warnings, "대상 필드가 없는 이벤트는 업로더가 확인한 자산 범위를 사용합니다. 이벤트 자체로 자산이 검증된 것은 아닙니다.")
	}
	if out.Stats.UnrecognizedMarkers > 0 {
		out.Warnings = append(out.Warnings, "알려진 ARTEX 실행과 일치하지 않는 검증 표식이 있습니다. 표식만으로 점검 트래픽에서 제외하지 않았습니다.")
	}
	return out, nil
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	default:
		return "", false
	}
}
func textField(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}
func lookup(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	var v any = m
	for _, p := range strings.Split(key, ".") {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return v, true
}
func parseTime(v any) (time.Time, error) {
	s, ok := scalar(v)
	if !ok || s == "" {
		return time.Time{}, errors.New("missing")
	}
	if t, e := time.Parse(time.RFC3339Nano, s); e == nil {
		return t.UTC(), nil
	}
	n, e := strconv.ParseFloat(s, 64)
	if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 253402300799 {
		return time.Time{}, errors.New("timestamp")
	}
	whole, frac := math.Modf(n)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC(), nil
}

func readRows(f InputFile, visit func(map[string]any, string, int) error) error {
	content := strings.TrimPrefix(f.Content, "\ufeff")
	trim := strings.TrimSpace(content)
	if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
		r := csv.NewReader(strings.NewReader(content))
		header, e := r.Read()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return invalid("CSV 헤더를 읽을 수 없습니다")
		}
		seen := map[string]bool{}
		for _, h := range header {
			if h == "" || seen[h] {
				return invalid("CSV 헤더에 빈 필드 또는 중복 필드가 있습니다")
			}
			seen[h] = true
		}
		for {
			start := r.InputOffset()
			row, e := r.Read()
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return invalid("CSV 행 형식이 올바르지 않습니다")
			}
			end := r.InputOffset()
			if end-start > MaxRecordBytes {
				return invalid("이벤트 하나는 128 KiB 이하여야 합니다")
			}
			line, _ := r.FieldPos(0)
			fields := map[string]any{}
			for i, v := range row {
				fields[header[i]] = v
			}
			if e = visit(fields, content[start:end], line); e != nil {
				return e
			}
		}
	}
	if strings.HasPrefix(trim, "[") {
		d := json.NewDecoder(strings.NewReader(content))
		d.UseNumber()
		if _, e := d.Token(); e != nil {
			return invalid("JSON 배열을 읽을 수 없습니다")
		}
		for d.More() {
			start := d.InputOffset()
			var raw json.RawMessage
			if e := d.Decode(&raw); e != nil {
				return invalid("JSON 배열 항목이 올바르지 않습니다")
			}
			if len(raw) > MaxRecordBytes {
				return invalid("이벤트 하나는 128 KiB 이하여야 합니다")
			}
			fields, e := decodeObject(string(raw))
			if e != nil {
				return invalid(e.Error())
			}
			prefix := content[:start]
			line := strings.Count(prefix, "\n") + 1
			between := content[start:d.InputOffset()]
			i := strings.Index(between, "{")
			if i >= 0 {
				line += strings.Count(between[:i], "\n")
			}
			if e = visit(fields, string(raw), line); e != nil {
				return e
			}
		}
		if _, e := d.Token(); e != nil {
			return invalid("JSON 배열이 끝나지 않았습니다")
		}
		var extra any
		if e := d.Decode(&extra); e != io.EOF {
			return invalid("JSON 배열 뒤에 추가 내용이 있습니다")
		}
		return nil
	}
	// A formatted single JSON object is accepted as one record. JSONL remains
	// line-oriented so file/line evidence refers to the actual original row.
	if strings.HasPrefix(trim, "{") {
		if fields, e := decodeObject(trim); e == nil {
			if len(trim) > MaxRecordBytes {
				return invalid("이벤트 하나는 128 KiB 이하여야 합니다")
			}
			line := strings.Count(content[:strings.Index(content, "{")], "\n") + 1
			return visit(fields, trim, line)
		}
	}
	scan := bufio.NewScanner(strings.NewReader(content))
	scan.Buffer(make([]byte, 4096), MaxRecordBytes+1)
	line := 0
	for scan.Scan() {
		line++
		raw := scan.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > MaxRecordBytes {
			return invalid("이벤트 하나는 128 KiB 이하여야 합니다")
		}
		fields, e := decodeObject(raw)
		if e != nil {
			return invalid(fmt.Sprintf("%d행 JSON 형식 오류: %s", line, e.Error()))
		}
		if e = visit(fields, raw, line); e != nil {
			return e
		}
	}
	if scan.Err() != nil {
		return invalid("이벤트 하나는 128 KiB 이하여야 합니다")
	}
	return nil
}
func decodeObject(s string) (map[string]any, error) {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("이벤트는 JSON 객체여야 합니다")
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("JSON 객체 뒤에 추가 내용이 있습니다")
	}
	return m, nil
}
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON 중첩 깊이는 64단계 이하여야 합니다")
	}
	t, e := d.Token()
	if e != nil {
		return nil, errors.New("JSON 구문을 해석할 수 없습니다")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			kt, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("JSON 필드 이름이 올바르지 않습니다")
			}
			if _, exists := m[key]; exists {
				return nil, errors.New("중복 JSON 필드가 있습니다: " + key)
			}
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = v
		}
		_, e = d.Token()
		return m, e
	case '[':
		a := []any{}
		for d.More() {
			v, e := decodeValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	default:
		return nil, errors.New("JSON 구분자가 올바르지 않습니다")
	}
}
