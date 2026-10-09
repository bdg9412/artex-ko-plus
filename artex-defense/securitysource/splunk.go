// Package securitysource reads correlated observations from a configured SIEM.
// It never creates alerts, executes caller-supplied SPL, or changes remote rules.
package securitysource

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrInvalid = errors.New("보안 로그 연결 설정이 올바르지 않습니다")

type Config struct {
	BaseURL          string `json:"base_url"`
	Index            string `json:"index"`
	AuditSourcetype  string `json:"audit_sourcetype"`
	AlertSourcetype  string `json:"alert_sourcetype"`
	CorrelationField string `json:"correlation_field"`
	ActionField      string `json:"action_field"`
	TLSFingerprint   string `json:"tls_fingerprint"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}
type Query struct {
	CorrelationID string
	Start, End    time.Time
}
type Event struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	CorrelationID string          `json:"correlation_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Action        string          `json:"action"`
	Raw           json.RawMessage `json:"raw"`
	FileName      string          `json:"file_name,omitempty"`
	Line          int             `json:"line,omitempty"`
}
type Evidence struct {
	Events      []Event           `json:"events"`
	Complete    bool              `json:"complete"`
	CollectedAt time.Time         `json:"collected_at"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	Warnings    []string          `json:"warnings"`
	Upload      *UploadProvenance `json:"upload,omitempty"`
	Diagnostics []Diagnostic      `json:"diagnostics,omitempty"`
}

var sourceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var correlationName = regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`)

const maxResponseBytes = 4 << 20
const maxRows = 200

func Validate(c Config) (Config, error) {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return c, fmt.Errorf("%w: HTTPS 관리 주소만 입력해 주세요 (경로·계정·쿼리 제외)", ErrInvalid)
	}
	if !sourceName.MatchString(c.Index) || !sourceName.MatchString(c.AuditSourcetype) || !sourceName.MatchString(c.AlertSourcetype) || c.AuditSourcetype == c.AlertSourcetype {
		return c, fmt.Errorf("%w: 인덱스와 서로 다른 감사·경보 sourcetype이 필요합니다", ErrInvalid)
	}
	if !fieldName.MatchString(c.CorrelationField) || !fieldName.MatchString(c.ActionField) {
		return c, fmt.Errorf("%w: 상관 ID·조치 필드 이름을 확인해 주세요", ErrInvalid)
	}
	c.TLSFingerprint = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.TLSFingerprint), ":", ""))
	if c.TLSFingerprint != "" {
		b, e := hex.DecodeString(c.TLSFingerprint)
		if e != nil || len(b) != 32 {
			return c, fmt.Errorf("%w: 인증서 SHA-256은 64자리 16진수여야 합니다", ErrInvalid)
		}
	}
	return c, nil
}
func ValidateCredentials(c Credentials) error {
	if c.Token != "" {
		if c.Username != "" || c.Password != "" || len(c.Token) > 8192 || strings.ContainsAny(c.Token, "\r\n\x00") {
			return fmt.Errorf("%w: 토큰 또는 계정 인증 중 하나를 사용해 주세요", ErrInvalid)
		}
		return nil
	}
	if c.Username == "" || c.Password == "" || len(c.Username) > 256 || len(c.Password) > 8192 || strings.ContainsAny(c.Username, ":\r\n\x00") || strings.ContainsRune(c.Password, 0) {
		return fmt.Errorf("%w: 연결 계정과 비밀번호가 필요합니다", ErrInvalid)
	}
	return nil
}

func client(c Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSFingerprint != "" {
		pin, _ := hex.DecodeString(c.TLSFingerprint)
		// A configured exact leaf-certificate pin replaces PKI validation. It
		// does not allow arbitrary self-signed certificates or redirects.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("인증서가 없습니다")
			}
			cert := cs.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			now := time.Now()
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("서버 인증서가 저장된 핀과 일치하지 않거나 만료됐습니다")
			}
			return nil
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func request(ctx context.Context, c Config, auth Credentials, path string, form url.Values) ([]byte, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method = http.MethodPost
		body = strings.NewReader(form.Encode())
	}
	r, e := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if e != nil {
		return nil, errors.New("보안 로그 조회 요청을 만들지 못했습니다")
	}
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
	} else {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Accept", "application/json")
	h := client(c)
	defer h.CloseIdleConnections()
	res, e := h.Do(r)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("Splunk 연결에 실패했습니다. 주소·인증서·네트워크를 확인해 주세요")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Splunk 조회가 HTTP %d로 거절됐습니다. 연결 계정과 검색 권한을 확인해 주세요", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if e != nil {
		return nil, errors.New("Splunk 응답을 끝까지 읽지 못했습니다")
	}
	if len(b) > maxResponseBytes {
		return nil, errors.New("Splunk 응답이 4 MiB를 초과했습니다. 조회 범위를 줄여 주세요")
	}
	return b, nil
}

func Test(ctx context.Context, c Config, auth Credentials) error {
	c, e := Validate(c)
	if e != nil {
		return e
	}
	if e = ValidateCredentials(auth); e != nil {
		return e
	}
	b, e := request(ctx, c, auth, "/services/server/info?output_mode=json", nil)
	if e != nil {
		return e
	}
	var v struct {
		Entry []json.RawMessage `json:"entry"`
	}
	if json.Unmarshal(b, &v) != nil || len(v.Entry) == 0 {
		return errors.New("Splunk 서버 정보 응답을 확인하지 못했습니다")
	}
	return nil
}

func Fetch(ctx context.Context, c Config, auth Credentials, q Query) (*Evidence, error) {
	c, e := Validate(c)
	if e != nil {
		return nil, e
	}
	if e = ValidateCredentials(auth); e != nil {
		return nil, e
	}
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour || q.End.After(time.Now().Add(5*time.Second)) {
		return nil, fmt.Errorf("%w: 실행 식별자 또는 조회 시간 범위를 확인해 주세요 (최대 24시간)", ErrInvalid)
	}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}, WindowStart: q.Start.UTC(), WindowEnd: q.End.UTC()}
	for _, s := range []struct{ kind, st string }{{"audit", c.AuditSourcetype}, {"alert", c.AlertSourcetype}} {
		// Names have restrictive allowlists, and the correlation ID is generated
		// by ARTEX. No free-form query or state-changing command is accepted.
		search := fmt.Sprintf(`search index="%s" sourcetype="%s" | spath | where '%s' = "%s" | head %d`, c.Index, s.st, c.CorrelationField, q.CorrelationID, maxRows+1)
		b, e := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{"search": {search}, "output_mode": {"json"}, "earliest_time": {strconv.FormatFloat(float64(q.Start.UnixNano())/1e9, 'f', 6, 64)}, "latest_time": {strconv.FormatFloat(float64(q.End.UnixNano())/1e9, 'f', 6, 64)}, "preview": {"false"}})
		if e != nil {
			return nil, e
		}
		if e = parseExport(b, s.kind, c, q, out); e != nil {
			return nil, e
		}
	}
	out.CollectedAt = time.Now().UTC()
	return out, nil
}

func field(m map[string]any, name string) any {
	if v, ok := m[name]; ok {
		return v
	}
	var v any = m
	for _, p := range strings.Split(name, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = obj[p]
	}
	return v
}
func textField(v any) string { s, _ := v.(string); return s }
func eventTime(v any) (time.Time, error) {
	s := fmt.Sprint(v)
	if t, e := time.Parse(time.RFC3339Nano, s); e == nil {
		return t.UTC(), nil
	}
	if n, e := strconv.ParseFloat(s, 64); e == nil && n > 0 && n < 1e11 {
		return time.Unix(int64(n), int64((n-math.Floor(n))*1e9)).UTC(), nil
	}
	return time.Time{}, errors.New("시각이 올바르지 않습니다")
}
func parseExport(b []byte, kind string, c Config, q Query, out *Evidence) error {
	scan := bufio.NewScanner(strings.NewReader(string(b)))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	count := 0
	seen := map[string][32]byte{}
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}
		var row struct {
			Result   map[string]any `json:"result"`
			Preview  bool           `json:"preview"`
			Messages []struct {
				Type string `json:"type"`
			} `json:"messages"`
			Error any `json:"error"`
		}
		decoder := json.NewDecoder(strings.NewReader(scan.Text()))
		decoder.UseNumber()
		if decoder.Decode(&row) != nil {
			return errors.New("Splunk 검색 응답 형식이 올바르지 않습니다")
		}
		if row.Error != nil {
			return errors.New("Splunk 검색에 실패했습니다")
		}
		for _, msg := range row.Messages {
			if msg.Type == "ERROR" || msg.Type == "FATAL" {
				return errors.New("Splunk 검색이 완료되지 않았습니다")
			}
			if msg.Type == "WARN" {
				out.Complete = false
				out.Warnings = append(out.Warnings, "Splunk가 검색 경고를 반환했습니다. 누락 여부를 확인해야 합니다")
			}
		}
		if row.Preview {
			out.Complete = false
			continue
		}
		if row.Result == nil {
			if len(row.Messages) == 0 {
				out.Complete = false
				out.Warnings = append(out.Warnings, "검색 결과 형식이 확인되지 않아 판정을 보류합니다")
			}
			continue
		}
		count++
		if count > maxRows {
			out.Complete = false
			out.Warnings = append(out.Warnings, kind+" 검색이 200건을 초과하여 판정을 보류합니다")
			continue
		}
		m := row.Result
		var raw map[string]any
		if s, ok := m["_raw"].(string); ok {
			d := json.NewDecoder(strings.NewReader(s))
			d.UseNumber()
			_ = d.Decode(&raw)
		}
		correlation := field(m, c.CorrelationField)
		if correlation == nil {
			correlation = field(raw, c.CorrelationField)
		}
		t, te := eventTime(m["_time"])
		if textField(correlation) != q.CorrelationID || te != nil || t.Before(q.Start) || !t.Before(q.End) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "실행 식별자 또는 조회 시각이 맞지 않는 이벤트가 반환됐습니다")
			continue
		}
		payload, e := json.Marshal(m)
		if e != nil {
			return errors.New("로그 원문을 보존하지 못했습니다")
		}
		if len(payload) > 128<<10 || strings.Contains(string(payload), `\u0000`) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "보존 한도를 넘거나 지원하지 않는 문자가 있는 이벤트가 제외됐습니다")
			continue
		}
		id := textField(m["_cd"])
		sum := sha256.Sum256(payload)
		if id == "" {
			id = hex.EncodeToString(sum[:])
		}
		id = c.Index + ":" + textField(m["splunk_server"]) + ":" + textField(m["_bkt"]) + ":" + id
		if previous, exists := seen[id]; exists {
			if previous != sum {
				out.Complete = false
				out.Warnings = append(out.Warnings, "같은 이벤트 ID에 서로 다른 근거가 반환되어 판정을 보류합니다")
			}
			continue
		}
		seen[id] = sum
		a := field(m, c.ActionField)
		if a == nil {
			a = field(raw, c.ActionField)
		}
		action := "unknown"
		switch strings.ToLower(textField(a)) {
		case "block", "blocked", "deny", "denied":
			action = "blocked"
		case "allow", "allowed", "pass", "passed":
			action = "allowed"
		}
		out.Events = append(out.Events, Event{ID: id, Kind: kind, CorrelationID: q.CorrelationID, OccurredAt: t, Action: action, Raw: payload})
	}
	if scan.Err() != nil {
		return errors.New("Splunk 검색 응답이 잘렸습니다")
	}
	return nil
}
