package securitysource

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxUploadBytes         = 4 << 20
	MaxUploadRecordBytes   = 128 << 10
	MaxUploadRows          = 5000
	MaxUploadEventsPerKind = 200
)

type FileConfig struct {
	Label            string `json:"label"`
	TimestampField   string `json:"timestamp_field"`
	CorrelationField string `json:"correlation_field"`
	ActionField      string `json:"action_field"`
	EventIDField     string `json:"event_id_field"`
}

type UploadFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type FileUpload struct {
	AuditFile        UploadFile  `json:"audit_file"`
	AlertFile        *UploadFile `json:"alert_file"`
	NoAlerts         bool        `json:"no_alerts"`
	CoverageStart    time.Time   `json:"coverage_start"`
	CoverageEnd      time.Time   `json:"coverage_end"`
	CoverageComplete bool        `json:"coverage_complete"`
}

type Diagnostic struct {
	Code           string   `json:"code"`
	Certainty      string   `json:"certainty"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	EventIDs       []string `json:"event_ids,omitempty"`
	FileName       string   `json:"file_name,omitempty"`
	Line           int      `json:"line,omitempty"`
}

type UploadedFileEvidence struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
	Content string `json:"content"`
	Rows    int    `json:"rows"`
}

type UploadStats struct {
	TotalRows       int `json:"total_rows"`
	Matched         int `json:"matched"`
	Unrelated       int `json:"unrelated"`
	OutsideWindow   int `json:"outside_window"`
	InvalidEvents   int `json:"invalid_events"`
	DuplicateEvents int `json:"duplicate_events"`
	Truncated       int `json:"truncated"`
}

type UploadProvenance struct {
	Config           FileConfig             `json:"config"`
	Files            []UploadedFileEvidence `json:"files"`
	CoverageComplete bool                   `json:"coverage_complete"`
	NoAlerts         bool                   `json:"no_alerts"`
	Stats            UploadStats            `json:"stats"`
}

func uploadInvalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }

func ValidateFileConfig(c FileConfig) (FileConfig, error) {
	c.Label = strings.TrimSpace(c.Label)
	if !utf8.ValidString(c.Label) || strings.ContainsRune(c.Label, 0) || utf8.RuneCountInString(c.Label) < 1 || utf8.RuneCountInString(c.Label) > 120 {
		return c, uploadInvalid("파일 증거 이름은 1~120자로 입력해 주세요")
	}
	fields := []struct {
		value    *string
		fallback string
	}{
		{&c.TimestampField, "timestamp"}, {&c.CorrelationField, "artex_verification_id"},
		{&c.ActionField, "action"}, {&c.EventIDField, "id"},
	}
	seen := map[string]bool{}
	for _, item := range fields {
		*item.value = strings.TrimSpace(*item.value)
		if *item.value == "" {
			*item.value = item.fallback
		}
		if !fieldName.MatchString(*item.value) {
			return c, uploadInvalid("필드 이름은 영문·숫자·밑줄·점·하이픈을 사용해 128자 이내로 입력해 주세요")
		}
		if seen[*item.value] {
			return c, uploadInvalid("시각·실행 UUID·조치·이벤트 ID는 서로 다른 필드에 매핑해 주세요")
		}
		seen[*item.value] = true
	}
	return c, nil
}

// ParseUpload treats names and contents only as data. It never opens a path,
// fetches a URL, evaluates a query, or sends log contents to another service.
// Dotted keys use the same literal-key-first lookup as the SIEM connector.
func ParseUpload(c FileConfig, in FileUpload, q Query) (*Evidence, error) {
	c, err := ValidateFileConfig(c)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour || q.End.After(now.Add(5*time.Second)) {
		return nil, uploadInvalid("실행 식별자와 조회 시간 범위를 확인해 주세요 (최대 24시간)")
	}
	if in.CoverageStart.IsZero() || !in.CoverageEnd.After(in.CoverageStart) || in.CoverageEnd.Sub(in.CoverageStart) > 24*time.Hour || in.CoverageEnd.After(now) {
		return nil, uploadInvalid("파일의 수집 구간은 과거의 시작·종료 시각으로 지정해 주세요 (최대 24시간)")
	}
	if in.AlertFile != nil && in.NoAlerts {
		return nil, uploadInvalid("경보 파일 업로드와 경보 없음 확인 중 하나만 선택해 주세요")
	}
	total := len(in.AuditFile.Content)
	if in.AlertFile != nil {
		total += len(in.AlertFile.Content)
	}
	if total > MaxUploadBytes {
		return nil, uploadInvalid("업로드 파일 원문 합계는 4 MiB 이하여야 합니다")
	}
	out := &Evidence{Events: []Event{}, Complete: true, CollectedAt: now, WindowStart: in.CoverageStart.UTC(), WindowEnd: in.CoverageEnd.UTC(), Warnings: []string{}, Diagnostics: []Diagnostic{},
		Upload: &UploadProvenance{Config: c, Files: []UploadedFileEvidence{}, CoverageComplete: in.CoverageComplete, NoAlerts: in.NoAlerts}}
	diagnostic := func(code, message, recommendation string, incomplete bool) {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: code, Certainty: "observed", Message: message, Recommendation: recommendation})
		if incomplete {
			out.Complete = false
			out.Warnings = append(out.Warnings, message)
		}
	}
	if !in.CoverageComplete {
		diagnostic("upload_coverage_unconfirmed", "업로드 로그의 수집 범위 완전성이 확인되지 않았습니다", "해당 시간 구간의 감사·경보 검색 결과를 빠짐없이 내보냈는지 확인하세요", true)
	}
	if in.CoverageStart.After(q.Start) || in.CoverageEnd.Before(q.End) {
		diagnostic("upload_window_incomplete", "파일의 수집 구간이 실행의 전체 조회 구간을 포함하지 않습니다", "실행 시작 30초 전부터 종료 후 대기 구간까지 포함하여 다시 내보내세요", true)
	}
	if in.AlertFile == nil && !in.NoAlerts {
		diagnostic("upload_alert_evidence_missing", "경보 파일 또는 해당 구간의 경보 없음 확인이 없습니다", "같은 UUID와 구간으로 조회한 경보 파일을 올리거나 실제 검색 후 경보 없음을 확인하세요", true)
	}
	if in.NoAlerts {
		diagnostic("upload_no_alerts_attested", "사용자가 해당 구간에 경보가 없음을 명시했습니다", "이 확인은 자동 SIEM 조회 결과가 아닙니다. 검색 조건과 원본 검색 결과를 별도로 확인하세요", false)
	}
	files := []struct {
		kind string
		file UploadFile
	}{{"audit", in.AuditFile}}
	if in.AlertFile != nil {
		files = append(files, struct {
			kind string
			file UploadFile
		}{"alert", *in.AlertFile})
	}
	seen := map[string][32]byte{}
	counts := map[string]int{}
	conflicts, unknownActions := 0, 0
	invalidDetails := 0
	invalidEvent := func(code, file string, line int, fieldName, message string) {
		out.Upload.Stats.InvalidEvents++
		if invalidDetails >= 10 {
			return
		}
		invalidDetails++
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: code, Certainty: "observed", FileName: file, Line: line,
			Message: fmt.Sprintf("필드 %s: %s", fieldName, message), Recommendation: "해당 파일·행의 원문과 실행 당시 필드 매핑을 확인하세요. 이 관측만으로 수집기나 장비 고장을 단정할 수 없습니다"})
	}
	unknownActionIDs := []string{}
	for _, item := range files {
		file := item.file
		if !utf8.ValidString(file.Name) || strings.TrimSpace(file.Name) == "" || len(file.Name) > 255 || strings.ContainsAny(file.Name, "\x00\r\n") {
			return nil, uploadInvalid("파일 이름은 비어 있지 않은 UTF-8 문자열이어야 하며 255바이트 이하여야 합니다")
		}
		if !utf8.ValidString(file.Content) || strings.ContainsRune(file.Content, 0) {
			return nil, uploadInvalid("파일 원문은 NUL 문자가 없는 UTF-8 텍스트여야 합니다")
		}
		sum := sha256.Sum256([]byte(file.Content))
		provenance := UploadedFileEvidence{Kind: item.kind, Name: file.Name, SHA256: hex.EncodeToString(sum[:]), Bytes: len(file.Content), Content: file.Content}
		err := readUploadRows(file, func(fields map[string]any, line int) error {
			provenance.Rows++
			stats := &out.Upload.Stats
			stats.TotalRows++
			if stats.TotalRows > MaxUploadRows {
				return uploadInvalid("파일의 이벤트 합계는 5000개 이하여야 합니다")
			}
			correlationValue := field(fields, c.CorrelationField)
			correlation, ok := correlationValue.(string)
			if correlationValue == nil || ok && correlation == "" {
				invalidEvent("upload_missing_correlation", file.Name, line, c.CorrelationField, "실행 UUID가 없거나 비어 있습니다")
				return nil
			}
			if !ok {
				invalidEvent("upload_invalid_correlation", file.Name, line, c.CorrelationField, "실행 UUID가 문자열이 아닙니다")
				return nil
			}
			if correlation != q.CorrelationID {
				stats.Unrelated++
				return nil
			}
			timestampValue := field(fields, c.TimestampField)
			if timestampValue == nil {
				invalidEvent("upload_missing_timestamp", file.Name, line, c.TimestampField, "이벤트 시각이 없습니다")
				return nil
			}
			occurred, timeErr := eventTime(timestampValue)
			if timeErr != nil {
				invalidEvent("upload_invalid_timestamp", file.Name, line, c.TimestampField, "시각을 RFC 3339 또는 Unix 초로 해석할 수 없습니다")
				return nil
			}
			if occurred.Before(q.Start) || !occurred.Before(q.End) || occurred.Before(in.CoverageStart) || !occurred.Before(in.CoverageEnd) {
				stats.OutsideWindow++
				return nil
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				return uploadInvalid("이벤트 원문을 보존하지 못했습니다")
			}
			if len(raw) > MaxUploadRecordBytes {
				return uploadInvalid("정규화한 이벤트 하나는 128 KiB 이하여야 합니다")
			}
			payloadHash := sha256.Sum256(raw)
			id := ""
			switch value := field(fields, c.EventIDField).(type) {
			case nil:
			case string:
				id = value
			case json.Number:
				id = value.String()
			default:
				invalidEvent("upload_invalid_event_id", file.Name, line, c.EventIDField, "이벤트 ID가 문자열 또는 숫자가 아닙니다")
				return nil
			}
			if id == "" {
				id = "sha256:" + hex.EncodeToString(payloadHash[:])
			}
			if len(id) > 1024 {
				invalidEvent("upload_invalid_event_id", file.Name, line, c.EventIDField, "이벤트 ID가 1024바이트를 넘습니다")
				return nil
			}
			key := item.kind + ":" + id
			if previous, exists := seen[key]; exists {
				stats.DuplicateEvents++
				if previous != payloadHash {
					conflicts++
				}
				return nil
			}
			seen[key] = payloadHash
			if counts[item.kind] >= MaxUploadEventsPerKind {
				stats.Truncated++
				return nil
			}
			action := "unknown"
			switch strings.ToLower(textField(field(fields, c.ActionField))) {
			case "block", "blocked", "deny", "denied":
				action = "blocked"
			case "allow", "allowed", "pass", "passed":
				action = "allowed"
			}
			if item.kind == "audit" && action == "unknown" {
				unknownActions++
				if len(unknownActionIDs) < 20 {
					unknownActionIDs = append(unknownActionIDs, id)
				}
			}
			out.Events = append(out.Events, Event{ID: id, Kind: item.kind, CorrelationID: correlation, OccurredAt: occurred, Action: action, Raw: raw, FileName: file.Name, Line: line})
			counts[item.kind]++
			stats.Matched++
			return nil
		})
		if err != nil {
			return nil, err
		}
		out.Upload.Files = append(out.Upload.Files, provenance)
	}
	if len(out.Upload.Files) == 2 && out.Upload.Files[0].Bytes > 0 && out.Upload.Files[0].SHA256 == out.Upload.Files[1].SHA256 {
		diagnostic("upload_duplicate_sources", "감사 파일과 경보 파일의 원문이 같습니다. 감사 로그의 복사본만으로 탐지 경보를 확인할 수 없습니다", "실제 탐지 시스템에서 별도로 내보낸 경보 파일을 선택하세요. 서로 다른 파일도 출처의 진위까지 자동 검증되지는 않습니다", true)
	}
	stats := out.Upload.Stats
	if stats.InvalidEvents > 0 {
		diagnostic("upload_invalid_events", fmt.Sprintf("UUID·시각·이벤트 ID를 확인할 수 없는 이벤트 %d개가 제외됐습니다", stats.InvalidEvents), "파일 필드 매핑과 시각 형식을 확인하세요. 필드 누락만으로 수집기 고장을 단정할 수 없습니다", true)
	}
	if stats.Unrelated > 0 {
		diagnostic("upload_other_execution", fmt.Sprintf("다른 실행 UUID의 이벤트 %d개가 제외됐습니다", stats.Unrelated), "선택한 실행의 UUID가 원본 요청과 감사·경보 로그에 동일하게 기록됐는지 확인하세요", false)
	}
	if stats.OutsideWindow > 0 {
		diagnostic("upload_outside_window", fmt.Sprintf("조회 또는 파일 수집 구간 밖의 이벤트 %d개가 제외됐습니다", stats.OutsideWindow), "로그 시각·시간대와 실행 및 파일 수집 구간을 확인하세요", false)
	}
	if stats.DuplicateEvents > 0 {
		diagnostic("upload_duplicate_events", fmt.Sprintf("중복 이벤트 ID %d개가 제외됐습니다", stats.DuplicateEvents), "이벤트 ID가 출처 내에서 고유한지 확인하세요. 동일한 원문의 중복은 한 번만 셉니다", false)
	}
	if conflicts > 0 {
		diagnostic("upload_conflicting_events", fmt.Sprintf("같은 이벤트 ID에 서로 다른 원문 %d개가 있어 판정을 보류합니다", conflicts), "충돌한 로그의 원래 출처와 이벤트 식별 필드를 확인하고 고유한 ID로 다시 내보내세요", true)
	}
	if stats.Truncated > 0 {
		diagnostic("upload_event_limit", fmt.Sprintf("종류별 200개 한도를 넘는 이벤트 %d개가 있어 판정을 보류합니다", stats.Truncated), "동일 실행의 로그 범위와 중복 수집 여부를 확인하세요", true)
	}
	if unknownActions > 0 {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: "upload_action_unknown", Certainty: "observed", Message: fmt.Sprintf("감사 이벤트 %d개의 차단·허용 조치를 해석할 수 없습니다", unknownActions), Recommendation: "실제 정책 조치를 기록한 필드를 매핑하세요. HTTP 상태 코드로 차단 여부를 대신 판정하지 않습니다", EventIDs: unknownActionIDs})
	}
	if counts["audit"] == 0 {
		diagnostic("upload_audit_missing", "선택한 실행과 조회 구간에 해당하는 감사 이벤트가 없습니다", "파일 선택·UUID 전달·필드 매핑·시각 구간을 확인하세요. 감사 이벤트 부재만으로 미탐을 판정하지 않습니다", true)
	}
	return out, nil
}

func readUploadRows(file UploadFile, consume func(map[string]any, int) error) error {
	content := strings.TrimPrefix(file.Content, "\ufeff")
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(file.Name))
	if ext == ".csv" {
		return readUploadCSV(content, consume)
	}
	if ext != ".json" && ext != ".jsonl" && ext != ".ndjson" && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		firstLine, _, _ := strings.Cut(trimmed, "\n")
		if !strings.Contains(firstLine, ",") {
			return uploadInvalid("JSON 객체 배열·JSONL 또는 쉼표로 구분된 CSV 파일이 필요합니다")
		}
		return readUploadCSV(content, consume)
	}
	if strings.HasPrefix(trimmed, "[") {
		d := json.NewDecoder(strings.NewReader(content))
		d.UseNumber()
		if _, err := d.Token(); err != nil {
			return uploadInvalid("JSON 배열 문법이 올바르지 않습니다")
		}
		line, lineOffset := 1, 0
		for d.More() {
			start := d.InputOffset()
			rowOffset := int(start)
			for rowOffset < len(content) && strings.ContainsRune(" \r\n\t,", rune(content[rowOffset])) {
				rowOffset++
			}
			line += strings.Count(content[lineOffset:rowOffset], "\n")
			lineOffset = rowOffset
			count := 0
			value, err := readUploadJSONValue(d, 0, &count)
			if err != nil {
				return err
			}
			if d.InputOffset()-start > MaxUploadRecordBytes {
				return uploadInvalid("이벤트 하나는 128 KiB 이하여야 합니다")
			}
			object, ok := value.(map[string]any)
			if !ok {
				return uploadInvalid("JSON 배열의 각 이벤트는 객체여야 합니다")
			}
			if err := consume(object, line); err != nil {
				return err
			}
		}
		if close, err := d.Token(); err != nil || close != json.Delim(']') {
			return uploadInvalid("JSON 배열이 완전하지 않습니다")
		}
		if _, err := d.Token(); err != io.EOF {
			return uploadInvalid("JSON 배열 뒤에 추가 데이터가 있습니다")
		}
		return nil
	}
	scan := bufio.NewScanner(strings.NewReader(content))
	scan.Buffer(make([]byte, 4096), MaxUploadRecordBytes+2)
	for line := 1; scan.Scan(); line++ {
		raw := scan.Text()
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if len(raw) > MaxUploadRecordBytes {
			return uploadInvalid("이벤트 하나는 128 KiB 이하여야 합니다")
		}
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		count := 0
		value, err := readUploadJSONValue(d, 0, &count)
		if err != nil {
			return err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return uploadInvalid("JSONL의 각 행은 JSON 객체여야 합니다")
		}
		if _, err := d.Token(); err != io.EOF {
			return uploadInvalid("JSON 객체 뒤에 추가 데이터가 있습니다")
		}
		if err := consume(object, line); err != nil {
			return err
		}
	}
	if scan.Err() != nil {
		return uploadInvalid("이벤트 하나는 128 KiB 이하여야 하며 완전한 UTF-8 행이어야 합니다")
	}
	return nil
}

func readUploadCSV(content string, consume func(map[string]any, int) error) error {
	r := csv.NewReader(strings.NewReader(content))
	header, err := r.Read()
	if err != nil || len(header) == 0 || r.InputOffset() > MaxUploadRecordBytes || len(header) > 256 {
		return uploadInvalid("CSV 첫 행에는 256개 이하의 고유한 필드 이름이 필요합니다")
	}
	seen := map[string]bool{}
	for _, key := range header {
		if key == "" || len(key) > 128 || seen[key] {
			return uploadInvalid("CSV 필드 이름이 비어 있거나 중복되거나 128바이트를 넘습니다")
		}
		seen[key] = true
	}
	for {
		start := r.InputOffset()
		row, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return uploadInvalid("CSV 인용부호 또는 열 개수가 올바르지 않습니다")
		}
		if r.InputOffset()-start > MaxUploadRecordBytes {
			return uploadInvalid("CSV 이벤트 하나는 128 KiB 이하여야 합니다")
		}
		line, _ := r.FieldPos(0)
		object := make(map[string]any, len(header))
		for i, key := range header {
			object[key] = row[i]
		}
		if err := consume(object, line); err != nil {
			return err
		}
	}
}

// Reject duplicate keys and decoded NUL before JSONB persistence, and bound
// nesting/values independently from the byte limit. Numbers remain json.Number.
func readUploadJSONValue(d *json.Decoder, depth int, count *int) (any, error) {
	if depth > 16 {
		return nil, uploadInvalid("JSON 중첩은 16단계 이하여야 합니다")
	}
	*count = *count + 1
	if *count > 4096 {
		return nil, uploadInvalid("이벤트의 값은 4096개 이하여야 합니다")
	}
	token, err := d.Token()
	if err != nil {
		return nil, uploadInvalid("JSON 문법이 올바르지 않습니다")
	}
	switch value := token.(type) {
	case json.Delim:
		if value == '{' {
			object := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || len(key) > 128 || strings.ContainsRune(key, 0) {
					return nil, uploadInvalid("JSON 필드 이름은 NUL 없이 128바이트 이하여야 합니다")
				}
				if _, exists := object[key]; exists {
					return nil, uploadInvalid("중복된 JSON 필드 이름은 허용하지 않습니다")
				}
				child, err := readUploadJSONValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if close, err := d.Token(); err != nil || close != json.Delim('}') {
				return nil, uploadInvalid("JSON 객체가 완전하지 않습니다")
			}
			return object, nil
		}
		if value == '[' {
			array := []any{}
			for d.More() {
				child, err := readUploadJSONValue(d, depth+1, count)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if close, err := d.Token(); err != nil || close != json.Delim(']') {
				return nil, uploadInvalid("JSON 배열이 완전하지 않습니다")
			}
			return array, nil
		}
		return nil, uploadInvalid("JSON 값이 올바르지 않습니다")
	case string:
		if strings.ContainsRune(value, 0) || len(value) > MaxUploadRecordBytes {
			return nil, uploadInvalid("JSON 문자열은 NUL 없이 128 KiB 이하여야 합니다")
		}
	case json.Number:
		if len(value) > 256 {
			return nil, uploadInvalid("숫자 값은 256바이트 이하여야 합니다")
		}
		// Preserve decimal precision without admitting exponents that cannot be
		// represented by the evidence store's bounded JSONB numeric type.
		if i := strings.IndexAny(value.String(), "eE"); i >= 0 {
			exponent, err := strconv.Atoi(value.String()[i+1:])
			if err != nil || exponent < -1000 || exponent > 1000 {
				return nil, uploadInvalid("숫자의 지수는 -1000~1000 범위여야 합니다")
			}
		}
	}
	return token, nil
}
