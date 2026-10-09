package defenseeval

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

func parseLogs(raw, label string, remaining int) ([]event, error) {
	if !utf8.ValidString(raw) {
		return nil, invalid("%s 로그는 올바른 UTF-8이어야 합니다", label)
	}
	out := []event{}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return out, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if _, err := decoder.Token(); err != nil {
			return nil, invalid("%s 로그 배열을 읽을 수 없습니다", label)
		}
		for decoder.More() {
			if len(out) >= remaining {
				return nil, invalid("로그 이벤트 합계는 2000개 이하여야 합니다")
			}
			start := decoder.InputOffset()
			count := 0
			value, err := readValue(decoder, 0, &count)
			if err != nil {
				return nil, invalid("%s 로그 배열의 %d번째 이벤트: %s", label, len(out)+1, err)
			}
			fields, ok := value.(map[string]any)
			if !ok {
				return nil, invalid("%s 로그의 각 이벤트는 JSON 객체여야 합니다", label)
			}
			if decoder.InputOffset()-start > MaxEventBytes {
				return nil, invalid("이벤트 하나는 128 KiB 이하여야 합니다")
			}
			out = append(out, event{line: len(out) + 1, fields: fields})
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
			return nil, invalid("%s 로그 배열이 완전하지 않습니다", label)
		}
		if err := requireEOF(decoder); err != nil {
			return nil, invalid("%s 로그 배열 뒤에 다른 값이 있습니다", label)
		}
		return out, nil
	}
	for line, text := range strings.Split(raw, "\n") {
		if strings.TrimSpace(text) == "" {
			continue
		}
		if len(out) >= remaining {
			return nil, invalid("로그 이벤트 합계는 2000개 이하여야 합니다")
		}
		if len(text) > MaxEventBytes {
			return nil, invalid("%s 로그 %d행: 이벤트 하나는 128 KiB 이하여야 합니다", label, line+1)
		}
		fields, err := parseObject(text)
		if err != nil {
			return nil, invalid("%s 로그 %d행: %s", label, line+1, err)
		}
		out = append(out, event{line: line + 1, fields: fields})
	}
	return out, nil
}

func parseObject(raw string) (map[string]any, error) {
	if !utf8.ValidString(raw) {
		return nil, fmt.Errorf("올바른 UTF-8이 아닙니다")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	count := 0
	value, err := readValue(decoder, 0, &count)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON 객체가 필요합니다")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	return object, nil
}

func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("JSON 값 뒤에 추가 데이터가 있습니다")
	}
	return nil
}

// Token parsing rejects duplicate keys rather than silently letting a later
// field override evidence, and bounds every event before evaluation.
func readValue(decoder *json.Decoder, depth int, count *int) (any, error) {
	if depth > MaxNestingDepth {
		return nil, fmt.Errorf("JSON 중첩은 16단계 이하여야 합니다")
	}
	*count = *count + 1
	if *count > MaxEventValues {
		return nil, fmt.Errorf("이벤트의 값은 4096개 이하여야 합니다")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("JSON 문법이 올바르지 않습니다")
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || utf8.RuneCountInString(key) > MaxFieldLength {
					return nil, fmt.Errorf("객체 필드 이름은 128자 이하여야 합니다")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("중복된 JSON 필드 이름은 허용하지 않습니다")
				}
				value, err := readValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
				return nil, fmt.Errorf("JSON 객체가 완전하지 않습니다")
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := readValue(decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
				return nil, fmt.Errorf("JSON 배열이 완전하지 않습니다")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("JSON 값이 올바르지 않습니다")
		}
	case string:
		if len(token) > MaxStringBytes {
			return nil, fmt.Errorf("문자열 값은 64 KiB 이하여야 합니다")
		}
		return token, nil
	case json.Number:
		if len(token) > MaxNumberBytes {
			return nil, fmt.Errorf("숫자 값은 256바이트 이하여야 합니다")
		}
		return token, nil
	default:
		return token, nil
	}
}
