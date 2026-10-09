package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// task_metadata.go 의 작업 메타데이터 수정 API 에러 응답을 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.

// TestTaskMetadataErrorConstantsLocalized 는 응답 상수 4종이 전부 한국어임을 단언한다.
// 어느 하나라도 중국어로 되돌리면 이 테스트가 실패한다.
func TestTaskMetadataErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"errTaskMetaRequestTooLarge": errTaskMetaRequestTooLarge,
		"errTaskMetaNoFields":        errTaskMetaNoFields,
		"errTaskMetaNameEmpty":       errTaskMetaNameEmpty,
		"errTaskMetaNameTooLongFmt":  fmt.Sprintf(errTaskMetaNameTooLongFmt, maxTaskNameRunes),
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestUpdateTaskMetadataResponsesLocalized 는 입력 검증 경로 4종을 실제 HTTP 응답 본문까지
// 검사한다. updateTaskMetadata 의 이 4경로(본문 초과·필드 누락·이름 공백·이름 길이 초과)는
// s.m.Task(맵 조회)와 요청 본문만 보고 s.m.UpdateTaskMetadata(DB)를 거치기 전에 반환하므로,
// tasks 맵에 작업 하나만 넣으면 DB 없이 끝까지 돈다. 상수가 응답에 실제로 실리는 연결까지 확인한다.
func TestUpdateTaskMetadataResponsesLocalized(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}}

	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/api/tasks/t1/metadata", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		rec := httptest.NewRecorder()
		s.updateTaskMetadata(rec, req)
		return rec
	}
	errBody := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var resp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("응답 JSON 파싱 실패: %v (본문 %q)", err, rec.Body.String())
		}
		return resp.Error
	}

	cases := []struct {
		name string
		body string
		code int
		want string
	}{
		// 16KB 한도를 넘기는 유효 JSON 본문. MaxBytesReader 가 읽기 도중 한도 초과를 돌려준다.
		{"request_too_large", `{"name":"` + strings.Repeat("a", maxTaskMetadataRequestSize+1024) + `"}`, http.StatusRequestEntityTooLarge, errTaskMetaRequestTooLarge},
		// name·pinned 를 둘 다 빼면 수정할 필드가 없다.
		{"no_fields", `{}`, http.StatusBadRequest, errTaskMetaNoFields},
		{"name_empty", `{"name":"  "}`, http.StatusBadRequest, errTaskMetaNameEmpty},
		{"name_too_long", `{"name":"` + strings.Repeat("가", maxTaskNameRunes+1) + `"}`, http.StatusBadRequest, fmt.Sprintf(errTaskMetaNameTooLongFmt, maxTaskNameRunes)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(c.body)
			if rec.Code != c.code {
				t.Fatalf("상태 코드 = %d, 기대 = %d (본문 %q)", rec.Code, c.code, rec.Body.String())
			}
			if got := errBody(t, rec); got != c.want {
				t.Fatalf("응답 문구 = %q, 기대 = %q", got, c.want)
			}
			assertKoreanError(t, c.name, errBody(t, rec))
		})
	}
}
