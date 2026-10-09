package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 인증 응답 문구의 한국어화(백로그 F3b)를 지키는 회귀 방어 테스트다. DB 가 없어도
// 도는 두 경로로 확인한다: ① requireAuth 미들웨어는 pg 를 거치지 않으므로 실제 HTTP
// 응답 본문까지 검사하고, ② 나머지 핸들러 문구는 명명 상수라 상수 자체를 검사한다.
// 한국어 판정은 F3a 가 만든 assertKoreanError 헬퍼(한글 포함·중국어 한자 0)를 재사용한다.

// TestRequireAuthMessagesLocalized 는 토큰이 없거나 잘못됐을 때 requireAuth 가 돌려주는
// 401 응답 본문이 한국어이고 중국어 한자가 없음을 실제 HTTP 핸들러로 확인한다. 이
// 미들웨어는 데이터베이스를 쓰지 않아 DB 없는 환경에서도 끝까지 실행된다.
func TestRequireAuthMessagesLocalized(t *testing.T) {
	s := &Server{jwtKey: []byte(strings.Repeat("k", 32))}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.requireAuth(next)

	cases := []struct {
		name   string
		bearer string
		want   string
	}{
		{"토큰 없음", "", authErrUnauthorized},
		{"토큰 무효", "Bearer not-a-valid-token", authErrTokenInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/tasks", nil)
			if c.bearer != "" {
				r.Header.Set("Authorization", c.bearer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("상태 코드 = %d, 기대 401", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, c.want) {
				t.Errorf("응답 본문에 %q 가 없습니다: %s", c.want, body)
			}
			assertKoreanError(t, c.name, body)
		})
	}
}

// TestAuthErrorConstantsLocalized 는 인증 핸들러가 쓰는 사용자 노출 문구 상수가 모두
// 한글을 포함하고 중국어 한자를 포함하지 않음을 단언한다. requireAuth 로 직접 칠 수
// 없는(= pg 를 거치는) 핸들러의 문구까지 DB 없이 회귀를 잡는다.
func TestAuthErrorConstantsLocalized(t *testing.T) {
	consts := map[string]string{
		"authErrUnauthorized":         authErrUnauthorized,
		"authErrTokenInvalid":         authErrTokenInvalid,
		"authErrPasswordAlreadySet":   authErrPasswordAlreadySet,
		"authErrPasswordEmpty":        authErrPasswordEmpty,
		"authErrNewPasswordEmpty":     authErrNewPasswordEmpty,
		"authErrPasswordHash":         authErrPasswordHash,
		"authErrSaveFailedPrefix":     authErrSaveFailedPrefix,
		"authErrTokenGen":             authErrTokenGen,
		"authErrBadRequest":           authErrBadRequest,
		"authErrPasswordNotInit":      authErrPasswordNotInit,
		"authErrCurrentPasswordWrong": authErrCurrentPasswordWrong,
		"authErrBadCredential":        authErrBadCredential,
	}
	for name, msg := range consts {
		assertKoreanError(t, name, msg)
	}
}
