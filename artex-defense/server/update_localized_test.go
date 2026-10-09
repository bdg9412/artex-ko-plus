package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F3b(update.go): 셀프 업데이트 엔드포인트의 사용자 노출 문구가 한국어인지 지키는 회귀 테스트.
// 프런트엔드(system/settings 의 update-card)가 progress.message·reason·writeErr 본문을 그대로
// 렌더하므로, 이 문구가 중국어로 되돌아가면 업데이트 화면에 중국어 토스트·진행 메시지가 다시 뜬다.
// assertKoreanError·decodeErrorField 헬퍼는 선행 F3b 테스트 파일(같은 package server)에서 재사용한다.

func TestUpdateMessageConstantsLocalized(t *testing.T) {
	assertKoreanError(t, "updateMsgPreparing", updateMsgPreparing)
	assertKoreanError(t, "updateMsgFailed", updateMsgFailed)
	assertKoreanError(t, "updateMsgStaged", updateMsgStaged)
	assertKoreanError(t, "updateErrInProgress", updateErrInProgress)
	assertKoreanError(t, "updateErrRollbackInProgress", updateErrRollbackInProgress)

	// 형식 문자열 상수는 플레이스홀더를 채운 뒤 검사한다(%q/%s 가 치환되고 한자 0).
	notRelease := fmt.Sprintf(updateErrNotReleaseFmt, "v0.0.0-dev")
	assertKoreanError(t, "updateErrNotReleaseFmt", notRelease)
	if !strings.Contains(notRelease, "v0.0.0-dev") {
		t.Fatalf("updateErrNotReleaseFmt: 버전 플레이스홀더가 치환되지 않았습니다: %q", notRelease)
	}
	latest := fmt.Sprintf(updateErrAlreadyLatestFmt, "v1.2.3")
	assertKoreanError(t, "updateErrAlreadyLatestFmt", latest)
	if !strings.Contains(latest, "v1.2.3") {
		t.Fatalf("updateErrAlreadyLatestFmt: 버전 플레이스홀더가 치환되지 않았습니다: %q", latest)
	}
}

// begin/finish 가 SSE 로 내보내는 진행 메시지가 한국어 상수로 설정되는지 실제 코드 경로로 확인한다.
// 전역 updHub 오염을 피하려 로컬 인스턴스를 쓴다(DB·네트워크 불필요).
func TestUpdateProgressMessagesLocalized(t *testing.T) {
	h := &updateHub{subs: map[chan updateProgress]struct{}{}}

	if !h.begin("v1.2.3") {
		t.Fatal("begin 은 최초 호출에서 true 여야 합니다")
	}
	cur, running := h.snapshot()
	if !running {
		t.Fatal("begin 후 running 이어야 합니다")
	}
	if cur.Message != updateMsgPreparing {
		t.Fatalf("준비 중 메시지 불일치: %q", cur.Message)
	}
	if h.begin("v1.2.4") {
		t.Fatal("진행 중이면 begin 은 false 여야 합니다")
	}

	h.finish(errors.New("다운로드 실패"))
	cur, running = h.snapshot()
	if running {
		t.Fatal("finish 후 running 이 해제돼야 합니다")
	}
	if cur.Message != updateMsgFailed {
		t.Fatalf("실패 메시지 불일치: %q", cur.Message)
	}

	h.finish(nil)
	cur, _ = h.snapshot()
	if cur.Message != updateMsgStaged {
		t.Fatalf("준비 완료 메시지 불일치: %q", cur.Message)
	}
}

// updateRollback 의 "진행 중이라 롤백 불가" 409 응답이 한국어인지 DB 없이 실제 HTTP 로 확인한다.
func TestUpdateRollbackInProgressLocalized(t *testing.T) {
	updHub.mu.Lock()
	prev := updHub.running
	updHub.running = true
	updHub.mu.Unlock()
	defer func() {
		updHub.mu.Lock()
		updHub.running = prev
		updHub.mu.Unlock()
	}()

	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/update/rollback", nil)
	rec := httptest.NewRecorder()
	s.updateRollback(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("상태 코드 409 기대, 실제 %d (본문 %s)", rec.Code, rec.Body.Bytes())
	}
	msg := decodeErrorField(t, rec.Body.Bytes())
	assertKoreanError(t, "updateRollback 진행 중 409", msg)
	if msg != updateErrRollbackInProgress {
		t.Fatalf("롤백 거부 문구 불일치: %q", msg)
	}
}
