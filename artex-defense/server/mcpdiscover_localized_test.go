package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// mcpdiscover.go 의 connectMCP 이 돌려주는 전송 설정 검증 오류 문구를 한국어로 유지하는
// 회귀 방어 테스트다. 네 오류 경로(stdio 명령 누락·http URL 누락·sse URL 누락·알 수 없는
// 전송 방식)는 전부 실제로 서버에 접속(dial)하기 전에 반환되므로, DB·네트워크 없이
// connectMCP 을 직접 호출해 반환 문구까지 검증한다. 한국어 판정은 F3a 가 만든
// assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다. 전송 방식 enum(stdio/http/sse)과
// URL 은 와이어 식별자라 ASCII 로 남으며 한자 판정에 걸리지 않는다. 누군가 이 문구를
// 중국어로 되돌리면 상수 핀 고정과 실제 경로가 함께 실패한다.
func TestConnectMCPErrorsLocalized(t *testing.T) {
	// 상수 핀 고정
	for _, c := range []struct{ label, msg string }{
		{"stdio_no_command", errMCPStdioNoCommand},
		{"http_no_url", errMCPHTTPNoURL},
		{"sse_no_url", errMCPSSENoURL},
		{"unknown_transport", errMCPUnknownTransportFmt},
	} {
		assertKoreanError(t, c.label, c.msg)
	}

	// 실제 경로: 네 거부 분기는 모두 dial 전에 반환한다.
	for _, c := range []struct {
		label string
		srv   *db.MCPServer
	}{
		{"stdio_missing_command", &db.MCPServer{Transport: "stdio", Command: ""}},
		{"http_missing_url", &db.MCPServer{Transport: "http", URL: ""}},
		{"sse_missing_url", &db.MCPServer{Transport: "sse", URL: ""}},
		{"unknown_transport_path", &db.MCPServer{Transport: "websocket"}},
	} {
		_, err := connectMCP(context.Background(), c.srv)
		if err == nil {
			t.Fatalf("%s: 오류가 없습니다(검증을 통과함)", c.label)
		}
		assertKoreanError(t, c.label, err.Error())
	}
}
