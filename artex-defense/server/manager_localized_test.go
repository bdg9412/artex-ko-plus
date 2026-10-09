package server

import "testing"

// manager.go 의 워크 에이전트 수 설정 검증 오류 문구를 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를
// 재사용한다. SetWorkers(n<=0) 분기는 m.pg.SetSetting 에 닿기 전에 반환하므로 DB 없는
// 이 호스트에서 빈 Manager 로 실제 구동할 수 있다. 누군가 이 리터럴을 중국어로
// 되돌리면 이 테스트가 실패한다.
//
// 호출 그래프 판정(errWorkersPositive 상수 주석 참조): 이 문구는 설정 PUT 핸들러
// (server.go:3512 → writeErr 400)로만 노출되는 사용자 전용이며, 에이전트 도구(actool)
// 경로가 없어 두뇌 입력이 아니다. 같은 파일 384 행의 기동 복구 오류는 운영자 기동
// 로그 성격이라 F3b 범위 밖(원문 보존)이므로 이 테스트의 대상이 아니다.
func TestSetWorkersErrorLocalized(t *testing.T) {
	err := (&Manager{}).SetWorkers(0)
	if err == nil {
		t.Fatal("워크 에이전트 수 0 은 거부되어야 합니다")
	}
	assertKoreanError(t, "set_workers_nonpositive", err.Error())
}
