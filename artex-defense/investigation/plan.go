package investigation

import (
	"regexp"
	"strings"
)

// BuildPlan uses documented templates. Finding text only selects a family; it
// cannot issue instructions, introduce new URLs, or establish an attack fact.
func BuildPlan(f FindingContext) Plan {
	text := strings.ToLower(f.Name + " " + f.VulnClass + " " + f.Summary)
	family := "generic"
	switch {
	case containsAny(text, "ssrf", "server-side request", "서버 측 요청", "서버측 요청"):
		family = "ssrf"
	case containsAny(text, "remote code", "command injection", "코드 실행", "명령 실행", "명령어 삽입") || regexp.MustCompile(`\brce\b`).MatchString(text):
		family = "code_execution"
	case containsAny(text, "authentication", "credential", "인증 우회", "인증 실패", "계정 탈취", "brute force"):
		family = "authentication"
	case containsAny(text, "information", "disclosure", "exposure", "directory", "listing", "정보 노출", "정보노출", "리스팅", "파일 노출", "/ftp"):
		family = "information_exposure"
	}
	refs := []Reference{
		{Title: "CTID 취약점 매핑 방법론", URL: "https://ctid.mitre.org/mappings/about/methodology/cve-methodology/"},
		{Title: "NIST SP 800-61r3", URL: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf"},
	}
	base := Hypothesis{ID: "path_access", Title: "취약 경로 접근 흔적", Statement: "취약한 경로가 조사 기간에 요청되었을 수 있습니다. 접근 기록만으로 악용 성공이나 침해를 확정하지 않습니다.", Preconditions: []string{"취약점이 조사 당시에도 해당 자산·경로에 존재했는지 확인"}, RequiredLogs: []string{"웹 서버 또는 리버스 프록시 요청 로그"}, RequiredFields: []string{"시각", "대상 자산", "요청 경로"}, Hunt: "선택한 자산·기간·경로와 일치하는 요청을 찾고, 알려진 ARTEX 검증 요청을 별도 표시합니다.", BenignAlternatives: []string{"관리자·사용자의 정상 접근", "승인된 취약점 점검", "검색 엔진이나 모니터링 요청"}, NextSteps: []string{"당시 노출 여부와 접근 통제 설정 확인", "원본 요청의 메서드·세션·응답과 승인된 점검 일정 대조"}, References: refs}
	hs := []Hypothesis{base}
	switch family {
	case "information_exposure":
		hs = append(hs, Hypothesis{ID: "multi_path", Title: "여러 하위 파일에 대한 요청 흐름", Statement: "동일한 로그 출처의 동일 세션 또는 출발지에서 짧은 시간 동안 여러 하위 경로를 요청했을 수 있습니다. 동일 IP는 동일 공격자를 뜻하지 않습니다.", Preconditions: []string{"대상 경로에 여러 파일 또는 하위 자원이 존재", "세션 또는 출발지 필드가 실제 요청 로그에 존재"}, RequiredLogs: []string{"경로별 웹 요청 로그", "전송 완료·응답 바이트 로그"}, RequiredFields: []string{"시각", "요청 경로", "세션 또는 출발지", "대상 자산"}, Hunt: "동일 파일 출처·세션(없으면 출발지)에서 10분 이내 서로 다른 하위 경로 2개 이상이 관측되는지 확인합니다. 경보 중복을 요청 수로 세지 않습니다.", BenignAlternatives: []string{"정상 브라우저의 여러 리소스 로딩", "공유 프록시·NAT", "허가된 수집·백업 작업"}, NextSteps: []string{"요청된 파일 내용과 민감도 확인", "전송 완료·바이트·인증 상태를 확인하여 실제 전달 범위 판단"}, References: refs}, Hypothesis{ID: "exposed_credentials", Title: "노출 정보의 후속 악용 여부", Statement: "노출된 파일에 당시 유효한 자격증명이 실제 포함되어 있었다면 해당 계정의 후속 사용을 조사할 필요가 있습니다.", Preconditions: []string{"노출된 파일의 실제 내용에서 자격증명 확인", "그 자격증명이 조사 당시 유효했는지 확인", "계정 식별자와 인증 로그 확보"}, RequiredLogs: []string{"당시 파일 내용 또는 보존본", "인증·계정 감사 로그"}, RequiredFields: []string{"계정", "인증 시각", "인증 결과", "세션", "출발지"}, Hunt: "확인된 계정을 기준으로 로그인과 권한 변경을 대조합니다. 정보 노출이나 같은 IP만으로 계정 탈취를 추정하지 않습니다.", BenignAlternatives: []string{"계정 소유자의 정상 사용", "이미 폐기된 예시 자격증명"}, NextSteps: []string{"파일 보존본과 인증 로그 확보", "계정 담당자와 활동의 승인 여부 확인"}, References: refs})
	case "authentication":
		hs = append(hs, Hypothesis{ID: "account_misuse", Title: "인증 우회·계정 사용 조사", Statement: "인증 취약점이 실제 악용되었다면 정상 인증 흐름과 다른 세션 발급·권한 사용 흔적이 남았을 수 있습니다.", Preconditions: []string{"취약 인증 경로와 필요한 조건 확인", "계정·세션 감사 로그 확보"}, RequiredLogs: []string{"인증 성공·실패 로그", "세션 발급 및 권한 변경 로그"}, RequiredFields: []string{"계정", "세션", "시각", "인증 결과", "권한"}, Hunt: "취약 경로 요청과 계정 활동을 실제 세션·계정 식별자로 대조하고 승인 여부를 확인합니다.", BenignAlternatives: []string{"정상 로그인 재시도", "SSO·서비스 계정 활동"}, NextSteps: []string{"인증 로그 확보 후 계정 담당자 확인", "권한 변경의 승인 기록 대조"}, References: refs})
	case "code_execution":
		hs = append(hs, Hypothesis{ID: "host_execution", Title: "후속 프로세스·지속성 흔적 조사", Statement: "서버에서 코드가 실제 실행되었다면 웹 프로세스 하위 프로세스와 파일·네트워크 활동을 조사해야 합니다.", Preconditions: []string{"실행 조건과 영향받는 서버 확인", "호스트 감사 또는 EDR 자료 확보"}, RequiredLogs: []string{"EDR·프로세스 생성 로그", "파일 변경·네트워크 연결 로그"}, RequiredFields: []string{"호스트", "프로세스 ID", "부모 프로세스", "명령행", "시각"}, Hunt: "웹 프로세스의 자식 프로세스와 파일·외부 연결을 호스트 식별자로 대조합니다. HTTP 응답으로 코드 실행 성공을 확정하지 않습니다.", BenignAlternatives: []string{"애플리케이션의 정상 외부 명령 실행", "배포·백업·관리 작업"}, NextSteps: []string{"EDR·호스트 원본 증거 확보", "배포 및 관리자 작업 이력 대조"}, References: refs})
	case "ssrf":
		hs = append(hs, Hypothesis{ID: "server_egress", Title: "서버 측 후속 요청 조사", Statement: "서버 측 요청 유도가 실제로 발생했다면 서버에서 나온 연결과 요청 대상의 기록을 조사할 수 있습니다.", Preconditions: []string{"취약 요청과 서버 식별자 확인", "서버 출발 연결 자료 확보"}, RequiredLogs: []string{"서버 DNS·프록시·네트워크 송신 로그", "요청 대상 서비스 접근 로그"}, RequiredFields: []string{"출발 호스트", "목적지", "시각", "요청 ID 또는 프로세스"}, Hunt: "입력 요청과 서버 송신 이벤트를 요청 ID·프로세스·시간으로 대조합니다. 시간 근접만으로 인과관계를 확정하지 않습니다.", BenignAlternatives: []string{"정상 URL 미리보기·웹훅", "정기 서버 간 통신"}, NextSteps: []string{"송신 및 목적지 감사 로그 확보", "민감 대상의 실제 응답·접근 통제 확인"}, References: refs})
	default:
		hs = append(hs, Hypothesis{ID: "impact_review", Title: "취약점 영향과 후속 행동 수동 조사", Statement: "현재 분류에서 후속 공격을 단정할 수 없습니다. 취약점 성립 조건과 영향을 확인한 뒤 필요한 로그를 선택합니다.", Preconditions: []string{"취약점의 실제 성립 조건과 당시 자산 상태 확인"}, RequiredLogs: []string{"애플리케이션 감사 로그", "영향에 맞는 인증 또는 호스트 로그"}, RequiredFields: []string{"자산", "시각", "요청·세션·계정 식별자"}, Hunt: "관측 요청과 실제 영향의 연결을 확인할 자료를 확보합니다.", BenignAlternatives: []string{"정상 기능 사용", "승인된 테스트"}, NextSteps: []string{"취약점 영향 범위 확인", "필요 로그와 필드 구체화"}, References: refs})
	}
	return Plan{EngineVersion: EngineVersion, Method: "근거 기반 조건부 조사 템플릿", Family: family, Summary: "예상 공격 경로와 관측된 행동을 분리하여 조사합니다. 후속 악용은 성립 조건과 별도 증거가 있어야 판단합니다.", Hypotheses: hs, Limitations: []string{"이 계획은 취약점 분류에 맞춘 조사 템플릿이며 LLM 분석 또는 실제 침해 판정이 아닙니다.", "취약점 발견 시점과 과거의 취약 상태는 다를 수 있습니다.", "자동 분석은 대상·경로 접근과 제한적인 다중 경로 요청 흐름을 다룹니다. 인증·호스트·송신 상관분석은 수동 검토가 필요합니다."}}
}
func containsAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
