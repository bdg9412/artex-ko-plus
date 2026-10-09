# 자율 AI 공격 방어·탐지 가이드

> 이 문서는 ARTEX 와 같은 **자율 AI 침투 에이전트**가 어떻게 동작하는지 방어하는 쪽에서 이해하고, 그 공격을 **탐지하고 차단하는 역량**을 기르기 위한 자료입니다. 공격 방법을 안내하는 문서가 아닙니다. 모든 내용은 자신이 소유하거나 서면으로 명시적 허가를 받은 시스템을 지키는 목적에만 사용하십시오. 권한 없이 타인의 정보통신망을 점검·공격하는 행위는 그 자체로 범죄입니다([상위 README 의 보안·오남용 경고](../README.md) 참조).
>
> English: **[Defense and Detection Guide (defense-en.md)](defense-en.md)**.

자율 AI 공격 도구는 사람 한 명이 붙어 수동으로 돌리던 침투 테스트를, LLM 에이전트가 **스스로 목표를 쪼개고 실제 도구를 실행하며 발견을 축적하는** 24시간 자동 과정으로 바꿉니다. 방어자가 맞서는 상대가 "숙련된 공격자 한 명"에서 "지치지 않고 쉬지 않는 에이전트 군집"으로 바뀌는 셈입니다. 이 가이드는 그 변화가 탐지·대응에 무엇을 요구하는지를 정리합니다.

---

## 1. 자율 AI 공격은 기존 스캐너와 무엇이 다른가

전통적인 취약점 스캐너(예: 고정 시그니처 기반 도구)는 미리 정해진 점검 항목을 순서대로 던지고 끝납니다. ARTEX 류의 자율 에이전트는 구조가 다릅니다. [시스템 아키텍처](../README.md#시스템-아키텍처)에서 설명하듯, 다음 요소가 결합해 **사람 개입 없이 여러 단계의 공격 체인을 완주**합니다.

- **역할이 나뉜 멀티 에이전트.** 목표를 분해하는 `goals`, 다음 방향을 판정해 의도(intent)를 내보내는 `planner`, 의도 하나를 실제 도구로 실행하는 `worker` 여러 개, 사람이 끼어드는 `mainagent` 로 나뉩니다. planner 가 유일한 의도 생성자이고, worker 들이 그 의도를 병렬로 수행합니다.
- **이중 그래프에 상태를 축적.** "무엇이 있는가"(자산 그래프)와 "어디까지 테스트했는가"(탐색 그래프)를 따로 쌓고 앵커로 연결합니다. 그래서 공격이 **점진적으로 깊어지고**, 같은 자산을 다른 각도에서 재방문하며, 앞선 관찰 위에 다음 단계를 세웁니다.
- **이벤트 구동 폐곡선.** 그래프가 바뀔 때마다 planner 가 깨어나 다음 의도를 배정하고, worker 의 쓰기가 다시 다음 라운드를 촉발합니다. 목표가 증명될 때까지 이 순환이 멈추지 않습니다.
- **직렬 공격 체인의 안정적 진행.** planner 는 "주입점 발견 → 인증 정보 획득 → 측면 이동 → 권한 상승" 같은 의존 순서를 공유 todolist 에 한 번만 기록하고, 선행 단계가 충족된 다음 단계에만 의도를 배정합니다. 그래서 무상태 세션 환경에서도 공격 체인이 어긋나지 않고 완주됩니다.
- **LLM 이 맥락마다 페이로드를 변형.** 실행 도구와 페이로드가 코드에 고정된 상수가 아니라 LLM 이 상황을 읽고 생성하는 값이므로, 요청 하나하나의 형태가 조금씩 달라집니다.

### 왜 탐지가 더 어려운가

- **고정 시그니처가 잘 맞지 않습니다.** 페이로드가 맥락마다 바뀌므로, 알려진 악성 문자열을 정확히 일치시키는 방식의 룰(WAF 시그니처)이 비껴가기 쉽습니다.
- **느리게, 그리고 사람처럼 끊어서 진행할 수 있습니다.** 에이전트는 라운드 사이에 쉬고, 발견에 따라 방향을 바꾸므로, 단순히 "짧은 시간에 많은 요청"만 보는 레이트 기반 탐지로는 놓칠 수 있습니다.
- **정찰과 침투가 한 흐름으로 이어집니다.** 사람이 정찰 결과를 보고 며칠 뒤 수동으로 공격하던 간극이 사라져, 최초 접촉부터 자료 반출까지의 시간이 크게 짧아집니다.

### 그래도 탐지할 수 있는 이유: 행동은 숨기기 어렵다

정적 지문(User-Agent, 특정 페이로드 문자열)은 운영자가 마음먹으면 바꿀 수 있습니다. 그러나 **자율 에이전트의 행동 양상**은 공격의 본질이라 바꾸기 어렵습니다. 아래 2~4절은 이 행동 기반 관점에 무게를 둡니다.

- 한 출처가 **여러 단계의 서로 다른 성격의 요청**(정찰 → 열거 → 인증 시도 → 익스플로잇)을 **일관된 세션으로 이어 가는** 패턴.
- 사람이라면 피곤해서 멈출 시간대에도 **끊김 없이 이어지는** 탐색.
- 실패한 응답에서 힌트를 얻어 **다음 요청을 체계적으로 변형**하는, 무작위가 아닌 적응적 진행.

---

## 2. 방어자가 관측할 수 있는 지문 (IoC·시그니처)

지문을 두 관점으로 나눠 봅니다. **(가) 대상(피공격자) 관점**은 내 시스템을 향한 ARTEX 트래픽에서 볼 수 있는 것이고, **(나) 운영자·포렌식 관점**은 ARTEX 가 실제로 돌아간(또는 침해된 중계) 호스트에서 볼 수 있는 것입니다. 둘을 섞지 않는 것이 중요합니다. 대상 쪽에서 보이는 정적 지문은 제한적이고, 행동 지문이 핵심입니다.

### (가) 대상 관점: 내 시스템을 향한 트래픽

- **보강(enrich) 조회의 User-Agent `artex-enrich/1.0`.** ARTEX 는 자산을 자동으로 보강(DNS·HTTP 확인)할 때 이 User-Agent 로 대상에 직접 `GET` 을 보냅니다(`enrich/enrich.go`). 이 경로는 LLM 과 무관하게 ARTEX 가 스스로 생성하며, **리다이렉트를 따라가지 않고, keep-alive 를 끄며, 응답 앞부분만 읽어 `<title>` 을 뽑는** 특징이 있습니다. 기본 동시성은 4 입니다. 따라서 `artex-enrich/1.0` UA 로 **짧은 연결·단발 GET·제목만 읽고 끊는** 조회가 여러 자산에 동시에 들어오면 ARTEX 계열 보강 트래픽을 강하게 시사합니다. 다만 운영자가 UA 를 바꿀 수 있으므로 **부재가 안전을 뜻하지는 않습니다.**
- **본 공격 트래픽은 도구 기본 지문을 따릅니다.** worker 는 실제 도구(Bash 로 실행하는 외부 도구·HTTP)로 요청을 보냅니다. ARTEX 는 이 트래픽을 자체 기록 프록시로 경유시키려고 서브프로세스 환경변수에 `HTTP_PROXY`·프록시 CA 경로를 주입할 뿐, **공격 트래픽에 ARTEX 고유 User-Agent 를 강제하지 않습니다.** 그래서 대상이 보는 User-Agent·헤더는 **그때 실행된 도구의 기본값**(각종 커맨드라인 도구의 기본 UA)입니다. 운영자가 커스텀하지 않았다면 흔한 자동화 도구 지문이 남고, 커스텀했다면 정상 브라우저처럼 위장될 수도 있습니다. 따라서 **단일 UA 매칭에 의존하지 말고 행동 기반 탐지와 결합**해야 합니다.
- **worker 내장 WebFetch 도구는 `norma/0.4` User-Agent 를 남깁니다.** 위의 Bash 실행 외부 도구와 달리, ARTEX 가 norma SDK(`github.com/Autumn-27/norma`)로 직접 수행하는 HTTP 조회(WebFetch 도구)는 그 SDK 의 기본 User-Agent `norma/0.4` 를 공격 단계에 싣습니다. 평문 HTTP 로 오갈 때(또는 TLS 종단 지점에서) 네트워크 선에서 관측되며, [Suricata 규칙 sid 1000003](../detections/suricata/README.ko.md)이 이 접두사(`norma/`)를 잡습니다. 다만 이 UA 는 ARTEX 고유가 아니라 norma SDK 를 쓰는 다른 도구도 함께 쓰므로, `artex-enrich/1.0` 과 마찬가지로 단독 증거가 아니라 보조 단서이고, Bash 로 실행된 도구는 각자의 UA 를 쓰므로 **부재가 안전을 뜻하지 않습니다.**
- **내장 레이트리밋이 없습니다.** ARTEX 자체에는 대상 트래픽 전용 속도 제한이 없고, 요청 속도는 LLM 이 돌리는 외부 도구가 결정합니다. 대신 태스크당 worker 는 기본 3개가 병렬로 돌아, 한 대상에 **여러 의도가 동시에** 진행될 수 있습니다. 즉 "느린 단일 세션"으로도, "여러 각도의 동시 진행"으로도 나타날 수 있어, 고정 임계값 하나로는 잡기 어렵습니다.
- **행동 시그니처(가장 중요).** 아래 패턴의 **동시 출현**이 자율 에이전트를 가리킵니다.
  - 한 출처(또는 소수의 회전 출처)에서 **정찰 → 디렉터리·엔드포인트 열거 → 파라미터 탐침 → 인증·주입 시도**가 **짧은 간격으로 연쇄**.
  - 같은 엔드포인트로 보내되 **응답 코드·길이에 반응해 체계적으로 변형하는** 연속 요청(무작위 퍼징이 아니라 적응적).
  - 사람 운영 시간대를 벗어나 **장시간 끊김 없이** 이어지는 세션.
  - 실패(401/403/429) 이후에도 멈추지 않고 **우회 변형**을 시도하는 끈질김.

### (나) 운영자·포렌식 관점: ARTEX 가 돌아간 호스트

침해 조사에서 중계·경유 호스트에 ARTEX 가 설치·실행된 흔적을 찾을 때 참고합니다.

- **기본 리스닝 포트 `:8787`.** ARTEX 서버의 기본 HTTP 수신 주소입니다(`cmd/artex/main.go`, `--addr` 로 변경 가능). 내부망 호스트가 이 포트에 관리 UI(대시보드·작업·자산 그래프)를 열고 있으면 ARTEX 인스턴스를 의심할 근거입니다.
- **기록형 MITM 프록시 `127.0.0.1:8788`.** worker 의 Bash·HTTP 실행을 가로채 전 과정을 기록하는 로컬 프록시의 기본 주소입니다(`cmd/artex/main.go` 의 `--proxy` 기본값, 루프백 전용). 자체 CA 를 생성해 TLS 를 복호화·기록하므로(`mitmproxy-ca-cert.pem`), 호스트에 **ARTEX 가 설치한 신뢰 CA 인증서**가 있는지, 그리고 서브프로세스에 `HTTP_PROXY`·프록시 CA 경로 환경변수를 주입하는 흔적이 있는지가 단서가 됩니다. 이 주입은 ARTEX 가 생성하는 모든 worker 도구에 들어가고 변수 이름이 소스에 하드코딩이라(`agent/worker.go`), **실행 중인 프로세스가 프록시 변수와 mitmproxy CA 신뢰 변수를 함께 지니는지**는 포트 하나보다 특이적인 지문입니다. [호스트 분류 도구](../detections/triage/README.ko.md)가 `/proc`(또는 포렌식 이미지에서는 캡처한 환경변수 덤프)에서 이 조합을 확인합니다.
- **self-update 콜백 `artex-selfupdate`.** 자가 업데이트가 GitHub 릴리스를 조회할 때 쓰는 User-Agent 입니다(`selfupdate/`). 송신(egress) 로그에서 이 UA 로 코드 저장소 호스트에 나가는 요청이 보이면 ARTEX 바이너리의 존재를 시사합니다.
- **PostgreSQL 상의 이중 그래프.** `exploration_nodes`·`assets`·`companies`·`activity` 같은 테이블과 `agent_prompts` 시드가 있는 DB 는 ARTEX 데이터 저장소의 특징입니다.
- **DB 기반 정규식 승인 규칙과 감사 로그.** 도구 호출을 평가하는 intercept 규칙이 DB 에 저장되고 우선순위대로 정규식으로 평가됩니다(`intercept/`). 차단된 호출은 감사 로그(`GET /api/audit`)에 `【ARTEX 平台管控·非目标防御】` 로 시작하는 통제 프레이밍과 함께 남으므로, 침해 호스트의 감사 기록에서 이 문자열이 보이면 ARTEX 실행을 뒷받침합니다.
- **파괴적 명령 헌팅 지표.** ARTEX 자체 가드가 차단 대상으로 내장한 명령 패턴은 곧 자율 에이전트가 **시도할 수 있는** 명령군의 역상입니다. 호스트 명령 감사에서 아래를 헌팅 지표로 삼으십시오: `rm -rf`, `mkfs`, `dd of=/dev/`, `shred`/`wipe`, SQL `DROP DATABASE`/`DROP TABLE`/`TRUNCATE`, MongoDB `drop`/`dropDatabase`, Redis `FLUSHALL`/`FLUSHDB`, `curl`/`wget` 의 `-X DELETE`, 그리고 `curl … | nc …` 류의 데이터 반출 파이프. 다만 맨 끝의 데이터 반출 파이프는 데이터를 파괴하는 명령이 아니라 밖으로 빼내는 유출 신호라 성격이 다릅니다. 앞의 파괴 패턴과 달리 ARTEX 가드도 이 규칙만은 기본값으로 꺼 둔 채 내장하는데(정상적인 점검용 리버스셸이나 데이터 전송 파이프에 오탐이 잦기 때문입니다), 배포용 파괴 명령 헌팅 규칙([`destructive_command_hunting.yml`](../detections/sigma/destructive_command_hunting.yml))도 파괴 범위에만 한정돼 이 패턴을 포함하지 않으므로, 반출 파이프는 곧바로 차단하지 말고 별도 헌팅 지표로 두어 환경에 맞게 조정하십시오.

> 정리: **대상 쪽 방어는 행동 지문에 걸고, 정적 UA(`artex-enrich/1.0`·`norma/0.4` 등)는 보조 단서로만** 씁니다. 운영자·포렌식 지문(`:8787`·`127.0.0.1:8788`·`artex-selfupdate`·DB 스키마·감사 로그 프레이밍)은 **침해된 경유 호스트를 조사할 때** 유효합니다.

### IP 주소 차단은 왜 약한 1차 방어인가

보안 사건이 알려지면 SNS·커뮤니티에 "공격 IP 목록을 공유하니 방화벽에서 차단하라"는 글이 흔히 돕니다. 공유하는 쪽의 선의와 달리, **출처가 불분명한 비공식 IP 목록을 그대로 차단 규칙에 넣는 것은 권하지 않습니다.** 자율 AI 공격에서는 특히 그렇습니다.

- **출처를 검증하기 어렵습니다.** 개인이 올린 비공식 목록은 누가 어떤 근거로 수집했는지 확인할 방법이 없고, 사건과 무관한 IP 가 섞여 있어도 걸러 낼 수단이 없습니다.
- **금방 낡습니다.** 자율 에이전트는 VPN·클라우드 인스턴스·탈취한 중계 서버를 거쳐 출발 IP 를 수시로 바꿉니다(위 (가) 절의 "소수의 회전 출처"). 어제 관측된 공격 IP 는 오늘 이미 버려졌을 가능성이 높아, 목록을 막아도 공격자는 다른 IP 로 되돌아옵니다.
- **오차단 위험이 큽니다.** 목록에 공유 대역·CDN·정상 클라우드 IP 가 섞여 있으면, 그 IP 를 막는 순간 멀쩡한 고객 트래픽이나 내부 서비스까지 함께 끊깁니다. 자동 차단(아래 6절)과 결합하면 오차단 피해가 더 빠르게 번집니다.

IP 차단 자체가 쓸모없다는 뜻은 아닙니다. **공식 침해지표(IoC)를 대응 기관이나 신뢰할 수 있는 위협 인텔리전스에서 받아, 유효 기간과 오차단 가능성을 검토한 뒤 적용할 때** 비로소 의미가 생깁니다. 그러나 IP 한 줄 차단은 회전하는 출발점을 뒤쫓는 임시 조치일 뿐이고, 오래가는 것은 바꾸기 어려운 **행동**(2~4절의 행동 기반 탐지)과 **공격 표면 축소**(3·5절의 하드닝: 노출 자산 정리·패치·MFA)입니다. "지문은 바꿀 수 있어도 행동은 숨기기 어렵다"는 이 가이드의 전제가 여기서도 그대로 적용됩니다.

---

## 3. 공격자가 노리는 진입점과 하드닝

자율 에이전트는 사람 공격자와 **같은 약점**을 노리되 더 빠르고 집요하게 반복합니다. 아래는 방어 관점의 우선 하드닝 지점입니다.

### 3.1 외부 노출 공격 표면과 알려진(n-day) 취약점

자율 에이전트가 가장 먼저, 그리고 가장 안정적으로 노리는 진입점은 교묘한 0-day 가 아니라 **외부에 노출된 채 패치되지 않은, 이미 알려진 취약점**입니다. 경계 장비(VPN·방화벽), 외부에 열린 관리·운영 콘솔, 애플리케이션 서버·미들웨어·프레임워크(예: 널리 악용되는 WebLogic·Struts 계열), 그리고 **본 서비스가 아니라 제휴·모집·직원용으로 붙은 보조 시스템**이 대표적인 표적입니다. 자율 에이전트는 자산 그래프로 노출 표면을 자동으로 열거한 뒤, 공개 익스플로잇(PoC)이 도는 n-day 를 **패치가 적용되기 전에** 수백 개 자산을 대상으로 동시에 겨냥합니다. 노출된 약점을 찾아 대입하는 이 과정의 속도가 사람 공격자와 비대칭적으로 벌어지는 지점입니다.

- **공격 표면을 줄입니다.** 인터넷에 노출된 자산·관리 콘솔·보조 시스템의 인벤토리를 지속적으로 유지하고, 꼭 외부에 둘 필요가 없는 것은 내부망·VPN·허용 목록 뒤로 옮깁니다.
- **알려진 취약점을 신속히 패치합니다.** 경계 장비·웹서버·애플리케이션 서버·미들웨어의 공개된 취약점(n-day)은 자율 에이전트의 1순위 표적이므로, 공개 PoC 가 도는 구성요소부터 패치 적용 간격을 최대한 짧게 가져갑니다. 어느 것을 먼저 손볼지는 실제 악용이 관측된 취약점을 모아 두는 [CISA KEV(알려진 악용 취약점) 카탈로그](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)를 우선순위 입력으로 삼고, 7.1 의 국내 권고(KISA 보호나라)와 교차 확인하십시오. 특정 CVE 번호를 문서에 고정하기보다 이렇게 갱신되는 공식 목록을 기준으로 삼아야, 자율 에이전트가 새로 도는 n-day 로 표적을 옮겨도 뒤처지지 않습니다.
- **노출이 불가피한 인터페이스를 조입니다.** 외부에 열어 둘 수밖에 없는 관리·운영 인터페이스에는 접근 출처 제한(IP 허용 목록)·MFA·VPN 을 더해, 인증 없는 열거 자체를 막습니다.
- **보조 시스템을 본 서비스와 같은 기준으로 관리합니다.** 제휴·모집·직원용 보조 시스템도 본 서비스와 동일한 패치·모니터링 수준으로 관리합니다. 자율 에이전트가 파고드는 입구는 본 서비스가 아니라 이런 보조 경로인 경우가 많습니다. 인증 흐름 자체의 하드닝은 다음 3.2 로 이어집니다.

탐지 관점에서는, 특정 취약점의 알려진 경로(URL·파라미터)를 겨냥한 요청이 외부에서 짧은 간격으로 연쇄하면 n-day 스캔의 신호입니다. 이 신호는 2절의 행동 지문, 4절의 동일 출처 다단계 상관 규칙과 결합할 때 가장 잘 드러납니다.

### 3.2 보조 인증·본인확인 흐름

부가 서비스·제휴·모집 채널처럼 **본 서비스와 다른 경로로 붙은 인증·본인확인 흐름**은 검증이 느슨한 경우가 많아 우회의 표적이 됩니다. 자율 에이전트는 이런 경로를 자동으로 열거하고, 응답 차이를 읽어 체계적으로 우회 조건을 찾습니다.

- 본인확인·인증 단계를 **본 서비스와 동일한 강도**로 통일하고, 우회 가능한 보조 경로를 전수 점검합니다.
- 인증 상태 전이(비로그인 → 로그인, 일반 → 권한)를 **서버에서 재검증**하고, 클라이언트가 보낸 신뢰 표식(쿠키·헤더·파라미터)을 그대로 믿지 않습니다.
- 본인확인 토큰·일회성 코드의 **수명·재사용·추측 가능성**을 점검합니다.

### 3.3 API 인증·인가 (IDOR·권한 상승)

- 모든 객체 접근에 **서버측 소유권·권한 검사**를 강제합니다(식별자만 바꾸면 남의 자원이 열리는 IDOR 차단).
- 수평·수직 권한 상승 경로를 열거해 봅니다. 자율 에이전트는 식별자를 기계적으로 증감시키며 대량으로 시도하므로, **단건 수동 테스트로는 놓친 구멍**을 금방 찾아냅니다.

### 3.4 자격 증명 스터핑(credential stuffing)

유출된 아이디·비밀번호 목록을 대입하는 공격은 자율 에이전트가 **속도와 분산**으로 증폭합니다.

- 로그인·본인확인 엔드포인트에 **적응형 레이트리밋**(IP·계정·디바이스·행동 기반)을 겁니다.
- **다단계 인증(MFA)** 을 민감 작업에 강제합니다. 스터핑으로 비밀번호가 맞아도 2차 인증이 막습니다.
- **크리덴셜 침해 탐지**(알려진 유출 목록 대조, 비정상 로그인 위치·속도)로 선제 차단합니다.
- 로그인 실패·성공의 **분포 변화**(갑작스러운 저속·광범위 시도)를 경보합니다.

### 3.5 세션·토큰·비밀 관리

- 세션 토큰의 **범위·수명·갱신**을 최소화하고, 민감 전이마다 재인증합니다.
- API 키·내부 토큰을 응답·로그·오류 메시지에 **노출하지 않습니다**(자율 에이전트는 오류 응답에서 단서를 적극 수집).

---

## 4. 탐지 규칙·로그 패턴 (실무)

특정 제품에 종속되지 않는 **의사 규칙** 형태로 적습니다. 자신의 WAF·IPS·SIEM 문법으로 옮겨 쓰십시오. 아래 규칙 가운데 정적 지문에 기반한 것은 바로 배포할 수 있는 [Sigma 규칙(`detections/sigma/`)](../detections/README.ko.md)으로 제공합니다. 핵심인 행동·상관 탐지(4.1·4.2)도 단일 규칙으로 환원되지는 않지만, 이 가운데 ARTEX 코드로 근거를 확인한 행동 지표는 배포 가능한 [Sigma 상관 규칙(`detections/sigma/correlation/`)](../detections/README.ko.md)으로 제공합니다(보강 조회 속도·보강 조회 대상 수·가드 차단 버스트·가드 마커와 파괴적 명령의 동일 호스트 동시 발생). 다만 그 순수 웹 다단계 상관(열거 → 탐침 → 인증)의 트래픽은 단일 ARTEX 고유 UA 로 환원되지 않으므로, 환경별 베이스 규칙이 필요합니다. 이 상관은 아래 4.2 에 바로 배포해 볼 수 있는 일반 행동 기반 Sigma 베이스 템플릿으로 실어 두었으니, 자신의 SIEM 과 기준선에 맞게 조정해 출발점으로 쓰십시오. 네트워크 계층에서 평문 HTTP 로 오갈 때(또는 TLS 종단 지점에서) 관측되는 ARTEX User-Agent 는 두 가지이고, 둘 다 [Suricata 규칙(`detections/suricata/`)](../detections/suricata/README.ko.md)으로 제공합니다. 하나는 enrich 프로브의 `artex-enrich/1.0`(존재 시그니처 sid 1000001·고속 열거 변형 sid 1000002)이고, 다른 하나는 norma SDK WebFetch 도구가 공격 단계에 보내는 `norma/0.4`(sid 1000003)입니다.

### 4.1 WAF·IPS (행동 기반)

- 단일 출처에서 **서로 다른 성격의 요청군**(정적 자원 요청 비중은 낮고, 열거·파라미터 탐침·인증 시도 비중이 높음)이 **한 세션으로** 이어지면 점수를 올립니다.
- 응답 코드·본문 길이에 **반응해 변형되는 연속 요청**(엔트로피는 높되 무작위가 아닌 적응 패턴)을 가중합니다.
- `artex-enrich/1.0` 같은 알려진 자동화 UA 는 **즉시 고위험**으로 태깅하되, UA 부재를 안전으로 해석하지 않습니다.

### 4.2 SIEM 상관 규칙

- **동일 출처 다단계 상관**: 같은 IP/ASN/세션에서 (a) 디렉터리·엔드포인트 열거, (b) 파라미터 탐침, (c) 인증/주입 시도가 **짧은 창 안에 모두** 관측되면 "자율 공격 의심" 경보.
- **시간대 이상**: 서비스의 정상 트래픽 분포를 벗어나 **장시간 끊김 없이** 이어지는 단일 세션.
- **실패 후 지속**: 403/429 를 받고도 멈추지 않고 **우회 변형**을 이어 가는 출처.

위 **동일 출처 다단계 상관**을 바로 배포해 볼 수 있는 베이스 템플릿을 아래에 둡니다. 공격 트래픽에는 ARTEX 고유 User-Agent 가 없으므로, 이 템플릿은 `detections/sigma/` 의 ARTEX 소스 기반 규칙과 달리 **일반 행동 기반 규칙**입니다. 특정 공격 도구의 지문이 아니라 "한 출처가 짧은 창 안에서 열거·탐침·인증을 모두 수행한다"는 행동만 봅니다. 세 하위 규칙과, 한 클라이언트가 시간 창 안에서 셋을 모두 충족할 때만 발화하는 temporal 상관 규칙을 한 파일에 담았습니다.

```yaml
# ── 일반 행동 기반 템플릿 (ARTEX 고유 시그니처가 아님) ──
# 방어 가이드 4.2절의 동일 출처 다단계 웹 패턴(열거 → 탐침 → 인증)입니다.
# ARTEX 공격 트래픽에는 ARTEX 지문이 없으므로, detections/sigma/ 의 규칙과 달리
# ARTEX 소스로 근거를 고정하지 않은 일반 행동 기반 출발점입니다. 필드 이름(SigmaHQ
# 웹서버 분류)과 임계값·시간 창은 자신의 로그와 기준선에 맞게 반드시 조정하십시오.
# 자족형: 세 하위 규칙 + 한 클라이언트가 창 안에서 셋을 모두 충족할 때만 발화하는
# temporal 상관 규칙.
title: Web Endpoint Enumeration Burst From One Source
id: f03c360c-dc33-4a8a-afa8-821b1ff5c4e3
status: experimental
description: |
    Stage 1 of the same-source multi-stage pattern in the ARTEX defense guide section 4.2: a
    burst of endpoint or directory enumeration from a single client, seen as a high rate of 404
    and 400 responses in a short window. This is generic behaviour, not an ARTEX-specific
    signature; tune the count and window to your own baseline. On its own this leg is low signal
    and earns weight only inside the correlation below.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.reconnaissance
    - attack.t1595
logsource:
    category: webserver
detection:
    enum_misses:
        sc-status:
            - 404
            - 400
    condition: enum_misses
falsepositives:
    - Broken links, authorised vulnerability scanners, or misconfigured clients that generate
      many 404 responses.
level: low
---
title: Web Parameter Or Path Injection Probe From One Source
id: f9296e55-6b7a-4030-b5f7-5f7b146233be
status: experimental
description: |
    Stage 2 of the same-source multi-stage pattern: parameter or path probing, matched here as
    query strings carrying common injection or traversal markers. This leg is unavoidably
    signature-like and noisy on its own, so it is scored low and earns weight only inside the
    correlation below. Extend the marker list to your own probe corpus and WAF categories; it is
    a coarse proxy for the broader "adapts requests to responses" behaviour the guide describes.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    probe_markers:
        cs-uri-query|contains:
            - '../'
            - "' or "
            - ' union select '
            - '<script'
            - '; drop '
    condition: probe_markers
falsepositives:
    - Legitimate request payloads that resemble probe markers; tune the marker list to your
      application.
level: low
---
title: Authentication Or Identity-Verification Attempt From One Source
id: 2614cacb-7455-46ad-9af2-7b9633f12d7b
status: experimental
description: |
    Stage 3 of the same-source multi-stage pattern: requests to login, authentication, or
    identity-verification endpoints, or 401 and 403 responses. Map the paths and your own
    authentication-event fields to your application; auxiliary, affiliate, and broker channels
    often expose weaker identity-verification endpoints than the main service and belong here
    too. This leg is broad by design and is only meaningful inside the correlation below.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.credential-access
    - attack.t1110
logsource:
    category: webserver
detection:
    auth_path:
        cs-uri-stem|contains:
            - '/login'
            - '/auth'
            - '/verify'
            - '/otp'
    auth_deny:
        sc-status:
            - 401
            - 403
    condition: auth_path or auth_deny
falsepositives:
    - Ordinary users signing in; this leg is broad and only meaningful inside the correlation.
level: low
---
title: Same-Source Multi-Stage Web Attack (Enumeration, Probe, Auth)
id: 9b7c7b86-702f-42b8-be99-3e60a188ec5b
status: experimental
description: |
    The behaviour-based core of ARTEX defense guide section 4.2 as a deployable template: one
    client runs endpoint enumeration, parameter or path probing, and an authentication or
    identity-verification attempt within the same short window. This is the pattern an autonomous
    agent drives at machine speed and keeps driving past 403 and 429 responses. It is UA-free and
    carries no ARTEX fingerprint, so it is a GENERIC behavioural rule, not one of the
    ARTEX-source-grounded rules under detections/sigma/. Normalise the client field (c-ip, or a
    session identifier if you have one) and tune the window to your baseline. If three legs are
    too strict and miss cases, relax to any two of the three.
references:
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-ko.md
    - https://github.com/jiwoochris/artex-ko/blob/main/docs/defense-en.md
author: artex-ko defense guide (generic template)
date: 2026-10-07
tags:
    - attack.initial-access
    - attack.t1190
correlation:
    type: temporal
    rules:
        - f03c360c-dc33-4a8a-afa8-821b1ff5c4e3
        - f9296e55-6b7a-4030-b5f7-5f7b146233be
        - 2614cacb-7455-46ad-9af2-7b9633f12d7b
    group-by:
        - c-ip
    timespan: 10m
falsepositives:
    - An authorised vulnerability scan or QA run from a single source; allow-list its address.
level: high
```

이 템플릿을 쓸 때 유의할 점입니다.

- 이 블록은 탐지 팩이 쓰는 것과 같은 도구로 검증했습니다. `sigma check` 를 SigmaHQ 규약 전수로 돌려 오류·이슈 0 으로 통과하고, `sigma convert -t splunk` 로 질의가 생성됩니다(세 하위 규칙을 10분 창에서 `c-ip` 로 묶어 셋을 모두 충족하면 발화). 다만 ARTEX 소스로 근거를 고정할 수 없어 `detections/` 의 테스트되는 규칙 트리에는 넣지 않았습니다. 그 트리의 "추정이 아니라 소스에서 확인한 것만 싣는다"는 원칙을 지키기 위함입니다. 이 사실들은 한 번만 재 본 수치가 아닙니다. [`detections/tests/check-defense-template.sh`](../detections/tests/check-defense-template.sh) 가 이 가이드가 바뀔 때마다 CI 에서 다시 돌려(`sigma check` 통과, splunk·eql·loki 변환, lucene·kusto 의 상관 거부, 한국어판·영어판 규칙 본문의 바이트 단위 동일) 확인하므로, 위 주장이 상류 `sigma-cli` 변경으로 조용히 낡는 일을 막습니다.
- 이 템플릿은 상관(correlation) 규칙이라, `sigma convert` 가 템플릿 전체를 내보내는지 아니면 세 하위 규칙만 내보내는지는 백엔드가 Sigma 상관 변환을 지원하는지에 달려 있습니다. 같은 고정 버전(`sigma-cli` 3.1.0)으로 실측하면, 템플릿 전체는 Splunk(`-t splunk`)·Elasticsearch EQL(`-t eql`)·Grafana Loki(`-t loki`)에서 변환됩니다. 반면 Microsoft `kusto` 백엔드(Sentinel·Defender)와 Elasticsearch Lucene(`-t lucene`)에서는 상관 규칙이 변환되지 않으므로(`Backend does not support correlation rules`), 이때는 세 하위 규칙만 변환하고 "10분 창·동일 `c-ip`" 상관은 제품에서 직접 표현하십시오(예: Sentinel 예약 분석 규칙의 `summarize ... by bin(TimeGenerated, 10m), <클라이언트>`). 이는 탐지 팩이 문서화한 이식성과 같으며, 실측 지원 표는 [Sigma 백엔드 이식성](../detections/README.ko.md#sigma-백엔드-이식성)에 정리돼 있습니다.
- 2단계(탐침)는 주입·순회 마커 목록에 기대는 거친 신호라 단독으로는 오탐이 많습니다. 그래서 세 하위 규칙의 `level` 은 낮게 두고, 셋이 한 출처에서 함께 나타나는 상관 규칙에서만 높은 경보가 되게 했습니다.
- 클라이언트는 `c-ip` 로 묶었습니다. 프록시·CDN 뒤라면 `X-Forwarded-For` 로 복원한 실제 클라이언트 주소나 세션 식별자로 바꾸십시오. 세 단계를 모두 요구하는 것이 너무 엄격해 놓치는 사례가 있으면, 셋 중 둘만 충족해도 발화하도록 완화하십시오.

### 4.3 인증 로그

- 계정·IP 당 **로그인 실패율의 급변**, 광범위 계정에 걸친 **저속 분산 시도**(스터핑 특유), 실패에서 성공으로의 **비정상 전이 속도**.
- 본인확인·일회성 코드 엔드포인트에 대한 **열거성 접근**.

### 4.4 송신(egress)·포렌식

- 내부 호스트에서 `artex-selfupdate` UA 로 코드 저장소 호스트에 나가는 요청.
- 내부에서 `:8787`(관리 UI)·`127.0.0.1:8788`(기록 프록시)로 바인딩된 프로세스.
- `artex-enrich/1.0` UA 로 짧은 시간에 대량의 외부 자산을 조회하는 DNS·HTTP 보강 패턴.

---

## 5. 하드닝 체크리스트

방어 조직이 바로 점검할 수 있도록 요약합니다.

- [ ] 로그인·본인확인·민감 API 에 **적응형 레이트리밋**을 적용했다(IP·계정·디바이스·행동).
- [ ] 민감 작업에 **MFA** 를 강제한다.
- [ ] 모든 객체 접근에 **서버측 소유권·권한 검사**가 있다(IDOR 차단).
- [ ] 인증 상태 전이를 **서버에서 재검증**하고 클라이언트 신뢰 표식을 그대로 믿지 않는다.
- [ ] **보조·제휴·모집 채널**의 본인확인 강도를 본 서비스와 통일했다.
- [ ] 유출 자격 증명 **침해 탐지·대조**를 운영한다.
- [ ] WAF 를 **행동 기반 모드**로 운용하고, 고정 시그니처에만 의존하지 않는다.
- [ ] **떠도는 비공식 IP 차단 목록을 그대로 적용하지 않고**, 공식 침해지표(IoC)를 신뢰할 수 있는 출처에서 받아 유효 기간·오차단 위험을 검토한 뒤 반영한다.
- [ ] SIEM 에 **동일 출처 다단계 상관 규칙**을 넣었다.
- [ ] 인증·접근·송신 **로그를 충분한 기간 보존**한다(자율 공격은 빠르므로 사후 추적 자료가 중요).
- [ ] 인터넷에 노출된 자산·관리 콘솔·보조 시스템의 **인벤토리를 유지해 공격 표면을 축소**하고, 경계 장비·애플리케이션 서버·미들웨어의 **알려진(n-day) 취약점을 신속히 패치**한다.
- [ ] 네트워크 **세그멘테이션**으로 측면 이동·권한 상승의 폭발 반경을 줄였다.
- [ ] 비밀(키·토큰)을 **응답·로그·오류 메시지에 노출하지 않는다**.
- [ ] **자동 차단·격리** 대응을 준비했다(사람 승인만 기다리면 자율 공격 속도를 못 따라간다).

---

## 6. 사고 대응 요약

자율 AI 공격의 특징은 **속도**입니다. 한 사람이 1년에 걸쳐 할 침투·반출을 에이전트는 훨씬 짧은 시간에 완주할 수 있습니다. 대응 설계도 이 속도를 전제로 합니다.

- **자동 차단을 선제로.** 의심 출처 격리·세션 무효화·레이트 급감 같은 조치를 사람 승인 전에 **자동 발동**할 수 있게 둡니다. 전부 사람 승인 루프에 묶으면 공격 속도를 못 따라갑니다.
- **보존할 로그를 미리 정합니다.** 인증 로그, 접근 로그(요청 본문 포함 가능 범위), 송신 로그, DNS 질의. 자율 공격은 흔적을 빠르게 쌓으므로, 사후에 공격 체인을 복원하려면 이 자료가 필요합니다.
- **침해 범위를 자산 단위로 추적합니다.** 공격이 자산 그래프를 따라 번지므로, 최초 진입 자산에서 측면 이동·권한 상승으로 이어진 **경로 전체**를 복원해야 재침투를 막습니다.

### 6.1 의심 호스트·트래픽 분류(triage) 절차

ARTEX 연루가 의심될 때 가장 먼저 확인할 것을 순서로 정리합니다. 2절에서 지문을 두 관점으로 나눈 것과 같이, 분류도 **(가) 내 서비스가 표적이 됐는지**와 **(나) 특정 호스트에서 ARTEX 가 돌았는지**로 나눠 봅니다. 어느 단계든 적중 하나만으로 단정하지 말고, 여러 지표와 행동 신호가 함께 나타나는지로 판단합니다. 정적 지표가 전부 없더라도 행동 신호가 보이면 조사를 이어 갑니다.

**(가) 대상 측: 내 서비스가 ARTEX 표적이 됐는지**

1. 접근·인증 로그에서 보강 조회 User-Agent `artex-enrich/1.0` 을 조회합니다. 리다이렉트를 따라가지 않는 단발 `GET` 조회가 짧은 간격으로 여러 자산에 동시에 들어왔는지 확인합니다(2절 (가)). 운영자가 User-Agent 를 바꿀 수 있으므로, 걸리지 않아도 다음 단계로 넘어갑니다.
2. 동일 출처(또는 소수의 회전 출처)에서 나오는 **다단계 연쇄**를 찾습니다. 정찰에서 엔드포인트 열거, 파라미터 탐침, 인증·주입 시도로 짧은 간격에 이어지고, 응답 코드·길이에 적응하며, 401·403·429 이후에도 우회 변형을 멈추지 않는 양상입니다. 이 행동 신호가 정적 User-Agent 보다 오래 남습니다(2절 (가) 행동 시그니처).
3. SIEM 을 운용한다면 이 행동을 [Sigma 상관 규칙](../detections/README.ko.md)(보강 조회 속도·대상 수·가드 차단 버스트·가드 마커와 파괴 명령의 동시 발생)으로 걸어 두고, 걸린 출처를 위 "자동 차단을 선제로" 원칙에 따라 격리·세션 무효화 대상으로 올립니다.

**(나) 호스트 포렌식: 특정 호스트에서 ARTEX 가 돌았는지**

의심 호스트에서 다음을 확인합니다. 지표의 근거는 2절 (나)와 기계가 읽는 [침해지표 목록](../detections/indicators/artex_indicators.csv)에 있습니다. 아래 다섯 가지 읽기 전용 점검 가운데 앞의 네 가지(리스닝 포트·송신 로그·감사 로그·상태·기록 저장소)는 [호스트 분류 스크립트](../detections/triage/)(`detections/triage/artex_host_triage.py`)가 한 번에 대신 돌려 줍니다. 다섯 번째 명령 감사는 파괴적 명령이 ARTEX 고유 지문이 아니라 정당한 관리자도 쓰는 헌팅 단서여서 자동 지표로 싣지 않으므로, 스크립트가 대신 돌리지 않고 호스트 명령 이력에서 직접 대조합니다. SIEM 없이 셸 접근만 있을 때 먼저 돌려 보고, 각 적중은 아래 설명대로 단서로만 다룹니다.

1. **리스닝 포트.** 기본 서버 포트 `:8787` 과 루프백 기록 프록시 `127.0.0.1:8788` 이 열려 있는지 호스트에서 직접 확인합니다.
   ```sh
   ss -ltnp | grep -E ':8787|:8788'   # ss 가 없으면 netstat -ltnp 를 씁니다
   ```
   두 포트는 `--addr`·`--proxy` 플래그로 바뀔 수 있으므로, 이 조회가 비어도 열린 포트 전체와 내부 관리 UI 가 떠 있는지를 함께 봅니다.
2. **송신 로그.** 자가 업데이트 User-Agent `artex-selfupdate` 로 코드 저장소 호스트(GitHub 릴리스)에 나간 요청이 송신 로그에 있는지 확인합니다(`selfupdate/`). 이 호스트에서 ARTEX 바이너리가 돌았음을 시사합니다.
3. **감사 로그.** 가드 통제 마커 `【ARTEX 平台管控·非目标防御】` 가 감사 기록에 있으면 ARTEX 실행을 뒷받침합니다(`guard/guard.go`). 차단된 도구 호출마다 이 프레이밍으로 남습니다.
4. **상태·기록 저장소.** ARTEX 는 PostgreSQL 에 탐색 그래프를 두고(`exploration_nodes`·`assets`·`companies`·`activity` 테이블과 `agent_prompts` 시드), 실행 파일 옆 데이터 디렉터리(`cmd/artex/main.go` 의 `--data` 기본값)에 상태와 기록을 남깁니다. 이 디렉터리 바로 아래에는 작업별 산출물을 담는 `tasks/` 와 대화 기록을 담는 `transcripts/` 하위 디렉터리가 있고, 기록 프록시의 산출물은 그 안의 `traffic/` 하위 디렉터리에 따로 모입니다(`server/manager.go` 가 데이터 디렉터리 아래 `traffic/` 를 기록 프록시 저장소로 엽니다). 그래서 신뢰 CA 인증서는 `traffic/_ca/mitmproxy-ca-cert.pem`, 트래픽 색인은 `traffic/_index/index.sqlite`, 기록한 요청·응답 본문은 `traffic/_blobs/` 에 있습니다. 이 셋이 `tasks/`·`transcripts/` 와 함께 보이면 기록 프록시가 실제로 돌았다는 정황이 강해집니다.
5. **명령 감사.** 파괴적 명령 헌팅 지표(2절 (나) 끝의 `rm -rf`·`DROP DATABASE`·`FLUSHALL`·반출 파이프 등)를 호스트 명령 이력과 대조합니다. 정당한 관리자도 같은 명령을 쓰므로 단서로만 다룹니다.

정적 지표(포트·User-Agent·마커)는 운영자가 바꾸거나 지울 수 있습니다. 따라서 **부재가 안전을 뜻하지 않으며**, (가)의 행동 신호와 (나)의 호스트 흔적을 함께 모아 판단하는 것이 자율 AI 공격 분류의 핵심입니다.

---

## 7. 국내 공식 채널: 침해지표·보안 권고와 신고 의무

국내 방어 조직은 침해지표와 보안 권고를 공식 채널에서 받고, 사고가 나면 법에서 정한 신고 의무를 지켜야 합니다. 떠도는 비공식 목록 대신 아래 공식 출처를 1차 기준으로 삼으십시오.

### 7.1 침해지표·보안 권고를 받는 곳

- **KISA(한국인터넷진흥원)의 [보호나라·KrCERT/CC](https://www.boho.or.kr)** 는 보안 권고와 취약점 공지, 침해사고 대응 정보를 제공합니다. 사이버위협정보 분석·공유체계(C-TAS)로 기관 사이에 위협정보를 공유합니다(C-TAS 는 가입 기관 간 공유 체계라 공개 포털과 달리 별도 신청 절차를 거칩니다).
- **[금융보안원(FSI)](https://www.fsec.or.kr)** 은 금융 분야의 침해·위협 정보를 업권을 가로질러 공유합니다(금융 분야 ISAC). 금융권이라면 이 채널을 함께 봅니다.
- **[개인정보보호위원회](https://www.pipc.go.kr)** 는 개인정보 유출 신고 기준과 보호 조치에 관한 고시·가이드를 공개합니다.

5절 하드닝 체크리스트의 "공식 침해지표를 신뢰할 수 있는 출처에서 받는다"가 가리키는 출처가 바로 이 채널들입니다. 공식 침해지표라도 유효 기간과 오차단 위험을 먼저 검토한 뒤 반영하는 원칙은 2절의 "IP 주소 차단은 왜 약한 1차 방어인가"에서 설명한 것과 같습니다.

### 7.2 국내법상 신고 의무

자율 공격은 빠르게 번지므로, 6절 사고 대응 절차 안에 법정 신고 단계를 미리 넣어 두십시오. 아래는 요지이며, 정확한 적용 대상과 기한, 요건은 각 기관의 최신 고시로 확인해야 합니다.

- **개인정보 유출**: 「개인정보 보호법」 제34조에 따라, 유출을 인지한 때부터 72시간 이내에 개인정보보호위원회 또는 KISA 에 신고하고 정보주체에게 통지합니다(정보주체 1천 명 이상, 민감정보나 고유식별정보의 유출, 외부의 불법적 접근에 의한 유출 등이 신고 요건에 해당합니다).
- **침해사고**: 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」에 따라, 정보통신서비스 제공자는 침해사고를 인지한 뒤 24시간 이내에 과학기술정보통신부와 KISA(KrCERT/CC)에 신고합니다.
- **금융회사**: 금융 분야 감독 규정에 따라 금융감독원이나 금융보안원 같은 소관 기관에 별도로 보고해야 할 수 있으므로, 해당 규정을 함께 확인하십시오.

실제 신고는 침해사고의 경우 [보호나라](https://www.boho.or.kr)나 국번 없이 118(KISA 사이버민원센터)로, 개인정보 유출의 경우 개인정보보호위원회 [개인정보 포털](https://www.privacy.go.kr)로 접수합니다. 신고 기한이 짧으므로 담당자와 연락 경로를 6절 사고 대응 절차에 미리 적어 두십시오.

---

## 참고

- 원본 프로젝트: [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX) (AGPL-3.0). 이 문서는 그 한국어판 저장소의 방어 자료입니다.
- 상위 [README 의 보안·오남용 경고와 사용 범위·국내법 고지](../README.md).
- 이 판본은 한국 사용자를 위한 현지화본이며, 개인정보가 결부된 경우에는 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」과 「개인정보 보호법」이 함께 적용됩니다. 그와 무관하게 권한 없는 점검은 대부분의 관할에서 범죄가 되므로, 반드시 서면 허가와 합의된 범위를 먼저 확보한 뒤에 진행하십시오.
- 일반 웹 보안 하드닝의 표준 참고: [OWASP Top 10](https://owasp.org/www-project-top-ten/), [OWASP ASVS(애플리케이션 보안 검증 표준)](https://owasp.org/www-project-application-security-verification-standard/), [OWASP API Security Top 10](https://api-security.owasp.org/).

> 이 가이드는 방어·탐지 역량을 돕기 위해 계속 보강됩니다. 보완할 탐지 규칙·하드닝 항목 제안은 저장소 이슈로 환영합니다.
