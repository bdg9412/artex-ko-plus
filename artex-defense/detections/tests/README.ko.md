# ARTEX 탐지 규칙 테스트

한국어 · [English](README.md)

[`../`](../) 아래의 탐지 규칙이 실제로 발화하는지, 그리고 그에 못지않게 중요한, 양성(benign)
트래픽에는 침묵하는지를 재현 가능하게 증명하는 회귀 테스트입니다. 돌려 볼 수 없는 탐지 규칙은
주장에 지나지 않습니다. 이 테스트들은 규칙 파일과 방어 가이드에 적힌 주장을 검토자가 소스에서
다시 돌려 볼 수 있는 것으로 바꿉니다.

이진 패킷 캡처는 저장소에 넣지 않습니다. 캡처는 **매 실행마다 결정론적으로 생성**했다가 끝난 뒤
지우므로, 테스트는 불투명한 고정 파일이 아니라 읽을 수 있는 소스로 배포되며 저장소를 불리지
않습니다.

## 모든 스위트를 한 번에 실행: [`run-all.sh`](run-all.sh)

[`run-all.sh`](run-all.sh) 는 아래 여덟 스위트를 CI 와 같은 순서로 한 명령에 전부 돌리므로, 여덟 개
`run.sh` 스크립트를 손으로 하나씩 호출하지 않아도 됩니다. 앞 스위트가 실패해도 각 스위트는 끝까지
돌고, 스크립트는 마지막에 스위트마다 PASS/FAIL 한 줄 요약을 출력하며, 하나라도 실패하면 0 이 아닌
코드로 종료합니다.

스위트를 돌리기 전에 하네스 자기 점검([`check-harness-sync.sh`](check-harness-sync.sh))을 먼저 실행합니다.
이 점검은 위의 스위트 목록, [CI](../../.github/workflows/detections.yml) 의 스위트별 스텝, 디스크의 스위트
디렉터리 이 셋이 서로 다른 스위트나 다른 순서를 가리키면 실행을 실패로 끝냅니다. 이것은 여덟 스위트가
스스로 보지 못하는 유일한 공백입니다. 세 곳 중 한 곳에만 배선된 스위트(예: `run-all.sh` 항목 없이 CI
스텝만 추가하거나, 어느 쪽에도 넣지 않은 디렉터리)는 스위트별 테스트를 모두 통과하면서도, 로컬에서
초록이던 `run-all.sh` 가 더는 초록 CI 를 뜻하지 않게 만듭니다. 이 점검은 아홉째 스위트가 아니라 게이트라서
아래 요약에는 나타나지 않으므로, 탐지 스위트는 여덟 그대로입니다.

게이트가 두 개 더 같은 방식으로 돕니다. 스위트 루프 전에 돌고, 요약에 나타나지 않으며, 스위트로 세지
않습니다. 하나는 [호스트 분류 도구](../triage/)의 `--self-test`([`triage-selftest.sh`](triage-selftest.sh))이고,
다른 하나는 방어 템플릿 정합 검사([`check-defense-template.sh`](check-defense-template.sh))입니다. 뒤의 것은
방어 가이드가 인라인 Sigma 상관 템플릿에 대해 단언한 사실(`sigma check` 통과, splunk·eql·loki 변환,
lucene·kusto 의 상관 거부, 한국어판·영어판 규칙 본문의 바이트 단위 동일)을 다시 돌립니다. 그 템플릿은
[`../sigma/`](../sigma/) 규칙 트리 밖 산문으로 들어 있어, 상류 `sigma-cli` 가 올라가 주장이 낡아도 다른
어떤 스위트도 잡지 못하기 때문입니다.

```sh
detections/tests/run-all.sh
```

예상 출력(축약):

```
===== detection suites summary =====
  PASS  sigma
  PASS  sigma_match
  PASS  sigma_lint
  PASS  sigma_backends
  PASS  suricata
  PASS  attack
  PASS  indicators
  PASS  misp
RESULT: PASS
```

실패가 하나라도 있으면 0 이 아닌 코드로 종료하므로 pre-commit 훅에 그대로 넣을 수 있습니다. 바로 쓸
수 있는 예시가 저장소 최상위 [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) 에 있습니다.
`pip install pre-commit && pre-commit install` 로 설치하면, 탐지 규칙이나 그 규칙이 고정한 상류 소스
파일을 건드리는 커밋에서 러너가 발화합니다. CI 와 같은 범위입니다. 개별 스위트가 인식하는 이미지·버전
재정의(`PYTHON_IMAGE`, `SIGMA_CLI_VERSION`, `SIGMAHQ_VALIDATORS_VERSION`, `SURICATA_IMAGE`)는 러너가
그대로 물려받으므로, 그중 어느 것을 export 해도 모든 스위트에 한꺼번에 적용됩니다.

## Suricata: [`suricata/`](suricata/)

[`suricata/run.sh`](suricata/run.sh) 는 [`../suricata/artex.rules`](../suricata/artex.rules) 의
네트워크 규칙을 종단으로 돌려 다섯 가지 속성을 단언합니다:

- **유효성**: 규칙 파일 전체가 `suricata -T --init-errors-fatal` 로 적재되므로, 아래 어떤 캡처도
  건드리지 않는 규칙이라도 파싱·초기화에 실패하면 잡아냅니다. 그냥 `suricata -r` 는 그런 규칙을
  건너뛰고도 0 으로 종료하므로, 이 적재 검사는 Sigma 스위트의 `sigma check` 유효성 단언에 해당하는
  Suricata 쪽 장치입니다.
- **존재성(보강 프로버)**: sid `1000001` 이 보강 프로브마다 정확히 한 번 발화합니다.
- **속도**: 소스당 300 초에 30 요청이라는 `detection_filter` 임계를 넘으면 sid `1000002` 가
  발화합니다.
- **존재성(WebFetch)**: sid `1000003` 이 norma WebFetch 요청마다 정확히 한 번 발화하고, 같은 캡처에서
  보강 프로버 sid 는 침묵합니다. 두 네트워크 시그니처가 각자 발화할 뿐 아니라 서로 특이적임을
  확인합니다.
- **특이성**: 다른 것은 같고 User-Agent 만 양성(benign) 브라우저로 바꾼 캡처는 ARTEX 경보를
  **하나도** 내지 않습니다.

[`suricata/gen_pcap.py`](suricata/gen_pcap.py) 는 [scapy](https://scapy.net) 로 캡처를 만듭니다.
고정된 한 소스에서 나오는 N 개의 독립적인 평문 HTTP 요청/응답 흐름을, 각각 지정한 User-Agent 를
실어, 고정된 기준 타임스탬프에서 1 초 간격으로 배치합니다. 파일을 쓰기만 할 뿐, 패킷을 보내거나
네트워크를 건드리지 않습니다.

### 실행

Docker 만 있으면 됩니다. scapy 와 Suricata 모두 컨테이너에서 돕니다.

```sh
detections/tests/suricata/run.sh
```

예상 출력(축약):

```
  PASS  ruleset loads with zero parse/init errors (suricata -T)
  PASS  sid 1000001 presence: one alert per probe  (got 35, want eq 35)
  PASS  sid 1000002 velocity: fires past 30-in-300s  (got 5, want ge 1)
  PASS  sid 1000003 presence: one alert per WebFetch request  (got 8, want eq 8)
  PASS  enrich sids stay silent on norma traffic (specificity)  (got 0, want eq 0)
  PASS  benign browser UA produces no ARTEX alerts  (got 0, want eq 0)
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료하므로 CI 나 pre-commit 훅에 그대로 넣을 수
있습니다. 내부에 미러를 두었다면 `SURICATA_IMAGE` / `PYTHON_IMAGE` 로 이미지를 재정의하십시오.

### 속도 경보 수를 정확한 값이 아니라 하한으로 단언하는 이유

`run.sh` 는 존재성 경보 수(`1000001 == 35`·`1000003 == 8`)와 양성 경보 수(`== 0`)를 정확히 단언합니다.
이들은 엔진 버전과 무관하기 때문입니다. 일치하는 요청마다 경보 하나, 다른 User-Agent 에는 불일치입니다. 속도
규칙의 경보 수는 특정 Suricata 릴리스가 경계에서 `detection_filter` 임계를 어떻게 처리하느냐에 달려
있으므로, 테스트는 `>= 1` 로 단언하고 기준값은 따로 기록합니다. **Suricata 8.0.7** 에서는 기준
실행이 sid `1000002` 에 경보 **5** 개를 냅니다(300 초에 30 임계를 넘긴 뒤의 31–35 번째 흐름).

## Sigma: [`sigma/`](sigma/)

[`sigma/run.sh`](sigma/run.sh) 는 [`../sigma/`](../sigma/) 아래의 Sigma 규칙을 구조적으로, 그리고
[sigma-cli](https://github.com/SigmaHQ/sigma-cli)(pySigma) 로 컴파일해 검증하며, 다섯 가지 속성을
단언합니다:

- **유효성**: `sigma check` 가 트리 전체에서 오류 0, 조건 오류 0, 이슈 0 을 보고합니다.
- **컴파일**: `sigma convert -t splunk` 가 트리 전체를 오류 없이 백엔드 질의 언어로 변환합니다.
- **지표 보존**: 각 원자 지표 문자열(`artex-enrich/1.0`, `artex-selfupdate`, 가드 마커, 그리고 기록용
  프록시 CA 파일명 `mitmproxy-ca-cert.pem`)이 컴파일된 질의에 그대로 남아 있으므로, 규칙이 자신이
  기반한 문자열을 조용히 잃을 수 없습니다.
- **상관 규칙 컴파일**: [`../sigma/correlation/`](../sigma/correlation/) 의 행동 규칙이 버려지지
  않고 `event_count` / `value_count` 집계를 내보냅니다.
- **상관 규칙이 실제로 작동함**: 상관 규칙 하나만 *단독으로* 변환하면 실패합니다. 그 규칙이 원자
  기반 규칙을 `id` 로 참조하기 때문이며, 이 참조는 장식이 아니라 강제됩니다. 이는 위 Suricata
  특이성 단언에 해당하는 Sigma 쪽 장치입니다.

이는 [`../README.ko.md`](../README.ko.md) 에 설명한 구조 + 컴파일 검증을, 실행 가능하고 단언하는 형태로 만든
것입니다. 아래의 짝 스위트 [`sigma_match/`](sigma_match/) 가 원자 규칙과 상관 규칙 양쪽에 *매칭* 절반을
더합니다. 대표적인 악성 이벤트(또는 타임라인)가 각 규칙을 발화시키고 정상 이벤트는 발화시키지 않음을
확인하므로, 이제 Sigma 규칙도 Suricata 규칙처럼 재현 가능한 검증 테스트와 재현 가능한 매칭 테스트를 함께
갖습니다. (엉성하게 손으로 짠 매처가 규칙을
깎아내릴 수 있다는 기존 우려는, 파싱을 전부 pySigma 에 위임해 해소했습니다. 신뢰 모델은 다음 절에서 설명합니다.)

### 실행

Docker 만 있으면 됩니다. sigma-cli 와 splunk 백엔드가 컨테이너에서 돌고 저장소에는 아무것도 쓰지
않습니다.

```sh
detections/tests/sigma/run.sh
```

예상 출력(축약):

```
  PASS  sigma check: 0 errors, 0 condition errors, 0 issues
  PASS  whole tree converts to splunk (exit 0)
  PASS  indicator present: artex-enrich/1.0
  PASS  correlation rule fails to convert alone — it requires its atomic base rule
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료하므로 CI 나 pre-commit 훅에 그대로 넣을 수
있습니다. sigma-cli 는 기준 버전(`3.1.0`)으로 고정돼 있습니다. 내부에 미러를 두었다면
`SIGMA_CLI_VERSION` 으로 버전을, `PYTHON_IMAGE` 로 이미지를 재정의하십시오.

## Sigma 실시간 이벤트 매칭: [`sigma_match/`](sigma_match/)

[`sigma_match/run.sh`](sigma_match/run.sh) 는 [`../sigma/`](../sigma/) 아래의 Sigma 규칙이, 원자 규칙과
[`../sigma/correlation/`](../sigma/correlation/) 의 상관 규칙을 모두 포함해, 매칭되는 이벤트에 실제로 *발화*하고
정상 이벤트에는 침묵함을 증명합니다. Suricata 스위트가 네트워크 규칙에 주는 "돌려 볼 수 없는 탐지 규칙은
주장일 뿐"이라는 보증을, 호스트·로그 계층 규칙으로 확장한 것입니다. 원자 규칙 셋과 상관 규칙 셋, 모두 여섯
속성을 단언합니다:

- **규칙·샘플 짝짓기**: 모든 원자 규칙에는 [`events/<이름>.json`](sigma_match/events/) 샘플 파일이 있고,
  모든 샘플 파일은 규칙으로 되짚어집니다. 샘플 없이 추가한 규칙은 검증을 못 받고 넘어가는 대신 여기서
  실패합니다.
- **참 양성(true positive)**: 각 규칙이 자신의 악성 샘플 이벤트를 전부 매칭합니다.
- **참 음성(true negative)**: 각 규칙이 자신의 정상 샘플 이벤트를 하나도 매칭하지 않습니다. 예를 들어
  `.mitmproxy/` 아래의 단독 `mitmproxy-ca-cert.pem` 은 기록용 프록시 규칙을 발화시키지 **않습니다**. 그
  규칙의 `|all` 수식자가 ARTEX 가 쓰는 `_ca/` 디렉터리까지 함께 요구하기 때문이며, 이 판별을 증명하는 것이
  바로 매칭 테스트입니다.
- **상관 규칙·타임라인 짝짓기**: 모든 상관 규칙에는 [`events/correlation/<이름>.json`](sigma_match/events/correlation/)
  타임라인 파일이 있고, 모든 타임라인은 규칙으로 되짚어집니다. 타임라인의 각 이벤트는 상대 초를 담은 `ts`
  필드를 지닙니다.
- **상관 규칙의 참 양성**: 임계를 시간 창 안에서 한 그룹이 채우는 양성 타임라인에 각 규칙이 발화합니다.
  예를 들어 한 출처(`c-ip`)에서 10분 안에 서로 다른 20개 호스트로 퍼지는 요청이 수집 팬아웃 규칙을
  발화시킵니다.
- **상관 규칙의 참 음성**: 임계 미달, 임계는 채웠지만 시간 창을 벗어난 경우, 그룹이 갈린 경우,
  시간 상관에서 한쪽 레그가 빠진 경우에는 침묵합니다. 특히 요청량은 많아도 폭(서로 다른 호스트 수)이 작은
  버스트는 팬아웃 규칙을 발화시키지 **않습니다**. 폭이 신호이지 양이 신호가 아니며, 이 판별을 증명하는 것이
  바로 매칭 테스트입니다.

신뢰 모델은 이렇습니다. 손으로 짠 코드가 아니라 pySigma 가 각 규칙을 파싱합니다. 원자 규칙은 수식자와
조건을 트리로 컴파일하고(`|contains` → 와일드카드 값, `|all` → AND, `1 of selection_*` → OR), 상관 규칙은
집계 명세(유형·group-by·시간 창·임계 조건·참조하는 원자 규칙)로 컴파일합니다. [`check.py`](sigma_match/check.py)
는 그 트리와 명세를 따라 걷을 뿐이고, 상관 규칙이 어느 이벤트를 먹는지는 원자 규칙과 똑같은 매처로
판정하므로 권위 있는 Sigma 로직은 pySigma 안에 남습니다. 명시적으로 지원하지 않는 구문을 만나면 조용히
통과시키지 않고 예외를 던집니다(fail-closed). 범위와 한계는 스크립트 머리말에 밝혀 둡니다. 상관 규칙의
시간 창은 표준 슬라이딩 윈도(매칭 이벤트마다 `timespan` 길이의 창을 잡는) 해석이며, 실제 SIEM 의 윈도
방식은 다를 수 있습니다. 매칭은 **대소문자를 무시**하고(`sigma/` 스위트가 겨냥하는 splunk 백엔드의
기본값이며, 파괴 명령 규칙의 오탐 주석 자체가 이를 전제합니다), 키워드 매칭은 전문 부분 문자열 검색입니다.
이것은 규칙의 필드·값·조건·집계 로직에 대한 회귀 테스트이지, 필드 정규화가 다를 수 있는 각자의 SIEM 에서
검증하는 일을 대신하지는 않습니다.

### 실행

Docker 만 있으면 됩니다. pySigma 가 컨테이너에서 돌고 저장소에는 아무것도 쓰지 않습니다.

```sh
detections/tests/sigma_match/run.sh
```

예상 출력(축약):

```
  PASS  rule/sample pairing: 5 atomic rules, 5 event files, no orphans
  PASS  artex_enrich_user_agent: 1/1 positive events matched
  PASS  artex_recording_proxy_ca: 2/2 benign events correctly not matched
  PASS  rule/timeline pairing: 4 correlation rules, 4 timeline files, no orphans
  PASS  artex_enrich_fanout: fired — 20 distinct hosts from one source within the 10-minute window
  PASS  artex_enrich_fanout: quiet — high volume, low breadth: 25 requests from one source but only 4 distinct hosts
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료하므로 CI 나 pre-commit 훅에 그대로 넣을 수
있습니다. pySigma 는 기준 버전(`2.0.0`)으로 고정돼 있습니다. 내부에 미러를 두었다면 `PYSIGMA_VERSION`
으로 버전을, `PYTHON_IMAGE` 로 이미지를 재정의하십시오.

## Sigma 백엔드 이식성: [`sigma_backends/`](sigma_backends/)

[`sigma_backends/run.sh`](sigma_backends/run.sh) 는 규칙이 Sigma 테스트가 돌려 보는 단일 Splunk
예시를 넘어서도 변환됨을 증명하고, [`../README.ko.md`](../README.ko.md) 의 백엔드별 지원 표를 정직하게
유지합니다. Sigma 상관 규칙 변환은 백엔드에 따라 다르므로, README 는 어떤 `-t` 대상이 트리 전체를
받고 어떤 대상이 원자 규칙만 받는지 방어자에게 알려 줍니다. 다시 돌려 봐야만 믿을 수 있는
주장입니다. 두 가지 속성을 단언하는데, 둘 다 긍정형이라 실제 회귀가 있을 때만 실패합니다:

- **상관 규칙의 이식성**: 트리 전체(원자 + 상관)가 Splunk, Elasticsearch `eql` 대상, Grafana
  `loki` 에서 변환되며, 보강 지표가 각 질의에 그대로 살아남습니다. 상관 규칙이 Splunk 전용이 아님을
  보여 줍니다.
- **원자 전용 폴백 동작**: 다섯 개의 원자 규칙은 `lucene` 과 Microsoft `kusto` 백엔드에서도
  변환됩니다. 이 백엔드들은 고정된 버전에서 Sigma 상관 규칙 변환을 지원하지 않으므로, 해당 백엔드를
  쓰는 방어자는 원자 규칙을 배포하고 상관 윈도우는 그 백엔드 고유 기능으로 표현할 수 있습니다.

"백엔드 X 는 상관 규칙을 처리하지 못한다"는 부정형은 일부러 단언하지 않습니다. 그렇게 하면 백엔드가
*개선되는* 것이 빨간 빌드가 되기 때문입니다. 정직한 한계는 README 에 적어 두었고, 이 테스트의 명령이
그것을 재현합니다. [`sigma_backends/check.sh`](sigma_backends/check.sh) 는 컨테이너 안쪽 절반입니다.
고정된 sigma-cli 와 네 백엔드를 설치하고, 읽기 전용으로 마운트한 규칙 트리를 읽습니다.

### 실행

Docker 만 있으면 됩니다. sigma-cli 와 백엔드들이 컨테이너에서 돌고 저장소에는 아무것도 쓰지
않습니다.

```sh
detections/tests/sigma_backends/run.sh
```

예상 출력(축약):

```
  PASS  whole tree (atomic + correlation) converts on 'eql', enrich indicator survives
  PASS  five atomic rules convert on 'kusto', enrich indicator survives
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료합니다. sigma-cli 는 고정돼 있고(`3.1.0`,
`SIGMA_CLI_VERSION` 으로 재정의), 백엔드 플러그인은 호환되는 최신 버전으로 설치됩니다. 그래서 이
스위트는 상류 백엔드 릴리스에 가장 민감합니다. 지원을 떨어뜨린 플러그인은 빌드를 빨갛게 만들고, 이는
고정 버전과 README 표를 함께 갱신하라는 신호입니다.

## SigmaHQ 관례 린트: [`sigma_lint/`](sigma_lint/)

[`sigma_lint/run.sh`](sigma_lint/run.sh) 는 README 와 `CONTRIBUTING.md` 의 "`sigma check` 를 깨끗이
통과한다"는 약속이 pySigma 의 핵심 검사뿐 아니라 SigmaHQ 의 관례까지 포함하도록 만듭니다. 그냥
`sigma check` 는 `pySigma-validators-sigmahq` 플러그인을 적재하지 않으므로, 제목 대소문자·필드명 분류
체계·로그소스 분류 체계·참조 링크 관례가 검사되지 않고 지나갑니다. 이 스위트는 그 플러그인을 설치하고,
[`sigma_lint/validators.yml`](sigma_lint/validators.yml) 에 문서화한 기준선에 맞춰 전체 검사 집합을
돌립니다. 두 가지 속성을 단언합니다:

- **문서화한 기준선이 깨끗함**: `validators.yml` 과 함께 `sigma check` 를 돌리면 오류 0, 이슈 0 을
  보고합니다.
- **전체 집합이 살아 있고, 문서화한 제외만 남음**: 제외 없이 모든 SigmaHQ 검증기를 돌려도 이슈가
  보고되며, 그 각각은 `validators.yml` 이 일부러 끄는 네 검사 중 하나입니다(그 외에는 없음). 이것은
  공허 방지 가드입니다. 플러그인이 적재에 실패했다면 전체 실행이 아무것도 보고하지 않아 첫 번째 속성이
  잘못된 이유로 통과할 것이므로, 알려진 제외 항목이 반드시 나타나도록 요구합니다.

네 제외 항목은 SigmaHQ 의 모노레포 파일 정리 방식(로그소스 접두어가 붙은 파일명과 `correlation_`
파일명)과 분류 체계(일반 `application` 로그소스, 제품명 없는 `process_creation`), 그리고 브랜치 대
영구링크(permalink) 참조 관례를 담습니다. 어느 것도 자기 저장소의 살아 있는 문서를 참조하는 작고
독립적인 규칙 집합에는 맞지 않습니다. 각 제외 항목은 그 근거를 `validators.yml` 안에 함께 적어
두었습니다. *나머지* 모든 SigmaHQ 검사는 강제되므로, 새 관례 이슈를 들인 규칙(대소문자가 틀린 제목,
분류 체계를 벗어난 필드명)은 빌드를 빨갛게 만듭니다. `pySigma-validators-sigmahq` 는 고정돼 있고
(`0.21.0`, `SIGMAHQ_VALIDATORS_VERSION` 으로 재정의), 버전을 올리면 새 관례가 드러날 수 있는데, 이는
규칙이나 문서화한 기준선을 갱신하라는 신호입니다.

### 실행

Docker 만 있으면 됩니다. sigma-cli 와 검증기 플러그인이 컨테이너에서 돌고 저장소에는 아무것도 쓰지
않습니다.

```sh
detections/tests/sigma_lint/run.sh
```

예상 출력(축약):

```
  PASS  sigma check with the documented baseline: 0 errors, 0 issues
  PASS  every reported issue is one of the four documented exclusions
RESULT: PASS
```

## ATT&CK 레이어: [`attack/`](attack/)

[`attack/run.sh`](attack/run.sh) 는 [`../attack/artex_navigator_layer.json`](../attack/artex_navigator_layer.json)
의 [ATT&CK 커버리지 레이어](../attack/)가 커버한다고 주장하는 규칙과 어긋나지 않는지 확인합니다. 규칙
집합에서 어긋난 커버리지 레이어는 없느니만 못하므로, 이 테스트는 "이 규칙들이 이 ATT&CK 기법들을
커버한다"를 검토자가 소스에서 다시 돌려 볼 수 있는 것으로 바꿉니다. 단언하는 것:

- **유효한 레이어**: 파일이 JSON 으로 파싱되고 필수 ATT&CK Navigator v4.x 필드를 지니며, 모든
  항목에 올바른 형식의 기법 ID 와 유효한 ATT&CK 전술이 있습니다.
- **양방향 일치**: 점수가 매겨진 기법이 Sigma 규칙의 `attack.*` 기법 태그와 *정확히* 일치합니다.
  레이어에 빠진 규칙 기법도, 규칙에 없는 레이어 기법도 없습니다. 전술도 같은 방식으로 일치합니다.
- **근거 있음**: 점수가 매겨진 모든 기법의 주석이 실재하는 규칙 파일을 가리키므로, 레이어가 이름이
  바뀌거나 삭제된 규칙을 인용할 수 없습니다.

이것은 발화 테스트가 아니라 일관성 검사입니다. 탐지 백엔드가 필요 없고 Python 표준 라이브러리만 있으면
되므로, Sigma·Suricata 테스트와 달리 버전에 의존하는 경보 수가 없습니다. [`attack/check.py`](attack/check.py)
는 컨테이너 안쪽 절반입니다. 읽기 전용으로 마운트한 탐지 트리를 읽고 아무것도 쓰지 않습니다.

### 실행

Docker 만 있으면 됩니다. 검사가 Python 컨테이너에서 돌고 저장소에는 아무것도 쓰지 않습니다.

```sh
detections/tests/attack/run.sh
```

예상 출력(축약):

```
  PASS  scored techniques match the rule set exactly (8: T1059, T1105, T1485, T1489, T1557, T1561.002, T1592, T1595)
  PASS  scored tactics match the rule set exactly (collection, command-and-control, credential-access, execution, impact, reconnaissance)
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료하므로 CI 나 pre-commit 훅에 그대로 넣을 수
있습니다. 내부에 미러를 두었다면 `PYTHON_IMAGE` 로 이미지를 재정의하십시오.

## 지표 근거(source-of-truth): [`indicators/`](indicators/)

[`indicators/run.sh`](indicators/run.sh) 는 위 세 테스트가 하지 못하는 한 가지를 증명합니다. 각 규칙이
고정한 지표가 여전히 ARTEX 자신의 소스가 실제로 내보내는 문자열인지입니다. Sigma 테스트는 지표가
규칙→질의 *컴파일*을 거쳐 살아남음을 증명하고, ATT&CK 테스트는 레이어가 규칙 태그와 일치함을
증명하며, Suricata 테스트는 네트워크 규칙이 생성한 캡처에서 *발화*함을 증명합니다. 어느 것도 지표가
유래했다고 주장하는 소스 파일을 되짚어 보지는 않습니다. 이들이 모두 놓치는 부패는, 프로버 User-Agent
를 `artex-enrich/2.0` 으로 올리거나 가드 마커를 다시 쓰는 상류 재동기화입니다. 그래도 규칙은 모두
컴파일되고, 레이어는 여전히 일치하고, pcap 테스트도 여전히 발화합니다. 그런데 배포된 규칙은 실제
ARTEX 트래픽에 조용히 매칭을 멈춥니다. 각 지표에 대해 양방향으로 단언합니다:

- **소스가 여전히 내보냄**: 값이 그것을 만들어 내는 상류 소스 파일에 존재합니다(`enrich/enrich.go`
  의 `artex-enrich/1.0`, `selfupdate/` 의 `artex-selfupdate`, `guard/guard.go` 의 가드 마커). 값이
  없다는 것은 규칙이 아직 따라잡지 못한 상류 변경을 뜻합니다.
- **규칙이 여전히 고정함**: 값이 그것을 기반으로 세운 규칙에 존재하므로, 규칙 편집이 지표를 소스에서
  조용히 떼어 놓을 수 없습니다. Suricata 규칙은 `startswith` 접두어로 확인하는데, 이는 그 규칙이
  실제로 와이어를 매칭하는 방식과 같습니다.
- **차단 목록 대응**: 파괴적 명령 토큰(`rm -rf`, `mkfs`, `DROP DATABASE`, `FLUSHALL`)이 ARTEX
  가드의 차단 목록(`db/db.go`)과 그것을 반영한 헌팅 규칙 양쪽에 나타납니다. 이것들은 고유 지문이
  아니라 일반 헌팅 단서이므로, 테스트는 규칙이 실제로 주장하는 대응 관계만 단언합니다.
- **공개 목록이 근거를 유지함**: 방어자가 가져다 쓰는 산출물인 기계가 읽는 지표 목록
  [`detections/indicators/artex_indicators.csv`](../indicators/artex_indicators.csv) 을 행 단위로 다시
  읽습니다. 모든 값은 인용한 소스 파일에 여전히 존재하고 인용한 규칙에 고정돼 있어야 하며, 테스트가
  근거를 확인한 모든 지문은 이 목록에 나타나야 합니다. 그래서 공개된 CSV 는 자신이 유래했다고 주장하는
  소스에서 어느 방향으로도 조용히 어긋날 수 없습니다.
- **두 관문이 고정된 각 소스에서 발화함**: 테스트가 읽는 모든 상류 소스는 그것을 돌리는 두 관문에
  포함됩니다. CI 워크플로의 `push`·`pull_request` paths 필터([`.github/workflows/detections.yml`](../../.github/workflows/detections.yml))와
  로컬 pre-commit 훅의 `files` 정규식([`.pre-commit-config.yaml`](../../.pre-commit-config.yaml))입니다.
  필요한 집합은 지표 자체에서 파생되므로, 새 소스를 고정하면서(예전의 `cmd/artex/main.go` 포트가
  그랬듯) *두* 관문에 모두 배선하지 않으면 여기서 실패합니다. 그러지 않으면 그 소스만 건드린 변경이
  그 소스를 빠뜨린 관문에서 테스트를 건너뜁니다. CI 에서는 머지 게이트를 초록으로 통과하고, 훅에서는
  "CI 와 같은 소스 범위"라고 약속해 놓고도 로컬에서 끝내 잡히지 않습니다.

이는 [`../README.ko.md`](../README.ko.md) 의 약속("여기 모든 지표는 추정이 아니라 이 저장소 소스에서 확인한
문자열에 근거한다")과 CONTRIBUTING 의 첫 번째 기여 계약을, 검토자가 다시 돌려 볼 수 있는 가드로
바꿉니다. ATT&CK 테스트처럼 탐지 백엔드가 필요 없고 Python 표준 라이브러리만 있으면 됩니다.
[`indicators/check.py`](indicators/check.py) 는 규칙 트리, 공개 지표 목록, 고정된 소스 패키지, 그리고
그것을 발화시키는 두 관문(CI 워크플로와 pre-commit 설정)을 읽기 전용으로 마운트해 읽고, 아무것도 쓰지
않습니다.

### 실행

Docker 만 있으면 됩니다. 검사가 Python 컨테이너에서 돌고 저장소에는 아무것도 쓰지 않습니다.

```sh
detections/tests/indicators/run.sh
```

예상 출력(축약):

```
  PASS  enrichment prober User-Agent: 'artex-enrich/1.0' emitted by enrich/enrich.go
  PASS  detections/sigma/artex_enrich_user_agent.yml pins 'artex-enrich/1.0'
  PASS  'FLUSHALL' present in both db/db.go and detections/sigma/destructive_command_hunting.yml
  PASS  enrich-user-agent: 'artex-enrich/1.0' grounded in enrich/enrich.go
  PASS  tested fingerprint 'artex-enrich/1.0' is published in the list
  PASS  .github/workflows/detections.yml push paths covers cmd/artex/main.go
  PASS  .pre-commit-config.yaml files covers cmd/artex/main.go
RESULT: PASS
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료하므로 CI 나 pre-commit 훅에 그대로 넣을 수
있습니다. 내부에 미러를 두었다면 `PYTHON_IMAGE` 로 이미지를 재정의하십시오.

## MISP 내보내기 일관성: [`misp/`](misp/)

[`misp/run.sh`](misp/run.sh) 는 지표의 두 번째 공개 형태, 바로 가져올 수 있는 MISP 이벤트
[`detections/indicators/artex_indicators.misp.json`](../indicators/artex_indicators.misp.json) 를
다룹니다. 위 지표 테스트가 CSV 를 소스에 근거하게 유지한다면, 이 테스트는 방어자가 실제로 위협
인텔리전스 플랫폼에 적재하는 산출물인 MISP 이벤트가 그 CSV 에서 어긋나지 않게 유지합니다. 단언하는 것:

- **정말로 MISP 임**: 이벤트가 [pymisp](https://github.com/MISP/PyMISP) 로 적재되는데, 그 객체
  모델은 `type` 이 진짜 MISP 타입이 아닌 속성을 거부합니다. 그럴듯해 보여도 유효하지 않은 타입은
  여기서 실패하므로, "유효한 MISP"는 그냥 주장하는 것이 아니라 MISP 서버가 쓰는 라이브러리로
  증명됩니다.
- **CSV 와 행 단위 동기화**: 모든 CSV 행이 의도한 타입·카테고리를 가진 MISP 속성 정확히 하나로
  대응되고(`http.user-agent` → `user-agent`, 가드 마커 `string` → `pattern-in-file`, `port` →
  `port`, `ip-dst|port` → 합성 `ip|port` 값을 가진 `ip-dst|port`, 탐색 스키마 `other` → `other`), CSV 행 없이 남는 MISP 속성이
  하나도 없습니다. 이벤트는 CSV 와 함께 손으로 유지하므로, `artex_indicators.misp.json` 을 같은
  커밋에서 맞춰 갱신하지 않은 채 CSV 행을 추가·삭제·타입 변경하면 실패합니다.
- **`to_ids` 가 `rule` 열을 반영함**: 규칙이 뒷받침하는 지표는 `to_ids: true` 이고, 규칙이 없는
  호스트 포렌식 행은 `disable_correlation: true` 와 함께 `to_ids: false` 입니다. CSV 가 함의하는
  것과 다르게 플래그를 뒤집으면 실패하므로, MISP 이벤트는 어떤 지문이 실행 가능한지를 조용히
  부풀리거나 줄여 주장할 수 없습니다.
- **가드 마커가 바이트 단위로 보존되고** `detections/**` 가 CI paths 필터에 있어, CSV 나 이벤트를
  바꾸면 이 스위트가 발화합니다.

위의 순수 표준 라이브러리 테스트들과 달리, 이 스위트는 컨테이너 안에 고정된 `pymisp` 를
설치합니다(호스트에는 아무것도 설치하지 않음). [`misp/check.py`](misp/check.py) 는 CSV, MISP 이벤트,
CI 워크플로를 읽기 전용으로 마운트해 읽고, 아무것도 쓰지 않습니다.

### 실행

Docker 만 있으면 됩니다. pymisp 가 컨테이너에 설치되고 저장소에는 아무것도 쓰지 않습니다.

```sh
detections/tests/misp/run.sh
```

단언이 하나라도 실패하면 스크립트가 0 이 아닌 코드로 종료합니다. 내부에 미러를 두었다면
`PYTHON_IMAGE` 로 이미지를, `PYMISP_VERSION` 으로 고정된 라이브러리를 재정의하십시오.

## 기여

새 탐지 규칙은 그것이 발화함을 보여 주는 테스트가 있을 때 더 강합니다. 테스트는 자기 입력을 결정론적으로
생성하고, 엔진 버전과 무관한 속성은 정확히 단언하며(그보다 무른 속성은 기준값을 기록한 하한으로), 공격
안내로 읽힐 수 있는 내용은 피해야 합니다. [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) 와
[`../README.ko.md`](../README.ko.md) 의 규칙 색인을 보십시오.

여덟 스위트는 모두 `detections/` 를 건드리는 모든 push 나 pull request 에서 CI 로 돕니다
([`../../.github/workflows/detections.yml`](../../.github/workflows/detections.yml) 참조). 그리고 지표
테스트는 그것이 고정한 상류 소스 파일(`enrich/`, `selfupdate/`, `guard/`, `db/`, `cmd/artex/main.go`)이
바뀔 때도 돕니다. 그래서 지표를 떨어뜨리거나, ATT&CK 레이어에서 어긋나거나, 문서화한 백엔드에서
변환이 멈추거나, SigmaHQ 관례를 깨거나, 소스와 동기화가 어긋나거나, MISP 이벤트가 CSV 에서 어긋나게
두거나, 워크플로가 아직 감시하지 않는 새 소스를 고정하는 규칙 변경은 머지되기 전에 빌드를 빨갛게
만듭니다.
