# ARTEX 탐지 규칙

한국어 · [English](README.md)

> 이 디렉터리는 [방어·탐지 가이드(../docs/defense-ko.md)](../docs/defense-ko.md) 4절 "탐지 규칙"의
> 의사 규칙을, 각자의 SIEM·EDR 질의 언어로 변환해 바로 배포할 수 있는 벤더 중립
> [Sigma](https://sigmahq.io) 형식으로 옮긴 것입니다. 여기 실린 모든 지표는 **추정이 아니라** 이
> 저장소 소스에서 실제로 확인한 문자열이나 행동에 근거합니다. 모든 규칙은 자신이 소유하거나 서면
> 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 사용하십시오.

## 원자(atomic) 규칙

- **`sigma/artex_enrich_user_agent.yml`**: ARTEX 자산 보강(`enrich/enrich.go`)이 보내는 인바운드
  `artex-enrich/1.0` User-Agent 입니다. 대상 측에서 관측하는 보조 지표입니다. `level: high`.
- **`sigma/artex_selfupdate_egress.yml`**: 자가 업데이트 루틴(`selfupdate/github.go`)이 내보내는
  아웃바운드 `artex-selfupdate` User-Agent 입니다. 호스트·포렌식 관점의 송신(egress) 지표입니다.
  `level: medium`.
- **`sigma/artex_guard_audit_framing.yml`**: 도구 호출이 차단될 때 감사 로그에 기록되는 플랫폼
  가드 통제 마커(`guard/guard.go`)입니다. 호스트·포렌식 지표입니다. `level: high`.
- **`sigma/destructive_command_hunting.yml`**: ARTEX 가드의 기본 차단 목록(`db/db.go` 시드)을
  그대로 반영한 파괴적 셸·DB 명령입니다. ARTEX 고유 시그니처가 아니라 일반적인 헌팅 단서입니다.
  `level: medium`.
- **`sigma/artex_recording_proxy_ca.yml`**: 기록용 프록시가 `_ca/mitmproxy-ca-cert.pem` 배치로
  생성하는 MITM CA 인증서 파일(`traffic/traffic.go`)입니다. 호스트·포렌식 아티팩트이며, 파일명
  자체는 단독 실행한 mitmproxy 와 공유되므로 헌팅 단서로 다룹니다. `level: medium`.

## 상관(correlation) 규칙: 행동 기반

정적 문자열은 바꿀 수 있지만 행동은 숨기기가 더 어렵습니다. [`sigma/correlation/`](sigma/correlation/)
의 Sigma **상관** 규칙은 방어 가이드(4.1~4.2절, 4.4절)의 행동 기반 계층을 담습니다. 각 상관 규칙은
위 원자 규칙을 `id` 로 참조하므로, 참조를 풀려면 단일 상관 파일이 아니라 `sigma/` 트리 전체를
변환해야 합니다(아래 참조).

- **`sigma/correlation/artex_enrich_scan_velocity.yml`**: 한 출처가 짧은 시간 창 안에서 쏟아내는
  `artex-enrich/1.0` 프로브 묶음입니다(보강은 동시성 4 로 속도 제한 없이 돕니다). 단건 규칙이
  놓치는 속도를 잡습니다. `event_count`, `level: high`.
- **`sigma/correlation/artex_enrich_fanout.yml`**: 한 출처가 보강 User-Agent 를 여러 **서로 다른**
  호스트로 실어 나르는 경우입니다. 자산 목록 전체로 기계 속도로 퍼지는 양상으로, 양(volume)만이
  아니라 폭(breadth)이 단서입니다. `value_count`, `level: high`.
- **`sigma/correlation/artex_guard_block_burst.yml`**: 한 호스트에서 플랫폼 가드 통제 마커가 반복해
  찍히는 경우입니다. 단지 마커를 인용한 문서가 아니라, 돌고 있는 ARTEX 실행이 자기 가드를 건드리고
  있다는 신호입니다. `event_count`, `level: high`.
- **`sigma/correlation/artex_guard_marker_then_destructive.yml`**: 한 호스트에서 시간 창 안에 가드
  마커와 파괴적 명령이 함께 나타나는 경우입니다(방어 가이드 §4.2, 다단계). ARTEX 고유 마커를, 그
  자체로는 일반적인 파괴 명령 신호와 결합해 특이도를 높입니다. `temporal`, `level: high`.

임계값과 시간 창은 보수적인 기본값입니다. 각자의 기준선(baseline)에 맞게 조정하십시오. §4.2 의 순수
웹 다단계 사례(열거 → 프로브 → 인증)는 그 패턴이 단일 ARTEX 고유 User-Agent 로 환원되지 않으므로,
여전히 환경별 기본 규칙이 따로 필요합니다. 그 출발점으로 쓸 수 있는 일반 행동 기반 Sigma 베이스
템플릿을 [방어 가이드 §4.2](../docs/defense-ko.md#42-siem-상관-규칙)에 두었습니다. ARTEX 소스로 근거를
고정할 수 없어 여기 테스트되는 규칙 트리에는 넣지 않았습니다.

## 네트워크 규칙 (Suricata)

Sigma 는 호스트와 로그 텔레메트리를 다룹니다. 네트워크 선에서 관측되는 ARTEX 고유 User-Agent 는 두
가지이고, 둘 다 [`suricata/`](suricata/)에 [Suricata](https://suricata.io) 규칙으로 들어 있습니다. 보강
프로버의 `artex-enrich/1.0`(`enrich/enrich.go`)에는 존재 시그니처 하나와 고속 열거 변형 하나(sid
1000001·1000002)가, norma SDK 의 WebFetch 도구가 공격 단계에 보내는 `norma/0.4`(`github.com/Autumn-27/norma/tool/webfetch.go`)에는
존재 시그니처 하나(sid 1000003)가 대응합니다. 그 밖의 worker 도구(Bash 로 실행하는 `curl`·`nmap` 등)는
자체 User-Agent 를 쓰므로 ARTEX 고유 지문이 없어, 네트워크 계층은 의도적으로 이 두 UA 로만 좁게
잡았습니다. 범위와 TLS 유의점, `suricata -T` 와 참조 pcap 으로 검증하는 방법은
[`suricata/README.ko.md`](suricata/README.ko.md)를 참조하십시오.

## ATT&CK 커버리지

이 규칙들이 태그하는 기법은 [MITRE ATT&CK](https://attack.mitre.org/) Navigator 레이어
[`attack/artex_navigator_layer.json`](attack/)에 모았습니다. 여섯 전술(정찰, 명령·제어, 실행, 임팩트,
자격 증명 접근, 수집)에 걸친 여덟 기법으로, 각 기법은 규칙의 `attack.*` 태그에 근거하고 탐지 강도(ARTEX 고유 시그니처인지,
일반 헌팅 단서인지)로 점수를 매겼습니다. [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
에서 열면 어떤 ARTEX 행동을 어떤 규칙이 덮는지 볼 수 있습니다. 점수 산정과 기법↔규칙 대응, 그리고
정직한 범위(커버리지는 완전성이 아닙니다)는 [`attack/README.ko.md`](attack/README.ko.md)를 참조하십시오.
[일관성 테스트](tests/attack/run.sh)가 레이어와 규칙 집합이 서로 어긋나지 않게 지킵니다.

## 침해지표 목록 (기계가 읽는)

탐지 로직이 아니라 원자 지표 자체를 원하는 방어자를 위해,
[`indicators/artex_indicators.csv`](indicators/)는 ARTEX 가 내보내는 고유 지문을 CSV 한 파일에
모았습니다. 위협 인텔리전스 플랫폼이나 SIEM 조회 테이블, 호스트 분류(triage) 체크리스트에 바로
넣을 수 있도록 보강·자가 업데이트 User-Agent, 가드 감사 마커, 서버·프록시 기본 엔드포인트, 기록
프록시 CA 인증서, 그리고 PostgreSQL 탐색 그래프 스키마 지문을 담고, 각 행에는 근거가 된 소스
파일과 (있다면) 그 위에 세운 규칙을 함께 적었습니다. 같은 지표를 바로
가져올 수 있는 [MISP](https://www.misp-project.org/) 이벤트
([`indicators/artex_indicators.misp.json`](indicators/))로도 제공하므로, MISP 를 쓰거나 거기서
STIX 로 내보내는 방어자는 CSV 열을 손으로 매핑할 필요가 없습니다. 규칙에 근거한 지문은 `to_ids`
로 표시했고, 호스트 포렌식용 포트와 스키마 지문은 표시하지 않았습니다. 일반 헌팅 단서(파괴 명령)와
norma SDK 가 공유하는 `norma/0.4` WebFetch User-Agent(Suricata sid 1000003 이 잡는 네트워크 서명이지
ARTEX 고유 문자열이 아닙니다)는 오탐을 피하려 가져오기용 목록에서 의도적으로 뺐습니다. 열 구성, MISP 타입 매핑, 정직한 유의점, 그리고 CSV 와
MISP 이벤트가 어긋나지 않게 지키는 일관성 테스트는 [`indicators/README.ko.md`](indicators/README.ko.md)를
참조하십시오.

## 호스트 분류(triage)

위 규칙은 SIEM·네트워크 센서·위협 인텔리전스 플랫폼을 쓰는 방어자를 위한 것입니다. 그와 다른 대응자, 곧
SIEM 없이 의심 호스트 한 대의 셸 앞에 선 사람을 위해 [`triage/artex_host_triage.py`](triage/)를 둡니다. 로컬
상태만으로 "여기서 ARTEX 가 돌았는가"를 답하는 읽기 전용 스크립트입니다. 같은 지문을 점검하고, 여기에 더해
**CSV 가 의도적으로 Sigma 규칙 없이 둔 세 가지 호스트·DB 지표**(서버 리슨 포트, 기록 프록시 엔드포인트,
PostgreSQL 탐색 스키마)까지 점검합니다. 이 세 가지는 로그나 네트워크로 관측되지 않아 호스트에서 직접 확인할
수밖에 없습니다. 또한 기록기가 자식 프로세스에 주입하는 환경변수 흔적, 곧 실행 중인 프로세스가 프록시 변수와
mitmproxy CA 신뢰 변수를 함께 지니는지(`agent/worker.go`)를 `/proc` 나 `--proc-from` 덤프에서 확인합니다.
각 발견은 해당 침해지표 행과 같은 한계를 지닌 분류 단서입니다. 자세한 내용은
[`triage/README.ko.md`](triage/README.ko.md)에 있고, 내장된 `--self-test` 가 아래 머지 게이트로 돌아갑니다.

## 테스트

규칙에는 Docker 만 있으면 돌릴 수 있는 재현 테스트가 [`tests/`](tests/)에 함께 들어 있습니다.

- **Suricata** ([`tests/suricata/run.sh`](tests/suricata/run.sh)): 먼저 규칙 파일 전체가
  `suricata -T --init-errors-fatal` 로 적재되는지 검증하고(어떤 캡처도 건드리지 않는 규칙이라도
  파싱 실패는 잡힙니다), scapy 로 결정적 캡처를 합성한 뒤 `suricata -r` 로 그 위를 돌려, 존재 규칙이
  프로브마다 한 번씩 발화하고 속도 규칙이 임계를 넘으면 걸리며 양성(benign) User-Agent 캡처에서는
  경보가 0 인지 단언합니다. 이진 캡처는 커밋하지 않고 매 실행마다 다시 생성합니다.
- **Sigma** ([`tests/sigma/run.sh`](tests/sigma/run.sh)): 아래 "검증과 변환"의 `sigma check` 와
  `sigma convert` 검증을 실행 가능한 테스트로 돌립니다. 오류 0 과, 트리 전체가 백엔드 질의로
  컴파일됨과, 각 원자 지표 문자열이 그 질의까지 살아남음과, 상관 규칙이 홀로는 변환에 실패함을
  단언합니다. 마지막 단언은 상관 규칙이 참조하는 원자 규칙에 실제로 의존함을 증명합니다.
- **Sigma 실시간 이벤트 매칭** ([`tests/sigma_match/run.sh`](tests/sigma_match/run.sh)): 위 Sigma 테스트가
  규칙의 유효성과 컴파일을 증명한다면, 이 테스트는 원자 규칙과 상관 규칙이 실제로 발화하는지를 증명합니다.
  각 원자 규칙마다 대표적인 악성 샘플 이벤트가 규칙을 발화시키고 정상 샘플 이벤트는 발화시키지 않음을
  단언합니다(예: `.mitmproxy/` 아래 단독 CA 파일은 `_ca/` 디렉터리까지 함께 요구하는 기록용 프록시 규칙을
  발화시키지 않습니다). 각 상관 규칙에 대해서는 임계를 시간 창 안에서 한 그룹이 채우는 양성 타임라인에
  발화하고, 임계 미달·창 초과·그룹 분할·레그 누락 타임라인에는 침묵함을 단언합니다. 파싱은 전부 pySigma 에
  맡기고 테스트는 컴파일된 조건 트리와 집계 명세만 걸으며, 상관 규칙이 어느 이벤트를 먹는지는 원자 규칙과
  같은 매처로 판정합니다. "돌려 볼 수 없는 탐지 규칙은 주장일 뿐"이라는 원칙을 Suricata 처럼 Sigma 쪽에도
  적용합니다.
- **ATT&CK 레이어** ([`tests/attack/run.sh`](tests/attack/run.sh)): ATT&CK 커버리지 레이어가
  규칙과 일관되게 유지되는지 확인합니다. 점수를 매긴 기법·전술이 정확히 규칙 집합의 `attack.*`
  태그여야 하고, 각 기법은 실재하는 규칙 파일을 지목해야 합니다. 레이어를 갱신하지 않고 규칙을
  추가하면(또는 그 반대면) 테스트가 실패합니다.
- **지표 근거(source-of-truth)** ([`tests/indicators/run.sh`](tests/indicators/run.sh)): 각 규칙이
  고정한 지표가 여전히 상류 소스가 내보내는 바로 그 문자열인지 확인합니다. `enrich/enrich.go` 의
  `artex-enrich/1.0`, `selfupdate/` 의 `artex-selfupdate`, `guard/guard.go` 의 가드 마커, `db/db.go`
  의 파괴 토큰이 규칙에도 여전히 고정돼 있는지 봅니다. 다른 세 테스트가 놓치는 드리프트, 즉 모든
  규칙이 컴파일되고 발화하는 와중에 상류 재동기화가 User-Agent 나 마커를 바꿔 버리는 경우를
  잡습니다. 같은 테스트가 기계가 읽는 [`indicators/artex_indicators.csv`](indicators/artex_indicators.csv)
  를 다시 읽어, 발행된 모든 행이 여전히 소스와 규칙에 근거함을 단언하므로 방어자가 가져오는 산출물도
  낡지 않습니다. 끝으로, 읽는 모든 상류 소스가 CI 워크플로의 `push`·`pull_request` 경로 필터에
  들어 있음을 단언해, 새로 고정한 소스 하나만 건드린 PR 이 테스트를 건너뛰어 그 드리프트가 머지
  게이트를 통과하지 못하게 합니다. 이로써 "추정이 아니라 이 저장소 소스에서 확인한 문자열에
  근거한다"(위)는 약속이 말이 아니라 가드가 됩니다.
- **MISP 내보내기 일관성** ([`tests/misp/run.sh`](tests/misp/run.sh)): MISP 이벤트
  ([`indicators/artex_indicators.misp.json`](indicators/artex_indicators.misp.json))가 유효한 MISP
  문서임을 증명합니다. [pymisp](https://github.com/MISP/PyMISP) 로 적재되는데, pymisp 의 객체 모델은
  실재하지 않는 속성 타입을 거부하므로 이 산출물은 MISP 처럼 보이기만 하는 것이 아니라 실제로
  가져와집니다. 또한 위 CSV 와 행 단위로 동기화됨을 단언합니다. 같은 값, 지표별로 의도한 MISP
  타입·카테고리, 그리고 CSV 의 정직함을 그대로 반영하는 `to_ids`·`disable_correlation` 플래그가
  일치해야 합니다(규칙에 근거 = 조치 가능이므로 `to_ids` on, 호스트 포렌식용 포트 = 분류 힌트이므로
  `to_ids` off 에 상관 비활성화). 이 이벤트는 CSV 와 나란히 손으로 관리됩니다. CSV 에 없는 설명
  주석·UUID·태그를 지니므로, CSV 행을 더하거나 빼거나 타입을 바꿀 때 같은 커밋에서 MISP 이벤트도
  고쳐야 하고, 둘이 일치할 때까지 이 테스트가 실패합니다.
- **Sigma 백엔드 이식성** ([`tests/sigma_backends/run.sh`](tests/sigma_backends/run.sh)): 규칙이
  Splunk 예시 하나를 넘어 변환됨을 증명합니다. 트리 전체(원자 + 상관)가 Splunk, Elasticsearch `eql`
  타깃, Grafana Loki 로 컴파일되고, 다섯 원자 규칙은 Sigma 상관을 지원하지 않는 백엔드(Elasticsearch
  `lucene`, Microsoft `kusto` 백엔드)에서도 여전히 컴파일됩니다. 아래 "검증과 변환"의 백엔드별 지원
  표를 다시 돌릴 수 있는 점검으로 뒷받침합니다.
- **SigmaHQ 관례 린트** ([`tests/sigma_lint/run.sh`](tests/sigma_lint/run.sh)): SigmaHQ 검증기
  전체(`pySigma-validators-sigmahq` 플러그인으로, 평범한 `sigma check` 는 적재하지 않습니다)를
  [`tests/sigma_lint/validators.yml`](tests/sigma_lint/validators.yml)에 문서화한 기준선에 맞춰
  돌리고 이슈 0 을 단언합니다. 또한 검증기 전체가 실제로 돌았고 의도적으로 제외한, 문서화된 네
  검사만 남아 있음을 확인하므로, 규칙이 새 관례 이슈(잘못 대소문자를 쓴 제목, 분류 체계를 벗어난
  필드)를 하나라도 들이면 빌드가 실패합니다.

여덟 규칙 테스트와 별개로, 규칙이 아닌 세 게이트가 같은 CI 워크플로와 [`tests/run-all.sh`](tests/run-all.sh)
에서 함께 돕니다. 첫째는 하네스 동기 검사(run-all.sh·CI·스위트 디렉터리가 같은 스위트를 같은 순서로 부르는지
확인)입니다. 둘째는 [호스트 분류 도구](triage/)의 `--self-test`([`tests/triage-selftest.sh`](tests/triage-selftest.sh))
로, 합성 호스트를 만들어 모든 분류 점검이 발화하는지와 깨끗한 호스트에서는 발견이 0 건인지 단언합니다. 셋째는
방어 가이드의 인라인 Sigma 상관 템플릿 정합 검사([`tests/check-defense-template.sh`](tests/check-defense-template.sh))
로, 방어 가이드가 그 템플릿에 대해 단언한 사실을 재현합니다. `sigma check` 가 통과하고, splunk·eql·loki 로
변환되며, lucene·kusto 는 상관 규칙을 거부하고, 한국어판과 영어판의 규칙 본문이 바이트 단위로 같은지
확인합니다. 이 템플릿은 규칙 트리 밖 산문으로 들어 있어, 상류 `sigma-cli` 가 올라가 그 주장이 낡아도 다른
어떤 스위트도 잡지 못하기 때문입니다.

각 스크립트는 단언이 하나라도 실패하면 0 이 아닌 코드로 종료합니다. [`tests/README.ko.md`](tests/README.ko.md)
를 참조하십시오.

## 이 규칙들을 정직하게 읽는 법

- **정적 지표는 바꿀 수 있습니다.** 운영자가 User-Agent 를 다른 값으로 설정할 수 있으므로,
  `artex-enrich/1.0` 이나 `artex-selfupdate` 가 **없다고 해서 안전하다는 뜻은 아닙니다.** 오래가는
  신호는 *행동* 입니다. 한 출처가 정찰 → 열거 → 프로브 → 인증·주입 시도로 이어지며 응답에 적응하고
  쉼 없이 도는 양상입니다. 그 계층은 방어 가이드(1절·2절·4.1~4.2절)에 설명했고, 위
  `sigma/correlation/` 규칙이 배포 가능한 상관(속도, 팬아웃, 가드 차단 묶음, 그리고 가드
  마커+파괴명령 다단계)으로 담았으며, 순수 웹 다단계 사례는 여전히 환경별 기본 규칙이 필요합니다.
- **파괴 명령 규칙은 일반 헌팅입니다.** ARTEX 가드의 차단 목록을 반영하지만, 같은 명령은 정당한
  관리자도 실행합니다. 적중은 단서로 다루고, 환경에 맞게 허용 목록을 두며, 그것만으로 ARTEX 라고
  단정하지 마십시오.
- **포트 지표는 Sigma 가 아니라 호스트 포렌식용입니다.** ARTEX 서버 기본 `:8787` 과 기록 프록시
  `127.0.0.1:8788`(`cmd/artex/main.go`)은 의심되는 호스트에서 `ss`·`netstat` 로 확인하는 편이
  낫습니다. 그래서 시끄러운 네트워크 규칙으로 싣지 않고, 방어 가이드에 문서화하고 분류용으로
  [지표 CSV](indicators/)에 올렸습니다. [호스트 분류 스크립트](triage/)는 바로 이런 호스트 로컬 점검(포트,
  기록 프록시 아티팩트, 로그 마커, PostgreSQL 스키마)을 셸 접근은 있으나 SIEM 이 없는 대응자를 위해
  대신 돌려 줍니다.

## 검증과 변환

이 규칙들은 [sigma-cli](https://github.com/SigmaHQ/sigma-cli)(pySigma)로 검증했습니다. 재현하려면:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install sigma-cli

# 구조 + 모범 사례 검증 (기대: 오류 0, 이슈 0)
sigma check detections/sigma/

# 이 독립 규칙 집합을 위한 문서화된 기준선으로 SigmaHQ 관례 전체 검사 (기대: 이슈 0).
# 위의 평범한 `sigma check` 는 이 검증기들을 적재하지 않습니다.
pip install pySigma-validators-sigmahq
sigma check --validation-config detections/tests/sigma_lint/validators.yml detections/sigma/

# 대상 질의 언어로 컴파일, 예: Splunk
sigma plugin install splunk
sigma convert -t splunk --without-pipeline detections/sigma/artex_enrich_user_agent.yml

# 상관 규칙이 id 로 참조하는 원자 규칙을 풀 수 있도록 트리 전체를 변환
sigma convert -t splunk --without-pipeline detections/sigma/
```

기준선은 SigmaHQ 관례를 모두 강제하되, SigmaHQ 모노레포의 파일 정리 체계와 분류 체계를 담은 네
검사만은 이 독립 규칙 집합에 해당하지 않으므로 제외합니다. 각 제외와 그 근거는
[`tests/sigma_lint/validators.yml`](tests/sigma_lint/validators.yml)에 문서화했고 위 린트 테스트가
강제합니다.

### Sigma 백엔드 이식성

`sigma/correlation/` 규칙은 원자 기본 규칙을 `id` 로 참조하므로, Sigma 상관 변환을 지원하는
백엔드에서만 변환됩니다. 그 지원은 백엔드마다 다르므로 `-t` 선택이 중요합니다. 아래 표는 고정한
기준(`sigma-cli` 3.1.0, 호환되는 최신 백엔드)에 맞춰 측정했고
[`tests/sigma_backends/run.sh`](tests/sigma_backends/run.sh)가 재현합니다.

- **트리 전체(원자 + 상관) 변환:** Splunk(`-t splunk`), Elasticsearch EQL(`-t eql`),
  Grafana Loki(`-t loki`). `detections/sigma/` 를 바로 변환하면 상관 질의까지 함께 얻습니다.
- **원자 규칙만(상관 아직 미지원):** Elasticsearch Lucene(`-t lucene`),
  OpenSearch(`-t opensearch_lucene`), 그리고 Sentinel·Defender XDR 를 겨냥하는 Microsoft `kusto`
  백엔드(`-t kusto`). 이들에서는 다섯 원자 규칙을 변환하고 상관 시간 창은 제품 안에서 네이티브로
  표현합니다(예: Sentinel 예약 분석의 `summarize ... by bin(TimeGenerated, 30m)`). 디렉터리 전체를
  넘기면 "Backend does not support correlation rules" 로 변환이 멈춥니다.

```sh
# 원자 규칙만, 예: Microsoft Sentinel / Defender (kusto 백엔드)
sigma plugin install kusto
sigma convert -t kusto --without-pipeline \
  detections/sigma/artex_enrich_user_agent.yml \
  detections/sigma/artex_selfupdate_egress.yml \
  detections/sigma/artex_guard_audit_framing.yml \
  detections/sigma/artex_recording_proxy_ca.yml \
  detections/sigma/destructive_command_hunting.yml
```

고정한 버전에서 알려진 경계: Elasticsearch ES|QL 타깃(`-t esql`)은 가드 마커 규칙을 거부하므로
(`String value expressions are not supported`) 거기서는 나머지 세 원자 규칙을 변환하십시오. 그리고
IBM QRadar 플러그인(`ibm-qradar-aql`)은 고정한 pySigma 와 호환되지 않아 `--force-install` 이
필요하므로 테스트에서 다루지 않습니다. 환경에 설치된 백엔드는 `sigma list targets` 로 확인하십시오.

위 예시는 `--without-pipeline` 을 써서 규칙 본문의 일반 필드명(`cs-user-agent`·`cs-host`·
`CommandLine`)을 그대로 내보냅니다. 제품 스키마에 맞추려면 그 플래그를 빼고 `-p` 로 처리
파이프라인을 적용하십시오(`sigma list pipelines` 참조). 다만 제품 파이프라인은 필드명을 매핑하되
규칙의 일반 `logsource` 가 지정하지 않는 대상 테이블을 추가로 요구할 수 있습니다. 예를 들어
`-p sentinel_asim` 은 데이터에 맞는 `query_table` 을 설정하기 전까지 "Unable to determine table name"
으로 멈추므로, 배포 전에 필드와 목적지 테이블을 환경에 맞게 매핑하십시오.

## 기여

탐지와 하드닝 기여를 환영합니다. 새 규칙은 모든 지표를 관측 가능한 사실에 근거해 두고, 한계를
`description` 에 밝히며, SigmaHQ 검증기 기준선을 깨끗이 통과하고
(`sigma check --validation-config tests/sigma_lint/validators.yml`), 공격 안내로 읽히는 내용을
담지 않아야 합니다. [`../CONTRIBUTING.md`](../CONTRIBUTING.md)를 참조하십시오.
