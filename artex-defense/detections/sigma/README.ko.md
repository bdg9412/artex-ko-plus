# ARTEX 탐지 규칙 (Sigma / 호스트·로그·SIEM)

한국어 · [English](README.md)

이 디렉터리는 ARTEX 탐지 묶음에서 호스트·로그·SIEM 계층을 맡습니다. 여기 실린
[Sigma](https://sigmahq.io) 규칙은 방어 가이드([한국어](../../docs/defense-ko.md) ·
[English](../../docs/defense-en.md)) 4절의 의사 규칙을 벤더 중립 형식으로 정식화한 것이고, 각자의
SIEM·EDR 질의 언어로 변환해 씁니다. 모든 지표는 추정이 아니라 이 저장소 소스에서 실제로 확인한
문자열이나 행동에 근거합니다. 네트워크 계층은 [`../suricata/`](../suricata/)에 있고, ATT&CK 레이어와
지표 CSV·MISP 내보내기, 호스트 분류 스크립트를 포함한 전체 탐지 묶음은
[`../README.ko.md`](../README.ko.md)가 색인합니다. 모든 규칙은 자신이 소유하거나 서면 허가를 받은
시스템을 지키는 **방어·탐지 목적에만** 사용하십시오.

## 원자(atomic) 규칙

규칙 하나가 관측 가능한 사실 하나에 대응합니다. 개별로 변환해도 되고, 트리 전체의 일부로 변환해도
됩니다.

- **[`artex_enrich_user_agent.yml`](artex_enrich_user_agent.yml)**: *ARTEX Asset Enrichment Probe
  User-Agent*. 자산 보강(`enrich/enrich.go`)이 보내는 인바운드 `artex-enrich/1.0` User-Agent 입니다.
  대상 측에서 관측하는 보조 지표입니다. `level: high`.
- **[`artex_selfupdate_egress.yml`](artex_selfupdate_egress.yml)**: *ARTEX Self-Update Egress
  User-Agent*. 자가 업데이트 루틴(`selfupdate/github.go`)이 내보내는 아웃바운드 `artex-selfupdate`
  User-Agent 입니다. 호스트·포렌식 egress 지표입니다. `level: medium`.
- **[`artex_guard_audit_framing.yml`](artex_guard_audit_framing.yml)**: *ARTEX Platform Guard
  Audit-Log Framing*. 도구 호출이 차단될 때 감사 로그에 기록되는 플랫폼 가드 통제 마커입니다
  (`guard/guard.go`). 호스트·포렌식 지표입니다. `level: high`.
- **[`artex_recording_proxy_ca.yml`](artex_recording_proxy_ca.yml)**: *ARTEX Recording-Proxy MITM CA
  Certificate Artifact*. 기록 프록시가 `_ca/mitmproxy-ca-cert.pem` 배치로 생성하는 MITM CA 파일입니다
  (`traffic/traffic.go`). 호스트·포렌식 산출물이며, 파일명 자체는 단독 실행 mitmproxy 와도 공유되므로
  사냥 단서(hunting lead)로 취급합니다. `level: medium`.
- **[`destructive_command_hunting.yml`](destructive_command_hunting.yml)**: *Destructive Command
  Execution (ARTEX Guard-List Hunting)*. ARTEX 가드의 내장 거부 목록(`db/db.go` 시드)을 반영한 파괴적
  셸·DB 명령입니다. ARTEX 고유 시그니처가 **아니라** 일반 사냥 단서입니다. `level: medium`.

## 상관(correlation) 규칙 (행동 기반) · [`correlation/`](correlation/)

정적 문자열은 바꿀 수 있지만 행동은 숨기기가 더 어렵습니다. 이 Sigma **상관** 규칙들은 방어 가이드
4.1~4.2절과 4.4절의 행동 기반 계층을 정식화합니다. 각 규칙은 위의 원자 규칙 하나를 `id` 로 참조하므로,
상관 파일 하나가 아니라 **`sigma/` 트리 전체를 변환해야** 참조가 풀립니다([Sigma 테스트](../tests/sigma/)가
바로 이 의존 관계를 단언합니다).

- **[`correlation/artex_enrich_scan_velocity.yml`](correlation/artex_enrich_scan_velocity.yml)**:
  *Enrichment Scan Velocity*. 한 출처가 짧은 창 안에 `artex-enrich/1.0` 프로브를 몰아치는 경우입니다
  (보강은 동시성 4로, 속도 제한 없이 돕니다). 단건 규칙이 놓치는 속도를 잡습니다. `event_count`,
  `level: high`.
- **[`correlation/artex_enrich_fanout.yml`](correlation/artex_enrich_fanout.yml)**: *Enrichment
  Fan-Out*. 한 출처가 보강 User-Agent 를 서로 다른 여러 호스트로 퍼뜨리는 경우입니다. 요청량이 아니라
  접촉한 서로 다른 호스트 수가 신호이며, 자산 목록을 기계 속도로 훑는 폭을 잡습니다. `value_count`,
  `level: high`.
- **[`correlation/artex_guard_block_burst.yml`](correlation/artex_guard_block_burst.yml)**:
  *Guard-Block Burst*. 한 호스트에서 플랫폼 가드 통제 마커가 반복되는 경우입니다. 마커를 인용만 한
  문서가 아니라, 실제로 가동 중인 ARTEX 실행이 자기 가드를 건드리는 상황을 가리킵니다. `event_count`,
  `level: high`.
- **[`correlation/artex_guard_marker_then_destructive.yml`](correlation/artex_guard_marker_then_destructive.yml)**:
  *Guard Marker With Destructive Command*. 가드 마커와 파괴적 명령이 한 호스트에서 한 창 안에 함께
  나타나는 경우입니다(방어 가이드 4.2절, 다단계). ARTEX 고유 마커를 원래 일반적인 파괴적 명령 신호와
  결합하므로 특이도가 올라갑니다. `temporal`, `level: high`.

임계값과 창은 보수적인 기본값이므로, 자신의 기준선에 맞게 조정하십시오. 순수 웹 다단계 경우(열거 →
프로빙 → 인증)는 여전히 환경별 기본 규칙이 필요합니다. 그 패턴은 ARTEX 고유 User-Agent 하나로
환원되지 않기 때문입니다. 시작점으로 쓸 일반 행동 기반 기본 템플릿은 [방어 가이드 4.2절](../../docs/defense-ko.md)에
있으며, ARTEX 소스에 근거를 둘 수 없어 이 검증된 트리에서는 의도적으로 뺐습니다.

## 범위와 정직함: 배포 전에 읽으십시오

- **정적 지표는 바꿀 수 있습니다.** 운영자가 User-Agent 를 바꾸거나 CA 파일을 지울 수 있으므로, 원자
  지표가 없다고 해서 안전하다는 뜻은 **아닙니다**. 오래가는 신호는 `correlation/` 규칙이 기준으로 삼는
  행동입니다. 한 출처가 정찰에서 열거, 프로빙, 인증·주입 시도로 이어 가며, 응답에 적응하고, 쉬지 않고
  도는 흐름이 그것입니다.
- **파괴적 명령 규칙은 일반 사냥입니다.** ARTEX 가드 거부 목록을 반영하지만, 같은 명령을 정당한
  관리자도 실행합니다. 적중은 단서로 다루고, 자신의 환경을 허용 목록으로 걸러 내며, 그것만으로 ARTEX
  라고 단정하지 마십시오.
- **포트와 스키마는 네트워크가 아니라 호스트 포렌식입니다.** 서버 기본 포트 `:8787` 과 기록 프록시
  `127.0.0.1:8788`(`cmd/artex/main.go`), 그리고 PostgreSQL 탐색 그래프 스키마는 의심 호스트에서 직접
  확인하는 편이 낫습니다. 그래서 시끄러운 규칙 대신 [지표 CSV](../indicators/)와
  [호스트 분류 스크립트](../triage/)로 제공합니다.
- **`logsource` 와 필드명은 일반값입니다.** 규칙은 일반 `category`·`product` 로그 소스와 필드명
  (`cs-user-agent`, `CommandLine`, `TargetFilename`)을 씁니다. 변환 시 파이프라인(`-p`)으로 자신의
  제품 스키마에 매핑하십시오. 아래 백엔드 설명을 참조하십시오.

## 검증과 변환

[sigma-cli](https://github.com/SigmaHQ/sigma-cli)(pySigma)로 검증했습니다. 저장소 루트에서 실행합니다.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install sigma-cli

# 구조 + 모범 사례 검증 (기대: 0 errors, 0 issues)
sigma check detections/sigma/

# 이 규칙 세트의 문서화된 기준선으로 SigmaHQ 관례 전체를 검사 (기대: 0 issues)
pip install pySigma-validators-sigmahq
sigma check --validation-config detections/tests/sigma_lint/validators.yml detections/sigma/

# 상관 규칙이 참조하는 원자 규칙을 풀 수 있도록 트리 전체를 변환
sigma plugin install splunk
sigma convert -t splunk --without-pipeline detections/sigma/
```

백엔드마다 상관 규칙 지원이 다르므로 `-t` 선택이 중요합니다. Splunk, Elasticsearch EQL, Grafana Loki 는
트리 전체를 변환하고, Elasticsearch Lucene, OpenSearch, 마이크로소프트 `kusto` 백엔드는 원자 규칙
다섯 개만 변환합니다(창은 제품에서 네이티브로 표현합니다). 백엔드별 실측 표와 `--without-pipeline` ·
`-p` 필드 매핑 설명은 [`../README.ko.md`](../README.ko.md)에 있고,
[`../tests/sigma_backends/`](../tests/sigma_backends/)가 재현합니다.

## 테스트

[`../tests/`](../tests/) 아래 재현 가능한 네 스위트가 이 규칙들을 다루며, 각각 Docker 만 있으면 됩니다.
[`sigma/`](../tests/sigma/)는 검증과 트리 전체 컴파일, 그리고 상관 규칙이 단독으로는 변환에 실패함을
단언하고, [`sigma_match/`](../tests/sigma_match/)는 규칙이 악성 샘플에 실제로 발화하고 양성 샘플에는
침묵하는지 확인하며, [`sigma_backends/`](../tests/sigma_backends/)는 백엔드 다섯 종의 이식성을,
[`sigma_lint/`](../tests/sigma_lint/)는 SigmaHQ 검증기 기준선 전체(0 issues)를 확인합니다.
[`../tests/README.ko.md`](../tests/README.ko.md)를 참조하십시오.

## 기여

탐지 기여를 환영합니다. 새 규칙은 모든 지표를 관측 가능한 사실에 근거해 두고, 한계를 `description` 에
밝히며, SigmaHQ 검증기 기준선을 깨끗이 통과하고
(`sigma check --validation-config ../tests/sigma_lint/validators.yml .`), 공격 안내로 읽히는 내용을
담지 않아야 합니다. [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)와
[`../suricata/`](../suricata/)의 네트워크 계층, 그리고 [`../README.ko.md`](../README.ko.md)를
참조하십시오.
