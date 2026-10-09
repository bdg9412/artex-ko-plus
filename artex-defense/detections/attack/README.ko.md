# ARTEX ATT&CK 커버리지

한국어 · [English](README.md)

이 저장소의 탐지 규칙이 태그하는 [MITRE ATT&CK](https://attack.mitre.org/)(Enterprise) 기법을
Navigator 레이어로 정리한 것입니다. [Sigma 규칙](../sigma/)의 `attack.*` 태그에서 손으로 만들었고,
모든 기법은 지표가 이 저장소 소스에서 확인한 문자열이나 행동인 규칙에 근거합니다. 추정으로 넣은
항목은 없으며, [일관성 테스트](../tests/attack/run.sh)가 레이어와 규칙이 서로 어긋나지 않게 지킵니다.

- **`artex_navigator_layer.json`**: ATT&CK Navigator v4.5 형식의 레이어입니다.

## 점수의 의미

여기서 커버리지는 "이 저장소가 이 기법을 태그하는 탐지를 제공한다"는 뜻이지, "이 기법이 완전히
덮인다"는 뜻이 아닙니다. 점수는 탐지 강도를 일부러 정직하게 매겼습니다.

- **100: ARTEX 고유 시그니처 또는 행동.** ARTEX 에만 있는 정적 지표(`artex-enrich/1.0`·
  `artex-selfupdate` User-Agent, 가드 감사 마커)이거나, 그 위에 세운 행동 규칙(보강 속도·팬아웃,
  가드 차단 묶음)입니다.
- **50–65: 일반 헌팅 단서.** ARTEX 가드의 차단 목록을 반영한 파괴적 명령 헌팅입니다. 같은 명령은
  정당한 관리자도 실행하므로 양성(benign) 활동에서도 발화합니다. 적중은 단서로 다루고 단정의
  근거로 삼지 마십시오. 65 는 상관 규칙이 그 명령을 ARTEX 가드 마커와 결합해 특이도를 높인
  경우를 가리킵니다.

## 다루는 기법

여섯 전술에 걸친 여덟 기법입니다. 각 기법은 그것을 태그하는 규칙에 대응합니다.

- **정찰(Reconnaissance): T1595 (Active Scanning), T1592 (Gather Victim Host Information).**
  [`sigma/artex_enrich_user_agent.yml`](../sigma/artex_enrich_user_agent.yml),
  [`sigma/correlation/artex_enrich_scan_velocity.yml`](../sigma/correlation/artex_enrich_scan_velocity.yml),
  [`sigma/correlation/artex_enrich_fanout.yml`](../sigma/correlation/artex_enrich_fanout.yml), 그리고
  [Suricata 규칙](../suricata/artex.rules)(sid 1000001 / 1000002)입니다.
- **명령·제어(Command and Control): T1105 (Ingress Tool Transfer).**
  [`sigma/artex_selfupdate_egress.yml`](../sigma/artex_selfupdate_egress.yml)입니다.
- **실행(Execution): T1059 (Command and Scripting Interpreter).**
  [`sigma/artex_guard_audit_framing.yml`](../sigma/artex_guard_audit_framing.yml),
  [`sigma/correlation/artex_guard_block_burst.yml`](../sigma/correlation/artex_guard_block_burst.yml),
  [`sigma/correlation/artex_guard_marker_then_destructive.yml`](../sigma/correlation/artex_guard_marker_then_destructive.yml)입니다.
- **임팩트(Impact): T1485 (Data Destruction), T1561.002 (Disk Wipe: Disk Structure Wipe), T1489 (Service Stop).**
  [`sigma/destructive_command_hunting.yml`](../sigma/destructive_command_hunting.yml)이며, T1485 는
  [`sigma/correlation/artex_guard_marker_then_destructive.yml`](../sigma/correlation/artex_guard_marker_then_destructive.yml)로도 보강됩니다.
- **자격 증명 접근·수집(Credential Access / Collection): T1557 (Adversary-in-the-Middle).**
  [`sigma/artex_recording_proxy_ca.yml`](../sigma/artex_recording_proxy_ca.yml)이며, 워커 도구의 트래픽을
  복호화·기록하려고 ARTEX 내장 트래픽 기록기(`traffic/traffic.go`)가 설치하는 MITM 루트 CA 아티팩트를
  겨냥한 호스트·포렌식 헌팅 단서입니다.

## 사용법

1. [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)를 엽니다.
2. **Open Existing Layer → Upload from local** 을 골라 `artex_navigator_layer.json` 을 선택합니다
   (또는 이 저장소의 raw 파일 URL 을 가리킵니다).
3. 점수를 매긴 기법이 탐지 강도에 따라 색으로 구분되어 나타나고, 각 기법에는 근거가 된 규칙 파일과
   방어 가이드 절을 적은 주석이 붙어 있습니다.

## 범위와 정직함

- **커버리지는 완전성이 아닙니다.** 여기서 점수를 받은 기법은 규칙이 그것을 태그한다는 뜻이지, 그
  기법의 모든 변형을 탐지한다는 뜻이 아닙니다. 네트워크 선에서 ARTEX 고유 User-Agent 로 잡히는 신호는
  정찰 단계의 보강 프로버(`artex-enrich/1.0`)와 공격 단계의 norma SDK WebFetch(`norma/0.4`) 둘뿐이고,
  그 밖의 공격 트래픽은 도구 기본 지문을 따릅니다. 오래가는 탐지는 행동 기반입니다
  (방어 가이드 [한국어](../../docs/defense-ko.md) · [English](../../docs/defense-en.md) 1~2절·4.1~4.2절 참조). 순수 웹 다단계 사례는 여전히
  환경별 기본 규칙이 필요합니다.
- **정적 지표는 바꿀 수 있습니다.** 운영자가 User-Agent 를 다른 값으로 설정할 수 있으므로, 태그된
  지표가 없다고 해서 안전하다는 뜻은 아닙니다. 규칙 파일에도 같은 유의점을 달아 두었습니다.

## 검증과 기여

[일관성 테스트](../tests/attack/run.sh)를 돌리십시오. Docker 만 있으면 되며, 레이어가 점수를 매긴
기법·전술이 정확히 규칙의 `attack.*` 태그와 같은지, 그리고 모든 기법이 실재하는 규칙 파일에
근거하는지 단언합니다.

```sh
detections/tests/attack/run.sh
```

규칙을 추가하거나 다시 태그하면 이 레이어도 맞춰 갱신하십시오. 규칙의 기법이 레이어에 없거나
레이어의 기법이 규칙에 없으면 테스트가 실패합니다. [`../README.ko.md`](../README.ko.md)와
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)를 참조하십시오.
