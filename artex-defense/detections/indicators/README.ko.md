# ARTEX 침해지표 (기계가 읽는)

한국어 · [English](README.md)

ARTEX 가 스스로 내보내는 고유 지문을 한 파일로 모은, 기계가 읽는 목록입니다. 탐지 로직이 아니라
원자 지표 자체를 원하는 방어자를 위한 것입니다: [`artex_indicators.csv`](artex_indicators.csv)를
위협 인텔리전스 플랫폼이나 SIEM 조회 테이블, 호스트 분류(triage) 체크리스트에 바로 넣으십시오.
모든 값은 이 저장소 소스에서 확인한 문자열입니다. [탐지 규칙](../README.ko.md)과 방어 가이드
([한국어](../../docs/defense-ko.md) · [English](../../docs/defense-en.md) 2절)가 근거로 삼는 바로
그 문자열입니다. 각 행은 그 값이 어디서 오는지와 (있다면) 그 위에 세운 규칙을 적습니다.

## 열 구성

- **`id`**: 지표의 안정적인 슬러그입니다.
- **`type`**: 지표의 종류입니다: `http.user-agent`, `string`(로그·파일에서 찾을 리터럴), `port`,
  `ip-dst|port`, `other`(위 범주에 들지 않는 호스트 아티팩트, 예: 데이터베이스 스키마 객체 이름).
  이들은 대응하는 MISP/STIX 속성 타입에 매핑됩니다.
- **`value`**: 정확한 지표입니다. 비 ASCII 가드 마커를 포함해 원문 그대로 보존합니다.
- **`perspective`**: `target`(ARTEX 가 탐침하는 시스템을 *향하는* 트래픽에서 관측) 또는
  `forensic`(ARTEX 가 실행됐거나 경유한 호스트 *위에서* 관측)입니다. 방어 가이드는 이 둘을 일부러
  구분합니다. 섞으면 틀린 결론이 나옵니다.
- **`source`**: 그 값을 내보내는, 저장소 기준 상대 경로 소스 파일입니다(`;` 로 구분). 이것이
  근거입니다: 상류 재동기화가 내보내는 쪽을 바꾸면 여기 지표도 함께 바뀌어야 합니다.
- **`rule`**: 그 정확한 값 위에 세운 탐지 규칙입니다(`;` 로 구분). (시끄러운) 규칙으로 내보내지
  않고 직접 분류하는 호스트 포렌식 지표는 비어 있습니다.
- **`description`**: 한 줄 설명이며, 해당하는 경우 정직한 유의점을 함께 적습니다.

## MISP 이벤트 내보내기

같은 지표를 바로 가져올 수 있는 [MISP](https://www.misp-project.org/) 이벤트
[`artex_indicators.misp.json`](artex_indicators.misp.json)로도 제공합니다. MISP 인스턴스를 운영하는
(또는 MISP 형식을 적재하는 위협 인텔리전스 플랫폼을 쓰는) 방어자는 CSV 열을 손으로 매핑하지 않고
지문을 바로 가져올 수 있습니다. STIX 2.1 은 MISP 자체 변환기로 한 번 내보내면 되므로, 저장소가
손실 있는 두 번째 형식을 따로 만들지 않습니다.

- **타입 매핑.** 각 CSV `type` 은 대응하는 MISP 속성 타입이 됩니다: `http.user-agent` →
  `user-agent`, 가드 마커 `string` → `pattern-in-file`(카테고리 *Artifacts dropped*), `port` →
  `port`, `ip-dst|port` → `ip-dst|port`(합성 값은 MISP 의 `ip|port` 형식을 쓰므로 `127.0.0.1:8788`
  은 `127.0.0.1|8788` 로 저장됩니다), 탐색 그래프 스키마 지문 `other` → `other`(카테고리 *Other*).
- **`to_ids` 는 `rule` 열을 정직하게 따릅니다.** 탐지 규칙이 세워진 행은 조치 가능한 지표이므로
  `to_ids: true` 로 표시합니다. 규칙이 없는 호스트 포렌식 행(기본 수신 포트와 루프백 프록시
  엔드포인트, 그리고 탐색 그래프 스키마 지문)은 차단용 IoC 가 아니라 분류 힌트이므로
  `to_ids: false` 에 `disable_correlation: true` 로 둡니다(흔한 포트나 `127.0.0.1`, 또는 범용 테이블
  이름이 MISP 상관을 오염시키면 안 됩니다). 이는 CSV 의 `rule` 열과 아래 유의점이 이미 담고
  있는 것과 같은 구분입니다.
- **가져오기.** [pymisp](https://github.com/MISP/PyMISP)로
  `MISPEvent().load_file("artex_indicators.misp.json")`, 또는 *Add event → Populate from … → MISP
  format* UI, 또는 REST API 로 가져옵니다. 이벤트는 미발행 상태이고 `tlp:clear` 태그가 붙어
  있습니다. 가져올 때 인스턴스에 맞는 배포 범위와 발행 상태를 설정하십시오.

## 이 목록을 정직하게 읽는 법

- **이것들은 바뀔 수 있는 지문이지 안전의 증거가 아닙니다.** 운영자가 User-Agent 를 다른 값으로
  설정하거나 기본 포트를 바꿀 수 있으므로, 여기 있는 어떤 값이 *없다고* 해서 ARTEX 가 없다는 뜻은
  **아닙니다**. 오래가는 신호는 행동입니다. 상관 규칙과 방어 가이드 1·2·4.1~4.2절을 참조하십시오.
- **일반 헌팅 단서는 의도적으로 뺐습니다.** 파괴적 셸·DB 명령(`rm -rf`, `DROP DATABASE`, …)은 ARTEX
  지문이 *아닙니다*. 정당한 관리자도 실행합니다. 가져오기용 지표가 아니라 헌팅 단서이므로, 이
  목록이 아니라 [`destructive_command_hunting.yml`](../sigma/destructive_command_hunting.yml)과 방어
  가이드에 둡니다. 이것들을 차단용 지표로 가져오면 오탐이 생깁니다.
- **norma 의 WebFetch User-Agent 는 네트워크 서명이지 가져오기용 원자 지표가 아닙니다.** 워커의
  페이지 가져오기 도구는 공격 단계에서 `norma/0.4` 를 보내고 Suricata 규칙 sid 1000003 이 `norma/`
  접두사에 발화하지만, 그 문자열은 norma SDK 에 하드코딩된 자체 User-Agent(`github.com/Autumn-27/norma/tool/webfetch.go`)여서
  norma 위에 세운 모든 도구가 똑같이 내보내는 값이지 ARTEX 고유 지문이 아닙니다. 이 값을 차단용
  지표로 이 목록에 넣으면 모든 norma SDK 트래픽에 경보가 울리는데, 이는 파괴적 명령을 뺀 것과 같은
  오탐 함정입니다. 그래서 norma UA 는 이 목록에서 의도적으로 빼고 네트워크 규칙으로만 싣습니다
  ([`../suricata/README.ko.md`](../suricata/README.ko.md), sid 1000003). 또한 이 값은 이 저장소의
  소스가 아니라 고정된 의존성(`github.com/Autumn-27/norma`)에 근거를 두므로, 아래의 근거 테스트가
  ARTEX 자신이 내보내는 문자열을 다시 읽듯이 이 값을 다시 읽을 수는 없습니다.
- **호스트 포렌식 포트는 차단이 아니라 분류용입니다.** `:8787` 과 `127.0.0.1:8788` 은 ARTEX 를
  돌리고 있을 수 있는 호스트를 가리킵니다. `ss`·`netstat` 로 확인하고, 맹목적으로 방화벽을 걸지
  마십시오.
- **탐색 그래프 스키마 지문은 네트워크·파일 IoC 가 아니라 DB 조사용입니다.** `exploration_nodes`
  테이블은 ARTEX 가 PostgreSQL 에 두는 탐색 그래프의 핵심 테이블입니다. 단독 적중으로 단정하지
  말고, 형제 테이블(`exploration_edges`·`exploration_anchors`·`assets`·`companies`·`activity`)과
  `agent_prompts` 시드가 같은 데이터베이스에 함께 있는지로 확인하십시오. 운영자가 테이블을 바꾸거나
  지울 수 있으므로 부재가 안전을 뜻하지는 않습니다.
- **`rule` 이 비어 있는 호스트·DB 행에는 실행기가 있습니다.** Sigma 규칙으로 싣지 않고 직접 분류하는 세
  지표, 곧 리슨 포트·기록 프록시 엔드포인트·이 스키마 지문은 [호스트 분류 스크립트](../triage/)가 의심
  호스트에서 모두 점검합니다. 그래서 셸 접근은 있으나 SIEM 이 없는 대응자가 `ss`·`netstat`·`psql`
  을 손으로 돌리지 않아도 됩니다.

## 검증

이 목록은 [지표 근거(source-of-truth) 테스트](../tests/indicators/run.sh)가 덮습니다. 이 CSV 를 다시
읽어 모든 행에 대해, 그 값이 인용한 소스 파일에 여전히 있고 인용한 규칙에 고정돼 있는지, 그리고
테스트가 근거로 삼는 모든 지표가 목록에 나타나는지 단언합니다. 소스에서 어긋난 행이나 목록에서 빠진
알려진 지문이 있으면 테스트가 실패합니다. 다음으로 돌리십시오.

```sh
detections/tests/indicators/run.sh
```

MISP 이벤트는 자체 [MISP 내보내기 일관성 테스트](../tests/misp/run.sh)가 덮습니다. 이벤트를 pymisp
로 적재해(모든 속성 타입이 서버가 받아들이는 실재 MISP 타입이 되도록) 이 CSV 와 행 단위로
동기화됨을 단언합니다. 곧 같은 값, 의도한 타입·카테고리, 그리고 `rule` 열에 맞춘 `to_ids` 플래그입니다.
이벤트는 CSV 와 나란히 손으로 관리합니다. CSV 가 지니지 않는, 속성별로 정리한 주석·안정적인
UUID·이벤트 수준 태그도 함께 지니므로, 손실 있는 기본값으로 이것들을 덮어쓸 생성기가 없습니다.
CSV 행을 더하거나 빼거나 타입을 바꿀 때는 같은 커밋에서
[`artex_indicators.misp.json`](artex_indicators.misp.json)도 맞춰 고치십시오(새 속성에는 새 `uuid` 와
근거가 되는 `comment` 를 주십시오). 둘이 일치할 때까지 이 테스트가 실패하므로, 갱신을 조용히 잊을
수 없습니다. 다음으로 돌리십시오.

```sh
detections/tests/misp/run.sh
```
