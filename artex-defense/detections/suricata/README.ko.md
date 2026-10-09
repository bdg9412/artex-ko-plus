# ARTEX 탐지 규칙 (Suricata / 네트워크)

한국어 · [English](README.md)

[Sigma 규칙](../sigma/)의 네트워크 계층 짝입니다. 이 [Suricata](https://suricata.io) 시그니처는
네트워크 선에서 관측되는 두 가지 ARTEX 산출물을 다루며, 모든 지표는 추정이 아니라 이 저장소
소스에서 확인한 문자열이나 행동에 근거합니다. 호스트·로그·SIEM 계층은 [`../sigma/`](../sigma/)에
있고, 전체 그림은 방어 가이드([한국어](../../docs/defense-ko.md) · [English](../../docs/defense-en.md))가
설명합니다.

## 규칙: [`artex.rules`](artex.rules)

- **sid 1000001**: `ARTEX enrichment prober User-Agent`. User-Agent 가 `artex-enrich/` 로 시작하는
  인바운드 HTTP `GET` 입니다(자산 보강 프로버 `enrich/enrich.go:233`). 단건 요청 존재 지표입니다.
  `classtype: attempted-recon`.
- **sid 1000002**: `ARTEX enrichment prober high-rate enumeration`. 같은 User-Agent 가
  `detection_filter` 임계인 **출처당 300초에 30요청** 을 넘는 경우입니다. 단건 규칙이 놓치는, 기계
  속도로 쏟아내는 빈도입니다. Sigma 상관 규칙 `artex_enrich_scan_velocity` 를 반영합니다.
  `classtype: attempted-recon`.
- **sid 1000003**: `ARTEX worker WebFetch User-Agent`. User-Agent 가 `norma/` 로 시작하는 인바운드
  HTTP 요청입니다(norma SDK 의 WebFetch 도구 `github.com/Autumn-27/norma/tool/webfetch.go`). 이 UA 는 norma 전 버전
  (v0.1.0–v0.4.3, 검증 완료)에 걸쳐 하드코딩되어 있으며, 기록 프록시가 요청 헤더를 수정하지
  않으므로(`traffic/traffic.go`) 대상 호스트 와이어에 그대로 도달합니다. 보강 프로버와 달리
  **공격 단계**(능동적 취약점 프로빙) 에서 발화합니다. `classtype: attempted-recon`.

## 범위와 정직함: 배포 전에 읽으십시오

- **두 가지 ARTEX User-Agent 가 네트워크에서 관측됩니다.** 보강 프로버는 정찰 단계에서
  `artex-enrich/1.0`(`enrich/enrich.go:233`)을, norma SDK 의 WebFetch 도구는 공격 단계에서
  `norma/0.4`(`github.com/Autumn-27/norma/tool/webfetch.go`)를 보냅니다. 기록 프록시(`traffic/traffic.go`)는 요청 헤더를
  변경하지 않으므로 두 UA 모두 대상 와이어에 도달합니다. 그 외 worker 도구(Bash 하위 프로세스인
  `curl`, `nmap` 등)는 자체 User-Agent 를 사용하므로, 일반 스캐너 시그니처와
  [`../sigma/`](../sigma/)의 행동 기반 SIEM 규칙으로 탐지하십시오.
- **User-Agent 는 평문에서만 보입니다.** 트래픽이 평문 HTTP 이거나 TLS 를 종단하는 프록시·WAF 에서
  검사될 때 나타납니다. 종단 간 TLS 는 이것을 암호화하므로, 실제로 HTTP 요청 버퍼를 볼 수 있는
  자리에 배포하십시오.
- **정적 User-Agent 는 운영자가 바꿀 수 있으므로**, 없다고 해서 안전하다는 뜻은 **아닙니다**.
  오래가는 신호는 행동, 곧 속도와 폭입니다. sid 1000002(그리고 Sigma 상관 계층)가 속도를 기준으로
  삼는 이유, 그리고 순수 웹 다단계 탐지가 환경별 기본 규칙을 필요로 하는 이유가 여기에 있습니다.
- **의도적으로 뺀 것.** 자가 업데이트 User-Agent `artex-selfupdate` 는 GitHub 로 HTTPS 를 타고 가므로
  네트워크에서 관측되지 않습니다(TLS SNI 만으로는 경보를 걸기에 너무 흔합니다). 감사 통제 마커는
  대상을 향하는 트래픽이 아니라 운영자 측 로그 산출물이므로,
  [`../sigma/artex_guard_audit_framing.yml`](../sigma/artex_guard_audit_framing.yml)로 탐지하십시오.
  서버 포트 `:8787` 과 기록 프록시 `127.0.0.1:8788`(`cmd/artex/main.go`)은 네트워크 시그니처가
  아니라 호스트 포렌식용(`ss`·`netstat`)입니다.
- **지표 하나는 이 저장소의 소스가 아니라 고정된 의존성에 근거합니다.** 맨 위에서 모든 지표가 이 저장소
  소스에서 확인한 것이라고 밝혔는데, sid 1000003 이 그 유일한 예외입니다. 이 규칙의 `norma/` User-Agent 는
  norma SDK(`github.com/Autumn-27/norma/tool/webfetch.go`)에 하드코딩되어 있고, ARTEX 는 이 SDK 를 저장소
  트리로 들여오지(vendoring) 않고 `go.mod` 에 `v0.4.3` 으로 고정한 의존성으로 가져다 쓰므로, 이 문자열은
  저장소 안의 파일이 아니라 고정된 상류 의존성(v0.1.0–v0.4.3 에 걸쳐 하드코딩됨, 검증 완료)에 근거를
  둡니다. 지표 근거 테스트가 ARTEX 자체 방출 문자열은 다시 읽어도 이 값만은 다시 읽지 못하는 이유가
  여기에 있습니다. 같은 단서를 [지표 목록](../indicators/README.ko.md)도 밝혀 두었으며, 위의 "이 저장소
  소스에서 확인" 문장이 명시되지 않은 예외 없이 성립하도록 여기에도 적어 둡니다.

## 검증과 테스트

Suricata 8 로 검증했습니다. 적재 테스트는 트래픽이 필요 없고 항상 돌아갑니다.

```sh
# 문법 + 엔진 적재 테스트 (기대: "Configuration provided was successfully loaded")
docker run --rm -v "$PWD/detections/suricata":/r -w /r jasonish/suricata:latest \
  suricata -T -S artex.rules -l /tmp --init-errors-fatal
```

`--init-errors-fatal` 은 파싱은 되지만 초기화에 실패하는 규칙도 하드 에러로 만들어, 조용히 버려진
시그니처가 있으면 적재 테스트가 통과하지 못하게 합니다.

규칙이 실제로 발화하는지 확인하려면, 재현 가능한 회귀 테스트가 [`../tests/suricata/`](../tests/suricata/)에
있습니다. 먼저 같은 적재 점검을 돌리고, scapy 로 결정적 캡처를 합성한 뒤 그 위에서 `suricata -r` 를
돌려 경보 수를 단언합니다. Docker 만 있으면 됩니다.

```sh
detections/tests/suricata/run.sh
```

sid 1000001 이 프로브마다 정확히 한 번씩 발화하고(35플로 캡처에서 35회), sid 1000002 가 300초에 30
임계를 넘으며(Suricata 8.0.7 에서 **5**회 경보, 31~35번째 플로), 같은 캡처를 양성(benign) 브라우저
User-Agent 로 돌리면 경보가 **0** 임을 단언합니다. 시그니처가 특이함을 확인하는 것입니다.
[`../tests/README.ko.md`](../tests/README.ko.md)를 참조하십시오. 대신 자신의 트래픽으로 확인하려면, 로컬
서버에 대해 루프백 `curl -A 'artex-enrich/1.0'` 을 캡처해 경보를 읽으십시오.

```sh
suricata -r enrich.pcap -S artex.rules -l out && \
  grep -c '"signature_id":1000001' out/eve.json    # 존재: 프로브마다 한 번
```

## 기여

탐지 기여를 환영합니다. 새 규칙은 모든 지표를 관측 가능한 사실에 근거해 두고, 한계를 주석에
밝히며, `suricata -T` 를 깨끗이 통과하고, 공격 안내로 읽히는 내용을 담지 않아야 합니다.
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)와 [`../sigma/`](../sigma/)의 Sigma 계층 /
[`../README.ko.md`](../README.ko.md)를 참조하십시오.
