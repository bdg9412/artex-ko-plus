# 기여 가이드 (Contributing)

한국어 · [English](CONTRIBUTING.en.md)

ARTEX 한국어판(`artex-ko`)에 관심을 가져 주셔서 고맙습니다. 이 문서는 기여를 시작하기 전에
알아 두어야 할 범위·방침·절차를 한국어로 정리한 것입니다. 기여를 보내기 전에 반드시
[사용 범위와 법적 책임](#사용-범위와-법적-책임)과 [현지화 방침](#현지화-방침)을 먼저 읽어 주십시오.

- 버그를 신고하거나 기능을 제안하려면 → [이슈 템플릿](https://github.com/jiwoochris/artex-ko/issues/new/choose)을 사용하십시오.
- 번역·현지화 오류를 발견했다면 → "번역·현지화 오류" 이슈 템플릿을 사용하십시오.
- 보안 취약점을 발견했다면 → **공개 이슈로 올리지 말고** [SECURITY.md](SECURITY.md)의 절차를 따라 주십시오.
- 모든 참여자는 [행동 강령(CODE_OF_CONDUCT.md)](CODE_OF_CONDUCT.md)을 지켜야 합니다.

---

## 사용 범위와 법적 책임

ARTEX 는 LLM 멀티 에이전트가 **자율적으로** 침투 테스트를 수행하는 공격 보안 도구입니다.
기여자도 사용자와 똑같은 범위 제한을 받습니다.

- 코드를 검증할 때는 **자신이 소유했거나 서면으로 명시적 허가를 받은 대상**, 또는
  **로컬 격리 환경**(예: Docker 로 띄운 OWASP Juice Shop·DVWA 같은, 의도적으로 취약하며
  본인이 소유한 대상)에만 도구를 실행하십시오.
- 허가 범위를 벗어난 실제·운영·원격 시스템에 스캐닝·탐지·익스플로잇을 수행하는 코드,
  또는 그런 사용을 조장하는 변경은 받지 않습니다.
- 대한민국에서 권한 없이 타인의 정보통신망에 침입하거나 장애를 일으키는 행위는
  「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 위반이며, 수집·노출되는 개인정보는
  「개인정보 보호법」의 적용을 받습니다. 자세한 고지는 [README](README.md#️-먼저-읽어-주세요--사용-범위와-국내법-고지)에 있습니다.

기여로 제출한 코드·문서가 어떻게 쓰이는지에 대한 법적 책임은 그것을 실행하는 사용자 본인이
부담합니다. 이 저장소는 "있는 그대로(AS IS)" 제공됩니다.

---

## 현지화 방침

이 저장소의 존재 이유는 원본 [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)의
**판단 성능을 그대로 보존하면서 사용자에게 보이는 산출물만 한국어로 바꾸는 것**입니다.
이 방침을 벗어나는 번역 기여는 성능을 떨어뜨릴 수 있으므로 받지 않습니다.

- **에이전트의 내부 추론 프롬프트(행동 지침 본문)는 번역하지 마십시오.** 원문(중국어)으로
  벤치마크된 동작을 유지해야 합니다. 이 본문은 `agent/promptcatalog.go` 와 DB 시드
  (`agent_prompts`)에 있습니다. 번역은 에이전트의 판단에 드리프트를 일으킵니다.
- **사용자에게 노출되는 산출물만 한국어로 강제합니다.** 탐지 결과(`report_finding`),
  사실 요약(`record_fact`), 최종 리포트, 대화 응답이 여기에 해당합니다. 이 강제는
  `agent/prompt.go` 의 `langDirective()` 라는 코드 고정 꼬리로 각 역할의 system
  프롬프트 말미에 붙습니다. 출력 언어를 바꾸려면 이 함수를 수정하십시오.
- **명령·페이로드·코드·URL·로그 원문은 번역하지 않습니다.** 분석에 필요한 원본이므로
  그대로 둡니다.
- **원본 중국어는 보존합니다.** 문서는 `README.zh.md`, UI 문자열은 `web/messages/zh.json`
  에 원문을 그대로 남겨 상류(upstream) 저장소의 변경과 대조하기 쉽게 합니다. 한국어
  번역은 `web/messages/ko.json` 에 채웁니다.
- UI 문자열을 새로 번역할 때는 하드코딩하지 말고 메시지 파일의 키로 추가하십시오.
- **출력 언어 강제는 하드 캡이 아니라 프롬프트 유도입니다.** `langDirective()` 는 출력 언어를
  한국어로 **지시**할 뿐, 강제로 고정하지는 않습니다. 그래서 한국어 충실도는 모델 역량·역할·
  맥락에 따라 달라집니다. 현지화 변경을 검증할 때는 역량 있는 모델(프런티어급)을 쓰십시오.
  저가·소형 모델은 리포트·요약이 원문(중국어)으로 되돌아갈 수 있으므로, 번역이 제대로 적용됐는지를
  저가 모델의 출력만으로 판단하지 마십시오. OpenAI 계열 모델을 쓸 때의 `max_tokens` 설정 함정은
  [README 의 "모델 선택과 출력 언어" 절](README.md#모델-선택과-출력-언어)에 정리되어 있습니다.
- **상류(upstream) 변경을 따라잡는 절차는 메인테이너 안내 문서에 있습니다.** 원본 ARTEX 가
  갱신됐을 때 보존 자산과 번역 대상을 가려서 반영하고, 번역 대칭과 드리프트를 검사하는 런북은
  [MAINTAINING.md](MAINTAINING.md)에 정리되어 있습니다.

---

## 개발 환경

이 프로젝트는 **Go 백엔드**(단일 바이너리에 프런트엔드를 내장) + **Next.js 프런트엔드**로
구성됩니다.

주요 기능의 설계 의도는 `docs/` 의 설계 문서에 정리되어 있습니다. 취약점과 트래픽 증거를
연결하는 기능(보고서 에이전트의 자동 바인딩, `report_finding` 의 `traffic_refs` 등)을
다룰 때는 [취약점 다중 트래픽 증거 설계 문서](docs/finding-traffic-evidence-ko.md)를 먼저
읽으십시오. 원문(중국어)은 같은 폴더의 `finding-traffic-evidence-zh.md` 에 보존되어 있습니다.

### 요구 버전

- Go 1.26 이상 (`go.mod` 기준)
- Node.js 22 이상 (릴리스 워크플로 기준)
- Docker 와 Docker Compose (로컬 실행·검증용)

### 백엔드 (Go)

로컬에 Go 가 설치되어 있다면 저장소 루트에서 다음을 실행합니다.

```bash
go build ./...
go vet ./agent/
go test ./agent/
```

로컬에 Go 가 없다면 Docker 로 동일하게 검증할 수 있습니다. 모듈·빌드 캐시를 named volume
에 두면 재실행이 빨라집니다.

```bash
docker run --rm -v "$PWD":/src -w /src \
  -v artexko-gomod:/go/pkg/mod -v artexko-gocache:/root/.cache/go-build \
  golang:1.26 sh -c 'go build ./... && go vet ./agent/ && go test ./agent/'
```

#### DB 통합 테스트 (postgres 필요)

위의 `go test ./agent/` 는 PostgreSQL 에 붙어야 도는 **DB 통합 테스트를 조용히
건너뜁니다.** `agent`·`config`·`db`·`evidence`·`llmrec`·`server` 여섯 패키지에는 실제
데이터베이스가 있어야 도는 테스트가 들어 있는데, 환경 변수 `ARTEX_PG_DSN` 도 없고 설정
파일에도 `database` 항목이 없으면 그 테스트들은 `--- SKIP` 으로 넘어가고 패키지는 `ok` 로
끝납니다. 그래서 이 여섯 패키지를 고친 뒤 DSN 없이 검증하면 **로컬은 통과(ok)하는데 PR 의
`go-db` 작업은 실패**할 수 있습니다.

이 테스트들을 로컬에서 돌리려면 PostgreSQL 을 띄우고 `ARTEX_PG_DSN` 을 건넵니다. 아래는
CI 와 같은 `postgres:16-alpine` 을 격리 네트워크에 띄워 돌리는 예시이며, 위와 같은 named
volume 을 재사용합니다.

```bash
# 1) 격리 네트워크와 빈 postgres 를 띄웁니다 (CI 와 같은 이미지·계정).
docker network create artexko-db 2>/dev/null || true
docker run -d --name artexko-pg --network artexko-db \
  -e POSTGRES_USER=artex -e POSTGRES_PASSWORD=artex -e POSTGRES_DB=artex \
  postgres:16-alpine
until docker exec artexko-pg pg_isready -U artex -d artex >/dev/null 2>&1; do sleep 1; done

# 2) DSN 을 건네 DB 통합 패키지를 돌립니다 (DSN 의 host 는 컨테이너 이름입니다).
#    고친 패키지만 돌리려면 ./agent/ 자리를 config·db·evidence·llmrec·server 로 바꿉니다.
docker run --rm --network artexko-db -v "$PWD":/src -w /src \
  -v artexko-gomod:/go/pkg/mod -v artexko-gocache:/root/.cache/go-build \
  -e ARTEX_PG_DSN='postgres://artex:artex@artexko-pg:5432/artex?sslmode=disable' \
  golang:1.26 sh -c 'go test ./agent/ -count=1'

# 3) 정리합니다.
docker rm -f artexko-pg && docker network rm artexko-db
```

CI 의 `go-db` 작업은 이 여섯 패키지를 **각각 자체 postgres 로 격리해** 머지 전에 강제로
돌립니다(`.github/workflows/ci.yml`). DB 통합 패키지를 고쳤다면 PR 을 올리기 전에 위
방법으로 해당 패키지를 직접 확인하기를 권합니다.

### 프런트엔드 (web)

```bash
cd web
npm ci
npm run dev          # 개발 서버
npm run build        # 프로덕션 빌드
npm run build:static # 정적 내보내기 빌드(머지 게이트 · TypeScript 타입 검사 포함)
npm run check        # Biome 린트·포맷 검사(정보용 · 선재 부채로 아직 머지 게이트 아님)
npm run check:fix    # 자동 수정
```

커밋 전 포맷·린트는 Biome 으로 관리합니다. `lint-staged` 가 스테이징된 파일에 대해
`biome check --write` 를 자동으로 돌립니다.

### 전체 실행 (Docker Compose)

```bash
cp .env.example .env     # POSTGRES_PASSWORD 설정
docker compose up -d     # artex + postgres 기동 → http://localhost:8787
```

---

## 기여 절차

1. 먼저 **이슈를 엽니다.** 큰 변경은 작업을 시작하기 전에 이슈로 방향을 맞추는 편이
   좋습니다. 작은 수정(오타·링크·명백한 버그)은 바로 PR 을 보내도 됩니다.
2. 저장소를 **포크**하고 주제 브랜치를 만듭니다. 브랜치 이름은 `feat/...`, `fix/...`,
   `docs/...`, `i18n/...` 처럼 변경 성격을 앞에 둡니다.
3. 변경을 작성하고 **해당 범위의 검증을 직접 돌립니다.** Go 변경이면 위의
   `build`·`vet`·`test` 를 통과시킵니다. web 변경이면 `npm run build:static`
   (머지 게이트 · TypeScript 타입 검사를 함께 수행합니다)을 통과시킵니다.
   `npm run check`(Biome)는 상류에서 딸려온 선재 린트 부채가 남아 있어 아직 머지
   게이트가 아니고 `web.yml` 에서 정보용 단계로만 돌리므로, 전체를 통과시킬 필요는
   없습니다. 대신 **내 변경이 새 오류를 더하지 않았는지**만 확인하면 됩니다(커밋할 때
   `lint-staged` 가 스테이징한 파일에만 `biome check --write` 를 자동으로 적용합니다).
   문서(`.md`)를 바꿨다면 `python3 -I scripts/check-doc-links.py` 로 저장소 안
   링크·이미지 참조와 문서 앵커(`#헤딩`) 링크가 깨지지 않았는지 확인합니다. 앵커는
   GitHub 과 같은 규칙으로 헤딩에서 slug 를 만들어 대조하므로, 헤딩 글자를 바꾸면서
   그 헤딩을 가리키던 앵커 링크를 함께 고치지 않으면 여기서 걸립니다(CI 의 `docs`
   워크플로가 같은 검사를 머지 게이트로 강제합니다). 이 검사는 저장소 루트의
   [`.pre-commit-config.yaml`](.pre-commit-config.yaml)에 `docs` 훅으로도 들어 있어,
   `pre-commit install` 을 해 두면 커밋할 때 자동으로 돌아갑니다(파이썬 표준 라이브러리만
   쓰고 네트워크에 접속하지 않아 Docker 없이 끝납니다).
4. **PR 을 엽니다.** 제목·설명은 [PR 템플릿](.github/PULL_REQUEST_TEMPLATE.md)을 따르고,
   무엇을 왜 바꿨는지와 어떻게 검증했는지를 적습니다. UI 를 바꿨다면 스크린샷을 첨부합니다.
5. 사용자에게 보이는 변경(기능·현지화·문서·탐지 규칙 등)이라면 [변경 이력(CHANGELOG.md)](CHANGELOG.md)
   의 `[Unreleased]` 절에 한 줄을 더합니다. 내부 리팩터링이나 테스트 전용 변경은 생략해도 됩니다.

### 커밋 메시지

기존 커밋 이력의 관례를 따릅니다. 형식은 `type(scope): 설명` 이며, 설명은 한국어로 씁니다.

- `type`: `feat` · `fix` · `docs` · `chore` · `refactor` · `test` · `i18n` 등
- `scope`: 바뀐 영역(`agent` · `web` · `server` 등), 생략 가능

예시입니다.

```
feat(agent): 사용자 노출 출력을 한국어로 강제 (langDirective)
docs: 한국어 README 작성, 원본은 README.zh.md 로 보존
i18n(web): 대시보드 네비게이션 라벨 한국어 번역
```

---

## 탐지 규칙·탐지 테스트 기여

이 저장소는 ARTEX 같은 자율 AI 공격을 **방어·탐지**하기 위한 규칙을 [`detections/`](detections/)에 함께
둡니다. 배포 가능한 [Sigma](https://sigmahq.io) 규칙([`detections/sigma/`](detections/sigma/)), 네트워크용
[Suricata](https://suricata.io) 규칙([`detections/suricata/`](detections/suricata/)),
[MITRE ATT&CK](https://attack.mitre.org/) 커버리지 레이어([`detections/attack/`](detections/attack/)), 그리고
이 규칙들이 실제로 발화하는지 재현 가능하게 증명하는 테스트([`detections/tests/`](detections/tests/))로
이루어져 있습니다. 탐지 규칙을 새로 보내거나 고칠 때는 아래 계약을 지켜 주십시오. 여덟 테스트 스위트가 이
계약의 상당 부분을 기계적으로 강제하므로, 규칙만 바꾸고 테스트·레이어를 갱신하지 않으면 테스트가 실패합니다.

- **모든 지표를 관측 가능한 사실에 접지합니다.** 규칙이 쓰는 문자열·User-Agent·행동 임계값은 이 저장소
  소스에서 실제로 확인되는 것이어야 하고, 추정으로 만들지 않습니다. 근거가 되는 소스 파일을 규칙 안에
  밝혀 주십시오(예: `artex-enrich/1.0` 지표는 `enrich/enrich.go` 에서 확인됩니다). 지표 일치 테스트
  ([`detections/tests/indicators/`](detections/tests/indicators/))가 각 지표가 상류 소스와 규칙 양쪽에
  여전히 있는지 검사하므로, 상류 재동기화로 소스 문자열이 바뀌면 규칙을 함께 고치지 않는 한 테스트가 실패합니다.
  기계 판독 지표 목록([`detections/indicators/artex_indicators.csv`](detections/indicators/artex_indicators.csv))을
  바꾸면, 그 지표를 그대로 담은 MISP 이벤트([`detections/indicators/artex_indicators.misp.json`](detections/indicators/artex_indicators.misp.json))도
  함께 갱신합니다. MISP 내보내기 테스트([`detections/tests/misp/`](detections/tests/misp/))가 두 파일이 행
  단위로 일치하는지, 그리고 그 이벤트가 pymisp 로 적재되는 유효한 MISP 문서인지 강제합니다.
- **한계를 정직하게 적습니다.** Sigma 규칙은 `description` 에, Suricata 규칙은 주석에 그 규칙이 못 잡는
  경우와 오탐 가능성을 적습니다. ARTEX 고유 시그니처가 아니라 일반 헌팅 리드(예: 파괴 명령)라면 그렇게
  명시해, 한 번의 적중만으로 공격자를 ARTEX 로 단정하지 않게 합니다.
- **정적 검증을 통과시킵니다.** Sigma 규칙은 SigmaHQ 검증기 기준을 이슈 0 으로 통과해야 합니다
  (`sigma check --validation-config detections/tests/sigma_lint/validators.yml`). 기본 `sigma check` 는
  pySigma 핵심 검증기만 돌리므로, 제목 표기·필드/로그소스 분류·참조 링크 같은 SigmaHQ 관례는 이 기준으로만
  걸러집니다. 네 가지 예외는 단독 규칙 세트에 맞지 않는 SigmaHQ 모노레포 관례이고, 그 사유를
  [`detections/tests/sigma_lint/validators.yml`](detections/tests/sigma_lint/validators.yml) 에 적어 두었습니다.
  Suricata 규칙은 `suricata -T` 로 깨끗이 로드되어야 합니다.
- **재현 가능한 테스트를 함께 보냅니다.** 규칙이 발화하는지(또는 구조가 유효한지)를
  [`detections/tests/`](detections/tests/) 아래 테스트로 증명합니다. 입력은 바이너리를 저장소에 넣지 말고
  매번 결정론적으로 생성하고, 엔진 버전에 무관한 속성(발화 존재·오탐 없음)은 정확히 단언하며, 버전에 따라
  흔들리는 수치는 하한으로 단언하고 기준값을 따로 기록합니다. Sigma 상관 규칙을 더하거나 고치면 백엔드
  이식성 테스트([`detections/tests/sigma_backends/`](detections/tests/sigma_backends/))가 그 규칙이 여러
  백엔드에서 변환되는지 확인하므로, [`detections/README.md`](detections/README.md) 의 백엔드 지원 설명과
  어긋나지 않게 유지해 주십시오.
- **ATT&CK 레이어를 함께 갱신합니다.** 규칙에 `attack.*` 태그를 더하거나 바꾸면
  [`detections/attack/artex_navigator_layer.json`](detections/attack/artex_navigator_layer.json) 의 기법·점수도
  맞춰 갱신합니다. 정합 테스트가 규칙↔레이어 양방향 일치를 강제하므로, 레이어에 없는 규칙 태그나 규칙에
  없는 레이어 기법이 있으면 실패합니다.
- **공격 안내로 읽히는 내용을 넣지 않습니다.** 이 저장소의 탐지 자료는 방어·탐지 포지셔닝만 유지합니다.
  익스플로잇 수행 방법이나 탐지 우회 기법처럼 공격을 돕는 서술은 받지 않습니다.

여덟 테스트 스위트는 Docker 만 있으면 그대로 돌릴 수 있고, 생성물을 저장소에 커밋하지 않습니다. 각 스크립트는
단언이 하나라도 실패하면 0 이 아닌 코드로 끝나므로 CI 나 pre-commit 훅에 바로 넣을 수 있습니다.

```bash
detections/tests/sigma/run.sh           # Sigma: sigma check + 백엔드 변환 + 지표 보존
detections/tests/sigma_match/run.sh     # Sigma: 원자 규칙이 악성 샘플에 발화·정상 샘플에 침묵
detections/tests/sigma_lint/run.sh      # Sigma: SigmaHQ 관례 전체 검증기 + 문서화된 기준
detections/tests/sigma_backends/run.sh  # Sigma 이식성: 상관 규칙이 여러 백엔드에서 변환되는지
detections/tests/suricata/run.sh        # Suricata: pcap 합성 → suricata -r → 경보 수 단언
detections/tests/attack/run.sh          # ATT&CK: 레이어 ↔ 규칙 양방향 정합
detections/tests/indicators/run.sh      # 지표: 규칙의 고정 지표 ↔ 상류 소스 양방향 일치
detections/tests/misp/run.sh            # MISP: 지표 CSV ↔ MISP 이벤트 동기화 + pymisp 유효성
```

여덟을 한 번에 돌리려면 [`detections/tests/run-all.sh`](detections/tests/run-all.sh)를 쓰십시오. CI 와 같은
순서로 여덟을 순차 실행하고, 앞선 스위트가 실패해도 나머지를 끝까지 돌린 뒤 스위트별 PASS/FAIL 요약을
출력하며, 하나라도 실패하면 0 이 아닌 코드로 끝납니다. 이 러너를 pre-commit 훅으로 바로 거는 설정 예시가
저장소 루트의 [`.pre-commit-config.yaml`](.pre-commit-config.yaml)에 있습니다. `pip install pre-commit &&
pre-commit install` 로 설치하면, 탐지 규칙이나 그 규칙이 고정한 상류 소스가 바뀌는 커밋에서만(CI 와 같은
범위) 러너가 돌아 규칙·테스트 불일치를 푸시 전에 잡습니다. 같은 설정 파일에는 문서 내부 링크·이미지·앵커를
검사하는 `docs` 훅(위 기여 절차 3번의 `check-doc-links.py`)도 함께 들어 있습니다.

이 여덟 테스트는 저장소 CI([`.github/workflows/detections.yml`](.github/workflows/detections.yml))가
`detections/` 아래가 바뀐 푸시·PR 마다 돌립니다. 지표 일치 테스트는 그 지표가 가리키는 상류 소스 파일
(`enrich/`·`selfupdate/`·`guard/`·`db/`·`cmd/artex/main.go`)이 바뀔 때도 돌아, 상류 재동기화가 User-Agent·
마커·기본 포트를 바꿔 규칙이 조용히 낡는 경우를 함께 잡습니다. 따라서 규칙만 바꾸고 테스트·레이어를 갱신하지 않은 변경, SigmaHQ 관례를
깨뜨린 규칙, 또는 소스와 어긋난 규칙은 머지 전에 CI 에서 빨갛게 드러납니다.

규칙 색인과 각 규칙의 근거·한계는 [`detections/README.md`](detections/README.md)에, 테스트의 단언 항목과
실행법은 [`detections/tests/README.md`](detections/tests/README.md)에 정리되어 있습니다.

---

## 라이선스

이 프로젝트는 **GNU Affero General Public License v3.0(AGPL-3.0)** 으로 배포됩니다.
기여물을 제출하면, 그 기여물도 **AGPL-3.0 으로 공개된다는 데 동의**하는 것으로 봅니다.
특히 이 프로젝트를 수정해 네트워크를 통해(예: 온라인 서비스로) 사용자에게 제공한다면,
그 사용자에게 대응하는 완전한 소스 코드를 공개해야 합니다. 전체 조항은 [LICENSE](LICENSE)
파일에 있습니다.
