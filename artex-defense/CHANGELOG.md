# 변경 이력

한국어 · [English](CHANGELOG.en.md) · [中文(원본·상류)](CHANGELOG.zh.md)

이 문서는 ARTEX 한국어판(이 포크)이 상류 저장소에 더한 변경을 기록합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 를 참고합니다.

상류 ARTEX 프로젝트의 버전별 릴리스 이력(0.3.x 이하)과 기여자 목록은 원본 중국어 그대로 [`CHANGELOG.zh.md`](CHANGELOG.zh.md) 에 보존했습니다. 상류 변경과 대조하기 쉽도록 `README.zh.md` 와 같은 방식으로 원문을 그대로 남깁니다. 각 변경의 자세한 내용과 근거는 저장소 커밋 이력에서 확인할 수 있습니다.

## [Unreleased] · 한국어판 변경

### 현지화 (i18n)

- **사용자 노출 출력을 한국어로 강제했습니다.** 벤치마크된 에이전트의 행동 지침 본문(두뇌)은 성능 보존을 위해 원문 그대로 두고, 코드 고정 세그먼트(`langDirective`)로 사용자에게 보이는 산출물(취약점 리포트, 사실 요약, 최종 요약, 채팅 응답)만 한국어로 작성하도록 지시합니다. 명령·페이로드·코드·로그 원문은 원본을 보존합니다.
- **웹 UI 를 한국어로 옮겼습니다.** Next App Router 에 `next-intl` 을 도입하고 문자열을 `web/messages/ko.json` 과 `web/messages/zh.json` 으로 분리했습니다. 원본 중국어는 `zh.json` 에 보존해 상류 업데이트와 대조합니다. 대시보드·취약점·대화·알림 발송·가로채기·LLM 설정 등 화면 문자열을 한국어로 옮겼습니다.
- **서버 API 의 사용자 노출 오류·응답을 한국어로 옮겼습니다.** 브라우저로 돌아가는 HTTP 오류·응답 문구를 한국어로 교체했습니다. 단 에이전트 두뇌의 입력으로 되먹여지는 문구는 벤치마크 드리프트를 막기 위해 원문을 유지했고, 그 판정 근거는 저장소 작업 문서에 기록했습니다.
- **문서를 한국어로 정비했습니다.** 한국어 `README.md` 를 만들고 영어 `README.en.md` 를 함께 두었으며, 원본 중국어는 `README.zh.md` 로 보존했습니다.

### 방어·탐지 자료

- **방어·탐지 가이드를 추가했습니다.** 자율 AI 공격이 기존 스캐너와 무엇이 다른가, 방어자가 관측할 수 있는 지문(IoC), 진입점과 하드닝, 탐지 규칙, 사고 대응을 정리한 한국어 가이드([`docs/defense-ko.md`](docs/defense-ko.md))와 같은 내용의 영어판([`docs/defense-en.md`](docs/defense-en.md))을 두었습니다.
- **배포용 탐지 규칙을 제공합니다.** 가이드의 지문을 바로 쓸 수 있는 규칙으로 옮겼습니다. 호스트·로그 계층은 [Sigma](https://sigmahq.io) 원자·상관 규칙([`detections/sigma/`](detections/sigma/)), 네트워크 계층은 enrich 프로브와 norma SDK WebFetch 의 User-Agent 를 겨냥한 [Suricata](https://suricata.io) 규칙([`detections/suricata/`](detections/suricata/))으로 담았습니다.
- **ATT&CK 커버리지를 가시화했습니다.** 규칙이 태깅하는 기법을 MITRE ATT&CK Navigator 레이어([`detections/attack/`](detections/attack/))로 정리했습니다.
- **기계 판독 침해지표(IoC)를 표준 형식으로 제공합니다.** ARTEX 가 내보내는 고유 지문을 한 파일로 모은 CSV([`detections/indicators/artex_indicators.csv`](detections/indicators/artex_indicators.csv))와, 같은 지표를 위협 인텔리전스 플랫폼에 바로 가져올 수 있는 MISP 이벤트([`detections/indicators/artex_indicators.misp.json`](detections/indicators/artex_indicators.misp.json))로 담았습니다. 규칙이 받쳐 주는 지표는 `to_ids` 로, 호스트 포렌식 포트는 분류용 단서로 구분해 표기합니다.
- **재현 가능한 탐지 테스트를 붙였습니다.** 규칙을 실제로 돌려 증명하는 테스트 여덟 종(Sigma 구조·컴파일 검증, Sigma 실시간 이벤트 매칭, 백엔드 이식성, SigmaHQ 관례 린트, Suricata 로드·발화, ATT&CK 레이어 정합, 지표-소스 일치, MISP 내보내기 ↔ CSV 동기화)과 이를 한 번에 돌리는 일괄 러너·pre-commit 예시를 추가하고 CI 머지 게이트로 연결했습니다. Sigma 실시간 이벤트 매칭은 규칙이 컴파일될 뿐 아니라 악성 샘플 이벤트에는 실제로 발화하고 정상 이벤트에는 침묵하는지까지 원자·상관 규칙 모두에서 확인합니다.

### 저장소 정비

- **보안·오남용 경고와 국내법 고지를 넣었습니다.** README 최상단에 사용 범위, 정보통신망법·개인정보보호법 고지, 오남용 금지 경고를 추가했습니다.
- **한국어 UI 스크린샷으로 화면 미리 보기를 교체했습니다.**
- **메인테이너 런북과 기여 가이드를 정비했습니다.** 상류 동기화·번역 드리프트를 막기 위한 런북([`MAINTAINING.md`](MAINTAINING.md))과 탐지 규칙 기여 계약([`CONTRIBUTING.md`](CONTRIBUTING.md))을 두었습니다. 런북에는 릴리스 발행 파이프라인의 빌드 전제와, 태그 없이 로컬에서 그 전제를 검증하는 절차도 함께 정리했습니다.
- **푸시·PR 머지 게이트 CI 를 추가했습니다.** 상류 저장소는 태그 릴리스에서만 CI 가 돌았지만, 이 포크는 모든 푸시와 PR 에서 Go 빌드·정적 분석(`go vet`)·단위 테스트([`ci.yml`](.github/workflows/ci.yml)), 한국어 UI 정적 빌드([`web.yml`](.github/workflows/web.yml)), 문서의 저장소 내부 링크·이미지 참조 무결성([`docs.yml`](.github/workflows/docs.yml))을 돌려, 한국어화 과정에서 생긴 회귀를 머지 전에 잡습니다. 데이터베이스가 있어야 하는 통합 테스트는 패키지마다 격리된 PostgreSQL 서비스로 함께 검증합니다. 문서 링크 검사는 외부 네트워크에 의존하지 않는 결정론적 스크립트([`scripts/check-doc-links.py`](scripts/check-doc-links.py))로 돌려, 다국어 문서가 서로를 가리키는 많은 상대 링크와 화면 미리 보기 이미지가 깨진 채 머지되는 것을 막습니다. 문서 앵커(`#헤딩`) 링크도 GitHub 과 같은 slug 규칙으로 헤딩과 대조해, 헤딩 글자가 바뀌어 조용히 끊긴 목차·상호 참조 링크를 함께 잡습니다. 탐지 규칙 스위트는 위 '방어·탐지 자료' 절에서 설명한 머지 게이트가 담당합니다.
- **외부 링크 생존을 주기적으로 점검합니다.** 방어 가이드가 가리키는 사고 신고 창구·표준 참조 같은 외부 링크는 원격 서버 상태에 의존해 flaky 하므로 머지 게이트에서 빼고, 비차단 워크플로([`external-links`](.github/workflows/external-links.yml))가 매주 월요일과 수동 실행으로 브라우저 User-Agent·GET·리다이렉트 추적 점검([`scripts/check-external-links.py`](scripts/check-external-links.py))을 돌립니다. 호스트는 살아 있는데 확인 방법만 막힌 경우(봇 차단·속도 제한)와 우리가 고칠 수 없는 상류 상속 죽은 링크(allowlist)는 실패로 치지 않아, 우리 문서가 큐레이션한 외부 링크가 새로 깨질 때만 빨갛게 드러냅니다.
- **기여·거버넌스 인프라를 갖췄습니다.** 버그·기능·번역 이슈 템플릿([`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/))과 풀 리퀘스트 템플릿([`PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)), 보안 취약점 신고 정책([`SECURITY.md`](SECURITY.md)), 행동 강령([`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md))을 두어, 외부 기여자가 이슈·PR·보안 신고를 일관된 양식으로 제출하도록 했습니다.
- **해외 기여자를 위한 영어 문서 레이어를 완성했습니다.** 이 저장소는 한국어가 주 언어이지만, 한국어를 읽지 못하는 기여자·보안 연구자·방어자가 같은 정보에 도달하도록 핵심 문서의 영어판을 함께 두었습니다. 영어 `README.en.md`·방어 가이드([`docs/defense-en.md`](docs/defense-en.md))에 더해, 변경 이력([`CHANGELOG.en.md`](CHANGELOG.en.md)), 보안 신고 정책([`SECURITY.en.md`](SECURITY.en.md)), 행동 강령([`CODE_OF_CONDUCT.en.md`](CODE_OF_CONDUCT.en.md)), 기여 가이드([`CONTRIBUTING.en.md`](CONTRIBUTING.en.md)), 메인테이너 런북([`MAINTAINING.en.md`](MAINTAINING.en.md)), 트래픽 증거 설계 문서([`docs/finding-traffic-evidence-en.md`](docs/finding-traffic-evidence-en.md)), 그리고 버그·기능·번역 이슈 템플릿의 영어판을 갖췄습니다. 한국어판과 영어판은 머리말에서 서로를 가리켜, 어느 언어로 들어와도 반대쪽으로 이동할 수 있습니다. (풀 리퀘스트 템플릿은 현재 한국어판만 제공합니다.)

---

상류 ARTEX 프로젝트의 버전별 릴리스 이력과 기여자 목록은 [`CHANGELOG.zh.md`](CHANGELOG.zh.md) 에서 원문 그대로 볼 수 있습니다.
