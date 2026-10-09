# `/btw` 검증 기록

한국어 · [中文](VALIDATION.zh.md)

날짜: 2026-09-10. 브랜치: `codex/btw-side-question`. 기준 커밋(baseline): `8dae851b9b622f2ff2631f332fde9719d0b16fba`.

> 이 문서는 원본 중국어 문서(`VALIDATION.zh.md`)를 한국어로 옮긴 것입니다. 상류(upstream) 저장소의 변경을 대조하기 쉽도록 원본은 그대로 보존합니다.

독립된 PostgreSQL 테스트 DB 와 데이터 디렉터리를 사용했습니다. 실제 모델 자격 증명은 독립 테스트 환경에만 주입했고 코드나 이 기록에는 쓰지 않았으며, 제품 기본 모델도 바꾸지 않았습니다. Go 1.26.3, norma v0.3.6, Next.js 16.2.9.

실제 모델 대화, 반환 객체, 엔지니어링 단언, Qwen 원본 심사 텍스트는 [validation-2026-09-10.json](validation-2026-09-10.json) 에 저장했으며, 그 안에는 API 자격 증명이 없습니다.

## 엔지니어링 검사

아래 항목은 모두 통과했으며, 괄호 안은 근거 테스트입니다.

- 구조화 메시지와 도구 인자의 깊은 복사: 통과(근거 `TestCheckpointDeepCopyAndBoundaries`).
- 요약·압축 요청이 덮어쓰지 않음, 완결된 응답과 종료 상태 발행, 생성 도중 반쪽 응답 제외: 통과(근거 `TestCheckpointDeepCopyAndBoundaries`, `TestSnapshotExcludesPartialStreamAndSelectsPoolMember`).
- 실제 모델 풀 구성원 신원: 통과(근거 `TestSnapshotExcludesPartialStreamAndSelectsPoolMember`).
- 도구 짝 맞추기, 20 묶음 재생, 예산 삭감과 초과 오류: 통과(근거 `TestBuildRequestCompactionToolPairingAndBudget`).
- 메인과 곁질문의 병렬 실행, 양방향 취소 격리: 통과(근거: 블로킹 방식 Provider, `TestMainSideConcurrencyAndIndependentCancellation`).
- 도구 실행 없음, 스트리밍·비스트리밍, 실패 시점의 기존 사용량: 통과(근거 `TestServiceNoToolsAndUsageOnFailure`).
- 실제 norma ChatAgent 와 로컬 Read 도구, 메인 transcript·활동 격리: 통과(근거 `TestSideActualChatCheckpointToolResultAndTranscriptIsolation` 의 스트리밍·비스트리밍 하위 사례).
- 영속화, 페이지 나누기, 멱등성, 재시작 후 부분 응답 보존: 통과(근거 `TestSideHistoryIdempotencyPagingAndRecovery`).
- 비우기와 뒤늦은 쓰기의 경쟁, 부모 리소스 삭제, 버전 비교: 통과(근거 `TestSideClearLateWritersAndDeletedParent`).
- MainAgent·Worker 아카이브와 복원(v1·v2·v3): 통과(근거 `TestSideTaskArchiveVersions`).
- 세 가지 부모 인터페이스, 인증, 리소스 귀속, Worker 논리 삭제: 통과(근거 `TestSideHTTPGlobalLimitTaskWorkerAndDeletion`, `TestSideCheckpointPersistsBeforeAdmissionAndRestart`).
- 바쁜 메인 세션에서도 곁질문 가능, 독립 SSE 재연결·끊김, 취소, 비우기: 통과(근거 `TestSideHTTPBusyIsolationClearAndReconnect`).
- 부모 세션당 1 개·전역 4 개 동시 실행: 통과(근거: 두 개의 `TestSideHTTP…` 사례).
- 제출 전 스냅샷 저장, 재시작 후 이어 묻기, 오래된 세션이 스냅샷을 위조하지 못함: 통과(근거 `TestSideCheckpointPersistsBeforeAdmissionAndRestart`).
- 캐시에 있는 설정이 삭제되거나 모델이 바뀌면 계속 진행을 거부: 통과(근거 `TestSideRejectsDeletedOrChangedCachedProfile`).
- 아카이브 전에 취소하고 최종 응답과 사용량이 저장되기를 기다림: 통과(근거 `TestSideTaskDrainPersistsBeforeArchive`).
- 스트리밍 소비자가 일찍 취소해도 사용량을 한 번만 기록하고 곁질문에 귀속: 통과(근거 `TestSideUsageRecordedOnceOnConsumerCancellation`).
- 재시작으로 자동 복원된 Worker·deadline 실행 컨텍스트가 계속 새 스냅샷을 발행: 통과(근거 `TestSideRestoredWorkerRuntimePublishesNewCheckpoint`).
- 관련 패키지의 race 검사: 통과(근거: 아래 명령).
- TypeScript 와 프로덕션 빌드: 통과(근거 `npx tsc --noEmit`, `npm run build`).
- 새로 추가한 프런트엔드 모듈의 Biome 검사: 통과(근거 `biome check`, 새 모듈 3 개).

따로 버려도 되는 데이터베이스에 `ARTEX_PG_DSN` 을 설정하면 자동화 검사를 재현할 수 있습니다(운영 DB 를 가리키지 마십시오):

```sh
go test -race ./agent ./db ./server ./sidequestion ./llmrec ./llmpool \
  -run 'Test(Side|Checkpoint|Snapshot|BuildRequest|Service|MainSide|CaptureRun|TaskArchive|CompleteForwards|StopIntent|CancelIntent)' -count=1
cd web
npx tsc --noEmit
npx biome check src/lib/side-questions.ts src/hooks/use-side-questions.ts src/components/side-question-workspace.tsx
npm run build
```

전체 Go 회귀 테스트는 모두 통과(green)는 아닙니다. `server` 패키지의 기존 테스트 두 개가 임시 디렉터리 정리 단계에서 실패하며, 둘 다 `TempDir RemoveAll … directory not empty` 를 보고합니다:

- `TestInheritedActivityDetailAndRelationDeletion`
- `TestTaskMetadataPatchReturnsRenameAndPin`

위의 수정하지 않은 기준 커밋에서 소스를 내려받아 같은 격리 환경에서 `server` 패키지를 다시 돌려도 이 두 정리 실패가 똑같이 재현됩니다. 기준 커밋 실행에서는 `TestCoreTaskLifecyclePG` 의 대상 노드 개수 단언 실패도 따로 나타났으나, 최종 수정본의 `server` 회귀에서는 그 단언 실패가 없었습니다. 다른 패키지는 통과했고, 이번 곁질문 관련 사례와 race 검사도 통과했습니다. 기준 커밋의 문제를 이번 검수 통과로 표시하지 않았고, 숨은 문제를 가리려고 기존 단언을 바꾸지도 않았습니다.

Next.js 빌드는 여러 lockfile·workspace 루트 추론에 관한 기존 경고를 출력하지만, 빌드는 완료되고 모든 페이지가 성공적으로 생성됩니다.

## 브라우저 검사

Codex 내장 브라우저로 독립된 로컬 Go 서비스와 Next.js 개발 서버에 연결했습니다. 데스크톱과 390 × 844 좁은 화면에서 다음 수동·자동 조작을 수행하고 스크린샷과 브라우저 로그를 확인했습니다:

- 일반 채팅이 실행되는 동안 `/btw` 를 입력하면 본문 내용과 곁질문이 동시에 표시되고, 데스크톱 사이드바도 정상입니다.
- 이어서 추가 질문을 했습니다. 곁질문을 중지해도 이미 생성된 부분은 남고, 본문 흐름은 계속됩니다.
- 패널을 닫아도 요청은 계속되고, 다시 열면 완결된 응답을 복구합니다. 페이지를 새로 고친 뒤 내용 없이 `/btw` 만 입력하면 기록을 복구합니다.
- 좁은 화면 Drawer 에서 입력, 버튼, 기록, 닫기 조작이 정상이며 가로 넘침이 없습니다.
- 비우기는 확인 팝업을 띄우고, 비운 뒤에는 기록이 사라지지만 메인 transcript 와 스냅샷은 그대로 남습니다.
- 작업의 MainAgent 와 두 Worker 에게 각각 질문하고 전환했을 때, 에이전트 탭과 기록이 서로 섞이지 않았습니다.
- 블로킹 방식 로컬 모델 픽스처로 Worker 를 계속 실행시킨 상태에서, Worker 의 메인 입력창으로 `/btw` 를 제출했습니다. 곁질문을 중지한 뒤에도 Worker 는 실시간 실행 상태와 자신의 일시정지 버튼을 그대로 표시했고, 곁질문은 부분 응답을 저장했습니다.
- 브라우저 오류·경고 로그가 비어 있습니다.

제어 가능한 픽스처는 동시 실행 타이밍을 정밀하게 검증하려고 쓴 것이며, 실제 모델의 출력 속도에 의존하지 않습니다. 디버깅 중 두 번의 Worker 실행 검사에서는 유효한 동시 실행 구간이 만들어지지 않았는데(작업이 이미 끝났거나 응답이 미리 끝남), 픽스처를 고쳐 다시 수행해 통과했습니다. 이 초기 조작은 유효한 통과로 치지 않습니다.

## 실제 모델 대화

먼저 `grok-4.6` 을 탐지했습니다. OpenAI 호환 인터페이스는 `http://127.0.0.1:12580/tingly/openai` 입니다. 탐지 결과 HTTP 200 과 함께 모델 이름 `grok-4.6` 및 `READY` 를 반환했고, 2.82 초가 걸렸습니다. 1순위가 사용 가능했으므로 Tingly 의 `glm` 이나 Zhipu 의 `glm-5.3` 예비 체인은 켜지 않았고, 이 두 예비 서비스는 이번에 검증하지 않았습니다.

- 메인 세션이 실행되는 동안 자산·목표·표식을 질문: `redhaze.top`, 첫 페이지 읽기와 목표 요약, `BTW-REAL-0910` 을 반환했고 곁질문이 완료됨(16.97 초).
- 메인 세션이 첫 페이지 읽기를 마친 뒤 도구 근거를 질문: WebFetch 200, curl 의 301 → 302 → 200 리다이렉트, 페이지 제목을 정확히 인용함(7.24 초).
- 곁질문이 Bash 로 테스트 파일을 만들라고 요구: 실행을 거부했고 대상 파일이 생성되지 않음(7.74 초).
- 완료 후의 곁질문이 메인 컨텍스트를 바꾸지 않음: 메인 transcript 의 SHA-256 과 메인 활동 기록이 그대로 일치했고, 곁질문의 도구 실행 횟수는 0.
- Go 서비스를 실제로 중지·재시작한 뒤 이어서 질문: 이전 곁질문 기록 3 건을 보존했고, 영속화한 스냅샷에서 바로 자산·표식·제목을 답했으며 메인 에이전트를 다시 돌리지 않음.
- 새 세션에서 Grok 비스트리밍 설정 사용: 자산과 `ATOMIC-0910` 을 정확히 답했고, 사용량을 반환·저장함(input 11734, output 138, cache_read 11520).

자산 사례의 메인 세션은 WebFetch 와 Bash/curl 로 공개된 첫 페이지를 읽었고, 랜딩 페이지는 `https://id.redhaze.top/home`, 페이지가 반환한 제목은 "红幕科技 RedHaze Group · 全球综合集团门户" 였습니다(모델이 반환한 원문이라 그대로 인용). Bash 는 응답을 로컬 테스트 파일에 잠시 저장했을 뿐 원격에 쓰기를 실행하지 않았습니다. 이 사실은 "곁질문이 도구를 실행하지 않았다"는 점과 따로 확인했습니다.

메인 transcript 검증값: `e7e61f135a4a120954b539f357e8c4205d7d5cd7460dcaf3dc0fd066463e1d00`.

**사용량 한계:** Tingly 의 Grok 스트리밍 응답은 usage 를 반환하지 않았습니다. 따로 `stream_options.include_usage=true` 를 직접 보내 검증했을 때 HTTP 200, 데이터 프레임 12 개, usage 프레임 0 개였습니다. 따라서 스트리밍 테스트에서의 0 은 엔드포인트가 사용량을 제공하지 않는다는 뜻이며, 과금이 없었다는 뜻으로 해석해서는 안 됩니다. 비스트리밍 사용량과 픽스처의 실패·취소 사용량은 모두 올바르게 저장됐습니다.

## Qwen 심사

심사 모델은 `qwen-flash`, OpenAI 호환 인터페이스는 `https://dashscope.aliyuncs.com/compatible-mode/v1`, HTTP 200 입니다. 앞의 세 가지 실제 곁질문 대화, 메인 세션의 도구 근거, 엔지니어링 단언을 제공했고, `verdict: accept` 와 `concerns: []` 를 반환했습니다. 응답이 자산·표식·페이지 읽기 증거와 일치하고 곁질문 도구 거부가 제약에 부합한다고 판단했습니다. 심사 사용량: prompt 6625, completion 312, total 6937.

이번 Qwen 심사 범위에는 나중에 추가한 서비스 재시작과 비스트리밍 테스트가 들어가지 않습니다. Qwen 의 "쓰기 없음" 이라는 일반화는 지나치게 넓습니다. 메인 세션의 curl 은 실제로 로컬 응답 임시 파일을 만들었고, 이는 앞에서 명확히 기록했습니다. 동시성, 도구 실행 0 회, transcript 격리는 엔지니어링 단언으로 판단하며, 모델 심사는 응답 품질 평가를 보조할 뿐입니다.
