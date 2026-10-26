# GitHub 소스 배포 검증 증적 — 2026-10-26

이 기록은 GitHub용 **소스 ZIP**의 빌드·테스트와 공개 범위를 설명합니다. 로컬 DB, 모델 프로필, 실제 로그, 자격증명이나 과거 조사 내보내기는 배포하지 않습니다. 포함된 화면 이미지는 별도 로컬 실습에서 얻은 기능 예시이며 새 설치의 실행 결과가 아닙니다.

## 검증 결과

| 확인 항목 | 실행 명령 또는 방법 | 결과 |
|---|---|---|
| 배포 경계·무결성 단위 테스트 | `python3 -m unittest scripts.tests.test_package_release` | 11개 테스트 통과 |
| 백엔드 통합 테스트 | `./scripts/local-test.sh` | 임시 PostgreSQL을 쓰는 독립 Compose 프로젝트에서 통과, 종료 후 프로젝트 정리 |
| Bedrock·Ollama 제공자 테스트 | 테스트 이미지의 `agent.test -test.run 'Test(Bedrock\|Ollama)'` | 통과 |
| Bedrock·Ollama 프로필 저장/API 테스트 | 임시 PostgreSQL에서 `db.test`, `server.test`의 Bedrock·Ollama 관련 테스트 | 모두 통과, 종료 후 프로젝트 정리 |
| 웹 UI·Go 서버 이미지 빌드 | `docker build -f Dockerfile.local -t aegisloop-release-check:20261026 .` | 성공. 웹 정적 빌드 단계는 Docker 캐시 재사용, Go 실행 파일은 현재 소스에서 빌드 |
| 전달할 소스에서 이미지 빌드 | 생성한 GitHub 소스 폴더에서 `docker build -f Dockerfile.local ...` | 성공. 실행 중인 앱은 교체하지 않음 |
| 문서 참조 검사 | `python3 -I scripts/check-doc-links.py` | 내부 링크·이미지·앵커의 깨진 참조 0건 |

위 테스트는 모의 모델·모의 Splunk와 격리된 데이터베이스를 사용합니다. 실제 공급자의 모델 호출, 특정 AWS 계정의 권한, 운영 SIEM의 로그 수집·탐지 정확도를 증명하지 않습니다.

## 현재 로컬 실습 화면 증적

아래 네 이미지는 2026-10-26 로컬 실습 화면을 다시 캡처한 것입니다. 원본 요청·응답, PIN, API 키, 토큰과 계정 자격증명은 포함하지 않았습니다. 새 설치에 이 실행 기록이나 모델 프로필이 함께 생성되지는 않습니다.

### 취약점 진단

![취약점 10의 진단 요약과 재검증 기록](guide-images/diagnosis-finding-10-20261026.jpg)

[취약점 #10 진단 화면](guide-images/diagnosis-finding-10-20261026.jpg)은 비밀번호 재설정 API의 PIN 노출을 심각도로 기록하고, 재검증 #8·#9가 **취약점 재현**으로 저장된 상태를 보여 줍니다. 이는 이 실습 자산에서의 ARTEX 진단 결과이며 일반 환경의 취약성이나 방어 상태를 입증하지 않습니다.

### 방어 검증

![취약점 10의 방어 검증 실행과 근거 판정](guide-images/defense-finding-10-20261026.jpg)

[방어 검증 화면](guide-images/defense-finding-10-20261026.jpg)에서 실행 #7의 재진단은 취약점 재현으로 끝났습니다. 같은 실행의 Splunk 근거 조회는 완료됐지만 연결된 감사로그와 경보가 각각 **0건**이므로 탐지·차단은 모두 **판단 불가**입니다. 취약점 재현을 탐지 실패나 차단 실패로 해석하지 않습니다.

### 침해 조사

![취약점 10의 침해 조사 결과와 자료 부족 상태](guide-images/investigation-finding-10-20261026.jpg)

[침해 조사 화면](guide-images/investigation-finding-10-20261026.jpg)은 저장된 조사 범위의 이벤트 **0건**, AI 조사 상태 **추가 로그 필요**를 보여 줍니다. 이 실행에서 모델 호출은 1회였고 후속 로그 조회는 0회였습니다. 검색 결과 0건은 과거 침해가 없었다는 증거가 아닙니다.

### Ollama·Amazon Bedrock 설정 상태

![저장된 Ollama와 Bedrock Converse 프로필의 정상 표시](guide-images/llm-ollama-bedrock-status-20261026.jpg)

[LLM 프로필 상태 화면](guide-images/llm-ollama-bedrock-status-20261026.jpg)에는 로컬 Ollama와 Amazon Bedrock Converse의 **저장된 프로필이 ‘정상’으로 표시**됩니다. 이 이미지는 연결 테스트 결과 화면이 아니므로 캡처 시점의 실시간 응답이나 Bedrock의 모든 모델 호환성을 입증하지 않습니다. 모델 ID는 예시로 보이지만 키·키 힌트·계정번호는 보이지 않습니다.

## 공개 범위와 비밀값 확인

- GitHub README에 Anthropic, OpenAI Chat Completions/Responses, Ollama, Amazon Bedrock Converse의 **사용자 선택 절차**를 문서화했습니다. Bedrock의 모델 ID 또는 추론 프로필은 사용자가 자신의 계정에 맞게 입력합니다.
- 소스 ZIP은 현재 작업 트리의 공개용 소스만 복사합니다. `.env`·`.env.local`, 런타임 서명 키, 데이터베이스·원본 로그, 로컬 증적과 발표 자료는 제외합니다. `.env.example`의 DB 비밀번호는 실제 값 대신 교체 지시용 문자열입니다.
- 선택형 Offensive 실습 Compose의 JWT/앱 서명 키는 저장소의 고정 문자열 대신 로컬 준비 스크립트가 생성하는 환경값을 요구합니다. SMTP 인증을 끈 실습의 비밀번호 필드는 비웠습니다.
- `docs/guide-images/`의 공개용 로컬 실습 화면은 키·암호와 EXIF 메타데이터를 확인했습니다. 화면의 내부 실습 주소·검증 식별자는 실습 예시이며 운영 환경의 주소·인증 정보가 아닙니다.
- [LLM 제공자 선택 화면](guide-images/llm-model-selection-20261026.jpg)은 새 프로필의 빈 입력 폼과 제공자 목록만 캡처했습니다. 저장된 키나 계정 정보는 표시하지 않습니다.
- 패키지에는 `SOURCE_MANIFEST.sha256`과 ZIP 체크섬 파일이 생성됩니다. 두 파일로 복사된 소스와 전달된 ZIP의 무결성을 확인할 수 있습니다.

배포 폴더와 ZIP의 파일 목록·SHA-256 일치 여부를 확인했습니다. 로컬 환경 파일, 개인키, 데이터베이스, 패킷 캡처와 발표 자료는 포함되지 않았습니다. 공개 폴더의 `gitleaks` 결과 8건은 마스킹·오류 분류 테스트 코드의 합성 키 형태 픽스처로 확인했고, 실제 접속 가능한 비밀값은 발견하지 못했습니다. ZIP에는 Git 이력이 들어가지 않으므로, 이 기록은 기존 저장소 이력 전체의 공개 안전성을 보증하지 않습니다.
