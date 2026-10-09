# 소스 배포 검증 기록 · 2026-10-09

검증한 애플리케이션 소스 커밋은 `3379aa1`입니다. 이후 추가한 이 문서와 초기 설치 캡처는 검증 결과를 기록한 자료입니다. 기존 개발 환경을 복사하지 않고 해당 Git 커밋을 `git clone --no-local`로 별도 폴더에 복제했습니다.

## 새 설치

Docker Desktop의 Linux ARM64 환경에서 다음과 같이 기존 앱과 프로젝트·이미지·포트를 분리했습니다. LLM 공급자 관련 환경 변수는 비워 두었습니다.

```sh
ARTEX_PROJECT_NAME=artex-release-check \
ARTEX_LOCAL_IMAGE=artex-release-check:dev \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
./scripts/local-start.sh
```

| 확인 항목 | 실제 결과 |
|---|---|
| 클론 직후 운영 파일 | `.env.local`, `.local-runtime/`, `data/`, `evidence-local/` 없음 |
| 기본 서비스 | ARTEX·PostgreSQL 2개만 시작, 모두 healthy |
| 앱·프록시 포트 | `127.0.0.1:18887`, `127.0.0.1:18888` |
| 인증 초기화 상태 | `/api/auth/status`의 `initialized: false` |
| 기존 기록 | 작업·취약점·Splunk 연결·침해 조사 각각 0개 |
| 최초 화면 | 새 관리자 비밀번호 설정 화면; [실제 캡처](images/05-clean-install.png) |
| 외부 실행 | 실제 LLM·Splunk 호출 및 취약점 점검 실행 없음 |

Juice Shop은 이 설치 검증에 사용하지 않았습니다. 다른 [실습 캡처](README.md)는 별도로 실행했던 기존 실습 환경에서 확보했습니다.

## 실행한 검사

| 검사 | 결과와 범위 |
|---|---|
| `ARTEX_TEST_PROJECT_NAME=artex-release-test ./scripts/local-test.sh` | 새 클론에서 상위 테스트 150개 통과; 별도의 임시 PostgreSQL, 모의 LLM·TLS Splunk 사용 |
| `go test ./... -count=1` | 전체 패키지의 DB 없는 테스트 통과; DB 통합 경로는 위 별도 검사로 확인 |
| `go vet ./...` | 통과 |
| `npm run build:static` | 정적 웹 빌드·TypeScript 검사 통과 |
| `npm run check` | 오류 없이 통과; 기존 경고 126개·정보 747개는 남아 있음 |
| `python3 -I scripts/check-web-cjk.py` | 생성된 HTML 32개에서 한자 누출 0건 |
| `python3 -I scripts/check-doc-links.py` | 문서 내부 링크·이미지·앵커 검사 통과 |

일반 Go 검사는 외부 네트워크를 차단하고 운영 DB·호스트 환경을 전달하지 않은 임시 컨테이너에서 실행했습니다. 테스트 통과는 실제 침해 탐지 정확도나 모든 공급자·운영 SIEM과의 호환성을 입증하지 않습니다.

## 비밀·운영 데이터 제외

- 배포 후보와 상류를 포함한 과거 Git 이력을 Gitleaks 8.30.1 및 별도 키·개인키·JWT 패턴 검사로 검토했습니다. 실제 사용 가능한 자격 증명으로 확인된 항목은 없었습니다.
- Gitleaks 기본 규칙에서 나온 후보 5건·이력 8건은 마스킹 테스트의 합성 문자열과 과거 UI 데모의 인증 예시였습니다. 전체 파일을 예외 처리하거나 스캐너 오류를 무시해 통과시킨 결과가 아닙니다.
- 새 배포 변경분의 스테이징 검사에서는 Gitleaks 발견 0건이었습니다.
- 환경 파일, JWT 키, 운영 DB·덤프, 업로드 원본 로그, 전체 결과 내보내기는 Git에 포함하지 않았습니다. `.gitignore`와 두 Docker 빌드 제외 파일에 제외 규칙을 반영했습니다.
- 공개 이미지 5개는 별도로 육안 확인했습니다. API 키 설정 화면, 관리자 비밀번호, 연결 인증 정보, 원본 로그 전체를 포함하지 않습니다.

스캐너가 모든 비밀을 탐지하거나 이미지 픽셀을 자동 검사한다는 뜻은 아닙니다. 기존 개발자의 비밀과 데이터는 로컬에 그대로 보존하며, 배포 소스와 분리합니다.
