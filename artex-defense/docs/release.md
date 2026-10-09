# 소스 배포와 새 체크아웃 검증

배포 단위는 이 저장소의 소스와 문서입니다. 기본 실행은 `Dockerfile.local`에서 소스를 빌드하고 `docker-compose.local.yml`로 **ARTEX와 PostgreSQL**을 시작합니다. 공개되지 않은 상류 ARTEX 이미지, 개발자의 API 키, 기존 운영 DB가 필요하지 않습니다. Juice Shop은 화면 증적을 만들 때 별도로 사용한 실습 대상이며 기본 제품 배포에 포함하지 않습니다.

## 처음 받는 사용자의 실행 순서

1. 저장소를 clone하거나 소스 압축을 내려받아 압축을 풉니다.
2. Docker Desktop 또는 Docker Engine과 Compose v2를 실행합니다.
3. 저장소 루트에서 다음 명령을 실행합니다.

```sh
./scripts/local-start.sh
```

현재 UI와 Go 백엔드를 컨테이너 안에서 빌드하므로 호스트 Go·Node.js는 필요하지 않습니다. 최초 빌드는 이미지, 패키지와 브라우저 런타임을 내려받습니다.

[http://localhost:8787/setup/](http://localhost:8787/setup/)에서 본인의 관리자 비밀번호를 설정합니다. 취약점 점검·재검증이나 AI 조사를 실행할 때는 **시스템 → LLM 설정**에서 본인이 사용할 연결을 설정합니다. 초기 실행과 파일 근거 준비에는 모델 키가 필요하지 않습니다. Splunk를 사용할 때만 자신의 검색 계정 또는 토큰으로 연결합니다.

스크립트는 `.env.local`에 임의 DB 비밀번호, `.local-runtime/jwt.key`에 로그인 서명·연결 인증 정보 암호화용 키를 생성합니다. 기존 파일은 유지하며, 기존 키가 비어 있으면 자동 교체하지 않고 복구를 요청합니다. JWT 키는 해당 DB와 함께 로컬에 보존해야 하며 공개 저장소에 포함하지 않습니다.

자세한 운영 명령과 포트 변경은 [로컬 실행 안내](local-development.md)를 참고하세요. 루트의 기존 `install.sh`·`docker-compose.yml`은 상류 참고 경로이며, 이 확장의 기본 설치 절차가 아닙니다.

## 테스트

저장소 루트에서 실행합니다.

```sh
./scripts/local-test.sh
python3 -I scripts/check-doc-links.py
```

첫 명령은 별도의 `artex-purple-test` Compose 프로젝트와 임시 PostgreSQL을 사용합니다. 동시 검증에서는 `ARTEX_TEST_PROJECT_NAME=artex-clean-test ./scripts/local-test.sh`처럼 다른 테스트 프로젝트 이름을 지정할 수 있습니다. 실서비스 DB·실제 LLM·실제 Splunk에 접근하지 않고 확장 기능의 통합 테스트를 수행한 뒤 테스트 컨테이너를 정리합니다. 두 번째 명령은 Python 3가 있는 호스트에서 문서 내부 경로와 앵커를 검사합니다.

`local-start.sh`의 소스 빌드에는 프런트엔드 정적 빌드와 Go 컴파일이 포함됩니다. 테스트의 TLS 모의 Splunk는 연결·검색 범위·인증 정보 처리·원문 보존을 확인하지만, 기업 환경의 실제 로그 수집이나 탐지 품질을 검증한 것은 아닙니다. 모델 실행 테스트 역시 모의 응답으로 실행 제어를 검증하며 실제 공급자 호출의 성공을 보장하지 않습니다.

## 공개 파일의 범위

| 포함 | 제외 |
|---|---|
| 애플리케이션 소스, 의존성 잠금 파일, 테스트 | `.env`, `.env.local`, 기타 실제 환경 설정 파일 |
| 소스 빌드용 Dockerfile·Compose·실행 스크립트 | JWT 키, API 키, 인증 토큰, 인증서 개인키 |
| README와 기능·개발·배포 문서 | `data/`, `.local-runtime/`, `evidence-local/`, DB 덤프·볼륨 |
| 검토한 별도 로컬 실습 화면 | 원본 업로드 로그, 운영 취약점·조사 결과 전체 내보내기 |
| 원본 및 한국어판의 저작권 표시와 라이선스 | 개발자 전용 워크스페이스·검증 산출물 |

테스트 코드의 가상 계정·토큰과 설명용 예시는 실제 접근 권한이 없는 픽스처입니다. 실사용 값을 테스트 예시로 바꾸어 저장하면 안 됩니다. `.gitignore`는 신규 파일을 제외할 뿐, 이미 추적된 파일이나 과거 커밋에서 비밀을 제거하지 않습니다.

공개할 커밋에서 다음을 확인합니다.

- `git status --short`와 `git diff --cached --stat`로 의도한 소스·문서·검토된 화면만 포함됐는지 확인합니다.
- 새 파일뿐 아니라 실제 공개될 Git 이력에서도 API 키·비밀번호·JWT·원본 로그·DB 덤프를 제외합니다.
- 화면의 사용자 정보, 연결 주소, 로그 내용에 공개하면 안 되는 값이 없는지 직접 확인합니다.
- 초기 설정 화면에서 새 관리자 비밀번호를 요구하는지, 다른 사용자의 작업·로그·연결이 없는지 확인합니다.
- 기본 실행으로 별도 실습 앱이나 Splunk가 생성되지 않는지 확인합니다.

## 독립된 체크아웃에서 확인하기

기존 개발 폴더의 `.env.local`, `.local-runtime`, `data/`를 복사하지 않은 새 체크아웃을 사용합니다. 동일 컴퓨터에 기존 앱이 실행 중이라면 프로젝트·이미지·호스트 포트를 분리합니다.

```sh
ARTEX_PROJECT_NAME=artex-clean-check \
ARTEX_LOCAL_IMAGE=artex-clean-check:dev \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
./scripts/local-start.sh
```

[http://localhost:18887/setup/](http://localhost:18887/setup/)에서 새 초기 설정 화면을 확인합니다. 키·DB를 복사하지 않았으므로 기존 개발자의 로그인, LLM 연결, 작업과 로그가 나타나면 안 됩니다. 이 명령은 자체 데이터 볼륨을 만들며 실제 점검이나 AI 조사를 자동 실행하지 않습니다.

확인이 끝나면 같은 프로젝트 이름으로 테스트용 앱을 중지합니다. 아래 명령은 데이터를 삭제하지 않습니다.

```sh
ARTEX_PROJECT_NAME=artex-clean-check \
ARTEX_LOCAL_IMAGE=artex-clean-check:dev \
ARTEX_LOCAL_PORT=18887 \
ARTEX_LOCAL_PROXY_PORT=18888 \
docker compose --env-file .env.local -f docker-compose.local.yml stop
```

실습 화면과 실제 확인한 범위는 [공개 증적 안내](evidence/README.md)에 분리해서 기록합니다. 구현·테스트 통과, 로컬 화면 확인, 실제 외부 시스템 검증을 같은 성공으로 표현하지 않습니다.
