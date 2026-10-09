#!/usr/bin/env bash
# ARTEX 설치 스크립트: ① 전부 Docker  ② 로컬 컴파일 실행
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── docker 환경 감지 / 자동 설치 ──────────────────
ensure_docker(){
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "docker 와 docker compose 를 확인했습니다"; return
  fi
  warn "docker / docker compose 를 찾을 수 없습니다"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask 'Docker 를 자동으로 설치할까요? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker 설치를 완료했습니다 (사용자 그룹 변경은 다시 로그인해야 sudo 없이 적용됩니다)"
      else
        die "docker 를 직접 설치한 뒤 다시 실행해 주세요"
      fi ;;
    Darwin) die "macOS 에서는 Docker Desktop 을 설치해 주세요: https://www.docker.com/products/docker-desktop/" ;;
    *)      die "docker 를 직접 설치한 뒤 다시 실행해 주세요" ;;
  esac
}

# ── ① 전부 Docker ──────────────────────────────
install_docker(){
  ensure_docker
  if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
    local pw key
    pw="$(ask 'Postgres 비밀번호 (엔터를 누르면 무작위 생성)' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY (비워 둬도 되며 나중에 UI 에서 설정)' '')"
    sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pw}|" .env
    sed -i.bak "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${key}|" .env
    rm -f .env.bak
    ok ".env 파일을 생성했습니다 (POSTGRES_PASSWORD 설정 완료)"
  else
    info "이미 있는 .env 파일을 그대로 사용합니다"
  fi
  info "이미지를 받아 기동합니다…"
  docker compose pull || true
  if ! docker compose up -d; then
    warn "상류 이미지 autumn27/artex 를 Docker Hub 에서 받을 수 없어 기동에 실패했습니다(현재 상류에서 내려간 상태라 pull 이 거부됩니다)"
    warn "한국어판 화면·출력은 이 스크립트를 다시 실행해 \"2) 로컬 실행 (go 컴파일)\" 을 고르거나, README \"소스에서 단일 바이너리 컴파일\" 경로로 빌드하세요"
    die "Docker Compose(전부 Docker) 경로는 현재 상류 이미지를 받을 수 없어 사용할 수 없습니다"
  fi
  ok "기동을 완료했습니다 → http://localhost:8787"
  info "로그 확인: docker compose logs -f artex"
}

# ── ② 로컬 컴파일 실행 ────────────────────────────
install_local(){
  echo "데이터베이스 설치 방식:"
  echo "  1) 기존 PostgreSQL 에 연결"
  echo "  2) Docker 로 PostgreSQL 하나 기동 (docker 필요)"
  case "$(ask '선택' 1)" in
    2)
      ensure_docker
      local pw; pw="$(ask 'Postgres 비밀번호 (엔터를 누르면 무작위)' "$(rand)")"
      docker run -d --name artex-pg -p 5432:5432 \
        -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=artex \
        -v artex-pg:/var/lib/postgresql/data postgres:16-alpine
      DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=artex DB_PASS="$pw" DB_NAME=artex DB_SSL=disable ;;
    *)
      DB_HOST="$(ask '데이터베이스 주소' 127.0.0.1)"
      DB_PORT="$(ask '포트' 5432)"
      DB_USER="$(ask '계정' artex)"
      DB_PASS="$(ask '비밀번호' '')"
      DB_NAME="$(ask '데이터베이스 이름' artex)"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)" ;;
  esac

  # config.json 생성
  cat > config.json <<JSON
{
  "database": {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "${DB_SSL}"
  }
}
JSON
  ok "config.json 파일을 생성했습니다"

  # go 환경 확인
  command -v go >/dev/null 2>&1 || die "Go 를 찾을 수 없습니다. 먼저 Go (>=1.26) 를 설치해 주세요: https://go.dev/dl/"
  ok "Go: $(go version)"

  # 프런트엔드를 내장하려면 node 로 정적 산출물을 만들어야 합니다
  if command -v npm >/dev/null 2>&1; then
    info "프런트엔드 정적 산출물을 빌드합니다…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist
    info "프런트엔드를 내장한 단일 바이너리를 컴파일합니다…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm 을 찾을 수 없습니다: 프런트엔드를 내장하지 않은 백엔드만 컴파일합니다 (프런트엔드는 npm run dev 로 따로 실행)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "컴파일을 완료했습니다 → ./artex"

  info "기동합니다… (Ctrl-C 로 종료)"
  ./artex
}

echo "=============================="
echo "  ARTEX 설치"
echo "  1) 전부 Docker 설치"
echo "  2) 로컬 실행 (go 컴파일)"
echo "=============================="
case "$(ask '선택' 1)" in
  1) install_docker ;;
  2) install_local ;;
  *) die "잘못된 선택입니다" ;;
esac
