#!/usr/bin/env bash
# ARTEX 업데이트 스크립트: ① Docker 업데이트(새 이미지를 받아 재구성)  ② 로컬 컴파일 업데이트(바이너리 재빌드)
# install.sh 와 짝을 이룹니다. install 은 최초 설치를, update 는 새 버전으로의 업그레이드를 담당합니다.
# DB 마이그레이션은 직접 실행할 필요가 없습니다. artex 는 기동할 때마다 schema.sql 을 멱등하게 다시 돌리므로(ADD COLUMN/CREATE
# INDEX IF NOT EXISTS 포함) "재시작이 곧 마이그레이션"입니다. 데이터(pgdata 볼륨, ./data, ./skills)는 영향을 받지 않습니다.
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }

# ── 선택: 저장소를 최신 코드로 동기화합니다(compose·스크립트·로컬 컴파일 소스가 모두 이걸로 갱신됩니다) ───────
sync_repo(){
  [ -d .git ] && command -v git >/dev/null 2>&1 || { warn "git 작업 사본이 아니라 git pull 을 건너뜁니다"; return; }
  [ "$(ask '최신 코드를 받을까요 (git pull --ff-only)? (y/n)' y)" = y ] || return
  if ! git pull --ff-only; then
    warn "git pull 을 빨리 감기로 진행하지 못했습니다(로컬 변경이 있거나 브랜치가 갈라졌습니다). 직접 처리한 뒤 다시 시도하세요. 이번에는 현재 코드를 그대로 사용합니다"
  fi
}

# ── ① Docker 업데이트 ───────────────────────────────
update_docker(){
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
    || die "docker / docker compose 를 찾을 수 없습니다. 먼저 ./install.sh 로 설치·배포하세요"
  [ -f .env ] || die ".env 를 찾을 수 없습니다. 먼저 ./install.sh 로 최초 배포를 완료하세요"

  # 선택: 지정한 버전 tag 로 업그레이드합니다(비워 두면 .env 의 ARTEX_TAG 를 따르고, 기본값은 latest 입니다)
  local tag; tag="$(ask '대상 이미지 tag(엔터를 누르면 .env / latest 사용)' '')"
  if [ -n "$tag" ]; then
    if grep -q '^ARTEX_TAG=' .env; then
      sed -i.bak "s|^ARTEX_TAG=.*|ARTEX_TAG=${tag}|" .env && rm -f .env.bak
    else
      printf '\nARTEX_TAG=%s\n' "$tag" >> .env
    fi
    ok "ARTEX_TAG 를 ${tag} 로 설정했습니다"
  fi

  # artex 만 건드립니다. postgres 는 16-alpine 로 고정이라 따라 올릴 필요가 없습니다(받아 봐야 대역폭 낭비이고,
  # 메이저 버전이 바뀌면 호환성 위험도 있습니다). artex 는 depends_on postgres 를 선언하므로 서비스명을 붙여
  # up 하면 pg 가 안 떠 있을 때 자동으로 띄우고, 이미 떠 있으면 그대로 두고 재구성하지 않습니다.
  info "새 이미지를 받습니다(artex 만)…"
  if ! docker compose pull artex; then
    warn "상류 이미지 autumn27/artex 를 Docker Hub 에서 받을 수 없습니다(현재 상류에서 내려간 상태라 pull 이 거부됩니다)"
    die "Docker 이미지 업데이트 경로는 현재 사용할 수 없습니다. 한국어판은 \"2) 로컬 업데이트(go 로 다시 컴파일)\" 로 빌드하세요"
  fi
  info "재구성 후 시작합니다(artex 는 재시작 시 schema 를 자동으로 마이그레이션합니다)…"
  docker compose up -d artex
  ok "업데이트 완료 → http://localhost:8787"
  info "로그 보기: docker compose logs -f artex"
  info "오래된 이미지 정리(선택): docker image prune -f"
}

# ── ② 로컬 컴파일 업데이트 ──────────────────────────────
update_local(){
  command -v go >/dev/null 2>&1 || die "Go 를 찾을 수 없습니다(>=1.26): https://go.dev/dl/"
  [ -f config.json ] || warn "config.json 을 찾을 수 없습니다. 최초 배포라면 ./install.sh 를 사용하세요"
  ok "Go: $(go version)"

  if command -v npm >/dev/null 2>&1; then
    info "프런트엔드 정적 산출물을 다시 빌드합니다…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "프런트엔드를 내장한 단일 바이너리를 다시 컴파일합니다…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "npm 을 찾을 수 없습니다. 프런트엔드를 내장하지 않은 백엔드만 컴파일합니다(프런트엔드는 npm run dev 로 따로 실행해야 합니다)"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "컴파일 완료 → ./artex"
  warn "변경을 적용하려면 실행 중인 artex 프로세스를 재시작하세요(재시작 시 schema 를 자동으로 마이그레이션합니다)"
}

echo "=============================="
echo "  ARTEX 업데이트"
echo "  1) Docker 업데이트(새 이미지를 받아 재구성)"
echo "  2) 로컬 업데이트(go 로 다시 컴파일)"
echo "=============================="
case "$(ask '선택' 1)" in
  1) sync_repo; update_docker ;;
  2) sync_repo; update_local ;;
  *) die "잘못된 선택입니다" ;;
esac
