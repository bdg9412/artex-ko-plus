#!/bin/sh
# Build and start the local source checkout without changing upstream deployment.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
umask 077

if [ ! -e .env.local ]; then
  password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  printf 'POSTGRES_PASSWORD=%s\n' "$password" > .env.local
fi
mkdir -p .local-runtime data
if [ ! -e .local-runtime/jwt.key ]; then
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > .local-runtime/jwt.key
fi
if [ ! -s .env.local ] || [ ! -s .local-runtime/jwt.key ]; then
  printf 'Existing .env.local or JWT key is empty; restore it instead of rotating credentials.\n' >&2
  exit 1
fi
chmod 600 .env.local .local-runtime/jwt.key

docker compose --env-file .env.local -f docker-compose.local.yml config --quiet
docker compose --env-file .env.local -f docker-compose.local.yml up -d --build --wait --wait-timeout 180
