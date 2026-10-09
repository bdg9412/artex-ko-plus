#!/bin/sh
# Route the existing local practice target through a real audit/path detector.
# The Juice Shop container and its data are retained.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
umask 077
app=artex-local-artex-1
origin=artex-practice-juice-shop-1
observed=artex-practice-observe
direct=artex-practice_default
member() {
  docker inspect --format '{{json .NetworkSettings.Networks}}' "$1" |
    python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.load(sys.stdin) else 1)' "$2"
}
for container in "$app" "$origin"; do
  test "$(docker inspect --format '{{.State.Running}}' "$container")" = true || {
    printf '%s must be running first.\n' "$container" >&2; exit 1;
  }
done
mkdir -p evidence-local/juice-shop-defense/logs
chmod 700 evidence-local/juice-shop-defense evidence-local/juice-shop-defense/logs
export PRACTICE_UID="$(id -u)" PRACTICE_GID="$(id -g)"
docker network inspect "$observed" >/dev/null 2>&1 || docker network create "$observed" >/dev/null
member "$origin" "$observed" || docker network connect --alias juice-shop-origin "$observed" "$origin"
docker compose -f docker-compose.practice-logs.yml up -d --wait --wait-timeout 90

# Keep the app's database network; only swap its practice-target route.
had_direct=false
member "$app" "$direct" && had_direct=true
member "$app" "$observed" || docker network connect "$observed" "$app"
if [ "$had_direct" = true ]; then
  docker network disconnect "$direct" "$app"
fi
if ! docker exec "$app" curl --noproxy '*' --fail --silent --max-time 10 http://juice-shop:3000/__artex_health >/dev/null; then
  if [ "$had_direct" = true ]; then
    docker network connect "$direct" "$app"
  fi
  docker network disconnect "$observed" "$app"
  printf 'Observer check failed; restored the previous practice route.\n' >&2
  exit 1
fi
# Docker Desktop can lose published-port forwarding when a network is detached.
# Restarting this container retains both database and application volumes.
if ! curl --noproxy '*' --fail --silent --max-time 5 http://127.0.0.1:8787/api/health >/dev/null; then
  printf 'Refreshing the ARTEX published port after its network change.\n'
  docker restart "$app" >/dev/null
  attempt=0
  until curl --noproxy '*' --fail --silent --max-time 3 http://127.0.0.1:8787/api/health >/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 10 ]; then
      printf 'ARTEX host port has not recovered; inspect its container before verifying.\n' >&2
      exit 1
    fi
    sleep 1
  done
fi
printf 'Ready: ARTEX -> juice-shop:3000 -> audit/detector -> original Juice Shop.\n'
printf 'Browser through detector: http://localhost:8791/\n'
printf 'Wait at least 30 seconds before starting a new defense verification.\n'
