#!/bin/sh
# Pin official lab sources; never modify an existing checkout with local edits.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
umask 077
runtime=.local-runtime/offensive
mkdir -p "$runtime" data/offensive/runs data/offensive/targets
prepare_repo() {
  repo_url=$1
  repo_path=$2
  repo_commit=$3
  if [ ! -d "$repo_path/.git" ]; then
    if [ -e "$repo_path" ]; then
      printf 'Refusing to replace existing path: %s\n' "$repo_path" >&2
      exit 1
    fi
    git init -q "$repo_path"
    git -C "$repo_path" remote add origin "$repo_url"
    git -C "$repo_path" fetch --depth 1 origin "$repo_commit"
    git -C "$repo_path" checkout -q --detach FETCH_HEAD
  fi
  if [ "$(git -C "$repo_path" rev-parse HEAD)" != "$repo_commit" ] || [ -n "$(git -C "$repo_path" status --porcelain)" ]; then
    printf 'Expected clean pinned checkout %s at %s; preserve/move your existing checkout before retrying.\n' "$repo_commit" "$repo_path" >&2
    exit 1
  fi
}
prepare_repo https://github.com/OWASP/crAPI.git "$runtime/crAPI" 700f03d12a392d9e408260b4beae72ed02a4a1a4
prepare_repo https://github.com/OWASP-Benchmark/BenchmarkJava.git "$runtime/BenchmarkJava" 8b67a88d73b2594570fc21150705283de884620b
if [ ! -e "$runtime/token" ]; then
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$runtime/token"
fi
if [ ! -s "$runtime/token" ]; then
  printf 'Existing Offensive token is empty; restore it instead of rotating it.\n' >&2
  exit 1
fi
if [ ! -e "$runtime/lab.env" ]; then
  lab_password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  printf 'CRAPI_DB_PASSWORD=%s\n' "$lab_password" > "$runtime/lab.env"
fi
ensure_env_secret() {
  secret_name=$1
  if ! grep -q "^${secret_name}=" "$runtime/lab.env"; then
    secret_value=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    printf '%s=%s\n' "$secret_name" "$secret_value" >> "$runtime/lab.env"
  fi
}
ensure_env_secret CRAPI_JWT_SECRET
ensure_env_secret CRAPI_SECRET_KEY
chmod 600 "$runtime/token" "$runtime/lab.env"
printf 'Official crAPI and Benchmark sources ready. Runtime credentials stay in .local-runtime/offensive/.\n'
