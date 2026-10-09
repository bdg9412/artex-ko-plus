#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Force a test-only project even if the caller exported COMPOSE_PROJECT_NAME for
# an application checkout. Separate clones can choose distinct test projects.
test_project=${ARTEX_TEST_PROJECT_NAME:-artex-purple-test}
app_project=${COMPOSE_PROJECT_NAME:-${ARTEX_PROJECT_NAME:-artex-local}}
case "$test_project" in
  ''|[!a-z0-9]*|*[!a-z0-9_-]*)
    printf 'ARTEX_TEST_PROJECT_NAME must be a lowercase Docker Compose project name.\n' >&2
    exit 1
    ;;
esac
if [ "$test_project" = "$app_project" ] || [ "$test_project" = artex-local ]; then
  printf 'The test project must differ from the application project.\n' >&2
  exit 1
fi

# This project has no published ports or persistent volumes. Cleanup only the
# test project; the user's artex-local database and containers remain running.
cleanup() {
  docker compose --project-name "$test_project" -f docker-compose.test.yml down --remove-orphans
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker compose --project-name "$test_project" -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from tests
