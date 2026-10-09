#!/usr/bin/env bash
#
# Source-of-truth consistency test for the ARTEX detection indicators
# (see check.py for the assertions). It proves the one thing the Sigma, Suricata,
# and ATT&CK tests do not: that each rule's pinned indicator is still the string
# ARTEX's own source actually emits. The realistic rot it catches is an upstream
# re-sync that bumps the prober User-Agent or rewrites the guard marker — every
# other test stays green while the deployed rule silently stops matching.
#
# No host dependency beyond Docker: the check is pure Python standard library and
# runs in a container with only the rule tree, the published indicator list, the
# source packages it pins, and the two configs that gate on them — the CI workflow
# and the pre-commit hook — mounted read-only (never work/ or anything else).
# Nothing is installed on the host and nothing is written to the repo.
#
# Usage:   detections/tests/indicators/run.sh
# Env:     PYTHON_IMAGE  (default python:3.12-slim)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"

docker run --rm \
  -e ARTEX_REPO_ROOT=/repo \
  -v "$REPO/detections:/repo/detections:ro" \
  -v "$REPO/enrich:/repo/enrich:ro" \
  -v "$REPO/selfupdate:/repo/selfupdate:ro" \
  -v "$REPO/guard:/repo/guard:ro" \
  -v "$REPO/db:/repo/db:ro" \
  -v "$REPO/cmd:/repo/cmd:ro" \
  -v "$REPO/traffic:/repo/traffic:ro" \
  -v "$REPO/.github:/repo/.github:ro" \
  -v "$REPO/.pre-commit-config.yaml:/repo/.pre-commit-config.yaml:ro" \
  -v "$HERE:/src:ro" \
  "$PYTHON_IMAGE" python3 /src/check.py
