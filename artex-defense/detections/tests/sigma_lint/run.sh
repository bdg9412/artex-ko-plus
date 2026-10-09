#!/usr/bin/env bash
#
# Reproducible SigmaHQ-convention lint for the ARTEX Sigma rules (../../sigma/).
# `sigma check` on its own runs only pySigma's core validators; this test runs
# the full SigmaHQ convention set (the pySigma-validators-sigmahq plugin) against
# the documented baseline in validators.yml, so the "passes sigma check cleanly"
# claim in the README and CONTRIBUTING covers SigmaHQ's conventions, not just the
# core checks.
#
# It proves two properties with no host dependency beyond Docker (everything runs
# in a container, nothing is installed on the host and nothing is written to the
# repo tree):
#
#   1. the documented baseline (validators.yml) reports 0 errors and 0 issues
#   2. the full validator set actually runs, and only the four documented
#      exclusions remain — the anti-vacuity guard (see check.sh)
#
# The four exclusions and the rationale for each live in validators.yml.
#
# Usage:   detections/tests/sigma_lint/run.sh
# Env:     PYTHON_IMAGE                (default python:3.12-slim)
#          SIGMA_CLI_VERSION           (default 3.1.0 — the pinned reference version)
#          SIGMAHQ_VALIDATORS_VERSION  (default 0.21.0 — the pinned validator plugin)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIGMA_DIR="$REPO/detections/sigma"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
SIGMA_CLI_VERSION="${SIGMA_CLI_VERSION:-3.1.0}"
SIGMAHQ_VALIDATORS_VERSION="${SIGMAHQ_VALIDATORS_VERSION:-0.21.0}"

# Everything runs inside the container: check.sh installs the pinned sigma-cli and
# SigmaHQ validator plugin, then asserts the two properties and exits non-zero on
# any failure. The rule tree and this directory are mounted read-only.
docker run --rm \
  -v "$SIGMA_DIR:/sigma:ro" \
  -v "$HERE:/src:ro" \
  -e SIGMA_CLI_VERSION="$SIGMA_CLI_VERSION" \
  -e SIGMAHQ_VALIDATORS_VERSION="$SIGMAHQ_VALIDATORS_VERSION" \
  "$PYTHON_IMAGE" sh /src/check.sh
