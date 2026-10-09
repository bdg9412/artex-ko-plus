#!/usr/bin/env bash
#
# Reproducible backend-portability test for the ARTEX Sigma rules (../../sigma/).
# The rule README claims the rules "convert to your own SIEM or EDR query
# language" and lists several supported targets. The base Sigma test (../sigma/)
# only exercises Splunk; this test turns the cross-backend claim into something a
# reviewer can re-run, and keeps the README's per-backend guidance honest.
#
# It proves two properties with no host dependency beyond Docker (sigma-cli and
# its backends run in a container, nothing is installed on the host and nothing
# is written to the repo tree):
#
#   1. correlations are portable    the whole tree converts on splunk, the
#                                   Elasticsearch eql target, and Grafana loki
#   2. the atomic-only fallback     the five atomic rules convert on lucene and
#      works                        kusto (Microsoft Sentinel / Defender), which
#                                   do not support Sigma correlation conversion
#
# See ../README.md "Sigma backend portability" for the measured support matrix
# and the exact per-backend commands this test reproduces.
#
# Usage:   detections/tests/sigma_backends/run.sh
# Env:     PYTHON_IMAGE      (default python:3.12-slim)
#          SIGMA_CLI_VERSION (default 3.1.0 — the pinned reference version)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIGMA_DIR="$REPO/detections/sigma"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
SIGMA_CLI_VERSION="${SIGMA_CLI_VERSION:-3.1.0}"

# Everything runs inside the container: check.sh installs the pinned sigma-cli and
# four backends, then asserts the two properties and exits non-zero on any
# failure. The rule tree and this directory are mounted read-only.
docker run --rm \
  -v "$SIGMA_DIR:/sigma:ro" \
  -v "$HERE:/src:ro" \
  -e SIGMA_CLI_VERSION="$SIGMA_CLI_VERSION" \
  "$PYTHON_IMAGE" sh /src/check.sh
