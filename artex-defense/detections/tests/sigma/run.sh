#!/usr/bin/env bash
#
# Reproducible regression test for the ARTEX Sigma rules (../../sigma/). It turns
# the "validated by sigma check and sigma convert" claim in the rule README into
# something a reviewer can re-run from source with one command, and it catches
# regressions: a malformed rule, a broken correlation reference, or an indicator
# string that silently dropped out of the compiled query.
#
# It proves five properties with no host dependency beyond Docker (sigma-cli
# runs in a container, nothing is installed on the host and nothing is written to
# the repo tree):
#
#   1. sigma check passes          0 errors / 0 condition errors / 0 issues
#   2. the whole tree compiles     sigma convert -> splunk, exit 0
#   3. atomic indicators survive   artex-enrich/1.0, artex-selfupdate, guard marker, mitmproxy-ca-cert.pem
#   4. correlations compile        event_count / value_count aggregations present
#   5. correlations are load-bearing  one correlation rule converted alone FAILS,
#                                     because it references its atomic base rule by id
#
# Unlike a live event-matching harness (which needs a backend that normalizes the
# generic webserver/proxy/application fields — see ../README.md), this is the
# structural + compilation validation the Sigma README documents, made executable.
#
# Usage:   detections/tests/sigma/run.sh
# Env:     PYTHON_IMAGE      (default python:3.12-slim)
#          SIGMA_CLI_VERSION (default 3.1.0 — the pinned reference version)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIGMA_DIR="$REPO/detections/sigma"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
SIGMA_CLI_VERSION="${SIGMA_CLI_VERSION:-3.1.0}"

# Everything runs inside the container: check.sh installs the pinned sigma-cli and
# the splunk backend, then asserts the five properties and exits non-zero on any
# failure. The rule tree and this directory are mounted read-only.
docker run --rm \
  -v "$SIGMA_DIR:/sigma:ro" \
  -v "$HERE:/src:ro" \
  -e SIGMA_CLI_VERSION="$SIGMA_CLI_VERSION" \
  "$PYTHON_IMAGE" sh /src/check.sh
