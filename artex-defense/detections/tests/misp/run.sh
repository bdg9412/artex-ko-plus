#!/usr/bin/env bash
#
# Reproducible consistency test for the MISP-format export of the ARTEX
# indicators (see check.py for the assertions). It proves two things no other
# detection test does: that detections/indicators/artex_indicators.misp.json is
# a MISP document pymisp actually parses (every attribute type/category is a real
# MISP type a server would accept), and that it stays row-for-row in sync with
# the source-of-truth CSV it is generated from — same values, the intended MISP
# type/category per indicator, and a to_ids/disable_correlation flag that mirrors
# the CSV's own honesty (rule-backed = actionable; host-forensic = triage hint).
#
# No host dependency beyond Docker: pymisp is pinned and installed inside the
# container, and the detection tree and CI workflow are mounted read-only.
# Nothing is installed on the host and nothing is written to the repo tree.
#
# Usage:   detections/tests/misp/run.sh
# Env:     PYTHON_IMAGE    (default python:3.12-slim)
#          PYMISP_VERSION  (default 2.5.34.4 — the pinned reference version)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
PYMISP_VERSION="${PYMISP_VERSION:-2.5.34.4}"

docker run --rm \
  -e ARTEX_REPO_ROOT=/repo \
  -e PYMISP_VERSION="$PYMISP_VERSION" \
  -v "$REPO/detections:/repo/detections:ro" \
  -v "$REPO/.github:/repo/.github:ro" \
  -v "$HERE:/src:ro" \
  "$PYTHON_IMAGE" sh -c 'pip install --quiet "pymisp==${PYMISP_VERSION}" && python3 /src/check.py'
