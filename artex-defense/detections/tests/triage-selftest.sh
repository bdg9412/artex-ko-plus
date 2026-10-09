#!/usr/bin/env bash
#
# Non-suite gate: runs the host-triage tool's built-in --self-test in a container.
#
# The triage tool (detections/triage/artex_host_triage.py) is a responder helper,
# not a detection rule, so it is deliberately NOT one of the detections/tests/<x>/
# run.sh suites — that keeps the harness-sync registry exactly the eight rule
# suites (check-harness-sync.py counts only SUITES entries, `detections/tests/<x>/
# run.sh` CI steps, and directories carrying a run.sh; this file is none of them).
# It is a gate like check-harness-sync.sh: both run-all.sh and the detections CI
# workflow call it, so a broken triage check fails the same merge gate as the
# rule suites. A detection you cannot run is only a claim.
#
# The self-test builds its own synthetic host in a temporary directory, asserts
# every check fires on it and that a clean host produces zero findings, and exits
# non-zero on any failure. No host dependency beyond Docker: the tool is pure
# Python standard library and runs in a container with only detections/triage
# mounted read-only; nothing is installed on the host and nothing is written to
# the repo tree.
#
# Usage:   detections/tests/triage-selftest.sh
# Env:     PYTHON_IMAGE  (default python:3.12-slim)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"

docker run --rm \
  -v "$REPO/detections/triage:/triage:ro" \
  "$PYTHON_IMAGE" python3 /triage/artex_host_triage.py --self-test
