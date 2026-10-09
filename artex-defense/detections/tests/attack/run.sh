#!/usr/bin/env bash
#
# Reproducible consistency test for the ARTEX ATT&CK coverage layer
# (../../attack/artex_navigator_layer.json). A coverage layer that drifts from the
# rules it claims to cover is worse than none, so this turns "these rules cover
# these ATT&CK techniques" from a claim into something a reviewer can re-run from
# source. It catches the realistic regression: a rule is added, removed, or
# retagged, but the Navigator layer is not updated to match.
#
# It proves (see check.py for the assertions) that the layer is a valid Navigator
# v4.x document and that its scored techniques and tactics are EXACTLY the attack.*
# tags on the Sigma rules — no rule technique missing from the layer, no layer
# technique absent from the rules — with every scored technique grounded in a rule
# file that exists.
#
# No host dependency beyond Docker: the check is pure Python standard library and
# runs in a container with the detections tree mounted read-only. Nothing is
# installed on the host and nothing is written to the repo.
#
# Usage:   detections/tests/attack/run.sh
# Env:     PYTHON_IMAGE  (default python:3.12-slim)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
DET_DIR="$REPO/detections"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"

docker run --rm \
  -v "$DET_DIR:/detections:ro" \
  -v "$HERE:/src:ro" \
  "$PYTHON_IMAGE" python3 /src/check.py
