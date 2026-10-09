#!/usr/bin/env bash
#
# Reproducible live event-matching test for the ARTEX Sigma rules — both the
# atomic rules (../../sigma/*.yml) and the correlation rules
# (../../sigma/correlation/*.yml). The sibling sigma/ suite proves those rules are
# valid and COMPILE to a backend query; this suite proves they actually FIRE on a
# matching event (or timeline) and stay quiet on a benign one — the same "a
# detection you cannot run is only a claim" guarantee the suricata/ suite already
# gives the network rule with a pcap replay.
#
# It proves six properties with no host dependency beyond Docker (pySigma runs in
# a container, nothing is installed on the host and nothing is written to the repo
# tree):
#
#   atomic 1  rule/sample pairing   every atomic rule has an events/<name>.json and
#                                   every events file maps to a rule (no orphans)
#   atomic 2  true positives        each rule matches all of its malicious events
#   atomic 3  true negatives        each rule matches none of its benign events
#   corr   1  rule/timeline pairing every correlation rule has an
#                                   events/correlation/<name>.json (no orphans)
#   corr   2  true positives        each rule FIRES on its positive timeline
#                                   (threshold met, inside the window, one group)
#   corr   3  true negatives        each rule stays QUIET on its negative timelines
#                                   (below threshold, window exceeded, split group,
#                                   or a missing leg)
#
# pySigma parses each rule — for an atomic rule its condition tree, for a
# correlation rule its aggregation spec (type, group-by, timespan, threshold, and
# the resolved references to the atomic base rules) — and check.py only walks that
# parsed structure, so the authoritative Sigma logic stays in pySigma (see
# check.py's header). The correlation window is the standard sliding-window model
# and matching is case-insensitive; see check.py for the full scope and honesty
# notes.
#
# Usage:   detections/tests/sigma_match/run.sh
# Env:     PYTHON_IMAGE    (default python:3.12-slim)
#          PYSIGMA_VERSION (default 2.0.0 — the pinned reference version)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SIGMA_DIR="$REPO/detections/sigma"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
PYSIGMA_VERSION="${PYSIGMA_VERSION:-2.0.0}"

# Everything runs inside the container: check.sh installs the pinned pySigma and
# runs check.py, which asserts the three properties and exits non-zero on any
# failure. The rule tree and this directory are mounted read-only.
docker run --rm \
  -v "$SIGMA_DIR:/sigma:ro" \
  -v "$HERE:/src:ro" \
  -e PYSIGMA_VERSION="$PYSIGMA_VERSION" \
  "$PYTHON_IMAGE" sh /src/check.sh
