#!/usr/bin/env bash
#
# Documentation-claim consistency gate for the inline Sigma correlation template
# in the defense guide (see check-defense-template.py for the assertions). It
# proves the four present-tense facts docs/defense-{ko,en}.md state about their
# base template — `sigma check` passes with zero errors, the correlation converts
# on splunk/eql/loki, and lucene/kusto reject it with "Backend does not support
# correlation rules" — and that the two languages carry a byte-identical Sigma rule
# body. The template lives as prose outside detections/sigma/ on purpose (it is a
# generic behavioural rule, not grounded in ARTEX source), so no suite re-ran those
# claims; an upstream sigma-cli or backend change could make the prose silently
# false. This gate closes that gap.
#
# It is a gate, not a suite: run-all.sh runs it alongside the harness-sync and
# triage self-test gates, before the suite loop, and it does not appear in the
# per-suite summary. It is not a SUITES entry, a `.../run.sh` CI step, or a run.sh
# directory, so the eight detection suites stay eight and check-harness-sync never
# counts it.
#
# No host dependency beyond Docker: the pinned sigma-cli and its four backends are
# installed inside the container, the two defense guides are mounted read-only, and
# the extracted YAML is written only under the container's /tmp — nothing is
# installed on the host and nothing is written to the repo tree. The version and
# image overrides are inherited from the environment, matching the detection
# suites (PYTHON_IMAGE, SIGMA_CLI_VERSION).
#
# Usage:   detections/tests/check-defense-template.sh
# Env:     PYTHON_IMAGE      (default python:3.12-slim)
#          SIGMA_CLI_VERSION (default 3.1.0 — the pinned reference version)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PYTHON_IMAGE="${PYTHON_IMAGE:-python:3.12-slim}"
SIGMA_CLI_VERSION="${SIGMA_CLI_VERSION:-3.1.0}"

# Install the pinned sigma-cli plus the same four backends the sigma_backends suite
# uses (elasticsearch ships both the lucene and eql targets), then run the checker.
docker run --rm \
  -e ARTEX_DOCS_DIR=/docs \
  -e SIGMA_CLI_VERSION="$SIGMA_CLI_VERSION" \
  -v "$REPO/docs:/docs:ro" \
  -v "$HERE:/src:ro" \
  "$PYTHON_IMAGE" sh -ec '
    pip install --quiet --disable-pip-version-check "sigma-cli==${SIGMA_CLI_VERSION}" >/dev/null 2>&1
    for plugin in splunk elasticsearch loki kusto; do
      sigma plugin install "$plugin" >/dev/null 2>&1
    done
    exec python3 /src/check-defense-template.py
  '
