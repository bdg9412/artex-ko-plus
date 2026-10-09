#!/usr/bin/env bash
#
# Runs every detection test suite under this directory in one command — the
# local-developer and pre-commit counterpart to the per-suite CI steps in
# ../../.github/workflows/detections.yml. CONTRIBUTING.md and this directory's
# README.md promise that each suite "drops straight into CI or a pre-commit
# hook"; this is the single entry point that honours that promise for all of
# them at once, so a contributor does not have to invoke the eight run.sh scripts
# by hand (and reviewers do not have to improvise a loop).
#
# It runs the suites in the same order as CI, lets each suite's own output flow
# through, prints a one-line PASS/FAIL summary per suite at the end, and exits
# non-zero if any suite failed — so it is safe to drop into a CI step or a
# pre-commit hook. Every suite runs to completion even if an earlier one fails,
# so one invocation surfaces every regression rather than only the first.
#
# No host dependency beyond Docker: each suite runs its checks in a container and
# writes nothing to the repo tree (see the per-suite run.sh headers). The image
# and version overrides the child scripts honour (PYTHON_IMAGE, SIGMA_CLI_VERSION,
# SIGMAHQ_VALIDATORS_VERSION, SURICATA_IMAGE) are inherited from this process's
# environment, so exporting any of them here applies to every suite at once.
#
# Usage:   detections/tests/run-all.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Same order as the steps in .github/workflows/detections.yml.
SUITES="sigma sigma_match sigma_lint sigma_backends suricata attack indicators misp"

fail=0
harness_fail=0
triage_fail=0
template_fail=0
results=""

# Before the suites, verify the harness itself is consistent: the SUITES list
# above, the per-suite steps in CI, and the suite directories on disk must all
# name the same suites in the same order. A suite wired into only one of the
# three (say a new CI step with no SUITES entry) passes every per-suite test yet
# silently breaks the "run-all.sh runs the same suites as CI" promise, which no
# other suite can see. This is a gate, not a suite: it runs first and stays out
# of the per-suite summary below, so that summary remains the detection suites.
printf '\n===== harness sync =====\n'
if ! "$HERE/check-harness-sync.sh"; then
  harness_fail=1
  fail=1
fi

# A second gate, not a suite: the host-triage tool's --self-test. The triage tool
# is a responder helper, not a detection rule, so it stays out of SUITES and the
# harness-sync registry (see triage-selftest.sh). It runs here and in the CI
# workflow so a local run-all.sh covers it too.
printf '\n===== triage self-test =====\n'
if ! "$HERE/triage-selftest.sh"; then
  triage_fail=1
  fail=1
fi

# A third gate, not a suite: the defense guide's inline Sigma template consistency
# check. That template is prose outside detections/sigma/ (a generic behavioural
# rule, not grounded in ARTEX source), so no per-suite test re-runs the facts the
# guide states about it. This gate does — sigma check, the splunk/eql/loki
# conversions, the lucene/kusto rejection, and ko/en rule-body parity — so it stays
# out of SUITES and the harness-sync registry like the two gates above (see
# check-defense-template.sh).
printf '\n===== defense template consistency =====\n'
if ! "$HERE/check-defense-template.sh"; then
  template_fail=1
  fail=1
fi

for suite in $SUITES; do
  printf '\n===== %s =====\n' "$suite"
  if "$HERE/$suite/run.sh"; then
    results="${results}  PASS  ${suite}"$'\n'
  else
    rc=$?
    results="${results}  FAIL  ${suite} (exit ${rc})"$'\n'
    fail=1
  fi
done

printf '\n===== detection suites summary =====\n'
printf '%s' "$results"
if [ "$harness_fail" -ne 0 ]; then
  printf '  FAIL  harness sync (run-all.sh / CI / directories out of sync: see above)\n'
fi
if [ "$triage_fail" -ne 0 ]; then
  printf '  FAIL  triage self-test (detections/triage/artex_host_triage.py --self-test: see above)\n'
fi
if [ "$template_fail" -ne 0 ]; then
  printf '  FAIL  defense template consistency (check-defense-template.sh: see above)\n'
fi
if [ "$fail" -ne 0 ]; then
  printf 'RESULT: FAIL\n'
  exit 1
fi
printf 'RESULT: PASS\n'
