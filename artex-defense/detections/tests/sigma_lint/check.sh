#!/bin/sh
#
# In-container half of the ARTEX Sigma SigmaHQ-convention lint test. run.sh
# launches this inside a Python container with the Sigma rule tree mounted
# read-only at /sigma and this directory at /src. It installs a pinned sigma-cli
# plus the pinned SigmaHQ validator plugin, then asserts two properties:
#
#   1. baseline is clean    sigma check with the documented validators.yml
#                           baseline reports 0 errors and 0 issues.
#   2. the full set is live  running ALL SigmaHQ validators (no exclusions) still
#                           reports issues, and every issue type is one of the
#                           four documented, excluded categories — nothing else.
#
# Property 2 is the anti-vacuity guard. If the validator plugin failed to load,
# the "all" run would report zero issues and property 1 would pass vacuously;
# requiring the known exclusions to appear proves the full SigmaHQ set actually
# ran. It also fails the build the moment a rule picks up a NEW convention issue
# outside the documented baseline (e.g. a mis-cased title or an invalid field),
# because that issue type would not be in the allow-list below and property 1
# would stop being clean.
#
# POSIX sh (the slim image ships dash). Exits non-zero if any assertion fails.
set -eu

VERSION="${SIGMA_CLI_VERSION:-3.1.0}"
SIGMAHQ_VALIDATORS_VERSION="${SIGMAHQ_VALIDATORS_VERSION:-0.21.0}"

pip install --quiet --disable-pip-version-check \
  "sigma-cli==${VERSION}" "pySigma-validators-sigmahq==${SIGMAHQ_VALIDATORS_VERSION}" >/dev/null 2>&1

# The four issue types the documented baseline (validators.yml) intentionally
# excludes. Any issue outside this set must fail the build.
ALLOWED='SigmahqGithubLinkIssue SigmahqFilenamePrefixIssue SigmahqCorrelationFilenamePrefixIssue SigmahqLogsourceUnknownIssue'

printf 'validators:\n  - all\n' > /tmp/all.yml

fail=0
note() { printf '  %s\n' "$1"; }
pass() { note "PASS  $1"; }
bad()  { note "FAIL  $1"; fail=1; }

echo "== 1/2  documented SigmaHQ baseline is clean (validators.yml) =="
if base_out="$(sigma check --validation-config /src/validators.yml /sigma 2>&1)" \
   && printf '%s' "$base_out" | grep -q 'Found 0 errors, 0 condition errors and 0 issues'; then
  pass "sigma check with the documented baseline: 0 errors, 0 issues"
else
  bad  "the documented baseline reported problems (a non-excluded convention issue, or an error)"
  printf '%s\n' "$base_out" | sed 's/^/        /'
fi

echo "== 2/2  the full SigmaHQ validator set runs, and only the documented exclusions remain =="
all_out="$(sigma check --validation-config /tmp/all.yml /sigma 2>&1 || true)"
# Collect the distinct issue types the full set reports.
types="$(printf '%s' "$all_out" | grep -oE 'issue=Sigmahq[A-Za-z]+Issue' | sed 's/^issue=//' | sort -u)"

if [ -z "$types" ]; then
  bad  "the full validator set reported no SigmaHQ issues at all — the plugin did not load (vacuous)"
else
  # Anti-vacuity: the two load-bearing exclusions must actually appear.
  for must in SigmahqGithubLinkIssue SigmahqLogsourceUnknownIssue; do
    if printf '%s\n' "$types" | grep -qx "$must"; then
      pass "full set is live: $must present"
    else
      bad  "expected $must from the full validator set but it was absent — plugin/version drift"
    fi
  done
  # No issue type outside the documented allow-list may appear.
  unexpected=0
  for t in $types; do
    case " $ALLOWED " in
      *" $t "*) : ;;
      *) bad "undocumented convention issue from the full set: $t"; unexpected=1 ;;
    esac
  done
  [ "$unexpected" -eq 0 ] && pass "every reported issue is one of the four documented exclusions"
fi

echo
echo "reference: sigma-cli ${VERSION}, pySigma-validators-sigmahq ${SIGMAHQ_VALIDATORS_VERSION}"
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
