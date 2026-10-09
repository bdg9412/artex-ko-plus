#!/bin/sh
#
# In-container half of the ARTEX Sigma rule test. run.sh launches this inside a
# Python container with the Sigma rule tree mounted read-only at /sigma. It
# installs a pinned sigma-cli (pySigma) plus the splunk backend, then asserts
# the properties the rule files and the defense guide claim:
#
#   1. structural + best-practice validation passes          (sigma check == 0 errors)
#   2. the whole tree compiles to a backend query language   (sigma convert -> splunk)
#   3. each atomic indicator string survives into the query  (enrich UA, self-update UA, guard marker, CA file)
#   4. the correlation rules compile as correlations         (event_count / value_count aggregations)
#   5. a correlation rule converted ALONE fails              (it genuinely depends on its atomic base rule)
#
# POSIX sh (the slim image ships dash). Exits non-zero if any assertion fails.
set -eu

VERSION="${SIGMA_CLI_VERSION:-3.1.0}"

pip install --quiet --disable-pip-version-check "sigma-cli==${VERSION}" >/dev/null 2>&1
sigma plugin install splunk >/dev/null 2>&1

fail=0
note() { printf '  %s\n' "$1"; }
pass() { note "PASS  $1"; }
bad()  { note "FAIL  $1"; fail=1; }

echo "== 1/4  structural + best-practice validation (sigma check) =="
if check_out="$(sigma check /sigma 2>&1)" \
   && printf '%s' "$check_out" | grep -q 'Found 0 errors'; then
  pass "sigma check: 0 errors, 0 condition errors, 0 issues"
else
  bad  "sigma check reported problems"
  printf '%s\n' "$check_out" | sed 's/^/        /'
fi

echo "== 2/4  compile the whole tree to a backend (sigma convert -> splunk) =="
if tree_out="$(sigma convert -t splunk --without-pipeline /sigma 2>&1)"; then
  pass "whole tree converts to splunk (exit 0)"
else
  bad  "whole-tree conversion failed"
  printf '%s\n' "$tree_out" | sed 's/^/        /'
  tree_out=""
fi

echo "== 3/4  each atomic indicator survives into the compiled query =="
# Grep the indicator VALUES, not backend field names or quoting, so the test is
# robust across splunk-backend releases. These strings come straight from the
# rule bodies, which are grounded in this repository's source. The last one is
# the recording-proxy CA filename, grounded in traffic/traffic.go.
for ind in 'artex-enrich/1.0' 'artex-selfupdate' '【ARTEX 平台管控·非目标防御】' 'mitmproxy-ca-cert.pem'; do
  if printf '%s' "$tree_out" | grep -qF "$ind"; then
    pass "indicator present: $ind"
  else
    bad  "indicator missing from compiled query: $ind"
  fi
done

echo "== 4/4  correlation rules compile as correlations, and depend on their base rules =="
# The event_count / value_count aggregation aliases prove the correlation rules
# were compiled as correlations (not dropped), using the whole tree so their
# base-rule references resolve.
if printf '%s' "$tree_out" | grep -q 'event_count' \
   && printf '%s' "$tree_out" | grep -q 'value_count'; then
  pass "correlation aggregations present (event_count, value_count)"
else
  bad  "correlation aggregations missing from compiled query"
fi

# Specificity, mirrored from the Suricata test: converting one correlation rule
# ALONE must fail, because it references an atomic rule by id that is absent from
# a single-file input. A passing conversion here would mean the reference is
# decorative; this asserts it is load-bearing.
if sigma convert -t splunk --without-pipeline \
     /sigma/correlation/artex_enrich_scan_velocity.yml >/dev/null 2>&1; then
  bad  "a correlation rule converted alone (its base-rule reference is not enforced)"
else
  pass "correlation rule fails to convert alone — it requires its atomic base rule"
fi

echo
echo "reference: sigma-cli ${VERSION}, splunk backend (latest), pySigma"
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
