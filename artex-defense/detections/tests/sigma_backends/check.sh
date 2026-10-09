#!/bin/sh
#
# In-container half of the ARTEX Sigma backend-portability test. run.sh launches
# this inside a Python container with the Sigma rule tree mounted read-only at
# /sigma. It installs a pinned sigma-cli (pySigma) plus four stable backends and
# proves that the rules convert beyond the single Splunk example the README used
# to show, and that the documented per-backend guidance is true for OUR rules.
#
# The base Sigma test (../sigma/) proves the rules are correct against Splunk.
# This test proves they are PORTABLE, and pins the two facts the README's
# "Validate and convert" section now documents:
#
#   1. Correlations are portable        the WHOLE tree (atomic + correlation)
#      beyond Splunk                    converts on splunk, Elasticsearch eql,
#                                        and Grafana loki (exit 0), and the enrich
#                                        indicator value survives into each query.
#   2. The atomic-only fallback works   backends that do not support Sigma
#      where correlations are not        correlation conversion (Elasticsearch
#      supported                         lucene, Microsoft kusto) still convert
#                                        the five atomic rules (exit 0), with the
#                                        enrich indicator surviving.
#
# Every assertion is POSITIVE (a capability that must keep working), so the test
# only fails on a genuine regression: a rule that stops converting, or a backend
# that drops support. It deliberately does not assert the negative "backend X
# cannot do correlations" — that would break when a backend improves. The honest
# limitation is documented in ../README.md, reproduced by this test's commands.
#
# POSIX sh (the slim image ships dash). Exits non-zero if any assertion fails.
set -eu

VERSION="${SIGMA_CLI_VERSION:-3.1.0}"

pip install --quiet --disable-pip-version-check "sigma-cli==${VERSION}" >/dev/null 2>&1
# elasticsearch ships the lucene + eql targets; the others are one plugin each.
for plugin in splunk elasticsearch loki kusto; do
  sigma plugin install "$plugin" >/dev/null 2>&1
done

ENRICH='artex-enrich/1.0'
ATOMICS='/sigma/artex_enrich_user_agent.yml /sigma/artex_selfupdate_egress.yml /sigma/artex_guard_audit_framing.yml /sigma/artex_recording_proxy_ca.yml /sigma/destructive_command_hunting.yml'

fail=0
note() { printf '  %s\n' "$1"; }
pass() { note "PASS  $1"; }
bad()  { note "FAIL  $1"; fail=1; }

# Backends escape regex metacharacters differently (lucene: artex\-enrich\/1.0,
# loki: artex\-enrich/1\.0, splunk/eql/kusto: artex-enrich/1.0). Strip backslashes
# before matching so the indicator-survival check is robust across all of them
# without asserting any one backend's escaping syntax.
has_enrich() { printf '%s' "$1" | tr -d '\\' | grep -qF "$ENRICH"; }

echo "== 1/2  correlations are portable: the whole tree converts beyond Splunk =="
# Whole-tree conversion includes the four correlation rules, which reference
# their atomic base rules by id. If a backend compiles the whole tree at exit 0
# it supports Sigma correlation conversion for our rules.
for target in splunk eql loki; do
  if out="$(sigma convert -t "$target" --without-pipeline /sigma 2>&1)" \
     && has_enrich "$out"; then
    pass "whole tree (atomic + correlation) converts on '$target', enrich indicator survives"
  else
    bad  "whole-tree conversion on '$target' failed or dropped the enrich indicator"
    printf '%s' "$out" | grep -iE 'error|not supported' | head -2 | sed 's/^/        /'
  fi
done

echo "== 2/2  atomic-only fallback: the five atomic rules convert where correlations are not supported =="
# Lucene and kusto (the Microsoft Sentinel / Defender backend) do not convert
# Sigma correlations at the pinned versions, so a defender deploys the five
# atomic rules and expresses the correlation logic natively. That fallback must
# work: all five atomic rules convert and the enrich indicator survives.
for target in lucene kusto; do
  if out="$(sigma convert -t "$target" --without-pipeline $ATOMICS 2>&1)" \
     && has_enrich "$out"; then
    pass "five atomic rules convert on '$target', enrich indicator survives"
  else
    bad  "atomic-only conversion on '$target' failed or dropped the enrich indicator"
    printf '%s' "$out" | grep -iE 'error|not supported' | head -2 | sed 's/^/        /'
  fi
done

echo
echo "reference: sigma-cli ${VERSION}; backends splunk, elasticsearch (lucene/eql), loki, kusto (latest compatible), pySigma"
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
