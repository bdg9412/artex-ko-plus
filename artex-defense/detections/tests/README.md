# ARTEX detection rule tests

English · [한국어](README.ko.md)

> 한국어: 이 디렉터리는 [`../`](../)의 탐지 규칙이 실제로 발화하는지를 재현 가능하게 증명하는
> 회귀 테스트입니다. 바이너리 캡처를 저장소에 넣지 않고, 패킷 캡처를 매번 결정론적으로 생성한 뒤
> [Suricata](https://suricata.io)로 직접 돌려 경보 수를 확인합니다. 모든 테스트는 자신이 소유하거나
> 서면 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 쓰십시오. 한국어 전체 문서는
> **[README.ko.md](README.ko.md)** 를 보십시오.

Reproducible regression tests that prove the rules under [`../`](../) actually fire — and, just as
important, stay silent on benign traffic. A detection rule you cannot run is a claim; these tests turn the
claims in the rule files and the defense guide into something a reviewer can re-run from source.

No binary packet capture is committed. The capture is **synthesized deterministically on every run** and
removed afterwards, so the test ships as readable source, not as an opaque fixture, and never bloats the
repository.

## Run every suite at once — [`run-all.sh`](run-all.sh)

[`run-all.sh`](run-all.sh) runs all eight suites below in one command, in the same order as CI, so you do not
have to invoke the eight `run.sh` scripts by hand. Each suite runs to completion even if an earlier one fails,
the script prints a one-line PASS/FAIL summary per suite at the end, and it exits non-zero if any suite failed.

Before the suites, it runs a harness self-check ([`check-harness-sync.sh`](check-harness-sync.sh)) that fails
the run if this suite list, the per-suite steps in [CI](../../.github/workflows/detections.yml), and the suite
directories on disk ever name different suites or a different order. That is the one gap the eight suites
cannot see on their own: a suite wired into only one of the three (a new CI step with no `run-all.sh` entry, or
a directory never added to either) would otherwise pass every per-suite test while a green local `run-all.sh`
quietly stopped meaning a green CI. The check is a gate, not a ninth suite: it stays out of the summary
below, so the eight detection suites stay eight.

Two more gates run the same way — before the suite loop, out of the summary, and never counted as suites:
the [host-triage tool](../triage/)'s `--self-test` ([`triage-selftest.sh`](triage-selftest.sh)) and the
defense-template consistency check ([`check-defense-template.sh`](check-defense-template.sh)). The latter
re-runs the facts the defense guide states about its inline Sigma correlation template (`sigma check`
passes, it converts on splunk/eql/loki, lucene and kusto reject the correlation, and the Korean and English
copies carry a byte-identical rule body); that template is prose outside the [`../sigma/`](../sigma/) rule
tree, so no suite would otherwise catch it going stale against an upstream sigma-cli.

```sh
detections/tests/run-all.sh
```

Expected output (abridged):

```
===== detection suites summary =====
  PASS  sigma
  PASS  sigma_match
  PASS  sigma_lint
  PASS  sigma_backends
  PASS  suricata
  PASS  attack
  PASS  indicators
  PASS  misp
RESULT: PASS
```

Because it exits non-zero on any failure, it drops straight into a pre-commit hook. A ready-to-use example
lives in [`.pre-commit-config.yaml`](../../.pre-commit-config.yaml) at the repository root: install it with
`pip install pre-commit && pre-commit install`, and the runner then fires on commits that touch the detection
rules or the upstream source files they pin — the same scope as CI. The image and version overrides the
individual suites honour (`PYTHON_IMAGE`, `SIGMA_CLI_VERSION`, `SIGMAHQ_VALIDATORS_VERSION`, `SURICATA_IMAGE`)
are inherited by the runner, so exporting any of them applies to every suite at once.

## Suricata — [`suricata/`](suricata/)

[`suricata/run.sh`](suricata/run.sh) exercises the network rules in
[`../suricata/artex.rules`](../suricata/artex.rules) end to end and asserts five properties:

- **Valid** — the whole rules file loads under `suricata -T --init-errors-fatal`, so a rule that fails to
  parse or initialise is caught even when no capture below exercises it. Plain `suricata -r` skips such a
  rule and still exits 0, so this load check is the Suricata analogue of the Sigma suite's `sigma check`
  validity assertion.
- **Presence (enrich)** — sid `1000001` fires exactly once per enrichment probe.
- **Velocity** — sid `1000002` fires once the `detection_filter` rate of 30 requests in 300 s per source is
  crossed.
- **Presence (WebFetch)** — sid `1000003` fires exactly once per norma WebFetch request, and the enrich sids
  stay silent on that same capture — so the two network signatures are mutually specific, not just each
  present.
- **Specificity** — an identical capture whose only change is a benign browser User-Agent produces **zero**
  ARTEX alerts.

[`suricata/gen_pcap.py`](suricata/gen_pcap.py) builds the capture with [scapy](https://scapy.net): N
independent plaintext HTTP request/response flows from one fixed source, each carrying a chosen
User-Agent, at a fixed base timestamp spaced one second apart. It only writes a file — it never sends a
packet or touches a network.

### Run it

Needs only Docker; scapy and Suricata both run in containers.

```sh
detections/tests/suricata/run.sh
```

Expected output (abridged):

```
  PASS  ruleset loads with zero parse/init errors (suricata -T)
  PASS  sid 1000001 presence: one alert per probe  (got 35, want eq 35)
  PASS  sid 1000002 velocity: fires past 30-in-300s  (got 5, want ge 1)
  PASS  sid 1000003 presence: one alert per WebFetch request  (got 8, want eq 8)
  PASS  enrich sids stay silent on norma traffic (specificity)  (got 0, want eq 0)
  PASS  benign browser UA produces no ARTEX alerts  (got 0, want eq 0)
RESULT: PASS
```

The script exits non-zero if any assertion fails, so it drops straight into CI or a pre-commit hook.
Override the images with `SURICATA_IMAGE` / `PYTHON_IMAGE` if you mirror them internally.

### Why the velocity count is a floor, not an exact match

`run.sh` asserts the presence counts (`1000001 == 35`, `1000003 == 8`) and the benign count (`== 0`) exactly,
because those are engine-version-independent: one alert per matching request, and no match on a different
User-Agent. The
velocity rule's count depends on how a given Suricata release resolves the `detection_filter` threshold at
the boundary, so the test asserts `>= 1` and records the reference value separately. On **Suricata 8.0.7**
the reference run produces **5** alerts on sid `1000002` (flows 31–35, after the 30-in-300 s threshold is
crossed).

## Sigma — [`sigma/`](sigma/)

[`sigma/run.sh`](sigma/run.sh) validates the Sigma rules under [`../sigma/`](../sigma/) structurally and by
compilation with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) (pySigma), and asserts five properties:

- **Valid** — `sigma check` reports 0 errors, 0 condition errors, and 0 issues over the whole tree.
- **Compiles** — `sigma convert -t splunk` turns the whole tree into a backend query language without error.
- **Indicators survive** — each atomic indicator string (`artex-enrich/1.0`, `artex-selfupdate`, the guard
  marker, and the recording-proxy CA filename `mitmproxy-ca-cert.pem`) is still present in the compiled query,
  so a rule cannot silently lose the string it is built on.
- **Correlations compile** — the behaviour rules in [`../sigma/correlation/`](../sigma/correlation/) emit their
  `event_count` / `value_count` aggregations rather than being dropped.
- **Correlations are load-bearing** — converting one correlation rule *alone* fails, because it references its
  atomic base rule by `id`; the reference is enforced, not decorative. This is the Sigma analogue of the
  Suricata specificity assertion above.

This is the structural + compilation validation documented in [`../README.md`](../README.md), made executable
and assertive. The companion [`sigma_match/`](sigma_match/) suite below adds the *matching* half for both the
atomic and the correlation rules — a representative malicious event (or timeline) fires each rule and a benign
one does not — so the Sigma rules now get both a reproducible validation test and a reproducible matching test,
the way the Suricata rule does. (The
earlier concern that a weak hand-written matcher would undercut the rules is addressed by delegating all parsing
to pySigma; see the trust model in the next section.)

### Run it

Needs only Docker; sigma-cli and the splunk backend run in a container and nothing is written to the repo.

```sh
detections/tests/sigma/run.sh
```

Expected output (abridged):

```
  PASS  sigma check: 0 errors, 0 condition errors, 0 issues
  PASS  whole tree converts to splunk (exit 0)
  PASS  indicator present: artex-enrich/1.0
  PASS  correlation rule fails to convert alone — it requires its atomic base rule
RESULT: PASS
```

The script exits non-zero if any assertion fails, so it drops straight into CI or a pre-commit hook. sigma-cli
is pinned to a reference version (`3.1.0`); override it with `SIGMA_CLI_VERSION`, or the image with
`PYTHON_IMAGE`, if you mirror them internally.

## Sigma live event-matching — [`sigma_match/`](sigma_match/)

[`sigma_match/run.sh`](sigma_match/run.sh) proves the Sigma rules under [`../sigma/`](../sigma/) — both the
atomic rules and the correlation rules under [`../sigma/correlation/`](../sigma/correlation/) — actually *fire*
on a matching event (or timeline) and stay quiet on a benign one — the "a detection you cannot run is only a
claim" guarantee the Suricata suite gives the network rule, extended here to the host/log-layer rules. It
asserts six properties, three for the atomic rules and three for the correlations:

- **Rule/sample pairing** — every atomic rule has an [`events/<name>.json`](sigma_match/events/) sample file and
  every sample file maps back to a rule, so a rule added without samples fails here rather than going untested.
- **True positives** — each rule matches every one of its malicious sample events.
- **True negatives** — each rule matches none of its benign sample events. For example, a standalone
  `mitmproxy-ca-cert.pem` under `.mitmproxy/` does **not** trip the recording-proxy rule, because its `|all`
  modifier also requires the `_ca/` directory ARTEX writes — the matching test is what proves that discrimination.
- **Correlation rule/timeline pairing** — every correlation rule has an
  [`events/correlation/<name>.json`](sigma_match/events/correlation/) timeline file and every timeline maps back
  to a rule. Each timeline event carries a `ts` field in relative seconds.
- **Correlation true positives** — each rule fires on a positive timeline where the threshold is met inside the
  window within one group. For example, requests from one source (`c-ip`) fanning out to 20 distinct hosts
  within 10 minutes trip the enrichment fan-out rule.
- **Correlation true negatives** — each rule stays quiet when the threshold is not met, when it is met but the
  events are spread beyond the window, when they are split across groups, or when a temporal rule is missing a
  leg. In particular a high-volume, low-breadth burst does **not** trip the fan-out rule: breadth, not volume, is
  the signal, and the matching test is what proves that discrimination.

The trust model is that pySigma — not hand-written code — parses each rule: an atomic rule into a condition tree
(`|contains` → a wildcard value, `|all` → an AND, `1 of selection_*` → an OR), and a correlation rule into its
aggregation spec (type, group-by, timespan, threshold, and the resolved references to the atomic base rules).
[`check.py`](sigma_match/check.py) only walks that tree and spec, deciding which events feed a referenced rule
with the very same atomic matcher, so the authoritative Sigma logic stays in pySigma; it raises rather than
passing on any construct it does not explicitly support (fail-closed). Scope and limits are stated in the script
header: the correlation window is the standard sliding-window interpretation (a `timespan`-second window
anchored at each matching event) and a real SIEM's windowing may differ; matching is **case-insensitive** (the
splunk-backend default the `sigma/` suite targets, which the destructive rule's own false-positive note
assumes); and keyword matching is a full-text substring search. It is a regression test for the rules'
field/value/condition/aggregation logic, not a substitute for validating in your own SIEM, whose field
normalization may differ.

### Run it

Needs only Docker; pySigma runs in a container and nothing is written to the repo.

```sh
detections/tests/sigma_match/run.sh
```

Expected output (abridged):

```
  PASS  rule/sample pairing: 5 atomic rules, 5 event files, no orphans
  PASS  artex_enrich_user_agent: 1/1 positive events matched
  PASS  artex_recording_proxy_ca: 2/2 benign events correctly not matched
  PASS  rule/timeline pairing: 4 correlation rules, 4 timeline files, no orphans
  PASS  artex_enrich_fanout: fired — 20 distinct hosts from one source within the 10-minute window
  PASS  artex_enrich_fanout: quiet — high volume, low breadth: 25 requests from one source but only 4 distinct hosts
RESULT: PASS
```

The script exits non-zero if any assertion fails, so it drops straight into CI or a pre-commit hook. pySigma is
pinned to a reference version (`2.0.0`); override it with `PYSIGMA_VERSION`, or the image with `PYTHON_IMAGE`,
if you mirror them internally.

## Sigma backend portability — [`sigma_backends/`](sigma_backends/)

[`sigma_backends/run.sh`](sigma_backends/run.sh) proves the rules convert beyond the single Splunk example the
Sigma test exercises, and keeps the per-backend support matrix in [`../README.md`](../README.md) honest. Sigma
correlation conversion is backend-dependent, so the README tells a defender which `-t` targets take the whole
tree and which take only the atomic rules — a claim that is only trustworthy if it is re-run. It asserts two
properties, both positive so the test fails only on a real regression:

- **Correlations are portable** — the whole tree (atomic + correlation) converts on Splunk, the Elasticsearch
  `eql` target, and Grafana `loki`, with the enrich indicator surviving into each query. This shows the
  correlation rules are not Splunk-only.
- **Atomic-only fallback works** — the five atomic rules still convert on `lucene` and the Microsoft `kusto`
  backend, which do not support Sigma correlation conversion at the pinned versions, so a defender on those
  backends can deploy the atomic rules and express the correlation window natively.

It deliberately does not assert the negative "backend X cannot do correlations": that would turn a backend
*improving* into a red build. The honest limitation lives in the README, reproduced by this test's commands.
[`sigma_backends/check.sh`](sigma_backends/check.sh) is the in-container half; it installs the pinned sigma-cli
plus four backends and reads the rule tree mounted read-only.

### Run it

Needs only Docker; sigma-cli and the backends run in a container and nothing is written to the repo.

```sh
detections/tests/sigma_backends/run.sh
```

Expected output (abridged):

```
  PASS  whole tree (atomic + correlation) converts on 'eql', enrich indicator survives
  PASS  five atomic rules convert on 'kusto', enrich indicator survives
RESULT: PASS
```

The script exits non-zero if any assertion fails. sigma-cli is pinned (`3.1.0`, override with
`SIGMA_CLI_VERSION`); the backend plugins install at their latest compatible version, so this suite is the one
most sensitive to an upstream backend release — a plugin that drops support turns the build red, which is the
signal to update the pin and the README matrix together.

## SigmaHQ convention lint — [`sigma_lint/`](sigma_lint/)

[`sigma_lint/run.sh`](sigma_lint/run.sh) makes the "passes `sigma check` cleanly" promise in the README and
`CONTRIBUTING.md` cover SigmaHQ's conventions, not just pySigma's core checks. Plain `sigma check` does not
load the `pySigma-validators-sigmahq` plugin, so title casing, field-name taxonomy, logsource taxonomy, and
reference-link conventions go unchecked. This suite installs that plugin and runs the full set against the
documented baseline in [`sigma_lint/validators.yml`](sigma_lint/validators.yml). It asserts two properties:

- **The documented baseline is clean** — `sigma check` with `validators.yml` reports 0 errors and 0 issues.
- **The full set is live, and only the documented exclusions remain** — running every SigmaHQ validator with
  no exclusions still reports issues, and each one is among the four checks `validators.yml` deliberately
  disables (nothing else). This is the anti-vacuity guard: if the plugin failed to load, the full run would
  report nothing and the first property would pass for the wrong reason, so the known exclusions are required
  to appear.

The four exclusions encode SigmaHQ's monorepo filing scheme (logsource-prefixed and `correlation_` filenames)
and taxonomy (a generic `application` logsource and a product-less `process_creation`), plus the
branch-vs-permalink reference convention — none of which fit a small standalone rule set that references its
own living docs. Each exclusion carries its rationale inline in `validators.yml`. Because every *other*
SigmaHQ check is enforced, a rule that picks up a new convention issue — a mis-cased title, an off-taxonomy
field name — turns the build red. `pySigma-validators-sigmahq` is pinned (`0.21.0`, override with
`SIGMAHQ_VALIDATORS_VERSION`); bumping it may surface new conventions, which is the signal to update the rules
or the documented baseline.

### Run it

Needs only Docker; sigma-cli and the validator plugin run in a container and nothing is written to the repo.

```sh
detections/tests/sigma_lint/run.sh
```

Expected output (abridged):

```
  PASS  sigma check with the documented baseline: 0 errors, 0 issues
  PASS  every reported issue is one of the four documented exclusions
RESULT: PASS
```

## ATT&CK layer — [`attack/`](attack/)

[`attack/run.sh`](attack/run.sh) checks that the [ATT&CK coverage layer](../attack/) in
[`../attack/artex_navigator_layer.json`](../attack/artex_navigator_layer.json) stays consistent with the
rules it claims to cover. A coverage layer that drifts from its rule set is worse than none, so this turns
"these rules cover these ATT&CK techniques" into something a reviewer can re-run from source. It asserts:

- **Valid layer** — the file parses as JSON and carries the required ATT&CK Navigator v4.x fields, with a
  well-formed technique ID and a valid ATT&CK tactic on every entry.
- **Bidirectional match** — the scored techniques are *exactly* the `attack.*` technique tags on the Sigma
  rules: no rule technique missing from the layer, no layer technique absent from the rules. The tactics
  match the same way.
- **Grounded** — every scored technique's comment names a rule file that exists, so the layer cannot cite a
  rule that was renamed or removed.

This is a consistency check, not a firing test: it needs no detection backend, only the Python standard
library, so unlike the Sigma and Suricata tests it carries no version-dependent counts. [`attack/check.py`](attack/check.py)
is the in-container half; it reads the detections tree mounted read-only and writes nothing.

### Run it

Needs only Docker; the check runs in a Python container and nothing is written to the repo.

```sh
detections/tests/attack/run.sh
```

Expected output (abridged):

```
  PASS  scored techniques match the rule set exactly (8: T1059, T1105, T1485, T1489, T1557, T1561.002, T1592, T1595)
  PASS  scored tactics match the rule set exactly (collection, command-and-control, credential-access, execution, impact, reconnaissance)
RESULT: PASS
```

The script exits non-zero if any assertion fails, so it drops straight into CI or a pre-commit hook.
Override the image with `PYTHON_IMAGE` if you mirror it internally.

## Indicator source-of-truth — [`indicators/`](indicators/)

[`indicators/run.sh`](indicators/run.sh) proves the one thing the three tests above do not: that each rule's
pinned indicator is still the string ARTEX's own source actually emits. The Sigma test proves an indicator
survives rule→query *compilation*; the ATT&CK test proves the layer matches the rules' tags; the Suricata
test proves the network rule *fires* on a synthesized capture. None of them look back at the source file the
indicator claims to come from. The rot they all miss is an upstream re-sync that bumps the prober User-Agent
to `artex-enrich/2.0` or rewrites the guard marker: every rule still compiles, the layer still matches, the
pcap test still fires — and the deployed rule silently stops matching real ARTEX traffic. It asserts, for
each indicator, bidirectionally:

- **Source still emits it** — the value is present in the upstream source file(s) that produce it
  (`artex-enrich/1.0` in `enrich/enrich.go`, `artex-selfupdate` in `selfupdate/`, the guard marker in
  `guard/guard.go`). A missing value means an upstream change the rule has not caught up with.
- **Rule still pins it** — the value is present in the rule built on it, so a rule edit cannot quietly move
  the indicator away from its source. The Suricata rule is checked by its `startswith` prefix, matching how
  it actually matches the wire.
- **Deny-list correspondence** — the destructive-command tokens (`rm -rf`, `mkfs`, `DROP DATABASE`,
  `FLUSHALL`) appear both in ARTEX's guard deny-list (`db/db.go`) and in the hunting rule that mirrors it.
  These are generic hunting leads, not unique fingerprints, so the test asserts only the correspondence the
  rule actually claims.
- **Published list stays grounded** — the machine-readable indicator list
  [`detections/indicators/artex_indicators.csv`](../indicators/artex_indicators.csv), the artifact a
  defender imports, is re-read row by row: every value must still be present in the source file(s) it cites
  and pinned in the rule(s) it cites, and every fingerprint the test grounds must appear in the list. So the
  published CSV cannot silently drift from the source it claims to come from, in either direction.
- **Both gates fire on each pinned source** — every upstream source the test reads is covered by the two
  gates that run it: the CI workflow's `push` and `pull_request` paths filter
  ([`.github/workflows/detections.yml`](../../.github/workflows/detections.yml)) and the local pre-commit
  hook's `files` regex ([`.pre-commit-config.yaml`](../../.pre-commit-config.yaml)). The required set is
  derived from the indicators themselves, so pinning a new source (as the `cmd/artex/main.go` ports once were)
  without wiring it into *both* gates fails here — otherwise a change touching only that source skips the test
  on whichever gate omits it: on CI it passes the merge gate green, on the hook it is never caught locally
  even though the hook promises "the same source scope as CI".

This turns [`../README.md`](../README.md)'s promise — "every indicator here is grounded in a string verified
in this repository's source, not inferred" — and CONTRIBUTING's first contribution contract into a guard a
reviewer can re-run. Like the ATT&CK test it needs no detection backend, only the Python standard library;
[`indicators/check.py`](indicators/check.py) reads the rule tree, the published indicator list, the pinned
source packages, and the two gates that fire it (the CI workflow and the pre-commit config) mounted read-only
and writes nothing.

### Run it

Needs only Docker; the check runs in a Python container and nothing is written to the repo.

```sh
detections/tests/indicators/run.sh
```

Expected output (abridged):

```
  PASS  enrichment prober User-Agent: 'artex-enrich/1.0' emitted by enrich/enrich.go
  PASS  detections/sigma/artex_enrich_user_agent.yml pins 'artex-enrich/1.0'
  PASS  'FLUSHALL' present in both db/db.go and detections/sigma/destructive_command_hunting.yml
  PASS  enrich-user-agent: 'artex-enrich/1.0' grounded in enrich/enrich.go
  PASS  tested fingerprint 'artex-enrich/1.0' is published in the list
  PASS  .github/workflows/detections.yml push paths covers cmd/artex/main.go
  PASS  .pre-commit-config.yaml files covers cmd/artex/main.go
RESULT: PASS
```

The script exits non-zero if any assertion fails, so it drops straight into CI or a pre-commit hook.
Override the image with `PYTHON_IMAGE` if you mirror it internally.

## MISP export consistency — [`misp/`](misp/)

[`misp/run.sh`](misp/run.sh) covers the second published form of the indicators — the ready-to-import MISP
event [`detections/indicators/artex_indicators.misp.json`](../indicators/artex_indicators.misp.json). The
indicator test above keeps the CSV grounded in the source; this test keeps the MISP event, the artifact a
defender actually loads into a threat-intelligence platform, from drifting away from that CSV. It asserts:

- **It is really MISP** — the event loads under [pymisp](https://github.com/MISP/PyMISP), whose object model
  rejects any attribute whose `type` is not a genuine MISP type. A plausible-looking but invalid type fails
  here, so "valid MISP" is proven by the library a MISP server uses, not asserted.
- **Row-for-row sync with the CSV** — every CSV row maps to exactly one MISP attribute with the intended type
  and category (`http.user-agent` → `user-agent`, the guard marker `string` → `pattern-in-file`, `port` →
  `port`, `ip-dst|port` → `ip-dst|port` with the composite `ip|port` value, and the exploration-schema `other` → `other`), and no MISP attribute is left
  without a CSV row. The event is hand-maintained alongside the CSV, so adding, removing, or retyping a CSV
  row without updating `artex_indicators.misp.json` to match in the same commit fails.
- **`to_ids` mirrors the `rule` column** — a rule-backed indicator is `to_ids: true`; a host-forensic row
  with no rule is `to_ids: false` with `disable_correlation: true`. Flipping a flag away from what the CSV
  implies fails, so the MISP event cannot quietly over- or under-claim which fingerprints are actionable.
- **The guard marker survives byte-for-byte** and `detections/**` is in the CI paths filter, so a change to
  the CSV or the event triggers this suite.

Unlike the pure-standard-library tests above, this suite installs a pinned `pymisp` inside its container
(nothing is installed on the host); [`misp/check.py`](misp/check.py) reads the CSV, the MISP event, and the
CI workflow mounted read-only and writes nothing.

### Run it

Needs only Docker; pymisp is installed in the container and nothing is written to the repo.

```sh
detections/tests/misp/run.sh
```

The script exits non-zero if any assertion fails. Override the image with `PYTHON_IMAGE` and the pinned
library with `PYMISP_VERSION` if you mirror them internally.

## Contributing

A new detection rule is stronger with a test that shows it firing. Tests should synthesize their own input
deterministically, assert engine-version-independent properties exactly (and softer ones as floors with a
recorded reference), and avoid any content that reads as attack guidance. See
[`../../CONTRIBUTING.en.md`](../../CONTRIBUTING.en.md) and the rule indexes in [`../README.md`](../README.md).

All eight suites run in CI (see [`../../.github/workflows/detections.yml`](../../.github/workflows/detections.yml))
on every push or pull request that touches `detections/` — and the indicator test also runs when the upstream
source files it pins (`enrich/`, `selfupdate/`, `guard/`, `db/`, `cmd/artex/main.go`) change — so a rule
change that drops an indicator, drifts from the ATT&CK layer, stops converting on a documented backend,
breaks a SigmaHQ convention, falls out of sync with the source, lets the MISP event drift from the CSV, or
pins a new source the workflow does not yet watch turns the build red before it can merge.
