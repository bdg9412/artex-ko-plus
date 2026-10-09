# ARTEX detection rules

English · [한국어](README.ko.md)

> 한국어: 이 디렉터리는 [방어·탐지 가이드(docs/defense-ko.md)](../docs/defense-ko.md)의 4절 "탐지 규칙"을
> 실제로 배포 가능한 [Sigma](https://sigmahq.io) 규칙으로 옮긴 것입니다. 모든 규칙은 자신이 소유하거나 서면
> 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 사용하십시오. 한국어 전체 문서는
> **[detections/README.ko.md](README.ko.md)** 를 보십시오.

Deployable [Sigma](https://sigmahq.io) rules that formalize the pseudo-rules in the defense guide
([Korean](../docs/defense-ko.md) · [English](../docs/defense-en.md), section 4) into a vendor-neutral
format you can convert to your own SIEM or EDR query language. Every indicator here is grounded in a
string or behaviour verified in this repository's source, not inferred.

## Atomic rules

- **`sigma/artex_enrich_user_agent.yml`** — inbound `artex-enrich/1.0` User-Agent from ARTEX asset
  enrichment (`enrich/enrich.go`). Target-side, supporting indicator. `level: high`.
- **`sigma/artex_selfupdate_egress.yml`** — outbound `artex-selfupdate` User-Agent from the self-update
  routine (`selfupdate/github.go`). Host/forensic egress indicator. `level: medium`.
- **`sigma/artex_guard_audit_framing.yml`** — the platform-guard control marker written to the audit log
  on a blocked tool call (`guard/guard.go`). Host/forensic indicator. `level: high`.
- **`sigma/destructive_command_hunting.yml`** — destructive shell/DB commands mirroring the ARTEX guard's
  built-in deny list (`db/db.go` seed). Generic hunting lead, not an ARTEX signature. `level: medium`.
- **`sigma/artex_recording_proxy_ca.yml`** — creation of the recording proxy's MITM CA file under the
  `_ca/mitmproxy-ca-cert.pem` layout (`traffic/traffic.go`). Host/forensic artifact; the bare filename is
  shared with standalone mitmproxy, so it is a hunting lead. `level: medium`.

## Correlation rules (behaviour)

Static strings can be changed; behaviour is harder to hide. These Sigma **correlation** rules in
[`sigma/correlation/`](sigma/correlation/) encode the behaviour-based layer of the defense guide
(sections 4.1–4.2 and 4.4). Each references an atomic rule above by its `id`, so convert the whole
`sigma/` tree — not a single correlation file — to resolve the reference (see below).

- **`sigma/correlation/artex_enrich_scan_velocity.yml`** — a burst of `artex-enrich/1.0` probes from one
  source in a short window (enrichment runs at concurrency 4 with no rate limit). The velocity the
  single-request rule misses. `event_count`, `level: high`.
- **`sigma/correlation/artex_enrich_fanout.yml`** — one source carrying the enrichment User-Agent to many
  *distinct* hosts: machine-speed fan-out across an asset list, where breadth (not just volume) is the
  tell. `value_count`, `level: high`.
- **`sigma/correlation/artex_guard_block_burst.yml`** — repeated platform-guard control markers on one
  host, i.e. an active ARTEX run tripping its guard rather than a document that merely quotes the marker.
  `event_count`, `level: high`.
- **`sigma/correlation/artex_guard_marker_then_destructive.yml`** — the guard marker and a destructive
  command co-occurring on one host within a window (defense guide §4.2, multi-stage). Combining an
  ARTEX-specific marker with the otherwise-generic destructive-command signal raises specificity.
  `temporal`, `level: high`.

Thresholds and windows are conservative defaults — tune them to your baseline. The pure web multi-stage
case in §4.2 (enumerate → probe → authenticate) still needs base rules specific to your environment,
because that pattern does not reduce to a single ARTEX-unique User-Agent. A generic behavioral Sigma base
template to start from is provided in [defense guide §4.2](../docs/defense-en.md#42-siem-correlation-rules);
it is kept out of this tested rule tree because it cannot be grounded in ARTEX source.

## Network rules (Suricata)

Sigma covers host and log telemetry. The two ARTEX User-Agents observable on the wire both ship as
[Suricata](https://suricata.io) rules in [`suricata/`](suricata/): the enrichment prober's `artex-enrich/1.0`
(`enrich/enrich.go`) with a presence signature plus a high-rate enumeration variant (sid 1000001–1000002),
and the norma SDK WebFetch tool's attack-phase `norma/0.4` (`github.com/Autumn-27/norma/tool/webfetch.go`) with a presence signature
(sid 1000003). Other worker tools (Bash-run `curl`, `nmap`) use their own User-Agents and carry no
ARTEX-unique fingerprint, so the network layer is intentionally narrow to these two UAs; see
[`suricata/README.md`](suricata/README.md) for the scope, the TLS caveat, and how to validate with
`suricata -T` and a reference pcap.

## ATT&CK coverage

The techniques these rules tag are collected into a [MITRE ATT&CK](https://attack.mitre.org/) Navigator
layer in [`attack/artex_navigator_layer.json`](attack/) — eight techniques across six tactics
(Reconnaissance, Command and Control, Execution, Impact, Credential Access, Collection), each grounded in a rule's `attack.*` tags and
scored by detection strength (ARTEX-specific signature vs. generic hunting lead). Open it in the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see which ARTEX behaviour each
rule covers; see [`attack/README.md`](attack/README.md) for the scoring, the technique-to-rule map, and
the honest scope (coverage is not completeness). A [consistency test](tests/attack/run.sh) keeps the layer
from drifting away from the rule set.

## Indicator list (machine-readable)

For defenders who want the atomic indicators rather than the detection logic,
[`indicators/artex_indicators.csv`](indicators/) collects the unique fingerprints ARTEX emits into one
CSV to drop into a threat-intelligence platform, a SIEM lookup, or a host-triage checklist — the enrichment
and self-update User-Agents, the guard audit marker, the server/proxy default endpoints, the recording-proxy
CA certificate, and the PostgreSQL exploration-graph schema fingerprint — each row recording the source file
it is grounded in and the rule (if any) built on it. The same indicators ship as a
ready-to-import [MISP](https://www.misp-project.org/) event
([`indicators/artex_indicators.misp.json`](indicators/)), so a defender running MISP (or exporting on to
STIX from it) does not have to map the CSV columns by hand — the rule-backed fingerprints are flagged
`to_ids`, the host-forensic ports and schema fingerprint are not. Generic hunting leads (the
destructive commands) and the norma SDK's shared `norma/0.4` WebFetch User-Agent — a wire signature carried
by Suricata sid 1000003, not an ARTEX-unique string — are deliberately kept out of the import-ready list to
avoid false positives; see
[`indicators/README.md`](indicators/README.md) for the columns, the MISP type mapping, the honest caveats,
and the consistency test that keeps both the CSV and the MISP event from drifting.

## Host triage

The rules above serve defenders with a SIEM, a network sensor, or a threat-intel platform. For the other
responder — the one at a single suspected host's shell, with no SIEM — [`triage/artex_host_triage.py`](triage/)
is a read-only script that answers "did ARTEX run here?" from local state. It operationalizes the same
fingerprints, **plus the three host/DB indicators the CSV deliberately carries without a Sigma rule**
(the server listen port, the recording-proxy endpoint, and the PostgreSQL exploration schema),
which are not log- or network-observable and can only be checked on the box. It also flags the recorder's
subprocess env-injection — a running process carrying a proxy var together with a mitmproxy CA-trust var
(`agent/worker.go`), read from `/proc` or a `--proc-from` dump. Every finding is a triage lead carrying the
same caveat as its indicator row. See [`triage/README.md`](triage/README.md); a built-in `--self-test`
runs as a merge-gate (below).

## Tests

The rules ship with reproducible tests in [`tests/`](tests/), each needing only Docker:

- **Suricata** ([`tests/suricata/run.sh`](tests/suricata/run.sh)) first validates that the whole rules file
  loads under `suricata -T --init-errors-fatal` (a rule that fails to parse is caught even if no capture
  exercises it), then synthesizes a deterministic capture with scapy, runs `suricata -r` over it, and asserts
  that the presence rule fires once per probe, the velocity rule trips past its rate threshold, and a
  benign-User-Agent capture produces zero alerts. No binary capture is committed — the test regenerates it on
  every run.
- **Sigma** ([`tests/sigma/run.sh`](tests/sigma/run.sh)) runs the `sigma check` and `sigma convert` validation
  below as an executable test: it asserts 0 errors, that the whole tree compiles to a backend query, that each
  atomic indicator string survives into that query, and that a correlation rule fails to convert on its own —
  proving it genuinely depends on the atomic rule it references.
- **Sigma live event-matching** ([`tests/sigma_match/run.sh`](tests/sigma_match/run.sh)) extends the Sigma suite
  above from validity/compilation to actual firing, for both the atomic and the correlation rules: for every
  atomic rule it asserts a representative malicious sample event matches and a benign one does not (for example,
  a standalone CA file under `.mitmproxy/` does not trip the recording-proxy rule, whose `|all` also requires the
  `_ca/` directory); for every correlation rule it asserts a positive timeline fires (threshold met inside the
  window within one group) and negative ones stay quiet (below threshold, window exceeded, split group, or a
  missing leg). pySigma does all parsing; the test only walks the compiled condition tree and aggregation spec,
  deciding which events feed a referenced rule with the same atomic matcher. It brings "a detection you cannot
  run is only a claim" to the Sigma side the way Suricata has it.
- **ATT&CK layer** ([`tests/attack/run.sh`](tests/attack/run.sh)) checks that the ATT&CK coverage layer stays
  consistent with the rules: its scored techniques and tactics must be exactly the `attack.*` tags on the
  rule set, and each technique must name a rule file that exists. Adding a rule without updating the layer
  (or vice versa) fails the test.
- **Indicator source-of-truth** ([`tests/indicators/run.sh`](tests/indicators/run.sh)) checks that each rule's
  pinned indicator is still the string the upstream source emits — `artex-enrich/1.0` in `enrich/enrich.go`,
  `artex-selfupdate` in `selfupdate/`, the guard marker in `guard/guard.go`, the destructive tokens in
  `db/db.go` — and is still pinned in the rule. It catches the drift the other three miss: an upstream re-sync
  that changes a User-Agent or marker while every rule still compiles and fires. The same test re-reads the
  machine-readable [`indicators/artex_indicators.csv`](indicators/artex_indicators.csv) and asserts every
  published row is still grounded in its source and rule, so the artifact a defender imports cannot drift
  either. Finally it asserts that every upstream source it reads is listed in the CI workflow's `push` and
  `pull_request` paths filter, so a PR touching only a newly pinned source cannot skip the test and let that
  drift pass the merge gate. This makes "grounded in a string verified in this repository's source, not
  inferred" (above) a guard, not a promise.
- **MISP export consistency** ([`tests/misp/run.sh`](tests/misp/run.sh)) proves the MISP event
  ([`indicators/artex_indicators.misp.json`](indicators/artex_indicators.misp.json)) is a valid MISP document —
  it loads under [pymisp](https://github.com/MISP/PyMISP), whose object model rejects any attribute type that
  is not a real MISP type, so the artifact really imports rather than merely looking like MISP — and that it
  stays row-for-row in sync with the CSV above: same values, the intended MISP type/category per indicator,
  and a `to_ids`/`disable_correlation` flag that mirrors the CSV's honesty (rule-backed = actionable, so
  `to_ids` on; host-forensic port = triage hint, so `to_ids` off and correlation disabled). The event is
  hand-maintained alongside the CSV — it carries curated comments, UUIDs, and tags the CSV does not — so
  when you add, remove, or retype a CSV row you update the MISP event in the same commit, and this test
  fails until the two agree.
- **Sigma backend portability** ([`tests/sigma_backends/run.sh`](tests/sigma_backends/run.sh)) proves the rules
  convert beyond the single Splunk example: the whole tree (atomic + correlation) compiles on Splunk, the
  Elasticsearch `eql` target, and Grafana Loki, and the five atomic rules still compile on backends that do not
  support Sigma correlations (Elasticsearch `lucene`, the Microsoft `kusto` backend). It backs the per-backend
  support matrix in [Validate and convert](#validate-and-convert) below with a re-runnable check.
- **SigmaHQ convention lint** ([`tests/sigma_lint/run.sh`](tests/sigma_lint/run.sh)) runs the full SigmaHQ
  validator set (the `pySigma-validators-sigmahq` plugin, which plain `sigma check` does not load) against the
  documented baseline in [`tests/sigma_lint/validators.yml`](tests/sigma_lint/validators.yml) and asserts 0
  issues. It also checks that the full set actually ran and that only four deliberately excluded, documented
  checks remain, so a rule that picks up a new convention issue (a mis-cased title, an off-taxonomy field)
  fails the build.

Alongside the eight rule suites, three non-suite gates run in the same CI workflow and in
[`tests/run-all.sh`](tests/run-all.sh): a harness-sync check (that `run-all.sh`, CI, and the suite
directories name the same suites in the same order); the [host-triage tool](triage/)'s `--self-test`
([`tests/triage-selftest.sh`](tests/triage-selftest.sh)), which builds a synthetic host and asserts every
triage check fires on it while a clean host produces zero findings; and a defense-template consistency
check ([`tests/check-defense-template.sh`](tests/check-defense-template.sh)) that re-runs the facts the
defense guide states about its inline Sigma correlation template — `sigma check` passes, it converts on
splunk/eql/loki, lucene and kusto reject the correlation, and the Korean and English copies carry a
byte-identical rule body — since that template lives as prose outside this rule tree and no suite would
otherwise catch it going stale against an upstream sigma-cli.

Each script exits non-zero on any failed assertion. See [`tests/README.md`](tests/README.md).

## How to read these honestly

- **Static indicators can be changed.** An operator can set a different User-Agent, so the absence of
  `artex-enrich/1.0` or `artex-selfupdate` does **not** mean safety. The durable signal is *behaviour* —
  a single source chaining recon → enumeration → probing → auth/injection attempts, adapting to responses,
  running without pause. That layer is described in the defense guide (sections 1, 2, and 4.1–4.2); the
  `sigma/correlation/` rules above ship it as deployable correlations (velocity, fan-out, guard-block
  burst, and a guard-marker-with-destructive-command multi-stage), and the pure web multi-stage case
  still needs base rules specific to your environment.
- **The destructive-command rule is generic hunting.** It mirrors ARTEX's guard deny list, but the same
  commands are run by legitimate administrators. Treat a hit as a lead, allow-list your environment, and
  do not attribute it to ARTEX on its own.
- **Port indicators are host-forensic, not Sigma.** The ARTEX server default `:8787` and the recording
  proxy `127.0.0.1:8788` (`cmd/artex/main.go`) are best checked on a suspected host with `ss`/`netstat`,
  so they are documented in the defense guide and listed in the [indicator CSV](indicators/) for triage,
  rather than shipped as a noisy network rule. The [host-triage script](triage/) runs exactly those
  host-local checks (ports, recording-proxy artifacts, log markers, and the PostgreSQL schema) for a
  responder who has shell access but no SIEM.

## Validate and convert

These rules are validated with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) (pySigma). To reproduce:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install sigma-cli

# structural + best-practice validation (expect: 0 errors, 0 issues)
sigma check detections/sigma/

# full SigmaHQ convention set with the documented baseline for this standalone
# rule set (expect: 0 issues). Plain `sigma check` above does not load these.
pip install pySigma-validators-sigmahq
sigma check --validation-config detections/tests/sigma_lint/validators.yml detections/sigma/

# compile to a target query language, e.g. Splunk
sigma plugin install splunk
sigma convert -t splunk --without-pipeline detections/sigma/artex_enrich_user_agent.yml

# convert the whole tree so the correlation rules can resolve the atomic rules they reference by id
sigma convert -t splunk --without-pipeline detections/sigma/
```

The baseline enforces every SigmaHQ convention except four checks that encode SigmaHQ's monorepo filing scheme
and taxonomy, which do not apply to a standalone rule set; each exclusion and its rationale is documented in
[`tests/sigma_lint/validators.yml`](tests/sigma_lint/validators.yml) and enforced by the lint test above.

### Sigma backend portability

The `sigma/correlation/` rules reference their atomic base rules by `id`, so they only convert on backends
that support Sigma correlation conversion. That support varies by backend, so `-t` choice matters. The matrix
below is measured against the pinned reference (`sigma-cli` 3.1.0, latest compatible backends) and reproduced
by [`tests/sigma_backends/run.sh`](tests/sigma_backends/run.sh):

- **Converts the whole tree (atomic + correlation):** Splunk (`-t splunk`), Elasticsearch EQL (`-t eql`),
  Grafana Loki (`-t loki`). Convert `detections/sigma/` directly and you get the correlation queries too.
- **Atomic rules only (correlations not yet supported):** Elasticsearch Lucene (`-t lucene`), OpenSearch
  (`-t opensearch_lucene`), and the Microsoft `kusto` backend that targets Sentinel and Defender XDR
  (`-t kusto`). On these, convert the five atomic rules and express the correlation window natively in the
  product (e.g. a Sentinel scheduled-analytics `summarize ... by bin(TimeGenerated, 30m)`). Pass the whole
  directory and the conversion stops with "Backend does not support correlation rules."

```sh
# atomic rules only, e.g. for Microsoft Sentinel / Defender (kusto backend)
sigma plugin install kusto
sigma convert -t kusto --without-pipeline \
  detections/sigma/artex_enrich_user_agent.yml \
  detections/sigma/artex_selfupdate_egress.yml \
  detections/sigma/artex_guard_audit_framing.yml \
  detections/sigma/artex_recording_proxy_ca.yml \
  detections/sigma/destructive_command_hunting.yml
```

Known edges at the pinned versions: the Elasticsearch ES|QL target (`-t esql`) rejects the guard-marker rule
(`String value expressions are not supported`), so convert the other three atomic rules there; and the IBM
QRadar plugin (`ibm-qradar-aql`) is not compatible with the pinned pySigma and needs `--force-install`, so it
is not covered by the test. Run `sigma list targets` for the backends installed in your environment.

The examples above use `--without-pipeline`, which emits the generic field names from the rule bodies
(`cs-user-agent`, `cs-host`, `CommandLine`). To match your product's schema, drop that flag and apply a
processing pipeline with `-p` (see `sigma list pipelines`). Note that a product pipeline maps field names but
may also need a target table the rules' generic `logsource` does not specify — e.g. `-p sentinel_asim` stops
with "Unable to determine table name" until you set `query_table` for your data, so map the fields and the
destination table to your environment before deploying.

## Contributing

Detection and hardening contributions are welcome. New rules should keep every indicator grounded in an
observable fact, state limitations in the `description`, pass the SigmaHQ validator baseline cleanly
(`sigma check --validation-config tests/sigma_lint/validators.yml`), and avoid any content that reads as
attack guidance. See [`../CONTRIBUTING.en.md`](../CONTRIBUTING.en.md).
