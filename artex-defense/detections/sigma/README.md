# ARTEX detection rules (Sigma / host · log · SIEM)

English · [한국어](README.ko.md)

> 한국어: 이 디렉터리는 [방어·탐지 가이드(docs/defense-ko.md)](../../docs/defense-ko.md) 4절
> "탐지 규칙"의 의사 규칙을 실제로 배포 가능한 [Sigma](https://sigmahq.io) 규칙으로 옮긴 것입니다.
> 네트워크 계층은 [`../suricata/`](../suricata/)가 담당합니다. 모든 규칙은 자신이 소유하거나 서면
> 허가를 받은 시스템을 지키는 **방어·탐지 목적에만** 사용하십시오. 한국어 전체 문서는
> **[README.ko.md](README.ko.md)** 를, 전체 탐지 묶음 개요는 **[../README.ko.md](../README.ko.md)** 를 보십시오.

The host, log, and SIEM layer of the ARTEX detection set. These [Sigma](https://sigmahq.io) rules
formalize the pseudo-rules in the defense guide ([Korean](../../docs/defense-ko.md) ·
[English](../../docs/defense-en.md), section 4) into a vendor-neutral format you convert to your own
SIEM or EDR query language. Every indicator is grounded in a string or behaviour verified in this
repository's source, not inferred. The network layer lives under [`../suricata/`](../suricata/); the
full detection set — the ATT&CK coverage layer, the indicator CSV / MISP export, and the host-triage
script — is indexed in [`../README.md`](../README.md).

## Atomic rules

One rule, one observable fact. Convert them individually or as part of the whole tree.

- **[`artex_enrich_user_agent.yml`](artex_enrich_user_agent.yml)** — *ARTEX Asset Enrichment Probe
  User-Agent*. Inbound `artex-enrich/1.0` User-Agent from asset enrichment (`enrich/enrich.go`).
  Target-side, supporting indicator. `level: high`.
- **[`artex_selfupdate_egress.yml`](artex_selfupdate_egress.yml)** — *ARTEX Self-Update Egress
  User-Agent*. Outbound `artex-selfupdate` User-Agent from the self-update routine
  (`selfupdate/github.go`). Host/forensic egress indicator. `level: medium`.
- **[`artex_guard_audit_framing.yml`](artex_guard_audit_framing.yml)** — *ARTEX Platform Guard
  Audit-Log Framing*. The platform-guard control marker written to the audit log on a blocked tool
  call (`guard/guard.go`). Host/forensic indicator. `level: high`.
- **[`artex_recording_proxy_ca.yml`](artex_recording_proxy_ca.yml)** — *ARTEX Recording-Proxy MITM CA
  Certificate Artifact*. Creation of the recording proxy's MITM CA file under the
  `_ca/mitmproxy-ca-cert.pem` layout (`traffic/traffic.go`). Host/forensic artifact; the bare filename
  is shared with standalone mitmproxy, so it is a hunting lead. `level: medium`.
- **[`destructive_command_hunting.yml`](destructive_command_hunting.yml)** — *Destructive Command
  Execution (ARTEX Guard-List Hunting)*. Destructive shell/DB commands mirroring the ARTEX guard's
  built-in deny list (`db/db.go` seed). Generic hunting lead, **not** an ARTEX signature. `level: medium`.

## Correlation rules (behaviour) — [`correlation/`](correlation/)

Static strings can be changed; behaviour is harder to hide. These Sigma **correlation** rules encode the
behaviour-based layer of the defense guide (sections 4.1–4.2 and 4.4). Each references an atomic rule
above by its `id`, so **convert the whole `sigma/` tree, not a single correlation file**, or the
reference will not resolve (the [Sigma test](../tests/sigma/) asserts exactly this dependency).

- **[`correlation/artex_enrich_scan_velocity.yml`](correlation/artex_enrich_scan_velocity.yml)** —
  *Enrichment Scan Velocity*. A burst of `artex-enrich/1.0` probes from one source in a short window
  (enrichment runs at concurrency 4 with no rate limit) — the velocity the single-request rule misses.
  `event_count`, `level: high`.
- **[`correlation/artex_enrich_fanout.yml`](correlation/artex_enrich_fanout.yml)** — *Enrichment
  Fan-Out*. One source carrying the enrichment User-Agent to many *distinct* hosts: machine-speed breadth
  across an asset list, where the distinct-host count, not request volume, is the tell. `value_count`,
  `level: high`.
- **[`correlation/artex_guard_block_burst.yml`](correlation/artex_guard_block_burst.yml)** —
  *Guard-Block Burst*. Repeated platform-guard control markers on one host — an actively engaged ARTEX
  run tripping its own guard, not a document that merely quotes the marker. `event_count`, `level: high`.
- **[`correlation/artex_guard_marker_then_destructive.yml`](correlation/artex_guard_marker_then_destructive.yml)**
  — *Guard Marker With Destructive Command*. The guard marker and a destructive command co-occurring on
  one host within a window (defense guide §4.2, multi-stage): combining an ARTEX-specific marker with the
  otherwise-generic destructive-command signal raises specificity. `temporal`, `level: high`.

Thresholds and windows are conservative defaults — tune them to your baseline. The pure web multi-stage
case (enumerate → probe → authenticate) still needs base rules specific to your environment, because that
pattern does not reduce to a single ARTEX-unique User-Agent; a generic behavioural base template to start
from is in the [defense guide §4.2](../../docs/defense-en.md), kept out of this tested tree because it
cannot be grounded in ARTEX source.

## Scope and honesty — read before deploying

- **Static indicators can be changed.** An operator can set a different User-Agent or clean up the CA
  file, so the absence of an atomic indicator does **not** mean safety. The durable signal is the
  behaviour the `correlation/` rules key on — one source chaining recon → enumeration → probing →
  auth/injection attempts, adapting to responses, running without pause.
- **The destructive-command rule is generic hunting.** It mirrors ARTEX's guard deny list, but the same
  commands are run by legitimate administrators. Treat a hit as a lead, allow-list your environment, and
  do not attribute it to ARTEX on its own.
- **Ports and schema are host-forensic, not Sigma.** The server default `:8787` and recording proxy
  `127.0.0.1:8788` (`cmd/artex/main.go`), and the PostgreSQL exploration-graph schema, are best checked on
  a suspected host, so they ship in the [indicator CSV](../indicators/) and the
  [host-triage script](../triage/) rather than as noisy rules.
- **`logsource` and field names are generic.** The rules use generic `category`/`product` log sources and
  field names (`cs-user-agent`, `CommandLine`, `TargetFilename`). Map them to your product's schema with a
  pipeline (`-p`) at convert time; see the backend notes below.

## Validate and convert

Validated with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) (pySigma). From the repository root:

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install sigma-cli

# structural + best-practice validation (expect: 0 errors, 0 issues)
sigma check detections/sigma/

# full SigmaHQ convention set with this rule set's documented baseline (expect: 0 issues)
pip install pySigma-validators-sigmahq
sigma check --validation-config detections/tests/sigma_lint/validators.yml detections/sigma/

# compile the WHOLE tree so the correlation rules resolve the atomic rules they reference by id
sigma plugin install splunk
sigma convert -t splunk --without-pipeline detections/sigma/
```

Backends vary in correlation support, so the `-t` choice matters: Splunk, Elasticsearch EQL, and Grafana
Loki convert the whole tree, while Elasticsearch Lucene, OpenSearch, and the Microsoft `kusto` backend
convert the five atomic rules only (express the window natively in the product). The measured per-backend
matrix and the `--without-pipeline` / `-p` field-mapping notes are in [`../README.md`](../README.md), and
they are reproduced by [`../tests/sigma_backends/`](../tests/sigma_backends/).

## Tests

Four reproducible suites under [`../tests/`](../tests/) cover these rules, each needing only Docker:
[`sigma/`](../tests/sigma/) (validation, whole-tree compilation, and that a correlation rule fails to
convert alone), [`sigma_match/`](../tests/sigma_match/) (the rules actually fire on malicious samples and
stay quiet on benign ones), [`sigma_backends/`](../tests/sigma_backends/) (portability across five
backends), and [`sigma_lint/`](../tests/sigma_lint/) (the full SigmaHQ validator baseline, 0 issues). See
[`../tests/README.md`](../tests/README.md).

## Contributing

Detection contributions are welcome. New rules should keep every indicator grounded in an observable fact,
state limitations in the `description`, pass the SigmaHQ validator baseline cleanly
(`sigma check --validation-config ../tests/sigma_lint/validators.yml .`), and avoid any content that reads
as attack guidance. See [`../../CONTRIBUTING.en.md`](../../CONTRIBUTING.en.md) and the network layer in
[`../suricata/`](../suricata/) / [`../README.md`](../README.md).
