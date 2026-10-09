# ARTEX indicators (machine-readable)

English · [한국어](README.ko.md)

> 한국어: [`artex_indicators.csv`](artex_indicators.csv) 는 ARTEX 가 실제로 내보내는 고유 지문(침해지표,
> IoC)을 한 파일로 모은 것입니다. 위협 인텔리전스 플랫폼·SIEM 조회 테이블·호스트 분류 작업에 바로
> 넣을 수 있게 기계가 읽는 CSV 로 둡니다. 모든 값은 이 저장소 소스에서 확인한 문자열이며, 각 행의
> 출처 파일과 탐지 규칙을 함께 적습니다. 배경 설명은 [방어·탐지 가이드(docs/defense-ko.md)](../../docs/defense-ko.md)
> 2절 "방어자가 관측할 수 있는 지문"에 있습니다. 자신이 소유하거나 서면 허가를 받은 시스템을 지키는
> **방어·탐지 목적에만** 사용하십시오. 한국어 전체 문서는 **[README.ko.md](README.ko.md)** 를
> 보십시오.

A single, machine-readable list of the unique fingerprints ARTEX itself emits, for defenders who want the
atomic indicators rather than the detection logic: drop [`artex_indicators.csv`](artex_indicators.csv)
into a threat-intelligence platform, a SIEM lookup table, or a host-triage checklist. Every value is a
string verified in this repository's source — the same grounding the
[detection rules](../README.md) and the defense guide
([Korean](../../docs/defense-ko.md) · [English](../../docs/defense-en.md), section 2) rely on — and each
row records where it comes from and which rule (if any) is built on it.

## Columns

- **`id`** — a stable slug for the indicator.
- **`type`** — the kind of indicator: `http.user-agent`, `string` (a literal to hunt for in logs/files),
  `port`, `ip-dst|port`, or `other` (a host artifact that fits none of the above, e.g. a database schema
  object name). These map onto the equivalent MISP/STIX attribute types.
- **`value`** — the exact indicator. Preserved verbatim, including the non-ASCII guard marker.
- **`perspective`** — `target` (observable in traffic *toward* a system ARTEX probes) or `forensic`
  (observable *on* a host where ARTEX ran or was relayed through). The defense guide keeps these apart on
  purpose; mixing them produces false conclusions.
- **`source`** — the repository-relative source file(s) that emit the value, `;`-separated. This is the
  grounding: if an upstream re-sync changes the emitter, the indicator here must change with it.
- **`rule`** — the detection rule(s) built on the exact value, `;`-separated, or empty for host-forensic
  indicators that are triaged directly rather than shipped as a (noisy) rule.
- **`description`** — a one-line note, including the honest caveat where one applies.

## MISP event export

The same indicators ship as a ready-to-import [MISP](https://www.misp-project.org/) event,
[`artex_indicators.misp.json`](artex_indicators.misp.json), so a defender running a MISP instance (or a
threat-intelligence platform that ingests the MISP format) can import the fingerprints directly instead of
mapping the CSV columns by hand. STIX 2.1 is then one export away using MISP's own converter, so the
repository does not hand-roll a second, lossy format.

- **Type mapping.** Each CSV `type` becomes the equivalent MISP attribute type: `http.user-agent` →
  `user-agent`, the guard marker `string` → `pattern-in-file` (category *Artifacts dropped*), `port` →
  `port`, `ip-dst|port` → `ip-dst|port` (the composite value uses MISP's `ip|port` form, so
  `127.0.0.1:8788` is stored as `127.0.0.1|8788`), and the exploration-graph schema fingerprint `other` →
  `other` (category *Other*).
- **`to_ids` follows the `rule` column, honestly.** A row that a detection rule is built on is an actionable
  indicator and is flagged `to_ids: true`. A host-forensic row with no rule — the default listen port, the
  loopback proxy endpoint, and the exploration-graph schema fingerprint — is a triage hint, not a blocking
  IoC, so it is `to_ids: false` with `disable_correlation: true` (a common port, `127.0.0.1`, or a generic
  table name should not pollute MISP correlations). This is the same distinction the CSV `rule` column and
  the caveats below already carry.
- **Import.** `MISPEvent().load_file("artex_indicators.misp.json")` with
  [pymisp](https://github.com/MISP/PyMISP), the *Add event → Populate from … → MISP format* UI, or the REST
  API. The event is unpublished and tagged `tlp:clear`; set the distribution and publish state your instance
  needs on import.

## How to read this honestly

- **These are changeable fingerprints, not proof of safety.** An operator can set a different User-Agent
  or change a default port, so the *absence* of any value here does **not** mean ARTEX is absent. The
  durable signal is behaviour — see the correlation rules and sections 1, 2, and 4.1–4.2 of the defense
  guide.
- **Generic hunting leads are deliberately excluded.** Destructive shell/DB commands (`rm -rf`, `DROP
  DATABASE`, …) are *not* ARTEX fingerprints — legitimate administrators run them too. They are a hunting
  lead, not an import-ready indicator, so they live in
  [`destructive_command_hunting.yml`](../sigma/destructive_command_hunting.yml) and the defense guide, not
  in this list. Importing them as blocking indicators would cause false positives.
- **The norma WebFetch User-Agent is a wire signature, not an atomic indicator.** The worker's page-fetch
  tool sends `norma/0.4` during the attack phase, and Suricata sid 1000003 fires on the `norma/` prefix, but
  that string is the norma SDK's own hardcoded User-Agent (`github.com/Autumn-27/norma/tool/webfetch.go`), shared by every tool built on
  norma rather than an ARTEX-unique fingerprint. Importing it here as a blocking indicator would alert on all
  norma-SDK traffic — the same false-positive trap the destructive commands sit in — so it is deliberately
  kept out of this list and shipped only as the network rule
  ([`../suricata/README.md`](../suricata/README.md), sid 1000003). It is also grounded in a pinned dependency
  (`github.com/Autumn-27/norma`), not this repository's own source, so the source-of-truth test below cannot
  re-read it the way it re-reads ARTEX's own emitters.
- **Host-forensic ports are for triage, not blocking.** `:8787` and `127.0.0.1:8788` describe a host that
  may be running ARTEX; check them with `ss`/`netstat`, do not firewall them blindly.
- **The exploration-graph schema fingerprint is for DB inspection, not a network/file IoC.** The
  `exploration_nodes` table is the core of the exploration graph ARTEX keeps in PostgreSQL. Do not conclude
  from a single hit; confirm that the sibling tables (`exploration_edges`, `exploration_anchors`, `assets`,
  `companies`, `activity`) and the `agent_prompts` seed sit in the same database. An operator can rename or
  drop tables, so absence does not mean safety.
- **The host/DB rows with no `rule` have a runner.** The three indicators triaged directly rather than
  shipped as a Sigma rule — the listen ports, the recording-proxy endpoint, and this schema fingerprint —
  are all checked by the [host-triage script](../triage/) on a suspected host, so a responder with
  shell access but no SIEM does not have to run `ss`/`netstat`/`psql` by hand.

## Verification

The list is covered by the [indicator source-of-truth test](../tests/indicators/run.sh): it re-reads this
CSV and asserts, for every row, that the value is still present in the cited source file(s) and pinned in
the cited rule(s), and that every indicator the test grounds appears in the list. A row that drifts from
the source, or a known fingerprint dropped from the list, fails the test. Run it with:

```sh
detections/tests/indicators/run.sh
```

The MISP event is covered by its own [MISP export consistency test](../tests/misp/run.sh): it loads the
event under pymisp (so every attribute type is a real MISP type a server accepts) and asserts it stays
row-for-row in sync with this CSV — same values, the intended type/category, and the `to_ids` flag matching
the `rule` column. The event is maintained by hand alongside the CSV — it also carries curated per-attribute
comments, stable UUIDs, and event-level tags that the CSV does not hold, so there is no generator that would
overwrite them with lossy defaults. When you add, remove, or retype a CSV row, edit
[`artex_indicators.misp.json`](artex_indicators.misp.json) to match in the same commit (give a new attribute a
fresh `uuid` and a grounding `comment`); this test fails until the two agree, so the update cannot be silently
forgotten. Run it with:

```sh
detections/tests/misp/run.sh
```
