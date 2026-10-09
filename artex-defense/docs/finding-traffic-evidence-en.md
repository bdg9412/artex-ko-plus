# Vulnerability multi-traffic evidence

> This document is an English translation of the upstream (original) ARTEX design doc. It records,
> for contributors and maintainers, the design of the feature that links vulnerabilities to traffic
> evidence. The original (Chinese) is preserved in
> [`finding-traffic-evidence-zh.md`](finding-traffic-evidence-zh.md).
>
> 한국어판: **[취약점 다중 트래픽 증거 (finding-traffic-evidence-ko.md)](finding-traffic-evidence-ko.md)**.

The **Linked traffic** panel on the vulnerability detail screen supports multi-select across pages, entering a role and a description, ordering, and unbinding. The traffic page likewise lets you select several records at once and link them to a single existing vulnerability. Vulnerability evidence that a task inherits is read-only; to change it you must enter the source task.

**Agent automatic traffic binding** in system settings is off by default, and its read/write interface is `agent_traffic_binding` under `/api/settings`. Turning it on increases the Token consumption that comes from inspecting requests/responses, from tool calls, and from the prompt, and the new setting takes effect from the next round's Agent onward. While it is off, the automatic-binding parameters and the supplementary binding tool are hidden, the automatic-binding guidance is not injected, and automatic bindings newly submitted by an already-running session are rejected. Manual binding, traffic capture, and reading or exporting saved evidence are unaffected.

Once the feature is on, the default flow is: save the finding → automatically trigger the report Agent → cross-check and bind traffic → write the report against the latest evidence version. In `evidence`, the reporter leaves the verification commands, the key output, and the real traffic IDs and their roles that are already in hand. The report Agent combines the vulnerability detail with the execution record, confirms with `traffic_search` / `traffic_get`, then calls `bind_finding_traffic`, reads the latest `version`, and saves the report. When the switch is off, the report Agent does not additionally receive the raw traffic search/read tools and does not bind automatically; it can still read manually bound snapshots and generate a report.

It stays compatible with existing callers. You can still bind explicitly and immediately via `report_finding`'s `traffic_refs` / `evidence_hint_id`. Binding is optional. For a non-HTTP vulnerability such as TCP, when nothing has been collected yet, or when you cannot find the exact record, you may omit the references and still report and write the report normally. We recommend leaving other verifiable evidence — command output, logs, and so on — and explaining why you did not bind; no new required input field is added. Every ID you submit must be valid and its body intact. If even one fails, the entire binding operation for this call is rolled back. If an explicit bind-while-reporting fails, the whole report is rolled back. Appending the same snapshot again does not add a binding and does not overwrite the description.

## Agent ID scheme and report version

New optional parameters were added to `report_finding`, and the array order is the initial evidence order:

```json
{
  "traffic_refs": [
    {"traffic_id": "real traffic ID", "role": "baseline", "note": "normal account request"},
    {"traffic_id": "another real traffic ID", "role": "proof", "note": "reproduction request"}
  ]
}
```

The roles are `baseline` (normal control), `proof` (vulnerability proof), `verification` (supplementary verification), and `supporting` (supporting evidence, the default). First cross-check against real records with `traffic_search` / `traffic_get`. Use the domain and the timestamp only to narrow down candidates, and do not assume task attribution.

The prompt draws on [CyberStrikeAI's vulnerability-reporting tool guidance](https://github.com/RuoJi6/CyberStrikeAI/blob/54d56774b8bd285817d16d48b70a4a5e6e0963f7/internal/app/vulnerability_tools.go), combined with this project's optional-binding convention, but without adding a rule that makes a reason-for-not-binding mandatory. You must not guess IDs, and you should not probe repeatedly just to fill in evidence.

The first line of the return value is still `finding recorded: <exploration node ID>`. The JSON that follows provides the standalone vulnerability record's `finding_id`, the exploration node's `finding_node_id`, and a binding summary.

- `get_finding_traffic(finding_id)` uses the **standalone vulnerability record ID** and returns an ordered list together with `version`. Passing `binding_id`, `side=request|response`, `offset`, and `length` lets you read in segments, with each segment capped at 8192 bytes.
- `update_finding_report`'s `finding_id` **continues to use the exploration node ID.** Fill the newly added `evidence_version` with the version you actually read. If the evidence changes while the report is being generated, a write from the old version is rejected, so you must read again and regenerate.
- When an old report call does not pass a version, it is not treated as having overwritten existing traffic evidence. When a binding, description, role, or ordering changes, the existing report is flagged as needing an update.

With automatic binding on, `add_hint` / `add_task_hint` can store `traffic_refs` on a single hint or on each element of a batch `hints`. When the planner reports on someone's behalf, it can pass `evidence_hint_id` to unambiguously select the references within the hint for this task, and it cannot reference inherited hints. The system does not guess a binding from the domain, the timestamp, or the browsing history. A failed submission does not create a partially formed vulnerability or trigger the report early.

When an existing vulnerability is missing a binding, you can supplement it with `bind_finding_traffic(finding_id, traffic_refs)` without registering it again. `list_findings` / `list_task_findings` / `node_detail` / `get_task_node_detail` return explicit `finding_id` and `finding_node_id`, and the old `id` keeps its exploration-node meaning.

At startup, only optional properties are added to the old tool schema; the original default traffic-tool binding is extended to the report Agent as well, and the supplementary binding tool is, by default, left to the report Agent. Custom binding lists, prompts, descriptions, and the enabled state are preserved as-is. Guidance is added all at once after the final tool assembly is done. The reporting role is responsible for handing over evidence already in hand, and the report Agent is responsible for cross-checking, binding, and writing the report. When a platform conversation has no task context, it must hand off to the task Agent as a structured hint and must not report directly. Before judging a task complete, it must first hand over the evidence already in hand, and it is not forced to wait when there is no traffic to bind. A failed `report_finding` does not trigger the report Agent.

## API

The base path is `/api/exploration/findings/{finding_id}/traffic`, and it uses the standalone vulnerability ID. Authentication follows the existing scheme, and `context_task` verifies task visibility and whether inherited reads are read-only.

The request and return for each method and relative path are as follows:

- `GET`: returns the ordered summary, the evidence version, and the version the report adopted.
- `POST`: adds `{"traffic_refs":[...]}` in a single batch.
- `PATCH /{binding_id}`: edits with `{"version":1,"role":"proof","note":"description"}`.
- `DELETE /{binding_id}`: deletes with `{"version":1}`.
- `PUT /order`: reorders with `{"version":1,"binding_ids":["2","1"]}`, and the list must be complete.
- `GET /{binding_id}`: returns the snapshot metadata and a length-limited body preview.
- `GET /{binding_id}/body`: takes `side`, `offset`, and `length`, and with `download=1` it downloads the complete raw bytes.

A version/ordering set conflict or a write while archiving is in progress returns `409`, a write against an inherited item returns `403`, and a binding that does not exist or does not belong to the vulnerability returns `404`. When reading and verifying traffic or attachments fails, a clear error is returned.

## Storage and migration

At startup an idempotent migration is run against PostgreSQL. It newly adds the `traffic_evidence_snapshots` and `finding_traffic_bindings` tables and the `findings.evidence_version` / `report_evidence_version` columns (default `0`). It does not guess supplementary bindings from past text.

A snapshot stores the original traffic ID, the capture time, the URL, the method, the status, the request/response headers, the body length, and the SHA-256. The body is stored by hash at `<data>/evidence/blobs/<first two characters>/<hash>.bin`, kept separate from the cleanup-subject `data/traffic`, so that several vulnerabilities can share a snapshot/body. A snapshot offers no interface for updating its content, and if verification does not match, reading and exporting fail.

Under the original traffic write lock, the full body is read, including large body blobs and old directory records. The file is persisted and verified first, then a single PostgreSQL transaction records the exploration node, the intent relationship, the vulnerability, the snapshot, and the binding, and only after the commit is the planner notified. On failure, unreferenced files may remain, but no partially recorded business record is created.

The PostgreSQL advisory lock `7337741004` coordinates evidence files and SQL references. A task row lock forbids evidence modification after it has been queued for archiving. Restore holds the evidence lock across the whole process, from body installation to metadata commit. Deleting a vulnerability cascades to remove its bindings as well.

The cleaner runs every hour and only reclaims the content of tasks that are unreferenced and not in progress, with a minimum delay of 24 hours. Ordinary traffic cleanup does not touch the evidence directory. When backing up hot data, back up PostgreSQL and `data/evidence` together.

## Export and archiving

Markdown includes the ordered evidence list and the version, JSON adds the metadata, and CSV adds the count and the binding IDs. `md-zip` keeps the vulnerability Markdown while also providing the following structure:

```text
evidence/<finding_id>/<binding_id>/
  manifest.json
  request.http
  response.http
  request.bin
  response.bin
```

Markdown references the packets with relative links. Before sending the download, it finishes copying the attachments, verifying the hashes, compressing, syncing to disk, and verifying the CRC read of every ZIP entry. If an entry is missing or corrupted, the entire download fails. A complete attachment preserves the raw binary bytes exactly.

Archive v3 collects snapshots and bodies according to the vulnerability-binding relationships, without depending on the original traffic or the domain. It cleans hot data only after the package verification is done, and it keeps shared evidence. Restore first verifies the installed body, then restores the metadata and bindings in a transaction, and supports retries on failure. v1/v2 can still be restored, and missing new fields are explicitly filled with `0`.

## Verification and boundaries

Each test package has its own freshly created PostgreSQL test database, specified via `ARTEX_PG_DSN`, so that leftover task/model fixtures do not trigger background execution. Run the full test suite of the relevant packages and confirm that no test was skipped because of missing configuration:

```sh
# Set ARTEX_PG_DSN to the relevant isolated test database before running each package. If the explicit setting fails, it must raise an error.
go test ./<package> -count=1
go test -race -p 1 ./evidence ./db ./agent ./server -run 'TestEvidence|TestFindingTraffic|TestFindingEvidence|TestReportFindingAtomicContract|TestTaskArchive'
```

Frontend verification includes `npx tsc --noEmit`, a Biome check of the affected files, a Webpack build, and a `NEXT_EXPORT=1` static export. Use a separate cache directory so that a running dev server is not overwritten.

Local end-to-end acceptance verification uses a separate port, a controlled HTTP / domain-HTTPS target, and a temporary data directory, and it covers the two binding entry points, selection across pages, ordering/description, error guidance, inherited read-only, and download. It also covers export after the original traffic has been deleted, archiving, hot-body reclamation, and restore with hash verification.

The first version uses a global evidence-coordination lock. While a bulk binding/export or a slow attachment download is in progress, other evidence operations may wait. Without a recording or a complete body, evidence cannot be fabricated. This feature does not change the capture switch, nor does it address the certificate problem when accessing an IP directly over HTTPS.
