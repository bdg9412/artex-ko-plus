#!/usr/bin/env python3
"""Export observed local practice-proxy events for one ARTEX verification.

This reads existing logs only. It never generates requests, creates events,
changes timestamps, or uploads evidence. Continuous coverage applies solely to
the practice forwarding proxy and its ftp-access-v1 rule.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID


SCOPE = "local-practice-detector"
CONTROL_SCOPE = "practice-forwarding-proxy"
RULE_ID = "ftp-access-v1"
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
MAX_UPLOAD_ROWS = 5000
MAX_RECORD_BYTES = 128 * 1024
MAX_HEARTBEAT_GAP = timedelta(seconds=15)
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


class ExportError(ValueError):
    pass


def timestamp(value):
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        raise ExportError("Timestamps must use RFC3339 with an explicit timezone.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise ExportError("Invalid RFC3339 timestamp.") from exc


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportError("Duplicate JSON fields are not valid evidence.")
        result[key] = value
    return result


def reject_constant(_value):
    raise ExportError("Non-finite JSON numbers are not valid evidence.")


def read_snapshot(path):
    """Read one bounded append-only snapshot; never silently trim a partial row."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ExportError(f"Cannot read required log: {path.name}.") from exc
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SNAPSHOT_BYTES:
            raise ExportError(f"{path.name} must be a regular file no larger than 32 MiB.")
        data = stream.read(before.st_size)
        after = os.fstat(stream.fileno())
        try:
            current = path.stat()
        except OSError as exc:
            raise ExportError(f"{path.name} changed while reading; retry export.") from exc
        if (len(data) != before.st_size or after.st_size < before.st_size
                or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ExportError(f"{path.name} rotated or shrank while reading; retry export.")
    if data and not data.endswith(b"\n"):
        raise ExportError(f"{path.name} ends in an incomplete row; retry after the next heartbeat.")
    return data


def records(data, name):
    for line_number, raw in enumerate(data.splitlines(keepends=True), 1):
        if len(raw) > MAX_RECORD_BYTES:
            raise ExportError(f"{name}:{line_number} exceeds the 128 KiB record limit.")
        try:
            event = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                               parse_constant=reject_constant)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ExportError(f"{name}:{line_number} is not a valid UTF-8 JSON object.") from exc
        if not isinstance(event, dict):
            raise ExportError(f"{name}:{line_number} must be a JSON object.")
        try:
            observed = timestamp(event.get("timestamp"))
        except ExportError as exc:
            raise ExportError(f"{name}:{line_number} has an invalid timestamp.") from exc
        yield event, observed, raw


def continuous_coverage(data, start, end):
    segments = []
    chain = []
    active_instance = None
    process_started = None
    previous_time = None
    allowed_events = {"started", "heartbeat", "stopped", "evidence_write_failed"}
    for event, observed, _raw in records(data, "metadata.jsonl"):
        if (event.get("scope") != SCOPE or event.get("rule_id") != RULE_ID
                or event.get("event") not in allowed_events
                or not isinstance(event.get("instance_id"), str)
                or not event["instance_id"]
                or not isinstance(event.get("healthy"), bool)):
            raise ExportError("metadata.jsonl has an unexpected service journal record.")
        if previous_time is not None and observed < previous_time:
            raise ExportError("Service journal timestamps moved backwards; coverage cannot be confirmed.")
        previous_time = observed
        if event["event"] == "started" and event["healthy"]:
            if chain:
                segments.append((active_instance, process_started, chain))
            active_instance = event["instance_id"]
            process_started = observed
            chain = [observed]
        elif (event["event"] == "heartbeat" and event["healthy"]
              and event["instance_id"] == active_instance):
            if chain and observed - chain[-1] > MAX_HEARTBEAT_GAP:
                segments.append((active_instance, process_started, chain))
                chain = []
            chain.append(observed)
        else:
            if chain:
                segments.append((active_instance, process_started, chain))
            active_instance, process_started, chain = None, None, []
    if chain:
        segments.append((active_instance, process_started, chain))
    for instance, started, observations in segments:
        if observations[0] <= start and observations[-1] >= end:
            left = max(index for index, value in enumerate(observations) if value <= start)
            right = next(index for index, value in enumerate(observations) if value >= end)
            selected = observations[left:right + 1]
            gaps = [(b - a).total_seconds() for a, b in zip(selected, selected[1:])]
            return {
                "complete": True,
                "instance_id": instance,
                "process_started_at": iso(started),
                "first_healthy_observation": iso(selected[0]),
                "last_healthy_observation": iso(selected[-1]),
                "healthy_observations": len(selected),
                "maximum_gap_seconds": max(gaps, default=0),
                "allowed_gap_seconds": MAX_HEARTBEAT_GAP.total_seconds(),
            }
    raise ExportError("No continuous healthy proxy coverage for the full window. "
                      "Keep the proxy running through the end plus one heartbeat; "
                      "a restart, late start, or heartbeat gap requires a new verification.")


def select_events(data, name, kind, verification_id, start, end, instance_id):
    selected = []
    for event, observed, raw in records(data, name):
        if (event.get("event_kind") != kind or event.get("control_scope") != CONTROL_SCOPE):
            raise ExportError(f"{name} contains records from an unexpected evidence source.")
        if event.get("artex_verification_id") != verification_id or not start <= observed <= end:
            continue
        if event.get("instance_id") != instance_id:
            raise ExportError(f"{name} contains matching events outside the covered proxy instance.")
        if kind == "alert" and event.get("rule_id") != RULE_ID:
            raise ExportError("alerts.jsonl contains an unexpected detection rule.")
        selected.append(raw)
    return b"".join(selected), len(selected)


def export_evidence(log_dir, verification_id, start, end, output_dir, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        if str(UUID(verification_id)) != verification_id:
            raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise ExportError("Use the exact canonical UUID shown for the ARTEX verification.") from exc
    if start >= end or end - start > timedelta(hours=24):
        raise ExportError("The export window must be positive and no longer than 24 hours.")
    if end > now:
        raise ExportError("The end of the export window is still in the future; wait before exporting.")
    if output_dir.exists() or output_dir.is_symlink():
        raise ExportError("Output directory already exists; choose a new directory to preserve prior evidence.")

    # Read the journal first. A closing healthy heartbeat guarantees prior
    # synchronous audit/alert appends completed before their snapshots below.
    journal = read_snapshot(log_dir / "metadata.jsonl")
    coverage = continuous_coverage(journal, start, end)
    snapshots = {"metadata.jsonl": journal}
    outputs = {}
    counts = {}
    for kind, name in (("audit", "audit.jsonl"), ("alert", "alerts.jsonl")):
        snapshots[name] = read_snapshot(log_dir / name)
        outputs[name], counts[kind] = select_events(
            snapshots[name], name, kind, verification_id, start, end, coverage["instance_id"])
    if sum(map(len, outputs.values())) > MAX_UPLOAD_BYTES or sum(counts.values()) > MAX_UPLOAD_ROWS:
        raise ExportError("Selected evidence exceeds the 4 MiB / 5,000 record upload limit. "
                          "Nothing was exported; run a narrower verification.")
    manifest = {
        "version": 1,
        "generated_at": iso(now),
        "scope": SCOPE,
        "control_scope": CONTROL_SCOPE,
        "rule_id": RULE_ID,
        "verification_id": verification_id,
        "coverage_start": iso(start),
        "coverage_end": iso(end),
        "coverage": coverage,
        "counts": counts,
        "no_alerts": counts["alert"] == 0,
        "boundary": "Observed traffic through the local practice forwarding proxy only. "
                    "This does not establish coverage of direct target access or any enterprise SIEM.",
        "files": {name: {"bytes": len(data), "sha256": sha256(data)}
                  for name, data in outputs.items()},
        "source_snapshots": {name: {"bytes": len(data), "sha256": sha256(data)}
                             for name, data in snapshots.items()},
    }
    outputs["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".practice-evidence-", dir=output_dir.parent))
    try:
        for name, data in outputs.items():
            with os.fdopen(os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        if output_dir.exists() or output_dir.is_symlink():
            raise ExportError("Output directory appeared during export; choose a new directory.")
        staging.rename(output_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", required=True, type=Path)
    parser.add_argument("--verification-id", required=True)
    parser.add_argument("--start", required=True, help="RFC3339 start, normally execution start minus 30 seconds")
    parser.add_argument("--end", required=True, help="RFC3339 end, normally execution end plus 60 seconds")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = export_evidence(args.log_dir, args.verification_id, timestamp(args.start),
                                   timestamp(args.end), args.output_dir)
    except (ExportError, OSError) as exc:
        print(f"Export refused: {exc}", file=sys.stderr)
        return 1
    print(f"Exported actual proxy evidence to {args.output_dir.resolve()}")
    print(f"Audit events: {manifest['counts']['audit']}; alerts: {manifest['counts']['alert']}.")
    print("Upload audit.jsonl and alerts.jsonl using the exact coverage window in manifest.json.")
    if not manifest["counts"]["audit"]:
        print("No matching audit event was observed; ARTEX must treat the result as inconclusive.")
    print(manifest["boundary"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
