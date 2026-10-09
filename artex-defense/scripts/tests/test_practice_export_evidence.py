"""Tests for raw evidence preservation and conservative practice-proxy coverage."""

import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "practice_export", Path(__file__).resolve().parents[1] / "practice-export-evidence.py")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)
VERIFICATION_ID = "11111111-2222-4333-8444-555555555555"
OTHER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.out = self.root / "output"
        self.journal()
        (self.logs / "audit.jsonl").write_bytes(b"")
        (self.logs / "alerts.jsonl").write_bytes(b"")

    def row(self, kind="audit", seconds=10, verification_id=VERIFICATION_ID, **extra):
        event = {
            "timestamp": exporter.iso(START + timedelta(seconds=seconds)),
            "id": "event-1", "instance_id": "process-1", "event_kind": kind,
            "artex_verification_id": verification_id,
            "control_scope": exporter.CONTROL_SCOPE, "action": "allowed",
        }
        if kind == "alert":
            event["rule_id"] = exporter.RULE_ID
            event["audit_event_id"] = "event-1"
        event.update(extra)
        return (json.dumps(event, ensure_ascii=False) + "\n").encode()

    def journal(self, timestamps=range(-5, 31, 5), instance="process-1"):
        rows = []
        for index, seconds in enumerate(timestamps):
            rows.append(json.dumps({
                "timestamp": exporter.iso(START + timedelta(seconds=seconds)),
                "event": "started" if index == 0 else "heartbeat",
                "instance_id": instance, "healthy": True,
                "scope": exporter.SCOPE, "rule_id": exporter.RULE_ID,
            }) + "\n")
        (self.logs / "metadata.jsonl").write_text("".join(rows))

    def export(self, **kwargs):
        return exporter.export_evidence(
            self.logs, VERIFICATION_ID, START, START + timedelta(seconds=20), self.out,
            now=kwargs.get("now", START + timedelta(minutes=1)))

    def test_preserves_matching_raw_bytes_and_large_integer(self):
        audit = self.row(note="실제 로그", large_integer=9007199254740993).replace(b"\n", b"\r\n")
        unrelated = self.row(verification_id=OTHER_ID)
        outside = self.row(seconds=21)
        alert = self.row(kind="alert", id="alert-1")
        (self.logs / "audit.jsonl").write_bytes(unrelated + audit + outside)
        (self.logs / "alerts.jsonl").write_bytes(alert)
        result = self.export()
        self.assertEqual((self.out / "audit.jsonl").read_bytes(), audit)
        self.assertEqual((self.out / "alerts.jsonl").read_bytes(), alert)
        self.assertEqual(result["counts"], {"audit": 1, "alert": 1})
        self.assertEqual(result["files"]["audit.jsonl"]["sha256"], exporter.sha256(audit))
        self.assertFalse(result["no_alerts"])
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual((self.out / "audit.jsonl").stat().st_mode & 0o777, 0o600)

    def test_actual_zero_alerts_exports_empty_file(self):
        (self.logs / "audit.jsonl").write_bytes(self.row())
        result = self.export()
        self.assertTrue(result["no_alerts"])
        self.assertEqual((self.out / "alerts.jsonl").read_bytes(), b"")
        self.assertEqual(result["counts"], {"audit": 1, "alert": 0})

    def test_no_audit_remains_zero(self):
        result = self.export()
        self.assertEqual(result["counts"], {"audit": 0, "alert": 0})
        self.assertEqual((self.out / "audit.jsonl").read_bytes(), b"")

    def test_heartbeat_gap_rejects_full_coverage(self):
        self.journal([-5, 0, 20, 25])
        with self.assertRaisesRegex(exporter.ExportError, "continuous healthy"):
            self.export()
        self.assertFalse(self.out.exists())

    def test_stop_inside_window_rejects_coverage(self):
        self.journal([-5, 0, 5, 10, 15, 20])
        path = self.logs / "metadata.jsonl"
        rows = path.read_text().splitlines()
        record = json.loads(rows[3])
        record.update(event="stopped", healthy=False)
        rows[3] = json.dumps(record)
        path.write_text("\n".join(rows) + "\n")
        with self.assertRaisesRegex(exporter.ExportError, "continuous healthy"):
            self.export()

    def test_late_start_or_end_without_heartbeat_rejects_coverage(self):
        for stamps in ([5, 10, 15, 20, 25], [-5, 0, 5, 10, 15]):
            with self.subTest(stamps=stamps):
                self.journal(stamps)
                with self.assertRaises(exporter.ExportError):
                    self.export()

    def test_missing_partial_or_invalid_log_rejects_without_output(self):
        audit = self.logs / "audit.jsonl"
        for content in (None, self.row().rstrip(b"\n"), b'{"timestamp":null}\n'):
            with self.subTest(content=content):
                if content is None:
                    audit.unlink(missing_ok=True)
                else:
                    audit.write_bytes(content)
                with self.assertRaises(exporter.ExportError):
                    self.export()
                self.assertFalse(self.out.exists())

    def test_future_window_and_existing_output_are_refused(self):
        with self.assertRaisesRegex(exporter.ExportError, "future"):
            self.export(now=START)
        self.out.mkdir()
        marker = self.out / "keep.txt"
        marker.write_text("preserve")
        with self.assertRaisesRegex(exporter.ExportError, "already exists"):
            self.export()
        self.assertEqual(marker.read_text(), "preserve")

    def test_wrong_instance_or_rule_is_refused(self):
        (self.logs / "audit.jsonl").write_bytes(self.row(instance_id="other-process"))
        with self.assertRaisesRegex(exporter.ExportError, "instance"):
            self.export()
        (self.logs / "audit.jsonl").write_bytes(self.row())
        (self.logs / "alerts.jsonl").write_bytes(self.row(kind="alert", rule_id="other-rule"))
        with self.assertRaisesRegex(exporter.ExportError, "rule"):
            self.export()

    def test_record_count_limit_never_silently_truncates(self):
        (self.logs / "audit.jsonl").write_bytes(self.row() * 5001)
        with self.assertRaisesRegex(exporter.ExportError, "upload limit"):
            self.export()
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
