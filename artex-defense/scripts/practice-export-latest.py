#!/usr/bin/env python3
"""Export existing practice logs for a finding's latest completed file verification."""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence-local" / "juice-shop-defense"
KST = timezone(timedelta(hours=9), "KST")
SPEC = importlib.util.spec_from_file_location("practice_export", ROOT / "scripts" / "practice-export-evidence.py")
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


def finding_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", value):
        raise argparse.ArgumentTypeError("취약점 번호는 양의 정수로 입력하세요.")
    result = int(value)
    if result > 9223372036854775807:
        raise argparse.ArgumentTypeError("취약점 번호가 너무 큽니다.")
    return result


def read_latest(identifier):
    identifier = finding_id(str(identifier))
    # Select the latest execution before checking its state. Never fall back to
    # an older completed execution when the newest one is still running.
    query = f"""
WITH latest AS (
  SELECT id, source_kind, correlation_id, retest_id, retest_snapshot
  FROM finding_defense_executions
  WHERE finding_id = {identifier}
  ORDER BY id DESC LIMIT 1
), resolved AS (
  SELECT e.id, e.source_kind, e.correlation_id,
    CASE WHEN e.retest_snapshot->>'status' IN ('completed','failed','stopped')
      THEN e.retest_snapshot
      ELSE COALESCE(to_jsonb(r)-'snapshot', e.retest_snapshot) END AS retest
  FROM latest e LEFT JOIN finding_retests r ON r.id = e.retest_id
)
SELECT json_build_object('execution_id', id, 'source_kind', source_kind,
  'verification_id', correlation_id, 'status', retest->>'status',
  'created_at', retest->>'created_at', 'started_at', retest->>'started_at',
  'finished_at', retest->>'finished_at') FROM resolved;
"""
    try:
        result = subprocess.run(
            ["docker", "exec", "-e", "PGOPTIONS=-c default_transaction_read_only=on",
             "artex-local-postgres-1", "psql", "-X", "-q", "-t", "-A",
             "-v", "ON_ERROR_STOP=1", "-U", "artex", "-d", "artex", "-c", query],
            check=True, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EXPORTER.ExportError("로컬 ARTEX 데이터베이스를 읽지 못했습니다. Docker와 ARTEX 실행 상태를 확인하세요.") from exc
    if not result.stdout.strip():
        raise EXPORTER.ExportError("이 취약점의 방어 검증 실행이 없습니다. 화면에서 파일 방식으로 먼저 실행하세요.")
    try:
        record = json.loads(result.stdout)
    except ValueError as exc:
        raise EXPORTER.ExportError("실행 정보를 읽지 못했습니다. 내보내기를 중단합니다.") from exc
    if not isinstance(record, dict):
        raise EXPORTER.ExportError("실행 정보 형식이 올바르지 않습니다.")
    return record


def export_window(record):
    if record.get("source_kind") != "file":
        raise EXPORTER.ExportError("가장 최근 실행이 파일 방식이 아닙니다. 파일 방식으로 새 방어 검증을 실행하세요.")
    if record.get("status") != "completed":
        raise EXPORTER.ExportError("가장 최근 실행이 정상 완료되지 않았습니다. 실행 중이면 기다리고, 실패·중단이면 새로 실행하세요.")
    started = record.get("started_at")
    if started is None:
        started = record.get("created_at")
    try:
        started = EXPORTER.timestamp(started)
        finished = EXPORTER.timestamp(record.get("finished_at"))
    except EXPORTER.ExportError as exc:
        raise EXPORTER.ExportError("실행 시작·종료 시간이 없거나 올바르지 않아 내보낼 수 없습니다.") from exc
    if finished < started:
        raise EXPORTER.ExportError("실행 종료 시간이 시작 시간보다 빠릅니다.")
    # Match the upload form while covering fractional completion seconds.
    return started.replace(microsecond=0) - timedelta(seconds=30), finished.replace(microsecond=0) + timedelta(seconds=61)


def main():
    parser = argparse.ArgumentParser(description="취약점의 최신 파일 방어 검증에 해당하는 실제 로컬 로그를 내보냅니다.")
    parser.add_argument("finding_id", type=finding_id, help="취약점 상세 URL의 id 값 (예: 3)")
    args = parser.parse_args()
    try:
        record = read_latest(args.finding_id)
        start, end = export_window(record)
        now = datetime.now(timezone.utc)
        if now < end + timedelta(seconds=5):
            ready = (end + timedelta(seconds=5)).astimezone(KST).strftime("%H:%M:%S")
            raise EXPORTER.ExportError(f"종료 후 로그 수집 중입니다. 한국 시간 {ready} 이후 같은 명령을 다시 실행하세요.")
        execution_id = record.get("execution_id")
        if type(execution_id) is not int or execution_id <= 0:
            raise EXPORTER.ExportError("방어 검증 실행 번호가 올바르지 않습니다.")
        if not isinstance(record.get("verification_id"), str):
            raise EXPORTER.ExportError("방어 검증 식별자가 올바르지 않습니다.")
        output = EVIDENCE / f"execution-{execution_id}-{now.strftime('%Y%m%dT%H%M%S%fZ')}"
        manifest = EXPORTER.export_evidence(
            EVIDENCE / "logs", record.get("verification_id"), start, end, output, now=now)
    except EXPORTER.ExportError as exc:
        print(f"내보내기 중단: {exc}", file=sys.stderr)
        print("수집 종료 직후라면 5초 뒤 다시 실행하세요. 수집 시작 지연·재시작·공백이 있었다면 새 방어 검증이 필요합니다.", file=sys.stderr)
        return 1
    except OSError:
        print("내보내기 중단: 로그 읽기 또는 파일 저장에 실패했습니다. 파일 권한과 저장 공간을 확인하세요.", file=sys.stderr)
        return 1
    print(f"방어 검증 실행 #{execution_id}의 실제 로그를 저장했습니다.")
    print(f"폴더: {output}")
    print(f"감사 파일: audit.jsonl ({manifest['counts']['audit']}건)")
    print(f"경보 파일: alerts.jsonl ({manifest['counts']['alert']}건)")
    print("범위·무결성 기록: manifest.json")
    print(f"수집 시작 (한국 시간): {start.astimezone(KST).isoformat()}")
    print(f"수집 종료 (한국 시간): {end.astimezone(KST).isoformat()}")
    print("동일한 실행의 파일 등록 화면에 두 JSONL 파일을 올리고 위 수집 범위를 입력하세요.")
    print("전체 범위 수집 확인은 이 로컬 프록시의 /ftp 탐지 규칙에만 해당합니다.")
    if not manifest["counts"]["audit"]:
        print("해당 실행의 감사 로그가 0건입니다. 탐지 여부를 확정할 수 없습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
