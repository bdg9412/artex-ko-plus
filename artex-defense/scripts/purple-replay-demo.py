#!/usr/bin/env python3
"""Generate replay inputs from a disposable, loopback-only HTTP fixture.

Two synthetic orders and users exercise the same request before/after an
ownership check. No external target, credentials, SIEM or LLM is used.
"""

import argparse
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


def collect(enforce_ownership):
    events = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def do_GET(self):
            owners = {"/orders/1": "alice", "/orders/2": "bob"}
            owner = owners.get(self.path)
            actor = self.headers.get("X-Demo-User", "")
            if owner is None or actor != "alice":
                self.send_error(404)
                return
            cross_owner = actor != owner
            status = 403 if enforce_ownership and cross_owner else 200
            # This audit fact is derived from the fixture's ownership data, not
            # from the expected-match label or a request-supplied truth flag.
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": {"action": "order_access"},
                "actor": {"id": actor},
                "resource": {"owner": owner},
                "access": {"cross_owner": cross_owner},
                "http": {"path": self.path, "status_code": status},
            })
            body = json.dumps({"result": "denied" if status == 403 else "synthetic order"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Ignore system proxies: all traffic stays inside this process's host.
    opener = build_opener(ProxyHandler({}))
    try:
        statuses = []
        for path in ("/orders/1", "/orders/2"):
            request = Request(
                f"http://127.0.0.1:{server.server_port}{path}",
                headers={"X-Demo-User": "alice"},
            )
            try:
                with opener.open(request, timeout=5) as response:
                    statuses.append(response.status)
                    response.read()
            except HTTPError as response:
                statuses.append(response.code)
                response.read()
                response.close()
        expected = [200, 403 if enforce_ownership else 200]
        if statuses != expected or len(events) != 2:
            raise RuntimeError(f"Unexpected fixture responses: {statuses}")
        return events
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".local-runtime/replay-demo"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    before, after = collect(False), collect(True)
    streams = {
        "target-before.jsonl": [before[1]],
        "target-after.jsonl": [after[1]],
        "control.jsonl": [before[0], after[0]],
        "missing-telemetry.jsonl": [{k: v for k, v in after[1].items() if k != "access"}],
    }
    for name, events in streams.items():
        (args.output / name).write_text(
            "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events),
            encoding="utf-8",
        )
    rule = {"version": 1, "all": [{"field": "access.cross_owner", "op": "eq", "value": True}]}
    (args.output / "rule.json").write_text(json.dumps(rule, indent=2) + "\n", encoding="utf-8")
    print(f"Fixture logs written to {args.output.resolve()}")
    print("Same cross-owner request: before HTTP 200, after HTTP 403; own-order controls HTTP 200.")
    print("Replay should match both target files, not controls. Missing telemetry is inconclusive.")
    print("These are local fixture observations, not evidence of a deployed SIEM or real-world defense.")


if __name__ == "__main__":
    main()
