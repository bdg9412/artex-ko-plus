#!/usr/bin/env python3
"""Generate real UI evidence for the OrcaRouter Cyber Inference profile.

Runs the repository's own Next.js static export, drives the real profile sheet
with Playwright/Chromium, and writes ``orca-evidence/`` (manifest + PNGs) into
the checkout. The model list shown in the UI comes from the authoritative
catalog (``GET https://api.orcarouter.ai/v1/models?capability=chat``): the
automation fetches it itself and answers the app's discovery call with exactly
those ids, so the screenshot cannot drift from the catalog.

Nothing secret is used: only a placeholder API key for masking, and no
inference request is sent.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

CATALOG_URL = "https://api.orcarouter.ai/v1/models?capability=chat"
TEXT_ENDPOINTS = {"openai", "anthropic", "gemini", "openai-response"}
NON_TEXT_ENDPOINTS = {"image-generation", "openai-video", "jina-rerank", "embeddings"}

ROOT = pathlib.Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
OUT = WEB / "out"
EVIDENCE = ROOT / "orca-evidence"
PLACEHOLDER_KEY = "sk-orca-evidence-placeholder-0001"


def chat_models(payload: dict) -> list[dict]:
    models = []
    for record in payload.get("data") or []:
        if not isinstance(record, dict):
            continue
        model_id = (record.get("id") or "").strip()
        endpoints = record.get("supported_endpoint_types") or []
        if not model_id or not isinstance(endpoints, list) or not endpoints:
            continue
        if not (set(endpoints) & TEXT_ENDPOINTS):
            continue
        if set(endpoints) <= NON_TEXT_ENDPOINTS:
            continue
        models.append(record)
    return models


def fetch_catalog() -> dict:
    request = urllib.request.Request(CATALOG_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def run(argv: list[str], cwd: pathlib.Path, env: dict | None = None) -> None:
    print("+", " ".join(argv), flush=True)
    subprocess.run(argv, cwd=str(cwd), check=True, env=env)


def build_export() -> None:
    env = dict(os.environ)
    env["NEXT_EXPORT"] = "1"
    env["NODE_ENV"] = "production"
    run(["npx", "--no-install", "next", "build"], WEB, env)


def serve(directory: pathlib.Path) -> tuple[ThreadingHTTPServer, int]:
    handler = partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: A003 - silence per-request noise
        pass


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shoot(page, name: str) -> pathlib.Path:
    path = EVIDENCE / name
    page.screenshot(path=str(path))
    return path


def main() -> int:
    catalog = fetch_catalog()
    models = chat_models(catalog)
    ids = [m["id"] for m in models]
    image_ids = [
        m["id"]
        for m in models
        if "image" in (((m.get("architecture") or {}).get("input_modalities")) or [])
    ]
    if not ids:
        raise SystemExit("authoritative catalog returned no chat models")
    print(f"catalog: {len(ids)} chat models, {len(image_ids)} image-input models", flush=True)

    build_export()
    if not (OUT / "system" / "llm" / "index.html").is_file():
        raise SystemExit("static export is missing system/llm/index.html")

    EVIDENCE.mkdir(exist_ok=True)
    server, port = serve(OUT)
    base = f"http://127.0.0.1:{port}"
    print(f"serving {OUT} at {base}", flush=True)

    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                executable_path="/usr/bin/chromium", args=["--no-sandbox"]
            )
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.add_init_script(
                "localStorage.setItem('artex_token','orca-evidence-token');"
                "document.cookie='artex_token=orca-evidence-token; path=/';"
            )

            def api_route(route, request):
                path = request.url.split("/api/", 1)[-1].split("?")[0]
                if path == "llm/models":
                    body = {"ok": True, "models": ids}
                elif path == "llm/profiles":
                    body = {"profiles": []}
                elif path == "llm/pool":
                    body = {"chain": [], "enabled": False}
                elif path == "llm/retry-policy":
                    body = {}
                else:
                    body = {}
                route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps(body),
                )

            page.route("**/api/**", api_route)
            page.goto(f"{base}/system/llm/", wait_until="networkidle", timeout=120000)
            page.wait_for_selector("text=새로 만들기", timeout=60000)
            page.click("text=새로 만들기")
            page.wait_for_selector("#p-name", timeout=30000)

            # Format -> OrcaRouter Cyber Inference (real Radix select in the sheet).
            page.click("[data-slot='select-trigger']")
            page.click("[role='option']:has-text('OrcaRouter Cyber Inference')")
            page.wait_for_selector("#p-model", timeout=30000)

            # Base URL is the provider's own origin, filled by the provider defaults.
            base_url = page.input_value("#p-base-url")
            if base_url.rstrip("/") != "https://api.orcarouter.ai/v1":
                raise SystemExit(f"unexpected base URL in the sheet: {base_url}")

            api_key = page.locator("#p-api-key")
            api_key.fill(PLACEHOLDER_KEY)
            secret_masked = api_key.get_attribute("type") == "password" and api_key.input_value() == PLACEHOLDER_KEY
            api_key_visible = api_key.is_visible()
            controls_enabled = page.locator("#p-model").is_enabled() and page.locator("#p-name").is_enabled()
            if not (secret_masked and api_key_visible and controls_enabled):
                raise SystemExit(
                    f"auth assertions failed: masked={secret_masked} visible={api_key_visible} enabled={controls_enabled}"
                )
            auth_png = shoot(page, "auth-methods.png")

            # Load the real catalog into the picker. The items live inside the
            # popover, so they are only queried once it is open.
            with page.expect_response("**/api/llm/models") as discovery:
                page.click("[aria-label='API에서 사용 가능한 모델 불러오기']")
            discovered = discovery.value.json()
            if not discovered.get("ok") or not discovered.get("models"):
                raise SystemExit(f"model discovery did not return a catalog: {discovered}")
            page.wait_for_timeout(500)
            page.click("#p-model")
            page.wait_for_selector("[data-orca-model]", state="visible", timeout=30000)
            # The popover animates in with a zoom; measure only the settled panel.
            page.wait_for_timeout(600)

            items = page.locator("[data-orca-model]")
            item_count = items.count()
            panel = page.locator("[data-orca-model]").first.locator("xpath=..")
            trigger = page.locator("#p-model")
            box = panel.bounding_box()
            tbox = trigger.bounding_box()
            if not box or not tbox:
                raise SystemExit("could not measure the dropdown geometry")
            delta = (tbox["x"] + tbox["width"]) - (box["x"] + box["width"])
            styles = panel.evaluate(
                """el => {
                    const s = getComputedStyle(el);
                    return {background: s.backgroundColor, borderWidth: s.borderTopWidth, borderColor: s.borderTopColor};
                }"""
            )
            opaque = _is_opaque(styles["background"])
            visible_border = float(styles["borderWidth"].replace("px", "") or 0) > 0 and not _is_transparent(
                styles["borderColor"]
            )
            dropdown_open = items.first.is_visible() and box["height"] > 0
            if item_count != len(ids):
                raise SystemExit(f"dropdown shows {item_count} items, catalog has {len(ids)}")
            if not (dropdown_open and opaque and visible_border and abs(delta) <= 2):
                raise SystemExit(
                    f"dropdown assertions failed: open={dropdown_open} opaque={opaque} border={visible_border} delta={delta}"
                )
            dropdown_png = shoot(page, "text-model-dropdown.png")
            browser.close()
    finally:
        server.shutdown()

    manifest = {
        "automation": {
            "framework": "playwright",
            "passed": True,
            "catalog_source": CATALOG_URL,
            "catalog_model_count": len(ids),
            "image_model_count": len(image_ids),
            "note": "Real static export of this repository driven in Chromium; the app's "
            "model-discovery call is answered with the authoritative chat catalog.",
        },
        "artifacts": [
            {
                "kind": "auth-methods",
                "path": auth_png.name,
                "sha256": sha256(auth_png),
                "ui": {
                    "api_key_visible": True,
                    "secret_masked": True,
                    "controls_enabled": True,
                },
            },
            {
                "kind": "text-model-dropdown",
                "path": dropdown_png.name,
                "sha256": sha256(dropdown_png),
                "ui": {
                    "dropdown_open": True,
                    "item_count": item_count,
                    "opaque_background": True,
                    "visible_border": True,
                    "trigger_panel_right_delta": round(delta, 2),
                },
            },
        ],
    }
    (EVIDENCE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"evidence written to {EVIDENCE}", flush=True)
    return 0


def _is_opaque(color: str) -> bool:
    return _alpha(color) == 1.0


def _is_transparent(color: str) -> bool:
    return _alpha(color) == 0.0


def _alpha(color: str) -> float:
    color = color.strip()
    if color.startswith("rgba"):
        return float(color.rstrip(")").split(",")[-1])
    return 1.0 if color and color != "transparent" else 0.0


if __name__ == "__main__":
    sys.exit(main())
