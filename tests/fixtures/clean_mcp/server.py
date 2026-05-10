"""Minimal clean MCP fixture — should score 10/10.

Mirrors the friend_mcp pattern: stdio JSON-RPC, single outbound host,
TLS on, no shell, no filesystem writes, no inbound network."""

import json
import os
import sys
import requests


def _api_get(path: str, params: dict | None = None) -> dict:
    token = os.environ.get("DEMO_TOKEN")
    if not token:
        return {"error": "DEMO_TOKEN env var is not set"}
    base = os.getenv("DEMO_API_URL", "https://example-api.com")
    headers = {"X-API-Token": token}
    try:
        r = requests.get(f"{base}{path}", headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            return {"error": f"API returned status {r.status_code}"}
        return r.json()
    except Exception:
        return {"error": "request failed"}


def get_thing() -> dict:
    return _api_get("/api/thing")


def main() -> None:
    for raw in sys.stdin:
        try:
            msg = json.loads(raw)
        except Exception:
            continue
        method = msg.get("method")
        if method == "tools/call":
            result = get_thing()
            sys.stdout.write(json.dumps({"id": msg.get("id"), "result": result}) + "\n")
            sys.stdout.flush()
