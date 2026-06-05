#!/usr/bin/env python3
"""Probe S0 public daemon boundary through documented local-safe endpoints."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def request_json(base_url: str, path: str, timeout: float = 2.0) -> dict:
    req = urllib.request.Request(base_url.rstrip("/") + path, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        return {"status": response.status, "body": json.loads(body), "path": path, "method": "GET"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    evidence = {
        "schema_version": "splendor.e2e.public-boundary.v1",
        "checked_at": utc_now(),
        "base_url": args.base_url,
        "mode": "explicit_local_acceptance_dev",
        "caller_evidence": {
            "transport": "compose-local-network",
            "auth_model": "documented local-dev health/capabilities only",
            "mutating_calls_attempted": False,
            "health_or_capabilities_authorize_actions": False,
        },
        "requests": [],
        "failures": [],
    }

    for _ in range(60):
        try:
            evidence["requests"].append(request_json(args.base_url, "/health"))
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            time.sleep(0.5)
    else:
        evidence["failures"].append(f"daemon health endpoint was not reachable: {last_error}")

    if not evidence["failures"]:
        try:
            evidence["requests"].append(request_json(args.base_url, "/capabilities"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            evidence["failures"].append(f"daemon capabilities endpoint failed: {exc}")

    paths = {item.get("path") for item in evidence["requests"]}
    if {"/health", "/capabilities"} - paths:
        evidence["failures"].append("missing required health/capabilities public-boundary evidence")
    for item in evidence["requests"]:
        if item.get("status") != 200:
            evidence["failures"].append(f"{item.get('path')} returned {item.get('status')}")

    evidence["status"] = "passed" if not evidence["failures"] else "failed"
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    traffic = out.parent / "api-traffic.ndjson"
    with traffic.open("w", encoding="utf-8") as handle:
        for item in evidence["requests"]:
            handle.write(json.dumps(item, sort_keys=True) + "\n")

    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
