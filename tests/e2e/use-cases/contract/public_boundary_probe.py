#!/usr/bin/env python3
"""Probe S0 public daemon boundary through documented local-safe endpoints."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def caller_credential(scopes: list[str]) -> dict:
    return {
        "credential_id": "cred_uc_e2e_s0_public_boundary",
        "principal": {
            "app": {"app_principal_id": "app_uc_e2e_s0", "label": "UC-E2E-S0"},
            "client_principal_id": "client_uc_e2e_s0",
            "label": "S0 public-boundary probe",
        },
        "scopes": scopes,
        "binding": {"tenant": {"tenant_id": "00000000-0000-0000-0000-00000000e200"}},
        "audience": {"daemon": {"daemon_id": "daemon_local"}},
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "revocation": "active",
    }


def request_json(base_url: str, path: str, scopes: list[str], timeout: float = 2.0) -> dict:
    credential = caller_credential(scopes)
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        headers={
            "Accept": "application/json",
            "X-Splendor-Caller-Credential": json.dumps(credential, sort_keys=True, separators=(",", ":")),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        return {
            "status": response.status,
            "body": json.loads(body),
            "path": path,
            "method": "GET",
            "credential_id": credential["credential_id"],
            "scopes": scopes,
        }


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
            "auth_model": "schema-aligned caller credential header validated by daemon security path",
            "credential_backed": True,
            "mutating_calls_attempted": False,
            "health_or_capabilities_authorize_actions": False,
        },
        "requests": [],
        "failures": [],
    }

    for _ in range(60):
        try:
            evidence["requests"].append(request_json(args.base_url, "/health", ["health_read"]))
            break
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP Error {exc.code}: {exc.reason}; body={exc.read().decode('utf-8', errors='replace')}"
            time.sleep(0.5)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            time.sleep(0.5)
    else:
        evidence["failures"].append(f"daemon health endpoint was not reachable: {last_error}")

    if not evidence["failures"]:
        try:
            evidence["requests"].append(
                request_json(args.base_url, "/capabilities", ["capabilities_read"])
            )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            evidence["failures"].append(f"daemon capabilities endpoint failed: HTTP {exc.code}; body={body}")
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
