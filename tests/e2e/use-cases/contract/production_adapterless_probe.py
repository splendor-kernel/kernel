#!/usr/bin/env python3
"""Proves the production daemon cannot select a reachable acceptance provider."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures"))
from acceptance_provider_evidence import (  # noqa: E402
    provider_effect_state,
    read_provider_evidence,
)


TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
RUN_ID = "33333333-3333-4333-8333-333333333333"
IDEMPOTENCY_KEY = "corr-001-production-adapterless"


def utc(minutes: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(minutes=minutes)
    ).isoformat().replace("+00:00", "Z")


def credential(scope: str) -> dict[str, Any]:
    return {
        "credential_id": f"cred_corr_001_{scope}",
        "principal": {
            "app": {"app_principal_id": "app_corr_001", "label": "CORR-001"},
            "client_principal_id": "client_corr_001",
            "label": "CORR-001 production probe",
        },
        "scopes": [scope],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"daemon": {"daemon_id": "daemon_local"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def audit(caller: dict[str, Any]) -> dict[str, Any]:
    return {
        "principal": caller["principal"],
        "credential_id": caller["credential_id"],
        "requested_at": utc(0),
    }


def sign_work_order(
    root: Path, artifact_dir: Path, action: str, adapter: str, suffix: str
) -> dict[str, Any]:
    work_order = {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": f"wo_corr_001_{suffix}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "objective": "prove production daemon remains adapterless",
        "allowed_actions": [action],
        "allowed_adapters": [adapter],
        "allowed_permissions": [],
        "data_refs": [],
        "quotas": {"max_actions_per_tick": 1},
        "placement": {"target": "local_resident", "requires_gpu": False},
        "issued_at": utc(-1),
        "expires_at": utc(60),
        "revocation": "active",
    }
    unsigned = artifact_dir / f"{suffix}.unsigned.json"
    unsigned.write_text(json.dumps(work_order, sort_keys=True), encoding="utf-8")
    completed = subprocess.run(
        [
            str(root / "target/debug/splendorctl"),
            "work-order",
            "sign",
            "--input",
            str(unsigned),
            "--key-id",
            "work-order-local-key",
            "--secret",
            "splendor-local-work-order-secret",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def create_request(
    envelope: dict[str, Any], action: str, adapter: str
) -> dict[str, Any]:
    caller = credential("runs_create")
    return {
        "request_id": f"req-corr-001-{action}",
        "idempotency_key": IDEMPOTENCY_KEY,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": caller,
        "audit_attribution": audit(caller),
        "allowed_actions": [action],
        "allowed_adapters": [adapter],
        "allowed_permissions": [],
        "policy_actions": [],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "registered_actions": [{"name": action, "adapter": adapter}],
        "approval_policies": [],
        "circuit_breakers": [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"probe": "production-adapterless"},
        "snapshot_interval": 1,
    }


def request_json(
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    caller: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if caller is not None:
        headers["X-Splendor-Caller-Credential"] = json.dumps(caller, sort_keys=True)
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=None if body is None else json.dumps(body).encode("utf-8"),
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def provider_evidence(base_url: str) -> dict[str, Any]:
    return read_provider_evidence(base_url)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8077")
    parser.add_argument("--action-provider-url", default="http://127.0.0.1:8086")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    artifact_dir = Path(args.report_dir).resolve() / "production-adapterless"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    before = provider_evidence(args.action_provider_url)

    first_action = "missing.production.action"
    first_adapter = "daemon.local"
    first = create_request(
        sign_work_order(root, artifact_dir, first_action, first_adapter, "first"),
        first_action,
        first_adapter,
    )
    first_status, first_error = request_json(
        args.base_url, "POST", "/runs", body=first
    )

    retry_action = "missing.production.action.retry"
    retry_adapter = "artifact-store"
    retry = create_request(
        sign_work_order(root, artifact_dir, retry_action, retry_adapter, "retry"),
        retry_action,
        retry_adapter,
    )
    retry_status, retry_error = request_json(
        args.base_url, "POST", "/runs", body=retry
    )
    read_status, read_error = request_json(
        args.base_url,
        "GET",
        f"/runs/{RUN_ID}",
        caller=credential("runs_read"),
    )
    after = provider_evidence(args.action_provider_url)

    passed = (
        first_status == 503
        and first_error.get("code") == "action_adapter_unavailable"
        and first_error.get("details", {}).get("admission_stage")
        == "before_run_and_idempotency_commit"
        and retry_status == 503
        and retry_error.get("code") == "action_adapter_unavailable"
        and retry_error.get("details", {}).get("adapter") == retry_adapter
        and read_status == 404
        and read_error.get("code") == "invalid_run"
        and provider_effect_state(before) == provider_effect_state(after)
    )
    report = {
        "schema_version": "splendor.corr_001.production_adapterless.v1",
        "status": "passed" if passed else "failed",
        "first_create": {"status": first_status, "body": first_error},
        "same_idempotency_key_retry": {
            "status": retry_status,
            "body": retry_error,
        },
        "run_read": {"status": read_status, "body": read_error},
        "provider_evidence_before": before,
        "provider_evidence_after": after,
    }
    (artifact_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not passed:
        raise SystemExit(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
