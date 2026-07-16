#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures"))
from canonical_fleet_profiles import (  # noqa: E402
    VPC_INSTANCE_FEATURES,
    VPC_NODE_CAPABILITIES,
)
from resident_http import request_json_no_redirect  # noqa: E402

FLEET_ID = "00000000-0000-4000-8000-000000000104"
TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "11111111-1111-4111-8111-222222222227"
ORCH = "22222222-2222-4222-8222-222222222227"
SPEC = "33333333-3333-4333-8333-333333333337"
ORCH_RUN = "44444444-4444-4444-8444-444444444447"
SPEC_RUN = "44444444-4444-4444-8444-555555555557"
PUBLISH_RUN = "44444444-4444-4444-8444-666666666667"
VPC_NODE = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE = "00000000-0000-4000-8000-000000000302"
WORK_ORDER_SPEC_DATA = "wo_uc_e2e_s7_specialist_data_read"
WORK_ORDER_INTERNAL = "wo_uc_e2e_s7_internal_artifact"
WORK_ORDER_PUBLISH = "wo_uc_e2e_s7_orchestrator_publish"
WORK_ORDER_REQUEST_MESSAGE = "wo_uc_e2e_s7_request_message"
WORK_ORDER_RESPONSE_MESSAGE = "wo_uc_e2e_s7_response_message"
VPC_WORK_ORDER_KEY_ID = "work-order-acceptance-vpc"
RUNTIME_IMAGE_IDENTITY = "splendor-kernel-runtime:acceptance-target-runtime"
DATA_REF_A = "dataset:tenant-a.finance.board_pack.v1"
DATA_REF_B = "dataset:tenant-b.finance.board_pack.v1"
INTERNAL_ARTIFACT = f"artifact://{TENANT_A}/board/specialist-analysis.md"
PUBLISHED_ARTIFACT = f"artifact://{TENANT_A}/board/report.md"
RAW_A = "TENANT_A_PROTECTED_REVENUE_RAW_9173"
RAW_B = "TENANT_B_PROTECTED_REVENUE_RAW_4421"
PUBLISH_ACTION_ID = "55555555-5555-4555-8555-555555555717"
TASK_REQUEST_ID = "55555555-5555-4555-8555-555555555707"
TASK_RESPONSE_ID = "55555555-5555-4555-8555-555555555708"
SMUGGLE_MESSAGE_ID = "55555555-5555-4555-8555-555555555709"
CAPABILITY_GRANT_ID = "77777777-7777-4777-8777-777777777707"
POLICY_ID = "policy_uc_e2e_s7_external_publish"


def utc(offset_minutes: int = 0) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    ).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def request_json(
    method: str,
    base_url: str,
    path: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None,
) -> tuple[int, dict[str, Any]]:
    return request_json_no_redirect(
        method,
        base_url.rstrip("/") + path,
        body,
        headers,
        context,
        timeout=20,
    )


def splendorctl(root: Path) -> list[str]:
    for candidate in [
        Path("/usr/local/bin/splendorctl"),
        root / "target" / "debug" / "splendorctl",
    ]:
        if candidate.exists():
            return [str(candidate)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s7_manager",
        "principal": {
            "app": {
                "app_principal_id": "app_uc_e2e_s7",
                "label": "UC-E2E-S7",
            },
            "client_principal_id": "client_uc_e2e_s7",
            "label": "UC-E2E-S7 manager",
        },
        "scopes": scopes
        or [
            "nodes_register",
            "instances_register",
            "nodes_heartbeat",
            "instances_heartbeat",
            "fleet_read",
            "fleet_dispatch",
            "work_orders_submit",
            "traces_read",
            "messages_send",
            "messages_read",
            "approvals_manage",
        ],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def resident_auth(
    root: Path,
    auth_dir: Path,
    scopes: list[str],
    *,
    tenant_id: str = TENANT_A,
) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "token",
        "--auth-dir",
        str(auth_dir),
        "--tenant-id",
        tenant_id,
        "--instance-id",
        VPC_INSTANCE,
    ]
    for scope in scopes:
        command.extend(["--scope", scope])
    process = subprocess.run(command, text=True, capture_output=True)
    if process.returncode != 0:
        raise SystemExit("resident caller token fixture failed")
    return json.loads(process.stdout)


def manager_approval_auth(root: Path, auth_dir: Path) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "manager-token",
        "--auth-dir",
        str(auth_dir),
        "--fleet-id",
        FLEET_ID,
        "--manager-id",
        "central-manager",
        "--scope",
        "approvals_manage",
    ]
    process = subprocess.run(command, text=True, capture_output=True)
    if process.returncode != 0:
        raise SystemExit("manager approval caller token fixture failed")
    return json.loads(process.stdout)


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {
        "principal": credential["principal"],
        "credential_id": credential["credential_id"],
        "requested_at": utc(0),
    }


def sec(credential: dict[str, Any]) -> dict[str, Any]:
    return {"credential": credential, "audit_attribution": audit(credential)}


def message_scope(
    credential: dict[str, Any], run_id: str, agent_id: str
) -> dict[str, Any]:
    return {
        **sec(credential),
        "tenant_id": TENANT_A,
        "run_id": run_id,
        "agent_id": agent_id,
    }


def credential_header(
    auth: dict[str, Any], mirror: dict[str, Any] | None = None
) -> dict[str, str]:
    return {
        "authorization": f"Bearer {auth['token']}",
        "x-splendor-caller-credential": json.dumps(
            mirror or auth["credential"], sort_keys=True
        ),
    }


def node_registration(vpc_url: str) -> dict[str, Any]:
    # This is intentionally identical to the canonical S4 VPC registration.
    return {
        "node_id": VPC_NODE,
        "kind": "vpc.worker",
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": list(VPC_NODE_CAPABILITIES),
            "constraints": {
                "placement_target": "customer_vpc",
                "data_locality": "vpc",
                "region": "eu-west",
                "resident_daemon_url": vpc_url,
                "runtime_image_identity": RUNTIME_IMAGE_IDENTITY,
                "trust_level": "acceptance",
            },
        },
        "runtime_version": "0.1-acceptance",
        "health": {
            "status": "healthy",
            "observed_at": utc(0),
            "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY},
        },
        "registered_at": utc(0),
    }


def instance_registration() -> dict[str, Any]:
    # Keep immutable identity metadata byte-for-byte equivalent to S4 fields.
    return {
        "instance_id": VPC_INSTANCE,
        "node_id": VPC_NODE,
        "runtime_mode": "resident",
        "hosted_tenants": [TENANT_A],
        "supported_features": list(VPC_INSTANCE_FEATURES),
        "runtime_version": "0.1-acceptance",
        "health": {
            "status": "healthy",
            "observed_at": utc(0),
            "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY},
        },
        "registered_at": utc(0),
    }


def exact_work_order(
    work_order_id: str,
    agent_id: str,
    run_id: str,
    action_name: str,
    adapter: str,
    permission: str,
    data_refs: list[str],
    *,
    required_capability: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": work_order_id,
        "tenant_id": TENANT_A,
        "agent_id": agent_id,
        "run_id": run_id,
        "objective": f"UC-E2E-S7 exact authority for {action_name}",
        "allowed_actions": [action_name],
        "allowed_adapters": [adapter],
        "allowed_permissions": [permission],
        "data_refs": data_refs,
        "quotas": {"max_actions_per_tick": 8, "max_action_duration_ms": 30000},
        "placement": {
            "target": "customer_vpc",
            "data_locality": "vpc",
            "requires_gpu": False,
            "dedicated_instance": False,
            "required_capabilities": [required_capability or action_name],
            "max_runtime_ms": 30000,
        },
        "issued_at": utc(-2),
        "expires_at": utc(60),
        "revocation": "active",
    }


def sign_work_order(
    root: Path,
    artifact_dir: Path,
    commands: Path,
    auth_dir: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    secret = (
        auth_dir / f"work-order-signing-{VPC_INSTANCE}.secret"
    ).read_text(encoding="ascii")
    command = splendorctl(root) + [
        "work-order",
        "sign",
        "--input",
        str(unsigned),
        "--key-id",
        VPC_WORK_ORDER_KEY_ID,
        "--secret",
        secret,
    ]
    with commands.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(command[:-1] + ["[REDACTED]"]) + "\n")
    process = subprocess.run(command, cwd=root, text=True, capture_output=True)
    with commands.open("a", encoding="utf-8") as log:
        log.write(process.stderr)
        log.write(f"exit={process.returncode}\n")
    if process.returncode != 0:
        raise SystemExit("VPC work-order signing failed")
    return json.loads(process.stdout)


def quota() -> dict[str, int]:
    return {
        "actions": 1,
        "action_duration_ms": 0,
        "filesystem_read_bytes": 0,
        "filesystem_write_bytes": 0,
        "network_read_bytes": 0,
        "network_write_bytes": 0,
        "http_requests": 0,
    }


def action(name: str, permission: str, **params: Any) -> dict[str, Any]:
    return {
        "name": name,
        "params": params,
        "side_effect_class": "External" if name.startswith("artifact") else "ReadOnly",
        "cost_estimate": None,
        "required_permissions": [permission],
        "preconditions": [],
        "postconditions": [],
    }


def approval_policy(expires_at: str) -> dict[str, Any]:
    return {
        "schema_version": "splendor.approval_policy.v1",
        "policy_id": POLICY_ID,
        "tenant_id": TENANT_A,
        "agent_id": ORCH,
        "action_name": "artifact.publish_external",
        "adapter": "artifact-store",
        "required_permission": "artifact.publish_external",
        "side_effect_class": "External",
        "risk_level": "high",
        "reason": "external artifact publication requires scoped approval",
        "expires_at": expires_at,
    }


def publish_create_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": f"req-uc-e2e-s7-{WORK_ORDER_PUBLISH}-{PUBLISH_RUN}",
        "idempotency_key": f"idem-uc-e2e-s7-{WORK_ORDER_PUBLISH}-{PUBLISH_RUN}",
        "tenant_id": TENANT_A,
        "agent_id": ORCH,
        "work_order": envelope,
        "allowed_actions": ["artifact.publish_external"],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": ["artifact.publish_external"],
        "registered_actions": [
            {
                "name": "artifact.publish_external",
                "adapter": "artifact-store",
                "required_permissions": ["artifact.publish_external"],
            }
        ],
        "policy_actions": [
            {
                "action_id": PUBLISH_ACTION_ID,
                "action": action(
                    "artifact.publish_external",
                    "artifact.publish_external",
                    publish_ref=PUBLISHED_ARTIFACT,
                ),
                "adapter": "artifact-store",
                "quota_usage": quota(),
                "satisfied_preconditions": [],
            }
        ],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "approval_policies": [approval_policy(envelope["expires_at"])],
        "circuit_breakers": [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"scenario": "UC-E2E-S7", "profile": "publish-only"},
        "snapshot_interval": 1,
    }


def internal_create_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_id": f"req-uc-e2e-s7-{WORK_ORDER_INTERNAL}-{ORCH_RUN}",
        "idempotency_key": f"idem-uc-e2e-s7-{WORK_ORDER_INTERNAL}-{ORCH_RUN}",
        "tenant_id": TENANT_A,
        "agent_id": ORCH,
        "work_order": envelope,
        "allowed_actions": ["artifact.create_internal"],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": ["artifact.create_internal"],
        "registered_actions": [
            {
                "name": "artifact.create_internal",
                "adapter": "artifact-store",
                "required_permissions": ["artifact.create_internal"],
            }
        ],
        "policy_actions": [],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "approval_policies": [],
        "circuit_breakers": [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {
            "scenario": "UC-E2E-S7",
            "profile": "internal-artifact-only",
        },
        "snapshot_interval": 1,
    }


def extract_action_outcome(operation: str, response: dict[str, Any]) -> dict[str, Any]:
    outcomes = response.get("body", {}).get("action_outcomes", [])
    if response.get("status") != 200 or not outcomes:
        raise SystemExit(
            f"{operation} did not return an action outcome: "
            + json.dumps(response, sort_keys=True)
        )
    return outcomes[0]


def extract_approval_context(outcome: dict[str, Any]) -> dict[str, Any]:
    challenge = outcome.get("approval_challenge")
    if not isinstance(challenge, dict) or not challenge:
        raise SystemExit("exact approval challenge missing from needs_approval outcome")
    return challenge


def approval_request_payload(
    challenge: dict[str, Any], reason: str
) -> dict[str, Any]:
    return {
        "approval_id": challenge["approval_id"],
        "tenant_id": challenge["tenant_id"],
        "agent_id": challenge["agent_id"],
        "run_id": challenge["run_id"],
        "action_id": challenge["action_id"],
        "action_name": challenge["action_name"],
        "adapter": challenge["adapter"],
        "policy_id": challenge["policy_id"],
        "risk_level": challenge.get("risk_level"),
        "audience": challenge["receipt_audience"],
        "expires_at": challenge["expires_at"],
        "reason": reason,
        "challenge": challenge,
    }


def event_kind(record: dict[str, Any]) -> str:
    kind = record.get("payload", {}).get("kind", {})
    return next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)


def event_payload(record: dict[str, Any]) -> dict[str, Any]:
    kind = record.get("payload", {}).get("kind", {})
    if isinstance(kind, dict) and kind:
        value = next(iter(kind.values()))
        return value if isinstance(value, dict) else {}
    return {}


def trace_id(record: dict[str, Any]) -> str:
    return str(record.get("payload", {}).get("trace_event_id", ""))


def build_event_ids(
    records: list[dict[str, Any]],
    manager_events: list[dict[str, Any]],
    *,
    trace_export_id: str,
    replay_id: str,
) -> dict[str, list[str]]:
    ids: dict[str, list[str]] = {
        "trace.exported.redacted": [trace_export_id],
        "replay.explained": [replay_id],
    }
    for event in manager_events:
        mapped = {
            "work_order.accepted": "work_order.accepted",
            "remote_message.delivered": "message.sent",
            "remote_message.received": "message.received",
            "remote_message.rejected": "message.denied",
        }.get(event.get("event_type"))
        if mapped:
            ids.setdefault(mapped, []).append(event.get("trace_event_id", ""))
    for record in records:
        kind = event_kind(record)
        payload = event_payload(record)
        action_name = payload.get("action", {}).get("name")
        text = json.dumps(payload, sort_keys=True)
        if kind == "ActionVerificationCompleted" and (
            "data_scope_verified" in text or action_name == "data.read_fixture"
        ):
            ids.setdefault("data_scope.verified", []).append(trace_id(record))
        if kind == "ActionDenied" and "data_scope_denied" in text:
            ids.setdefault("data_scope.denied", []).append(trace_id(record))
        if kind == "ActionExecuted" and action_name == "artifact.create_internal":
            ids.setdefault("artifact.created", []).append(trace_id(record))
        if kind == "ActionNeedsApproval" and action_name == "artifact.publish_external":
            ids.setdefault("artifact.publish.needs_approval", []).append(trace_id(record))
        if kind == "ActionExecuted" and action_name == "artifact.publish_external":
            ids.setdefault("artifact.publish.executed", []).append(trace_id(record))
        if kind == "ActionDenied" and (
            action_name == "artifact.publish_external"
            or "artifact_path_tenant_mismatch" in text
        ):
            ids.setdefault("artifact.publish.denied", []).append(trace_id(record))
        if kind == "StateCommitted":
            ids.setdefault("state.committed", []).append(trace_id(record))
        if kind == "RunResumed":
            ids.setdefault("run.resumed", []).append(trace_id(record))
        if kind == "DaemonAudit" and payload.get("endpoint") == "splendor.traces.export.redacted":
            ids.setdefault("trace.exported.redacted", []).append(trace_id(record))
        if kind == "DaemonAudit" and payload.get("endpoint") == "splendor.replay.explained":
            ids.setdefault("replay.explained", []).append(trace_id(record))
    return ids


def action_evidence(outcome: dict[str, Any]) -> dict[str, Any]:
    output = outcome.get("output") if isinstance(outcome.get("output"), dict) else {}
    verification = (
        outcome.get("verification")
        if isinstance(outcome.get("verification"), dict)
        else {}
    )
    artifacts = (
        verification.get("artifacts")
        if isinstance(verification.get("artifacts"), dict)
        else {}
    )
    return {
        "action_id": outcome.get("action_id"),
        "status": outcome.get("status"),
        "trace_event_id": outcome.get("trace_event_id")
        or artifacts.get("trace_event_id"),
        "artifact_path": output.get("artifact_path") or output.get("publish_ref"),
        "tenant_id": output.get("tenant_id"),
        "integrity": output.get("integrity"),
        "output": output,
    }


def action_execution_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "data.read_fixture": 0,
        "artifact.create_internal": 0,
        "artifact.publish_external": 0,
    }
    for record in records:
        if event_kind(record) != "ActionExecuted":
            continue
        name = event_payload(record).get("action", {}).get("name")
        if name in counts:
            counts[name] += 1
    return counts


def resolve_action_trace_evidence(
    records: list[dict[str, Any]], outcome: dict[str, Any], action_name: str
) -> dict[str, Any]:
    evidence = action_evidence(outcome)
    artifact_path = evidence.get("artifact_path")
    tenant_id = evidence.get("tenant_id")
    integrity = evidence.get("integrity")
    action_id = evidence.get("action_id")
    for record in records:
        if event_kind(record) != "ActionExecuted":
            continue
        payload = event_payload(record)
        candidate = payload.get("action", {})
        output = payload.get("outcome", {}) if isinstance(payload.get("outcome"), dict) else {}
        trace_path = output.get("artifact_path") or candidate.get("params", {}).get("publish_ref")
        if candidate.get("name") != action_name:
            continue
        if artifact_path and trace_path != artifact_path:
            continue
        if tenant_id and output.get("tenant_id") != tenant_id:
            continue
        if integrity and output.get("integrity") != integrity:
            continue
        if not evidence.get("artifact_path") and trace_path:
            evidence["artifact_path"] = trace_path
            artifact_path = trace_path
        if not evidence.get("tenant_id") and isinstance(trace_path, str) and trace_path.startswith("artifact://"):
            evidence["tenant_id"] = trace_path.removeprefix("artifact://").split("/", 1)[0]
            tenant_id = evidence["tenant_id"]
        evidence.update(
            {
                "trace_event_id": trace_id(record),
                "trace_run_id": record.get("run_id"),
                "trace_action_name": candidate.get("name"),
                "trace_artifact_path": trace_path,
                "trace_integrity": output.get("integrity"),
                "trace_tenant_id": output.get("tenant_id"),
            }
        )
        break
    for record in records:
        if event_kind(record) != "OutcomeRecorded":
            continue
        payload = event_payload(record).get("outcome", {})
        candidates = (
            payload.get("actions")
            if isinstance(payload.get("actions"), list)
            else [payload.get("action_outcome")]
        )
        for candidate in candidates:
            if not isinstance(candidate, dict) or candidate.get("action_id") != action_id:
                continue
            output = candidate.get("output") if isinstance(candidate.get("output"), dict) else {}
            candidate_path = output.get("artifact_path") or output.get("publish_ref")
            if artifact_path and candidate_path != artifact_path:
                continue
            if integrity and output.get("integrity") != integrity:
                continue
            evidence.update(
                {
                    "outcome_trace_event_id": trace_id(record),
                    "outcome_action_id": candidate.get("action_id"),
                    "outcome_artifact_path": candidate_path,
                    "outcome_integrity": output.get("integrity"),
                    "outcome_tenant_id": output.get("tenant_id"),
                }
            )
            return evidence
    return evidence


def exact_profile_summary(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "work_order_id": envelope.get("work_order_id"),
        "tenant_id": envelope.get("tenant_id"),
        "agent_id": envelope.get("agent_id"),
        "run_id": envelope.get("run_id"),
        "allowed_actions": envelope.get("allowed_actions", []),
        "allowed_adapters": envelope.get("allowed_adapters", []),
        "allowed_permissions": envelope.get("allowed_permissions", []),
        "data_refs": envelope.get("data_refs", []),
        "required_capabilities": envelope.get("placement", {}).get(
            "required_capabilities", []
        ),
        "signature_key_id": envelope.get("signature", {}).get("key_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="https://resident-vpc-node:8092")
    parser.add_argument(
        "--resident-auth-dir",
        default=os.environ.get("SPLENDOR_RESIDENT_AUTH_DIR", "/run/splendor-auth"),
    )
    parser.add_argument(
        "--resident-ca-file",
        default=os.environ.get(
            "SPLENDOR_RESIDENT_CA_FILE",
            "/run/splendor-auth/resident-root-ca.pem",
        ),
    )
    args = parser.parse_args()
    if not args.vpc_url.lower().startswith("https://"):
        raise SystemExit("UC-E2E-S7 resident VPC URL must use HTTPS")

    root = Path(args.root)
    auth_dir = Path(args.resident_auth_dir)
    resident_ssl = ssl.create_default_context(cafile=args.resident_ca_file)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S7"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []
    resident_security_events: list[dict[str, Any]] = []
    manager_approval_auth_events: list[dict[str, Any]] = []
    used_resident_credentials: set[str] = set()
    used_manager_approval_credentials: set[str] = set()

    def call(
        operation: str,
        method: str,
        base: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        *,
        manager_approval_call_id: str | None = None,
    ) -> dict[str, Any]:
        context = resident_ssl if base.lower().startswith("https://") else None
        status, data = request_json(method, base, path, body, headers, context)
        api_rows.append(
            {
                "operation_id": operation,
                "method": method,
                "url": base.rstrip("/") + path,
                "status": status,
                "request": body,
                "response": data,
                "transport": "verified_tls" if context is not None else "local_acceptance_http",
                "manager_approval_call_id": manager_approval_call_id,
            }
        )
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    def resident_call(
        operation: str,
        method: str,
        path: str,
        scope: str,
        body: dict[str, Any] | None = None,
        *,
        tenant_id: str = TENANT_A,
        mirror: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        auth = resident_auth(root, auth_dir, [scope], tenant_id=tenant_id)
        credential_id = auth["credential"]["credential_id"]
        if credential_id in used_resident_credentials:
            raise SystemExit("resident caller fixture reused a bearer JTI")
        used_resident_credentials.add(credential_id)
        credential = mirror or auth["credential"]
        secured_body = (
            None
            if body is None
            else {
                **body,
                "credential": credential,
                "audit_attribution": audit(credential),
            }
        )
        resident_security_events.append(
            {
                "operation_id": operation,
                "scope": scope,
                "credential_id": credential_id,
                "mirror_credential_id": credential.get("credential_id"),
                "mirror_matches_verified_projection": mirror is None,
                "intentional_projection_mismatch_negative": mirror is not None,
                "bearer_present": True,
                "tls_verified_with_acceptance_ca": True,
                "mutating": method in {"POST", "PUT", "PATCH", "DELETE"},
                "credential_and_audit_mirrored_in_body": body is not None,
                "raw_bearer_recorded": False,
            }
        )
        return call(
            operation,
            method,
            args.vpc_url,
            path,
            secured_body,
            credential_header(auth, credential),
        )

    def manager_approval_call(
        operation: str,
        path: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        auth = manager_approval_auth(root, auth_dir)
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_manager_approval_credentials:
            raise SystemExit("manager approval caller fixture reused a bearer JTI")
        used_manager_approval_credentials.add(credential_id)
        if (
            credential.get("scopes") != ["approvals_manage"]
            or credential.get("binding") != {"fleet": {"fleet_id": FLEET_ID}}
            or credential.get("audience")
            != {"central_manager": {"manager_id": "central-manager"}}
        ):
            raise SystemExit("manager approval caller fixture returned an invalid projection")
        secured_body = {
            **body,
            "credential": credential,
            "audit_attribution": audit(credential),
        }
        call_id = f"manager-approval-call-{len(manager_approval_auth_events) + 1:04d}"
        result = call(
            operation,
            "POST",
            args.manager_url,
            path,
            secured_body,
            {"authorization": f"Bearer {auth['token']}"},
            manager_approval_call_id=call_id,
        )
        manager_approval_auth_events.append(
            {
                "call_id": call_id,
                "operation_id": operation,
                "method": "POST",
                "scope": "approvals_manage",
                "credential_id": credential_id,
                "fleet_id": credential["binding"]["fleet"]["fleet_id"],
                "target_manager_id": "central-manager",
                "audience_manager_id": credential["audience"]["central_manager"][
                    "manager_id"
                ],
                "header_presence": {"authorization": True},
                "body_mirror_status": "matched",
                "result_status": result["status"],
                "trace_event_ids": [result["body"]["trace_event_id"]]
                if isinstance(result.get("body"), dict)
                and result["body"].get("trace_event_id")
                else [],
                "raw_bearer_recorded": False,
            }
        )
        return result

    def require_status(operation: str, response: dict[str, Any], expected: int = 200) -> None:
        if response["status"] != expected:
            raise SystemExit(
                f"{operation} returned {response['status']}, expected {expected}: "
                + json.dumps(response["body"], sort_keys=True)
            )

    for _ in range(40):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)
    for _ in range(40):
        if resident_call("residentHealth", "GET", "/health", "health_read")["status"] == 200:
            break
        time.sleep(0.25)

    fixtures = {
        "tenants": {
            TENANT_A: {"data_ref": DATA_REF_A, "protected_raw_fixture": RAW_A},
            TENANT_B: {"data_ref": DATA_REF_B, "protected_raw_fixture": RAW_B},
        }
    }
    write_json(artifact_dir / "tenant-data-fixtures.json", fixtures)

    manager = manager_credential()
    canonical_node = node_registration(args.vpc_url)
    canonical_instance = instance_registration()
    register_node = call(
        "registerNode",
        "POST",
        args.manager_url,
        "/fleet/nodes",
        {**sec(manager), "registration": canonical_node},
    )
    register_instance = call(
        "registerInstance",
        "POST",
        args.manager_url,
        "/fleet/instances",
        {**sec(manager), "registration": canonical_instance},
    )
    node_heartbeat = call(
        "heartbeatNode",
        "POST",
        args.manager_url,
        f"/fleet/nodes/{VPC_NODE}/heartbeat",
        {
            **sec(manager),
            "heartbeat": {
                "node_id": VPC_NODE,
                "health": canonical_node["health"],
                "recorded_at": utc(0),
            },
        },
    )
    instance_heartbeat = call(
        "heartbeatInstance",
        "POST",
        args.manager_url,
        f"/fleet/instances/{VPC_INSTANCE}/heartbeat",
        {
            **sec(manager),
            "heartbeat": {
                "node_id": VPC_NODE,
                "instance_id": VPC_INSTANCE,
                "health": canonical_instance["health"],
                "recorded_at": utc(0),
            },
        },
    )
    capabilities = call(
        "advertiseCapabilities",
        "POST",
        args.manager_url,
        f"/fleet/nodes/{VPC_NODE}/capabilities",
        {**sec(manager), "capability_document": canonical_node["capability_document"]},
    )
    for operation, response in [
        ("registerNode", register_node),
        ("registerInstance", register_instance),
        ("heartbeatNode", node_heartbeat),
        ("heartbeatInstance", instance_heartbeat),
        ("advertiseCapabilities", capabilities),
    ]:
        require_status(operation, response)

    unsigned_profiles = {
        "specialist_data": exact_work_order(
            WORK_ORDER_SPEC_DATA,
            SPEC,
            SPEC_RUN,
            "data.read_fixture",
            "fixture-data-store",
            "data.read_fixture",
            [DATA_REF_A],
            required_capability="sql.read_fixture",
        ),
        "internal_artifact": exact_work_order(
            WORK_ORDER_INTERNAL,
            ORCH,
            ORCH_RUN,
            "artifact.create_internal",
            "artifact-store",
            "artifact.create_internal",
            [INTERNAL_ARTIFACT],
        ),
        "publish": exact_work_order(
            WORK_ORDER_PUBLISH,
            ORCH,
            PUBLISH_RUN,
            "artifact.publish_external",
            "artifact-store",
            "artifact.publish_external",
            [PUBLISHED_ARTIFACT],
        ),
        "request_message": exact_work_order(
            WORK_ORDER_REQUEST_MESSAGE,
            ORCH,
            ORCH_RUN,
            "message.remote.proposal",
            "remote-message",
            f"message.remote.proposal:{SPEC}",
            [DATA_REF_A],
        ),
        "response_message": exact_work_order(
            WORK_ORDER_RESPONSE_MESSAGE,
            SPEC,
            SPEC_RUN,
            "message.remote.proposal",
            "remote-message",
            f"message.remote.proposal:{ORCH}",
            [DATA_REF_A],
        ),
    }
    envelopes = {
        name: sign_work_order(root, artifact_dir, commands, auth_dir, payload)
        for name, payload in unsigned_profiles.items()
    }
    submissions: dict[str, dict[str, Any]] = {}
    placements: dict[str, dict[str, Any]] = {}
    for name, envelope in envelopes.items():
        submissions[name] = call(
            "submitWorkOrder",
            "POST",
            args.manager_url,
            "/work-orders",
            {
                **sec(manager),
                "work_order": envelope,
                "expected_audience": "central-manager",
                "approval_policies": [approval_policy(envelope["expires_at"])] if name == "publish" else [],
            },
        )
        placements[name] = call(
            "evaluatePlacement",
            "POST",
            args.manager_url,
            "/fleet/placement/evaluate",
            {
                **sec(manager),
                "work_order_id": envelope["work_order_id"],
                "request": {
                    "target": "customer_vpc",
                    "required_capabilities": envelope["placement"][
                        "required_capabilities"
                    ],
                    "data_locality": "vpc",
                    "dedicated_instance": False,
                    "required_runtime_version": None,
                    "max_runtime_ms": 30000,
                    "execution_mode": "live",
                },
            },
        )
        require_status(f"submitWorkOrder:{name}", submissions[name])
        require_status(f"evaluatePlacement:{name}", placements[name])

    dispatch_data = call(
        "dispatchWorkOrder",
        "POST",
        args.manager_url,
        f"/work-orders/{WORK_ORDER_SPEC_DATA}/dispatch",
        {**sec(manager), "target_node_id": VPC_NODE},
    )
    require_status("dispatchWorkOrder:specialist_data", dispatch_data)

    internal_create = resident_call(
        "createRun",
        "POST",
        "/runs",
        "runs_create",
        internal_create_payload(envelopes["internal_artifact"]),
    )
    require_status("createRun:internal_artifact", internal_create)
    internal_start = resident_call(
        "startRun",
        "POST",
        f"/runs/{ORCH_RUN}/start",
        "runs_start",
        {
            "work_order": None,
            "reason": "uc_e2e_s7_internal_artifact_state_commit",
            "approval_evidence": None,
        },
    )
    require_status("startRun:internal_artifact", internal_start)

    causal_anchor = dispatch_data["body"].get("trace_event_id")
    task_request = {
        "message": {
            "message_id": TASK_REQUEST_ID,
            "source_agent_id": ORCH,
            "target_agent_id": SPEC,
            "run_id": ORCH_RUN,
            "schema": "splendor.message.task_request.v2",
            "payload": {
                "parent_run_id": ORCH_RUN,
                "child_run_id": SPEC_RUN,
                "target_agent_id": SPEC,
                "objective": "analyze the separately authorized tenant A board pack",
                "delegated_authority": {
                    "allowed_actions": [],
                    "allowed_adapters": [],
                    "allowed_permissions": [],
                },
                "capability_grant_id": CAPABILITY_GRANT_ID,
                "data_refs": [DATA_REF_A],
            },
            "causal_parent": causal_anchor,
            "requires_response": True,
            "created_at": utc(0),
        },
        "schema_version": "v2",
        "delivery_status": "pending",
        "trace_links": {},
    }
    sent = call(
        "sendMessage",
        "POST",
        args.manager_url,
        "/messages",
        {
            **sec(manager),
            "work_order_id": WORK_ORDER_REQUEST_MESSAGE,
            "message_envelope": task_request,
            "source_instance_id": VPC_INSTANCE,
            "target_instance_id": VPC_INSTANCE,
            "idempotency_key": "s7-task-request-exact",
            "simulate_failure": None,
        },
    )
    received = call(
        "getMessage",
        "POST",
        args.manager_url,
        f"/messages/{TASK_REQUEST_ID}/read",
        message_scope(manager, ORCH_RUN, SPEC),
    )
    task_response = {
        "message": {
            "message_id": TASK_RESPONSE_ID,
            "source_agent_id": SPEC,
            "target_agent_id": ORCH,
            "run_id": ORCH_RUN,
            "schema": "splendor.message.task_response.v1",
            "payload": {
                "parent_run_id": ORCH_RUN,
                "child_run_id": SPEC_RUN,
                "status": "completed",
                "output": {
                    "analysis_ref": "analysis:s7:tenant-a",
                    "data_refs": [DATA_REF_A],
                    "summary": "tenant A scoped margin and revenue trend summary",
                    "raw_payload_included": False,
                },
                "failure": None,
            },
            "causal_parent": sent["body"].get("trace_event_id") or causal_anchor,
            "requires_response": False,
            "created_at": utc(0),
        },
        "schema_version": "v1",
        "delivery_status": "pending",
        "trace_links": {},
    }
    response_sent = call(
        "sendMessage",
        "POST",
        args.manager_url,
        "/messages",
        {
            **sec(manager),
            "work_order_id": WORK_ORDER_RESPONSE_MESSAGE,
            "message_envelope": task_response,
            "source_instance_id": VPC_INSTANCE,
            "target_instance_id": VPC_INSTANCE,
            "idempotency_key": "s7-task-response-exact",
            "simulate_failure": None,
        },
    )
    response_received = call(
        "getMessage",
        "POST",
        args.manager_url,
        f"/messages/{TASK_RESPONSE_ID}/read",
        message_scope(manager, ORCH_RUN, ORCH),
    )

    smuggle_message = json.loads(json.dumps(task_request))
    smuggle_message["message"]["message_id"] = SMUGGLE_MESSAGE_ID
    smuggle_message["message"]["payload"]["data_refs"] = [DATA_REF_A, DATA_REF_B]
    smuggle_message["message"]["payload"]["delegated_authority"] = {
        "allowed_actions": ["artifact.publish_external"],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": ["artifact.publish_external"],
    }
    smuggle = call(
        "sendMessage",
        "POST",
        args.manager_url,
        "/messages",
        {
            **sec(manager),
            "work_order_id": WORK_ORDER_REQUEST_MESSAGE,
            "message_envelope": smuggle_message,
            "source_instance_id": VPC_INSTANCE,
            "target_instance_id": VPC_INSTANCE,
            "idempotency_key": "s7-smuggle-exact",
            "simulate_failure": None,
        },
    )

    action_causal_trace_id = (
        response_sent["body"].get("trace_event_id")
        or sent["body"].get("trace_event_id")
        or causal_anchor
    )
    allowed_data_read = resident_call(
        "submitAction",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": SPEC_RUN,
            "tenant_id": TENANT_A,
            "agent_id": SPEC,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "data.read_fixture", "data.read_fixture", data_ref=DATA_REF_A
            ),
            "adapter": "fixture-data-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
    )
    inspect_data_before_denials = resident_call(
        "inspectRunBeforeDeniedActions",
        "GET",
        f"/runs/{SPEC_RUN}",
        "runs_read",
    )
    tenant_b_denial = resident_call(
        "submitAction",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": SPEC_RUN,
            "tenant_id": TENANT_A,
            "agent_id": SPEC,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "data.read_fixture", "data.read_fixture", data_ref=DATA_REF_B
            ),
            "adapter": "fixture-data-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
    )
    manager_permission_denial = resident_call(
        "submitActionManagerCredential",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": SPEC_RUN,
            "tenant_id": TENANT_A,
            "agent_id": SPEC,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "data.read_fixture", "data.read_fixture", data_ref=DATA_REF_A
            ),
            "adapter": "fixture-data-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
        mirror=manager,
    )
    specialist_publish_denial = resident_call(
        "submitAction",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": SPEC_RUN,
            "tenant_id": TENANT_A,
            "agent_id": SPEC,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "artifact.publish_external",
                "artifact.publish_external",
                publish_ref=INTERNAL_ARTIFACT,
            ),
            "adapter": "artifact-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
    )
    inspect_data_after_denials = resident_call(
        "inspectRunAfterDeniedActions",
        "GET",
        f"/runs/{SPEC_RUN}",
        "runs_read",
    )

    internal_artifact = resident_call(
        "submitAction",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": ORCH_RUN,
            "tenant_id": TENANT_A,
            "agent_id": ORCH,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "artifact.create_internal",
                "artifact.create_internal",
                artifact_path=INTERNAL_ARTIFACT,
            ),
            "adapter": "artifact-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
    )
    inspect_artifact_before_collision = resident_call(
        "inspectOrchestratorRunBeforeCollision",
        "GET",
        f"/runs/{ORCH_RUN}",
        "runs_read",
    )
    collision = resident_call(
        "submitAction",
        "POST",
        "/actions",
        "actions_submit",
        {
            "run_id": ORCH_RUN,
            "tenant_id": TENANT_A,
            "agent_id": ORCH,
            "causal_trace_id": action_causal_trace_id,
            "action": action(
                "artifact.create_internal",
                "artifact.create_internal",
                artifact_path=f"artifact://{TENANT_B}/board/report.md",
            ),
            "adapter": "artifact-store",
            "quota_usage": quota(),
            "satisfied_preconditions": [],
        },
    )
    inspect_artifact_after_collision = resident_call(
        "inspectOrchestratorRunAfterCollision",
        "GET",
        f"/runs/{ORCH_RUN}",
        "runs_read",
    )

    missing_redaction = resident_call(
        "exportTracesMissingRedaction",
        "POST",
        f"/runs/{SPEC_RUN}/traces/export",
        "traces_read",
        {"redaction_policy": None, "start": None, "end": None},
    )

    publish_payload = publish_create_payload(envelopes["publish"])
    admitted_publish_action = publish_payload["policy_actions"][0]
    dispatch_publish = call(
        "dispatchWorkOrder",
        "POST",
        args.manager_url,
        f"/work-orders/{WORK_ORDER_PUBLISH}/dispatch",
        {**sec(manager), "target_node_id": VPC_NODE},
    )
    require_status("dispatchWorkOrder:publish", dispatch_publish)
    publish_create = {
        "status": dispatch_publish["body"].get("create_run_status"),
        "body": json.loads(dispatch_publish["body"].get("create_run_body") or "{}"),
    }
    publish_start = {
        "status": dispatch_publish["body"].get("start_run_status"),
        "body": json.loads(dispatch_publish["body"].get("start_run_body") or "{}"),
    }
    if publish_create["status"] not in {200, 201} or publish_start["status"] != 200:
        raise SystemExit("manager dispatch did not create and start the publish run")
    publish_without_approval_response = resident_call(
        "submitUnapprovedPublish",
        "POST",
        "/actions",
        "actions_submit",
        {
            "action_id": admitted_publish_action["action_id"],
            "run_id": PUBLISH_RUN,
            "tenant_id": TENANT_A,
            "agent_id": ORCH,
            "causal_trace_id": dispatch_publish["body"].get("trace_event_id"),
            "action": admitted_publish_action["action"],
            "adapter": admitted_publish_action["adapter"],
            "quota_usage": admitted_publish_action["quota_usage"],
            "satisfied_preconditions": admitted_publish_action["satisfied_preconditions"],
            "requested_at": utc(0),
        },
    )
    require_status("submitUnapprovedPublish", publish_without_approval_response)
    publish_no_approval = publish_without_approval_response["body"]
    approval_context = extract_approval_context(publish_no_approval)
    publish_waiting = resident_call(
        "inspectPublishWaitingForApproval",
        "GET",
        f"/runs/{PUBLISH_RUN}",
        "runs_read",
    )
    publish_state_before_approval = resident_call(
        "getPublishStateHeadBeforeApproval",
        "GET",
        f"/runs/{PUBLISH_RUN}/state-head",
        "state_read",
    )
    if (
        admitted_publish_action["action_id"] != approval_context["action_id"]
        or admitted_publish_action["action"]["name"]
        != approval_context["action_name"]
        or admitted_publish_action["adapter"] != approval_context["adapter"]
    ):
        raise SystemExit("daemon approval challenge did not match admitted publish action")
    manager_request = approval_request_payload(
        approval_context,
        "S7 scoped approval for external publication",
    )
    approval_request = manager_approval_call(
        "requestApproval",
        "/approvals",
        manager_request,
    )
    require_status("requestApproval", approval_request)
    approval_grant = manager_approval_call(
        "grantApproval",
        f"/approvals/{approval_context['approval_id']}/grant",
        {"reason": "approved_for_s7_publication"},
    )
    require_status("grantApproval", approval_grant)
    authority_receipt = approval_grant["body"].get("authority_obligation_receipt")
    if not isinstance(authority_receipt, dict):
        raise SystemExit("manager grant did not issue a trusted approval obligation receipt")
    if (
        authority_receipt.get("approval_trace_event_id")
        != approval_grant["body"].get("trace_event_id")
        or not authority_receipt.get("issuer")
    ):
        raise SystemExit("manager approval receipt was not trace-linked to its issuance")
    approved_action_request = {
        "action_id": admitted_publish_action["action_id"],
        "run_id": PUBLISH_RUN,
        "tenant_id": TENANT_A,
        "agent_id": ORCH,
        "causal_trace_id": approval_grant["body"].get("trace_event_id"),
        "action": admitted_publish_action["action"],
        "adapter": admitted_publish_action["adapter"],
        "quota_usage": admitted_publish_action["quota_usage"],
        "satisfied_preconditions": admitted_publish_action[
            "satisfied_preconditions"
        ],
        "requested_at": approval_context["requested_at"],
        "authority_obligation_receipts": [authority_receipt],
    }
    approved_publish_response = resident_call(
        "submitApprovedExactAction",
        "POST",
        "/actions",
        "actions_submit",
        approved_action_request,
    )
    require_status("submitApprovedExactAction", approved_publish_response)
    approved_publish = approved_publish_response["body"]
    publish_after_approval = resident_call(
        "inspectPublishAfterExactAction",
        "GET",
        f"/runs/{PUBLISH_RUN}",
        "runs_read",
    )
    publish_state_after_approval = resident_call(
        "getPublishStateHeadAfterApproval",
        "GET",
        f"/runs/{PUBLISH_RUN}/state-head",
        "state_read",
    )

    traces_before_replay: dict[str, dict[str, Any]] = {}
    for label, run_id in [
        ("orchestrator", ORCH_RUN),
        ("specialist", SPEC_RUN),
        ("publish", PUBLISH_RUN),
    ]:
        traces_before_replay[label] = resident_call(
            "exportTraces",
            "POST",
            f"/runs/{run_id}/traces/export",
            "traces_read",
            {
                "redaction_policy": "uc-e2e-s7-redacted",
                "start": None,
                "end": None,
            },
        )
    records_before_replay = [
        record
        for response in traces_before_replay.values()
        for record in response["body"].get("records", [])
    ]
    action_counts_before_replay = action_execution_counts(records_before_replay)

    inspect_before_replay: dict[str, dict[str, Any]] = {}
    replay_responses: dict[str, dict[str, Any]] = {}
    inspect_after_replay: dict[str, dict[str, Any]] = {}
    for label, run_id in [
        ("orchestrator", ORCH_RUN),
        ("specialist", SPEC_RUN),
        ("publish", PUBLISH_RUN),
    ]:
        inspect_before_replay[label] = resident_call(
            "inspectRunBeforeReplay", "GET", f"/runs/{run_id}", "runs_read"
        )
        replay_responses[label] = resident_call(
            "replayRun",
            "POST",
            f"/runs/{run_id}/replay",
            "replay_create",
            {"mode": "inspect_only", "side_effects_allowed": False},
        )
        inspect_after_replay[label] = resident_call(
            "inspectRunAfterReplay", "GET", f"/runs/{run_id}", "runs_read"
        )
    cross_tenant_replay = resident_call(
        "crossTenantReplay",
        "POST",
        f"/runs/{SPEC_RUN}/replay",
        "replay_create",
        {"mode": "inspect_only", "side_effects_allowed": False},
        tenant_id=TENANT_B,
    )

    traces_after_replay: dict[str, dict[str, Any]] = {}
    for label, run_id in [
        ("orchestrator", ORCH_RUN),
        ("specialist", SPEC_RUN),
        ("publish", PUBLISH_RUN),
    ]:
        traces_after_replay[label] = resident_call(
            "exportTracesAfterReplay",
            "POST",
            f"/runs/{run_id}/traces/export",
            "traces_read",
            {
                "redaction_policy": "uc-e2e-s7-redacted",
                "start": None,
                "end": None,
            },
        )
    records = [
        record
        for response in traces_after_replay.values()
        for record in response["body"].get("records", [])
    ]
    action_counts_after_replay = action_execution_counts(records)
    trace_text = json.dumps(records, sort_keys=True)
    replay_text = json.dumps(
        {label: response["body"] for label, response in replay_responses.items()},
        sort_keys=True,
    )
    manager_audit = call(
        "managerAudit", "POST", args.manager_url, "/fleet/audit/read", sec(manager)
    )
    manager_body = manager_audit["body"]
    manager_events = (
        manager_body if isinstance(manager_body, list) else manager_body.get("events", [])
    )

    state_heads = {
        label: resident_call(
            "getStateHead", "GET", f"/runs/{run_id}/state-head", "state_read"
        )["body"]
        for label, run_id in [
            ("orchestrator", ORCH_RUN),
            ("specialist", SPEC_RUN),
            ("publish", PUBLISH_RUN),
        ]
    }
    event_ids = build_event_ids(
        records,
        manager_events,
        trace_export_id=traces_after_replay["specialist"]["body"].get(
            "integrity_hash", ""
        ),
        replay_id=",".join(
            response["body"].get("replay_id", "")
            for response in replay_responses.values()
        ),
    )

    adapter_before_denials = {
        "specialist": inspect_data_before_denials["body"].get("adapter_executions"),
        "orchestrator": inspect_artifact_before_collision["body"].get(
            "adapter_executions"
        ),
    }
    adapter_after_denials = {
        "specialist": inspect_data_after_denials["body"].get("adapter_executions"),
        "orchestrator": inspect_artifact_after_collision["body"].get(
            "adapter_executions"
        ),
    }
    adapter_before_replay = {
        label: response["body"].get("adapter_executions")
        for label, response in inspect_before_replay.items()
    }
    adapter_after_replay = {
        label: response["body"].get("adapter_executions")
        for label, response in inspect_after_replay.items()
    }

    negatives = [
        {
            "case": "specialist_tenant_b_data_ref_denied_before_adapter",
            "passed": tenant_b_denial["body"].get("status") == "Denied"
            and "data_scope_denied"
            in tenant_b_denial["body"].get("verification", {}).get("reasons", []),
            "status": tenant_b_denial["body"].get("status"),
            "reason_codes": tenant_b_denial["body"].get("verification", {}).get(
                "reasons", []
            ),
        },
        {
            "case": "manager_credential_as_action_permission_denied",
            "passed": manager_permission_denial["status"] == 403,
            "status": manager_permission_denial["status"],
            "code": manager_permission_denial["body"].get("code"),
        },
        {
            "case": "specialist_external_publish_denied_by_narrow_work_order",
            "passed": specialist_publish_denial["body"].get("status") == "Denied"
            and "trusted_action_profile_missing"
            in specialist_publish_denial["body"]
            .get("verification", {})
            .get("reasons", []),
            "status": specialist_publish_denial["body"].get("status"),
            "reason_codes": specialist_publish_denial["body"]
            .get("verification", {})
            .get("reasons", []),
        },
        {
            "case": "message_payload_data_ref_permission_smuggling_denied",
            "passed": smuggle["status"] == 403
            and smuggle["body"].get("code") == "message_payload_scope_smuggling",
            "status": smuggle["status"],
            "code": smuggle["body"].get("code"),
        },
        {
            "case": "trace_export_without_redaction_policy_rejected",
            "passed": missing_redaction["status"] == 403
            and missing_redaction["body"].get("code")
            == "missing_trace_redaction_policy",
            "status": missing_redaction["status"],
            "code": missing_redaction["body"].get("code"),
        },
        {
            "case": "external_artifact_publish_without_approval_pauses",
            "passed": publish_no_approval.get("status") == "NeedsApproval",
            "status": publish_no_approval.get("status"),
        },
        {
            "case": "cross_tenant_replay_cannot_reveal_raw_payloads",
            "passed": cross_tenant_replay["status"] == 403
            and RAW_A not in replay_text
            and RAW_B not in replay_text,
            "status": cross_tenant_replay["status"],
        },
        {
            "case": "artifact_path_collision_across_tenants_rejected",
            "passed": collision["body"].get("status") == "Denied"
            and "artifact_path_tenant_mismatch"
            in collision["body"].get("verification", {}).get("reasons", []),
            "status": collision["body"].get("status"),
            "reason_codes": collision["body"].get("verification", {}).get(
                "reasons", []
            ),
        },
        {
            "case": "denied_data_and_artifact_actions_did_not_reach_adapter",
            "passed": adapter_before_denials == adapter_after_denials,
            "adapter_executions_before": adapter_before_denials,
            "adapter_executions_after": adapter_after_denials,
        },
        {
            "case": "replay_did_not_reread_republish_or_rewrite_artifacts",
            "passed": adapter_before_replay == adapter_after_replay
            and action_counts_before_replay == action_counts_after_replay,
            "adapter_executions_before_replay": adapter_before_replay,
            "adapter_executions_after_replay": adapter_after_replay,
            "action_execution_counts_before_replay": action_counts_before_replay,
            "action_execution_counts_after_replay": action_counts_after_replay,
            "published_artifact_path": PUBLISHED_ARTIFACT,
        },
    ]

    internal_artifact_evidence = resolve_action_trace_evidence(
        records, internal_artifact["body"], "artifact.create_internal"
    )
    approved_publish_evidence = resolve_action_trace_evidence(
        records, approved_publish, "artifact.publish_external"
    )
    profile_summaries = {
        name: exact_profile_summary(envelope) for name, envelope in envelopes.items()
    }
    exact_profiles = all(
        len(summary["allowed_actions"]) == 1
        and len(summary["allowed_adapters"]) == 1
        and len(summary["allowed_permissions"]) == 1
        and summary["signature_key_id"] == VPC_WORK_ORDER_KEY_ID
        for summary in profile_summaries.values()
    )
    credential_ids = [event["credential_id"] for event in resident_security_events]
    resident_security_passed = (
        all(
            event["bearer_present"]
            and event["tls_verified_with_acceptance_ca"]
            and not event["raw_bearer_recorded"]
            and (
                not event["mutating"]
                or event["credential_and_audit_mirrored_in_body"]
            )
            for event in resident_security_events
        )
        and len(credential_ids) == len(set(credential_ids))
        and sum(
            1
            for event in resident_security_events
            if event["intentional_projection_mismatch_negative"]
        )
        == 1
    )
    manager_approval_credential_ids = [
        event.get("credential_id") for event in manager_approval_auth_events
    ]
    manager_approval_auth_valid = (
        len(manager_approval_auth_events) == 2
        and {event.get("operation_id") for event in manager_approval_auth_events}
        == {"requestApproval", "grantApproval"}
        and len(manager_approval_credential_ids)
        == len(set(manager_approval_credential_ids))
        and all(
            event.get("scope") == "approvals_manage"
            and event.get("fleet_id") == FLEET_ID
            and event.get("target_manager_id") == "central-manager"
            and event.get("audience_manager_id") == "central-manager"
            and event.get("header_presence", {}).get("authorization") is True
            and event.get("body_mirror_status") == "matched"
            and event.get("result_status") == 200
            and event.get("trace_event_ids")
            and event.get("raw_bearer_recorded") is False
            for event in manager_approval_auth_events
        )
    )
    manager_approval_auth_report = {
        "schema_version": "splendor.uc_e2e_s7.manager_approval_auth.v1",
        "status": "passed" if manager_approval_auth_valid else "failed",
        "mode": "local_acceptance",
        "events": manager_approval_auth_events,
        "fresh_mutating_credential_ids": len(manager_approval_credential_ids)
        == len(set(manager_approval_credential_ids)),
        "exact_scope": "approvals_manage",
        "fleet_id": FLEET_ID,
        "manager_id": "central-manager",
        "raw_bearers_recorded": False,
        "production_manager_auth_claimed": False,
        "other_manager_endpoints_authenticated_by_this_profile": False,
    }
    receipt_matches_challenge = (
        authority_receipt.get("approval_id") == approval_context["approval_id"]
        and authority_receipt.get("audience")
        == approval_context["receipt_audience"]
        and authority_receipt.get("subject") == approval_context["subject"]
        and authority_receipt.get("authority_decision_id")
        == approval_context["authority_decision_id"]
        and authority_receipt.get("obligation_id")
        == approval_context["obligation_id"]
        and authority_receipt.get("canonical_request_digest")
        == approval_context["canonical_request_digest"]
        and authority_receipt.get("approval_trace_event_id")
        == approval_grant["body"].get("trace_event_id")
        and authority_receipt.get("evidence_ref")
        == f"approval-trace:{approval_grant['body'].get('trace_event_id')}"
    )
    publish_execution_records = [
        record
        for record in records
        if record.get("run_id") == PUBLISH_RUN
        and event_kind(record) == "ActionExecuted"
        and event_payload(record).get("action", {}).get("name")
        == "artifact.publish_external"
    ]
    publish_state_unchanged = all(
        publish_state_before_approval["body"].get(key)
        == publish_state_after_approval["body"].get(key)
        for key in ["state_node_id", "data_hash"]
    )
    approved_action_exact = (
        approved_action_request["action_id"] == approval_context["action_id"]
        and approved_action_request["action"] == admitted_publish_action["action"]
        and approved_action_request["action"]["name"]
        == approval_context["action_name"]
        and approved_action_request["adapter"] == approval_context["adapter"]
        and approved_action_request["requested_at"]
        == approval_context["requested_at"]
        and approved_action_request["quota_usage"]
        == admitted_publish_action["quota_usage"]
        and approved_action_request["satisfied_preconditions"]
        == admitted_publish_action["satisfied_preconditions"]
        and approved_action_request["authority_obligation_receipts"]
        == [authority_receipt]
        and "approval_evidence" not in approved_action_request
    )
    positives = {
        "tenant_fixtures_separate": DATA_REF_A != DATA_REF_B and RAW_A != RAW_B,
        "canonical_vpc_registration_reused": all(
            response["status"] == 200
            for response in [
                register_node,
                register_instance,
                node_heartbeat,
                instance_heartbeat,
                capabilities,
            ]
        ),
        "resident_tls_bearer_and_fresh_jti_verified": resident_security_passed,
        "per_instance_work_orders_use_exact_profiles": exact_profiles,
        "specialist_work_order_narrow": profile_summaries["specialist_data"][
            "allowed_actions"
        ]
        == ["data.read_fixture"],
        "work_orders_accepted": len(
            [
                event
                for event in manager_events
                if event.get("event_type") == "work_order.accepted"
            ]
        )
        >= len(envelopes),
        "vpc_dispatch_used_for_specialist_data": dispatch_data["body"].get(
            "create_run_status"
        )
        in {200, 201}
        and dispatch_data["body"].get("start_run_status") == 200,
        "internal_artifact_exact_run_created_directly": internal_create["status"]
        == 200
        and internal_start["status"] == 200,
        "typed_messages_delivered": bool(
            sent["body"].get("delivery_status") == "delivered"
            and received["body"].get("receive_side_validated") is True
            and received["body"].get("read_trace_event_id")
            and response_sent["body"].get("delivery_status") == "delivered"
            and response_received["body"].get("receive_side_validated") is True
            and response_received["body"].get("read_trace_event_id")
        ),
        "response_work_order_bound_to_child_run": envelopes["response_message"].get(
            "run_id"
        )
        == task_response["message"]["payload"]["child_run_id"]
        and task_response["message"]["run_id"]
        == task_response["message"]["payload"]["parent_run_id"],
        "allowed_specialist_data_read_executed": allowed_data_read["body"].get(
            "status"
        )
        == "Executed",
        "internal_artifact_recorded": internal_artifact["body"].get("status")
        == "Executed"
        and internal_artifact_evidence.get("artifact_path") == INTERNAL_ARTIFACT
        and internal_artifact_evidence.get("integrity")
        and internal_artifact_evidence.get("trace_event_id")
        in event_ids.get("artifact.created", []),
        "approved_publish_executed": approved_publish.get("status") == "Executed"
        and approved_publish_evidence.get("integrity")
        and approved_publish_evidence.get("trace_event_id")
        in event_ids.get("artifact.publish.executed", []),
        "approval_action_trace_matched": approval_context.get("action_id")
        == PUBLISH_ACTION_ID
        == approved_publish.get("action_id"),
        "manager_approval_calls_authenticated_once": manager_approval_auth_valid,
        "full_exact_challenge_recorded_by_manager": manager_request.get("challenge")
        == approval_context
        and approval_request["body"].get("challenge") == approval_context,
        "manager_receipt_trace_linked_to_exact_challenge": receipt_matches_challenge,
        "publish_waited_without_execution": publish_waiting["body"].get("status")
        == "waiting_for_approval"
        and publish_waiting["body"].get("adapter_executions") == 0,
        "approved_pending_action_retried_exactly": approved_action_exact,
        "approved_publish_returned_running_after_one_execution": publish_after_approval[
            "body"
        ].get("status")
        == "running"
        and publish_after_approval["body"].get("adapter_executions") == 1
        and len(publish_execution_records) == 1,
        "approved_publish_did_not_tick_or_advance_state": publish_waiting["body"].get(
            "ticks"
        )
        == publish_after_approval["body"].get("ticks")
        and publish_state_unchanged,
        "approved_publish_emitted_run_resumed": bool(event_ids.get("run.resumed")),
        "trace_redacted": RAW_A not in trace_text and RAW_B not in trace_text,
        "replay_inspect_only": all(
            response["body"].get("mode") == "inspect_only"
            for response in replay_responses.values()
        ),
    }
    failures = [key for key, passed in positives.items() if not passed]
    failures.extend(
        f"negative_failed:{item['case']}"
        for item in negatives
        if item.get("passed") is not True
    )
    required_events = {
        "work_order.accepted",
        "data_scope.verified",
        "data_scope.denied",
        "message.sent",
        "message.received",
        "message.denied",
        "artifact.created",
        "artifact.publish.needs_approval",
        "artifact.publish.executed",
        "artifact.publish.denied",
        "run.resumed",
        "trace.exported.redacted",
        "state.committed",
        "replay.explained",
    }
    failures.extend(
        f"missing_event:{event}"
        for event in sorted(required_events)
        if not event_ids.get(event)
    )

    replay_suppression = {
        "required": True,
        "evidence_present": True,
        "side_effects_allowed_default": False,
        "external_publish_replayed": False,
        "internal_artifact_rewritten": False,
        "adapter_executions_before_replay": adapter_before_replay,
        "adapter_executions_after_replay": adapter_after_replay,
        "action_execution_counts_before_replay": action_counts_before_replay,
        "action_execution_counts_after_replay": action_counts_after_replay,
        "orchestrator_replay_id": replay_responses["orchestrator"]["body"].get(
            "replay_id"
        ),
        "specialist_replay_id": replay_responses["specialist"]["body"].get(
            "replay_id"
        ),
        "publish_replay_id": replay_responses["publish"]["body"].get("replay_id"),
        "approved_publish_artifact_path": approved_publish_evidence.get(
            "artifact_path"
        ),
        "approved_publish_trace_event_id": approved_publish_evidence.get(
            "trace_event_id"
        ),
        "internal_artifact_trace_event_id": internal_artifact_evidence.get(
            "trace_event_id"
        ),
    }
    resident_security_report = {
        "status": "passed" if resident_security_passed else "failed",
        "resident_url": args.vpc_url,
        "transport": "verified_tls",
        "ca_validation": "ssl.create_default_context",
        "credential_count": len(credential_ids),
        "unique_credential_count": len(set(credential_ids)),
        "fresh_jti_per_request": len(credential_ids) == len(set(credential_ids)),
        "raw_bearer_recorded": False,
        "events": resident_security_events,
    }
    scenario = {
        "id": "UC-E2E-S7",
        "status": "passed" if not failures else "failed",
        "fr_coverage": ["UC-E2E-S7", "FR-0.1-05", "FR-0.1-08"],
        "components": [
            "central-manager",
            "resident-vpc-node",
            "work-order",
            "placement",
            "message-routing",
            "data-scope-verifier",
            "artifact-adapter",
            "approval",
            "trace-redaction",
            "replay/audit",
        ],
        "positive_evidence": [key for key, passed in positives.items() if passed],
        "positive_checks": positives,
        "negative_evidence": [
            item["case"] for item in negatives if item.get("passed") is True
        ],
        "replay_evidence": [
            "public replay APIs returned inspect_only explanations for all three exact-authority resident runs; raw protected fixture strings were absent; cross-tenant replay was rejected; adapter and trace-derived action execution counts were unchanged"
        ],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": replay_suppression,
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": [
            "verified_vpc_tls_and_fresh_bearer_used",
            "public_manager_and_resident_http_used",
            "gateway_data_scope_verifier_before_adapter",
            "shared_specialist_exact_data_work_order_only",
            "manager_credential_not_action_authority",
            "manager_approval_bearers_are_fresh_and_one_use",
            "raw_approval_evidence_not_action_authority",
            "approved_action_retried_without_tick_or_state_advance",
            "trace_redaction_required",
            "replay_no_artifact_publish",
        ],
        "run_ids": [ORCH_RUN, SPEC_RUN, PUBLISH_RUN],
        "trace_event_ids": sorted(
            {trace for ids in event_ids.values() for trace in ids if trace}
        ),
        "state_node_ids": [
            state.get("state_node_id", "") for state in state_heads.values()
        ],
        "state_hashes": [state.get("data_hash", "") for state in state_heads.values()],
        "message_ids": [TASK_REQUEST_ID, TASK_RESPONSE_ID, SMUGGLE_MESSAGE_ID],
        "work_order_ids": [
            WORK_ORDER_SPEC_DATA,
            WORK_ORDER_INTERNAL,
            WORK_ORDER_PUBLISH,
            WORK_ORDER_REQUEST_MESSAGE,
            WORK_ORDER_RESPONSE_MESSAGE,
        ],
        "approval_ids": [approval_context.get("approval_id", "")],
        "node_ids": [VPC_NODE],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "negative_cases": negatives,
        "scenario_failures": failures,
        "resident_security": resident_security_report,
        "manager_approval_auth": manager_approval_auth_report,
        "artifact_paths": [],
    }
    artifacts: dict[str, object] = {
        "scenario-report.json": scenario,
        "tenant-data-fixtures.json": fixtures,
        "work-order-validation.json": {
            "orchestrator": envelopes["internal_artifact"],
            "specialist": envelopes["specialist_data"],
            **envelopes,
            "exact_profiles": profile_summaries,
            "submissions": submissions,
            "placements": placements,
        },
        "message-flow.json": {
            "request": sent["body"],
            "request_read": received["body"],
            "response": response_sent["body"],
            "response_read": response_received["body"],
            "smuggling_denial": smuggle,
            "authority_binding": {
                "parent_run_id": ORCH_RUN,
                "child_run_id": SPEC_RUN,
                "request_work_order_id": WORK_ORDER_REQUEST_MESSAGE,
                "response_work_order_id": WORK_ORDER_RESPONSE_MESSAGE,
                "response_work_order_run_id": SPEC_RUN,
                "message_run_id": ORCH_RUN,
                "message_payload_is_authority": False,
            },
        },
        "artifact-report.json": {
            "internal_artifact": internal_artifact["body"],
            "internal_artifact_evidence": internal_artifact_evidence,
            "internal_run_create": internal_create["body"],
            "internal_run_start": internal_start["body"],
            "publish_run_create": publish_create["body"],
            "publish_run_start": publish_start["body"],
            "publish_without_approval": publish_no_approval,
            "approval_challenge": approval_context,
            "manager_approval_request_payload": manager_request,
            "manager_approval_request": approval_request["body"],
            "manager_approval_grant": approval_grant["body"],
            "admitted_publish_action": admitted_publish_action,
            "approved_exact_action_request": approved_action_request,
            "approved_exact_action_response": approved_publish_response["body"],
            "approved_publish": approved_publish,
            "approved_publish_evidence": approved_publish_evidence,
            "publish_run_waiting": publish_waiting["body"],
            "publish_run_after_exact_action": publish_after_approval["body"],
            "publish_state_head_before_exact_action": publish_state_before_approval[
                "body"
            ],
            "publish_state_head_after_exact_action": publish_state_after_approval[
                "body"
            ],
            "publish_execution_trace_count": len(publish_execution_records),
            "receipt_matches_challenge": receipt_matches_challenge,
            "state_head_unchanged": publish_state_unchanged,
            "collision": collision["body"],
            "specialist_publish_denial": specialist_publish_denial["body"],
        },
        "data-scope-report.json": {
            "allowed_data_read": allowed_data_read["body"],
            "tenant_b_denial": tenant_b_denial["body"],
            "manager_permission_denial": manager_permission_denial,
            "specialist_publish_denial": specialist_publish_denial["body"],
            "adapter_executions_before": adapter_before_denials,
            "adapter_executions_after": adapter_after_denials,
        },
        # Preserve S8's existing single-state import contract while separately
        # retaining all exact-run heads below.
        "state-export.json": state_heads["specialist"],
        "state-heads.json": state_heads,
        "replay-report.json": {
            **replay_responses["specialist"]["body"],
            "orchestrator_replay": replay_responses["orchestrator"]["body"],
            "publish_replay": replay_responses["publish"]["body"],
            "side_effects_allowed_default": False,
            "external_publish_replayed": False,
            "raw_payloads_absent": RAW_A not in replay_text and RAW_B not in replay_text,
            "cross_tenant_replay": cross_tenant_replay,
            "adapter_executions_before_replay": adapter_before_replay,
            "adapter_executions_after_replay": adapter_after_replay,
            "action_execution_counts_before_replay": action_counts_before_replay,
            "action_execution_counts_after_replay": action_counts_after_replay,
            "approved_publish_artifact_path": approved_publish_evidence.get(
                "artifact_path"
            ),
            "approved_publish_trace_event_id": approved_publish_evidence.get(
                "trace_event_id"
            ),
            "internal_artifact_trace_event_id": internal_artifact_evidence.get(
                "trace_event_id"
            ),
        },
        "audit-report.json": {
            "events": manager_events,
            "in_scope_data_refs": [DATA_REF_A],
            "denied_data_refs": [DATA_REF_B],
            "negative_cases": negatives,
            "event_ids": event_ids,
            "exact_authority_profiles": profile_summaries,
            "approval_receipt_trace_event_id": authority_receipt.get(
                "approval_trace_event_id"
            ),
            "approval_grant_trace_event_id": approval_grant["body"].get(
                "trace_event_id"
            ),
        },
        "resident-security.json": resident_security_report,
        "manager-approval-auth.json": manager_approval_auth_report,
        "anti-drift-results.json": {
            "status": "passed" if not failures else "failed",
            "private_helper_only_e2e": False,
            "gateway_bypass": False,
            "specialist_broad_permission_inheritance": False,
            "manager_credential_authorizes_action": False,
            "trace_export_without_redaction_allowed": False,
            "replay_side_effects_allowed_default": False,
            "resident_tls_bypassed": False,
            "resident_bearer_reused": False,
            "local_work_order_key_used_for_resident": False,
            "broad_action_adapter_profile_used": False,
            "raw_approval_evidence_used_for_execution": False,
            "approval_lifecycle_resume_used": False,
            "approval_retry_started_second_tick": False,
            "approval_retry_advanced_state_head": False,
        },
        "stdout.log": "UC-E2E-S7 data-local analysis scenario completed through public manager and verified-TLS resident APIs\n",
        "stderr.log": "",
    }
    for name, data in artifacts.items():
        path = artifact_dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", records)
    scenario["artifact_paths"].extend(
        [
            str(artifact_dir / "api-traffic.ndjson"),
            str(artifact_dir / "trace-export.jsonl"),
        ]
    )
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit(
            "UC-E2E-S7 failed required evidence checks: " + ",".join(failures)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
