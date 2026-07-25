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
    CLOUD_INSTANCE_FEATURES,
    CLOUD_NODE_CAPABILITIES,
)
from acceptance_provider_evidence import (  # noqa: E402
    provider_effect_state,
    read_provider_evidence,
)
from acceptance_provider_output import project_private_v3_output  # noqa: E402
from acceptance_scenario_expectations import expectation_for  # noqa: E402
from resident_http import request_json_no_redirect  # noqa: E402

FLEET_ID = "00000000-0000-4000-8000-000000000104"
TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
RUN_ID = "44444444-4444-4444-8444-444444444445"
INTERNAL_RUN_ID = "44444444-4444-4444-8444-444444445446"
REVOKE_RUN_ID = "44444444-4444-4444-8444-444444445546"
EXPIRE_RUN_ID = "44444444-4444-4444-8444-444444445646"
DENY_RUN_ID = "44444444-4444-4444-8444-444444444545"
KILL_RUN_ID = "44444444-4444-4444-8444-444444444645"
CANCEL_RUN_ID = "44444444-4444-4444-8444-444444445345"
POLICY_ID = "policy_uc_e2e_s5_publish_external"
WORK_ORDER_ID = "wo_uc_e2e_s5_governance"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
CLOUD_WORK_ORDER_KEY_ID = "work-order-acceptance-cloud"
RUNTIME_IMAGE_IDENTITY = "splendor-kernel-runtime:acceptance-target-runtime"
ARTIFACT_SECRET_KEYS = {"authorization", "bearer", "signature", "token"}
ARTIFACT_REF = f"artifact://{TENANT_ID}/governance/uc-e2e-s5.md"


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def utc_seconds(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def artifact_safe(data: Any) -> Any:
    if isinstance(data, dict):
        return {
            key: "[REDACTED]" if key.lower() in ARTIFACT_SECRET_KEYS else artifact_safe(value)
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [artifact_safe(value) for value in data]
    return data


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact_safe(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(artifact_safe(row), sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None, context: ssl.SSLContext | None = None) -> tuple[int, dict[str, Any]]:
    return request_json_no_redirect(
        method,
        base_url.rstrip("/") + path,
        body,
        headers,
        context,
        timeout=20,
    )


def provider_counters(base_url: str) -> dict[str, Any]:
    return read_provider_evidence(base_url)


def splendorctl(root: Path) -> list[str]:
    for candidate in [Path("/usr/local/bin/splendorctl"), root / "target" / "debug" / "splendorctl"]:
        if candidate.exists():
            return [str(candidate)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s5_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s5", "label": "UC-E2E-S5"}, "client_principal_id": "client_uc_e2e_s5", "label": "UC-E2E-S5 governance client"},
        "scopes": scopes or ["policies_publish", "policies_revoke", "approvals_manage", "governance_control", "traces_read", "fleet_read", "fleet_dispatch", "work_orders_submit", "nodes_register", "instances_register", "nodes_heartbeat", "instances_heartbeat"],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def daemon_credential(run_id: str | None = None, scopes: list[str] | None = None) -> dict[str, Any]:
    suffix = (run_id or RUN_ID)[-3:]
    return {
        "credential_id": f"cred_uc_e2e_s5_daemon_{suffix}",
        "principal": manager_credential()["principal"],
        "scopes": scopes or ["runs_create", "runs_start", "runs_read", "runs_resume", "runs_stop", "actions_submit", "state_read", "traces_read", "replay_create", "policies_sync"],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"daemon": {"daemon_id": "daemon_local"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def resident_auth(root: Path, auth_dir: Path, instance_id: str, scopes: list[str]) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "token",
        "--auth-dir",
        str(auth_dir),
        "--tenant-id",
        TENANT_ID,
        "--instance-id",
        instance_id,
    ]
    for scope in scopes:
        command.extend(["--scope", scope])
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("resident caller token fixture failed")
    return json.loads(proc.stdout)


def manager_auth(root: Path, auth_dir: Path) -> dict[str, Any]:
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
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("manager approval caller token fixture failed")
    return json.loads(proc.stdout)


def node_registration(node_id: str, instance_url: str) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": "cloud.worker",
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": list(CLOUD_NODE_CAPABILITIES),
            "constraints": {"placement_target": "resident_cloud_pool", "data_locality": "cloud", "region": "eu-west", "resident_daemon_url": instance_url, "runtime_image_identity": RUNTIME_IMAGE_IDENTITY, "trust_level": "acceptance"},
        },
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": list(CLOUD_INSTANCE_FEATURES), "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}}, "registered_at": utc(0)}


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any] | None = None) -> dict[str, Any]:
    credential = credential or manager_credential()
    return {"credential": credential, "audit_attribution": audit(credential)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def resident_credential_header(auth: dict[str, Any]) -> dict[str, str]:
    return {
        "authorization": f"Bearer {auth['token']}",
        "x-splendor-caller-credential": json.dumps(auth["credential"], sort_keys=True),
    }


def work_order(run_id: str = RUN_ID, expires: int = 60, *, action_name: str = "artifact.publish_external") -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": WORK_ORDER_ID + "_" + run_id[-3:],
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": f"UC-E2E-S5 governed {action_name}",
        "allowed_actions": [action_name],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": [action_name],
        "data_refs": ["artifact:uc-e2e-s5.internal"],
        "quotas": {"max_actions_per_tick": 5, "max_action_duration_ms": 30000},
        "placement": {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": [action_name]},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    command = splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET]
    with commands.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(command[:-1] + ["[REDACTED]"]) + "\n")
    proc = subprocess.run(command, cwd=root, text=True, capture_output=True)
    with commands.open("a", encoding="utf-8") as fh:
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if proc.returncode != 0:
        raise SystemExit("local work-order signing failed")
    return json.loads(proc.stdout)


def sign_resident_work_order(root: Path, artifact_dir: Path, commands: Path, auth_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.resident.unsigned.json"
    write_json(unsigned, payload)
    secret = (auth_dir / f"work-order-signing-{CLOUD_INSTANCE_ID}.secret").read_text(encoding="ascii")
    command = splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", CLOUD_WORK_ORDER_KEY_ID, "--secret", secret]
    with commands.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(command[:-1] + ["[REDACTED]"]) + "\n")
    proc = subprocess.run(command, cwd=root, text=True, capture_output=True)
    with commands.open("a", encoding="utf-8") as fh:
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if proc.returncode != 0:
        raise SystemExit("resident work-order signing failed")
    return json.loads(proc.stdout)


def action(name: str) -> dict[str, Any]:
    create = name == "artifact.create_internal"
    return {
        "name": name,
        "params": {"artifact_path" if create else "publish_ref": ARTIFACT_REF},
        "side_effect_class": "External",
        "cost_estimate": None,
        "required_permissions": [name],
        "preconditions": [],
        "postconditions": ["artifact_created" if create else "artifact_published"],
    }


def action_id_for_run(run_id: str) -> str:
    return "55555555-5555-4555-8555-555555" + run_id[-6:]


def quota() -> dict[str, int]:
    return {"actions": 1, "action_duration_ms": 1, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def approval_policy(expires: int = 60) -> dict[str, Any]:
    return {"schema_version": "splendor.approval_policy.v1", "policy_id": POLICY_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "action_name": "artifact.publish_external", "adapter": "artifact-store", "required_permission": "artifact.publish_external", "side_effect_class": "External", "risk_level": "high", "reason": "external publication requires governance approval", "expires_at": utc(expires)}


def policy_bundle(expires: int = 60, policy_id: str = POLICY_ID, expires_at: str | None = None) -> dict[str, Any]:
    return {"schema_version": "splendor.policy_bundle.v1", "policy_bundle_id": policy_id, "version": "uc-e2e-s5.v1", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "issued_at": utc(-1), "expires_at": expires_at or utc(expires), "revocation": "active", "degraded_mode": {"allow_low_risk_cached": False, "disconnected_low_risk_actions": ["artifact.create_internal"], "disconnected_high_risk_actions": ["artifact.publish_external"], "high_risk_disconnected_behavior": "deny"}}


def create_run_payload(run_id: str, envelope: dict[str, Any], signed_policy: dict[str, Any] | None, *, policies: list[dict[str, Any]] | None = None, circuit_breakers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cred = daemon_credential(run_id)
    signed_payload = envelope.get("work_order", envelope)
    work_order_id = signed_payload.get("work_order_id", "unknown")
    allowed_actions = signed_payload.get("allowed_actions", [])
    allowed_adapters = signed_payload.get("allowed_adapters", [])
    allowed_permissions = signed_payload.get("allowed_permissions", [])
    if len(allowed_actions) != 1 or len(allowed_adapters) != 1 or allowed_permissions != allowed_actions:
        raise SystemExit("UC-E2E-S5 work orders must contain one exact action/adapter/permission profile")
    action_name = allowed_actions[0]
    adapter = allowed_adapters[0]
    return {
        "request_id": f"req-uc-e2e-s5-{work_order_id}-{run_id}",
        "idempotency_key": f"idem-uc-e2e-s5-{work_order_id}-{run_id}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": cred,
        "audit_attribution": audit(cred),
        "allowed_actions": allowed_actions,
        "allowed_adapters": allowed_adapters,
        "allowed_permissions": allowed_permissions,
        "registered_actions": [{"name": action_name, "adapter": adapter}],
        "policy_actions": [{"action_id": action_id_for_run(run_id), "action": action(action_name), "adapter": adapter, "quota_usage": quota(), "satisfied_preconditions": []}],
        "policy_bundle_required": signed_policy is not None,
        "policy_bundle": signed_policy,
        "approval_policies": policies if policies is not None else [approval_policy()],
        "circuit_breakers": circuit_breakers or [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"scenario": "UC-E2E-S5", "run_id": run_id},
        "snapshot_interval": 1,
    }


def extract_approval_context(outcome: dict[str, Any]) -> dict[str, Any]:
    challenge = outcome.get("approval_challenge")
    if not isinstance(challenge, dict) or not challenge:
        raise SystemExit("exact approval challenge missing from needs_approval outcome")
    return challenge


def approval_request_payload(security: dict[str, Any], challenge: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        **security,
        "approval_id": challenge["approval_id"],
        "tenant_id": challenge["tenant_id"],
        "agent_id": challenge["agent_id"],
        "run_id": challenge["run_id"],
        "action_id": challenge["action_id"],
        "action_name": challenge["action_name"],
        "adapter": challenge["adapter"],
        "policy_id": challenge["policy_id"],
        "risk_level": challenge.get("risk_level") or "",
        "audience": challenge["receipt_audience"],
        "expires_at": challenge["expires_at"],
        "reason": reason,
        "challenge": challenge,
    }


def trace_event_id_map(records: list[dict[str, Any]], manager_events: list[dict[str, Any]]) -> dict[str, list[str]]:
    mapping = {
        "LoopTickStarted": "tick.started",
        "LoopTickCompleted": "tick.completed",
        "PolicyInvoked": "policy.invoked",
        "PolicyCompleted": "policy.completed",
        "CandidatesProposed": "actions.proposed",
        "ConstraintsEvaluated": "constraints.evaluated",
        "ActionVerificationStarted": "verification.started",
        "ActionVerificationCompleted": "verification.completed",
        "ActionExecuted": "action.executed",
        "ActionDenied": "action.denied",
        "ActionNeedsApproval": "action.needs_approval",
        "ActionNeedsIntervention": "action.needs_intervention",
        "ApprovalRequested": "approval.requested",
        "ApprovalGranted": "approval.granted",
        "ApprovalDenied": "approval.denied",
        "ApprovalExpired": "approval.expired",
        "ApprovalRevoked": "approval.revoked",
        "RunPaused": "run.paused",
        "RunResumed": "run.resumed",
        "RunStopped": "run.cancelled",
        "PolicyExpired": "policy.expired",
        "PolicyRevoked": "policy.revoked",
        "StateCommitted": "state.committed",
        "OutcomeRecorded": "outcome.recorded",
    }
    result: dict[str, list[str]] = {}
    for rec in records:
        payload = rec.get("payload", {})
        kind = payload.get("kind", {})
        key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
        result.setdefault(mapping.get(key, key), []).append(payload.get("trace_event_id", ""))
    for ev in manager_events:
        result.setdefault(ev.get("event_type", "unknown"), []).append(ev.get("trace_event_id", ""))
    return result


def first_trace_event_id(records: list[dict[str, Any]]) -> str:
    for record in records:
        trace_event_id = record.get("payload", {}).get("trace_event_id")
        if trace_event_id:
            return str(trace_event_id)
    raise SystemExit("approval-required run did not expose a causal trace identity")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default="http://splendor-daemon-local:8080")
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--action-provider-url", default="http://acceptance-action-provider:8086")
    parser.add_argument("--cloud-url", default="https://resident-cloud-node:8091")
    parser.add_argument("--resident-auth-dir", default=os.environ.get("SPLENDOR_RESIDENT_AUTH_DIR", "/run/splendor-auth"))
    parser.add_argument("--resident-ca-file", default=os.environ.get("SPLENDOR_RESIDENT_CA_FILE", "/run/splendor-auth/resident-root-ca.pem"))
    args = parser.parse_args()
    root = Path(args.root)
    auth_dir = Path(args.resident_auth_dir)
    resident_ssl = ssl.create_default_context(cafile=args.resident_ca_file)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S5"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("", encoding="utf-8")
    api_rows: list[dict[str, Any]] = []
    resident_security_events: list[dict[str, Any]] = []
    used_resident_credentials: set[str] = set()
    manager_approval_auth_events: list[dict[str, Any]] = []
    used_manager_approval_credentials: set[str] = set()

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        context = resident_ssl if base.lower().startswith("https://") else None
        status, data = request_json(method, base, path, body, headers, context)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    def resident_call(operation: str, method: str, path: str, scope: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, [scope])
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_resident_credentials:
            raise SystemExit("resident caller fixture reused a bearer JTI")
        used_resident_credentials.add(credential_id)
        expected_binding = {"tenant": {"tenant_id": TENANT_ID}}
        expected_audience = {"instance": {"instance_id": CLOUD_INSTANCE_ID}}
        if credential.get("scopes") != [scope] or credential.get("binding") != expected_binding or credential.get("audience") != expected_audience:
            raise SystemExit("resident caller fixture returned an invalid projection")
        secured_body = None if body is None else {**body, "credential": credential, "audit_attribution": audit(credential)}
        result = call(operation, method, args.cloud_url, path, secured_body, resident_credential_header(auth))
        response_trace_ids = [
            str(result["body"][key])
            for key in ["trace_event_id", "audit_trace_event_id"]
            if isinstance(result.get("body"), dict) and result["body"].get(key)
        ]
        resident_security_events.append(
            {
                "operation_id": operation,
                "method": method,
                "endpoint": path,
                "scope": scope,
                "credential_correlation_id": credential_id,
                "binding": expected_binding,
                "audience": expected_audience,
                "target_instance_id": CLOUD_INSTANCE_ID,
                "tls_verification": "acceptance_ca",
                "redirect_policy": "forbid",
                "result_status": result["status"],
                "trace_event_ids": response_trace_ids,
                "raw_bearer_recorded": False,
                "raw_jti_recorded": False,
            }
        )
        return result

    def manager_approval_call(operation: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        auth = manager_auth(root, auth_dir)
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_manager_approval_credentials:
            raise SystemExit("manager approval caller fixture reused a bearer JTI")
        used_manager_approval_credentials.add(credential_id)
        if credential.get("scopes") != ["approvals_manage"] or credential.get("binding") != {"fleet": {"fleet_id": FLEET_ID}} or credential.get("audience") != {"central_manager": {"manager_id": "central-manager"}}:
            raise SystemExit("manager approval caller fixture returned an invalid projection")
        secured_body = {
            **body,
            "credential": credential,
            "audit_attribution": audit(credential),
        }
        result = call(
            operation,
            "POST",
            args.manager_url,
            path,
            secured_body,
            {"authorization": f"Bearer {auth['token']}"},
        )
        manager_approval_auth_events.append(
            {
                "operation_id": operation,
                "method": "POST",
                "endpoint": path,
                "scope": "approvals_manage",
                "credential_correlation_id": credential_id,
                "binding": credential["binding"],
                "audience": credential["audience"],
                "result_status": result["status"],
                "trace_event_ids": [str(result["body"]["trace_event_id"])] if result["body"].get("trace_event_id") else [],
                "raw_bearer_recorded": False,
                "raw_jti_recorded": False,
            }
        )
        return result

    def require_status(operation: str, response: dict[str, Any], expected: int) -> None:
        if response["status"] != expected:
            raise SystemExit(f"{operation} returned {response['status']}, expected {expected}: {json.dumps(response['body'], sort_keys=True)}")

    def require_action_outcome(operation: str, response: dict[str, Any], index: int = 0) -> dict[str, Any]:
        require_status(operation, response, 200)
        outcomes = response["body"].get("action_outcomes", [])
        if len(outcomes) <= index:
            raise SystemExit(f"{operation} missing action outcome {index}: {json.dumps(response['body'], sort_keys=True)}")
        return outcomes[index]

    for _ in range(40):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)

    manager_cred = manager_credential()
    cloud_node = node_registration(CLOUD_NODE_ID, args.cloud_url)
    cloud_instance = instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID)
    register_node = call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager_cred), "registration": cloud_node})
    require_status("register governance cloud node", register_node, 200)
    register_instance = call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager_cred), "registration": cloud_instance})
    require_status("register governance cloud instance", register_instance, 200)
    node_heartbeat = call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{CLOUD_NODE_ID}/heartbeat", {**sec(manager_cred), "heartbeat": {"node_id": CLOUD_NODE_ID, "health": cloud_node["health"], "recorded_at": utc(0)}})
    require_status("refresh governance cloud node heartbeat", node_heartbeat, 200)
    instance_heartbeat = call("heartbeatInstance", "POST", args.manager_url, f"/fleet/instances/{CLOUD_INSTANCE_ID}/heartbeat", {**sec(manager_cred), "heartbeat": {"node_id": CLOUD_NODE_ID, "instance_id": CLOUD_INSTANCE_ID, "health": cloud_instance["health"], "recorded_at": utc(0)}})
    require_status("refresh governance cloud instance heartbeat", instance_heartbeat, 200)
    published = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle()})
    signed_policy = published["body"].get("envelope")
    policy_status = call("getPolicyStatus", "POST", args.manager_url, f"/policies/{POLICY_ID}/read", sec(manager_cred))

    internal_envelope = sign_work_order(root, artifact_dir, commands, work_order(INTERNAL_RUN_ID, action_name="artifact.create_internal"))
    internal_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(INTERNAL_RUN_ID, internal_envelope, None, policies=[]))
    require_status("internal createRun", internal_create, 200)
    internal_cred = daemon_credential(INTERNAL_RUN_ID)
    internal_start = call("startRun", "POST", args.base_url, f"/runs/{INTERNAL_RUN_ID}/start", {"credential": internal_cred, "audit_attribution": audit(internal_cred), "reason": "uc_e2e_s5_internal_artifact"})
    internal = require_action_outcome("internal startRun", internal_start)
    internal_projection = project_private_v3_output(
        internal,
        expectation=expectation_for("UC-E2E-S5", "internal_artifact"),
    )
    internal_state_head = call("getStateHead", "GET", args.base_url, f"/runs/{INTERNAL_RUN_ID}/state-head", headers=credential_header(internal_cred))

    envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID))
    create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(RUN_ID, envelope, signed_policy))
    require_status("createRun", create, 200)
    daemon_cred = daemon_credential(RUN_ID)
    start = call("startRun", "POST", args.base_url, f"/runs/{RUN_ID}/start", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "reason": "uc_e2e_s5_external_publish_proposed"})
    needs_approval = require_action_outcome("startRun", start)
    approval_context = extract_approval_context(needs_approval)
    pending_traces = call("getRunTraces", "GET", args.base_url, f"/runs/{RUN_ID}/traces?redaction_policy=uc-e2e-s5-redacted", headers=credential_header(daemon_cred))
    require_status("getRunTraces", pending_traces, 200)
    pending_causal_trace_id = first_trace_event_id(pending_traces["body"].get("records", []))
    provider_before_publish = provider_counters(args.action_provider_url)
    forged_legacy = {
        "schema_version": "splendor.approval_evidence.v1",
        "approval_id": approval_context["approval_id"],
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "action_id": approval_context["action_id"],
        "action_name": approval_context["action_name"],
        "adapter": approval_context["adapter"],
        "decision": "Granted",
        "reason": "forged legacy grant must not authorize",
        "issued_at": utc(0),
        "expires_at": approval_context["expires_at"],
        "revoked": False,
        "trace_event_id": None,
    }
    forged_legacy_retry = call("submitAction", "POST", args.base_url, "/actions", {"action_id": approval_context["action_id"], "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": pending_causal_trace_id, "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "requested_at": approval_context["requested_at"], "approval_evidence": forged_legacy})
    after_forged_legacy = call("inspectRun", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(daemon_cred))
    provider_after_forged_legacy = provider_counters(args.action_provider_url)
    approval_request = manager_approval_call("requestApproval", "/approvals", approval_request_payload(sec(manager_cred), approval_context, "external publication requested"))
    approval_grant = manager_approval_call("grantApproval", f"/approvals/{approval_context['approval_id']}/grant", {"reason": "approved_for_uc_e2e_s5"})
    evidence = approval_grant["body"].get("evidence")
    authority_receipt = approval_grant["body"].get("authority_obligation_receipt")
    if not isinstance(authority_receipt, dict):
        raise SystemExit("manager grant did not issue a trusted approval obligation receipt")
    receipt_resume_rejected = call("resumeRun", "POST", args.base_url, f"/runs/{RUN_ID}/resume", {"credential": daemon_cred, "work_order": envelope, "audit_attribution": audit(daemon_cred), "reason": "receipt must retry exact action", "authority_obligation_receipts": [authority_receipt]})
    approved_retry = call("submitAction", "POST", args.base_url, "/actions", {"action_id": approval_context["action_id"], "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": approval_grant["body"].get("trace_event_id"), "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "requested_at": approval_context["requested_at"], "authority_obligation_receipts": [authority_receipt]})
    publish_projection = project_private_v3_output(
        approved_retry["body"],
        expectation=expectation_for("UC-E2E-S5", "approved_publish"),
    )
    provider_after_publish = provider_counters(args.action_provider_url)
    publish_provider_delta = (
        provider_after_publish.get("by_action", {}).get("artifact.publish_external", 0)
        - provider_before_publish.get("by_action", {}).get("artifact.publish_external", 0)
    )
    publish_provider_receipt = next(
        (
            receipt
            for receipt in provider_after_publish.get("receipts", [])
            if receipt.get("action_id") == approval_context["action_id"]
        ),
        {},
    )
    state_head = call("getStateHead", "GET", args.base_url, f"/runs/{RUN_ID}/state-head", headers=credential_header(daemon_cred))

    before_expired_raw = call("inspectRunBeforeExpiredRaw", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(daemon_cred))
    before_expired_raw_traces = call("getRunTracesBeforeExpiredRaw", "GET", args.base_url, f"/runs/{RUN_ID}/traces?redaction_policy=uc-e2e-s5-redacted", headers=credential_header(daemon_cred))
    expired_evidence = json.loads(json.dumps(evidence))
    expired_evidence["approval_id"] = "55555555-5555-4555-8555-555555555502"
    expired_evidence["issued_at"] = utc(-10)
    expired_evidence["expires_at"] = utc(-5)
    expired_raw_rejection = call("submitExpiredRawEvidenceOnActiveRun", "POST", args.base_url, "/actions", {"action_id": evidence["action_id"], "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": approval_grant["body"].get("trace_event_id"), "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": expired_evidence})
    after_expired_raw = call("inspectRunAfterExpiredRaw", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(daemon_cred))
    after_expired_raw_traces = call("getRunTracesAfterExpiredRaw", "GET", args.base_url, f"/runs/{RUN_ID}/traces?redaction_policy=uc-e2e-s5-redacted", headers=credential_header(daemon_cred))
    before_expired_trace_ids = [record.get("payload", {}).get("trace_event_id") for record in before_expired_raw_traces["body"].get("records", [])]
    after_expired_trace_ids = [record.get("payload", {}).get("trace_event_id") for record in after_expired_raw_traces["body"].get("records", [])]
    expired_raw_trace_delta = [trace_id for trace_id in after_expired_trace_ids if trace_id not in set(before_expired_trace_ids)]
    expired_raw_lifecycle_fields = ["status", "ticks", "state_head", "adapter_executions"]
    expired_raw_lifecycle_unchanged = all(before_expired_raw["body"].get(field) == after_expired_raw["body"].get(field) for field in expired_raw_lifecycle_fields)
    expired_raw_approval_trace_records = [
        record
        for record in after_expired_raw_traces["body"].get("records", [])
        if expired_evidence["approval_id"] in json.dumps(record, sort_keys=True)
    ]
    active_expired_raw_evidence = {
        "classification": "pre_gateway_run_action_admission_rejection",
        "http_status": expired_raw_rejection["status"],
        "code": expired_raw_rejection["body"].get("code"),
        "approval_id": expired_evidence["approval_id"],
        "run_id": RUN_ID,
        "action_id": evidence["action_id"],
        "before": {field: before_expired_raw["body"].get(field) for field in expired_raw_lifecycle_fields},
        "after": {field: after_expired_raw["body"].get(field) for field in expired_raw_lifecycle_fields},
        "lifecycle_unchanged": expired_raw_lifecycle_unchanged,
        "trace_ids_before": before_expired_trace_ids,
        "trace_ids_after": after_expired_trace_ids,
        "appended_trace_event_ids": expired_raw_trace_delta,
        "approval_trace_records": expired_raw_approval_trace_records,
        "gateway_invoked": False,
        "adapter_effect_delta": after_expired_raw["body"].get("adapter_executions", 0) - before_expired_raw["body"].get("adapter_executions", 0),
    }

    expire_envelope = sign_work_order(root, artifact_dir, commands, work_order(EXPIRE_RUN_ID))
    expire_create = call("createExpiringRun", "POST", args.base_url, "/runs", create_run_payload(EXPIRE_RUN_ID, expire_envelope, signed_policy))
    require_status("create expiring run", expire_create, 200)
    expire_cred = daemon_credential(EXPIRE_RUN_ID)
    expire_start = call("startExpiringRun", "POST", args.base_url, f"/runs/{EXPIRE_RUN_ID}/start", {"credential": expire_cred, "audit_attribution": audit(expire_cred), "reason": "exact_waiting_expiry_branch"})
    expire_context = extract_approval_context(require_action_outcome("start expiring run", expire_start))
    expire_pending_traces = call("getExpiringRunTraces", "GET", args.base_url, f"/runs/{EXPIRE_RUN_ID}/traces?redaction_policy=uc-e2e-s5-redacted", headers=credential_header(expire_cred))
    require_status("get expiring run traces", expire_pending_traces, 200)
    expire_evidence = {
        "schema_version": "splendor.approval_evidence.v1",
        "approval_id": expire_context["approval_id"],
        "tenant_id": expire_context["tenant_id"],
        "agent_id": expire_context["agent_id"],
        "run_id": expire_context["run_id"],
        "action_id": expire_context["action_id"],
        "action_name": expire_context["action_name"],
        "adapter": expire_context["adapter"],
        "decision": "Granted",
        "reason": "expired exact waiting approval",
        "issued_at": utc(-10),
        "expires_at": utc(-5),
        "revoked": False,
        "trace_event_id": None,
    }
    expired = call("submitExpiredExactWaitingApproval", "POST", args.base_url, "/actions", {"action_id": expire_context["action_id"], "run_id": EXPIRE_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": expire_cred, "audit_attribution": audit(expire_cred), "causal_trace_id": first_trace_event_id(expire_pending_traces["body"].get("records", [])), "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "requested_at": expire_context["requested_at"], "approval_evidence": expire_evidence})
    require_status("submit expired exact waiting approval", expired, 200)
    expire_after = call("inspectExpiredRun", "GET", args.base_url, f"/runs/{EXPIRE_RUN_ID}", headers=credential_header(expire_cred))

    revoke_work_order = work_order(REVOKE_RUN_ID)
    revoke_envelope = sign_resident_work_order(root, artifact_dir, commands, auth_dir, revoke_work_order)
    revoke_policy = approval_policy(55)
    revoke_policy["policy_id"] = f"{POLICY_ID}_resident_revoke"
    revoke_validation = call(
        "submitRevocableWorkOrder",
        "POST",
        args.manager_url,
        "/work-orders",
        {**sec(manager_cred), "work_order": revoke_envelope, "expected_audience": "central-manager", "approval_policies": [revoke_policy]},
    )
    require_status("submit revocable work order", revoke_validation, 200)
    revoke_placement = call(
        "evaluateRevocablePlacement",
        "POST",
        args.manager_url,
        "/fleet/placement/evaluate",
        {
            **sec(manager_cred),
            "work_order_id": revoke_work_order["work_order_id"],
            "request": {
                "target": "resident_cloud_pool",
                "required_capabilities": ["artifact.publish_external"],
                "data_locality": "cloud",
                "dedicated_instance": False,
                "required_runtime_version": None,
                "max_runtime_ms": None,
                "execution_mode": "live",
            },
        },
    )
    require_status("evaluate revocable placement", revoke_placement, 200)
    if revoke_placement["body"].get("status") != "selected" or revoke_placement["body"].get("candidate_id") != CLOUD_NODE_ID:
        raise SystemExit(f"revocable placement did not select the governance cloud node: {json.dumps(revoke_placement['body'], sort_keys=True)}")
    revoke_dispatch = call(
        "dispatchRevocableWorkOrder",
        "POST",
        args.manager_url,
        f"/work-orders/{revoke_work_order['work_order_id']}/dispatch",
        {**sec(manager_cred), "target_node_id": CLOUD_NODE_ID},
    )
    require_status("dispatch revocable work order", revoke_dispatch, 200)
    revoke_dispatch_start = json.loads(revoke_dispatch["body"].get("start_run_body") or "{}")
    if revoke_dispatch["body"].get("selected_instance_id") != CLOUD_INSTANCE_ID or revoke_dispatch_start.get("status") != "running":
        raise SystemExit("revocable work order did not start on the exact cloud resident")

    revoke_action_request = {
        "action_id": action_id_for_run(REVOKE_RUN_ID),
        "run_id": REVOKE_RUN_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "causal_trace_id": revoke_dispatch["body"].get("trace_event_id"),
        "action": action("artifact.publish_external"),
        "adapter": "artifact-store",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "requested_at": utc(0),
    }
    revoke_proposal = resident_call("submitRevocableAction", "POST", "/actions", "actions_submit", revoke_action_request)
    require_status("submit revocable action", revoke_proposal, 200)
    if revoke_proposal["body"].get("status") != "NeedsApproval":
        raise SystemExit("cloud resident revocable action did not require approval")
    revoke_context = extract_approval_context(revoke_proposal["body"])
    revoke_pending_traces = resident_call("getRevocableTraces", "GET", f"/runs/{REVOKE_RUN_ID}/traces?redaction_policy=uc-e2e-s5-redacted", "traces_read")
    require_status("get revocable traces", revoke_pending_traces, 200)
    revoke_causal_trace_id = first_trace_event_id(revoke_pending_traces["body"].get("records", []))
    revoke_request = manager_approval_call("requestRevocableApproval", "/approvals", approval_request_payload(sec(manager_cred), revoke_context, "resident receipt revocation branch requested"))
    require_status("request revocable approval", revoke_request, 200)
    revoke_grant = manager_approval_call("grantRevocableApproval", f"/approvals/{revoke_context['approval_id']}/grant", {"reason": "grant_before_resident_revocation"})
    require_status("grant revocable approval", revoke_grant, 200)
    retained_revoke_receipt = revoke_grant["body"].get("authority_obligation_receipt")
    if not isinstance(retained_revoke_receipt, dict):
        raise SystemExit("manager did not retain the exact revocable resident receipt")
    expected_revoke_audience = f"splendor.daemon.approval_receipt.v2:instance:{CLOUD_INSTANCE_ID}:run:{REVOKE_RUN_ID}"
    if retained_revoke_receipt.get("audience") != expected_revoke_audience or revoke_context.get("receipt_audience") != expected_revoke_audience:
        raise SystemExit("revocable receipt did not bind the exact cloud instance and run")

    revoke_before_manager = resident_call("inspectRevocableBeforeManagerRevoke", "GET", f"/runs/{REVOKE_RUN_ID}", "runs_read")
    revoke_state_before_manager = resident_call("getRevocableStateBeforeManagerRevoke", "GET", f"/runs/{REVOKE_RUN_ID}/state-head", "state_read")
    approval_revoke = manager_approval_call("revokeApproval", f"/approvals/{revoke_context['approval_id']}/revoke", {"reason": "operator_revoked_resident_publication"})
    require_status("revoke resident approval", approval_revoke, 200)
    resident_revocation_ack = approval_revoke["body"].get("resident_receipt_revocation_ack")
    if not isinstance(resident_revocation_ack, dict):
        raise SystemExit("manager reported revocation without an exact resident acknowledgement")
    revoke_after_manager = resident_call("inspectRevocableAfterManagerRevoke", "GET", f"/runs/{REVOKE_RUN_ID}", "runs_read")
    revoke_retry_request = {
        **revoke_action_request,
        "action_id": revoke_context["action_id"],
        "causal_trace_id": revoke_causal_trace_id,
        "requested_at": revoke_context["requested_at"],
        "authority_obligation_receipts": [retained_revoke_receipt],
    }
    revoked = resident_call("submitRevokedOriginalReceipt", "POST", "/actions", "actions_submit", revoke_retry_request)
    require_status("submit revoked original receipt", revoked, 200)
    revoke_after_retry = resident_call("inspectRevocableAfterDeniedRetry", "GET", f"/runs/{REVOKE_RUN_ID}", "runs_read")
    revoke_state_after_retry = resident_call("getRevocableStateAfterDeniedRetry", "GET", f"/runs/{REVOKE_RUN_ID}/state-head", "state_read")

    deny_envelope = sign_work_order(root, artifact_dir, commands, work_order(DENY_RUN_ID))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(DENY_RUN_ID, deny_envelope, signed_policy))
    deny_cred = daemon_credential(DENY_RUN_ID)
    deny_start = call("startRun", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/start", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "reason": "deny_branch"})
    deny_context = extract_approval_context(require_action_outcome("deny startRun", deny_start))
    manager_approval_call("requestApproval", "/approvals", approval_request_payload(sec(manager_cred), deny_context, "denial branch requested"))
    denial = manager_approval_call("denyApproval", f"/approvals/{deny_context['approval_id']}/deny", {"reason": "operator_denied_publication"})
    denial_evidence = denial["body"].get("evidence")
    deny_resume = call("submitAction", "POST", args.base_url, "/actions", {"action_id": deny_context["action_id"], "run_id": DENY_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": deny_cred, "audit_attribution": audit(deny_cred), "causal_trace_id": denial["body"].get("trace_event_id"), "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "requested_at": deny_context["requested_at"], "approval_evidence": denial_evidence})

    missing_policy = call("createRun", "POST", args.base_url, "/runs", {**create_run_payload("44444444-4444-4444-8444-444444444745", sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444444745")), None), "policy_bundle_required": True})
    expired_policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle(-1, "policy_uc_e2e_s5_expired")})
    expired_policy_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload("44444444-4444-4444-8444-444444444845", sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444444845")), expired_policy["body"].get("envelope")))
    ttl_policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle(policy_id="policy_uc_e2e_s5_runtime_expiry", expires_at=utc_seconds(3))})
    ttl_run_id = "44444444-4444-4444-8444-444444445245"
    ttl_action_id = action_id_for_run(ttl_run_id)
    ttl_cred = daemon_credential(ttl_run_id)
    ttl_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(ttl_run_id, sign_work_order(root, artifact_dir, commands, work_order(ttl_run_id)), ttl_policy["body"].get("envelope"), policies=[]))
    time.sleep(4)
    ttl_start = call("startRun", "POST", args.base_url, f"/runs/{ttl_run_id}/start", {"credential": ttl_cred, "audit_attribution": audit(ttl_cred), "reason": "runtime_policy_ttl_expired"})
    revoked_policy = call("revokePolicyBundle", "POST", args.manager_url, f"/policies/{POLICY_ID}/revoke", {**sec(manager_cred), "reason": "policy_revoked_negative"})
    revoked_policy_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload("44444444-4444-4444-8444-444444444945", sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444444945")), revoked_policy["body"].get("envelope")))

    uncertain_envelope = sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444445045"))
    uncertain_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload("44444444-4444-4444-8444-444444445045", uncertain_envelope, signed_policy, policies=[approval_policy(-1)]))
    uncertain_cred = daemon_credential("44444444-4444-4444-8444-444444445045")
    uncertainty = call("startRun", "POST", args.base_url, "/runs/44444444-4444-4444-8444-444444445045/start", {"credential": uncertain_cred, "audit_attribution": audit(uncertain_cred), "reason": "expired_approval_policy"})

    breaker_uuid = "55555555-5555-4555-8555-555555555506"
    breaker = call("createCircuitBreaker", "POST", args.manager_url, "/governance/circuit-breakers", {**sec(manager_cred), "breaker_id": breaker_uuid, "tenant_id": TENANT_ID, "adapter": "artifact-store", "action": "artifact.publish_external", "reason": "incident_block_external_publish"})
    cb_run_id = "44444444-4444-4444-8444-444444445145"
    cb_envelope = sign_work_order(root, artifact_dir, commands, work_order(cb_run_id))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(cb_run_id, cb_envelope, signed_policy, policies=[]))
    cb_cred = daemon_credential(cb_run_id)
    cb_payload = call("readCircuitBreakerSyncPayload", "POST", args.manager_url, f"/governance/circuit-breakers/{breaker_uuid}/sync-payload", {**sec(manager_cred), "run_id": cb_run_id, "reason": "manager_propagated_breaker"})
    cb_sync = call("syncCircuitBreakers", "POST", args.base_url, f"/runs/{cb_run_id}/governance/circuit-breakers/sync", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "circuit_breakers": cb_payload["body"].get("circuit_breakers", []), "reason": cb_payload["body"].get("reason")})
    cb_submit = call("submitAction", "POST", args.base_url, "/actions", {"run_id": cb_run_id, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": cb_cred, "audit_attribution": audit(cb_cred), "causal_trace_id": "55555555-5555-4555-8555-555555555507", "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    clear = call("clearCircuitBreaker", "POST", args.manager_url, f"/governance/circuit-breakers/{breaker_uuid}/clear", {**sec(manager_cred), "reason": "incident_resolved"})
    clear_wrong_scope = call("clearCircuitBreaker", "POST", args.manager_url, f"/governance/circuit-breakers/{breaker_uuid}/clear", {**sec(manager_credential(["fleet_read"])), "reason": "missing_control_scope"})

    kill_envelope = sign_resident_work_order(root, artifact_dir, commands, auth_dir, work_order(KILL_RUN_ID))
    kill_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["runs_create"])
    kill_cred = kill_auth["credential"]
    kill_create = create_run_payload(KILL_RUN_ID, kill_envelope, None, policies=[])
    kill_create["credential"] = kill_cred
    kill_create["audit_attribution"] = audit(kill_cred)
    call("createRun", "POST", args.cloud_url, "/runs", kill_create, resident_credential_header(kill_auth))
    kill = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager_cred), "kill_switch_id": "ks_uc_e2e_s5_run", "run_id": KILL_RUN_ID, "tenant_id": TENANT_ID, "node_id": CLOUD_NODE_ID, "instance_id": CLOUD_INSTANCE_ID, "reason": "operator_kill_switch", "propagation_ack_required": True})
    kill_missing_ack = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager_cred), "kill_switch_id": "ks_uc_e2e_s5_missing_ack", "run_id": KILL_RUN_ID, "tenant_id": TENANT_ID, "node_id": None, "instance_id": None, "reason": "missing_ack_negative", "propagation_ack_required": True})
    cancel_envelope = sign_work_order(root, artifact_dir, commands, work_order(CANCEL_RUN_ID))
    cancel_cred = daemon_credential(CANCEL_RUN_ID)
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(CANCEL_RUN_ID, cancel_envelope, signed_policy, policies=[]))
    cancel = call("cancelRun", "POST", args.base_url, f"/runs/{CANCEL_RUN_ID}/cancel", {"credential": cancel_cred, "audit_attribution": audit(cancel_cred), "reason": "separate_lifecycle_cancel_operation_not_kill_switch_evidence"})
    broad_mutation = manager_approval_call("grantApproval", "/approvals/55555555-5555-4555-8555-555555559999/grant", {"reason": "unknown_broad_grant"})

    internal_traces = call("exportTraces", "POST", args.base_url, f"/runs/{INTERNAL_RUN_ID}/traces/export", {"credential": internal_cred, "audit_attribution": audit(internal_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    traces = call("exportTraces", "POST", args.base_url, f"/runs/{RUN_ID}/traces/export", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    expire_traces = call("exportExpiringRunTraces", "POST", args.base_url, f"/runs/{EXPIRE_RUN_ID}/traces/export", {"credential": expire_cred, "audit_attribution": audit(expire_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    revoke_traces = resident_call("exportRevocableTraces", "POST", f"/runs/{REVOKE_RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    deny_traces = call("exportTraces", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/traces/export", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    cb_traces = call("exportTraces", "POST", args.base_url, f"/runs/{cb_run_id}/traces/export", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    kill_trace_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["traces_read"])
    kill_trace_cred = kill_trace_auth["credential"]
    kill_traces = call("exportTraces", "POST", args.cloud_url, f"/runs/{KILL_RUN_ID}/traces/export", {"credential": kill_trace_cred, "audit_attribution": audit(kill_trace_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None}, resident_credential_header(kill_trace_auth))
    ttl_traces = call("exportTraces", "POST", args.base_url, f"/runs/{ttl_run_id}/traces/export", {"credential": ttl_cred, "audit_attribution": audit(ttl_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    uncertainty_traces = call("exportTraces", "POST", args.base_url, "/runs/44444444-4444-4444-8444-444444445045/traces/export", {"credential": uncertain_cred, "audit_attribution": audit(uncertain_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    provider_before_replay = provider_counters(args.action_provider_url)
    replay = call("replayRun", "POST", args.base_url, f"/runs/{RUN_ID}/replay", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "mode": "inspect_only", "side_effects_allowed": False})
    provider_after_replay = provider_counters(args.action_provider_url)
    audit_export = call("exportGovernanceAudit", "POST", args.manager_url, "/governance/audit/export", {**sec(manager_cred), "run_id": RUN_ID})
    revoke_audit_export = call("exportRevocableGovernanceAudit", "POST", args.manager_url, "/governance/audit/export", {**sec(manager_cred), "run_id": REVOKE_RUN_ID})

    records = internal_traces["body"].get("records", []) + traces["body"].get("records", []) + expire_traces["body"].get("records", []) + revoke_traces["body"].get("records", []) + deny_traces["body"].get("records", []) + cb_traces["body"].get("records", []) + kill_traces["body"].get("records", []) + ttl_traces["body"].get("records", []) + uncertainty_traces["body"].get("records", [])
    manager_events = audit_export["body"].get("events", [])
    event_ids = trace_event_id_map(records, manager_events)
    external_executions = [approved_retry["body"]] if approved_retry["body"].get("status") == "Executed" and publish_projection.get("operation_id") == "artifact-store/artifact.publish_external" else []
    cb_denied_breaker = cb_submit["body"].get("verification", {}).get("artifacts", {}).get("circuit_breaker", {})
    cb_denied_breaker_id = cb_denied_breaker.get("breaker_id") or cb_denied_breaker.get("circuit_breaker", {}).get("breaker_id")
    ttl_trace_ids = trace_event_id_map(ttl_traces["body"].get("records", []), {})
    ttl_action_outcomes = ttl_start.get("body", {}).get("action_outcomes", [])
    ttl_policy_denial = next((outcome for outcome in ttl_action_outcomes if outcome.get("action_id") == ttl_action_id and outcome.get("status") in {"Denied", "NeedsIntervention"} and "policy_expired" in outcome.get("verification", {}).get("reasons", [])), {})
    ttl_policy_artifacts = ttl_policy_denial.get("verification", {}).get("artifacts", {})
    uncertainty_trace_ids = trace_event_id_map(uncertainty_traces["body"].get("records", []), {})
    manager_breaker_trace_id = breaker["body"].get("trace_event_id")
    breaker_payload_record = cb_payload["body"].get("breaker_record", {})
    revoked_denial = revoked["body"]
    resident_revocation_exact = (
        approval_revoke["body"].get("status") == "revoked"
        and resident_revocation_ack.get("receipt_id") == retained_revoke_receipt.get("receipt_id")
        and resident_revocation_ack.get("approval_id") == revoke_context.get("approval_id")
        and resident_revocation_ack.get("target_instance_id") == CLOUD_INSTANCE_ID
        and resident_revocation_ack.get("run_id") == REVOKE_RUN_ID
        and resident_revocation_ack.get("receipt_audience") == expected_revoke_audience
        and resident_revocation_ack.get("status") in {"revoked", "already_revoked"}
        and resident_revocation_ack.get("effect_certainty") == "known"
    )
    revoke_lifecycle_unchanged = all(
        revoke_before_manager["body"].get(field) == revoke_after_manager["body"].get(field) == revoke_after_retry["body"].get(field)
        for field in ["ticks", "state_head"]
    )
    revoke_state_unchanged = all(
        revoke_state_before_manager["body"].get(field) == revoke_state_after_retry["body"].get(field)
        for field in ["state_node_id", "data_hash", "parent_state_node_ids"]
    )
    revoke_adapter_effects = {
        "before_manager_revoke": revoke_before_manager["body"].get("adapter_executions", 0),
        "after_manager_revoke": revoke_after_manager["body"].get("adapter_executions", 0),
        "after_denied_retry": revoke_after_retry["body"].get("adapter_executions", 0),
    }
    revoke_execution_traces = [
        record
        for record in revoke_traces["body"].get("records", [])
        if "ActionExecuted" in record.get("payload", {}).get("kind", {})
    ]
    revocation_daemon_audits = []
    for record in revoke_traces["body"].get("records", []):
        kind = record.get("payload", {}).get("kind", {})
        daemon_audit = kind.get("DaemonAudit") if isinstance(kind, dict) else None
        if isinstance(daemon_audit, dict) and daemon_audit.get("endpoint") == "splendor.approval_receipts.revoke":
            audit_value = daemon_audit.get("audit") if isinstance(daemon_audit.get("audit"), dict) else {}
            revocation_daemon_audits.append(
                {
                    "endpoint": f"/runs/{REVOKE_RUN_ID}/approval-receipts/{retained_revoke_receipt.get('receipt_id')}/revoke",
                    "required_scope": "splendor.approval_receipts.revoke",
                    "target_instance_id": CLOUD_INSTANCE_ID,
                    "run_id": REVOKE_RUN_ID,
                    "receipt_id": retained_revoke_receipt.get("receipt_id"),
                    "approval_id": revoke_context.get("approval_id"),
                    "credential_correlation_id": audit_value.get("credential_id"),
                    "trace_event_id": record.get("payload", {}).get("trace_event_id"),
                    "tls_verification": "acceptance_ca",
                    "redirect_policy": "forbid",
                    "ack_status": resident_revocation_ack.get("status"),
                    "effect_certainty": resident_revocation_ack.get("effect_certainty"),
                    "raw_bearer_recorded": False,
                    "raw_jti_recorded": False,
                    "receipt_signature_recorded": False,
                }
            )
    resident_revocation_security_valid = (
        len(revocation_daemon_audits) == 1
        and str(revocation_daemon_audits[0].get("credential_correlation_id", "")).startswith("sha256:")
        and bool(revocation_daemon_audits[0].get("trace_event_id"))
    )
    negatives = [
        {"case": "approval_denial_blocks_pending_action", "passed": denial["body"].get("status") == "denied" and deny_resume["status"] == 200 and deny_resume["body"].get("status") == "Denied" and deny_resume["body"].get("error") == "approval_denied" and deny_resume["body"].get("verification", {}).get("artifacts", {}).get("approval_status") == "denied" and deny_resume["body"].get("output") is None, "reason_code": "operator_denied_publication"},
        {"case": "expired_approval_cannot_authorize_execution", "passed": expired_raw_rejection["status"] == 409 and expired_raw_rejection["body"].get("code") == "legacy_approval_evidence_non_authorizing" and before_expired_raw["body"].get("status") == "running" and expired_raw_lifecycle_unchanged and before_expired_trace_ids == after_expired_trace_ids and not expired_raw_approval_trace_records and active_expired_raw_evidence["adapter_effect_delta"] == 0 and expired["body"].get("status") == "Denied" and expired["body"].get("verification", {}).get("artifacts", {}).get("approval_status") == "expired" and expired["body"].get("output") is None and expire_after["body"].get("status") == "expired" and expire_after["body"].get("adapter_executions") == 0, "boundary": "active_rejection_and_exact_waiting_fail_closed", "reason_code": "approval_expired"},
        {"case": "revoked_approval_cannot_authorize_execution", "passed": revoked["status"] == 200 and revoked_denial.get("status") == "Denied" and "authority_obligation_receipt_revoked" in revoked_denial.get("verification", {}).get("reasons", []) and revoked_denial.get("output") is None and resident_revocation_exact and resident_revocation_security_valid and revoke_lifecycle_unchanged and revoke_state_unchanged and set(revoke_adapter_effects.values()) == {0} and not revoke_execution_traces, "reason_code": "authority_obligation_receipt_revoked", "resident_ack_status": resident_revocation_ack.get("status")},
        {"case": "forged_legacy_grant_has_zero_effect", "passed": forged_legacy_retry["status"] == 409 and forged_legacy_retry["body"].get("code") == "legacy_approval_evidence_non_authorizing" and after_forged_legacy["body"].get("adapter_executions") == 0 and after_forged_legacy["body"].get("status") == "waiting_for_approval" and provider_effect_state(provider_before_publish) == provider_effect_state(provider_after_forged_legacy)},
        {"case": "receipt_resume_does_not_tick", "passed": receipt_resume_rejected["status"] == 409 and receipt_resume_rejected["body"].get("code") == "approval_receipt_resume_not_supported"},
        {"case": "missing_policy_bundle_fails_closed", "passed": missing_policy["status"] == 400 and missing_policy["body"].get("code") == "missing_policy_bundle"},
        {"case": "expired_policy_bundle_fails_closed", "passed": expired_policy_create["status"] == 403 and expired_policy_create["body"].get("code") == "expired_policy_bundle" and ttl_create["status"] == 200 and ttl_start["status"] == 200 and ttl_policy_artifacts.get("policy_bundle_id") == "policy_uc_e2e_s5_runtime_expiry" and ttl_policy_artifacts.get("action") == "artifact.publish_external" and bool(ttl_trace_ids.get("policy.expired"))},
        {"case": "revoked_policy_bundle_fails_closed", "passed": revoked_policy_create["status"] == 403 and revoked_policy_create["body"].get("code") == "revoked_policy_bundle"},
        {"case": "verifier_uncertainty_escalates_not_allow", "passed": uncertain_create["status"] == 200 and uncertainty["body"].get("status") in {"failed", "waiting_for_approval"} and bool(uncertainty_trace_ids.get("action.needs_intervention"))},
        {"case": "circuit_breaker_blocks_matching_action", "passed": cb_payload["status"] == 200 and breaker_payload_record.get("trace_event_id") == manager_breaker_trace_id and cb_sync["body"].get("accepted") is True and cb_submit["body"].get("status") == "Denied" and cb_denied_breaker_id == breaker_uuid},
        {"case": "clearing_circuit_breaker_requires_scope", "passed": clear["body"].get("status") == "cleared" and clear_wrong_scope["status"] == 403},
        {"case": "kill_switch_cancels_matching_run", "passed": kill["body"].get("propagation_acknowledged") is True and kill["body"].get("cancel_status") == 200 and kill["body"].get("target_derived_from_registry") is True and kill["body"].get("cancel_payload_schema") == "splendor.daemon.lifecycle_request.v1" and cancel["body"].get("status") == "cancelled"},
        {"case": "kill_switch_missing_ack_fails_closed", "passed": kill_missing_ack["body"].get("fail_closed") is True},
        {"case": "governance_plane_cannot_issue_broad_unknown_authority", "passed": broad_mutation["status"] == 404},
    ]
    required_positive = {
        "policy_published": published["status"] == 200 and bool(signed_policy) and published["body"].get("status") == "published",
        "policy_status_publicly_read": policy_status["status"] == 200,
        "internal_artifact_run_created": internal_create["status"] == 200,
        "run_created": create["status"] == 200,
        "internal_artifact_executed": internal.get("status") == "Executed" and internal_projection.get("operation_id") == "artifact-store/artifact.create_internal" and internal_projection.get("resource_id") == ARTIFACT_REF,
        "external_needs_approval": needs_approval.get("status") == "NeedsApproval",
        "adapter_not_called_before_approval": start["body"].get("status") == "waiting_for_approval" and start["body"].get("action_outcomes", [{}])[0].get("output") is None,
        "approval_granted": approval_request["status"] == 200 and approval_grant["body"].get("status") == "granted" and evidence.get("action_id") == approval_context["action_id"],
        "approved_action_executed_once": len(external_executions) == 1 and approved_retry["status"] == 200 and publish_provider_delta == 1 and publish_provider_receipt.get("action_id") == approval_context["action_id"] and publish_provider_receipt.get("operation_id") == "artifact-store/artifact.publish_external",
        "resident_receipt_revocation_acknowledged": revoke_validation["body"].get("accepted") is True and revoke_dispatch["body"].get("selected_instance_id") == CLOUD_INSTANCE_ID and resident_revocation_exact,
        "state_committed": bool(state_head["body"].get("state_node_id")),
        "audit_exported": audit_export["body"].get("exported") is True,
        "replay_inspect_only": replay["body"].get("mode") == "inspect_only" and provider_effect_state(provider_before_replay) == provider_effect_state(provider_after_replay),
    }
    failures = [name for name, ok in required_positive.items() if not ok]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    scenario = {
        "id": "UC-E2E-S5",
        "status": "passed" if not failures else "failed",
        "fr_coverage": ["FR-0.04-01", "FR-0.04-02", "FR-0.04-03", "FR-0.04-04", "FR-0.04-05", "FR-0.04-06", "FR-0.04-07", "FR-0.04-08", "FR-0.04-09", "FR-0.04-10"],
        "components": ["daemon", "central-manager", "governance", "approval", "policy-bundle", "circuit-breaker", "kill-switch", "gateway", "trace", "replay/audit", "artifact-adapter"],
        "positive_evidence": [key for key, ok in required_positive.items() if ok],
        "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True],
        "replay_evidence": ["replayRun public API returned inspect_only approval explanation and provider counters were unchanged"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "external_publish_replayed": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["public_daemon_and_manager_http_used", "gateway_required_before_artifact_publish", "approval_scoped_to_action", "governance_plane_no_direct_runtime_mutation", "replay_no_external_publish"],
        "run_ids": [INTERNAL_RUN_ID, RUN_ID, EXPIRE_RUN_ID, REVOKE_RUN_ID, DENY_RUN_ID, cb_run_id, KILL_RUN_ID, ttl_run_id, CANCEL_RUN_ID],
        "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid}),
        "state_node_ids": [internal_state_head["body"].get("state_node_id", ""), state_head["body"].get("state_node_id", "")],
        "state_hashes": [internal_state_head["body"].get("data_hash", ""), state_head["body"].get("data_hash", "")],
        "message_ids": [],
        "work_order_ids": [internal_envelope["work_order_id"], envelope["work_order_id"], expire_envelope["work_order_id"], revoke_envelope["work_order_id"], deny_envelope["work_order_id"], cb_envelope["work_order_id"], kill_envelope["work_order_id"], cancel_envelope["work_order_id"]],
        "approval_ids": [approval_context["approval_id"], expire_context["approval_id"], revoke_context["approval_id"], deny_context["approval_id"], expired_evidence["approval_id"]],
        "node_ids": [CLOUD_NODE_ID],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "negative_cases": negatives,
        "positive_checks": required_positive,
        "scenario_failures": failures,
        "private_v3_outputs": [internal_projection, publish_projection],
        "provider_evidence": [provider_before_replay, provider_after_replay],
        "artifact_paths": [],
    }
    artifacts = {
        "scenario-report.json": scenario,
        "approval-flow.json": {
            "request": revoke_request["body"],
            "grant": revoke_grant["body"],
            "revoke": approval_revoke["body"],
            "revoked": revoked_denial,
            "revoked_run": revoked["body"],
            "publication_request": approval_request["body"],
            "publication_grant": approval_grant["body"],
            "forged_legacy_retry": forged_legacy_retry,
            "receipt_resume_rejected": receipt_resume_rejected,
            "approved_exact_action_retry": approved_retry["body"],
            "denial": denial["body"],
            "expired": expired["body"],
            "active_run_expired_raw_rejection": active_expired_raw_evidence,
            "resident_receipt_revocation": {
                "work_order_admission": revoke_validation["body"],
                "placement": revoke_placement["body"],
                "dispatch": revoke_dispatch["body"],
                "dispatch_start": revoke_dispatch_start,
                "approval_policy": revoke_policy,
                "proposal": revoke_proposal["body"],
                "approval_id": revoke_context["approval_id"],
                "receipt_id": retained_revoke_receipt.get("receipt_id"),
                "receipt_audience": retained_revoke_receipt.get("audience"),
                "retained_receipt": retained_revoke_receipt,
                "acknowledgement": resident_revocation_ack,
                "exact_acknowledgement": resident_revocation_exact,
                "revoked_receipt_retry": revoked,
                "lifecycle": {
                    "before_manager_revoke": revoke_before_manager["body"],
                    "after_manager_revoke": revoke_after_manager["body"],
                    "after_denied_retry": revoke_after_retry["body"],
                    "unchanged_tick_and_state_head": revoke_lifecycle_unchanged,
                },
                "state": {
                    "before_manager_revoke": revoke_state_before_manager["body"],
                    "after_denied_retry": revoke_state_after_retry["body"],
                    "unchanged": revoke_state_unchanged,
                },
                "adapter_execution_counts": revoke_adapter_effects,
                "action_executed_trace_records": revoke_execution_traces,
                "resident_revocation_authentication": revocation_daemon_audits,
                "resident_direct_call_authentication": resident_security_events,
                "manager_approval_call_authentication": manager_approval_auth_events,
                "trace_event_ids": sorted({record.get("payload", {}).get("trace_event_id") for record in revoke_traces["body"].get("records", []) if record.get("payload", {}).get("trace_event_id")}),
            },
        },
        "policy-bundle-report.json": {"published": published["body"], "status": policy_status["body"], "revoked": revoked_policy["body"], "expired_policy_create": expired_policy_create, "runtime_expired_policy": {"published": ttl_policy["body"], "create": ttl_create, "start": ttl_start, "run_id": ttl_run_id, "action_id": ttl_action_id, "action_name": "artifact.publish_external", "reason_code": "policy_expired", "denial": ttl_policy_denial}, "revoked_policy_create": revoked_policy_create, "missing_policy_create": missing_policy},
        "circuit-breaker-report.json": {"created": breaker["body"], "manager_sync_payload": cb_payload["body"], "synced": cb_sync["body"], "blocked_action": cb_submit["body"], "cleared": clear["body"], "clear_wrong_scope": clear_wrong_scope},
        "kill-switch-report.json": {"activated": kill["body"], "separate_lifecycle_cancel": cancel, "missing_ack": kill_missing_ack["body"]},
        "internal-artifact-report.json": {"work_order_id": internal_envelope["work_order_id"], "run_id": INTERNAL_RUN_ID, "create": internal_create["body"], "start": internal_start["body"], "outcome": internal, "state_head": internal_state_head["body"]},
        "state-export.json": state_head["body"],
        "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "external_publish_replayed": False, "approval_lifecycles": [event.get("lifecycle") for event in replay["body"].get("approval_events", [])]},
        "action-provider-evidence.json": {"before_publish": provider_before_publish, "after_forged_legacy": provider_after_forged_legacy, "after_publish": provider_after_publish, "publish_call_delta": publish_provider_delta, "provider_receipt": publish_provider_receipt, "before_replay": provider_before_replay, "after_replay": provider_after_replay},
        "audit-report.json": {"manager": audit_export["body"], "resident_revocation_manager": revoke_audit_export["body"], "negative_cases": negatives, "event_ids": event_ids},
        "anti-drift-results.json": {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "governance_plane_direct_runtime_mutation": False, "broad_action_authority": False, "replay_side_effects_allowed_default": False},
        "stdout.log": "UC-E2E-S5 governance scenario completed through public daemon and manager HTTP APIs\n",
        "stderr.log": "",
    }
    for name, data in artifacts.items():
        path = artifact_dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
    write_jsonl(artifact_dir / "trace-export.jsonl", records)
    scenario["artifact_paths"].extend([str(artifact_dir / "api-traffic.ndjson"), str(artifact_dir / "trace-export.jsonl")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S5 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
