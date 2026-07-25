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
    EDGE_INSTANCE_FEATURES,
    EDGE_NODE_CAPABILITIES,
)
from acceptance_provider_evidence import (  # noqa: E402
    provider_effect_state,
    read_provider_evidence,
)
from acceptance_provider_output import project_private_v3_output  # noqa: E402
from acceptance_scenario_expectations import expectation_for  # noqa: E402
from resident_http import request_json_no_redirect  # noqa: E402

TENANT_ID = "11111111-1111-4111-8111-111111111111"
FLEET_ID = "00000000-0000-4000-8000-000000000104"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
HELPER_AGENT_ID = "33333333-3333-4333-8333-333333333336"
RUN_ID = "44444444-4444-4444-8444-444444444446"
APPROVAL_RUN_ID = "44444444-4444-4444-8444-444444444846"
APPROVAL_ACTION_ID = "55555555-5555-4555-8555-555555555646"
APPROVAL_POLICY_ID = "policy_uc_e2e_s6_physical_capture_approval"
HELPER_WORK_ORDER_ID = "wo_uc_e2e_s6_cloud_helper_proposal"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
EDGE_NODE_ID = "00000000-0000-4000-8000-000000000604"
OTHER_EDGE_NODE_ID = "00000000-0000-4000-8000-000000000605"
EDGE_INSTANCE_ID = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ID = "wo_uc_e2e_s6_physical_edge"
APPROVAL_WORK_ORDER_ID = "wo_uc_e2e_s6_physical_approval"
WORK_ORDER_KEY_IDS = {
    CLOUD_INSTANCE_ID: "work-order-acceptance-cloud",
    EDGE_INSTANCE_ID: "work-order-acceptance-edge",
}
PHYSICAL_PERMISSION = "physical.high_level"
ALLOWED_ACTIONS = ["read_battery", "read_sensor_summary", "inspect_zone", "move_to_waypoint", "capture_image", "return_to_base", "upload_trace_summary"]
CLOUD_MESSAGE_ID = "66666666-6666-4666-8666-666666666606"
CLOUD_CAUSAL_TRACE_ID = "55555555-5555-4555-8555-555555555651"
FORBIDDEN_ACTIONS = [
    "set" + "_motor" + "_pwm",
    "raw" + "_actuator" + "_write",
    "disable" + "_firmware" + "_safety",
    "bypass" + "_collision" + "_avoidance",
    "ignore" + "_emergency" + "_stop",
    "modify" + "_flight" + "_controller" + "_internals",
    "hard" + "_real" + "_time" + "_stabilization",
]


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in {"authorization", "secret", "token"}:
                redacted[key] = "[REDACTED]"
            elif key.lower() == "signature" and not isinstance(item, dict):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None, context: ssl.SSLContext | None = None) -> tuple[int, dict[str, Any]]:
    return request_json_no_redirect(
        method,
        base_url.rstrip("/") + path,
        body,
        headers,
        context,
        timeout=20,
    )


def sim_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    if method == "GET" and path == "/evidence" and body is None:
        return read_provider_evidence(base_url)
    status, data = request_json(method, base_url, path, body)
    if status != 200:
        raise SystemExit(f"device-sim request failed: {method} {path} status={status} body={data}")
    return data


def sim_total(counters: dict[str, Any]) -> int:
    return int(counters.get("requests_total", counters.get("total", 0)))


def sim_action_count(counters: dict[str, Any], action_name: str) -> int:
    return int(counters.get("by_action", {}).get(action_name, 0))


def splendorctl(root: Path) -> list[str]:
    for candidate in [Path("/usr/local/bin/splendorctl"), root / "target" / "debug" / "splendorctl"]:
        if candidate.exists():
            return [str(candidate)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def resident_auth(root: Path, auth_dir: Path, instance_id: str, scopes: list[str], *, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "token",
        "--auth-dir",
        str(auth_dir),
        "--tenant-id",
        tenant_id,
        "--instance-id",
        instance_id,
    ]
    for scope in scopes:
        command.extend(["--scope", scope])
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("resident caller token fixture failed")
    return json.loads(proc.stdout)


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s6_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s6_manager", "label": "UC-E2E-S6 manager"}, "client_principal_id": "client_uc_e2e_s6_manager", "label": "UC-E2E-S6 manager client"},
        "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "instances_heartbeat", "fleet_read", "fleet_dispatch", "work_orders_submit", "messages_send", "messages_read"],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


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
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("manager approval caller token fixture failed")
    return json.loads(proc.stdout)


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def credential_header(auth: dict[str, Any], mirror: dict[str, Any] | None = None) -> dict[str, str]:
    return {
        "authorization": f"Bearer {auth['token']}",
        "x-splendor-caller-credential": json.dumps(mirror or auth["credential"], sort_keys=True),
    }


def sec(credential: dict[str, Any]) -> dict[str, Any]:
    return {"credential": credential, "audit_attribution": audit(credential)}


def message_scope(credential: dict[str, Any], run_id: str, agent_id: str, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {**sec(credential), "tenant_id": tenant_id, "run_id": run_id, "agent_id": agent_id}


def node_registration(node_id: str, kind: str, target: str, locality: str, url: str, capabilities: list[str]) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": kind,
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {"schema": "splendor.capabilities.v1", "capabilities": capabilities, "constraints": {"placement_target": target, "data_locality": locality, "region": "eu-west", "resident_daemon_url": url, "runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime", "trust_level": "acceptance"}},
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime"}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str, supported_features: list[str]) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": supported_features, "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime"}}, "registered_at": utc(0)}


def work_order(expires: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": WORK_ORDER_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "objective": "UC-E2E-S6 drone_sim inspect_zone under offline safety constraints",
        "allowed_actions": ALLOWED_ACTIONS,
        "allowed_adapters": ["device-sim"],
        "allowed_permissions": [PHYSICAL_PERMISSION],
        "data_refs": ["zone:warehouse-a3", "privacy_zone:warehouse-a3-public"],
        "quotas": {"max_actions_per_tick": 32, "max_action_duration_ms": 30000},
        "placement": {"target": "edge_device", "data_locality": "device", "requires_gpu": False, "required_capabilities": [f"physical.action.{name}" for name in ALLOWED_ACTIONS]},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def helper_work_order(expires: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": HELPER_WORK_ORDER_ID,
        "tenant_id": TENANT_ID,
        "agent_id": HELPER_AGENT_ID,
        "run_id": RUN_ID,
        "objective": "Cloud helper may propose an inspection route but cannot authorize physical action",
        "allowed_actions": ["message.remote.proposal"],
        "allowed_adapters": ["remote-message"],
        "allowed_permissions": [f"message.remote.proposal:{AGENT_ID}"],
        "data_refs": ["zone:warehouse-a3"],
        "quotas": {"max_actions_per_tick": 1, "max_action_duration_ms": 30000},
        "placement": {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": ["message.remote.proposal"], "execution_mode": "cloud_helper"},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def approval_work_order(expires: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": APPROVAL_WORK_ORDER_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": APPROVAL_RUN_ID,
        "objective": "UC-E2E-S6 exact approval-gated capture on the resident edge target",
        "allowed_actions": ["capture_image"],
        "allowed_adapters": ["device-sim"],
        "allowed_permissions": [PHYSICAL_PERMISSION],
        "data_refs": ["zone:warehouse-a3", "privacy_zone:warehouse-a3-public"],
        "quotas": {"max_actions_per_tick": 4, "max_action_duration_ms": 30000},
        "placement": {
            "target": "edge_device",
            "data_locality": "device",
            "requires_gpu": False,
            "dedicated_instance": False,
            "required_capabilities": ["physical.action.capture_image"],
            "max_runtime_ms": 30000,
            "execution_mode": "live",
        },
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, auth_dir: Path, payload: dict[str, Any], instance_id: str) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    secret = (auth_dir / f"work-order-signing-{instance_id}.secret").read_text(encoding="ascii")
    command = splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", WORK_ORDER_KEY_IDS[instance_id], "--secret", secret]
    with commands.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(command[:-1] + ["[REDACTED]"]) + "\n")
    proc = subprocess.run(command, cwd=root, text=True, capture_output=True)
    with commands.open("a", encoding="utf-8") as fh:
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if proc.returncode != 0:
        raise SystemExit("work-order signing failed")
    return json.loads(proc.stdout)


def action(name: str, **params: Any) -> dict[str, Any]:
    postcondition = "sensor_read" if name in {"read_battery", "read_sensor_summary"} else "device_state_updated"
    return {"name": name, "params": params or {"physical_action": True}, "side_effect_class": {"Custom": "physical.high_level"}, "cost_estimate": None, "required_permissions": [PHYSICAL_PERMISSION], "preconditions": [], "postconditions": [postcondition]}


def quota() -> dict[str, int]:
    return {"actions": 1, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def create_run_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    work_order_id = envelope.get("work_order_id") or envelope.get("work_order", {}).get("work_order_id", WORK_ORDER_ID)
    return {
        "request_id": f"req-uc-e2e-s6-{work_order_id}-{RUN_ID}",
        "idempotency_key": f"idem-uc-e2e-s6-{work_order_id}-{RUN_ID}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "allowed_actions": ALLOWED_ACTIONS,
        "allowed_adapters": ["device-sim"],
        "allowed_permissions": [PHYSICAL_PERMISSION],
        "registered_actions": [{"name": name, "adapter": "device-sim", "required_permissions": [PHYSICAL_PERMISSION]} for name in ALLOWED_ACTIONS],
        "policy_actions": [],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "approval_policies": [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"scenario": "UC-E2E-S6", "run_id": RUN_ID},
        "snapshot_interval": 1,
    }


def approval_policy(expires_at: str) -> dict[str, Any]:
    return {
        "schema_version": "splendor.approval_policy.v1",
        "policy_id": APPROVAL_POLICY_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "action_name": "capture_image",
        "adapter": "device-sim",
        "required_permission": PHYSICAL_PERMISSION,
        "side_effect_class": {"Custom": "physical.high_level"},
        "risk_level": "physical",
        "reason": "physical capture requires exact resident approval",
        "expires_at": expires_at,
    }


def safety(**overrides: Any) -> dict[str, Any]:
    base = {"allowed_zone_refs": ["zone:warehouse-a3"], "zone_ref": "zone:warehouse-a3", "altitude_m": 12.0, "max_altitude_m": 30.0, "battery_percent": 0.82, "privacy_clear": True, "human_proximity_clear": True, "emergency_stop_clear": True, "offline": False, "policy_cache_expired": False, "high_risk": False, "cloud_helper_direct_authority": False, "cloud_helper_proposal_id": None}
    base.update(overrides)
    return base


def physical_payload(
    name: str, *, action_id: str | None = None, **safety_overrides: Any
) -> dict[str, Any]:
    action_params = {"physical_action": True}
    for key in ["cloud_helper_proposal_id", "cloud_helper_message_id"]:
        if safety_overrides.get(key):
            action_params[key] = safety_overrides[key]
    payload = {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "causal_trace_id": CLOUD_CAUSAL_TRACE_ID, "action": action(name, **action_params), "adapter": "device-sim", "quota_usage": quota(), "satisfied_preconditions": [], "safety_context": safety(**safety_overrides)}
    if action_id is not None:
        payload["action_id"] = action_id
    return payload


def approval_physical_payload(causal_trace_id: str, requested_at: str) -> dict[str, Any]:
    return {
        "action_id": APPROVAL_ACTION_ID,
        "run_id": APPROVAL_RUN_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "causal_trace_id": causal_trace_id,
        "action": action("capture_image", physical_action=True),
        "adapter": "device-sim",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "requested_at": requested_at,
        "approval_evidence": None,
        "authority_obligation_receipts": [],
        "safety_context": safety(),
        "operator_intervention_evidence": None,
    }


def approval_request_payload(challenge: dict[str, Any], reason: str) -> dict[str, Any]:
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


def approval_action_trace_ids(records: list[dict[str, Any]]) -> list[str]:
    return [
        str(record.get("payload", {}).get("trace_event_id"))
        for record in records
        if record.get("payload", {}).get("identity", {}).get("action_id") == APPROVAL_ACTION_ID
        and record.get("payload", {}).get("trace_event_id")
    ]


def typed_cloud_helper_message(causal_parent: str) -> dict[str, Any]:
    return {
        "message_id": CLOUD_MESSAGE_ID,
        "source_agent_id": HELPER_AGENT_ID,
        "target_agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "schema": "splendor.message.proposal_request.v1",
        "payload": {"task": "propose inspection route for zone warehouse-a3", "proposal_id": "route-proposal-s6-a3", "input_ref": "zone:warehouse-a3", "actions": ["inspect_zone", "move_to_waypoint", "capture_image"], "direct_actuator_authority": False, "waypoints": [{"waypoint_ref": "wp-a3-1", "zone_ref": "zone:warehouse-a3"}]},
        "causal_parent": causal_parent,
        "requires_response": False,
        "created_at": utc(0),
    }


def trace_event_ids(records: list[dict[str, Any]], extra: dict[str, list[str]]) -> dict[str, list[str]]:
    result = {key: list(value) for key, value in extra.items()}
    mapping = {"ActionExecuted": "action.executed", "ActionDenied": "action.denied", "ActionNeedsApproval": "action.needs_approval", "ActionNeedsIntervention": "action.needs_intervention", "ApprovalRequested": "approval.requested", "ApprovalGranted": "approval.granted", "RunPaused": "run.paused", "RunResumed": "run.resumed", "DaemonAudit": "daemon.audit", "StateCommitted": "state.committed", "OutcomeRecorded": "outcome.recorded"}
    for rec in records:
        payload = rec.get("payload", {})
        kind = payload.get("kind", {})
        key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
        event = kind.get("DaemonAudit", {}).get("endpoint", "daemon.audit") if key == "DaemonAudit" else mapping.get(key, key)
        result.setdefault(event, []).append(payload.get("trace_event_id", ""))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--edge-url", default="https://resident-edge-node:8093")
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument(
        "--action-provider-url",
        dest="device_sim_url",
        metavar="ACTION_PROVIDER_URL",
        default="http://acceptance-action-provider:8086",
    )
    parser.add_argument("--resident-auth-dir", default=os.environ.get("SPLENDOR_RESIDENT_AUTH_DIR", "/run/splendor-auth"))
    parser.add_argument("--resident-ca-file", default=os.environ.get("SPLENDOR_RESIDENT_CA_FILE", "/run/splendor-auth/resident-root-ca.pem"))
    args = parser.parse_args()
    if not args.edge_url.lower().startswith("https://"):
        raise SystemExit("UC-E2E-S6 resident edge URL must use HTTPS")
    root = Path(args.root)
    auth_dir = Path(args.resident_auth_dir)
    resident_ssl = ssl.create_default_context(cafile=args.resident_ca_file)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S6"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []
    manager_approval_auth_events: list[dict[str, Any]] = []
    used_manager_approval_credentials: set[str] = set()

    def call(operation: str, method: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None, base_url: str | None = None, *, manager_approval_call_id: str | None = None) -> dict[str, Any]:
        base_url = base_url or args.edge_url
        context = resident_ssl if base_url.lower().startswith("https://") else None
        status, data = request_json(method, base_url, path, body, headers, context)
        api_rows.append({"operation_id": operation, "method": method, "url": base_url.rstrip("/") + path, "status": status, "request": redact_sensitive(body), "response": redact_sensitive(data), "manager_approval_call_id": manager_approval_call_id})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    def resident_call(operation: str, method: str, path: str, scope: str, body: dict[str, Any] | None = None, *, auth: dict[str, Any] | None = None, mirror: dict[str, Any] | None = None) -> dict[str, Any]:
        auth = auth or resident_auth(root, auth_dir, EDGE_INSTANCE_ID, [scope])
        credential = mirror or auth["credential"]
        secured_body = None if body is None else {**body, "credential": credential, "audit_attribution": audit(credential)}
        return call(operation, method, path, secured_body, credential_header(auth, credential))

    def manager_approval_call(operation: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        auth = manager_approval_auth(root, auth_dir)
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_manager_approval_credentials:
            raise SystemExit("manager approval caller fixture reused a bearer JTI")
        used_manager_approval_credentials.add(credential_id)
        if credential.get("scopes") != ["approvals_manage"] or credential.get("binding") != {"fleet": {"fleet_id": FLEET_ID}} or credential.get("audience") != {"central_manager": {"manager_id": "central-manager"}}:
            raise SystemExit("manager approval caller fixture returned an invalid projection")
        secured_body = {**body, "credential": credential, "audit_attribution": audit(credential)}
        call_id = f"s6-manager-approval-{len(manager_approval_auth_events) + 1:04d}"
        result = call(operation, "POST", path, secured_body, {"authorization": f"Bearer {auth['token']}"}, args.manager_url, manager_approval_call_id=call_id)
        manager_approval_auth_events.append({
            "call_id": call_id,
            "operation_id": operation,
            "scope": "approvals_manage",
            "credential_id": credential_id,
            "fleet_id": credential["binding"]["fleet"]["fleet_id"],
            "target_manager_id": "central-manager",
            "audience_manager_id": credential["audience"]["central_manager"]["manager_id"],
            "header_presence": {"authorization": True},
            "body_mirror_status": "matched",
            "result_status": result["status"],
            "trace_event_ids": [result["body"]["trace_event_id"]] if result.get("body", {}).get("trace_event_id") else [],
            "raw_bearer_recorded": False,
            "raw_signature_recorded": False,
        })
        return result

    def require_status(operation: str, response: dict[str, Any], expected: set[int] | int = 200) -> None:
        expected_statuses = {expected} if isinstance(expected, int) else expected
        if response.get("status") not in expected_statuses:
            raise SystemExit(f"{operation} returned {response.get('status')}, expected {sorted(expected_statuses)}: {json.dumps(redact_sensitive(response.get('body')), sort_keys=True)}")

    for _ in range(40):
        if resident_call("getHealth", "GET", "/health", "health_read")["status"] == 200:
            break
        time.sleep(0.25)
    for _ in range(40):
        if call("managerHealth", "GET", "/health", base_url=args.manager_url)["status"] == 200:
            break
        time.sleep(0.25)

    profile = {"node_id": EDGE_NODE_ID, "tenant_id": TENANT_ID, "device_kind": "drone_sim", "capabilities": ["camera.rgb", "battery", "geofence", "privacy_zone"] + [f"physical.action.{name}" for name in ALLOWED_ACTIONS], "allowed_physical_actions": ALLOWED_ACTIONS, "forbidden_action_classes": FORBIDDEN_ACTIONS, "safety_constraints": {"max_altitude_m": 30, "allowed_zones": ["zone:warehouse-a3"], "privacy_zones": ["privacy_zone:warehouse-a3-public"], "min_battery_percent": 0.25}, "runtime_mode": "resident", "safety_status": {"battery_percent": 0.82, "emergency_stop": "clear", "collision_risk": "low", "current_zone": "zone:warehouse-a3", "altitude_m": 10, "human_proximity": "clear", "privacy": "clear", "offline": False, "cloud_helper_direct_authority": False}, "policy_cache": {"policy_id": "policy_uc_e2e_s6_safety", "loaded": True, "ttl_seconds": 3600, "expires_at": utc(60), "expired": False}, "trace_buffer": {"enabled": True, "buffered_records": 0, "integrity": "hash_chain"}, "registered_at": utc(0)}
    register = resident_call("registerDeviceProfile", "POST", "/devices/profiles", "device_register", {"profile": profile})
    other_profile = json.loads(json.dumps(profile))
    other_profile["node_id"] = OTHER_EDGE_NODE_ID
    other_device_register = resident_call("registerOtherDeviceProfile", "POST", "/devices/profiles", "device_register", {"profile": other_profile})
    status = resident_call("getDeviceStatus", "GET", f"/devices/{EDGE_NODE_ID}/status", "device_read")
    cache = resident_call("getPolicyCacheStatus", "GET", f"/devices/{EDGE_NODE_ID}/policy-cache", "device_read")
    missing_credential_status = call("getDeviceStatusMissingCredential", "GET", f"/devices/{EDGE_NODE_ID}/status")
    wrong_bearer_audience_status = resident_call("getDeviceStatusWrongBearerAudience", "GET", f"/devices/{EDGE_NODE_ID}/status", "device_read", auth=resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["device_read"]))
    wrong_audience_status = resident_call("getDeviceStatusWrongAudience", "GET", f"/devices/{EDGE_NODE_ID}/status", "device_read", auth=resident_auth(root, auth_dir, EDGE_INSTANCE_ID, ["device_read"]), mirror=resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["device_read"])["credential"])
    wrong_tenant_status = resident_call("getDeviceStatusWrongTenant", "GET", f"/devices/{EDGE_NODE_ID}/status", "device_read", auth=resident_auth(root, auth_dir, EDGE_INSTANCE_ID, ["device_read"], tenant_id="11111111-1111-4111-8111-999999999999"))

    envelope = sign_work_order(root, artifact_dir, commands, auth_dir, work_order(), EDGE_INSTANCE_ID)
    create = resident_call("createRun", "POST", "/runs", "runs_create", create_run_payload(envelope))
    start = resident_call("startRun", "POST", f"/runs/{RUN_ID}/start", "runs_start", {"work_order": None, "reason": "uc_e2e_s6_initial_state_commit", "approval_evidence": None})
    state_head = resident_call("getStateHead", "GET", f"/runs/{RUN_ID}/state-head", "state_read")
    initial_traces = resident_call("exportTracesInitial", "POST", f"/runs/{RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    initial_records = initial_traces["body"].get("records", [])
    causal_parent = next((row.get("payload", {}).get("trace_event_id") for row in reversed(initial_records) if row.get("payload", {}).get("trace_event_id")), CLOUD_CAUSAL_TRACE_ID)
    cloud_message = typed_cloud_helper_message(causal_parent)
    manager_cred = manager_credential()
    manager_nodes = [
        node_registration(CLOUD_NODE_ID, "cloud.worker", "resident_cloud_pool", "cloud", "https://resident-cloud-node:8091", list(CLOUD_NODE_CAPABILITIES)),
        node_registration(EDGE_NODE_ID, "edge.device", "edge_device", "device", args.edge_url, list(EDGE_NODE_CAPABILITIES)),
    ]
    for node in manager_nodes:
        registration = call("registerNode", "POST", "/fleet/nodes", {**sec(manager_cred), "registration": node}, base_url=args.manager_url)
        require_status(f"registerNode:{node['node_id']}", registration)
        heartbeat = call("heartbeatNode", "POST", f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(manager_cred), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}}, base_url=args.manager_url)
        require_status(f"heartbeatNode:{node['node_id']}", heartbeat)
        if heartbeat["body"].get("accepted") is not True:
            raise SystemExit(f"node heartbeat was not accepted for {node['node_id']}")
    instances = [
        instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID, list(CLOUD_INSTANCE_FEATURES)),
        instance_registration(EDGE_NODE_ID, EDGE_INSTANCE_ID, list(EDGE_INSTANCE_FEATURES)),
    ]
    for inst in instances:
        registration = call("registerInstance", "POST", "/fleet/instances", {**sec(manager_cred), "registration": inst}, base_url=args.manager_url)
        require_status(f"registerInstance:{inst['instance_id']}", registration)
        heartbeat = call("heartbeatInstance", "POST", f"/fleet/instances/{inst['instance_id']}/heartbeat", {**sec(manager_cred), "heartbeat": {"node_id": inst["node_id"], "instance_id": inst["instance_id"], "health": inst["health"], "recorded_at": utc(0)}}, base_url=args.manager_url)
        require_status(f"heartbeatInstance:{inst['instance_id']}", heartbeat)
        if heartbeat["body"].get("accepted") is not True:
            raise SystemExit(f"instance heartbeat was not accepted for {inst['instance_id']}")
    edge_capability_document = manager_nodes[1]["capability_document"]
    edge_capability_advertisement = call("advertiseCapabilities", "POST", f"/fleet/nodes/{EDGE_NODE_ID}/capabilities", {**sec(manager_cred), "capability_document": edge_capability_document}, base_url=args.manager_url)
    require_status("advertise edge capabilities", edge_capability_advertisement)
    helper_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, helper_work_order(), CLOUD_INSTANCE_ID)
    helper_work_order_submit = call("submitWorkOrder", "POST", "/work-orders", {**sec(manager_cred), "work_order": helper_envelope, "expected_audience": "central-manager"}, base_url=args.manager_url)
    message_envelope = {"message": cloud_message, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    cloud_message_delivery = call("sendMessage", "POST", "/messages", {**sec(manager_cred), "work_order_id": HELPER_WORK_ORDER_ID, "message_envelope": message_envelope, "source_instance_id": CLOUD_INSTANCE_ID, "target_instance_id": EDGE_INSTANCE_ID, "idempotency_key": "s6-cloud-helper-proposal", "simulate_failure": None}, base_url=args.manager_url)
    cloud_message_received = call("getMessage", "POST", f"/messages/{CLOUD_MESSAGE_ID}/read", message_scope(manager_cred, RUN_ID, AGENT_ID), base_url=args.manager_url)
    manager_audit = call("managerAudit", "POST", "/fleet/audit/read", sec(manager_cred), base_url=args.manager_url)

    simulator_evidence: list[dict[str, Any]] = []

    approval_work_order_payload = approval_work_order()
    approval_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, approval_work_order_payload, EDGE_INSTANCE_ID)
    approval_policy_narrowing = approval_policy(approval_work_order_payload["expires_at"])
    approval_work_order_submit = call("submitWorkOrder", "POST", "/work-orders", {**sec(manager_cred), "work_order": approval_envelope, "expected_audience": "central-manager", "approval_policies": [approval_policy_narrowing]}, base_url=args.manager_url)
    require_status("submitPhysicalApprovalWorkOrder", approval_work_order_submit)
    approval_placement_request = {
        "target": "edge_device",
        "required_capabilities": ["physical.action.capture_image"],
        "data_locality": "device",
        "dedicated_instance": False,
        "required_runtime_version": None,
        "max_runtime_ms": 30000,
        "execution_mode": "live",
    }
    approval_placement = call("evaluatePlacement", "POST", "/fleet/placement/evaluate", {**sec(manager_cred), "work_order_id": APPROVAL_WORK_ORDER_ID, "request": approval_placement_request}, base_url=args.manager_url)
    require_status("evaluatePhysicalApprovalPlacement", approval_placement)
    if approval_placement["body"].get("status") != "selected" or approval_placement["body"].get("candidate_id") != EDGE_NODE_ID:
        raise SystemExit(f"physical approval placement did not select the edge node: {json.dumps(approval_placement['body'], sort_keys=True)}")
    approval_dispatch = call("dispatchWorkOrder", "POST", f"/work-orders/{APPROVAL_WORK_ORDER_ID}/dispatch", {**sec(manager_cred), "target_node_id": EDGE_NODE_ID}, base_url=args.manager_url)
    require_status("dispatchPhysicalApprovalWorkOrder", approval_dispatch)
    approval_initial_traces = resident_call("exportTraces", "POST", f"/runs/{APPROVAL_RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    approval_initial_records = approval_initial_traces["body"].get("records", [])
    approval_causal_trace_id = next((row.get("payload", {}).get("trace_event_id") for row in reversed(approval_initial_records) if row.get("payload", {}).get("trace_event_id")), CLOUD_CAUSAL_TRACE_ID)
    approval_requested_at = utc(0)
    approval_action_request = approval_physical_payload(approval_causal_trace_id, approval_requested_at)

    sim_before_coordinate_injection = sim_json("GET", args.device_sim_url, "/evidence")
    coordinate_injection_payload = json.loads(json.dumps(approval_action_request))
    coordinate_injection_payload["physical_action_resource_coordinate"] = {"resource_kind": "physical_node", "node_id": OTHER_EDGE_NODE_ID}
    coordinate_injection = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", coordinate_injection_payload)
    sim_after_coordinate_injection = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "physical_coordinate_field_injection_rejected", "action_name": "capture_image", "status": coordinate_injection.get("status"), "counter_before": sim_before_coordinate_injection, "counter_after": sim_after_coordinate_injection, "total_delta": sim_total(sim_after_coordinate_injection) - sim_total(sim_before_coordinate_injection), "action_delta": sim_action_count(sim_after_coordinate_injection, "capture_image") - sim_action_count(sim_before_coordinate_injection, "capture_image"), "expected_sim_delta": 0})

    sim_before_unknown_authority = sim_json("GET", args.device_sim_url, "/evidence")
    unknown_authority_payload = json.loads(json.dumps(approval_action_request))
    unknown_authority_payload["authority_override"] = {"node_id": OTHER_EDGE_NODE_ID, "allowed": True}
    unknown_authority = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", unknown_authority_payload)
    sim_after_unknown_authority = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "physical_unknown_authority_field_rejected", "action_name": "capture_image", "status": unknown_authority.get("status"), "counter_before": sim_before_unknown_authority, "counter_after": sim_after_unknown_authority, "total_delta": sim_total(sim_after_unknown_authority) - sim_total(sim_before_unknown_authority), "action_delta": sim_action_count(sim_after_unknown_authority, "capture_image") - sim_action_count(sim_before_unknown_authority, "capture_image"), "expected_sim_delta": 0})

    sim_before_reserved_node = sim_json("GET", args.device_sim_url, "/evidence")
    reserved_node_payload = physical_payload(
        "capture_image",
        action_id="55555555-5555-4555-8555-555555556699",
    )
    reserved_node_payload["action"]["params"]["node_id"] = OTHER_EDGE_NODE_ID
    reserved_node_injection = resident_call(
        "submitPhysicalActionReservedNodeParam",
        "POST",
        f"/devices/{EDGE_NODE_ID}/actions",
        "actions_submit",
        reserved_node_payload,
    )
    sim_after_reserved_node = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "physical_reserved_node_param_rejected", "action_name": "capture_image", "status": reserved_node_injection.get("body", {}).get("status"), "counter_before": sim_before_reserved_node, "counter_after": sim_after_reserved_node, "total_delta": sim_total(sim_after_reserved_node) - sim_total(sim_before_reserved_node), "action_delta": sim_action_count(sim_after_reserved_node, "capture_image") - sim_action_count(sim_before_reserved_node, "capture_image"), "expected_sim_delta": 0})

    sim_before_challenge = sim_json("GET", args.device_sim_url, "/evidence")
    approval_required = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", approval_action_request)
    require_status("submitPhysicalActionNeedsApproval", approval_required)
    sim_after_challenge = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "physical_approval_challenge_no_effect", "action_name": "capture_image", "status": approval_required.get("body", {}).get("status"), "counter_before": sim_before_challenge, "counter_after": sim_after_challenge, "total_delta": sim_total(sim_after_challenge) - sim_total(sim_before_challenge), "action_delta": sim_action_count(sim_after_challenge, "capture_image") - sim_action_count(sim_before_challenge, "capture_image"), "expected_sim_delta": 0})
    approval_challenge = approval_required["body"].get("approval_challenge")
    if not isinstance(approval_challenge, dict):
        raise SystemExit("physical NeedsApproval response omitted the exact approval challenge")
    approval_waiting_before_wrong_node = resident_call("inspectRun", "GET", f"/runs/{APPROVAL_RUN_ID}", "runs_read")
    approval_traces_before_wrong_node = resident_call("exportTraces", "POST", f"/runs/{APPROVAL_RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})

    approval_manager_request = manager_approval_call("requestApproval", "/approvals", approval_request_payload(approval_challenge, "S6 exact physical capture approval"))
    require_status("requestPhysicalApproval", approval_manager_request)
    approval_grant = manager_approval_call("grantApproval", f"/approvals/{approval_challenge['approval_id']}/grant", {"reason": "approved_for_s6_exact_physical_target"})
    require_status("grantPhysicalApproval", approval_grant)
    authority_receipt = approval_grant["body"].get("authority_obligation_receipt")
    if not isinstance(authority_receipt, dict):
        raise SystemExit("manager grant did not issue a trusted physical approval receipt")
    expected_receipt_audience = f"splendor.daemon.approval_receipt.v2:instance:{EDGE_INSTANCE_ID}:run:{APPROVAL_RUN_ID}"
    receipt_retry_request = json.loads(json.dumps(approval_action_request))
    receipt_retry_request["authority_obligation_receipts"] = [authority_receipt]
    receipt_retry_request["causal_trace_id"] = approval_grant["body"].get("trace_event_id") or approval_causal_trace_id

    sim_before_wrong_node = sim_json("GET", args.device_sim_url, "/evidence")
    wrong_node_receipt_retry = resident_call("submitPhysicalAction", "POST", f"/devices/{OTHER_EDGE_NODE_ID}/actions", "actions_submit", receipt_retry_request)
    sim_after_wrong_node = sim_json("GET", args.device_sim_url, "/evidence")
    approval_waiting_after_wrong_node = resident_call("inspectRun", "GET", f"/runs/{APPROVAL_RUN_ID}", "runs_read")
    approval_traces_after_wrong_node = resident_call("exportTraces", "POST", f"/runs/{APPROVAL_RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    simulator_evidence.append({"label": "physical_approval_wrong_node_preclaim_rejected", "action_name": "capture_image", "status": wrong_node_receipt_retry.get("status"), "reason_code": wrong_node_receipt_retry.get("body", {}).get("code"), "counter_before": sim_before_wrong_node, "counter_after": sim_after_wrong_node, "total_delta": sim_total(sim_after_wrong_node) - sim_total(sim_before_wrong_node), "action_delta": sim_action_count(sim_after_wrong_node, "capture_image") - sim_action_count(sim_before_wrong_node, "capture_image"), "expected_sim_delta": 0})

    sim_before_exact_node = sim_json("GET", args.device_sim_url, "/evidence")
    exact_node_receipt_retry = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", receipt_retry_request)
    require_status("submitPhysicalApprovalReceiptExactNode", exact_node_receipt_retry)
    sim_after_exact_node = sim_json("GET", args.device_sim_url, "/evidence")
    approval_after_exact_node = resident_call("inspectRun", "GET", f"/runs/{APPROVAL_RUN_ID}", "runs_read")
    simulator_evidence.append({"label": "physical_approval_exact_node_executed", "action_name": "capture_image", "status": exact_node_receipt_retry.get("body", {}).get("status"), "counter_before": sim_before_exact_node, "counter_after": sim_after_exact_node, "total_delta": sim_total(sim_after_exact_node) - sim_total(sim_before_exact_node), "action_delta": sim_action_count(sim_after_exact_node, "capture_image") - sim_action_count(sim_before_exact_node, "capture_image"), "expected_sim_delta": 1})

    sim_before_receipt_replay = sim_json("GET", args.device_sim_url, "/evidence")
    receipt_replay = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", receipt_retry_request)
    require_status("replayPhysicalApprovalReceipt", receipt_replay)
    sim_after_receipt_replay = sim_json("GET", args.device_sim_url, "/evidence")
    approval_after_receipt_replay = resident_call("inspectRun", "GET", f"/runs/{APPROVAL_RUN_ID}", "runs_read")
    simulator_evidence.append({"label": "physical_approval_receipt_replay_denied", "action_name": "capture_image", "status": receipt_replay.get("body", {}).get("status"), "reason_codes": receipt_replay.get("body", {}).get("verification", {}).get("reasons", []), "counter_before": sim_before_receipt_replay, "counter_after": sim_after_receipt_replay, "total_delta": sim_total(sim_after_receipt_replay) - sim_total(sim_before_receipt_replay), "action_delta": sim_action_count(sim_after_receipt_replay, "capture_image") - sim_action_count(sim_before_receipt_replay, "capture_image"), "expected_sim_delta": 0})
    approval_final_traces = resident_call("exportTraces", "POST", f"/runs/{APPROVAL_RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    sim_before_approval_replay = sim_json("GET", args.device_sim_url, "/evidence")
    approval_replay = resident_call("replayRun", "POST", f"/runs/{APPROVAL_RUN_ID}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": False})
    sim_after_approval_replay = sim_json("GET", args.device_sim_url, "/evidence")

    def physical_call_with_counters(label: str, name: str, expected_sim_delta: int, *, expectation_id: str | None = None, **safety_overrides: Any) -> dict[str, Any]:
        before = sim_json("GET", args.device_sim_url, "/evidence")
        expected_action_id = (
            expectation_for("UC-E2E-S6", expectation_id)["action_id"]
            if expectation_id is not None
            else None
        )
        response = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload(name, action_id=expected_action_id, **safety_overrides))
        after = sim_json("GET", args.device_sim_url, "/evidence")
        simulator_evidence.append({"label": label, "action_name": name, "status": response.get("body", {}).get("status"), "reason_codes": response.get("body", {}).get("verification", {}).get("reasons", []), "counter_before": before, "counter_after": after, "total_delta": sim_total(after) - sim_total(before), "action_delta": sim_action_count(after, name) - sim_action_count(before, name), "expected_sim_delta": expected_sim_delta})
        return response

    before_warmup = sim_json("GET", args.device_sim_url, "/evidence")
    read_battery = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload("read_battery", action_id=expectation_for("UC-E2E-S6", "read_battery")["action_id"]))
    after_warmup = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "read_battery_policy_warmup", "action_name": "read_battery", "status": read_battery.get("body", {}).get("status"), "counter_before": before_warmup, "counter_after": after_warmup, "total_delta": sim_total(after_warmup) - sim_total(before_warmup), "action_delta": sim_action_count(after_warmup, "read_battery") - sim_action_count(before_warmup, "read_battery"), "expected_sim_delta": 1})
    inspect_zone = physical_call_with_counters("inspect_zone_from_typed_cloud_proposal", "inspect_zone", 1, expectation_id="inspect_zone", cloud_helper_proposal_id=cloud_message["payload"]["proposal_id"], cloud_helper_message_id=CLOUD_MESSAGE_ID)
    waypoint = physical_call_with_counters("move_to_waypoint_from_typed_cloud_proposal", "move_to_waypoint", 1, expectation_id="move_to_waypoint", cloud_helper_proposal_id=cloud_message["payload"]["proposal_id"], cloud_helper_message_id=CLOUD_MESSAGE_ID)
    capture = physical_call_with_counters("capture_image", "capture_image", 1, expectation_id="capture_image")
    offline_sensor = physical_call_with_counters("read_sensor_summary_offline", "read_sensor_summary", 1, expectation_id="read_sensor_summary", offline=True)
    offline_rtb = physical_call_with_counters("return_to_base_low_battery_safe", "return_to_base", 1, expectation_id="return_to_base", offline=True, battery_percent=0.18)
    upload_summary = physical_call_with_counters("upload_trace_summary", "upload_trace_summary", 1, expectation_id="upload_trace_summary")

    ambiguous = physical_call_with_counters("ambiguous_privacy_denied_until_operator", "capture_image", 0, offline=True, high_risk=True, privacy_clear=False)
    intervention_expires_at = utc(30)
    intervention_request = resident_call("requestOperatorIntervention", "POST", "/operator/interventions", "operator_intervene", {"intervention_id": "intervention_uc_e2e_s6_capture", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "node_id": EDGE_NODE_ID, "action_name": "capture_image", "reason": "ambiguous privacy state while offline", "expires_at": intervention_expires_at})
    intervention_grant = resident_call("grantOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/grant", "operator_intervene", {"reason": "local operator verified privacy clear", "expires_at": intervention_expires_at})
    granted_payload = physical_payload("capture_image", action_id=expectation_for("UC-E2E-S6", "operator_capture")["action_id"], offline=True, high_risk=True)
    granted_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    before_granted = sim_json("GET", args.device_sim_url, "/evidence")
    intervention_capture = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", granted_payload)
    after_granted = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_granted_capture", "action_name": "capture_image", "status": intervention_capture.get("body", {}).get("status"), "counter_before": before_granted, "counter_after": after_granted, "total_delta": sim_total(after_granted) - sim_total(before_granted), "action_delta": sim_action_count(after_granted, "capture_image") - sim_action_count(before_granted, "capture_image"), "expected_sim_delta": 1})
    private_v3_outputs = [
        project_private_v3_output(
            response["body"],
            expectation=expectation_for("UC-E2E-S6", expectation_id),
        )
        for expectation_id, response in (
            ("approved_capture", exact_node_receipt_retry),
            ("read_battery", read_battery),
            ("inspect_zone", inspect_zone),
            ("move_to_waypoint", waypoint),
            ("capture_image", capture),
            ("read_sensor_summary", offline_sensor),
            ("return_to_base", offline_rtb),
            ("upload_trace_summary", upload_summary),
            ("operator_capture", intervention_capture),
        )
    ]

    extended_evidence = dict(intervention_grant["body"].get("evidence", {}))
    extended_evidence["expires_at"] = utc(60)
    extended_payload = physical_payload("capture_image")
    extended_payload["operator_intervention_evidence"] = extended_evidence
    before_extended = sim_json("GET", args.device_sim_url, "/evidence")
    extended_intervention = resident_call("submitPhysicalActionExtendedIntervention", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", extended_payload)
    after_extended = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_extended_expiry_denied", "action_name": "capture_image", "status": extended_intervention.get("status"), "counter_before": before_extended, "counter_after": after_extended, "total_delta": sim_total(after_extended) - sim_total(before_extended), "expected_sim_delta": 0})

    reused_payload = physical_payload("capture_image")
    reused_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    before_reuse = sim_json("GET", args.device_sim_url, "/evidence")
    reused_intervention = resident_call("submitPhysicalActionReusedIntervention", "POST", f"/devices/{OTHER_EDGE_NODE_ID}/actions", "actions_submit", reused_payload)
    after_reuse = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_cross_device_reuse_denied", "action_name": "capture_image", "status": reused_intervention.get("status"), "counter_before": before_reuse, "counter_after": after_reuse, "total_delta": sim_total(after_reuse) - sim_total(before_reuse), "expected_sim_delta": 0})
    intervention_deny = resident_call("denyOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/deny", "operator_intervene", {"reason": "negative denial branch", "expires_at": utc(30)})

    forbidden = [resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload(name)) for name in FORBIDDEN_ACTIONS]
    geofence = physical_call_with_counters("geofence_breach_denied", "move_to_waypoint", 0, zone_ref="zone:outside-geofence")
    low_battery = physical_call_with_counters("low_battery_needs_intervention", "move_to_waypoint", 0, battery_percent=0.12)
    expired_policy = physical_call_with_counters("expired_policy_cache_denied", "capture_image", 0, offline=True, high_risk=True, policy_cache_expired=True)
    cloud_direct = physical_call_with_counters("cloud_helper_direct_authority_denied", "move_to_waypoint", 0, cloud_helper_proposal_id="bad-direct", cloud_helper_message_id=CLOUD_MESSAGE_ID, cloud_helper_direct_authority=True)
    wrong_scope_evidence = dict(intervention_grant["body"].get("evidence", {}))
    wrong_scope_evidence["action_name"] = "move_to_waypoint"
    wrong_scope_payload = physical_payload("capture_image")
    wrong_scope_payload["operator_intervention_evidence"] = wrong_scope_evidence
    before_wrong_scope = sim_json("GET", args.device_sim_url, "/evidence")
    wrong_scope = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", wrong_scope_payload)
    after_wrong_scope = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_wrong_scope_denied", "action_name": "capture_image", "status": wrong_scope.get("status"), "counter_before": before_wrong_scope, "counter_after": after_wrong_scope, "total_delta": sim_total(after_wrong_scope) - sim_total(before_wrong_scope), "expected_sim_delta": 0})
    expired_evidence = dict(intervention_grant["body"].get("evidence", {}))
    expired_evidence["expires_at"] = utc(-1)
    expired_evidence_payload = physical_payload("capture_image")
    expired_evidence_payload["operator_intervention_evidence"] = expired_evidence
    before_expired_approval = sim_json("GET", args.device_sim_url, "/evidence")
    expired_approval = resident_call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", expired_evidence_payload)
    after_expired_approval = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_expired_evidence_denied", "action_name": "capture_image", "status": expired_approval.get("status"), "counter_before": before_expired_approval, "counter_after": after_expired_approval, "total_delta": sim_total(after_expired_approval) - sim_total(before_expired_approval), "expected_sim_delta": 0})
    missing_credential_action = call("submitPhysicalActionMissingCredential", "POST", f"/devices/{EDGE_NODE_ID}/actions", {**physical_payload("inspect_zone"), "credential": None, "audit_attribution": None})
    wrong_bearer_audience_action = resident_call("submitPhysicalActionWrongBearerAudience", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload("inspect_zone"), auth=resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["actions_submit"]))
    wrong_audience_action = resident_call("submitPhysicalActionWrongAudience", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload("inspect_zone"), auth=resident_auth(root, auth_dir, EDGE_INSTANCE_ID, ["actions_submit"]), mirror=resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["actions_submit"])["credential"])
    wrong_tenant_action = resident_call("submitPhysicalActionWrongTenant", "POST", f"/devices/{EDGE_NODE_ID}/actions", "actions_submit", physical_payload("inspect_zone"), auth=resident_auth(root, auth_dir, EDGE_INSTANCE_ID, ["actions_submit"], tenant_id="11111111-1111-4111-8111-999999999999"))

    traces = resident_call("exportTraces", "POST", f"/runs/{RUN_ID}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    records = traces["body"].get("records", [])
    sync_records = []
    for record in records:
        if "[REDACTED" in json.dumps(record.get("payload", {}), sort_keys=True):
            break
        sync_records.append(record)
    wrong_trace_scope = resident_call("syncDeviceTraceBufferWrongScope", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_read", {"run_id": RUN_ID, "records": sync_records, "simulate_tamper": False})
    sync = resident_call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": sync_records, "simulate_tamper": False})
    duplicate_sync = resident_call("syncDeviceTraceBufferDuplicate", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": sync_records, "simulate_tamper": False})
    tampered_records = json.loads(json.dumps(sync_records))
    if tampered_records:
        tampered_records[0]["prev_event_hash"] = {"algorithm": "Blake3", "value": "0" * 64}
    tamper = resident_call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": tampered_records, "simulate_tamper": False})
    payload_tampered_records = json.loads(json.dumps(sync_records))
    if payload_tampered_records:
        payload_tampered_records[0].setdefault("payload", {})["s6_payload_tamper"] = True
    payload_tamper = resident_call("syncDeviceTraceBufferPayloadTamper", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": payload_tampered_records, "simulate_tamper": False})
    cross_run_records = json.loads(json.dumps(sync_records))
    if cross_run_records:
        cross_run_records[0]["run_id"] = "44444444-4444-4444-8444-444444444499"
    cross_run_sync = resident_call("syncDeviceTraceBufferCrossRun", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": cross_run_records, "simulate_tamper": False})
    reordered_records = json.loads(json.dumps(sync_records))
    if reordered_records:
        reordered_records[0]["sequence"] = 1
    reordered = resident_call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", "device_trace_sync", {"run_id": RUN_ID, "records": reordered_records, "simulate_tamper": False})
    sim_before_replay = sim_json("GET", args.device_sim_url, "/evidence")
    replay = resident_call("replayRun", "POST", f"/runs/{RUN_ID}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": False})
    sim_after_replay = sim_json("GET", args.device_sim_url, "/evidence")

    approval_final_records = approval_final_traces["body"].get("records", [])
    extra_events = {"device.profile.registered": [register["body"].get("trace_event_id", ""), other_device_register["body"].get("trace_event_id", "")], "policy.cache.loaded": [register["body"].get("trace_event_id", ""), other_device_register["body"].get("trace_event_id", "")], "cloud_helper.proposal.received": [cloud_message_received["body"].get("read_trace_event_id", "")], "approval.requested": [approval_manager_request["body"].get("trace_event_id", "")], "approval.granted": [approval_grant["body"].get("trace_event_id", "")], "operator.intervention.requested": [intervention_request["body"].get("trace_event_id", "")], "operator.intervention.granted": [intervention_grant["body"].get("trace_event_id", "")], "operator.intervention.denied": [intervention_deny["body"].get("trace_event_id", "")], "trace.sync.completed": [sync["body"].get("trace_event_id", ""), duplicate_sync["body"].get("trace_event_id", "")], "trace.sync.failed": [tamper["body"].get("trace_event_id", ""), payload_tamper["body"].get("trace_event_id", ""), cross_run_sync["body"].get("trace_event_id", ""), reordered["body"].get("trace_event_id", "")]}
    event_ids = trace_event_ids(records + approval_final_records, extra_events)
    trace_payload = json.dumps(records, sort_keys=True)
    manager_audit_payload = json.dumps(manager_audit["body"], sort_keys=True)
    proposal_trace_linked = CLOUD_MESSAGE_ID in trace_payload and cloud_message["payload"]["proposal_id"] in trace_payload
    challenge_coordinate = approval_challenge.get("physical_action_resource_coordinate", {})
    wrong_node_trace_ids_before = approval_action_trace_ids(approval_traces_before_wrong_node["body"].get("records", []))
    wrong_node_trace_ids_after = approval_action_trace_ids(approval_traces_after_wrong_node["body"].get("records", []))
    profile_a_governed = {key: value for key, value in register["body"].get("profile", {}).items() if key not in {"node_id", "registered_at"}}
    profile_b_governed = {key: value for key, value in other_device_register["body"].get("profile", {}).items() if key not in {"node_id", "registered_at"}}
    manager_approval_auth_valid = (
        len(manager_approval_auth_events) == 2
        and len({event["credential_id"] for event in manager_approval_auth_events}) == 2
        and {event["operation_id"] for event in manager_approval_auth_events} == {"requestApproval", "grantApproval"}
        and all(event["scope"] == "approvals_manage" and event["fleet_id"] == FLEET_ID and event["target_manager_id"] == event["audience_manager_id"] == "central-manager" and event["body_mirror_status"] == "matched" and event["result_status"] == 200 and event["raw_bearer_recorded"] is False and event["raw_signature_recorded"] is False for event in manager_approval_auth_events)
    )
    physical_approval_binding_valid = (
        approval_work_order_submit["body"].get("accepted") is True
        and approval_placement["body"].get("status") == "selected"
        and approval_placement["body"].get("candidate_id") == EDGE_NODE_ID
        and approval_dispatch["body"].get("run_id") == APPROVAL_RUN_ID
        and approval_dispatch["body"].get("selected_node_id") == EDGE_NODE_ID
        and approval_dispatch["body"].get("selected_instance_id") == EDGE_INSTANCE_ID
        and approval_dispatch["body"].get("create_run_status") == 200
        and approval_dispatch["body"].get("start_run_status") == 200
        and approval_policy_narrowing["action_name"] == "capture_image"
        and approval_policy_narrowing["adapter"] == "device-sim"
        and approval_policy_narrowing["required_permission"] == PHYSICAL_PERMISSION
        and approval_policy_narrowing["expires_at"] == approval_work_order_payload["expires_at"]
        and edge_capability_advertisement["status"] == 200
        and approval_required["body"].get("status") == "NeedsApproval"
        and approval_challenge.get("run_id") == APPROVAL_RUN_ID
        and approval_challenge.get("action_id") == APPROVAL_ACTION_ID
        and approval_challenge.get("gateway_action_request_digest", "").startswith("blake3:")
        and challenge_coordinate == {"resource_kind": "physical_node", "node_id": EDGE_NODE_ID}
        and approval_challenge.get("receipt_audience") == expected_receipt_audience
        and authority_receipt.get("audience") == expected_receipt_audience
        and authority_receipt.get("approval_id") == approval_challenge.get("approval_id")
        and manager_approval_auth_valid
    )
    wrong_node_preclaim_valid = (
        wrong_node_receipt_retry["status"] == 409
        and wrong_node_receipt_retry["body"].get("code") == "approval_challenge_retry_mismatch"
        and provider_effect_state(sim_before_wrong_node)
        == provider_effect_state(sim_after_wrong_node)
        and approval_waiting_before_wrong_node["body"].get("status") == "waiting_for_approval"
        and approval_waiting_after_wrong_node["body"].get("status") == "waiting_for_approval"
        and approval_waiting_before_wrong_node["body"].get("adapter_executions") == 0
        and approval_waiting_after_wrong_node["body"].get("adapter_executions") == 0
        and wrong_node_trace_ids_before == wrong_node_trace_ids_after
    )
    exact_node_execution_valid = (
        exact_node_receipt_retry["body"].get("status") == "Executed"
        and sim_total(sim_after_exact_node) - sim_total(sim_before_exact_node) == 1
        and sim_action_count(sim_after_exact_node, "capture_image") - sim_action_count(sim_before_exact_node, "capture_image") == 1
        and approval_after_exact_node["body"].get("status") == "running"
        and approval_after_exact_node["body"].get("adapter_executions") == 1
    )
    receipt_replay_denied = (
        receipt_replay["body"].get("status") == "Denied"
        and "authority_obligation_receipt_replayed" in receipt_replay["body"].get("verification", {}).get("reasons", [])
        and provider_effect_state(sim_before_receipt_replay)
        == provider_effect_state(sim_after_receipt_replay)
        and approval_after_receipt_replay["body"].get("adapter_executions") == 1
    )
    approval_replay_unchanged = provider_effect_state(
        sim_before_approval_replay
    ) == provider_effect_state(sim_after_approval_replay)

    def from_safety_verifier(response: dict[str, Any]) -> bool:
        return response.get("body", {}).get("verification", {}).get("artifacts", {}).get("source") == "safety_verifier"

    negatives = [
        {"case": "forbidden_low_level_actions_rejected", "passed": all(item["status"] == 400 and item["body"].get("code") == "low_level_physical_action_rejected" for item in forbidden)},
        {"case": "physical_action_resource_coordinate_injection_rejected", "passed": coordinate_injection["status"] == 422 and provider_effect_state(sim_before_coordinate_injection) == provider_effect_state(sim_after_coordinate_injection)},
        {"case": "physical_unknown_authority_field_rejected", "passed": unknown_authority["status"] == 422 and provider_effect_state(sim_before_unknown_authority) == provider_effect_state(sim_after_unknown_authority)},
        {"case": "physical_reserved_node_param_rejected", "passed": reserved_node_injection["status"] == 200 and reserved_node_injection["body"].get("status") == "Failed" and reserved_node_injection["body"].get("error") == "adapter failed" and "acceptance_operation_reserved_field" not in str(reserved_node_injection["body"]) and provider_effect_state(sim_before_reserved_node) == provider_effect_state(sim_after_reserved_node)},
        {"case": "physical_approval_wrong_node_rejected_before_claim", "passed": wrong_node_preclaim_valid},
        {"case": "physical_approval_receipt_replay_denied", "passed": receipt_replay_denied},
        {"case": "geofence_breach_denied_before_adapter", "passed": geofence["body"].get("status") == "Denied" and "geofence_violation" in geofence["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(geofence)},
        {"case": "low_battery_forces_return_to_base_or_intervention", "passed": low_battery["body"].get("status") == "NeedsIntervention" and "battery_below_minimum" in low_battery["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(low_battery) and offline_rtb["body"].get("status") == "Executed"},
        {"case": "expired_policy_cache_denies_high_risk_offline", "passed": expired_policy["body"].get("status") == "Denied" and "policy_cache_expired" in expired_policy["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(expired_policy)},
        {"case": "cloud_helper_direct_action_attempt_denied", "passed": cloud_direct["body"].get("status") == "Denied" and "cloud_helper_direct_authority_denied" in cloud_direct["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(cloud_direct)},
        {"case": "operator_approval_outside_scope_rejected", "passed": wrong_scope["status"] == 403 and wrong_scope["body"].get("code") == "operator_intervention_scope_mismatch"},
        {"case": "operator_approval_after_expiry_rejected", "passed": expired_approval["status"] == 403 and expired_approval["body"].get("code") == "operator_intervention_expired"},
        {"case": "operator_intervention_expiry_extension_rejected", "passed": extended_intervention["status"] == 403 and extended_intervention["body"].get("code") == "operator_intervention_expiry_mismatch"},
        {"case": "operator_intervention_cross_device_reuse_rejected", "passed": other_device_register["status"] == 200 and reused_intervention["status"] == 403 and reused_intervention["body"].get("code") == "operator_intervention_scope_mismatch"},
        {"case": "trace_sync_requires_dedicated_mutating_scope", "passed": wrong_trace_scope["status"] == 403 and wrong_trace_scope["body"].get("code") == "missing_scope"},
        {"case": "trace_sync_tamper_or_reordering_detected", "passed": tamper["body"].get("accepted") is False and tamper["body"].get("accepted_records") == 0 and tamper["body"].get("reason_code") == "trace_sync_hash_chain_mismatch" and payload_tamper["body"].get("accepted") is False and payload_tamper["body"].get("accepted_records") == 0 and payload_tamper["body"].get("reason_code") == "trace_sync_event_hash_mismatch" and cross_run_sync["body"].get("accepted") is False and cross_run_sync["body"].get("accepted_records") == 0 and cross_run_sync["body"].get("reason_code") == "trace_sync_run_mismatch" and reordered["body"].get("accepted") is False and reordered["body"].get("accepted_records") == 0},
        {"case": "device_endpoint_missing_credential_rejected", "passed": missing_credential_status["status"] in {401, 403} and missing_credential_action["status"] in {401, 403}},
        {"case": "device_endpoint_wrong_audience_rejected", "passed": wrong_bearer_audience_status["status"] == 401 and wrong_bearer_audience_status["body"].get("code") == "wrong_caller_token_audience" and wrong_bearer_audience_action["status"] == 401 and wrong_bearer_audience_action["body"].get("code") == "wrong_caller_token_audience" and wrong_audience_status["status"] == 403 and wrong_audience_status["body"].get("code") == "caller_credential_mirror_mismatch" and wrong_audience_action["status"] == 403 and wrong_audience_action["body"].get("code") == "caller_credential_mirror_mismatch"},
        {"case": "device_endpoint_wrong_tenant_rejected", "passed": wrong_tenant_status["status"] == 403 and wrong_tenant_status["body"].get("code") == "wrong_credential_binding" and wrong_tenant_action["status"] == 403 and wrong_tenant_action["body"].get("code") == "wrong_credential_binding"},
    ]
    simulator_counters_valid = all(item.get("total_delta") == item.get("expected_sim_delta") for item in simulator_evidence)
    replay_unchanged = provider_effect_state(sim_before_replay) == provider_effect_state(
        sim_after_replay
    )
    cloud_message_valid = all(cloud_message.get(field) for field in ["message_id", "source_agent_id", "target_agent_id", "run_id", "schema", "causal_parent", "created_at"]) and cloud_message["payload"].get("direct_actuator_authority") is False and helper_work_order_submit["body"].get("accepted") is True and cloud_message_delivery["body"].get("message_id") == CLOUD_MESSAGE_ID and cloud_message_delivery["body"].get("delivery_status") == "delivered" and cloud_message_delivery["body"].get("receive_side_validated") is True and cloud_message_delivery["body"].get("remote_state_mutated") is False and cloud_message_received["body"].get("message_id") == CLOUD_MESSAGE_ID and CLOUD_MESSAGE_ID in manager_audit_payload and proposal_trace_linked
    positives = {"device_registered": register["status"] == 200 and register["body"].get("profile", {}).get("device_kind") == "drone_sim", "equivalent_same_tenant_device_nodes_registered": other_device_register["status"] == 200 and register["body"].get("profile", {}).get("node_id") == EDGE_NODE_ID and other_device_register["body"].get("profile", {}).get("node_id") == OTHER_EDGE_NODE_ID and register["body"].get("profile", {}).get("tenant_id") == other_device_register["body"].get("profile", {}).get("tenant_id") == TENANT_ID and profile_a_governed == profile_b_governed, "policy_cache_loaded": cache["body"].get("loaded") is True and cache["body"].get("expired") is False, "run_created_started": create["status"] == 200 and start["status"] == 200, "physical_approval_v2_node_and_resident_target_bound": physical_approval_binding_valid, "physical_approval_exact_node_executes_once": exact_node_execution_valid, "physical_approval_inspect_replay_suppressed": approval_replay["body"].get("mode") == "inspect_only" and approval_replay_unchanged, "cloud_helper_typed_proposal_local_only": waypoint["body"].get("status") == "Executed" and inspect_zone["body"].get("status") == "Executed" and cloud_message_valid, "inspect_zone_executed": inspect_zone["body"].get("status") == "Executed", "safe_actions_executed": all(resp["body"].get("status") == "Executed" for resp in [read_battery, inspect_zone, waypoint, capture, offline_sensor, offline_rtb, upload_summary, intervention_capture]), "ambiguous_action_denied_by_safety_verifier": ambiguous["body"].get("status") == "Denied" and from_safety_verifier(ambiguous), "simulator_counters_valid": simulator_counters_valid, "trace_sync_completed": len(sync_records) > 0 and sync["body"].get("accepted") is True and duplicate_sync["body"].get("accepted") is True and duplicate_sync["body"].get("accepted_records") == sync["body"].get("accepted_records"), "replay_inspect_only": replay["body"].get("mode") == "inspect_only" and replay_unchanged}
    failures = [key for key, ok in positives.items() if not ok]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    scenario = {"id": "UC-E2E-S6", "status": "passed" if not failures else "failed", "fr_coverage": [f"FR-0.05-{i:02d}" for i in range(1, 11)], "components": ["resident-edge-node", "central-manager-message-api", "device-profile", "physical-capability", "device-sim-adapter", "safety-verifier", "offline-policy-cache", "trace-buffer", "operator-intervention", "typed-cloud-helper-proposal", "gateway", "trace", "replay/audit"], "positive_evidence": [key for key, ok in positives.items() if ok], "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True], "replay_evidence": ["replayRun public API returned inspect_only and device-sim counters were unchanged"], "replay_mode": "inspect_only", "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "simulator_counter_before": sim_before_replay, "simulator_counter_after": sim_after_replay}, "replay_artifacts": [str(artifact_dir / "replay-report.json")], "anti_drift_checks": ["public_device_daemon_verified_https_bearer_used", "public_manager_message_api_used", "gateway_required_before_device_sim_adapter", "cloud_helper_proposal_only", "no_low_level_physical_action_accepted", "replay_no_simulator_control"], "run_ids": [RUN_ID], "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid and not str(tid).startswith("operator_")}), "state_node_ids": [state_head["body"].get("state_node_id", "")], "state_hashes": [state_head["body"].get("data_hash", "")], "message_ids": [CLOUD_MESSAGE_ID], "work_order_ids": [WORK_ORDER_ID, HELPER_WORK_ORDER_ID], "approval_ids": ["intervention_uc_e2e_s6_capture"], "node_ids": [EDGE_NODE_ID, CLOUD_NODE_ID], "api_operations": sorted({row["operation_id"] for row in api_rows}), "required_trace_event_ids": event_ids, "negative_cases": negatives, "positive_checks": positives, "scenario_failures": failures, "private_v3_outputs": private_v3_outputs, "provider_evidence": [sim_before_replay, sim_after_replay], "artifact_paths": []}
    artifacts = {"scenario-report.json": scenario, "device-profile.json": register["body"], "device-status.json": status["body"], "policy-cache-status.json": cache["body"], "cloud-helper-message.json": {"work_order_submit": helper_work_order_submit["body"], "delivery": cloud_message_delivery["body"], "received": cloud_message_received["body"], "manager_audit_contains_message_id": CLOUD_MESSAGE_ID in manager_audit_payload, "trace_payload_contains_message_id": CLOUD_MESSAGE_ID in trace_payload, "trace_payload_contains_proposal_id": cloud_message["payload"]["proposal_id"] in trace_payload}, "cloud-helper-proposal.json": {"message": cloud_message, "proposal": cloud_message["payload"], "local_validation_inputs": {"inspect_zone": {"cloud_helper_proposal_id": cloud_message["payload"]["proposal_id"], "cloud_helper_message_id": CLOUD_MESSAGE_ID}, "move_to_waypoint": {"cloud_helper_proposal_id": cloud_message["payload"]["proposal_id"], "cloud_helper_message_id": CLOUD_MESSAGE_ID}}, "local_validation_outcomes": {"inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"]}, "direct_attempt": cloud_direct["body"]}, "device-sim-counters.json": {"evidence": simulator_evidence, "before_replay": sim_before_replay, "after_replay": sim_after_replay}, "device-safety-evidence.json": {"positive": positives, "safe_actions": {"read_battery": read_battery["body"], "inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"], "capture_image": capture["body"], "offline_sensor": offline_sensor["body"], "return_to_base": offline_rtb["body"], "upload_trace_summary": upload_summary["body"]}, "denials": {"geofence": geofence["body"], "low_battery": low_battery["body"], "expired_policy": expired_policy["body"], "cloud_direct": cloud_direct["body"]}}, "operator-intervention.json": {"ambiguous": ambiguous["body"], "request": intervention_request["body"], "grant": intervention_grant["body"], "granted_capture": intervention_capture["body"], "deny": intervention_deny["body"], "wrong_scope": wrong_scope, "expired": expired_approval}, "security-negatives.json": {"missing_credential_status": missing_credential_status, "wrong_bearer_audience_status": wrong_bearer_audience_status, "wrong_audience_status": wrong_audience_status, "wrong_tenant_status": wrong_tenant_status, "missing_credential_action": missing_credential_action, "wrong_bearer_audience_action": wrong_bearer_audience_action, "wrong_audience_action": wrong_audience_action, "wrong_tenant_action": wrong_tenant_action}, "trace-sync-report.json": {"completed": sync["body"], "tamper": tamper["body"], "reordered": reordered["body"], "tampered_record_mutation": "prev_event_hash", "reordered_records": True}, "state-export.json": state_head["body"], "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "simulator_counter_before": sim_before_replay, "simulator_counter_after": sim_after_replay, "simulator_actuator_calls_replayed": not replay_unchanged, "physical_decisions_explained": [item["case"] for item in negatives if item.get("passed") is True]}, "audit-report.json": {"cloud_helper_authority": "proposal_only", "cloud_helper_direct_action_authorized": False, "operator_intervention_ids": ["intervention_uc_e2e_s6_capture"], "event_ids": event_ids}, "anti-drift-results.json": {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "raw_physical_action_accepted": False, "cloud_helper_direct_actuator_authority": False, "replay_side_effects_allowed_default": False}, "stdout.log": "UC-E2E-S6 physical/edge scenario completed through public resident-edge daemon and central-manager message HTTP endpoints\n", "stderr.log": ""}
    scenario.update({
        "components": scenario["components"] + ["manager-approval-api", "physical-v2-node-binding", "authority-receipt-ledger"],
        "replay_evidence": scenario["replay_evidence"] + ["wrong-node receipt retry rejected before claim", "same receipt executed once on node A and replay was denied", "physical approval inspect-only replay left simulator counters unchanged"],
        "anti_drift_checks": scenario["anti_drift_checks"] + ["physical_coordinate_server_derived", "approval_receipt_exact_instance_and_run", "wrong_device_rejected_before_receipt_claim", "closed_action_transport_schema", "manager_approval_auth_redacted"],
        "run_ids": [RUN_ID, APPROVAL_RUN_ID],
        "trace_event_ids": sorted({trace_id for ids in event_ids.values() for trace_id in ids if trace_id and not str(trace_id).startswith("operator_")}),
        "work_order_ids": [WORK_ORDER_ID, HELPER_WORK_ORDER_ID, APPROVAL_WORK_ORDER_ID],
        "approval_ids": ["intervention_uc_e2e_s6_capture", approval_challenge["approval_id"]],
        "node_ids": [EDGE_NODE_ID, OTHER_EDGE_NODE_ID, CLOUD_NODE_ID],
        "instance_ids": [EDGE_INSTANCE_ID, CLOUD_INSTANCE_ID],
        "action_ids": [APPROVAL_ACTION_ID],
        "required_trace_event_ids": event_ids,
        "artifact_keys": {
            "physical_approval_node_binding": "physical-approval-node-binding.json",
            "manager_approval_auth": "manager-approval-auth.json",
            "physical_approval_trace": "physical-approval-trace.jsonl",
            "device_profiles": "device-profiles.json",
        },
    })
    physical_approval_artifact = {
        "schema_version": "splendor.uc_e2e_s6.physical_approval_node_binding.v1",
        "digest_profile": "splendor.gateway.authority_action_binding.physical.v2",
        "ids": {
            "tenant_id": TENANT_ID,
            "agent_id": AGENT_ID,
            "run_id": APPROVAL_RUN_ID,
            "action_id": APPROVAL_ACTION_ID,
            "approval_id": approval_challenge["approval_id"],
            "work_order_id": APPROVAL_WORK_ORDER_ID,
            "node_a_id": EDGE_NODE_ID,
            "node_b_id": OTHER_EDGE_NODE_ID,
            "target_instance_id": EDGE_INSTANCE_ID,
            "receipt_id": authority_receipt.get("receipt_id"),
        },
        "manager_target_binding": {
            "work_order_submit": approval_work_order_submit["body"],
            "approval_policy_narrowing": approval_policy_narrowing,
            "placement": approval_placement["body"],
            "dispatch": approval_dispatch["body"],
            "capability_advertisement_status": edge_capability_advertisement["status"],
            "expected_node_id": EDGE_NODE_ID,
            "expected_instance_id": EDGE_INSTANCE_ID,
            "expected_run_id": APPROVAL_RUN_ID,
        },
        "challenge": {
            "status": approval_required["body"].get("status"),
            "request": redact_sensitive(approval_action_request),
            "canonical_request_digest": approval_challenge.get("canonical_request_digest"),
            "gateway_action_request_digest": approval_challenge.get("gateway_action_request_digest"),
            "authority_decision_digest": approval_challenge.get("authority_decision_digest"),
            "physical_action_resource_coordinate": challenge_coordinate,
            "receipt_audience": approval_challenge.get("receipt_audience"),
            "caller_action_param_node_id": approval_action_request["action"]["params"].get("node_id"),
            "caller_param_did_not_override_server_coordinate": "node_id" not in approval_action_request["action"]["params"] and challenge_coordinate.get("node_id") == EDGE_NODE_ID,
            "simulator_counter_before": sim_before_challenge,
            "simulator_counter_after": sim_after_challenge,
        },
        "manager_approval": {
            "request": redact_sensitive(approval_manager_request["body"]),
            "grant": redact_sensitive(approval_grant["body"]),
            "receipt": redact_sensitive(authority_receipt),
            "expected_receipt_audience": expected_receipt_audience,
            "exact_instance_and_run_audience": authority_receipt.get("audience") == expected_receipt_audience,
        },
        "closed_schema": {
            "physical_action_resource_coordinate": coordinate_injection,
            "unknown_authority_field": unknown_authority,
            "reserved_node_action_param": reserved_node_injection,
            "simulator_unchanged": provider_effect_state(sim_before_coordinate_injection) == provider_effect_state(sim_after_coordinate_injection) and provider_effect_state(sim_before_unknown_authority) == provider_effect_state(sim_after_unknown_authority) and provider_effect_state(sim_before_reserved_node) == provider_effect_state(sim_after_reserved_node),
        },
        "wrong_node_preclaim": {
            "response": wrong_node_receipt_retry,
            "run_before": approval_waiting_before_wrong_node["body"],
            "run_after": approval_waiting_after_wrong_node["body"],
            "simulator_counter_before": sim_before_wrong_node,
            "simulator_counter_after": sim_after_wrong_node,
            "action_trace_ids_before": wrong_node_trace_ids_before,
            "action_trace_ids_after": wrong_node_trace_ids_after,
            "trace_unchanged": wrong_node_trace_ids_before == wrong_node_trace_ids_after,
            "receipt_unclaimed": wrong_node_preclaim_valid,
        },
        "exact_node_execution": {
            "request": redact_sensitive(receipt_retry_request),
            "response": redact_sensitive(exact_node_receipt_retry["body"]),
            "run_after": approval_after_exact_node["body"],
            "simulator_counter_before": sim_before_exact_node,
            "simulator_counter_after": sim_after_exact_node,
            "executed_exactly_once": exact_node_execution_valid,
        },
        "receipt_replay": {
            "response": redact_sensitive(receipt_replay["body"]),
            "run_after": approval_after_receipt_replay["body"],
            "simulator_counter_before": sim_before_receipt_replay,
            "simulator_counter_after": sim_after_receipt_replay,
            "denied_without_effect": receipt_replay_denied,
        },
        "inspect_only_replay": {
            "response": approval_replay["body"],
            "simulator_counter_before": sim_before_approval_replay,
            "simulator_counter_after": sim_after_approval_replay,
            "unchanged": approval_replay_unchanged,
        },
        "no_low_level_authority": all(name not in ALLOWED_ACTIONS for name in FORBIDDEN_ACTIONS),
    }
    artifacts.update({
        "device-profiles.json": {"node_a": register["body"], "node_b": other_device_register["body"], "equivalent_governed_profile": profile_a_governed == profile_b_governed, "server_owned_fields_compared_separately": ["node_id", "registered_at"], "same_tenant": register["body"].get("profile", {}).get("tenant_id") == other_device_register["body"].get("profile", {}).get("tenant_id") == TENANT_ID},
        "physical-approval-node-binding.json": physical_approval_artifact,
        "manager-approval-auth.json": {"schema_version": "splendor.uc_e2e.manager_approval_auth.v1", "events": manager_approval_auth_events, "all_calls_authenticated_once": manager_approval_auth_valid, "raw_bearer_recorded": False, "raw_signature_recorded": False},
    })
    artifacts["device-sim-counters.json"].update({"physical_approval_before_replay": sim_before_approval_replay, "physical_approval_after_replay": sim_after_approval_replay})
    artifacts["replay-report.json"].update({"physical_approval_receipt_replay_denied": receipt_replay_denied, "physical_approval_inspect_only": approval_replay["body"], "physical_approval_simulator_counter_before": sim_before_approval_replay, "physical_approval_simulator_counter_after": sim_after_approval_replay})
    artifacts["audit-report.json"].update({"physical_approval_id": approval_challenge["approval_id"], "physical_approval_action_id": APPROVAL_ACTION_ID, "physical_approval_challenge_digest": approval_challenge.get("gateway_action_request_digest"), "physical_approval_resource_coordinate": challenge_coordinate, "physical_approval_receipt_audience": authority_receipt.get("audience"), "manager_approval_auth_artifact": "manager-approval-auth.json"})
    artifacts["anti-drift-results.json"].update({"physical_coordinate_caller_controlled": False, "wrong_node_receipt_claimed": False, "approval_receipt_replay_executed": False, "manager_approval_bearer_or_signature_leaked": False, "low_level_physical_authority": False})
    for name, data in artifacts.items():
        path = artifact_dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", records)
    write_jsonl(artifact_dir / "physical-approval-trace.jsonl", approval_final_records)
    scenario["artifact_paths"].extend([str(artifact_dir / "api-traffic.ndjson"), str(artifact_dir / "trace-export.jsonl"), str(artifact_dir / "physical-approval-trace.jsonl")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S6 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
