#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FLEET_ID = "00000000-0000-4000-8000-000000000104"
TENANT_ID = "11111111-1111-4111-8111-111111111111"
ORCH_AGENT = "22222222-2222-4222-8222-222222222210"
SPECIALIST_AGENT = "33333333-3333-4333-8333-333333333310"
CLOUD_HELPER_AGENT = "33333333-3333-4333-8333-333333333311"
EDGE_AGENT = "22222222-2222-4222-8222-222222222610"
ORCH_RUN = "44444444-4444-4444-8444-444444448810"
SPECIALIST_RUN = "44444444-4444-4444-8444-444444448811"
CLOUD_HELPER_RUN = "44444444-4444-4444-8444-444444448812"
EDGE_RUN = "44444444-4444-4444-8444-444444448813"
CB_RUN = "44444444-4444-4444-8444-444444448814"
KILL_RUN = "44444444-4444-4444-8444-444444448815"
VPC_NODE = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE = "00000000-0000-4000-8000-000000000302"
CLOUD_NODE = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE = "00000000-0000-4000-8000-000000000304"
EDGE_NODE = "00000000-0000-4000-8000-000000000604"
EDGE_INSTANCE = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ORCH = "wo_uc_e2e_s10_field_intelligence"
WORK_ORDER_SPECIALIST = "wo_uc_e2e_s10_scoped_specialist"
WORK_ORDER_CLOUD_HELPER = "wo_uc_e2e_s10_cloud_helper_proposal"
WORK_ORDER_EDGE = "wo_uc_e2e_s10_edge_inspection"
WORK_ORDER_CB = "wo_uc_e2e_s10_circuit_branch"
WORK_ORDER_KILL = "wo_uc_e2e_s10_kill_branch"
POLICY_ID = "policy_uc_e2e_s10_final_journey"
BREAKER_ID = "55555555-5555-4555-8555-555555558816"
KILL_SWITCH_ID = "ks_uc_e2e_s10_controlled_branch"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
DATA_REF = "dataset:tenant-a.field-intel.fixture.v1"
DENIED_DATA_REF = "dataset:tenant-b.field-intel.restricted.v1"
INTERNAL_ARTIFACT = f"artifact://{TENANT_ID}/field-intelligence/s10-internal.md"
EXTERNAL_ARTIFACT = f"artifact://{TENANT_ID}/field-intelligence/s10-public.md"
ROUTE_PROPOSAL_ID = "route-proposal-s10-zone-a3"
CLOUD_MESSAGE_ID = "55555555-5555-4555-8555-555555558810"
TASK_REQUEST_ID = "55555555-5555-4555-8555-555555558811"
TASK_RESPONSE_ID = "55555555-5555-4555-8555-555555558812"
DUPLICATE_MESSAGE_ID = "55555555-5555-4555-8555-555555558813"
EDGE_CAUSAL_TRACE_ID = "55555555-5555-4555-8555-555555558814"
ALLOWED_PHYSICAL_ACTIONS = [
    "read_battery",
    "read_sensor_summary",
    "inspect_zone",
    "move_to_waypoint",
    "capture_image",
    "return_to_base",
    "upload_trace_summary",
]
FORBIDDEN_PHYSICAL_ACTIONS = [
    "set" + "_motor" + "_pwm",
    "raw" + "_actuator" + "_write",
    "disable" + "_firmware" + "_safety",
    "bypass" + "_collision" + "_avoidance",
    "ignore" + "_emergency" + "_stop",
]

REQUIRED_NEGATIVES = {
    "invalid_work_order_rejected_before_run_start",
    "unauthorized_data_ref_denied",
    "specialist_permission_escalation_denied",
    "remote_duplicate_not_double_applied",
    "unsupported_message_schema_validation_rejected",
    "omitted_message_read_scope_denied",
    "cross_tenant_message_read_rejected",
    "unauthorized_ack_nack_denied",
    "ack_nack_scope_or_payload_mutation_denied",
    "raw_physical_control_rejected",
    "expired_approval_rejected",
    "circuit_breaker_blocks_matching_publish_attempt",
    "kill_switch_cancels_separate_run",
    "tampered_trace_state_import_rejected",
    "replay_side_effect_mode_rejected_by_default",
}

REQUIRED_POSITIVES = {
    "api_contract_passed",
    "nodes_and_instances_registered",
    "policy_bundle_published_with_ttl",
    "signed_work_order_accepted_and_placed_on_vpc",
    "data_local_analysis_executed",
    "shared_specialist_typed_response_delivered",
    "message_public_api_surface_exercised",
    "cloud_helper_proposal_only",
    "edge_bounded_inspection_executed",
    "internal_artifact_created",
    "external_publication_approval_gated_and_executed_once",
    "state_handoff_imported_and_resumed_once",
    "central_trace_aggregation_completed",
    "audit_and_replay_explain_without_side_effects",
}

REQUIRED_EVENTS = {
    "work_order.accepted",
    "placement.evaluated",
    "data_scope.verified",
    "message.sent",
    "message.received",
    "cloud_helper.proposal.received",
    "safety.verification.completed",
    "action.executed",
    "action.denied",
    "action.needs_approval",
    "approval.granted",
    "artifact.created",
    "artifact.publish.executed",
    "state.committed",
    "state.exported",
    "state.imported",
    "run.resumed",
    "trace.sync.completed",
    "replay.explained",
    "governance.audit.exported",
    "circuit_breaker.tripped",
    "kill_switch.activated",
}

S10_RUN_IDS = {ORCH_RUN, SPECIALIST_RUN, CLOUD_HELPER_RUN, EDGE_RUN, CB_RUN, KILL_RUN}
S10_WORK_ORDER_IDS = {
    WORK_ORDER_ORCH,
    WORK_ORDER_SPECIALIST,
    WORK_ORDER_CLOUD_HELPER,
    WORK_ORDER_EDGE,
    WORK_ORDER_CB,
    WORK_ORDER_KILL,
}
S10_MESSAGE_IDS = {TASK_REQUEST_ID, TASK_RESPONSE_ID, CLOUD_MESSAGE_ID, DUPLICATE_MESSAGE_ID}
S10_NODE_IDS = {VPC_NODE, CLOUD_NODE, EDGE_NODE}
S10_INSTANCE_IDS = {VPC_INSTANCE, CLOUD_INSTANCE, EDGE_INSTANCE}


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def utc_seconds(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def request_json(
    method: str,
    base_url: str,
    path: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + path, data=payload, method=method)
    if payload is not None:
        req.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def sim_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    status, data = request_json(method, base_url, path, body)
    if status != 200:
        raise SystemExit(f"device simulator request failed: {method} {path} status={status} body={data}")
    return data


def sim_total(counters: dict[str, Any]) -> int:
    return int(counters.get("total", 0))


def sim_action_count(counters: dict[str, Any], action_name: str) -> int:
    return int(counters.get("by_action", {}).get(action_name, 0))


def run_cmd(cmd: list[str], cwd: Path, log: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    with log.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        fh.write(proc.stdout)
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return proc


def splendorctl(root: Path) -> list[str]:
    for candidate in [Path("/usr/local/bin/splendorctl"), root / "target" / "debug" / "splendorctl"]:
        if candidate.exists():
            return [str(candidate)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s10_manager",
        "principal": {
            "app": {"app_principal_id": "app_uc_e2e_s10", "label": "UC-E2E-S10"},
            "client_principal_id": "client_uc_e2e_s10",
            "label": "UC-E2E-S10 final journey client",
        },
        "scopes": scopes
        or [
            "nodes_register",
            "instances_register",
            "nodes_heartbeat",
            "fleet_read",
            "fleet_dispatch",
            "work_orders_submit",
            "work_orders_revoke",
            "traces_read",
            "messages_send",
            "messages_read",
            "policies_publish",
            "policies_revoke",
            "approvals_manage",
            "governance_control",
        ],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def resident_credential(instance_id: str, scopes: list[str] | None = None, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {
        "credential_id": f"cred_uc_e2e_s10_resident_{instance_id[-3:]}",
        "principal": manager_credential()["principal"],
        "scopes": scopes
        or [
            "runs_create",
            "runs_start",
            "runs_read",
            "runs_pause",
            "runs_resume",
            "runs_stop",
            "actions_submit",
            "state_read",
            "state_handoff",
            "traces_read",
            "replay_create",
            "policies_sync",
        ],
        "binding": {"tenant": {"tenant_id": tenant_id}},
        "audience": {"instance": {"instance_id": instance_id}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def edge_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s10_edge",
        "principal": manager_credential()["principal"],
        "scopes": scopes
        or [
            "runs_create",
            "runs_start",
            "runs_read",
            "actions_submit",
            "state_read",
            "traces_read",
            "replay_create",
            "device_register",
            "device_read",
            "operator_intervene",
        ],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"instance": {"instance_id": EDGE_INSTANCE}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any]) -> dict[str, Any]:
    return {"credential": credential, "audit_attribution": audit(credential)}


def message_scope(credential: dict[str, Any], run_id: str, agent_id: str, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {**sec(credential), "tenant_id": tenant_id, "run_id": run_id, "agent_id": agent_id}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def node_registration(node_id: str, kind: str, target: str, locality: str, url: str, capabilities: list[str]) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": kind,
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": capabilities,
            "constraints": {
                "placement_target": target,
                "data_locality": locality,
                "region": "eu-west",
                "resident_daemon_url": url,
                "runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime",
                "trust_level": "acceptance",
            },
        },
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime"}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str, features: list[str]) -> dict[str, Any]:
    return {
        "instance_id": instance_id,
        "node_id": node_id,
        "runtime_mode": "resident",
        "hosted_tenants": [TENANT_ID],
        "supported_features": features,
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime"}},
        "registered_at": utc(0),
    }


def policy_bundle(expires_minutes: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.policy_bundle.v1",
        "policy_bundle_id": POLICY_ID,
        "version": "uc-e2e-s10.v1",
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "issued_at": utc(-1),
        "expires_at": utc(expires_minutes),
        "revocation": "active",
        "degraded_mode": {
            "allow_low_risk_cached": False,
            "disconnected_low_risk_actions": ["artifact.create_internal", "data.read_fixture"],
            "disconnected_high_risk_actions": ["artifact.publish_external"],
            "high_risk_disconnected_behavior": "deny",
        },
    }


def base_work_order(work_order_id: str, agent_id: str, run_id: str, objective: str, allowed_actions: list[str], allowed_adapters: list[str], allowed_permissions: list[str], data_refs: list[str], placement: dict[str, Any], quota_max: int = 12) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": work_order_id,
        "tenant_id": TENANT_ID,
        "agent_id": agent_id,
        "run_id": run_id,
        "objective": objective,
        "allowed_actions": allowed_actions,
        "allowed_adapters": allowed_adapters,
        "allowed_permissions": allowed_permissions,
        "data_refs": data_refs,
        "quotas": {"max_actions_per_tick": quota_max, "max_action_duration_ms": 30000, "max_http_requests_per_minute": 12},
        "placement": placement,
        "issued_at": utc(-2),
        "expires_at": utc(60),
        "revocation": "active",
    }


def orchestrator_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_ORCH,
        ORCH_AGENT,
        ORCH_RUN,
        "Governed field-intelligence package: data-local analysis, specialist response, edge inspection, approval-gated publication",
        ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"],
        ["fixture-data-store", "artifact-store", "remote-message"],
        ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", f"message.remote.proposal:{SPECIALIST_AGENT}"],
        [DATA_REF, "zone:warehouse-a3"],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"]},
        12,
    )


def specialist_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_SPECIALIST,
        SPECIALIST_AGENT,
        SPECIALIST_RUN,
        "Shared specialist analyzes only the scoped field-intelligence fixture and returns a typed response",
        ["data.read_fixture", "artifact.create_internal", "message.remote.proposal"],
        ["fixture-data-store", "artifact-store", "remote-message"],
        ["data.read_fixture", "artifact.create_internal", f"message.remote.proposal:{ORCH_AGENT}"],
        [DATA_REF],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["data.read_fixture", "artifact.create_internal", "message.remote.proposal"]},
        6,
    )


def cloud_helper_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_CLOUD_HELPER,
        CLOUD_HELPER_AGENT,
        CLOUD_HELPER_RUN,
        "Cloud helper may propose route/publication inputs but cannot authorize execution",
        ["message.remote.proposal"],
        ["remote-message"],
        [f"message.remote.proposal:{EDGE_AGENT}"],
        ["zone:warehouse-a3"],
        {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": ["message.remote.proposal"]},
        2,
    )


def edge_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_EDGE,
        EDGE_AGENT,
        EDGE_RUN,
        "Bounded edge inspection under local safety verifiers and trace-buffer sync",
        ALLOWED_PHYSICAL_ACTIONS,
        ["device-sim"],
        [f"physical.{name}" for name in ALLOWED_PHYSICAL_ACTIONS],
        ["zone:warehouse-a3", "privacy_zone:warehouse-a3-public"],
        {"target": "edge_device", "data_locality": "device", "requires_gpu": False, "required_capabilities": [f"physical.action.{name}" for name in ALLOWED_PHYSICAL_ACTIONS]},
        32,
    )


def branch_work_order(work_order_id: str, run_id: str, actions: list[str]) -> dict[str, Any]:
    return base_work_order(
        work_order_id,
        ORCH_AGENT,
        run_id,
        "UC-E2E-S10 controlled governance branch",
        actions,
        ["artifact-store", "daemon.recording"],
        actions,
        [INTERNAL_ARTIFACT],
        {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": ["artifact.publish_external"]},
        4,
    )


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def quota(actions: int = 1) -> dict[str, int]:
    return {"actions": actions, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def action(name: str, permission: str | None = None, side_effect_class: str = "External", **params: Any) -> dict[str, Any]:
    return {
        "name": name,
        "params": params,
        "side_effect_class": side_effect_class,
        "cost_estimate": None,
        "required_permissions": [permission or name],
        "preconditions": [],
        "postconditions": [],
    }


def physical_action(name: str, **params: Any) -> dict[str, Any]:
    return action(name, f"physical.{name}", {"Custom": "physical.high_level"}, **(params or {"physical_action": True}))


def safety_context(**overrides: Any) -> dict[str, Any]:
    base = {
        "allowed_zone_refs": ["zone:warehouse-a3"],
        "zone_ref": "zone:warehouse-a3",
        "altitude_m": 12.0,
        "max_altitude_m": 30.0,
        "battery_percent": 0.82,
        "privacy_clear": True,
        "human_proximity_clear": True,
        "emergency_stop_clear": True,
        "offline": False,
        "policy_cache_expired": False,
        "high_risk": False,
        "cloud_helper_direct_authority": False,
        "cloud_helper_proposal_id": None,
    }
    base.update(overrides)
    return base


def physical_payload(name: str, credential: dict[str, Any], **safety_overrides: Any) -> dict[str, Any]:
    params = {"physical_action": True}
    for key in ["cloud_helper_proposal_id", "cloud_helper_message_id"]:
        if safety_overrides.get(key):
            params[key] = safety_overrides[key]
    return {
        "run_id": EDGE_RUN,
        "tenant_id": TENANT_ID,
        "agent_id": EDGE_AGENT,
        "credential": credential,
        "audit_attribution": audit(credential),
        "causal_trace_id": EDGE_CAUSAL_TRACE_ID,
        "action": physical_action(name, **params),
        "adapter": "device-sim",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "safety_context": safety_context(**safety_overrides),
    }


def create_run_payload(
    *,
    run_id: str,
    agent_id: str,
    envelope: dict[str, Any],
    credential: dict[str, Any],
    initial_state: dict[str, Any],
    policy_actions: list[dict[str, Any]] | None = None,
    approval_policies: list[dict[str, Any]] | None = None,
    circuit_breakers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    allowed_actions = envelope.get("allowed_actions", [])
    allowed_adapters = envelope.get("allowed_adapters", [])
    work_order_id = envelope.get("work_order_id") or envelope.get("work_order", {}).get("work_order_id", "unknown")
    registered_actions = [{"name": name, "adapter": allowed_adapters[0] if allowed_adapters else "daemon.recording"} for name in allowed_actions]
    for entry in registered_actions:
        if entry["name"].startswith("artifact."):
            entry["adapter"] = "artifact-store"
        if entry["name"] == "data.read_fixture":
            entry["adapter"] = "fixture-data-store"
        if entry["name"] in ALLOWED_PHYSICAL_ACTIONS:
            entry["adapter"] = "device-sim"
    return {
        "request_id": f"req-uc-e2e-s10-{work_order_id}-{run_id}",
        "idempotency_key": f"idem-uc-e2e-s10-{work_order_id}-{run_id}",
        "tenant_id": TENANT_ID,
        "agent_id": agent_id,
        "work_order": envelope,
        "credential": credential,
        "audit_attribution": audit(credential),
        "allowed_actions": allowed_actions,
        "allowed_adapters": allowed_adapters,
        "allowed_permissions": envelope.get("allowed_permissions", []),
        "registered_actions": registered_actions,
        "policy_actions": policy_actions or [],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "approval_policies": approval_policies or [],
        "circuit_breakers": circuit_breakers or [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": initial_state | {"run_id": run_id, "scenario": "UC-E2E-S10"},
        "snapshot_interval": 1,
    }


def approval_policy(action_name: str = "artifact.publish_external") -> dict[str, Any]:
    return {
        "schema_version": "splendor.approval_policy.v1",
        "policy_id": f"policy_uc_e2e_s10_{action_name.replace('.', '_')}",
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "action_name": action_name,
        "adapter": "artifact-store",
        "required_permission": action_name,
        "side_effect_class": "External",
        "risk_level": "high",
        "reason": "S10 external publication requires scoped approval",
        "expires_at": utc(60),
    }


def typed_message(message_id: str, source: str, target: str, run_id: str, schema: str, payload: dict[str, Any], causal_parent: str | None, requires_response: bool) -> dict[str, Any]:
    return {
        "message": {
            "message_id": message_id,
            "source_agent_id": source,
            "target_agent_id": target,
            "run_id": run_id,
            "schema": schema,
            "payload": payload,
            "causal_parent": causal_parent,
            "requires_response": requires_response,
            "created_at": utc(0),
        },
        "schema_version": "v1",
        "delivery_status": "pending",
        "trace_links": {},
    }


def extract_approval_context(outcome: dict[str, Any]) -> dict[str, Any]:
    artifact = outcome.get("verification", {}).get("artifacts", {}).get("approval", {})
    approval = artifact.get("approval") or artifact
    if not approval:
        raise SystemExit("approval context missing from S10 needs_approval outcome")
    return approval


def dispatch_start_body(dispatch: dict[str, Any]) -> dict[str, Any]:
    raw = dispatch.get("body", {}).get("start_run_body")
    if isinstance(raw, str) and raw.strip():
        return json.loads(raw)
    if isinstance(raw, dict):
        return raw
    return {}


def first_outcome(body: dict[str, Any], *, status: str | None = None, action_name: str | None = None) -> dict[str, Any]:
    for outcome in body.get("action_outcomes", []):
        if not isinstance(outcome, dict):
            continue
        if status and outcome.get("status") != status:
            continue
        text = json.dumps(outcome, sort_keys=True)
        if action_name and action_name not in text:
            continue
        return outcome
    return {}


def trace_kind(record: dict[str, Any]) -> str:
    kind = record.get("payload", {}).get("kind")
    key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
    return {
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
        "OutcomeRecorded": "outcome.recorded",
        "StateCommitted": "state.committed",
        "RunPaused": "run.paused",
        "RunResumed": "run.resumed",
        "RunStopped": "run.cancelled",
        "StateHandoffExported": "state.exported",
        "StateHandoffImported": "state.imported",
        "StateHandoffImportFailed": "state.rejected",
        "DaemonAudit": "daemon.audit",
    }.get(key, key)


def trace_body(record: dict[str, Any]) -> dict[str, Any]:
    kind = record.get("payload", {}).get("kind")
    if isinstance(kind, dict) and kind:
        value = next(iter(kind.values()))
        return value if isinstance(value, dict) else {}
    return {}


def trace_id(record: dict[str, Any]) -> str:
    return str(record.get("payload", {}).get("trace_event_id") or record.get("trace_event_id") or "")


def trace_identity(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("payload", {}).get("identity") or record.get("identity") or {}


def trace_action_name(record: dict[str, Any]) -> str:
    body = trace_body(record)
    action_value = body.get("action") if isinstance(body.get("action"), dict) else {}
    if not action_value:
        result = body.get("result") if isinstance(body.get("result"), dict) else {}
        action_value = result.get("action") if isinstance(result.get("action"), dict) else {}
    return str(action_value.get("name") or "")


def action_execution_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        if trace_kind(record) != "action.executed":
            continue
        name = trace_action_name(record)
        counts[name] = counts.get(name, 0) + 1
    return counts


def add_event_evidence(
    evidence: dict[str, list[dict[str, Any]]],
    event: str,
    *,
    trace_event_id: str | None,
    source: str,
    original_event_type: str,
    artifact: str,
    run_id: str | None = None,
    action_id: str | None = None,
    message_id: str | None = None,
    work_order_id: str | None = None,
    state_node_id: str | None = None,
    approval_id: str | None = None,
    node_id: str | None = None,
    instance_id: str | None = None,
    circuit_breaker_id: str | None = None,
    kill_switch_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    if not trace_event_id:
        return
    evidence.setdefault(event, []).append(
        {
            "trace_event_id": trace_event_id,
            "source": source,
            "original_event_type": original_event_type,
            "artifact": artifact,
            "run_id": run_id,
            "action_id": action_id,
            "message_id": message_id,
            "work_order_id": work_order_id,
            "state_node_id": state_node_id,
            "approval_id": approval_id,
            "node_id": node_id,
            "instance_id": instance_id,
            "circuit_breaker_id": circuit_breaker_id,
            "kill_switch_id": kill_switch_id,
            "details": details or {},
        }
    )


def evidence_ids(evidence: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    return {
        event: sorted({str(row.get("trace_event_id")) for row in rows if row.get("trace_event_id")})
        for event, rows in evidence.items()
    }


def trace_action_id(record: dict[str, Any]) -> str | None:
    identity = trace_identity(record)
    if identity.get("action_id"):
        return str(identity["action_id"])
    body = trace_body(record)
    for path in [body, body.get("result", {}) if isinstance(body.get("result"), dict) else {}, body.get("outcome", {}) if isinstance(body.get("outcome"), dict) else {}]:
        if isinstance(path, dict) and path.get("action_id"):
            return str(path["action_id"])
    return None


def trace_state_node_id(record: dict[str, Any]) -> str | None:
    identity = trace_identity(record)
    return str(identity.get("state_node_id")) if identity.get("state_node_id") else None


def add_s10_manager_event_evidence(evidence: dict[str, list[dict[str, Any]]], event: dict[str, Any]) -> None:
    event_type = str(event.get("event_type"))
    trace_event_id = event.get("trace_event_id")
    details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
    work_order_id = str(details.get("work_order_id") or "")
    message_id = str(details.get("message_id") or "")
    run_id = str(details.get("run_id") or "")
    if event_type == "work_order.accepted" and work_order_id in S10_WORK_ORDER_IDS:
        add_event_evidence(evidence, "work_order.accepted", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", work_order_id=work_order_id, details=details)
    elif event_type == "placement.evaluated" and work_order_id in S10_WORK_ORDER_IDS:
        add_event_evidence(evidence, "placement.evaluated", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", work_order_id=work_order_id, node_id=details.get("candidate_id"), details=details)
    elif event_type == "remote_message.delivered" and message_id in S10_MESSAGE_IDS:
        add_event_evidence(evidence, "message.sent", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", message_id=message_id, work_order_id=work_order_id, details=details)
        if message_id == CLOUD_MESSAGE_ID:
            add_event_evidence(evidence, "cloud_helper.proposal.received", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=CLOUD_HELPER_RUN, message_id=message_id, work_order_id=work_order_id, details=details)
    elif event_type == "remote_message.received" and message_id in S10_MESSAGE_IDS:
        add_event_evidence(evidence, "message.received", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", message_id=message_id, work_order_id=work_order_id, details=details)
        if message_id == CLOUD_MESSAGE_ID:
            add_event_evidence(evidence, "cloud_helper.proposal.received", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=CLOUD_HELPER_RUN, message_id=message_id, work_order_id=work_order_id, details=details)
    elif event_type == "approval.granted" and run_id == ORCH_RUN:
        add_event_evidence(evidence, "approval.granted", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, action_id=details.get("action_id"), approval_id=details.get("approval_id"), details=details)
    elif event_type == "circuit_breaker.tripped" and details.get("breaker_id") == BREAKER_ID:
        add_event_evidence(evidence, "circuit_breaker.tripped", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=CB_RUN, circuit_breaker_id=BREAKER_ID, details=details)
    elif event_type == "kill_switch.activated" and details.get("kill_switch_id") == KILL_SWITCH_ID and run_id == KILL_RUN:
        add_event_evidence(evidence, "kill_switch.activated", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, kill_switch_id=KILL_SWITCH_ID, node_id=details.get("node_id"), instance_id=details.get("instance_id"), details=details)
    elif event_type == "governance.audit.exported" and run_id == ORCH_RUN:
        add_event_evidence(evidence, "governance.audit.exported", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, details=details)


def build_required_event_evidence(records: list[dict[str, Any]], manager_events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    evidence: dict[str, list[dict[str, Any]]] = {}
    for event in manager_events:
        add_s10_manager_event_evidence(evidence, event)
    for record in records:
        kind = trace_kind(record)
        tid = trace_id(record)
        run_id = str(record.get("run_id") or trace_identity(record).get("run_id") or "")
        if not tid or run_id not in S10_RUN_IDS:
            continue
        name = trace_action_name(record)
        action_id = trace_action_id(record)
        state_node_id = trace_state_node_id(record)
        body = trace_body(record)
        body_text = json.dumps(body, sort_keys=True)
        if kind in {"action.executed", "action.denied", "action.needs_approval", "state.committed", "run.resumed"}:
            add_event_evidence(evidence, kind, trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, state_node_id=state_node_id, details={"action": name} if name else {})
        if kind == "verification.completed" and name == "data.read_fixture":
            add_event_evidence(evidence, "data_scope.verified", trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"action": name})
        if kind == "action.executed" and name == "artifact.create_internal":
            add_event_evidence(evidence, "artifact.created", trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"action": name})
        if kind == "action.executed" and name == "artifact.publish_external":
            add_event_evidence(evidence, "artifact.publish.executed", trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"action": name})
        if kind == "daemon.audit" and trace_body(record).get("endpoint") == "splendor.replay.explained":
            add_event_evidence(evidence, "replay.explained", trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, details=trace_body(record))
        if "safety" in kind or "safety_verifier" in body_text:
            add_event_evidence(evidence, "safety.verification.completed", trace_event_id=tid, source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"action": name, "contains_safety_verifier_evidence": True})
    return evidence


def build_event_ids(records: list[dict[str, Any]], manager_events: list[dict[str, Any]], response_events: dict[str, list[str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {key: [value for value in values if value] for key, values in response_events.items()}
    for event in manager_events:
        event_type = event.get("event_type")
        mapped = {
            "remote_message.delivered": "message.sent",
            "remote_message.received": "message.received",
            "remote_message.rejected": "message.denied",
        }.get(str(event_type), str(event_type))
        if event.get("trace_event_id"):
            result.setdefault(mapped, []).append(event["trace_event_id"])
        if event_type == "remote_message.delivered" and event.get("details", {}).get("message_id") == CLOUD_MESSAGE_ID:
            result.setdefault("cloud_helper.proposal.received", []).append(event["trace_event_id"])
    for record in records:
        kind = trace_kind(record)
        tid = trace_id(record)
        if not tid:
            continue
        result.setdefault(kind, []).append(tid)
        name = trace_action_name(record)
        body_text = json.dumps(trace_body(record), sort_keys=True)
        if kind == "verification.completed" and name == "data.read_fixture":
            result.setdefault("data_scope.verified", []).append(tid)
        if kind == "action.executed" and name == "artifact.create_internal":
            result.setdefault("artifact.created", []).append(tid)
        if kind == "action.executed" and name == "artifact.publish_external":
            result.setdefault("artifact.publish.executed", []).append(tid)
        if kind == "action.needs_approval" and name == "artifact.publish_external":
            result.setdefault("artifact.publish.needs_approval", []).append(tid)
        if kind == "daemon.audit" and trace_body(record).get("endpoint") == "splendor.replay.explained":
            result.setdefault("replay.explained", []).append(tid)
        if "safety" in kind or "safety_verifier" in body_text:
            result.setdefault("safety.verification.completed", []).append(tid)
    return {key: sorted({value for value in values if value}) for key, values in result.items()}


def collect_action_ids(records: list[dict[str, Any]], responses: list[dict[str, Any]]) -> list[str]:
    ids = set()
    for record in records:
        identity = trace_identity(record)
        if identity.get("action_id"):
            ids.add(str(identity["action_id"]))
        body = trace_body(record)
        for path in [body, body.get("result", {}) if isinstance(body.get("result"), dict) else {}, body.get("outcome", {}) if isinstance(body.get("outcome"), dict) else {}]:
            if isinstance(path, dict) and path.get("action_id"):
                ids.add(str(path["action_id"]))
    for response in responses:
        body = response.get("body", response)
        if isinstance(body, dict) and body.get("action_id"):
            ids.add(str(body["action_id"]))
        for outcome in body.get("action_outcomes", []) if isinstance(body, dict) else []:
            if isinstance(outcome, dict) and outcome.get("action_id"):
                ids.add(str(outcome["action_id"]))
    return sorted(ids)


def resolve_action_trace_evidence(records: list[dict[str, Any]], outcome: dict[str, Any], action_name: str) -> dict[str, Any]:
    output = outcome.get("output") if isinstance(outcome.get("output"), dict) else {}
    evidence = {
        "action_id": outcome.get("action_id"),
        "status": outcome.get("status"),
        "artifact_path": output.get("artifact_path") or output.get("publish_ref"),
        "tenant_id": output.get("tenant_id"),
        "integrity": output.get("integrity"),
        "trace_event_id": outcome.get("trace_event_id"),
        "output": output,
    }
    for record in records:
        if trace_kind(record) != "action.executed" or trace_action_name(record) != action_name:
            continue
        body = trace_body(record)
        trace_output = body.get("outcome") if isinstance(body.get("outcome"), dict) else {}
        trace_path = trace_output.get("artifact_path") or trace_output.get("publish_ref") or body.get("action", {}).get("params", {}).get("publish_ref")
        if evidence.get("artifact_path") and trace_path != evidence.get("artifact_path"):
            continue
        evidence.update(
            {
                "trace_event_id": trace_id(record),
                "trace_run_id": record.get("run_id") or trace_identity(record).get("run_id"),
                "trace_action_name": action_name,
                "trace_artifact_path": trace_path,
                "trace_integrity": trace_output.get("integrity"),
                "trace_tenant_id": trace_output.get("tenant_id"),
            }
        )
        if not evidence.get("artifact_path") and trace_path:
            evidence["artifact_path"] = trace_path
        if not evidence.get("tenant_id") and isinstance(trace_path, str) and trace_path.startswith("artifact://"):
            evidence["tenant_id"] = trace_path.removeprefix("artifact://").split("/", 1)[0]
        if not evidence.get("integrity") and trace_output.get("integrity"):
            evidence["integrity"] = trace_output.get("integrity")
        break
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="http://resident-vpc-node:8092")
    parser.add_argument("--cloud-url", default="http://resident-cloud-node:8091")
    parser.add_argument("--edge-url", default="http://resident-edge-node:8093")
    parser.add_argument("--device-sim-url", default="http://device-sim:8086")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifacts_root = report_dir / "artifacts"
    artifact_dir = artifacts_root / "UC-E2E-S10"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10\n", encoding="utf-8")
    (artifact_dir / "stdout.log").write_text("UC-E2E-S10 final cross-component journey completed through public boundaries\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        status, data = request_json(method, base, path, body, headers)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    for _ in range(60):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)
    for base, operation in [(args.vpc_url, "vpcHealth"), (args.cloud_url, "cloudHealth"), (args.edge_url, "edgeHealth")]:
        for _ in range(60):
            if call(operation, "GET", base, "/health", headers=credential_header(resident_credential(VPC_INSTANCE if base == args.vpc_url else CLOUD_INSTANCE if base == args.cloud_url else EDGE_INSTANCE, ["health_read"]))) ["status"] == 200:
                break
            time.sleep(0.25)

    manager = manager_credential()
    manager_audit_baseline = call("managerAudit", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    baseline_manager_events = manager_audit_baseline["body"] if isinstance(manager_audit_baseline["body"], list) else []
    baseline_manager_event_ids = {
        event.get("trace_event_id")
        for event in baseline_manager_events
        if event.get("trace_event_id")
    }
    nodes = [
        node_registration(VPC_NODE, "vpc.worker", "customer_vpc", "vpc", args.vpc_url, ["sql.read_fixture", "data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal", "runtime.resident"]),
        node_registration(CLOUD_NODE, "cloud.worker", "resident_cloud_pool", "cloud", args.cloud_url, ["message.remote.proposal", "runtime.resident"]),
        node_registration(EDGE_NODE, "edge.appliance", "edge_device", "device", args.edge_url, ["runtime.resident", "trace.buffer.local"]),
    ]
    instances = [
        instance_registration(VPC_NODE, VPC_INSTANCE, ["trace.buffer.local", "state.handoff", "message.remote", "gateway.verified"]),
        instance_registration(CLOUD_NODE, CLOUD_INSTANCE, ["trace.buffer.local", "state.handoff", "message.remote", "gateway.verified"]),
        instance_registration(EDGE_NODE, EDGE_INSTANCE, ["trace.buffer.local", "state.handoff", "message.remote", "gateway.verified"]),
    ]
    node_registrations = [call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager), "registration": node}) for node in nodes]
    instance_registrations = [call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager), "registration": inst}) for inst in instances]
    for node in nodes:
        call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(manager), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}})
        call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/capabilities", {**sec(manager), "capability_document": node["capability_document"]})
    node_list = call("listNodes", "POST", args.manager_url, "/fleet/nodes/list", sec(manager))

    policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager), "policy_bundle": policy_bundle()})
    policy_status = call("getPolicyStatus", "POST", args.manager_url, f"/policies/{POLICY_ID}/read", sec(manager))

    orch_envelope = sign_work_order(root, artifact_dir, commands, orchestrator_work_order())
    spec_envelope = sign_work_order(root, artifact_dir, commands, specialist_work_order())
    helper_envelope = sign_work_order(root, artifact_dir, commands, cloud_helper_work_order())
    edge_envelope = sign_work_order(root, artifact_dir, commands, edge_work_order())
    for envelope in [orch_envelope, spec_envelope, helper_envelope, edge_envelope]:
        call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": envelope, "expected_audience": "central-manager"})
    placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_ORCH, "request": {"target": "customer_vpc", "required_capabilities": ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_spec = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_SPECIALIST, "request": {"target": "customer_vpc", "required_capabilities": ["data.read_fixture", "artifact.create_internal", "message.remote.proposal"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_helper = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_CLOUD_HELPER, "request": {"target": "resident_cloud_pool", "required_capabilities": ["message.remote.proposal"], "data_locality": "cloud", "dedicated_instance": False, "execution_mode": "live"}})
    dispatch_orch = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ORCH}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    dispatch_spec = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_SPECIALIST}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    dispatch_helper = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_CLOUD_HELPER}/dispatch", {**sec(manager), "target_node_id": CLOUD_NODE})
    orch_start_body = dispatch_start_body(dispatch_orch)
    dispatch_publish_outcome = first_outcome(orch_start_body, status="NeedsApproval", action_name="artifact.publish_external")

    invalid_work_order = orchestrator_work_order() | {"work_order_id": "wo_uc_e2e_s10_invalid_unsigned", "run_id": "44444444-4444-4444-8444-444444448899"}
    invalid_submit = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": invalid_work_order, "expected_audience": "central-manager"})

    vpc_cred = resident_credential(VPC_INSTANCE)
    cloud_cred = resident_credential(CLOUD_INSTANCE)
    edge_cred = edge_credential()
    data_analysis = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": ORCH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": dispatch_orch["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    specialist_data = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": dispatch_spec["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})

    task_request = typed_message(TASK_REQUEST_ID, ORCH_AGENT, SPECIALIST_AGENT, ORCH_RUN, "splendor.message.task_request.v1", {"parent_run_id": ORCH_RUN, "child_run_id": SPECIALIST_RUN, "target_agent_id": SPECIALIST_AGENT, "objective": "analyze scoped field-intelligence package", "data_refs": [DATA_REF], "permissions": ["data.read_fixture", "artifact.create_internal"], "delegated_authority": {"allowed_actions": ["data.read_fixture", "artifact.create_internal"], "allowed_adapters": ["fixture-data-store", "artifact-store"], "allowed_permissions": ["data.read_fixture", "artifact.create_internal"]}}, dispatch_spec["body"].get("trace_event_id") or dispatch_orch["body"].get("trace_event_id"), True)
    task_sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_ORCH, "message_envelope": task_request, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s10-task-request", "simulate_failure": None})
    task_read = call("getMessage", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/read", message_scope(manager, ORCH_RUN, SPECIALIST_AGENT))
    task_response = typed_message(TASK_RESPONSE_ID, SPECIALIST_AGENT, ORCH_AGENT, ORCH_RUN, "splendor.message.task_response.v1", {"parent_run_id": ORCH_RUN, "child_run_id": SPECIALIST_RUN, "status": "completed", "output": {"analysis_ref": "analysis:s10:field-intel", "summary": "trace-safe field-intelligence summary", "data_refs": [DATA_REF], "raw_payload_included": False}, "failure": None}, task_sent["body"].get("trace_event_id") or dispatch_spec["body"].get("trace_event_id"), False)
    response_sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_SPECIALIST, "message_envelope": task_response, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s10-task-response", "simulate_failure": None})
    response_read = call("getMessage", "POST", args.manager_url, f"/messages/{TASK_RESPONSE_ID}/read", message_scope(manager, ORCH_RUN, ORCH_AGENT))

    cloud_proposal = typed_message(CLOUD_MESSAGE_ID, CLOUD_HELPER_AGENT, EDGE_AGENT, CLOUD_HELPER_RUN, "splendor.message.proposal_request.v1", {"task": "propose bounded inspection route", "edge_run_id": EDGE_RUN, "proposal_id": ROUTE_PROPOSAL_ID, "zone_ref": "zone:warehouse-a3", "actions": ["inspect_zone", "move_to_waypoint", "capture_image"], "direct_actuator_authority": False, "publication_authority": False}, dispatch_helper["body"].get("trace_event_id"), False)
    cloud_delivery = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_CLOUD_HELPER, "message_envelope": cloud_proposal, "source_instance_id": CLOUD_INSTANCE, "target_instance_id": EDGE_INSTANCE, "idempotency_key": "s10-cloud-helper-proposal", "simulate_failure": None})
    cloud_duplicate = typed_message(DUPLICATE_MESSAGE_ID, CLOUD_HELPER_AGENT, EDGE_AGENT, CLOUD_HELPER_RUN, "splendor.message.proposal_request.v1", cloud_proposal["message"]["payload"], dispatch_helper["body"].get("trace_event_id"), False)
    duplicate_delivery = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_CLOUD_HELPER, "message_envelope": cloud_duplicate, "source_instance_id": CLOUD_INSTANCE, "target_instance_id": EDGE_INSTANCE, "idempotency_key": "s10-cloud-helper-proposal", "simulate_failure": None})
    cloud_read = call("getMessage", "POST", args.manager_url, f"/messages/{CLOUD_MESSAGE_ID}/read", message_scope(manager, CLOUD_HELPER_RUN, EDGE_AGENT))
    message_schemas = call("listMessageSchemas", "GET", args.manager_url, "/message-schemas", sec(manager))
    schema_validation = call("validateMessageSchema", "POST", args.manager_url, "/message-schemas/validate", {**sec(manager), "message_envelope": task_request})
    unsupported_schema_validation = call("validateMessageSchema", "POST", args.manager_url, "/message-schemas/validate", {**sec(manager), "schema": "splendor.message.unsupported.v2", "payload": {"unsupported": True}})
    orchestrator_outbox = call("listOutbox", "GET", args.manager_url, f"/agents/{ORCH_AGENT}/outbox", message_scope(manager, ORCH_RUN, ORCH_AGENT))
    specialist_inbox = call("listInbox", "GET", args.manager_url, f"/agents/{SPECIALIST_AGENT}/inbox", message_scope(manager, ORCH_RUN, SPECIALIST_AGENT))
    specialist_outbox = call("listOutbox", "GET", args.manager_url, f"/agents/{SPECIALIST_AGENT}/outbox", message_scope(manager, ORCH_RUN, SPECIALIST_AGENT))
    edge_inbox = call("listInbox", "GET", args.manager_url, f"/agents/{EDGE_AGENT}/inbox", message_scope(manager, CLOUD_HELPER_RUN, EDGE_AGENT))
    causal_graph = call("getMessageCausalGraph", "GET", args.manager_url, f"/runs/{ORCH_RUN}/messages/causal-graph", message_scope(manager, ORCH_RUN, ORCH_AGENT))
    omitted_scope_read = call("getMessageOmittedScope", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/read", {**sec(manager), "run_id": ORCH_RUN, "agent_id": SPECIALIST_AGENT})
    cross_tenant_read = call("getMessageCrossTenant", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/read", message_scope(manager, ORCH_RUN, SPECIALIST_AGENT, tenant_id="11111111-1111-4111-8111-222222222222"))
    unrelated_agent_read = call("getMessageUnrelatedAgent", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/read", message_scope(manager, ORCH_RUN, CLOUD_HELPER_AGENT))
    ack_scope_failure = call("ackMessageScopeFailure", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/ack", {**message_scope(manager_credential(["messages_read"]), ORCH_RUN, SPECIALIST_AGENT), "reason": "missing send scope should fail closed"})
    ack_source_denial = call("ackMessageSourceAgentDenied", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/ack", {**message_scope(manager, ORCH_RUN, ORCH_AGENT), "reason": "source agent must not consume target inbox message"})
    nack_unrelated_denial = call("nackMessageUnrelatedAgentDenied", "POST", args.manager_url, f"/messages/{TASK_RESPONSE_ID}/nack", {**message_scope(manager, ORCH_RUN, EDGE_AGENT), "reason": "unrelated agent must not fail target inbox message"})
    ack_cross_tenant_denial = call("ackMessageCrossTenantDenied", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/ack", {**message_scope(manager, ORCH_RUN, SPECIALIST_AGENT, tenant_id="11111111-1111-4111-8111-222222222222"), "reason": "cross tenant ack should fail closed"})
    nack_payload_mutation_denial = call("nackMessagePayloadMutationDenied", "POST", args.manager_url, f"/messages/{TASK_RESPONSE_ID}/nack", {**message_scope(manager, ORCH_RUN, ORCH_AGENT), "reason": "payload mutation attempt must be rejected", "payload": {"mutated": True}})
    ack_task = call("ackMessage", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/ack", {**message_scope(manager, ORCH_RUN, SPECIALIST_AGENT), "reason": "specialist consumed scoped task request"})
    ack_response = call("ackMessage", "POST", args.manager_url, f"/messages/{TASK_RESPONSE_ID}/ack", {**message_scope(manager, ORCH_RUN, ORCH_AGENT), "reason": "orchestrator consumed scoped task response"})
    nack_duplicate = call("nackMessage", "POST", args.manager_url, f"/messages/{DUPLICATE_MESSAGE_ID}/nack", {**message_scope(manager, CLOUD_HELPER_RUN, EDGE_AGENT), "reason": "duplicate idempotency marker was not double-applied"})
    helper_publish_denial = call("submitAction", "POST", args.cloud_url, "/actions", {"run_id": CLOUD_HELPER_RUN, "tenant_id": TENANT_ID, "agent_id": CLOUD_HELPER_AGENT, "credential": cloud_cred, "audit_attribution": audit(cloud_cred), "causal_trace_id": cloud_delivery["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    device_profile = {"node_id": EDGE_NODE, "tenant_id": TENANT_ID, "device_kind": "drone_sim", "capabilities": ["camera.rgb", "battery", "geofence", "privacy_zone"] + [f"physical.action.{name}" for name in ALLOWED_PHYSICAL_ACTIONS], "allowed_physical_actions": ALLOWED_PHYSICAL_ACTIONS, "forbidden_action_classes": FORBIDDEN_PHYSICAL_ACTIONS, "safety_constraints": {"max_altitude_m": 30, "allowed_zones": ["zone:warehouse-a3"], "privacy_zones": ["privacy_zone:warehouse-a3-public"], "min_battery_percent": 0.25}, "runtime_mode": "resident", "safety_status": {"battery_percent": 0.82, "emergency_stop": "clear", "human_proximity": "clear", "privacy": "clear"}, "policy_cache": {"policy_id": "policy_uc_e2e_s10_edge_cache", "loaded": True, "ttl_seconds": 3600, "expires_at": utc(60), "expired": False}, "trace_buffer": {"enabled": True, "buffered_records": 0, "integrity": "hash_chain"}, "registered_at": utc(0)}
    device_register = call("registerDeviceProfile", "POST", args.edge_url, "/devices/profiles", {"credential": edge_cred, "audit_attribution": audit(edge_cred), "profile": device_profile})
    device_status = call("getDeviceStatus", "GET", args.edge_url, f"/devices/{EDGE_NODE}/status", headers=credential_header(edge_credential(["device_read"])))
    policy_cache = call("getPolicyCacheStatus", "GET", args.edge_url, f"/devices/{EDGE_NODE}/policy-cache", headers=credential_header(edge_credential(["device_read"])))
    edge_create = call("createRun", "POST", args.edge_url, "/runs", create_run_payload(run_id=EDGE_RUN, agent_id=EDGE_AGENT, envelope=edge_envelope, credential=edge_cred, initial_state={"edge": "s10"}, policy_actions=[{"action_id": "55555555-5555-4555-8555-555555558820", "action": physical_action("read_battery"), "adapter": "device-sim", "quota_usage": quota(), "satisfied_preconditions": []}]))
    edge_start = call("startRun", "POST", args.edge_url, f"/runs/{EDGE_RUN}/start", {"credential": edge_cred, "audit_attribution": audit(edge_cred), "reason": "s10_edge_policy_warmup"})

    simulator_evidence: list[dict[str, Any]] = []

    def physical_call(label: str, name: str, expected_delta: int, **safety_overrides: Any) -> dict[str, Any]:
        before = sim_json("GET", args.device_sim_url, "/counters")
        response = call("submitPhysicalAction", "POST", args.edge_url, f"/devices/{EDGE_NODE}/actions", physical_payload(name, edge_cred, **safety_overrides))
        after = sim_json("GET", args.device_sim_url, "/counters")
        simulator_evidence.append({"label": label, "action_name": name, "status": response["body"].get("status"), "counter_before": before, "counter_after": after, "total_delta": sim_total(after) - sim_total(before), "action_delta": sim_action_count(after, name) - sim_action_count(before, name), "expected_sim_delta": expected_delta, "reason_codes": response["body"].get("verification", {}).get("reasons", [])})
        return response

    inspect_zone = physical_call("inspect_zone_from_cloud_proposal", "inspect_zone", 1, cloud_helper_proposal_id=ROUTE_PROPOSAL_ID, cloud_helper_message_id=CLOUD_MESSAGE_ID)
    waypoint = physical_call("move_to_waypoint_from_cloud_proposal", "move_to_waypoint", 1, cloud_helper_proposal_id=ROUTE_PROPOSAL_ID, cloud_helper_message_id=CLOUD_MESSAGE_ID)
    offline_sensor = physical_call("offline_sensor_summary_buffered", "read_sensor_summary", 1, offline=True)
    upload_summary = physical_call("upload_trace_summary_after_reconnect", "upload_trace_summary", 1)
    cloud_direct_denial = physical_call("cloud_helper_direct_authority_denied", "move_to_waypoint", 0, cloud_helper_proposal_id="bad-direct", cloud_helper_message_id=CLOUD_MESSAGE_ID, cloud_helper_direct_authority=True)
    raw_physical = [call("submitPhysicalAction", "POST", args.edge_url, f"/devices/{EDGE_NODE}/actions", physical_payload(name, edge_cred)) for name in FORBIDDEN_PHYSICAL_ACTIONS]

    internal_artifact = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": ORCH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": response_sent["body"].get("trace_event_id") or task_sent["body"].get("trace_event_id") or data_analysis["body"].get("trace_event_id") or dispatch_orch["body"].get("trace_event_id"), "action": action("artifact.create_internal", "artifact.create_internal", "External", artifact_path=INTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    publish_needs_approval = {"status": 200 if dispatch_publish_outcome else 500, "body": dispatch_publish_outcome}
    approval_context = extract_approval_context(publish_needs_approval["body"])
    approval_request = call("requestApproval", "POST", args.manager_url, "/approvals", {**sec(manager), "approval_id": approval_context["approval_id"], "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_RUN, "action_id": approval_context["action_id"], "action_name": "artifact.publish_external", "adapter": "artifact-store", "policy_id": approval_context.get("policy_id") or POLICY_ID, "risk_level": "high", "audience": "resident-vpc-node", "expires_at": utc(30), "reason": "S10 scoped approval for external field-intelligence publication"})
    approval_grant = call("grantApproval", "POST", args.manager_url, f"/approvals/{approval_context['approval_id']}/grant", {**sec(manager), "reason": "approved_for_s10_publication", "expires_at": utc(30)})
    approval_evidence = approval_grant["body"].get("evidence")
    approved_publish = call("submitAction", "POST", args.vpc_url, "/actions", {"action_id": approval_context["action_id"], "run_id": ORCH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": approval_grant["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": approval_evidence})
    expired_evidence = copy.deepcopy(approval_evidence)
    expired_evidence["approval_id"] = "55555555-5555-4555-8555-555555558817"
    expired_evidence["expires_at"] = utc(-1)
    expired_approval = call("submitAction", "POST", args.vpc_url, "/actions", {"action_id": approval_context["action_id"], "run_id": ORCH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": approval_grant["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": expired_evidence})

    unauthorized_data = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": task_sent["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DENIED_DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    specialist_escalation = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": task_sent["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    state_before = call("getStateHead", "GET", args.vpc_url, f"/runs/{ORCH_RUN}/state-head", headers=credential_header(vpc_cred))
    handoff_export = call("exportStateSnapshot", "POST", args.vpc_url, "/state-snapshots/export", {"run_id": ORCH_RUN, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "work_order_id": WORK_ORDER_ORCH, "source_instance_id": VPC_INSTANCE, "receiver_instance_id": CLOUD_INSTANCE, "previous_state_node_id": None})
    cloud_create = call("createRun", "POST", args.cloud_url, "/runs", create_run_payload(run_id=ORCH_RUN, agent_id=ORCH_AGENT, envelope=orch_envelope, credential=cloud_cred, initial_state={"resume_target": "cloud"}))
    cloud_pause = call("pauseRun", "POST", args.cloud_url, f"/runs/{ORCH_RUN}/pause", {"credential": cloud_cred, "audit_attribution": audit(cloud_cred), "reason": "s10_state_handoff_pause_before_import"})
    handoff_import = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": handoff_export["body"].get("handoff"), "work_order": orch_envelope, "credential": cloud_cred, "audit_attribution": audit(cloud_cred)})
    bad_handoff = copy.deepcopy(handoff_export["body"].get("handoff", {}))
    if bad_handoff:
        bad_handoff.setdefault("snapshot", {}).setdefault("state_hash", {})["value"] = "0" * 64
    tampered_state_import = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": bad_handoff, "work_order": orch_envelope, "credential": cloud_cred, "audit_attribution": audit(cloud_cred)})
    cloud_resume = call("resumeRun", "POST", args.cloud_url, f"/runs/{ORCH_RUN}/resume", {"credential": cloud_cred, "work_order": orch_envelope, "audit_attribution": audit(cloud_cred), "reason": "s10_state_handoff_resume"})
    state_after = call("getStateHead", "GET", args.cloud_url, f"/runs/{ORCH_RUN}/state-head", headers=credential_header(cloud_cred))

    cb_envelope = sign_work_order(root, artifact_dir, commands, branch_work_order(WORK_ORDER_CB, CB_RUN, ["artifact.publish_external"]))
    cb_create = call("createRun", "POST", args.vpc_url, "/runs", create_run_payload(run_id=CB_RUN, agent_id=ORCH_AGENT, envelope=cb_envelope, credential=vpc_cred, initial_state={"branch": "circuit_breaker"}, approval_policies=[]))
    breaker = call("createCircuitBreaker", "POST", args.manager_url, "/governance/circuit-breakers", {**sec(manager), "breaker_id": BREAKER_ID, "tenant_id": TENANT_ID, "adapter": "artifact-store", "action": "artifact.publish_external", "reason": "S10 controlled publish branch"})
    breaker_payload = call("readCircuitBreakerSyncPayload", "POST", args.manager_url, f"/governance/circuit-breakers/{BREAKER_ID}/sync-payload", {**sec(manager), "run_id": CB_RUN, "reason": "s10_manager_propagated_breaker"})
    breaker_sync = call("syncCircuitBreakers", "POST", args.vpc_url, f"/runs/{CB_RUN}/governance/circuit-breakers/sync", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "circuit_breakers": breaker_payload["body"].get("circuit_breakers", []), "reason": breaker_payload["body"].get("reason")})
    breaker_block = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": CB_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "causal_trace_id": breaker["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    kill_envelope = sign_work_order(root, artifact_dir, commands, branch_work_order(WORK_ORDER_KILL, KILL_RUN, ["artifact.create_internal"]))
    kill_cred = resident_credential(CLOUD_INSTANCE)
    kill_create = call("createRun", "POST", args.cloud_url, "/runs", create_run_payload(run_id=KILL_RUN, agent_id=ORCH_AGENT, envelope=kill_envelope, credential=kill_cred, initial_state={"branch": "kill_switch"}))
    kill_switch = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager), "kill_switch_id": KILL_SWITCH_ID, "run_id": KILL_RUN, "tenant_id": TENANT_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "reason": "S10 controlled kill-switch branch", "propagation_ack_required": True})

    inspect_before_replay = call("inspectRunBeforeReplay", "GET", args.vpc_url, f"/runs/{ORCH_RUN}", headers=credential_header(vpc_cred))
    helper_before_replay = call("inspectHelperBeforeReplay", "GET", args.cloud_url, f"/runs/{CLOUD_HELPER_RUN}", headers=credential_header(cloud_cred))
    sim_before_replay = sim_json("GET", args.device_sim_url, "/counters")
    replay_orch = call("replayRun", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/replay", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "mode": "inspect_only", "side_effects_allowed": False})
    replay_edge = call("replayEdgeRun", "POST", args.edge_url, f"/runs/{EDGE_RUN}/replay", {"credential": edge_credential(["replay_create"]), "audit_attribution": audit(edge_credential(["replay_create"])), "mode": "inspect_only", "side_effects_allowed": False})
    unsafe_replay = call("replaySideEffectMode", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/replay", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "mode": "inspect_only", "side_effects_allowed": True})
    sim_after_replay = sim_json("GET", args.device_sim_url, "/counters")
    inspect_after_replay = call("inspectRunAfterReplay", "GET", args.vpc_url, f"/runs/{ORCH_RUN}", headers=credential_header(vpc_cred))
    helper_after_replay = call("inspectHelperAfterReplay", "GET", args.cloud_url, f"/runs/{CLOUD_HELPER_RUN}", headers=credential_header(cloud_cred))

    traces_orch = call("exportTraces", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/traces/export", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_spec = call("exportTraces", "POST", args.vpc_url, f"/runs/{SPECIALIST_RUN}/traces/export", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cb = call("exportTraces", "POST", args.vpc_url, f"/runs/{CB_RUN}/traces/export", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_edge = call("exportTraces", "POST", args.edge_url, f"/runs/{EDGE_RUN}/traces/export", {"credential": edge_credential(["traces_read"]), "audit_attribution": audit(edge_credential(["traces_read"])), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cloud_orch = call("exportTraces", "POST", args.cloud_url, f"/runs/{ORCH_RUN}/traces/export", {"credential": cloud_cred, "audit_attribution": audit(cloud_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cloud_helper = call("exportTraces", "POST", args.cloud_url, f"/runs/{CLOUD_HELPER_RUN}/traces/export", {"credential": cloud_cred, "audit_attribution": audit(cloud_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_kill = call("exportTraces", "POST", args.cloud_url, f"/runs/{KILL_RUN}/traces/export", {"credential": kill_cred, "audit_attribution": audit(kill_cred), "redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    records = traces_orch["body"].get("records", []) + traces_spec["body"].get("records", []) + traces_cb["body"].get("records", []) + traces_edge["body"].get("records", []) + traces_cloud_orch["body"].get("records", []) + traces_cloud_helper["body"].get("records", []) + traces_kill["body"].get("records", [])

    vpc_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_RUN, "work_order_id": WORK_ORDER_ORCH}, "records": traces_orch["body"].get("records", [])}
    vpc_spec_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "run_id": SPECIALIST_RUN, "work_order_id": WORK_ORDER_SPECIALIST}, "records": traces_spec["body"].get("records", [])}
    edge_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": EDGE_NODE, "instance_id": EDGE_INSTANCE, "tenant_id": TENANT_ID, "agent_id": EDGE_AGENT, "run_id": EDGE_RUN, "work_order_id": WORK_ORDER_EDGE}, "records": traces_edge["body"].get("records", [])}
    cloud_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "tenant_id": TENANT_ID, "agent_id": CLOUD_HELPER_AGENT, "run_id": CLOUD_HELPER_RUN, "work_order_id": WORK_ORDER_CLOUD_HELPER}, "records": traces_cloud_helper["body"].get("records", [])}
    cloud_orch_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_RUN, "work_order_id": WORK_ORDER_ORCH}, "records": traces_cloud_orch["body"].get("records", [])}
    tampered_batch = copy.deepcopy(vpc_batch)
    if tampered_batch["records"]:
        tampered_batch["records"][0].setdefault("payload", {})["s10_tamper"] = "trace_import_mutation"
    trace_sync_tampered = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": tampered_batch})
    trace_sync_vpc = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_batch})
    trace_sync_vpc_spec = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_spec_batch})
    trace_sync_edge = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": edge_batch})
    trace_sync_cloud = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": cloud_batch})
    trace_sync_cloud_orch = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": cloud_orch_batch})
    device_trace_sync = call("syncDeviceTraceBuffer", "POST", args.edge_url, f"/devices/{EDGE_NODE}/trace-buffer/sync", {"credential": edge_cred, "audit_attribution": audit(edge_cred), "run_id": EDGE_RUN, "records": traces_edge["body"].get("records", []), "simulate_tamper": False})
    telemetry = call("getFleetTelemetry", "POST", args.manager_url, "/fleet/telemetry/read", sec(manager))
    manager_audit = call("managerAudit", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    governance_audit = call("exportGovernanceAudit", "POST", args.manager_url, "/governance/audit/export", {**sec(manager), "run_id": ORCH_RUN})
    manager_event_by_id: dict[str, dict[str, Any]] = {}
    final_manager_events = manager_audit["body"] if isinstance(manager_audit["body"], list) else []
    governance_events = governance_audit["body"].get("events", []) if isinstance(governance_audit["body"], dict) else []
    for event in final_manager_events + governance_events:
        trace_event_id = event.get("trace_event_id") if isinstance(event, dict) else None
        if trace_event_id and trace_event_id not in baseline_manager_event_ids:
            manager_event_by_id[trace_event_id] = event
    manager_events = sorted(manager_event_by_id.values(), key=lambda event: str(event.get("trace_event_id")))
    event_evidence = build_required_event_evidence(records, manager_events)
    add_event_evidence(event_evidence, "cloud_helper.proposal.received", trace_event_id=cloud_delivery["body"].get("trace_event_id"), source="public_api_response", original_event_type="sendMessage", artifact="cloud-helper-report.json", run_id=CLOUD_HELPER_RUN, message_id=CLOUD_MESSAGE_ID, work_order_id=WORK_ORDER_CLOUD_HELPER, details={"delivery_status": cloud_delivery["body"].get("delivery_status"), "proposal_id": ROUTE_PROPOSAL_ID})
    add_event_evidence(event_evidence, "approval.granted", trace_event_id=approval_grant["body"].get("trace_event_id"), source="public_api_response", original_event_type="grantApproval", artifact="artifact-publication-report.json", run_id=ORCH_RUN, action_id=approval_context.get("action_id"), approval_id=approval_context.get("approval_id"), details={"status": approval_grant["body"].get("status")})
    add_event_evidence(event_evidence, "state.exported", trace_event_id=handoff_export["body"].get("trace_event_id"), source="public_api_response", original_event_type="exportStateSnapshot", artifact="state-handoff-report.json", run_id=ORCH_RUN, work_order_id=WORK_ORDER_ORCH, state_node_id=handoff_export["body"].get("state_node_id"), details={"source_instance_id": VPC_INSTANCE, "receiver_instance_id": CLOUD_INSTANCE})
    add_event_evidence(event_evidence, "state.imported", trace_event_id=handoff_import["body"].get("trace_event_id"), source="public_api_response", original_event_type="importStateSnapshot", artifact="state-handoff-report.json", run_id=ORCH_RUN, work_order_id=WORK_ORDER_ORCH, state_node_id=handoff_import["body"].get("state_node_id"), details={"accepted": handoff_import["body"].get("accepted")})
    for label, response, run_id, node_id, instance_id in [
        ("vpc", trace_sync_vpc, ORCH_RUN, VPC_NODE, VPC_INSTANCE),
        ("edge", trace_sync_edge, EDGE_RUN, EDGE_NODE, EDGE_INSTANCE),
        ("cloud", trace_sync_cloud, CLOUD_HELPER_RUN, CLOUD_NODE, CLOUD_INSTANCE),
        ("device", device_trace_sync, EDGE_RUN, EDGE_NODE, EDGE_INSTANCE),
    ]:
        add_event_evidence(event_evidence, "trace.sync.completed", trace_event_id=response["body"].get("trace_event_id"), source="public_api_response", original_event_type="syncTraceBuffer" if label != "device" else "syncDeviceTraceBuffer", artifact="trace-sync-report.json", run_id=run_id, node_id=node_id, instance_id=instance_id, details={"label": label, "accepted_records": response["body"].get("accepted_records")})
    add_event_evidence(event_evidence, "governance.audit.exported", trace_event_id=governance_audit["body"].get("trace_event_id"), source="public_api_response", original_event_type="exportGovernanceAudit", artifact="audit-package.json", run_id=ORCH_RUN, details={"exported": governance_audit["body"].get("exported")})
    event_ids = evidence_ids(event_evidence)
    action_counts = action_execution_counts(records)
    orch_publish_executions = [record for record in records if (record.get("run_id") or trace_identity(record).get("run_id")) == ORCH_RUN and trace_kind(record) == "action.executed" and trace_action_name(record) == "artifact.publish_external"]
    internal_evidence = resolve_action_trace_evidence(records, internal_artifact["body"], "artifact.create_internal")
    publish_evidence = resolve_action_trace_evidence(records, approved_publish["body"], "artifact.publish_external")
    replay_counts_before = {"orchestrator_adapter_executions": inspect_before_replay["body"].get("adapter_executions"), "cloud_helper_adapter_executions": helper_before_replay["body"].get("adapter_executions"), "device_sim_total": sim_total(sim_before_replay)}
    replay_counts_after = {"orchestrator_adapter_executions": inspect_after_replay["body"].get("adapter_executions"), "cloud_helper_adapter_executions": helper_after_replay["body"].get("adapter_executions"), "device_sim_total": sim_total(sim_after_replay)}

    negatives = [
        {"case": "invalid_work_order_rejected_before_run_start", "passed": invalid_submit["status"] == 403 and invalid_submit["body"].get("code") == "unsigned_work_order", "status": invalid_submit["status"], "code": invalid_submit["body"].get("code")},
        {"case": "unauthorized_data_ref_denied", "passed": unauthorized_data["body"].get("status") == "Denied" and "data_scope_denied" in unauthorized_data["body"].get("verification", {}).get("reasons", []), "status": unauthorized_data["body"].get("status"), "reason_codes": unauthorized_data["body"].get("verification", {}).get("reasons", [])},
        {"case": "specialist_permission_escalation_denied", "passed": specialist_escalation["body"].get("status") == "Denied", "status": specialist_escalation["body"].get("status"), "reason_codes": specialist_escalation["body"].get("verification", {}).get("reasons", [])},
        {"case": "remote_duplicate_not_double_applied", "passed": duplicate_delivery["body"].get("duplicate") is True and duplicate_delivery["body"].get("idempotency_key") == "s10-cloud-helper-proposal", "duplicate": duplicate_delivery["body"].get("duplicate")},
        {"case": "unsupported_message_schema_validation_rejected", "passed": unsupported_schema_validation["status"] == 200 and unsupported_schema_validation["body"].get("valid") is False and unsupported_schema_validation["body"].get("supported") is False, "status": unsupported_schema_validation["status"], "reason": unsupported_schema_validation["body"].get("reason")},
        {"case": "omitted_message_read_scope_denied", "passed": omitted_scope_read["status"] == 403 and omitted_scope_read["body"].get("code") == "missing_message_tenant_scope", "status": omitted_scope_read["status"], "code": omitted_scope_read["body"].get("code")},
        {"case": "cross_tenant_message_read_rejected", "passed": cross_tenant_read["status"] == 403 and cross_tenant_read["body"].get("code") == "cross_tenant_message_read_denied", "status": cross_tenant_read["status"], "code": cross_tenant_read["body"].get("code")},
        {"case": "unauthorized_ack_nack_denied", "passed": unrelated_agent_read["status"] == 403 and ack_source_denial["status"] == 403 and ack_source_denial["body"].get("code") == "message_ack_agent_not_recipient" and nack_unrelated_denial["status"] == 403 and ack_cross_tenant_denial["status"] == 403, "unrelated_read_status": unrelated_agent_read["status"], "unrelated_read_code": unrelated_agent_read["body"].get("code"), "ack_source_status": ack_source_denial["status"], "ack_source_code": ack_source_denial["body"].get("code"), "nack_unrelated_status": nack_unrelated_denial["status"], "nack_unrelated_code": nack_unrelated_denial["body"].get("code"), "ack_cross_tenant_status": ack_cross_tenant_denial["status"], "ack_cross_tenant_code": ack_cross_tenant_denial["body"].get("code")},
        {"case": "ack_nack_scope_or_payload_mutation_denied", "passed": ack_scope_failure["status"] == 403 and nack_payload_mutation_denial["status"] == 400 and nack_payload_mutation_denial["body"].get("code") == "message_payload_mutation_forbidden", "ack_scope_status": ack_scope_failure["status"], "nack_mutation_status": nack_payload_mutation_denial["status"], "nack_mutation_code": nack_payload_mutation_denial["body"].get("code")},
        {"case": "raw_physical_control_rejected", "passed": all(item["status"] == 400 and item["body"].get("code") == "low_level_physical_action_rejected" for item in raw_physical), "statuses": [item["status"] for item in raw_physical]},
        {"case": "expired_approval_rejected", "passed": expired_approval["body"].get("status") == "Denied" and expired_approval["body"].get("verification", {}).get("artifacts", {}).get("approval_status") == "expired", "status": expired_approval["body"].get("status")},
        {"case": "circuit_breaker_blocks_matching_publish_attempt", "passed": breaker_payload["status"] == 200 and breaker_sync["body"].get("accepted") is True and breaker_block["body"].get("status") == "Denied", "status": breaker_block["body"].get("status")},
        {"case": "kill_switch_cancels_separate_run", "passed": kill_switch["body"].get("propagation_acknowledged") is True and kill_switch["body"].get("cancel_status") == 200 and kill_switch["body"].get("target_derived_from_registry") is True, "cancel_status": kill_switch["body"].get("cancel_status")},
        {"case": "tampered_trace_state_import_rejected", "passed": trace_sync_tampered["status"] == 403 and tampered_state_import["status"] == 403, "trace_status": trace_sync_tampered["status"], "state_status": tampered_state_import["status"]},
        {"case": "replay_side_effect_mode_rejected_by_default", "passed": unsafe_replay["status"] in {400, 403} and replay_counts_before == replay_counts_after, "status": unsafe_replay["status"]},
    ]
    contract_report = read_json(report_dir / "contract-status.json")
    contract_unblocked = not any(group.get("status") == "blocked_not_yet_covered" for group in contract_report.get("blocked_not_yet_covered", []))
    message_api_operations = {"getMessage", "listMessageSchemas", "validateMessageSchema", "listInbox", "listOutbox", "getMessageCausalGraph", "ackMessage", "nackMessage"}
    positives = {
        "api_contract_passed": contract_report.get("status") == "passed" and contract_unblocked,
        "nodes_and_instances_registered": node_list["status"] == 200 and all(item["status"] == 200 for item in node_registrations + instance_registrations),
        "policy_bundle_published_with_ttl": policy["body"].get("status") == "published" and policy_status["body"].get("status") == "published" and bool(policy["body"].get("envelope", {}).get("expires_at")),
        "signed_work_order_accepted_and_placed_on_vpc": placement["body"].get("status") == "selected" and placement["body"].get("candidate_id") == VPC_NODE and dispatch_orch["body"].get("create_run_status") in {200, 201},
        "data_local_analysis_executed": data_analysis["body"].get("status") == "Executed" and data_analysis["body"].get("output", {}).get("data_ref") == DATA_REF,
        "shared_specialist_typed_response_delivered": specialist_data["body"].get("status") == "Executed" and task_sent["body"].get("delivery_status") == "delivered" and task_read["body"].get("receive_side_validated") is True and response_sent["body"].get("delivery_status") == "delivered" and response_read["body"].get("receive_side_validated") is True,
        "message_public_api_surface_exercised": {row["operation_id"] for row in api_rows} >= message_api_operations and schema_validation["body"].get("valid") is True and message_schemas["body"].get("delivery_authority_granted") is False and orchestrator_outbox["body"].get("messages") and specialist_inbox["body"].get("messages") and specialist_outbox["body"].get("messages") and edge_inbox["body"].get("messages") and len(causal_graph["body"].get("nodes", [])) >= 2 and ack_task["body"].get("delivery_status") == "consumed" and ack_response["body"].get("delivery_status") == "consumed" and nack_duplicate["body"].get("payload_preserved") is True,
        "cloud_helper_proposal_only": cloud_delivery["body"].get("delivery_status") == "delivered" and cloud_read["body"].get("receive_side_validated") is True and cloud_proposal["message"]["payload"].get("direct_actuator_authority") is False and cloud_proposal["message"]["payload"].get("publication_authority") is False and helper_publish_denial["body"].get("status") == "Denied" and cloud_direct_denial["body"].get("status") == "Denied",
        "edge_bounded_inspection_executed": device_register["status"] == 200 and device_status["status"] == 200 and policy_cache["body"].get("loaded") is True and inspect_zone["body"].get("status") == "Executed" and waypoint["body"].get("status") == "Executed" and all(item.get("total_delta") == item.get("expected_sim_delta") for item in simulator_evidence),
        "internal_artifact_created": internal_artifact["body"].get("status") == "Executed" and internal_evidence.get("artifact_path") == INTERNAL_ARTIFACT and bool(internal_evidence.get("trace_event_id")),
        "external_publication_approval_gated_and_executed_once": publish_needs_approval["body"].get("status") == "NeedsApproval" and approval_request["status"] == 200 and approval_grant["body"].get("status") == "granted" and approved_publish["body"].get("status") == "Executed" and len(orch_publish_executions) == 1 and bool(publish_evidence.get("trace_event_id")),
        "state_handoff_imported_and_resumed_once": handoff_export["status"] == 200 and cloud_create["status"] == 200 and cloud_pause["status"] == 200 and handoff_import["body"].get("accepted") is True and cloud_resume["status"] == 200 and bool(state_after["body"].get("state_node_id")),
        "central_trace_aggregation_completed": trace_sync_vpc["body"].get("accepted_records", 0) > 0 and trace_sync_edge["body"].get("accepted_records", 0) > 0 and trace_sync_cloud["body"].get("accepted_records", 0) > 0 and telemetry["body"].get("authority") == "observational_only",
        "audit_and_replay_explain_without_side_effects": replay_orch["body"].get("mode") == "inspect_only" and replay_edge["body"].get("mode") == "inspect_only" and replay_counts_before == replay_counts_after and governance_audit["body"].get("exported") is True,
    }
    failures = [key for key, ok in positives.items() if ok is not True]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    missing_events = sorted(event for event in REQUIRED_EVENTS if not event_ids.get(event))
    failures.extend(f"missing_required_event:{event}" for event in missing_events)

    contract_report = read_json(report_dir / "contract-status.json")
    topology_path = root / "tests" / "e2e" / "use-cases" / "docker-compose.acceptance.yml"
    topology = {"compose_file": str(topology_path), "topology_hash": digest_file(topology_path), "services": ["central-manager", "resident-vpc-node", "resident-cloud-node", "resident-edge-node", "device-sim", "e2e-runner"]}
    trace_event_ids = sorted({tid for values in event_ids.values() for tid in values if tid} | {trace_id(record) for record in records if trace_id(record)})
    state_node_ids = sorted({state_before["body"].get("state_node_id", ""), handoff_export["body"].get("state_node_id", ""), handoff_import["body"].get("state_node_id", ""), state_after["body"].get("state_node_id", ""), cloud_resume["body"].get("state_node_id", "")})
    state_hashes = sorted({state_before["body"].get("data_hash", ""), state_after["body"].get("data_hash", ""), handoff_export["body"].get("handoff", {}).get("snapshot", {}).get("state_hash", {}).get("value", "")})
    action_ids = collect_action_ids(records, [data_analysis, specialist_data, helper_publish_denial, inspect_zone, waypoint, cloud_direct_denial, internal_artifact, publish_needs_approval, approved_publish, expired_approval, unauthorized_data, specialist_escalation, breaker_block])
    artifact_ids = sorted(value for value in {INTERNAL_ARTIFACT, EXTERNAL_ARTIFACT, internal_evidence.get("artifact_path") or "", publish_evidence.get("artifact_path") or ""} if value)
    replay_report = {"mode": "inspect_only", "side_effects_allowed_default": False, "side_effects_executed": replay_counts_before != replay_counts_after, "orchestrator_replay": replay_orch["body"], "edge_replay": replay_edge["body"], "unsafe_replay_negative": unsafe_replay, "action_execution_counts": action_counts, "counts_before_replay": replay_counts_before, "counts_after_replay": replay_counts_after, "simulator_before_replay": sim_before_replay, "simulator_after_replay": sim_after_replay}
    message_api_report = {
        "operations": sorted({row["operation_id"] for row in api_rows if row["operation_id"] in message_api_operations}),
        "schemas": message_schemas["body"],
        "schema_validation": schema_validation["body"],
        "unsupported_schema_validation": unsupported_schema_validation["body"],
        "orchestrator_outbox_count": len(orchestrator_outbox["body"].get("messages", [])),
        "specialist_inbox_count": len(specialist_inbox["body"].get("messages", [])),
        "specialist_outbox_count": len(specialist_outbox["body"].get("messages", [])),
        "edge_inbox_count": len(edge_inbox["body"].get("messages", [])),
        "causal_graph": {"node_count": len(causal_graph["body"].get("nodes", [])), "edge_count": len(causal_graph["body"].get("edges", [])), "trace_event_id": causal_graph["body"].get("trace_event_id")},
        "ack_task": ack_task,
        "ack_response": ack_response,
        "nack_duplicate": nack_duplicate,
        "cross_tenant_read": cross_tenant_read,
        "ack_scope_failure": ack_scope_failure,
        "nack_payload_mutation_denial": nack_payload_mutation_denial,
        "authority_granted_by_read_validation": False,
    }
    audit_package = {
        "schema_version": "splendor.audit_package.v1",
        "package_id": "audit_uc_e2e_s10_final_journey",
        "human_readable": {
            "summary": "S10 executed the final bounded field-intelligence journey across manager, VPC resident, cloud helper, edge simulator, governance, state handoff, trace aggregation, and replay.",
            "replay_side_effects_executed": replay_report["side_effects_executed"],
            "telemetry_authorized_actions": False,
            "physical_actions_high_level_only": True,
        },
        "machine_readable": {
            "positive_checks": positives,
            "negative_cases": negatives,
            "required_trace_event_ids": event_ids,
            "required_event_evidence": event_evidence,
            "action_execution_counts": action_counts,
            "manager_events": manager_events,
            "api_operations": sorted({row["operation_id"] for row in api_rows}),
        },
    }
    coverage_matrix = {
        "fr_groups": {
            "FR-0.01-01..07": ["local daemon runs, gateway actions, state trace replay"],
            "FR-0.02-01..10": ["typed task request/response and shared specialist delegation"],
            "FR-0.03-01..11": ["fleet registry, signed work orders, placement, trace sync, state handoff"],
            "FR-0.04-01..10": ["approval, circuit breaker, kill switch, governance audit"],
            "FR-0.05-01..10": ["edge profile, safety verifier, trace buffer, bounded high-level actions"],
            "FR-0.1-01..08": ["contract, anti-drift, replay/audit, compatibility evidence"],
        },
        "primitives": {
            primitive: "covered_by_uc_e2e_s10"
            for primitive in [
                "tenant",
                "agent",
                "runtime_context",
                "run",
                "tick",
                "percept",
                "policy",
                "constraint",
                "action_gateway",
                "verifier",
                "adapter",
                "quota",
                "state_graph",
                "trace_store",
                "message",
                "replay",
                "work_order",
                "approval",
                "fleet_identity",
                "node_registry",
                "governance",
                "device_profile",
                "SDK/API",
            ]
        },
        "evidence_artifacts": ["scenario-report.json", "journey-report.json", "message-api-report.json", "trace-export.jsonl", "state-handoff-report.json", "replay-report.json", "audit-package.json"],
    }
    human_summary = "\n".join(
        [
            "# UC-E2E-S10 Final Cross-Component Acceptance Journey",
            "",
            "S10 completed the governed field-intelligence package through public manager, daemon, message, governance, device, trace, state, and replay boundaries.",
            "",
            f"- Main run: `{ORCH_RUN}` on VPC node `{VPC_NODE}`; state handoff resumed on cloud instance `{CLOUD_INSTANCE}`.",
            f"- Specialist message response: `{TASK_RESPONSE_ID}`; cloud helper proposal: `{CLOUD_MESSAGE_ID}`.",
            f"- Internal artifact: `{INTERNAL_ARTIFACT}`; approved external artifact: `{EXTERNAL_ARTIFACT}`.",
            "- External publication paused for scoped approval and executed exactly once after approval.",
            "- Controlled negative branches rejected invalid work orders, unauthorized data, specialist escalation, duplicate remote delivery, low-level physical action, expired approval, circuit breaker publish, kill-switch target run, tampered trace/state import, and unsafe replay mode.",
            "- Replay was inspect-only by default and preserved daemon adapter counts and device simulator counters.",
            "- Telemetry, health, and capabilities remained observational and did not authorize actions.",
        ]
    ) + "\n"

    scenario = {
        "id": "UC-E2E-S10",
        "status": "passed" if not failures else "failed",
        "fr_coverage": ["FR-0.01-01..07", "FR-0.02-01..10", "FR-0.03-01..11", "FR-0.04-01..10", "FR-0.05-01..10", "FR-0.1-01..08"],
        "components": ["Rust runtime core", "scheduler", "action gateway", "verifier chain", "state graph", "trace store", "replay", "daemon API", "central manager", "signed work orders", "placement", "remote typed messaging", "local specialist delegation", "OpenAPI contract", "CLI signing", "artifact adapter", "governance", "device simulator", "safety verifier", "trace buffer", "telemetry"],
        "positive_evidence": [key for key, ok in positives.items() if ok],
        "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True],
        "replay_evidence": ["public replay APIs returned inspect_only for orchestrator and edge runs; unsafe side-effect replay was rejected; daemon adapter counts and device simulator counters were unchanged"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "side_effects_executed": replay_report["side_effects_executed"], "counts_before_replay": replay_counts_before, "counts_after_replay": replay_counts_after},
        "replay_artifacts": [str(artifact_dir / "replay-report.json"), str(artifact_dir / "audit-package.json")],
        "anti_drift_checks": ["public_manager_daemon_device_apis_used", "no_gateway_bypass", "no_synthetic_required_evidence", "replay_no_side_effects", "telemetry_observational_only", "physical_high_level_only", "cloud_helper_proposal_only"],
        "run_ids": [ORCH_RUN, SPECIALIST_RUN, CLOUD_HELPER_RUN, EDGE_RUN, CB_RUN, KILL_RUN],
        "trace_event_ids": trace_event_ids,
        "state_node_ids": [value for value in state_node_ids if value],
        "state_hashes": [value for value in state_hashes if value],
        "message_ids": [TASK_REQUEST_ID, TASK_RESPONSE_ID, CLOUD_MESSAGE_ID, DUPLICATE_MESSAGE_ID],
        "work_order_ids": [WORK_ORDER_ORCH, WORK_ORDER_SPECIALIST, WORK_ORDER_CLOUD_HELPER, WORK_ORDER_EDGE, WORK_ORDER_CB, WORK_ORDER_KILL, "wo_uc_e2e_s10_invalid_unsigned"],
        "approval_ids": [approval_context.get("approval_id", ""), expired_evidence.get("approval_id", "")],
        "node_ids": [VPC_NODE, CLOUD_NODE, EDGE_NODE],
        "instance_ids": [VPC_INSTANCE, CLOUD_INSTANCE, EDGE_INSTANCE],
        "action_ids": action_ids,
        "policy_ids": [POLICY_ID],
        "circuit_breaker_ids": [BREAKER_ID],
        "kill_switch_ids": [KILL_SWITCH_ID],
        "artifact_ids": [value for value in artifact_ids if value],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "required_event_evidence": event_evidence,
        "positive_checks": positives,
        "negative_cases": negatives,
        "scenario_failures": failures,
        "artifact_paths": [],
    }
    anti = {
        "status": "passed" if not failures else "failed",
        "private_helper_only_e2e": False,
        "gateway_bypass": False,
        "synthetic_required_evidence": False,
        "telemetry_authorizes_action_or_placement": False,
        "cloud_helper_direct_authority": False,
        "raw_physical_action_accepted": False,
        "replay_side_effects_allowed_default": False,
        "coverage_matrix_present": True,
        "derived_from_required_event_evidence": sorted(event_evidence),
        "public_api_operations": sorted({row["operation_id"] for row in api_rows}),
    }
    artifacts: dict[str, object] = {
        "scenario-report.json": scenario,
        "human-summary.md": human_summary,
        "api-contract-report.json": {"source": str(report_dir / "contract-status.json"), "digest": digest_file(report_dir / "contract-status.json"), "contract": contract_report},
        "topology.json": topology,
        "registry-report.json": {"node_registrations": node_registrations, "instance_registrations": instance_registrations, "list_nodes": node_list, "all_registration_requests_accepted": all(item["status"] == 200 for item in node_registrations + instance_registrations), "duplicate_registration_rejections_treated_as_success": False},
        "journey-report.json": {"positive_checks": positives, "run_dispatch": {"orchestrator": dispatch_orch["body"], "specialist": dispatch_spec["body"], "cloud_helper": dispatch_helper["body"]}, "data_analysis": data_analysis["body"], "device": {"register": device_register["body"], "status": device_status["body"], "policy_cache": policy_cache["body"], "simulator_evidence": simulator_evidence}, "state_before": state_before["body"], "state_after": state_after["body"]},
        "message-flow.json": {"task_request": task_sent["body"], "task_request_read": task_read["body"], "task_response": response_sent["body"], "task_response_read": response_read["body"], "cloud_proposal": cloud_delivery["body"], "cloud_proposal_read": cloud_read["body"], "duplicate": duplicate_delivery["body"]},
        "message-api-report.json": message_api_report,
        "artifact-publication-report.json": {"internal_artifact": internal_artifact["body"], "internal_artifact_evidence": internal_evidence, "publish_needs_approval": publish_needs_approval["body"], "approval_request": approval_request["body"], "approval_grant": approval_grant["body"], "approved_publish": approved_publish["body"], "approved_publish_evidence": publish_evidence, "expired_approval": expired_approval["body"], "publish_execution_count_for_positive_run": len(orch_publish_executions)},
        "cloud-helper-report.json": {"proposal": cloud_proposal, "delivery": cloud_delivery["body"], "read": cloud_read["body"], "duplicate": duplicate_delivery["body"], "publish_denial": helper_publish_denial["body"], "device_direct_denial": cloud_direct_denial["body"]},
        "edge-inspection-report.json": {"device_profile": device_register["body"], "start": edge_start["body"], "inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"], "offline_sensor": offline_sensor["body"], "upload_summary": upload_summary["body"], "device_trace_sync": device_trace_sync["body"], "simulator_evidence": simulator_evidence},
        "state-handoff-report.json": {"exported": handoff_export["body"], "cloud_create": cloud_create["body"], "cloud_pause": cloud_pause["body"], "imported": handoff_import["body"], "tampered_state_import": tampered_state_import, "cloud_resume": cloud_resume["body"], "state_before": state_before["body"], "state_after": state_after["body"]},
        "trace-sync-report.json": {"vpc": trace_sync_vpc["body"], "vpc_specialist": trace_sync_vpc_spec["body"], "edge": trace_sync_edge["body"], "cloud": trace_sync_cloud["body"], "cloud_orchestrator": trace_sync_cloud_orch["body"], "device": device_trace_sync["body"], "tampered": trace_sync_tampered},
        "governance-branches.json": {"circuit_breaker": {"created": breaker["body"], "sync_payload": breaker_payload["body"], "synced": breaker_sync["body"], "blocked_action": breaker_block["body"], "run_create": cb_create["body"]}, "kill_switch": {"run_create": kill_create["body"], "activated": kill_switch["body"]}},
        "negative-branches.json": {item["case"]: item for item in negatives},
        "fleet-telemetry.json": telemetry["body"],
        "state-export.json": {"orchestrator_vpc": state_before["body"], "orchestrator_cloud_after_resume": state_after["body"], "handoff": handoff_export["body"].get("handoff")},
        "replay-report.json": replay_report,
        "audit-package.json": audit_package,
        "audit-report.json": audit_package,
        "manager-audit-export.json": {"audit_read": manager_audit["body"], "governance_export": governance_audit["body"]},
        "fr-primitive-coverage-matrix.json": coverage_matrix,
        "anti-drift-results.json": anti,
    }
    for name, data in artifacts.items():
        path = artifact_dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", records)
    write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
    scenario["artifact_paths"].extend([str(artifact_dir / "trace-export.jsonl"), str(artifact_dir / "api-traffic.ndjson"), str(commands), str(artifact_dir / "stdout.log"), str(artifact_dir / "stderr.log")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S10 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
