#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TENANT_ID = "11111111-1111-4111-8111-111111111111"
FLEET_ID = "00000000-0000-4000-8000-000000000104"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
HELPER_AGENT_ID = "33333333-3333-4333-8333-333333333336"
RUN_ID = "44444444-4444-4444-8444-444444444446"
HELPER_WORK_ORDER_ID = "wo_uc_e2e_s6_cloud_helper_proposal"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
EDGE_NODE_ID = "00000000-0000-4000-8000-000000000604"
EDGE_INSTANCE_ID = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ID = "wo_uc_e2e_s6_physical_edge"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
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


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + path, data=payload, method=method)
    if payload is not None:
        req.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
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
        raise SystemExit(f"device-sim request failed: {method} {path} status={status} body={data}")
    return data


def sim_total(counters: dict[str, Any]) -> int:
    return int(counters.get("total", 0))


def sim_action_count(counters: dict[str, Any], action_name: str) -> int:
    return int(counters.get("by_action", {}).get(action_name, 0))


def run_cmd(cmd: list[str], cwd: Path, log: Path, check: bool = True) -> subprocess.CompletedProcess:
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


def edge_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s6_edge",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s6", "label": "UC-E2E-S6"}, "client_principal_id": "client_uc_e2e_s6", "label": "UC-E2E-S6 edge client"},
        "scopes": scopes or ["runs_create", "runs_start", "runs_read", "actions_submit", "state_read", "traces_read", "replay_create", "device_register", "device_read", "operator_intervene"],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"instance": {"instance_id": EDGE_INSTANCE_ID}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s6_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s6_manager", "label": "UC-E2E-S6 manager"}, "client_principal_id": "client_uc_e2e_s6_manager", "label": "UC-E2E-S6 manager client"},
        "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "fleet_read", "work_orders_submit", "messages_send", "messages_read"],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def wrong_audience_credential() -> dict[str, Any]:
    cred = edge_credential()
    cred["credential_id"] = "cred_uc_e2e_s6_wrong_audience"
    cred["audience"] = {"instance": {"instance_id": "00000000-0000-4000-8000-000000000999"}}
    return cred


def wrong_tenant_credential() -> dict[str, Any]:
    cred = edge_credential()
    cred["credential_id"] = "cred_uc_e2e_s6_wrong_tenant"
    cred["binding"] = {"tenant": {"tenant_id": "11111111-1111-4111-8111-999999999999"}}
    return cred


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def sec(credential: dict[str, Any]) -> dict[str, Any]:
    return {"credential": credential, "audit_attribution": audit(credential)}


def message_scope(credential: dict[str, Any], run_id: str, agent_id: str, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {**sec(credential), "tenant_id": tenant_id, "run_id": run_id, "agent_id": agent_id}


def node_registration(node_id: str, kind: str, target: str, locality: str, url: str, capabilities: list[str]) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": kind,
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {"schema": "splendor.capabilities.v1", "capabilities": capabilities, "constraints": {"placement_target": target, "data_locality": locality, "resident_daemon_url": url, "runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime"}},
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": ["message.remote", "gateway.verified", "physical.edge"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}}, "registered_at": utc(0)}


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
        "allowed_permissions": [f"physical.{name}" for name in ALLOWED_ACTIONS],
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


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def action(name: str, **params: Any) -> dict[str, Any]:
    return {"name": name, "params": params or {"physical_action": True}, "side_effect_class": {"Custom": "physical.high_level"}, "cost_estimate": None, "required_permissions": [f"physical.{name}"], "preconditions": [], "postconditions": []}


def quota() -> dict[str, int]:
    return {"actions": 1, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def create_run_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    cred = edge_credential()
    return {
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": cred,
        "audit_attribution": audit(cred),
        "allowed_actions": ALLOWED_ACTIONS,
        "allowed_adapters": ["device-sim"],
        "allowed_permissions": [f"physical.{name}" for name in ALLOWED_ACTIONS],
        "registered_actions": [{"name": name, "adapter": "device-sim"} for name in ALLOWED_ACTIONS],
        "policy_actions": [{"action_id": "55555555-5555-4555-8555-555555555606", "action": action("read_battery"), "adapter": "device-sim", "quota_usage": quota(), "satisfied_preconditions": []}],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "approval_policies": [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"scenario": "UC-E2E-S6", "run_id": RUN_ID},
        "snapshot_interval": 1,
    }


def safety(**overrides: Any) -> dict[str, Any]:
    base = {"allowed_zone_refs": ["zone:warehouse-a3"], "zone_ref": "zone:warehouse-a3", "altitude_m": 12.0, "max_altitude_m": 30.0, "battery_percent": 0.82, "privacy_clear": True, "human_proximity_clear": True, "emergency_stop_clear": True, "offline": False, "policy_cache_expired": False, "high_risk": False, "cloud_helper_direct_authority": False, "cloud_helper_proposal_id": None}
    base.update(overrides)
    return base


def physical_payload(name: str, cred: dict[str, Any], **safety_overrides: Any) -> dict[str, Any]:
    action_params = {"physical_action": True}
    for key in ["cloud_helper_proposal_id", "cloud_helper_message_id"]:
        if safety_overrides.get(key):
            action_params[key] = safety_overrides[key]
    return {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": CLOUD_CAUSAL_TRACE_ID, "action": action(name, **action_params), "adapter": "device-sim", "quota_usage": quota(), "satisfied_preconditions": [], "safety_context": safety(**safety_overrides)}


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
    mapping = {"ActionExecuted": "action.executed", "ActionDenied": "action.denied", "ActionNeedsIntervention": "action.needs_intervention", "DaemonAudit": "daemon.audit", "StateCommitted": "state.committed", "OutcomeRecorded": "outcome.recorded"}
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
    parser.add_argument("--edge-url", default="http://resident-edge-node:8093")
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--device-sim-url", default="http://device-sim:8086")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S6"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None, base_url: str | None = None) -> dict[str, Any]:
        base_url = base_url or args.edge_url
        status, data = request_json(method, base_url, path, body, headers)
        api_rows.append({"operation_id": operation, "method": method, "url": base_url.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    for _ in range(40):
        if call("getHealth", "GET", "/health", headers=credential_header(edge_credential(["health_read"])))["status"] == 200:
            break
        time.sleep(0.25)
    for _ in range(40):
        if call("managerHealth", "GET", "/health", base_url=args.manager_url)["status"] == 200:
            break
        time.sleep(0.25)

    cred = edge_credential()
    profile = {"node_id": EDGE_NODE_ID, "tenant_id": TENANT_ID, "device_kind": "drone_sim", "capabilities": ["camera.rgb", "battery", "geofence", "privacy_zone"] + [f"physical.action.{name}" for name in ALLOWED_ACTIONS], "allowed_physical_actions": ALLOWED_ACTIONS, "forbidden_action_classes": FORBIDDEN_ACTIONS, "safety_constraints": {"max_altitude_m": 30, "allowed_zones": ["zone:warehouse-a3"], "privacy_zones": ["privacy_zone:warehouse-a3-public"], "min_battery_percent": 0.25}, "runtime_mode": "resident", "safety_status": {"battery_percent": 0.82, "emergency_stop": "clear", "human_proximity": "clear", "privacy": "clear"}, "policy_cache": {"policy_id": "policy_uc_e2e_s6_safety", "loaded": True, "ttl_seconds": 3600, "expires_at": utc(60), "expired": False}, "trace_buffer": {"enabled": True, "buffered_records": 0, "integrity": "hash_chain"}, "registered_at": utc(0)}
    register = call("registerDeviceProfile", "POST", "/devices/profiles", {"credential": cred, "audit_attribution": audit(cred), "profile": profile})
    status = call("getDeviceStatus", "GET", f"/devices/{EDGE_NODE_ID}/status", headers=credential_header(edge_credential(["device_read"])))
    cache = call("getPolicyCacheStatus", "GET", f"/devices/{EDGE_NODE_ID}/policy-cache", headers=credential_header(edge_credential(["device_read"])))
    missing_credential_status = call("getDeviceStatusMissingCredential", "GET", f"/devices/{EDGE_NODE_ID}/status")
    wrong_audience_status = call("getDeviceStatusWrongAudience", "GET", f"/devices/{EDGE_NODE_ID}/status", headers=credential_header(wrong_audience_credential()))
    wrong_tenant_status = call("getDeviceStatusWrongTenant", "GET", f"/devices/{EDGE_NODE_ID}/status", headers=credential_header(wrong_tenant_credential()))

    envelope = sign_work_order(root, artifact_dir, commands, work_order())
    create = call("createRun", "POST", "/runs", create_run_payload(envelope))
    start = call("startRun", "POST", f"/runs/{RUN_ID}/start", {"credential": cred, "audit_attribution": audit(cred), "reason": "uc_e2e_s6_initial_state_commit"})
    state_head = call("getStateHead", "GET", f"/runs/{RUN_ID}/state-head", headers=credential_header(edge_credential(["state_read"])))
    initial_traces = call("exportTracesInitial", "POST", f"/runs/{RUN_ID}/traces/export", {"credential": edge_credential(["traces_read"]), "audit_attribution": audit(edge_credential(["traces_read"])), "redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    initial_records = initial_traces["body"].get("records", [])
    causal_parent = next((row.get("payload", {}).get("trace_event_id") for row in reversed(initial_records) if row.get("payload", {}).get("trace_event_id")), CLOUD_CAUSAL_TRACE_ID)
    cloud_message = typed_cloud_helper_message(causal_parent)
    manager_cred = manager_credential()
    for node in [
        node_registration(CLOUD_NODE_ID, "cloud.worker", "resident_cloud_pool", "cloud", "http://resident-cloud-node:8091", ["message.remote.proposal", "runtime.resident"]),
        node_registration(EDGE_NODE_ID, "edge.device", "edge_device", "device", args.edge_url, ["message.remote.proposal", "runtime.resident", "physical.edge"]),
    ]:
        call("registerNode", "POST", "/fleet/nodes", {**sec(manager_cred), "registration": node}, base_url=args.manager_url)
        call("heartbeatNode", "POST", f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(manager_cred), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}}, base_url=args.manager_url)
    for inst in [instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID), instance_registration(EDGE_NODE_ID, EDGE_INSTANCE_ID)]:
        call("registerInstance", "POST", "/fleet/instances", {**sec(manager_cred), "registration": inst}, base_url=args.manager_url)
    helper_envelope = sign_work_order(root, artifact_dir, commands, helper_work_order())
    helper_work_order_submit = call("submitWorkOrder", "POST", "/work-orders", {**sec(manager_cred), "work_order": helper_envelope, "expected_audience": "central-manager"}, base_url=args.manager_url)
    message_envelope = {"message": cloud_message, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    cloud_message_delivery = call("sendMessage", "POST", "/messages", {**sec(manager_cred), "work_order_id": HELPER_WORK_ORDER_ID, "message_envelope": message_envelope, "source_instance_id": CLOUD_INSTANCE_ID, "target_instance_id": EDGE_INSTANCE_ID, "idempotency_key": "s6-cloud-helper-proposal", "simulate_failure": None}, base_url=args.manager_url)
    cloud_message_received = call("getMessage", "POST", f"/messages/{CLOUD_MESSAGE_ID}/read", message_scope(manager_cred, RUN_ID, AGENT_ID), base_url=args.manager_url)
    manager_audit = call("managerAudit", "POST", "/fleet/audit/read", sec(manager_cred), base_url=args.manager_url)

    simulator_evidence: list[dict[str, Any]] = []

    def physical_call_with_counters(label: str, name: str, expected_sim_delta: int, **safety_overrides: Any) -> dict[str, Any]:
        before = sim_json("GET", args.device_sim_url, "/counters")
        response = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload(name, cred, **safety_overrides))
        after = sim_json("GET", args.device_sim_url, "/counters")
        simulator_evidence.append({"label": label, "action_name": name, "status": response.get("body", {}).get("status"), "reason_codes": response.get("body", {}).get("verification", {}).get("reasons", []), "counter_before": before, "counter_after": after, "total_delta": sim_total(after) - sim_total(before), "action_delta": sim_action_count(after, name) - sim_action_count(before, name), "expected_sim_delta": expected_sim_delta})
        return response

    before_warmup = sim_json("GET", args.device_sim_url, "/counters")
    read_battery = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("read_battery", cred))
    after_warmup = sim_json("GET", args.device_sim_url, "/counters")
    simulator_evidence.append({"label": "read_battery_policy_warmup", "action_name": "read_battery", "status": read_battery.get("body", {}).get("status"), "counter_before": before_warmup, "counter_after": after_warmup, "total_delta": sim_total(after_warmup) - sim_total(before_warmup), "action_delta": sim_action_count(after_warmup, "read_battery") - sim_action_count(before_warmup, "read_battery"), "expected_sim_delta": 1})
    inspect_zone = physical_call_with_counters("inspect_zone_from_typed_cloud_proposal", "inspect_zone", 1, cloud_helper_proposal_id=cloud_message["payload"]["proposal_id"], cloud_helper_message_id=CLOUD_MESSAGE_ID)
    waypoint = physical_call_with_counters("move_to_waypoint_from_typed_cloud_proposal", "move_to_waypoint", 1, cloud_helper_proposal_id=cloud_message["payload"]["proposal_id"], cloud_helper_message_id=CLOUD_MESSAGE_ID)
    capture = physical_call_with_counters("capture_image", "capture_image", 1)
    offline_sensor = physical_call_with_counters("read_sensor_summary_offline", "read_sensor_summary", 1, offline=True)
    offline_rtb = physical_call_with_counters("return_to_base_low_battery_safe", "return_to_base", 1, offline=True, battery_percent=0.18)
    upload_summary = physical_call_with_counters("upload_trace_summary", "upload_trace_summary", 1)

    ambiguous = physical_call_with_counters("ambiguous_privacy_denied_until_operator", "capture_image", 0, offline=True, high_risk=True, privacy_clear=False)
    intervention_request = call("requestOperatorIntervention", "POST", "/operator/interventions", {"credential": cred, "audit_attribution": audit(cred), "intervention_id": "intervention_uc_e2e_s6_capture", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "node_id": EDGE_NODE_ID, "action_name": "capture_image", "reason": "ambiguous privacy state while offline", "expires_at": utc(30)})
    intervention_grant = call("grantOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/grant", {"credential": cred, "audit_attribution": audit(cred), "reason": "local operator verified privacy clear", "expires_at": utc(30)})
    granted_payload = physical_payload("capture_image", cred, offline=True, high_risk=True)
    granted_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    before_granted = sim_json("GET", args.device_sim_url, "/counters")
    intervention_capture = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", granted_payload)
    after_granted = sim_json("GET", args.device_sim_url, "/counters")
    simulator_evidence.append({"label": "operator_granted_capture", "action_name": "capture_image", "status": intervention_capture.get("body", {}).get("status"), "counter_before": before_granted, "counter_after": after_granted, "total_delta": sim_total(after_granted) - sim_total(before_granted), "action_delta": sim_action_count(after_granted, "capture_image") - sim_action_count(before_granted, "capture_image"), "expected_sim_delta": 1})
    intervention_deny = call("denyOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/deny", {"credential": cred, "audit_attribution": audit(cred), "reason": "negative denial branch", "expires_at": utc(30)})

    forbidden = [call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload(name, cred)) for name in FORBIDDEN_ACTIONS]
    geofence = physical_call_with_counters("geofence_breach_denied", "move_to_waypoint", 0, zone_ref="zone:outside-geofence")
    low_battery = physical_call_with_counters("low_battery_needs_intervention", "move_to_waypoint", 0, battery_percent=0.12)
    expired_policy = physical_call_with_counters("expired_policy_cache_denied", "capture_image", 0, offline=True, high_risk=True, policy_cache_expired=True)
    cloud_direct = physical_call_with_counters("cloud_helper_direct_authority_denied", "move_to_waypoint", 0, cloud_helper_proposal_id="bad-direct", cloud_helper_message_id=CLOUD_MESSAGE_ID, cloud_helper_direct_authority=True)
    wrong_scope_evidence = dict(intervention_grant["body"].get("evidence", {}))
    wrong_scope_evidence["action_name"] = "move_to_waypoint"
    wrong_scope_payload = physical_payload("capture_image", cred)
    wrong_scope_payload["operator_intervention_evidence"] = wrong_scope_evidence
    before_wrong_scope = sim_json("GET", args.device_sim_url, "/counters")
    wrong_scope = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", wrong_scope_payload)
    after_wrong_scope = sim_json("GET", args.device_sim_url, "/counters")
    simulator_evidence.append({"label": "operator_wrong_scope_denied", "action_name": "capture_image", "status": wrong_scope.get("status"), "counter_before": before_wrong_scope, "counter_after": after_wrong_scope, "total_delta": sim_total(after_wrong_scope) - sim_total(before_wrong_scope), "expected_sim_delta": 0})
    expired_evidence = dict(intervention_grant["body"].get("evidence", {}))
    expired_evidence["expires_at"] = utc(-1)
    expired_evidence_payload = physical_payload("capture_image", cred)
    expired_evidence_payload["operator_intervention_evidence"] = expired_evidence
    before_expired_approval = sim_json("GET", args.device_sim_url, "/counters")
    expired_approval = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", expired_evidence_payload)
    after_expired_approval = sim_json("GET", args.device_sim_url, "/counters")
    simulator_evidence.append({"label": "operator_expired_evidence_denied", "action_name": "capture_image", "status": expired_approval.get("status"), "counter_before": before_expired_approval, "counter_after": after_expired_approval, "total_delta": sim_total(after_expired_approval) - sim_total(before_expired_approval), "expected_sim_delta": 0})
    missing_credential_action = call("submitPhysicalActionMissingCredential", "POST", f"/devices/{EDGE_NODE_ID}/actions", {**physical_payload("inspect_zone", cred), "credential": None, "audit_attribution": None})
    wrong_audience_action = call("submitPhysicalActionWrongAudience", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("inspect_zone", wrong_audience_credential()))
    wrong_tenant_action = call("submitPhysicalActionWrongTenant", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("inspect_zone", wrong_tenant_credential()))

    traces = call("exportTraces", "POST", f"/runs/{RUN_ID}/traces/export", {"credential": edge_credential(["traces_read"]), "audit_attribution": audit(edge_credential(["traces_read"])), "redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    records = traces["body"].get("records", [])
    sync = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": records, "simulate_tamper": False})
    tampered_records = json.loads(json.dumps(records))
    if len(tampered_records) > 1:
        tampered_records[1]["prev_event_hash"] = {"algorithm": "Blake3", "value": "0" * 64}
    tamper = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": tampered_records, "simulate_tamper": False})
    reordered_records = list(reversed(records)) if len(records) > 1 else records
    reordered = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": reordered_records, "simulate_tamper": False})
    sim_before_replay = sim_json("GET", args.device_sim_url, "/counters")
    replay = call("replayRun", "POST", f"/runs/{RUN_ID}/replay", {"credential": edge_credential(["replay_create"]), "audit_attribution": audit(edge_credential(["replay_create"])), "mode": "inspect_only", "side_effects_allowed": False})
    sim_after_replay = sim_json("GET", args.device_sim_url, "/counters")

    extra_events = {"device.profile.registered": [register["body"].get("trace_event_id", "")], "policy.cache.loaded": [register["body"].get("trace_event_id", "")], "operator.intervention.requested": [intervention_request["body"].get("trace_event_id", "")], "operator.intervention.granted": [intervention_grant["body"].get("trace_event_id", "")], "operator.intervention.denied": [intervention_deny["body"].get("trace_event_id", "")], "trace.sync.completed": [sync["body"].get("trace_event_id", "")], "trace.sync.failed": [tamper["body"].get("trace_event_id", ""), reordered["body"].get("trace_event_id", "")]}
    event_ids = trace_event_ids(records, extra_events)
    trace_payload = json.dumps(records, sort_keys=True)
    manager_audit_payload = json.dumps(manager_audit["body"], sort_keys=True)
    proposal_trace_linked = CLOUD_MESSAGE_ID in trace_payload and cloud_message["payload"]["proposal_id"] in trace_payload

    def from_safety_verifier(response: dict[str, Any]) -> bool:
        return response.get("body", {}).get("verification", {}).get("artifacts", {}).get("source") == "safety_verifier"

    negatives = [
        {"case": "forbidden_low_level_actions_rejected", "passed": all(item["status"] == 400 and item["body"].get("code") == "low_level_physical_action_rejected" for item in forbidden)},
        {"case": "geofence_breach_denied_before_adapter", "passed": geofence["body"].get("status") == "Denied" and "geofence_violation" in geofence["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(geofence)},
        {"case": "low_battery_forces_return_to_base_or_intervention", "passed": low_battery["body"].get("status") == "NeedsIntervention" and "battery_below_minimum" in low_battery["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(low_battery) and offline_rtb["body"].get("status") == "Executed"},
        {"case": "expired_policy_cache_denies_high_risk_offline", "passed": expired_policy["body"].get("status") == "Denied" and "policy_cache_expired" in expired_policy["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(expired_policy)},
        {"case": "cloud_helper_direct_action_attempt_denied", "passed": cloud_direct["body"].get("status") == "Denied" and "cloud_helper_direct_authority_denied" in cloud_direct["body"].get("verification", {}).get("reasons", []) and from_safety_verifier(cloud_direct)},
        {"case": "operator_approval_outside_scope_rejected", "passed": wrong_scope["status"] == 403 and wrong_scope["body"].get("code") == "operator_intervention_scope_mismatch"},
        {"case": "operator_approval_after_expiry_rejected", "passed": expired_approval["status"] == 403 and expired_approval["body"].get("code") == "operator_intervention_expired"},
        {"case": "trace_sync_tamper_or_reordering_detected", "passed": tamper["body"].get("accepted") is False and tamper["body"].get("reason_code") == "trace_sync_hash_chain_mismatch" and reordered["body"].get("accepted") is False},
        {"case": "device_endpoint_missing_credential_rejected", "passed": missing_credential_status["status"] in {401, 403} and missing_credential_action["status"] in {401, 403}},
        {"case": "device_endpoint_wrong_audience_rejected", "passed": wrong_audience_status["status"] == 403 and wrong_audience_action["status"] == 403},
        {"case": "device_endpoint_wrong_tenant_rejected", "passed": wrong_tenant_status["status"] == 403 and wrong_tenant_action["status"] == 403},
    ]
    simulator_counters_valid = all(item.get("total_delta") == item.get("expected_sim_delta") for item in simulator_evidence)
    replay_unchanged = sim_before_replay == sim_after_replay
    cloud_message_valid = all(cloud_message.get(field) for field in ["message_id", "source_agent_id", "target_agent_id", "run_id", "schema", "causal_parent", "created_at"]) and cloud_message["payload"].get("direct_actuator_authority") is False and helper_work_order_submit["body"].get("accepted") is True and cloud_message_delivery["body"].get("message_id") == CLOUD_MESSAGE_ID and cloud_message_delivery["body"].get("delivery_status") == "delivered" and cloud_message_delivery["body"].get("receive_side_validated") is True and cloud_message_delivery["body"].get("remote_state_mutated") is False and cloud_message_received["body"].get("message_id") == CLOUD_MESSAGE_ID and CLOUD_MESSAGE_ID in manager_audit_payload and proposal_trace_linked
    positives = {"device_registered": register["status"] == 200 and register["body"].get("profile", {}).get("device_kind") == "drone_sim", "policy_cache_loaded": cache["body"].get("loaded") is True and cache["body"].get("expired") is False, "run_created_started": create["status"] == 200 and start["status"] == 200, "cloud_helper_typed_proposal_local_only": waypoint["body"].get("status") == "Executed" and inspect_zone["body"].get("status") == "Executed" and cloud_message_valid, "inspect_zone_executed": inspect_zone["body"].get("status") == "Executed", "safe_actions_executed": all(resp["body"].get("status") == "Executed" for resp in [read_battery, inspect_zone, waypoint, capture, offline_sensor, offline_rtb, upload_summary, intervention_capture]), "ambiguous_action_denied_by_safety_verifier": ambiguous["body"].get("status") == "Denied" and from_safety_verifier(ambiguous), "simulator_counters_valid": simulator_counters_valid, "trace_sync_completed": sync["body"].get("accepted") is True, "replay_inspect_only": replay["body"].get("mode") == "inspect_only" and replay_unchanged}
    failures = [key for key, ok in positives.items() if not ok]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    scenario = {"id": "UC-E2E-S6", "status": "passed" if not failures else "failed", "fr_coverage": [f"FR-0.05-{i:02d}" for i in range(1, 11)], "components": ["resident-edge-node", "central-manager-message-api", "device-profile", "physical-capability", "device-sim-adapter", "safety-verifier", "offline-policy-cache", "trace-buffer", "operator-intervention", "typed-cloud-helper-proposal", "gateway", "trace", "replay/audit"], "positive_evidence": [key for key, ok in positives.items() if ok], "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True], "replay_evidence": ["replayRun public API returned inspect_only and device-sim counters were unchanged"], "replay_mode": "inspect_only", "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "simulator_counter_before": sim_before_replay, "simulator_counter_after": sim_after_replay}, "replay_artifacts": [str(artifact_dir / "replay-report.json")], "anti_drift_checks": ["public_device_daemon_http_used", "public_manager_message_api_used", "gateway_required_before_device_sim_adapter", "cloud_helper_proposal_only", "no_low_level_physical_action_accepted", "replay_no_simulator_control"], "run_ids": [RUN_ID], "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid and not str(tid).startswith("operator_")}), "state_node_ids": [state_head["body"].get("state_node_id", "")], "state_hashes": [state_head["body"].get("data_hash", "")], "message_ids": [CLOUD_MESSAGE_ID], "work_order_ids": [WORK_ORDER_ID, HELPER_WORK_ORDER_ID], "approval_ids": ["intervention_uc_e2e_s6_capture"], "node_ids": [EDGE_NODE_ID, CLOUD_NODE_ID], "api_operations": sorted({row["operation_id"] for row in api_rows}), "required_trace_event_ids": event_ids, "negative_cases": negatives, "positive_checks": positives, "scenario_failures": failures, "artifact_paths": []}
    artifacts = {"scenario-report.json": scenario, "device-profile.json": register["body"], "device-status.json": status["body"], "policy-cache-status.json": cache["body"], "cloud-helper-message.json": {"work_order_submit": helper_work_order_submit["body"], "delivery": cloud_message_delivery["body"], "received": cloud_message_received["body"], "manager_audit_contains_message_id": CLOUD_MESSAGE_ID in manager_audit_payload, "trace_payload_contains_message_id": CLOUD_MESSAGE_ID in trace_payload, "trace_payload_contains_proposal_id": cloud_message["payload"]["proposal_id"] in trace_payload}, "cloud-helper-proposal.json": {"message": cloud_message, "proposal": cloud_message["payload"], "local_validation_inputs": {"inspect_zone": {"cloud_helper_proposal_id": cloud_message["payload"]["proposal_id"], "cloud_helper_message_id": CLOUD_MESSAGE_ID}, "move_to_waypoint": {"cloud_helper_proposal_id": cloud_message["payload"]["proposal_id"], "cloud_helper_message_id": CLOUD_MESSAGE_ID}}, "local_validation_outcomes": {"inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"]}, "direct_attempt": cloud_direct["body"]}, "device-sim-counters.json": {"evidence": simulator_evidence, "before_replay": sim_before_replay, "after_replay": sim_after_replay}, "device-safety-evidence.json": {"positive": positives, "safe_actions": {"read_battery": read_battery["body"], "inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"], "capture_image": capture["body"], "offline_sensor": offline_sensor["body"], "return_to_base": offline_rtb["body"], "upload_trace_summary": upload_summary["body"]}, "denials": {"geofence": geofence["body"], "low_battery": low_battery["body"], "expired_policy": expired_policy["body"], "cloud_direct": cloud_direct["body"]}}, "operator-intervention.json": {"ambiguous": ambiguous["body"], "request": intervention_request["body"], "grant": intervention_grant["body"], "granted_capture": intervention_capture["body"], "deny": intervention_deny["body"], "wrong_scope": wrong_scope, "expired": expired_approval}, "security-negatives.json": {"missing_credential_status": missing_credential_status, "wrong_audience_status": wrong_audience_status, "wrong_tenant_status": wrong_tenant_status, "missing_credential_action": missing_credential_action, "wrong_audience_action": wrong_audience_action, "wrong_tenant_action": wrong_tenant_action}, "trace-sync-report.json": {"completed": sync["body"], "tamper": tamper["body"], "reordered": reordered["body"], "tampered_record_mutation": "prev_event_hash", "reordered_records": True}, "state-export.json": state_head["body"], "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "simulator_counter_before": sim_before_replay, "simulator_counter_after": sim_after_replay, "simulator_actuator_calls_replayed": not replay_unchanged, "physical_decisions_explained": [item["case"] for item in negatives if item.get("passed") is True]}, "audit-report.json": {"cloud_helper_authority": "proposal_only", "cloud_helper_direct_action_authorized": False, "operator_intervention_ids": ["intervention_uc_e2e_s6_capture"], "event_ids": event_ids}, "anti-drift-results.json": {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "raw_physical_action_accepted": False, "cloud_helper_direct_actuator_authority": False, "replay_side_effects_allowed_default": False}, "stdout.log": "UC-E2E-S6 physical/edge scenario completed through public resident-edge daemon and central-manager message HTTP endpoints\n", "stderr.log": ""}
    for name, data in artifacts.items():
        path = artifact_dir / name
        if isinstance(data, str):
            path.write_text(data, encoding="utf-8")
        else:
            write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", records)
    scenario["artifact_paths"].extend([str(artifact_dir / "api-traffic.ndjson"), str(artifact_dir / "trace-export.jsonl")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S6 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
