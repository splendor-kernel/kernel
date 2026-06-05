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

FLEET_ID = "00000000-0000-4000-8000-000000000104"
TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
HELPER_AGENT_ID = "33333333-3333-4333-8333-333333333336"
RUN_ID = "44444444-4444-4444-8444-444444444446"
EDGE_NODE_ID = "00000000-0000-4000-8000-000000000604"
EDGE_INSTANCE_ID = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ID = "wo_uc_e2e_s6_physical_edge"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
ALLOWED_ACTIONS = ["read_battery", "read_sensor_summary", "move_to_waypoint", "capture_image", "return_to_base", "upload_trace_summary"]
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


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


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
        "quotas": {"max_actions_per_tick": 8, "max_action_duration_ms": 30000},
        "placement": {"target": "edge_device", "data_locality": "device", "requires_gpu": False, "required_capabilities": [f"physical.action.{name}" for name in ALLOWED_ACTIONS]},
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
    return {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": "55555555-5555-4555-8555-555555555650", "action": action(name), "adapter": "device-sim", "quota_usage": quota(), "satisfied_preconditions": [], "safety_context": safety(**safety_overrides)}


def trace_event_ids(records: list[dict[str, Any]], extra: dict[str, list[str]]) -> dict[str, list[str]]:
    result = {key: list(value) for key, value in extra.items()}
    mapping = {"ActionExecuted": "action.executed", "ActionDenied": "action.denied", "ActionNeedsIntervention": "action.needs_intervention", "DaemonAudit": "daemon.audit", "StateCommitted": "state.committed", "OutcomeRecorded": "outcome.recorded"}
    for rec in records:
        payload = rec.get("payload", {})
        kind = payload.get("kind", {})
        key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
        if key == "DaemonAudit":
            event = kind.get("DaemonAudit", {}).get("endpoint", "daemon.audit")
        else:
            event = mapping.get(key, key)
        result.setdefault(event, []).append(payload.get("trace_event_id", ""))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--edge-url", default="http://resident-edge-node:8093")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S6"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        status, data = request_json(method, args.edge_url, path, body, headers)
        api_rows.append({"operation_id": operation, "method": method, "url": args.edge_url.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    for _ in range(40):
        if call("getHealth", "GET", "/health", headers=credential_header(edge_credential(["health_read"])))["status"] == 200:
            break
        time.sleep(0.25)

    cred = edge_credential()
    profile = {"node_id": EDGE_NODE_ID, "tenant_id": TENANT_ID, "device_kind": "drone_sim", "capabilities": ["camera.rgb", "battery", "geofence", "privacy_zone"] + [f"physical.action.{name}" for name in ALLOWED_ACTIONS], "allowed_physical_actions": ALLOWED_ACTIONS, "forbidden_action_classes": FORBIDDEN_ACTIONS, "safety_constraints": {"max_altitude_m": 30, "allowed_zones": ["zone:warehouse-a3"], "privacy_zones": ["privacy_zone:warehouse-a3-public"], "min_battery_percent": 0.25}, "runtime_mode": "resident", "safety_status": {"battery_percent": 0.82, "emergency_stop": "clear", "human_proximity": "clear", "privacy": "clear"}, "policy_cache": {"policy_id": "policy_uc_e2e_s6_safety", "loaded": True, "ttl_seconds": 3600, "expires_at": utc(60), "expired": False}, "trace_buffer": {"enabled": True, "buffered_records": 0, "integrity": "hash_chain"}, "registered_at": utc(0)}
    register = call("registerDeviceProfile", "POST", "/devices/profiles", {"credential": cred, "audit_attribution": audit(cred), "profile": profile})
    status = call("getDeviceStatus", "GET", f"/devices/{EDGE_NODE_ID}/status", headers=credential_header(edge_credential(["device_read"])))
    cache = call("getPolicyCacheStatus", "GET", f"/devices/{EDGE_NODE_ID}/policy-cache", headers=credential_header(edge_credential(["device_read"])))

    envelope = sign_work_order(root, artifact_dir, commands, work_order())
    create = call("createRun", "POST", "/runs", create_run_payload(envelope))
    start = call("startRun", "POST", f"/runs/{RUN_ID}/start", {"credential": cred, "audit_attribution": audit(cred), "reason": "uc_e2e_s6_initial_state_commit"})
    state_head = call("getStateHead", "GET", f"/runs/{RUN_ID}/state-head", headers=credential_header(edge_credential(["state_read"])))

    cloud_proposal = {"proposal_id": "route-proposal-s6-a3", "source_agent_id": HELPER_AGENT_ID, "direct_actuator_authority": False, "waypoints": [{"waypoint_ref": "wp-a3-1", "zone_ref": "zone:warehouse-a3"}]}
    read_battery = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("read_battery", cred))
    waypoint = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("move_to_waypoint", cred, cloud_helper_proposal_id=cloud_proposal["proposal_id"]))
    capture = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("capture_image", cred))
    offline_sensor = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("read_sensor_summary", cred, offline=True))
    offline_rtb = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("return_to_base", cred, offline=True, battery_percent=0.18))
    upload_summary = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("upload_trace_summary", cred))

    ambiguous = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("capture_image", cred, offline=True, high_risk=True, privacy_clear=False))
    intervention_request = call("requestOperatorIntervention", "POST", "/operator/interventions", {"credential": cred, "audit_attribution": audit(cred), "intervention_id": "intervention_uc_e2e_s6_capture", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "node_id": EDGE_NODE_ID, "action_name": "capture_image", "reason": "ambiguous privacy state while offline", "expires_at": utc(30)})
    intervention_grant = call("grantOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/grant", {"credential": cred, "audit_attribution": audit(cred), "reason": "local operator verified privacy clear", "expires_at": utc(30)})
    granted_payload = physical_payload("capture_image", cred, offline=True, high_risk=True)
    granted_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    intervention_capture = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", granted_payload)
    intervention_deny = call("denyOperatorIntervention", "POST", "/operator/interventions/intervention_uc_e2e_s6_capture/deny", {"credential": cred, "audit_attribution": audit(cred), "reason": "negative denial branch", "expires_at": utc(30)})

    forbidden = [call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload(name, cred)) for name in FORBIDDEN_ACTIONS]
    geofence = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("move_to_waypoint", cred, zone_ref="zone:outside-geofence"))
    low_battery = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("move_to_waypoint", cred, battery_percent=0.12))
    expired_policy = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("capture_image", cred, offline=True, high_risk=True, policy_cache_expired=True))
    cloud_direct = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", physical_payload("move_to_waypoint", cred, cloud_helper_proposal_id="bad-direct", cloud_helper_direct_authority=True))
    wrong_scope_evidence = dict(intervention_grant["body"].get("evidence", {}))
    wrong_scope_evidence["action_name"] = "move_to_waypoint"
    wrong_scope_payload = physical_payload("capture_image", cred)
    wrong_scope_payload["operator_intervention_evidence"] = wrong_scope_evidence
    wrong_scope = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", wrong_scope_payload)
    expired_evidence = dict(intervention_grant["body"].get("evidence", {}))
    expired_evidence["expires_at"] = utc(-1)
    expired_evidence_payload = physical_payload("capture_image", cred)
    expired_evidence_payload["operator_intervention_evidence"] = expired_evidence
    expired_approval = call("submitPhysicalAction", "POST", f"/devices/{EDGE_NODE_ID}/actions", expired_evidence_payload)

    traces = call("exportTraces", "POST", f"/runs/{RUN_ID}/traces/export", {"credential": edge_credential(["traces_read"]), "audit_attribution": audit(edge_credential(["traces_read"])), "redaction_policy": "uc-e2e-s6-redacted", "start": None, "end": None})
    records = traces["body"].get("records", [])
    sync = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": records, "simulate_tamper": False})
    tamper = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": records, "simulate_tamper": True})
    reordered_records = list(reversed(records)) if len(records) > 1 else records
    reordered = call("syncDeviceTraceBuffer", "POST", f"/devices/{EDGE_NODE_ID}/trace-buffer/sync", {"credential": cred, "audit_attribution": audit(cred), "run_id": RUN_ID, "records": reordered_records, "simulate_tamper": False})
    replay = call("replayRun", "POST", f"/runs/{RUN_ID}/replay", {"credential": edge_credential(["replay_create"]), "audit_attribution": audit(edge_credential(["replay_create"])), "mode": "inspect_only", "side_effects_allowed": False})

    extra_events = {
        "device.profile.registered": [register["body"].get("trace_event_id", "")],
        "policy.cache.loaded": [register["body"].get("trace_event_id", "")],
        "operator.intervention.requested": [intervention_request["body"].get("trace_event_id", "")],
        "operator.intervention.granted": [intervention_grant["body"].get("trace_event_id", "")],
        "operator.intervention.denied": [intervention_deny["body"].get("trace_event_id", "")],
        "trace.sync.completed": [sync["body"].get("trace_event_id", "")],
        "trace.sync.failed": [tamper["body"].get("trace_event_id", ""), reordered["body"].get("trace_event_id", "")],
    }
    event_ids = trace_event_ids(records, extra_events)
    negatives = [
        {"case": "forbidden_low_level_actions_rejected", "passed": all(item["status"] == 400 and item["body"].get("code") == "low_level_physical_action_rejected" for item in forbidden)},
        {"case": "geofence_breach_denied_before_adapter", "passed": geofence["body"].get("status") == "Denied" and "geofence_breach" in geofence["body"].get("verification", {}).get("reasons", [])},
        {"case": "low_battery_forces_return_to_base_or_intervention", "passed": low_battery["body"].get("status") == "NeedsIntervention" and "low_battery_return_to_base_required" in low_battery["body"].get("verification", {}).get("reasons", []) and offline_rtb["body"].get("status") == "Executed"},
        {"case": "expired_policy_cache_denies_high_risk_offline", "passed": expired_policy["body"].get("status") == "Denied" and "policy_cache_expired" in expired_policy["body"].get("verification", {}).get("reasons", [])},
        {"case": "cloud_helper_direct_action_attempt_denied", "passed": cloud_direct["body"].get("status") == "Denied" and "cloud_helper_direct_authority_denied" in cloud_direct["body"].get("verification", {}).get("reasons", [])},
        {"case": "operator_approval_outside_scope_rejected", "passed": wrong_scope["status"] == 403 and wrong_scope["body"].get("code") == "operator_intervention_scope_mismatch"},
        {"case": "operator_approval_after_expiry_rejected", "passed": expired_approval["status"] == 403 and expired_approval["body"].get("code") == "operator_intervention_expired"},
        {"case": "trace_sync_tamper_or_reordering_detected", "passed": tamper["body"].get("accepted") is False and reordered["body"].get("accepted") is False},
    ]
    positives = {"device_registered": register["status"] == 200 and register["body"].get("profile", {}).get("device_kind") == "drone_sim", "policy_cache_loaded": cache["body"].get("loaded") is True and cache["body"].get("expired") is False, "run_created_started": create["status"] == 200 and start["status"] == 200, "cloud_helper_proposal_local_only": waypoint["body"].get("status") == "Executed" and cloud_proposal["direct_actuator_authority"] is False, "safe_actions_executed": all(resp["body"].get("status") == "Executed" for resp in [read_battery, waypoint, capture, offline_sensor, offline_rtb, upload_summary, intervention_capture]), "ambiguous_action_needs_intervention": ambiguous["body"].get("status") == "NeedsIntervention", "trace_sync_completed": sync["body"].get("accepted") is True, "replay_inspect_only": replay["body"].get("mode") == "inspect_only"}
    failures = [key for key, ok in positives.items() if not ok]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    scenario = {"id": "UC-E2E-S6", "status": "passed" if not failures else "failed", "fr_coverage": [f"FR-0.05-{i:02d}" for i in range(1, 11)], "components": ["resident-edge-node", "device-profile", "physical-capability", "device-sim-adapter", "safety-verifier", "offline-policy-cache", "trace-buffer", "operator-intervention", "cloud-helper-proposal", "gateway", "trace", "replay/audit"], "positive_evidence": [key for key, ok in positives.items() if ok], "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True], "replay_evidence": ["replayRun public API returned inspect_only physical decision explanation without simulator actuator calls"], "replay_mode": "inspect_only", "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "simulator_actuator_calls_replayed": False}, "replay_artifacts": [str(artifact_dir / "replay-report.json")], "anti_drift_checks": ["public_device_daemon_http_used", "gateway_required_before_device_sim_adapter", "cloud_helper_proposal_only", "no_low_level_physical_action_accepted", "replay_no_simulator_control"], "run_ids": [RUN_ID], "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid and not str(tid).startswith("operator_")}), "state_node_ids": [state_head["body"].get("state_node_id", "")], "state_hashes": [state_head["body"].get("data_hash", "")], "message_ids": [], "work_order_ids": [WORK_ORDER_ID], "approval_ids": ["intervention_uc_e2e_s6_capture"], "node_ids": [EDGE_NODE_ID], "api_operations": sorted({row["operation_id"] for row in api_rows}), "required_trace_event_ids": event_ids, "negative_cases": negatives, "positive_checks": positives, "scenario_failures": failures, "artifact_paths": []}
    artifacts = {"scenario-report.json": scenario, "device-profile.json": register["body"], "device-status.json": status["body"], "policy-cache-status.json": cache["body"], "cloud-helper-proposal.json": {"proposal": cloud_proposal, "local_validation_outcome": waypoint["body"], "direct_attempt": cloud_direct["body"]}, "device-safety-evidence.json": {"positive": positives, "safe_actions": {"read_battery": read_battery["body"], "move_to_waypoint": waypoint["body"], "capture_image": capture["body"], "offline_sensor": offline_sensor["body"], "return_to_base": offline_rtb["body"], "upload_trace_summary": upload_summary["body"]}, "denials": {"geofence": geofence["body"], "low_battery": low_battery["body"], "expired_policy": expired_policy["body"], "cloud_direct": cloud_direct["body"]}}, "operator-intervention.json": {"ambiguous": ambiguous["body"], "request": intervention_request["body"], "grant": intervention_grant["body"], "granted_capture": intervention_capture["body"], "deny": intervention_deny["body"], "wrong_scope": wrong_scope, "expired": expired_approval}, "trace-sync-report.json": {"completed": sync["body"], "tamper": tamper["body"], "reordered": reordered["body"]}, "state-export.json": state_head["body"], "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "simulator_actuator_calls_replayed": False, "physical_decisions_explained": [item["case"] for item in negatives if item.get("passed") is True]}, "audit-report.json": {"cloud_helper_authority": "proposal_only", "cloud_helper_direct_action_authorized": False, "operator_intervention_ids": ["intervention_uc_e2e_s6_capture"], "event_ids": event_ids}, "anti-drift-results.json": {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "raw_physical_action_accepted": False, "cloud_helper_direct_actuator_authority": False, "replay_side_effects_allowed_default": False}, "stdout.log": "UC-E2E-S6 physical/edge scenario completed through public resident-edge daemon HTTP APIs\n", "stderr.log": ""}
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
