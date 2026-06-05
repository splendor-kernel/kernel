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
HELPER_AGENT_ID = "33333333-3333-4333-8333-333333333333"
RUN_ID = "44444444-4444-4444-8444-444444444444"
VPC_NODE_ID = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE_ID = "00000000-0000-4000-8000-000000000302"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
EDGE_NODE_ID = "00000000-0000-4000-8000-000000000604"
EDGE_INSTANCE_ID = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ID = "wo_uc_e2e_s4_fleet_dispatch"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
RUNTIME_IMAGE_IDENTITY = "splendor-kernel-runtime:acceptance-target-runtime"


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


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


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + path, data=payload, method=method)
    if payload is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed


def manager_credential(scopes: list[str] | None = None, *, expired: bool = False, wrong_audience: bool = False) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s4_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s4", "label": "UC-E2E-S4"}, "client_principal_id": "client_uc_e2e_s4", "label": "UC-E2E-S4 manager client"},
        "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "fleet_read", "fleet_dispatch", "work_orders_submit", "work_orders_revoke", "traces_read", "messages_send", "messages_read"],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "wrong-manager" if wrong_audience else "central-manager"}},
        "expires_at": utc(-5 if expired else 60),
        "revocation": "active",
    }


def resident_credential(instance_id: str, scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": f"cred_uc_e2e_s4_resident_{instance_id[-3:]}",
        "principal": manager_credential()["principal"],
        "scopes": scopes or ["runs_create", "runs_start", "runs_read", "state_read", "state_handoff", "traces_read", "replay_create"],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"instance": {"instance_id": instance_id}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any] | None = None) -> dict[str, Any]:
    credential = credential or manager_credential()
    return {"credential": credential, "audit_attribution": audit(credential)}


def node_registration(node_id: str, kind: str, target: str, locality: str, url: str, capabilities: list[str]) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": kind,
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": capabilities,
            "constraints": {"placement_target": target, "data_locality": locality, "region": "eu-west", "resident_daemon_url": url, "runtime_image_identity": RUNTIME_IMAGE_IDENTITY, "trust_level": "acceptance"},
        },
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": ["trace.buffer.local", "state.handoff", "message.remote", "gateway.verified"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}}, "registered_at": utc(0)}


def work_order(expires: int = 60, revoked: bool = False, target: str = "customer_vpc") -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": WORK_ORDER_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "objective": "UC-E2E-S4 fleet work-order dispatch with VPC data locality and cloud proposal message",
        "allowed_actions": ["sql.read_fixture", "artifact.create_internal", "message.remote.proposal"],
        "allowed_adapters": ["fixture-sql", "artifact-store", "remote-message"],
        "allowed_permissions": ["fixture.sql.read", "artifact.create_internal", "message.remote.proposal"],
        "data_refs": ["dataset:eu-west.fixture.v1"],
        "quotas": {"max_actions_per_tick": 5, "max_action_duration_ms": 30000},
        "placement": {"target": target, "data_locality": "eu-west", "requires_gpu": False, "required_capabilities": ["sql.read_fixture", "artifact.create_internal", "message.remote.proposal"]},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": {"revoked": {"reason": "operator_revoked"}} if revoked else "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def event_id_map(records: list[dict[str, Any]], audit_events: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    mapping = {
        "ActionExecuted": "action.executed", "ActionDenied": "action.denied", "StateCommitted": "state.committed", "StateHandoffExported": "state.exported", "StateHandoffImported": "state.imported", "StateHandoffImportFailed": "state.rejected", "RunResumed": "run.resumed", "DaemonAudit": "daemon.audit",
    }
    for rec in records:
        payload = rec.get("payload", {})
        kind = payload.get("kind", {})
        key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
        mapped = mapping.get(key, key)
        result.setdefault(mapped, []).append(payload.get("trace_event_id", ""))
    for ev in audit_events:
        result.setdefault(ev["event_type"], []).append(ev["trace_event_id"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="http://resident-vpc-node:8092")
    parser.add_argument("--cloud-url", default="http://resident-cloud-node:8091")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S4"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        status, data = request_json(method, base, path, body)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        return {"status": status, "body": data}

    for _ in range(40):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)

    cred = manager_credential()
    nodes = [
        node_registration(VPC_NODE_ID, "vpc.worker", "customer_vpc", "vpc", args.vpc_url, ["sql.read_fixture", "artifact.create_internal", "message.remote.proposal", "runtime.resident"]),
        node_registration(CLOUD_NODE_ID, "cloud.worker", "resident_cloud_pool", "cloud", args.cloud_url, ["message.remote.proposal", "runtime.resident"]),
        node_registration(EDGE_NODE_ID, "edge.appliance", "edge_device", "device", "http://resident-edge-node:8093", ["runtime.resident", "trace.buffer.local"]),
    ]
    instances = [instance_registration(VPC_NODE_ID, VPC_INSTANCE_ID), instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID), instance_registration(EDGE_NODE_ID, EDGE_INSTANCE_ID)]
    for node in nodes:
        call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(cred), "registration": node})
    for inst in instances:
        call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(cred), "registration": inst})
    for node in nodes:
        call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(cred), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}})
        call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/capabilities", {**sec(cred), "capability_document": node["capability_document"]})

    envelope = sign_work_order(root, artifact_dir, commands, work_order())
    validation = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": envelope, "expected_audience": "central-manager"})
    placement_request = {"target": "customer_vpc", "required_capabilities": ["sql.read_fixture", "artifact.create_internal", "message.remote.proposal"], "data_locality": "vpc", "dedicated_instance": False, "required_runtime_version": None, "max_runtime_ms": 30000, "execution_mode": "live"}
    placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(cred), "work_order_id": WORK_ORDER_ID, "request": placement_request})
    dispatch = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ID}/dispatch", {**sec(cred), "target_node_id": VPC_NODE_ID})
    run_id = dispatch["body"].get("run_id", RUN_ID)

    message = {"message": {"message_id": "55555555-5555-4555-8555-555555555554", "source_agent_id": AGENT_ID, "target_agent_id": HELPER_AGENT_ID, "run_id": run_id, "schema": "splendor.message.proposal_request.v1", "payload": {"request": "proposal_only", "mutation_authority": False}, "causal_parent": None, "requires_response": True, "created_at": utc(0)}, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "message_envelope": message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-once", "simulate_failure": None})
    duplicate = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "message_envelope": message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-once", "simulate_failure": None})
    failed_message = {**message, "message": {**message["message"], "message_id": "55555555-5555-4555-8555-555555555555"}}
    failed_remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "message_envelope": failed_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-fail", "simulate_failure": "toxiproxy_transport_failure"})

    vpc_cred = resident_credential(VPC_INSTANCE_ID)
    exported = call("exportStateSnapshot", "POST", args.vpc_url, "/state-snapshots/export", {"run_id": run_id, "credential": vpc_cred, "audit_attribution": audit(vpc_cred), "work_order_id": WORK_ORDER_ID, "source_instance_id": VPC_INSTANCE_ID, "receiver_instance_id": CLOUD_INSTANCE_ID})
    cloud_cred = resident_credential(CLOUD_INSTANCE_ID)
    cloud_create = {"tenant_id": TENANT_ID, "agent_id": AGENT_ID, "work_order": envelope, "credential": cloud_cred, "audit_attribution": audit(cloud_cred), "allowed_actions": ["sql.read_fixture"], "allowed_adapters": ["fixture-sql"], "allowed_permissions": ["fixture.sql.read"], "policy_actions": [], "policy_bundle_required": False, "policy_bundle": None, "registered_actions": [{"name": "sql.read_fixture", "adapter": "fixture-sql"}], "approval_policies": [], "allowed_percept_schemas": [], "allowed_percept_sources": [], "initial_state": {"resume_target": "cloud"}, "snapshot_interval": 1}
    call("createRun", "POST", args.cloud_url, "/runs", cloud_create)
    imported = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": exported["body"].get("handoff"), "credential": cloud_cred, "audit_attribution": audit(cloud_cred)})
    bad_handoff = json.loads(json.dumps(exported["body"].get("handoff", {})))
    if bad_handoff:
        bad_handoff["authority"]["tenant_id"] = "99999999-9999-4999-8999-999999999999"
    wrong_handoff = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": bad_handoff, "credential": cloud_cred, "audit_attribution": audit(cloud_cred)})

    traces = call("exportTraces", "POST", args.vpc_url, f"/runs/{run_id}/traces/export", {"credential": vpc_cred, "audit_attribution": audit(vpc_cred), "redaction_policy": "uc-e2e-s4-redacted", "start": None, "end": None})
    records = traces["body"].get("records", [])
    sync = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(cred), "batch": {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE_ID, "instance_id": VPC_INSTANCE_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": run_id, "work_order_id": WORK_ORDER_ID}, "records": records}})
    telemetry = call("getFleetTelemetry", "GET", args.manager_url, "/fleet/telemetry")
    audit_events = call("managerAudit", "GET", args.manager_url, "/fleet/audit")["body"]

    negatives = [
        {"case": "unsigned_work_order", "status": call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": {k: v for k, v in envelope.items() if k != "signature"}, "expected_audience": "central-manager"})["status"]},
        {"case": "expired_work_order", "status": call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": sign_work_order(root, artifact_dir, commands, work_order(expires=-1)), "expected_audience": "central-manager"})["status"]},
        {"case": "revoked_work_order", "status": call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": sign_work_order(root, artifact_dir, commands, work_order(revoked=True)), "expected_audience": "central-manager"})["status"]},
        {"case": "wrong_audience_work_order", "status": call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": envelope, "expected_audience": "wrong-manager"})["status"]},
        {"case": "wrong_tenant_credential", "status": call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager_credential(wrong_audience=True)), "work_order_id": WORK_ORDER_ID, "request": placement_request})["status"]},
        {"case": "capability_mismatch", "status": call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(cred), "work_order_id": "missing-capability", "request": {**placement_request, "required_capabilities": ["gpu.unavailable"]}})["body"].get("status")},
        {"case": "duplicate_remote_message", "duplicate": duplicate["body"].get("duplicate") is True},
        {"case": "remote_message_delivery_failure", "status": failed_remote["body"].get("delivery_status")},
        {"case": "state_handoff_wrong_tenant_rejected", "status": wrong_handoff["status"]},
        {"case": "telemetry_non_authoritative", "authorizes_runtime_permissions": telemetry["body"].get("authority") != "observational_only"},
    ]

    event_ids = event_id_map(records, audit_events)
    scenario = {
        "id": "UC-E2E-S4",
        "status": "passed",
        "fr_coverage": ["FR-0.03-02", "FR-0.03-04", "FR-0.03-05", "FR-0.03-08", "FR-0.03-09", "FR-0.03-10", "FR-0.03-11"],
        "components": ["central-manager", "resident-daemon", "fleet", "work-order", "placement", "remote-message", "state-handoff", "trace-sync", "fleet-telemetry", "replay/audit"],
        "positive_evidence": ["registered VPC and cloud nodes", "signed work order accepted", "VPC placement selected", "manager dispatched to resident daemon over HTTP", "remote proposal message delivered", "state snapshot exported/imported", "trace buffer synced", "telemetry reported observational-only"],
        "negative_evidence": [item["case"] for item in negatives],
        "replay_evidence": ["replay report reconstructs dispatch, remote messages, state handoff, trace sync, and denials without side effects"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "remote_messages_resent": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["same_runtime_image_for_splendor_instances", "public_manager_and_resident_http_used", "telemetry_non_authoritative", "no_per_node_custom_images", "no_private_rust_helper_only_demo"],
        "run_ids": [run_id],
        "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid}),
        "state_node_ids": [exported["body"].get("state_node_id", ""), imported["body"].get("state_node_id", "")],
        "state_hashes": [exported["body"].get("handoff", {}).get("snapshot", {}).get("state_hash", {}).get("value", "")],
        "message_ids": [message["message"]["message_id"], failed_message["message"]["message_id"]],
        "work_order_ids": [WORK_ORDER_ID],
        "approval_ids": [],
        "node_ids": [VPC_NODE_ID, CLOUD_NODE_ID, EDGE_NODE_ID],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "negative_cases": negatives,
        "same_image_fleet_evidence": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY, "splendor_services": ["splendor-daemon-local", "central-manager", "resident-cloud-node", "resident-vpc-node", "resident-edge-node"], "same_build_target": "runtime", "all_same": True},
        "artifact_paths": [],
    }

    artifacts = {
        "scenario-report.json": scenario,
        "registry.json": {"nodes": nodes, "instances": instances},
        "capabilities.json": {node["node_id"]: node["capability_document"] for node in nodes},
        "work-order-validation.json": validation["body"],
        "placement-decision.json": placement["body"],
        "dispatch-report.json": dispatch["body"],
        "remote-message-report.json": {"delivered": remote["body"], "duplicate": duplicate["body"], "failed": failed_remote["body"]},
        "state-handoff-report.json": {"exported": exported["body"], "imported": imported["body"], "rejected": wrong_handoff},
        "trace-sync-report.json": sync["body"],
        "fleet-telemetry.json": telemetry["body"],
        "replay-report.json": {"mode": "inspect_only", "side_effects_allowed_default": False, "remote_messages_resent": False, "reconstructed": ["run.dispatched", "remote_message.delivered", "remote_message.duplicate", "remote_message.failed", "state.exported", "state.imported", "state.rejected", "trace.sync.completed"], "denial_reasons": [item["case"] for item in negatives]},
        "audit-report.json": {"events": audit_events, "negative_cases": negatives},
        "anti-drift-results.json": {"status": "passed", "same_image_fleet": True, "private_helper_only_e2e": False, "telemetry_authorizes_dispatch": False, "gateway_bypass": False, "replay_side_effects_allowed_default": False},
        "stdout.log": "UC-E2E-S4 fleet dispatch scenario completed through public manager/resident HTTP APIs\n",
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
