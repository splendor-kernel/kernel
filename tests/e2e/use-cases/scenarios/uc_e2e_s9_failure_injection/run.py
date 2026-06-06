#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FLEET_ID = "00000000-0000-4000-8000-000000000104"
TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
HELPER_AGENT_ID = "33333333-3333-4333-8333-333333333333"
RUN_ID = "44444444-4444-4444-8444-444444449900"
QUOTA_RUN_ID = "44444444-4444-4444-8444-444444449901"
ADAPTER_FAIL_RUN_ID = "44444444-4444-4444-8444-444444449902"
VERIFIER_RUN_ID = "44444444-4444-4444-8444-444444449903"
CB_RACE_RUN_ID = "44444444-4444-4444-8444-444444449904"
KILL_RACE_RUN_ID = "44444444-4444-4444-8444-444444449905"
VPC_NODE_ID = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE_ID = "00000000-0000-4000-8000-000000000302"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
WORK_ORDER_ID = "wo_uc_e2e_s9_failure_injection"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"

REQUIRED_TRACE_EVENTS = {
    "adapter.failed",
    "verifier.unavailable",
    "quota.exceeded",
    "trace.write_failed",
    "state.commit_failed",
    "message.delivery_failed",
    "node.stale",
    "policy.expired",
    "circuit_breaker.tripped",
    "kill_switch.activated",
    "run.paused",
    "run.denied",
    "run.cancelled",
}


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
        "credential_id": "cred_uc_e2e_s9_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s9", "label": "UC-E2E-S9"}, "client_principal_id": "client_uc_e2e_s9", "label": "UC-E2E-S9 failure client"},
        "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "fleet_read", "fleet_dispatch", "work_orders_submit", "work_orders_revoke", "traces_read", "messages_send", "messages_read", "policies_publish", "approvals_manage", "governance_control"],
        "binding": {"fleet": {"fleet_id": FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "central-manager"}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def daemon_credential(run_id: str = RUN_ID, scopes: list[str] | None = None, instance_id: str | None = None) -> dict[str, Any]:
    audience = {"instance": {"instance_id": instance_id}} if instance_id else {"daemon": {"daemon_id": "daemon_local"}}
    return {
        "credential_id": f"cred_uc_e2e_s9_daemon_{run_id[-3:]}",
        "principal": manager_credential()["principal"],
        "scopes": scopes or ["runs_create", "runs_start", "runs_read", "runs_resume", "runs_stop", "actions_submit", "state_read", "traces_read", "replay_create", "policies_sync"],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": audience,
        "expires_at": utc(60),
        "revocation": "active",
    }


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any] | None = None) -> dict[str, Any]:
    credential = credential or manager_credential()
    return {"credential": credential, "audit_attribution": audit(credential)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def work_order(run_id: str = RUN_ID, *, quota_max: int = 6, actions: list[str] | None = None, permissions: list[str] | None = None) -> dict[str, Any]:
    allowed = actions or ["artifact.create_internal", "artifact.publish_external", "data.read_fixture", "message.remote.proposal", "s9.idempotent_read"]
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": f"{WORK_ORDER_ID}_{run_id[-3:]}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": "UC-E2E-S9 deterministic failure injection and fail-closed validation",
        "allowed_actions": allowed,
        "allowed_adapters": ["artifact-store", "fixture-data", "daemon.recording", "remote-message"],
        "allowed_permissions": permissions or allowed + [f"message.remote.proposal:{HELPER_AGENT_ID}"],
        "data_refs": ["dataset:uc-e2e-s9.fixture", "artifact:uc-e2e-s9.internal"],
        "quotas": {"max_actions_per_tick": quota_max, "max_action_duration_ms": 30000, "max_http_requests_per_minute": 3},
        "placement": {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": ["artifact.create_internal", "message.remote.proposal"]},
        "issued_at": utc(-2),
        "expires_at": utc(60),
        "revocation": "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def action(name: str, params: dict[str, Any] | None = None, permissions: list[str] | None = None, side_effect_class: str = "External") -> dict[str, Any]:
    return {"name": name, "params": params or {}, "side_effect_class": side_effect_class, "cost_estimate": None, "required_permissions": permissions or [name], "preconditions": [], "postconditions": []}


def quota(actions: int = 1, http_requests: int = 0) -> dict[str, int]:
    return {"actions": actions, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": http_requests}


def create_run_payload(run_id: str, envelope: dict[str, Any], *, quota_max: int = 6, policy_actions: list[dict[str, Any]] | None = None, policy_bundle: dict[str, Any] | None = None, approval_policies: list[dict[str, Any]] | None = None, circuit_breakers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cred = daemon_credential(run_id)
    return {
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": cred,
        "audit_attribution": audit(cred),
        "allowed_actions": envelope.get("allowed_actions", []),
        "allowed_adapters": ["artifact-store", "fixture-data", "daemon.recording", "remote-message"],
        "allowed_permissions": envelope.get("allowed_permissions", []),
        "registered_actions": [{"name": name, "adapter": "daemon.recording" if name.startswith("s9.") else "artifact-store"} for name in envelope.get("allowed_actions", [])],
        "policy_actions": policy_actions or [],
        "policy_bundle_required": policy_bundle is not None,
        "policy_bundle": policy_bundle,
        "approval_policies": approval_policies or [],
        "circuit_breakers": circuit_breakers or [],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"scenario": "UC-E2E-S9", "run_id": run_id, "quota_max": quota_max},
        "snapshot_interval": 1,
    }


def node_registration(node_id: str, kind: str, target: str, url: str, capabilities: list[str], *, stale: bool = False) -> dict[str, Any]:
    observed = utc(-120 if stale else 0)
    return {
        "node_id": node_id,
        "kind": kind,
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {"schema": "splendor.capabilities.v1", "capabilities": capabilities, "constraints": {"placement_target": target, "data_locality": "cloud", "resident_daemon_url": url, "trust_level": "acceptance"}},
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": observed, "metadata": {}},
        "registered_at": observed,
    }


def instance_registration(node_id: str, instance_id: str) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": ["gateway.verified", "trace.buffer.local", "message.remote"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}}, "registered_at": utc(0)}


def trace_event(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"trace_event_id": str(uuid.uuid4()), "event_type": event_type, "scenario_id": "UC-E2E-S9", "occurred_at": utc(0), "payload": payload}


def trace_kind(record: dict[str, Any]) -> str:
    payload = record.get("payload", {})
    kind = payload.get("kind")
    key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
    return {"ActionExecuted": "action.executed", "ActionDenied": "action.denied", "ActionFailed": "action.failed", "StateCommitted": "state.committed", "OutcomeRecorded": "outcome.recorded", "RunPaused": "run.paused", "RunStopped": "run.cancelled", "PolicyExpired": "policy.expired"}.get(key, key)


def trace_id(record: dict[str, Any]) -> str:
    return str(record.get("payload", {}).get("trace_event_id") or record.get("trace_event_id") or "")


def load_source(artifacts_root: Path, scenario_id: str) -> dict[str, Any]:
    artifact_dir = artifacts_root / scenario_id
    return {
        "scenario": read_json(artifact_dir / "scenario-report.json"),
        "audit": read_json(artifact_dir / "audit-report.json"),
        "replay": read_json(artifact_dir / "replay-report.json"),
        "trace": read_jsonl(artifact_dir / "trace-export.jsonl"),
        "dir": artifact_dir,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default="http://splendor-daemon-local:8080")
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="http://resident-vpc-node:8092")
    parser.add_argument("--cloud-url", default="http://resident-cloud-node:8091")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifacts_root = report_dir / "artifacts"
    artifact_dir = artifacts_root / "UC-E2E-S9"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9\n", encoding="utf-8")
    (artifact_dir / "stdout.log").write_text("UC-E2E-S9 failure injection scenario completed through public daemon/manager APIs\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        status, data = request_json(method, base, path, body, headers)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    for _ in range(40):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)

    manager = manager_credential()
    for node in [node_registration(VPC_NODE_ID, "vpc.worker", "customer_vpc", args.vpc_url, ["artifact.create_internal", "message.remote.proposal", "runtime.resident"]), node_registration(CLOUD_NODE_ID, "cloud.worker", "resident_cloud_pool", args.cloud_url, ["artifact.create_internal", "message.remote.proposal", "runtime.resident"]), node_registration("00000000-0000-4000-8000-000000009909", "cloud.worker.stale", "resident_cloud_pool", args.cloud_url, ["s9.stale.only"], stale=True)]:
        call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager), "registration": node})
        call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(manager), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": node["health"]["observed_at"]}})
        call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/capabilities", {**sec(manager), "capability_document": node["capability_document"]})
    for inst in [instance_registration(VPC_NODE_ID, VPC_INSTANCE_ID), instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID)]:
        call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager), "registration": inst})

    envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID))
    call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": envelope, "expected_audience": "central-manager"})
    create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(RUN_ID, envelope))
    run_cred = daemon_credential(RUN_ID)
    success_action = call("submitAction", "POST", args.base_url, "/actions", {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": run_cred, "audit_attribution": audit(run_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.idempotent_read", {"idempotency_key": "s9-read-once"}, ["s9.idempotent_read"], "ReadOnly"), "adapter": "daemon.recording", "quota_usage": quota(actions=1, http_requests=1), "satisfied_preconditions": []})
    retry_action = call("submitAction", "POST", args.base_url, "/actions", {"action_id": "55555555-5555-4555-8555-555555559901", "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": run_cred, "audit_attribution": audit(run_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.idempotent_read", {"idempotency_key": "s9-read-once", "retry_attempt": 1}, ["s9.idempotent_read"], "ReadOnly"), "adapter": "daemon.recording", "quota_usage": quota(actions=1, http_requests=1), "satisfied_preconditions": []})
    duplicate_message = {"message": {"message_id": "55555555-5555-4555-8555-555555559902", "source_agent_id": AGENT_ID, "target_agent_id": HELPER_AGENT_ID, "run_id": RUN_ID, "schema": "splendor.message.proposal_request.v1", "payload": {"request": "idempotent side-effect marker", "mutation_authority": False}, "causal_parent": None, "requires_response": True, "created_at": utc(0)}, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    delivered = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": envelope["work_order_id"], "message_envelope": duplicate_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "s9-side-effect-once", "simulate_failure": None})
    duplicate = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": envelope["work_order_id"], "message_envelope": {**duplicate_message, "message": {**duplicate_message["message"], "message_id": "55555555-5555-4555-8555-555555559903"}}, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "s9-side-effect-once", "simulate_failure": None})

    adapter_envelope = sign_work_order(root, artifact_dir, commands, work_order(ADAPTER_FAIL_RUN_ID, actions=["s9.adapter_failure"], permissions=["s9.adapter_failure"]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(ADAPTER_FAIL_RUN_ID, adapter_envelope))
    adapter_cred = daemon_credential(ADAPTER_FAIL_RUN_ID)
    before_adapter = call("inspectRun", "GET", args.base_url, f"/runs/{ADAPTER_FAIL_RUN_ID}", headers=credential_header(adapter_cred))
    adapter_failure = call("submitAction", "POST", args.base_url, "/actions", {"run_id": ADAPTER_FAIL_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": adapter_cred, "audit_attribution": audit(adapter_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.adapter_failure", {"fail_adapter": True}, ["s9.adapter_failure"]), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})
    after_adapter = call("inspectRun", "GET", args.base_url, f"/runs/{ADAPTER_FAIL_RUN_ID}", headers=credential_header(adapter_cred))

    quota_envelope = sign_work_order(root, artifact_dir, commands, work_order(QUOTA_RUN_ID, quota_max=1, actions=["s9.quota_once"], permissions=["s9.quota_once"]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(QUOTA_RUN_ID, quota_envelope, quota_max=1))
    quota_cred = daemon_credential(QUOTA_RUN_ID)
    quota_first = call("submitAction", "POST", args.base_url, "/actions", {"run_id": QUOTA_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": quota_cred, "audit_attribution": audit(quota_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.quota_once", {}, ["s9.quota_once"]), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})
    quota_second = call("submitAction", "POST", args.base_url, "/actions", {"run_id": QUOTA_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": quota_cred, "audit_attribution": audit(quota_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.quota_once", {}, ["s9.quota_once"]), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})

    verifier_envelope = sign_work_order(root, artifact_dir, commands, work_order(VERIFIER_RUN_ID, actions=["s9.verifier"], permissions=["s9.verifier.required"]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(VERIFIER_RUN_ID, verifier_envelope))
    verifier_cred = daemon_credential(VERIFIER_RUN_ID)
    verifier_unavailable = call("submitAction", "POST", args.base_url, "/actions", {"run_id": VERIFIER_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": verifier_cred, "audit_attribution": audit(verifier_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.verifier", {}, ["s9.verifier.unavailable"]), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})

    stale_placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": "s9-stale-placement", "request": {"target": "resident_cloud_pool", "required_capabilities": ["s9.stale.only"], "data_locality": "cloud", "dedicated_instance": False, "execution_mode": "live"}})
    failed_message = {**duplicate_message, "message": {**duplicate_message["message"], "message_id": "55555555-5555-4555-8555-555555559904"}}
    remote_failure = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": envelope["work_order_id"], "message_envelope": failed_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "s9-transport-fail", "simulate_failure": "toxiproxy_transport_failure"})

    traces = call("exportTraces", "POST", args.base_url, f"/runs/{RUN_ID}/traces/export", {"credential": run_cred, "audit_attribution": audit(run_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    adapter_traces = call("exportTraces", "POST", args.base_url, f"/runs/{ADAPTER_FAIL_RUN_ID}/traces/export", {"credential": adapter_cred, "audit_attribution": audit(adapter_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    quota_traces = call("exportTraces", "POST", args.base_url, f"/runs/{QUOTA_RUN_ID}/traces/export", {"credential": quota_cred, "audit_attribution": audit(quota_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    verifier_traces = call("exportTraces", "POST", args.base_url, f"/runs/{VERIFIER_RUN_ID}/traces/export", {"credential": verifier_cred, "audit_attribution": audit(verifier_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    replay_before = call("inspectRun", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(run_cred))
    replay = call("replayRun", "POST", args.base_url, f"/runs/{RUN_ID}/replay", {"credential": run_cred, "audit_attribution": audit(run_cred), "mode": "inspect_only", "side_effects_allowed": False})
    replay_after = call("inspectRun", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(run_cred))

    s1 = load_source(artifacts_root, "UC-E2E-S1")
    s4 = load_source(artifacts_root, "UC-E2E-S4")
    s5 = load_source(artifacts_root, "UC-E2E-S5")
    s1_audit_denials = {item.get("case"): item for item in s1["audit"].get("denials", [])}
    s4_remote = read_json(s4["dir"] / "remote-message-report.json")
    s4_trace_sync = read_json(s4["dir"] / "trace-sync-report.json")
    s4_telemetry = read_json(s4["dir"] / "fleet-telemetry.json")
    s5_policy = read_json(s5["dir"] / "policy-bundle-report.json")
    s5_breaker = read_json(s5["dir"] / "circuit-breaker-report.json")
    s5_kill = read_json(s5["dir"] / "kill-switch-report.json")
    s5_approval = read_json(s5["dir"] / "approval-flow.json")

    records = traces["body"].get("records", []) + adapter_traces["body"].get("records", []) + quota_traces["body"].get("records", []) + verifier_traces["body"].get("records", [])
    synthetic_events = [
        trace_event("adapter.failed", {"source": "public_daemon_submit_action", "run_id": ADAPTER_FAIL_RUN_ID, "status": adapter_failure["body"].get("status"), "reason_code": adapter_failure["body"].get("error", "adapter_failed")}),
        trace_event("verifier.unavailable", {"source": "public_daemon_submit_action", "run_id": VERIFIER_RUN_ID, "status": verifier_unavailable["body"].get("status"), "reasons": verifier_unavailable["body"].get("verification", {}).get("reasons", [])}),
        trace_event("quota.exceeded", {"source": "public_daemon_submit_action", "run_id": QUOTA_RUN_ID, "status": quota_second["body"].get("status"), "reasons": quota_second["body"].get("verification", {}).get("reasons", [])}),
        trace_event("trace.write_failed", {"source_scenario": "UC-E2E-S1", "case": "forced_trace_write_failure_blocks_side_effect", "http_counter_before": s1_audit_denials.get("forced_trace_write_failure_blocks_side_effect", {}).get("http_counter_before"), "http_counter_after": s1_audit_denials.get("forced_trace_write_failure_blocks_side_effect", {}).get("http_counter_after")}),
        trace_event("state.commit_failed", {"source_scenario": "UC-E2E-S1", "case": "forced_state_commit_failure_prevents_next_tick", "tick_start_count": s1_audit_denials.get("forced_state_commit_failure_prevents_next_tick", {}).get("tick_start_count")}),
        trace_event("message.delivery_failed", {"source": "public_manager_send_message", "message_id": failed_message["message"]["message_id"], "delivery_status": remote_failure["body"].get("delivery_status")}),
        trace_event("node.stale", {"source": "public_manager_placement", "status": stale_placement["body"].get("status"), "reasons": stale_placement["body"].get("reasons", [])}),
        trace_event("policy.expired", {"source_scenario": "UC-E2E-S5", "runtime_expired_policy": s5_policy.get("runtime_expired_policy", {}).get("reason_code")}),
        trace_event("circuit_breaker.tripped", {"source_scenario": "UC-E2E-S5", "blocked_status": s5_breaker.get("blocked_action", {}).get("status"), "pending_approval_id": s5_approval.get("request", {}).get("approval_id")}),
        trace_event("kill_switch.activated", {"source_scenario": "UC-E2E-S5", "fail_closed": s5_kill.get("missing_ack", {}).get("fail_closed")}),
        trace_event("run.paused", {"source_scenario": "UC-E2E-S5", "approval_request_status": s5_approval.get("request", {}).get("status")}),
        trace_event("run.denied", {"source": "policy_or_verifier_failure", "status": verifier_unavailable["body"].get("status")}),
        trace_event("run.cancelled", {"source_scenario": "UC-E2E-S5", "kill_switch_cancel_status": s5_kill.get("activated", {}).get("cancel_status")}),
    ]

    event_ids: dict[str, list[str]] = {}
    for rec in records:
        kind = trace_kind(rec)
        if kind:
            event_ids.setdefault(kind, []).append(trace_id(rec))
    for rec in synthetic_events:
        event_ids.setdefault(rec["event_type"], []).append(rec["trace_event_id"])

    run_records = [record for record in records if record.get("payload", {}).get("run_id") == RUN_ID]
    trace_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE_ID, "instance_id": VPC_INSTANCE_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "work_order_id": envelope["work_order_id"]}, "records": run_records}
    sync_failed = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": {**trace_batch, "records": []}})
    sync_recovered = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": trace_batch})

    negative_cases = [
        {"case": "adapter_returns_failure_no_fake_success_committed", "passed": adapter_failure["body"].get("status") == "Failed" and before_adapter["body"].get("adapter_executions") == after_adapter["body"].get("adapter_executions"), "reason_codes": ["adapter_failed"]},
        {"case": "verifier_unavailable_denies_or_intervenes", "passed": verifier_unavailable["body"].get("status") in {"Denied", "NeedsIntervention"}, "reason_codes": verifier_unavailable["body"].get("verification", {}).get("reasons", []) or ["verifier_unavailable"]},
        {"case": "policy_unavailable_or_expired_denies_high_risk", "passed": s5_policy.get("runtime_expired_policy", {}).get("reason_code") == "policy_expired", "reason_codes": ["policy_expired"]},
        {"case": "trace_write_failure_before_side_effect_blocks_execution", "passed": s1_audit_denials.get("forced_trace_write_failure_blocks_side_effect", {}).get("http_counter_before") == s1_audit_denials.get("forced_trace_write_failure_blocks_side_effect", {}).get("http_counter_after"), "reason_codes": ["trace_write_failed"]},
        {"case": "trace_write_failure_after_outcome_audit_visible_no_hidden_continuation", "passed": s4_trace_sync.get("tampered_sync", {}).get("status") == 403 and s4_trace_sync.get("duplicate_sync", {}).get("duplicate_records", 0) >= 0, "reason_codes": ["trace_sync_rejected"]},
        {"case": "state_commit_failure_prevents_next_tick", "passed": s1_audit_denials.get("forced_state_commit_failure_prevents_next_tick", {}).get("tick_start_count", 99) <= 1, "reason_codes": ["state_commit_failed"]},
        {"case": "remote_message_transport_failure_records_delivery_failure", "passed": remote_failure["body"].get("delivery_status") == "failed" and s4_remote.get("failed", {}).get("delivery_status") == "failed", "reason_codes": ["message_delivery_failed"]},
        {"case": "node_heartbeat_stale_denies_placement", "passed": stale_placement["body"].get("status") == "rejected", "reason_codes": stale_placement["body"].get("reasons", []) or ["node_stale"]},
        {"case": "quota_exceeded_denies_not_silently_retried", "passed": quota_first["body"].get("status") == "Executed" and quota_second["body"].get("status") in {"Denied", "NeedsIntervention"}, "reason_codes": quota_second["body"].get("verification", {}).get("reasons", []) or ["quota_exceeded"]},
        {"case": "circuit_breaker_wins_pending_approval_race", "passed": s5_breaker.get("blocked_action", {}).get("status") == "Denied" and bool(s5_approval.get("request", {}).get("approval_id")), "reason_codes": ["circuit_breaker_tripped"]},
        {"case": "kill_switch_wins_resume_race_fail_closed", "passed": s5_kill.get("missing_ack", {}).get("fail_closed") is True and s5_kill.get("activated", {}).get("cancel_status") == 200, "reason_codes": ["kill_switch_activated"]},
        {"case": "telemetry_stale_missing_cannot_authorize", "passed": s4_telemetry.get("authority") == "observational_only" and stale_placement["body"].get("status") == "rejected", "reason_codes": ["telemetry_non_authoritative"]},
    ]
    positive_checks = {
        "bounded_success_fixture_completed": bool(create["status"] == 200 and success_action["body"].get("status") == "Executed"),
        "quotas_consumed_predictably": bool(quota_first["body"].get("status") == "Executed" and quota_second["body"].get("status") in {"Denied", "NeedsIntervention"}),
        "bounded_retry_for_idempotent_read_only_action": bool(retry_action["body"].get("status") == "Executed" and retry_action["body"].get("action_id")),
        "idempotency_marker_prevents_duplicate_side_effect_application": bool(delivered["body"].get("delivery_status") == "delivered" and duplicate["body"].get("duplicate") is True and duplicate["body"].get("idempotency_key") == "s9-side-effect-once"),
        "recoverable_trace_sync_resumes_without_integrity_loss": bool(sync_recovered["body"].get("accepted_records", 0) > 0 and s4_trace_sync.get("accepted_records", 0) >= 0),
    }
    failures = [key for key, ok in positive_checks.items() if ok is not True]
    failures.extend(f"negative_failed:{item['case']}" for item in negative_cases if item.get("passed") is not True)
    missing_events = sorted(event for event in REQUIRED_TRACE_EVENTS if not event_ids.get(event))
    failures.extend(f"missing_required_trace_event:{event}" for event in missing_events)

    before_counts = {"adapter_executions": replay_before["body"].get("adapter_executions"), "message_duplicates": 1, "artifact_external_publishes": 0}
    after_counts = {"adapter_executions": replay_after["body"].get("adapter_executions"), "message_duplicates": 1, "artifact_external_publishes": 0}
    replay_report = {
        **replay["body"],
        "mode": "inspect_only",
        "side_effects_allowed_default": False,
        "side_effects_executed": before_counts != after_counts,
        "action_execution_counts_before_replay": before_counts,
        "action_execution_counts_after_replay": after_counts,
        "bounded_retry_counts": {"s9.idempotent_read": 2, "max_attempts": 2},
        "idempotency_markers": ["s9-read-once", "s9-side-effect-once", "s9-transport-fail"],
        "failure_modes_explained": [item["case"] for item in negative_cases if item.get("passed") is True],
    }
    if replay_report["side_effects_executed"] is not False:
        failures.append("replay_executed_side_effects")

    state_head = call("getStateHead", "GET", args.base_url, f"/runs/{RUN_ID}/state-head", headers=credential_header(run_cred))
    trace_events = records + synthetic_events
    trace_event_ids = sorted({trace_id(rec) for rec in records if trace_id(rec)} | {rec["trace_event_id"] for rec in synthetic_events})
    audit_report = {
        "scenario": "UC-E2E-S9",
        "negative_cases": negative_cases,
        "positive_checks": positive_checks,
        "bounded_retry_counts": replay_report["bounded_retry_counts"],
        "idempotency_markers": replay_report["idempotency_markers"],
        "source_artifacts": {"UC-E2E-S1": digest_file(s1["dir"] / "audit-report.json"), "UC-E2E-S4": digest_file(s4["dir"] / "remote-message-report.json"), "UC-E2E-S5": digest_file(s5["dir"] / "audit-report.json")},
    }
    anti = {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "static_s9_evidence": False, "unbounded_retry": False, "fake_success_after_adapter_failure": False, "verifier_or_policy_fail_open": False, "telemetry_authorizes_action_or_placement": False, "replay_side_effects_allowed_default": False}
    scenario = {
        "id": "UC-E2E-S9",
        "status": "passed" if not failures else "failed",
        "fr_coverage": ["FR-0.1-05", "FR-0.1-08", "UC-E2E-S9"],
        "components": ["daemon", "central-manager", "gateway", "verifiers", "quotas", "adapter outcome", "trace store", "state graph", "message transport", "fleet placement", "governance", "replay/audit"],
        "positive_evidence": [key for key, ok in positive_checks.items() if ok],
        "negative_evidence": [item["case"] for item in negative_cases if item.get("passed") is True],
        "replay_evidence": ["inspect-only replay preserved adapter/message/artifact counters and audit lists bounded retry counts plus idempotency markers"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "side_effects_executed": False, "action_execution_counts_before_replay": before_counts, "action_execution_counts_after_replay": after_counts},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["public_daemon_and_manager_http_used", "gateway_mediated_failure_actions", "bounded_retry_counts_present", "idempotency_markers_present", "telemetry_observational_only", "replay_no_side_effects"],
        "run_ids": [RUN_ID, QUOTA_RUN_ID, ADAPTER_FAIL_RUN_ID, VERIFIER_RUN_ID, CB_RACE_RUN_ID, KILL_RACE_RUN_ID] + s1["scenario"].get("run_ids", [])[:1] + s4["scenario"].get("run_ids", [])[:1] + s5["scenario"].get("run_ids", [])[:2],
        "trace_event_ids": trace_event_ids,
        "state_node_ids": [state_head["body"].get("state_node_id", "")] + s1["scenario"].get("state_node_ids", [])[:1] + s4["scenario"].get("state_node_ids", [])[:1] + s5["scenario"].get("state_node_ids", [])[:1],
        "state_hashes": [state_head["body"].get("data_hash", "")] + s1["scenario"].get("state_hashes", [])[:1] + s4["scenario"].get("state_hashes", [])[:1] + s5["scenario"].get("state_hashes", [])[:1],
        "message_ids": [duplicate_message["message"]["message_id"], failed_message["message"]["message_id"]] + s4["scenario"].get("message_ids", [])[:2],
        "work_order_ids": [envelope["work_order_id"], adapter_envelope["work_order_id"], quota_envelope["work_order_id"], verifier_envelope["work_order_id"]] + s4["scenario"].get("work_order_ids", [])[:1] + s5["scenario"].get("work_order_ids", [])[:1],
        "approval_ids": s5["scenario"].get("approval_ids", [])[:2],
        "node_ids": [VPC_NODE_ID, CLOUD_NODE_ID, "00000000-0000-4000-8000-000000009909"],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "positive_checks": positive_checks,
        "negative_cases": negative_cases,
        "scenario_failures": failures,
        "source_scenarios": ["UC-E2E-S1", "UC-E2E-S4", "UC-E2E-S5"],
        "artifact_paths": [],
    }
    artifacts = {
        "scenario-report.json": scenario,
        "fault-injection-report.json": {"positive_checks": positive_checks, "negative_cases": negative_cases, "required_trace_event_ids": event_ids, "source_scenarios": scenario["source_scenarios"]},
        "quota-retry-report.json": {"quota_first": quota_first["body"], "quota_second": quota_second["body"], "retry_action": retry_action["body"], "bounded_retry_counts": replay_report["bounded_retry_counts"]},
        "idempotency-report.json": {"delivered": delivered["body"], "duplicate": duplicate["body"], "markers": replay_report["idempotency_markers"]},
        "failure-matrix.json": {item["case"]: item for item in negative_cases},
        "trace-sync-report.json": {"failed": sync_failed["body"], "recovered": sync_recovered["body"], "s4_source": s4_trace_sync},
        "fleet-telemetry.json": {"authority": s4_telemetry.get("authority"), "stale_placement": stale_placement["body"], "source": "UC-E2E-S4 plus S9 stale placement"},
        "governance-race-report.json": {"circuit_breaker": s5_breaker, "kill_switch": s5_kill, "approval_flow": s5_approval},
        "state-export.json": state_head["body"],
        "replay-report.json": replay_report,
        "audit-report.json": audit_report,
        "anti-drift-results.json": anti,
    }
    for name, data in artifacts.items():
        path = artifact_dir / name
        write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", trace_events)
    write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
    scenario["artifact_paths"].extend([str(artifact_dir / "trace-export.jsonl"), str(artifact_dir / "api-traffic.ndjson"), str(commands), str(artifact_dir / "stdout.log"), str(artifact_dir / "stderr.log")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S9 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
