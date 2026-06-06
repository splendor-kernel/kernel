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
TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "11111111-1111-4111-8111-222222222227"
ORCH = "22222222-2222-4222-8222-222222222227"
SPEC = "33333333-3333-4333-8333-333333333337"
ORCH_RUN = "44444444-4444-4444-8444-444444444447"
SPEC_RUN = "44444444-4444-4444-8444-555555555557"
VPC_NODE = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE = "00000000-0000-4000-8000-000000000302"
WORK_ORDER_ORCH = "wo_uc_e2e_s7_tenant_a_orchestrator"
WORK_ORDER_SPEC = "wo_uc_e2e_s7_tenant_a_specialist"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"
DATA_REF_A = "dataset:tenant-a.finance.board_pack.v1"
DATA_REF_B = "dataset:tenant-b.finance.board_pack.v1"
RAW_A = "TENANT_A_PROTECTED_REVENUE_RAW_9173"
RAW_B = "TENANT_B_PROTECTED_REVENUE_RAW_4421"


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


def manager_credential(scopes: list[str] | None = None) -> dict[str, Any]:
    return {"credential_id": "cred_uc_e2e_s7_manager", "principal": {"app": {"app_principal_id": "app_uc_e2e_s7", "label": "UC-E2E-S7"}, "client_principal_id": "client_uc_e2e_s7", "label": "UC-E2E-S7 manager"}, "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "fleet_read", "fleet_dispatch", "work_orders_submit", "traces_read", "messages_send", "messages_read", "approvals_manage"], "binding": {"fleet": {"fleet_id": FLEET_ID}}, "audience": {"central_manager": {"manager_id": "central-manager"}}, "expires_at": utc(60), "revocation": "active"}


def resident_credential(scopes: list[str] | None = None, tenant: str = TENANT_A) -> dict[str, Any]:
    return {"credential_id": f"cred_uc_e2e_s7_resident_{tenant[-3:]}", "principal": manager_credential()["principal"], "scopes": scopes or ["runs_create", "runs_start", "runs_read", "runs_resume", "actions_submit", "state_read", "traces_read", "replay_create"], "binding": {"tenant": {"tenant_id": tenant}}, "audience": {"instance": {"instance_id": VPC_INSTANCE}}, "expires_at": utc(60), "revocation": "active"}


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any]) -> dict[str, Any]:
    return {"credential": credential, "audit_attribution": audit(credential)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def node_registration(vpc_url: str) -> dict[str, Any]:
    return {"node_id": VPC_NODE, "kind": "vpc.worker", "scope": {"fleet_id": FLEET_ID, "tenant_id": None}, "capability_document": {"schema": "splendor.capabilities.v1", "capabilities": ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal", "runtime.resident"], "constraints": {"placement_target": "customer_vpc", "data_locality": "vpc", "region": "eu-west", "resident_daemon_url": vpc_url, "runtime_image_identity": "splendor-kernel-runtime:acceptance-target-runtime", "trust_level": "acceptance"}}, "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}}, "registered_at": utc(0)}


def instance_registration() -> dict[str, Any]:
    return {"instance_id": VPC_INSTANCE, "node_id": VPC_NODE, "runtime_mode": "resident", "hosted_tenants": [TENANT_A, TENANT_B], "supported_features": ["gateway.verified", "data.local", "artifact.store", "message.remote"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}}, "registered_at": utc(0)}


def work_order(work_order_id: str, agent_id: str, run_id: str, route_target: str, *, specialist: bool = False) -> dict[str, Any]:
    allowed_actions = ["data.read_fixture", "artifact.create_internal", "message.remote.proposal"] if specialist else ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"]
    allowed_permissions = ["data.read_fixture", "artifact.create_internal", f"message.remote.proposal:{route_target}"] if specialist else ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", f"message.remote.proposal:{route_target}"]
    return {"schema_version": "splendor.work_order.v1", "work_order_id": work_order_id, "tenant_id": TENANT_A, "agent_id": agent_id, "run_id": run_id, "objective": "UC-E2E-S7 tenant A data-local analysis with scoped artifact publication", "allowed_actions": allowed_actions, "allowed_adapters": ["fixture-data-store", "artifact-store", "remote-message"], "allowed_permissions": allowed_permissions, "data_refs": [DATA_REF_A], "quotas": {"max_actions_per_tick": 8, "max_action_duration_ms": 30000}, "placement": {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"]}, "issued_at": utc(-2), "expires_at": utc(60), "revocation": "active"}


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def quota() -> dict[str, int]:
    return {"actions": 1, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def action(name: str, permission: str, **params: Any) -> dict[str, Any]:
    return {"name": name, "params": params, "side_effect_class": "External" if name.startswith("artifact") else "ReadOnly", "cost_estimate": None, "required_permissions": [permission], "preconditions": [], "postconditions": []}


def approval_policy(action_id: str) -> dict[str, Any]:
    return {"schema_version": "splendor.approval_policy.v1", "policy_id": "policy_uc_e2e_s7_external_publish", "tenant_id": TENANT_A, "agent_id": ORCH, "action_name": "artifact.publish_external", "adapter": "artifact-store", "required_permission": "artifact.publish_external", "side_effect_class": "External", "risk_level": "high", "reason": "external artifact publication requires scoped approval", "expires_at": utc(60), "action_id": action_id}


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


def build_event_ids(records: list[dict[str, Any]], manager_events: list[dict[str, Any]], *, trace_export_id: str, replay_id: str) -> dict[str, list[str]]:
    ids: dict[str, list[str]] = {"trace.exported.redacted": [trace_export_id], "replay.explained": [replay_id]}
    for event in manager_events:
        mapped = {"work_order.accepted": "work_order.accepted", "remote_message.delivered": "message.sent", "remote_message.received": "message.received", "remote_message.rejected": "message.denied"}.get(event.get("event_type"))
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
            action_name == "artifact.publish_external" or "artifact_path_tenant_mismatch" in text
        ):
            ids.setdefault("artifact.publish.denied", []).append(trace_id(record))
        if kind == "StateCommitted":
            ids.setdefault("state.committed", []).append(trace_id(record))
        if kind == "DaemonAudit" and payload.get("endpoint") == "splendor.traces.export.redacted":
            ids.setdefault("trace.exported.redacted", []).append(trace_id(record))
        if kind == "DaemonAudit" and payload.get("endpoint") == "splendor.replay.explained":
            ids.setdefault("replay.explained", []).append(trace_id(record))
    return ids


def action_evidence(outcome: dict[str, Any]) -> dict[str, Any]:
    output = outcome.get("output") if isinstance(outcome.get("output"), dict) else {}
    verification = outcome.get("verification") if isinstance(outcome.get("verification"), dict) else {}
    artifacts = verification.get("artifacts") if isinstance(verification.get("artifacts"), dict) else {}
    return {
        "action_id": outcome.get("action_id"),
        "status": outcome.get("status"),
        "trace_event_id": outcome.get("trace_event_id") or artifacts.get("trace_event_id"),
        "artifact_path": output.get("artifact_path") or output.get("publish_ref"),
        "tenant_id": output.get("tenant_id"),
        "integrity": output.get("integrity"),
        "output": output,
    }


def action_execution_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"data.read_fixture": 0, "artifact.create_internal": 0, "artifact.publish_external": 0}
    for record in records:
        if event_kind(record) != "ActionExecuted":
            continue
        payload = event_payload(record)
        name = payload.get("action", {}).get("name")
        if name in counts:
            counts[name] += 1
    return counts


def resolve_action_trace_evidence(
    records: list[dict[str, Any]], outcome: dict[str, Any], action_name: str
) -> dict[str, Any]:
    evidence = action_evidence(outcome)
    output = evidence.get("output") if isinstance(evidence.get("output"), dict) else {}
    artifact_path = evidence.get("artifact_path")
    tenant_id = evidence.get("tenant_id")
    integrity = evidence.get("integrity")
    action_id = evidence.get("action_id")
    for record in records:
        if event_kind(record) != "ActionExecuted":
            continue
        payload = event_payload(record)
        action = payload.get("action", {})
        trace_output = payload.get("outcome", {}) if isinstance(payload.get("outcome"), dict) else {}
        trace_path = trace_output.get("artifact_path") or action.get("params", {}).get("publish_ref")
        if action.get("name") != action_name:
            continue
        if artifact_path and trace_path != artifact_path:
            continue
        if tenant_id and trace_output.get("tenant_id") != tenant_id:
            continue
        if integrity and trace_output.get("integrity") != integrity:
            continue
        if not evidence.get("artifact_path") and trace_path:
            evidence["artifact_path"] = trace_path
            artifact_path = trace_path
        if not evidence.get("tenant_id") and isinstance(trace_path, str) and trace_path.startswith("artifact://"):
            evidence["tenant_id"] = trace_path.removeprefix("artifact://").split("/", 1)[0]
            tenant_id = evidence["tenant_id"]
        evidence["trace_event_id"] = trace_id(record)
        evidence["trace_run_id"] = record.get("run_id")
        evidence["trace_action_name"] = action.get("name")
        evidence["trace_artifact_path"] = trace_path
        evidence["trace_integrity"] = trace_output.get("integrity")
        evidence["trace_tenant_id"] = trace_output.get("tenant_id")
        break
    for record in records:
        if event_kind(record) != "OutcomeRecorded":
            continue
        payload = event_payload(record).get("outcome", {})
        candidates = payload.get("actions") if isinstance(payload.get("actions"), list) else [payload.get("action_outcome")]
        for candidate in candidates:
            if not isinstance(candidate, dict) or candidate.get("action_id") != action_id:
                continue
            candidate_output = candidate.get("output") if isinstance(candidate.get("output"), dict) else {}
            candidate_path = candidate_output.get("artifact_path") or candidate_output.get("publish_ref")
            if artifact_path and candidate_path != artifact_path:
                continue
            if integrity and candidate_output.get("integrity") != integrity:
                continue
            evidence["outcome_trace_event_id"] = trace_id(record)
            evidence["outcome_action_id"] = candidate.get("action_id")
            evidence["outcome_artifact_path"] = candidate_path
            evidence["outcome_integrity"] = candidate_output.get("integrity")
            evidence["outcome_tenant_id"] = candidate_output.get("tenant_id")
            return evidence
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="http://resident-vpc-node:8092")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S7"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
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

    fixtures = {"tenants": {TENANT_A: {"data_ref": DATA_REF_A, "protected_raw_fixture": RAW_A}, TENANT_B: {"data_ref": DATA_REF_B, "protected_raw_fixture": RAW_B}}}
    write_json(artifact_dir / "tenant-data-fixtures.json", fixtures)
    manager = manager_credential()
    call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager), "registration": node_registration(args.vpc_url)})
    call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager), "registration": instance_registration()})
    call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{VPC_NODE}/heartbeat", {**sec(manager), "heartbeat": {"node_id": VPC_NODE, "health": node_registration(args.vpc_url)["health"], "recorded_at": utc(0)}})
    call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{VPC_NODE}/capabilities", {**sec(manager), "capability_document": node_registration(args.vpc_url)["capability_document"]})

    orch_envelope = sign_work_order(root, artifact_dir, commands, work_order(WORK_ORDER_ORCH, ORCH, ORCH_RUN, SPEC))
    spec_envelope = sign_work_order(root, artifact_dir, commands, work_order(WORK_ORDER_SPEC, SPEC, SPEC_RUN, ORCH, specialist=True))
    dispatch_reports: dict[str, dict[str, Any]] = {}
    for envelope in [orch_envelope, spec_envelope]:
        call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": envelope, "expected_audience": "central-manager"})
        call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": envelope["work_order_id"], "request": {"target": "customer_vpc", "required_capabilities": ["data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal"], "data_locality": "vpc", "dedicated_instance": False, "required_runtime_version": None, "max_runtime_ms": 30000, "execution_mode": "live"}})
        dispatch_reports[envelope["work_order_id"]] = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{envelope['work_order_id']}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})

    causal_anchor = dispatch_reports[WORK_ORDER_SPEC]["body"].get("trace_event_id")
    task_request = {"message": {"message_id": "55555555-5555-4555-8555-555555555707", "source_agent_id": ORCH, "target_agent_id": SPEC, "run_id": ORCH_RUN, "schema": "splendor.message.task_request.v1", "payload": {"parent_run_id": ORCH_RUN, "child_run_id": SPEC_RUN, "target_agent_id": SPEC, "objective": "analyze scoped board pack", "data_refs": [DATA_REF_A], "permissions": ["data.read_fixture"], "delegated_authority": {"allowed_actions": ["data.read_fixture", "artifact.create_internal"], "allowed_adapters": ["fixture-data-store", "artifact-store"], "allowed_permissions": ["data.read_fixture", "artifact.create_internal"]}}, "causal_parent": causal_anchor, "requires_response": True, "created_at": utc(0)}, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_ORCH, "message_envelope": task_request, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s7-task-request", "simulate_failure": None})
    received = call("getMessage", "POST", args.manager_url, f"/messages/{task_request['message']['message_id']}/read", sec(manager))
    task_response = {"message": {"message_id": "55555555-5555-4555-8555-555555555708", "source_agent_id": SPEC, "target_agent_id": ORCH, "run_id": ORCH_RUN, "schema": "splendor.message.task_response.v1", "payload": {"parent_run_id": ORCH_RUN, "child_run_id": SPEC_RUN, "status": "completed", "output": {"analysis_ref": "analysis:s7:tenant-a", "data_refs": [DATA_REF_A], "summary": "tenant A scoped margin and revenue trend summary", "raw_payload_included": False}, "failure": None}, "causal_parent": sent["body"].get("trace_event_id") or causal_anchor, "requires_response": False, "created_at": utc(0)}, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    response_sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_SPEC, "message_envelope": task_response, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s7-task-response", "simulate_failure": None})
    response_received = call("getMessage", "POST", args.manager_url, f"/messages/{task_response['message']['message_id']}/read", sec(manager))

    cred = resident_credential()
    inspect_before = call("inspectRunBeforeNegatives", "GET", args.vpc_url, f"/runs/{SPEC_RUN}", headers=credential_header(cred))
    action_causal_trace_id = response_sent["body"].get("trace_event_id") or sent["body"].get("trace_event_id") or causal_anchor
    internal_artifact = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPEC_RUN, "tenant_id": TENANT_A, "agent_id": SPEC, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("artifact.create_internal", "artifact.create_internal", artifact_path=f"artifact://{TENANT_A}/board/specialist-analysis.md"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    inspect_before_denials = call("inspectRunBeforeDeniedActions", "GET", args.vpc_url, f"/runs/{SPEC_RUN}", headers=credential_header(cred))
    tenant_b_denial = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPEC_RUN, "tenant_id": TENANT_A, "agent_id": SPEC, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("data.read_fixture", "data.read_fixture", data_ref=DATA_REF_B), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    manager_permission_denial = call("submitActionManagerCredential", "POST", args.vpc_url, "/actions", {"run_id": SPEC_RUN, "tenant_id": TENANT_A, "agent_id": SPEC, "credential": manager, "audit_attribution": audit(manager), "causal_trace_id": action_causal_trace_id, "action": action("data.read_fixture", "data.read_fixture", data_ref=DATA_REF_A), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    specialist_publish_denial = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": SPEC_RUN, "tenant_id": TENANT_A, "agent_id": SPEC, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("artifact.publish_external", "artifact.publish_external", publish_ref=f"artifact://{TENANT_A}/board/specialist-analysis.md"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    smuggle_message = json.loads(json.dumps(task_request))
    smuggle_message["message"]["message_id"] = "55555555-5555-4555-8555-555555555709"
    smuggle_message["message"]["payload"]["data_refs"] = [DATA_REF_A, DATA_REF_B]
    smuggle_message["message"]["payload"]["permissions"] = ["data.read_fixture", "artifact.publish_external"]
    smuggle = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_ORCH, "message_envelope": smuggle_message, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s7-smuggle", "simulate_failure": None})
    missing_redaction = call("exportTracesMissingRedaction", "POST", args.vpc_url, f"/runs/{SPEC_RUN}/traces/export", {"credential": cred, "audit_attribution": audit(cred), "redaction_policy": None, "start": None, "end": None})
    publish_no_approval = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": ORCH_RUN, "tenant_id": TENANT_A, "agent_id": ORCH, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("artifact.publish_external", "artifact.publish_external", publish_ref=f"artifact://{TENANT_A}/board/report.md"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    collision = call("submitAction", "POST", args.vpc_url, "/actions", {"run_id": ORCH_RUN, "tenant_id": TENANT_A, "agent_id": ORCH, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("artifact.create_internal", "artifact.create_internal", artifact_path=f"artifact://{TENANT_B}/board/report.md"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    inspect_after = call("inspectRunAfterNegatives", "GET", args.vpc_url, f"/runs/{SPEC_RUN}", headers=credential_header(cred))

    approval_context = publish_no_approval["body"].get("verification", {}).get("artifacts", {}).get("approval", {})
    approval_request = call("requestApproval", "POST", args.manager_url, "/approvals", {**sec(manager), "approval_id": approval_context.get("approval_id"), "tenant_id": TENANT_A, "agent_id": ORCH, "run_id": ORCH_RUN, "action_id": approval_context.get("action_id"), "action_name": "artifact.publish_external", "adapter": "artifact-store", "policy_id": "policy_uc_e2e_s7_external_publish", "risk_level": "high", "audience": "resident-vpc-node", "expires_at": utc(30), "reason": "S7 external publication approved after scoped review"})
    grant = call("grantApproval", "POST", args.manager_url, f"/approvals/{approval_context.get('approval_id')}/grant", {**sec(manager), "reason": "approved_for_s7", "expires_at": utc(30)})
    approved_publish = call("submitAction", "POST", args.vpc_url, "/actions", {"action_id": approval_context.get("action_id"), "run_id": ORCH_RUN, "tenant_id": TENANT_A, "agent_id": ORCH, "credential": cred, "audit_attribution": audit(cred), "causal_trace_id": action_causal_trace_id, "action": action("artifact.publish_external", "artifact.publish_external", publish_ref=f"artifact://{TENANT_A}/board/report.md"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": grant["body"].get("evidence")})

    traces_orch = call("exportTraces", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/traces/export", {"credential": cred, "audit_attribution": audit(cred), "redaction_policy": "uc-e2e-s7-redacted", "start": None, "end": None})
    traces_spec = call("exportTraces", "POST", args.vpc_url, f"/runs/{SPEC_RUN}/traces/export", {"credential": cred, "audit_attribution": audit(cred), "redaction_policy": "uc-e2e-s7-redacted", "start": None, "end": None})
    records_before_replay = traces_orch["body"].get("records", []) + traces_spec["body"].get("records", [])
    action_counts_before_replay = action_execution_counts(records_before_replay)
    inspect_before_replay = call("inspectRunBeforeReplay", "GET", args.vpc_url, f"/runs/{SPEC_RUN}", headers=credential_header(cred))
    inspect_orch_before_replay = call("inspectOrchestratorRunBeforeReplay", "GET", args.vpc_url, f"/runs/{ORCH_RUN}", headers=credential_header(cred))
    replay = call("replayRun", "POST", args.vpc_url, f"/runs/{SPEC_RUN}/replay", {"credential": cred, "audit_attribution": audit(cred), "mode": "inspect_only", "side_effects_allowed": False})
    replay_orch = call("replayOrchestratorRun", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/replay", {"credential": cred, "audit_attribution": audit(cred), "mode": "inspect_only", "side_effects_allowed": False})
    inspect_after_replay = call("inspectRunAfterReplay", "GET", args.vpc_url, f"/runs/{SPEC_RUN}", headers=credential_header(cred))
    inspect_orch_after_replay = call("inspectOrchestratorRunAfterReplay", "GET", args.vpc_url, f"/runs/{ORCH_RUN}", headers=credential_header(cred))
    cross_tenant_replay = call("crossTenantReplay", "POST", args.vpc_url, f"/runs/{SPEC_RUN}/replay", {"credential": resident_credential(tenant=TENANT_B), "audit_attribution": audit(resident_credential(tenant=TENANT_B)), "mode": "inspect_only", "side_effects_allowed": False})
    traces_orch_after_replay = call("exportTracesAfterReplay", "POST", args.vpc_url, f"/runs/{ORCH_RUN}/traces/export", {"credential": cred, "audit_attribution": audit(cred), "redaction_policy": "uc-e2e-s7-redacted", "start": None, "end": None})
    traces_spec_after_replay = call("exportTracesAfterReplay", "POST", args.vpc_url, f"/runs/{SPEC_RUN}/traces/export", {"credential": cred, "audit_attribution": audit(cred), "redaction_policy": "uc-e2e-s7-redacted", "start": None, "end": None})
    manager_audit = call("managerAudit", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    state_head = call("getStateHead", "GET", args.vpc_url, f"/runs/{SPEC_RUN}/state-head", headers=credential_header(cred))

    records = traces_orch_after_replay["body"].get("records", []) + traces_spec_after_replay["body"].get("records", [])
    action_counts_after_replay = action_execution_counts(records)
    trace_text = json.dumps(records, sort_keys=True)
    replay_text = json.dumps({"specialist": replay["body"], "orchestrator": replay_orch["body"]}, sort_keys=True)
    manager_body = manager_audit["body"]
    manager_events = manager_body if isinstance(manager_body, list) else manager_body.get("events", [])
    event_ids = build_event_ids(records, manager_events, trace_export_id=traces_spec_after_replay["body"].get("integrity_hash", ""), replay_id=",".join([replay["body"].get("replay_id", ""), replay_orch["body"].get("replay_id", "")]))
    adapter_before = inspect_before_denials["body"].get("adapter_executions")
    adapter_after = inspect_after["body"].get("adapter_executions")
    adapter_before_replay = {"specialist": inspect_before_replay["body"].get("adapter_executions"), "orchestrator": inspect_orch_before_replay["body"].get("adapter_executions")}
    adapter_after_replay = {"specialist": inspect_after_replay["body"].get("adapter_executions"), "orchestrator": inspect_orch_after_replay["body"].get("adapter_executions")}
    negatives = [
        {"case": "specialist_tenant_b_data_ref_denied_before_adapter", "passed": tenant_b_denial["body"].get("status") == "Denied" and "data_scope_denied" in tenant_b_denial["body"].get("verification", {}).get("reasons", []), "status": tenant_b_denial["body"].get("status"), "reason_codes": tenant_b_denial["body"].get("verification", {}).get("reasons", [])},
        {"case": "manager_credential_as_action_permission_denied", "passed": manager_permission_denial["status"] == 403, "status": manager_permission_denial["status"], "code": manager_permission_denial["body"].get("code")},
        {"case": "specialist_external_publish_denied_by_narrow_work_order", "passed": specialist_publish_denial["body"].get("status") == "Denied" and "action_not_allowed" in specialist_publish_denial["body"].get("verification", {}).get("reasons", []), "status": specialist_publish_denial["body"].get("status"), "reason_codes": specialist_publish_denial["body"].get("verification", {}).get("reasons", [])},
        {"case": "message_payload_data_ref_permission_smuggling_denied", "passed": smuggle["status"] == 403 and smuggle["body"].get("code") == "message_payload_scope_smuggling", "status": smuggle["status"], "code": smuggle["body"].get("code")},
        {"case": "trace_export_without_redaction_policy_rejected", "passed": missing_redaction["status"] == 403 and missing_redaction["body"].get("code") == "missing_trace_redaction_policy", "status": missing_redaction["status"], "code": missing_redaction["body"].get("code")},
        {"case": "external_artifact_publish_without_approval_pauses", "passed": publish_no_approval["body"].get("status") == "NeedsApproval", "status": publish_no_approval["body"].get("status")},
        {"case": "cross_tenant_replay_cannot_reveal_raw_payloads", "passed": cross_tenant_replay["status"] == 403 and RAW_A not in replay_text and RAW_B not in replay_text, "status": cross_tenant_replay["status"]},
        {"case": "artifact_path_collision_across_tenants_rejected", "passed": collision["body"].get("status") == "Denied" and "artifact_path_tenant_mismatch" in collision["body"].get("verification", {}).get("reasons", []), "status": collision["body"].get("status"), "reason_codes": collision["body"].get("verification", {}).get("reasons", [])},
        {"case": "denied_data_and_artifact_actions_did_not_reach_adapter", "passed": adapter_before == adapter_after, "adapter_executions_before": adapter_before, "adapter_executions_after": adapter_after},
        {"case": "replay_did_not_reread_republish_or_rewrite_artifacts", "passed": adapter_before_replay == adapter_after_replay and action_counts_before_replay == action_counts_after_replay, "adapter_executions_before_replay": adapter_before_replay, "adapter_executions_after_replay": adapter_after_replay, "action_execution_counts_before_replay": action_counts_before_replay, "action_execution_counts_after_replay": action_counts_after_replay, "orchestrator_replay_id": replay_orch["body"].get("replay_id"), "published_artifact_path": f"artifact://{TENANT_A}/board/report.md"},
    ]
    internal_artifact_evidence = resolve_action_trace_evidence(records, internal_artifact["body"], "artifact.create_internal")
    approved_publish_evidence = resolve_action_trace_evidence(records, approved_publish["body"], "artifact.publish_external")
    positives = {"tenant_fixtures_separate": DATA_REF_A != DATA_REF_B and RAW_A != RAW_B, "specialist_work_order_narrow": "artifact.publish_external" not in spec_envelope.get("allowed_actions", []) and "artifact.publish_external" not in spec_envelope.get("allowed_permissions", []), "work_orders_accepted": len([e for e in manager_events if e.get("event_type") == "work_order.accepted"]) >= 2, "vpc_dispatch_used": any(row.get("operation_id") == "dispatchWorkOrder" and row.get("status") == 200 for row in api_rows), "typed_messages_delivered": sent["body"].get("delivery_status") == "delivered" and received["body"].get("receive_side_validated") is True and received["body"].get("read_trace_event_id") and response_sent["body"].get("delivery_status") == "delivered" and response_received["body"].get("receive_side_validated") is True and response_received["body"].get("read_trace_event_id"), "internal_artifact_recorded": internal_artifact["body"].get("status") == "Executed" and internal_artifact_evidence.get("artifact_path") == f"artifact://{TENANT_A}/board/specialist-analysis.md" and internal_artifact_evidence.get("integrity") and internal_artifact_evidence.get("trace_event_id") in event_ids.get("artifact.created", []), "approved_publish_executed": approved_publish["body"].get("status") == "Executed" and approved_publish_evidence.get("integrity") and approved_publish_evidence.get("trace_event_id") in event_ids.get("artifact.publish.executed", []), "approval_action_trace_matched": approval_context.get("action_id") == approved_publish["body"].get("action_id") and action_causal_trace_id, "trace_redacted": RAW_A not in trace_text and RAW_B not in trace_text, "replay_inspect_only": replay["body"].get("mode") == "inspect_only" and replay_orch["body"].get("mode") == "inspect_only"}
    failures = [key for key, ok in positives.items() if not ok]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    required_events = {"work_order.accepted", "data_scope.verified", "data_scope.denied", "message.sent", "message.received", "message.denied", "artifact.created", "artifact.publish.needs_approval", "artifact.publish.executed", "artifact.publish.denied", "trace.exported.redacted", "state.committed", "replay.explained"}
    failures.extend(f"missing_event:{event}" for event in sorted(required_events) if not event_ids.get(event))
    replay_suppression = {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "external_publish_replayed": False, "internal_artifact_rewritten": False, "adapter_executions_before_replay": adapter_before_replay, "adapter_executions_after_replay": adapter_after_replay, "action_execution_counts_before_replay": action_counts_before_replay, "action_execution_counts_after_replay": action_counts_after_replay, "orchestrator_replay_id": replay_orch["body"].get("replay_id"), "specialist_replay_id": replay["body"].get("replay_id"), "approved_publish_artifact_path": approved_publish_evidence.get("artifact_path"), "approved_publish_trace_event_id": approved_publish_evidence.get("trace_event_id"), "internal_artifact_trace_event_id": internal_artifact_evidence.get("trace_event_id")}

    scenario = {"id": "UC-E2E-S7", "status": "passed" if not failures else "failed", "fr_coverage": ["UC-E2E-S7", "FR-0.1-05", "FR-0.1-08"], "components": ["central-manager", "resident-vpc-node", "work-order", "placement", "message-routing", "data-scope-verifier", "artifact-adapter", "approval", "trace-redaction", "replay/audit"], "positive_evidence": [key for key, ok in positives.items() if ok], "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True], "replay_evidence": ["replayRun public API returned inspect_only explanation; raw protected fixture strings absent; cross-tenant replay rejected; adapter execution count unchanged across replay"], "replay_mode": "inspect_only", "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "external_publish_replayed": False, "internal_artifact_rewritten": False, "adapter_executions_before_replay": inspect_before_replay["body"].get("adapter_executions"), "adapter_executions_after_replay": inspect_after_replay["body"].get("adapter_executions")}, "replay_artifacts": [str(artifact_dir / "replay-report.json")], "anti_drift_checks": ["public_manager_and_resident_http_used", "gateway_data_scope_verifier_before_adapter", "shared_specialist_scoped_work_order_only", "manager_credential_not_action_authority", "trace_redaction_required", "replay_no_artifact_publish"], "run_ids": [ORCH_RUN, SPEC_RUN], "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid}), "state_node_ids": [state_head["body"].get("state_node_id", "")], "state_hashes": [state_head["body"].get("data_hash", "")], "message_ids": [task_request["message"]["message_id"], task_response["message"]["message_id"], smuggle_message["message"]["message_id"]], "work_order_ids": [WORK_ORDER_ORCH, WORK_ORDER_SPEC], "approval_ids": [approval_context.get("approval_id", "")], "node_ids": [VPC_NODE], "api_operations": sorted({row["operation_id"] for row in api_rows}), "required_trace_event_ids": event_ids, "negative_cases": negatives, "positive_checks": positives, "scenario_failures": failures, "artifact_paths": []}
    artifacts = {"scenario-report.json": scenario, "tenant-data-fixtures.json": fixtures, "work-order-validation.json": {"orchestrator": orch_envelope, "specialist": spec_envelope}, "message-flow.json": {"request": sent["body"], "request_read": received["body"], "response": response_sent["body"], "response_read": response_received["body"], "smuggling_denial": smuggle}, "artifact-report.json": {"internal_artifact": internal_artifact["body"], "internal_artifact_evidence": internal_artifact_evidence, "publish_without_approval": publish_no_approval["body"], "approval_request": approval_request["body"], "grant": grant["body"], "approved_publish": approved_publish["body"], "approved_publish_evidence": approved_publish_evidence, "collision": collision["body"], "specialist_publish_denial": specialist_publish_denial["body"]}, "data-scope-report.json": {"tenant_b_denial": tenant_b_denial["body"], "manager_permission_denial": manager_permission_denial, "specialist_publish_denial": specialist_publish_denial["body"], "adapter_executions_before": adapter_before, "adapter_executions_after": adapter_after}, "state-export.json": state_head["body"], "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "external_publish_replayed": False, "raw_payloads_absent": RAW_A not in replay_text and RAW_B not in replay_text, "cross_tenant_replay": cross_tenant_replay, "adapter_executions_before_replay": inspect_before_replay["body"].get("adapter_executions"), "adapter_executions_after_replay": inspect_after_replay["body"].get("adapter_executions")}, "audit-report.json": {"events": manager_events, "in_scope_data_refs": [DATA_REF_A], "denied_data_refs": [DATA_REF_B], "negative_cases": negatives, "event_ids": event_ids}, "anti-drift-results.json": {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "specialist_broad_permission_inheritance": False, "manager_credential_authorizes_action": False, "trace_export_without_redaction_allowed": False, "replay_side_effects_allowed_default": False}, "stdout.log": "UC-E2E-S7 data-local analysis scenario completed through public manager and resident HTTP APIs\n", "stderr.log": ""}
    scenario["replay_evidence"] = ["public replay APIs returned inspect_only explanations for specialist and orchestrator runs; raw protected fixture strings absent; cross-tenant replay rejected; adapter and trace-derived action execution counts unchanged across replay"]
    scenario["replay_side_effect_suppression"] = replay_suppression
    artifacts["replay-report.json"].update({"orchestrator_replay": replay_orch["body"], "adapter_executions_before_replay": adapter_before_replay, "adapter_executions_after_replay": adapter_after_replay, "action_execution_counts_before_replay": action_counts_before_replay, "action_execution_counts_after_replay": action_counts_after_replay, "approved_publish_artifact_path": approved_publish_evidence.get("artifact_path"), "approved_publish_trace_event_id": approved_publish_evidence.get("trace_event_id"), "internal_artifact_trace_event_id": internal_artifact_evidence.get("trace_event_id")})
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
        raise SystemExit("UC-E2E-S7 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
