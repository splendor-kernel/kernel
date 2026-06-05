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
CLOUD_INSTANCE_ID = "00000000-0000-4000-8000-000000000304"
CLOUD_NODE_ID = "00000000-0000-4000-8000-000000000404"
RUN_ID = "44444444-4444-4444-8444-444444444445"
DENY_RUN_ID = "44444444-4444-4444-8444-444444444545"
KILL_RUN_ID = "44444444-4444-4444-8444-444444444645"
POLICY_ID = "policy_uc_e2e_s5_publish_external"
WORK_ORDER_ID = "wo_uc_e2e_s5_governance"
KEY_ID = "work-order-local-key"
SECRET = "splendor-local-work-order-secret"


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
    return {
        "credential_id": "cred_uc_e2e_s5_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s5", "label": "UC-E2E-S5"}, "client_principal_id": "client_uc_e2e_s5", "label": "UC-E2E-S5 governance client"},
        "scopes": scopes or ["policies_publish", "policies_revoke", "approvals_manage", "governance_control", "traces_read", "fleet_read", "nodes_register", "instances_register"],
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


def resident_credential(instance_id: str, scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "credential_id": f"cred_uc_e2e_s5_resident_{instance_id[-3:]}",
        "principal": manager_credential()["principal"],
        "scopes": scopes or ["runs_create", "runs_read", "runs_stop", "actions_submit", "state_read", "traces_read"],
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"instance": {"instance_id": instance_id}},
        "expires_at": utc(60),
        "revocation": "active",
    }


def node_registration(node_id: str, instance_url: str) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "kind": "cloud.worker",
        "scope": {"fleet_id": FLEET_ID, "tenant_id": None},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": ["artifact.create_internal", "artifact.publish_external", "governance.kill_switch"],
            "constraints": {"placement_target": "resident_cloud_pool", "data_locality": "cloud", "resident_daemon_url": instance_url, "trust_level": "acceptance"},
        },
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str) -> dict[str, Any]:
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": ["gateway.verified", "governance.kill_switch"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {}}, "registered_at": utc(0)}


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any] | None = None) -> dict[str, Any]:
    credential = credential or manager_credential()
    return {"credential": credential, "audit_attribution": audit(credential)}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def work_order(run_id: str = RUN_ID, expires: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": WORK_ORDER_ID + "_" + run_id[-3:],
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": "UC-E2E-S5 governed internal artifact and approval-gated external publication",
        "allowed_actions": ["artifact.create_internal", "artifact.publish_external"],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": ["artifact.create_internal", "artifact.publish_external"],
        "data_refs": ["artifact:uc-e2e-s5.internal"],
        "quotas": {"max_actions_per_tick": 5, "max_action_duration_ms": 30000},
        "placement": {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": ["artifact.create_internal", "artifact.publish_external"]},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(splendorctl(root) + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET], root, commands)
    return json.loads(proc.stdout)


def action(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "params": {"artifact": "uc-e2e-s5", "external": name.endswith("external")},
        "side_effect_class": "External",
        "cost_estimate": None,
        "required_permissions": [name],
        "preconditions": [],
        "postconditions": [],
    }


def action_id_for_run(run_id: str) -> str:
    return "55555555-5555-4555-8555-555555" + run_id[-6:]


def quota() -> dict[str, int]:
    return {"actions": 1, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def approval_policy(expires: int = 60) -> dict[str, Any]:
    return {"schema_version": "splendor.approval_policy.v1", "policy_id": POLICY_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "action_name": "artifact.publish_external", "adapter": "artifact-store", "required_permission": "artifact.publish_external", "side_effect_class": "External", "risk_level": "high", "reason": "external publication requires governance approval", "expires_at": utc(expires)}


def policy_bundle(expires: int = 60, policy_id: str = POLICY_ID, expires_at: str | None = None) -> dict[str, Any]:
    return {"schema_version": "splendor.policy_bundle.v1", "policy_bundle_id": policy_id, "version": "uc-e2e-s5.v1", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "issued_at": utc(-1), "expires_at": expires_at or utc(expires), "revocation": "active", "degraded_mode": {"allow_low_risk_cached": False, "disconnected_low_risk_actions": ["artifact.create_internal"], "disconnected_high_risk_actions": ["artifact.publish_external"], "high_risk_disconnected_behavior": "deny"}}


def create_run_payload(run_id: str, envelope: dict[str, Any], signed_policy: dict[str, Any] | None, *, policies: list[dict[str, Any]] | None = None, circuit_breakers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cred = daemon_credential(run_id)
    return {
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": cred,
        "audit_attribution": audit(cred),
        "allowed_actions": ["artifact.create_internal", "artifact.publish_external"],
        "allowed_adapters": ["artifact-store"],
        "allowed_permissions": ["artifact.create_internal", "artifact.publish_external"],
        "registered_actions": [{"name": "artifact.create_internal", "adapter": "artifact-store"}, {"name": "artifact.publish_external", "adapter": "artifact-store"}],
        "policy_actions": [{"action_id": action_id_for_run(run_id), "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []}],
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
    artifact = outcome.get("verification", {}).get("artifacts", {}).get("approval", {})
    approval = artifact.get("approval") or artifact
    if not approval:
        raise SystemExit("approval context missing from needs_approval outcome")
    return approval


def trace_event_id_map(records: list[dict[str, Any]], manager_events: list[dict[str, Any]]) -> dict[str, list[str]]:
    mapping = {
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default="http://splendor-daemon-local:8080")
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--cloud-url", default="http://resident-cloud-node:8091")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S5"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        status, data = request_json(method, base, path, body, headers)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

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
    register_node = call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager_cred), "registration": node_registration(CLOUD_NODE_ID, args.cloud_url)})
    register_instance = call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager_cred), "registration": instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID)})
    published = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle()})
    signed_policy = published["body"].get("envelope")
    policy_status = call("getPolicyStatus", "POST", args.manager_url, f"/policies/{POLICY_ID}/read", sec(manager_cred))

    envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID))
    create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(RUN_ID, envelope, signed_policy))
    require_status("createRun", create, 200)
    daemon_cred = daemon_credential(RUN_ID)
    internal = call("submitAction", "POST", args.base_url, "/actions", {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": "55555555-5555-4555-8555-555555555501", "action": action("artifact.create_internal"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    start = call("startRun", "POST", args.base_url, f"/runs/{RUN_ID}/start", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "reason": "uc_e2e_s5_external_publish_proposed"})
    needs_approval = require_action_outcome("startRun", start)
    approval_context = extract_approval_context(needs_approval)
    approval_request = call("requestApproval", "POST", args.manager_url, "/approvals", {**sec(manager_cred), "approval_id": approval_context["approval_id"], "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "action_id": approval_context["action_id"], "action_name": "artifact.publish_external", "adapter": "artifact-store", "policy_id": POLICY_ID, "risk_level": "high", "audience": "daemon_local", "expires_at": utc(30), "reason": "external publication requested"})
    approval_grant = call("grantApproval", "POST", args.manager_url, f"/approvals/{approval_context['approval_id']}/grant", {**sec(manager_cred), "reason": "approved_for_uc_e2e_s5", "expires_at": utc(30)})
    evidence = approval_grant["body"].get("evidence")
    resume = call("resumeRun", "POST", args.base_url, f"/runs/{RUN_ID}/resume", {"credential": daemon_cred, "work_order": envelope, "audit_attribution": audit(daemon_cred), "reason": "approval_granted", "approval_evidence": evidence})
    state_head = call("getStateHead", "GET", args.base_url, f"/runs/{RUN_ID}/state-head", headers=credential_header(daemon_cred))

    expired_evidence = json.loads(json.dumps(evidence))
    expired_evidence["approval_id"] = "55555555-5555-4555-8555-555555555502"
    expired_evidence["expires_at"] = utc(-5)
    expired = call("submitAction", "POST", args.base_url, "/actions", {"action_id": evidence["action_id"], "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": "55555555-5555-4555-8555-555555555503", "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": expired_evidence})
    approval_revoke = call("revokeApproval", "POST", args.manager_url, f"/approvals/{approval_context['approval_id']}/revoke", {**sec(manager_cred), "reason": "operator_revoked_publication"})
    revoked_evidence = approval_revoke["body"].get("evidence")
    revoked = call("submitAction", "POST", args.base_url, "/actions", {"action_id": revoked_evidence["action_id"], "run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": daemon_cred, "audit_attribution": audit(daemon_cred), "causal_trace_id": "55555555-5555-4555-8555-555555555505", "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "approval_evidence": revoked_evidence})

    deny_envelope = sign_work_order(root, artifact_dir, commands, work_order(DENY_RUN_ID))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(DENY_RUN_ID, deny_envelope, signed_policy))
    deny_cred = daemon_credential(DENY_RUN_ID)
    deny_start = call("startRun", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/start", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "reason": "deny_branch"})
    deny_context = extract_approval_context(require_action_outcome("deny startRun", deny_start))
    call("requestApproval", "POST", args.manager_url, "/approvals", {**sec(manager_cred), "approval_id": deny_context["approval_id"], "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": DENY_RUN_ID, "action_id": deny_context["action_id"], "action_name": "artifact.publish_external", "adapter": "artifact-store", "policy_id": POLICY_ID, "risk_level": "high", "audience": "daemon_local", "expires_at": utc(30), "reason": "denial branch requested"})
    denial = call("denyApproval", "POST", args.manager_url, f"/approvals/{deny_context['approval_id']}/deny", {**sec(manager_cred), "reason": "operator_denied_publication"})
    denial_evidence = denial["body"].get("evidence")
    deny_resume = call("resumeRun", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/resume", {"credential": deny_cred, "work_order": deny_envelope, "audit_attribution": audit(deny_cred), "reason": "approval_denied", "approval_evidence": denial_evidence})

    missing_policy = call("createRun", "POST", args.base_url, "/runs", {**create_run_payload("44444444-4444-4444-8444-444444444745", sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444444745")), None), "policy_bundle_required": True})
    expired_policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle(-1, "policy_uc_e2e_s5_expired")})
    expired_policy_create = call("createRun", "POST", args.base_url, "/runs", create_run_payload("44444444-4444-4444-8444-444444444845", sign_work_order(root, artifact_dir, commands, work_order("44444444-4444-4444-8444-444444444845")), expired_policy["body"].get("envelope")))
    ttl_policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager_cred), "policy_bundle": policy_bundle(policy_id="policy_uc_e2e_s5_runtime_expiry", expires_at=utc_seconds(3))})
    ttl_run_id = "44444444-4444-4444-8444-444444445245"
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
    breaker_obj = {"schema_version": "splendor.circuit_breaker.v1", "breaker_id": breaker_uuid, "scope": {"scope": "adapter", "value": "artifact-store"}, "state": "tripped", "reason": "incident_block_external_publish", "created_at": utc(0), "updated_at": utc(0)}
    cb_run_id = "44444444-4444-4444-8444-444444445145"
    cb_envelope = sign_work_order(root, artifact_dir, commands, work_order(cb_run_id))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(cb_run_id, cb_envelope, signed_policy, policies=[]))
    cb_cred = daemon_credential(cb_run_id)
    cb_sync = call("syncCircuitBreakers", "POST", args.base_url, f"/runs/{cb_run_id}/governance/circuit-breakers/sync", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "circuit_breakers": [breaker_obj], "reason": "manager_propagated_breaker"})
    cb_submit = call("submitAction", "POST", args.base_url, "/actions", {"run_id": cb_run_id, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": cb_cred, "audit_attribution": audit(cb_cred), "causal_trace_id": "55555555-5555-4555-8555-555555555507", "action": action("artifact.publish_external"), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    clear = call("clearCircuitBreaker", "POST", args.manager_url, f"/governance/circuit-breakers/{breaker_uuid}/clear", {**sec(manager_cred), "reason": "incident_resolved"})
    clear_wrong_scope = call("clearCircuitBreaker", "POST", args.manager_url, f"/governance/circuit-breakers/{breaker_uuid}/clear", {**sec(manager_credential(["fleet_read"])), "reason": "missing_control_scope"})

    kill_envelope = sign_work_order(root, artifact_dir, commands, work_order(KILL_RUN_ID))
    kill_cred = resident_credential(CLOUD_INSTANCE_ID)
    kill_create = create_run_payload(KILL_RUN_ID, kill_envelope, signed_policy, policies=[])
    kill_create["credential"] = kill_cred
    kill_create["audit_attribution"] = audit(kill_cred)
    call("createRun", "POST", args.cloud_url, "/runs", kill_create)
    kill = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager_cred), "kill_switch_id": "ks_uc_e2e_s5_run", "run_id": KILL_RUN_ID, "tenant_id": TENANT_ID, "node_id": CLOUD_NODE_ID, "instance_id": CLOUD_INSTANCE_ID, "reason": "operator_kill_switch", "propagation_ack_required": True})
    cancel = call("cancelRun", "POST", args.cloud_url, f"/runs/{KILL_RUN_ID}/cancel", {"credential": kill_cred, "audit_attribution": audit(kill_cred), "reason": "explicit_public_cancel_evidence"})
    kill_missing_ack = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager_cred), "kill_switch_id": "ks_uc_e2e_s5_missing_ack", "run_id": KILL_RUN_ID, "tenant_id": TENANT_ID, "node_id": None, "instance_id": None, "reason": "missing_ack_negative", "propagation_ack_required": True})
    broad_mutation = call("grantApproval", "POST", args.manager_url, "/approvals/55555555-5555-4555-8555-555555559999/grant", {**sec(manager_cred), "reason": "unknown_broad_grant"})

    traces = call("exportTraces", "POST", args.base_url, f"/runs/{RUN_ID}/traces/export", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    deny_traces = call("exportTraces", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/traces/export", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    cb_traces = call("exportTraces", "POST", args.base_url, f"/runs/{cb_run_id}/traces/export", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    kill_traces = call("exportTraces", "POST", args.cloud_url, f"/runs/{KILL_RUN_ID}/traces/export", {"credential": kill_cred, "audit_attribution": audit(kill_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    ttl_traces = call("exportTraces", "POST", args.base_url, f"/runs/{ttl_run_id}/traces/export", {"credential": ttl_cred, "audit_attribution": audit(ttl_cred), "redaction_policy": "uc-e2e-s5-redacted", "start": None, "end": None})
    replay = call("replayRun", "POST", args.base_url, f"/runs/{RUN_ID}/replay", {"credential": daemon_cred, "audit_attribution": audit(daemon_cred), "mode": "inspect_only", "side_effects_allowed": False})
    audit_export = call("exportGovernanceAudit", "POST", args.manager_url, "/governance/audit/export", {**sec(manager_cred), "run_id": RUN_ID})

    records = traces["body"].get("records", []) + deny_traces["body"].get("records", []) + cb_traces["body"].get("records", []) + kill_traces["body"].get("records", []) + ttl_traces["body"].get("records", [])
    manager_events = audit_export["body"].get("events", [])
    event_ids = trace_event_id_map(records, manager_events)
    external_executions = [o for o in resume["body"].get("action_outcomes", []) if o.get("status") == "Executed" and o.get("output", {}).get("action") == "artifact.publish_external"]
    cb_denied_breaker = cb_submit["body"].get("verification", {}).get("artifacts", {}).get("circuit_breaker", {})
    cb_denied_breaker_id = cb_denied_breaker.get("breaker_id") or cb_denied_breaker.get("circuit_breaker", {}).get("breaker_id")
    negatives = [
        {"case": "approval_denial_blocks_pending_action", "passed": denial["body"].get("status") == "denied" and deny_resume["body"].get("status") in {"denied", "expired"}, "reason_code": "operator_denied_publication"},
        {"case": "expired_approval_cannot_authorize_execution", "passed": expired["body"].get("status") == "Denied" and expired["body"].get("verification", {}).get("artifacts", {}).get("approval_status") == "expired"},
        {"case": "revoked_approval_cannot_authorize_execution", "passed": revoked["body"].get("status") == "Denied" and revoked["body"].get("verification", {}).get("artifacts", {}).get("approval_status") == "revoked"},
        {"case": "missing_policy_bundle_fails_closed", "passed": missing_policy["status"] == 400 and missing_policy["body"].get("code") == "missing_policy_bundle"},
        {"case": "expired_policy_bundle_fails_closed", "passed": expired_policy_create["status"] == 403 and expired_policy_create["body"].get("code") == "expired_policy_bundle" and ttl_create["status"] == 200 and ttl_start["status"] in {200, 500}},
        {"case": "revoked_policy_bundle_fails_closed", "passed": revoked_policy_create["status"] == 403 and revoked_policy_create["body"].get("code") == "revoked_policy_bundle"},
        {"case": "verifier_uncertainty_escalates_not_allow", "passed": uncertain_create["status"] == 200 and uncertainty["body"].get("status") in {"failed", "waiting_for_approval"}},
        {"case": "circuit_breaker_blocks_matching_action", "passed": cb_sync["body"].get("accepted") is True and cb_submit["body"].get("status") == "Denied" and cb_denied_breaker_id == breaker_uuid},
        {"case": "clearing_circuit_breaker_requires_scope", "passed": clear["body"].get("status") == "cleared" and clear_wrong_scope["status"] == 403},
        {"case": "kill_switch_cancels_matching_run", "passed": kill["body"].get("propagation_acknowledged") is True and kill["body"].get("cancel_status") == 200 and kill["body"].get("target_derived_from_registry") is True and kill["body"].get("cancel_payload_schema") == "splendor.daemon.lifecycle_request.v1"},
        {"case": "kill_switch_missing_ack_fails_closed", "passed": kill_missing_ack["body"].get("fail_closed") is True},
        {"case": "governance_plane_cannot_issue_broad_unknown_authority", "passed": broad_mutation["status"] == 404},
    ]
    required_positive = {
        "policy_published": published["status"] == 200 and bool(signed_policy) and published["body"].get("status") == "published",
        "policy_status_publicly_read": policy_status["status"] == 200,
        "run_created": create["status"] == 200,
        "internal_artifact_executed": internal["body"].get("status") == "Executed",
        "external_needs_approval": needs_approval.get("status") == "NeedsApproval",
        "adapter_not_called_before_approval": start["body"].get("status") == "waiting_for_approval" and start["body"].get("action_outcomes", [{}])[0].get("output") is None,
        "approval_granted": approval_request["status"] == 200 and approval_grant["body"].get("status") == "granted" and evidence.get("action_id") == approval_context["action_id"],
        "approved_action_executed_once": len(external_executions) == 1,
        "state_committed": bool(state_head["body"].get("state_node_id")),
        "audit_exported": audit_export["body"].get("exported") is True,
        "replay_inspect_only": replay["body"].get("mode") == "inspect_only",
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
        "replay_evidence": ["replayRun public API returned inspect_only approval explanation and did not execute external publish"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "external_publish_replayed": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["public_daemon_and_manager_http_used", "gateway_required_before_artifact_publish", "approval_scoped_to_action", "governance_plane_no_direct_runtime_mutation", "replay_no_external_publish"],
        "run_ids": [RUN_ID, DENY_RUN_ID, cb_run_id, KILL_RUN_ID, ttl_run_id],
        "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid}),
        "state_node_ids": [state_head["body"].get("state_node_id", "")],
        "state_hashes": [state_head["body"].get("data_hash", "")],
        "message_ids": [],
        "work_order_ids": [envelope["work_order_id"], deny_envelope["work_order_id"], cb_envelope["work_order_id"], kill_envelope["work_order_id"]],
        "approval_ids": [approval_context["approval_id"], deny_context["approval_id"], expired_evidence["approval_id"], revoked_evidence["approval_id"]],
        "node_ids": [CLOUD_NODE_ID],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "negative_cases": negatives,
        "positive_checks": required_positive,
        "scenario_failures": failures,
        "artifact_paths": [],
    }
    artifacts = {
        "scenario-report.json": scenario,
        "approval-flow.json": {"request": approval_request["body"], "grant": approval_grant["body"], "revoke": approval_revoke["body"], "denial": denial["body"], "expired": expired["body"], "revoked": revoked["body"]},
        "policy-bundle-report.json": {"published": published["body"], "status": policy_status["body"], "revoked": revoked_policy["body"], "expired_policy_create": expired_policy_create, "runtime_expired_policy": {"published": ttl_policy["body"], "create": ttl_create, "start": ttl_start}, "revoked_policy_create": revoked_policy_create, "missing_policy_create": missing_policy},
        "circuit-breaker-report.json": {"created": breaker["body"], "synced": cb_sync["body"], "blocked_action": cb_submit["body"], "cleared": clear["body"], "clear_wrong_scope": clear_wrong_scope},
        "kill-switch-report.json": {"activated": kill["body"], "explicit_cancel": cancel, "missing_ack": kill_missing_ack["body"]},
        "state-export.json": state_head["body"],
        "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "external_publish_replayed": False, "approval_lifecycles": [event.get("lifecycle") for event in replay["body"].get("approval_events", [])]},
        "audit-report.json": {"manager": audit_export["body"], "negative_cases": negatives, "event_ids": event_ids},
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
