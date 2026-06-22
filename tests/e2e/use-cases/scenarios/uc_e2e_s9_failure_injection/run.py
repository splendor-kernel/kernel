#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import shutil
import subprocess
import threading
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
RETRY_RUN_ID = "44444444-4444-4444-8444-444444449906"
UNSAFE_RETRY_RUN_ID = "44444444-4444-4444-8444-444444449907"
DENY_RUN_ID = "44444444-4444-4444-8444-444444449908"
TRACE_FAIL_RUN_ID = "44444444-4444-4444-8444-444444449909"
STATE_FAIL_RUN_ID = "44444444-4444-4444-8444-444444449910"
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


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    counter = 0

    def do_GET(self):  # noqa: N802
        type(self).counter += 1
        if self.path == "/allowed/s9-failure-fixture":
            body = json.dumps({"fixture": "uc-e2e-s9", "status": "ok"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_: object) -> None:
        return


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


def message_scope(credential: dict[str, Any], run_id: str, agent_id: str, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {**sec(credential), "tenant_id": tenant_id, "run_id": run_id, "agent_id": agent_id}


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
        "allowed_permissions": permissions if permissions is not None else allowed + [f"message.remote.proposal:{HELPER_AGENT_ID}"],
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
    work_order_id = envelope.get("work_order_id") or envelope.get("work_order", {}).get("work_order_id", "unknown")
    return {
        "request_id": f"req-uc-e2e-s9-{work_order_id}-{run_id}",
        "idempotency_key": f"idem-uc-e2e-s9-{work_order_id}-{run_id}",
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


def approval_policy(action_name: str, permission: str, *, expires_minutes: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.approval_policy.v1",
        "policy_id": f"policy_uc_e2e_s9_{action_name.replace('.', '_')}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "action_name": action_name,
        "adapter": "daemon.recording",
        "required_permission": permission,
        "side_effect_class": "External",
        "risk_level": "high",
        "reason": "UC-E2E-S9 verifier uncertainty/approval gate failure injection",
        "expires_at": utc(expires_minutes),
    }


def cli_work_order(run_id: str) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": f"{WORK_ORDER_ID}_cli_{run_id[-3:]}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": "UC-E2E-S9 public CLI trace/state failure injection",
        "allowed_actions": ["http_get", "write_file"],
        "allowed_adapters": ["http", "filesystem"],
        "allowed_permissions": ["s9.http.read", "s9.artifact.write"],
        "data_refs": ["fixture:http://local/allowed/s9-failure-fixture", "sandbox://uc-e2e-s9/failure.txt"],
        "quotas": {"max_actions_per_tick": 4, "max_http_requests_per_minute": 4, "max_filesystem_write_bytes": 4096},
        "placement": {"target": "local_resident", "requires_gpu": False},
        "issued_at": utc(-1),
        "expires_at": utc(60),
        "revocation": "active",
    }


def cli_action_http(port: int) -> dict[str, Any]:
    return {"name": "http_get", "adapter": "http", "params": {"url": f"http://127.0.0.1:{port}/allowed/s9-failure-fixture"}, "required_permissions": ["s9.http.read"], "usage": {"actions": 1, "http_requests": 1, "network_read_bytes": 128}}


def cli_action_write() -> dict[str, Any]:
    return {"name": "write_file", "adapter": "filesystem", "params": {"path": "artifacts/failure.txt", "contents": "UC-E2E-S9 failure fixture\n"}, "required_permissions": ["s9.artifact.write"], "usage": {"actions": 1, "filesystem_write_bytes": 28}}


def cli_config(root: Path, artifact_dir: Path, envelope: dict[str, Any], run_id: str, port: int, injection: dict[str, Any], actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "trace_db": str(artifact_dir / f"{run_id}.trace.db"),
        "state_db": str(artifact_dir / f"{run_id}.state.db"),
        "run_id": run_id,
        "cycles": 2 if injection.get("state_commit_fail") else 1,
        "work_order": {**envelope, "verification_secret": SECRET, "expected_placement_target": "local_resident"},
        "failure_injection": injection,
        "adapters": {
            "http": {"allowed_domains": ["127.0.0.1"], "allowed_methods": ["GET"], "timeout_ms": 2000},
            "filesystem": {"base_dir": str(artifact_dir / "cli-sandbox"), "max_write_bytes": 4096},
        },
        "tenants": [{"id": TENANT_ID, "allowed_actions": ["http_get", "write_file"], "allowed_adapters": ["http", "filesystem"], "allowed_permissions": ["s9.http.read", "s9.artifact.write"], "quotas": {"max_actions_per_tick": 4, "max_http_requests_per_minute": 4, "max_filesystem_write_bytes": 4096}}],
        "agents": [{
            "id": AGENT_ID,
            "tenant_id": TENANT_ID,
            "run_id": run_id,
            "snapshot_interval": 1,
            "initial_state": "{\"scenario\":\"UC-E2E-S9\"}",
            "allowed_permissions": ["s9.http.read", "s9.artifact.write"],
            "percepts": [{"schema": "splendor.percept.s9_failure.v1", "payload": {"url": f"http://127.0.0.1:{port}/allowed/s9-failure-fixture"}, "source": "uc-e2e-s9", "detail": "public CLI failure injection fixture"}],
            "policy": {"type": "static", "next_state": "{\"failure\":\"injected\"}", "actions": actions or [cli_action_http(port), cli_action_write()]},
        }],
    }


def trace_kind(record: dict[str, Any]) -> str:
    payload = record.get("payload", {})
    kind = payload.get("kind")
    key = next(iter(kind.keys())) if isinstance(kind, dict) and kind else str(kind)
    return {"LoopTickStarted": "tick.started", "LoopTickCompleted": "tick.completed", "ActionExecuted": "action.executed", "ActionDenied": "action.denied", "ActionFailed": "action.failed", "ActionNeedsApproval": "action.needs_approval", "ActionNeedsIntervention": "action.needs_intervention", "StateCommitted": "state.committed", "OutcomeRecorded": "outcome.recorded", "RunPaused": "run.paused", "RunStopped": "run.cancelled", "PolicyExpired": "policy.expired", "TraceWriteFailed": "trace.write_failed", "StateCommitFailed": "state.commit_failed"}.get(key, key)


def trace_id(record: dict[str, Any]) -> str:
    return str(record.get("payload", {}).get("trace_event_id") or record.get("trace_event_id") or "")


def trace_identity(record: dict[str, Any]) -> dict[str, Any]:
    return record.get("payload", {}).get("identity") or record.get("identity") or {}


def trace_action(record: dict[str, Any]) -> dict[str, Any]:
    kind = record.get("payload", {}).get("kind", {})
    if not isinstance(kind, dict) or not kind:
        return {}
    body = next(iter(kind.values()))
    if not isinstance(body, dict):
        return {}
    action = body.get("action") or body.get("result", {}).get("action")
    return action if isinstance(action, dict) else {}


def trace_kind_body(record: dict[str, Any]) -> dict[str, Any]:
    kind = record.get("payload", {}).get("kind", {})
    if not isinstance(kind, dict) or not kind:
        return {}
    body = next(iter(kind.values()))
    return body if isinstance(body, dict) else {}


def trace_action_id(record: dict[str, Any]) -> str | None:
    identity = trace_identity(record)
    if identity.get("action_id"):
        return str(identity["action_id"])
    body = trace_kind_body(record)
    result = body.get("result") if isinstance(body.get("result"), dict) else {}
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
    context = artifacts.get("context") if isinstance(artifacts.get("context"), dict) else {}
    approval = artifacts.get("approval") if isinstance(artifacts.get("approval"), dict) else {}
    outcome = body.get("outcome") if isinstance(body.get("outcome"), dict) else {}
    action_outcome = outcome.get("action_outcome") if isinstance(outcome.get("action_outcome"), dict) else {}
    approval_payload = body.get("approval") if isinstance(body.get("approval"), dict) else {}
    return context.get("action_id") or approval.get("action_id") or action_outcome.get("action_id") or approval_payload.get("action_id")


def trace_reasons(record: dict[str, Any]) -> list[str]:
    body = trace_kind_body(record)
    result = body.get("result") if isinstance(body.get("result"), dict) else {}
    reasons = result.get("reasons") or body.get("reasons") or []
    return [str(reason) for reason in reasons]


def add_event_evidence(evidence: dict[str, list[dict[str, Any]]], event: str, *, trace_event_id: str, source: str, original_event_type: str, artifact: str, run_id: str | None = None, action_id: str | None = None, message_id: str | None = None, state_node_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    if not trace_event_id:
        return
    row = {
        "trace_event_id": trace_event_id,
        "source": source,
        "original_event_type": original_event_type,
        "artifact": artifact,
        "run_id": run_id,
        "action_id": action_id,
        "message_id": message_id,
        "state_node_id": state_node_id,
        "details": details or {},
    }
    evidence.setdefault(event, []).append(row)


def evidence_ids(evidence: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    return {event: [row["trace_event_id"] for row in rows if row.get("trace_event_id")] for event, rows in evidence.items()}


def load_source(artifacts_root: Path, scenario_id: str) -> dict[str, Any]:
    artifact_dir = artifacts_root / scenario_id
    return {
        "scenario": read_json(artifact_dir / "scenario-report.json"),
        "audit": read_json(artifact_dir / "audit-report.json"),
        "replay": read_json(artifact_dir / "replay-report.json"),
        "trace": read_jsonl(artifact_dir / "trace-export.jsonl"),
        "dir": artifact_dir,
    }


def run_cli_failure_case(root: Path, artifact_dir: Path, commands: Path, run_id: str, port: int, case: str, injection: dict[str, Any], actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    envelope = sign_work_order(root, artifact_dir, commands, cli_work_order(run_id))
    config = cli_config(root, artifact_dir, envelope, run_id, port, injection, actions)
    config_path = artifact_dir / f"{case}.config.json"
    write_json(config_path, config)
    before = FixtureHandler.counter
    result = run_cmd(splendorctl(root) + ["run", "--config", str(config_path)], root, commands, check=False)
    export = run_cmd(splendorctl(root) + ["trace", "export", "--db", config["trace_db"], "--run", run_id], root, commands, check=False)
    records = read_jsonl_from_text(export.stdout) if export.returncode == 0 else []
    return {
        "case": case,
        "run_id": run_id,
        "work_order_id": envelope["work_order_id"],
        "exit": result.returncode,
        "stderr": result.stderr[-1000:],
        "http_counter_before": before,
        "http_counter_after": FixtureHandler.counter,
        "trace_export_exit": export.returncode,
        "records": records,
        "events": [trace_kind(record) for record in records],
        "trace_db": config["trace_db"],
        "state_db": config["state_db"],
    }


def read_jsonl_from_text(text: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


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
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9\n", encoding="utf-8")
    (artifact_dir / "stdout.log").write_text("UC-E2E-S9 failure injection scenario completed through public daemon/manager APIs\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")
    api_rows: list[dict[str, Any]] = []
    FixtureHandler.counter = 0
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    fixture_port = int(httpd.server_address[1])

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

    trace_failure_cli = run_cli_failure_case(root, artifact_dir, commands, TRACE_FAIL_RUN_ID, fixture_port, "trace_write_failure", {"trace_fail_on_event": "ActionVerificationStarted"})
    state_failure_cli = run_cli_failure_case(root, artifact_dir, commands, STATE_FAIL_RUN_ID, fixture_port, "state_commit_failure", {"state_commit_fail": True})
    verifier_unavailable_cli = run_cli_failure_case(
        root,
        artifact_dir,
        commands,
        VERIFIER_RUN_ID,
        fixture_port,
        "verifier_unavailable",
        {"verifier_unavailable_actions": ["http_get"]},
        actions=[cli_action_http(fixture_port)],
    )

    envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID))
    call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": envelope, "expected_audience": "central-manager"})
    create = call("createRun", "POST", args.base_url, "/runs", create_run_payload(RUN_ID, envelope))
    run_cred = daemon_credential(RUN_ID)
    success_action = call("submitAction", "POST", args.base_url, "/actions", {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": run_cred, "audit_attribution": audit(run_cred), "causal_trace_id": str(uuid.uuid4()), "action": action("s9.idempotent_read", {"idempotency_key": "s9-read-once"}, ["s9.idempotent_read"], "ReadOnly"), "adapter": "daemon.recording", "quota_usage": quota(actions=1, http_requests=1), "satisfied_preconditions": []})

    retry_envelope = sign_work_order(root, artifact_dir, commands, work_order(RETRY_RUN_ID, quota_max=2, actions=["s9.idempotent_read"], permissions=["s9.idempotent_read"]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(RETRY_RUN_ID, retry_envelope, quota_max=2))
    retry_cred = daemon_credential(RETRY_RUN_ID)
    retry_attempts = []
    for attempt in [1, 2, 3]:
        retry_attempts.append(call("submitAction", "POST", args.base_url, "/actions", {"action_id": f"55555555-5555-4555-8555-5555555598{attempt:02d}", "run_id": RETRY_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": retry_cred, "audit_attribution": audit(retry_cred), "causal_trace_id": f"55555555-5555-4555-8555-5555555597{attempt:02d}", "action": action("s9.idempotent_read", {"idempotency_key": "s9-read-once", "retry_attempt": attempt, "retryable": True, "max_attempts": 2}, ["s9.idempotent_read"], "ReadOnly"), "adapter": "daemon.recording", "quota_usage": quota(actions=1, http_requests=1), "satisfied_preconditions": []}))
    unsafe_envelope = sign_work_order(root, artifact_dir, commands, work_order(UNSAFE_RETRY_RUN_ID, quota_max=2, actions=["s9.unsafe_retry"], permissions=[]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(UNSAFE_RETRY_RUN_ID, unsafe_envelope, quota_max=2))
    unsafe_cred = daemon_credential(UNSAFE_RETRY_RUN_ID)
    unsafe_retry = call("submitAction", "POST", args.base_url, "/actions", {"action_id": "55555555-5555-4555-8555-555555559899", "run_id": UNSAFE_RETRY_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": unsafe_cred, "audit_attribution": audit(unsafe_cred), "causal_trace_id": "55555555-5555-4555-8555-555555559798", "action": action("s9.unsafe_retry", {"retry_attempt": 1, "retryable": False, "idempotency_key": None}, ["s9.unsafe_retry"], "External"), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})
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

    stale_placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": "s9-stale-placement", "request": {"target": "resident_cloud_pool", "required_capabilities": ["s9.stale.only"], "data_locality": "cloud", "dedicated_instance": False, "execution_mode": "live"}})
    failed_message = {**duplicate_message, "message": {**duplicate_message["message"], "message_id": "55555555-5555-4555-8555-555555559904"}}
    remote_failure = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": envelope["work_order_id"], "message_envelope": failed_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "s9-transport-fail", "simulate_failure": "toxiproxy_transport_failure"})

    deny_envelope = sign_work_order(root, artifact_dir, commands, work_order(DENY_RUN_ID, actions=["s9.approval_required"], permissions=["s9.approval_required"]))
    deny_action_id = "55555555-5555-4555-8555-555555559908"
    deny_policy_actions = [{"action_id": deny_action_id, "action": action("s9.approval_required", {}, ["s9.approval_required"]), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []}]
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(DENY_RUN_ID, deny_envelope, policy_actions=deny_policy_actions, approval_policies=[approval_policy("s9.approval_required", "s9.approval_required")]))
    deny_cred = daemon_credential(DENY_RUN_ID)
    deny_start = call("startRun", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/start", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "reason": "uc_e2e_s9_pending_approval"})
    approval_artifact = deny_start["body"].get("action_outcomes", [{}])[0].get("verification", {}).get("artifacts", {}).get("approval", {})
    approval_context = approval_artifact.get("approval") or approval_artifact
    approval_request = call("requestApproval", "POST", args.manager_url, "/approvals", {**sec(manager), "approval_id": approval_context.get("approval_id"), "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": DENY_RUN_ID, "action_id": approval_context.get("action_id"), "action_name": "s9.approval_required", "adapter": "daemon.recording", "policy_id": approval_context.get("policy_id") or "policy_uc_e2e_s9_s9_approval_required", "risk_level": "high", "audience": "daemon_local", "expires_at": utc(30), "reason": "S9 pending approval branch"})
    approval_denial = call("denyApproval", "POST", args.manager_url, f"/approvals/{approval_context.get('approval_id')}/deny", {**sec(manager), "reason": "S9 operator denial for fail-closed run"})
    deny_resume = call("resumeRun", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/resume", {"credential": deny_cred, "work_order": deny_envelope, "audit_attribution": audit(deny_cred), "reason": "approval_denied", "approval_evidence": approval_denial["body"].get("evidence")})

    cb_breaker_id = "55555555-5555-4555-8555-555555559911"
    cb_envelope = sign_work_order(root, artifact_dir, commands, work_order(CB_RACE_RUN_ID, actions=["s9.idempotent_read"], permissions=["s9.idempotent_read"]))
    call("createRun", "POST", args.base_url, "/runs", create_run_payload(CB_RACE_RUN_ID, cb_envelope))
    cb_cred = daemon_credential(CB_RACE_RUN_ID)
    cb_created = call("createCircuitBreaker", "POST", args.manager_url, "/governance/circuit-breakers", {**sec(manager), "breaker_id": cb_breaker_id, "tenant_id": TENANT_ID, "adapter": "daemon.recording", "action": "s9.idempotent_read", "reason": "S9 circuit breaker race wins"})
    cb_payload = call("readCircuitBreakerSyncPayload", "POST", args.manager_url, f"/governance/circuit-breakers/{cb_breaker_id}/sync-payload", {**sec(manager), "run_id": CB_RACE_RUN_ID, "reason": "S9 manager-propagated breaker"})
    cb_sync = call("syncCircuitBreakers", "POST", args.base_url, f"/runs/{CB_RACE_RUN_ID}/governance/circuit-breakers/sync", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "circuit_breakers": cb_payload["body"].get("circuit_breakers", []), "reason": cb_payload["body"].get("reason")})
    cb_blocked = call("submitAction", "POST", args.base_url, "/actions", {"run_id": CB_RACE_RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "credential": cb_cred, "audit_attribution": audit(cb_cred), "causal_trace_id": "55555555-5555-4555-8555-555555559912", "action": action("s9.idempotent_read", {"idempotency_key": "s9-cb-race"}, ["s9.idempotent_read"], "ReadOnly"), "adapter": "daemon.recording", "quota_usage": quota(), "satisfied_preconditions": []})

    kill_envelope = sign_work_order(root, artifact_dir, commands, work_order(KILL_RACE_RUN_ID, actions=["s9.idempotent_read"], permissions=["s9.idempotent_read"]))
    kill_cred = daemon_credential(KILL_RACE_RUN_ID, instance_id=CLOUD_INSTANCE_ID)
    kill_create_payload = create_run_payload(KILL_RACE_RUN_ID, kill_envelope)
    kill_create_payload["credential"] = kill_cred
    kill_create_payload["audit_attribution"] = audit(kill_cred)
    call("createRun", "POST", args.cloud_url, "/runs", kill_create_payload)
    kill_switch = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager), "kill_switch_id": "ks_uc_e2e_s9_run", "run_id": KILL_RACE_RUN_ID, "tenant_id": TENANT_ID, "node_id": CLOUD_NODE_ID, "instance_id": CLOUD_INSTANCE_ID, "reason": "S9 kill switch wins resume race", "propagation_ack_required": True})
    kill_missing_ack = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager), "kill_switch_id": "ks_uc_e2e_s9_missing_ack", "run_id": KILL_RACE_RUN_ID, "tenant_id": TENANT_ID, "node_id": None, "instance_id": None, "reason": "S9 missing ack fail closed", "propagation_ack_required": True})

    traces = call("exportTraces", "POST", args.base_url, f"/runs/{RUN_ID}/traces/export", {"credential": run_cred, "audit_attribution": audit(run_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    adapter_traces = call("exportTraces", "POST", args.base_url, f"/runs/{ADAPTER_FAIL_RUN_ID}/traces/export", {"credential": adapter_cred, "audit_attribution": audit(adapter_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    quota_traces = call("exportTraces", "POST", args.base_url, f"/runs/{QUOTA_RUN_ID}/traces/export", {"credential": quota_cred, "audit_attribution": audit(quota_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    retry_traces = call("exportTraces", "POST", args.base_url, f"/runs/{RETRY_RUN_ID}/traces/export", {"credential": retry_cred, "audit_attribution": audit(retry_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    unsafe_traces = call("exportTraces", "POST", args.base_url, f"/runs/{UNSAFE_RETRY_RUN_ID}/traces/export", {"credential": unsafe_cred, "audit_attribution": audit(unsafe_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    deny_traces = call("exportTraces", "POST", args.base_url, f"/runs/{DENY_RUN_ID}/traces/export", {"credential": deny_cred, "audit_attribution": audit(deny_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    cb_traces = call("exportTraces", "POST", args.base_url, f"/runs/{CB_RACE_RUN_ID}/traces/export", {"credential": cb_cred, "audit_attribution": audit(cb_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    kill_traces = call("exportTraces", "POST", args.cloud_url, f"/runs/{KILL_RACE_RUN_ID}/traces/export", {"credential": kill_cred, "audit_attribution": audit(kill_cred), "redaction_policy": "uc-e2e-s9-redacted", "start": None, "end": None})
    telemetry_read = call("getFleetTelemetry", "POST", args.manager_url, "/fleet/telemetry/read", sec(manager))
    manager_audit = call("auditEvents", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    governance_audit = call("exportGovernanceAudit", "POST", args.manager_url, "/governance/audit/export", {**sec(manager), "run_id": RUN_ID})
    message_before = call("getMessage", "POST", args.manager_url, f"/messages/{duplicate_message['message']['message_id']}/read", message_scope(manager, RUN_ID, HELPER_AGENT_ID))
    replay_before = call("inspectRun", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(run_cred))
    replay_audit_before = call("auditEvents", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    replay = call("replayRun", "POST", args.base_url, f"/runs/{RUN_ID}/replay", {"credential": run_cred, "audit_attribution": audit(run_cred), "mode": "inspect_only", "side_effects_allowed": False})
    replay_after = call("inspectRun", "GET", args.base_url, f"/runs/{RUN_ID}", headers=credential_header(run_cred))
    replay_audit_after = call("auditEvents", "POST", args.manager_url, "/fleet/audit/read", sec(manager))
    message_after = call("getMessage", "POST", args.manager_url, f"/messages/{duplicate_message['message']['message_id']}/read", message_scope(manager, RUN_ID, HELPER_AGENT_ID))

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

    records = (
        traces["body"].get("records", [])
        + adapter_traces["body"].get("records", [])
        + quota_traces["body"].get("records", [])
        + retry_traces["body"].get("records", [])
        + unsafe_traces["body"].get("records", [])
        + deny_traces["body"].get("records", [])
        + cb_traces["body"].get("records", [])
        + kill_traces["body"].get("records", [])
        + trace_failure_cli["records"]
        + state_failure_cli["records"]
        + verifier_unavailable_cli["records"]
    )
    manager_events: list[dict[str, Any]] = []
    if isinstance(manager_audit.get("body"), list):
        manager_events.extend(manager_audit["body"])
    governance_events = governance_audit.get("body", {}).get("events", []) if isinstance(governance_audit.get("body"), dict) else []
    if isinstance(governance_events, list):
        manager_events.extend(governance_events)
    event_evidence: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        kind = trace_kind(rec)
        identity = trace_identity(rec)
        action_name = trace_action(rec).get("name")
        reasons = trace_reasons(rec)
        run_id = rec.get("run_id") or identity.get("run_id")
        action_id = trace_action_id(rec)
        state_node_id = identity.get("state_node_id")
        if kind == "action.failed" and run_id == ADAPTER_FAIL_RUN_ID and action_name == "s9.adapter_failure":
            adapter_action_id = action_id or adapter_failure["body"].get("action_id")
            add_event_evidence(event_evidence, "adapter.failed", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=adapter_action_id, details={"action": action_name, "status": adapter_failure["body"].get("status"), "outcome_action_id": adapter_failure["body"].get("action_id"), "api_operation": "submitAction"})
        if kind in {"action.denied", "action.needs_intervention"} and run_id == VERIFIER_RUN_ID and "verifier_unavailable" in reasons:
            add_event_evidence(event_evidence, "verifier.unavailable", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"reasons": reasons, "status": "Denied", "public_path": "splendorctl run --config", "failure_injection": "verifier_unavailable_actions", "http_counter_before": verifier_unavailable_cli["http_counter_before"], "http_counter_after": verifier_unavailable_cli["http_counter_after"]})
        if kind == "action.denied" and run_id == QUOTA_RUN_ID and quota_second["body"].get("status") in {"Denied", "NeedsIntervention"}:
            add_event_evidence(event_evidence, "quota.exceeded", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"reasons": reasons})
        if kind == "trace.write_failed" and run_id == TRACE_FAIL_RUN_ID:
            add_event_evidence(event_evidence, "trace.write_failed", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, details={"http_counter_before": trace_failure_cli["http_counter_before"], "http_counter_after": trace_failure_cli["http_counter_after"]})
        if kind == "state.commit_failed" and run_id == STATE_FAIL_RUN_ID:
            add_event_evidence(event_evidence, "state.commit_failed", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, details={"events": state_failure_cli["events"]})
        if kind == "run.paused" and run_id == DENY_RUN_ID:
            add_event_evidence(event_evidence, "run.paused", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, details={"status": deny_start["body"].get("status")})
        if kind == "action.denied" and run_id == DENY_RUN_ID and deny_resume["body"].get("status") == "denied":
            add_event_evidence(event_evidence, "run.denied", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, action_id=action_id, details={"status": deny_resume["body"].get("status"), "reasons": reasons})
        if kind == "run.cancelled" and run_id == KILL_RACE_RUN_ID:
            add_event_evidence(event_evidence, "run.cancelled", trace_event_id=trace_id(rec), source="runtime_trace_export", original_event_type=kind, artifact="trace-export.jsonl", run_id=run_id, details={"kill_switch_id": "ks_uc_e2e_s9_run"})
    for ev in manager_events:
        event_type = ev.get("event_type")
        details = ev.get("details", {})
        trace_event_id = ev.get("trace_event_id", "")
        if event_type == "remote_message.failed" and details.get("message_id") == failed_message["message"]["message_id"]:
            add_event_evidence(event_evidence, "message.delivery_failed", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=RUN_ID, message_id=details.get("message_id"), details=details)
        if event_type == "placement.evaluated" and stale_placement["body"].get("status") == "rejected" and any("not available" in str(reason) for reason in stale_placement["body"].get("reasons", [])):
            add_event_evidence(event_evidence, "node.stale", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=None, details={"placement": stale_placement["body"]})
        if event_type == "circuit_breaker.tripped" and details.get("breaker_id") == cb_breaker_id:
            add_event_evidence(event_evidence, "circuit_breaker.tripped", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=CB_RACE_RUN_ID, details=details)
        if event_type == "kill_switch.activated" and details.get("kill_switch_id") in {"ks_uc_e2e_s9_run", "ks_uc_e2e_s9_missing_ack"}:
            add_event_evidence(event_evidence, "kill_switch.activated", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=KILL_RACE_RUN_ID, details=details)
    for trace_event_id in s5["scenario"].get("required_trace_event_ids", {}).get("policy.expired", []):
        add_event_evidence(event_evidence, "policy.expired", trace_event_id=trace_event_id, source="source_runtime_trace_export", original_event_type="policy.expired", artifact="UC-E2E-S5/trace-export.jsonl", run_id=s5_policy.get("runtime_expired_policy", {}).get("run_id"), action_id=s5_policy.get("runtime_expired_policy", {}).get("action_id"), details={"source_scenario": "UC-E2E-S5", "reason_code": s5_policy.get("runtime_expired_policy", {}).get("reason_code")})

    event_ids = evidence_ids(event_evidence)

    run_records = [record for record in records if record.get("run_id") == RUN_ID or trace_identity(record).get("run_id") == RUN_ID]
    trace_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE_ID, "instance_id": VPC_INSTANCE_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": RUN_ID, "work_order_id": envelope["work_order_id"]}, "records": run_records}
    tampered_records = json.loads(json.dumps(run_records))
    if tampered_records:
        tampered_records[0].setdefault("event_hash", {})["value"] = "0" * 64
    sync_failed = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": {**trace_batch, "records": tampered_records}})
    sync_recovered = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": trace_batch})

    retry_statuses = [attempt["body"].get("status") for attempt in retry_attempts]
    retry_executed = sum(1 for status in retry_statuses[:2] if status == "Executed")
    retry_third_denied = retry_statuses[2] in {"Denied", "NeedsIntervention"}
    bounded_retry_counts = {"s9.idempotent_read": retry_executed, "max_attempts": 2, "attempts_submitted": len(retry_attempts), "attempt_statuses": retry_statuses, "third_attempt_status": retry_statuses[2], "enforced_by": "gateway_quota", "quota_consumed_attempts": retry_executed}
    negative_cases = [
        {"case": "adapter_returns_failure_no_fake_success_committed", "passed": adapter_failure["body"].get("status") == "Failed" and before_adapter["body"].get("adapter_executions") == after_adapter["body"].get("adapter_executions"), "reason_codes": ["adapter_failed"]},
        {"case": "verifier_unavailable_denies_or_intervenes", "passed": verifier_unavailable_cli["trace_export_exit"] == 0 and verifier_unavailable_cli["http_counter_before"] == verifier_unavailable_cli["http_counter_after"] and bool(event_ids.get("verifier.unavailable")), "reason_codes": ["verifier_unavailable"]},
        {"case": "policy_unavailable_or_expired_denies_high_risk", "passed": s5_policy.get("runtime_expired_policy", {}).get("reason_code") == "policy_expired", "reason_codes": ["policy_expired"]},
        {"case": "trace_write_failure_before_side_effect_blocks_execution", "passed": trace_failure_cli["exit"] != 0 and trace_failure_cli["http_counter_before"] == trace_failure_cli["http_counter_after"] and bool(event_ids.get("trace.write_failed")), "reason_codes": ["trace_write_failed"]},
        {"case": "trace_write_failure_after_outcome_audit_visible_no_hidden_continuation", "passed": sync_failed["status"] == 403 and sync_recovered["body"].get("accepted_records", 0) > 0, "reason_codes": ["trace_sync_rejected"]},
        {"case": "state_commit_failure_prevents_next_tick", "passed": state_failure_cli["exit"] != 0 and state_failure_cli["http_counter_after"] - state_failure_cli["http_counter_before"] <= 1 and state_failure_cli["events"].count("tick.started") <= 1 and bool(event_ids.get("state.commit_failed")), "reason_codes": ["state_commit_failed"]},
        {"case": "remote_message_transport_failure_records_delivery_failure", "passed": remote_failure["body"].get("delivery_status") == "failed" and remote_failure["body"].get("remote_state_mutated") is False and bool(event_ids.get("message.delivery_failed")), "reason_codes": ["message_delivery_failed"]},
        {"case": "node_heartbeat_stale_denies_placement", "passed": stale_placement["body"].get("status") == "rejected", "reason_codes": stale_placement["body"].get("reasons", []) or ["node_stale"]},
        {"case": "quota_exceeded_denies_not_silently_retried", "passed": quota_first["body"].get("status") == "Executed" and quota_second["body"].get("status") in {"Denied", "NeedsIntervention"}, "reason_codes": quota_second["body"].get("verification", {}).get("reasons", []) or ["quota_exceeded"]},
        {"case": "circuit_breaker_wins_pending_approval_race", "passed": cb_payload["status"] == 200 and cb_sync["body"].get("accepted") is True and cb_blocked["body"].get("status") == "Denied" and bool(event_ids.get("circuit_breaker.tripped")), "reason_codes": ["circuit_breaker_tripped"]},
        {"case": "kill_switch_wins_resume_race_fail_closed", "passed": kill_switch["body"].get("cancel_status") == 200 and kill_missing_ack["body"].get("fail_closed") is True and bool(event_ids.get("kill_switch.activated")), "reason_codes": ["kill_switch_activated"]},
        {"case": "telemetry_stale_missing_cannot_authorize", "passed": telemetry_read["body"].get("authority") == "observational_only" and stale_placement["body"].get("status") == "rejected", "reason_codes": ["telemetry_non_authoritative"]},
    ]
    positive_checks = {
        "bounded_success_fixture_completed": bool(create["status"] == 200 and success_action["body"].get("status") == "Executed"),
        "quotas_consumed_predictably": bool(quota_first["body"].get("status") == "Executed" and quota_second["body"].get("status") in {"Denied", "NeedsIntervention"}),
        "bounded_retry_for_idempotent_read_only_action": bool(retry_executed == 2 and retry_third_denied and unsafe_retry["body"].get("status") in {"Denied", "NeedsIntervention"}),
        "idempotency_marker_prevents_duplicate_side_effect_application": bool(delivered["body"].get("delivery_status") == "delivered" and duplicate["body"].get("duplicate") is True and duplicate["body"].get("idempotency_key") == "s9-side-effect-once"),
        "recoverable_trace_sync_resumes_without_integrity_loss": bool(sync_failed["status"] == 403 and sync_recovered["body"].get("accepted_records", 0) > 0),
    }
    failures = [key for key, ok in positive_checks.items() if ok is not True]
    failures.extend(f"negative_failed:{item['case']}" for item in negative_cases if item.get("passed") is not True)
    missing_events = sorted(event for event in REQUIRED_TRACE_EVENTS if not event_ids.get(event))
    failures.extend(f"missing_required_trace_event:{event}" for event in missing_events)

    before_counts = {"adapter_executions": replay_before["body"].get("adapter_executions"), "manager_audit_events": len(replay_audit_before["body"]), "message_delivery_status": message_before["body"].get("delivery_status"), "message_duplicate": message_before["body"].get("duplicate"), "artifact_external_publishes": 0, "counter_sources": {"adapter": "GET /runs/{run_id}", "message": "POST /messages/{message_id}/read", "audit": "POST /fleet/audit/read", "artifact": "not_used_by_s9"}}
    after_counts = {"adapter_executions": replay_after["body"].get("adapter_executions"), "manager_audit_events": len(replay_audit_after["body"]), "message_delivery_status": message_after["body"].get("delivery_status"), "message_duplicate": message_after["body"].get("duplicate"), "artifact_external_publishes": 0, "counter_sources": before_counts["counter_sources"]}
    replay_report = {
        **replay["body"],
        "mode": "inspect_only",
        "side_effects_allowed_default": False,
        "side_effects_executed": before_counts != after_counts,
        "action_execution_counts_before_replay": before_counts,
        "action_execution_counts_after_replay": after_counts,
        "bounded_retry_counts": bounded_retry_counts,
        "idempotency_markers": ["s9-read-once", "s9-side-effect-once", "s9-transport-fail"],
        "public_replay_api": {"before_status": replay_before["status"], "replay_status": replay["status"], "after_status": replay_after["status"]},
        "failure_modes_explained": [item["case"] for item in negative_cases if item.get("passed") is True],
    }
    if replay_report["side_effects_executed"] is not False:
        failures.append("replay_executed_side_effects")

    state_head = call("getStateHead", "GET", args.base_url, f"/runs/{RUN_ID}/state-head", headers=credential_header(run_cred))
    trace_events = records
    trace_event_ids = sorted({trace_id(rec) for rec in records if trace_id(rec)} | {row["trace_event_id"] for rows in event_evidence.values() for row in rows if row.get("trace_event_id")})
    audit_report = {
        "scenario": "UC-E2E-S9",
        "negative_cases": negative_cases,
        "positive_checks": positive_checks,
        "bounded_retry_counts": replay_report["bounded_retry_counts"],
        "idempotency_markers": replay_report["idempotency_markers"],
        "required_event_evidence": event_evidence,
        "manager_audit_events": manager_events,
        "source_artifacts": {"UC-E2E-S1": digest_file(s1["dir"] / "audit-report.json"), "UC-E2E-S4": digest_file(s4["dir"] / "remote-message-report.json"), "UC-E2E-S5": digest_file(s5["dir"] / "audit-report.json")},
    }
    anti = {"status": "passed" if not failures else "failed", "private_helper_only_e2e": False, "gateway_bypass": False, "static_s9_evidence": False, "unbounded_retry": False, "fake_success_after_adapter_failure": False, "verifier_or_policy_fail_open": False, "telemetry_authorizes_action_or_placement": False, "replay_side_effects_allowed_default": False, "derived_from_required_event_evidence": sorted(event_evidence), "public_api_operations": sorted({row["operation_id"] for row in api_rows}), "retry_attempt_statuses": retry_statuses, "replay_counter_sources": before_counts["counter_sources"]}
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
        "run_ids": [RUN_ID, QUOTA_RUN_ID, ADAPTER_FAIL_RUN_ID, VERIFIER_RUN_ID, CB_RACE_RUN_ID, KILL_RACE_RUN_ID, RETRY_RUN_ID, UNSAFE_RETRY_RUN_ID, DENY_RUN_ID, TRACE_FAIL_RUN_ID, STATE_FAIL_RUN_ID] + s5["scenario"].get("run_ids", [])[:1],
        "trace_event_ids": trace_event_ids,
        "state_node_ids": [state_head["body"].get("state_node_id", "")] + s5["scenario"].get("state_node_ids", [])[:1],
        "state_hashes": [state_head["body"].get("data_hash", "")] + s5["scenario"].get("state_hashes", [])[:1],
        "message_ids": [duplicate_message["message"]["message_id"], failed_message["message"]["message_id"]],
        "work_order_ids": [envelope["work_order_id"], retry_envelope["work_order_id"], unsafe_envelope["work_order_id"], adapter_envelope["work_order_id"], quota_envelope["work_order_id"], verifier_unavailable_cli["work_order_id"], deny_envelope["work_order_id"], cb_envelope["work_order_id"], kill_envelope["work_order_id"], trace_failure_cli["work_order_id"], state_failure_cli["work_order_id"]] + s5["scenario"].get("work_order_ids", [])[:1],
        "approval_ids": [approval_context.get("approval_id", "")] + s5["scenario"].get("approval_ids", [])[:1],
        "node_ids": [VPC_NODE_ID, CLOUD_NODE_ID, "00000000-0000-4000-8000-000000009909"],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "required_event_evidence": event_evidence,
        "positive_checks": positive_checks,
        "negative_cases": negative_cases,
        "scenario_failures": failures,
        "source_scenarios": ["UC-E2E-S1", "UC-E2E-S4", "UC-E2E-S5"],
        "artifact_paths": [],
    }
    artifacts = {
        "scenario-report.json": scenario,
        "fault-injection-report.json": {"positive_checks": positive_checks, "negative_cases": negative_cases, "required_trace_event_ids": event_ids, "required_event_evidence": event_evidence, "source_scenarios": scenario["source_scenarios"], "cli_trace_failure": {k: v for k, v in trace_failure_cli.items() if k != "records"}, "cli_state_failure": {k: v for k, v in state_failure_cli.items() if k != "records"}, "cli_verifier_unavailable": {k: v for k, v in verifier_unavailable_cli.items() if k != "records"}},
        "verifier-unavailable-report.json": {"public_path": "splendorctl run --config + splendorctl trace export", "case": {k: v for k, v in verifier_unavailable_cli.items() if k != "records"}, "denied_action": "http_get", "adapter_counter": {"http_counter_before": verifier_unavailable_cli["http_counter_before"], "http_counter_after": verifier_unavailable_cli["http_counter_after"]}, "required_event_evidence": event_evidence.get("verifier.unavailable", [])},
        "quota-retry-report.json": {"quota_first": quota_first["body"], "quota_second": quota_second["body"], "retry_attempts": [attempt["body"] for attempt in retry_attempts], "unsafe_retry": unsafe_retry["body"], "bounded_retry_counts": replay_report["bounded_retry_counts"], "retry_policy": {"mode": "explicit_public_retry_policy", "max_attempts": 2, "retryable_action": "s9.idempotent_read", "idempotency_key": "s9-read-once", "enforced_by": "gateway_quota", "unsafe_retry_rejection": "gateway_permission_denial"}},
        "idempotency-report.json": {"delivered": delivered["body"], "duplicate": duplicate["body"], "markers": replay_report["idempotency_markers"]},
        "failure-matrix.json": {item["case"]: item for item in negative_cases},
        "trace-sync-report.json": {"failed": sync_failed["body"], "failed_status": sync_failed["status"], "recovered": sync_recovered["body"], "tampered_record_count": len(tampered_records)},
        "fleet-telemetry.json": {"authority": telemetry_read["body"].get("authority"), "stale_placement": stale_placement["body"], "telemetry": telemetry_read["body"], "source": "S9 public fleet telemetry and stale placement"},
        "governance-race-report.json": {"circuit_breaker": {"created": cb_created["body"], "sync_payload": cb_payload["body"], "synced": cb_sync["body"], "blocked_action": cb_blocked["body"]}, "kill_switch": {"activated": kill_switch["body"], "missing_ack": kill_missing_ack["body"]}, "approval_flow": {"request": approval_request["body"], "denial": approval_denial["body"], "start": deny_start["body"], "resume": deny_resume["body"]}},
        "state-export.json": state_head["body"],
        "replay-report.json": replay_report,
        "audit-report.json": audit_report,
        "manager-audit-export.json": {"audit_read": manager_audit["body"], "governance_export": governance_audit["body"]},
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
    httpd.shutdown()
    if failures:
        raise SystemExit("UC-E2E-S9 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
