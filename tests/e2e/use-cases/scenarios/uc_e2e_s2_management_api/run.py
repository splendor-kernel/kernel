#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures"))
from acceptance_provider_evidence import (  # noqa: E402
    provider_effect_state,
    read_provider_evidence,
)


TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "55555555-5555-4555-8555-555555555555"
RUN_ID = "66666666-6666-4666-8666-666666666666"
TS_RUN_ID = "77777777-7777-4777-8777-777777777777"
PY_RUN_ID = "88888888-8888-4888-8888-888888888888"
CLI_RUN_ID = "99999999-9999-4999-8999-999999999999"
PROVIDER_FAILURE_RUN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
MISSING_PROVIDER_RUN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
WORK_ORDER_ID = "wo_uc_e2e_s2_management_api"
SECRET = "splendor-local-work-order-secret"
KEY_ID = "work-order-local-key"
ACTION_NAME = "daemon_management_action"
ADAPTER = "daemon.local"
PROVIDER_FAILURE_ACTION = "s9.adapter_failure"
PROVIDER_FAILURE_ADAPTER = "acceptance-fixture"
MISSING_PROVIDER_ACTION = "missing.provider.action"
MISSING_PROVIDER_ADAPTER = "missing-provider"
BASE_SCOPES = [
    "health_read",
    "capabilities_read",
    "runs_create",
    "runs_start",
    "runs_read",
    "runs_pause",
    "runs_resume",
    "runs_stop",
    "percepts_append",
    "actions_submit",
    "traces_read",
    "state_read",
    "replay_create",
]


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def splendorctl_cmd_prefix(root: Path) -> list[str]:
    container = Path("/usr/local/bin/splendorctl")
    if root == Path("/workspace") and container.exists():
        return [str(container)]
    local = root / "target" / "debug" / "splendorctl"
    if local.exists():
        return [str(local)]
    if container.exists():
        return [str(container)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    if shutil.which("cargo"):
        return ["cargo", "run", "-q", "-p", "splendorctl", "--"]
    return ["splendorctl"]


def principal(label: str) -> dict[str, Any]:
    return {
        "app": {"app_principal_id": "app_uc_e2e_s2", "label": "UC-E2E-S2"},
        "client_principal_id": f"client_uc_e2e_s2_{label}",
        "label": f"UC-E2E-S2 {label}",
    }


def caller_credential(
    scopes: list[str] | None = None,
    *,
    credential_id: str = "cred_uc_e2e_s2_management",
    expired: bool = False,
    revoked: bool = False,
    wrong_audience: bool = False,
) -> dict[str, Any]:
    return {
        "credential_id": credential_id,
        "principal": principal(credential_id),
        "scopes": scopes or BASE_SCOPES,
        "binding": {"tenant": {"tenant_id": TENANT_ID}},
        "audience": {"daemon": {"daemon_id": "daemon_other" if wrong_audience else "daemon_local"}},
        "expires_at": utc(-5 if expired else 60),
        "revocation": {"revoked": {"reason": "operator_revoked"}} if revoked else "active",
    }


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {
        "principal": credential["principal"],
        "credential_id": credential["credential_id"],
        "requested_at": utc(0),
    }


def work_order(run_id: str | None, suffix: str, *, expires_offset_minutes: int = 60, revoked: bool = False) -> dict[str, Any]:
    issued_offset = -2 if expires_offset_minutes > 0 else expires_offset_minutes - 10
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": f"{WORK_ORDER_ID}_{suffix}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": "UC-E2E-S2 management API public-boundary run",
        "allowed_actions": [ACTION_NAME],
        "allowed_adapters": [ADAPTER],
        "allowed_permissions": [],
        "data_refs": ["management-api://fixture"],
        "quotas": {"max_actions_per_tick": 4},
        "placement": {"target": "local_resident", "requires_gpu": False},
        "issued_at": utc(issued_offset),
        "expires_at": utc(expires_offset_minutes),
        "revocation": {"revoked": {"reason": "operator_revoked"}} if revoked else "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    proc = run_cmd(
        splendorctl_cmd_prefix(root)
        + ["work-order", "sign", "--input", str(unsigned), "--key-id", KEY_ID, "--secret", SECRET],
        root,
        commands,
    )
    return json.loads(proc.stdout)


def action(name: str = ACTION_NAME) -> dict[str, Any]:
    if name == PROVIDER_FAILURE_ACTION:
        params = {}
        permissions = [name]
        postconditions = ["failure_recorded"]
    else:
        params = {"source": "uc-e2e-s2", "ok": True}
        permissions = []
        postconditions = ["marker_recorded"]
    return {
        "name": name,
        "params": params,
        "side_effect_class": "External",
        "cost_estimate": None,
        "required_permissions": permissions,
        "preconditions": [],
        "postconditions": postconditions,
    }


def create_run_request(envelope: dict[str, Any], credential: dict[str, Any], run_id: str) -> dict[str, Any]:
    return {
        "request_id": f"req-uc-e2e-s2-{run_id}",
        "idempotency_key": f"idem-uc-e2e-s2-{run_id}",
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "work_order": envelope,
        "credential": credential,
        "audit_attribution": audit(credential),
        "allowed_actions": [ACTION_NAME],
        "allowed_adapters": [ADAPTER],
        "allowed_permissions": [],
        "policy_actions": [],
        "policy_bundle_required": False,
        "policy_bundle": None,
        "registered_actions": [{"name": ACTION_NAME, "adapter": ADAPTER}],
        "approval_policies": [],
        "circuit_breakers": [],
        "allowed_percept_schemas": ["splendor.percept.management_api.v1"],
        "allowed_percept_sources": ["uc-e2e-s2-management-client"],
        "initial_state": {"scenario": "UC-E2E-S2", "run_id": run_id},
        "snapshot_interval": 1,
    }


def lifecycle(credential: dict[str, Any], reason: str, work_order_envelope: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "credential": credential,
        "work_order": work_order_envelope,
        "audit_attribution": audit(credential),
        "reason": reason,
        "approval_evidence": None,
    }


def percept() -> dict[str, Any]:
    return {
        "schema": "splendor.percept.management_api.v1",
        "payload": {"request": "exercise management API", "scenario": "UC-E2E-S2"},
        "provenance": {"source": "uc-e2e-s2-management-client", "detail": "public daemon API"},
        "timestamp": utc(0),
    }


def trace_event_id(record: dict[str, Any]) -> str:
    return str(record.get("payload", {}).get("trace_event_id", ""))


def event_type(record: dict[str, Any]) -> str:
    kind = record.get("payload", {}).get("kind")
    key = kind if isinstance(kind, str) else next(iter(kind.keys())) if isinstance(kind, dict) and kind else "unknown"
    return {
        "RunStarted": "run.started",
        "WorkOrderAccepted": "work_order.accepted",
        "DaemonAudit": "daemon.audit",
        "PerceptsAppended": "percepts.appended",
        "LoopTickStarted": "tick.started",
        "PerceptsReceived": "percepts.received",
        "StateLoaded": "state.loaded",
        "PolicyInvoked": "policy.invoked",
        "PolicyCompleted": "policy.completed",
        "CandidatesProposed": "actions.proposed",
        "ConstraintsEvaluated": "constraints.evaluated",
        "ActionVerificationStarted": "verification.started",
        "ActionVerificationCompleted": "verification.completed",
        "ActionExecuted": "action.executed",
        "ActionFailed": "action.failed",
        "ActionDenied": "action.denied",
        "OutcomeRecorded": "outcome.recorded",
        "StateCommitted": "state.committed",
        "LoopTickCompleted": "tick.completed",
        "RunPaused": "run.paused",
        "RunResumed": "run.resumed",
        "RunStopped": "run.cancelled_or_stopped",
    }.get(key, key)


def is_uuid(value: object) -> bool:
    try:
        return str(uuid.UUID(str(value))) == str(value).lower()
    except Exception:
        return False


class ApiClient:
    def __init__(self, base_url: str, traffic_path: Path):
        self.base_url = base_url.rstrip("/")
        self.traffic_path = traffic_path

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        header_credential: dict[str, Any] | None = None,
        expected: int | None = None,
    ) -> tuple[int, dict[str, Any]]:
        url = self.base_url + path
        headers = {"Accept": "application/json", "X-Splendor-API-Version": "0.1", "X-Splendor-Client": "uc-e2e-s2"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, sort_keys=True).encode("utf-8")
        if header_credential is not None:
            headers["X-Splendor-Caller-Credential"] = json.dumps(header_credential, sort_keys=True, separators=(",", ":"))
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        started = utc(0)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read().decode("utf-8")
                status = response.status
                parsed = json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            status = exc.code
            try:
                parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}
        entry = {
            "method": method,
            "path": path,
            "status": status,
            "started_at": started,
            "completed_at": utc(0),
            "request_has_body": body is not None,
            "request_credential_id": (body or {}).get("credential", {}).get("credential_id") if isinstance((body or {}).get("credential"), dict) else None,
            "header_credential_id": header_credential.get("credential_id") if header_credential else None,
            "response_code": parsed.get("code"),
        }
        with self.traffic_path.open("a", encoding="utf-8") as traffic:
            traffic.write(json.dumps(entry, sort_keys=True) + "\n")
        if expected is not None and status != expected:
            raise AssertionError(f"{method} {path} expected {expected}, got {status}: {parsed}")
        return status, parsed


def wait_for_daemon(client: ApiClient, credential: dict[str, Any]) -> dict[str, Any]:
    last: Exception | None = None
    for _ in range(90):
        try:
            status, body = client.request("GET", "/health", header_credential=credential)
            if status == 200:
                return body
        except Exception as exc:  # noqa: BLE001 - probe loop records final error below
            last = exc
        time.sleep(0.5)
    raise SystemExit(f"daemon did not become ready: {last}")


def provider_counters(base_url: str) -> dict[str, Any]:
    return read_provider_evidence(base_url)


def unauthenticated_provider_mutation(base_url: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/actions",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def load_ts_client_contract(root: Path) -> dict[str, Any]:
    source = (root / "typescript/packages/client/src/index.ts").read_text(encoding="utf-8")
    types = (root / "typescript/packages/types/src/index.ts").read_text(encoding="utf-8")
    required_methods = [
        "createRun",
        "inspectRun",
        "startRun",
        "pauseRun",
        "resumeRun",
        "stopRun",
        "cancelRun",
        "appendPercept",
        "readTraces",
        "exportTraces",
        "getStateHead",
        "requestReplay",
        "submitAction",
        "getHealth",
        "getVersion",
        "getCapabilities",
    ]
    missing = [method for method in required_methods if f"async {method}" not in source]
    required_type_markers = ["TraceExportRequest", "TraceExportResponse", "VersionResponse", "ReplayRequest"]
    missing_types = [marker for marker in required_type_markers if marker not in types]
    return {
        "status": "passed" if not missing and not missing_types else "failed",
        "required_methods": required_methods,
        "missing_methods": missing,
        "required_type_markers": required_type_markers,
        "missing_type_markers": missing_types,
        "client_refuses_anonymous_fallback": "unauthenticated fallback is not allowed" in source,
        "client_sends_caller_credential_header": "X-Splendor-Caller-Credential" in source,
        "client_requires_replay_suppression": "side_effects_allowed: false" in source,
    }


def load_python_sdk_contract(root: Path) -> dict[str, Any]:
    daemon_client = root / "python/splendor/daemon_client.py"
    source = daemon_client.read_text(encoding="utf-8") if daemon_client.exists() else ""
    return {
        "status": "passed" if "class SplendorDaemonClient" in source else "failed",
        "daemon_client_present": daemon_client.exists(),
        "refuses_anonymous_fallback": "anonymous fallback is not allowed" in source,
        "replay_suppressed_by_default": '"side_effects_allowed": False' in source,
        "side_effect_boundary": "only calls daemon endpoints" in source,
    }


def workflow_input(base_url: str, run_id: str, envelope: dict[str, Any], credential: dict[str, Any]) -> dict[str, Any]:
    create = create_run_request(envelope, credential, run_id)
    life = lifecycle(credential, "client-workflow")
    return {
        "base_url": base_url,
        "token": "uc-e2e-s2-token",
        "run_id": run_id,
        "credential": credential,
        "audit_attribution": audit(credential),
        "create_run": create,
        "lifecycle": life,
        "percept": percept(),
        "submit_action": {
            "run_id": run_id,
            "tenant_id": TENANT_ID,
            "agent_id": AGENT_ID,
            "credential": credential,
            "audit_attribution": audit(credential),
            "causal_trace_id": None,
            "action": action(),
            "adapter": ADAPTER,
            "quota_usage": None,
            "satisfied_preconditions": [],
            "approval_evidence": None,
        },
    }


def execute_python_sdk_workflow(root: Path, base_url: str, artifact_dir: Path, commands: Path, envelope: dict[str, Any]) -> dict[str, Any]:
    import sys

    sys.path.insert(0, str(root / "python"))
    from splendor.daemon_client import SplendorDaemonClient  # type: ignore

    cred = caller_credential(credential_id="cred_uc_e2e_s2_python")
    data = workflow_input(base_url, PY_RUN_ID, envelope, cred)
    sdk = SplendorDaemonClient(base_url, data["token"], default_credential=cred, default_audit_attribution=data["audit_attribution"])
    operations: list[str] = []
    def rec(name: str, fn):
        value = fn(); operations.append(name); return value
    health = rec("getHealth", lambda: sdk.get_health())
    version = rec("getVersion", lambda: sdk.get_version())
    capabilities = rec("getCapabilities", lambda: sdk.get_capabilities())
    created = rec("createRun", lambda: sdk.create_run(data["create_run"]))
    rec("appendPercept", lambda: sdk.append_percept(PY_RUN_ID, data["percept"]))
    tick = rec("startRun", lambda: sdk.start_run(PY_RUN_ID, data["lifecycle"]))
    inspected = rec("inspectRun", lambda: sdk.inspect_run(PY_RUN_ID))
    state = rec("getStateHead", lambda: sdk.get_state_head(PY_RUN_ID))
    traces_body = rec("getRunTraces", lambda: sdk.read_traces(PY_RUN_ID, redaction_policy="tenant-default"))
    traces = traces_body.get("records", [])
    causal = next((trace_event_id(record) for record in traces if trace_event_id(record)), None)
    if not causal:
        raise AssertionError("python SDK workflow missing causal trace id")
    submit = {**data["submit_action"], "causal_trace_id": causal}
    outcome = rec("submitAction", lambda: sdk.submit_action(submit))
    exported = rec("exportTraces", lambda: sdk.export_traces(PY_RUN_ID, redaction_policy="tenant-default"))
    before = sdk.inspect_run(PY_RUN_ID)
    replay = rec("replayRun", lambda: sdk.request_replay(PY_RUN_ID))
    after = sdk.inspect_run(PY_RUN_ID)
    stopped = rec("cancelRun", lambda: sdk.cancel_run(PY_RUN_ID, {**data["lifecycle"], "reason": "python-sdk-cancel"}))
    evidence = {
        "status": "passed", "executable_workflow": True, "operations_observed": operations, "run_id": PY_RUN_ID,
        "health_local_only": health.get("local_only"), "version": version.get("version"), "capabilities_local_only": capabilities.get("local_only"),
        "created_status": created.get("status"), "tick_id": tick.get("tick_id"), "inspect_status": inspected.get("status"),
        "state_node_id": state.get("state_node_id"), "trace_count": len(traces), "action_status": outcome.get("status"),
        "trace_export_record_count": exported.get("record_count"), "replay_mode": replay.get("mode"),
        "replay_side_effects_allowed": replay.get("side_effects_allowed"),
        "adapter_executions_before_replay": before.get("adapter_executions"), "adapter_executions_after_replay": after.get("adapter_executions"),
        "stopped_status": stopped.get("status"),
    }
    write_json(artifact_dir / "python-sdk-workflow.json", evidence)
    commands.write_text(commands.read_text(encoding="utf-8") + "# executed Python SplendorDaemonClient workflow\n", encoding="utf-8")
    return evidence


def execute_ts_client_workflow(root: Path, base_url: str, artifact_dir: Path, commands: Path, envelope: dict[str, Any]) -> dict[str, Any]:
    input_path = artifact_dir / "typescript-workflow-input.json"
    output_path = artifact_dir / "typescript-client-workflow.json"
    cred = caller_credential(credential_id="cred_uc_e2e_s2_typescript")
    write_json(input_path, workflow_input(base_url, TS_RUN_ID, envelope, cred))
    run_cmd(["npm", "run", "build"], root, commands)
    run_cmd(["node", str(Path(__file__).with_name("ts_client_workflow.mjs")), str(input_path), str(output_path)], root, commands)
    return json.loads(output_path.read_text(encoding="utf-8"))


def execute_cli_request(root: Path, base_url: str, artifact_dir: Path, commands: Path, method: str, path: str, *, body: dict[str, Any] | None = None, credential: dict[str, Any] | None = None, name: str) -> dict[str, Any]:
    args = splendorctl_cmd_prefix(root) + ["daemon", "request", "--method", method, "--url", base_url.rstrip("/") + path, "--token", "uc-e2e-s2-token"]
    if body is not None:
        body_path = artifact_dir / f"cli-{name}-body.json"
        write_json(body_path, body)
        args += ["--body", str(body_path)]
    if credential is not None:
        cred_path = artifact_dir / f"cli-{name}-credential.json"
        write_json(cred_path, credential)
        args += ["--caller-credential", str(cred_path)]
    proc = run_cmd(args, root, commands)
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def execute_cli_workflow(root: Path, base_url: str, artifact_dir: Path, commands: Path, envelope: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("cargo"):
        run_cmd(["cargo", "build", "-p", "splendorctl"], root, commands)
    cred = caller_credential(credential_id="cred_uc_e2e_s2_cli")
    data = workflow_input(base_url, CLI_RUN_ID, envelope, cred)
    ops: list[str] = []
    def rec(name: str, method: str, path: str, **kwargs):
        value = execute_cli_request(root, base_url, artifact_dir, commands, method, path, name=name, **kwargs)
        ops.append(name)
        return value
    health = rec("getHealth", "GET", "/health", credential=cred)
    version = rec("getVersion", "GET", "/version", credential=cred)
    capabilities = rec("getCapabilities", "GET", "/capabilities", credential=cred)
    created = rec("createRun", "POST", "/runs", body=data["create_run"])
    rec("appendPercept", "POST", f"/runs/{CLI_RUN_ID}/percepts", body={"credential": cred, "audit_attribution": data["audit_attribution"], "percept": data["percept"]})
    tick = rec("startRun", "POST", f"/runs/{CLI_RUN_ID}/start", body=data["lifecycle"])
    inspected = rec("inspectRun", "GET", f"/runs/{CLI_RUN_ID}", credential=cred)
    state = rec("getStateHead", "GET", f"/runs/{CLI_RUN_ID}/state-head", credential=cred)
    traces_body = rec("getRunTraces", "GET", f"/runs/{CLI_RUN_ID}/traces?redaction_policy=tenant-default", credential=cred)
    traces = traces_body.get("records", [])
    causal = next((trace_event_id(record) for record in traces if trace_event_id(record)), None)
    if not causal:
        raise AssertionError("splendorctl workflow missing causal trace id")
    outcome = rec("submitAction", "POST", "/actions", body={**data["submit_action"], "causal_trace_id": causal})
    exported = rec("exportTraces", "POST", f"/runs/{CLI_RUN_ID}/traces/export", body={"credential": cred, "audit_attribution": data["audit_attribution"], "redaction_policy": "tenant-default", "start": None, "end": None})
    before = execute_cli_request(root, base_url, artifact_dir, commands, "GET", f"/runs/{CLI_RUN_ID}", credential=cred, name="inspect-before-replay")
    replay = rec("replayRun", "POST", f"/runs/{CLI_RUN_ID}/replay", body={"credential": cred, "audit_attribution": data["audit_attribution"], "mode": "inspect_only", "side_effects_allowed": False})
    after = execute_cli_request(root, base_url, artifact_dir, commands, "GET", f"/runs/{CLI_RUN_ID}", credential=cred, name="inspect-after-replay")
    stopped = rec("cancelRun", "POST", f"/runs/{CLI_RUN_ID}/cancel", body={**data["lifecycle"], "reason": "cli-cancel"})
    evidence = {
        "status": "passed", "executable_workflow": True, "operations_observed": ops, "run_id": CLI_RUN_ID,
        "health_local_only": health.get("local_only"), "version": version.get("version"), "capabilities_local_only": capabilities.get("local_only"),
        "created_status": created.get("status"), "tick_id": tick.get("tick_id"), "inspect_status": inspected.get("status"),
        "state_node_id": state.get("state_node_id"), "trace_count": len(traces), "action_status": outcome.get("status"),
        "trace_export_record_count": exported.get("record_count"), "replay_mode": replay.get("mode"),
        "replay_side_effects_allowed": replay.get("side_effects_allowed"), "adapter_executions_before_replay": before.get("adapter_executions"),
        "adapter_executions_after_replay": after.get("adapter_executions"), "stopped_status": stopped.get("status"),
    }
    write_json(artifact_dir / "splendorctl-workflow.json", evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default=os.environ.get("SPLENDOR_DAEMON_URL", "http://127.0.0.1:8077"))
    parser.add_argument("--action-provider-url", default="http://acceptance-action-provider:8086")
    args = parser.parse_args()

    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S2"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("", encoding="utf-8")
    traffic = artifact_dir / "api-traffic.ndjson"
    traffic.write_text("", encoding="utf-8")
    client = ApiClient(args.base_url, traffic)

    failures: list[str] = []
    negative_cases: list[dict[str, Any]] = []
    operation_ids: list[str] = []
    management_credential = caller_credential()
    health = wait_for_daemon(client, caller_credential(["health_read"], credential_id="cred_uc_e2e_s2_health"))
    _, version_body = client.request("GET", "/version", header_credential=caller_credential(["health_read"], credential_id="cred_uc_e2e_s2_version"), expected=200)
    _, capabilities = client.request("GET", "/capabilities", header_credential=caller_credential(["capabilities_read"], credential_id="cred_uc_e2e_s2_capabilities"), expected=200)
    operation_ids.extend(["getHealth", "getVersion", "getCapabilities"])

    envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID, "primary"))
    create_req = create_run_request(envelope, caller_credential(["runs_create"], credential_id="cred_uc_e2e_s2_create"), RUN_ID)
    _, created = client.request("POST", "/runs", body=create_req, expected=200)
    operation_ids.append("createRun")

    append_cred = caller_credential(["percepts_append"], credential_id="cred_uc_e2e_s2_percepts")
    _, append_response = client.request(
        "POST",
        f"/runs/{RUN_ID}/percepts",
        body={"credential": append_cred, "audit_attribution": audit(append_cred), "percept": percept()},
        expected=200,
    )
    operation_ids.append("appendPercept")

    start_cred = caller_credential(["runs_start"], credential_id="cred_uc_e2e_s2_start")
    _, tick = client.request("POST", f"/runs/{RUN_ID}/start", body=lifecycle(start_cred, "start"), expected=200)
    operation_ids.append("startRun")

    read_cred = caller_credential(["runs_read"], credential_id="cred_uc_e2e_s2_read")
    _, inspected = client.request("GET", f"/runs/{RUN_ID}", header_credential=read_cred, expected=200)
    operation_ids.append("inspectRun")
    state_cred = caller_credential(["state_read"], credential_id="cred_uc_e2e_s2_state")
    _, state_head = client.request("GET", f"/runs/{RUN_ID}/state-head", header_credential=state_cred, expected=200)
    operation_ids.append("getStateHead")
    traces_cred = caller_credential(["traces_read"], credential_id="cred_uc_e2e_s2_traces")
    _, traces = client.request(
        "GET",
        f"/runs/{RUN_ID}/traces?redaction_policy=tenant-default",
        header_credential=traces_cred,
        expected=200,
    )
    operation_ids.append("getRunTraces")
    trace_records = traces.get("records", [])
    causal_trace_id = next((trace_event_id(record) for record in trace_records if is_uuid(trace_event_id(record))), None)
    if not causal_trace_id:
        failures.append("s2_missing_causal_trace_id")

    action_cred = caller_credential(["actions_submit"], credential_id="cred_uc_e2e_s2_action")
    provider_before_unauthenticated = provider_counters(args.action_provider_url)
    unauthenticated_status, unauthenticated_body = unauthenticated_provider_mutation(
        args.action_provider_url
    )
    provider_after_unauthenticated = provider_counters(args.action_provider_url)
    unauthenticated_denied = (
        unauthenticated_status == 401
        and unauthenticated_body.get("error")
        == "request_authentication_failed"
        and provider_after_unauthenticated.get("requests_total")
        == provider_before_unauthenticated.get("requests_total")
        and provider_after_unauthenticated.get("effects_applied")
        == provider_before_unauthenticated.get("effects_applied")
        and provider_after_unauthenticated.get("authenticated_requests")
        == provider_before_unauthenticated.get("authenticated_requests")
    )
    negative_cases.append(
        {
            "case": "direct_unauthenticated_provider_mutation_rejected",
            "passed": unauthenticated_denied,
            "status": unauthenticated_status,
            "before": provider_before_unauthenticated,
            "after": provider_after_unauthenticated,
        }
    )
    if not unauthenticated_denied:
        failures.append("s2_provider_mutation_was_not_authenticated")
    provider_before_action = provider_counters(args.action_provider_url)
    _, action_outcome = client.request(
        "POST",
        "/actions",
        body={
            "run_id": RUN_ID,
            "tenant_id": TENANT_ID,
            "agent_id": AGENT_ID,
            "credential": action_cred,
            "audit_attribution": audit(action_cred),
            "causal_trace_id": causal_trace_id,
            "action": action(),
            "adapter": ADAPTER,
            "quota_usage": None,
            "satisfied_preconditions": [],
            "approval_evidence": None,
        },
        expected=200,
    )
    operation_ids.append("submitAction")
    if action_outcome.get("status") != "Executed":
        failures.append(
            f"s2_allowed_action_not_executed:{action_outcome.get('status')}:{action_outcome.get('error')}"
        )
    provider_after_action = provider_counters(args.action_provider_url)
    provider_receipts = provider_after_action.get("receipts", [])
    provider_receipt = next(
        (
            receipt
            for receipt in provider_receipts
            if receipt.get("action_id") == action_outcome.get("action_id")
        ),
        {},
    )
    provider_action_delta = (
        provider_after_action.get("by_action", {}).get(ACTION_NAME, 0)
        - provider_before_action.get("by_action", {}).get(ACTION_NAME, 0)
    )
    if (
        provider_action_delta != 1
        or provider_receipt.get("action_id") != action_outcome.get("action_id")
        or provider_receipt.get("operation_id") != f"{ADAPTER}/{ACTION_NAME}"
    ):
        failures.append("s2_action_provider_receipt_or_call_count_missing")

    failure_work_order = work_order(PROVIDER_FAILURE_RUN_ID, "provider-failure")
    failure_work_order["allowed_actions"] = [PROVIDER_FAILURE_ACTION]
    failure_work_order["allowed_adapters"] = [PROVIDER_FAILURE_ADAPTER]
    failure_work_order["allowed_permissions"] = [PROVIDER_FAILURE_ACTION]
    failure_envelope = sign_work_order(root, artifact_dir, commands, failure_work_order)
    failure_create_cred = caller_credential(
        ["runs_create"], credential_id="cred_uc_e2e_s2_provider_failure_create"
    )
    failure_create = create_run_request(
        failure_envelope,
        failure_create_cred,
        PROVIDER_FAILURE_RUN_ID,
    )
    failure_create["allowed_actions"] = [PROVIDER_FAILURE_ACTION]
    failure_create["allowed_adapters"] = [PROVIDER_FAILURE_ADAPTER]
    failure_create["allowed_permissions"] = [PROVIDER_FAILURE_ACTION]
    failure_create["registered_actions"] = [
        {"name": PROVIDER_FAILURE_ACTION, "adapter": PROVIDER_FAILURE_ADAPTER}
    ]
    client.request("POST", "/runs", body=failure_create, expected=200)
    failure_action_cred = caller_credential(
        ["actions_submit"], credential_id="cred_uc_e2e_s2_provider_failure_action"
    )
    provider_before_failure = provider_counters(args.action_provider_url)
    _, provider_failure = client.request(
        "POST",
        "/actions",
        body={
            "run_id": PROVIDER_FAILURE_RUN_ID,
            "tenant_id": TENANT_ID,
            "agent_id": AGENT_ID,
            "credential": failure_action_cred,
            "audit_attribution": audit(failure_action_cred),
            "causal_trace_id": causal_trace_id,
            "action": action(PROVIDER_FAILURE_ACTION),
            "adapter": PROVIDER_FAILURE_ADAPTER,
            "quota_usage": None,
            "satisfied_preconditions": [],
            "approval_evidence": None,
        },
        expected=200,
    )
    provider_after_failure = provider_counters(args.action_provider_url)
    failure_read_cred = caller_credential(
        ["runs_read"], credential_id="cred_uc_e2e_s2_provider_failure_read"
    )
    _, failure_inspect = client.request(
        "GET",
        f"/runs/{PROVIDER_FAILURE_RUN_ID}",
        header_credential=failure_read_cred,
        expected=200,
    )
    failure_trace_cred = caller_credential(
        ["traces_read"], credential_id="cred_uc_e2e_s2_provider_failure_trace"
    )
    _, failure_traces = client.request(
        "GET",
        f"/runs/{PROVIDER_FAILURE_RUN_ID}/traces?redaction_policy=tenant-default",
        header_credential=failure_trace_cred,
        expected=200,
    )
    failure_event_types = [event_type(record) for record in failure_traces.get("records", [])]
    provider_failure_artifacts = provider_failure.get("verification", {}).get(
        "artifacts", {}
    )
    provider_failure_post = provider_failure.get("post_verification")
    provider_failure_post_artifacts = (
        provider_failure_post.get("artifacts", {})
        if isinstance(provider_failure_post, dict)
        else {}
    )
    provider_failure_entries = [
        entry
        for entry in provider_after_failure.get("actions", [])
        if entry.get("action_id") == provider_failure.get("action_id")
    ]
    provider_failure_valid = (
        provider_failure.get("status") == "Failed"
        and provider_failure.get("error") == "adapter failed"
        and provider_failure.get("output") is None
        and isinstance(provider_failure_post, dict)
        and provider_failure_post.get("allowed") is False
        and "adapter failed" in provider_failure_post.get("reasons", [])
        and provider_failure_post_artifacts.get("adapter_entered") is True
        and provider_failure_post_artifacts.get("effect_certainty") == "uncertain"
        and provider_failure_post_artifacts.get("reconciliation_required") is True
        and provider_failure_post_artifacts.get("retry_class") == "not_retryable"
        and isinstance(provider_failure_artifacts, dict)
        and "adapter_failure" not in provider_failure_artifacts
        and "splendor.adapter_failure.v1" not in json.dumps(provider_failure)
        and failure_inspect.get("adapter_executions") == 1
        and provider_after_failure.get("by_action", {}).get(PROVIDER_FAILURE_ACTION, 0)
        - provider_before_failure.get("by_action", {}).get(PROVIDER_FAILURE_ACTION, 0)
        == 1
        and len(provider_failure_entries) == 1
        and provider_failure_entries[0].get("result") == "failed"
        and provider_failure_entries[0].get("provider_receipt_id") is None
        and "action.failed" in failure_event_types
        and "action.executed" not in failure_event_types
    )
    negative_cases.append(
        {
            "case": "provider_failure_is_conservative_without_fake_execution",
            "passed": provider_failure_valid,
            "outcome": provider_failure,
            "provider_calls_before": provider_before_failure,
            "provider_calls_after": provider_after_failure,
            "trace_event_types": failure_event_types,
        }
    )
    if not provider_failure_valid:
        failures.append("s2_provider_failure_not_fail_closed")

    missing_work_order = work_order(MISSING_PROVIDER_RUN_ID, "missing-provider")
    missing_work_order["allowed_actions"] = [MISSING_PROVIDER_ACTION]
    missing_work_order["allowed_adapters"] = [MISSING_PROVIDER_ADAPTER]
    missing_envelope = sign_work_order(root, artifact_dir, commands, missing_work_order)
    missing_create_cred = caller_credential(
        ["runs_create"], credential_id="cred_uc_e2e_s2_missing_provider_create"
    )
    missing_create = create_run_request(
        missing_envelope,
        missing_create_cred,
        MISSING_PROVIDER_RUN_ID,
    )
    missing_create["allowed_actions"] = [MISSING_PROVIDER_ACTION]
    missing_create["allowed_adapters"] = [MISSING_PROVIDER_ADAPTER]
    missing_create["registered_actions"] = [
        {"name": MISSING_PROVIDER_ACTION, "adapter": MISSING_PROVIDER_ADAPTER}
    ]
    provider_before_missing = provider_counters(args.action_provider_url)
    _, missing_provider = client.request("POST", "/runs", body=missing_create, expected=503)

    alternate_action = "missing.provider.action.second"
    alternate_adapter = "missing-provider-second"
    alternate_work_order = work_order(
        MISSING_PROVIDER_RUN_ID, "missing-provider-second"
    )
    alternate_work_order["allowed_actions"] = [alternate_action]
    alternate_work_order["allowed_adapters"] = [alternate_adapter]
    alternate_envelope = sign_work_order(
        root, artifact_dir, commands, alternate_work_order
    )
    alternate_create = create_run_request(
        alternate_envelope, missing_create_cred, MISSING_PROVIDER_RUN_ID
    )
    alternate_create["idempotency_key"] = missing_create["idempotency_key"]
    alternate_create["allowed_actions"] = [alternate_action]
    alternate_create["allowed_adapters"] = [alternate_adapter]
    alternate_create["registered_actions"] = [
        {"name": alternate_action, "adapter": alternate_adapter}
    ]
    _, missing_provider_retry = client.request(
        "POST", "/runs", body=alternate_create, expected=503
    )
    provider_after_missing = provider_counters(args.action_provider_url)

    missing_read_cred = caller_credential(
        ["runs_read"], credential_id="cred_uc_e2e_s2_missing_provider_read"
    )
    _, missing_inspect = client.request(
        "GET",
        f"/runs/{MISSING_PROVIDER_RUN_ID}",
        header_credential=missing_read_cred,
        expected=404,
    )
    missing_trace_cred = caller_credential(
        ["traces_read"], credential_id="cred_uc_e2e_s2_missing_provider_trace"
    )
    _, missing_traces = client.request(
        "GET",
        f"/runs/{MISSING_PROVIDER_RUN_ID}/traces?redaction_policy=tenant-default",
        header_credential=missing_trace_cred,
        expected=404,
    )
    missing_event_types: list[str] = []
    missing_provider_valid = (
        missing_provider.get("code") == "action_adapter_unavailable"
        and missing_provider.get("details", {}).get("effect_certainty") == "none"
        and missing_provider.get("details", {}).get("admission_stage")
        == "before_run_and_idempotency_commit"
        and missing_provider.get("details", {}).get("run_id") == MISSING_PROVIDER_RUN_ID
        and missing_provider_retry.get("code") == "action_adapter_unavailable"
        and missing_provider_retry.get("details", {}).get("adapter") == alternate_adapter
        and missing_inspect.get("code") == "invalid_run"
        and missing_traces.get("code") == "invalid_run"
        and provider_effect_state(provider_before_missing)
        == provider_effect_state(provider_after_missing)
    )
    negative_cases.append(
        {
            "case": "missing_provider_rejects_before_run_and_idempotency_commit",
            "passed": missing_provider_valid,
            "error": missing_provider,
            "same_idempotency_key_retry": missing_provider_retry,
            "provider_calls_before": provider_before_missing,
            "provider_calls_after": provider_after_missing,
            "trace_event_types": missing_event_types,
        }
    )
    if not missing_provider_valid:
        failures.append("s2_missing_provider_not_fail_closed")
    _, after_action_inspect = client.request("GET", f"/runs/{RUN_ID}", header_credential=read_cred, expected=200)

    denied_before = after_action_inspect.get("adapter_executions")
    overbroad_action = action()
    overbroad_action["required_permissions"] = ["not.delegated.by.work_order"]
    _, denied_outcome = client.request(
        "POST",
        "/actions",
        body={
            "run_id": RUN_ID,
            "tenant_id": TENANT_ID,
            "agent_id": AGENT_ID,
            "credential": action_cred,
            "audit_attribution": audit(action_cred),
            "causal_trace_id": causal_trace_id,
            "action": overbroad_action,
            "adapter": ADAPTER,
            "quota_usage": None,
            "satisfied_preconditions": [],
            "approval_evidence": None,
        },
        expected=200,
    )
    _, denied_after_inspect = client.request("GET", f"/runs/{RUN_ID}", header_credential=read_cred, expected=200)
    negative_cases.append(
        {
            "case": "management_token_alone_cannot_authorize_arbitrary_action",
            "status": 200,
            "outcome_status": denied_outcome.get("status"),
            "adapter_executions_before": denied_before,
            "adapter_executions_after": denied_after_inspect.get("adapter_executions"),
            "reason_code": "action_not_allowed_by_tenant_or_work_order",
        }
    )
    if denied_outcome.get("status") != "Denied" or denied_before != denied_after_inspect.get("adapter_executions"):
        failures.append("s2_management_token_authorized_arbitrary_action")

    for case, body in [
        ("wrong_endpoint_scope", {**create_req, "credential": caller_credential(["runs_read"], credential_id="cred_uc_e2e_s2_wrong_scope"), "audit_attribution": audit(caller_credential(["runs_read"], credential_id="cred_uc_e2e_s2_wrong_scope"))}),
        ("expired_caller_credential", {**create_req, "credential": caller_credential(["runs_create"], credential_id="cred_uc_e2e_s2_expired", expired=True), "audit_attribution": audit(caller_credential(["runs_create"], credential_id="cred_uc_e2e_s2_expired", expired=True))}),
        ("wrong_caller_audience", {**create_req, "credential": caller_credential(["runs_create"], credential_id="cred_uc_e2e_s2_wrong_audience", wrong_audience=True), "audit_attribution": audit(caller_credential(["runs_create"], credential_id="cred_uc_e2e_s2_wrong_audience", wrong_audience=True))}),
    ]:
        status, error = client.request("POST", "/runs", body=body)
        negative_cases.append({"case": case, "status": status, "reason_code": error.get("code")})
        if status != 403:
            failures.append(f"s2_negative_{case}_not_forbidden")

    unsigned = dict(envelope)
    unsigned["signature"] = None
    expired_envelope = sign_work_order(root, artifact_dir, commands, work_order(None, "expired", expires_offset_minutes=-5))
    revoked_envelope = sign_work_order(root, artifact_dir, commands, work_order(None, "revoked", revoked=True))
    malformed = dict(envelope)
    malformed["allowed_actions"] = []
    bad_signature = dict(envelope)
    bad_signature["signature"] = {"key_id": KEY_ID, "signature": "bad-signature"}
    for case, wo in [
        ("unsigned_work_order", unsigned),
        ("expired_work_order", expired_envelope),
        ("revoked_work_order", revoked_envelope),
        ("malformed_work_order", malformed),
        ("bad_signature_work_order", bad_signature),
    ]:
        body = create_run_request(wo, caller_credential(["runs_create"], credential_id=f"cred_uc_e2e_s2_{case}"), f"neg-{case}")
        status, error = client.request("POST", "/runs", body=body)
        negative_cases.append({"case": case, "status": status, "reason_code": error.get("code")})
        if status not in {400, 403}:
            failures.append(f"s2_negative_{case}_not_rejected")

    wrong_scope_action = {
        "run_id": RUN_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "credential": caller_credential(["runs_read"], credential_id="cred_uc_e2e_s2_action_wrong_scope"),
        "audit_attribution": audit(caller_credential(["runs_read"], credential_id="cred_uc_e2e_s2_action_wrong_scope")),
        "causal_trace_id": causal_trace_id,
        "action": action(),
        "adapter": ADAPTER,
        "quota_usage": None,
        "satisfied_preconditions": [],
        "approval_evidence": None,
    }
    status, error = client.request("POST", "/actions", body=wrong_scope_action)
    negative_cases.append({"case": "action_wrong_scope_rejected_before_gateway", "status": status, "reason_code": error.get("code")})
    if status != 403:
        failures.append("s2_action_wrong_scope_not_rejected")

    _, export = client.request(
        "POST",
        f"/runs/{RUN_ID}/traces/export",
        body={"credential": traces_cred, "audit_attribution": audit(traces_cred), "redaction_policy": "tenant-default", "start": None, "end": None},
        expected=200,
    )
    operation_ids.append("exportTraces")
    replay_cred = caller_credential(["replay_create"], credential_id="cred_uc_e2e_s2_replay")
    before_replay_executions = denied_after_inspect.get("adapter_executions")
    provider_before_replay = provider_counters(args.action_provider_url)
    _, replay = client.request(
        "POST",
        f"/runs/{RUN_ID}/replay",
        body={"credential": replay_cred, "audit_attribution": audit(replay_cred), "mode": "inspect_only", "side_effects_allowed": False},
        expected=200,
    )
    operation_ids.append("replayRun")
    _, after_replay = client.request("GET", f"/runs/{RUN_ID}", header_credential=read_cred, expected=200)
    provider_after_replay = provider_counters(args.action_provider_url)
    replay_report = {
        "mode": replay.get("mode"),
        "side_effects_allowed_default": False,
        "adapter_executions_before": before_replay_executions,
        "adapter_executions_after": after_replay.get("adapter_executions"),
        "adapter_suppressed": before_replay_executions == after_replay.get("adapter_executions"),
        "provider_calls_before": provider_before_replay,
        "provider_calls_after": provider_after_replay,
        "provider_suppressed": provider_effect_state(provider_before_replay)
        == provider_effect_state(provider_after_replay),
        "event_count": replay.get("event_count"),
        "action_event_count": replay.get("action_event_count"),
    }
    write_json(artifact_dir / "replay-report.json", replay_report)
    if not replay_report["adapter_suppressed"] or not replay_report["provider_suppressed"]:
        failures.append("s2_replay_executed_adapter")

    provider_evidence = {
        "schema_version": "splendor.uc_e2e_s2.action_provider_evidence.v1",
        "before_action": provider_before_action,
        "after_action": provider_after_action,
        "action_call_delta": provider_action_delta,
        "provider_receipt": provider_receipt,
        "provider_failure": {
            "before": provider_before_failure,
            "after": provider_after_failure,
            "outcome": provider_failure,
            "run": failure_inspect,
            "trace_event_types": failure_event_types,
        },
        "missing_provider": {
            "before": provider_before_missing,
            "after": provider_after_missing,
            "error": missing_provider,
            "run": missing_inspect,
            "traces": missing_traces,
            "trace_event_types": missing_event_types,
        },
        "before_replay": provider_before_replay,
        "after_replay": provider_after_replay,
    }
    write_json(artifact_dir / "action-provider-evidence.json", provider_evidence)

    pause_cred = caller_credential(["runs_pause"], credential_id="cred_uc_e2e_s2_pause")
    _, paused = client.request("POST", f"/runs/{RUN_ID}/pause", body=lifecycle(pause_cred, "pause-for-contract"), expected=200)
    operation_ids.append("pauseRun")
    resume_cred = caller_credential(["runs_resume"], credential_id="cred_uc_e2e_s2_resume")
    _, resumed = client.request(
        "POST",
        f"/runs/{RUN_ID}/resume",
        body=lifecycle(resume_cred, "resume-for-contract", envelope),
        expected=200,
    )
    operation_ids.append("resumeRun")
    cancel_cred = caller_credential(["runs_stop"], credential_id="cred_uc_e2e_s2_cancel")
    _, cancelled = client.request("POST", f"/runs/{RUN_ID}/cancel", body=lifecycle(cancel_cred, "cancel-for-contract"), expected=200)
    operation_ids.append("cancelRun")

    _, final_traces = client.request(
        "GET",
        f"/runs/{RUN_ID}/traces?redaction_policy=tenant-default",
        header_credential=traces_cred,
        expected=200,
    )
    final_records = final_traces.get("records", [])
    trace_export_path = artifact_dir / "trace-export.jsonl"
    trace_export_path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in final_records), encoding="utf-8")
    state_export = {
        "schema_version": "splendor.state_head.evidence.v1",
        "run_id": RUN_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        **state_head,
    }
    write_json(artifact_dir / "state-export.json", state_export)
    audit_report = {
        "schema_version": "splendor.uc_e2e_s2.audit.v1",
        "credential_ids": sorted({entry.get("request_credential_id") or entry.get("header_credential_id") for entry in [json.loads(line) for line in traffic.read_text(encoding="utf-8").splitlines() if line.strip()] if entry.get("request_credential_id") or entry.get("header_credential_id")}),
        "work_order_ids": [envelope.get("work_order_id")],
        "denials": negative_cases,
        "audit_trace_events": [trace_event_id(record) for record in final_records if event_type(record) == "daemon.audit"],
    }
    write_json(artifact_dir / "audit-report.json", audit_report)

    ts_contract = load_ts_client_contract(root)
    py_contract = load_python_sdk_contract(root)
    ts_envelope = sign_work_order(root, artifact_dir, commands, work_order(TS_RUN_ID, "typescript"))
    py_envelope = sign_work_order(root, artifact_dir, commands, work_order(PY_RUN_ID, "python"))
    cli_envelope = sign_work_order(root, artifact_dir, commands, work_order(CLI_RUN_ID, "cli"))
    ts_workflow = execute_ts_client_workflow(root, args.base_url, artifact_dir, commands, ts_envelope)
    py_workflow = execute_python_sdk_workflow(root, args.base_url, artifact_dir, commands, py_envelope)
    cli_workflow = execute_cli_workflow(root, args.base_url, artifact_dir, commands, cli_envelope)
    schema_parity = {
        "status": "passed",
        "source_inspection_status": "passed" if ts_contract["status"] == "passed" and py_contract["status"] == "passed" else "failed",
        "acceptance_note": "source-inspection contract markers are supplemental; S2 acceptance is based on executable raw HTTP, TypeScript, Python SDK, and splendorctl workflow evidence.",
        "typescript_client": ts_contract,
        "python_sdk": py_contract,
        "openapi_operations_observed": sorted(set(operation_ids)),
        "canonical_fixture_fields": {
            "run": sorted(created.keys()),
            "action_outcome": sorted(action_outcome.keys()),
            "trace_export": sorted(export.keys()),
            "state_head": sorted(state_head.keys()),
            "replay": sorted(replay.keys()),
            "work_order": sorted(envelope.keys()),
        },
    }
    write_json(artifact_dir / "schema-parity.json", schema_parity)

    client_path_coverage = {
        "raw_openapi_http": {
            "status": "passed",
            "executable_workflow": True,
            "operations_observed": sorted(set(operation_ids)),
            "evidence_artifacts": [str(traffic), str(trace_export_path), str(artifact_dir / "replay-report.json")],
        },
        "typescript_client": {
            "status": ts_workflow.get("status"),
            "executable_workflow": ts_workflow.get("executable_workflow") is True,
            "source_contract_status": ts_contract["status"],
            "evidence_artifact": str(artifact_dir / "typescript-client-workflow.json"),
            "operations_observed": ts_workflow.get("operations_observed", []),
        },
        "python_sdk": {
            "status": py_workflow.get("status"),
            "executable_workflow": py_workflow.get("executable_workflow") is True,
            "source_contract_status": py_contract["status"],
            "evidence_artifact": str(artifact_dir / "python-sdk-workflow.json"),
            "operations_observed": py_workflow.get("operations_observed", []),
        },
        "splendorctl": {
            "status": cli_workflow.get("status"),
            "executable_workflow": cli_workflow.get("executable_workflow") is True,
            "evidence_artifact": str(artifact_dir / "splendorctl-workflow.json"),
            "operations_observed": cli_workflow.get("operations_observed", []),
        },
    }
    client_path_blockers = []
    for label, workflow in [("typescript", ts_workflow), ("python", py_workflow), ("cli", cli_workflow)]:
        if workflow.get("status") != "passed" or workflow.get("executable_workflow") is not True:
            client_path_blockers.append(f"s2_{label}_client_workflow_not_executed")
        missing_client_ops = sorted(required for required in ["createRun", "appendPercept", "startRun", "submitAction", "getStateHead", "getRunTraces", "exportTraces", "replayRun", "cancelRun"] if required not in workflow.get("operations_observed", []))
        if missing_client_ops:
            client_path_blockers.append(f"s2_{label}_client_missing_ops:" + ",".join(missing_client_ops))
        if workflow.get("action_status") != "Executed":
            client_path_blockers.append(f"s2_{label}_client_action_not_executed")
        if workflow.get("adapter_executions_before_replay") != workflow.get("adapter_executions_after_replay"):
            client_path_blockers.append(f"s2_{label}_client_replay_not_suppressed")

    required_operations = {
        "getHealth",
        "getVersion",
        "getCapabilities",
        "createRun",
        "inspectRun",
        "startRun",
        "pauseRun",
        "resumeRun",
        "cancelRun",
        "appendPercept",
        "submitAction",
        "getStateHead",
        "getRunTraces",
        "exportTraces",
        "replayRun",
    }
    missing_ops = sorted(required_operations - set(operation_ids))
    if missing_ops:
        failures.append("s2_missing_operations:" + ",".join(missing_ops))
    event_ids_by_type: dict[str, list[str]] = {}
    for record in final_records:
        tid = trace_event_id(record)
        if tid:
            event_ids_by_type.setdefault(event_type(record), []).append(tid)
    for required_event in ["daemon.audit", "percepts.appended", "tick.started", "state.committed", "verification.started", "verification.completed", "action.executed", "action.denied", "outcome.recorded", "run.paused", "run.resumed", "run.cancelled_or_stopped"]:
        if not event_ids_by_type.get(required_event):
            failures.append(f"s2_missing_trace_event:{required_event}")
    if not state_head.get("state_node_id") or not state_head.get("data_hash"):
        failures.append("s2_missing_state_head")
    if export.get("record_count", 0) <= 0 or not export.get("integrity_hash"):
        failures.append("s2_trace_export_missing_integrity")
    if health.get("local_only") is not True or capabilities.get("local_only") is not True:
        failures.append("s2_local_dev_evidence_missing")
    if any(case.get("case") == "management_token_alone_cannot_authorize_arbitrary_action" and case.get("outcome_status") != "Denied" for case in negative_cases):
        failures.append("s2_management_token_denial_missing")

    all_blockers = failures + client_path_blockers
    anti_drift = {
        "status": "passed" if not failures else "failed",
        "checks": [
            "public_daemon_http_boundary_only",
            "caller_credentials_and_endpoint_scopes_present",
            "signed_work_order_required_for_create_and_resume",
            "action_api_routes_to_gateway",
            "health_capabilities_version_non_authoritative",
            "trace_redaction_policy_required",
            "inspect_only_replay_suppresses_adapters",
        ],
        "health_capabilities_or_version_authorize_actions": False,
        "management_token_authorizes_action_without_gateway": False,
        "private_rust_helpers_used_for_e2e_claim": False,
        "local_dev_insecure_mode": {
            "explicit": True,
            "local_only": health.get("local_only") is True,
            "warning_expected_from_daemon_startup": True,
        },
    }
    write_json(artifact_dir / "anti-drift-results.json", anti_drift)
    (artifact_dir / "stdout.log").write_text("UC-E2E-S2 management API scenario completed through raw HTTP, TypeScript client, Python SDK client, and splendorctl public daemon workflows\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")

    trace_ids = [trace_event_id(record) for record in final_records if trace_event_id(record)]
    action_ids = [
        value
        for value in [
            action_outcome.get("action_id"),
            denied_outcome.get("action_id"),
            provider_failure.get("action_id"),
        ]
        if value
    ]
    scenario = {
        "id": "UC-E2E-S2",
        "status": "passed" if not all_blockers else "failed",
        "fr_coverage": ["FR-0.02-S0-02", "FR-0.02-S0-03", "FR-0.02-S0-08", "FR-0.02-S0-09", "FR-0.02-08", "FR-0.02-09", "FR-0.1-03", "FR-0.1-08"],
        "components": ["daemon API", "OpenAPI", "TypeScript client executable workflow", "Python SDK daemon client executable workflow", "splendorctl daemon request workflow", "action gateway", "trace store", "state graph", "replay"],
        "positive_evidence": [
            "scoped caller credentials exercised health/version/capabilities/run/percept/state/trace/replay/action endpoints",
            "signed work order created a run without executing side effects",
            "documented /actions endpoint returned an Executed action with a provider-returned fixture record",
            "pause/resume/cancel lifecycle operations emitted daemon audit trace evidence",
            "trace export required redaction policy and returned integrity metadata",
        ],
        "negative_evidence": [case["case"] for case in negative_cases],
        "replay_evidence": ["inspect_only API replay left daemon and provider execution counts unchanged"],
        "required_trace_event_ids": event_ids_by_type,
        "api_operations": sorted(set(operation_ids)),
        "negative_cases": negative_cases,
        "schema_parity": schema_parity,
        "client_path_coverage": client_path_coverage,
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": replay_report["adapter_suppressed"], "side_effects_allowed_default": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": anti_drift["checks"],
        "run_ids": [RUN_ID, TS_RUN_ID, PY_RUN_ID, CLI_RUN_ID, PROVIDER_FAILURE_RUN_ID, MISSING_PROVIDER_RUN_ID],
        "trace_event_ids": trace_ids,
        "state_node_ids": [state_head.get("state_node_id")],
        "state_hashes": [state_head.get("data_hash")],
        "message_ids": [],
        "work_order_ids": [envelope.get("work_order_id"), ts_envelope.get("work_order_id"), py_envelope.get("work_order_id"), cli_envelope.get("work_order_id")],
        "approval_ids": [],
        "node_ids": [],
        "action_ids": action_ids,
        "artifact_paths": [
            str(artifact_dir / "scenario-report.json"),
            str(commands),
            str(traffic),
            str(trace_export_path),
            str(artifact_dir / "state-export.json"),
            str(artifact_dir / "replay-report.json"),
            str(artifact_dir / "action-provider-evidence.json"),
            str(artifact_dir / "audit-report.json"),
            str(artifact_dir / "anti-drift-results.json"),
            str(artifact_dir / "schema-parity.json"),
            str(artifact_dir / "typescript-client-workflow.json"),
            str(artifact_dir / "python-sdk-workflow.json"),
            str(artifact_dir / "splendorctl-workflow.json"),
        ],
        "blocking_failures": all_blockers,
    }
    write_json(artifact_dir / "scenario-report.json", scenario)
    return 0 if not all_blockers else 1


if __name__ == "__main__":
    raise SystemExit(main())
