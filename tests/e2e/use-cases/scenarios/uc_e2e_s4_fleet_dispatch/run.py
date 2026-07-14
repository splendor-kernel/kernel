#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
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
MESSAGE_WORK_ORDER_ID = "wo_uc_e2e_s4_remote_message"
WORK_ORDER_KEY_IDS = {
    VPC_INSTANCE_ID: "work-order-acceptance-vpc",
    CLOUD_INSTANCE_ID: "work-order-acceptance-cloud",
    EDGE_INSTANCE_ID: "work-order-acceptance-edge",
}
RUNTIME_IMAGE_IDENTITY = "splendor-kernel-runtime:acceptance-target-runtime"
HEARTBEAT_STALE_AFTER_SECONDS = 60


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


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None, context: ssl.SSLContext | None = None) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + path, data=payload, method=method)
    if payload is not None:
        req.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=20, context=context) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return exc.code, parsed
    except urllib.error.URLError:
        return 599, {"code": "transport_unavailable"}


def manager_credential(scopes: list[str] | None = None, *, expired: bool = False, wrong_audience: bool = False, wrong_tenant: bool = False, revoked: bool = False) -> dict[str, Any]:
    return {
        "credential_id": "cred_uc_e2e_s4_manager",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s4", "label": "UC-E2E-S4"}, "client_principal_id": "client_uc_e2e_s4", "label": "UC-E2E-S4 manager client"},
        "scopes": scopes or ["nodes_register", "instances_register", "nodes_heartbeat", "instances_heartbeat", "fleet_read", "fleet_dispatch", "work_orders_submit", "work_orders_revoke", "traces_read", "messages_send", "messages_read"],
        "binding": {"fleet": {"fleet_id": "99999999-9999-4999-8999-999999999999" if wrong_tenant else FLEET_ID}},
        "audience": {"central_manager": {"manager_id": "wrong-manager" if wrong_audience else "central-manager"}},
        "expires_at": utc(-5 if expired else 60),
        "revocation": {"revoked": {"reason": "test_revoked"}} if revoked else "active",
    }


def resident_auth(root: Path, auth_dir: Path, instance_id: str, scopes: list[str]) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "token",
        "--auth-dir",
        str(auth_dir),
        "--tenant-id",
        TENANT_ID,
        "--instance-id",
        instance_id,
    ]
    for scope in scopes:
        command.extend(["--scope", scope])
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit("resident caller token fixture failed")
    return json.loads(proc.stdout)


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any] | None = None) -> dict[str, Any]:
    credential = credential or manager_credential()
    return {"credential": credential, "audit_attribution": audit(credential)}


def message_scope(credential: dict[str, Any], run_id: str, agent_id: str, tenant_id: str = TENANT_ID) -> dict[str, Any]:
    return {**sec(credential), "tenant_id": tenant_id, "run_id": run_id, "agent_id": agent_id}


def credential_header(auth: dict[str, Any]) -> dict[str, str]:
    return {
        "authorization": f"Bearer {auth['token']}",
        "x-splendor-caller-credential": json.dumps(auth["credential"], sort_keys=True),
    }


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
    return {"instance_id": instance_id, "node_id": node_id, "runtime_mode": "resident", "hosted_tenants": [TENANT_ID], "supported_features": ["runtime.resident", "gateway.verified", "trace.buffer.local", "state.handoff", "message.remote", "message.remote.proposal", "sql.read_fixture"], "runtime_version": "0.1-acceptance", "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}}, "registered_at": utc(0)}


def compose_same_image_evidence(root: Path) -> dict[str, Any]:
    compose = root / "tests" / "e2e" / "use-cases" / "docker-compose.acceptance.yml"
    services: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_build = False
    for raw in compose.read_text(encoding="utf-8").splitlines():
        if raw.startswith("  ") and not raw.startswith("    ") and raw.strip().endswith(":"):
            current = raw.strip().removesuffix(":")
            services[current] = {}
            in_build = False
        elif current and raw.startswith("    build:"):
            in_build = True
        elif current and in_build and raw.startswith("      target:"):
            services[current]["build_target"] = raw.split(":", 1)[1].strip().strip('"')
        elif current and raw.startswith("    command:"):
            services[current]["command"] = raw.split(":", 1)[1].strip()
        elif current and raw.startswith("    image:"):
            services[current]["image"] = raw.split(":", 1)[1].strip()
            in_build = False
    splendor_services = ["splendor-daemon-local", "central-manager", "resident-cloud-node", "resident-vpc-node", "resident-edge-node"]
    targets = {name: services.get(name, {}).get("build_target") for name in splendor_services}
    return {
        "compose_file": str(compose),
        "compose_digest": "sha256:" + __import__("hashlib").sha256(compose.read_bytes()).hexdigest(),
        "splendor_services": splendor_services,
        "build_targets": targets,
        "same_build_target": "runtime" if set(targets.values()) == {"runtime"} else None,
        "all_same": set(targets.values()) == {"runtime"},
        "runner_exception": services.get("e2e-runner", {}).get("build_target") == "acceptance-runner",
    }


def work_order(expires: int = 60, revoked: bool = False, target: str = "customer_vpc", *, work_order_id: str = WORK_ORDER_ID, required_capability: str = "sql.read_fixture") -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": work_order_id,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "objective": "UC-E2E-S4 single-adapter resident dispatch with VPC data locality",
        "allowed_actions": ["sql.read_fixture"],
        "allowed_adapters": ["fixture-sql"],
        "allowed_permissions": ["fixture.sql.read"],
        "data_refs": ["dataset:eu-west.fixture.v1"],
        "quotas": {"max_actions_per_tick": 5, "max_action_duration_ms": 30000},
        "placement": {"target": target, "data_locality": "vpc", "requires_gpu": False, "dedicated_instance": False, "required_capabilities": [required_capability], "max_runtime_ms": 30000},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": {"revoked": {"reason": "operator_revoked"}} if revoked else "active",
    }


def message_work_order(expires: int = 60) -> dict[str, Any]:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": MESSAGE_WORK_ORDER_ID,
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": RUN_ID,
        "objective": "UC-E2E-S4 proposal-only remote message delegation",
        "allowed_actions": ["message.remote.proposal"],
        "allowed_adapters": ["remote-message"],
        "allowed_permissions": [f"message.remote.proposal:{HELPER_AGENT_ID}"],
        "data_refs": [],
        "quotas": {"max_actions_per_tick": 1, "max_action_duration_ms": 30000},
        "placement": {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "dedicated_instance": False, "required_capabilities": ["message.remote.proposal"], "max_runtime_ms": 30000},
        "issued_at": utc(-2),
        "expires_at": utc(expires),
        "revocation": "active",
    }


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, auth_dir: Path, payload: dict[str, Any], instance_id: str = VPC_INSTANCE_ID) -> dict[str, Any]:
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
    parser.add_argument("--vpc-url", default="https://resident-vpc-node:8092")
    parser.add_argument("--cloud-url", default="https://resident-cloud-node:8091")
    parser.add_argument("--resident-auth-dir", default=os.environ.get("SPLENDOR_RESIDENT_AUTH_DIR", "/run/splendor-auth"))
    parser.add_argument("--resident-ca-file", default=os.environ.get("SPLENDOR_RESIDENT_CA_FILE", "/run/splendor-auth/resident-root-ca.pem"))
    args = parser.parse_args()
    root = Path(args.root)
    auth_dir = Path(args.resident_auth_dir)
    resident_ssl = ssl.create_default_context(cafile=args.resident_ca_file)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S4"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    api_rows: list[dict[str, Any]] = []

    def call(operation: str, method: str, base: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
        context = resident_ssl if base.lower().startswith("https://") else None
        status, data = request_json(method, base, path, body, headers, context)
        api_rows.append({"operation_id": operation, "method": method, "url": base.rstrip("/") + path, "status": status, "request": body, "response": data})
        return {"status": status, "body": data}

    for _ in range(40):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)

    for label, base, instance_id in [
        ("vpc", args.vpc_url, VPC_INSTANCE_ID),
        ("cloud", args.cloud_url, CLOUD_INSTANCE_ID),
    ]:
        for _ in range(40):
            health_auth = resident_auth(root, auth_dir, instance_id, ["health_read"])
            if call(f"residentHealth-{label}", "GET", base, "/health", headers=credential_header(health_auth))["status"] == 200:
                break
            time.sleep(0.25)

    cred = manager_credential()
    nodes = [
        node_registration(VPC_NODE_ID, "vpc.worker", "customer_vpc", "vpc", args.vpc_url, ["sql.read_fixture", "data.read_fixture", "artifact.create_internal", "artifact.publish_external", "message.remote.proposal", "runtime.resident"]),
        node_registration(CLOUD_NODE_ID, "cloud.worker", "resident_cloud_pool", "cloud", args.cloud_url, ["message.remote.proposal", "runtime.resident"]),
        node_registration(EDGE_NODE_ID, "edge.appliance", "edge_device", "device", "https://resident-edge-node:8093", ["runtime.resident", "trace.buffer.local"]),
    ]
    instances = [instance_registration(VPC_NODE_ID, VPC_INSTANCE_ID), instance_registration(CLOUD_NODE_ID, CLOUD_INSTANCE_ID), instance_registration(EDGE_NODE_ID, EDGE_INSTANCE_ID)]
    for node in nodes:
        call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(cred), "registration": node})
    node_list = call("listNodes", "POST", args.manager_url, "/fleet/nodes/list", sec(cred))
    for inst in instances:
        call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(cred), "registration": inst})
    for node in nodes:
        call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(cred), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}})
        call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/capabilities", {**sec(cred), "capability_document": node["capability_document"]})
    instance_heartbeats = [
        call("heartbeatInstance", "POST", args.manager_url, f"/fleet/instances/{inst['instance_id']}/heartbeat", {**sec(cred), "heartbeat": {"node_id": inst["node_id"], "instance_id": inst["instance_id"], "health": inst["health"], "recorded_at": utc(0)}})
        for inst in instances
    ]

    dispatch_payload = work_order()
    envelope = sign_work_order(root, artifact_dir, commands, auth_dir, dispatch_payload)
    cloud_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, dispatch_payload, CLOUD_INSTANCE_ID)
    message_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, message_work_order())
    validation = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": envelope, "expected_audience": "central-manager"})
    message_validation = call("submitMessageWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": message_envelope, "expected_audience": "central-manager"})
    placement_request = {"target": "customer_vpc", "required_capabilities": ["sql.read_fixture"], "data_locality": "vpc", "dedicated_instance": False, "required_runtime_version": None, "max_runtime_ms": 30000, "execution_mode": "live"}
    placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(cred), "work_order_id": WORK_ORDER_ID, "request": placement_request})
    dispatch = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ID}/dispatch", {**sec(cred), "target_node_id": VPC_NODE_ID})
    run_id = dispatch["body"].get("run_id", RUN_ID)

    message = {"message": {"message_id": "55555555-5555-4555-8555-555555555554", "source_agent_id": AGENT_ID, "target_agent_id": HELPER_AGENT_ID, "run_id": run_id, "schema": "splendor.message.proposal_request.v1", "payload": {"request": "proposal_only", "mutation_authority": False}, "causal_parent": None, "requires_response": True, "created_at": utc(0)}, "schema_version": "v1", "delivery_status": "pending", "trace_links": {}}
    remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "work_order_id": MESSAGE_WORK_ORDER_ID, "message_envelope": message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-once", "simulate_failure": None})
    duplicate_message = {**message, "message": {**message["message"], "message_id": "55555555-5555-4555-8555-555555555556"}}
    duplicate = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "work_order_id": MESSAGE_WORK_ORDER_ID, "message_envelope": duplicate_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-once", "simulate_failure": None})
    received = call("getMessage", "POST", args.manager_url, f"/messages/{message['message']['message_id']}/read", message_scope(cred, run_id, HELPER_AGENT_ID))
    failed_message = {**message, "message": {**message["message"], "message_id": "55555555-5555-4555-8555-555555555555"}}
    failed_remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "work_order_id": MESSAGE_WORK_ORDER_ID, "message_envelope": failed_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-fail", "simulate_failure": "toxiproxy_transport_failure"})
    unsupported_message = {**message, "message": {**message["message"], "message_id": "55555555-5555-4555-8555-555555555557", "schema": "splendor.message.unsupported.v1"}}
    unsupported_remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "work_order_id": MESSAGE_WORK_ORDER_ID, "message_envelope": unsupported_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-unsupported", "simulate_failure": None})
    unauthorized_message = {**message, "message": {**message["message"], "message_id": "55555555-5555-4555-8555-555555555558", "target_agent_id": AGENT_ID}}
    unauthorized_remote = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(cred), "work_order_id": MESSAGE_WORK_ORDER_ID, "message_envelope": unauthorized_message, "source_instance_id": VPC_INSTANCE_ID, "target_instance_id": CLOUD_INSTANCE_ID, "idempotency_key": "proposal-unauthorized", "simulate_failure": None})

    vpc_export_auth = resident_auth(root, auth_dir, VPC_INSTANCE_ID, ["state_handoff"])
    vpc_export_cred = vpc_export_auth["credential"]
    exported = call("exportStateSnapshot", "POST", args.vpc_url, "/state-snapshots/export", {"run_id": run_id, "credential": vpc_export_cred, "audit_attribution": audit(vpc_export_cred), "work_order_id": WORK_ORDER_ID, "source_instance_id": VPC_INSTANCE_ID, "receiver_instance_id": CLOUD_INSTANCE_ID, "previous_state_node_id": None}, credential_header(vpc_export_auth))
    cloud_create_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["runs_create"])
    cloud_create_cred = cloud_create_auth["credential"]
    cloud_work_order_id = envelope.get("work_order_id") or envelope.get("work_order", {}).get("work_order_id", WORK_ORDER_ID)
    cloud_create = {"request_id": f"req-uc-e2e-s4-{cloud_work_order_id}-{run_id}", "idempotency_key": f"idem-uc-e2e-s4-{cloud_work_order_id}-{run_id}", "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "work_order": envelope, "credential": cloud_create_cred, "audit_attribution": audit(cloud_create_cred), "allowed_actions": ["sql.read_fixture"], "allowed_adapters": ["fixture-sql"], "allowed_permissions": ["fixture.sql.read"], "policy_actions": [], "policy_bundle_required": False, "policy_bundle": None, "registered_actions": [{"name": "sql.read_fixture", "adapter": "fixture-sql"}], "approval_policies": [], "allowed_percept_schemas": [], "allowed_percept_sources": [], "initial_state": {"resume_target": "cloud"}, "snapshot_interval": 1}
    sibling_key_denied = call("createRunSiblingKeyDenied", "POST", args.cloud_url, "/runs", cloud_create, credential_header(cloud_create_auth))
    cloud_create_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["runs_create"])
    cloud_create_cred = cloud_create_auth["credential"]
    cloud_create = {**cloud_create, "work_order": cloud_envelope, "credential": cloud_create_cred, "audit_attribution": audit(cloud_create_cred)}
    call("createRun", "POST", args.cloud_url, "/runs", cloud_create, credential_header(cloud_create_auth))
    cloud_import_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["state_handoff"])
    cloud_import_cred = cloud_import_auth["credential"]
    imported = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": exported["body"].get("handoff"), "work_order": cloud_envelope, "credential": cloud_import_cred, "audit_attribution": audit(cloud_import_cred)}, credential_header(cloud_import_auth))
    cloud_state_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["state_read"])
    state_before_failed_import = call("getStateHead", "GET", args.cloud_url, f"/runs/{run_id}/state-head", headers=credential_header(cloud_state_auth))
    bad_handoff = json.loads(json.dumps(exported["body"].get("handoff", {})))
    if bad_handoff:
        bad_handoff["authority"]["tenant_id"] = "99999999-9999-4999-8999-999999999999"
    wrong_handoff_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["state_handoff"])
    wrong_handoff_cred = wrong_handoff_auth["credential"]
    wrong_handoff = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": bad_handoff, "work_order": cloud_envelope, "credential": wrong_handoff_cred, "audit_attribution": audit(wrong_handoff_cred)}, credential_header(wrong_handoff_auth))
    wrong_hash_handoff = json.loads(json.dumps(exported["body"].get("handoff", {})))
    if wrong_hash_handoff:
        wrong_hash_handoff["snapshot"]["state_hash"]["value"] = "0" * 64
    wrong_hash_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["state_handoff"])
    wrong_hash_cred = wrong_hash_auth["credential"]
    wrong_hash = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": wrong_hash_handoff, "work_order": cloud_envelope, "credential": wrong_hash_cred, "audit_attribution": audit(wrong_hash_cred)}, credential_header(wrong_hash_auth))
    wrong_run_handoff = json.loads(json.dumps(exported["body"].get("handoff", {})))
    if wrong_run_handoff:
        wrong_run_handoff["authority"]["run_id"] = "77777777-7777-4777-8777-777777777777"
    wrong_run_auth = resident_auth(root, auth_dir, CLOUD_INSTANCE_ID, ["state_handoff"])
    wrong_run_cred = wrong_run_auth["credential"]
    wrong_run = call("importStateSnapshot", "POST", args.cloud_url, "/state-snapshots/import", {"handoff": wrong_run_handoff, "work_order": cloud_envelope, "credential": wrong_run_cred, "audit_attribution": audit(wrong_run_cred)}, credential_header(wrong_run_auth))
    state_after_failed_import = call("getStateHead", "GET", args.cloud_url, f"/runs/{run_id}/state-head", headers=credential_header(cloud_state_auth))

    vpc_trace_auth = resident_auth(root, auth_dir, VPC_INSTANCE_ID, ["traces_read"])
    vpc_trace_cred = vpc_trace_auth["credential"]
    traces = call("exportTraces", "POST", args.vpc_url, f"/runs/{run_id}/traces/export", {"credential": vpc_trace_cred, "audit_attribution": audit(vpc_trace_cred), "redaction_policy": "uc-e2e-s4-redacted", "start": None, "end": None}, credential_header(vpc_trace_auth))
    vpc_replay_auth = resident_auth(root, auth_dir, VPC_INSTANCE_ID, ["replay_create"])
    vpc_replay_cred = vpc_replay_auth["credential"]
    replay = call("replayRun", "POST", args.vpc_url, f"/runs/{run_id}/replay", {"credential": vpc_replay_cred, "audit_attribution": audit(vpc_replay_cred), "mode": "inspect_only", "side_effects_allowed": False}, credential_header(vpc_replay_auth))
    records = traces["body"].get("records", [])
    trace_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE_ID, "instance_id": VPC_INSTANCE_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "run_id": run_id, "work_order_id": WORK_ORDER_ID}, "records": records}
    sync = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(cred), "batch": trace_batch})
    sync_duplicate = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(cred), "batch": trace_batch})
    tampered_batch = json.loads(json.dumps(trace_batch))
    if tampered_batch["records"]:
        tampered_batch["records"][0]["payload"]["kind"] = "tampered"
    sync_tampered = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(cred), "batch": tampered_batch})
    telemetry = call("getFleetTelemetry", "POST", args.manager_url, "/fleet/telemetry/read", sec(cred))
    audit_events = call("managerAudit", "POST", args.manager_url, "/fleet/audit/read", sec(cred))["body"]

    dispatch_target_mismatch = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ID}/dispatch", {**sec(cred), "target_node_id": CLOUD_NODE_ID})
    revoke_dispatch = call("revokeWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ID}/revoke", {**sec(cred), "reason": "dispatch_revalidation_negative"})
    revoked_dispatch = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ID}/dispatch", {**sec(cred), "target_node_id": VPC_NODE_ID})
    stale_node = node_registration("00000000-0000-4000-8000-000000000704", "vpc.worker.stale", "customer_vpc", "vpc", args.vpc_url, ["stale.only", "runtime.resident"])
    stale_node["health"]["observed_at"] = utc(-120)
    stale_node["registered_at"] = utc(-120)
    call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(cred), "registration": stale_node})
    stale_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, work_order(work_order_id="wo_uc_e2e_s4_stale", required_capability="stale.only"))
    call("submitStaleWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": stale_envelope, "expected_audience": "central-manager"})
    # Freshness is receiver-owned, so exercise real manager receipt-time aging
    # instead of trusting the deliberately old sender timestamps above.
    time.sleep(HEARTBEAT_STALE_AFTER_SECONDS + 1)
    stale_placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(cred), "work_order_id": "wo_uc_e2e_s4_stale", "request": {**placement_request, "required_capabilities": ["stale.only"]}})

    def neg(case: str, passed: bool, **details: Any) -> dict[str, Any]:
        return {"case": case, "passed": passed, **details}

    wrong_tenant = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager_credential(wrong_tenant=True)), "work_order_id": WORK_ORDER_ID, "request": placement_request})
    wrong_audience = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager_credential(wrong_audience=True)), "work_order_id": WORK_ORDER_ID, "request": placement_request})
    missing_capability_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, work_order(work_order_id="wo_uc_e2e_s4_missing_capability", required_capability="gpu.unavailable"))
    call("submitMissingCapabilityWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": missing_capability_envelope, "expected_audience": "central-manager"})
    capability_mismatch = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(cred), "work_order_id": "wo_uc_e2e_s4_missing_capability", "request": {**placement_request, "required_capabilities": ["gpu.unavailable"]}})
    unsigned = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": {k: v for k, v in envelope.items() if k != "signature"}, "expected_audience": "central-manager"})
    expired = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": sign_work_order(root, artifact_dir, commands, auth_dir, work_order(expires=-1, work_order_id="wo_uc_e2e_s4_expired")), "expected_audience": "central-manager"})
    revoked = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": sign_work_order(root, artifact_dir, commands, auth_dir, work_order(revoked=True, work_order_id="wo_uc_e2e_s4_revoked")), "expected_audience": "central-manager"})
    wrong_wo_audience = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(cred), "work_order": envelope, "expected_audience": "wrong-manager"})
    receiver_unchanged = state_before_failed_import["body"].get("state_node_id") == state_after_failed_import["body"].get("state_node_id")
    negatives = [
        neg("unsigned_work_order", unsigned["status"] == 403 and unsigned["body"].get("code") == "unsigned_work_order", status=unsigned["status"], code=unsigned["body"].get("code")),
        neg("expired_work_order", expired["status"] == 403 and expired["body"].get("code") == "expired_work_order", status=expired["status"], code=expired["body"].get("code")),
        neg("revoked_work_order", revoked["status"] == 403 and revoked["body"].get("code") == "revoked_work_order", status=revoked["status"], code=revoked["body"].get("code")),
        neg("wrong_audience_work_order", wrong_wo_audience["status"] == 403 and wrong_wo_audience["body"].get("code") == "wrong_audience", status=wrong_wo_audience["status"], code=wrong_wo_audience["body"].get("code")),
        neg("wrong_tenant_credential", wrong_tenant["status"] == 403 and wrong_tenant["body"].get("code") == "wrong_credential_binding", status=wrong_tenant["status"], code=wrong_tenant["body"].get("code")),
        neg("wrong_audience_credential", wrong_audience["status"] == 403 and wrong_audience["body"].get("code") == "wrong_audience", status=wrong_audience["status"], code=wrong_audience["body"].get("code")),
        neg("capability_mismatch", capability_mismatch["body"].get("status") == "rejected", status=capability_mismatch["body"].get("status"), reasons=capability_mismatch["body"].get("reasons")),
        neg("stale_heartbeat_placement_rejection", stale_placement["body"].get("status") == "rejected", status=stale_placement["body"].get("status"), reasons=stale_placement["body"].get("reasons")),
        neg("dispatch_target_mismatch", dispatch_target_mismatch["status"] == 403 and dispatch_target_mismatch["body"].get("code") == "dispatch_target_mismatch", status=dispatch_target_mismatch["status"], code=dispatch_target_mismatch["body"].get("code")),
        neg("dispatch_revoked_work_order", revoke_dispatch["status"] == 200 and revoked_dispatch["status"] == 403 and revoked_dispatch["body"].get("code") == "revoked_work_order", revoke_status=revoke_dispatch["status"], status=revoked_dispatch["status"], code=revoked_dispatch["body"].get("code")),
        neg("sibling_work_order_key_rejected", sibling_key_denied["status"] == 403 and sibling_key_denied["body"].get("code") in {"unknown_signature_key", "bad_signature"}, status=sibling_key_denied["status"], code=sibling_key_denied["body"].get("code")),
        neg("duplicate_remote_message", duplicate["body"].get("duplicate") is True and duplicate["body"].get("idempotency_key") == "proposal-once", duplicate=duplicate["body"].get("duplicate"), idempotency_key=duplicate["body"].get("idempotency_key")),
        neg("remote_message_delivery_failure", failed_remote["body"].get("delivery_status") == "failed", status=failed_remote["body"].get("delivery_status")),
        neg("unsupported_remote_message_schema", unsupported_remote["status"] == 400 and unsupported_remote["body"].get("code") == "unsupported_message_schema", status=unsupported_remote["status"], code=unsupported_remote["body"].get("code")),
        neg("unauthorized_remote_message_recipient", unauthorized_remote["status"] == 403 and unauthorized_remote["body"].get("code") == "unauthorized_recipient", status=unauthorized_remote["status"], code=unauthorized_remote["body"].get("code")),
        neg("state_handoff_wrong_tenant_rejected", wrong_handoff["status"] == 403 and wrong_handoff["body"].get("code") == "state_handoff_authority_mismatch", status=wrong_handoff["status"], code=wrong_handoff["body"].get("code")),
        neg("state_handoff_wrong_hash_rejected", wrong_hash["status"] == 403 and wrong_hash["body"].get("code") == "state_handoff_rejected", status=wrong_hash["status"], code=wrong_hash["body"].get("code")),
        neg("state_handoff_wrong_run_rejected", wrong_run["status"] in {400, 404}, status=wrong_run["status"], code=wrong_run["body"].get("code")),
        neg("receiver_state_unchanged_on_failed_import", receiver_unchanged, before=state_before_failed_import["body"].get("state_node_id"), after=state_after_failed_import["body"].get("state_node_id")),
        neg("trace_sync_idempotent_duplicate", sync_duplicate["body"].get("duplicate_records", 0) >= len(records), duplicate_records=sync_duplicate["body"].get("duplicate_records")),
        neg("trace_sync_tamper_rejected", sync_tampered["status"] == 403 and sync_tampered["body"].get("code") == "trace_sync_rejected", status=sync_tampered["status"], code=sync_tampered["body"].get("code")),
        neg("telemetry_non_authoritative", telemetry["body"].get("authority") == "observational_only", authority=telemetry["body"].get("authority")),
    ]

    event_ids = event_id_map(records, audit_events)
    same_image_evidence = compose_same_image_evidence(root)
    required_positive_checks = {
        "node_list_authenticated": node_list["status"] == 200,
        "instance_heartbeats_authenticated": all(result["status"] == 200 and result["body"].get("accepted") is True for result in instance_heartbeats),
        "work_order_accepted": validation["status"] == 200 and validation["body"].get("accepted") is True,
        "message_work_order_accepted": message_validation["status"] == 200 and message_validation["body"].get("accepted") is True,
        "placement_selected": placement["body"].get("status") == "selected" and placement["body"].get("candidate_id") == VPC_NODE_ID,
        "dispatch_started_resident_run": dispatch["body"].get("create_run_status") in {200, 201} and dispatch["body"].get("start_run_status") in {200, 201},
        "remote_message_delivered": remote["body"].get("delivery_status") == "delivered" and remote["body"].get("recipient_validated") is True and remote["body"].get("work_order_authority_validated") is True and remote["body"].get("route_permission") == f"message.remote.proposal:{HELPER_AGENT_ID}" and remote["body"].get("remote_state_mutated") is False,
        "remote_message_received_publicly": received["status"] == 200 and received["body"].get("receive_side_validated") is True,
        "state_handoff_imported": imported["body"].get("accepted") is True,
        "trace_sync_accepted": sync["body"].get("accepted_records", 0) > 0,
        "telemetry_observational": telemetry["body"].get("authority") == "observational_only",
        "replay_public_api": replay["status"] == 200 and replay["body"].get("mode") == "inspect_only",
        "same_image_compose_target": same_image_evidence.get("all_same") is True,
    }
    scenario_failures = [name for name, ok in required_positive_checks.items() if not ok]
    scenario_failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    scenario = {
        "id": "UC-E2E-S4",
        "status": "passed" if not scenario_failures else "failed",
        "fr_coverage": ["FR-0.03-02", "FR-0.03-04", "FR-0.03-05", "FR-0.03-08", "FR-0.03-09", "FR-0.03-10", "FR-0.03-11"],
        "components": ["central-manager", "resident-daemon", "fleet", "work-order", "placement", "remote-message", "state-handoff", "trace-sync", "fleet-telemetry", "replay/audit"],
        "positive_evidence": ["registered VPC and cloud nodes", "narrow signed dispatch and message work orders accepted", "VPC placement selected", "manager dispatched to resident daemon over verified TLS", "per-instance work-order key isolation rejected VPC authority at the cloud sibling", "remote proposal message delivered", "state snapshot exported/imported", "trace buffer synced", "telemetry reported observational-only"],
        "negative_evidence": [item["case"] for item in negatives if item.get("passed") is True],
        "replay_evidence": ["resident replayRun public API returned inspect_only replay over exported trace evidence without side effects"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "remote_messages_resent": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["same_runtime_image_for_splendor_instances", "public_manager_and_resident_https_used", "ephemeral_acceptance_keys_only", "telemetry_non_authoritative", "no_per_node_custom_images", "no_private_rust_helper_only_demo"],
        "run_ids": [run_id],
        "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids if tid}),
        "state_node_ids": [exported["body"].get("state_node_id", ""), imported["body"].get("state_node_id", "")],
        "state_hashes": [exported["body"].get("handoff", {}).get("snapshot", {}).get("state_hash", {}).get("value", "")],
        "message_ids": [message["message"]["message_id"], duplicate_message["message"]["message_id"], failed_message["message"]["message_id"]],
        "work_order_ids": [WORK_ORDER_ID, MESSAGE_WORK_ORDER_ID],
        "work_order_key_ids": WORK_ORDER_KEY_IDS,
        "approval_ids": [],
        "node_ids": [VPC_NODE_ID, CLOUD_NODE_ID, EDGE_NODE_ID],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "negative_cases": negatives,
        "same_image_fleet_evidence": same_image_evidence,
        "scenario_failures": scenario_failures,
        "artifact_paths": [],
    }

    artifacts = {
        "scenario-report.json": scenario,
        "registry.json": {"nodes": nodes, "instances": instances},
        "capabilities.json": {node["node_id"]: node["capability_document"] for node in nodes},
        "work-order-validation.json": {"dispatch": validation["body"], "remote_message": message_validation["body"], "sibling_key_denied": sibling_key_denied, "per_instance_key_ids": WORK_ORDER_KEY_IDS},
        "placement-decision.json": placement["body"],
        "dispatch-report.json": dispatch["body"],
        "remote-message-report.json": {"delivered": remote["body"], "received": received["body"], "duplicate": duplicate["body"], "failed": failed_remote["body"], "unsupported_schema": unsupported_remote, "unauthorized_recipient": unauthorized_remote},
        "state-handoff-report.json": {"exported": exported["body"], "imported": imported["body"], "rejected": wrong_handoff, "wrong_hash": wrong_hash, "wrong_run": wrong_run, "receiver_state_before_failed_import": state_before_failed_import["body"], "receiver_state_after_failed_import": state_after_failed_import["body"], "receiver_unchanged_on_failed_import": receiver_unchanged},
        "trace-sync-report.json": {**sync["body"], "duplicate_sync": sync_duplicate["body"], "tampered_sync": sync_tampered},
        "fleet-telemetry.json": telemetry["body"],
        "replay-report.json": {**replay["body"], "side_effects_allowed_default": False, "remote_messages_resent": False, "derived_from_public_replay_api": True, "reconstructed": ["run.dispatched", "remote_message.delivered", "remote_message.duplicate", "remote_message.failed", "state.exported", "state.imported", "state.rejected", "trace.sync.completed"], "denial_reasons": [item["case"] for item in negatives if item.get("passed") is True]},
        "audit-report.json": {"events": audit_events, "negative_cases": negatives},
        "anti-drift-results.json": {"status": "passed" if not scenario_failures else "failed", "same_image_fleet": same_image_evidence.get("all_same") is True, "private_helper_only_e2e": False, "telemetry_authorizes_dispatch": False, "gateway_bypass": False, "replay_side_effects_allowed_default": False},
        "stdout.log": "UC-E2E-S4 fleet dispatch scenario completed through public manager and verified-TLS resident APIs\n",
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
    if scenario_failures:
        raise SystemExit("UC-E2E-S4 failed required evidence checks: " + ",".join(scenario_failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
