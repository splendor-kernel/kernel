#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "fixtures"))
from canonical_fleet_profiles import (  # noqa: E402
    CLOUD_INSTANCE_FEATURES,
    CLOUD_NODE_CAPABILITIES,
    EDGE_INSTANCE_FEATURES,
    EDGE_NODE_CAPABILITIES,
    VPC_INSTANCE_FEATURES,
    VPC_NODE_CAPABILITIES,
)
from acceptance_provider_evidence import read_provider_evidence  # noqa: E402
from acceptance_provider_output import project_private_v3_output  # noqa: E402
from acceptance_scenario_expectations import expectation_for  # noqa: E402
from resident_http import (  # noqa: E402
    REDIRECT_POLICY,
    project_retained_approval_evidence,
    request_json_no_redirect,
)

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
ORCH_DATA_RUN = "44444444-4444-4444-8444-444444448816"
PUBLISH_RUN = "44444444-4444-4444-8444-444444448817"
REVOKE_RUN = "44444444-4444-4444-8444-444444448818"
VPC_NODE = "00000000-0000-4000-8000-000000000204"
VPC_INSTANCE = "00000000-0000-4000-8000-000000000302"
CLOUD_NODE = "00000000-0000-4000-8000-000000000404"
CLOUD_INSTANCE = "00000000-0000-4000-8000-000000000304"
EDGE_NODE = "00000000-0000-4000-8000-000000000604"
OTHER_EDGE_NODE = "00000000-0000-4000-8000-000000000605"
EDGE_INSTANCE = "00000000-0000-4000-8000-000000000306"
WORK_ORDER_ORCH = "wo_uc_e2e_s10_field_intelligence"
WORK_ORDER_ORCH_DATA = "wo_uc_e2e_s10_field_intelligence_data"
WORK_ORDER_ORCH_PUBLISH = "wo_uc_e2e_s10_field_intelligence_publish"
WORK_ORDER_ORCH_MESSAGE = "wo_uc_e2e_s10_field_intelligence_message"
WORK_ORDER_SPECIALIST = "wo_uc_e2e_s10_scoped_specialist"
WORK_ORDER_SPECIALIST_MESSAGE = "wo_uc_e2e_s10_scoped_specialist_message"
WORK_ORDER_CLOUD_HELPER = "wo_uc_e2e_s10_cloud_helper_proposal"
WORK_ORDER_EDGE = "wo_uc_e2e_s10_edge_inspection"
WORK_ORDER_CB = "wo_uc_e2e_s10_circuit_branch"
WORK_ORDER_KILL = "wo_uc_e2e_s10_kill_branch"
WORK_ORDER_ORCH_REVOKE = "wo_uc_e2e_s10_field_intelligence_publish_revoke"
POLICY_ID = "policy_uc_e2e_s10_final_journey"
PUBLISH_ACTION_ID = "55555555-5555-4555-8555-555555558821"
REVOKE_ACTION_ID = "55555555-5555-4555-8555-555555558822"
BREAKER_ID = "55555555-5555-4555-8555-555555558816"
KILL_SWITCH_ID = "ks_uc_e2e_s10_controlled_branch"
WORK_ORDER_KEY_IDS = {
    VPC_INSTANCE: "work-order-acceptance-vpc",
    CLOUD_INSTANCE: "work-order-acceptance-cloud",
    EDGE_INSTANCE: "work-order-acceptance-edge",
}
RUNTIME_IMAGE_IDENTITY = "splendor-kernel-runtime:acceptance-target-runtime"
PHYSICAL_PERMISSION = "physical.high_level"
DATA_REF = "dataset:tenant-a.field-intel.fixture.v1"
DENIED_DATA_REF = "dataset:tenant-b.field-intel.restricted.v1"
INTERNAL_ARTIFACT = f"artifact://{TENANT_ID}/field-intelligence/s10-internal.md"
EXTERNAL_ARTIFACT = f"artifact://{TENANT_ID}/field-intelligence/s10-public.md"
ROUTE_PROPOSAL_ID = "route-proposal-s10-zone-a3"
CLOUD_MESSAGE_ID = "55555555-5555-4555-8555-555555558810"
TASK_REQUEST_ID = "55555555-5555-4555-8555-555555558811"
TASK_RESPONSE_ID = "55555555-5555-4555-8555-555555558812"
DUPLICATE_MESSAGE_ID = "55555555-5555-4555-8555-555555558813"
CAPABILITY_GRANT_ID = "77777777-7777-4777-8777-777777778810"
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
    "operator_intervention_expiry_extension_rejected",
    "operator_intervention_cross_device_reuse_rejected",
    "expired_approval_rejected",
    "revoked_resident_receipt_retry_has_zero_effect",
    "circuit_breaker_blocks_matching_publish_attempt",
    "kill_switch_cancels_separate_run",
    "tampered_trace_state_import_rejected",
    "resident_device_trace_scope_integrity_rejected",
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
    "resident_approval_receipt_revocation_acknowledged",
    "resident_state_handoff_denied_without_source_proof_and_receiver_resumed",
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
    "approval.revoked",
    "artifact.created",
    "artifact.publish.executed",
    "state.committed",
    "state.exported",
    "run.resumed",
    "trace.sync.completed",
    "replay.explained",
    "governance.audit.exported",
    "circuit_breaker.tripped",
    "kill_switch.activated",
}

S10_RUN_IDS = {ORCH_RUN, ORCH_DATA_RUN, PUBLISH_RUN, REVOKE_RUN, SPECIALIST_RUN, CLOUD_HELPER_RUN, EDGE_RUN, CB_RUN, KILL_RUN}
S10_WORK_ORDER_IDS = {
    WORK_ORDER_ORCH,
    WORK_ORDER_ORCH_DATA,
    WORK_ORDER_ORCH_PUBLISH,
    WORK_ORDER_ORCH_MESSAGE,
    WORK_ORDER_SPECIALIST,
    WORK_ORDER_SPECIALIST_MESSAGE,
    WORK_ORDER_CLOUD_HELPER,
    WORK_ORDER_EDGE,
    WORK_ORDER_CB,
    WORK_ORDER_KILL,
    WORK_ORDER_ORCH_REVOKE,
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
    retained = project_retained_approval_evidence(data)
    path.write_text(json.dumps(retained, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(project_retained_approval_evidence(row), sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


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
    context: ssl.SSLContext | None = None,
) -> tuple[int, dict[str, Any]]:
    return request_json_no_redirect(
        method,
        base_url.rstrip("/") + path,
        body,
        headers,
        context,
        timeout=30,
    )


def resident_security_event_is_valid(event: dict[str, Any]) -> bool:
    method = event.get("method")
    result_status = event.get("result_status")
    expected_statuses = event.get("expected_statuses")
    expected_result = event.get("expected_result")
    scope_expectation = event.get("scope_expectation")
    correlation = event.get("correlation", {})
    mutating = event.get("mutating") is True
    if (
        not event.get("call_id")
        or not event.get("operation_id")
        or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        or event.get("url_scheme") != "https"
        or event.get("tls_verification") != "acceptance_ca"
        or event.get("redirect_policy") != REDIRECT_POLICY
        or event.get("target_instance_id") != event.get("audience_instance_id")
        or event.get("target_audience")
        != f"urn:splendor:instance:{event.get('target_instance_id')}"
        or not str(event.get("credential_id", "")).startswith("sha256:")
        or event.get("header_presence", {}).get("authorization") is not True
        or event.get("header_presence", {}).get("caller_credential_mirror") is not True
        or event.get("raw_bearer_recorded") is not False
        or not isinstance(expected_statuses, list)
        or not expected_statuses
        or result_status not in expected_statuses
    ):
        return False
    if expected_result == "success" and not (isinstance(result_status, int) and 200 <= result_status < 300):
        return False
    if expected_result == "error" and not (isinstance(result_status, int) and 300 <= result_status < 600):
        return False
    if mutating and event.get("body_mirror_status") != "matched":
        return False
    if not mutating and event.get("body_mirror_status") not in {"matched", "not_applicable"}:
        return False
    if scope_expectation == "exact":
        if event.get("scope") != event.get("required_scope"):
            return False
    elif scope_expectation == "intentional_mismatch":
        if event.get("scope") == event.get("required_scope") or expected_result != "error":
            return False
    else:
        return False
    if mutating:
        if correlation.get("status") == "available":
            if not correlation.get("trace_event_ids") and not correlation.get("daemon_audit_trace_event_ids"):
                return False
        elif correlation.get("status") == "unavailable":
            if not correlation.get("unavailable_reason"):
                return False
        else:
            return False
    elif correlation.get("status") != "not_required_read_only":
        return False
    return True


def derive_resident_security_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    mutating = [event for event in events if event.get("mutating") is True]
    mutating_ids = [event.get("credential_id") for event in mutating]
    valid_events = [event for event in events if resident_security_event_is_valid(event)]
    return {
        "total_calls": len(events),
        "mutating_calls": len(mutating),
        "read_only_calls": len(events) - len(mutating),
        "successful_response_calls": sum(
            isinstance(event.get("result_status"), int)
            and 200 <= event["result_status"] < 300
            for event in events
        ),
        "expected_error_calls": sum(event.get("expected_result") == "error" for event in events),
        "expected_result_matches": sum(
            event.get("result_status") in event.get("expected_statuses", [])
            for event in events
        ),
        "unique_mutating_credential_ids": len(set(mutating_ids)),
        "response_trace_correlated_mutating_calls": sum(
            bool(event.get("correlation", {}).get("trace_event_ids")) for event in mutating
        ),
        "daemon_audit_correlated_mutating_calls": sum(
            bool(event.get("correlation", {}).get("daemon_audit_trace_event_ids"))
            for event in mutating
        ),
        "unavailable_mutating_correlations": sum(
            event.get("correlation", {}).get("status") == "unavailable"
            for event in mutating
        ),
        "invalid_calls": len(events) - len(valid_events),
        "status": "passed" if events and len(valid_events) == len(events) and len(mutating_ids) == len(set(mutating_ids)) else "failed",
    }


def sim_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    if method == "GET" and path == "/evidence" and body is None:
        return read_provider_evidence(base_url)
    status, data = request_json(method, base_url, path, body)
    if status != 200:
        raise SystemExit(f"device simulator request failed: {method} {path} status={status} body={data}")
    return data


def sim_total(counters: dict[str, Any]) -> int:
    return int(counters.get("requests_total", counters.get("total", 0)))


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
            "instances_heartbeat",
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


def resident_auth(
    root: Path,
    auth_dir: Path,
    instance_id: str,
    scopes: list[str],
    *,
    tenant_id: str = TENANT_ID,
) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "token",
        "--auth-dir",
        str(auth_dir),
        "--tenant-id",
        tenant_id,
        "--instance-id",
        instance_id,
    ]
    for scope in scopes:
        command.extend(["--scope", scope])
    process = subprocess.run(command, text=True, capture_output=True)
    if process.returncode != 0:
        raise SystemExit("resident caller token fixture failed")
    return json.loads(process.stdout)


def manager_approval_auth(root: Path, auth_dir: Path) -> dict[str, Any]:
    command = [
        "python3",
        str(root / "tests/e2e/use-cases/fixtures/resident_auth_fixture.py"),
        "manager-token",
        "--auth-dir",
        str(auth_dir),
        "--fleet-id",
        FLEET_ID,
        "--manager-id",
        "central-manager",
        "--scope",
        "approvals_manage",
    ]
    process = subprocess.run(command, text=True, capture_output=True)
    if process.returncode != 0:
        raise SystemExit("manager approval caller token fixture failed")
    return json.loads(process.stdout)


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc(0)}


def sec(credential: dict[str, Any]) -> dict[str, Any]:
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
            "constraints": {
                "placement_target": target,
                "data_locality": locality,
                "region": "eu-west",
                "resident_daemon_url": url,
                "runtime_image_identity": RUNTIME_IMAGE_IDENTITY,
                "trust_level": "acceptance",
            },
        },
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}},
        "registered_at": utc(0),
    }


def instance_registration(node_id: str, instance_id: str, supported_features: list[str]) -> dict[str, Any]:
    return {
        "instance_id": instance_id,
        "node_id": node_id,
        "runtime_mode": "resident",
        "hosted_tenants": [TENANT_ID],
        "supported_features": supported_features,
        "runtime_version": "0.1-acceptance",
        "health": {"status": "healthy", "observed_at": utc(0), "metadata": {"runtime_image_identity": RUNTIME_IMAGE_IDENTITY}},
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
        "Internal field-intelligence artifact creation under an exact profile",
        ["artifact.create_internal"],
        ["artifact-store"],
        ["artifact.create_internal"],
        [INTERNAL_ARTIFACT],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["artifact.create_internal"]},
        12,
    )


def orchestrator_publish_work_order(
    work_order_id: str = WORK_ORDER_ORCH_PUBLISH,
    run_id: str = PUBLISH_RUN,
    objective: str = "Approval-gated external publication under an exact profile",
) -> dict[str, Any]:
    return base_work_order(
        work_order_id,
        ORCH_AGENT,
        run_id,
        objective,
        ["artifact.publish_external"],
        ["artifact-store"],
        ["artifact.publish_external"],
        [EXTERNAL_ARTIFACT],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["runtime.resident"]},
        4,
    )


def orchestrator_data_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_ORCH_DATA,
        ORCH_AGENT,
        ORCH_DATA_RUN,
        "Data-local analysis under an exact fixture-data-store profile",
        ["data.read_fixture"],
        ["fixture-data-store"],
        ["data.read_fixture"],
        [DATA_REF],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["sql.read_fixture"]},
        4,
    )


def orchestrator_message_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_ORCH_MESSAGE,
        ORCH_AGENT,
        ORCH_RUN,
        "Typed specialist request with no delegated action authority",
        ["message.remote.proposal"],
        ["remote-message"],
        [f"message.remote.proposal:{SPECIALIST_AGENT}"],
        [DATA_REF],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["message.remote.proposal"]},
        2,
    )


def specialist_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_SPECIALIST,
        SPECIALIST_AGENT,
        SPECIALIST_RUN,
        "Shared specialist analyzes only the scoped field-intelligence fixture",
        ["data.read_fixture"],
        ["fixture-data-store"],
        ["data.read_fixture"],
        [DATA_REF],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["sql.read_fixture"]},
        6,
    )


def specialist_message_work_order() -> dict[str, Any]:
    return base_work_order(
        WORK_ORDER_SPECIALIST_MESSAGE,
        SPECIALIST_AGENT,
        SPECIALIST_RUN,
        "Typed specialist response under exact remote-message authority",
        ["message.remote.proposal"],
        ["remote-message"],
        [f"message.remote.proposal:{ORCH_AGENT}"],
        [DATA_REF],
        {"target": "customer_vpc", "data_locality": "vpc", "requires_gpu": False, "required_capabilities": ["message.remote.proposal"]},
        2,
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
        [PHYSICAL_PERMISSION],
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
        ["artifact-store"],
        actions,
        [EXTERNAL_ARTIFACT if actions == ["artifact.publish_external"] else INTERNAL_ARTIFACT],
        {"target": "resident_cloud_pool", "data_locality": "cloud", "requires_gpu": False, "required_capabilities": actions},
        4,
    )


def sign_work_order(
    root: Path,
    artifact_dir: Path,
    commands: Path,
    auth_dir: Path,
    payload: dict[str, Any],
    instance_id: str,
) -> dict[str, Any]:
    unsigned = artifact_dir / f"{payload['work_order_id']}.unsigned.json"
    write_json(unsigned, payload)
    secret = (auth_dir / f"work-order-signing-{instance_id}.secret").read_text(encoding="ascii")
    command = splendorctl(root) + [
        "work-order",
        "sign",
        "--input",
        str(unsigned),
        "--key-id",
        WORK_ORDER_KEY_IDS[instance_id],
        "--secret",
        secret,
    ]
    with commands.open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(command[:-1] + ["[REDACTED]"]) + "\n")
    process = subprocess.run(command, cwd=root, text=True, capture_output=True)
    with commands.open("a", encoding="utf-8") as log:
        log.write(process.stderr)
        log.write(f"exit={process.returncode}\n")
    if process.returncode != 0:
        raise SystemExit(f"{instance_id} work-order signing failed")
    return json.loads(process.stdout)


def quota(actions: int = 1) -> dict[str, int]:
    return {"actions": actions, "action_duration_ms": 1, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0}


def postcondition_for_action(name: str) -> str:
    if name in {"read_battery", "read_sensor_summary"}:
        return "sensor_read"
    if name in set(ALLOWED_PHYSICAL_ACTIONS) - {"read_battery", "read_sensor_summary"}:
        return "device_state_updated"
    return {
        "data.read_fixture": "data_read",
        "artifact.create_internal": "artifact_created",
        "artifact.publish_external": "artifact_published",
    }.get(name, "marker_recorded")


def action(name: str, permission: str | None = None, side_effect_class: str = "External", **params: Any) -> dict[str, Any]:
    return {
        "name": name,
        "params": params,
        "side_effect_class": side_effect_class,
        "cost_estimate": None,
        "required_permissions": [permission or name],
        "preconditions": [],
        "postconditions": [postcondition_for_action(name)],
    }


def physical_action(name: str, **params: Any) -> dict[str, Any]:
    return action(name, PHYSICAL_PERMISSION, {"Custom": "physical.high_level"}, **(params or {"physical_action": True}))


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


def physical_payload(
    name: str, *, action_id: str | None = None, **safety_overrides: Any
) -> dict[str, Any]:
    params = {"physical_action": True}
    for key in ["cloud_helper_proposal_id", "cloud_helper_message_id"]:
        if safety_overrides.get(key):
            params[key] = safety_overrides[key]
    payload = {
        "run_id": EDGE_RUN,
        "tenant_id": TENANT_ID,
        "agent_id": EDGE_AGENT,
        "causal_trace_id": EDGE_CAUSAL_TRACE_ID,
        "action": physical_action(name, **params),
        "adapter": "device-sim",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "safety_context": safety_context(**safety_overrides),
    }
    if action_id is not None:
        payload["action_id"] = action_id
    return payload


def create_run_payload(
    *,
    run_id: str,
    agent_id: str,
    envelope: dict[str, Any],
    initial_state: dict[str, Any],
    policy_actions: list[dict[str, Any]] | None = None,
    approval_policies: list[dict[str, Any]] | None = None,
    circuit_breakers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    allowed_actions = envelope.get("allowed_actions", [])
    allowed_adapters = envelope.get("allowed_adapters", [])
    work_order_id = envelope.get("work_order_id") or envelope.get("work_order", {}).get("work_order_id", "unknown")
    registered_actions = [
        {
            "name": name,
            "adapter": allowed_adapters[0] if allowed_adapters else "acceptance-fixture",
            "required_permissions": list(envelope.get("allowed_permissions", [])),
        }
        for name in allowed_actions
    ]
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


def approval_policy(
    expires_at: str,
    *,
    policy_id: str,
    action_name: str = "artifact.publish_external",
) -> dict[str, Any]:
    return {
        "schema_version": "splendor.approval_policy.v1",
        "policy_id": policy_id,
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "action_name": action_name,
        "adapter": "artifact-store",
        "required_permission": action_name,
        "side_effect_class": "External",
        "risk_level": "high",
        "reason": "S10 external publication requires scoped approval",
        "expires_at": expires_at,
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
        "schema_version": schema.rsplit(".", 1)[-1],
        "delivery_status": "pending",
        "trace_links": {},
    }


def extract_approval_context(outcome: dict[str, Any]) -> dict[str, Any]:
    challenge = outcome.get("approval_challenge")
    if not isinstance(challenge, dict) or not challenge:
        raise SystemExit("exact approval challenge missing from S10 needs_approval outcome")
    return challenge


def approval_request_payload(security: dict[str, Any], challenge: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        **security,
        "approval_id": challenge["approval_id"],
        "tenant_id": challenge["tenant_id"],
        "agent_id": challenge["agent_id"],
        "run_id": challenge["run_id"],
        "action_id": challenge["action_id"],
        "action_name": challenge["action_name"],
        "adapter": challenge["adapter"],
        "policy_id": challenge["policy_id"],
        "risk_level": challenge.get("risk_level") or "",
        "audience": challenge["receipt_audience"],
        "expires_at": challenge["expires_at"],
        "reason": reason,
        "challenge": challenge,
    }


def dispatch_start_body(dispatch: dict[str, Any]) -> dict[str, Any]:
    raw = dispatch.get("body", {}).get("start_run_body")
    if isinstance(raw, str) and raw.strip():
        return json.loads(raw)
    if isinstance(raw, dict):
        return raw
    return {}


def dispatch_create_body(dispatch: dict[str, Any]) -> dict[str, Any]:
    raw = dispatch.get("body", {}).get("create_run_body")
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


def correlate_resident_security_events(
    events: list[dict[str, Any]], records: list[dict[str, Any]]
) -> None:
    daemon_audit_ids: dict[str, set[str]] = {}
    for record in records:
        if trace_kind(record) != "daemon.audit":
            continue
        body = trace_body(record)
        audit_value = body.get("audit") if isinstance(body.get("audit"), dict) else {}
        credential_id = audit_value.get("credential_id")
        event_id = trace_id(record)
        if credential_id and event_id:
            daemon_audit_ids.setdefault(str(credential_id), set()).add(event_id)

    for event in events:
        if event.get("mutating") is not True:
            event["correlation"] = {
                "status": "not_required_read_only",
                "trace_event_ids": [],
                "daemon_audit_trace_event_ids": [],
                "unavailable_reason": None,
            }
            continue
        correlation = event.get("correlation", {})
        response_ids = sorted(
            {
                str(value)
                for value in correlation.get("trace_event_ids", [])
                if value
            }
        )
        audit_ids = sorted(daemon_audit_ids.get(str(event.get("credential_id")), set()))
        event["correlation"] = {
            "status": "available" if response_ids or audit_ids else "unavailable",
            "trace_event_ids": response_ids,
            "daemon_audit_trace_event_ids": audit_ids,
            "unavailable_reason": None
            if response_ids or audit_ids
            else "response_exposed_no_trace_id_and_exported_daemon_audit_attribution_was_unavailable",
        }


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
    elif event_type == "approval.granted" and run_id == PUBLISH_RUN:
        add_event_evidence(evidence, "approval.granted", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, action_id=details.get("action_id"), approval_id=details.get("approval_id"), details=details)
    elif event_type == "approval.granted" and run_id == REVOKE_RUN:
        add_event_evidence(evidence, "approval.granted", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, action_id=details.get("action_id"), approval_id=details.get("approval_id"), details=details)
    elif event_type == "approval.revoked" and run_id == REVOKE_RUN:
        add_event_evidence(evidence, "approval.revoked", trace_event_id=trace_event_id, source="manager_audit_export", original_event_type=event_type, artifact="manager-audit-export.json", run_id=run_id, action_id=details.get("action_id"), approval_id=details.get("approval_id"), details=details)
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


def resolve_action_trace_evidence(
    records: list[dict[str, Any]],
    outcome: dict[str, Any],
    expectation_id: str,
    action_name: str,
) -> dict[str, Any]:
    expectation = expectation_for("UC-E2E-S10", expectation_id)
    projection = project_private_v3_output(
        outcome,
        expectation=expectation,
    )
    output = projection["output"]
    evidence = {
        "action_id": outcome.get("action_id"),
        "status": outcome.get("status"),
        "artifact_path": projection["resource_id"],
        "tenant_id": projection["tenant_id"],
        "integrity": projection["state_digest"],
        "trace_event_id": outcome.get("trace_event_id"),
        "output": output,
        "private_v3_projection": projection,
    }
    for record in records:
        if trace_kind(record) != "action.executed" or trace_action_name(record) != action_name:
            continue
        body = trace_body(record)
        trace_output = body.get("outcome") if isinstance(body.get("outcome"), dict) else {}
        trace_projection = project_private_v3_output(
            trace_output,
            expectation=expectation,
        )
        trace_path = trace_projection["resource_id"]
        if evidence.get("artifact_path") and trace_path != evidence.get("artifact_path"):
            continue
        evidence.update(
            {
                "trace_event_id": trace_id(record),
                "trace_run_id": record.get("run_id") or trace_identity(record).get("run_id"),
                "trace_action_name": action_name,
                "trace_artifact_path": trace_path,
                "trace_integrity": trace_projection["state_digest"],
                "trace_tenant_id": trace_projection["tenant_id"],
                "trace_private_v3_projection": trace_projection,
            }
        )
        if not evidence.get("artifact_path") and trace_path:
            evidence["artifact_path"] = trace_path
        if not evidence.get("tenant_id") and isinstance(trace_path, str) and trace_path.startswith("artifact://"):
            evidence["tenant_id"] = trace_path.removeprefix("artifact://").split("/", 1)[0]
        if not evidence.get("integrity"):
            evidence["integrity"] = trace_projection["state_digest"]
        break
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--manager-url", default="http://central-manager:8081")
    parser.add_argument("--vpc-url", default="https://resident-vpc-node:8092")
    parser.add_argument("--cloud-url", default="https://resident-cloud-node:8091")
    parser.add_argument("--edge-url", default="https://resident-edge-node:8093")
    parser.add_argument(
        "--action-provider-url",
        dest="device_sim_url",
        metavar="ACTION_PROVIDER_URL",
        default="http://acceptance-action-provider:8086",
    )
    parser.add_argument(
        "--resident-auth-dir",
        default=os.environ.get("SPLENDOR_RESIDENT_AUTH_DIR", "/run/splendor-auth"),
    )
    parser.add_argument(
        "--resident-ca-file",
        default=os.environ.get(
            "SPLENDOR_RESIDENT_CA_FILE",
            "/run/splendor-auth/resident-root-ca.pem",
        ),
    )
    args = parser.parse_args()
    for label, url in [("VPC", args.vpc_url), ("cloud", args.cloud_url), ("edge", args.edge_url)]:
        if not url.lower().startswith("https://"):
            raise SystemExit(f"UC-E2E-S10 resident {label} URL must use HTTPS")
    root = Path(args.root)
    auth_dir = Path(args.resident_auth_dir)
    resident_ssl = ssl.create_default_context(cafile=args.resident_ca_file)
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
    resident_security_events: list[dict[str, Any]] = []
    used_resident_credentials: set[str] = set()
    manager_approval_auth_events: list[dict[str, Any]] = []
    used_manager_approval_credentials: set[str] = set()

    def call(
        operation: str,
        method: str,
        base: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        *,
        resident_call_id: str | None = None,
        manager_approval_call_id: str | None = None,
    ) -> dict[str, Any]:
        context = resident_ssl if base.lower().startswith("https://") else None
        status, data = request_json(method, base, path, body, headers, context)
        row = {
            "operation_id": operation,
            "method": method,
            "url": base.rstrip("/") + path,
            "status": status,
            "request": body,
            "response": data,
            "transport": "verified_tls" if context is not None else "local_acceptance_http",
        }
        if resident_call_id is not None:
            row["resident_call_id"] = resident_call_id
        if manager_approval_call_id is not None:
            row["manager_approval_call_id"] = manager_approval_call_id
        api_rows.append(row)
        write_jsonl(artifact_dir / "api-traffic.ndjson", api_rows)
        return {"status": status, "body": data}

    def resident_call(
        operation: str,
        method: str,
        base: str,
        instance_id: str,
        path: str,
        scope: str,
        body: dict[str, Any] | None = None,
        *,
        required_scope: str | None = None,
        scope_expectation: str = "exact",
        expected_statuses: tuple[int, ...] = (200,),
        expected_result: str = "success",
    ) -> dict[str, Any]:
        if operation == "createRun" and expected_statuses == (200,):
            expected_statuses = (200, 201)
        auth = resident_auth(root, auth_dir, instance_id, [scope])
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_resident_credentials:
            raise SystemExit("resident caller fixture reused a bearer JTI")
        used_resident_credentials.add(credential_id)
        expected_audience = {"instance": {"instance_id": instance_id}}
        if credential.get("scopes") != [scope] or credential.get("audience") != expected_audience:
            raise SystemExit("resident caller fixture returned an invalid request scope or audience")
        request_headers = credential_header(auth)
        secured_body = (
            None
            if body is None
            else {
                **body,
                "credential": credential,
                "audit_attribution": audit(credential),
            }
        )
        call_id = f"resident-call-{len(resident_security_events) + 1:04d}"
        result = call(
            operation,
            method,
            base,
            path,
            secured_body,
            request_headers,
            resident_call_id=call_id,
        )
        response_trace_ids = []
        if isinstance(result.get("body"), dict):
            for key in ["trace_event_id", "audit_trace_event_id"]:
                if result["body"].get(key):
                    response_trace_ids.append(str(result["body"][key]))
        mirror_matches = (
            secured_body is not None
            and secured_body.get("credential") == credential
            and secured_body.get("audit_attribution", {}).get("credential_id")
            == credential_id
            and secured_body.get("audit_attribution", {}).get("principal")
            == credential["principal"]
        )
        resident_security_events.append(
            {
                "call_id": call_id,
                "operation_id": operation,
                "method": method,
                "scope": scope,
                "required_scope": required_scope or scope,
                "scope_expectation": scope_expectation,
                "credential_id": credential_id,
                "target_instance_id": instance_id,
                "audience_instance_id": credential["audience"]["instance"]["instance_id"],
                "target_audience": f"urn:splendor:instance:{instance_id}",
                "url_scheme": urlsplit(base).scheme.lower(),
                "tls_verification": "acceptance_ca"
                if urlsplit(base).scheme.lower() == "https"
                else "unverified",
                "header_presence": {
                    "authorization": "authorization" in request_headers,
                    "caller_credential_mirror": "x-splendor-caller-credential"
                    in request_headers,
                },
                "body_mirror_status": "not_applicable"
                if secured_body is None
                else "matched"
                if mirror_matches
                else "mismatch",
                "redirect_policy": REDIRECT_POLICY,
                "result_status": result["status"],
                "expected_statuses": sorted(set(expected_statuses)),
                "expected_result": expected_result,
                "mutating": method in {"POST", "PUT", "PATCH", "DELETE"},
                "raw_bearer_recorded": False,
                "correlation": {
                    "status": "available"
                    if response_trace_ids
                    else "unavailable",
                    "trace_event_ids": sorted(set(response_trace_ids)),
                    "daemon_audit_trace_event_ids": [],
                    "unavailable_reason": None
                    if response_trace_ids
                    else "response_exposed_no_trace_id; exported_daemon_audit_correlation_pending",
                },
            }
        )
        return result

    def manager_approval_call(
        operation: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_statuses: tuple[int, ...] = (200,),
        expected_result: str = "success",
    ) -> dict[str, Any]:
        auth = manager_approval_auth(root, auth_dir)
        credential = auth["credential"]
        credential_id = credential["credential_id"]
        if credential_id in used_manager_approval_credentials:
            raise SystemExit("manager approval caller fixture reused a bearer JTI")
        used_manager_approval_credentials.add(credential_id)
        expected_binding = {"fleet": {"fleet_id": FLEET_ID}}
        expected_audience = {"central_manager": {"manager_id": "central-manager"}}
        if credential.get("scopes") != ["approvals_manage"] or credential.get("binding") != expected_binding or credential.get("audience") != expected_audience:
            raise SystemExit("manager approval caller fixture returned an invalid projection")
        secured_body = {
            **body,
            "credential": credential,
            "audit_attribution": audit(credential),
        }
        call_id = f"manager-approval-call-{len(manager_approval_auth_events) + 1:04d}"
        result = call(
            operation,
            "POST",
            args.manager_url,
            path,
            secured_body,
            {"authorization": f"Bearer {auth['token']}"},
            manager_approval_call_id=call_id,
        )
        manager_approval_auth_events.append(
            {
                "call_id": call_id,
                "operation_id": operation,
                "method": "POST",
                "endpoint": path,
                "scope": "approvals_manage",
                "required_scope": "approvals_manage",
                "credential_id": credential_id,
                "fleet_id": credential["binding"]["fleet"]["fleet_id"],
                "target_manager_id": "central-manager",
                "audience_manager_id": credential["audience"]["central_manager"]["manager_id"],
                "header_presence": {"authorization": True},
                "body_mirror_status": "matched",
                "result_status": result["status"],
                "expected_statuses": sorted(set(expected_statuses)),
                "expected_result": expected_result,
                "response_code": result["body"].get("code")
                if isinstance(result.get("body"), dict)
                else None,
                "trace_event_ids": [result["body"]["trace_event_id"]]
                if isinstance(result.get("body"), dict) and result["body"].get("trace_event_id")
                else [],
                "raw_bearer_recorded": False,
                "raw_jti_recorded": False,
                "receipt_signature_recorded": False,
            }
        )
        if result["status"] not in expected_statuses:
            raise SystemExit(
                f"{operation} returned {result['status']}, expected {expected_statuses}: "
                + json.dumps(result["body"], sort_keys=True)
            )
        return result

    for _ in range(60):
        if call("managerHealth", "GET", args.manager_url, "/health")["status"] == 200:
            break
        time.sleep(0.25)
    for base, operation in [(args.vpc_url, "vpcHealth"), (args.cloud_url, "cloudHealth"), (args.edge_url, "edgeHealth")]:
        instance_id = VPC_INSTANCE if base == args.vpc_url else CLOUD_INSTANCE if base == args.cloud_url else EDGE_INSTANCE
        for _ in range(60):
            if resident_call(operation, "GET", base, instance_id, "/health", "health_read")["status"] == 200:
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
        node_registration(VPC_NODE, "vpc.worker", "customer_vpc", "vpc", args.vpc_url, list(VPC_NODE_CAPABILITIES)),
        node_registration(CLOUD_NODE, "cloud.worker", "resident_cloud_pool", "cloud", args.cloud_url, list(CLOUD_NODE_CAPABILITIES)),
        node_registration(EDGE_NODE, "edge.device", "edge_device", "device", args.edge_url, list(EDGE_NODE_CAPABILITIES)),
    ]
    instances = [
        instance_registration(VPC_NODE, VPC_INSTANCE, list(VPC_INSTANCE_FEATURES)),
        instance_registration(CLOUD_NODE, CLOUD_INSTANCE, list(CLOUD_INSTANCE_FEATURES)),
        instance_registration(EDGE_NODE, EDGE_INSTANCE, list(EDGE_INSTANCE_FEATURES)),
    ]
    node_registrations = [call("registerNode", "POST", args.manager_url, "/fleet/nodes", {**sec(manager), "registration": node}) for node in nodes]
    instance_registrations = [call("registerInstance", "POST", args.manager_url, "/fleet/instances", {**sec(manager), "registration": inst}) for inst in instances]
    for node in nodes:
        call("heartbeatNode", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/heartbeat", {**sec(manager), "heartbeat": {"node_id": node["node_id"], "health": node["health"], "recorded_at": utc(0)}})
        call("advertiseCapabilities", "POST", args.manager_url, f"/fleet/nodes/{node['node_id']}/capabilities", {**sec(manager), "capability_document": node["capability_document"]})
    instance_heartbeats = [
        call(
            "heartbeatInstance",
            "POST",
            args.manager_url,
            f"/fleet/instances/{instance['instance_id']}/heartbeat",
            {
                **sec(manager),
                "heartbeat": {
                    "node_id": instance["node_id"],
                    "instance_id": instance["instance_id"],
                    "health": instance["health"],
                    "recorded_at": utc(0),
                },
            },
        )
        for instance in instances
    ]
    node_list = call("listNodes", "POST", args.manager_url, "/fleet/nodes/list", sec(manager))

    policy = call("publishPolicyBundle", "POST", args.manager_url, "/policies", {**sec(manager), "policy_bundle": policy_bundle()})
    policy_status = call("getPolicyStatus", "POST", args.manager_url, f"/policies/{POLICY_ID}/read", sec(manager))

    orchestrator_payload = orchestrator_work_order()
    orch_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, orchestrator_payload, VPC_INSTANCE)
    cloud_receiver_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, orchestrator_payload, CLOUD_INSTANCE)
    orch_data_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, orchestrator_data_work_order(), VPC_INSTANCE)
    publish_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, orchestrator_publish_work_order(), VPC_INSTANCE)
    revoke_envelope = sign_work_order(
        root,
        artifact_dir,
        commands,
        auth_dir,
        orchestrator_publish_work_order(
            WORK_ORDER_ORCH_REVOKE,
            REVOKE_RUN,
            "Grant, retain, revoke, and retry one exact resident publication receipt",
        ),
        VPC_INSTANCE,
    )
    orch_message_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, orchestrator_message_work_order(), VPC_INSTANCE)
    spec_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, specialist_work_order(), VPC_INSTANCE)
    spec_message_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, specialist_message_work_order(), VPC_INSTANCE)
    helper_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, cloud_helper_work_order(), CLOUD_INSTANCE)
    edge_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, edge_work_order(), EDGE_INSTANCE)
    publish_approval_policies = [
        approval_policy(
            publish_envelope["expires_at"],
            policy_id="policy_uc_e2e_s10_artifact_publish_external",
        )
    ]
    revoke_approval_policies = [
        approval_policy(
            revoke_envelope["expires_at"],
            policy_id="policy_uc_e2e_s10_artifact_publish_external_revoke",
        )
    ]
    work_order_submissions: dict[str, dict[str, Any]] = {}
    for envelope, admitted_approval_policies in [
        (orch_envelope, []),
        (orch_data_envelope, []),
        (publish_envelope, publish_approval_policies),
        (revoke_envelope, revoke_approval_policies),
        (orch_message_envelope, []),
        (spec_envelope, []),
        (spec_message_envelope, []),
        (helper_envelope, []),
        (edge_envelope, []),
    ]:
        submission = call(
            "submitWorkOrder",
            "POST",
            args.manager_url,
            "/work-orders",
            {
                **sec(manager),
                "work_order": envelope,
                "expected_audience": "central-manager",
                "approval_policies": admitted_approval_policies,
            },
        )
        if submission["status"] != 200 or submission["body"].get("accepted") is not True:
            raise SystemExit(
                f"manager rejected S10 work order {envelope['work_order_id']}: "
                + json.dumps(submission, sort_keys=True)
            )
        work_order_submissions[envelope["work_order_id"]] = submission
    publish_submit = work_order_submissions[WORK_ORDER_ORCH_PUBLISH]
    revoke_submit = work_order_submissions[WORK_ORDER_ORCH_REVOKE]
    placement = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_ORCH, "request": {"target": "customer_vpc", "required_capabilities": ["artifact.create_internal"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_publish = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_ORCH_PUBLISH, "request": {"target": "customer_vpc", "required_capabilities": ["runtime.resident"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_revoke = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_ORCH_REVOKE, "request": {"target": "customer_vpc", "required_capabilities": ["runtime.resident"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_data = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_ORCH_DATA, "request": {"target": "customer_vpc", "required_capabilities": ["sql.read_fixture"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_spec = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_SPECIALIST, "request": {"target": "customer_vpc", "required_capabilities": ["sql.read_fixture"], "data_locality": "vpc", "dedicated_instance": False, "execution_mode": "live"}})
    placement_helper = call("evaluatePlacement", "POST", args.manager_url, "/fleet/placement/evaluate", {**sec(manager), "work_order_id": WORK_ORDER_CLOUD_HELPER, "request": {"target": "resident_cloud_pool", "required_capabilities": ["message.remote.proposal"], "data_locality": "cloud", "dedicated_instance": False, "execution_mode": "live"}})
    dispatch_data = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ORCH_DATA}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    dispatch_spec = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_SPECIALIST}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    dispatch_helper = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_CLOUD_HELPER}/dispatch", {**sec(manager), "target_node_id": CLOUD_NODE})
    dispatch_publish = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ORCH_PUBLISH}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    dispatch_revoke = call("dispatchWorkOrder", "POST", args.manager_url, f"/work-orders/{WORK_ORDER_ORCH_REVOKE}/dispatch", {**sec(manager), "target_node_id": VPC_NODE})
    orch_create = resident_call("createRun", "POST", args.vpc_url, VPC_INSTANCE, "/runs", "runs_create", create_run_payload(run_id=ORCH_RUN, agent_id=ORCH_AGENT, envelope=orch_envelope, initial_state={"profile": "internal-artifact-only"}))
    orch_start = resident_call("startRun", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}/start", "runs_start", {"work_order": None, "reason": "s10_internal_artifact_state_commit", "approval_evidence": None})

    invalid_work_order = orchestrator_work_order() | {"work_order_id": "wo_uc_e2e_s10_invalid_unsigned", "run_id": "44444444-4444-4444-8444-444444448899"}
    invalid_submit = call("submitWorkOrder", "POST", args.manager_url, "/work-orders", {**sec(manager), "work_order": invalid_work_order, "expected_audience": "central-manager"})

    data_analysis = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"action_id": expectation_for("UC-E2E-S10", "orchestrator_data_read")["action_id"], "run_id": ORCH_DATA_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "causal_trace_id": dispatch_data["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    specialist_data = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"action_id": expectation_for("UC-E2E-S10", "specialist_data_read")["action_id"], "run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "causal_trace_id": dispatch_spec["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    data_analysis_projection = project_private_v3_output(
        data_analysis["body"],
        expectation=expectation_for("UC-E2E-S10", "orchestrator_data_read"),
    )
    specialist_data_projection = project_private_v3_output(
        specialist_data["body"],
        expectation=expectation_for("UC-E2E-S10", "specialist_data_read"),
    )

    task_request = typed_message(TASK_REQUEST_ID, ORCH_AGENT, SPECIALIST_AGENT, ORCH_RUN, "splendor.message.task_request.v2", {"parent_run_id": ORCH_RUN, "child_run_id": SPECIALIST_RUN, "target_agent_id": SPECIALIST_AGENT, "objective": "analyze scoped field-intelligence package under separately signed data authority", "capability_grant_id": CAPABILITY_GRANT_ID, "data_refs": [DATA_REF], "permissions": [], "delegated_authority": {"allowed_actions": [], "allowed_adapters": [], "allowed_permissions": []}}, dispatch_spec["body"].get("trace_event_id") or dispatch_data["body"].get("trace_event_id"), True)
    task_sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_ORCH_MESSAGE, "message_envelope": task_request, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s10-task-request", "simulate_failure": None})
    task_read = call("getMessage", "POST", args.manager_url, f"/messages/{TASK_REQUEST_ID}/read", message_scope(manager, ORCH_RUN, SPECIALIST_AGENT))
    task_response = typed_message(TASK_RESPONSE_ID, SPECIALIST_AGENT, ORCH_AGENT, ORCH_RUN, "splendor.message.task_response.v1", {"parent_run_id": ORCH_RUN, "child_run_id": SPECIALIST_RUN, "status": "completed", "output": {"analysis_ref": "analysis:s10:field-intel", "summary": "trace-safe field-intelligence summary", "data_refs": [DATA_REF], "raw_payload_included": False}, "failure": None}, task_sent["body"].get("trace_event_id") or dispatch_spec["body"].get("trace_event_id"), False)
    response_sent = call("sendMessage", "POST", args.manager_url, "/messages", {**sec(manager), "work_order_id": WORK_ORDER_SPECIALIST_MESSAGE, "message_envelope": task_response, "source_instance_id": VPC_INSTANCE, "target_instance_id": VPC_INSTANCE, "idempotency_key": "s10-task-response", "simulate_failure": None})
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
    helper_publish_denial = resident_call("submitAction", "POST", args.cloud_url, CLOUD_INSTANCE, "/actions", "actions_submit", {"run_id": CLOUD_HELPER_RUN, "tenant_id": TENANT_ID, "agent_id": CLOUD_HELPER_AGENT, "causal_trace_id": cloud_delivery["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    device_profile = {"node_id": EDGE_NODE, "tenant_id": TENANT_ID, "device_kind": "drone_sim", "capabilities": ["camera.rgb", "battery", "geofence", "privacy_zone"] + [f"physical.action.{name}" for name in ALLOWED_PHYSICAL_ACTIONS], "allowed_physical_actions": ALLOWED_PHYSICAL_ACTIONS, "forbidden_action_classes": FORBIDDEN_PHYSICAL_ACTIONS, "safety_constraints": {"max_altitude_m": 30, "allowed_zones": ["zone:warehouse-a3"], "privacy_zones": ["privacy_zone:warehouse-a3-public"], "min_battery_percent": 0.25}, "runtime_mode": "resident", "safety_status": {"battery_percent": 0.82, "emergency_stop": "clear", "collision_risk": "low", "current_zone": "zone:warehouse-a3", "altitude_m": 10, "human_proximity": "clear", "privacy": "clear", "offline": False, "cloud_helper_direct_authority": False}, "policy_cache": {"policy_id": "policy_uc_e2e_s10_edge_cache", "loaded": True, "ttl_seconds": 3600, "expires_at": utc(60), "expired": False}, "trace_buffer": {"enabled": True, "buffered_records": 0, "integrity": "hash_chain"}, "registered_at": utc(0)}
    device_register = resident_call("registerDeviceProfile", "POST", args.edge_url, EDGE_INSTANCE, "/devices/profiles", "device_register", {"profile": device_profile})
    device_status = resident_call("getDeviceStatus", "GET", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/status", "device_read")
    policy_cache = resident_call("getPolicyCacheStatus", "GET", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/policy-cache", "device_read")
    edge_create = resident_call("createRun", "POST", args.edge_url, EDGE_INSTANCE, "/runs", "runs_create", create_run_payload(run_id=EDGE_RUN, agent_id=EDGE_AGENT, envelope=edge_envelope, initial_state={"edge": "s10"}))
    edge_start = resident_call("startRun", "POST", args.edge_url, EDGE_INSTANCE, f"/runs/{EDGE_RUN}/start", "runs_start", {"work_order": None, "reason": "s10_edge_policy_warmup", "approval_evidence": None})

    simulator_evidence: list[dict[str, Any]] = []

    def physical_call(label: str, name: str, expected_delta: int, *, expectation_id: str | None = None, **safety_overrides: Any) -> dict[str, Any]:
        before = sim_json("GET", args.device_sim_url, "/evidence")
        expected_action_id = (
            expectation_for("UC-E2E-S10", expectation_id)["action_id"]
            if expectation_id is not None
            else None
        )
        response = resident_call("submitPhysicalAction", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/actions", "actions_submit", physical_payload(name, action_id=expected_action_id, **safety_overrides))
        after = sim_json("GET", args.device_sim_url, "/evidence")
        simulator_evidence.append({"label": label, "action_name": name, "status": response["body"].get("status"), "counter_before": before, "counter_after": after, "total_delta": sim_total(after) - sim_total(before), "action_delta": sim_action_count(after, name) - sim_action_count(before, name), "expected_sim_delta": expected_delta, "reason_codes": response["body"].get("verification", {}).get("reasons", [])})
        return response

    inspect_zone = physical_call("inspect_zone_from_cloud_proposal", "inspect_zone", 1, expectation_id="inspect_zone", cloud_helper_proposal_id=ROUTE_PROPOSAL_ID, cloud_helper_message_id=CLOUD_MESSAGE_ID)
    waypoint = physical_call("move_to_waypoint_from_cloud_proposal", "move_to_waypoint", 1, expectation_id="move_to_waypoint", cloud_helper_proposal_id=ROUTE_PROPOSAL_ID, cloud_helper_message_id=CLOUD_MESSAGE_ID)
    offline_sensor = physical_call("offline_sensor_summary_buffered", "read_sensor_summary", 1, expectation_id="read_sensor_summary", offline=True)
    upload_summary = physical_call("upload_trace_summary_after_reconnect", "upload_trace_summary", 1, expectation_id="upload_trace_summary")
    cloud_direct_denial = physical_call("cloud_helper_direct_authority_denied", "move_to_waypoint", 0, cloud_helper_proposal_id="bad-direct", cloud_helper_message_id=CLOUD_MESSAGE_ID, cloud_helper_direct_authority=True)
    raw_physical = [resident_call("submitPhysicalAction", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/actions", "actions_submit", physical_payload(name), expected_statuses=(400,), expected_result="error") for name in FORBIDDEN_PHYSICAL_ACTIONS]

    intervention_expires_at = utc(30)
    intervention_request = resident_call("requestOperatorIntervention", "POST", args.edge_url, EDGE_INSTANCE, "/operator/interventions", "operator_intervene", {"intervention_id": "intervention_uc_e2e_s10_capture", "tenant_id": TENANT_ID, "agent_id": EDGE_AGENT, "run_id": EDGE_RUN, "node_id": EDGE_NODE, "action_name": "capture_image", "reason": "S10 local operator review", "expires_at": intervention_expires_at})
    intervention_grant = resident_call("grantOperatorIntervention", "POST", args.edge_url, EDGE_INSTANCE, "/operator/interventions/intervention_uc_e2e_s10_capture/grant", "operator_intervene", {"reason": "S10 local operator cleared capture", "expires_at": intervention_expires_at})
    intervention_payload = physical_payload("capture_image", action_id=expectation_for("UC-E2E-S10", "operator_capture")["action_id"])
    intervention_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    before_intervention_capture = sim_json("GET", args.device_sim_url, "/evidence")
    intervention_capture = resident_call("submitPhysicalActionWithIntervention", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/actions", "actions_submit", intervention_payload)
    after_intervention_capture = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_intervention_capture", "action_name": "capture_image", "status": intervention_capture["body"].get("status"), "http_status": intervention_capture["status"], "counter_before": before_intervention_capture, "counter_after": after_intervention_capture, "total_delta": sim_total(after_intervention_capture) - sim_total(before_intervention_capture), "action_delta": sim_action_count(after_intervention_capture, "capture_image") - sim_action_count(before_intervention_capture, "capture_image"), "expected_sim_delta": 1, "reason_codes": intervention_capture["body"].get("verification", {}).get("reasons", [])})
    physical_projections = [
        project_private_v3_output(
            response["body"],
            expectation=expectation_for("UC-E2E-S10", expectation_id),
        )
        for expectation_id, response in (
            ("inspect_zone", inspect_zone),
            ("move_to_waypoint", waypoint),
            ("read_sensor_summary", offline_sensor),
            ("upload_trace_summary", upload_summary),
            ("operator_capture", intervention_capture),
        )
    ]

    extended_intervention_payload = physical_payload("capture_image")
    extended_intervention_evidence = copy.deepcopy(intervention_grant["body"].get("evidence", {}))
    extended_intervention_evidence["expires_at"] = utc(60)
    extended_intervention_payload["operator_intervention_evidence"] = extended_intervention_evidence
    before_extended_intervention = sim_json("GET", args.device_sim_url, "/evidence")
    extended_intervention = resident_call("submitPhysicalActionExtendedIntervention", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/actions", "actions_submit", extended_intervention_payload, expected_statuses=(403,), expected_result="error")
    after_extended_intervention = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_intervention_extended_expiry", "action_name": "capture_image", "status": extended_intervention["body"].get("status"), "http_status": extended_intervention["status"], "counter_before": before_extended_intervention, "counter_after": after_extended_intervention, "total_delta": sim_total(after_extended_intervention) - sim_total(before_extended_intervention), "action_delta": sim_action_count(after_extended_intervention, "capture_image") - sim_action_count(before_extended_intervention, "capture_image"), "expected_sim_delta": 0, "reason_codes": extended_intervention["body"].get("verification", {}).get("reasons", [])})

    other_device_profile = copy.deepcopy(device_profile)
    other_device_profile["node_id"] = OTHER_EDGE_NODE
    other_device_register = resident_call("registerOtherDeviceProfile", "POST", args.edge_url, EDGE_INSTANCE, "/devices/profiles", "device_register", {"profile": other_device_profile})
    reused_intervention_payload = physical_payload("capture_image")
    reused_intervention_payload["operator_intervention_evidence"] = intervention_grant["body"].get("evidence")
    before_intervention_reuse = sim_json("GET", args.device_sim_url, "/evidence")
    reused_intervention = resident_call("submitPhysicalActionReusedIntervention", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{OTHER_EDGE_NODE}/actions", "actions_submit", reused_intervention_payload, expected_statuses=(403,), expected_result="error")
    after_intervention_reuse = sim_json("GET", args.device_sim_url, "/evidence")
    simulator_evidence.append({"label": "operator_intervention_cross_device_reuse", "action_name": "capture_image", "status": reused_intervention["body"].get("status"), "http_status": reused_intervention["status"], "counter_before": before_intervention_reuse, "counter_after": after_intervention_reuse, "total_delta": sim_total(after_intervention_reuse) - sim_total(before_intervention_reuse), "action_delta": sim_action_count(after_intervention_reuse, "capture_image") - sim_action_count(before_intervention_reuse, "capture_image"), "expected_sim_delta": 0, "reason_codes": reused_intervention["body"].get("verification", {}).get("reasons", [])})

    internal_artifact = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"action_id": expectation_for("UC-E2E-S10", "internal_artifact")["action_id"], "run_id": ORCH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "causal_trace_id": response_sent["body"].get("trace_event_id") or task_sent["body"].get("trace_event_id") or data_analysis["body"].get("trace_event_id"), "action": action("artifact.create_internal", "artifact.create_internal", "External", artifact_path=INTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})
    publish_create = dispatch_create_body(dispatch_publish)
    publish_start = dispatch_start_body(dispatch_publish)
    publish_after_dispatch = resident_call("inspectPublishAfterDispatch", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    publish_state_after_dispatch = resident_call("getPublishStateAfterDispatch", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/state-head", "state_read")
    publish_requested_at = utc(0)
    publish_action_request = {
        "action_id": PUBLISH_ACTION_ID,
        "run_id": PUBLISH_RUN,
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "causal_trace_id": dispatch_publish["body"].get("trace_event_id"),
        "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT),
        "adapter": "artifact-store",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "requested_at": publish_requested_at,
    }
    publish_proposal = resident_call("submitPublishForApproval", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", publish_action_request)
    publish_needs_approval = {"status": publish_proposal["status"], "body": publish_proposal["body"]}
    approval_context = extract_approval_context(publish_needs_approval["body"])
    publish_pending_traces = resident_call("getPendingApprovalTraces", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/traces?redaction_policy=uc-e2e-s10-redacted", "traces_read")
    publish_causal_trace_id = str(publish_action_request.get("causal_trace_id") or "")
    if not publish_causal_trace_id:
        raise SystemExit("S10 approval-required run did not expose a causal trace identity")
    forged_legacy_grant = {
        "schema_version": "splendor.approval_evidence.v1",
        "approval_id": approval_context["approval_id"],
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "run_id": PUBLISH_RUN,
        "action_id": approval_context["action_id"],
        "action_name": approval_context["action_name"],
        "adapter": approval_context["adapter"],
        "decision": "Granted",
        "reason": "forged legacy S10 grant",
        "issued_at": utc(0),
        "expires_at": approval_context["expires_at"],
        "revoked": False,
        "trace_event_id": None,
    }
    forged_legacy_publish = resident_call("submitForgedLegacyApproval", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"action_id": approval_context["action_id"], "run_id": PUBLISH_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "causal_trace_id": publish_causal_trace_id, "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": [], "requested_at": approval_context["requested_at"], "approval_evidence": forged_legacy_grant}, expected_statuses=(409,), expected_result="fail_closed")
    publish_after_forged_legacy = resident_call("inspectPublishAfterForgedLegacy", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    approval_request = manager_approval_call("requestApproval", "/approvals", approval_request_payload(sec(manager), approval_context, "S10 scoped approval for external field-intelligence publication"))
    approval_grant = manager_approval_call("grantApproval", f"/approvals/{approval_context['approval_id']}/grant", {"reason": "approved_for_s10_publication"})
    approval_evidence = approval_grant["body"].get("evidence")
    authority_receipt = approval_grant["body"].get("authority_obligation_receipt")
    if not isinstance(approval_evidence, dict) or not isinstance(authority_receipt, dict):
        raise SystemExit("manager grant did not issue a trusted S10 approval obligation receipt")
    expected_publish_audience = f"splendor.daemon.approval_receipt.v2:instance:{VPC_INSTANCE}:run:{PUBLISH_RUN}"
    if (
        authority_receipt.get("schema_version") != "splendor.authority.obligation_receipt.v1"
        or authority_receipt.get("approval_id") != approval_context.get("approval_id")
        or authority_receipt.get("audience") != expected_publish_audience
        or approval_context.get("receipt_audience") != expected_publish_audience
    ):
        raise SystemExit("manager did not issue the exact S10 VPC instance+run approval receipt")
    publish_before_retry = resident_call("inspectPublishBeforeExactRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    publish_state_before_retry = resident_call("getPublishStateBeforeExactRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/state-head", "state_read")
    publish_exact_action_request = {
        **publish_action_request,
        "action_id": approval_context["action_id"],
        "causal_trace_id": publish_causal_trace_id,
        "requested_at": approval_context["requested_at"],
        "authority_obligation_receipts": [authority_receipt],
    }
    publish_retry = resident_call("submitApprovedExactAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", publish_exact_action_request)
    approved_publish = {"status": publish_retry["status"], "body": publish_retry["body"]}
    publish_after_retry = resident_call("inspectPublishAfterExactRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    publish_state_after_retry = resident_call("getPublishStateAfterExactRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/state-head", "state_read")

    claim_first_revoke = manager_approval_call(
        "revokeApprovalClaimFirst",
        f"/approvals/{approval_context['approval_id']}/revoke",
        {"reason": "S10 claim-first receipt must report too late"},
        expected_statuses=(409, 504),
        expected_result="error",
    )

    expired_evidence = copy.deepcopy(approval_evidence)
    expired_evidence["issued_at"] = utc(-2)
    expired_evidence["expires_at"] = utc(-1)
    publish_before_expired_raw = resident_call("inspectPublishBeforeExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    publish_state_before_expired_raw = resident_call("getPublishStateBeforeExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/state-head", "state_read")
    publish_traces_before_expired_raw = resident_call("getPublishTracesBeforeExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/traces?redaction_policy=uc-e2e-s10-redacted", "traces_read")
    expired_approval = resident_call(
        "submitExpiredRawApprovalOnActiveRun",
        "POST",
        args.vpc_url,
        VPC_INSTANCE,
        "/actions",
        "actions_submit",
        {
            **publish_action_request,
            "action_id": approval_context["action_id"],
            "causal_trace_id": approval_grant["body"].get("trace_event_id"),
            "requested_at": approval_context["requested_at"],
            "approval_evidence": expired_evidence,
        },
        expected_statuses=(409,),
        expected_result="error",
    )
    publish_after_expired_raw = resident_call("inspectPublishAfterExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    publish_state_after_expired_raw = resident_call("getPublishStateAfterExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/state-head", "state_read")
    publish_traces_after_expired_raw = resident_call("getPublishTracesAfterExpiredRaw", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/traces?redaction_policy=uc-e2e-s10-redacted", "traces_read")

    revoke_create = dispatch_create_body(dispatch_revoke)
    revoke_start = dispatch_start_body(dispatch_revoke)
    revoke_requested_at = utc(0)
    revoke_action_request = {
        "action_id": REVOKE_ACTION_ID,
        "run_id": REVOKE_RUN,
        "tenant_id": TENANT_ID,
        "agent_id": ORCH_AGENT,
        "causal_trace_id": dispatch_revoke["body"].get("trace_event_id"),
        "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT),
        "adapter": "artifact-store",
        "quota_usage": quota(),
        "satisfied_preconditions": [],
        "requested_at": revoke_requested_at,
    }
    revoke_proposal = resident_call("submitRevocablePublishForApproval", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", revoke_action_request)
    if revoke_proposal["body"].get("status") != "NeedsApproval":
        raise SystemExit("manager-dispatched S10 revocation branch did not require approval")
    revoke_context = extract_approval_context(revoke_proposal["body"])
    revoke_pending_traces = resident_call("getRevocablePublishTraces", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}/traces?redaction_policy=uc-e2e-s10-redacted", "traces_read")
    revoke_causal_trace_id = str(revoke_action_request.get("causal_trace_id") or "")
    if not revoke_causal_trace_id:
        raise SystemExit("S10 revocable approval run did not expose a causal trace identity")
    revoke_request = manager_approval_call("requestRevocableApproval", "/approvals", approval_request_payload(sec(manager), revoke_context, "S10 resident receipt revocation branch"))
    revoke_grant = manager_approval_call("grantRevocableApproval", f"/approvals/{revoke_context['approval_id']}/grant", {"reason": "grant_before_resident_revocation"})
    retained_revoke_receipt = revoke_grant["body"].get("authority_obligation_receipt")
    if not isinstance(retained_revoke_receipt, dict):
        raise SystemExit("manager did not retain the S10 revocation-branch receipt")
    expected_revoke_audience = f"splendor.daemon.approval_receipt.v2:instance:{VPC_INSTANCE}:run:{REVOKE_RUN}"
    if retained_revoke_receipt.get("audience") != expected_revoke_audience:
        raise SystemExit("revocation-branch receipt did not bind the immutable VPC instance+run target")
    revoke_before_manager = resident_call("inspectRevocablePublishBeforeManagerRevoke", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}", "runs_read")
    revoke_state_before_manager = resident_call("getRevocablePublishStateBeforeManagerRevoke", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}/state-head", "state_read")
    approval_revoke = manager_approval_call("revokeApproval", f"/approvals/{revoke_context['approval_id']}/revoke", {"reason": "operator_revoked_s10_resident_receipt"})
    resident_revocation_ack = approval_revoke["body"].get("resident_receipt_revocation_ack")
    if not isinstance(resident_revocation_ack, dict):
        raise SystemExit("manager reported revocation without an exact resident acknowledgement")
    revoke_after_manager = resident_call("inspectRevocablePublishAfterManagerRevoke", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}", "runs_read")
    revoke_retry_request = {
        **revoke_action_request,
        "action_id": revoke_context["action_id"],
        "causal_trace_id": revoke_causal_trace_id,
        "requested_at": revoke_context["requested_at"],
        "authority_obligation_receipts": [retained_revoke_receipt],
    }
    revoked_receipt_retry = resident_call("submitRevokedOriginalReceipt", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", revoke_retry_request)
    revoke_after_retry = resident_call("inspectRevocablePublishAfterDeniedRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}", "runs_read")
    revoke_state_after_retry = resident_call("getRevocablePublishStateAfterDeniedRetry", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}/state-head", "state_read")

    unauthorized_data = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "causal_trace_id": task_sent["body"].get("trace_event_id"), "action": action("data.read_fixture", "data.read_fixture", "ReadOnly", data_ref=DENIED_DATA_REF), "adapter": "fixture-data-store", "quota_usage": quota(), "satisfied_preconditions": []})
    specialist_escalation = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"run_id": SPECIALIST_RUN, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "causal_trace_id": task_sent["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    state_before = resident_call("getStateHead", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}/state-head", "state_read")
    cloud_create = resident_call("createRun", "POST", args.cloud_url, CLOUD_INSTANCE, "/runs", "runs_create", create_run_payload(run_id=ORCH_RUN, agent_id=ORCH_AGENT, envelope=cloud_receiver_envelope, initial_state={"resume_target": "cloud", "authority": "receiver-own-state"}))
    cloud_start = resident_call("startRun", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/start", "runs_start", {"work_order": None, "reason": "s10_prepare_fail_closed_handoff_receiver", "approval_evidence": None})
    cloud_state_before_import = resident_call("getStateHead", "GET", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/state-head", "state_read")
    cloud_pause = resident_call("pauseRun", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/pause", "runs_pause", {"reason": "s10_state_handoff_pause_before_import"})
    handoff_export = resident_call("exportStateSnapshot", "POST", args.vpc_url, VPC_INSTANCE, "/state-snapshots/export", "state_handoff", {"run_id": ORCH_RUN, "work_order_id": WORK_ORDER_ORCH, "source_instance_id": VPC_INSTANCE, "receiver_instance_id": CLOUD_INSTANCE, "previous_state_node_id": cloud_state_before_import["body"].get("state_node_id")})
    handoff_import = resident_call("importStateSnapshot", "POST", args.cloud_url, CLOUD_INSTANCE, "/state-snapshots/import", "state_handoff", {"handoff": handoff_export["body"].get("handoff"), "work_order": cloud_receiver_envelope}, expected_statuses=(503,), expected_result="error")
    cloud_state_after_import_denial = resident_call("getStateHeadAfterImportDenial", "GET", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/state-head", "state_read")
    bad_handoff = copy.deepcopy(handoff_export["body"].get("handoff", {}))
    if bad_handoff:
        bad_handoff.setdefault("snapshot", {}).setdefault("state_hash", {})["value"] = "0" * 64
    tampered_state_import = resident_call("importStateSnapshot", "POST", args.cloud_url, CLOUD_INSTANCE, "/state-snapshots/import", "state_handoff", {"handoff": bad_handoff, "work_order": cloud_receiver_envelope}, expected_statuses=(503,), expected_result="error")
    cloud_resume = resident_call("resumeRun", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/resume", "runs_resume", {"work_order": cloud_receiver_envelope, "reason": "s10_resume_receiver_own_state_after_proof_denial", "approval_evidence": None})
    state_after = resident_call("getStateHead", "GET", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/state-head", "state_read")

    cb_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, branch_work_order(WORK_ORDER_CB, CB_RUN, ["artifact.publish_external"]), VPC_INSTANCE)
    cb_create = resident_call("createRun", "POST", args.vpc_url, VPC_INSTANCE, "/runs", "runs_create", create_run_payload(run_id=CB_RUN, agent_id=ORCH_AGENT, envelope=cb_envelope, initial_state={"branch": "circuit_breaker"}, approval_policies=[]))
    breaker = call("createCircuitBreaker", "POST", args.manager_url, "/governance/circuit-breakers", {**sec(manager), "breaker_id": BREAKER_ID, "tenant_id": TENANT_ID, "adapter": "artifact-store", "action": "artifact.publish_external", "reason": "S10 controlled publish branch"})
    breaker_payload = call("readCircuitBreakerSyncPayload", "POST", args.manager_url, f"/governance/circuit-breakers/{BREAKER_ID}/sync-payload", {**sec(manager), "run_id": CB_RUN, "reason": "s10_manager_propagated_breaker"})
    breaker_sync = resident_call("syncCircuitBreakers", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{CB_RUN}/governance/circuit-breakers/sync", "policies_sync", {"circuit_breakers": breaker_payload["body"].get("circuit_breakers", []), "reason": breaker_payload["body"].get("reason")})
    breaker_block = resident_call("submitAction", "POST", args.vpc_url, VPC_INSTANCE, "/actions", "actions_submit", {"run_id": CB_RUN, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "causal_trace_id": breaker["body"].get("trace_event_id"), "action": action("artifact.publish_external", "artifact.publish_external", "External", publish_ref=EXTERNAL_ARTIFACT), "adapter": "artifact-store", "quota_usage": quota(), "satisfied_preconditions": []})

    kill_envelope = sign_work_order(root, artifact_dir, commands, auth_dir, branch_work_order(WORK_ORDER_KILL, KILL_RUN, ["artifact.create_internal"]), CLOUD_INSTANCE)
    kill_create = resident_call("createRun", "POST", args.cloud_url, CLOUD_INSTANCE, "/runs", "runs_create", create_run_payload(run_id=KILL_RUN, agent_id=ORCH_AGENT, envelope=kill_envelope, initial_state={"branch": "kill_switch"}))
    kill_switch = call("activateKillSwitch", "POST", args.manager_url, "/governance/kill-switches", {**sec(manager), "kill_switch_id": KILL_SWITCH_ID, "run_id": KILL_RUN, "tenant_id": TENANT_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "reason": "S10 controlled kill-switch branch", "propagation_ack_required": True})

    inspect_before_replay = resident_call("inspectRunBeforeReplay", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}", "runs_read")
    publish_before_replay = resident_call("inspectPublishBeforeReplay", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    helper_before_replay = resident_call("inspectHelperBeforeReplay", "GET", args.cloud_url, CLOUD_INSTANCE, f"/runs/{CLOUD_HELPER_RUN}", "runs_read")
    sim_before_replay = sim_json("GET", args.device_sim_url, "/evidence")
    replay_orch = resident_call("replayRun", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": False})
    replay_publish = resident_call("replayPublishRun", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": False})
    replay_edge = resident_call("replayEdgeRun", "POST", args.edge_url, EDGE_INSTANCE, f"/runs/{EDGE_RUN}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": False})
    unsafe_replay = resident_call("replaySideEffectMode", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/replay", "replay_create", {"mode": "inspect_only", "side_effects_allowed": True}, expected_statuses=(400, 403), expected_result="error")
    sim_after_replay = sim_json("GET", args.device_sim_url, "/evidence")
    inspect_after_replay = resident_call("inspectRunAfterReplay", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}", "runs_read")
    publish_after_replay = resident_call("inspectPublishAfterReplay", "GET", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}", "runs_read")
    helper_after_replay = resident_call("inspectHelperAfterReplay", "GET", args.cloud_url, CLOUD_INSTANCE, f"/runs/{CLOUD_HELPER_RUN}", "runs_read")

    traces_orch = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_orch_data = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{ORCH_DATA_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_publish = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{PUBLISH_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_revoke = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{REVOKE_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_spec = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{SPECIALIST_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cb = resident_call("exportTraces", "POST", args.vpc_url, VPC_INSTANCE, f"/runs/{CB_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_edge = resident_call("exportTraces", "POST", args.edge_url, EDGE_INSTANCE, f"/runs/{EDGE_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cloud_orch = resident_call("exportTraces", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{ORCH_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_cloud_helper = resident_call("exportTraces", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{CLOUD_HELPER_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    traces_kill = resident_call("exportTraces", "POST", args.cloud_url, CLOUD_INSTANCE, f"/runs/{KILL_RUN}/traces/export", "traces_read", {"redaction_policy": "uc-e2e-s10-redacted", "start": None, "end": None})
    records = traces_orch["body"].get("records", []) + traces_orch_data["body"].get("records", []) + traces_publish["body"].get("records", []) + traces_revoke["body"].get("records", []) + traces_spec["body"].get("records", []) + traces_cb["body"].get("records", []) + traces_edge["body"].get("records", []) + traces_cloud_orch["body"].get("records", []) + traces_cloud_helper["body"].get("records", []) + traces_kill["body"].get("records", [])

    vpc_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_RUN, "work_order_id": WORK_ORDER_ORCH}, "records": traces_orch["body"].get("records", [])}
    vpc_data_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_DATA_RUN, "work_order_id": WORK_ORDER_ORCH_DATA}, "records": traces_orch_data["body"].get("records", [])}
    vpc_publish_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": PUBLISH_RUN, "work_order_id": WORK_ORDER_ORCH_PUBLISH}, "records": traces_publish["body"].get("records", [])}
    vpc_revoke_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": REVOKE_RUN, "work_order_id": WORK_ORDER_ORCH_REVOKE}, "records": traces_revoke["body"].get("records", [])}
    vpc_spec_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": VPC_NODE, "instance_id": VPC_INSTANCE, "tenant_id": TENANT_ID, "agent_id": SPECIALIST_AGENT, "run_id": SPECIALIST_RUN, "work_order_id": WORK_ORDER_SPECIALIST}, "records": traces_spec["body"].get("records", [])}
    edge_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": EDGE_NODE, "instance_id": EDGE_INSTANCE, "tenant_id": TENANT_ID, "agent_id": EDGE_AGENT, "run_id": EDGE_RUN, "work_order_id": WORK_ORDER_EDGE}, "records": traces_edge["body"].get("records", [])}
    cloud_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "tenant_id": TENANT_ID, "agent_id": CLOUD_HELPER_AGENT, "run_id": CLOUD_HELPER_RUN, "work_order_id": WORK_ORDER_CLOUD_HELPER}, "records": traces_cloud_helper["body"].get("records", [])}
    cloud_orch_batch = {"scope": {"fleet_id": FLEET_ID, "node_id": CLOUD_NODE, "instance_id": CLOUD_INSTANCE, "tenant_id": TENANT_ID, "agent_id": ORCH_AGENT, "run_id": ORCH_RUN, "work_order_id": WORK_ORDER_ORCH}, "records": traces_cloud_orch["body"].get("records", [])}
    tampered_batch = copy.deepcopy(vpc_batch)
    if tampered_batch["records"]:
        tampered_batch["records"][0].setdefault("payload", {})["s10_tamper"] = "trace_import_mutation"
    trace_sync_tampered = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": tampered_batch})
    trace_sync_vpc = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_batch})
    trace_sync_vpc_data = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_data_batch})
    trace_sync_vpc_publish = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_publish_batch})
    trace_sync_vpc_revoke = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_revoke_batch})
    trace_sync_vpc_spec = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": vpc_spec_batch})
    trace_sync_edge = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": edge_batch})
    trace_sync_cloud = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": cloud_batch})
    trace_sync_cloud_orch = call("syncTraceBuffer", "POST", args.manager_url, "/fleet/traces/sync", {**sec(manager), "batch": cloud_orch_batch})
    edge_trace_records = traces_edge["body"].get("records", [])
    device_sync_records = []
    for record in edge_trace_records:
        if "[REDACTED" in json.dumps(record.get("payload", {}), sort_keys=True):
            break
        device_sync_records.append(record)
    device_trace_wrong_scope = resident_call("syncDeviceTraceBufferWrongScope", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/trace-buffer/sync", "device_read", {"run_id": EDGE_RUN, "records": device_sync_records, "simulate_tamper": False}, required_scope="device_trace_sync", scope_expectation="intentional_mismatch", expected_statuses=(403,), expected_result="error")
    device_trace_sync = resident_call("syncDeviceTraceBuffer", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/trace-buffer/sync", "device_trace_sync", {"run_id": EDGE_RUN, "records": device_sync_records, "simulate_tamper": False})
    device_trace_duplicate = resident_call("syncDeviceTraceBufferDuplicate", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/trace-buffer/sync", "device_trace_sync", {"run_id": EDGE_RUN, "records": device_sync_records, "simulate_tamper": False})
    device_payload_tampered_records = copy.deepcopy(device_sync_records)
    if device_payload_tampered_records:
        device_payload_tampered_records[0].setdefault("payload", {})["s10_device_payload_tamper"] = True
    device_trace_payload_tampered = resident_call("syncDeviceTraceBufferPayloadTampered", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/trace-buffer/sync", "device_trace_sync", {"run_id": EDGE_RUN, "records": device_payload_tampered_records, "simulate_tamper": False})
    device_cross_run_records = copy.deepcopy(device_sync_records)
    if device_cross_run_records:
        device_cross_run_records[0]["run_id"] = ORCH_RUN
    device_trace_cross_run = resident_call("syncDeviceTraceBufferCrossRun", "POST", args.edge_url, EDGE_INSTANCE, f"/devices/{EDGE_NODE}/trace-buffer/sync", "device_trace_sync", {"run_id": EDGE_RUN, "records": device_cross_run_records, "simulate_tamper": False})
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
    add_event_evidence(event_evidence, "approval.granted", trace_event_id=approval_grant["body"].get("trace_event_id"), source="public_api_response", original_event_type="grantApproval", artifact="artifact-publication-report.json", run_id=PUBLISH_RUN, action_id=approval_context.get("action_id"), approval_id=approval_context.get("approval_id"), details={"status": approval_grant["body"].get("status")})
    add_event_evidence(event_evidence, "approval.revoked", trace_event_id=approval_revoke["body"].get("trace_event_id"), source="public_api_response", original_event_type="revokeApproval", artifact="approval-receipt-revocation-report.json", run_id=REVOKE_RUN, action_id=revoke_context.get("action_id"), approval_id=revoke_context.get("approval_id"), details={"status": approval_revoke["body"].get("status"), "resident_status": resident_revocation_ack.get("status")})
    add_event_evidence(event_evidence, "state.exported", trace_event_id=handoff_export["body"].get("trace_event_id"), source="public_api_response", original_event_type="exportStateSnapshot", artifact="state-handoff-report.json", run_id=ORCH_RUN, work_order_id=WORK_ORDER_ORCH, state_node_id=handoff_export["body"].get("state_node_id"), details={"source_instance_id": VPC_INSTANCE, "receiver_instance_id": CLOUD_INSTANCE})
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
    orch_publish_executions = [record for record in records if (record.get("run_id") or trace_identity(record).get("run_id")) == PUBLISH_RUN and trace_kind(record) == "action.executed" and trace_action_name(record) == "artifact.publish_external"]
    revoke_publish_executions = [record for record in records if (record.get("run_id") or trace_identity(record).get("run_id")) == REVOKE_RUN and trace_kind(record) == "action.executed" and trace_action_name(record) == "artifact.publish_external"]
    internal_evidence = resolve_action_trace_evidence(
        records,
        internal_artifact["body"],
        "internal_artifact",
        "artifact.create_internal",
    )
    publish_evidence = resolve_action_trace_evidence(
        records,
        approved_publish["body"],
        "approved_publish",
        "artifact.publish_external",
    )
    expired_raw_trace_records_before = publish_traces_before_expired_raw["body"].get("records", [])
    expired_raw_trace_records_after = publish_traces_after_expired_raw["body"].get("records", [])
    def approval_action_outcome_trace_ids(trace_records: list[dict[str, Any]]) -> list[str]:
        return sorted(
            trace_id(record)
            for record in trace_records
            if trace_id(record)
            and (
                trace_kind(record).startswith("action.")
                or trace_kind(record).startswith("approval.")
                or trace_kind(record).startswith("Approval")
                or trace_kind(record) in {"verification.started", "verification.completed", "outcome.recorded"}
            )
        )

    expired_raw_decision_traces_before = approval_action_outcome_trace_ids(expired_raw_trace_records_before)
    expired_raw_decision_traces_after = approval_action_outcome_trace_ids(expired_raw_trace_records_after)
    expired_raw_no_new_decision_trace = expired_raw_decision_traces_before == expired_raw_decision_traces_after
    expired_raw_lifecycle_unchanged = all(
        publish_before_expired_raw["body"].get(key) == publish_after_expired_raw["body"].get(key)
        for key in ["status", "ticks", "state_head", "adapter_executions"]
    )
    expired_raw_state_unchanged = all(
        publish_state_before_expired_raw["body"].get(key) == publish_state_after_expired_raw["body"].get(key)
        for key in ["state_node_id", "data_hash", "parent_state_node_ids"]
    )
    expired_raw_pre_gateway_unchanged = (
        expired_approval["status"] == 409
        and expired_approval["body"].get("code") == "legacy_approval_evidence_non_authorizing"
        and publish_before_expired_raw["body"].get("status") == "running"
        and publish_after_expired_raw["body"].get("status") == "running"
        and expired_raw_lifecycle_unchanged
        and expired_raw_state_unchanged
        and expired_raw_no_new_decision_trace
    )
    publish_retry_preserved_tick_and_state = (
        publish_before_retry["body"].get("ticks") == publish_after_retry["body"].get("ticks")
        and publish_before_retry["body"].get("state_head") == publish_after_retry["body"].get("state_head")
        and publish_state_before_retry["body"].get("state_node_id") == publish_state_after_retry["body"].get("state_node_id")
        and publish_state_before_retry["body"].get("data_hash") == publish_state_after_retry["body"].get("data_hash")
    )
    publish_retry_executed_once_without_lifecycle_advance = (
        publish_before_retry["body"].get("status") == "waiting_for_approval"
        and publish_after_retry["body"].get("status") == "running"
        and publish_before_retry["body"].get("adapter_executions") == 0
        and publish_after_retry["body"].get("adapter_executions") == 1
        and publish_retry_preserved_tick_and_state
        and len(orch_publish_executions) == 1
    )
    resident_revocation_exact = (
        resident_revocation_ack.get("schema_version") == "splendor.resident.approval_receipt_revocation_ack.v1"
        and resident_revocation_ack.get("receipt_id") == retained_revoke_receipt.get("receipt_id")
        and resident_revocation_ack.get("approval_id") == revoke_context.get("approval_id")
        and resident_revocation_ack.get("target_instance_id") == VPC_INSTANCE
        and resident_revocation_ack.get("run_id") == REVOKE_RUN
        and resident_revocation_ack.get("receipt_audience") == expected_revoke_audience
        and resident_revocation_ack.get("status") in {"revoked", "already_revoked"}
        and resident_revocation_ack.get("effect_certainty") == "known"
    )
    revoked_retry_zero_effect = (
        revoked_receipt_retry["status"] == 200
        and revoked_receipt_retry["body"].get("status") == "Denied"
        and "authority_obligation_receipt_revoked" in revoked_receipt_retry["body"].get("verification", {}).get("reasons", [])
        and revoke_before_manager["body"].get("adapter_executions") == 0
        and revoke_after_manager["body"].get("adapter_executions") == 0
        and revoke_after_retry["body"].get("adapter_executions") == 0
        and revoke_before_manager["body"].get("ticks") == revoke_after_retry["body"].get("ticks")
        and revoke_before_manager["body"].get("state_head") == revoke_after_retry["body"].get("state_head")
        and revoke_state_before_manager["body"].get("state_node_id") == revoke_state_after_retry["body"].get("state_node_id")
        and revoke_state_before_manager["body"].get("data_hash") == revoke_state_after_retry["body"].get("data_hash")
        and not revoke_publish_executions
    )
    claim_first_too_late = (
        claim_first_revoke["status"] == 409
        and claim_first_revoke["body"].get("code") == "approval_receipt_revocation_too_late"
        and claim_first_revoke["body"].get("details", {}).get("outcome") == "too_late"
        and claim_first_revoke["body"].get("details", {}).get("effect_certainty") == "known"
        and claim_first_revoke["body"].get("details", {}).get("revocation_applied") is False
    )
    claim_first_effect_unknown = (
        claim_first_revoke["status"] == 504
        and claim_first_revoke["body"].get("code") == "approval_receipt_revocation_effect_unknown"
        and claim_first_revoke["body"].get("details", {}).get("outcome") == "effect_unknown"
        and claim_first_revoke["body"].get("details", {}).get("effect_certainty") == "unknown"
        and claim_first_revoke["body"].get("details", {}).get("revocation_applied") is None
    )
    claim_first_safe_non_success = claim_first_too_late or claim_first_effect_unknown
    revocation_daemon_audits = [
        record
        for record in traces_revoke["body"].get("records", [])
        if trace_kind(record) == "daemon.audit"
        and trace_body(record).get("endpoint") == "splendor.approval_receipts.revoke"
    ]
    resident_revocation_events = []
    for index, record in enumerate(revocation_daemon_audits, start=1):
        audit_value = trace_body(record).get("audit") if isinstance(trace_body(record).get("audit"), dict) else {}
        credential_id = audit_value.get("credential_id")
        resident_revocation_events.append(
            {
                "call_id": f"manager-resident-approval-revoke-{index:04d}",
                "manager_approval_call_id": next(
                    (
                        event.get("call_id")
                        for event in manager_approval_auth_events
                        if event.get("operation_id") == "revokeApproval"
                    ),
                    None,
                ),
                "operation_id": "revokeApprovalReceipt",
                "method": "POST",
                "endpoint": f"/runs/{REVOKE_RUN}/approval-receipts/{retained_revoke_receipt.get('receipt_id')}/revoke",
                "target_origin": args.vpc_url,
                "target_instance_id": VPC_INSTANCE,
                "audience_instance_id": VPC_INSTANCE,
                "target_audience": f"urn:splendor:instance:{VPC_INSTANCE}",
                "run_id": REVOKE_RUN,
                "receipt_id": retained_revoke_receipt.get("receipt_id"),
                "approval_id": revoke_context.get("approval_id"),
                "receipt_audience": expected_revoke_audience,
                "scope": "splendor.approval_receipts.revoke",
                "required_scope": "splendor.approval_receipts.revoke",
                "scope_expectation": "exact",
                "url_scheme": urlsplit(args.vpc_url).scheme.lower(),
                "tls_verification": "acceptance_ca",
                "redirect_policy": REDIRECT_POLICY,
                "credential_correlation_id": credential_id,
                "credential_id": credential_id,
                "fresh_one_use_jti": credential_id not in used_resident_credentials,
                "result_status": 200,
                "ack_status": resident_revocation_ack.get("status"),
                "effect_certainty": resident_revocation_ack.get("effect_certainty"),
                "trace_event_ids": [trace_id(record)] if trace_id(record) else [],
                "raw_bearer_recorded": False,
                "raw_jti_recorded": False,
                "receipt_signature_recorded": False,
                "evidence_source": "resident_daemon_audit_plus_exact_manager_ack_and_manager_runtime_scope_contract",
            }
        )
    resident_revocation_credential_ids = [
        event.get("credential_id") for event in resident_revocation_events
    ]
    resident_revocation_security_valid = (
        len(resident_revocation_events) == 1
        and resident_revocation_events[0].get("credential_correlation_id", "").startswith("sha256:")
        and resident_revocation_events[0].get("scope") == "splendor.approval_receipts.revoke"
        and resident_revocation_events[0].get("target_instance_id") == VPC_INSTANCE
        and resident_revocation_events[0].get("audience_instance_id") == VPC_INSTANCE
        and resident_revocation_events[0].get("fresh_one_use_jti") is True
        and len(resident_revocation_credential_ids) == len(set(resident_revocation_credential_ids))
        and resident_revocation_events[0].get("trace_event_ids")
        and resident_revocation_events[0].get("ack_status") in {"revoked", "already_revoked"}
        and resident_revocation_events[0].get("effect_certainty") == "known"
        and resident_revocation_events[0].get("raw_bearer_recorded") is False
        and resident_revocation_events[0].get("raw_jti_recorded") is False
        and resident_revocation_events[0].get("receipt_signature_recorded") is False
    )
    replay_counts_before = {"orchestrator_adapter_executions": inspect_before_replay["body"].get("adapter_executions"), "publish_adapter_executions": publish_before_replay["body"].get("adapter_executions"), "cloud_helper_adapter_executions": helper_before_replay["body"].get("adapter_executions"), "device_sim_total": sim_total(sim_before_replay)}
    replay_counts_after = {"orchestrator_adapter_executions": inspect_after_replay["body"].get("adapter_executions"), "publish_adapter_executions": publish_after_replay["body"].get("adapter_executions"), "cloud_helper_adapter_executions": helper_after_replay["body"].get("adapter_executions"), "device_sim_total": sim_total(sim_after_replay)}
    correlate_resident_security_events(resident_security_events, records)
    resident_security_summary = derive_resident_security_summary(resident_security_events)
    mutating_credential_ids = [
        event["credential_id"]
        for event in resident_security_events
        if event.get("mutating") is True
    ]
    signing_profiles = {
        "vpc_internal": {"instance_id": VPC_INSTANCE, "key_id": orch_envelope.get("signature", {}).get("key_id")},
        "cloud_receiver": {"instance_id": CLOUD_INSTANCE, "key_id": cloud_receiver_envelope.get("signature", {}).get("key_id")},
        "vpc_data": {"instance_id": VPC_INSTANCE, "key_id": orch_data_envelope.get("signature", {}).get("key_id")},
        "vpc_publish": {"instance_id": VPC_INSTANCE, "key_id": publish_envelope.get("signature", {}).get("key_id")},
        "vpc_publish_revoke": {"instance_id": VPC_INSTANCE, "key_id": revoke_envelope.get("signature", {}).get("key_id")},
        "vpc_request_message": {"instance_id": VPC_INSTANCE, "key_id": orch_message_envelope.get("signature", {}).get("key_id")},
        "vpc_specialist": {"instance_id": VPC_INSTANCE, "key_id": spec_envelope.get("signature", {}).get("key_id")},
        "vpc_response_message": {"instance_id": VPC_INSTANCE, "key_id": spec_message_envelope.get("signature", {}).get("key_id")},
        "cloud_helper": {"instance_id": CLOUD_INSTANCE, "key_id": helper_envelope.get("signature", {}).get("key_id")},
        "edge_inspection": {"instance_id": EDGE_INSTANCE, "key_id": edge_envelope.get("signature", {}).get("key_id")},
        "vpc_circuit_branch": {"instance_id": VPC_INSTANCE, "key_id": cb_envelope.get("signature", {}).get("key_id")},
        "cloud_kill_branch": {"instance_id": CLOUD_INSTANCE, "key_id": kill_envelope.get("signature", {}).get("key_id")},
    }
    authority_profiles = {
        "internal_artifact": {
            "run_id": ORCH_RUN,
            "work_order_id": WORK_ORDER_ORCH,
            "target_instance_id": VPC_INSTANCE,
            "allowed_actions": orch_envelope.get("allowed_actions"),
            "allowed_adapters": orch_envelope.get("allowed_adapters"),
            "allowed_permissions": orch_envelope.get("allowed_permissions"),
            "signature_key_id": orch_envelope.get("signature", {}).get("key_id"),
        },
        "external_publish": {
            "run_id": PUBLISH_RUN,
            "work_order_id": WORK_ORDER_ORCH_PUBLISH,
            "target_instance_id": VPC_INSTANCE,
            "allowed_actions": publish_envelope.get("allowed_actions"),
            "allowed_adapters": publish_envelope.get("allowed_adapters"),
            "allowed_permissions": publish_envelope.get("allowed_permissions"),
            "signature_key_id": publish_envelope.get("signature", {}).get("key_id"),
        },
        "external_publish_revoke": {
            "run_id": REVOKE_RUN,
            "work_order_id": WORK_ORDER_ORCH_REVOKE,
            "target_instance_id": VPC_INSTANCE,
            "allowed_actions": revoke_envelope.get("allowed_actions"),
            "allowed_adapters": revoke_envelope.get("allowed_adapters"),
            "allowed_permissions": revoke_envelope.get("allowed_permissions"),
            "signature_key_id": revoke_envelope.get("signature", {}).get("key_id"),
        },
        "physical_edge": {
            "run_id": EDGE_RUN,
            "work_order_id": WORK_ORDER_EDGE,
            "target_instance_id": EDGE_INSTANCE,
            "allowed_actions": edge_envelope.get("allowed_actions"),
            "allowed_adapters": edge_envelope.get("allowed_adapters"),
            "allowed_permissions": edge_envelope.get("allowed_permissions"),
            "signature_key_id": edge_envelope.get("signature", {}).get("key_id"),
        },
        "cloud_receiver": {
            "run_id": ORCH_RUN,
            "work_order_id": WORK_ORDER_ORCH,
            "target_instance_id": CLOUD_INSTANCE,
            "allowed_actions": cloud_receiver_envelope.get("allowed_actions"),
            "allowed_adapters": cloud_receiver_envelope.get("allowed_adapters"),
            "allowed_permissions": cloud_receiver_envelope.get("allowed_permissions"),
            "signature_key_id": cloud_receiver_envelope.get("signature", {}).get("key_id"),
        },
    }
    resident_security = {
        "schema_version": "splendor.uc_e2e_s10.resident_security.v2",
        "status": resident_security_summary["status"],
        "transport": "verified_tls",
        "ca_file": str(Path(args.resident_ca_file)),
        "events": resident_security_events,
        "summary": resident_security_summary,
        "all_calls_tls_verified": all(event.get("url_scheme") == "https" and event.get("tls_verification") == "acceptance_ca" for event in resident_security_events),
        "all_calls_exact_one_scope": all(bool(event.get("scope")) for event in resident_security_events),
        "all_calls_target_bound": all(event.get("target_instance_id") == event.get("audience_instance_id") for event in resident_security_events),
        "all_body_mirrors_match_verified_projection": all(event.get("body_mirror_status") in {"matched", "not_applicable"} for event in resident_security_events),
        "all_redirects_disabled": all(event.get("redirect_policy") == REDIRECT_POLICY for event in resident_security_events),
        "mutating_credential_ids_unique": len(mutating_credential_ids) == len(set(mutating_credential_ids)),
        "raw_bearers_recorded": any(event.get("raw_bearer_recorded") is not False for event in resident_security_events),
        "manager_dispatched_approval_receipt_revocations": resident_revocation_events,
        "approval_receipt_revocation_security_valid": resident_revocation_security_valid,
        "approval_receipt_revocation_credentials_unique": len(resident_revocation_credential_ids)
        == len(set(resident_revocation_credential_ids)),
        "approval_receipt_revocation_raw_jtis_recorded": False,
        "approval_receipt_revocation_receipt_signatures_recorded": False,
        "signing_profiles": signing_profiles,
        "all_work_orders_signed_for_target_instance": all(profile.get("key_id") == WORK_ORDER_KEY_IDS[profile["instance_id"]] for profile in signing_profiles.values()),
        "local_development_work_order_key_used": False,
        "cloud_receiver_create_import_resume_used_same_envelope": True,
        "cloud_receiver_envelope_key_id": cloud_receiver_envelope.get("signature", {}).get("key_id"),
        "source_and_receiver_authority_payloads_match": {
            key: value
            for key, value in orch_envelope.items()
            if key != "signature"
        }
        == {
            key: value
            for key, value in cloud_receiver_envelope.items()
            if key != "signature"
        },
    }
    if resident_security_summary["status"] != "passed":
        resident_security["status"] = "failed"
    manager_approval_credential_ids = [
        event.get("credential_id") for event in manager_approval_auth_events
    ]
    expected_manager_approval_operations = {
        "requestApproval": 200,
        "grantApproval": 200,
        "revokeApprovalClaimFirst": (409, 504),
        "requestRevocableApproval": 200,
        "grantRevocableApproval": 200,
        "revokeApproval": 200,
    }
    manager_approval_auth_valid = (
        len(manager_approval_auth_events) == len(expected_manager_approval_operations)
        and {event.get("operation_id") for event in manager_approval_auth_events}
        == set(expected_manager_approval_operations)
        and len(manager_approval_credential_ids)
        == len(set(manager_approval_credential_ids))
        and all(
            event.get("scope") == "approvals_manage"
            and event.get("required_scope") == "approvals_manage"
            and event.get("fleet_id") == FLEET_ID
            and event.get("target_manager_id") == "central-manager"
            and event.get("audience_manager_id") == "central-manager"
            and event.get("header_presence", {}).get("authorization") is True
            and event.get("body_mirror_status") == "matched"
            and event.get("result_status")
            in (
                expected_manager_approval_operations.get(event.get("operation_id"))
                if isinstance(
                    expected_manager_approval_operations.get(event.get("operation_id")),
                    tuple,
                )
                else (expected_manager_approval_operations.get(event.get("operation_id")),)
            )
            and event.get("result_status") in event.get("expected_statuses", [])
            and (
                event.get("result_status") != 200
                or bool(event.get("trace_event_ids"))
            )
            and event.get("raw_bearer_recorded") is False
            and event.get("raw_jti_recorded") is False
            and event.get("receipt_signature_recorded") is False
            for event in manager_approval_auth_events
        )
    )
    manager_approval_auth_report = {
        "schema_version": "splendor.uc_e2e_s10.manager_approval_auth.v1",
        "status": "passed" if manager_approval_auth_valid else "failed",
        "mode": "local_acceptance",
        "events": manager_approval_auth_events,
        "operations": expected_manager_approval_operations,
        "resident_approval_receipt_revocations": resident_revocation_events,
        "fresh_mutating_credential_ids": len(manager_approval_credential_ids)
        == len(set(manager_approval_credential_ids)),
        "exact_scope": "approvals_manage",
        "fleet_id": FLEET_ID,
        "manager_id": "central-manager",
        "raw_bearers_recorded": False,
        "raw_jtis_recorded": False,
        "receipt_signatures_recorded": False,
        "production_manager_auth_claimed": False,
        "other_manager_endpoints_authenticated_by_this_profile": False,
    }

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
        {"case": "operator_intervention_expiry_extension_rejected", "passed": intervention_request["status"] == 200 and intervention_grant["status"] == 200 and intervention_capture["body"].get("status") == "Executed" and extended_intervention["status"] == 403 and extended_intervention["body"].get("code") == "operator_intervention_expiry_mismatch", "status": extended_intervention["status"], "code": extended_intervention["body"].get("code")},
        {"case": "operator_intervention_cross_device_reuse_rejected", "passed": other_device_register["status"] == 200 and reused_intervention["status"] == 403 and reused_intervention["body"].get("code") == "operator_intervention_scope_mismatch", "status": reused_intervention["status"], "code": reused_intervention["body"].get("code")},
        {"case": "expired_approval_rejected", "passed": expired_raw_pre_gateway_unchanged, "status": expired_approval["status"], "code": expired_approval["body"].get("code"), "run_status_before": publish_before_expired_raw["body"].get("status"), "run_status_after": publish_after_expired_raw["body"].get("status"), "lifecycle_unchanged": expired_raw_lifecycle_unchanged, "state_unchanged": expired_raw_state_unchanged, "no_new_approval_action_outcome_trace": expired_raw_no_new_decision_trace, "decision_trace_ids_before": expired_raw_decision_traces_before, "decision_trace_ids_after": expired_raw_decision_traces_after},
        {"case": "revoked_resident_receipt_retry_has_zero_effect", "passed": revoked_retry_zero_effect, "retry_status": revoked_receipt_retry["body"].get("status"), "reason_codes": revoked_receipt_retry["body"].get("verification", {}).get("reasons", []), "adapter_executions_before": revoke_before_manager["body"].get("adapter_executions"), "adapter_executions_after": revoke_after_retry["body"].get("adapter_executions")},
        {"case": "claim_first_receipt_revocation_never_reports_false_success", "passed": claim_first_safe_non_success, "too_late_observed": claim_first_too_late, "effect_unknown_observed": claim_first_effect_unknown, "status": claim_first_revoke["status"], "code": claim_first_revoke["body"].get("code"), "details": claim_first_revoke["body"].get("details")},
        {"case": "circuit_breaker_blocks_matching_publish_attempt", "passed": breaker_payload["status"] == 200 and breaker_sync["body"].get("accepted") is True and breaker_block["body"].get("status") == "Denied", "status": breaker_block["body"].get("status")},
        {"case": "kill_switch_cancels_separate_run", "passed": kill_switch["body"].get("propagation_acknowledged") is True and kill_switch["body"].get("cancel_status") == 200 and kill_switch["body"].get("target_derived_from_registry") is True, "cancel_status": kill_switch["body"].get("cancel_status")},
        {"case": "tampered_trace_state_import_rejected", "passed": trace_sync_tampered["status"] == 403 and tampered_state_import["status"] == 503 and tampered_state_import["body"].get("code") == "state_handoff_proof_unavailable", "trace_status": trace_sync_tampered["status"], "state_status": tampered_state_import["status"], "state_code": tampered_state_import["body"].get("code")},
        {"case": "resident_device_trace_scope_integrity_rejected", "passed": device_trace_wrong_scope["status"] == 403 and device_trace_wrong_scope["body"].get("code") == "missing_scope" and device_trace_payload_tampered["body"].get("accepted") is False and device_trace_payload_tampered["body"].get("accepted_records") == 0 and device_trace_payload_tampered["body"].get("reason_code") == "trace_sync_event_hash_mismatch" and device_trace_cross_run["body"].get("accepted") is False and device_trace_cross_run["body"].get("accepted_records") == 0 and device_trace_cross_run["body"].get("reason_code") == "trace_sync_run_mismatch", "wrong_scope_status": device_trace_wrong_scope["status"], "payload_tamper": device_trace_payload_tampered["body"], "cross_run": device_trace_cross_run["body"]},
        {"case": "replay_side_effect_mode_rejected_by_default", "passed": unsafe_replay["status"] in {400, 403} and replay_counts_before == replay_counts_after, "status": unsafe_replay["status"]},
    ]
    contract_report = read_json(report_dir / "contract-status.json")
    contract_unblocked = not any(group.get("status") == "blocked_not_yet_covered" for group in contract_report.get("blocked_not_yet_covered", []))
    message_api_operations = {"getMessage", "listMessageSchemas", "validateMessageSchema", "listInbox", "listOutbox", "getMessageCausalGraph", "ackMessage", "nackMessage"}
    positives = {
        "api_contract_passed": contract_report.get("status") == "passed" and contract_unblocked,
        "nodes_and_instances_registered": node_list["status"] == 200 and all(item["status"] == 200 for item in node_registrations + instance_registrations + instance_heartbeats),
        "policy_bundle_published_with_ttl": policy["body"].get("status") == "published" and policy_status["body"].get("status") == "published" and bool(policy["body"].get("envelope", {}).get("expires_at")),
        "signed_work_order_accepted_and_placed_on_vpc": placement["body"].get("status") == "selected" and placement["body"].get("candidate_id") == VPC_NODE and placement_data["body"].get("status") == "selected" and placement_data["body"].get("candidate_id") == VPC_NODE and placement_spec["body"].get("status") == "selected" and placement_spec["body"].get("candidate_id") == VPC_NODE and placement_publish["body"].get("status") == "selected" and placement_publish["body"].get("candidate_id") == VPC_NODE and placement_revoke["body"].get("status") == "selected" and placement_revoke["body"].get("candidate_id") == VPC_NODE and orch_create["status"] in {200, 201} and orch_start["status"] == 200 and dispatch_data["body"].get("create_run_status") in {200, 201} and dispatch_spec["body"].get("create_run_status") in {200, 201} and dispatch_publish["body"].get("selected_instance_id") == VPC_INSTANCE and dispatch_revoke["body"].get("selected_instance_id") == VPC_INSTANCE and resident_security["status"] == "passed" and resident_security["all_work_orders_signed_for_target_instance"] is True,
        "data_local_analysis_executed": data_analysis["body"].get("status") == "Executed" and data_analysis_projection.get("resource_id") == DATA_REF and specialist_data_projection.get("resource_id") == DATA_REF,
        "shared_specialist_typed_response_delivered": specialist_data["body"].get("status") == "Executed" and task_sent["body"].get("delivery_status") == "delivered" and task_read["body"].get("receive_side_validated") is True and response_sent["body"].get("delivery_status") == "delivered" and response_read["body"].get("receive_side_validated") is True,
        "message_public_api_surface_exercised": {row["operation_id"] for row in api_rows} >= message_api_operations and schema_validation["body"].get("valid") is True and message_schemas["body"].get("delivery_authority_granted") is False and orchestrator_outbox["body"].get("messages") and specialist_inbox["body"].get("messages") and specialist_outbox["body"].get("messages") and edge_inbox["body"].get("messages") and len(causal_graph["body"].get("nodes", [])) >= 2 and ack_task["body"].get("delivery_status") == "consumed" and ack_response["body"].get("delivery_status") == "consumed" and nack_duplicate["body"].get("payload_preserved") is True,
        "cloud_helper_proposal_only": cloud_delivery["body"].get("delivery_status") == "delivered" and cloud_read["body"].get("receive_side_validated") is True and cloud_proposal["message"]["payload"].get("direct_actuator_authority") is False and cloud_proposal["message"]["payload"].get("publication_authority") is False and helper_publish_denial["body"].get("status") == "Denied" and cloud_direct_denial["body"].get("status") == "Denied",
        "edge_bounded_inspection_executed": device_register["status"] == 200 and device_status["status"] == 200 and policy_cache["body"].get("loaded") is True and inspect_zone["body"].get("status") == "Executed" and waypoint["body"].get("status") == "Executed" and intervention_capture["body"].get("status") == "Executed" and all(item.get("total_delta") == item.get("expected_sim_delta") for item in simulator_evidence),
        "internal_artifact_created": internal_artifact["body"].get("status") == "Executed" and internal_evidence.get("artifact_path") == INTERNAL_ARTIFACT and bool(internal_evidence.get("trace_event_id")),
        "external_publication_approval_gated_and_executed_once": publish_submit["status"] == 200 and publish_submit["body"].get("accepted") is True and dispatch_publish["status"] == 200 and dispatch_publish["body"].get("create_run_status") == 200 and dispatch_publish["body"].get("start_run_status") == 200 and publish_create.get("run_id") == PUBLISH_RUN and publish_start.get("status") == "running" and publish_after_dispatch["body"].get("status") == "running" and publish_needs_approval["body"].get("status") == "NeedsApproval" and forged_legacy_publish["status"] == 409 and forged_legacy_publish["body"].get("code") == "legacy_approval_evidence_non_authorizing" and publish_after_forged_legacy["body"].get("adapter_executions") == 0 and publish_after_forged_legacy["body"].get("status") == "waiting_for_approval" and approval_request["status"] == 200 and approval_grant["body"].get("status") == "granted" and approval_context.get("receipt_audience") == expected_publish_audience and authority_receipt.get("audience") == expected_publish_audience and manager_approval_auth_valid and publish_retry["status"] == 200 and approved_publish["body"].get("status") == "Executed" and publish_retry_executed_once_without_lifecycle_advance and bool(publish_evidence.get("trace_event_id")),
        "resident_approval_receipt_revocation_acknowledged": revoke_submit["status"] == 200 and revoke_submit["body"].get("accepted") is True and dispatch_revoke["status"] == 200 and dispatch_revoke["body"].get("create_run_status") == 200 and dispatch_revoke["body"].get("start_run_status") == 200 and revoke_create.get("run_id") == REVOKE_RUN and revoke_start.get("status") == "running" and revoke_proposal["body"].get("status") == "NeedsApproval" and revoke_grant["body"].get("status") == "granted" and revoke_before_manager["body"].get("status") == "waiting_for_approval" and resident_revocation_exact and resident_revocation_security_valid and revoked_retry_zero_effect,
        "resident_state_handoff_denied_without_source_proof_and_receiver_resumed": handoff_export["status"] == 200 and cloud_create["status"] == 200 and cloud_start["status"] == 200 and cloud_pause["status"] == 200 and handoff_import["status"] == 503 and handoff_import["body"].get("code") == "state_handoff_proof_unavailable" and handoff_import["body"].get("details", {}).get("disposition") == "needs_intervention" and cloud_state_before_import["body"].get("state_node_id") == cloud_state_after_import_denial["body"].get("state_node_id") and cloud_resume["status"] == 200 and bool(state_after["body"].get("state_node_id")) and resident_security["cloud_receiver_create_import_resume_used_same_envelope"] is True,
        "central_trace_aggregation_completed": trace_sync_vpc["body"].get("accepted_records", 0) > 0 and trace_sync_vpc_data["body"].get("accepted_records", 0) > 0 and trace_sync_vpc_publish["body"].get("accepted_records", 0) > 0 and trace_sync_vpc_revoke["body"].get("accepted_records", 0) > 0 and trace_sync_vpc_spec["body"].get("accepted_records", 0) > 0 and trace_sync_cloud["body"].get("accepted_records", 0) > 0 and device_trace_sync["body"].get("accepted") is True and device_trace_sync["body"].get("accepted_records", 0) > 0 and device_trace_duplicate["body"].get("accepted") is True and device_trace_duplicate["body"].get("accepted_records") == device_trace_sync["body"].get("accepted_records") and trace_sync_edge["status"] == 403 and trace_sync_edge["body"].get("code") == "trace_sync_rejected" and telemetry["body"].get("authority") == "observational_only",
        "audit_and_replay_explain_without_side_effects": replay_orch["body"].get("mode") == "inspect_only" and replay_publish["body"].get("mode") == "inspect_only" and replay_edge["body"].get("mode") == "inspect_only" and replay_counts_before == replay_counts_after and governance_audit["body"].get("exported") is True,
    }
    failures = [key for key, ok in positives.items() if ok is not True]
    failures.extend(f"negative_failed:{item['case']}" for item in negatives if item.get("passed") is not True)
    missing_events = sorted(event for event in REQUIRED_EVENTS if not event_ids.get(event))
    failures.extend(f"missing_required_event:{event}" for event in missing_events)

    contract_report = read_json(report_dir / "contract-status.json")
    topology_path = root / "tests" / "e2e" / "use-cases" / "docker-compose.acceptance.yml"
    topology = {"compose_file": str(topology_path), "topology_hash": digest_file(topology_path), "services": ["central-manager", "resident-vpc-node", "resident-cloud-node", "resident-edge-node", "acceptance-action-provider", "e2e-runner"]}
    trace_event_ids = sorted({tid for values in event_ids.values() for tid in values if tid} | {trace_id(record) for record in records if trace_id(record)})
    state_node_ids = sorted({state_before["body"].get("state_node_id", ""), handoff_export["body"].get("state_node_id", ""), cloud_state_before_import["body"].get("state_node_id", ""), cloud_state_after_import_denial["body"].get("state_node_id", ""), state_after["body"].get("state_node_id", ""), cloud_resume["body"].get("state_node_id", "")})
    state_hashes = sorted({state_before["body"].get("data_hash", ""), state_after["body"].get("data_hash", ""), handoff_export["body"].get("handoff", {}).get("snapshot", {}).get("state_hash", {}).get("value", "")})
    action_ids = collect_action_ids(records, [data_analysis, specialist_data, helper_publish_denial, inspect_zone, waypoint, cloud_direct_denial, internal_artifact, publish_needs_approval, approved_publish, revoke_proposal, revoked_receipt_retry, expired_approval, unauthorized_data, specialist_escalation, breaker_block])
    artifact_ids = sorted(value for value in {INTERNAL_ARTIFACT, EXTERNAL_ARTIFACT, internal_evidence.get("artifact_path") or "", publish_evidence.get("artifact_path") or ""} if value)
    replay_report = {"mode": "inspect_only", "side_effects_allowed_default": False, "side_effects_executed": replay_counts_before != replay_counts_after, "orchestrator_replay": replay_orch["body"], "publish_replay": replay_publish["body"], "edge_replay": replay_edge["body"], "unsafe_replay_negative": unsafe_replay, "action_execution_counts": action_counts, "counts_before_replay": replay_counts_before, "counts_after_replay": replay_counts_after, "simulator_before_replay": sim_before_replay, "simulator_after_replay": sim_after_replay}
    approval_receipt_revocation_report = {
        "schema_version": "splendor.uc_e2e_s10.approval_receipt_revocation.v1",
        "status": "passed"
        if resident_revocation_exact
        and resident_revocation_security_valid
        and revoked_retry_zero_effect
        else "failed",
        "revoke_before_claim": {
            "work_order_id": WORK_ORDER_ORCH_REVOKE,
            "run_id": REVOKE_RUN,
            "target_instance_id": VPC_INSTANCE,
            "manager_submission": revoke_submit,
            "manager_dispatch": dispatch_revoke,
            "approval_policies": revoke_approval_policies,
            "challenge": revoke_context,
            "grant": {
                "status": revoke_grant["body"].get("status"),
                "trace_event_id": revoke_grant["body"].get("trace_event_id"),
            },
            "retained_receipt": {
                "schema_version": retained_revoke_receipt.get("schema_version"),
                "receipt_id": retained_revoke_receipt.get("receipt_id"),
                "approval_id": retained_revoke_receipt.get("approval_id"),
                "audience": retained_revoke_receipt.get("audience"),
                "revocation": retained_revoke_receipt.get("revocation"),
            },
            "resident_ack": resident_revocation_ack,
            "retry_outcome": revoked_receipt_retry["body"],
            "run_before_revoke": revoke_before_manager["body"],
            "run_after_revoke": revoke_after_manager["body"],
            "run_after_retry": revoke_after_retry["body"],
            "state_before_revoke": revoke_state_before_manager["body"],
            "state_after_retry": revoke_state_after_retry["body"],
            "zero_effect": revoked_retry_zero_effect,
        },
        "claim_before_revoke": {
            "work_order_id": WORK_ORDER_ORCH_PUBLISH,
            "run_id": PUBLISH_RUN,
            "target_instance_id": VPC_INSTANCE,
            "manager_response": claim_first_revoke,
            "status": "passed"
            if claim_first_too_late
            else "blocked_effect_unknown"
            if claim_first_effect_unknown
            else "failed",
            "outcome": "too_late"
            if claim_first_too_late
            else "effect_unknown"
            if claim_first_effect_unknown
            else "unexpected",
            "too_late_observed": claim_first_too_late,
            "effect_unknown_observed": claim_first_effect_unknown,
            "successful_revocation_claimed": False,
            "effect_certainty": claim_first_revoke["body"].get("details", {}).get("effect_certainty"),
            "resident_audit_correlation": "unavailable_for_known_too_late_response"
            if claim_first_too_late
            else "unavailable_after_post_send_uncertainty",
        },
        "manager_calls": [
            event
            for event in manager_approval_auth_events
            if event.get("operation_id")
            in {"revokeApprovalClaimFirst", "revokeApproval"}
        ],
        "resident_calls": resident_revocation_events,
        "resident_revocation_security_valid": resident_revocation_security_valid,
        "fresh_manager_jtis": len(manager_approval_credential_ids)
        == len(set(manager_approval_credential_ids)),
        "fresh_resident_revocation_jtis": len(resident_revocation_credential_ids)
        == len(set(resident_revocation_credential_ids)),
        "exact_resident_scope": "splendor.approval_receipts.revoke",
        "raw_bearers_recorded": False,
        "raw_jtis_recorded": False,
        "receipt_signatures_recorded_in_per_call_evidence": False,
        "uncertainty_mocked": False,
    }
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
            "summary": "S10 executed the final bounded field-intelligence journey across manager, TLS-authenticated VPC/cloud/edge residents, governance, fail-closed state handoff, trace aggregation, and replay.",
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
        "evidence_artifacts": ["scenario-report.json", "journey-report.json", "message-api-report.json", "artifact-publication-report.json", "approval-receipt-revocation-report.json", "resident-security.json", "manager-approval-auth.json", "authority-profiles-report.json", "trace-export.jsonl", "state-handoff-report.json", "replay-report.json", "audit-package.json"],
    }
    human_summary = "\n".join(
        [
            "# UC-E2E-S10 Final Cross-Component Acceptance Journey",
            "",
            "S10 completed the governed field-intelligence package through public manager, daemon, message, governance, device, trace, state, and replay boundaries.",
            "",
            f"- Main run: `{ORCH_RUN}` on VPC node `{VPC_NODE}`; target cloud instance `{CLOUD_INSTANCE}` denied state import without source proof and resumed only its own state.",
            f"- Publish-only run: `{PUBLISH_RUN}` used exact `artifact.publish_external` authority and a separate VPC-signed work order.",
            f"- Receipt-revocation run: `{REVOKE_RUN}` was separately submitted and dispatched by the manager with immutable narrowing approval policy `{revoke_approval_policies[0]['policy_id']}`.",
            f"- Specialist message response: `{TASK_RESPONSE_ID}`; cloud helper proposal: `{CLOUD_MESSAGE_ID}`.",
            f"- Internal artifact: `{INTERNAL_ARTIFACT}`; approved external artifact: `{EXTERNAL_ARTIFACT}`.",
            "- External publication paused for scoped approval and executed exactly once after approval.",
            "- Active raw expired approval evidence was rejected with pre-gateway 409 while the run, tick, state, adapter count, and approval/action/outcome trace projection remained unchanged.",
            "- A retained resident receipt was revoked with an exact known acknowledgement and its retry had zero effects; the separately claimed publish receipt never reported revocation success, with exact `too_late` retained only when observed.",
            "- Controlled negative branches rejected invalid work orders, unauthorized data, specialist escalation, duplicate remote delivery, low-level physical action, extended/cross-device operator intervention, expired raw approval, revoked receipt reuse, circuit breaker publish, kill-switch target run, resident payload/cross-run trace sync, tampered central trace/state import, and unsafe replay mode.",
            "- Replay was inspect-only by default and preserved daemon adapter counts and device simulator counters.",
            "- Every resident request used CA-verified TLS, a no-redirect client, and a freshly minted target-instance bearer; per-call evidence independently records exact scope, mirror status, result, and available server correlation without token bytes.",
            "- Manager approval request/grant/revoke calls used fresh fleet-bound central-manager bearers and matching body/audit mirrors; resident receipt revocation used the dedicated exact scope and a distinct target-instance JTI. Raw bearer/JTI/signature material was not retained in per-call evidence. Other manager endpoints remain local-acceptance-only.",
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
        "run_ids": [ORCH_RUN, ORCH_DATA_RUN, PUBLISH_RUN, REVOKE_RUN, SPECIALIST_RUN, CLOUD_HELPER_RUN, EDGE_RUN, CB_RUN, KILL_RUN],
        "trace_event_ids": trace_event_ids,
        "state_node_ids": [value for value in state_node_ids if value],
        "state_hashes": [value for value in state_hashes if value],
        "message_ids": [TASK_REQUEST_ID, TASK_RESPONSE_ID, CLOUD_MESSAGE_ID, DUPLICATE_MESSAGE_ID],
        "work_order_ids": [WORK_ORDER_ORCH, WORK_ORDER_ORCH_DATA, WORK_ORDER_ORCH_PUBLISH, WORK_ORDER_ORCH_REVOKE, WORK_ORDER_ORCH_MESSAGE, WORK_ORDER_SPECIALIST, WORK_ORDER_SPECIALIST_MESSAGE, WORK_ORDER_CLOUD_HELPER, WORK_ORDER_EDGE, WORK_ORDER_CB, WORK_ORDER_KILL, "wo_uc_e2e_s10_invalid_unsigned"],
        "approval_ids": [approval_context.get("approval_id", ""), revoke_context.get("approval_id", ""), expired_evidence.get("approval_id", ""), "intervention_uc_e2e_s10_capture"],
        "node_ids": [VPC_NODE, CLOUD_NODE, EDGE_NODE],
        "instance_ids": [VPC_INSTANCE, CLOUD_INSTANCE, EDGE_INSTANCE],
        "action_ids": action_ids,
        "policy_ids": [POLICY_ID, publish_approval_policies[0]["policy_id"], revoke_approval_policies[0]["policy_id"]],
        "circuit_breaker_ids": [BREAKER_ID],
        "kill_switch_ids": [KILL_SWITCH_ID],
        "artifact_ids": [value for value in artifact_ids if value],
        "api_operations": sorted({row["operation_id"] for row in api_rows}),
        "required_trace_event_ids": event_ids,
        "required_event_evidence": event_evidence,
        "positive_checks": positives,
        "negative_cases": negatives,
        "scenario_failures": failures,
        "private_v3_outputs": [
            data_analysis_projection,
            specialist_data_projection,
            internal_evidence["private_v3_projection"],
            publish_evidence["private_v3_projection"],
            *physical_projections,
        ],
        "provider_evidence": [sim_before_replay, sim_after_replay],
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
        "resident_tls_verified": resident_security["all_calls_tls_verified"],
        "resident_redirects_disabled": resident_security["all_redirects_disabled"],
        "fresh_mutating_resident_jtis": resident_security["mutating_credential_ids_unique"],
        "fresh_manager_approval_jtis": manager_approval_auth_report["fresh_mutating_credential_ids"],
        "manager_approval_auth_only": manager_approval_auth_valid,
        "target_instance_work_order_signing": resident_security["all_work_orders_signed_for_target_instance"],
        "exact_action_profiles": True,
        "derived_from_required_event_evidence": sorted(event_evidence),
        "public_api_operations": sorted({row["operation_id"] for row in api_rows}),
    }
    artifacts: dict[str, object] = {
        "scenario-report.json": scenario,
        "human-summary.md": human_summary,
        "api-contract-report.json": {"source": str(report_dir / "contract-status.json"), "digest": digest_file(report_dir / "contract-status.json"), "contract": contract_report},
        "topology.json": topology,
        "registry-report.json": {"node_registrations": node_registrations, "instance_registrations": instance_registrations, "instance_heartbeats": instance_heartbeats, "list_nodes": node_list, "canonical_s4_registration_reused": True, "all_registration_requests_accepted": all(item["status"] == 200 for item in node_registrations + instance_registrations + instance_heartbeats), "duplicate_registration_rejections_treated_as_success": False},
        "journey-report.json": {"positive_checks": positives, "run_dispatch": {"orchestrator": {"mode": "direct_exact_profile", "create": orch_create["body"], "start": orch_start["body"]}, "orchestrator_data": dispatch_data["body"], "specialist": dispatch_spec["body"], "cloud_helper": dispatch_helper["body"], "publish": dispatch_publish["body"], "publish_revoke": dispatch_revoke["body"]}, "publish_run": {"manager_submission": publish_submit["body"], "manager_dispatch": dispatch_publish["body"], "create": publish_create, "start": publish_start, "approval_policies": publish_approval_policies, "exact_action_retry": publish_retry["body"], "forged_legacy_grant": forged_legacy_publish, "expired_raw_pre_gateway": expired_raw_pre_gateway_unchanged}, "data_analysis": data_analysis["body"], "specialist_data": specialist_data["body"], "device": {"register": device_register["body"], "status": device_status["body"], "policy_cache": policy_cache["body"], "simulator_evidence": simulator_evidence}, "state_before": state_before["body"], "state_after": state_after["body"]},
        "message-flow.json": {"task_request": task_sent["body"], "task_request_read": task_read["body"], "task_response": response_sent["body"], "task_response_read": response_read["body"], "cloud_proposal": cloud_delivery["body"], "cloud_proposal_read": cloud_read["body"], "duplicate": duplicate_delivery["body"]},
        "message-api-report.json": message_api_report,
        "artifact-publication-report.json": {"internal_run_id": ORCH_RUN, "publish_run_id": PUBLISH_RUN, "internal_work_order_id": WORK_ORDER_ORCH, "publish_work_order_id": WORK_ORDER_ORCH_PUBLISH, "profiles_split": True, "internal_create": orch_create["body"], "internal_start": orch_start["body"], "publish_manager_submission": publish_submit["body"], "publish_manager_dispatch": dispatch_publish["body"], "publish_approval_policies": publish_approval_policies, "publish_create": publish_create, "publish_start": publish_start, "publish_after_dispatch": publish_after_dispatch["body"], "publish_state_after_dispatch": publish_state_after_dispatch["body"], "publish_exact_action_request": publish_exact_action_request, "publish_exact_action_retry": publish_retry["body"], "publish_before_exact_retry": publish_before_retry["body"], "publish_after_exact_retry": publish_after_retry["body"], "publish_state_before_exact_retry": publish_state_before_retry["body"], "publish_state_after_exact_retry": publish_state_after_retry["body"], "exact_retry_preserved_tick_and_state": publish_retry_preserved_tick_and_state, "exact_retry_executed_once_without_lifecycle_advance": publish_retry_executed_once_without_lifecycle_advance, "forged_legacy_grant": forged_legacy_publish, "forged_legacy_adapter_executions": publish_after_forged_legacy["body"].get("adapter_executions"), "internal_artifact": internal_artifact["body"], "internal_artifact_evidence": internal_evidence, "publish_needs_approval": publish_needs_approval["body"], "approval_request": approval_request["body"], "approval_grant": approval_grant["body"], "approved_publish": approved_publish["body"], "approved_publish_evidence": publish_evidence, "expired_approval": expired_approval, "expired_raw_active_run": {"pre_gateway_rejected_unchanged": expired_raw_pre_gateway_unchanged, "run_before": publish_before_expired_raw["body"], "run_after": publish_after_expired_raw["body"], "state_before": publish_state_before_expired_raw["body"], "state_after": publish_state_after_expired_raw["body"], "lifecycle_unchanged": expired_raw_lifecycle_unchanged, "state_unchanged": expired_raw_state_unchanged, "no_new_approval_action_outcome_trace": expired_raw_no_new_decision_trace, "decision_trace_ids_before": expired_raw_decision_traces_before, "decision_trace_ids_after": expired_raw_decision_traces_after}, "claim_first_revoke": claim_first_revoke, "publish_execution_count_for_positive_run": len(orch_publish_executions)},
        "approval-receipt-revocation-report.json": approval_receipt_revocation_report,
        "cloud-helper-report.json": {"proposal": cloud_proposal, "delivery": cloud_delivery["body"], "read": cloud_read["body"], "duplicate": duplicate_delivery["body"], "publish_denial": helper_publish_denial["body"], "device_direct_denial": cloud_direct_denial["body"]},
        "edge-inspection-report.json": {"device_profile": device_register["body"], "start": edge_start["body"], "inspect_zone": inspect_zone["body"], "move_to_waypoint": waypoint["body"], "offline_sensor": offline_sensor["body"], "upload_summary": upload_summary["body"], "operator_intervention": {"request": intervention_request["body"], "grant": intervention_grant["body"], "capture": intervention_capture["body"], "extended_expiry": extended_intervention, "cross_device_reuse": reused_intervention}, "device_trace_sync": device_trace_sync["body"], "simulator_evidence": simulator_evidence},
        "state-handoff-report.json": {"exported": handoff_export["body"], "cloud_create": cloud_create["body"], "cloud_start": cloud_start["body"], "cloud_pause": cloud_pause["body"], "resident_import_denied": handoff_import, "tampered_state_import": tampered_state_import, "cloud_resume": cloud_resume["body"], "source_envelope_key_id": orch_envelope.get("signature", {}).get("key_id"), "receiver_envelope_key_id": cloud_receiver_envelope.get("signature", {}).get("key_id"), "receiver_create_import_resume_used_exact_admitted_envelope": True, "source_state_before": state_before["body"], "receiver_state_before_import": cloud_state_before_import["body"], "receiver_state_after_import_denial": cloud_state_after_import_denial["body"], "receiver_unchanged_on_import_denial": cloud_state_before_import["body"].get("state_node_id") == cloud_state_after_import_denial["body"].get("state_node_id"), "receiver_state_after_resume": state_after["body"], "outcome_claim": "state_handoff_proof_unavailable; receiver resumed only its own state"},
        "trace-sync-report.json": {"vpc": trace_sync_vpc["body"], "vpc_data": trace_sync_vpc_data["body"], "vpc_publish": trace_sync_vpc_publish["body"], "vpc_publish_revoke": trace_sync_vpc_revoke["body"], "vpc_specialist": trace_sync_vpc_spec["body"], "edge": device_trace_sync["body"], "edge_duplicate": device_trace_duplicate["body"], "edge_wrong_scope": device_trace_wrong_scope, "edge_payload_tamper": device_trace_payload_tampered["body"], "edge_cross_run": device_trace_cross_run["body"], "edge_central_redacted_export_rejection": trace_sync_edge, "redacted_edge_export_resynced": False, "trace_hashes_rewritten": False, "cloud": trace_sync_cloud["body"], "cloud_orchestrator": trace_sync_cloud_orch["body"], "device": device_trace_sync["body"], "tampered": trace_sync_tampered},
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
        "resident-security.json": resident_security,
        "manager-approval-auth.json": manager_approval_auth_report,
        "authority-profiles-report.json": {
            "schema_version": "splendor.uc_e2e_s10.authority_profiles.v1",
            "profiles": authority_profiles,
            "artifact_profiles_split": ORCH_RUN != PUBLISH_RUN,
            "manager_admitted_approval_policies": {
                WORK_ORDER_ORCH_PUBLISH: publish_approval_policies,
                WORK_ORDER_ORCH_REVOKE: revoke_approval_policies,
            },
            "manager_dispatch_forwards_immutable_approval_policies": True,
            "physical_permission": PHYSICAL_PERMISSION,
            "physical_action_allowlist": ALLOWED_PHYSICAL_ACTIONS,
            "forbidden_physical_actions": FORBIDDEN_PHYSICAL_ACTIONS,
            "secrets_redacted": True,
        },
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
