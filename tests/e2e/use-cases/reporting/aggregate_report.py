#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


FUTURE_SCENARIOS = [f"UC-E2E-S{i}" for i in range(1, 11)]
S1_REQUIRED_EVENTS = {
    "tick.started",
    "percepts.received",
    "state.loaded",
    "policy.invoked",
    "policy.completed",
    "actions.proposed",
    "constraints.evaluated",
    "verification.started",
    "verification.completed",
    "action.executed",
    "action.denied",
    "outcome.recorded",
    "state.committed",
    "tick.completed",
    "replay.started",
    "replay.adapter_suppressed",
    "replay.completed",
}
S2_REQUIRED_OPERATIONS = {
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
S2_REQUIRED_NEGATIVES = {
    "management_token_alone_cannot_authorize_arbitrary_action",
    "wrong_endpoint_scope",
    "expired_caller_credential",
    "wrong_caller_audience",
    "unsigned_work_order",
    "expired_work_order",
    "revoked_work_order",
    "malformed_work_order",
    "bad_signature_work_order",
    "action_wrong_scope_rejected_before_gateway",
}
S3_REQUIRED_EVENTS = {
    "message.queued",
    "message.delivered",
    "message.consumed",
    "message.rejected",
    "delegation.requested",
    "delegation.rejected",
    "child_run.started",
    "child_run.completed",
    "action.executed",
    "action.denied",
    "state.committed",
}
S3_REQUIRED_NEGATIVES = {
    "specialist_external_artifact_publish_denied",
    "unauthorized_recipient_message_denied",
    "unsupported_message_schema_rejected_before_delivery",
    "broad_permission_data_ref_smuggling_denied",
    "cross_tenant_message_attempt_rejected",
    "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger",
}
S4_REQUIRED_OPERATIONS = {
    "registerNode",
    "registerInstance",
    "heartbeatNode",
    "advertiseCapabilities",
    "evaluatePlacement",
    "submitWorkOrder",
    "dispatchWorkOrder",
    "sendMessage",
    "exportStateSnapshot",
    "importStateSnapshot",
    "syncTraceBuffer",
    "getFleetTelemetry",
}
S4_REQUIRED_NEGATIVES = {
    "unsigned_work_order",
    "expired_work_order",
    "revoked_work_order",
    "wrong_audience_work_order",
    "wrong_tenant_credential",
    "wrong_audience_credential",
    "capability_mismatch",
    "stale_heartbeat_placement_rejection",
    "dispatch_target_mismatch",
    "dispatch_revoked_work_order",
    "duplicate_remote_message",
    "remote_message_delivery_failure",
    "unsupported_remote_message_schema",
    "unauthorized_remote_message_recipient",
    "state_handoff_wrong_tenant_rejected",
    "state_handoff_wrong_hash_rejected",
    "state_handoff_wrong_run_rejected",
    "receiver_state_unchanged_on_failed_import",
    "trace_sync_idempotent_duplicate",
    "trace_sync_tamper_rejected",
    "telemetry_non_authoritative",
}
S5_REQUIRED_OPERATIONS = {
    "publishPolicyBundle",
    "getPolicyStatus",
    "revokePolicyBundle",
    "requestApproval",
    "grantApproval",
    "denyApproval",
    "revokeApproval",
    "createCircuitBreaker",
    "syncCircuitBreakers",
    "clearCircuitBreaker",
    "activateKillSwitch",
    "exportGovernanceAudit",
    "createRun",
    "startRun",
    "resumeRun",
    "cancelRun",
    "submitAction",
    "getStateHead",
    "exportTraces",
    "replayRun",
}
S5_REQUIRED_NEGATIVES = {
    "approval_denial_blocks_pending_action",
    "expired_approval_cannot_authorize_execution",
    "revoked_approval_cannot_authorize_execution",
    "missing_policy_bundle_fails_closed",
    "expired_policy_bundle_fails_closed",
    "revoked_policy_bundle_fails_closed",
    "verifier_uncertainty_escalates_not_allow",
    "circuit_breaker_blocks_matching_action",
    "clearing_circuit_breaker_requires_scope",
    "kill_switch_cancels_matching_run",
    "kill_switch_missing_ack_fails_closed",
    "governance_plane_cannot_issue_broad_unknown_authority",
}
S5_REQUIRED_EVENTS = {
    "approval.requested",
    "approval.granted",
    "approval.denied",
    "approval.expired",
    "approval.revoked",
    "action.needs_approval",
    "action.needs_intervention",
    "action.denied",
    "run.paused",
    "run.resumed",
    "run.cancelled",
    "policy.expired",
    "policy.revoked",
    "circuit_breaker.tripped",
    "circuit_breaker.cleared",
    "kill_switch.activated",
    "governance.audit.exported",
}
S6_REQUIRED_OPERATIONS = {
    "registerDeviceProfile",
    "getDeviceStatus",
    "getPolicyCacheStatus",
    "createRun",
    "startRun",
    "submitPhysicalAction",
    "requestOperatorIntervention",
    "grantOperatorIntervention",
    "denyOperatorIntervention",
    "syncDeviceTraceBuffer",
    "exportTraces",
    "replayRun",
    "registerNode",
    "heartbeatNode",
    "registerInstance",
    "submitWorkOrder",
    "sendMessage",
    "getMessage",
    "managerAudit",
}
S6_REQUIRED_NEGATIVES = {
    "forbidden_low_level_actions_rejected",
    "geofence_breach_denied_before_adapter",
    "low_battery_forces_return_to_base_or_intervention",
    "expired_policy_cache_denies_high_risk_offline",
    "cloud_helper_direct_action_attempt_denied",
    "operator_approval_outside_scope_rejected",
    "operator_approval_after_expiry_rejected",
    "trace_sync_tamper_or_reordering_detected",
}
S6_REQUIRED_SECURITY_NEGATIVES = {
    "device_endpoint_missing_credential_rejected",
    "device_endpoint_wrong_audience_rejected",
    "device_endpoint_wrong_tenant_rejected",
}
S6_REQUIRED_EVENTS = {
    "device.profile.registered",
    "policy.cache.loaded",
    "policy.cache.expired",
    "cloud_helper.proposal.received",
    "safety.verification.started",
    "safety.verification.completed",
    "safety.verification.denied",
    "action.executed",
    "action.denied",
    "action.needs_intervention",
    "operator.intervention.requested",
    "operator.intervention.granted",
    "operator.intervention.denied",
    "operator.intervention.expired",
    "offline.entered",
    "offline.exited",
    "trace.buffer.appended",
    "trace.sync.completed",
    "trace.sync.failed",
}
S6_REQUIRED_SIMULATED_ACTION_LABELS = {
    "read_battery_policy_warmup": 1,
    "inspect_zone_from_typed_cloud_proposal": 1,
    "move_to_waypoint_from_typed_cloud_proposal": 1,
    "capture_image": 1,
    "read_sensor_summary_offline": 1,
    "return_to_base_low_battery_safe": 1,
    "upload_trace_summary": 1,
    "ambiguous_privacy_denied_until_operator": 0,
    "operator_granted_capture": 1,
    "geofence_breach_denied": 0,
    "low_battery_needs_intervention": 0,
    "expired_policy_cache_denied": 0,
    "cloud_helper_direct_authority_denied": 0,
    "operator_wrong_scope_denied": 0,
    "operator_expired_evidence_denied": 0,
}
S6_DENIED_SIMULATOR_LABELS = {
    "ambiguous_privacy_denied_until_operator",
    "geofence_breach_denied",
    "low_battery_needs_intervention",
    "expired_policy_cache_denied",
    "cloud_helper_direct_authority_denied",
    "operator_wrong_scope_denied",
    "operator_expired_evidence_denied",
}
S7_REQUIRED_OPERATIONS = {
    "registerNode",
    "registerInstance",
    "heartbeatNode",
    "advertiseCapabilities",
    "evaluatePlacement",
    "submitWorkOrder",
    "dispatchWorkOrder",
    "sendMessage",
    "getMessage",
    "submitAction",
    "requestApproval",
    "grantApproval",
    "getStateHead",
    "exportTraces",
    "replayRun",
}
S7_REQUIRED_NEGATIVES = {
    "specialist_tenant_b_data_ref_denied_before_adapter",
    "manager_credential_as_action_permission_denied",
    "specialist_external_publish_denied_by_narrow_work_order",
    "message_payload_data_ref_permission_smuggling_denied",
    "trace_export_without_redaction_policy_rejected",
    "external_artifact_publish_without_approval_pauses",
    "cross_tenant_replay_cannot_reveal_raw_payloads",
    "artifact_path_collision_across_tenants_rejected",
    "denied_data_and_artifact_actions_did_not_reach_adapter",
    "replay_did_not_reread_republish_or_rewrite_artifacts",
}
S7_REQUIRED_EVENTS = {
    "work_order.accepted",
    "data_scope.verified",
    "data_scope.denied",
    "message.sent",
    "message.received",
    "message.denied",
    "artifact.created",
    "artifact.publish.needs_approval",
    "artifact.publish.executed",
    "artifact.publish.denied",
    "trace.exported.redacted",
    "state.committed",
    "replay.explained",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def trace_record_id(record: dict) -> str:
    return str(record.get("payload", {}).get("trace_event_id", ""))


def trace_record_kind(record: dict) -> str:
    kind = record.get("payload", {}).get("kind")
    key = kind if isinstance(kind, str) else next(iter(kind.keys())) if isinstance(kind, dict) and kind else "unknown"
    return {
        "LoopTickStarted": "tick.started",
        "LoopTickCompleted": "tick.completed",
        "PolicyInvoked": "policy.invoked",
        "PolicyCompleted": "policy.completed",
        "CandidatesProposed": "actions.proposed",
        "ConstraintsEvaluated": "constraints.evaluated",
        "ActionVerificationStarted": "verification.started",
        "MessageQueued": "message.queued",
        "MessageDelivered": "message.delivered",
        "MessageConsumed": "message.consumed",
        "MessageRejected": "message.rejected",
        "DelegationRequested": "delegation.requested",
        "DelegationRejected": "delegation.rejected",
        "ChildRunStarted": "child_run.started",
        "ChildRunCompleted": "child_run.completed",
        "ActionVerificationCompleted": "verification.completed",
        "ActionExecuted": "action.executed",
        "ActionDenied": "action.denied",
        "ActionNeedsApproval": "action.needs_approval",
        "ActionNeedsIntervention": "action.needs_intervention",
        "OutcomeRecorded": "outcome.recorded",
        "StateCommitted": "state.committed",
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
    }.get(key, key)


def trace_record_kind_payload(record: dict) -> dict:
    kind = record.get("payload", {}).get("kind")
    if isinstance(kind, dict) and kind:
        value = next(iter(kind.values()))
        return value if isinstance(value, dict) else {}
    return {}


def content_hash_string(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        algorithm = str(value.get("algorithm", "")).lower()
        digest = value.get("value")
        if algorithm and digest:
            return f"{algorithm}:{digest}"
    return ""


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def is_canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


def git_revision(root: Path) -> str:
    env_revision = os.environ.get("SPLENDOR_E2E_SOURCE_REV")
    if env_revision and env_revision != "unknown-source-revision":
        return env_revision
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        git_head = root / ".git" / "HEAD"
        try:
            head = git_head.read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref_path = root / ".git" / head.split(" ", 1)[1]
                return ref_path.read_text(encoding="utf-8").strip()
            return head
        except Exception:
            return "unknown-source-revision"


def package_version(path: Path) -> str:
    if not path.exists():
        return "not-present"
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("version", "unknown")
    except Exception:
        return "unknown"


def text_version(path: Path) -> str:
    if not path.exists():
        return "not-present"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def write_s0_artifacts(artifact_dir: Path, contract: dict, anti: dict, seed: dict, public_boundary: dict) -> list[str]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "scenario-report.json": {
            "id": "UC-E2E-S0",
            "status": "passed" if public_boundary.get("status") == "passed" else "failed",
            "contract_status": contract.get("status"),
            "anti_drift_status": anti.get("status"),
            "public_boundary_status": public_boundary.get("status"),
            "fixture_seed_digest": seed.get("deterministic_digest"),
        },
        "replay-report.json": {
            "mode": "inspect_only_schema_required",
            "side_effects_allowed_default": False,
            "adapter_suppression_evidence_required_for_later_scenarios": True,
            "evidence_scope": "schema_and_report_contract_only_for_s0",
        },
        "anti-drift-results.json": anti,
        "stdout.log": "S0 static harness checks completed\n",
    }
    paths = []
    for name, value in artifacts.items():
        path = artifact_dir / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths.append(str(path))
    return paths


def validate_required_s0_artifacts(artifact_dir: Path) -> list[str]:
    failures: list[str] = []
    required_non_empty = [
        "commands.log",
        "api-traffic.ndjson",
        "fixture-seed.json",
        "public-boundary.json",
        "scenario-report.json",
        "replay-report.json",
        "anti-drift-results.json",
        "stdout.log",
    ]
    for name in required_non_empty:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s0_artifact:{name}")
        elif path.stat().st_size == 0:
            failures.append(f"empty_required_s0_artifact:{name}")
    return failures


def validate_report_shape(report: dict) -> list[str]:
    failures: list[str] = []
    required_top = {
        "suite_id",
        "suite_version",
        "source_revision",
        "started_at",
        "completed_at",
        "container_topology_hash",
        "topology_identifier",
        "commands",
        "api_contract_versions",
        "component_versions",
        "contract_status",
        "anti_drift_status",
        "scenarios",
        "blocking_failures",
        "non_goal_observations",
        "human_summary_path",
    }
    missing = sorted(required_top - report.keys())
    if missing:
        failures.append("report_missing_top_level_fields:" + ",".join(missing))
    if report.get("suite_id") != "splendor-use-case-e2e-through-0.1":
        failures.append("report_suite_id_invalid")
    if not str(report.get("container_topology_hash", "")).startswith("sha256:"):
        failures.append("report_topology_hash_invalid")
    scenario_required = {
        "id",
        "status",
        "fr_coverage",
        "components",
        "positive_evidence",
        "negative_evidence",
        "replay_evidence",
        "replay_mode",
        "replay_side_effect_suppression",
        "replay_artifacts",
        "anti_drift_checks",
        "artifact_paths",
    }
    for scenario in report.get("scenarios", []):
        missing_scenario = sorted(scenario_required - scenario.keys())
        if missing_scenario:
            failures.append(f"scenario_{scenario.get('id','unknown')}_missing_fields:" + ",".join(missing_scenario))
        if scenario.get("status") not in {"passed", "failed", "blocked_not_yet_covered"}:
            failures.append(f"scenario_{scenario.get('id','unknown')}_invalid_status")
    if not any(s.get("id") == "UC-E2E-S0" for s in report.get("scenarios", [])):
        failures.append("report_missing_uc_e2e_s0")
    return failures


def render_markdown(report: dict) -> str:
    lines = [
        "# Splendor Use-Case E2E Acceptance Report",
        "",
        f"- Suite: `{report['suite_id']}` `{report['suite_version']}`",
        f"- Source revision: `{report['source_revision']}`",
        f"- Topology: `{report['topology_identifier']}` `{report['container_topology_hash']}`",
        f"- Contract status: `{report['contract_status']['status']}`",
        f"- Anti-drift status: `{report['anti_drift_status']['status']}`",
        "",
        "## Scenario status",
        "",
    ]
    for scenario in report["scenarios"]:
        lines.append(f"- `{scenario['id']}`: **{scenario['status']}**")
    lines.extend(
        [
            "",
            "## S0 evidence",
            "",
            "- OpenAPI contract parsing ran before scenario reporting.",
            "- Daemon `/health` and `/capabilities` were called through the compose public boundary.",
            "- Anti-drift scanner self-tests proved negative fixtures fail closed.",
            "- Replay fields are present with inspect-only/side-effect suppression requirements.",
            "- Future scenarios remain blocked/not-yet-covered unless their scenario evidence is present.",
            "",
            "## S2 evidence",
            "",
            "- Management API traffic is recorded in `artifacts/UC-E2E-S2/api-traffic.ndjson` when S2 runs.",
            "- S2 requires health/version/capabilities, run lifecycle, percept, action, state, trace export, and replay operations.",
            "- S2 requires caller credentials, endpoint scopes, signed work orders, audit attribution, gateway denial evidence, and replay adapter-suppression evidence.",
            "",
            "## S3 evidence",
            "",
            "- Local multi-agent delegation evidence is recorded in `artifacts/UC-E2E-S3/` when S3 runs.",
            "- S3 requires typed task request/response messages, parent/child runs, scoped specialist authority, gateway denial evidence, state commits, and replay causal graph reconstruction.",
            "- S3 is local-only and does not claim daemon message API, remote transport, fleet, governance, or physical/edge coverage.",
            "",
            "## S4 evidence",
            "",
            "- Fleet dispatch evidence is recorded in `artifacts/UC-E2E-S4/` when S4 runs.",
            "- S4 requires public manager/resident HTTP APIs, same-image Splendor services, signed work-order validation, placement, remote messages, state handoff, trace sync, telemetry, and replay/audit evidence.",
            "- S4 keeps telemetry observational only and leaves later scenarios blocked until their own scenario evidence exists.",
            "",
            "## S5 evidence",
            "",
            "- Governance evidence is recorded in `artifacts/UC-E2E-S5/` when S5 runs.",
            "- S5 requires public daemon and manager APIs, scoped approval grant/deny/revoke, policy bundle TTL/revocation, circuit breaker, kill switch, audit export, and inspect-only replay evidence.",
            "- S5 keeps governance runtime-enforced and does not claim enterprise approval UI or product workflow coverage.",
            "",
            "## Non-goals observed",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["non_goal_observations"])
    if report["blocking_failures"]:
        lines.extend(["", "## Blocking failures", ""])
        lines.extend(f"- {item}" for item in report["blocking_failures"])
    return "\n".join(lines) + "\n"


def blocked_future_scenario(scenario_id: str) -> dict:
    return {
        "id": scenario_id,
        "status": "blocked_not_yet_covered",
        "fr_coverage": [],
        "components": [],
        "positive_evidence": [],
        "negative_evidence": [],
        "replay_evidence": [],
        "replay_mode": "not_run",
        "replay_side_effect_suppression": {"required": True, "evidence_present": False, "side_effects_allowed_default": False},
        "replay_artifacts": [],
        "anti_drift_checks": [],
        "run_ids": [],
        "trace_event_ids": [],
        "state_node_ids": [],
        "state_hashes": [],
        "message_ids": [],
        "work_order_ids": [],
        "approval_ids": [],
        "node_ids": [],
        "artifact_paths": [],
        "blocker": "Scenario behavior is outside UC-E2E-S0 and must be implemented by its own scenario sprint before it can count as acceptance coverage.",
    }


def load_s1_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S1"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s1_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s1_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s1_scenario_report_failed")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_hashes"):
        failures.append("s1_missing_runtime_ids")
    ids_by_event = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S1_REQUIRED_EVENTS if not ids_by_event.get(event))
    if missing_events:
        failures.append("s1_missing_required_trace_events:" + ",".join(missing_events))
    suppression = scenario.get("replay_side_effect_suppression", {})
    if not suppression.get("evidence_present") or suppression.get("side_effects_allowed_default") is not False:
        failures.append("s1_replay_suppression_missing")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("http_counter_before") != replay.get("http_counter_after"):
        failures.append("s1_replay_http_counter_changed")
    if replay.get("artifact_checksum_before") != replay.get("artifact_checksum_after"):
        failures.append("s1_replay_artifact_checksum_changed")
    if not {"replay.started", "replay.adapter_suppressed", "replay.completed"}.issubset(set(replay.get("events", []))):
        failures.append("s1_replay_events_missing")
    replay_event_ids = replay.get("event_ids", {})
    raw_events = {}
    for item in replay.get("raw_lines", []):
        if item.get("type") != "replay_lifecycle":
            continue
        if "replay_event_id" in item:
            failures.append(f"s1_replay_lifecycle_uses_ad_hoc_id:{item.get('event')}")
        raw_events[item.get("event")] = item.get("trace_event_id")
    for event in ["replay.started", "replay.adapter_suppressed", "replay.completed"]:
        replay_trace_id = replay_event_ids.get(event)
        if not is_canonical_uuid(replay_trace_id):
            failures.append(f"s1_replay_trace_event_id_not_canonical_uuid:{event}")
        elif raw_events.get(event) != replay_trace_id:
            failures.append(f"s1_replay_event_not_backed_by_raw_output:{event}")
        if not scenario.get("required_trace_event_ids", {}).get(event):
            failures.append(f"s1_replay_event_missing_from_required_trace_event_ids:{event}")
        if replay_trace_id not in scenario.get("trace_event_ids", []):
            failures.append(f"s1_replay_event_missing_from_trace_event_ids:{event}")
    if replay.get("derived_from_raw_output") is not True:
        failures.append("s1_replay_lifecycle_not_derived_from_raw_output")
    state = read_json(artifact_dir / "state-export.json")
    for key in ["state_node_id", "tenant_id", "agent_id", "run_id", "parent_state_node_ids", "snapshot_ref", "state_hash", "trace_linkage", "timestamp"]:
        if state.get(key) in (None, "", "available_in_state_store"):
            failures.append(f"s1_state_export_missing:{key}")
    if not state.get("parent_state_node_ids"):
        failures.append("s1_state_export_empty_parent_state_node_ids")
    audit = read_json(artifact_dir / "audit-report.json")
    denials = {item.get("case"): item for item in audit.get("denials", [])}
    for case in ["deny_url", "deny_path"]:
        item = denials.get(case, {})
        if "action.denied" not in item.get("events", []) or "action.failed" in item.get("events", []):
            failures.append(f"s1_{case}_not_pre_adapter_denial")
        if not any(denial.get("adapter_execution") for denial in item.get("denials", [])):
            failures.append(f"s1_{case}_missing_adapter_non_execution_evidence")
    trace_failure = denials.get("forced_trace_write_failure_blocks_side_effect", {})
    if trace_failure.get("http_counter_before") != trace_failure.get("http_counter_after"):
        failures.append("s1_trace_failure_allowed_side_effect")
    state_failure = denials.get("forced_state_commit_failure_prevents_next_tick", {})
    if state_failure.get("exit") == 0 or state_failure.get("http_counter_after", 0) - state_failure.get("http_counter_before", 0) > 1:
        failures.append("s1_state_failure_advanced_next_tick")
    if state_failure.get("tick_start_count", 0) > 1 or 2 in state_failure.get("tick_start_ids", []):
        failures.append("s1_state_failure_started_second_tick")
    return scenario, failures


def load_s2_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S2"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "schema-parity.json",
        "typescript-client-workflow.json",
        "python-sdk-workflow.json",
        "splendorctl-workflow.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s2_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s2_artifact:{name}")
    scenario_blockers = scenario.get("blocking_failures", [])
    for blocker in scenario_blockers:
        if blocker not in failures:
            failures.append(blocker)
    if scenario.get("status") == "partial":
        failures.append("s2_scenario_partial")
    elif scenario.get("status") != "passed":
        failures.append("s2_scenario_report_failed")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes"):
        failures.append("s2_missing_runtime_ids")
    if not scenario.get("work_order_ids"):
        failures.append("s2_missing_work_order_ids")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S2_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s2_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S2_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s2_missing_negative_cases:" + ",".join(missing_negatives))
    for case in ["wrong_endpoint_scope", "expired_caller_credential", "wrong_caller_audience", "action_wrong_scope_rejected_before_gateway"]:
        if negatives.get(case, {}).get("status") != 403:
            failures.append(f"s2_{case}_not_forbidden")
    for case in ["unsigned_work_order", "expired_work_order", "revoked_work_order", "malformed_work_order", "bad_signature_work_order"]:
        if negatives.get(case, {}).get("status") not in {400, 403}:
            failures.append(f"s2_{case}_not_rejected")
    arbitrary = negatives.get("management_token_alone_cannot_authorize_arbitrary_action", {})
    if arbitrary.get("outcome_status") != "Denied":
        failures.append("s2_arbitrary_action_not_denied")
    if arbitrary.get("adapter_executions_before") != arbitrary.get("adapter_executions_after"):
        failures.append("s2_arbitrary_action_reached_adapter")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only":
        failures.append("s2_replay_not_inspect_only")
    if replay.get("side_effects_allowed_default") is not False:
        failures.append("s2_replay_side_effect_default_not_false")
    if replay.get("adapter_executions_before") != replay.get("adapter_executions_after"):
        failures.append("s2_replay_executed_adapter")
    suppression = scenario.get("replay_side_effect_suppression", {})
    if not suppression.get("evidence_present") or suppression.get("side_effects_allowed_default") is not False:
        failures.append("s2_replay_suppression_missing")
    state = read_json(artifact_dir / "state-export.json")
    for key in ["state_node_id", "data_hash", "run_id", "tenant_id", "agent_id"]:
        if not state.get(key):
            failures.append(f"s2_state_export_missing:{key}")
    schema = read_json(artifact_dir / "schema-parity.json")
    client_paths = scenario.get("client_path_coverage", {})
    for path_name in ["raw_openapi_http", "typescript_client", "python_sdk", "splendorctl"]:
        if client_paths.get(path_name, {}).get("executable_workflow") is not True:
            failures.append(f"s2_client_path_not_executable:{path_name}")
    raw_http = client_paths.get("raw_openapi_http", {})
    raw_missing = sorted(S2_REQUIRED_OPERATIONS - set(raw_http.get("operations_observed", [])))
    if raw_missing:
        failures.append("s2_raw_http_workflow_missing_ops:" + ",".join(raw_missing))
    if not raw_http.get("evidence_artifacts"):
        failures.append("s2_raw_http_workflow_missing_evidence_artifacts")
    workflow_artifacts = {
        "typescript_client": "typescript-client-workflow.json",
        "python_sdk": "python-sdk-workflow.json",
        "splendorctl": "splendorctl-workflow.json",
    }
    for path_name, artifact_name in workflow_artifacts.items():
        workflow = read_json(artifact_dir / artifact_name)
        if workflow.get("status") != "passed" or workflow.get("executable_workflow") is not True:
            failures.append(f"s2_client_workflow_artifact_not_passed:{path_name}")
        observed = set(workflow.get("operations_observed", []))
        missing = sorted({"createRun", "appendPercept", "startRun", "submitAction", "getStateHead", "getRunTraces", "exportTraces", "replayRun", "cancelRun"} - observed)
        if missing:
            failures.append(f"s2_client_workflow_missing_ops:{path_name}:" + ",".join(missing))
        if workflow.get("action_status") != "Executed":
            failures.append(f"s2_client_workflow_action_not_executed:{path_name}")
        if workflow.get("adapter_executions_before_replay") != workflow.get("adapter_executions_after_replay"):
            failures.append(f"s2_client_workflow_replay_executed_adapter:{path_name}")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    if anti.get("status") != "passed":
        failures.append("s2_anti_drift_failed")
    if anti.get("health_capabilities_or_version_authorize_actions") is not False:
        failures.append("s2_health_capabilities_version_authoritative")
    if anti.get("management_token_authorizes_action_without_gateway") is not False:
        failures.append("s2_management_token_authorized_action")
    event_ids = scenario.get("required_trace_event_ids", {})
    for event in ["daemon.audit", "percepts.appended", "tick.started", "state.committed", "verification.started", "verification.completed", "action.executed", "action.denied", "outcome.recorded", "run.paused", "run.resumed", "run.cancelled_or_stopped"]:
        if not event_ids.get(event):
            failures.append(f"s2_missing_required_trace_event:{event}")
    for trace_id in scenario.get("trace_event_ids", [])[:20]:
        if trace_id and not is_canonical_uuid(trace_id):
            failures.append("s2_trace_event_id_not_canonical_uuid")
            break
    return scenario, failures


def load_s3_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S3"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "message-causal-graph.json",
        "audit-report.json",
        "anti-drift-results.json",
        "runtime-evidence.json",
        "schema-parity.json",
        "schema-parity-rust.json",
        "schema-parity-typescript.json",
        "schema-parity-python.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s3_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s3_artifact:{name}")
    for blocker in scenario.get("blocking_failures", []):
        if blocker not in failures:
            failures.append(blocker)
    if scenario.get("status") != "passed":
        failures.append("s3_scenario_report_failed")
    if len(scenario.get("run_ids", [])) < 2:
        failures.append("s3_missing_parent_child_run_ids")
    if len(scenario.get("message_ids", [])) < 4:
        failures.append("s3_missing_message_ids")
    if len(scenario.get("state_node_ids", [])) < 2 or len(scenario.get("state_hashes", [])) < 2:
        failures.append("s3_missing_parent_child_state_evidence")
    ids_by_event = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S3_REQUIRED_EVENTS if not ids_by_event.get(event))
    if missing_events:
        failures.append("s3_missing_required_trace_events:" + ",".join(missing_events))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S3_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s3_missing_negative_cases:" + ",".join(missing_negatives))
    for case, item in negatives.items():
        if item.get("adapter_executions_before") != item.get("adapter_executions_after") and case != "broad_permission_data_ref_smuggling_denied":
            failures.append(f"s3_denial_reached_adapter:{case}")
        if not item.get("reason_codes"):
            failures.append(f"s3_negative_missing_reason_codes:{case}")
    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    trace_by_id = {trace_record_id(record): record for record in trace_records if trace_record_id(record)}
    expected_negative_kinds = {
        "specialist_external_artifact_publish_denied": "action.denied",
        "unauthorized_recipient_message_denied": "message.rejected",
        "unsupported_message_schema_rejected_before_delivery": "message.rejected",
        "broad_permission_data_ref_smuggling_denied": "delegation.rejected",
        "cross_tenant_message_attempt_rejected": "delegation.rejected",
        "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger": "action.denied",
    }
    expected_reason_text = {
        "unsupported_message_schema_rejected_before_delivery": ["unsupported"],
    }
    for case, item in negatives.items():
        expected_kind = expected_negative_kinds.get(case)
        trace_ids = item.get("trace_event_ids") or []
        if not trace_ids:
            failures.append(f"s3_negative_missing_trace_ids:{case}")
            continue
        for trace_id in trace_ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s3_negative_trace_id_not_canonical:{case}")
                continue
            record = trace_by_id.get(trace_id)
            if record is None:
                failures.append(f"s3_negative_trace_id_missing_from_export:{case}:{trace_id}")
                continue
            if expected_kind and trace_record_kind(record) != expected_kind:
                failures.append(f"s3_negative_trace_wrong_kind:{case}:{trace_record_kind(record)}")
            record_text = json.dumps(record, sort_keys=True)
            for reason in expected_reason_text.get(case, item.get("reason_codes", [])):
                if reason not in record_text:
                    failures.append(f"s3_negative_trace_wrong_reason:{case}:{reason}")
            message_id = item.get("message_id")
            if message_id and message_id not in record_text:
                failures.append(f"s3_negative_trace_wrong_message:{case}:{message_id}")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only":
        failures.append("s3_replay_not_inspect_only")
    if replay.get("side_effects_replayed") is not False or replay.get("side_effects_allowed_default") is not False:
        failures.append("s3_replay_side_effect_suppression_missing")
    if len(replay.get("messages", [])) < 4:
        failures.append("s3_replay_missing_messages")
    lifecycles = {message.get("lifecycle") for message in replay.get("messages", [])}
    for lifecycle in ["queued", "delivered", "consumed", "rejected"]:
        if lifecycle not in lifecycles:
            failures.append(f"s3_replay_missing_message_lifecycle:{lifecycle}")
    if not replay.get("parent_child_runs"):
        failures.append("s3_replay_missing_parent_child_runs")
    if not replay.get("isolation_denials"):
        failures.append("s3_replay_missing_isolation_denials")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    if anti.get("status") != "passed":
        failures.append("s3_anti_drift_failed")
    expected_false = [
        "private_helper_only_e2e",
        "gateway_bypass",
        "specialist_broad_permission_inheritance",
        "hidden_shared_state",
        "replay_side_effects_allowed_default",
        "remote_transport",
        "fleet_governance_or_physical_scope",
    ]
    for key in expected_false:
        if anti.get(key) is not False:
            failures.append(f"s3_anti_drift_expected_false:{key}")
    runtime = read_json(artifact_dir / "runtime-evidence.json")
    delegated = runtime.get("delegated_authority", {})
    if "artifact.publish_external" in delegated.get("allowed_permissions", []):
        failures.append("s3_specialist_delegation_includes_broad_publish_permission")
    state_export = read_json(artifact_dir / "state-export.json")
    state_commit_ids = set(scenario.get("required_trace_event_ids", {}).get("state.committed", []))
    for state_name in ["parent", "child"]:
        state = state_export.get(state_name, {})
        trace_id = state.get("trace_event_id")
        metadata_trace_id = state.get("metadata_trace_event_id")
        if not trace_id or trace_id != metadata_trace_id:
            failures.append(f"s3_state_metadata_trace_mismatch:{state_name}")
        if trace_id not in trace_by_id or trace_record_kind(trace_by_id.get(trace_id, {})) != "state.committed":
            failures.append(f"s3_state_trace_not_committed_event:{state_name}")
        if trace_id not in state_commit_ids:
            failures.append(f"s3_state_trace_missing_from_required_events:{state_name}")
        trace_state_hash = content_hash_string(
            trace_record_kind_payload(trace_by_id.get(trace_id, {})).get("state_hash")
        )
        if state.get("state_hash") != trace_state_hash:
            failures.append(f"s3_state_hash_trace_mismatch:{state_name}")
        if not state.get("state_node_hash"):
            failures.append(f"s3_state_node_hash_missing:{state_name}")
    schema = read_json(artifact_dir / "schema-parity.json")
    if schema.get("status") != "passed":
        failures.append("s3_schema_parity_not_passed")
    rust_schema = schema.get("rust", {})
    typescript_schema = schema.get("typescript", {})
    python_schema = schema.get("python", {})
    if typescript_schema.get("status") != "passed" or typescript_schema.get("executable_check") is not True:
        failures.append("s3_typescript_schema_parity_not_executable")
    if python_schema.get("status") != "passed" or python_schema.get("executable_check") is not True:
        failures.append("s3_python_schema_parity_not_executable")
    missing_python_fields = python_schema.get("missing_canonical_message_fields", [])
    if missing_python_fields:
        failures.append("s3_python_missing_canonical_message_fields:" + ",".join(missing_python_fields))
    canonical_fields = set(rust_schema.get("task_request_message", {}).keys())
    python_present_fields = set(python_schema.get("message_required_fields_present", []))
    missing_present_fields = sorted(canonical_fields - python_present_fields)
    if missing_present_fields:
        failures.append("s3_python_required_fields_do_not_cover_canonical_message:" + ",".join(missing_present_fields))
    if "causal_parent" not in python_present_fields:
        failures.append("s3_python_message_required_fields_missing_causal_parent")
    for callback in ["perceptor", "policy", "trace_subscriber"]:
        if callback not in python_schema.get("callbacks_observed", []):
            failures.append(f"s3_python_callback_missing:{callback}")
    if python_schema.get("actions_proposed") != 0 or python_schema.get("adapter_callbacks_executed") != 0:
        failures.append("s3_python_callback_side_effect_boundary_failed")
    if rust_schema.get("task_request_schema") != "splendor.message.task_request.v1" or rust_schema.get("task_response_schema") != "splendor.message.task_response.v1":
        failures.append("s3_rust_schema_parity_wrong_schema")
    return scenario, failures


def load_s4_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S4"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "registry.json",
        "capabilities.json",
        "work-order-validation.json",
        "placement-decision.json",
        "dispatch-report.json",
        "remote-message-report.json",
        "state-handoff-report.json",
        "trace-sync-report.json",
        "fleet-telemetry.json",
        "trace-export.jsonl",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s4_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s4_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s4_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s4_scenario_failure:{failure}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S4_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s4_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S4_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s4_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S4_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s4_negative_case_not_asserted:{case}")
    same_image = scenario.get("same_image_fleet_evidence", {})
    if same_image.get("all_same") is not True or same_image.get("same_build_target") != "runtime":
        failures.append("s4_same_image_fleet_evidence_missing")
    if len(same_image.get("splendor_services", [])) < 5:
        failures.append("s4_same_image_missing_splendor_services")
    targets = same_image.get("build_targets", {})
    if targets and set(targets.values()) != {"runtime"}:
        failures.append("s4_same_image_build_targets_differ")
    if same_image.get("runner_exception") is not True:
        failures.append("s4_acceptance_runner_exception_missing")
    placement = read_json(artifact_dir / "placement-decision.json")
    if placement.get("status") != "selected" or placement.get("candidate_id") not in scenario.get("node_ids", []):
        failures.append("s4_vpc_placement_not_selected")
    dispatch = read_json(artifact_dir / "dispatch-report.json")
    if dispatch.get("create_run_status") not in {200, 201} or dispatch.get("start_run_status") not in {200, 201}:
        failures.append("s4_dispatch_did_not_create_and_start_resident_run")
    remote = read_json(artifact_dir / "remote-message-report.json")
    if remote.get("delivered", {}).get("delivery_status") != "delivered":
        failures.append("s4_remote_message_not_delivered")
    delivered = remote.get("delivered", {})
    if delivered.get("recipient_validated") is not True or delivered.get("remote_state_mutated") is not False:
        failures.append("s4_remote_receive_validation_missing")
    if delivered.get("work_order_authority_validated") is not True or not str(delivered.get("route_permission", "")).startswith("message.remote.proposal:"):
        failures.append("s4_remote_route_not_work_order_authorized")
    if remote.get("received", {}).get("receive_side_validated") is not True:
        failures.append("s4_remote_message_not_publicly_read")
    if remote.get("duplicate", {}).get("duplicate") is not True:
        failures.append("s4_duplicate_message_not_detected")
    if remote.get("duplicate", {}).get("idempotency_key") != "proposal-once":
        failures.append("s4_duplicate_not_based_on_idempotency_key")
    if remote.get("failed", {}).get("delivery_status") != "failed":
        failures.append("s4_remote_failure_not_trace_linked")
    if remote.get("unsupported_schema", {}).get("status") != 400:
        failures.append("s4_unsupported_schema_not_rejected")
    if remote.get("unauthorized_recipient", {}).get("status") != 403:
        failures.append("s4_unauthorized_recipient_not_rejected")
    handoff = read_json(artifact_dir / "state-handoff-report.json")
    if not handoff.get("exported", {}).get("handoff") or handoff.get("imported", {}).get("accepted") is not True:
        failures.append("s4_state_handoff_export_import_missing")
    if handoff.get("rejected", {}).get("status") not in {400, 403}:
        failures.append("s4_bad_state_handoff_not_rejected")
    if handoff.get("wrong_hash", {}).get("status") != 403:
        failures.append("s4_wrong_hash_handoff_not_rejected")
    if handoff.get("wrong_run", {}).get("status") not in {400, 404}:
        failures.append("s4_wrong_run_handoff_not_rejected")
    if handoff.get("receiver_unchanged_on_failed_import") is not True:
        failures.append("s4_failed_handoff_mutated_receiver_state")
    trace_sync = read_json(artifact_dir / "trace-sync-report.json")
    if trace_sync.get("duplicate_sync", {}).get("duplicate_records", 0) <= 0:
        failures.append("s4_trace_sync_duplicate_not_idempotent")
    if trace_sync.get("tampered_sync", {}).get("status") != 403:
        failures.append("s4_trace_sync_tamper_not_rejected")
    telemetry = read_json(artifact_dir / "fleet-telemetry.json")
    if telemetry.get("authority") != "observational_only":
        failures.append("s4_telemetry_not_observational_only")
    if len(telemetry.get("nodes", [])) < 2 or len(telemetry.get("instances", [])) < 2:
        failures.append("s4_telemetry_missing_node_instance_status")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("remote_messages_resent") is not False:
        failures.append("s4_replay_suppression_missing")
    if replay.get("derived_from_public_replay_api") is not True or not replay.get("replay_id"):
        failures.append("s4_replay_not_from_public_api")
    audit = read_json(artifact_dir / "audit-report.json")
    if not audit.get("events"):
        failures.append("s4_audit_events_missing")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["same_image_fleet", "private_helper_only_e2e", "telemetry_authorizes_dispatch", "gateway_bypass", "replay_side_effects_allowed_default"]:
        if key == "same_image_fleet":
            if anti.get(key) is not True:
                failures.append("s4_anti_drift_same_image_not_true")
        elif anti.get(key) is not False:
            failures.append(f"s4_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or len(scenario.get("node_ids", [])) < 2 or not scenario.get("work_order_ids") or not scenario.get("message_ids"):
        failures.append("s4_missing_required_identity_evidence")
    return scenario, failures


def load_s5_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S5"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "approval-flow.json",
        "policy-bundle-report.json",
        "circuit-breaker-report.json",
        "kill-switch-report.json",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s5_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s5_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s5_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s5_scenario_failure:{failure}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S5_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s5_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S5_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s5_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S5_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s5_negative_case_not_asserted:{case}")
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S5_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s5_missing_required_trace_events:" + ",".join(missing_events))
    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    trace_by_id = {trace_record_id(record): record for record in trace_records if trace_record_id(record)}
    audit = read_json(artifact_dir / "audit-report.json")
    exported = audit.get("manager", {})
    manager_events = exported.get("events", [])
    manager_by_id = {str(event.get("trace_event_id", "")): event for event in manager_events if event.get("trace_event_id")}
    for event_name, ids in event_ids.items():
        if not isinstance(ids, list):
            failures.append(f"s5_trace_event_ids_not_list:{event_name}")
            continue
        for trace_id in ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s5_trace_event_id_not_uuid:{event_name}:{trace_id}")
            if trace_id not in trace_by_id and trace_id not in manager_by_id:
                failures.append(f"s5_trace_event_id_missing_from_exports:{event_name}:{trace_id}")
            if trace_id in trace_by_id and trace_record_kind(trace_by_id[trace_id]) != event_name:
                failures.append(f"s5_trace_event_kind_mismatch:{event_name}:{trace_record_kind(trace_by_id[trace_id])}")
            if trace_id in manager_by_id and manager_by_id[trace_id].get("event_type") != event_name:
                failures.append(f"s5_manager_event_kind_mismatch:{event_name}:{manager_by_id[trace_id].get('event_type')}")
    if not scenario.get("run_ids") or not scenario.get("work_order_ids") or not scenario.get("approval_ids"):
        failures.append("s5_missing_identity_evidence")
    if not scenario.get("state_node_ids") or not scenario.get("state_hashes"):
        failures.append("s5_missing_state_evidence")
    positive = scenario.get("positive_checks", {})
    for key in ["policy_published", "internal_artifact_executed", "external_needs_approval", "adapter_not_called_before_approval", "approved_action_executed_once", "audit_exported", "replay_inspect_only"]:
        if positive.get(key) is not True:
            failures.append(f"s5_positive_check_missing:{key}")
    approval_flow = read_json(artifact_dir / "approval-flow.json")
    grant_evidence = approval_flow.get("grant", {}).get("evidence", {})
    request_approval = approval_flow.get("request", {})
    if grant_evidence.get("decision") != "Granted":
        failures.append("s5_grant_missing_scoped_evidence")
    for field in ["approval_id", "tenant_id", "agent_id", "run_id", "action_id", "action_name", "adapter"]:
        if not grant_evidence.get(field):
            failures.append(f"s5_grant_evidence_missing:{field}")
    for field in ["approval_id", "tenant_id", "agent_id", "run_id", "action_id", "action_name", "adapter"]:
        if request_approval.get(field) and grant_evidence.get(field) != request_approval.get(field):
            failures.append(f"s5_grant_evidence_scope_mismatch:{field}")
    revoked_record = approval_flow.get("revoke", {})
    revoked_evidence = revoked_record.get("evidence", {})
    if revoked_record.get("status") != "revoked" or revoked_evidence.get("revoked") is not True:
        failures.append("s5_revoke_approval_missing_public_evidence")
    if revoked_evidence.get("action_id") != grant_evidence.get("action_id"):
        failures.append("s5_revoked_evidence_action_scope_mismatch")
    if approval_flow.get("expired", {}).get("status") != "Denied":
        failures.append("s5_expired_approval_not_denied")
    if approval_flow.get("revoked", {}).get("status") != "Denied":
        failures.append("s5_revoked_approval_not_denied")
    policy = read_json(artifact_dir / "policy-bundle-report.json")
    if policy.get("published", {}).get("status") != "published" or not policy.get("published", {}).get("envelope", {}).get("signature"):
        failures.append("s5_policy_publish_not_signed")
    if policy.get("revoked_policy_create", {}).get("status") != 403:
        failures.append("s5_revoked_policy_create_not_forbidden")
    runtime_expired = policy.get("runtime_expired_policy", {})
    runtime_start = runtime_expired.get("start", {})
    ttl_run_id = runtime_expired.get("run_id")
    ttl_action_id = runtime_expired.get("action_id")
    ttl_action_name = runtime_expired.get("action_name")
    ttl_denial = runtime_expired.get("denial", {})
    ttl_denial_verification = ttl_denial.get("verification", {})
    ttl_denial_artifacts = ttl_denial_verification.get("artifacts", {})
    if runtime_expired.get("create", {}).get("status") != 200 or runtime_start.get("status") != 200:
        failures.append("s5_policy_expiry_not_runtime_exercised")
    if ttl_denial.get("action_id") != ttl_action_id or ttl_denial.get("status") not in {"Denied", "NeedsIntervention"}:
        failures.append("s5_policy_expiry_missing_action_level_outcome")
    if runtime_expired.get("reason_code") != "policy_expired" or "policy_expired" not in ttl_denial_verification.get("reasons", []):
        failures.append("s5_policy_expiry_missing_reason_code")
    if ttl_denial_artifacts.get("policy_bundle_id") != "policy_uc_e2e_s5_runtime_expiry" or ttl_denial_artifacts.get("action") != "artifact.publish_external":
        failures.append("s5_policy_expiry_action_artifacts_mismatch")
    policy_expired_records = [trace_by_id[trace_id] for trace_id in event_ids.get("policy.expired", []) if trace_id in trace_by_id]
    ttl_policy_expired_records = [
        record for record in policy_expired_records
        if trace_record_kind_payload(record).get("policy_bundle_id") == "policy_uc_e2e_s5_runtime_expiry"
        and trace_record_kind_payload(record).get("action") == ttl_action_name == "artifact.publish_external"
        and record.get("payload", {}).get("run_id") == ttl_run_id
        and record.get("payload", {}).get("identity", {}).get("action_id") == ttl_action_id
    ]
    if not ttl_policy_expired_records:
        failures.append("s5_policy_expired_trace_not_linked_to_ttl_action")
    ttl_action_records = [
        trace_by_id[trace_id]
        for trace_id in event_ids.get("action.denied", []) + event_ids.get("action.needs_intervention", [])
        if trace_id in trace_by_id
        and trace_by_id[trace_id].get("payload", {}).get("run_id") == ttl_run_id
        and trace_by_id[trace_id].get("payload", {}).get("identity", {}).get("action_id") == ttl_action_id
    ]
    if not any(
        "policy_expired" in json.dumps(trace_record_kind_payload(record), sort_keys=True)
        and "artifact.publish_external" in json.dumps(trace_record_kind_payload(record), sort_keys=True)
        for record in ttl_action_records
    ):
        failures.append("s5_policy_expired_action_denial_trace_missing")
    intervention_records = [trace_by_id[trace_id] for trace_id in event_ids.get("action.needs_intervention", []) if trace_id in trace_by_id]
    if not any(
        "approval_policy_expired" in json.dumps(trace_record_kind_payload(record), sort_keys=True)
        or "intervention_required" in json.dumps(trace_record_kind_payload(record), sort_keys=True)
        for record in intervention_records
    ):
        failures.append("s5_verifier_uncertainty_trace_not_explicit")
    breaker = read_json(artifact_dir / "circuit-breaker-report.json")
    if breaker.get("blocked_action", {}).get("status") != "Denied":
        failures.append("s5_circuit_breaker_action_not_denied")
    created_breaker_id = breaker.get("created", {}).get("breaker_id")
    manager_payload = breaker.get("manager_sync_payload", {})
    manager_record = manager_payload.get("breaker_record", {})
    synced_ids = set(breaker.get("synced", {}).get("breaker_ids", []))
    denied_breaker = breaker.get("blocked_action", {}).get("verification", {}).get("artifacts", {}).get("circuit_breaker", {})
    denied_breaker_id = denied_breaker.get("breaker_id") or denied_breaker.get("circuit_breaker", {}).get("breaker_id")
    if not created_breaker_id or created_breaker_id not in synced_ids or denied_breaker_id != created_breaker_id:
        failures.append("s5_circuit_breaker_not_manager_correlated")
    if manager_record.get("breaker_id") != created_breaker_id or manager_record.get("trace_event_id") != breaker.get("created", {}).get("trace_event_id"):
        failures.append("s5_circuit_breaker_sync_payload_not_manager_derived")
    if not manager_payload.get("circuit_breakers") or manager_payload.get("reason") != "manager_propagated_breaker":
        failures.append("s5_circuit_breaker_sync_payload_missing")
    if breaker.get("synced", {}).get("trace_event_id") not in trace_by_id:
        failures.append("s5_circuit_breaker_sync_trace_missing")
    if breaker.get("clear_wrong_scope", {}).get("status") != 403:
        failures.append("s5_clear_breaker_wrong_scope_not_forbidden")
    kill = read_json(artifact_dir / "kill-switch-report.json")
    if kill.get("activated", {}).get("propagation_acknowledged") is not True:
        failures.append("s5_kill_switch_not_acknowledged")
    activated_kill = kill.get("activated", {})
    if activated_kill.get("target_derived_from_registry") is not True or not activated_kill.get("target_instance_id") or activated_kill.get("cancel_payload_schema") != "splendor.daemon.lifecycle_request.v1":
        failures.append("s5_kill_switch_target_not_registry_derived")
    for row in read_jsonl(artifact_dir / "api-traffic.ndjson"):
        if row.get("operation_id") != "activateKillSwitch":
            continue
        request_keys = set((row.get("request") or {}).keys())
        if {"target_daemon_url", "cancel_payload"} & request_keys:
            failures.append("s5_kill_switch_request_contains_caller_supplied_target_or_payload")
    if kill.get("missing_ack", {}).get("fail_closed") is not True:
        failures.append("s5_kill_switch_missing_ack_not_fail_closed")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("external_publish_replayed") is not False:
        failures.append("s5_replay_suppression_missing")
    if "requested" not in replay.get("approval_lifecycles", []) or "granted" not in replay.get("approval_lifecycles", []):
        failures.append("s5_replay_missing_approval_explanation")
    if exported.get("exported") is not True or not exported.get("approval_ids") or not exported.get("policy_bundle_ids") or not exported.get("circuit_breaker_ids") or not exported.get("kill_switch_ids"):
        failures.append("s5_governance_audit_missing_links")
    required_manager_events = {"circuit_breaker.tripped", "circuit_breaker.sync_payload.exported", "circuit_breaker.cleared", "kill_switch.activated", "governance.audit.exported"}
    missing_manager_events = sorted(required_manager_events - {event.get("event_type") for event in manager_events})
    if missing_manager_events:
        failures.append("s5_governance_audit_missing_event_types:" + ",".join(missing_manager_events))
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "governance_plane_direct_runtime_mutation", "broad_action_authority", "replay_side_effects_allowed_default"]:
        if anti.get(key) is not False:
            failures.append(f"s5_anti_drift_expected_false:{key}")
    return scenario, failures


def load_s6_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S6"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "device-profile.json",
        "device-status.json",
        "policy-cache-status.json",
        "cloud-helper-message.json",
        "cloud-helper-proposal.json",
        "device-safety-evidence.json",
        "operator-intervention.json",
        "trace-sync-report.json",
        "device-sim-counters.json",
        "security-negatives.json",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s6_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s6_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s6_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s6_scenario_failure:{failure}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S6_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s6_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S6_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s6_missing_negative_cases:" + ",".join(missing_negatives))
    missing_security_negatives = sorted(S6_REQUIRED_SECURITY_NEGATIVES - set(negatives))
    if missing_security_negatives:
        failures.append("s6_missing_security_negative_cases:" + ",".join(missing_security_negatives))
    for case in (S6_REQUIRED_NEGATIVES | S6_REQUIRED_SECURITY_NEGATIVES) & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s6_negative_case_not_asserted:{case}")
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S6_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s6_missing_required_trace_events:" + ",".join(missing_events))
    for event_name, ids in event_ids.items():
        if not isinstance(ids, list):
            failures.append(f"s6_trace_event_ids_not_list:{event_name}")
            continue
        for trace_id in ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s6_trace_event_id_not_uuid:{event_name}:{trace_id}")
    profile = read_json(artifact_dir / "device-profile.json")
    profile_body = profile.get("profile", profile)
    if profile_body.get("device_kind") != "drone_sim" or profile_body.get("runtime_mode") != "resident":
        failures.append("s6_device_profile_not_resident_drone_sim")
    forbidden = set(profile_body.get("forbidden_action_classes", []))
    if not {"set_motor_pwm", "disable_firmware_safety", "bypass_collision_avoidance", "ignore_emergency_stop"} <= forbidden:
        failures.append("s6_device_profile_missing_forbidden_action_classes")
    allowed = set(profile_body.get("allowed_physical_actions", []))
    if not {"read_battery", "read_sensor_summary", "inspect_zone", "move_to_waypoint", "capture_image", "return_to_base", "upload_trace_summary"} <= allowed:
        failures.append("s6_device_profile_missing_high_level_actions")
    cache = read_json(artifact_dir / "policy-cache-status.json")
    if cache.get("loaded") is not True or cache.get("expired") is not False:
        failures.append("s6_policy_cache_status_not_loaded")
    helper = read_json(artifact_dir / "cloud-helper-proposal.json")
    public_message = read_json(artifact_dir / "cloud-helper-message.json")
    helper_message = helper.get("message", {})
    helper_payload = helper.get("proposal", {})
    if helper_payload.get("direct_actuator_authority") is not False:
        failures.append("s6_cloud_helper_has_direct_actuator_authority")
    for field in ["message_id", "source_agent_id", "target_agent_id", "run_id", "schema", "causal_parent", "created_at"]:
        if not helper_message.get(field):
            failures.append(f"s6_cloud_helper_missing_typed_message_field:{field}")
    if helper_message.get("message_id") not in scenario.get("message_ids", []):
        failures.append("s6_cloud_helper_message_id_missing_from_scenario")
    if helper_message.get("schema") != "splendor.message.proposal_request.v1":
        failures.append("s6_cloud_helper_wrong_message_schema")
    if helper_message.get("requires_response") is not False:
        failures.append("s6_cloud_helper_requires_response_unexpected")
    if public_message.get("work_order_submit", {}).get("accepted") is not True:
        failures.append("s6_cloud_helper_work_order_not_accepted_by_manager")
    delivery = public_message.get("delivery", {})
    received = public_message.get("received", {})
    if delivery.get("message_id") != helper_message.get("message_id"):
        failures.append("s6_cloud_helper_public_delivery_message_id_mismatch")
    if delivery.get("delivery_status") != "delivered":
        failures.append("s6_cloud_helper_public_delivery_not_delivered")
    if delivery.get("receive_side_validated") is not True:
        failures.append("s6_cloud_helper_public_delivery_not_receive_validated")
    if delivery.get("remote_state_mutated") is not False:
        failures.append("s6_cloud_helper_public_delivery_mutated_remote_state")
    if received.get("message_id") != helper_message.get("message_id"):
        failures.append("s6_cloud_helper_public_read_message_id_mismatch")
    if public_message.get("manager_audit_contains_message_id") is not True:
        failures.append("s6_cloud_helper_message_missing_from_manager_audit")
    if public_message.get("trace_payload_contains_message_id") is not True:
        failures.append("s6_cloud_helper_message_id_missing_from_trace_payload")
    if public_message.get("trace_payload_contains_proposal_id") is not True:
        failures.append("s6_cloud_helper_proposal_id_missing_from_trace_payload")
    if helper_payload.get("proposal_id") != helper.get("local_validation_inputs", {}).get("inspect_zone", {}).get("cloud_helper_proposal_id"):
        failures.append("s6_inspect_zone_not_linked_to_cloud_helper_proposal")
    if helper.get("local_validation_outcomes", {}).get("inspect_zone", {}).get("status") != "Executed":
        failures.append("s6_inspect_zone_not_executed_through_physical_endpoint")
    if helper.get("direct_attempt", {}).get("status") != "Denied":
        failures.append("s6_cloud_helper_direct_attempt_not_denied")
    safety = read_json(artifact_dir / "device-safety-evidence.json")
    if safety.get("positive", {}).get("safe_actions_executed") is not True:
        failures.append("s6_safe_high_level_actions_not_executed")
    safe_actions = safety.get("safe_actions", {})
    if safe_actions.get("inspect_zone", {}).get("status") != "Executed":
        failures.append("s6_safety_evidence_missing_inspect_zone_execution")
    denials = safety.get("denials", {})
    expected_denials = {
        "geofence": ("Denied", "geofence_violation"),
        "low_battery": ("NeedsIntervention", "battery_below_minimum"),
        "expired_policy": ("Denied", "policy_cache_expired"),
        "cloud_direct": ("Denied", "cloud_helper_direct_authority_denied"),
    }
    for key, (expected_status, expected_reason) in expected_denials.items():
        if not denials.get(key):
            failures.append(f"s6_missing_safety_denial:{key}")
        elif denials.get(key, {}).get("status") != expected_status:
            failures.append(f"s6_safety_denial_wrong_status:{key}")
        elif expected_reason not in denials.get(key, {}).get("verification", {}).get("reasons", []):
            failures.append(f"s6_safety_denial_missing_reason_code:{key}:{expected_reason}")
        elif denials.get(key, {}).get("verification", {}).get("artifacts", {}).get("source") != "safety_verifier":
            failures.append(f"s6_safety_denial_not_from_safety_verifier:{key}")
    operator = read_json(artifact_dir / "operator-intervention.json")
    if operator.get("ambiguous", {}).get("status") != "Denied":
        failures.append("s6_ambiguous_action_not_denied")
    elif operator.get("ambiguous", {}).get("verification", {}).get("artifacts", {}).get("source") != "safety_verifier":
        failures.append("s6_ambiguous_action_not_from_safety_verifier")
    if operator.get("grant", {}).get("status") != "granted" or operator.get("granted_capture", {}).get("status") != "Executed":
        failures.append("s6_operator_grant_did_not_scope_execution")
    if operator.get("wrong_scope", {}).get("status") != 403 or operator.get("expired", {}).get("status") != 403:
        failures.append("s6_operator_scope_or_expiry_not_rejected")
    trace_sync = read_json(artifact_dir / "trace-sync-report.json")
    if trace_sync.get("completed", {}).get("accepted") is not True:
        failures.append("s6_trace_sync_not_completed")
    if trace_sync.get("tamper", {}).get("accepted") is not False or trace_sync.get("reordered", {}).get("accepted") is not False:
        failures.append("s6_trace_sync_tamper_or_reorder_not_detected")
    if trace_sync.get("tamper", {}).get("reason_code") != "trace_sync_hash_chain_mismatch":
        failures.append("s6_trace_sync_tamper_wrong_reason")
    if trace_sync.get("tampered_record_mutation") != "prev_event_hash" or trace_sync.get("reordered_records") is not True:
        failures.append("s6_trace_sync_not_mutating_real_records")
    simulator = read_json(artifact_dir / "device-sim-counters.json")
    simulator_evidence = {item.get("label"): item for item in simulator.get("evidence", [])}
    missing_sim_labels = sorted(set(S6_REQUIRED_SIMULATED_ACTION_LABELS) - set(simulator_evidence))
    if missing_sim_labels:
        failures.append("s6_missing_simulator_counter_labels:" + ",".join(missing_sim_labels))
    for label, expected_delta in S6_REQUIRED_SIMULATED_ACTION_LABELS.items():
        item = simulator_evidence.get(label, {})
        if item.get("expected_sim_delta") != expected_delta or item.get("total_delta") != expected_delta:
            failures.append(f"s6_simulator_counter_delta_mismatch:{label}")
        if expected_delta == 1 and item.get("action_delta") != 1:
            failures.append(f"s6_simulator_action_delta_mismatch:{label}")
        if label in S6_DENIED_SIMULATOR_LABELS and item.get("total_delta") != 0:
            failures.append(f"s6_denied_action_reached_simulator:{label}")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("simulator_actuator_calls_replayed") is not False:
        failures.append("s6_replay_suppression_missing")
    if replay.get("simulator_counter_before") != replay.get("simulator_counter_after"):
        failures.append("s6_replay_changed_simulator_counters")
    if simulator.get("before_replay") != simulator.get("after_replay"):
        failures.append("s6_device_sim_counter_artifact_replay_changed")
    security = read_json(artifact_dir / "security-negatives.json")
    if security.get("missing_credential_status", {}).get("status") not in {401, 403} or security.get("missing_credential_action", {}).get("status") not in {401, 403}:
        failures.append("s6_missing_credential_not_rejected")
    for key in ["wrong_audience_status", "wrong_tenant_status", "wrong_audience_action", "wrong_tenant_action"]:
        if security.get(key, {}).get("status") != 403:
            failures.append(f"s6_security_negative_not_forbidden:{key}")
    audit = read_json(artifact_dir / "audit-report.json")
    if audit.get("cloud_helper_direct_action_authorized") is not False or audit.get("cloud_helper_authority") != "proposal_only":
        failures.append("s6_audit_does_not_prove_cloud_helper_proposal_only")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "raw_physical_action_accepted", "cloud_helper_direct_actuator_authority", "replay_side_effects_allowed_default"]:
        if anti.get(key) is not False:
            failures.append(f"s6_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes") or not scenario.get("work_order_ids") or not scenario.get("node_ids"):
        failures.append("s6_missing_identity_state_work_order_evidence")
    return scenario, failures


def load_s7_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S7"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "tenant-data-fixtures.json",
        "work-order-validation.json",
        "message-flow.json",
        "artifact-report.json",
        "data-scope-report.json",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s7_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s7_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s7_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s7_scenario_failure:{failure}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S7_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s7_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S7_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s7_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S7_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s7_negative_case_not_asserted:{case}")
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S7_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s7_missing_required_trace_events:" + ",".join(missing_events))
    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    trace_by_id = {trace_record_id(record): record for record in trace_records if trace_record_id(record)}
    trace_text = json.dumps(trace_records, sort_keys=True)
    fixtures = read_json(artifact_dir / "tenant-data-fixtures.json")
    protected = [
        tenant.get("protected_raw_fixture", "")
        for tenant in fixtures.get("tenants", {}).values()
        if tenant.get("protected_raw_fixture")
    ]
    for raw in protected:
        if raw in trace_text:
            failures.append("s7_trace_export_contains_raw_protected_fixture")
    artifact = read_json(artifact_dir / "artifact-report.json")
    internal = artifact.get("internal_artifact_evidence", {})
    if artifact.get("internal_artifact", {}).get("status") != "Executed":
        failures.append("s7_internal_artifact_not_executed")
    if not internal.get("action_id") or not internal.get("artifact_path") or not internal.get("integrity") or not internal.get("tenant_id"):
        failures.append("s7_internal_artifact_missing_identity_path_or_integrity")
    elif not str(internal.get("artifact_path", "")).startswith(f"artifact://{internal.get('tenant_id')}/"):
        failures.append("s7_internal_artifact_path_not_tenant_scoped")
    internal_trace_id = internal.get("trace_event_id")
    if not internal_trace_id:
        failures.append("s7_internal_artifact_missing_trace_event_id")
    elif internal_trace_id not in event_ids.get("artifact.created", []):
        failures.append("s7_internal_artifact_trace_id_not_required_artifact_created")
    elif internal_trace_id not in trace_by_id:
        failures.append("s7_internal_artifact_trace_id_missing_from_export")
    else:
        payload = trace_record_kind_payload(trace_by_id[internal_trace_id])
        action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
        output = payload.get("outcome", {}) if isinstance(payload.get("outcome"), dict) else {}
        if trace_record_kind(trace_by_id[internal_trace_id]) != "action.executed" or action.get("name") != "artifact.create_internal":
            failures.append("s7_internal_artifact_trace_not_create_execution")
        if output.get("artifact_path") != internal.get("artifact_path"):
            failures.append("s7_internal_artifact_trace_path_mismatch")
        if output.get("tenant_id") != internal.get("tenant_id"):
            failures.append("s7_internal_artifact_trace_tenant_mismatch")
        if output.get("integrity") != internal.get("integrity"):
            failures.append("s7_internal_artifact_trace_integrity_mismatch")
    if internal.get("outcome_action_id") and internal.get("outcome_action_id") != internal.get("action_id"):
        failures.append("s7_internal_artifact_outcome_action_mismatch")
    if internal.get("outcome_artifact_path") and internal.get("outcome_artifact_path") != internal.get("artifact_path"):
        failures.append("s7_internal_artifact_outcome_path_mismatch")
    if internal.get("outcome_integrity") and internal.get("outcome_integrity") != internal.get("integrity"):
        failures.append("s7_internal_artifact_outcome_integrity_mismatch")
    if artifact.get("publish_without_approval", {}).get("status") != "NeedsApproval":
        failures.append("s7_publish_without_approval_not_paused")
    if artifact.get("approved_publish", {}).get("status") != "Executed":
        failures.append("s7_approved_publish_not_executed")
    if artifact.get("approved_publish", {}).get("action_id") != artifact.get("publish_without_approval", {}).get("action_id"):
        failures.append("s7_approval_action_id_mismatch")
    publish_evidence = artifact.get("approved_publish_evidence", {})
    if not publish_evidence.get("integrity"):
        failures.append("s7_approved_publish_missing_integrity")
    publish_trace_id = publish_evidence.get("trace_event_id")
    if not publish_trace_id:
        failures.append("s7_approved_publish_missing_trace_event_id")
    elif publish_trace_id not in event_ids.get("artifact.publish.executed", []):
        failures.append("s7_approved_publish_trace_id_not_required_publish_executed")
    elif publish_trace_id not in trace_by_id:
        failures.append("s7_approved_publish_trace_id_missing_from_export")
    else:
        payload = trace_record_kind_payload(trace_by_id[publish_trace_id])
        action = payload.get("action", {}) if isinstance(payload.get("action"), dict) else {}
        params = action.get("params", {}) if isinstance(action.get("params"), dict) else {}
        output = payload.get("outcome", {}) if isinstance(payload.get("outcome"), dict) else {}
        if trace_record_kind(trace_by_id[publish_trace_id]) != "action.executed" or action.get("name") != "artifact.publish_external":
            failures.append("s7_approved_publish_trace_not_publish_execution")
        trace_publish_path = output.get("publish_ref") or output.get("artifact_path") or params.get("publish_ref")
        if trace_publish_path != publish_evidence.get("artifact_path"):
            failures.append("s7_approved_publish_trace_path_mismatch")
        trace_tenant_id = output.get("tenant_id")
        if not trace_tenant_id and isinstance(trace_publish_path, str) and trace_publish_path.startswith("artifact://"):
            trace_tenant_id = trace_publish_path.removeprefix("artifact://").split("/", 1)[0]
        if trace_tenant_id != publish_evidence.get("tenant_id"):
            failures.append("s7_approved_publish_trace_tenant_mismatch")
        if output.get("integrity") != publish_evidence.get("integrity"):
            failures.append("s7_approved_publish_trace_integrity_mismatch")
    if artifact.get("collision", {}).get("status") != "Denied":
        failures.append("s7_artifact_collision_not_denied")
    if artifact.get("specialist_publish_denial", {}).get("status") != "Denied":
        failures.append("s7_specialist_publish_not_denied")
    data_scope = read_json(artifact_dir / "data-scope-report.json")
    if data_scope.get("tenant_b_denial", {}).get("status") != "Denied":
        failures.append("s7_tenant_b_data_ref_not_denied")
    if data_scope.get("manager_permission_denial", {}).get("status") != 403:
        failures.append("s7_manager_credential_did_not_fail_daemon_action_auth")
    if data_scope.get("adapter_executions_before") != data_scope.get("adapter_executions_after"):
        failures.append("s7_denied_data_or_artifact_reached_adapter")
    message = read_json(artifact_dir / "message-flow.json")
    if message.get("request", {}).get("delivery_status") != "delivered" or message.get("response", {}).get("delivery_status") != "delivered":
        failures.append("s7_task_messages_not_delivered")
    request_send = message.get("request", {}).get("trace_event_id")
    request_read = message.get("request_read", {}).get("read_trace_event_id")
    response_send = message.get("response", {}).get("trace_event_id")
    response_read = message.get("response_read", {}).get("read_trace_event_id")
    if message.get("request_read", {}).get("receive_side_validated") is not True or message.get("response_read", {}).get("receive_side_validated") is not True:
        failures.append("s7_task_messages_not_read_validated")
    if not request_read or not response_read or request_read == request_send or response_read == response_send:
        failures.append("s7_missing_explicit_distinct_receive_trace")
    if message.get("smuggling_denial", {}).get("status") != 403:
        failures.append("s7_smuggling_message_not_rejected")
    work_orders = read_json(artifact_dir / "work-order-validation.json")
    specialist = work_orders.get("specialist", {})
    if "artifact.publish_external" in specialist.get("allowed_actions", []) or "artifact.publish_external" in specialist.get("allowed_permissions", []):
        failures.append("s7_specialist_work_order_overbroad")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("external_publish_replayed") is not False or replay.get("raw_payloads_absent") is not True:
        failures.append("s7_replay_suppression_or_redaction_missing")
    if replay.get("adapter_executions_before_replay") != replay.get("adapter_executions_after_replay"):
        failures.append("s7_replay_changed_adapter_execution_count")
    before_counts = replay.get("action_execution_counts_before_replay")
    after_counts = replay.get("action_execution_counts_after_replay")
    if not isinstance(before_counts, dict) or not isinstance(after_counts, dict):
        failures.append("s7_replay_missing_action_execution_counts")
    elif before_counts != after_counts:
        failures.append("s7_replay_changed_action_execution_counts")
    else:
        for action_name in ["data.read_fixture", "artifact.create_internal", "artifact.publish_external"]:
            if action_name not in before_counts:
                failures.append(f"s7_replay_missing_action_execution_count:{action_name}")
        if before_counts.get("artifact.publish_external", 0) < 1:
            failures.append("s7_replay_proof_missing_orchestrator_publish_execution")
    if not replay.get("orchestrator_replay", {}).get("replay_id"):
        failures.append("s7_replay_missing_orchestrator_replay_id")
    if replay.get("approved_publish_artifact_path") != artifact.get("approved_publish_evidence", {}).get("artifact_path"):
        failures.append("s7_replay_publish_artifact_path_mismatch")
    if replay.get("approved_publish_trace_event_id") != artifact.get("approved_publish_evidence", {}).get("trace_event_id"):
        failures.append("s7_replay_publish_trace_id_mismatch")
    if replay.get("internal_artifact_trace_event_id") != artifact.get("internal_artifact_evidence", {}).get("trace_event_id"):
        failures.append("s7_replay_internal_artifact_trace_id_mismatch")
    if replay.get("cross_tenant_replay", {}).get("status") != 403:
        failures.append("s7_cross_tenant_replay_not_rejected")
    audit = read_json(artifact_dir / "audit-report.json")
    if not audit.get("in_scope_data_refs") or not audit.get("denied_data_refs"):
        failures.append("s7_audit_missing_data_ref_scope_evidence")
    if set(["message.sent", "message.received"]) - set(event_ids):
        failures.append("s7_missing_message_trace_evidence")
    elif set(event_ids.get("message.sent", [])) & set(event_ids.get("message.received", [])):
        failures.append("s7_message_receive_trace_reuses_send_trace")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "specialist_broad_permission_inheritance", "manager_credential_authorizes_action", "trace_export_without_redaction_allowed", "replay_side_effects_allowed_default"]:
        if anti.get(key) is not False:
            failures.append(f"s7_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes") or not scenario.get("work_order_ids") or not scenario.get("message_ids") or not scenario.get("approval_ids"):
        failures.append("s7_missing_identity_state_message_approval_evidence")
    return scenario, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--compose-file", required=True)
    args = parser.parse_args()

    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S0"
    contract = read_json(report_dir / "contract-status.json")
    anti = read_json(report_dir / "anti-drift-results.json")
    seed = read_json(artifact_dir / "fixture-seed.json")
    public_boundary = read_json(artifact_dir / "public-boundary.json")

    blocking = []
    if contract.get("status") != "passed":
        blocking.append("contract_status_failed")
    if anti.get("status") != "passed":
        blocking.append("anti_drift_status_failed")
    if public_boundary.get("status") != "passed":
        blocking.append("public_boundary_evidence_failed")

    artifact_paths = write_s0_artifacts(artifact_dir, contract, anti, seed, public_boundary)
    commands_log = artifact_dir / "commands.log"
    if not commands_log.exists():
        blocking.append("missing_commands_log")
    else:
        artifact_paths.append(str(commands_log))
    artifact_paths.append(str(artifact_dir / "fixture-seed.json"))
    artifact_paths.append(str(artifact_dir / "public-boundary.json"))
    artifact_paths.append(str(artifact_dir / "api-traffic.ndjson"))
    blocking.extend(validate_required_s0_artifacts(artifact_dir))

    topology_hash = digest_file(Path(args.compose_file))
    s0_scenario = {
        "id": "UC-E2E-S0",
        "status": "passed" if not blocking else "failed",
        "fr_coverage": ["UC-E2E-S0-acceptance-harness", "FR-0.1-05", "FR-0.1-08"],
        "components": ["OpenAPI", "reporting", "anti-drift", "fixtures", "Docker Compose topology"],
        "positive_evidence": [
            "contract-status.json present and passing for current local daemon operation IDs",
            "public-boundary.json proves /health and /capabilities were called through documented loopback daemon HTTP endpoints with caller credentials",
            "fixture-seed.json written with deterministic digest",
            "report.json/report.md generated from executable checks",
        ],
        "negative_evidence": [
            "anti-drift negative fixtures fail for direct adapter execution, private helper E2E claims, anonymous non-dev calls, missing replay suppression evidence, and low-level physical allowed actions"
        ],
        "replay_evidence": ["report schema includes replay mode, side-effect suppression, and replay artifact fields"],
        "replay_mode": "inspect_only_schema_required",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": anti.get("self_test", {}).get("required_rules", []),
        "run_ids": [],
        "trace_event_ids": [],
        "state_node_ids": [],
        "state_hashes": [],
        "message_ids": [],
        "work_order_ids": [seed.get("ids", {}).get("work_order_id", "")],
        "approval_ids": [],
        "node_ids": [seed.get("ids", {}).get("node_id", "")],
        "artifact_paths": artifact_paths,
    }

    scenarios = [s0_scenario]
    s1_scenario, s1_failures = load_s1_scenario(report_dir)
    s2_scenario, s2_failures = load_s2_scenario(report_dir)
    s3_scenario, s3_failures = load_s3_scenario(report_dir)
    s4_scenario, s4_failures = load_s4_scenario(report_dir)
    s5_scenario, s5_failures = load_s5_scenario(report_dir)
    s6_scenario, s6_failures = load_s6_scenario(report_dir)
    s7_scenario, s7_failures = load_s7_scenario(report_dir)
    active_ids: set[str] = set()
    if args.scenario == "UC-E2E-S1" or args.mode == "all":
        active_ids.add("UC-E2E-S1")
        if s1_scenario is None:
            blocking.append("missing_uc_e2e_s1_scenario_report")
        else:
            scenarios.append(s1_scenario)
            blocking.extend(s1_failures)
    if args.scenario == "UC-E2E-S2" or args.mode == "all":
        active_ids.add("UC-E2E-S2")
        if s2_scenario is None:
            blocking.append("missing_uc_e2e_s2_scenario_report")
        else:
            scenarios.append(s2_scenario)
            blocking.extend(s2_failures)
    if args.scenario == "UC-E2E-S3" or args.mode == "all":
        active_ids.add("UC-E2E-S3")
        if s3_scenario is None:
            blocking.append("missing_uc_e2e_s3_scenario_report")
        else:
            scenarios.append(s3_scenario)
            blocking.extend(s3_failures)
    if args.scenario == "UC-E2E-S4" or args.mode == "all":
        active_ids.add("UC-E2E-S4")
        if s4_scenario is None:
            blocking.append("missing_uc_e2e_s4_scenario_report")
        else:
            scenarios.append(s4_scenario)
            blocking.extend(s4_failures)
    if args.scenario == "UC-E2E-S5" or args.mode == "all":
        active_ids.add("UC-E2E-S5")
        if s5_scenario is None:
            blocking.append("missing_uc_e2e_s5_scenario_report")
        else:
            scenarios.append(s5_scenario)
            blocking.extend(s5_failures)
    if args.scenario == "UC-E2E-S6" or args.mode == "all":
        active_ids.add("UC-E2E-S6")
        if s6_scenario is None:
            blocking.append("missing_uc_e2e_s6_scenario_report")
        else:
            scenarios.append(s6_scenario)
            blocking.extend(s6_failures)
    if args.scenario == "UC-E2E-S7" or args.mode == "all":
        active_ids.add("UC-E2E-S7")
        if s7_scenario is None:
            blocking.append("missing_uc_e2e_s7_scenario_report")
        else:
            scenarios.append(s7_scenario)
            blocking.extend(s7_failures)
    blocked_ids = [sid for sid in FUTURE_SCENARIOS if sid not in active_ids]

    report = {
        "suite_id": "splendor-use-case-e2e-through-0.1",
        "suite_version": "0.1-s7-data-isolation-artifacts",
        "source_revision": git_revision(root),
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "container_topology_hash": topology_hash,
        "topology_identifier": "docker-compose.acceptance.yml:S0-static-runner-v1",
        "commands": [
            "bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --contract-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S2",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S3",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S4",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S5",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S6",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S7",
            "docker compose -f tests/e2e/use-cases/docker-compose.acceptance.yml config",
        ],
        "api_contract_versions": {
            "openapi": contract.get("openapi_declared_version", "unknown"),
            "rust_crates": text_version(root / "Cargo.toml"),
            "python_sdk": text_version(root / "python/pyproject.toml"),
            "typescript_client": package_version(root / "typescript/packages/client/package.json"),
        },
        "component_versions": {
            "workspace_package": package_version(root / "package.json"),
            "typescript_types": package_version(root / "typescript/packages/types/package.json"),
            "docker_compose_available": os.environ.get("SPLENDOR_E2E_DOCKER_COMPOSE", "not_captured"),
            "public_boundary": public_boundary.get("status", "unknown"),
        },
        "contract_status": {
            "status": contract.get("status"),
            "blocked_not_yet_covered": contract.get("blocked_not_yet_covered", []),
            "missing_core_operation_ids": contract.get("missing_core_operation_ids", []),
        },
        "anti_drift_status": {
            "status": anti.get("status"),
            "self_test": anti.get("self_test", {}),
            "findings": anti.get("findings", []),
        },
        "scenarios": scenarios + [blocked_future_scenario(sid) for sid in blocked_ids],
        "blocking_failures": blocking,
        "non_goal_observations": [
            "S0 does not mark later scenarios passing; UC-E2E-S1 is included only when executable scenario evidence is present.",
            "UC-E2E-S2 validates the local management API/client contract only when raw HTTP, TypeScript, Python SDK, and splendorctl executable workflow evidence is present.",
            "UC-E2E-S3 validates local multi-agent delegation through public crate APIs and splendorctl replay only; it does not claim daemon message API coverage.",
            "UC-E2E-S4 validates fleet dispatch through public manager and resident daemon HTTP APIs with same-image Splendor services.",
            "UC-E2E-S5 validates governance through public manager and daemon HTTP APIs without enterprise UI or direct governance-plane runtime mutation.",
            "UC-E2E-S6 validates physical/edge orchestration through public resident-edge daemon HTTP APIs without low-level robot control.",
            "UC-E2E-S7 validates data-local artifact and cross-tenant isolation through public manager and resident daemon HTTP APIs without enterprise data workspace UI.",
            "S8-S10 remain blocked until their own executable scenario evidence is present.",
            "No production OAuth/PKI, Kubernetes, SaaS UI, marketplace, real robot/cloud/database dependency, or low-level physical control is added.",
            "Daemon startup remains loopback-only; compose shares the daemon network namespace and does not publish daemon ports.",
        ],
        "human_summary_path": str(report_dir / "report.md"),
    }

    blocking.extend(validate_report_shape(report))
    report["blocking_failures"] = blocking
    report["scenarios"][0]["status"] = "passed" if not blocking else "failed"

    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (report_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"status": "passed" if not blocking else "failed", "report": str(report_path)}, indent=2))
    return 0 if not blocking else 1


if __name__ == "__main__":
    raise SystemExit(main())
