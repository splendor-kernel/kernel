#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from source_identity import (
    SOURCE_TREE_DIGEST_ALGORITHM,
    clean_source_tree_digest,
    source_tree_identity,
)


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
    "invalid_v2_task_request_payload_rejected_before_delivery",
    "broad_permission_data_ref_smuggling_denied",
    "cross_tenant_message_attempt_rejected",
    "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger",
}
S4_REQUIRED_OPERATIONS = {
    "registerNode",
    "registerInstance",
    "heartbeatNode",
    "heartbeatInstance",
    "advertiseCapabilities",
    "evaluatePlacement",
    "submitWorkOrder",
    "dispatchWorkOrder",
    "createRun",
    "startRun",
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
    "resident_state_handoff_proof_unavailable",
    "hash_valid_fabricated_handoff_proof_unavailable",
    "state_handoff_wrong_hash_not_evaluated_without_proof",
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
    "run.resumed",
    "trace.exported.redacted",
    "state.committed",
    "replay.explained",
}
S8_REQUIRED_SOURCE_SCENARIOS = {"UC-E2E-S1", "UC-E2E-S3", "UC-E2E-S4", "UC-E2E-S5", "UC-E2E-S6", "UC-E2E-S7"}
S8_REQUIRED_EVENTS = {
    "replay.started",
    "replay.completed",
    "replay.failed",
    "replay.adapter_suppressed",
    "replay.policy_compared",
    "replay.verifier_explained",
    "trace.imported",
    "trace.rejected",
    "state.imported",
    "state.rejected",
    "schema.migrated",
    "schema.rejected",
    "audit.exported",
}
S8_REQUIRED_NEGATIVES = {
    "tampered_trace_chain_detected",
    "state_hash_mismatch_prevents_replay_continuation",
    "unsupported_schema_version_rejected_with_migration_guidance",
    "side_effectful_replay_mode_rejected_without_gate",
    "replay_cannot_use_real_external_credentials",
    "generated_schema_mismatch_fails_compatibility_gate",
    "audit_export_requires_denial_reason_codes",
}
S8_REQUIRED_EXPLANATION_CATEGORIES = {
    "approval",
    "denial",
    "quota_failure",
    "work_order_rejection",
    "data_scope_denial",
    "safety_denial",
}
S9_REQUIRED_SOURCE_SCENARIOS = {"UC-E2E-S1", "UC-E2E-S4", "UC-E2E-S5"}
S9_REQUIRED_OPERATIONS = {
    "createRun",
    "submitAction",
    "startRun",
    "resumeRun",
    "inspectRun",
    "getStateHead",
    "exportTraces",
    "replayRun",
    "evaluatePlacement",
    "submitWorkOrder",
    "sendMessage",
    "getMessage",
    "requestApproval",
    "denyApproval",
    "createCircuitBreaker",
    "readCircuitBreakerSyncPayload",
    "syncCircuitBreakers",
    "activateKillSwitch",
    "getFleetTelemetry",
    "auditEvents",
    "exportGovernanceAudit",
}
S9_REQUIRED_EVENTS = {
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
S9_REQUIRED_NEGATIVES = {
    "adapter_returns_failure_no_fake_success_committed",
    "verifier_unavailable_denies_or_intervenes",
    "policy_unavailable_or_expired_denies_high_risk",
    "trace_write_failure_before_side_effect_blocks_execution",
    "trace_write_failure_after_outcome_audit_visible_no_hidden_continuation",
    "state_commit_failure_prevents_next_tick",
    "remote_message_transport_failure_records_delivery_failure",
    "node_heartbeat_stale_denies_placement",
    "quota_exceeded_denies_not_silently_retried",
    "non_idempotent_adapter_failure_not_automatically_retried",
    "circuit_breaker_wins_pending_approval_race",
    "kill_switch_wins_resume_race_fail_closed",
    "telemetry_stale_missing_cannot_authorize",
}
S9_ALLOWED_EVIDENCE_SOURCES = {
    "runtime_trace_export",
    "manager_audit_export",
    "source_runtime_trace_export",
}
S9_RUNTIME_EVENT_ORIGINALS = {
    "adapter.failed": {"action.failed"},
    "verifier.unavailable": {"action.denied", "action.needs_intervention"},
    "quota.exceeded": {"action.denied", "action.needs_intervention"},
    "trace.write_failed": {"trace.write_failed"},
    "state.commit_failed": {"state.commit_failed"},
    "run.paused": {"run.paused"},
    "run.denied": {"action.denied"},
    "run.cancelled": {"run.cancelled"},
}
S9_MANAGER_EVENT_ORIGINALS = {
    "message.delivery_failed": {"remote_message.failed"},
    "node.stale": {"placement.evaluated"},
    "circuit_breaker.tripped": {"circuit_breaker.tripped"},
    "kill_switch.activated": {"kill_switch.activated"},
}
S9_SOURCE_EVENT_ORIGINALS = {
    "policy.expired": {"policy.expired"},
}
S10_REQUIRED_POSITIVES = {
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
    "resident_state_handoff_denied_without_source_proof_and_receiver_resumed",
    "central_trace_aggregation_completed",
    "audit_and_replay_explain_without_side_effects",
}
S10_REQUIRED_NEGATIVES = {
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
    "expired_approval_rejected",
    "circuit_breaker_blocks_matching_publish_attempt",
    "kill_switch_cancels_separate_run",
    "tampered_trace_state_import_rejected",
    "replay_side_effect_mode_rejected_by_default",
}
S10_REQUIRED_EVENTS = {
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
S10_REQUIRED_OPERATIONS = {
    "registerNode",
    "registerInstance",
    "heartbeatNode",
    "advertiseCapabilities",
    "listNodes",
    "publishPolicyBundle",
    "getPolicyStatus",
    "submitWorkOrder",
    "evaluatePlacement",
    "dispatchWorkOrder",
    "sendMessage",
    "getMessage",
    "listInbox",
    "listOutbox",
    "ackMessage",
    "nackMessage",
    "getMessageCausalGraph",
    "validateMessageSchema",
    "listMessageSchemas",
    "createRun",
    "startRun",
    "pauseRun",
    "resumeRun",
    "submitAction",
    "registerDeviceProfile",
    "getDeviceStatus",
    "getPolicyCacheStatus",
    "submitPhysicalAction",
    "exportStateSnapshot",
    "importStateSnapshot",
    "requestApproval",
    "grantApproval",
    "createCircuitBreaker",
    "readCircuitBreakerSyncPayload",
    "syncCircuitBreakers",
    "activateKillSwitch",
    "exportTraces",
    "syncTraceBuffer",
    "syncDeviceTraceBuffer",
    "getFleetTelemetry",
    "replayRun",
    "exportGovernanceAudit",
    "managerAudit",
}
S10_REQUIRED_PRIMITIVES = {
    "tenant",
    "agent",
    "runtime_context",
    "run",
    "tick",
    "policy",
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
}
S10_RUN_IDS = {
    "44444444-4444-4444-8444-444444448810",
    "44444444-4444-4444-8444-444444448811",
    "44444444-4444-4444-8444-444444448812",
    "44444444-4444-4444-8444-444444448813",
    "44444444-4444-4444-8444-444444448814",
    "44444444-4444-4444-8444-444444448815",
    "44444444-4444-4444-8444-444444448816",
    "44444444-4444-4444-8444-444444448817",
    "44444444-4444-4444-8444-444444448818",
}
S10_WORK_ORDER_IDS = {
    "wo_uc_e2e_s10_field_intelligence",
    "wo_uc_e2e_s10_field_intelligence_data",
    "wo_uc_e2e_s10_field_intelligence_publish",
    "wo_uc_e2e_s10_field_intelligence_publish_revoke",
    "wo_uc_e2e_s10_field_intelligence_message",
    "wo_uc_e2e_s10_scoped_specialist",
    "wo_uc_e2e_s10_scoped_specialist_message",
    "wo_uc_e2e_s10_cloud_helper_proposal",
    "wo_uc_e2e_s10_edge_inspection",
    "wo_uc_e2e_s10_circuit_branch",
    "wo_uc_e2e_s10_kill_branch",
}
S10_MESSAGE_IDS = {
    "55555555-5555-4555-8555-555555558810",
    "55555555-5555-4555-8555-555555558811",
    "55555555-5555-4555-8555-555555558812",
    "55555555-5555-4555-8555-555555558813",
}
S10_NODE_IDS = {
    "00000000-0000-4000-8000-000000000204",
    "00000000-0000-4000-8000-000000000404",
    "00000000-0000-4000-8000-000000000604",
}
S10_INSTANCE_IDS = {
    "00000000-0000-4000-8000-000000000302",
    "00000000-0000-4000-8000-000000000304",
    "00000000-0000-4000-8000-000000000306",
}
S10_ALLOWED_EVIDENCE_SOURCES = {
    "runtime_trace_export",
    "manager_audit_export",
    "public_api_response",
}
S10_RUNTIME_EVENT_ORIGINALS = {
    "data_scope.verified": {"verification.completed"},
    "safety.verification.completed": {"verification.completed", "action.executed", "action.denied", "action.needs_approval", "action.needs_intervention", "outcome.recorded", "daemon.audit"},
    "action.executed": {"action.executed"},
    "action.denied": {"action.denied"},
    "action.needs_approval": {"action.needs_approval"},
    "artifact.created": {"action.executed"},
    "artifact.publish.executed": {"action.executed"},
    "state.committed": {"state.committed"},
    "run.resumed": {"run.resumed"},
    "replay.explained": {"daemon.audit"},
}
S10_MANAGER_EVENT_ORIGINALS = {
    "work_order.accepted": {"work_order.accepted"},
    "placement.evaluated": {"placement.evaluated"},
    "message.sent": {"remote_message.delivered"},
    "message.received": {"remote_message.received"},
    "cloud_helper.proposal.received": {"remote_message.delivered", "remote_message.received"},
    "approval.granted": {"approval.granted"},
    "approval.revoked": {"approval.revoked"},
    "governance.audit.exported": {"governance.audit.exported"},
    "circuit_breaker.tripped": {"circuit_breaker.tripped"},
    "kill_switch.activated": {"kill_switch.activated"},
}
S10_RESPONSE_EVENT_ORIGINALS = {
    "cloud_helper.proposal.received": {"sendMessage"},
    "approval.granted": {"grantApproval"},
    "approval.revoked": {"revokeApproval"},
    "state.exported": {"exportStateSnapshot"},
    "trace.sync.completed": {"syncTraceBuffer", "syncDeviceTraceBuffer"},
    "governance.audit.exported": {"exportGovernanceAudit"},
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
        "ActionFailed": "action.failed",
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
        "TraceWriteFailed": "trace.write_failed",
        "StateCommitFailed": "state.commit_failed",
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


def trace_record_run_id(record: dict) -> str:
    identity = record.get("payload", {}).get("identity", {})
    return str(record.get("run_id") or identity.get("run_id") or "")


def trace_record_action_id(record: dict) -> str:
    identity = record.get("payload", {}).get("identity", {})
    if identity.get("action_id"):
        return str(identity.get("action_id"))
    payload = trace_record_kind_payload(record)
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), dict) else {}
    context = artifacts.get("context") if isinstance(artifacts.get("context"), dict) else {}
    approval = artifacts.get("approval") if isinstance(artifacts.get("approval"), dict) else {}
    outcome = payload.get("outcome") if isinstance(payload.get("outcome"), dict) else {}
    action_outcome = outcome.get("action_outcome") if isinstance(outcome.get("action_outcome"), dict) else {}
    approval_payload = payload.get("approval") if isinstance(payload.get("approval"), dict) else {}
    return str(
        context.get("action_id")
        or approval.get("action_id")
        or action_outcome.get("action_id")
        or approval_payload.get("action_id")
        or ""
    )


def trace_record_action_name(record: dict) -> str:
    payload = trace_record_kind_payload(record)
    action = payload.get("action") if isinstance(payload.get("action"), dict) else {}
    if not action:
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        action = result.get("action") if isinstance(result.get("action"), dict) else {}
    return str(action.get("name") or "")


def trace_record_reasons(record: dict) -> list[str]:
    payload = trace_record_kind_payload(record)
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    reasons = result.get("reasons")
    if not isinstance(reasons, list):
        outcome = payload.get("outcome") if isinstance(payload.get("outcome"), dict) else {}
        action_outcome = outcome.get("action_outcome") if isinstance(outcome.get("action_outcome"), dict) else {}
        verification = action_outcome.get("verification") if isinstance(action_outcome.get("verification"), dict) else {}
        reasons = verification.get("reasons")
    return [str(reason) for reason in reasons] if isinstance(reasons, list) else []


def value_contains_key_value(value: object, key: str, expected: object) -> bool:
    if isinstance(value, dict):
        if value.get(key) == expected:
            return True
        return any(value_contains_key_value(child, key, expected) for child in value.values())
    if isinstance(value, list):
        return any(value_contains_key_value(child, key, expected) for child in value)
    return False


def trace_record_message_id(record: dict) -> str:
    identity = record.get("payload", {}).get("identity", {})
    return str(identity.get("message_id") or "")


def trace_record_state_node_id(record: dict) -> str:
    identity = record.get("payload", {}).get("identity", {})
    return str(identity.get("state_node_id") or "")


def index_trace_records(records: list[dict]) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for record in records:
        trace_id = trace_record_id(record)
        if trace_id:
            indexed[trace_id] = {
                "record": record,
                "kind": trace_record_kind(record),
                "run_id": trace_record_run_id(record),
                "action_id": trace_record_action_id(record),
                "message_id": trace_record_message_id(record),
                "state_node_id": trace_record_state_node_id(record),
            }
    return indexed


def index_manager_audit_events(events: list[dict]) -> dict[str, dict]:
    return {
        str(event.get("trace_event_id")): event
        for event in events
        if event.get("trace_event_id")
    }


def collect_values_for_key(value: object, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for item_key, item_value in value.items():
            if item_key == key and isinstance(item_value, str) and item_value.strip():
                found.append(item_value)
            else:
                found.extend(collect_values_for_key(item_value, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(collect_values_for_key(item, key))
    return found


def operation_rows(api_rows: list[dict], operation_id: str) -> list[tuple[int, dict]]:
    return [
        (index, row)
        for index, row in enumerate(api_rows)
        if row.get("operation_id") == operation_id
    ]


def row_path(row: dict) -> str:
    return urlsplit(str(row.get("url", ""))).path.rstrip("/") or "/"


def lifecycle_projection(value: object) -> dict:
    source = value if isinstance(value, dict) else {}
    return {
        key: source.get(key)
        for key in ["run_id", "status", "ticks", "state_head", "adapter_executions"]
    }


def state_projection(value: object) -> dict:
    source = value if isinstance(value, dict) else {}
    return {
        key: source.get(key)
        for key in ["run_id", "state_node_id", "data_hash", "parent_state_node_ids"]
    }


def authority_receipt_projection(value: object) -> dict:
    source = value if isinstance(value, dict) else {}
    validation = source.get("validation", {})
    if not isinstance(validation, dict):
        validation = {}
    return {
        key: source.get(key)
        for key in [
            "schema_version",
            "receipt_id",
            "issuer",
            "kind",
            "approval_id",
            "subject",
            "audience",
            "authority_decision_id",
            "obligation_id",
            "canonical_request_digest",
            "evidence_digest",
            "expires_at",
            "approval_trace_event_id",
            "evidence_ref",
            "revocation",
            "revocation_ref",
        ]
    } | {
        "validation": {
            key: validation.get(key)
            for key in ["algorithm", "digest", "key_id", "validation_kind"]
        }
    }


def contains_unredacted_authority_receipt_signature(value: object) -> bool:
    if isinstance(value, dict):
        is_receipt = (
            value.get("schema_version")
            == "splendor.authority.obligation_receipt.v1"
            or bool(value.get("receipt_id") and value.get("validation"))
        )
        validation = value.get("validation")
        if is_receipt and isinstance(validation, dict):
            signature = validation.get("signature")
            if signature and not str(signature).startswith("[REDACTED"):
                return True
        return any(
            contains_unredacted_authority_receipt_signature(child)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(contains_unredacted_authority_receipt_signature(child) for child in value)
    return False


def validate_manager_approval_auth_evidence(
    report: dict,
    api_rows: list[dict],
    required_operations: set[str],
    prefix: str,
) -> list[str]:
    failures: list[str] = []
    events = report.get("events", [])
    relevant_rows = [row for row in api_rows if row.get("manager_approval_call_id")]
    if not isinstance(events, list):
        return [f"{prefix}_manager_approval_auth_events_invalid"]
    event_ids = [event.get("call_id") for event in events]
    row_ids = [row.get("manager_approval_call_id") for row in relevant_rows]
    events_by_id = {event.get("call_id"): event for event in events}
    rows_by_id = {row.get("manager_approval_call_id"): row for row in relevant_rows}
    if (
        len(events) != len(required_operations)
        or {event.get("operation_id") for event in events} != required_operations
    ):
        failures.append(f"{prefix}_manager_approval_auth_operations_invalid")
    if (
        len(event_ids) != len(set(event_ids))
        or len(row_ids) != len(set(row_ids))
        or set(event_ids) != set(row_ids)
    ):
        failures.append(f"{prefix}_manager_approval_auth_api_cardinality_mismatch")
    credential_ids: list[str] = []
    for call_id, event in events_by_id.items():
        row = rows_by_id.get(call_id, {})
        request = row.get("request", {}) if isinstance(row.get("request"), dict) else {}
        credential = request.get("credential", {}) if isinstance(request.get("credential"), dict) else {}
        audit = request.get("audit_attribution", {}) if isinstance(request.get("audit_attribution"), dict) else {}
        response = row.get("response", {}) if isinstance(row.get("response"), dict) else {}
        credential_id = str(event.get("credential_id") or "")
        credential_ids.append(credential_id)
        trace_ids = event.get("trace_event_ids", [])
        response_trace_id = response.get("trace_event_id")
        if (
            event.get("operation_id") not in required_operations
            or event.get("method") not in {None, "POST"}
            or event.get("scope") != "approvals_manage"
            or event.get("required_scope", "approvals_manage") != "approvals_manage"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", credential_id)
            or event.get("fleet_id") != "00000000-0000-4000-8000-000000000104"
            or event.get("target_manager_id") != "central-manager"
            or event.get("audience_manager_id") != "central-manager"
            or event.get("header_presence", {}).get("authorization") is not True
            or event.get("body_mirror_status") != "matched"
            or event.get("raw_bearer_recorded") is not False
            or event.get("raw_signature_recorded", False) is not False
            or event.get("receipt_signature_recorded", False) is not False
            or row.get("operation_id") != event.get("operation_id")
            or row.get("method") != "POST"
            or row.get("status") != event.get("result_status")
            or event.get("result_status") not in event.get(
                "expected_statuses", [event.get("result_status")]
            )
            or credential.get("credential_id") != credential_id
            or credential.get("scopes") != ["approvals_manage"]
            or credential.get("binding")
            != {"fleet": {"fleet_id": "00000000-0000-4000-8000-000000000104"}}
            or credential.get("audience")
            != {"central_manager": {"manager_id": "central-manager"}}
            or audit.get("credential_id") != credential_id
            or audit.get("principal") != credential.get("principal")
            or contains_bearer_bytes(row)
            or (
                row.get("status") == 200
                and (not response_trace_id or response_trace_id not in trace_ids)
            )
        ):
            failures.append(f"{prefix}_manager_approval_auth_event_invalid:{call_id}")
    if len(credential_ids) != len(set(credential_ids)) or any(not value for value in credential_ids):
        failures.append(f"{prefix}_manager_approval_auth_jti_reused")
    if contains_unredacted_authority_receipt_signature(report) or contains_unredacted_authority_receipt_signature(relevant_rows):
        failures.append(f"{prefix}_manager_approval_auth_contains_receipt_signature")
    return failures


def validate_s9_required_event_evidence(
    *,
    scenario: dict,
    fault: dict,
    audit: dict,
    trace_records: list[dict],
    manager_events: list[dict],
    source_trace_records: dict[str, list[dict]],
) -> list[str]:
    failures: list[str] = []
    scenario_evidence = scenario.get("required_event_evidence", {})
    fault_evidence = fault.get("required_event_evidence", {})
    audit_evidence = audit.get("required_event_evidence", {})
    event_ids = scenario.get("required_trace_event_ids", {})
    if not isinstance(scenario_evidence, dict):
        return ["s9_required_event_evidence_not_object"]
    if not isinstance(fault_evidence, dict):
        failures.append("s9_fault_required_event_evidence_not_object")
        fault_evidence = {}
    if not isinstance(audit_evidence, dict):
        failures.append("s9_audit_required_event_evidence_not_object")
        audit_evidence = {}

    runtime_index = index_trace_records(trace_records)
    manager_index = index_manager_audit_events(manager_events)
    runtime_records_by_id: dict[str, list[dict]] = {}
    for record in trace_records:
        trace_id = trace_record_id(record)
        if trace_id:
            runtime_records_by_id.setdefault(trace_id, []).append(
                {
                    "record": record,
                    "kind": trace_record_kind(record),
                    "run_id": trace_record_run_id(record),
                    "action_id": trace_record_action_id(record),
                    "message_id": trace_record_message_id(record),
                    "state_node_id": trace_record_state_node_id(record),
                }
            )
    source_indexes = {
        source_id: index_trace_records(records)
        for source_id, records in source_trace_records.items()
    }
    trace_failure_modes = {"before_side_effect": False, "after_side_effect": False}

    for record in trace_records:
        if record.get("event_type") or record.get("scenario_id"):
            failures.append("s9_trace_export_contains_synthetic_top_level_event")
        if trace_record_kind(record) in S9_REQUIRED_EVENTS and not trace_record_id(record):
            failures.append(f"s9_required_runtime_trace_missing_trace_id:{trace_record_kind(record)}")

    for event_name in sorted(S9_REQUIRED_EVENTS):
        rows = scenario_evidence.get(event_name)
        if not isinstance(rows, list) or not rows:
            failures.append(f"s9_required_event_evidence_missing:{event_name}")
            continue
        ids_from_rows = [row.get("trace_event_id") for row in rows if isinstance(row, dict)]
        ids_from_report = event_ids.get(event_name, [])
        if sorted(ids_from_rows) != sorted(ids_from_report):
            failures.append(f"s9_required_event_ids_do_not_match_evidence:{event_name}")
        fault_ids = [row.get("trace_event_id") for row in fault_evidence.get(event_name, []) if isinstance(row, dict)]
        if sorted(fault_ids) != sorted(ids_from_rows):
            failures.append(f"s9_fault_event_evidence_mismatch:{event_name}")
        audit_ids = [row.get("trace_event_id") for row in audit_evidence.get(event_name, []) if isinstance(row, dict)]
        if sorted(audit_ids) != sorted(ids_from_rows):
            failures.append(f"s9_audit_event_evidence_mismatch:{event_name}")

        for row in rows:
            if not isinstance(row, dict):
                failures.append(f"s9_required_event_evidence_row_not_object:{event_name}")
                continue
            trace_id = row.get("trace_event_id")
            source = row.get("source")
            original = row.get("original_event_type")
            artifact = row.get("artifact")
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if not is_canonical_uuid(trace_id):
                failures.append(f"s9_required_event_evidence_trace_id_not_uuid:{event_name}:{trace_id}")
            if source not in S9_ALLOWED_EVIDENCE_SOURCES:
                failures.append(f"s9_required_event_forbidden_source:{event_name}:{source}")
                continue
            if source in {"synthetic", "manual", "scenario_python", "scenario_report"}:
                failures.append(f"s9_required_event_synthetic_source:{event_name}:{source}")

            if source == "runtime_trace_export":
                if original not in S9_RUNTIME_EVENT_ORIGINALS.get(event_name, set()):
                    failures.append(f"s9_runtime_event_wrong_original:{event_name}:{original}")
                observed = runtime_index.get(str(trace_id))
                if not observed:
                    failures.append(f"s9_runtime_event_missing_from_trace_export:{event_name}:{trace_id}")
                    continue
                if artifact != "trace-export.jsonl":
                    failures.append(f"s9_runtime_event_wrong_artifact:{event_name}:{artifact}")
                if observed["kind"] != original:
                    failures.append(f"s9_runtime_event_kind_mismatch:{event_name}:{original}:{observed['kind']}")
                if row.get("run_id") and row.get("run_id") != observed["run_id"]:
                    failures.append(f"s9_runtime_event_run_mismatch:{event_name}")
                if event_name in {"adapter.failed", "verifier.unavailable", "quota.exceeded", "run.denied"}:
                    observed_action_id = observed["action_id"]
                    if not row.get("action_id"):
                        failures.append(f"s9_runtime_event_action_correlation_missing:{event_name}")
                    elif observed_action_id and row.get("action_id") != observed_action_id:
                        failures.append(f"s9_runtime_event_action_correlation_mismatch:{event_name}")
                    elif not observed_action_id and details.get("outcome_action_id") != row.get("action_id"):
                        failures.append(f"s9_runtime_event_action_correlation_missing:{event_name}")
                    elif details.get("action") and trace_record_action_name(observed["record"]) != details.get("action"):
                        failures.append(f"s9_runtime_event_action_name_mismatch:{event_name}")
                if event_name == "verifier.unavailable":
                    observed_payload = trace_record_kind_payload(observed["record"])
                    observed_reasons = trace_record_reasons(observed["record"])
                    observed_text = json.dumps(observed_payload, sort_keys=True)
                    if "verifier_unavailable" not in observed_reasons:
                        failures.append("s9_verifier_unavailable_missing_runtime_reason")
                    if any(forbidden in observed_text for forbidden in ["policy_expired", "approval_policy_expired"]):
                        failures.append("s9_verifier_unavailable_confused_with_policy_or_approval_expiry")
                    if not value_contains_key_value(observed_payload, "verifier_status", "unavailable"):
                        failures.append("s9_verifier_unavailable_missing_verifier_status")
                    if not value_contains_key_value(observed_payload, "adapter_execution", "not_attempted"):
                        failures.append("s9_verifier_unavailable_adapter_not_blocked")
                    if details.get("failure_injection") != "verifier_unavailable_actions" or details.get("public_path") != "splendorctl run --config":
                        failures.append("s9_verifier_unavailable_public_cli_path_missing")
                    if details.get("http_counter_before") != details.get("http_counter_after"):
                        failures.append("s9_verifier_unavailable_adapter_counter_changed")
                if event_name in {"trace.write_failed", "state.commit_failed", "run.paused", "run.cancelled"} and not row.get("run_id"):
                    failures.append(f"s9_runtime_event_run_correlation_missing:{event_name}")
                if event_name == "trace.write_failed":
                    observed_payload = trace_record_kind_payload(observed["record"])
                    failed_event = observed_payload.get("failed_event")
                    side_effect_executed = observed_payload.get("side_effect_executed")
                    if details.get("failed_event") != failed_event or details.get("side_effect_executed") is not side_effect_executed:
                        failures.append("s9_trace_write_failure_details_not_runtime_derived")
                    if failed_event == "ActionVerificationStarted":
                        trace_failure_modes["before_side_effect"] = True
                        if side_effect_executed is not False or details.get("http_counter_before") != details.get("http_counter_after"):
                            failures.append("s9_trace_write_failure_before_effect_not_blocked")
                    elif failed_event == "OutcomeRecorded":
                        trace_failure_modes["after_side_effect"] = True
                        events = details.get("events", [])
                        exported_run_events = [trace_record_kind(record) for record in trace_records if trace_record_run_id(record) == observed["run_id"]]
                        if side_effect_executed is not True or details.get("effect_exists") is not True or details.get("effect_contents") != "executed-once\n":
                            failures.append("s9_trace_write_failure_after_effect_not_proven")
                        if events.count("action.executed") != 1 or events.count("tick.started") != 1 or any(forbidden in events for forbidden in ["outcome.recorded", "state.committed", "tick.completed"]):
                            failures.append("s9_trace_write_failure_after_effect_hidden_continuation")
                        if exported_run_events.count("action.executed") != 1 or exported_run_events.count("tick.started") != 1 or any(forbidden in exported_run_events for forbidden in ["outcome.recorded", "state.committed", "tick.completed"]):
                            failures.append("s9_trace_write_failure_after_effect_export_mismatch")
                    else:
                        failures.append(f"s9_trace_write_failure_unexpected_injection_point:{failed_event}")
                if event_name == "state.commit_failed":
                    events = details.get("events", [])
                    failure_indexes = [index for index, observed_event in enumerate(events) if observed_event == "state.commit_failed"]
                    if not failure_indexes or "tick.started" in events[failure_indexes[-1] + 1 :] or events.count("tick.started") > 1:
                        failures.append("s9_state_commit_failure_advanced_next_tick")

            elif source == "manager_audit_export":
                if original not in S9_MANAGER_EVENT_ORIGINALS.get(event_name, set()):
                    failures.append(f"s9_manager_event_wrong_original:{event_name}:{original}")
                observed = manager_index.get(str(trace_id))
                if not observed:
                    failures.append(f"s9_manager_event_missing_from_audit_export:{event_name}:{trace_id}")
                    continue
                if artifact != "manager-audit-export.json":
                    failures.append(f"s9_manager_event_wrong_artifact:{event_name}:{artifact}")
                if observed.get("event_type") != original:
                    failures.append(f"s9_manager_event_type_mismatch:{event_name}:{original}:{observed.get('event_type')}")
                observed_details = observed.get("details", {})
                if event_name == "message.delivery_failed":
                    if not row.get("message_id") or observed_details.get("message_id") != row.get("message_id"):
                        failures.append("s9_message_failure_message_correlation_missing")
                    if observed_details.get("remote_state_mutated") is not False:
                        failures.append("s9_message_failure_mutated_remote_state")
                if event_name == "node.stale":
                    placement = details.get("placement", {})
                    if placement.get("status") != "rejected" or not any("not available" in str(reason) for reason in placement.get("reasons", [])):
                        failures.append("s9_node_stale_not_rejected_by_placement")
                if event_name == "circuit_breaker.tripped" and not observed_details.get("breaker_id"):
                    failures.append("s9_circuit_breaker_missing_breaker_id")
                if event_name == "kill_switch.activated" and not observed_details.get("kill_switch_id"):
                    failures.append("s9_kill_switch_missing_kill_switch_id")

            elif source == "source_runtime_trace_export":
                if event_name not in S9_SOURCE_EVENT_ORIGINALS or original not in S9_SOURCE_EVENT_ORIGINALS[event_name]:
                    failures.append(f"s9_source_event_wrong_original:{event_name}:{original}")
                source_scenario = details.get("source_scenario")
                source_index = source_indexes.get(str(source_scenario), {})
                observed = source_index.get(str(trace_id))
                if not observed:
                    failures.append(f"s9_source_event_missing_from_trace_export:{event_name}:{trace_id}:{source_scenario}")
                    continue
                if artifact != f"{source_scenario}/trace-export.jsonl":
                    failures.append(f"s9_source_event_wrong_artifact:{event_name}:{artifact}")
                if observed["kind"] != original:
                    failures.append(f"s9_source_event_kind_mismatch:{event_name}:{observed['kind']}")
                if event_name == "policy.expired":
                    if details.get("reason_code") != "policy_expired" or not row.get("run_id") or not row.get("action_id"):
                        failures.append("s9_policy_expired_missing_action_correlation")

    if not trace_failure_modes["before_side_effect"]:
        failures.append("s9_trace_write_failure_before_effect_evidence_missing")
    if not trace_failure_modes["after_side_effect"]:
        failures.append("s9_trace_write_failure_after_effect_evidence_missing")
    return failures


def validate_s10_required_event_evidence(
    *,
    scenario: dict,
    audit: dict,
    trace_records: list[dict],
    manager_events: list[dict],
    response_ids: set[str],
) -> list[str]:
    def runtime_kind_matches(actual: str, expected: object) -> bool:
        return actual == expected or (actual == "DaemonAudit" and expected == "daemon.audit")

    failures: list[str] = []
    scenario_evidence = scenario.get("required_event_evidence", {})
    audit_evidence = audit.get("machine_readable", {}).get("required_event_evidence", {})
    event_ids = scenario.get("required_trace_event_ids", {})
    if not isinstance(scenario_evidence, dict):
        return ["s10_required_event_evidence_not_object"]
    if not isinstance(audit_evidence, dict):
        failures.append("s10_audit_required_event_evidence_not_object")
        audit_evidence = {}

    manager_index = index_manager_audit_events(manager_events)
    runtime_records_by_id: dict[str, list[dict]] = {}
    for record in trace_records:
        trace_id = trace_record_id(record)
        if trace_id:
            runtime_records_by_id.setdefault(trace_id, []).append(
                {
                    "record": record,
                    "kind": trace_record_kind(record),
                    "run_id": trace_record_run_id(record),
                    "action_id": trace_record_action_id(record),
                    "message_id": trace_record_message_id(record),
                    "state_node_id": trace_record_state_node_id(record),
                }
            )
    for record in trace_records:
        if record.get("event_type") or record.get("scenario_id"):
            failures.append("s10_trace_export_contains_synthetic_top_level_event")
        if trace_record_kind(record) in S10_REQUIRED_EVENTS and not trace_record_id(record):
            failures.append(f"s10_required_runtime_trace_missing_trace_id:{trace_record_kind(record)}")

    for event_name in sorted(S10_REQUIRED_EVENTS):
        rows = scenario_evidence.get(event_name)
        if not isinstance(rows, list) or not rows:
            failures.append(f"s10_required_event_evidence_missing:{event_name}")
            continue
        ids_from_rows = sorted({row.get("trace_event_id") for row in rows if isinstance(row, dict)})
        ids_from_report = sorted(event_ids.get(event_name, []))
        if ids_from_rows != ids_from_report:
            failures.append(f"s10_required_event_ids_do_not_match_evidence:{event_name}")
        audit_ids = sorted({row.get("trace_event_id") for row in audit_evidence.get(event_name, []) if isinstance(row, dict)})
        if audit_ids and audit_ids != ids_from_rows:
            failures.append(f"s10_audit_event_evidence_mismatch:{event_name}")

        for row in rows:
            if not isinstance(row, dict):
                failures.append(f"s10_required_event_evidence_row_not_object:{event_name}")
                continue
            trace_id = row.get("trace_event_id")
            source = row.get("source")
            original = row.get("original_event_type")
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if not is_canonical_uuid(trace_id):
                failures.append(f"s10_required_event_evidence_trace_id_not_uuid:{event_name}:{trace_id}")
            if source not in S10_ALLOWED_EVIDENCE_SOURCES:
                failures.append(f"s10_required_event_forbidden_source:{event_name}:{source}")
                continue
            if source in {"synthetic", "manual", "scenario_python", "scenario_report"}:
                failures.append(f"s10_required_event_synthetic_source:{event_name}:{source}")

            has_s10_correlation = any(
                [
                    row.get("run_id") in S10_RUN_IDS,
                    row.get("work_order_id") in S10_WORK_ORDER_IDS,
                    row.get("message_id") in S10_MESSAGE_IDS,
                    row.get("node_id") in S10_NODE_IDS,
                    row.get("instance_id") in S10_INSTANCE_IDS,
                    row.get("circuit_breaker_id") == "55555555-5555-4555-8555-555555558816",
                    row.get("kill_switch_id") == "ks_uc_e2e_s10_controlled_branch",
                    row.get("approval_id") and row.get("run_id") == "44444444-4444-4444-8444-444444448817",
                    details.get("proposal_id") == "route-proposal-s10-zone-a3",
                ]
            )
            if not has_s10_correlation:
                failures.append(f"s10_required_event_missing_s10_correlation:{event_name}:{trace_id}")

            if source == "runtime_trace_export":
                if original not in S10_RUNTIME_EVENT_ORIGINALS.get(event_name, set()):
                    failures.append(f"s10_runtime_event_wrong_original:{event_name}:{original}")
                observed_candidates = runtime_records_by_id.get(str(trace_id), [])
                observed = next(
                    (
                        candidate
                        for candidate in observed_candidates
                        if runtime_kind_matches(candidate["kind"], original) and candidate["run_id"] == row.get("run_id")
                    ),
                    None,
                ) or next(
                    (
                        candidate
                        for candidate in observed_candidates
                        if runtime_kind_matches(candidate["kind"], original)
                    ),
                    None,
                )
                if not observed:
                    failures.append(f"s10_runtime_event_missing_from_trace_export:{event_name}:{trace_id}")
                    continue
                if row.get("artifact") != "trace-export.jsonl":
                    failures.append(f"s10_runtime_event_wrong_artifact:{event_name}:{row.get('artifact')}")
                if row.get("run_id") != observed["run_id"] or row.get("run_id") not in S10_RUN_IDS:
                    failures.append(f"s10_runtime_event_run_mismatch:{event_name}")
                if row.get("action_id") and observed["action_id"] and row.get("action_id") != observed["action_id"]:
                    failures.append(f"s10_runtime_event_action_mismatch:{event_name}")
                if event_name == "data_scope.verified" and details.get("action") != "data.read_fixture":
                    failures.append("s10_data_scope_verified_wrong_action")
                if event_name == "artifact.created" and details.get("action") != "artifact.create_internal":
                    failures.append("s10_artifact_created_wrong_action")
                if event_name == "artifact.publish.executed" and details.get("action") != "artifact.publish_external":
                    failures.append("s10_artifact_publish_wrong_action")
                if event_name == "safety.verification.completed" and not details.get("contains_safety_verifier_evidence"):
                    failures.append("s10_safety_event_missing_evidence_marker")

            elif source == "manager_audit_export":
                if original not in S10_MANAGER_EVENT_ORIGINALS.get(event_name, set()):
                    failures.append(f"s10_manager_event_wrong_original:{event_name}:{original}")
                observed = manager_index.get(str(trace_id))
                if not observed:
                    failures.append(f"s10_manager_event_missing_from_audit_export:{event_name}:{trace_id}")
                    continue
                if row.get("artifact") != "manager-audit-export.json":
                    failures.append(f"s10_manager_event_wrong_artifact:{event_name}:{row.get('artifact')}")
                if observed.get("event_type") != original:
                    failures.append(f"s10_manager_event_type_mismatch:{event_name}:{original}:{observed.get('event_type')}")
                observed_details = observed.get("details", {}) if isinstance(observed.get("details"), dict) else {}
                if row.get("work_order_id") and observed_details.get("work_order_id") != row.get("work_order_id"):
                    failures.append(f"s10_manager_event_work_order_mismatch:{event_name}")
                if row.get("message_id") and observed_details.get("message_id") != row.get("message_id"):
                    failures.append(f"s10_manager_event_message_mismatch:{event_name}")
                if event_name == "placement.evaluated" and observed_details.get("work_order_id") not in S10_WORK_ORDER_IDS:
                    failures.append("s10_placement_event_missing_work_order_correlation")
                if event_name == "circuit_breaker.tripped" and observed_details.get("breaker_id") != "55555555-5555-4555-8555-555555558816":
                    failures.append("s10_circuit_breaker_event_wrong_id")
                if event_name == "kill_switch.activated" and observed_details.get("kill_switch_id") != "ks_uc_e2e_s10_controlled_branch":
                    failures.append("s10_kill_switch_event_wrong_id")

            elif source == "public_api_response":
                if original not in S10_RESPONSE_EVENT_ORIGINALS.get(event_name, set()):
                    failures.append(f"s10_response_event_wrong_original:{event_name}:{original}")
                if str(trace_id) not in response_ids:
                    failures.append(f"s10_response_event_missing_from_public_artifacts:{event_name}:{trace_id}")

    return failures


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
        "source_tree",
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
    source_tree = report.get("source_tree")
    if not isinstance(source_tree, dict):
        failures.append("report_source_tree_invalid")
    else:
        required_source_tree = {
            "status",
            "source",
            "head_revision",
            "dirty",
            "digest",
            "digest_algorithm",
            "tracked_change_count",
            "staged_change_count",
            "unstaged_change_count",
            "untracked_file_count",
            "reason",
        }
        missing_source_tree = sorted(required_source_tree - source_tree.keys())
        if missing_source_tree:
            failures.append(
                "report_source_tree_missing_fields:" + ",".join(missing_source_tree)
            )
        if source_tree.get("digest_algorithm") != SOURCE_TREE_DIGEST_ALGORITHM:
            failures.append("report_source_tree_algorithm_invalid")
        if source_tree.get("status") == "known":
            if source_tree.get("source") not in {"git", "environment_override"}:
                failures.append("report_source_tree_source_invalid")
            if not isinstance(source_tree.get("dirty"), bool):
                failures.append("report_source_tree_dirty_invalid")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(source_tree.get("digest", ""))):
                failures.append("report_source_tree_digest_invalid")
            if not source_tree.get("head_revision"):
                failures.append("report_source_tree_head_invalid")
        elif source_tree.get("status") == "unknown":
            if source_tree.get("source") != "unknown":
                failures.append("report_unknown_source_tree_source_invalid")
            unknown_values = [
                source_tree.get("head_revision"),
                source_tree.get("dirty"),
                source_tree.get("digest"),
                source_tree.get("tracked_change_count"),
                source_tree.get("staged_change_count"),
                source_tree.get("unstaged_change_count"),
                source_tree.get("untracked_file_count"),
            ]
            if any(value is not None for value in unknown_values):
                failures.append("report_unknown_source_tree_fabricates_state")
        else:
            failures.append("report_source_tree_status_invalid")
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
    def source_count(field: str) -> str:
        value = report["source_tree"][field]
        return "unknown" if value is None else str(value)

    source_tree = report["source_tree"]
    dirty = source_tree["dirty"]
    dirty_text = "unknown" if dirty is None else str(dirty).lower()
    digest = source_tree["digest"] or "unknown"
    lines = [
        "# Splendor Use-Case E2E Acceptance Report",
        "",
        f"- Suite: `{report['suite_id']}` `{report['suite_version']}`",
        f"- Source revision: `{report['source_revision']}`",
        f"- Source tree status: `{source_tree['status']}` ({source_tree['source']})",
        f"- Source tree dirty: `{dirty_text}`",
        f"- Source tree digest: `{digest}` ({source_tree['digest_algorithm']})",
        f"- Source changes: tracked `{source_count('tracked_change_count')}`, staged `{source_count('staged_change_count')}`, unstaged `{source_count('unstaged_change_count')}`, untracked non-ignored `{source_count('untracked_file_count')}`",
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
            "## S6 evidence",
            "",
            "- Physical/edge safety evidence is recorded in `artifacts/UC-E2E-S6/` when S6 runs.",
            "- S6 requires public resident-edge daemon APIs, high-level physical actions only, local safety verifier denial, operator intervention, trace buffer sync, and inspect-only replay evidence.",
            "- S6 keeps device simulation beyond Splendor adapter boundaries and does not claim real-time robotics control.",
            "",
            "## S7 evidence",
            "",
            "- Data-local isolation and artifact evidence is recorded in `artifacts/UC-E2E-S7/` when S7 runs.",
            "- S7 requires scoped work orders, typed specialist messages, data-scope denial, trace redaction, governed artifact publish, and replay without rereading or republishing artifacts.",
            "- S7 does not claim enterprise data workspace UI coverage.",
            "",
            "## S8 evidence",
            "",
            "- Replay/audit/schema compatibility evidence is recorded in `artifacts/UC-E2E-S8/` when S8 runs.",
            "- S8 imports S1/S3/S4/S5/S6/S7 trace and state artifacts into a clean workspace, validates trace chains and state hashes, rejects tampered copies, and emits replay/schema/audit events.",
            "- S8 keeps replay inspect/read-only/comparison/explanation-only by default and rejects side-effectful replay without a separate explicit gate.",
            "",
            "## S9 evidence",
            "",
            "- Failure injection evidence is recorded in `artifacts/UC-E2E-S9/` when S9 runs.",
            "- S9 requires public daemon/manager API traffic, deterministic adapter/verifier/quota/message/placement/governance failures, bounded retry counts, idempotency markers, and replay side-effect suppression.",
            "- S9 consumes S1/S4/S5 source artifacts for trace/state/remote/governance failure evidence.",
            "",
            "## S10 evidence",
            "",
            "- Final cross-component journey evidence is recorded in `artifacts/UC-E2E-S10/` when S10 runs.",
            "- S10 requires API contract validation, topology hash, signed work-order placement, typed specialist/cloud helper messages, edge simulator safety verification, approval-gated artifact publication, one state handoff/resume, central trace aggregation, audit, replay, and anti-drift/FR coverage matrix evidence.",
            "- S10 keeps cloud helpers proposal-only, telemetry observational only, replay side-effect-free by default, and physical actions high-level only.",
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
        "invalid_v2_task_request_payload_rejected_before_delivery": "message.rejected",
        "broad_permission_data_ref_smuggling_denied": "delegation.rejected",
        "cross_tenant_message_attempt_rejected": "delegation.rejected",
        "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger": "action.denied",
    }
    expected_reason_text = {
        "invalid_v2_task_request_payload_rejected_before_delivery": [
            "missing field",
            "parent_run_id",
        ],
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
    if rust_schema.get("task_request_schema") != "splendor.message.task_request.v2" or rust_schema.get("task_response_schema") != "splendor.message.task_response.v1":
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
    import_denied = handoff.get("resident_import_denied", {})
    if not handoff.get("exported", {}).get("handoff"):
        failures.append("s4_state_handoff_export_missing")
    if import_denied.get("status") != 503 or import_denied.get("body", {}).get("code") != "state_handoff_proof_unavailable":
        failures.append("s4_resident_handoff_import_not_denied_without_source_proof")
    if import_denied.get("body", {}).get("details", {}).get("disposition") != "needs_intervention":
        failures.append("s4_resident_handoff_denial_missing_intervention_disposition")
    if handoff.get("hash_valid_fabricated", {}).get("status") != 503:
        failures.append("s4_hash_valid_fabricated_handoff_not_denied")
    if handoff.get("wrong_hash", {}).get("status") != 503:
        failures.append("s4_wrong_hash_handoff_reached_validation_without_source_proof")
    if handoff.get("wrong_run", {}).get("status") != 503 or handoff.get("wrong_run", {}).get("body", {}).get("code") != "state_handoff_proof_unavailable":
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


def validate_s5_approval_remediation(
    approval_flow: dict, api_rows: list[dict]
) -> list[str]:
    failures: list[str] = []

    active_raw = approval_flow.get("active_run_expired_raw_rejection", {})
    active_operations = [
        "inspectRunBeforeExpiredRaw",
        "submitExpiredRawEvidenceOnActiveRun",
        "inspectRunAfterExpiredRaw",
    ]
    active_rows = [operation_rows(api_rows, operation) for operation in active_operations]
    if any(len(rows) != 1 for rows in active_rows):
        failures.append("s5_active_raw_api_cardinality_invalid")
    else:
        indexes = [rows[0][0] for rows in active_rows]
        before_row, raw_row, after_row = [rows[0][1] for rows in active_rows]
        if indexes != sorted(indexes):
            failures.append("s5_active_raw_api_order_invalid")
        if (
            raw_row.get("method") != "POST"
            or row_path(raw_row) != "/actions"
            or raw_row.get("status") != 409
            or raw_row.get("response", {}).get("code")
            != "legacy_approval_evidence_non_authorizing"
            or not isinstance(raw_row.get("request", {}).get("approval_evidence"), dict)
            or raw_row.get("request", {}).get("authority_obligation_receipts")
        ):
            failures.append("s5_active_raw_not_pre_gateway_rejected")
        before = lifecycle_projection(before_row.get("response"))
        after = lifecycle_projection(after_row.get("response"))
        artifact_before = lifecycle_projection(active_raw.get("before"))
        if (
            before != after
            or any(
                before.get(key) != artifact_before.get(key)
                for key in ["status", "ticks", "state_head", "adapter_executions"]
            )
            or before.get("run_id") != active_raw.get("run_id")
        ):
            failures.append("s5_active_raw_lifecycle_or_effect_changed")
        if (
            active_raw.get("classification")
            != "pre_gateway_run_action_admission_rejection"
            or active_raw.get("gateway_invoked") is not False
            or active_raw.get("http_status") != 409
            or active_raw.get("code") != "legacy_approval_evidence_non_authorizing"
            or active_raw.get("adapter_effect_delta") != 0
            or active_raw.get("appended_trace_event_ids") != []
            or active_raw.get("approval_trace_records") != []
            or active_raw.get("trace_ids_before") != active_raw.get("trace_ids_after")
        ):
            failures.append("s5_active_raw_artifact_not_fail_closed")

    expired_rows = operation_rows(api_rows, "submitExpiredExactWaitingApproval")
    expired = approval_flow.get("expired", {})
    if len(expired_rows) != 1:
        failures.append("s5_exact_pending_expiry_api_cardinality_invalid")
    else:
        expired_row = expired_rows[0][1]
        if (
            expired_row.get("method") != "POST"
            or row_path(expired_row) != "/actions"
            or expired_row.get("status") != 200
            or expired_row.get("response") != expired
            or not isinstance(expired_row.get("request", {}).get("approval_evidence"), dict)
            or expired_row.get("request", {}).get("authority_obligation_receipts")
            or expired.get("status") != "Denied"
            or expired.get("error") != "approval_expired"
            or expired.get("output") is not None
            or "approval_expired" not in expired.get("verification", {}).get("reasons", [])
        ):
            failures.append("s5_exact_pending_expiry_not_denied")

    revocation = approval_flow.get("resident_receipt_revocation", {})
    required_order = [
        "submitRevocableWorkOrder",
        "dispatchRevocableWorkOrder",
        "submitRevocableAction",
        "requestRevocableApproval",
        "grantRevocableApproval",
        "inspectRevocableBeforeManagerRevoke",
        "revokeApproval",
        "inspectRevocableAfterManagerRevoke",
        "submitRevokedOriginalReceipt",
        "inspectRevocableAfterDeniedRetry",
        "getRevocableStateAfterDeniedRetry",
    ]
    ordered_rows = [operation_rows(api_rows, operation) for operation in required_order]
    if any(len(rows) != 1 for rows in ordered_rows):
        failures.append("s5_resident_revocation_api_cardinality_invalid")
    else:
        indexes = [rows[0][0] for rows in ordered_rows]
        rows = [rows[0][1] for rows in ordered_rows]
        if indexes != sorted(indexes):
            failures.append("s5_resident_revocation_api_order_invalid")
        (
            submit_row,
            dispatch_row,
            proposal_row,
            request_row,
            grant_row,
            before_row,
            revoke_row,
            after_revoke_row,
            retry_row,
            after_retry_row,
            state_after_row,
        ) = rows
        retained_receipt = revocation.get("retained_receipt", {})
        grant_receipt = grant_row.get("response", {}).get(
            "authority_obligation_receipt", {}
        )
        retry_receipts = retry_row.get("request", {}).get(
            "authority_obligation_receipts", []
        )
        acknowledgement = revocation.get("acknowledgement", {})
        expected_audience = (
            "splendor.daemon.approval_receipt.v2:instance:"
            f"{revocation.get('dispatch', {}).get('selected_instance_id')}:run:"
            f"{revocation.get('dispatch', {}).get('run_id')}"
        )
        if (
            submit_row.get("response") != revocation.get("work_order_admission")
            or dispatch_row.get("response") != revocation.get("dispatch")
            or proposal_row.get("response") != revocation.get("proposal")
            or request_row.get("response") != approval_flow.get("request")
            or authority_receipt_projection(grant_receipt)
            != authority_receipt_projection(retained_receipt)
            or len(retry_receipts) != 1
            or authority_receipt_projection(retry_receipts[0])
            != authority_receipt_projection(retained_receipt)
            or retained_receipt.get("audience") != expected_audience
            or retained_receipt.get("revocation") != "active"
        ):
            failures.append("s5_resident_revocation_receipt_or_dispatch_mismatch")
        if (
            revoke_row.get("status") != 200
            or revoke_row.get("response", {}).get("resident_receipt_revocation_ack")
            != acknowledgement
            or approval_flow.get("revoke", {}).get("resident_receipt_revocation_ack")
            != acknowledgement
            or acknowledgement.get("schema_version")
            != "splendor.resident.approval_receipt_revocation_ack.v1"
            or acknowledgement.get("status") not in {"revoked", "already_revoked"}
            or acknowledgement.get("effect_certainty") != "known"
            or acknowledgement.get("receipt_id") != retained_receipt.get("receipt_id")
            or acknowledgement.get("approval_id") != retained_receipt.get("approval_id")
            or acknowledgement.get("receipt_audience") != expected_audience
        ):
            failures.append("s5_resident_revocation_ack_not_exact")
        retry_response = retry_row.get("response", {})
        if (
            retry_row.get("status") != 200
            or retry_response != revocation.get("revoked_receipt_retry", {}).get("body")
            or retry_response.get("status") != "Denied"
            or retry_response.get("error") != "authority_obligation_receipt_revoked"
            or retry_response.get("output") is not None
            or "authority_obligation_receipt_revoked"
            not in retry_response.get("verification", {}).get("reasons", [])
        ):
            failures.append("s5_revoked_original_receipt_not_denied")
        before = lifecycle_projection(before_row.get("response"))
        after_revoke = lifecycle_projection(after_revoke_row.get("response"))
        after_retry = lifecycle_projection(after_retry_row.get("response"))
        if (
            before != after_revoke
            or before != after_retry
            or before.get("adapter_executions") != 0
            or state_projection(state_after_row.get("response"))
            != state_projection(revocation.get("state", {}).get("before_manager_revoke"))
            or revocation.get("action_executed_trace_records") != []
        ):
            failures.append("s5_resident_revocation_changed_tick_state_or_effect")

    revocation_auth = revocation.get("resident_revocation_authentication", [])
    if (
        len(revocation_auth) != 1
        or revocation_auth[0].get("required_scope")
        != "splendor.approval_receipts.revoke"
        or revocation_auth[0].get("tls_verification") != "acceptance_ca"
        or revocation_auth[0].get("target_instance_id")
        != revocation.get("acknowledgement", {}).get("target_instance_id")
        or revocation_auth[0].get("run_id")
        != revocation.get("acknowledgement", {}).get("run_id")
        or revocation_auth[0].get("receipt_id")
        != revocation.get("acknowledgement", {}).get("receipt_id")
        or revocation_auth[0].get("ack_status")
        != revocation.get("acknowledgement", {}).get("status")
        or revocation_auth[0].get("raw_bearer_recorded") is not False
        or revocation_auth[0].get("raw_jti_recorded") is not False
        or revocation_auth[0].get("receipt_signature_recorded") is not False
    ):
        failures.append("s5_resident_revocation_authentication_invalid")
    if contains_unredacted_authority_receipt_signature(approval_flow) or contains_unredacted_authority_receipt_signature(api_rows):
        failures.append("s5_retained_evidence_contains_receipt_signature")
    return failures


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
    api_rows = read_jsonl(artifact_dir / "api-traffic.ndjson")
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
    failures.extend(validate_s5_approval_remediation(approval_flow, api_rows))
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
    for row in api_rows:
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


def validate_s6_physical_approval_binding(
    artifact: dict, manager_auth: dict, api_rows: list[dict]
) -> list[str]:
    failures: list[str] = []
    ids = artifact.get("ids", {})
    run_id = ids.get("run_id")
    action_id = ids.get("action_id")
    node_a = ids.get("node_a_id")
    node_b = ids.get("node_b_id")
    instance_id = ids.get("target_instance_id")
    work_order_id = ids.get("work_order_id")
    expected_audience = (
        f"splendor.daemon.approval_receipt.v2:instance:{instance_id}:run:{run_id}"
    )

    submit_rows = [
        (index, row)
        for index, row in operation_rows(api_rows, "submitWorkOrder")
        if row.get("request", {}).get("work_order", {}).get("work_order_id")
        == work_order_id
    ]
    dispatch_rows = [
        (index, row)
        for index, row in operation_rows(api_rows, "dispatchWorkOrder")
        if row_path(row) == f"/work-orders/{work_order_id}/dispatch"
    ]
    if len(submit_rows) != 1 or len(dispatch_rows) != 1:
        failures.append("s6_physical_manager_dispatch_api_cardinality_invalid")
    else:
        submit_index, submit_row = submit_rows[0]
        dispatch_index, dispatch_row = dispatch_rows[0]
        target = artifact.get("manager_target_binding", {})
        if (
            submit_index >= dispatch_index
            or submit_row.get("response") != target.get("work_order_submit")
            or dispatch_row.get("response") != target.get("dispatch")
            or dispatch_row.get("response", {}).get("selected_node_id") != node_a
            or dispatch_row.get("response", {}).get("selected_instance_id")
            != instance_id
            or dispatch_row.get("response", {}).get("run_id") != run_id
        ):
            failures.append("s6_physical_manager_dispatch_not_exact")

    physical_rows = [
        (index, row)
        for index, row in enumerate(api_rows)
        if row.get("method") == "POST"
        and row_path(row).startswith("/devices/")
        and row_path(row).endswith("/actions")
        and row.get("request", {}).get("action_id") == action_id
    ]
    coordinate_rows = [
        item
        for item in physical_rows
        if "physical_action_resource_coordinate" in item[1].get("request", {})
    ]
    unknown_rows = [
        item
        for item in physical_rows
        if "authority_override" in item[1].get("request", {})
    ]
    challenge_rows = [
        item
        for item in physical_rows
        if not item[1].get("request", {}).get("authority_obligation_receipts")
        and "physical_action_resource_coordinate" not in item[1].get("request", {})
        and "authority_override" not in item[1].get("request", {})
        and item[1].get("response", {}).get("status") == "NeedsApproval"
    ]
    receipt_rows = [
        item
        for item in physical_rows
        if item[1].get("request", {}).get("authority_obligation_receipts")
    ]
    wrong_rows = [
        item
        for item in receipt_rows
        if row_path(item[1]) == f"/devices/{node_b}/actions"
    ]
    exact_rows = [
        item
        for item in receipt_rows
        if row_path(item[1]) == f"/devices/{node_a}/actions"
        and item[1].get("response", {}).get("status") == "Executed"
    ]
    replay_rows = [
        item
        for item in receipt_rows
        if row_path(item[1]) == f"/devices/{node_a}/actions"
        and item[1].get("response", {}).get("status") == "Denied"
    ]
    classified = [
        coordinate_rows,
        unknown_rows,
        challenge_rows,
        wrong_rows,
        exact_rows,
        replay_rows,
    ]
    if any(len(rows) != 1 for rows in classified):
        failures.append("s6_physical_approval_api_cardinality_invalid")
    else:
        indexes = [rows[0][0] for rows in classified]
        coordinate_row, unknown_row, challenge_row, wrong_row, exact_row, replay_row = [
            rows[0][1] for rows in classified
        ]
        if indexes != sorted(indexes):
            failures.append("s6_physical_approval_api_order_invalid")
        closed = artifact.get("closed_schema", {})
        if (
            coordinate_row.get("status") != 422
            or unknown_row.get("status") != 422
            or coordinate_row.get("response")
            != closed.get("physical_action_resource_coordinate", {}).get("body")
            or unknown_row.get("response")
            != closed.get("unknown_authority_field", {}).get("body")
            or closed.get("simulator_unchanged") is not True
        ):
            failures.append("s6_physical_action_transport_schema_not_closed")
        challenge = artifact.get("challenge", {})
        challenge_body = challenge_row.get("response", {})
        exact_challenge = challenge_body.get("approval_challenge", {})
        if (
            challenge_row.get("status") != 200
            or challenge_body.get("status") != "NeedsApproval"
            or challenge.get("status") != "NeedsApproval"
            or challenge.get("physical_action_resource_coordinate")
            != {"resource_kind": "physical_node", "node_id": node_a}
            or exact_challenge.get("physical_action_resource_coordinate")
            != challenge.get("physical_action_resource_coordinate")
            or exact_challenge.get("canonical_request_digest")
            != challenge.get("canonical_request_digest")
            or exact_challenge.get("gateway_action_request_digest")
            != challenge.get("gateway_action_request_digest")
            or exact_challenge.get("authority_decision_digest")
            != challenge.get("authority_decision_digest")
            or exact_challenge.get("receipt_audience") != expected_audience
            or challenge.get("caller_action_param_node_id") != node_b
            or challenge.get("caller_param_did_not_override_server_coordinate")
            is not True
            or challenge.get("simulator_counter_before")
            != challenge.get("simulator_counter_after")
        ):
            failures.append("s6_physical_v2_challenge_not_server_bound")
        receipt = artifact.get("manager_approval", {}).get("receipt", {})
        grant_receipt = artifact.get("manager_approval", {}).get("grant", {}).get(
            "authority_obligation_receipt", {}
        )
        wrong_receipts = wrong_row.get("request", {}).get(
            "authority_obligation_receipts", []
        )
        exact_receipts = exact_row.get("request", {}).get(
            "authority_obligation_receipts", []
        )
        if (
            authority_receipt_projection(receipt)
            != authority_receipt_projection(grant_receipt)
            or receipt.get("audience") != expected_audience
            or len(wrong_receipts) != 1
            or len(exact_receipts) != 1
            or authority_receipt_projection(wrong_receipts[0])
            != authority_receipt_projection(receipt)
            or authority_receipt_projection(exact_receipts[0])
            != authority_receipt_projection(receipt)
        ):
            failures.append("s6_physical_receipt_not_exact")
        wrong = artifact.get("wrong_node_preclaim", {})
        if (
            wrong_row.get("status") != 409
            or wrong_row.get("response", {}).get("code")
            != "approval_challenge_retry_mismatch"
            or wrong.get("response") != {
                "status": wrong_row.get("status"),
                "body": wrong_row.get("response"),
            }
            or lifecycle_projection(wrong.get("run_before"))
            != lifecycle_projection(wrong.get("run_after"))
            or wrong.get("simulator_counter_before")
            != wrong.get("simulator_counter_after")
            or wrong.get("action_trace_ids_before")
            != wrong.get("action_trace_ids_after")
            or wrong.get("receipt_unclaimed") is not True
        ):
            failures.append("s6_wrong_node_retry_not_preclaim_rejected")
        execution = artifact.get("exact_node_execution", {})
        execution_response = exact_row.get("response", {})
        if (
            exact_row.get("status") != 200
            or execution_response != execution.get("response")
            or execution_response.get("status") != "Executed"
            or execution_response.get("output", {}).get("execution") != 1
            or execution_response.get("verification", {})
            .get("artifacts", {})
            .get("safety", {})
            .get("source")
            != "safety_verifier"
            or execution_response.get("post_verification", {})
            .get("artifacts", {})
            .get("safety", {})
            .get("source")
            != "safety_verifier"
            or execution.get("simulator_counter_after", {}).get("total")
            - execution.get("simulator_counter_before", {}).get("total")
            != 1
            or execution.get("run_after", {}).get("adapter_executions") != 1
            or execution.get("executed_exactly_once") is not True
        ):
            failures.append("s6_exact_node_did_not_execute_once_with_safety")
        replay = artifact.get("receipt_replay", {})
        if (
            replay_row.get("status") != 200
            or replay_row.get("response") != replay.get("response")
            or replay_row.get("response", {}).get("status") != "Denied"
            or replay_row.get("response", {}).get("error")
            != "authority_obligation_receipt_replayed"
            or replay.get("simulator_counter_before")
            != replay.get("simulator_counter_after")
            or replay.get("run_after", {}).get("adapter_executions") != 1
            or replay.get("denied_without_effect") is not True
        ):
            failures.append("s6_physical_receipt_replay_not_denied")

    failures.extend(
        validate_manager_approval_auth_evidence(
            manager_auth,
            api_rows,
            {"requestApproval", "grantApproval"},
            "s6",
        )
    )
    approval_order = [
        challenge_rows,
        operation_rows(api_rows, "requestApproval"),
        operation_rows(api_rows, "grantApproval"),
        wrong_rows,
        exact_rows,
        replay_rows,
    ]
    if any(len(rows) != 1 for rows in approval_order) or [
        rows[0][0] for rows in approval_order
    ] != sorted(rows[0][0] for rows in approval_order):
        failures.append("s6_physical_approval_manager_order_invalid")
    inspect_replay = artifact.get("inspect_only_replay", {})
    if (
        inspect_replay.get("response", {}).get("mode") != "inspect_only"
        or inspect_replay.get("simulator_counter_before")
        != inspect_replay.get("simulator_counter_after")
        or inspect_replay.get("unchanged") is not True
    ):
        failures.append("s6_physical_inspect_replay_changed_effects")
    if contains_bearer_bytes(manager_auth) or contains_bearer_bytes(api_rows):
        failures.append("s6_retained_evidence_contains_bearer")
    if contains_unredacted_authority_receipt_signature(artifact) or contains_unredacted_authority_receipt_signature(api_rows):
        failures.append("s6_retained_evidence_contains_receipt_signature")
    return failures


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
        "physical-approval-node-binding.json",
        "physical-approval-trace.jsonl",
        "manager-approval-auth.json",
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
    api_rows = read_jsonl(artifact_dir / "api-traffic.ndjson")
    failures.extend(
        validate_s6_physical_approval_binding(
            read_json(artifact_dir / "physical-approval-node-binding.json"),
            read_json(artifact_dir / "manager-approval-auth.json"),
            api_rows,
        )
    )
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


def validate_s7_manager_approval_auth(
    manager_auth: dict, api_rows: list[dict]
) -> list[str]:
    failures: list[str] = []
    events = manager_auth.get("events", [])
    if not isinstance(events, list) or len(events) != 2:
        return ["s7_manager_approval_auth_event_count_invalid"]
    relevant_rows = [row for row in api_rows if row.get("manager_approval_call_id")]
    events_by_id = {event.get("call_id"): event for event in events}
    rows_by_id = {row.get("manager_approval_call_id"): row for row in relevant_rows}
    if set(events_by_id) != set(rows_by_id) or len(events_by_id) != len(events):
        failures.append("s7_manager_approval_auth_api_cardinality_mismatch")
    if {event.get("operation_id") for event in events} != {
        "requestApproval",
        "grantApproval",
    }:
        failures.append("s7_manager_approval_auth_operations_invalid")
    credential_ids: list[str] = []
    for call_id, event in events_by_id.items():
        row = rows_by_id.get(call_id, {})
        request = row.get("request", {}) if isinstance(row.get("request"), dict) else {}
        credential = (
            request.get("credential", {})
            if isinstance(request.get("credential"), dict)
            else {}
        )
        audit = (
            request.get("audit_attribution", {})
            if isinstance(request.get("audit_attribution"), dict)
            else {}
        )
        response = (
            row.get("response", {}) if isinstance(row.get("response"), dict) else {}
        )
        credential_id = str(event.get("credential_id") or "")
        credential_ids.append(credential_id)
        response_trace_id = response.get("trace_event_id")
        if (
            event.get("operation_id") not in {"requestApproval", "grantApproval"}
            or event.get("method") != "POST"
            or event.get("scope") != "approvals_manage"
            or not credential_id.startswith("sha256:")
            or event.get("fleet_id") != "00000000-0000-4000-8000-000000000104"
            or event.get("target_manager_id") != "central-manager"
            or event.get("audience_manager_id") != "central-manager"
            or event.get("header_presence", {}).get("authorization") is not True
            or event.get("body_mirror_status") != "matched"
            or event.get("result_status") != 200
            or event.get("raw_bearer_recorded") is not False
            or row.get("status") != 200
            or row.get("operation_id") != event.get("operation_id")
            or row.get("transport") != "local_acceptance_http"
            or credential.get("credential_id") != credential_id
            or credential.get("scopes") != ["approvals_manage"]
            or credential.get("binding")
            != {"fleet": {"fleet_id": "00000000-0000-4000-8000-000000000104"}}
            or credential.get("audience")
            != {"central_manager": {"manager_id": "central-manager"}}
            or audit.get("credential_id") != credential_id
            or audit.get("principal") != credential.get("principal")
            or contains_bearer_bytes(row)
            or not response_trace_id
            or response_trace_id not in event.get("trace_event_ids", [])
        ):
            failures.append(f"s7_manager_approval_auth_event_invalid:{call_id}")
    if len(credential_ids) != len(set(credential_ids)):
        failures.append("s7_manager_approval_auth_jti_reused")
    if (
        manager_auth.get("status") != "passed"
        or manager_auth.get("mode") != "local_acceptance"
        or manager_auth.get("exact_scope") != "approvals_manage"
        or manager_auth.get("raw_bearers_recorded") is not False
        or manager_auth.get("production_manager_auth_claimed") is not False
        or manager_auth.get("other_manager_endpoints_authenticated_by_this_profile")
        is not False
        or manager_auth.get("fresh_mutating_credential_ids")
        != (len(credential_ids) == len(set(credential_ids)))
    ):
        failures.append("s7_manager_approval_auth_summary_invalid")
    return failures


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
        "manager-approval-auth.json",
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
    api_rows = read_jsonl(artifact_dir / "api-traffic.ndjson")
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
    challenge = artifact.get("approval_challenge", {})
    manager_request_payload = artifact.get("manager_approval_request_payload", {})
    manager_request = artifact.get("manager_approval_request", {})
    manager_grant = artifact.get("manager_approval_grant", {})
    receipt = manager_grant.get("authority_obligation_receipt", {})
    admitted_action = artifact.get("admitted_publish_action", {})
    approved_request = artifact.get("approved_exact_action_request", {})
    request_receipts = approved_request.get("authority_obligation_receipts", [])
    if not challenge or manager_request_payload.get("challenge") != challenge:
        failures.append("s7_manager_request_missing_full_exact_challenge")
    if manager_request.get("challenge") != challenge:
        failures.append("s7_manager_did_not_record_full_exact_challenge")
    for field, challenge_field in [
        ("approval_id", "approval_id"),
        ("tenant_id", "tenant_id"),
        ("agent_id", "agent_id"),
        ("run_id", "run_id"),
        ("action_id", "action_id"),
        ("action_name", "action_name"),
        ("adapter", "adapter"),
        ("policy_id", "policy_id"),
        ("risk_level", "risk_level"),
        ("audience", "receipt_audience"),
        ("expires_at", "expires_at"),
    ]:
        if manager_request_payload.get(field) != challenge.get(challenge_field):
            failures.append(f"s7_manager_request_challenge_coordinate_mismatch:{field}")
    approval_request_rows = [
        row for row in api_rows if row.get("operation_id") == "requestApproval"
    ]
    approval_grant_rows = [
        row for row in api_rows if row.get("operation_id") == "grantApproval"
    ]
    if (
        len(approval_request_rows) != 1
        or approval_request_rows[0].get("request", {}).get("challenge") != challenge
    ):
        failures.append("s7_manager_api_request_missing_full_exact_challenge")
    if (
        len(approval_grant_rows) != 1
        or approval_grant_rows[0]
        .get("response", {})
        .get("authority_obligation_receipt")
        != receipt
        or approval_grant_rows[0].get("response", {}).get("trace_event_id")
        != manager_grant.get("trace_event_id")
    ):
        failures.append("s7_manager_api_grant_receipt_not_correlated")
    if (
        manager_grant.get("status") != "granted"
        or not isinstance(receipt, dict)
        or not receipt.get("receipt_id")
        or not receipt.get("issuer")
        or receipt.get("approval_id") != challenge.get("approval_id")
        or receipt.get("audience") != challenge.get("receipt_audience")
        or receipt.get("subject") != challenge.get("subject")
        or receipt.get("authority_decision_id")
        != challenge.get("authority_decision_id")
        or receipt.get("obligation_id") != challenge.get("obligation_id")
        or receipt.get("canonical_request_digest")
        != challenge.get("canonical_request_digest")
        or receipt.get("approval_trace_event_id") != manager_grant.get("trace_event_id")
        or receipt.get("evidence_ref")
        != f"approval-trace:{manager_grant.get('trace_event_id')}"
        or artifact.get("receipt_matches_challenge") is not True
    ):
        failures.append("s7_manager_receipt_not_exact_or_trace_linked")
    if (
        approved_request.get("action_id") != challenge.get("action_id")
        or approved_request.get("action") != admitted_action.get("action")
        or approved_request.get("action", {}).get("name")
        != challenge.get("action_name")
        or approved_request.get("action", {}).get("params")
        != admitted_action.get("action", {}).get("params")
        or approved_request.get("adapter") != admitted_action.get("adapter")
        or approved_request.get("adapter") != challenge.get("adapter")
        or approved_request.get("requested_at") != challenge.get("requested_at")
        or approved_request.get("quota_usage") != admitted_action.get("quota_usage")
        or approved_request.get("satisfied_preconditions")
        != admitted_action.get("satisfied_preconditions")
        or request_receipts != [receipt]
        or "approval_evidence" in approved_request
    ):
        failures.append("s7_approved_action_did_not_preserve_exact_pending_request")
    approved_action_rows = [
        row for row in api_rows if row.get("operation_id") == "submitApprovedExactAction"
    ]
    if len(approved_action_rows) != 1:
        failures.append("s7_approved_exact_action_api_call_count_invalid")
    else:
        actual_request = approved_action_rows[0].get("request", {})
        for field in [
            "action_id",
            "run_id",
            "tenant_id",
            "agent_id",
            "causal_trace_id",
            "action",
            "adapter",
            "quota_usage",
            "satisfied_preconditions",
            "requested_at",
            "authority_obligation_receipts",
        ]:
            if actual_request.get(field) != approved_request.get(field):
                failures.append(f"s7_approved_action_api_request_mismatch:{field}")
        if "approval_evidence" in actual_request:
            failures.append("s7_approved_action_used_raw_grant_evidence")
    waiting = artifact.get("publish_run_waiting", {})
    after_exact_action = artifact.get("publish_run_after_exact_action", {})
    state_before = artifact.get("publish_state_head_before_exact_action", {})
    state_after = artifact.get("publish_state_head_after_exact_action", {})
    if (
        waiting.get("status") != "waiting_for_approval"
        or waiting.get("adapter_executions") != 0
    ):
        failures.append("s7_publish_not_waiting_with_zero_executions")
    if (
        after_exact_action.get("status") != "running"
        or after_exact_action.get("adapter_executions") != 1
    ):
        failures.append("s7_publish_not_running_after_exactly_one_execution")
    if waiting.get("ticks") != after_exact_action.get("ticks"):
        failures.append("s7_approved_action_started_second_tick")
    if (
        state_before.get("state_node_id") != state_after.get("state_node_id")
        or state_before.get("data_hash") != state_after.get("data_hash")
        or artifact.get("state_head_unchanged") is not True
    ):
        failures.append("s7_approved_action_advanced_state_head")
    publish_execution_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == challenge.get("run_id")
        and trace_record_kind(record) == "action.executed"
        and trace_record_action_name(record) == challenge.get("action_name")
    ]
    if (
        len(publish_execution_records) != 1
        or artifact.get("publish_execution_trace_count") != 1
    ):
        failures.append("s7_approved_publish_execution_count_not_one")
    resumed_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == challenge.get("run_id")
        and trace_record_kind(record) == "run.resumed"
    ]
    if not resumed_records or not set(event_ids.get("run.resumed", [])) & {
        trace_record_id(record) for record in resumed_records
    }:
        failures.append("s7_approved_publish_missing_run_resumed_evidence")
    if "publish_run_resume" in artifact or "grant" in artifact:
        failures.append("s7_stale_approval_artifact_key_present")
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
    specialist = work_orders.get("specialist_data", work_orders.get("specialist", {}))
    if "artifact.publish_external" in specialist.get("allowed_actions", []) or "artifact.publish_external" in specialist.get("allowed_permissions", []):
        failures.append("s7_specialist_work_order_overbroad")
    exact_profiles = work_orders.get("exact_profiles", {})
    expected_profiles = {
        "specialist_data": (
            "data.read_fixture",
            "fixture-data-store",
            "data.read_fixture",
            "sql.read_fixture",
        ),
        "internal_artifact": (
            "artifact.create_internal",
            "artifact-store",
            "artifact.create_internal",
            "artifact.create_internal",
        ),
        "publish": (
            "artifact.publish_external",
            "artifact-store",
            "artifact.publish_external",
            "artifact.publish_external",
        ),
        "request_message": (
            "message.remote.proposal",
            "remote-message",
            f"message.remote.proposal:{specialist.get('agent_id')}",
            "message.remote.proposal",
        ),
        "response_message": (
            "message.remote.proposal",
            "remote-message",
            f"message.remote.proposal:{work_orders.get('internal_artifact', {}).get('agent_id')}",
            "message.remote.proposal",
        ),
    }
    for profile_name, (action_name, adapter, permission, capability) in expected_profiles.items():
        profile = exact_profiles.get(profile_name, {})
        if profile.get("allowed_actions") != [action_name]:
            failures.append(f"s7_exact_profile_action_mismatch:{profile_name}")
        if profile.get("allowed_adapters") != [adapter]:
            failures.append(f"s7_exact_profile_adapter_mismatch:{profile_name}")
        if profile.get("allowed_permissions") != [permission]:
            failures.append(f"s7_exact_profile_permission_mismatch:{profile_name}")
        if profile.get("required_capabilities") != [capability]:
            failures.append(f"s7_exact_profile_capability_mismatch:{profile_name}")
        if profile.get("signature_key_id") != "work-order-acceptance-vpc":
            failures.append(f"s7_work_order_not_signed_for_vpc_instance:{profile_name}")
    message_authority = message.get("authority_binding", {})
    if (
        message_authority.get("response_work_order_run_id")
        != message_authority.get("child_run_id")
        or message_authority.get("message_run_id")
        != message_authority.get("parent_run_id")
        or message_authority.get("message_payload_is_authority") is not False
    ):
        failures.append("s7_specialist_response_authority_binding_mismatch")
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
    resident_security = read_json(artifact_dir / "resident-security.json")
    security_events = resident_security.get("events", [])
    credential_ids = [
        event.get("credential_id")
        for event in security_events
        if event.get("credential_id")
    ]
    if (
        resident_security.get("status") != "passed"
        or resident_security.get("transport") != "verified_tls"
        or not str(resident_security.get("resident_url", "")).startswith("https://")
        or resident_security.get("raw_bearer_recorded") is not False
        or resident_security.get("fresh_jti_per_request") is not True
        or not security_events
    ):
        failures.append("s7_resident_security_evidence_missing_or_invalid")
    if len(credential_ids) != len(set(credential_ids)):
        failures.append("s7_resident_mutating_jti_reused")
    for event in security_events:
        if event.get("bearer_present") is not True or event.get("tls_verified_with_acceptance_ca") is not True:
            failures.append(
                f"s7_resident_security_boundary_not_enforced:{event.get('operation_id')}"
            )
        if event.get("mutating") is True and event.get("credential_and_audit_mirrored_in_body") is not True:
            failures.append(
                f"s7_resident_mutation_missing_credential_audit_mirror:{event.get('operation_id')}"
            )
        if event.get("raw_bearer_recorded") is not False:
            failures.append(
                f"s7_resident_security_evidence_contains_bearer:{event.get('operation_id')}"
            )
    if sum(
        1
        for event in security_events
        if event.get("intentional_projection_mismatch_negative") is True
    ) != 1:
        failures.append("s7_manager_projection_negative_not_isolated")
    manager_approval_auth = read_json(artifact_dir / "manager-approval-auth.json")
    failures.extend(
        validate_s7_manager_approval_auth(manager_approval_auth, api_rows)
    )
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in [
        "private_helper_only_e2e",
        "gateway_bypass",
        "specialist_broad_permission_inheritance",
        "manager_credential_authorizes_action",
        "trace_export_without_redaction_allowed",
        "replay_side_effects_allowed_default",
        "raw_approval_evidence_used_for_execution",
        "approval_lifecycle_resume_used",
        "approval_retry_started_second_tick",
        "approval_retry_advanced_state_head",
    ]:
        if anti.get(key) is not False:
            failures.append(f"s7_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes") or not scenario.get("work_order_ids") or not scenario.get("message_ids") or not scenario.get("approval_ids"):
        failures.append("s7_missing_identity_state_message_approval_evidence")
    return scenario, failures


def load_s8_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S8"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "trace-export.jsonl",
        "trace-import-report.json",
        "state-import-report.json",
        "tamper-report.json",
        "replay-report.json",
        "schema-migration-report.json",
        "audit-package.json",
        "audit-report.json",
        "resident-security.json",
        "public-boundary-evidence.json",
        "anti-drift-results.json",
        "tampered-trace-export.jsonl",
        "tampered-state-export.json",
        "commands.log",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s8_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s8_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s8_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s8_scenario_failure:{failure}")
    sources = set(scenario.get("source_scenarios", []))
    if sources != S8_REQUIRED_SOURCE_SCENARIOS:
        failures.append("s8_wrong_source_scenarios:" + ",".join(sorted(sources)))
    for source_id in S8_REQUIRED_SOURCE_SCENARIOS:
        source_report = report_dir / "artifacts" / source_id / "scenario-report.json"
        if not source_report.exists():
            failures.append(f"s8_missing_source_scenario_report:{source_id}")
        elif read_json(source_report).get("status") != "passed":
            failures.append(f"s8_source_scenario_not_passed:{source_id}")
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S8_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s8_missing_required_trace_events:" + ",".join(missing_events))
    for event_name, ids in event_ids.items():
        if not isinstance(ids, list):
            failures.append(f"s8_trace_event_ids_not_list:{event_name}")
            continue
        for trace_id in ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s8_trace_event_id_not_uuid:{event_name}:{trace_id}")
    trace_events = read_jsonl(artifact_dir / "trace-export.jsonl")
    event_types = {record.get("event_type") for record in trace_events}
    missing_exported_events = sorted(S8_REQUIRED_EVENTS - event_types)
    if missing_exported_events:
        failures.append("s8_trace_export_missing_event_types:" + ",".join(missing_exported_events))
    trace_import = read_json(artifact_dir / "trace-import-report.json")
    public_boundary = read_json(artifact_dir / "public-boundary-evidence.json")
    public_commands = public_boundary.get("commands", [])
    if len(public_commands) < len(S8_REQUIRED_SOURCE_SCENARIOS):
        failures.append("s8_public_import_command_outputs_missing")
    if not all(item.get("command") == "acceptance validate-import" and item.get("stdout", {}).get("accepted") is True for item in public_commands if item.get("command") == "acceptance validate-import"):
        failures.append("s8_public_import_command_not_authoritative")
    imports = trace_import.get("imports", [])
    if len(imports) != len(S8_REQUIRED_SOURCE_SCENARIOS):
        failures.append("s8_trace_import_wrong_source_count")
    clean_workspace = trace_import.get("clean_workspace", "")
    if "clean-import-workspace" not in str(clean_workspace):
        failures.append("s8_clean_import_workspace_missing")
    for row in imports:
        if row.get("scenario_id") not in S8_REQUIRED_SOURCE_SCENARIOS:
            failures.append(f"s8_unknown_import_source:{row.get('scenario_id')}")
        if not str(row.get("trace_digest", "")).startswith(("sha256:", "blake3:")) or not str(row.get("trace_chain_hash", "")).startswith(("sha256:", "blake3:")):
            failures.append(f"s8_import_missing_trace_hashes:{row.get('scenario_id')}")
        if row.get("trace_records", 0) <= 0:
            failures.append(f"s8_import_empty_trace:{row.get('scenario_id')}")
        if not str(row.get("state_digest", "")).startswith(("sha256:", "blake3:")):
            failures.append(f"s8_import_missing_state_digest:{row.get('scenario_id')}")
        if row.get("public_command") != "splendorctl acceptance validate-import":
            failures.append(f"s8_import_missing_public_command:{row.get('scenario_id')}")
    state_import = read_json(artifact_dir / "state-import-report.json")
    for row in state_import.get("imports", []):
        if row.get("accepted") is not True or not row.get("matching_hashes"):
            failures.append(f"s8_state_import_not_hash_validated:{row.get('scenario_id')}")
    tamper = read_json(artifact_dir / "tamper-report.json")
    trace_tamper = tamper.get("trace", {})
    state_tamper = tamper.get("state", {})
    if trace_tamper.get("accepted") is not False or trace_tamper.get("reason_code") != "trace_chain_hash_mismatch":
        failures.append("s8_tampered_trace_not_rejected")
    if trace_tamper.get("public_command_exit") == 0:
        failures.append("s8_tampered_trace_public_validator_did_not_fail")
    if trace_tamper.get("original_chain_hash") == trace_tamper.get("tampered_chain_hash"):
        failures.append("s8_tampered_trace_chain_unchanged")
    if state_tamper.get("accepted") is not False or state_tamper.get("reason_code") != "state_hash_mismatch":
        failures.append("s8_tampered_state_not_rejected")
    if state_tamper.get("public_command_exit") == 0:
        failures.append("s8_tampered_state_public_validator_did_not_fail")
    if set(state_tamper.get("original_hashes", [])) == set(state_tamper.get("tampered_hashes", [])):
        failures.append("s8_tampered_state_hashes_unchanged")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("side_effects_allowed_default") is not False or replay.get("side_effects_executed") is not False:
        failures.append("s8_replay_side_effect_suppression_missing")
    public_replays = replay.get("public_replay_api_runs", []) or public_boundary.get("replay_api_runs", [])
    if not public_replays:
        failures.append("s8_public_replay_api_runs_missing")
    for item in public_replays:
        if not str(item.get("base_url", "")).startswith("https://"):
            failures.append(f"s8_public_replay_api_not_tls:{item.get('label')}:{item.get('run_id')}")
        if item.get("before_status") != 200 or item.get("replay_status") != 200 or item.get("after_status") != 200:
            failures.append(f"s8_public_replay_api_status_failed:{item.get('label')}:{item.get('run_id')}")
        if item.get("adapter_executions_before") is None or item.get("adapter_executions_after") is None:
            failures.append(f"s8_public_replay_counter_missing:{item.get('label')}:{item.get('run_id')}")
        if item.get("adapter_executions_before") != item.get("adapter_executions_after"):
            failures.append(f"s8_public_replay_counter_changed:{item.get('label')}:{item.get('run_id')}")
    resident_security = read_json(artifact_dir / "resident-security.json")
    security_events = resident_security.get("events", [])
    credential_ids = [
        event.get("credential_id") for event in security_events if event.get("credential_id")
    ]
    mutating_credential_ids = [
        event.get("credential_id")
        for event in security_events
        if event.get("mutating") is True and event.get("credential_id")
    ]
    if (
        resident_security.get("status") != "passed"
        or resident_security.get("transport") != "verified_tls"
        or resident_security.get("request_local_bearer") is not True
        or resident_security.get("exact_endpoint_scopes") is not True
        or resident_security.get("fresh_jti_per_request") is not True
        or resident_security.get("fresh_mutating_jti_per_request") is not True
        or resident_security.get("body_credential_and_audit_mirrors_aligned") is not True
        or resident_security.get("raw_bearer_recorded") is not False
        or not security_events
    ):
        failures.append("s8_resident_security_evidence_missing_or_invalid")
    if len(credential_ids) != len(set(credential_ids)):
        failures.append("s8_resident_request_credential_reused")
    if len(mutating_credential_ids) != len(set(mutating_credential_ids)):
        failures.append("s8_resident_mutating_jti_reused")
    for event in security_events:
        operation = event.get("operation_id")
        method = event.get("method")
        expected_scope = "runs_read" if method == "GET" else "replay_create"
        if (
            event.get("bearer_present") is not True
            or event.get("caller_credential_header_present") is not True
            or event.get("tls_verified_with_acceptance_ca") is not True
            or event.get("scope") != expected_scope
            or event.get("target_instance_id") != event.get("audience_instance_id")
        ):
            failures.append(f"s8_resident_security_boundary_not_enforced:{operation}")
        if method == "POST" and (
            event.get("credential_and_audit_mirrored_in_body") is not True
            or event.get("body_credential_matches_verified_projection") is not True
            or event.get("body_audit_matches_verified_projection") is not True
        ):
            failures.append(f"s8_resident_mutation_mirror_mismatch:{operation}")
        if event.get("raw_bearer_recorded") is not False:
            failures.append(f"s8_resident_security_evidence_contains_bearer:{operation}")
    modes = replay.get("modes", {})
    for mode in ["inspect_only", "read_only_re_evaluation", "policy_comparison", "verifier_explanation"]:
        evidence = modes.get(mode, {})
        if evidence.get("status") != "completed":
            failures.append(f"s8_replay_mode_not_completed:{mode}")
        if evidence.get("schema_version") != "splendor.acceptance.replay_mode.v1":
            failures.append(f"s8_replay_mode_missing_public_schema:{mode}")
        if evidence.get("public_command") != "splendorctl acceptance replay-mode":
            failures.append(f"s8_replay_mode_missing_public_command:{mode}")
        if evidence.get("side_effects_allowed") is not False or evidence.get("side_effects_executed") is not False:
            failures.append(f"s8_replay_mode_side_effectful:{mode}")
        for key in ["trace_digest", "state_digest", "audit_digest", "scenario_report_digest", "trace_chain_hash"]:
            if not str(evidence.get(key, "")).startswith(("sha256:", "blake3:")):
                failures.append(f"s8_replay_mode_missing_digest:{mode}:{key}")
        if not evidence.get("matching_state_hashes"):
            failures.append(f"s8_replay_mode_missing_state_hash_evidence:{mode}")
        if evidence.get("trace_records", 0) <= 0:
            failures.append(f"s8_replay_mode_empty_trace:{mode}")
    if modes.get("policy_comparison", {}).get("side_effects_executed") is not False:
        failures.append("s8_policy_comparison_executed_side_effect")
    replay_mode_outputs = replay.get("public_replay_mode_outputs", []) or public_boundary.get("replay_mode_outputs", [])
    output_modes = {item.get("mode") for item in replay_mode_outputs if item.get("command") == "acceptance replay-mode" and item.get("public_command_exit") == 0}
    missing_output_modes = sorted({"inspect_only", "read_only_re_evaluation", "policy_comparison", "verifier_explanation"} - output_modes)
    if missing_output_modes:
        failures.append("s8_public_replay_mode_outputs_missing:" + ",".join(missing_output_modes))
    unsafe = replay.get("unsafe_replay_negative", {})
    if unsafe.get("status") != "rejected" or unsafe.get("side_effects_allowed_default") is not False:
        failures.append("s8_unsafe_replay_not_rejected")
    if replay.get("real_credential_negative", {}).get("status") != "rejected":
        failures.append("s8_real_credential_replay_not_rejected")
    if replay.get("real_credential_negative", {}).get("public_command_exit") == 0:
        failures.append("s8_real_credential_public_validator_did_not_fail")
    if replay.get("adapter_executions_before") != replay.get("adapter_executions_after"):
        failures.append("s8_replay_changed_source_adapter_counts")
    schema = read_json(artifact_dir / "schema-migration-report.json")
    if schema.get("status") != "passed" or not schema.get("migrated"):
        failures.append("s8_schema_migration_not_passed")
    if not schema.get("public_command"):
        failures.append("s8_schema_migration_missing_public_command")
    if schema.get("unsupported_schema_negative", {}).get("status") != "rejected" or not schema.get("unsupported_schema_negative", {}).get("migration_guidance"):
        failures.append("s8_unsupported_schema_not_rejected_with_guidance")
    if schema.get("unsupported_schema_negative", {}).get("public_command_exit") == 0:
        failures.append("s8_unsupported_schema_public_command_did_not_fail")
    if not schema.get("generated_type_parity"):
        failures.append("s8_generated_type_parity_missing")
    if schema.get("generated_type_mismatch_negative", {}).get("compatibility_gate_failed") is not True:
        failures.append("s8_schema_mismatch_negative_not_failed")
    if schema.get("generated_type_mismatch_negative", {}).get("public_command_exit") == 0:
        failures.append("s8_schema_mismatch_public_command_did_not_fail")
    audit = read_json(artifact_dir / "audit-package.json")
    machine = audit.get("machine_readable", {})
    explanations = machine.get("verifier_explanations", [])
    categories = {item.get("category") for item in explanations}
    missing_categories = sorted(S8_REQUIRED_EXPLANATION_CATEGORIES - categories)
    if missing_categories:
        failures.append("s8_missing_verifier_explanation_categories:" + ",".join(missing_categories))
    for item in explanations:
        if not item.get("reason_codes"):
            failures.append(f"s8_audit_explanation_missing_reason_codes:{item.get('category')}")
    if audit.get("human_readable", {}).get("replay_side_effects_executed") is not False:
        failures.append("s8_audit_human_summary_allows_replay_side_effects")
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S8_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s8_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S8_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s8_negative_case_not_asserted:{case}")
        if not negatives.get(case, {}).get("reason_codes"):
            failures.append(f"s8_negative_missing_reason_codes:{case}")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "replay_side_effects_allowed_default", "real_external_credentials_used", "static_s8_evidence", "unsupported_schema_silently_accepted", "audit_denial_reason_codes_omitted"]:
        if anti.get(key) is not False:
            failures.append(f"s8_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_hashes") or not scenario.get("work_order_ids"):
        failures.append("s8_missing_imported_identity_state_work_order_evidence")
    return scenario, failures


def load_s9_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S9"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "fault-injection-report.json",
        "verifier-unavailable-report.json",
        "quota-retry-report.json",
        "idempotency-report.json",
        "failure-matrix.json",
        "trace-sync-report.json",
        "fleet-telemetry.json",
        "governance-race-report.json",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "manager-audit-export.json",
        "anti-drift-results.json",
        "commands.log",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s9_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s9_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s9_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s9_scenario_failure:{failure}")
    sources = set(scenario.get("source_scenarios", []))
    if sources != S9_REQUIRED_SOURCE_SCENARIOS:
        failures.append("s9_wrong_source_scenarios:" + ",".join(sorted(sources)))
    for source_id in S9_REQUIRED_SOURCE_SCENARIOS:
        source_report = report_dir / "artifacts" / source_id / "scenario-report.json"
        if not source_report.exists():
            failures.append(f"s9_missing_source_scenario_report:{source_id}")
        elif read_json(source_report).get("status") != "passed":
            failures.append(f"s9_source_scenario_not_passed:{source_id}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S9_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s9_missing_required_api_operations:" + ",".join(missing_ops))
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S9_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s9_missing_required_trace_events:" + ",".join(missing_events))
    for event_name, ids in event_ids.items():
        if not isinstance(ids, list):
            failures.append(f"s9_trace_event_ids_not_list:{event_name}")
            continue
        for trace_id in ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s9_trace_event_id_not_uuid:{event_name}:{trace_id}")
    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S9_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s9_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S9_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s9_negative_case_not_asserted:{case}")
        if not negatives.get(case, {}).get("reason_codes"):
            failures.append(f"s9_negative_missing_reason_codes:{case}")
    positive = scenario.get("positive_checks", {})
    for key in ["bounded_success_fixture_completed", "quotas_consumed_predictably", "bounded_retry_for_idempotent_read_only_action", "idempotency_marker_prevents_duplicate_side_effect_application", "recoverable_trace_sync_resumes_without_integrity_loss"]:
        if positive.get(key) is not True:
            failures.append(f"s9_positive_check_missing:{key}")
    fault = read_json(artifact_dir / "fault-injection-report.json")
    if set(fault.get("source_scenarios", [])) != S9_REQUIRED_SOURCE_SCENARIOS:
        failures.append("s9_fault_report_missing_source_scenarios")
    verifier_report = read_json(artifact_dir / "verifier-unavailable-report.json")
    verifier_counter = verifier_report.get("adapter_counter", {})
    if verifier_report.get("public_path") != "splendorctl run --config + splendorctl trace export" or verifier_report.get("denied_action") != "http_get":
        failures.append("s9_verifier_unavailable_report_missing_public_cli_path")
    if verifier_counter.get("http_counter_before") != verifier_counter.get("http_counter_after"):
        failures.append("s9_verifier_unavailable_report_counter_changed")
    verifier_evidence_ids = [
        row.get("trace_event_id")
        for row in verifier_report.get("required_event_evidence", [])
        if isinstance(row, dict)
    ]
    if sorted(verifier_evidence_ids) != sorted(event_ids.get("verifier.unavailable", [])):
        failures.append("s9_verifier_unavailable_report_evidence_mismatch")
    audit = read_json(artifact_dir / "audit-report.json")
    manager_export = read_json(artifact_dir / "manager-audit-export.json")
    manager_events = []
    audit_read = manager_export.get("audit_read", [])
    governance_events = manager_export.get("governance_export", {}).get("events", [])
    if isinstance(audit_read, list):
        manager_events.extend(audit_read)
    if isinstance(governance_events, list):
        manager_events.extend(governance_events)
    source_trace_records = {
        source_id: read_jsonl(report_dir / "artifacts" / source_id / "trace-export.jsonl")
        for source_id in S9_REQUIRED_SOURCE_SCENARIOS
        if (report_dir / "artifacts" / source_id / "trace-export.jsonl").exists()
    }
    failures.extend(
        validate_s9_required_event_evidence(
            scenario=scenario,
            fault=fault,
            audit=audit,
            trace_records=trace_records,
            manager_events=manager_events,
            source_trace_records=source_trace_records,
        )
    )
    quota = read_json(artifact_dir / "quota-retry-report.json")
    retry_counts = quota.get("bounded_retry_counts", {})
    retry_attempts = quota.get("retry_attempts", [])
    retry_statuses = [attempt.get("status") for attempt in retry_attempts if isinstance(attempt, dict)]
    if retry_counts.get("max_attempts") != 2 or retry_counts.get("s9.idempotent_read") != 2:
        failures.append("s9_bounded_retry_counts_invalid")
    if len(retry_attempts) != 3 or retry_statuses[:2] != ["Executed", "Executed"] or retry_statuses[2:] != ["Denied"]:
        failures.append("s9_bounded_retry_attempt_outcomes_invalid")
    if retry_counts.get("s9.idempotent_read") != retry_statuses[:2].count("Executed"):
        failures.append("s9_bounded_retry_counts_not_derived_from_attempts")
    retry_policy = quota.get("retry_policy", {})
    if retry_policy.get("mode") != "explicit_public_retry_policy" or retry_policy.get("enforced_by") != "gateway_quota" or retry_policy.get("max_attempts") != 2:
        failures.append("s9_retry_policy_shape_invalid")
    if quota.get("unsafe_retry", {}).get("status") != "Failed":
        failures.append("s9_non_idempotent_adapter_failure_missing")
    if retry_policy.get("non_idempotent_action") != "s9.unsafe_retry" or retry_policy.get("non_idempotent_submissions") != 1 or retry_policy.get("non_idempotent_failure_events") != 1 or retry_policy.get("automatic_retry_observed") is not False:
        failures.append("s9_non_idempotent_automatic_retry_not_disproven")
    if quota.get("quota_first", {}).get("status") != "Executed" or quota.get("quota_second", {}).get("status") not in {"Denied", "NeedsIntervention"}:
        failures.append("s9_quota_outcomes_invalid")
    idempotency = read_json(artifact_dir / "idempotency-report.json")
    if idempotency.get("duplicate", {}).get("duplicate") is not True or idempotency.get("duplicate", {}).get("idempotency_key") != "s9-side-effect-once":
        failures.append("s9_idempotency_duplicate_not_proven")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("side_effects_executed") is not False:
        failures.append("s9_replay_suppression_missing")
    before_counts = replay.get("action_execution_counts_before_replay", {})
    after_counts = replay.get("action_execution_counts_after_replay", {})
    if before_counts != after_counts:
        failures.append("s9_replay_changed_action_counts")
    counter_sources = before_counts.get("counter_sources", {}) if isinstance(before_counts, dict) else {}
    if counter_sources.get("adapter") != "GET /runs/{run_id}" or counter_sources.get("message") != "POST /messages/{message_id}/read" or counter_sources.get("audit") != "POST /fleet/audit/read":
        failures.append("s9_replay_counter_sources_not_public")
    for counter_name in ["adapter_executions", "manager_audit_events", "message_delivery_status", "message_duplicate"]:
        if before_counts.get(counter_name) is None or after_counts.get(counter_name) is None:
            failures.append(f"s9_replay_counter_missing:{counter_name}")
    replay_api = replay.get("public_replay_api", {})
    if replay_api.get("before_status") != 200 or replay_api.get("replay_status") != 200 or replay_api.get("after_status") != 200:
        failures.append("s9_public_replay_api_status_failed")
    if replay.get("bounded_retry_counts", {}).get("max_attempts") != 2:
        failures.append("s9_replay_missing_bounded_retry_counts")
    markers = set(replay.get("idempotency_markers", []))
    if {"s9-read-once", "s9-side-effect-once", "s9-transport-fail"} - markers:
        failures.append("s9_replay_missing_idempotency_markers")
    trace_sync = read_json(artifact_dir / "trace-sync-report.json")
    if trace_sync.get("failed_status") != 403:
        failures.append("s9_trace_sync_tamper_not_rejected")
    if trace_sync.get("recovered", {}).get("accepted_records", 0) <= 0:
        failures.append("s9_trace_sync_recovery_missing")
    if trace_sync.get("source_scenario") != "UC-E2E-S4" or trace_sync.get("source_artifact") != "UC-E2E-S4/trace-sync-report.json" or trace_sync.get("raw_sync_accepted_by_s4") is not True or trace_sync.get("tamper_rejected_by_s4") is not True:
        failures.append("s9_trace_sync_not_derived_from_s4_raw_sync")
    if trace_sync.get("redacted_records_resynced_by_s9") is not False or trace_sync.get("trace_hashes_rewritten") is not False:
        failures.append("s9_trace_sync_redacted_or_hash_rewritten")
    telemetry = read_json(artifact_dir / "fleet-telemetry.json")
    if telemetry.get("authority") != "observational_only" or telemetry.get("stale_placement", {}).get("status") != "rejected":
        failures.append("s9_telemetry_or_stale_placement_authoritative")
    governance = read_json(artifact_dir / "governance-race-report.json")
    if governance.get("circuit_breaker", {}).get("blocked_action", {}).get("status") != "Denied":
        failures.append("s9_circuit_breaker_race_not_denied")
    if governance.get("kill_switch", {}).get("missing_ack", {}).get("fail_closed") is not True:
        failures.append("s9_kill_switch_race_not_fail_closed")
    if not audit.get("bounded_retry_counts") or not audit.get("idempotency_markers"):
        failures.append("s9_audit_missing_retry_or_idempotency")
    if sorted(audit.get("required_event_evidence", {})) != sorted(S9_REQUIRED_EVENTS):
        failures.append("s9_audit_missing_required_event_evidence")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "static_s9_evidence", "unbounded_retry", "fake_success_after_adapter_failure", "verifier_or_policy_fail_open", "telemetry_authorizes_action_or_placement", "replay_side_effects_allowed_default"]:
        if anti.get(key) is not False:
            failures.append(f"s9_anti_drift_expected_false:{key}")
    if anti.get("immutable_s4_identities_reused") is not True or anti.get("redacted_trace_records_resynced") is not False or anti.get("trace_hashes_rewritten") is not False:
        failures.append("s9_anti_drift_identity_or_trace_integrity_claim_missing")
    if sorted(anti.get("derived_from_required_event_evidence", [])) != sorted(S9_REQUIRED_EVENTS):
        failures.append("s9_anti_drift_not_derived_from_event_evidence")
    if set(anti.get("public_api_operations", [])) < S9_REQUIRED_OPERATIONS:
        failures.append("s9_anti_drift_missing_public_api_operations")
    if anti.get("retry_attempt_statuses") != retry_statuses:
        failures.append("s9_anti_drift_retry_statuses_not_observed")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes") or not scenario.get("message_ids") or not scenario.get("work_order_ids") or not scenario.get("approval_ids") or not scenario.get("node_ids"):
        failures.append("s9_missing_identity_state_message_work_order_approval_node_evidence")
    return scenario, failures


def s10_resident_required_scope(method: str, url: str) -> str | None:
    path = urlsplit(url).path.rstrip("/") or "/"
    parts = [part for part in path.split("/") if part]
    if method == "GET" and path == "/health":
        return "health_read"
    if method == "POST" and path == "/runs":
        return "runs_create"
    if method == "POST" and path == "/actions":
        return "actions_submit"
    if method == "POST" and path == "/state-snapshots/export":
        return "state_handoff"
    if method == "POST" and path == "/state-snapshots/import":
        return "state_handoff"
    if method == "POST" and path == "/devices/profiles":
        return "device_register"
    if parts[:1] == ["operator"] and len(parts) >= 2 and parts[1] == "interventions" and method == "POST":
        return "operator_intervene"
    if len(parts) >= 3 and parts[0] == "devices":
        if method == "GET" and parts[2] in {"status", "policy-cache"}:
            return "device_read"
        if method == "POST" and parts[2] == "actions":
            return "actions_submit"
        if method == "POST" and parts[2:] == ["trace-buffer", "sync"]:
            return "device_trace_sync"
    if len(parts) >= 2 and parts[0] == "runs":
        if method == "GET" and len(parts) == 2:
            return "runs_read"
        if method == "POST" and parts[2:] == ["start"]:
            return "runs_start"
        if method == "POST" and parts[2:] == ["pause"]:
            return "runs_pause"
        if method == "POST" and parts[2:] == ["resume"]:
            return "runs_resume"
        if method == "GET" and parts[2:] == ["state-head"]:
            return "state_read"
        if method == "GET" and parts[2:] == ["traces"]:
            return "traces_read"
        if method == "POST" and parts[2:] == ["replay"]:
            return "replay_create"
        if method == "POST" and parts[2:] == ["traces", "export"]:
            return "traces_read"
        if method == "POST" and parts[2:] == ["governance", "circuit-breakers", "sync"]:
            return "policies_sync"
    return None


def contains_bearer_bytes(value: object) -> bool:
    if isinstance(value, str):
        return bool(
            re.search(r"(?i)\bbearer\s+\S+", value)
            or re.search(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b", value)
        )
    if isinstance(value, dict):
        return any(contains_bearer_bytes(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_bearer_bytes(item) for item in value)
    return False


def s10_resident_event_structurally_valid(event: dict) -> bool:
    status = event.get("result_status")
    expected_statuses = event.get("expected_statuses")
    expected_result = event.get("expected_result")
    mutating = event.get("mutating") is True
    correlation = event.get("correlation", {})
    if (
        not event.get("call_id")
        or not event.get("operation_id")
        or event.get("method") not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        or event.get("url_scheme") != "https"
        or event.get("tls_verification") != "acceptance_ca"
        or event.get("redirect_policy") != "disabled"
        or event.get("target_instance_id") != event.get("audience_instance_id")
        or event.get("target_audience") != f"urn:splendor:instance:{event.get('target_instance_id')}"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(event.get("credential_id", "")))
        or event.get("header_presence", {}).get("authorization") is not True
        or event.get("header_presence", {}).get("caller_credential_mirror") is not True
        or event.get("raw_bearer_recorded") is not False
        or contains_bearer_bytes(event)
        or not isinstance(expected_statuses, list)
        or not expected_statuses
        or status not in expected_statuses
    ):
        return False
    if expected_result == "success" and not (isinstance(status, int) and 200 <= status < 300):
        return False
    if expected_result == "error" and not (isinstance(status, int) and 300 <= status < 600):
        return False
    if mutating and event.get("body_mirror_status") != "matched":
        return False
    if not mutating and event.get("body_mirror_status") not in {"matched", "not_applicable"}:
        return False
    if event.get("scope_expectation") == "exact":
        if event.get("scope") != event.get("required_scope"):
            return False
    elif event.get("scope_expectation") == "intentional_mismatch":
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


def derive_s10_resident_security_summary(
    events: list[dict], invalid_call_ids: set[str] | None = None
) -> dict:
    invalid_call_ids = invalid_call_ids or {
        str(event.get("call_id"))
        for event in events
        if not s10_resident_event_structurally_valid(event)
    }
    mutating = [event for event in events if event.get("mutating") is True]
    mutating_ids = [event.get("credential_id") for event in mutating]
    unique_mutating_ids = len(set(mutating_ids))
    return {
        "total_calls": len(events),
        "mutating_calls": len(mutating),
        "read_only_calls": len(events) - len(mutating),
        "successful_response_calls": sum(isinstance(event.get("result_status"), int) and 200 <= event["result_status"] < 300 for event in events),
        "expected_error_calls": sum(event.get("expected_result") == "error" for event in events),
        "expected_result_matches": sum(event.get("result_status") in event.get("expected_statuses", []) for event in events),
        "unique_mutating_credential_ids": unique_mutating_ids,
        "response_trace_correlated_mutating_calls": sum(bool(event.get("correlation", {}).get("trace_event_ids")) for event in mutating),
        "daemon_audit_correlated_mutating_calls": sum(bool(event.get("correlation", {}).get("daemon_audit_trace_event_ids")) for event in mutating),
        "unavailable_mutating_correlations": sum(event.get("correlation", {}).get("status") == "unavailable" for event in mutating),
        "invalid_calls": len(invalid_call_ids),
        "status": "passed" if events and not invalid_call_ids and len(mutating_ids) == unique_mutating_ids else "failed",
    }


def validate_s10_resident_security(
    resident_security: dict,
    authority_profiles: dict,
    api_rows: list[dict] | None = None,
    trace_records: list[dict] | None = None,
) -> list[str]:
    failures: list[str] = []
    api_rows = api_rows or []
    trace_records = trace_records or []
    resident_calls = resident_security.get("events", [])
    if not isinstance(resident_calls, list) or not resident_calls:
        resident_calls = []
        failures.append("s10_resident_mutating_jti_reuse_or_missing_calls")
    if resident_security.get("transport") != "verified_tls" or resident_security.get("local_development_work_order_key_used") is not False:
        failures.append("s10_resident_security_transport_or_secret_redaction_failed")

    relevant_api_rows = [
        row
        for row in api_rows
        if row.get("resident_call_id")
        or urlsplit(str(row.get("url", ""))).hostname in {
            "resident-vpc-node",
            "resident-cloud-node",
            "resident-edge-node",
        }
    ]
    if contains_unredacted_authority_receipt_signature(relevant_api_rows):
        failures.append("s10_resident_security_contains_receipt_signature")
    event_ids = [event.get("call_id") for event in resident_calls]
    traffic_ids = [row.get("resident_call_id") for row in relevant_api_rows]
    if len(event_ids) != len(set(event_ids)) or len(traffic_ids) != len(set(traffic_ids)) or set(event_ids) != set(traffic_ids):
        failures.append("s10_resident_event_api_traffic_cardinality_mismatch")
    traffic_by_id = {row.get("resident_call_id"): row for row in relevant_api_rows if row.get("resident_call_id")}

    daemon_audit_ids: dict[str, set[str]] = {}
    for record in trace_records:
        payload = record.get("payload", {}) if isinstance(record, dict) else {}
        kind = payload.get("kind", {}) if isinstance(payload, dict) else {}
        audit_event = kind.get("DaemonAudit", {}) if isinstance(kind, dict) else {}
        audit = audit_event.get("audit", {}) if isinstance(audit_event, dict) else {}
        credential_id = audit.get("credential_id") if isinstance(audit, dict) else None
        event_id = payload.get("trace_event_id") if isinstance(payload, dict) else None
        if credential_id and event_id:
            daemon_audit_ids.setdefault(str(credential_id), set()).add(str(event_id))

    invalid_call_ids: set[str] = set()
    mutating_ids: list[str | None] = []
    for event in resident_calls:
        call_id = str(event.get("call_id") or "missing")
        row = traffic_by_id.get(event.get("call_id"))
        event_invalid = not s10_resident_event_structurally_valid(event)
        if row is None:
            event_invalid = True
        else:
            actual_scheme = urlsplit(str(row.get("url", ""))).scheme.lower()
            required_scope = s10_resident_required_scope(str(row.get("method", "")), str(row.get("url", "")))
            if (
                actual_scheme != "https"
                or event.get("url_scheme") != actual_scheme
                or event.get("operation_id") != row.get("operation_id")
                or event.get("method") != row.get("method")
                or event.get("result_status") != row.get("status")
                or required_scope is None
                or event.get("required_scope") != required_scope
                or row.get("transport") != "verified_tls"
                or contains_bearer_bytes(row)
            ):
                event_invalid = True
            intentional_mismatch = event.get("scope_expectation") == "intentional_mismatch"
            if intentional_mismatch:
                if event.get("scope") == required_scope or row.get("status") != 403:
                    event_invalid = True
            elif event.get("scope") != required_scope:
                event_invalid = True
            request = row.get("request") if isinstance(row.get("request"), dict) else None
            if event.get("mutating") is True:
                mutating_ids.append(event.get("credential_id"))
                credential = request.get("credential", {}) if request else {}
                audit = request.get("audit_attribution", {}) if request else {}
                if (
                    not request
                    or credential.get("credential_id") != event.get("credential_id")
                    or credential.get("scopes") != [event.get("scope")]
                    or credential.get("audience") != {"instance": {"instance_id": event.get("target_instance_id")}}
                    or audit.get("credential_id") != event.get("credential_id")
                    or event.get("body_mirror_status") != "matched"
                ):
                    event_invalid = True
            elif request is not None and event.get("body_mirror_status") == "not_applicable":
                event_invalid = True

            response = row.get("response") if isinstance(row.get("response"), dict) else {}
            exposed_ids = {
                str(response[key])
                for key in ["trace_event_id", "audit_trace_event_id"]
                if response.get(key)
            }
            correlation = event.get("correlation", {})
            reported_response_ids = set(correlation.get("trace_event_ids", []))
            reported_audit_ids = set(correlation.get("daemon_audit_trace_event_ids", []))
            expected_audit_ids = daemon_audit_ids.get(str(event.get("credential_id")), set())
            if not exposed_ids.issubset(reported_response_ids) or not expected_audit_ids.issubset(reported_audit_ids):
                event_invalid = True
            if event.get("mutating") is True:
                expected_correlation = "available" if exposed_ids or expected_audit_ids else "unavailable"
                if correlation.get("status") != expected_correlation:
                    event_invalid = True
        if event_invalid:
            invalid_call_ids.add(call_id)

    if not resident_calls or len(mutating_ids) != len(set(mutating_ids)) or any(not value for value in mutating_ids):
        failures.append("s10_resident_mutating_jti_reuse_or_missing_calls")
    if invalid_call_ids:
        failures.append("s10_resident_per_call_evidence_invalid:" + ",".join(sorted(invalid_call_ids)))
    if {row.get("target_instance_id") for row in resident_calls} < S10_INSTANCE_IDS:
        failures.append("s10_resident_security_missing_instance_coverage")
    if {row.get("required_scope") for row in resident_calls} < {"runs_create", "runs_start", "runs_pause", "runs_resume", "actions_submit", "state_handoff", "replay_create", "policies_sync"}:
        failures.append("s10_resident_security_missing_exact_scope_coverage")

    derived_summary = derive_s10_resident_security_summary(resident_calls, invalid_call_ids)
    if resident_security.get("summary") != derived_summary or resident_security.get("status") != derived_summary["status"]:
        failures.append("s10_resident_security_summary_event_mismatch")
    derived_aliases = {
        "all_calls_tls_verified": bool(resident_calls) and all(event.get("url_scheme") == "https" and event.get("tls_verification") == "acceptance_ca" for event in resident_calls),
        "all_calls_exact_one_scope": bool(resident_calls) and all(bool(event.get("scope")) for event in resident_calls),
        "all_calls_target_bound": bool(resident_calls) and all(event.get("target_instance_id") == event.get("audience_instance_id") for event in resident_calls),
        "all_body_mirrors_match_verified_projection": bool(resident_calls) and all(event.get("body_mirror_status") in {"matched", "not_applicable"} for event in resident_calls),
        "all_redirects_disabled": bool(resident_calls) and all(event.get("redirect_policy") == "disabled" for event in resident_calls),
        "mutating_credential_ids_unique": bool(mutating_ids) and len(mutating_ids) == len(set(mutating_ids)),
        "raw_bearers_recorded": any(event.get("raw_bearer_recorded") is not False or contains_bearer_bytes(event) for event in resident_calls),
    }
    if any(resident_security.get(key) != value for key, value in derived_aliases.items()):
        failures.append("s10_resident_security_summary_alias_mismatch")

    signing_profiles = resident_security.get("signing_profiles", {})
    expected_signing_keys = {
        "00000000-0000-4000-8000-000000000302": "work-order-acceptance-vpc",
        "00000000-0000-4000-8000-000000000304": "work-order-acceptance-cloud",
        "00000000-0000-4000-8000-000000000306": "work-order-acceptance-edge",
    }
    signed_for_targets = bool(signing_profiles) and all(
        profile.get("key_id") == expected_signing_keys.get(profile.get("instance_id"))
        for profile in signing_profiles.values()
    )
    if resident_security.get("all_work_orders_signed_for_target_instance") != signed_for_targets:
        failures.append("s10_resident_work_order_signing_summary_mismatch")

    profiles = authority_profiles.get("profiles", {})
    internal_profile = profiles.get("internal_artifact", {})
    publish_profile = profiles.get("external_publish", {})
    physical_profile = profiles.get("physical_edge", {})
    cloud_receiver_profile = profiles.get("cloud_receiver", {})
    if authority_profiles.get("artifact_profiles_split") is not True or internal_profile.get("run_id") == publish_profile.get("run_id"):
        failures.append("s10_artifact_authority_profiles_not_split")
    if internal_profile.get("allowed_actions") != ["artifact.create_internal"] or internal_profile.get("allowed_adapters") != ["artifact-store"] or internal_profile.get("allowed_permissions") != ["artifact.create_internal"]:
        failures.append("s10_internal_artifact_profile_not_exact")
    if publish_profile.get("allowed_actions") != ["artifact.publish_external"] or publish_profile.get("allowed_adapters") != ["artifact-store"] or publish_profile.get("allowed_permissions") != ["artifact.publish_external"]:
        failures.append("s10_publish_artifact_profile_not_exact")
    if physical_profile.get("allowed_actions") != authority_profiles.get("physical_action_allowlist") or physical_profile.get("allowed_adapters") != ["device-sim"] or physical_profile.get("allowed_permissions") != ["physical.high_level"]:
        failures.append("s10_physical_profile_not_high_level_exact")
    if cloud_receiver_profile.get("signature_key_id") != "work-order-acceptance-cloud" or authority_profiles.get("secrets_redacted") is not True:
        failures.append("s10_cloud_receiver_signing_or_secret_redaction_failed")
    return failures


def validate_s10_manager_approval_auth(
    manager_auth: dict, api_rows: list[dict] | None = None
) -> list[str]:
    api_rows = api_rows or []
    required_operations = {
        "requestApproval",
        "grantApproval",
        "revokeApprovalClaimFirst",
        "requestRevocableApproval",
        "grantRevocableApproval",
        "revokeApproval",
    }
    failures = validate_manager_approval_auth_evidence(
        manager_auth, api_rows, required_operations, "s10"
    )
    events = manager_auth.get("events", [])
    credential_ids = [event.get("credential_id") for event in events]
    if (
        manager_auth.get("status") != "passed"
        or manager_auth.get("mode") != "local_acceptance"
        or manager_auth.get("exact_scope") != "approvals_manage"
        or manager_auth.get("raw_bearers_recorded") is not False
        or manager_auth.get("production_manager_auth_claimed") is not False
        or manager_auth.get("other_manager_endpoints_authenticated_by_this_profile")
        is not False
        or manager_auth.get("raw_jtis_recorded") is not False
        or manager_auth.get("receipt_signatures_recorded") is not False
        or manager_auth.get("fresh_mutating_credential_ids")
        != (len(credential_ids) == len(set(credential_ids)))
    ):
        failures.append("s10_manager_approval_auth_summary_invalid")
    return failures


def validate_s10_approval_exact_retry(
    artifact: dict, api_rows: list[dict], trace_records: list[dict]
) -> list[str]:
    failures: list[str] = []
    needs_approval = artifact.get("publish_needs_approval", {})
    challenge = needs_approval.get("approval_challenge", {})
    publish_start = artifact.get("publish_start", {})
    approval_request = artifact.get("approval_request", {})
    approval_grant = artifact.get("approval_grant", {})
    challenge_fields = {
        "approval_id",
        "tenant_id",
        "agent_id",
        "run_id",
        "action_id",
        "action_name",
        "adapter",
        "policy_id",
        "subject",
        "receipt_audience",
        "authority_decision_id",
        "authority_decision_digest",
        "obligation_id",
        "canonical_request_digest",
        "gateway_action_request_digest",
        "requested_at",
        "expires_at",
    }
    if (
        not isinstance(challenge, dict)
        or not challenge
        or any(not challenge.get(field) for field in challenge_fields)
        or approval_request.get("challenge") != challenge
        or approval_grant.get("challenge") != challenge
        or publish_start.get("status") != "running"
        or publish_start.get("action_outcomes") != []
    ):
        failures.append("s10_approval_challenge_not_exact_across_artifacts")

    run_id = challenge.get("run_id")
    action_id = challenge.get("action_id")
    action_name = challenge.get("action_name")
    work_order_id = artifact.get("publish_work_order_id")
    target_instance_id = artifact.get("publish_manager_dispatch", {}).get(
        "selected_instance_id"
    )
    expected_audience = (
        f"splendor.daemon.approval_receipt.v2:instance:{target_instance_id}:run:{run_id}"
    )
    if challenge.get("receipt_audience") != expected_audience:
        failures.append("s10_approval_challenge_audience_not_instance_run_bound")

    submit_rows = [
        item
        for item in operation_rows(api_rows, "submitWorkOrder")
        if item[1].get("request", {}).get("work_order", {}).get("work_order_id")
        == work_order_id
    ]
    dispatch_rows = [
        item
        for item in operation_rows(api_rows, "dispatchWorkOrder")
        if row_path(item[1]) == f"/work-orders/{work_order_id}/dispatch"
    ]
    proposal_rows = operation_rows(api_rows, "submitPublishForApproval")
    if len(submit_rows) != 1 or len(dispatch_rows) != 1:
        failures.append("s10_publish_manager_dispatch_api_cardinality_invalid")
    else:
        submit_row = submit_rows[0][1]
        dispatch_row = dispatch_rows[0][1]
        if (
            submit_row.get("response") != artifact.get("publish_manager_submission")
            or dispatch_row.get("response") != artifact.get("publish_manager_dispatch")
            or dispatch_row.get("response", {}).get("run_id") != run_id
            or dispatch_row.get("response", {}).get("selected_instance_id")
            != target_instance_id
            or dispatch_row.get("response", {}).get("create_run_status") != 200
            or dispatch_row.get("response", {}).get("start_run_status") != 200
        ):
            failures.append("s10_publish_manager_dispatch_not_exact")

    proposal_row = proposal_rows[0][1] if len(proposal_rows) == 1 else {}
    proposal_request = proposal_row.get("request", {})
    if (
        len(proposal_rows) != 1
        or proposal_row.get("method") != "POST"
        or row_path(proposal_row) != "/actions"
        or proposal_row.get("status") != 200
        or proposal_row.get("response") != needs_approval
        or proposal_request.get("action_id") != action_id
        or proposal_request.get("run_id") != run_id
        or proposal_request.get("tenant_id") != challenge.get("tenant_id")
        or proposal_request.get("agent_id") != challenge.get("agent_id")
        or proposal_request.get("action", {}).get("name") != action_name
        or proposal_request.get("adapter") != challenge.get("adapter")
        or proposal_request.get("requested_at") != challenge.get("requested_at")
        or proposal_request.get("authority_obligation_receipts")
        or "approval_evidence" in proposal_request
        or needs_approval.get("status") != "NeedsApproval"
    ):
        failures.append("s10_publish_proposal_not_exact_public_action")

    request_approval_rows = [
        item
        for item in operation_rows(api_rows, "requestApproval")
        if item[1].get("request", {}).get("challenge", {}).get("approval_id")
        == challenge.get("approval_id")
    ]
    if (
        len(request_approval_rows) != 1
        or request_approval_rows[0][1].get("request", {}).get("challenge")
        != challenge
        or request_approval_rows[0][1].get("response", {}).get("challenge")
        != challenge
        or request_approval_rows[0][1].get("response") != approval_request
    ):
        failures.append("s10_manager_approval_request_not_exact")

    grant_rows = [
        item
        for item in operation_rows(api_rows, "grantApproval")
        if item[1].get("response", {}).get("approval_id")
        == challenge.get("approval_id")
    ]
    manager_grant: dict = {}
    receipt: dict = {}
    if len(grant_rows) != 1:
        failures.append("s10_manager_approval_grant_count_invalid")
    else:
        manager_grant = grant_rows[0][1].get("response", {})
        manager_receipt = manager_grant.get("authority_obligation_receipt")
        if isinstance(manager_receipt, dict):
            receipt = manager_receipt
        if (
            grant_rows[0][1].get("method") != "POST"
            or grant_rows[0][1].get("status") != 200
            or authority_receipt_projection(manager_receipt)
            != authority_receipt_projection(
                approval_grant.get("authority_obligation_receipt", {})
            )
            or manager_grant.get("challenge") != approval_grant.get("challenge")
            or approval_grant.get("status") != "granted"
        ):
            failures.append("s10_manager_approval_grant_not_correlated")

    retry_indexes = [
        index
        for index, row in enumerate(api_rows)
        if row.get("operation_id") == "submitApprovedExactAction"
    ]
    retry_row = api_rows[retry_indexes[0]] if len(retry_indexes) == 1 else {}
    if len(retry_indexes) != 1:
        failures.append("s10_approved_exact_action_api_call_count_invalid")
    if (
        retry_row.get("method") != "POST"
        or row_path(retry_row) != "/actions"
        or retry_row.get("status") != 200
    ):
        failures.append("s10_approved_exact_action_not_public_post_actions")

    retry_request = retry_row.get("request", {})
    expected_coordinates = {
        "action_id": challenge.get("action_id"),
        "run_id": challenge.get("run_id"),
        "tenant_id": challenge.get("tenant_id"),
        "agent_id": challenge.get("agent_id"),
    }
    if any(retry_request.get(field) != value for field, value in expected_coordinates.items()):
        failures.append("s10_approved_exact_action_coordinate_mismatch")
    if retry_request.get("action", {}).get("name") != action_name:
        failures.append("s10_approved_exact_action_name_mismatch")
    for field in [
        "action_id",
        "run_id",
        "tenant_id",
        "agent_id",
        "causal_trace_id",
        "action",
        "adapter",
        "quota_usage",
        "satisfied_preconditions",
        "requested_at",
    ]:
        if retry_request.get(field) != proposal_request.get(field):
            failures.append(f"s10_approved_exact_action_proposal_mismatch:{field}")
        if retry_request.get(field) != artifact.get(
            "publish_exact_action_request", {}
        ).get(field):
            failures.append(f"s10_approved_exact_action_artifact_mismatch:{field}")
    if retry_request.get("adapter") != challenge.get("adapter"):
        failures.append("s10_approved_exact_action_effective_adapter_mismatch")
    if retry_request.get("requested_at") != challenge.get("requested_at"):
        failures.append("s10_approved_exact_action_requested_at_mismatch")
    challenge_approval = (
        needs_approval.get("verification", {})
        .get("artifacts", {})
        .get("approval", {})
    )
    if challenge_approval.get("adapter") != challenge.get("adapter"):
        failures.append("s10_approval_challenge_effective_adapter_mismatch")

    retry_receipts = retry_request.get("authority_obligation_receipts", [])
    if not isinstance(retry_receipts, list) or len(retry_receipts) != 1:
        failures.append("s10_approved_exact_action_receipt_count_invalid")
    elif authority_receipt_projection(retry_receipts[0]) != authority_receipt_projection(receipt):
        failures.append("s10_approved_exact_action_receipt_not_manager_issued")
    if "approval_evidence" in retry_request:
        failures.append("s10_approved_exact_action_used_raw_approval_evidence")

    manager_trace_id = manager_grant.get("trace_event_id")
    receipt_validation = receipt.get("validation", {}) if receipt else {}
    if (
        not receipt
        or not receipt.get("receipt_id")
        or not receipt.get("issuer")
        or receipt.get("schema_version")
        != "splendor.authority.obligation_receipt.v1"
        or receipt.get("kind") != "approval_required"
        or receipt.get("revocation") != "active"
        or receipt.get("approval_id") != challenge.get("approval_id")
        or receipt.get("subject") != challenge.get("subject")
        or receipt.get("audience") != challenge.get("receipt_audience")
        or receipt.get("authority_decision_id")
        != challenge.get("authority_decision_id")
        or receipt.get("obligation_id") != challenge.get("obligation_id")
        or receipt.get("canonical_request_digest")
        != challenge.get("canonical_request_digest")
        or not str(receipt.get("evidence_digest", "")).startswith("blake3:")
        or receipt.get("expires_at") != challenge.get("expires_at")
        or receipt.get("approval_trace_event_id") != manager_trace_id
        or receipt.get("evidence_ref") != f"approval-trace:{manager_trace_id}"
        or not is_canonical_uuid(manager_trace_id)
        or not str(receipt_validation.get("digest", "")).startswith("blake3:")
    ):
        failures.append("s10_authority_receipt_not_exact_or_trace_linked")

    retry_response = retry_row.get("response", {})
    verification = retry_response.get("verification", {})
    verification_artifacts = verification.get("artifacts", {})
    obligation = verification_artifacts.get("authority_obligation", {})
    approval_result = verification_artifacts.get("approval", {}).get("approval", {})
    authority_decisions = verification_artifacts.get("authority", {}).get(
        "decisions", []
    )
    action_decisions = [
        decision
        for decision in authority_decisions
        if isinstance(decision, dict)
        and decision.get("decision_id") == challenge.get("authority_decision_id")
    ]
    receipt_id = receipt.get("receipt_id")
    obligation_id = challenge.get("obligation_id")
    response_valid = (
        retry_response.get("status") == "Executed"
        and retry_response.get("action_id") == action_id
        and retry_response.get("error") is None
        and verification.get("allowed") is True
        and retry_response.get("post_verification", {}).get("allowed") is True
        and retry_response.get("output", {}).get("execution") == 1
        and obligation.get("authority_obligation_status") == "satisfied"
        and obligation.get("decision_id") == challenge.get("authority_decision_id")
        and obligation.get("authority_decision_digest")
        == challenge.get("authority_decision_digest")
        and obligation.get("gateway_action_request_digest")
        == challenge.get("gateway_action_request_digest")
        and obligation.get("obligation_ids") == [obligation_id]
        and obligation.get("satisfied_obligation_ids") == [obligation_id]
        and obligation.get("receipt_ids") == [receipt_id]
        and obligation.get("pre_effect_recorded") is True
        and len(action_decisions) == 1
        and obligation.get("authority_decision_evidence_digest")
        == action_decisions[0].get("decision_digest")
        and approval_result.get("decision") == "Granted"
        and approval_result.get("action_id") == action_id
        and approval_result.get("adapter") == challenge.get("adapter")
    )
    if not response_valid:
        failures.append("s10_approved_exact_action_response_not_executed_and_satisfied")
    if (
        artifact.get("approved_publish") != retry_response
        or artifact.get("publish_exact_action_retry") != retry_response
    ):
        failures.append("s10_approved_exact_action_response_artifact_mismatch")

    before_inspections = operation_rows(api_rows, "inspectPublishBeforeExactRetry")
    after_inspections = operation_rows(api_rows, "inspectPublishAfterExactRetry")
    before_states = operation_rows(api_rows, "getPublishStateBeforeExactRetry")
    after_states = operation_rows(api_rows, "getPublishStateAfterExactRetry")
    if any(
        len(rows) != 1
        for rows in [before_inspections, after_inspections, before_states, after_states]
    ):
        failures.append("s10_approved_exact_action_public_run_inspections_missing")
    else:
        before = before_inspections[0][1].get("response", {})
        after = after_inspections[0][1].get("response", {})
        state_before = before_states[0][1].get("response", {})
        state_after = after_states[0][1].get("response", {})
        if (
            before.get("ticks") != after.get("ticks")
            or before.get("ticks") != publish_start.get("tick_id")
        ):
            failures.append("s10_approved_exact_action_advanced_tick")
        if (
            before.get("state_head") != after.get("state_head")
            or before.get("state_head") != publish_start.get("state_node_id")
        ):
            failures.append("s10_approved_exact_action_advanced_state_head")
        if state_projection(state_before) != state_projection(state_after):
            failures.append("s10_approved_exact_action_advanced_state_head")
        if (
            before.get("adapter_executions") != 0
            or after.get("adapter_executions") != 1
        ):
            failures.append("s10_approved_publish_public_execution_count_not_one")

    if artifact.get("publish_execution_count_for_positive_run") != 1:
        failures.append("s10_approved_publish_artifact_execution_count_not_one")

    pending_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == run_id
        and trace_record_action_id(record) == action_id
        and trace_record_kind(record) == "action.needs_approval"
        and trace_record_action_name(record) == action_name
    ]
    if (
        len(pending_records) != 1
        or trace_record_kind_payload(pending_records[0]).get("action")
        != proposal_request.get("action")
    ):
        failures.append("s10_approved_publish_pending_trace_not_exact")

    execution_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == run_id
        and trace_record_action_id(record) == action_id
        and trace_record_kind(record) == "action.executed"
        and trace_record_action_name(record) == action_name
    ]
    if (
        len(execution_records) != 1
        or trace_record_kind_payload(execution_records[0]).get("action")
        != proposal_request.get("action")
        or execution_records
        and trace_record_kind_payload(execution_records[0])
        .get("outcome", {})
        .get("execution")
        != 1
    ):
        failures.append("s10_approved_publish_execution_trace_count_not_one")

    resumed_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == run_id
        and trace_record_kind(record) == "run.resumed"
    ]
    if (
        len(execution_records) != 1
        or len(resumed_records) != 1
        or trace_record_sequence(resumed_records[0])
        <= trace_record_sequence(execution_records[0])
        or trace_record_kind_payload(resumed_records[0]).get("reason")
        != "exact approved action executed"
    ):
        failures.append("s10_approved_publish_post_effect_resume_missing")

    lifecycle_resume_rows = [
        row
        for row in api_rows
        if row.get("method") == "POST"
        and row_path(row) == f"/runs/{run_id}/resume"
    ]
    if lifecycle_resume_rows:
        failures.append("s10_approved_publish_used_lifecycle_resume")
    order_groups = [
        submit_rows,
        dispatch_rows,
        proposal_rows,
        request_approval_rows,
        grant_rows,
        before_inspections,
        before_states,
        [(retry_indexes[0], retry_row)] if len(retry_indexes) == 1 else [],
        after_inspections,
        after_states,
    ]
    if all(len(group) == 1 for group in order_groups):
        indexes = [group[0][0] for group in order_groups]
        if indexes != sorted(indexes):
            failures.append("s10_approved_publish_api_order_invalid")
    if contains_unredacted_authority_receipt_signature(artifact) or contains_unredacted_authority_receipt_signature(
        [row for _, row in proposal_rows + request_approval_rows + grant_rows]
        + [retry_row]
    ):
        failures.append("s10_retained_approval_evidence_contains_receipt_signature")
    return failures


def trace_record_sequence(record: dict) -> int:
    sequence = record.get("sequence")
    if not isinstance(sequence, int):
        sequence = record.get("payload", {}).get("sequence")
    return sequence if isinstance(sequence, int) else -1


def validate_s10_active_raw_rejection(
    artifact: dict, api_rows: list[dict]
) -> list[str]:
    failures: list[str] = []
    required = [
        "inspectPublishBeforeExpiredRaw",
        "getPublishStateBeforeExpiredRaw",
        "getPublishTracesBeforeExpiredRaw",
        "submitExpiredRawApprovalOnActiveRun",
        "inspectPublishAfterExpiredRaw",
        "getPublishStateAfterExpiredRaw",
        "getPublishTracesAfterExpiredRaw",
    ]
    groups = [operation_rows(api_rows, operation) for operation in required]
    if any(len(group) != 1 for group in groups):
        return ["s10_active_raw_api_cardinality_invalid"]
    indexes = [group[0][0] for group in groups]
    rows = [group[0][1] for group in groups]
    if indexes != sorted(indexes):
        failures.append("s10_active_raw_api_order_invalid")
    before_run, before_state, before_traces, raw_row, after_run, after_state, after_traces = rows
    if (
        raw_row.get("method") != "POST"
        or row_path(raw_row) != "/actions"
        or raw_row.get("status") != 409
        or raw_row.get("response") != artifact.get("expired_approval", {}).get("body")
        or raw_row.get("response", {}).get("code")
        != "legacy_approval_evidence_non_authorizing"
        or not isinstance(raw_row.get("request", {}).get("approval_evidence"), dict)
        or raw_row.get("request", {}).get("authority_obligation_receipts")
    ):
        failures.append("s10_active_raw_not_pre_gateway_rejected")
    evidence = artifact.get("expired_raw_active_run", {})
    if (
        lifecycle_projection(before_run.get("response"))
        != lifecycle_projection(after_run.get("response"))
        or lifecycle_projection(before_run.get("response"))
        != lifecycle_projection(evidence.get("run_before"))
        or state_projection(before_state.get("response"))
        != state_projection(after_state.get("response"))
        or state_projection(before_state.get("response"))
        != state_projection(evidence.get("state_before"))
        or evidence.get("lifecycle_unchanged") is not True
        or evidence.get("state_unchanged") is not True
        or evidence.get("pre_gateway_rejected_unchanged") is not True
        or evidence.get("no_new_approval_action_outcome_trace") is not True
    ):
        failures.append("s10_active_raw_changed_lifecycle_tick_state_or_effect")

    def decision_trace_ids(row: dict) -> list[str]:
        records = row.get("response", {}).get("records", [])
        return sorted(
            trace_record_id(record)
            for record in records
            if trace_record_id(record)
            and (
                trace_record_kind(record).startswith("action.")
                or trace_record_kind(record).startswith("approval.")
                or trace_record_kind(record).startswith("Approval")
                or trace_record_kind(record)
                in {"verification.started", "verification.completed", "outcome.recorded"}
            )
        )

    before_ids = decision_trace_ids(before_traces)
    after_ids = decision_trace_ids(after_traces)
    if (
        before_ids != after_ids
        or before_ids != evidence.get("decision_trace_ids_before")
        or after_ids != evidence.get("decision_trace_ids_after")
    ):
        failures.append("s10_active_raw_appended_decision_trace")
    return failures


def validate_s10_approval_revocation(
    report: dict,
    resident_security: dict,
    manager_auth: dict,
    api_rows: list[dict],
    trace_records: list[dict],
) -> list[str]:
    failures: list[str] = []
    revoke = report.get("revoke_before_claim", {})
    run_id = revoke.get("run_id")
    work_order_id = revoke.get("work_order_id")
    challenge = revoke.get("challenge", {})
    receipt = revoke.get("retained_receipt", {})
    target_instance_id = revoke.get("target_instance_id")
    expected_audience = (
        f"splendor.daemon.approval_receipt.v2:instance:{target_instance_id}:run:{run_id}"
    )
    if (
        report.get("status") != "passed"
        or report.get("schema_version")
        != "splendor.uc_e2e_s10.approval_receipt_revocation.v1"
        or report.get("uncertainty_mocked") is not False
        or report.get("exact_resident_scope")
        != "splendor.approval_receipts.revoke"
        or report.get("fresh_manager_jtis") is not True
        or report.get("fresh_resident_revocation_jtis") is not True
        or report.get("raw_bearers_recorded") is not False
        or report.get("raw_jtis_recorded") is not False
        or report.get("receipt_signatures_recorded_in_per_call_evidence") is not False
    ):
        failures.append("s10_revocation_report_summary_invalid")

    submit_rows = [
        item
        for item in operation_rows(api_rows, "submitWorkOrder")
        if item[1].get("request", {}).get("work_order", {}).get("work_order_id")
        == work_order_id
    ]
    dispatch_rows = [
        item
        for item in operation_rows(api_rows, "dispatchWorkOrder")
        if row_path(item[1]) == f"/work-orders/{work_order_id}/dispatch"
    ]
    operation_names = [
        "submitRevocablePublishForApproval",
        "requestRevocableApproval",
        "grantRevocableApproval",
        "inspectRevocablePublishBeforeManagerRevoke",
        "getRevocablePublishStateBeforeManagerRevoke",
        "revokeApproval",
        "inspectRevocablePublishAfterManagerRevoke",
        "submitRevokedOriginalReceipt",
        "inspectRevocablePublishAfterDeniedRetry",
        "getRevocablePublishStateAfterDeniedRetry",
    ]
    groups = [submit_rows, dispatch_rows] + [
        operation_rows(api_rows, operation) for operation in operation_names
    ]
    if any(len(group) != 1 for group in groups):
        failures.append("s10_revocation_api_cardinality_invalid")
        rows: list[dict] = []
    else:
        indexes = [group[0][0] for group in groups]
        rows = [group[0][1] for group in groups]
        if indexes != sorted(indexes):
            failures.append("s10_revocation_api_order_invalid")

    if rows:
        (
            submit_row,
            dispatch_row,
            proposal_row,
            request_row,
            grant_row,
            before_row,
            state_before_row,
            manager_revoke_row,
            after_revoke_row,
            retry_row,
            after_retry_row,
            state_after_row,
        ) = rows
        if (
            submit_row.get("status") != revoke.get("manager_submission", {}).get("status")
            or submit_row.get("response")
            != revoke.get("manager_submission", {}).get("body")
            or dispatch_row.get("status")
            != revoke.get("manager_dispatch", {}).get("status")
            or dispatch_row.get("response")
            != revoke.get("manager_dispatch", {}).get("body")
            or dispatch_row.get("response", {}).get("selected_instance_id")
            != target_instance_id
            or dispatch_row.get("response", {}).get("run_id") != run_id
        ):
            failures.append("s10_revocation_manager_dispatch_not_exact")
        proposal = proposal_row.get("response", {})
        if (
            proposal_row.get("status") != 200
            or proposal.get("status") != "NeedsApproval"
            or proposal.get("approval_challenge") != challenge
            or proposal_row.get("request", {}).get("authority_obligation_receipts")
            or "approval_evidence" in proposal_row.get("request", {})
        ):
            failures.append("s10_revocation_proposal_not_exact")
        grant_receipt = grant_row.get("response", {}).get(
            "authority_obligation_receipt", {}
        )
        if (
            request_row.get("request", {}).get("challenge") != challenge
            or grant_row.get("response", {}).get("challenge") != challenge
            or grant_row.get("response", {}).get("status") != "granted"
            or grant_row.get("response", {}).get("trace_event_id")
            != revoke.get("grant", {}).get("trace_event_id")
            or grant_receipt.get("receipt_id") != receipt.get("receipt_id")
            or grant_receipt.get("approval_id") != receipt.get("approval_id")
            or grant_receipt.get("audience") != expected_audience
            or receipt.get("audience") != expected_audience
            or receipt.get("revocation") != "active"
        ):
            failures.append("s10_revocation_receipt_or_challenge_mismatch")
        acknowledgement = revoke.get("resident_ack", {})
        if (
            manager_revoke_row.get("status") != 200
            or manager_revoke_row.get("response", {}).get(
                "resident_receipt_revocation_ack"
            )
            != acknowledgement
            or manager_revoke_row.get("response", {}).get("status") != "revoked"
            or manager_revoke_row.get("response", {}).get("evidence", {}).get(
                "revoked"
            )
            is not True
            or acknowledgement.get("schema_version")
            != "splendor.resident.approval_receipt_revocation_ack.v1"
            or acknowledgement.get("status") not in {"revoked", "already_revoked"}
            or acknowledgement.get("effect_certainty") != "known"
            or acknowledgement.get("receipt_id") != receipt.get("receipt_id")
            or acknowledgement.get("approval_id") != receipt.get("approval_id")
            or acknowledgement.get("run_id") != run_id
            or acknowledgement.get("target_instance_id") != target_instance_id
            or acknowledgement.get("receipt_audience") != expected_audience
        ):
            failures.append("s10_revocation_resident_ack_not_exact")
        retry_receipts = retry_row.get("request", {}).get(
            "authority_obligation_receipts", []
        )
        retry_outcome = retry_row.get("response", {})
        if (
            len(retry_receipts) != 1
            or any(
                retry_receipts[0].get(key) != receipt.get(key)
                for key in [
                    "schema_version",
                    "receipt_id",
                    "approval_id",
                    "audience",
                    "revocation",
                ]
            )
            or retry_row.get("status") != 200
            or retry_outcome != revoke.get("retry_outcome")
            or retry_outcome.get("status") != "Denied"
            or retry_outcome.get("error")
            != "authority_obligation_receipt_revoked"
            or retry_outcome.get("output") is not None
        ):
            failures.append("s10_revoked_original_receipt_not_denied")
        before = lifecycle_projection(before_row.get("response"))
        after_revoke = lifecycle_projection(after_revoke_row.get("response"))
        after_retry = lifecycle_projection(after_retry_row.get("response"))
        if (
            before != lifecycle_projection(revoke.get("run_before_revoke"))
            or after_revoke != lifecycle_projection(revoke.get("run_after_revoke"))
            or after_retry != lifecycle_projection(revoke.get("run_after_retry"))
            or before != after_revoke
            or before != after_retry
            or before.get("adapter_executions") != 0
            or state_projection(state_before_row.get("response"))
            != state_projection(state_after_row.get("response"))
            or state_projection(state_before_row.get("response"))
            != state_projection(revoke.get("state_before_revoke"))
            or revoke.get("zero_effect") is not True
        ):
            failures.append("s10_revocation_changed_tick_state_or_effect")

    manager_events = manager_auth.get("events", [])
    manager_calls = report.get("manager_calls", [])
    expected_manager_calls = [
        event
        for event in manager_events
        if event.get("operation_id") in {"revokeApprovalClaimFirst", "revokeApproval"}
    ]
    if manager_calls != expected_manager_calls:
        failures.append("s10_revocation_manager_call_projection_mismatch")
    resident_calls = report.get("resident_calls", [])
    resident_security_calls = resident_security.get(
        "manager_dispatched_approval_receipt_revocations", []
    )
    manager_auth_calls = manager_auth.get("resident_approval_receipt_revocations", [])
    if (
        len(resident_calls) != 1
        or resident_calls != resident_security_calls
        or resident_calls != manager_auth_calls
    ):
        failures.append("s10_revocation_resident_call_projection_mismatch")
    else:
        resident_call = resident_calls[0]
        manager_revoke_call_ids = {
            event.get("call_id")
            for event in manager_events
            if event.get("operation_id") == "revokeApproval"
        }
        if (
            resident_call.get("operation_id") != "revokeApprovalReceipt"
            or resident_call.get("method") != "POST"
            or resident_call.get("manager_approval_call_id")
            not in manager_revoke_call_ids
            or resident_call.get("scope")
            != "splendor.approval_receipts.revoke"
            or resident_call.get("required_scope")
            != "splendor.approval_receipts.revoke"
            or resident_call.get("scope_expectation") != "exact"
            or resident_call.get("url_scheme") != "https"
            or resident_call.get("tls_verification") != "acceptance_ca"
            or resident_call.get("redirect_policy") != "disabled"
            or resident_call.get("target_instance_id") != target_instance_id
            or resident_call.get("audience_instance_id") != target_instance_id
            or resident_call.get("target_audience")
            != f"urn:splendor:instance:{target_instance_id}"
            or resident_call.get("run_id") != run_id
            or resident_call.get("receipt_id") != receipt.get("receipt_id")
            or resident_call.get("approval_id") != receipt.get("approval_id")
            or resident_call.get("receipt_audience") != expected_audience
            or resident_call.get("result_status") != 200
            or resident_call.get("ack_status") not in {"revoked", "already_revoked"}
            or resident_call.get("effect_certainty") != "known"
            or resident_call.get("fresh_one_use_jti") is not True
            or resident_call.get("credential_id")
            != resident_call.get("credential_correlation_id")
            or resident_call.get("raw_bearer_recorded") is not False
            or resident_call.get("raw_jti_recorded") is not False
            or resident_call.get("receipt_signature_recorded") is not False
        ):
            failures.append("s10_revocation_resident_security_invalid")

    claim = report.get("claim_before_revoke", {})
    claim_rows = operation_rows(api_rows, "revokeApprovalClaimFirst")
    if (
        len(claim_rows) != 1
        or claim_rows[0][1].get("status") != 409
        or claim_rows[0][1].get("response")
        != claim.get("manager_response", {}).get("body")
        or claim.get("manager_response", {}).get("status") != 409
        or claim.get("outcome") != "too_late"
        or claim.get("effect_certainty") != "known"
        or claim.get("too_late_observed") is not True
        or claim.get("successful_revocation_claimed") is not False
        or claim.get("effect_unknown_observed") is not False
        or claim_rows[0][1].get("response", {}).get("details", {}).get(
            "revocation_applied"
        )
        is not False
    ):
        failures.append("s10_claim_before_revoke_false_success_or_status")

    execution_records = [
        record
        for record in trace_records
        if trace_record_run_id(record) == run_id
        and trace_record_kind(record) == "action.executed"
        and trace_record_action_name(record) == challenge.get("action_name")
    ]
    if execution_records:
        failures.append("s10_revoked_receipt_reached_adapter")
    if contains_unredacted_authority_receipt_signature(report) or contains_unredacted_authority_receipt_signature(
        api_rows
    ):
        failures.append("s10_revocation_evidence_contains_receipt_signature")
    return failures


def validate_s10_trace_sync_evidence(trace_sync: dict) -> list[str]:
    failures: list[str] = []
    for key in ["vpc", "edge", "cloud"]:
        if trace_sync.get(key, {}).get("accepted_records", 0) <= 0:
            failures.append(f"s10_trace_sync_missing_records:{key}")
    redacted_rejection = trace_sync.get(
        "edge_central_redacted_export_rejection", {}
    )
    if (
        redacted_rejection.get("status") != 403
        or redacted_rejection.get("body", {}).get("code") != "trace_sync_rejected"
        or trace_sync.get("redacted_edge_export_resynced") is not False
        or trace_sync.get("trace_hashes_rewritten") is not False
    ):
        failures.append("s10_edge_redacted_trace_integrity_boundary_missing")
    if trace_sync.get("tampered", {}).get("status") != 403:
        failures.append("s10_tampered_trace_sync_not_rejected")
    return failures


def load_s10_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S10"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "human-summary.md",
        "api-contract-report.json",
        "topology.json",
        "registry-report.json",
        "journey-report.json",
        "message-flow.json",
        "message-api-report.json",
        "artifact-publication-report.json",
        "approval-receipt-revocation-report.json",
        "cloud-helper-report.json",
        "edge-inspection-report.json",
        "state-handoff-report.json",
        "trace-sync-report.json",
        "governance-branches.json",
        "negative-branches.json",
        "fleet-telemetry.json",
        "state-export.json",
        "trace-export.jsonl",
        "replay-report.json",
        "audit-package.json",
        "audit-report.json",
        "manager-audit-export.json",
        "fr-primitive-coverage-matrix.json",
        "anti-drift-results.json",
        "resident-security.json",
        "manager-approval-auth.json",
        "authority-profiles-report.json",
        "api-traffic.ndjson",
        "commands.log",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s10_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s10_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s10_scenario_report_failed")
    for failure in scenario.get("scenario_failures", []):
        failures.append(f"s10_scenario_failure:{failure}")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S10_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s10_missing_required_api_operations:" + ",".join(missing_ops))
    positives = scenario.get("positive_checks", {})
    missing_positives = sorted(S10_REQUIRED_POSITIVES - set(positives))
    if missing_positives:
        failures.append("s10_missing_positive_checks:" + ",".join(missing_positives))
    for key in S10_REQUIRED_POSITIVES & set(positives):
        if positives.get(key) is not True:
            failures.append(f"s10_positive_check_not_asserted:{key}")
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S10_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s10_missing_negative_cases:" + ",".join(missing_negatives))
    for case in S10_REQUIRED_NEGATIVES & set(negatives):
        if negatives.get(case, {}).get("passed") is not True:
            failures.append(f"s10_negative_case_not_asserted:{case}")
    event_ids = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S10_REQUIRED_EVENTS if not event_ids.get(event))
    if missing_events:
        failures.append("s10_missing_required_trace_events:" + ",".join(missing_events))
    for event_name, ids in event_ids.items():
        if not isinstance(ids, list):
            failures.append(f"s10_trace_event_ids_not_list:{event_name}")
            continue
        for trace_id in ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s10_trace_event_id_not_uuid:{event_name}:{trace_id}")

    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    for record in trace_records:
        if record.get("event_type") or record.get("scenario_id"):
            failures.append("s10_trace_export_contains_synthetic_top_level_event")
            break
    trace_ids = {trace_record_id(record) for record in trace_records if trace_record_id(record)}
    manager_export = read_json(artifact_dir / "manager-audit-export.json")
    manager_events: list[dict] = []
    if isinstance(manager_export.get("audit_read"), list):
        manager_events.extend(manager_export["audit_read"])
    if isinstance(manager_export.get("governance_export", {}).get("events"), list):
        manager_events.extend(manager_export["governance_export"]["events"])
    manager_ids = {event.get("trace_event_id") for event in manager_events if event.get("trace_event_id")}
    response_ids: set[str] = set()
    for name in [
        "journey-report.json",
        "message-flow.json",
        "message-api-report.json",
        "artifact-publication-report.json",
        "cloud-helper-report.json",
        "edge-inspection-report.json",
        "state-handoff-report.json",
        "trace-sync-report.json",
        "governance-branches.json",
        "replay-report.json",
        "audit-package.json",
    ]:
        response_ids.update(collect_values_for_key(read_json(artifact_dir / name), "trace_event_id"))
    backed_ids = trace_ids | manager_ids | response_ids
    for event_name, ids in event_ids.items():
        for trace_id in ids:
            if trace_id not in backed_ids:
                failures.append(f"s10_required_event_id_not_backed_by_exported_evidence:{event_name}:{trace_id}")
    audit_package = read_json(artifact_dir / "audit-package.json")
    failures.extend(
        validate_s10_required_event_evidence(
            scenario=scenario,
            audit=audit_package,
            trace_records=trace_records,
            manager_events=manager_events,
            response_ids=response_ids,
        )
    )

    required_identity_fields = {
        "run_ids",
        "trace_event_ids",
        "state_node_ids",
        "state_hashes",
        "message_ids",
        "work_order_ids",
        "approval_ids",
        "node_ids",
        "instance_ids",
        "action_ids",
        "policy_ids",
        "circuit_breaker_ids",
        "kill_switch_ids",
        "artifact_ids",
    }
    for key in sorted(required_identity_fields):
        if not scenario.get(key):
            failures.append(f"s10_missing_required_identity_field:{key}")
    if len(scenario.get("run_ids", [])) < 6 or len(scenario.get("message_ids", [])) < 4 or len(scenario.get("node_ids", [])) < 3 or len(scenario.get("instance_ids", [])) < 3:
        failures.append("s10_identity_cardinality_too_low")

    contract_report = read_json(artifact_dir / "api-contract-report.json")
    if contract_report.get("contract", {}).get("status") != "passed" or not str(contract_report.get("digest", "")).startswith("sha256:"):
        failures.append("s10_api_contract_report_not_passed")
    topology = read_json(artifact_dir / "topology.json")
    if not str(topology.get("topology_hash", "")).startswith("sha256:") or len(topology.get("services", [])) < 5:
        failures.append("s10_topology_hash_or_services_missing")
    registry = read_json(artifact_dir / "registry-report.json")
    if registry.get("all_registration_requests_accepted") is not True or registry.get("duplicate_registration_rejections_treated_as_success") is not False:
        failures.append("s10_registry_registration_requests_not_accepted")
    for group in ["node_registrations", "instance_registrations"]:
        for item in registry.get(group, []):
            if item.get("status") != 200:
                failures.append(f"s10_registry_status_not_accepted:{group}:{item.get('status')}")
    if registry.get("canonical_s4_registration_reused") is not True:
        failures.append("s10_canonical_s4_registration_not_reused")
    resident_security = read_json(artifact_dir / "resident-security.json")
    manager_approval_auth = read_json(artifact_dir / "manager-approval-auth.json")
    authority_profiles = read_json(artifact_dir / "authority-profiles-report.json")
    api_rows = read_jsonl(artifact_dir / "api-traffic.ndjson")
    failures.extend(
        validate_s10_resident_security(
            resident_security,
            authority_profiles,
            api_rows,
            trace_records,
        )
    )
    failures.extend(
        validate_s10_manager_approval_auth(
            manager_approval_auth, api_rows
        )
    )
    journey = read_json(artifact_dir / "journey-report.json")
    if journey.get("data_analysis", {}).get("status") != "Executed":
        failures.append("s10_journey_data_analysis_not_executed")
    message_api = read_json(artifact_dir / "message-api-report.json")
    required_message_ops = {
        "listMessageSchemas",
        "validateMessageSchema",
        "listInbox",
        "listOutbox",
        "getMessageCausalGraph",
        "ackMessage",
        "nackMessage",
    }
    if set(message_api.get("operations", [])) < required_message_ops:
        failures.append("s10_message_api_operations_missing")
    if message_api.get("schema_validation", {}).get("valid") is not True:
        failures.append("s10_message_schema_validation_not_positive")
    if message_api.get("unsupported_schema_validation", {}).get("valid") is not False:
        failures.append("s10_message_unsupported_schema_not_rejected")
    if message_api.get("cross_tenant_read", {}).get("status") != 403:
        failures.append("s10_cross_tenant_message_read_not_rejected")
    if message_api.get("ack_scope_failure", {}).get("status") != 403 or message_api.get("nack_payload_mutation_denial", {}).get("status") != 400:
        failures.append("s10_ack_nack_negative_scope_or_payload_missing")
    if message_api.get("causal_graph", {}).get("node_count", 0) < 2:
        failures.append("s10_message_causal_graph_missing_nodes")
    artifact = read_json(artifact_dir / "artifact-publication-report.json")
    if artifact.get("publish_needs_approval", {}).get("status") != "NeedsApproval":
        failures.append("s10_publish_did_not_pause_for_approval")
    if artifact.get("approved_publish", {}).get("status") != "Executed" or artifact.get("publish_execution_count_for_positive_run") != 1:
        failures.append("s10_publish_not_executed_once_after_approval")
    if artifact.get("internal_run_id") == artifact.get("publish_run_id"):
        failures.append("s10_publish_artifact_runs_not_split")
    failures.extend(
        validate_s10_approval_exact_retry(artifact, api_rows, trace_records)
    )
    failures.extend(validate_s10_active_raw_rejection(artifact, api_rows))
    failures.extend(
        validate_s10_approval_revocation(
            read_json(artifact_dir / "approval-receipt-revocation-report.json"),
            resident_security,
            manager_approval_auth,
            api_rows,
            trace_records,
        )
    )
    internal = artifact.get("internal_artifact_evidence", {})
    approved = artifact.get("approved_publish_evidence", {})
    for label, evidence in {"internal": internal, "approved_publish": approved}.items():
        if not evidence.get("artifact_path") or not evidence.get("integrity") or not evidence.get("trace_event_id"):
            failures.append(f"s10_artifact_evidence_missing:{label}")

    cloud = read_json(artifact_dir / "cloud-helper-report.json")
    proposal = cloud.get("proposal", {}).get("message", {}).get("payload", {})
    if proposal.get("direct_actuator_authority") is not False or proposal.get("publication_authority") is not False:
        failures.append("s10_cloud_helper_not_proposal_only")
    if cloud.get("publish_denial", {}).get("status") != "Denied" or cloud.get("device_direct_denial", {}).get("status") != "Denied":
        failures.append("s10_cloud_helper_direct_authority_not_denied")
    edge = read_json(artifact_dir / "edge-inspection-report.json")
    simulator_evidence = edge.get("simulator_evidence", [])
    for item in simulator_evidence:
        if item.get("total_delta") != item.get("expected_sim_delta"):
            failures.append(f"s10_simulator_delta_mismatch:{item.get('label')}")
    if edge.get("inspect_zone", {}).get("status") != "Executed" or edge.get("device_trace_sync", {}).get("accepted") is not True:
        failures.append("s10_edge_inspection_or_trace_sync_missing")
    state = read_json(artifact_dir / "state-handoff-report.json")
    import_denied = state.get("resident_import_denied", {})
    if import_denied.get("status") != 503 or import_denied.get("body", {}).get("code") != "state_handoff_proof_unavailable":
        failures.append("s10_resident_state_handoff_not_denied_without_source_proof")
    if state.get("receiver_unchanged_on_import_denial") is not True:
        failures.append("s10_resident_handoff_denial_mutated_receiver_state")
    if state.get("receiver_create_import_resume_used_exact_admitted_envelope") is not True or state.get("receiver_envelope_key_id") != "work-order-acceptance-cloud":
        failures.append("s10_resident_handoff_receiver_envelope_not_exact")
    if state.get("cloud_resume", {}).get("status") not in {"running", "waiting_for_approval", "completed"}:
        failures.append("s10_receiver_own_state_resume_missing")
    if state.get("tampered_state_import", {}).get("status") != 503:
        failures.append("s10_tampered_state_import_not_rejected")
    trace_sync = read_json(artifact_dir / "trace-sync-report.json")
    failures.extend(validate_s10_trace_sync_evidence(trace_sync))
    governance = read_json(artifact_dir / "governance-branches.json")
    if governance.get("circuit_breaker", {}).get("blocked_action", {}).get("status") != "Denied":
        failures.append("s10_circuit_breaker_branch_not_denied")
    if governance.get("kill_switch", {}).get("activated", {}).get("cancel_status") != 200:
        failures.append("s10_kill_switch_branch_not_cancelled")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("side_effects_executed") is not False:
        failures.append("s10_replay_suppression_missing")
    if replay.get("counts_before_replay") != replay.get("counts_after_replay"):
        failures.append("s10_replay_changed_public_counters")
    if replay.get("unsafe_replay_negative", {}).get("status") not in {400, 403}:
        failures.append("s10_unsafe_replay_not_rejected")
    audit = read_json(artifact_dir / "audit-package.json")
    human = audit.get("human_readable", {})
    if human.get("replay_side_effects_executed") is not False or human.get("telemetry_authorized_actions") is not False or human.get("physical_actions_high_level_only") is not True:
        failures.append("s10_audit_human_summary_invariant_missing")
    coverage = read_json(artifact_dir / "fr-primitive-coverage-matrix.json")
    if set(coverage.get("primitives", {})) < S10_REQUIRED_PRIMITIVES:
        failures.append("s10_primitive_coverage_matrix_incomplete")
    required_fr_groups = {"FR-0.01-01..07", "FR-0.02-01..10", "FR-0.03-01..11", "FR-0.04-01..10", "FR-0.05-01..10", "FR-0.1-01..08"}
    if set(coverage.get("fr_groups", {})) != required_fr_groups:
        failures.append("s10_fr_coverage_matrix_incomplete")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["private_helper_only_e2e", "gateway_bypass", "synthetic_required_evidence", "telemetry_authorizes_action_or_placement", "cloud_helper_direct_authority", "raw_physical_action_accepted", "replay_side_effects_allowed_default"]:
        if anti.get(key) is not False:
            failures.append(f"s10_anti_drift_expected_false:{key}")
    if anti.get("coverage_matrix_present") is not True:
        failures.append("s10_anti_drift_coverage_matrix_missing")
    if sorted(anti.get("derived_from_required_event_evidence", [])) != sorted(S10_REQUIRED_EVENTS):
        failures.append("s10_anti_drift_not_derived_from_event_evidence")
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
    if args.mode == "all" or args.scenario == "UC-E2E-S10":
        blocked_contract_groups = [
            group
            for group in contract.get("blocked_not_yet_covered", [])
            if group.get("status") == "blocked_not_yet_covered"
        ]
        for group in blocked_contract_groups:
            missing = ",".join(group.get("missing_operation_ids", []) or group.get("missing_fields", []))
            blocking.append(f"contract_required_group_blocked:{group.get('group')}:{missing}")
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
    source_tree = source_tree_identity(root)
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
    s8_scenario, s8_failures = load_s8_scenario(report_dir)
    s9_scenario, s9_failures = load_s9_scenario(report_dir)
    s10_scenario, s10_failures = load_s10_scenario(report_dir)
    active_ids: set[str] = set()
    if args.scenario in {"UC-E2E-S1", "UC-E2E-S8", "UC-E2E-S9", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S1")
        if s1_scenario is None:
            blocking.append("missing_uc_e2e_s1_scenario_report")
        else:
            scenarios.append(s1_scenario)
            blocking.extend(s1_failures)
    if args.scenario in {"UC-E2E-S2", "UC-E2E-S8", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S2")
        if s2_scenario is None:
            blocking.append("missing_uc_e2e_s2_scenario_report")
        else:
            scenarios.append(s2_scenario)
            blocking.extend(s2_failures)
    if args.scenario in {"UC-E2E-S3", "UC-E2E-S8", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S3")
        if s3_scenario is None:
            blocking.append("missing_uc_e2e_s3_scenario_report")
        else:
            scenarios.append(s3_scenario)
            blocking.extend(s3_failures)
    if args.scenario in {"UC-E2E-S4", "UC-E2E-S8", "UC-E2E-S9", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S4")
        if s4_scenario is None:
            blocking.append("missing_uc_e2e_s4_scenario_report")
        else:
            scenarios.append(s4_scenario)
            blocking.extend(s4_failures)
    if args.scenario in {"UC-E2E-S5", "UC-E2E-S8", "UC-E2E-S9", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S5")
        if s5_scenario is None:
            blocking.append("missing_uc_e2e_s5_scenario_report")
        else:
            scenarios.append(s5_scenario)
            blocking.extend(s5_failures)
    if args.scenario in {"UC-E2E-S6", "UC-E2E-S8", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S6")
        if s6_scenario is None:
            blocking.append("missing_uc_e2e_s6_scenario_report")
        else:
            scenarios.append(s6_scenario)
            blocking.extend(s6_failures)
    if args.scenario in {"UC-E2E-S7", "UC-E2E-S8", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S7")
        if s7_scenario is None:
            blocking.append("missing_uc_e2e_s7_scenario_report")
        else:
            scenarios.append(s7_scenario)
            blocking.extend(s7_failures)
    if args.scenario in {"UC-E2E-S8", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S8")
        if s8_scenario is None:
            blocking.append("missing_uc_e2e_s8_scenario_report")
        else:
            scenarios.append(s8_scenario)
            blocking.extend(s8_failures)
    if args.scenario in {"UC-E2E-S9", "UC-E2E-S10"} or args.mode == "all":
        active_ids.add("UC-E2E-S9")
        if s9_scenario is None:
            blocking.append("missing_uc_e2e_s9_scenario_report")
        else:
            scenarios.append(s9_scenario)
            blocking.extend(s9_failures)
    if args.scenario == "UC-E2E-S10" or args.mode == "all":
        active_ids.add("UC-E2E-S10")
        if s10_scenario is None:
            blocking.append("missing_uc_e2e_s10_scenario_report")
        else:
            scenarios.append(s10_scenario)
            blocking.extend(s10_failures)
    blocked_ids = [sid for sid in FUTURE_SCENARIOS if sid not in active_ids]

    report = {
        "suite_id": "splendor-use-case-e2e-through-0.1",
        "suite_version": "0.1-s10-final-journey",
        "source_revision": git_revision(root),
        "source_tree": source_tree,
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
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10",
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
            "UC-E2E-S8 validates replay/audit/schema compatibility by importing prior scenario artifacts and rejects tampered, unsupported, unsafe, or reason-less evidence.",
            "UC-E2E-S9 validates deterministic failure injection, quota pressure, bounded retry, idempotency markers, and fail-closed races through public daemon/manager APIs plus S1/S4/S5 source artifacts.",
            "UC-E2E-S10 validates the final cross-component field-intelligence journey through public manager, daemon, governance, message, state, trace, device, replay, and CLI signing boundaries.",
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
