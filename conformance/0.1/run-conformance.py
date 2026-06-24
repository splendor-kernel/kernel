#!/usr/bin/env python3
"""Splendor 0.1 primitive conformance runner.

The suite is intentionally fixture-driven. It validates stable primitive contract
evidence and adapter manifests without external services, production secrets, or
runtime feature shims.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "conformance" / "0.1" / "fixtures" / "conformance-cases.json"
ADAPTER_VALIDATOR = ROOT / "scripts" / "validate-adapter-manifests.py"
STABLE_EXAMPLES_PATH = ROOT / "docs" / "spec" / "0.1" / "stable-primitive-examples.json"
SECURITY_INVARIANTS_PATH = ROOT / "docs" / "rules" / "v2" / "security" / "security-invariants.json"
PERFORMANCE_BUDGETS_PATH = ROOT / "docs" / "spec" / "0.2" / "performance-budgets.json"
FOUNDATION_READINESS_PATH = ROOT / "docs" / "rules" / "v2" / "foundation-readiness.json"
ACTION_OUTCOMES = {
    "action.executed",
    "action.denied",
    "action.failed",
    "action.needs_approval",
    "action.needs_intervention",
}
REQUIRED_TICK_ORDER = [
    "tick.started",
    "percepts.received",
    "state.loaded",
    "policy.invoked",
    "policy.completed",
    "actions.proposed",
    "constraints.evaluated",
    "verification.started",
    "verification.completed",
    "ACTION_OUTCOME",
    "outcome.recorded",
    "state.committed",
    "tick.completed",
]
SECRET_KEYS = {
    "accesstoken",
    "apikey",
    "apitoken",
    "authorization",
    "bearertoken",
    "clientsecret",
    "credential",
    "password",
    "privatekey",
    "secret",
    "token",
}
AUTHORIZING_EXTENSION_KEY_FRAGMENTS = {
    "accesstoken",
    "adapter",
    "apikey",
    "approval",
    "authorized",
    "authheader",
    "authority",
    "authorization",
    "bearer",
    "capabilities",
    "capability",
    "credential",
    "datause",
    "driver",
    "execute",
    "executed",
    "gateway",
    "identity",
    "jwt",
    "oauth",
    "password",
    "permission",
    "policy",
    "principal",
    "privilege",
    "privatekey",
    "quota",
    "role",
    "runstart",
    "secret",
    "sideeffect",
    "signature",
    "token",
    "traceid",
    "verifier",
    "workorder",
}
REQUIRED_SECURITY_GOLD_IDS = {"G80", "G81", "G82", "G83", "G84", "G85", "G86", "G87", "G88", "G89"}
REQUIRED_SECURITY_PLANES = {
    "identity_authority",
    "artifact_lineage",
    "event_state_evidence",
    "execution_fabric",
    "driver_boundary",
    "agent_runtime_routing",
    "data_feedback_eval_learning_control",
    "change_governance",
}
REQUIRED_SECURITY_NON_CLAIMS = {"no_fnd_011_completion", "no_g80_g89_pass", "no_gold_harness_pass"}
PROMPT_ONLY_SECURITY_PHRASES = {
    "prompt instruction",
    "system prompt",
    "llm instruction",
    "model instruction",
    "assistant instruction",
    "developer instruction",
    "instruction prompt",
}
ALLOWED_SECURITY_SIGNATURE_ALGORITHMS = {"ed25519", "ecdsa_p256_sha256"}
DRIVER_SCHEMA_CONFUSION_SCHEMA_VERSION = "splendor.driver_schema_confusion_fixture.v1"
DRIVER_SCHEMA_CONFUSION_EVIDENCE_SCOPE = "partial_fnd_011_g86_driver_schema_confusion_v0"
DRIVER_SCHEMA_CONFUSION_NON_CLAIMS = {
    "no_g86_gold_pass",
    "no_g80_g89_pass",
    "no_full_driver_conformance",
    "no_driver_registry_implementation",
    "no_live_adapter_execution",
}
DRIVER_SCHEMA_MISMATCH_REASONS = {
    "driver_schema_mismatch",
    "driver_schema_version_mismatch",
    "driver_operation_schema_mismatch",
}
DRIVER_SCHEMA_EVENT_ORDER = [
    "driver.schema.checked",
    "verification.started",
    "driver.schema.rejected",
    "verification.completed",
    "action.denied",
    "outcome.recorded",
]
DRIVER_SCHEMA_REQUIRED_EVENTS = set(DRIVER_SCHEMA_EVENT_ORDER)
DRIVER_SCHEMA_FORBIDDEN_EVENTS = {
    "action.executed",
    "adapter.executed",
    "adapter.invoked",
    "driver.executed",
    "driver.invoked",
}
DRIVER_SCHEMA_FORBIDDEN_EVENT_PREFIXES = (
    "artifact.",
    "db.",
    "email.",
    "filesystem.",
    "network.",
    "shell.",
    "webhook.",
)
DRIVER_SCHEMA_TOP_LEVEL_KEYS = {
    "action_id",
    "description",
    "driver_id",
    "events",
    "evidence_scope",
    "gateway",
    "gold_id",
    "non_claims",
    "operation",
    "outcome",
    "run_id",
    "schema_mismatch",
    "schema_version",
    "side_effects",
    "task_id",
    "verification",
}
DRIVER_SCHEMA_MISMATCH_KEYS = {"detected_before_execution", "expected", "reason", "requested"}
DRIVER_SCHEMA_ENDPOINT_KEYS = {"schema", "version"}
DRIVER_SCHEMA_VERIFICATION_KEYS = {"allowed", "reasons", "verifier_results"}
DRIVER_SCHEMA_VERIFIER_RESULT_KEYS = {"allowed", "evidence", "reason", "verifier"}
DRIVER_SCHEMA_VERIFIER_EVIDENCE_KEYS = {"driver_manifest_ref", "expected_schema", "operation", "requested_schema"}
DRIVER_SCHEMA_GATEWAY_KEYS = {
    "adapter_executed",
    "adapter_invocation_count",
    "driver_invocation_count",
    "effect_certainty",
    "status",
}
DRIVER_SCHEMA_OUTCOME_KEYS = {"reason", "side_effect_occurred", "status"}
DRIVER_SCHEMA_SIDE_EFFECT_COUNTERS = {
    "artifacts_published",
    "external_mutations",
    "filesystem_writes",
    "network_calls",
}
DRIVER_SCHEMA_EVENT_KEYS = {"evidence_ref", "identity", "kind", "trace_event_id"}
DRIVER_SCHEMA_EVENT_IDENTITY_KEYS = {"action_id", "driver_id", "run_id"}
PROMPT_DATA_INJECTION_SCHEMA_VERSION = "splendor.prompt_data_injection_fixture.v1"
PROMPT_DATA_INJECTION_EVIDENCE_SCOPE = "partial_fnd_011_g80_prompt_data_injection_denial_v0"
PROMPT_DATA_INJECTION_NON_CLAIMS = {
    "no_g80_gold_pass",
    "no_g80_g89_pass",
    "no_fnd_011_completion",
    "no_route_taint_runtime",
    "no_live_adapter_execution",
}
PROMPT_DATA_INJECTION_AUTHORITY_FIELDS = {
    "allowed_actions",
    "allowed_adapters",
    "allowed_permissions",
    "approval",
    "verification",
    "gateway_bypass",
}
PROMPT_DATA_INJECTION_DENIAL_REASONS = {
    "action_not_allowed",
    "adapter_not_allowed",
    "permission_missing",
    "prompt_data_not_authority",
}
PROMPT_DATA_INJECTION_EVENT_ORDER = [
    "percepts.received",
    "route.input.tainted",
    "actions.proposed",
    "verification.started",
    "authorization.denied",
    "verification.completed",
    "action.denied",
    "outcome.recorded",
]
PROMPT_DATA_INJECTION_REQUIRED_EVENTS = set(PROMPT_DATA_INJECTION_EVENT_ORDER)
PROMPT_DATA_INJECTION_FORBIDDEN_EVENTS = {
    "action.executed",
    "adapter.executed",
    "adapter.invoked",
    "driver.executed",
    "driver.invoked",
    "gateway.executed",
}
PROMPT_DATA_INJECTION_FORBIDDEN_EVENT_PREFIXES = (
    "artifact.",
    "db.",
    "email.",
    "filesystem.",
    "network.",
    "shell.",
    "webhook.",
)
PROMPT_DATA_INJECTION_TOP_LEVEL_KEYS = {
    "action_id",
    "adapter_id",
    "agent_id",
    "description",
    "events",
    "evidence_scope",
    "gateway",
    "gold_id",
    "malicious_percept",
    "non_claims",
    "outcome",
    "policy_proposal",
    "run_id",
    "schema_version",
    "side_effects",
    "task_id",
    "tenant_id",
    "tick_id",
    "verification",
}
PROMPT_DATA_INJECTION_PERCEPT_KEYS = {"payload", "provenance", "schema", "tainted_fields"}
PROMPT_DATA_INJECTION_PROVENANCE_KEYS = {"source", "trust_boundary"}
PROMPT_DATA_INJECTION_REQUESTED_ACTION_KEYS = {
    "adapter",
    "name",
    "params",
    "required_permissions",
    "side_effect_class",
}
PROMPT_DATA_INJECTION_POLICY_KEYS = {
    "naive_policy",
    "proposed_action",
    "used_payload_requested_action",
}
PROMPT_DATA_INJECTION_VERIFICATION_KEYS = {"allowed", "reasons", "verifier_results"}
PROMPT_DATA_INJECTION_VERIFIER_RESULT_KEYS = {"allowed", "evidence", "reason", "verifier"}
PROMPT_DATA_INJECTION_VERIFIER_EVIDENCE_KEYS = {
    "allowed_actions",
    "allowed_adapters",
    "allowed_permissions",
    "requested_action",
    "requested_adapter",
    "requested_permissions",
}
PROMPT_DATA_INJECTION_GATEWAY_KEYS = {
    "adapter_executed",
    "adapter_invocation_count",
    "effect_certainty",
    "execution_attempted",
    "gateway_bypassed",
    "status",
    "verification_ran",
}
PROMPT_DATA_INJECTION_OUTCOME_KEYS = {"reason", "side_effect_occurred", "status"}
PROMPT_DATA_INJECTION_EVENT_KEYS = {"evidence_ref", "identity", "kind", "trace_event_id"}
PROMPT_DATA_INJECTION_EVENT_IDENTITY_KEYS = {
    "action_id",
    "agent_id",
    "percept_ref",
    "run_id",
    "tenant_id",
    "tick_id",
}
PERFORMANCE_BUDGET_SCHEMA_VERSION = "splendor.performance_budgets.v1"
PERFORMANCE_BUDGET_EVIDENCE_SCOPE = "partial_fnd_012_budget_contract_v0"
REQUIRED_PERFORMANCE_NON_CLAIMS = {
    "no_fnd_012_completion",
    "no_issue_231_completion",
    "no_issue_180_completion",
    "no_g29_pass",
    "no_g66_pass",
    "no_g68_pass",
    "no_g74_pass",
    "no_benchmark_execution",
}
REQUIRED_LATENCY_BUDGET_METRICS = {
    "local_event_append",
    "state_commit",
    "authority_decision",
    "gateway_preflight",
    "model_invocation_overhead",
    "percept_routing",
    "tick_admission",
}
REQUIRED_THROUGHPUT_BUDGET_METRICS = {
    "event_ingestion",
    "artifact_transfer",
    "scheduler_offers",
    "workload_transitions",
    "feedback_ingestion",
    "eval_fan_out",
    "one_thousand_node_simulation",
}
REQUIRED_PERFORMANCE_GOLD_IDS = {"G29", "G66", "G68", "G74"}
FOUNDATION_READINESS_SCHEMA_VERSION = "splendor.v2_foundation_readiness.v1"
FOUNDATION_READINESS_STATUS = "foundation_ready_for_c01"
REQUIRED_FOUNDATION_TASKS = {f"FND-{index:03d}" for index in range(1, 13)}
REQUIRED_FOUNDATION_NON_CLAIMS = {
    "no_fnd_full_validation",
    "no_fnd_001_012_completion_claim",
    "no_gold_pass_claim",
    "no_c01_implementation",
    "no_principal_registry_service",
}
FOUNDATION_READINESS_TOP_LEVEL_KEYS = {
    "aggregate_issue",
    "c01_readiness",
    "checkpoint_id",
    "exit_gate_coverage",
    "foundations",
    "non_claims",
    "schema_version",
    "status",
    "sprint",
}
FOUNDATION_RECORD_KEYS = {
    "evidence_paths",
    "foundation_status",
    "gold_ids",
    "gold_status",
    "issue",
    "non_claims",
    "remaining_validation",
    "task_id",
}
FOUNDATION_REQUIRED_EXIT_GATES = {
    "schema_compatibility",
    "non_authorizing_extensions",
    "failure_taxonomy",
    "conformance_harness_scope",
    "migration_fixture_family",
    "security_invariants",
    "performance_budgets",
}
FOUNDATION_EXIT_GATE_KEYS = {"evidence_paths", "status"}
FOUNDATION_C01_KEYS = {
    "allowed_next_work",
    "component_id",
    "component_label",
    "full_implementation_blocked_until_rfc_accepted",
    "non_claims",
    "readiness_scope",
    "required_fnd_dependencies",
    "required_rfc_refs",
}
REQUIRED_C01_TASKS = {f"IDR-{index:03d}" for index in range(1, 7)}
REQUIRED_C01_FND_DEPENDENCIES = {"FND-001", "FND-003", "FND-006", "FND-011"}


@dataclass
class Result:
    case_id: str
    primitive: str
    requirement: str
    path: str
    status: str
    message: str


class ConformanceError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ConformanceError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def require_exact_keys(value: dict[str, Any], expected_keys: set[str], label: str) -> None:
    actual_keys = set(value)
    missing = sorted(expected_keys - actual_keys)
    extras = sorted(actual_keys - expected_keys)
    assert_true(not missing, f"{label} missing keys: {', '.join(missing)}")
    assert_true(not extras, f"{label} unknown keys: {', '.join(extras)}")


def event_kind_matches(actual: str, expected: str) -> bool:
    if expected == "ACTION_OUTCOME":
        return actual in ACTION_OUTCOMES
    return actual == expected


def normalize_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def is_authorizing_extension_key(key: str, reserved_keys: list[str]) -> bool:
    normalized = normalize_key(key)
    normalized_reserved = {normalize_key(reserved_key) for reserved_key in reserved_keys}
    return (
        normalized in normalized_reserved
        or normalized in SECRET_KEYS
        or any(fragment in normalized for fragment in AUTHORIZING_EXTENSION_KEY_FRAGMENTS)
    )


def collect_authorizing_extension_paths(value: Any, reserved_keys: list[str], path: str) -> list[str]:
    illegal: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if not isinstance(key, str) or not key.strip() or key.strip() != key:
                illegal.append(child_path)
                continue
            if is_authorizing_extension_key(key, reserved_keys):
                illegal.append(child_path)
            illegal.extend(collect_authorizing_extension_paths(nested, reserved_keys, child_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            illegal.extend(collect_authorizing_extension_paths(nested, reserved_keys, f"{path}[{index}]"))
    return illegal


def validate_trace(trace: dict[str, Any]) -> None:
    events = trace.get("events")
    assert_true(isinstance(events, list) and events, "trace.events must be a non-empty array")
    sequences = [event.get("sequence") for event in events]
    assert_true(sequences == list(range(sequences[0], sequences[0] + len(sequences))), "trace sequences must be contiguous")

    trace_ids: set[str] = set()
    for event in events:
        assert_true(isinstance(event, dict), "trace event must be an object")
        trace_event_id = event.get("trace_event_id")
        assert_true(isinstance(trace_event_id, str) and trace_event_id, "trace_event_id is required")
        assert_true(trace_event_id not in trace_ids, f"duplicate trace_event_id {trace_event_id}")
        trace_ids.add(trace_event_id)
        assert_true("trace_id" not in event, "trace_id alias must not be emitted by 0.1 fixtures")
        identity = event.get("identity")
        assert_true(isinstance(identity, dict), "trace identity is required")
        assert_true(identity.get("run_id") == trace.get("run_id"), "trace identity.run_id must match trace run_id")
        if "tenant_id" in identity:
            assert_true(identity["tenant_id"] == trace.get("tenant_id"), "trace identity.tenant_id mismatch")
        if "agent_id" in identity:
            assert_true(identity["agent_id"] == trace.get("agent_id"), "trace identity.agent_id mismatch")

    ordered_kinds = [event["kind"] for event in events]
    verification_completed_index = next((index for index, kind in enumerate(ordered_kinds) if kind == "verification.completed"), None)
    first_outcome_index = next((index for index, kind in enumerate(ordered_kinds) if kind in ACTION_OUTCOMES), None)
    if first_outcome_index is not None:
        assert_true(verification_completed_index is not None, "action outcome occurred before verification.completed")
        assert_true(first_outcome_index > verification_completed_index, "action outcome occurred before verification.completed")

    cursor = 0
    for required in REQUIRED_TICK_ORDER:
        while cursor < len(ordered_kinds) and not event_kind_matches(ordered_kinds[cursor], required):
            cursor += 1
        if cursor >= len(ordered_kinds):
            raise ConformanceError(f"missing required ordered event {required.lower().replace('_', ' ')} before action outcome" if required == "ACTION_OUTCOME" else f"missing required ordered event {required}")
        cursor += 1


def validate_gateway(gateway: dict[str, Any]) -> None:
    status = gateway.get("status")
    assert_true(status in {"executed", "denied", "failed", "needs_approval", "needs_intervention"}, "gateway status is invalid")
    verification = gateway.get("verification")
    assert_true(isinstance(verification, dict), "gateway verification result is required")
    assert_true(isinstance(verification.get("allowed"), bool), "verification.allowed must be boolean")
    required_events = gateway.get("required_events")
    assert_true(isinstance(required_events, list) and "verification.started" in required_events and "verification.completed" in required_events, "gateway must require verification trace events")
    if status in {"denied", "needs_approval", "needs_intervention"}:
        assert_true(gateway.get("adapter_executed") is False, "pre-execution denial/intervention must not execute adapter")
        assert_true(verification.get("allowed") is False, "denial/intervention verification must fail closed")
    if status == "executed":
        assert_true(gateway.get("adapter_executed") is True, "executed gateway case must prove adapter execution")
        assert_true(verification.get("allowed") is True, "executed gateway case requires successful verification")
        assert_true("action.executed" in required_events, "executed gateway case must require action.executed trace event")
    if status == "failed":
        assert_true(gateway.get("adapter_executed") is True, "adapter failure case must prove adapter execution happened after allow")
        assert_true(verification.get("allowed") is True, "adapter failure requires successful pre-verification")
        assert_true(isinstance(gateway.get("error"), str) and gateway["error"], "adapter failure must include error")


def validate_state(case: dict[str, Any]) -> None:
    state = case.get("state")
    if state is not None:
        required = {"state_node_id", "tenant_id", "agent_id", "run_id", "parents", "state_hash", "trace_event_id", "created_at"}
        missing = sorted(required - set(state))
        assert_true(not missing, f"state commit missing fields: {', '.join(missing)}")
        assert_true(isinstance(state.get("parents"), list), "state parents must be an array")
        trace_event = case.get("trace_event")
        assert_true(isinstance(trace_event, dict), "state trace_event fixture is required")
        assert_true(trace_event.get("trace_event_id") == state.get("trace_event_id"), "state trace_event_id linkage mismatch")
        identity = trace_event.get("identity", {})
        assert_true(identity.get("state_node_id") == state.get("state_node_id"), "state trace identity state_node_id mismatch")
        assert_true(identity.get("tenant_id") == state.get("tenant_id"), "state trace identity tenant_id mismatch")
        assert_true(identity.get("agent_id") == state.get("agent_id"), "state trace identity agent_id mismatch")
    failure = case.get("state_failure")
    if failure is not None:
        assert_true(failure.get("state_committed") is False, "failed state commit must not be marked committed")
        assert_true(failure.get("tick_completed") is False, "state commit failure must prevent tick completion")
        assert_true(failure.get("next_tick_started") is False, "state commit failure must prevent next tick")


def validate_replay(replay: dict[str, Any]) -> None:
    assert_true(replay.get("mode") == "inspect_only", "replay default mode must be inspect_only")
    assert_true(replay.get("side_effects_replayed") is False, "replay must not replay side effects")
    assert_true(replay.get("invoked_components") == [], "replay must not invoke policies, gateways, verifiers, or adapters")


def validate_message(case: dict[str, Any]) -> None:
    message = case["message"]
    required = {"message_id", "source_agent_id", "target_agent_id", "run_id", "schema", "payload", "requires_response", "created_at"}
    missing = sorted(required - set(message))
    assert_true(not missing, f"message missing fields: {', '.join(missing)}")
    assert_true(message["source_agent_id"] != message["target_agent_id"], "message source and target agents must be distinct")
    trace_events = case.get("trace_events")
    assert_true(isinstance(trace_events, list) and trace_events, "message trace_events are required")
    trace_ids = {event.get("trace_event_id") for event in trace_events}
    assert_true(message.get("causal_parent") in trace_ids, "message causal_parent must reference a trace event")
    lifecycle = [event.get("kind") for event in trace_events if event.get("identity", {}).get("message_id") == message["message_id"]]
    assert_true("message.queued" in lifecycle and "message.delivered" in lifecycle, "message lifecycle must include queued and delivered events")
    for event in trace_events:
        identity = event.get("identity", {})
        assert_true(identity.get("run_id") == message["run_id"], "message trace run_id mismatch")


def validate_work_order(work_order: dict[str, Any]) -> None:
    status = work_order.get("status")
    assert_true(status in {"accepted", "rejected"}, "work order status must be accepted or rejected")
    if status == "accepted":
        assert_true(isinstance(work_order.get("signature"), dict), "accepted work order requires signature metadata")
        assert_true(work_order.get("revocation") == "active", "accepted work order must be active")
        tenant_actions = set(work_order.get("tenant_allowed_actions", []))
        allowed_actions = set(work_order.get("allowed_actions", []))
        assert_true(allowed_actions <= tenant_actions, "accepted work order must not broaden tenant action authority")
        assert_true(work_order.get("run_started") is True, "accepted work order should start run in positive fixture")
    else:
        assert_true(work_order.get("run_started") is False, "rejected work order must not start run")
        reason = work_order.get("reason")
        assert_true(reason in {"unsigned_work_order", "expired_work_order", "revoked_work_order", "overbroad_authority", "bad_signature", "incompatible_work_order"}, f"unexpected rejection reason {reason!r}")
        if reason == "unsigned_work_order":
            assert_true(not work_order.get("signature"), "unsigned rejection fixture must not carry signature")
        if reason == "overbroad_authority":
            tenant_actions = set(work_order.get("tenant_allowed_actions", []))
            allowed_actions = set(work_order.get("allowed_actions", []))
            assert_true(not allowed_actions <= tenant_actions, "overbroad fixture must broaden tenant authority")


def validate_governance(governance: dict[str, Any]) -> None:
    assert_true(governance.get("adapter_executed") is False, "governance denial/intervention must skip adapter execution")
    required_events = governance.get("required_events")
    assert_true(isinstance(required_events, list) and required_events, "governance required_events must be present")
    transition = governance.get("transition")
    if transition == "approval_requested":
        assert_true(governance.get("action_status") == "needs_approval", "approval request must produce needs_approval")
        assert_true(governance.get("run_status") == "waiting_for_approval", "approval request must pause run")
    elif transition == "approval_denied":
        assert_true(governance.get("action_status") == "denied", "approval denial must deny action")
    elif transition == "escalation_opened":
        assert_true(governance.get("action_status") == "needs_intervention", "escalation must require intervention")
    elif transition == "circuit_breaker_tripped":
        assert_true(governance.get("reason") == "circuit_breaker_tripped", "circuit breaker denial reason is required")
    else:
        raise ConformanceError(f"unknown governance transition {transition!r}")


def contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if normalize_key(key) in SECRET_KEYS:
                return True
            if contains_secret_key(nested):
                return True
    if isinstance(value, list):
        return any(contains_secret_key(item) for item in value)
    return False


def load_adapter_validator():
    spec = importlib.util.spec_from_file_location("validate_adapter_manifests", ADAPTER_VALIDATOR)
    if spec is None or spec.loader is None:
        raise ConformanceError("could not load adapter manifest validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_adapter_manifests(config: dict[str, Any]) -> None:
    module = load_adapter_validator()
    manifest_dir = ROOT / config.get("directory", "docs/spec/0.1/fixtures/adapter-manifests")
    manifests = sorted(manifest_dir.glob("*.json"))
    assert_true(bool(manifests), f"no adapter manifests found under {manifest_dir.relative_to(ROOT)}")
    for manifest in manifests:
        module.validate_manifest(manifest)
        data = load_json(manifest)
        if config.get("require_replay_side_effects_false"):
            assert_true(data.get("replay_behavior", {}).get("side_effects_replayed") is False, f"{manifest.relative_to(ROOT)} must suppress replay side effects")
        if config.get("forbid_secret_fields"):
            assert_true(not contains_secret_key(data), f"{manifest.relative_to(ROOT)} contains secret-shaped fixture keys")
        if config.get("require_gateway_evidence"):
            text = json.dumps(data).lower()
            assert_true("gateway" in text, f"{manifest.relative_to(ROOT)} must document gateway mediation")


def load_stable_examples_manifest(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    path = ROOT / config.get("path", STABLE_EXAMPLES_PATH.relative_to(ROOT))
    data = load_json(path)
    assert_true(data.get("schema_version") == "splendor.stable_primitives_manifest.v1", "stable examples schema_version mismatch")
    assert_true(data.get("milestone") == "Splendor0.1-dev", "stable examples milestone mismatch")
    extension_policy = data.get("extension_policy")
    assert_true(isinstance(extension_policy, dict), "stable examples extension_policy is required")
    assert_true(extension_policy.get("authority") == "non_authorizing", "stable examples extensions must be non_authorizing")
    reserved_keys = extension_policy.get("reserved_keys")
    assert_true(isinstance(reserved_keys, list) and reserved_keys, "stable examples reserved_keys must be present")

    primitives = data.get("primitives")
    assert_true(isinstance(primitives, list) and primitives, "stable examples primitives must be non-empty")
    by_name: dict[str, dict[str, Any]] = {}
    for primitive in primitives:
        assert_true(isinstance(primitive, dict), "stable primitive entry must be an object")
        name = primitive.get("name")
        assert_true(isinstance(name, str) and name, "stable primitive name is required")
        assert_true(name not in by_name, f"duplicate stable primitive {name}")
        by_name[name] = primitive
        required_fields = primitive.get("required_fields")
        example = primitive.get("example")
        assert_true(isinstance(required_fields, list), f"{name} required_fields must be an array")
        assert_true(isinstance(example, dict), f"{name} example must be an object")
        missing = [field for field in required_fields if field not in example]
        assert_true(not missing, f"{name} example missing required fields: {', '.join(missing)}")
        extensions = example.get("extensions")
        if isinstance(extensions, dict):
            illegal = sorted(collect_authorizing_extension_paths(extensions, reserved_keys, "extensions"))
            assert_true(not illegal, f"{name} extensions contain reserved authority keys: {', '.join(illegal)}")
    return data, by_name


def validate_required_stable_primitives(primitives: dict[str, dict[str, Any]], required_primitives: set[str]) -> None:
    missing_primitives = sorted(required_primitives - set(primitives))
    assert_true(not missing_primitives, f"stable examples missing primitives: {', '.join(missing_primitives)}")


def validate_stable_examples(config: dict[str, Any]) -> None:
    _, primitives = load_stable_examples_manifest(config)
    validate_required_stable_primitives(primitives, set(config.get("required_primitives", [])))


def validate_compatibility_non_claims(config: dict[str, Any]) -> None:
    assert_true(config.get("evidence_scope") == "partial_fnd_006_fixture_matrix_v0", "compatibility evidence_scope must be partial_fnd_006_fixture_matrix_v0")
    non_claims = set(config.get("non_claims", []))
    required_non_claims = {"no_fnd_006_completion", "no_g00_pass", "no_g72_pass"}
    missing = sorted(required_non_claims - non_claims)
    assert_true(not missing, f"compatibility non_claims missing: {', '.join(missing)}")


def validate_compatibility_stable_examples(config: dict[str, Any]) -> None:
    stable_config = config.get("stable_examples", {})
    assert_true(isinstance(stable_config, dict), "compatibility stable_examples must be an object")
    _, primitives = load_stable_examples_manifest(stable_config)
    validate_required_stable_primitives(primitives, set(stable_config.get("required_primitives", [])))
    expected_count = stable_config.get("expected_count")
    if expected_count is not None:
        assert_true(len(primitives) == expected_count, f"expected {expected_count} stable primitives, found {len(primitives)}")


def validate_non_authorizing_extension_variants(config: dict[str, Any]) -> None:
    stable_config = config.get("stable_examples", {})
    assert_true(isinstance(stable_config, dict), "compatibility stable_examples must be an object")
    data, primitives = load_stable_examples_manifest(stable_config)
    reserved_keys = data["extension_policy"]["reserved_keys"]
    variants = config.get("variants")
    assert_true(isinstance(variants, list) and variants, "compatibility variants must be a non-empty array")
    for variant in variants:
        assert_true(isinstance(variant, dict), "compatibility variant must be an object")
        primitive_name = variant.get("primitive")
        primitive = primitives.get(primitive_name)
        assert_true(primitive is not None, f"compatibility variant references unknown primitive {primitive_name!r}")
        assert_true(primitive.get("extensions") == "non_authorizing", f"{primitive_name} does not allow non-authorizing extensions")
        assert_true("extensions" in primitive.get("optional_fields", []), f"{primitive_name} optional_fields must include extensions")
        assert_true(variant.get("expected") == "accepted", f"{primitive_name} non-authorizing extension variant must expect accepted")
        assert_true(variant.get("authority_effect") == "none", f"{primitive_name} extension variant must declare no authority effect")
        extensions = variant.get("extensions")
        assert_true(isinstance(extensions, dict) and extensions, f"{primitive_name} compatibility extensions must be a non-empty object")
        illegal = sorted(collect_authorizing_extension_paths(extensions, reserved_keys, "extensions"))
        assert_true(not illegal, f"{primitive_name} accepted compatibility extensions contain authorizing keys: {', '.join(illegal)}")


def validate_authorizing_extension_rejections(config: dict[str, Any]) -> None:
    stable_config = config.get("stable_examples", {})
    assert_true(isinstance(stable_config, dict), "compatibility stable_examples must be an object")
    data, primitives = load_stable_examples_manifest(stable_config)
    reserved_keys = data["extension_policy"]["reserved_keys"]
    variants = config.get("variants")
    assert_true(isinstance(variants, list) and variants, "compatibility variants must be a non-empty array")
    for variant in variants:
        assert_true(isinstance(variant, dict), "compatibility variant must be an object")
        primitive_name = variant.get("primitive")
        primitive = primitives.get(primitive_name)
        assert_true(primitive is not None, f"compatibility variant references unknown primitive {primitive_name!r}")
        assert_true(primitive.get("extensions") == "non_authorizing", f"{primitive_name} rejection variant must target an extension-capable primitive")
        assert_true(variant.get("expected") == "rejected", f"{primitive_name} authorizing extension variant must expect rejected")
        assert_true(variant.get("failure_mode") == "fail_closed", f"{primitive_name} authorizing extension variant must fail closed")
        extensions = variant.get("extensions")
        assert_true(isinstance(extensions, dict) and extensions, f"{primitive_name} rejected extensions must be a non-empty object")
        illegal = sorted(collect_authorizing_extension_paths(extensions, reserved_keys, "extensions"))
        assert_true(illegal, f"{primitive_name} rejected compatibility fixture must include authorizing extension keys")
        fail_closed = variant.get("fail_closed")
        assert_true(isinstance(fail_closed, dict) and fail_closed, f"{primitive_name} fail_closed evidence must be present")
        for field, value in fail_closed.items():
            assert_true(value is False, f"{primitive_name} fail_closed.{field} must be false")


def validate_trace_alias_variants(config: dict[str, Any]) -> None:
    stable_config = config.get("stable_examples", {})
    assert_true(isinstance(stable_config, dict), "compatibility stable_examples must be an object")
    data, primitives = load_stable_examples_manifest(stable_config)
    assert_true("TraceEvent" in primitives, "TraceEvent stable example is required for alias compatibility")
    aliases = data.get("deprecated_aliases")
    assert_true(isinstance(aliases, list), "stable examples deprecated_aliases must be an array")
    replacements = {alias.get("alias"): alias.get("replacement") for alias in aliases if isinstance(alias, dict)}
    variants = config.get("variants")
    assert_true(isinstance(variants, list) and variants, "trace alias variants must be a non-empty array")
    for variant in variants:
        assert_true(isinstance(variant, dict), "trace alias variant must be an object")
        assert_true(variant.get("primitive") == "TraceEvent", "trace alias compatibility only applies to TraceEvent")
        alias = variant.get("alias")
        replacement = variant.get("replacement")
        assert_true(replacements.get(alias) == replacement, f"deprecated alias {alias!r} must map to {replacement!r}")
        input_event = variant.get("input")
        emitted_event = variant.get("emitted")
        assert_true(isinstance(input_event, dict), "trace alias input must be an object")
        assert_true(isinstance(emitted_event, dict), "trace alias emitted fixture must be an object")
        assert_true(alias in input_event, f"trace alias input must include {alias}")
        assert_true(replacement not in input_event, f"trace alias input fixture should exercise alias-only {alias}")
        assert_true(replacement in emitted_event, f"trace alias emitted fixture must include {replacement}")
        assert_true(alias not in emitted_event, f"trace alias emitted fixture must not include deprecated {alias}")
        assert_true(input_event[alias] == emitted_event[replacement], "trace alias value must canonicalize to trace_event_id")
        for field in ("run_id", "sequence", "timestamp", "identity", "kind"):
            assert_true(input_event.get(field) == emitted_event.get(field), f"trace alias canonicalization changed {field}")
        assert_true(variant.get("authority_effect") == "none", "trace alias compatibility must not grant authority")


def validate_compatibility(config: dict[str, Any]) -> None:
    validate_compatibility_non_claims(config)
    matrix = config.get("matrix")
    if matrix == "stable_examples_accepted":
        validate_compatibility_stable_examples(config)
    elif matrix == "non_authorizing_extensions_accepted":
        validate_non_authorizing_extension_variants(config)
    elif matrix == "authorizing_extensions_rejected":
        validate_authorizing_extension_rejections(config)
    elif matrix == "trace_id_alias_canonical_output":
        validate_trace_alias_variants(config)
    else:
        raise ConformanceError(f"unknown compatibility matrix {matrix!r}")


def require_non_empty_string(value: Any, field: str, gold_id: str | None = None) -> str:
    assert_true(isinstance(value, str) and value.strip(), f"{gold_id + ' ' if gold_id else ''}{field} must be a non-empty string")
    return value


def require_non_empty_array(value: Any, field: str, gold_id: str | None = None) -> list[Any]:
    assert_true(isinstance(value, list) and value, f"{gold_id + ' ' if gold_id else ''}{field} must be a non-empty array")
    return value


def load_security_invariants(config: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / config.get("path", SECURITY_INVARIANTS_PATH.relative_to(ROOT))
    return load_json(path)


def validate_security_crypto_agility(data: dict[str, Any]) -> None:
    crypto = data.get("crypto_agility")
    assert_true(isinstance(crypto, dict), "security_invariants crypto_agility is required")
    algorithms = require_non_empty_array(crypto.get("allowed_signature_algorithms"), "crypto_agility.allowed_signature_algorithms")
    for algorithm in algorithms:
        label = require_non_empty_string(algorithm, "crypto_agility.allowed_signature_algorithms")
        normalized = normalize_security_label(label)
        if normalized not in ALLOWED_SECURITY_SIGNATURE_ALGORITHMS:
            raise ConformanceError(f"security_invariants unsafe crypto algorithm label {label!r}")
    key_rotation = crypto.get("key_rotation")
    assert_true(isinstance(key_rotation, dict), "security_invariants key_rotation is required")
    assert_true(key_rotation.get("rotation_required") is True, "security_invariants key rotation must be required")
    assert_true(key_rotation.get("revocation_path_required") is True, "security_invariants revocation path must be required")
    require_non_empty_string(key_rotation.get("compromise_response"), "crypto_agility.key_rotation.compromise_response")
    require_non_empty_array(crypto.get("node_attestation_extension_points"), "crypto_agility.node_attestation_extension_points")
    require_non_empty_array(crypto.get("non_cryptographic_safety_assumptions"), "crypto_agility.non_cryptographic_safety_assumptions")


def validate_security_review_checklist(data: dict[str, Any]) -> None:
    checklist = require_non_empty_array(data.get("security_review_checklist"), "security_review_checklist")
    for item in checklist:
        assert_true(isinstance(item, dict), "security_review_checklist items must be objects")
        require_non_empty_string(item.get("id"), "security_review_checklist.id")
        require_non_empty_string(item.get("question"), "security_review_checklist.question")
        require_non_empty_string(item.get("required_evidence"), "security_review_checklist.required_evidence")


def validate_security_enforcement(invariant: dict[str, Any], gold_id: str) -> None:
    enforcement = invariant.get("enforcement")
    assert_true(isinstance(enforcement, dict), f"{gold_id} enforcement mapping is required")
    enforcing_component = require_non_empty_string(enforcement.get("enforcing_component"), "enforcement.enforcing_component", gold_id)
    if is_prompt_only_control_text(enforcing_component):
        raise ConformanceError(f"security invariant {gold_id} uses a prompt-only trust boundary")
    require_non_empty_array(enforcement.get("required_events"), "enforcement.required_events", gold_id)
    require_non_empty_array(enforcement.get("evidence_links"), "enforcement.evidence_links", gold_id)
    require_non_empty_array(enforcement.get("containment_actions"), "enforcement.containment_actions", gold_id)


def validate_security_invariant_record(invariant: dict[str, Any]) -> tuple[str, set[str], str]:
    assert_true(isinstance(invariant, dict), "security invariant record must be an object")
    gold_id = require_non_empty_string(invariant.get("gold_id"), "gold_id")
    require_non_empty_string(invariant.get("threat_id"), "threat_id", gold_id)
    require_non_empty_string(invariant.get("name"), "name", gold_id)
    require_non_empty_array(invariant.get("assets"), "assets", gold_id)
    require_non_empty_string(invariant.get("principal"), "principal", gold_id)
    require_non_empty_string(invariant.get("attacker_capability"), "attacker_capability", gold_id)
    require_non_empty_string(invariant.get("incident_classification"), "incident_classification", gold_id)
    require_non_empty_string(invariant.get("change_risk_classification"), "change_risk_classification", gold_id)

    maturity_gate = invariant.get("maturity_gate")
    assert_true(isinstance(maturity_gate, dict), f"{gold_id} maturity_gate is required")
    case_status = maturity_gate.get("case_status")
    if maturity_gate.get("conformant_required") is True and case_status == "skipped":
        raise ConformanceError(f"mandatory conformant security case {gold_id} is skipped")
    assert_true(
        case_status in {"mapped_not_exercised", "exercised", "skipped"},
        f"{gold_id} maturity_gate.case_status is invalid",
    )
    require_non_empty_string(maturity_gate.get("non_claim"), "maturity_gate.non_claim", gold_id)
    if case_status == "exercised":
        executable = maturity_gate.get("executable_gold_evidence")
        assert_true(isinstance(executable, dict), f"security invariant {gold_id} is exercised without executable gold evidence")
        require_non_empty_string(executable.get("harness_id"), "executable_gold_evidence.harness_id", gold_id)
        require_non_empty_string(executable.get("report_ref"), "executable_gold_evidence.report_ref", gold_id)
        require_non_empty_string(executable.get("executed_at"), "executable_gold_evidence.executed_at", gold_id)
        require_non_empty_array(executable.get("evidence_assertions"), "executable_gold_evidence.evidence_assertions", gold_id)

    boundary = invariant.get("trust_boundary")
    assert_true(isinstance(boundary, dict), f"{gold_id} trust_boundary is required")
    boundary_name = require_non_empty_string(boundary.get("name"), "trust_boundary.name", gold_id)
    enforced_by = require_non_empty_array(boundary.get("enforced_by"), "trust_boundary.enforced_by", gold_id)
    prompt_only_enforcers = any(isinstance(item, str) and is_prompt_only_control_text(item) for item in enforced_by)
    if boundary.get("prompt_only") is True or prompt_only_enforcers or is_prompt_only_control_text(boundary_name):
        raise ConformanceError(f"security invariant {gold_id} uses a prompt-only trust boundary")

    validate_security_enforcement(invariant, gold_id)

    primary_plane = require_non_empty_string(invariant.get("primary_plane"), "primary_plane", gold_id)
    related_planes = invariant.get("related_planes", [])
    assert_true(isinstance(related_planes, list), f"{gold_id} related_planes must be an array")
    planes = {primary_plane, *[plane for plane in related_planes if isinstance(plane, str)]}
    unknown_planes = sorted(planes - REQUIRED_SECURITY_PLANES)
    assert_true(not unknown_planes, f"{gold_id} unknown security planes: {', '.join(unknown_planes)}")
    return gold_id, planes, str(case_status)


def validate_security_invariants(config: dict[str, Any]) -> None:
    data = load_security_invariants(config)
    assert_true(data.get("schema_version") == "splendor.security_invariants.v1", "security_invariants schema_version mismatch")
    assert_true(
        data.get("evidence_scope") == "partial_fnd_011_security_invariants_v0",
        "security_invariants evidence_scope must be partial_fnd_011_security_invariants_v0",
    )
    non_claim_values = data.get("non_claims")
    assert_true(isinstance(non_claim_values, list), "security_invariants non_claims must be an array")
    non_claims = {require_non_empty_string(non_claim, "security_invariants non_claim") for non_claim in non_claim_values}
    missing_non_claims = sorted(REQUIRED_SECURITY_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"security_invariants non_claims missing: {', '.join(missing_non_claims)}")
    validate_security_crypto_agility(data)
    validate_security_review_checklist(data)

    invariants = require_non_empty_array(data.get("invariants"), "invariants")
    seen_gold_ids: set[str] = set()
    covered_planes: set[str] = set()
    required_case_status = config.get("required_case_status")
    for invariant in invariants:
        gold_id, planes, case_status = validate_security_invariant_record(invariant)
        assert_true(gold_id not in seen_gold_ids, f"duplicate security invariant mapping for {gold_id}")
        if required_case_status is not None:
            assert_true(case_status == required_case_status, f"{gold_id} case_status must be {required_case_status}")
        seen_gold_ids.add(gold_id)
        covered_planes.update(planes)

    required_gold_ids = set(config.get("required_gold_ids", sorted(REQUIRED_SECURITY_GOLD_IDS)))
    missing_gold_ids = sorted(required_gold_ids - seen_gold_ids)
    assert_true(not missing_gold_ids, f"missing security invariant mappings: {', '.join(missing_gold_ids)}")
    required_planes = set(config.get("required_planes", sorted(REQUIRED_SECURITY_PLANES)))
    missing_planes = sorted(required_planes - covered_planes)
    assert_true(not missing_planes, f"security_invariants missing security planes: {', '.join(missing_planes)}")


def normalize_security_text(value: str) -> str:
    normalized = []
    previous_was_space = True
    for character in value:
        if character.isalnum():
            normalized.append(character.lower())
            previous_was_space = False
        elif not previous_was_space:
            normalized.append(" ")
            previous_was_space = True
    return "".join(normalized).strip()


def normalize_security_label(value: str) -> str:
    normalized = []
    previous_was_separator = True
    for character in value.strip():
        if character.isalnum():
            normalized.append(character.lower())
            previous_was_separator = False
        elif not previous_was_separator:
            normalized.append("_")
            previous_was_separator = True
    return "".join(normalized).strip("_")


def is_prompt_only_control_text(value: str) -> bool:
    normalized = normalize_security_text(value)
    return any(phrase in normalized for phrase in PROMPT_ONLY_SECURITY_PHRASES)


def load_driver_schema_confusion_fixture(config: dict[str, Any]) -> dict[str, Any]:
    path_value = config.get("path")
    assert_true(isinstance(path_value, str) and path_value, "driver_schema_confusion.path is required")
    return load_json(ROOT / path_value)


def validate_schema_endpoint(endpoint: Any, label: str) -> tuple[str, str]:
    assert_true(isinstance(endpoint, dict), f"{label} schema endpoint is required")
    require_exact_keys(endpoint, DRIVER_SCHEMA_ENDPOINT_KEYS, label)
    schema = require_non_empty_string(endpoint.get("schema"), f"{label}.schema")
    version = require_non_empty_string(endpoint.get("version"), f"{label}.version")
    return schema, version


def driver_schema_ref(schema: str, version: str) -> str:
    return f"{schema}@{version}"


def validate_driver_schema_verification(
    data: dict[str, Any],
    reason: str,
    operation: str,
    expected_ref: str,
    requested_ref: str,
) -> None:
    verification = data.get("verification")
    assert_true(isinstance(verification, dict), "driver schema verification evidence is required")
    require_exact_keys(verification, DRIVER_SCHEMA_VERIFICATION_KEYS, "verification")
    assert_true(verification.get("allowed") is False, "driver schema mismatch verification must fail closed")
    reasons = verification.get("reasons")
    assert_true(reasons == [reason], "driver schema verification reasons must contain only the mismatch reason")
    verifier_results = require_non_empty_array(verification.get("verifier_results"), "verification.verifier_results")
    assert_true(len(verifier_results) == 1, "verification.verifier_results must contain only driver_schema denial evidence")
    for result in verifier_results:
        assert_true(isinstance(result, dict), "verification.verifier_results entries must be objects")
        require_exact_keys(result, DRIVER_SCHEMA_VERIFIER_RESULT_KEYS, "verification.verifier_results entry")
        assert_true(result.get("verifier") == "driver_schema", "driver_schema verifier denial is required")
        assert_true(result.get("allowed") is False, "driver_schema verifier must deny mismatch")
        assert_true(result.get("reason") == reason, "driver_schema verifier reason must match mismatch reason")
        evidence = result.get("evidence")
        assert_true(isinstance(evidence, dict), "driver_schema verifier evidence is required")
        require_exact_keys(evidence, DRIVER_SCHEMA_VERIFIER_EVIDENCE_KEYS, "driver_schema verifier evidence")
        require_non_empty_string(evidence.get("driver_manifest_ref"), "driver_schema verifier evidence.driver_manifest_ref")
        assert_true(
            evidence.get("operation") == operation,
            "driver_schema verifier evidence operation must match fixture operation",
        )
        assert_true(
            evidence.get("requested_schema") == requested_ref,
            "driver_schema verifier evidence requested_schema must match schema_mismatch.requested",
        )
        assert_true(
            evidence.get("expected_schema") == expected_ref,
            "driver_schema verifier evidence expected_schema must match schema_mismatch.expected",
        )


def validate_driver_schema_gateway(data: dict[str, Any]) -> None:
    gateway = data.get("gateway")
    assert_true(isinstance(gateway, dict), "driver schema gateway containment evidence is required")
    require_exact_keys(gateway, DRIVER_SCHEMA_GATEWAY_KEYS, "gateway")
    assert_true(gateway.get("status") == "denied", "schema mismatch must be denied")
    assert_true(gateway.get("adapter_executed") is False, "schema mismatch denial must not report adapter execution")
    adapter_count = gateway.get("adapter_invocation_count")
    assert_true(
        isinstance(adapter_count, int) and not isinstance(adapter_count, bool) and adapter_count == 0,
        "schema mismatch denial must keep adapter invocation count at zero",
    )
    driver_count = gateway.get("driver_invocation_count")
    assert_true(
        isinstance(driver_count, int) and not isinstance(driver_count, bool) and driver_count == 0,
        "schema mismatch denial must keep driver invocation count at zero",
    )
    assert_true(gateway.get("effect_certainty") == "none", "schema mismatch denial must record effect_certainty none")


def validate_driver_schema_outcome(data: dict[str, Any], reason: str) -> None:
    outcome = data.get("outcome")
    assert_true(isinstance(outcome, dict), "driver schema denial outcome evidence is required")
    require_exact_keys(outcome, DRIVER_SCHEMA_OUTCOME_KEYS, "outcome")
    assert_true(outcome.get("status") == "denied", "driver schema outcome status must be denied")
    assert_true(outcome.get("reason") == reason, "driver schema outcome reason must match mismatch reason")
    assert_true(outcome.get("side_effect_occurred") is False, "driver schema mismatch outcome must not report side effects")
    side_effects = data.get("side_effects")
    assert_true(isinstance(side_effects, dict), "driver schema side_effects evidence is required")
    require_exact_keys(side_effects, DRIVER_SCHEMA_SIDE_EFFECT_COUNTERS, "side_effects")
    for field in sorted(DRIVER_SCHEMA_SIDE_EFFECT_COUNTERS):
        value = side_effects.get(field)
        assert_true(
            isinstance(value, int) and not isinstance(value, bool) and value == 0,
            f"driver schema side_effects.{field} must be zero",
        )


def forbidden_driver_schema_event_reason(kind: str) -> str | None:
    if any(kind.startswith(prefix) for prefix in DRIVER_SCHEMA_FORBIDDEN_EVENT_PREFIXES):
        return f"driver schema side-effect event namespace {kind} is forbidden"
    if kind in DRIVER_SCHEMA_FORBIDDEN_EVENTS or "executed" in kind or "execution" in kind or kind.endswith(".invoked"):
        return f"driver schema execution event {kind} is forbidden"
    return None


def validate_driver_schema_events(data: dict[str, Any]) -> None:
    events = require_non_empty_array(data.get("events"), "driver schema events")
    run_id = require_non_empty_string(data.get("run_id"), "run_id")
    action_id = require_non_empty_string(data.get("action_id"), "action_id")
    driver_id = require_non_empty_string(data.get("driver_id"), "driver_id")
    assert_true(len(events) == len(DRIVER_SCHEMA_EVENT_ORDER), "driver schema event sequence must have exactly six denial events")
    event_kinds: list[str] = []
    trace_event_ids: set[str] = set()
    for event in events:
        assert_true(isinstance(event, dict), "driver schema events entries must be objects")
        require_exact_keys(event, DRIVER_SCHEMA_EVENT_KEYS, "driver schema event")
        trace_event_id = require_non_empty_string(event.get("trace_event_id"), "driver schema event.trace_event_id")
        assert_true(trace_event_id not in trace_event_ids, f"duplicate trace_event_id {trace_event_id}")
        trace_event_ids.add(trace_event_id)
        kind = require_non_empty_string(event.get("kind"), "driver schema event.kind")
        forbidden_reason = forbidden_driver_schema_event_reason(kind)
        assert_true(forbidden_reason is None, str(forbidden_reason))
        assert_true(kind in DRIVER_SCHEMA_REQUIRED_EVENTS, f"driver schema event kind {kind} is not allowed")
        event_kinds.append(kind)
        identity = event.get("identity")
        assert_true(isinstance(identity, dict), "driver schema event identity is required")
        require_exact_keys(identity, DRIVER_SCHEMA_EVENT_IDENTITY_KEYS, "driver schema event identity")
        assert_true(identity.get("run_id") == run_id, "driver schema event run_id mismatch")
        assert_true(identity.get("action_id") == action_id, "driver schema event action_id mismatch")
        assert_true(identity.get("driver_id") == driver_id, "driver schema event driver_id mismatch")
        require_non_empty_string(event.get("evidence_ref"), "driver schema event.evidence_ref")
    assert_true(
        event_kinds == DRIVER_SCHEMA_EVENT_ORDER,
        f"driver schema event sequence mismatch: expected {', '.join(DRIVER_SCHEMA_EVENT_ORDER)}",
    )


def validate_driver_schema_confusion(config: dict[str, Any]) -> None:
    data = load_driver_schema_confusion_fixture(config)
    require_exact_keys(data, DRIVER_SCHEMA_TOP_LEVEL_KEYS, "driver schema fixture")
    assert_true(data.get("schema_version") == DRIVER_SCHEMA_CONFUSION_SCHEMA_VERSION, "driver schema fixture schema_version mismatch")
    assert_true(data.get("task_id") == "FND-011", "driver schema fixture task_id must be FND-011")
    assert_true(data.get("gold_id") == "G86", "driver schema fixture gold_id must be G86")
    require_non_empty_string(data.get("description"), "description")
    operation = require_non_empty_string(data.get("operation"), "operation")
    require_non_empty_string(data.get("run_id"), "run_id")
    require_non_empty_string(data.get("action_id"), "action_id")
    require_non_empty_string(data.get("driver_id"), "driver_id")
    assert_true(
        data.get("evidence_scope") == DRIVER_SCHEMA_CONFUSION_EVIDENCE_SCOPE,
        "driver schema fixture evidence_scope mismatch",
    )
    non_claim_values = data.get("non_claims")
    assert_true(isinstance(non_claim_values, list), "driver schema fixture non_claims must be an array")
    non_claims = {require_non_empty_string(non_claim, "driver schema fixture non_claim") for non_claim in non_claim_values}
    missing_non_claims = sorted(DRIVER_SCHEMA_CONFUSION_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"driver schema fixture non_claims missing: {', '.join(missing_non_claims)}")

    mismatch = data.get("schema_mismatch")
    assert_true(isinstance(mismatch, dict), "driver schema mismatch evidence is required")
    require_exact_keys(mismatch, DRIVER_SCHEMA_MISMATCH_KEYS, "schema_mismatch")
    reason = require_non_empty_string(mismatch.get("reason"), "schema_mismatch.reason")
    assert_true(reason in DRIVER_SCHEMA_MISMATCH_REASONS, f"unsupported driver schema mismatch reason {reason!r}")
    expected_schema, expected_version = validate_schema_endpoint(mismatch.get("expected"), "schema_mismatch.expected")
    requested_schema, requested_version = validate_schema_endpoint(mismatch.get("requested"), "schema_mismatch.requested")
    assert_true(
        expected_schema != requested_schema or expected_version != requested_version,
        "driver schema mismatch fixture must actually differ by schema or version",
    )
    assert_true(mismatch.get("detected_before_execution") is True, "driver schema mismatch must be detected before execution")

    validate_driver_schema_verification(
        data,
        reason,
        operation,
        driver_schema_ref(expected_schema, expected_version),
        driver_schema_ref(requested_schema, requested_version),
    )
    validate_driver_schema_gateway(data)
    validate_driver_schema_outcome(data, reason)
    validate_driver_schema_events(data)


def load_prompt_data_injection_fixture(config: dict[str, Any]) -> dict[str, Any]:
    path_value = config.get("path")
    assert_true(isinstance(path_value, str) and path_value, "prompt_data_injection.path is required")
    return load_json(ROOT / path_value)


def validate_prompt_requested_action(action: Any, label: str) -> tuple[str, str, list[str]]:
    assert_true(isinstance(action, dict), f"{label} is required")
    require_exact_keys(action, PROMPT_DATA_INJECTION_REQUESTED_ACTION_KEYS, label)
    name = require_non_empty_string(action.get("name"), f"{label}.name")
    adapter = require_non_empty_string(action.get("adapter"), f"{label}.adapter")
    side_effect_class = require_non_empty_string(action.get("side_effect_class"), f"{label}.side_effect_class")
    assert_true(side_effect_class != "read_only", f"{label}.side_effect_class must be side-effectful")
    params = action.get("params")
    assert_true(isinstance(params, dict), f"{label}.params must be an object")
    permissions = action.get("required_permissions")
    assert_true(isinstance(permissions, list), f"{label}.required_permissions must be an array")
    for permission in permissions:
        require_non_empty_string(permission, f"{label}.required_permissions")
    return name, adapter, list(permissions)


def validate_prompt_malicious_percept(data: dict[str, Any]) -> tuple[str, str, list[str]]:
    percept = data.get("malicious_percept")
    assert_true(isinstance(percept, dict), "malicious_percept evidence is required")
    require_exact_keys(percept, PROMPT_DATA_INJECTION_PERCEPT_KEYS, "malicious_percept")
    require_non_empty_string(percept.get("schema"), "malicious_percept.schema")
    provenance = percept.get("provenance")
    assert_true(isinstance(provenance, dict), "malicious_percept.provenance is required")
    require_exact_keys(provenance, PROMPT_DATA_INJECTION_PROVENANCE_KEYS, "malicious_percept.provenance")
    require_non_empty_string(provenance.get("source"), "malicious_percept.provenance.source")
    require_non_empty_string(provenance.get("trust_boundary"), "malicious_percept.provenance.trust_boundary")

    payload = percept.get("payload")
    assert_true(isinstance(payload, dict), "malicious_percept.payload must be an object")
    tainted_fields = require_non_empty_array(percept.get("tainted_fields"), "malicious_percept.tainted_fields")
    for field in tainted_fields:
        require_non_empty_string(field, "malicious_percept.tainted_fields")
    tainted_set = set(tainted_fields)
    missing_taint = sorted(PROMPT_DATA_INJECTION_AUTHORITY_FIELDS - tainted_set)
    assert_true(not missing_taint, f"malicious percept missing tainted authority fields: {', '.join(missing_taint)}")
    missing_payload_fields = sorted(field for field in PROMPT_DATA_INJECTION_AUTHORITY_FIELDS if field not in payload)
    assert_true(not missing_payload_fields, f"malicious percept payload missing authority fields: {', '.join(missing_payload_fields)}")
    requested_name, requested_adapter, requested_permissions = validate_prompt_requested_action(
        payload.get("requested_action"),
        "malicious_percept.payload.requested_action",
    )
    payload_allowed_actions = payload.get("allowed_actions")
    assert_true(isinstance(payload_allowed_actions, list), "malicious_percept.payload.allowed_actions must be an array")
    for allowed_action in payload_allowed_actions:
        require_non_empty_string(allowed_action, "malicious_percept.payload.allowed_actions")
    assert_true(
        requested_name in payload_allowed_actions,
        "malicious percept payload must attempt to grant the requested action",
    )
    payload_allowed_adapters = payload.get("allowed_adapters")
    assert_true(isinstance(payload_allowed_adapters, list), "malicious_percept.payload.allowed_adapters must be an array")
    for allowed_adapter in payload_allowed_adapters:
        require_non_empty_string(allowed_adapter, "malicious_percept.payload.allowed_adapters")
    assert_true(
        requested_adapter in payload_allowed_adapters,
        "malicious percept payload must attempt to grant the requested adapter",
    )
    payload_allowed_permissions = payload.get("allowed_permissions")
    assert_true(
        isinstance(payload_allowed_permissions, list),
        "malicious_percept.payload.allowed_permissions must be an array",
    )
    for allowed_permission in payload_allowed_permissions:
        require_non_empty_string(allowed_permission, "malicious_percept.payload.allowed_permissions")
    assert_true(
        all(permission in payload_allowed_permissions for permission in requested_permissions),
        "malicious percept payload must attempt to grant the requested permissions",
    )
    approval = payload.get("approval")
    assert_true(isinstance(approval, dict), "malicious_percept.payload.approval must be an object")
    assert_true(
        approval.get("granted") is True,
        "malicious percept payload must attempt to forge an approval grant",
    )
    verification = payload.get("verification")
    assert_true(isinstance(verification, dict), "malicious_percept.payload.verification must be an object")
    assert_true(
        verification.get("allowed") is True,
        "malicious percept payload must attempt to forge verification allow",
    )
    assert_true(
        payload.get("gateway_bypass") is True,
        "malicious percept payload must attempt gateway bypass",
    )
    return requested_name, requested_adapter, requested_permissions


def validate_prompt_policy_proposal(
    data: dict[str, Any],
    requested_name: str,
    requested_adapter: str,
    requested_permissions: list[str],
) -> None:
    proposal = data.get("policy_proposal")
    assert_true(isinstance(proposal, dict), "policy_proposal evidence is required")
    require_exact_keys(proposal, PROMPT_DATA_INJECTION_POLICY_KEYS, "policy_proposal")
    assert_true(proposal.get("naive_policy") is True, "policy_proposal.naive_policy must be true")
    assert_true(
        proposal.get("used_payload_requested_action") is True,
        "policy_proposal must show the payload requested action was proposed",
    )
    proposed_name, proposed_adapter, proposed_permissions = validate_prompt_requested_action(
        proposal.get("proposed_action"),
        "policy_proposal.proposed_action",
    )
    assert_true(proposed_name == requested_name, "policy proposal action must match malicious requested action")
    assert_true(proposed_adapter == requested_adapter, "policy proposal adapter must match malicious requested adapter")
    assert_true(
        proposed_permissions == requested_permissions,
        "policy proposal permissions must match malicious requested permissions",
    )


def validate_prompt_verification(
    data: dict[str, Any],
    requested_name: str,
    requested_adapter: str,
    requested_permissions: list[str],
) -> str:
    verification = data.get("verification")
    assert_true(isinstance(verification, dict), "prompt injection verification evidence is required")
    require_exact_keys(verification, PROMPT_DATA_INJECTION_VERIFICATION_KEYS, "verification")
    assert_true(verification.get("allowed") is False, "prompt injection verification must fail closed")
    reasons = verification.get("reasons")
    assert_true(isinstance(reasons, list) and len(reasons) == 1, "prompt injection verification must have exactly one denial reason")
    reason = require_non_empty_string(reasons[0], "verification.reasons")
    assert_true(reason in PROMPT_DATA_INJECTION_DENIAL_REASONS, f"unsupported prompt injection denial reason {reason!r}")
    verifier_results = require_non_empty_array(verification.get("verifier_results"), "verification.verifier_results")
    tenant_denial_seen = False
    for result in verifier_results:
        assert_true(isinstance(result, dict), "verification.verifier_results entries must be objects")
        require_exact_keys(result, PROMPT_DATA_INJECTION_VERIFIER_RESULT_KEYS, "verification.verifier_results entry")
        verifier = require_non_empty_string(result.get("verifier"), "verification.verifier_results.verifier")
        assert_true(result.get("allowed") is False, "prompt injection verifier result must deny")
        assert_true(result.get("reason") == reason, "prompt injection verifier reason must match denial reason")
        evidence = result.get("evidence")
        assert_true(isinstance(evidence, dict), "prompt injection verifier evidence is required")
        require_exact_keys(evidence, PROMPT_DATA_INJECTION_VERIFIER_EVIDENCE_KEYS, "prompt injection verifier evidence")
        assert_true(evidence.get("requested_action") == requested_name, "verifier evidence requested_action must match proposal")
        assert_true(evidence.get("requested_adapter") == requested_adapter, "verifier evidence requested_adapter must match proposal")
        assert_true(
            evidence.get("requested_permissions") == requested_permissions,
            "verifier evidence requested_permissions must match proposal",
        )
        allowed_actions = evidence.get("allowed_actions")
        allowed_adapters = evidence.get("allowed_adapters")
        allowed_permissions = evidence.get("allowed_permissions")
        assert_true(isinstance(allowed_actions, list), "verifier evidence allowed_actions must be an array")
        assert_true(isinstance(allowed_adapters, list), "verifier evidence allowed_adapters must be an array")
        assert_true(isinstance(allowed_permissions, list), "verifier evidence allowed_permissions must be an array")
        assert_true(
            requested_name not in allowed_actions
            or requested_adapter not in allowed_adapters
            or any(permission not in allowed_permissions for permission in requested_permissions),
            "prompt injection fixture must prove tenant scope did not grant the requested authority",
        )
        tenant_denial_seen = tenant_denial_seen or verifier in {"tenant", "tenant_policy", "agent_permission"}
    assert_true(tenant_denial_seen, "prompt injection denial must include tenant or permission verifier evidence")
    return reason


def validate_prompt_gateway(data: dict[str, Any]) -> None:
    gateway = data.get("gateway")
    assert_true(isinstance(gateway, dict), "prompt injection gateway containment evidence is required")
    require_exact_keys(gateway, PROMPT_DATA_INJECTION_GATEWAY_KEYS, "gateway")
    assert_true(gateway.get("status") == "denied", "prompt injection gateway status must be denied")
    assert_true(gateway.get("verification_ran") is True, "prompt injection verification must run")
    assert_true(gateway.get("execution_attempted") is False, "prompt injection denial must not attempt gateway execution")
    assert_true(gateway.get("gateway_bypassed") is False, "prompt injection payload must not bypass the gateway")
    assert_true(gateway.get("adapter_executed") is False, "prompt injection denial must not report adapter execution")
    adapter_count = gateway.get("adapter_invocation_count")
    assert_true(
        isinstance(adapter_count, int) and not isinstance(adapter_count, bool) and adapter_count == 0,
        "prompt injection denial must keep adapter invocation count at zero",
    )
    assert_true(gateway.get("effect_certainty") == "none", "prompt injection denial must record effect_certainty none")


def validate_prompt_outcome_and_side_effects(data: dict[str, Any], reason: str) -> None:
    outcome = data.get("outcome")
    assert_true(isinstance(outcome, dict), "prompt injection denial outcome evidence is required")
    require_exact_keys(outcome, PROMPT_DATA_INJECTION_OUTCOME_KEYS, "outcome")
    assert_true(outcome.get("status") == "denied", "prompt injection outcome status must be denied")
    assert_true(outcome.get("reason") == reason, "prompt injection outcome reason must match verification reason")
    assert_true(outcome.get("side_effect_occurred") is False, "prompt injection outcome must not report side effects")
    side_effects = data.get("side_effects")
    assert_true(isinstance(side_effects, dict), "prompt injection side_effects evidence is required")
    require_exact_keys(side_effects, DRIVER_SCHEMA_SIDE_EFFECT_COUNTERS, "prompt injection side_effects")
    for field in sorted(DRIVER_SCHEMA_SIDE_EFFECT_COUNTERS):
        value = side_effects.get(field)
        assert_true(
            isinstance(value, int) and not isinstance(value, bool) and value == 0,
            f"prompt injection side_effects.{field} must be zero",
        )


def forbidden_prompt_data_injection_event_reason(kind: str) -> str | None:
    if any(kind.startswith(prefix) for prefix in PROMPT_DATA_INJECTION_FORBIDDEN_EVENT_PREFIXES):
        return f"prompt injection side-effect event namespace {kind} is forbidden"
    if kind in PROMPT_DATA_INJECTION_FORBIDDEN_EVENTS or kind.endswith(".invoked"):
        return f"prompt injection execution event {kind} is forbidden"
    return None


def validate_prompt_events(data: dict[str, Any]) -> None:
    events = require_non_empty_array(data.get("events"), "prompt injection events")
    run_id = require_non_empty_string(data.get("run_id"), "run_id")
    tenant_id = require_non_empty_string(data.get("tenant_id"), "tenant_id")
    agent_id = require_non_empty_string(data.get("agent_id"), "agent_id")
    action_id = require_non_empty_string(data.get("action_id"), "action_id")
    tick_id = data.get("tick_id")
    assert_true(isinstance(tick_id, int) and not isinstance(tick_id, bool) and tick_id > 0, "tick_id must be a positive integer")
    percept_ref = require_non_empty_string(data.get("malicious_percept", {}).get("provenance", {}).get("source"), "malicious_percept.provenance.source")
    assert_true(len(events) == len(PROMPT_DATA_INJECTION_EVENT_ORDER), "prompt injection event sequence must have exactly eight denial events")
    event_kinds: list[str] = []
    trace_event_ids: set[str] = set()
    for event in events:
        assert_true(isinstance(event, dict), "prompt injection events entries must be objects")
        require_exact_keys(event, PROMPT_DATA_INJECTION_EVENT_KEYS, "prompt injection event")
        trace_event_id = require_non_empty_string(event.get("trace_event_id"), "prompt injection event.trace_event_id")
        assert_true(trace_event_id not in trace_event_ids, f"duplicate trace_event_id {trace_event_id}")
        trace_event_ids.add(trace_event_id)
        kind = require_non_empty_string(event.get("kind"), "prompt injection event.kind")
        forbidden_reason = forbidden_prompt_data_injection_event_reason(kind)
        assert_true(forbidden_reason is None, str(forbidden_reason))
        assert_true(kind in PROMPT_DATA_INJECTION_REQUIRED_EVENTS, f"prompt injection event kind {kind} is not allowed")
        event_kinds.append(kind)
        identity = event.get("identity")
        assert_true(isinstance(identity, dict), "prompt injection event identity is required")
        require_exact_keys(identity, PROMPT_DATA_INJECTION_EVENT_IDENTITY_KEYS, "prompt injection event identity")
        assert_true(identity.get("run_id") == run_id, "prompt injection event run_id mismatch")
        assert_true(identity.get("tenant_id") == tenant_id, "prompt injection event tenant_id mismatch")
        assert_true(identity.get("agent_id") == agent_id, "prompt injection event agent_id mismatch")
        assert_true(identity.get("action_id") == action_id, "prompt injection event action_id mismatch")
        assert_true(identity.get("tick_id") == tick_id, "prompt injection event tick_id mismatch")
        assert_true(identity.get("percept_ref") == percept_ref, "prompt injection event percept_ref mismatch")
        require_non_empty_string(event.get("evidence_ref"), "prompt injection event.evidence_ref")
    assert_true(
        event_kinds == PROMPT_DATA_INJECTION_EVENT_ORDER,
        f"prompt injection event sequence mismatch: expected {', '.join(PROMPT_DATA_INJECTION_EVENT_ORDER)}",
    )


def validate_prompt_data_injection(config: dict[str, Any]) -> None:
    data = load_prompt_data_injection_fixture(config)
    require_exact_keys(data, PROMPT_DATA_INJECTION_TOP_LEVEL_KEYS, "prompt injection fixture")
    assert_true(data.get("schema_version") == PROMPT_DATA_INJECTION_SCHEMA_VERSION, "prompt injection fixture schema_version mismatch")
    assert_true(data.get("task_id") == "FND-011", "prompt injection fixture task_id must be FND-011")
    assert_true(data.get("gold_id") == "G80", "prompt injection fixture gold_id must be G80")
    assert_true(
        data.get("evidence_scope") == PROMPT_DATA_INJECTION_EVIDENCE_SCOPE,
        "prompt injection fixture evidence_scope mismatch",
    )
    require_non_empty_string(data.get("description"), "description")
    require_non_empty_string(data.get("tenant_id"), "tenant_id")
    require_non_empty_string(data.get("agent_id"), "agent_id")
    require_non_empty_string(data.get("run_id"), "run_id")
    require_non_empty_string(data.get("action_id"), "action_id")
    require_non_empty_string(data.get("adapter_id"), "adapter_id")
    assert_true(isinstance(data.get("tick_id"), int) and not isinstance(data.get("tick_id"), bool), "tick_id must be an integer")
    non_claim_values = data.get("non_claims")
    assert_true(isinstance(non_claim_values, list), "prompt injection fixture non_claims must be an array")
    non_claims = {require_non_empty_string(non_claim, "prompt injection fixture non_claim") for non_claim in non_claim_values}
    missing_non_claims = sorted(PROMPT_DATA_INJECTION_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"prompt injection fixture non_claims missing: {', '.join(missing_non_claims)}")

    requested_name, requested_adapter, requested_permissions = validate_prompt_malicious_percept(data)
    assert_true(data.get("adapter_id") == requested_adapter, "adapter_id must match malicious requested adapter")
    validate_prompt_policy_proposal(data, requested_name, requested_adapter, requested_permissions)
    reason = validate_prompt_verification(data, requested_name, requested_adapter, requested_permissions)
    validate_prompt_gateway(data)
    validate_prompt_outcome_and_side_effects(data, reason)
    validate_prompt_events(data)


def require_existing_relative_path(value: Any, label: str) -> Path:
    path_value = require_non_empty_string(value, label)
    path = Path(path_value)
    assert_true(not path.is_absolute(), f"{label} must be repository-relative")
    assert_true(".." not in path.parts, f"{label} must not traverse outside the repository")
    full_path = ROOT / path
    assert_true(full_path.exists(), f"{label} path does not exist: {path_value}")
    return full_path


def validate_foundation_readiness_record(record: Any) -> str:
    assert_true(isinstance(record, dict), "foundation readiness entries must be objects")
    require_exact_keys(record, FOUNDATION_RECORD_KEYS, "foundation readiness entry")
    task_id = require_non_empty_string(record.get("task_id"), "foundation.task_id")
    assert_true(task_id in REQUIRED_FOUNDATION_TASKS, f"unknown foundation task {task_id}")
    issue = record.get("issue")
    assert_true(isinstance(issue, int) and not isinstance(issue, bool) and 220 <= issue <= 231, f"foundation {task_id} issue must be a FND issue number")
    assert_true(record.get("foundation_status") == "foundation_ready", f"foundation {task_id} status must be foundation_ready")
    assert_true(record.get("gold_status") == "not_exercised", f"foundation {task_id} gold_status must remain not_exercised")
    evidence_paths = require_non_empty_array(record.get("evidence_paths"), f"foundation {task_id} evidence_paths")
    for evidence_path in evidence_paths:
        require_existing_relative_path(evidence_path, f"foundation {task_id} evidence_paths")
    remaining_validation = require_non_empty_array(record.get("remaining_validation"), f"foundation {task_id} remaining_validation")
    for item in remaining_validation:
        require_non_empty_string(item, f"foundation {task_id} remaining_validation")
    gold_ids = require_non_empty_array(record.get("gold_ids"), f"foundation {task_id} gold_ids")
    for gold_id in gold_ids:
        require_non_empty_string(gold_id, f"foundation {task_id} gold_ids")
    non_claims = set(require_non_empty_array(record.get("non_claims"), f"foundation {task_id} non_claims"))
    for non_claim in non_claims:
        require_non_empty_string(non_claim, f"foundation {task_id} non_claims")
    assert_true("no_full_task_completion" in non_claims, f"foundation {task_id} must not claim full task completion")
    assert_true("no_gold_pass" in non_claims, f"foundation {task_id} must not claim gold pass")
    return task_id


def validate_foundation_exit_gate_coverage(coverage: Any) -> None:
    assert_true(isinstance(coverage, dict), "foundation exit_gate_coverage must be an object")
    require_exact_keys(coverage, FOUNDATION_REQUIRED_EXIT_GATES, "foundation exit_gate_coverage")
    for gate_id, gate in coverage.items():
        assert_true(isinstance(gate, dict), f"foundation exit gate {gate_id} must be an object")
        require_exact_keys(gate, FOUNDATION_EXIT_GATE_KEYS, f"foundation exit gate {gate_id}")
        assert_true(gate.get("status") == "foundation_ready", f"foundation exit gate {gate_id} must be foundation_ready")
        evidence_paths = require_non_empty_array(gate.get("evidence_paths"), f"foundation exit gate {gate_id} evidence_paths")
        for evidence_path in evidence_paths:
            require_existing_relative_path(evidence_path, f"foundation exit gate {gate_id} evidence_paths")


def validate_c01_readiness(readiness: Any) -> None:
    assert_true(isinstance(readiness, dict), "c01_readiness must be an object")
    require_exact_keys(readiness, FOUNDATION_C01_KEYS, "c01_readiness")
    assert_true(readiness.get("component_label") == "C01", "c01_readiness.component_label must be C01")
    assert_true(readiness.get("component_id") == "splendor.identity-registry", "c01_readiness.component_id mismatch")
    assert_true(
        readiness.get("readiness_scope") == "may_start_contract_rfc_and_foundation_dependent_work",
        "c01_readiness.readiness_scope mismatch",
    )
    assert_true(
        readiness.get("full_implementation_blocked_until_rfc_accepted") is True,
        "C01 full implementation must remain blocked until the Principal Registry RFC is accepted",
    )
    allowed_next_work = {require_non_empty_string(item, "c01_readiness.allowed_next_work") for item in require_non_empty_array(readiness.get("allowed_next_work"), "c01_readiness.allowed_next_work")}
    missing_tasks = sorted(REQUIRED_C01_TASKS - allowed_next_work)
    assert_true(not missing_tasks, f"c01_readiness missing IDR tasks: {', '.join(missing_tasks)}")
    dependencies = {require_non_empty_string(item, "c01_readiness.required_fnd_dependencies") for item in require_non_empty_array(readiness.get("required_fnd_dependencies"), "c01_readiness.required_fnd_dependencies")}
    missing_deps = sorted(REQUIRED_C01_FND_DEPENDENCIES - dependencies)
    assert_true(not missing_deps, f"c01_readiness missing FND dependencies: {', '.join(missing_deps)}")
    rfc_refs = require_non_empty_array(readiness.get("required_rfc_refs"), "c01_readiness.required_rfc_refs")
    for rfc_ref in rfc_refs:
        if isinstance(rfc_ref, str) and rfc_ref.startswith("docs/"):
            require_existing_relative_path(rfc_ref, "c01_readiness.required_rfc_refs")
        else:
            require_non_empty_string(rfc_ref, "c01_readiness.required_rfc_refs")
    non_claims = {require_non_empty_string(item, "c01_readiness.non_claims") for item in require_non_empty_array(readiness.get("non_claims"), "c01_readiness.non_claims")}
    assert_true("no_c01_implementation" in non_claims, "c01_readiness must not claim C01 implementation")
    assert_true("no_principal_registry_service" in non_claims, "c01_readiness must not claim a Principal Registry service")


def validate_foundation_readiness(config: dict[str, Any]) -> None:
    path = ROOT / config.get("path", FOUNDATION_READINESS_PATH.relative_to(ROOT))
    data = load_json(path)
    require_exact_keys(data, FOUNDATION_READINESS_TOP_LEVEL_KEYS, "foundation readiness fixture")
    assert_true(data.get("schema_version") == FOUNDATION_READINESS_SCHEMA_VERSION, "foundation readiness schema_version mismatch")
    assert_true(data.get("sprint") == "V2-FND-0", "foundation readiness sprint must be V2-FND-0")
    assert_true(data.get("aggregate_issue") == 180, "foundation readiness aggregate_issue must be 180")
    assert_true(data.get("status") == FOUNDATION_READINESS_STATUS, f"foundation readiness status must be {FOUNDATION_READINESS_STATUS}")
    require_non_empty_string(data.get("checkpoint_id"), "foundation readiness checkpoint_id")
    non_claims = {require_non_empty_string(item, "foundation readiness non_claims") for item in require_non_empty_array(data.get("non_claims"), "foundation readiness non_claims")}
    missing_non_claims = sorted(REQUIRED_FOUNDATION_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"foundation readiness missing non_claims: {', '.join(missing_non_claims)}")
    foundations = require_non_empty_array(data.get("foundations"), "foundation readiness foundations")
    task_ids: set[str] = set()
    for record in foundations:
        task_id = validate_foundation_readiness_record(record)
        assert_true(task_id not in task_ids, f"duplicate foundation task {task_id}")
        task_ids.add(task_id)
    missing_tasks = sorted(REQUIRED_FOUNDATION_TASKS - task_ids)
    assert_true(not missing_tasks, f"foundation readiness missing tasks: {', '.join(missing_tasks)}")
    validate_foundation_exit_gate_coverage(data.get("exit_gate_coverage"))
    validate_c01_readiness(data.get("c01_readiness"))


def require_positive_number(value: Any, label: str) -> None:
    assert_true(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0, f"{label} must be positive")


def validate_performance_environment(environment: Any) -> None:
    assert_true(isinstance(environment, dict), "benchmark_environment is required")
    for field in (
        "environment_id",
        "captured_at",
        "host_class",
        "os",
        "cpu_model",
        "storage_backend",
        "rustc_version",
        "splendor_commit",
        "clock_source",
        "network_topology",
    ):
        require_non_empty_string(environment.get(field), f"benchmark_environment.{field}")
    require_positive_number(environment.get("cpu_cores"), "benchmark_environment.cpu_cores")
    require_positive_number(environment.get("memory_gib"), "benchmark_environment.memory_gib")


def validate_performance_report_summary(summary: Any) -> None:
    assert_true(isinstance(summary, dict), "performance report_summary is required")
    for field in ("report_id", "status", "benchmark_suite", "summary"):
        require_non_empty_string(summary.get(field), f"report_summary.{field}")
    assert_true(summary.get("measured") is False, "partial FND-012 fixture must not claim measured benchmark results")
    assert_true(summary.get("status") == "budget_contract_only", "partial FND-012 fixture status must be budget_contract_only")


def validate_measurement_boundary(metric_id: str, boundary: Any) -> None:
    assert_true(isinstance(boundary, dict), f"{metric_id} measurement_boundary is required")
    if boundary.get("kernel_control_plane_only") is not True or boundary.get("provider_model_training_time_included") is not False:
        raise ConformanceError("provider/model time must not be mixed into kernel control-plane overhead")
    assert_true(boundary.get("evidence_checks_included") is True, f"{metric_id} must include evidence checks")
    assert_true(boundary.get("authority_checks_included") is True, f"{metric_id} must include authority checks")
    assert_true(boundary.get("safety_checks_included") is True, f"{metric_id} must include safety checks")


def validate_latency_budget_records(records: Any) -> set[str]:
    assert_true(isinstance(records, list) and records, "latency_budgets must be a non-empty array")
    metrics: set[str] = set()
    for record in records:
        assert_true(isinstance(record, dict), "latency budget record must be an object")
        metric_id = record.get("metric_id")
        require_non_empty_string(metric_id, "latency_budgets.metric_id")
        assert_true(metric_id not in metrics, f"duplicate performance metric {metric_id}")
        metrics.add(metric_id)
        require_non_empty_string(record.get("description"), f"{metric_id}.description")
        for field in ("max_p50_ms", "max_p95_ms", "max_p99_ms"):
            require_positive_number(record.get(field), f"{metric_id}.{field}")
        assert_true(record["max_p50_ms"] <= record["max_p95_ms"] <= record["max_p99_ms"], f"{metric_id} latency percentiles must be ordered")
        validate_measurement_boundary(metric_id, record.get("measurement_boundary"))
    missing = sorted(REQUIRED_LATENCY_BUDGET_METRICS - metrics)
    assert_true(not missing, f"performance budgets missing mandatory latency metrics: {', '.join(missing)}")
    return metrics


def validate_throughput_budget_records(records: Any) -> set[str]:
    assert_true(isinstance(records, list) and records, "throughput_budgets must be a non-empty array")
    metrics: set[str] = set()
    for record in records:
        assert_true(isinstance(record, dict), "throughput budget record must be an object")
        metric_id = record.get("metric_id")
        require_non_empty_string(metric_id, "throughput_budgets.metric_id")
        assert_true(metric_id not in metrics, f"duplicate performance metric {metric_id}")
        metrics.add(metric_id)
        require_non_empty_string(record.get("description"), f"{metric_id}.description")
        require_positive_number(record.get("min_rate_per_second"), f"{metric_id}.min_rate_per_second")
        require_positive_number(record.get("window_seconds"), f"{metric_id}.window_seconds")
        validate_measurement_boundary(metric_id, record.get("measurement_boundary"))
    missing = sorted(REQUIRED_THROUGHPUT_BUDGET_METRICS - metrics)
    assert_true(not missing, f"performance budgets missing mandatory throughput metrics: {', '.join(missing)}")
    return metrics


def validate_regression_thresholds(thresholds: Any, required_metrics: set[str]) -> None:
    assert_true(isinstance(thresholds, list) and thresholds, "regression_thresholds must be a non-empty array")
    metrics: set[str] = set()
    for threshold in thresholds:
        assert_true(isinstance(threshold, dict), "regression threshold must be an object")
        metric_id = threshold.get("metric_id")
        require_non_empty_string(metric_id, "regression_thresholds.metric_id")
        metrics.add(metric_id)
        require_positive_number(threshold.get("max_regression_percent"), f"{metric_id}.max_regression_percent")
        require_non_empty_string(threshold.get("baseline_ref"), f"{metric_id}.baseline_ref")
        require_non_empty_string(threshold.get("action_on_regression"), f"{metric_id}.action_on_regression")
    missing = sorted(required_metrics - metrics)
    assert_true(not missing, f"performance budgets missing regression thresholds: {', '.join(missing)}")


def validate_retention_backpressure_actions(actions: Any, known_metrics: set[str]) -> None:
    assert_true(isinstance(actions, list) and actions, "retention_backpressure_actions must be a non-empty array")
    kinds: set[str] = set()
    for action in actions:
        assert_true(isinstance(action, dict), "retention/backpressure action must be an object")
        action_id = action.get("action_id")
        require_non_empty_string(action_id, "retention_backpressure_actions.action_id")
        kind = action.get("kind")
        assert_true(kind in {"retention", "backpressure"}, f"{action_id} kind must be retention or backpressure")
        kinds.add(kind)
        trigger_metric_id = action.get("trigger_metric_id")
        require_non_empty_string(trigger_metric_id, f"{action_id}.trigger_metric_id")
        assert_true(trigger_metric_id in known_metrics, f"{action_id} trigger_metric_id references unknown metric")
        require_non_empty_string(action.get("trigger"), f"{action_id}.trigger")
        require_non_empty_string(action.get("action"), f"{action_id}.action")
        require_non_empty_string(action.get("required_event"), f"{action_id}.required_event")
        assert_true(action.get("fail_closed") is True, f"{action_id} must fail closed")
    missing = sorted({"retention", "backpressure"} - kinds)
    assert_true(not missing, f"performance budgets missing retention/backpressure actions: {', '.join(missing)}")


def validate_gold_resource_budget(gold_id: str, budget: Any) -> None:
    assert_true(isinstance(budget, dict), f"{gold_id} resource budget must be an object")
    require_non_empty_string(budget.get("resource_id"), f"{gold_id}.resource_id")
    assert_true(budget.get("kind") in {"control_plane", "inference_reservation", "worker", "physical_safety", "simulation"}, f"{gold_id} resource budget kind is invalid")
    numeric_fields = ("cpu_cores", "memory_mib", "storage_mib", "network_mbps", "max_nodes")
    for field in numeric_fields:
        value = budget.get(field)
        if value is not None:
            assert_true(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0, f"{gold_id}.{field} must be positive and finite")
    assert_true(any(budget.get(field) is not None for field in numeric_fields), f"{gold_id} resource budget must include a positive numeric limit")
    require_non_empty_string(budget.get("notes"), f"{gold_id}.resource_budget.notes")


def validate_gold_slo_resource_budgets(budgets: Any, known_metrics: set[str]) -> None:
    assert_true(isinstance(budgets, list) and budgets, "gold_slo_resource_budgets must be a non-empty array")
    gold_ids: set[str] = set()
    for budget in budgets:
        assert_true(isinstance(budget, dict), "gold SLO/resource budget must be an object")
        gold_id = budget.get("gold_id")
        require_non_empty_string(gold_id, "gold_slo_resource_budgets.gold_id")
        assert_true(gold_id not in gold_ids, f"duplicate gold budget {gold_id}")
        gold_ids.add(gold_id)
        assert_true(budget.get("evidence_status") == "not_exercised", f"{gold_id} must remain not_exercised in this partial fixture")
        slo_metric_ids = budget.get("slo_metric_ids")
        assert_true(isinstance(slo_metric_ids, list) and slo_metric_ids, f"{gold_id} slo_metric_ids must be non-empty")
        for metric_id in slo_metric_ids:
            assert_true(metric_id in known_metrics, f"{gold_id} references unknown SLO metric {metric_id}")
        resources = budget.get("resource_budgets")
        assert_true(isinstance(resources, list) and resources, f"{gold_id} resource_budgets must be non-empty")
        for resource_budget in resources:
            validate_gold_resource_budget(gold_id, resource_budget)
        notes = budget.get("notes")
        assert_true(isinstance(notes, list) and notes, f"{gold_id} notes must be non-empty")
    missing = sorted(REQUIRED_PERFORMANCE_GOLD_IDS - gold_ids)
    assert_true(not missing, f"performance budgets missing gold SLO/resource mappings: {', '.join(missing)}")


def validate_performance_budgets(config: dict[str, Any]) -> None:
    path = ROOT / config.get("path", PERFORMANCE_BUDGETS_PATH.relative_to(ROOT))
    data = load_json(path)
    assert_true(data.get("schema_version") == PERFORMANCE_BUDGET_SCHEMA_VERSION, "performance budget schema_version mismatch")
    assert_true(data.get("task_id") == "FND-012", "performance budget task_id must be FND-012")
    assert_true(data.get("evidence_scope") == PERFORMANCE_BUDGET_EVIDENCE_SCOPE, "performance budget evidence_scope mismatch")
    non_claims = set(data.get("non_claims", []))
    missing_non_claims = sorted(REQUIRED_PERFORMANCE_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"performance budgets missing non_claims: {', '.join(missing_non_claims)}")
    validate_performance_environment(data.get("benchmark_environment"))
    validate_performance_report_summary(data.get("report_summary"))
    latency_metrics = validate_latency_budget_records(data.get("latency_budgets"))
    throughput_metrics = validate_throughput_budget_records(data.get("throughput_budgets"))
    known_metrics = latency_metrics | throughput_metrics
    required_metrics = REQUIRED_LATENCY_BUDGET_METRICS | REQUIRED_THROUGHPUT_BUDGET_METRICS
    validate_regression_thresholds(data.get("regression_thresholds"), required_metrics)
    validate_retention_backpressure_actions(data.get("retention_backpressure_actions"), known_metrics)
    validate_gold_slo_resource_budgets(data.get("gold_slo_resource_budgets"), known_metrics)


def validate_case(case: dict[str, Any]) -> None:
    primitive = case.get("primitive")
    if primitive == "runtime_loop":
        validate_trace(case["trace"])
    elif primitive == "trace":
        validate_trace(case["trace"])
    elif primitive == "gateway":
        validate_gateway(case["gateway"])
    elif primitive == "state":
        validate_state(case)
    elif primitive == "replay":
        validate_replay(case["replay"])
    elif primitive == "messages":
        validate_message(case)
    elif primitive == "work_orders":
        validate_work_order(case["work_order"])
    elif primitive == "governance":
        validate_governance(case["governance"])
    elif primitive == "adapters":
        validate_adapter_manifests(case["adapter_manifests"])
    elif primitive == "stable_primitives":
        validate_stable_examples(case["stable_examples"])
    elif primitive == "compatibility":
        validate_compatibility(case["compatibility"])
    elif primitive == "security_invariants":
        validate_security_invariants(case["security_invariants"])
    elif primitive == "driver_schema_confusion":
        validate_driver_schema_confusion(case["driver_schema_confusion"])
    elif primitive == "prompt_data_injection":
        validate_prompt_data_injection(case["prompt_data_injection"])
    elif primitive == "performance_budgets":
        validate_performance_budgets(case["performance_budgets"])
    elif primitive == "foundation_readiness":
        validate_foundation_readiness(case["foundation_readiness"])
    else:
        raise ConformanceError(f"unknown primitive {primitive!r}")


def run_suite(fixture_path: Path) -> list[Result]:
    fixture = load_json(fixture_path)
    cases = fixture.get("cases")
    assert_true(isinstance(cases, list) and cases, "conformance fixture must include cases")
    results: list[Result] = []
    for case in cases:
        case_id = str(case.get("case_id"))
        primitive = str(case.get("primitive"))
        requirement = str(case.get("requirement"))
        path = str(case.get("path"))
        try:
            validate_case(case)
        except Exception as error:  # exact messages become report evidence
            if path == "negative_fixture":
                expected = case.get("expected_failure")
                if expected and expected in str(error):
                    results.append(Result(case_id, primitive, requirement, path, "pass", f"negative fixture failed as expected: {error}"))
                else:
                    results.append(Result(case_id, primitive, requirement, path, "fail", f"negative fixture failed with unexpected error: {error}"))
            else:
                results.append(Result(case_id, primitive, requirement, path, "fail", str(error)))
        else:
            if path == "negative_fixture":
                results.append(Result(case_id, primitive, requirement, path, "fail", "negative fixture unexpectedly passed"))
            else:
                report_message = case.get("report_message")
                if not isinstance(report_message, str) or not report_message:
                    report_message = "ok"
                results.append(Result(case_id, primitive, requirement, path, "pass", report_message))
    return results


def render_text(results: list[Result]) -> str:
    failed = [result for result in results if result.status != "pass"]
    lines = ["Splendor 0.1 conformance report", f"status: {'fail' if failed else 'pass'}", f"cases: {len(results)}", f"failed: {len(failed)}"]
    for result in results:
        lines.append(f"{result.status.upper()} {result.primitive} {result.requirement} {result.case_id}: {result.message}")
    return "\n".join(lines)


def render_json(results: list[Result]) -> str:
    failed = [result for result in results if result.status != "pass"]
    payload = {
        "schema_version": "splendor.conformance_report.v1",
        "milestone": "Splendor0.1-dev",
        "sprint": "0.1-S2",
        "status": "fail" if failed else "pass",
        "case_count": len(results),
        "failed_count": len(failed),
        "results": [result.__dict__ for result in results],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Splendor 0.1 primitive conformance fixtures")
    parser.add_argument("--fixtures", type=Path, default=FIXTURE_PATH, help="path to conformance fixture JSON")
    parser.add_argument("--format", choices={"text", "json"}, default="text", help="report format")
    parser.add_argument("--output", type=Path, help="optional report output path")
    args = parser.parse_args()

    results = run_suite(args.fixtures)
    output = render_json(results) if args.format == "json" else render_text(results)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if any(result.status != "pass" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
