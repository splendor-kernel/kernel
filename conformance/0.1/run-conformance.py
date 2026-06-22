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
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "conformance" / "0.1" / "fixtures" / "conformance-cases.json"
ADAPTER_VALIDATOR = ROOT / "scripts" / "validate-adapter-manifests.py"
STABLE_EXAMPLES_PATH = ROOT / "docs" / "spec" / "0.1" / "stable-primitive-examples.json"
SECURITY_INVARIANTS_PATH = ROOT / "docs" / "rules" / "v2" / "security" / "security-invariants.json"
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
    require_non_empty_array(crypto.get("allowed_signature_algorithms"), "crypto_agility.allowed_signature_algorithms")
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
    require_non_empty_string(enforcement.get("enforcing_component"), "enforcement.enforcing_component", gold_id)
    require_non_empty_array(enforcement.get("required_events"), "enforcement.required_events", gold_id)
    require_non_empty_array(enforcement.get("evidence_links"), "enforcement.evidence_links", gold_id)
    require_non_empty_array(enforcement.get("containment_actions"), "enforcement.containment_actions", gold_id)


def validate_security_invariant_record(invariant: dict[str, Any]) -> tuple[str, set[str]]:
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
    if maturity_gate.get("conformant_required") is True and maturity_gate.get("case_status") == "skipped":
        raise ConformanceError(f"mandatory conformant security case {gold_id} is skipped")
    assert_true(
        maturity_gate.get("case_status") in {"mapped_not_exercised", "exercised", "skipped"},
        f"{gold_id} maturity_gate.case_status is invalid",
    )
    require_non_empty_string(maturity_gate.get("non_claim"), "maturity_gate.non_claim", gold_id)

    boundary = invariant.get("trust_boundary")
    assert_true(isinstance(boundary, dict), f"{gold_id} trust_boundary is required")
    require_non_empty_string(boundary.get("name"), "trust_boundary.name", gold_id)
    enforced_by = require_non_empty_array(boundary.get("enforced_by"), "trust_boundary.enforced_by", gold_id)
    prompt_only_enforcers = all(isinstance(item, str) and "prompt" in item.lower() for item in enforced_by)
    if boundary.get("prompt_only") is True or prompt_only_enforcers:
        raise ConformanceError(f"security invariant {gold_id} uses a prompt-only trust boundary")

    validate_security_enforcement(invariant, gold_id)

    primary_plane = require_non_empty_string(invariant.get("primary_plane"), "primary_plane", gold_id)
    related_planes = invariant.get("related_planes", [])
    assert_true(isinstance(related_planes, list), f"{gold_id} related_planes must be an array")
    planes = {primary_plane, *[plane for plane in related_planes if isinstance(plane, str)]}
    unknown_planes = sorted(planes - REQUIRED_SECURITY_PLANES)
    assert_true(not unknown_planes, f"{gold_id} unknown security planes: {', '.join(unknown_planes)}")
    return gold_id, planes


def validate_security_invariants(config: dict[str, Any]) -> None:
    data = load_security_invariants(config)
    assert_true(data.get("schema_version") == "splendor.security_invariants.v1", "security_invariants schema_version mismatch")
    assert_true(
        data.get("evidence_scope") == "partial_fnd_011_security_invariants_v0",
        "security_invariants evidence_scope must be partial_fnd_011_security_invariants_v0",
    )
    non_claims = set(data.get("non_claims", []))
    missing_non_claims = sorted(REQUIRED_SECURITY_NON_CLAIMS - non_claims)
    assert_true(not missing_non_claims, f"security_invariants non_claims missing: {', '.join(missing_non_claims)}")
    validate_security_crypto_agility(data)
    validate_security_review_checklist(data)

    invariants = require_non_empty_array(data.get("invariants"), "invariants")
    seen_gold_ids: set[str] = set()
    covered_planes: set[str] = set()
    for invariant in invariants:
        gold_id, planes = validate_security_invariant_record(invariant)
        assert_true(gold_id not in seen_gold_ids, f"duplicate security invariant mapping for {gold_id}")
        seen_gold_ids.add(gold_id)
        covered_planes.update(planes)

    required_gold_ids = set(config.get("required_gold_ids", sorted(REQUIRED_SECURITY_GOLD_IDS)))
    missing_gold_ids = sorted(required_gold_ids - seen_gold_ids)
    assert_true(not missing_gold_ids, f"missing security invariant mappings: {', '.join(missing_gold_ids)}")
    required_planes = set(config.get("required_planes", sorted(REQUIRED_SECURITY_PLANES)))
    missing_planes = sorted(required_planes - covered_planes)
    assert_true(not missing_planes, f"security_invariants missing security planes: {', '.join(missing_planes)}")


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
