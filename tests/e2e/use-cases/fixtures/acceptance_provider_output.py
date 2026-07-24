#!/usr/bin/env python3
"""Canonical verifier/projection for private-v3 acceptance host outputs."""

from __future__ import annotations

import copy
import hashlib
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from acceptance_provider_evidence import _verify_with_ring
from acceptance_scenario_expectations import (
    OUTPUT_EXPECTATION_FIELDS,
    ROLE_BINDINGS,
)
from acceptance_provider_protocol import (
    EFFECT_DOMAIN,
    OPERATION_MANIFEST,
    OUTPUT_DOMAIN,
    PROVIDER_ID,
    PROTOCOL_VERSION,
    RECEIPT_ENVELOPE_SCHEMA,
    RECEIPT_ID_DOMAIN,
    RECEIPT_PAYLOAD_SCHEMA,
    RECEIPT_SIGNATURE_DOMAIN,
    SIGNING_KEY_ID,
    STATE_DOMAIN,
    ProtocolError,
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    digest_bytes,
    digest_value,
    fixed_signing_frame,
    secure_read_file,
    strict_loads,
)


PROJECTION_SCHEMA = "splendor.acceptance.private_v3_output_projection.v2"
ENVELOPE_FIELDS = {
    "schema_version",
    "algorithm",
    "signing_key_id",
    "payload_encoding",
    "payload_b64",
    "signature_b64",
}
OUTPUT_FIELDS = {
    "operation_id",
    "proof_type",
    "tenant_id",
    "action_id",
    "effect_id",
    "state_digest",
    "result",
    "provider_receipt",
}
RECEIPT_FIELDS = {
    "schema_version",
    "protocol_version",
    "provider_id",
    "provider_revision",
    "provider_epoch",
    "provider_receipt_id",
    "request_body_digest",
    "request_key_id",
    "client_principal_id",
    "source_instance_id",
    "audience",
    "request_id",
    "tenant_id",
    "agent_id",
    "run_id",
    "tick_id",
    "action_id",
    "adapter_id",
    "action_name",
    "physical_action_resource_coordinate",
    "operation_id",
    "profile_set_digest",
    "operation_profile_digest",
    "idempotency_key",
    "semantic_digest",
    "request_issued_at_unix_ms",
    "request_deadline_unix_ms",
    "status",
    "effect_certainty",
    "effect_id",
    "state_digest",
    "output_profile",
    "output_b64",
    "output_digest",
    "satisfied_postconditions",
    "postcondition_proof",
    "issued_at_unix_ms",
    "expires_at_unix_ms",
}


def _exact_object(value: Any, fields: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError(reason)
    return value


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.int != 0 and str(parsed) == value


def _integer_bounds(value: Any, maximum: int) -> None:
    if type(value) is int:
        if abs(value) > maximum:
            raise ProtocolError("private_v3_output_integer_bound_exceeded")
    elif isinstance(value, list):
        for child in value:
            _integer_bounds(child, maximum)
    elif isinstance(value, dict):
        for child in value.values():
            _integer_bounds(child, maximum)


def _validated_expectation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OUTPUT_EXPECTATION_FIELDS:
        raise ProtocolError("private_v3_expectation_fields_invalid")
    role = value.get("request_principal_role")
    binding = ROLE_BINDINGS.get(role)
    if (
        binding is None
        or any(
            not isinstance(value.get(field), str) or not value[field]
            for field in (
                "scenario_id",
                "expectation_id",
                "operation_id",
                "request_key_id",
                "client_principal_id",
                "source_instance_id",
                "tenant_id",
                "agent_id",
                "run_id",
                "action_id",
                "audience",
                "provider_id",
                "signing_key_id",
            )
        )
        or any(
            not _canonical_uuid(value[field])
            for field in ("source_instance_id", "tenant_id", "agent_id", "run_id", "action_id")
        )
        or any(value[field] != expected for field, expected in binding.items())
        or value["provider_id"] != PROVIDER_ID
        or value["signing_key_id"] != SIGNING_KEY_ID
        or value["audience"] != OPERATION_MANIFEST.audience
    ):
        raise ProtocolError("private_v3_expectation_invalid")
    return value


def _validate_result(
    output: dict[str, Any],
    payload: dict[str, Any],
    operation: dict[str, Any],
    expected_resource: Any,
) -> tuple[str | None, str | None]:
    result = output["result"]
    if not isinstance(result, dict):
        raise ProtocolError("private_v3_result_not_object")
    profile = operation["output_profile"]
    exact: set[str]
    resource_kind: str | None = None
    resource_id: str | None = None
    valid = False
    if profile == "marker":
        exact = {"tenant_id", "run_id", "action_id", "action_name", "effect_id"}
        valid = (
            result.get("tenant_id") == output["tenant_id"]
            and result.get("run_id") == payload["run_id"]
            and result.get("action_id") == output["action_id"]
            and result.get("action_name") == operation["action_name"]
            and result.get("effect_id") == output["effect_id"]
        )
    elif profile == "fixture_read":
        exact = {"fixture", "record_count"}
        valid = result == {"fixture": "s9-idempotent-read", "record_count": 1}
    elif profile == "sql_read":
        exact = {"row_count", "rows"}
        valid = result == {"row_count": 1, "rows": [{"fixture": 1}]}
    elif profile == "data_read":
        exact = {"data_ref", "tenant_id", "raw_payload_included", "record_count"}
        resource_kind = "data_ref"
        resource_id = result.get("data_ref")
        valid = (
            resource_id == expected_resource
            and result.get("tenant_id") == output["tenant_id"]
            and result.get("raw_payload_included") is False
            and result.get("record_count") == 3
        )
    elif profile in {"artifact_create", "artifact_publish"}:
        exact = {"artifact_ref", "tenant_id", "created", "published", "external_store"}
        published = profile == "artifact_publish"
        resource_kind = "artifact_ref"
        resource_id = result.get("artifact_ref")
        valid = (
            resource_id == expected_resource
            and result.get("tenant_id") == output["tenant_id"]
            and result.get("created") is True
            and result.get("published") is published
            and result.get("external_store")
            == ("acceptance-action-provider-v3" if published else None)
        )
    else:
        exact_by_profile = {
            "physical_battery": {"coordinate", "battery_milli_percent"},
            "physical_sensor": {"coordinate", "battery_milli_percent", "sensor_status"},
            "physical_inspect": {"coordinate", "inspected_zone"},
            "physical_waypoint": {"coordinate", "waypoint"},
            "physical_image": {"coordinate", "images_captured"},
            "physical_return": {"coordinate", "at_base"},
            "physical_trace_upload": {"coordinate", "trace_summaries_uploaded"},
        }
        exact = exact_by_profile.get(profile, set())
        coordinate = result.get("coordinate")
        resource_kind = "physical_node"
        resource_id = coordinate.get("node_id") if isinstance(coordinate, dict) else None
        valid = coordinate == expected_resource
        if profile == "physical_battery":
            valid = valid and result.get("battery_milli_percent") == 820
        elif profile == "physical_sensor":
            valid = (
                valid
                and result.get("battery_milli_percent") == 820
                and result.get("sensor_status") == "nominal"
            )
        elif profile == "physical_inspect":
            valid = valid and result.get("inspected_zone") == "zone:warehouse-a3"
        elif profile == "physical_waypoint":
            valid = valid and result.get("waypoint") == "waypoint:warehouse-a3"
        elif profile == "physical_image":
            valid = valid and type(result.get("images_captured")) is int and result["images_captured"] > 0
        elif profile == "physical_return":
            valid = valid and result.get("at_base") is True
        elif profile == "physical_trace_upload":
            valid = (
                valid
                and type(result.get("trace_summaries_uploaded")) is int
                and result["trace_summaries_uploaded"] > 0
            )
        else:
            valid = False
    if set(result) != exact or not valid:
        raise ProtocolError("private_v3_output_result_family_mismatch")
    return resource_kind, resource_id


def project_private_v3_output(
    value: dict[str, Any],
    *,
    expectation: dict[str, Any],
    public_key_path: Path | None = None,
    now_ms: int | None = None,
    verifier: Callable[[Path, bytes, bytes], None] | None = None,
) -> dict[str, Any]:
    expected = _validated_expectation(expectation)
    expected_operation_id = expected["operation_id"]
    expected_resource = expected["resource"]
    candidate = value.get("output") if isinstance(value.get("output"), dict) else value
    output = _exact_object(candidate, OUTPUT_FIELDS, "private_v3_output_fields_invalid")
    operation = OPERATION_MANIFEST.by_operation_id.get(expected_operation_id)
    if operation is None or operation["provider_mode"] != "execute":
        raise ProtocolError("private_v3_operation_invalid")
    if (
        operation["coordinate_rule"] == "none"
        and operation["parameter_profile"]
        not in {"artifact_create", "artifact_publish", "data_read"}
        and expected_resource is not None
    ):
        raise ProtocolError("private_v3_expectation_resource_invalid")
    envelope = _exact_object(
        output["provider_receipt"], ENVELOPE_FIELDS, "private_v3_receipt_envelope_fields_invalid"
    )
    if (
        envelope["schema_version"] != RECEIPT_ENVELOPE_SCHEMA
        or envelope["algorithm"] != "Ed25519"
        or envelope["signing_key_id"] != expected["signing_key_id"]
        or envelope["payload_encoding"] != "base64url"
    ):
        raise ProtocolError("private_v3_receipt_envelope_identity_invalid")
    payload_raw = b64url_decode(envelope["payload_b64"])
    signature = b64url_decode(envelope["signature_b64"], expected_length=64)
    public_file = public_key_path or Path(
        os.environ["SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE"]
    )
    public_key = secure_read_file(public_file, max_bytes=32, owner_only=False)
    (verifier or _verify_with_ring)(
        public_file,
        signature,
        fixed_signing_frame(RECEIPT_SIGNATURE_DOMAIN, payload_raw),
    )
    payload = strict_loads(
        payload_raw,
        max_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        max_fields=OPERATION_MANIFEST.limits["max_fields"],
        max_array_items=OPERATION_MANIFEST.limits["max_array_items"],
        max_string_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        require_canonical=True,
    )
    _exact_object(payload, RECEIPT_FIELDS, "private_v3_receipt_payload_fields_invalid")
    binding = ROLE_BINDINGS[expected["request_principal_role"]]
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if (
        expected["request_principal_role"] not in operation["allowed_request_principals"]
        or payload["request_key_id"] != expected["request_key_id"]
        or payload["request_key_id"] != binding["request_key_id"]
        or payload["client_principal_id"] != expected["client_principal_id"]
        or payload["client_principal_id"] != binding["client_principal_id"]
        or payload["source_instance_id"] != expected["source_instance_id"]
        or payload["source_instance_id"] != binding["source_instance_id"]
        or payload["schema_version"] != RECEIPT_PAYLOAD_SCHEMA
        or payload["protocol_version"] != PROTOCOL_VERSION
        or payload["provider_id"] != expected["provider_id"]
        or payload["provider_revision"] != OPERATION_MANIFEST.provider_revision
        or not _canonical_uuid(payload["provider_epoch"])
        or not _canonical_uuid(payload["request_id"])
        or payload["audience"] != expected["audience"]
        or payload["tenant_id"] != expected["tenant_id"]
        or output["tenant_id"] != expected["tenant_id"]
        or payload["agent_id"] != expected["agent_id"]
        or payload["run_id"] != expected["run_id"]
        or payload["operation_id"] != expected_operation_id
        or output["operation_id"] != expected_operation_id
        or payload["adapter_id"] != operation["adapter_id"]
        or payload["action_name"] != operation["action_name"]
        or payload["profile_set_digest"] != OPERATION_MANIFEST.digest
        or payload["operation_profile_digest"]
        != OPERATION_MANIFEST.operation_digest(operation)
        or payload["output_profile"] != operation["output_profile"]
        or output["proof_type"] != operation["output_profile"]
        or payload["status"]
        not in {
            operation["expected_status"]["initial"],
            operation["expected_status"]["reconciled"],
        }
        or payload["effect_certainty"] != "known"
        or payload["action_id"] != output["action_id"]
        or output["action_id"] != expected["action_id"]
        or payload["effect_id"] != output["effect_id"]
        or payload["state_digest"] != output["state_digest"]
        or payload["satisfied_postconditions"] != [operation["postcondition"]]
        or type(payload["issued_at_unix_ms"]) is not int
        or type(payload["expires_at_unix_ms"]) is not int
        or payload["issued_at_unix_ms"] > current + OPERATION_MANIFEST.limits["max_future_skew_ms"]
        or payload["expires_at_unix_ms"] <= current
        or payload["expires_at_unix_ms"] <= payload["issued_at_unix_ms"]
        or payload["expires_at_unix_ms"] - payload["issued_at_unix_ms"]
        > OPERATION_MANIFEST.limits["max_receipt_ttl_ms"]
    ):
        raise ProtocolError("private_v3_receipt_binding_invalid")
    unsigned_output = {key: item for key, item in output.items() if key != "provider_receipt"}
    output_raw = b64url_decode(payload["output_b64"])
    parsed_output = strict_loads(
        output_raw,
        max_bytes=operation["bounds"]["max_output_bytes"],
        max_fields=OPERATION_MANIFEST.limits["max_fields"],
        max_array_items=operation["bounds"]["max_array_items"],
        max_string_bytes=operation["bounds"]["max_string_bytes"],
        require_canonical=True,
    )
    expected_output_digest = digest_bytes(OUTPUT_DOMAIN, output_raw)
    expected_state_digest = digest_value(STATE_DOMAIN, output["result"])
    expected_effect_id = digest_value(
        EFFECT_DOMAIN, {"idempotency_key": payload["idempotency_key"]}
    )
    expected_receipt_id = digest_value(
        RECEIPT_ID_DOMAIN,
        {
            "provider_epoch": payload["provider_epoch"],
            "idempotency_key": payload["idempotency_key"],
            "request_body_digest": payload["request_body_digest"],
            "status": payload["status"],
        },
    )
    proof = payload["postcondition_proof"]
    if (
        parsed_output != unsigned_output
        or canonical_bytes(parsed_output) != output_raw
        or payload["output_digest"] != expected_output_digest
        or payload["state_digest"] != expected_state_digest
        or payload["effect_id"] != expected_effect_id
        or payload["provider_receipt_id"] != expected_receipt_id
        or not isinstance(proof, dict)
        or proof
        != {
            "operation_id": expected_operation_id,
            "predicate": operation["postcondition"],
            "effect_id": payload["effect_id"],
            "state_digest": payload["state_digest"],
            "output_digest": payload["output_digest"],
        }
    ):
        raise ProtocolError("private_v3_output_integrity_invalid")
    _integer_bounds(output["result"], operation["bounds"]["max_integer_abs"])
    resource_kind, resource_id = _validate_result(
        output, payload, operation, expected_resource
    )
    if operation["coordinate_rule"] == "physical_node":
        if payload["physical_action_resource_coordinate"] != expected_resource:
            raise ProtocolError("private_v3_receipt_resource_mismatch")
    elif payload["physical_action_resource_coordinate"] is not None:
        raise ProtocolError("private_v3_receipt_resource_mismatch")
    return {
        "schema_version": PROJECTION_SCHEMA,
        "scenario_id": expected["scenario_id"],
        "expectation_id": expected["expectation_id"],
        "verified_at_unix_ms": payload["issued_at_unix_ms"],
        "public_key_b64": b64url_encode(public_key),
        "public_key_fingerprint": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "signing_key_id": envelope["signing_key_id"],
        "provider_id": payload["provider_id"],
        "provider_epoch": payload["provider_epoch"],
        "provider_receipt_id": payload["provider_receipt_id"],
        "request_body_digest": payload["request_body_digest"],
        "request_key_id": payload["request_key_id"],
        "request_principal_role": expected["request_principal_role"],
        "client_principal_id": payload["client_principal_id"],
        "source_instance_id": payload["source_instance_id"],
        "audience": payload["audience"],
        "request_id": payload["request_id"],
        "agent_id": payload["agent_id"],
        "run_id": payload["run_id"],
        "tick_id": payload["tick_id"],
        "physical_action_resource_coordinate": copy.deepcopy(
            payload["physical_action_resource_coordinate"]
        ),
        "operation_id": output["operation_id"],
        "proof_type": output["proof_type"],
        "tenant_id": output["tenant_id"],
        "action_id": output["action_id"],
        "effect_id": output["effect_id"],
        "state_digest": output["state_digest"],
        "output_digest": payload["output_digest"],
        "status": payload["status"],
        "receipt_issued_at_unix_ms": payload["issued_at_unix_ms"],
        "receipt_expires_at_unix_ms": payload["expires_at_unix_ms"],
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "result": copy.deepcopy(output["result"]),
        "output": copy.deepcopy(output),
    }


def verify_retained_private_v3_projection(
    value: dict[str, Any],
    *,
    trusted_public_key_path: Path,
    expectation: dict[str, Any],
) -> dict[str, Any]:
    if value.get("schema_version") != PROJECTION_SCHEMA:
        raise ProtocolError("private_v3_projection_schema_invalid")
    if not isinstance(trusted_public_key_path, Path):
        raise ProtocolError("private_v3_trusted_key_missing")
    trusted_public_key = secure_read_file(
        trusted_public_key_path, max_bytes=32, owner_only=False
    )
    retained_public_key = b64url_decode(
        value.get("public_key_b64"), expected_length=32
    )
    trusted_fingerprint = "sha256:" + hashlib.sha256(trusted_public_key).hexdigest()
    if (
        retained_public_key != trusted_public_key
        or value.get("public_key_fingerprint") != trusted_fingerprint
    ):
        raise ProtocolError("private_v3_projection_key_invalid")
    verified = project_private_v3_output(
        value["output"],
        expectation=expectation,
        public_key_path=trusted_public_key_path,
        now_ms=value["verified_at_unix_ms"],
    )
    if verified != value:
        raise ProtocolError("private_v3_projection_mismatch")
    return verified
