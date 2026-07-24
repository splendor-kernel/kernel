#!/usr/bin/env python3
"""Strict private-v3 protocol primitives shared by acceptance fixtures only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


REQUEST_SCHEMA = "splendor.acceptance.action_provider.request.v3"
RECEIPT_PAYLOAD_SCHEMA = "splendor.acceptance.action_provider.receipt_payload.v3"
RECEIPT_ENVELOPE_SCHEMA = "splendor.acceptance.signed_envelope.v3"
EVIDENCE_PAYLOAD_SCHEMA = "splendor.acceptance.action_provider.evidence_payload.v3"
EVIDENCE_CREDENTIAL_SCHEMA = "splendor.acceptance.evidence_reader_credential.v3"
REQUEST_CREDENTIAL_SCHEMA = "splendor.acceptance.request_credential.v3"
REQUEST_KEYRING_SCHEMA = "splendor.acceptance.request_keyring.v3"
EVIDENCE_KEYRING_SCHEMA = "splendor.acceptance.evidence_reader_keyring.v3"
HEALTH_SCHEMA = "splendor.acceptance.action_provider.health.v3"
PROTOCOL_VERSION = "private-v3"
PROFILE_SCHEMA = "splendor.acceptance.operation_profiles.v3"
PROFILE_DIGEST_DOMAIN = b"splendor.acceptance.profile_set.v3\0"
OPERATION_DIGEST_DOMAIN = "splendor.acceptance.operation_profile.v3"
REQUEST_BODY_DIGEST_DOMAIN = "splendor.acceptance.request_body.v3"
REQUEST_SIGNATURE_DOMAIN = b"splendor.acceptance.request_hmac.v3\0"
IDEMPOTENCY_DOMAIN = "splendor.acceptance.idempotency.v3"
SEMANTIC_DOMAIN = "splendor.acceptance.semantic.v3"
EFFECT_DOMAIN = "splendor.acceptance.effect.v3"
STATE_DOMAIN = "splendor.acceptance.domain_state.v3"
OUTPUT_DOMAIN = b"splendor.acceptance.output.v3\0"
RECEIPT_ID_DOMAIN = "splendor.acceptance.receipt_id.v3"
RECEIPT_SIGNATURE_DOMAIN = b"splendor.acceptance.receipt_signature.v3\0"
EVIDENCE_SIGNATURE_DOMAIN = b"splendor.acceptance.evidence_signature.v3\0"
EVIDENCE_AUTH_DOMAIN = b"splendor.acceptance.evidence_reader_hmac.v3\0"
PROVIDER_ID = "acceptance-action-provider"
SIGNING_KEY_ID = "acceptance-action-provider-ed25519-v3"
TENANT_A = "11111111-1111-4111-8111-111111111111"
MANIFEST_PATH = Path(__file__).with_name("acceptance-operation-profiles.v3.json")
MANIFEST_DIGEST_PATH = Path(__file__).with_name(
    "acceptance-operation-profiles.v3.sha256"
)

REQUEST_FIELDS = {
    "schema_version",
    "protocol_version",
    "provider_id",
    "provider_revision",
    "provider_epoch",
    "audience",
    "request_key_id",
    "client_principal_id",
    "source_instance_id",
    "request_id",
    "tenant_id",
    "agent_id",
    "run_id",
    "tick_id",
    "action_id",
    "adapter_id",
    "action_name",
    "action_requested_at_unix_nanos",
    "action",
    "physical_action_resource_coordinate",
    "operation_id",
    "profile_set_digest",
    "operation_profile_digest",
    "idempotency_key",
    "semantic_digest",
    "issued_at_unix_ms",
    "deadline_unix_ms",
    "request_body_digest",
}
ACTION_FIELDS = {
    "name",
    "params",
    "side_effect_class",
    "cost_estimate",
    "required_permissions",
    "preconditions",
    "postconditions",
}
RESERVED_PARAMETER_FIELDS = {
    "endpoint",
    "url",
    "authorization",
    "credential",
    "secret",
    "adapter_id",
    "tenant_id",
    "agent_id",
    "run_id",
    "tick_id",
    "action_id",
    "node_id",
    "resource_coordinate",
    "provider_receipt",
    "signature_b64",
    "request_key_id",
    "provider_epoch",
}
SUPPORTED_PARAMETER_PROFILES = {
    "empty",
    "management_marker",
    "idempotent_read",
    "unsafe_failure",
    "artifact_create",
    "artifact_publish",
    "data_read",
    "physical",
}
SUPPORTED_OUTPUT_PROFILES = {
    "none",
    "marker",
    "fixture_read",
    "artifact_create",
    "artifact_publish",
    "data_read",
    "sql_read",
    "physical_battery",
    "physical_sensor",
    "physical_inspect",
    "physical_waypoint",
    "physical_image",
    "physical_return",
    "physical_trace_upload",
}
SUPPORTED_PRINCIPALS = {"local", "cloud", "vpc", "edge"}
SEMANTIC_RETRY_FIELDS = [
    "action_id",
    "request_id",
    "issued_at_unix_ms",
    "deadline_unix_ms",
    "action.params.retry_attempt",
]
SEMANTIC_RETRY_MARKER = {
    "initial": 1,
    "path": "action.params.retry_attempt",
    "reconciled": 2,
}
EXTERNAL_IDEMPOTENCY_IDENTITY_FIELD = "action.params.idempotency_key"
SUPPORTED_OPERATION_CONTRACTS = {
    ("none", "failure_recorded", "controlled_failure", "empty", "none", None),
    ("none", "failure_recorded", "controlled_failure", "unsafe_failure", "none", None),
    ("none", "message_routed", "forbidden", "empty", "none", None),
    ("marker", "marker_recorded", "execute", "empty", "none", "executed"),
    (
        "marker",
        "marker_recorded",
        "execute",
        "management_marker",
        "none",
        "executed",
    ),
    ("fixture_read", "fixture_read", "execute", "idempotent_read", "none", "read"),
    (
        "artifact_create",
        "artifact_created",
        "execute",
        "artifact_create",
        "none",
        "executed",
    ),
    (
        "artifact_publish",
        "artifact_published",
        "execute",
        "artifact_publish",
        "none",
        "executed",
    ),
    ("data_read", "data_read", "execute", "data_read", "none", "read"),
    ("sql_read", "fixture_read", "execute", "empty", "none", "read"),
    (
        "physical_battery",
        "sensor_read",
        "execute",
        "physical",
        "physical_node",
        "read",
    ),
    (
        "physical_sensor",
        "sensor_read",
        "execute",
        "physical",
        "physical_node",
        "read",
    ),
    (
        "physical_inspect",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        "executed",
    ),
    (
        "physical_waypoint",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        "executed",
    ),
    (
        "physical_image",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        "executed",
    ),
    (
        "physical_return",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        "executed",
    ),
    (
        "physical_trace_upload",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        "executed",
    ),
}


class ProtocolError(ValueError):
    """Closed protocol validation failure."""


def _reject_float(_: str) -> None:
    raise ProtocolError("floating_point_not_supported")


def _parse_int(raw: str) -> int:
    if raw == "-0":
        raise ProtocolError("negative_zero_not_supported")
    if len(raw) > 20 or (len(raw) == 20 and not raw.startswith("-")):
        raise ProtocolError("integer_out_of_range")
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise ProtocolError("integer_out_of_range") from error
    if value < -(2**63) or value > 2**63 - 1:
        raise ProtocolError("integer_out_of_range")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("duplicate_object_key")
        value[key] = item
    return value


def _validate_tree(
    value: Any,
    *,
    max_depth: int,
    max_fields: int,
    max_array_items: int,
    max_string_bytes: int,
) -> None:
    fields = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal fields
        if depth > max_depth:
            raise ProtocolError("json_depth_exceeded")
        if isinstance(item, str):
            try:
                encoded = item.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ProtocolError("json_string_not_unicode_scalar") from error
            if (
                len(encoded) > max_string_bytes
                or any(byte < 0x20 or byte > 0x7E for byte in encoded)
            ):
                raise ProtocolError("json_string_not_printable_ascii")
            return
        if item is None or isinstance(item, bool):
            return
        if type(item) is int:
            if item < -(2**63) or item > 2**63 - 1:
                raise ProtocolError("integer_out_of_range")
            return
        if isinstance(item, list):
            if len(item) > max_array_items:
                raise ProtocolError("json_array_items_exceeded")
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, dict):
            fields += len(item)
            if fields > max_fields:
                raise ProtocolError("json_fields_exceeded")
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        raise ProtocolError("unsupported_json_value")

    visit(value, 1)


def canonical_bytes(
    value: Any,
    *,
    max_depth: int = 16,
    max_fields: int = 256,
    max_array_items: int = 64,
    max_string_bytes: int = 2048,
) -> bytes:
    _validate_tree(
        value,
        max_depth=max_depth,
        max_fields=max_fields,
        max_array_items=max_array_items,
        max_string_bytes=max_string_bytes,
    )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def strict_loads(
    raw: bytes,
    *,
    max_bytes: int,
    max_depth: int = 16,
    max_fields: int = 256,
    max_array_items: int = 64,
    max_string_bytes: int = 2048,
    require_canonical: bool = True,
) -> Any:
    if not raw or len(raw) > max_bytes:
        raise ProtocolError("json_size_invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("json_not_utf8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError) as error:
        raise ProtocolError("invalid_json") from error
    try:
        _validate_tree(
            value,
            max_depth=max_depth,
            max_fields=max_fields,
            max_array_items=max_array_items,
            max_string_bytes=max_string_bytes,
        )
    except ProtocolError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ProtocolError("invalid_json_tree") from error
    if require_canonical and canonical_bytes(
        value,
        max_depth=max_depth,
        max_fields=max_fields,
        max_array_items=max_array_items,
        max_string_bytes=max_string_bytes,
    ) != raw:
        raise ProtocolError("json_not_canonical")
    return value


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int | None = None) -> bytes:
    if (
        not value
        or "=" in value
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value)
    ):
        raise ProtocolError("base64url_not_canonical")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ProtocolError("base64url_invalid") from error
    if b64url_encode(decoded) != value or (
        expected_length is not None and len(decoded) != expected_length
    ):
        raise ProtocolError("base64url_not_canonical")
    return decoded


def digest_bytes(domain: bytes, raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + raw).hexdigest()


def digest_value(domain: str, value: Any) -> str:
    return digest_bytes(domain.encode("ascii") + b"\0", canonical_bytes(value))


def output_digest(raw: bytes) -> str:
    return digest_bytes(OUTPUT_DOMAIN, raw)


def request_signature(key_id: str, body: bytes, key: bytes) -> str:
    if len(key) != 32:
        raise ProtocolError("request_key_length_invalid")
    frame = REQUEST_SIGNATURE_DOMAIN + key_id.encode("ascii") + b"\0" + body
    return b64url_encode(hmac.new(key, frame, hashlib.sha256).digest())


def evidence_auth_signature(value: dict[str, Any], key: bytes) -> str:
    if len(key) != 32:
        raise ProtocolError("evidence_key_length_invalid")
    frame = EVIDENCE_AUTH_DOMAIN + canonical_bytes(value)
    return b64url_encode(hmac.new(key, frame, hashlib.sha256).digest())


def secure_read_file(path: Path, *, max_bytes: int, owner_only: bool) -> bytes:
    parent = path.parent
    try:
        parent_stat = parent.stat(follow_symlinks=False)
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ProtocolError("secure_file_unavailable") from error
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or (hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid())
        or parent_stat.st_mode & 0o022
        or not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
        or (owner_only and before.st_mode & 0o077)
        or (not owner_only and before.st_mode & 0o022)
        or before.st_size <= 0
        or before.st_size > max_bytes
    ):
        raise ProtocolError("secure_file_metadata_invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise ProtocolError("secure_file_changed")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ProtocolError("secure_file_open_failed") from error
    if len(data) != before.st_size or len(data) > max_bytes:
        raise ProtocolError("secure_file_size_invalid")
    return data


@dataclass(frozen=True)
class OperationManifest:
    raw_bytes: bytes
    digest: str
    value: dict[str, Any]
    by_operation_id: dict[str, dict[str, Any]]
    by_pair: dict[tuple[str, str], dict[str, Any]]

    @property
    def limits(self) -> dict[str, int]:
        return self.value["limits"]

    @property
    def audience(self) -> str:
        return self.value["audience"]

    @property
    def provider_revision(self) -> str:
        return self.value["provider_revision"]

    def operation_digest(self, operation: dict[str, Any]) -> str:
        return digest_value(OPERATION_DIGEST_DOMAIN, operation)


def _exact_fields(value: dict[str, Any], expected: set[str], reason: str) -> None:
    if set(value) != expected:
        raise ProtocolError(reason)


def _sorted_unique_strings(values: Any, *, allowed: set[str] | None = None) -> bool:
    return (
        isinstance(values, list)
        and all(isinstance(value, str) for value in values)
        and values == sorted(set(values))
        and (allowed is None or set(values) <= allowed)
    )


def load_operation_manifest(
    manifest_path: Path = MANIFEST_PATH,
    digest_path: Path = MANIFEST_DIGEST_PATH,
) -> OperationManifest:
    raw = manifest_path.read_bytes()
    value = strict_loads(
        raw,
        max_bytes=131072,
        max_depth=16,
        max_fields=1024,
        max_array_items=64,
        max_string_bytes=2048,
        require_canonical=False,
    )
    if not isinstance(value, dict):
        raise ProtocolError("manifest_not_object")
    _exact_fields(
        value,
        {
            "schema_version",
            "protocol_version",
            "provider_id",
            "provider_revision",
            "profile_revision",
            "audience",
            "limits",
            "operations",
        },
        "manifest_fields_invalid",
    )
    if (
        value["schema_version"] != PROFILE_SCHEMA
        or value["protocol_version"] != PROTOCOL_VERSION
        or value["provider_id"] != PROVIDER_ID
        or not isinstance(value["provider_revision"], str)
        or value["profile_revision"] != "acceptance-operation-profile.v3"
        or value["audience"] != "splendor.acceptance.action-provider.v3"
    ):
        raise ProtocolError("manifest_identity_invalid")
    limits = value["limits"]
    if not isinstance(limits, dict):
        raise ProtocolError("manifest_limits_invalid")
    expected_limit_fields = {
        "max_active_requests",
        "max_array_items",
        "max_depth",
        "max_evidence_bytes",
        "max_evidence_nonces",
        "max_fields",
        "max_future_skew_ms",
        "max_ledger_entries",
        "max_output_bytes",
        "max_principal_active_requests",
        "max_principal_ledger_entries",
        "max_receipt_ttl_ms",
        "max_request_bytes",
        "max_request_ttl_ms",
        "max_response_bytes",
        "max_string_bytes",
    }
    _exact_fields(limits, expected_limit_fields, "manifest_limits_fields_invalid")
    if any(type(limits[field]) is not int or limits[field] <= 0 for field in limits):
        raise ProtocolError("manifest_limit_invalid")
    if (
        limits["max_active_requests"] != 16
        or limits["max_principal_active_requests"] != 4
        or limits["max_principal_ledger_entries"] != 64
        or limits["max_ledger_entries"] != 256
        or limits["max_evidence_nonces"] != 128
        or limits["max_request_bytes"] != 65536
        or limits["max_output_bytes"] != 32768
        or limits["max_response_bytes"] != 262144
        or limits["max_evidence_bytes"] != 262144
        or limits["max_request_ttl_ms"] != 10000
        or limits["max_future_skew_ms"] != 2000
        or limits["max_receipt_ttl_ms"] != 60000
    ):
        raise ProtocolError("manifest_required_limit_drift")
    operations = value["operations"]
    if not isinstance(operations, list) or len(operations) != 18:
        raise ProtocolError("manifest_operation_count_invalid")
    operation_fields = {
        "operation_id",
        "adapter_id",
        "action_name",
        "effect_class",
        "required_permissions",
        "parameter_profile",
        "coordinate_rule",
        "provider_mode",
        "idempotency",
        "expected_status",
        "output_profile",
        "postcondition",
        "bounds",
        "allowed_request_principals",
    }
    by_id: dict[str, dict[str, Any]] = {}
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for operation in operations:
        if not isinstance(operation, dict):
            raise ProtocolError("manifest_operation_invalid")
        _exact_fields(operation, operation_fields, "manifest_operation_fields_invalid")
        operation_id = operation["operation_id"]
        adapter_id = operation["adapter_id"]
        action_name = operation["action_name"]
        if (
            not all(isinstance(item, str) and item for item in (operation_id, adapter_id, action_name))
            or operation_id != f"{adapter_id}/{action_name}"
            or operation_id in by_id
            or (adapter_id, action_name) in by_pair
        ):
            raise ProtocolError("manifest_operation_identity_invalid")
        effect = operation["effect_class"]
        if effect not in ("External", "ReadOnly") and effect != {
            "Custom": "physical.high_level"
        }:
            raise ProtocolError("manifest_effect_class_unsupported")
        if not _sorted_unique_strings(operation["required_permissions"]):
            raise ProtocolError("manifest_permissions_invalid")
        if operation["parameter_profile"] not in SUPPORTED_PARAMETER_PROFILES:
            raise ProtocolError("manifest_parameter_profile_unsupported")
        if operation["output_profile"] not in SUPPORTED_OUTPUT_PROFILES:
            raise ProtocolError("manifest_output_profile_unsupported")
        if operation["coordinate_rule"] not in {"none", "physical_node"}:
            raise ProtocolError("manifest_coordinate_rule_unsupported")
        if operation["provider_mode"] not in {
            "execute",
            "controlled_failure",
            "forbidden",
        }:
            raise ProtocolError("manifest_provider_mode_unsupported")
        principals = operation["allowed_request_principals"]
        if not _sorted_unique_strings(principals, allowed=SUPPORTED_PRINCIPALS):
            raise ProtocolError("manifest_request_principals_invalid")
        if operation["provider_mode"] == "forbidden" and principals:
            raise ProtocolError("manifest_forbidden_operation_scoped")
        idempotency = operation["idempotency"]
        status = operation["expected_status"]
        bounds = operation["bounds"]
        if not isinstance(idempotency, dict) or not isinstance(status, dict) or not isinstance(bounds, dict):
            raise ProtocolError("manifest_nested_contract_invalid")
        _exact_fields(status, {"initial", "reconciled"}, "manifest_status_fields_invalid")
        _exact_fields(bounds, {"max_output_bytes", "max_array_items", "max_string_bytes", "max_integer_abs"}, "manifest_bounds_fields_invalid")
        if idempotency["mode"] == "semantic_retry":
            _exact_fields(
                idempotency,
                {
                    "external_idempotency_identity_field",
                    "mode",
                    "required_retry_marker",
                    "retry_varying_fields",
                },
                "manifest_idempotency_fields_invalid",
            )
            if (
                idempotency["retry_varying_fields"] != SEMANTIC_RETRY_FIELDS
                or idempotency["required_retry_marker"] != SEMANTIC_RETRY_MARKER
                or idempotency["external_idempotency_identity_field"]
                != EXTERNAL_IDEMPOTENCY_IDENTITY_FIELD
                or status["reconciled"] != "reconciled"
            ):
                raise ProtocolError("manifest_semantic_retry_invalid")
        elif idempotency["mode"] == "invocation":
            _exact_fields(
                idempotency,
                {"mode", "retry_varying_fields"},
                "manifest_idempotency_fields_invalid",
            )
            if idempotency["retry_varying_fields"] != [] or status["reconciled"] is not None:
                raise ProtocolError("manifest_invocation_idempotency_invalid")
        else:
            raise ProtocolError("manifest_idempotency_mode_unsupported")
        valid_status = {None, "executed", "read"}
        if status["initial"] not in valid_status:
            raise ProtocolError("manifest_status_unsupported")
        if operation["provider_mode"] == "execute" and status["initial"] is None:
            raise ProtocolError("manifest_success_status_missing")
        if operation["provider_mode"] != "execute" and status["initial"] is not None:
            raise ProtocolError("manifest_non_success_status_present")
        contract = (
            operation["output_profile"],
            operation["postcondition"],
            operation["provider_mode"],
            operation["parameter_profile"],
            operation["coordinate_rule"],
            status["initial"],
        )
        if contract not in SUPPORTED_OPERATION_CONTRACTS:
            raise ProtocolError("manifest_operation_contract_incoherent")
        if any(type(bounds[field]) is not int or bounds[field] <= 0 for field in bounds):
            raise ProtocolError("manifest_operation_bound_invalid")
        if bounds["max_output_bytes"] > limits["max_output_bytes"]:
            raise ProtocolError("manifest_output_bound_too_large")
        by_id[operation_id] = operation
        by_pair[(adapter_id, action_name)] = operation
    if [operation["operation_id"] for operation in operations] != sorted(by_id):
        raise ProtocolError("manifest_operations_not_sorted")
    computed = digest_bytes(PROFILE_DIGEST_DOMAIN, raw)
    expected = digest_path.read_text(encoding="ascii").strip()
    if computed != expected or not expected.startswith("sha256:") or len(expected) != 71:
        raise ProtocolError("manifest_digest_drift")
    return OperationManifest(raw, computed, value, by_id, by_pair)


OPERATION_MANIFEST = load_operation_manifest()


def _required_token(value: Any, reason: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("ascii", errors="ignore")) != len(value)
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ProtocolError(reason)
    return value


def _canonical_uuid(value: Any, reason: str) -> str:
    token = _required_token(value, reason, maximum=36)
    try:
        parsed = uuid.UUID(token)
    except ValueError as error:
        raise ProtocolError(reason) from error
    if parsed.int == 0 or str(parsed) != token:
        raise ProtocolError(reason)
    return token


def _contains_reserved(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            key in RESERVED_PARAMETER_FIELDS or _contains_reserved(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_reserved(child) for child in value)
    return False


def validate_parameters(
    profile: str, request: dict[str, Any], params: dict[str, Any]
) -> None:
    keys = set(params)
    tenant_id = request["tenant_id"]
    valid = False
    if profile == "empty":
        valid = not keys
    elif profile == "management_marker":
        valid = params == {"source": "uc-e2e-s2", "ok": True}
    elif profile == "idempotent_read":
        valid = (
            keys <= {"idempotency_key", "retry_attempt", "retryable", "max_attempts"}
            and isinstance(params.get("idempotency_key"), str)
            and 0 < len(params["idempotency_key"]) <= 256
            and ("retry_attempt" not in params or type(params["retry_attempt"]) is int and params["retry_attempt"] in {1, 2})
            and ("retryable" not in params or params["retryable"] is True)
            and ("max_attempts" not in params or params["max_attempts"] == 2)
        )
    elif profile == "unsafe_failure":
        valid = params == {
            "retry_attempt": 1,
            "retryable": False,
            "idempotency_key": None,
        }
    elif profile in {"artifact_create", "artifact_publish"}:
        field = "artifact_path" if profile == "artifact_create" else "publish_ref"
        resource = params.get(field)
        valid = (
            keys == {field}
            and isinstance(resource, str)
            and resource.startswith(f"artifact://{tenant_id}/")
            and len(resource) <= 512
            and ".." not in resource
        )
    elif profile == "data_read":
        data_ref = params.get("data_ref")
        valid = (
            keys == {"data_ref"}
            and tenant_id == TENANT_A
            and isinstance(data_ref, str)
            and data_ref.startswith("dataset:tenant-a.")
            and len(data_ref) <= 512
            and ".." not in data_ref
        )
    elif profile == "physical":
        valid = (
            keys <= {"physical_action", "cloud_helper_proposal_id", "cloud_helper_message_id"}
            and params.get("physical_action") is True
            and all(
                field not in params
                or isinstance(params[field], str)
                and 0 < len(params[field]) <= 256
                for field in ("cloud_helper_proposal_id", "cloud_helper_message_id")
            )
        )
    if not valid:
        raise ProtocolError("operation_params_invalid")


def _remove_material_path(value: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    parent: Any = value
    for part in parts[:-1]:
        if not isinstance(parent, dict) or part not in parent:
            raise ProtocolError("semantic_retry_path_missing")
        parent = parent[part]
    if not isinstance(parent, dict) or parent.pop(parts[-1], None) is None:
        raise ProtocolError("semantic_retry_path_missing")


def semantic_material(request: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    material = copy_json(request)
    for field in ("idempotency_key", "semantic_digest", "request_body_digest"):
        material.pop(field, None)
    if operation["idempotency"]["mode"] == "semantic_retry":
        for path in operation["idempotency"]["retry_varying_fields"]:
            _remove_material_path(material, path)
    return material


def idempotency_material(
    request: dict[str, Any], operation: dict[str, Any]
) -> dict[str, Any]:
    if operation["idempotency"]["mode"] == "semantic_retry":
        return {
            "request_key_id": request["request_key_id"],
            "operation_id": request["operation_id"],
            "external_idempotency_key": request["action"]["params"][
                "idempotency_key"
            ],
            "provider_epoch": request["provider_epoch"],
        }
    return semantic_material(request, operation)


def copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def request_resource_scope(
    request: dict[str, Any], operation: dict[str, Any]
) -> tuple[str, str, str] | None:
    operation_id = operation["operation_id"]
    if operation["coordinate_rule"] == "physical_node":
        coordinate = request["physical_action_resource_coordinate"]
        return operation_id, "physical_node", coordinate["node_id"]
    profile = operation["parameter_profile"]
    if profile == "artifact_create":
        return operation_id, "artifact_ref", request["action"]["params"]["artifact_path"]
    if profile == "artifact_publish":
        return operation_id, "artifact_ref", request["action"]["params"]["publish_ref"]
    if profile == "data_read":
        return operation_id, "data_ref", request["action"]["params"]["data_ref"]
    return None


def finalize_request(request: dict[str, Any]) -> dict[str, Any]:
    operation = OPERATION_MANIFEST.by_pair.get(
        (str(request.get("adapter_id")), str(request.get("action_name")))
    )
    if operation is None:
        raise ProtocolError("operation_profile_unknown")
    value = json.loads(json.dumps(request))
    value["operation_id"] = operation["operation_id"]
    value["profile_set_digest"] = OPERATION_MANIFEST.digest
    value["operation_profile_digest"] = OPERATION_MANIFEST.operation_digest(operation)
    value["semantic_digest"] = digest_value(
        SEMANTIC_DOMAIN, semantic_material(value, operation)
    )
    value["idempotency_key"] = digest_value(
        IDEMPOTENCY_DOMAIN, idempotency_material(value, operation)
    )
    unsigned = dict(value)
    unsigned.pop("request_body_digest", None)
    value["request_body_digest"] = digest_value(REQUEST_BODY_DIGEST_DOMAIN, unsigned)
    return value


def validate_request_payload(request: dict[str, Any]) -> dict[str, Any]:
    _exact_fields(request, REQUEST_FIELDS, "invalid_request_fields")
    if (
        request["schema_version"] != REQUEST_SCHEMA
        or request["protocol_version"] != PROTOCOL_VERSION
        or request["provider_id"] != PROVIDER_ID
        or request["provider_revision"] != OPERATION_MANIFEST.provider_revision
        or request["audience"] != OPERATION_MANIFEST.audience
        or request["profile_set_digest"] != OPERATION_MANIFEST.digest
    ):
        raise ProtocolError("invalid_protocol_identity")
    for field in ("tenant_id", "agent_id", "run_id", "action_id", "source_instance_id"):
        _canonical_uuid(request[field], f"invalid_{field}")
    if request["tenant_id"] != TENANT_A:
        raise ProtocolError("wrong_tenant")
    for field in (
        "provider_epoch",
        "request_key_id",
        "client_principal_id",
        "request_id",
        "adapter_id",
        "action_name",
        "action_requested_at_unix_nanos",
        "operation_id",
        "operation_profile_digest",
        "idempotency_key",
        "semantic_digest",
        "request_body_digest",
    ):
        _required_token(request[field], f"invalid_{field}")
    if request["tick_id"] is not None:
        _canonical_uuid(request["tick_id"], "invalid_tick_id")
    if type(request["issued_at_unix_ms"]) is not int or type(request["deadline_unix_ms"]) is not int:
        raise ProtocolError("invalid_request_time")
    operation = OPERATION_MANIFEST.by_pair.get(
        (request["adapter_id"], request["action_name"])
    )
    if operation is None or request["operation_id"] != operation["operation_id"]:
        raise ProtocolError("operation_profile_unknown")
    if request["operation_profile_digest"] != OPERATION_MANIFEST.operation_digest(operation):
        raise ProtocolError("operation_profile_digest_mismatch")
    action = request["action"]
    if not isinstance(action, dict):
        raise ProtocolError("invalid_action")
    _exact_fields(action, ACTION_FIELDS, "invalid_action_fields")
    if (
        action["name"] != request["action_name"]
        or action["side_effect_class"] != operation["effect_class"]
        or action["cost_estimate"] is not None
        or action["required_permissions"] != operation["required_permissions"]
        or action["preconditions"] != []
        or action["postconditions"] != [operation["postcondition"]]
        or not isinstance(action["params"], dict)
    ):
        raise ProtocolError("operation_profile_mismatch")
    if _contains_reserved(action["params"]):
        raise ProtocolError("operation_reserved_field")
    validate_parameters(operation["parameter_profile"], request, action["params"])
    coordinate = request["physical_action_resource_coordinate"]
    if operation["coordinate_rule"] == "physical_node":
        if not isinstance(coordinate, dict):
            raise ProtocolError("invalid_physical_resource_coordinate")
        _exact_fields(
            coordinate,
            {"resource_kind", "node_id"},
            "invalid_physical_resource_coordinate",
        )
        if coordinate["resource_kind"] != "physical_node":
            raise ProtocolError("invalid_physical_resource_coordinate")
        _canonical_uuid(coordinate["node_id"], "invalid_physical_resource_coordinate")
    elif coordinate is not None:
        raise ProtocolError("unexpected_physical_resource_coordinate")
    expected_semantic = digest_value(
        SEMANTIC_DOMAIN, semantic_material(request, operation)
    )
    expected_idempotency = digest_value(
        IDEMPOTENCY_DOMAIN, idempotency_material(request, operation)
    )
    unsigned = dict(request)
    supplied_body_digest = unsigned.pop("request_body_digest")
    expected_body_digest = digest_value(REQUEST_BODY_DIGEST_DOMAIN, unsigned)
    for supplied, expected, reason in (
        (request["semantic_digest"], expected_semantic, "semantic_digest_mismatch"),
        (request["idempotency_key"], expected_idempotency, "idempotency_key_mismatch"),
        (supplied_body_digest, expected_body_digest, "request_body_digest_mismatch"),
    ):
        if not hmac.compare_digest(supplied, expected):
            raise ProtocolError(reason)
    return operation


def load_closed_json_file(
    path: Path, *, max_bytes: int, owner_only: bool, schema: str
) -> dict[str, Any]:
    raw = secure_read_file(path, max_bytes=max_bytes, owner_only=owner_only)
    value = strict_loads(
        raw,
        max_bytes=max_bytes,
        max_depth=12,
        max_fields=512,
        max_array_items=64,
        max_string_bytes=2048,
        require_canonical=False,
    )
    if not isinstance(value, dict) or value.get("schema_version") != schema:
        raise ProtocolError("credential_schema_invalid")
    return value


def fixed_signing_frame(domain: bytes, payload: bytes) -> bytes:
    return domain + payload


def sign_with_callback(
    signer: Callable[[bytes], bytes], domain: bytes, payload: bytes
) -> str:
    signature = signer(fixed_signing_frame(domain, payload))
    if len(signature) != 64:
        raise ProtocolError("signer_output_invalid")
    return b64url_encode(signature)
