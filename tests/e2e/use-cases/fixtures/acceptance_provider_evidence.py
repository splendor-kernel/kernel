#!/usr/bin/env python3
"""Authenticated and signature-verifying private-v3 evidence reader."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import subprocess
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

from acceptance_provider_protocol import (
    EVIDENCE_CREDENTIAL_SCHEMA,
    EVIDENCE_PAYLOAD_SCHEMA,
    EVIDENCE_SIGNATURE_DOMAIN,
    HEALTH_SCHEMA,
    OPERATION_MANIFEST,
    PROVIDER_ID,
    PROTOCOL_VERSION,
    RECEIPT_ENVELOPE_SCHEMA,
    SIGNING_KEY_ID,
    ProtocolError,
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    evidence_auth_signature,
    fixed_signing_frame,
    load_closed_json_file,
    secure_read_file,
    strict_loads,
)


EVIDENCE_PATH = "/evidence?view=bounded"
EVIDENCE_AUDIENCE = "splendor.acceptance.action-provider.evidence.v3"
EVIDENCE_READER_KEY_ID = "acceptance-evidence-runner-v3"
EVIDENCE_READER_PRINCIPAL_ID = "acceptance-e2e-runner"
ENVELOPE_FIELDS = {
    "schema_version",
    "algorithm",
    "signing_key_id",
    "payload_encoding",
    "payload_b64",
    "signature_b64",
}
PAYLOAD_FIELDS = {
    "schema_version",
    "protocol_version",
    "provider_id",
    "provider_epoch",
    "provider_revision",
    "profile_set_digest",
    "request_binding",
    "snapshot_sequence",
    "snapshot_at_unix_ms",
    "expires_at_unix_ms",
    "total",
    "requests_total",
    "authenticated_requests",
    "successful",
    "failed",
    "duplicates",
    "effects_applied",
    "counts",
    "by_action",
    "by_adapter",
    "actions",
    "receipts",
    "effects",
    "artifacts",
    "devices",
    "markers",
    "read_evidence",
    "bounds",
}
REQUEST_BINDING_FIELDS = {
    "method",
    "path",
    "query",
    "view",
    "timestamp_unix_ms",
    "nonce",
    "audience",
    "key_id",
    "client_principal_id",
    "provider_epoch",
}
VERIFICATION_MATERIAL_FIELD = "_evidence_verification"
_SEQUENCE_LOCK = threading.Lock()
# This is bounded process-local replay detection, not durable cross-process state.
_LAST_SEQUENCES: OrderedDict[tuple[str, str, str], int] = OrderedDict()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _validate_base_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "http"
        or host not in {"127.0.0.1", "localhost", "acceptance-action-provider"}
        or parsed.port != 8086
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolError("evidence_endpoint_invalid")
    return raw.rstrip("/")


def _load_credential(path: Path) -> tuple[dict[str, Any], bytes]:
    value = load_closed_json_file(
        path, max_bytes=16384, owner_only=True, schema=EVIDENCE_CREDENTIAL_SCHEMA
    )
    fields = {
        "schema_version",
        "key_id",
        "status",
        "client_principal_id",
        "audience",
        "not_before_unix_ms",
        "expires_at_unix_ms",
        "max_request_age_ms",
        "secret_b64",
    }
    if (
        set(value) != fields
        or value["status"] != "active"
        or value["key_id"] != EVIDENCE_READER_KEY_ID
        or value["client_principal_id"] != EVIDENCE_READER_PRINCIPAL_ID
        or value["audience"] != EVIDENCE_AUDIENCE
        or value["max_request_age_ms"] != 5000
        or type(value["not_before_unix_ms"]) is not int
        or type(value["expires_at_unix_ms"]) is not int
        or value["expires_at_unix_ms"] <= value["not_before_unix_ms"]
    ):
        raise ProtocolError("evidence_credential_invalid")
    return value, b64url_decode(value["secret_b64"], expected_length=32)


def _validate_request_binding(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != REQUEST_BINDING_FIELDS:
        raise ProtocolError("evidence_request_binding_fields_invalid")
    try:
        epoch = str(uuid.UUID(value["provider_epoch"]))
        b64url_decode(value["nonce"], expected_length=16)
    except (AttributeError, TypeError, ValueError, ProtocolError) as error:
        raise ProtocolError("evidence_request_binding_invalid") from error
    if (
        value["method"] != "GET"
        or value["path"] != "/evidence"
        or value["query"] != "view=bounded"
        or value["view"] != "bounded"
        or value["audience"] != EVIDENCE_AUDIENCE
        or value["key_id"] != EVIDENCE_READER_KEY_ID
        or value["client_principal_id"] != EVIDENCE_READER_PRINCIPAL_ID
        or epoch != value["provider_epoch"]
        or uuid.UUID(epoch).int == 0
        or type(value["timestamp_unix_ms"]) is not int
        or value["timestamp_unix_ms"] <= 0
    ):
        raise ProtocolError("evidence_request_binding_invalid")


def _verifier_path() -> Path:
    configured = os.environ.get("SPLENDOR_ACCEPTANCE_SIGNATURE_VERIFIER")
    candidates = [] if configured is None else [Path(configured)]
    discovered = shutil.which("resident_auth_key_tool")
    if discovered:
        candidates.append(Path(discovered))
    root = Path(__file__).resolve().parents[4]
    candidates.extend(
        [
            root / "target/debug/examples/resident_auth_key_tool",
            root / "target/release/examples/resident_auth_key_tool",
        ]
    )
    for candidate in candidates:
        if candidate.is_absolute() and candidate.is_file():
            return candidate
    raise ProtocolError("signature_verifier_unavailable")


def _verify_with_ring(public_key_path: Path, signature: bytes, frame: bytes) -> None:
    verifier = _verifier_path()
    try:
        completed = subprocess.run(
            [str(verifier), "verify", str(public_key_path)],
            input=signature + frame,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProtocolError("signature_verifier_failed") from error
    if completed.returncode != 0:
        raise ProtocolError("evidence_signature_invalid")


def _read_exact_response(response: Any) -> bytes:
    lengths = response.headers.get_all("Content-Length", [])
    encodings = response.headers.get_all("Transfer-Encoding", [])
    content_types = response.headers.get_all("Content-Type", [])
    if len(lengths) != 1 or encodings or content_types != ["application/json"]:
        raise ProtocolError("evidence_http_framing_invalid")
    try:
        length = int(lengths[0])
    except ValueError as error:
        raise ProtocolError("evidence_content_length_invalid") from error
    maximum = OPERATION_MANIFEST.limits["max_evidence_bytes"]
    if length <= 0 or length > maximum:
        raise ProtocolError("evidence_content_length_invalid")
    raw = response.read(maximum + 1)
    if len(raw) != length or len(raw) > maximum:
        raise ProtocolError("evidence_response_size_invalid")
    return raw


def _read_health_epoch(base: str, client: Any) -> str:
    request = urllib.request.Request(
        base + "/health",
        headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        method="GET",
    )
    try:
        with client.open(request, timeout=5) as response:
            if response.status != 200 or response.geturl() != base + "/health":
                raise ProtocolError("evidence_health_status_invalid")
            lengths = response.headers.get_all("Content-Length", [])
            encodings = response.headers.get_all("Transfer-Encoding", [])
            content_types = response.headers.get_all("Content-Type", [])
            if len(lengths) != 1 or encodings or content_types != ["application/json"]:
                raise ProtocolError("evidence_health_framing_invalid")
            try:
                length = int(lengths[0])
            except ValueError as error:
                raise ProtocolError("evidence_health_length_invalid") from error
            if length <= 0 or length > 4096:
                raise ProtocolError("evidence_health_length_invalid")
            raw = response.read(4097)
            if len(raw) != length:
                raise ProtocolError("evidence_health_size_invalid")
    except urllib.error.HTTPError as error:
        error.read(4097)
        raise ProtocolError("evidence_health_unavailable") from error
    value = strict_loads(raw, max_bytes=4096, require_canonical=True)
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "protocol_version",
        "status",
        "provider_epoch",
        "profile_set_digest",
    }:
        raise ProtocolError("evidence_health_fields_invalid")
    try:
        epoch = str(uuid.UUID(value["provider_epoch"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ProtocolError("evidence_health_epoch_invalid") from error
    if (
        epoch != value["provider_epoch"]
        or value["schema_version"] != HEALTH_SCHEMA
        or value["protocol_version"] != PROTOCOL_VERSION
        or value["status"] != "ready"
        or value["profile_set_digest"] != OPERATION_MANIFEST.digest
    ):
        raise ProtocolError("evidence_health_identity_invalid")
    return epoch


def _contains_secret_shape(value: Any) -> bool:
    forbidden = {
        "secret",
        "secret_b64",
        "authorization",
        "token",
        "private_key",
        "signing_key",
        "request_signature",
        "evidence_signature",
    }
    if isinstance(value, dict):
        return any(
            str(key).lower() in forbidden or _contains_secret_shape(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_shape(child) for child in value)
    return False


def verify_evidence_envelope(
    raw: bytes,
    public_key_path: Path,
    *,
    request_binding: dict[str, Any],
    now_ms: int | None = None,
    verifier: Callable[[Path, bytes, bytes], None] | None = None,
    enforce_monotonic: bool = False,
    sequence_scope: str = "default",
) -> dict[str, Any]:
    maximum = OPERATION_MANIFEST.limits["max_evidence_bytes"]
    envelope = strict_loads(
        raw,
        max_bytes=maximum,
        max_string_bytes=maximum,
        require_canonical=True,
    )
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ProtocolError("evidence_envelope_fields_invalid")
    if (
        envelope["schema_version"] != RECEIPT_ENVELOPE_SCHEMA
        or envelope["algorithm"] != "Ed25519"
        or envelope["signing_key_id"] != SIGNING_KEY_ID
        or envelope["payload_encoding"] != "base64url"
    ):
        raise ProtocolError("evidence_envelope_identity_invalid")
    payload_raw = b64url_decode(envelope["payload_b64"])
    signature = b64url_decode(envelope["signature_b64"], expected_length=64)
    if len(payload_raw) > maximum:
        raise ProtocolError("evidence_payload_oversized")
    secure_read_file(public_key_path, max_bytes=32, owner_only=False)
    (verifier or _verify_with_ring)(
        public_key_path,
        signature,
        fixed_signing_frame(EVIDENCE_SIGNATURE_DOMAIN, payload_raw),
    )
    payload = strict_loads(
        payload_raw,
        max_bytes=maximum,
        max_fields=OPERATION_MANIFEST.limits["max_ledger_entries"] * 32,
        max_array_items=OPERATION_MANIFEST.limits["max_ledger_entries"],
        require_canonical=True,
    )
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise ProtocolError("evidence_payload_fields_invalid")
    _validate_request_binding(request_binding)
    current = int(time.time() * 1000) if now_ms is None else now_ms
    try:
        uuid.UUID(payload["provider_epoch"])
    except (ValueError, TypeError) as error:
        raise ProtocolError("evidence_epoch_invalid") from error
    if (
        payload["schema_version"] != EVIDENCE_PAYLOAD_SCHEMA
        or payload["protocol_version"] != "private-v3"
        or payload["provider_id"] != PROVIDER_ID
        or payload["provider_revision"] != OPERATION_MANIFEST.provider_revision
        or payload["profile_set_digest"] != OPERATION_MANIFEST.digest
        or payload["request_binding"] != request_binding
        or payload["provider_epoch"] != request_binding["provider_epoch"]
        or type(payload["snapshot_sequence"]) is not int
        or payload["snapshot_sequence"] <= 0
        or type(payload["snapshot_at_unix_ms"]) is not int
        or type(payload["expires_at_unix_ms"]) is not int
        or payload["snapshot_at_unix_ms"] > current + 2000
        or payload["expires_at_unix_ms"] <= current
        or payload["expires_at_unix_ms"] - payload["snapshot_at_unix_ms"] > 5000
    ):
        raise ProtocolError("evidence_payload_identity_or_freshness_invalid")
    maximum_rows = OPERATION_MANIFEST.limits["max_ledger_entries"]
    for field in ("actions", "receipts", "effects", "read_evidence"):
        if not isinstance(payload[field], list) or len(payload[field]) > maximum_rows:
            raise ProtocolError("evidence_collection_bound_invalid")
    for field in ("by_action", "by_adapter", "artifacts", "devices", "markers"):
        if not isinstance(payload[field], dict) or len(payload[field]) > maximum_rows:
            raise ProtocolError("evidence_collection_bound_invalid")
    count_fields = {
        "total",
        "requests_total",
        "authenticated_requests",
        "successful",
        "failed",
        "duplicates",
        "effects_applied",
    }
    if (
        not isinstance(payload["counts"], dict)
        or set(payload["counts"]) != count_fields
        or any(
            type(payload[field]) is not int
            or payload[field] < 0
            or payload["counts"][field] != payload[field]
            for field in count_fields
        )
    ):
        raise ProtocolError("evidence_counts_invalid")
    expected_bounds = {
        "max_ledger_entries": maximum_rows,
        "max_principal_ledger_entries": OPERATION_MANIFEST.limits[
            "max_principal_ledger_entries"
        ],
        "max_principal_active_requests": OPERATION_MANIFEST.limits[
            "max_principal_active_requests"
        ],
        "max_evidence_nonces": OPERATION_MANIFEST.limits["max_evidence_nonces"],
        "max_evidence_bytes": maximum,
    }
    if payload["bounds"] != expected_bounds or _contains_secret_shape(payload):
        raise ProtocolError("evidence_bounds_or_secret_shape_invalid")
    if enforce_monotonic:
        sequence_key = (
            sequence_scope,
            payload["provider_epoch"],
            request_binding["key_id"],
        )
        with _SEQUENCE_LOCK:
            previous = _LAST_SEQUENCES.get(sequence_key, 0)
            if payload["snapshot_sequence"] <= previous:
                raise ProtocolError("evidence_snapshot_sequence_replayed")
            _LAST_SEQUENCES[sequence_key] = payload["snapshot_sequence"]
            _LAST_SEQUENCES.move_to_end(sequence_key)
            while len(_LAST_SEQUENCES) > OPERATION_MANIFEST.limits["max_evidence_nonces"]:
                _LAST_SEQUENCES.popitem(last=False)
    return payload


def read_provider_evidence(
    base_url: str,
    *,
    credential_path: Path | None = None,
    public_key_path: Path | None = None,
    now_ms: int | None = None,
    nonce_bytes: bytes | None = None,
    opener: Any | None = None,
    verifier: Callable[[Path, bytes, bytes], None] | None = None,
) -> dict[str, Any]:
    base = _validate_base_url(base_url)
    credential_file = credential_path or Path(
        os.environ["SPLENDOR_ACCEPTANCE_EVIDENCE_CREDENTIAL_FILE"]
    )
    public_file = public_key_path or Path(
        os.environ["SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE"]
    )
    credential, secret = _load_credential(credential_file)
    client = opener or urllib.request.build_opener(_NoRedirect())
    provider_epoch = _read_health_epoch(base, client)
    timestamp = int(time.time() * 1000) if now_ms is None else now_ms
    if (
        timestamp < credential["not_before_unix_ms"]
        or timestamp >= credential["expires_at_unix_ms"]
    ):
        raise ProtocolError("evidence_credential_not_active")
    nonce = b64url_encode(nonce_bytes or secrets.token_bytes(16))
    if len(b64url_decode(nonce, expected_length=16)) != 16:
        raise ProtocolError("evidence_nonce_invalid")
    auth_value = {
        "method": "GET",
        "path": "/evidence",
        "query": "view=bounded",
        "view": "bounded",
        "timestamp_unix_ms": timestamp,
        "nonce": nonce,
        "audience": credential["audience"],
        "key_id": credential["key_id"],
        "client_principal_id": credential["client_principal_id"],
        "provider_epoch": provider_epoch,
    }
    headers = {
        "Accept": "application/json",
        "X-Splendor-Evidence-Key-Id": credential["key_id"],
        "X-Splendor-Evidence-Principal": credential["client_principal_id"],
        "X-Splendor-Evidence-Audience": credential["audience"],
        "X-Splendor-Evidence-Timestamp": str(timestamp),
        "X-Splendor-Evidence-Nonce": nonce,
        "X-Splendor-Evidence-Provider-Epoch": provider_epoch,
        "X-Splendor-Evidence-View": "bounded",
        "X-Splendor-Evidence-Signature": evidence_auth_signature(
            auth_value, secret
        ),
    }
    request = urllib.request.Request(
        base + EVIDENCE_PATH, headers=headers, method="GET"
    )
    try:
        with client.open(request, timeout=5) as response:
            if response.status != 200 or response.geturl() != base + EVIDENCE_PATH:
                raise ProtocolError("evidence_http_status_invalid")
            raw = _read_exact_response(response)
    except urllib.error.HTTPError as error:
        raw = error.read(OPERATION_MANIFEST.limits["max_evidence_bytes"] + 1)
        raise ProtocolError(
            f"evidence_read_denied_{error.code}_{len(raw)}"
        ) from error
    payload = verify_evidence_envelope(
        raw,
        public_file,
        request_binding=auth_value,
        now_ms=timestamp,
        verifier=verifier,
        enforce_monotonic=True,
        sequence_scope=base,
    )
    envelope = strict_loads(
        raw,
        max_bytes=OPERATION_MANIFEST.limits["max_evidence_bytes"],
        max_string_bytes=OPERATION_MANIFEST.limits["max_evidence_bytes"],
        require_canonical=True,
    )
    public_key = secure_read_file(public_file, max_bytes=32, owner_only=False)
    result = dict(payload)
    result[VERIFICATION_MATERIAL_FIELD] = {
        "envelope": envelope,
        "request_binding": auth_value,
        "public_key_b64": b64url_encode(public_key),
        "public_key_fingerprint": "sha256:" + hashlib.sha256(public_key).hexdigest(),
    }
    return result


def verify_retained_provider_evidence(
    value: dict[str, Any], *, trusted_public_key_path: Path
) -> dict[str, Any]:
    if not isinstance(trusted_public_key_path, Path):
        raise ProtocolError("retained_evidence_trusted_key_missing")
    material = value.get(VERIFICATION_MATERIAL_FIELD)
    if not isinstance(material, dict) or set(material) != {
        "envelope",
        "request_binding",
        "public_key_b64",
        "public_key_fingerprint",
    }:
        raise ProtocolError("retained_evidence_material_invalid")
    trusted_public_key = secure_read_file(
        trusted_public_key_path, max_bytes=32, owner_only=False
    )
    retained_public_key = b64url_decode(
        material["public_key_b64"], expected_length=32
    )
    trusted_fingerprint = "sha256:" + hashlib.sha256(trusted_public_key).hexdigest()
    if (
        retained_public_key != trusted_public_key
        or material["public_key_fingerprint"] != trusted_fingerprint
    ):
        raise ProtocolError("retained_evidence_key_fingerprint_invalid")
    request_binding = material["request_binding"]
    _validate_request_binding(request_binding)
    payload = verify_evidence_envelope(
        canonical_bytes(
            material["envelope"],
            max_string_bytes=OPERATION_MANIFEST.limits["max_evidence_bytes"],
        ),
        trusted_public_key_path,
        request_binding=request_binding,
        now_ms=request_binding["timestamp_unix_ms"],
    )
    expected = {
        key: item
        for key, item in value.items()
        if key != VERIFICATION_MATERIAL_FIELD
    }
    if payload != expected:
        raise ProtocolError("retained_evidence_snapshot_mismatch")
    return payload


def provider_effect_state(evidence: dict[str, Any]) -> dict[str, Any]:
    """Project signed evidence to state, excluding per-read freshness fields."""
    return {
        key: value
        for key, value in evidence.items()
        if key
        not in {
            "snapshot_at_unix_ms",
            "expires_at_unix_ms",
            "request_binding",
            "snapshot_sequence",
            VERIFICATION_MATERIAL_FIELD,
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-url", required=True)
    args = parser.parse_args()
    last_error: Exception | None = None
    for _ in range(40):
        try:
            evidence = read_provider_evidence(args.smoke_url)
            verify_retained_provider_evidence(
                evidence,
                trusted_public_key_path=Path(
                    os.environ["SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE"]
                ),
            )
            return 0
        except Exception as error:  # noqa: BLE001 - bounded startup retry
            last_error = error
            time.sleep(0.25)
    raise SystemExit(
        "private-v3 evidence credential/read/verification smoke failed: "
        + type(last_error).__name__
    )


if __name__ == "__main__":
    raise SystemExit(main())
