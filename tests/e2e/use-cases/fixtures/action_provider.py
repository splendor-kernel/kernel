#!/usr/bin/env python3
"""Bounded, authenticated private-v3 provider for acceptance only."""

from __future__ import annotations

import copy
import hmac
import hashlib
import os
import selectors
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable

from acceptance_provider_protocol import (
    EVIDENCE_AUTH_DOMAIN,
    EVIDENCE_KEYRING_SCHEMA,
    EVIDENCE_PAYLOAD_SCHEMA,
    EVIDENCE_SIGNATURE_DOMAIN,
    EFFECT_DOMAIN,
    HEALTH_SCHEMA,
    OPERATION_MANIFEST,
    PROTOCOL_VERSION,
    PROVIDER_ID,
    RECEIPT_ENVELOPE_SCHEMA,
    RECEIPT_ID_DOMAIN,
    RECEIPT_PAYLOAD_SCHEMA,
    RECEIPT_SIGNATURE_DOMAIN,
    REQUEST_KEYRING_SCHEMA,
    SIGNING_KEY_ID,
    STATE_DOMAIN,
    ProtocolError,
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    digest_value,
    evidence_auth_signature,
    fixed_signing_frame,
    load_closed_json_file,
    output_digest,
    request_signature,
    request_resource_scope,
    secure_read_file,
    sign_with_callback,
    strict_loads,
    validate_request_payload,
)


EVIDENCE_PATH = "/evidence?view=bounded"
EVIDENCE_AUDIENCE = "splendor.acceptance.action-provider.evidence.v3"
SOCKET_TIMEOUT_SECONDS = 2.0
SIGNER_TIMEOUT_SECONDS = 2.0
RUNTIME: ProviderRuntime | None = None


def _canonical_uuid_string(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


@dataclass(frozen=True)
class ProviderResponse:
    status: int
    body: bytes


@dataclass(frozen=True)
class RequestKey:
    key_id: str
    request_principal_role: str
    client_principal_id: str
    source_instance_id: str
    tenant_id: str
    audience: str
    not_before_unix_ms: int
    expires_at_unix_ms: int
    max_request_ttl_ms: int
    allowed_operation_ids: tuple[str, ...]
    allowed_resource_scopes: tuple[tuple[str, str, str], ...]
    secret: bytes
    provider_epoch: str


@dataclass(frozen=True)
class EvidenceKey:
    key_id: str
    client_principal_id: str
    audience: str
    not_before_unix_ms: int
    expires_at_unix_ms: int
    max_request_age_ms: int
    secret: bytes


class SubprocessSigner:
    def __init__(self, executable: Path, private_key: Path) -> None:
        self._executable = executable
        self._private_key = private_key
        self._executable_identity = self._validate_executable()
        self._private_key_identity = self._validate_private_key()

    @staticmethod
    def _identity(metadata: os.stat_result, digest: str) -> tuple[int | str, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            digest,
        )

    def _validate_executable(self) -> tuple[int | str, ...]:
        path = self._executable
        if not path.is_absolute():
            raise ProtocolError("signer_executable_invalid")
        try:
            parent = path.parent.stat(follow_symlinks=False)
            before = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ProtocolError("signer_executable_invalid") from error
        allowed_owners = {0, os.geteuid()} if hasattr(os, "geteuid") else {before.st_uid}
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid not in allowed_owners
            or parent.st_mode & 0o022
            or not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_uid not in allowed_owners
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_mode & 0o111 == 0
            or before.st_size <= 0
            or before.st_size > 64 * 1024 * 1024
        ):
            raise ProtocolError("signer_executable_invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino
                    or opened.st_nlink != 1
                ):
                    raise ProtocolError("signer_executable_changed")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise ProtocolError("signer_executable_invalid") from error
        return self._identity(before, digest.hexdigest())

    def _validate_private_key(self) -> tuple[int | str, ...]:
        raw = secure_read_file(self._private_key, max_bytes=256, owner_only=True)
        try:
            metadata = self._private_key.stat(follow_symlinks=False)
        except OSError as error:
            raise ProtocolError("signer_private_key_invalid") from error
        return self._identity(metadata, hashlib.sha256(raw).hexdigest())

    @staticmethod
    def _stop(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.kill()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def __call__(self, frame: bytes) -> bytes:
        if (
            self._validate_executable() != self._executable_identity
            or self._validate_private_key() != self._private_key_identity
        ):
            raise ProtocolError("signer_material_changed")
        try:
            process = subprocess.Popen(
                [str(self._executable), "sign", str(self._private_key)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as error:
            raise ProtocolError("signer_unavailable") from error
        assert process.stdin is not None and process.stdout is not None
        selector = selectors.DefaultSelector()
        output = bytearray()
        written = 0
        stdout_open = True
        deadline = time.monotonic() + SIGNER_TIMEOUT_SECONDS
        try:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while process.poll() is None or stdout_open:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProtocolError("signer_timeout")
                events = selector.select(min(remaining, 0.1))
                for selected, _ in events:
                    if selected.fileobj is process.stdin:
                        try:
                            count = os.write(process.stdin.fileno(), frame[written:])
                        except BrokenPipeError:
                            count = 0
                        written += count
                        if written == len(frame) or count == 0:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 65 - len(output))
                        if chunk:
                            output.extend(chunk)
                            if len(output) > 64:
                                raise ProtocolError("signer_output_oversized")
                        else:
                            selector.unregister(process.stdout)
                            stdout_open = False
            return_code = process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProtocolError("signer_unavailable") from error
        finally:
            selector.close()
            self._stop(process)
            process.stdin.close()
            process.stdout.close()
        if return_code != 0 or len(output) != 64:
            raise ProtocolError("signer_failed")
        return bytes(output)


def _closed_error(reason: str, *, request_digest: str | None = None) -> bytes:
    value: dict[str, Any] = {
        "schema_version": "splendor.acceptance.action_provider.error.v3",
        "error": reason,
    }
    if request_digest is not None:
        value["request_body_digest"] = request_digest
    return canonical_bytes(value)


def _initial_state(epoch: str) -> dict[str, Any]:
    return {
        "schema_version": "splendor.acceptance.action_provider.state.v3",
        "provider_epoch": epoch,
        "total": 0,
        "requests_total": 0,
        "authenticated_requests": 0,
        "successful": 0,
        "failed": 0,
        "duplicates": 0,
        "effects_applied": 0,
        "by_action": {},
        "by_adapter": {},
        "invocations": {},
        "idempotency": {},
        "effects": {},
        "actions": [],
        "receipts": [],
        "artifacts": {},
        "devices": {},
        "markers": {},
        "read_evidence": [],
        "evidence_nonces": {},
        "snapshot_sequence": 0,
    }


def _load_request_keys(path: Path, epoch: str) -> dict[str, RequestKey]:
    value = load_closed_json_file(
        path, max_bytes=65536, owner_only=True, schema=REQUEST_KEYRING_SCHEMA
    )
    if set(value) != {"schema_version", "profile_set_digest", "keys"}:
        raise ProtocolError("request_keyring_fields_invalid")
    if value["profile_set_digest"] != OPERATION_MANIFEST.digest:
        raise ProtocolError("request_keyring_manifest_drift")
    keys = value["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 4:
        raise ProtocolError("request_keyring_count_invalid")
    result: dict[str, RequestKey] = {}
    request_secrets: set[bytes] = set()
    expected_fields = {
        "key_id",
        "status",
        "request_principal_role",
        "client_principal_id",
        "source_instance_id",
        "tenant_id",
        "audience",
        "not_before_unix_ms",
        "expires_at_unix_ms",
        "max_request_ttl_ms",
        "allowed_operation_ids",
        "allowed_resource_scopes",
        "secret_b64",
    }
    for item in keys:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise ProtocolError("request_keyring_entry_fields_invalid")
        role = item["request_principal_role"]
        allowed = item["allowed_operation_ids"]
        expected_allowed = sorted(
            operation["operation_id"]
            for operation in OPERATION_MANIFEST.value["operations"]
            if role in operation["allowed_request_principals"]
        )
        if (
            role not in {"local", "cloud", "vpc", "edge"}
            or item["status"] != "active"
            or item["tenant_id"] != "11111111-1111-4111-8111-111111111111"
            or item["audience"] != OPERATION_MANIFEST.audience
            or item["max_request_ttl_ms"]
            != OPERATION_MANIFEST.limits["max_request_ttl_ms"]
            or allowed != expected_allowed
            or allowed != sorted(set(allowed))
            or type(item["not_before_unix_ms"]) is not int
            or type(item["expires_at_unix_ms"]) is not int
            or item["expires_at_unix_ms"] <= item["not_before_unix_ms"]
            or item["key_id"] in result
        ):
            raise ProtocolError("request_keyring_entry_invalid")
        secret = b64url_decode(item["secret_b64"], expected_length=32)
        if secret in request_secrets:
            raise ProtocolError("request_keyring_secret_reused")
        request_secrets.add(secret)
        resource_scopes = item["allowed_resource_scopes"]
        if not isinstance(resource_scopes, list):
            raise ProtocolError("request_keyring_resource_scopes_invalid")
        parsed_scopes: list[tuple[str, str, str]] = []
        for scope in resource_scopes:
            if not isinstance(scope, dict) or set(scope) != {
                "operation_id",
                "resource_kind",
                "resource_id",
            }:
                raise ProtocolError("request_keyring_resource_scope_invalid")
            operation = OPERATION_MANIFEST.by_operation_id.get(scope["operation_id"])
            expected_kind = None
            if operation is not None:
                if operation["coordinate_rule"] == "physical_node":
                    expected_kind = "physical_node"
                elif operation["parameter_profile"] in {
                    "artifact_create",
                    "artifact_publish",
                }:
                    expected_kind = "artifact_ref"
                elif operation["parameter_profile"] == "data_read":
                    expected_kind = "data_ref"
            resource_id = scope["resource_id"]
            if (
                operation is None
                or operation["operation_id"] not in allowed
                or scope["resource_kind"] != expected_kind
                or not isinstance(resource_id, str)
                or not resource_id
                or len(resource_id) > 512
                or ".." in resource_id
                or expected_kind == "physical_node"
                and not _canonical_uuid_string(resource_id)
                or expected_kind == "artifact_ref"
                and not resource_id.startswith(f"artifact://{item['tenant_id']}/")
                or expected_kind == "data_ref"
                and not resource_id.startswith("dataset:tenant-a.")
            ):
                raise ProtocolError("request_keyring_resource_scope_invalid")
            parsed_scopes.append(
                (scope["operation_id"], scope["resource_kind"], resource_id)
            )
        resource_operations = {
            operation_id
            for operation_id in allowed
            if (
                OPERATION_MANIFEST.by_operation_id[operation_id]["coordinate_rule"]
                == "physical_node"
                or OPERATION_MANIFEST.by_operation_id[operation_id]["parameter_profile"]
                in {"artifact_create", "artifact_publish", "data_read"}
            )
        }
        if (
            parsed_scopes != sorted(set(parsed_scopes))
            or {scope[0] for scope in parsed_scopes} != resource_operations
        ):
            raise ProtocolError("request_keyring_resource_scopes_invalid")
        result[item["key_id"]] = RequestKey(
            key_id=item["key_id"],
            request_principal_role=role,
            client_principal_id=item["client_principal_id"],
            source_instance_id=item["source_instance_id"],
            tenant_id=item["tenant_id"],
            audience=item["audience"],
            not_before_unix_ms=item["not_before_unix_ms"],
            expires_at_unix_ms=item["expires_at_unix_ms"],
            max_request_ttl_ms=item["max_request_ttl_ms"],
            allowed_operation_ids=tuple(allowed),
            allowed_resource_scopes=tuple(parsed_scopes),
            secret=secret,
            provider_epoch=epoch,
        )
    if len({key.request_principal_role for key in result.values()}) != len(result):
        raise ProtocolError("request_keyring_roles_invalid")
    return result


def _load_evidence_keys(path: Path) -> dict[str, EvidenceKey]:
    value = load_closed_json_file(
        path, max_bytes=16384, owner_only=True, schema=EVIDENCE_KEYRING_SCHEMA
    )
    if set(value) != {"schema_version", "keys"}:
        raise ProtocolError("evidence_keyring_fields_invalid")
    keys = value["keys"]
    if not isinstance(keys, list) or len(keys) != 1:
        raise ProtocolError("evidence_keyring_count_invalid")
    item = keys[0]
    expected_fields = {
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
        not isinstance(item, dict)
        or set(item) != expected_fields
        or item["status"] != "active"
        or item["client_principal_id"] != "acceptance-e2e-runner"
        or item["audience"] != EVIDENCE_AUDIENCE
        or item["max_request_age_ms"] != 5000
        or type(item["not_before_unix_ms"]) is not int
        or type(item["expires_at_unix_ms"]) is not int
        or item["expires_at_unix_ms"] <= item["not_before_unix_ms"]
    ):
        raise ProtocolError("evidence_keyring_entry_invalid")
    key = EvidenceKey(
        key_id=item["key_id"],
        client_principal_id=item["client_principal_id"],
        audience=item["audience"],
        not_before_unix_ms=item["not_before_unix_ms"],
        expires_at_unix_ms=item["expires_at_unix_ms"],
        max_request_age_ms=item["max_request_age_ms"],
        secret=b64url_decode(item["secret_b64"], expected_length=32),
    )
    return {key.key_id: key}


def _validate_key_separation(
    request_keys: dict[str, RequestKey], evidence_keys: dict[str, EvidenceKey]
) -> None:
    request_secrets = [key.secret for key in request_keys.values()]
    evidence_secrets = {key.secret for key in evidence_keys.values()}
    if len(request_secrets) != len(set(request_secrets)):
        raise ProtocolError("request_keyring_secret_reused")
    if set(request_secrets) & evidence_secrets:
        raise ProtocolError("request_evidence_secret_reused")


class ProviderRuntime:
    def __init__(
        self,
        request_keys: dict[str, RequestKey],
        evidence_keys: dict[str, EvidenceKey],
        signer: Callable[[bytes], bytes],
        *,
        epoch: str | None = None,
    ) -> None:
        _validate_key_separation(request_keys, evidence_keys)
        self.epoch = epoch or str(uuid.uuid4())
        uuid.UUID(self.epoch)
        self.request_keys = {
            key_id: RequestKey(**{**key.__dict__, "provider_epoch": self.epoch})
            for key_id, key in request_keys.items()
        }
        self.evidence_keys = evidence_keys
        self.signer = signer
        self.state = _initial_state(self.epoch)
        self.lock = threading.Lock()
        self._principal_admission = {
            key.client_principal_id: threading.BoundedSemaphore(
                OPERATION_MANIFEST.limits["max_principal_active_requests"]
            )
            for key in self.request_keys.values()
        }

    @classmethod
    def load(
        cls,
        request_keyring: Path,
        evidence_keyring: Path,
        signer_executable: Path,
        signing_key: Path,
    ) -> ProviderRuntime:
        epoch = str(uuid.uuid4())
        request_keys = _load_request_keys(request_keyring, epoch)
        evidence_keys = _load_evidence_keys(evidence_keyring)
        _validate_key_separation(request_keys, evidence_keys)
        return cls(
            request_keys,
            evidence_keys,
            SubprocessSigner(signer_executable, signing_key),
            epoch=epoch,
        )

    def health(self) -> ProviderResponse:
        return ProviderResponse(
            200,
            canonical_bytes(
                {
                    "schema_version": HEALTH_SCHEMA,
                    "protocol_version": PROTOCOL_VERSION,
                    "status": "ready",
                    "provider_epoch": self.epoch,
                    "profile_set_digest": OPERATION_MANIFEST.digest,
                }
            ),
        )

    def _authenticate_action(
        self,
        body: bytes,
        key_id: str,
        signature: str,
        now_ms: int,
    ) -> tuple[dict[str, Any], dict[str, Any], RequestKey]:
        limits = OPERATION_MANIFEST.limits
        if not body or len(body) > limits["max_request_bytes"]:
            raise ProtocolError("request_size_invalid")
        key = self.request_keys.get(key_id)
        if key is None or not hmac.compare_digest(
            signature, request_signature(key_id, body, key.secret)
        ):
            raise ProtocolError("request_authentication_failed")
        request = strict_loads(
            body,
            max_bytes=limits["max_request_bytes"],
            max_depth=limits["max_depth"],
            max_fields=limits["max_fields"],
            max_array_items=limits["max_array_items"],
            max_string_bytes=limits["max_string_bytes"],
            require_canonical=True,
        )
        if not isinstance(request, dict):
            raise ProtocolError("request_not_object")
        operation = validate_request_payload(request)
        if (
            request["request_key_id"] != key.key_id
            or request["client_principal_id"] != key.client_principal_id
            or request["source_instance_id"] != key.source_instance_id
            or request["tenant_id"] != key.tenant_id
            or request["audience"] != key.audience
            or request["provider_epoch"] != key.provider_epoch
            or operation["operation_id"] not in key.allowed_operation_ids
            or key.request_principal_role
            not in operation["allowed_request_principals"]
            or operation["provider_mode"] == "forbidden"
        ):
            raise ProtocolError("request_scope_denied")
        resource_scope = request_resource_scope(request, operation)
        if resource_scope is not None and resource_scope not in key.allowed_resource_scopes:
            raise ProtocolError("request_resource_scope_denied")
        issued = request["issued_at_unix_ms"]
        deadline = request["deadline_unix_ms"]
        if (
            now_ms < key.not_before_unix_ms
            or now_ms >= key.expires_at_unix_ms
            or issued < key.not_before_unix_ms
            or deadline > key.expires_at_unix_ms
            or issued > now_ms + limits["max_future_skew_ms"]
            or deadline <= now_ms
            or deadline <= issued
            or deadline - issued > key.max_request_ttl_ms
            or now_ms - issued > key.max_request_ttl_ms
        ):
            raise ProtocolError("request_freshness_denied")
        return request, operation, key

    def handle_action(
        self,
        body: bytes,
        key_id: str,
        signature: str,
        *,
        now_ms: int | None = None,
    ) -> ProviderResponse:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        try:
            request, operation, key = self._authenticate_action(
                body, key_id, signature, now
            )
        except ProtocolError as error:
            return ProviderResponse(401, _closed_error(str(error)))
        admission = self._principal_admission[key.client_principal_id]
        if not admission.acquire(blocking=False):
            return ProviderResponse(
                503, _closed_error("provider_principal_concurrency_exhausted")
            )
        try:
            return self._process_authenticated(request, operation, key, now)
        finally:
            admission.release()

    def _has_capacity(
        self,
        *,
        invocations: int = 0,
        idempotency: int = 0,
        effects: int = 0,
        actions: int = 0,
        receipts: int = 0,
        domain: tuple[str, str | None] | None = None,
    ) -> bool:
        maximum = OPERATION_MANIFEST.limits["max_ledger_entries"]
        state = self.state
        checks = (
            (len(state["invocations"]), invocations),
            (len(state["idempotency"]), idempotency),
            (len(state["effects"]), effects),
            (len(state["actions"]), actions),
            (len(state["receipts"]), receipts),
        )
        if any(current + added > maximum for current, added in checks):
            return False
        if domain is None:
            return True
        collection, key = domain
        target = state[collection]
        if isinstance(target, list):
            return len(target) + 1 <= maximum
        return key in target or len(target) + 1 <= maximum

    def _has_principal_capacity(
        self,
        client_principal_id: str,
        *,
        invocations: int = 0,
        idempotency: int = 0,
        effects: int = 0,
        actions: int = 0,
        receipts: int = 0,
    ) -> bool:
        maximum = OPERATION_MANIFEST.limits["max_principal_ledger_entries"]

        def count(collection: str) -> int:
            target = self.state[collection]
            values = target.values() if isinstance(target, dict) else target
            return sum(
                1
                for value in values
                if isinstance(value, dict)
                and value.get("client_principal_id") == client_principal_id
            )

        return all(
            current + added <= maximum
            for current, added in (
                (count("invocations"), invocations),
                (count("idempotency"), idempotency),
                (count("effects"), effects),
                (count("actions"), actions),
                (count("receipts"), receipts),
            )
        )

    def _cached(self, request_digest: str) -> ProviderResponse | None:
        cached = self.state["invocations"].get(request_digest)
        if cached is None:
            return None
        self.state["requests_total"] += 1
        self.state["total"] += 1
        self.state["authenticated_requests"] += 1
        self.state["duplicates"] += 1
        if 200 <= cached["status"] < 300:
            self.state["successful"] += 1
        else:
            self.state["failed"] += 1
        return ProviderResponse(cached["status"], cached["body"])

    def _process_authenticated(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        key: RequestKey,
        now_ms: int,
    ) -> ProviderResponse:
        request_digest = request["request_body_digest"]
        with self.lock:
            cached = self._cached(request_digest)
            if cached is not None:
                return cached
            idempotency_key = request["idempotency_key"]
            existing = self.state["idempotency"].get(idempotency_key)
            if existing is not None and existing["semantic_digest"] != request["semantic_digest"]:
                return ProviderResponse(
                    409,
                    _closed_error(
                        "idempotency_semantic_conflict",
                        request_digest=request_digest,
                    ),
                )
            if operation["provider_mode"] == "controlled_failure":
                return self._controlled_failure(request, operation, key)
            retry_attempt = request["action"]["params"].get("retry_attempt", 1)
            semantic_retry = operation["idempotency"]["mode"] == "semantic_retry"
            retry_marker = operation["idempotency"].get("required_retry_marker")
            reconciled_attempt = (
                retry_marker["reconciled"] if semantic_retry else None
            )
            if semantic_retry and retry_attempt == reconciled_attempt and existing is None:
                return ProviderResponse(
                    409,
                    _closed_error("semantic_retry_without_effect", request_digest=request_digest),
                )
            if semantic_retry and existing is not None:
                if existing.get("reconciled_request_digest") is not None:
                    return ProviderResponse(
                        409,
                        _closed_error(
                            "semantic_retry_already_reconciled",
                            request_digest=request_digest,
                        ),
                    )
                return self._reconcile(request, operation, key, existing, now_ms)
            if existing is not None:
                return ProviderResponse(
                    409,
                    _closed_error("idempotency_reuse_conflict", request_digest=request_digest),
                )
            return self._execute_new(request, operation, key, now_ms)

    def _controlled_failure(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        key: RequestKey,
    ) -> ProviderResponse:
        if not self._has_capacity(invocations=1, actions=1):
            return ProviderResponse(503, _closed_error("provider_capacity_exhausted"))
        if not self._has_principal_capacity(
            key.client_principal_id, invocations=1, actions=1
        ):
            return ProviderResponse(
                503, _closed_error("provider_principal_capacity_exhausted")
            )
        body = canonical_bytes(
            {
                "schema_version": "splendor.acceptance.action_provider.error.v3",
                "error": "controlled_acceptance_provider_failure",
                "operation_id": operation["operation_id"],
                "action_id": request["action_id"],
                "request_body_digest": request["request_body_digest"],
            }
        )
        if len(body) > OPERATION_MANIFEST.limits["max_response_bytes"]:
            return ProviderResponse(503, _closed_error("provider_response_oversized"))
        row = self._action_row(request, None, None, None, "failed", False)
        self.state["invocations"][request["request_body_digest"]] = {
            "status": 503,
            "body": body,
            "client_principal_id": key.client_principal_id,
        }
        self.state["actions"].append(row)
        self._increment(request, successful=False)
        return ProviderResponse(503, body)

    def _domain_result(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        effect_id: str,
    ) -> tuple[dict[str, Any], tuple[str, str | None, Any]]:
        profile = operation["output_profile"]
        params = request["action"]["params"]
        coordinate = request["physical_action_resource_coordinate"]
        if profile == "marker":
            result = {
                "tenant_id": request["tenant_id"],
                "run_id": request["run_id"],
                "action_id": request["action_id"],
                "action_name": request["action_name"],
                "effect_id": effect_id,
            }
            return result, ("markers", effect_id, result)
        if profile == "fixture_read":
            result = {"fixture": "s9-idempotent-read", "record_count": 1}
            return result, ("read_evidence", None, result)
        if profile == "sql_read":
            result = {"row_count": 1, "rows": [{"fixture": 1}]}
            return result, ("read_evidence", None, result)
        if profile == "data_read":
            result = {
                "data_ref": params["data_ref"],
                "tenant_id": request["tenant_id"],
                "raw_payload_included": False,
                "record_count": 3,
            }
            return result, ("read_evidence", None, result)
        if profile in {"artifact_create", "artifact_publish"}:
            field = "artifact_path" if profile == "artifact_create" else "publish_ref"
            reference = params[field]
            result = {
                "artifact_ref": reference,
                "tenant_id": request["tenant_id"],
                "created": True,
                "published": profile == "artifact_publish",
                "external_store": (
                    "acceptance-action-provider-v3"
                    if profile == "artifact_publish"
                    else None
                ),
            }
            return result, ("artifacts", reference, result)
        node_id = coordinate["node_id"]
        device = copy.deepcopy(
            self.state["devices"].get(
                node_id,
                {
                    "node_id": node_id,
                    "images_captured": 0,
                    "trace_summaries_uploaded": 0,
                    "at_base": False,
                },
            )
        )
        if profile == "physical_battery":
            result = {"coordinate": coordinate, "battery_milli_percent": 820}
            mutation: tuple[str, str | None, Any] = ("read_evidence", None, result)
        elif profile == "physical_sensor":
            result = {
                "coordinate": coordinate,
                "battery_milli_percent": 820,
                "sensor_status": "nominal",
            }
            mutation = ("read_evidence", None, result)
        elif profile == "physical_inspect":
            result = {"coordinate": coordinate, "inspected_zone": "zone:warehouse-a3"}
            mutation = ("devices", node_id, device)
        elif profile == "physical_waypoint":
            result = {"coordinate": coordinate, "waypoint": "waypoint:warehouse-a3"}
            mutation = ("devices", node_id, device)
        elif profile == "physical_image":
            device["images_captured"] += 1
            result = {"coordinate": coordinate, "images_captured": device["images_captured"]}
            mutation = ("devices", node_id, device)
        elif profile == "physical_return":
            device["at_base"] = True
            result = {"coordinate": coordinate, "at_base": True}
            mutation = ("devices", node_id, device)
        elif profile == "physical_trace_upload":
            device["trace_summaries_uploaded"] += 1
            result = {
                "coordinate": coordinate,
                "trace_summaries_uploaded": device["trace_summaries_uploaded"],
            }
            mutation = ("devices", node_id, device)
        else:
            raise ProtocolError("output_profile_not_executable")
        return result, mutation

    def _output(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        effect_id: str,
    ) -> tuple[dict[str, Any], bytes, str, tuple[str, str | None, Any]]:
        result, mutation = self._domain_result(request, operation, effect_id)
        state_digest = digest_value(STATE_DOMAIN, result)
        output = {
            "operation_id": operation["operation_id"],
            "proof_type": operation["output_profile"],
            "tenant_id": request["tenant_id"],
            "action_id": request["action_id"],
            "effect_id": effect_id,
            "state_digest": state_digest,
            "result": result,
        }
        raw = canonical_bytes(
            output,
            max_depth=OPERATION_MANIFEST.limits["max_depth"],
            max_fields=OPERATION_MANIFEST.limits["max_fields"],
            max_array_items=operation["bounds"]["max_array_items"],
            max_string_bytes=operation["bounds"]["max_string_bytes"],
        )
        if len(raw) > operation["bounds"]["max_output_bytes"]:
            raise ProtocolError("operation_output_oversized")
        return output, raw, state_digest, mutation

    def _receipt(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        key: RequestKey,
        output: dict[str, Any],
        output_raw: bytes,
        state_digest: str,
        effect_id: str,
        status: str,
        now_ms: int,
    ) -> tuple[str, bytes, dict[str, Any]]:
        receipt_id = digest_value(
            RECEIPT_ID_DOMAIN,
            {
                "provider_epoch": self.epoch,
                "idempotency_key": request["idempotency_key"],
                "request_body_digest": request["request_body_digest"],
                "status": status,
            },
        )
        output_hash = output_digest(output_raw)
        expires = now_ms + OPERATION_MANIFEST.limits["max_receipt_ttl_ms"]
        payload = {
            "schema_version": RECEIPT_PAYLOAD_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "provider_id": PROVIDER_ID,
            "provider_revision": OPERATION_MANIFEST.provider_revision,
            "provider_epoch": self.epoch,
            "provider_receipt_id": receipt_id,
            "request_body_digest": request["request_body_digest"],
            "request_key_id": key.key_id,
            "client_principal_id": key.client_principal_id,
            "source_instance_id": key.source_instance_id,
            "audience": key.audience,
            "request_id": request["request_id"],
            "tenant_id": request["tenant_id"],
            "agent_id": request["agent_id"],
            "run_id": request["run_id"],
            "tick_id": request["tick_id"],
            "action_id": request["action_id"],
            "adapter_id": request["adapter_id"],
            "action_name": request["action_name"],
            "physical_action_resource_coordinate": request[
                "physical_action_resource_coordinate"
            ],
            "operation_id": operation["operation_id"],
            "profile_set_digest": OPERATION_MANIFEST.digest,
            "operation_profile_digest": request["operation_profile_digest"],
            "idempotency_key": request["idempotency_key"],
            "semantic_digest": request["semantic_digest"],
            "request_issued_at_unix_ms": request["issued_at_unix_ms"],
            "request_deadline_unix_ms": request["deadline_unix_ms"],
            "status": status,
            "effect_certainty": "known",
            "effect_id": effect_id,
            "state_digest": state_digest,
            "output_profile": operation["output_profile"],
            "output_b64": b64url_encode(output_raw),
            "output_digest": output_hash,
            "satisfied_postconditions": [operation["postcondition"]],
            "postcondition_proof": {
                "operation_id": operation["operation_id"],
                "predicate": operation["postcondition"],
                "effect_id": effect_id,
                "state_digest": state_digest,
                "output_digest": output_hash,
            },
            "issued_at_unix_ms": now_ms,
            "expires_at_unix_ms": expires,
        }
        payload_raw = canonical_bytes(
            payload,
            max_string_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        )
        envelope = {
            "schema_version": RECEIPT_ENVELOPE_SCHEMA,
            "algorithm": "Ed25519",
            "signing_key_id": SIGNING_KEY_ID,
            "payload_encoding": "base64url",
            "payload_b64": b64url_encode(payload_raw),
            "signature_b64": sign_with_callback(
                self.signer, RECEIPT_SIGNATURE_DOMAIN, payload_raw
            ),
        }
        body = canonical_bytes(
            envelope,
            max_string_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        )
        if len(body) > OPERATION_MANIFEST.limits["max_response_bytes"]:
            raise ProtocolError("provider_response_oversized")
        return receipt_id, body, payload

    def _execute_new(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        key: RequestKey,
        now_ms: int,
    ) -> ProviderResponse:
        effect_id = digest_value(
            EFFECT_DOMAIN, {"idempotency_key": request["idempotency_key"]}
        )
        try:
            output, output_raw, state_digest, mutation = self._output(
                request, operation, effect_id
            )
        except ProtocolError as error:
            print(
                f"acceptance private-v3 provider output failure: {error}",
                file=sys.stderr,
            )
            return ProviderResponse(503, _closed_error(str(error)))
        domain = (mutation[0], mutation[1])
        if not self._has_capacity(
            invocations=1,
            idempotency=1,
            effects=1,
            actions=1,
            receipts=1,
            domain=domain,
        ):
            return ProviderResponse(503, _closed_error("provider_capacity_exhausted"))
        if not self._has_principal_capacity(
            key.client_principal_id,
            invocations=1,
            idempotency=1,
            effects=1,
            actions=1,
            receipts=1,
        ):
            return ProviderResponse(
                503, _closed_error("provider_principal_capacity_exhausted")
            )
        status = operation["expected_status"]["initial"]
        try:
            receipt_id, body, payload = self._receipt(
                request,
                operation,
                key,
                output,
                output_raw,
                state_digest,
                effect_id,
                status,
                now_ms,
            )
        except ProtocolError as error:
            print(
                f"acceptance private-v3 provider receipt failure: {error}",
                file=sys.stderr,
            )
            return ProviderResponse(503, _closed_error(str(error)))
        effect = {
            "effect_id": effect_id,
            "idempotency_key": request["idempotency_key"],
            "semantic_digest": request["semantic_digest"],
            "tenant_id": request["tenant_id"],
            "agent_id": request["agent_id"],
            "run_id": request["run_id"],
            "operation_id": operation["operation_id"],
            "client_principal_id": key.client_principal_id,
            "state_digest": state_digest,
            "output": output,
            "output_raw": output_raw,
        }
        self.state["invocations"][request["request_body_digest"]] = {
            "status": 200,
            "body": body,
            "client_principal_id": key.client_principal_id,
        }
        self.state["idempotency"][request["idempotency_key"]] = {
            **effect,
            "first_request_digest": request["request_body_digest"],
            "reconciled_request_digest": None,
        }
        self.state["effects"][request["idempotency_key"]] = effect
        self.state["actions"].append(
            self._action_row(
                request, receipt_id, effect_id, state_digest, status, True
            )
        )
        self.state["receipts"].append(self._receipt_row(payload))
        collection, mutation_key, mutation_value = mutation
        if isinstance(self.state[collection], list):
            self.state[collection].append(
                {
                    "effect_id": effect_id,
                    "operation_id": operation["operation_id"],
                    "tenant_id": request["tenant_id"],
                    "run_id": request["run_id"],
                    "action_id": request["action_id"],
                    "state_digest": state_digest,
                }
            )
        else:
            self.state[collection][mutation_key] = mutation_value
        self.state["effects_applied"] += 1
        self._increment(request, successful=True)
        return ProviderResponse(200, body)

    def _reconcile(
        self,
        request: dict[str, Any],
        operation: dict[str, Any],
        key: RequestKey,
        existing: dict[str, Any],
        now_ms: int,
    ) -> ProviderResponse:
        retry_marker = operation["idempotency"]["required_retry_marker"]
        if (
            request["action"]["params"].get(
                "retry_attempt", retry_marker["initial"]
            )
            != retry_marker["reconciled"]
        ):
            return ProviderResponse(
                409,
                _closed_error(
                    "semantic_retry_attempt_invalid",
                    request_digest=request["request_body_digest"],
                ),
            )
        if not self._has_capacity(invocations=1, actions=1, receipts=1):
            return ProviderResponse(503, _closed_error("provider_capacity_exhausted"))
        if not self._has_principal_capacity(
            key.client_principal_id, invocations=1, actions=1, receipts=1
        ):
            return ProviderResponse(
                503, _closed_error("provider_principal_capacity_exhausted")
            )
        output = copy.deepcopy(existing["output"])
        output["action_id"] = request["action_id"]
        output_raw = canonical_bytes(output)
        status = operation["expected_status"]["reconciled"]
        try:
            receipt_id, body, payload = self._receipt(
                request,
                operation,
                key,
                output,
                output_raw,
                existing["state_digest"],
                existing["effect_id"],
                status,
                now_ms,
            )
        except ProtocolError as error:
            print(
                f"acceptance private-v3 provider reconciliation failure: {error}",
                file=sys.stderr,
            )
            return ProviderResponse(503, _closed_error(str(error)))
        self.state["invocations"][request["request_body_digest"]] = {
            "status": 200,
            "body": body,
            "client_principal_id": key.client_principal_id,
        }
        existing["reconciled_request_digest"] = request["request_body_digest"]
        self.state["actions"].append(
            self._action_row(
                request,
                receipt_id,
                existing["effect_id"],
                existing["state_digest"],
                status,
                False,
            )
        )
        self.state["receipts"].append(self._receipt_row(payload))
        self._increment(request, successful=True)
        return ProviderResponse(200, body)

    def _increment(self, request: dict[str, Any], *, successful: bool) -> None:
        self.state["requests_total"] += 1
        self.state["total"] += 1
        self.state["authenticated_requests"] += 1
        self.state["successful" if successful else "failed"] += 1
        action = request["action_name"]
        adapter = request["adapter_id"]
        self.state["by_action"][action] = self.state["by_action"].get(action, 0) + 1
        self.state["by_adapter"][adapter] = self.state["by_adapter"].get(adapter, 0) + 1

    @staticmethod
    def _action_row(
        request: dict[str, Any],
        receipt_id: str | None,
        effect_id: str | None,
        state_digest: str | None,
        result: str,
        effect_applied: bool,
    ) -> dict[str, Any]:
        return {
            "adapter_id": request["adapter_id"],
            "action_id": request["action_id"],
            "action_name": request["action_name"],
            "run_id": request["run_id"],
            "tenant_id": request["tenant_id"],
            "agent_id": request["agent_id"],
            "client_principal_id": request["client_principal_id"],
            "request_body_digest": request["request_body_digest"],
            "idempotency_key": request["idempotency_key"],
            "provider_receipt_id": receipt_id,
            "effect_id": effect_id,
            "state_digest": state_digest,
            "effect_applied": effect_applied,
            "result": result,
        }

    @staticmethod
    def _receipt_row(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider_receipt_id": payload["provider_receipt_id"],
            "request_body_digest": payload["request_body_digest"],
            "client_principal_id": payload["client_principal_id"],
            "operation_id": payload["operation_id"],
            "action_id": payload["action_id"],
            "effect_id": payload["effect_id"],
            "state_digest": payload["state_digest"],
            "output_digest": payload["output_digest"],
            "status": payload["status"],
            "issued_at_unix_ms": payload["issued_at_unix_ms"],
            "expires_at_unix_ms": payload["expires_at_unix_ms"],
        }

    def _snapshot(
        self,
        now_ms: int,
        request_binding: dict[str, Any],
        snapshot_sequence: int,
    ) -> dict[str, Any]:
        state = self.state
        return {
            "schema_version": EVIDENCE_PAYLOAD_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "provider_id": PROVIDER_ID,
            "provider_epoch": self.epoch,
            "provider_revision": OPERATION_MANIFEST.provider_revision,
            "profile_set_digest": OPERATION_MANIFEST.digest,
            "request_binding": copy.deepcopy(request_binding),
            "snapshot_sequence": snapshot_sequence,
            "snapshot_at_unix_ms": now_ms,
            "expires_at_unix_ms": now_ms + 5000,
            "total": state["total"],
            "requests_total": state["requests_total"],
            "authenticated_requests": state["authenticated_requests"],
            "successful": state["successful"],
            "failed": state["failed"],
            "duplicates": state["duplicates"],
            "effects_applied": state["effects_applied"],
            "counts": {
                key: state[key]
                for key in (
                    "total",
                    "requests_total",
                    "authenticated_requests",
                    "successful",
                    "failed",
                    "duplicates",
                    "effects_applied",
                )
            },
            "by_action": dict(sorted(state["by_action"].items())),
            "by_adapter": dict(sorted(state["by_adapter"].items())),
            "actions": copy.deepcopy(state["actions"]),
            "receipts": copy.deepcopy(state["receipts"]),
            "effects": [
                {
                    key: effect[key]
                    for key in (
                        "effect_id",
                        "idempotency_key",
                        "semantic_digest",
                        "tenant_id",
                        "agent_id",
                        "client_principal_id",
                        "run_id",
                        "operation_id",
                        "state_digest",
                    )
                }
                for _, effect in sorted(state["effects"].items())
            ],
            "artifacts": copy.deepcopy(state["artifacts"]),
            "devices": copy.deepcopy(state["devices"]),
            "markers": copy.deepcopy(state["markers"]),
            "read_evidence": copy.deepcopy(state["read_evidence"]),
            "bounds": {
                "max_ledger_entries": OPERATION_MANIFEST.limits["max_ledger_entries"],
                "max_principal_ledger_entries": OPERATION_MANIFEST.limits[
                    "max_principal_ledger_entries"
                ],
                "max_principal_active_requests": OPERATION_MANIFEST.limits[
                    "max_principal_active_requests"
                ],
                "max_evidence_nonces": OPERATION_MANIFEST.limits["max_evidence_nonces"],
                "max_evidence_bytes": OPERATION_MANIFEST.limits["max_evidence_bytes"],
            },
        }

    def handle_evidence(
        self,
        *,
        method: str,
        target: str,
        key_id: str,
        client_principal_id: str,
        audience: str,
        timestamp_ms: int,
        nonce: str,
        provider_epoch: str,
        view: str,
        signature: str,
        now_ms: int | None = None,
    ) -> ProviderResponse:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        key = self.evidence_keys.get(key_id)
        auth_value = {
            "method": method,
            "path": "/evidence",
            "query": "view=bounded",
            "view": view,
            "timestamp_unix_ms": timestamp_ms,
            "nonce": nonce,
            "audience": audience,
            "key_id": key_id,
            "client_principal_id": client_principal_id,
            "provider_epoch": provider_epoch,
        }
        try:
            b64url_decode(nonce, expected_length=16)
            if (
                key is None
                or method != "GET"
                or target != EVIDENCE_PATH
                or view != "bounded"
                or provider_epoch != self.epoch
                or audience != key.audience
                or client_principal_id != key.client_principal_id
                or now < key.not_before_unix_ms
                or now >= key.expires_at_unix_ms
                or timestamp_ms < key.not_before_unix_ms
                or abs(now - timestamp_ms) > key.max_request_age_ms
                or not hmac.compare_digest(
                    signature, evidence_auth_signature(auth_value, key.secret)
                )
            ):
                raise ProtocolError("evidence_authentication_failed")
        except ProtocolError as error:
            return ProviderResponse(401, _closed_error(str(error)))
        with self.lock:
            nonces = self.state["evidence_nonces"]
            expired = [value for value, expiry in nonces.items() if expiry <= now]
            for value in expired:
                del nonces[value]
            if nonce in nonces:
                return ProviderResponse(409, _closed_error("evidence_nonce_replayed"))
            if len(nonces) >= OPERATION_MANIFEST.limits["max_evidence_nonces"]:
                return ProviderResponse(503, _closed_error("evidence_nonce_capacity_exhausted"))
            nonces[nonce] = now + key.max_request_age_ms
            try:
                snapshot_sequence = self.state["snapshot_sequence"] + 1
                payload = self._snapshot(now, auth_value, snapshot_sequence)
                payload_raw = canonical_bytes(
                    payload,
                    max_fields=OPERATION_MANIFEST.limits["max_ledger_entries"] * 32,
                    max_array_items=OPERATION_MANIFEST.limits["max_ledger_entries"],
                    max_string_bytes=OPERATION_MANIFEST.limits["max_string_bytes"],
                )
                envelope = {
                    "schema_version": RECEIPT_ENVELOPE_SCHEMA,
                    "algorithm": "Ed25519",
                    "signing_key_id": SIGNING_KEY_ID,
                    "payload_encoding": "base64url",
                    "payload_b64": b64url_encode(payload_raw),
                    "signature_b64": sign_with_callback(
                        self.signer, EVIDENCE_SIGNATURE_DOMAIN, payload_raw
                    ),
                }
            except ProtocolError as error:
                return ProviderResponse(503, _closed_error(str(error)))
            body = canonical_bytes(
                envelope,
                max_string_bytes=OPERATION_MANIFEST.limits["max_evidence_bytes"],
            )
            if len(body) > OPERATION_MANIFEST.limits["max_evidence_bytes"]:
                return ProviderResponse(503, _closed_error("evidence_response_oversized"))
            self.state["snapshot_sequence"] = snapshot_sequence
            return ProviderResponse(200, body)

    def evidence_snapshot_for_test(self, now_ms: int) -> dict[str, Any]:
        with self.lock:
            return self._snapshot(
                now_ms,
                {
                    "method": "GET",
                    "path": "/evidence",
                    "query": "view=bounded",
                    "view": "bounded",
                    "timestamp_unix_ms": now_ms,
                    "nonce": "AAECAwQFBgcICQoLDA0ODw",
                    "audience": EVIDENCE_AUDIENCE,
                    "key_id": "acceptance-evidence-runner-v3",
                    "client_principal_id": "acceptance-e2e-runner",
                    "provider_epoch": self.epoch,
                },
                self.state["snapshot_sequence"] + 1,
            )


class BoundedThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], runtime: ProviderRuntime) -> None:
        self.runtime = runtime
        self._admission = threading.BoundedSemaphore(
            OPERATION_MANIFEST.limits["max_active_requests"]
        )
        super().__init__(address, Handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._admission.acquire(blocking=False):
            body = _closed_error("provider_concurrency_exhausted")
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            try:
                request.sendall(response)
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._admission.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    @property
    def runtime(self) -> ProviderRuntime:
        return self.server.runtime  # type: ignore[attr-defined,no-any-return]

    def log_message(self, _: str, *args: object) -> None:
        return

    def _send(self, response: ProviderResponse) -> None:
        if len(response.body) > OPERATION_MANIFEST.limits["max_response_bytes"]:
            response = ProviderResponse(503, _closed_error("response_limit_exceeded"))
        self.send_response_only(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response.body)
        self.close_connection = True

    def _single_header(self, name: str) -> str | None:
        values = self.headers.get_all(name, [])
        return values[0] if len(values) == 1 else None

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(self.runtime.health())
            return
        if self.path == EVIDENCE_PATH:
            evidence_headers = {
                name: self._single_header(name)
                for name in (
                    "X-Splendor-Evidence-Key-Id",
                    "X-Splendor-Evidence-Principal",
                    "X-Splendor-Evidence-Audience",
                    "X-Splendor-Evidence-Timestamp",
                    "X-Splendor-Evidence-Nonce",
                    "X-Splendor-Evidence-Provider-Epoch",
                    "X-Splendor-Evidence-View",
                    "X-Splendor-Evidence-Signature",
                )
            }
            if any(value is None for value in evidence_headers.values()):
                self._send(
                    ProviderResponse(
                        401, _closed_error("evidence_authentication_failed")
                    )
                )
                return
            try:
                timestamp = int(evidence_headers["X-Splendor-Evidence-Timestamp"] or "")
            except ValueError:
                timestamp = -(2**63)
            self._send(
                self.runtime.handle_evidence(
                    method="GET",
                    target=self.path,
                    key_id=evidence_headers["X-Splendor-Evidence-Key-Id"] or "",
                    client_principal_id=evidence_headers[
                        "X-Splendor-Evidence-Principal"
                    ]
                    or "",
                    audience=evidence_headers["X-Splendor-Evidence-Audience"] or "",
                    timestamp_ms=timestamp,
                    nonce=evidence_headers["X-Splendor-Evidence-Nonce"] or "",
                    provider_epoch=evidence_headers[
                        "X-Splendor-Evidence-Provider-Epoch"
                    ]
                    or "",
                    view=evidence_headers["X-Splendor-Evidence-View"] or "",
                    signature=evidence_headers["X-Splendor-Evidence-Signature"]
                    or "",
                )
            )
            return
        self._send(ProviderResponse(404, _closed_error("not_found")))

    def do_POST(self) -> None:
        if self.path != "/actions":
            self._send(ProviderResponse(404, _closed_error("not_found")))
            return
        content_lengths = self.headers.get_all("Content-Length", [])
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        if (
            len(content_lengths) != 1
            or transfer_encodings
            or self.headers.get("Content-Type") != "application/json"
        ):
            self._send(ProviderResponse(400, _closed_error("invalid_http_framing")))
            return
        try:
            length = int(content_lengths[0])
        except ValueError:
            length = 0
        if length <= 0 or length > OPERATION_MANIFEST.limits["max_request_bytes"]:
            self._send(ProviderResponse(400, _closed_error("invalid_content_length")))
            return
        try:
            body = self.rfile.read(length)
        except (OSError, TimeoutError):
            self._send(ProviderResponse(408, _closed_error("request_read_timeout")))
            return
        if len(body) != length:
            self._send(ProviderResponse(400, _closed_error("request_body_truncated")))
            return
        key_id = self._single_header("X-Splendor-Acceptance-Key-Id")
        signature = self._single_header("X-Splendor-Acceptance-Signature")
        if key_id is None or signature is None:
            self._send(
                ProviderResponse(401, _closed_error("request_authentication_failed"))
            )
            return
        self._send(
            self.runtime.handle_action(
                body,
                key_id,
                signature,
            )
        )


def main() -> int:
    global RUNTIME
    if os.environ.get("SPLENDOR_ACCEPTANCE_ONLY") != "1":
        raise SystemExit("action_provider.py requires SPLENDOR_ACCEPTANCE_ONLY=1")
    required = {
        name: os.environ.get(name)
        for name in (
            "SPLENDOR_ACCEPTANCE_REQUEST_KEYRING_FILE",
            "SPLENDOR_ACCEPTANCE_EVIDENCE_KEYRING_FILE",
            "SPLENDOR_ACCEPTANCE_RECEIPT_SIGNING_KEY_FILE",
            "SPLENDOR_ACCEPTANCE_SIGNER",
        )
    }
    if any(value is None for value in required.values()):
        raise SystemExit("private-v3 acceptance provider configuration is incomplete")
    RUNTIME = ProviderRuntime.load(
        Path(required["SPLENDOR_ACCEPTANCE_REQUEST_KEYRING_FILE"] or ""),
        Path(required["SPLENDOR_ACCEPTANCE_EVIDENCE_KEYRING_FILE"] or ""),
        Path(required["SPLENDOR_ACCEPTANCE_SIGNER"] or ""),
        Path(required["SPLENDOR_ACCEPTANCE_RECEIPT_SIGNING_KEY_FILE"] or ""),
    )
    BoundedThreadingHTTPServer(("0.0.0.0", 8086), RUNTIME).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
