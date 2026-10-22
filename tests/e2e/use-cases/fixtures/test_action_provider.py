from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

import acceptance_provider_evidence
import action_provider
from acceptance_provider_auth import resource_scopes_for_role
from acceptance_provider_evidence import (
    _verifier_path,
    _verify_with_ring,
    verify_evidence_envelope,
)
from acceptance_provider_output import project_private_v3_output
from acceptance_scenario_expectations import make_output_expectation
from acceptance_provider_protocol import (
    EVIDENCE_AUTH_DOMAIN,
    OPERATION_MANIFEST,
    PROFILE_DIGEST_DOMAIN,
    RECEIPT_SIGNATURE_DOMAIN,
    ProtocolError,
    b64url_decode,
    b64url_encode,
    canonical_bytes,
    evidence_auth_signature,
    finalize_request,
    load_operation_manifest,
    request_signature,
    secure_read_file,
    semantic_material,
    strict_loads,
)


NOW = 1_800_000_000_000
EPOCH = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "11111111-1111-4111-8111-222222222227"
AGENT = "22222222-2222-4222-8222-222222222222"
RUN = "44444444-4444-4444-8444-444444444444"
ROLE_BINDINGS = {
    "local": (
        "acceptance-request-local-v3",
        "acceptance-host-local",
        "00000000-0000-4000-8000-000000000300",
    ),
    "cloud": (
        "acceptance-request-cloud-v3",
        "acceptance-host-cloud",
        "00000000-0000-4000-8000-000000000304",
    ),
    "vpc": (
        "acceptance-request-vpc-v3",
        "acceptance-host-vpc",
        "00000000-0000-4000-8000-000000000302",
    ),
    "edge": (
        "acceptance-request-edge-v3",
        "acceptance-host-edge",
        "00000000-0000-4000-8000-000000000306",
    ),
}


def load_s9_scenario_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "scenarios"
        / "uc_e2e_s9_failure_injection"
        / "run.py"
    )
    spec = importlib.util.spec_from_file_location("s9_semantic_retry_source", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the S9 source module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


S9_SCENARIO = load_s9_scenario_module()


def deterministic_signer(frame: bytes) -> bytes:
    return hashlib.sha512(b"acceptance-test-signer\0" + frame).digest()


def failing_signer(_: bytes) -> bytes:
    raise ProtocolError("injected_signer_failure")


def request_keys(*, expires_at: int = NOW + 100_000) -> dict[str, action_provider.RequestKey]:
    result: dict[str, action_provider.RequestKey] = {}
    for index, (role, binding) in enumerate(ROLE_BINDINGS.items(), start=1):
        allowed = tuple(
            sorted(
                operation["operation_id"]
                for operation in OPERATION_MANIFEST.value["operations"]
                if role in operation["allowed_request_principals"]
            )
        )
        key = action_provider.RequestKey(
            key_id=binding[0],
            request_principal_role=role,
            client_principal_id=binding[1],
            source_instance_id=binding[2],
            tenant_id=TENANT_A,
            audience=OPERATION_MANIFEST.audience,
            not_before_unix_ms=NOW - 10_000,
            expires_at_unix_ms=expires_at,
            max_request_ttl_ms=OPERATION_MANIFEST.limits["max_request_ttl_ms"],
            allowed_operation_ids=allowed,
            allowed_resource_scopes=tuple(
                (
                    scope["operation_id"],
                    scope["resource_kind"],
                    scope["resource_id"],
                )
                for scope in resource_scopes_for_role(role)
            ),
            secret=bytes([index]) * 32,
            provider_epoch=EPOCH,
        )
        result[key.key_id] = key
    return result


def evidence_keys() -> dict[str, action_provider.EvidenceKey]:
    key = action_provider.EvidenceKey(
        key_id="acceptance-evidence-runner-v3",
        client_principal_id="acceptance-e2e-runner",
        audience=action_provider.EVIDENCE_AUDIENCE,
        not_before_unix_ms=NOW - 10_000,
        expires_at_unix_ms=NOW + 100_000,
        max_request_age_ms=5_000,
        secret=b"e" * 32,
    )
    return {key.key_id: key}


def runtime(
    *,
    signer=deterministic_signer,
    epoch: str = EPOCH,
    keys: dict[str, action_provider.RequestKey] | None = None,
) -> action_provider.ProviderRuntime:
    return action_provider.ProviderRuntime(
        keys or request_keys(), evidence_keys(), signer, epoch=epoch
    )


def default_params(operation: dict[str, Any], tenant_id: str) -> dict[str, Any]:
    profile = operation["parameter_profile"]
    if profile == "empty":
        return {}
    if profile == "management_marker":
        return {"source": "uc-e2e-s2", "ok": True}
    if profile == "idempotent_read":
        return {
            "idempotency_key": "read-once",
            "retry_attempt": 1,
            "retryable": True,
            "max_attempts": 2,
        }
    if profile == "unsafe_failure":
        return {"retry_attempt": 1, "retryable": False, "idempotency_key": None}
    if profile == "artifact_create":
        return {"artifact_path": f"artifact://{tenant_id}/internal.md"}
    if profile == "artifact_publish":
        return {"publish_ref": f"artifact://{tenant_id}/published.md"}
    if profile == "data_read":
        return {"data_ref": "dataset:tenant-a.finance.v1"}
    if profile == "physical":
        return {"physical_action": True}
    raise AssertionError(profile)


def make_request(
    operation_id: str = "daemon.local/daemon_management_action",
    *,
    role: str | None = None,
    tenant_id: str = TENANT_A,
    agent_id: str = AGENT,
    run_id: str = RUN,
    action_id: str = "55555555-5555-4555-8555-555555555555",
    request_id: str = "66666666-6666-4666-8666-666666666666",
    issued_at: int = NOW,
    action_requested_at: int | None = None,
    params: dict[str, Any] | None = None,
    provider_epoch: str = EPOCH,
) -> dict[str, Any]:
    operation = OPERATION_MANIFEST.by_operation_id[operation_id]
    selected_role = role or (
        operation["allowed_request_principals"][0]
        if operation["allowed_request_principals"]
        else "local"
    )
    binding = ROLE_BINDINGS[selected_role]
    coordinate = (
        {
            "resource_kind": "physical_node",
            "node_id": "00000000-0000-4000-8000-000000000604",
        }
        if operation["coordinate_rule"] == "physical_node"
        else None
    )
    value = {
        "schema_version": "splendor.acceptance.action_provider.request.v3",
        "protocol_version": "private-v3",
        "provider_id": "acceptance-action-provider",
        "provider_revision": OPERATION_MANIFEST.provider_revision,
        "provider_epoch": provider_epoch,
        "audience": OPERATION_MANIFEST.audience,
        "request_key_id": binding[0],
        "client_principal_id": binding[1],
        "source_instance_id": binding[2],
        "request_id": request_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "run_id": run_id,
        "tick_id": None,
        "action_id": action_id,
        "adapter_id": operation["adapter_id"],
        "action_name": operation["action_name"],
        "action_requested_at_unix_nanos": str(
            (issued_at if action_requested_at is None else action_requested_at) * 1_000_000
        ),
        "action": {
            "name": operation["action_name"],
            "params": default_params(operation, tenant_id) if params is None else params,
            "side_effect_class": operation["effect_class"],
            "cost_estimate": None,
            "required_permissions": operation["required_permissions"],
            "preconditions": [],
            "postconditions": [operation["postcondition"]],
        },
        "physical_action_resource_coordinate": coordinate,
        "operation_id": operation["operation_id"],
        "profile_set_digest": OPERATION_MANIFEST.digest,
        "operation_profile_digest": OPERATION_MANIFEST.operation_digest(operation),
        "idempotency_key": "pending",
        "semantic_digest": "pending",
        "issued_at_unix_ms": issued_at,
        "deadline_unix_ms": issued_at + 5_000,
        "request_body_digest": "pending",
    }
    return finalize_request(value)


def signed_request(
    request: dict[str, Any], keys: dict[str, action_provider.RequestKey]
) -> tuple[bytes, str, str]:
    body = canonical_bytes(request)
    key = keys[request["request_key_id"]]
    return body, key.key_id, request_signature(key.key_id, body, key.secret)


def handle(
    provider: action_provider.ProviderRuntime, request: dict[str, Any]
) -> action_provider.ProviderResponse:
    body, key_id, signature = signed_request(request, provider.request_keys)
    return provider.handle_action(body, key_id, signature, now_ms=NOW)


def response_json(response: action_provider.ProviderResponse) -> dict[str, Any]:
    return strict_loads(
        response.body,
        max_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        max_fields=8192,
        max_array_items=256,
        max_string_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        require_canonical=True,
    )


def receipt_payload(response: action_provider.ProviderResponse) -> dict[str, Any]:
    envelope = response_json(response)
    return strict_loads(
        b64url_decode(envelope["payload_b64"]),
        max_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        max_string_bytes=OPERATION_MANIFEST.limits["max_response_bytes"],
        require_canonical=True,
    )


class ManifestAndProtocolTests(unittest.TestCase):
    def test_manifest_is_the_single_complete_policy_owner(self) -> None:
        vector = json.loads(
            Path(__file__)
            .with_name("acceptance-provider-private-v3-golden.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(len(OPERATION_MANIFEST.by_operation_id), 18)
        self.assertEqual(
            OPERATION_MANIFEST.digest,
            "sha256:7c0bbbc1fbe5d60c844a5c672d2f53bcf96782f72631c70abf30f4c2fd9909a0",
        )
        self.assertFalse(hasattr(action_provider, "PROFILES"))
        self.assertEqual(
            sorted(OPERATION_MANIFEST.by_operation_id),
            [
                operation["operation_id"]
                for operation in OPERATION_MANIFEST.value["operations"]
            ],
        )
        self.assertEqual(
            vector["operation_digests"],
            {
                operation_id: OPERATION_MANIFEST.operation_digest(operation)
                for operation_id, operation in OPERATION_MANIFEST.by_operation_id.items()
            },
        )

    def test_manifest_rejects_unknown_predicates_and_cross_family_contracts(self) -> None:
        source = copy.deepcopy(OPERATION_MANIFEST.value)

        def rejected(mutator) -> None:
            value = copy.deepcopy(source)
            mutator(value)
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            digest = "sha256:" + hashlib.sha256(PROFILE_DIGEST_DOMAIN + raw).hexdigest()
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "manifest.json"
                sidecar = root / "manifest.sha256"
                manifest.write_bytes(raw)
                sidecar.write_text(digest + "\n", encoding="ascii")
                with self.assertRaises(ProtocolError):
                    load_operation_manifest(manifest, sidecar)

        rejected(
            lambda value: value["operations"][5].__setitem__(
                "postcondition", "totally_unimplemented_predicate"
            )
        )
        rejected(
            lambda value: value["operations"][5].__setitem__(
                "output_profile", "marker"
            )
        )
        rejected(
            lambda value: value["operations"][8].__setitem__(
                "postcondition", "sensor_read"
            )
        )

    def test_shared_canonical_hmac_and_ed25519_golden_vectors(self) -> None:
        path = Path(__file__).with_name("acceptance-provider-private-v3-golden.json")
        vector = json.loads(path.read_text(encoding="utf-8"))
        canonical = canonical_bytes(vector["canonical_value"])
        self.assertEqual(canonical.decode("ascii"), vector["canonical_bytes"])
        digest = "sha256:" + hashlib.sha256(
            vector["canonical_digest_domain"].encode("ascii") + b"\0" + canonical
        ).hexdigest()
        self.assertEqual(digest, vector["canonical_digest"])
        key = b64url_decode(
            vector["request_hmac_test_input_b64"], expected_length=32
        )
        self.assertEqual(
            request_signature(vector["request_key_id"], canonical, key),
            vector["request_signature_b64"],
        )
        payload = b64url_decode(vector["receipt_payload_b64"])
        signature = b64url_decode(vector["receipt_signature_b64"], expected_length=64)
        public_key = b64url_decode(vector["receipt_public_key_b64"], expected_length=32)
        with tempfile.TemporaryDirectory() as directory:
            public_path = Path(directory) / "public.raw"
            public_path.write_bytes(public_key)
            public_path.chmod(0o644)
            _verify_with_ring(
                public_path,
                signature,
                RECEIPT_SIGNATURE_DOMAIN + payload,
            )

    def test_invalid_grammar_and_base64_vectors_fail_closed(self) -> None:
        vector = json.loads(
            Path(__file__)
            .with_name("acceptance-provider-private-v3-golden.json")
            .read_text(encoding="utf-8")
        )
        for case in vector["invalid_json"]:
            raw = base64.urlsafe_b64decode(case["raw_b64"] + "=" * (-len(case["raw_b64"]) % 4))
            with self.assertRaisesRegex(
                ProtocolError, f"^{case['reason']}$", msg=case["reason"]
            ):
                strict_loads(raw, max_bytes=1024, require_canonical=True)
        for case in vector["canonical_integer_boundaries"]:
            raw = base64.urlsafe_b64decode(
                case["raw_b64"] + "=" * (-len(case["raw_b64"]) % 4)
            )
            self.assertEqual(
                strict_loads(raw, max_bytes=1024, require_canonical=True)["a"],
                case["value"],
            )
        generated = {
            "huge_integer": (b'{"a":' + b"9" * 5000 + b"}", {"max_bytes": 6000}),
            "depth": (b'{"a":{"b":{"c":{"d":1}}}}', {"max_depth": 4}),
            "fields": (b'{"a":1,"b":2,"c":3}', {"max_fields": 2}),
            "array": (b'{"a":[1,2,3]}', {"max_array_items": 2}),
            "string": (b'{"a":"abc"}', {"max_string_bytes": 2}),
            "body": (b'{"a":123}', {"max_bytes": 8}),
        }
        for case in vector["invalid_generated_json"]:
            raw, limits = generated[case["case"]]
            options = {"max_bytes": 1024, "require_canonical": True, **limits}
            with self.assertRaisesRegex(
                ProtocolError, f"^{case['reason']}$", msg=case["case"]
            ):
                strict_loads(raw, **options)
        for case in vector["closed_object_vectors"]:
            raw = b64url_decode(case["raw_b64"])
            parsed = strict_loads(raw, max_bytes=1024, require_canonical=True)
            self.assertNotEqual(set(parsed), set(case["allowed_fields"]))
        for case in vector["typed_integer_vectors"]:
            raw = b64url_decode(case["raw_b64"])
            parsed = strict_loads(raw, max_bytes=1024, require_canonical=True)
            self.assertIsNot(type(parsed[case["field"]]), int)
        for value in vector["invalid_base64url"]:
            with self.assertRaises(ProtocolError, msg=value):
                b64url_decode(value)

        malformed_requests = []
        unknown = make_request()
        unknown["unknown_field"] = True
        malformed_requests.append(("unknown_top_level", finalize_request(unknown)))
        unknown_action = make_request()
        unknown_action["action"]["unknown_field"] = True
        malformed_requests.append(
            ("unknown_nested_field", finalize_request(unknown_action))
        )
        boolean_time = make_request()
        boolean_time["issued_at_unix_ms"] = True
        malformed_requests.append(("boolean_integer", finalize_request(boolean_time)))
        for label, request in malformed_requests:
            provider = runtime()
            before = copy.deepcopy(provider.state)
            response = handle(provider, request)
            self.assertEqual(response.status, 401, label)
            self.assertEqual(provider.state, before, label)

    def test_request_and_evidence_hmac_keys_cannot_forge_provider_receipts(self) -> None:
        vector = json.loads(
            Path(__file__)
            .with_name("acceptance-provider-private-v3-golden.json")
            .read_text(encoding="utf-8")
        )
        payload = b64url_decode(vector["receipt_payload_b64"])
        frame = RECEIPT_SIGNATURE_DOMAIN + payload
        public_key = b64url_decode(
            vector["receipt_public_key_b64"], expected_length=32
        )
        for secret in (bytes(range(32)), b"e" * 32):
            forged = hmac.new(secret, frame, hashlib.sha256).digest() * 2
            with tempfile.TemporaryDirectory() as directory:
                public_path = Path(directory) / "public.raw"
                public_path.write_bytes(public_key)
                public_path.chmod(0o644)
                with self.assertRaises(ProtocolError):
                    _verify_with_ring(public_path, forged, frame)

    def test_signed_evidence_helper_verifies_before_parsing_and_rejects_tampering(self) -> None:
        tool = _verifier_path()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "private.pk8"
            public_path = root / "public.raw"
            subprocess.run(
                [str(tool), "generate", str(private_path), str(public_path)],
                check=True,
                capture_output=True,
                timeout=5,
            )
            provider = runtime(
                signer=action_provider.SubprocessSigner(tool, private_path)
            )
            key = next(iter(provider.evidence_keys.values()))
            nonce = "BAECAwQFBgcICQoLDA0ODw"
            auth = {
                "method": "GET",
                "path": "/evidence",
                "query": "view=bounded",
                "view": "bounded",
                "timestamp_unix_ms": NOW,
                "nonce": nonce,
                "audience": key.audience,
                "key_id": key.key_id,
                "client_principal_id": key.client_principal_id,
                "provider_epoch": EPOCH,
            }
            response = provider.handle_evidence(
                method="GET",
                target=action_provider.EVIDENCE_PATH,
                key_id=key.key_id,
                client_principal_id=key.client_principal_id,
                audience=key.audience,
                timestamp_ms=NOW,
                nonce=nonce,
                provider_epoch=EPOCH,
                view="bounded",
                signature=evidence_auth_signature(auth, key.secret),
                now_ms=NOW,
            )
            self.assertEqual(response.status, 200)
            payload = verify_evidence_envelope(
                response.body,
                public_path,
                request_binding=auth,
                now_ms=NOW,
            )
            self.assertEqual(payload["provider_epoch"], EPOCH)
            self.assertEqual(payload["request_binding"], auth)
            self.assertEqual(payload["snapshot_sequence"], 1)

            invalid_bindings = {
                "wrong_method": {**auth, "method": "POST"},
                "wrong_path": {**auth, "path": "/other"},
                "wrong_query": {**auth, "query": "view=full"},
                "wrong_view": {**auth, "view": "full"},
                "wrong_audience": {**auth, "audience": "other"},
                "wrong_reader_key": {**auth, "key_id": "other"},
                "wrong_reader_principal": {
                    **auth,
                    "client_principal_id": "other",
                },
                "invalid_timestamp": {**auth, "timestamp_unix_ms": 0},
                "invalid_nonce": {**auth, "nonce": "not-base64url"},
                "invalid_epoch": {
                    **auth,
                    "provider_epoch": "00000000-0000-0000-0000-000000000000",
                },
            }
            for label, invalid_binding in invalid_bindings.items():
                with self.subTest(label=label), self.assertRaisesRegex(
                    ProtocolError, "evidence_request_binding_invalid"
                ):
                    verify_evidence_envelope(
                        response.body,
                        public_path,
                        request_binding=invalid_binding,
                        now_ms=NOW,
                    )

            fresh_nonce_auth = {
                **auth,
                "nonce": "BQECAwQFBgcICQoLDA0ODw",
            }
            with self.assertRaisesRegex(
                ProtocolError, "evidence_payload_identity_or_freshness_invalid"
            ):
                verify_evidence_envelope(
                    response.body,
                    public_path,
                    request_binding=fresh_nonce_auth,
                    now_ms=NOW,
                )

            restarted_auth = {
                **fresh_nonce_auth,
                "provider_epoch": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
            }
            restarted = runtime(epoch=restarted_auth["provider_epoch"])
            self.assertNotEqual(restarted.epoch, provider.epoch)
            with self.assertRaisesRegex(
                ProtocolError, "evidence_payload_identity_or_freshness_invalid"
            ):
                verify_evidence_envelope(
                    response.body,
                    public_path,
                    request_binding=restarted_auth,
                    now_ms=NOW,
                )

            sequence_scope = f"unit:{uuid.uuid4()}"
            verify_evidence_envelope(
                response.body,
                public_path,
                request_binding=auth,
                now_ms=NOW,
                enforce_monotonic=True,
                sequence_scope=sequence_scope,
            )
            with self.assertRaisesRegex(
                ProtocolError, "evidence_snapshot_sequence_replayed"
            ):
                verify_evidence_envelope(
                    response.body,
                    public_path,
                    request_binding=auth,
                    now_ms=NOW,
                    enforce_monotonic=True,
                    sequence_scope=sequence_scope,
                )

            maximum_scopes = OPERATION_MANIFEST.limits["max_evidence_nonces"]
            with acceptance_provider_evidence._SEQUENCE_LOCK:
                acceptance_provider_evidence._LAST_SEQUENCES.clear()
            try:
                for index in range(maximum_scopes + 1):
                    verify_evidence_envelope(
                        response.body,
                        public_path,
                        request_binding=auth,
                        now_ms=NOW,
                        enforce_monotonic=True,
                        sequence_scope=f"bounded-sequence-scope:{index}",
                    )
                with acceptance_provider_evidence._SEQUENCE_LOCK:
                    self.assertEqual(
                        len(acceptance_provider_evidence._LAST_SEQUENCES),
                        maximum_scopes,
                    )
                    self.assertNotIn(
                        ("bounded-sequence-scope:0", EPOCH, key.key_id),
                        acceptance_provider_evidence._LAST_SEQUENCES,
                    )
            finally:
                with acceptance_provider_evidence._SEQUENCE_LOCK:
                    acceptance_provider_evidence._LAST_SEQUENCES.clear()

            tampered = response_json(response)
            signature = bytearray(
                b64url_decode(tampered["signature_b64"], expected_length=64)
            )
            signature[0] ^= 1
            tampered["signature_b64"] = (
                base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
            )
            with self.assertRaises(ProtocolError):
                verify_evidence_envelope(
                    canonical_bytes(
                        tampered,
                        max_string_bytes=OPERATION_MANIFEST.limits[
                            "max_evidence_bytes"
                        ],
                    ),
                    public_path,
                    request_binding=auth,
                    now_ms=NOW,
                )

    def test_secret_file_loader_rejects_mode_symlink_hardlink_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.write_bytes(b"k" * 32)
            private.chmod(0o644)
            with self.assertRaises(ProtocolError):
                secure_read_file(private, max_bytes=32, owner_only=True)
            private.chmod(0o600)
            self.assertEqual(
                secure_read_file(private, max_bytes=32, owner_only=True), b"k" * 32
            )
            symlink = root / "symlink"
            symlink.symlink_to(private)
            with self.assertRaises(ProtocolError):
                secure_read_file(symlink, max_bytes=32, owner_only=True)
            hardlink = root / "hardlink"
            os.link(private, hardlink)
            with self.assertRaises(ProtocolError):
                secure_read_file(private, max_bytes=32, owner_only=True)
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * 33)
            oversized.chmod(0o600)
            with self.assertRaises(ProtocolError):
                secure_read_file(oversized, max_bytes=32, owner_only=True)

    def test_keyring_loading_rejects_duplicate_and_cross_purpose_secrets(self) -> None:
        def request_entry(key: action_provider.RequestKey) -> dict[str, Any]:
            return {
                "key_id": key.key_id,
                "status": "active",
                "request_principal_role": key.request_principal_role,
                "client_principal_id": key.client_principal_id,
                "source_instance_id": key.source_instance_id,
                "tenant_id": key.tenant_id,
                "audience": key.audience,
                "not_before_unix_ms": key.not_before_unix_ms,
                "expires_at_unix_ms": key.expires_at_unix_ms,
                "max_request_ttl_ms": key.max_request_ttl_ms,
                "allowed_operation_ids": list(key.allowed_operation_ids),
                "allowed_resource_scopes": [
                    {
                        "operation_id": operation_id,
                        "resource_kind": resource_kind,
                        "resource_id": resource_id,
                    }
                    for operation_id, resource_kind, resource_id in key.allowed_resource_scopes
                ],
                "secret_b64": b64url_encode(key.secret),
            }

        keys = sorted(request_keys().values(), key=lambda key: key.key_id)
        request_ring = {
            "schema_version": "splendor.acceptance.request_keyring.v3",
            "profile_set_digest": OPERATION_MANIFEST.digest,
            "keys": [request_entry(key) for key in keys],
        }
        evidence_key = next(iter(evidence_keys().values()))
        evidence_ring = {
            "schema_version": "splendor.acceptance.evidence_reader_keyring.v3",
            "keys": [
                {
                    "key_id": evidence_key.key_id,
                    "status": "active",
                    "client_principal_id": evidence_key.client_principal_id,
                    "audience": evidence_key.audience,
                    "not_before_unix_ms": evidence_key.not_before_unix_ms,
                    "expires_at_unix_ms": evidence_key.expires_at_unix_ms,
                    "max_request_age_ms": evidence_key.max_request_age_ms,
                    "secret_b64": b64url_encode(evidence_key.secret),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request-keyring.json"
            evidence_path = root / "evidence-keyring.json"

            duplicate_ring = copy.deepcopy(request_ring)
            duplicate_ring["keys"][1]["secret_b64"] = duplicate_ring["keys"][0][
                "secret_b64"
            ]
            request_path.write_bytes(canonical_bytes(duplicate_ring))
            request_path.chmod(0o600)
            with self.assertRaisesRegex(
                ProtocolError, "request_keyring_secret_reused"
            ):
                action_provider._load_request_keys(request_path, EPOCH)

            request_path.write_bytes(canonical_bytes(request_ring))
            request_path.chmod(0o600)
            cross_purpose_ring = copy.deepcopy(evidence_ring)
            cross_purpose_ring["keys"][0]["secret_b64"] = request_ring["keys"][0][
                "secret_b64"
            ]
            evidence_path.write_bytes(canonical_bytes(cross_purpose_ring))
            evidence_path.chmod(0o600)
            loaded_requests = action_provider._load_request_keys(request_path, EPOCH)
            loaded_evidence = action_provider._load_evidence_keys(evidence_path)
            with self.assertRaisesRegex(
                ProtocolError, "request_evidence_secret_reused"
            ):
                action_provider._validate_key_separation(
                    loaded_requests, loaded_evidence
                )

    def test_static_compose_and_image_roles_are_separated(self) -> None:
        root = Path(__file__).resolve().parents[4]
        compose_path = root / "tests/e2e/use-cases/docker-compose.acceptance.yml"
        compose = (
            compose_path.read_text(encoding="utf-8")
        )
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("SPLENDOR_ACCEPTANCE_PROVIDER_KEY_FILE", compose)
        self.assertNotIn("action-provider.key", compose)
        self.assertEqual(
            compose.count("e2e-action-provider-auth:/run/splendor-provider-auth:ro"),
            1,
        )
        for role in ("local", "cloud", "vpc", "edge"):
            self.assertEqual(
                compose.count(
                    f"e2e-provider-{role}-auth:/run/splendor-provider-client:ro"
                ),
                1,
            )
        self.assertEqual(
            compose.count(
                "e2e-provider-runner-auth:/run/splendor-provider-evidence:ro"
            ),
            1,
        )
        self.assertIn("FROM python:${PYTHON_VERSION}-slim-bookworm AS acceptance-action-provider", dockerfile)
        provider_stage = dockerfile.split(
            "FROM python:${PYTHON_VERSION}-slim-bookworm AS acceptance-action-provider",
            1,
        )[1].split("FROM runtime AS production", 1)[0]
        self.assertIn("USER splendor", provider_stage)
        self.assertIn("resident_auth_key_tool", provider_stage)
        production_stage = dockerfile.split("FROM runtime AS production", 1)[1]
        self.assertNotIn("action_provider.py", production_stage)
        self.assertNotIn("acceptance-operation-profiles", production_stage)

        effective = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_path),
                "--profile",
                "setup",
                "config",
                "--format",
                "json",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        topology = json.loads(effective.stdout)
        runner = topology["services"]["e2e-runner"]
        setup = topology["services"]["resident-auth-fixture"]
        self.assertEqual(runner["user"], "root")
        runner_evidence_mount = next(
            mount
            for mount in runner["volumes"]
            if mount["target"] == "/run/splendor-provider-evidence"
        )
        self.assertEqual(runner_evidence_mount["type"], "volume")
        self.assertTrue(runner_evidence_mount["read_only"])
        self.assertEqual(runner_evidence_mount["source"], "e2e-provider-runner-auth")
        self.assertEqual(setup["user"], "root")
        setup_script = setup["command"][-1]
        self.assertIn(
            "chown -R root:root /run/splendor-provider-runner-auth", setup_script
        )
        runner_script = runner["command"][-1]
        self.assertIn("acceptance_provider_evidence.py", runner_script)
        self.assertIn("--smoke-url", runner_script)


class ProviderAuthorityTests(unittest.TestCase):
    def test_complete_role_operation_scope_matrix(self) -> None:
        for role in ROLE_BINDINGS:
            for operation in OPERATION_MANIFEST.value["operations"]:
                provider = runtime()
                request = make_request(operation["operation_id"], role=role)
                response = handle(provider, request)
                allowed = role in operation["allowed_request_principals"]
                if not allowed or operation["provider_mode"] == "forbidden":
                    self.assertEqual(response.status, 401, (role, operation["operation_id"]))
                    self.assertEqual(provider.state["effects_applied"], 0)
                    self.assertEqual(provider.state["requests_total"], 0)
                elif operation["provider_mode"] == "controlled_failure":
                    self.assertEqual(response.status, 503, (role, operation["operation_id"]))
                    self.assertEqual(provider.state["effects_applied"], 0)
                else:
                    self.assertEqual(response.status, 200, (role, operation["operation_id"]))
                    self.assertEqual(provider.state["effects_applied"], 1)

    def test_wrong_host_tenant_audience_key_expiry_epoch_and_freshness_are_zero_state(self) -> None:
        cases: list[tuple[str, action_provider.ProviderRuntime, dict[str, Any], str | None]] = []
        base = make_request()

        wrong_host = copy.deepcopy(base)
        cloud = ROLE_BINDINGS["cloud"]
        wrong_host.update(
            {
                "request_key_id": cloud[0],
                "client_principal_id": cloud[1],
                "source_instance_id": cloud[2],
            }
        )
        cases.append(("wrong_host", runtime(), finalize_request(wrong_host), None))

        cases.append(("wrong_tenant", runtime(), make_request(tenant_id=TENANT_B), None))
        wrong_audience = copy.deepcopy(base)
        wrong_audience["audience"] = "splendor.acceptance.other"
        cases.append(("wrong_audience", runtime(), finalize_request(wrong_audience), None))
        cases.append(("expired", runtime(keys=request_keys(expires_at=NOW)), base, None))
        cases.append(
            (
                "epoch",
                runtime(),
                make_request(provider_epoch="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"),
                None,
            )
        )
        cases.append(("stale", runtime(), make_request(issued_at=NOW - 20_000), None))
        cases.append(("future", runtime(), make_request(issued_at=NOW + 3_000), None))

        for label, provider, request, _ in cases:
            before = copy.deepcopy(provider.state)
            if label == "expired":
                key = provider.request_keys[request["request_key_id"]]
                body = canonical_bytes(request)
                response = provider.handle_action(
                    body,
                    key.key_id,
                    request_signature(key.key_id, body, key.secret),
                    now_ms=NOW,
                )
            else:
                response = handle(provider, request)
            self.assertEqual(response.status, 401, label)
            self.assertEqual(provider.state, before, label)

        provider = runtime()
        body, key_id, _ = signed_request(base, provider.request_keys)
        before = copy.deepcopy(provider.state)
        response = provider.handle_action(body, key_id, "forged", now_ms=NOW)
        self.assertEqual(response.status, 401)
        self.assertEqual(provider.state, before)

    def test_cross_tenant_regression_denies_without_any_counter_or_cache_change(self) -> None:
        provider = runtime()
        request = make_request(
            "artifact-store/artifact.publish_external", tenant_id=TENANT_B
        )
        before = copy.deepcopy(provider.state)
        response = handle(provider, request)
        self.assertEqual(response.status, 401)
        self.assertEqual(response_json(response)["error"], "wrong_tenant")
        self.assertEqual(provider.state, before)

    def test_exact_node_data_and_artifact_resource_scope_denials_are_zero_state(self) -> None:
        cases = [
            make_request(
                "device-sim/capture_image",
                params={"physical_action": True},
            ),
            make_request(
                "artifact-store/artifact.create_internal",
                params={"artifact_path": f"artifact://{TENANT_A}/not-provisioned.md"},
            ),
            make_request(
                "fixture-data-store/data.read_fixture",
                params={"data_ref": "dataset:tenant-a.not-provisioned.v1"},
            ),
        ]
        cases[0]["physical_action_resource_coordinate"]["node_id"] = (
            "99999999-9999-4999-8999-999999999999"
        )
        cases[0] = finalize_request(cases[0])
        for request in cases:
            provider = runtime()
            before = copy.deepcopy(provider.state)
            response = handle(provider, request)
            self.assertEqual(response.status, 401)
            self.assertEqual(
                response_json(response)["error"], "request_resource_scope_denied"
            )
            self.assertEqual(provider.state, before)

    def test_reserved_node_action_parameter_is_rejected_without_effect(self) -> None:
        provider = runtime()
        request = make_request(
            "device-sim/capture_image",
            params={
                "physical_action": True,
                "node_id": "00000000-0000-4000-8000-000000000604",
            },
        )
        before = copy.deepcopy(provider.state)
        response = handle(provider, request)
        self.assertEqual(response.status, 401)
        self.assertEqual(response_json(response)["error"], "operation_reserved_field")
        self.assertEqual(provider.state, before)

    def test_all_positive_output_families_are_specific_and_bound(self) -> None:
        profiles = set()
        for operation in OPERATION_MANIFEST.value["operations"]:
            if operation["provider_mode"] != "execute":
                continue
            provider = runtime()
            request = make_request(operation["operation_id"])
            response = handle(provider, request)
            self.assertEqual(response.status, 200, operation["operation_id"])
            payload = receipt_payload(response)
            output = strict_loads(
                b64url_decode(payload["output_b64"]),
                max_bytes=operation["bounds"]["max_output_bytes"],
                require_canonical=True,
            )
            profiles.add(payload["output_profile"])
            self.assertEqual(payload["operation_id"], operation["operation_id"])
            self.assertEqual(output["proof_type"], operation["output_profile"])
            self.assertEqual(output["operation_id"], operation["operation_id"])
            self.assertEqual(output["effect_id"], payload["effect_id"])
            self.assertEqual(output["state_digest"], payload["state_digest"])
            self.assertEqual(
                payload["postcondition_proof"]["predicate"],
                operation["postcondition"],
            )
        self.assertEqual(
            profiles,
            {
                "artifact_create",
                "artifact_publish",
                "data_read",
                "fixture_read",
                "marker",
                "physical_battery",
                "physical_image",
                "physical_inspect",
                "physical_return",
                "physical_sensor",
                "physical_trace_upload",
                "physical_waypoint",
                "sql_read",
            },
        )

    def test_canonical_projection_accepts_production_shaped_operation_families(self) -> None:
        tool = _verifier_path()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "private.pk8"
            public_path = root / "public.raw"
            subprocess.run(
                [str(tool), "generate", str(private_path), str(public_path)],
                check=True,
                capture_output=True,
                timeout=5,
            )
            provider = runtime(
                signer=action_provider.SubprocessSigner(tool, private_path)
            )
            for operation_id in (
                "daemon.local/daemon_management_action",
                "artifact-store/artifact.create_internal",
                "artifact-store/artifact.publish_external",
                "fixture-data-store/data.read_fixture",
                "fixture-sql/sql.read_fixture",
                "device-sim/read_sensor_summary",
                "device-sim/capture_image",
            ):
                request = make_request(
                    operation_id,
                    action_id=str(uuid.uuid4()),
                    request_id=str(uuid.uuid4()),
                )
                response = handle(provider, request)
                self.assertEqual(response.status, 200, operation_id)
                envelope = response_json(response)
                payload = receipt_payload(response)
                output = strict_loads(
                    b64url_decode(payload["output_b64"]),
                    max_bytes=OPERATION_MANIFEST.by_operation_id[operation_id]["bounds"][
                        "max_output_bytes"
                    ],
                    require_canonical=True,
                )
                output["provider_receipt"] = envelope
                operation = OPERATION_MANIFEST.by_operation_id[operation_id]
                expected_resource: Any = None
                if operation["coordinate_rule"] == "physical_node":
                    expected_resource = request["physical_action_resource_coordinate"]
                elif operation["parameter_profile"] == "artifact_create":
                    expected_resource = request["action"]["params"]["artifact_path"]
                elif operation["parameter_profile"] == "artifact_publish":
                    expected_resource = request["action"]["params"]["publish_ref"]
                elif operation["parameter_profile"] == "data_read":
                    expected_resource = request["action"]["params"]["data_ref"]
                projection = project_private_v3_output(
                    output,
                    expectation=make_output_expectation(
                        "UNIT",
                        operation_id,
                        operation_id,
                        next(
                            role
                            for role, binding in ROLE_BINDINGS.items()
                            if binding[0] == request["request_key_id"]
                        ),
                        request["agent_id"],
                        request["run_id"],
                        request["action_id"],
                        expected_resource,
                    ),
                    public_key_path=public_path,
                    now_ms=NOW,
                )
                self.assertEqual(projection["operation_id"], operation_id)
                self.assertEqual(projection["resource_id"], (
                    expected_resource.get("node_id")
                    if isinstance(expected_resource, dict)
                    else expected_resource
                ))

    def test_thirty_two_concurrent_exact_duplicates_are_byte_identical_and_one_effect(self) -> None:
        provider = runtime()
        request = make_request("artifact-store/artifact.publish_external")
        body, key_id, signature = signed_request(request, provider.request_keys)

        def submit(_: int) -> action_provider.ProviderResponse:
            return provider.handle_action(body, key_id, signature, now_ms=NOW)

        with ThreadPoolExecutor(max_workers=32) as executor:
            responses = list(executor.map(submit, range(32)))
        self.assertEqual({response.status for response in responses}, {200})
        self.assertEqual({response.body for response in responses}, {responses[0].body})
        self.assertEqual(provider.state["effects_applied"], 1)
        self.assertEqual(len(provider.state["effects"]), 1)
        self.assertEqual(len(provider.state["invocations"]), 1)
        self.assertEqual(provider.state["duplicates"], 31)

    def test_semantic_retry_reconciles_once_and_conflicting_semantics_return_409(self) -> None:
        provider = runtime()
        first = make_request("acceptance-fixture/s9.idempotent_read")
        first_response = handle(provider, first)
        self.assertEqual(first_response.status, 200)
        second = make_request(
            "acceptance-fixture/s9.idempotent_read",
            action_id="55555555-5555-4555-8555-555555555556",
            request_id="66666666-6666-4666-8666-666666666667",
            issued_at=NOW + 1,
            action_requested_at=NOW,
            params={
                "idempotency_key": "read-once",
                "retry_attempt": 2,
                "retryable": True,
                "max_attempts": 2,
            },
        )
        second_response = handle(provider, second)
        self.assertEqual(second_response.status, 200)
        self.assertEqual(receipt_payload(second_response)["status"], "reconciled")
        self.assertEqual(
            receipt_payload(first_response)["effect_id"],
            receipt_payload(second_response)["effect_id"],
        )
        exact_second = handle(provider, second)
        self.assertEqual(exact_second.body, second_response.body)
        third = make_request(
            "acceptance-fixture/s9.idempotent_read",
            action_id="55555555-5555-4555-8555-555555555559",
            request_id="66666666-6666-4666-8666-666666666670",
            issued_at=NOW + 2,
            action_requested_at=NOW,
            params={
                "idempotency_key": "read-once",
                "retry_attempt": 2,
                "retryable": True,
                "max_attempts": 2,
            },
        )
        self.assertEqual(handle(provider, third).status, 409)
        self.assertEqual(provider.state["effects_applied"], 1)

        conflict_provider = runtime()
        self.assertEqual(handle(conflict_provider, first).status, 200)
        conflict = make_request(
            "acceptance-fixture/s9.idempotent_read",
            action_id="55555555-5555-4555-8555-555555555557",
            request_id="66666666-6666-4666-8666-666666666668",
            issued_at=NOW + 1,
            action_requested_at=NOW,
            params={
                "idempotency_key": "read-once",
                "retry_attempt": 2,
                "retryable": True,
            },
        )
        conflict_response = handle(conflict_provider, conflict)
        self.assertEqual(conflict_response.status, 409)
        self.assertEqual(conflict_provider.state["effects_applied"], 1)

        requested_at_conflict = make_request(
            "acceptance-fixture/s9.idempotent_read",
            action_id="55555555-5555-4555-8555-555555555580",
            request_id="66666666-6666-4666-8666-666666666680",
            issued_at=NOW + 1,
            action_requested_at=NOW + 2,
            params={
                "idempotency_key": "read-once",
                "retry_attempt": 2,
                "retryable": True,
                "max_attempts": 2,
            },
        )
        requested_at_provider = runtime()
        self.assertEqual(handle(requested_at_provider, first).status, 200)
        self.assertEqual(handle(requested_at_provider, requested_at_conflict).status, 409)

    def test_exact_s9_source_reconciles_bounded_retry_without_identity_collision(self) -> None:
        fixed_requested_at = (
            datetime.fromtimestamp(NOW / 1000, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        standalone_credential = S9_SCENARIO.daemon_credential(S9_SCENARIO.RUN_ID)
        retry_credential = S9_SCENARIO.daemon_credential(S9_SCENARIO.RETRY_RUN_ID)
        standalone = S9_SCENARIO.s9_standalone_success_action_request(
            standalone_credential,
            requested_at=fixed_requested_at,
            action_id="55555555-5555-4555-8555-555555559800",
            causal_trace_id="55555555-5555-4555-8555-555555559700",
        )
        retries = [
            S9_SCENARIO.s9_bounded_retry_action_request(
                retry_credential,
                retry_attempt=attempt,
                requested_at=fixed_requested_at,
                action_id=f"55555555-5555-4555-8555-5555555598{attempt:02d}",
                causal_trace_id=f"55555555-5555-4555-8555-5555555597{attempt:02d}",
            )
            for attempt in S9_SCENARIO.S9_BOUNDED_RETRY_ATTEMPTS
        ]

        self.assertEqual(standalone["action"]["params"]["retry_attempt"], 1)
        self.assertEqual(
            [request["action"]["params"]["retry_attempt"] for request in retries],
            [1, 2, 3],
        )
        self.assertNotEqual(
            standalone["action"]["params"]["idempotency_key"],
            retries[0]["action"]["params"]["idempotency_key"],
        )
        self.assertEqual(
            {request["requested_at"] for request in retries},
            {fixed_requested_at},
        )
        self.assertEqual(
            {request["audit_attribution"]["requested_at"] for request in retries},
            {fixed_requested_at},
        )

        def canonical_provider_request(
            source: dict[str, Any], request_id: str, issued_at: int
        ) -> dict[str, Any]:
            requested_at = datetime.fromisoformat(
                source["requested_at"].replace("Z", "+00:00")
            )
            requested_at_ms = int(requested_at.timestamp() * 1000)
            operation = OPERATION_MANIFEST.by_pair[
                (source["adapter"], source["action"]["name"])
            ]
            request = make_request(
                operation["operation_id"],
                run_id=source["run_id"],
                action_id=source["action_id"],
                request_id=request_id,
                issued_at=issued_at,
                action_requested_at=requested_at_ms,
                params=copy.deepcopy(source["action"]["params"]),
            )
            self.assertEqual(request["action"], source["action"])
            self.assertEqual(
                request["action_requested_at_unix_nanos"],
                str(requested_at_ms * 1_000_000),
            )
            return request

        requests = [
            canonical_provider_request(
                standalone,
                "66666666-6666-4666-8666-666666669800",
                NOW,
            ),
            *[
                canonical_provider_request(
                    source,
                    f"66666666-6666-4666-8666-6666666698{index:02d}",
                    NOW + index,
                )
                for index, source in enumerate(retries, start=1)
            ],
        ]
        self.assertEqual(
            {request["action_requested_at_unix_nanos"] for request in requests[1:]},
            {str(NOW * 1_000_000)},
        )
        self.assertNotEqual(requests[0]["idempotency_key"], requests[1]["idempotency_key"])
        self.assertEqual(requests[1]["idempotency_key"], requests[2]["idempotency_key"])
        self.assertEqual(requests[1]["semantic_digest"], requests[2]["semantic_digest"])

        provider = runtime()
        responses = [handle(provider, request) for request in requests]
        self.assertEqual([response.status for response in responses], [200, 200, 200, 401])
        self.assertEqual(
            response_json(responses[3])["error"],
            "operation_params_invalid",
        )
        payloads = [receipt_payload(response) for response in responses[:3]]
        self.assertEqual([payload["status"] for payload in payloads], ["read", "read", "reconciled"])
        self.assertNotEqual(payloads[0]["effect_id"], payloads[1]["effect_id"])
        self.assertEqual(payloads[1]["effect_id"], payloads[2]["effect_id"])
        self.assertNotEqual(payloads[0]["idempotency_key"], payloads[1]["idempotency_key"])
        self.assertEqual(payloads[1]["idempotency_key"], payloads[2]["idempotency_key"])

        self.assertEqual(provider.state["effects_applied"], 2)
        self.assertEqual(len(provider.state["effects"]), 2)
        self.assertEqual(len(provider.state["idempotency"]), 2)
        self.assertEqual(len(provider.state["invocations"]), 3)
        self.assertEqual(len(provider.state["actions"]), 3)
        self.assertEqual(len(provider.state["receipts"]), 3)
        self.assertEqual(provider.state["requests_total"], 3)
        self.assertEqual(provider.state["authenticated_requests"], 3)
        self.assertEqual(provider.state["successful"], 3)
        self.assertEqual(provider.state["failed"], 0)
        self.assertEqual(provider.state["by_action"], {standalone["action"]["name"]: 3})
        self.assertEqual(
            [row["effect_applied"] for row in provider.state["actions"]],
            [True, True, False],
        )

    def test_semantic_retry_required_marker_allows_every_companion_combination(self) -> None:
        operation = OPERATION_MANIFEST.by_operation_id[
            "acceptance-fixture/s9.idempotent_read"
        ]
        marker = operation["idempotency"]["required_retry_marker"]
        companions = [
            "action_id",
            "request_id",
            "issued_at_unix_ms",
            "deadline_unix_ms",
        ]
        self.assertEqual(marker["path"], "action.params.retry_attempt")
        self.assertEqual(
            operation["idempotency"]["external_idempotency_identity_field"],
            "action.params.idempotency_key",
        )
        self.assertEqual(
            set(operation["idempotency"]["retry_varying_fields"]),
            {*companions, marker["path"]},
        )

        for mask in range(1 << len(companions)):
            varied = {
                field for index, field in enumerate(companions) if mask & (1 << index)
            }
            with self.subTest(varied=sorted(varied)):
                provider = runtime()
                first = make_request("acceptance-fixture/s9.idempotent_read")
                first_response = handle(provider, first)
                self.assertEqual(first_response.status, 200)

                retry = copy.deepcopy(first)
                retry["action"]["params"]["retry_attempt"] = marker["reconciled"]
                if "action_id" in varied:
                    retry["action_id"] = "55555555-5555-4555-8555-555555555556"
                if "request_id" in varied:
                    retry["request_id"] = "66666666-6666-4666-8666-666666666667"
                if "issued_at_unix_ms" in varied:
                    retry["issued_at_unix_ms"] += 1
                if "deadline_unix_ms" in varied:
                    retry["deadline_unix_ms"] += 1
                retry = finalize_request(retry)

                retried = handle(provider, retry)
                self.assertEqual(retried.status, 200)
                self.assertEqual(receipt_payload(retried)["status"], "reconciled")
                self.assertEqual(provider.state["effects_applied"], 1)
                self.assertEqual(len(provider.state["effects"]), 1)

    def test_semantic_retry_unlisted_fields_conflict_and_external_key_is_identity(self) -> None:
        operation_id = "acceptance-fixture/s9.idempotent_read"

        def retry_from(first: dict[str, Any]) -> dict[str, Any]:
            retry = copy.deepcopy(first)
            retry["action"]["params"]["retry_attempt"] = 2
            return retry

        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "action_requested_at_unix_nanos": lambda request: request.__setitem__(
                "action_requested_at_unix_nanos", str((NOW + 1) * 1_000_000)
            ),
            "agent_id": lambda request: request.__setitem__(
                "agent_id", "22222222-2222-4222-8222-222222222223"
            ),
            "run_id": lambda request: request.__setitem__(
                "run_id", "44444444-4444-4444-8444-444444444445"
            ),
            "tick_id": lambda request: request.__setitem__(
                "tick_id", "77777777-7777-4777-8777-777777777777"
            ),
            "missing_max_attempts": lambda request: request["action"]["params"].pop(
                "max_attempts"
            ),
            "missing_retryable": lambda request: request["action"]["params"].pop(
                "retryable"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                provider = runtime()
                first = make_request(operation_id)
                self.assertEqual(handle(provider, first).status, 200)
                retry = retry_from(first)
                mutate(retry)
                response = handle(provider, finalize_request(retry))
                self.assertEqual(response.status, 409)
                self.assertEqual(provider.state["effects_applied"], 1)

        provider = runtime()
        first = make_request(operation_id)
        first_response = handle(provider, first)
        separate_identity = copy.deepcopy(first)
        separate_identity["request_id"] = "66666666-6666-4666-8666-666666666699"
        separate_identity["action_id"] = "55555555-5555-4555-8555-555555555599"
        separate_identity["action"]["params"]["idempotency_key"] = "another-read"
        separate_identity = finalize_request(separate_identity)
        second_response = handle(provider, separate_identity)
        self.assertEqual(second_response.status, 200)
        self.assertNotEqual(
            receipt_payload(first_response)["effect_id"],
            receipt_payload(second_response)["effect_id"],
        )
        self.assertEqual(provider.state["effects_applied"], 2)

        invalid_reconcile = copy.deepcopy(separate_identity)
        invalid_reconcile["request_id"] = "66666666-6666-4666-8666-666666666698"
        invalid_reconcile["action_id"] = "55555555-5555-4555-8555-555555555598"
        invalid_reconcile["action"]["params"]["idempotency_key"] = "third-read"
        invalid_reconcile["action"]["params"]["retry_attempt"] = 2
        self.assertEqual(handle(provider, finalize_request(invalid_reconcile)).status, 409)
        self.assertEqual(provider.state["effects_applied"], 2)

    def test_semantic_retry_material_removes_only_manifest_declared_paths(self) -> None:
        request = make_request("acceptance-fixture/s9.idempotent_read")
        operation = OPERATION_MANIFEST.by_operation_id[
            "acceptance-fixture/s9.idempotent_read"
        ]
        baseline = semantic_material(request, operation)
        varying = set(operation["idempotency"]["retry_varying_fields"])
        derived = {"idempotency_key", "semantic_digest", "request_body_digest"}

        def leaves(value: Any, prefix: str = "") -> list[str]:
            result: list[str] = []
            if isinstance(value, dict):
                for key, child in value.items():
                    path = f"{prefix}.{key}" if prefix else key
                    if isinstance(child, dict):
                        result.extend(leaves(child, path))
                    else:
                        result.append(path)
            return result

        def change(value: Any) -> Any:
            if value is None:
                return "changed"
            if isinstance(value, bool):
                return not value
            if type(value) is int:
                return value + 1
            if isinstance(value, str):
                return value + "-changed"
            if isinstance(value, list):
                return [*value, "changed"]
            raise AssertionError(type(value))

        for path in leaves(request):
            top = path.split(".", 1)[0]
            if top in derived:
                continue
            changed = copy.deepcopy(request)
            parent: Any = changed
            parts = path.split(".")
            for part in parts[:-1]:
                parent = parent[part]
            parent[parts[-1]] = change(parent[parts[-1]])
            material = semantic_material(changed, operation)
            if path in varying:
                self.assertEqual(material, baseline, path)
            else:
                self.assertNotEqual(material, baseline, path)

    def test_controlled_failure_duplicate_signer_failure_and_capacity_fail_closed(self) -> None:
        provider = runtime()
        request = make_request("acceptance-fixture/s9.adapter_failure")
        first = handle(provider, request)
        duplicate = handle(provider, request)
        self.assertEqual(first.status, 503)
        self.assertEqual(duplicate.status, 503)
        self.assertEqual(first.body, duplicate.body)
        self.assertEqual(provider.state["effects_applied"], 0)
        self.assertEqual(len(provider.state["actions"]), 1)
        self.assertEqual(provider.state["duplicates"], 1)

        signer_provider = runtime(signer=failing_signer)
        signer_response = handle(signer_provider, make_request())
        self.assertEqual(signer_response.status, 503)
        self.assertEqual(signer_provider.state["effects_applied"], 0)
        self.assertEqual(signer_provider.state["invocations"], {})

        capacity_provider = runtime()
        existing_request = make_request()
        existing = handle(capacity_provider, existing_request)
        self.assertEqual(existing.status, 200)
        for index in range(255):
            capacity_provider.state["invocations"][f"capacity-{index}"] = {
                "status": 503,
                "body": b"{}",
            }
        duplicate_existing = handle(capacity_provider, existing_request)
        self.assertEqual(duplicate_existing.body, existing.body)
        new_request = make_request(
            action_id="55555555-5555-4555-8555-555555555558",
            request_id="66666666-6666-4666-8666-666666666669",
        )
        capacity = handle(capacity_provider, new_request)
        self.assertEqual(capacity.status, 503)
        self.assertEqual(response_json(capacity)["error"], "provider_capacity_exhausted")
        self.assertEqual(capacity_provider.state["effects_applied"], 1)

    def test_principal_ledger_and_concurrency_reserves_preserve_other_roles(self) -> None:
        provider = runtime()
        first_request: dict[str, Any] | None = None
        first_response: action_provider.ProviderResponse | None = None
        for _ in range(OPERATION_MANIFEST.limits["max_principal_ledger_entries"]):
            request = make_request(
                "acceptance-fixture/s9.adapter_failure",
                action_id=str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
            )
            response = handle(provider, request)
            self.assertEqual(response.status, 503)
            if first_request is None:
                first_request, first_response = request, response
        denied = handle(
            provider,
            make_request(
                "acceptance-fixture/s9.adapter_failure",
                action_id=str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
            ),
        )
        self.assertEqual(
            response_json(denied)["error"], "provider_principal_capacity_exhausted"
        )
        assert first_request is not None and first_response is not None
        self.assertEqual(handle(provider, first_request).body, first_response.body)
        self.assertEqual(handle(provider, make_request("device-sim/read_battery")).status, 200)

        concurrent = runtime()
        local = ROLE_BINDINGS["local"][1]
        held = [
            concurrent._principal_admission[local].acquire(blocking=False)  # noqa: SLF001
            for _ in range(OPERATION_MANIFEST.limits["max_principal_active_requests"])
        ]
        try:
            response = handle(concurrent, make_request())
            self.assertEqual(response.status, 503)
            self.assertEqual(
                response_json(response)["error"],
                "provider_principal_concurrency_exhausted",
            )
            self.assertEqual(
                handle(concurrent, make_request("device-sim/read_battery")).status,
                200,
            )
        finally:
            for acquired in held:
                if acquired:
                    concurrent._principal_admission[local].release()  # noqa: SLF001

    def test_subprocess_signer_rejects_replacement_links_flood_and_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            private = root / "private.pk8"
            private.write_bytes(b"k" * 32)
            private.chmod(0o600)

            def script(path: Path, body: str) -> None:
                path.write_text("#!/bin/sh\n" + body + "\n", encoding="ascii")
                path.chmod(0o700)

            executable = root / "signer"
            script(executable, "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\"*64)' ")
            signer = action_provider.SubprocessSigner(executable, private)
            self.assertEqual(signer(b"frame"), b"x" * 64)

            executable.unlink()
            script(executable, "python3 -c 'import sys; sys.stdout.buffer.write(b\"y\"*64)' ")
            with self.assertRaises(ProtocolError):
                signer(b"frame")

            link_target = root / "link-target"
            script(link_target, "exit 0")
            symlink = root / "symlink"
            symlink.symlink_to(link_target)
            with self.assertRaises(ProtocolError):
                action_provider.SubprocessSigner(symlink, private)
            hardlink = root / "hardlink"
            os.link(link_target, hardlink)
            with self.assertRaises(ProtocolError):
                action_provider.SubprocessSigner(link_target, private)

            flood = root / "flood"
            script(flood, "python3 -c 'import sys; sys.stdout.buffer.write(b\"z\"*100000)' ")
            with self.assertRaisesRegex(ProtocolError, "signer_output_oversized"):
                action_provider.SubprocessSigner(flood, private)(b"frame")

            timeout = root / "timeout"
            script(timeout, "sleep 5")
            with mock.patch.object(action_provider, "SIGNER_TIMEOUT_SECONDS", 0.05):
                with self.assertRaisesRegex(ProtocolError, "signer_timeout"):
                    action_provider.SubprocessSigner(timeout, private)(b"frame")

            orphan_pid_file = root / "orphan.pid"
            orphan = root / "orphan"
            script(
                orphan,
                f"sleep 5 & printf '%s' \"$!\" > \"{orphan_pid_file}\"; exit 0",
            )
            with mock.patch.object(action_provider, "SIGNER_TIMEOUT_SECONDS", 0.05):
                with self.assertRaisesRegex(ProtocolError, "signer_timeout"):
                    action_provider.SubprocessSigner(orphan, private)(b"frame")
            orphan_pid = int(orphan_pid_file.read_text(encoding="ascii"))
            for _ in range(100):
                try:
                    os.kill(orphan_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail("timed-out signer descendant remained alive")

    def test_restart_changes_epoch_and_old_captured_request_is_rejected(self) -> None:
        old = runtime(epoch=EPOCH)
        captured = make_request(provider_epoch=EPOCH)
        self.assertEqual(handle(old, captured).status, 200)
        restarted = runtime(epoch="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2")
        before = copy.deepcopy(restarted.state)
        response = handle(restarted, captured)
        self.assertEqual(response.status, 401)
        self.assertEqual(restarted.state, before)

    def test_evidence_auth_nonce_replay_signature_shape_bounds_and_secret_absence(self) -> None:
        provider = runtime()
        self.assertEqual(handle(provider, make_request()).status, 200)
        key = next(iter(provider.evidence_keys.values()))
        nonce = "AAECAwQFBgcICQoLDA0ODw"
        auth = {
            "method": "GET",
            "path": "/evidence",
            "query": "view=bounded",
            "view": "bounded",
            "timestamp_unix_ms": NOW,
            "nonce": nonce,
            "audience": key.audience,
            "key_id": key.key_id,
            "client_principal_id": key.client_principal_id,
            "provider_epoch": EPOCH,
        }
        signature = evidence_auth_signature(auth, key.secret)
        response = provider.handle_evidence(
            method="GET",
            target=action_provider.EVIDENCE_PATH,
            key_id=key.key_id,
            client_principal_id=key.client_principal_id,
            audience=key.audience,
            timestamp_ms=NOW,
            nonce=nonce,
            provider_epoch=EPOCH,
            view="bounded",
            signature=signature,
            now_ms=NOW,
        )
        self.assertEqual(response.status, 200)
        envelope = response_json(response)
        self.assertEqual(envelope["algorithm"], "Ed25519")
        payload = strict_loads(
            b64url_decode(envelope["payload_b64"]),
            max_bytes=OPERATION_MANIFEST.limits["max_evidence_bytes"],
            max_fields=8192,
            max_array_items=256,
            require_canonical=True,
        )
        self.assertEqual(payload["effects_applied"], 1)
        serialized = json.dumps(payload, sort_keys=True).lower()
        for forbidden in ("secret_b64", "private_key", "request_signature"):
            self.assertNotIn(forbidden, serialized)
        replay = provider.handle_evidence(
            method="GET",
            target=action_provider.EVIDENCE_PATH,
            key_id=key.key_id,
            client_principal_id=key.client_principal_id,
            audience=key.audience,
            timestamp_ms=NOW,
            nonce=nonce,
            provider_epoch=EPOCH,
            view="bounded",
            signature=signature,
            now_ms=NOW,
        )
        self.assertEqual(replay.status, 409)
        denied = provider.handle_evidence(
            method="GET",
            target=action_provider.EVIDENCE_PATH,
            key_id=key.key_id,
            client_principal_id=key.client_principal_id,
            audience=key.audience,
            timestamp_ms=NOW,
            nonce="AQECAwQFBgcICQoLDA0ODw",
            provider_epoch=EPOCH,
            view="bounded",
            signature="forged",
            now_ms=NOW,
        )
        self.assertEqual(denied.status, 401)

        bounded = runtime()
        bounded.state["actions"] = [{"index": index} for index in range(256)]
        bounded_key = next(iter(bounded.evidence_keys.values()))

        def bounded_read(nonce_value: str) -> action_provider.ProviderResponse:
            value = {
                "method": "GET",
                "path": "/evidence",
                "query": "view=bounded",
                "view": "bounded",
                "timestamp_unix_ms": NOW,
                "nonce": nonce_value,
                "audience": bounded_key.audience,
                "key_id": bounded_key.key_id,
                "client_principal_id": bounded_key.client_principal_id,
                "provider_epoch": EPOCH,
            }
            return bounded.handle_evidence(
                method="GET",
                target=action_provider.EVIDENCE_PATH,
                key_id=bounded_key.key_id,
                client_principal_id=bounded_key.client_principal_id,
                audience=bounded_key.audience,
                timestamp_ms=NOW,
                nonce=nonce_value,
                provider_epoch=EPOCH,
                view="bounded",
                signature=evidence_auth_signature(value, bounded_key.secret),
                now_ms=NOW,
            )

        self.assertEqual(bounded_read("AgECAwQFBgcICQoLDA0ODw").status, 200)
        bounded.state["actions"].append({"index": 256})
        over_bound = bounded_read("AwECAwQFBgcICQoLDA0ODw")
        self.assertEqual(over_bound.status, 503)
        self.assertEqual(response_json(over_bound)["error"], "json_array_items_exceeded")

    def test_evidence_authentication_attack_matrix_denies_before_nonce_state(self) -> None:
        def attempt(
            label: str,
            *,
            mutate: Callable[[dict[str, Any]], None],
            use_action_key: bool = False,
        ) -> None:
            provider = runtime()
            evidence_key = next(iter(provider.evidence_keys.values()))
            nonce = b64url_encode(hashlib.sha256(label.encode("ascii")).digest()[:16])
            values = {
                "method": "GET",
                "target": action_provider.EVIDENCE_PATH,
                "key_id": evidence_key.key_id,
                "client_principal_id": evidence_key.client_principal_id,
                "audience": evidence_key.audience,
                "timestamp_ms": NOW,
                "nonce": nonce,
                "provider_epoch": EPOCH,
                "view": "bounded",
            }
            mutate(values)
            auth = {
                "method": values["method"],
                "path": "/evidence",
                "query": "view=bounded",
                "view": values["view"],
                "timestamp_unix_ms": values["timestamp_ms"],
                "nonce": values["nonce"],
                "audience": values["audience"],
                "key_id": values["key_id"],
                "client_principal_id": values["client_principal_id"],
                "provider_epoch": values["provider_epoch"],
            }
            secret = (
                next(iter(provider.request_keys.values())).secret
                if use_action_key
                else evidence_key.secret
            )
            signature = evidence_auth_signature(auth, secret)
            before = copy.deepcopy(provider.state)
            response = provider.handle_evidence(
                **values,
                signature=signature,
                now_ms=NOW,
            )
            self.assertEqual(response.status, 401, label)
            self.assertEqual(provider.state, before, label)

        cases = {
            "anonymous": lambda value: value.update(
                key_id="", client_principal_id="", audience="", nonce=""
            ),
            "wrong_key": lambda value: value.update(key_id="wrong-evidence-key"),
            "wrong_principal": lambda value: value.update(
                client_principal_id="wrong-reader"
            ),
            "wrong_audience": lambda value: value.update(audience="wrong-audience"),
            "wrong_method": lambda value: value.update(method="POST"),
            "wrong_path_query": lambda value: value.update(
                target="/evidence?view=unbounded"
            ),
            "wrong_view": lambda value: value.update(view="unbounded"),
            "stale": lambda value: value.update(timestamp_ms=NOW - 5_001),
            "future": lambda value: value.update(timestamp_ms=NOW + 5_001),
            "wrong_epoch": lambda value: value.update(
                provider_epoch="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                attempt(label, mutate=mutate)
        attempt("action_key", mutate=lambda _: None, use_action_key=True)

    def test_oversized_request_is_rejected_without_mutation(self) -> None:
        provider = runtime()
        before = copy.deepcopy(provider.state)
        body = b"x" * (OPERATION_MANIFEST.limits["max_request_bytes"] + 1)
        response = provider.handle_action(body, "any", "any", now_ms=NOW)
        self.assertEqual(response.status, 401)
        self.assertEqual(provider.state, before)

    def test_server_worker_admission_and_socket_timeout_are_bounded(self) -> None:
        server = action_provider.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), runtime()
        )
        client = socket.create_connection(server.server_address, timeout=1)
        accepted, _ = server.get_request()
        try:
            self.assertEqual(accepted.gettimeout(), action_provider.SOCKET_TIMEOUT_SECONDS)
        finally:
            accepted.close()
            client.close()
        acquired = [
            server._admission.acquire(blocking=False)  # noqa: SLF001 - fixed admission contract
            for _ in range(OPERATION_MANIFEST.limits["max_active_requests"])
        ]
        self.assertTrue(all(acquired))
        self.assertFalse(server._admission.acquire(blocking=False))  # noqa: SLF001
        for _ in acquired:
            server._admission.release()  # noqa: SLF001
        server.server_close()


if __name__ == "__main__":
    unittest.main()
