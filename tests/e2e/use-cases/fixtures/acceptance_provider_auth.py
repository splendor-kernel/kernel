#!/usr/bin/env python3
"""Generate role-separated private-v3 acceptance provider credentials."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import subprocess
import time
from pathlib import Path

from acceptance_provider_protocol import (
    EVIDENCE_CREDENTIAL_SCHEMA,
    EVIDENCE_KEYRING_SCHEMA,
    OPERATION_MANIFEST,
    REQUEST_CREDENTIAL_SCHEMA,
    REQUEST_KEYRING_SCHEMA,
    SIGNING_KEY_ID,
    TENANT_A,
    b64url_encode,
    canonical_bytes,
)


ROLE_BINDINGS = {
    "local": {
        "key_id": "acceptance-request-local-v3",
        "client_principal_id": "acceptance-host-local",
        "source_instance_id": "00000000-0000-4000-8000-000000000300",
    },
    "cloud": {
        "key_id": "acceptance-request-cloud-v3",
        "client_principal_id": "acceptance-host-cloud",
        "source_instance_id": "00000000-0000-4000-8000-000000000304",
    },
    "vpc": {
        "key_id": "acceptance-request-vpc-v3",
        "client_principal_id": "acceptance-host-vpc",
        "source_instance_id": "00000000-0000-4000-8000-000000000302",
    },
    "edge": {
        "key_id": "acceptance-request-edge-v3",
        "client_principal_id": "acceptance-host-edge",
        "source_instance_id": "00000000-0000-4000-8000-000000000306",
    },
}
EVIDENCE_AUDIENCE = "splendor.acceptance.action-provider.evidence.v3"
EVIDENCE_KEY_ID = "acceptance-evidence-runner-v3"
EDGE_NODE_ID = "00000000-0000-4000-8000-000000000604"


def resource_scopes_for_role(role: str) -> list[dict[str, str]]:
    default_internal = f"artifact://{TENANT_A}/internal.md"
    default_published = f"artifact://{TENANT_A}/published.md"
    artifact_refs = {
        "local": {
            "artifact-store/artifact.create_internal": [
                default_internal,
                f"artifact://{TENANT_A}/governance/uc-e2e-s5.md",
            ],
            "artifact-store/artifact.publish_external": [
                default_published,
                f"artifact://{TENANT_A}/governance/uc-e2e-s5.md",
            ],
        },
        "cloud": {
            "artifact-store/artifact.create_internal": [default_internal],
            "artifact-store/artifact.publish_external": [default_published],
        },
        "vpc": {
            "artifact-store/artifact.create_internal": [
                default_internal,
                f"artifact://{TENANT_A}/board/specialist-analysis.md",
                f"artifact://{TENANT_A}/field-intelligence/s10-internal.md",
            ],
            "artifact-store/artifact.publish_external": [
                default_published,
                f"artifact://{TENANT_A}/board/report.md",
                f"artifact://{TENANT_A}/field-intelligence/s10-public.md",
            ],
        },
    }
    scopes: list[dict[str, str]] = []
    for operation_id, references in artifact_refs.get(role, {}).items():
        scopes.extend(
            {
                "operation_id": operation_id,
                "resource_kind": "artifact_ref",
                "resource_id": reference,
            }
            for reference in references
        )
    if role == "vpc":
        scopes.extend(
            {
                "operation_id": "fixture-data-store/data.read_fixture",
                "resource_kind": "data_ref",
                "resource_id": reference,
            }
            for reference in (
                "dataset:tenant-a.finance.v1",
                "dataset:tenant-a.finance.board_pack.v1",
                "dataset:tenant-a.field-intel.fixture.v1",
            )
        )
    if role == "edge":
        scopes.extend(
            {
                "operation_id": operation["operation_id"],
                "resource_kind": "physical_node",
                "resource_id": EDGE_NODE_ID,
            }
            for operation in OPERATION_MANIFEST.value["operations"]
            if operation["coordinate_rule"] == "physical_node"
        )
    return sorted(
        scopes,
        key=lambda item: (
            item["operation_id"],
            item["resource_kind"],
            item["resource_id"],
        ),
    )


def _write(path: Path, data: bytes, mode: int) -> None:
    parent = path.parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_mode & 0o022
        or (hasattr(os, "geteuid") and parent.st_uid != os.geteuid())
    ):
        raise SystemExit("acceptance credential output parent is insecure")
    before = None
    try:
        before = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        pass
    if before is not None and (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
    ):
        raise SystemExit("acceptance credential output file is insecure")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
            or before is not None
            and (opened.st_dev != before.st_dev or opened.st_ino != before.st_ino)
        ):
            raise SystemExit("acceptance credential output changed during open")
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: object, *, private: bool) -> None:
    _write(path, canonical_bytes(value), 0o600 if private else 0o644)


def _key_tool(*args: str) -> None:
    executable = shutil.which("resident_auth_key_tool")
    if executable is None:
        raise SystemExit("acceptance resident key tool is unavailable")
    result = subprocess.run(
        [executable, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if result.returncode != 0:
        raise SystemExit("acceptance provider key generation failed")


def initialize(
    provider_out: Path,
    runner_out: Path,
    role_outs: dict[str, Path],
    *,
    roles: tuple[str, ...] | None = None,
) -> None:
    active_roles = tuple(sorted(roles or tuple(ROLE_BINDINGS)))
    if (
        not active_roles
        or set(active_roles) - set(ROLE_BINDINGS)
        or set(role_outs) != set(active_roles)
    ):
        raise SystemExit("acceptance provider role outputs are incomplete")
    outputs = [provider_out, runner_out, *role_outs.values()]
    for output in outputs:
        try:
            before = output.stat(follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is not None and (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (hasattr(os, "geteuid") and before.st_uid != os.geteuid())
        ):
            raise SystemExit("acceptance credential output directory is insecure")
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        output.chmod(0o700)
        opened = output.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or opened.st_mode & 0o077
            or (hasattr(os, "geteuid") and opened.st_uid != os.geteuid())
        ):
            raise SystemExit("acceptance credential output directory is insecure")

    private_key = provider_out / "receipt-signing-key.pk8"
    public_key = provider_out / "receipt-public-key.raw"
    _key_tool("generate", str(private_key), str(public_key))
    private_key.chmod(0o600)
    public_key.chmod(0o644)
    public_bytes = public_key.read_bytes()
    if len(public_bytes) != 32:
        raise SystemExit("acceptance provider public key was malformed")
    for output in [runner_out, *role_outs.values()]:
        _write(output / "receipt-public-key.raw", public_bytes, 0o644)

    now_ms = int(time.time() * 1000)
    not_before = now_ms - 60_000
    expires_at = now_ms + 86_400_000
    keyring_entries: list[dict[str, object]] = []
    generated_secrets: set[bytes] = set()

    def unique_secret() -> bytes:
        while True:
            secret = secrets.token_bytes(32)
            if secret not in generated_secrets:
                generated_secrets.add(secret)
                return secret

    for role in active_roles:
        binding = ROLE_BINDINGS[role]
        secret = unique_secret()
        operations = sorted(
            operation["operation_id"]
            for operation in OPERATION_MANIFEST.value["operations"]
            if role in operation["allowed_request_principals"]
        )
        common = {
            "key_id": binding["key_id"],
            "status": "active",
            "request_principal_role": role,
            "client_principal_id": binding["client_principal_id"],
            "source_instance_id": binding["source_instance_id"],
            "tenant_id": TENANT_A,
            "audience": OPERATION_MANIFEST.audience,
            "not_before_unix_ms": not_before,
            "expires_at_unix_ms": expires_at,
            "max_request_ttl_ms": OPERATION_MANIFEST.limits["max_request_ttl_ms"],
            "allowed_operation_ids": operations,
            "allowed_resource_scopes": resource_scopes_for_role(role),
        }
        credential = {
            "schema_version": REQUEST_CREDENTIAL_SCHEMA,
            **common,
            "secret_b64": b64url_encode(secret),
        }
        _write_json(
            role_outs[role] / "action-provider-request-credential.json",
            credential,
            private=True,
        )
        keyring_entries.append({**common, "secret_b64": b64url_encode(secret)})
    _write_json(
        provider_out / "action-provider-request-keyring.json",
        {
            "schema_version": REQUEST_KEYRING_SCHEMA,
            "profile_set_digest": OPERATION_MANIFEST.digest,
            "keys": sorted(keyring_entries, key=lambda entry: str(entry["key_id"])),
        },
        private=True,
    )

    evidence_secret = unique_secret()
    evidence_common = {
        "key_id": EVIDENCE_KEY_ID,
        "status": "active",
        "client_principal_id": "acceptance-e2e-runner",
        "audience": EVIDENCE_AUDIENCE,
        "not_before_unix_ms": not_before,
        "expires_at_unix_ms": expires_at,
        "max_request_age_ms": 5000,
    }
    _write_json(
        runner_out / "action-provider-evidence-credential.json",
        {
            "schema_version": EVIDENCE_CREDENTIAL_SCHEMA,
            **evidence_common,
            "secret_b64": b64url_encode(evidence_secret),
        },
        private=True,
    )
    _write_json(
        provider_out / "action-provider-evidence-keyring.json",
        {
            "schema_version": EVIDENCE_KEYRING_SCHEMA,
            "keys": [{**evidence_common, "secret_b64": b64url_encode(evidence_secret)}],
        },
        private=True,
    )
    _write_json(
        provider_out / "receipt-signing-metadata.json",
        {
            "schema_version": "splendor.acceptance.receipt_signing_metadata.v3",
            "algorithm": "Ed25519",
            "signing_key_id": SIGNING_KEY_ID,
            "public_key_b64": b64url_encode(public_bytes),
        },
        private=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-out", required=True)
    parser.add_argument("--runner-out", required=True)
    parser.add_argument("--local-out")
    parser.add_argument("--cloud-out")
    parser.add_argument("--vpc-out")
    parser.add_argument("--edge-out")
    parser.add_argument("--roles", default="local,cloud,vpc,edge")
    args = parser.parse_args()
    roles = tuple(sorted(set(args.roles.split(","))))
    outputs = {
        role: Path(value)
        for role, value in {
            "local": args.local_out,
            "cloud": args.cloud_out,
            "vpc": args.vpc_out,
            "edge": args.edge_out,
        }.items()
        if value is not None
    }
    initialize(
        Path(args.provider_out),
        Path(args.runner_out),
        outputs,
        roles=roles,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
