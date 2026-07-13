#!/usr/bin/env python3
"""Generate ephemeral acceptance-only resident trust and caller tokens.

Nothing produced by this helper is production key material. The fixture keeps
private values in an untracked Docker volume and emits caller tokens only to the
requesting acceptance process.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ISSUER = "urn:splendor:manager:central-manager"
APP_PRINCIPAL_ID = "central-manager"
CLIENT_PRINCIPAL_ID = "resident-dispatch-client"
KEY_ID = "manager-resident-acceptance"
WORK_ORDER_KEYS = {
    "00000000-0000-4000-8000-000000000302": "work-order-acceptance-vpc",
    "00000000-0000-4000-8000-000000000304": "work-order-acceptance-cloud",
    "00000000-0000-4000-8000-000000000306": "work-order-acceptance-edge",
}
JTI_CORRELATION_DOMAIN = b"splendor.resident.caller-jti-correlation.v1\0"
SCOPE_VALUES = {
    "runs_create": "splendor.runs.create",
    "runs_start": "splendor.runs.start",
    "runs_read": "splendor.runs.read",
    "state_read": "splendor.state.read",
    "state_handoff": "splendor.state.handoff",
    "traces_read": "splendor.traces.read",
    "replay_create": "splendor.replay.create",
    "health_read": "splendor.health.read",
}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def write_json(path: Path, value: object, *, private: bool = False) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600 if private else 0o644)


def openssl(*args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("acceptance fixture OpenSSL command failed")
    return result.stdout


def key_tool(*args: str, input_bytes: bytes | None = None) -> bytes:
    executable = shutil.which("resident_auth_key_tool")
    if executable is None:
        raise SystemExit("acceptance resident key tool is unavailable")
    result = subprocess.run(
        [executable, *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("acceptance resident key operation failed")
    return result.stdout


def initialize(manager_out: Path, runner_out: Path, resident_outs: dict[str, Path]) -> None:
    outputs = [manager_out, runner_out, *resident_outs.values()]
    for out in outputs:
        out.mkdir(parents=True, exist_ok=True, mode=0o700)
        out.chmod(0o700)

    caller_key = manager_out / "caller-signing-key.pk8"
    caller_public_key = manager_out / "caller-public-key.raw"
    key_tool("generate", str(caller_key), str(caller_public_key))
    caller_key.chmod(0o600)
    caller_public_key.chmod(0o644)
    shutil.copy2(caller_key, runner_out / caller_key.name)
    (runner_out / caller_key.name).chmod(0o600)
    public_key = caller_public_key.read_bytes()
    if len(public_key) != 32:
        raise SystemExit("acceptance caller public key was malformed")

    now = datetime.now(timezone.utc)
    trust = {
        "schema_version": "splendor.caller_trust.v1",
        "revision": 1,
        "issued_at": utc(now - timedelta(minutes=1)),
        "expires_at": utc(now + timedelta(hours=23, minutes=59)),
        "issuer": ISSUER,
        "app_principal_id": APP_PRINCIPAL_ID,
        "max_token_ttl_seconds": 300,
        "allowed_scopes": list(SCOPE_VALUES.values()),
        "keys": [
            {
                "kid": KEY_ID,
                "algorithm": "Ed25519",
                "public_key": b64url(public_key),
                "status": "active",
            }
        ],
        "revoked_jtis": [],
    }
    for out in resident_outs.values():
        write_json(out / "caller-trust.json", trust)

    manager_keys: list[dict[str, str]] = []
    for instance_id, key_id in WORK_ORDER_KEYS.items():
        resident_out = resident_outs.get(instance_id)
        if resident_out is None:
            raise SystemExit(f"missing resident fixture output for {instance_id}")
        work_order_secret = secrets.token_urlsafe(32)
        write_private(
            runner_out / f"work-order-signing-{instance_id}.secret",
            work_order_secret.encode("ascii"),
        )
        key = {
            "key_id": key_id,
            "shared_secret_base64url": b64url(work_order_secret.encode("ascii")),
        }
        manager_keys.append(key)
        write_json(
            resident_out / "work-order-keyring.json",
            {"schema_version": "splendor.work_order_keyring.v1", "keys": [key]},
            private=True,
        )
    write_json(
        manager_out / "work-order-keyring.json",
        {
            "schema_version": "splendor.work_order_keyring.v1",
            "keys": manager_keys,
        },
        private=True,
    )
    for instance_id, out in resident_outs.items():
        write_json(
            out / "policy-keyring.json",
            {
                "schema_version": "splendor.policy_keyring.v1",
                "keys": [
                    {
                        "key_id": f"policy-acceptance-{instance_id}",
                        "shared_secret_base64url": b64url(secrets.token_bytes(32)),
                    }
                ],
            },
            private=True,
        )

    with tempfile.TemporaryDirectory(prefix="splendor-resident-tls-") as temp:
        tls_key = Path(temp) / "resident-tls-key.pem"
        tls_cert = Path(temp) / "resident-tls-cert.pem"
        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(tls_key),
            "-out",
            str(tls_cert),
            "-days",
            "1",
            "-subj",
            "/CN=splendor-resident-acceptance",
            "-addext",
            "subjectAltName=DNS:resident-cloud-node,DNS:resident-vpc-node,DNS:resident-edge-node,DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-addext",
            "extendedKeyUsage=serverAuth",
        )
        for out in [manager_out, runner_out, *resident_outs.values()]:
            shutil.copy2(tls_cert, out / "resident-tls-cert.pem")
            (out / "resident-tls-cert.pem").chmod(0o644)
        for out in resident_outs.values():
            shutil.copy2(tls_key, out / "resident-tls-key.pem")
            (out / "resident-tls-key.pem").chmod(0o600)


def token(auth_dir: Path, tenant_id: str, instance_id: str, scopes: list[str]) -> None:
    if not scopes or len(scopes) != len(set(scopes)) or any(scope not in SCOPE_VALUES for scope in scopes):
        raise SystemExit("acceptance caller scopes were invalid")
    uuid.UUID(tenant_id)
    uuid.UUID(instance_id)
    now = int(datetime.now(timezone.utc).timestamp())
    expires = now + 60
    jti = str(uuid.uuid4())
    header = {"alg": "Ed25519", "kid": KEY_ID, "typ": "splendor-caller+jwt"}
    claims = {
        "iss": ISSUER,
        "sub": CLIENT_PRINCIPAL_ID,
        "aud": f"urn:splendor:instance:{instance_id}",
        "iat": now,
        "nbf": now,
        "exp": expires,
        "jti": jti,
        "splendor_ver": 1,
        "app_principal_id": APP_PRINCIPAL_ID,
        "tenant_id": tenant_id,
        "scope": [SCOPE_VALUES[scope] for scope in scopes],
    }
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_claims = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = key_tool("sign", str(auth_dir / "caller-signing-key.pk8"), input_bytes=signing_input)
    if len(signature) != 64:
        raise SystemExit("acceptance caller signature was malformed")
    credential = {
        "credential_id": "sha256:" + hashlib.sha256(JTI_CORRELATION_DOMAIN + jti.encode("ascii")).hexdigest(),
        "principal": {
            "app": {"app_principal_id": APP_PRINCIPAL_ID, "label": None},
            "client_principal_id": CLIENT_PRINCIPAL_ID,
            "label": None,
        },
        "scopes": scopes,
        "binding": {"tenant": {"tenant_id": tenant_id}},
        "audience": {"instance": {"instance_id": instance_id}},
        "expires_at": utc(datetime.fromtimestamp(expires, timezone.utc)),
        "revocation": "active",
    }
    print(
        json.dumps(
            {
                "token": f"{encoded_header}.{encoded_claims}.{b64url(signature)}",
                "credential": credential,
            },
            separators=(",", ":"),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--manager-out", required=True)
    init_parser.add_argument("--runner-out", required=True)
    init_parser.add_argument("--vpc-out", required=True)
    init_parser.add_argument("--cloud-out", required=True)
    init_parser.add_argument("--edge-out", required=True)
    token_parser = subparsers.add_parser("token")
    token_parser.add_argument("--auth-dir", required=True)
    token_parser.add_argument("--tenant-id", required=True)
    token_parser.add_argument("--instance-id", required=True)
    token_parser.add_argument("--scope", action="append", required=True)
    args = parser.parse_args()
    if args.command == "init":
        initialize(
            Path(args.manager_out),
            Path(args.runner_out),
            {
                "00000000-0000-4000-8000-000000000302": Path(args.vpc_out),
                "00000000-0000-4000-8000-000000000304": Path(args.cloud_out),
                "00000000-0000-4000-8000-000000000306": Path(args.edge_out),
            },
        )
    else:
        token(Path(args.auth_dir), args.tenant_id, args.instance_id, args.scope)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
