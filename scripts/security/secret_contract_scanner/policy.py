"""Closed scanner policy validation and exact exception registries."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .io_utils import RepositoryReader, safe_read_file
from .model import (
    DEFAULT_POLICY_PATH,
    FORMAT_KINDS,
    HARD_MAX_ARCHIVE_BYTES,
    HARD_MAX_ARCHIVE_MEMBERS,
    HARD_MAX_FILE_BYTES,
    HARD_MAX_FILES,
    HARD_MAX_FINDINGS,
    HARD_MAX_TOTAL_BYTES,
    HARD_MAX_PARSER_OPERATIONS,
    HARD_POLICY_BYTES,
    POLICY_SCHEMA,
    RULE_MESSAGES,
    SCANNER_VERSION,
    Finding,
    ScanDataError,
    bounded_plain_string,
    exact_keys,
    safe_policy_path,
)
from .structured import parse_json_bytes


GOVERNED_ROOT_INVENTORY: dict[str, tuple[str, dict[str, str]]] = {
    "c03-canonical-fixtures": (
        "crates/splendor-types/tests/fixtures/secrets",
        {".json": "json"},
    ),
    "driver-credential-sink-fixture": (
        "crates/splendor-types/tests/fixtures/driver/operation-credential-sinks-v1.json",
        {".json": "json"},
    ),
    "c03-foundation-conformance": (
        "conformance/0.2/c03-foundation/v1",
        {".json": "json", ".md": "markdown"},
    ),
    "stable-adapter-manifests": (
        "docs/spec/0.1/fixtures/adapter-manifests",
        {".json": "json"},
    ),
    "runtime-daemon-openapi": (
        "openapi/splendor-runtime-daemon.yaml",
        {".yaml": "yaml"},
    ),
    "openapi-external-surface": (
        "openapi",
        {".json": "json", ".yaml": "yaml", ".yml": "yaml"},
    ),
    "repository-examples": (
        "examples",
        {
            ".gitkeep": "empty",
            ".cjs": "typescript_source",
            ".json": "json",
            ".js": "typescript_source",
            ".jsx": "typescript_source",
            ".md": "markdown",
            ".mjs": "typescript_source",
            ".mts": "typescript_source",
            ".py": "python_source",
            ".ts": "typescript_source",
            ".tsx": "typescript_source",
            ".yaml": "yaml",
            ".yml": "yaml",
        },
    ),
    "python-sdk-external-surface": (
        "python/splendor",
        {".py": "python_source"},
    ),
    "python-package-manifest": (
        "python/pyproject.toml",
        {".toml": "config"},
    ),
    "typescript-packages-external-surface": (
        "typescript/packages",
        {
            ".cjs": "typescript_source",
            ".js": "typescript_source",
            ".json": "json",
            ".jsx": "typescript_source",
            ".mjs": "typescript_source",
            ".mts": "typescript_source",
            ".ts": "typescript_source",
            ".tsx": "typescript_source",
        },
    ),
    "typescript-types-external-surface": (
        "typescript/packages/types/src",
        {".ts": "typescript_source"},
    ),
    "typescript-client-external-surface": (
        "typescript/packages/client/src",
        {".ts": "typescript_source"},
    ),
    "gold-example-catalog": (
        "docs/rules/v2/gold/examples",
        {".json": "json", ".md": "markdown", ".yaml": "yaml", ".yml": "yaml"},
    ),
}

SOURCE_OWNER_EXPORT_INVENTORY: tuple[
    tuple[str, str, str, str, str, str, tuple[str, ...]], ...
] = (
    (
        "typescript",
        "@splendor/types",
        "typescript/packages/types/src/index.ts",
        "adb32535e7708bd8109870b32496ad4bd364d55fffdc93c0b368f5fbd75d1241",
        "typescript/packages/types/package.json",
        "c67bd9b0f8983dfe041ada5528c3f85204726dbdd8e87ebfe89f2f48d47f3c92",
        (
            "CallerCredential",
            "CredentialAudience",
            "CredentialBinding",
            "WorkOrderAuthorization",
        ),
    ),
)
CONTENT_ALLOWLIST_INVENTORY_SHA256 = (
    "a42a4ad3e63099bded1822036a455d19d7bc592b102ff4ca732a1227565295c7"
)


def parse_date(value: Any) -> dt.date | None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value
    ):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _policy_text(value: Any, maximum: int = 256) -> bool:
    return bounded_plain_string(value, maximum)


def validate_policy(policy: Any, *, today: dt.date) -> list[Finding]:
    def invalid() -> list[Finding]:
        return [Finding(DEFAULT_POLICY_PATH, 0, "SCN001_POLICY_INVALID")]

    top_keys = {
        "content_allowlist",
        "governed_roots",
        "limits",
        "owner",
        "owner_schema_documents",
        "reviewed_on",
        "scanner_version",
        "schema_version",
        "source_owner_exports",
        "structural_exceptions",
        "symbolic_fixtures",
    }
    if not exact_keys(policy, top_keys):
        return invalid()
    if (
        policy["schema_version"] != POLICY_SCHEMA
        or policy["scanner_version"] != SCANNER_VERSION
    ):
        return invalid()
    reviewed_on = parse_date(policy["reviewed_on"])
    if not _policy_text(policy["owner"]) or reviewed_on is None or reviewed_on > today:
        return invalid()

    required_limits = {
        "max_archive_members",
        "max_archive_unpacked_bytes",
        "max_array_items",
        "max_file_bytes",
        "max_files",
        "max_findings",
        "max_markdown_fences",
        "max_parser_operations",
        "max_object_members",
        "max_string_bytes",
        "max_structure_depth",
        "max_structure_nodes",
        "max_total_bytes",
    }
    limits = policy["limits"]
    if not exact_keys(limits, required_limits) or not all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in limits.values()
    ):
        return invalid()
    if (
        limits["max_file_bytes"] > HARD_MAX_FILE_BYTES
        or limits["max_total_bytes"] > HARD_MAX_TOTAL_BYTES
        or limits["max_files"] > HARD_MAX_FILES
        or limits["max_findings"] > HARD_MAX_FINDINGS
        or limits["max_archive_members"] > HARD_MAX_ARCHIVE_MEMBERS
        or limits["max_archive_unpacked_bytes"] > HARD_MAX_ARCHIVE_BYTES
        or limits["max_parser_operations"] > HARD_MAX_PARSER_OPERATIONS
        or limits["max_structure_depth"] > 128
        or limits["max_structure_nodes"] > 1_000_000
        or limits["max_total_bytes"] < limits["max_file_bytes"]
    ):
        return invalid()

    roots = policy["governed_roots"]
    root_keys = {"formats", "id", "owner", "path", "reason"}
    root_ids: set[str] = set()
    root_paths: set[str] = set()
    if not isinstance(roots, list) or not roots:
        return invalid()
    for entry in roots:
        if not exact_keys(entry, root_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        if not all(_policy_text(entry[name]) for name in ("id", "owner", "reason")):
            return invalid()
        if entry["id"] in root_ids or entry["path"] in root_paths:
            return invalid()
        root_ids.add(entry["id"])
        root_paths.add(entry["path"])
        formats = entry["formats"]
        if not isinstance(formats, dict) or not formats:
            return invalid()
        for suffix, kind in formats.items():
            if (
                not isinstance(suffix, str)
                or not suffix.startswith(".")
                or "/" in suffix
                or kind not in FORMAT_KINDS
            ):
                return invalid()
    actual_roots = {
        entry["id"]: (entry["path"], entry["formats"])
        for entry in roots
        if isinstance(entry, dict)
    }
    if actual_roots != GOVERNED_ROOT_INVENTORY:
        return invalid()

    source_owner_keys = {
        "exports",
        "language",
        "module",
        "package_path",
        "package_sha256",
        "path",
        "sha256",
    }
    source_owners = policy["source_owner_exports"]
    if not isinstance(source_owners, list):
        return invalid()
    actual_source_owners: list[
        tuple[str, str, str, str, str, str, tuple[str, ...]]
    ] = []
    for entry in source_owners:
        if not exact_keys(entry, source_owner_keys):
            return invalid()
        exports = entry["exports"]
        if (
            entry["language"] not in {"python", "typescript"}
            or not _policy_text(entry["module"])
            or not safe_policy_path(entry["path"])
            or not safe_policy_path(entry["package_path"])
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not re.fullmatch(r"[0-9a-f]{64}", entry["package_sha256"])
            or not isinstance(exports, list)
            or not exports
            or exports != sorted(set(exports))
            or not all(
                isinstance(name, str)
                and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name)
                for name in exports
            )
        ):
            return invalid()
        actual_source_owners.append(
            (
                entry["language"],
                entry["module"],
                entry["path"],
                entry["sha256"],
                entry["package_path"],
                entry["package_sha256"],
                tuple(exports),
            )
        )
    if tuple(actual_source_owners) != SOURCE_OWNER_EXPORT_INVENTORY:
        return invalid()

    digest_entry_keys = {"owner", "path", "reason", "schema_version", "sha256"}
    owner_paths: set[str] = set()
    owner_documents = policy["owner_schema_documents"]
    if not isinstance(owner_documents, list) or not owner_documents:
        return invalid()
    for entry in owner_documents:
        if not exact_keys(entry, digest_entry_keys) or not safe_policy_path(
            entry["path"]
        ):
            return invalid()
        if (
            entry["path"] in owner_paths
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not all(
                _policy_text(entry[name])
                for name in ("owner", "reason", "schema_version")
            )
        ):
            return invalid()
        owner_paths.add(entry["path"])

    expiring_common = {
        "expires_on",
        "owner",
        "path",
        "reason",
        "scanner_version",
        "validator",
    }
    exception_keys = expiring_common | {
        "document_schema",
        "field_path",
        "occurrences",
        "sha256",
    }
    exception_identities: set[tuple[str, str, str]] = set()
    exception_validators = {
        "caller_credential_projection",
        "caller_credential_header_name",
        "caller_credential_ref",
        "credential_correlation_id_schema",
        "credential_correlation_value",
        "local_verification_secret_placeholder",
        "non_secret_scope_statement",
        "python_acceptance_auth_projection",
        "python_acceptance_signing_material",
        "python_caller_auth_transport",
        "typescript_caller_auth_transport",
        "typescript_json_value_index",
        "typescript_owner_safe_reference",
        "typescript_record_key",
    }
    exceptions = policy["structural_exceptions"]
    if not isinstance(exceptions, list):
        return invalid()
    for entry in exceptions:
        if not exact_keys(entry, exception_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        expiry = parse_date(entry["expires_on"])
        identity = (entry["path"], entry["document_schema"], entry["field_path"])
        if (
            expiry is None
            or expiry < today
            or entry["scanner_version"] != SCANNER_VERSION
            or entry["validator"] not in exception_validators
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not isinstance(entry["occurrences"], int)
            or isinstance(entry["occurrences"], bool)
            or entry["occurrences"] != 1
            or not isinstance(entry["field_path"], str)
            or not entry["field_path"].startswith("$.")
            or "*" in entry["field_path"]
            or identity in exception_identities
            or not all(
                _policy_text(entry[name])
                for name in ("owner", "reason", "document_schema")
            )
        ):
            return invalid()
        exception_identities.add(identity)

    symbolic_keys = {
        "expires_on",
        "owner",
        "path",
        "reason",
        "scanner_version",
        "sha256",
    }
    symbolic_paths: set[str] = set()
    symbolic = policy["symbolic_fixtures"]
    if not isinstance(symbolic, list) or not symbolic:
        return invalid()
    for entry in symbolic:
        if not exact_keys(entry, symbolic_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        expiry = parse_date(entry["expires_on"])
        if (
            expiry is None
            or expiry < today
            or entry["scanner_version"] != SCANNER_VERSION
            or entry["path"] in symbolic_paths
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not all(_policy_text(entry[name]) for name in ("owner", "reason"))
        ):
            return invalid()
        symbolic_paths.add(entry["path"])

    content_keys = {
        "expires_on",
        "matches",
        "owner",
        "path",
        "reason",
        "scanner_version",
        "sha256",
    }
    content_paths: set[str] = set()
    content = policy["content_allowlist"]
    if not isinstance(content, list):
        return invalid()
    for entry in content:
        if not exact_keys(entry, content_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        expiry = parse_date(entry["expires_on"])
        matches = entry["matches"]
        if (
            expiry is None
            or expiry < today
            or entry["scanner_version"] != SCANNER_VERSION
            or entry["path"] in content_paths
            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
            or not isinstance(matches, dict)
            or not matches
            or not all(
                code in RULE_MESSAGES
                and code.startswith("SCC")
                and isinstance(count, int)
                and not isinstance(count, bool)
                and count > 0
                for code, count in matches.items()
            )
            or not all(_policy_text(entry[name]) for name in ("owner", "reason"))
        ):
            return invalid()
        content_paths.add(entry["path"])
    encoded_content = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if (
        hashlib.sha256(encoded_content).hexdigest()
        != CONTENT_ALLOWLIST_INVENTORY_SHA256
    ):
        return invalid()
    return []


def load_policy(
    repo_root: Path | RepositoryReader, policy_path: str, *, today: dt.date
) -> tuple[dict[str, Any] | None, list[Finding]]:
    if not safe_policy_path(policy_path):
        return None, [Finding(DEFAULT_POLICY_PATH, 0, "SCN001_POLICY_INVALID")]
    try:
        data = safe_read_file(repo_root, policy_path, HARD_POLICY_BYTES)
        policy = parse_json_bytes(data)
        findings = validate_policy(policy, today=today)
    except (ScanDataError, KeyError, TypeError, ValueError, OverflowError):
        return None, [Finding(policy_path, 0, "SCN001_POLICY_INVALID")]
    if findings:
        return None, findings
    return policy, []
