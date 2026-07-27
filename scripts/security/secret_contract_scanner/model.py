"""Shared limits, fixed diagnostics, and cumulative work accounting."""

from __future__ import annotations

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

SCANNER_VERSION = "1.0.0"
POLICY_SCHEMA = "splendor.secret_field_scan.v1"
DEFAULT_POLICY_PATH = "scripts/security/secret-contract-policy.json"

HARD_POLICY_BYTES = 512 * 1024
HARD_MAX_FILE_BYTES = 8 * 1024 * 1024
HARD_MAX_TOTAL_BYTES = 256 * 1024 * 1024
HARD_MAX_FILES = 50_000
HARD_MAX_FINDINGS = 1_000
HARD_MAX_ARCHIVE_MEMBERS = 2_048
HARD_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
HARD_GIT_TIMEOUT_SECONDS = 15

ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".zip", ".gz", ".gzip")
SOURCE_SUFFIXES = {
    ".cjs",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".py",
    ".ts",
    ".tsx",
}
FORMAT_KINDS = {
    "content",
    "config",
    "empty",
    "json",
    "markdown",
    "python_source",
    "typescript_source",
    "yaml",
}

RULE_MESSAGES = {
    "SCN001_POLICY_INVALID": "scanner policy is invalid",
    "SCN002_PATH_UNAVAILABLE": "required scan path is unavailable",
    "SCN003_PATH_AMBIGUOUS": "path is not a regular no-symlink repository file",
    "SCN004_UNSUPPORTED_FORMAT": "governed file format is not registered",
    "SCN005_BUDGET_EXCEEDED": "cumulative scanner resource budget was exceeded",
    "SCN006_MALFORMED_JSON": "governed JSON is malformed or ambiguous",
    "SCN007_MALFORMED_YAML": "governed YAML is malformed or outside the closed subset",
    "SCN008_MALFORMED_MARKDOWN": "governed Markdown has a malformed structured fence",
    "SCN009_STALE_ALLOWLIST": "allowlist entry is stale, changed, or did not match exactly",
    "SCN010_REPOSITORY_UNAVAILABLE": "repository candidate-file enumeration failed",
    "SCN011_MALFORMED_SOURCE": "governed source is malformed or outside the bounded scanner",
    "SCN012_WORKFLOW_UNGATED": "build or publication workflow is not scanner-gated",
    "SCF001_SECRET_FIELD": "unregistered secret-like value field is forbidden",
    "SCF002_FAKE_WRAPPER": "unregistered generic secret wrapper is forbidden",
    "SCF003_INVALID_SAFE_RECORD": "registered owner fixture digest or schema is not exact",
    "SCF004_INVALID_EXCEPTION": "registered structural exception did not validate exactly",
    "SCF005_SOURCE_FIELD": "credential-capable source declaration is forbidden",
    "SCC001_PRIVATE_KEY": "private-key material signature is forbidden",
    "SCC002_PROVIDER_TOKEN": "known provider credential signature is forbidden",
    "SCC003_AUTH_VALUE": "raw authorization credential signature is forbidden",
    "SCC004_HIGH_ENTROPY": "high-entropy token candidate is forbidden",
    "SCC005_CREDENTIAL_URL": "credential-bearing URL or connection signature is forbidden",
    "SCC006_ENCODED_PRIVATE_KEY": "encoded private-key material signature is forbidden",
    "SCA001_ARCHIVE_INVALID": "archive is unsafe, malformed, nested, or over budget",
}


class ScanDataError(Exception):
    """A bounded parse/read error whose exception text is never candidate data."""

    def __init__(self, code: str, line: int = 0):
        super().__init__(code)
        self.code = code
        self.line = line


class DuplicateJsonKey(ValueError):
    """Raised internally for ambiguous duplicate JSON members."""


def utf8_size(value: str) -> int | None:
    """Return the exact UTF-8 size, rejecting lone surrogates safely."""

    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:auth(?:orization)?s?|credentials?|passwords?|passwds?|secrets?|tokens?|api[_-]?keys?|client[_-]?secrets?|private[_-]?keys?)\s*[=:][^/\\\s]+"
)
_URL_USERINFO = re.compile(r"(?i)[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@")
_USERINFO_FRAGMENT = re.compile(r"[^/:@\s]+:[^/@\s]+@")
_AUTH_FRAGMENT = re.compile(
    r"(?i)(?:bearer|basic)(?:[ _:+%-]|%20)+[A-Za-z0-9._~+/=%-]{1,512}"
)
_PROVIDER_FRAGMENT = re.compile(
    r"(?i)(?:AKIA|ASIA)[A-Z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{12,}|sk_live_[A-Za-z0-9]{12,}|glpat-[A-Za-z0-9_-]{12,}"
)
_OPAQUE_MIXED_FRAGMENT = re.compile(r"[A-Za-z0-9_~+.-]{24,512}")


def _segment_variants(segment: str) -> tuple[str, ...]:
    raw_variants = [segment]
    if re.search(r"%[0-9A-Fa-f]{2}", segment):
        try:
            decoded = urllib.parse.unquote(segment, errors="strict")
        except (UnicodeDecodeError, ValueError):
            pass
        else:
            if decoded != segment:
                raw_variants.append(decoded)
    variants: list[str] = []
    for value in raw_variants:
        variants.append(value)
        nfkc = unicodedata.normalize("NFKC", value)
        if nfkc != value:
            variants.append(nfkc)
        normalized = "".join(" " if char.isspace() else char for char in value)
        if normalized != value:
            variants.append(normalized)
    return tuple(dict.fromkeys(variants))


def _looks_like_opaque_mixed_fragment(value: str) -> bool:
    for match in _OPAQUE_MIXED_FRAGMENT.finditer(value):
        candidate = match.group(0)
        if (
            any(char.islower() for char in candidate)
            and any(char.isupper() for char in candidate)
            and any(char.isdigit() or not char.isalnum() for char in candidate)
        ):
            return True
    return False


def _redact_segment(segment: str) -> str:
    if not segment:
        return segment
    # Keep coordinate classification canonical without creating an import cycle
    # while this module is initialized. Diagnostics are rendered only after all
    # scanner modules have loaded.
    from .content import is_secret_field_name

    variants = _segment_variants(segment)
    unsafe = (
        utf8_size(segment) is None
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in segment)
        or any(
            bool(_CREDENTIAL_ASSIGNMENT.search(value))
            or bool(_URL_USERINFO.search(value))
            or bool(_USERINFO_FRAGMENT.search(value))
            or bool(_AUTH_FRAGMENT.search(value))
            or bool(_PROVIDER_FRAGMENT.search(value))
            or _looks_like_opaque_mixed_fragment(value)
            or is_secret_field_name(value.rsplit(".", 1)[0])
            for value in variants
        )
    )
    if not unsafe:
        return segment
    return "<redacted>"


def redact_diagnostic_path(value: str) -> str:
    """Redact credential-capable path/member segments without echoing candidates."""

    outer, marker, member = value.partition("!")
    safe_outer = "/".join(_redact_segment(part) for part in outer.split("/"))
    if not marker:
        return safe_outer
    safe_member = "/".join(_redact_segment(part) for part in member.split("/"))
    return f"{safe_outer}!{safe_member}"


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    code: str

    def render(self) -> str:
        safe_path = redact_diagnostic_path(self.path)
        location = f"{safe_path}:{self.line}" if self.line else safe_path
        return f"{location}: {self.code}: {RULE_MESSAGES[self.code]}"


@dataclass(frozen=True, order=True)
class ContentHit:
    line: int
    start: int
    end: int
    code: str


@dataclass
class ScanStats:
    governed_files: int = 0
    content_files: int = 0
    archive_members: int = 0
    bytes_worked: int = 0
    structural_exceptions: int = 0
    content_allowlists: int = 0


@dataclass
class WorkBudget:
    """One repository-global budget for reads, expansion, parsing, and scans."""

    limits: dict[str, int]
    files: int = 0
    work_bytes: int = 0
    structure_nodes: int = 0
    archive_members: int = 0
    archive_unpacked_bytes: int = 0

    def charge_file(self) -> None:
        self.files += 1
        if self.files > self.limits["max_files"]:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

    def ensure_file_capacity(self, amount: int) -> None:
        if amount < 0 or self.files + amount > self.limits["max_files"]:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

    def ensure_archive_capacity(self, amount: int) -> None:
        if (
            amount < 0
            or self.archive_members + amount > self.limits["max_archive_members"]
            or self.files + amount > self.limits["max_files"]
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")

    def remaining_work_bytes(self) -> int:
        return max(0, self.limits["max_total_bytes"] - self.work_bytes)

    def ensure_work_capacity(self, amount: int) -> None:
        if amount < 0 or amount > self.remaining_work_bytes():
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

    def charge_work(self, amount: int) -> None:
        if amount < 0:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        self.work_bytes += amount
        if self.work_bytes > self.limits["max_total_bytes"]:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

    def charge_text(self, value: str) -> None:
        size = utf8_size(value)
        if size is None:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        self.charge_work(size)

    def charge_structure(self, amount: int = 1) -> None:
        self.structure_nodes += amount
        if self.structure_nodes > self.limits["max_structure_nodes"]:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")

    def remaining_archive_bytes(self) -> int:
        return max(
            0,
            self.limits["max_archive_unpacked_bytes"] - self.archive_unpacked_bytes,
        )

    def charge_archive_expansion(self, size: int) -> None:
        if size < 0:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        self.archive_unpacked_bytes += size
        if self.archive_unpacked_bytes > self.limits["max_archive_unpacked_bytes"]:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        self.charge_work(size)

    def charge_archive_member(self, size: int, *, count_unpacked: bool = True) -> None:
        self.charge_file()
        self.archive_members += 1
        if self.archive_members > self.limits["max_archive_members"]:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        if count_unpacked:
            self.charge_archive_expansion(size)


def safe_policy_path(value: Any) -> bool:
    size = utf8_size(value) if isinstance(value, str) else None
    if (
        not isinstance(value, str)
        or not value
        or size is None
        or size > 4096
        or not all(char.isprintable() for char in value)
        or "\\" in value
        or any(char in value for char in "*?[]")
    ):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(
        part not in {"", ".", ".."} for part in path.parts
    )


def bounded_plain_string(value: Any, maximum: int = 256) -> bool:
    size = utf8_size(value) if isinstance(value, str) else None
    return bool(
        isinstance(value, str)
        and size is not None
        and 0 < size <= maximum
        and all(char.isprintable() for char in value)
    )


def exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def suffix_for(path: str) -> str:
    name = PurePosixPath(path).name
    if name.startswith(".") and name.count(".") == 1:
        return name.lower()
    lowered = path.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return suffix
    return PurePosixPath(path).suffix.lower()


def path_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")
