#!/usr/bin/env python3
"""Fail-closed C03 contract, fixture, and repository-content scanner.

This guard is intentionally offline and standard-library only.  It structurally
checks the exact JSON/YAML/example roots declared by the companion policy and
content-scans candidate repository files for credential formats.  It is not the
runtime output barrier and does not claim arbitrary encrypted/compressed/binary
payload coverage.
"""

from __future__ import annotations

import argparse
import ast
import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import math
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Sequence


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

TEXT_EXTENSIONS = {
    ".adoc",
    ".bat",
    ".c",
    ".cert",
    ".cfg",
    ".cmake",
    ".conf",
    ".cpp",
    ".crt",
    ".css",
    ".csv",
    ".env",
    ".gql",
    ".go",
    ".gradle",
    ".graphql",
    ".h",
    ".hcl",
    ".hpp",
    ".html",
    ".http",
    ".ini",
    ".ipynb",
    ".j2",
    ".java",
    ".js",
    ".json",
    ".jsonl",
    ".key",
    ".kt",
    ".lock",
    ".md",
    ".mustache",
    ".ndjson",
    ".pem",
    ".php",
    ".properties",
    ".proto",
    ".ps1",
    ".py",
    ".rb",
    ".rego",
    ".rs",
    ".rst",
    ".scala",
    ".service",
    ".sh",
    ".sql",
    ".svelte",
    ".swift",
    ".tf",
    ".tfvars",
    ".tmpl",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_FILENAMES = {
    "CMakeLists.txt",
    "Containerfile",
    "Dockerfile",
    "Gemfile",
    "Justfile",
    "Makefile",
    "Procfile",
    "Rakefile",
}
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".zip")
FORMAT_KINDS = {
    "content",
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
    "SCN005_BUDGET_EXCEEDED": "declared scanner resource budget was exceeded",
    "SCN006_MALFORMED_JSON": "governed JSON is malformed or ambiguous",
    "SCN007_MALFORMED_YAML": "governed YAML is malformed or outside the closed subset",
    "SCN008_MALFORMED_MARKDOWN": "governed Markdown has a malformed structured fence",
    "SCN009_STALE_ALLOWLIST": "allowlist entry is stale, changed, or did not match exactly",
    "SCN010_REPOSITORY_UNAVAILABLE": "repository candidate-file enumeration failed",
    "SCF001_SECRET_FIELD": "unregistered secret-like value field is forbidden",
    "SCF002_FAKE_WRAPPER": "unregistered generic secret wrapper is forbidden",
    "SCF003_INVALID_SAFE_RECORD": "registered safe C03 record is not closed and valid",
    "SCF004_INVALID_EXCEPTION": "registered structural exception did not validate exactly",
    "SCC001_PRIVATE_KEY": "private-key material signature is forbidden",
    "SCC002_PROVIDER_TOKEN": "known provider credential signature is forbidden",
    "SCC003_AUTH_VALUE": "raw authorization credential signature is forbidden",
    "SCC004_HIGH_ENTROPY": "high-entropy token candidate is forbidden",
    "SCC005_CREDENTIAL_URL": "credential-bearing URL or connection signature is forbidden",
    "SCC006_ENCODED_PRIVATE_KEY": "encoded private-key material signature is forbidden",
    "SCA001_ARCHIVE_INVALID": "archive is unsafe, malformed, encrypted, or over budget",
}


class ScanDataError(Exception):
    """A bounded parse/read error whose text is never candidate material."""

    def __init__(self, code: str, line: int = 0):
        super().__init__(code)
        self.code = code
        self.line = line


class DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    code: str

    def render(self) -> str:
        location = f"{self.path}:{self.line}" if self.line else self.path
        return f"{location}: {self.code}: {RULE_MESSAGES[self.code]}"


@dataclass(frozen=True)
class ContentHit:
    code: str
    line: int


@dataclass
class ScanStats:
    governed_files: int = 0
    content_files: int = 0
    archive_members: int = 0
    bytes_read: int = 0
    structural_exceptions: int = 0
    content_allowlists: int = 0


@dataclass(frozen=True)
class YamlLine:
    indent: int
    text: str
    number: int


def duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey()
        result[key] = value
    return result


def parse_json_bytes(data: bytes, limits: dict[str, int] | None = None) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCN006_MALFORMED_JSON") from exc
    if text.startswith("\ufeff"):
        raise ScanDataError("SCN006_MALFORMED_JSON")
    try:
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (json.JSONDecodeError, DuplicateJsonKey, ValueError, RecursionError) as exc:
        line = exc.lineno if isinstance(exc, json.JSONDecodeError) else 0
        raise ScanDataError("SCN006_MALFORMED_JSON", line) from exc
    if limits is not None:
        enforce_value_budget(value, limits)
    return value


def enforce_value_budget(value: Any, limits: dict[str, int]) -> None:
    max_depth = limits["max_structure_depth"]
    max_nodes = limits["max_structure_nodes"]
    max_members = limits["max_object_members"]
    max_items = limits["max_array_items"]
    max_string = limits["max_string_bytes"]
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        if isinstance(current, dict):
            if len(current) > max_members:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            for key, child in current.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > max_string:
                    raise ScanDataError("SCN005_BUDGET_EXCEEDED")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if len(current) > max_items:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str) and len(current.encode("utf-8")) > max_string:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")


def strip_yaml_comment(text: str) -> str:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if quote == "'":
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == "'":
                    continue
                quote = None
            continue
        if char in {'"', "'"}:
            # Apostrophes and quotation marks inside a plain scalar are not YAML
            # quote delimiters.  A quote starts a quoted token only at the start
            # of the scalar or after flow punctuation/whitespace.
            previous = text[index - 1] if index else ""
            if index == 0 or previous.isspace() or previous in "[{,:-":
                quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ScanDataError("SCN007_MALFORMED_YAML")
        elif char == "#" and depth == 0 and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    if quote is not None or depth != 0:
        raise ScanDataError("SCN007_MALFORMED_YAML")
    return text.rstrip()


def split_yaml_mapping(text: str) -> tuple[str, str] | None:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if quote == "'":
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == "'":
                    continue
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == ":" and depth == 0:
            if index + 1 == len(text) or text[index + 1].isspace():
                return text[:index].strip(), text[index + 1 :].strip()
    return None


class FlowParser:
    def __init__(self, text: str, max_depth: int = 128):
        self.text = text
        self.index = 0
        self.max_depth = max_depth

    def parse(self) -> Any:
        value = self.parse_value(1)
        self.skip_space()
        if self.index != len(self.text):
            raise ScanDataError("SCN007_MALFORMED_YAML")
        return value

    def skip_space(self) -> None:
        while self.index < len(self.text) and self.text[self.index].isspace():
            self.index += 1

    def parse_value(self, depth: int) -> Any:
        if depth > self.max_depth:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        self.skip_space()
        if self.index >= len(self.text):
            raise ScanDataError("SCN007_MALFORMED_YAML")
        char = self.text[self.index]
        if char == "{":
            return self.parse_map(depth)
        if char == "[":
            return self.parse_list(depth)
        if char in {'"', "'"}:
            return self.parse_quoted()
        return parse_yaml_scalar(self.parse_bare())

    def parse_map(self, depth: int) -> dict[str, Any]:
        self.index += 1
        result: dict[str, Any] = {}
        self.skip_space()
        if self.consume("}"):
            return result
        while True:
            self.skip_space()
            if self.index >= len(self.text):
                raise ScanDataError("SCN007_MALFORMED_YAML")
            key_value = (
                self.parse_quoted()
                if self.text[self.index] in {'"', "'"}
                else self.parse_bare(stop_at_colon=True)
            )
            key = str(key_value).strip()
            if not key or key == "<<" or key in result:
                raise ScanDataError("SCN007_MALFORMED_YAML")
            self.skip_space()
            if not self.consume(":"):
                raise ScanDataError("SCN007_MALFORMED_YAML")
            result[key] = self.parse_value(depth + 1)
            self.skip_space()
            if self.consume("}"):
                return result
            if not self.consume(","):
                raise ScanDataError("SCN007_MALFORMED_YAML")

    def parse_list(self, depth: int) -> list[Any]:
        self.index += 1
        result: list[Any] = []
        self.skip_space()
        if self.consume("]"):
            return result
        while True:
            result.append(self.parse_value(depth + 1))
            self.skip_space()
            if self.consume("]"):
                return result
            if not self.consume(","):
                raise ScanDataError("SCN007_MALFORMED_YAML")

    def parse_quoted(self) -> str:
        quote = self.text[self.index]
        self.index += 1
        chars: list[str] = []
        while self.index < len(self.text):
            char = self.text[self.index]
            self.index += 1
            if char == quote:
                if (
                    quote == "'"
                    and self.index < len(self.text)
                    and self.text[self.index] == "'"
                ):
                    chars.append("'")
                    self.index += 1
                    continue
                return "".join(chars)
            if quote == '"' and char == "\\":
                if self.index >= len(self.text):
                    break
                escaped = self.text[self.index]
                self.index += 1
                escapes = {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    '"': '"',
                    "\\": "\\",
                    "/": "/",
                }
                if escaped not in escapes:
                    raise ScanDataError("SCN007_MALFORMED_YAML")
                chars.append(escapes[escaped])
            else:
                chars.append(char)
        raise ScanDataError("SCN007_MALFORMED_YAML")

    def parse_bare(self, *, stop_at_colon: bool = False) -> str:
        start = self.index
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in ",]}" or (stop_at_colon and char == ":"):
                break
            self.index += 1
        value = self.text[start : self.index].strip()
        if not value or value.startswith(("&", "*", "!")):
            raise ScanDataError("SCN007_MALFORMED_YAML")
        return value

    def consume(self, expected: str) -> bool:
        self.skip_space()
        if self.index < len(self.text) and self.text[self.index] == expected:
            self.index += 1
            return True
        return False


def parse_yaml_scalar(text: str) -> Any:
    value = text.strip()
    if not value:
        return None
    if value.startswith(("&", "*", "!")) or value == "<<":
        raise ScanDataError("SCN007_MALFORMED_YAML")
    if value[0] in "[{":
        return FlowParser(value).parse()
    if value[0] in {'"', "'"}:
        return FlowParser(value).parse()
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        try:
            return int(value)
        except ValueError as exc:
            raise ScanDataError("SCN007_MALFORMED_YAML") from exc
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]+", value):
        try:
            number = float(value)
        except ValueError as exc:
            raise ScanDataError("SCN007_MALFORMED_YAML") from exc
        if not math.isfinite(number):
            raise ScanDataError("SCN007_MALFORMED_YAML")
        return number
    return value


def parse_yaml_key(text: str) -> str:
    value = parse_yaml_scalar(text)
    if not isinstance(value, (str, int)):
        raise ScanDataError("SCN007_MALFORMED_YAML")
    key = str(value)
    if not key or key == "<<":
        raise ScanDataError("SCN007_MALFORMED_YAML")
    return key


class YamlSubsetParser:
    """Closed YAML subset used by current OpenAPI and repository examples."""

    def __init__(self, data: bytes, limits: dict[str, int]):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ScanDataError("SCN007_MALFORMED_YAML") from exc
        if text.startswith("\ufeff") or "\x00" in text:
            raise ScanDataError("SCN007_MALFORMED_YAML")
        self.lines: list[YamlLine] = []
        for number, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
                raise ScanDataError("SCN007_MALFORMED_YAML", number)
            indent = len(raw) - len(raw.lstrip(" "))
            try:
                stripped = strip_yaml_comment(raw[indent:])
            except ScanDataError as exc:
                raise ScanDataError(exc.code, number) from exc
            if not stripped:
                continue
            if stripped in {"---", "..."} or stripped.startswith("%"):
                raise ScanDataError("SCN007_MALFORMED_YAML", number)
            self.lines.append(YamlLine(indent, stripped, number))
        self.limits = limits

    def parse(self) -> Any:
        if not self.lines:
            raise ScanDataError("SCN007_MALFORMED_YAML")
        if self.lines[0].indent != 0:
            raise ScanDataError("SCN007_MALFORMED_YAML", self.lines[0].number)
        value, index = self.parse_block(0, 0, 1)
        if index != len(self.lines):
            raise ScanDataError("SCN007_MALFORMED_YAML", self.lines[index].number)
        enforce_value_budget(value, self.limits)
        return value

    def parse_block(self, index: int, indent: int, depth: int) -> tuple[Any, int]:
        if depth > self.limits["max_structure_depth"] or index >= len(self.lines):
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        line = self.lines[index]
        if line.indent != indent:
            raise ScanDataError("SCN007_MALFORMED_YAML", line.number)
        if line.text == "-" or line.text.startswith("- "):
            return self.parse_list(index, indent, depth)
        return self.parse_mapping(index, indent, depth)

    def parse_mapping(
        self,
        index: int,
        indent: int,
        depth: int,
        seed: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        result = {} if seed is None else dict(seed)
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent > indent or line.text == "-" or line.text.startswith("- "):
                break
            split = split_yaml_mapping(line.text)
            if split is None:
                raise ScanDataError("SCN007_MALFORMED_YAML", line.number)
            raw_key, raw_value = split
            key = parse_yaml_key(raw_key)
            if key in result:
                raise ScanDataError("SCN007_MALFORMED_YAML", line.number)
            index += 1
            value, index = self.parse_mapping_value(
                raw_value, index, indent, depth, line.number
            )
            result[key] = value
        return result, index

    def parse_mapping_value(
        self,
        raw_value: str,
        index: int,
        parent_indent: int,
        depth: int,
        line_number: int,
    ) -> tuple[Any, int]:
        if raw_value in {"|", "|-", "|+", ">", ">-", ">+"}:
            chunks: list[str] = []
            while index < len(self.lines) and self.lines[index].indent > parent_indent:
                chunks.append(self.lines[index].text)
                index += 1
            if not chunks:
                return "", index
            separator = "\n" if raw_value.startswith("|") else " "
            return separator.join(chunks), index
        if raw_value:
            return parse_yaml_scalar(raw_value), index
        if index < len(self.lines) and self.lines[index].indent > parent_indent:
            child_indent = self.lines[index].indent
            return self.parse_block(index, child_indent, depth + 1)
        return None, index

    def parse_list(self, index: int, indent: int, depth: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent != indent or not (
                line.text == "-" or line.text.startswith("- ")
            ):
                break
            item = line.text[1:].strip()
            index += 1
            if not item:
                if index >= len(self.lines) or self.lines[index].indent <= indent:
                    raise ScanDataError("SCN007_MALFORMED_YAML", line.number)
                value, index = self.parse_block(
                    index, self.lines[index].indent, depth + 1
                )
                result.append(value)
                continue
            split = split_yaml_mapping(item)
            if split is None:
                result.append(parse_yaml_scalar(item))
                if index < len(self.lines) and self.lines[index].indent > indent:
                    raise ScanDataError(
                        "SCN007_MALFORMED_YAML", self.lines[index].number
                    )
                continue
            raw_key, raw_value = split
            key = parse_yaml_key(raw_key)
            seed: dict[str, Any] = {}
            value, index = self.parse_mapping_value(
                raw_value, index, indent, depth, line.number
            )
            seed[key] = value
            if index < len(self.lines) and self.lines[index].indent > indent:
                continuation_indent = self.lines[index].indent
                continuation, index = self.parse_mapping(
                    index, continuation_indent, depth + 1, seed
                )
                seed = continuation
            result.append(seed)
        return result, index


def parse_yaml_bytes(data: bytes, limits: dict[str, int]) -> Any:
    try:
        return YamlSubsetParser(data, limits).parse()
    except RecursionError as exc:
        raise ScanDataError("SCN005_BUDGET_EXCEEDED") from exc


def normalize_field_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return re.sub(r"_+", "_", value)


def is_secret_field_name(key: str) -> bool:
    normalized = normalize_field_name(key)
    collapsed = normalized.replace("_", "")
    tokens = [token for token in normalized.split("_") if token]
    token_set = set(tokens)
    if collapsed in {
        "apikey",
        "authorization",
        "clientsecret",
        "connectionstring",
        "credential",
        "dsn",
        "password",
        "passwd",
        "privatekey",
        "secret",
        "token",
    }:
        return True
    if token_set & {
        "secret",
        "credential",
        "password",
        "passwd",
        "authorization",
        "cookie",
        "token",
        "dsn",
    }:
        return True
    pairs = {
        ("api", "key"),
        ("client", "secret"),
        ("private", "key"),
        ("proxy", "authorization"),
        ("connection", "string"),
        ("set", "cookie"),
    }
    if any(left in token_set and right in token_set for left, right in pairs):
        return True
    if normalized == "material":
        return True
    if "default" in token_set and ("key" in token_set or "material" in token_set):
        return True
    if "master" in token_set and "key" in token_set:
        return True
    return False


def schema_marker_is_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    tokens = set(normalize_field_name(value).split("_"))
    return bool(tokens & {"secret", "credential", "password", "token"})


def object_is_fake_wrapper(value: dict[str, Any]) -> bool:
    for marker in ("schema", "schema_version", "type", "kind"):
        if marker in value and schema_marker_is_secret(value[marker]):
            return True
    return False


def json_child_path(parent: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$-]*", key):
        return f"{parent}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{parent}["{escaped}"]'


def canonical_uuid(value: Any) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        )
    )


def canonical_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z",
        value,
    ):
        return False
    try:
        dt.datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%S.%fZ" if "." in value else "%Y-%m-%dT%H:%M:%SZ",
        )
    except ValueError:
        return False
    return True


def exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def bounded_plain_string(value: Any, maximum: int = 256) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= maximum
        and all(char.isprintable() for char in value)
    )


def validate_driver_operation(value: Any) -> bool:
    return (
        exact_keys(value, {"driver", "operation", "schema_version"})
        and bounded_plain_string(value["driver"], 128)
        and bounded_plain_string(value["operation"], 128)
        and value["schema_version"] == "splendor.driver.operation.v1"
    )


def validate_trusted_send(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("kind") == "not_applicable":
        return set(value) == {"kind"}
    if value.get("kind") != "trusted_injection":
        return False
    if set(value) != {
        "applicable_delivery_controls",
        "kind",
        "max_credential_bearing_sends",
    }:
        return False
    controls = value["applicable_delivery_controls"]
    sends = value["max_credential_bearing_sends"]
    return (
        isinstance(controls, list)
        and 1 <= len(controls) <= 8
        and len(set(controls)) == len(controls)
        and all(
            item in PREPLACEMENT_ENUMS["SecretDeliveryControlKind"] for item in controls
        )
        and isinstance(sends, int)
        and not isinstance(sends, bool)
        and 1 <= sends <= 8
    )


def validate_credential_authorization(
    value: Any, expected_schema: str | None = None
) -> bool:
    if not isinstance(value, dict):
        return False
    schema = value.get("schema_version")
    if expected_schema is not None and schema != expected_schema:
        return False
    if schema == "splendor.secret.credential_authorization.v1":
        keys = {
            "approved_destination_digests",
            "credential_slot_id",
            "delivery_exposure_profile",
            "destination_schema",
            "driver_operation",
            "schema_version",
            "trusted_send_profile",
        }
    elif schema == "splendor.secret.credential_authorization.v2":
        keys = {
            "approved_destination_digests",
            "credential_slot_id",
            "delivery_exposure_profile",
            "destination_schema",
            "driver_declaration_revision",
            "driver_operation",
            "schema_version",
            "trusted_send_profile",
        }
    else:
        return False
    if set(value) != keys:
        return False
    digests = value["approved_destination_digests"]
    revision = value.get("driver_declaration_revision", 1)
    return (
        isinstance(digests, list)
        and 1 <= len(digests) <= 16
        and len(set(digests)) == len(digests)
        and all(
            isinstance(item, str) and re.fullmatch(r"blake3:[0-9a-f]{64}", item)
            for item in digests
        )
        and canonical_uuid(value["credential_slot_id"])
        and value["delivery_exposure_profile"]
        in {"trusted_injection", "material_exposed"}
        and bounded_plain_string(value["destination_schema"], 128)
        and isinstance(revision, int)
        and not isinstance(revision, bool)
        and 1 <= revision <= 9_007_199_254_740_991
        and validate_driver_operation(value["driver_operation"])
        and validate_trusted_send(value["trusted_send_profile"])
    )


def validate_secret_use_requirement(value: Any) -> bool:
    keys = {
        "credential_slot_id",
        "delivery_methods",
        "intent",
        "purpose",
        "requested_duration_seconds",
        "requested_max_uses",
        "required",
        "schema_version",
        "secret_ref_id",
    }
    if (
        not exact_keys(value, keys)
        or value["schema_version"] != "splendor.secret.use_requirement.v1"
    ):
        return False
    methods = value["delivery_methods"]
    return (
        canonical_uuid(value["credential_slot_id"])
        and canonical_uuid(value["secret_ref_id"])
        and isinstance(methods, list)
        and 1 <= len(methods) <= 5
        and len(set(methods)) == len(methods)
        and all(item in PREPLACEMENT_ENUMS["SecretDeliveryMethod"] for item in methods)
        and value["intent"] in PREPLACEMENT_ENUMS["SecretUseIntent"]
        and value["purpose"] in PREPLACEMENT_ENUMS["SecretPurpose"]
        and isinstance(value["requested_duration_seconds"], int)
        and 1 <= value["requested_duration_seconds"] <= 86_400
        and isinstance(value["requested_max_uses"], int)
        and 1 <= value["requested_max_uses"] <= 1_000
        and isinstance(value["required"], bool)
    )


def validate_secret_ref(value: Any, expected_schema: str | None = None) -> bool:
    required_keys = {
        "allowed_credential_bindings",
        "allowed_delivery_methods",
        "classification",
        "created_at",
        "lease_policy",
        "logical_name",
        "offline_behavior",
        "provider_namespace",
        "provider_version_ref",
        "schema_version",
        "secret_provider_id",
        "secret_ref_id",
        "secret_ref_revision",
        "tenant_id",
    }
    if not isinstance(value, dict) or not (
        set(value) == required_keys or set(value) == required_keys | {"disabled_at"}
    ):
        return False
    schema = value["schema_version"]
    if schema not in {
        "splendor.secret.ref." + "v1",
        "splendor.secret.ref." + "v2",
    }:
        return False
    if expected_schema is not None and schema != expected_schema:
        return False
    auth_schema = (
        "splendor.secret.credential_authorization.v1"
        if schema.endswith("ref.v1")
        else "splendor.secret.credential_authorization.v2"
    )
    bindings = value["allowed_credential_bindings"]
    methods = value["allowed_delivery_methods"]
    policy = value["lease_policy"]
    policy_keys = {
        "clock_skew_tolerance_seconds",
        "max_continuous_lifetime_seconds",
        "max_lease_duration_seconds",
        "max_uses",
        "renewable",
    }
    return (
        isinstance(bindings, list)
        and 1 <= len(bindings) <= 16
        and all(
            validate_credential_authorization(item, auth_schema) for item in bindings
        )
        and isinstance(methods, list)
        and 1 <= len(methods) <= 5
        and len(set(methods)) == len(methods)
        and all(item in PREPLACEMENT_ENUMS["SecretDeliveryMethod"] for item in methods)
        and value["classification"] in PREPLACEMENT_ENUMS["SecretClassification"]
        and canonical_timestamp(value["created_at"])
        and ("disabled_at" not in value or canonical_timestamp(value["disabled_at"]))
        and exact_keys(policy, policy_keys)
        and all(
            isinstance(policy[name], int)
            and not isinstance(policy[name], bool)
            and 0 <= policy[name] <= 9_007_199_254_740_991
            for name in policy_keys - {"renewable"}
        )
        and isinstance(policy["renewable"], bool)
        and bounded_plain_string(value["logical_name"], 128)
        and value["offline_behavior"] in PREPLACEMENT_ENUMS["SecretOfflineBehavior"]
        and bounded_plain_string(value["provider_namespace"], 128)
        and bounded_plain_string(value["provider_version_ref"], 128)
        and canonical_uuid(value["secret_provider_id"])
        and canonical_uuid(value["secret_ref_id"])
        and isinstance(value["secret_ref_revision"], int)
        and not isinstance(value["secret_ref_revision"], bool)
        and value["secret_ref_revision"] >= 1
        and canonical_uuid(value["tenant_id"])
    )


def validate_driver_sinks(value: Any) -> bool:
    if not exact_keys(
        value,
        {
            "credential_sinks",
            "driver_declaration_revision",
            "driver_operation",
            "schema_version",
        },
    ):
        return False
    if value["schema_version"] != "splendor.driver.operation_credential_sinks.v1":
        return False
    sinks = value["credential_sinks"]
    sink_keys = {
        "allowed_classifications",
        "allowed_intents",
        "credential_slot_id",
        "delivery_exposure_profile",
        "destination_schema",
        "trusted_send_profile",
    }
    return (
        isinstance(sinks, list)
        and 1 <= len(sinks) <= 16
        and all(
            exact_keys(item, sink_keys)
            and isinstance(item["allowed_classifications"], list)
            and item["allowed_classifications"]
            and len(set(item["allowed_classifications"]))
            == len(item["allowed_classifications"])
            and all(
                entry in PREPLACEMENT_ENUMS["SecretClassification"]
                for entry in item["allowed_classifications"]
            )
            and isinstance(item["allowed_intents"], list)
            and item["allowed_intents"]
            and len(set(item["allowed_intents"])) == len(item["allowed_intents"])
            and all(
                entry in PREPLACEMENT_ENUMS["SecretUseIntent"]
                for entry in item["allowed_intents"]
            )
            and canonical_uuid(item["credential_slot_id"])
            and item["delivery_exposure_profile"]
            in {"trusted_injection", "material_exposed"}
            and bounded_plain_string(item["destination_schema"], 128)
            and validate_trusted_send(item["trusted_send_profile"])
            for item in sinks
        )
        and isinstance(value["driver_declaration_revision"], int)
        and not isinstance(value["driver_declaration_revision"], bool)
        and 1 <= value["driver_declaration_revision"] <= 9_007_199_254_740_991
        and validate_driver_operation(value["driver_operation"])
    )


PREPLACEMENT_ENUMS = {
    "SecretClassification": [
        "authentication_credential",
        "signing_material",
        "encryption_material",
        "private_configuration",
        "opaque_secret",
    ],
    "SecretDeliveryMethod": [
        "inherited_fd",
        "tmpfs_file",
        "one_shot_local_socket",
        "orchestrator_projected_secret",
        "environment_variable",
    ],
    "SecretUseIntent": [
        "authenticate",
        "sign",
        "encrypt",
        "decrypt",
        "derive_session",
        "bootstrap_transport",
    ],
    "SecretPurpose": [
        "external_service_access",
        "data_source_access",
        "artifact_store_access",
        "model_provider_access",
        "orchestrator_access",
        "device_service_access",
        "cryptographic_operation",
    ],
    "SecretOfflineBehavior": ["deny", "continue_existing_until_expiry"],
    "SecretDeliveryExposureProfile": ["trusted_injection", "material_exposed"],
    "SecretDeliveryControlKind": [
        "core_dump",
        "ptrace_debug",
        "child_inheritance",
        "output_capture",
        "swap_page_dump",
        "generic_cache",
        "orchestrator_projection",
        "trusted_injection_boundary",
        "destination_network_egress",
        "filesystem_sink_egress",
        "ipc_egress",
        "child_process_egress",
        "proxy_egress",
        "alternate_mount_egress",
    ],
}

SECRET_ID_FIXTURE_NAMES = {
    "SecretAccessEventId",
    "SecretActionIdempotencyKey",
    "SecretActionSubmissionId",
    "SecretApprovalContinuationId",
    "SecretAudienceId",
    "SecretBootstrapSourceBindingId",
    "SecretCleanupCommandId",
    "SecretConsumedEffectTombstoneId",
    "SecretContainmentCommandId",
    "SecretContainmentReserveId",
    "SecretDeliveryControlAttestationId",
    "SecretDeliveryHandleId",
    "SecretDeliveryReceiptId",
    "SecretDetectorRegistrationId",
    "SecretExposureLineageId",
    "SecretLeaseId",
    "SecretLeaseRequestId",
    "SecretNodeControlInvocationId",
    "SecretNodeControlReceiptId",
    "SecretOuterAdmissionCapacityBindingId",
    "SecretPermanentAuxiliaryIdentityMarkerId",
    "SecretProviderAuditId",
    "SecretProviderControlInvocationId",
    "SecretProviderId",
    "SecretProviderRouteId",
    "SecretPublicationAuthorizationId",
    "SecretPublicationPreparationId",
    "SecretPublicationPrepareReceiptId",
    "SecretReconciliationClaimId",
    "SecretRefId",
    "SecretRefMutationCommandId",
    "SecretRenewalCommandId",
    "SecretRetiredAuthorityDomainDenyHeadId",
    "SecretRetirementManifestId",
    "SecretRevocationCommandId",
    "SecretRotationCommandId",
    "SecretTickCandidateObservationId",
    "SecretTickCandidateObservationLinkReceiptId",
    "SecretUseAttemptId",
    "SecretUseClaimId",
}


def validate_preplacement_fixture(value: Any) -> bool:
    if not exact_keys(value, {"enums", "version_ref", "policy", "policy_rfc8785"}):
        return False
    enums = value["enums"]
    if enums != PREPLACEMENT_ENUMS:
        return False
    policy = value["policy"]
    policy_keys = {
        "clock_skew_tolerance_seconds",
        "max_continuous_lifetime_seconds",
        "max_lease_duration_seconds",
        "max_uses",
        "renewable",
    }
    if not exact_keys(policy, policy_keys):
        return False
    if not all(
        isinstance(policy[name], int)
        and not isinstance(policy[name], bool)
        and 0 <= policy[name] <= 9_007_199_254_740_991
        for name in policy_keys - {"renewable"}
    ) or not isinstance(policy["renewable"], bool):
        return False
    canonical_policy = json.dumps(
        policy, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return (
        exact_keys(value["version_ref"], {"minimum", "maximum"})
        and all(
            bounded_plain_string(item, 128) for item in value["version_ref"].values()
        )
        and value["policy_rfc8785"] == canonical_policy
    )


def validate_ids_fixture(value: Any) -> bool:
    if not exact_keys(value, {"valid", "invalid_strings", "invalid_json"}):
        return False
    valid = value["valid"]
    return (
        isinstance(valid, dict)
        and set(valid) == SECRET_ID_FIXTURE_NAMES
        and len(set(valid.values())) == len(valid)
        and all(canonical_uuid(item) for item in valid.values())
        and isinstance(value["invalid_strings"], list)
        and 1 <= len(value["invalid_strings"]) <= 32
        and all(
            isinstance(item, str) and len(item.encode("utf-8")) <= 128
            for item in value["invalid_strings"]
        )
        and value["invalid_json"] == [None, True, 17, 17.5, {}, []]
    )


def validate_caller_credential(value: Any) -> bool:
    if not exact_keys(
        value,
        {
            "credential_id",
            "principal",
            "scopes",
            "binding",
            "audience",
            "expires_at",
            "revocation",
        },
    ):
        return False
    principal = value["principal"]
    if not exact_keys(principal, {"app", "client_principal_id", "label"}):
        return False
    credential_id = value["credential_id"]
    app = principal["app"]
    if not exact_keys(app, {"app_principal_id", "label"}):
        return False

    def label_ok(item: Any) -> bool:
        return item is None or bounded_plain_string(item, 128)

    binding = value["binding"]
    audience = value["audience"]
    binding_ok = (
        exact_keys(binding, {"tenant"})
        and exact_keys(binding["tenant"], {"tenant_id"})
        and bounded_plain_string(binding["tenant"]["tenant_id"], 128)
    ) or (
        exact_keys(binding, {"fleet"})
        and exact_keys(binding["fleet"], {"fleet_id"})
        and bounded_plain_string(binding["fleet"]["fleet_id"], 128)
    )
    audience_shapes = {
        "daemon": "daemon_id",
        "instance": "instance_id",
        "fleet": "fleet_id",
        "central_manager": "manager_id",
    }
    audience_ok = False
    if isinstance(audience, dict) and len(audience) == 1:
        audience_kind = next(iter(audience))
        identity_key = audience_shapes.get(audience_kind)
        audience_ok = bool(
            identity_key
            and exact_keys(audience[audience_kind], {identity_key})
            and bounded_plain_string(audience[audience_kind][identity_key], 128)
        )
    revocation = value["revocation"]
    revocation_ok = revocation == "active" or (
        exact_keys(revocation, {"revoked"})
        and exact_keys(revocation["revoked"], {"reason"})
        and bounded_plain_string(revocation["revoked"]["reason"], 256)
    )
    return (
        isinstance(credential_id, str)
        and bool(
            re.fullmatch(
                r"(?:(?:cred|credential)_[A-Za-z0-9._-]+|sha256:[0-9a-f]{64})",
                credential_id,
            )
        )
        and bounded_plain_string(app["app_principal_id"], 128)
        and label_ok(app["label"])
        and bounded_plain_string(principal["client_principal_id"], 128)
        and label_ok(principal["label"])
        and isinstance(value["scopes"], list)
        and len(set(value["scopes"])) == len(value["scopes"])
        and all(bounded_plain_string(scope, 128) for scope in value["scopes"])
        and binding_ok
        and audience_ok
        and canonical_timestamp(value["expires_at"])
        and revocation_ok
    )


def contains_secret_field_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            is_secret_field_name(key) or contains_secret_field_key(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_secret_field_key(item) for item in value)
    return False


def iter_nested_json_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = json_child_path(path, key)
            if (
                isinstance(child, str)
                and key in {"json", "serialized_utf8"}
                and child.lstrip().startswith(("{", "["))
            ):
                yield child_path, child
            else:
                yield from iter_nested_json_strings(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_nested_json_strings(child, f"{path}[{index}]")


def nested_has_secret_shape(value: Any) -> bool:
    if isinstance(value, dict):
        if object_is_fake_wrapper(value):
            return True
        return any(
            is_secret_field_name(key) or nested_has_secret_shape(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(nested_has_secret_shape(item) for item in value)
    return False


def validate_conformance_cases(value: Any, limits: dict[str, int]) -> bool:
    if not exact_keys(
        value,
        {"case_count", "cases", "format_id", "polarity", "profile"},
    ) or not isinstance(value["cases"], list):
        return False
    if (
        value.get("format_id")
        != "splendor.internal.conformance.rfc0021.offline-slice-1-cases.v1"
    ):
        return False
    if not bounded_plain_string(value["profile"], 128):
        return False
    if value.get("polarity") not in {"positive", "negative"} or value.get(
        "case_count"
    ) != len(value["cases"]):
        return False
    if contains_secret_field_key(value):
        return False
    for case in value["cases"]:
        if not isinstance(case, dict):
            return False
        expected = case.get("expected")
        subject = case.get("subject")
        for nested_path, nested_text in iter_nested_json_strings(case):
            try:
                nested = parse_json_bytes(nested_text.encode("utf-8"), limits)
            except ScanDataError:
                if (
                    value.get("polarity") == "negative"
                    and isinstance(expected, dict)
                    and expected.get("execution_result") == "rejected"
                    and not nested_path.endswith("serialized_utf8")
                    and not scan_content(nested_text)
                ):
                    continue
                return False
            if not nested_has_secret_shape(nested):
                continue
            if subject == "caller_credential" and validate_caller_credential(nested):
                continue
            if (
                not isinstance(expected, dict)
                or expected.get("execution_result") != "rejected"
            ):
                return False
            if nested_path.endswith("serialized_utf8"):
                return False
            if scan_content(nested_text):
                return False
    return True


SAFE_DOCUMENT_VALIDATORS = {
    "credential_authorization": lambda value,
    schema,
    _limits: validate_credential_authorization(value, schema),
    "driver_operation_credential_sinks": lambda value,
    _schema,
    _limits: validate_driver_sinks(value),
    "secret_ref": lambda value, schema, _limits: validate_secret_ref(value, schema),
    "secret_use_requirement": lambda value,
    _schema,
    _limits: validate_secret_use_requirement(value),
}
SYMBOLIC_VALIDATORS = {
    "c03_conformance_cases": validate_conformance_cases,
    "c03_id_grammar": lambda value, _limits: validate_ids_fixture(value),
    "c03_preplacement_grammar": lambda value, _limits: validate_preplacement_fixture(
        value
    ),
}


def validate_exception_node(name: str, value: Any) -> bool:
    if name == "caller_credential_ref":
        direct = {"$ref": "#/components/schemas/CallerCredential"}
        nullable = {"oneOf": [{"type": "null"}, direct]}
        return value == direct or value == nullable
    if name == "credential_correlation_id_schema":
        return value in ({"type": "string"}, {"type": ["string", "null"]})
    if name == "caller_credential_projection":
        return validate_caller_credential(value)
    if name == "credential_correlation_value":
        return bounded_plain_string(value, 128) and bool(
            re.fullmatch(r"(?:cred|sha256)_[A-Za-z0-9._-]+", value)
        )
    if name == "local_verification_secret_placeholder":
        return value == "<local-fixture-secret>"
    if name == "non_secret_scope_statement":
        return value in {
            "not_applicable",
            "no ambient broad credentials; caller-provided secrets must be scoped and redacted",
            "no direct cloud actuator credentials; local middleware authority remains device-local and gateway-mediated",
        }
    return False


def document_schema(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("openapi"), str):
        return f"openapi:{value['openapi']}"
    for key in ("schema_version", "format_id"):
        if isinstance(value.get(key), str):
            return value[key]
    return None


def walk_structural_fields(
    value: Any,
    *,
    file_path: str,
    doc_schema: str | None,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: set[tuple[str, str, str]],
    findings: list[Finding],
    path: str = "$",
    openapi_mode: bool = False,
    openapi_payload: bool = False,
) -> None:
    if isinstance(value, dict):
        openapi_payload = openapi_payload or openapi_payload_root(path)
        if object_is_fake_wrapper(value):
            findings.append(Finding(file_path, 0, "SCF002_FAKE_WRAPPER"))
        for key, child in value.items():
            child_path = json_child_path(path, key)
            inspect_key = (
                not openapi_mode
                or path.endswith(".properties")
                or openapi_payload
            )
            validated_exception = False
            if inspect_key and is_secret_field_name(key):
                identity = (file_path, doc_schema or "", child_path)
                entry = exceptions.get(identity)
                if entry is None:
                    findings.append(Finding(file_path, 0, "SCF001_SECRET_FIELD"))
                else:
                    used_exceptions.add(identity)
                    if validate_exception_node(entry["validator"], child):
                        validated_exception = True
                    else:
                        findings.append(
                            Finding(file_path, 0, "SCF004_INVALID_EXCEPTION")
                        )
            if validated_exception:
                continue
            walk_structural_fields(
                child,
                file_path=file_path,
                doc_schema=doc_schema,
                exceptions=exceptions,
                used_exceptions=used_exceptions,
                findings=findings,
                path=child_path,
                openapi_mode=openapi_mode,
                openapi_payload=openapi_payload,
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_structural_fields(
                child,
                file_path=file_path,
                doc_schema=doc_schema,
                exceptions=exceptions,
                used_exceptions=used_exceptions,
                findings=findings,
                path=f"{path}[{index}]",
                openapi_mode=openapi_mode,
                openapi_payload=openapi_payload,
            )


def openapi_payload_root(path: str) -> bool:
    if re.search(r"\.(?:example|default|const)(?:\[[0-9]+\])*$", path):
        return True
    if re.search(r"\.examples\[[0-9]+\](?:\[[0-9]+\])*$", path):
        return True
    return ".examples." in path and path.endswith(".value")


PEM_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,16384}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
PROVIDER_PATTERNS = [
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{16,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{16,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
    ),
]
AUTH_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])(?:bearer|basic)[ \t]+([A-Za-z0-9._~+/=-]{4,512})"
)
CREDENTIAL_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@"
)
ENTROPY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_~+/-])"
    r"([A-Za-z0-9_~-]{40,512}|[A-Za-z0-9+/]{40,510}={0,2})"
    r"(?![A-Za-z0-9_~+/=-])"
)
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:==|=)?(?![A-Za-z0-9+/=])"
)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def shannon_entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def looks_like_auth_candidate(value: str) -> bool:
    value = value.rstrip(".,;:)]}")
    lowered = value.lower()
    if lowered.startswith("realm=") or lowered in {
        "action/verifier/evidence",
        "management-plane",
    }:
        return False
    if any(char.isdigit() for char in value):
        return True
    if any(char in "_~+/-=" for char in value):
        return True
    return len(value) >= 24 and shannon_entropy(value) >= 4.3


def looks_high_entropy(value: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return False
    if value == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
        return False
    classes = sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
    return classes >= 3 and shannon_entropy(value) >= 4.6


def is_subresource_integrity_digest(value: str) -> bool:
    match = re.fullmatch(r"sha(256|384|512)-([A-Za-z0-9+/]+={0,2})", value)
    if match is None:
        return False
    expected_bytes = {"256": 32, "384": 48, "512": 64}[match.group(1)]
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == expected_bytes


def decoded_private_key_signature(value: str) -> bool:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return False
    if decoded.startswith(b"openssh-key-v1\x00"):
        return True
    if len(decoded) < 48 or not decoded.startswith((b"0\x81", b"0\x82", b"0\x83")):
        return False
    prefix = decoded[:32]
    return b"\x02\x01\x00" in prefix and (
        b"\x02\x82" in decoded[:64]
        or b"\x06\x09*\x86H\x86\xf7\r\x01\x01\x01" in decoded[:96]
    )


def scan_content(
    text: str, maximum: int = HARD_MAX_FINDINGS + 1
) -> list[ContentHit]:
    hits: set[ContentHit] = set()
    occupied: list[tuple[int, int]] = []

    def add(code: str, start: int, end: int) -> None:
        hit = ContentHit(code, line_for_offset(text, start))
        if hit in hits:
            return
        hits.add(hit)
        occupied.append((start, end))

    def complete() -> list[ContentHit] | None:
        if len(hits) >= maximum:
            return sorted(hits, key=lambda item: (item.line, item.code))
        return None

    for match in PEM_PATTERN.finditer(text):
        add("SCC001_PRIVATE_KEY", match.start(), match.end())
        if (result := complete()) is not None:
            return result
    for pattern in PROVIDER_PATTERNS:
        for match in pattern.finditer(text):
            if match.group(0).lower().startswith("sk-learn-"):
                continue
            add("SCC002_PROVIDER_TOKEN", match.start(), match.end())
            if (result := complete()) is not None:
                return result
    for match in CREDENTIAL_URL_PATTERN.finditer(text):
        add("SCC005_CREDENTIAL_URL", match.start(), match.end())
        if (result := complete()) is not None:
            return result
    for match in AUTH_PATTERN.finditer(text):
        if looks_like_auth_candidate(match.group(1)):
            add("SCC003_AUTH_VALUE", match.start(), match.end())
            if (result := complete()) is not None:
                return result
    for match in BASE64_PATTERN.finditer(text):
        if decoded_private_key_signature(match.group(0)):
            add("SCC006_ENCODED_PRIVATE_KEY", match.start(), match.end())
            if (result := complete()) is not None:
                return result
    for match in ENTROPY_PATTERN.finditer(text):
        if any(match.start() < end and match.end() > start for start, end in occupied):
            continue
        if is_subresource_integrity_digest(match.group(1)):
            continue
        if looks_high_entropy(match.group(1)):
            add("SCC004_HIGH_ENTROPY", match.start(), match.end())
            if (result := complete()) is not None:
                return result
    return sorted(hits, key=lambda item: (item.line, item.code))


def safe_policy_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or not all(char.isprintable() for char in value)
        or "\\" in value
    ):
        return False
    if any(char in value for char in "*?[]"):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(
        part not in {"", ".", ".."} for part in path.parts
    )


def bounded_policy_text(value: Any, maximum: int = 256) -> bool:
    return bounded_plain_string(value, maximum)


def parse_date(value: Any) -> dt.date | None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value
    ):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def validate_policy(policy: Any, *, today: dt.date) -> list[Finding]:
    findings: list[Finding] = []

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
    if (
        not bounded_policy_text(policy["owner"])
        or reviewed_on is None
        or reviewed_on > today
    ):
        return invalid()
    required_limits = {
        "max_archive_members",
        "max_archive_unpacked_bytes",
        "max_array_items",
        "max_file_bytes",
        "max_files",
        "max_findings",
        "max_markdown_fences",
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
        or limits["max_structure_depth"] > 128
        or limits["max_structure_nodes"] > 1_000_000
    ):
        return invalid()

    roots = policy["governed_roots"]
    root_keys = {"formats", "id", "owner", "path", "reason"}
    root_ids: set[str] = set()
    root_paths: set[str] = set()
    if not isinstance(roots, list) or not roots:
        return invalid()
    for entry in roots:
        if not exact_keys(entry, root_keys):
            return invalid()
        if not all(
            bounded_policy_text(entry[name]) for name in ("id", "owner", "reason")
        ) or not safe_policy_path(entry["path"]):
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

    safe_keys = {"owner", "path", "reason", "schema_version", "validator"}
    safe_identities: set[str] = set()
    safe_validators = set(SAFE_DOCUMENT_VALIDATORS)
    safe_documents = policy["owner_schema_documents"]
    if not isinstance(safe_documents, list):
        return invalid()
    for entry in safe_documents:
        if not exact_keys(entry, safe_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        if (
            entry["path"] in safe_identities
            or entry["validator"] not in safe_validators
        ):
            return invalid()
        if not all(
            bounded_policy_text(entry[name])
            for name in ("owner", "reason", "schema_version")
        ):
            return invalid()
        safe_identities.add(entry["path"])

    expiring_common = {
        "expires_on",
        "owner",
        "path",
        "reason",
        "scanner_version",
        "validator",
    }
    exception_keys = expiring_common | {"document_schema", "field_path"}
    exception_identities: set[tuple[str, str, str]] = set()
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
            or entry["validator"]
            not in {
                "caller_credential_projection",
                "caller_credential_ref",
                "credential_correlation_id_schema",
                "credential_correlation_value",
                "local_verification_secret_placeholder",
                "non_secret_scope_statement",
            }
            or not isinstance(entry["field_path"], str)
            or not entry["field_path"].startswith("$.")
            or "*" in entry["field_path"]
            or identity in exception_identities
        ):
            return invalid()
        if not all(
            bounded_policy_text(entry[name])
            for name in ("owner", "reason", "document_schema")
        ):
            return invalid()
        exception_identities.add(identity)

    symbolic_keys = expiring_common
    symbolic_paths: set[str] = set()
    symbolic = policy["symbolic_fixtures"]
    if not isinstance(symbolic, list):
        return invalid()
    for entry in symbolic:
        if not exact_keys(entry, symbolic_keys) or not safe_policy_path(entry["path"]):
            return invalid()
        expiry = parse_date(entry["expires_on"])
        if (
            expiry is None
            or expiry < today
            or entry["scanner_version"] != SCANNER_VERSION
            or entry["validator"] not in SYMBOLIC_VALIDATORS
            or entry["path"] in symbolic_paths
            or not all(bounded_policy_text(entry[name]) for name in ("owner", "reason"))
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
                and count > 0
                for code, count in matches.items()
            )
            or not all(bounded_policy_text(entry[name]) for name in ("owner", "reason"))
        ):
            return invalid()
        content_paths.add(entry["path"])
    return findings


def load_policy(
    repo_root: Path, policy_path: str, *, today: dt.date
) -> tuple[dict[str, Any] | None, list[Finding]]:
    if not safe_policy_path(policy_path):
        return None, [Finding(DEFAULT_POLICY_PATH, 0, "SCN001_POLICY_INVALID")]
    try:
        data = safe_read_file(repo_root, policy_path, HARD_POLICY_BYTES)
        policy = parse_json_bytes(data)
    except ScanDataError:
        return None, [Finding(policy_path, 0, "SCN001_POLICY_INVALID")]
    try:
        findings = validate_policy(policy, today=today)
    except (KeyError, TypeError, ValueError, OverflowError):
        findings = [Finding(policy_path, 0, "SCN001_POLICY_INVALID")]
    return (policy if not findings else None), findings


def ensure_no_symlink_ancestry(repo_root: Path, relative: str) -> Path:
    if not safe_policy_path(relative):
        raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    current = repo_root
    for part in PurePosixPath(relative).parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
    try:
        resolved = current.resolve(strict=True)
        root_resolved = repo_root.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ScanDataError("SCN003_PATH_AMBIGUOUS") from exc
    return current


def safe_read_file(repo_root: Path, relative: str, maximum: int) -> bytes:
    path = ensure_no_symlink_ancestry(repo_root, relative)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ScanDataError("SCN002_PATH_UNAVAILABLE") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ScanDataError("SCN003_PATH_AMBIGUOUS")
        if info.st_size > maximum:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        return data
    finally:
        os.close(descriptor)


def enumerate_repository_files(repo_root: Path) -> tuple[list[str], list[Finding]]:
    command = [
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]
    try:
        completed = subprocess.run(
            command, cwd=repo_root, check=False, capture_output=True
        )
    except (FileNotFoundError, OSError):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    if completed.returncode != 0:
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    try:
        values = completed.stdout.decode("utf-8").split("\x00")
    except UnicodeDecodeError:
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    files = sorted(value for value in values if value)
    if len(files) != len(set(files)) or any(
        not safe_policy_path(value) for value in files
    ):
        return [], [Finding(".", 0, "SCN010_REPOSITORY_UNAVAILABLE")]
    return files, []


def suffix_for(path: str) -> str:
    name = PurePosixPath(path).name
    if name.startswith(".") and name.count(".") == 1:
        return name
    lowered = path.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lowered.endswith(suffix):
            return suffix
    return PurePosixPath(path).suffix.lower()


def path_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def governed_formats(
    policy: dict[str, Any], files: Sequence[str]
) -> tuple[dict[str, str], list[Finding]]:
    formats: dict[str, str] = {}
    findings: list[Finding] = []
    file_set = set(files)
    for root in policy["governed_roots"]:
        root_path = root["path"]
        candidates = [path for path in files if path_under(path, root_path)]
        if root_path in file_set:
            candidates = [root_path]
        if not candidates:
            findings.append(Finding(root_path, 0, "SCN002_PATH_UNAVAILABLE"))
            continue
        for path in candidates:
            kind = root["formats"].get(suffix_for(path))
            if kind is None:
                findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
                continue
            previous = formats.get(path)
            if previous is not None and previous != kind:
                findings.append(Finding(path, 0, "SCN001_POLICY_INVALID"))
            formats[path] = kind
    return formats, findings


def is_content_candidate(path: str) -> bool:
    suffix = suffix_for(path)
    name = PurePosixPath(path).name
    return (
        suffix in TEXT_EXTENSIONS
        or suffix in ARCHIVE_SUFFIXES
        or suffix == ".gitkeep"
        or name in TEXT_FILENAMES
        or name.startswith(".env.")
    )


def parse_markdown_fences(
    data: bytes, limits: dict[str, int]
) -> list[tuple[int, str, bytes]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN") from exc
    fences: list[tuple[int, str, bytes]] = []
    active_marker: str | None = None
    active_marker_length = 0
    active_kind: str | None = None
    start_line = 0
    chunks: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_-]*)\s*", line)
        if active_marker is None:
            if opening and opening.group(2).lower() in {"json", "yaml", "yml"}:
                marker = opening.group(1)
                active_marker = marker[0]
                active_marker_length = len(marker)
                active_kind = opening.group(2).lower()
                start_line = number
                chunks = []
            continue
        closing = re.fullmatch(
            rf" {{0,3}}{re.escape(active_marker)}{{{active_marker_length},}}\s*",
            line,
        )
        if closing:
            kind = "json" if active_kind == "json" else "yaml"
            nonblank_indents = [
                len(chunk) - len(chunk.lstrip(" ")) for chunk in chunks if chunk.strip()
            ]
            common_indent = min(nonblank_indents, default=0)
            dedented = [
                chunk[common_indent:] if chunk.strip() else "" for chunk in chunks
            ]
            fences.append(
                (start_line, kind, ("\n".join(dedented) + "\n").encode("utf-8"))
            )
            if len(fences) > limits["max_markdown_fences"]:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            active_marker = None
            active_marker_length = 0
            active_kind = None
            chunks = []
        else:
            chunks.append(line)
    if active_marker is not None:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN", start_line)
    return fences


def parse_structured_data(kind: str, data: bytes, limits: dict[str, int]) -> Any:
    if kind == "json":
        return parse_json_bytes(data, limits)
    if kind == "yaml":
        return parse_yaml_bytes(data, limits)
    raise AssertionError(kind)


def scan_structured_value(
    value: Any,
    *,
    path: str,
    policy: dict[str, Any],
    safe_documents: dict[str, dict[str, Any]],
    symbolic_fixtures: dict[str, dict[str, Any]],
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_safe: set[str],
    used_symbolic: set[str],
    used_exceptions: set[tuple[str, str, str]],
    schema_hint: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    safe = safe_documents.get(path)
    if safe is not None:
        used_safe.add(path)
        validator = SAFE_DOCUMENT_VALIDATORS[safe["validator"]]
        try:
            valid = document_schema(value) == safe["schema_version"] and validator(
                value, safe["schema_version"], policy["limits"]
            )
        except (KeyError, TypeError, ValueError, IndexError, RecursionError):
            valid = False
        if not valid:
            findings.append(Finding(path, 0, "SCF003_INVALID_SAFE_RECORD"))
        return findings
    symbolic = symbolic_fixtures.get(path)
    if symbolic is not None:
        used_symbolic.add(path)
        validator = SYMBOLIC_VALIDATORS[symbolic["validator"]]
        try:
            valid = validator(value, policy["limits"])
        except (KeyError, TypeError, ValueError, IndexError, RecursionError):
            valid = False
        if not valid:
            findings.append(Finding(path, 0, "SCF003_INVALID_SAFE_RECORD"))
        return findings
    schema = document_schema(value) or schema_hint
    walk_structural_fields(
        value,
        file_path=path,
        doc_schema=schema,
        exceptions=exceptions,
        used_exceptions=used_exceptions,
        findings=findings,
        openapi_mode=bool(schema and schema.startswith("openapi:")),
    )
    return findings


def decode_text(data: bytes, code: str = "SCN003_PATH_AMBIGUOUS") -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError(code) from exc
    if text.startswith("\ufeff") or "\x00" in text:
        raise ScanDataError(code)
    return text


def archive_members(
    path: str, data: bytes, limits: dict[str, int]
) -> Iterator[tuple[str, bytes]]:
    member_count = 0
    unpacked = 0
    seen_names: set[str] = set()

    def accept_member(name: str, size: int, *, directory: bool = False) -> str:
        nonlocal member_count, unpacked
        if not isinstance(name, str) or not name or "\x00" in name:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        normalized = name.replace("\\", "/")
        stripped = (
            normalized[:-1] if directory and normalized.endswith("/") else normalized
        )
        parts = stripped.split("/")
        pure = PurePosixPath(stripped)
        if (
            not bounded_plain_string(stripped, min(limits["max_string_bytes"], 4096))
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
            or pure.as_posix() in seen_names
            or size < 0
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        seen_names.add(pure.as_posix())
        member_count += 1
        if not directory:
            unpacked += size
        if (
            member_count > limits["max_archive_members"]
            or unpacked > limits["max_archive_unpacked_bytes"]
            or size > limits["max_file_bytes"]
        ):
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        return pure.as_posix()

    def bounded_gzip_payload() -> bytes:
        maximum = limits["max_archive_unpacked_bytes"]
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
                payload = compressed.read(maximum + 1)
        except (gzip.BadGzipFile, OSError, EOFError) as exc:
            raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc
        if len(payload) > maximum:
            raise ScanDataError("SCA001_ARCHIVE_INVALID")
        return payload

    try:
        if path.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                if len(infos) > limits["max_archive_members"]:
                    raise ScanDataError("SCA001_ARCHIVE_INVALID")
                for info in sorted(infos, key=lambda item: item.filename):
                    mode = (info.external_attr >> 16) & 0xFFFF
                    file_type = stat.S_IFMT(mode)
                    is_directory = info.is_dir()
                    if (
                        info.flag_bits & 0x1
                        or stat.S_ISLNK(mode)
                        or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or (is_directory and info.file_size != 0)
                    ):
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    name = accept_member(
                        info.filename, info.file_size, directory=is_directory
                    )
                    if info.is_dir():
                        continue
                    if info.file_size > max(1, info.compress_size) * 100:
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    with archive.open(info, "r") as member:
                        member_data = member.read(limits["max_file_bytes"] + 1)
                    if (
                        len(member_data) != info.file_size
                        or len(member_data) > limits["max_file_bytes"]
                    ):
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    yield name, member_data
        else:
            tar_data = (
                bounded_gzip_payload()
                if path.lower().endswith((".tar.gz", ".tgz"))
                else data
            )
            with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
                for info in archive:
                    name = accept_member(info.name, info.size, directory=info.isdir())
                    if info.isdir():
                        continue
                    if not info.isfile() or info.issym() or info.islnk():
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    handle = archive.extractfile(info)
                    if handle is None:
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    member_data = handle.read(limits["max_file_bytes"] + 1)
                    if (
                        len(member_data) != info.size
                        or len(member_data) > limits["max_file_bytes"]
                    ):
                        raise ScanDataError("SCA001_ARCHIVE_INVALID")
                    yield name, member_data
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        OSError,
        EOFError,
        RuntimeError,
        ValueError,
    ) as exc:
        raise ScanDataError("SCA001_ARCHIVE_INVALID") from exc


def content_allowlist_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in policy["content_allowlist"]}


def apply_content_allowlist(
    path: str,
    data: bytes,
    hits: list[ContentHit],
    allowlists: dict[str, dict[str, Any]],
    *,
    enforce_stale: bool,
) -> tuple[list[ContentHit], bool, list[Finding]]:
    entry = allowlists.get(path)
    if entry is None:
        return hits, False, []
    digest = hashlib.sha256(data).hexdigest()
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.code] = counts.get(hit.code, 0) + 1
    expected = entry["matches"]
    if digest != entry["sha256"] or counts != expected:
        if enforce_stale:
            return hits, False, [Finding(path, 0, "SCN009_STALE_ALLOWLIST")]
        return hits, False, []
    return [], True, []


def scan_one_content_blob(
    path: str, data: bytes, maximum: int
) -> tuple[list[ContentHit], list[Finding]]:
    try:
        text = decode_text(data)
    except ScanDataError as exc:
        return [], [Finding(path, exc.line, exc.code)]
    return scan_content(text, maximum + 1), []


def scan_repository(
    repo_root: Path,
    policy: dict[str, Any],
    *,
    explicit_paths: Sequence[str] | None = None,
) -> tuple[list[Finding], ScanStats]:
    findings: list[Finding] = []
    stats = ScanStats()
    limits = policy["limits"]
    if explicit_paths:
        files = sorted(set(explicit_paths))
        if len(files) != len(explicit_paths) or any(
            not safe_policy_path(path) for path in files
        ):
            return [Finding(".", 0, "SCN003_PATH_AMBIGUOUS")], stats
        formats: dict[str, str] = {}
        for path in files:
            suffix = suffix_for(path)
            if suffix in ARCHIVE_SUFFIXES:
                continue
            kind = {
                ".json": "json",
                ".yaml": "yaml",
                ".yml": "yaml",
                ".md": "markdown",
                ".py": "python_source",
                ".ts": "typescript_source",
            }.get(suffix, "content" if is_content_candidate(path) else "")
            if kind:
                formats[path] = kind
            else:
                findings.append(Finding(path, 0, "SCN004_UNSUPPORTED_FORMAT"))
    else:
        files, enum_findings = enumerate_repository_files(repo_root)
        findings.extend(enum_findings)
        if enum_findings:
            return findings, stats
        formats, format_findings = governed_formats(policy, files)
        findings.extend(format_findings)
    if len(files) > limits["max_files"]:
        findings.append(Finding(".", 0, "SCN005_BUDGET_EXCEEDED"))
        return findings, stats

    safe_documents = {
        entry["path"]: entry for entry in policy["owner_schema_documents"]
    }
    symbolic_fixtures = {entry["path"]: entry for entry in policy["symbolic_fixtures"]}
    exceptions = {
        (entry["path"], entry["document_schema"], entry["field_path"]): entry
        for entry in policy["structural_exceptions"]
    }
    used_safe: set[str] = set()
    used_symbolic: set[str] = set()
    used_exceptions: set[tuple[str, str, str]] = set()
    allowlists = content_allowlist_map(policy)
    used_allowlists: set[str] = set()
    for path in files:
        needs_content = is_content_candidate(path)
        needs_structural = path in formats and bool(formats[path])
        if not needs_content and not needs_structural:
            continue
        try:
            data = safe_read_file(repo_root, path, limits["max_file_bytes"])
        except ScanDataError as exc:
            findings.append(Finding(path, exc.line, exc.code))
            continue
        stats.bytes_read += len(data)
        if stats.bytes_read > limits["max_total_bytes"]:
            findings.append(Finding(path, 0, "SCN005_BUDGET_EXCEEDED"))
            break
        if needs_content:
            suffix = suffix_for(path)
            if suffix in ARCHIVE_SUFFIXES:
                try:
                    for member_name, member_data in archive_members(path, data, limits):
                        display = f"{path}!{member_name}"
                        stats.archive_members += 1
                        member_suffix = suffix_for(member_name)
                        if member_suffix in ARCHIVE_SUFFIXES:
                            raise ScanDataError("SCA001_ARCHIVE_INVALID")
                        if member_suffix not in TEXT_EXTENSIONS:
                            continue
                        hits, blob_findings = scan_one_content_blob(
                            display, member_data, limits["max_findings"]
                        )
                        findings.extend(blob_findings)
                        hits, allowed, allow_findings = apply_content_allowlist(
                            display,
                            member_data,
                            hits,
                            allowlists,
                            enforce_stale=explicit_paths is None,
                        )
                        findings.extend(allow_findings)
                        if allowed:
                            used_allowlists.add(display)
                            stats.content_allowlists += 1
                        findings.extend(
                            Finding(display, hit.line, hit.code) for hit in hits
                        )
                        if member_suffix in {".json", ".yaml", ".yml", ".md"}:
                            member_kind = {
                                ".json": "json",
                                ".yaml": "yaml",
                                ".yml": "yaml",
                                ".md": "markdown",
                            }[member_suffix]
                            if member_kind == "markdown":
                                for (
                                    fence_number,
                                    fence_kind,
                                    fence_data,
                                ) in parse_markdown_fences(member_data, limits):
                                    member_value = parse_structured_data(
                                        fence_kind, fence_data, limits
                                    )
                                    findings.extend(
                                        scan_structured_value(
                                            member_value,
                                            path=f"{display}#fence-{fence_number}",
                                            policy=policy,
                                            safe_documents=safe_documents,
                                            symbolic_fixtures=symbolic_fixtures,
                                            exceptions=exceptions,
                                            used_safe=used_safe,
                                            used_symbolic=used_symbolic,
                                            used_exceptions=used_exceptions,
                                            schema_hint=f"markdown:{fence_kind}",
                                        )
                                    )
                            else:
                                member_value = parse_structured_data(
                                    "yaml" if member_kind == "yaml" else "json",
                                    member_data,
                                    limits,
                                )
                                findings.extend(
                                    scan_structured_value(
                                        member_value,
                                        path=display,
                                        policy=policy,
                                        safe_documents=safe_documents,
                                        symbolic_fixtures=symbolic_fixtures,
                                        exceptions=exceptions,
                                        used_safe=used_safe,
                                        used_symbolic=used_symbolic,
                                        used_exceptions=used_exceptions,
                                    )
                                )
                        if len(findings) > limits["max_findings"]:
                            return bounded_findings(
                                findings, limits["max_findings"]
                            ), stats
                except ScanDataError as exc:
                    findings.append(Finding(path, exc.line, exc.code))
            else:
                hits, blob_findings = scan_one_content_blob(
                    path, data, limits["max_findings"]
                )
                findings.extend(blob_findings)
                hits, allowed, allow_findings = apply_content_allowlist(
                    path,
                    data,
                    hits,
                    allowlists,
                    enforce_stale=explicit_paths is None,
                )
                findings.extend(allow_findings)
                if allowed:
                    used_allowlists.add(path)
                    stats.content_allowlists += 1
                findings.extend(Finding(path, hit.line, hit.code) for hit in hits)
                stats.content_files += 1

        if not needs_structural:
            continue
        kind = formats[path]
        stats.governed_files += 1
        try:
            if kind in {"json", "yaml"}:
                value = parse_structured_data(kind, data, limits)
                findings.extend(
                    scan_structured_value(
                        value,
                        path=path,
                        policy=policy,
                        safe_documents=safe_documents,
                        symbolic_fixtures=symbolic_fixtures,
                        exceptions=exceptions,
                        used_safe=used_safe,
                        used_symbolic=used_symbolic,
                        used_exceptions=used_exceptions,
                    )
                )
            elif kind == "markdown":
                for fence_number, fence_kind, fence_data in parse_markdown_fences(
                    data, limits
                ):
                    value = parse_structured_data(fence_kind, fence_data, limits)
                    fence_path = f"{path}#fence-{fence_number}"
                    findings.extend(
                        scan_structured_value(
                            value,
                            path=fence_path,
                            policy=policy,
                            safe_documents=safe_documents,
                            symbolic_fixtures=symbolic_fixtures,
                            exceptions=exceptions,
                            used_safe=used_safe,
                            used_symbolic=used_symbolic,
                            used_exceptions=used_exceptions,
                            schema_hint=f"markdown:{fence_kind}",
                        )
                    )
            elif kind == "python_source":
                text = decode_text(data)
                try:
                    ast.parse(text, filename=path)
                except (SyntaxError, ValueError, RecursionError) as exc:
                    line = (
                        exc.lineno if isinstance(exc, SyntaxError) and exc.lineno else 0
                    )
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS", line) from exc
            elif kind == "typescript_source":
                decode_text(data)
            elif kind == "empty":
                if data:
                    raise ScanDataError("SCN003_PATH_AMBIGUOUS")
            elif kind == "content":
                decode_text(data)
            else:
                raise ScanDataError("SCN004_UNSUPPORTED_FORMAT")
        except ScanDataError as exc:
            findings.append(Finding(path, exc.line, exc.code))

        if len(findings) > limits["max_findings"]:
            return bounded_findings(findings, limits["max_findings"]), stats

    if explicit_paths is None:
        for path in sorted(set(safe_documents) - used_safe):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
        for path in sorted(set(symbolic_fixtures) - used_symbolic):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
        for identity in sorted(set(exceptions) - used_exceptions):
            findings.append(Finding(identity[0], 0, "SCN009_STALE_ALLOWLIST"))
        for path in sorted(set(allowlists) - used_allowlists):
            findings.append(Finding(path, 0, "SCN009_STALE_ALLOWLIST"))
    stats.structural_exceptions = len(used_exceptions)
    return bounded_findings(findings, limits["max_findings"]), stats


def bounded_findings(findings: Iterable[Finding], maximum: int) -> list[Finding]:
    unique = sorted(set(findings))
    if len(unique) <= maximum:
        return unique
    return unique[:maximum] + [Finding(".", 0, "SCN005_BUDGET_EXCEEDED")]


def minimal_test_policy(root_path: str = "fixture.json") -> dict[str, Any]:
    return {
        "schema_version": POLICY_SCHEMA,
        "scanner_version": SCANNER_VERSION,
        "owner": "SECR-006",
        "reviewed_on": "2026-07-26",
        "limits": {
            "max_files": 100,
            "max_file_bytes": 65_536,
            "max_total_bytes": 1_048_576,
            "max_structure_depth": 24,
            "max_structure_nodes": 2_048,
            "max_object_members": 256,
            "max_array_items": 256,
            "max_string_bytes": 32_768,
            "max_markdown_fences": 16,
            "max_archive_members": 16,
            "max_archive_unpacked_bytes": 262_144,
            "max_findings": 128,
        },
        "governed_roots": [
            {
                "id": "self-test",
                "path": root_path,
                "formats": {
                    ".json": "json",
                    ".yaml": "yaml",
                    ".yml": "yaml",
                    ".md": "markdown",
                },
                "owner": "SECR-006",
                "reason": "self-test fixture",
            }
        ],
        "owner_schema_documents": [],
        "structural_exceptions": [],
        "symbolic_fixtures": [],
        "content_allowlist": [],
    }


def run_self_test() -> int:
    failures: list[str] = []
    checks = 0

    def check(name: str, condition: bool) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(name)

    limits = minimal_test_policy()["limits"]
    slot_id_fixture = "018f0a1b-2c3d-4e5f-" + "8a9b-0c1d2e3f4101"
    ref_id_fixture = "018f0a1b-2c3d-4e5f-" + "8a9b-0c1d2e3f4001"
    provider_id_fixture = "018f0a1b-2c3d-4e5f-" + "8a9b-0c1d2e3f4201"
    safe_requirement = {
        "credential_slot_id": slot_id_fixture,
        "delivery_methods": ["inherited_fd"],
        "intent": "authenticate",
        "purpose": "external_service_access",
        "requested_duration_seconds": 30,
        "requested_max_uses": 1,
        "required": True,
        "schema_version": "splendor.secret.use_requirement.v1",
        "secret_ref_id": ref_id_fixture,
    }
    check("safe requirement", validate_secret_use_requirement(safe_requirement))
    changed_requirement = dict(safe_requirement)
    changed_requirement["value"] = "symbolic"
    check(
        "safe requirement closure",
        not validate_secret_use_requirement(changed_requirement),
    )
    safe_authorization = {
        "approved_destination_digests": ["blake3:" + "a" * 64],
        "credential_slot_id": slot_id_fixture,
        "delivery_exposure_profile": "trusted_injection",
        "destination_schema": "splendor.destination.synthetic.v1",
        "driver_declaration_revision": 1,
        "driver_operation": {
            "driver": "synthetic",
            "operation": "read",
            "schema_version": "splendor.driver.operation.v1",
        },
        "schema_version": "splendor.secret.credential_authorization.v2",
        "trusted_send_profile": {"kind": "not_applicable"},
    }
    safe_ref = {
        "allowed_credential_bindings": [safe_authorization],
        "allowed_delivery_methods": ["inherited_fd"],
        "classification": "authentication_credential",
        "created_at": "2026-07-26T00:00:00Z",
        "lease_policy": {
            "clock_skew_tolerance_seconds": 0,
            "max_continuous_lifetime_seconds": 60,
            "max_lease_duration_seconds": 30,
            "max_uses": 1,
            "renewable": False,
        },
        "logical_name": "synthetic",
        "offline_behavior": "deny",
        "provider_namespace": "synthetic",
        "provider_version_ref": "version-1",
        "schema_version": "splendor.secret.ref.v2",
        "secret_provider_id": provider_id_fixture,
        "secret_ref_id": ref_id_fixture,
        "secret_ref_revision": 1,
        "tenant_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4301",
    }
    check("safe reference", validate_secret_ref(safe_ref, "splendor.secret.ref.v2"))
    changed_ref = dict(safe_ref)
    changed_ref["value"] = "symbolic"
    check(
        "safe reference closure",
        not validate_secret_ref(changed_ref, "splendor.secret.ref.v2"),
    )

    forbidden_names = [
        "password",
        "PassWd",
        "api-key",
        "apiKey",
        "TOKEN",
        "client secret",
        "privateKey",
        "credential",
        "Authorization",
        "set_cookie",
        "connectionString",
        "dsn",
        "secretValue",
        "default-master-key",
        "material",
    ]
    for name in forbidden_names:
        check(
            f"normalized field {normalize_field_name(name)}", is_secret_field_name(name)
        )
    check("false-positive state value", not is_secret_field_name("state_value"))
    check("false-positive idempotency", not is_secret_field_name("idempotency_key"))

    findings: list[Finding] = []
    walk_structural_fields(
        {"outer": [{"password": "symbolic"}]},
        file_path="fixture.json",
        doc_schema=None,
        exceptions={},
        used_exceptions=set(),
        findings=findings,
    )
    check(
        "nested array/object",
        any(item.code == "SCF001_SECRET_FIELD" for item in findings),
    )
    findings = []
    walk_structural_fields(
        {"schema_version": "splendor.secret.use_requirement.v1", "value": "symbolic"},
        file_path="copy.json",
        doc_schema="splendor.secret.use_requirement.v1",
        exceptions={},
        used_exceptions=set(),
        findings=findings,
    )
    check(
        "fake schema wrapper",
        any(item.code == "SCF002_FAKE_WRAPPER" for item in findings),
    )

    malformed_json = [b'{"a":', b'{"a":1,"a":2}', b"\xff"]
    for index, data in enumerate(malformed_json):
        try:
            parse_json_bytes(data, limits)
            check(f"malformed json {index}", False)
        except ScanDataError:
            check(f"malformed json {index}", True)
    malformed_yaml = [b"a: 1\na: 2\n", b"a:\n   - ok\n  - bad\n", b"a: *alias\n"]
    for index, data in enumerate(malformed_yaml):
        try:
            parse_yaml_bytes(data, limits)
            check(f"malformed yaml {index}", False)
        except ScanDataError:
            check(f"malformed yaml {index}", True)
    try:
        deeply_nested_flow = ("a: " + "[" * 129 + "0" + "]" * 129).encode()
        parse_yaml_bytes(deeply_nested_flow, limits)
        check("flow yaml depth budget", False)
    except ScanDataError as exc:
        check("flow yaml depth budget", exc.code == "SCN005_BUDGET_EXCEEDED")

    long_fence = (
        "````json\n"
        '{"safe":"value"}\n'
        "```\n"
        '{"password":"symbolic"}\n'
        "````\n"
    ).encode()
    long_fences = parse_markdown_fences(long_fence, limits)
    check(
        "markdown closing fence cannot be shorter than opener",
        len(long_fences) == 1 and b'"password"' in long_fences[0][2],
    )

    openapi_findings: list[Finding] = []
    walk_structural_fields(
        {"example": {"password": "symbolic"}},
        file_path="openapi.yaml",
        doc_schema="openapi:3.1.0",
        exceptions={},
        used_exceptions=set(),
        findings=openapi_findings,
        openapi_mode=True,
    )
    check(
        "openapi example payload fields remain governed",
        any(item.code == "SCF001_SECRET_FIELD" for item in openapi_findings),
    )

    malformed_caller = {
        "credential_id": "cred_symbolic",
        "principal": {},
        "scopes": [],
        "binding": {},
        "audience": {},
        "expires_at": "2026-07-26T00:00:00Z",
        "revocation": "active",
    }
    check(
        "malformed caller exception is a fixed invalid shape",
        not validate_caller_credential(malformed_caller),
    )

    private_header = "-----BEGIN " + "PRIVATE KEY-----"
    private_footer = "-----END " + "PRIVATE KEY-----"
    private_fixture = (
        private_header
        + "\n"
        + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 2)
        + "\n"
        + private_footer
    )
    auth_fixture = "Bearer " + ("A1b2_" * 8)
    provider_fixture = "AK" + "IA" + ("A1" * 8)
    entropy_fixture = "Q7m_Z2p-L9x_V4c-N8r_K1t-" + "H6w_J3s-P5y_D0f-M2q_R8u"
    encoded_key_fixture = base64.b64encode(
        b"0\x82\x00\x44\x02\x01\x00\x02\x82" + bytes(range(1, 64))
    ).decode("ascii")
    credential_url_fixture = (
        "https://" + "fixture-user:" + entropy_fixture + "@example.invalid/resource"
    )
    integrity_fixture = "sha256-" + base64.b64encode(bytes(range(32))).decode("ascii")
    check(
        "private-key content",
        any(hit.code == "SCC001_PRIVATE_KEY" for hit in scan_content(private_fixture)),
    )
    rendered_private_finding = Finding(
        "fixture.txt", 1, "SCC001_PRIVATE_KEY"
    ).render()
    check(
        "diagnostics never echo candidate content",
        private_fixture not in rendered_private_finding
        and "fixture.txt:1" in rendered_private_finding,
    )
    check(
        "authorization content",
        any(hit.code == "SCC003_AUTH_VALUE" for hit in scan_content(auth_fixture)),
    )
    check(
        "provider content",
        any(
            hit.code == "SCC002_PROVIDER_TOKEN"
            for hit in scan_content(provider_fixture)
        ),
    )
    check(
        "high-entropy content",
        any(hit.code == "SCC004_HIGH_ENTROPY" for hit in scan_content(entropy_fixture)),
    )
    check(
        "high-entropy marker is not a bypass",
        any(
            hit.code == "SCC004_HIGH_ENTROPY"
            for hit in scan_content("synthetic_" + entropy_fixture)
        ),
    )
    check(
        "high-entropy assignment value",
        any(
            hit.code == "SCC004_HIGH_ENTROPY"
            for hit in scan_content("SPLENDOR_TEST_VALUE=" + entropy_fixture)
        ),
    )
    check(
        "credential URL content",
        any(
            hit.code == "SCC005_CREDENTIAL_URL"
            for hit in scan_content(credential_url_fixture)
        ),
    )
    check(
        "encoded private-key content",
        any(
            hit.code == "SCC006_ENCODED_PRIVATE_KEY"
            for hit in scan_content(encoded_key_fixture)
        ),
    )
    check(
        "false-positive prose",
        not scan_content("Bearer transport and Basic planning are ordinary prose."),
    )
    check(
        "false-positive hyphenated basic name",
        not scan_content(
            "COPY examples/circuit-breaker-basic ./examples/circuit-breaker-basic"
        ),
    )
    check(
        "false-positive configuration assignment",
        not scan_content("SPLENDOR_CALLER_TRUST_FILE=/etc/splendor/caller-trust.json"),
    )
    check(
        "false-positive exact integrity digest",
        not scan_content(integrity_fixture),
    )
    check(
        "content finding count is bounded",
        len(scan_content((auth_fixture + "\n") * 20, maximum=3)) == 3,
    )

    exception = {
        "path": "openapi.yaml",
        "document_schema": "openapi:3.1.0",
        "field_path": "$.components.schemas.Request.properties.credential",
        "validator": "caller_credential_ref",
        "owner": "daemon-auth",
        "reason": "closed caller authentication mirror",
        "expires_on": "2099-01-01",
        "scanner_version": SCANNER_VERSION,
    }
    identity = (
        exception["path"],
        exception["document_schema"],
        exception["field_path"],
    )
    exact_node = {"$ref": "#/components/schemas/CallerCredential"}
    used: set[tuple[str, str, str]] = set()
    exact_findings: list[Finding] = []
    walk_structural_fields(
        {
            "components": {
                "schemas": {"Request": {"properties": {"credential": exact_node}}}
            }
        },
        file_path="openapi.yaml",
        doc_schema="openapi:3.1.0",
        exceptions={identity: exception},
        used_exceptions=used,
        findings=exact_findings,
        openapi_mode=True,
    )
    check("exact exception", not exact_findings and identity in used)
    wrong_findings: list[Finding] = []
    walk_structural_fields(
        {
            "components": {
                "schemas": {"Other": {"properties": {"credential": exact_node}}}
            }
        },
        file_path="openapi.yaml",
        doc_schema="openapi:3.1.0",
        exceptions={identity: exception},
        used_exceptions=set(),
        findings=wrong_findings,
        openapi_mode=True,
    )
    check(
        "exception wrong path",
        any(item.code == "SCF001_SECRET_FIELD" for item in wrong_findings),
    )
    wrong_shape: list[Finding] = []
    walk_structural_fields(
        {
            "components": {
                "schemas": {
                    "Request": {"properties": {"credential": {"type": "string"}}}
                }
            }
        },
        file_path="openapi.yaml",
        doc_schema="openapi:3.1.0",
        exceptions={identity: exception},
        used_exceptions=set(),
        findings=wrong_shape,
        openapi_mode=True,
    )
    check(
        "exception wrong shape",
        any(item.code == "SCF004_INVALID_EXCEPTION" for item in wrong_shape),
    )

    allow_data = auth_fixture.encode("utf-8")
    allow_entry = {
        "path": "fixture.txt",
        "sha256": hashlib.sha256(allow_data).hexdigest(),
        "matches": {"SCC003_AUTH_VALUE": 1, "SCC004_HIGH_ENTROPY": 1},
    }
    raw_hits = scan_content(auth_fixture)
    actual_counts: dict[str, int] = {}
    for hit in raw_hits:
        actual_counts[hit.code] = actual_counts.get(hit.code, 0) + 1
    allow_entry["matches"] = actual_counts
    filtered, allowed, allow_findings = apply_content_allowlist(
        "fixture.txt",
        allow_data,
        raw_hits,
        {"fixture.txt": allow_entry},
        enforce_stale=True,
    )
    check(
        "content allowlist exact digest/count",
        allowed and not filtered and not allow_findings,
    )
    changed, allowed, changed_findings = apply_content_allowlist(
        "fixture.txt",
        allow_data + b"x",
        raw_hits,
        {"fixture.txt": allow_entry},
        enforce_stale=True,
    )
    check(
        "content allowlist changed digest",
        not allowed and changed and bool(changed_findings),
    )
    changed_count_entry = dict(allow_entry)
    changed_count_entry["matches"] = dict(actual_counts)
    changed_count_code = next(iter(changed_count_entry["matches"]))
    changed_count_entry["matches"][changed_count_code] += 1
    changed_count_hits, changed_count_allowed, changed_count_findings = (
        apply_content_allowlist(
            "fixture.txt",
            allow_data,
            raw_hits,
            {"fixture.txt": changed_count_entry},
            enforce_stale=True,
        )
    )
    check(
        "content allowlist changed match count",
        not changed_count_allowed
        and changed_count_hits
        and changed_count_findings
        == [Finding("fixture.txt", 0, "SCN009_STALE_ALLOWLIST")],
    )

    tiny_limits = dict(limits)
    tiny_limits["max_structure_nodes"] = 3
    try:
        enforce_value_budget({"a": [1, 2, 3]}, tiny_limits)
        check("resource cap", False)
    except ScanDataError:
        check("resource cap", True)

    expired_policy = minimal_test_policy()
    expired_policy["structural_exceptions"] = [dict(exception, expires_on="2020-01-01")]
    check(
        "expired exception",
        bool(validate_policy(expired_policy, today=dt.date(2026, 7, 26))),
    )
    invalid_root_policy = minimal_test_policy("../escape.json")
    check(
        "traversal policy",
        bool(validate_policy(invalid_root_policy, today=dt.date(2026, 7, 26))),
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        unavailable_files, unavailable_findings = enumerate_repository_files(root)
        check(
            "repository scanner unavailable",
            not unavailable_files
            and any(
                item.code == "SCN010_REPOSITORY_UNAVAILABLE"
                for item in unavailable_findings
            ),
        )
        missing_policy = minimal_test_policy("missing.json")
        missing, _ = scan_repository(
            root, missing_policy, explicit_paths=["missing.json"]
        )
        check(
            "unavailable path",
            any(item.code == "SCN002_PATH_UNAVAILABLE" for item in missing),
        )
        malformed_policy = minimal_test_policy()
        malformed_policy["content_allowlist"] = [
            {
                "path": "fixture.txt",
                "sha256": None,
                "matches": {"SCC003_AUTH_VALUE": 1},
                "owner": "self-test",
                "reason": "malformed policy type",
                "expires_on": "2099-01-01",
                "scanner_version": SCANNER_VERSION,
            }
        ]
        (root / "policy.json").write_text(
            json.dumps(malformed_policy), encoding="utf-8"
        )
        loaded_policy, malformed_policy_findings = load_policy(
            root, "policy.json", today=dt.date(2026, 7, 26)
        )
        check(
            "malformed policy types use fixed diagnostics",
            loaded_policy is None
            and malformed_policy_findings
            == [Finding("policy.json", 0, "SCN001_POLICY_INVALID")],
        )
        unsupported_path = root / "fixture.bin"
        unsupported_path.write_bytes(b"bounded symbolic fixture")
        unsupported, _ = scan_repository(
            root,
            minimal_test_policy("fixture.bin"),
            explicit_paths=["fixture.bin"],
        )
        check(
            "unsupported governed extension",
            any(item.code == "SCN004_UNSUPPORTED_FORMAT" for item in unsupported),
        )
        extensionless_path = root / "Dockerfile"
        extensionless_path.write_text(auth_fixture, encoding="utf-8")
        extensionless, _ = scan_repository(
            root,
            minimal_test_policy("Dockerfile"),
            explicit_paths=["Dockerfile"],
        )
        check(
            "extensionless candidate content",
            any(item.code == "SCC003_AUTH_VALUE" for item in extensionless)
            and not any(
                item.code == "SCN004_UNSUPPORTED_FORMAT" for item in extensionless
            ),
        )
        archive_path = root / "fixture.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/fixture.txt", auth_fixture.encode("utf-8"))
        archived, archive_stats = scan_repository(
            root,
            minimal_test_policy("fixture.zip"),
            explicit_paths=["fixture.zip"],
        )
        check(
            "explicit archive content",
            archive_stats.archive_members == 1
            and any(item.code == "SCC003_AUTH_VALUE" for item in archived)
            and not any(item.code == "SCN004_UNSUPPORTED_FORMAT" for item in archived),
        )

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.txt", b"bounded fixture")
        traversal_archive, _ = scan_repository(
            root,
            minimal_test_policy("fixture.zip"),
            explicit_paths=["fixture.zip"],
        )
        check(
            "archive traversal",
            any(item.code == "SCA001_ARCHIVE_INVALID" for item in traversal_archive),
        )

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
            for index in range(limits["max_archive_members"] + 1):
                archive.writestr(f"member-{index}.txt", b"")
        member_budget_archive, _ = scan_repository(
            root,
            minimal_test_policy("fixture.zip"),
            explicit_paths=["fixture.zip"],
        )
        check(
            "archive member budget",
            any(
                item.code == "SCA001_ARCHIVE_INVALID" for item in member_budget_archive
            ),
        )

        nested_buffer = io.BytesIO()
        with zipfile.ZipFile(nested_buffer, "w", zipfile.ZIP_STORED) as nested:
            nested.writestr("fixture.txt", b"bounded nested fixture")
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("nested.zip", nested_buffer.getvalue())
        nested_archive, _ = scan_repository(
            root,
            minimal_test_policy("fixture.zip"),
            explicit_paths=["fixture.zip"],
        )
        check(
            "nested archives fail closed instead of being skipped",
            any(item.code == "SCA001_ARCHIVE_INVALID" for item in nested_archive),
        )

        tar_buffer = io.BytesIO()
        tar_member_data = b"bounded tar fixture"
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as archive:
            tar_info = tarfile.TarInfo("nested/fixture.txt")
            tar_info.size = len(tar_member_data)
            archive.addfile(tar_info, io.BytesIO(tar_member_data))
        check(
            "gzip tar content",
            list(archive_members("fixture.tar.gz", tar_buffer.getvalue(), limits))
            == [("nested/fixture.txt", tar_member_data)],
        )

        gzip_limits = dict(limits)
        gzip_limits["max_archive_unpacked_bytes"] = 64
        try:
            list(
                archive_members(
                    "fixture.tar.gz",
                    gzip.compress(b"x" * 65),
                    gzip_limits,
                )
            )
            check("gzip expansion budget", False)
        except ScanDataError as exc:
            check("gzip expansion budget", exc.code == "SCA001_ARCHIVE_INVALID")

        target = root / "target.json"
        target.write_text("{}", encoding="utf-8")
        link = root / "link.json"
        try:
            link.symlink_to(target)
            linked, _ = scan_repository(
                root, minimal_test_policy("link.json"), explicit_paths=["link.json"]
            )
            check(
                "symlink ambiguity",
                any(item.code == "SCN003_PATH_AMBIGUOUS" for item in linked),
            )
        except (OSError, NotImplementedError):
            checks -= 1

    if failures:
        print(
            f"C03 secret contract scanner self-test: FAIL ({len(failures)}/{checks})",
            file=sys.stderr,
        )
        for failure in sorted(failures):
            print(f"self-test: {failure}", file=sys.stderr)
        return 1
    print(f"C03 secret contract scanner self-test: PASS ({checks} checks)")
    return 0


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check C03 contracts/fixtures and repository content for raw secret material."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root (default: inferred from this script).",
    )
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_PATH,
        help=f"Repository-relative policy path (default: {DEFAULT_POLICY_PATH}).",
    )
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Scan one repository-relative candidate path instead of normal repository mode; repeatable.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run deterministic built-in positive and negative tests.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        repo_root = args.repo_root.resolve(strict=True)
    except OSError:
        print(Finding(".", 0, "SCN002_PATH_UNAVAILABLE").render(), file=sys.stderr)
        return 1
    if not repo_root.is_dir():
        print(Finding(".", 0, "SCN002_PATH_UNAVAILABLE").render(), file=sys.stderr)
        return 1
    policy, policy_findings = load_policy(
        repo_root, args.policy, today=dt.datetime.now(dt.timezone.utc).date()
    )
    if policy is None:
        for finding in policy_findings:
            print(finding.render(), file=sys.stderr)
        return 1
    findings, stats = scan_repository(repo_root, policy, explicit_paths=args.paths)
    if findings:
        print(
            f"C03 secret contract scan: FAIL ({len(findings)} finding(s))",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        return 1
    print(
        "C03 secret contract scan: PASS "
        f"(governed_files={stats.governed_files}, content_files={stats.content_files}, "
        f"archive_members={stats.archive_members}, structural_exceptions={stats.structural_exceptions}, "
        f"content_allowlists={stats.content_allowlists})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
