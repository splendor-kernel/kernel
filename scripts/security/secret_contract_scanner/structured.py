"""Closed JSON/YAML/Markdown parsing and bounded structural/source checks."""

from __future__ import annotations

import ast
import datetime as dt
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from .content import (
    is_authorization_context,
    is_secret_field_name,
    object_is_fake_wrapper,
    scan_content,
)
from .model import (
    ContentHit,
    DuplicateJsonKey,
    Finding,
    ScanDataError,
    WorkBudget,
    bounded_plain_string,
    exact_keys,
    utf8_size,
)


def duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey()
        result[key] = value
    return result


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError
    return parsed


def parse_json_bytes(
    data: bytes,
    limits: dict[str, int] | None = None,
    budget: WorkBudget | None = None,
) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCN006_MALFORMED_JSON") from exc
    if "\ufeff" in text or "\x00" in text:
        raise ScanDataError("SCN006_MALFORMED_JSON")
    try:
        value = json.loads(
            text,
            object_pairs_hook=duplicate_rejecting_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            parse_float=_parse_json_float,
        )
        ensure_unicode_scalars(value, "SCN006_MALFORMED_JSON")
        if limits is not None:
            enforce_value_budget(value, limits, budget)
    except (json.JSONDecodeError, DuplicateJsonKey, ValueError, RecursionError) as exc:
        line = exc.lineno if isinstance(exc, json.JSONDecodeError) else 0
        raise ScanDataError("SCN006_MALFORMED_JSON", line) from exc
    return value


def ensure_unicode_scalars(value: Any, code: str) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    not isinstance(key, str)
                    or utf8_size(key) is None
                    or "\x00" in key
                    or "\ufeff" in key
                ):
                    raise ScanDataError(code)
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            if utf8_size(current) is None or "\x00" in current or "\ufeff" in current:
                raise ScanDataError(code)


def enforce_value_budget(
    value: Any, limits: dict[str, int], budget: WorkBudget | None = None
) -> None:
    max_depth = limits["max_structure_depth"]
    max_nodes = limits["max_structure_nodes"]
    max_members = limits["max_object_members"]
    max_items = limits["max_array_items"]
    max_string = limits["max_string_bytes"]
    local_nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        local_nodes += 1
        if budget is not None:
            budget.charge_structure()
        if local_nodes > max_nodes or depth > max_depth:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        if isinstance(current, dict):
            if len(current) > max_members:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            for key, child in current.items():
                size = utf8_size(key) if isinstance(key, str) else None
                if size is None or size > max_string:
                    raise ScanDataError("SCN005_BUDGET_EXCEEDED")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if len(current) > max_items:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            size = utf8_size(current)
            if size is None or size > max_string:
                raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ScanDataError("SCN006_MALFORMED_JSON")


def split_yaml_comment_text(text: str) -> tuple[str, str | None]:
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
            return text[:index].rstrip(), text[index + 1 :].strip()
    if quote is not None or depth != 0:
        raise ScanDataError("SCN007_MALFORMED_YAML")
    return text.rstrip(), None


def strip_yaml_comment(text: str) -> str:
    return split_yaml_comment_text(text)[0]


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
                    "0": "\x00",
                    "a": "\x07",
                    "b": "\x08",
                    "e": "\x1b",
                    "f": "\x0c",
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "v": "\x0b",
                    " ": " ",
                    '"': '"',
                    "\\": "\\",
                    "/": "/",
                    "N": "\x85",
                    "_": "\xa0",
                    "L": "\u2028",
                    "P": "\u2029",
                }
                widths = {"x": 2, "u": 4, "U": 8}
                if escaped in widths:
                    width = widths[escaped]
                    digits = self.text[self.index : self.index + width]
                    if not re.fullmatch(rf"[0-9A-Fa-f]{{{width}}}", digits):
                        raise ScanDataError("SCN007_MALFORMED_YAML")
                    codepoint = int(digits, 16)
                    if 0xD800 <= codepoint <= 0xDFFF or codepoint > 0x10FFFF:
                        raise ScanDataError("SCN007_MALFORMED_YAML")
                    chars.append(chr(codepoint))
                    self.index += width
                elif escaped in escapes:
                    chars.append(escapes[escaped])
                else:
                    raise ScanDataError("SCN007_MALFORMED_YAML")
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
    if value[0] in "[{" or value[0] in {'"', "'"}:
        return FlowParser(value).parse()
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {".nan", ".inf", "+.inf", "-.inf"}:
        raise ScanDataError("SCN007_MALFORMED_YAML")
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
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ScanDataError("SCN007_MALFORMED_YAML")
    key = str(value)
    if not key or key == "<<":
        raise ScanDataError("SCN007_MALFORMED_YAML")
    return key


@dataclass(frozen=True)
class YamlLine:
    indent: int
    text: str
    number: int


class YamlSubsetParser:
    """Closed YAML subset used by current OpenAPI, workflows, and examples."""

    def __init__(
        self, data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
    ):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ScanDataError("SCN007_MALFORMED_YAML") from exc
        if "\ufeff" in text or "\x00" in text:
            raise ScanDataError("SCN007_MALFORMED_YAML")
        self.lines: list[YamlLine] = []
        self.comments: list[tuple[int, str]] = []
        block_parent_indent: int | None = None
        raw_lines = text.splitlines()
        position = 0
        while position < len(raw_lines):
            number = position + 1
            raw = raw_lines[position]
            position += 1
            if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
                raise ScanDataError("SCN007_MALFORMED_YAML", number)
            indent = len(raw) - len(raw.lstrip(" "))
            if block_parent_indent is not None:
                if not raw.strip():
                    self.lines.append(YamlLine(block_parent_indent + 1, "", number))
                    continue
                if indent > block_parent_indent:
                    self.lines.append(YamlLine(indent, raw[indent:], number))
                    continue
                block_parent_indent = None
            comment: str | None = None
            try:
                stripped, comment = split_yaml_comment_text(raw[indent:])
            except ScanDataError as exc:
                combined = raw[indent:]
                recovered: str | None = None
                continuation = position
                while continuation < len(raw_lines):
                    next_raw = raw_lines[continuation]
                    next_number = continuation + 1
                    if "\t" in next_raw[: len(next_raw) - len(next_raw.lstrip(" \t"))]:
                        raise ScanDataError("SCN007_MALFORMED_YAML", next_number)
                    next_indent = len(next_raw) - len(next_raw.lstrip(" "))
                    if next_raw.strip() and next_indent <= indent:
                        break
                    combined += " " + next_raw.strip()
                    continuation += 1
                    try:
                        recovered, comment = split_yaml_comment_text(combined)
                    except ScanDataError:
                        continue
                    break
                if recovered is None:
                    raise ScanDataError(exc.code, number) from exc
                stripped = recovered
                position = continuation
            if comment:
                self.comments.append((number, comment))
            if not stripped:
                continue
            if stripped in {"---", "..."} or stripped.startswith("%"):
                raise ScanDataError("SCN007_MALFORMED_YAML", number)
            self.lines.append(YamlLine(indent, stripped, number))
            candidate = stripped[2:] if stripped.startswith("- ") else stripped
            split = split_yaml_mapping(candidate)
            if (
                split is not None and split[1] in {"|", "|-", "|+", ">", ">-", ">+"}
            ) or candidate in {"|", "|-", "|+", ">", ">-", ">+"}:
                block_parent_indent = indent
        self.limits = limits
        self.budget = budget

    def parse(self) -> Any:
        if not self.lines:
            raise ScanDataError("SCN007_MALFORMED_YAML")
        if self.lines[0].indent != 0:
            raise ScanDataError("SCN007_MALFORMED_YAML", self.lines[0].number)
        value, index = self.parse_block(0, 0, 1)
        if index != len(self.lines):
            raise ScanDataError("SCN007_MALFORMED_YAML", self.lines[index].number)
        ensure_unicode_scalars(value, "SCN007_MALFORMED_YAML")
        enforce_value_budget(value, self.limits, self.budget)
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
            value, index = self.parse_mapping_value(raw_value, index, indent, depth)
            result[key] = value
        return result, index

    def parse_mapping_value(
        self, raw_value: str, index: int, parent_indent: int, depth: int
    ) -> tuple[Any, int]:
        if raw_value in {"|", "|-", "|+", ">", ">-", ">+"}:
            chunks: list[str] = []
            while index < len(self.lines) and self.lines[index].indent > parent_indent:
                chunks.append(self.lines[index].text)
                index += 1
            separator = "\n" if raw_value.startswith("|") else " "
            return separator.join(chunks), index
        if raw_value:
            value = parse_yaml_scalar(raw_value)
            if isinstance(value, str) and raw_value[0] not in "[{\"'":
                chunks = [value]
                while (
                    index < len(self.lines) and self.lines[index].indent > parent_indent
                ):
                    continuation = self.lines[index]
                    if (
                        continuation.text.startswith(("-", "?"))
                        or split_yaml_mapping(continuation.text) is not None
                    ):
                        break
                    chunks.append(continuation.text.strip())
                    index += 1
                value = " ".join(chunk for chunk in chunks if chunk)
            return value, index
        if index < len(self.lines) and self.lines[index].indent > parent_indent:
            child_indent = self.lines[index].indent
            return self.parse_block(index, child_indent, depth + 1)
        if (
            index < len(self.lines)
            and self.lines[index].indent == parent_indent
            and (
                self.lines[index].text == "-" or self.lines[index].text.startswith("- ")
            )
        ):
            return self.parse_block(index, parent_indent, depth + 1)
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
            if item in {"|", "|-", "|+", ">", ">-", ">+"}:
                chunks: list[str] = []
                while index < len(self.lines) and self.lines[index].indent > indent:
                    chunks.append(self.lines[index].text)
                    index += 1
                separator = "\n" if item.startswith("|") else " "
                result.append(separator.join(chunks))
                continue
            split = split_yaml_mapping(item)
            if split is None:
                value = parse_yaml_scalar(item)
                if isinstance(value, str) and item[0] not in "[{\"'":
                    chunks = [value]
                    while index < len(self.lines) and self.lines[index].indent > indent:
                        continuation = self.lines[index]
                        if (
                            continuation.text.startswith(("-", "?"))
                            or split_yaml_mapping(continuation.text) is not None
                        ):
                            break
                        chunks.append(continuation.text.strip())
                        index += 1
                    value = " ".join(chunk for chunk in chunks if chunk)
                result.append(value)
                if index < len(self.lines) and self.lines[index].indent > indent:
                    raise ScanDataError(
                        "SCN007_MALFORMED_YAML", self.lines[index].number
                    )
                continue
            raw_key, raw_value = split
            key = parse_yaml_key(raw_key)
            seed: dict[str, Any] = {}
            value, index = self.parse_mapping_value(raw_value, index, indent, depth)
            seed[key] = value
            if index < len(self.lines) and self.lines[index].indent > indent:
                continuation_indent = self.lines[index].indent
                seed, index = self.parse_mapping(
                    index, continuation_indent, depth + 1, seed
                )
            result.append(seed)
        return result, index


def parse_yaml_bytes(
    data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
) -> Any:
    return parse_yaml_document(data, limits, budget)[0]


def parse_yaml_document(
    data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
) -> tuple[Any, list[tuple[int, str]]]:
    try:
        parser = YamlSubsetParser(data, limits, budget)
        return parser.parse(), parser.comments
    except RecursionError as exc:
        raise ScanDataError("SCN005_BUDGET_EXCEEDED") from exc
    except UnicodeEncodeError as exc:
        raise ScanDataError("SCN007_MALFORMED_YAML") from exc


def scan_yaml_comments(
    comments: list[tuple[int, str]],
    *,
    budget: WorkBudget,
    maximum_hits: int,
) -> list[ContentHit]:
    """Scan contiguous YAML comments while preserving physical line numbers."""

    hits: list[ContentHit] = []

    def scan_group(start_line: int, chunks: list[str]) -> None:
        remaining = maximum_hits - len(hits)
        if remaining <= 0:
            return
        text = "\n".join(chunks)
        budget.charge_text(text)
        for hit in scan_content(text, remaining):
            hits.append(
                ContentHit(
                    start_line + hit.line - 1,
                    hit.start,
                    hit.end,
                    hit.code,
                )
            )

    start_line = 0
    previous_line = 0
    chunks: list[str] = []
    for line, comment in comments:
        if chunks and line != previous_line + 1:
            scan_group(start_line, chunks)
            chunks = []
        if not chunks:
            start_line = line
        chunks.append(comment)
        previous_line = line
    if chunks:
        scan_group(start_line, chunks)
    return hits


@dataclass(frozen=True)
class StructuredFence:
    start_line: int
    end_line: int
    kind: str
    data: bytes


def _fence_kind(info: str) -> str | None:
    info = info.strip()
    if not info:
        return None
    candidates: list[str] = []
    if info.startswith("{") and "}" in info:
        annotation = info[1 : info.index("}")]
        candidates.extend(token.lstrip(".") for token in annotation.split())
    else:
        candidates.append(info.split(maxsplit=1)[0])
    for candidate in candidates:
        token = candidate.strip().lower().split(";", 1)[0]
        if token in {"json", "application/json"} or token.endswith("+json"):
            return "json"
        if token in {
            "yaml",
            "yml",
            "application/yaml",
            "application/x-yaml",
            "text/yaml",
        }:
            return "yaml"
        if token in {
            "jsonc",
            "json5",
            "application/jsonc",
            "application/json5",
        } or token.startswith(("jsonc", "json5")):
            return "unsupported"
        if "json" in token:
            return "unsupported"
    return None


def parse_markdown_fences(
    data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
) -> list[StructuredFence]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN") from exc
    if "\ufeff" in text or "\x00" in text:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN")
    fences: list[StructuredFence] = []
    active_marker: str | None = None
    active_marker_length = 0
    active_kind: str | None = None
    start_line = 0
    chunks: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})\s*(.*?)\s*", line)
        if active_marker is None:
            if opening is None:
                continue
            kind = _fence_kind(opening.group(2))
            if kind == "unsupported":
                raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
            if kind is None:
                continue
            marker = opening.group(1)
            active_marker = marker[0]
            active_marker_length = len(marker)
            active_kind = kind
            start_line = number
            chunks = []
            continue
        closing = re.fullmatch(
            rf" {{0,3}}{re.escape(active_marker)}{{{active_marker_length},}}\s*", line
        )
        if closing:
            nonblank_indents = [
                len(chunk) - len(chunk.lstrip(" ")) for chunk in chunks if chunk.strip()
            ]
            common_indent = min(nonblank_indents, default=0)
            dedented = [
                chunk[common_indent:] if chunk.strip() else "" for chunk in chunks
            ]
            fence_data = ("\n".join(dedented) + "\n").encode("utf-8")
            if budget is not None:
                budget.charge_work(len(fence_data))
            fences.append(
                StructuredFence(start_line, number, active_kind or "json", fence_data)
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


def markdown_outside_fences(text: str, fences: list[StructuredFence]) -> str:
    lines = text.splitlines(keepends=True)
    for fence in fences:
        for index in range(fence.start_line - 1, min(fence.end_line, len(lines))):
            lines[index] = "\n" if lines[index].endswith("\n") else ""
    return "".join(lines)


def parse_structured_data(
    kind: str, data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
) -> Any:
    if kind == "json":
        return parse_json_bytes(data, limits, budget)
    if kind == "yaml":
        return parse_yaml_bytes(data, limits, budget)
    raise AssertionError(kind)


def json_child_path(parent: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$-]*", key):
        return f"{parent}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{parent}["{escaped}"]'


def document_schema(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("openapi"), str):
        return f"openapi:{value['openapi']}"
    for key in ("schema_version", "format_id"):
        if isinstance(value.get(key), str):
            return value[key]
    return None


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
    app = principal["app"]
    if not exact_keys(app, {"app_principal_id", "label"}):
        return False
    binding = value["binding"]
    binding_ok = (
        exact_keys(binding, {"tenant"})
        and exact_keys(binding["tenant"], {"tenant_id"})
        and bounded_plain_string(binding["tenant"]["tenant_id"], 128)
    ) or (
        exact_keys(binding, {"fleet"})
        and exact_keys(binding["fleet"], {"fleet_id"})
        and bounded_plain_string(binding["fleet"]["fleet_id"], 128)
    )
    audience = value["audience"]
    audience_shapes = {
        "daemon": "daemon_id",
        "instance": "instance_id",
        "fleet": "fleet_id",
        "central_manager": "manager_id",
    }
    audience_ok = False
    if isinstance(audience, dict) and len(audience) == 1:
        kind = next(iter(audience))
        identity = audience_shapes.get(kind)
        audience_ok = bool(
            identity
            and exact_keys(audience[kind], {identity})
            and bounded_plain_string(audience[kind][identity], 128)
        )
    revocation = value["revocation"]
    revocation_ok = revocation == "active" or (
        exact_keys(revocation, {"revoked"})
        and exact_keys(revocation["revoked"], {"reason"})
        and bounded_plain_string(revocation["revoked"]["reason"], 256)
    )
    credential_id = value["credential_id"]
    return bool(
        isinstance(credential_id, str)
        and re.fullmatch(
            r"(?:(?:cred|credential)_[A-Za-z0-9._-]+|sha256:[0-9a-f]{64})",
            credential_id,
        )
        and bounded_plain_string(app["app_principal_id"], 128)
        and (app["label"] is None or bounded_plain_string(app["label"], 128))
        and bounded_plain_string(principal["client_principal_id"], 128)
        and (
            principal["label"] is None or bounded_plain_string(principal["label"], 128)
        )
        and isinstance(value["scopes"], list)
        and len(set(value["scopes"])) == len(value["scopes"])
        and all(bounded_plain_string(scope, 128) for scope in value["scopes"])
        and binding_ok
        and audience_ok
        and canonical_timestamp(value["expires_at"])
        and revocation_ok
    )


def validate_exception_node(name: str, value: Any) -> bool:
    if name == "caller_credential_ref":
        direct = {"$ref": "#/components/schemas/CallerCredential"}
        nullable = {"oneOf": [{"type": "null"}, direct]}
        return value == direct or value == nullable
    if name == "credential_correlation_id_schema":
        return value in ({"type": "string"}, {"type": ["string", "null"]})
    if name == "caller_credential_header_name":
        return value == "X-Splendor-Caller-Credential"
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
    if name == "python_acceptance_signing_material":
        return value == ("secret", "bytes")
    if name == "python_caller_auth_transport":
        return value in {
            ("token", "str"),
            ("default_credential", "dict[str, Any] | None"),
        }
    if name == "typescript_caller_auth_transport":
        return value in {("token", "string")}
    return False


@dataclass
class StructuredScan:
    hits: list[ContentHit]
    findings: list[Finding]


def _openapi_payload_root(path: str) -> bool:
    if re.search(r"\.(?:example|default|const)(?:\[[0-9]+\])*$", path):
        return True
    if re.search(r"\.examples\[[0-9]+\](?:\[[0-9]+\])*$", path):
        return True
    return ".examples." in path and path.endswith(".value")


def scan_structured_value(
    value: Any,
    *,
    file_path: str,
    doc_schema: str | None,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: set[tuple[str, str, str]],
    budget: WorkBudget,
    maximum_hits: int,
    owner_exact: bool = False,
    base_line: int = 1,
) -> StructuredScan:
    hits: list[ContentHit] = []
    findings: list[Finding] = []
    openapi_mode = bool(doc_schema and doc_schema.startswith("openapi:"))

    def add_text(text: str, *, context: bool, line: int) -> None:
        budget.charge_text(text)
        remaining = maximum_hits - len(hits)
        if remaining <= 0:
            return
        for hit in scan_content(text, remaining, authorization_context=context):
            hits.append(ContentHit(line + hit.line - 1, hit.start, hit.end, hit.code))

    def walk(
        current: Any,
        path: str,
        *,
        structural_enabled: bool,
        openapi_payload: bool,
        parent_key: str | None,
    ) -> None:
        if isinstance(current, dict):
            openapi_payload = openapi_payload or _openapi_payload_root(path)
            if (
                structural_enabled
                and not owner_exact
                and object_is_fake_wrapper(current)
            ):
                findings.append(Finding(file_path, base_line, "SCF002_FAKE_WRAPPER"))
            for key, child in current.items():
                add_text(key, context=False, line=base_line)
                child_path = json_child_path(path, key)
                inspect_key = (
                    not openapi_mode or path.endswith(".properties") or openapi_payload
                )
                parameter_name = (
                    openapi_mode
                    and key == "name"
                    and isinstance(child, str)
                    and "in" in current
                )
                is_secret_coordinate = (inspect_key and is_secret_field_name(key)) or (
                    parameter_name and is_secret_field_name(child)
                )
                child_structural = structural_enabled
                if structural_enabled and not owner_exact and is_secret_coordinate:
                    identity = (file_path, doc_schema or "", child_path)
                    entry = exceptions.get(identity)
                    if entry is None:
                        findings.append(
                            Finding(file_path, base_line, "SCF001_SECRET_FIELD")
                        )
                    else:
                        used_exceptions.add(identity)
                        if validate_exception_node(entry["validator"], child):
                            child_structural = False
                        else:
                            findings.append(
                                Finding(
                                    file_path, base_line, "SCF004_INVALID_EXCEPTION"
                                )
                            )
                walk(
                    child,
                    child_path,
                    structural_enabled=child_structural,
                    openapi_payload=openapi_payload,
                    parent_key=key,
                )
        elif isinstance(current, list):
            for index, child in enumerate(current):
                walk(
                    child,
                    f"{path}[{index}]",
                    structural_enabled=structural_enabled,
                    openapi_payload=openapi_payload,
                    parent_key=parent_key,
                )
        elif isinstance(current, str):
            add_text(
                current,
                context=is_authorization_context(parent_key)
                or (openapi_mode and parent_key in {"example", "default", "const"}),
                line=base_line,
            )

    walk(
        value,
        "$",
        structural_enabled=True,
        openapi_payload=False,
        parent_key=None,
    )
    return StructuredScan(hits, findings)


def _annotation_text(annotation: ast.expr | None) -> str:
    if annotation is None:
        return ""
    try:
        return ast.unparse(annotation)
    except (ValueError, RecursionError):
        return ""


_SAFE_SOURCE_TYPES = re.compile(
    r"\b(?:CallerCredential|Credential(?:Id|Ref)(?:V[0-9]+)?|Secret(?:Ref(?:V[0-9]+)?|UseRequirement|CredentialAuthorization)|Redacted(?:Value|Bytes|String)?|Digest(?:Ref|Value)?|PublicKey(?:Ref|Bytes)?)\b"
)
_RAW_SOURCE_TYPES = re.compile(
    r"\b(?:Any|Buffer|Uint8Array|bytes|bytearray|dict|object|str|string|unknown)\b"
)


def _safe_source_type(value: str) -> bool:
    return bool(_SAFE_SOURCE_TYPES.search(value)) and not _RAW_SOURCE_TYPES.search(
        value
    )


def _source_exception(
    *,
    file_path: str,
    schema: str,
    field_path: str,
    node: tuple[str, str],
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: set[tuple[str, str, str]],
) -> bool:
    identity = (file_path, schema, field_path)
    entry = exceptions.get(identity)
    if entry is None:
        return False
    used_exceptions.add(identity)
    if validate_exception_node(entry["validator"], node):
        return True
    raise ScanDataError("SCF004_INVALID_EXCEPTION")


def scan_python_source(
    text: str,
    *,
    file_path: str,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: set[tuple[str, str, str]],
    budget: WorkBudget,
    maximum_hits: int,
) -> StructuredScan:
    del maximum_hits
    try:
        tree = ast.parse(text, filename=file_path)
    except (SyntaxError, ValueError, RecursionError) as exc:
        line = exc.lineno if isinstance(exc, SyntaxError) and exc.lineno else 0
        raise ScanDataError("SCN011_MALFORMED_SOURCE", line) from exc
    hits: list[ContentHit] = []
    findings: list[Finding] = []
    schema = "python:source.v1"
    for node in ast.walk(tree):
        budget.charge_structure()
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            name: str | None = None
            annotation = ""
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                name = statement.target.id
                annotation = _annotation_text(statement.annotation)
            elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name):
                    name = target.id
            if name is None:
                continue
            budget.charge_text(name)
            field_path = f"$.classes.{node.name}.fields.{name}"
            if is_secret_field_name(name) and not _safe_source_type(annotation):
                try:
                    allowed = _source_exception(
                        file_path=file_path,
                        schema=schema,
                        field_path=field_path,
                        node=(name, annotation),
                        exceptions=exceptions,
                        used_exceptions=used_exceptions,
                    )
                except ScanDataError:
                    findings.append(
                        Finding(file_path, statement.lineno, "SCF004_INVALID_EXCEPTION")
                    )
                    allowed = True
                if not allowed:
                    findings.append(
                        Finding(file_path, statement.lineno, "SCF005_SOURCE_FIELD")
                    )
    return StructuredScan(hits, findings)


_TS_BLOCK = re.compile(
    r"^\s*(?:(?:export|default|declare|abstract)\s+)*"
    r"(?:(interface|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)|"
    r"type\s+([A-Za-z_$][A-Za-z0-9_$]*)(?:\s*<[^>{}\n]{1,512}>)?\s*=)"
)
_TS_FIELD_NAME = (
    r'(?:#?[A-Za-z_$][A-Za-z0-9_$-]*|["\'][A-Za-z_$][A-Za-z0-9_$-]*["\']|'
    r'\[\s*["\'][A-Za-z_$][A-Za-z0-9_$-]*["\']\s*\])'
)
_TS_FIELD = re.compile(
    rf"^\s*(?:(?:public|private|protected|static|readonly|declare|abstract)\s+)*"
    rf"(?P<name>{_TS_FIELD_NAME})[?!]?\s*[:=]\s*(?P<type>[^;]+)"
)
_TS_BARE_FIELD = re.compile(
    rf"^\s*(?:(?:public|private|protected|static|readonly|declare|abstract)\s+)*"
    rf"(?P<name>{_TS_FIELD_NAME})\??\s*$"
)
_TS_PARAMETER_FIELD = re.compile(
    rf"(?:(?:public|private|protected|readonly)\s+)+"
    rf"(?P<name>{_TS_FIELD_NAME})\??\s*:\s*(?P<type>[^,)=]+)"
)


def _typescript_field_name(raw: str) -> str:
    value = raw.strip()
    if value.startswith("["):
        value = value[1:-1].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.removeprefix("#")


def _brace_delta(line: str) -> int:
    result: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            result.append(" ")
            index += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            result.append(" ")
            index += 1
            continue
        if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
            break
        result.append(char)
        index += 1
    cleaned = "".join(result)
    return cleaned.count("{") - cleaned.count("}")


def scan_typescript_source(
    text: str,
    *,
    file_path: str,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: set[tuple[str, str, str]],
    budget: WorkBudget,
    maximum_hits: int,
) -> StructuredScan:
    del maximum_hits
    findings: list[Finding] = []
    schema = "typescript:source.v1"
    block_kind: str | None = None
    block_name: str | None = None
    depth = 0

    def inspect_field(raw_name: str, declared_type: str, number: int) -> None:
        assert block_name is not None
        name = _typescript_field_name(raw_name)
        budget.charge_text(name)
        collection = {
            "interface": "interfaces",
            "class": "classes",
            "type": "types",
        }[block_kind or "type"]
        field_path = f"$.{collection}.{block_name}.fields.{name}"
        if not is_secret_field_name(name) or _safe_source_type(declared_type):
            return
        try:
            allowed = _source_exception(
                file_path=file_path,
                schema=schema,
                field_path=field_path,
                node=(name, declared_type),
                exceptions=exceptions,
                used_exceptions=used_exceptions,
            )
        except ScanDataError:
            findings.append(Finding(file_path, number, "SCF004_INVALID_EXCEPTION"))
            return
        if not allowed:
            findings.append(Finding(file_path, number, "SCF005_SOURCE_FIELD"))

    def inspect_line(line: str, number: int) -> None:
        for segment in line.split(";"):
            field = _TS_FIELD.match(segment)
            if field is not None:
                inspect_field(field.group("name"), field.group("type").strip(), number)
                continue
            bare_field = _TS_BARE_FIELD.match(segment)
            if bare_field is not None:
                inspect_field(bare_field.group("name"), "", number)
        if "constructor" in line:
            for parameter in _TS_PARAMETER_FIELD.finditer(line):
                inspect_field(
                    parameter.group("name"), parameter.group("type").strip(), number
                )

    for number, line in enumerate(text.splitlines(), 1):
        budget.charge_structure()
        if block_name is None:
            match = _TS_BLOCK.match(line)
            if match is None:
                continue
            block_kind = match.group(1) or "type"
            block_name = match.group(2) or match.group(3)
            depth = _brace_delta(line)
            opening = line.find("{", match.end())
            if opening >= 0:
                inspect_line(line[opening + 1 :], number)
            if depth <= 0 and opening >= 0:
                block_kind = None
                block_name = None
                depth = 0
            continue
        if depth == 1:
            inspect_line(line, number)
        depth += _brace_delta(line)
        if depth <= 0:
            block_kind = None
            block_name = None
            depth = 0
    if block_name is not None:
        raise ScanDataError("SCN011_MALFORMED_SOURCE")
    return StructuredScan([], findings)


def looks_like_yaml_document(text: str) -> bool:
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "---":
            return True
        if stripped == "-" or stripped.startswith("- "):
            return True
        return split_yaml_mapping(stripped) is not None
    return False
