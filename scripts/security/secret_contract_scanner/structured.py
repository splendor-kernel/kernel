"""Closed JSON/YAML/Markdown parsing and bounded structural/source checks."""

from __future__ import annotations

import ast
import datetime as dt
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .content import (
    is_authorization_context,
    is_credential_metadata_field,
    is_secret_field_name,
    normalize_field_name,
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
    if budget is not None:
        budget.charge_parser_operations(len(text))
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
                    or any(unicodedata.category(char) in {"Cc", "Cf"} for char in key)
                ):
                    raise ScanDataError(code)
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            if (
                utf8_size(current) is None
                or "\x00" in current
                or "\ufeff" in current
                or any(
                    unicodedata.category(char) in {"Cc", "Cf"}
                    and char not in {"\n", "\r", "\t"}
                    for char in current
                )
            ):
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
            budget.charge_parser_operations()
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
        if budget is not None:
            # The closed parser makes a fixed bounded number of character
            # passes for comments, mapping separators, and scalar decoding.
            budget.charge_parser_operations(len(text) * 8)
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
        for hit in scan_content(
            text, remaining, assignment_context=True, budget=budget
        ):
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
    myst = re.fullmatch(
        r"\{(?:code-block|sourcecode)\}(?:\s+(.+))?",
        info,
        flags=re.IGNORECASE,
    )
    if myst is not None:
        language = myst.group(1)
        if language is None or len(language.split()) != 1:
            return "unsupported"
        candidates.append(language)
    elif info.startswith("{") and "}" in info:
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
        if token in {"py", "python", "python3"}:
            return "python_source"
        if token in {
            "cjs",
            "javascript",
            "js",
            "jsx",
            "mjs",
            "mts",
            "node",
            "ts",
            "tsx",
            "typescript",
        }:
            return "typescript_source"
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


def _commonmark_container_prefixes(
    line: str, maximum_depth: int
) -> tuple[str, str, str, bool]:
    """Return normalized text plus opener and continuation container prefixes."""

    current = line
    opener = ""
    continuation = ""
    for _ in range(maximum_depth):
        quote = re.match(r"^ {0,3}> ?", current)
        if quote is not None:
            marker = current[: quote.end()]
            opener += marker
            continuation += marker
            current = current[quote.end() :]
            continue
        listing = re.match(r"^ {0,3}(?:[-+*]|[0-9]{1,9}[.)]) {1,4}", current)
        if listing is not None:
            marker = current[: listing.end()]
            opener += marker
            continuation += " " * len(marker)
            current = current[listing.end() :]
            continue
        break
    residual = bool(
        re.match(r"^ {0,3}> ?", current)
        or re.match(r"^ {0,3}(?:[-+*]|[0-9]{1,9}[.)]) {1,4}", current)
    )
    return current, opener, continuation, residual


def parse_markdown_fences(
    data: bytes, limits: dict[str, int], budget: WorkBudget | None = None
) -> list[StructuredFence]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN") from exc
    if "\ufeff" in text or "\x00" in text:
        raise ScanDataError("SCN008_MALFORMED_MARKDOWN")
    if budget is not None:
        budget.charge_parser_operations(len(text) * 4)
    fences: list[StructuredFence] = []
    active_marker: str | None = None
    active_marker_length = 0
    active_kind: str | None = None
    active_prefix = ""
    continuation_prefix = ""
    start_line = 0
    chunks: list[str] = []
    active_myst = False
    myst_options_open = False
    myst_option_count = 0
    for number, physical_line in enumerate(text.splitlines(), 1):
        if active_marker is None:
            (
                line,
                opening_prefix,
                opening_continuation,
                residual_container,
            ) = _commonmark_container_prefixes(
                physical_line, limits["max_structure_depth"]
            )
            if residual_container:
                raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
        elif active_prefix and physical_line.startswith(active_prefix):
            line = physical_line[len(active_prefix) :]
            opening_prefix = ""
            opening_continuation = ""
        elif continuation_prefix and physical_line.startswith(continuation_prefix):
            line = physical_line[len(continuation_prefix) :]
            opening_prefix = ""
            opening_continuation = ""
        else:
            line = physical_line
            opening_prefix = ""
            opening_continuation = ""
        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})\s*(.*?)\s*", line)
        colon_opening = re.fullmatch(
            r" {0,3}(:{3,})\{(?:code-block|sourcecode)\}\s*(.*?)\s*",
            line,
            flags=re.IGNORECASE,
        )
        if active_marker is None:
            if opening is None and colon_opening is None:
                continue
            if colon_opening is not None:
                marker_text = colon_opening.group(1)
                info = "{code-block} " + colon_opening.group(2)
            else:
                assert opening is not None
                marker_text = opening.group(1)
                info = opening.group(2)
            kind = _fence_kind(info)
            if kind == "unsupported":
                raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
            if kind is None:
                continue
            active_marker = marker_text[0]
            active_marker_length = len(marker_text)
            active_kind = kind
            active_myst = colon_opening is not None or bool(
                re.match(r"\{(?:code-block|sourcecode)\}", info, flags=re.IGNORECASE)
            )
            myst_options_open = active_myst
            myst_option_count = 0
            active_prefix = opening_prefix
            continuation_prefix = opening_continuation
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
            active_myst = False
            myst_options_open = False
            myst_option_count = 0
            active_prefix = ""
            continuation_prefix = ""
            chunks = []
        else:
            if active_myst and myst_options_open:
                option = re.fullmatch(
                    r" {0,3}:([A-Za-z][A-Za-z0-9_-]{0,63}):(?:[ \t]+(.*))?",
                    line,
                )
                if option is not None:
                    if option.group(1).lower() not in {
                        "caption",
                        "class",
                        "dedent",
                        "emphasize-lines",
                        "lineno-start",
                        "linenos",
                        "name",
                    }:
                        raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
                    option_value = option.group(2) or ""
                    if len(option_value) > 512:
                        raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
                    myst_option_count += 1
                    if myst_option_count > 16:
                        raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
                    if budget is not None:
                        budget.charge_text(option_value)
                    if scan_content(
                        option_value,
                        1,
                        assignment_context=True,
                        budget=budget,
                    ):
                        raise ScanDataError("SCN008_MALFORMED_MARKDOWN", number)
                    continue
                if not line.strip():
                    continue
                myst_options_open = False
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
        return value in {
            SourceDeclaration("secret", "bytes", "class_field", "one", "absent"),
            SourceDeclaration(
                "request_secrets",
                "set[bytes]",
                "function_field",
                "one",
                "expression",
            ),
            SourceDeclaration(
                "request_secrets", "", "function_field", "one", "expression"
            ),
            SourceDeclaration(
                "evidence_secrets", "", "function_field", "one", "expression"
            ),
            SourceDeclaration("secret", "", "function_field", "one", "expression"),
            SourceDeclaration("private_key", "Path", "parameter", "one", "absent"),
            SourceDeclaration("signing_key", "Path", "parameter", "one", "absent"),
            SourceDeclaration("_private_key", "", "self_field", "one", "expression"),
        }
    if name == "python_acceptance_auth_projection":
        return value == SourceDeclaration(
            "auth_value", "", "function_field", "one", "expression"
        )
    if name == "python_caller_auth_transport":
        return value in {
            SourceDeclaration("token", "str", "class_field", "one", "absent"),
            SourceDeclaration(
                "default_credential",
                "dict[str, Any] | None",
                "class_field",
                "one",
                "none",
            ),
            SourceDeclaration(
                "credential",
                "dict[str, Any] | None",
                "parameter",
                "one",
                "none",
            ),
            SourceDeclaration(
                "credential",
                "dict[str, Any] | None",
                "parameter",
                "one",
                "absent",
            ),
            SourceDeclaration(
                "header_credential",
                "dict[str, Any] | None",
                "parameter",
                "one",
                "none",
            ),
            SourceDeclaration("credential", "", "object_field", "one", "expression"),
            SourceDeclaration("Authorization", "", "object_field", "one", "expression"),
            SourceDeclaration(
                "X-Splendor-Caller-Credential",
                "",
                "object_field",
                "one",
                "expression",
            ),
        }
    if name == "typescript_caller_auth_transport":
        return value in {
            SourceDeclaration("token", "string", "interface_field", "one", "absent"),
            SourceDeclaration("token", "string", "class_field", "one", "absent"),
            SourceDeclaration("token", "", "source_field", "one", "expression"),
            SourceDeclaration(
                "credential",
                "CallerCredential",
                "source_field",
                "one",
                "expression",
            ),
            SourceDeclaration(
                "defaultCredential", "", "source_field", "one", "expression"
            ),
            SourceDeclaration("credential", "", "object_field", "one", "expression"),
            SourceDeclaration("Authorization", "", "object_field", "one", "expression"),
        }
    if name == "typescript_owner_safe_reference":
        return value in {
            SourceDeclaration(
                "CredentialBinding", "", "source_field", "one", "expression"
            ),
            SourceDeclaration(
                "CredentialAudience", "", "source_field", "one", "expression"
            ),
            SourceDeclaration("CallerCredential", "", "source_field", "one", "absent"),
            SourceDeclaration(
                "WorkOrderAuthorization", "", "source_field", "one", "absent"
            ),
            SourceDeclaration(
                "credential",
                "CallerCredential",
                "interface_field",
                "one",
                "absent",
            ),
            SourceDeclaration(
                "credential",
                "CallerCredential|null",
                "interface_field",
                "one",
                "absent",
            ),
        }
    if name == "typescript_json_value_index":
        return value in {
            SourceDeclaration("key", "key:string", "index_signature", "many", "absent"),
            SourceDeclaration(
                "adapter", "adapter:string", "index_signature", "many", "absent"
            ),
        }
    if name == "typescript_record_key":
        return value in {
            SourceDeclaration(
                "StablePrimitiveName",
                "StablePrimitiveName",
                "record_key",
                "many",
                "absent",
            ),
            SourceDeclaration("string", "string", "record_key", "many", "absent"),
        }
    return False


@dataclass
class StructuredScan:
    hits: list[ContentHit]
    findings: list[Finding]


def _openapi_payload_root(path: str) -> bool:
    if re.search(r"\.(?:example|default|const|enum|value)(?:\[[0-9]+\])*$", path):
        return True
    if re.search(r"\.examples\[[0-9]+\](?:\[[0-9]+\])*$", path):
        return True
    return ".examples." in path and path.endswith(".value")


_OPENAPI_SAFE_SECURITY_KEYS = {
    "authorization_code",
    "authorization_url",
    "bearer_format",
    "client_credentials",
    "description",
    "flows",
    "implicit",
    "in",
    "name",
    "open_id_connect_url",
    "password",
    "refresh_url",
    "scheme",
    "scopes",
    "token_url",
    "type",
}


def _openapi_security_secret_coordinate(path: str, key: str) -> bool:
    if not path.startswith("$.components.securitySchemes.") or ".scopes" in path:
        return False
    normalized = normalize_field_name(key)
    return (
        normalized not in _OPENAPI_SAFE_SECURITY_KEYS
        and not normalized.startswith("x_public_")
        and is_secret_field_name(key)
    )


_IDENTIFIER_MAP_PATHS = {
    "$.components.callbacks",
    "$.components.examples",
    "$.components.headers",
    "$.components.links",
    "$.components.parameters",
    "$.components.requestBodies",
    "$.components.responses",
    "$.components.schemas",
    "$.components.securitySchemes",
    "$.configs",
    "$.jobs",
    "$.networks",
    "$.permissions",
    "$.services",
    "$.volumes",
    "$.webhooks",
}


def _mapping_keys_are_identifiers(path: str) -> bool:
    """Return whether this mapping's keys are names, not record fields.

    Workflow job IDs, Compose service/volume IDs, and OpenAPI registry/security
    references may legitimately contain words such as ``secret`` or
    ``credential``. Their child values still receive ordinary content scanning,
    and real fields below those named entries remain structural coordinates.
    """

    return bool(
        path in _IDENTIFIER_MAP_PATHS
        or re.fullmatch(r"\$\.paths(?:\[.*?\]|\.[^.]+)?", path)
        or re.search(r"\.security\[[0-9]+\]$", path)
        or path.endswith((".$defs", ".definitions"))
    )


def scan_structured_value(
    value: Any,
    *,
    file_path: str,
    doc_schema: str | None,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: dict[tuple[str, str, str], int],
    budget: WorkBudget,
    maximum_hits: int,
    owner_exact: bool = False,
    structural_fields_enabled: bool = True,
    base_line: int = 1,
) -> StructuredScan:
    hits: list[ContentHit] = []
    findings: list[Finding] = []
    openapi_mode = bool(doc_schema and doc_schema.startswith("openapi:"))

    def add_text(
        text: str,
        *,
        context: bool,
        line: int,
        assignment_key: str | None = None,
        force_assignment: bool = False,
    ) -> None:
        prefix = (
            "credential="
            if assignment_key is not None and force_assignment
            else f"{assignment_key}="
            if assignment_key is not None and is_secret_field_name(assignment_key)
            else ""
        )
        scan_text = prefix + text
        budget.charge_text(scan_text)
        remaining = maximum_hits - len(hits)
        if remaining <= 0:
            return
        for hit in scan_content(
            scan_text,
            remaining,
            authorization_context=context,
            assignment_context=True,
            budget=budget,
        ):
            if hit.end <= len(prefix):
                continue
            hits.append(
                ContentHit(
                    line + hit.line - 1,
                    max(0, hit.start - len(prefix)),
                    max(1, hit.end - len(prefix)),
                    hit.code,
                )
            )

    def walk(
        current: Any,
        path: str,
        *,
        structural_enabled: bool,
        assignment_enabled: bool,
        openapi_payload: bool,
        parent_key: str | None,
        credential_ancestor: bool,
    ) -> None:
        if isinstance(current, dict):
            openapi_payload = openapi_payload or _openapi_payload_root(path)
            identifier_keys = _mapping_keys_are_identifiers(path)
            if (
                openapi_mode
                and structural_enabled
                and not owner_exact
                and re.fullmatch(
                    r"\$\.components\.securitySchemes\.[A-Za-z0-9_$-]+", path
                )
                and current.get("type") == "apiKey"
            ):
                findings.append(Finding(file_path, base_line, "SCF001_SECRET_FIELD"))
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
                    not openapi_mode
                    or path.endswith((".properties", ".headers"))
                    or openapi_payload
                )
                parameter_name = (
                    openapi_mode
                    and key == "name"
                    and isinstance(child, str)
                    and "in" in current
                )
                is_secret_coordinate = (
                    (inspect_key and is_secret_field_name(key))
                    or _openapi_security_secret_coordinate(path, key)
                    or (parameter_name and is_secret_field_name(child))
                )
                child_structural = structural_enabled
                child_assignment = assignment_enabled
                child_credential_ancestor = credential_ancestor or (
                    not identifier_keys and is_secret_field_name(key)
                )
                if structural_enabled and not owner_exact and is_secret_coordinate:
                    identity = (file_path, doc_schema or "", child_path)
                    entry = exceptions.get(identity)
                    if entry is None:
                        findings.append(
                            Finding(file_path, base_line, "SCF001_SECRET_FIELD")
                        )
                    else:
                        used_exceptions[identity] = used_exceptions.get(identity, 0) + 1
                        if validate_exception_node(entry["validator"], child):
                            child_structural = False
                            child_assignment = False
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
                    assignment_enabled=child_assignment,
                    openapi_payload=openapi_payload,
                    parent_key=key,
                    credential_ancestor=child_credential_ancestor,
                )
        elif isinstance(current, list):
            openapi_payload = openapi_payload or (
                openapi_mode and _openapi_payload_root(path)
            )
            for index, child in enumerate(current):
                walk(
                    child,
                    f"{path}[{index}]",
                    structural_enabled=structural_enabled,
                    assignment_enabled=assignment_enabled,
                    openapi_payload=openapi_payload,
                    parent_key=parent_key,
                    credential_ancestor=credential_ancestor,
                )
        elif isinstance(current, str):
            add_text(
                current,
                context=is_authorization_context(parent_key)
                or credential_ancestor
                or openapi_payload
                or (
                    openapi_mode
                    and parent_key
                    in {"const", "default", "enum", "example", "examples", "value"}
                ),
                line=base_line,
                assignment_key=parent_key if assignment_enabled else None,
                force_assignment=bool(
                    assignment_enabled
                    and credential_ancestor
                    and parent_key
                    and not is_credential_metadata_field(parent_key)
                ),
            )

    walk(
        value,
        "$",
        structural_enabled=structural_fields_enabled,
        assignment_enabled=not owner_exact,
        openapi_payload=False,
        parent_key=None,
        credential_ancestor=False,
    )
    return StructuredScan(hits, findings)


def _annotation_text(annotation: ast.expr | None) -> str:
    if annotation is None:
        return ""
    try:
        return ast.unparse(annotation)
    except (ValueError, RecursionError):
        return ""


_PYTHON_SAFE_MODULES = {"splendor", "splendor.types", "splendor.secret_refs"}
_TYPESCRIPT_SAFE_MODULE = "@splendor/types"


@dataclass(frozen=True)
class SourceDeclaration:
    name: str
    declared_type: str
    declaration_kind: str
    cardinality: str
    default_kind: str


def _source_exception(
    *,
    file_path: str,
    schema: str,
    field_path: str,
    node: SourceDeclaration,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: dict[tuple[str, str, str], int],
) -> bool:
    identity = (file_path, schema, field_path)
    entry = exceptions.get(identity)
    if entry is None:
        return False
    used_exceptions[identity] = used_exceptions.get(identity, 0) + 1
    if validate_exception_node(entry["validator"], node):
        return True
    raise ScanDataError("SCF004_INVALID_EXCEPTION")


def _default_kind(value: ast.expr | None, *, absent: bool = False) -> str:
    if absent:
        return "absent"
    if isinstance(value, ast.Constant):
        if value.value is None:
            return "none"
        if value.value is Ellipsis:
            return "required"
        return "literal"
    return "expression"


def _python_safe_imports(
    tree: ast.Module, allowed_types: set[str]
) -> tuple[dict[str, str], dict[str, str]]:
    names: dict[str, str] = {}
    modules: dict[str, str] = {}
    canonical_bindings: dict[str, int] = {}
    for statement in tree.body:
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module in _PYTHON_SAFE_MODULES
        ):
            for alias in statement.names:
                if alias.name in allowed_types:
                    local = alias.asname or alias.name
                    names[local] = alias.name
                    canonical_bindings[local] = canonical_bindings.get(local, 0) + 1
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in _PYTHON_SAFE_MODULES:
                    local = alias.asname or alias.name.split(".")[0]
                    modules[local] = alias.name
                    canonical_bindings[local] = canonical_bindings.get(local, 0) + 1

    bound_counts: dict[str, int] = {}
    invalid_modules: set[str] = set()

    def bind(name: str | None) -> None:
        if name:
            bound_counts[name] = bound_counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            bind(node.name)
        elif isinstance(node, ast.arg):
            bind(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id)
        elif isinstance(node, ast.ExceptHandler):
            bind(node.name)
        elif node.__class__.__name__ in {"MatchAs", "MatchStar"}:
            bind(getattr(node, "name", None))
        elif isinstance(node, ast.alias):
            bind(node.asname or node.name.split(".")[0])
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and isinstance(node.value, ast.Name)
        ):
            invalid_modules.add(node.value.id)
        elif isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root: ast.expr = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                invalid_modules.add(root.id)
        elif isinstance(node, ast.Call):
            function = _annotation_text(node.func)
            if function in {"eval", "exec", "globals", "locals"}:
                names.clear()
            if (
                function in {"setattr", "delattr"}
                and node.args
                and isinstance(node.args[0], ast.Name)
            ):
                invalid_modules.add(node.args[0].id)

    for name in set(names) | set(modules):
        if canonical_bindings.get(name) != 1 or bound_counts.get(name) != 1:
            names.pop(name, None)
            modules.pop(name, None)
    for name in invalid_modules:
        modules.pop(name, None)
    return names, modules


def _flatten_python_union(annotation: ast.expr) -> list[ast.expr]:
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _flatten_python_union(annotation.left) + _flatten_python_union(
            annotation.right
        )
    if isinstance(annotation, ast.Subscript):
        base = _annotation_text(annotation.value).replace(" ", "")
        if base in {"Optional", "typing.Optional"}:
            return [annotation.slice, ast.Constant(value=None)]
        if base in {"Union", "typing.Union"}:
            if isinstance(annotation.slice, ast.Tuple):
                return list(annotation.slice.elts)
            return [annotation.slice]
    return [annotation]


def _python_type_is_safe(
    annotation: ast.expr | None,
    *,
    safe_names: dict[str, str],
    safe_modules: dict[str, str],
    allowed_types: set[str],
    default_kind: str,
) -> bool:
    if annotation is None or default_kind not in {"absent", "none", "required"}:
        return False
    safe_count = 0
    for member in _flatten_python_union(annotation):
        if isinstance(member, ast.Constant) and member.value is None:
            continue
        if isinstance(member, ast.Name) and member.id in safe_names:
            safe_count += 1
            continue
        if isinstance(member, ast.Attribute) and isinstance(member.value, ast.Name):
            module = safe_modules.get(member.value.id)
            if module in _PYTHON_SAFE_MODULES and member.attr in allowed_types:
                safe_count += 1
                continue
        return False
    return safe_count == 1


def _python_source_offset(lines: list[int], node: ast.AST) -> int:
    line = max(1, getattr(node, "lineno", 1))
    return lines[min(line - 1, len(lines) - 1)] + getattr(node, "col_offset", 0)


def _sensitive_parameter(name: str) -> bool:
    return is_secret_field_name(name)


def _python_static_string(
    node: ast.expr,
    depth: int = 0,
    bindings: dict[str, str] | None = None,
) -> str | None:
    if depth > 16:
        return None
    if isinstance(node, ast.Name) and bindings is not None:
        return bindings.get(node.id)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_static_string(node.left, depth + 1, bindings)
        right = _python_static_string(node.right, depth + 1, bindings)
        if left is not None and right is not None and len(left) + len(right) <= 512:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        joined = "".join(parts)
        return joined if len(joined) <= 512 else None
    return None


def _python_static_string_bindings(tree: ast.Module) -> dict[str, str]:
    """Resolve simple constant keys conservatively across the source unit."""

    candidates: dict[str, list[str]] = {}
    assignment_values: dict[str, list[ast.expr]] = {}
    stores: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[node.id] = stores.get(node.id, 0) + 1
        assignments: list[tuple[ast.expr, ast.expr]] = []
        if isinstance(node, ast.Assign):
            assignments.extend((target, node.value) for target in node.targets)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append((node.target, node.value))
        elif isinstance(node, ast.NamedExpr):
            assignments.append((node.target, node.value))
        for target, value_node in assignments:
            if not isinstance(target, ast.Name):
                continue
            assignment_values.setdefault(target.id, []).append(value_node)
            value = _python_static_string(value_node)
            if value is not None:
                candidates.setdefault(target.id, []).append(value)

    resolved: dict[str, str] = {}
    for name, values in candidates.items():
        sensitive = next(
            (value for value in values if is_secret_field_name(value)), None
        )
        if sensitive is not None:
            # Any credential-capable binding makes later dynamic key use unsafe,
            # even if the name is rebound elsewhere.
            resolved[name] = sensitive
        elif stores.get(name) == 1 and len(values) == 1:
            resolved[name] = values[0]

    def resolve_alias(name: str, visiting: set[str]) -> str | None:
        if name in resolved:
            return resolved[name]
        values = assignment_values.get(name, [])
        if stores.get(name) != 1 or len(values) != 1 or name in visiting:
            return None
        value_node = values[0]
        if not isinstance(value_node, ast.Name):
            return None
        value = resolve_alias(value_node.id, {*visiting, name})
        if value is not None:
            resolved[name] = value
        return value

    for name in assignment_values:
        resolve_alias(name, set())

    dependents: dict[str, set[str]] = {}
    for binding_name, value_nodes in assignment_values.items():
        for bound_value_node in value_nodes:
            if isinstance(bound_value_node, ast.Name):
                dependents.setdefault(bound_value_node.id, set()).add(binding_name)
    queue = [name for name, value in resolved.items() if is_secret_field_name(value)]
    cursor = 0
    while cursor < len(queue):
        source = queue[cursor]
        cursor += 1
        for dependent_name in dependents.get(source, set()):
            if dependent_name in resolved and is_secret_field_name(
                resolved[dependent_name]
            ):
                continue
            resolved[dependent_name] = resolved[source]
            queue.append(dependent_name)
    return resolved


def _python_dynamic_key_is_credential_capable(
    node: ast.expr, bindings: dict[str, str] | None = None
) -> bool:
    resolved = _python_static_string(node, bindings=bindings)
    if resolved is not None and is_secret_field_name(resolved):
        return True
    fragments = [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]
    fragments.extend(
        child.id for child in ast.walk(node) if isinstance(child, ast.Name)
    )
    fragments.extend(
        child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)
    )
    joined = "".join(fragments)
    for value in [*fragments, joined]:
        if not value:
            continue
        normalized = normalize_field_name(value)
        if is_credential_metadata_field(normalized):
            continue
        if is_secret_field_name(value) or normalized.startswith(
            ("auth", "cred", "pass", "private", "secret", "token")
        ):
            return True
    return False


def scan_python_source(
    text: str,
    *,
    file_path: str,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: dict[tuple[str, str, str], int],
    budget: WorkBudget,
    maximum_hits: int,
    safe_type_names: set[str] | None = None,
) -> StructuredScan:
    try:
        tree = ast.parse(text, filename=file_path)
    except (SyntaxError, ValueError, RecursionError) as exc:
        line = exc.lineno if isinstance(exc, SyntaxError) and exc.lineno else 0
        raise ScanDataError("SCN011_MALFORMED_SOURCE", line) from exc
    hits: list[ContentHit] = []
    findings: list[Finding] = []
    schema = "python:source.v1"
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > budget.limits["max_structure_depth"]:
            raise ScanDataError("SCN011_MALFORMED_SOURCE", getattr(node, "lineno", 0))
        budget.charge_structure()
        budget.charge_parser_operations()
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    allowed_safe_types = safe_type_names or set()
    safe_names, safe_modules = _python_safe_imports(tree, allowed_safe_types)
    static_strings = _python_static_string_bindings(tree)
    line_offsets = [0]
    for match in re.finditer("\n", text):
        line_offsets.append(match.end())

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.classes: list[str] = []
            self.functions: list[str] = []
            self.scopes: list[str] = []
            self.context_literals: set[int] = set()

        def object_field_path(self, name: str) -> str:
            if self.functions and self.classes:
                return (
                    f"$.classes.{self.classes[-1]}.methods.{self.functions[-1]}."
                    f"object_fields.{name}"
                )
            if self.functions:
                return f"$.functions.{self.functions[-1]}.object_fields.{name}"
            if self.classes:
                return f"$.classes.{self.classes[-1]}.object_fields.{name}"
            return f"$.module.object_fields.{name}"

        def inspect_object_field(
            self, name: str, value: ast.expr | None, line: int
        ) -> None:
            self.inspect(
                name=name,
                annotation=None,
                default=value,
                default_absent=value is None,
                kind="object_field",
                path=self.object_field_path(name),
                line=line,
            )
            self.scan_literal(value, name)

        def inspect(
            self,
            *,
            name: str,
            annotation: ast.expr | None,
            default: ast.expr | None,
            default_absent: bool,
            kind: str,
            path: str,
            line: int,
            parameter: bool = False,
            cardinality: str = "one",
        ) -> None:
            budget.charge_text(name)
            if not is_secret_field_name(name) or (
                parameter and not _sensitive_parameter(name)
            ):
                return
            default_state = _default_kind(default, absent=default_absent)
            declaration = SourceDeclaration(
                name,
                _annotation_text(annotation),
                kind,
                cardinality,
                default_state,
            )
            if cardinality == "one" and _python_type_is_safe(
                annotation,
                safe_names=safe_names,
                safe_modules=safe_modules,
                allowed_types=allowed_safe_types,
                default_kind=default_state,
            ):
                # Existing exact exceptions remain stale-failing even when the
                # independently digest-pinned owner export is sufficient.
                # This consumes only an exact path/schema/field/shape entry;
                # new files may use the pinned type without an allowlist.
                try:
                    _source_exception(
                        file_path=file_path,
                        schema=schema,
                        field_path=path,
                        node=declaration,
                        exceptions=exceptions,
                        used_exceptions=used_exceptions,
                    )
                except ScanDataError:
                    findings.append(
                        Finding(file_path, line, "SCF004_INVALID_EXCEPTION")
                    )
                return
            try:
                allowed = _source_exception(
                    file_path=file_path,
                    schema=schema,
                    field_path=path,
                    node=declaration,
                    exceptions=exceptions,
                    used_exceptions=used_exceptions,
                )
            except ScanDataError:
                findings.append(Finding(file_path, line, "SCF004_INVALID_EXCEPTION"))
                return
            if not allowed:
                findings.append(Finding(file_path, line, "SCF005_SOURCE_FIELD"))

        def scan_literal(self, value: ast.expr | None, coordinate: str | None) -> None:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return
            if coordinate is None and id(value) in self.context_literals:
                return
            if coordinate is not None:
                self.context_literals.add(id(value))
            if any(
                unicodedata.category(char) in {"Cc", "Cf"}
                and char not in {"\n", "\r", "\t"}
                for char in value.value
            ):
                raise ScanDataError("SCN011_MALFORMED_SOURCE", value.lineno)
            budget.charge_text(value.value)
            remaining = maximum_hits - len(hits)
            if remaining <= 0:
                return
            assignment = bool(coordinate and is_secret_field_name(coordinate))
            prefix = f"{coordinate}=" if assignment else ""
            literal_hits = scan_content(
                prefix + value.value,
                remaining,
                authorization_context=is_authorization_context(coordinate),
                assignment_context=True,
                budget=budget,
            )
            base = _python_source_offset(line_offsets, value)
            for hit in literal_hits:
                if hit.end <= len(prefix):
                    continue
                start = max(0, hit.start - len(prefix))
                end = max(start + 1, hit.end - len(prefix))
                hits.append(
                    ContentHit(
                        getattr(value, "lineno", 1) + hit.line - 1,
                        base + start,
                        base + end,
                        hit.code,
                    )
                )

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.classes.append(node.name)
            self.scopes.append("class")
            self.generic_visit(node)
            self.scopes.pop()
            self.classes.pop()

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            scope = (
                f"$.classes.{self.classes[-1]}.methods.{node.name}"
                if self.classes
                else f"$.functions.{node.name}"
            )
            positional = list(node.args.posonlyargs) + list(node.args.args)
            defaults: list[ast.expr | None] = [None] * (
                len(positional) - len(node.args.defaults)
            ) + list(node.args.defaults)
            pairs = [
                (argument, default, "one")
                for argument, default in zip(positional, defaults)
            ]
            pairs.extend(
                (argument, default, "one")
                for argument, default in zip(
                    node.args.kwonlyargs, node.args.kw_defaults
                )
            )
            if node.args.vararg is not None:
                pairs.append((node.args.vararg, None, "many"))
            if node.args.kwarg is not None:
                pairs.append((node.args.kwarg, None, "many"))
            self.functions.append(node.name)
            self.scopes.append("function")
            for argument, default, cardinality in pairs:
                if argument.arg in {"self", "cls"}:
                    continue
                self.inspect(
                    name=argument.arg,
                    annotation=argument.annotation,
                    default=default,
                    default_absent=default is None,
                    kind="parameter",
                    path=f"{scope}.parameters.{argument.arg}",
                    line=argument.lineno,
                    parameter=True,
                    cardinality=cardinality,
                )
                self.scan_literal(default, argument.arg)
            self.generic_visit(node)
            self.scopes.pop()
            self.functions.pop()

        visit_FunctionDef = _visit_function
        visit_AsyncFunctionDef = _visit_function

        def visit_Constant(self, node: ast.Constant) -> None:
            self.scan_literal(node, None)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            name: str | None = None
            path: str | None = None
            kind: str | None = None
            if isinstance(node.target, ast.Name):
                name = node.target.id
                if self.scopes and self.scopes[-1] == "class":
                    path = f"$.classes.{self.classes[-1]}.fields.{name}"
                    kind = "class_field"
                elif not self.scopes:
                    path = f"$.module.fields.{name}"
                    kind = "module_field"
                else:
                    path = (
                        f"$.classes.{self.classes[-1]}.methods."
                        f"{self.functions[-1]}.fields.{name}"
                        if self.classes and self.functions
                        else f"$.functions.{self.functions[-1]}.fields.{name}"
                    )
                    kind = "function_field"
            elif (
                isinstance(node.target, ast.Attribute)
                and isinstance(node.target.value, ast.Name)
                and node.target.value.id in {"self", "cls"}
            ):
                name = node.target.attr
                owner = self.classes[-1] if self.classes else "<module>"
                path = f"$.classes.{owner}.self_fields.{name}"
                kind = "self_field"
            if name is not None and path is not None and kind is not None:
                self.inspect(
                    name=name,
                    annotation=node.annotation,
                    default=node.value,
                    default_absent=node.value is None,
                    kind=kind,
                    path=path,
                    line=node.lineno,
                )
                self.scan_literal(node.value, name)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                name: str | None = None
                path: str | None = None
                kind: str | None = None
                inspect_declaration = True
                if isinstance(target, ast.Name):
                    name = target.id
                    if self.scopes and self.scopes[-1] == "class":
                        path = f"$.classes.{self.classes[-1]}.fields.{name}"
                        kind = "class_field"
                    elif not self.scopes:
                        path = f"$.module.fields.{name}"
                        kind = "module_field"
                    else:
                        path = (
                            f"$.classes.{self.classes[-1]}.methods."
                            f"{self.functions[-1]}.fields.{name}"
                            if self.classes and self.functions
                            else f"$.functions.{self.functions[-1]}.fields.{name}"
                        )
                        kind = "function_field"
                elif (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in {"self", "cls"}
                ):
                    name = target.attr
                    owner = self.classes[-1] if self.classes else "<module>"
                    path = f"$.classes.{owner}.self_fields.{name}"
                    kind = "self_field"
                elif isinstance(target, ast.Subscript):
                    key = _python_static_string(target.slice, bindings=static_strings)
                    if key is not None:
                        self.inspect_object_field(key, node.value, node.lineno)
                    elif _python_dynamic_key_is_credential_capable(
                        target.slice, static_strings
                    ):
                        raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                elif isinstance(target, ast.Attribute):
                    self.inspect_object_field(target.attr, node.value, node.lineno)
                if name is None:
                    continue
                if inspect_declaration and path is not None and kind is not None:
                    self.inspect(
                        name=name,
                        annotation=None,
                        default=node.value,
                        default_absent=False,
                        kind=kind,
                        path=path,
                        line=node.lineno,
                    )
                self.scan_literal(node.value, name)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            target = node.target
            if isinstance(target, ast.Name):
                self.inspect_object_field(target.id, node.value, node.lineno)
            elif isinstance(target, ast.Attribute):
                self.inspect_object_field(target.attr, node.value, node.lineno)
            elif isinstance(target, ast.Subscript):
                key = _python_static_string(target.slice, bindings=static_strings)
                if key is not None:
                    self.inspect_object_field(key, node.value, node.lineno)
                elif _python_dynamic_key_is_credential_capable(
                    target.slice, static_strings
                ):
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
            self.generic_visit(node)

        def visit_Dict(self, node: ast.Dict) -> None:
            for key, value in zip(node.keys, node.values):
                if key is None:
                    continue
                static_key = _python_static_string(key, bindings=static_strings)
                if static_key is not None:
                    self.inspect_object_field(
                        static_key, value, getattr(key, "lineno", node.lineno)
                    )
                elif _python_dynamic_key_is_credential_capable(key, static_strings):
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            function = _annotation_text(node.func).split(".")[-1]
            factory_name = "<anonymous>"
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                factory_name = node.args[0].value
            if function == "dict":
                for keyword in node.keywords:
                    if keyword.arg is None:
                        continue
                    self.inspect_object_field(keyword.arg, keyword.value, node.lineno)
            elif function == "setattr":
                if len(node.args) < 3:
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                attribute = _python_static_string(node.args[1], bindings=static_strings)
                if attribute is not None:
                    self.inspect_object_field(attribute, node.args[2], node.lineno)
                elif _python_dynamic_key_is_credential_capable(
                    node.args[1], static_strings
                ):
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
            elif function in {"TypedDict", "NamedTuple"}:
                if len(node.args) >= 2:
                    fields = node.args[1]
                    if isinstance(fields, ast.Dict):
                        pairs = list(zip(fields.keys, fields.values))
                    elif isinstance(fields, (ast.List, ast.Tuple)):
                        pairs = []
                        for field in fields.elts:
                            if not (
                                isinstance(field, (ast.List, ast.Tuple))
                                and len(field.elts) == 2
                            ):
                                raise ScanDataError(
                                    "SCN011_MALFORMED_SOURCE", node.lineno
                                )
                            pairs.append((field.elts[0], field.elts[1]))
                    else:
                        raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                    for key, field_annotation in pairs:
                        if not (
                            isinstance(key, ast.Constant) and isinstance(key.value, str)
                        ):
                            raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                        self.inspect(
                            name=key.value,
                            annotation=field_annotation,
                            default=None,
                            default_absent=True,
                            kind="typed_dict_field",
                            path=f"$.factories.{factory_name}.fields.{key.value}",
                            line=getattr(key, "lineno", node.lineno),
                        )
                for keyword in node.keywords:
                    if keyword.arg is None:
                        raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                    if keyword.arg in {"closed", "extra_items", "total"}:
                        continue
                    self.inspect(
                        name=keyword.arg,
                        annotation=keyword.value,
                        default=None,
                        default_absent=True,
                        kind="typed_dict_field",
                        path=f"$.factories.{factory_name}.fields.{keyword.arg}",
                        line=keyword.value.lineno,
                    )
            elif function == "namedtuple":
                if len(node.args) < 2:
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                fields_node = node.args[1]
                field_names: list[tuple[str, int]] = []
                if isinstance(fields_node, ast.Constant) and isinstance(
                    fields_node.value, str
                ):
                    field_names = [
                        (name, fields_node.lineno)
                        for name in re.split(r"[\s,]+", fields_node.value.strip())
                        if name
                    ]
                elif isinstance(fields_node, (ast.List, ast.Tuple)):
                    for field in fields_node.elts:
                        name = _python_static_string(field)
                        if name is None:
                            raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                        field_names.append(
                            (name, getattr(field, "lineno", node.lineno))
                        )
                else:
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                for name, line in field_names:
                    self.inspect(
                        name=name,
                        annotation=None,
                        default=None,
                        default_absent=True,
                        kind="namedtuple_factory_field",
                        path=f"$.factories.{factory_name}.fields.{name}",
                        line=line,
                    )
            elif function == "make_dataclass":
                if len(node.args) < 2 or not isinstance(
                    node.args[1], (ast.List, ast.Tuple)
                ):
                    raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                for field in node.args[1].elts:
                    if isinstance(field, ast.Constant) and isinstance(field.value, str):
                        self.inspect(
                            name=field.value,
                            annotation=None,
                            default=None,
                            default_absent=True,
                            kind="dataclass_factory_field",
                            path=f"$.factories.{factory_name}.fields.{field.value}",
                            line=getattr(field, "lineno", node.lineno),
                        )
                        continue
                    if not (
                        isinstance(field, (ast.List, ast.Tuple))
                        and 2 <= len(field.elts) <= 3
                    ):
                        raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                    name_node = field.elts[0]
                    if not (
                        isinstance(name_node, ast.Constant)
                        and isinstance(name_node.value, str)
                    ):
                        raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                    field_default = field.elts[2] if len(field.elts) == 3 else None
                    self.inspect(
                        name=name_node.value,
                        annotation=field.elts[1],
                        default=field_default,
                        default_absent=field_default is None,
                        kind="dataclass_factory_field",
                        path=f"$.factories.{factory_name}.fields.{name_node.value}",
                        line=getattr(name_node, "lineno", node.lineno),
                    )
            elif function == "create_model":
                for keyword in node.keywords:
                    model_fields: list[tuple[ast.expr | None, ast.expr]]
                    if keyword.arg is None:
                        if not isinstance(keyword.value, ast.Dict):
                            raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                        model_fields = list(
                            zip(keyword.value.keys, keyword.value.values)
                        )
                    else:
                        model_fields = [
                            (ast.Constant(value=keyword.arg), keyword.value)
                        ]
                    for model_name_node, field_value in model_fields:
                        if not (
                            isinstance(model_name_node, ast.Constant)
                            and isinstance(model_name_node.value, str)
                        ):
                            raise ScanDataError("SCN011_MALFORMED_SOURCE", node.lineno)
                        model_annotation: ast.expr | None = None
                        model_default: ast.expr | None = field_value
                        if (
                            isinstance(field_value, ast.Tuple)
                            and len(field_value.elts) == 2
                        ):
                            model_annotation, model_default = field_value.elts
                        self.inspect(
                            name=model_name_node.value,
                            annotation=model_annotation,
                            default=model_default,
                            default_absent=False,
                            kind="pydantic_factory_field",
                            path=(
                                f"$.factories.{factory_name}.fields."
                                f"{model_name_node.value}"
                            ),
                            line=getattr(model_name_node, "lineno", field_value.lineno),
                        )
                        self.scan_literal(model_default, model_name_node.value)
            self.generic_visit(node)

    Visitor().visit(tree)
    return StructuredScan(hits, findings)


@dataclass(frozen=True)
class JsToken:
    kind: str
    value: str
    start: int
    end: int
    line: int


def _decode_js_string(raw: str, quote: str) -> str:
    chars: list[str] = []
    index = 0
    escapes = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\x00",
    }
    while index < len(raw):
        char = raw[index]
        index += 1
        if char != "\\":
            chars.append(char)
            continue
        if index >= len(raw):
            raise ScanDataError("SCN011_MALFORMED_SOURCE")
        escaped = raw[index]
        index += 1
        if escaped in {"x", "u"}:
            width = 2 if escaped == "x" else 4
            digits = raw[index : index + width]
            if not re.fullmatch(rf"[0-9A-Fa-f]{{{width}}}", digits):
                raise ScanDataError("SCN011_MALFORMED_SOURCE")
            codepoint = int(digits, 16)
            if 0xD800 <= codepoint <= 0xDFFF:
                raise ScanDataError("SCN011_MALFORMED_SOURCE")
            chars.append(chr(codepoint))
            index += width
        elif escaped in escapes:
            chars.append(escapes[escaped])
        elif escaped in {"\\", "'", '"', "`", "/"}:
            chars.append(escaped)
        elif escaped in {"\n", "\r"}:
            if escaped == "\r" and index < len(raw) and raw[index] == "\n":
                index += 1
        else:
            raise ScanDataError("SCN011_MALFORMED_SOURCE")
    value = "".join(chars)
    if any(
        unicodedata.category(char) in {"Cc", "Cf"} and char not in {"\n", "\r", "\t"}
        for char in value
    ):
        raise ScanDataError("SCN011_MALFORMED_SOURCE")
    return value


def _tokenize_typescript(
    text: str, budget: WorkBudget
) -> tuple[list[JsToken], dict[int, int]]:
    tokens: list[JsToken] = []
    index = 0
    line = 1
    budget.charge_parser_operations(len(text))
    while index < len(text):
        char = text[index]
        if char.isspace():
            line += char == "\n"
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ScanDataError("SCN011_MALFORMED_SOURCE", line)
            line += text.count("\n", index, end + 2)
            index = end + 2
            continue
        start = index
        token_line = line
        if char in {'"', "'", "`"}:
            quote = char
            index += 1
            escaped = False
            while index < len(text):
                current = text[index]
                if not escaped and current == quote:
                    break
                if not escaped and current == "\\":
                    escaped = True
                else:
                    escaped = False
                line += current == "\n"
                index += 1
            if index >= len(text):
                raise ScanDataError("SCN011_MALFORMED_SOURCE", token_line)
            raw = text[start + 1 : index]
            index += 1
            value = _decode_js_string(raw, quote)
            dynamic_template = quote == "`" and bool(
                re.search(r"(?<!\\)(?:\\\\)*\$\{", raw)
            )
            tokens.append(
                JsToken(
                    "template" if dynamic_template else "string",
                    value,
                    start,
                    index,
                    token_line,
                )
            )
        elif char.isalpha() or char in "_$":
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "_$-"):
                index += 1
            tokens.append(
                JsToken("identifier", text[start:index], start, index, token_line)
            )
        elif char.isdigit():
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "._"):
                index += 1
            tokens.append(
                JsToken("number", text[start:index], start, index, token_line)
            )
        else:
            operator = text[index : index + 3]
            matched = next(
                (
                    value
                    for value in (
                        "??=",
                        "||=",
                        "&&=",
                        "=>",
                        "?.",
                        "...",
                        "??",
                        "||",
                        "&&",
                    )
                    if operator.startswith(value)
                ),
                char,
            )
            index += len(matched)
            tokens.append(JsToken("punct", matched, start, index, token_line))
        budget.charge_structure()
    stack: list[tuple[str, int]] = []
    matching: dict[int, int] = {}
    pairs = {")": "(", "]": "[", "}": "{"}
    for token_index, token in enumerate(tokens):
        if token.value in {"(", "[", "{"}:
            stack.append((token.value, token_index))
            if len(stack) > budget.limits["max_structure_depth"]:
                raise ScanDataError("SCN011_MALFORMED_SOURCE", token.line)
        elif token.value in pairs:
            if not stack or stack[-1][0] != pairs[token.value]:
                raise ScanDataError("SCN011_MALFORMED_SOURCE", token.line)
            _opening, opening_index = stack.pop()
            matching[opening_index] = token_index
    if stack:
        raise ScanDataError("SCN011_MALFORMED_SOURCE")
    return tokens, matching


def _matching_token(
    tokens: list[JsToken],
    matching: dict[int, int],
    start: int,
    opening: str,
    closing: str,
) -> int:
    end = matching.get(start)
    if end is None or tokens[start].value != opening or tokens[end].value != closing:
        raise ScanDataError("SCN011_MALFORMED_SOURCE", tokens[start].line)
    return end


def _typescript_import_provenance(
    tokens: list[JsToken],
    matching: dict[int, int],
    file_path: str,
    parameter_ranges: list[tuple[int, int]],
    allowed_types: set[str],
    budget: WorkBudget,
) -> set[str]:
    del file_path
    safe: set[str] = set()
    index = 0
    while index < len(tokens):
        budget.charge_parser_operations()
        if tokens[index].value != "import":
            index += 1
            continue
        source_index: int | None = None
        depth = 0
        for position in range(index + 1, len(tokens)):
            budget.charge_parser_operations()
            value = tokens[position].value
            if value in {"{", "["}:
                depth += 1
            elif value in {"}", "]"} and depth:
                depth -= 1
            if depth == 0 and value == ";":
                break
            if (
                depth == 0
                and position > index + 1
                and value
                in {
                    "class",
                    "const",
                    "enum",
                    "export",
                    "function",
                    "import",
                    "interface",
                    "let",
                    "namespace",
                    "var",
                }
            ):
                break
            if (
                tokens[position].kind == "string"
                and tokens[position - 1].value == "from"
            ):
                source_index = position
                break
        if (
            source_index is not None
            and tokens[source_index].value == _TYPESCRIPT_SAFE_MODULE
        ):
            opening = next(
                (
                    position
                    for position in range(index + 1, source_index)
                    if tokens[position].value == "{"
                ),
                None,
            )
            if opening is not None:
                closing = _matching_token(tokens, matching, opening, "{", "}")
                if closing < source_index:
                    specifier: list[JsToken] = []

                    def record_specifier(parts: list[JsToken]) -> None:
                        values = list(parts)
                        if values and values[0].value == "type":
                            values = values[1:]
                        if (
                            len(values) == 1
                            and values[0].kind == "identifier"
                            and values[0].value in allowed_types
                        ):
                            safe.add(values[0].value)
                        elif (
                            len(values) == 3
                            and values[0].kind == "identifier"
                            and values[0].value in allowed_types
                            and values[1].value == "as"
                            and values[2].kind == "identifier"
                        ):
                            safe.add(values[2].value)

                    for position in range(opening + 1, closing):
                        budget.charge_parser_operations()
                        if tokens[position].value == ",":
                            record_specifier(specifier)
                            specifier = []
                        else:
                            specifier.append(tokens[position])
                    record_specifier(specifier)
        index = source_index + 1 if source_index is not None else index + 1
    for index, token in enumerate(tokens[:-1]):
        budget.charge_parser_operations()
        if token.value in {
            "interface",
            "type",
            "class",
            "const",
            "enum",
            "let",
            "namespace",
            "var",
            "function",
        }:
            if (
                token.value == "type"
                and index > 0
                and tokens[index - 1].value == "import"
            ):
                continue
            local = tokens[index + 1].value
            if local in safe:
                safe.discard(local)
            if token.value in {"const", "let", "var"} and local in {"{", "["}:
                closing = _matching_token(
                    tokens,
                    matching,
                    index + 1,
                    local,
                    "}" if local == "{" else "]",
                )
                if any(
                    candidate.value in safe for candidate in tokens[index + 2 : closing]
                ):
                    safe.difference_update(
                        candidate.value
                        for candidate in tokens[index + 2 : closing]
                        if candidate.value in safe
                    )
    for index, token in enumerate(tokens):
        budget.charge_parser_operations()
        if token.value not in safe:
            continue
        matching_range = next(
            ((start, end) for start, end in parameter_ranges if start < index < end),
            None,
        )
        if matching_range is None:
            continue
        previous = tokens[index - 1].value if index else ""
        nested_destructure = any(
            token.value in {"{", "["} for token in tokens[matching_range[0] + 1 : index]
        )
        if nested_destructure or previous not in {":", "|", "&", "<"}:
            safe.discard(token.value)
    return safe


def _typescript_type_is_safe(
    tokens: list[JsToken], safe_names: set[str], default_kind: str
) -> bool:
    if default_kind not in {"absent", "none"}:
        return False
    values = [
        token.value for token in tokens if token.value not in {"?", " ", "readonly"}
    ]
    if not values:
        return False
    members: list[list[str]] = [[]]
    for value in values:
        if value == "|":
            members.append([])
        else:
            members[-1].append(value)
    safe_count = 0
    for member in members:
        if member in (["null"], ["undefined"]):
            continue
        if len(member) == 1 and member[0] in safe_names:
            safe_count += 1
            continue
        return False
    return safe_count == 1


def scan_typescript_source(
    text: str,
    *,
    file_path: str,
    exceptions: dict[tuple[str, str, str], dict[str, Any]],
    used_exceptions: dict[tuple[str, str, str], int],
    budget: WorkBudget,
    maximum_hits: int,
    safe_type_names: set[str] | None = None,
) -> StructuredScan:
    findings: list[Finding] = []
    hits: list[ContentHit] = []
    schema = "typescript:source.v1"
    tokens, matching = _tokenize_typescript(text, budget)
    blocks: list[tuple[int, int, str, str]] = []
    for index, token in enumerate(tokens[:-1]):
        budget.charge_parser_operations()
        if token.value not in {"interface", "class", "type"}:
            continue
        name = tokens[index + 1].value
        opening = None
        for position in range(index + 2, len(tokens)):
            budget.charge_parser_operations()
            if tokens[position].value in {"{", ";"}:
                opening = position
                break
        if opening is None or tokens[opening].value != "{":
            continue
        blocks.append(
            (
                opening,
                _matching_token(tokens, matching, opening, "{", "}"),
                token.value,
                name,
            )
        )

    def enclosing(index: int) -> tuple[str, str] | None:
        budget.charge_parser_operations(len(blocks))
        candidates = [
            (end - start, kind, name)
            for start, end, kind, name in blocks
            if start < index < end
        ]
        if not candidates:
            return None
        _width, kind, name = min(candidates)
        return kind, name

    method_blocks: list[tuple[int, int, str, str]] = []
    method_parameter_ranges: list[tuple[int, int, str, str]] = []

    def enclosing_method(index: int) -> tuple[str, str] | None:
        budget.charge_parser_operations(len(method_blocks))
        candidates = [
            (end - start, class_name, method_name)
            for start, end, class_name, method_name in [
                *method_blocks,
                *method_parameter_ranges,
            ]
            if start < index < end
        ]
        if not candidates:
            return None
        _width, class_name, method_name = min(candidates)
        return class_name, method_name

    def inspect_field(
        name: str,
        declared_tokens: list[JsToken],
        default_kind: str,
        number: int,
        index: int,
        declaration_kind: str,
        *,
        force: bool = False,
        cardinality: str = "one",
    ) -> None:
        budget.charge_text(name)
        block = enclosing(index)
        method = enclosing_method(index)
        collection = {
            "interface": "interfaces",
            "class": "classes",
            "type": "types",
        }[(block or ("type", "<module>"))[0]]
        block_name = (block or ("type", "<module>"))[1]
        if declaration_kind == "source_field" and method is not None:
            declaration_kind = "object_field"
            field_path = (
                f"$.classes.{method[0]}.methods.{method[1]}.object_fields.{name}"
            )
        elif declaration_kind == "record_key" and method is not None:
            field_path = f"$.classes.{method[0]}.methods.{method[1]}.record_keys.{name}"
        else:
            field_path = f"$.{collection}.{block_name}.fields.{name}"
        if declaration_kind == "source_field" and block is not None and method is None:
            declaration_kind = f"{block[0]}_field"
        declared_type = "".join(token.value for token in declared_tokens)
        if not force and not is_secret_field_name(name):
            return
        declaration = SourceDeclaration(
            name, declared_type, declaration_kind, cardinality, default_kind
        )
        if not force and _typescript_type_is_safe(
            declared_tokens, safe_names, default_kind
        ):
            try:
                _source_exception(
                    file_path=file_path,
                    schema=schema,
                    field_path=field_path,
                    node=declaration,
                    exceptions=exceptions,
                    used_exceptions=used_exceptions,
                )
            except ScanDataError:
                findings.append(Finding(file_path, number, "SCF004_INVALID_EXCEPTION"))
            return
        try:
            allowed = _source_exception(
                file_path=file_path,
                schema=schema,
                field_path=field_path,
                node=declaration,
                exceptions=exceptions,
                used_exceptions=used_exceptions,
            )
        except ScanDataError:
            findings.append(Finding(file_path, number, "SCF004_INVALID_EXCEPTION"))
            return
        if not allowed:
            findings.append(Finding(file_path, number, "SCF005_SOURCE_FIELD"))

    def type_and_default(index: int) -> tuple[list[JsToken], str]:
        cursor = index + 1
        while cursor < len(tokens) and tokens[cursor].value in {"?", "!"}:
            cursor += 1
        declared: list[JsToken] = []
        default = "absent"
        if cursor < len(tokens) and tokens[cursor].value == ":":
            cursor += 1
            depth = 0
            while cursor < len(tokens):
                value = tokens[cursor].value
                if depth == 0 and value in {"=", ";", ",", ")", "}"}:
                    break
                if value in {"<", "(", "[", "{"}:
                    depth += 1
                elif value in {">", ")", "]", "}"} and depth:
                    depth -= 1
                declared.append(tokens[cursor])
                cursor += 1
        if cursor < len(tokens) and tokens[cursor].value == "=":
            next_value = tokens[cursor + 1].value if cursor + 1 < len(tokens) else ""
            default = (
                "none"
                if next_value in {"null", "undefined"}
                else "literal"
                if cursor + 1 < len(tokens)
                and tokens[cursor + 1].kind in {"string", "number"}
                else "expression"
            )
        return declared, default

    declaration_keywords = {"const", "let", "var"}
    modifiers = {
        "abstract",
        "declare",
        "private",
        "protected",
        "public",
        "readonly",
        "static",
    }
    brace_depths: list[int] = []
    brace_depth = 0
    for candidate in tokens:
        budget.charge_parser_operations()
        brace_depths.append(brace_depth)
        if candidate.value == "{":
            brace_depth += 1
        elif candidate.value == "}":
            brace_depth -= 1

    parameter_ranges: list[tuple[int, int]] = []

    def callable_name(opening: int) -> str:
        cursor = opening - 1
        if cursor >= 0 and tokens[cursor].value == ">":
            depth = 1
            cursor -= 1
            while cursor >= 0 and depth:
                if tokens[cursor].value == ">":
                    depth += 1
                elif tokens[cursor].value == "<":
                    depth -= 1
                cursor -= 1
        return tokens[cursor].value if cursor >= 0 else "<anonymous>"

    for opening, candidate in enumerate(tokens):
        budget.charge_parser_operations()
        if candidate.value != "(":
            continue
        closing = _matching_token(tokens, matching, opening, "(", ")")
        previous = tokens[opening - 1].value if opening else ""
        before_previous = tokens[opening - 2].value if opening >= 2 else ""
        block = enclosing(opening)
        class_method = bool(
            block
            and block[0] == "class"
            and brace_depths[opening]
            == brace_depths[
                next(
                    start
                    for start, _end, kind, name in blocks
                    if kind == block[0] and name == block[1]
                )
            ]
            + 1
            and previous not in {"if", "for", "while", "switch", "catch"}
        )
        function_declaration = (
            before_previous in {"function", "constructor"} or previous == "constructor"
        )
        arrow = closing + 1 < len(tokens) and tokens[closing + 1].value == "=>"
        if class_method or function_declaration or arrow:
            parameter_ranges.append((opening, closing))
        if class_method and block is not None:
            method_name = callable_name(opening)
            method_parameter_ranges.append((opening, closing, block[1], method_name))
            body_opening = None
            for position in range(closing + 1, len(tokens)):
                budget.charge_parser_operations()
                if tokens[position].value in {"{", ";"}:
                    body_opening = position
                    break
            if body_opening is not None and tokens[body_opening].value == "{":
                method_blocks.append(
                    (
                        body_opening,
                        _matching_token(tokens, matching, body_opening, "{", "}"),
                        block[1],
                        method_name,
                    )
                )

    def in_parameter_list(index: int) -> bool:
        budget.charge_parser_operations(len(parameter_ranges))
        return any(start < index < end for start, end in parameter_ranges)

    shadow_ranges = list(parameter_ranges)
    for opening, candidate in enumerate(tokens):
        if (
            candidate.value == "("
            and opening > 0
            and tokens[opening - 1].value == "catch"
        ):
            shadow_ranges.append(
                (opening, _matching_token(tokens, matching, opening, "(", ")"))
            )

    safe_names = _typescript_import_provenance(
        tokens,
        matching,
        file_path,
        shadow_ranges,
        safe_type_names or set(),
        budget,
    )
    assignment_values = {"=", "??=", "||=", "&&="}
    for index, token in enumerate(tokens[:-1]):
        if token.value in safe_names and tokens[index + 1].value in assignment_values:
            safe_names.discard(token.value)

    static_string_bindings: dict[str, set[str]] = {}
    type_string_aliases: dict[str, set[str]] = {}
    type_alias_tokens: dict[str, list[JsToken]] = {}
    for index, token in enumerate(tokens[:-3]):
        budget.charge_parser_operations()
        if (
            token.value == "const"
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == "="
            and tokens[index + 3].kind == "string"
        ):
            static_string_bindings.setdefault(tokens[index + 1].value, set()).add(
                tokens[index + 3].value
            )
        if (
            token.value != "type"
            or tokens[index + 1].kind != "identifier"
            or tokens[index + 2].value != "="
        ):
            continue
        values: set[str] = set()
        alias_tokens: list[JsToken] = []
        expect_string = True
        literal_alias = True
        closed = False
        for candidate in tokens[index + 3 :]:
            budget.charge_parser_operations()
            if candidate.value == ";":
                type_alias_tokens[tokens[index + 1].value] = alias_tokens
                closed = literal_alias and bool(values) and not expect_string
                break
            alias_tokens.append(candidate)
            if expect_string and candidate.kind == "string":
                values.add(candidate.value)
                expect_string = False
                continue
            if not expect_string and candidate.value == "|":
                expect_string = True
                continue
            literal_alias = False
        if closed:
            type_string_aliases[tokens[index + 1].value] = values

    def closed_key_values(
        key_tokens: list[JsToken], visiting: frozenset[str] = frozenset()
    ) -> set[str] | None:
        while key_tokens and key_tokens[0].value == "|":
            key_tokens = key_tokens[1:]
        if len(key_tokens) == 1:
            key = key_tokens[0]
            if key.kind == "string":
                return {key.value}
            if key.kind == "identifier":
                direct = static_string_bindings.get(
                    key.value, type_string_aliases.get(key.value)
                )
                if direct is not None:
                    return direct
                if key.value in visiting:
                    return None
                alias = type_alias_tokens.get(key.value)
                if alias is not None:
                    return closed_key_values(alias, visiting | {key.value})
        if not any(key.value == "|" for key in key_tokens):
            return None
        values: set[str] = set()
        member: list[JsToken] = []
        for key in [*key_tokens, JsToken("punct", "|", 0, 0, 0)]:
            budget.charge_parser_operations()
            if key.value != "|":
                member.append(key)
                continue
            if not member:
                return None
            resolved_member = closed_key_values(member, visiting)
            if resolved_member is None:
                return None
            values.update(resolved_member)
            member = []
        return values or None

    def alias_has_dynamic_template(
        name: str, visiting: frozenset[str] = frozenset()
    ) -> bool:
        if name in visiting:
            return False
        alias = type_alias_tokens.get(name, [])
        if any(token.kind == "template" for token in alias):
            return True
        return any(
            token.kind == "identifier"
            and token.value in type_alias_tokens
            and alias_has_dynamic_template(token.value, visiting | {name})
            for token in alias
        )

    # Closed handling for generic Record keys. Concrete credential-capable keys
    # are declarations even though they occur in a type-argument position.
    for index, token in enumerate(tokens[:-1]):
        if token.value != "Record" or tokens[index + 1].value != "<":
            continue
        depth = 0
        first_argument: list[tuple[int, JsToken]] = []
        closed = False
        first_complete = False
        for position in range(index + 1, len(tokens)):
            budget.charge_parser_operations()
            value = tokens[position].value
            if value == "<":
                depth += 1
                continue
            if value == ">":
                depth -= 1
                if depth == 0:
                    closed = True
                    break
            if depth == 1 and value == ",":
                first_complete = True
                continue
            if depth >= 1 and not first_complete:
                first_argument.append((position, tokens[position]))
        if not closed or not first_complete:
            raise ScanDataError("SCN011_MALFORMED_SOURCE", token.line)
        resolved_keys = closed_key_values(
            [key_token for _position, key_token in first_argument]
        )
        for key_value in sorted(resolved_keys or set()):
            if is_secret_field_name(key_value):
                position = first_argument[0][0]
                key_token = first_argument[0][1]
                inspect_field(
                    key_value,
                    [],
                    "absent",
                    key_token.line,
                    position,
                    "record_key",
                )
        dynamic_template_alias = bool(
            len(first_argument) == 1
            and first_argument[0][1].kind == "identifier"
            and alias_has_dynamic_template(first_argument[0][1].value)
        )
        if (
            resolved_keys is None
            or dynamic_template_alias
            or any(
                key_token.kind == "template" for _position, key_token in first_argument
            )
        ):
            position, key_token = first_argument[0]
            inspect_field(
                key_token.value,
                [candidate for _position, candidate in first_argument],
                "absent",
                key_token.line,
                position,
                "record_key",
                force=True,
                cardinality="many",
            )

    # Mapped/index signatures and dynamic computed properties are rejected when
    # their key set cannot be statically closed. Static computed names are
    # inspected through the same field grammar.
    for opening, closing in sorted(matching.items()):
        budget.charge_parser_operations()
        if tokens[opening].value != "[":
            continue
        cursor = closing + 1
        if cursor < len(tokens) and tokens[cursor].value == "?":
            cursor += 1
        if cursor >= len(tokens) or tokens[cursor].value != ":":
            continue
        key_tokens = tokens[opening + 1 : closing]
        mapped = any(key_token.value == "in" for key_token in key_tokens)
        resolved_tokens = key_tokens
        if mapped:
            in_index = next(
                index
                for index, key_token in enumerate(key_tokens)
                if key_token.value == "in"
            )
            resolved_tokens = key_tokens[in_index + 1 :]
        resolved_values = closed_key_values(resolved_tokens)
        sensitive_values = sorted(
            value for value in resolved_values or set() if is_secret_field_name(value)
        )
        sensitive = [
            (opening + 1 + offset, key_token)
            for offset, key_token in enumerate(key_tokens)
            if key_token.kind in {"identifier", "string"}
            and is_secret_field_name(key_token.value)
        ]
        direct_sensitive_values = {
            key_token.value for _position, key_token in sensitive
        }
        for position, key_token in sensitive:
            inspect_field(
                key_token.value,
                [],
                "absent",
                key_token.line,
                position,
                "computed_field",
            )
        for key_value in sensitive_values:
            if key_value in direct_sensitive_values:
                continue
            inspect_field(
                key_value,
                [],
                "absent",
                tokens[opening].line,
                opening,
                "computed_field",
            )
        static_computed = resolved_values is not None
        if not sensitive and not sensitive_values and (mapped or not static_computed):
            key_token = next(
                (
                    candidate
                    for candidate in key_tokens
                    if candidate.kind in {"identifier", "string"}
                ),
                tokens[opening],
            )
            inspect_field(
                key_token.value,
                key_tokens,
                "absent",
                key_token.line,
                opening + 1,
                "index_signature" if not mapped else "mapped_field",
                force=True,
                cardinality="many",
            )

    # A client package cannot create an unpinned credential contract by
    # re-exporting an owner symbol under a new surface.
    for index, token in enumerate(tokens):
        budget.charge_parser_operations()
        if token.value != "export":
            continue
        opening = index + 1
        if opening < len(tokens) and tokens[opening].value == "type":
            opening += 1
        if opening >= len(tokens) or tokens[opening].value != "{":
            continue
        closing = _matching_token(tokens, matching, opening, "{", "}")
        if closing + 2 >= len(tokens) or tokens[closing + 1].value != "from":
            continue
        for exported in tokens[opening + 1 : closing]:
            budget.charge_parser_operations()
            if exported.kind == "identifier" and is_secret_field_name(exported.value):
                inspect_field(
                    exported.value,
                    [],
                    "absent",
                    exported.line,
                    index,
                    "reexport_field",
                )

    destructuring_ranges: list[tuple[int, int]] = []
    for index, token in enumerate(tokens[:-1]):
        budget.charge_parser_operations()
        if token.value not in declaration_keywords or tokens[index + 1].value not in {
            "{",
            "[",
        }:
            continue
        destructuring_opening = tokens[index + 1].value
        destructuring_ranges.append(
            (
                index + 1,
                _matching_token(
                    tokens,
                    matching,
                    index + 1,
                    destructuring_opening,
                    "}" if destructuring_opening == "{" else "]",
                ),
            )
        )
    for start, end in parameter_ranges:
        for position in range(start + 1, end):
            budget.charge_parser_operations()
            if tokens[position].value not in {"{", "["}:
                continue
            previous = tokens[position - 1].value
            if previous not in {"(", ",", "..."}:
                continue
            destructuring_opening = tokens[position].value
            closing = _matching_token(
                tokens,
                matching,
                position,
                destructuring_opening,
                "}" if destructuring_opening == "{" else "]",
            )
            if closing < end:
                destructuring_ranges.append((position, closing))

    def in_destructuring_binding(index: int) -> bool:
        budget.charge_parser_operations(len(destructuring_ranges))
        return any(start < index < end for start, end in destructuring_ranges)

    class_fields: set[tuple[str, str]] = set()
    for index, token in enumerate(tokens):
        budget.charge_parser_operations()
        block = enclosing(index)
        if block is None or block[0] != "class":
            continue
        budget.charge_parser_operations(len(blocks))
        class_opening = next(
            start
            for start, _end, kind, name in blocks
            if kind == "class" and name == block[1]
        )
        if (
            brace_depths[index] == brace_depths[class_opening] + 1
            and not in_parameter_list(index)
            and index + 1 < len(tokens)
            and (
                tokens[index + 1].value in {"?", "!", ":", "=", ";"}
                or (
                    tokens[index + 1].value == "("
                    and index > 0
                    and tokens[index - 1].value in {"get", "set"}
                )
            )
        ):
            class_fields.add((block[1], token.value.removeprefix("#")))

    for index, token in enumerate(tokens):
        budget.charge_parser_operations()
        if token.kind not in {"identifier", "string"}:
            continue
        name = token.value.removeprefix("#")
        if not is_secret_field_name(name):
            continue
        previous = tokens[index - 1].value if index else ""
        next_value = tokens[index + 1].value if index + 1 < len(tokens) else ""
        # A sensitive-looking imported type name in ``field: SecretRefV2`` is
        # a type use, not another field declaration.
        if previous in {":", "|", "&", "<"} and not in_destructuring_binding(index):
            continue
        block = enclosing(index)
        is_alias_name = previous in {"type", "interface", "class"}
        is_module_variable = brace_depths[index] == 0 and (
            previous in declaration_keywords
            or (
                index >= 2
                and tokens[index - 2].value in declaration_keywords
                and previous in modifiers
            )
        )
        direct_class_member = bool(
            block
            and block[0] == "class"
            and (block[1], name) in class_fields
            and brace_depths[index]
            == brace_depths[
                next(
                    start
                    for start, _end, kind, class_name in blocks
                    if kind == "class" and class_name == block[1]
                )
            ]
            + 1
        )
        is_accessor = previous in {"get", "set"} and direct_class_member
        is_object_property = (
            next_value == ":"
            and brace_depths[index] > 0
            and previous not in {"?", "case", "."}
        )
        runtime_object_property = bool(
            is_object_property
            and not (
                block and (block[0] in {"interface", "type"} or direct_class_member)
            )
        )
        is_property = bool(
            is_object_property
            or (
                block
                and next_value in {"?", "!", ":", "=", ";", "("}
                and not in_parameter_list(index)
                and (block[0] in {"interface", "type"} or direct_class_member)
            )
        )
        is_parameter = next_value in {"?", ":", "="} and in_parameter_list(index)
        is_destructured_alias = in_destructuring_binding(index)
        assignment_operators = {"=", "??=", "||=", "&&="}
        is_member_assignment = bool(
            previous == "." and index >= 2 and next_value in assignment_operators
        )
        is_plain_assignment = previous != "." and next_value in assignment_operators
        is_self_assignment = bool(
            is_member_assignment
            and tokens[index - 2].value == "this"
            and block is not None
            and (block[1], name) not in class_fields
        )
        value_literal = (
            (
                is_module_variable
                or is_property
                or is_member_assignment
                or is_plain_assignment
            )
            and next_value in {":", *assignment_operators}
            and index + 2 < len(tokens)
            and tokens[index + 2].kind in {"string", "number"}
        )
        if not (
            is_alias_name
            or is_module_variable
            or is_accessor
            or is_property
            or is_parameter
            or is_destructured_alias
            or is_member_assignment
            or is_self_assignment
            or value_literal
        ):
            continue
        declared, default = type_and_default(index)
        if runtime_object_property:
            declared = []
            value_token = tokens[index + 2] if index + 2 < len(tokens) else None
            default = (
                "none"
                if value_token is not None
                and value_token.value in {"null", "undefined"}
                else "literal"
                if value_token is not None and value_token.kind in {"string", "number"}
                else "expression"
            )
        existing_class_assignment = bool(
            is_member_assignment
            and block is not None
            and (block[1], name) in class_fields
        )
        if not existing_class_assignment:
            inspect_field(
                name,
                declared,
                default,
                token.line,
                index,
                "parameter"
                if is_parameter and not is_property
                else "self_field"
                if is_self_assignment
                else "source_field",
            )
        if (
            index + 2 < len(tokens)
            and tokens[index + 1].value in {":", *assignment_operators}
            and tokens[index + 2].kind == "string"
        ):
            value_token = tokens[index + 2]
            remaining = maximum_hits - len(hits)
            for hit in scan_content(
                name + "=" + value_token.value,
                remaining,
                authorization_context=is_authorization_context(name),
                assignment_context=True,
                budget=budget,
            ):
                hits.append(
                    ContentHit(
                        value_token.line + hit.line - 1,
                        value_token.start + hit.start,
                        value_token.start + max(hit.start + 1, hit.end),
                        hit.code,
                    )
                )

    for token in tokens:
        if token.kind not in {"string", "template"}:
            continue
        budget.charge_text(token.value)
        remaining = maximum_hits - len(hits)
        if remaining <= 0:
            break
        for hit in scan_content(
            token.value, remaining, assignment_context=True, budget=budget
        ):
            hits.append(
                ContentHit(
                    token.line + hit.line - 1,
                    token.start + hit.start,
                    token.start + max(hit.start + 1, hit.end),
                    hit.code,
                )
            )
    return StructuredScan(sorted(set(hits)), findings)


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
