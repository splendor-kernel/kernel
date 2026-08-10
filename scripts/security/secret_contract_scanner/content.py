"""Credential-coordinate classification and bounded content signatures."""

from __future__ import annotations

import base64
import math
import re
import unicodedata
import urllib.parse
from array import array
from collections import Counter
from collections.abc import Sequence

from .model import ContentHit, ScanDataError, WorkBudget, utf8_size


def normalize_field_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return re.sub(r"_+", "_", value)


_BENIGN_EXACT_FIELDS = {
    "allowed_credential_bindings",
    "auth_method",
    "auth_mode",
    "auth_policy",
    "auth_scheme",
    "auth_state",
    "authorization_endpoint",
    "authorization_url",
    "authentication_method",
    "authentication_mode",
    "authentication_policy",
    "authentication_state",
    "authorization_policy",
    "authorization_state",
    "credential_backend",
    "credential_binding",
    "credential_bearing_send_sequence",
    "credential_count",
    "credential_format",
    "credential_id",
    "credential_ids",
    "credential_kind",
    "credential_ref",
    "credential_refs",
    "credential_scope",
    "credential_sink",
    "credential_sinks",
    "credential_slot",
    "credential_slots",
    "credential_algorithm",
    "jwks_uri",
    "max_tokens",
    "oauth_authorization_endpoint",
    "oauth_token_endpoint",
    "public_metadata",
    "public_key",
    "public_keys",
    "password_policy",
    "secret_backend",
    "secret_count",
    "secret_format",
    "secret_policy",
    "secret_ref",
    "secret_ref_id",
    "secret_ref_ids",
    "secret_state",
    "signature_algorithm",
    "token_algorithm",
    "token_count",
    "token_counts",
    "token_index",
    "token_length",
    "token_type",
    "token_types",
    "token_usage",
    "token_endpoint",
    "token_endpoint_auth_method",
    "token_policy",
    "token_url",
    "tokenizer",
    "tokenizers",
    "tokens_used",
}
_BENIGN_SUFFIXES = (
    "_algorithm",
    "_count",
    "_digest",
    "_dir",
    "_directory",
    "_endpoint",
    "_file",
    "_filename",
    "_hash",
    "_id",
    "_ids",
    "_identities",
    "_identity",
    "_index",
    "_kind",
    "_length",
    "_non_disclosure",
    "_path",
    "_provider",
    "_ref",
    "_refs",
    "_revision",
    "_secret_broker",
    "_status",
    "_type",
    "_version",
    "_url",
)
_SECRET_EXACT_FIELDS = {
    "access_key",
    "access_key_id",
    "access_key_ids",
    "access_keys",
    "api_key",
    "api_keys",
    "auth",
    "authentication",
    "authentications",
    "authorization",
    "authorizations",
    "client_secret",
    "client_secrets",
    "connection_string",
    "connection_strings",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "dsn",
    "dsns",
    "password",
    "passwords",
    "passphrase",
    "passphrases",
    "passwd",
    "passwds",
    "private_key",
    "private_keys",
    "proxy_authorization",
    "pwd",
    "pwds",
    "secret",
    "secret_access_key",
    "secret_access_keys",
    "secret_key",
    "secret_keys",
    "secrets",
    "set_cookie",
    "token",
    "tokens",
    "aws_access_key_id",
    "aws_secret_access_key",
}
_KEY_QUALIFIERS = {
    "access",
    "api",
    "client",
    "credential",
    "decryption",
    "encryption",
    "hmac",
    "master",
    "private",
    "secret",
    "session",
    "signing",
    "ssh",
    "symmetric",
    "tls",
}
_PAYLOAD_TERMS = {"bytes", "data", "material", "payload", "raw", "value"}
_MEASUREMENT_TERMS = {
    "attempt",
    "attempts",
    "budget",
    "capacity",
    "ceiling",
    "count",
    "counts",
    "length",
    "limit",
    "limits",
    "max",
    "maximum",
    "metric",
    "min",
    "minimum",
    "quota",
    "sequence",
    "sequences",
    "send",
    "sends",
    "usage",
    "used",
}
_CONTEXT_METADATA_FIELDS = {
    "algorithm",
    "backend",
    "format",
    "id",
    "kind",
    "policy",
    "provider",
    "ref",
    "state",
    "type",
}


def is_credential_metadata_field(key: str) -> bool:
    """Recognize only exact non-material coordinates in credential contexts."""

    normalized = normalize_field_name(key)
    return normalized in _BENIGN_EXACT_FIELDS or normalized in _CONTEXT_METADATA_FIELDS


def is_secret_field_name(key: str) -> bool:
    """Classify credential payload coordinates without flagging metrics/refs."""

    normalized = normalize_field_name(key)
    if not normalized or normalized in _BENIGN_EXACT_FIELDS:
        return False
    if normalized in _SECRET_EXACT_FIELDS:
        return True
    if normalized.endswith(_BENIGN_SUFFIXES):
        return False
    tokens = {token for token in normalized.split("_") if token}
    if not tokens:
        return False
    # Counts, limits, and sequence coordinates describe enforcement metadata,
    # not material. Keep this structural and token-exact so ``password=123``
    # remains a credential assignment while names such as
    # ``max_credential_sends_per_attempt`` remain ordinary policy metadata.
    if (
        normalized.split("_", 1)[0] in {"max", "maximum", "min", "minimum"}
        and tokens & _MEASUREMENT_TERMS
    ):
        return False
    if "oauth" in tokens and tokens & {"endpoint", "url", "uri"}:
        return False
    if "key" in tokens and tokens & _KEY_QUALIFIERS:
        return "public" not in tokens
    if tokens & {
        "password",
        "passwords",
        "passphrase",
        "passphrases",
        "passwd",
        "passwds",
        "pwd",
        "pwds",
    }:
        return True
    if tokens & {"credential", "credentials", "secret", "secrets"}:
        return True
    if tokens & {"authorization", "authorizations"}:
        return True
    if tokens & {"auth", "authentication"} and not tokens & {
        "method",
        "mode",
        "scheme",
        "type",
    }:
        return True
    if tokens & {"token", "tokens"} and not tokens & {
        "budget",
        "count",
        "index",
        "length",
        "limit",
        "max",
        "metric",
        "minimum",
        "type",
        "usage",
        "used",
    }:
        return True
    if "material" in tokens and not tokens & {"public", "description", "kind"}:
        return True
    return bool(tokens & _PAYLOAD_TERMS and tokens & _KEY_QUALIFIERS)


def is_authorization_context(key: str | None) -> bool:
    if key is None:
        return False
    normalized = normalize_field_name(key)
    return is_secret_field_name(key) or normalized in {
        "header",
        "headers",
        "http_header",
        "proxy_header",
        "www_authenticate",
    }


def schema_marker_is_secret(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = normalize_field_name(value)
    tokens = set(normalized.split("_"))
    return bool(
        tokens
        & {
            "auth",
            "authorization",
            "credential",
            "credentials",
            "password",
            "secret",
            "secrets",
            "token",
            "tokens",
        }
    )


def object_is_fake_wrapper(value: dict[str, object]) -> bool:
    return any(
        normalize_field_name(marker) in {"schema", "schema_version", "type", "kind"}
        and schema_marker_is_secret(marker_value)
        for marker, marker_value in value.items()
    )


PEM_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,16384}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
PROVIDER_PATTERNS = [
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,255}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{16,255}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{16,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])sk_live_[A-Za-z0-9]{16,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])rk_live_[A-Za-z0-9]{16,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"),
    re.compile(
        r"(?<![A-Za-z0-9_-])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,255}(?![A-Za-z0-9_-])"
    ),
    re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
    ),
]
AUTH_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])(?P<scheme>bearer|basic)[ \t]+(?P<value>[A-Za-z0-9._~+/=-]{1,512})"
)
AUTH_COORDINATE_PREFIX = re.compile(
    r"(?i)(?:authorization|proxy[_ -]?authorization|auth|token|credential)\s*[=:]\s*[\"']?\s*$"
)
CREDENTIAL_URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp(?:s)?|ftp)://[^\s/@:]+:[^\s/@]+@"
)
URL_PATTERN = re.compile(
    r"(?i)\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp(?:s)?|ftp)://[^\s\"'<>]{1,4096}"
)
BARE_QUERY_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:^|[?&;])(?P<name>[A-Za-z0-9_.%+-]{1,128})=(?P<value>[^&#;\s]{1,1024})"
)
CONFIG_ASSIGNMENT_PATTERN = re.compile(
    r"(?im)^[ \t]*(?:(?:(?:export|readonly|local|typeset)(?:[ \t]+-[A-Za-z]+)?|"
    r"set|setenv|declare[ \t]+-[A-Za-z]+)[ \t]+|\$env:)?"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_.$%+-]{0,127})[ \t]*"
    r"(?P<operator>=|:)[ \t]*(?P<value>[^\r\n]{1,2048})$"
)
SHELL_SETENV_PATTERN = re.compile(
    r"(?im)^[ \t]*setenv[ \t]+(?P<name>[^\s=:]{1,128})[ \t]+"
    r"(?P<value>[^\r\n]{1,2048})$"
)
ENTROPY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_~+/-])"
    r"([A-Za-z0-9_~-]{40,512}|[A-Za-z0-9+/]{40,510}={0,2})"
    r"(?![A-Za-z0-9_~+/=-])"
)
BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){20,}(?:==|=)?(?![A-Za-z0-9+/=])"
)
CREDENTIAL_HEX_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?P<name>[A-Za-z][A-Za-z0-9_.-]{0,63})\s*(?:=|:)\s*[\"']?"
    r"(?P<value>[0-9a-f]{32,512})(?![0-9a-f])"
)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _decode_basic(value: str) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return None
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (ValueError, TypeError):
        return None


def looks_like_auth_candidate(
    scheme: str, value: str, *, authorization_context: bool
) -> bool:
    value = value.rstrip(".,;:)]}")
    if value.lower().startswith("realm="):
        return False
    if scheme.lower() == "basic":
        decoded = _decode_basic(value)
        return (
            decoded is not None
            and b":" in decoded
            and not any(byte < 0x20 and byte not in {0x09} for byte in decoded)
        )
    if not re.fullmatch(r"[A-Za-z0-9\-._~+/]+={0,}", value):
        return False
    if authorization_context:
        return True
    if any(char.isdigit() or char in "_~+/-=." for char in value):
        return True
    return len(value) >= 24 and shannon_entropy(value) >= 4.3


def looks_high_entropy(value: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return False
    if value == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
        return False
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        value,
    ):
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


def _percent_decode_bounded(value: str) -> str | None:
    current = value
    for _ in range(8):
        if not re.search(r"%[0-9A-Fa-f]{2}", current):
            return current
        try:
            decoded = urllib.parse.unquote(current, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return None
        if len(decoded.encode("utf-8", "strict")) > 4096:
            return None
        if decoded == current:
            return current
        current = decoded
    if re.search(r"%[0-9A-Fa-f]{2}", current):
        return None
    return current


def _credential_value_present(value: str, coordinate: str | None = None) -> bool:
    candidate = re.split(r"[ \t]+[#;]", value.strip(), maxsplit=1)[0].strip()
    if not candidate:
        return False
    quoted = candidate[0:1] == candidate[-1:] and candidate.startswith(("'", '"'))
    if quoted:
        candidate = candidate[1:-1].strip()
    elif ("'" in candidate or '"' in candidate) and not (
        coordinate is not None and is_secret_field_name(coordinate)
    ):
        return False
    lowered = candidate.lower()
    if lowered in {
        "[]",
        "{}",
        "false",
        "nil",
        "none",
        "null",
        "true",
        "undefined",
        "<redacted>",
        "<secret-ref>",
    }:
        return False
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", candidate):
        return False
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", candidate):
        return False
    shell_default = re.fullmatch(
        r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-|:=)([^}]*)\}", candidate
    )
    if shell_default is not None:
        return _credential_value_present(shell_default.group(1), coordinate)
    if re.fullmatch(
        r"(?i)(?:bearer|basic)[ \t]+\$\{[A-Za-z_$][A-Za-z0-9_$.]*\}",
        candidate,
    ):
        return False
    if re.fullmatch(
        r"\$\{\{\s*(?:secrets|vars)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}",
        candidate,
    ):
        return False
    if re.fullmatch(
        r"<(?:value|redacted|secret-ref|non-nil-[a-z0-9-]+|"
        r"configured-[a-z0-9-]+|at-least-[0-9]+-decoded-bytes|"
        r"local-[a-z0-9-]+-id)>",
        lowered,
    ):
        return False
    if coordinate is not None and normalize_field_name(
        candidate
    ) == normalize_field_name(coordinate):
        return False
    if candidate in {"self", "this"}:
        return False
    if (
        coordinate is not None
        and is_secret_field_name(coordinate)
        and candidate.startswith(("[", "{"))
        and candidate.endswith(("]", "}"))
    ):
        return candidate not in {"[]", "{}"}
    if quoted:
        return True
    return bool(
        re.fullmatch(r"[A-Za-z0-9_~+./:@%=-]{1,1024}", candidate)
        or re.fullmatch(
            r"(?i)(?:bearer|basic)[ \t]+[A-Za-z0-9._~+/=%-]{1,512}", candidate
        )
    )


def _query_credential_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for url_match in URL_PATTERN.finditer(text):
        raw_url = url_match.group(0).rstrip(".,)]}")
        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except ValueError:
            continue
        if parsed.username is not None and parsed.password not in {None, ""}:
            spans.append((url_match.start(), url_match.start() + len(raw_url)))
        for query_match in BARE_QUERY_CREDENTIAL_PATTERN.finditer("?" + parsed.query):
            name = _percent_decode_bounded(query_match.group("name"))
            value = _percent_decode_bounded(query_match.group("value"))
            if (
                name is not None
                and value is not None
                and is_secret_field_name(name)
                and _credential_value_present(value)
            ):
                query_offset = raw_url.find("?")
                if query_offset >= 0:
                    start = (
                        url_match.start() + query_offset + query_match.start("value")
                    )
                    spans.append((start, start + len(query_match.group("value"))))
    for query_match in BARE_QUERY_CREDENTIAL_PATTERN.finditer(text):
        # A bare ``name=value`` line is an assignment, not a URL query.  This
        # second pass exists for query fragments beginning with a real query
        # delimiter; complete URLs were handled above.
        if query_match.group(0)[0] not in "?&;":
            continue
        name = _percent_decode_bounded(query_match.group("name"))
        value = _percent_decode_bounded(query_match.group("value"))
        if (
            name is not None
            and value is not None
            and is_secret_field_name(name)
            and _credential_value_present(value)
        ):
            spans.append((query_match.start("value"), query_match.end("value")))
    return sorted(set(spans))


def _nfkc_scan_view(
    text: str, budget: WorkBudget | None = None
) -> tuple[str, Sequence[int] | None]:
    """Build a normalized view after charging expansion/provenance allocation."""

    if budget is not None:
        budget.charge_parser_operations(len(text))
    changed = False
    normalized_length = 0
    normalized_bytes = 0
    for char in text:
        normalized = unicodedata.normalize("NFKC", char)
        changed = changed or normalized != char
        normalized_length += len(normalized)
        size = utf8_size(normalized)
        if size is None:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        normalized_bytes += size
    if not changed:
        return text, None

    # ``array('I')`` is the bounded four-byte source provenance representation.
    # Charge both allocations before constructing either one.
    allocation = normalized_bytes + normalized_length * 4
    if budget is not None:
        budget.ensure_work_capacity(allocation)
        budget.charge_work(allocation)
        budget.charge_parser_operations(len(text))
    chunks: list[str] = []
    offsets = array("I")
    for index, char in enumerate(text):
        normalized = unicodedata.normalize("NFKC", char)
        chunks.append(normalized)
        offsets.extend([index] * len(normalized))
    return "".join(chunks), offsets


_SECTION_HEADER = re.compile(r"^\s*\[\[?([^\]\r\n]{1,512})\]\]?\s*(?:[#;].*)?$")


def _credential_assignment_spans(
    text: str, *, allow_colon_assignment: bool
) -> list[tuple[int, int]]:
    """Return low-entropy assignment values with INI/TOML section context."""

    spans: list[tuple[int, int]] = []
    credential_section = False
    offset = 0
    for line in text.splitlines(keepends=True):
        logical = line.rstrip("\r\n")
        section = _SECTION_HEADER.fullmatch(logical)
        if section is not None:
            components = [
                component.strip().strip("'\"")
                for component in section.group(1).split(".")
            ]
            credential_section = any(
                is_secret_field_name(component) for component in components
            )
            offset += len(line)
            continue
        for pattern in (CONFIG_ASSIGNMENT_PATTERN, SHELL_SETENV_PATTERN):
            match = pattern.fullmatch(logical)
            if match is None:
                continue
            if (
                pattern is CONFIG_ASSIGNMENT_PATTERN
                and match.group("operator") == ":"
                and not allow_colon_assignment
            ):
                continue
            name = _percent_decode_bounded(match.group("name"))
            if name is None or not _credential_value_present(
                match.group("value"), name
            ):
                continue
            normalized_name = normalize_field_name(name)
            sensitive = is_secret_field_name(name) or (
                credential_section and not is_credential_metadata_field(normalized_name)
            )
            if sensitive:
                spans.append(
                    (offset + match.start("value"), offset + match.end("value"))
                )
        offset += len(line)
    return sorted(set(spans))


def scan_content(
    text: str,
    maximum: int,
    *,
    authorization_context: bool = False,
    assignment_context: bool = False,
    colon_assignment_context: bool = False,
    budget: WorkBudget | None = None,
) -> list[ContentHit]:
    """Return every occurrence (including same-line duplicates) up to the cap."""

    normalized_text, source_offsets = _nfkc_scan_view(text, budget)
    needs_whitespace_view = any(
        char.isspace() and char not in {"\n", "\r", "\t", " "}
        for char in normalized_text
    )
    if needs_whitespace_view and budget is not None:
        normalized_size = utf8_size(normalized_text)
        if normalized_size is None:
            raise ScanDataError("SCN005_BUDGET_EXCEEDED")
        budget.ensure_work_capacity(normalized_size)
        budget.charge_work(normalized_size)
    search_text = (
        "".join(
            " " if char.isspace() and char not in {"\n", "\r", "\t"} else char
            for char in normalized_text
        )
        if needs_whitespace_view
        else normalized_text
    )
    hits: list[ContentHit] = []
    occupied: list[tuple[int, int]] = []

    def add(code: str, start: int, end: int) -> bool:
        if start >= len(search_text) or end <= start:
            return False
        source_start = source_offsets[start] if source_offsets is not None else start
        source_end = (
            source_offsets[min(end - 1, len(source_offsets) - 1)] + 1
            if source_offsets is not None
            else end
        )
        hits.append(
            ContentHit(
                line_for_offset(text, source_start),
                source_start,
                source_end,
                code,
            )
        )
        occupied.append((start, end))
        return len(hits) >= maximum

    def overlaps(start: int, end: int) -> bool:
        return any(
            start < occupied_end and end > occupied_start
            for occupied_start, occupied_end in occupied
        )

    for match in PEM_PATTERN.finditer(search_text):
        if add("SCC001_PRIVATE_KEY", match.start(), match.end()):
            return sorted(hits)
    for pattern in PROVIDER_PATTERNS:
        for match in pattern.finditer(search_text):
            if match.group(0).lower().startswith("sk-learn-"):
                continue
            if add("SCC002_PROVIDER_TOKEN", match.start(), match.end()):
                return sorted(hits)
    for match in CREDENTIAL_URL_PATTERN.finditer(search_text):
        if add("SCC005_CREDENTIAL_URL", match.start(), match.end()):
            return sorted(hits)
    for start, end in _query_credential_spans(search_text):
        if overlaps(start, end):
            continue
        if add("SCC005_CREDENTIAL_URL", start, end):
            return sorted(hits)
    for match in AUTH_PATTERN.finditer(search_text):
        line_start = search_text.rfind("\n", 0, match.start()) + 1
        contextual = authorization_context or bool(
            AUTH_COORDINATE_PREFIX.search(search_text[line_start : match.start()])
        )
        if looks_like_auth_candidate(
            match.group("scheme"),
            match.group("value"),
            authorization_context=contextual,
        ) and add("SCC003_AUTH_VALUE", match.start(), match.end()):
            return sorted(hits)
    if assignment_context:
        for start, end in _credential_assignment_spans(
            search_text, allow_colon_assignment=colon_assignment_context
        ):
            if overlaps(start, end):
                continue
            if add("SCC003_AUTH_VALUE", start, end):
                return sorted(hits)
    for match in CREDENTIAL_HEX_ASSIGNMENT_PATTERN.finditer(search_text):
        if not is_secret_field_name(match.group("name")):
            continue
        if add("SCC004_HIGH_ENTROPY", match.start("value"), match.end("value")):
            return sorted(hits)
    for match in BASE64_PATTERN.finditer(search_text):
        if decoded_private_key_signature(match.group(0)) and add(
            "SCC006_ENCODED_PRIVATE_KEY", match.start(), match.end()
        ):
            return sorted(hits)
    for match in ENTROPY_PATTERN.finditer(search_text):
        if overlaps(match.start(), match.end()):
            continue
        value = match.group(1)
        if is_subresource_integrity_digest(value) or not looks_high_entropy(value):
            continue
        if add("SCC004_HIGH_ENTROPY", match.start(), match.end()):
            return sorted(hits)
    return sorted(hits)
