"""Credential-coordinate classification and bounded content signatures."""

from __future__ import annotations

import base64
import math
import re
from collections import Counter

from .model import ContentHit


def normalize_field_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return re.sub(r"_+", "_", value)


_BENIGN_EXACT_FIELDS = {
    "auth_method",
    "auth_mode",
    "auth_scheme",
    "authentication_method",
    "authentication_mode",
    "credential_count",
    "credential_id",
    "credential_ids",
    "credential_kind",
    "credential_ref",
    "credential_refs",
    "credential_scope",
    "max_tokens",
    "public_key",
    "public_keys",
    "secret_count",
    "secret_ref",
    "secret_ref_id",
    "secret_ref_ids",
    "token_count",
    "token_counts",
    "token_index",
    "token_length",
    "token_type",
    "token_types",
    "token_usage",
    "tokenizer",
    "tokenizers",
    "tokens_used",
}
_BENIGN_SUFFIXES = (
    "_count",
    "_digest",
    "_hash",
    "_id",
    "_ids",
    "_index",
    "_kind",
    "_length",
    "_ref",
    "_refs",
    "_revision",
    "_status",
    "_type",
    "_version",
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


def scan_content(
    text: str,
    maximum: int,
    *,
    authorization_context: bool = False,
) -> list[ContentHit]:
    """Return every occurrence (including same-line duplicates) up to the cap."""

    search_text = "".join(
        " " if char.isspace() and char not in {"\n", "\r", "\t"} else char
        for char in text
    )
    hits: list[ContentHit] = []
    occupied: list[tuple[int, int]] = []

    def add(code: str, start: int, end: int) -> bool:
        hits.append(ContentHit(line_for_offset(text, start), start, end, code))
        occupied.append((start, end))
        return len(hits) >= maximum

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
        if any(match.start() < end and match.end() > start for start, end in occupied):
            continue
        value = match.group(1)
        if is_subresource_integrity_digest(value) or not looks_high_entropy(value):
            continue
        if add("SCC004_HIGH_ENTROPY", match.start(), match.end()):
            return sorted(hits)
    return sorted(hits)
