from __future__ import annotations

import copy
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from typing import Any, Callable
from unittest import mock

SECURITY_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SECURITY_ROOT.parents[1]
sys.path.insert(0, str(SECURITY_ROOT))

from secret_contract_scanner.archives import (  # noqa: E402
    archive_members,
    detect_archive_kind,
)
from secret_contract_scanner.content import (  # noqa: E402
    is_secret_field_name,
    scan_content,
)
from secret_contract_scanner.engine import (  # noqa: E402
    apply_content_allowlist,
    scan_repository,
)
from secret_contract_scanner.model import (  # noqa: E402
    SOURCE_SUFFIXES,
    Finding,
    ScanDataError,
    WorkBudget,
    safe_policy_path,
)
from secret_contract_scanner.io_utils import safe_read_file  # noqa: E402
from secret_contract_scanner.policy import load_policy, validate_policy  # noqa: E402
from secret_contract_scanner.self_test import run_self_test  # noqa: E402
from secret_contract_scanner.structured import (  # noqa: E402
    parse_json_bytes,
    parse_yaml_bytes,
)
from secret_contract_scanner.workflows import (  # noqa: E402
    REQUIRED_WORKFLOWS,
    validate_workflow_text,
)

EXPECTED_OWNER_DOCUMENTS = {
    "crates/splendor-types/tests/fixtures/driver/operation-credential-sinks-v1.json": (
        "splendor.driver.operation_credential_sinks.v1",
        "5dbfcd9d37c71dec2fbc8caeb9997bf3a7161e1b5211c50a2d5e1bd8c7b85ffa",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v1a/secret-use-requirement.json": (
        "splendor.secret.use_requirement.v1",
        "8d016ec66804acf5688b9377adaee6d80b954ae06f3432b01744951c65644cb9",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v2/authorization-v2-legal-maximum.json": (
        "splendor.secret.credential_authorization.v2",
        "b9dadb04a379f53b0f7a8c1e570f95f23abbd7fd59bc2525d1e0da64e0c8dae3",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v2/authorization-v2-same-revision.json": (
        "splendor.secret.credential_authorization.v2",
        "1a992c53a7625c9364879f0b0fa091e5ca519bca34df73231b4ee60010cf6b2d",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v2/historical-secret-ref-v1.json": (
        "splendor.secret.ref.v1",
        "d5d5c6fb7437286c8a813c7b191f245005f96f85566bdeb6dfb0cdd646937962",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-legal-maximum.json": (
        "splendor.secret.ref.v2",
        "01b1315e8c4e9d144a36d47a730148c26c6103b8aceb2f09ff49cbb16736767a",
    ),
    "crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-same-revision.json": (
        "splendor.secret.ref.v2",
        "6316575b030cebf96e5f827ed79492900eeb24f80b54e8e38ec5da6fe146f1eb",
    ),
}
EXPECTED_SYMBOLIC_FIXTURES = {
    "conformance/0.2/c03-foundation/v1/negative/cases.json": (
        "b835e1c0891898f905b2b87c5157ef2a06b31eca232ea80ca470316e32389fb6"
    ),
    "conformance/0.2/c03-foundation/v1/positive/cases.json": (
        "bb2816cdd0ed7a31ec628b9781d94eae4e608efdd45d247c674e9fdca84cbf32"
    ),
    "crates/splendor-types/tests/fixtures/secrets/v1a/ids.json": (
        "b98e1b0439d87f7cda2a673017501d5319eb715475a68e02b79d73a1c961ada6"
    ),
    "crates/splendor-types/tests/fixtures/secrets/v1a/preplacement-primitives.json": (
        "903e606ff96933fb9aadd8ff2173772a872b33122dcf472817bb3cf981fa1b6f"
    ),
}
MINIMAL_SCANNER_WORKFLOW = b"""jobs:
  secret-contracts:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: |
          /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test
          /usr/bin/python3 -I scripts/security/check-secret-contracts.py
"""


def bearer(value: str = "abc") -> str:
    return "Bea" + "rer " + value


def basic(value: str = "dTpw") -> str:
    return "Bas" + "ic " + value


def provider_token() -> str:
    return "gh" + "p_" + ("A1" * 12)


def credential_url() -> str:
    return "https://" + "fixture-user:fixture-pass" + "@example.invalid/path"


def low_entropy_assignment(name: str = "PASS" + "WORD", value: str = "abc") -> str:
    return name + "=" + value


def low_entropy_query(name: str = "api_" + "key", value: str = "abc") -> str:
    return "https://example.invalid/path?" + name + "=" + value


def policy_template() -> dict[str, Any]:
    return {
        "schema_version": "splendor.secret_field_scan.v1",
        "scanner_version": "1.0.0",
        "owner": "SECR-006",
        "reviewed_on": "2026-07-26",
        "limits": {
            "max_files": 100,
            "max_file_bytes": 1_048_576,
            "max_total_bytes": 8_388_608,
            "max_structure_depth": 32,
            "max_structure_nodes": 20_000,
            "max_object_members": 512,
            "max_array_items": 512,
            "max_string_bytes": 65_536,
            "max_markdown_fences": 32,
            "max_parser_operations": 1_000_000,
            "max_archive_members": 64,
            "max_archive_unpacked_bytes": 1_048_576,
            "max_findings": 256,
        },
        "governed_roots": [],
        "source_owner_exports": [],
        "owner_schema_documents": [],
        "structural_exceptions": [],
        "symbolic_fixtures": [],
        "content_allowlist": [],
    }


def write_file(root: pathlib.Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def scan_explicit(
    relative: str,
    data: bytes,
    *,
    policy: dict[str, object] | None = None,
) -> list[Finding]:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        write_file(root, relative, data)
        findings, _stats = scan_repository(
            root,
            policy or policy_template(),
            explicit_paths=[relative],
        )
        return findings


def scan_with_production_types_owner(relative: str, data: bytes) -> list[Finding]:
    policy, policy_findings = load_policy(
        REPO_ROOT,
        "scripts/security/secret-contract-policy.json",
        today=dt.date(2026, 7, 26),
    )
    if policy is None or policy_findings:
        raise AssertionError(policy_findings)
    owner = policy["source_owner_exports"][0]
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        write_file(root, relative, data)
        for key in ("path", "package_path"):
            source_path = owner[key]
            write_file(root, source_path, (REPO_ROOT / source_path).read_bytes())
        local_policy = policy_template()
        local_policy["source_owner_exports"] = [owner]
        findings, _stats = scan_repository(
            root,
            local_policy,
            explicit_paths=[relative],
        )
        return findings


def codes(findings: list[Finding]) -> list[str]:
    return [finding.code for finding in findings]


class DecodedStructuredContentTests(unittest.TestCase):
    def test_json_unicode_escape_exposes_short_bearer(self) -> None:
        data = b'{"authorization":"Bea\\u0072er abc"}'
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.json", data)))

    def test_json_unicode_whitespace_exposes_short_bearer(self) -> None:
        data = b'{"authorization":"Bearer\\u00a0abc"}'
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.json", data)))

    def test_json_slash_escape_exposes_credential_url(self) -> None:
        raw = credential_url().replace("/", "\\/")
        data = (json.dumps({"endpoint": raw}).replace("\\\\/", "\\/")).encode()
        self.assertIn(
            "SCC005_CREDENTIAL_URL", codes(scan_explicit("fixture.json", data))
        )

    def test_json_escape_exposes_provider_token(self) -> None:
        token = provider_token()
        escaped = token[:2] + "\\u0070" + token[3:]
        data = ('{"value":"' + escaped + '"}').encode()
        self.assertIn(
            "SCC002_PROVIDER_TOKEN", codes(scan_explicit("fixture.json", data))
        )

    def test_yaml_folded_low_entropy_basic_is_detected(self) -> None:
        data = ("authorization: >\n  " + basic().split()[0] + "\n  dTpw\n").encode()
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.yaml", data)))

    def test_yaml_standard_hex_and_unicode_escapes_are_decoded(self) -> None:
        for escape in (r"\x42asic dTpw", r"\u0042asic dTpw", r"\U00000042asic dTpw"):
            with self.subTest(escape=escape):
                data = ('authorization: "' + escape + '"\n').encode()
                self.assertIn(
                    "SCC003_AUTH_VALUE", codes(scan_explicit("fixture.yaml", data))
                )

    def test_yaml_block_content_starting_with_hash_is_not_a_comment(self) -> None:
        data = ("note: >\n  # " + provider_token() + "\n").encode()
        self.assertIn(
            "SCC002_PROVIDER_TOKEN", codes(scan_explicit("fixture.yaml", data))
        )

    def test_yaml_inline_comment_content_is_scanned(self) -> None:
        data = ("note: safe # " + provider_token() + "\n").encode()
        findings = scan_explicit("fixture.yaml", data)
        hit = next(
            finding for finding in findings if finding.code == "SCC002_PROVIDER_TOKEN"
        )
        self.assertEqual(hit.line, 1)

    def test_contiguous_yaml_comments_are_scanned_as_one_bounded_value(self) -> None:
        marker = "PRIVATE" + " KEY-----"
        lines = [
            "note: safe",
            "# -----BEGIN " + marker,
            "# fixture-material",
            "# -----END " + marker,
        ]
        findings = scan_explicit("fixture.yaml", ("\n".join(lines) + "\n").encode())
        hit = next(
            finding for finding in findings if finding.code == "SCC001_PRIVATE_KEY"
        )
        self.assertEqual(hit.line, 2)

    def test_short_bearer_is_detected_in_authorizing_text_context(self) -> None:
        data = ("authorization: " + bearer() + "\n").encode()
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.txt", data)))

    def test_low_entropy_basic_is_syntactically_detected(self) -> None:
        hits = scan_content(basic(), 10)
        self.assertEqual([hit.code for hit in hits], ["SCC003_AUTH_VALUE"])

    def test_same_line_duplicate_occurrences_are_counted(self) -> None:
        text = basic() + " " + basic("dTpx")
        hits = [
            hit for hit in scan_content(text, 10) if hit.code == "SCC003_AUTH_VALUE"
        ]
        self.assertEqual(len(hits), 2)
        self.assertNotEqual(hits[0].start, hits[1].start)

    def test_source_literal_is_not_counted_twice_after_ast_inspection(self) -> None:
        data = ("class Request:\n    token: str = '" + basic() + "'\n").encode()
        findings = scan_explicit("fixture.py", data)
        self.assertEqual(codes(findings).count("SCC003_AUTH_VALUE"), 1)
        self.assertIn("SCF005_SOURCE_FIELD", codes(findings))

    def test_json_lone_surrogate_has_fixed_error(self) -> None:
        with self.assertRaisesRegex(ScanDataError, "SCN006_MALFORMED_JSON"):
            parse_json_bytes(b'{"value":"\\ud800"}', policy_template()["limits"])

    def test_decoded_json_nul_and_bom_have_fixed_errors(self) -> None:
        for data in (b'{"value":"\\u0000"}', b'{"value":"a\\ufeffb"}'):
            with self.subTest(data=data), self.assertRaisesRegex(
                ScanDataError, "SCN006_MALFORMED_JSON"
            ):
                parse_json_bytes(data, policy_template()["limits"])

    def test_decoded_yaml_nul_and_bom_have_fixed_errors(self) -> None:
        for escape in (r"\0", r"\uFEFF"):
            data = ('value: "' + escape + '"\n').encode()
            with self.subTest(escape=escape), self.assertRaisesRegex(
                ScanDataError, "SCN007_MALFORMED_YAML"
            ):
                parse_yaml_bytes(data, policy_template()["limits"])

    def test_non_finite_json_numbers_have_fixed_error(self) -> None:
        for data in (b'{"value":NaN}', b'{"value":1e999}'):
            with self.subTest(data=data), self.assertRaisesRegex(
                ScanDataError, "SCN006_MALFORMED_JSON"
            ):
                parse_json_bytes(data, policy_template()["limits"])

    def test_non_finite_yaml_number_has_fixed_error(self) -> None:
        with self.assertRaisesRegex(ScanDataError, "SCN007_MALFORMED_YAML"):
            parse_yaml_bytes(b"value: .inf\n", policy_template()["limits"])

    def test_yaml_indentless_and_multiline_standard_forms_are_decoded(self) -> None:
        data = b"""items:
- first value,
  continued
- 'quoted value,
  continued'
command:
  - |
    line one
    line two
"""
        self.assertEqual(
            parse_yaml_bytes(data, policy_template()["limits"]),
            {
                "items": ["first value, continued", "quoted value, continued"],
                "command": ["line one\nline two"],
            },
        )

    def test_normal_repository_mode_decodes_json_and_yaml_scalars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True, capture_output=True
            )
            write_file(root, ".github/workflows/ci.yml", MINIMAL_SCANNER_WORKFLOW)
            write_file(
                root,
                ".github/workflows/docker-image.yml",
                MINIMAL_SCANNER_WORKFLOW,
            )
            token = provider_token()
            escaped = token[:2] + "\\u0070" + token[3:]
            write_file(root, "fixture.json", ('{"note":"' + escaped + '"}').encode())
            write_file(root, "fixture.yaml", ("note: >\n  # " + token + "\n").encode())
            write_file(root, "low.json", b'{"password":"abc"}')
            findings, _stats = scan_repository(root, policy_template())
            affected = {
                finding.path
                for finding in findings
                if finding.code == "SCC002_PROVIDER_TOKEN"
            }
            self.assertEqual(affected, {"fixture.json", "fixture.yaml"})
            self.assertIn(
                ("low.json", "SCC003_AUTH_VALUE"),
                {(finding.path, finding.code) for finding in findings},
            )


class ContextualCredentialContentTests(unittest.TestCase):
    def test_short_low_entropy_bearer_is_detected_after_nested_decoding(self) -> None:
        data = b'{"outer":{"authorization":"Bea\\u0072er a"}}'
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.json", data)))

    def test_low_entropy_config_assignment_families_are_detected(self) -> None:
        fixtures = {
            ".env": "export " + low_entropy_assignment(),
            "settings.ini": "[service]\n" + low_entropy_assignment("API_" + "KEY"),
            "settings.toml": low_entropy_assignment("client_" + "secret", '"abc"'),
            "settings.conf": low_entropy_assignment("access_" + "token"),
            "configure": "#!/bin/sh\nexport "
            + low_entropy_assignment("SERVICE_" + "TOKEN"),
            "fixture.sh": "readonly " + low_entropy_assignment(),
            "fixture.bash": "local " + low_entropy_assignment("API_" + "KEY"),
            "fixture.zsh": "typeset " + low_entropy_assignment("client_" + "secret"),
            "fixture.ksh": "setenv SERVICE_" + "TOKEN abc",
        }
        for path, value in fixtures.items():
            with self.subTest(path=path):
                self.assertIn(
                    "SCC003_AUTH_VALUE", codes(scan_explicit(path, value.encode()))
                )

    def test_low_entropy_python_literal_assignment_is_detected(self) -> None:
        source = "api_" + "key = " + repr("abc") + "\n"
        self.assertIn(
            "SCC003_AUTH_VALUE", codes(scan_explicit("fixture.py", source.encode()))
        )

    def test_dsn_userinfo_and_query_credentials_are_detected(self) -> None:
        fixtures = (
            low_entropy_assignment(
                "DATABASE_" + "DSN",
                "postgresql://" + "fixture-user:fixture-pass" + "@example.invalid/db",
            ),
            credential_url(),
            low_entropy_query(),
            "https://example.invalid/path?client%5F" + "secret=abc",
            "redis://"
            + "fixture-user:fixture-pass"
            + "@example.invalid/0?access_"
            + "token=abc",
        )
        for value in fixtures:
            with self.subTest(value=value):
                self.assertTrue(
                    {"SCC003_AUTH_VALUE", "SCC005_CREDENTIAL_URL"}
                    & set(codes(scan_explicit("fixture.conf", value.encode())))
                )

    def test_plural_and_shell_default_aliases_are_detected(self) -> None:
        fixtures = (
            low_entropy_assignment("API_" + "KEYS"),
            low_entropy_assignment("PASS" + "WORDS"),
            "export SERVICE_" + "TOKEN=${SERVICE_TOKEN:-abc}",
        )
        for value in fixtures:
            with self.subTest(value=value):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.env", value.encode())),
                )

    def test_benign_oauth_algorithm_metric_digest_and_public_metadata_pass(
        self,
    ) -> None:
        fixtures = (
            "oauth_token_endpoint=https://issuer.example.invalid/oauth/token",
            "authorization_endpoint=https://issuer.example.invalid/oauth/authorize",
            "token_signing_algorithm=EdDSA",
            "credential_count=3",
            "token_usage=12",
            "payload_digest=blake3:" + ("ab" * 32),
            "public_key_algorithm=Ed25519",
            "public_metadata=authentication supported",
        )
        for value in fixtures:
            with self.subTest(value=value):
                self.assertEqual(scan_explicit("fixture.conf", value.encode()), [])

    def test_nfkc_alias_is_detected_and_format_controls_fail_closed(self) -> None:
        fullwidth = "ＰＡＳＳＷＯＲＤ=abc".encode()
        controlled = ("authorization=Bea" + "\u200b" + "rer a").encode()
        compatibility_json = (
            '{"ＡＵＴＨＯＲＩＺＡＴＩＯＮ":"Ｂｅａｒｅｒ ａ"}'
        ).encode()
        escaped_control_json = b'{"note":"Bea\\u200brer a"}'
        self.assertIn(
            "SCC003_AUTH_VALUE", codes(scan_explicit("fixture.env", fullwidth))
        )
        self.assertIn(
            "SCN003_PATH_AMBIGUOUS", codes(scan_explicit("fixture.env", controlled))
        )
        self.assertIn(
            "SCC003_AUTH_VALUE",
            codes(scan_explicit("fixture.json", compatibility_json)),
        )
        self.assertIn(
            "SCN006_MALFORMED_JSON",
            codes(scan_explicit("fixture.json", escaped_control_json)),
        )

    def test_nested_same_line_occurrences_remain_exact(self) -> None:
        data = json.dumps(
            {
                "first": {"authorization": bearer("a")},
                "second": {"authorization": bearer("b")},
            },
            separators=(",", ":"),
        ).encode()
        findings = scan_explicit("fixture.json", data)
        self.assertEqual(codes(findings).count("SCC003_AUTH_VALUE"), 2)


class FieldClassifierTests(unittest.TestCase):
    def test_plural_auth_and_key_aliases_are_forbidden(self) -> None:
        for name in (
            "credentials",
            "secrets",
            "passwords",
            "tokens",
            "auth",
            "authentication",
            "access_key",
            "access_key_id",
            "accessKeyId",
            "aws_access_key_id",
            "passphrase",
            "pwd",
            "secret_key",
            "signing_key",
            "hmacKey",
            "tls-key",
        ):
            with self.subTest(name=name):
                self.assertTrue(is_secret_field_name(name))

    def test_benign_metrics_public_material_and_refs_are_not_fields(self) -> None:
        for name in (
            "token_count",
            "tokens_used",
            "max_tokens",
            "tokenizer",
            "credential_id",
            "secret_ref_id",
            "public_key",
            "payload_digest",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_secret_field_name(name))

    def test_plural_wrapper_with_neutral_hex_key_is_rejected(self) -> None:
        value = {"credentials": {"key": "ab" * 32}}
        findings = scan_explicit("fixture.json", json.dumps(value).encode())
        self.assertIn("SCF001_SECRET_FIELD", codes(findings))

    def test_hex_value_is_rejected_only_in_credential_assignment_context(self) -> None:
        hex_value = "ab" * 32
        self.assertEqual(
            [hit.code for hit in scan_content("token=" + hex_value, 10)],
            ["SCC004_HIGH_ENTROPY"],
        )
        self.assertEqual(scan_content("payload_digest=" + hex_value, 10), [])

    def test_camel_case_fake_wrapper_is_rejected(self) -> None:
        value = {"schemaVersion": "splendor.secret.ref.v2", "payload": "ordinary"}
        self.assertIn(
            "SCF002_FAKE_WRAPPER",
            codes(scan_explicit("fixture.json", json.dumps(value).encode())),
        )

    def test_token_metrics_remain_accepted(self) -> None:
        value = {"model": {"tokenizer": "gpt2", "token_count": 42}}
        self.assertNotIn(
            "SCF001_SECRET_FIELD",
            codes(scan_explicit("fixture.json", json.dumps(value).encode())),
        )

    def test_exact_sri_and_public_digest_are_not_entropy_findings(self) -> None:
        sri = "sha256-" + "AAECAwQFBgcICQoLDA0ODxAR" + "EhMUFRYXGBkaGxwdHh8="
        public_digest = "blake3:" + ("ab" * 32)
        self.assertEqual(scan_content(sri + " " + public_digest, 10), [])


class SourceSurfaceTests(unittest.TestCase):
    def test_utf8_binary_suffix_and_dotfile_are_scanned(self) -> None:
        for path in ("fixture.bin", ".fixture"):
            with self.subTest(path=path):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit(path, ("auth=" + basic()).encode())),
                )

    def test_internal_utf8_bom_fails_closed_in_text_file(self) -> None:
        findings = scan_explicit("fixture.txt", "ordinary\ufefftext".encode())
        self.assertIn("SCN003_PATH_AMBIGUOUS", codes(findings))

    def test_toml_table_header_is_not_misclassified_as_a_json_array(self) -> None:
        findings = scan_explicit("fixture.toml", b'[package]\nname = "fixture"\n')
        self.assertNotIn("SCN006_MALFORMED_JSON", codes(findings))

    def test_python_authorizing_field_declaration_is_rejected(self) -> None:
        data = b"class Request:\n    token: str\n"
        self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.py", data)))

    def test_typescript_authorizing_field_declaration_is_rejected(self) -> None:
        data = b"export interface Request {\n  credentials: string;\n}\n"
        self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", data)))

    def test_inline_typescript_authorizing_field_declaration_is_rejected(self) -> None:
        data = b"export interface Request { safe: string; credentials: string; }\n"
        self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", data)))

    def test_javascript_and_mjs_class_fields_are_rejected(self) -> None:
        for path in ("fixture.js", "fixture.mjs"):
            data = b"class Request {\n  password = null;\n}\n"
            with self.subTest(path=path):
                self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit(path, data)))

    def test_javascript_bare_class_field_is_rejected(self) -> None:
        data = b"class Request {\n  token;\n}\n"
        self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.js", data)))

    def test_quoted_private_and_parameter_property_fields_are_rejected(self) -> None:
        fixtures = (
            b'export interface Request {\n  "token": string;\n}\n',
            b"class Request {\n  #password = null;\n}\n",
            b"class Request {\n  constructor(private readonly token: string) {}\n}\n",
            b"export default class Request { token!: string; }\n",
            b"export declare interface Request { credentials: string; }\n",
            b"export type Request<T> = { password: T; };\n",
        )
        for data in fixtures:
            with self.subTest(data=data):
                self.assertIn(
                    "SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", data))
                )

    def test_unpinned_lexical_secret_reference_is_rejected(self) -> None:
        data = b'import type { SecretRefV2 } from "@splendor/types";\nexport interface Request {\n  secret: SecretRefV2;\n}\n'
        self.assertIn("SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", data)))

    def test_safe_type_name_or_raw_union_cannot_smuggle_source_field(self) -> None:
        for annotation in ("SecretRefButRaw", "SecretRef | bytes"):
            with self.subTest(annotation=annotation):
                data = f"class Request:\n    secret: {annotation}\n".encode()
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.py", data)),
                )

    def test_normal_repository_mode_reads_every_utf8_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True, capture_output=True
            )
            write_file(root, "fixture.bin", ("auth=" + basic()).encode())
            write_file(root, ".fixture", ("auth=" + basic("dTpx")).encode())
            findings, stats = scan_repository(root, policy_template())
            affected = {
                finding.path
                for finding in findings
                if finding.code == "SCC003_AUTH_VALUE"
            }
            self.assertEqual(affected, {".fixture", "fixture.bin"})
            self.assertEqual(stats.content_files, 2)

    def test_normal_repository_mode_decodes_json_without_a_json_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True, capture_output=True
            )
            write_file(root, ".github/workflows/ci.yml", MINIMAL_SCANNER_WORKFLOW)
            write_file(
                root,
                ".github/workflows/docker-image.yml",
                MINIMAL_SCANNER_WORKFLOW,
            )
            token = provider_token()
            escaped = token[:2] + "\\u0070" + token[3:]
            write_file(root, "manifest.bin", ('{"note":"' + escaped + '"}').encode())
            findings, _stats = scan_repository(root, policy_template())
            self.assertIn("SCC002_PROVIDER_TOKEN", codes(findings))

    def test_normal_repository_mode_structurally_checks_source_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True, capture_output=True
            )
            write_file(root, ".github/workflows/ci.yml", MINIMAL_SCANNER_WORKFLOW)
            write_file(
                root,
                ".github/workflows/docker-image.yml",
                MINIMAL_SCANNER_WORKFLOW,
            )
            write_file(root, "request.py", b"class Request:\n    token: str\n")
            policy = policy_template()
            policy["governed_roots"] = [
                {
                    "id": "request-source",
                    "path": "request.py",
                    "formats": {".py": "python_source"},
                    "owner": "test",
                    "reason": "exercise governed source production wiring",
                }
            ]
            findings, _stats = scan_repository(root, policy)
            self.assertIn("SCF005_SOURCE_FIELD", codes(findings))

    def test_production_source_exceptions_are_exact(self) -> None:
        policy, policy_findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(policy_findings, [])
        assert policy is not None
        findings, _stats = scan_repository(
            REPO_ROOT,
            policy,
            explicit_paths=[
                "python/splendor/daemon_client.py",
                "tests/e2e/use-cases/fixtures/action_provider.py",
                "typescript/packages/client/src/index.ts",
                "typescript/packages/types/src/index.ts",
            ],
        )
        self.assertFalse(
            {"SCF004_INVALID_EXCEPTION", "SCF005_SOURCE_FIELD"} & set(codes(findings))
        )

    def test_extensionless_and_shebang_sources_receive_declaration_checks(self) -> None:
        fixtures = {
            "module": "class Request:\n    api_" + "key: str\n",
            "python-tool": "#!/usr/bin/env python3\nclass Request:\n    pass"
            + "word: str\n",
            "node-tool": "#!/usr/bin/env node\nclass Request {\n  access"
            + "Token;\n}\n",
        }
        for path, source in fixtures.items():
            with self.subTest(path=path):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit(path, source.encode())),
                )

    def test_python_module_self_constructor_and_function_parameters_are_checked(
        self,
    ) -> None:
        fixtures = (
            "api_" + "key: str\n",
            "class Request:\n    def __init__(self, pass"
            + "word: str):\n        self.pass"
            + "word = password\n",
            "def call(access_" + "token: str) -> None:\n    pass\n",
            "class Request:\n    def set_value(self, value: str) -> None:\n        self.client_"
            + "secret = value\n",
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.py", source.encode())),
                )

    def test_python_typed_record_factory_forms_are_checked(self) -> None:
        fixtures = (
            'from typing import TypedDict\nRequest = TypedDict("Request", {"api_'
            + 'key": str})\n',
            'from typing import TypedDict\nRequest = TypedDict("Request", pass'
            + "word=str)\n",
            'from dataclasses import make_dataclass\nRequest = make_dataclass("Request", [("pass'
            + 'word", str)])\n',
            'from pydantic import create_model\nRequest = create_model("Request", access_'
            + "token=(str, ...))\n",
            'from pydantic import create_model\nRequest = create_model("Request", **{"client_'
            + 'secret": (str, ...)})\n',
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.py", source.encode())),
                )

    def test_python_lexical_safe_reference_has_no_pinned_owner_export(self) -> None:
        canonical = (
            "from splendor.types import SecretRefV2\n"
            "class Request:\n    secret: SecretRefV2 | None = None\n"
        )
        shadowed = (
            "class SecretRefV2: pass\n"
            "class Request:\n    secret: SecretRefV2 | None = None\n"
        )
        alias_shadowed = (
            "from splendor.types import SecretRefV2 as Ref\n"
            "def build(Ref):\n"
            "    class Request:\n"
            "        secret: Ref | None = None\n"
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            codes(scan_explicit("fixture.py", canonical.encode())),
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.py", shadowed.encode()))
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            codes(scan_explicit("fixture.py", alias_shadowed.encode())),
        )

    def test_python_safe_reference_with_unsafe_default_is_rejected(self) -> None:
        source = (
            "from splendor.types import SecretRefV2\n"
            "class Request:\n    secret: SecretRefV2 = " + repr("abc") + "\n"
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.py", source.encode()))
        )

    def test_python_relative_import_and_variadic_reference_are_not_safe(self) -> None:
        fixtures = (
            "from .splendor.types import SecretRefV2\n"
            "class Request:\n    secret: SecretRefV2 | None = None\n",
            "from splendor.types import SecretRefV2\n"
            "def call(*secrets: SecretRefV2):\n    pass\n",
            "from splendor.types import SecretRefV2\n"
            "def call(**credentials: SecretRefV2):\n    pass\n",
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.py", source.encode())),
                )

    def test_python_decoded_literal_is_scanned_in_assignment_context(self) -> None:
        source = "api_" + 'key = "Bea\\u0072er a"\n'
        self.assertIn(
            "SCC003_AUTH_VALUE", codes(scan_explicit("fixture.py", source.encode()))
        )
        token = provider_token()
        escaped = token[:2] + "\\u0070" + token[3:]
        self.assertIn(
            "SCC002_PROVIDER_TOKEN",
            codes(scan_explicit("fixture.py", f'send("{escaped}")\n'.encode())),
        )

    def test_multiline_nested_typescript_fields_parameters_and_accessors_are_checked(
        self,
    ) -> None:
        fixtures = (
            "export interface Request {\n  api" + "Key:\n    string;\n}\n",
            "export type Request = { nested: { pass" + "word: string } };\n",
            "class Request {\n  constructor(\n    private readonly access"
            + "Token: string,\n  ) {}\n}\n",
            "class Request {\n  get client" + 'Secret(): string { return ""; }\n}\n',
            "function call(\n  api_" + "key: string,\n): void {}\n",
            'const request = { nested: "safe", pass' + 'word: "abc" };\n',
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.ts", source.encode())),
                )

    def test_typescript_safe_reference_requires_nonshadowed_import(self) -> None:
        canonical = (
            'import type { CallerCredential } from "@splendor/types";\n'
            "export interface Request { credential: CallerCredential | null; }\n"
        )
        shadowed = (
            'import type { CallerCredential } from "@splendor/types";\n'
            "type CallerCredential = string;\n"
            "export interface Request { credential: CallerCredential; }\n"
        )
        alias_shadowed = (
            'import type { CallerCredential as Ref } from "@splendor/types";\n'
            "function build(Ref: unknown) {\n"
            "  class Request { credential: Ref; }\n"
            "}\n"
        )
        name_only_owner = (
            "export type SecretRefV2 = string;\n"
            "export interface Request { secret: SecretRefV2; }\n"
        )
        self.assertNotIn(
            "SCF005_SOURCE_FIELD",
            codes(scan_with_production_types_owner("fixture.ts", canonical.encode())),
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            codes(scan_with_production_types_owner("fixture.ts", shadowed.encode())),
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            codes(
                scan_with_production_types_owner("fixture.ts", alias_shadowed.encode())
            ),
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            codes(
                scan_explicit(
                    "typescript/packages/types/src/index.ts",
                    name_only_owner.encode(),
                )
            ),
        )

    def test_typescript_safe_reference_with_initializer_is_rejected(self) -> None:
        source = (
            'import type { SecretRefV2 } from "@splendor/types";\n'
            "class Request { secret: SecretRefV2 = " + json.dumps("abc") + "; }\n"
        )
        self.assertIn(
            "SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", source.encode()))
        )

    def test_typescript_forged_import_and_destructuring_alias_are_rejected(
        self,
    ) -> None:
        fixtures = (
            'import type { Evil as SecretRefV2 } from "@splendor/types";\n'
            "interface Request { secret: SecretRefV2; }\n",
            'import type SecretRefV2 from "@splendor/types";\n'
            "interface Request { secret: SecretRefV2; }\n",
            "const { safe: password } = source;\n",
            "const { apiKey: safe } = source;\n",
            "function call({ safe: password }: Record<string, string>) {}\n",
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCF005_SOURCE_FIELD",
                    codes(scan_explicit("fixture.ts", source.encode())),
                )

    def test_typescript_safe_reference_constructor_literal_is_scanned(self) -> None:
        source = (
            'import type { SecretRefV2 } from "@splendor/types";\n'
            "class Request { secret: SecretRefV2; constructor() { "
            'this.secret = "abc" as any; } }\n'
        )
        self.assertIn(
            "SCC003_AUTH_VALUE", codes(scan_explicit("fixture.ts", source.encode()))
        )

    def test_typescript_compound_assignment_literal_is_scanned(self) -> None:
        fixtures = (
            'const request = {} as any; request.password ||= "abc";\n',
            'let password: string | undefined; password ??= "abc";\n',
        )
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.ts", source.encode())),
                )

    def test_typescript_decoded_literal_and_property_assignment_are_checked(
        self,
    ) -> None:
        source = "const api_" + 'key = "Bea\\u0072er a";\n'
        findings = scan_explicit("fixture.ts", source.encode())
        self.assertIn("SCF005_SOURCE_FIELD", codes(findings))
        self.assertIn("SCC003_AUTH_VALUE", codes(findings))
        object_source = "const request = { client" + 'Secret: "abc" };\n'
        object_findings = scan_explicit("fixture.ts", object_source.encode())
        self.assertIn("SCF005_SOURCE_FIELD", codes(object_findings))
        self.assertIn("SCC003_AUTH_VALUE", codes(object_findings))

    def test_source_exception_is_bound_to_default_and_file_digest(self) -> None:
        policy, policy_findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(policy_findings, [])
        assert policy is not None
        source = (REPO_ROOT / "python/splendor/daemon_client.py").read_text()
        changed = source.replace(
            "    token: str\n", "    token: str = " + repr("abc") + "\n", 1
        )
        findings = scan_explicit(
            "python/splendor/daemon_client.py", changed.encode(), policy=policy
        )
        self.assertIn("SCF004_INVALID_EXCEPTION", codes(findings))

        types_path = "typescript/packages/types/src/index.ts"
        types_source = (REPO_ROOT / types_path).read_text()
        changed_types = types_source.replace(
            "  credential: CallerCredential;",
            "  credential: string;",
            1,
        )
        self.assertIn(
            "SCF004_INVALID_EXCEPTION",
            codes(scan_explicit(types_path, changed_types.encode(), policy=policy)),
        )


class MarkdownAndOpenApiTests(unittest.TestCase):
    def test_markdown_first_token_and_annotation_variants_are_parsed(self) -> None:
        variants = (
            "```json title=fixture",
            "```{.json #fixture}",
            "```application/json annotate=true",
            "```application/json;charset=utf-8",
        )
        for opener in variants:
            document = (
                opener + "\n" + json.dumps({"authorization": bearer()}) + "\n```\n"
            ).encode()
            with self.subTest(opener=opener):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.md", document)),
                )

    def test_jsonc_like_fence_fails_closed(self) -> None:
        for label in (
            "jsonc title=fixture",
            "json5",
            "json-with-comments",
            "json_lines",
            "ndjson",
        ):
            document = ("```" + label + '\n{"safe":true}\n```\n').encode()
            with self.subTest(label=label):
                self.assertIn(
                    "SCN008_MALFORMED_MARKDOWN",
                    codes(scan_explicit("fixture.md", document)),
                )

    def test_markdown_yaml_first_token_and_annotation_variants_are_parsed(
        self,
    ) -> None:
        variants = (
            "```yaml title=fixture",
            "```{.yml #fixture}",
            "```application/yaml annotate=true",
            "```application/x-yaml",
            "```text/yaml",
        )
        for opener in variants:
            document = (opener + "\nauthorization: " + basic() + "\n```\n").encode()
            with self.subTest(opener=opener):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.md", document)),
                )

    def test_openapi_parameter_name_is_structurally_checked(self) -> None:
        data = b"""openapi: 3.1.0
components:
  parameters:
    RawHeader:
      name: Authorization
      in: header
      schema: {type: string}
"""
        self.assertIn("SCF001_SECRET_FIELD", codes(scan_explicit("openapi.yaml", data)))

    def test_openapi_parameter_name_cannot_hide_in_incomplete_shape(self) -> None:
        data = b"""openapi: 3.1.0
components:
  parameters:
    RawHeader:
      name: Authorization
      in: header
"""
        self.assertIn("SCF001_SECRET_FIELD", codes(scan_explicit("openapi.yaml", data)))

    def test_openapi_scalar_example_default_and_const_are_content_checked(self) -> None:
        for keyword in ("example", "default", "const"):
            data = (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Value:\n      "
                + keyword
                + ": '"
                + bearer()
                + "'\n"
            ).encode()
            with self.subTest(keyword=keyword):
                self.assertIn(
                    "SCC003_AUTH_VALUE", codes(scan_explicit("openapi.yaml", data))
                )

    def test_commonmark_blockquote_and_list_container_fences_are_decoded(self) -> None:
        documents = (
            "> ```json\n> " + json.dumps({"authorization": bearer("a")}) + "\n> ```\n",
            "- contract\n\n  > ```yaml\n  > authorization: "
            + bearer("a")
            + "\n  > ```\n",
        )
        for document in documents:
            with self.subTest(document=document):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.md", document.encode())),
                )

    def test_myst_code_block_json_and_yaml_directives_are_decoded(self) -> None:
        documents = (
            "```{code-block} json\n"
            + json.dumps({"authorization": bearer("a")})
            + "\n```\n",
            "```{code-block} yaml\nauthorization: " + bearer("a") + "\n```\n",
        )
        for document in documents:
            with self.subTest(document=document):
                self.assertIn(
                    "SCC003_AUTH_VALUE",
                    codes(scan_explicit("fixture.md", document.encode())),
                )

    def test_myst_colon_code_block_directive_is_decoded(self) -> None:
        for directive in ("code-block", "sourcecode"):
            with self.subTest(directive=directive):
                document = f":::{{{directive}}} yaml\npassword: abc\n:::\n"
                findings = scan_explicit("fixture.md", document.encode())
                self.assertIn("SCF001_SECRET_FIELD", codes(findings))
                self.assertIn("SCC003_AUTH_VALUE", codes(findings))

    def test_ambiguous_myst_governed_fence_fails_closed(self) -> None:
        for opener in (
            "```{code-block}",
            "```{code-block} json yaml",
            "```{code-block} jsonc",
        ):
            with self.subTest(opener=opener):
                document = opener + "\n{}\n```\n"
                self.assertIn(
                    "SCN008_MALFORMED_MARKDOWN",
                    codes(scan_explicit("fixture.md", document.encode())),
                )

    def test_openapi_authorization_header_and_api_key_scheme_are_rejected(self) -> None:
        documents = (
            b"""openapi: 3.1.0
components:
  headers:
    Authorization:
      schema: {type: string, default: abc}
""",
            b"""openapi: 3.1.0
components:
  securitySchemes:
    UnsafeKey:
      type: apiKey
      in: header
      name: X-API-Key
""",
            b"""openapi: 3.1.0
components:
  securitySchemes:
    UnsafeOAuth:
      type: oauth2
      clientSecret: abc
""",
        )
        for document in documents:
            with self.subTest(document=document):
                self.assertIn(
                    "SCF001_SECRET_FIELD",
                    codes(scan_explicit("openapi.yaml", document)),
                )

    def test_openapi_value_coordinates_include_enum_examples_and_header_values(
        self,
    ) -> None:
        data = (
            "openapi: 3.1.0\ncomponents:\n  headers:\n    X-Session:\n"
            '      schema:\n        type: string\n        examples: ["'
            + bearer("a")
            + '"]\n'
        ).encode()
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("openapi.yaml", data)))

    def test_openapi_exact_bearer_oauth_metadata_remains_accepted(self) -> None:
        data = b"""openapi: 3.1.0
components:
  securitySchemes:
    ResidentBearer:
      type: http
      scheme: bearer
      bearerFormat: JWT (EdDSA)
    OAuth:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://issuer.example.invalid/oauth/authorize
          tokenUrl: https://issuer.example.invalid/oauth/token
          scopes: {read: Read public metadata.}
  responses:
    Unauthorized:
      headers:
        WWW-Authenticate:
          schema: {type: string}
          example: 'Bearer realm="splendor"'
"""
        findings = scan_explicit("openapi.yaml", data)
        self.assertNotIn("SCF001_SECRET_FIELD", codes(findings))
        self.assertFalse(
            set(codes(findings)) & {"SCC003_AUTH_VALUE", "SCC005_CREDENTIAL_URL"}
        )


class ArchiveTests(unittest.TestCase):
    @staticmethod
    def zip_bytes(name: str, data: bytes) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(name, data)
        return output.getvalue()

    def test_outer_archive_is_detected_by_magic_not_name(self) -> None:
        data = self.zip_bytes("fixture.txt", ("auth=" + basic()).encode())
        self.assertEqual(detect_archive_kind(data), "zip")
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("fixture.bin", data)))

    def test_json_member_is_structurally_sniffed_without_suffix(self) -> None:
        member = json.dumps({"credentials": {"key": "ab" * 32}}).encode()
        data = self.zip_bytes("manifest.bin", member)
        self.assertIn("SCF001_SECRET_FIELD", codes(scan_explicit("fixture.zip", data)))

    def test_yaml_member_is_structurally_sniffed_without_suffix(self) -> None:
        member = b"metadata: ordinary\ncredentials:\n  key: ordinary\n"
        data = self.zip_bytes("manifest.bin", member)
        self.assertIn("SCF001_SECRET_FIELD", codes(scan_explicit("fixture.zip", data)))

    def test_structural_member_sniff_precedes_a_misleading_source_suffix(self) -> None:
        member = b"metadata: ordinary\ncredentials:\n  key: ordinary\n"
        data = self.zip_bytes("manifest.py", member)
        self.assertIn("SCF001_SECRET_FIELD", codes(scan_explicit("fixture.zip", data)))

    def test_nested_zip_is_rejected_even_with_binary_name(self) -> None:
        nested = self.zip_bytes("fixture.txt", b"ordinary")
        outer = self.zip_bytes("nested.bin", nested)
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", outer))
        )

    def test_nested_gzip_is_rejected(self) -> None:
        outer = self.zip_bytes("nested.bin", gzip.compress(b"ordinary"))
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", outer))
        )

    def test_nested_tar_is_rejected_even_with_binary_name(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        outer = self.zip_bytes("nested.bin", output.getvalue())
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", outer))
        )

    def test_standalone_gzip_text_is_supported(self) -> None:
        data = gzip.compress(("auth=" + basic()).encode())
        self.assertIn("SCC003_AUTH_VALUE", codes(scan_explicit("payload.dat", data)))

    def test_gzip_wrapped_tar_is_supported(self) -> None:
        output = io.BytesIO()
        payload = ("auth=" + basic()).encode()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        self.assertIn(
            "SCC003_AUTH_VALUE", codes(scan_explicit("payload.bin", output.getvalue()))
        )

    def test_malformed_gzip_has_fixed_archive_error(self) -> None:
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("payload.gz", b"\x1f\x8bmalformed")),
        )

    def test_malformed_zip_has_fixed_archive_error(self) -> None:
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("payload.bin", b"PK\x03\x04malformed")),
        )

    def test_unsupported_zip_compression_has_fixed_archive_error(self) -> None:
        data = bytearray(self.zip_bytes("fixture.txt", b"ordinary"))
        central = data.index(b"PK\x01\x02")
        unsupported = (99).to_bytes(2, "little")
        data[8:10] = unsupported
        data[central + 10 : central + 12] = unsupported
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("payload.zip", bytes(data))),
        )

    def test_truncated_tar_has_fixed_archive_error(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = 16
            archive.addfile(info, io.BytesIO(b"x" * 16))
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("payload.bin", output.getvalue()[:512])),
        )

    def test_corrupt_deflate_stream_has_fixed_archive_error(self) -> None:
        data = bytearray(gzip.compress(b"A" * 10_000))
        data[10] ^= 0xFF
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("payload.gz", bytes(data)))
        )

    def test_archive_traversal_and_link_members_fail_closed(self) -> None:
        traversal = self.zip_bytes("../escape.txt", b"ordinary")
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", traversal))
        )

        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("link.txt")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"target.txt")
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("outer.zip", output.getvalue())),
        )

    def test_utf8_bom_member_fails_closed_and_opaque_member_is_a_nonclaim(self) -> None:
        ambiguous = self.zip_bytes("fixture.bin", b"\xef\xbb\xbfordinary")
        self.assertIn(
            "SCN003_PATH_AMBIGUOUS", codes(scan_explicit("outer.zip", ambiguous))
        )
        opaque = self.zip_bytes("fixture.bin", b"\xff\x00\xfe")
        self.assertEqual(scan_explicit("outer.zip", opaque), [])

    def test_archive_unpacked_budget_is_repository_global(self) -> None:
        policy = policy_template()
        policy["limits"]["max_archive_unpacked_bytes"] = 600
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = self.zip_bytes("one.txt", b"a" * 400)
            second = self.zip_bytes("two.txt", b"b" * 400)
            write_file(root, "one.zip", first)
            write_file(root, "two.zip", second)
            findings, _stats = scan_repository(
                root, policy, explicit_paths=["one.zip", "two.zip"]
            )
            self.assertIn("SCA001_ARCHIVE_INVALID", codes(findings))

    def test_archive_expansion_is_charged_to_global_work_budget(self) -> None:
        member = b"a" * 400
        data = self.zip_bytes("one.txt", member)
        policy = policy_template()
        policy["limits"]["max_total_bytes"] = len(data) + len(member) - 1
        self.assertIn(
            "SCN005_BUDGET_EXCEEDED",
            codes(scan_explicit("one.zip", data, policy=policy)),
        )

    def test_archive_member_budget_is_repository_global(self) -> None:
        policy = policy_template()
        policy["limits"]["max_archive_members"] = 1
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            write_file(root, "one.zip", self.zip_bytes("one.txt", b"a"))
            write_file(root, "two.zip", self.zip_bytes("two.txt", b"b"))
            findings, _stats = scan_repository(
                root, policy, explicit_paths=["one.zip", "two.zip"]
            )
            self.assertIn("SCA001_ARCHIVE_INVALID", codes(findings))

    def test_archive_findings_stop_at_global_finding_budget(self) -> None:
        policy = policy_template()
        policy["limits"]["max_findings"] = 2
        member = (basic() + "\n") * 10
        findings = scan_explicit(
            "outer.zip", self.zip_bytes("fixture.txt", member.encode()), policy=policy
        )
        self.assertLessEqual(len(findings), 3)
        self.assertIn("SCN005_BUDGET_EXCEEDED", codes(findings))

    def test_gzip_expansion_budget_is_repository_global(self) -> None:
        policy = policy_template()
        policy["limits"]["max_archive_unpacked_bytes"] = 600
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            write_file(root, "one.gz", gzip.compress(b"a" * 400))
            write_file(root, "two.gz", gzip.compress(b"b" * 400))
            findings, _stats = scan_repository(
                root, policy, explicit_paths=["one.gz", "two.gz"]
            )
            self.assertIn("SCA001_ARCHIVE_INVALID", codes(findings))

    def test_archive_helper_rejects_nested_standalone_gzip_payload(self) -> None:
        policy = policy_template()
        budget = WorkBudget(policy["limits"])
        with self.assertRaisesRegex(ScanDataError, "SCA001_ARCHIVE_INVALID"):
            list(
                archive_members(
                    gzip.compress(gzip.compress(b"x")), policy["limits"], budget
                )
            )

    def test_prefixed_zip_is_detected_structurally_and_fails_closed(self) -> None:
        data = b"#!/bin/sh\nexit 0\n" + self.zip_bytes("fixture.txt", b"ordinary")
        self.assertEqual(detect_archive_kind(data), "zip")
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("polyglot.bin", data))
        )
        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        for polyglot in (
            b"prefix" + gzip.compress(b"ordinary"),
            b"prefix" + tar_output.getvalue(),
        ):
            with self.subTest(kind=detect_archive_kind(polyglot)):
                self.assertIn(
                    "SCA001_ARCHIVE_INVALID",
                    codes(scan_explicit("polyglot.bin", polyglot)),
                )

    def test_nested_prefixed_zip_is_not_treated_as_opaque(self) -> None:
        nested = b"prefix" + self.zip_bytes("fixture.txt", b"ordinary")
        outer = self.zip_bytes("nested.bin", nested)
        self.assertIn(
            "SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", outer))
        )

    def test_zip_trailing_data_and_comments_fail_closed(self) -> None:
        trailing = self.zip_bytes("fixture.txt", b"ordinary") + b"appended"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
            archive.comment = low_entropy_assignment().encode()
            info = zipfile.ZipInfo("fixture.txt")
            info.comment = low_entropy_assignment("API_" + "KEY").encode()
            archive.writestr(info, b"ordinary")
        extra_output = io.BytesIO()
        with zipfile.ZipFile(extra_output, "w", zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("fixture.txt")
            info.extra = b"\xfe\xca\x03\x00abc"
            archive.writestr(info, b"ordinary")
        for data in (trailing, output.getvalue(), extra_output.getvalue()):
            with self.subTest(size=len(data)):
                self.assertIn(
                    "SCA001_ARCHIVE_INVALID",
                    codes(scan_explicit("outer.zip", data)),
                )

    def test_zip_local_metadata_and_precentral_gap_fail_closed(self) -> None:
        base = bytearray(self.zip_bytes("safe.txt", b"ordinary"))
        central = base.index(b"PK\x01\x02")
        eocd = base.index(b"PK\x05\x06")
        name_length = struct.unpack_from("<H", base, 26)[0]
        insert_at = 30 + name_length

        local_extra = b"PASSWORD=abc"
        with_local_extra = bytearray(base[:insert_at] + local_extra + base[insert_at:])
        struct.pack_into("<H", with_local_extra, 28, len(local_extra))
        struct.pack_into(
            "<I",
            with_local_extra,
            eocd + len(local_extra) + 16,
            central + len(local_extra),
        )

        gap = b"PASSWORD=abc"
        with_gap = bytearray(base[:central] + gap + base[central:])
        struct.pack_into("<I", with_gap, eocd + len(gap) + 16, central + len(gap))
        for data in (bytes(with_local_extra), bytes(with_gap)):
            with self.subTest(size=len(data)):
                self.assertIn(
                    "SCA001_ARCHIVE_INVALID",
                    codes(scan_explicit("outer.zip", data)),
                )

    def test_zip_compressed_stream_trailing_data_fails_closed(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("safe.txt", b"ordinary")
        data = bytearray(output.getvalue())
        central = data.index(b"PK\x01\x02")
        eocd = data.index(b"PK\x05\x06")
        trailing = b"PASSWORD=abc"
        compressed = struct.unpack_from("<I", data, 18)[0]
        data[central:central] = trailing
        struct.pack_into("<I", data, 18, compressed + len(trailing))
        central += len(trailing)
        eocd += len(trailing)
        struct.pack_into("<I", data, central + 20, compressed + len(trailing))
        struct.pack_into("<I", data, eocd + 16, central)

        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("outer.zip", bytes(data))),
        )

    def test_supported_zip_compression_streams_are_scanned(self) -> None:
        for compression in (zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2):
            with self.subTest(compression=compression):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w", compression) as archive:
                    archive.writestr("safe.txt", b"password: abc\n")
                self.assertIn(
                    "SCF001_SECRET_FIELD",
                    codes(scan_explicit("outer.zip", output.getvalue())),
                )

    def test_credential_capable_zip_member_name_fails_closed(self) -> None:
        name = low_entropy_assignment("API_" + "KEY") + ".txt"
        data = self.zip_bytes(name, b"ordinary")
        self.assertIn("SCA001_ARCHIVE_INVALID", codes(scan_explicit("outer.zip", data)))
        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.uname = low_entropy_assignment()
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("outer.tar", tar_output.getvalue())),
        )

    def test_tar_hidden_name_metadata_fails_closed(self) -> None:
        output = io.BytesIO()
        with tarfile.open(
            fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT
        ) as archive:
            info = tarfile.TarInfo("safe.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        data = bytearray(output.getvalue())
        hidden = b"safe.txt\x00PASSWORD=abc"
        data[0:100] = hidden + (b"\x00" * (100 - len(hidden)))
        data[148:156] = b"        "
        checksum = sum(data[:512])
        data[148:156] = f"{checksum:06o}\x00 ".encode()
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("outer.tar", bytes(data))),
        )

    def test_tar_hidden_payload_padding_fails_closed(self) -> None:
        output = io.BytesIO()
        with tarfile.open(
            fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT
        ) as archive:
            info = tarfile.TarInfo("safe.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        data = bytearray(output.getvalue())
        data[513 : 513 + len(b"PASSWORD=abc")] = b"PASSWORD=abc"
        self.assertIn(
            "SCA001_ARCHIVE_INVALID",
            codes(scan_explicit("outer.tar", bytes(data))),
        )

    def test_gzip_name_comment_concatenation_and_trailing_data_fail_closed(
        self,
    ) -> None:
        named = io.BytesIO()
        with gzip.GzipFile(
            filename=low_entropy_assignment(), mode="wb", fileobj=named
        ) as archive:
            archive.write(b"ordinary")
        concatenated = gzip.compress(b"first") + gzip.compress(b"second")
        trailing = gzip.compress(b"ordinary") + b"appended"
        for data in (named.getvalue(), concatenated, trailing):
            with self.subTest(size=len(data)):
                self.assertIn(
                    "SCA001_ARCHIVE_INVALID",
                    codes(scan_explicit("payload.bin", data)),
                )

    def test_global_member_budget_is_checked_before_zip_enumeration(self) -> None:
        policy = policy_template()
        budget = WorkBudget(policy["limits"])
        budget.archive_members = policy["limits"]["max_archive_members"]
        data = self.zip_bytes("fixture.txt", b"ordinary")
        with mock.patch.object(
            zipfile.ZipFile,
            "infolist",
            side_effect=AssertionError("enumerated before global budget check"),
        ):
            with self.assertRaisesRegex(ScanDataError, "SCA001_ARCHIVE_INVALID"):
                list(archive_members(data, policy["limits"], budget))

        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with mock.patch.object(
            tarfile,
            "open",
            side_effect=AssertionError("enumerated before global budget check"),
        ):
            with self.assertRaisesRegex(ScanDataError, "SCA001_ARCHIVE_INVALID"):
                list(archive_members(tar_output.getvalue(), policy["limits"], budget))

    def test_work_budget_is_checked_before_archive_library_enumeration(self) -> None:
        policy = policy_template()
        zip_data = self.zip_bytes("fixture.txt", b"ordinary")
        zip_budget = WorkBudget(policy["limits"])
        zip_budget.work_bytes = policy["limits"]["max_total_bytes"]
        with mock.patch.object(
            zipfile,
            "ZipFile",
            side_effect=AssertionError("enumerated before global work check"),
        ):
            with self.assertRaisesRegex(ScanDataError, "SCN005_BUDGET_EXCEEDED"):
                list(archive_members(zip_data, policy["limits"], zip_budget))

        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w:") as archive:
            info = tarfile.TarInfo("fixture.txt")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        tar_budget = WorkBudget(policy["limits"])
        tar_budget.work_bytes = policy["limits"]["max_total_bytes"]
        with mock.patch.object(
            tarfile,
            "open",
            side_effect=AssertionError("enumerated before global work check"),
        ):
            with self.assertRaisesRegex(ScanDataError, "SCN005_BUDGET_EXCEEDED"):
                list(
                    archive_members(tar_output.getvalue(), policy["limits"], tar_budget)
                )


class ContentAllowlistTests(unittest.TestCase):
    def test_digest_and_actual_occurrence_count_are_both_exact(self) -> None:
        path = "fixture.txt"
        data = (basic() + " " + basic("dTpx")).encode()
        hits = scan_content(data.decode(), 10)
        entry: dict[str, Any] = {
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "matches": {"SCC003_AUTH_VALUE": 2},
        }
        filtered, allowed, findings = apply_content_allowlist(
            path, data, hits, {path: entry}, enforce_stale=True
        )
        self.assertEqual((filtered, allowed, findings), ([], True, []))

        changed_count = copy.deepcopy(entry)
        changed_count["matches"]["SCC003_AUTH_VALUE"] = 1
        filtered, allowed, findings = apply_content_allowlist(
            path, data, hits, {path: changed_count}, enforce_stale=True
        )
        self.assertEqual(filtered, hits)
        self.assertFalse(allowed)
        self.assertEqual(findings, [Finding(path, 0, "SCN009_STALE_ALLOWLIST")])

        filtered, allowed, findings = apply_content_allowlist(
            path, data + b"x", hits, {path: entry}, enforce_stale=True
        )
        self.assertEqual(filtered, hits)
        self.assertFalse(allowed)
        self.assertEqual(findings, [Finding(path, 0, "SCN009_STALE_ALLOWLIST")])


class StructuralExceptionTests(unittest.TestCase):
    def test_exception_is_exact_to_path_schema_field_and_shape(self) -> None:
        entry: dict[str, Any] = {
            "path": "fixture.json",
            "document_schema": "example.contract.v1",
            "field_path": "$.credential",
            "validator": "caller_credential_ref",
            "owner": "test",
            "reason": "exact closed reference",
            "expires_on": "2099-01-01",
            "scanner_version": "1.0.0",
        }
        exact = {
            "schema_version": "example.contract.v1",
            "credential": {"$ref": "#/components/schemas/CallerCredential"},
        }
        exact_data = json.dumps(exact).encode()
        entry["occurrences"] = 1
        entry["sha256"] = hashlib.sha256(exact_data).hexdigest()
        policy = policy_template()
        policy["structural_exceptions"] = [entry]
        self.assertEqual(
            scan_explicit("fixture.json", exact_data, policy=policy),
            [],
        )

        wrong_shape = copy.deepcopy(exact)
        wrong_shape["credential"] = {"type": "string"}
        self.assertIn(
            "SCF004_INVALID_EXCEPTION",
            codes(
                scan_explicit(
                    "fixture.json", json.dumps(wrong_shape).encode(), policy=policy
                )
            ),
        )

        wrong_path_policy = copy.deepcopy(policy)
        wrong_path_policy["structural_exceptions"][0]["field_path"] = "$.other"
        self.assertIn(
            "SCF001_SECRET_FIELD",
            codes(
                scan_explicit(
                    "fixture.json",
                    json.dumps(exact).encode(),
                    policy=wrong_path_policy,
                )
            ),
        )

    def test_expired_production_exception_invalidates_policy(self) -> None:
        production, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(findings, [])
        assert production is not None
        expired = copy.deepcopy(production)
        expired["structural_exceptions"][0]["expires_on"] = "2020-01-01"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            write_file(root, "policy.json", json.dumps(expired).encode())
            loaded, policy_findings = load_policy(
                root, "policy.json", today=dt.date(2026, 7, 26)
            )
        self.assertIsNone(loaded)
        self.assertEqual(codes(policy_findings), ["SCN001_POLICY_INVALID"])


class OwnerDigestTests(unittest.TestCase):
    def production_policy(self) -> dict[str, Any]:
        policy, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(findings, [])
        assert policy is not None
        return policy

    def test_owner_registry_is_digest_pinned_without_copied_validators(self) -> None:
        policy = self.production_policy()
        actual_owner_documents = {
            entry["path"]: (entry["schema_version"], entry["sha256"])
            for entry in policy["owner_schema_documents"]
        }
        actual_symbolic = {
            entry["path"]: entry["sha256"] for entry in policy["symbolic_fixtures"]
        }
        self.assertEqual(actual_owner_documents, EXPECTED_OWNER_DOCUMENTS)
        self.assertEqual(actual_symbolic, EXPECTED_SYMBOLIC_FIXTURES)
        for entry in policy["owner_schema_documents"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("validator", entry)
        for entry in policy["symbolic_fixtures"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("validator", entry)

    def test_legal_owner_maxima_pass_exact_digest(self) -> None:
        policy = self.production_policy()
        paths = [
            "crates/splendor-types/tests/fixtures/secrets/v2/authorization-v2-legal-maximum.json",
            "crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-legal-maximum.json",
        ]
        findings, _stats = scan_repository(REPO_ROOT, policy, explicit_paths=paths)
        self.assertEqual(findings, [])

    def test_every_reproduced_owner_semantic_mutation_fails_exact_digest(self) -> None:
        fixtures: list[tuple[str, Callable[[dict[str, Any]], None]]] = []

        def required_false(value: dict[str, Any]) -> None:
            value["required"] = False

        def revision_over_cap(value: dict[str, Any]) -> None:
            value["secret_ref_revision"] = 9_007_199_254_740_992

        def zero_max_uses(value: dict[str, Any]) -> None:
            value["lease_policy"]["max_uses"] = 0

        def reversed_time(value: dict[str, Any]) -> None:
            value["disabled_at"] = "2020-01-01T00:00:00.000000Z"

        def invalid_destination(value: dict[str, Any]) -> None:
            value["allowed_credential_bindings"][0]["destination_schema"] = "printable"

        def profile_mismatch(value: dict[str, Any]) -> None:
            value["allowed_credential_bindings"][0]["delivery_exposure_profile"] = (
                "material_exposed"
            )

        def duplicate_binding(value: dict[str, Any]) -> None:
            value["allowed_credential_bindings"].append(
                copy.deepcopy(value["allowed_credential_bindings"][0])
            )

        fixtures.append(
            (
                "crates/splendor-types/tests/fixtures/secrets/v1a/secret-use-requirement.json",
                required_false,
            )
        )
        ref_path = "crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-same-revision.json"
        fixtures.extend(
            (ref_path, mutation)
            for mutation in (
                revision_over_cap,
                zero_max_uses,
                reversed_time,
                invalid_destination,
                profile_mismatch,
                duplicate_binding,
            )
        )
        production = self.production_policy()
        owner_by_path = {
            entry["path"]: entry for entry in production["owner_schema_documents"]
        }
        for path, mutation in fixtures:
            with self.subTest(path=path, mutation=mutation.__name__):
                value = json.loads((REPO_ROOT / path).read_text())
                mutation(value)
                data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
                policy = policy_template()
                policy["owner_schema_documents"] = [owner_by_path[path]]
                findings = scan_explicit(path, data, policy=policy)
                self.assertIn("SCF003_INVALID_SAFE_RECORD", codes(findings))

    def test_empty_conformance_inventory_fails_pinned_digest(self) -> None:
        path = "conformance/0.2/c03-foundation/v1/positive/cases.json"
        value = json.loads((REPO_ROOT / path).read_text())
        value["cases"] = []
        value["case_count"] = 0
        data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        production = self.production_policy()
        entry = next(
            item for item in production["symbolic_fixtures"] if item["path"] == path
        )
        policy = policy_template()
        policy["symbolic_fixtures"] = [entry]
        self.assertIn(
            "SCF003_INVALID_SAFE_RECORD",
            codes(scan_explicit(path, data, policy=policy)),
        )

    def test_conformance_inventory_counts_and_identities_are_nonempty_and_exact(
        self,
    ) -> None:
        expected = {"positive": 55, "negative": 68}
        for polarity, count in expected.items():
            path = f"conformance/0.2/c03-foundation/v1/{polarity}/cases.json"
            value = json.loads((REPO_ROOT / path).read_text())
            case_ids = [case["case_id"] for case in value["cases"]]
            with self.subTest(polarity=polarity):
                self.assertEqual(value["polarity"], polarity)
                self.assertEqual(value["case_count"], count)
                self.assertEqual(len(case_ids), count)
                self.assertEqual(len(set(case_ids)), count)


class WorkflowAndPolicyContractTests(unittest.TestCase):
    def test_production_workflows_have_exact_scanner_dependency_chain(self) -> None:
        workflow_root = REPO_ROOT / ".github/workflows"
        actual_workflows = {
            path.relative_to(REPO_ROOT).as_posix()
            for pattern in ("*.yml", "*.yaml")
            for path in workflow_root.glob(pattern)
        }
        self.assertEqual(actual_workflows, set(REQUIRED_WORKFLOWS))
        expected_jobs = {
            ".github/workflows/ci.yml": {
                "secret-contracts",
                "rust",
                "python",
                "typescript",
                "docker",
            },
            ".github/workflows/docker-image.yml": {
                "secret-contracts",
                "smoke",
                "verify-smoke",
                "publish-platform",
                "publish-manifest",
            },
        }
        for path in REQUIRED_WORKFLOWS:
            with self.subTest(path=path):
                text = (REPO_ROOT / path).read_text()
                self.assertTrue(validate_workflow_text(path, text))
                jobs = set(
                    match.group(1)
                    for match in re.finditer(
                        r"(?m)^  ([A-Za-z0-9_-]+):\s*$", text.split("jobs:", 1)[1]
                    )
                )
                self.assertEqual(jobs, expected_jobs[path])
                self.assertIsNone(re.search(r"\bGITHUB_REF\b", text))
                self.assertNotIn("FETCH_HEAD", text)
                checkout_count = text.count(
                    'git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"'
                )
                self.assertEqual(checkout_count, len(expected_jobs[path]))
                self.assertEqual(
                    text.count('test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"'),
                    len(expected_jobs[path]),
                )

    def test_workflow_command_or_dependency_removal_fails(self) -> None:
        ci_path, docker_path = REQUIRED_WORKFLOWS
        ci = (REPO_ROOT / ci_path).read_text()
        docker = (REPO_ROOT / docker_path).read_text()
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    "/usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test",
                    "true",
                    1,
                ),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    "    timeout-minutes: 5\n",
                    "    timeout-minutes: 5\n    continue-on-error: true\n",
                    1,
                ),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    "  rust:\n    needs: secret-contracts\n",
                    "  rust:\n    needs: secret-contracts\n    if: always()\n",
                    1,
                ),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace("    timeout-minutes: 5", "    timeout-minutes: 6", 1),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    '          env -i HOME="${sandbox}" PATH="/usr/bin:/bin" /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test\n',
                    '          set +e\n          env -i HOME="${sandbox}" PATH="/usr/bin:/bin" /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test\n',
                    1,
                ),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                docker_path, docker.replace("    needs: secret-contracts\n", "", 1)
            )
        )
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    "/usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test",
                    "# /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test",
                    1,
                ),
            )
        )

    def test_workflow_default_shell_path_and_failure_swallowing_mutations_fail(
        self,
    ) -> None:
        ci_path = REQUIRED_WORKFLOWS[0]
        ci = (REPO_ROOT / ci_path).read_text()
        mutations = (
            ci.replace(
                "jobs:\n",
                "defaults:\n  run:\n    shell: bash --noprofile --norc {0}; exit 0\njobs:\n",
                1,
            ),
            ci.replace(
                "    steps:\n", "    env:\n      PATH: /tmp/hijack\n    steps:\n", 1
            ),
            ci.replace(
                "      - name: C03 secret contract and fixture guard\n",
                "      - name: C03 secret contract and fixture guard\n        shell: bash {0}\n",
                1,
            ),
            ci.replace(
                "      - name: C03 secret contract and fixture guard\n",
                "      - name: C03 secret contract and fixture guard\n        continue-on-error: true\n",
                1,
            ),
            ci.replace(
                '          /usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "${GITHUB_SHA}"\n',
                '          /usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "${GITHUB_SHA}" || true\n',
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=hashlib.sha256(mutation.encode()).hexdigest()):
                self.assertFalse(validate_workflow_text(ci_path, mutation))

    def test_workflow_quoted_unknown_and_alternate_ref_jobs_fail(self) -> None:
        ci_path = REQUIRED_WORKFLOWS[0]
        ci = (REPO_ROOT / ci_path).read_text()
        quoted = ci.replace("  rust:\n", "  'rust':\n", 1)
        unknown = (
            ci
            + "\n  shadow-build:\n    needs: secret-contracts\n    runs-on: ubuntu-latest\n"
        )
        alternate = ci.replace(
            'git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"',
            'git fetch --no-tags --depth=1 origin "refs/heads/main"',
            1,
        )
        for mutation in (quoted, unknown, alternate):
            with self.subTest(mutation=hashlib.sha256(mutation.encode()).hexdigest()):
                self.assertFalse(validate_workflow_text(ci_path, mutation))

    def test_workflow_trigger_and_path_filter_bypass_mutations_fail(self) -> None:
        ci_path = REQUIRED_WORKFLOWS[0]
        ci = (REPO_ROOT / ci_path).read_text()
        mutations = (
            ci.replace(
                "  pull_request:\n", "  pull_request:\n    paths-ignore: ['**']\n", 1
            ),
            ci.replace("  push:\n", "  push:\n    branches: [main]\n", 1),
            ci.replace("  pull_request:\n", "", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=hashlib.sha256(mutation.encode()).hexdigest()):
                self.assertFalse(validate_workflow_text(ci_path, mutation))

    def test_every_build_and_publish_job_has_direct_scanner_dependency(self) -> None:
        docker_path = REQUIRED_WORKFLOWS[1]
        docker = (REPO_ROOT / docker_path).read_text()
        self.assertTrue(validate_workflow_text(docker_path, docker))
        for job in ("smoke", "verify-smoke", "publish-platform", "publish-manifest"):
            block = re.search(
                rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                docker,
            )
            self.assertIsNotNone(block)
            assert block is not None
            self.assertRegex(block.group("body"), r"(?m)^    needs:.*secret-contracts")

    def test_production_roots_and_source_extensions_are_independently_pinned(
        self,
    ) -> None:
        policy, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(findings, [])
        assert policy is not None
        required_roots = {
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
                {
                    ".json": "json",
                    ".md": "markdown",
                },
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
                    ".cjs": "typescript_source",
                    ".gitkeep": "empty",
                    ".js": "typescript_source",
                    ".json": "json",
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
                {
                    ".json": "json",
                    ".md": "markdown",
                    ".yaml": "yaml",
                    ".yml": "yaml",
                },
            ),
        }
        self.assertEqual(
            {
                entry["id"]: (entry["path"], entry["formats"])
                for entry in policy["governed_roots"]
            },
            required_roots,
        )
        self.assertTrue({".py", ".ts", ".js", ".mjs"}.issubset(SOURCE_SUFFIXES))

    def test_governed_root_path_or_format_drift_invalidates_policy(self) -> None:
        policy, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 26),
        )
        self.assertEqual(findings, [])
        assert policy is not None
        path_drift = copy.deepcopy(policy)
        path_drift["governed_roots"][0]["path"] = "other/path"
        format_drift = copy.deepcopy(policy)
        format_drift["governed_roots"][0]["formats"] = {".yaml": "yaml"}
        for candidate in (path_drift, format_drift):
            with self.subTest(candidate=candidate["governed_roots"][0]):
                self.assertEqual(
                    codes(validate_policy(candidate, today=dt.date(2026, 7, 26))),
                    ["SCN001_POLICY_INVALID"],
                )


class FailureAndDiagnosticTests(unittest.TestCase):
    def test_credential_capable_path_and_member_segments_are_redacted(self) -> None:
        marker = "token=" + ("A1" * 12)
        rendered = Finding(
            f"safe/{marker}/fixture.zip!nested/{marker}.json",
            7,
            "SCC003_AUTH_VALUE",
        ).render()
        self.assertNotIn(marker, rendered)
        self.assertIn("safe/", rendered)
        self.assertIn("fixture.zip!nested/", rendered)
        for candidate in (
            "Bearer%20A1b2_credential",
            "Bearer\u00a0A1b2_credential",
            "user:password@example.invalid",
            provider_token(),
            "tokens",
            "client-secrets.json",
        ):
            with self.subTest(candidate=candidate):
                rendered = Finding(
                    f"safe/{candidate}/fixture.json", 1, "SCC003_AUTH_VALUE"
                ).render()
                self.assertNotIn(candidate, rendered)
        opaque = "Q7m_Z2p-L9x_V4c-N8r_K1t-" + "H6w_J3s-P5y_D0f-M2q_R8u"
        rendered = Finding(
            f"safe/{opaque}/fixture.json", 1, "SCC004_HIGH_ENTROPY"
        ).render()
        self.assertNotIn(opaque, rendered)

    def test_percent_encoded_credential_path_segment_is_redacted(self) -> None:
        candidate = "Bearer%20A1b2_credential"
        rendered = Finding(
            f"safe/{candidate}/fixture.json", 1, "SCC003_AUTH_VALUE"
        ).render()
        self.assertNotIn(candidate, rendered)

    def test_surrogate_policy_path_is_rejected_without_exception(self) -> None:
        self.assertFalse(safe_policy_path("fixture-\ud800.json"))

    def test_directory_is_rejected_as_nonregular(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "entry").mkdir()
            findings, _stats = scan_repository(
                root, policy_template(), explicit_paths=["entry"]
            )
            self.assertIn("SCN003_PATH_AMBIGUOUS", codes(findings))

    def test_missing_symlink_and_oversized_paths_fail_with_fixed_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            missing, _stats = scan_repository(
                root, policy_template(), explicit_paths=["missing.txt"]
            )
            self.assertEqual(codes(missing), ["SCN002_PATH_UNAVAILABLE"])

            write_file(root, "target.txt", b"ordinary")
            try:
                (root / "link.txt").symlink_to(root / "target.txt")
            except (OSError, NotImplementedError):
                pass
            else:
                linked, _stats = scan_repository(
                    root, policy_template(), explicit_paths=["link.txt"]
                )
                self.assertEqual(codes(linked), ["SCN003_PATH_AMBIGUOUS"])

            write_file(root, "large.txt", b"ab")
            policy = policy_template()
            policy["limits"]["max_file_bytes"] = 1
            oversized, _stats = scan_repository(
                root, policy, explicit_paths=["large.txt"]
            )
            self.assertEqual(codes(oversized), ["SCN005_BUDGET_EXCEEDED"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unsupported")
    def test_fifo_is_opened_nonblocking_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            os.mkfifo(root / "entry")
            findings, _stats = scan_repository(
                root, policy_template(), explicit_paths=["entry"]
            )
            self.assertIn("SCN003_PATH_AMBIGUOUS", codes(findings))

    def test_cumulative_decoded_work_budget_fails_closed(self) -> None:
        policy = policy_template()
        data = json.dumps({"items": ["ordinary"] * 20}).encode()
        policy["limits"]["max_total_bytes"] = len(data) + 20
        findings = scan_explicit("fixture.json", data, policy=policy)
        self.assertIn("SCN005_BUDGET_EXCEEDED", codes(findings))

    def test_safe_diagnostic_never_contains_candidate(self) -> None:
        candidate = bearer("A1_" * 8)
        rendered = Finding("fixture.txt", 1, "SCC003_AUTH_VALUE").render()
        self.assertNotIn(candidate, rendered)
        self.assertEqual(
            rendered,
            "fixture.txt:1: SCC003_AUTH_VALUE: raw authorization credential signature is forbidden",
        )

    def test_redacted_diagnostic_uses_one_fixed_marker_without_hash_oracle(
        self,
    ) -> None:
        first = "token=" + ("A1" * 12)
        second = "token=" + ("B2" * 12)
        rendered = [
            Finding(f"safe/{candidate}/fixture.json", 1, "SCC003_AUTH_VALUE").render()
            for candidate in (first, second)
        ]
        self.assertEqual(rendered[0], rendered[1])
        self.assertIn("safe/<redacted>/fixture.json", rendered[0])
        self.assertNotRegex(rendered[0], r"<redacted-[0-9a-f]+>")

    def test_ancestor_symlink_swap_during_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inside = root / "inside"
            outside = root / "outside"
            inside.mkdir()
            outside.mkdir()
            (inside / "fixture.txt").write_bytes(b"inside")
            (outside / "fixture.txt").write_bytes(b"outside")
            original_open = os.open
            swapped = False

            def racing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
                nonlocal swapped
                name = os.fspath(path)
                if not swapped and str(name).endswith("fixture.txt"):
                    swapped = True
                    inside.rename(root / "inside-old")
                    try:
                        inside.symlink_to(outside, target_is_directory=True)
                    except OSError:
                        (root / "inside-old").rename(inside)
                        raise unittest.SkipTest("directory symlinks unavailable")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch(
                "secret_contract_scanner.io_utils.os.open", side_effect=racing_open
            ):
                with self.assertRaisesRegex(ScanDataError, "SCN003_PATH_AMBIGUOUS"):
                    safe_read_file(root, "inside/fixture.txt", 1024)

    def test_file_identity_swap_during_read_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "fixture.txt").write_bytes(b"first")
            (root / "replacement.txt").write_bytes(b"second")
            original_read = os.read
            swapped = False

            def racing_read(descriptor: int, amount: int) -> bytes:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    (root / "fixture.txt").unlink()
                    (root / "replacement.txt").rename(root / "fixture.txt")
                return original_read(descriptor, amount)

            with mock.patch(
                "secret_contract_scanner.io_utils.os.read", side_effect=racing_read
            ):
                with self.assertRaisesRegex(ScanDataError, "SCN003_PATH_AMBIGUOUS"):
                    safe_read_file(root, "fixture.txt", 1024)


class SelfTestManifestTests(unittest.TestCase):
    def test_self_test_cannot_pass_zero_discovered_cases(self) -> None:
        empty = unittest.TestSuite()
        with mock.patch.object(
            unittest.defaultTestLoader, "discover", return_value=empty
        ), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(run_self_test(), 1)

    def test_self_test_cannot_pass_a_missing_case(self) -> None:
        incomplete = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with mock.patch.object(
            unittest.defaultTestLoader, "discover", return_value=incomplete
        ), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(run_self_test(), 1)


if __name__ == "__main__":
    unittest.main()
