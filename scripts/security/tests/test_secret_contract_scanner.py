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
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from typing import Any, Callable

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
from secret_contract_scanner.policy import load_policy  # noqa: E402
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
          python3 scripts/security/check-secret-contracts.py --self-test
          python3 scripts/security/check-secret-contracts.py
"""


def bearer(value: str = "abc") -> str:
    return "Bea" + "rer " + value


def basic(value: str = "dTpw") -> str:
    return "Bas" + "ic " + value


def provider_token() -> str:
    return "gh" + "p_" + ("A1" * 12)


def credential_url() -> str:
    return "https://" + "fixture-user:fixture-pass" + "@example.invalid/path"


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
            "max_archive_members": 64,
            "max_archive_unpacked_bytes": 1_048_576,
            "max_findings": 256,
        },
        "governed_roots": [],
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
            findings, _stats = scan_repository(root, policy_template())
            affected = {
                finding.path
                for finding in findings
                if finding.code == "SCC002_PROVIDER_TOKEN"
            }
            self.assertEqual(affected, {"fixture.json", "fixture.yaml"})


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

    def test_safe_typed_secret_reference_is_not_rejected(self) -> None:
        data = b"export interface Request {\n  secretRef: SecretRefV2;\n}\n"
        self.assertNotIn(
            "SCF005_SOURCE_FIELD", codes(scan_explicit("fixture.ts", data))
        )

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
            findings, _stats = scan_repository(root, policy_template())
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
            ],
        )
        self.assertFalse(
            {"SCF004_INVALID_EXCEPTION", "SCF005_SOURCE_FIELD"} & set(codes(findings))
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
        entry = {
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
        policy = policy_template()
        policy["structural_exceptions"] = [entry]
        self.assertEqual(
            scan_explicit("fixture.json", json.dumps(exact).encode(), policy=policy),
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

    def test_workflow_command_or_dependency_removal_fails(self) -> None:
        ci_path, docker_path = REQUIRED_WORKFLOWS
        ci = (REPO_ROOT / ci_path).read_text()
        docker = (REPO_ROOT / docker_path).read_text()
        self.assertFalse(
            validate_workflow_text(
                ci_path,
                ci.replace(
                    "python3 scripts/security/check-secret-contracts.py --self-test",
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
                    "          python3 scripts/security/check-secret-contracts.py --self-test\n",
                    "          set +e\n          python3 scripts/security/check-secret-contracts.py --self-test\n",
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
                    "python3 scripts/security/check-secret-contracts.py --self-test",
                    "# python3 scripts/security/check-secret-contracts.py --self-test",
                    1,
                ),
            )
        )

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
            "c03-canonical-fixtures": {".json": "json"},
            "driver-credential-sink-fixture": {".json": "json"},
            "c03-foundation-conformance": {
                ".json": "json",
                ".md": "markdown",
            },
            "stable-adapter-manifests": {".json": "json"},
            "runtime-daemon-openapi": {".yaml": "yaml"},
            "repository-examples": {
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
            "python-sdk-external-surface": {".py": "python_source"},
            "typescript-types-external-surface": {".ts": "typescript_source"},
            "typescript-client-external-surface": {".ts": "typescript_source"},
        }
        self.assertEqual(
            {entry["id"]: entry["formats"] for entry in policy["governed_roots"]},
            required_roots,
        )
        self.assertTrue({".py", ".ts", ".js", ".mjs"}.issubset(SOURCE_SUFFIXES))


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


if __name__ == "__main__":
    unittest.main()
