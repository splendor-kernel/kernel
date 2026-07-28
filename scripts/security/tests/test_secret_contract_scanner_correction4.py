from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from typing import Any
from unittest import mock

SECURITY_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SECURITY_ROOT.parents[1]
sys.path.insert(0, str(SECURITY_ROOT))

from secret_contract_scanner.archives import (  # noqa: E402
    detect_archive_kind,
)
from secret_contract_scanner.engine import scan_repository  # noqa: E402
from secret_contract_scanner.model import (  # noqa: E402
    Finding,
    ScanDataError,
    WorkBudget,
)
from secret_contract_scanner.policy import load_policy, validate_policy  # noqa: E402
from secret_contract_scanner.self_test import (  # noqa: E402
    _test_module_inventory_valid,
)
from secret_contract_scanner.structured import (  # noqa: E402
    parse_yaml_document,
)
import secret_contract_scanner.workflows as workflow_contract  # noqa: E402
from secret_contract_scanner.workflows import (  # noqa: E402
    REQUIRED_WORKFLOWS,
    validate_workflow_text,
)


def _policy() -> dict[str, Any]:
    return {
        "schema_version": "splendor.secret_field_scan.v1",
        "scanner_version": "1.0.0",
        "owner": "SECR-006",
        "reviewed_on": "2026-07-28",
        "limits": {
            "max_files": 512,
            "max_file_bytes": 1_048_576,
            "max_total_bytes": 32_000_000,
            "max_structure_depth": 64,
            "max_structure_nodes": 200_000,
            "max_object_members": 4_096,
            "max_array_items": 4_096,
            "max_string_bytes": 524_288,
            "max_markdown_fences": 128,
            "max_parser_operations": 16_000_000,
            "max_archive_members": 256,
            "max_archive_unpacked_bytes": 8_388_608,
            "max_findings": 256,
        },
        "governed_roots": [],
        "source_owner_exports": [],
        "owner_schema_documents": [],
        "structural_exceptions": [],
        "symbolic_fixtures": [],
        "content_allowlist": [],
    }


def _write(root: pathlib.Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _normal_scan(
    files: dict[str, bytes], policy: dict[str, Any] | None = None
) -> tuple[list[Finding], Any]:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for relative, data in files.items():
            _write(root, relative, data)
        return scan_repository(root, policy or _policy())


def _scan_explicit(
    path: str, data: bytes, policy: dict[str, Any] | None = None
) -> list[Finding]:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        _write(root, path, data)
        findings, _stats = scan_repository(
            root, policy or _policy(), explicit_paths=[path]
        )
        return findings


def _codes(findings: list[Finding]) -> set[str]:
    return {finding.code for finding in findings}


def _by_path(findings: list[Finding]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for finding in findings:
        result.setdefault(finding.path, set()).add(finding.code)
    return result


def _root(identifier: str, path: str, formats: dict[str, str]) -> dict[str, object]:
    return {
        "id": identifier,
        "path": path,
        "formats": formats,
        "owner": "correction-4 regression",
        "reason": "exercise normal repository mode",
    }


def _signed_tar(member_name: bytes, payload: bytes, *, ustar: bool) -> bytes:
    header = bytearray(512)
    header[: len(member_name)] = member_name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{len(payload):011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156:157] = b"0"
    if ustar:
        header[257:263] = b"ustar\0"
        header[263:265] = b"00"
    signed = sum(byte if byte < 128 else byte - 256 for byte in header)
    header[148:156] = f"{signed:06o}\0 ".encode("ascii")
    padding = b"\0" * ((512 - len(payload) % 512) % 512)
    return bytes(header) + payload + padding + (b"\0" * 1024)


class ImmutableScanAndExceptionTests(unittest.TestCase):
    def test_git_object_scan_ignores_import_time_checkout_rewrite(self) -> None:
        from secret_contract_scanner.io_utils import GitObjectRepository

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "scanner@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Scanner Fixture"],
                cwd=root,
                check=True,
            )
            _write(root, "docs/victim.txt", b"PASSWORD=abc\n")
            _write(
                root,
                "scripts/security/tests/test_rewriter.py",
                b"from pathlib import Path\nPath('docs/victim.txt').write_text('safe\\n')\n",
            )
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            subprocess.run(
                [sys.executable, "scripts/security/tests/test_rewriter.py"],
                cwd=root,
                check=True,
            )
            self.assertEqual((root / "docs/victim.txt").read_text(), "safe\n")
            with GitObjectRepository(root, revision) as repository:
                findings, _stats = scan_repository(repository, _policy())
                self.assertEqual(
                    repository.list_files(max_files=0)[1][0].code,
                    "SCN005_BUDGET_EXCEEDED",
                )
                with self.assertRaisesRegex(ScanDataError, "SCN002_PATH_UNAVAILABLE"):
                    repository.read_file("missing.txt", 128)
                with self.assertRaisesRegex(ScanDataError, "SCN003_PATH_AMBIGUOUS"):
                    repository.read_file("../victim.txt", 128)
                with self.assertRaisesRegex(ScanDataError, "SCN005_BUDGET_EXCEEDED"):
                    repository.read_file("docs/victim.txt", 1)
            self.assertIn(
                ("docs/victim.txt", "SCC003_AUTH_VALUE"),
                {(finding.path, finding.code) for finding in findings},
            )
            with self.assertRaisesRegex(ScanDataError, "SCN010_REPOSITORY_UNAVAILABLE"):
                GitObjectRepository(root, "not-a-full-object-id")

            empty = root / "empty"
            empty.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=empty, check=True)
            subprocess.run(
                ["git", "config", "user.email", "scanner@example.invalid"],
                cwd=empty,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Scanner Fixture"],
                cwd=empty,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "--allow-empty", "-qm", "empty"],
                cwd=empty,
                check=True,
            )
            empty_revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=empty, text=True
            ).strip()
            with self.assertRaisesRegex(ScanDataError, "SCN010_REPOSITORY_UNAVAILABLE"):
                GitObjectRepository(empty, empty_revision)

    def test_candidate_cannot_add_an_arbitrary_matching_content_exception(self) -> None:
        policy, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 28),
        )
        self.assertEqual(findings, [])
        assert policy is not None
        candidates: list[tuple[str, dict[str, Any]]] = []

        def candidate(label: str) -> dict[str, Any]:
            value = copy.deepcopy(policy)
            candidates.append((label, value))
            return value

        value = candidate("candidate-authored content suppression")
        value["content_allowlist"].append(
            {
                "path": "docs/candidate.txt",
                "sha256": hashlib.sha256(b"PASSWORD=abc\n").hexdigest(),
                "matches": {"SCC003_AUTH_VALUE": 1},
                "owner": "candidate",
                "reason": "candidate-authored suppression",
                "expires_on": "2027-07-28",
                "scanner_version": "1.0.0",
            }
        )

        value = candidate("unknown top-level field")
        value["candidate_override"] = True
        value = candidate("candidate schema")
        value["schema_version"] = "candidate.v1"
        value = candidate("blank owner")
        value["owner"] = ""
        value = candidate("invalid review date")
        value["reviewed_on"] = "2026-02-30"
        value = candidate("missing limit")
        value["limits"].pop("max_findings")
        value = candidate("boolean limit")
        value["limits"]["max_findings"] = True
        for name in (
            "max_file_bytes",
            "max_total_bytes",
            "max_files",
            "max_findings",
            "max_archive_members",
            "max_archive_unpacked_bytes",
            "max_parser_operations",
            "max_structure_depth",
            "max_structure_nodes",
        ):
            value = candidate(f"unbounded {name}")
            value["limits"][name] = 10**20
        value = candidate("total smaller than one file")
        value["limits"]["max_total_bytes"] = 1

        value = candidate("empty governed roots")
        value["governed_roots"] = []
        value = candidate("governed root extra field")
        value["governed_roots"][0]["candidate_override"] = True
        value = candidate("unsafe governed root path")
        value["governed_roots"][0]["path"] = "../candidate"
        value = candidate("blank governed root reason")
        value["governed_roots"][0]["reason"] = ""
        value = candidate("duplicate governed root")
        value["governed_roots"].append(copy.deepcopy(value["governed_roots"][0]))
        value = candidate("empty governed formats")
        value["governed_roots"][0]["formats"] = {}
        value = candidate("invalid governed suffix")
        value["governed_roots"][0]["formats"] = {"ts": "typescript_source"}
        value = candidate("incomplete governed inventory")
        value["governed_roots"].pop()

        value = candidate("invalid source-owner collection")
        value["source_owner_exports"] = {}
        value = candidate("source-owner extra field")
        value["source_owner_exports"][0]["candidate_override"] = True
        value = candidate("source-owner language")
        value["source_owner_exports"][0]["language"] = "candidate"
        value = candidate("source-owner duplicate export")
        value["source_owner_exports"][0]["exports"].append(
            value["source_owner_exports"][0]["exports"][0]
        )
        value = candidate("incomplete source-owner inventory")
        value["source_owner_exports"] = []

        value = candidate("empty owner documents")
        value["owner_schema_documents"] = []
        value = candidate("owner document extra field")
        value["owner_schema_documents"][0]["candidate_override"] = True
        value = candidate("owner document digest")
        value["owner_schema_documents"][0]["sha256"] = "candidate"

        value = candidate("invalid structural exception collection")
        value["structural_exceptions"] = {}
        value = candidate("unsafe structural exception path")
        value["structural_exceptions"][0]["path"] = "../candidate"
        value = candidate("invalid structural exception expiry")
        value["structural_exceptions"][0]["expires_on"] = "2026-02-30"

        value = candidate("empty symbolic fixture inventory")
        value["symbolic_fixtures"] = []
        value = candidate("unsafe symbolic fixture path")
        value["symbolic_fixtures"][0]["path"] = "../candidate"
        value = candidate("expired symbolic fixture")
        value["symbolic_fixtures"][0]["expires_on"] = "2026-07-27"

        value = candidate("invalid content allowlist collection")
        value["content_allowlist"] = {}
        value = candidate("unsafe content allowlist path")
        value["content_allowlist"][0]["path"] = "../candidate"
        value = candidate("invalid content allowlist match")
        value["content_allowlist"][0]["matches"] = {"CANDIDATE": 1}

        for label, value in candidates:
            with self.subTest(label=label):
                self.assertEqual(
                    _codes(validate_policy(value, today=dt.date(2026, 7, 28))),
                    {"SCN001_POLICY_INVALID"},
                )


class ContentAndRootDiscoveryTests(unittest.TestCase):
    def test_suffixless_yaml_numeric_json_and_toml_inline_values_fail(self) -> None:
        files = {
            "payload.bin": b"password: abc\n",
            "numeric.json": b'{"password":1234}',
            "settings.toml": b'credentials = { key = "abc" }\n',
            "suffixless": b'credentials = { password = "abc" }\n',
        }
        findings, _stats = _normal_scan(files)
        by_path = _by_path(findings)
        for path in files:
            with self.subTest(path=path):
                self.assertTrue(
                    by_path.get(path, set())
                    & {"SCF001_SECRET_FIELD", "SCC003_AUTH_VALUE"}
                )

    def test_openapi_marker_and_schema_property_maps_are_content_discovered(
        self,
    ) -> None:
        documents = {
            "specs/api.yaml": b"""openapi: 3.1.0
info: {title: Fixture, version: 1.0.0}
paths: {}
components:
  schemas:
    Request:
      type: object
      properties:
        password: {type: string}
""",
            "openapi/pattern.yaml": b"""openapi: 3.1.0
info: {title: Fixture, version: 1.0.0}
paths: {}
components:
  schemas:
    Request:
      type: object
      patternProperties:
        '^password$': {type: string}
""",
            "openapi/composed.json": json.dumps(
                {
                    "openapi": "3.1.0",
                    "info": {"title": "Fixture", "version": "1"},
                    "paths": {},
                    "components": {
                        "schemas": {
                            "Request": {
                                "allOf": [
                                    {
                                        "type": "object",
                                        "properties": {"password": {"type": "string"}},
                                    }
                                ]
                            }
                        }
                    },
                }
            ).encode(),
        }
        findings, _stats = _normal_scan(documents)
        by_path = _by_path(findings)
        for path in documents:
            with self.subTest(path=path):
                self.assertTrue(
                    by_path.get(path, set())
                    & {"SCN004_UNSUPPORTED_FORMAT", "SCF001_SECRET_FIELD"}
                )

    def test_new_adapter_rust_contract_and_control_plane_roots_fail_closed(
        self,
    ) -> None:
        files = {
            "adapters/new-driver/security_driver.py": b"class Request:\n    password: str\n",
            "crates/splendor-types/src/security_unsafe_secret.rs": (
                b"pub struct Request { pub password: String }\n"
            ),
            "tools/control-plane/security_schema.ts": (
                b"export interface Request { password: string; }\n"
            ),
        }
        findings, _stats = _normal_scan(files)
        by_path = _by_path(findings)
        for path in files:
            with self.subTest(path=path):
                self.assertIn("SCN004_UNSUPPORTED_FORMAT", by_path.get(path, set()))


class MarkdownGrammarTests(unittest.TestCase):
    def test_commonmark_tabs_ordered_lists_and_indented_json_are_scanned(self) -> None:
        documents = (
            '>\t```json\n>\t{"password":"abc"}\n>\t```\n',
            '10. item\n\n    ```json\n    {"password":"abc"}\n    ```\n',
            'Example contract:\n\n\t{"password":"abc"}\n',
            'Example contract:\n\n        {"password":"abc"}\n',
            "10. item\n\n    ```yaml\n    agents:\n      - id: worker\n        password: abc\n    ```\n",
        )
        for document in documents:
            with self.subTest(document=document):
                findings = _scan_explicit("fixture.md", document.encode())
                self.assertTrue(
                    _codes(findings) & {"SCF001_SECRET_FIELD", "SCC003_AUTH_VALUE"}
                )


class PythonGrammarTests(unittest.TestCase):
    def test_alias_schema_update_destructuring_comment_and_variadic_forms_fail(
        self,
    ) -> None:
        sources = (
            'from typing import NamedTuple as NT\nRequest = NT("Request", [("password", str)])\n',
            'from pydantic import BaseModel, Field as F\nclass Request(BaseModel):\n    safe: str = F(alias="password")\n',
            "password, ordinary = load()\n",
            "*ordinary, password = load()\n",
            'request.update(password="abc")\n',
            'request.update({"password": "abc"})\n',
            '# PASSWORD=abc\nvalue = "ordinary"\n',
            "from .types import CallerCredential\nclass Request:\n    credential: CallerCredential\n",
        )
        for source in sources:
            with self.subTest(source=source):
                findings = _scan_explicit("fixture.py", source.encode())
                self.assertTrue(
                    _codes(findings) & {"SCF005_SOURCE_FIELD", "SCC003_AUTH_VALUE"}
                )


class TypeScriptGrammarTests(unittest.TestCase):
    def _scan_with_owner(self, source: str) -> list[Finding]:
        policy, findings = load_policy(
            REPO_ROOT,
            "scripts/security/secret-contract-policy.json",
            today=dt.date(2026, 7, 28),
        )
        self.assertEqual(findings, [])
        assert policy is not None
        owner = policy["source_owner_exports"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            _write(root, "fixture.ts", source.encode())
            for key in ("path", "package_path"):
                owner_path = owner[key]
                _write(root, owner_path, (REPO_ROOT / owner_path).read_bytes())
            local = _policy()
            local["source_owner_exports"] = [owner]
            result, _stats = scan_repository(root, local, explicit_paths=["fixture.ts"])
            return result

    def test_regex_unicode_bracket_utility_shadow_and_star_export_forms_fail(
        self,
    ) -> None:
        sources = (
            "const first = /[/*]/;\nexport interface Request { password: string; }\nconst second = /[*/]/;\n",
            'const pass\\u0077ord = "abc";\n',
            'const request: any = {}; request["password"] = "abc";\n',
            'type Request = Pick<External, "password">;\n',
            'export * from "./ordinary";\n',
            'const key = `pass${"word"}`; const request: any = {}; request[key] = "abc";\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(
                    _codes(_scan_explicit("fixture.ts", source.encode()))
                    & {
                        "SCF005_SOURCE_FIELD",
                        "SCC003_AUTH_VALUE",
                        "SCN011_MALFORMED_SOURCE",
                    }
                )
        shadowed = (
            'import type { CallerCredential } from "@splendor/types";\n'
            "export type Request<CallerCredential> = { credential: CallerCredential };\n"
        )
        self.assertIn("SCF005_SOURCE_FIELD", _codes(self._scan_with_owner(shadowed)))


class ConfigGrammarTests(unittest.TestCase):
    def test_shell_docker_make_toml_ini_and_yaml_logical_forms_fail(self) -> None:
        fixtures = {
            "fixture.sh": b"PASSWORD=a\\\nbc\n",
            "fixture.bash": b"PASSWORD=$'abc'\n",
            "Dockerfile.fixture": b"FROM scratch\nENV PASSWORD abc\nARG API_KEY=abc\nRUN PASSWORD=abc command\n",
            "Makefile": b"PASSWORD := abc\nall:\n\tPASSWORD=abc command\n",
            "settings.toml": b'password = [\n  "abc",\n]\n',
            "settings.ini": b"[service]\npassword =\n  abc\n",
            "settings.yaml": b"password: >\n  a\n  bc\n",
        }
        for path, data in fixtures.items():
            with self.subTest(path=path):
                self.assertIn("SCC003_AUTH_VALUE", _codes(_scan_explicit(path, data)))

    def test_invalid_byte_recognized_executable_fails_closed(self) -> None:
        findings = _scan_explicit("fixture.sh", b"# invalid byte: \xff\nPASSWORD=abc\n")
        self.assertTrue(
            _codes(findings) & {"SCN003_PATH_AMBIGUOUS", "SCN011_MALFORMED_SOURCE"}
        )

    def test_realistic_benign_config_forms_remain_accepted(self) -> None:
        fixtures = {
            "Dockerfile": b"ARG RUST_VERSION=1.88\nENV PATH=/usr/local/bin:$PATH\n",
            "Makefile": b"TOKEN_COUNT := 3\nall:\n\t@true\n",
            "settings.toml": b'[auth_policy]\nmode = "strict"\ntoken_endpoint = "https://issuer.example.invalid/token"\n',
            "settings.ini": b"[credentials]\nbackend = vault\nformat = json\n",
        }
        for path, data in fixtures.items():
            with self.subTest(path=path):
                self.assertEqual(_scan_explicit(path, data), [])


class ArchiveAndBudgetTests(unittest.TestCase):
    def test_signed_v7_and_ustar_are_recognized_before_opaque_skip(self) -> None:
        for ustar in (False, True):
            for prefix in (b"", b"x" * 4097):
                with self.subTest(ustar=ustar, prefix=len(prefix)):
                    archive = _signed_tar(
                        b"\xffsafe.bin", b"PASSWORD=abc\n", ustar=ustar
                    )
                    payload = prefix + archive
                    self.assertEqual(detect_archive_kind(payload), "tar")
                    self.assertIn(
                        "SCA001_ARCHIVE_INVALID",
                        _codes(_scan_explicit("payload.bin", payload)),
                    )

                    nested = io.BytesIO()
                    with zipfile.ZipFile(nested, "w") as container:
                        container.writestr("payload.bin", payload)
                    self.assertIn(
                        "SCA001_ARCHIVE_INVALID",
                        _codes(_scan_explicit("nested.zip", nested.getvalue())),
                    )

    def test_archive_recognition_charges_before_linear_probe_and_limit_plus_one(
        self,
    ) -> None:
        limits = dict(_policy()["limits"])
        data = b"0" * 4096
        budget = WorkBudget(limits)
        self.assertIsNone(detect_archive_kind(data, budget=budget))
        self.assertGreaterEqual(budget.parser_operations, len(data))
        constrained = dict(limits)
        constrained["max_parser_operations"] = len(data) - 1
        with self.assertRaisesRegex(ScanDataError, "SCN005_BUDGET_EXCEEDED"):
            detect_archive_kind(data, budget=WorkBudget(constrained))

    def test_yaml_multiline_recovery_work_is_linear_and_budgeted(self) -> None:
        operations: list[int] = []
        for lines in (100, 200, 400):
            data = (
                'key: "start\n'
                + "".join("  continuation\n" for _ in range(lines))
                + '  end"\n'
            ).encode()
            budget = WorkBudget(dict(_policy()["limits"]))
            value, _comments = parse_yaml_document(data, budget.limits, budget)
            self.assertIn("end", value["key"])
            operations.append(budget.parser_operations)
        self.assertLessEqual(operations[1], operations[0] * 3)
        self.assertLessEqual(operations[2], operations[1] * 3)


class InventoryWorkflowReleaseTests(unittest.TestCase):
    def assert_digest_adjusted_workflow_invalid(self, path: str, text: str) -> None:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with mock.patch.dict(
            workflow_contract.EXPECTED_WORKFLOW_SHA256, {path: digest}
        ):
            self.assertFalse(validate_workflow_text(path, text))

    def test_nested_test_module_is_recursively_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in (
                "test_secret_contract_scanner.py",
                "test_secret_contract_scanner_correction3.py",
                "test_secret_contract_scanner_correction4.py",
            ):
                (root / name).write_bytes(
                    pathlib.Path(__file__).with_name(name).read_bytes()
                )
            _write(root, "nested/test_hidden_failure.py", b"raise AssertionError\n")
            self.assertFalse(_test_module_inventory_valid(root))

    def test_ci_declares_read_only_permissions_and_pristine_scan_first(self) -> None:
        path = REQUIRED_WORKFLOWS[0]
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(path, text))
        self.assertIn("permissions:\n  contents: read\n", text)
        scan = text.index(
            '/usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "${GITHUB_SHA}"'
        )
        self_test = text.index("--self-test", scan)
        self.assertLess(scan, self_test)
        self.assertIn('git archive "${GITHUB_SHA}"', text)
        for mutation in (
            text.replace("permissions:\n  contents: read\n", "permissions: {}\n", 1),
            text.replace(' --git-tree "${GITHUB_SHA}"', "", 1),
            text.replace('git archive "${GITHUB_SHA}"', "git archive HEAD", 1),
        ):
            self.assert_digest_adjusted_workflow_invalid(path, mutation)

    def test_release_requires_protected_ref_environment_and_promotes_once_built_artifact(
        self,
    ) -> None:
        path = REQUIRED_WORKFLOWS[1]
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        self.assertTrue(validate_workflow_text(path, text))
        self.assertIn("GITHUB_REF_PROTECTED", text)
        self.assertIn("environment: ghcr-release", text)
        self.assertIn("sha256sum --check", text)
        self.assertIn("docker load", text)
        self.assertIn("published manifest children differ from tested digests", text)
        self.assertEqual(text.count("docker/build-push-action@"), 1)
        publish_start = text.index("  publish-platform:")
        self.assertNotIn("docker/build-push-action@", text[publish_start:])
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(
            dockerfile.splitlines()[0],
            r"^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$",
        )
        for line in dockerfile.splitlines():
            if line.startswith(("FROM rust:", "FROM python:")):
                self.assertRegex(line, r"@sha256:[0-9a-f]{64} AS ")
        self.assertIn("snapshot.debian.org/archive/debian/", dockerfile)
        self.assertIn("build-essential=12.9", dockerfile)
        self.assertIn("tini=0.19.0-1+b3", dockerfile)
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("--no-build-isolation", dockerfile)
        self.assertNotIn("pip install --no-cache-dir --upgrade pip", dockerfile)
        build_requirements = (REPO_ROOT / "python/build-requirements.txt").read_text(
            encoding="utf-8"
        )
        self.assertEqual(build_requirements.count("--hash=sha256:"), 2)
        self.assertNotIn(">=", build_requirements)
        for mutation in (
            text.replace("    environment: ghcr-release\n", "", 1),
            text.replace("    if: github.ref_protected == true\n", "", 1),
            text.replace("GITHUB_REF_PROTECTED", "UNPROTECTED_REF", 1),
            text.replace("sha256sum --check", "true #", 1),
        ):
            self.assert_digest_adjusted_workflow_invalid(path, mutation)


if __name__ == "__main__":
    unittest.main()
