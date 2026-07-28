from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.parse
import zipfile
from typing import Any
from unittest import mock

SECURITY_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SECURITY_ROOT.parents[1]
sys.path.insert(0, str(SECURITY_ROOT))

from secret_contract_scanner import cli as scanner_cli  # noqa: E402
from secret_contract_scanner import workflows as workflow_contract  # noqa: E402
from secret_contract_scanner.archives import detect_archive_kind  # noqa: E402
from secret_contract_scanner.content import scan_content  # noqa: E402
from secret_contract_scanner.engine import scan_repository  # noqa: E402
from secret_contract_scanner.model import (  # noqa: E402
    Finding,
    ScanDataError,
    ScanStats,
    WorkBudget,
)
from secret_contract_scanner.self_test import (  # noqa: E402
    _test_module_inventory_valid,
    run_self_test,
)
from secret_contract_scanner.workflows import (  # noqa: E402
    EXPECTED_ACTIONS,
    REQUIRED_WORKFLOWS,
    validate_workflow_text,
)


def _policy() -> dict[str, Any]:
    return {
        "schema_version": "splendor.secret_field_scan.v1",
        "scanner_version": "1.0.0",
        "owner": "SECR-006",
        "reviewed_on": "2026-07-26",
        "limits": {
            "max_files": 256,
            "max_file_bytes": 1_048_576,
            "max_total_bytes": 16_777_216,
            "max_structure_depth": 64,
            "max_structure_nodes": 100_000,
            "max_object_members": 2_048,
            "max_array_items": 2_048,
            "max_string_bytes": 262_144,
            "max_markdown_fences": 64,
            "max_parser_operations": 4_000_000,
            "max_archive_members": 128,
            "max_archive_unpacked_bytes": 4_194_304,
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
) -> tuple[list[Finding], ScanStats]:
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        for relative, data in files.items():
            _write(root, relative, data)
        return scan_repository(root, policy or _policy())


def _findings_by_path(findings: list[Finding]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for finding in findings:
        result.setdefault(finding.path, set()).add(finding.code)
    return result


def _root(identifier: str, path: str, formats: dict[str, str]) -> dict[str, object]:
    return {
        "id": identifier,
        "path": path,
        "formats": formats,
        "owner": "correction-3 regression",
        "reason": "exercise normal repository mode",
    }


def _v7_tar(member_name: str, payload: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT
    ) as archive:
        info = tarfile.TarInfo(member_name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    result = bytearray(output.getvalue())
    result[257:512] = b"\0" * (512 - 257)
    result[148:156] = b" " * 8
    checksum = sum(result[:512])
    result[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(result)


class RepositoryCoverageCorrection3Tests(unittest.TestCase):
    def test_normal_mode_suffix_and_ancestor_config_matrix(self) -> None:
        sensitive = "PASS" + "WORD"
        files = {
            "payload.bin": f"{sensitive}=abc\n".encode(),
            "nested.json": json.dumps({"credentials": {"key": "ab" * 32}}).encode(),
            "nested.yaml": b"credentials:\n  key: abc\n",
            "settings.ini": b"[credentials]\nkey=abc\n",
            "settings.toml": b'[[credentials]]\nkey="abc"\n',
        }
        findings, _stats = _normal_scan(files)
        by_path = _findings_by_path(findings)
        for path in files:
            with self.subTest(path=path):
                self.assertTrue(
                    by_path.get(path, set())
                    & {"SCC003_AUTH_VALUE", "SCC004_HIGH_ENTROPY"}
                )

    def test_normal_mode_discovers_new_openapi_sdk_and_package_surfaces(self) -> None:
        sensitive = "pass" + "word"
        policy = _policy()
        policy["governed_roots"] = [
            _root(
                "openapi",
                "openapi",
                {".json": "json", ".yaml": "yaml", ".yml": "yaml"},
            ),
            _root(
                "typescript-packages",
                "typescript/packages",
                {".json": "json", ".ts": "typescript_source"},
            ),
        ]
        files = {
            "openapi/new-api.yaml": (
                "openapi: 3.1.0\ncomponents:\n  schemas:\n    Request:\n"
                f"      properties:\n        {sensitive}:\n          type: string\n"
            ).encode(),
            "typescript/packages/new-client/package.json": b'{"name":"new-client"}',
            "typescript/packages/new-client/src/index.ts": (
                f"export interface Request {{ {sensitive}: string; }}\n"
            ).encode(),
            "python/new_sdk/client.py": b"class Client:\n    pass\n",
            "sdk/package.json": b'{"name":"outside-sdk"}',
            "sdk/client.ts": b"export interface Safe { value: string; }\n",
            "api/swagger.yaml": b"openapi: 3.1.0\ninfo: {title: safe, version: '1'}\n",
        }
        findings, _stats = _normal_scan(files, policy)
        by_path = _findings_by_path(findings)
        self.assertIn("SCF001_SECRET_FIELD", by_path["openapi/new-api.yaml"])
        self.assertIn(
            "SCF005_SOURCE_FIELD",
            by_path["typescript/packages/new-client/src/index.ts"],
        )
        for path in (
            "python/new_sdk/client.py",
            "sdk/package.json",
            "sdk/client.ts",
            "api/swagger.yaml",
        ):
            with self.subTest(path=path):
                self.assertIn("SCN004_UNSUPPORTED_FORMAT", by_path[path])

    def test_normal_mode_rejects_every_unknown_workflow_identity_and_trigger(
        self,
    ) -> None:
        workflow_bodies = {
            ".github/workflows/release.yaml": b"on: {push: {}}\njobs: {publish: {runs-on: ubuntu-latest}}\n",
            ".github/workflows/callable.yml": b"on: {workflow_call: {}}\njobs: {build: {runs-on: ubuntu-latest}}\n",
            ".github/workflows/target.yaml": b"on: {pull_request_target: {}}\njobs: {test: {runs-on: ubuntu-latest}}\n",
            ".github/workflows/ci-copy.yml": b"on: {push: {}}\njobs: {package: {runs-on: ubuntu-latest}}\n",
        }
        findings, _stats = _normal_scan(workflow_bodies)
        by_path = _findings_by_path(findings)
        for path in workflow_bodies:
            with self.subTest(path=path):
                self.assertIn("SCN012_WORKFLOW_UNGATED", by_path[path])

    def test_identifier_namespaces_and_exact_metadata_do_not_become_material(
        self,
    ) -> None:
        metadata = b"\n".join(
            [
                b"auth_state=active",
                b"authorization_policy=rbac",
                b"password_policy=strict",
                b"secret_backend=vault",
                b"credential_format=json",
                b"credential_binding=trusted_injection",
                b"credential_sink=adapter",
                b"credential_slot=slot_1",
                b"credential_bearing_send_sequence=7",
            ]
        )
        structured = {
            "jobs": {
                "secret-contracts": {"needs": [], "permissions": {"contents": "read"}}
            },
            "services": {"resident-auth-fixture": {"image": "local/example"}},
            "volumes": {"e2e-provider-auth": {}},
            "credentials": {
                "policy": "strict",
                "backend": "vault",
                "format": "json",
                "state": "active",
            },
            "allowed_credential_bindings": [{"kind": "trusted_injection"}],
            "credential_sinks": [{"credential_slot": "slot_1"}],
        }
        findings, _stats = _normal_scan(
            {
                "metadata.bin": metadata + b"\n",
                "material.bin": b"\n".join(
                    [
                        b"pass" + b"word_binding=abc",
                        b"pass" + b"word_attempt=abc",
                        b"credential_send=abc",
                    ]
                )
                + b"\n",
                "layout.yaml": (
                    "jobs:\n  secret-contracts:\n    needs: []\n"
                    "    permissions:\n      contents: read\n"
                    "services:\n  resident-auth-fixture:\n    image: local/example\n"
                    "volumes:\n  e2e-provider-auth: {}\n"
                    "credentials:\n  policy: strict\n  backend: vault\n"
                    "  format: json\n  state: active\n"
                ).encode(),
                "metadata.json": json.dumps(structured).encode(),
            }
        )
        self.assertFalse(
            [
                finding
                for finding in findings
                if finding.path != "material.bin"
                and finding.code.startswith(("SCC", "SCF"))
            ]
        )
        self.assertIn("SCC003_AUTH_VALUE", _findings_by_path(findings)["material.bin"])


class SourceGrammarCorrection3Tests(unittest.TestCase):
    def test_python_dynamic_namedtuple_and_rebinding_matrix(self) -> None:
        sensitive = "pass" + "word"
        owner_source = b"class SecretRefV2:\n    pass\n"
        package = b"[project]\nname = 'splendor'\nversion = '0.0.0'\n"
        policy = _policy()
        policy["governed_roots"] = [
            _root("python-sdk", "python/splendor", {".py": "python_source"})
        ]
        policy["source_owner_exports"] = [
            {
                "language": "python",
                "module": "splendor.types",
                "path": "python/splendor/types.py",
                "sha256": hashlib.sha256(owner_source).hexdigest(),
                "package_path": "python/pyproject.toml",
                "package_sha256": hashlib.sha256(package).hexdigest(),
                "exports": ["SecretRefV2"],
            }
        ]
        files = {
            "python/splendor/types.py": owner_source,
            "python/pyproject.toml": package,
            "python/splendor/safe.py": (
                "from splendor.types import SecretRefV2\n"
                "class Request:\n    secret: SecretRefV2 | None = None\n"
            ).encode(),
            "python/splendor/rebound.py": (
                "from splendor.types import SecretRefV2\nSecretRefV2 = str\n"
                "class Request:\n    secret: SecretRefV2 | None = None\n"
            ).encode(),
            "python/splendor/module_rebound.py": (
                "import splendor as owner\nowner.SecretRefV2 = str\n"
                "class Request:\n    secret: owner.SecretRefV2 | None = None\n"
            ).encode(),
            "python/splendor/named.py": (
                "from typing import NamedTuple\n"
                f'Request = NamedTuple("Request", [("{sensitive}", str)])\n'
            ).encode(),
            "python/splendor/dynamic.py": (
                "from typing import TypedDict\n"
                f'{sensitive}_field = "{sensitive}"\n'
                f'Request = TypedDict("Request", {{{sensitive}_field: str}})\n'
            ).encode(),
            "python/splendor/dict_key.py": (
                f'field = "{sensitive}"\nrequest = {{field: "abc"}}\n'
            ).encode(),
            "python/splendor/subscript.py": (
                f'field = "{sensitive}"\nrequest = {{}}\nrequest[field] = "abc"\n'
            ).encode(),
            "python/splendor/setattr_key.py": (
                f'field = "{sensitive}"\nrequest = object()\n'
                'setattr(request, field, "abc")\n'
            ).encode(),
            "python/splendor/rebound_key.py": (
                f'field = "{sensitive}"\nfield = choose_field()\n'
                'request = {field: "abc"}\n'
            ).encode(),
            "python/splendor/aliased_key.py": (
                f'field = "{sensitive}"\nalias = field\n' 'request = {alias: "abc"}\n'
            ).encode(),
            "python/splendor/aliased_rebound_key.py": (
                f'field = "{sensitive}"\nalias = field\nalias = choose_field()\n'
                'request = {alias: "abc"}\n'
            ).encode(),
        }
        findings, _stats = _normal_scan(files, policy)
        by_path = _findings_by_path(findings)
        self.assertNotIn(
            "SCF005_SOURCE_FIELD", by_path.get("python/splendor/safe.py", set())
        )
        for path in (
            "python/splendor/rebound.py",
            "python/splendor/module_rebound.py",
            "python/splendor/named.py",
        ):
            with self.subTest(path=path):
                self.assertIn("SCF005_SOURCE_FIELD", by_path[path])
        self.assertIn("SCN011_MALFORMED_SOURCE", by_path["python/splendor/dynamic.py"])
        for path in (
            "python/splendor/dict_key.py",
            "python/splendor/subscript.py",
            "python/splendor/setattr_key.py",
            "python/splendor/rebound_key.py",
            "python/splendor/aliased_key.py",
            "python/splendor/aliased_rebound_key.py",
        ):
            with self.subTest(path=path):
                self.assertIn("SCF005_SOURCE_FIELD", by_path[path])

    def test_typescript_record_mapped_and_reexport_matrix(self) -> None:
        sensitive = "pass" + "word"
        client_secret = "client" + "Secret"
        policy = _policy()
        policy["governed_roots"] = [
            _root(
                "typescript-packages",
                "typescript/packages",
                {".ts": "typescript_source"},
            )
        ]
        files = {
            "typescript/packages/new/src/record.ts": (
                f'export type Request = Record<"{sensitive}", string>;\n'
            ).encode(),
            "typescript/packages/new/src/mapped.ts": (
                f'export type Request = {{ [K in "{client_secret}"]: string }};\n'
            ).encode(),
            "typescript/packages/new/src/reexport.ts": (
                'export type { CallerCredential } from "@splendor/types";\n'
            ).encode(),
            "typescript/packages/new/src/record-alias.ts": (
                f'type Fields = "{sensitive}";\n'
                "export type Request = Record<Fields, string>;\n"
            ).encode(),
            "typescript/packages/new/src/record-alias-chain.ts": (
                f'type SensitiveFields = "{sensitive}";\n'
                "type Fields = SensitiveFields;\n"
                "export type Request = Record<Fields, string>;\n"
            ).encode(),
            "typescript/packages/new/src/record-template-alias.ts": (
                'type Fields = `pass${"word"}`;\n'
                "export type Request = Record<Fields, string>;\n"
            ).encode(),
            "typescript/packages/new/src/mapped-alias.ts": (
                f'type Fields = "{sensitive}";\n'
                "export type Request = { [K in Fields]: string };\n"
            ).encode(),
            "typescript/packages/new/src/computed.ts": (
                f'const field = "{sensitive}";\n'
                'export const request = { [field]: "abc" };\n'
            ).encode(),
            "typescript/packages/new/src/computed-dynamic.ts": (
                "const field = chooseField();\n"
                'export const request = { [field]: "abc" };\n'
            ).encode(),
            "typescript/packages/new/src/computed-template.ts": (
                'const segment = "word";\n'
                'export const request = { [`pass${segment}`]: "abc" };\n'
            ).encode(),
        }
        findings, _stats = _normal_scan(files, policy)
        by_path = _findings_by_path(findings)
        for path in files:
            with self.subTest(path=path):
                self.assertIn("SCF005_SOURCE_FIELD", by_path[path])


class MarkdownArchiveBudgetCorrection3Tests(unittest.TestCase):
    def test_deep_commonmark_fences_and_depth_overflow_fail_closed(self) -> None:
        sensitive = "pass" + "word"
        policy = _policy()
        policy["governed_roots"] = [_root("examples", "examples", {".md": "markdown"})]

        def fenced(depth: int) -> bytes:
            prefix = "> " * depth
            return (
                prefix
                + "```json\n"
                + prefix
                + json.dumps({sensitive: "abc"})
                + "\n"
                + prefix
                + "```\n"
            ).encode()

        findings, _stats = _normal_scan(
            {
                "examples/depth-17.md": fenced(17),
                "examples/depth-64.md": fenced(64),
                "examples/depth-65.md": fenced(65),
            },
            policy,
        )
        by_path = _findings_by_path(findings)
        for path in ("examples/depth-17.md", "examples/depth-64.md"):
            with self.subTest(path=path):
                self.assertTrue(
                    by_path[path] & {"SCF001_SECRET_FIELD", "SCC003_AUTH_VALUE"}
                )
        self.assertIn("SCN008_MALFORMED_MARKDOWN", by_path["examples/depth-65.md"])

    def test_governed_source_fences_and_myst_options_are_structural(self) -> None:
        sensitive = "pass" + "word"
        policy = _policy()
        policy["governed_roots"] = [_root("examples", "examples", {".md": "markdown"})]
        files = {
            "examples/python.md": (
                "```python\nclass Request:\n    " + sensitive + ": str\n```\n"
            ).encode(),
            "examples/typescript.md": (
                "```typescript\nexport interface Request { "
                + sensitive
                + ": string; }\n```\n"
            ).encode(),
            "examples/myst.md": (
                "```{code-block} json\n:caption: bounded example\n:name: safe-example\n\n"
                '{"public_metadata":"safe"}\n```\n'
                ":::{code-block} yaml\n:caption: another example\n\n"
                "public_metadata: safe\n:::\n"
            ).encode(),
        }
        findings, _stats = _normal_scan(files, policy)
        by_path = _findings_by_path(findings)
        self.assertIn("SCF005_SOURCE_FIELD", by_path["examples/python.md#fence-1"])
        self.assertIn("SCF005_SOURCE_FIELD", by_path["examples/typescript.md#fence-1"])
        self.assertFalse(
            [
                finding
                for finding in findings
                if finding.path.startswith("examples/myst.md")
            ]
        )

    def test_v7_tar_after_4096_bytes_and_nested_member_are_not_opaque(self) -> None:
        sensitive = "pass" + "word"
        archive = _v7_tar("manifest.json", json.dumps({sensitive: "abc"}).encode())
        prefixed = b"\xff" + (b"A" * 4096) + archive
        self.assertEqual(detect_archive_kind(prefixed), "tar")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as zipped:
            zipped.writestr("payload.bin", prefixed)
        findings, _stats = _normal_scan(
            {"polyglot.bin": prefixed, "outer.zip": outer.getvalue()}
        )
        by_path = _findings_by_path(findings)
        self.assertIn("SCA001_ARCHIVE_INVALID", by_path["polyglot.bin"])
        self.assertIn("SCA001_ARCHIVE_INVALID", by_path["outer.zip"])

    def test_parser_operation_budget_fails_before_unbounded_source_work(self) -> None:
        policy = _policy()
        policy["limits"]["max_parser_operations"] = 16
        policy["governed_roots"] = [
            _root("typescript", "typescript", {".ts": "typescript_source"})
        ]
        findings, stats = _normal_scan(
            {
                "typescript/index.ts": (
                    "export interface Request {\n"
                    + "  ordinary: string;\n" * 32
                    + "}\n"
                ).encode()
            },
            policy,
        )
        self.assertIn("SCN005_BUDGET_EXCEEDED", {finding.code for finding in findings})
        self.assertGreater(stats.parser_operations, 16)

        yaml_policy = _policy()
        yaml_policy["limits"]["max_parser_operations"] = 16
        yaml_policy["governed_roots"] = [_root("yaml", "contracts", {".yaml": "yaml"})]
        yaml_findings, yaml_stats = _normal_scan(
            {"contracts/manifest.yaml": b"items:\n  - ordinary\n  - ordinary\n"},
            yaml_policy,
        )
        self.assertIn(
            "SCN005_BUDGET_EXCEEDED", {finding.code for finding in yaml_findings}
        )
        self.assertGreater(yaml_stats.parser_operations, 16)

    def test_python_and_typescript_source_nesting_limits_fail_closed(self) -> None:
        policy = _policy()
        policy["governed_roots"] = [
            _root("python", "python/splendor", {".py": "python_source"}),
            _root("typescript", "typescript/packages", {".ts": "typescript_source"}),
        ]
        files = {
            "python/splendor/deep.py": (
                "value = " + ("[" * 65) + "0" + ("]" * 65) + "\n"
            ).encode(),
            "typescript/packages/deep.ts": (
                "const value = " + ("[" * 65) + "0" + ("]" * 65) + ";\n"
            ).encode(),
        }
        findings, _stats = _normal_scan(files, policy)
        by_path = _findings_by_path(findings)
        for path in files:
            with self.subTest(path=path):
                self.assertIn("SCN011_MALFORMED_SOURCE", by_path[path])

    def test_nfkc_expansion_and_provenance_are_charged_deterministically(self) -> None:
        text = "\ufdfa" * 4
        generous_limits = dict(_policy()["limits"])
        first = WorkBudget(generous_limits)
        second = WorkBudget(generous_limits)
        self.assertEqual(scan_content(text, 8, budget=first), [])
        self.assertEqual(scan_content(text, 8, budget=second), [])
        self.assertEqual(
            (first.work_bytes, first.parser_operations),
            (second.work_bytes, second.parser_operations),
        )
        self.assertGreater(first.work_bytes, len(text.encode("utf-8")))

        constrained_limits = dict(generous_limits)
        constrained_limits["max_total_bytes"] = len(text.encode("utf-8"))
        with self.assertRaisesRegex(ScanDataError, "SCN005_BUDGET_EXCEEDED"):
            scan_content(text, 8, budget=WorkBudget(constrained_limits))


class BootstrapInventoryDiagnosticWorkflowCorrection3Tests(unittest.TestCase):
    def test_cli_failure_boundaries_return_fixed_nonzero_results(self) -> None:
        repository = mock.MagicMock()
        repository.__enter__.return_value = repository
        repository.__exit__.return_value = False
        policy_finding = Finding(
            "scripts/security/secret-contract-policy.json",
            0,
            "SCN001_POLICY_INVALID",
        )
        with (
            mock.patch.object(scanner_cli, "PinnedRepository", return_value=repository),
            mock.patch.object(
                scanner_cli, "load_policy", return_value=(None, [policy_finding])
            ),
            mock.patch("sys.stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(scanner_cli.main(["--repo-root", "."]), 1)
            self.assertIn("SCN001_POLICY_INVALID", stderr.getvalue())

        scan_finding = Finding("ordinary.txt", 0, "SCN005_BUDGET_EXCEEDED")
        with (
            mock.patch.object(scanner_cli, "PinnedRepository", return_value=repository),
            mock.patch.object(scanner_cli, "load_policy", return_value=({}, [])),
            mock.patch.object(
                scanner_cli,
                "scan_repository",
                return_value=([scan_finding], ScanStats()),
            ),
            mock.patch("sys.stderr", io.StringIO()) as stderr,
        ):
            self.assertEqual(scanner_cli.main(["--repo-root", "."]), 1)
            self.assertIn("FAIL (1 finding(s))", stderr.getvalue())
            self.assertIn("SCN005_BUDGET_EXCEEDED", stderr.getvalue())

        for failure in (ScanDataError("SCN005_BUDGET_EXCEEDED", 7), OSError()):
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(scanner_cli, "PinnedRepository", side_effect=failure),
                mock.patch("sys.stderr", io.StringIO()) as stderr,
            ):
                self.assertEqual(scanner_cli.main(["--repo-root", "."]), 1)
                self.assertIn("C03 secret contract scan: FAIL", stderr.getvalue())

    def test_isolated_subprocess_resists_hostile_stdlib_shadow_for_both_commands(
        self,
    ) -> None:
        if os.environ.get("SPLENDOR_SCANNER_ISOLATION_CHILD") == "1":
            return
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            listed = subprocess.run(
                ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")
            for raw_path in listed:
                if not raw_path:
                    continue
                relative = raw_path.decode("utf-8")
                source = REPO_ROOT / relative
                if source.is_file() and not source.is_symlink():
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            marker = root / "shadow-imported"
            hostile = (
                f"open({os.fspath(marker)!r}, 'w', encoding='utf-8').write('imported')\n"
                "raise SystemExit(0)\n"
            ).encode()
            _write(root, "scripts/security/hashlib.py", hostile)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "SPLENDOR_SCANNER_ISOLATION_CHILD": "1",
                }
            )
            commands = (
                [
                    "/usr/bin/python3",
                    "-I",
                    "scripts/security/check-secret-contracts.py",
                    "--self-test",
                ],
                [
                    "/usr/bin/python3",
                    "-I",
                    "scripts/security/check-secret-contracts.py",
                ],
            )
            for command in commands:
                completed = subprocess.run(
                    command,
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
                with self.subTest(command=command[-1]):
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn("PASS", completed.stdout)
                    self.assertFalse(marker.exists())

    def test_iterative_percent_redaction_reaches_fixed_point_without_oracle(
        self,
    ) -> None:
        candidate = "PASS" + "WORD=abc"
        variants = [candidate]
        for _ in range(9):
            variants.append(urllib.parse.quote(variants[-1], safe=""))
        rendered = [
            Finding(f"safe/{value}/fixture.json", 1, "SCC003_AUTH_VALUE").render()
            for value in variants[2:]
        ]
        self.assertTrue(
            all("safe/<redacted>/fixture.json" in value for value in rendered)
        )
        for output in rendered:
            self.assertNotIn(candidate, output)
            self.assertNotRegex(output, r"<redacted-[0-9a-f]+>")

    def test_extra_test_module_is_rejected_before_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in (
                "test_secret_contract_scanner.py",
                "test_secret_contract_scanner_correction3.py",
            ):
                shutil.copyfile(pathlib.Path(__file__).with_name(name), root / name)
            (root / "test_secret_contract_scanner_extra.py").write_text(
                "raise AssertionError('must not be ignored')\n", encoding="utf-8"
            )
            self.assertFalse(_test_module_inventory_valid(root))
            with mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(run_self_test(root), 1)

    def test_third_party_actions_and_package_write_permissions_are_exact(self) -> None:
        for path in REQUIRED_WORKFLOWS:
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            self.assertTrue(validate_workflow_text(path, text))
            actions = re.findall(r"(?m)^\s+(?:-\s+)?uses:\s*([^\s#]+)\s*$", text)
            self.assertEqual(sorted(actions), sorted(EXPECTED_ACTIONS[path].elements()))
            self.assertTrue(
                all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in actions)
            )
            mutable = re.sub(r"@[0-9a-f]{40}", "@v1", text, count=1)
            self.assertFalse(validate_workflow_text(path, mutable))

        docker_path = REQUIRED_WORKFLOWS[1]
        docker = (REPO_ROOT / docker_path).read_text(encoding="utf-8")
        top_level = docker.split("env:", 1)[0]
        self.assertNotIn("packages: write", top_level)
        for job in ("publish-platform", "publish-manifest"):
            block = re.search(
                rf"(?ms)^  {job}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
                docker,
            )
            self.assertIsNotNone(block)
            assert block is not None
            self.assertIn(
                "    permissions:\n      contents: read\n      packages: write\n",
                block.group("body"),
            )
        smoke = re.search(
            r"(?ms)^  smoke:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", docker
        )
        self.assertIsNotNone(smoke)
        assert smoke is not None
        self.assertNotIn("packages: write", smoke.group("body"))
        self.assertFalse(
            validate_workflow_text(
                docker_path,
                docker.replace(
                    "permissions:\n  contents: read\n",
                    "permissions:\n  contents: read\n  packages: write\n",
                    1,
                ),
            )
        )
        self.assertFalse(
            validate_workflow_text(
                docker_path,
                docker.replace(
                    "  publish-platform:\n    needs: [secret-contracts, smoke, verify-smoke]\n    if: github.ref_protected == true\n    environment: ghcr-release\n    permissions:\n      contents: read\n      packages: write\n",
                    "  publish-platform:\n    needs: [secret-contracts, smoke, verify-smoke]\n",
                    1,
                ),
            )
        )

    def test_workflow_structural_guards_reject_digest_adjusted_mutations(self) -> None:
        path = REQUIRED_WORKFLOWS[0]
        text = (REPO_ROOT / path).read_text(encoding="utf-8")
        action = next(iter(EXPECTED_ACTIONS[path]))
        mutations = {
            "trigger": text.replace("  pull_request:\n", "", 1),
            "defaults": text.replace(
                "jobs:\n", "defaults:\n  run:\n    shell: bash\njobs:\n", 1
            ),
            "job-shape": text.replace("  rust:\n", "  'rust':\n", 1),
            "action": text.replace(action, action.rsplit("@", 1)[0] + "@v1", 1),
            "dependency": text.replace(
                "  rust:\n    needs: secret-contracts\n",
                "  rust:\n    needs: [secret-contracts, shadow]\n",
                1,
            ),
            "job-condition": text.replace(
                "  rust:\n    needs: secret-contracts\n",
                "  rust:\n    needs: secret-contracts\n    if: success()\n",
                1,
            ),
            "checkout": text.replace("          git init .\n", "", 1),
            "scanner-command": text.replace(
                '          /usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "${GITHUB_SHA}"\n',
                "",
                1,
            ),
        }
        for name, mutation in mutations.items():
            digest = hashlib.sha256(mutation.encode("utf-8")).hexdigest()
            with (
                self.subTest(name=name),
                mock.patch.dict(
                    workflow_contract.EXPECTED_WORKFLOW_SHA256,
                    {path: digest},
                ),
            ):
                self.assertFalse(validate_workflow_text(path, mutation))


if __name__ == "__main__":
    unittest.main()
