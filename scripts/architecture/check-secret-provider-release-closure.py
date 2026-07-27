#!/usr/bin/env python3
"""Build and inspect normal release consumers for dev Secret Provider leakage."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


PRODUCTION_PACKAGES = ("splendor-daemon", "splendorctl")
FORBIDDEN_TREE_MARKERS = (
    "splendor-adapter-secrets-local-file",
    "secret-provider-test-support",
)
FORBIDDEN_BINARY_MARKERS = (
    b"LocalFileSecretProvider",
    b"SecretProviderTestInvocation",
    b"local_file_secret_provider_runtime_mode_unsupported",
    b"secret_provider_test_support",
    b"splendor_adapter_secrets_local_file",
)


def run(command: list[str], root: Path) -> str:
    completed = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return completed.stdout


def marker_hits(payload: bytes) -> list[str]:
    return [
        marker.decode("ascii")
        for marker in FORBIDDEN_BINARY_MARKERS
        if marker in payload
    ]


def tree_marker_hits(tree: str) -> list[str]:
    return [marker for marker in FORBIDDEN_TREE_MARKERS if marker in tree]


def check(root: Path) -> list[str]:
    violations: list[str] = []
    for package in PRODUCTION_PACKAGES:
        tree = run(
            [
                "cargo",
                "tree",
                "--locked",
                "-p",
                package,
                "--edges",
                "normal,build,features",
                "--prefix",
                "none",
            ],
            root,
        )
        for marker in tree_marker_hits(tree):
            violations.append(
                f"{package}: normal/build dependency graph contains {marker!r}"
            )

    run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "-p",
            "splendor-daemon",
            "-p",
            "splendorctl",
            "--bins",
        ],
        root,
    )
    metadata = json.loads(
        run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
            root,
        )
    )
    target_dir = Path(metadata["target_directory"])
    for package in metadata["packages"]:
        if package["name"] not in PRODUCTION_PACKAGES:
            continue
        for target in package["targets"]:
            if "bin" not in target["kind"]:
                continue
            binary = target_dir / "release" / target["name"]
            if not binary.is_file():
                violations.append(f"expected production binary is missing: {binary}")
                continue
            hits = marker_hits(binary.read_bytes())
            if hits:
                violations.append(
                    f"{package['name']} binary {target['name']!r} contains forbidden dev symbols/markers: {hits!r}"
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        assert marker_hits(b"safe") == []
        assert marker_hits(b"prefix LocalFileSecretProvider suffix") == [
            "LocalFileSecretProvider"
        ]
        assert tree_marker_hits("splendor-daemon\nsplendor-types") == []
        assert tree_marker_hits(
            "splendor-daemon\nsplendor-adapter-secrets-local-file\n"
            'splendor-authority feature "secret-provider-test-support"'
        ) == [
            "splendor-adapter-secrets-local-file",
            "secret-provider-test-support",
        ]
        print("Secret Provider release closure self-test: PASS")
        return 0
    try:
        violations = check(args.repo_root.resolve())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"Secret Provider release closure: ERROR: {error}", file=sys.stderr)
        return 2
    if violations:
        print("Secret Provider release closure: FAIL")
        for violation in violations:
            print(f"- {violation}")
        return 1
    print("Secret Provider release closure: PASS")
    print("Normal daemon/CLI dependency graphs and built binaries contain no dev provider/test-support markers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
