#!/usr/bin/env python3
"""Build and inspect normal release consumers for dev Secret Provider leakage."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


PRODUCTION_PACKAGES = ("splendor-daemon", "splendorctl")
PRODUCTION_IMAGE_BINARIES = (
    "/usr/local/bin/splendorctl",
    "/usr/local/bin/splendor-daemon",
    "/usr/local/bin/splendor-manager",
)
PUBLISH_WORKFLOW = Path(".github/workflows/docker-image.yml")
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


def workflow_job_blocks(workflow: str) -> dict[str, str]:
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in workflow.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        job = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
        if job:
            current = job.group(1)
            jobs[current] = [line]
            continue
        if current is not None:
            jobs[current].append(line)
    return {name: "\n".join(lines) for name, lines in jobs.items()}


def workflow_job_needs(block: str) -> set[str]:
    match = re.search(r"^    needs:\s*(.+?)\s*$", block, flags=re.MULTILINE)
    if not match:
        return set()
    value = match.group(1).strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return {item.strip().strip("'\"") for item in value.split(",") if item.strip()}


def check_publish_workflow_text(workflow: str) -> list[str]:
    violations: list[str] = []
    jobs = workflow_job_blocks(workflow)
    closure = jobs.get("release-closure")
    if closure is None:
        return ["Docker publication workflow is missing the release-closure job"]
    for required in (
        "check-secret-provider-release-closure.py",
        "--image",
        "--expected-revision",
        "${GITHUB_SHA}",
        'git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"',
    ):
        if required not in closure:
            violations.append(
                f"Docker release-closure job is missing exact-artifact gate fragment {required!r}"
            )

    dependencies = {name: workflow_job_needs(block) for name, block in jobs.items()}

    def depends_on_closure(job: str, seen: set[str] | None = None) -> bool:
        if job == "release-closure":
            return True
        seen = set() if seen is None else seen
        if job in seen:
            return False
        seen.add(job)
        return any(
            depends_on_closure(dependency, seen.copy())
            for dependency in dependencies.get(job, set())
        )

    publication_markers = (
        "docker/login-action@",
        "push=true",
        "push: true",
        "docker buildx imagetools create",
        "/visibility",
    )
    for name, block in jobs.items():
        if any(marker in block for marker in publication_markers) and not depends_on_closure(name):
            violations.append(
                f"Docker publication job {name!r} does not depend on release-closure"
            )
    return violations


def inspect_binary(binary: Path, label: str, violations: list[str]) -> None:
    if not binary.is_file():
        violations.append(f"expected production binary is missing: {label}")
        return
    hits = marker_hits(binary.read_bytes())
    if hits:
        violations.append(
            f"production binary {label!r} contains forbidden dev symbols/markers: {hits!r}"
        )


def check_host_binaries(root: Path, violations: list[str]) -> None:
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
            inspect_binary(binary, f"{package['name']}:{target['name']}", violations)


def check_image_binaries(
    root: Path, image: str, expected_revision: str, violations: list[str]
) -> None:
    revision = run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            '{{ index .Config.Labels "org.opencontainers.image.revision" }}',
            image,
        ],
        root,
    ).strip()
    if revision != expected_revision:
        violations.append(
            f"production image revision mismatch: expected {expected_revision!r}, got {revision!r}"
        )

    container_id = run(["docker", "create", image], root).strip()
    if not container_id:
        raise RuntimeError(f"docker create {image} returned no container ID")
    try:
        with tempfile.TemporaryDirectory(prefix="splendor-release-closure-") as directory:
            extraction_root = Path(directory)
            for source in PRODUCTION_IMAGE_BINARIES:
                destination = extraction_root / Path(source).name
                try:
                    run(
                        ["docker", "cp", f"{container_id}:{source}", str(destination)],
                        root,
                    )
                except RuntimeError as error:
                    violations.append(
                        f"failed to extract production image binary {source!r}: {error}"
                    )
                    continue
                inspect_binary(destination, f"{image}:{source}", violations)
    finally:
        run(["docker", "rm", "--force", container_id], root)


def check(
    root: Path, image: str | None = None, expected_revision: str | None = None
) -> list[str]:
    violations: list[str] = []
    workflow_path = root / PUBLISH_WORKFLOW
    if not workflow_path.is_file():
        violations.append(f"Docker publication workflow is missing: {workflow_path}")
    else:
        violations.extend(check_publish_workflow_text(workflow_path.read_text()))

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

    if image is None:
        if expected_revision is not None:
            raise ValueError("--expected-revision requires --image")
        check_host_binaries(root, violations)
    else:
        if not expected_revision:
            raise ValueError("--image requires --expected-revision")
        check_image_binaries(root, image, expected_revision, violations)
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--image")
    parser.add_argument("--expected-revision")
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
        safe_workflow = """jobs:
  release-closure:
    steps:
      - run: git fetch --no-tags --depth=1 origin "${GITHUB_SHA}"
      - run: python3 scripts/architecture/check-secret-provider-release-closure.py --image fixture --expected-revision "${GITHUB_SHA}"
  smoke:
    steps:
      - run: smoke
  publish-platform:
    needs: [smoke, release-closure]
    steps:
      - uses: docker/login-action@v3
      - run: publish push=true
  publish-manifest:
    needs: publish-platform
    steps:
      - run: docker buildx imagetools create fixture
"""
        assert check_publish_workflow_text(safe_workflow) == []
        unsafe_workflow = safe_workflow.replace(
            "    needs: [smoke, release-closure]\n", "    needs: smoke\n"
        )
        assert check_publish_workflow_text(unsafe_workflow) == [
            "Docker publication job 'publish-platform' does not depend on release-closure",
            "Docker publication job 'publish-manifest' does not depend on release-closure",
        ]
        print("Secret Provider release closure self-test: PASS")
        return 0
    try:
        violations = check(
            args.repo_root.resolve(),
            image=args.image,
            expected_revision=args.expected_revision,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"Secret Provider release closure: ERROR: {error}", file=sys.stderr)
        return 2
    if violations:
        print("Secret Provider release closure: FAIL")
        for violation in violations:
            print(f"- {violation}")
        return 1
    print("Secret Provider release closure: PASS")
    boundary = f"Docker image {args.image!r}" if args.image else "host release binaries"
    print(
        "Normal daemon/CLI dependency graphs, the publication workflow, and "
        f"{boundary} contain no dev provider/test-support closure violations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
