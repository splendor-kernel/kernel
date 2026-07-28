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
IMAGE_VERSION_EXPRESSION = (
    "${{ (inputs.publish_0_05_dev == true || inputs.publish_0_05_dev == 'true') "
    "&& 'v0.05-dev' || (inputs.publish_0_04_dev == true || "
    "inputs.publish_0_04_dev == 'true') && 'v0.04-dev' || "
    "(inputs.publish_0_02_dev == true || inputs.publish_0_02_dev == 'true') "
    "&& 'v0.02-dev' || github.ref_name }}"
)
EXPECTED_BUILD_INPUTS = {
    "context",
    "platforms",
    "tags",
    "labels",
    "outputs",
    "build-args",
}
EXPECTED_BUILD_ARGS = (
    f"SPLENDOR_IMAGE_VERSION={IMAGE_VERSION_EXPRESSION}",
    "VCS_REF=${{ github.sha }}",
    "BUILD_DATE=${{ steps.build-date.outputs.created }}",
)
EXPECTED_RELEASE_VERIFICATION_STEP = "\n".join(
    (
        "      - name: Verify exact candidate dependency and binary release closure",
        "        env:",
        "          CANDIDATE_IMAGE: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ env.CANDIDATE_TAG }}-${{ matrix.artifact }}",
        "        run: |",
        "          python3 scripts/architecture/check-secret-provider-release-closure.py \\",
        '            --image "${CANDIDATE_IMAGE}" \\',
        '            --expected-revision "${GITHUB_SHA}"',
    )
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


def workflow_named_step(block: str, name: str) -> str | None:
    lines = block.splitlines()
    marker = f"      - name: {name}"
    start = next((index for index, line in enumerate(lines) if line == marker), None)
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("      - "):
            end = index
            break
    return "\n".join(lines[start:end]).rstrip()


def workflow_step_input_names(step: str) -> list[str]:
    return re.findall(r"^          ([A-Za-z0-9_-]+):(?:\s|$)", step, re.MULTILINE)


def workflow_step_scalar_inputs(step: str, name: str) -> list[str]:
    return re.findall(
        rf"^          {re.escape(name)}:\s*(.*?)\s*$", step, re.MULTILINE
    )


def workflow_step_multiline_input(step: str, name: str) -> tuple[str, ...] | None:
    lines = step.splitlines()
    markers = [
        index
        for index, line in enumerate(lines)
        if line == f"          {name}: |"
    ]
    if len(markers) != 1:
        return None
    values: list[str] = []
    for line in lines[markers[0] + 1 :]:
        if not line.startswith("            "):
            break
        values.append(line[12:])
    return tuple(values)


def job_has_packages_write(block: str) -> bool:
    return bool(re.search(r"^      packages:\s*write\s*$", block, re.MULTILINE))


def action_refs_are_immutable(workflow: str) -> list[str]:
    violations: list[str] = []
    for action, reference in re.findall(
        r"^\s+uses:\s*([^@\s]+)@([^\s#]+)", workflow, flags=re.MULTILINE
    ):
        if not re.fullmatch(r"[0-9a-f]{40}", reference):
            violations.append(
                f"Docker publication workflow action {action!r} is not pinned to a full commit SHA"
            )
    return violations


def check_protected_artifact_workflow(
    workflow: str, jobs: dict[str, str], violations: list[str]
) -> list[str]:
    """Validate the scanner-gated build-once protected publication profile."""

    if (
        re.search(r"\|\|\s*true\b", workflow)
        or re.search(r"^\s*set\s+\+e\s*$", workflow, re.MULTILINE)
        or re.search(r"^\s+continue-on-error:", workflow, re.MULTILINE)
    ):
        violations.append("Docker publication workflow must not ignore validation failures")

    required_jobs = {
        "secret-contracts",
        "smoke",
        "verify-smoke",
        "publish-platform",
        "publish-manifest",
    }
    if set(jobs) != required_jobs:
        violations.append("Docker publication workflow has an unexpected job set")
        return violations

    build = jobs["smoke"]
    closure = jobs["verify-smoke"]
    publish_platform = jobs["publish-platform"]
    publish_manifest = jobs["publish-manifest"]

    if workflow.count("docker/build-push-action@") != 1:
        violations.append(
            "Docker publication workflow must contain exactly one matrixed image build step"
        )
    for required in (
        "Build each platform image exactly once",
        "outputs: type=docker,dest=${{ runner.temp }}/image.tar",
        "tags: splendor:publish-smoke-${{ matrix.artifact }}",
        "VCS_REF=${{ github.sha }}",
        "BUILD_DATE=${{ steps.build-date.outputs.created }}",
        "Upload tested image artifact",
    ):
        if required not in build:
            violations.append(f"Docker one-time build is missing {required!r}")
    build_step = workflow_named_step(build, "Build each platform image exactly once")
    if build_step is None:
        violations.append("Docker one-time build step is missing")
    else:
        input_names = workflow_step_input_names(build_step)
        if len(input_names) != len(EXPECTED_BUILD_INPUTS) or set(
            input_names
        ) != EXPECTED_BUILD_INPUTS:
            violations.append(
                "Docker one-time platform build inputs differ from the reviewed exact set"
            )
        for name, expected in (
            ("context", "."),
            ("platforms", "${{ matrix.platform }}"),
            ("tags", "splendor:publish-smoke-${{ matrix.artifact }}"),
            ("outputs", "type=docker,dest=${{ runner.temp }}/image.tar"),
        ):
            if workflow_step_scalar_inputs(build_step, name) != [expected]:
                violations.append(
                    f"Docker one-time platform build has unexpected {name!r} input"
                )
        if workflow_step_multiline_input(build_step, "build-args") != EXPECTED_BUILD_ARGS:
            violations.append(
                "Docker one-time platform build arguments differ from the reviewed exact set"
            )
    if job_has_packages_write(build):
        violations.append("Docker one-time build job must remain registry read-only")

    verify_step = workflow_named_step(
        closure, "Verify exact candidate dependency and binary release closure"
    )
    if verify_step is None:
        violations.append("Docker verification job is missing release-closure validation")
    else:
        for required in (
            "CANDIDATE_IMAGE: splendor:publish-smoke-${{ matrix.artifact }}",
            "check-secret-provider-release-closure.py",
            '--image "${CANDIDATE_IMAGE}"',
            '--expected-revision "${GITHUB_SHA}"',
        ):
            if required not in verify_step:
                violations.append(
                    f"Docker release-closure verification is missing {required!r}"
                )
        if re.search(r"^        if:", verify_step, re.MULTILINE):
            violations.append("Docker release-closure verification must not be conditional")
    for required in (
        "needs: [secret-contracts, smoke]",
        "Download sealed image artifact",
        "sha256sum --check image.tar.sha256",
        "docker load --input image.tar",
        "Smoke test the sealed image copy",
        "bash scripts/container-tests.sh",
    ):
        if required not in closure:
            violations.append(f"Docker verification job is missing {required!r}")
    if "docker/build-push-action@" in closure or re.search(
        r"\bdocker\s+(?:build|buildx\s+build)\b", closure
    ):
        violations.append("Docker verification job must validate, not rebuild, candidates")
    if job_has_packages_write(closure):
        violations.append("Docker verification job must remain registry read-only")

    for name, block in (
        ("publish-platform", publish_platform),
        ("publish-manifest", publish_manifest),
    ):
        if "if: github.ref_protected == true" not in block:
            violations.append(f"Docker {name} job lacks protected-ref gating")
        if "environment: ghcr-release" not in block:
            violations.append(f"Docker {name} job lacks protected release environment")
        if not job_has_packages_write(block):
            violations.append(f"Docker {name} job lacks scoped packages:write")
        if "docker/build-push-action@" in block or re.search(
            r"\bdocker\s+(?:build|buildx\s+build)\b", block
        ):
            violations.append(f"Docker {name} job must publish, not rebuild, candidates")

    for required in (
        "needs: [secret-contracts, smoke, verify-smoke]",
        "Verify and load tested image artifact",
        "sha256sum --check image.tar.sha256",
        "docker load --input image.tar",
        "Promote the loaded tested image",
    ):
        if required not in publish_platform:
            violations.append(f"Docker publish-platform job is missing {required!r}")
    validation_index = publish_platform.find("Verify and load tested image artifact")
    login_index = publish_platform.find("Log in to GitHub Container Registry")
    if validation_index < 0 or login_index < 0 or validation_index > login_index:
        violations.append("Docker registry login occurs before exact archive validation")

    for required in (
        "needs: [secret-contracts, publish-platform]",
        "published manifest children differ from tested digests",
        "if len(expected) != 2 or len(entries) != 2 or actual != expected or platforms != {",
        "Create and publish multi-arch manifest",
    ):
        if required not in publish_manifest:
            violations.append(f"Docker publish-manifest job is missing {required!r}")

    dependencies = {name: workflow_job_needs(block) for name, block in jobs.items()}

    def depends_on_verification(job: str, seen: set[str] | None = None) -> bool:
        if job == "verify-smoke":
            return True
        seen = set() if seen is None else seen
        if job in seen:
            return False
        seen.add(job)
        return any(
            depends_on_verification(dependency, seen.copy())
            for dependency in dependencies.get(job, set())
        )

    for name, block in jobs.items():
        if any(
            marker in block
            for marker in (
                "docker/login-action@",
                "docker push",
                "docker buildx imagetools create",
                "/visibility",
            )
        ) and not depends_on_verification(name):
            violations.append(
                f"Docker publication job {name!r} does not depend on release verification"
            )
        if job_has_packages_write(block) and name not in {
            "publish-platform",
            "publish-manifest",
        }:
            violations.append(
                f"Docker pre-validation job {name!r} unexpectedly has packages:write"
            )
    return violations


def check_publish_workflow_text(workflow: str) -> list[str]:
    violations: list[str] = []
    jobs = workflow_job_blocks(workflow)
    top_level = workflow.split("\njobs:\n", 1)[0]
    if re.search(r"^  packages:\s*write\s*$", top_level, re.MULTILINE):
        violations.append("Docker publication workflow grants packages:write before job validation")

    violations.extend(action_refs_are_immutable(workflow))
    if "verify-smoke" in jobs:
        return check_protected_artifact_workflow(workflow, jobs, violations)
    if workflow.count("docker/build-push-action@") != 1:
        violations.append(
            "Docker publication workflow must contain exactly one matrixed image build step"
        )
    build = jobs.get("build-platform")
    closure = jobs.get("release-closure")
    publish_platform = jobs.get("publish-platform")
    publish_manifest = jobs.get("publish-manifest")
    for name, block in (
        ("build-platform", build),
        ("release-closure", closure),
        ("publish-platform", publish_platform),
        ("publish-manifest", publish_manifest),
    ):
        if block is None:
            violations.append(f"Docker publication workflow is missing the {name} job")
        elif re.search(r"^\s+continue-on-error:", block, re.MULTILINE):
            violations.append(
                f"Docker publication job {name!r} must not ignore step or job failures"
            )

    if build is not None:
        build_step = workflow_named_step(build, "Build platform image exactly once")
        if build_step is None:
            violations.append("Docker build-platform job is missing its one-time build step")
        else:
            if (
                "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8"
                not in build_step
            ):
                violations.append(
                    "Docker one-time platform build is missing the immutable build action"
                )
            input_names = workflow_step_input_names(build_step)
            if len(input_names) != len(EXPECTED_BUILD_INPUTS) or set(
                input_names
            ) != EXPECTED_BUILD_INPUTS:
                violations.append(
                    "Docker one-time platform build inputs differ from the reviewed exact set"
                )
            for name, expected in (
                ("context", "."),
                ("platforms", "${{ matrix.platform }}"),
                (
                    "tags",
                    "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ env.CANDIDATE_TAG }}-${{ matrix.artifact }}",
                ),
                (
                    "outputs",
                    "type=docker,dest=${{ runner.temp }}/splendor-${{ matrix.artifact }}.tar",
                ),
            ):
                if workflow_step_scalar_inputs(build_step, name) != [expected]:
                    violations.append(
                        f"Docker one-time platform build has unexpected {name!r} input"
                    )
            if workflow_step_multiline_input(build_step, "build-args") != EXPECTED_BUILD_ARGS:
                violations.append(
                    "Docker one-time platform build arguments differ from the reviewed exact set"
                )
            if re.search(r"^        if:", build_step, re.MULTILINE):
                violations.append("Docker one-time platform build must not be conditional")
        if job_has_packages_write(build):
            violations.append("Docker build-platform job must remain registry read-only")
        if "name: candidate-${{ matrix.artifact }}-${{ github.run_attempt }}" not in build:
            violations.append("Docker platform candidate artifact is not run-attempt scoped")

    if closure is not None:
        if re.search(r"^    if:", closure, re.MULTILINE):
            violations.append("Docker release-closure job must not be conditional")
        verify_step = workflow_named_step(
            closure, "Verify exact candidate dependency and binary release closure"
        )
        if verify_step is None:
            violations.append("Docker release-closure job is missing exact candidate verification")
        else:
            if verify_step != EXPECTED_RELEASE_VERIFICATION_STEP:
                violations.append(
                    "Docker release-closure verification differs from the reviewed exact command"
                )
            for required in (
                "check-secret-provider-release-closure.py",
                '--image "${CANDIDATE_IMAGE}"',
                '--expected-revision "${GITHUB_SHA}"',
            ):
                if required not in verify_step:
                    violations.append(
                        f"Docker release-closure verification is missing {required!r}"
                    )
            if re.search(r"^        if:", verify_step, re.MULTILINE):
                violations.append("Docker release-closure verification must not be conditional")
        for required in (
            "needs: build-platform",
            "Download immutable platform candidate",
            'sha256sum --check "splendor-${{ matrix.artifact }}.tar.sha256"',
            'docker load --input "${RUNNER_TEMP}/candidate/splendor-${{ matrix.artifact }}.tar"',
            "Smoke test the exact candidate image",
            "validated-${{ matrix.artifact }}.sha256",
            "Upload release-closure receipt",
            "name: candidate-${{ matrix.artifact }}-${{ github.run_attempt }}",
            "name: validated-${{ matrix.artifact }}-${{ github.run_attempt }}",
        ):
            if required not in closure:
                violations.append(
                    f"Docker release-closure job is missing exact-artifact fragment {required!r}"
                )
        if (
            "docker/build-push-action@" in closure
            or "          context:" in closure
            or re.search(r"\bdocker\s+(?:build|buildx\s+build)\b", closure)
        ):
            violations.append("Docker release-closure job must validate, not rebuild, candidates")
        if job_has_packages_write(closure):
            violations.append("Docker release-closure job must remain registry read-only")

    if publish_platform is not None:
        for required in (
            "needs: release-closure",
            "Download exact validated platform candidate",
            "Download release-closure receipt",
            'sha256sum --check "validated-${{ matrix.artifact }}.sha256"',
            "Load exact validated platform image",
            "Recheck exact revision before registry authority",
            "Log in to GitHub Container Registry after validation",
            'docker push "${CANDIDATE_IMAGE}"',
            "name: candidate-${{ matrix.artifact }}-${{ github.run_attempt }}",
            "name: validated-${{ matrix.artifact }}-${{ github.run_attempt }}",
            "name: digests-${{ github.run_attempt }}-${{ matrix.artifact }}",
        ):
            if required not in publish_platform:
                violations.append(
                    f"Docker publish-platform job is missing exact-artifact fragment {required!r}"
                )
        if (
            "docker/build-push-action@" in publish_platform
            or "          context:" in publish_platform
            or re.search(r"\bdocker\s+(?:build|buildx\s+build)\b", publish_platform)
        ):
            violations.append("Docker publish-platform job must publish, not rebuild, candidates")
        if not job_has_packages_write(publish_platform):
            violations.append("Docker publish-platform job lacks scoped packages:write")
        checksum_step = workflow_named_step(
            publish_platform, "Verify exact validated archive before registry authority"
        )
        if checksum_step is None or "sha256sum --check" not in checksum_step:
            violations.append(
                "Docker publish-platform job lacks exact validated archive checksum enforcement"
            )
        elif re.search(r"^        if:", checksum_step, re.MULTILINE):
            violations.append("Docker publish-platform checksum enforcement must not be conditional")
        validation_index = publish_platform.find(
            "Verify exact validated archive before registry authority"
        )
        login_index = publish_platform.find("Log in to GitHub Container Registry after validation")
        if validation_index < 0 or login_index < 0 or validation_index > login_index:
            violations.append("Docker registry login occurs before exact archive validation")

    if publish_manifest is not None:
        if "needs: publish-platform" not in publish_manifest:
            violations.append("Docker publish-manifest job does not depend on platform publication")
        if not job_has_packages_write(publish_manifest):
            violations.append("Docker publish-manifest job lacks scoped packages:write")
        if "pattern: digests-${{ github.run_attempt }}-*" not in publish_manifest:
            violations.append("Docker manifest digest selection is not run-attempt scoped")
        manifest_validation = workflow_named_step(
            publish_manifest, "Validate exact published digest set before registry login"
        )
        if (
            manifest_validation is None
            or '"${#digests[@]}" -ne 2' not in manifest_validation
            or "^[0-9a-f]{64}$" not in manifest_validation
        ):
            violations.append("Docker manifest publication lacks exact two-digest validation")
        elif re.search(r"^        if:", manifest_validation, re.MULTILINE):
            violations.append("Docker manifest digest validation must not be conditional")
        manifest_validation_index = publish_manifest.find(
            "Validate exact published digest set before registry login"
        )
        manifest_login_index = publish_manifest.find("Log in to GitHub Container Registry")
        if (
            manifest_validation_index < 0
            or manifest_login_index < 0
            or manifest_validation_index > manifest_login_index
        ):
            violations.append("Docker manifest registry login occurs before digest validation")

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
        if job_has_packages_write(block) and name not in {
            "publish-platform",
            "publish-manifest",
        }:
            violations.append(
                f"Docker pre-validation job {name!r} unexpectedly has packages:write"
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
        workflow_path = args.repo_root.resolve() / PUBLISH_WORKFLOW
        workflow = workflow_path.read_text()
        assert check_publish_workflow_text(workflow) == []

        mutations = {
            "conditional_verification": workflow.replace(
                "      - name: Verify exact candidate dependency and binary release closure\n        env:",
                "      - name: Verify exact candidate dependency and binary release closure\n        if: ${{ false }}\n        env:",
                1,
            ),
            "disabled_verification": workflow.replace(
                "          python3 scripts/architecture/check-secret-provider-release-closure.py \\",
                "          true # exact candidate verification disabled \\",
                1,
            ),
            "ignored_verification_failure": workflow.replace(
                "      - name: Verify exact candidate dependency and binary release closure\n        env:",
                "      - name: Verify exact candidate dependency and binary release closure\n        continue-on-error: true\n        env:",
                1,
            ),
            "verification_shell_bypass": workflow.replace(
                '            --expected-revision "${GITHUB_SHA}"',
                '            --expected-revision "${GITHUB_SHA}" || true',
                1,
            ),
            "changed_build_context": workflow.replace(
                "          context: .", "          context: ./unvalidated", 1
            ),
            "changed_revision_arg": workflow.replace(
                "            VCS_REF=${{ github.sha }}", "            VCS_REF=untrusted", 1
            ),
            "changed_image_version_arg": workflow.replace(
                f"            SPLENDOR_IMAGE_VERSION={IMAGE_VERSION_EXPRESSION}",
                "            SPLENDOR_IMAGE_VERSION=unvalidated",
                1,
            ),
            "extra_build_arg": workflow.replace(
                "            BUILD_DATE=${{ steps.build-date.outputs.created }}",
                "            BUILD_DATE=${{ steps.build-date.outputs.created }}\n            UNVALIDATED_BUILD_INPUT=true",
                1,
            ),
            "publish_rebuild": workflow.replace(
                "      - name: Download exact validated platform candidate",
                "      - name: Rebuild unchecked candidate\n        uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8\n        with:\n          context: ./unvalidated\n      - name: Download exact validated platform candidate",
                1,
            ),
            "pre_gate_registry_authority": workflow.replace(
                "  release-closure:\n    needs: build-platform\n    permissions:\n      contents: read",
                "  release-closure:\n    needs: build-platform\n    permissions:\n      contents: read\n      packages: write",
                1,
            ),
            "mutable_action_ref": workflow.replace(
                "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
                "docker/setup-buildx-action@v3",
                1,
            ),
            "publish_without_validated_checksum": workflow.replace(
                'sha256sum --check "validated-${{ matrix.artifact }}.sha256"',
                'true # checksum deliberately bypassed',
                1,
            ),
            "cross_attempt_candidate_artifact": workflow.replace(
                "name: candidate-${{ matrix.artifact }}-${{ github.run_attempt }}",
                "name: candidate-${{ matrix.artifact }}",
                1,
            ),
            "cross_attempt_manifest_digest_selection": workflow.replace(
                "pattern: digests-${{ github.run_attempt }}-*",
                "pattern: digests-*",
                1,
            ),
            "manifest_without_exact_digest_validation": workflow.replace(
                '          if [ "${#digests[@]}" -ne 2 ]; then',
                '          if false; then',
                1,
            ),
        }
        if "  verify-smoke:\n" in workflow:
            mutations = {
                "conditional_verification": workflow.replace(
                    "      - name: Verify exact candidate dependency and binary release closure\n        env:",
                    "      - name: Verify exact candidate dependency and binary release closure\n        if: ${{ false }}\n        env:",
                    1,
                ),
                "disabled_verification": workflow.replace(
                    "          python3 scripts/architecture/check-secret-provider-release-closure.py \\",
                    "          true # exact candidate verification disabled \\",
                    1,
                ),
                "ignored_verification_failure": workflow.replace(
                    "      - name: Verify exact candidate dependency and binary release closure\n        env:",
                    "      - name: Verify exact candidate dependency and binary release closure\n        continue-on-error: true\n        env:",
                    1,
                ),
                "verification_shell_bypass": workflow.replace(
                    '            --expected-revision "${GITHUB_SHA}"',
                    '            --expected-revision "${GITHUB_SHA}" || true',
                    1,
                ),
                "changed_build_context": workflow.replace(
                    "          context: .", "          context: ./unvalidated", 1
                ),
                "changed_revision_arg": workflow.replace(
                    "            VCS_REF=${{ github.sha }}",
                    "            VCS_REF=untrusted",
                    1,
                ),
                "changed_image_version_arg": workflow.replace(
                    f"            SPLENDOR_IMAGE_VERSION={IMAGE_VERSION_EXPRESSION}",
                    "            SPLENDOR_IMAGE_VERSION=unvalidated",
                    1,
                ),
                "extra_build_arg": workflow.replace(
                    "            BUILD_DATE=${{ steps.build-date.outputs.created }}",
                    "            BUILD_DATE=${{ steps.build-date.outputs.created }}\n            UNVALIDATED_BUILD_INPUT=true",
                    1,
                ),
                "publish_rebuild": workflow.replace(
                    "      - name: Download tested image artifact",
                    "      - name: Rebuild unchecked candidate\n        uses: docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8\n        with:\n          context: ./unvalidated\n      - name: Download tested image artifact",
                    1,
                ),
                "pre_gate_registry_authority": workflow.replace(
                    "  verify-smoke:\n    needs: [secret-contracts, smoke]",
                    "  verify-smoke:\n    needs: [secret-contracts, smoke]\n    permissions:\n      contents: read\n      packages: write",
                    1,
                ),
                "mutable_action_ref": workflow.replace(
                    "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
                    "docker/setup-buildx-action@v3",
                    1,
                ),
                "publish_without_validated_checksum": workflow.replace(
                    "          sha256sum --check image.tar.sha256",
                    "          true # checksum deliberately bypassed",
                    1,
                ),
                "manifest_without_exact_digest_validation": workflow.replace(
                    '          if len(expected) != 2 or len(entries) != 2 or actual != expected or platforms != {',
                    "          if False:",
                    1,
                ),
            }
        for name, mutated in mutations.items():
            assert mutated != workflow, name
            assert check_publish_workflow_text(mutated), name
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
