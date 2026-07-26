#!/usr/bin/env python3
"""FND-002 current-baseline Rust dependency policy guard.

This is intentionally a narrow 0.1-baseline smoke guard, not the full v2
package ownership split. It closes the exact current Cargo workspace package
identities, binds every governed dependency name to its canonical local
manifest, keeps repository-local path dependencies inside that governance,
checks direct non-dev package edges, and deterministically detects internal
cycles across all direct package edges. It deliberately does not read or enforce
docs/rules/v2/catalog/architecture/dependency_policy.proposed.json or inspect
Rust source effects.
"""

from __future__ import annotations

import argparse
import copy
import errno
import json
import posixpath
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


# Exact package identities governed by this current-baseline guard. Package name
# alone is insufficient: excluding or relocating a repository package must not
# turn it into an ungoverned external dependency.
EXPECTED_WORKSPACE_PACKAGE_MANIFESTS: dict[str, str] = {
    "splendor-types": "crates/splendor-types/Cargo.toml",
    "splendor-authority": "crates/splendor-authority/Cargo.toml",
    "splendor-kernel": "crates/splendor-kernel/Cargo.toml",
    "splendor-gateway": "crates/splendor-gateway/Cargo.toml",
    "splendor-store": "crates/splendor-store/Cargo.toml",
    "splendor-daemon": "crates/splendor-daemon/Cargo.toml",
    "splendorctl": "crates/splendorctl/Cargo.toml",
    "splendor-adapter-filesystem": "adapters/filesystem/Cargo.toml",
    "splendor-adapter-http": "adapters/http/Cargo.toml",
    "splendor-adapter-robotics": "adapters/robotics/Cargo.toml",
    "splendor-adapter-secrets-local-file": (
        "adapters/secrets-local-file/Cargo.toml"
    ),
    "splendor-adapter-secrets-memory": "adapters/secrets-memory/Cargo.toml",
    "splendor-acceptance-action-host": (
        "tests/e2e/use-cases/acceptance-host/Cargo.toml"
    ),
    "splendor-bindings": "python/bindings/Cargo.toml",
}
EXPECTED_PACKAGE_BY_MANIFEST = {
    manifest: name for name, manifest in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.items()
}


# Direct non-dev workspace package dependencies allowed for the current 0.1
# compatibility baseline.  These entries deliberately cover existing packages
# only; proposed v2 plane crates are RFC-gated and are not required by this
# guard.
ALLOWED_INTERNAL_DEPS: dict[str, set[str]] = {
    "splendor-types": set(),
    "splendor-store": {"splendor-types"},
    "splendor-authority": {"splendor-types", "splendor-store"},
    "splendor-gateway": {"splendor-types", "splendor-authority"},
    "splendor-kernel": {
        "splendor-types",
        "splendor-store",
        "splendor-gateway",
        "splendor-authority",
    },
    "splendor-daemon": {
        "splendor-types",
        "splendor-store",
        "splendor-gateway",
        "splendor-kernel",
    },
    "splendorctl": {
        "splendor-types",
        "splendor-store",
        "splendor-gateway",
        "splendor-kernel",
        "splendor-adapter-filesystem",
        "splendor-adapter-http",
    },
    "splendor-bindings": {"splendor-kernel"},
    "splendor-acceptance-action-host": {
        "splendor-daemon",
        "splendor-gateway",
        "splendor-types",
    },
}

ADAPTER_ALLOWED_INTERNAL_DEPS = {"splendor-types", "splendor-gateway"}
SECRET_PROVIDER_ALLOWED_INTERNAL_DEPS = {"splendor-types", "splendor-authority"}
LOCAL_FILE_SECRET_PROVIDER_PACKAGE = "splendor-adapter-secrets-local-file"
LOCAL_FILE_SECRET_PROVIDER_FEATURE = "local-file-secret-provider"
SECRET_PROVIDER_TEST_SUPPORT_FEATURE = "secret-provider-test-support"
LOCAL_FILE_SECRET_PROVIDER_EXPECTED_FEATURES = {
    "default": [],
    LOCAL_FILE_SECRET_PROVIDER_FEATURE: [],
}
LOCAL_FILE_SECRET_PROVIDER_EXPECTED_PRODUCTION_DEPS = {
    "libc",
    "splendor-authority",
    "splendor-types",
    "zeroize",
}
CHECKED_DEP_KINDS = {None, "build"}
CARGO_METADATA_COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--format-version",
    "1",
    "--no-deps",
)
# Current capability-bearing HTTP clients are closed to their existing package
# owners. This is package metadata enforcement, not source-effect analysis.
PROVIDER_CLIENT_OWNERS = {
    "reqwest": {"splendor-daemon"},
    "ureq": {"splendor-adapter-http", "splendor-acceptance-action-host"},
}
DAEMON_ALLOWED_EXTERNAL_DEPS = {
    "axum",
    "axum-server",
    "base64",
    "libc",
    "reqwest",  # Accepted only in the exact RFC-0011 dependency shape below.
    "ring",
    "serde",
    "serde_json",
    "thiserror",
    "time",
    "tokio",
    "uuid",
}

CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
DAEMON_EXPECTED_TARGETS = {
    ("lib", "splendor_daemon", "crates/splendor-daemon/src/lib.rs"),
    ("bin", "splendor-daemon", "crates/splendor-daemon/src/main.rs"),
    (
        "bin",
        "splendor-manager",
        "crates/splendor-daemon/src/bin/splendor-manager.rs",
    ),
    (
        "example",
        "resident_auth_key_tool",
        "crates/splendor-daemon/examples/resident_auth_key_tool.rs",
    ),
}
DAEMON_CLOSED_TARGET_KINDS = {"lib", "bin", "example", "custom-build"}
DAEMON_EXPECTED_PACKAGE_FEATURES: dict[str, list[str]] = {}


def daemon_registry_dependency(
    name: str,
    requirement: str,
    *,
    features: tuple[str, ...] = (),
    uses_default_features: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "rename": None,
        "kind": None,
        "target": None,
        "optional": False,
        "uses_default_features": uses_default_features,
        "features": tuple(sorted(features)),
        "req": requirement,
        "source": CRATES_IO_SOURCE,
        "path": None,
    }


def daemon_path_dependency(name: str, path: str) -> dict[str, Any]:
    return {
        "name": name,
        "rename": None,
        "kind": None,
        "target": None,
        "optional": False,
        "uses_default_features": True,
        "features": (),
        "req": "*",
        "source": None,
        "path": path,
    }


DAEMON_EXPECTED_PRODUCTION_DEPENDENCIES = {
    item["name"]: item
    for item in [
        daemon_registry_dependency("axum", "^0.7"),
        daemon_registry_dependency(
            "axum-server", "^0.8", features=("tls-rustls-no-provider",)
        ),
        daemon_registry_dependency("base64", "^0.22"),
        daemon_registry_dependency("libc", "^0.2"),
        daemon_registry_dependency(
            "reqwest",
            "^0.12",
            features=("json", "rustls-tls"),
            uses_default_features=False,
        ),
        daemon_registry_dependency("ring", "^0.17"),
        daemon_registry_dependency("serde", "^1.0", features=("derive",)),
        daemon_registry_dependency("serde_json", "^1.0"),
        daemon_path_dependency("splendor-gateway", "crates/splendor-gateway"),
        daemon_path_dependency("splendor-kernel", "crates/splendor-kernel"),
        daemon_path_dependency("splendor-store", "crates/splendor-store"),
        daemon_path_dependency("splendor-types", "crates/splendor-types"),
        daemon_registry_dependency("thiserror", "^1.0"),
        daemon_registry_dependency(
            "time", "^0.3", features=("serde", "serde-well-known")
        ),
        daemon_registry_dependency(
            "tokio", "^1", features=("macros", "net", "rt-multi-thread", "time")
        ),
        daemon_registry_dependency(
            "uuid", "^1.7", features=("serde", "v4", "v5")
        ),
    ]
}

RULE_NOTES: dict[str, str] = {
    "splendor-types": "splendor-types is behavior-free canonical IDs/schemas; it must not depend on other internal packages.",
    "splendor-store": "splendor-store is persistence-only; current baseline allows only splendor-types directly.",
    "splendor-authority": "RFC 0009 / IDR-001 allows splendor-authority to own identity lifecycle decisions over types and storage-only registry persistence.",
    "splendor-gateway": "splendor-gateway is the action/driver boundary; AUTH-004b allows the narrow splendor-authority edge to validate obligation receipts before adapter invocation.",
    "splendor-kernel": "splendor-kernel is the compatibility composition root; RFC 0010 AUTH-003b allows the bounded local delegation authority bridge in addition to types/store/gateway.",
    "splendor-daemon": "MIG-137-DAEMON-STORES-GATEWAY allows the existing daemon -> kernel/store/gateway/types composition seam only.",
    "splendorctl": "MIG-137-CLI-EMBEDDED-LOCAL allows existing embedded-local CLI edges to kernel/store/gateway/types and filesystem/http adapters only.",
    "splendor-bindings": "Python bindings may bind the kernel facade directly; transitive core deps must remain Cargo transitive, not direct.",
    "splendor-acceptance-action-host": "CORR-001 permits this exact unpublished non-production outer host to compose the daemon with its controlled acceptance adapter; it must not become a production dependency.",
    "adapter": "Adapter crates may directly depend only on splendor-types and splendor-gateway; no adapter -> kernel/store/daemon/adapter core edge.",
    "secret_provider": "RFC 0012 permits only adapters/secrets-* -> splendor-authority + splendor-types; secret providers may not import gateway/kernel/store/daemon/node or another adapter.",
}


@dataclass(frozen=True)
class Violation:
    message: str


@dataclass(frozen=True)
class MetadataPathResolution:
    relative: str | None
    display: str | None
    error: str | None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check current-baseline Splendor Rust package dependency policy."
    )
    parser.add_argument(
        "--metadata-json",
        type=Path,
        help="Read cargo metadata JSON from a file instead of invoking cargo metadata.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root used when invoking cargo metadata (default: cwd).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in invalid-fixture checks and exit.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    try:
        metadata = load_metadata(args)
    except RuntimeError as exc:
        print(f"FND-002 dependency policy: ERROR: {exc}", file=sys.stderr)
        return 2

    violations, stats = check_metadata(metadata)
    print_result(violations, stats)
    return 1 if violations else 0


def load_metadata(args: argparse.Namespace) -> dict[str, Any]:
    if args.metadata_json:
        try:
            return json.loads(args.metadata_json.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RuntimeError(f"could not read metadata JSON {args.metadata_json}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid metadata JSON {args.metadata_json}: {exc}") from exc

    command = list(CARGO_METADATA_COMMAND)
    try:
        completed = subprocess.run(
            command,
            cwd=args.repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("cargo was not found while running cargo metadata") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"cargo metadata failed with exit {completed.returncode}: {detail}"
        )

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"cargo metadata returned invalid JSON: {exc}") from exc


def check_metadata(metadata: dict[str, Any]) -> tuple[list[Violation], dict[str, int]]:
    path_violations = metadata_path_violations(metadata)
    if path_violations:
        return sorted(path_violations, key=lambda item: item.message), {
            "workspace_packages": 0,
            "checked_internal_edges": 0,
            "cycle_internal_edges": 0,
            "ignored_dev_internal_edges": 0,
        }

    workspace_packages = get_workspace_packages(metadata)
    policy_packages = get_policy_packages(metadata)
    policy_names = {package["name"] for package in policy_packages}
    known_internal_names = set(EXPECTED_WORKSPACE_PACKAGE_MANIFESTS) | policy_names
    governed_member_names = {
        package["name"]
        for package in workspace_packages
        if package["name"] in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS
        and package_manifest_identity(package, metadata)
        == EXPECTED_WORKSPACE_PACKAGE_MANIFESTS[package["name"]]
    }

    violations = workspace_identity_violations(metadata, workspace_packages)
    violations.extend(governed_package_record_violations(metadata))
    violations.extend(
        development_secret_provider_surface_violations(policy_packages)
    )
    checked_edges: dict[str, list[tuple[str, str]]] = {
        name: [] for name in known_internal_names
    }
    cycle_edges: dict[str, list[tuple[str, str]]] = {
        name: [] for name in known_internal_names
    }

    for package in sorted(policy_packages, key=lambda pkg: package_sort_key(pkg, metadata)):
        source = package["name"]
        allowed = allowed_deps_for(package)
        if allowed is None:
            violations.append(
                Violation(
                    f"{source}: no current-baseline dependency policy is defined for this workspace package. "
                    "This FND-002 guard covers existing 0.1 crates/adapters only; add an accepted policy/RFC or update this guard deliberately."
                )
            )
            allowed = set()

        for dependency in sorted(
            package.get("dependencies", []), key=dependency_sort_key
        ):
            dep_name = dependency.get("name")
            dep_kind = dependency.get("kind")
            path_resolution = resolve_metadata_path(dependency.get("path"), metadata)
            local_path = path_resolution.relative
            local_target: str | None = None
            governed_identity_matches = False
            expected_manifest = EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.get(dep_name)
            if expected_manifest is not None:
                expected_directory = Path(expected_manifest).parent.as_posix()
                governed_identity_matches = (
                    dependency.get("source") is None
                    and local_path == expected_directory
                )
                if not governed_identity_matches:
                    resolved_directory = (
                        local_path
                        if local_path is not None
                        else (
                            "<outside-workspace>"
                            if path_resolution.display is not None
                            else None
                        )
                    )
                    violations.append(
                        Violation(
                            f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) does not resolve to governed package identity "
                            f"{dep_name!r} at {expected_manifest!r}; expected source=None and repository-relative directory "
                            f"{expected_directory!r}, actual source={dependency.get('source')!r}, declared path={dependency.get('path')!r}, "
                            f"resolved directory={resolved_directory!r}. Governed package names cannot be substituted by registry, Git, outside, missing, or different local packages."
                        )
                    )
            if local_path is not None:
                local_manifest = (Path(local_path) / "Cargo.toml").as_posix()
                local_target = EXPECTED_PACKAGE_BY_MANIFEST.get(local_manifest)
                if local_target is None:
                    violations.append(
                        Violation(
                            f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) is an unmodeled repository-local path dependency at {local_path!r}; "
                            f"no governed workspace package identity matches {local_manifest!r}. All repository-local Rust path dependencies must remain governed workspace members."
                        )
                    )
                elif dep_name != local_target:
                    violations.append(
                        Violation(
                            f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) declares the wrong repository-local package identity for {local_path!r}; "
                            f"expected package {local_target!r} at {local_manifest!r}."
                        )
                    )
                elif local_target not in governed_member_names:
                    violations.append(
                        Violation(
                            f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) is an unmodeled repository-local path dependency at {local_path!r}; "
                            f"expected governed workspace member {local_target!r} at {local_manifest!r}. All repository-local Rust path dependencies must remain governed workspace members."
                        )
                    )

            provider_owners = PROVIDER_CLIENT_OWNERS.get(dep_name)
            if (
                dep_kind != "dev"
                and provider_owners is not None
                and source not in provider_owners
            ):
                accepted_owners = ", ".join(sorted(provider_owners))
                violations.append(
                    Violation(
                        f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) is forbidden by current provider-client ownership. "
                        f"Accepted owners: {accepted_owners}."
                    )
                )

            internal_target = None
            if expected_manifest is not None:
                if governed_identity_matches:
                    internal_target = dep_name
            elif local_target is not None:
                internal_target = local_target
            elif dep_name in known_internal_names:
                internal_target = dep_name

            if internal_target is None:
                if (
                    expected_manifest is None
                    and source == "splendor-daemon"
                    and dep_kind in CHECKED_DEP_KINDS
                    and dep_name not in DAEMON_ALLOWED_EXTERNAL_DEPS
                ):
                    violations.append(
                        Violation(
                            f"splendor-daemon -> {dep_name} ({dependency_kind_label(dependency)} dependency) is forbidden. "
                            "Daemon production external dependencies are closed; provider clients belong in adapters/* or an explicit outer host."
                        )
                    )
                continue

            cycle_edges.setdefault(source, []).append(
                (internal_target, dependency_kind_label(dependency))
            )
            if dep_kind == "dev":
                continue
            if dep_kind not in CHECKED_DEP_KINDS:
                # Unknown future dependency kinds are safer to check than to silently skip.
                dep_kind_label = dependency_kind_label(dependency)
                violations.append(
                    Violation(
                        f"{source} -> {dep_name} ({dep_kind_label} dependency) uses an unknown dependency kind; "
                        "update scripts/architecture/check-dependency-policy.py before relying on this edge."
                    )
                )
                continue

            checked_edges.setdefault(source, []).append(
                (internal_target, dependency_kind_label(dependency))
            )
            if internal_target not in allowed:
                violations.append(
                    forbidden_edge_violation(package, internal_target, dependency)
                )

        if source == "splendor-daemon":
            violations.extend(daemon_closure_violations(package, metadata))

    checked_edges = normalize_edge_map(checked_edges)
    cycle_edges = normalize_edge_map(cycle_edges)
    ignored_dev_edges = sum(
        kind == "dev" for targets in cycle_edges.values() for _target, kind in targets
    )
    violations.extend(cycle_violations(cycle_edges))
    stats = {
        "workspace_packages": len(workspace_packages),
        "checked_internal_edges": sum(len(edges) for edges in checked_edges.values()),
        "cycle_internal_edges": sum(len(edges) for edges in cycle_edges.values()),
        "ignored_dev_internal_edges": ignored_dev_edges,
    }
    return sorted(violations, key=lambda item: item.message), stats


def get_workspace_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    packages_by_id: dict[Any, list[dict[str, Any]]] = {}
    for package in metadata.get("packages", []):
        packages_by_id.setdefault(package.get("id"), []).append(package)
    packages = [
        package
        for member_id in metadata.get("workspace_members") or []
        for package in packages_by_id.get(member_id, [])
    ]
    return sorted(packages, key=lambda package: package_sort_key(package, metadata))


def workspace_identity_violations(
    metadata: dict[str, Any], workspace_packages: list[dict[str, Any]]
) -> list[Violation]:
    violations: list[Violation] = []
    package_ids = {package.get("id") for package in metadata.get("packages", [])}
    missing_member_ids = count_names(
        str(member_id)
        for member_id in metadata.get("workspace_members") or []
        if member_id not in package_ids
    )
    for member_id, count in sorted(missing_member_ids.items()):
        violations.append(
            Violation(
                f"workspace member id {member_id!r} appears {count} time(s) but has no package metadata entry; workspace identity cannot be governed."
            )
        )

    packages_by_name: dict[str, list[dict[str, Any]]] = {}
    for package in workspace_packages:
        packages_by_name.setdefault(str(package.get("name")), []).append(package)

    for name, expected_manifest in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.items():
        packages = packages_by_name.get(name, [])
        actual_manifests = sorted(
            (package_manifest_identity(package, metadata) for package in packages),
            key=lambda manifest: str(manifest),
        )
        if not packages:
            violations.append(
                Violation(
                    f"required workspace package {name!r} at {expected_manifest!r} is missing from workspace_members; workspace exclusion cannot remove it from dependency governance."
                )
            )
        elif len(packages) > 1:
            violations.append(
                Violation(
                    f"required workspace package {name!r} appears {len(packages)} times in workspace_members with manifest identities {actual_manifests!r}; "
                    f"expected exactly once at {expected_manifest!r}."
                )
            )
        elif actual_manifests[0] != expected_manifest:
            violations.append(
                Violation(
                    f"workspace package {name!r} has unexpected manifest identity {actual_manifests[0]!r}; expected {expected_manifest!r}."
                )
            )

    unexpected_counts: dict[tuple[str, str | None], int] = {}
    for package in workspace_packages:
        name = str(package.get("name"))
        if name in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS:
            continue
        identity = (name, package_manifest_identity(package, metadata))
        unexpected_counts[identity] = unexpected_counts.get(identity, 0) + 1
    for (name, manifest), count in sorted(
        unexpected_counts.items(), key=lambda item: (item[0][0], str(item[0][1]))
    ):
        violations.append(
            Violation(
                f"unexpected workspace package identity {name!r} at {manifest!r} appears {count} time(s); "
                "current-baseline governance requires every workspace member to have an explicit expected package name and manifest path."
            )
        )
    return violations


def governed_package_record_violations(
    metadata: dict[str, Any],
) -> list[Violation]:
    packages = list(metadata.get("packages", []))
    manifests = [package_manifest_identity(package, metadata) for package in packages]
    records_by_id: dict[str, list[int]] = {}
    for index, package in enumerate(packages):
        package_id = package.get("id")
        if package_id is not None:
            records_by_id.setdefault(str(package_id), []).append(index)

    violations: list[Violation] = []
    for name, expected_manifest in sorted(EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.items()):
        name_records = {
            index
            for index, package in enumerate(packages)
            if package.get("name") == name
        }
        manifest_records = {
            index
            for index, manifest in enumerate(manifests)
            if manifest == expected_manifest
        }
        related_records = name_records | manifest_records
        duplicate_ids = {
            str(packages[index].get("id"))
            for index in related_records
            if packages[index].get("id") is not None
            and len(records_by_id.get(str(packages[index].get("id")), [])) > 1
        }
        if (
            len(name_records) <= 1
            and len(manifest_records) <= 1
            and (len(related_records) <= 1 or name_records == manifest_records)
            and not duplicate_ids
        ):
            continue

        ambiguous_records = set(related_records)
        for package_id in duplicate_ids:
            ambiguous_records.update(records_by_id[package_id])
        descriptors = sorted(
            package_identity_descriptor(packages[index], manifests[index])
            for index in ambiguous_records
        )
        violations.append(
            Violation(
                f"governed package identity {name!r} at {expected_manifest!r} is ambiguous across "
                f"{len(ambiguous_records)} package metadata records [{'; '.join(descriptors)}]; "
                "expected one canonical name/manifest record and no duplicate package id."
            )
        )
    return violations


def package_identity_descriptor(
    package: dict[str, Any], manifest: str | None
) -> str:
    return json.dumps(
        {
            "id": package.get("id"),
            "manifest": manifest,
            "name": package.get("name"),
            "source": package.get("source"),
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def get_policy_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    member_ids = set(metadata.get("workspace_members") or [])
    candidates = [
        package
        for package in metadata.get("packages", [])
        if package.get("id") in member_ids
        or package.get("name") in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS
        or package_manifest_identity(package, metadata) in EXPECTED_PACKAGE_BY_MANIFEST
    ]
    return sorted(candidates, key=lambda package: package_sort_key(package, metadata))


def package_sort_key(
    package: dict[str, Any], metadata: dict[str, Any]
) -> tuple[str, str, str, str]:
    return (
        str(package.get("name")),
        str(package_manifest_identity(package, metadata)),
        str(package.get("id")),
        json.dumps(package, sort_keys=True, separators=(",", ":"), default=str),
    )


def dependency_sort_key(dependency: dict[str, Any]) -> str:
    return json.dumps(
        dependency, sort_keys=True, separators=(",", ":"), default=str
    )


def package_manifest_identity(
    package: dict[str, Any], metadata: dict[str, Any]
) -> str | None:
    return relative_metadata_path(package.get("manifest_path"), metadata)


def metadata_path_violations(metadata: dict[str, Any]) -> list[Violation]:
    root_probe = resolve_metadata_path(".", metadata)
    if root_probe.error is not None:
        return [
            Violation(
                f"Cargo metadata workspace_root {metadata.get('workspace_root')!r} cannot be resolved: "
                f"{root_probe.error}. Package identity checks fail closed."
            )
        ]

    path_fields: list[tuple[str, Any]] = []
    for package in metadata.get("packages", []):
        package_context = (
            f"package {package.get('name')!r} (id {package.get('id')!r})"
        )
        path_fields.append(
            (f"{package_context} manifest_path", package.get("manifest_path"))
        )
        for dependency in package.get("dependencies", []):
            if dependency.get("path") is None:
                continue
            dependency_context = (
                f"{package_context} dependency {dependency.get('name')!r} "
                f"({dependency_kind_label(dependency)}, rename={dependency.get('rename')!r})"
            )
            path_fields.append((dependency_context, dependency.get("path")))
        for target in package.get("targets", []):
            if target.get("src_path") is None:
                continue
            target_context = (
                f"{package_context} target {target.get('name')!r} "
                f"(kind={sorted(target.get('kind') or [])!r})"
            )
            path_fields.append((target_context, target.get("src_path")))

    violations: list[Violation] = []
    for context, raw in sorted(path_fields, key=lambda item: (item[0], repr(item[1]))):
        resolution = resolve_metadata_path(raw, metadata)
        if resolution.error is not None:
            violations.append(
                Violation(
                    f"Cargo metadata path for {context} cannot be resolved from {raw!r}: "
                    f"{resolution.error}. Package identity checks fail closed."
                )
            )
    return violations


def resolve_metadata_path(
    raw: Any, metadata: dict[str, Any]
) -> MetadataPathResolution:
    root_raw = metadata.get("workspace_root")
    if not isinstance(root_raw, str) or not root_raw:
        return MetadataPathResolution(
            None, None, "workspace_root must be a non-empty path string"
        )
    if raw is None:
        return MetadataPathResolution(None, None, None)
    if not isinstance(raw, str) or not raw:
        return MetadataPathResolution(
            None, None, "path value must be a non-empty string"
        )
    if "\x00" in root_raw or "\x00" in raw:
        return MetadataPathResolution(
            None, None, "path contains an embedded NUL byte"
        )

    root_path = Path(root_raw)
    if not root_path.is_absolute():
        return resolve_lexical_metadata_path(raw, root_raw)

    try:
        resolved_root = root_path.resolve(strict=False)
        path = Path(raw)
        if not path.is_absolute():
            path = resolved_root / path
        resolved_path = path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        return MetadataPathResolution(None, None, path_resolution_error(exc))

    try:
        relative = resolved_path.relative_to(resolved_root).as_posix()
    except ValueError:
        relative = None
    return MetadataPathResolution(relative, resolved_path.as_posix(), None)


def resolve_lexical_metadata_path(
    raw: str, root_raw: str
) -> MetadataPathResolution:
    normalized_root = posixpath.normpath(root_raw)
    normalized_path = posixpath.normpath(
        raw if posixpath.isabs(raw) else posixpath.join(normalized_root, raw)
    )
    try:
        relative = PurePosixPath(normalized_path).relative_to(
            PurePosixPath(normalized_root)
        ).as_posix()
    except ValueError:
        relative = None
    return MetadataPathResolution(relative, normalized_path, None)


def path_resolution_error(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) or (
        isinstance(exc, OSError) and exc.errno == errno.ELOOP
    ):
        return "symlink loop or recursive path resolution"
    if isinstance(exc, OSError):
        return "filesystem path resolution error"
    return "invalid path value"


def relative_metadata_path(raw: Any, metadata: dict[str, Any]) -> str | None:
    resolution = resolve_metadata_path(raw, metadata)
    if resolution.error is not None:
        return None
    if resolution.relative is not None:
        return resolution.relative
    return resolution.display


def repository_relative_path(
    raw: Any, metadata: dict[str, Any]
) -> str | None:
    resolution = resolve_metadata_path(raw, metadata)
    if resolution.error is not None:
        return None
    return resolution.relative


def daemon_dependency_shape(
    dependency: dict[str, Any], metadata: dict[str, Any]
) -> dict[str, Any]:
    return {
        "name": dependency.get("name"),
        "rename": dependency.get("rename"),
        "kind": dependency.get("kind"),
        "target": dependency.get("target"),
        "optional": dependency.get("optional"),
        "uses_default_features": dependency.get("uses_default_features"),
        "features": tuple(sorted(dependency.get("features") or [])),
        "req": dependency.get("req"),
        "source": dependency.get("source"),
        "path": relative_metadata_path(dependency.get("path"), metadata),
    }


def daemon_closure_violations(
    package: dict[str, Any], metadata: dict[str, Any]
) -> list[Violation]:
    violations: list[Violation] = []
    actual_package_features = package.get("features")
    if actual_package_features != DAEMON_EXPECTED_PACKAGE_FEATURES:
        violations.append(
            Violation(
                "splendor-daemon package feature map changed; dependency feature forwarding is closed: "
                f"expected={DAEMON_EXPECTED_PACKAGE_FEATURES!r} actual={actual_package_features!r}."
            )
        )
    production_dependencies = [
        dependency
        for dependency in package.get("dependencies", [])
        if dependency.get("kind") != "dev"
    ]
    actual_by_name: dict[str, dict[str, Any]] = {}
    for dependency in sorted(production_dependencies, key=dependency_sort_key):
        shape = daemon_dependency_shape(dependency, metadata)
        name = str(shape["name"])
        if name in actual_by_name:
            violations.append(
                Violation(
                    f"splendor-daemon production dependency {name!r} is declared more than once; aliases and duplicate dependency capabilities are forbidden."
                )
            )
            continue
        actual_by_name[name] = shape

    expected_names = set(DAEMON_EXPECTED_PRODUCTION_DEPENDENCIES)
    actual_names = set(actual_by_name)
    for name in sorted(expected_names - actual_names):
        violations.append(
            Violation(
                f"splendor-daemon production dependency {name!r} is missing from the closed declaration."
            )
        )
    for name in sorted(actual_names - expected_names):
        shape = actual_by_name[name]
        violations.append(
            Violation(
                f"splendor-daemon -> {name} ({dependency_kind_label(shape)} dependency) is forbidden by the exact production dependency closure."
            )
        )
    for name in sorted(expected_names & actual_names):
        expected = DAEMON_EXPECTED_PRODUCTION_DEPENDENCIES[name]
        actual = actual_by_name[name]
        changed = [
            field
            for field in (
                "rename",
                "kind",
                "target",
                "optional",
                "uses_default_features",
                "features",
                "req",
                "source",
                "path",
            )
            if actual[field] != expected[field]
        ]
        if changed:
            detail = ", ".join(
                f"{field}: expected={expected[field]!r} actual={actual[field]!r}"
                for field in changed
            )
            violations.append(
                Violation(
                    f"splendor-daemon production dependency {name!r} changed closed fields: {detail}."
                )
            )

    actual_targets: set[tuple[str, str, str | None]] = set()
    for target in package.get("targets", []):
        closed_kinds = set(target.get("kind") or []) & DAEMON_CLOSED_TARGET_KINDS
        for kind in closed_kinds:
            actual_targets.add(
                (
                    kind,
                    str(target.get("name")),
                    relative_metadata_path(target.get("src_path"), metadata),
                )
            )
    for target in sorted(DAEMON_EXPECTED_TARGETS - actual_targets):
        violations.append(
            Violation(f"splendor-daemon closed target is missing: {target!r}.")
        )
    for target in sorted(actual_targets - DAEMON_EXPECTED_TARGETS):
        violations.append(
            Violation(
                f"splendor-daemon target is not in the closed lib/bin/example/build declaration: {target!r}."
            )
        )
    return violations


def development_secret_provider_surface_violations(
    packages: list[dict[str, Any]],
) -> list[Violation]:
    """Keep test/dev provider capabilities out of normal release graphs."""

    violations: list[Violation] = []
    packages_by_name = {str(package.get("name")): package for package in packages}

    authority = packages_by_name.get("splendor-authority")
    if authority is not None:
        authority_features = authority.get("features")
        if not isinstance(authority_features, dict):
            violations.append(
                Violation(
                    "splendor-authority package feature map is unavailable; the default-off secret provider test-support boundary cannot be verified."
                )
            )
        else:
            if authority_features.get("default") != []:
                violations.append(
                    Violation(
                        "splendor-authority default features must remain empty; secret provider test support may never be enabled by default."
                    )
                )
            if authority_features.get(SECRET_PROVIDER_TEST_SUPPORT_FEATURE) != []:
                violations.append(
                    Violation(
                        "splendor-authority secret-provider-test-support must remain an empty, explicit feature with no feature forwarding."
                    )
                )

    provider = packages_by_name.get(LOCAL_FILE_SECRET_PROVIDER_PACKAGE)
    if provider is not None:
        if provider.get("publish") != []:
            violations.append(
                Violation(
                    "splendor-adapter-secrets-local-file must remain publish=false (Cargo metadata publish=[])."
                )
            )
        actual_features = provider.get("features")
        if actual_features != LOCAL_FILE_SECRET_PROVIDER_EXPECTED_FEATURES:
            violations.append(
                Violation(
                    "splendor-adapter-secrets-local-file feature map changed; expected only empty default and explicit local-file-secret-provider features: "
                    f"expected={LOCAL_FILE_SECRET_PROVIDER_EXPECTED_FEATURES!r} actual={actual_features!r}."
                )
            )

        production_dependencies = [
            dependency
            for dependency in provider.get("dependencies", [])
            if dependency.get("kind") != "dev"
        ]
        production_names = [
            str(dependency.get("name")) for dependency in production_dependencies
        ]
        actual_name_set = set(production_names)
        if (
            actual_name_set != LOCAL_FILE_SECRET_PROVIDER_EXPECTED_PRODUCTION_DEPS
            or len(production_names) != len(actual_name_set)
        ):
            violations.append(
                Violation(
                    "splendor-adapter-secrets-local-file production dependency closure changed; "
                    f"expected={sorted(LOCAL_FILE_SECRET_PROVIDER_EXPECTED_PRODUCTION_DEPS)!r} "
                    f"actual={sorted(production_names)!r}."
                )
            )
        for dependency in production_dependencies:
            if dependency.get("name") == "splendor-authority" and (
                dependency.get("features") or []
            ):
                violations.append(
                    Violation(
                        "splendor-adapter-secrets-local-file normal splendor-authority dependency must enable no features; secret provider test support is dev-only."
                    )
                )

    for package in packages:
        authority_dependency_aliases = {
            str(dependency.get("rename") or dependency.get("name"))
            for dependency in package.get("dependencies", [])
            if dependency.get("name") == "splendor-authority"
        }
        for feature_name, activations in (package.get("features") or {}).items():
            for alias in authority_dependency_aliases:
                forbidden_activations = {
                    f"{alias}/{SECRET_PROVIDER_TEST_SUPPORT_FEATURE}",
                    f"{alias}?/{SECRET_PROVIDER_TEST_SUPPORT_FEATURE}",
                }
                if forbidden_activations.intersection(activations):
                    violations.append(
                        Violation(
                            f"{package.get('name')} feature {feature_name!r} may not forward "
                            "splendor-authority secret-provider-test-support; provider test support is dev-only."
                        )
                    )
        for dependency in package.get("dependencies", []):
            if (
                dependency.get("name") == "splendor-authority"
                and dependency.get("kind") != "dev"
                and SECRET_PROVIDER_TEST_SUPPORT_FEATURE
                in (dependency.get("features") or [])
            ):
                violations.append(
                    Violation(
                        f"{package.get('name')} -> splendor-authority "
                        f"({dependency_kind_label(dependency)} dependency) may not enable "
                        "secret-provider-test-support; provider test support is dev-only."
                    )
            )
            if (
                package.get("name") != LOCAL_FILE_SECRET_PROVIDER_PACKAGE
                and dependency.get("name") == LOCAL_FILE_SECRET_PROVIDER_PACKAGE
                and dependency.get("kind") != "dev"
            ):
                violations.append(
                    Violation(
                        f"{package.get('name')} -> {LOCAL_FILE_SECRET_PROVIDER_PACKAGE} "
                        f"({dependency_kind_label(dependency)} dependency) is forbidden: the local-file Secret Provider is development-only and absent from normal release graphs."
                    )
                )

    return violations


def count_names(names: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return counts


def allowed_deps_for(package: dict[str, Any]) -> set[str] | None:
    if is_secret_provider_package(package):
        return set(SECRET_PROVIDER_ALLOWED_INTERNAL_DEPS)
    if is_adapter_package(package):
        return set(ADAPTER_ALLOWED_INTERNAL_DEPS)
    allowed = ALLOWED_INTERNAL_DEPS.get(package["name"])
    if allowed is None:
        return None
    return set(allowed)


def is_adapter_package(package: dict[str, Any]) -> bool:
    if package["name"].startswith("splendor-adapter-"):
        return True
    manifest_path = package.get("manifest_path") or ""
    return "adapters" in Path(manifest_path).parts


def is_secret_provider_package(package: dict[str, Any]) -> bool:
    manifest_path = package.get("manifest_path") or ""
    manifest_dir = Path(manifest_path).parent
    return (
        package["name"].startswith("splendor-adapter-secrets-")
        and manifest_dir.parent.name == "adapters"
        and manifest_dir.name.startswith("secrets-")
    )


def dependency_kind_label(dependency: dict[str, Any]) -> str:
    return dependency.get("kind") or "normal"


def forbidden_edge_violation(
    package: dict[str, Any], dep_name: str, dependency: dict[str, Any]
) -> Violation:
    source = package["name"]
    if is_secret_provider_package(package):
        rule_key = "secret_provider"
    elif is_adapter_package(package):
        rule_key = "adapter"
    else:
        rule_key = source
    note = RULE_NOTES.get(rule_key, "No rule note found; update dependency guard policy.")
    allowed = sorted(allowed_deps_for(package) or [])
    allowed_text = ", ".join(allowed) if allowed else "no internal packages"
    return Violation(
        f"{source} -> {dep_name} ({dependency_kind_label(dependency)} dependency) is forbidden. "
        f"Allowed direct internal deps: {allowed_text}. Rule/exception note: {note}"
    )


def normalize_edge_map(
    edges: dict[str, list[tuple[str, str]]],
) -> dict[str, list[tuple[str, str]]]:
    return {
        source: sorted(set(targets))
        for source, targets in sorted(edges.items())
    }


def cycle_violations(edges: dict[str, list[tuple[str, str]]]) -> list[Violation]:
    adjacency = {
        source: sorted({target for target, _kind in targets})
        for source, targets in sorted(edges.items())
    }
    visited: set[str] = set()
    active: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        visited.add(node)
        active.add(node)
        stack.append(node)
        for target in adjacency.get(node, []):
            if target not in visited:
                visit(target)
            elif target in active:
                start = stack.index(target)
                cycles.append(stack[start:] + [target])
        stack.pop()
        active.remove(node)

    for node in sorted(adjacency):
        if node not in visited:
            visit(node)

    seen: set[tuple[str, ...]] = set()
    for cycle in cycles:
        key = canonical_cycle_key(cycle)
        seen.add(key)

    return [
        Violation(
            "Dependency cycle detected among internal workspace packages: "
            + " -> ".join((*cycle, cycle[0]))
            + ". Rule/exception note: the current-baseline internal workspace graph must remain acyclic."
        )
        for cycle in sorted(seen)
    ]


def canonical_cycle_key(cycle: list[str]) -> tuple[str, ...]:
    # Drop repeated terminal node, rotate to the lexicographically smallest node.
    body = cycle[:-1]
    rotations = [tuple(body[index:] + body[:index]) for index in range(len(body))]
    return min(rotations)


def print_result(violations: list[Violation], stats: dict[str, int]) -> None:
    if violations:
        print("FND-002 current-baseline dependency policy: FAIL")
        for violation in violations:
            print(f"- {violation.message}")
        print(
            "Note: this guard enforces exact current 0.1 Cargo workspace/dependency identities, governed package-record uniqueness, "
            "repository-local path membership, non-dev Rust package allowlists, and internal cycle checks; "
            "it does not inspect Rust source, enforce the proposed v2 JSON dependency policy, require RFC-gated plane crates, "
            "or detect universal duplicate semantic ownership."
        )
        return

    print("FND-002 current-baseline dependency policy: PASS")
    print(
        "Checked {workspace_packages} workspace packages, {checked_internal_edges} direct non-dev internal edges, "
        "and {cycle_internal_edges} direct internal edges for cycles.".format(
            **stats
        )
    )
    if stats["ignored_dev_internal_edges"]:
        print(
            "Ignored {ignored_dev_internal_edges} internal dev-dependency edges for allowlist enforcement; they are still included in cycle detection.".format(
                **stats
            )
        )
    print(
        "Scope: current 0.1 Cargo package/provider metadata only; governed Cargo package-record duplicates are rejected, but "
        "source-wide effect scanning and universal duplicate semantic-owner detection remain out of scope; "
        "proposed v2 plane crates and dependency_policy.proposed.json are not implemented by this guard."
    )


def run_self_test() -> int:
    failures = 0
    expected_metadata_command = (
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    )
    if CARGO_METADATA_COMMAND != expected_metadata_command:
        failures += 1
        print(
            "self-test cargo_metadata_locked_command: FAIL "
            f"(expected {expected_metadata_command!r}, actual {CARGO_METADATA_COMMAND!r})",
            file=sys.stderr,
        )
    else:
        print("self-test cargo_metadata_locked_command: PASS")

    current_fixture = accepted_metadata_fixture()
    current_violations, _stats = check_metadata(current_fixture)
    failures += report_exact_self_test(
        "governed_workspace_current_shape", current_violations, []
    )

    local_provider_default = accepted_metadata_fixture()
    package_named(local_provider_default, LOCAL_FILE_SECRET_PROVIDER_PACKAGE)[
        "features"
    ]["default"] = [LOCAL_FILE_SECRET_PROVIDER_FEATURE]
    failures += report_exact_self_test(
        "local_file_secret_provider_default_feature_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(local_provider_default)
        ),
        [
            "splendor-adapter-secrets-local-file feature map changed; expected only empty default and explicit "
            "local-file-secret-provider features: expected={'default': [], 'local-file-secret-provider': []} "
            "actual={'default': ['local-file-secret-provider'], 'local-file-secret-provider': []}."
        ],
    )

    local_provider_publish = accepted_metadata_fixture()
    package_named(local_provider_publish, LOCAL_FILE_SECRET_PROVIDER_PACKAGE)[
        "publish"
    ] = None
    failures += report_exact_self_test(
        "local_file_secret_provider_publish_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(local_provider_publish)
        ),
        [
            "splendor-adapter-secrets-local-file must remain publish=false (Cargo metadata publish=[])."
        ],
    )

    authority_test_support_default = accepted_metadata_fixture()
    package_named(authority_test_support_default, "splendor-authority")["features"][
        "default"
    ] = [SECRET_PROVIDER_TEST_SUPPORT_FEATURE]
    failures += report_exact_self_test(
        "authority_provider_test_support_default_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(authority_test_support_default)
        ),
        [
            "splendor-authority default features must remain empty; secret provider test support may never be enabled by default."
        ],
    )

    local_provider_normal_test_support = accepted_metadata_fixture()
    dependency_named(
        package_named(
            local_provider_normal_test_support, LOCAL_FILE_SECRET_PROVIDER_PACKAGE
        ),
        "splendor-authority",
    )["features"] = [SECRET_PROVIDER_TEST_SUPPORT_FEATURE]
    failures += report_exact_self_test(
        "local_file_normal_authority_test_support_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(local_provider_normal_test_support)
        ),
        [
            "splendor-adapter-secrets-local-file normal splendor-authority dependency must enable no features; secret provider test support is dev-only.",
            "splendor-adapter-secrets-local-file -> splendor-authority (normal dependency) may not enable secret-provider-test-support; provider test support is dev-only."
        ],
    )

    authority_test_support_release_consumer = accepted_metadata_fixture()
    dependency_named(
        package_named(authority_test_support_release_consumer, "splendor-gateway"),
        "splendor-authority",
    )["features"] = [SECRET_PROVIDER_TEST_SUPPORT_FEATURE]
    failures += report_exact_self_test(
        "authority_provider_test_support_release_consumer_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(authority_test_support_release_consumer)
        ),
        [
            "splendor-gateway -> splendor-authority (normal dependency) may not enable secret-provider-test-support; provider test support is dev-only."
        ],
    )

    authority_test_support_forwarding = accepted_metadata_fixture()
    package_named(authority_test_support_forwarding, "splendor-gateway")["features"] = {
        "default": [],
        "unsafe-test-support": [
            "splendor-authority/secret-provider-test-support"
        ],
    }
    failures += report_exact_self_test(
        "authority_provider_test_support_forwarding_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(authority_test_support_forwarding)
        ),
        [
            "splendor-gateway feature 'unsafe-test-support' may not forward splendor-authority secret-provider-test-support; provider test support is dev-only."
        ],
    )

    local_provider_dependency_widening = accepted_metadata_fixture()
    package_named(
        local_provider_dependency_widening, LOCAL_FILE_SECRET_PROVIDER_PACKAGE
    )["dependencies"].append(
        dependency_fixture("reqwest", repository_local=False)
    )
    failures += report_exact_self_test(
        "local_file_secret_provider_dependency_widening_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(local_provider_dependency_widening)
        ),
        [
            "splendor-adapter-secrets-local-file production dependency closure changed; expected=['libc', "
            "'splendor-authority', 'splendor-types', 'zeroize'] actual=['libc', 'reqwest', "
            "'splendor-authority', 'splendor-types', 'zeroize']."
        ],
    )

    local_provider_release_consumer = accepted_metadata_fixture()
    package_named(local_provider_release_consumer, "splendor-daemon")[
        "dependencies"
    ].append(dependency_fixture(LOCAL_FILE_SECRET_PROVIDER_PACKAGE))
    failures += report_exact_self_test(
        "local_file_secret_provider_release_consumer_rejected",
        development_secret_provider_surface_violations(
            get_policy_packages(local_provider_release_consumer)
        ),
        [
            "splendor-daemon -> splendor-adapter-secrets-local-file (normal dependency) is forbidden: the "
            "local-file Secret Provider is development-only and absent from normal release graphs."
        ],
    )

    missing_outer_host = accepted_metadata_fixture()
    remove_workspace_member(
        missing_outer_host, "splendor-acceptance-action-host"
    )
    failures += report_exact_self_test(
        "required_workspace_package_missing",
        check_metadata(missing_outer_host)[0],
        [
            "required workspace package 'splendor-acceptance-action-host' at "
            "'tests/e2e/use-cases/acceptance-host/Cargo.toml' is missing from workspace_members; "
            "workspace exclusion cannot remove it from dependency governance."
        ],
    )

    changed_manifest = accepted_metadata_fixture()
    package_named(changed_manifest, "splendor-bindings")["manifest_path"] = (
        "python/other-bindings/Cargo.toml"
    )
    failures += report_exact_self_test(
        "required_workspace_manifest_identity_changed",
        check_metadata(changed_manifest)[0],
        [
            "workspace package 'splendor-bindings' has unexpected manifest identity "
            "'python/other-bindings/Cargo.toml'; expected 'python/bindings/Cargo.toml'."
        ],
    )

    duplicate_package = accepted_metadata_fixture()
    append_duplicate_workspace_package(duplicate_package, "splendor-bindings")
    failures += report_exact_self_test(
        "required_workspace_package_duplicated",
        check_metadata(duplicate_package)[0],
        [
            "governed package identity 'splendor-bindings' at 'python/bindings/Cargo.toml' is ambiguous across "
            "2 package metadata records [{\"id\":\"fixture://splendor-bindings#0.1.0\",\"manifest\":\"python/bindings/Cargo.toml\","
            "\"name\":\"splendor-bindings\",\"source\":null}; {\"id\":\"fixture://splendor-bindings#0.1.0-duplicate\","
            "\"manifest\":\"python/bindings/Cargo.toml\",\"name\":\"splendor-bindings\",\"source\":null}]; "
            "expected one canonical name/manifest record and no duplicate package id.",
            "required workspace package 'splendor-bindings' appears 2 times in workspace_members "
            "with manifest identities ['python/bindings/Cargo.toml', 'python/bindings/Cargo.toml']; "
            "expected exactly once at 'python/bindings/Cargo.toml'."
        ],
    )

    duplicate_member_id = accepted_metadata_fixture()
    duplicate_member_id["workspace_members"].append(
        package_named(duplicate_member_id, "splendor-bindings")["id"]
    )
    failures += report_exact_self_test(
        "required_workspace_member_id_duplicated",
        check_metadata(duplicate_member_id)[0],
        [
            "required workspace package 'splendor-bindings' appears 2 times in workspace_members with manifest "
            "identities ['python/bindings/Cargo.toml', 'python/bindings/Cargo.toml']; expected exactly once at "
            "'python/bindings/Cargo.toml'."
        ],
    )

    dangling_member_id = accepted_metadata_fixture()
    dangling_member_id["workspace_members"].append("fixture://missing-package#0.1.0")
    failures += report_exact_self_test(
        "dangling_workspace_member_id",
        check_metadata(dangling_member_id)[0],
        [
            "workspace member id 'fixture://missing-package#0.1.0' appears 1 time(s) but has no package "
            "metadata entry; workspace identity cannot be governed."
        ],
    )

    unexpected_package = accepted_metadata_fixture()
    append_workspace_package(
        unexpected_package,
        "splendor-rogue",
        "tools/rogue/Cargo.toml",
    )
    failures += report_exact_self_test(
        "unexpected_workspace_package_identity",
        check_metadata(unexpected_package)[0],
        [
            "unexpected workspace package identity 'splendor-rogue' at "
            "'tools/rogue/Cargo.toml' appears 1 time(s); current-baseline governance requires "
            "every workspace member to have an explicit expected package name and manifest path.",
            "splendor-rogue: no current-baseline dependency policy is defined for this workspace package. "
            "This FND-002 guard covers existing 0.1 crates/adapters only; add an accepted policy/RFC "
            "or update this guard deliberately.",
        ],
    )

    unmodeled_local_path = accepted_metadata_fixture()
    package_named(unmodeled_local_path, "splendor-kernel")["dependencies"].append(
        dependency_fixture(
            "splendor-rogue-local", path="local/rogue"
        )
    )
    failures += report_exact_self_test(
        "unmodeled_repository_local_path_dependency",
        check_metadata(unmodeled_local_path)[0],
        [
            "splendor-kernel -> splendor-rogue-local (normal dependency) is an unmodeled "
            "repository-local path dependency at 'local/rogue'; no governed workspace package "
            "identity matches 'local/rogue/Cargo.toml'. All repository-local Rust path dependencies "
            "must remain governed workspace members."
        ],
    )

    governed_outside_path = accepted_metadata_fixture()
    dependency_named(
        package_named(governed_outside_path, "splendor-adapter-http"),
        "splendor-gateway",
    )["path"] = "../outside/splendor-gateway"
    failures += report_exact_self_test(
        "governed_name_outside_path_substitution",
        check_metadata(governed_outside_path)[0],
        [
            "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed package "
            "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
            "repository-relative directory 'crates/splendor-gateway', actual source=None, declared "
            "path='../outside/splendor-gateway', resolved directory='<outside-workspace>'. Governed package names "
            "cannot be substituted by registry, Git, outside, missing, or different local packages."
        ],
    )

    unknown_outside_path = accepted_metadata_fixture()
    package_named(unknown_outside_path, "splendor-kernel")["dependencies"].append(
        dependency_fixture(
            "external-unknown", path="../outside/external-unknown"
        )
    )
    failures += report_exact_self_test(
        "unknown_outside_path_remains_external",
        check_metadata(unknown_outside_path)[0],
        [],
    )

    normalized_governed_path = accepted_metadata_fixture()
    dependency_named(
        package_named(normalized_governed_path, "splendor-adapter-http"),
        "splendor-gateway",
    )["path"] = "crates/splendor-gateway/../splendor-gateway"
    failures += report_exact_self_test(
        "normalized_governed_path_resolves_to_identity",
        check_metadata(normalized_governed_path)[0],
        [],
    )

    governed_registry_source = accepted_metadata_fixture()
    registry_dependency = dependency_named(
        package_named(governed_registry_source, "splendor-adapter-http"),
        "splendor-gateway",
    )
    registry_dependency.update({"path": None, "source": CRATES_IO_SOURCE})
    failures += report_exact_self_test(
        "governed_name_registry_substitution",
        check_metadata(governed_registry_source)[0],
        [
            "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed package "
            "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
            "repository-relative directory 'crates/splendor-gateway', actual "
            "source='registry+https://github.com/rust-lang/crates.io-index', declared path=None, resolved "
            "directory=None. Governed package names cannot be substituted by registry, Git, outside, missing, "
            "or different local packages."
        ],
    )

    governed_git_source = accepted_metadata_fixture()
    git_dependency = dependency_named(
        package_named(governed_git_source, "splendor-adapter-http"),
        "splendor-gateway",
    )
    git_dependency.update(
        {"path": None, "source": "git+https://example.invalid/splendor-gateway"}
    )
    failures += report_exact_self_test(
        "governed_name_git_substitution",
        check_metadata(governed_git_source)[0],
        [
            "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed package "
            "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
            "repository-relative directory 'crates/splendor-gateway', actual "
            "source='git+https://example.invalid/splendor-gateway', declared path=None, resolved directory=None. "
            "Governed package names cannot be substituted by registry, Git, outside, missing, or different "
            "local packages."
        ],
    )

    governed_missing_path = accepted_metadata_fixture()
    missing_path_dependency = dependency_named(
        package_named(governed_missing_path, "splendor-adapter-http"),
        "splendor-gateway",
    )
    missing_path_dependency["path"] = None
    failures += report_exact_self_test(
        "governed_name_missing_path_substitution",
        check_metadata(governed_missing_path)[0],
        [
            "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed package "
            "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
            "repository-relative directory 'crates/splendor-gateway', actual source=None, declared path=None, "
            "resolved directory=None. Governed package names cannot be substituted by registry, Git, outside, "
            "missing, or different local packages."
        ],
    )

    governed_wrong_manifest = accepted_metadata_fixture()
    dependency_named(
        package_named(governed_wrong_manifest, "splendor-adapter-http"),
        "splendor-gateway",
    )["path"] = "crates/splendor-store"
    failures += report_exact_self_test(
        "governed_name_wrong_manifest_substitution",
        check_metadata(governed_wrong_manifest)[0],
        [
            "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed package "
            "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
            "repository-relative directory 'crates/splendor-gateway', actual source=None, declared "
            "path='crates/splendor-store', resolved directory='crates/splendor-store'. Governed package names "
            "cannot be substituted by registry, Git, outside, missing, or different local packages.",
            "splendor-adapter-http -> splendor-gateway (normal dependency) declares the wrong repository-local "
            "package identity for 'crates/splendor-store'; expected package 'splendor-store' at "
            "'crates/splendor-store/Cargo.toml'.",
        ],
    )

    wrong_canonical_name = accepted_metadata_fixture()
    dependency_named(
        package_named(wrong_canonical_name, "splendor-adapter-http"),
        "splendor-gateway",
    )["name"] = "not-splendor-gateway"
    failures += report_exact_self_test(
        "wrong_canonical_name_at_governed_manifest",
        check_metadata(wrong_canonical_name)[0],
        [
            "splendor-adapter-http -> not-splendor-gateway (normal dependency) declares the wrong "
            "repository-local package identity for 'crates/splendor-gateway'; expected package "
            "'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'."
        ],
    )

    allowed_alias = accepted_metadata_fixture()
    dependency_named(
        package_named(allowed_alias, "splendorctl"), "splendor-gateway"
    )["rename"] = "gateway_alias"
    failures += report_exact_self_test(
        "governed_dependency_allowed_cargo_alias",
        check_metadata(allowed_alias)[0],
        [],
    )

    forbidden_alias = accepted_metadata_fixture()
    aliased_dependency = dependency_fixture("splendor-adapter-http")
    aliased_dependency["rename"] = "http_alias"
    package_named(forbidden_alias, "splendor-kernel")["dependencies"].append(
        aliased_dependency
    )
    failures += report_exact_self_test(
        "governed_dependency_forbidden_cargo_alias",
        check_metadata(forbidden_alias)[0],
        [
            "splendor-kernel -> splendor-adapter-http (normal dependency) is forbidden. Allowed direct internal "
            "deps: splendor-authority, splendor-gateway, splendor-store, splendor-types. Rule/exception note: "
            "splendor-kernel is the compatibility composition root; RFC 0010 AUTH-003b allows the bounded local "
            "delegation authority bridge in addition to types/store/gateway."
        ],
    )

    duplicate_record_expected = [
        "governed package identity 'splendor-adapter-http' at 'adapters/http/Cargo.toml' is ambiguous across "
        "2 package metadata records [{\"id\":\"fixture://splendor-adapter-http#0.1.0\","
        "\"manifest\":\"adapters/http/Cargo.toml\",\"name\":\"splendor-adapter-http\",\"source\":null}; "
        "{\"id\":\"fixture://splendor-adapter-http#0.1.0-duplicate\",\"manifest\":\"adapters/http/Cargo.toml\","
        "\"name\":\"splendor-adapter-http\",\"source\":null}]; expected one canonical name/manifest record and "
        "no duplicate package id.",
        "splendor-adapter-http -> splendor-kernel (normal dependency) is forbidden. Allowed direct internal "
        "deps: splendor-gateway, splendor-types. Rule/exception note: Adapter crates may directly depend only "
        "on splendor-types and splendor-gateway; no adapter -> kernel/store/daemon/adapter core edge.",
        "Dependency cycle detected among internal workspace packages: splendor-adapter-http -> splendor-kernel "
        "-> splendor-adapter-http. Rule/exception note: the current-baseline internal workspace graph must "
        "remain acyclic.",
    ]
    duplicate_record_after = duplicate_governed_record_fixture(prepend=False)
    duplicate_record_before = duplicate_governed_record_fixture(prepend=True)
    failures += report_exact_self_test(
        "duplicate_governed_record_after_member",
        check_metadata(duplicate_record_after)[0],
        duplicate_record_expected,
    )
    failures += report_exact_self_test(
        "duplicate_governed_record_before_member",
        check_metadata(duplicate_record_before)[0],
        duplicate_record_expected,
    )

    cycle_order_expected = [
        "Dependency cycle detected among internal workspace packages: a -> b -> c -> a. Rule/exception note: "
        "the current-baseline internal workspace graph must remain acyclic."
    ]
    failures += report_exact_self_test(
        "cycle_adjacency_order_a",
        cycle_violations(
            {
                "a": [("b", "normal"), ("c", "normal")],
                "b": [("c", "normal")],
                "c": [("a", "normal")],
            }
        ),
        cycle_order_expected,
    )
    failures += report_exact_self_test(
        "cycle_adjacency_order_b",
        cycle_violations(
            {
                "c": [("a", "normal")],
                "b": [("c", "normal")],
                "a": [
                    ("c", "normal"),
                    ("b", "normal"),
                    ("b", "normal"),
                ],
            }
        ),
        cycle_order_expected,
    )

    metadata_order_a = fixture_with_dependency(
        "splendor-adapter-http", "splendor-kernel"
    )
    metadata_order_b = copy.deepcopy(metadata_order_a)
    metadata_order_b["packages"].reverse()
    metadata_order_b["workspace_members"].reverse()
    for package in metadata_order_b["packages"]:
        package["dependencies"].reverse()
    metadata_order_expected = [
        "splendor-adapter-http -> splendor-kernel (normal dependency) is forbidden. Allowed direct internal "
        "deps: splendor-gateway, splendor-types. Rule/exception note: Adapter crates may directly depend only "
        "on splendor-types and splendor-gateway; no adapter -> kernel/store/daemon/adapter core edge.",
        "Dependency cycle detected among internal workspace packages: splendor-adapter-http -> splendor-kernel "
        "-> splendor-adapter-http. Rule/exception note: the current-baseline internal workspace graph must "
        "remain acyclic.",
    ]
    failures += report_exact_self_test(
        "metadata_package_dependency_order_a",
        check_metadata(metadata_order_a)[0],
        metadata_order_expected,
    )
    failures += report_exact_self_test(
        "metadata_package_dependency_order_b",
        check_metadata(metadata_order_b)[0],
        metadata_order_expected,
    )

    malformed_path = accepted_metadata_fixture()
    dependency_named(
        package_named(malformed_path, "splendor-adapter-http"),
        "splendor-gateway",
    )["path"] = "\x00bad"
    failures += report_exact_self_test(
        "malformed_dependency_path_fails_closed",
        check_metadata(malformed_path)[0],
        [
            "Cargo metadata path for package 'splendor-adapter-http' "
            "(id 'fixture://splendor-adapter-http#0.1.0') dependency 'splendor-gateway' "
            "(normal, rename=None) cannot be resolved from '\\x00bad': path contains an embedded NUL byte. "
            "Package identity checks fail closed."
        ],
    )

    with tempfile.TemporaryDirectory(prefix="splendor-dependency-policy-") as temp_dir:
        symlink_root = Path(temp_dir) / "workspace"
        symlink_root.mkdir()
        (symlink_root / "loop").symlink_to("loop")
        symlink_loop = accepted_metadata_fixture()
        symlink_loop["workspace_root"] = symlink_root.as_posix()
        dependency_named(
            package_named(symlink_loop, "splendor-adapter-http"),
            "splendor-gateway",
        )["path"] = "loop"
        failures += report_exact_self_test(
            "symlink_loop_dependency_path_fails_closed",
            check_metadata(symlink_loop)[0],
            [
                "Cargo metadata path for package 'splendor-adapter-http' "
                "(id 'fixture://splendor-adapter-http#0.1.0') dependency 'splendor-gateway' "
                "(normal, rename=None) cannot be resolved from 'loop': symlink loop or recursive path "
                "resolution. Package identity checks fail closed."
            ],
        )

    with tempfile.TemporaryDirectory(prefix="splendor-dependency-policy-") as temp_dir:
        symlink_root = Path(temp_dir) / "workspace"
        outside_root = Path(temp_dir) / "outside-gateway"
        symlink_root.mkdir()
        outside_root.mkdir()
        (symlink_root / "escaped-gateway").symlink_to(outside_root)
        symlink_escape = accepted_metadata_fixture()
        symlink_escape["workspace_root"] = symlink_root.as_posix()
        dependency_named(
            package_named(symlink_escape, "splendor-adapter-http"),
            "splendor-gateway",
        )["path"] = "escaped-gateway"
        failures += report_exact_self_test(
            "governed_name_symlink_escape_substitution",
            check_metadata(symlink_escape)[0],
            [
                "splendor-adapter-http -> splendor-gateway (normal dependency) does not resolve to governed "
                "package identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None "
                "and repository-relative directory 'crates/splendor-gateway', actual source=None, declared "
                "path='escaped-gateway', resolved directory='<outside-workspace>'. Governed package names cannot "
                "be substituted by registry, Git, outside, missing, or different local packages."
            ],
        )

    excluded_adapter = excluded_http_adapter_fixture(add_kernel_normal_edge=True)
    failures += report_exact_self_test(
        "excluded_adapter_path_to_kernel_rejected",
        check_metadata(excluded_adapter)[0],
        excluded_http_adapter_expected_messages(include_kernel_normal_edge=True),
    )

    omitted_adapter = excluded_http_adapter_fixture(
        add_kernel_normal_edge=True, remove_package=True
    )
    failures += report_exact_self_test(
        "omitted_local_package_path_to_kernel_rejected",
        check_metadata(omitted_adapter)[0],
        excluded_http_adapter_expected_messages(include_kernel_normal_edge=True),
    )

    excluded_cycle = excluded_http_adapter_fixture(add_adapter_reverse_edge=True)
    failures += report_exact_self_test(
        "excluded_adapter_edge_and_cycle_remain_governed",
        check_metadata(excluded_cycle)[0],
        excluded_http_adapter_expected_messages(include_cycle=True),
    )

    relocated_secret_provider = accepted_metadata_fixture()
    package_named(
        relocated_secret_provider, "splendor-adapter-secrets-memory"
    )["manifest_path"] = "adapters/experimental/secrets-memory/Cargo.toml"
    secret_provider_with_node = accepted_metadata_fixture()
    append_workspace_package(
        secret_provider_with_node,
        "splendor-node",
        "binaries/splendor-node/Cargo.toml",
    )
    package_named(
        secret_provider_with_node, "splendor-adapter-secrets-memory"
    )["dependencies"].append(
        dependency_fixture("splendor-node", repository_local=False)
    )

    secret_provider_rule = (
        "Allowed direct internal deps: splendor-authority, splendor-types. "
        "Rule/exception note: RFC 0012 permits only adapters/secrets-* -> "
        "splendor-authority + splendor-types; secret providers may not import "
        "gateway/kernel/store/daemon/node or another adapter."
    )
    edge_cases = [
        (
            "adapter_reverse_edge_to_kernel",
            fixture_with_dependency(
                "splendor-adapter-http", "splendor-kernel"
            ),
            [
                "splendor-adapter-http -> splendor-kernel (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-types. Rule/exception note: "
                "Adapter crates may directly depend only on splendor-types and splendor-gateway; "
                "no adapter -> kernel/store/daemon/adapter core edge.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-adapter-http -> splendor-kernel -> splendor-adapter-http. Rule/exception note: "
                "the current-baseline internal workspace graph must remain acyclic.",
            ],
        ),
        (
            "core_depends_on_adapter",
            fixture_with_dependency(
                "splendor-kernel", "splendor-adapter-http"
            ),
            [
                "splendor-kernel -> splendor-adapter-http (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-authority, splendor-gateway, splendor-store, splendor-types. "
                "Rule/exception note: splendor-kernel is the compatibility composition root; RFC 0010 AUTH-003b "
                "allows the bounded local delegation authority bridge in addition to types/store/gateway."
            ],
        ),
        (
            "ordinary_adapter_depends_on_authority",
            fixture_with_dependency(
                "splendor-adapter-http", "splendor-authority"
            ),
            [
                "splendor-adapter-http -> splendor-authority (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-types. Rule/exception note: "
                "Adapter crates may directly depend only on splendor-types and splendor-gateway; "
                "no adapter -> kernel/store/daemon/adapter core edge."
            ],
        ),
        (
            "secret_provider_depends_on_gateway",
            fixture_with_dependency(
                "splendor-adapter-secrets-memory", "splendor-gateway"
            ),
            [
                "splendor-adapter-secrets-memory -> splendor-gateway (normal dependency) is forbidden. "
                + secret_provider_rule
            ],
        ),
        (
            "secret_provider_exact_dependencies_allowed",
            accepted_metadata_fixture(),
            [],
        ),
        (
            "secret_provider_depends_on_kernel",
            fixture_with_dependency(
                "splendor-adapter-secrets-memory", "splendor-kernel"
            ),
            [
                "splendor-adapter-secrets-memory -> splendor-kernel (normal dependency) is forbidden. "
                + secret_provider_rule
            ],
        ),
        (
            "secret_provider_depends_on_store",
            fixture_with_dependency(
                "splendor-adapter-secrets-memory", "splendor-store"
            ),
            [
                "splendor-adapter-secrets-memory -> splendor-store (normal dependency) is forbidden. "
                + secret_provider_rule
            ],
        ),
        (
            "secret_provider_depends_on_daemon",
            fixture_with_dependency(
                "splendor-adapter-secrets-memory", "splendor-daemon"
            ),
            [
                "splendor-adapter-secrets-memory -> splendor-daemon (normal dependency) is forbidden. "
                + secret_provider_rule
            ],
        ),
        (
            "secret_provider_depends_on_http_adapter",
            fixture_with_dependency(
                "splendor-adapter-secrets-memory", "splendor-adapter-http"
            ),
            [
                "splendor-adapter-secrets-memory -> splendor-adapter-http (normal dependency) is forbidden. "
                + secret_provider_rule
            ],
        ),
        (
            "secret_provider_depends_on_node",
            secret_provider_with_node,
            [
                "splendor-adapter-secrets-memory -> splendor-node (normal dependency) is forbidden. "
                + secret_provider_rule,
                "splendor-node: no current-baseline dependency policy is defined for this workspace package. "
                "This FND-002 guard covers existing 0.1 crates/adapters only; add an accepted policy/RFC "
                "or update this guard deliberately.",
                "unexpected workspace package identity 'splendor-node' at "
                "'binaries/splendor-node/Cargo.toml' appears 1 time(s); current-baseline governance "
                "requires every workspace member to have an explicit expected package name and manifest path.",
            ],
        ),
        (
            "nested_secret_provider_does_not_receive_exception",
            relocated_secret_provider,
            [
                "splendor-adapter-secrets-memory -> splendor-authority (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-types. Rule/exception note: "
                "Adapter crates may directly depend only on splendor-types and splendor-gateway; "
                "no adapter -> kernel/store/daemon/adapter core edge.",
                "workspace package 'splendor-adapter-secrets-memory' has unexpected manifest identity "
                "'adapters/experimental/secrets-memory/Cargo.toml'; expected "
                "'adapters/secrets-memory/Cargo.toml'.",
            ],
        ),
        (
            "daemon_depends_on_authority",
            fixture_with_dependency(
                "splendor-daemon", "splendor-authority"
            ),
            [
                "splendor-daemon -> splendor-authority (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-kernel, splendor-store, splendor-types. "
                "Rule/exception note: MIG-137-DAEMON-STORES-GATEWAY allows the existing daemon -> "
                "kernel/store/gateway/types composition seam only.",
                "splendor-daemon -> splendor-authority (normal dependency) is forbidden by the exact "
                "production dependency closure.",
            ],
        ),
        (
            "daemon_depends_on_adapter",
            fixture_with_dependency(
                "splendor-daemon", "splendor-adapter-http"
            ),
            [
                "splendor-daemon -> splendor-adapter-http (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-kernel, splendor-store, splendor-types. "
                "Rule/exception note: MIG-137-DAEMON-STORES-GATEWAY allows the existing daemon -> "
                "kernel/store/gateway/types composition seam only.",
                "splendor-daemon -> splendor-adapter-http (normal dependency) is forbidden by the exact "
                "production dependency closure.",
            ],
        ),
        (
            "daemon_depends_on_acceptance_outer_host",
            fixture_with_dependency(
                "splendor-daemon", "splendor-acceptance-action-host"
            ),
            [
                "splendor-daemon -> splendor-acceptance-action-host (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-kernel, splendor-store, splendor-types. "
                "Rule/exception note: MIG-137-DAEMON-STORES-GATEWAY allows the existing daemon -> "
                "kernel/store/gateway/types composition seam only.",
                "splendor-daemon -> splendor-acceptance-action-host (normal dependency) is forbidden by the exact "
                "production dependency closure.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-acceptance-action-host -> splendor-daemon -> "
                "splendor-acceptance-action-host. Rule/exception note: the current-baseline internal "
                "workspace graph must remain acyclic.",
            ],
        ),
        (
            "types_depends_on_provider_client",
            fixture_with_dependency(
                "splendor-types", "reqwest", repository_local=False
            ),
            [
                "splendor-types -> reqwest (normal dependency) is forbidden by current provider-client ownership. "
                "Accepted owners: splendor-daemon."
            ],
        ),
        (
            "core_depends_on_provider_client",
            fixture_with_dependency(
                "splendor-kernel", "ureq", repository_local=False
            ),
            [
                "splendor-kernel -> ureq (normal dependency) is forbidden by current provider-client ownership. "
                "Accepted owners: splendor-acceptance-action-host, splendor-adapter-http."
            ],
        ),
        (
            "types_depends_on_store",
            fixture_with_dependency(
                "splendor-types", "splendor-store"
            ),
            [
                "splendor-types -> splendor-store (normal dependency) is forbidden. "
                "Allowed direct internal deps: no internal packages. Rule/exception note: "
                "splendor-types is behavior-free canonical IDs/schemas; it must not depend on other internal packages.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-store -> splendor-types -> splendor-store. Rule/exception note: "
                "the current-baseline internal workspace graph must remain acyclic.",
            ],
        ),
        (
            "cycle_between_types_and_store",
            fixture_with_dependency(
                "splendor-types", "splendor-store"
            ),
            [
                "splendor-types -> splendor-store (normal dependency) is forbidden. "
                "Allowed direct internal deps: no internal packages. Rule/exception note: "
                "splendor-types is behavior-free canonical IDs/schemas; it must not depend on other internal packages.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-store -> splendor-types -> splendor-store. Rule/exception note: "
                "the current-baseline internal workspace graph must remain acyclic.",
            ],
        ),
        (
            "dev_cycle_between_kernel_and_adapter",
            fixture_with_dependency(
                "splendor-adapter-http", "splendor-kernel"
            ),
            [
                "splendor-adapter-http -> splendor-kernel (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-types. Rule/exception note: "
                "Adapter crates may directly depend only on splendor-types and splendor-gateway; "
                "no adapter -> kernel/store/daemon/adapter core edge.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-adapter-http -> splendor-kernel -> splendor-adapter-http. Rule/exception note: "
                "the current-baseline internal workspace graph must remain acyclic.",
            ],
        ),
    ]

    for name, metadata, expected in edge_cases:
        violations, _stats = check_metadata(metadata)
        failures += report_exact_self_test(name, violations, expected)

    exact_metadata = accepted_metadata_fixture()
    exact_package = package_named(exact_metadata, "splendor-daemon")
    exact_violations = daemon_closure_violations(exact_package, exact_metadata)
    failures += report_exact_self_test(
        "daemon_rfc0011_current_shape", exact_violations, []
    )

    closure_cases = [
        (
            "daemon_dependency_alias",
            lambda package: dependency_named(package, "reqwest").update(
                {"rename": "outbound"}
            ),
            "splendor-daemon production dependency 'reqwest' changed closed fields: "
            "rename: expected=None actual='outbound'.",
        ),
        (
            "daemon_dependency_direct_feature_widening",
            lambda package: dependency_named(package, "reqwest")["features"].append(
                "blocking"
            ),
            "splendor-daemon production dependency 'reqwest' changed closed fields: "
            "features: expected=('json', 'rustls-tls') actual=('blocking', 'json', 'rustls-tls').",
        ),
        (
            "daemon_dependency_default_feature_widening",
            lambda package: dependency_named(package, "reqwest").update(
                {"uses_default_features": True}
            ),
            "splendor-daemon production dependency 'reqwest' changed closed fields: "
            "uses_default_features: expected=False actual=True.",
        ),
        (
            "daemon_dependency_build_kind",
            lambda package: dependency_named(package, "libc").update({"kind": "build"}),
            "splendor-daemon production dependency 'libc' changed closed fields: "
            "kind: expected=None actual='build'.",
        ),
        (
            "daemon_dependency_target_predicate",
            lambda package: dependency_named(package, "axum").update(
                {"target": "cfg(unix)"}
            ),
            "splendor-daemon production dependency 'axum' changed closed fields: "
            "target: expected=None actual='cfg(unix)'.",
        ),
        (
            "daemon_dependency_optional_widening",
            lambda package: dependency_named(package, "ring").update({"optional": True}),
            "splendor-daemon production dependency 'ring' changed closed fields: "
            "optional: expected=False actual=True.",
        ),
        (
            "daemon_dependency_requirement_change",
            lambda package: dependency_named(package, "reqwest").update({"req": "^0.13"}),
            "splendor-daemon production dependency 'reqwest' changed closed fields: "
            "req: expected='^0.12' actual='^0.13'.",
        ),
        (
            "daemon_dependency_source_change",
            lambda package: dependency_named(package, "reqwest").update(
                {"source": "git+https://example.invalid/reqwest"}
            ),
            "splendor-daemon production dependency 'reqwest' changed closed fields: "
            "source: expected='registry+https://github.com/rust-lang/crates.io-index' "
            "actual='git+https://example.invalid/reqwest'.",
        ),
        (
            "daemon_dependency_path_change",
            lambda package: dependency_named(package, "splendor-gateway").update(
                {"path": "crates/other-gateway"}
            ),
            [
                "splendor-daemon -> splendor-gateway (normal dependency) does not resolve to governed package "
                "identity 'splendor-gateway' at 'crates/splendor-gateway/Cargo.toml'; expected source=None and "
                "repository-relative directory 'crates/splendor-gateway', actual source=None, declared "
                "path='crates/other-gateway', resolved directory='crates/other-gateway'. Governed package names "
                "cannot be substituted by registry, Git, outside, missing, or different local packages.",
                "splendor-daemon production dependency 'splendor-gateway' changed closed fields: "
                "path: expected='crates/splendor-gateway' actual='crates/other-gateway'.",
                "splendor-daemon -> splendor-gateway (normal dependency) is an unmodeled repository-local "
                "path dependency at 'crates/other-gateway'; no governed workspace package identity matches "
                "'crates/other-gateway/Cargo.toml'. All repository-local Rust path dependencies must remain "
                "governed workspace members.",
            ],
        ),
        (
            "daemon_package_feature_forwarding",
            lambda package: package.update(
                {"features": {"default": ["reqwest/blocking"]}}
            ),
            "splendor-daemon package feature map changed; dependency feature forwarding is closed: "
            "expected={} actual={'default': ['reqwest/blocking']}.",
        ),
        (
            "daemon_dependency_unapproved_client",
            lambda package: package["dependencies"].append(
                daemon_registry_dependency("ureq", "^2")
            ),
            [
                "splendor-daemon -> ureq (normal dependency) is forbidden by current provider-client ownership. "
                "Accepted owners: splendor-acceptance-action-host, splendor-adapter-http.",
                "splendor-daemon -> ureq (normal dependency) is forbidden. Daemon production external "
                "dependencies are closed; provider clients belong in adapters/* or an explicit outer host.",
                "splendor-daemon -> ureq (normal dependency) is forbidden by the exact production dependency closure.",
            ],
        ),
        (
            "daemon_unapproved_lib_target",
            lambda package: append_daemon_target(
                package,
                "lib",
                "shadow_daemon",
                "crates/splendor-daemon/src/shadow.rs",
            ),
            "splendor-daemon target is not in the closed lib/bin/example/build declaration: "
            "('lib', 'shadow_daemon', 'crates/splendor-daemon/src/shadow.rs').",
        ),
        (
            "daemon_unapproved_bin_target",
            lambda package: append_daemon_target(
                package,
                "bin",
                "shadow-daemon",
                "crates/splendor-daemon/src/bin/shadow-daemon.rs",
            ),
            "splendor-daemon target is not in the closed lib/bin/example/build declaration: "
            "('bin', 'shadow-daemon', 'crates/splendor-daemon/src/bin/shadow-daemon.rs').",
        ),
        (
            "daemon_unapproved_example_target",
            lambda package: append_daemon_target(
                package,
                "example",
                "shadow_daemon",
                "crates/splendor-daemon/examples/shadow_daemon.rs",
            ),
            "splendor-daemon target is not in the closed lib/bin/example/build declaration: "
            "('example', 'shadow_daemon', 'crates/splendor-daemon/examples/shadow_daemon.rs').",
        ),
        (
            "daemon_unapproved_build_target",
            lambda package: append_daemon_target(
                package,
                "custom-build",
                "build-script-build",
                "crates/splendor-daemon/build.rs",
            ),
            "splendor-daemon target is not in the closed lib/bin/example/build declaration: "
            "('custom-build', 'build-script-build', 'crates/splendor-daemon/build.rs').",
        ),
    ]
    for name, mutate, expected in closure_cases:
        metadata = accepted_metadata_fixture()
        package = package_named(metadata, "splendor-daemon")
        mutate(package)
        violations, _stats = check_metadata(metadata)
        failures += report_exact_self_test(name, violations, expected)

    if failures:
        return 1
    print("FND-002 dependency policy self-test: PASS")
    return 0


def report_exact_self_test(
    name: str, violations: list[Violation], expected: str | Iterable[str]
) -> int:
    messages = sorted(violation.message for violation in violations)
    expected_messages = sorted([expected] if isinstance(expected, str) else expected)
    if messages != expected_messages:
        print(
            f"self-test {name}: FAIL (exact violation multiset mismatch)",
            file=sys.stderr,
        )
        print(
            f"expected ({len(expected_messages)}):\n"
            + ("\n".join(expected_messages) or "<no violations>"),
            file=sys.stderr,
        )
        print(
            f"actual ({len(messages)}):\n"
            + ("\n".join(messages) or "<no violations>"),
            file=sys.stderr,
        )
        return 1
    print(f"self-test {name}: PASS (violations={len(messages)})")
    return 0


def append_daemon_target(
    package: dict[str, Any], kind: str, name: str, path: str
) -> None:
    package["targets"].append(
        {
            "name": name,
            "kind": [kind],
            "crate_types": ["lib" if kind == "lib" else "bin"],
            "src_path": path,
        }
    )


def accepted_metadata_fixture() -> dict[str, Any]:
    internal_dependencies: dict[str, list[tuple[str, str | None]]] = {
        "splendor-types": [],
        "splendor-store": [("splendor-types", None)],
        "splendor-authority": [
            ("splendor-store", None),
            ("splendor-types", None),
        ],
        "splendor-gateway": [
            ("splendor-authority", None),
            ("splendor-types", None),
        ],
        "splendor-kernel": [
            ("splendor-authority", None),
            ("splendor-gateway", None),
            ("splendor-store", None),
            ("splendor-types", None),
            ("splendor-adapter-filesystem", "dev"),
            ("splendor-adapter-http", "dev"),
            ("splendor-adapter-robotics", "dev"),
        ],
        "splendor-daemon": [("splendor-authority", "dev")],
        "splendorctl": [
            ("splendor-adapter-filesystem", None),
            ("splendor-adapter-http", None),
            ("splendor-gateway", None),
            ("splendor-kernel", None),
            ("splendor-store", None),
            ("splendor-types", None),
        ],
        "splendor-bindings": [("splendor-kernel", None)],
        "splendor-acceptance-action-host": [
            ("splendor-daemon", None),
            ("splendor-gateway", None),
            ("splendor-types", None),
        ],
        "splendor-adapter-filesystem": [
            ("splendor-gateway", None),
            ("splendor-types", None),
        ],
        "splendor-adapter-http": [
            ("splendor-gateway", None),
            ("splendor-types", None),
        ],
        "splendor-adapter-robotics": [
            ("splendor-gateway", None),
            ("splendor-types", None),
        ],
        "splendor-adapter-secrets-local-file": [
            ("splendor-authority", None),
            ("splendor-types", None),
        ],
        "splendor-adapter-secrets-memory": [
            ("splendor-authority", None),
            ("splendor-types", None),
        ],
    }

    packages: list[dict[str, Any]] = []
    workspace_members: list[str] = []
    for name, manifest in EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.items():
        package_id = f"fixture://{name}#0.1.0"
        if name == "splendor-daemon":
            package = daemon_fixture_package(package_id)
        else:
            package = {
                "id": package_id,
                "name": name,
                "manifest_path": manifest,
                "dependencies": [],
            }
        package["dependencies"].extend(
            dependency_fixture(dependency, kind)
            for dependency, kind in internal_dependencies[name]
        )
        if name == "splendor-authority":
            package["features"] = {
                "default": [],
                SECRET_PROVIDER_TEST_SUPPORT_FEATURE: [],
            }
        if name == LOCAL_FILE_SECRET_PROVIDER_PACKAGE:
            package["publish"] = []
            package["features"] = copy.deepcopy(
                LOCAL_FILE_SECRET_PROVIDER_EXPECTED_FEATURES
            )
            package["dependencies"].extend(
                [
                    dependency_fixture("libc", repository_local=False),
                    dependency_fixture("zeroize", repository_local=False),
                    {
                        **dependency_fixture("splendor-authority", "dev"),
                        "features": [SECRET_PROVIDER_TEST_SUPPORT_FEATURE],
                    },
                    dependency_fixture("tempfile", "dev", repository_local=False),
                    dependency_fixture("uuid", "dev", repository_local=False),
                ]
            )
        if name in {"splendor-adapter-http", "splendor-acceptance-action-host"}:
            package["dependencies"].append(
                dependency_fixture("ureq", repository_local=False)
            )
        packages.append(package)
        workspace_members.append(package_id)
    return {
        "workspace_root": "__splendor_dependency_policy_fixture_root__",
        "packages": packages,
        "workspace_members": workspace_members,
    }


def dependency_fixture(
    name: str,
    kind: str | None = None,
    *,
    path: str | None = None,
    repository_local: bool = True,
) -> dict[str, Any]:
    if path is None and repository_local:
        manifest = EXPECTED_WORKSPACE_PACKAGE_MANIFESTS.get(name)
        if manifest is not None:
            path = Path(manifest).parent.as_posix()
    return {
        "name": name,
        "rename": None,
        "kind": kind,
        "path": path,
    }


def daemon_fixture_package(package_id: str) -> dict[str, Any]:
    dependencies: list[dict[str, Any]] = []
    for expected in DAEMON_EXPECTED_PRODUCTION_DEPENDENCIES.values():
        dependency = copy.deepcopy(expected)
        dependency["features"] = list(dependency["features"])
        dependencies.append(dependency)
    targets = [
        {
            "name": name,
            "kind": [kind],
            "crate_types": ["lib" if kind == "lib" else "bin"],
            "src_path": path,
        }
        for kind, name, path in sorted(DAEMON_EXPECTED_TARGETS)
    ]
    return {
        "id": package_id,
        "name": "splendor-daemon",
        "manifest_path": "crates/splendor-daemon/Cargo.toml",
        "dependencies": dependencies,
        "features": {},
        "targets": targets,
    }


def fixture_with_dependency(
    source: str,
    target: str,
    *,
    kind: str | None = None,
    repository_local: bool = True,
) -> dict[str, Any]:
    metadata = accepted_metadata_fixture()
    package_named(metadata, source)["dependencies"].append(
        dependency_fixture(target, kind, repository_local=repository_local)
    )
    return metadata


def remove_workspace_member(metadata: dict[str, Any], name: str) -> None:
    package_id = package_named(metadata, name)["id"]
    metadata["workspace_members"] = [
        member_id
        for member_id in metadata["workspace_members"]
        if member_id != package_id
    ]


def append_duplicate_workspace_package(metadata: dict[str, Any], name: str) -> None:
    duplicate = copy.deepcopy(package_named(metadata, name))
    duplicate["id"] = f"{duplicate['id']}-duplicate"
    metadata["packages"].append(duplicate)
    metadata["workspace_members"].append(duplicate["id"])


def duplicate_governed_record_fixture(*, prepend: bool) -> dict[str, Any]:
    metadata = accepted_metadata_fixture()
    duplicate = copy.deepcopy(package_named(metadata, "splendor-adapter-http"))
    duplicate["id"] = f"{duplicate['id']}-duplicate"
    duplicate["dependencies"].append(dependency_fixture("splendor-kernel"))
    if prepend:
        metadata["packages"].insert(0, duplicate)
    else:
        metadata["packages"].append(duplicate)
    return metadata


def append_workspace_package(
    metadata: dict[str, Any], name: str, manifest: str
) -> None:
    package_id = f"fixture://{name}#0.1.0"
    metadata["packages"].append(
        {
            "id": package_id,
            "name": name,
            "manifest_path": manifest,
            "dependencies": [],
        }
    )
    metadata["workspace_members"].append(package_id)


def excluded_http_adapter_fixture(
    *,
    add_kernel_normal_edge: bool = False,
    add_adapter_reverse_edge: bool = False,
    remove_package: bool = False,
) -> dict[str, Any]:
    metadata = accepted_metadata_fixture()
    remove_workspace_member(metadata, "splendor-adapter-http")
    if add_kernel_normal_edge:
        package_named(metadata, "splendor-kernel")["dependencies"].append(
            dependency_fixture("splendor-adapter-http")
        )
    if add_adapter_reverse_edge:
        package_named(metadata, "splendor-adapter-http")["dependencies"].append(
            dependency_fixture("splendor-kernel")
        )
    if remove_package:
        metadata["packages"] = [
            package
            for package in metadata["packages"]
            if package["name"] != "splendor-adapter-http"
        ]
    return metadata


def excluded_http_adapter_expected_messages(
    *, include_kernel_normal_edge: bool = False, include_cycle: bool = False
) -> list[str]:
    messages = [
        "required workspace package 'splendor-adapter-http' at 'adapters/http/Cargo.toml' "
        "is missing from workspace_members; workspace exclusion cannot remove it from dependency governance.",
        "splendor-kernel -> splendor-adapter-http (dev dependency) is an unmodeled repository-local "
        "path dependency at 'adapters/http'; expected governed workspace member "
        "'splendor-adapter-http' at 'adapters/http/Cargo.toml'. All repository-local Rust path "
        "dependencies must remain governed workspace members.",
        "splendorctl -> splendor-adapter-http (normal dependency) is an unmodeled repository-local "
        "path dependency at 'adapters/http'; expected governed workspace member "
        "'splendor-adapter-http' at 'adapters/http/Cargo.toml'. All repository-local Rust path "
        "dependencies must remain governed workspace members.",
    ]
    if include_kernel_normal_edge:
        messages.extend(
            [
                "splendor-kernel -> splendor-adapter-http (normal dependency) is an unmodeled "
                "repository-local path dependency at 'adapters/http'; expected governed workspace member "
                "'splendor-adapter-http' at 'adapters/http/Cargo.toml'. All repository-local Rust path "
                "dependencies must remain governed workspace members.",
                "splendor-kernel -> splendor-adapter-http (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-authority, splendor-gateway, splendor-store, "
                "splendor-types. Rule/exception note: splendor-kernel is the compatibility composition root; "
                "RFC 0010 AUTH-003b allows the bounded local delegation authority bridge in addition to "
                "types/store/gateway.",
            ]
        )
    if include_cycle:
        messages.extend(
            [
                "splendor-adapter-http -> splendor-kernel (normal dependency) is forbidden. "
                "Allowed direct internal deps: splendor-gateway, splendor-types. Rule/exception note: "
                "Adapter crates may directly depend only on splendor-types and splendor-gateway; "
                "no adapter -> kernel/store/daemon/adapter core edge.",
                "Dependency cycle detected among internal workspace packages: "
                "splendor-adapter-http -> splendor-kernel -> splendor-adapter-http. Rule/exception note: "
                "the current-baseline internal workspace graph must remain acyclic.",
            ]
        )
    return messages


def package_named(metadata: dict[str, Any], name: str) -> dict[str, Any]:
    return next(package for package in metadata["packages"] if package["name"] == name)


def dependency_named(package: dict[str, Any], name: str) -> dict[str, Any]:
    return next(
        dependency
        for dependency in package["dependencies"]
        if dependency["name"] == name
    )


if __name__ == "__main__":
    sys.exit(main())
