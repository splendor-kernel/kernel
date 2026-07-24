#!/usr/bin/env python3
"""FND-002 current-baseline Rust dependency policy guard.

This is intentionally a narrow 0.1-baseline smoke guard, not the full v2
package ownership split.  It checks the direct, non-dev Rust workspace package
edges that exist today, detects internal cycles across all direct workspace
edges, and preserves documented migration seams while preventing obvious
wrong-direction/provider drift.  It deliberately does not read or enforce
docs/rules/v2/catalog/architecture/dependency_policy.proposed.json.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


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
}

ADAPTER_ALLOWED_INTERNAL_DEPS = {"splendor-types", "splendor-gateway"}
SECRET_PROVIDER_ALLOWED_INTERNAL_DEPS = {"splendor-types", "splendor-authority"}
CHECKED_DEP_KINDS = {None, "build"}

RULE_NOTES: dict[str, str] = {
    "splendor-types": "splendor-types is behavior-free canonical IDs/schemas; it must not depend on other internal packages.",
    "splendor-store": "splendor-store is persistence-only; current baseline allows only splendor-types directly.",
    "splendor-authority": "RFC 0009 / IDR-001 allows splendor-authority to own identity lifecycle decisions over types and storage-only registry persistence.",
    "splendor-gateway": "splendor-gateway is the action/driver boundary; AUTH-004b allows the narrow splendor-authority edge to validate obligation receipts before adapter invocation.",
    "splendor-kernel": "splendor-kernel is the compatibility composition root; RFC 0010 AUTH-003b allows the bounded local delegation authority bridge in addition to types/store/gateway.",
    "splendor-daemon": "MIG-137-DAEMON-STORES-GATEWAY allows the existing daemon -> kernel/store/gateway/types composition seam only.",
    "splendorctl": "MIG-137-CLI-EMBEDDED-LOCAL allows existing embedded-local CLI edges to kernel/store/gateway/types and filesystem/http adapters only.",
    "splendor-bindings": "Python bindings may bind the kernel facade directly; transitive core deps must remain Cargo transitive, not direct.",
    "adapter": "Adapter crates may directly depend only on splendor-types and splendor-gateway; no adapter -> kernel/store/daemon/adapter core edge.",
    "secret_provider": "RFC 0012 permits only adapters/secrets-* -> splendor-authority + splendor-types; secret providers may not import gateway/kernel/store/daemon/node or another adapter.",
}


@dataclass(frozen=True)
class Violation:
    message: str


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

    command = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
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
    workspace_packages = get_workspace_packages(metadata)
    workspace_names = {package["name"] for package in workspace_packages}
    name_counts = count_names(package["name"] for package in workspace_packages)

    violations: list[Violation] = []
    for name, count in sorted(name_counts.items()):
        if count > 1:
            violations.append(
                Violation(
                    f"duplicate workspace package name {name!r}; dependency policy needs unique package names."
                )
            )

    checked_edges: dict[str, list[tuple[str, str]]] = {name: [] for name in workspace_names}
    cycle_edges: dict[str, list[tuple[str, str]]] = {name: [] for name in workspace_names}
    ignored_dev_edges = 0

    for package in sorted(workspace_packages, key=lambda pkg: pkg["name"]):
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

        for dependency in package.get("dependencies", []):
            dep_name = dependency.get("name")
            if dep_name not in workspace_names:
                continue

            cycle_edges.setdefault(source, []).append((dep_name, dependency_kind_label(dependency)))
            dep_kind = dependency.get("kind")
            if dep_kind == "dev":
                ignored_dev_edges += 1
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

            checked_edges.setdefault(source, []).append((dep_name, dependency_kind_label(dependency)))
            if dep_name not in allowed:
                violations.append(forbidden_edge_violation(package, dep_name, dependency))

    violations.extend(cycle_violations(cycle_edges))
    stats = {
        "workspace_packages": len(workspace_packages),
        "checked_internal_edges": sum(len(edges) for edges in checked_edges.values()),
        "cycle_internal_edges": sum(len(edges) for edges in cycle_edges.values()),
        "ignored_dev_internal_edges": ignored_dev_edges,
    }
    return violations, stats


def get_workspace_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    packages = metadata.get("packages", [])
    workspace_member_ids = set(metadata.get("workspace_members") or [])
    if not workspace_member_ids:
        return list(packages)
    return [package for package in packages if package.get("id") in workspace_member_ids]


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
    parts = Path(manifest_path).parts
    return (
        package["name"].startswith("splendor-adapter-secrets-")
        and "adapters" in parts
        and any(part.startswith("secrets-") for part in parts)
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


def cycle_violations(edges: dict[str, list[tuple[str, str]]]) -> list[Violation]:
    adjacency = {source: [target for target, _kind in targets] for source, targets in edges.items()}
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

    unique_cycles = []
    seen: set[tuple[str, ...]] = set()
    for cycle in cycles:
        key = canonical_cycle_key(cycle)
        if key in seen:
            continue
        seen.add(key)
        unique_cycles.append(cycle)

    return [
        Violation(
            "Dependency cycle detected among internal workspace packages: "
            + " -> ".join(cycle)
            + ". Rule/exception note: the current-baseline internal workspace graph must remain acyclic."
        )
        for cycle in unique_cycles
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
            "Note: this guard enforces current 0.1 non-dev Rust workspace allowlists and internal cycle checks; "
            "it does not enforce the proposed v2 JSON dependency policy or require RFC-gated plane crates."
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
        "Scope: current 0.1 baseline only; proposed v2 plane crates and dependency_policy.proposed.json are not enforced."
    )


def run_self_test() -> int:
    cases = [
        (
            "adapter_depends_on_kernel",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-gateway": ["splendor-types", "splendor-authority"],
                    "splendor-kernel": ["splendor-types", "splendor-gateway"],
                    "splendor-adapter-http": ["splendor-types", "splendor-gateway", "splendor-kernel"],
                }
            ),
            "splendor-adapter-http -> splendor-kernel",
        ),
        (
            "ordinary_adapter_depends_on_authority",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-authority": ["splendor-types"],
                    "splendor-adapter-http": ["splendor-types", "splendor-authority"],
                }
            ),
            "splendor-adapter-http -> splendor-authority",
        ),
        (
            "secret_provider_depends_on_gateway",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-authority": ["splendor-types"],
                    "splendor-gateway": ["splendor-types", "splendor-authority"],
                    "splendor-adapter-secrets-memory": [
                        "splendor-types",
                        "splendor-authority",
                        "splendor-gateway",
                    ],
                }
            ),
            "splendor-adapter-secrets-memory -> splendor-gateway",
        ),
        (
            "secret_provider_exact_dependencies_allowed",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-authority": ["splendor-types"],
                    "splendor-adapter-secrets-memory": [
                        "splendor-types",
                        "splendor-authority",
                    ],
                }
            ),
            None,
        ),
        (
            "daemon_depends_on_authority",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-authority": ["splendor-types"],
                    "splendor-kernel": ["splendor-types", "splendor-authority"],
                    "splendor-daemon": [
                        "splendor-types",
                        "splendor-kernel",
                        "splendor-authority",
                    ],
                }
            ),
            "splendor-daemon -> splendor-authority",
        ),
        (
            "types_depends_on_store",
            metadata_fixture(
                {
                    "splendor-types": ["splendor-store"],
                    "splendor-store": [],
                }
            ),
            "splendor-types -> splendor-store",
        ),
        (
            "cycle_between_types_and_store",
            metadata_fixture(
                {
                    "splendor-types": ["splendor-store"],
                    "splendor-store": ["splendor-types"],
                }
            ),
            "Dependency cycle detected",
        ),
        (
            "dev_cycle_between_kernel_and_adapter",
            metadata_fixture(
                {
                    "splendor-types": [],
                    "splendor-gateway": ["splendor-types", "splendor-authority"],
                    "splendor-kernel": [("splendor-adapter-http", "dev")],
                    "splendor-adapter-http": ["splendor-gateway", "splendor-kernel"],
                }
            ),
            "Dependency cycle detected",
        ),
    ]

    forbidden_secret_provider_edges = [
        "splendor-kernel",
        "splendor-store",
        "splendor-daemon",
        "splendor-node",
        "splendor-adapter-http",
    ]
    for dependency in forbidden_secret_provider_edges:
        cases.append(
            (
                f"secret_provider_depends_on_{dependency.removeprefix('splendor-').replace('-', '_')}",
                metadata_fixture(
                    {
                        "splendor-types": [],
                        "splendor-authority": ["splendor-types"],
                        dependency: [],
                        "splendor-adapter-secrets-memory": [
                            "splendor-types",
                            "splendor-authority",
                            dependency,
                        ],
                    }
                ),
                f"splendor-adapter-secrets-memory -> {dependency}",
            )
        )

    failures = 0
    for name, metadata, expected in cases:
        violations, _stats = check_metadata(metadata)
        messages = "\n".join(violation.message for violation in violations)
        if expected is None and violations:
            failures += 1
            print(f"self-test {name}: FAIL (expected no violations)", file=sys.stderr)
            print(messages, file=sys.stderr)
        elif expected is not None and expected not in messages:
            failures += 1
            print(f"self-test {name}: FAIL (expected {expected!r})", file=sys.stderr)
            print(messages or "no violations", file=sys.stderr)
        else:
            print(f"self-test {name}: PASS")

    if failures:
        return 1
    print("FND-002 dependency policy self-test: PASS")
    return 0


def metadata_fixture(edges: dict[str, list[str | tuple[str, str | None]]]) -> dict[str, Any]:
    packages = []
    workspace_members = []
    for name, deps in edges.items():
        package_id = f"fixture://{name}#0.1.0"
        workspace_members.append(package_id)
        if name.startswith("splendor-adapter-secrets-"):
            manifest_parent = f"adapters/{name.removeprefix('splendor-adapter-')}"
        elif name.startswith("splendor-adapter-"):
            manifest_parent = "adapters/http"
        else:
            manifest_parent = f"crates/{name}"
        packages.append(
            {
                "id": package_id,
                "name": name,
                "manifest_path": f"/{manifest_parent}/Cargo.toml",
                "dependencies": [dependency_fixture(dep) for dep in deps],
            }
        )
    return {"packages": packages, "workspace_members": workspace_members}


def dependency_fixture(dep: str | tuple[str, str | None]) -> dict[str, str | None]:
    if isinstance(dep, tuple):
        name, kind = dep
    else:
        name, kind = dep, None
    return {"name": name, "kind": kind}


if __name__ == "__main__":
    sys.exit(main())
