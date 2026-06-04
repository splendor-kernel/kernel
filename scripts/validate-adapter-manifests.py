#!/usr/bin/env python3
"""Lightweight validation for 0.1 adapter maturity manifests.

This checks JSON syntax and the stable shape required by 0.1-S3. It is not an
adapter certification process and does not execute adapters.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_DIR = ROOT / "docs" / "spec" / "0.1" / "fixtures" / "adapter-manifests"
ALLOWED_LEVELS = {
    "experimental",
    "local-safe",
    "network-safe",
    "governance-aware",
    "device-safe",
}
REQUIRED_TOP_LEVEL = {
    "schema_version",
    "adapter",
    "maturity_level",
    "supported_actions",
    "required_verifiers",
    "quota_dimensions",
    "trace_behavior",
    "replay_behavior",
    "scopes",
    "governance_support",
    "physical_device_safety",
    "limitations",
    "evidence",
}
REQUIRED_ADAPTER = {"id", "name", "version", "description"}
REQUIRED_ACTION = {
    "name",
    "side_effect_class",
    "required_permissions",
    "required_preconditions",
    "postconditions",
    "params_scope",
    "risk",
}
REQUIRED_OBJECT_FIELDS = {
    "trace_behavior",
    "replay_behavior",
    "scopes",
    "governance_support",
    "physical_device_safety",
}


def fail(path: Path, message: str) -> None:
    raise ValueError(f"{path.relative_to(ROOT)}: {message}")


def require_keys(path: Path, value: dict, required: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    if missing:
        fail(path, f"missing {label} fields: {', '.join(missing)}")


def evidence_ref_exists(ref: str) -> bool:
    # Evidence refs are repository-relative file paths for this sprint's
    # manifests. Future conformance URLs or opaque IDs should use another key.
    if ref.startswith(("http://", "https://")):
        return True
    return (ROOT / ref).exists()


def has_verifier(verifiers: list[object], expected: str) -> bool:
    return any(isinstance(verifier, str) and expected in verifier for verifier in verifiers)


def validate_manifest(path: Path) -> None:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        fail(path, "manifest must be a JSON object")
    require_keys(path, data, REQUIRED_TOP_LEVEL, "top-level")

    if data["schema_version"] != "splendor.adapter_manifest.v1":
        fail(path, "schema_version must be splendor.adapter_manifest.v1")
    if data["maturity_level"] not in ALLOWED_LEVELS:
        fail(path, f"invalid maturity_level {data['maturity_level']!r}")

    for field in REQUIRED_OBJECT_FIELDS:
        if not isinstance(data[field], dict):
            fail(path, f"{field} must be an object")

    adapter = data["adapter"]
    if not isinstance(adapter, dict):
        fail(path, "adapter must be an object")
    require_keys(path, adapter, REQUIRED_ADAPTER, "adapter")

    actions = data["supported_actions"]
    if not isinstance(actions, list) or not actions:
        fail(path, "supported_actions must be a non-empty array")
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            fail(path, f"supported_actions[{index}] must be an object")
        require_keys(path, action, REQUIRED_ACTION, f"supported_actions[{index}]")

    for field in ("required_verifiers", "quota_dimensions", "limitations", "evidence"):
        if not isinstance(data[field], list) or not data[field]:
            fail(path, f"{field} must be a non-empty array")

    verifiers = data["required_verifiers"]
    if not all(isinstance(verifier, str) for verifier in verifiers):
        fail(path, "required_verifiers entries must be strings")

    maturity_level = data["maturity_level"]
    if maturity_level == "network-safe" and not has_verifier(verifiers, "network_egress"):
        fail(path, "network-safe manifests require a network_egress verifier")
    if maturity_level == "device-safe" and not has_verifier(verifiers, "safety"):
        fail(path, "device-safe manifests require a safety verifier")

    for index, evidence in enumerate(data["evidence"]):
        if not isinstance(evidence, dict):
            fail(path, f"evidence[{index}] must be an object")
        ref = evidence.get("ref")
        if not isinstance(ref, str) or not ref:
            fail(path, f"evidence[{index}].ref must be a non-empty string")
        if not evidence_ref_exists(ref):
            fail(path, f"evidence[{index}].ref does not exist: {ref}")

    replay = data["replay_behavior"]
    if replay.get("side_effects_replayed") is not False:
        fail(path, "replay_behavior.side_effects_replayed must be false")

    trace = data["trace_behavior"]
    if not trace.get("required_events"):
        fail(path, "trace_behavior.required_events must be present")


def main() -> int:
    manifests = sorted(MANIFEST_DIR.glob("*.json"))
    if not manifests:
        print(f"no adapter manifests found under {MANIFEST_DIR.relative_to(ROOT)}", file=sys.stderr)
        return 1

    errors: list[str] = []
    for manifest in manifests:
        try:
            validate_manifest(manifest)
        except (json.JSONDecodeError, ValueError) as error:
            errors.append(str(error))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"validated {len(manifests)} adapter manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
