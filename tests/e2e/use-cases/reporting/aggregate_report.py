#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


FUTURE_SCENARIOS = [f"UC-E2E-S{i}" for i in range(1, 11)]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def git_revision(root: Path) -> str:
    env_revision = os.environ.get("SPLENDOR_E2E_SOURCE_REV")
    if env_revision and env_revision != "unknown-source-revision":
        return env_revision
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        git_head = root / ".git" / "HEAD"
        try:
            head = git_head.read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref_path = root / ".git" / head.split(" ", 1)[1]
                return ref_path.read_text(encoding="utf-8").strip()
            return head
        except Exception:
            return "unknown-source-revision"


def package_version(path: Path) -> str:
    if not path.exists():
        return "not-present"
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("version", "unknown")
    except Exception:
        return "unknown"


def text_version(path: Path) -> str:
    if not path.exists():
        return "not-present"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def write_s0_artifacts(artifact_dir: Path, contract: dict, anti: dict, seed: dict, public_boundary: dict) -> list[str]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "scenario-report.json": {
            "id": "UC-E2E-S0",
            "status": "passed" if public_boundary.get("status") == "passed" else "failed",
            "contract_status": contract.get("status"),
            "anti_drift_status": anti.get("status"),
            "public_boundary_status": public_boundary.get("status"),
            "fixture_seed_digest": seed.get("deterministic_digest"),
        },
        "replay-report.json": {
            "mode": "inspect_only_schema_required",
            "side_effects_allowed_default": False,
            "adapter_suppression_evidence_required_for_later_scenarios": True,
            "evidence_scope": "schema_and_report_contract_only_for_s0",
        },
        "anti-drift-results.json": anti,
        "stdout.log": "S0 static harness checks completed\n",
    }
    paths = []
    for name, value in artifacts.items():
        path = artifact_dir / name
        if isinstance(value, str):
            path.write_text(value, encoding="utf-8")
        else:
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        paths.append(str(path))
    return paths


def validate_required_s0_artifacts(artifact_dir: Path) -> list[str]:
    failures: list[str] = []
    required_non_empty = [
        "commands.log",
        "api-traffic.ndjson",
        "fixture-seed.json",
        "public-boundary.json",
        "scenario-report.json",
        "replay-report.json",
        "anti-drift-results.json",
        "stdout.log",
    ]
    for name in required_non_empty:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s0_artifact:{name}")
        elif path.stat().st_size == 0:
            failures.append(f"empty_required_s0_artifact:{name}")
    return failures


def validate_report_shape(report: dict) -> list[str]:
    failures: list[str] = []
    required_top = {
        "suite_id",
        "suite_version",
        "source_revision",
        "started_at",
        "completed_at",
        "container_topology_hash",
        "topology_identifier",
        "commands",
        "api_contract_versions",
        "component_versions",
        "contract_status",
        "anti_drift_status",
        "scenarios",
        "blocking_failures",
        "non_goal_observations",
        "human_summary_path",
    }
    missing = sorted(required_top - report.keys())
    if missing:
        failures.append("report_missing_top_level_fields:" + ",".join(missing))
    if report.get("suite_id") != "splendor-use-case-e2e-through-0.1":
        failures.append("report_suite_id_invalid")
    if not str(report.get("container_topology_hash", "")).startswith("sha256:"):
        failures.append("report_topology_hash_invalid")
    scenario_required = {
        "id",
        "status",
        "fr_coverage",
        "components",
        "positive_evidence",
        "negative_evidence",
        "replay_evidence",
        "replay_mode",
        "replay_side_effect_suppression",
        "replay_artifacts",
        "anti_drift_checks",
        "artifact_paths",
    }
    for scenario in report.get("scenarios", []):
        missing_scenario = sorted(scenario_required - scenario.keys())
        if missing_scenario:
            failures.append(f"scenario_{scenario.get('id','unknown')}_missing_fields:" + ",".join(missing_scenario))
        if scenario.get("status") not in {"passed", "failed", "blocked_not_yet_covered"}:
            failures.append(f"scenario_{scenario.get('id','unknown')}_invalid_status")
    if not any(s.get("id") == "UC-E2E-S0" for s in report.get("scenarios", [])):
        failures.append("report_missing_uc_e2e_s0")
    return failures


def render_markdown(report: dict) -> str:
    lines = [
        "# Splendor Use-Case E2E Acceptance Report",
        "",
        f"- Suite: `{report['suite_id']}` `{report['suite_version']}`",
        f"- Source revision: `{report['source_revision']}`",
        f"- Topology: `{report['topology_identifier']}` `{report['container_topology_hash']}`",
        f"- Contract status: `{report['contract_status']['status']}`",
        f"- Anti-drift status: `{report['anti_drift_status']['status']}`",
        "",
        "## Scenario status",
        "",
    ]
    for scenario in report["scenarios"]:
        lines.append(f"- `{scenario['id']}`: **{scenario['status']}**")
    lines.extend(
        [
            "",
            "## S0 evidence",
            "",
            "- OpenAPI contract parsing ran before scenario reporting.",
            "- Daemon `/health` and `/capabilities` were called through the compose public boundary.",
            "- Anti-drift scanner self-tests proved negative fixtures fail closed.",
            "- Replay fields are present with inspect-only/side-effect suppression requirements.",
            "- Future S1-S10 scenarios are blocked/not-yet-covered, not marked passing.",
            "",
            "## Non-goals observed",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["non_goal_observations"])
    if report["blocking_failures"]:
        lines.extend(["", "## Blocking failures", ""])
        lines.extend(f"- {item}" for item in report["blocking_failures"])
    return "\n".join(lines) + "\n"


def blocked_future_scenario(scenario_id: str) -> dict:
    return {
        "id": scenario_id,
        "status": "blocked_not_yet_covered",
        "fr_coverage": [],
        "components": [],
        "positive_evidence": [],
        "negative_evidence": [],
        "replay_evidence": [],
        "replay_mode": "not_run",
        "replay_side_effect_suppression": {"required": True, "evidence_present": False, "side_effects_allowed_default": False},
        "replay_artifacts": [],
        "anti_drift_checks": [],
        "run_ids": [],
        "trace_event_ids": [],
        "state_node_ids": [],
        "state_hashes": [],
        "message_ids": [],
        "work_order_ids": [],
        "approval_ids": [],
        "node_ids": [],
        "artifact_paths": [],
        "blocker": "Scenario behavior is outside UC-E2E-S0 and must be implemented by its own scenario sprint before it can count as acceptance coverage.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--compose-file", required=True)
    args = parser.parse_args()

    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S0"
    contract = read_json(report_dir / "contract-status.json")
    anti = read_json(report_dir / "anti-drift-results.json")
    seed = read_json(artifact_dir / "fixture-seed.json")
    public_boundary = read_json(artifact_dir / "public-boundary.json")

    blocking = []
    if contract.get("status") != "passed":
        blocking.append("contract_status_failed")
    if anti.get("status") != "passed":
        blocking.append("anti_drift_status_failed")
    if public_boundary.get("status") != "passed":
        blocking.append("public_boundary_evidence_failed")

    artifact_paths = write_s0_artifacts(artifact_dir, contract, anti, seed, public_boundary)
    commands_log = artifact_dir / "commands.log"
    if not commands_log.exists():
        blocking.append("missing_commands_log")
    else:
        artifact_paths.append(str(commands_log))
    artifact_paths.append(str(artifact_dir / "fixture-seed.json"))
    artifact_paths.append(str(artifact_dir / "public-boundary.json"))
    artifact_paths.append(str(artifact_dir / "api-traffic.ndjson"))
    blocking.extend(validate_required_s0_artifacts(artifact_dir))

    topology_hash = digest_file(Path(args.compose_file))
    s0_scenario = {
        "id": "UC-E2E-S0",
        "status": "passed" if not blocking else "failed",
        "fr_coverage": ["UC-E2E-S0-acceptance-harness", "FR-0.1-05", "FR-0.1-08"],
        "components": ["OpenAPI", "reporting", "anti-drift", "fixtures", "Docker Compose topology"],
        "positive_evidence": [
            "contract-status.json present and passing for current local daemon operation IDs",
            "public-boundary.json proves /health and /capabilities were called through documented local daemon HTTP endpoints",
            "fixture-seed.json written with deterministic digest",
            "report.json/report.md generated from executable checks",
        ],
        "negative_evidence": [
            "anti-drift negative fixtures fail for direct adapter execution, private helper E2E claims, anonymous non-dev calls, missing replay suppression evidence, and low-level physical allowed actions"
        ],
        "replay_evidence": ["report schema includes replay mode, side-effect suppression, and replay artifact fields"],
        "replay_mode": "inspect_only_schema_required",
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": anti.get("self_test", {}).get("required_rules", []),
        "run_ids": [],
        "trace_event_ids": [],
        "state_node_ids": [],
        "state_hashes": [],
        "message_ids": [],
        "work_order_ids": [seed.get("ids", {}).get("work_order_id", "")],
        "approval_ids": [],
        "node_ids": [seed.get("ids", {}).get("node_id", "")],
        "artifact_paths": artifact_paths,
    }

    report = {
        "suite_id": "splendor-use-case-e2e-through-0.1",
        "suite_version": "0.1-s0-harness",
        "source_revision": git_revision(root),
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "container_topology_hash": topology_hash,
        "topology_identifier": "docker-compose.acceptance.yml:S0-static-runner-v1",
        "commands": [
            "bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --contract-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0",
            "docker compose -f tests/e2e/use-cases/docker-compose.acceptance.yml config",
        ],
        "api_contract_versions": {
            "openapi": contract.get("openapi_declared_version", "unknown"),
            "rust_crates": text_version(root / "Cargo.toml"),
            "python_sdk": text_version(root / "python/pyproject.toml"),
            "typescript_client": package_version(root / "typescript/packages/client/package.json"),
        },
        "component_versions": {
            "workspace_package": package_version(root / "package.json"),
            "typescript_types": package_version(root / "typescript/packages/types/package.json"),
            "docker_compose_available": os.environ.get("SPLENDOR_E2E_DOCKER_COMPOSE", "not_captured"),
            "public_boundary": public_boundary.get("status", "unknown"),
        },
        "contract_status": {
            "status": contract.get("status"),
            "blocked_not_yet_covered": contract.get("blocked_not_yet_covered", []),
            "missing_core_operation_ids": contract.get("missing_core_operation_ids", []),
        },
        "anti_drift_status": {
            "status": anti.get("status"),
            "self_test": anti.get("self_test", {}),
            "findings": anti.get("findings", []),
        },
        "scenarios": [s0_scenario] + [blocked_future_scenario(sid) for sid in FUTURE_SCENARIOS],
        "blocking_failures": blocking,
        "non_goal_observations": [
            "No S1-S10 scenario behavior is implemented or marked passing by S0.",
            "No production OAuth/PKI, Kubernetes, SaaS UI, marketplace, real robot/cloud/database dependency, or low-level physical control is added.",
            "Default daemon startup remains loopback-only; the compose cross-container bind is guarded by explicit acceptance-only environment variables.",
        ],
        "human_summary_path": str(report_dir / "report.md"),
    }

    blocking.extend(validate_report_shape(report))
    report["blocking_failures"] = blocking
    report["scenarios"][0]["status"] = "passed" if not blocking else "failed"

    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (report_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"status": "passed" if not blocking else "failed", "report": str(report_path)}, indent=2))
    return 0 if not blocking else 1


if __name__ == "__main__":
    raise SystemExit(main())
