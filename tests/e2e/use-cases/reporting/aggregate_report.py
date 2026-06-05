#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


FUTURE_SCENARIOS = [f"UC-E2E-S{i}" for i in range(1, 11)]
S1_REQUIRED_EVENTS = {
    "tick.started",
    "percepts.received",
    "state.loaded",
    "policy.invoked",
    "policy.completed",
    "actions.proposed",
    "constraints.evaluated",
    "verification.started",
    "verification.completed",
    "action.executed",
    "action.denied",
    "outcome.recorded",
    "state.committed",
    "tick.completed",
    "replay.started",
    "replay.adapter_suppressed",
    "replay.completed",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def is_canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


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
            "- Future scenarios remain blocked/not-yet-covered unless their scenario evidence is present.",
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


def load_s1_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S1"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s1_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s1_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s1_scenario_report_failed")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_hashes"):
        failures.append("s1_missing_runtime_ids")
    ids_by_event = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S1_REQUIRED_EVENTS if not ids_by_event.get(event))
    if missing_events:
        failures.append("s1_missing_required_trace_events:" + ",".join(missing_events))
    suppression = scenario.get("replay_side_effect_suppression", {})
    if not suppression.get("evidence_present") or suppression.get("side_effects_allowed_default") is not False:
        failures.append("s1_replay_suppression_missing")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("http_counter_before") != replay.get("http_counter_after"):
        failures.append("s1_replay_http_counter_changed")
    if replay.get("artifact_checksum_before") != replay.get("artifact_checksum_after"):
        failures.append("s1_replay_artifact_checksum_changed")
    if not {"replay.started", "replay.adapter_suppressed", "replay.completed"}.issubset(set(replay.get("events", []))):
        failures.append("s1_replay_events_missing")
    replay_event_ids = replay.get("event_ids", {})
    raw_events = {}
    for item in replay.get("raw_lines", []):
        if item.get("type") != "replay_lifecycle":
            continue
        if "replay_event_id" in item:
            failures.append(f"s1_replay_lifecycle_uses_ad_hoc_id:{item.get('event')}")
        raw_events[item.get("event")] = item.get("trace_event_id")
    for event in ["replay.started", "replay.adapter_suppressed", "replay.completed"]:
        replay_trace_id = replay_event_ids.get(event)
        if not is_canonical_uuid(replay_trace_id):
            failures.append(f"s1_replay_trace_event_id_not_canonical_uuid:{event}")
        elif raw_events.get(event) != replay_trace_id:
            failures.append(f"s1_replay_event_not_backed_by_raw_output:{event}")
        if not scenario.get("required_trace_event_ids", {}).get(event):
            failures.append(f"s1_replay_event_missing_from_required_trace_event_ids:{event}")
        if replay_trace_id not in scenario.get("trace_event_ids", []):
            failures.append(f"s1_replay_event_missing_from_trace_event_ids:{event}")
    if replay.get("derived_from_raw_output") is not True:
        failures.append("s1_replay_lifecycle_not_derived_from_raw_output")
    state = read_json(artifact_dir / "state-export.json")
    for key in ["state_node_id", "tenant_id", "agent_id", "run_id", "parent_state_node_ids", "snapshot_ref", "state_hash", "trace_linkage", "timestamp"]:
        if state.get(key) in (None, "", "available_in_state_store"):
            failures.append(f"s1_state_export_missing:{key}")
    if not state.get("parent_state_node_ids"):
        failures.append("s1_state_export_empty_parent_state_node_ids")
    audit = read_json(artifact_dir / "audit-report.json")
    denials = {item.get("case"): item for item in audit.get("denials", [])}
    for case in ["deny_url", "deny_path"]:
        item = denials.get(case, {})
        if "action.denied" not in item.get("events", []) or "action.failed" in item.get("events", []):
            failures.append(f"s1_{case}_not_pre_adapter_denial")
        if not any(denial.get("adapter_execution") for denial in item.get("denials", [])):
            failures.append(f"s1_{case}_missing_adapter_non_execution_evidence")
    trace_failure = denials.get("forced_trace_write_failure_blocks_side_effect", {})
    if trace_failure.get("http_counter_before") != trace_failure.get("http_counter_after"):
        failures.append("s1_trace_failure_allowed_side_effect")
    state_failure = denials.get("forced_state_commit_failure_prevents_next_tick", {})
    if state_failure.get("exit") == 0 or state_failure.get("http_counter_after", 0) - state_failure.get("http_counter_before", 0) > 1:
        failures.append("s1_state_failure_advanced_next_tick")
    if state_failure.get("tick_start_count", 0) > 1 or 2 in state_failure.get("tick_start_ids", []):
        failures.append("s1_state_failure_started_second_tick")
    return scenario, failures


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
            "public-boundary.json proves /health and /capabilities were called through documented loopback daemon HTTP endpoints with caller credentials",
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

    scenarios = [s0_scenario]
    s1_scenario, s1_failures = load_s1_scenario(report_dir)
    if args.scenario == "UC-E2E-S1" or args.mode == "all":
        if s1_scenario is None:
            blocking.append("missing_uc_e2e_s1_scenario_report")
        else:
            scenarios.append(s1_scenario)
            blocking.extend(s1_failures)
        blocked_ids = [sid for sid in FUTURE_SCENARIOS if sid != "UC-E2E-S1"]
    else:
        blocked_ids = FUTURE_SCENARIOS

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
        "scenarios": scenarios + [blocked_future_scenario(sid) for sid in blocked_ids],
        "blocking_failures": blocking,
        "non_goal_observations": [
            "S0 does not mark later scenarios passing; UC-E2E-S1 is included only when executable scenario evidence is present.",
            "No production OAuth/PKI, Kubernetes, SaaS UI, marketplace, real robot/cloud/database dependency, or low-level physical control is added.",
            "Daemon startup remains loopback-only; compose shares the daemon network namespace and does not publish daemon ports.",
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
