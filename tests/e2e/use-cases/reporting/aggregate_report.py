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
S2_REQUIRED_OPERATIONS = {
    "getHealth",
    "getVersion",
    "getCapabilities",
    "createRun",
    "inspectRun",
    "startRun",
    "pauseRun",
    "resumeRun",
    "cancelRun",
    "appendPercept",
    "submitAction",
    "getStateHead",
    "getRunTraces",
    "exportTraces",
    "replayRun",
}
S2_REQUIRED_NEGATIVES = {
    "management_token_alone_cannot_authorize_arbitrary_action",
    "wrong_endpoint_scope",
    "expired_caller_credential",
    "wrong_caller_audience",
    "unsigned_work_order",
    "expired_work_order",
    "revoked_work_order",
    "malformed_work_order",
    "bad_signature_work_order",
    "action_wrong_scope_rejected_before_gateway",
}
S3_REQUIRED_EVENTS = {
    "message.queued",
    "message.delivered",
    "message.consumed",
    "message.rejected",
    "delegation.requested",
    "delegation.rejected",
    "child_run.started",
    "child_run.completed",
    "action.executed",
    "action.denied",
    "state.committed",
}
S3_REQUIRED_NEGATIVES = {
    "specialist_external_artifact_publish_denied",
    "unauthorized_recipient_message_denied",
    "unsupported_message_schema_rejected_before_delivery",
    "broad_permission_data_ref_smuggling_denied",
    "cross_tenant_message_attempt_rejected",
    "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger",
}
S4_REQUIRED_OPERATIONS = {
    "registerNode",
    "registerInstance",
    "heartbeatNode",
    "advertiseCapabilities",
    "evaluatePlacement",
    "submitWorkOrder",
    "dispatchWorkOrder",
    "sendMessage",
    "exportStateSnapshot",
    "importStateSnapshot",
    "syncTraceBuffer",
    "getFleetTelemetry",
}
S4_REQUIRED_NEGATIVES = {
    "unsigned_work_order",
    "expired_work_order",
    "revoked_work_order",
    "wrong_audience_work_order",
    "wrong_tenant_credential",
    "capability_mismatch",
    "duplicate_remote_message",
    "remote_message_delivery_failure",
    "state_handoff_wrong_tenant_rejected",
    "telemetry_non_authoritative",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"required evidence artifact missing: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def trace_record_id(record: dict) -> str:
    return str(record.get("payload", {}).get("trace_event_id", ""))


def trace_record_kind(record: dict) -> str:
    kind = record.get("payload", {}).get("kind")
    key = kind if isinstance(kind, str) else next(iter(kind.keys())) if isinstance(kind, dict) and kind else "unknown"
    return {
        "LoopTickStarted": "tick.started",
        "LoopTickCompleted": "tick.completed",
        "PolicyCompleted": "policy.completed",
        "MessageQueued": "message.queued",
        "MessageDelivered": "message.delivered",
        "MessageConsumed": "message.consumed",
        "MessageRejected": "message.rejected",
        "DelegationRequested": "delegation.requested",
        "DelegationRejected": "delegation.rejected",
        "ChildRunStarted": "child_run.started",
        "ChildRunCompleted": "child_run.completed",
        "ActionVerificationCompleted": "verification.completed",
        "ActionExecuted": "action.executed",
        "ActionDenied": "action.denied",
        "OutcomeRecorded": "outcome.recorded",
        "StateCommitted": "state.committed",
    }.get(key, key)


def trace_record_kind_payload(record: dict) -> dict:
    kind = record.get("payload", {}).get("kind")
    if isinstance(kind, dict) and kind:
        value = next(iter(kind.values()))
        return value if isinstance(value, dict) else {}
    return {}


def content_hash_string(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        algorithm = str(value.get("algorithm", "")).lower()
        digest = value.get("value")
        if algorithm and digest:
            return f"{algorithm}:{digest}"
    return ""


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
            "## S2 evidence",
            "",
            "- Management API traffic is recorded in `artifacts/UC-E2E-S2/api-traffic.ndjson` when S2 runs.",
            "- S2 requires health/version/capabilities, run lifecycle, percept, action, state, trace export, and replay operations.",
            "- S2 requires caller credentials, endpoint scopes, signed work orders, audit attribution, gateway denial evidence, and replay adapter-suppression evidence.",
            "",
            "## S3 evidence",
            "",
            "- Local multi-agent delegation evidence is recorded in `artifacts/UC-E2E-S3/` when S3 runs.",
            "- S3 requires typed task request/response messages, parent/child runs, scoped specialist authority, gateway denial evidence, state commits, and replay causal graph reconstruction.",
            "- S3 is local-only and does not claim daemon message API, remote transport, fleet, governance, or physical/edge coverage.",
            "",
            "## S4 evidence",
            "",
            "- Fleet dispatch evidence is recorded in `artifacts/UC-E2E-S4/` when S4 runs.",
            "- S4 requires public manager/resident HTTP APIs, same-image Splendor services, signed work-order validation, placement, remote messages, state handoff, trace sync, telemetry, and replay/audit evidence.",
            "- S4 keeps telemetry observational only and leaves S5-S10 blocked until their own scenario evidence exists.",
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


def load_s2_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S2"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "schema-parity.json",
        "typescript-client-workflow.json",
        "python-sdk-workflow.json",
        "splendorctl-workflow.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s2_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s2_artifact:{name}")
    scenario_blockers = scenario.get("blocking_failures", [])
    for blocker in scenario_blockers:
        if blocker not in failures:
            failures.append(blocker)
    if scenario.get("status") == "partial":
        failures.append("s2_scenario_partial")
    elif scenario.get("status") != "passed":
        failures.append("s2_scenario_report_failed")
    if not scenario.get("run_ids") or not scenario.get("trace_event_ids") or not scenario.get("state_node_ids") or not scenario.get("state_hashes"):
        failures.append("s2_missing_runtime_ids")
    if not scenario.get("work_order_ids"):
        failures.append("s2_missing_work_order_ids")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S2_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s2_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S2_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s2_missing_negative_cases:" + ",".join(missing_negatives))
    for case in ["wrong_endpoint_scope", "expired_caller_credential", "wrong_caller_audience", "action_wrong_scope_rejected_before_gateway"]:
        if negatives.get(case, {}).get("status") != 403:
            failures.append(f"s2_{case}_not_forbidden")
    for case in ["unsigned_work_order", "expired_work_order", "revoked_work_order", "malformed_work_order", "bad_signature_work_order"]:
        if negatives.get(case, {}).get("status") not in {400, 403}:
            failures.append(f"s2_{case}_not_rejected")
    arbitrary = negatives.get("management_token_alone_cannot_authorize_arbitrary_action", {})
    if arbitrary.get("outcome_status") != "Denied":
        failures.append("s2_arbitrary_action_not_denied")
    if arbitrary.get("adapter_executions_before") != arbitrary.get("adapter_executions_after"):
        failures.append("s2_arbitrary_action_reached_adapter")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only":
        failures.append("s2_replay_not_inspect_only")
    if replay.get("side_effects_allowed_default") is not False:
        failures.append("s2_replay_side_effect_default_not_false")
    if replay.get("adapter_executions_before") != replay.get("adapter_executions_after"):
        failures.append("s2_replay_executed_adapter")
    suppression = scenario.get("replay_side_effect_suppression", {})
    if not suppression.get("evidence_present") or suppression.get("side_effects_allowed_default") is not False:
        failures.append("s2_replay_suppression_missing")
    state = read_json(artifact_dir / "state-export.json")
    for key in ["state_node_id", "data_hash", "run_id", "tenant_id", "agent_id"]:
        if not state.get(key):
            failures.append(f"s2_state_export_missing:{key}")
    schema = read_json(artifact_dir / "schema-parity.json")
    client_paths = scenario.get("client_path_coverage", {})
    for path_name in ["raw_openapi_http", "typescript_client", "python_sdk", "splendorctl"]:
        if client_paths.get(path_name, {}).get("executable_workflow") is not True:
            failures.append(f"s2_client_path_not_executable:{path_name}")
    raw_http = client_paths.get("raw_openapi_http", {})
    raw_missing = sorted(S2_REQUIRED_OPERATIONS - set(raw_http.get("operations_observed", [])))
    if raw_missing:
        failures.append("s2_raw_http_workflow_missing_ops:" + ",".join(raw_missing))
    if not raw_http.get("evidence_artifacts"):
        failures.append("s2_raw_http_workflow_missing_evidence_artifacts")
    workflow_artifacts = {
        "typescript_client": "typescript-client-workflow.json",
        "python_sdk": "python-sdk-workflow.json",
        "splendorctl": "splendorctl-workflow.json",
    }
    for path_name, artifact_name in workflow_artifacts.items():
        workflow = read_json(artifact_dir / artifact_name)
        if workflow.get("status") != "passed" or workflow.get("executable_workflow") is not True:
            failures.append(f"s2_client_workflow_artifact_not_passed:{path_name}")
        observed = set(workflow.get("operations_observed", []))
        missing = sorted({"createRun", "appendPercept", "startRun", "submitAction", "getStateHead", "getRunTraces", "exportTraces", "replayRun", "cancelRun"} - observed)
        if missing:
            failures.append(f"s2_client_workflow_missing_ops:{path_name}:" + ",".join(missing))
        if workflow.get("action_status") != "Executed":
            failures.append(f"s2_client_workflow_action_not_executed:{path_name}")
        if workflow.get("adapter_executions_before_replay") != workflow.get("adapter_executions_after_replay"):
            failures.append(f"s2_client_workflow_replay_executed_adapter:{path_name}")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    if anti.get("status") != "passed":
        failures.append("s2_anti_drift_failed")
    if anti.get("health_capabilities_or_version_authorize_actions") is not False:
        failures.append("s2_health_capabilities_version_authoritative")
    if anti.get("management_token_authorizes_action_without_gateway") is not False:
        failures.append("s2_management_token_authorized_action")
    event_ids = scenario.get("required_trace_event_ids", {})
    for event in ["daemon.audit", "percepts.appended", "tick.started", "state.committed", "verification.started", "verification.completed", "action.executed", "action.denied", "outcome.recorded", "run.paused", "run.resumed", "run.cancelled_or_stopped"]:
        if not event_ids.get(event):
            failures.append(f"s2_missing_required_trace_event:{event}")
    for trace_id in scenario.get("trace_event_ids", [])[:20]:
        if trace_id and not is_canonical_uuid(trace_id):
            failures.append("s2_trace_event_id_not_canonical_uuid")
            break
    return scenario, failures


def load_s3_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S3"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "commands.log",
        "api-traffic.ndjson",
        "trace-export.jsonl",
        "state-export.json",
        "replay-report.json",
        "message-causal-graph.json",
        "audit-report.json",
        "anti-drift-results.json",
        "runtime-evidence.json",
        "schema-parity.json",
        "schema-parity-rust.json",
        "schema-parity-typescript.json",
        "schema-parity-python.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s3_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s3_artifact:{name}")
    for blocker in scenario.get("blocking_failures", []):
        if blocker not in failures:
            failures.append(blocker)
    if scenario.get("status") != "passed":
        failures.append("s3_scenario_report_failed")
    if len(scenario.get("run_ids", [])) < 2:
        failures.append("s3_missing_parent_child_run_ids")
    if len(scenario.get("message_ids", [])) < 4:
        failures.append("s3_missing_message_ids")
    if len(scenario.get("state_node_ids", [])) < 2 or len(scenario.get("state_hashes", [])) < 2:
        failures.append("s3_missing_parent_child_state_evidence")
    ids_by_event = scenario.get("required_trace_event_ids", {})
    missing_events = sorted(event for event in S3_REQUIRED_EVENTS if not ids_by_event.get(event))
    if missing_events:
        failures.append("s3_missing_required_trace_events:" + ",".join(missing_events))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S3_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s3_missing_negative_cases:" + ",".join(missing_negatives))
    for case, item in negatives.items():
        if item.get("adapter_executions_before") != item.get("adapter_executions_after") and case != "broad_permission_data_ref_smuggling_denied":
            failures.append(f"s3_denial_reached_adapter:{case}")
        if not item.get("reason_codes"):
            failures.append(f"s3_negative_missing_reason_codes:{case}")
    trace_records = read_jsonl(artifact_dir / "trace-export.jsonl")
    trace_by_id = {trace_record_id(record): record for record in trace_records if trace_record_id(record)}
    expected_negative_kinds = {
        "specialist_external_artifact_publish_denied": "action.denied",
        "unauthorized_recipient_message_denied": "message.rejected",
        "unsupported_message_schema_rejected_before_delivery": "message.rejected",
        "broad_permission_data_ref_smuggling_denied": "delegation.rejected",
        "cross_tenant_message_attempt_rejected": "delegation.rejected",
        "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger": "action.denied",
    }
    expected_reason_text = {
        "unsupported_message_schema_rejected_before_delivery": ["unsupported"],
    }
    for case, item in negatives.items():
        expected_kind = expected_negative_kinds.get(case)
        trace_ids = item.get("trace_event_ids") or []
        if not trace_ids:
            failures.append(f"s3_negative_missing_trace_ids:{case}")
            continue
        for trace_id in trace_ids:
            if not is_canonical_uuid(trace_id):
                failures.append(f"s3_negative_trace_id_not_canonical:{case}")
                continue
            record = trace_by_id.get(trace_id)
            if record is None:
                failures.append(f"s3_negative_trace_id_missing_from_export:{case}:{trace_id}")
                continue
            if expected_kind and trace_record_kind(record) != expected_kind:
                failures.append(f"s3_negative_trace_wrong_kind:{case}:{trace_record_kind(record)}")
            record_text = json.dumps(record, sort_keys=True)
            for reason in expected_reason_text.get(case, item.get("reason_codes", [])):
                if reason not in record_text:
                    failures.append(f"s3_negative_trace_wrong_reason:{case}:{reason}")
            message_id = item.get("message_id")
            if message_id and message_id not in record_text:
                failures.append(f"s3_negative_trace_wrong_message:{case}:{message_id}")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only":
        failures.append("s3_replay_not_inspect_only")
    if replay.get("side_effects_replayed") is not False or replay.get("side_effects_allowed_default") is not False:
        failures.append("s3_replay_side_effect_suppression_missing")
    if len(replay.get("messages", [])) < 4:
        failures.append("s3_replay_missing_messages")
    lifecycles = {message.get("lifecycle") for message in replay.get("messages", [])}
    for lifecycle in ["queued", "delivered", "consumed", "rejected"]:
        if lifecycle not in lifecycles:
            failures.append(f"s3_replay_missing_message_lifecycle:{lifecycle}")
    if not replay.get("parent_child_runs"):
        failures.append("s3_replay_missing_parent_child_runs")
    if not replay.get("isolation_denials"):
        failures.append("s3_replay_missing_isolation_denials")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    if anti.get("status") != "passed":
        failures.append("s3_anti_drift_failed")
    expected_false = [
        "private_helper_only_e2e",
        "gateway_bypass",
        "specialist_broad_permission_inheritance",
        "hidden_shared_state",
        "replay_side_effects_allowed_default",
        "remote_transport",
        "fleet_governance_or_physical_scope",
    ]
    for key in expected_false:
        if anti.get(key) is not False:
            failures.append(f"s3_anti_drift_expected_false:{key}")
    runtime = read_json(artifact_dir / "runtime-evidence.json")
    delegated = runtime.get("delegated_authority", {})
    if "artifact.publish_external" in delegated.get("allowed_permissions", []):
        failures.append("s3_specialist_delegation_includes_broad_publish_permission")
    state_export = read_json(artifact_dir / "state-export.json")
    state_commit_ids = set(scenario.get("required_trace_event_ids", {}).get("state.committed", []))
    for state_name in ["parent", "child"]:
        state = state_export.get(state_name, {})
        trace_id = state.get("trace_event_id")
        metadata_trace_id = state.get("metadata_trace_event_id")
        if not trace_id or trace_id != metadata_trace_id:
            failures.append(f"s3_state_metadata_trace_mismatch:{state_name}")
        if trace_id not in trace_by_id or trace_record_kind(trace_by_id.get(trace_id, {})) != "state.committed":
            failures.append(f"s3_state_trace_not_committed_event:{state_name}")
        if trace_id not in state_commit_ids:
            failures.append(f"s3_state_trace_missing_from_required_events:{state_name}")
        trace_state_hash = content_hash_string(
            trace_record_kind_payload(trace_by_id.get(trace_id, {})).get("state_hash")
        )
        if state.get("state_hash") != trace_state_hash:
            failures.append(f"s3_state_hash_trace_mismatch:{state_name}")
        if not state.get("state_node_hash"):
            failures.append(f"s3_state_node_hash_missing:{state_name}")
    schema = read_json(artifact_dir / "schema-parity.json")
    if schema.get("status") != "passed":
        failures.append("s3_schema_parity_not_passed")
    rust_schema = schema.get("rust", {})
    typescript_schema = schema.get("typescript", {})
    python_schema = schema.get("python", {})
    if typescript_schema.get("status") != "passed" or typescript_schema.get("executable_check") is not True:
        failures.append("s3_typescript_schema_parity_not_executable")
    if python_schema.get("status") != "passed" or python_schema.get("executable_check") is not True:
        failures.append("s3_python_schema_parity_not_executable")
    missing_python_fields = python_schema.get("missing_canonical_message_fields", [])
    if missing_python_fields:
        failures.append("s3_python_missing_canonical_message_fields:" + ",".join(missing_python_fields))
    canonical_fields = set(rust_schema.get("task_request_message", {}).keys())
    python_present_fields = set(python_schema.get("message_required_fields_present", []))
    missing_present_fields = sorted(canonical_fields - python_present_fields)
    if missing_present_fields:
        failures.append("s3_python_required_fields_do_not_cover_canonical_message:" + ",".join(missing_present_fields))
    if "causal_parent" not in python_present_fields:
        failures.append("s3_python_message_required_fields_missing_causal_parent")
    for callback in ["perceptor", "policy", "trace_subscriber"]:
        if callback not in python_schema.get("callbacks_observed", []):
            failures.append(f"s3_python_callback_missing:{callback}")
    if python_schema.get("actions_proposed") != 0 or python_schema.get("adapter_callbacks_executed") != 0:
        failures.append("s3_python_callback_side_effect_boundary_failed")
    if rust_schema.get("task_request_schema") != "splendor.message.task_request.v1" or rust_schema.get("task_response_schema") != "splendor.message.task_response.v1":
        failures.append("s3_rust_schema_parity_wrong_schema")
    return scenario, failures


def load_s4_scenario(report_dir: Path) -> tuple[dict | None, list[str]]:
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S4"
    scenario_path = artifact_dir / "scenario-report.json"
    if not scenario_path.exists():
        return None, []
    scenario = read_json(scenario_path)
    failures: list[str] = []
    required = [
        "scenario-report.json",
        "api-traffic.ndjson",
        "registry.json",
        "capabilities.json",
        "work-order-validation.json",
        "placement-decision.json",
        "dispatch-report.json",
        "remote-message-report.json",
        "state-handoff-report.json",
        "trace-sync-report.json",
        "fleet-telemetry.json",
        "trace-export.jsonl",
        "replay-report.json",
        "audit-report.json",
        "anti-drift-results.json",
        "stdout.log",
        "stderr.log",
    ]
    for name in required:
        path = artifact_dir / name
        if not path.exists():
            failures.append(f"missing_required_s4_artifact:{name}")
        elif path.stat().st_size == 0 and name != "stderr.log":
            failures.append(f"empty_required_s4_artifact:{name}")
    if scenario.get("status") != "passed":
        failures.append("s4_scenario_report_failed")
    operations = set(scenario.get("api_operations", []))
    missing_ops = sorted(S4_REQUIRED_OPERATIONS - operations)
    if missing_ops:
        failures.append("s4_missing_required_api_operations:" + ",".join(missing_ops))
    negatives = {item.get("case"): item for item in scenario.get("negative_cases", [])}
    missing_negatives = sorted(S4_REQUIRED_NEGATIVES - set(negatives))
    if missing_negatives:
        failures.append("s4_missing_negative_cases:" + ",".join(missing_negatives))
    same_image = scenario.get("same_image_fleet_evidence", {})
    if same_image.get("all_same") is not True or same_image.get("same_build_target") != "runtime":
        failures.append("s4_same_image_fleet_evidence_missing")
    if len(same_image.get("splendor_services", [])) < 5:
        failures.append("s4_same_image_missing_splendor_services")
    placement = read_json(artifact_dir / "placement-decision.json")
    if placement.get("status") != "selected" or placement.get("candidate_id") not in scenario.get("node_ids", []):
        failures.append("s4_vpc_placement_not_selected")
    dispatch = read_json(artifact_dir / "dispatch-report.json")
    if dispatch.get("create_run_status") not in {200, 201} or dispatch.get("start_run_status") not in {200, 201}:
        failures.append("s4_dispatch_did_not_create_and_start_resident_run")
    remote = read_json(artifact_dir / "remote-message-report.json")
    if remote.get("delivered", {}).get("delivery_status") != "delivered":
        failures.append("s4_remote_message_not_delivered")
    if remote.get("duplicate", {}).get("duplicate") is not True:
        failures.append("s4_duplicate_message_not_detected")
    if remote.get("failed", {}).get("delivery_status") != "failed":
        failures.append("s4_remote_failure_not_trace_linked")
    handoff = read_json(artifact_dir / "state-handoff-report.json")
    if not handoff.get("exported", {}).get("handoff") or handoff.get("imported", {}).get("accepted") is not True:
        failures.append("s4_state_handoff_export_import_missing")
    if handoff.get("rejected", {}).get("status") not in {400, 403}:
        failures.append("s4_bad_state_handoff_not_rejected")
    telemetry = read_json(artifact_dir / "fleet-telemetry.json")
    if telemetry.get("authority") != "observational_only":
        failures.append("s4_telemetry_not_observational_only")
    if len(telemetry.get("nodes", [])) < 2 or len(telemetry.get("instances", [])) < 2:
        failures.append("s4_telemetry_missing_node_instance_status")
    replay = read_json(artifact_dir / "replay-report.json")
    if replay.get("mode") != "inspect_only" or replay.get("side_effects_allowed_default") is not False or replay.get("remote_messages_resent") is not False:
        failures.append("s4_replay_suppression_missing")
    anti = read_json(artifact_dir / "anti-drift-results.json")
    for key in ["same_image_fleet", "private_helper_only_e2e", "telemetry_authorizes_dispatch", "gateway_bypass", "replay_side_effects_allowed_default"]:
        if key == "same_image_fleet":
            if anti.get(key) is not True:
                failures.append("s4_anti_drift_same_image_not_true")
        elif anti.get(key) is not False:
            failures.append(f"s4_anti_drift_expected_false:{key}")
    if not scenario.get("run_ids") or len(scenario.get("node_ids", [])) < 2 or not scenario.get("work_order_ids") or not scenario.get("message_ids"):
        failures.append("s4_missing_required_identity_evidence")
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
    s2_scenario, s2_failures = load_s2_scenario(report_dir)
    s3_scenario, s3_failures = load_s3_scenario(report_dir)
    s4_scenario, s4_failures = load_s4_scenario(report_dir)
    active_ids: set[str] = set()
    if args.scenario == "UC-E2E-S1" or args.mode == "all":
        active_ids.add("UC-E2E-S1")
        if s1_scenario is None:
            blocking.append("missing_uc_e2e_s1_scenario_report")
        else:
            scenarios.append(s1_scenario)
            blocking.extend(s1_failures)
    if args.scenario == "UC-E2E-S2" or args.mode == "all":
        active_ids.add("UC-E2E-S2")
        if s2_scenario is None:
            blocking.append("missing_uc_e2e_s2_scenario_report")
        else:
            scenarios.append(s2_scenario)
            blocking.extend(s2_failures)
    if args.scenario == "UC-E2E-S3" or args.mode == "all":
        active_ids.add("UC-E2E-S3")
        if s3_scenario is None:
            blocking.append("missing_uc_e2e_s3_scenario_report")
        else:
            scenarios.append(s3_scenario)
            blocking.extend(s3_failures)
    if args.scenario == "UC-E2E-S4" or args.mode == "all":
        active_ids.add("UC-E2E-S4")
        if s4_scenario is None:
            blocking.append("missing_uc_e2e_s4_scenario_report")
        else:
            scenarios.append(s4_scenario)
            blocking.extend(s4_failures)
    blocked_ids = [sid for sid in FUTURE_SCENARIOS if sid not in active_ids]

    report = {
        "suite_id": "splendor-use-case-e2e-through-0.1",
        "suite_version": "0.1-s4-fleet-dispatch",
        "source_revision": git_revision(root),
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "container_topology_hash": topology_hash,
        "topology_identifier": "docker-compose.acceptance.yml:S0-static-runner-v1",
        "commands": [
            "bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --contract-only",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S2",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S3",
            "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S4",
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
            "UC-E2E-S2 validates the local management API/client contract only when raw HTTP, TypeScript, Python SDK, and splendorctl executable workflow evidence is present.",
            "UC-E2E-S3 validates local multi-agent delegation through public crate APIs and splendorctl replay only; it does not claim daemon message API coverage.",
            "UC-E2E-S4 validates fleet dispatch through public manager and resident daemon HTTP APIs with same-image Splendor services.",
            "S5-S10 remain blocked until their own executable scenario evidence is present.",
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
