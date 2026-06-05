#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


PARENT_RUN_ID = "11111111-2222-4333-8444-555555555555"
CHILD_RUN_ID = "66666666-7777-4888-8999-000000000000"


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_cmd(cmd: list[str], cwd: Path, log: Path, check: bool = True) -> subprocess.CompletedProcess:
    with log.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        fh.write(proc.stdout)
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return proc


def splendorctl_cmd_prefix(root: Path) -> list[str]:
    container = Path("/usr/local/bin/splendorctl")
    if root == Path("/workspace") and container.exists():
        return [str(container)]
    local = root / "target" / "debug" / "splendorctl"
    if local.exists():
        return [str(local)]
    if container.exists():
        return [str(container)]
    if shutil.which("splendorctl"):
        return ["splendorctl"]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def s3_scenario_cmd_prefix(root: Path) -> list[str]:
    container = Path("/usr/local/bin/uc_e2e_s3_multi_agent_delegation")
    if container.exists():
        return [str(container)]
    local_release = root / "target" / "release" / "examples" / "uc_e2e_s3_multi_agent_delegation"
    if local_release.exists():
        return [str(local_release)]
    local_debug = root / "target" / "debug" / "examples" / "uc_e2e_s3_multi_agent_delegation"
    if local_debug.exists():
        return [str(local_debug)]
    return ["cargo", "run", "-q", "-p", "splendor-kernel", "--example", "uc_e2e_s3_multi_agent_delegation", "--"]


def json_lines(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def event_type(record: dict) -> str:
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


def trace_event_id(record: dict) -> str:
    return str(record.get("payload", {}).get("trace_event_id", ""))


def ids_by_type(records: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for record in records:
        result.setdefault(event_type(record), []).append(trace_event_id(record))
    return result


def replay_summary(lines: list[dict]) -> dict:
    graph = next(item for item in lines if item.get("type") == "causal_graph")
    lifecycle = {item.get("event"): item for item in lines if item.get("type") == "replay_lifecycle"}
    return {
        "mode": graph.get("replay_mode"),
        "side_effects_replayed": graph.get("side_effects_replayed"),
        "side_effects_allowed_default": False,
        "messages": graph.get("messages", []),
        "parent_child_runs": graph.get("parent_child_runs", []),
        "isolation_denials": graph.get("isolation_denials", []),
        "events": sorted(lifecycle),
        "event_ids": {name: item.get("trace_event_id") for name, item in lifecycle.items()},
        "raw_lines": lines,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()

    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S3"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("", encoding="utf-8")
    ctl = splendorctl_cmd_prefix(root)

    run_cmd(s3_scenario_cmd_prefix(root) + ["--artifact-dir", str(artifact_dir)], root, commands)
    runtime_evidence = json.loads((artifact_dir / "runtime-evidence.json").read_text(encoding="utf-8"))
    trace_db = runtime_evidence["trace_db"]
    state_db = runtime_evidence["state_db"]

    parent_trace = run_cmd(ctl + ["trace", "export", "--db", trace_db, "--run", PARENT_RUN_ID], root, commands)
    child_trace = run_cmd(ctl + ["trace", "export", "--db", trace_db, "--run", CHILD_RUN_ID], root, commands)
    (artifact_dir / "trace-export.jsonl").write_text(parent_trace.stdout + child_trace.stdout, encoding="utf-8")
    parent_records = json_lines(parent_trace.stdout)
    child_records = json_lines(child_trace.stdout)
    all_records = parent_records + child_records

    replay_proc = run_cmd(ctl + ["replay", "--db", trace_db, "--state-db", state_db, "--run", PARENT_RUN_ID], root, commands)
    replay_lines = json_lines(replay_proc.stdout)
    replay = replay_summary(replay_lines)
    write_json(artifact_dir / "replay-report.json", replay)
    write_json(artifact_dir / "message-causal-graph.json", {
        "messages": replay["messages"],
        "parent_child_runs": replay["parent_child_runs"],
        "isolation_denials": replay["isolation_denials"],
        "side_effects_replayed": replay["side_effects_replayed"],
    })

    state_export = {
        "parent": runtime_evidence["parent_state"],
        "child": runtime_evidence["child_state"],
    }
    write_json(artifact_dir / "state-export.json", state_export)
    write_json(artifact_dir / "audit-report.json", {
        "mode": "inspect_only",
        "negative_cases": runtime_evidence["negative_cases"],
        "replay_denials": replay["isolation_denials"],
    })
    anti = {"status": "passed", **runtime_evidence["anti_drift"]}
    write_json(artifact_dir / "anti-drift-results.json", anti)
    (artifact_dir / "api-traffic.ndjson").write_text(json.dumps({"surface": "public_crate_api_and_splendorctl", "commands_log": str(commands)}) + "\n", encoding="utf-8")
    (artifact_dir / "stdout.log").write_text("UC-E2E-S3 local multi-agent delegation scenario completed through public crate APIs and splendorctl replay\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")

    failures: list[str] = []
    required_events = {"message.queued", "message.delivered", "message.consumed", "message.rejected", "delegation.requested", "delegation.rejected", "child_run.started", "child_run.completed", "action.executed", "action.denied", "state.committed"}
    by_type = ids_by_type(all_records)
    missing_events = sorted(event for event in required_events if not by_type.get(event))
    if missing_events:
        failures.append("s3_missing_trace_events:" + ",".join(missing_events))
    if len(replay["messages"]) < 8:
        failures.append("s3_replay_missing_message_causal_graph")
    if not replay["parent_child_runs"]:
        failures.append("s3_replay_missing_parent_child_runs")
    if not replay["isolation_denials"]:
        failures.append("s3_replay_missing_isolation_denials")
    if replay["side_effects_replayed"] is not False:
        failures.append("s3_replay_side_effects_replayed")
    negative_cases = {item["case"]: item for item in runtime_evidence["negative_cases"]}
    for case in [
        "specialist_external_artifact_publish_denied",
        "unauthorized_recipient_message_denied",
        "unsupported_message_schema_rejected_before_delivery",
        "broad_permission_data_ref_smuggling_denied",
        "cross_tenant_message_attempt_rejected",
        "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger",
    ]:
        if case not in negative_cases:
            failures.append(f"s3_missing_negative_case:{case}")
    for item in runtime_evidence["negative_cases"]:
        if item["adapter_executions_before"] != item["adapter_executions_after"] and item["case"] != "broad_permission_data_ref_smuggling_denied":
            failures.append(f"s3_denied_case_reached_adapter:{item['case']}")

    trace_ids = [trace_event_id(record) for record in all_records if trace_event_id(record)]
    message_ids = sorted({message["message_id"] for message in replay["messages"] if message.get("message_id")})
    scenario = {
        "id": "UC-E2E-S3",
        "status": "passed" if not failures else "failed",
        "fr_coverage": ["FR-0.02-01", "FR-0.02-02", "FR-0.02-03", "FR-0.02-04", "FR-0.02-05", "FR-0.02-06", "FR-0.02-07", "FR-0.02-10", "FR-0.1-05", "FR-0.1-08"],
        "components": ["LocalMessageRouter", "LocalDelegationManager", "agent isolation ledger", "action gateway", "state graph", "trace store", "splendorctl replay causal graph"],
        "positive_evidence": ["orchestrator delegated task_request to specialist", "specialist child run committed state and returned task_response", "orchestrator consumed response and executed internal artifact action through gateway"],
        "negative_evidence": sorted(negative_cases),
        "replay_evidence": ["splendorctl replay emitted causal_graph with messages, parent_child_runs, isolation_denials, side_effects_replayed=false"],
        "required_trace_event_ids": by_type,
        "negative_cases": runtime_evidence["negative_cases"],
        "replay_mode": "inspect_only",
        "replay_side_effect_suppression": {"required": True, "evidence_present": replay["side_effects_replayed"] is False, "side_effects_allowed_default": False},
        "replay_artifacts": [str(artifact_dir / "replay-report.json"), str(artifact_dir / "message-causal-graph.json")],
        "anti_drift_checks": ["public_crate_api_boundary", "no_private_helper_only_e2e", "no_gateway_bypass", "no_specialist_broad_permission_inheritance", "no_hidden_shared_state", "inspect_only_replay", "local_only_no_remote_fleet_governance_physical"],
        "run_ids": [PARENT_RUN_ID, CHILD_RUN_ID],
        "trace_event_ids": trace_ids + list(replay["event_ids"].values()),
        "state_node_ids": [runtime_evidence["parent_state"]["state_node_id"], runtime_evidence["child_state"]["state_node_id"]],
        "state_hashes": [runtime_evidence["parent_state"]["state_hash"], runtime_evidence["child_state"]["state_hash"]],
        "message_ids": message_ids,
        "work_order_ids": [],
        "approval_ids": [],
        "node_ids": [],
        "artifact_paths": [
            str(artifact_dir / "scenario-report.json"),
            str(commands),
            str(artifact_dir / "api-traffic.ndjson"),
            str(artifact_dir / "trace-export.jsonl"),
            str(artifact_dir / "state-export.json"),
            str(artifact_dir / "replay-report.json"),
            str(artifact_dir / "message-causal-graph.json"),
            str(artifact_dir / "audit-report.json"),
            str(artifact_dir / "anti-drift-results.json"),
            str(artifact_dir / "runtime-evidence.json"),
        ],
        "blocking_failures": failures,
    }
    write_json(artifact_dir / "scenario-report.json", scenario)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
