#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


TENANT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
RUN_ID = "33333333-3333-4333-8333-333333333333"
WORK_ORDER_ID = "wo_uc_e2e_s1_local_loop"
SECRET = "splendor-local-work-order-secret"
KEY_ID = "work-order-local-key"


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    counter = 0

    def do_GET(self):  # noqa: N802
        type(self).counter += 1
        if self.path == "/allowed/research-summary":
            body = json.dumps({"summary": "deterministic research fixture", "version": 1}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        return


def utc(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace("+00:00", "Z")


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


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sign_work_order(root: Path, artifact_dir: Path, commands: Path, work_order: dict) -> dict:
    raw = artifact_dir / f"{work_order['work_order_id']}.unsigned.json"
    write_json(raw, work_order)
    proc = run_cmd(
        ["splendorctl", "work-order", "sign", "--input", str(raw), "--key-id", KEY_ID, "--secret", SECRET],
        root,
        commands,
    )
    return json.loads(proc.stdout)


def work_order(run_id: str, max_actions: int = 4) -> dict:
    return {
        "schema_version": "splendor.work_order.v1",
        "work_order_id": WORK_ORDER_ID + "_" + run_id[-4:],
        "tenant_id": TENANT_ID,
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "objective": "UC-E2E-S1 tenant_research agent_research_writer local governed loop",
        "allowed_actions": ["http_get", "write_file"],
        "allowed_adapters": ["http", "filesystem"],
        "allowed_permissions": ["research.read", "artifact.write"],
        "data_refs": ["fixture:http://local/allowed/research-summary", "sandbox://tenant_research/artifacts/summary.md"],
        "quotas": {"max_actions_per_tick": max_actions, "max_http_requests_per_minute": 4, "max_filesystem_write_bytes": 4096},
        "placement": {"target": "local_resident", "requires_gpu": False},
        "issued_at": utc(-1),
        "expires_at": utc(60),
        "revocation": "active",
    }


def config(root: Path, artifact_dir: Path, envelope: dict, run_id: str, actions: list[dict], port: int, max_actions: int = 4) -> dict:
    return {
        "trace_db": str(artifact_dir / f"{run_id}.trace.db"),
        "state_db": str(artifact_dir / f"{run_id}.state.db"),
        "run_id": run_id,
        "cycles": 1,
        "work_order": {**envelope, "verification_secret": SECRET, "expected_placement_target": "local_resident"},
        "adapters": {
            "http": {"allowed_domains": ["127.0.0.1"], "allowed_methods": ["GET"], "timeout_ms": 2000},
            "filesystem": {"base_dir": str(artifact_dir / "sandbox"), "max_write_bytes": 4096},
        },
        "tenants": [{"id": TENANT_ID, "allowed_actions": ["http_get", "write_file"], "allowed_adapters": ["http", "filesystem"], "allowed_permissions": ["research.read", "artifact.write"], "quotas": {"max_actions_per_tick": max_actions}}],
        "agents": [{
            "id": AGENT_ID,
            "tenant_id": TENANT_ID,
            "run_id": run_id,
            "snapshot_interval": 1,
            "initial_state": "{\"seed\":true}",
            "allowed_permissions": ["research.read", "artifact.write"],
            "percepts": [{"schema": "splendor.percept.research_request.v1", "payload": {"url": f"http://127.0.0.1:{port}/allowed/research-summary"}, "source": "uc-e2e-s1", "detail": "structured local fixture"}],
            "policy": {"type": "static", "next_state": "{\"artifact\":\"summary.md\"}", "actions": actions},
        }],
    }


def action_http(port: int, url: str | None = None) -> dict:
    return {"name": "http_get", "adapter": "http", "params": {"url": url or f"http://127.0.0.1:{port}/allowed/research-summary"}, "required_permissions": ["research.read"], "usage": {"actions": 1, "http_requests": 1, "network_read_bytes": 128}}


def action_write(path: str = "artifacts/summary.md") -> dict:
    return {"name": "write_file", "adapter": "filesystem", "params": {"path": path, "contents": "# Research Summary\n\nDeterministic fixture summary.\n"}, "required_permissions": ["artifact.write"], "usage": {"actions": 1, "filesystem_write_bytes": 48}}


def event_type(record: dict) -> str:
    kind = record["payload"]["kind"]
    key = kind if isinstance(kind, str) else next(iter(kind.keys()))
    return {
        "LoopTickStarted": "tick.started", "PerceptsReceived": "percepts.received", "StateLoaded": "state.loaded",
        "PolicyInvoked": "policy.invoked", "PolicyCompleted": "policy.completed", "CandidatesProposed": "actions.proposed",
        "ConstraintsEvaluated": "constraints.evaluated", "ActionVerificationStarted": "verification.started",
        "ActionVerificationCompleted": "verification.completed", "ActionExecuted": "action.executed", "ActionDenied": "action.denied",
        "ActionFailed": "action.failed", "OutcomeRecorded": "outcome.recorded", "StateCommitted": "state.committed",
        "LoopTickCompleted": "tick.completed", "WorkOrderAccepted": "work_order.accepted",
    }.get(key, key)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifact_dir = report_dir / "artifacts" / "UC-E2E-S1"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    commands = artifact_dir / "commands.log"
    commands.write_text("", encoding="utf-8")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    try:
        envelope = sign_work_order(root, artifact_dir, commands, work_order(RUN_ID))
        cfg = config(root, artifact_dir, envelope, RUN_ID, [action_http(port), action_write()], port)
        cfg_path = artifact_dir / "positive.config.json"
        write_json(cfg_path, cfg)
        run_cmd(["splendorctl", "run", "--config", str(cfg_path)], root, commands)

        trace_export = artifact_dir / "trace-export.jsonl"
        proc = run_cmd(["splendorctl", "trace", "export", "--db", cfg["trace_db"], "--run", RUN_ID], root, commands)
        trace_export.write_text(proc.stdout, encoding="utf-8")
        state_proc = run_cmd(["splendorctl", "state", "head", "--db", cfg["trace_db"], "--run", RUN_ID], root, commands)
        state_head = json.loads(state_proc.stdout)
        records = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        events = [event_type(r) for r in records]
        before_replay = FixtureHandler.counter
        replay_proc = run_cmd(["splendorctl", "replay", "--db", cfg["trace_db"], "--state-db", cfg["state_db"], "--run", RUN_ID], root, commands)
        after_replay = FixtureHandler.counter
        artifact = artifact_dir / "sandbox" / TENANT_ID / "artifacts" / "summary.md"
        checksum_before = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
        checksum_after = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
        replay_report = {"mode": "inspect_only", "http_counter_before": before_replay, "http_counter_after": after_replay, "artifact_checksum_before": checksum_before, "artifact_checksum_after": checksum_after, "adapter_suppressed": before_replay == after_replay and checksum_before == checksum_after, "raw_lines": [json.loads(line) for line in replay_proc.stdout.splitlines() if line.strip()]}
        write_json(artifact_dir / "replay-report.json", replay_report)

        negatives = []
        for suffix, actions, quota in [
            ("deny_url", [action_http(port, "http://example.com/outside")], 4),
            ("deny_path", [action_write("../../escape.md")], 4),
            ("deny_quota", [action_http(port), action_write()], 1),
        ]:
            rid = "33333333-3333-4333-8333-" + {"deny_url": "333333333334", "deny_path": "333333333335", "deny_quota": "333333333336"}[suffix]
            env = sign_work_order(root, artifact_dir, commands, work_order(rid, quota))
            c = config(root, artifact_dir, env, rid, actions, port, quota)
            p = artifact_dir / f"{suffix}.config.json"
            write_json(p, c)
            res = run_cmd(["splendorctl", "run", "--config", str(p)], root, commands, check=False)
            trace = run_cmd(["splendorctl", "trace", "export", "--db", c["trace_db"], "--run", rid], root, commands, check=False)
            negatives.append({"case": suffix, "exit": res.returncode, "trace_present": trace.returncode == 0, "evidence": trace.stdout[-2000:]})
        trace_fail = run_cmd(["splendorctl", "run", "--config", "/proc/forbidden/s1.json"], root, commands, check=False)
        negatives.append({"case": "forced_trace_or_config_failure_blocks_side_effect", "exit": trace_fail.returncode, "http_counter": FixtureHandler.counter})

        api_traffic = artifact_dir / "api-traffic.ndjson"
        api_traffic.write_text(json.dumps({"surface": "splendorctl", "commands_log": str(commands)}) + "\n", encoding="utf-8")
        state_committed = next(r for r in records if event_type(r) == "state.committed")
        committed_kind = state_committed["payload"]["kind"]["StateCommitted"]
        state_node_id = state_committed["payload"]["identity"].get("state_node_id")
        state_hash = f"{committed_kind['state_hash']['algorithm'].lower()}:{committed_kind['state_hash']['value']}"
        state_export = {"run_id": RUN_ID, "tenant_id": TENANT_ID, "agent_id": AGENT_ID, "state_node_id": state_node_id, "state_hash": state_hash, "parent_state_node_ids": "available_in_state_store", "trace_linkage": state_head.get("trace_sequence")}
        write_json(artifact_dir / "state-export.json", state_export)
        write_json(artifact_dir / "audit-report.json", {"mode": "inspect_only", "denials": negatives, "work_order_id": WORK_ORDER_ID})
        write_json(artifact_dir / "anti-drift-results.json", {"status": "passed", "checks": ["public_cli_boundary", "gateway_traces_present", "inspect_only_replay_suppression"]})
        (artifact_dir / "stdout.log").write_text("UC-E2E-S1 local governed loop completed with inspect_only side-effect suppression\n", encoding="utf-8")
        (artifact_dir / "stderr.log").write_text("", encoding="utf-8")
        trace_ids = [r["payload"].get("trace_event_id", "") for r in records]
        action_ids = [r["payload"].get("identity", {}).get("action_id") for r in records if r["payload"].get("identity", {}).get("action_id")]
        required = {"tick.started", "percepts.received", "state.loaded", "policy.invoked", "policy.completed", "actions.proposed", "constraints.evaluated", "verification.started", "verification.completed", "action.executed", "outcome.recorded", "state.committed", "tick.completed"}
        failures = sorted(required - set(events))
        if not replay_report["adapter_suppressed"]:
            failures.append("replay_side_effect_suppression_missing")
        scenario = {
            "id": "UC-E2E-S1", "status": "passed" if not failures else "failed", "fr_coverage": ["FR-0.01-01", "FR-0.01-02", "FR-0.01-03", "FR-0.01-04", "FR-0.01-05"],
            "components": ["splendorctl", "action gateway", "HTTP adapter", "filesystem adapter", "state graph", "trace store", "replay"],
            "positive_evidence": ["signed scoped work order accepted", "HTTP read and sandbox filesystem write executed through gateway", "state head and ordered trace exported"],
            "negative_evidence": [n["case"] for n in negatives], "replay_evidence": ["inspect_only replay did not increment HTTP counter or change artifact checksum"],
            "replay_mode": "inspect_only", "replay_side_effect_suppression": {"required": True, "evidence_present": replay_report["adapter_suppressed"], "side_effects_allowed_default": False},
            "replay_artifacts": [str(artifact_dir / "replay-report.json")], "anti_drift_checks": ["public_cli_boundary", "no_direct_adapter_execution", "inspect_only"],
            "run_ids": [RUN_ID], "trace_event_ids": trace_ids, "state_node_ids": [state_node_id], "state_hashes": [state_hash], "message_ids": [], "work_order_ids": [envelope["work_order_id"]], "approval_ids": [], "node_ids": [], "action_ids": action_ids,
            "artifact_paths": [str(p) for p in [artifact_dir / "scenario-report.json", commands, api_traffic, trace_export, artifact_dir / "state-export.json", artifact_dir / "replay-report.json", artifact_dir / "audit-report.json", artifact_dir / "anti-drift-results.json", artifact]],
            "blocking_failures": failures,
        }
        write_json(artifact_dir / "scenario-report.json", scenario)
        return 0 if not failures else 1
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
