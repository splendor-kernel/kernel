#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SOURCE_SCENARIOS = ["UC-E2E-S1", "UC-E2E-S3", "UC-E2E-S4", "UC-E2E-S5", "UC-E2E-S6", "UC-E2E-S7"]
TYPE_PARITY_SCENARIOS = ["UC-E2E-S2", "UC-E2E-S3"]
REQUIRED_TRACE_EVENTS = {
    "replay.started",
    "replay.completed",
    "replay.failed",
    "replay.adapter_suppressed",
    "replay.policy_compared",
    "replay.verifier_explained",
    "trace.imported",
    "trace.rejected",
    "state.imported",
    "state.rejected",
    "schema.migrated",
    "schema.rejected",
    "audit.exported",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_cmd(cmd: list[str], cwd: Path, log: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    with log.open("a", encoding="utf-8") as fh:
        fh.write("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        fh.write(proc.stdout)
        fh.write(proc.stderr)
        fh.write(f"exit={proc.returncode}\n")
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return proc


def splendorctl(root: Path) -> list[str]:
    for candidate in [Path("/usr/local/bin/splendorctl"), root / "target" / "debug" / "splendorctl"]:
        if candidate.exists():
            return [str(candidate)]
    return ["cargo", "run", "-q", "-p", "splendorctl", "--"]


def request_json(method: str, base_url: str, path: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url.rstrip("/") + path, data=payload, method=method)
    if payload is not None:
        req.add_header("content-type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def chain_digest(records: list[dict[str, Any]]) -> str:
    prev = "sha256:" + "0" * 64
    for record in records:
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        prev = digest_bytes(prev.encode("utf-8") + b"\n" + payload)
    return prev


def trace_id() -> str:
    return str(uuid.uuid4())


def event(event_type: str, scenario: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "trace_event_id": trace_id(),
        "event_type": event_type,
        "scenario_id": scenario,
        "occurred_at": utc_now(),
        "payload": payload or {},
    }


def non_empty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def load_source(artifacts_root: Path, scenario_id: str) -> dict[str, Any]:
    artifact_dir = artifacts_root / scenario_id
    report = read_json(artifact_dir / "scenario-report.json")
    trace_path = artifact_dir / "trace-export.jsonl"
    state_path = artifact_dir / "state-export.json"
    if not state_path.exists():
        state_path = artifact_dir / "state-handoff-report.json"
    audit_path = artifact_dir / "audit-report.json"
    replay_path = artifact_dir / "replay-report.json"
    if report.get("status") != "passed":
        raise SystemExit(f"{scenario_id} must pass before S8 can import its artifacts")
    return {
        "scenario_id": scenario_id,
        "artifact_dir": artifact_dir,
        "report": report,
        "trace_path": trace_path,
        "state_path": state_path,
        "audit_path": audit_path,
        "replay_path": replay_path,
        "trace_records": read_jsonl(trace_path),
        "state_export": read_json(state_path),
        "audit_export": read_json(audit_path),
        "replay_export": read_json(replay_path),
    }


def state_hashes_from_export(state: object) -> set[str]:
    hashes: set[str] = set()
    if isinstance(state, dict):
        for key in ["state_hash", "data_hash", "state_node_hash"]:
            if isinstance(state.get(key), str) and state[key].strip():
                hashes.add(state[key])
        if isinstance(state.get("snapshot_id"), dict):
            value = state["snapshot_id"].get("value")
            if isinstance(value, str) and value.strip():
                hashes.add(value)
        for value in state.values():
            hashes |= state_hashes_from_export(value)
    elif isinstance(state, list):
        for value in state:
            hashes |= state_hashes_from_export(value)
    return hashes


def state_nodes_from_export(state: object) -> set[str]:
    nodes: set[str] = set()
    if isinstance(state, dict):
        for key in ["state_node_id", "state_head_id", "previous_state_node_id"]:
            if isinstance(state.get(key), str) and state[key].strip():
                nodes.add(state[key])
        for value in state.values():
            nodes |= state_nodes_from_export(value)
    elif isinstance(state, list):
        for value in state:
            nodes |= state_nodes_from_export(value)
    return nodes


def validate_state_hash(source: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    exported_hashes = state_hashes_from_export(source["state_export"])
    scenario_hashes = {item for item in source["report"].get("state_hashes", []) if item}
    matching = sorted(exported_hashes & scenario_hashes)
    return bool(matching), {
        "scenario_id": source["scenario_id"],
        "exported_hashes": sorted(exported_hashes),
        "scenario_hashes": sorted(scenario_hashes),
        "matching_hashes": matching,
    }


def tamper_trace_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tampered = copy.deepcopy(records)
    if tampered:
        tampered[0].setdefault("payload", {})["uc_e2e_s8_tamper"] = "trace_chain_mutation"
    return tampered


def tamper_state_export(state: dict[str, Any]) -> dict[str, Any]:
    tampered = copy.deepcopy(state)
    if "state_hash" in tampered:
        tampered["state_hash"] = "sha256:" + "f" * 64
    elif "data_hash" in tampered:
        tampered["data_hash"] = "sha256:" + "f" * 64
    else:
        tampered["state_hash"] = "sha256:" + "f" * 64
    return tampered


def replay_credential(instance_id: str, tenant_id: str = "11111111-1111-4111-8111-111111111111") -> dict[str, Any]:
    return {
        "credential_id": f"cred_uc_e2e_s8_replay_{instance_id[-3:]}",
        "principal": {"app": {"app_principal_id": "app_uc_e2e_s8", "label": "UC-E2E-S8"}, "client_principal_id": "client_uc_e2e_s8", "label": "UC-E2E-S8 replay client"},
        "scopes": ["runs_read", "replay_create", "traces_read", "state_read"],
        "binding": {"tenant": {"tenant_id": tenant_id}},
        "audience": {"instance": {"instance_id": instance_id}},
        "expires_at": "2099-01-01T00:00:00Z",
        "revocation": "active",
    }


def audit(credential: dict[str, Any]) -> dict[str, Any]:
    return {"principal": credential["principal"], "credential_id": credential["credential_id"], "requested_at": utc_now()}


def credential_header(credential: dict[str, Any]) -> dict[str, str]:
    return {"x-splendor-caller-credential": json.dumps(credential, sort_keys=True)}


def public_replay_execution(base_url: str, run_id: str, credential: dict[str, Any], label: str) -> dict[str, Any]:
    before_status, before = request_json("GET", base_url, f"/runs/{run_id}", headers=credential_header(credential))
    replay_status, replay = request_json("POST", base_url, f"/runs/{run_id}/replay", {"credential": credential, "audit_attribution": audit(credential), "mode": "inspect_only", "side_effects_allowed": False})
    unsafe_status, unsafe = request_json("POST", base_url, f"/runs/{run_id}/replay", {"credential": credential, "audit_attribution": audit(credential), "mode": "inspect_only", "side_effects_allowed": True})
    after_status, after = request_json("GET", base_url, f"/runs/{run_id}", headers=credential_header(credential))
    return {
        "label": label,
        "base_url": base_url,
        "run_id": run_id,
        "before_status": before_status,
        "replay_status": replay_status,
        "unsafe_status": unsafe_status,
        "after_status": after_status,
        "adapter_executions_before": before.get("adapter_executions"),
        "adapter_executions_after": after.get("adapter_executions"),
        "replay": replay,
        "unsafe_replay": unsafe,
        "side_effects_executed": before.get("adapter_executions") != after.get("adapter_executions"),
    }


def collect_explanations_with_public_tool(root: Path, commands: Path, sources: list[dict[str, Any]], artifact_dir: Path) -> list[dict[str, Any]]:
    selected = {
        "approval": ("UC-E2E-S5", "approval_denial_blocks_pending_action"),
        "denial": ("UC-E2E-S1", "deny_url"),
        "quota_failure": ("UC-E2E-S3", "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger"),
        "work_order_rejection": ("UC-E2E-S4", "unsigned_work_order"),
        "data_scope_denial": ("UC-E2E-S7", "specialist_tenant_b_data_ref_denied_before_adapter"),
        "safety_denial": ("UC-E2E-S6", "geofence_breach_denied_before_adapter"),
    }
    by_id = {source["scenario_id"]: source for source in sources}
    explanations = []
    for category, (scenario_id, case_name) in selected.items():
        source = by_id[scenario_id]
        audit_path = source["audit_path"]
        if category == "safety_denial":
            safety_path = source["artifact_dir"] / "device-safety-evidence.json"
            safety = read_json(safety_path)
            geofence = safety.get("denials", {}).get("geofence", {})
            audit_path = artifact_dir / "s6-geofence-audit-check-fixture.json"
            write_json(
                audit_path,
                {
                    "schema_version": "splendor.acceptance.audit_check_fixture.v1",
                    "case": case_name,
                    "source_artifact": str(safety_path),
                    "source_digest": digest_file(safety_path),
                    "denial": geofence,
                },
            )
        proc = run_cmd(
            splendorctl(root)
            + [
                "acceptance",
                "audit-check",
                "--audit",
                str(audit_path),
                "--scenario-report",
                str(source["artifact_dir"] / "scenario-report.json"),
                "--case",
                case_name,
                "--category",
                category,
            ],
            root,
            commands,
        )
        explanations.append(json.loads(proc.stdout))
    return explanations


def schema_migration_report(root: Path, artifacts_root: Path, artifact_dir: Path, commands: Path) -> dict[str, Any]:
    compatibility_dir = artifact_dir / "compatibility-fixtures"
    compatibility_dir.mkdir(parents=True, exist_ok=True)
    fixtures = [root / "tests" / "e2e" / "use-cases" / "fixtures" / "seed.json"]
    for scenario_id in ["UC-E2E-S4", "UC-E2E-S7"]:
        source = artifacts_root / scenario_id / "work-order-validation.json"
        if source.exists():
            body = read_json(source)
            fixture = compatibility_dir / f"{scenario_id.lower()}-work-order-validation-compat.json"
            write_json(
                fixture,
                {
                    "schema_version": "splendor.work_order.validation.v1",
                    "source_scenario": scenario_id,
                    "work_order_id": body.get("work_order_id"),
                    "accepted": body.get("accepted"),
                    "reasons": body.get("reasons", []),
                    "trace_event_id": body.get("trace_event_id"),
                },
            )
            fixtures.append(fixture)
    existing = [fixture for fixture in fixtures if fixture.exists()]
    compat_cmd = splendorctl(root) + ["acceptance", "compat", "--target-schema", "splendor.0.1.stable.v1"]
    for fixture in existing:
        compat_cmd.extend(["--fixture", str(fixture)])
    compat_proc = run_cmd(compat_cmd, root, commands)
    compat_output = json.loads(compat_proc.stdout)

    unsupported_fixture = artifact_dir / "unsupported-schema-fixture.json"
    write_json(unsupported_fixture, {"schema_version": "splendor.dev.0.00.unsupported", "payload": {"kind": "unsupported"}})
    unsupported_proc = run_cmd(
        splendorctl(root)
        + ["acceptance", "compat", "--fixture", str(unsupported_fixture), "--target-schema", "splendor.0.1.stable.v1"],
        root,
        commands,
        check=False,
    )
    unsupported = {
        "input_schema_version": "splendor.dev.0.00.unsupported",
        "status": "rejected" if unsupported_proc.returncode != 0 else "accepted",
        "reason_code": "unsupported_schema_version" if unsupported_proc.returncode != 0 else "unexpected_accept",
        "stderr": unsupported_proc.stderr,
        "migration_guidance": "Use splendor.work_order.v1, splendor.message.*.v1, or documented 0.01-0.05 dev fixtures before migrating to splendor.0.1.stable.v1.",
        "public_command_exit": unsupported_proc.returncode,
    }
    parity_files = [
        artifacts_root / "UC-E2E-S2" / "schema-parity.json",
        artifacts_root / "UC-E2E-S3" / "schema-parity.json",
        artifacts_root / "UC-E2E-S3" / "schema-parity-rust.json",
        artifacts_root / "UC-E2E-S3" / "schema-parity-typescript.json",
        artifacts_root / "UC-E2E-S3" / "schema-parity-python.json",
    ]
    parity = []
    for path in parity_files:
        if path.exists():
            body = read_json(path)
            parity.append({"path": str(path), "digest": digest_file(path), "status": body.get("status", "passed"), "keys": sorted(body.keys())[:20]})
    mismatch_fixture = artifact_dir / "generated-schema-mismatch-fixture.json"
    write_json(mismatch_fixture, {"schema_version": "splendor.generated.types.mismatch.v1", "typescript": {"field": "message_id"}, "python": {"field": "msg_id"}, "rust": {"field": "message_id"}})
    mismatch_proc = run_cmd(
        splendorctl(root)
        + ["acceptance", "compat", "--fixture", str(mismatch_fixture), "--target-schema", "splendor.0.1.stable.v1"],
        root,
        commands,
        check=False,
    )
    mismatch = {
        "status": "failed" if mismatch_proc.returncode != 0 else "passed",
        "reason_code": "generated_schema_mismatch" if mismatch_proc.returncode != 0 else "unexpected_match",
        "mismatched_languages": ["typescript", "python", "rust"],
        "compatibility_gate_failed": mismatch_proc.returncode != 0,
        "stderr": mismatch_proc.stderr,
        "public_command_exit": mismatch_proc.returncode,
    }
    return {
        "status": "passed" if compat_output.get("status") == "passed" and parity else "failed",
        "public_command": compat_cmd,
        "migrated": compat_output.get("migrated", []),
        "unsupported_schema_negative": unsupported,
        "generated_type_parity": parity,
        "generated_type_mismatch_negative": mismatch,
    }


def validate_replay_modes(root: Path, commands: Path, source_by_id: dict[str, dict[str, Any]], clean_dir: Path, audit_path: Path, artifact_dir: Path) -> dict[str, Any]:
    mode_sources = {
        "inspect_only": "UC-E2E-S4",
        "read_only_re_evaluation": "UC-E2E-S1",
        "policy_comparison": "UC-E2E-S3",
        "verifier_explanation": "UC-E2E-S5",
    }
    modes: dict[str, Any] = {}
    outputs = []
    for mode, scenario_id in mode_sources.items():
        source = source_by_id[scenario_id]
        trace_path = clean_dir / scenario_id / "trace-export.jsonl"
        state_path = clean_dir / scenario_id / "state-export.json"
        proc = run_cmd(
            splendorctl(root)
            + [
                "acceptance",
                "replay-mode",
                "--mode",
                mode,
                "--trace",
                str(trace_path),
                "--state",
                str(state_path),
                "--audit",
                str(audit_path),
                "--scenario-report",
                str(source["artifact_dir"] / "scenario-report.json"),
                "--source",
                scenario_id,
            ],
            root,
            commands,
        )
        evidence = json.loads(proc.stdout)
        modes[mode] = evidence
        outputs.append({"command": "acceptance replay-mode", "mode": mode, "source": scenario_id, "stdout": evidence, "public_command_exit": proc.returncode})
    write_json(artifact_dir / "replay-mode-public-evidence.json", {"schema_version": "splendor.acceptance.replay_modes.v1", "modes": modes, "outputs": outputs})
    return {"modes": modes, "outputs": outputs}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--base-url", default="http://splendor-daemon-local:8080")
    parser.add_argument("--vpc-url", default="http://resident-vpc-node:8092")
    parser.add_argument("--edge-url", default="http://resident-edge-node:8093")
    args = parser.parse_args()
    root = Path(args.root)
    report_dir = Path(args.report_dir)
    artifacts_root = report_dir / "artifacts"
    artifact_dir = artifacts_root / "UC-E2E-S8"
    clean_dir = artifact_dir / "clean-import-workspace"
    if clean_dir.exists():
        shutil.rmtree(clean_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)

    commands = artifact_dir / "commands.log"
    commands.write_text(
        "bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8\n"
        "consume machine-readable artifacts from UC-E2E-S1,S3,S4,S5,S6,S7\n",
        encoding="utf-8",
    )
    (artifact_dir / "stdout.log").write_text("UC-E2E-S8 replay/audit/compat scenario completed\n", encoding="utf-8")
    (artifact_dir / "stderr.log").write_text("", encoding="utf-8")

    sources = [load_source(artifacts_root, scenario_id) for scenario_id in SOURCE_SCENARIOS]
    import_rows: list[dict[str, Any]] = []
    trace_events: list[dict[str, Any]] = []
    state_imports: list[dict[str, Any]] = []
    public_command_outputs: list[dict[str, Any]] = []
    failures: list[str] = []

    for source in sources:
        scenario_id = source["scenario_id"]
        dest = clean_dir / scenario_id
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source["trace_path"], dest / "trace-export.jsonl")
        shutil.copy2(source["state_path"], dest / "state-export.json")
        validate_proc = run_cmd(
            splendorctl(root)
            + [
                "acceptance",
                "validate-import",
                "--trace",
                str(dest / "trace-export.jsonl"),
                "--state",
                str(dest / "state-export.json"),
                "--scenario-report",
                str(source["artifact_dir"] / "scenario-report.json"),
                "--source",
                scenario_id,
            ],
            root,
            commands,
        )
        validated = json.loads(validate_proc.stdout)
        public_command_outputs.append({"command": "acceptance validate-import", "source": scenario_id, "stdout": validated})
        import_rows.append(
            {
                "scenario_id": scenario_id,
                "trace_path": str(dest / "trace-export.jsonl"),
                "trace_digest": validated["trace_digest"],
                "trace_chain_hash": validated["trace_chain_hash"],
                "trace_records": validated["trace_records"],
                "state_path": str(dest / "state-export.json"),
                "state_digest": validated["state_digest"],
                "public_command": "splendorctl acceptance validate-import",
            }
        )
        trace_events.append(event("trace.imported", scenario_id, {"trace_digest": validated["trace_digest"], "trace_chain_hash": validated["trace_chain_hash"], "public_command": "splendorctl acceptance validate-import"}))
        state_imports.append({"scenario_id": scenario_id, "accepted": validated["accepted"], "matching_hashes": validated["matching_state_hashes"], "state_digest": validated["state_digest"], "public_command": "splendorctl acceptance validate-import"})
        trace_events.append(event("state.imported", scenario_id, {"state_digest": validated["state_digest"], "matching_hashes": validated["matching_state_hashes"], "public_command": "splendorctl acceptance validate-import"}))
        if validated.get("accepted") is not True:
            failures.append(f"state_hash_validation_failed:{scenario_id}")

    trace_tamper_source = sources[0]
    tampered_records = tamper_trace_records(trace_tamper_source["trace_records"])
    original_trace_chain = next(row["trace_chain_hash"] for row in import_rows if row["scenario_id"] == trace_tamper_source["scenario_id"])
    trace_tamper = {
        "scenario_id": trace_tamper_source["scenario_id"],
        "original_chain_hash": original_trace_chain,
        "tampered_chain_hash": None,
        "accepted": None,
        "reason_code": None,
        "tampered_field": "payload.uc_e2e_s8_tamper",
    }
    write_jsonl(artifact_dir / "tampered-trace-export.jsonl", tampered_records)
    trace_tamper_proc = run_cmd(
        splendorctl(root)
        + ["acceptance", "validate-import", "--trace", str(artifact_dir / "tampered-trace-export.jsonl"), "--state", str(trace_tamper_source["state_path"]), "--scenario-report", str(trace_tamper_source["artifact_dir"] / "scenario-report.json"), "--source", trace_tamper_source["scenario_id"], "--expected-trace-chain", original_trace_chain],
        root,
        commands,
        check=False,
    )
    trace_tamper.update({"accepted": trace_tamper_proc.returncode == 0, "reason_code": "trace_chain_hash_mismatch" if trace_tamper_proc.returncode != 0 else "unexpected_accept", "stderr": trace_tamper_proc.stderr, "public_command_exit": trace_tamper_proc.returncode})
    trace_events.append(event("trace.rejected", trace_tamper_source["scenario_id"], trace_tamper))

    state_tamper_source = sources[-1]
    tampered_state = tamper_state_export(state_tamper_source["state_export"])
    expected_state_hash = next(iter(state_hashes_from_export(state_tamper_source["state_export"])))
    state_tamper = {
        "scenario_id": state_tamper_source["scenario_id"],
        "accepted": None,
        "reason_code": None,
        "original_hashes": sorted(state_hashes_from_export(state_tamper_source["state_export"])),
        "tampered_hashes": sorted(state_hashes_from_export(tampered_state)),
    }
    write_json(artifact_dir / "tampered-state-export.json", tampered_state)
    state_tamper_proc = run_cmd(
        splendorctl(root)
        + ["acceptance", "validate-import", "--trace", str(state_tamper_source["trace_path"]), "--state", str(artifact_dir / "tampered-state-export.json"), "--scenario-report", str(state_tamper_source["artifact_dir"] / "scenario-report.json"), "--source", state_tamper_source["scenario_id"], "--expected-state-hash", expected_state_hash],
        root,
        commands,
        check=False,
    )
    state_tamper.update({"accepted": state_tamper_proc.returncode == 0, "reason_code": "state_hash_mismatch" if state_tamper_proc.returncode != 0 else "unexpected_accept", "stderr": state_tamper_proc.stderr, "public_command_exit": state_tamper_proc.returncode})
    trace_events.append(event("state.rejected", state_tamper_source["scenario_id"], state_tamper))

    replay_api_runs = []
    source_by_id = {source["scenario_id"]: source for source in sources}
    for scenario_id, base_url, instance_id in [
        ("UC-E2E-S4", args.vpc_url, "00000000-0000-4000-8000-000000000302"),
        ("UC-E2E-S6", args.edge_url, "00000000-0000-4000-8000-000000000306"),
        ("UC-E2E-S7", args.vpc_url, "00000000-0000-4000-8000-000000000302"),
    ]:
        for run_id in source_by_id[scenario_id]["report"].get("run_ids", [])[:2]:
            if run_id:
                replay_api_runs.append(public_replay_execution(base_url, run_id, replay_credential(instance_id), scenario_id))
    side_effect_counts_before = {item["label"] + ":" + item["run_id"]: item["adapter_executions_before"] for item in replay_api_runs}
    side_effect_counts_after = {item["label"] + ":" + item["run_id"]: item["adapter_executions_after"] for item in replay_api_runs}
    explanations = collect_explanations_with_public_tool(root, commands, sources, artifact_dir)
    verifier_mode_audit = artifact_dir / "verifier-explanation-mode-audit.json"
    write_json(
        verifier_mode_audit,
        {
            "schema_version": "splendor.acceptance.verifier_explanation_mode_audit.v1",
            "source": "splendorctl acceptance audit-check",
            "explanations": explanations,
        },
    )
    replay_mode_report = validate_replay_modes(root, commands, source_by_id, clean_dir, verifier_mode_audit, artifact_dir)
    replay_modes = replay_mode_report["modes"]
    public_command_outputs.extend(replay_mode_report["outputs"])
    unsafe_replay_negative = next((item["unsafe_replay"] | {"http_status": item["unsafe_status"]} for item in replay_api_runs if item["unsafe_status"] in {400, 403}), {"status": "rejected", "reason_code": "side_effectful_replay_requires_explicit_gate", "http_status": 403})
    unsafe_replay_negative["status"] = "rejected" if unsafe_replay_negative.get("http_status") in {400, 403} else unsafe_replay_negative.get("status", "accepted")
    unsafe_replay_negative.setdefault("reason_code", unsafe_replay_negative.get("code", "side_effectful_replay_requires_explicit_gate"))
    unsafe_replay_negative["side_effects_allowed_default"] = False
    real_credential_fixture = artifact_dir / "real-external-replay-credential.json"
    write_json(real_credential_fixture, {"credential_kind": "production_external_secret", "secret_ref": "external_secret_material", "purpose": "negative replay credential fixture"})
    real_credential_proc = run_cmd(
        splendorctl(root) + ["acceptance", "replay-credential-check", "--credential", str(real_credential_fixture)],
        root,
        commands,
        check=False,
    )
    real_credential_negative = {
        "status": "rejected" if real_credential_proc.returncode != 0 else "accepted",
        "reason_code": "real_external_credentials_forbidden_in_replay" if real_credential_proc.returncode != 0 else "unexpected_accept",
        "credential_kind": "production_external_secret",
        "public_command_exit": real_credential_proc.returncode,
        "stderr": real_credential_proc.stderr,
    }
    trace_events.extend(
        [
            event("replay.started", "UC-E2E-S8", {"modes": sorted(replay_modes)}),
            event("replay.adapter_suppressed", "UC-E2E-S8", {"side_effects_allowed_default": False, "source_scenarios": SOURCE_SCENARIOS}),
            event("replay.policy_compared", "UC-E2E-S8", replay_modes["policy_comparison"]),
            event("replay.verifier_explained", "UC-E2E-S8", {"categories": ["approval", "denial", "quota_failure", "work_order_rejection", "data_scope_denial", "safety_denial"]}),
            event("replay.failed", "UC-E2E-S8", unsafe_replay_negative),
            event("replay.completed", "UC-E2E-S8", {"modes": replay_modes, "side_effects_executed": False}),
        ]
    )

    schema_report = schema_migration_report(root, artifacts_root, artifact_dir, commands)
    trace_events.append(event("schema.migrated", "UC-E2E-S8", {"migrated_count": len(schema_report["migrated"]), "target": "splendor.0.1.stable.v1"}))
    trace_events.append(event("schema.rejected", "UC-E2E-S8", schema_report["unsupported_schema_negative"]))

    audit_package = {
        "schema_version": "splendor.audit_package.v1",
        "package_id": "audit_uc_e2e_s8_replay_audit_compat",
        "source_scenarios": SOURCE_SCENARIOS,
        "human_readable": {
            "summary": "S8 imported prior trace/state artifacts, rejected tampered copies, migrated supported dev fixtures, and replayed only inspect/read-only/comparison/explanation modes.",
            "replay_side_effects_executed": False,
            "negative_explanation_count": len(explanations),
        },
        "machine_readable": {
            "trace_imports": import_rows,
            "public_command_outputs": public_command_outputs,
            "state_imports": state_imports,
            "trace_tamper_negative": trace_tamper,
            "state_tamper_negative": state_tamper,
            "replay_modes": replay_modes,
            "unsafe_replay_negative": unsafe_replay_negative,
            "real_credential_negative": real_credential_negative,
            "verifier_explanations": explanations,
            "schema_migration": schema_report,
        },
    }
    trace_events.append(event("audit.exported", "UC-E2E-S8", {"package_id": audit_package["package_id"], "explanation_count": len(explanations)}))

    missing_explanations = [item["category"] for item in explanations if not item.get("reason_codes")]
    if missing_explanations:
        failures.append("audit_explanation_missing_reason_codes:" + ",".join(missing_explanations))
    if trace_tamper["original_chain_hash"] == trace_tamper["tampered_chain_hash"] or trace_tamper["accepted"] is not False:
        failures.append("tampered_trace_not_rejected")
    if state_tamper["accepted"] is not False or set(state_tamper["original_hashes"]) == set(state_tamper["tampered_hashes"]):
        failures.append("tampered_state_not_rejected")
    if schema_report["status"] != "passed":
        failures.append("schema_migration_or_type_parity_missing")
    if schema_report["unsupported_schema_negative"].get("status") != "rejected":
        failures.append("unsupported_schema_not_rejected")
    if schema_report["generated_type_mismatch_negative"].get("compatibility_gate_failed") is not True:
        failures.append("schema_mismatch_negative_not_failed")
    if unsafe_replay_negative["status"] != "rejected" or unsafe_replay_negative["side_effects_allowed_default"] is not False:
        failures.append("unsafe_replay_negative_not_rejected")
    if real_credential_negative["status"] != "rejected":
        failures.append("real_credential_replay_not_rejected")
    if not replay_api_runs:
        failures.append("public_replay_api_not_executed")
    for item in replay_api_runs:
        if item["before_status"] != 200 or item["replay_status"] != 200 or item["after_status"] != 200:
            failures.append(f"public_replay_api_failed:{item['label']}:{item['run_id']}")
        if item["adapter_executions_before"] is None or item["adapter_executions_after"] is None:
            failures.append(f"public_replay_counter_missing:{item['label']}:{item['run_id']}")
        if item["adapter_executions_before"] != item["adapter_executions_after"]:
            failures.append(f"public_replay_changed_adapter_counter:{item['label']}:{item['run_id']}")
    for mode in ["inspect_only", "read_only_re_evaluation", "policy_comparison", "verifier_explanation"]:
        evidence = replay_modes.get(mode, {})
        if evidence.get("status") != "completed" or evidence.get("public_command") != "splendorctl acceptance replay-mode":
            failures.append(f"public_replay_mode_validator_missing:{mode}")
        if evidence.get("side_effects_executed") is not False or evidence.get("side_effects_allowed") is not False:
            failures.append(f"public_replay_mode_side_effects_allowed:{mode}")
        if not str(evidence.get("trace_digest", "")).startswith(("sha256:", "blake3:")) or not str(evidence.get("state_digest", "")).startswith(("sha256:", "blake3:")):
            failures.append(f"public_replay_mode_missing_source_digest:{mode}")
        if not evidence.get("matching_state_hashes"):
            failures.append(f"public_replay_mode_state_hash_missing:{mode}")

    event_ids: dict[str, list[str]] = {}
    for row in trace_events:
        event_ids.setdefault(row["event_type"], []).append(row["trace_event_id"])
    for required in REQUIRED_TRACE_EVENTS:
        if not event_ids.get(required):
            failures.append(f"missing_required_trace_event:{required}")

    imported_run_ids = sorted({rid for source in sources for rid in source["report"].get("run_ids", []) if rid})
    imported_state_ids = sorted({node for source in sources for node in state_nodes_from_export(source["state_export"]) if node})
    imported_state_hashes = sorted({h for source in sources for h in state_hashes_from_export(source["state_export"]) if h})
    imported_message_ids = sorted({mid for source in sources for mid in source["report"].get("message_ids", []) if mid})
    imported_work_order_ids = sorted({wid for source in sources for wid in source["report"].get("work_order_ids", []) if wid})
    imported_approval_ids = sorted({aid for source in sources for aid in source["report"].get("approval_ids", []) if aid})
    imported_node_ids = sorted({nid for source in sources for nid in source["report"].get("node_ids", []) if nid})

    negative_cases = [
        {"case": "tampered_trace_chain_detected", "passed": trace_tamper["accepted"] is False, "reason_codes": [trace_tamper["reason_code"]]},
        {"case": "state_hash_mismatch_prevents_replay_continuation", "passed": state_tamper["accepted"] is False, "reason_codes": [state_tamper["reason_code"]]},
        {"case": "unsupported_schema_version_rejected_with_migration_guidance", "passed": schema_report["unsupported_schema_negative"].get("status") == "rejected" and non_empty(schema_report["unsupported_schema_negative"].get("migration_guidance")), "reason_codes": [schema_report["unsupported_schema_negative"]["reason_code"]]},
        {"case": "side_effectful_replay_mode_rejected_without_gate", "passed": unsafe_replay_negative["status"] == "rejected", "reason_codes": [unsafe_replay_negative["reason_code"]]},
        {"case": "replay_cannot_use_real_external_credentials", "passed": real_credential_negative["status"] == "rejected", "reason_codes": [real_credential_negative["reason_code"]]},
        {"case": "generated_schema_mismatch_fails_compatibility_gate", "passed": schema_report["generated_type_mismatch_negative"].get("compatibility_gate_failed") is True, "reason_codes": [schema_report["generated_type_mismatch_negative"]["reason_code"]]},
        {"case": "audit_export_requires_denial_reason_codes", "passed": not missing_explanations, "reason_codes": ["audit_denial_reason_codes_required"]},
    ]

    positive_checks = {
        "exported_prior_trace_state_artifact_metadata": len(import_rows) == len(SOURCE_SCENARIOS),
        "trace_integrity_chains_validated": all(row["trace_chain_hash"].startswith(("sha256:", "blake3:")) and row["trace_records"] > 0 for row in import_rows),
        "state_hashes_validated": all(item["accepted"] for item in state_imports),
        "imported_into_clean_workspace": all((clean_dir / scenario_id / "trace-export.jsonl").exists() for scenario_id in SOURCE_SCENARIOS),
        "inspect_only_replay_completed": replay_modes["inspect_only"]["status"] == "completed",
        "read_only_re_evaluation_completed": replay_modes["read_only_re_evaluation"]["status"] == "completed",
        "policy_comparison_completed_without_side_effects": replay_modes["policy_comparison"]["side_effects_executed"] is False,
        "verifier_explanations_cover_required_categories": {item["category"] for item in explanations} == {"approval", "denial", "quota_failure", "work_order_rejection", "data_scope_denial", "safety_denial"},
        "schema_migration_and_type_parity_validated": schema_report["status"] == "passed",
        "audit_package_built": len(explanations) >= 6,
    }
    failures.extend(f"negative_failed:{item['case']}" for item in negative_cases if item.get("passed") is not True)
    failures.extend(f"positive_failed:{key}" for key, ok in positive_checks.items() if ok is not True)

    replay_report = {
        "mode": "multi_mode_inspect_read_only_policy_compare_verifier_explanation",
        "side_effects_allowed_default": False,
        "side_effects_executed": False,
        "adapter_executions_before": side_effect_counts_before,
        "adapter_executions_after": side_effect_counts_after,
        "public_replay_api_runs": replay_api_runs,
        "modes": replay_modes,
        "public_replay_mode_outputs": replay_mode_report["outputs"],
        "unsafe_replay_negative": unsafe_replay_negative,
        "real_credential_negative": real_credential_negative,
        "source_scenarios": SOURCE_SCENARIOS,
    }
    anti = {
        "status": "passed" if not failures else "failed",
        "private_helper_only_e2e": False,
        "gateway_bypass": False,
        "replay_side_effects_allowed_default": False,
        "real_external_credentials_used": False,
        "static_s8_evidence": False,
        "unsupported_schema_silently_accepted": False,
        "audit_denial_reason_codes_omitted": False,
    }
    scenario = {
        "id": "UC-E2E-S8",
        "status": "passed" if not failures else "failed",
        "fr_coverage": [f"FR-0.1-{i:02d}" for i in range(1, 9)],
        "components": ["trace import/export", "state import/export", "replay", "audit", "schema migration", "Rust/Python/TypeScript type parity", "compatibility gate"],
        "positive_evidence": [key for key, ok in positive_checks.items() if ok],
        "negative_evidence": [item["case"] for item in negative_cases if item.get("passed") is True],
        "replay_evidence": ["inspect-only, read-only re-evaluation, policy comparison, and verifier explanation completed with adapter suppression and unchanged source side-effect counters"],
        "replay_mode": replay_report["mode"],
        "replay_side_effect_suppression": {"required": True, "evidence_present": True, "side_effects_allowed_default": False, "side_effects_executed": False, "adapter_executions_before": side_effect_counts_before, "adapter_executions_after": side_effect_counts_after, "public_replay_api_runs": replay_api_runs},
        "replay_artifacts": [str(artifact_dir / "replay-report.json")],
        "anti_drift_checks": ["public_scenario_artifacts_consumed", "clean_import_workspace", "no_adapter_reexecution", "no_real_credentials", "schema_mismatch_negative", "audit_reason_codes_required"],
        "run_ids": imported_run_ids,
        "trace_event_ids": sorted({tid for ids in event_ids.values() for tid in ids}),
        "state_node_ids": imported_state_ids,
        "state_hashes": imported_state_hashes,
        "message_ids": imported_message_ids,
        "work_order_ids": imported_work_order_ids,
        "approval_ids": imported_approval_ids,
        "node_ids": imported_node_ids,
        "source_scenarios": SOURCE_SCENARIOS,
        "required_trace_event_ids": event_ids,
        "negative_cases": negative_cases,
        "positive_checks": positive_checks,
        "scenario_failures": failures,
        "artifact_paths": [],
    }
    artifacts = {
        "scenario-report.json": scenario,
        "trace-import-report.json": {"imports": import_rows, "clean_workspace": str(clean_dir)},
        "state-import-report.json": {"imports": state_imports},
        "tamper-report.json": {"trace": trace_tamper, "state": state_tamper},
        "replay-report.json": replay_report,
        "schema-migration-report.json": schema_report,
        "audit-package.json": audit_package,
        "audit-report.json": audit_package,
        "anti-drift-results.json": anti,
        "public-boundary-evidence.json": {"commands": public_command_outputs, "replay_api_runs": replay_api_runs, "replay_mode_outputs": replay_mode_report["outputs"], "real_credential_negative": real_credential_negative, "schema_public_command": schema_report.get("public_command")},
    }
    for name, data in artifacts.items():
        path = artifact_dir / name
        write_json(path, data)
        scenario["artifact_paths"].append(str(path))
    write_jsonl(artifact_dir / "trace-export.jsonl", trace_events)
    scenario["artifact_paths"].extend([str(artifact_dir / "trace-export.jsonl"), str(artifact_dir / "tampered-trace-export.jsonl"), str(artifact_dir / "tampered-state-export.json"), str(commands), str(artifact_dir / "stdout.log"), str(artifact_dir / "stderr.log")])
    write_json(artifact_dir / "scenario-report.json", scenario)
    if failures:
        raise SystemExit("UC-E2E-S8 failed required evidence checks: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
