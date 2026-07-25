#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

import aggregate_report as ar


def load_s9_scenario_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "scenarios"
        / "uc_e2e_s9_failure_injection"
        / "run.py"
    )
    spec = importlib.util.spec_from_file_location("uc_e2e_s9_failure_injection_run", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load S9 scenario helper module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


S9_SCENARIO = load_s9_scenario_module()


RUN_ID = "44444444-4444-4444-8444-444444449903"
PRE_EFFECT_TRACE_RUN_ID = "44444444-4444-4444-8444-444444449909"
POST_EFFECT_TRACE_RUN_ID = "44444444-4444-4444-8444-444444449911"
ACTION_ID = "55555555-5555-4555-8555-555555559903"
MESSAGE_ID = "66666666-6666-4666-8666-666666669903"


def uuid_for(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def runtime_record(
    trace_id: str,
    kind: str,
    *,
    action_name: str = "s9.test",
    action_id: str = ACTION_ID,
    reasons: list[str] | None = None,
    artifacts: dict | None = None,
    run_id: str = RUN_ID,
    failed_event: str = "ActionVerificationStarted",
    side_effect_executed: bool = False,
) -> dict:
    body: dict = {}
    if kind in {"ActionDenied", "ActionNeedsIntervention", "ActionFailed"}:
        result = {"allowed": False, "reasons": reasons or ["denied"], "artifacts": artifacts or {}}
        body = {"action": {"name": action_name}, "result": result}
        if kind == "ActionFailed":
            body["error"] = "adapter_failed"
    elif kind == "TraceWriteFailed":
        body = {"failed_event": failed_event, "side_effect_executed": side_effect_executed}
    elif kind == "StateCommitFailed":
        body = {"reason": "injected_state_commit_failure", "next_tick_advanced": False}
    elif kind == "RunPaused":
        body = {"reason": "waiting_for_approval"}
    elif kind == "RunStopped":
        body = {"reason": "kill_switch"}
    elif kind == "PolicyExpired":
        body = {"policy_bundle_id": "policy_uc_e2e_s5_runtime_expiry", "version": "v1", "action": "artifact.publish_external"}
    return {
        "payload": {
            "trace_event_id": trace_id,
            "identity": {"run_id": run_id, "action_id": action_id},
            "kind": {kind: body},
        },
        "run_id": run_id,
    }


def valid_fixture() -> tuple[dict, dict, dict, list[dict], list[dict], dict[str, list[dict]]]:
    evidence: dict[str, list[dict]] = {}
    trace_records: list[dict] = []
    manager_events: list[dict] = []
    source_records: dict[str, list[dict]] = {"UC-E2E-S5": []}

    def add_runtime(event: str, original: str, record: dict, *, details: dict | None = None) -> None:
        trace_records.append(record)
        row = {
            "trace_event_id": ar.trace_record_id(record),
            "source": "runtime_trace_export",
            "original_event_type": original,
            "artifact": "trace-export.jsonl",
            "run_id": ar.trace_record_run_id(record),
            "action_id": ar.trace_record_action_id(record),
            "details": details or {},
        }
        evidence.setdefault(event, []).append(row)

    def add_manager(event: str, original: str, details: dict) -> None:
        trace_id = uuid_for(len(evidence) + 20)
        manager_events.append({"trace_event_id": trace_id, "event_type": original, "details": details})
        evidence.setdefault(event, []).append({
            "trace_event_id": trace_id,
            "source": "manager_audit_export",
            "original_event_type": original,
            "artifact": "manager-audit-export.json",
            "run_id": RUN_ID,
            "message_id": details.get("message_id"),
            "details": details,
        })

    add_runtime(
        "adapter.failed",
        "action.failed",
        runtime_record(uuid_for(1), "ActionFailed", action_name="s9.adapter_failure", reasons=["adapter_failed"]),
        details={"action": "s9.adapter_failure", "outcome_action_id": ACTION_ID},
    )
    add_runtime(
        "verifier.unavailable",
        "action.denied",
        runtime_record(
            uuid_for(2),
            "ActionDenied",
            action_name="http_get",
            reasons=["verifier_unavailable"],
            artifacts={
                "resource_boundary": {
                    "verifier_status": "unavailable",
                    "adapter_execution": "not_attempted",
                    "failure_injection": "splendorctl_public_run_config",
                }
            },
        ),
        details={
            "reasons": ["verifier_unavailable"],
            "public_path": "splendorctl run --config",
            "failure_injection": "verifier_unavailable_actions",
            "http_counter_before": 0,
            "http_counter_after": 0,
        },
    )
    add_runtime("quota.exceeded", "action.denied", runtime_record(uuid_for(3), "ActionDenied", reasons=["quota_exceeded"]))
    add_runtime(
        "trace.write_failed",
        "trace.write_failed",
        runtime_record(uuid_for(4), "TraceWriteFailed", action_id="", run_id=PRE_EFFECT_TRACE_RUN_ID),
        details={"failed_event": "ActionVerificationStarted", "side_effect_executed": False, "http_counter_before": 0, "http_counter_after": 0},
    )
    trace_records.extend([
        runtime_record(uuid_for(40), "LoopTickStarted", action_id="", run_id=POST_EFFECT_TRACE_RUN_ID),
        runtime_record(uuid_for(41), "ActionExecuted", action_name="write_file", run_id=POST_EFFECT_TRACE_RUN_ID),
    ])
    add_runtime(
        "trace.write_failed",
        "trace.write_failed",
        runtime_record(uuid_for(42), "TraceWriteFailed", action_id="", run_id=POST_EFFECT_TRACE_RUN_ID, failed_event="OutcomeRecorded", side_effect_executed=True),
        details={"failed_event": "OutcomeRecorded", "side_effect_executed": True, "effect_exists": True, "effect_contents": "executed-once\n", "events": ["tick.started", "action.executed", "trace.write_failed"]},
    )
    add_runtime("state.commit_failed", "state.commit_failed", runtime_record(uuid_for(5), "StateCommitFailed", action_id=""), details={"events": ["tick.started", "state.commit_failed"]})
    add_runtime("run.paused", "run.paused", runtime_record(uuid_for(6), "RunPaused", action_id=""))
    add_runtime("run.denied", "action.denied", runtime_record(uuid_for(7), "ActionDenied", reasons=["approval_denied"]))
    add_runtime("run.cancelled", "run.cancelled", runtime_record(uuid_for(8), "RunStopped", action_id=""))

    add_manager("message.delivery_failed", "remote_message.failed", {"message_id": MESSAGE_ID, "remote_state_mutated": False})
    add_manager("node.stale", "placement.evaluated", {"placement": {"status": "rejected", "reasons": ["candidate not available"]}})
    add_manager("circuit_breaker.tripped", "circuit_breaker.tripped", {"breaker_id": "breaker-s9"})
    add_manager("kill_switch.activated", "kill_switch.activated", {"kill_switch_id": "kill-s9"})

    policy_record = runtime_record(uuid_for(30), "PolicyExpired")
    source_records["UC-E2E-S5"].append(policy_record)
    evidence["policy.expired"] = [{
        "trace_event_id": ar.trace_record_id(policy_record),
        "source": "source_runtime_trace_export",
        "original_event_type": "policy.expired",
        "artifact": "UC-E2E-S5/trace-export.jsonl",
        "run_id": RUN_ID,
        "action_id": ACTION_ID,
        "details": {"source_scenario": "UC-E2E-S5", "reason_code": "policy_expired"},
    }]

    event_ids = {event: [row["trace_event_id"] for row in rows] for event, rows in evidence.items()}
    scenario = {"required_event_evidence": evidence, "required_trace_event_ids": event_ids}
    fault = {"required_event_evidence": copy.deepcopy(evidence)}
    audit = {"required_event_evidence": copy.deepcopy(evidence)}
    return scenario, fault, audit, trace_records, manager_events, source_records


class S9AggregateEvidenceTests(unittest.TestCase):
    def test_accepts_runtime_verifier_unavailable_evidence(self) -> None:
        scenario, fault, audit, trace_records, manager_events, source_records = valid_fixture()
        failures = ar.validate_s9_required_event_evidence(
            scenario=scenario,
            fault=fault,
            audit=audit,
            trace_records=trace_records,
            manager_events=manager_events,
            source_trace_records=source_records,
        )
        self.assertEqual([], failures)

    def test_rejects_approval_policy_expiry_as_verifier_unavailable(self) -> None:
        scenario, fault, audit, trace_records, manager_events, source_records = valid_fixture()
        trace_records[1]["payload"]["kind"]["ActionDenied"]["result"] = {
            "allowed": False,
            "reasons": ["approval_policy_expired"],
            "artifacts": {"approval_status": "intervention_required", "verifier": "approval_verifier"},
        }
        failures = ar.validate_s9_required_event_evidence(
            scenario=scenario,
            fault=fault,
            audit=audit,
            trace_records=trace_records,
            manager_events=manager_events,
            source_trace_records=source_records,
        )
        self.assertIn("s9_verifier_unavailable_missing_runtime_reason", failures)
        self.assertIn("s9_verifier_unavailable_confused_with_policy_or_approval_expiry", failures)

    def test_rejects_manual_verifier_unavailable_evidence_row(self) -> None:
        scenario, fault, audit, trace_records, manager_events, source_records = valid_fixture()
        for container in [scenario, fault, audit]:
            container["required_event_evidence"]["verifier.unavailable"][0]["source"] = "scenario_report"
        failures = ar.validate_s9_required_event_evidence(
            scenario=scenario,
            fault=fault,
            audit=audit,
            trace_records=trace_records,
            manager_events=manager_events,
            source_trace_records=source_records,
        )
        self.assertIn("s9_required_event_forbidden_source:verifier.unavailable:scenario_report", failures)

    def test_rejects_missing_post_effect_trace_failure_evidence(self) -> None:
        scenario, fault, audit, trace_records, manager_events, source_records = valid_fixture()
        for container in [scenario, fault, audit]:
            container["required_event_evidence"]["trace.write_failed"] = container["required_event_evidence"]["trace.write_failed"][:1]
        scenario["required_trace_event_ids"]["trace.write_failed"] = scenario["required_trace_event_ids"]["trace.write_failed"][:1]
        trace_records = [record for record in trace_records if ar.trace_record_run_id(record) != POST_EFFECT_TRACE_RUN_ID]
        failures = ar.validate_s9_required_event_evidence(
            scenario=scenario,
            fault=fault,
            audit=audit,
            trace_records=trace_records,
            manager_events=manager_events,
            source_trace_records=source_records,
        )
        self.assertIn("s9_trace_write_failure_after_effect_evidence_missing", failures)


class S9ScenarioFailurePredicateTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, dict, dict, dict, dict, int]:
        action_id = "55555555-5555-4555-8555-555555559902"
        outcome = {
            "action_id": action_id,
            "status": "Failed",
            "error": "adapter failed",
            "output": None,
            "post_verification": None,
            "verification": {"artifacts": {}},
        }
        before = {"adapter_executions": 0}
        after = {"adapter_executions": 0}
        provider_before = {"by_action": {"s9.adapter_failure": 0}, "actions": []}
        provider_after = {
            "by_action": {"s9.adapter_failure": 1},
            "actions": [
                {
                    "action_id": action_id,
                    "result": "failed",
                    "provider_receipt_id": None,
                }
            ],
        }
        return outcome, before, after, provider_before, provider_after, 1

    def test_accepts_bounded_failure_without_self_asserted_certainty(self) -> None:
        self.assertTrue(S9_SCENARIO.conservative_adapter_failure_evidence(*self.fixture()))

    def test_rejects_magic_prefix_or_structured_adapter_claim(self) -> None:
        fixture = list(self.fixture())
        fixture[0] = copy.deepcopy(fixture[0])
        fixture[0]["error"] = (
            "splendor.adapter_failure.v1|spoofed|unavailable|"
            "retry_with_same_idempotency_key|none|pre_send"
        )
        self.assertFalse(S9_SCENARIO.conservative_adapter_failure_evidence(*fixture))

        fixture = list(self.fixture())
        fixture[0] = copy.deepcopy(fixture[0])
        fixture[0]["verification"]["artifacts"]["adapter_failure"] = {
            "effect_certainty": "none",
            "retry_class": "retry_with_same_idempotency_key",
        }
        self.assertFalse(S9_SCENARIO.conservative_adapter_failure_evidence(*fixture))

    def test_rejects_retry_or_success_counter_drift(self) -> None:
        fixture = list(self.fixture())
        fixture[-1] = 2
        self.assertFalse(S9_SCENARIO.conservative_adapter_failure_evidence(*fixture))

        fixture = list(self.fixture())
        fixture[2] = {"adapter_executions": 1}
        self.assertFalse(S9_SCENARIO.conservative_adapter_failure_evidence(*fixture))

    def test_rejects_missing_or_non_exact_execution_counters(self) -> None:
        cases = [
            ("both_missing", {}, {}),
            ("before_missing", {}, {"adapter_executions": 0}),
            ("after_missing", {"adapter_executions": 0}, {}),
            ("none", {"adapter_executions": None}, {"adapter_executions": None}),
            ("bool", {"adapter_executions": False}, {"adapter_executions": False}),
            ("float", {"adapter_executions": 0.0}, {"adapter_executions": 0.0}),
            ("string", {"adapter_executions": "0"}, {"adapter_executions": "0"}),
        ]
        for name, before, after in cases:
            with self.subTest(name=name):
                fixture = list(self.fixture())
                fixture[1] = before
                fixture[2] = after
                self.assertFalse(
                    S9_SCENARIO.conservative_adapter_failure_evidence(*fixture)
                )

    def test_rejects_retired_authority_schemas_under_any_artifact_nesting(self) -> None:
        cases = [
            {"alternate": {"schema": "splendor.adapter_failure_evidence.v1"}},
            {"nested": [{"schema": "splendor.adapter_failure.v1"}]},
            {"splendor.adapter_failure_evidence.v1": {"claim": "none"}},
        ]
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                fixture = list(self.fixture())
                fixture[0] = copy.deepcopy(fixture[0])
                fixture[0]["verification"]["artifacts"] = artifacts
                self.assertFalse(
                    S9_SCENARIO.conservative_adapter_failure_evidence(*fixture)
                )


class S9ReplayProviderStateTests(unittest.TestCase):
    def test_ignores_read_freshness_and_detects_effect_changes(self) -> None:
        before = {
            "by_action": {"s9.idempotent_read": 1},
            "actions": [{"action_id": ACTION_ID, "result": "executed"}],
            "snapshot_at_unix_ms": 1,
            "expires_at_unix_ms": 2,
            "snapshot_sequence": 7,
            "request_binding": {"nonce": "before"},
            "_evidence_verification": {"envelope": {"signature_b64": "before"}},
        }
        after = copy.deepcopy(before)
        after.update(
            {
                "snapshot_at_unix_ms": 3,
                "expires_at_unix_ms": 4,
                "snapshot_sequence": 8,
                "request_binding": {"nonce": "after"},
                "_evidence_verification": {
                    "envelope": {"signature_b64": "after"}
                },
            }
        )

        self.assertEqual(
            S9_SCENARIO.replay_provider_effect_state(before),
            S9_SCENARIO.replay_provider_effect_state(after),
        )

        after["by_action"]["s9.idempotent_read"] = 2
        self.assertNotEqual(
            S9_SCENARIO.replay_provider_effect_state(before),
            S9_SCENARIO.replay_provider_effect_state(after),
        )


if __name__ == "__main__":
    unittest.main()
