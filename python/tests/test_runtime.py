import json
import time
from pathlib import Path

import splendor

from splendor import KernelRuntime, KernelRuntimeConfig, QuotaPolicy
from splendor.runtime import (
    Action,
    ActionCandidate,
    Constraint,
    Percept,
    QuotaLedger,
    QuotaUsage,
    STABLE_0_1_ENUM_VALUES,
    STABLE_0_1_PRIMITIVES,
    STABLE_0_1_REQUIRED_FIELDS,
    STABLE_0_1_RESERVED_EXTENSION_KEYS,
    TenantPolicy,
    VerificationResult,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_stable_manifest() -> dict[str, object]:
    path = REPO_ROOT / "docs" / "spec" / "0.1" / "stable-primitive-examples.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _reject_authority_fields(
    primitive: dict[str, object], candidate: dict[str, object]
) -> None:
    required = set(primitive["required_fields"])
    optional = set(primitive["optional_fields"])
    declared = required | optional
    reserved = set(STABLE_0_1_RESERVED_EXTENSION_KEYS)
    for key in candidate:
        if key in reserved and key not in declared:
            raise ValueError(f"unknown top-level authority field {key}")
    extensions = candidate.get("extensions")
    if extensions is not None:
        if primitive["extensions"] != "non_authorizing" or not isinstance(extensions, dict):
            raise ValueError("extensions not allowed")
        for key in extensions:
            if key in reserved:
                raise ValueError(f"extension key {key} carries authority")


def test_stable_0_1_python_schema_constants_match_examples() -> None:
    manifest = _load_stable_manifest()
    primitives = manifest["primitives"]
    assert [entry["name"] for entry in primitives] == list(STABLE_0_1_PRIMITIVES)
    assert manifest["extension_policy"]["reserved_keys"] == list(
        STABLE_0_1_RESERVED_EXTENSION_KEYS
    )
    assert manifest["enum_values"] == {
        key: list(value) for key, value in STABLE_0_1_ENUM_VALUES.items()
    }

    by_name = {entry["name"]: entry for entry in primitives}
    for name in STABLE_0_1_PRIMITIVES:
        entry = by_name[name]
        assert entry["required_fields"] == list(STABLE_0_1_REQUIRED_FIELDS[name])
        example = entry["example"]
        for field in STABLE_0_1_REQUIRED_FIELDS[name]:
            assert field in example
        _reject_authority_fields(entry, example)

        bad_extension = dict(example)
        bad_extension["extensions"] = {"allowed_permissions": ["admin"]}
        if entry["extensions"] == "non_authorizing":
            try:
                _reject_authority_fields(entry, bad_extension)
            except ValueError as exc:
                assert "extension key allowed_permissions" in str(exc)
            else:
                raise AssertionError("authority-bearing extension key was accepted")

        bad_top_level = dict(example)
        bad_top_level["credential"] = "secret"
        try:
            _reject_authority_fields(entry, bad_top_level)
        except ValueError as exc:
            assert "unknown top-level authority field credential" in str(exc)
        else:
            raise AssertionError("unknown top-level authority field was accepted")

    assert by_name["Run"]["example"]["status"] in STABLE_0_1_ENUM_VALUES["run_status"]
    assert (
        by_name["Action"]["example"]["side_effect_class"]
        in STABLE_0_1_ENUM_VALUES["side_effect_class"]
    )
    assert (
        by_name["Approval"]["example"]["decision"]
        in STABLE_0_1_ENUM_VALUES["approval_decision"]
    )
    assert by_name["Constraint"]["example"]["kind"] in STABLE_0_1_ENUM_VALUES[
        "constraint_kind"
    ]
    assert by_name["Constraint"]["example"]["scope"] in STABLE_0_1_ENUM_VALUES[
        "constraint_scope"
    ]
    assert by_name["WorkOrder"]["example"]["signature"] is not None


def test_record_trace() -> None:
    runtime = KernelRuntime(KernelRuntimeConfig(name="test"))
    event = runtime.record_trace("boot", "hello")
    assert event["sequence"] == 0
    assert event["message"] == "hello"
    assert event["runtime"] == "test"


def test_default_trace_sink_prints(capsys) -> None:
    runtime = KernelRuntime()
    event = runtime.record_trace("boot", "hello")
    captured = capsys.readouterr()
    assert "hello" in captured.out
    assert event["runtime"] == "splendor"


def test_custom_trace_sink_receives_events() -> None:
    events = []

    def sink(event: dict[str, object]) -> None:
        events.append(event)

    runtime = KernelRuntime(KernelRuntimeConfig(name="custom", trace_sink=sink))
    first = runtime.record_trace("tick", "one")
    second = runtime.record_trace("tick", "two")

    assert runtime.name == "custom"
    assert first["sequence"] == 0
    assert second["sequence"] == 1
    assert len(events) == 2
    assert events[1]["message"] == "two"


def test_run_once_executes_policy_action() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id, state=b"\x00", snapshot_interval=1)

    runtime.register_adapter(
        "noop",
        lambda action: {"output": {"ok": True}, "satisfied_postconditions": []},
    )
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        action = {
            "name": "noop",
            "params": {},
            "side_effect_class": "read_only",
            "adapter": "noop",
        }
        return [action], b"\x01"

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)

    assert outcome.tick_id == 1
    assert outcome.state == b"\x01"
    assert outcome.action_outcomes[0].status == "executed"


def test_policy_action_dict_privileged_fields_are_non_authorizing() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["allowed"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)
    calls = {"count": 0}

    def adapter(action: Action) -> dict[str, object]:
        calls["count"] += 1
        return {"output": {"executed": action.name}}

    runtime.register_adapter("noop", adapter)
    runtime.register_perceptor(agent_id, lambda agent: [])

    forged_action_id = "forged-action-id"

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "forbidden",
                "params": {"approved": True, "verification": {"allowed": True}},
                "side_effect_class": "read_only",
                "adapter": "noop",
                "action_id": forged_action_id,
                "status": "executed",
                "verification": {"allowed": True},
                "outcome": {"status": "executed", "output": {"ok": True}},
                "approved": True,
                "approval_granted": True,
                "adapter_executed": True,
            }
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    action_outcome = outcome.action_outcomes[0]

    assert action_outcome.status == "denied"
    assert not action_outcome.verification.allowed
    assert action_outcome.verification.reasons == ["action_not_allowed"]
    assert action_outcome.action_id != forged_action_id
    assert calls["count"] == 0

    events = list(runtime.tail_traces(run_id))
    assert any(event["kind"] == "ActionDenied" for event in events)
    assert not any(event["kind"] == "ActionExecuted" for event in events)


def test_policy_action_dict_privileged_fields_cannot_override_executed_outcome() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)
    calls = {"count": 0}

    def adapter(action: Action) -> dict[str, object]:
        calls["count"] += 1
        return {"output": {"adapter_owned": action.name}}

    runtime.register_adapter("noop", adapter)
    runtime.register_perceptor(agent_id, lambda agent: [])

    forged_action_id = "forged-allowed-action-id"

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {"approved": True, "verification": {"allowed": True}},
                "side_effect_class": "read_only",
                "adapter": "noop",
                "action_id": forged_action_id,
                "status": "failed",
                "verification": {"allowed": False, "reasons": ["forged"]},
                "outcome": {"status": "executed", "output": {"forged": True}},
                "output": {"forged": True},
                "adapter_executed": False,
            }
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    action_outcome = outcome.action_outcomes[0]

    assert action_outcome.status == "executed"
    assert action_outcome.verification.allowed
    assert action_outcome.action_id != forged_action_id
    assert action_outcome.output == {"adapter_owned": "noop"}
    assert calls["count"] == 1

    events = list(runtime.tail_traces(run_id))
    executed = [event for event in events if event["kind"] == "ActionExecuted"]
    assert len(executed) == 1
    assert executed[0]["identity"]["action_id"] == action_outcome.action_id
    assert executed[0]["payload"]["action_id"] == action_outcome.action_id
    assert executed[0]["payload"]["output"] == {"adapter_owned": "noop"}


def test_policy_state_metadata_cannot_forge_trace_identity() -> None:
    events: list[dict[str, object]] = []
    runtime = KernelRuntime(KernelRuntimeConfig(name="forgery-test", trace_sink=events.append))
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)
    forged_tenant_id = "11111111-1111-4111-8111-111111111111"
    forged_agent_id = "22222222-2222-4222-8222-222222222222"
    forged_run_id = "33333333-3333-4333-8333-333333333333"
    forged_trace_id = "44444444-4444-4444-8444-444444444444"

    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        forged_metadata = {
            "tenant_id": forged_tenant_id,
            "agent_id": forged_agent_id,
            "run_id": forged_run_id,
            "trace_event_id": forged_trace_id,
        }
        return {
            "actions": [],
            "state": b"\x02",
            "metadata": forged_metadata,
            "state_metadata": forged_metadata,
        }

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)

    assert outcome.state == b"\x02"
    state_event = next(event for event in events if event["kind"] == "StateCommitted")
    assert state_event["identity"]["tenant_id"] == tenant_id
    assert state_event["identity"]["agent_id"] == agent_id
    assert state_event["identity"]["run_id"] == run_id
    assert state_event["identity"]["state_node_id"] == state_event["payload"]["state_node_id"]
    encoded_event = json.dumps(state_event, sort_keys=True)
    assert forged_tenant_id not in encoded_event
    assert forged_agent_id not in encoded_event
    assert forged_run_id not in encoded_event
    assert forged_trace_id not in encoded_event


def test_constraints_deny_actions() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    runtime.register_constraints(agent_id, lambda state, percepts, actions: False)
    outcome = runtime.run_once(agent_id)

    assert outcome.action_outcomes[0].status == "denied"


def test_start_and_stop_runs_ticks() -> None:
    runtime = KernelRuntime(KernelRuntimeConfig(tick_interval=0.01))
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    runtime.start(agent_id)
    time.sleep(0.03)
    runtime.stop(agent_id)
    assert runtime.agent_tick(agent_id) >= 1


def test_trace_subscription_and_tail() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    events: list[dict[str, object]] = []
    runtime.subscribe_traces(run_id, lambda event: events.append(event))
    runtime.run_once(agent_id)

    assert any(event["kind"] == "LoopTickCompleted" for event in events)
    tail = list(runtime.tail_traces(run_id))
    assert len(tail) >= len(events)
    assert tail[0]["run_id"] == run_id


def test_runtime_traces_include_canonical_identity_context() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    runtime.run_once(agent_id)
    events = list(runtime.tail_traces(run_id))

    for sequence, event in enumerate(events):
        assert event["sequence"] == sequence
        assert "trace_event_id" in event
        assert event["identity"]["run_id"] == run_id
        assert event["identity"].get("tenant_id") == tenant_id
        assert event["identity"].get("agent_id") == agent_id

    action_events = [
        event for event in events if event["kind"].startswith("Action")
    ]
    assert action_events
    action_id = action_events[0]["identity"]["action_id"]
    assert all(event["identity"]["action_id"] == action_id for event in action_events)

    state_event = next(event for event in events if event["kind"] == "StateCommitted")
    assert state_event["identity"]["state_node_id"].startswith("sha256:")


def test_identity_validation_rejects_invalid_python_ids() -> None:
    runtime = KernelRuntime()
    try:
        runtime.create_tenant(tenant_id="not-a-uuid")
    except ValueError as exc:
        assert "tenant_id is invalid" in str(exc)
    else:
        raise AssertionError("expected invalid tenant_id")

    tenant_id = runtime.create_tenant()
    try:
        runtime.create_agent(tenant_id, run_id="00000000-0000-0000-0000-000000000000")
    except ValueError as exc:
        assert "run_id is required" in str(exc)
    else:
        raise AssertionError("expected missing run_id")


def test_replay_run_does_not_repeat_adapter_side_effects() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["write"],
        allowed_adapters=["filesystem"],
    )
    agent_id = runtime.create_agent(tenant_id)
    run_id = runtime.agent_run_id(agent_id)
    calls = {"count": 0}

    def adapter(action: Action) -> dict[str, object]:
        calls["count"] += 1
        return {"output": {"written": action.params["path"]}}

    runtime.register_adapter("filesystem", adapter)
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "write",
                "adapter": "filesystem",
                "side_effect_class": "filesystem",
                "params": {"path": "artifact.txt"},
            }
        ]

    runtime.register_policy(agent_id, policy)
    runtime.run_once(agent_id)
    assert calls["count"] == 1

    replay = runtime.replay_run(run_id)

    assert calls["count"] == 1
    assert any(event["kind"] == "ActionExecuted" for event in replay)
    assert any(event["kind"] == "StateCommitted" for event in replay)


def test_quota_denial_is_recorded() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
        quotas=QuotaPolicy(max_actions_per_tick=0),
    )
    agent_id = runtime.create_agent(tenant_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "denied"
    assert "max_actions_per_tick" in outcome.action_outcomes[0].verification.reasons


def test_missing_adapter_is_failure() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "failed"
    assert outcome.action_outcomes[0].error == "adapter not registered"


def test_replay_run_rejects_missing_run() -> None:
    runtime = KernelRuntime()
    try:
        runtime.replay_run("missing")
    except ValueError as exc:
        assert "run not found" in str(exc)
    else:
        raise AssertionError("expected error")


def test_create_agent_requires_tenant() -> None:
    runtime = KernelRuntime()
    try:
        runtime.create_agent("missing")
    except ValueError as exc:
        assert "tenant not found" in str(exc)
    else:
        raise AssertionError("expected error")


def test_normalize_percepts_and_actions() -> None:
    runtime = KernelRuntime()

    percept = Percept(
        schema="sensor",
        payload={"k": 1},
        provenance={"source": "test"},
        timestamp=1.0,
    )
    normalized = runtime._normalize_percept(percept)
    assert normalized["schema"] == "sensor"

    normalized = runtime._normalize_percept({"payload": {"v": 2}})
    assert normalized["schema"] == ""
    assert normalized["payload"]["v"] == 2

    normalized = runtime._normalize_percept("raw")
    assert normalized["schema"] == "unknown"
    assert normalized["payload"]["value"] == "raw"

    action = Action(name="noop", params={}, side_effect_class="read_only")
    candidate = ActionCandidate(action=action, adapter="noop")
    assert runtime._normalize_action(candidate) is candidate

    normalized = runtime._normalize_action(action)
    assert normalized.action.name == "noop"

    normalized = runtime._normalize_action(
        {
            "name": "noop",
            "params": {},
            "side_effect_class": "read_only",
            "usage": {"actions": 2, "http_requests": 1},
            "adapter": "noop",
            "satisfied_preconditions": ["ready"],
        }
    )
    assert normalized.usage.actions == 2
    assert normalized.usage.http_requests == 1
    assert normalized.satisfied_preconditions == ["ready"]

    try:
        runtime._normalize_action(object())
    except ValueError as exc:
        assert "invalid action" in str(exc)
    else:
        raise AssertionError("expected error")


def test_policy_output_variants() -> None:
    runtime = KernelRuntime()
    action = {"name": "noop", "params": {}, "side_effect_class": "read_only"}
    candidates, next_state = runtime._normalize_policy_output(
        {"actions": [action], "state": b"\x02"}, b"\x01"
    )
    assert candidates[0].action.name == "noop"
    assert next_state == b"\x02"

    candidates, next_state = runtime._normalize_policy_output(
        ([action], b"\x03"), b"\x01"
    )
    assert next_state == b"\x03"
    assert candidates[0].action.name == "noop"

    candidates, next_state = runtime._normalize_policy_output([], b"\x01")
    assert candidates == []
    assert next_state == b"\x01"


def test_constraints_dict_and_verification_result() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)

    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
            }
        ]

    runtime.register_policy(agent_id, policy)
    runtime.register_constraints(
        agent_id,
        lambda state, percepts, actions: {
            "allowed": False,
            "reasons": ["constraints_denied"],
            "constraints": [
                {"id": "c1", "kind": "hard", "scope": "action", "predicate": "no"},
                "raw",
            ],
        },
    )
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "denied"

    runtime.register_constraints(
        agent_id, lambda state, percepts, actions: VerificationResult.allow()
    )
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "executed"


def test_policy_verification_paths() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["ok"],
        allowed_adapters=["adapter"],
    )
    agent_id = runtime.create_agent(tenant_id)
    runtime.register_adapter("adapter", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {"name": "bad", "params": {}, "side_effect_class": "read_only"},
            {
                "name": "ok",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "missing",
            },
            {
                "name": "ok",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "adapter",
                "required_permissions": ["admin"],
            },
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    reasons = [outcome.action_outcomes[i].verification.reasons[0] for i in range(3)]
    assert "action_not_allowed" in reasons
    assert "adapter_not_allowed" in reasons
    assert "permission_missing" in reasons


def test_preconditions_and_postconditions() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    runtime.register_adapter(
        "noop",
        lambda action: {"output": {"ok": True}, "satisfied_postconditions": []},
    )
    runtime.register_perceptor(agent_id, lambda agent: [])

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
                "preconditions": ["ready"],
                "satisfied_preconditions": [],
            },
            {
                "name": "noop",
                "params": {},
                "side_effect_class": "read_only",
                "adapter": "noop",
                "postconditions": ["done"],
            },
        ]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "denied"
    assert outcome.action_outcomes[0].verification.reasons == ["precondition_missing"]
    assert outcome.action_outcomes[1].status == "executed"
    assert outcome.needs_intervention


def test_quota_ledger_limits_and_reset() -> None:
    ledger = QuotaLedger()
    quotas = QuotaPolicy(
        max_actions_per_tick=0,
        max_action_duration_ms=0,
        max_filesystem_read_bytes=0,
        max_filesystem_write_bytes=0,
        max_network_read_bytes=0,
        max_network_write_bytes=0,
        max_http_requests_per_minute=0,
    )
    usage = QuotaUsage(
        actions=1,
        action_duration_ms=1,
        filesystem_read_bytes=1,
        filesystem_write_bytes=1,
        network_read_bytes=1,
        network_write_bytes=1,
        http_requests=1,
    )
    result = ledger.record_usage("agent", usage, quotas, time.time())
    assert not result.allowed
    assert "max_actions_per_tick" in result.reasons
    assert "max_http_requests_per_minute" in result.reasons

    ledger.begin_tick(1)
    allowed = ledger.record_usage(
        "agent",
        QuotaUsage(http_requests=0),
        QuotaPolicy(max_http_requests_per_minute=1),
        time.time() + 61,
    )
    assert allowed.allowed


def test_policy_output_accepts_action_dataclass() -> None:
    runtime = KernelRuntime()
    tenant_id = runtime.create_tenant(
        allowed_actions=["noop"],
        allowed_adapters=["noop"],
    )
    agent_id = runtime.create_agent(tenant_id)
    runtime.register_adapter("noop", lambda action: {"output": {"ok": True}})
    runtime.register_perceptor(agent_id, lambda agent: [])

    action = Action(name="noop", params={}, side_effect_class="read_only")

    def policy(state: bytes, percepts: list[dict[str, object]]):
        return [action]

    runtime.register_policy(agent_id, policy)
    outcome = runtime.run_once(agent_id)
    assert outcome.action_outcomes[0].status == "executed"


def test_verify_policy_direct() -> None:
    runtime = KernelRuntime()
    policy = TenantPolicy(allowed_actions=["ok"], allowed_adapters=["adapter"])
    action = Action(name="ok", params={}, side_effect_class="read_only")
    candidate = ActionCandidate(action=action, adapter="adapter")
    result = runtime._verify_policy(policy, candidate)
    assert result.allowed


def test_package_exports() -> None:
    assert "KernelRuntime" in splendor.__all__
    assert "KernelRuntimeConfig" in splendor.__all__
    assert "Action" in splendor.__all__
    assert "QuotaUsage" in splendor.__all__
    assert isinstance(splendor.__version__, str)
    assert splendor.__version__
    assert splendor.__baseline__ == "Splendor0.05-dev"
