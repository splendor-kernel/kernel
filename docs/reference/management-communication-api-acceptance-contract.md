# Splendor Management and Communication API Contract Exposure

**Date:** 2026-06-02
**Status:** Proposed acceptance contract for post-implementation E2E validation
**Intended repository placement:** `docs/reference/management-communication-api-acceptance-contract.md`
**Companion acceptance pack:** [`docs/rules/verifiable_criteria/use-case-e2e-through-0.1.md`](../rules/verifiable_criteria/use-case-e2e-through-0.1.md)

This document defines the API surface that acceptance tests must treat as fully exposed and executable for Splendor management and communication. It is not a replacement for the repository OpenAPI file; it is the contract checklist that the OpenAPI file, Rust daemon handlers, TypeScript client, Python SDK, CLI, and acceptance tests must satisfy.

The exact stable paths may be adapted during implementation only through an RFC or documented migration. The **operation IDs, security model, required schemas, semantics, and negative tests** are the acceptance contract.

---

## 1. Security model: three separate authorities

Splendor API acceptance tests must preserve three separate authorities:

| Layer | What it proves | What it must not do |
| --- | --- | --- |
| Caller credential | Authenticates the app, SDK, CLI, sidecar, adapter, central manager, operator console, or control plane. | Must not authorize arbitrary agent actions by itself. |
| Signed work order | Authorizes a run objective, allowed actions, adapters, permissions, data refs, quotas, placement, expiry, and audience. | Must not bypass runtime gateway/verifier enforcement. |
| Action Gateway | Authorizes side effects after constraints and verifier chain evaluation. | Must not be skipped by SDK, API handler, CLI, replay, central manager, or tests. |

Every non-dev request to a daemon, sidecar, resident node, or central manager must include:

- authenticated caller identity;
- tenant or fleet binding;
- endpoint-level scope authorization;
- expiry;
- audience binding;
- revocation path;
- trace/audit attribution for mutating calls.

Local development mode is valid only when explicitly enabled, loopback/Unix-socket bound, warning-logged, and excluded from fleet/remote/resident/production operation.

---

## 2. Required scopes

Scopes should be stable string values so clients and generated tests can reason about least privilege.

| Scope | Intended operations |
| --- | --- |
| `splendor.health.read` | health/version readiness checks only. |
| `splendor.capabilities.read` | capability discovery only; non-authoritative. |
| `splendor.runs.create` | create run from signed work order. |
| `splendor.runs.read` | inspect run status and metadata. |
| `splendor.runs.control` | start, pause, resume, cancel, stop run. |
| `splendor.percepts.append` | append percepts to a run or agent context. |
| `splendor.actions.submit` | submit action requests to gateway path. |
| `splendor.traces.read` | query/export traces with redaction policy. |
| `splendor.state.read` | read state head or snapshot references. |
| `splendor.state.handoff` | export/import state snapshots or handoff refs. |
| `splendor.replay.run` | run inspect-only/read-only/simulation/policy-comparison/verifier-explanation replay modes. |
| `splendor.messages.send` | send local/remote typed messages. |
| `splendor.messages.read` | read inbox/outbox/delivery/causal graph metadata. |
| `splendor.work_orders.submit` | submit work order for validation/dispatch. |
| `splendor.work_orders.revoke` | revoke work order. |
| `splendor.fleet.register` | register node/instance. |
| `splendor.fleet.read` | read registry, placement explanation, heartbeat, telemetry. |
| `splendor.fleet.dispatch` | dispatch accepted work order to a selected node. |
| `splendor.policies.publish` | publish governance/safety policy bundle. |
| `splendor.policies.revoke` | revoke policy bundle. |
| `splendor.approvals.manage` | grant/deny/revoke approval under scoped authority. |
| `splendor.governance.control` | create/clear circuit breakers and activate kill switches. |
| `splendor.device.register` | register physical/edge device profiles. |
| `splendor.device.read` | read device safety status and policy cache status. |
| `splendor.operator.intervene` | grant/deny local intervention requests. |

---

## 3. Local runtime daemon management operations

| Operation ID | Required path shape | Method | Required scope | Work order required? | Semantics acceptance tests must prove |
| --- | --- | --- | --- | --- | --- |
| `getHealth` | `/health` | `GET` | `splendor.health.read` or explicit local-dev mode | No | Reports liveness/readiness only; cannot authorize runs/actions/placement. |
| `getVersion` | `/version` | `GET` | `splendor.health.read` | No | Reports daemon/runtime/schema/client compatibility metadata. |
| `getCapabilities` | `/capabilities` | `GET` | `splendor.capabilities.read` | No | Reports adapters, runtime mode, supported schemas, replay modes; non-authoritative for actions. |
| `createRun` | `/runs` | `POST` | `splendor.runs.create` | Yes | Validates caller, signed work order, tenant/audience/expiry/revocation, and creates run identity without executing side effects. |
| `inspectRun` | `/runs/{run_id}` | `GET` | `splendor.runs.read` | No, but tenant binding required | Returns run state, tenant/agent/run IDs, current status, work-order linkage, and redacted metadata. |
| `startRun` | `/runs/{run_id}/start` | `POST` | `splendor.runs.control` | Existing run must be work-order authorized | Starts scheduler loop; mutating call trace-attributed. |
| `pauseRun` | `/runs/{run_id}/pause` | `POST` | `splendor.runs.control` | Existing run | Pauses run with reason and trace event. |
| `resumeRun` | `/runs/{run_id}/resume` | `POST` | `splendor.runs.control` | Existing run plus valid approval/intervention token when required | Resumes only when runtime state and governance conditions allow. |
| `cancelRun` | `/runs/{run_id}/cancel` | `POST` | `splendor.runs.control` | Existing run | Cancels/denies safely with trace/audit reason. |
| `stopRun` | `/runs/{run_id}/stop` | `POST` | `splendor.runs.control` | Existing run | Stops local execution without deleting trace/state evidence. |
| `appendPercept` | `/percepts` or `/runs/{run_id}/percepts` | `POST` | `splendor.percepts.append` | Existing run/context | Appends structured percept and emits trace; does not execute side effects directly. |
| `submitAction` | `/actions` or `/runs/{run_id}/actions` | `POST` | `splendor.actions.submit` | Existing run/action must be work-order-compatible | Submits action request to runtime gateway; API handler cannot self-attest verifier completion. |
| `getStateHead` | `/state-head` or `/runs/{run_id}/state-head` | `GET` | `splendor.state.read` | No, but tenant binding required | Returns current state node ID/hash/parent/linkage; no hidden state. |
| `exportStateSnapshot` | `/state-snapshots/export` | `POST` | `splendor.state.handoff` | Existing run/context | Exports explicit state reference for replay/handoff. |
| `importStateSnapshot` | `/state-snapshots/import` | `POST` | `splendor.state.handoff` | Existing target context | Validates tenant/run/hash/version before import. |
| `getRunTraces` | `/traces` or `/runs/{run_id}/traces` | `GET` | `splendor.traces.read` | No, but redaction policy required | Returns append-only trace records with required redaction. |
| `exportTraces` | `/traces/export` | `POST` | `splendor.traces.read` | No, but redaction policy required | Exports trace package and integrity metadata. |
| `replayRun` | `/replay` or `/runs/{run_id}/replay` | `POST` | `splendor.replay.run` | Existing trace/state evidence | Runs inspect-only by default; side-effectful modes separately gated and off by default. |

---

## 4. Fleet and central-manager operations

| Operation ID | Path shape | Method | Required scope | Semantics acceptance tests must prove |
| --- | --- | --- | --- | --- |
| `registerNode` | `/fleet/nodes` | `POST` | `splendor.fleet.register` | Registers stable `fleet_id`/`node_id`, node kind, trust level, locality, health endpoint, version, supported features. |
| `registerInstance` | `/fleet/instances` | `POST` | `splendor.fleet.register` | Registers `instance_id` distinct from node/agent/run; binds tenant/fleet/runtime mode. |
| `heartbeatNode` | `/fleet/nodes/{node_id}/heartbeat` | `POST` | `splendor.fleet.register` | Updates health without authorizing placement/actions by itself. |
| `advertiseCapabilities` | `/fleet/nodes/{node_id}/capabilities` | `POST` | `splendor.fleet.register` | Publishes capability set, quotas, adapter levels, locality, safety status. |
| `listNodes` | `/fleet/nodes` | `GET` | `splendor.fleet.read` | Reads registry; cannot dispatch or authorize by itself. |
| `evaluatePlacement` | `/fleet/placement/evaluate` | `POST` | `splendor.fleet.read` | Explains valid target or rejection based on explicit capability/work-order rules. |
| `submitWorkOrder` | `/work-orders` | `POST` | `splendor.work_orders.submit` | Validates signature, tenant, expiry, revocation, allowed actions/adapters/permissions/data refs/quotas/audience. |
| `revokeWorkOrder` | `/work-orders/{work_order_id}/revoke` | `POST` | `splendor.work_orders.revoke` | Prevents create/resume/authorize for revoked work order. |
| `dispatchWorkOrder` | `/work-orders/{work_order_id}/dispatch` | `POST` | `splendor.fleet.dispatch` | Dispatches to selected node only after validation and placement; trace-linked. |
| `getFleetTelemetry` | `/fleet/telemetry` | `GET` | `splendor.fleet.read` | Reports health/run/quota/trace-sync status; non-authoritative. |
| `syncTraceBuffer` | `/fleet/traces/sync` | `POST` | `splendor.traces.read` or node sync credential | Aggregates trace buffers with ordering/integrity validation. |

---

## 5. Communication operations

| Operation ID | Path shape | Method | Required scope | Semantics acceptance tests must prove |
| --- | --- | --- | --- | --- |
| `sendMessage` | `/messages` | `POST` | `splendor.messages.send` | Sends typed message with source/target/run/schema/payload/causal parent/timestamp through router/transport. |
| `getMessage` | `/messages/{message_id}` | `GET` | `splendor.messages.read` | Returns message metadata and delivery status only with explicit tenant_id, run_id, and participating source/target agent_id scope. |
| `listInbox` | `/agents/{agent_id}/inbox` | `GET` | `splendor.messages.read` | Reads delivered messages scoped to caller/tenant/run/path agent; omitted tenant/run/agent scope fails closed. |
| `listOutbox` | `/agents/{agent_id}/outbox` | `GET` | `splendor.messages.read` | Reads sent messages and delivery states scoped to caller/tenant/run/path agent. |
| `ackMessage` | `/messages/{message_id}/ack` | `POST` | `splendor.messages.send` | Records acknowledgement only when tenant_id, run_id, and recipient target agent_id match; cannot mutate payload or grant authority. |
| `nackMessage` | `/messages/{message_id}/nack` | `POST` | `splendor.messages.send` | Records failure reason only when tenant_id, run_id, and recipient target agent_id match; cannot mutate payload, route, work-order authority, source/target, run, tenant, permissions, or data refs. |
| `getMessageCausalGraph` | `/runs/{run_id}/messages/causal-graph` | `GET` | `splendor.messages.read` | Reconstructs causal parent graph from trace/message IDs under explicit tenant/run/agent scope. |
| `validateMessageSchema` | `/message-schemas/validate` | `POST` | `splendor.messages.read` | Validates schema version/payload without delivery. |
| `listMessageSchemas` | `/message-schemas` | `GET` | `splendor.messages.read` | Lists stable supported schema IDs/versions. |

Message operations must reject unsupported schemas, unauthorized recipients, cross-tenant delivery, missing causal parent where required, replay-time delivery, and attempts to smuggle permissions/data refs outside the work order or delegation scope.

---

## 6. Governance operations

| Operation ID | Path shape | Method | Required scope | Semantics acceptance tests must prove |
| --- | --- | --- | --- | --- |
| `publishPolicyBundle` | `/policies` | `POST` | `splendor.policies.publish` | Publishes policy with version, TTL, tenant/fleet scope, risk rules, revocation metadata. |
| `revokePolicyBundle` | `/policies/{policy_id}/revoke` | `POST` | `splendor.policies.revoke` | Revoked policy denies high-risk side effects or requests intervention. |
| `getPolicyStatus` | `/policies/{policy_id}` | `GET` | `splendor.fleet.read` | Reads status only; cannot authorize action. |
| `requestApproval` | `/approvals` | `POST` | Runtime or governance bridge credential | Creates approval request tied to action/run/work order; adapter not called. |
| `grantApproval` | `/approvals/{approval_id}/grant` | `POST` | `splendor.approvals.manage` | Grants scoped, expiring approval for exact action/risk/context. |
| `denyApproval` | `/approvals/{approval_id}/deny` | `POST` | `splendor.approvals.manage` | Denies pending action/run and trace-links reason. |
| `revokeApproval` | `/approvals/{approval_id}/revoke` | `POST` | `splendor.approvals.manage` | Prevents future resume/authorization. |
| `createCircuitBreaker` | `/governance/circuit-breakers` | `POST` | `splendor.governance.control` | Blocks matching tenant/agent/adapter/action/node/fleet/global scope. |
| `clearCircuitBreaker` | `/governance/circuit-breakers/{breaker_id}/clear` | `POST` | `splendor.governance.control` | Clears only with scoped authority and trace event. |
| `activateKillSwitch` | `/governance/kill-switches` | `POST` | `splendor.governance.control` | Cancels/blocks matching runs/actions fail-closed. |
| `exportGovernanceAudit` | `/governance/audit/export` | `POST` | `splendor.traces.read` | Exports approval/denial/circuit/kill/policy explanations. |

---

## 7. Physical/edge operations

| Operation ID | Path shape | Method | Required scope | Semantics acceptance tests must prove |
| --- | --- | --- | --- | --- |
| `registerDeviceProfile` | `/devices/profiles` | `POST` | `splendor.device.register` | Registers node kind, high-level capabilities, locality, safety constraints, runtime mode. |
| `getDeviceStatus` | `/devices/{node_id}/status` | `GET` | `splendor.device.read` | Reads battery/safety/offline/cache status; non-authoritative for unsafe action. |
| `getPolicyCacheStatus` | `/devices/{node_id}/policy-cache` | `GET` | `splendor.device.read` | Reports TTL/cache state; expired high-risk actions fail closed. |
| `submitPhysicalAction` | `/devices/{node_id}/actions` | `POST` | `splendor.actions.submit` | Sends high-level bounded action through gateway/safety verifiers. |
| `requestOperatorIntervention` | `/operator/interventions` | `POST` | Runtime or edge credential | Requests local/manual approval for ambiguous/high-risk action. |
| `grantOperatorIntervention` | `/operator/interventions/{intervention_id}/grant` | `POST` | `splendor.operator.intervene` | Grants scoped local intervention with expiry. |
| `denyOperatorIntervention` | `/operator/interventions/{intervention_id}/deny` | `POST` | `splendor.operator.intervene` | Denies and trace-links reason. |
| `syncDeviceTraceBuffer` | `/devices/{node_id}/trace-buffer/sync` | `POST` | Node sync credential | Syncs buffered offline traces with ordering/integrity checks. |

Allowed high-level physical actions for acceptance fixtures:

```text
read_battery
read_sensor_summary
read_map
move_to_waypoint
return_to_base
dock
inspect_zone
capture_image
pause_mission
resume_mission
request_operator_override
notify_operator
upload_trace_summary
```

Forbidden as Splendor direct actions:

```text
set_motor_pwm
raw actuator writes
disable_firmware_safety
bypass_collision_avoidance
modify_flight_controller_internals
ignore_emergency_stop
hard_real_time_stabilization
```

---

## 8. Required canonical schemas

Every schema below must be exposed in the OpenAPI contract or referenced from canonical schema files with generated/parity-checked Rust, Python, and TypeScript models.

### `CallerCredential`

Required fields:

- `credential_id`
- `principal_id`
- `principal_kind`
- `tenant_id` or `fleet_id`
- `audience`
- `scopes`
- `issued_at`
- `expires_at`
- `revocation_ref`
- `signature` or local-dev equivalent marker

### `WorkOrder`

Required fields:

- `work_order_id`
- `tenant_id`
- `agent_id`
- `objective`
- `allowed_actions`
- `allowed_adapters`
- `allowed_permissions`
- `data_refs`
- `quotas`
- `placement`
- `issued_at`
- `expires_at`
- `audience`
- `revocation_ref`
- `signature`

### `Run`

Required fields:

- `run_id`
- `tenant_id`
- `agent_id`
- `runtime_context_id`
- `work_order_id`
- `status`
- `created_at`
- `started_at`
- `completed_at`
- `current_tick_id`
- `state_head_id`
- `trace_head_id`
- `caller_attribution`

### `ActionRequest`

Required fields:

- `action_id`
- `tenant_id`
- `agent_id`
- `run_id`
- `tick_id`
- `adapter_id`
- `action_type`
- `payload`
- `preconditions`
- `requested_permissions`
- `data_refs`
- `idempotency_key`
- `causal_trace_event_id`

### `ActionOutcome`

Required fields:

- `action_id`
- `status`: `executed`, `denied`, `failed`, `needs_approval`, `needs_intervention`
- `reason_code`
- `verifier_results`
- `adapter_outcome_ref`
- `side_effect_summary`
- `trace_event_id`
- `state_node_id`
- `occurred_at`

### `TraceEvent`

Required fields:

- `trace_event_id`
- `tenant_id`
- `agent_id`
- `run_id`
- optional `tick_id`, `action_id`, `message_id`, `work_order_id`, `approval_id`, `node_id`, `instance_id`
- `event_type`
- `payload_ref` or redacted payload
- `causal_parent_id`
- `sequence`
- `integrity_hash`
- `previous_hash`
- `timestamp`

### `StateNode`

Required fields:

- `state_node_id`
- `tenant_id`
- `agent_id`
- `run_id`
- `parent_state_node_ids`
- `snapshot_ref` or `patch_ref`
- `state_hash`
- `trace_event_id`
- `schema_version`
- `created_at`

### `Message`

Required fields:

- `message_id`
- `tenant_id`
- `source_agent_id`
- `target_agent_id`
- `run_id`
- `schema`
- `payload`
- `causal_parent`
- `requires_response`
- `delivery_status`
- `created_at`

### `Approval`

Required fields:

- `approval_id`
- `tenant_id`
- `agent_id`
- `run_id`
- `action_id`
- `policy_id`
- `risk_level`
- `status`
- `granted_permissions`
- `scope`
- `issued_by`
- `issued_at`
- `expires_at`
- `revocation_ref`

### `NodeRegistration` / `InstanceRegistration`

Required fields:

- `fleet_id`
- `node_id`
- `instance_id`
- `node_kind`
- `runtime_mode`
- `locality`
- `capabilities`
- `adapter_maturity_levels`
- `trust_level`
- `version`
- `heartbeat_status`
- `registered_at`

### `DeviceProfile`

Required fields:

- `node_id`
- `device_kind`
- `capabilities`
- `allowed_physical_actions`
- `forbidden_action_classes`
- `safety_constraints`
- `offline_policy_cache_ttl`
- `operator_intervention_modes`
- `trace_buffer_config`

### `ReplayRequest`

Required fields:

- `run_id`
- `mode`: `inspect_only`, `read_only_re_evaluation`, `safe_simulation`, `policy_comparison`, `verifier_explanation`
- `trace_ref`
- `state_ref`
- `policy_ref`
- `side_effects_allowed`: must default `false`
- `explicit_gate_ref`: required for any non-default side-effectful mode

---

## 9. API contract acceptance tests

The acceptance suite must include these contract tests:

1. OpenAPI parses as OpenAPI 3.1 and includes every required operation ID.
2. Every operation declares security requirements unless explicitly local-dev-only.
3. Every mutating operation declares caller attribution and trace/audit semantics.
4. Every request and response used in use-case E2E tests validates against the OpenAPI schema.
5. Rust, Python, and TypeScript fixtures serialize canonical schemas with stable field names and enum values.
6. TypeScript client is generated from or parity-checked against the OpenAPI/canonical schemas.
7. Python SDK cannot expose direct side-effect execution that bypasses daemon/gateway enforcement.
8. `submitAction` contract explicitly routes through gateway and cannot self-attest verification.
9. Health/capabilities/telemetry schemas are marked non-authoritative for action/work-order/placement authorization.
10. Replay schema defaults to side effects disabled.
11. Physical action schema rejects forbidden low-level actuator classes.
12. Trace export requires redaction policy.
13. Work-order schema rejects unsigned, expired, revoked, incompatible, wrong-tenant, wrong-audience, or overbroad requests.
14. Message schema rejects unsupported schemas, unauthorized recipients, cross-tenant delivery, and permission/data-ref smuggling.
15. Backward-compatible schema evolution is tested with stable version markers and migration fixtures.

---

## 10. Blocking conditions

Block acceptance if any of these occur:

- An endpoint exists in the daemon or central manager but is missing from the contract.
- The contract documents an endpoint that has no passing executable test.
- A client uses a private handler or direct Rust helper for a scenario that claims API E2E coverage.
- A management credential can authorize an action without a valid work order and gateway verification.
- A communication endpoint can mutate remote state without typed message routing and trace linkage.
- A physical endpoint accepts low-level actuator commands.
- The API schema allows replay side effects by default.
- Generated Rust/Python/TypeScript schema parity fails.
