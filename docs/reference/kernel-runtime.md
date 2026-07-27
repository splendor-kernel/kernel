# Kernel Runtime

The kernel runtime is a lightweight execution context used to emit ordered trace
records. It owns a `RunId`, a monotonic sequence counter, and a trace sink.

## KernelRuntimeConfig

**Fields**
- `trace_sink` (`Arc<dyn TraceSink>`): destination for serialized trace events.
- `run_id` (`Option<RunId>`): optional run identifier to resume or reuse.
- `initial_sequence` (`u64`): initial event sequence counter.
- `initial_prev_hash` (`Option<ContentHash>`): integrity chain seed.

`KernelRuntimeConfig::default()` uses `StdoutTraceSink`.

## KernelRuntime

**Responsibilities**
- Assign a `RunId` to the runtime instance.
- Track event sequence numbers.
- Serialize every emitter for one run through one shared trace cursor. A process
  composition must reuse the same `Arc<KernelRuntime>` for all loop, gateway,
  and agent emitters that resolve to the same `RunId`; independently initialized
  runtimes for one run are invalid because their persisted cursors can race or
  become stale.
- Emit `TraceEvent` payloads via the configured sink.
- Expose the next trace sequence so new persisted runs can emit `RunStarted`
  exactly once before the first tick.
- Atomically admit one fresh persisted run owner and emit `RunStarted` under the
  shared cursor lock. Additional local agents may assemble against that same
  runtime before tick activity begins; a reopened or already-active runtime is
  not fresh admission.
- Emit integrity metadata in `LoopTickCompleted` when available.

**Methods**
- `new(config)` creates a runtime without emitting events.
- `with_trace_store(store, run_id)` initializes the cursor from the latest
  durable sequence/hash. Call it once per resolved run in a composition, then
  share the returned runtime.
- `boot(config)` creates a runtime and emits `LoopTickStarted`.
- `record_event(kind)` serializes and emits a `TraceEvent`.
- `record_event_with_identity(identity, kind)` uses the same cursor while
  retaining the emitting tenant/agent/tick/action identity and rejects a
  different run identity.

## TraceSink

`TraceSink` is the synchronous interface for recording events:
```
fn record(&self, event: &TraceEvent) -> Result<(), TraceError>
```

`AsyncTraceSink` provides an async-friendly equivalent using a future.

### StdoutTraceSink

`StdoutTraceSink` encodes events as JSON and writes to stdout. It implements
both `TraceSink` and `AsyncTraceSink`.

### TraceError

`TraceError::Serialization` is returned when JSON encoding fails.

## Tenancy and Quotas

`TenantContext` captures tenant policy, quotas, and the mutable usage ledger that
records consumption per tick. Use `TenantContext::verify_action` to evaluate
allowlists and required permissions before execution.

### TenantPolicy

**Fields**
- `allowed_actions` (`Vec<String>`): action names permitted for the tenant.
- `allowed_adapters` (`Vec<String>`): adapter identifiers the tenant can use.
- `allowed_permissions` (`Vec<String>`): permission tokens granted to the tenant.

**Behavior**
- Allowlists are enforced strictly (empty lists deny access).
- `TenantPolicy::verify_action` returns a `VerificationResult` with reason codes:
  `action_not_allowed`, `adapter_not_allowed`, and `permission_denied`.
- `TenantPolicy::constrain_to_work_order` narrows allowlists to the intersection
  of tenant policy and validated work-order authority. It never broadens tenant
  permissions.

### QuotaPolicy

**Fields**
- `max_actions_per_tick` (`Option<u32>`): per-tick action cap.
- `max_action_duration_ms` (`Option<u64>`): maximum per-action duration.
- `filesystem` (`AdapterQuota`): filesystem read/write budgets per tick.
- `network` (`AdapterQuota`): network read/write budgets per tick.
- `max_http_requests_per_minute` (`Option<u32>`): HTTP request rate limit.

### AdapterQuota

**Fields**
- `max_read_bytes` (`Option<u64>`): read budget per tick.
- `max_write_bytes` (`Option<u64>`): write budget per tick.

### QuotaUsage

**Fields**
- `actions` (`u32`): actions counted for a tick.
- `action_duration_ms` (`u64`): duration in milliseconds for the action.
- `filesystem_read_bytes` (`u64`): bytes read from filesystem adapters.
- `filesystem_write_bytes` (`u64`): bytes written via filesystem adapters.
- `network_read_bytes` (`u64`): bytes read via network adapters.
- `network_write_bytes` (`u64`): bytes written via network adapters.
- `http_requests` (`u32`): HTTP requests issued.

`TenantContext::record_usage` consumes `QuotaUsage` to enforce policies.
`QuotaPolicy::constrain_to_work_order` narrows each quota field to the smaller of
tenant and work-order limits when both are present; missing work-order limits do
not increase tenant quotas.

### AgentContext

**Fields**
- `agent_id` (`AgentId`): agent identifier.
- `tenant_id` (`TenantId`): owning tenant identifier.
- `interpreter_handles` (`Vec<String>`): interpreter handles assigned to the agent.
- `state_head` (`Option<StateNodeId>`): current state graph head.
- `config` (`AgentRuntimeConfig`): agent runtime configuration.

### AgentRuntimeConfig

**Fields**
- `label` (`Option<String>`): human-friendly agent label.
- `metadata` (`HashMap<String, String>`): additional tags.

### QuotaLedger

**Responsibilities**
- Reset per-tick counters with `begin_tick`.
- Record action usage via `record_usage` and emit `VerificationResult`.

### TenantRegistry

`TenantRegistry` stores tenant contexts for schedulers and gateways. It exposes
`begin_tick` to reset quotas across tenants and implements `TenantAccess` for
permission and quota verification.

## Scheduler and Loop Engine

`LoopEngine` executes a single agent tick and emits the ordered trace events for
run start, percepts, state load, policy decisions, verification, outcomes, and
state commits.

### LoopEngine

**Responsibilities**
- Collect percepts from registered `Perceptor` implementations.
- Record the loaded state hash before policy execution.
- Invoke the `Policy` callback to propose actions and next state.
- Evaluate constraints via the `ConstraintEngine`.
- Verify actions via gateway verifiers (`TenantAccess` + invariants) and record quotas.
- Execute actions through an `ActionGateway` implementation.
- Record `OutcomeRecorded` and `StateCommitted` events.
- Record `WorkOrderAccepted` after `RunStarted` when constructed with a validated
  work order via `with_trace_store_and_work_order` or
  `resume_from_trace_store_with_work_order`.
- Accept an existing shared runtime via
  `with_shared_trace_runtime_and_work_order` or
  `resume_from_shared_trace_runtime_and_work_order`. These constructors are
  required when a gateway pre-effect evidence recorder or another local agent
  emits into the same run stream. Resume rejects a runtime whose `RunId` differs
  from the requested run before restoring state.
- Treat `with_trace_store*` and `with_shared_trace_runtime*` as fresh-run
  constructors. Fresh admission and the single `RunStarted` append occur under
  one shared runtime lock, so competing constructors cannot both become fresh
  owners. They return fixed `run_already_exists` when their runtime was reopened
  over persisted trace history or tick activity has begun. Multiple local agents
  may still assemble on the same runtime before its first tick; persisted recovery
  must use an explicit `resume_from_*` constructor.
- During resume, reject an action-capable tick attempt that lacks its matching
  completed-tick event. `ActionVerificationStarted` is the durable conservative
  boundary: loss of any later post-Gateway trace or state write cannot make the
  run runnable again without reconciliation.
- Restore only the latest completed state whose state node, snapshot metadata,
  and trace linkage bind the requested run, tenant, and agent. Missing or
  mismatched identity metadata is a fixed resume failure, not a fallback to a
  shared run's latest sibling state.

`with_trace_store_and_work_order` and `resume_from_trace_store_with_work_order`
create their own runtime and remain suitable only when that loop is the sole
emitter for the run. Composition roots must own runtime reuse; stores persist
records but do not arbitrate multiple stale in-process cursors.

**Key Types**
- `ActionCandidate`: action proposal plus adapter, quota usage, and satisfied preconditions.
- `PolicyDecision`: actions plus `StateData`/`StateMetadata` for commits.
- `TickOutcome`: action outcomes, state commit, tick duration, and `needs_intervention`.

### Perceptor

`Perceptor::collect(agent)` returns a list of `Percept` values for the tick.

### Policy

`Policy::decide(state, percepts)` returns a `PolicyDecision` for the tick. Use
`Policy::name()` to populate the trace `PolicyInvoked` event.

### ConstraintEngine

`ConstraintEngine::evaluate(state, percepts, actions)` returns a
`ConstraintEvaluation` containing evaluated constraints and a `VerificationResult`.

### OutcomeEvaluator

`OutcomeEvaluator::evaluate(action, outcome)` returns optional `Feedback` and
`Reward` signals captured in `OutcomeRecorded`.

### Scheduler

`Scheduler` executes loop engines in a fair queue and resets tenant quotas at the
start of each scheduler cycle.

**SchedulerConfig**
- `tick_budget` (`Option<Duration>`): optional per-tick time budget.
- `tick_interval` (`Option<Duration>`): optional pacing interval per scheduler cycle.

**SchedulerStep**
- `tick_id` (`u64`): scheduler tick identifier.
- `agent_id` (`AgentId`): executed agent.
- `outcome` (`TickOutcome`): loop output.
- `elapsed` (`Duration`): wall-clock tick duration.

## Example

```rust
use splendor_kernel::{KernelRuntime, KernelRuntimeConfig, TraceEventKind};

let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
let event = runtime
    .record_event(TraceEventKind::LoopTickCompleted {
        tick_id: 1,
        integrity: None,
    })
    .expect("record event");
assert_eq!(event.sequence, 0);
```
