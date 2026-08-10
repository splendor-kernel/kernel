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
- Acquire combined runtime locks only in this order: trace cursor, writer
  lifecycle, then writer-session operation. Fresh distinct-agent admission and
  event append use that same order; no path may acquire the lifecycle and then
  wait for the cursor.
- Emit `TraceEvent` payloads via the configured sink.
- Expose the next trace sequence so new persisted runs can emit `RunStarted`
  exactly once before the first tick.
- Atomically admit one fresh engine for each exact tenant/agent identity and emit
  `RunStarted` once under the shared cursor lock. Distinct local agents may
  assemble against that same runtime before tick activity begins; a duplicate
  identity, reopened runtime, or already-active runtime is not fresh admission.
- Emit integrity metadata in `LoopTickCompleted` when available.
- Validate the complete storage-owned run/hash/previous-hash/sequence chain
  before initializing a cursor from persisted history.

**Methods**
- `new(config)` creates a runtime without emitting events.
- `with_trace_store(store, run_id)` initializes the cursor from the latest
  durable sequence/hash only after full-chain integrity validation. Call it once
  per resolved run in a composition, then share the returned runtime.
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
  emits into the same run stream. They require a runtime created through
  `KernelRuntime::with_trace_store`; a custom sink without the store-backed
  ownership boundary fails closed. Resume rejects a runtime whose `RunId`
  differs from the requested run before restoring state.
- Treat `with_trace_store*` and `with_shared_trace_runtime*` as fresh-run
  constructors. Persisted construction first acquires the store's exact
  `run_id + tenant_id + agent_id` live-owner claim. Fresh admission and the
  single `RunStarted` append then occur under one shared runtime cursor lock, so
  competing constructors cannot both become emitters. The rejected constructor
  appends nothing, and dropping the admitted engine releases its local claim.
  Constructors return fixed `run_already_exists` for a duplicate identity, when
  their runtime was reopened over persisted trace history, or after tick activity
  has begun. Distinct local agents may still assemble on the same runtime before
  its first tick; persisted recovery must use an explicit `resume_from_*`
  constructor.
- During resume, reject an action-capable tick attempt that lacks its matching
  completed-tick event. `ActionVerificationStarted` is the durable conservative
  boundary: loss of any later post-Gateway trace or state write cannot make the
  run runnable again without reconciliation.
- In a live tick, latch persistence denial immediately after
  `ActionVerificationStarted` becomes durable and retain a reconciliation block
  until the complete action/tick suffix reaches `LoopTickCompleted`. A Gateway
  denial or `NeedsApproval` result that proves no adapter entry does not clear
  this latch before the suffix is durable. A completed tick clears the transient
  latch only when its recorded action outcome does not independently require
  reconciliation.
- The Evidence owner validates action episodes even when direct or physical
  daemon actions have no tick identity. A complete tickless episode keeps one
  exact action identity and action body from `ActionVerificationStarted` through the matching
  `ActionVerificationCompleted`, a terminal action event, and the action-scoped
  strict `OutcomeRecorded`. It also retains immutable tick/direct/physical origin
  across approval continuation and returns a bounded fresh, complete,
  pending-approval, or reconciliation-required disposition. It does not replace
  the latest completed tick snapshot and is never re-executed during resume. An
  incomplete, malformed, source-substituted, illegally repeated, mismatched,
  duplicate, or effect-uncertain episode requires reconciliation.
  Direct/physical origins remain one-shot except for one endpoint-bound approval
  continuation. A tick origin may reuse the exact ID and action on a strictly
  later completed tick; an open tick challenge must first close through its one
  direct continuation. Resume shares this model and selects the latest completed
  target snapshot after legal repeated tick use.
  `ActionFailed` must carry explicit `adapter_entered: false` evidence, or
  `adapter_entered: true` with known effect certainty and
  `reconciliation_required: false`; missing or malformed effect facts fail
  closed.
  Tickless actions never fabricate state; a history with no completed snapshot
  remains snapshot-unavailable.
- Restore only a snapshot for the latest completed tick whose state node,
  snapshot metadata, and trace linkage bind the requested run, tenant, and agent.
  A latest completed tick without its own snapshot fails with
  `resume_latest_completed_snapshot_unavailable`; missing or mismatched identity
  metadata is a fixed resume failure, not a fallback to an older or sibling
  state.
- Validate every record in the complete run chain before parsing recovery events
  or loading a snapshot. Payload/hash/prior-hash mutation, deletion, reordering,
  insertion, or a record/event envelope identity mismatch returns a structured
  integrity error before policy, scheduler, state restoration, or adapter entry.
- Retain the highest exact-identity tick observed in all validated events, not
  only the latest completed tick. A strictly later tick may supersede an earlier
  incomplete attempt only when that attempt has no action order or
  `ActionVerificationStarted`, outcome, state commit, pending episode, or effect
  evidence. The superseded identity remains in the monotonic tick floor and
  cannot be reused. This permits an ordinary live-scheduler requeue before action
  start; an unsuperseded open attempt, or an attempt that crossed any of those
  boundaries, remains reconciliation-required.
- Evidence requires every completed target tick—including a tick with zero
  actions—to contain exactly one correctly ordered `OutcomeRecorded`, one later
  `StateCommitted`, and one later `LoopTickCompleted`. Missing, duplicate,
  orphaned, or misordered lifecycle events fail closed even when no adapter or
  effect boundary was entered. A safely superseded pre-action attempt is not a
  completed tick and therefore has no completion suffix. Missing or malformed
  effect-certainty facts fail closed rather than being inferred as no effect.
- If legacy state-node preparation succeeds but the required `StateCommitted`
  append fails, restore the process-visible prior graph head/tick and retain the
  prior engine state and agent head. The live engine latches reconciliation before
  returning the trace error, so a later tick cannot consume the untraced state.
  Because the compatibility `StateStore` and `TraceStore` remain separate, an
  immutable detached node/data/snapshot may remain in the state store; it is not
  current or returned as a successful commit. This is bounded local rollback and
  fail-stop behavior, not a cross-store atomicity or automatic-reconciliation
  claim.
- If `StateGraph::commit` itself fails at any store stage, including for a
  state-only tick with no adapter entry, latch persistence denial before returning
  the state error. The next direct tick is rejected and the scheduler parks the
  engine; no policy re-invocation through that live engine or scheduler may turn
  a partial state write into an implicit retry.
- If `StateCommitted` succeeds but the required `LoopTickCompleted` append fails,
  retain that durably traced state and live head, latch reconciliation, and return
  the completion append error. Do not roll the committed state back, and do not
  admit another live tick; restart treats the incomplete stateful tick as
  reconciliation-required.

`with_trace_store_and_work_order` and `resume_from_trace_store_with_work_order`
create their own runtime and remain suitable only when that loop is the sole
emitter for the run. Composition roots must own runtime reuse; stores persist
records and reject duplicate exact live identities, but they do not make
independently initialized cursors for different identities in one run composable.

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
start of each scheduler cycle. `try_add_agent` returns a typed
`DuplicateRuntimeIdentity` conflict when the exact run/tenant/agent identity is
already queued or parked. The compatibility `add_agent` method also fails closed
by declining duplicate admission. Admission raises the scheduler's tick floor to
the engine's highest validated durable tick before the next cycle begins.

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
