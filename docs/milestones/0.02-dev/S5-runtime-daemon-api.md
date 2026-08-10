# 0.02-S5 — Runtime daemon API

## Objective

Expose a minimal local daemon API that controls and inspects a Splendor runtime
without weakening the core loop: percepts, policy, constraints, gateway,
verifiers, adapter, outcome, state commit, and trace.

## Functional scope

- Added `crates/splendor-daemon`, a local-only Rust daemon crate and binary.
- Implemented endpoints for runs, percepts, state-head, trace read/export,
  replay, actions, health, version, and capabilities.
- Reused the 0.02-S0 daemon security validator for endpoint scope, work-order,
  audit attribution, and explicit insecure local dev mode checks.
- Added `StateStore::get_node` so state-head responses prove the node exists.
- Added integration tests for the local daemon workflow and required failures.

## Non-goals

- No remote node registry.
- No fleet scheduling.
- No production OAuth/OIDC/PKI implementation.
- No TypeScript client.
- No governance workflow engine.
- No distributed state migration or remote message transport.

## Public contracts changed

- New crate: `splendor-daemon`.
- New daemon endpoints documented in `docs/reference/runtime-daemon-api.md`.
- New OpenAPI file: `openapi/splendor-runtime-daemon.yaml`.
- Extended daemon scopes: `splendor.runs.start`, `splendor.runs.read`,
  `splendor.runs.pause`, and `splendor.runs.stop`.
- Added management-contract aliases for `cancelRun`, `getVersion`, and
  `exportTraces` without widening runtime authority: cancel uses the same stop
  scope, version is health/read-only metadata, and trace export still requires
  `splendor.traces.read` plus explicit redaction policy.
- Added trace event variants: `RunPaused`, `RunResumed`, `RunStopped`, and
  `PerceptsAppended`.
- Added `StateStore::get_node` and async equivalent.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Percept | Daemon append queue feeds normal tick percept collection. |
| Policy | No new policy semantics; daemon test policy is static/local. |
| Gateway | `/actions` and policy actions route through `VerifiedActionGateway`. |
| Verifier | Existing tenant/quota/precondition verifier path is preserved. |
| State graph | State-head reads verify committed node existence. |
| Trace store | Endpoints read ordered trace records; daemon lifecycle events are appended through the run runtime. |
| Replay | Inspect-only replay endpoint validates trace order and never calls adapters. |
| Message | None. |
| Work order | Create/resume require signed scoped work orders through S0 validation. |
| Governance | None. |

## Trace behavior

- `RunStarted` is emitted when a daemon run slot is created.
- `PerceptsAppended` records daemon percept acceptance before the next tick.
- Normal tick events remain ordered by `LoopEngine`.
- `RunPaused`, `RunResumed`, and `RunStopped` record local lifecycle transitions;
  `/runs/{run_id}/cancel` emits the same stop transition while preserving
  trace/state evidence.
- `/actions` records action verification, action result, and outcome events through
  the run's trace runtime.
- Trace pages are returned in store sequence order. Trace exports return the same
  ordered redacted records plus redaction-policy and projection-local integrity
  metadata computed from only the selected returned full/ranged records.
- `start` and `end` are independently optional half-open sequence bounds. Equal
  bounds return an empty range, reversed bounds reject, and each selected range
  is rechained from a local first record only after the complete trusted source
  history passes validation.

## State behavior

- Each start/resume tick commits a state node through `StateGraph`.
- The daemon tracks the latest `state_head` from the tick outcome.
- `GET /runs/{run_id}/state-head` calls `StateStore::get_node` before returning.
- State commit failure makes the tick fail; the daemon marks the run failed and
  returns a structured scheduler error.

## Gateway and verifier behavior

- `/actions` validates daemon security with `GatewayVerificationState::Required`.
- A caller token never authorizes a side effect by itself.
- Tenant action, adapter, permission, quota, and invariant checks run before
  adapter execution.
- Gateway denial returns an `ActionOutcome` with status `Denied`; the adapter is
  not executed.
- A caller-supplied action ID is a run-local durable retry identity. Exact
  completed retries, changed action/source reuse, and cross-node physical reuse
  all return the same non-retryable `action_id_conflict` without a second
  Gateway/adapter call, action episode, or stored outcome. Missing IDs remain
  fresh, and incomplete/ambiguous durable evidence closes admission for
  reconciliation. Evidence owns the strict episode/outcome/source/effect-certainty
  interpretation; daemon handlers combine only its bounded disposition with live
  status and run authority. Direct/physical origins permit only one endpoint-bound
  pending-approval continuation. Tick origins may reuse an exact ID/action on a
  strictly later completed tick only after any direct continuation closes.
  Tick/direct challenges use `/actions`, while physical origins use the original
  physical node endpoint. Source or node mismatch happens before a new episode,
  receipt claim, or adapter call.
  Original-response replay and provider/global/distributed/restart
  exactly-once behavior are not implemented.
- Raw-credential classification precedes duplicate/reservation disposition. A
  non-action-admissible run or static-policy-reserved caller ID receives only the
  fixed denial with no audit/action episode, history read, quota mutation, or ID
  consumption. Active requests with nonreserved IDs retain bounded fixed denial
  evidence without retaining caller-controlled action fields.
- Direct and run-bound physical requests use private per-run effect admission.
  Live contention returns retryable `action_in_progress` without closing
  authority. Durable history validation is bounded and occurs outside the run
  mutex. Concurrent tail movement receives three fresh-reader attempts, then
  retryable `action_history_changed`; temporary Store failure returns retryable
  `action_history_unavailable`. Both are pre-start and leave later admission
  available. Every Gateway outcome,
  including no-effect denial/approval/intervention, keeps admission closed until
  its complete required trace/status suffix is durable. Suffix failure blocks
  retries before Gateway with
  `tick_reconciliation_required`, lifecycle ticks consult the same guard, and
  shared live run authority closes. Reconciliation-required outcomes terminate
  the run without another adapter execution; ordinary durable denial releases
  admission only after status update when the run remains effect-capable.
  `NeedsApproval` leaves status `waiting_for_approval`, while
  `NeedsIntervention` leaves status `failed`.
- Pause shares that admission barrier: action-first makes pause conflict, while
  pause-first denies later direct/physical entry. Pause cannot suppress a
  concurrently admitted approval/intervention result.

## Replay behavior

- Replay mode is `inspect_only`.
- Replay reads persisted trace records and validates sequence continuity.
- Replay does not invoke perceptors, policies, gateways, verifiers, or adapters.
- A test asserts adapter execution count is unchanged after replay.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| `daemon_run_lifecycle_state_trace_and_replay_are_local_and_ordered` | End-to-end create/start/pause/resume/stop/inspect, percept ingestion, state-head, ordered traces, replay suppression | `cargo test -p splendor-daemon` |
| `action_endpoint_uses_gateway_and_returns_structured_denial` | Proves `/actions` routes through gateway and returns denied action outcome | `cargo test -p splendor-daemon` |
| `create_run_rejects_incompatible_and_duplicate_work_orders` | Work-order compatibility and duplicate local run rejection | `cargo test -p splendor-daemon` |
| `daemon_error_paths_cover_state_trace_lifecycle_scope_and_percepts` | State-head, trace redaction, percept allowlist, lifecycle, wrong-scope, and health error paths | `cargo test -p splendor-daemon` |
| `daemon_executes_allowed_actions_and_pages_trace_ranges` | Allowed action execution through the gateway and trace range reads | `cargo test -p splendor-daemon` |
| `completed_direct_and_physical_action_retries_return_uniform_conflict` | Completed stable-ID retries return a uniform conflict with one original action episode; a new ID remains usable | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests completed_direct_and_physical_action_retries_return_uniform_conflict` |
| `completed_action_credential_bearing_retry_is_denied_before_durable_disposition` | Credential-bearing retries cannot retrieve prior outputs or persist rejected metadata | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests completed_action_credential_bearing_retry_is_denied_before_durable_disposition` |
| `explicit_static_policy_action_ids_block_direct_and_physical_preemption` | Identical and changed raw direct/physical requests using a reserved policy ID return the same fixed denial with zero history/trace/action growth; the policy action then executes once and remains reusable on a later tick | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests explicit_static_policy_action_ids_block_direct_and_physical_preemption` |
| `same_id_in_flight_direct_and_physical_retries_are_retryable_without_reexecution` | Live same-ID contention returns retryable `action_in_progress`, does not re-enter the adapter, and does not poison later authority | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests same_id_in_flight_direct_and_physical_retries_are_retryable_without_reexecution` |
| `durable_action_history_scan_does_not_hold_the_run_mutex` | A blocked bounded history read does not block run inspection and returns deterministic live-admission conflict to lifecycle work | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests durable_action_history_scan_does_not_hold_the_run_mutex` |
| `percept_append_during_action_history_scan_retries_without_poisoning_the_run` / `transient_history_exhaustion_and_store_unavailability_release_action_admission` | Concurrent valid tail growth retries with a fresh reader; bounded exhaustion and pre-start Store unavailability return retryable errors without closing admission | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests action_history` |
| `reused_action_id_conflicts_on_changed_action_or_endpoint_source` / `omitted_action_id_remains_a_fresh_attempt` | Stable-ID action/source/cross-node conflicts and missing-ID fresh-attempt behavior | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests action_id` |
| `action_endpoint_traces_approval_lifecycles_without_adapter_bypass` / `physical_approval_uses_exact_one_use_receipt_and_never_legacy_grant` | Direct↔physical and cross-node approval continuation mismatch leaves the run waiting, opens no duplicate episode, claims no receipt, and permits one original-endpoint execution | `cargo test --locked -p splendor-daemon approval` |
| `post_effect_trace_failures_close_direct_and_physical_effect_admission` | `ActionExecuted`/`OutcomeRecorded` append failure after direct or physical adapter entry blocks exact retries without another adapter call | `cargo test -p splendor-daemon --test runtime_daemon_api_tests effect_admission` |
| `physical_offline_suffix_failure_requires_reconciliation` / `approval_resume_suffix_failure_requires_reconciliation` | Offline and approval/status trace failures before the final durable outcome remain reconciliation-required | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests suffix_failure_requires_reconciliation` |
| `credential_output_suppression_closes_direct_and_physical_effect_admission` | Suppressed adapter output fails the run and cannot re-enter direct or physical adapters | `cargo test -p splendor-daemon --test runtime_daemon_api_tests effect_admission` |
| `ambiguous_start_failure_quarantines_while_durable_denial_reopens_admission` / `prestart_drop_reopens_but_gateway_error_after_start_closes_admission` | Ambiguous durable start and Gateway-error RAII close admission, while deterministic pre-start drop and complete durable denial reopen it | `cargo test --locked -p splendor-daemon admission` |
| `post_start_failure_closes_admission_and_gateway_no_effect_outcome_completes_suffix` | Post-start pre-Gateway failure closes admission; a complete no-effect intervention suffix terminates deterministically without adapter entry | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests post_start_failure` |
| `no_effect_suffix_failures_close_direct_physical_and_lifecycle_admission` | Approval/intervention suffix failure after a no-effect Gateway outcome blocks later action and lifecycle effects | `cargo test -p splendor-daemon --test runtime_daemon_api_tests no_effect_suffix` |
| `no_effect_suffix_barrier_blocks_concurrent_action_and_lifecycle_calls` | Concurrent action/lifecycle calls cannot cross an incomplete no-effect suffix | `cargo test -p splendor-daemon --test runtime_daemon_api_tests no_effect_suffix` |
| `action_first_pause_conflicts_while_gateway_admission_is_active` / `pause_first_denies_later_direct_and_physical_actions` | Both pause/action orderings are deterministic and do not suppress terminal action status | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests pause` |
| `trace_read_export_and_replay_never_persist_raw_action_credentials` | Full/ranged export integrity equals the returned redacted projection tail and exposes no trusted source hash | `cargo test -p splendor-daemon --test runtime_daemon_api_tests trace_read_export_and_replay_never_persist_raw_action_credentials` |
| `trace_range_rejects_corruption_outside_the_selected_slice` | Range projection validates complete source history before selection | `cargo test --locked -p splendor-daemon --test runtime_daemon_api_tests trace_range_rejects_corruption_outside_the_selected_slice` |
| `structured_errors_cover_invalid_run_malformed_percept_and_unavailable_runtime` | Required structured error cases | `cargo test -p splendor-daemon` |
| `state_store_commits_and_snapshots` / `sqlite_store_persists_state` | `StateStore::get_node` in memory and SQLite | `cargo test --workspace` |

## Example or fixture

See `examples/daemon-client-local/README.md` for a local server smoke path and
request snippets. The reproducible integration path is:

```bash
cargo test -p splendor-daemon
```

## Future extension notes

- 0.02-S6 can target the documented HTTP/OpenAPI contract from TypeScript without
  implementing runtime semantics in TypeScript.
- Later fleet work can add authenticated transports and remote placement without
  changing the local gateway/state/trace/replay invariants.
- A future resident scheduler can widen lifecycle behavior beyond one tick per
  start/resume while preserving the same endpoint names.
