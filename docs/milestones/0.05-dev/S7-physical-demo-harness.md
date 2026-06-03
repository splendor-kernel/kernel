# 0.05-S7 — Physical demo harness

## Objective

Provide a runnable, contract-focused physical simulation harness that proves the 0.05 physical/edge primitives work together without live hardware and without implying production robot readiness.

## Functional scope

- Adds a physical simulation harness in `crates/splendor-kernel/tests/unit/physical_simulation_harness_tests.rs`.
- Validates a `DeviceProfile` and physical capability document before scenarios run.
- Routes high-level robotics actions through `VerifiedActionGateway`, `SimulatedSafetyVerifier`, and `SimulatedRoboticsAdapter`.
- Exercises offline policy cache behavior, local trace buffer reconnect sync, operator intervention, and cloud-helper local validation.
- Produces replayable `TraceEvent` records and explicit in-memory state graph commits/final state heads.

## Non-goals

- No production robot deployment.
- No live flight testing, ROS integration, native device drivers, motor control, or firmware control.
- No certification or hardware-readiness claim.
- No plugin framework or hardware adapter discovery system.

## Public contracts changed

- No public runtime/schema contract changes.
- Adds `splendor-adapter-robotics` as a `splendor-kernel` dev-dependency for scenario tests.
- Adds example docs under `examples/physical-simulation-harness/`.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Percept | none |
| Policy | validates offline policy-cache decisions |
| Gateway | exercises existing gateway boundary |
| Verifier | exercises safety verifier denial/intervention |
| State graph | commits final scenario state heads |
| Trace store | writes replayable trace events and offline sync metadata |
| Replay | inspects trace records only; no adapter/helper execution |
| Message | traces helper proposal message delivery |
| Work order | validates helper authority pattern indirectly through proposal/local validation |
| Governance | uses intervention outcome/request flow, no workflow engine |

## Trace behavior

- Uses existing trace event kinds only: `ActionVerificationStarted`, `ActionVerificationCompleted`, `ActionExecuted`, `ActionDenied`, `ActionNeedsIntervention`, `OutcomeRecorded`, `StateCommitted`, `OfflineTraceIntervalStarted`, `OfflineTraceIntervalEnded`, `PolicyConnectivityChanged`, `RemoteMessageSent`, and `MessageDelivered`.
- No demo-only trace format is introduced.
- Offline reconnect sync uses existing `TraceSyncBatch` metadata and central index deduplication.

## State behavior

- Each scenario commits an in-memory state graph node with tenant, agent, and run metadata.
- The final state head is obtained from `InMemoryStateStore`; the tests do not fake state head strings.
- State commits emit `StateCommitted` with the node data hash and snapshot ID.

## Gateway and verifier behavior

- All robotics actions are submitted to `VerifiedActionGateway` with `SimulatedSafetyVerifier` installed.
- `SimulatedRoboticsAdapter` is called only after gateway policy, quota, physical action boundary, and safety verification pass.
- Safety denial and forbidden low-level action scenarios assert no adapter execution.
- Disconnected high-risk movement returns `NeedsIntervention` through `PolicyDistributionGateway` before adapter execution.

## Replay behavior

- Replay reconstructs scenario behavior by reading serialized `TraceEvent` records from `LocalTraceBuffer`/`TraceStore`.
- Replay does not call the cloud helper, gateway, safety verifier, or robotics adapter.
- The replay proof is inspect-only and validates event presence/orderability plus final state head existence.

## Failure behavior

- Battery-below-minimum denies movement before adapter execution.
- Unknown collision risk returns `ActionNeedsIntervention` before adapter execution.
- Forbidden low-level physical action (`set_motor_pwm`) is denied and is absent from successful executed actions.
- Unsafe cloud-helper route proposals produce denial trace and no bounded local action.
- Offline duplicate reconnect batches are deduplicated by the central trace index.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| `physical_harness_successful_mission_uses_only_high_level_actions` | successful mission and forbidden action denial | gateway traces, executed high-level actions only, state head |
| `physical_harness_safety_denial_never_reaches_adapter` | safety verifier denial | `ActionDenied`, adapter call count `0`, state head |
| `physical_harness_offline_interval_syncs_without_duplicates` | offline interval and reconnect trace sync | offline trace events, central sync metadata, duplicate count |
| `physical_harness_operator_intervention_then_override_request_is_traced` | same-run intervention/override flow | ordered `ActionNeedsIntervention` before executed `request_operator_override`, final state includes both statuses, replay has no adapter calls |
| `physical_harness_cloud_helper_proposal_is_locally_validated_before_action` | cloud-helper proposal local validation | remote message trace, local validation, safe action, unsafe denial |

Run the focused harness tests:

```bash
cargo test -p splendor-kernel physical_harness --no-default-features
```

## Example or fixture

- `examples/physical-simulation-harness/README.md`
- `examples/physical-simulation-harness/scenarios.md`

## Future extension notes

The harness keeps simulation-specific status snapshots and adapters at the boundary. Later physical/edge work can replace `SimulatedRoboticsAdapter` and `SimulatedSafetyVerifier` with real bounded middleware integrations while preserving gateway submission, verifier results, trace events, state commits, and replay inspection.
