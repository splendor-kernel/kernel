# UC-E2E-S10 — Final Cross-Component Acceptance Journey

## Objective

Validate the final `0.1-dev` use-case acceptance journey after prior UC-E2E scenarios pass. UC-E2E-S10 strengthens the SDK/API, work-order, fleet identity, message, action gateway, verifier, adapter, state graph, trace store, approval/governance, physical/edge, replay, and docs/tests primitives by proving they work together through documented public boundaries.

## Functional Scope

- Adds `tests/e2e/use-cases/scenarios/uc_e2e_s10_final_journey/run.py` as the S10 scenario runner.
- Runs after S1-S9 when invoked directly and as part of `--all`.
- Uses public manager, verified-TLS resident daemon, edge-device, device simulator, `splendorctl work-order sign`, contract, trace/state export, telemetry, governance audit, and replay surfaces.
- Mints a fresh one-scope, target-instance bearer for every resident request, mirrors only the verified credential/audit projection, and rejects any mutating JTI reuse in fixture evidence. Credentialed resident clients use CA-verified HTTPS with an explicit no-redirect opener; a 3xx is returned as an error response and cannot forward the bearer to another origin or plaintext URL.
- Mints a separate fresh one-scope, fleet-bound bearer for every manager approval mutation. Its exact manager audience, verified credential/audit mirrors, and one-use JTI are checked before any approval/audit mutation or receipt issuance.
- Signs each VPC, cloud, and edge work-order envelope with the corresponding acceptance instance key; command/evidence artifacts redact signing secrets and never admit the local-development work-order key.
- Reuses the canonical S4 node/instance registrations and refreshes both node and instance health without changing immutable identity metadata.
- Splits internal artifact creation and external publication into separate exact action/adapter/permission profiles. The manager submits and dispatches both signed work orders to the selected VPC resident; the publish-only run has one exact policy action and approval policy, pauses with an exact challenge, then retries that exact action through canonical `POST /actions` with one manager-issued authority obligation receipt. The publish retry does not call the lifecycle resume endpoint. Data-analysis and specialist profiles retain manager dispatch through the canonical `sql.read_fixture` placement capability.
- Uses the shared `physical.high_level` permission with the bounded action allowlist and `device-sim` adapter instead of per-action physical permissions.
- Syncs the edge trace buffer through the resident device reconnect boundary. The fixture does not resubmit redacted edge export records or rewrite their integrity hashes; the central manager's rejection of that redacted batch is retained alongside successful central VPC/cloud aggregation.
- Uses the dedicated one-use `splendor.device.trace_sync` resident scope and
  proves resident payload-tamper and cross-run trace batches are rejected with
  zero accepted records.
- Requires machine-readable evidence for API contract status, topology hash, resident TLS/bearer security, exact authority profiles, signed work-order placement, data-local analysis, typed specialist response, proposal-only cloud helper, bounded edge inspection, approval-gated publication, state-handoff export plus fail-closed resident import with unchanged receiver state, receiver resume from its own state, central trace aggregation, replay/audit, controlled negative branches, anti-drift results, and FR/primitive coverage. The publication evidence retains the admitted policy action, exact challenge, manager request/grant, one redacted authority obligation receipt projection, one receipt-bearing action response, public run inspections, and ordered traces. `resident-security.json` contains one token-free event per resident call with operation, method, exact/presented scope, credential correlation ID, audience, URL scheme, safe header-presence facts, body-mirror status, redirect policy, result status, and response/audit correlation or an explicit unavailable reason. `manager-approval-auth.json` independently records only token-free manager audience/fleet/scope, mirror, one-use, response, and audit/receipt correlation facts. Retained summaries and API traffic must not contain bearer bytes, raw JTI bytes, or unredacted authority-receipt signatures.
- Updates report aggregation so S10 remains failed unless required artifacts, IDs, events, positives, negatives, replay suppression, and coverage matrix evidence are present. Aggregate security status and counts are independently recomputed from every event and matching API-traffic row; top-level summary booleans are consistency checks, not authority. The AUTH-004c publish check is also derived independently: exactly one evidence operation labeled `submitApprovedExactAction` must map to canonical public `POST /actions`, preserve all admitted action fields, carry exactly the manager-issued receipt and no raw approval evidence, return an executed and obligation-satisfied response, execute once without advancing the tick or state head, emit `action.executed` before post-effect `run.resumed`, and make no publish-run lifecycle resume call. Separate checks derive active-run raw-evidence rejection and revoke-before-claim/claim-before-revoke outcomes from ordered API traffic, run/state inspections, resident acknowledgement evidence, and adapter traces.

## Non-Goals

- No real customer data, robot, drone, cloud service, database, or external artifact publisher.
- No enterprise SaaS UI, marketplace, billing, or approval product workflow.
- No production OAuth/PKI, Kubernetes rollout, full distributed consensus, or universal shared memory.
- No direct actuator, motor, firmware-safety-bypass, or hard real-time robotics control.
- No replay side effects by default.
- No private helper-only path for acceptance evidence.

## Public Contracts Changed

- `bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10` is accepted.
- `bash scripts/e2e/verify-use-case-acceptance.sh --all` includes S10.
- S10 writes acceptance artifacts under `target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S10/`.
- Resident fixture scopes add the schema-aligned `runs_pause` and `policies_sync` mappings needed by S10's pause and circuit-breaker synchronization calls. `traces_read` is the exact scope for both `GET /runs/{run_id}/traces` and trace export. `runs_resume` remains the exact scope for the separate state-handoff receiver resume and is not used for approval-gated publication.
- The acceptance manager registration boundary now treats identical duplicate node/instance registration requests as idempotent success while still rejecting incompatible duplicate metadata; this lets S10 run after prerequisite scenarios without counting duplicate rejection as success.
- Message read/list/causal-graph and ack/nack OpenAPI request schemas now require explicit non-null tenant/run/agent scope for the acceptance caller path; no broad fleet-admin message-read path is introduced.

## Runtime Primitive Impact

| Primitive | Impact |
| --- | --- |
| Work order | validates per-instance signed, exact-profile work orders and invalid unsigned work-order rejection |
| Fleet/node identity | validates node and instance registration, capabilities, placement, dispatch, telemetry, and audit attribution |
| Message | validates typed specialist task request/response and cloud-helper proposal messages with duplicate non-double-apply evidence |
| Gateway/verifier/adapter | validates data, artifact, governance, and device actions remain mediated by public gateway/API calls |
| State graph | validates explicit export, a cloud-signed receiver envelope used unchanged for create/import/resume, resident proof-unavailable denial before mutation, unchanged receiver state, and resume from the receiver's own state |
| Trace store | validates central trace aggregation, required event IDs, tamper rejection, and trace/state export paths |
| Approval/governance | validates exact challenge recording, manager-issued obligation receipt correlation, exact `POST /actions` retry without raw grant or lifecycle resume, post-effect run resume, active raw-evidence rejection, acknowledged resident receipt revocation, claim/revoke race results, expired approval denial, circuit breaker, kill switch, and audit export |
| Physical/edge | validates high-level bounded inspection through the simulator and raw physical action rejection |
| Replay | validates inspect-only replay and unsafe side-effect replay rejection without changing public counters |

## Required Trace/Audit Behavior

S10 requires evidence for:

- `work_order.accepted`
- `placement.evaluated`
- `data_scope.verified`
- `message.sent`
- `message.received`
- `cloud_helper.proposal.received`
- `safety.verification.completed`
- `action.executed`
- `action.denied`
- `action.needs_approval`
- `approval.granted`
- `approval.revoked`
- `artifact.created`
- `artifact.publish.executed`
- `state.committed`
- `state.exported`
- `run.resumed`
- `trace.sync.completed`
- `replay.explained`
- `governance.audit.exported`
- `circuit_breaker.tripped`
- `kill_switch.activated`

The report aggregator rejects missing event IDs, non-UUID event IDs, required event IDs not backed by exported trace records, manager audit records, or public API response evidence, and evidence rows that lack S10 run/work-order/message/node/instance/governance correlation. For the approval-gated publish it additionally requires one matching `action.executed` followed by a post-effect `run.resumed`, with no second tick, state-head advance, duplicate execution, raw approval evidence, changed receipt binding, or publish-run lifecycle resume.

## Controlled Negative Branches

S10 includes independent negative branches for invalid work order, unauthorized data ref, specialist permission escalation including nested delegated-authority smuggling, duplicate remote delivery, unsupported/omitted-scope/cross-tenant/unrelated-agent message API access, unauthorized ack/nack attempts, raw physical action, expired approval, circuit-breaker blocked publish, kill-switch cancellation, resident trace payload tamper/cross-run batches with zero accepted records, tampered central trace/state import, and unsafe replay mode.

## Replay Behavior

- Replay mode is `inspect_only`.
- `side_effects_allowed_default` is `false`.
- Unsafe side-effect replay is rejected.
- Public daemon adapter counters and device simulator counters must not change across replay.

## Tests and Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| integration | Run final field-intelligence journey | `scenario-report.json`, `journey-report.json`, `registry-report.json`, `resident-security.json`, `authority-profiles-report.json`, `api-traffic.ndjson` |
| security negative | Prove resident redirects cannot receive bearer credentials | `tests/e2e/use-cases/fixtures/test_resident_http.py` (cross-origin and HTTPS-to-HTTP redirect capture fixtures) |
| message | Prove typed specialist/cloud helper causality | `message-flow.json`, `manager-audit-export.json` |
| governance | Prove authenticated approval/circuit-breaker/kill-switch branches and independently derived exact receipt retry, raw rejection, and receipt revocation semantics | `artifact-publication-report.json`, `approval-receipt-revocation-report.json`, `resident-security.json`, `api-traffic.ndjson`, `trace-export.jsonl`, `governance-branches.json`, `manager-approval-auth.json`, reporting unit mutation tests |
| physical/edge | Prove bounded simulator execution and raw-action denial | `edge-inspection-report.json` |
| state/trace | Prove export, resident proof denial without receiver mutation, receiver-own-state resume, trace sync, and tamper rejection | `state-handoff-report.json`, `trace-sync-report.json`, `trace-export.jsonl`, `state-export.json` |
| replay/audit | Prove no replay side effects and explainability | `replay-report.json`, `audit-package.json`, `audit-report.json` |
| coverage | Prove FR and primitive coverage | `fr-primitive-coverage-matrix.json`, `anti-drift-results.json` |

## Example

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

## Future Extension Notes

- S10 intentionally uses deterministic fixture services and simulated device behavior.
- Resident work-order v1 fixture keys demonstrate target-instance sibling isolation with shared secrets, not asymmetric issuer/verifier separation.
- Resident state import remains truthfully fail-closed with `state_handoff_proof_unavailable`; S10 does not claim cross-instance state import success.
- Any future replacement with real external systems must remain separately gated, authenticated, scoped, trace-linked, and safe for replay.
