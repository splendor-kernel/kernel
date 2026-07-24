# Splendor Full Use-Case E2E Acceptance Sprint Pack

**Date:** 2026-06-02
**Status:** Proposed post-implementation acceptance rule pack
**Intended repository placement:** `docs/rules/verifiable_criteria/use-case-e2e-through-0.1.md`
**Execution timing:** Run after the implementation sprints for `0.01-dev` through `0.1-dev` are complete.
**Coverage target:** full use-case validation, not MVP smoke coverage.
**Primary companion files:**

- [`docs/reference/management-communication-api-acceptance-contract.md`](../../reference/management-communication-api-acceptance-contract.md)
- [`docs/development/containerized-use-case-e2e-harness.md`](../../development/containerized-use-case-e2e-harness.md)

**Resident approval amendment status:** The raw-evidence, physical binding,
target-resident receipt audience, and acknowledged revocation criteria added on
2026-07-15 are required contract targets. They are not passing or implemented
until the corresponding code, public contracts, and retained E2E evidence land.

This pack defines acceptance-level use-case sprints for Splendor. The tests are intentionally neither toy smoke tests nor sprawling product demos: each sprint validates one bounded, realistic runtime use case while exercising the real Splendor kernel boundaries, public API/client paths, state graph, trace store, gateway, verifiers, replay, governance, fleet, and physical/edge safety surfaces that exist by the end of the implementation milestones.

The suite must be treated as a **post-implementation acceptance gate**. Sprint-local tests can prove isolated implementation behavior; this pack proves that the completed product direction still holds when all components are used together.

---

## 1. Product-direction guardrail

Every use-case sprint must preserve this product direction:

Splendor is a **kernel-grade runtime substrate for governed autonomous agent loops**. It runs in user space on Unix-like systems, keeps Unix as the host OS, and standardizes/runtime-enforces identities, state graph commits, append-only trace events, verified action boundaries, quotas, policies, constraints, messages, work orders, approvals, fleet execution, and replay. Python and TypeScript are ergonomic/client surfaces; Rust remains the enforcement owner for runtime-critical behavior.

The governed loop remains the acceptance-test spine:

```text
Percepts
  -> Policy
  -> Constraints
  -> Action Gateway
  -> Verifiers
  -> Adapter
  -> Outcome
  -> State Commit
  -> Trace
```

### Hard anti-drift boundaries

The acceptance suite must fail if it observes any of the following:

- a side-effectful action executes without the action gateway;
- a required verifier is skipped, unavailable-but-allowed, or silently converted to allow;
- a trace write failure allows a side effect to continue without a fail-closed outcome;
- state changes that affect runtime behavior occur without a state node commit or state reference;
- replay executes filesystem, HTTP, shell, database, artifact-publish, webhook, robot/device, or other side-effectful adapters by default;
- tenant, agent, run, tick, action, state, trace, message, work-order, approval, fleet, node, or instance IDs are overloaded;
- a shared/specialist agent inherits broad caller permissions instead of scoped delegated authority;
- daemon, sidecar, SDK, CLI, central manager, adapter, or control-plane calls are accepted as anonymous callers outside explicit local development mode;
- a daemon API token is treated as permission to execute arbitrary agent actions;
- raw `ApprovalEvidence` reaches a gateway, runtime trace, or lifecycle mutation
  outside the exact stored `WaitingForApproval` `/actions` denial/expiry/
  revocation exception, or a raw grant pauses or authorizes an active run;
- a secure resident approval receipt is not bound to exact target `InstanceId`
  plus `RunId`, or a physical approval digest accepts a caller-supplied node/
  resource coordinate;
- a manager reports post-grant approval revocation success without an
  authenticated exact-target resident acknowledgement from the authority-owned
  atomic claim/revoke ledger;
- a health, capabilities, telemetry, or placement response becomes authority to run or act;
- a physical/edge adapter accepts raw motor writes, firmware safety bypasses, hard real-time control, or low-level actuator commands as Splendor direct actions;
- tests validate a chat-first agent UX, enterprise SaaS admin product, marketplace, broad low-code builder, universal distributed memory, or bare-metal OS direction as if it were Splendor kernel scope.

---

## 2. Definition of a complete use-case E2E sprint

A use-case E2E sprint is complete only when all of these are true:

1. **Containerized reproducibility:** the use case runs from a clean checkout through the standard Docker Compose acceptance topology, without undocumented host setup.
2. **Public-boundary execution:** the test drives Splendor through documented public surfaces: daemon API, CLI, Python SDK, TypeScript client, OpenAPI-derived contract checks, fleet manager API, or adapter interfaces. It must not call private Rust helpers to claim end-to-end correctness.
3. **Real enforcement path:** all proposed actions go through the real action gateway and required verifier chain. Boundary fakes may simulate external services, but gateway, verifier, state, trace, replay, message, work-order, and governance contracts must not be mocked away.
4. **Positive, negative, and replay paths:** every use case proves at least one successful path, at least one denial/fail-closed path, and replay/audit behavior with side effects suppressed by default.
5. **Trace and state evidence:** the evidence report contains run IDs, tick IDs, action IDs, state node IDs, state hashes, trace event IDs, governance IDs, work-order IDs, node/instance IDs, and message IDs relevant to the scenario.
6. **API contract validation:** every management or communication API request/response used in the scenario validates against the exposed OpenAPI/schema contract and generated Rust/Python/TypeScript types where available.
7. **Anti-drift assertions:** each test includes explicit assertions that the use case did not rely on non-goals, insecure shortcuts, telemetry-as-authority, direct adapter calls, hidden state, or replay side effects.
8. **Evidence quality:** the sprint produces machine-readable and human-readable artifacts suitable for management review, security review, and implementation review.

---

## 3. Standard acceptance entry point

The final aggregate gate must expose one stable command:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

The script must run the containerized topology:

```bash
docker compose   -f tests/e2e/use-cases/docker-compose.acceptance.yml   up --abort-on-container-exit --exit-code-from e2e-runner
```

The aggregate command must produce:

```text
target/splendor-e2e/use-case-acceptance/report.json
target/splendor-e2e/use-case-acceptance/report.md
target/splendor-e2e/use-case-acceptance/artifacts/
```

A green test process without the evidence report is an incomplete acceptance run.

---

## 4. Required container topology

The acceptance topology should be deterministic and local-first. It may use fake external services, but those fakes must sit beyond Splendor adapter boundaries and must never replace the gateway, verifier chain, state graph, trace store, or daemon API.

| Container/service | Purpose | Must exercise |
| --- | --- | --- |
| `e2e-runner` | Runs Rust tests, Python tests, TypeScript tests, OpenAPI checks, CLI flows, report aggregation, and anti-drift scans. | `cargo test`, `pytest`, `npm test`, `splendorctl`, OpenAPI validation, evidence aggregation. |
| `splendor-daemon-local` | Local runtime daemon for run lifecycle, percept append, action submission, traces, state-head, replay, health, capabilities. | Management API, action gateway, state graph, trace store, replay, local adapters. |
| `central-manager` | Minimal fleet/control manager for node registration, work-order dispatch, policy distribution, kill-switch/circuit-breaker propagation, telemetry aggregation. | Fleet management API, signed work orders, placement, governance distribution. |
| `resident-cloud-node` | General compute node. | Node/instance identity, remote run execution, trace sync, remote messaging. |
| `resident-vpc-node` | Data-local node. | Data-local placement, data refs, scoped permissions, artifact creation. |
| `resident-edge-node` | Edge/physical runtime target. | Offline policy cache, local trace buffer, device profile, safety verifiers. |
| `acceptance-action-provider` | Controlled receipt-bearing provider beyond the acceptance-host adapter boundary. | Data/artifact fixture effects, high-level physical actions only, deterministic failures, receipt/read-only observations, and no direct actuator authority. |
| `fake-http-service` | Controlled external HTTP endpoint. | HTTP adapter allowlist/denylist, quota, retry, failure outcomes. |
| `fake-governance-plane` | External approval/control-plane simulator. | Approval request/grant/deny/expiry/revocation without owning runtime internals. |
| `fake-telemetry-sink` | Receives telemetry snapshots. | Non-authoritative telemetry, fleet health, trace-sync status. |
| `toxiproxy` or equivalent fault proxy | Deterministic transport failures and latency. | Remote message failures, trace sync retries, bounded retry behavior. |
| `e2e-volume-state` | Shared persistent volume scoped to the compose project. | SQLite/state snapshots, trace exports, report artifacts. |

---

## 5. Evidence report contract

The report must be machine-readable JSON with a stable schema. At minimum:

```json
{
  "suite_id": "splendor-use-case-e2e-through-0.1",
  "suite_version": "0.1",
  "source_revision": "<git-sha-or-source-id>",
  "started_at": "2026-06-02T00:00:00Z",
  "completed_at": "2026-06-02T00:00:00Z",
  "container_topology_hash": "sha256:...",
  "api_contract_versions": {
    "openapi": "0.1",
    "rust_crates": "0.1.x",
    "python_sdk": "0.1.x",
    "typescript_client": "0.1.x"
  },
  "scenarios": [
    {
      "id": "UC-E2E-S1",
      "status": "passed",
      "fr_coverage": ["FR-0.01-01"],
      "components": ["daemon", "gateway", "state", "trace", "replay"],
      "positive_evidence": ["..."],
      "negative_evidence": ["..."],
      "replay_evidence": ["..."],
      "anti_drift_checks": ["..."],
      "run_ids": ["run_..."],
      "trace_event_ids": ["trace_evt_..."],
      "state_node_ids": ["state_..."],
      "state_hashes": ["sha256:..."],
      "message_ids": [],
      "work_order_ids": [],
      "approval_ids": [],
      "node_ids": [],
      "artifact_paths": ["target/splendor-e2e/use-case-acceptance/artifacts/..."]
    }
  ],
  "blocking_failures": [],
  "non_goal_observations": [],
  "human_summary_path": "target/splendor-e2e/use-case-acceptance/report.md"
}
```

---

## 6. Use-case E2E sprint index

| Sprint | Acceptance focus | Main product risk prevented |
| --- | --- | --- |
| UC-E2E-S0 | Acceptance harness and anti-drift gate | Tests become demos, mocks, or private-helper checks. |
| UC-E2E-S1 | Local governed action loop | Local runtime correctness drifts from gateway/state/trace/replay invariants. |
| UC-E2E-S2 | Management API and client contract | Daemon/client contract drifts from runtime semantics or becomes insecure. |
| UC-E2E-S3 | Multi-agent delegation and communication | Shared/specialist agents launder permissions or messages lose causality. |
| UC-E2E-S4 | Fleet work-order dispatch, placement, state handoff, remote messaging | Distributed execution becomes magical or identity/state continuity weakens. |
| UC-E2E-S5 | Governance approval, escalation, circuit breaker, kill switch | Governance becomes UI/product-shaped instead of runtime-enforced. |
| UC-E2E-S6 | Physical/edge orchestration and offline safety | Splendor drifts into real-time robot control or unsafe cloud authority. |
| UC-E2E-S7 | Data-local analysis, artifacts, and cross-tenant isolation | Data refs, artifacts, and shared agents leak across tenants. |
| UC-E2E-S8 | Replay, audit explanation, schema compatibility, migration | Replay/audit/compatibility are incomplete or cause side effects. |
| UC-E2E-S9 | Failure injection, quotas, bounded retry, fail-closed behavior | Reliability tests accidentally normalize unsafe continuation. |
| UC-E2E-S10 | Final cross-component journey | Components pass in isolation but drift when combined. |

---

# UC-E2E-S0 — Acceptance Harness and Anti-Drift Gate

## Objective

Build the common harness that every later use-case sprint must use. This sprint is complete only when the acceptance suite can be run in containers, collect evidence, validate API contracts, and fail when tests bypass public/runtime boundaries.

## Use case

A reviewer checks out the repository, runs one script, and receives a deterministic report showing which Splendor primitives, FRs, API contracts, and anti-drift rules were validated.

## Components exercised

- Docker Compose acceptance topology
- `splendorctl` CLI
- Rust test runner
- Python SDK test runner
- TypeScript client test runner
- OpenAPI/schema validator
- report aggregator
- artifact collector
- anti-drift scanner

## Required work

1. Add `tests/e2e/use-cases/docker-compose.acceptance.yml`.
2. Add `scripts/e2e/verify-use-case-acceptance.sh`.
3. Add report schema and report aggregator under `tests/e2e/use-cases/reporting/`.
4. Add a deterministic fixture seed mechanism for tenant IDs, agent IDs, run IDs, node IDs, message IDs, and external-service responses.
5. Add anti-drift scanner checks that fail on private-helper-only E2E tests, direct adapter execution in scenario code, undocumented management/communication endpoints, missing replay suppression evidence, anonymous non-dev daemon calls, and physical low-level action acceptance.
6. Add a `make e2e-acceptance` or equivalent convenience target that calls the script without changing semantics.

## Positive acceptance evidence

- Compose topology starts all required services.
- The runner proves it can call daemon health/capabilities through the documented API with a valid test caller credential.
- The report includes suite metadata, source revision, container topology hash, command list, and component versions.
- OpenAPI/schema validation runs before any scenario-specific test.
- CLI, Python, TypeScript, and Rust runners contribute at least one evidence item.

## Negative/fail-closed evidence

- A test fixture that calls an adapter directly while claiming E2E status is detected and fails the suite.
- A fixture that omits caller identity for a non-dev daemon call is rejected.
- A fixture that claims replay success without recording adapter-suppression evidence is rejected.
- A fixture that references `set_motor_pwm`, `disable_firmware_safety`, or similar low-level physical actions as allowed is rejected.

## Replay/audit evidence

This sprint does not need a full run replay, but it must prove the report schema has fields for replay mode, replay side-effect suppression, and replay artifacts. Later sprints must populate those fields.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0
```

## Exit gate

The harness fails closed when scenario code bypasses the public boundary, omits evidence, uses anonymous non-dev calls, or claims unsupported product scope.

## Non-goals

- No Kubernetes requirement.
- No production OAuth/PKI rollout.
- No real external SaaS, robot, drone, cloud, or database dependency.
- No dashboard or admin product UI.

---

# UC-E2E-S1 — Local Governed Action Loop

## Objective

Validate the local kernel loop end to end with real state commits, trace events, gateway enforcement, verifier outcomes, local safe adapters, quotas, and inspect-only replay.

## Use case

A tenant-owned research agent receives a structured percept requesting an allowed HTTP read from the fixture service, summarizes the response, writes a scoped artifact to the tenant sandbox, commits state, emits trace, and then replays the run without re-calling HTTP or rewriting the file.

This is a bounded use case: realistic enough to involve percepts, policy, constraints, two adapters, quotas, state, trace, and replay, but not a broad product workflow.

## Components exercised

- local runtime daemon
- Rust scheduler/loop engine
- action gateway
- verifier chain: tenant, agent permission, adapter, quota, precondition, data-scope, network/filesystem, postcondition
- filesystem adapter
- HTTP adapter
- state graph store
- trace store
- replay engine
- `splendorctl`
- Python policy/perceptor/constraint hooks

## Public/API surface

- `POST /runs`
- `POST /percepts` or documented equivalent
- `POST /actions` through runtime action submission path
- `GET /state-head`
- `GET /traces`
- `POST /replay`
- CLI equivalents for run, trace export, state head, replay
- Python SDK hooks for policy/perceptor/constraints/traces

## Positive path

1. Create a signed/scoped local work order for `tenant_research` and `agent_research_writer`.
2. Start a local run with deterministic fixture IDs.
3. Append a percept referencing `fixture:http://fake-http-service/allowed/research-summary`.
4. Python policy proposes two action requests:
   - `http.get` for the allowlisted fixture URL;
   - `filesystem.write` to `sandbox://tenant_research/artifacts/summary.md`.
5. Constraints evaluate the URL allowlist and sandbox path.
6. Gateway runs required verifiers before each adapter call.
7. HTTP adapter returns deterministic fixture payload.
8. Filesystem adapter writes only within the tenant sandbox.
9. Outcome is recorded and state commits with parent linkage and hash.
10. Trace contains required tick events and action-specific events.
11. CLI exports trace and state evidence.
12. Inspect-only replay reconstructs proposed actions and outcomes without calling HTTP or writing the file again.

## Required negative paths

- A URL outside the allowlist is denied before HTTP adapter execution.
- A path traversal write such as `sandbox://tenant_research/../../escape.md` is denied before filesystem adapter execution.
- Quota exhaustion denies or pauses a later action predictably and records reason code.
- A verifier-unavailable fixture denies or pauses; it must never become implicit allow.
- A forced trace-write failure blocks side-effectful execution or records fail-closed evidence before any side effect.
- A forced state-commit failure prevents the next tick from advancing.

## Required trace evidence

At minimum, the report must include IDs for:

- `tick.started`
- `percepts.received`
- `state.loaded`
- `policy.invoked`
- `policy.completed`
- `actions.proposed`
- `constraints.evaluated`
- `verification.started`
- `verification.completed`
- `action.executed` and `action.denied`
- `outcome.recorded`
- `state.committed`
- `tick.completed`
- `replay.started`
- `replay.adapter_suppressed`
- `replay.completed`

## Required state evidence

- state node ID
- tenant ID
- agent ID
- run ID
- parent state node ID
- snapshot or patch reference
- state hash
- trace linkage
- timestamp

## Replay/audit evidence

- Replay mode is `inspect_only` by default.
- HTTP request counter does not increase during replay.
- Filesystem artifact checksum does not change during replay.
- Replay explains the denied URL/path/quota cases.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1
```

## Exit gate

A reviewer can prove the local loop ran through the Splendor kernel path and that allowed side effects, denied side effects, state commits, trace events, quotas, and replay all behaved safely.

## Non-goals

- No remote messaging.
- No fleet placement.
- No governance approval workflow.
- No physical/edge device action.

---

# UC-E2E-S2 — Management API and Client Contract

## Objective

Validate that the management API is fully exposed, authenticated, schema-stable, generated/client-compatible, and semantically aligned with runtime enforcement.

## Use case

A management client creates and controls a run using only the exposed daemon API contract. The same workflow is driven through a TypeScript client, Python SDK, CLI wrapper, and OpenAPI-validated HTTP requests. The API can manage run lifecycle, percepts, traces, state, replay, actions, health, and capabilities without bypassing the gateway or treating management credentials as action authority.

## Components exercised

- local runtime daemon
- OpenAPI 3.1 contract
- TypeScript `@splendor/types` and `@splendor/client`
- Python SDK client path
- `splendorctl`
- Rust daemon handlers
- caller credential validation
- signed work-order validation
- endpoint-scope authorization
- trace/audit attribution
- action gateway
- replay engine

## Public/API surface

This sprint must validate every operation in [`docs/reference/management-communication-api-acceptance-contract.md`](../../reference/management-communication-api-acceptance-contract.md) marked as required for local daemon management:

- health, version, capabilities
- run create/inspect/start/pause/resume/cancel
- percept append
- action submit
- state-head read
- trace query/export
- replay
- caller/work-order rejection paths

## Positive path

1. Validate the OpenAPI document parses and has stable operation IDs.
2. Generate or parity-check TypeScript types from the OpenAPI/canonical schemas.
3. Validate Rust/Python/TypeScript schema fixtures serialize to identical canonical JSON for run, action, trace, state, replay, and work-order types.
4. Use a scoped caller credential to create a run from a signed work order.
5. Append a percept and start the run.
6. Submit an action through the documented API and verify the gateway, not the API handler, authorizes execution.
7. Read state head and traces with a required redaction policy.
8. Pause/resume/cancel a run through documented lifecycle operations.
9. Run inspect-only replay through the API.
10. Repeat the core workflow with the TypeScript client and CLI wrapper.

## Required negative paths

- Missing caller credential is rejected outside explicit local dev mode.
- Expired caller credential is rejected.
- Wrong endpoint scope is rejected.
- Expired, revoked, malformed, unsigned, or audience-mismatched work order is rejected before run start.
- A management token alone cannot authorize arbitrary action execution.
- `GET /health`, `GET /capabilities`, or telemetry responses cannot authorize actions, placement, or work orders.
- An undocumented path, wrong HTTP method, missing required field, extra unstable enum value, or schema mismatch fails contract tests.
- Local-dev insecure mode is accepted only on loopback or Unix domain socket with explicit flag and warning evidence.

## Required trace/audit evidence

- Every mutating call includes caller attribution.
- Work-order ID is trace-linked to run creation.
- Action submission trace links to gateway verification result.
- Replay trace records inspect-only mode.
- Denials include scope/work-order/caller reason codes.

## Replay/audit evidence

- API-driven replay emits replay events and cannot call side-effectful adapters by default.
- Audit export links caller credential ID, work-order ID, run ID, action IDs, and denial reason codes.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S2
```

## Exit gate

The exposed management API is executable, documented, schema-validated, client-compatible, authenticated, scoped, and unable to bypass runtime enforcement.

## Non-goals

- No enterprise admin product UI.
- No product-specific control plane dependency.
- No production OAuth vendor integration requirement.

---

# UC-E2E-S3 — Multi-Agent Delegation and Communication

## Objective

Validate local multi-agent coordination inside one Splendor instance with typed messages, parent/child run references, per-agent isolation ledgers, scoped delegation, quotas, trace-linked causality, and replay reconstruction.

## Use case

A local orchestrator agent receives a request to prepare a document summary. It delegates analysis to a specialist agent with narrower authority. The specialist returns a typed response. The orchestrator writes an internal artifact. The specialist attempts one unauthorized action and one unauthorized message path; both are denied without affecting the allowed flow.

## Components exercised

- local multi-agent runtime
- message schema/envelope
- local message router
- inbox/outbox
- per-agent isolation ledger
- local delegation model
- child run references
- gateway and verifier chain
- state graph and trace store
- multi-agent replay causal graph
- Python SDK callback hooks

## Public/API surface

- run lifecycle API
- message send/receive or documented local message operation
- traces query/export
- replay causal graph endpoint or CLI command
- TypeScript/Python schema parity for `Message`

## Positive path

1. Create orchestrator and specialist runtime contexts under one tenant.
2. Give orchestrator permission to read the input ref and create internal artifacts.
3. Give specialist permission only to read the delegated data ref and return a typed summary message.
4. Start parent run for orchestrator.
5. Orchestrator sends `splendor.message.task_request.v1` to specialist with causal parent trace event.
6. Specialist starts child run linked to parent run.
7. Specialist reads only allowed data ref, commits state, and sends `splendor.message.task_result.v1` response.
8. Orchestrator receives response, writes internal artifact through gateway, commits state, and traces completion.
9. Replay reconstructs parent/child run relationship and message causal graph.

## Required negative paths

- Specialist tries to publish an external artifact; denied because delegated permissions are narrower.
- Specialist tries to send a message to an unauthorized recipient; denied with delivery failure state.
- Specialist uses an unsupported message schema; schema validation fails before delivery.
- Orchestrator tries to pass broad permissions through a message payload; delegation verifier denies permission laundering.
- Cross-tenant message attempt is rejected and trace-linked.
- Specialist quota exhaustion denies or pauses without affecting the orchestrator’s separate ledger.

## Required trace evidence

- message sent, delivered, received, failed/denied
- parent run created
- child run created
- delegated permissions evaluated
- action denied for permission laundering or excessive scope
- state committed for parent and child
- replay causal graph reconstructed

## Replay/audit evidence

- Replay shows message causality and parent/child run linkage without re-running adapters.
- Replay explains why unauthorized artifact publish and unauthorized message attempts were denied.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S3
```

## Exit gate

Local agents coordinate through typed, trace-linked messages while preserving agent-level isolation and preventing delegated permission laundering.

## Non-goals

- No remote transport.
- No central fleet manager.
- No external approval workflow.

---

# UC-E2E-S4 — Fleet Work-Order Dispatch, Placement, State Handoff, and Remote Messaging

## Objective

Validate distributed/fleet execution using explicit identities, node/instance registration, capability matching, signed work orders, remote typed messages, trace aggregation, state handoff, and telemetry that remains non-authoritative.

## Use case

A central manager dispatches a signed data-local work order to a resident VPC node. The VPC node executes the run, sends a typed remote message to a cloud helper for a non-authoritative proposal, and exports a state snapshot. A compatible resident receiver prepares its own state, rejects import because v0 lacks accepted source-authenticated proof, preserves its state unchanged, and the fleet syncs traces to the central trace index.

## Components exercised

- central manager
- resident node and instance registry
- capability advertisement
- placement v0
- signed work orders
- remote work-order dispatch
- remote message transport
- trace aggregation
- state handoff
- fleet telemetry
- gateway/verifier chain on resident nodes
- TypeScript or CLI management client

## Public/API surface

- node registration
- instance registration
- heartbeat/capabilities
- work-order submit/revoke/dispatch
- placement decision query
- remote message send/delivery status
- state snapshot export/import or handoff reference
- trace buffer sync / central trace query
- fleet telemetry read

## Positive path

1. Register `resident-vpc-node` and `resident-cloud-node` with distinct node/instance IDs.
2. Advertise capabilities: data locality, adapters, runtime version, trust level, quotas, physical/device absence.
3. Submit a signed work order requiring `data_locality=eu-west`, `sql.read_fixture`, `artifact.create_internal`, and `message.remote.proposal`.
4. Central manager validates caller, work-order signature, expiry, revocation, audience, and compatibility.
5. Placement selects the VPC node with an explainable reason.
6. VPC node starts run and verifies every side-effectful action locally.
7. VPC node sends a remote typed message to cloud helper requesting a proposal.
8. Cloud helper returns a proposal message without authority to mutate data or act.
9. VPC node commits state and exports explicit state snapshot reference.
10. Attempt import on a compatible resident node; require `state_handoff_proof_unavailable`/`needs_intervention` before store/state/trace mutation and verify the receiver head is unchanged.
11. Local trace buffers sync to central trace aggregation without losing ordering or integrity.
12. Fleet telemetry reports health, run status, quota use, and trace sync status.

## Required negative paths

- Unsigned, expired, revoked, incompatible, wrong-tenant, or wrong-audience work order rejected before run start.
- Stale node heartbeat prevents placement unless policy explicitly allows degraded placement.
- Capability mismatch gives a deterministic rejection reason.
- Duplicate remote message with same idempotency marker is not double-applied.
- Remote message delivery failure is trace-linked and does not mutate remote state directly.
- Hash-valid fabricated and hash-tampered handoffs cannot bypass the missing-source-proof denial; a valid exact-profile unknown-run request receives the same proof-unavailable denial before mutation and does not expose run existence.
- Telemetry cannot authorize work-order dispatch, action execution, or placement.

## Required trace evidence

- node registered
- instance registered
- heartbeat received
- capabilities advertised
- work_order.received / accepted / rejected
- placement.evaluated
- run.dispatched
- remote_message.sent / delivered / failed
- state.exported
- trace.sync.started / completed / failed
- telemetry.reported

## Replay/audit evidence

- Replay reconstructs the export boundary, remote message causality, and denial reasons without re-executing remote side effects. Resident proof denial itself creates no run-trace mutation.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S4
```

## Exit gate

Distributed execution remains explicit: identity, placement, work orders, remote messages, trace aggregation, and state handoff are visible, verified, and not magical.

## Non-goals

- No full distributed consensus.
- No arbitrary shared distributed memory.
- No global exactly-once claim beyond explicit idempotency behavior.
- No mature enterprise fleet UI.

---

# UC-E2E-S5 — Governance Approval, Escalation, Circuit Breaker, and Kill Switch

## Objective

Validate runtime governance workflows: approval-required actions pause instead of executing, external grant/deny flows resume or cancel safely, policy TTLs fail closed, escalations are deterministic, circuit breakers block within scope, kill switches propagate, and audit/replay explains decisions.

## Use case

A report agent generates an internal artifact and requests external publication. External publication is high risk and requires approval. The run pauses, a governance plane grants one approval, the action executes once, a later attempt is denied because approval expired, a circuit breaker blocks the adapter, and a fleet kill switch cancels a matching run.

## Components exercised

- governance state model
- approval verifier
- governance adapter/control-plane surface
- escalation engine
- policy bundle distribution and TTL cache
- circuit breaker engine
- kill switch propagation
- daemon API and central manager API
- trace/audit export
- replay explanation
- artifact adapter
- gateway/verifier chain

## Public/API surface

- policy bundle publish/revoke/read
- approval request/grant/deny/expire/revoke
- resident approval-receipt revoke acknowledgement
- run pause/resume/cancel
- circuit breaker create/clear/status
- kill switch activate/status
- governance audit export
- replay explanation

## Positive path

1. Publish a policy bundle requiring approval for `artifact.publish_external`.
2. Start a run under a signed work order allowing internal artifact creation but requiring governance for external publish.
3. Agent creates internal artifact through gateway.
4. Agent proposes `artifact.publish_external`.
5. Approval verifier returns `action.needs_approval`; adapter is not called.
6. Run pauses with trace-linked approval request.
7. Governance plane grants scoped approval with action ID, tenant, agent, adapter, expiry, audience, and approval ID. The request uses a fresh fleet-bound central-manager bearer with exact `splendor.approvals.manage` scope; body credential/audit fields are matching non-authoritative mirrors. A secure resident receipt audience is versioned and binds the server-derived target `InstanceId` plus exact `RunId`.
8. The exact receipt-bearing `/actions` retry executes once, then the run records
   its post-effect resumed transition without a lifecycle-resume tick.
9. Audit export explains approval request, grant, resume, execution, and state commit.

## Required negative paths

- Approval denial cancels or blocks the pending action and records reason code.
- Expired approval token cannot resume or authorize execution.
- Revoked approval cannot authorize execution.
- Missing/expired/revoked policy bundle denies high-risk side effects or requests intervention.
- Verifier uncertainty triggers deterministic escalation, not implicit allow.
- Circuit breaker scoped to tenant/adapter/action blocks matching actions and records scope.
- Clearing circuit breaker requires scoped caller authority and trace evidence.
- Kill switch propagates to matching node/instance/run and fails closed when propagation acknowledgement is missing.
- External governance adapter cannot mutate runtime internals directly or issue broad action authority.
- Missing, forged, expired, revoked, wrong-manager, wrong-fleet, wrong-scope, or replayed manager approval bearer cannot mutate approval/audit state or issue a trusted receipt.
- Raw granted approval evidence, and raw denial/expiry/revocation on an active run,
  is rejected before gateway, runtime trace, pause, or lifecycle mutation. Only
  exact fail-closed evidence on the stored `WaitingForApproval` `/actions` retry
  is admitted; mixed raw evidence plus receipts is rejected.
- Grant and retain an exact resident receipt/target, revoke it through the
  dedicated `splendor.approval_receipts.revoke` resident endpoint, require an
  authenticated `revoked`/`already_revoked` acknowledgement, then retry the exact
  action and prove zero adapter effects.
- Concurrent resident revoke and gateway claim produces one winner. Revoke-first
  prevents the effect; claim-first returns resident `already_claimed` and manager
  `too_late`. Neither timeout nor both outcomes may be reported as success.
- Send the retained receipt to a wrong node/instance with a fresh exact-scope JTI:
  it rejects without receipt/semantic tombstones. A second fresh-JTI request to
  the original target succeeds.
- Missing dedicated scope, wrong bearer audience, reused JTI, TLS/hostname or
  exact-origin failure, malformed/oversized acknowledgement, reset, or timeout
  cannot produce manager revocation success. Post-send uncertainty is explicit.

## Required governance trace evidence

- approval.requested
- approval.granted / denied / expired / revoked
- action.needs_approval
- action.denied
- run.paused
- run.resumed
- run.cancelled
- policy.expired / revoked
- circuit_breaker.tripped / cleared
- kill_switch.activated
- governance.audit.exported

## Replay/audit evidence

- Replay explains why each action was allowed, denied, paused, escalated, resumed, or cancelled.
- Replay never publishes artifacts or re-calls external systems.
- Audit export links caller, work order, policy bundle, approval, circuit breaker, kill switch, run, action, and trace IDs.
- Audit/API evidence distinguishes resident `revoked`/`already_revoked`, resident
  `already_claimed` mapped to manager `too_late`, and transport/effect uncertainty.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S5
```

## Exit gate

Governance is enforced as runtime state and verifier behavior, not as an external dashboard convention or product-specific workflow.

## Non-goals

- No enterprise admin SaaS.
- No universal approval UI.
- No billing/org management UX.
- No product-specific Harmony dependency inside the kernel.

---

# UC-E2E-S6 — Physical/Edge Orchestration and Offline Safety

## Objective

Validate that Splendor can govern physical/edge autonomy using bounded high-level actions, local safety verifiers, offline policy cache, local trace buffer, operator intervention, reconnect sync, and cloud helper proposals without becoming a real-time robot controller.

## Use case

A simulated inspection drone receives a work order to inspect a zone. A cloud helper proposes a route. The edge node validates the proposal locally against geofence, battery, human proximity, privacy zone, and policy TTL. The drone simulator executes only high-level bounded actions. During a network partition, cached policy allows safe read-only sensing and `return_to_base`; high-risk actions require local intervention or are denied. Traces buffer offline and sync after reconnect.

## Components exercised

- resident edge node
- device profile schema
- physical capability model
- robotics/physical adapter interface
- device simulator
- safety verifier API
- offline policy cache
- local trace buffer
- operator intervention protocol
- cloud helper pattern
- central manager
- trace aggregation
- replay/audit

## Public/API surface

- device profile register/read
- capabilities/health with safety status
- policy cache status
- high-level physical action request
- operator intervention request/grant/deny
- trace buffer sync
- cloud helper proposal message
- safety verifier evidence read

## Positive path

1. Register `resident-edge-node` with `device_kind=drone_sim`, high-level capabilities, safety constraints, and local runtime mode.
2. Sync policy bundle with TTL.
3. Submit signed work order for `inspect_zone` with bounded zone, altitude, privacy, and battery constraints.
4. Cloud helper proposes route via typed message and has no direct actuator authority.
5. Edge node validates proposal locally.
6. Safety verifiers approve `read_battery`, `read_sensor_summary`, `move_to_waypoint`, `capture_image`, `return_to_base`, and `upload_trace_summary` as applicable.
7. Network partition starts.
8. Node continues only actions allowed by cached policy.
9. Operator intervention is requested for an ambiguous high-risk action.
10. Trace buffer records offline safety decisions.
11. Network reconnects and trace buffer sync preserves order/integrity.
12. Replay explains physical decisions without controlling the simulator.

## Required negative paths

- `set_motor_pwm`, raw actuator write, firmware safety bypass, collision avoidance bypass, emergency stop ignore, or flight-controller internals modification is rejected at schema/adapter boundary.
- Geofence breach is denied before adapter execution.
- Low battery forces `return_to_base`, `dock`, pause, or intervention according to policy.
- Expired policy cache denies high-risk action while offline.
- Cloud helper direct action attempt is denied.
- Operator intervention outside exact tenant/agent/run/node/action scope, reused
  on another device, extended beyond authoritative expiry, or used after the
  authoritative record expires is rejected.
- A physical approval challenge binds the path/profile-derived typed `NodeId` in
  the domain-separated physical v2 gateway authority action digest. Supplying a
  different node through action params, metadata, body fields, mirrors, or an
  otherwise valid receipt cannot override the server resource coordinate.
- Nonphysical digest fixtures remain byte-for-byte v1. An outstanding physical
  v1 challenge/receipt cannot execute and must be re-challenged under physical
  v2; no translation or permissive fallback is accepted.
- Trace sync empty, cross-run, payload/event-hash tamper, gap, or reordering is
  detected and the whole batch reports zero accepted records.

## Required trace evidence

- device.profile.registered
- policy.cache.loaded
- policy.cache.expired where applicable
- cloud_helper.proposal.received
- safety.verification.started / completed / denied
- action.executed / denied / needs_intervention
- operator.intervention.requested / granted / denied / expired
- offline.entered / exited
- trace.buffer.appended
- trace.sync.started / completed / failed

## Replay/audit evidence

- Replay simulates or explains high-level physical decisions and never controls device simulator actuators by default.
- Audit export shows cloud helper could propose but not authorize physical action.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S6
```

## Exit gate

Splendor governs physical/edge workflows through bounded actions and local safety gates while preserving the boundary that real-time controllers and firmware remain outside Splendor.

## Non-goals

- No real robot, drone, PLC, ROS, flight controller, or motor control.
- No production safety certification claim.
- No hard real-time safety loop.

---

# UC-E2E-S7 — Data-Local Analysis, Artifacts, and Cross-Tenant Isolation

## Objective

Validate a realistic data-local use case with scoped data references, shared specialist agents, internal/external artifacts, trace redaction, cross-tenant isolation, governance-aware publication, and communication boundaries.

## Use case

Two tenants use a shared document/analysis specialist. Tenant A asks for a board-ready finance report using data-local fixtures. Tenant B has similarly named data. The specialist may process Tenant A’s scoped data refs and return a typed analysis message, but must not read Tenant B’s data, publish externally without approval, leak raw data through traces, or inherit broad management permissions.

## Components exercised

- central manager and VPC node
- local and remote message routing
- shared specialist agent
- per-agent isolation ledgers
- data-scope verifier
- artifact adapter
- trace redaction policy
- governance approval for external publish
- state graph and replay
- TypeScript/Python clients for scenario setup

## Public/API surface

- work-order dispatch
- data ref authorization
- message send/receive
- artifact create/read/publish request
- trace query/export with redaction policy
- approval flow for publish
- replay/audit explanation

## Positive path

1. Register two tenants with separate data refs.
2. Submit per-instance signed Tenant A work orders with separate exact profiles
   for specialist data read, internal artifact creation, external publication,
   request messaging, and response messaging.
3. Reuse the canonical VPC node/instance identity, refresh both health records,
   place exact profiles on the data-local node, and dispatch only profiles
   supported by manager dispatch.
4. Drive every resident request over verified TLS with a fresh scoped bearer and
   matching caller/audit projection fields.
5. Shared specialist receives a typed request whose payload is non-authorizing;
   its separately signed data-read work order is the only action authority.
6. Specialist reads the allowed data fixture, returns a typed response bound to
   its child run, and commits state.
7. Orchestrator creates an internal artifact under its separate exact run.
8. A publish-only run is created directly with one exact policy action and
   approval policy, starts in `NeedsApproval`, and records the full exact
   challenge with the manager through fresh one-use `splendor.approvals.manage`
   bearers. One manager-issued, trace-linked authority receipt then retries the
   exact pending action through `POST /actions`, producing one execution and a
   `run.resumed` transition to `running` without another tick or state-head
   advance. Raw grant evidence and lifecycle `/resume` are not execution
   authority.
9. Trace export with redaction policy excludes protected raw data while preserving IDs and reason codes.
10. Replay reconstructs data refs, messages, approvals, artifacts, and denials.

## Required negative paths

- Specialist attempts to read Tenant B data ref; denied before adapter execution.
- Specialist attempts to use manager credential as action permission; denied.
- Message payload tries to smuggle additional data refs or permissions; denied.
- Trace export without redaction policy is rejected.
- External artifact publish without approval pauses or denies.
- Cross-tenant replay cannot reveal raw payloads outside redaction policy.
- Artifact path collision across tenants is rejected.

## Required trace evidence

- work_order.accepted
- data_scope.verified / denied
- message.sent / received / denied
- artifact.created
- artifact.publish.needs_approval / executed / denied
- run.resumed after the exact receipt-bearing publish retry
- trace.exported.redacted
- state.committed
- replay.explained

## Replay/audit evidence

- Audit package proves which data refs were in scope and which were denied.
- Replay explains cross-tenant denial without reading or exporting raw protected data.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S7
```

## Exit gate

Data-local analysis works with shared specialists and artifacts without cross-tenant leakage, permission laundering, or trace/data redaction drift.

## Non-goals

- No real finance data.
- No external SaaS artifact store.
- No enterprise board-report product workflow.

---

# UC-E2E-S8 — Replay, Audit Explanation, Schema Compatibility, and Migration

## Objective

Validate that replay and audit are safe, explanatory, and compatible with the stable primitive line. The sprint proves state/trace integrity, schema version compatibility, migration from dev milestone fixtures, generated type parity, and replay side-effect suppression.

## Use case

The suite exports traces and state snapshots from prior scenarios, tampers with selected artifacts to prove integrity failures, migrates supported dev-schema fixtures to the 0.1 stable line, and runs inspect-only replay, read-only re-evaluation, policy comparison, and verifier explanation modes.

## Components exercised

- trace export/import
- state snapshot export/import
- replay engine
- policy comparison mode
- verifier explanation mode
- schema migration tools
- Rust/Python/TypeScript generated types
- compatibility test suite
- audit package builder

## Public/API surface

- trace export/import
- state snapshot export/import
- replay request
- replay mode selection
- schema migration command/API
- compatibility/conformance command
- audit export

## Positive path

1. Export trace/state/artifact metadata from S1, S3, S4, S5, S6, and S7.
2. Validate trace integrity chain and state hashes.
3. Import exported trace/state into a clean container volume.
4. Run inspect-only replay.
5. Run read-only re-evaluation where allowed.
6. Run policy comparison against a new policy bundle without executing side effects.
7. Run verifier explanation for approvals, denials, quota failures, work-order rejection, data-scope denial, and safety denial.
8. Migrate supported dev-schema fixtures to stable 0.1 schema and validate generated Rust/Python/TS types.
9. Build an audit package with human-readable and machine-readable explanations.

## Required negative paths

- Tampered trace chain is detected.
- State hash mismatch prevents replay continuation.
- Unsupported schema version is rejected with migration guidance.
- Replay request that enables side-effectful mode is rejected unless separately gated, explicitly marked, and off by default.
- Replay cannot use real external credentials.
- Generated TypeScript/Python/Rust schema mismatch fails compatibility gate.
- Audit export cannot omit denial reason codes for negative paths.

## Required trace/audit evidence

- replay.started / completed / failed
- replay.adapter_suppressed
- replay.policy_compared
- replay.verifier_explained
- trace.imported / rejected
- state.imported / rejected
- schema.migrated / rejected
- audit.exported

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8
```

## Exit gate

Replay, audit, and compatibility work across prior use cases and cannot become an accidental side-effect execution path.

## Non-goals

- No guarantee of reproducing nondeterministic model internals.
- No real production credential replay.
- No broad historical migration beyond documented supported versions.

---

# UC-E2E-S9 — Failure Injection, Quotas, Bounded Retry, and Fail-Closed Behavior

## Objective

Validate that Splendor fails safely under realistic runtime failures: adapter errors, verifier uncertainty, trace write failure, state commit failure, remote message failure, node staleness, trace sync interruption, quota pressure, and kill-switch/circuit-breaker races.

## Use case

The runner injects deterministic failures into fake HTTP, the controlled action provider, message transport, trace sync, state store, and policy distribution. The runtime must either complete safely, deny, pause, request intervention, or cancel with traceable evidence. It must never silently continue, retry unboundedly, double-apply side effects, or convert errors into allow.

## Components exercised

- gateway/verifier chain
- quotas
- safe adapters
- message transport
- state store
- trace store
- policy cache/distribution
- governance workflows
- fleet manager
- local trace buffer
- replay/audit
- fault proxy

## Positive path

1. Run bounded success fixture with stable latency and quotas.
2. Verify quotas are consumed predictably.
3. Verify bounded retry for a retryable read-only or idempotent action.
4. Verify idempotency marker prevents duplicate side-effect application after transport retry.
5. Verify recoverable trace sync resumes without losing integrity.

## Required negative paths

- Adapter returns failure: outcome is recorded and no fake success is committed.
- Verifier unavailable: action denied, paused, or requests intervention.
- Policy unavailable or expired: high-risk side effects denied.
- Trace write failure before side effect: side effect does not run.
- Trace write failure after permitted outcome: failure is trace/audit-visible and no hidden continuation occurs.
- State commit failure: next tick does not advance.
- Remote message transport fails: delivery failure state is recorded and no direct remote mutation occurs.
- Node heartbeat stale: placement denied or explicitly degraded by policy.
- Quota exceeded: action denied or paused, not silently retried.
- Circuit breaker races with pending approval: circuit breaker wins for matching scope unless policy explicitly says otherwise.
- Kill switch races with run resume: kill switch fails closed.
- Telemetry stale/missing: telemetry cannot authorize anything.

## Required trace evidence

- adapter.failed
- verifier.unavailable
- quota.exceeded
- trace.write_failed
- state.commit_failed
- message.delivery_failed
- node.stale
- policy.expired
- circuit_breaker.tripped
- kill_switch.activated
- run.paused / denied / cancelled

## Replay/audit evidence

- Replay explains the failure mode and confirms no additional side effects occurred during replay.
- Audit report includes bounded retry counts and idempotency markers.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9
```

## Exit gate

Failure behavior is safe, deterministic, traceable, bounded, and compatible with Splendor’s fail-closed runtime model.

## Non-goals

- No chaos testing against real production infrastructure.
- No high-scale load benchmark.
- No global exactly-once distributed guarantee.

---

# UC-E2E-S10 — Final Cross-Component Acceptance Journey

## Objective

Prove that all completed Splendor components work together in one coherent, bounded, product-aligned journey. This is the final use-case validation after all implementation sprints and prior use-case sprints pass.

## Use case

A central manager receives a signed work order for a governed field-intelligence package:

- a data-local resident node analyzes a scoped fixture dataset;
- a shared specialist provides a typed analysis response;
- a controlled action provider executes one bounded edge inspection under local safety verifiers and returns fixture receipt evidence;
- a cloud helper proposes, but cannot authorize, a route or publication;
- the orchestrator creates an internal artifact;
- external publication requires approval;
- a circuit breaker and kill switch are tested on separate controlled branches;
- traces aggregate centrally;
- state handoff export occurs once, resident import fails closed without source proof, receiver state remains unchanged, and the receiver resumes only from its own state;
- audit/replay explains the full journey without side effects.

This is not an enterprise product demo. It is a kernel acceptance journey that uses the full component surface while keeping external systems deterministic and simulated.

## Components exercised

All available components in the acceptance topology:

- Rust runtime core
- scheduler/loop engine
- action gateway
- verifier chain
- quotas
- state graph
- trace store
- replay
- local daemon API
- central manager/fleet API
- signed work orders
- placement
- remote typed messaging
- local multi-agent router
- Python SDK
- PyO3/Python boundary if present
- TypeScript types/client
- OpenAPI contract
- CLI
- filesystem/HTTP/artifact adapters
- governance adapter
- device/robotics simulator adapter
- safety verifier API
- offline policy cache
- local trace buffer
- telemetry sink
- fault proxy

## Positive path

1. Validate API contracts and generated type parity.
2. Register all nodes and instances.
3. Publish policy bundle with TTL.
4. Submit target-instance-signed work orders with exact allowed action, adapter, permission, data-ref, quota, placement, and expiry profiles. Every resident call uses verified TLS and a fresh exact-scope, target-instance bearer; mutating JTIs are not reused.
5. Place data-local analysis on VPC node.
6. Delegate document/data analysis to shared specialist with scoped authority.
7. Send remote proposal request to cloud helper.
8. Send physical inspection request to edge node.
9. Edge node validates the cloud proposal locally, performs bounded high-level inspection through the explicitly composed `device-sim` adapter and controlled receipt-bearing provider, buffers traces during a network partition, and syncs after reconnect.
10. Orchestrator collects typed messages, commits state, and creates an internal artifact under an internal-create-only work order.
11. A separate publish-only VPC run is created with one exact approval-policy action and pauses with a daemon-issued approval challenge. The manager records that exact challenge and issues one authority obligation receipt whose v2 audience binds the server-derived target `InstanceId` and exact `RunId`. The exact challenged action is then retried once through canonical `POST /actions` (`submitAction`; the retained traffic labels this specific evidence row `submitApprovedExactAction`). The retry contains the unchanged action payload, effective adapter, request time, quota, and preconditions; contains no raw approval evidence; executes once; leaves the tick and state head unchanged; and emits `run.resumed` only after `action.executed`. No publish-run lifecycle resume call is allowed. Every manager approval mutation uses a fresh exact-audience, fleet-bound, one-scope bearer and matching non-authoritative request mirrors.
12. Export state, create a receiver run with a cloud-signed envelope, use that exact admitted envelope for import and resume, prove resident import denies with `state_handoff_proof_unavailable` before mutation, then resume only the receiver's own committed state.
13. Aggregate hash-verifiable VPC/cloud traces and telemetry centrally, sync the edge trace buffer through its resident reconnect boundary, and prove redacted edge exports are not resubmitted or rehashed to manufacture central acceptance.
14. Export audit package and run inspect-only replay.

## Required controlled negative branches

Each branch must be independent so the positive path can still complete:

- invalid work order rejected before run start;
- unauthorized data ref denied;
- unauthorized specialist permission escalation denied;
- remote message duplicate not double-applied;
- raw physical actuator action rejected;
- expired approval rejected;
- missing/forged/replayed manager approval authentication rejected before approval/audit mutation or receipt issuance;
- raw grant and active-run raw evidence rejected before gateway/trace/lifecycle,
  with unchanged active run status and no new approval pause;
- a separate granted receipt is retained, revoked through the authenticated exact-
  target resident endpoint, acknowledged as `revoked`/`already_revoked`, and then
  rejected on exact action retry with zero adapter effect;
- concurrent revoke/claim records exactly one winner and maps claim-first to
  resident `already_claimed`/manager `too_late`;
- wrong-node receipt revocation rejects without poisoning the original target,
  then succeeds at the original node with a fresh one-use JTI;
- dedicated-scope/JTI/TLS/exact-origin failure and timeout/reset uncertainty never
  become manager revocation success;
- physical challenge binds the server-derived typed `NodeId` under physical v2,
  rejects caller override, and requires re-challenge for physical v1 while
  nonphysical v1 digest bytes remain unchanged;
- circuit breaker blocks matching publish attempt;
- kill switch cancels a separate matching run;
- tampered trace/state import rejected;
- replay side-effect mode rejected by default.

## Required evidence

The final report must include:

- one page human summary for management review;
- machine-readable scenario evidence;
- API contract validation report;
- container topology hash;
- run, action, state, trace, message, work-order, approval, node, instance, policy, circuit-breaker, kill-switch, and artifact IDs;
- trace/state export paths;
- replay/audit explanation path;
- token-free manager approval authentication evidence and API-traffic correlation;
- retained publish API traffic, artifact report, approval challenge, manager grant response, authority obligation receipt, action response, and ordered traces that independently prove the exact AUTH-004c retry;
- exactly one receipt-bearing publish evidence row mapped to public `POST /actions`, with matching subject, audience, decision, obligation, request/evidence digests, approval trace linkage, satisfied verification/post-verification, one execution, unchanged tick/state head, post-effect `run.resumed`, and no publish-run lifecycle resume;
- token-free resident receipt-revocation request/ack evidence proving exact scope,
  fresh JTIs, TLS/hostname, exact origin, target instance/run audience, receipt and
  semantic tombstones, zero-effect revoke-before-retry, one concurrent winner,
  wrong-node rejection then original-node success, and explicit no-success
  transport/effect uncertainty;
- physical digest fixtures proving trusted typed-`NodeId` binding, caller override
  rejection, physical v1 re-challenge, and byte-identical nonphysical v1 digests;
- anti-drift gate results;
- FR and primitive coverage matrix.

## Container command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10
```

The final aggregate command must include S10:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

## Exit gate

Splendor can be accepted as a complete kernel-grade governed agent runtime line through `0.1-dev` only when this cross-component journey passes without bypasses, unsupported product drift, unsafe replay, hidden state, untraceable actions, or insecure management/communication APIs.

## Non-goals

- No real external customer data.
- No real robot or drone.
- No enterprise SaaS UI.
- No marketplace.
- No production certification claim.
- No full distributed consensus or universal shared memory.

---

## 7. FR coverage by use-case sprint

| FR group | Primary use-case sprint evidence |
| --- | --- |
| `FR-0.01-01..07` local runtime, gateway, state, trace, replay, SDK, CLI | S1, S2, S8, S9, S10 |
| `FR-0.02-01..10` messages, local router, isolation, delegation, daemon API, TypeScript, multi-agent replay | S2, S3, S7, S8, S10 |
| `FR-0.03-01..11` identity, registry, work orders, placement, remote messages, trace aggregation, state handoff, telemetry | S4, S8, S9, S10 |
| `FR-0.04-01..10` approvals, interventions, escalation, circuit breakers, policy TTL, external governance adapter, replay/audit | S5, S7, S8, S9, S10 |
| `FR-0.05-01..10` device profiles, physical capability model, offline cache, trace buffer, robotics adapter, safety verifier, operator intervention, cloud helper | S6, S8, S9, S10 |
| `FR-0.1-01..08` stable specs, versioning, compatibility, adapter maturity, conformance, migration, operations docs, hard invariants | S0, S2, S8, S9, S10 |

---

## 8. Review checklist

Reviewers must block acceptance if any answer is no:

- Does every scenario use containerized, reproducible execution?
- Does every scenario use documented public surfaces rather than private helpers?
- Does every side-effectful action route through the gateway and verifier chain?
- Are denial/fail-closed paths as strong as success paths?
- Does replay suppress side-effect adapters by default?
- Are state commits explicit, hashed, parent-linked, and trace-linked?
- Are trace events treated as runtime contract, not logging?
- Are daemon/client/central-manager calls authenticated and scoped?
- Are work orders signed, scoped, expiry-bound, audience-bound, and revocable?
- Are management credentials prevented from becoming action authority?
- Is telemetry non-authoritative?
- Are messages typed, trace-linked, and causally reconstructable?
- Does delegation remain narrower than caller authority?
- Do physical tests use high-level bounded actions only?
- Does the suite explicitly fail for unsupported product drift?
- Is the API contract fully exposed and executable for management and communication?
- Is the report sufficient for engineering, security, and management review?

---

## 9. Final acceptance rule

The implementation sprints can be individually complete while the product is not yet accepted. Splendor through `0.1-dev` is accepted only when this use-case E2E pack passes as a whole, with evidence that the kernel runtime remains explicit, traceable, fail-closed, local-correct before distributed, primitive-aligned, schema-stable, safe, and non-drifting.
