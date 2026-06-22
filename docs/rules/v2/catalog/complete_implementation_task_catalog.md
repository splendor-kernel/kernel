> **Status:** Active 0.2/v2 catalog of record for component, task, dependency, and gold-evidence decomposition. This file is authoritative for 0.2/v2 sprint planning only after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements the described behavior.

# Splendor Agent Kernel — Complete Implementation Task Catalog

> **Document status:** Complete implementation decomposition at component/contract/task granularity. It is **not** an implementation-complete claim. Every task below remains required until its own validation evidence passes.

## Purpose

This file is the dependency-aware engineering contract for evolving Splendor from its implemented 0.1 runtime foundations into a full kernel substrate for persistent neuro-symbolic agents, data and feedback control, evaluation, flexible-fleet training, physical AI, and governed self-evolution. It is intentionally not organized as generic sprints. Every numbered task has one owning component, concrete contracts, forbidden scope, integration obligations, and executable completion evidence.

The central novelty target is narrow and falsifiable: **make learning/evolution, symbolic control, verified action, feedback/evaluation, and deployment governance interoperable as one kernel-routed process while preserving user-space freedom.** The catalog does not claim that this target is already achieved, that GPT-2 or any learning algorithm is novel, or that value alignment is solved.

## Reviewed 0.1 compatibility anchors

The task decomposition preserves and extends the repository surfaces identified during baseline review: state graph and snapshots, append-only trace/replay, local scheduler/loop engine, action gateway and verifiers, filesystem/HTTP/robotics adapters, daemon/SDK/client, typed messages and local delegation, node/instance and placement foundations, signed work orders, trace aggregation/state handoff/fleet telemetry, governance workflows, and physical/edge simulation contracts.

The following are treated as compatibility anchors rather than reimplemented from zero: existing identity types; `Percept`, `Action`, `Constraint`, `Feedback`, and `Reward`; `LoopEngine`; `Scheduler`; state/trace stores; `VerifiedActionGateway`; work orders and policy bundles; local messages/delegation; node/instance registration and placement v0; governance/approval/circuit-breaker/escalation objects; device profiles and simulated safety.

The reviewed baseline does **not** yet provide the complete workload fabric, artifact/data/evidence services, generic driver profiles, distributed training controller, protected evaluation/data-control plane, improvement/change/gate/deployment lifecycle, or cross-plane incident management specified below.

## Non-negotiable architecture law

1. **One mutation owner per concept.** Stores persist; daemon handlers translate; SDKs call; exporters project. None become shadow owners of service semantics.
2. **One workload grammar.** Agent ticks, inference, training, evaluation, data work, simulation, shell/Python/OCI/Kubernetes jobs, migration, and maintenance are governed `WorkloadSpec`s with different profiles—not separate bypass systems.
3. **Algorithms remain user space.** Model architecture, optimizer, loss, planner, solver, ontology, reward function, evaluator, data transform, parallelism strategy, and domain behavior are plugins/adapters/application code.
4. **Control remains kernel space.** Identity, authority, data purpose, placement, leases, fencing, driver invocation, resource accounting, state/event/evidence integrity, change risk, gates, rollout, rollback, and incidents are kernel contracts.
5. **All side effects cross the gateway.** Filesystem, HTTP, database, shell, Kubernetes, cloud, robot, drone, human workflow, and sub-agent-as-actuator calls have typed proposals, verification, idempotency, receipts, and outcome evidence.
6. **Feedback is not reward; reward is not evaluation; evaluation is not promotion.** Every conversion is versioned, attributable, independently gateable, and linked to source evidence.
7. **Training publishes candidates only.** No trainer, optimizer, improvement agent, or candidate may activate a model, code, route, policy, data, world, or agent revision.
8. **Neuro-symbolic is runtime structure.** Neural decisions, symbolic composition/constraints, boundary verification, and feedback/reward are explicit cooperating paths, not a marketing label or one mandated architecture.
9. **Physical safety remains local where latency demands it.** Splendor governs high-level physical actions and orchestration; it does not replace firmware, motor control, hard-real-time loops, or certification.
10. **Self-evolution is proposal plus evidence plus controlled deployment.** It is never in-place self-modification or self-approval.

## PyTorch compatibility contract

“Arbitrary PyTorch project” has a precise compatibility meaning:

| Tier | What Splendor may do | What Splendor must not claim |
|---|---|---|
| T0 — opaque | Reproduce a locked single-process workload; schedule independent trials, data work, or eval fan-out. | Automatic gradient/state distribution. |
| T1 — torchrun-compatible | Form a compatible worker group, rendezvous, launch, fence epochs, checkpoint/restart, and account data/global work. | That Splendor owns or repairs project distributed semantics. |
| T2 — structured hooks | Wrap declared model/data/optimizer/step/checkpoint hooks with supported DDP/FSDP-style providers. | Universal source rewriting or unchanged numerical behavior without evidence. |
| T3 — explicit parallel plugin | Orchestrate a signed tensor/pipeline/expert/custom/federated plugin and its resources/state. | That one plugin generalizes to arbitrary architectures/devices. |

Synchronous collective groups are compatibility-homogeneous unless an explicit T3 plugin proves otherwise. Heterogeneous devices are still valuable for complementary preprocessing, evaluation, inference, checkpoint conversion, simulation, independent trials, and data-local work.

## Package and responsibility map

| Package | Owned components | Rule |
|---|---|---|
| `crates/splendor-types` | Cross-cutting support surface; see responsibility. | Canonical behavior-free IDs, schemas, enums, receipts, and compatibility serialization. |
| `crates/splendor-kernel` | Cross-cutting support surface; see responsibility. | Composition root, invariant wiring, local compatibility facade, and no provider-specific algorithms. |
| `crates/splendor-authority` | Identity Registry, Authority Service, Secret Broker, Data-Use Controller | Identity, capability authority, secret-reference semantics, and data-use decisions. |
| `crates/splendor-artifacts` | Artifact Registry, Lineage Service | Artifact registry and lineage semantics; byte storage remains behind store/provider interfaces. |
| `crates/splendor-evidence` | Event Log, State Service, Evidence Service, Replay/Simulation Service, Observability Exporter | Event, state semantics, evidence, replay/simulation control, and observability export contracts. |
| `crates/splendor-fabric` | Node Agent, Fleet Scheduler, Workload Controller | Node, fleet placement/scheduling, WorkloadSpec lifecycle, resource leases, epochs, and fencing. |
| `crates/splendor-gateway` | Driver Registry, Driver Gateway, Perceptor Driver Contract and Reference Drivers, Actuator Driver Contract and Reference Drivers, Model Driver Contract and Reference Drivers, Trainer Driver Contract and Framework Adapters, Evaluator Driver Contract and Reference Drivers, Data Operator Driver Contract and Reference Drivers, Sandbox and Executor Driver Contract | Driver registry plus verified invocation protocol; current ActionGateway is a compatibility profile. |
| `crates/splendor-agent` | Agent Registry, Agent Instance Controller, Neuro-Symbolic Route Runtime, World-State and Memory Service, Message and Delegation Service | Agent registry/instances, neuro-symbolic routing, world state/memory, messages, and delegation. |
| `crates/splendor-learning` | Collection Controller, Feedback Service, Reward Derivation Service, Evaluation Controller, Training Controller, Improvement and Evolution Controller | Collection, feedback, reward, evaluation, training flow control, and improvement programs. |
| `crates/splendor-change` | Change Controller, Gate Engine, Deployment Controller, Incident Controller | ChangeSet, gate, deployment, rollback, and incident state machines with separated principals. |
| `crates/splendor-store` | Cross-cutting support surface; see responsibility. | Persistence traits and engines only; no policy, scheduling, gate, or lifecycle decisions. |
| `crates/splendor-daemon` | Cross-cutting support surface; see responsibility. | Authenticated API translation and process composition; no duplicate service state machines. |
| `crates/splendorctl` | Cross-cutting support surface; see responsibility. | Operator/developer CLI that calls public services and supports validate/explain/watch/replay. |
| `binaries/splendor-node` | Cross-cutting support surface; see responsibility. | Resident node agent hosting local execution backends, cache, safety, and fleet protocol. |
| `python/splendor and splendor-train` | Cross-cutting support surface; see responsibility. | Generated clients and user-space authoring hooks for agents, data, eval, and trainers. |
| `typescript/packages/*` | Cross-cutting support surface; see responsibility. | Generated control/inspection/UI clients; no independent runtime semantics. |
| `adapters/*` | Cross-cutting support surface; see responsibility. | Framework, provider, hardware, sandbox, data, model, trainer, evaluator, actuator, perceptor, and exporter implementations. |

## How to read a task

A task is complete only when every required implementation item exists, every anti-drift boundary is respected, every integration is exercised, and every validation condition passes with retained evidence. A type definition or happy-path unit test alone is never completion. Task-level `Required contracts / collaborating tasks` are interface dependencies and may be mutually recursive; contract-first stubs and conformance fixtures break those implementation cycles. The eight dependency gates later in this file define the architectural partial order.

Component sections titled `Implemented baseline to preserve` are compatibility-anchor notes, not standalone acceptance evidence. Treat them as preservation targets that still require current code, test, and validation evidence before making implementation-complete or production-readiness claims.

Component completion gates and validation bullets describe the required future
done state for 0.2/v2 work. Present-tense phrases such as “is implemented,”
“are implemented,” or “pass” in those sections are not current repository
capability claims unless backed by separate current implementation evidence.

**Catalog totals:** 12 cross-cutting foundations; 38 component owners; 350 component tasks; 19 integration/research/operations tasks; **381 total tasks**; 90 gold cases.

## Component coverage index

| # | Component | Plane | Declared owner | Tasks | Current status |
|---:|---|---|---|---:|---|
| 1 | `splendor.identity-registry` — Identity Registry | `identity_authority` | crates/splendor-authority (identity module); schemas in splendor-types; persistence in splendor-store | 6 | partial foundation |
| 2 | `splendor.authority-service` — Authority Service | `identity_authority` | crates/splendor-authority (capability module); verifier integration in splendor-gateway and splendor-kernel | 7 | substantial partial foundation |
| 3 | `splendor.secret-broker` — Secret Broker | `identity_authority` | crates/splendor-authority (secrets module); provider adapters under adapters/secrets-*; node injection in splendor-node | 6 | missing |
| 4 | `splendor.artifact-registry` — Artifact Registry | `artifact_lineage` | crates/splendor-artifacts (registry module); bytes backends via splendor-store/adapters | 7 | missing |
| 5 | `splendor.lineage-service` — Lineage Service | `artifact_lineage` | crates/splendor-artifacts (lineage module); graph persistence in splendor-store | 6 | missing |
| 6 | `splendor.data-use-controller` — Data-Use Controller | `identity_authority` | crates/splendor-authority (data_use module); enforcement hooks in artifacts, fabric, learning, gateway, and node agent | 7 | missing |
| 7 | `splendor.event-log` — Event Log | `event_state_evidence` | crates/splendor-evidence (event module); storage engines in splendor-store | 8 | strong partial foundation |
| 8 | `splendor.state-service` — State Service | `event_state_evidence` | crates/splendor-evidence (state semantics) plus splendor-store (persistence); orchestration hooks in splendor-kernel | 8 | strong partial foundation |
| 9 | `splendor.evidence-service` — Evidence Service | `event_state_evidence` | crates/splendor-evidence (evidence module); schemas in splendor-types | 6 | missing |
| 10 | `splendor.replay-simulation-service` — Replay/Simulation Service | `event_state_evidence` | crates/splendor-evidence (replay module); simulation providers under adapters/simulation-* | 7 | partial foundation |
| 11 | `splendor.node-agent` — Node Agent | `execution_fabric` | crates/splendor-fabric (node_agent module) and `splendor-node` resident binary; host integrations remain adapters | 10 | partial foundation |
| 12 | `splendor.fleet-scheduler` — Fleet Scheduler | `execution_fabric` | crates/splendor-fabric (scheduler module); provider capacity adapters outside core | 11 | partial foundation |
| 13 | `splendor.workload-controller` — Workload Controller | `execution_fabric` | crates/splendor-fabric (workload module) | 10 | missing |
| 14 | `splendor.driver-registry` — Driver Registry | `driver_boundary` | crates/splendor-gateway (registry module) with manifests in splendor-types; concrete drivers remain adapter crates | 6 | missing |
| 15 | `splendor.driver-gateway` — Driver Gateway | `driver_boundary` | crates/splendor-gateway (invocation module); current action gateway preserved as compatibility facade | 9 | partial foundation |
| 16 | `splendor.perceptor-driver` — Perceptor Driver Contract and Reference Drivers | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; concrete providers in `adapters/perceptors/*` | 9 | partial foundation |
| 17 | `splendor.actuator-driver` — Actuator Driver Contract and Reference Drivers | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; concrete implementations in `adapters/actuators/*` | 8 | partial foundation |
| 18 | `splendor.model-driver` — Model Driver Contract and Reference Drivers | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; implementations in `adapters/models/*`; optional Python helpers in `python/splendor` | 10 | missing |
| 19 | `splendor.trainer-driver` — Trainer Driver Contract and Framework Adapters | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; framework adapters in `adapters/trainers/*`; Python integration package `splendor-train` | 10 | missing |
| 20 | `splendor.evaluator-driver` — Evaluator Driver Contract and Reference Drivers | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; implementations in `adapters/evaluators/*` | 8 | missing |
| 21 | `splendor.data-operator-driver` — Data Operator Driver Contract and Reference Drivers | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; implementations in `adapters/data/*` | 9 | missing |
| 22 | `splendor.sandbox-executor-driver` — Sandbox and Executor Driver Contract | `driver_boundary` | contract in crates/splendor-types and splendor-gateway; implementations in `adapters/executors/*` and Node Agent host backends | 13 | partial foundation |
| 23 | `splendor.agent-registry` — Agent Registry | `agent_cognition` | crates/splendor-agent (registry module) | 8 | partial foundation |
| 24 | `splendor.agent-instance-controller` — Agent Instance Controller | `agent_cognition` | crates/splendor-agent (instance module), composed by splendor-kernel | 10 | partial foundation |
| 25 | `splendor.route-runtime` — Neuro-Symbolic Route Runtime | `agent_cognition` | crates/splendor-agent (route module); user-space node plugins via SDK/workloads | 11 | partial foundation |
| 26 | `splendor.world-state-service` — World-State and Memory Service | `agent_cognition` | crates/splendor-agent (world module); persistence interfaces in splendor-store | 12 | missing |
| 27 | `splendor.message-delegation-service` — Message and Delegation Service | `agent_cognition` | crates/splendor-agent (message/delegation module), extending current splendor-kernel message_router/local_delegation/remote_transport | 10 | partial foundation |
| 28 | `splendor.collection-controller` — Collection Controller | `data_learning` | crates/splendor-learning (collection module) | 10 | missing |
| 29 | `splendor.feedback-service` — Feedback Service | `data_learning` | crates/splendor-learning (feedback module) | 10 | partial foundation |
| 30 | `splendor.reward-derivation-service` — Reward Derivation Service | `data_learning` | crates/splendor-learning (reward module) | 9 | partial foundation |
| 31 | `splendor.eval-controller` — Evaluation Controller | `data_learning` | crates/splendor-learning (eval module) | 12 | missing |
| 32 | `splendor.training-controller` — Training Controller | `data_learning` | crates/splendor-learning (training module); PyTorch/framework algorithms stay in trainer adapters and user code | 18 | missing |
| 33 | `splendor.improvement-controller` — Improvement and Evolution Controller | `data_learning` | crates/splendor-learning (improvement module); optimization/search algorithms remain user-space plugins | 10 | missing |
| 34 | `splendor.change-controller` — Change Controller | `change_governance` | crates/splendor-change | 9 | Missing; candidate artifacts and governance objects exist separately, but there is no canonical immutable change unit or dependency-aware change state machine. |
| 35 | `splendor.gate-engine` — Gate Engine | `change_governance` | crates/splendor-change | 10 | Missing as a general evidence-to-promotion engine; current approval verifiers, policy TTL/revocation, constraints, and circuit breakers provide valuable enforcement primitives. |
| 36 | `splendor.deployment-controller` — Deployment Controller | `change_governance` | crates/splendor-change | 12 | Missing as a general progressive deployment service; current run lifecycle, policy cache, state handoff, placement, circuit breakers, and physical offline behavior are foundations only. |
| 37 | `splendor.incident-controller` — Incident Controller | `change_governance` | crates/splendor-change | 9 | Partial foundations only: escalation, circuit breakers, interventions, action denials, trace durability state, and physical safety outcomes exist, but there is no cross-plane incident lifecycle. |
| 38 | `splendor.observability-exporter` — Observability Exporter | `event_state_evidence` | crates/splendor-evidence | 9 | Partial telemetry/trace export exists, but no unified typed metrics/log/trace/evidence export boundary with privacy, cardinality, and non-authority rules. |

---

## Part I — Cross-cutting foundations

### Task 1 — FND-001: Freeze the vNext object and identity grammar

**Anti-drift implementation goal**

Create the canonical serialized grammar on which every later service depends, while preserving the existing 0.1 identities and wire compatibility.

**Required implementation**

1. Add versioned schemas in `crates/splendor-types` for `Principal`, `Scope`, `ArtifactRef`, `EventEnvelope`, `StateCommit`, `WorkloadSpec`, `ExecutionLease`, `DriverManifest`, `Invocation`, `Proposal`, `EvidenceBundle`, `ChangeSet`, and `DeploymentPlan`.
2. Give every object a distinct opaque ID type; explicitly prohibit reuse of run, workload, attempt, worker, artifact, dataset, model, checkpoint, eval, change, deployment, incident, and lease identities.
3. Define canonical serialization, field ordering where hashes depend on bytes, RFC3339 time rules, enum forward-compatibility rules, and content-hash calculation.
4. Define `extensions` as non-authorizing metadata only and reject any extension that attempts to carry identity, capability, approval, secret, data-use, gate, or driver-selection semantics.
5. Generate JSON Schema and language bindings from the Rust source of truth rather than maintaining hand-written divergent schemas.

**Responsibility boundaries: this task must not drift into**

- Do not turn `serde_json::Value` into the permanent public contract for privileged fields; opaque payloads are allowed only behind a named schema and payload reference.
- Do not break the existing `TenantId`, `AgentId`, `RunId`, `TickId`, `ActionId`, `StateNodeId`, `TraceEventId`, `MessageId`, `WorkOrderId`, and approval identities.
- Do not include model architecture, optimizer, planner, ontology, or reward algorithm semantics in foundational types.

**Required integration**

- Add conversion wrappers from 0.1 `TraceEvent`, `ActionRequest`, `Percept`, `Feedback`, `Reward`, `WorkOrder`, and state nodes into vNext envelopes.
- Expose the same schemas through Rust, Python, and TypeScript packages and make daemon API models import generated definitions.

**Validation and definition of done**

- Golden byte fixtures round-trip identically in Rust, Python, and TypeScript.
- Unknown authorizing fields, nil identities, hash mismatches, and cross-type ID reuse fail before persistence or execution.
- Run G00 and compatibility tests against existing 0.1 examples.

**Required contracts / collaborating tasks:** None.

**Gold evidence:** `G00`

### Task 2 — FND-002: Define package ownership and enforce dependency direction

**Anti-drift implementation goal**

Prevent the kernel from becoming a monolith by making package responsibility mechanically enforceable.

**Required implementation**

1. Keep `splendor-types` behavior-free; create or formalize plane crates: `splendor-authority`, `splendor-artifacts`, `splendor-evidence`, `splendor-fabric`, `splendor-agent`, `splendor-learning`, and `splendor-change`.
2. Retain `splendor-kernel` as the composition root and invariant coordinator, not as a home for concrete providers or algorithms.
3. Retain `splendor-gateway` as the driver invocation boundary; concrete filesystem, HTTP, robotics, model, trainer, evaluator, data, and sandbox implementations remain separate adapter crates.
4. Keep persistence engines in `splendor-store`; service crates own policy and state-machine semantics, while stores only persist validated records.
5. Add a dependency-policy check that rejects cycles and imports from adapters into core crates.

**Responsibility boundaries: this task must not drift into**

- Do not create one crate per struct or split packages before their public boundary is stable.
- Do not let daemon handlers own business rules; handlers authenticate, parse, call a service, and translate errors.
- Do not put PyTorch, Kubernetes, Docker, robotics SDKs, model providers, or domain ontologies in core crates.

**Required integration**

- Introduce facade re-exports so existing users of `splendor-kernel` and `splendor-gateway` continue to compile while implementations move.
- Document one owner for every public mutation and add CODEOWNERS/package README responsibility statements.

**Validation and definition of done**

- A static architecture test verifies allowed crate edges and detects duplicate service ownership.
- All current unit/integration tests pass through compatibility re-exports.
- A deliberately misplaced provider dependency fails CI.

**Required contracts / collaborating tasks:** `FND-001`

**Gold evidence:** `G00`

### Task 3 — FND-003: Implement the command–decision–event transaction pattern

**Anti-drift implementation goal**

Give all privileged mutations one consistent ordering model so state, evidence, and side effects cannot disagree silently.

**Required implementation**

1. Define `CommandEnvelope`, `DecisionRecord`, and `MutationReceipt` internal contracts carrying principal, scope, idempotency key, expected state head, causal parents, and requested operation.
2. For each service mutation, validate schema and authority, append required pre-execution events, execute the bounded mutation, persist resulting state/artifact references, and append terminal events.
3. Use an outbox/inbox pattern for cross-service messages so process crashes cannot create an unrecorded committed mutation or a recorded mutation that never becomes visible.
4. Classify event durability requirements: required-before-effect, required-after-effect, best-effort telemetry, and derived/export-only.
5. Define recovery behavior for every crash point and require idempotent resumption or explicit operator intervention.

**Responsibility boundaries: this task must not drift into**

- Do not pretend a distributed multi-store transaction is atomic without a recovery protocol.
- Do not acknowledge a privileged command before its required authorization and pre-effect evidence are durable.
- Do not use log text as the transaction record.

**Required integration**

- Adapt the current loop engine trace-before-action invariant and state-commit failure behavior to the generic command transaction.
- Require artifact, workload, driver, data, eval, training, change, deployment, and incident services to use the same mutation receipt.

**Validation and definition of done**

- Fault injection at every persistence and process boundary yields either no effect, one evidenced effect, or a clearly quarantined uncertain effect.
- G02, G04, G15, G47, G75, and G87 exercise the transaction rules.

**Required contracts / collaborating tasks:** `FND-001`

**Gold evidence:** `G02`, `G04`, `G15`, `G47`, `G75`, `G87`

### Task 4 — FND-004: Create a single error and denial taxonomy

**Anti-drift implementation goal**

Make failures machine-actionable across local runtime, fleet, drivers, data, learning, and deployment without leaking provider-specific ambiguity.

**Required implementation**

1. Define stable categories for invalid input, incompatible schema, unauthenticated, unauthorized, revoked, expired, quota exceeded, unavailable, conflict, stale head, unsafe, uncertain, protected-data denial, integrity failure, timeout, cancellation, preemption, worker failure, driver failure, postcondition failure, and internal invariant violation.
2. Require every public error to carry a stable reason code, retry class, effect certainty (`none`, `known`, `uncertain`), causal event reference, and optional provider detail that is non-authorizing.
3. Map current daemon, gateway, scheduler, state, trace, governance, placement, message, and adapter errors into the taxonomy.
4. Specify which errors fail closed, which permit retry with the same idempotency key, and which require a new authorization.

**Responsibility boundaries: this task must not drift into**

- Do not make human prose the only discriminator.
- Do not expose secrets, protected eval content, raw physical sensor payloads, or provider credentials in error details.
- Do not mark an uncertain side effect as safely retryable.

**Required integration**

- Generate SDK exception types and HTTP/gRPC status mappings from the canonical taxonomy.
- Use the taxonomy in incident classification and scheduler retry policy.

**Validation and definition of done**

- Cross-language fixtures map to the same category and retry/effect semantics.
- Failure-injection examples assert exact reason codes, not substring matching.
- Unknown provider errors are wrapped as non-retryable uncertain failures until classified.

**Required contracts / collaborating tasks:** `FND-001`

**Gold evidence:** `G04`, `G07`, `G87`

### Task 5 — FND-005: Build the conformance and fault-injection harness before new drivers

**Anti-drift implementation goal**

Make every new provider prove lifecycle, isolation, authority, evidence, and cleanup semantics before it can be registered as production-capable.

**Required implementation**

1. Create a reusable harness that can run a service or driver in-process, as a subprocess, on a resident node, and through a remote transport.
2. Provide deterministic faults for timeout, cancellation, dropped acknowledgements, duplicate delivery, stale lease, revoked capability, corrupt artifact, disk full, network partition, worker death, process crash, clock skew, and malformed payload.
3. Define maturity levels `experimental`, `development`, `conformant`, and `certified`; only objective evidence may advance maturity.
4. Persist a signed `ConformanceReport` artifact tied to implementation digest, environment, test suite, and results.
5. Make registry resolution capable of requiring a minimum maturity per operation/risk class.

**Responsibility boundaries: this task must not drift into**

- Do not let a driver self-declare itself certified.
- Do not equate unit test coverage with conformance.
- Do not allow skipped mandatory cases to be reported as pass.

**Required integration**

- Reuse existing adapter and physical simulation fixtures as initial harness targets.
- Make all future model, trainer, evaluator, data, shell, Python, OCI, Kubernetes, and physical drivers consume the harness.

**Validation and definition of done**

- G07 passes for filesystem and HTTP adapters before accepting the harness as stable.
- At least one intentionally faulty driver is rejected for each lifecycle class.
- Reports are reproducible and registry lookup rejects revoked or incompatible evidence.

**Required contracts / collaborating tasks:** `FND-003`, `FND-004`

**Gold evidence:** `G07`

### Task 6 — FND-006: Implement schema migration and compatibility discipline

**Anti-drift implementation goal**

Allow the kernel to evolve for decades without silent semantic drift or flag-day migrations.

**Required implementation**

1. Define compatibility classes: additive non-authorizing, additive authorizing, behavioral, storage, transport, and security-critical.
2. Require an RFC, migration function, downgrade behavior, replay behavior, and fixture update for every authorizing or behavioral change.
3. Implement version negotiation for daemon, node, driver, message, work-order, policy, artifact, and workload protocols.
4. Add online storage migrations with resumable checkpoints and immutable backups for SQLite; define backend-neutral migration traits for later stores.
5. Preserve the stable 0.1 primitive line and provide explicit adapters rather than changing its meanings in place.

**Responsibility boundaries: this task must not drift into**

- Do not use `extensions` to smuggle a new authorization path.
- Do not auto-upgrade a policy/value/data-use meaning without an explicit migration decision.
- Do not discard unknown facts needed for replay or audit.

**Required integration**

- Add compatibility matrices to capability endpoints and driver manifests.
- Run mixed-version node and client tests as part of release qualification.

**Validation and definition of done**

- N-1/N/N+1 schema fixtures have documented accept/reject behavior.
- A rolling upgrade preserves live inference and rejects an incompatible training worker before rendezvous.
- Historical traces and state remain inspectable after migration.

**Required contracts / collaborating tasks:** `FND-001`, `FND-002`

**Gold evidence:** `G00`, `G72`

### Task 7 — FND-007: Define the kernel/user-space privilege boundary in code

**Anti-drift implementation goal**

Ensure arbitrary agent, model, planner, evaluator, and training code stays flexible while every privileged crossing is mediated.

**Required implementation**

1. Introduce internal marker traits or sealed interfaces for privileged commits: authority grant, state-head update, artifact publication, workload lease, driver invocation, feedback/reward acceptance, eval publication, candidate creation, gate decision, and deployment activation.
2. Expose proposal APIs to user space; only service-owned implementations can convert proposals into committed objects.
3. Require driver and workload code to receive scoped handles rather than direct database, secret, registry, or scheduler references.
4. Separate read capabilities from mutation capabilities and training data access from eval data access.
5. Add compile-time and runtime checks that prevent SDK callbacks from constructing trusted receipts or decisions.

**Responsibility boundaries: this task must not drift into**

- Do not sandbox ordinary pure computation unnecessarily.
- Do not make kernel code interpret domain reasoning or chain-of-thought.
- Do not allow a Python object or JSON field named `approved` to become authority.

**Required integration**

- Refactor current `Policy` and `Perceptor` callbacks to return typed proposals/results while the Rust runtime remains the committing authority.
- Apply the boundary to future training, eval, data, world-state, and self-change APIs.

**Validation and definition of done**

- A malicious SDK callback cannot forge an action outcome, state commit, eval pass, capability, or deployment activation.
- G01, G27, G40, G78, G79, and G80 prove the boundary.

**Required contracts / collaborating tasks:** `FND-001`, `FND-003`

**Gold evidence:** `G01`, `G27`, `G40`, `G78`, `G79`, `G80`

### Task 8 — FND-008: Create deterministic fixture, clock, randomness, and payload-reference utilities

**Anti-drift implementation goal**

Provide testable time/randomness and large-payload handling without pretending every neural workload is bitwise deterministic.

**Required implementation**

1. Add injectable monotonic/wall clocks, deterministic UUID/ID factories for tests, seed bundles, and random-stream identifiers.
2. Define determinism classes: bitwise, numerically bounded, statistically equivalent, behaviorally equivalent, and non-deterministic-with-evidence.
3. Move large percepts, model outputs, datasets, checkpoints, and reports into artifact payloads; events carry hashes and bounded summaries.
4. Define canonical environment capture for software versions, accelerator/runtime versions, locale, time zone, and relevant numerical flags.
5. Add stable test factories for tenants, agents, work orders, capabilities, leases, artifacts, workloads, drivers, evals, and changes.

**Responsibility boundaries: this task must not drift into**

- Do not promise bitwise reproducibility across unsupported hardware or collective libraries.
- Do not put unbounded binary/model/sensor payloads in the event log.
- Do not leave seed ownership implicit between controller and worker.

**Required integration**

- Use utilities in replay, training resume, distributed equivalence, eval, simulation, and fault tests.
- Expose determinism claims in artifact and eval manifests.

**Validation and definition of done**

- G03, G39, G42, G52, and G64 distinguish exact from bounded/statistical equivalence.
- Changing a captured environment field changes the evidence/reproducibility fingerprint.
- Oversized event payloads are rejected with an artifact-publication remediation.

**Required contracts / collaborating tasks:** `FND-001`

**Gold evidence:** `G03`, `G39`, `G42`, `G52`, `G64`

### Task 9 — FND-009: Implement policy-independent audit redaction and protected payload handling

**Anti-drift implementation goal**

Keep evidence useful without leaking secrets, private data, hidden evaluations, or physical sensor content.

**Required implementation**

1. Classify every field and payload reference by visibility: public, tenant, restricted, secret, protected-eval, safety-local, and legal-hold.
2. Build deterministic redaction views that preserve object identity, causal shape, reason codes, and hashes while replacing inaccessible payloads.
3. Require access checks on artifact/event/state/evidence reads; possession of an ID or trace reference never grants payload access.
4. Add non-reversible structured summaries for safety evidence and protected eval outcomes.
5. Record every privileged evidence export as its own event and artifact.

**Responsibility boundaries: this task must not drift into**

- Do not redact away the fact that a denial, approval, or protected evaluation occurred.
- Do not store raw secrets and rely on later redaction.
- Do not allow observability exporters to bypass the same read policy.

**Required integration**

- Apply to existing trace export, governance audit export, device trace sync, and future evidence bundles.
- Use the secret broker and data-use controller as policy inputs, not duplicated policy engines.

**Validation and definition of done**

- G08, G35, G82, and G84 verify payload absence and preserved causal evidence.
- Cross-tenant export attempts fail without revealing whether protected content matches a query.
- Redacted and full views retain the same event/artifact identity and integrity chain.

**Required contracts / collaborating tasks:** `FND-001`, `FND-007`

**Gold evidence:** `G08`, `G35`, `G82`, `G84`

### Task 10 — FND-010: Create end-to-end service APIs and idempotent SDK semantics

**Anti-drift implementation goal**

Expose kernel primitives to higher-level code without making the daemon a second source of semantics.

**Required implementation**

1. Define versioned REST/gRPC-neutral service traits first; map them into the existing Axum daemon and TypeScript/Python clients.
2. Require request IDs and idempotency keys for all mutating APIs; define retry and conflict behavior.
3. Add watch/stream APIs with cursors for events, workloads, agents, feedback, evals, training, changes, deployments, and incidents.
4. Return typed references and receipts rather than embedding unbounded artifacts in API responses.
5. Expose capabilities/compatibility endpoints that report implemented profiles and maturity, not aspirational roadmap labels.

**Responsibility boundaries: this task must not drift into**

- Do not implement service logic independently in Rust daemon, Python SDK, and TypeScript client.
- Do not make a dropped HTTP response create duplicate irreversible work.
- Do not report a feature as available because its schema exists.

**Required integration**

- Keep current run, percept, trace, replay, action, device, health, and capability endpoints working through compatibility adapters.
- Add CLI commands only after service contracts and SDK methods are stable.

**Validation and definition of done**

- Contract tests execute the same mutation twice and observe one result/receipt.
- Generated clients pass schema round-trip and mixed-version tests.
- Capability output distinguishes implemented, experimental, simulated, and unavailable surfaces.

**Required contracts / collaborating tasks:** `FND-001`, `FND-004`, `FND-006`

**Gold evidence:** `G00`, `G06`

### Task 11 — FND-011: Establish threat models and security invariants per plane

**Anti-drift implementation goal**

Make security requirements concrete before enabling remote fleet execution, protected evals, self-change, and physical actuation.

**Required implementation**

1. Document assets, principals, trust boundaries, attacker capabilities, and fail-closed decisions for all eight planes.
2. Cover compromised user code, malicious data, prompt injection, compromised worker/node, malicious driver, stolen credential, stale policy, evaluator manipulation, supply-chain tampering, trace deletion, and physical device disconnection.
3. Map each threat to an enforcing component, required event, containment action, and gold test.
4. Define cryptographic agility, key rotation, node attestation extension points, and non-cryptographic safety assumptions.
5. Add a security review checklist required for new authorizing schemas and driver operations.

**Responsibility boundaries: this task must not drift into**

- Do not claim cryptography proves model alignment, data quality, or physical safety.
- Do not rely on prompts as a security boundary.
- Do not make remote production operation depend on the current explicit local insecure-development mode.

**Required integration**

- Feed threat IDs into conformance reports, incident classification, and change risk classification.
- Use current work-order, policy bundle, approval, circuit-breaker, and physical safety primitives as initial controls.

**Validation and definition of done**

- Every G80–G89 attack maps to a named invariant and owning service.
- Red-team tests demonstrate denial/containment without secret or hidden-eval leakage.
- A component cannot graduate to conformant while mandatory threat cases are skipped.

**Required contracts / collaborating tasks:** `FND-005`, `FND-007`, `FND-009`

**Gold evidence:** `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 12 — FND-012: Create performance budgets and reference-scale benchmarks

**Anti-drift implementation goal**

Prevent correctness abstractions from making live agents unusable and prevent background learning from stealing inference/physical-control capacity.

**Required implementation**

1. Define latency budgets for local event append, state commit, authority decision, gateway preflight, model invocation overhead, percept routing, and agent tick admission.
2. Define throughput/scale targets for event ingestion, artifact transfer, scheduler offers, workload transitions, feedback ingestion, eval fan-out, and 1,000-node simulation.
3. Measure control-plane overhead separately from provider/model/training time.
4. Add soak tests for 24/7 agents, backpressure, event compaction, cache churn, lease renewal, and repeated rollout/rollback.
5. Require regression thresholds and captured benchmark environments.

**Responsibility boundaries: this task must not drift into**

- Do not optimize by skipping evidence, authority, or safety checks.
- Do not publish one hardware result as a universal performance guarantee.
- Do not allow unbounded metric cardinality or trace payload growth.

**Required integration**

- Make scheduler interference control consume real measured usage and inference SLO signals.
- Use benchmark reports as gate evidence for kernel releases and driver maturity.

**Validation and definition of done**

- G29, G66, G68, and G74 run under explicit SLOs and resource budgets.
- A background training workload is preempted before configured live inference breach.
- Long-run storage and memory growth remain bounded or trigger explicit retention action.

**Required contracts / collaborating tasks:** `FND-003`, `FND-005`, `FND-008`

**Gold evidence:** `G29`, `G66`, `G68`, `G74`

---

## Part II — Component-owned implementation tasks

## Component 1 — Identity Registry

**Canonical component ID:** `splendor.identity-registry`
**Plane:** `identity_authority`
**Current status:** partial foundation
**Owning package:** `crates/splendor-authority (identity module); schemas in splendor-types; persistence in splendor-store`

**Implemented baseline to preserve**

The repository already has distinct tenant, agent, fleet, node, instance, run, message, work-order, approval, and governance IDs plus node/instance registration types. It does not yet provide a single lifecycle service for human, service, agent, node, device, and governance principals, or proof/rotation/revocation semantics across those identities.

**Exact kernel responsibility**

Own identity existence, attributes, proof bindings, lifecycle, and status. It never grants an operational capability merely because a principal exists; authorization remains the Authority Service.

**Public contracts:** `Principal`, `PrincipalKind`, `PrincipalProof`, `PrincipalBinding`, `PrincipalStatus`, `IdentityRotation`, `IdentityRevocation`, `IdentityQuery`

### Task 1 — IDR-001: Implement the unified principal schema and registry state machine

**Anti-drift implementation goal**

Represent every actor that can own, request, approve, execute, or attest agent work without collapsing identity into authority.

**Required implementation**

1. Define `Principal` with `principal_id`, kind, tenant/fleet ownership, display metadata, proof bindings, created/updated times, and status.
2. Support human, service, agent, runtime instance, node, physical device, governance authority, external provider, and workload identities; keep existing typed IDs as bindings rather than replacing them with strings.
3. Implement transitions `pending -> active -> suspended -> revoked` plus rotation/supersession; reject resurrection of a revoked identity without a new identity.
4. Persist immutable identity history and one mutable current-status pointer with compare-and-swap.

**Responsibility boundaries: this task must not drift into**

- Do not encode permissions, allowed actions, secret refs, or data access in identity metadata.
- Do not merge `AgentId`, `NodeId`, and `InstanceId`; they represent different failure and ownership domains.
- Do not permit a display name or external subject string to be a stable registry key.

**Required integration**

- Map existing tenant/agent/node/instance registration into principal bindings.
- Emit identity lifecycle events into the Event Log and use registry status as an Authority Service input.

**Validation and definition of done**

- Register each principal kind, rotate one proof, suspend and revoke it, then prove old credentials fail.
- Duplicate external subject binding and nil-ID registration fail deterministically.
- G01 and G60 use registry-backed principals.

**Required contracts / collaborating tasks:** `FND-001`, `FND-003`

**Gold evidence:** `G01`, `G60`

### Task 2 — IDR-002: Implement proof binding and authentication adapter contracts

**Anti-drift implementation goal**

Allow Unix-local, mTLS/PKI, OIDC/service-account, device attestation, and external governance identities without hard-coding one provider.

**Required implementation**

1. Define provider-neutral `IdentityProofVerifier` and `AuthenticatedPrincipal` contracts with audience, issuer, subject, key/credential ID, expiry, assurance class, and proof digest.
2. Add local Unix peer credential and test mTLS verifiers first; add OIDC and hardware-attestation providers as out-of-kernel adapters.
3. Bind multiple proofs to one principal with explicit precedence and revocation; prohibit proof metadata from widening tenant/fleet scope.
4. Cache verified proof results only until the earliest credential, key, registry, or policy expiry.

**Responsibility boundaries: this task must not drift into**

- Do not implement an OAuth server in the kernel.
- Do not accept bearer strings from action parameters or prompts.
- Do not treat a successful TLS connection as authorization for an operation.

**Required integration**

- Replace daemon-specific authentication parsing with an authentication adapter followed by registry lookup.
- Node-agent bootstrap and driver/provider calls consume the same authenticated principal result.

**Validation and definition of done**

- Wrong audience, issuer, subject binding, expired proof, rotated key, and revoked principal fail closed.
- Local insecure mode remains explicit and loopback-only.
- A proof cache cannot outlive revocation or expiry.

**Required contracts / collaborating tasks:** `IDR-001`, `FND-011`

**Gold evidence:** `G01`, `G83`

### Task 3 — IDR-003: Implement node and physical-device ownership/attestation lifecycle

**Anti-drift implementation goal**

Distinguish the computer running Splendor from attached physical devices and preserve local safety ownership.

**Required implementation**

1. Extend current node/instance registration with immutable hardware/runtime claims, owner principal, trust domain, attestation refs, and supported execution/safety modes.
2. Represent attached devices as separate principals bound to a node with connection state, calibration artifact refs, local safety-controller identity, and revocation state.
3. Require re-registration after identity key rotation or node reimage; maintain history so old work and traces remain attributable.
4. Define quarantine status that blocks new leases while preserving evidence export and containment commands.

**Responsibility boundaries: this task must not drift into**

- Do not equate Kubernetes node names, IP addresses, or robot serial-number text with authenticated identity.
- Do not allow cloud control to revoke the local emergency-stop authority.
- Do not allow an attached sensor identity to imply actuator authority.

**Required integration**

- Feed node/device status to placement and physical driver resolution.
- Use current `DeviceProfile`, `NodeRegistration`, and heartbeat types as compatibility inputs.

**Validation and definition of done**

- Node reimage creates a new instance binding; stale leases are fenced.
- Compromised-node fixture enters quarantine and cannot publish a trusted checkpoint.
- G73, G74, and G83 preserve device/node separation.

**Required contracts / collaborating tasks:** `IDR-001`, `IDR-002`

**Gold evidence:** `G73`, `G74`, `G83`

### Task 4 — IDR-004: Implement human and governance-principal lifecycle

**Anti-drift implementation goal**

Make HIL approvals, annotations, overrides, and value changes attributable to durable identities and roles without embedding organizational policy in identity.

**Required implementation**

1. Define human/external-governance proof bindings and assurance classes sufficient for approval policies and annotation provenance.
2. Support temporary operator sessions, break-glass session markers, multi-party approval identities, and separation-of-duty facts.
3. Record organization membership as non-authorizing attributes consumed by policy, with explicit freshness and source.
4. Support pseudonymous annotation identities where privacy requires it while retaining auditable provider linkage.

**Responsibility boundaries: this task must not drift into**

- Do not store raw biometric or unnecessary identity-provider payloads.
- Do not let group membership alone grant a capability.
- Do not allow the same principal to satisfy independent proposer and approver roles when policy forbids it.

**Required integration**

- Approval, feedback, annotation, gate, and incident services reference `principal_id` plus proof evidence.
- External governance adapters map identities rather than inventing Splendor approvals.

**Validation and definition of done**

- Two-person value-change flow rejects self-approval and stale membership.
- Annotation provenance remains queryable after pseudonymization.
- G43 and G79 exercise separation of duty.

**Required contracts / collaborating tasks:** `IDR-001`, `IDR-002`

**Gold evidence:** `G43`, `G79`

### Task 5 — IDR-005: Implement registry query, caching, and revocation propagation

**Anti-drift implementation goal**

Make identity status available at high frequency without creating unsafe stale-authority behavior.

**Required implementation**

1. Provide exact-ID lookup, binding lookup, ownership queries, status watches, and revision-numbered snapshots.
2. Implement bounded local caches with negative caching, revision checks, and revocation push; require high-risk operations to refresh when freshness budget expires.
3. Define behavior for registry unavailability by risk class: cached low-risk reads may continue, new privileged leases and physical high-risk actions fail closed.
4. Add fleet-wide revocation fan-out and acknowledgement tracking through node agents.

**Responsibility boundaries: this task must not drift into**

- Do not use eventual consistency as an excuse to accept an indefinitely stale active status.
- Do not make registry reads a global bottleneck for every pure computation.
- Do not hide partial revocation propagation.

**Required integration**

- Authority decisions include identity revision/freshness evidence.
- Incident containment can quarantine a principal and observe propagation status.

**Validation and definition of done**

- Revocation during a long workload prevents renewal/new effects while allowing configured checkpoint/cleanup.
- Partitioned node follows explicit offline policy.
- G88 covers stale offline identity/policy behavior.

**Required contracts / collaborating tasks:** `IDR-001`, `FND-003`

**Gold evidence:** `G88`

### Task 6 — IDR-006: Migrate existing identities without semantic collapse

**Anti-drift implementation goal**

Adopt the registry incrementally while preserving the stable 0.1 contract and historical evidence.

**Required implementation**

1. Create deterministic principal records for existing tenants, agents, nodes, instances, and governance issuers on first use or migration.
2. Store bidirectional compatibility bindings and migration version; never rewrite historical trace IDs.
3. Update daemon, scheduler, gateway, message router, node registry, work-order validation, and physical APIs to resolve principals through the registry.
4. Add a migration audit report listing ambiguous or orphaned bindings and require operator resolution before production enablement.

**Responsibility boundaries: this task must not drift into**

- Do not infer a human or service identity from free-form metadata.
- Do not change historical owner attribution to fit the new model.
- Do not block local development examples that use explicit synthetic principals.

**Required integration**

- Ship dual-read/single-write, then dual-write verification, then registry-required modes behind capability flags.
- Keep old API IDs visible while adding principal refs.

**Validation and definition of done**

- All current examples run after migration.
- Historical replay returns identical tenant/agent/run identities plus optional principal bindings.
- Ambiguous mapping fixture fails migration rather than choosing silently.

**Required contracts / collaborating tasks:** `IDR-001`, `FND-006`

**Gold evidence:** `G00`, `G03`

### Component completion gate

- Every privileged request is attributable to an active principal revision.
- Identity status changes are durable, watchable, and enforced without being confused with authorization.
- Existing stable IDs and historical traces remain valid.

---

## Component 2 — Authority Service

**Canonical component ID:** `splendor.authority-service`
**Plane:** `identity_authority`
**Current status:** substantial partial foundation
**Owning package:** `crates/splendor-authority (capability module); verifier integration in splendor-gateway and splendor-kernel`

**Implemented baseline to preserve**

Current code has tenant policies and quotas, agent isolation ledgers, signed work orders, capability documents, approval evidence, policy bundles, circuit breakers, and scoped local delegation. These are useful controls but not yet one composable capability service covering all workloads, data, models, drivers, state partitions, and self-change.

**Exact kernel responsibility**

Own issuance, evaluation, narrowing, delegation, expiry, revocation, and explanation of operational authority. It does not authenticate identities, execute work, judge model quality, or infer permission from messages/prompts.

**Public contracts:** `CapabilityGrant`, `CapabilityRequest`, `OperationScope`, `ResourceScope`, `DelegationChain`, `AuthorityDecision`, `AuthorityObligation`, `RevocationRecord`

### Task 1 — AUTH-001: Define a composable capability and scope model

**Anti-drift implementation goal**

Replace scattered allowlists with one typed authority grammar that can express agent, workload, data, driver, model, device, state, and change permissions.

**Required implementation**

1. Define operations as namespaced typed verbs bound to resource kinds and schema versions, not arbitrary unvalidated strings.
2. Define scope intersections for tenant, fleet, agent, run, workload, device, data purpose, artifact, state partition, driver operation, time, budget, network, and locality.
3. Represent grants as immutable signed/validated objects with issuer, subject, parent grants, start/expiry, revocation ref, obligations, and maximum delegation depth.
4. Implement deterministic scope intersection and prove child grants cannot broaden any dimension.
5. Preserve current tenant policy, work-order allowed actions/adapters/permissions, and delegated authority as compatibility profiles.

**Responsibility boundaries: this task must not drift into**

- Do not create a universal string wildcard that bypasses typed resource checks.
- Do not infer authority from ownership, message source, model confidence, or policy output.
- Do not combine data read, training use, eval use, and publication into one permission.

**Required integration**

- Gateway, workload admission, artifact reads, state writes, data-use leases, eval access, deployment, and physical actuation call one evaluator.
- Authority decisions become required pre-effect events.

**Validation and definition of done**

- Property tests prove intersection is monotonic and delegation never broadens scope.
- G01 exercises missing, expired, revoked, and wrong-audience grants.
- G18 and G70 exercise narrow sub-agent grants.

**Required contracts / collaborating tasks:** `IDR-001`, `FND-001`, `FND-007`

**Gold evidence:** `G01`, `G18`, `G70`

### Task 2 — AUTH-002: Implement issuance and signed work-order integration

**Anti-drift implementation goal**

Make work orders one issuance vehicle for bounded workload authority rather than a separate parallel authorization system.

**Required implementation**

1. Define an issuer service that validates issuer authority and creates a `CapabilityGrant` or `WorkOrder` envelope with embedded grant refs.
2. Refactor current signed work-order validation to resolve subject principals, scope intersections, data-use refs, placement constraints, quotas, and expiry through authority services.
3. Support one-time, renewable, and non-renewable grants with explicit renewal issuer and maximum lifetime.
4. Attach issuance evidence and canonical reason codes; reject unsigned production/fleet work as currently intended.

**Responsibility boundaries: this task must not drift into**

- Do not make work-order signature validity sufficient if issuer or subject is revoked.
- Do not allow local dev unsigned mode to leak into resident/fleet configurations.
- Do not let placement metadata broaden authority.

**Required integration**

- Workload Controller requires a validated grant before admission.
- Node Agent validates the signed lease/work-order subset independently before execution.

**Validation and definition of done**

- Tampered, expired, revoked, wrong-subject, wrong-runtime-version, and overbroad work orders fail before worker start.
- G60 validates remote task lease issuance.

**Required contracts / collaborating tasks:** `AUTH-001`, `IDR-002`

**Gold evidence:** `G60`, `G83`

### Task 3 — AUTH-003: Implement delegation chains and sub-agent authority narrowing

**Anti-drift implementation goal**

Support persistent, ephemeral, trigger, critic, and actuator sub-agents without implicit parent permission inheritance.

**Required implementation**

1. Create `DelegationGrant` as a capability child with parent run/agent, child principal, objective, allowed messages, state/data/artifact scopes, operations, budget, expiry, and result contract.
2. Validate every chain edge and cap depth, total budget, and fan-out; store the complete chain as evidence.
3. Support revocation/cancellation propagation and child cleanup obligations.
4. Adapt current local delegation manager and message types to require the grant reference for every delegated action or workload.

**Responsibility boundaries: this task must not drift into**

- Do not use a message payload as a permission token.
- Do not proxy the orchestrator credential into a child environment.
- Do not allow a critic or evaluator child to acquire actuation rights accidentally.

**Required integration**

- Message/Delegation Service creates the child relation; Authority Service owns grant validity.
- Agent Instance Controller pauses or cancels children when the parent/grant is revoked according to policy.

**Validation and definition of done**

- G18, G70, and G71 prove no inheritance, bounded budgets, and critic non-actuation.
- A nested child escalation attempt is denied with the chain edge identified.

**Required contracts / collaborating tasks:** `AUTH-001`

**Gold evidence:** `G18`, `G70`, `G71`

### Task 4 — AUTH-004: Implement obligations and approval requirements as authority results

**Anti-drift implementation goal**

Allow decisions to require HIL, sandbox mode, protected evaluator, local safety, logging, or postcondition checks without treating approval as bypass.

**Required implementation**

1. Return `allow`, `deny`, or `conditional` with typed obligations such as approval, MFA/assurance, dedicated isolation, network deny, human review, independent evaluator, local safety verifier, or maximum blast radius.
2. Bind approvals to exact operation, artifact/change/action ID, subject, scope, evidence digest, decision, expiry, and revocation state.
3. Require the caller to satisfy obligations through owning services and re-evaluate authority before effect.
4. Migrate current approval verifier and governance state into this obligation flow while preserving gateway mediation.

**Responsibility boundaries: this task must not drift into**

- Do not let approval replace normal permission, quota, safety, or data-use checks.
- Do not accept free-form “approved” text or a stale approval for a changed payload.
- Do not allow the requester to fabricate obligation completion.

**Required integration**

- Gate Engine can add change-specific obligations; Authority Service remains the source of operational permission.
- Driver Gateway verifies obligation receipts before invocation.

**Validation and definition of done**

- Changed action parameters invalidate approval evidence.
- G11, G43, G75, and G79 cover high-risk and multi-party obligations.

**Required contracts / collaborating tasks:** `AUTH-001`, `IDR-004`

**Gold evidence:** `G11`, `G43`, `G75`, `G79`

### Task 5 — AUTH-005: Implement revocation, lease renewal, and offline authority behavior

**Anti-drift implementation goal**

Make authority safe for 24/7 agents and intermittent devices without pretending connectivity is guaranteed.

**Required implementation**

1. Create revocation records and watches for principals, grants, policies, work orders, driver versions, data-use grants, and deployment versions.
2. Define renewal protocols with nonce/current revision, maximum offline lifetime, and no implicit renewal after scope change.
3. Cache only validated narrowed grants with expiry and pinned safe-degraded behavior by operation/risk class.
4. Permit configured local cleanup/emergency stop when central authority is unavailable; forbid new high-risk effects and self-change.

**Responsibility boundaries: this task must not drift into**

- Do not keep authority valid indefinitely because a device is offline.
- Do not require the cloud for emergency stop or local collision prevention.
- Do not convert “cannot verify” into allow.

**Required integration**

- Node Agent and Policy Cache consume revocation/renewal events.
- Incident Controller can revoke/quarantine and observe acknowledgement lag.

**Validation and definition of done**

- G88 verifies expired offline policy behavior.
- A network partition during low-risk sensing continues only within declared cache scope; high-risk actuation denies.

**Required contracts / collaborating tasks:** `AUTH-001`, `FND-003`

**Gold evidence:** `G73`, `G88`

### Task 6 — AUTH-006: Implement authority decision evidence and explainability

**Anti-drift implementation goal**

Make every allow, deny, or conditional result reproducible without exposing secrets or hidden policy content.

**Required implementation**

1. Record requested operation, principal/grant revisions, evaluated scopes, policy refs, data-use refs, obligations, reason codes, cache freshness, and decision digest.
2. Provide an explanation tree that distinguishes identity failure, scope mismatch, revocation, expiry, quota, data-use, gate, and provider constraints.
3. Support inspect-only re-evaluation against historical policy versions and current-policy comparison without changing history.
4. Expose redacted views for tenants/operators and full restricted views for authorized audit.

**Responsibility boundaries: this task must not drift into**

- Do not log credential or secret material.
- Do not expose protected eval case identifiers through denial explanations.
- Do not recompute a historical decision using only current policy and call it original evidence.

**Required integration**

- Evidence Service bundles authority trees.
- Replay can compare historical and counterfactual authority decisions in non-live mode.

**Validation and definition of done**

- G01 produces deterministic reason trees.
- Historical audit after policy revocation still explains the original decision and current incompatibility.

**Required contracts / collaborating tasks:** `AUTH-001`, `FND-009`

**Gold evidence:** `G01`, `G03`

### Task 7 — AUTH-007: Build authority adversarial/property test suites

**Anti-drift implementation goal**

Prove the capability algebra and all compatibility adapters fail closed under ambiguous or hostile inputs.

**Required implementation**

1. Property-test scope intersection, delegation depth, budget accumulation, time windows, audience binding, and revocation monotonicity.
2. Fuzz serialized grants, work orders, approval evidence, extension fields, and nested delegation chains.
3. Test confused-deputy paths through message routing, sub-agents, driver selection, artifact references, and physical cloud-helper plans.
4. Run cross-version policy and cache-staleness scenarios.

**Responsibility boundaries: this task must not drift into**

- Do not limit tests to happy-path allow decisions.
- Do not mock away signature/audience/expiry checks in fleet tests.
- Do not accept nondeterministic denial codes for the same facts.

**Required integration**

- Make the suite mandatory for any new authorizing schema or operation.
- Publish capability algebra fixtures for external driver/framework authors.

**Validation and definition of done**

- G01, G18, G70, G79, G80, G86, and G88 pass.
- Mutation testing demonstrates that removing any critical check causes a gold failure.

**Required contracts / collaborating tasks:** `AUTH-001`, `AUTH-002`, `AUTH-003`, `AUTH-004`, `AUTH-005`

**Gold evidence:** `G01`, `G18`, `G70`, `G79`, `G80`, `G86`, `G88`

### Component completion gate

- One evaluator answers authority for every privileged plane with typed scopes and deterministic evidence.
- Existing work orders, approvals, tenant policy, and delegation are compatibility profiles, not bypasses.
- Offline and revoked behavior is explicit and tested.

---

## Component 3 — Secret Broker

**Canonical component ID:** `splendor.secret-broker`
**Plane:** `identity_authority`
**Current status:** missing
**Owning package:** `crates/splendor-authority (secrets module); provider adapters under adapters/secrets-*; node injection in splendor-node`

**Implemented baseline to preserve**

The current repository correctly warns against placing credentials in action parameters, but it has no first-class secret reference, lease, provider, injection, redaction, or revocation service.

**Exact kernel responsibility**

Own short-lived secret leases and delivery to a specific isolated boundary. It never exposes secret values to agent state, prompts, events, datasets, generic action parameters, or artifact manifests.

**Public contracts:** `SecretRef`, `SecretLeaseRequest`, `SecretLease`, `SecretDeliveryHandle`, `SecretProvider`, `SecretAccessEvent`

### Task 1 — SECR-001: Define opaque secret references and lease contracts

**Anti-drift implementation goal**

Represent secret use without making secret bytes serializable kernel data.

**Required implementation**

1. Define `SecretRef` as provider/name/version metadata with classification and allowed delivery methods; prohibit embedded value fields.
2. Define lease requests bound to principal, workload, driver operation, node, audience, purpose, start/expiry, and maximum uses.
3. Return an opaque `SecretDeliveryHandle` resolvable only inside the authorized executor/driver process.
4. Create provider traits for fetch, renew, revoke, and audit without importing vendor SDKs into core.

**Responsibility boundaries: this task must not drift into**

- Do not add a `String value` field for convenience.
- Do not allow arbitrary user code to resolve handles outside the declared sandbox.
- Do not treat a secret reference as authorization to use it.

**Required integration**

- Authority Service approves lease requests; Driver Gateway and Sandbox Driver request delivery after placement.
- Artifact/event schemas store refs and access evidence only.

**Validation and definition of done**

- Serialization tests prove no provider response bytes enter kernel objects.
- Wrong workload/node/audience handles fail.
- G08 covers basic leasing.

**Required contracts / collaborating tasks:** `AUTH-001`, `FND-001`

**Gold evidence:** `G08`

### Task 2 — SECR-002: Implement node-local secret delivery mechanisms

**Anti-drift implementation goal**

Deliver secrets to shell, Python, OCI, Kubernetes, model, data, and actuator drivers with the narrowest practical exposure.

**Required implementation**

1. Support inherited file descriptor, tmpfs file, one-shot local socket, and orchestrator-native projected secret mechanisms; environment variables are opt-in high-risk compatibility only.
2. Bind delivery to process/container identity and close/unmount/revoke on completion, cancellation, lease expiry, or node quarantine.
3. Prevent core dumps, debug bundles, stdout/stderr capture, and child-process inheritance unless explicitly allowed.
4. Provide delivery receipts containing mechanism, target identity, timestamps, and value hash commitment where safe, never bytes.

**Responsibility boundaries: this task must not drift into**

- Do not write secrets into OCI image layers, workspace artifacts, command lines, Kubernetes manifests, or persisted environment snapshots.
- Do not make the Node Agent a general secret store.
- Do not promise complete erasure from untrusted code memory; state the isolation boundary honestly.

**Required integration**

- Sandbox and concrete driver adapters consume delivery handles.
- Node Agent enforces cleanup and reports uncertain cleanup as an incident-worthy fact.

**Validation and definition of done**

- G08 and G82 scan events, artifacts, logs, process args, and captured environments for canary secrets.
- Cancellation and crash tests verify handle closure/unmount.

**Required contracts / collaborating tasks:** `SECR-001`, `NODE-003`, `SBX-001`

**Gold evidence:** `G08`, `G82`

### Task 3 — SECR-003: Implement rotation, revocation, and bounded renewal

**Anti-drift implementation goal**

Support long-lived agents without long-lived exposed credentials.

**Required implementation**

1. Renew leases through the broker using current workload/driver identity and authority, with a maximum continuous lifetime.
2. Handle provider rotation by creating a new delivery handle and invalidating the old one without changing artifact manifests.
3. Push revocation to node agents and deny new uses; define behavior for in-flight irreversible calls explicitly.
4. Record provider-unavailable and revocation-uncertain states without leaking existence across tenants.

**Responsibility boundaries: this task must not drift into**

- Do not auto-renew after capability, workload lease, or data-use expiry.
- Do not reuse a secret lease across worker attempts or sub-agents by default.
- Do not retry an uncertain irreversible operation merely because a new secret was issued.

**Required integration**

- Workload Controller owns retry attempt identity; each attempt requests its own lease.
- Incident Controller may revoke by secret ref, principal, driver, node, or deployment scope.

**Validation and definition of done**

- Rotate during a 24/7 model service with no request receiving both old and new credentials.
- Revocation during partition follows explicit offline policy.

**Required contracts / collaborating tasks:** `SECR-001`, `AUTH-005`

**Gold evidence:** `G08`, `G88`

### Task 4 — SECR-004: Implement secret-safe telemetry, redaction, and leak detection

**Anti-drift implementation goal**

Make accidental leaks detectable while ensuring the detection system does not replicate secrets.

**Required implementation**

1. Register per-lease canary fingerprints or keyed detectors in a restricted node-local redaction service.
2. Scan captured stdout/stderr, command metadata, event summaries, artifact metadata, and model prompt construction paths before persistence.
3. Replace detected values with stable leak tokens, fail the operation or quarantine output by policy, and open an incident with restricted evidence.
4. Maintain false-positive-safe matching for structured credentials and user-provided data.

**Responsibility boundaries: this task must not drift into**

- Do not send raw secrets to a central scanning service.
- Do not claim absence from arbitrary encrypted/compressed user payloads unless inspected under policy.
- Do not silently redact and mark the workload successful.

**Required integration**

- Integrate with Event Log append, Artifact Registry publication, Sandbox output capture, and Observability Exporter.
- Incident Controller receives leak events and can revoke affected leases.

**Validation and definition of done**

- G82 includes plain, encoded, split, and log-injection attempts.
- Leak evidence identifies source process/output without revealing the secret.

**Required contracts / collaborating tasks:** `SECR-002`, `FND-009`

**Gold evidence:** `G82`

### Task 5 — SECR-005: Implement provider adapters and high-availability semantics

**Anti-drift implementation goal**

Support local development and production secret managers without baking one vendor into Splendor.

**Required implementation**

1. Provide an in-memory deterministic test provider and a local file/OS keychain provider restricted to development.
2. Define adapter contracts for Vault/KMS/cloud/Kubernetes providers with provider-specific code out of core.
3. Implement provider health, latency, retry, circuit breaking, and audit correlation; never cache beyond lease rules.
4. Support multiple providers per tenant with explicit routing policy and no fallback that broadens scope.

**Responsibility boundaries: this task must not drift into**

- Do not ship a production default master key in the repository or image.
- Do not fall back from an unavailable restricted provider to a less trusted provider automatically.
- Do not place provider SDK error payloads directly in public traces.

**Required integration**

- Driver Registry tracks provider adapter maturity.
- Node Agent can use a configured local device keystore for safety-critical offline credentials.

**Validation and definition of done**

- Conformance tests cover outage, stale cache, wrong provider version, and cross-tenant reference.
- Provider failover only occurs where the same scope/trust policy explicitly permits it.

**Required contracts / collaborating tasks:** `SECR-001`, `FND-005`

**Gold evidence:** `G07`, `G08`

### Task 6 — SECR-006: Add secret handling to every external contract and gold example

**Anti-drift implementation goal**

Eliminate ambient credentials from examples, SDKs, and drivers so the safe path is the normal path.

**Required implementation**

1. Replace direct token/password fields in proposed shell, Python, OCI, Kubernetes, HTTP, database, model, data-source, and artifact-publication examples with `SecretRef`.
2. Add SDK helpers for requesting secret use without reading values.
3. Document which user-space code sees a delivered secret and how to avoid prompt/model exposure.
4. Add CI scanners for committed fixture secrets and manifests that embed values.

**Responsibility boundaries: this task must not drift into**

- Do not make examples depend on real cloud credentials.
- Do not obscure the fact that some user code legitimately receives a secret inside its sandbox.
- Do not allow tests to pass only because dummy values are ignored.

**Required integration**

- Update G10–G17, G53, G73–G75, and G82 manifests.
- Make driver authoring documentation require secret-delivery declaration.

**Validation and definition of done**

- Every relevant example runs with canary secrets and proves scoped delivery/cleanup.
- Static validation rejects secret-like fields in authorizing schemas.

**Required contracts / collaborating tasks:** `SECR-001`, `SECR-002`, `SECR-004`

**Gold evidence:** `G08`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G53`, `G73`, `G74`, `G75`, `G82`

### Component completion gate

- Secret values never enter durable kernel objects or generic user-visible traces.
- Every use is scoped to one principal/workload/operation/boundary and expires.
- Leak, rotation, crash, and revocation paths are tested.

---

## Component 4 — Artifact Registry

**Canonical component ID:** `splendor.artifact-registry`
**Plane:** `artifact_lineage`
**Current status:** missing
**Owning package:** `crates/splendor-artifacts (registry module); bytes backends via splendor-store/adapters`

**Implemented baseline to preserve**

The current state and trace stores persist JSON/state snapshots, and examples refer to governed artifacts, but there is no general immutable registry for datasets, code, environments, models, checkpoints, eval suites/reports, policies, routes, world snapshots, deployment bundles, or large event payloads.

**Exact kernel responsibility**

Own immutable artifact identity, integrity, metadata, storage location, access classification, retention, replication, and publication lifecycle. It never decides quality, promotion, or deployment.

**Public contracts:** `ArtifactRef`, `ArtifactManifest`, `ArtifactKind`, `ArtifactUploadSession`, `ArtifactReplica`, `ArtifactAttestation`, `ArtifactTombstone`

### Task 1 — ART-001: Define artifact kinds, manifests, and content identity

**Anti-drift implementation goal**

Make every material input/output of agent evolution immutable and addressable without constraining its modality or format.

**Required implementation**

1. Define artifact kinds for opaque blob, record shard, dataset snapshot, code bundle, source revision, environment lock, OCI image, model, tokenizer/processor, checkpoint, adapter, eval suite, eval report, policy/value bundle, route, world snapshot/rollout, evidence bundle, deployment bundle, and incident package.
2. Use content digest plus manifest digest; distinguish logical artifact ID from physical replica URI and mutable human tags.
3. Require media type/schema, size, creator principal/workload, classification, creation time, compatibility metadata, and parent lineage refs.
4. Support multipart/manifest artifacts for sharded datasets/checkpoints while preserving a stable root digest.

**Responsibility boundaries: this task must not drift into**

- Do not encode modality-specific tensors or domain ontologies in the registry core.
- Do not use mutable URI/tag as identity.
- Do not make an artifact reference confer read authority.

**Required integration**

- Replace large trace/state payload embedding with artifact refs.
- Training, eval, data, model, route, and deployment services publish typed manifests.

**Validation and definition of done**

- Hash mutation and mismatched manifest/payload fail.
- Cross-language manifest fixtures round-trip.
- G05 validates identity versus authority.

**Required contracts / collaborating tasks:** `FND-001`, `FND-008`

**Gold evidence:** `G05`

### Task 2 — ART-002: Implement transactional publication and quarantine

**Anti-drift implementation goal**

Prevent partially uploaded or unverified data/models/checkpoints from appearing as valid artifacts.

**Required implementation**

1. Implement upload sessions with expected digest/size, temporary storage, chunk verification, resumable offsets, and terminal commit/abort.
2. On commit, verify full root digest, schema/manifest rules, authority, data-use obligations, and required producer evidence before making the artifact discoverable.
3. Publish suspicious, incomplete, or policy-blocked objects into a non-readable quarantine namespace with explicit reason and retention.
4. Make publication idempotent by content/manifest digest and retain separate producer attestations for identical bytes.

**Responsibility boundaries: this task must not drift into**

- Do not expose partial uploads through normal lookup.
- Do not overwrite an existing digest with new bytes or metadata.
- Do not call a quarantined artifact a failed upload and discard its forensic evidence automatically.

**Required integration**

- Use command–decision–event transaction and lineage edge publication atomically/recoverably.
- Node Agent uploads outputs/checkpoints through sessions.

**Validation and definition of done**

- Crash at each upload stage yields resumable temp state or no published artifact.
- Corrupt chunk/manifest fixtures quarantine.
- G17 and G69 cover publication/recovery.

**Required contracts / collaborating tasks:** `ART-001`, `FND-003`

**Gold evidence:** `G17`, `G69`

### Task 3 — ART-003: Implement access, retention, legal hold, and deletion semantics

**Anti-drift implementation goal**

Control artifact payload access and lifecycle without rewriting immutable history.

**Required implementation**

1. Authorize reads through principal, capability, classification, tenant, data-use purpose, locality, and protected-eval policy.
2. Represent retention deadlines, legal holds, source deletion obligations, and derived-artifact impact through metadata/obligation records.
3. Implement tombstones and cryptographic/storage deletion receipts while preserving non-sensitive lineage facts and hashes where lawful.
4. Prevent an expired/tombstoned payload from being newly mounted into workloads; define reproducibility reports that explain missing governed inputs.

**Responsibility boundaries: this task must not drift into**

- Do not delete lineage/evidence silently to make a report look complete.
- Do not assume hash-only metadata is always non-sensitive.
- Do not grant read because a workload produced or referenced the artifact.

**Required integration**

- Data-Use Controller supplies purpose/retention decisions.
- Evidence Service reports unavailable payloads honestly.

**Validation and definition of done**

- Cross-purpose and cross-tenant reads deny.
- Retention expiry during a workload follows lease semantics and prevents reuse.
- G26, G34, and G35 exercise lifecycle/access separation.

**Required contracts / collaborating tasks:** `ART-001`, `AUTH-001`, `DUC-001`

**Gold evidence:** `G26`, `G34`, `G35`

### Task 4 — ART-004: Implement signatures, attestations, and supply-chain metadata

**Anti-drift implementation goal**

Make code, environment, image, driver, model, checkpoint, and deployment artifacts verifiable back to their producers and build inputs.

**Required implementation**

1. Define detached attestation objects for producer identity, workload, builder/executor, source digest, environment, test/conformance evidence, and signature.
2. Support SLSA-compatible provenance and OCI/SBOM references without requiring those formats internally for every artifact.
3. Verify signatures and trusted builder/producer policy on artifact admission, driver registration, node execution, and deployment.
4. Support key rotation/revocation and distinguish artifact integrity from producer trust or model quality.

**Responsibility boundaries: this task must not drift into**

- Do not treat a valid signature as proof that a model is safe or an eval passed.
- Do not accept floating image tags as attested deployment inputs.
- Do not let the producer attest its own independent gate result.

**Required integration**

- Driver Registry consumes conformance/build attestations.
- Change and Deployment Controllers require exact signed artifacts according to risk.

**Validation and definition of done**

- Tampered source/image/checkpoint and revoked signer fixtures deny.
- G17 and G83 cover publication and compromised-worker artifacts.

**Required contracts / collaborating tasks:** `ART-001`, `IDR-002`, `FND-011`

**Gold evidence:** `G17`, `G83`

### Task 5 — ART-005: Implement replication, caching, locality, and integrity repair

**Anti-drift implementation goal**

Move large datasets/models/checkpoints across heterogeneous fleets without confusing cache presence with trust or authority.

**Required implementation**

1. Track replicas by digest, backend, region/node, health, verification time, encryption/classification, and eviction policy.
2. Implement resumable transfer with chunk hashes, bandwidth limits, locality policy, and post-transfer root verification.
3. Add node-local read-only caches keyed by digest and lease; verify before mount and after suspicious failures.
4. Quarantine corrupt replicas, select another authorized replica, and repair only from a verified source.

**Responsibility boundaries: this task must not drift into**

- Do not replicate restricted/protected data outside locality policy.
- Do not trust filesystem existence or filename as integrity.
- Do not let cache eviction delete the last retained artifact unknowingly.

**Required integration**

- Fleet Scheduler uses replica/locality data for placement.
- Node Agent reports cache inventory and transfer progress.

**Validation and definition of done**

- G62 and G69 validate locality-aware placement, resume, digest verification, and corrupt replica quarantine.
- Interrupted transfer never appears mounted as complete.

**Required contracts / collaborating tasks:** `ART-002`, `DUC-003`

**Gold evidence:** `G62`, `G69`

### Task 6 — ART-006: Implement registry query, tags, collections, and compatibility resolution

**Anti-drift implementation goal**

Make artifacts discoverable without allowing mutable convenience metadata to alter immutable meaning.

**Required implementation**

1. Provide exact lookup, lineage parent/child queries, kind/schema filters, producer/run queries, and access-filtered search.
2. Implement mutable aliases/tags as separately versioned pointers with authority and audit; deployment activation pointers remain owned by Deployment Controller.
3. Support artifact collections/manifests for dataset shards, model bundles, eval suites, and deployment bundles.
4. Implement compatibility predicates for model/tokenizer, checkpoint/code, route/agent schema, driver/runtime, and state migration refs; the owning service decides acceptance.

**Responsibility boundaries: this task must not drift into**

- Do not permit a tag update to change a running workload or deployment implicitly.
- Do not return inaccessible artifact existence/details in broad search.
- Do not put deployment or gate state inside registry tags.

**Required integration**

- SDK exposes refs and signed download/mount requests.
- Agent/Training/Eval/Deployment controllers resolve exact versions at plan admission and pin them.

**Validation and definition of done**

- Concurrent tag updates use CAS and are audited.
- Pinned workloads remain on original digest after alias movement.
- G53 and G55 verify bundle compatibility.

**Required contracts / collaborating tasks:** `ART-001`, `AUTH-001`

**Gold evidence:** `G53`, `G55`

### Task 7 — ART-007: Migrate existing state snapshots, trace exports, and governed refs

**Anti-drift implementation goal**

Adopt artifact identity without rewriting historical runtime evidence or breaking local stores.

**Required implementation**

1. Add artifact-backed variants for current state snapshot payloads, trace export bundles, policy bundles, device profiles, and governance audit exports.
2. Create deterministic manifests for existing persisted objects when possible; mark legacy non-content-addressed objects explicitly when not.
3. Backfill artifact refs lazily with an audit report and preserve original hashes/locations.
4. Update SQLite schemas and backup/restore tools for artifact metadata and upload sessions.

**Responsibility boundaries: this task must not drift into**

- Do not claim legacy payload reproducibility when bytes/environment are unavailable.
- Do not rewrite historical trace sequence or state node hash.
- Do not require migrating all large payloads before local runtime continues.

**Required integration**

- Dual-read legacy and artifact-backed records; new vNext producers publish artifacts by default.
- Replay/Evidence understands both with explicit confidence.

**Validation and definition of done**

- Migration round-trip preserves current examples and trace/state inspection.
- Legacy missing payload yields an honest incomplete evidence result.

**Required contracts / collaborating tasks:** `ART-001`, `FND-006`

**Gold evidence:** `G03`, `G05`

### Component completion gate

- Every durable model/data/code/environment/eval/checkpoint/change input or output is immutable and integrity-checked.
- Artifact reference never implies authority, quality, or activation.
- Partial/corrupt/revoked artifacts cannot enter normal execution silently.

---

## Component 5 — Lineage Service

**Canonical component ID:** `splendor.lineage-service`
**Plane:** `artifact_lineage`
**Current status:** missing
**Owning package:** `crates/splendor-artifacts (lineage module); graph persistence in splendor-store`

**Implemented baseline to preserve**

Current traces link actions, state, messages, child runs, work orders, and approvals, but there is no general derivation graph connecting data records/snapshots, code, environments, models, checkpoints, evals, reward derivations, routes, world models, changes, and deployments.

**Exact kernel responsibility**

Own immutable derivation and usage relationships among principals, activities/workloads, and artifacts. It never assigns quality or rewrites producer history.

**Public contracts:** `LineageEdge`, `LineageRelation`, `ProducerActivity`, `UsageRecord`, `LineageClosure`, `ReproducibilityGraph`

### Task 1 — LIN-001: Define the lineage relation model and invariants

**Anti-drift implementation goal**

Capture enough derivation to reproduce and assess every agent evolution artifact while remaining domain and modality agnostic.

**Required implementation**

1. Model `used`, `generated`, `derived_from`, `was_revision_of`, `evaluated`, `trained_on`, `validated_by`, `deployed_as`, `observed_by`, `reward_derived_from`, and `superseded` relations.
2. Represent activities as workload/driver/change/deployment identities with exact attempt and environment refs.
3. Require relation schema, role, event time, producer, causal event, and optional transform/config artifact.
4. Enforce immutability, tenant/classification consistency, no self-derivation cycles, and explicit cross-tenant sharing grants.

**Responsibility boundaries: this task must not drift into**

- Do not use file paths or tags as lineage nodes.
- Do not collapse “used during inference” and “trained on” into the same edge.
- Do not infer lineage from naming conventions after the fact when the producer can declare it transactionally.

**Required integration**

- Use W3C PROV concepts for interoperability but keep Splendor-specific typed relations.
- Artifact Registry publication requires producer edges.

**Validation and definition of done**

- Cycle, missing producer, illegal cross-tenant, and relation/schema confusion fixtures fail.
- G05 and G39 validate complete derivation.

**Required contracts / collaborating tasks:** `ART-001`, `FND-001`

**Gold evidence:** `G05`, `G39`

### Task 2 — LIN-002: Publish lineage transactionally from every producer

**Anti-drift implementation goal**

Eliminate best-effort after-the-fact lineage that can diverge from artifact publication.

**Required implementation**

1. Add a `ProducerReceipt` containing declared inputs, transform/code/environment/config, outputs, and activity identity.
2. Commit output artifact visibility and required lineage edges as one recoverable publication transaction.
3. Require data operators, trainers, evaluators, model conversions, reward derivations, simulations, builds, and deployment packaging to use producer receipts.
4. Reject production-grade artifacts with incomplete mandatory lineage; permit explicit experimental/incomplete classification only where policy allows.

**Responsibility boundaries: this task must not drift into**

- Do not let workers edit lineage after publication.
- Do not accept a training checkpoint without exact dataset snapshot and code/environment refs.
- Do not silently drop lineage when one backend is unavailable.

**Required integration**

- Workload Controller aggregates worker outputs and submits the authoritative producer receipt.
- Event Log records publication decision and recovery.

**Validation and definition of done**

- Crash/failure injection never yields a visible output without required edges.
- G50–G59 inspect candidate lineage.

**Required contracts / collaborating tasks:** `LIN-001`, `ART-002`, `FND-003`

**Gold evidence:** `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`

### Task 3 — LIN-003: Implement lineage closure and impact queries

**Anti-drift implementation goal**

Answer what produced an artifact, what consumed protected data, and what must be reevaluated or revoked after a change.

**Required implementation**

1. Provide bounded ancestor/descendant, relation-filtered, time-windowed, and classification-aware graph queries.
2. Implement impact analysis for revoked data/source, compromised worker/driver, vulnerable environment, changed eval suite, or invalid checkpoint.
3. Return partial/completeness indicators when history is legacy, deleted, or access-restricted.
4. Add pagination and cycle/size guards suitable for long-lived evolution graphs.

**Responsibility boundaries: this task must not drift into**

- Do not leak protected ancestor identities through query cardinality or error details.
- Do not assume all descendants are invalid; return relation and policy facts for owning controllers.
- Do not make graph traversal an unbounded synchronous daemon request.

**Required integration**

- Change/Incident/Data-Use controllers consume impact queries.
- CLI provides inspect-only `lineage explain` and `lineage impact`.

**Validation and definition of done**

- A revoked training record identifies affected datasets/checkpoints/candidates/deployments without exposing protected eval cases.
- G35 and G83 exercise impact paths.

**Required contracts / collaborating tasks:** `LIN-001`, `ART-003`

**Gold evidence:** `G35`, `G83`

### Task 4 — LIN-004: Build reproducibility and evidence graph materialization

**Anti-drift implementation goal**

Materialize the exact minimal graph needed to rerun or audit a workload/change without copying the entire fleet history.

**Required implementation**

1. Create `ReproducibilityGraph` containing pinned inputs, code/environment, driver versions, workload plan, seed/determinism class, outputs, and relevant state/event ranges.
2. Include unavailable/restricted nodes as typed placeholders with reason and access path.
3. Support export as a signed artifact and import into an isolated test environment without granting original authority.
4. Compute a graph digest used by eval, gate, and novelty reports.

**Responsibility boundaries: this task must not drift into**

- Do not include live credentials or authority grants as reusable permissions.
- Do not claim reproducibility when required payloads are missing.
- Do not let an imported graph execute side effects by default.

**Required integration**

- Evidence and Replay services consume the graph.
- Gold runners publish a graph with every result.

**Validation and definition of done**

- G03, G39, G42, G52, and G64 verify complete or explicitly incomplete graphs.
- Imported graphs run only with new local authority and non-live drivers.

**Required contracts / collaborating tasks:** `LIN-001`, `LIN-002`, `FND-008`

**Gold evidence:** `G03`, `G39`, `G42`, `G52`, `G64`

### Task 5 — LIN-005: Implement lineage integrity, signing, and anti-tamper checks

**Anti-drift implementation goal**

Prevent a worker or candidate from rewriting its data/eval/producer history to pass gates.

**Required implementation**

1. Hash lineage edge content and bind edges to producer receipts, events, and artifact manifests.
2. Verify worker-supplied declarations against controller-known mounts/inputs, environment, and output upload sessions.
3. Sign or integrity-chain restricted producer receipts at the trusted controller/node boundary.
4. Quarantine inconsistent outputs and open an incident for attempted lineage manipulation.

**Responsibility boundaries: this task must not drift into**

- Do not trust training/eval code to self-report protected data access completely.
- Do not treat a signature from a compromised worker as sufficient without node/workload binding.
- Do not mutate bad lineage into a corrected story; supersede with explicit correction evidence.

**Required integration**

- Node Agent reports actual mounted artifact leases; Workload Controller reconciles declarations.
- Gate Engine requires verified lineage status.

**Validation and definition of done**

- G83 and G85 reject invalid checkpoint/reward lineage.
- A candidate that omits a mounted dataset cannot publish a conformant candidate.

**Required contracts / collaborating tasks:** `LIN-002`, `ART-004`, `NODE-003`

**Gold evidence:** `G83`, `G85`

### Task 6 — LIN-006: Provide interoperability mappings without diluting kernel semantics

**Anti-drift implementation goal**

Allow export/import with W3C PROV, OpenLineage, SLSA, and OCI metadata while retaining Splendor authority and AI-specific distinctions.

**Required implementation**

1. Implement one-way and round-trip mappings for the common entity/activity/agent subset and document information loss.
2. Map build/code/image attestations to SLSA/OCI refs and data job lineage to OpenLineage where possible.
3. Keep data-use, protected eval, reward derivation, change/gate, deployment, and agent-route relations as Splendor extensions.
4. Validate imported provenance as untrusted claims until corroborated by trusted receipts.

**Responsibility boundaries: this task must not drift into**

- Do not make external provenance an authority grant.
- Do not collapse `evaluated` and `trained_on` because an external schema lacks the distinction.
- Do not claim lossless round-trip when it is not.

**Required integration**

- Observability/export adapters publish external formats.
- Artifact/lineage imports retain source and trust classification.

**Validation and definition of done**

- Mapping fixtures preserve all common fields and list lost extensions.
- Imported forged provenance cannot satisfy a promotion gate.

**Required contracts / collaborating tasks:** `LIN-001`, `LIN-005`

**Gold evidence:** `G05`, `G17`

### Component completion gate

- Every published derived artifact has a transactionally bound producer and input graph.
- Training, evaluation, inference, and deployment usage remain distinguishable.
- Impact and reproducibility queries are access-controlled and honest about incompleteness.

---

## Component 6 — Data-Use Controller

**Canonical component ID:** `splendor.data-use-controller`
**Plane:** `identity_authority`
**Current status:** missing
**Owning package:** `crates/splendor-authority (data_use module); enforcement hooks in artifacts, fabric, learning, gateway, and node agent`

**Implemented baseline to preserve**

Current tenants and work orders can carry `data_refs`, and placement has a locality hint, but the kernel does not model collection consent/license, purpose limitation, retention, training versus eval use, derived-data obligations, subject deletion, or protected-holdout access.

**Exact kernel responsibility**

Own whether data may be collected, stored, transformed, viewed, used for inference, training, evaluation, feedback/reward derivation, publication, or incident analysis under purpose/locality/retention rules. It does not implement curation algorithms.

**Public contracts:** `DataClass`, `DataPurpose`, `DataUsePolicy`, `DataUseRequest`, `DataUseGrant`, `DataAccessLease`, `RetentionObligation`, `DeletionImpact`

### Task 1 — DUC-001: Define data classification, purpose, and use operations

**Anti-drift implementation goal**

Make data permissions explicit enough for continual learning, protected eval, feedback, and physical sensors without imposing a domain schema.

**Required implementation**

1. Define classifications for public, tenant-private, personal, sensitive, secret, licensed, synthetic, protected-eval, safety-local, and custom policy labels.
2. Define operations separately: collect, persist, inspect, transform, label, deduplicate, train, tune, derive reward, evaluate, infer, export, publish, share, retain, delete, and incident-analyze.
3. Define purposes as versioned policy artifacts with controller/owner, lawful/contractual basis refs where applicable, allowed audiences, locality, retention, and derivation obligations.
4. Attach source/subject/license/consent/provenance refs without forcing raw personal content into policy records.

**Responsibility boundaries: this task must not drift into**

- Do not assume readable data is trainable data.
- Do not treat “research” or “future use” as an unbounded default purpose.
- Do not hard-code jurisdictional legal conclusions into the kernel; expose enforceable policy inputs and obligations.

**Required integration**

- Artifact manifests and Percept/Feedback records carry classifications/purpose refs.
- Authority Service intersects capability and data-use decisions.

**Validation and definition of done**

- G30 and G34 deny undeclared persistence/training even when source access exists.
- Schema supports text, image, audio, video, sensor, action, code, and arbitrary record payload refs.

**Required contracts / collaborating tasks:** `FND-001`, `AUTH-001`, `ART-001`

**Gold evidence:** `G30`, `G34`

### Task 2 — DUC-002: Implement data-use decision and grant issuance

**Anti-drift implementation goal**

Issue bounded, auditable grants for exact datasets/shards/streams and workload purposes.

**Required implementation**

1. Evaluate requester principal, operation, purpose, data classes, source policy, consent/license, audience, locality, time, retention, and downstream derivation plan.
2. Return allow/deny/conditional obligations such as redaction, aggregation, local execution, no raw export, human review, or deletion propagation.
3. Bind grants to immutable dataset/artifact refs or collection source selectors with maximum record/time volume.
4. Sign/version decisions and support revocation or policy supersession.

**Responsibility boundaries: this task must not drift into**

- Do not let a collection/training controller issue its own data permission.
- Do not allow a wildcard source selector without volume/time/purpose bounds.
- Do not silently broaden a grant when a dataset snapshot gains records.

**Required integration**

- Collection, Artifact, Eval, Training, Feedback, Reward, and Sandbox services request grants before data mounting/persistence.
- Work orders carry grant refs, not unverified data refs alone.

**Validation and definition of done**

- Wrong purpose, changed snapshot, expired consent/license, and cross-locality use fail.
- G34 exercises incompatible purpose despite readability.

**Required contracts / collaborating tasks:** `DUC-001`, `AUTH-001`

**Gold evidence:** `G34`, `G84`

### Task 3 — DUC-003: Implement data access leases and mount-level enforcement

**Anti-drift implementation goal**

Translate policy decisions into concrete, time-bounded access on nodes and sandboxes.

**Required implementation**

1. Create `DataAccessLease` bound to workload attempt, node, artifact/shard/stream, allowed operations, mount/read API, expiry, and audit requirements.
2. Node Agent exposes read-only scoped mounts or brokered streams; protected eval leases are resolvable only by evaluator-driver identities.
3. Record bytes/records accessed, locality, and lease close/expiry; reconcile actual mounts with lineage declarations.
4. Deny copying to unauthorized output artifacts or child workloads unless a derived-data grant exists.

**Responsibility boundaries: this task must not drift into**

- Do not pass raw storage credentials to training code.
- Do not rely only on path conventions for protected data isolation.
- Do not allow a trainer to request an evaluator lease through user-provided role text.

**Required integration**

- Fleet Scheduler places within locality; Node Agent and Sandbox Driver enforce the lease.
- Lineage records actual use.

**Validation and definition of done**

- G36 and G84 prove trainer/candidate cannot read protected cases or answers.
- Lease expiry and node compromise close/newly deny access.

**Required contracts / collaborating tasks:** `DUC-002`, `NODE-003`, `SBX-007`

**Gold evidence:** `G36`, `G84`

### Task 4 — DUC-004: Implement retention, deletion, and derivation impact handling

**Anti-drift implementation goal**

Carry source obligations into snapshots, derived datasets, checkpoints, and deployments without pretending all learned influence can be perfectly removed.

**Required implementation**

1. Represent retention deadlines, legal holds, source deletion requests, non-export obligations, and derivation propagation policy.
2. Use Lineage Service impact queries to identify affected raw artifacts, datasets, training runs, checkpoints, models, eval reports, and deployments.
3. Execute deterministic deletions/tombstones where possible; for trained models, record required remediation class such as retrain, unlearn via user-space algorithm, restrict, or document impossibility.
4. Require Change/Deployment decisions for any active artifact affected by a material deletion obligation.

**Responsibility boundaries: this task must not drift into**

- Do not claim cryptographic deletion from a trained model without evidence.
- Do not silently leave active deployments using invalidated data.
- Do not erase audit facts needed to demonstrate handling.

**Required integration**

- Artifact Registry performs payload lifecycle; Change Controller owns active-bundle response.
- Incident Controller tracks missed obligations.

**Validation and definition of done**

- Deletion fixture traces impact and blocks reuse; derived-model handling is explicit.
- G35 and G39 verify reproducibility/obligation behavior.

**Required contracts / collaborating tasks:** `DUC-002`, `LIN-003`, `ART-003`

**Gold evidence:** `G35`, `G39`

### Task 5 — DUC-005: Implement locality, federated, and device-resident data policies

**Anti-drift implementation goal**

Support training/eval/data work across private clouds, on-premises, and physical devices while data remains where policy requires.

**Required implementation**

1. Express allowed execution trust domains, geographic/organizational locality, raw-data export prohibition, aggregation thresholds, and update-only egress.
2. Expose scheduler predicates and node admission checks derived from grants.
3. Define federated/local update artifacts with source cohort, aggregation eligibility, privacy/noise metadata, and dropout policy refs; algorithms remain user-space trainer drivers.
4. Require explicit policy for sensor recordings, safety-local maps, and physical-device traces before central sync.

**Responsibility boundaries: this task must not drift into**

- Do not claim federated execution is private by default.
- Do not move data to satisfy compute convenience when locality forbids it.
- Do not treat model gradients/updates as automatically non-sensitive.

**Required integration**

- Fleet Scheduler and Training Controller form locality-compatible worker groups.
- Artifact replication and trace sync consult the same policy.

**Validation and definition of done**

- G62 and G67 validate locality and federated dropout/update provenance.
- A disallowed replica/worker is never selected even when it is faster.

**Required contracts / collaborating tasks:** `DUC-002`, `FLEET-003`

**Gold evidence:** `G62`, `G67`, `G73`

### Task 6 — DUC-006: Implement protected-evaluation data isolation

**Anti-drift implementation goal**

Make holdout secrecy a kernel property rather than a convention in training scripts.

**Required implementation**

1. Classify eval cases, answer keys, judge prompts, and scoring code separately with protected access paths.
2. Issue evaluator-only leases where candidate/trainer code receives inputs only through a controlled protocol and never raw answers or full case enumeration where avoidable.
3. Expose aggregated/sliced results according to release policy; bind reports to protected suite digest without revealing payload.
4. Detect and deny attempts to copy, log, embed, cache, or include protected payloads in candidate artifacts.

**Responsibility boundaries: this task must not drift into**

- Do not let a candidate-selected evaluator satisfy independent gates.
- Do not reveal hidden case IDs/answers in error messages.
- Do not call public benchmarks protected merely because they are stored separately.

**Required integration**

- Eval Controller owns run protocol; Data-Use Controller owns access.
- Secret/redaction and sandbox controls protect payload paths.

**Validation and definition of done**

- G36, G44, G49, G78, and G84 exercise leakage and self-judge paths.
- Canary logs/artifacts contain no hidden payload fingerprints.

**Required contracts / collaborating tasks:** `DUC-003`, `FND-009`

**Gold evidence:** `G36`, `G44`, `G49`, `G78`, `G84`

### Task 7 — DUC-007: Build data-use audit, policy simulation, and adversarial tests

**Anti-drift implementation goal**

Make data decisions explainable and test policy changes before they affect active collection/training/evaluation.

**Required implementation**

1. Produce decision trees with data/purpose/policy revisions, obligations, locality, expiry, and reason codes.
2. Add non-live simulation comparing proposed policy to historical access and lineage without granting access.
3. Fuzz source metadata, licenses/consent refs, purpose strings, extension fields, nested derived datasets, and cross-tenant sharing.
4. Create impact reports for policy revocation and changed retention.

**Responsibility boundaries: this task must not drift into**

- Do not expose protected payloads through simulation output.
- Do not use policy simulation to rewrite historical decisions.
- Do not treat missing provenance as permissive.

**Required integration**

- Evidence/Replay bundle decisions; Change Controller requires impact evidence for policy changes.
- Gold data examples publish audit reports.

**Validation and definition of done**

- G30–G39 and G84 pass with deterministic decisions.
- Mutation tests removing purpose/locality checks cause gold failures.

**Required contracts / collaborating tasks:** `DUC-001`, `DUC-002`, `DUC-003`, `DUC-004`, `DUC-006`

**Gold evidence:** `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G84`

### Component completion gate

- Every data read/use is purpose-, operation-, workload-, locality-, and time-scoped.
- Training and protected evaluation access are mechanically separated.
- Retention/deletion obligations propagate through lineage with honest limits.

---

## Component 7 — Event Log

**Canonical component ID:** `splendor.event-log`
**Plane:** `event_state_evidence`
**Current status:** strong partial foundation
**Owning package:** `crates/splendor-evidence (event module); storage engines in splendor-store`

**Implemented baseline to preserve**

The repository already has ordered `TraceEvent` streams, integrity chaining, SQLite/in-memory trace stores, local buffering/sync, trace aggregation references, and fail-closed pre-action durability. The missing work is to generalize traces into a typed multi-service event contract with subscriptions, partitions, payload refs, transactional outboxes, retention, and fleet-scale causality without degrading current replay guarantees.

**Exact kernel responsibility**

Own append-only ordered facts, causal links, integrity, subscription cursors, and retention. It is not mutable state, an analytics warehouse, a log-text sink, or an authority source.

**Public contracts:** `EventEnvelope`, `EventKind`, `EventPartition`, `EventCursor`, `CausalLink`, `EventAppendReceipt`, `SubscriptionSpec`, `EventIntegrityProof`

### Task 1 — EVT-001: Generalize TraceEvent into a versioned EventEnvelope without losing the stable trace line

**Anti-drift implementation goal**

Provide one event grammar for agent ticks, workloads, drivers, data, feedback, eval, training, change, deployment, incidents, and fleet control.

**Required implementation**

1. Define envelope fields for event ID, schema/version, partition, sequence, occurred/recorded time, principal/scope, causal parents, correlation IDs, payload artifact ref or bounded inline payload, integrity, and visibility class.
2. Create typed event-kind schemas by owning service; event kinds cannot carry hidden authorization outside documented fields.
3. Represent current `TraceEvent` as the `agent_run` partition compatibility profile and preserve deterministic trace-event IDs/sequence semantics.
4. Define producer requirements and durability class per event kind.

**Responsibility boundaries: this task must not drift into**

- Do not replace stable typed events with arbitrary topic/string JSON.
- Do not force globally total ordering across an entire fleet.
- Do not make event presence confer authority or state ownership.

**Required integration**

- Kernel runtime writes current tick/action/state events through the new append API.
- All new services emit envelopes rather than private audit tables as the only truth.

**Validation and definition of done**

- Existing replay fixtures produce equivalent ordered run traces.
- Unknown privileged event schema fails before append.
- G00, G02, and G03 validate compatibility.

**Required contracts / collaborating tasks:** `FND-001`, `FND-006`

**Gold evidence:** `G00`, `G02`, `G03`

### Task 2 — EVT-002: Implement partitioned ordering and causal graph semantics

**Anti-drift implementation goal**

Scale beyond one run while preserving the exact local order that matters and explicit cross-partition causality.

**Required implementation**

1. Define partitions for run, agent instance, workload, node, dataset build, eval run, training run, change, deployment, and incident with one ordered writer/epoch at a time.
2. Use monotonic sequence within partition plus writer epoch/fencing token; reject stale writers after handoff.
3. Represent cross-partition links as immutable causal edges with relation type and source event identity.
4. Provide causal traversal with cycle detection, missing-parent markers, and access filtering.

**Responsibility boundaries: this task must not drift into**

- Do not invent wall-clock ordering as causal truth.
- Do not allow two unfenced writers to append to the same ordered partition.
- Do not require a distributed consensus write for unrelated partitions.

**Required integration**

- State, workload, message, delegation, data, eval, and deployment services use partition writers.
- Trace aggregation imports remote events without renumbering source partitions.

**Validation and definition of done**

- Agent migration and node partition tests show no duplicate sequence or effect.
- Causal graph reconstructs message/child/workload/eval/change chains.
- G68 and G72 exercise scale/handoff.

**Required contracts / collaborating tasks:** `EVT-001`, `STA-002`

**Gold evidence:** `G68`, `G70`, `G72`

### Task 3 — EVT-003: Implement durable append, outbox, and acknowledgement semantics

**Anti-drift implementation goal**

Guarantee required events survive crashes and make cross-service publication recoverable.

**Required implementation**

1. Extend `TraceStore` into `EventStore` with append-if-sequence/epoch, batch append, read range, durable cursor, and integrity verification.
2. Implement SQLite first with WAL, explicit transactions, bounded batch size, and crash recovery; retain in-memory deterministic test store.
3. Provide transactional outbox records for service state changes and idempotent consumers with inbox deduplication.
4. Return append receipts only after configured durability and never acknowledge required-before-effect events early.

**Responsibility boundaries: this task must not drift into**

- Do not claim exactly-once delivery across systems; provide at-least-once plus idempotent consumption and unique event identity.
- Do not block a completed irreversible effect forever if the post-event store is unavailable; mark effect certainty and quarantine for recovery.
- Do not silently discard outbox backlog.

**Required integration**

- Migrate current trace durability gateway/monitor.
- Service command transactions rely on append receipts and outbox status.

**Validation and definition of done**

- Power-loss/process-kill injection at each boundary satisfies G02.
- Duplicate consumer delivery does not duplicate state/workload/action mutations.

**Required contracts / collaborating tasks:** `EVT-001`, `FND-003`

**Gold evidence:** `G02`, `G04`, `G87`

### Task 4 — EVT-004: Implement subscriptions, cursors, backpressure, and retention-aware resume

**Anti-drift implementation goal**

Support 24/7 agents, feedback consumers, monitors, and exporters without unbounded queues or hidden event loss.

**Required implementation**

1. Define subscription filters by tenant/scope/kind/partition, delivery mode, maximum lag, buffer, and loss policy.
2. Persist durable cursors for required consumers and ephemeral cursors for observability; expose lag/expiry state.
3. Implement bounded buffers with block, drop-oldest, drop-newest, sample, spill-to-disk, or fail-source policies chosen explicitly per stream.
4. If retention removes unseen events, emit a gap record and require snapshot/rebuild flow rather than pretending seamless resume.

**Responsibility boundaries: this task must not drift into**

- Do not give every subscriber an unbounded in-memory queue.
- Do not drop feedback, governance, or required state events under a telemetry policy.
- Do not let a subscriber’s cursor grant payload visibility.

**Required integration**

- Perceptor streams, agent inboxes, feedback/reward pipelines, drift monitors, fleet telemetry, and exporters use this API.
- State snapshots provide resume anchors.

**Validation and definition of done**

- G21 and G29 validate bounded stream resume and long-lived agents.
- Slow consumer tests exercise every loss/backpressure mode with explicit evidence.

**Required contracts / collaborating tasks:** `EVT-003`, `FND-009`

**Gold evidence:** `G21`, `G29`, `G48`

### Task 5 — EVT-005: Implement integrity chaining, remote sync, quarantine, and gap repair

**Anti-drift implementation goal**

Preserve evidence across offline devices and untrusted transport without rewriting source history.

**Required implementation**

1. Chain events per partition/epoch and sign sync batches or bind them to authenticated node/workload identities.
2. Extend current local trace buffer/sync with resumable ranges, duplicate detection, gap negotiation, corruption quarantine, and acknowledgement receipts.
3. Keep remote source sequence and integrity proof; central indexing adds separate arrival metadata.
4. Define repair as re-fetching verified ranges or marking irrecoverable gaps, never synthesizing missing events.

**Responsibility boundaries: this task must not drift into**

- Do not renumber or mutate edge events during central import.
- Do not accept a valid batch signature from a revoked/quarantined node without policy review.
- Do not hide an irrecoverable gap behind a new chain.

**Required integration**

- Node Agent buffers events offline; central Event Log indexes after verification.
- Incident Controller receives integrity/gap events.

**Validation and definition of done**

- G69, G73, G83, and G88 exercise partial transfer, offline sync, compromised node, and stale policy.
- Corrupt batch never advances trusted cursor.

**Required contracts / collaborating tasks:** `EVT-003`, `IDR-003`, `ART-005`

**Gold evidence:** `G69`, `G73`, `G83`, `G88`

### Task 6 — EVT-006: Implement event payload offload, schemas, and privacy boundaries

**Anti-drift implementation goal**

Keep the event log compact and queryable while preserving modality-agnostic observations and reports.

**Required implementation**

1. Set per-kind inline payload limits and require large/binary/private payloads in Artifact Registry.
2. Register payload schemas with compatibility class and ownership; validate before append.
3. Store bounded summaries, hashes, classifications, and artifact refs in events.
4. Apply field/payload visibility and redacted views at read/export time while preventing raw secret persistence at write time.

**Responsibility boundaries: this task must not drift into**

- Do not inline images, audio, video, datasets, model tensors, checkpoints, full prompts, or unbounded stdout.
- Do not let a payload artifact reference bypass data-use or artifact-read checks.
- Do not strip provenance to reduce event size.

**Required integration**

- Perceptor, model, sandbox, data, eval, and training drivers publish payload artifacts.
- Observability exporter uses redacted summaries.

**Validation and definition of done**

- Oversize inline payload rejects with a clear artifact path.
- G28, G35, and G82 verify multimodal/private/secret handling.

**Required contracts / collaborating tasks:** `EVT-001`, `ART-001`, `FND-009`

**Gold evidence:** `G28`, `G35`, `G82`

### Task 7 — EVT-007: Implement retention, compaction, archival, and restore

**Anti-drift implementation goal**

Bound long-term storage without turning replay into the project’s central constraint or losing required governance evidence.

**Required implementation**

1. Define retention by event kind/classification/tenant/legal hold, with required minimums for authority, effects, changes, deployments, incidents, and data-use decisions.
2. Compact only derived/reconstructable indexes or payloads; retain immutable event identity and integrity anchors.
3. Archive partition ranges as signed artifacts with indexes and restore them into inspect-only stores.
4. Report replay/evidence limitations after permitted deletion or legacy gaps.

**Responsibility boundaries: this task must not drift into**

- Do not compact away denials, approvals, lineage, effect certainty, or incident facts needed for accountability.
- Do not keep sensitive raw payloads indefinitely because traces are useful.
- Do not let restore activate live state or effects.

**Required integration**

- Data-use/legal hold controls retention; Evidence Service checks archive availability.
- State Service snapshots anchor compaction.

**Validation and definition of done**

- 24/7 soak test keeps hot store bounded and restores archived causal ranges.
- G03 and G29 remain inspectable after archival.

**Required contracts / collaborating tasks:** `EVT-003`, `ART-002`, `DUC-004`

**Gold evidence:** `G03`, `G29`

### Task 8 — EVT-008: Migrate all current trace producers and consumers

**Anti-drift implementation goal**

Complete the transition without two competing audit systems.

**Required implementation**

1. Route loop engine, gateway, scheduler, message router, delegation, governance, policy cache, node registry, trace sync, physical APIs, and daemon audit through Event Log adapters.
2. Replace ad hoc audit vectors/tables only after equivalent typed events and queries exist.
3. Update CLI trace export/replay/state inspection and TypeScript/Python trace subscriptions.
4. Add event-kind ownership documentation and reject new private audit-only persistence in review/CI.

**Responsibility boundaries: this task must not drift into**

- Do not remove current TraceStore APIs before compatibility tests and migration tools pass.
- Do not duplicate events in both paths without stable deduplication identity.
- Do not let observability logs become the fallback source of truth.

**Required integration**

- Use dual-write verification, then Event Log primary with TraceEvent projection.
- Publish migration report for existing SQLite databases.

**Validation and definition of done**

- All current examples and 0.1 trace fixtures pass.
- Projection yields expected old trace order and IDs.
- No privileged service lacks an event owner.

**Required contracts / collaborating tasks:** `EVT-001`, `EVT-003`, `FND-006`

**Gold evidence:** `G00`, `G02`, `G03`

### Component completion gate

- All privileged facts are typed, durable according to effect risk, causally linked, and queryable.
- Current trace/replay compatibility remains intact.
- Fleet/offline synchronization preserves source identity and exposes gaps honestly.

---

## Component 8 — State Service

**Canonical component ID:** `splendor.state-service`
**Plane:** `event_state_evidence`
**Current status:** strong partial foundation
**Owning package:** `crates/splendor-evidence (state semantics) plus splendor-store (persistence); orchestration hooks in splendor-kernel`

**Implemented baseline to preserve**

The repository has explicit content-addressed state graph nodes, snapshots, SQLite/in-memory stores, state handoff contracts, and a rule that failed state commit stops tick completion. Missing are named state partitions, CAS heads, writer leases/fencing, merge policies, artifact-backed large state, distributed handoff execution, and separation of agent/world/runtime/control state.

**Exact kernel responsibility**

Own versioned mutable heads over immutable commits, partition ownership, compare-and-swap, snapshot, branch/merge policy, and handoff. It does not own domain reasoning or allow arbitrary mutation by replay.

**Public contracts:** `StatePartition`, `StateHead`, `StateCommit`, `StateProposal`, `WriterLease`, `MergePolicy`, `StateSnapshot`, `StateHandoffReceipt`

### Task 1 — STA-001: Define named state partitions and explicit ownership

**Anti-drift implementation goal**

Separate task, world, memory, runtime, deployment, and learning state so one generic JSON blob cannot silently control everything.

**Required implementation**

1. Define partition identity, owner principal/agent, scope, schema, classification, writer policy, merge policy, retention, and current head.
2. Provide standard profiles for agent task state, inbox cursor, episodic/semantic memory refs, world claims, workload controller state, feedback/eval/training state, deployment state, and incidents.
3. Allow domain-specific schemas and opaque payload artifacts while keeping commit metadata typed.
4. Require an explicit partition reference and expected head on every mutation proposal.

**Responsibility boundaries: this task must not drift into**

- Do not create one global shared mutable “agent memory” object.
- Do not let a model output choose its own state partition or writer authority.
- Do not force user-space ontologies into kernel schemas.

**Required integration**

- AgentSpec declares allowed state bindings; World-State Service owns world partition semantics.
- Migrate current per-run state graph as an agent task-state partition.

**Validation and definition of done**

- Cross-partition writes without grants deny.
- G23, G26, and G29 exercise partition separation and persistence.

**Required contracts / collaborating tasks:** `FND-001`, `AUTH-001`

**Gold evidence:** `G23`, `G26`, `G29`

### Task 2 — STA-002: Implement compare-and-swap heads, writer leases, and fencing

**Anti-drift implementation goal**

Prevent duplicate agents, stale nodes, retries, or migrations from mutating the same live state head concurrently.

**Required implementation**

1. Create writer leases bound to principal, agent/workload instance, partition, head revision, lease epoch, expiry, and allowed transition schema.
2. Commit using CAS on expected head and current fencing epoch; return conflict with actual head and no mutation.
3. Renew/revoke leases through Authority/Agent/Workload controllers; stale writers can only publish detached artifacts, not advance heads.
4. Persist lease and head transition events before acknowledging ownership changes.

**Responsibility boundaries: this task must not drift into**

- Do not rely on process-local mutexes for fleet state ownership.
- Do not automatically merge conflicting privileged state.
- Do not allow replay or imported snapshots to acquire a live writer lease.

**Required integration**

- Agent migration, workload retry, deployment controller, and node handoff use writer leases.
- Event partitions use the same fencing epoch concept.

**Validation and definition of done**

- G72 proves single writer during migration and no duplicate effects.
- Concurrent commit property tests produce one winner and explicit conflict.

**Required contracts / collaborating tasks:** `STA-001`, `AUTH-001`, `FND-003`

**Gold evidence:** `G02`, `G72`

### Task 3 — STA-003: Implement immutable commits, snapshots, branches, and declared merge policies

**Anti-drift implementation goal**

Support experiments, world hypotheses, rollouts, and self-change comparison without mutating live state.

**Required implementation**

1. Extend current content-addressed state nodes with partition, schema, parent heads, payload artifact ref, event/evidence refs, writer lease epoch, and transition kind.
2. Support detached branches for simulation, replay, candidate agent revisions, and offline device work.
3. Provide merge policies: forbidden, fast-forward only, last-writer forbidden, CRDT/provider-defined, and explicit user-space merge proposal validated by kernel.
4. Snapshot by commit interval/size/policy and verify snapshot digest before restore.

**Responsibility boundaries: this task must not drift into**

- Do not make arbitrary JSON deep-merge a default.
- Do not equate a simulation branch with live truth.
- Do not let a user-space merge function commit without authority and evidence.

**Required integration**

- Replay/Simulation writes detached branches only.
- World-State Service uses explicit conflict/corroboration policies rather than generic merge.

**Validation and definition of done**

- Branch/merge fixtures cover conflict, fast-forward, invalid parent, corrupt snapshot, and forbidden live merge.
- G23–G25 validate world branches/rollouts.

**Required contracts / collaborating tasks:** `STA-001`, `ART-001`

**Gold evidence:** `G23`, `G24`, `G25`

### Task 4 — STA-004: Implement atomic state/event/artifact transition coordination

**Anti-drift implementation goal**

Ensure a state head never references missing evidence or payload and an effect outcome never lacks the corresponding state transition decision.

**Required implementation**

1. Define a state transition transaction with proposal, authority, required pre-events, payload artifact publication, commit CAS, and terminal event/outbox.
2. Use recoverable pending transitions when artifact/event/state stores are separate; reconciliation decides complete, abort, or quarantine.
3. Preserve current invariant that failed commit prevents successful tick completion.
4. Record effect certainty when external action succeeded but state/post-event persistence failed and route to incident/recovery.

**Responsibility boundaries: this task must not drift into**

- Do not claim multi-backend ACID without implementing recovery.
- Do not re-execute an external effect to rebuild state automatically.
- Do not advance a head if required payload/artifact integrity is unknown.

**Required integration**

- Loop engine, agent routes, world claims, workload controllers, and deployments use this transaction.
- Evidence Service can materialize the exact transition receipt.

**Validation and definition of done**

- G02 injects failure before/after every stage.
- Uncertain post-effect fixture opens containment path rather than duplicate retry.

**Required contracts / collaborating tasks:** `STA-002`, `EVT-003`, `ART-002`, `FND-003`

**Gold evidence:** `G02`, `G87`

### Task 5 — STA-005: Implement distributed handoff, checkpoint, and migration execution

**Anti-drift implementation goal**

Turn existing handoff schemas into a fenced, resumable operation for agents and workloads across devices.

**Required implementation**

1. Create handoff protocol: quiesce/drain, checkpoint/snapshot publication, close old writer lease, issue target lease, transfer/verify artifacts, restore, advance ownership, resume.
2. Support bounded mailbox/event cursor transfer and deduplication; preserve causal links and pending approval/action states.
3. Define rollback if target restore fails before ownership transfer and intervention if failure occurs after transfer.
4. Require target compatibility for runtime, drivers, state schema, model bundle, locality, and physical/device bindings.

**Responsibility boundaries: this task must not drift into**

- Do not run source and target as active writers during “seamless” migration.
- Do not migrate physical actuator authority to a cloud helper.
- Do not assume all in-memory Python/model state is checkpointable; declare checkpoint class.

**Required integration**

- Agent Instance Controller and Workload Controller own lifecycle; State Service owns head/lease handoff.
- Artifact transfer and Event Log sync are dependencies.

**Validation and definition of done**

- G72 kills source/target at each phase and proves one writer/no duplicate effects.
- Incompatible target rejects before source lease closes.

**Required contracts / collaborating tasks:** `STA-002`, `STA-003`, `ART-005`, `EVT-005`

**Gold evidence:** `G60`, `G72`

### Task 6 — STA-006: Implement state schema evolution and controlled migrations

**Anti-drift implementation goal**

Allow long-lived agents and world models to evolve state structures without unreviewed in-place mutation.

**Required implementation**

1. Bind each partition commit to a schema artifact/version and compatibility class.
2. Represent migrations as versioned code/environment artifacts executed as bounded workloads producing candidate commits on detached branches.
3. Validate invariants, rollback/forward-only semantics, data-use constraints, and old/new reader compatibility before advancing live head.
4. Require Change/Gate/Deployment control for active agent or deployment state migrations.

**Responsibility boundaries: this task must not drift into**

- Do not run arbitrary migration code in the state service process.
- Do not overwrite old commits or snapshots.
- Do not assume rollback is possible after irreversible external/data changes.

**Required integration**

- Sandbox/Workload executes migration; Change Controller packages migration with agent/deployment revision.
- Agent Registry declares compatible state schemas.

**Validation and definition of done**

- Migration fixtures cover successful, invalid, partial, forward-only, and rollback-required cases.
- G77 and G89 include state compatibility during code rollout.

**Required contracts / collaborating tasks:** `STA-003`, `WORK-001`, `CHG-003`

**Gold evidence:** `G77`, `G89`

### Task 7 — STA-007: Implement state query, subscription, retention, and privacy

**Anti-drift implementation goal**

Expose state safely to agents, humans, monitors, and evaluators without making the state store a vector database or leaking restricted payloads.

**Required implementation**

1. Provide exact head/commit/snapshot queries and change subscriptions with access control and redacted payload refs.
2. Keep semantic/vector/search indexes as user-space or provider artifacts linked to state, not hidden mutable kernel internals.
3. Implement retention/archival by partition policy while preserving required heads, lineage, and integrity anchors.
4. Support point-in-time read handles pinned to a head for deterministic route/eval execution.

**Responsibility boundaries: this task must not drift into**

- Do not expose mutable references or direct database handles.
- Do not let search index results become authoritative state facts.
- Do not delete state required by active leases or legal hold.

**Required integration**

- Route Runtime and evaluators use pinned read handles.
- Observability receives summaries, not unrestricted payloads.

**Validation and definition of done**

- Concurrent route steps see declared snapshot semantics.
- G26 verifies memory retention and active bundle immutability.

**Required contracts / collaborating tasks:** `STA-001`, `FND-009`

**Gold evidence:** `G26`, `G42`

### Task 8 — STA-008: Migrate current StateGraph/Store and prove compatibility

**Anti-drift implementation goal**

Reuse current implementation strengths while moving to partitioned service semantics.

**Required implementation**

1. Wrap current `StateGraph`, `StateNode`, `StateSnapshot`, and `StateStore` behind partition/head interfaces.
2. Backfill partition IDs and writer epochs deterministically for legacy runs without changing node content hashes where impossible; mark legacy hash profile.
3. Update loop engine, daemon state-head, snapshot export/import, replay, and handoff examples.
4. Add migration tools and rollback-safe SQLite backup.

**Responsibility boundaries: this task must not drift into**

- Do not delete or rewrite current state history.
- Do not block local-only use on distributed features.
- Do not maintain two independent live heads for the same run.

**Required integration**

- Dual-read legacy and vNext commits; new writes use partition service.
- Expose compatibility projection through existing APIs.

**Validation and definition of done**

- Current unit/integration/examples pass.
- Historical state-head/replay results remain identical or have documented legacy projection differences.

**Required contracts / collaborating tasks:** `STA-001`, `STA-002`, `FND-006`

**Gold evidence:** `G02`, `G03`

### Component completion gate

- All mutable state is a named, schema-bound partition with one fenced writer and immutable history.
- Simulation/replay branches cannot alter live heads.
- Current state graph semantics and failure invariants remain preserved.

---

## Component 9 — Evidence Service

**Canonical component ID:** `splendor.evidence-service`
**Plane:** `event_state_evidence`
**Current status:** missing
**Owning package:** `crates/splendor-evidence (evidence module); schemas in splendor-types`

**Implemented baseline to preserve**

Current traces, state graphs, governance exports, and telemetry provide pieces of evidence, but no service assembles the exact, access-controlled, completeness-checked bundle required to explain an action, reproduce a training run, judge a candidate, prove a deployment, or investigate an incident.

**Exact kernel responsibility**

Own evidence references, completeness rules, signed bundles, redacted views, and claim support. It does not decide authority, quality, alignment, or deployment; it states what evidence exists and what it supports.

**Public contracts:** `EvidenceBundle`, `EvidenceRequirement`, `EvidenceItem`, `EvidenceCompleteness`, `EvidenceClaim`, `EvidenceAttestation`, `EvidenceView`

### Task 1 — EVID-001: Define evidence bundles and typed claim support

**Anti-drift implementation goal**

Create a common unit for audit, gate, reproduction, incident, and novelty claims without copying raw protected payloads.

**Required implementation**

1. Define bundle subject, claim/purpose, required and optional item types, event ranges, state heads, artifact/lineage refs, authority/gate/approval decisions, environment, metrics, incidents, signatures, and visibility.
2. Represent claims as bounded statements with evaluator/issuer and support level: demonstrated, bounded, inconclusive, contradicted, or unavailable.
3. Use references and digests; include payloads only through authorized export artifacts.
4. Version requirement profiles for action execution, workload result, dataset publication, training candidate, eval report, change gate, deployment, incident closure, and novelty experiment.

**Responsibility boundaries: this task must not drift into**

- Do not let a bundle assert more certainty than its items support.
- Do not make “trace exists” equivalent to correctness or alignment.
- Do not include private chain-of-thought as required evidence.

**Required integration**

- Every terminal service receipt can request/build a bundle.
- Gate Engine consumes completeness and item results, not free-form audit prose.

**Validation and definition of done**

- Missing mandatory item yields explicit incomplete, never pass.
- G04, G05, G42, G47, and G83 publish typed bundles.

**Required contracts / collaborating tasks:** `EVT-001`, `ART-001`, `LIN-001`

**Gold evidence:** `G04`, `G05`, `G42`, `G47`, `G83`

### Task 2 — EVID-002: Implement evidence materialization and causal closure

**Anti-drift implementation goal**

Assemble a minimal reproducible/explainable graph from distributed events and artifacts.

**Required implementation**

1. Resolve subject events, causal parents, state commits, producer lineage, authority decisions, workload attempts, driver invocations, evals, approvals, changes, and deployment/incident refs.
2. Use bounded traversal with explicit truncation, missing, inaccessible, legacy, and corrupt statuses.
3. Cache immutable materializations by requirement profile and source revisions; invalidate only on availability/access changes, not historical mutation.
4. Create downloadable signed bundle artifacts and index summaries.

**Responsibility boundaries: this task must not drift into**

- Do not traverse unrestricted tenant/fleet history by default.
- Do not silently omit inaccessible negative evidence.
- Do not recompute historical metrics without labeling the new evaluation.

**Required integration**

- Lineage closure and Event causal queries are core dependencies.
- CLI/API offers `evidence build/explain/verify`.

**Validation and definition of done**

- Bundle digest is stable for the same authorized source graph.
- G03 and G39 reproduce or state exact missing constraints.

**Required contracts / collaborating tasks:** `EVID-001`, `LIN-003`, `EVT-002`

**Gold evidence:** `G03`, `G39`

### Task 3 — EVID-003: Implement completeness validators per privileged lifecycle

**Anti-drift implementation goal**

Turn “we logged something” into enforceable evidence requirements.

**Required implementation**

1. Define machine-readable requirements with item cardinality, acceptable status/trust, freshness, independence, and subject binding.
2. Create profiles for irreversible effects, protected eval, training candidates, self-change risk classes, physical actions, and rollout promotion.
3. Validate signatures/integrity, exact artifact/change IDs, environment, lineage, required negative/regression results, and approval separation.
4. Return structured missing/invalid/conflicting items and never let an exception silently waive them.

**Responsibility boundaries: this task must not drift into**

- Do not hard-code model metrics or domain thresholds in the evidence service.
- Do not count candidate-authored self-evaluation as independent evidence when the profile requires independence.
- Do not let an absent regression result count as zero regression.

**Required integration**

- Gate policies reference evidence profiles plus metric/constraint conditions.
- Incident closure and driver certification use dedicated profiles.

**Validation and definition of done**

- G44, G49, G75, G78, G79, and G89 fail when mandatory independent/rollback evidence is removed.

**Required contracts / collaborating tasks:** `EVID-001`, `ART-004`, `LIN-005`

**Gold evidence:** `G44`, `G49`, `G75`, `G78`, `G79`, `G89`

### Task 4 — EVID-004: Implement redacted, protected, and external evidence views

**Anti-drift implementation goal**

Share useful audit/eval/deployment facts with different audiences without duplicating truth or leaking data.

**Required implementation**

1. Define view policies that transform item payload visibility while preserving identity, digest, status, reason, and causal relation.
2. Support tenant operator, model developer, evaluator, governance reviewer, security investigator, public report, and external compliance views.
3. Represent withheld evidence and authority to request it; never omit its existence when it affects a decision unless existence itself is protected.
4. Record exports as artifacts/events and apply retention/data-use policy.

**Responsibility boundaries: this task must not drift into**

- Do not create a separately editable “sanitized report” as the truth.
- Do not leak hidden eval answers, secret values, PII, safety-local maps, or exploit details.
- Do not expose cross-tenant graph shape through redaction.

**Required integration**

- Use shared redaction primitives; Observability exporter can link to views.
- External governance adapter receives bounded evidence views.

**Validation and definition of done**

- G35, G43, G82, and G84 verify audience differences and no payload leaks.

**Required contracts / collaborating tasks:** `EVID-001`, `FND-009`

**Gold evidence:** `G35`, `G43`, `G82`, `G84`

### Task 5 — EVID-005: Implement evidence verification, signatures, and correction

**Anti-drift implementation goal**

Allow offline verification and explicit correction without rewriting history.

**Required implementation**

1. Verify item digests, event integrity, producer/gate signatures, subject bindings, requirement profile version, and bundle signature.
2. Represent corrections/retractions as new evidence linked to superseded items and update current views without deleting originals.
3. Support verification in an isolated environment using public keys/trust roots and no live service access.
4. Mark compromised signer/node/driver impact through lineage/incident refs.

**Responsibility boundaries: this task must not drift into**

- Do not mutate signed historical bundles.
- Do not accept a new correction as proof the original effect did not occur.
- Do not require online revocation service during inspect-only historical replay; report checked-at time.

**Required integration**

- Artifact attestations and Identity/Authority status feed verification.
- Incident impact can invalidate trust while preserving bytes/history.

**Validation and definition of done**

- Tampered, truncated, wrong-subject, revoked-signer, and corrected bundles behave explicitly.
- G83 and G85 reject compromised/tampered evidence.

**Required contracts / collaborating tasks:** `EVID-001`, `ART-004`, `IDR-005`

**Gold evidence:** `G83`, `G85`

### Task 6 — EVID-006: Integrate evidence bundles into gold runner and research claims

**Anti-drift implementation goal**

Make every gold and novelty result independently inspectable and prevent prose-only claims.

**Required implementation**

1. Extend the gold result schema with evidence bundle ID/digest, requirement profile, environment, exact code/artifact refs, baseline/candidate refs, and explicit skipped/unavailable cases.
2. Require novelty experiments to include preregistration/hypothesis, baselines, ablations, repeated seeds/cohorts, confidence/uncertainty, negative/regression results, and claim limitations.
3. Publish machine-readable and human-readable reports from the same bundle.
4. Add CI checks that prevent “PASS” without a complete verified bundle.

**Responsibility boundaries: this task must not drift into**

- Do not call specified tests implemented.
- Do not claim convergence, alignment, or novelty from a single cherry-picked run.
- Do not hide failed/negative cases in an appendix not linked to the result.

**Required integration**

- All G00–G89 examples use the runner.
- Evolution proof programs consume evidence profiles defined later in this catalog.

**Validation and definition of done**

- A synthetic false-claim fixture is rejected for missing baseline/ablation/independent eval.
- Gold catalog statuses remain honest until executable evidence exists.

**Required contracts / collaborating tasks:** `EVID-001`, `EVID-003`, `EVID-005`

**Gold evidence:** `G00`, `G89`

### Component completion gate

- Every privileged result and scientific claim can name a complete, verifiable, audience-appropriate evidence bundle.
- Incompleteness and contradiction are first-class results.
- Evidence never becomes the decision-maker.

---

## Component 10 — Replay/Simulation Service

**Canonical component ID:** `splendor.replay-simulation-service`
**Plane:** `event_state_evidence`
**Current status:** partial foundation
**Owning package:** `crates/splendor-evidence (replay module); simulation providers under adapters/simulation-*`

**Implemented baseline to preserve**

Inspect-only replay, trace reconstruction, state snapshots, multi-agent causal replay, physical simulation harnesses, and cloud-helper advisory patterns exist. Replay is currently overemphasized relative to learning/control, but remains an important evidence tool. Missing are explicit modes, driver substitution, deterministic input manifests, divergence/counterfactual reports, simulation clocks, and a strict no-live-effect proof across all new drivers.

**Exact kernel responsibility**

Own reconstruction, re-evaluation, simulation, and counterfactual execution from pinned evidence under non-live authority. It never mutates live state, reuses historical authorization, or executes live effects by default.

**Public contracts:** `ReplayPlan`, `ReplayMode`, `DriverSubstitution`, `SimulationContext`, `ReplayResult`, `DivergenceReport`, `CounterfactualBranch`

### Task 1 — RPLY-001: Define replay, re-evaluation, simulation, and counterfactual modes

**Anti-drift implementation goal**

Remove ambiguity about what code runs and what outputs mean.

**Required implementation**

1. Define `inspect`: reconstruct only; `re_evaluate`: rerun selected pure policy/eval logic; `simulate`: run against simulation drivers/world branch; `counterfactual`: vary declared inputs/policies/artifacts and compare.
2. Require pinned source evidence, state head/snapshot, artifact versions, environment, route/model/driver substitutions, clock/randomness policy, and output branch.
3. Label result authority/effect status and determinism class.
4. Reject mode escalation after plan admission without a new plan and authority.

**Responsibility boundaries: this task must not drift into**

- Do not use “replay” as a synonym for production retry.
- Do not execute recorded actions merely because they were previously approved.
- Do not present simulated outcomes as observed world facts.

**Required integration**

- Current replay endpoint maps to inspect mode.
- Route/Model/Eval/World services provide pure/simulation hooks.

**Validation and definition of done**

- G03 shows zero live adapter calls.
- Mode confusion and historical approval reuse tests deny.

**Required contracts / collaborating tasks:** `EVID-001`, `STA-003`, `FND-007`

**Gold evidence:** `G03`

### Task 2 — RPLY-002: Implement driver substitution and non-live capability classes

**Anti-drift implementation goal**

Guarantee every effectful dependency is replaced, denied, or explicitly isolated during simulation.

**Required implementation**

1. Extend DriverManifest with `live`, `read_only`, `recorded`, `simulated`, and `null/deny` execution profiles per operation.
2. Resolve a complete substitution table before execution and fail if any proposed effect lacks a non-live mapping.
3. Provide recorded-response and deterministic fake drivers for filesystem, HTTP, database, shell, Kubernetes, model, and physical interfaces where semantically valid.
4. Record substitution provenance and known fidelity limitations.

**Responsibility boundaries: this task must not drift into**

- Do not silently route an unmocked operation to the live driver.
- Do not call a stub a faithful simulator without validation.
- Do not reuse production secret/data leases in simulation.

**Required integration**

- Driver Registry/Gateway enforce execution profile.
- Physical simulation drivers consume separate device/world models.

**Validation and definition of done**

- G03, G45, and G73 prove no live effects and report fidelity.
- A new actuator without simulation profile causes plan rejection.

**Required contracts / collaborating tasks:** `RPLY-001`, `DRREG-001`, `DGW-001`

**Gold evidence:** `G03`, `G45`, `G73`

### Task 3 — RPLY-003: Implement deterministic input, clock, randomness, and environment capture

**Anti-drift implementation goal**

Make divergence attributable while respecting neural/numerical non-determinism.

**Required implementation**

1. Build replay input manifests from evidence/reproducibility graphs including event range, state, artifacts, code/env, seeds, random streams, external recorded responses, and clock schedule.
2. Provide virtual wall/monotonic clocks and deterministic timer/event injection.
3. Capture unsupported nondeterminism and select equivalence tolerances/profile.
4. Prevent current wall time, network, filesystem, or random sources from entering a deterministic plan unless declared.

**Responsibility boundaries: this task must not drift into**

- Do not claim bitwise identity for unsupported accelerator kernels.
- Do not hide a missing recorded dependency behind a default value.
- Do not normalize away meaningful timing/race divergences.

**Required integration**

- Use foundation determinism utilities and sandbox environment capture.
- Eval comparison consumes equivalence class.

**Validation and definition of done**

- G39, G42, G52, and G64 produce exact or bounded equivalence evidence.
- Undeclared time/random source is detected in reference examples.

**Required contracts / collaborating tasks:** `RPLY-001`, `LIN-004`, `FND-008`

**Gold evidence:** `G39`, `G42`, `G52`, `G64`

### Task 4 — RPLY-004: Implement divergence and causal comparison reports

**Anti-drift implementation goal**

Explain where candidate/baseline or recorded/replayed behavior first differs instead of dumping traces.

**Required implementation**

1. Align events/route steps/state commits/model calls/proposals/gate decisions/driver outcomes by stable causal identities and schemas.
2. Report first divergence, downstream causal cone, changed artifacts/config/policy, numerical tolerance, and missing/inaccessible evidence.
3. Support candidate-versus-baseline replay on the same input branch and aggregate per-slice differences.
4. Publish a report artifact usable by evaluators, gates, and humans.

**Responsibility boundaries: this task must not drift into**

- Do not equate a different event ID caused by a new run with semantic divergence.
- Do not expose hidden eval payloads in comparison.
- Do not automatically classify divergence as improvement or regression.

**Required integration**

- Eval Controller owns metric judgment; Replay supplies matched executions and divergence facts.
- Change Controller links reports to changed refs.

**Validation and definition of done**

- G45 and G46 compare baseline/candidate and preserve no-effect/shadow isolation.
- Known injected divergence points are localized correctly.

**Required contracts / collaborating tasks:** `RPLY-003`, `EVID-002`

**Gold evidence:** `G45`, `G46`

### Task 5 — RPLY-005: Implement counterfactual world/state branches and rollout artifacts

**Anti-drift implementation goal**

Support planning, RL, learned world models, and physical simulation without contaminating live world truth.

**Required implementation**

1. Create detached state/world branches with parent head, intervention variables, simulation model/version, horizon, rollout seed, and uncertainty.
2. Run user-space planners/models through route/workload drivers and publish rollout trajectories as artifacts plus state deltas.
3. Keep observations, predictions, hypotheses, and simulated transitions distinct in schemas and evidence.
4. Allow branch comparison and explicit promotion of validated knowledge only through World-State proposals/gates.

**Responsibility boundaries: this task must not drift into**

- Do not write simulated facts into live world partitions automatically.
- Do not let a learned world model claim calibration without eval evidence.
- Do not grant simulated action authority on real devices.

**Required integration**

- World-State Service and Eval Controller consume rollout artifacts.
- Physical simulation harness becomes one provider.

**Validation and definition of done**

- G25, G57, G59, and G73 validate learned rollout/calibration/safety boundaries.

**Required contracts / collaborating tasks:** `RPLY-001`, `STA-003`, `WORLD-001`

**Gold evidence:** `G25`, `G57`, `G59`, `G73`

### Task 6 — RPLY-006: Implement scalable replay/simulation workloads

**Anti-drift implementation goal**

Run large matched evaluations and simulations through the same execution fabric instead of inside the daemon process.

**Required implementation**

1. Represent replay/simulation shards as `WorkloadSpec` profiles with pinned inputs, non-live drivers, output branches, resource requests, and aggregation.
2. Fan out independent cases across fleet nodes with data locality and protected access constraints.
3. Support checkpoint/resume for long simulations and deterministic aggregation by case ID.
4. Reserve live inference/physical control capacity like any other background workload.

**Responsibility boundaries: this task must not drift into**

- Do not execute heavy model/simulation code in the control-plane service.
- Do not assume result ordering equals completion ordering.
- Do not let replay fan-out acquire live driver profiles.

**Required integration**

- Workload/Fleet/Eval controllers orchestrate execution.
- Evidence Service assembles results.

**Validation and definition of done**

- G61 and G68 validate heterogeneous fan-out and mixed fleet load.
- Cancellation cleans workers and leaves partial results explicit.

**Required contracts / collaborating tasks:** `RPLY-002`, `WORK-001`, `FLEET-001`

**Gold evidence:** `G61`, `G68`

### Task 7 — RPLY-007: Prove no-live-effect and compatibility across all drivers

**Anti-drift implementation goal**

Make replay safety a conformance property rather than a convention.

**Required implementation**

1. Add a harness that wraps every registered effectful operation with a live-effect counter/trap and runs inspect/simulate plans.
2. Test historical approvals, work orders, secret refs, data leases, deployment pointers, and physical commands cannot be reused as live authority.
3. Verify replay endpoints and imported evidence stores cannot mutate live state heads or aliases.
4. Retain current inspect-only defaults and require explicit simulation profile selection.

**Responsibility boundaries: this task must not drift into**

- Do not skip new driver operations.
- Do not exempt “read-only” network/database operations from data-use and non-live policy.
- Do not mark a test pass if the driver was simply unavailable unless denial is the expected profile.

**Required integration**

- Driver conformance registry requires replay profile tests.
- CI enumerates operation manifests and ensures coverage.

**Validation and definition of done**

- G03 and G45 pass for every conformant driver family.
- A deliberately malicious replay driver is quarantined.

**Required contracts / collaborating tasks:** `RPLY-001`, `RPLY-002`, `FND-005`

**Gold evidence:** `G03`, `G45`

### Component completion gate

- Replay is explicitly inspect/re-evaluate/simulate/counterfactual, never an ambiguous retry.
- Every effectful operation is substituted or denied before execution.
- Results are detached, evidence-bound, and honest about fidelity/determinism.

---

## Component 11 — Node Agent

**Canonical component ID:** `splendor.node-agent`
**Plane:** `execution_fabric`
**Current status:** partial foundation
**Owning package:** `crates/splendor-fabric (node_agent module) and `splendor-node` resident binary; host integrations remain adapters`

**Implemented baseline to preserve**

The repository implements node/instance registration, heartbeats, capability documents, fleet telemetry reference paths, state handoff, remote messages, and resident daemon configuration. It does not yet provide a hardened resident executor that acquires leases, fences stale work, mounts governed artifacts/data, supervises arbitrary workloads, accounts resources, preserves live inference/physical reservations, and recovers across disconnection.

**Exact kernel responsibility**

Own the trusted resident boundary on one machine or device: authenticated membership, measured capability inventory, lease enforcement, local resource isolation, workload process supervision, artifact/data mounts, local safety reservations, checkpoint/output transfer, and reconnect reconciliation. It never chooses global placement, training algorithms, eval metrics, or agent policy.

**Public contracts:** `NodeRegistrationV2`, `NodeCapabilitySnapshot`, `NodeAttestation`, `LocalResourceInventory`, `NodeLease`, `WorkerAttempt`, `MountReceipt`, `NodeReservation`, `NodeReconcileReport`

### Task 1 — NODE-001: Implement authenticated node bootstrap and renewable membership

**Anti-drift implementation goal**

Make every cloud worker, desktop, edge computer, robot, or drone computer a separately identifiable and revocable Splendor execution boundary.

**Required implementation**

1. Create a bootstrap protocol that exchanges a one-time enrollment credential for a node identity, instance identity, certificate/key material, fleet binding, tenant eligibility, and short-lived membership lease.
2. Bind every heartbeat, work acknowledgement, artifact upload, driver registration, and telemetry envelope to node/instance identity and monotonic membership generation.
3. Implement certificate rotation, membership renewal, explicit revocation, duplicate-instance detection, and safe re-enrollment after disk replacement.
4. Persist only the minimum resident identity material with OS-backed permissions; integrate an external attestation provider through a plugin rather than hard-coding TPM/cloud semantics.

**Responsibility boundaries: this task must not drift into**

- Do not reuse `AgentId` or `RunId` as machine identity.
- Do not accept a heartbeat as proof that a node still owns an execution lease.
- Do not make optional hardware attestation a mandatory assumption for all device classes.

**Required integration**

- Extend current node/instance registry schemas through compatibility adapters.
- Authority Service validates enrollment and Fleet Scheduler consumes current membership generation.

**Validation and definition of done**

- G60 enrolls, rotates, revokes, and re-enrolls a resident node.
- A cloned disk/image cannot operate concurrently under one instance identity.
- Clock skew and stale membership fail without evicting healthy work merely on wall-clock disagreement.

**Required contracts / collaborating tasks:** `IDR-002`, `AUTH-001`, `FND-006`

**Gold evidence:** `G60`, `G72`

### Task 2 — NODE-002: Implement measured capability and health inventory

**Anti-drift implementation goal**

Advertise schedulable facts that are sufficiently precise for compute, data, model, sandbox, and physical workloads without trusting arbitrary labels.

**Required implementation**

1. Inventory CPU architecture/count/features, memory, local storage classes/capacity, accelerators, accelerator memory, numerical dtypes, interconnects, network reachability classes, container runtimes, Python/runtime versions, installed driver digests, device-plugin resources, and physical device capabilities.
2. Separate measured facts, operator-declared labels, driver-reported capabilities, and transient health; assign freshness, provenance, and trust level to each.
3. Continuously probe resource and driver health with bounded overhead and publish deltas rather than unbounded full snapshots.
4. Expose compatibility fingerprints for collective groups: framework/runtime, accelerator family, communication backend, local worker count, topology, and required extensions.

**Responsibility boundaries: this task must not drift into**

- Do not let a node invent an authorizing capability token.
- Do not reduce heterogeneous hardware to a single generic GPU count.
- Do not schedule from stale health without an explicit degraded policy.

**Required integration**

- Extend current `CapabilityDocument`, `DeviceProfile`, node heartbeat, and fleet telemetry objects.
- Driver Registry supplies installed-driver status and conformance digest.

**Validation and definition of done**

- G60 and G61 place only on compatible measured resources.
- A false accelerator claim is detected by allocation/probe and quarantines the capability.
- Capability changes trigger reconciliation without rewriting historical placement evidence.

**Required contracts / collaborating tasks:** `NODE-001`, `DRREG-001`

**Gold evidence:** `G60`, `G61`, `G62`

### Task 3 — NODE-003: Implement local resource allocation, leases, and fencing

**Anti-drift implementation goal**

Ensure a node executes only currently leased work and cannot oversubscribe or continue stale work after reassignment.

**Required implementation**

1. Create a local allocator for CPU sets/shares, memory hard/soft limits, accelerator/device IDs, accelerator memory policy, local storage, network class, process count, and optional real-time/physical reservations.
2. Validate signed execution leases against membership generation, workload/attempt, exact resources, start deadline, expiry/renewal, data/artifact grants, and driver set.
3. Issue a node-local fencing token to every worker and driver invocation; reject state/output commits, checkpoints, and effects from expired or superseded tokens.
4. Track requested, reserved, allocated, and observed usage separately; report accounting drift and enforce local hard boundaries even when the control plane is unavailable.
5. Define cooperative preemption grace followed by hard termination, with non-preemptible critical sections declared narrowly and bounded.

**Responsibility boundaries: this task must not drift into**

- Do not treat a scheduler assignment message as an execution lease.
- Do not use best-effort metrics as the only memory/device boundary.
- Do not let an expired worker publish a “newest” checkpoint or action outcome.

**Required integration**

- Fleet Scheduler owns global reservation; Node Agent owns final local admission and fencing.
- Driver Gateway and Artifact Registry verify fencing tokens on privileged receipts.

**Validation and definition of done**

- Duplicate and delayed lease delivery executes at most one current attempt.
- G63 and G65 inject preemption, stale workers, and resource overrun.
- A partitioned node stops or degrades work according to lease policy and cannot commit after fencing.

**Required contracts / collaborating tasks:** `NODE-001`, `AUTH-005`, `FND-003`

**Gold evidence:** `G63`, `G65`, `G83`

### Task 4 — NODE-004: Implement governed artifact cache and data mounts

**Anti-drift implementation goal**

Stage exact immutable inputs efficiently while preserving integrity, purpose, locality, and deletion obligations.

**Required implementation**

1. Resolve artifact replicas authorized by the lease, download with resumable chunks, verify root/manifests, and store in a digest-keyed read-only cache.
2. Create per-attempt mount namespaces or equivalent scoped views; mount artifacts read-only and allocate separate writable scratch/output paths.
3. Redeem data-use grants locally, enforce allowed purpose/fields/time/record filters where the connector supports them, and emit mount/access receipts.
4. Scrub revoked/expired secret and protected-data mounts promptly; mark cached encrypted bytes unusable without current key/access grants.
5. Implement cache quotas, pinning for live workloads/checkpoints, safe eviction, corrupt-replica quarantine, and locality-aware prefetch hooks.

**Responsibility boundaries: this task must not drift into**

- Do not make cache possession equivalent to payload access.
- Do not mount mutable tags or unverified partial downloads.
- Do not share writable dataset/model directories across attempts.

**Required integration**

- Artifact Registry supplies replicas; Data-Use Controller supplies scoped grants; Sandbox Executor consumes mount specs.
- Lineage Service reconciles actual mounts with producer receipts.

**Validation and definition of done**

- G08, G34, G62, and G69 prove scoped mounts, locality, resume, cleanup, and integrity.
- A revoked protected eval artifact cannot be remounted from cache.

**Required contracts / collaborating tasks:** `NODE-003`, `ART-005`, `DUC-003`, `SECR-002`

**Gold evidence:** `G08`, `G34`, `G62`, `G69`

### Task 5 — NODE-005: Implement worker launch and process supervision

**Anti-drift implementation goal**

Run shell, Python, OCI, Kubernetes-local, model, training, eval, data, simulation, and agent workers under one observable lifecycle.

**Required implementation**

1. Translate an admitted workload task into an executor invocation with immutable code/environment refs, scoped mounts, environment contract, resource allocation, driver endpoints, attempt identity, and fencing token.
2. Supervise process/container/pod startup, readiness, liveness, exit, timeout, cancellation, preemption, child processes, and orphan cleanup.
3. Capture bounded stdout/stderr as artifacts, structured worker events over a control channel, and exact exit/effect certainty.
4. Require workers to acknowledge initialized environment and input digests before entering running state; report startup versus user-code failure distinctly.
5. Support multi-role local groups while preserving one attempt identity per role/rank and one parent worker group.

**Responsibility boundaries: this task must not drift into**

- Do not parse arbitrary log text as the sole progress protocol.
- Do not run user code inside the node-agent process.
- Do not report cancellation complete until processes, drivers, mounts, and leases are cleaned or explicitly quarantined.

**Required integration**

- Workload Controller supplies task/attempt specs; Sandbox/Model/Trainer/Evaluator/Data drivers supply execution profiles.
- Event Log receives lifecycle receipts.

**Validation and definition of done**

- G04, G10–G14, G52, G64, and G87 cover all terminal paths and orphan cleanup.
- SIGKILL/process crash and node-agent restart reconcile to one terminal or recoverable state.

**Required contracts / collaborating tasks:** `NODE-003`, `NODE-004`, `WORK-001`, `SBX-001`

**Gold evidence:** `G04`, `G10`, `G11`, `G12`, `G13`, `G14`, `G52`, `G64`, `G87`

### Task 6 — NODE-006: Implement local QoS and protected live-capacity reservations

**Anti-drift implementation goal**

Allow background training, eval, replay, and data work to use spare resources without harming live inference or physical control.

**Required implementation**

1. Represent node reservations for latency-critical inference, persistent agent loops, safety services, physical control, trace durability, and emergency operations.
2. Enforce CPU/memory/device/network/storage floors and interference limits locally, including accelerator memory headroom and configurable power/thermal bounds.
3. Measure latency/queue/thermal/memory pressure and throttle, checkpoint, preempt, or reject background workloads before protected SLOs are breached.
4. Expose reservation violations and reclaim decisions as evidence; let application policy choose acceptable quality degradation, never hidden oversubscription.
5. Support non-capable edge devices that contribute only data/eval/CPU tasks while retaining device-local inference reservations.

**Responsibility boundaries: this task must not drift into**

- Do not rely solely on fleet scheduler estimates after work starts.
- Do not preempt a physical safety loop to finish a training checkpoint.
- Do not call all unused memory/compute safely reclaimable without measured interference policy.

**Required integration**

- Fleet Scheduler places against declared reservations; Observability supplies SLO signals; Workload Controller coordinates checkpoint/preemption.

**Validation and definition of done**

- G68 sustains configured live inference latency while mixed training/eval/data jobs use residual fleet capacity.
- Thermal and memory pressure tests preempt background work before protected service failure.

**Required contracts / collaborating tasks:** `NODE-003`, `OBS-004`, `FLEET-005`

**Gold evidence:** `G68`, `G74`

### Task 7 — NODE-007: Implement offline, degraded, and reconnect behavior

**Anti-drift implementation goal**

Keep edge and physical nodes safe and useful through intermittent connectivity without inventing new authority.

**Required implementation**

1. Define per-workload offline policy: stop on lease loss, finish bounded operation, continue read-only/local-safe operation, buffer percepts/events, or enter operator-defined degraded route.
2. Cache only signed policy/work-order/driver manifests with expiry and revocation metadata; fail closed for high-risk physical effects when freshness requirements are not met.
3. Buffer events, feedback, artifact uploads, and checkpoint metadata locally with integrity chaining and storage limits.
4. On reconnect, re-authenticate membership, reconcile leases and attempts, upload trace/evidence ranges, resolve state heads explicitly, and quarantine outputs from fenced work.
5. Provide deterministic conflict reports rather than last-write-wins for agent/world/data state.

**Responsibility boundaries: this task must not drift into**

- Do not extend an expired authority merely because the node is offline.
- Do not merge conflicting state or feedback silently.
- Do not upload buffered raw sensor/private data outside its data-use policy on reconnect.

**Required integration**

- Build on current offline policy cache, local trace buffer, reconnect sync, and state handoff foundations.
- Incident Controller handles prolonged or unsafe divergence.

**Validation and definition of done**

- G72–G75 exercise disconnect, offline action limits, buffered data, stale policy, and reconciliation.
- A fenced offline checkpoint remains inspectable but cannot become candidate head.

**Required contracts / collaborating tasks:** `NODE-001`, `NODE-003`, `EVT-006`, `STA-007`

**Gold evidence:** `G72`, `G73`, `G74`, `G75`

### Task 8 — NODE-008: Implement checkpoint, output, and progress transfer protocol

**Anti-drift implementation goal**

Move large outputs from workers to durable stores without blocking control messages or accepting partial/corrupt results.

**Required implementation**

1. Provide a side-channel protocol for progress, metrics, heartbeats, checkpoint intents, upload sessions, output manifests, and terminal worker receipts.
2. Support asynchronous and incremental checkpoint staging, multi-rank shard manifests, resumable uploads, local retention until durable acknowledgement, and bandwidth prioritization.
3. Bind every output to workload/task/attempt/fencing token and actual mounted inputs/environment.
4. On cancellation/preemption, permit only explicitly requested final checkpoint/output classes and enforce a bounded grace period.
5. Garbage-collect abandoned local outputs after durable terminal evidence and retention rules.

**Responsibility boundaries: this task must not drift into**

- Do not transmit model checkpoints through the heartbeat channel.
- Do not mark a checkpoint durable before all required shards/manifests are committed.
- Do not accept an output from an old attempt after retry succeeded.

**Required integration**

- Artifact Registry handles upload commit; Training Controller validates distributed checkpoint completeness; Workload Controller advances state.

**Validation and definition of done**

- G52, G63, and G69 kill workers during every checkpoint stage and resume from only complete checkpoints.
- Progress floods cannot starve lease renewal or cancellation.

**Required contracts / collaborating tasks:** `NODE-005`, `ART-002`, `LIN-005`

**Gold evidence:** `G52`, `G63`, `G69`

### Task 9 — NODE-009: Harden the resident boundary and worker isolation

**Anti-drift implementation goal**

Reduce the blast radius of arbitrary or compromised agent code on desktops, servers, clusters, and robots.

**Required implementation**

1. Run node agent as a minimal privileged service and delegate workloads to unprivileged identities/namespaces/containers according to executor profile.
2. Enforce filesystem, network, device, process, syscall, capability, and kernel-interface policies; default deny host paths and device access.
3. Verify code/environment/image signatures and driver digests before launch; record node/runtime attestation and effective isolation profile.
4. Protect control sockets, lease/fencing material, resident keys, local policy cache, and trace buffer from worker access.
5. Detect attempted namespace escape, unexpected device access, cryptomining/resource abuse, or control-channel forgery and contain the attempt.

**Responsibility boundaries: this task must not drift into**

- Do not claim a container alone is a complete security boundary.
- Do not grant broad host Docker/Kubernetes credentials to a workload.
- Do not expose robot motor/firmware interfaces to cloud-helper or generic shell workloads.

**Required integration**

- Sandbox Executor defines requested profile; Node Agent enforces host-specific realization; Incident Controller receives violations.

**Validation and definition of done**

- G80–G83 run adversarial escape, forged receipt, secret exfiltration, and compromised-worker cases.
- Host control state remains unchanged and evidence is preserved.

**Required contracts / collaborating tasks:** `NODE-005`, `FND-011`, `SBX-007`

**Gold evidence:** `G80`, `G81`, `G82`, `G83`

### Task 10 — NODE-010: Implement drain, upgrade, restart, and disaster recovery

**Anti-drift implementation goal**

Upgrade and repair resident nodes without losing work identity, violating reservations, or executing duplicate effects.

**Required implementation**

1. Add node states active, cordoned, draining, maintenance, offline, quarantined, and retired with explicit scheduler behavior.
2. During drain, stop new leases, migrate/preempt eligible workloads, preserve protected local services, upload checkpoints, and report blockers.
3. Implement signed resident updates with staged rollout, health check, rollback, and compatibility negotiation; never self-update during an unsafe physical operation.
4. On node-agent restart, scan supervised processes/containers, local lease journal, mounts, uploads, and trace buffer; reattach only with valid current fencing.
5. Provide backup/restore procedures for identity, cache metadata, local state buffer, and device configuration without cloning active instance identity.

**Responsibility boundaries: this task must not drift into**

- Do not kill all workloads for every binary upgrade.
- Do not reattach an orphan merely because its PID/container name matches.
- Do not clear quarantine automatically after reboot.

**Required integration**

- Deployment Controller governs node-agent updates; Fleet Scheduler coordinates drain; Workload Controller handles migration/retry.

**Validation and definition of done**

- G65 and G72 perform rolling upgrades and crash recovery while live service remains within SLO.
- Duplicate-effect sentinel remains zero across restart.

**Required contracts / collaborating tasks:** `NODE-003`, `NODE-005`, `DEP-005`

**Gold evidence:** `G65`, `G68`, `G72`

### Component completion gate

- A resident node executes only authenticated, current, locally admitted leases with effective resource/isolation enforcement.
- Every worker, mount, output, checkpoint, and effect is bound to attempt and fencing identity.
- Offline, crash, drain, and upgrade paths preserve safety, evidence, and protected live capacity.

---

## Component 12 — Fleet Scheduler

**Canonical component ID:** `splendor.fleet-scheduler`
**Plane:** `execution_fabric`
**Current status:** partial foundation
**Owning package:** `crates/splendor-fabric (scheduler module); provider capacity adapters outside core`

**Implemented baseline to preserve**

The repository has placement v0 that deterministically selects one registered target by declared capabilities, locality, runtime version, execution mode, and dedicated-instance availability. It explicitly does not autoscale or execute work, and there is no queueing, reservations, gang/elastic scheduling, topology model, interference control, preemption, or thousand-node reconciliation.

**Exact kernel responsibility**

Own global admission, queues, resource reservations, compatibility/topology-aware placement, worker-group formation, fairness, preemption policy, and lease issuance across nodes. It schedules declared work; it never rewrites user training code, evaluates models, manages local processes, or grants data/action authority beyond validated inputs.

**Public contracts:** `FleetResource`, `SchedulingClass`, `PlacementPlan`, `ReservationSet`, `GangLease`, `WorkerGroupPlan`, `QueuePolicy`, `PreemptionPlan`, `SchedulingDecision`

### Task 1 — FLEET-001: Define the schedulable resource and requirement model

**Anti-drift implementation goal**

Represent arbitrary compute, data, model, sandbox, and physical workload needs precisely enough for safe placement.

**Required implementation**

1. Define scalar resources (CPU, memory, storage, bandwidth), discrete resources (accelerators, devices, licenses), properties (architecture, dtype, runtime), topology (node/rack/zone/interconnect), locality, isolation, deadline, duration estimate, and execution mode.
2. Separate hard requirements, soft preferences, anti-affinity, co-location, reservation floors, and application-declared elasticity bounds.
3. Represent worker roles and per-role resources rather than assuming every distributed process is identical.
4. Version resource names/capability schemas and reject unknown hard requirements rather than dropping them.
5. Map current `PlacementRequest/Candidate` into a one-role placement plan for compatibility.

**Responsibility boundaries: this task must not drift into**

- Do not model all accelerators as interchangeable.
- Do not infer physical actuator authority from proximity to a device.
- Do not turn cost/latency estimates into hidden hard constraints.

**Required integration**

- Node Agent supplies measured inventory; Workload Controller supplies normalized task requirements; Data-Use Controller adds locality constraints.

**Validation and definition of done**

- G09, G60–G62 validate exact requirement matching, explanation, and rejection.
- Unknown or stale critical capability fails plan admission.

**Required contracts / collaborating tasks:** `FND-001`, `NODE-002`

**Gold evidence:** `G09`, `G60`, `G61`, `G62`

### Task 2 — FLEET-002: Implement durable queues, admission, and scheduling classes

**Anti-drift implementation goal**

Control what enters the fleet and preserve fairness and critical-service capacity under load.

**Required implementation**

1. Create tenant/project queues with quota, concurrency, burst, debt, rate, cost, and accelerator-hour budgets.
2. Define scheduling classes for physical safety, live inference, persistent agent, interactive sandbox, checkpoint-critical, eval, training, data, replay/simulation, batch, and maintenance.
3. Implement admission checks for authority, valid workload plan, driver availability, artifact/data locality, quota, protected reservations, and schedulability.
4. Persist queue position and decisions so scheduler restart does not reorder privileged work silently.
5. Support deadlines and max queue time without allowing client-supplied priority inflation.

**Responsibility boundaries: this task must not drift into**

- Do not let a training job claim physical-safety priority.
- Do not admit an unschedulable gang indefinitely without an explicit pending/reject policy.
- Do not reset quota debt on scheduler restart.

**Required integration**

- Authority Service maps principals to permitted classes; Workload Controller owns workload state; Observability supplies queue/SLO facts.

**Validation and definition of done**

- G67 proves weighted fairness and quota isolation under sustained mixed load.
- Priority abuse, queue restart, and impossible request cases have deterministic outcomes.

**Required contracts / collaborating tasks:** `FLEET-001`, `AUTH-004`, `WORK-002`

**Gold evidence:** `G09`, `G67`, `G68`

### Task 3 — FLEET-003: Implement reservation, gang admission, and fenced lease issuance

**Anti-drift implementation goal**

Start collective/distributed work only when the required compatible resource set is secured, while preventing double allocation.

**Required implementation**

1. Implement two-phase reservation: provisional holds across selected nodes followed by atomic/recoverable gang commitment with one reservation generation.
2. Issue per-node/per-attempt signed execution leases and a worker-group lease containing roles, ranks/logical slots, rendezvous identity, topology, and expiry.
3. Cancel all provisional holds on timeout/conflict; reconcile uncertain node acknowledgements with idempotent reservation IDs.
4. Fence superseded reservation generations and make lease renewal contingent on workload state and node membership.
5. Support fixed-size gang, min/max elastic group, and independent shard/fan-out plans as distinct semantics.

**Responsibility boundaries: this task must not drift into**

- Do not launch half of a fixed collective and hope remaining workers appear.
- Do not use rank as a stable worker identity.
- Do not release a resource until local fencing/termination is confirmed or it is quarantined.

**Required integration**

- Node Agent performs final local admission; Training Controller owns distributed semantics; Workload Controller owns attempt transitions.

**Validation and definition of done**

- G63 and G64 inject partial reservation, duplicate acknowledgement, membership change, and scheduler crash.
- No device is leased to two current attempts.

**Required contracts / collaborating tasks:** `FLEET-001`, `NODE-003`, `FND-003`

**Gold evidence:** `G63`, `G64`, `G87`

### Task 4 — FLEET-004: Implement compatibility- and topology-aware placement

**Anti-drift implementation goal**

Form worker groups that can actually communicate and execute the declared parallel plan.

**Required implementation**

1. Filter by framework/runtime/driver versions, accelerator family/features, numerical dtype, local worker count, communication backend, network reachability, interconnect, data locality, and security/isolation class.
2. Optimize hard-valid candidates for locality, expected communication cost, checkpoint replica proximity, cost/energy preferences, and fragmentation while preserving deterministic explainability.
3. Generate an identical canonical topology/mesh document for all ranks and bind its digest to leases.
4. Form compatibility-homogeneous synchronous collective groups; allocate incompatible devices to independent data/eval/sweep/helper roles unless a trainer driver explicitly supports heterogeneous collectives.
5. Support physical/cloud-helper constraints so cloud workers propose plans but cannot receive local actuator roles.

**Responsibility boundaries: this task must not drift into**

- Do not put mismatched collective libraries or mesh definitions into one group.
- Do not interpret heterogeneous fleet utilization as requiring heterogeneous synchronous all-reduce.
- Do not optimize cost by violating data locality or protected eval isolation.

**Required integration**

- Trainer Driver validates parallel-plan support; Data-Use Controller authorizes locality; Node capabilities provide topology.

**Validation and definition of done**

- G61 and G64 prove homogeneous collective formation plus heterogeneous fleet decomposition.
- An inconsistent DeviceMesh-like plan is rejected before worker launch rather than hanging.

**Required contracts / collaborating tasks:** `FLEET-001`, `FLEET-003`, `TRDRV-004`, `DUC-003`

**Gold evidence:** `G61`, `G62`, `G64`

### Task 5 — FLEET-005: Implement protected service reservations and interference-aware co-scheduling

**Anti-drift implementation goal**

Exploit residual resources across up to thousands of devices without degrading live inference, 24/7 agents, or physical safety.

**Required implementation**

1. Ingest node-level protected reservations, workload SLOs, latency/throughput baselines, accelerator memory floors, bandwidth ceilings, and thermal/power constraints.
2. Admit background jobs only into residual envelopes and include reclaim/preemption policy in leases.
3. Continuously adjust placement or request checkpoint/preemption when measured interference crosses configured thresholds.
4. Prefer independent data/eval tasks on weak/edge devices and communication-heavy training on compatible low-latency groups.
5. Account for model-loading and checkpoint-transfer spikes, not only steady-state compute.

**Responsibility boundaries: this task must not drift into**

- Do not assume a low average utilization means latency headroom.
- Do not evict resident physical safety or trace durability services.
- Do not silently lower live model quality to create training capacity.

**Required integration**

- Node Agent enforces local floors; Observability provides measurements; Training/Workload controllers honor preemption/checkpoint requests.

**Validation and definition of done**

- G68 runs inference, persistent agents, training, eval, data, and maintenance across a 1,000-node simulated fleet while asserting SLO and progress.
- Injected memory/thermal/network pressure triggers bounded reclaim.

**Required contracts / collaborating tasks:** `FLEET-002`, `NODE-006`, `OBS-004`

**Gold evidence:** `G68`, `G74`

### Task 6 — FLEET-006: Implement elastic worker-group membership and rendezvous control

**Anti-drift implementation goal**

Coordinate legitimate elasticity without assuming stable ranks or arbitrary mid-step resizing.

**Required implementation**

1. Define worker-group epochs, logical role slots, min/max membership, restart policy, rendezvous backend contract, join deadline, and group generation.
2. On membership change, terminate/fence the old group unless the trainer protocol explicitly supports in-place reconfiguration; create a new epoch and restore from a compatible checkpoint.
3. Assign rank/world-size only for one group epoch; preserve logical worker/attempt identities separately.
4. Bind topology, data-shard epoch, global-batch policy, seed derivation, and checkpoint source to the group epoch.
5. Support fixed groups for DDP/FSDP/TP/pipeline and independent elastic pools for embarrassingly parallel jobs.

**Responsibility boundaries: this task must not drift into**

- Do not promise seamless arbitrary rank addition to user code.
- Do not hard-code stable rank/world-size assumptions.
- Do not restart from a checkpoint whose optimizer/data semantics are incompatible with the new group.

**Required integration**

- Training Controller decides whether and how a run supports elasticity; Trainer Driver launches framework rendezvous; Node Agent fences old workers.

**Validation and definition of done**

- G64 changes membership repeatedly and verifies no sample duplication beyond declared semantics, no stale commit, and bounded lost work.

**Required contracts / collaborating tasks:** `FLEET-003`, `TRAIN-008`, `TRAIN-009`

**Gold evidence:** `G64`

### Task 7 — FLEET-007: Implement preemption, rescheduling, and failure-domain policy

**Anti-drift implementation goal**

Recover capacity and failed work without creating duplicate effects or unbounded restart storms.

**Required implementation**

1. Classify workloads and phases as preemptible, checkpoint-preemptible, non-preemptible-bounded, or physical/live protected.
2. Build preemption plans that identify victims, expected freed resources, checkpoint grace, effect certainty, and downstream group consequences.
3. Reschedule independent shards selectively; restart collective groups by epoch; preserve retry budgets and exponential backoff by failure category/domain.
4. Avoid repeatedly placing on a suspect node/driver/failure domain and open incidents at configured thresholds.
5. Support operator drain and emergency fleet reclaim with explicit evidence and priority rules.

**Responsibility boundaries: this task must not drift into**

- Do not retry an uncertain side-effectful workload automatically.
- Do not preempt only one rank of a synchronous group and leave survivors blocked.
- Do not treat user-code deterministic failure as transient infrastructure failure.

**Required integration**

- Workload Controller owns retries; Node Agent performs checkpoint/termination; Incident Controller quarantines failure domains.

**Validation and definition of done**

- G63, G65, G87, and G88 exercise worker loss, preemption, scheduler failover, and retry storms.
- Retry budget exhaustion is terminal and explained.

**Required contracts / collaborating tasks:** `FLEET-003`, `FND-004`, `INC-002`

**Gold evidence:** `G63`, `G65`, `G87`, `G88`

### Task 8 — FLEET-008: Implement heterogeneous workload decomposition policy

**Anti-drift implementation goal**

Use every capable device to its greatest valid potential while preserving algorithmic semantics.

**Required implementation**

1. Accept a workload task graph with role compatibility and independence constraints; schedule synchronous collective roles separately from data preprocessing, eval shards, sampling, rollout, search, labeling, and artifact transfer roles.
2. Provide standard decomposition templates for training-plus-data, training-plus-eval, RL actor/learner/evaluator, world-model rollout, and multi-agent simulation.
3. Allow application/trainer plugins to produce decomposition proposals; validate resources, authority, data flow, and synchronization in kernel space.
4. Aggregate progress and bottlenecks by logical stage and let controller rebalance independent pools without mutating synchronous group semantics.
5. Make unused devices visible with exact incompatibility/restriction reasons.

**Responsibility boundaries: this task must not drift into**

- Do not force every available device into one training collective.
- Do not move protected data to a device merely to increase utilization.
- Do not let a decomposition plugin bypass WorkloadSpec or Driver Gateway.

**Required integration**

- Training/Eval/Data/Improvement controllers generate stage graphs; Workload Controller realizes tasks; Fleet Scheduler places them.

**Validation and definition of done**

- G61 and G68 show CPUs, mixed accelerators, edge nodes, and servers doing valid complementary work.
- An incompatible device contributes a safe independent task or remains idle with explanation.

**Required contracts / collaborating tasks:** `WORK-003`, `FLEET-004`

**Gold evidence:** `G61`, `G68`, `G70`

### Task 9 — FLEET-009: Implement provider capacity and elastic-infrastructure interfaces

**Anti-drift implementation goal**

Allow external cloud, cluster, Kubernetes, and on-prem capacity managers to add/remove nodes without embedding provider APIs in the scheduler.

**Required implementation**

1. Define a `CapacityProvider` adapter contract for capacity inventory, scale request, provisioning status, cost/carbon metadata, failure, and retirement.
2. Issue bounded desired-capacity requests from queue pressure and reservations; treat provider acknowledgements as advisory until authenticated nodes enroll.
3. Support static fleets, Kubernetes-backed pools, cloud autoscaling groups, and manually managed physical/edge nodes through providers.
4. Apply startup deadlines, budget limits, locality/region constraints, warm-pool policy, and scale-down drain requirements.
5. Record provider decisions and distinguish unavailable capacity from unschedulable workload semantics.

**Responsibility boundaries: this task must not drift into**

- Do not let a cloud provider response create a node identity or lease directly.
- Do not autoscale physical robots or user desktops as if they were fungible VMs.
- Do not require autoscaling for a valid static deployment.

**Required integration**

- Node enrollment confirms provisioned capacity; Authority/Quota constrain spend; Deployment Controller manages provider adapter rollout.

**Validation and definition of done**

- G66 scales a reference Kubernetes/cloud pool under queue load and drains safely.
- Provider timeout/budget exhaustion leaves workloads pending/rejected with exact reason.

**Required contracts / collaborating tasks:** `FLEET-002`, `NODE-001`, `ACT-001`

**Gold evidence:** `G66`, `G68`

### Task 10 — FLEET-010: Implement scheduling explanations, dry runs, and capacity simulation

**Anti-drift implementation goal**

Make placement and starvation debuggable without exposing other tenants or mutating live queues.

**Required implementation**

1. Persist normalized candidate filtering, score contributions, reservation conflicts, quota decisions, locality restrictions, and selected plan digest.
2. Expose access-controlled `explain`, `why pending`, `what-if`, and dry-run APIs using redacted fleet snapshots.
3. Simulate queue/policy/reservation changes against recorded or synthetic capacity without issuing leases.
4. Report minimal unsatisfied constraints and possible user-space remediations without automatically weakening requirements.

**Responsibility boundaries: this task must not drift into**

- Do not leak node/tenant workload details through explanations.
- Do not let a dry run reserve resources.
- Do not recommend dropping a security/locality constraint as a normal optimization.

**Required integration**

- Evidence Service stores decisions; Replay/Simulation executes scheduler simulations; CLI/SDK exposes summaries.

**Validation and definition of done**

- G62 and G67 assert deterministic explanations and redaction.
- Counterfactual policy changes reproduce expected placement differences without live effects.

**Required contracts / collaborating tasks:** `FLEET-001`, `EVID-002`, `RPLY-006`

**Gold evidence:** `G62`, `G67`

### Task 11 — FLEET-011: Harden scheduler reconciliation, availability, and 1,000-node scale

**Anti-drift implementation goal**

Operate the control loop at fleet scale without losing ownership or making global stop-the-world assumptions.

**Required implementation**

1. Implement leader fencing or single-writer generation for scheduling decisions, durable queue/reservation state, and idempotent reconciliation workers.
2. Partition/watch node and workload changes incrementally; avoid full fleet scans on every heartbeat.
3. Define backpressure and bounded staleness for telemetry, candidate caches, and scheduling loops while requiring fresh facts for critical placement.
4. Benchmark 1,000 nodes, tens of thousands of queued tasks, thousands of running attempts, and bursty heartbeats/failures.
5. Implement disaster recovery from durable state and node lease reconciliation before issuing new conflicting work.

**Responsibility boundaries: this task must not drift into**

- Do not rely on in-memory ownership for production reservations.
- Do not allow two scheduler leaders to issue current lease generations.
- Do not let telemetry cardinality or explanation storage dominate scheduling latency.

**Required integration**

- Event/State stores provide durable records; Node Agents reconcile current lease generations; Observability exports bounded metrics.

**Validation and definition of done**

- G68 and G88 pass scheduler failover, partition, heartbeat storm, and 1,000-node performance budgets.
- No duplicate current allocation or priority inversion persists beyond defined bounds.

**Required contracts / collaborating tasks:** `FLEET-003`, `EVT-006`, `STA-005`, `OBS-008`

**Gold evidence:** `G68`, `G88`

### Component completion gate

- Only hard-valid, authorized, quota-valid plans receive fenced resource leases.
- Collective groups are compatibility/topology coherent; heterogeneity is used through explicit role decomposition.
- Live inference, persistent agents, and physical safety retain declared capacity and SLO priority under fleet load.

---

## Component 13 — Workload Controller

**Canonical component ID:** `splendor.workload-controller`
**Plane:** `execution_fabric`
**Current status:** missing
**Owning package:** `crates/splendor-fabric (workload module)`

**Implemented baseline to preserve**

Runs and ticks exist for agent loops, and work orders/placement describe some authority and target constraints. There is no generic durable controller for inference, training, eval, data, simulation, shell/Python/OCI/Kubernetes, build, maintenance, or recurring workloads with tasks, attempts, leases, checkpoints, cancellation, and reconciliation.

**Exact kernel responsibility**

Own the framework-neutral desired/observed lifecycle of every governed computation. It validates and expands WorkloadSpecs into tasks/attempts, coordinates scheduler and node leases, records progress/output/checkpoint state, and reconciles failures. It does not implement user algorithms, select model quality, or execute code itself.

**Public contracts:** `WorkloadSpec`, `WorkloadProfile`, `TaskSpec`, `TaskGraph`, `Attempt`, `WorkerGroup`, `ProgressEvent`, `CheckpointRecord`, `WorkloadResult`, `RecurringSchedule`

### Task 1 — WORK-001: Implement the canonical WorkloadSpec and lifecycle state machine

**Anti-drift implementation goal**

Give all computation one durable, inspectable, cancellable kernel contract without flattening domain-specific semantics.

**Required implementation**

1. Define workload identity, owner/scope, profile, immutable code/environment/config/input refs, output declarations, task graph, resources, placement, drivers, data/secret grants, determinism, retry, checkpoint, timeout, priority, and evidence policy.
2. Implement states proposed, validating, admitted, queued, reserving, starting, running, checkpointing, pausing, paused, resuming, cancelling, succeeded, failed, denied, expired, and quarantined with permitted transitions.
3. Separate workload, task, attempt, worker-group, and worker identities and statuses.
4. Persist desired and observed state with optimistic concurrency and command idempotency.
5. Define profile extensions for agent, inference, training, eval, data, replay/simulation, sandbox, build, physical-helper, and maintenance without placing algorithms in core.

**Responsibility boundaries: this task must not drift into**

- Do not equate a workload with an OS process or one node.
- Do not permit profile payloads to override authority, drivers, resources, or gates.
- Do not infer success from process exit alone when required outputs/evidence are missing.

**Required integration**

- Wrap current `Run`/scheduler loop as an `agent_runtime` workload profile while preserving run/tick identity.
- Fleet Scheduler and Node Agent consume normalized tasks/attempts.

**Validation and definition of done**

- G04 exercises every valid/invalid transition and restart reconciliation.
- G00 round-trips all profiles and rejects authorizing extensions.

**Required contracts / collaborating tasks:** `FND-001`, `FND-003`, `FND-007`

**Gold evidence:** `G00`, `G04`

### Task 2 — WORK-002: Implement validation, planning, and admission receipts

**Anti-drift implementation goal**

Reject ambiguous or impossible work before reserving resources or exposing protected inputs.

**Required implementation**

1. Validate schema, principal, work order/capabilities, exact artifact/code/environment refs, driver operations, resource feasibility, data/secret purposes, output classes, and risk policy.
2. Resolve mutable user aliases into immutable refs and freeze a `WorkloadPlan` digest before admission.
3. Ask profile controllers/drivers to validate domain-specific sections through pure planning interfaces and collect compatibility reports.
4. Produce one decision with denials/warnings, resolved refs, estimated resource/cost envelope, replay mode, and required approvals.
5. Revalidate time-sensitive grants at start and privileged invocations without mutating the frozen plan.

**Responsibility boundaries: this task must not drift into**

- Do not download/mount protected payloads during ordinary plan validation.
- Do not silently default a missing training/eval/data purpose or side-effect class.
- Do not weaken a hard requirement to make work schedulable.

**Required integration**

- Authority, Artifact, Data-Use, Driver Registry, Fleet Scheduler, and Gate services contribute facts; Workload Controller owns final admission record.

**Validation and definition of done**

- G01, G08, G09, G34, and G60 validate deny-first planning.
- Plan digest changes whenever a privileged resolved input changes.

**Required contracts / collaborating tasks:** `WORK-001`, `AUTH-003`, `ART-006`, `DUC-002`, `DRREG-003`, `FLEET-001`

**Gold evidence:** `G01`, `G08`, `G09`, `G34`, `G60`

### Task 3 — WORK-003: Implement task-graph expansion and role semantics

**Anti-drift implementation goal**

Express independent shards, pipelines, collectives, services, actors/learners, and agent/sub-agent work without embedding an orchestration language in every controller.

**Required implementation**

1. Define typed task dependencies: data, control, barrier, stream, service-ready, checkpoint, and approval/gate dependencies.
2. Support fixed tasks, indexed shards, dynamic bounded fan-out, worker groups, long-running services, and reducer/aggregator tasks.
3. Require output/input artifact or channel contracts on every edge and detect cycles except explicitly bounded feedback loops.
4. Let profile controllers provide a `TaskGraphProposal`; kernel validation freezes it and enforces resource/data/authority flow.
5. Version graph revisions between workload epochs; never mutate a running collective graph in place.

**Responsibility boundaries: this task must not drift into**

- Do not build user model/planner logic into the graph engine.
- Do not allow unbounded recursive task spawn.
- Do not use implicit shared filesystem paths as data edges.

**Required integration**

- Training, Eval, Data, Improvement, Agent, and Replay controllers generate proposals.
- Fleet Scheduler uses role/group annotations.

**Validation and definition of done**

- G18, G19, G58, G61, and G70 validate sub-agent, trigger, RL actor/learner, distributed, and dynamic fan-out graphs.
- Cycle and authority-flow violations deny.

**Required contracts / collaborating tasks:** `WORK-001`, `FND-007`

**Gold evidence:** `G18`, `G19`, `G58`, `G61`, `G70`

### Task 4 — WORK-004: Implement attempts, idempotency, fencing, and result acceptance

**Anti-drift implementation goal**

Make retries and distributed execution safe across duplicate delivery, scheduler failover, and stale workers.

**Required implementation**

1. Create a new attempt identity for each execution while retaining logical task identity; bind scheduler reservation and node fencing generation.
2. Define retry eligibility from error taxonomy, effect certainty, retry budget, profile policy, and checkpoint availability.
3. Accept progress, outputs, checkpoints, and terminal receipts only from the current authorized attempt/fencing token.
4. Deduplicate commands and worker messages by stable idempotency keys and sequence/epoch.
5. Quarantine late or conflicting results instead of overwriting the accepted result.

**Responsibility boundaries: this task must not drift into**

- Do not retry uncertain external effects automatically.
- Do not let first-arriving result win without current fencing.
- Do not reuse an attempt identity after process restart.

**Required integration**

- Fleet Scheduler issues reservations; Node Agent enforces fencing; Artifact/Lineage verify outputs.

**Validation and definition of done**

- G63, G65, G87, and G88 inject duplicate, late, stale, and partial results.
- Exactly one accepted terminal result exists per task epoch.

**Required contracts / collaborating tasks:** `WORK-001`, `FLEET-003`, `NODE-003`, `FND-004`

**Gold evidence:** `G63`, `G65`, `G87`, `G88`

### Task 5 — WORK-005: Implement pause, checkpoint, resume, cancel, timeout, and expiration

**Anti-drift implementation goal**

Give every long-running workload bounded control semantics rather than provider-specific best effort.

**Required implementation**

1. Define profile-declared safe points and checkpoint capabilities: unsupported, best-effort, coordinated, asynchronous, and state-only.
2. Implement pause intent, task/group checkpoint coordination, durable checkpoint acceptance, resource release policy, and resume from exact checkpoint/plan compatibility.
3. Implement graceful cancel with deadline then hard kill; propagate cancellation through task graph and drivers.
4. Distinguish queue/start/run/idle/overall timeout and authority/grant expiry; record effect certainty and partial outputs.
5. Allow physical/live workloads to define safety-specific stop/hold behavior through actuator drivers, not generic process kill alone.

**Responsibility boundaries: this task must not drift into**

- Do not claim paused until a consistent checkpoint or declared paused state exists.
- Do not resume with changed code/data/topology without compatibility validation.
- Do not treat timeout as safe cancellation when effects are uncertain.

**Required integration**

- Profile controllers implement checkpoint planning; Node Agent executes; Artifact Registry stores checkpoint; Incident handles uncertain termination.

**Validation and definition of done**

- G52, G63, G69, G75, and G87 validate coordinated and unsupported cases, including crash between checkpoint shards.

**Required contracts / collaborating tasks:** `WORK-004`, `NODE-008`, `ART-002`

**Gold evidence:** `G52`, `G63`, `G69`, `G75`, `G87`

### Task 6 — WORK-006: Implement progress, checkpoint, output, and terminal result contracts

**Anti-drift implementation goal**

Expose domain-neutral lifecycle facts while allowing rich typed training/eval/data/agent progress as artifacts.

**Required implementation**

1. Define bounded `ProgressEvent` with phase, monotonic step/cursor, units, resource usage, optional metric summaries, and artifact refs.
2. Define checkpoint records with compatibility, completeness, shard manifest, logical progress, data cursor, RNG/optimizer/world state refs as applicable.
3. Define declared outputs with required/optional, kind/schema, publication policy, and lineage requirements.
4. Compute terminal result only after required outputs, producer receipts, final evidence, and cleanup status are known.
5. Support partial result manifests that explicitly enumerate missing/failed shards rather than presenting them as complete.

**Responsibility boundaries: this task must not drift into**

- Do not put unbounded metrics/logs in control state.
- Do not let user code declare its own workload success without controller validation.
- Do not treat a checkpoint as a deployment candidate automatically.

**Required integration**

- Evidence and Artifact services store rich reports; Observability handles high-volume telemetry; profile controllers interpret metrics.

**Validation and definition of done**

- G17, G39, G47, G52, and G69 prove output completeness and lineage.
- A zero-exit worker missing a required report fails with exact reason.

**Required contracts / collaborating tasks:** `WORK-001`, `ART-002`, `LIN-002`, `EVID-001`

**Gold evidence:** `G17`, `G39`, `G47`, `G52`, `G69`

### Task 7 — WORK-007: Implement continuous, recurring, triggered, and service workloads

**Anti-drift implementation goal**

Support 24/7 agents, data collectors, online evals, retraining triggers, and resident model services without ad hoc loops.

**Required implementation**

1. Define recurring schedules, event triggers, debounce/coalescing, concurrency policy, missed-run policy, maximum active instances, and suspension.
2. Represent long-running services with readiness, desired replicas, update policy, state/checkpoint hooks, and health contracts.
3. Bind every triggered execution to the triggering events/state version and current authorization; deduplicate trigger identities.
4. Support bounded child workloads and recurring improvement cycles with explicit cycle identity and termination budgets.
5. Keep schedules and triggers as desired state so controller restart resumes without duplicate unbounded executions.

**Responsibility boundaries: this task must not drift into**

- Do not implement scheduling by sleeping inside a daemon request handler.
- Do not let an event storm spawn unbounded training or sub-agents.
- Do not carry expired authority from the schedule definition into future runs.

**Required integration**

- Agent Instance, Collection, Eval, Training, and Improvement controllers use the generic recurrence/trigger layer.
- Message/route events may trigger through typed subscriptions.

**Validation and definition of done**

- G19, G29, G38, G49, and G70 validate trigger deduplication, 24/7 restart, periodic data/eval, and bounded evolution cycles.

**Required contracts / collaborating tasks:** `WORK-001`, `EVT-004`, `AUTH-006`

**Gold evidence:** `G19`, `G29`, `G38`, `G49`, `G70`

### Task 8 — WORK-008: Implement managed, observed, and unmanaged execution modes

**Anti-drift implementation goal**

Integrate existing external jobs without falsely claiming kernel control and provide a migration path to full governance.

**Required implementation**

1. Define managed mode: Splendor owns launch, resources, mounts, drivers, lifecycle, and receipts.
2. Define observed mode: an external orchestrator launches work, but registers immutable plan/attempt, emits signed lifecycle/output evidence, and accepts limited cancellation/inspection semantics.
3. Define unmanaged import: Splendor records externally produced artifacts/evidence as untrusted or externally attested history only.
4. Expose an explicit capability matrix for guarantees unavailable in observed/unmanaged modes, including fencing, secrets, data-use enforcement, checkpoint safety, and effect certainty.
5. Require gates/deployments to state whether external evidence meets their trust policy.

**Responsibility boundaries: this task must not drift into**

- Do not market observed Kubernetes/SLURM jobs as fully kernel-controlled.
- Do not grant trusted lineage because an external job supplied JSON.
- Do not block incremental adoption when honest reduced guarantees are acceptable.

**Required integration**

- Kubernetes/cluster adapters implement observed receipts; Artifact/Lineage classify trust; Gate Engine enforces policy.

**Validation and definition of done**

- G06 demonstrates all three modes and prevents guarantee confusion.
- A forged observed receipt cannot satisfy a production promotion gate.

**Required contracts / collaborating tasks:** `WORK-001`, `LIN-005`, `GATE-002`

**Gold evidence:** `G06`, `G14`

### Task 9 — WORK-009: Integrate current runs, daemon, CLI, and SDK without duplicate lifecycle owners

**Anti-drift implementation goal**

Move from agent-only run control to generic workloads while preserving the working local runtime.

**Required implementation**

1. Map current daemon run create/start/pause/resume/stop/cancel to an `agent_runtime` WorkloadSpec and retain `run_id` as profile identity, not workload identity.
2. Add generic workload create/inspect/control/events/results endpoints with idempotency and generated Rust/Python/TypeScript types.
3. Keep current agent endpoints as compatibility views that delegate to Workload Controller rather than maintaining parallel state machines.
4. Extend `splendorctl` with plan, submit, inspect, watch, cancel, checkpoint, resume, and explain commands.
5. Add SDK builders that require immutable refs and make managed/observed guarantees explicit.

**Responsibility boundaries: this task must not drift into**

- Do not delete stable 0.1 routes before compatibility policy permits.
- Do not put scheduler/node internals in public SDK models.
- Do not maintain a second status enum in each controller.

**Required integration**

- Daemon becomes transport/composition layer; current Scheduler/LoopEngine becomes one local worker provider.

**Validation and definition of done**

- All existing examples pass unchanged or through documented migration.
- G04 executes the same workload through Rust, Python, TypeScript, and CLI.

**Required contracts / collaborating tasks:** `WORK-001`, `FND-006`, `FND-010`

**Gold evidence:** `G04`, `G06`

### Task 10 — WORK-010: Harden reconciliation, garbage collection, and controller availability

**Anti-drift implementation goal**

Recover desired/observed workload truth after process or store failure without leaking resources or losing forensic state.

**Required implementation**

1. Implement idempotent reconcilers for queued reservations, starting attempts, running leases, checkpointing, cancelling, and terminal cleanup.
2. Use ownership generations/leases for controller workers and durable event/state cursors so only one reconciler commits a transition.
3. Detect orphan reservations, workers, mounts, upload sessions, temporary artifacts, and recurring trigger locks; clean only after fencing/retention checks.
4. Retain terminal metadata/evidence according to policy while garbage-collecting high-volume transient state separately.
5. Provide disaster recovery that rebuilds materialized workload state from events plus durable snapshots and reconciles nodes before issuing work.

**Responsibility boundaries: this task must not drift into**

- Do not delete uncertain attempts or partial artifacts to make state clean.
- Do not run global full scans continuously.
- Do not acknowledge controller failover until ownership fencing is established.

**Required integration**

- State/Event stores persist authoritative transitions; Fleet and Node agents answer reconciliation queries; Incident handles uncertainty.

**Validation and definition of done**

- G04, G65, G87, and G88 inject controller crash at every transition and verify no duplicate effect/current lease.
- Garbage collection never removes referenced checkpoint/evidence.

**Required contracts / collaborating tasks:** `WORK-004`, `EVT-006`, `STA-005`

**Gold evidence:** `G04`, `G65`, `G87`, `G88`

### Component completion gate

- All governed computation uses one durable workload/task/attempt lifecycle and exact immutable plan.
- The controller coordinates but never runs algorithms or treats process exit as sufficient success.
- Retries, cancellation, checkpointing, triggers, and recovery have explicit effect and fencing semantics.

---

## Component 14 — Driver Registry

**Canonical component ID:** `splendor.driver-registry`
**Plane:** `driver_boundary`
**Current status:** missing
**Owning package:** `crates/splendor-gateway (registry module) with manifests in splendor-types; concrete drivers remain adapter crates`

**Implemented baseline to preserve**

Filesystem, HTTP, robotics, gateway verifier, perceptor/policy hooks, and capability documents exist, but there is no unified versioned registry for perceptor, actuator, model, trainer, evaluator, data-operator, executor, secret, artifact, and capacity drivers with operation schemas, execution profiles, compatibility, maturity, and revocation.

**Exact kernel responsibility**

Own discoverable driver identity, manifests, operation schemas, compatibility, maturity/conformance evidence, installation scope, selection metadata, version lifecycle, and revocation. It never invokes drivers, grants permissions, or judges model/data quality.

**Public contracts:** `DriverManifest`, `DriverKind`, `DriverOperation`, `OperationSchema`, `ExecutionProfile`, `DriverVersion`, `DriverInstallation`, `DriverConformanceRef`, `DriverSelection`

### Task 1 — DRREG-001: Define the universal DriverManifest and operation contract

**Anti-drift implementation goal**

Standardize kernel-facing metadata across all driver families without forcing one implementation language or algorithm.

**Required implementation**

1. Define stable driver ID/version/digest, kind, provider, implementation transport, supported runtime versions/platforms, operation names, request/result schemas, streaming mode, side-effect class, idempotency, cancellation, compensation, data classifications, required capabilities, resource model, execution profiles, and maturity.
2. Support kinds perceptor, actuator, model, trainer, evaluator, data operator, sandbox executor, artifact backend, secret backend, capacity provider, governance, and observability exporter.
3. Require each operation to declare whether it is pure, read-only external, reversible, compensatable, irreversible, physical, training-mutating, or control-plane mutation.
4. Bind manifests to implementation artifact/image/binary digest and conformance evidence.
5. Map existing adapter name/action combinations to driver/operation aliases.

**Responsibility boundaries: this task must not drift into**

- Do not put provider credentials or mutable endpoints in the immutable manifest.
- Do not infer idempotency or side-effect class from operation name.
- Do not make all drivers implement every lifecycle method.

**Required integration**

- FND object schemas and current `CapabilityDocument` are extended; Driver Gateway consumes resolved operation contracts.

**Validation and definition of done**

- G07 validates manifests for current filesystem/HTTP/robotics plus reference model/trainer/evaluator/data/sandbox drivers.
- Missing effect/cancellation/schema declarations reject registration.

**Required contracts / collaborating tasks:** `FND-001`, `FND-005`

**Gold evidence:** `G07`

### Task 2 — DRREG-002: Implement registration, installation, and conformance admission

**Anti-drift implementation goal**

Prevent untested or mismatched driver code from becoming selectable merely by publishing a name.

**Required implementation**

1. Separate global driver definition/version from node/cluster installation and endpoint instance.
2. Verify artifact signature/digest, producer trust, runtime compatibility, required libraries/devices, and conformance report before accepting maturity.
3. Allow experimental/development drivers in explicitly permitted scopes and require conformant/certified maturity for configured risk classes.
4. Record installation health, node scope, endpoint identity, transport security, and last successful self-test.
5. Quarantine installations whose binary digest or reported operation set diverges from the manifest.

**Responsibility boundaries: this task must not drift into**

- Do not let a driver sign its own independent conformance result.
- Do not promote maturity because one node self-test passed.
- Do not expose experimental physical drivers to production routes by default.

**Required integration**

- Artifact/Lineage verify implementation; Node Agent reports installations; Authority restricts registrars/scopes.

**Validation and definition of done**

- G07 and G83 reject tampered, self-attested, incompatible, and changed-operation drivers.
- Revoked conformance removes production selection without deleting history.

**Required contracts / collaborating tasks:** `DRREG-001`, `ART-004`, `LIN-005`, `AUTH-003`

**Gold evidence:** `G07`, `G83`

### Task 3 — DRREG-003: Implement deterministic compatibility and driver resolution

**Anti-drift implementation goal**

Select an exact valid driver implementation while keeping policy, placement, and user preference explicit.

**Required implementation**

1. Resolve by requested kind/operation/schema, required profiles, platform/device, locality, runtime/API version, maturity, classification support, cancellation/idempotency needs, and tenant policy.
2. Return an ordered selection with immutable manifest/implementation/installation refs and explain rejected candidates.
3. Allow user-space preferences for provider/cost/latency but prevent them from bypassing hard policy or capability requirements.
4. Freeze the selection into WorkloadPlan/Invocation; do not follow mutable “latest” during execution.
5. Support explicit fallback sets whose semantics and risk are validated before admission.

**Responsibility boundaries: this task must not drift into**

- Do not choose a live driver for replay/simulation because no simulator exists.
- Do not silently fall back from local physical to cloud execution.
- Do not select by driver name alone when schemas/effect semantics differ.

**Required integration**

- Workload/Route controllers request resolution; Fleet Scheduler uses installation locality; Gateway receives exact selection.

**Validation and definition of done**

- G07, G15, G45, G61, and G73 validate deterministic selection/fallback and refusal.
- Same facts produce same selection digest.

**Required contracts / collaborating tasks:** `DRREG-001`, `DRREG-002`, `AUTH-001`

**Gold evidence:** `G07`, `G15`, `G45`, `G61`, `G73`

### Task 4 — DRREG-004: Implement driver lifecycle, revocation, deprecation, and rollout

**Anti-drift implementation goal**

Change driver versions without mutating running plans or leaving unsafe versions active.

**Required implementation**

1. Define active, deprecated, disabled, revoked, quarantined, and retired states per version/installation/operation.
2. Stop new resolution immediately on revocation; notify Workload/Agent/Deployment controllers of affected running usages for policy-specific containment.
3. Support side-by-side versions, compatibility windows, canary installation, health comparison, and rollback.
4. Require schema/effect/lifecycle changes to follow compatibility/RFC rules and update conformance.
5. Retain manifests and usage history for reproducibility after binaries are retired.

**Responsibility boundaries: this task must not drift into**

- Do not hot-swap a driver inside an active invocation.
- Do not kill all running read-only work on every deprecation.
- Do not erase a revoked driver from historical evidence.

**Required integration**

- Deployment Controller governs driver rollout; Incident/Lineage identify affected artifacts/effects; Node Agent installs/uninstalls.

**Validation and definition of done**

- G65, G75, and G83 test revocation during running workloads and rollback.
- New invocations refuse revoked versions; running behavior matches declared policy.

**Required contracts / collaborating tasks:** `DRREG-002`, `FND-006`, `DEP-005`

**Gold evidence:** `G65`, `G75`, `G83`

### Task 5 — DRREG-005: Implement capability discovery and schema/tooling APIs

**Anti-drift implementation goal**

Let application code discover what can be proposed without confusing discoverability with authority.

**Required implementation**

1. Expose access-filtered manifests, operation input/output JSON schemas, examples, execution profiles, maturity, compatibility, and installation availability.
2. Generate typed Rust/Python/TypeScript invocation builders and driver-authoring stubs from schemas.
3. Provide validation-only APIs that check requests without invoking or revealing protected endpoint details.
4. Support semantic tags and documentation references as non-authorizing metadata.
5. Cache discovery results with version/ETag and invalidate on revocation or policy change.

**Responsibility boundaries: this task must not drift into**

- Do not expose another tenant’s private driver/endpoints.
- Do not tell clients an operation is authorized merely because it is discoverable.
- Do not generate SDK code that can fabricate trusted results.

**Required integration**

- Daemon capability endpoint becomes a registry-backed view; Route/Agent builders consume generated schemas.

**Validation and definition of done**

- G00 and G07 round-trip generated requests/results and enforce access filtering.
- A discoverable but unauthorized operation is denied at planning/invocation.

**Required contracts / collaborating tasks:** `DRREG-001`, `FND-010`, `FND-009`

**Gold evidence:** `G00`, `G07`

### Task 6 — DRREG-006: Build the driver authoring kit and conformance workflow

**Anti-drift implementation goal**

Make high-quality third-party drivers feasible without moving provider logic into the kernel.

**Required implementation**

1. Provide Rust and Python SDKs for manifest generation, request/result validation, cancellation, progress/streaming, scoped handles, error taxonomy, and test fixtures.
2. Provide reference out-of-process transport and optional in-process Rust transport for tightly trusted drivers.
3. Generate a conformance suite from operation semantics, including replay profile, secret/data cleanup, timeout, duplicate request, postcondition, and fault tests.
4. Package driver implementation, manifest, SBOM/build provenance, schemas, and report as a signed bundle.
5. Document explicit trust/maturity requirements for physical and irreversible effect drivers.

**Responsibility boundaries: this task must not drift into**

- Do not require all providers to be written in Rust.
- Do not hide unsafe shell/network shortcuts in the SDK.
- Do not let a passing local test upload itself as certified without trusted CI/maintainer policy.

**Required integration**

- Reference drivers cover filesystem, HTTP, shell, Python, OCI, Kubernetes, model, trainer, evaluator, data, and simulated robotics.

**Validation and definition of done**

- G07 executes the same harness across every family; mandatory skips fail maturity.
- A third-party sample driver can be implemented without importing kernel internals.

**Required contracts / collaborating tasks:** `DRREG-001`, `FND-005`, `FND-010`

**Gold evidence:** `G07`, `G10`, `G12`, `G13`, `G14`, `G15`

### Component completion gate

- Every selectable operation has explicit schema, effect, lifecycle, compatibility, implementation digest, and conformance status.
- Discovery never grants authority; resolution never follows mutable latest during work.
- Concrete provider/framework logic remains outside kernel crates.

---

## Component 15 — Driver Gateway

**Canonical component ID:** `splendor.driver-gateway`
**Plane:** `driver_boundary`
**Current status:** partial foundation
**Owning package:** `crates/splendor-gateway (invocation module); current action gateway preserved as compatibility facade`

**Implemented baseline to preserve**

The existing `VerifiedActionGateway` provides strong mediation for action requests, verifier chains, adapter execution, approvals, quotas, circuit breakers, and physical safety. It is action-centric and does not yet mediate model, trainer, evaluator, data, perceptor, sandbox, artifact, secret, or capacity operations under one invocation lifecycle.

**Exact kernel responsibility**

Own the only kernel-mediated invocation path into drivers: exact selection, request validation, scoped handle issuance, pre/post verification, lifecycle, streaming, cancellation, idempotency, effect certainty, result validation, and evidence. It never chooses application intent, implements the provider, or converts a result into model promotion/deployment.

**Public contracts:** `Invocation`, `InvocationContext`, `InvocationDecision`, `InvocationLease`, `InvocationStatus`, `DriverRequest`, `DriverResult`, `DriverStreamFrame`, `CompensationRequest`, `InvocationReceipt`

### Task 1 — DGW-001: Implement the universal driver invocation state machine

**Anti-drift implementation goal**

Generalize the successful action gateway invariant to every agent-related privileged crossing.

**Required implementation**

1. Define invocation states proposed, validating, denied, waiting-approval, admitted, starting, running, streaming, cancelling, compensating, succeeded, failed, uncertain, and quarantined.
2. Bind invocation to principal/scope, workload/task/attempt/fencing, exact driver version/installation/operation/profile, request schema/digest, resource/data/secret grants, timeout, and causal parents.
3. Validate identity, current lease, schema, operation compatibility, authority, and required evidence before contacting the driver.
4. Persist required pre-effect event/decision, execute through selected transport, validate result/postconditions, and append terminal receipt.
5. Map current `ActionRequest/ActionOutcome` into actuator invocations without weakening no-side-effect-without-verifier.

**Responsibility boundaries: this task must not drift into**

- Do not call provider code before durable required pre-effect evidence.
- Do not let a generic invocation claim action authority it was not granted.
- Do not treat driver process success as valid result if schema/postconditions fail.

**Required integration**

- Workload/Route/Agent controllers submit proposals; Driver Registry supplies exact selection; current adapters use a compatibility wrapper.

**Validation and definition of done**

- G07 and G15 exercise every terminal transition; G01 verifies deny before provider call.
- Existing gateway tests remain green.

**Required contracts / collaborating tasks:** `DRREG-003`, `FND-003`, `FND-007`

**Gold evidence:** `G01`, `G07`, `G15`

### Task 2 — DGW-002: Implement composable pre-, in-, and post-invocation verifier stages

**Anti-drift implementation goal**

Apply authority, safety, data, resource, invariant, approval, and output checks consistently while preserving driver-specific verifiers.

**Required implementation**

1. Define ordered verifier stages for identity/lease, operation policy, data/secret scope, quota/resource, state/world preconditions, governance approval, physical safety, provider-specific checks, result schema, postconditions, and evidence obligations.
2. Require structured allow/deny/intervention/uncertain decisions with reason codes and artifacts; hard denials prevent provider contact.
3. Permit streaming/in-flight monitors to request cancel/hold for long operations, while the driver protocol reports effect certainty.
4. Separate advisory soft constraints from enforcing verifiers and record both.
5. Version verifier bundles and bind exact bundle digest to invocation receipts.

**Responsibility boundaries: this task must not drift into**

- Do not make prompt instructions an enforcement stage.
- Do not allow later verifier stages to override an earlier hard denial.
- Do not run remote high-latency policy calls in a physical emergency-stop path.

**Required integration**

- Gate/Authority/Data-Use/World/Physical services contribute verifier plugins; current permission/quota/invariant/approval/safety verifiers migrate.

**Validation and definition of done**

- G15, G27, G73, G78, and G80 validate hard/soft/approval/physical/adversarial paths.
- Verifier timeout follows declared fail-closed/intervention policy.

**Required contracts / collaborating tasks:** `DGW-001`, `AUTH-003`, `DUC-002`

**Gold evidence:** `G15`, `G27`, `G73`, `G78`, `G80`

### Task 3 — DGW-003: Issue scoped invocation handles for secrets, data, artifacts, state, and channels

**Anti-drift implementation goal**

Give a driver only the minimum resources needed for one operation and revoke them with invocation lifecycle.

**Required implementation**

1. Create opaque handles for input artifacts, output upload sessions, secret leases, data views, state/world read snapshots, progress channels, and optional constrained callback operations.
2. Bind handles to invocation/attempt/fencing, allowed operation, byte/record/time budgets, classification, and locality.
3. Deliver handles through the driver transport without embedding underlying credentials/paths in durable request objects.
4. Revoke and clean handles on denial, cancellation, terminal state, lease expiry, or driver quarantine; record non-secret cleanup receipts.
5. Require explicit sub-invocation capabilities if a driver needs nested model/tool operations.

**Responsibility boundaries: this task must not drift into**

- Do not give drivers direct store database connections or registry admin credentials.
- Do not let one invocation reuse another invocation’s output session or data handle.
- Do not expose secrets in trace/result serialization.

**Required integration**

- Secret Broker, Artifact Registry, Data-Use Controller, State/World services issue handles; Node Agent realizes local mounts.

**Validation and definition of done**

- G08, G16, G34, G82, and G83 prove scoping, revocation, and exfiltration prevention.
- Handle replay from stale attempt fails.

**Required contracts / collaborating tasks:** `DGW-001`, `SECR-002`, `ART-002`, `DUC-003`, `NODE-003`

**Gold evidence:** `G08`, `G16`, `G34`, `G82`, `G83`

### Task 4 — DGW-004: Implement idempotency, retry, compensation, and effect certainty

**Anti-drift implementation goal**

Prevent duplicate external effects and make uncertain outcomes first-class instead of hiding them behind retries.

**Required implementation**

1. Require operation-declared idempotency semantics and client-generated idempotency key for retryable effects.
2. Persist attempt/provider request identity and terminal receipt; return the same known result on duplicate current requests.
3. Classify failures as no-effect, effect-known, effect-uncertain, and effect-partial; automatically retry only where policy and operation semantics permit.
4. Support explicit compensation operations linked to the original invocation, with separate authority, verification, and evidence.
5. Open intervention/incident for irreducibly uncertain high-risk effects rather than guessing or blindly retrying.

**Responsibility boundaries: this task must not drift into**

- Do not assume HTTP retry safety from method name alone.
- Do not describe compensation as transaction rollback unless the provider guarantees it.
- Do not reuse historical approval for a compensation or retry outside scope.

**Required integration**

- Workload retry policy consumes effect certainty; Incident handles uncertainty; Actuator drivers declare compensation.

**Validation and definition of done**

- G15, G16, G47, and G87 inject dropped responses before/after effect and verify no duplicate or false certainty.

**Required contracts / collaborating tasks:** `DGW-001`, `FND-004`, `INC-001`

**Gold evidence:** `G15`, `G16`, `G47`, `G87`

### Task 5 — DGW-005: Implement streaming, flow control, cancellation, and deadlines

**Anti-drift implementation goal**

Support token streams, sensor streams, logs, progress, long tools, physical operations, and distributed worker channels without unbounded buffering.

**Required implementation**

1. Define ordered stream frames with invocation/stream/sequence, schema, timestamp, payload or artifact ref, integrity, and terminal marker.
2. Implement bounded buffers, backpressure, credits/windowing, heartbeat, idle deadline, resume policy, and consumer cancellation.
3. Distinguish advisory client disconnect from authoritative cancel; route cancel to driver and continue tracking until effect certainty/terminal state.
4. Allow local safety monitors to interrupt physical streams independently of remote consumers.
5. Move large frames to artifacts and preserve causal link in stream metadata.

**Responsibility boundaries: this task must not drift into**

- Do not buffer unbounded model tokens/video/sensor data in the gateway.
- Do not mark an operation cancelled because the client disconnected.
- Do not replay a live sensor/actuator stream as if it were current.

**Required integration**

- Perceptor/Model/Actuator/Trainer drivers use common streaming protocol; Observability exports summaries.

**Validation and definition of done**

- G20, G22, G23, G53, and G74 test backpressure, reconnect, cancellation, and physical local interruption.

**Required contracts / collaborating tasks:** `DGW-001`, `FND-008`

**Gold evidence:** `G20`, `G22`, `G23`, `G53`, `G74`

### Task 6 — DGW-006: Implement secure local and remote driver transports

**Anti-drift implementation goal**

Run drivers in-process, sidecar, subprocess, container, node service, or remote provider without changing invocation semantics.

**Required implementation**

1. Define transport-neutral handshake, protocol/schema negotiation, endpoint identity, mutual authentication, request/stream/cancel/result messages, and health.
2. Provide trusted in-process Rust, Unix-domain/local IPC, mutually authenticated remote RPC, and provider-HTTP bridge transports.
3. Bind endpoint to registered installation/implementation digest and reject operation drift after handshake.
4. Apply payload limits, timeouts, replay protection, connection pooling, and circuit breaking by driver/endpoint.
5. Preserve the same evidence and error taxonomy across transports.

**Responsibility boundaries: this task must not drift into**

- Do not expose an unauthenticated generic remote execution endpoint.
- Do not trust a TLS connection without driver/installation identity binding.
- Do not let transport-specific status replace kernel error/effect semantics.

**Required integration**

- Node Agent hosts local endpoints; Daemon/control plane routes remote invocations; Driver Registry tracks installations.

**Validation and definition of done**

- G07 runs one reference operation over each transport.
- MITM/replay/schema-downgrade and endpoint-drift tests deny.

**Required contracts / collaborating tasks:** `DGW-001`, `NODE-001`, `FND-006`

**Gold evidence:** `G07`, `G81`

### Task 7 — DGW-007: Enforce driver isolation and nested-operation policy

**Anti-drift implementation goal**

Keep provider code from bypassing the gateway or acquiring ambient authority.

**Required implementation**

1. Run out-of-process drivers in declared sandbox profiles with only scoped handles and required network/device access.
2. Require nested operations to be submitted as child invocations with causal parent and delegated capability; prohibit direct callbacks into privileged stores.
3. Limit recursion/depth/rate and detect cycles such as model driver invoking itself through a route.
4. Separate control-plane drivers from user-space algorithm plugins and require stronger maturity/isolation for irreversible/physical operations.
5. Quarantine driver installation on protocol forgery, undeclared network/device use, or result/effect inconsistency.

**Responsibility boundaries: this task must not drift into**

- Do not assume a Python driver is trusted because it uses the SDK.
- Do not let a trainer/evaluator call protected eval or deployment APIs directly.
- Do not allow arbitrary nested invocation graphs.

**Required integration**

- Sandbox Executor and Node Agent enforce environment; Authority attenuates child capabilities; Incident contains violations.

**Validation and definition of done**

- G80–G85 exercise ambient credential, recursive tool, protected eval, and forged result attacks.

**Required contracts / collaborating tasks:** `DGW-003`, `SBX-007`, `AUTH-005`, `INC-003`

**Gold evidence:** `G80`, `G81`, `G82`, `G83`, `G84`, `G85`

### Task 8 — DGW-008: Implement invocation evidence, redaction, and high-volume separation

**Anti-drift implementation goal**

Make every driver use auditable without turning traces into secret or payload dumps.

**Required implementation**

1. Record request/result schema and digest, selected driver/operation/profile, verifier decisions, scoped handle refs, timings, resource summary, effect certainty, output refs, and terminal reason.
2. Store large/sensitive request/result payloads as classified artifacts and expose deterministic redacted views.
3. Send high-volume tokens/sensor/progress/metrics to bounded stream/artifact/telemetry channels while preserving causal event refs.
4. Create an `InvocationReceipt` suitable for lineage, eval, change, physical audit, and replay substitution.
5. Ensure trace durability requirements are stricter before side effects than for optional telemetry.

**Responsibility boundaries: this task must not drift into**

- Do not log prompts, secrets, protected eval cases, raw physical frames, or dataset records by default.
- Do not omit a denied invocation because the driver was never called.
- Do not let redaction alter decision reason or causal shape.

**Required integration**

- Event/Evidence/Artifact/Lineage services consume receipts; Observability consumes summaries.

**Validation and definition of done**

- G03, G15, G39, G73, and G82 validate evidence completeness and redaction.
- Payload-size stress does not break control-plane latency.

**Required contracts / collaborating tasks:** `DGW-001`, `EVID-001`, `FND-009`

**Gold evidence:** `G03`, `G15`, `G39`, `G73`, `G82`

### Task 9 — DGW-009: Migrate current action adapters through the universal gateway

**Anti-drift implementation goal**

Preserve the strongest implemented boundary while eliminating parallel invocation semantics.

**Required implementation**

1. Wrap filesystem, HTTP, and robotics `ActionAdapter` operations as actuator driver manifests and invocation handlers.
2. Translate current permission/quota/invariant/approval/circuit-breaker/physical safety checks into ordered verifier stages with identical fail-closed behavior.
3. Preserve ActionRequest/Outcome APIs as compatibility facades backed by Invocation records and IDs linked explicitly.
4. Update daemon and loop engine to call the universal gateway without changing existing traces unexpectedly; emit compatibility event mapping.
5. Add migration tests for replay inspect-only, approval pause/resume, and physical safety evidence.

**Responsibility boundaries: this task must not drift into**

- Do not rewrite history or reuse ActionId as InvocationId.
- Do not relax adapters-only side-effect invariant during migration.
- Do not maintain two separate quota ledgers.

**Required integration**

- Current examples become first production-conformant actuator drivers.

**Validation and definition of done**

- All existing gateway/daemon/physical tests pass plus G07/G15/G73.
- Compatibility exports identify both action and invocation identity.

**Required contracts / collaborating tasks:** `DGW-001`, `DGW-002`, `FND-006`

**Gold evidence:** `G07`, `G15`, `G73`

### Component completion gate

- No driver operation—perception, model, training, eval, data, sandbox, or effect—crosses the boundary without an exact invocation and current scoped authority.
- Pre-effect evidence, verifier ordering, fencing, effect certainty, and result validation are consistent across transports.
- The gateway mediates; it never promotes, deploys, or embeds provider algorithms.

---

## Component 16 — Perceptor Driver Contract and Reference Drivers

**Canonical component ID:** `splendor.perceptor-driver`
**Plane:** `driver_boundary`
**Current status:** partial foundation
**Owning package:** `contract in crates/splendor-types and splendor-gateway; concrete providers in `adapters/perceptors/*``

**Implemented baseline to preserve**

A `Perceptor` trait collects vectors of minimal `Percept {schema,payload,provenance,timestamp}` values, daemon percept append endpoints validate allowlists, and device/simulation examples exist. Missing are stable perceptor manifests, event identity, source sequence/cursors, push/stream/subscription modes, clock/calibration/uncertainty, quality/freshness, artifact-backed modalities, data-use enforcement, backpressure, and cross-device recovery.

**Exact kernel responsibility**

Define and implement the driver-side contract that converts an external environment, sensor, tool, service, user channel, or agent into governed observations. It owns source interaction and declared normalization; it does not update world truth, choose policy, train models, or grant action authority.

**Public contracts:** `PerceptorManifest`, `Observation`, `ObservationBatch`, `ObservationProvenance`, `SourceCursor`, `SourceClock`, `QualitySignal`, `CalibrationRef`, `PerceptorSubscription`

### Task 1 — PERC-001: Define the observation envelope, identity, and provenance model

**Anti-drift implementation goal**

Make percepts usable for world state, learning, feedback, and audit across arbitrary modalities without placing modality payloads in core.

**Required implementation**

1. Introduce `observation_id`, source identity, source sequence/cursor, acquisition time, receive time, schema/version, payload ref or bounded inline payload, provenance chain, classification, quality/freshness, calibration ref, uncertainty summary, and causal parents.
2. Distinguish raw observation, normalized observation, derived feature, external assertion, user message, system event, and simulated/replayed observation.
3. Define modality as extensible metadata/media type rather than a closed text/image/audio enum.
4. Preserve current `Percept` as a compatibility view and create deterministic mapping to `Observation`.
5. Require source-specific identifiers/cursors where available so duplicates and gaps can be reasoned about.

**Responsibility boundaries: this task must not drift into**

- Do not make source timestamp globally trustworthy.
- Do not treat an observation as a verified world fact.
- Do not inline unbounded video/audio/tensor/document payloads in trace or state.

**Required integration**

- Artifact Registry stores large payloads; Event Log records receipt; World-State Service decides assimilation.

**Validation and definition of done**

- G20 and G21 round-trip text, image, audio, telemetry, document, message, and custom tensor observations.
- Duplicate IDs, invalid provenance, and schema/classification mismatch fail.

**Required contracts / collaborating tasks:** `DRREG-001`, `ART-001`, `FND-008`

**Gold evidence:** `G20`, `G21`

### Task 2 — PERC-002: Implement pull, push, subscription, and streaming lifecycle profiles

**Anti-drift implementation goal**

Support polling APIs, event buses, sensors, files, databases, human input, and continuous physical streams through one lifecycle.

**Required implementation**

1. Declare per-operation mode: snapshot pull, cursor pull, webhook/push ingest, subscription, finite stream, continuous stream, or trigger-only.
2. Implement open/start/read/ack/commit-cursor/pause/resume/close/health methods only where the profile requires them.
3. Bind subscriptions and cursors to workload/agent instance, source scope, data purpose, schema, and lease generation.
4. Define delivery semantics at-most-once, at-least-once, source-exactly-once-when-supported, and best-effort with explicit gaps.
5. Route every provider interaction through Driver Gateway, including subscription creation and acknowledgement.

**Responsibility boundaries: this task must not drift into**

- Do not claim exactly-once when the source lacks stable cursor/transaction semantics.
- Do not keep a subscription alive after its data-use or workload lease expires.
- Do not model continuous sensors as repeated synchronous daemon HTTP calls.

**Required integration**

- Agent Instance and Collection Controller own consumption/cursor commit; Gateway owns invocation/stream state.

**Validation and definition of done**

- G20–G22 cover all lifecycle profiles, restart from cursor, source duplication, and disconnect.
- Lease expiry terminates or pauses source according to policy.

**Required contracts / collaborating tasks:** `PERC-001`, `DGW-005`, `WORK-007`

**Gold evidence:** `G20`, `G21`, `G22`

### Task 3 — PERC-003: Implement ordering, watermarks, deduplication, freshness, and backpressure

**Anti-drift implementation goal**

Make asynchronous and multi-source observations operationally coherent without inventing total order.

**Required implementation**

1. Track source sequence, receive sequence, event-time watermark, allowed lateness, gap markers, duplicate fingerprints, and out-of-order policy.
2. Provide bounded buffers and consumer credits; define source-specific drop, sample, spill-to-artifact, or pause behavior.
3. Emit explicit stale, duplicate, gap, overflow, and source-reset observations/events rather than silently hiding them.
4. Allow application code to select event-time/window semantics while kernel enforces bounds and cursor durability.
5. Commit durable cursor only after configured downstream acceptance to avoid invisible data loss.

**Responsibility boundaries: this task must not drift into**

- Do not impose a false global order across independent sensors.
- Do not drop observations without an evidenced policy decision.
- Do not let slow learning/data consumers stall a physical safety consumer sharing the same source.

**Required integration**

- Collection Controller can fork governed streams; Agent Instance has independent consumer cursors; Event Log stores control metadata.

**Validation and definition of done**

- G22 saturates a stream and proves bounded memory, explicit gaps, independent consumers, and deterministic cursor recovery.

**Required contracts / collaborating tasks:** `PERC-002`, `EVT-004`, `STA-006`

**Gold evidence:** `G22`, `G29`

### Task 4 — PERC-004: Implement artifact-backed multimodal payload and transform declarations

**Anti-drift implementation goal**

Handle arbitrary sensor/model/document payloads efficiently while preserving exact source bytes and declared transformations.

**Required implementation**

1. Upload large payloads through artifact sessions before or alongside observation publication, with chunking/streaming where supported.
2. Declare transforms such as decoding, resizing, resampling, compression, unit conversion, tokenization, embedding, redaction, or feature extraction as versioned user-space/driver artifacts with lineage.
3. Preserve raw artifact refs when policy allows and link normalized/derived artifacts rather than overwriting them.
4. Validate media/schema, dimensions/rates/units, payload digest, and bounded preview metadata.
5. Support zero-copy/local handles only as lease-scoped optimization; durable identity remains content-addressed.

**Responsibility boundaries: this task must not drift into**

- Do not standardize one tensor layout or tokenizer in kernel core.
- Do not label a transformed feature as raw sensor evidence.
- Do not retain raw sensitive media merely for convenience when policy requires early redaction/deletion.

**Required integration**

- Artifact/Lineage services own bytes/derivation; Data-Use governs retention; Model/Data drivers can perform transforms.

**Validation and definition of done**

- G21 processes large image/audio/custom tensors and verifies raw/derived lineage and retention.
- Corrupt partial media never becomes accepted observation.

**Required contracts / collaborating tasks:** `PERC-001`, `ART-002`, `LIN-002`, `DUC-004`

**Gold evidence:** `G21`, `G26`

### Task 5 — PERC-005: Implement source quality, calibration, uncertainty, and health signals

**Anti-drift implementation goal**

Expose measurement limitations so world models and policies can reason instead of treating all inputs as equally reliable.

**Required implementation**

1. Define optional quality dimensions such as completeness, signal validity, confidence, resolution, noise, drift, saturation, occlusion, packet loss, and source health using named schemas.
2. Reference immutable calibration artifacts and validity windows; detect missing/expired/incompatible calibration.
3. Allow drivers to emit uncertainty summaries and health facts but keep interpretation/fusion in user-space/world/eval code.
4. Add source self-tests and cross-check hooks whose results are evidence, not automatic truth.
5. Propagate quality and calibration refs into observation lineage and downstream eval slices.

**Responsibility boundaries: this task must not drift into**

- Do not define one universal confidence scale.
- Do not let a driver mark itself trustworthy without independent evaluation.
- Do not hide missing calibration behind a default zero uncertainty.

**Required integration**

- World-State assimilation consumes quality; Gate/Route may require minimum source health for actions; Eval Controller slices by quality.

**Validation and definition of done**

- G23 and G74 degrade/corrupt sensors and prove uncertainty/fallback/local safety behavior.
- Expired calibration blocks configured physical actions but may permit clearly marked observation.

**Required contracts / collaborating tasks:** `PERC-001`, `EVID-002`, `WORLD-003`

**Gold evidence:** `G23`, `G73`, `G74`

### Task 6 — PERC-006: Enforce data-use, privacy, consent, and source authority at collection time

**Anti-drift implementation goal**

Prevent perception from becoming an unrestricted data-exfiltration path.

**Required implementation**

1. Require a source capability and collection/data-use purpose for opening subscriptions, polling protected sources, or storing payloads.
2. Apply source/field/region/person/tenant filters and minimization before durable publication where technically possible.
3. Attach consent/licence/privacy-zone/retention obligations as non-forgeable refs; support source revocation and deletion propagation.
4. Keep safety-local sensor evidence on device when policy requires, exporting only bounded safety summaries.
5. Separate observations permitted for live operation from those permitted for training, evaluation, debugging, or sharing.

**Responsibility boundaries: this task must not drift into**

- Do not assume data visible to an agent is automatically trainable.
- Do not let payload fields carry their own consent or permissions.
- Do not upload raw physical/privacy-zone media to cloud helper by default.

**Required integration**

- Data-Use Controller authorizes and Collection Controller manages obligations; Node Agent enforces locality.

**Validation and definition of done**

- G26, G34, G35, and G73 validate purpose separation, consent revocation, deletion impact, and safety-local summaries.

**Required contracts / collaborating tasks:** `PERC-002`, `DUC-001`, `NODE-004`

**Gold evidence:** `G26`, `G34`, `G35`, `G73`

### Task 7 — PERC-007: Implement live, recorded, simulated, and null execution profiles

**Anti-drift implementation goal**

Make replay, tests, counterfactuals, and physical simulation safe and semantically explicit.

**Required implementation**

1. Require every production perceptor operation to declare supported live/recorded/simulated/null profiles and fidelity limitations.
2. Recorded profile serves immutable observations with original timing or virtual-clock schedule and provenance marked recorded.
3. Simulated profile obtains observations from a declared simulator/world model and links simulation configuration/seed.
4. Null/deny profile returns explicit absence where source use is prohibited.
5. Prevent profile changes during a running subscription without a new invocation/route epoch.

**Responsibility boundaries: this task must not drift into**

- Do not label recorded camera data as live.
- Do not silently use live sensors in replay when no recording exists.
- Do not promote simulator outputs into live world truth automatically.

**Required integration**

- Replay/Simulation resolves profiles; World-State distinguishes observation classes; Driver conformance traps live access.

**Validation and definition of done**

- G03, G23, G25, and G73 prove profile isolation and provenance.
- A perceptor lacking a non-live profile causes simulation plan denial.

**Required contracts / collaborating tasks:** `PERC-001`, `RPLY-002`

**Gold evidence:** `G03`, `G23`, `G25`, `G73`

### Task 8 — PERC-008: Build reference perceptors across software and physical domains

**Anti-drift implementation goal**

Prove the abstraction is not overfit to text prompts or one sensor stack.

**Required implementation**

1. Implement reference drivers for HTTP polling/webhook, filesystem watch, message bus, database change feed, human input queue, model-generated observation, process/log stream, and timer/event trigger.
2. Implement simulated and development physical drivers for camera/frame refs, IMU/GPS/telemetry, battery/status, and robot mission state without hard real-time control claims.
3. Implement sub-agent/message perceptor and protected eval input perceptor with access separation.
4. Use common schemas only for envelope/lifecycle; each domain payload has its own versioned schema.
5. Ship runnable examples with disconnect, duplication, backpressure, calibration, privacy, and replay tests.

**Responsibility boundaries: this task must not drift into**

- Do not call development physical drivers production-certified.
- Do not add provider/domain parsing to kernel crates.
- Do not create one “generic sensor JSON” schema for every modality.

**Required integration**

- Agent/world/data examples consume reference drivers; Driver Registry publishes their maturity.

**Validation and definition of done**

- G20–G23 and G73–G74 pass across at least three transports and two modalities.

**Required contracts / collaborating tasks:** `PERC-001`, `PERC-007`, `DRREG-006`

**Gold evidence:** `G20`, `G21`, `G22`, `G23`, `G73`, `G74`

### Task 9 — PERC-009: Add perceptor conformance and adversarial validation

**Anti-drift implementation goal**

Make source lifecycle, data controls, and observation integrity testable for third-party drivers.

**Required implementation**

1. Generate tests from manifest for schema, sequence/cursor, cancellation, backpressure, payload limits, artifact integrity, classification, data-use expiry, and execution profiles.
2. Inject source reset, duplicates, reordering, stale clock, malformed payload, calibration expiry, privacy-zone violation, and driver crash.
3. Trap undeclared network/filesystem/device access and raw payload leakage into events/logs.
4. Verify cursor/mount/subscription cleanup after every terminal path.
5. Publish conformance evidence per operation/profile, not one blanket driver badge.

**Responsibility boundaries: this task must not drift into**

- Do not allow mandatory lifecycle tests to be skipped because a driver is inconvenient.
- Do not accept provider logs as proof of no data leakage.
- Do not certify simulation fidelity from interface conformance alone.

**Required integration**

- Driver Registry maturity and Gate policies consume reports.

**Validation and definition of done**

- G07 and G20–G23 reject intentionally faulty perceptors and retain precise failure evidence.

**Required contracts / collaborating tasks:** `PERC-002`, `PERC-006`, `FND-005`

**Gold evidence:** `G07`, `G20`, `G21`, `G22`, `G23`

### Component completion gate

- Observations have identity, provenance, timing, quality, classification, and lifecycle independent of payload modality.
- A perceptor observes; world truth, policy, reward, and learning remain separately owned.
- Every source access is purpose-scoped, bounded, replay-profiled, and conformance-tested.

---

## Component 17 — Actuator Driver Contract and Reference Drivers

**Canonical component ID:** `splendor.actuator-driver`
**Plane:** `driver_boundary`
**Current status:** partial foundation
**Owning package:** `contract in crates/splendor-types and splendor-gateway; concrete implementations in `adapters/actuators/*``

**Implemented baseline to preserve**

Filesystem, HTTP, and high-level simulated robotics adapters already execute verified `Action`s with pre/postconditions, permissions, quotas, approval, circuit-breaker, and safety checks. Missing are a complete actuator operation contract, effect/idempotency/compensation semantics, long-running actions, device-local execution, shell/database/Kubernetes adapters, sub-agent actuators, result observation linkage, and conformance across uncertain failures.

**Exact kernel responsibility**

Translate an admitted high-level action invocation into one bounded external effect and report exact result/effect certainty. It owns provider/device interaction and declared compensation; it does not decide the action, bypass verification, mutate agent/world state directly, or declare improvement.

**Public contracts:** `ActuatorManifest`, `ActuatorOperation`, `EffectClass`, `ActionCommand`, `ActionReceipt`, `CompensationSpec`, `LongOperationHandle`, `PhysicalActionContract`

### Task 1 — ACT-001: Define actuator operations and capability semantics

**Anti-drift implementation goal**

Make effectful interfaces explicit enough for software services, subprocesses, infrastructure, sub-agents, and physical devices.

**Required implementation**

1. Define operation schema, required capabilities, target scope, effect class, idempotency, preconditions, postconditions, timeout/deadline, cancellation, compensation, observability, and result schema.
2. Distinguish read-only external access, reversible mutation, compensatable mutation, irreversible digital effect, high-level physical effect, and local emergency/safety operation.
3. Bind operation capability to exact resource/endpoint/device and parameter constraints, not only an action name.
4. Map existing `Action` fields into the contract and retain action identity linked to invocation identity.
5. Allow extensible domain operations without a global action-name namespace collision.

**Responsibility boundaries: this task must not drift into**

- Do not infer effect safety from HTTP method, shell command name, or provider documentation.
- Do not expose raw motor/firmware control as a generic high-level actuator.
- Do not make an action payload carry its own permission or approval.

**Required integration**

- Authority Service grants operations/scopes; Driver Registry publishes semantics; Gateway enforces.

**Validation and definition of done**

- G15, G16, and G73 validate digital, database, and physical contracts.
- Incomplete effect/idempotency declarations cannot reach conformant maturity.

**Required contracts / collaborating tasks:** `DRREG-001`, `DGW-001`

**Gold evidence:** `G15`, `G16`, `G73`

### Task 2 — ACT-002: Implement precondition, postcondition, and outcome observation contracts

**Anti-drift implementation goal**

Connect proposed effects to verifiable state/world conditions and observed outcomes without trusting the actuator alone.

**Required implementation**

1. Represent preconditions/postconditions as typed predicate refs evaluated by verifier providers against pinned state/world snapshots or local safety status.
2. Require actuator results to include provider receipt, observed identifiers, changed-resource refs, satisfied/failed declared postconditions, and effect certainty.
3. Support independent outcome perceptors/verifiers to confirm externally observable effects after execution.
4. Record expected versus observed state delta as evidence; State/World services accept only separate update proposals.
5. Define timeout windows and inconclusive postcondition behavior.

**Responsibility boundaries: this task must not drift into**

- Do not let the actuator directly mark arbitrary postconditions satisfied without evidence policy.
- Do not update world truth from a provider success code alone.
- Do not erase a successful effect because post-verification failed; report effect plus failed assurance.

**Required integration**

- World-State, State, Perceptor, and Gateway verifier stages contribute facts.

**Validation and definition of done**

- G15 and G47 inject false provider success, delayed outcome, and postcondition failure.
- Effect remains traceable while follow-up/incident behavior is correct.

**Required contracts / collaborating tasks:** `ACT-001`, `DGW-002`, `WORLD-003`

**Gold evidence:** `G15`, `G47`, `G73`

### Task 3 — ACT-003: Implement idempotent, compensatable, and uncertain-effect operation patterns

**Anti-drift implementation goal**

Provide reusable safe patterns for common external mutation semantics while retaining provider-specific truth.

**Required implementation**

1. Provide SDK helpers for provider idempotency keys, compare-and-set/versioned update, transactional database operation, create-if-absent, append-with-dedup, and immutable object publication.
2. Define compensation plan schemas referencing original result/resource version and requiring independent capability and verification.
3. Capture request-sent, provider-accepted, effect-observed, response-received, and compensation states where supported.
4. Route unknown outcome to `uncertain` and intervention/incident; support reconciliation perceptors that later resolve certainty.
5. Make retry behavior operation-specific and bounded.

**Responsibility boundaries: this task must not drift into**

- Do not claim exactly-once external effects generically.
- Do not automatically compensate physical or irreversible effects.
- Do not retry after timeout when provider acceptance is unknown unless operation contract proves idempotency.

**Required integration**

- Gateway handles generic effect state; provider drivers implement exact primitives; Incident/Reconciliation handles uncertainty.

**Validation and definition of done**

- G15, G16, G47, and G87 cover dropped responses, duplicates, compensation failure, and later reconciliation.

**Required contracts / collaborating tasks:** `ACT-001`, `DGW-004`

**Gold evidence:** `G15`, `G16`, `G47`, `G87`

### Task 4 — ACT-004: Implement long-running and streaming actuator operations

**Anti-drift implementation goal**

Control jobs, deployments, remote builds, robot missions, and other effects that outlive one request/response.

**Required implementation**

1. Define start/status/progress/cancel/hold/resume/finalize operations around a stable provider operation handle.
2. Bind status polling/subscription and cancellation to the original invocation authority and fencing generation.
3. Separate accepted/started/running/completed from merely submitted; capture external operation identity and expiry.
4. Support local safety hold/emergency stop independently of cloud connectivity for physical operations.
5. Reconcile after gateway/node restart without duplicating start.

**Responsibility boundaries: this task must not drift into**

- Do not treat “job submitted” as action completed.
- Do not lose control because the client session ended.
- Do not poll unboundedly without quota/deadline.

**Required integration**

- Workload Controller may model the external operation as a child workload; Gateway maintains invocation lifecycle; Perceptor observes status.

**Validation and definition of done**

- G14, G15, G73, and G75 test job/mission lifecycle, cancel, disconnect, and restart.

**Required contracts / collaborating tasks:** `ACT-001`, `DGW-005`, `WORK-005`

**Gold evidence:** `G14`, `G15`, `G73`, `G75`

### Task 5 — ACT-005: Implement shell, process, database, Kubernetes, and service reference actuators

**Anti-drift implementation goal**

Cover essential software actuation with narrow safe contracts rather than a single unrestricted command executor.

**Required implementation**

1. Keep restricted argv process execution in Sandbox Executor and expose only explicitly registered commands/working directories/env/mounts as actuator operations.
2. Provide an explicit high-risk `sh -c` operation requiring stronger capability, sandbox, egress/filesystem policy, and approval where configured.
3. Implement database driver operations for parameterized query/transaction/migration with datasource scope, statement class, row/byte/time limits, and transaction outcome.
4. Implement Kubernetes operations for applying exact signed manifests, starting Jobs, querying status, and rollback through scoped cluster credentials—not raw cluster-admin shell.
5. Implement HTTP/service operations with endpoint/method/schema/egress/rate/idempotency constraints.

**Responsibility boundaries: this task must not drift into**

- Do not make unrestricted shell the universal adapter.
- Do not pass raw SQL or Kubernetes admin credentials without an operation-specific policy.
- Do not duplicate sandbox execution logic inside actuator drivers.

**Required integration**

- Sandbox Executor owns isolation; Secret Broker delivers credentials; Gateway verifies target/action scopes.

**Validation and definition of done**

- G10–G16 prove safe and denied paths, injection resistance, quotas, uncertain outcomes, and cleanup.

**Required contracts / collaborating tasks:** `ACT-001`, `SBX-001`, `SECR-002`

**Gold evidence:** `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`

### Task 6 — ACT-006: Implement physical-device and robot high-level actuator boundary

**Anti-drift implementation goal**

Permit useful physical AI while ensuring local safety, capability, and control remain on the device.

**Required implementation**

1. Define high-level physical operations such as navigate-to bounded region, inspect, capture, grasp-with-profile, mission start/hold/return, or device-specific equivalents through versioned domain schemas.
2. Require device identity, local actuator capability, coordinate/frame refs, limits, safety policy version, freshness, deadline, and fallback/hold behavior.
3. Execute final precondition and safety verification on the resident device using current local sensor/status; cloud outputs remain advisory proposals.
4. Support emergency stop/hold paths outside ordinary remote gateway latency and prohibit bypass by model, planner, shell, or cloud-helper code.
5. Record trace-safe safety evidence and bounded outcome summaries; keep raw safety-local sensor data under local policy.

**Responsibility boundaries: this task must not drift into**

- Do not claim hard real-time motor control or certification.
- Do not let a cloud model directly command actuators.
- Do not execute when coordinate frame, safety policy, or critical sensor freshness is uncertain.

**Required integration**

- Build on current device profiles, allowed physical action patterns, safety verifier, offline cache, and robotics simulation harness.

**Validation and definition of done**

- G73–G75 and G80 test local deny/hold/estop, cloud-helper authority separation, offline operation, and prompt/tool bypass.

**Required contracts / collaborating tasks:** `ACT-001`, `NODE-006`, `DGW-002`, `WORLD-009`

**Gold evidence:** `G73`, `G74`, `G75`, `G80`

### Task 7 — ACT-007: Implement sub-agent and trigger-agent actuator profiles

**Anti-drift implementation goal**

Make delegation a first-class governed action while preserving separate agent identity and attenuated authority.

**Required implementation**

1. Define `spawn_agent`, `delegate_task`, `send_request`, `await_response`, `cancel_child`, and `register_trigger` operations backed by Agent/Message services.
2. Require a target AgentSpec/revision or allowed dynamic template, delegated scope/capabilities/data refs, resource/time budget, parent run/workload, and response schema.
3. Treat child response as an observation/result, not as trusted action authority or world truth.
4. Bound recursion, fan-out, duration, and authority attenuation; revoke child authority on cancellation/expiry.
5. Support a persistent trigger agent with its own identity and independently governed actions.

**Responsibility boundaries: this task must not drift into**

- Do not run sub-agents inside an actuator driver implementation.
- Do not inherit parent permissions by default.
- Do not let child text or messages widen authority.

**Required integration**

- Agent Instance Controller realizes child workloads; Message/Delegation routes communication; Gateway mediates operation.

**Validation and definition of done**

- G18, G19, G70, and G81 prove specialist delegation, trigger behavior, recursion limits, and forged-message resistance.

**Required contracts / collaborating tasks:** `ACT-001`, `AGREG-005`, `MSG-003`, `AINST-006`

**Gold evidence:** `G18`, `G19`, `G70`, `G81`

### Task 8 — ACT-008: Implement actuator conformance, simulation, and fault validation

**Anti-drift implementation goal**

Prove each effectful driver has honest lifecycle and safety behavior before production use.

**Required implementation**

1. Generate tests for operation schema, capability scope, no-call-on-deny, idempotency, duplicate requests, timeout before/after effect, cancellation, compensation, postconditions, output redaction, and cleanup.
2. Require recorded/simulated/null profiles or an explicit no-simulation declaration with affected test/route restrictions.
3. Use effect sentinels and disposable resources to distinguish no-effect, one-effect, partial, and uncertain cases.
4. For physical drivers, require simulation-harness and local safety tests but label certification outside scope.
5. Publish per-operation conformance/fidelity evidence and quarantine inconsistent behavior.

**Responsibility boundaries: this task must not drift into**

- Do not certify an irreversible operation without injected uncertain-failure cases.
- Do not call a mock a faithful physical simulator solely because schemas match.
- Do not permit skipped postcondition tests to pass maturity.

**Required integration**

- Driver Registry/Gate consume reports; Replay resolves non-live profiles.

**Validation and definition of done**

- G07, G15, G16, G45, and G73 reject intentionally faulty digital and physical actuators.

**Required contracts / collaborating tasks:** `ACT-001`, `FND-005`, `RPLY-002`

**Gold evidence:** `G07`, `G15`, `G16`, `G45`, `G73`

### Component completion gate

- Actuators execute only bounded, verified operations with explicit effect semantics and current target capability.
- External success, observed outcome, state/world update, reward, and promotion remain distinct.
- Uncertain and physical effects fail safely and retain local control/evidence.

---

## Component 18 — Model Driver Contract and Reference Drivers

**Canonical component ID:** `splendor.model-driver`
**Plane:** `driver_boundary`
**Current status:** missing
**Owning package:** `contract in crates/splendor-types and splendor-gateway; implementations in `adapters/models/*`; optional Python helpers in `python/splendor``

**Implemented baseline to preserve**

Current policy callbacks may call any model in user space, but Splendor has no first-class model identity, loading/session lifecycle, structured invocation, local/remote provider abstraction, batching/streaming, multimodal payloads, state/cache management, resource accounting, or model-level routing evidence. Model artifacts and activation are not separated explicitly.

**Exact kernel responsibility**

Expose inference and model-computation operations for arbitrary neural networks, LLMs, classical learned models, or differentiable modules through governed invocations. It owns model runtime/provider interaction and session-local compute state; it never decides policy, trains/updates weights, assigns reward, or activates a candidate.

**Public contracts:** `ModelManifest`, `ModelArtifactBinding`, `ModelOperation`, `InferenceRequest`, `InferenceResult`, `ModelSession`, `BatchPolicy`, `ModelRuntimeProfile`, `AdapterComposition`

### Task 1 — MODEL-001: Define model manifests, artifacts, operations, and compatibility

**Anti-drift implementation goal**

Represent models from custom PyTorch modules to remote LLM APIs without making “text generation” the universal contract.

**Required implementation**

1. Define model identity/revision as immutable bundle refs containing architecture/code or provider model ref, weights, processor/tokenizer/codec, config, environment/runtime, licence/classification, supported operations, input/output schemas, and compatibility.
2. Support operations such as forward, generate, embed, score, classify, value/critic, encode/decode, predict transition, custom named tensor/structured operation, and remote provider call.
3. Declare modality/media schemas, batching constraints, statefulness, streaming, determinism class, numerical precision, resource envelopes, context/window limits, and allowed adapter composition.
4. Separate logical model artifact from runtime installation/loaded instance/session and from deployment alias.
5. Allow opaque custom payload schemas and artifact-backed tensors while keeping privileged fields typed.

**Responsibility boundaries: this task must not drift into**

- Do not hard-code Transformer or LLM assumptions in core.
- Do not identify a model by mutable provider name or filesystem path.
- Do not treat a model manifest as evidence of quality/alignment.

**Required integration**

- Artifact/Lineage store model bundles; Driver Registry publishes runtime operations; Deployment owns aliases.

**Validation and definition of done**

- G53 and G54 invoke a GPT-style Transformer and a non-language custom neural net through the same envelope.
- Model/processor/version mismatch fails before loading.

**Required contracts / collaborating tasks:** `ART-001`, `DRREG-001`

**Gold evidence:** `G53`, `G54`

### Task 2 — MODEL-002: Implement model load, instance, session, and unload lifecycle

**Anti-drift implementation goal**

Control expensive model state and prevent mutable runtime caches from becoming hidden agent state.

**Required implementation**

1. Define load requests with exact artifact/runtime/device/precision/quantization/adapter refs and resource lease; return loaded-instance identity and measured footprint.
2. Support warm pools and instance reuse only when tenant/classification/session isolation permits; pin implementation/model digest.
3. Define session state for KV cache, recurrent hidden state, decoder state, or custom opaque state with size/TTL/ownership and optional checkpoint/export profile.
4. Make session state explicit as ephemeral, state-service-backed, or artifact-backed; never hide it from lifecycle/evidence policy.
5. Implement drain/unload/eviction and OOM/corrupt-load recovery without changing deployment alias implicitly.

**Responsibility boundaries: this task must not drift into**

- Do not let one tenant/agent inherit another session cache.
- Do not treat process memory as durable agent memory.
- Do not unload protected live instances solely to admit background training.

**Required integration**

- Node Agent allocates resources; State Service may own durable session refs; Fleet/Deployment manage warm placement.

**Validation and definition of done**

- G53 tests cold/warm/session isolation and node restart.
- Memory-pressure tests preserve reserved live service and produce exact eviction evidence.

**Required contracts / collaborating tasks:** `MODEL-001`, `NODE-003`, `STA-001`

**Gold evidence:** `G53`, `G68`

### Task 3 — MODEL-003: Implement generic inference request/result and streaming semantics

**Anti-drift implementation goal**

Serve structured, tensor, multimodal, and generative model calls with bounded, schema-valid evidence.

**Required implementation**

1. Define input refs/inline bounds, operation-specific parameters, seed/sampling config, session ref, output schema, resource/deadline/cost budgets, and requested evidence detail.
2. Support finite results and ordered streams; attach token/frame/chunk sequence, usage, finish reason, model/runtime refs, and bounded confidence/calibration metadata where provided.
3. Validate structured outputs against declared schema but preserve raw output artifact for debugging where policy permits.
4. Support cancellation and report whether provider/local generation ceased; distinguish client truncation, model stop, timeout, safety/provider denial, and driver failure.
5. Publish large logits/embeddings/tensors/media as artifacts rather than trace payloads.

**Responsibility boundaries: this task must not drift into**

- Do not treat model-generated JSON as trusted because it parses.
- Do not claim provider cancellation guarantees not observed.
- Do not expose hidden chain-of-thought as a required kernel artifact.

**Required integration**

- Route Runtime consumes model results as proposals/facts of computation; Gateway streams; Evidence stores receipts.

**Validation and definition of done**

- G53–G54 cover text, embedding, value, tensor, structured, streaming, cancellation, and malformed output.

**Required contracts / collaborating tasks:** `MODEL-001`, `DGW-005`, `FND-009`

**Gold evidence:** `G53`, `G54`

### Task 4 — MODEL-004: Implement local PyTorch/Transformers and remote-provider reference drivers

**Anti-drift implementation goal**

Prove framework/provider neutrality with production-shaped but bounded adapters.

**Required implementation**

1. Implement a local PyTorch driver that loads a user-provided factory/exported bundle and invokes named operations without requiring Transformers.
2. Implement a Hugging Face Transformers reference driver as user-space adapter supporting GPT-2-class causal LM and common processor bundles.
3. Implement a provider-neutral remote HTTP model driver with endpoint-specific plugins, secret leases, rate limits, request/response schema conversion, and usage receipts.
4. Implement a deterministic tiny-model driver for conformance and CI without network/model downloads.
5. Keep framework imports and provider schemas entirely out of core crates.

**Responsibility boundaries: this task must not drift into**

- Do not call remote provider models reproducible when provider revision is opaque.
- Do not make Transformers a dependency of the kernel.
- Do not allow provider API key scope to exceed exact driver endpoint/operation.

**Required integration**

- Sandbox/Node hosts local runtimes; Secret Broker handles remote credentials; Artifact Registry pins local code/weights.

**Validation and definition of done**

- G53 reproduces tiny/GPT-2 inference locally and runs a recorded remote-provider fixture with honest determinism.
- Custom module G54 needs no Transformers import.

**Required contracts / collaborating tasks:** `MODEL-001`, `MODEL-003`, `SBX-004`, `SECR-002`

**Gold evidence:** `G53`, `G54`

### Task 5 — MODEL-005: Implement batching, admission, quotas, and latency control

**Anti-drift implementation goal**

Share model compute efficiently while respecting per-request deadlines, isolation, budgets, and live SLOs.

**Required implementation**

1. Declare compatible batching keys including model revision, operation, dtype, adapter composition, input shape/context class, output constraints, tenant/isolation, and determinism policy.
2. Implement dynamic/static batching with max wait, batch size/token/memory limits, per-request cancellation, and result demultiplexing.
3. Account input/output units, accelerator time, memory, provider cost, cache usage, and rejected/queued requests to tenant/workload quotas.
4. Reserve capacity for latency-critical routes and expose queue/admission decisions; optionally spill to compatible instances/providers through prevalidated route policy.
5. Prevent one oversized/slow request from starving unrelated tenants or physical safety inference.

**Responsibility boundaries: this task must not drift into**

- Do not batch requests across protected isolation boundaries by default.
- Do not let batching change sampling seed semantics silently.
- Do not hide latency caused by queueing behind model execution time.

**Required integration**

- Fleet/Node reserve instances; Route Runtime expresses fallback; Observability monitors SLO; Authority enforces quotas.

**Validation and definition of done**

- G53 and G68 load mixed tenants/requests and assert isolation, accounting, deadlines, and protected latency.

**Required contracts / collaborating tasks:** `MODEL-002`, `AUTH-004`, `NODE-006`, `OBS-004`

**Gold evidence:** `G53`, `G68`

### Task 6 — MODEL-006: Implement explicit model routing inputs and outcome evidence

**Anti-drift implementation goal**

Give Route Runtime reliable facts for choosing models without embedding routing policy in the driver.

**Required implementation**

1. Expose static capabilities, schemas, context/resource/cost limits, locality, current health/load, and deployment maturity as routing facts.
2. Return actual usage, latency, provider/model revision evidence, finish reason, and output quality signals declared by the model—not an aggregate routing score.
3. Support dry-run token/resource estimation as an operation with bounded trust and error measurement.
4. Record fallback/provider changes explicitly and never substitute a model revision outside the frozen allowed set.
5. Allow application evaluators to attach post-hoc quality evidence separately.

**Responsibility boundaries: this task must not drift into**

- Do not let the model driver choose the “best” model for an agent objective.
- Do not treat self-reported confidence as calibrated value.
- Do not silently route protected data to a remote model.

**Required integration**

- Route Runtime owns choice; Data-Use controls provider/locality; Eval supplies empirical evidence.

**Validation and definition of done**

- G24 and G28 route by explicit rules/learned selectors and verify exact selected revision and no hidden fallback.

**Required contracts / collaborating tasks:** `MODEL-001`, `ROUTE-001`, `DUC-002`

**Gold evidence:** `G24`, `G28`

### Task 7 — MODEL-007: Implement adapter, ensemble, and composed-model declarations

**Anti-drift implementation goal**

Support LoRA/PEFT, heads, critics, encoders, ensembles, and modular agents without losing artifact identity or compatibility.

**Required implementation**

1. Define ordered composition refs for base model, parameter-efficient adapters, heads, processors, calibration artifacts, safety/value modules, and merge strategy.
2. Validate architecture/key/shape/runtime/licence compatibility and compute a composition digest used for loading/invocation/eval.
3. Support pre-merged immutable model artifacts and runtime composition as distinct evidenced modes.
4. Represent ensembles/cascades as Route graphs unless the model driver owns one atomic mathematical operation.
5. Record every component in lineage and prohibit mutable hot injection into loaded production instance.

**Responsibility boundaries: this task must not drift into**

- Do not call an adapter-only change the same model revision.
- Do not hide routing/agent architecture inside an opaque model driver unnecessarily.
- Do not combine components with incompatible data-use/licence obligations.

**Required integration**

- Training publishes adapter candidates; Artifact/Lineage track composition; Deployment activates exact bundle.

**Validation and definition of done**

- G55 trains/evaluates/deploys an adapter composition and detects base/adapter mismatch.

**Required contracts / collaborating tasks:** `MODEL-001`, `LIN-002`, `TRAIN-014`

**Gold evidence:** `G55`

### Task 8 — MODEL-008: Enforce inference isolation, data controls, and no-training boundary

**Anti-drift implementation goal**

Prevent model runtimes from becoming ambient data collectors or unauthorized online trainers.

**Required implementation**

1. Mount inputs/model artifacts read-only and permit only declared session/output writes.
2. Require explicit collection policy before prompts/inputs/outputs/activations enter datasets; normal invocation evidence stores bounded hashes/summaries.
3. Disable gradients/optimizer/update paths in inference profiles where framework supports it and detect model artifact mutation on unload.
4. Separate protected eval, training, and live inference instances/caches according to policy.
5. Scope provider retention/training opt-out requirements through data-use/provider contracts and record unverifiable external guarantees honestly.

**Responsibility boundaries: this task must not drift into**

- Do not assume remote providers do not retain data without a verified contract.
- Do not let inference code overwrite model weights and publish them as a candidate.
- Do not route protected eval inputs through a cache visible to training.

**Required integration**

- Collection Controller explicitly captures eligible records; Data-Use governs provider use; Node/Gateway enforce mounts/handles.

**Validation and definition of done**

- G34, G40, G43, and G84 test training/eval/cache separation and attempted model mutation/exfiltration.

**Required contracts / collaborating tasks:** `MODEL-002`, `DUC-001`, `COLL-001`, `NODE-004`

**Gold evidence:** `G34`, `G40`, `G43`, `G84`

### Task 9 — MODEL-009: Implement determinism, caching, and reproducibility profiles

**Anti-drift implementation goal**

Reuse safe computations and compare behavior without overstating numerical/provider reproducibility.

**Required implementation**

1. Declare determinism class and capture model/composition/runtime/hardware, operation, inputs, parameters, seeds/random streams, and relevant numerical flags.
2. Define cache eligibility only for pure operations with data-classification-safe scope and exact cache key; generative stochastic calls require explicit seed/profile.
3. Keep provider-side opaque caching as external behavior and record limited reproducibility.
4. Support recorded-result substitution for replay and bounded numerical/statistical comparison profiles.
5. Invalidate caches on revocation, policy change, or artifact deletion and never make cache hit grant payload access.

**Responsibility boundaries: this task must not drift into**

- Do not claim bitwise equality across unsupported devices/kernels.
- Do not cache one tenant’s protected prompt/result for another.
- Do not use a cache result under a model alias that now points elsewhere.

**Required integration**

- Replay/Evidence uses reproducibility graph; Artifact cache stores results; Data-Use controls access.

**Validation and definition of done**

- G39, G42, G52, and G53 verify exact/bounded/statistical classes and cache isolation.

**Required contracts / collaborating tasks:** `MODEL-003`, `FND-008`, `RPLY-003`

**Gold evidence:** `G39`, `G42`, `G52`, `G53`

### Task 10 — MODEL-010: Implement model-driver conformance and conversion examples

**Anti-drift implementation goal**

Prove custom and standard models can interoperate without conflating inference support with training/eval support.

**Required implementation**

1. Generate lifecycle tests for manifest/load/invoke/stream/cancel/session/isolation/resource/error/result schema/replay and artifact mutation.
2. Provide conversion/import tools that create a model bundle from a PyTorch state dict/module factory, Transformers directory, ONNX-like runtime artifact, or remote provider descriptor as separate adapters.
3. Validate numerical reference cases, shape/schema errors, OOM, corrupt weights, processor mismatch, session leakage, and provider timeout.
4. Publish a capability report identifying which operations and determinism claims are actually supported.
5. Keep training compatibility assessment in Trainer/Training components.

**Responsibility boundaries: this task must not drift into**

- Do not infer trainability from successful inference import.
- Do not report a model converted when unsupported custom operators were skipped.
- Do not allow mandatory isolation tests to be waived for production.

**Required integration**

- Gold GPT-2 and custom-net examples use the same bundle/driver protocol.

**Validation and definition of done**

- G07, G53, and G54 pass for tiny Transformer, GPT-2-class, CNN/custom tensor model, and recorded remote provider.

**Required contracts / collaborating tasks:** `MODEL-001`, `MODEL-004`, `FND-005`

**Gold evidence:** `G07`, `G53`, `G54`

### Component completion gate

- Models are immutable addressed artifacts invoked through typed operations; loaded instances and sessions are explicit runtime state.
- Inference never mutates or activates model weights, and model output remains a proposal/computation result.
- The contract is modality, framework, provider, and architecture agnostic.

---

## Component 19 — Trainer Driver Contract and Framework Adapters

**Canonical component ID:** `splendor.trainer-driver`
**Plane:** `driver_boundary`
**Current status:** missing
**Owning package:** `contract in crates/splendor-types and splendor-gateway; framework adapters in `adapters/trainers/*`; Python integration package `splendor-train``

**Implemented baseline to preserve**

There is no trainer driver in the current repository. Training is explicitly a prior MVP non-goal, and Python has no dependencies. Missing are a framework-neutral worker protocol, project compatibility contract, PyTorch launch adapter, distributed parallelism plugins, progress/checkpoint/data-cursor callbacks, failure semantics, and candidate-output publication.

**Exact kernel responsibility**

Run a user-supplied training algorithm inside an admitted worker/group and expose lifecycle, progress, checkpoint, and candidate outputs to Splendor. It does not choose data, objectives, hyperparameters, topology, gates, or activation; those are controller/application responsibilities.

**Public contracts:** `TrainerManifest`, `TrainingProjectContract`, `TrainerLaunch`, `WorkerContext`, `ParallelPlan`, `TrainingProgress`, `CheckpointProtocol`, `TrainerResult`, `CompatibilityReport`

### Task 1 — TRDRV-001: Define the framework-neutral trainer worker protocol

**Anti-drift implementation goal**

Give any training framework a stable contract for launch, progress, checkpoint, cancellation, and result without moving the algorithm into kernel code.

**Required implementation**

1. Define trainer operations inspect-project, validate-plan, prepare, launch-worker, checkpoint, restore, quiesce/cancel, finalize, and collect-result.
2. Pass a `WorkerContext` containing workload/task/attempt, role/logical slot/rank for current group epoch, topology, resources, input/output handles, seed bundle, data shard/cursor, checkpoint source, progress endpoint, and fencing token.
3. Define structured progress and checkpoint callbacks independent of training metrics names.
4. Require terminal result to enumerate produced model/checkpoint/optimizer/config/report artifacts and exact logical progress.
5. Support single-process and distributed groups through the same contract.

**Responsibility boundaries: this task must not drift into**

- Do not require a specific loss, optimizer, loop, model class, or dataset API.
- Do not let trainer workers call deployment or gate APIs.
- Do not parse stdout as the only checkpoint/progress channel.

**Required integration**

- Training Controller creates plan; Workload/Fleet/Node realize group; Gateway mediates trainer operations.

**Validation and definition of done**

- G52 and G54 run single-process custom loops and pass all lifecycle/failure cases.

**Required contracts / collaborating tasks:** `DRREG-001`, `WORK-001`, `DGW-001`

**Gold evidence:** `G52`, `G54`

### Task 2 — TRDRV-002: Define honest project compatibility tiers for arbitrary training projects

**Anti-drift implementation goal**

Support arbitrary PyTorch projects without promising impossible automatic distributed conversion.

**Required implementation**

1. Implement tier T0 `opaque`: run the original entrypoint unchanged as one worker; only independent trials/eval/data fan-out are automatic.
2. Implement tier T1 `torchrun-compatible`: project already honors distributed environment and checkpoint semantics; Splendor forms groups and launches it without rewriting algorithm code.
3. Implement tier T2 `structured project`: project provides model/optimizer/data/step/checkpoint factories or hooks, allowing Splendor adapters to apply supported DDP/FSDP/data-sharding wrappers.
4. Implement tier T3 `explicit parallel plan`: project supplies validated tensor/pipeline/expert/custom parallel plugin and topology requirements.
5. Generate a `CompatibilityReport` listing detected framework/version, entrypoints, side effects, state/checkpoint patterns, distributed initialization, data-loader behavior, unsupported dynamic code/custom extensions, and exact guarantees available.
6. Require explicit opt-in/manifest selection; never silently transform source code.

**Responsibility boundaries: this task must not drift into**

- Do not claim T0 has become distributed because multiple copies run.
- Do not automatically wrap arbitrary dynamic models/optimizers/data pipelines when semantics cannot be proven.
- Do not fail all unusual projects; preserve single-node/observed execution with honest limits.

**Required integration**

- Training Controller uses report to choose/reject a plan; Sandbox Executor builds/runs project; Artifact/Lineage pin source/env.

**Validation and definition of done**

- G60–G64 include T0, T1, T2, and T3 fixtures and verify advertised guarantees.
- A deliberately unsafe/global-state project remains T0 with actionable reasons.

**Required contracts / collaborating tasks:** `TRDRV-001`, `SBX-004`, `LIN-004`

**Gold evidence:** `G60`, `G61`, `G62`, `G63`, `G64`

### Task 3 — TRDRV-003: Implement the PyTorch torchrun/elastic launch adapter

**Anti-drift implementation goal**

Launch existing distributed-aware PyTorch projects across Splendor worker groups while respecting PyTorch restart semantics.

**Required implementation**

1. Generate `torchrun`/elastic rendezvous parameters, node rank/local rank/world size for one group epoch, master/rendezvous endpoint, restart budget, and error recording from the frozen WorkerGroupPlan.
2. Treat rank/world-size as epoch-local; logical worker identity remains Splendor attempt/slot and is passed separately.
3. Validate homogeneous local worker count and runtime/backend compatibility where required by the selected PyTorch mode.
4. On membership/failure, fence all old workers, create a new group epoch, restore from a compatible checkpoint, and regenerate rank/data assignment.
5. Capture per-rank errors, first/root-cause evidence, process group initialization/teardown, and collective timeout diagnostics.

**Responsibility boundaries: this task must not drift into**

- Do not hard-code stable rank assumptions.
- Do not leave surviving ranks blocked after one worker fails.
- Do not use elastic min/max for projects whose batch/data/checkpoint semantics are fixed.

**Required integration**

- Fleet Scheduler owns group epochs; Node Agent launches local workers; Training Controller chooses elasticity.

**Validation and definition of done**

- G64 repeatedly changes membership and validates checkpoint/restart, no stale commits, and declared sample semantics.
- Collective initialization mismatch fails before training steps where possible.

**Required contracts / collaborating tasks:** `TRDRV-002`, `FLEET-006`, `NODE-005`

**Gold evidence:** `G64`

### Task 4 — TRDRV-004: Implement DDP, FSDP, tensor, pipeline, and custom parallel adapters

**Anti-drift implementation goal**

Expose a bounded set of real parallelization mechanisms through plugins instead of one magical “distributed=true” flag.

**Required implementation**

1. For T2 projects, implement DDP wrapping with explicit device placement, sampler/data semantics, gradient accumulation, unused-parameter/static-graph options, and global batch declaration.
2. Implement modern fully-sharded adapter through version-pinned PyTorch APIs with sharding plan, optimizer state, mixed precision, CPU/offload policy, and distributed checkpoint integration.
3. Implement DeviceMesh/tensor-parallel and pipeline-parallel adapters only with identical canonical mesh/partition plan on all ranks and project-provided partitionable structure.
4. Define a custom parallel plugin interface for expert/dataflow/domain-specific systems with explicit group/topology/checkpoint/equivalence contract.
5. Validate combinations (for example data + tensor + pipeline) as named supported profiles; reject unknown compositions.

**Responsibility boundaries: this task must not drift into**

- Do not apply tensor or pipeline parallelism by guessing model layer boundaries.
- Do not combine parallel methods whose optimizer/checkpoint semantics are unvalidated.
- Do not expose unstable framework details as permanent kernel primitives; keep them in versioned adapter plugins.

**Required integration**

- Training Controller selects a `ParallelPlan`; Fleet Scheduler realizes topology; Checkpoint protocol stores topology-independent metadata where possible.

**Validation and definition of done**

- G61–G64 cover DDP and sharded modes plus one explicit 2D mesh fixture; inconsistent mesh is rejected rather than hanging.

**Required contracts / collaborating tasks:** `TRDRV-002`, `TRDRV-003`, `FLEET-004`

**Gold evidence:** `G61`, `G62`, `G63`, `G64`

### Task 5 — TRDRV-005: Implement structured progress, metric, and safe-point callbacks

**Anti-drift implementation goal**

Observe training and coordinate control without dictating the user loop.

**Required implementation**

1. Provide a lightweight Python API/context for step/epoch/token/sample progress, named metrics, optimizer-step boundaries, safe checkpoint points, evaluation request, and graceful stop checks.
2. Batch/rate-limit metric events and publish detailed histories as artifacts/telemetry rather than controller state.
3. Allow opaque/T1 projects to emit the protocol explicitly or fall back to coarse process/checkpoint evidence with reduced guarantees.
4. Bind metric schema/source/rank/aggregation status and prevent worker-reported metrics from directly satisfying gates.
5. Expose checkpoint/preemption/cancel requests cooperatively and define hard-kill fallback.

**Responsibility boundaries: this task must not drift into**

- Do not monkey-patch arbitrary training loops invisibly.
- Do not let a worker declare its own metric globally aggregated.
- Do not block every step on control-plane availability.

**Required integration**

- Node Agent hosts local control channel; Training Controller aggregates/decides; Observability stores high-volume metrics.

**Validation and definition of done**

- G52, G63, and G68 validate progress under backpressure, control-plane reconnect, and preemption.

**Required contracts / collaborating tasks:** `TRDRV-001`, `DGW-005`, `OBS-004`

**Gold evidence:** `G52`, `G63`, `G68`

### Task 6 — TRDRV-006: Implement data-shard and cursor integration without owning dataset logic

**Anti-drift implementation goal**

Give workers deterministic, purpose-scoped sample streams compatible with restart and elastic group changes.

**Required implementation**

1. Accept dataset/split refs plus a DataAssignment containing shard/partition, sampling policy digest, epoch/generation, global batch semantics, and cursor/checkpoint refs.
2. Provide adapters for map-style and iterable/streaming datasets while requiring application hooks when exact cursor restoration is impossible.
3. Record consumed record/shard ranges or privacy-preserving fingerprints according to policy and reconcile with data-use leases.
4. On group resize, obtain a new assignment from Training Controller rather than deriving it from unstable rank alone.
5. Support replay buffers/online data streams as explicit source contracts with snapshot/watermark semantics.

**Responsibility boundaries: this task must not drift into**

- Do not assume `DistributedSampler` solves arbitrary iterable/streaming data exactly.
- Do not let ranks independently select protected eval data.
- Do not hide duplicate/skip semantics after failure.

**Required integration**

- Data/Training controllers own snapshots/assignments; Node mounts; Lineage records trained-on edges.

**Validation and definition of done**

- G52, G56, G58, and G64 verify map, stream, replay-buffer, restart, and resize semantics with declared duplication bounds.

**Required contracts / collaborating tasks:** `TRDRV-001`, `DODRV-007`, `TRAIN-008`, `DUC-003`

**Gold evidence:** `G52`, `G56`, `G58`, `G64`

### Task 7 — TRDRV-007: Implement distributed checkpoint and restore protocol

**Anti-drift implementation goal**

Preserve model, optimizer, scheduler, scaler, RNG, data cursor, and algorithm state across failure/topology changes where the project supports it.

**Required implementation**

1. Define checkpoint component manifests, group epoch/topology, logical progress, framework/adapter versions, determinism class, completeness, and compatibility constraints.
2. Support single-file and sharded checkpoints; for PyTorch structured modes integrate distributed checkpoint save/load and load-time resharding through adapter code.
3. Coordinate rank-local staging, global manifest commit, asynchronous upload, and only then advertise a durable checkpoint.
4. Restore into same or different supported topology after validating state allocation, optimizer/model compatibility, data cursor/global batch policy, and project migration hook.
5. Retain the last N known-good checkpoints and quarantine corrupt/incomplete/newer stale-attempt outputs.

**Responsibility boundaries: this task must not drift into**

- Do not treat a set of rank files as complete without a committed root manifest.
- Do not assume checkpoint state_dict compatibility across arbitrary framework versions.
- Do not resume with reset optimizer/data cursor silently.

**Required integration**

- Node Agent uploads; Artifact Registry commits; Training Controller selects and validates resume; Lineage binds inputs.

**Validation and definition of done**

- G52, G63, G64, and G69 kill ranks during save/load, reshard topology, and validate numerical/behavioral continuity.

**Required contracts / collaborating tasks:** `TRDRV-004`, `NODE-008`, `ART-002`, `FND-008`

**Gold evidence:** `G52`, `G63`, `G64`, `G69`

### Task 8 — TRDRV-008: Implement candidate-bundle finalization and publication

**Anti-drift implementation goal**

Turn training outputs into immutable candidates without granting them deployment or policy authority.

**Required implementation**

1. Define trainer result outputs for model/adapters, processor, training config, final/selected checkpoint, optimizer optional retention, metric artifacts, environment, and compatibility metadata.
2. Verify output digests, required components, producer receipt, exact dataset/code/environment/parallel plan, and current fencing before publication.
3. Run conversion/export hooks as separate evidenced workloads where needed; never mutate the raw checkpoint in place.
4. Publish a `CandidateBundle` in candidate-only state and hand it to Eval/Improvement controllers.
5. Reject or quarantine outputs whose worker declarations disagree with actual mounts/plan or whose checkpoint is incomplete.

**Responsibility boundaries: this task must not drift into**

- Do not update deployment/model aliases from trainer code.
- Do not call training metrics evaluation evidence.
- Do not let a stale rank or compromised worker select the accepted candidate.

**Required integration**

- Artifact/Lineage own bundle; Training Controller owns run result; Eval Controller evaluates; Deployment remains separate.

**Validation and definition of done**

- G50–G59 verify candidate-only publication and complete lineage; G83 rejects forged/stale candidate.

**Required contracts / collaborating tasks:** `TRDRV-007`, `LIN-002`, `MODEL-001`

**Gold evidence:** `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G83`

### Task 9 — TRDRV-009: Provide non-PyTorch and custom trainer adapter path

**Anti-drift implementation goal**

Keep Splendor’s kernel contract framework-neutral while PyTorch remains the first deep integration.

**Required implementation**

1. Implement an executable/OCI trainer adapter using the generic worker/progress/checkpoint/result protocol for JAX, TensorFlow, native code, simulators, solvers, or custom systems.
2. Define framework plugin interfaces for project inspection, worker launch, parallel plan validation, checkpoint compatibility, and candidate packaging.
3. Keep collective/runtime-specific semantics entirely in plugin manifests and compatibility reports.
4. Support observed external trainers with reduced guarantees through Workload observed mode.
5. Add one non-PyTorch minimal numerical training fixture proving no PyTorch types enter core schemas.

**Responsibility boundaries: this task must not drift into**

- Do not generalize PyTorch-specific rank/state_dict concepts into foundational objects.
- Do not claim automatic distribution for a framework without a conformant plugin.
- Do not require deep integration to run an opaque training executable.

**Required integration**

- Training Controller calls framework-neutral contract; Sandbox/Fleet execute.

**Validation and definition of done**

- G06 and G54 run an opaque custom trainer and compare guarantees with structured PyTorch.

**Required contracts / collaborating tasks:** `TRDRV-001`, `WORK-008`, `SBX-005`

**Gold evidence:** `G06`, `G54`

### Task 10 — TRDRV-010: Build trainer conformance and distributed failure matrix

**Anti-drift implementation goal**

Prove lifecycle and recovery claims at one, many, elastic, and heterogeneous fleet scales.

**Required implementation**

1. Generate tests for project tiers, worker context, rank/group epochs, progress, data assignments, checkpoint completeness, cancellation, preemption, OOM, collective timeout, node loss, stale output, and candidate publication.
2. Run 1-process, multi-process one-node, multi-node fixed, elastic restart, topology-reshard, and independent heterogeneous role cases.
3. Use numerical/behavioral tolerances appropriate to determinism class and compare against single-process reference where semantics permit.
4. Measure lost work, restart time, checkpoint overhead, throughput scaling, live-inference interference, and duplicate/skip sample bounds.
5. Publish per-version/per-parallel-profile conformance evidence.

**Responsibility boundaries: this task must not drift into**

- Do not call a driver distributed-conformant after only launching two processes.
- Do not hide failed/unsupported topology combinations.
- Do not use speedup alone as correctness evidence.

**Required integration**

- Driver Registry maturity, Training Controller plan selection, and gold distributed program consume reports.

**Validation and definition of done**

- G52 and G60–G69 form the mandatory matrix; injected broken trainer is rejected.

**Required contracts / collaborating tasks:** `TRDRV-001`, `TRDRV-008`, `FND-005`

**Gold evidence:** `G52`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`

### Component completion gate

- Trainer drivers execute user algorithms and report control/evidence; they never choose or activate improvements.
- Arbitrary projects receive an honest T0–T3 compatibility tier, not source rewriting or false distribution claims.
- Distributed lifecycle, data, checkpoint, elasticity, and stale-worker semantics are explicit and tested.

---

## Component 20 — Evaluator Driver Contract and Reference Drivers

**Canonical component ID:** `splendor.evaluator-driver`
**Plane:** `driver_boundary`
**Current status:** missing
**Owning package:** `contract in crates/splendor-types and splendor-gateway; implementations in `adapters/evaluators/*``

**Implemented baseline to preserve**

The loop has a minimal `OutcomeEvaluator` returning optional `Feedback` and `Reward`, but there is no evaluator driver contract for dataset cases, interactive episodes, simulations, human review, model judges, red teams, protected suites, distributed shards, metric artifacts, or statistically valid aggregation.

**Exact kernel responsibility**

Execute one evaluation method/case/episode or aggregation operation against pinned inputs and candidate/baseline outputs, then return measured evidence. It does not choose promotion thresholds, derive authoritative reward automatically, expose protected cases, or activate changes.

**Public contracts:** `EvaluatorManifest`, `EvalCaseInput`, `EvalObservation`, `MetricSample`, `SliceKey`, `EvalShardResult`, `AggregationResult`, `HumanReviewRequest`

### Task 1 — EVDRV-001: Define evaluator operation and result schemas

**Anti-drift implementation goal**

Support deterministic tests, learned judges, human review, simulators, physical trials, and custom metrics without one generic score blob.

**Required implementation**

1. Define operations prepare-case, run-case/episode, score-output/trajectory, aggregate-shard, compare-baseline, and request-human-review.
2. Bind exact evaluator implementation/model/rubric, case/suite ref, candidate/baseline refs, environment/world snapshot, seed, sampling, timeout, and protected-data handle.
3. Return per-case observations, metric samples with units/direction/range, categorical findings, failure reason, slice attributes, artifacts, and evaluator confidence/limitations.
4. Distinguish task failure, model failure, evaluator failure, invalid case, abstention, and safety abort.
5. Keep gate pass/fail outside evaluator results.

**Responsibility boundaries: this task must not drift into**

- Do not reduce all evaluation to one scalar.
- Do not let result payload carry its own gate decision or reward authority.
- Do not hide evaluator failures as candidate score zero unless suite semantics explicitly require it.

**Required integration**

- Eval Controller defines suites/plans; Workload runs shards; Evidence stores results.

**Validation and definition of done**

- G39–G49 cover deterministic, stochastic, human, learned, interactive, and failure cases.

**Required contracts / collaborating tasks:** `DRREG-001`, `EVID-001`

**Gold evidence:** `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`

### Task 2 — EVDRV-002: Implement modality- and domain-agnostic metric plugin interfaces

**Anti-drift implementation goal**

Let application code define meaningful metrics while retaining typed provenance, aggregation, and validation.

**Required implementation**

1. Provide SDKs for scalar/vector/distribution/confusion-matrix/ranking/trajectory/constraint-violation/resource/latency/physical-safety metric outputs.
2. Require schema, units, direction, valid range, missingness, aggregation rule, weighting, and version for each metric definition.
3. Allow opaque domain artifacts such as proofs, videos, code test reports, simulator traces, or scientific outputs linked from metric samples.
4. Separate deterministic programmatic checkers, statistical estimators, and learned/human judgments in metadata.
5. Validate metric values and aggregation compatibility before accepting results.

**Responsibility boundaries: this task must not drift into**

- Do not bake NLP benchmark assumptions into core.
- Do not average metrics with incompatible units or undefined missingness.
- Do not interpret self-reported model confidence as an eval metric without an evaluator.

**Required integration**

- Eval Controller owns suite composition and statistical interpretation; Reward Derivation may consume accepted metrics explicitly.

**Validation and definition of done**

- G39, G42, G44, G47, and G57 validate code, language, probabilistic, safety, and world-model metrics.

**Required contracts / collaborating tasks:** `EVDRV-001`, `FND-001`

**Gold evidence:** `G39`, `G42`, `G44`, `G47`, `G57`

### Task 3 — EVDRV-003: Implement protected-case execution and blind result protocol

**Anti-drift implementation goal**

Evaluate candidates on hidden cases without allowing training, candidate code, or broad operators to read the payloads.

**Required implementation**

1. Run protected evaluator/candidate interactions in isolated workloads with separate principals, data handles, caches, logs, and output channels.
2. Deliver only the minimum case input to the candidate/model path and prevent raw case/label/rubric from appearing in training-accessible artifacts or general traces.
3. Return blinded aggregate/per-slice evidence according to disclosure policy and sealed detailed reports for authorized reviewers.
4. Record access attempts, case fingerprints, candidate outputs, and evaluator provenance without leaking protected content.
5. Rotate/retire suites and invalidate affected claims on suspected exposure.

**Responsibility boundaries: this task must not drift into**

- Do not mount protected eval data into trainer workers.
- Do not reveal labels/rubrics through error messages, cache keys, filenames, or timing where policy forbids.
- Do not let a candidate invoke the evaluator/judge directly.

**Required integration**

- Data-Use/Secret/Node/Gateway enforce isolation; Eval Controller owns split; Incident handles leakage.

**Validation and definition of done**

- G40, G43, G44, G84, and G86 attempt direct/indirect leakage and reward gaming; all fail while aggregate evidence remains useful.

**Required contracts / collaborating tasks:** `EVDRV-001`, `DUC-006`, `NODE-009`, `DGW-007`

**Gold evidence:** `G40`, `G43`, `G44`, `G84`, `G86`

### Task 4 — EVDRV-004: Implement distributed case/episode sharding and deterministic aggregation

**Anti-drift implementation goal**

Scale evals across arbitrary capable devices without changing suite meaning or biasing results by completion order.

**Required implementation**

1. Accept exact case manifest and deterministic shard assignment independent of worker rank; support static shards, dynamic work queue, and long episode roles.
2. Bind each case result to one current attempt and deduplicate retries; preserve invalid/missing/aborted cases explicitly.
3. Aggregate by case ID and declared metric rule using stable numerical methods and weights; never by arrival order.
4. Support incremental checkpoints for large evals and resume only unfinished/invalidated cases.
5. Run capability-appropriate cases on heterogeneous devices only when environment/hardware is part of or controlled by the eval plan.

**Responsibility boundaries: this task must not drift into**

- Do not double-count retried cases.
- Do not compare candidate and baseline on different random cases without paired-plan declaration.
- Do not hide slow/failed cases by timing out and aggregating survivors silently.

**Required integration**

- Workload/Fleet schedule shards; Eval Controller validates completeness; Evidence assembles report.

**Validation and definition of done**

- G42, G61, and G68 compare one-device and fleet aggregation exactly/boundedly and inject retries/stragglers.

**Required contracts / collaborating tasks:** `EVDRV-001`, `WORK-003`, `FLEET-008`

**Gold evidence:** `G42`, `G61`, `G68`

### Task 5 — EVDRV-005: Implement statistical, calibration, and uncertainty evaluator helpers

**Anti-drift implementation goal**

Provide reliable measurements for stochastic models and long-horizon agents without turning statistics into hidden gate policy.

**Required implementation**

1. Implement reusable estimators for paired differences, confidence/credible intervals, bootstrap, sequential bounds, calibration curves, distribution shift, and multiple-comparison metadata.
2. Require sample/episode identity, seed, pairing/stratification, missingness, stopping rule, and estimator version.
3. Support abstention and insufficient-power results rather than forced pass/fail.
4. Record assumptions and raw sufficient statistics/artifact refs so results can be recomputed.
5. Keep threshold/risk decisions in Gate Engine.

**Responsibility boundaries: this task must not drift into**

- Do not cherry-pick seeds or stop when a desired threshold first appears.
- Do not report point estimates without uncertainty where suite requires it.
- Do not make one statistical method mandatory for all domains.

**Required integration**

- Eval Controller chooses analysis plan before execution; Gate Engine consumes resulting evidence.

**Validation and definition of done**

- G42 and G46 use pre-registered paired plans and reproduce intervals; optional-stopping attack fails.

**Required contracts / collaborating tasks:** `EVDRV-002`, `EVID-003`

**Gold evidence:** `G42`, `G46`

### Task 6 — EVDRV-006: Implement interactive, world-model, RL, and physical evaluation profiles

**Anti-drift implementation goal**

Evaluate agents and learned dynamics in environments where outcomes are trajectories rather than static outputs.

**Required implementation**

1. Define episode reset/step/observe/terminate contracts using perceptor/actuator or simulator drivers and explicit world/environment version.
2. Capture trajectory artifact, actions, constraints/verifier decisions, rewards/feedback refs, safety aborts, and environment stochasticity.
3. Support learned-world rollout calibration against observed transitions and branch-specific uncertainty.
4. For physical trials, require simulation pre-gates, local safety authority, bounded test envelope, human/operator policy, and independent telemetry.
5. Support multi-agent episode roles and hidden adversary/evaluator agents with isolated authority.

**Responsibility boundaries: this task must not drift into**

- Do not let eval mode bypass action verification.
- Do not call simulator improvement proof for real physical behavior without transfer evidence.
- Do not allow evaluator agents to grant capabilities through messages.

**Required integration**

- Replay/World/Route/Agent/Actuator components realize episodes; Eval Controller owns suite.

**Validation and definition of done**

- G47, G57–G59, G73, and G77 cover code/agent, world model, RL, simulation-to-physical, and multi-agent cases.

**Required contracts / collaborating tasks:** `EVDRV-001`, `RPLY-005`, `WORLD-007`, `ACT-006`

**Gold evidence:** `G47`, `G57`, `G58`, `G59`, `G73`, `G77`

### Task 7 — EVDRV-007: Implement learned-judge and human-review protocols with independence evidence

**Anti-drift implementation goal**

Use subjective feedback without allowing the candidate and evaluator to collapse into an unaudited self-score.

**Required implementation**

1. Define learned judge refs, prompt/rubric/version, blinded candidate labels, randomization, calibration set, adjudication, and judge output schema.
2. Define human review requests with minimized payload, reviewer qualifications/role, conflict-of-interest, randomized/blinded presentation, response schema, confidence, and appeal/adjudication.
3. Support multiple judges/reviewers and disagreement artifacts; keep identities protected where required but auditable.
4. Record shared base-model/context/training-data risk between candidate and judge as an independence attribute.
5. Require programmatic or human holdout cross-checks for gates susceptible to reward hacking.

**Responsibility boundaries: this task must not drift into**

- Do not treat an LLM judge as ground truth.
- Do not let candidate-generated explanations reveal treatment or manipulate reviewers unchecked.
- Do not expose reviewer credentials or protected cases to candidate code.

**Required integration**

- Feedback Service ingests human/judge findings; Eval Controller composes; Gate policy enforces independence.

**Validation and definition of done**

- G41, G44, G48, and G86 demonstrate disagreement, calibration, shared-model reward hacking, and appeal.

**Required contracts / collaborating tasks:** `EVDRV-001`, `FDBK-002`, `GATE-003`

**Gold evidence:** `G41`, `G44`, `G48`, `G86`

### Task 8 — EVDRV-008: Implement evaluator conformance and adversarial validation

**Anti-drift implementation goal**

Make metric correctness, isolation, determinism, and aggregation testable before evaluator evidence can gate changes.

**Required implementation**

1. Generate tests for schema/range/units, deterministic fixtures, protected access, case dedup, failure/missingness, aggregation, cancellation, seed handling, redaction, and candidate/evaluator isolation.
2. Inject mislabeled cases, leaking error messages, completion-order bias, duplicate retries, judge prompt injection, metric overflow/NaN, and forged pass fields.
3. Validate against hand-computed small suites and independent implementation where feasible.
4. Publish conformance evidence per metric/eval profile and list known validity limits separately from interface conformance.
5. Quarantine evaluator versions whose results change without versioned inputs/implementation.

**Responsibility boundaries: this task must not drift into**

- Do not certify scientific validity solely from software conformance.
- Do not ignore NaN/missing/failed cases.
- Do not let evaluator code write directly to gate decisions.

**Required integration**

- Driver Registry and Eval Controller require maturity; Gate Engine validates trusted evaluator policy.

**Validation and definition of done**

- G07 and G39–G49 reject intentionally faulty evaluators and preserve failure evidence.

**Required contracts / collaborating tasks:** `EVDRV-001`, `FND-005`

**Gold evidence:** `G07`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`

### Component completion gate

- Evaluators produce typed measurements and findings, never promotion authority or hidden reward.
- Protected cases, retries, aggregation, uncertainty, and independence are explicit.
- Static, interactive, physical, human, and learned evaluation share lifecycle but retain domain-specific user-space logic.

---

## Component 21 — Data Operator Driver Contract and Reference Drivers

**Canonical component ID:** `splendor.data-operator-driver`
**Plane:** `driver_boundary`
**Current status:** missing
**Owning package:** `contract in crates/splendor-types and splendor-gateway; implementations in `adapters/data/*``

**Implemented baseline to preserve**

The current kernel can persist percepts/traces/state and work orders carry data refs, but it lacks drivers for source extraction, validation, transformation, deduplication, labeling, contamination analysis, splitting, synthesis, indexing, and distributed data processing with record-level lineage and purpose controls.

**Exact kernel responsibility**

Execute one declared data operation over governed input snapshots/streams and publish immutable output shards/reports with record- or shard-level lineage. It does not decide collection purpose, quality acceptance, train/eval use, reward, or model promotion.

**Public contracts:** `DataOperatorManifest`, `DataOperation`, `RecordEnvelope`, `RecordBatch`, `TransformSpec`, `QualityFinding`, `ContaminationFinding`, `PartitionAssignment`, `DataOperatorResult`

### Task 1 — DODRV-001: Define the data operation and record/batch contract

**Anti-drift implementation goal**

Support arbitrary modalities and schemas while standardizing lifecycle, identity, lineage, and quality outputs.

**Required implementation**

1. Define operations extract, normalize, validate, filter, transform, join, deduplicate, label, redact, sample, split, shard, synthesize, index, summarize, compare, and contamination-scan.
2. Represent records with stable source/record identity or explicit anonymous fingerprint, schema, payload ref/inline bound, provenance, classification, event time, and obligations.
3. Represent batches/shards as manifests with ordering semantics, record count/bytes, schema, partition key/range, digest, and completeness.
4. Require transform/config/code/environment refs, input/output schemas, determinism/idempotency, and quality/report outputs.
5. Allow domain-specific opaque payloads; no text-token assumption in core.

**Responsibility boundaries: this task must not drift into**

- Do not require every source to have a natural stable record ID; make limitations explicit.
- Do not put raw records in control events.
- Do not treat a transform output as approved training data automatically.

**Required integration**

- Artifact/Lineage store records/shards; Data-Use scopes inputs/outputs; Collection/Data controllers select operations.

**Validation and definition of done**

- G30 and G31 process text, image metadata, telemetry, structured tables, and custom records through the same envelope.

**Required contracts / collaborating tasks:** `DRREG-001`, `ART-001`, `LIN-001`

**Gold evidence:** `G30`, `G31`

### Task 2 — DODRV-002: Implement source connectors, cursors, and snapshot extraction

**Anti-drift implementation goal**

Create reproducible datasets from files, object stores, databases, APIs, event streams, percept/event logs, feedback, and device buffers.

**Required implementation**

1. Define connector operations inspect-schema, enumerate/snapshot, read-shard, stream-from-cursor, acknowledge, and close.
2. Capture source version/snapshot/transaction/watermark/cursor and extraction query/config as immutable refs.
3. Support incremental extraction with high-water marks and backfill windows while recording inserts/updates/deletes distinctly.
4. Use secret/data handles and locality constraints; emit source access/row/byte receipts.
5. Declare consistency and replay guarantees honestly for sources lacking snapshots or stable cursors.

**Responsibility boundaries: this task must not drift into**

- Do not call a mutable URL or database query a reproducible dataset without source version evidence.
- Do not advance cursor before durable output/decision.
- Do not embed source credentials in dataset manifests.

**Required integration**

- Collection Controller owns plans/cursors; Node Agent mounts/localizes; Data-Use grants access.

**Validation and definition of done**

- G30 and G38 test snapshot, stream, incremental backfill, deletion, and source reset.

**Required contracts / collaborating tasks:** `DODRV-001`, `PERC-002`, `DUC-003`

**Gold evidence:** `G30`, `G38`

### Task 3 — DODRV-003: Implement schema, integrity, validity, and distribution quality operators

**Anti-drift implementation goal**

Make data quality measurable and sliceable before training or evaluation.

**Required implementation**

1. Provide operators for schema/type/range/unit, required fields, corrupt media, encoding/decoding, referential consistency, temporal ordering, sensor validity, and custom predicates.
2. Produce per-record findings where permitted plus aggregate counts/rates, severity, affected slices, examples as protected refs, and operator version.
3. Add distribution summaries, missingness, class/domain/source coverage, drift, long-tail/rare-group representation, and duplicate cluster statistics.
4. Support quarantine/filter/repair proposals as separate outputs; never mutate source snapshots in place.
5. Allow application-defined validators through sandboxed operators and conformance fixtures.

**Responsibility boundaries: this task must not drift into**

- Do not define one global quality score.
- Do not delete rare or anomalous records merely because they are outliers.
- Do not let a validator repair data without preserving original and lineage.

**Required integration**

- Data controller composes quality policy; Eval/Training gate dataset use; Evidence stores reports.

**Validation and definition of done**

- G31 and G32 inject corrupt, missing, biased, drifted, and rare-tail data and verify findings/quarantine.

**Required contracts / collaborating tasks:** `DODRV-001`, `EVID-001`

**Gold evidence:** `G31`, `G32`

### Task 4 — DODRV-004: Implement deduplication, similarity, and leakage-safe grouping operators

**Anti-drift implementation goal**

Prevent exact/near duplicate leakage across splits and repeated self-generated data while preserving auditable decisions.

**Required implementation**

1. Implement exact digest/normalized digest plus pluggable modality-specific similarity fingerprints/embeddings.
2. Produce duplicate/similarity clusters with method/version/threshold and representative policy; keep uncertain matches explicit.
3. Support group-aware split constraints so related records, conversations, users, trajectories, code repositories, or generated variants remain together.
4. Track source/model/generation ancestry for synthetic/augmented examples and detect recursive reuse depth.
5. Publish removal/weighting proposals with reversible manifests and retained cluster evidence.

**Responsibility boundaries: this task must not drift into**

- Do not rely only on exact string hashes for semantic contamination.
- Do not drop records without a versioned policy/output snapshot.
- Do not expose protected eval content through similarity reports.

**Required integration**

- Dataset/Eval controllers provide protected fingerprints or sealed scans; Lineage supplies ancestry.

**Validation and definition of done**

- G32, G33, G36, and G43 cover exact/near duplicates, group leakage, synthetic recursion, and protected matching.

**Required contracts / collaborating tasks:** `DODRV-001`, `LIN-003`, `DUC-006`

**Gold evidence:** `G32`, `G33`, `G36`, `G43`

### Task 5 — DODRV-005: Implement contamination, memorization-risk, and overlap scanning

**Anti-drift implementation goal**

Detect train/eval and generation-source overlap using multiple methods without claiming perfect decontamination.

**Required implementation**

1. Define contamination scans comparing candidate training/feedback/synthetic snapshots against protected eval fingerprint services, public benchmarks, prior generation outputs, deployment logs, and excluded sources.
2. Support exact/n-gram/code AST/media perceptual hash/embedding/model-assisted detectors as versioned user-space plugins.
3. Return matches or blinded counts/slices/confidence according to protected policy, plus false-positive/false-negative limitations.
4. Bind scan inputs/versions/thresholds to dataset/eval reports and rerun when either side changes.
5. Provide canary records and membership/memorization probes as separate evaluators where lawful.

**Responsibility boundaries: this task must not drift into**

- Do not claim “clean” from one string-matching pass.
- Do not reveal protected test cases to training operators.
- Do not equate possible semantic similarity with proven leakage without confidence/evidence.

**Required integration**

- Eval Controller owns protected suite interface; Data controller gates snapshot readiness; Incident handles exposure.

**Validation and definition of done**

- G33, G43, G51, and G86 insert paraphrased, translated, generated, and exact overlaps and require correct bounded findings.

**Required contracts / collaborating tasks:** `DODRV-004`, `EVDRV-003`

**Gold evidence:** `G33`, `G43`, `G51`, `G86`

### Task 6 — DODRV-006: Implement labeling, annotation, enrichment, and synthetic-data operators

**Anti-drift implementation goal**

Support human, model, programmatic, simulator, and agent-generated labels/data with explicit uncertainty and ancestry.

**Required implementation**

1. Define label/annotation schemas with target record/span/region/trajectory, annotator principal/model/program, rubric, confidence, timestamp, conflicts, and adjudication.
2. Support weak/programmatic supervision and model-generated labels as separate source classes, never indistinguishable from human or ground truth.
3. Define synthetic generation manifests with generator model/route/prompt/config/seed/source refs and quality/filter/eval reports.
4. Track generation number/ancestry and real-versus-synthetic composition by slice to monitor recursive collapse/tail loss.
5. Provide active-learning request/response interfaces, while selection policy remains application/Collection/Improvement code.

**Responsibility boundaries: this task must not drift into**

- Do not call synthetic labels human feedback.
- Do not let a generating model approve its own data without independent checks.
- Do not overwrite conflicting annotations with a silent majority.

**Required integration**

- Feedback Service supplies annotations; Model/World/Agent workloads generate candidates; Data controller composes/adjudicates.

**Validation and definition of done**

- G36, G37, G48, and G56 track synthetic generations, disagreements, tail retention, and independent validation.

**Required contracts / collaborating tasks:** `DODRV-001`, `FDBK-001`, `MODEL-003`

**Gold evidence:** `G36`, `G37`, `G48`, `G56`

### Task 7 — DODRV-007: Implement deterministic split, shard, sampling, and data-assignment operators

**Anti-drift implementation goal**

Create immutable train/validation/test/protected/online splits and worker assignments that survive retries and fleet changes.

**Required implementation**

1. Define split policies using stable record/group identity, stratification, time/source boundaries, exclusion sets, and seed/version.
2. Publish split manifests as record/shard membership refs, not mutable directory convention.
3. Implement deterministic sharding and sampling plans with replacement/weights/curriculum/order semantics and global batch/data cursor compatibility.
4. Support protected split membership where clients see only opaque handles/fingerprints.
5. Generate worker DataAssignments independent of unstable rank and record duplicate/skip guarantees.

**Responsibility boundaries: this task must not drift into**

- Do not randomly split related records independently.
- Do not create eval/test splits after examining candidate-specific results without versioning/adaptive-eval evidence.
- Do not derive persistent sample ownership from rank alone.

**Required integration**

- Training/Eval controllers request assignments; Trainer/Evaluator drivers consume; Dataset state stores manifests.

**Validation and definition of done**

- G33, G39, G42, G52, and G64 verify leakage-safe split, deterministic assignment, retry, and resize.

**Required contracts / collaborating tasks:** `DODRV-004`, `STA-001`, `FND-008`

**Gold evidence:** `G33`, `G39`, `G42`, `G52`, `G64`

### Task 8 — DODRV-008: Implement distributed data-operation execution and aggregation

**Anti-drift implementation goal**

Scale collection preparation and quality work across arbitrary devices while preserving deterministic outputs and data locality.

**Required implementation**

1. Partition input snapshots into immutable work units by source/shard/range and execute operators as Workload tasks.
2. Schedule locality- and capability-aware operations; allow CPUs/edge devices to perform suitable decode/filter/label/quality work without joining training collectives.
3. Deduplicate task retries by work-unit identity and merge outputs through deterministic manifests/reducers.
4. Checkpoint stream cursors and long indexing/dedup jobs; preserve partial results explicitly.
5. Enforce per-task data-use leases and prevent reducer/aggregator from reading unauthorized raw payloads when summaries suffice.

**Responsibility boundaries: this task must not drift into**

- Do not assume output ordering equals task completion.
- Do not move all data to one coordinator by default.
- Do not count partial shards as a complete dataset.

**Required integration**

- Workload/Fleet schedule; Node mounts; Collection/Data controller validates completeness; Artifact publishes.

**Validation and definition of done**

- G30–G38 and G61/G68 run quality, dedup, contamination, labeling, and incremental work on heterogeneous fleet with failure injection.

**Required contracts / collaborating tasks:** `DODRV-001`, `WORK-003`, `FLEET-008`

**Gold evidence:** `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G61`, `G68`

### Task 9 — DODRV-009: Build data-operator conformance and audit validation

**Anti-drift implementation goal**

Make record conservation, lineage, determinism, privacy, and protected-data behavior testable.

**Required implementation**

1. Generate tests for schema, input/output counts, transform determinism class, lineage completeness, source cursor, duplicate retry, partial shard, cancellation, classification, deletion, and protected eval isolation.
2. Inject corrupt records, poison labels, malicious payloads, path traversal, archive bombs, PII, conflicting IDs, source reset, and operator crash.
3. Use small hand-computed fixtures and invariants such as every output record maps to declared inputs/generation or explicit drop finding.
4. Publish conformance reports per operation/schema and separately document detector scientific validity/limitations.
5. Quarantine operators that emit undeclared records, omit mounted sources, or leak protected payloads.

**Responsibility boundaries: this task must not drift into**

- Do not certify contamination detector completeness from interface tests.
- Do not ignore dropped records or count drift.
- Do not let data operators grant training/eval use themselves.

**Required integration**

- Driver Registry/Data controller require reports; Incident handles poisoning/leakage.

**Validation and definition of done**

- G07 and G30–G38 reject intentionally faulty operators and preserve exact record accounting.

**Required contracts / collaborating tasks:** `DODRV-001`, `FND-005`, `LIN-005`

**Gold evidence:** `G07`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`

### Component completion gate

- Data operators transform governed inputs into immutable outputs/reports with complete declared lineage.
- Quality, contamination, labeling, synthetic ancestry, split, and use approval remain distinguishable.
- Data work scales through workload tasks and locality, not through hidden one-off scripts.

---

## Component 22 — Sandbox and Executor Driver Contract

**Canonical component ID:** `splendor.sandbox-executor-driver`
**Plane:** `driver_boundary`
**Current status:** partial foundation
**Owning package:** `contract in crates/splendor-types and splendor-gateway; implementations in `adapters/executors/*` and Node Agent host backends`

**Implemented baseline to preserve**

The README describes managed Python and planned shell adapters; a Docker image exists for local runtime smoke tests, but there is no general isolated executor contract for restricted argv, explicit shell, locked Python, OCI, Kubernetes Jobs, interactive coding, builds, devices, mounts, network, resource accounting, or supply-chain evidence.

**Exact kernel responsibility**

Create and supervise an isolated execution environment for user/provider code from immutable environment/code inputs and scoped resources. It owns environment realization and process/container/job lifecycle; it does not decide what code is allowed, grant capabilities, interpret algorithm success, or bypass driver/workload controls.

**Public contracts:** `ExecutorManifest`, `EnvironmentSpec`, `ProcessSpec`, `SandboxProfile`, `MountSpec`, `NetworkPolicy`, `DeviceAllocation`, `ExecutionHandle`, `ProcessResult`, `EnvironmentReceipt`

### Task 1 — SBX-001: Define executor operations, environment specs, and isolation profiles

**Anti-drift implementation goal**

Provide one explicit contract for process, Python, container, cluster job, and interactive environments without pretending they offer equal isolation.

**Required implementation**

1. Define operations build-environment, start, exec-registered, exec-shell, attach/stream, signal, checkpoint-if-supported, stop, inspect, and collect-output.
2. Define environment refs for host runtime, locked Python, OCI image, Kubernetes template, VM/microVM plugin, or custom executor; bind exact code/config.
3. Define isolation profiles by filesystem, process/user namespace, network, devices, syscalls/capabilities, secrets, mounts, IPC, privilege, and persistence.
4. Declare maturity and guarantee differences for host process, container, Kubernetes pod, and stronger sandbox providers.
5. Require requested profile and host-realized effective profile in evidence.

**Responsibility boundaries: this task must not drift into**

- Do not call all containers sandboxes.
- Do not allow an executor profile to grant authority missing from workload/driver invocation.
- Do not make one Linux-specific primitive mandatory in the abstract contract.

**Required integration**

- Node Agent maps profile to host mechanisms; Driver Gateway passes scoped handles; Workload owns lifecycle.

**Validation and definition of done**

- G10–G14 validate profiles and evidence on reference Linux/container/Kubernetes backends.
- Unsupported isolation requirements reject rather than downgrade silently.

**Required contracts / collaborating tasks:** `DRREG-001`, `NODE-005`, `FND-011`

**Gold evidence:** `G10`, `G11`, `G12`, `G13`, `G14`

### Task 2 — SBX-002: Implement restricted argv process execution

**Anti-drift implementation goal**

Provide a safe default for known tools and scripts without a shell parser or ambient host environment.

**Required implementation**

1. Execute an immutable binary/script ref with structured argv, fixed/validated working directory, allowlisted environment keys, scoped mounts, resource limits, and no shell expansion.
2. Resolve executables from signed environment/code bundles rather than host PATH by default.
3. Support registered command templates with typed parameters and explicit allowed exit codes/output artifacts.
4. Capture stdout/stderr with bounds/redaction and exact process/child cleanup.
5. Reject NUL/path traversal/working-directory escape and undeclared executable changes.

**Responsibility boundaries: this task must not drift into**

- Do not concatenate argv into a shell command.
- Do not inherit the node agent’s environment or credentials.
- Do not consider exit code zero sufficient for workload success.

**Required integration**

- Actuator driver may expose registered commands; Workload/Node supervise; Artifact stores outputs.

**Validation and definition of done**

- G10 tests injection, PATH replacement, env leakage, timeout, child process, and output bounds.

**Required contracts / collaborating tasks:** `SBX-001`, `NODE-009`

**Gold evidence:** `G10`

### Task 3 — SBX-003: Implement explicit high-risk shell execution

**Anti-drift implementation goal**

Support necessary shell/coding workflows while making the security boundary and authority materially stronger than restricted argv.

**Required implementation**

1. Expose `sh -c`/chosen shell only through a distinct operation, side-effect class, capability, approval/risk policy, and sandbox profile.
2. Require immutable script artifact or bounded command text, explicit shell/version, working tree, mounts, network destinations, secret refs, resource/time/process limits, and output declarations.
3. Record script digest and effective policy; redact secret values while preserving command provenance.
4. Disable host privilege, broad sockets, Docker daemon, device access, and uncontrolled package install by default.
5. Provide disposable workspace and cleanup/forensic retention policy.

**Responsibility boundaries: this task must not drift into**

- Do not hide shell behind a generic tool call.
- Do not pass user strings through nested shell interpolation.
- Do not mount the host repository or home directory read-write by default.

**Required integration**

- Authority/Gate enforce risk; Node realizes isolation; Coding agent uses through actuator/workload only.

**Validation and definition of done**

- G11 and G80–G82 attempt injection, escape, secret theft, network exfiltration, and daemon socket access.

**Required contracts / collaborating tasks:** `SBX-001`, `AUTH-007`, `DGW-007`

**Gold evidence:** `G11`, `G80`, `G81`, `G82`

### Task 4 — SBX-004: Implement reproducible locked Python environments

**Anti-drift implementation goal**

Run model, trainer, evaluator, data, planner, and coding code with exact dependencies and no ambient package drift.

**Required implementation**

1. Build environment artifacts from lockfiles/wheels/conda-like specs through a separate build workload with hashes, indexes, platform, Python version, and build provenance.
2. Run with read-only environment, isolated user/site packages, explicit entrypoint/module, structured args/config, scoped mounts, and network policy.
3. Support PyO3/in-process callbacks only for tightly trusted local compatibility; production arbitrary Python runs out-of-process.
4. Capture Python/framework/native-extension versions and verify environment digest before execution.
5. Cache environments by digest and prevent runtime pip/install mutation unless a new build workload is authorized.

**Responsibility boundaries: this task must not drift into**

- Do not `pip install` mutable latest inside a training run.
- Do not share writable virtualenvs across tenants/attempts.
- Do not make Python the required implementation language for user space.

**Required integration**

- Trainer/Model/Evaluator/Data drivers use the executor; Artifact/Lineage own environment build.

**Validation and definition of done**

- G12, G52–G54 reproduce environments, reject dependency drift, and isolate concurrent attempts.

**Required contracts / collaborating tasks:** `SBX-001`, `ART-004`, `LIN-002`

**Gold evidence:** `G12`, `G52`, `G53`, `G54`

### Task 5 — SBX-005: Implement OCI image execution and build workflows

**Anti-drift implementation goal**

Run complete arbitrary software stacks with immutable images while retaining Splendor authority and evidence.

**Required implementation**

1. Execute only digest-pinned images with declared entrypoint/argv, user, filesystem, mounts, network, devices, seccomp/capabilities, resource limits, and output paths.
2. Create separate image-build workloads from source/recipe/base-image refs; publish image/SBOM/provenance/signature artifacts.
3. Support container runtime adapters behind Node Agent and record runtime/effective isolation.
4. Prevent image entrypoint or environment from overriding the workload control channel/fencing/mount contracts.
5. Implement image scan/admission hooks and revocation impact without treating scan pass as algorithm safety.

**Responsibility boundaries: this task must not drift into**

- Do not run floating image tags.
- Do not expose host Docker/containerd control sockets.
- Do not allow privileged/root/device access unless an exact high-risk profile and capability requires it.

**Required integration**

- Artifact Registry verifies image/build; Node Agent starts container; Driver Registry binds executor backend.

**Validation and definition of done**

- G13 and G83 test signed build, runtime isolation, tampered image, privileged escape, and revocation.

**Required contracts / collaborating tasks:** `SBX-001`, `ART-004`, `NODE-009`

**Gold evidence:** `G13`, `G83`

### Task 6 — SBX-006: Implement Kubernetes Job and workload execution adapter

**Anti-drift implementation goal**

Use existing Kubernetes clusters without making Kubernetes the Splendor kernel or losing workload identity/authority.

**Required implementation**

1. Create digest-pinned Job/PodGroup-compatible manifests from Workload tasks with namespace/service account, resources/devices, node constraints, volumes, network/pod security, deadlines, labels, and owner identity.
2. Use scoped cluster credentials and server-side apply/create with immutable workload/attempt labels; watch pod/job lifecycle and map failures precisely.
3. Support indexed Jobs for independent shards and an external gang/PodGroup integration where available; keep Splendor reservation semantics explicit.
4. Inject control channel, fencing token, artifact/data/secret mounts through secure mechanisms and collect outputs/cleanup.
5. Support observed mode for externally managed CRDs/operators with reduced guarantees.

**Responsibility boundaries: this task must not drift into**

- Do not grant cluster-admin to workloads.
- Do not assume a Kubernetes Job provides distributed training semantics or gang scheduling automatically.
- Do not treat pod Running as worker ready.

**Required integration**

- Capacity provider can provision clusters; Node/Workload controller owns semantics; Kubernetes is an executor/provider.

**Validation and definition of done**

- G14, G61, G63, and G66 cover single Job, indexed shards, gang failure, device plugin resource, cancellation, and observed mode.

**Required contracts / collaborating tasks:** `SBX-001`, `WORK-008`, `FLEET-003`

**Gold evidence:** `G14`, `G61`, `G63`, `G66`

### Task 7 — SBX-007: Implement filesystem, network, process, syscall, IPC, and device isolation

**Anti-drift implementation goal**

Enforce effective least privilege around arbitrary code across host backends.

**Required implementation**

1. Default filesystem to read-only root/environment/input mounts plus bounded writable scratch/output; deny host paths and path traversal.
2. Default network deny; permit exact DNS/IP/domain/service/port/protocol or local driver endpoints with egress accounting and optional proxy mediation.
3. Isolate users/process IDs/namespaces/IPC; bound child count, file descriptors, shared memory, and signals; apply syscall/capability profiles where supported.
4. Allocate only leased device IDs/resources and prevent direct access to physical actuators or unrelated accelerators.
5. Record effective controls and unsupported host limitations; reject required guarantees that cannot be realized.

**Responsibility boundaries: this task must not drift into**

- Do not treat application allowlists as kernel isolation.
- Do not allow loopback/control sockets broadly.
- Do not pass through all `/dev` for GPU convenience.

**Required integration**

- Node Agent performs host enforcement; Gateway supplies allowed endpoints; Authority/Data-Use supply scope.

**Validation and definition of done**

- G10–G16 and G80–G83 run escape/exfiltration/resource attacks and assert host/control/device isolation.

**Required contracts / collaborating tasks:** `SBX-001`, `NODE-009`

**Gold evidence:** `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G80`, `G81`, `G82`, `G83`

### Task 8 — SBX-008: Implement governed mounts, secrets, data handles, and output publication

**Anti-drift implementation goal**

Make environment I/O exact, attributable, and revocable rather than relying on shared directories and environment variables.

**Required implementation**

1. Translate Artifact/Data/Secret handles into read-only mounts, pipes, local proxy endpoints, or short-lived files according to profile; never expose backing credentials.
2. Create writable scratch and declared output locations with quotas, classification, and upload sessions.
3. Track mount/read/write/open lifecycle where feasible and emit a mount/output receipt bound to attempt/fencing.
4. Revoke/unmount/scrub on cancellation/expiry and verify no secret values appear in outputs/logs before publication policy.
5. Support large streaming inputs/outputs without staging all bytes when locality/backend allows.

**Responsibility boundaries: this task must not drift into**

- Do not use a shared `/data` convention as identity or authority.
- Do not put secret values in command lines or durable environment manifests.
- Do not publish every workspace file automatically.

**Required integration**

- Node Agent artifact cache/data grants/secret broker realize handles; Artifact Registry commits declared outputs.

**Validation and definition of done**

- G08, G13, G17, G34, and G82 validate mount scope, cleanup, output selection, and leak detection.

**Required contracts / collaborating tasks:** `SBX-007`, `NODE-004`, `SECR-002`, `ART-002`

**Gold evidence:** `G08`, `G13`, `G17`, `G34`, `G82`

### Task 9 — SBX-009: Implement resource accounting, limits, deadlines, and cleanup

**Anti-drift implementation goal**

Ensure arbitrary code cannot evade fleet quotas or leave resource leaks after failure.

**Required implementation**

1. Enforce CPU, memory, accelerator/device, storage, I/O, network, process, wall/CPU time, and output/log limits through host backend.
2. Measure requested/reserved/allocated/peak/consumed resources and provider cost where available; attribute to tenant/workload/attempt.
3. Support graceful signal/cancel then hard termination, descendant cleanup, mount revocation, upload resolution, and residual resource scan.
4. Detect OOM, disk-full, quota, thermal/device reset, and external eviction distinctly.
5. Quarantine resources or node on uncertain device/process cleanup.

**Responsibility boundaries: this task must not drift into**

- Do not rely only on user-reported usage.
- Do not return success before child processes and outputs are reconciled.
- Do not reuse an accelerator after a fatal/reset error without health validation.

**Required integration**

- Node Agent allocator owns enforcement; Workload receives outcomes; Fleet accounting updates quota.

**Validation and definition of done**

- G09–G14, G63, and G68 exceed every limit and verify cleanup/accounting and protected SLOs.

**Required contracts / collaborating tasks:** `SBX-001`, `NODE-003`, `AUTH-004`

**Gold evidence:** `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G63`, `G68`

### Task 10 — SBX-010: Implement interactive coding and persistent workspace sessions

**Anti-drift implementation goal**

Support agents/humans performing iterative code work while retaining snapshots, permissions, and rollback.

**Required implementation**

1. Define a workspace as an immutable base code artifact plus versioned writable overlay/snapshots, owner, lifetime, mounts, network, tools, and resource quota.
2. Support controlled exec/test/build/file-diff/apply-patch operations through executor/actuator contracts; every mutation yields a workspace state commit or artifact.
3. Provide session attach/stream without granting host shell; authenticate each participant and record bounded command/diff/test evidence.
4. Checkpoint/suspend/resume/migrate a workspace where backend supports it; otherwise rebuild from snapshot/environment.
5. Make generated code changes candidates requiring build/test/eval/change gates before deployment or kernel modification.

**Responsibility boundaries: this task must not drift into**

- Do not let a coding agent edit the running kernel checkout or deployment directly.
- Do not persist hidden untracked files as the only state.
- Do not treat passing self-authored tests as sufficient validation.

**Required integration**

- Change/Improvement controllers consume code candidates; Git/provider operations are actuator drivers; Artifact/State store snapshots.

**Validation and definition of done**

- G47 and G76 demonstrate coding feedback, isolated patch/test, rollback, and independent eval without live code mutation.

**Required contracts / collaborating tasks:** `SBX-002`, `SBX-004`, `STA-001`, `CHG-008`

**Gold evidence:** `G47`, `G76`

### Task 11 — SBX-011: Implement environment build, cache, and reproducibility receipts

**Anti-drift implementation goal**

Make environments reusable and fast without allowing mutable cache or supply-chain ambiguity.

**Required implementation**

1. Build environment/image artifacts in isolated, network-scoped workloads from exact source/lock/base/toolchain refs.
2. Capture resolved dependencies, native libraries, compiler/runtime, accelerator stack, SBOM, build logs, tests, provenance, and signatures.
3. Cache by complete build key/digest and verify bytes/signatures before use; separate trusted and untrusted cache namespaces.
4. Support platform-specific variants under one logical environment collection with exact per-platform refs.
5. Rebuild periodically or on vulnerability/revocation and compare outputs; do not mutate prior environment artifact.

**Responsibility boundaries: this task must not drift into**

- Do not make a local virtualenv or Docker tag a durable environment identity.
- Do not execute build scripts with unrestricted secrets/network.
- Do not call non-reproducible builds reproducible; record class/variance.

**Required integration**

- Artifact/Lineage own outputs; Driver Registry/Deployment consume signatures; Incident handles compromised dependencies.

**Validation and definition of done**

- G12, G13, G52, and G83 test cold/reused build, tampering, dependency revocation, and reproducibility class.

**Required contracts / collaborating tasks:** `SBX-004`, `SBX-005`, `ART-004`, `LIN-002`

**Gold evidence:** `G12`, `G13`, `G52`, `G83`

### Task 12 — SBX-012: Implement device image and edge workload deployment executor

**Anti-drift implementation goal**

Allow a robot/drone/edge computer to receive and run approved images/services while keeping physical authority local and bounded.

**Required implementation**

1. Define device-compatible deployment bundle with architecture/runtime, signed image/environment, services, resources, drivers, local policy, health, rollback, and offline behavior.
2. Stage bytes to node cache, verify signatures/integrity/compatibility, preflight reservations and safety state, then activate through Deployment Controller.
3. Run cloud-helper/model/planner containers without direct actuator device mounts; expose high-level actuator endpoint only through local gateway.
4. Support A/B slots or equivalent rollback where device platform allows and safe-mode fallback otherwise.
5. Coordinate update with mission/operation state, battery/network/storage, and local operator policy.

**Responsibility boundaries: this task must not drift into**

- Do not flash firmware or bypass certified safety systems through generic executor.
- Do not update during unsafe mission phase merely because control plane requests it.
- Do not give cloud workloads direct motor buses.

**Required integration**

- Node Agent and Deployment Controller own activation; physical actuator driver owns effects; Incident handles failed update.

**Validation and definition of done**

- G73–G75 deploy a simulated robot/drone compute image, preserve local safety, operate offline, and roll back failed health.

**Required contracts / collaborating tasks:** `SBX-005`, `ACT-006`, `DEP-006`

**Gold evidence:** `G73`, `G74`, `G75`

### Task 13 — SBX-013: Build executor conformance and cross-backend equivalence tests

**Anti-drift implementation goal**

Prove claimed isolation/lifecycle semantics for host, Python, OCI, Kubernetes, and edge backends.

**Required implementation**

1. Generate tests for launch, readiness, streams, signals, timeout, cancellation, child cleanup, mounts, network, secrets, devices, resource limits, outputs, crash recovery, and evidence.
2. Run an adversarial fixture attempting path, namespace, socket, credential, device, fork-bomb, disk, network, and control-channel abuse.
3. Compare a portable reference workload across backends and record behavioral/environment differences rather than assuming equivalence.
4. Publish effective-isolation reports per platform/runtime version and revoke on changed backend/security profile.
5. Require stronger independent review for high-risk shell/privileged/device profiles.

**Responsibility boundaries: this task must not drift into**

- Do not infer host security from manifest intent only.
- Do not mark skipped controls pass on a backend lacking them.
- Do not claim Kubernetes and local containers have identical networking/storage behavior.

**Required integration**

- Driver Registry maturity and Node capability advertise exact supported profiles.

**Validation and definition of done**

- G07, G10–G14, and G80–G83 reject faulty backends and record honest guarantee differences.

**Required contracts / collaborating tasks:** `SBX-001`, `SBX-009`, `FND-005`

**Gold evidence:** `G07`, `G10`, `G11`, `G12`, `G13`, `G14`, `G80`, `G81`, `G82`, `G83`

### Component completion gate

- Arbitrary code runs only in an explicitly selected, measured isolation profile with immutable environment/code and scoped I/O.
- Shell, Python, OCI, Kubernetes, and device execution are providers under one workload/gateway contract, not authority bypasses.
- Environment success, algorithm success, candidate validity, and deployment remain separate decisions.

---

## Component 23 — Agent Registry

**Canonical component ID:** `splendor.agent-registry`
**Plane:** `agent_cognition`
**Current status:** partial foundation
**Owning package:** `crates/splendor-agent (registry module)`

**Implemented baseline to preserve**

The current runtime has `AgentId`, `AgentContext`, per-agent isolation policy, runtime config, state head, local registration/delegation records, and work orders. It lacks a versioned immutable AgentSpec describing complete agent composition, value/constraint bindings, world/memory partitions, routes, model/driver dependencies, triggers, sub-agent templates, deployment compatibility, and revision history.

**Exact kernel responsibility**

Own persistent agent definition identity and immutable revisions. It validates references and compatibility for the complete agent composition but does not run instances, execute routes, choose changes, train models, or activate revisions.

**Public contracts:** `AgentSpec`, `AgentRevision`, `AgentComponentBinding`, `AgentAuthorityProfile`, `AgentValueProfile`, `AgentWorldProfile`, `SubagentTemplate`, `AgentCompatibilityReport`

### Task 1 — AGREG-001: Define AgentSpec and immutable revision semantics

**Anti-drift implementation goal**

Represent a complete agent as a versioned composition of kernel-governed primitives and user-space artifacts rather than a prompt-plus-tools blob.

**Required implementation**

1. Define agent identity, tenant/owner, revision ID, objective/role metadata, route refs, model bindings, perceptor/actuator bindings, world/state/memory partitions, constraints/value policy refs, feedback/eval links, triggers/schedules, sub-agent templates, resource/SLO profile, and deployment compatibility.
2. Require exact immutable artifact/driver/policy refs in a revision; allow mutable aliases only in a separate desired deployment/config pointer.
3. Distinguish stable agent identity from revision, deployed configuration, instance, run, workload, and sub-agent identities.
4. Permit arbitrary user-space planner/model/memory/ontology artifacts through typed bindings without interpreting their internals.
5. Define draft, validated, candidate, approved-for-target, deprecated, revoked, and retired revision states without conflating approval with deployment.

**Responsibility boundaries: this task must not drift into**

- Do not make an agent equal to one model or one route.
- Do not store secret values, live endpoints, or mutable state inside AgentSpec.
- Do not permit a revision to self-declare deployed or aligned.

**Required integration**

- Wrap current AgentContext/config as a generated compatibility AgentSpec revision.
- Artifact/Driver/Authority/World/Route registries validate refs.

**Validation and definition of done**

- G23 and G29 instantiate the same immutable revision repeatedly and preserve identity distinctions.
- Cross-language fixtures reject mutable/latest and missing privileged bindings.

**Required contracts / collaborating tasks:** `FND-001`, `ART-001`, `DRREG-001`

**Gold evidence:** `G23`, `G29`

### Task 2 — AGREG-002: Define typed component bindings and compatibility validation

**Anti-drift implementation goal**

Ensure a revision can actually connect its models, routes, perceptors, actuators, state, world, and policies before runtime.

**Required implementation**

1. Define binding roles and input/output schema contracts between route ports and model/driver/state/world/message operations.
2. Validate schema/version/media compatibility, model processor/composition, route node requirements, driver operations/profiles, state/world partition schemas, and resource/runtime requirements.
3. Resolve exact permitted fallback sets but do not select runtime instances/providers.
4. Produce a compatibility report with hard failures, warnings, required migrations, and target-specific constraints.
5. Support extension bindings through named schemas and kernel validation hooks rather than arbitrary code execution during registry validation.

**Responsibility boundaries: this task must not drift into**

- Do not validate compatibility by matching string names only.
- Do not run untrusted user code in the registry service.
- Do not silently insert converters or fallback components.

**Required integration**

- Route compiler, Model/Driver registries, State/World schemas, and Deployment target facts contribute pure validation.

**Validation and definition of done**

- G24, G28, G54, and G55 validate compatible and incompatible custom model/route/adapter compositions.

**Required contracts / collaborating tasks:** `AGREG-001`, `ROUTE-009`, `MODEL-001`

**Gold evidence:** `G24`, `G28`, `G54`, `G55`

### Task 3 — AGREG-003: Define authority, value, constraint, and data bindings as independent profiles

**Anti-drift implementation goal**

Make what an agent may do, what it should optimize, what must never occur, and what data it may use separately replaceable and auditable.

**Required implementation**

1. Bind an `AgentAuthorityProfile` to allowed capability/work-order templates and delegation ceilings without embedding grants.
2. Bind an `AgentValueProfile` to versioned objectives/preferences/constitutional or domain policy artifacts, evaluators, reward derivations, uncertainty/escalation policy, and protected non-self-modifiable roots.
3. Bind hard/soft constraint/verifier bundles separately from learned value/reward models.
4. Bind collection/data-use purposes, prohibited sources, retention, feedback eligibility, and protected eval policy separately.
5. Define which bindings may be changed at each self-adjustment risk class and which require external approval.

**Responsibility boundaries: this task must not drift into**

- Do not equate value alignment with one reward scalar or prompt.
- Do not let a model artifact grant authority.
- Do not permit a revision change to delete immutable root constraints or its own approval requirements.

**Required integration**

- Authority/Gate/Data-Use/Reward services own semantics; Agent Registry stores exact refs/compatibility.

**Validation and definition of done**

- G27, G40, G78, G79, and G86 attempt value/reward/authority/profile bypass and fail.

**Required contracts / collaborating tasks:** `AGREG-001`, `AUTH-003`, `GATE-001`, `DUC-001`

**Gold evidence:** `G27`, `G40`, `G78`, `G79`, `G86`

### Task 4 — AGREG-004: Implement revision derivation, diff, migration, and compatibility history

**Anti-drift implementation goal**

Make agent evolution inspectable and reversible across models, routes, world schemas, drivers, and policies.

**Required implementation**

1. Create new revisions only through a derivation record referencing parent(s), ChangeSet, changed bindings, rationale/hypothesis, and evidence.
2. Generate semantic diffs by component role and classify expected impact on state/world schemas, authority, resources, data, behavior, physical scope, and deployment targets.
3. Require state/world/session migration refs where schemas change; validate rollback compatibility separately.
4. Retain every historical revision and dependency manifest for replay/audit even after revocation.
5. Support branches and experimental revisions without moving the production desired pointer.

**Responsibility boundaries: this task must not drift into**

- Do not mutate a revision in place.
- Do not infer rollback safety from a textual version number.
- Do not hide a policy/value change inside model metadata.

**Required integration**

- Change Controller creates derived revisions; Lineage records ancestry; Deployment activates exact revision.

**Validation and definition of done**

- G45, G70, G76, and G79 show model/route/code/value changes with exact diffs, migrations, and rollback.

**Required contracts / collaborating tasks:** `AGREG-001`, `CHG-001`, `LIN-001`

**Gold evidence:** `G45`, `G70`, `G76`, `G79`

### Task 5 — AGREG-005: Implement sub-agent templates and topology constraints

**Anti-drift implementation goal**

Support specialists, peers, supervisors, swarms, trigger agents, and agents-as-actuators without implicit identity or permission inheritance.

**Required implementation**

1. Define template refs, allowed child revisions/dynamic parameter schemas, relationship role, communication schemas, delegated capability ceiling, data/state sharing, resource/fan-out/depth/duration limits, and lifecycle policy.
2. Support child per task, persistent specialist, pooled specialist, peer federation, supervisor, evaluator/adversary, trigger agent, and external agent bridge as distinct templates.
3. Define parent/child causal and ownership links but retain independent state, authority, workloads, and evidence.
4. Validate topology cycles/recursion and require explicit allowed self-similar templates with bounded depth/fan-out.
5. Separate a sub-agent response/action proposal from trusted verifier/evaluator evidence.

**Responsibility boundaries: this task must not drift into**

- Do not inherit parent permissions or secrets by default.
- Do not make every child a nested thread in the parent process.
- Do not allow a candidate agent to spawn an unbounded evaluator that approves it.

**Required integration**

- Agent Instance realizes templates; Message/Delegation attenuates authority; Actuator profile submits child tasks.

**Validation and definition of done**

- G18, G19, G70, G77, and G81 validate specialist, trigger, swarm, evaluator, recursion, and forged delegation.

**Required contracts / collaborating tasks:** `AGREG-001`, `AUTH-005`, `MSG-003`

**Gold evidence:** `G18`, `G19`, `G70`, `G77`, `G81`

### Task 6 — AGREG-006: Implement desired-state pointers, ownership, visibility, and lifecycle policy

**Anti-drift implementation goal**

Manage discoverability and intended deployment without turning mutable registry tags into activation.

**Required implementation**

1. Create separately versioned desired revision pointers per environment/fleet/device class, owned by Deployment Controller and protected by change/gate policy.
2. Implement private/tenant/shared/public visibility and explicit sharing grants for AgentSpecs and selected artifacts.
3. Define owner/maintainer/operator/evaluator roles and transfer process without moving tenant/data authority silently.
4. Implement deprecation/revocation notifications and impact queries for running instances/deployments.
5. Support agent retirement while retaining history/evidence and revoking new instance admission.

**Responsibility boundaries: this task must not drift into**

- Do not let an agent update its own desired production pointer directly.
- Do not make public visibility grant data/model artifact payload access automatically.
- Do not kill running instances on deprecation unless policy says revoke.

**Required integration**

- Deployment Controller is sole activator; Authority controls roles; Lineage/Incident identify impact.

**Validation and definition of done**

- G70, G75, and G79 test candidate pointer isolation, revocation, and retirement.

**Required contracts / collaborating tasks:** `AGREG-001`, `DEP-001`, `AUTH-001`

**Gold evidence:** `G70`, `G75`, `G79`

### Task 7 — AGREG-007: Implement framework bridges and portable import/export

**Anti-drift implementation goal**

Let higher-level agent frameworks consume Splendor primitives without forcing their internal architecture into the kernel.

**Required implementation**

1. Provide SDK builders and import adapters for callback agents, graph/workflow frameworks, planner-tool stacks, model-centric agents, and custom event loops.
2. Map external models/tools/memory nodes to explicit model/driver/state/world/route bindings and emit a compatibility/guarantee report.
3. Export an AgentSpec bundle with non-secret refs, schemas, lineage, and required external dependencies; imports are untrusted until validated.
4. Allow framework-managed internal pure computation while requiring all kernel crossings through SDK handles.
5. Document unsupported opaque behavior and observed/unmanaged modes honestly.

**Responsibility boundaries: this task must not drift into**

- Do not reimplement every agent framework.
- Do not wrap arbitrary framework tool calls and claim they are verified if they bypass the gateway.
- Do not serialize live Python objects as durable AgentSpec.

**Required integration**

- Python/TypeScript SDKs provide bridge interfaces; Workload/Sandbox can host framework code.

**Validation and definition of done**

- G06, G23, G24, and G54 implement the same small agent in callback, graph, and custom-loop styles with identical boundary evidence.

**Required contracts / collaborating tasks:** `AGREG-001`, `WORK-008`, `FND-010`

**Gold evidence:** `G06`, `G23`, `G24`, `G54`

### Task 8 — AGREG-008: Build AgentSpec conformance and anti-drift fixtures

**Anti-drift implementation goal**

Keep the complete agent model stable, explicit, and free of hidden privileged configuration.

**Required implementation**

1. Generate valid/invalid fixtures for every binding class, revision state, topology, authority/value/data profile, migration, target compatibility, and extension rule.
2. Scan manifests for floating refs, secret values, direct endpoints, undeclared tools/drivers, missing schemas, and hidden activation flags.
3. Instantiate revisions in dry-run mode and verify all dependencies resolve without executing user code/effects.
4. Compare generated SDK manifests across Rust/Python/TypeScript.
5. Add a minimal and a maximally composed gold AgentSpec to prevent simplification around one use case.

**Responsibility boundaries: this task must not drift into**

- Do not make validation pass by ignoring unknown component fields.
- Do not encode runtime mutable state into fixtures.
- Do not consider a schema-valid agent safe/aligned without eval/gates.

**Required integration**

- CI uses Agent Registry validator before gold examples; Change Controller uses semantic diff.

**Validation and definition of done**

- G00, G23, G29, and G70 pass; malicious hidden-authority manifest fails.

**Required contracts / collaborating tasks:** `AGREG-001`, `AGREG-003`, `FND-005`

**Gold evidence:** `G00`, `G23`, `G29`, `G70`

### Component completion gate

- An AgentSpec is complete enough to reconstruct the governed composition, but contains no live state, secrets, grants, or activation authority.
- Authority, values, constraints, data policy, models, routes, and world bindings remain separate versioned concerns.
- Every evolution creates an immutable derived revision with explicit diff and evidence.

---

## Component 24 — Agent Instance Controller

**Canonical component ID:** `splendor.agent-instance-controller`
**Plane:** `agent_cognition`
**Current status:** partial foundation
**Owning package:** `crates/splendor-agent (instance module), composed by splendor-kernel`

**Implemented baseline to preserve**

The current LoopEngine and cooperative Scheduler run persistent local ticks; daemon run lifecycle, state, percept queues, policy cache, approvals, and delegation exist. Missing are a generic durable AgentInstance state machine, 24/7 supervision across nodes, route-driven concurrency/events, trigger/schedule management, instance migration, revision rollout, sub-agent lifecycle, SLO health, and separation between instance/run/workload/session.

**Exact kernel responsibility**

Own desired/observed lifecycle for one deployed AgentSpec revision instance: admission, resource/workload creation, event consumption, route execution epochs, state/world heads, timers/triggers, health, pause/checkpoint/migration, revision updates, and child-agent supervision. It does not implement route nodes, model inference, training, or external effects.

**Public contracts:** `AgentInstance`, `AgentInstanceSpec`, `InstanceStatus`, `InstanceEpoch`, `RunSession`, `TriggerBinding`, `InstanceCheckpoint`, `InstanceHealth`, `InstanceRevisionTransition`

### Task 1 — AINST-001: Implement the durable AgentInstance state machine and identities

**Anti-drift implementation goal**

Make a 24/7 agent a recoverable governed service rather than an unbounded loop in one process.

**Required implementation**

1. Define instance identity separate from AgentSpec revision, deployment, workload, process, run/session, tick, and node instance.
2. Implement states proposed, admitted, provisioning, starting, running, degraded, waiting, paused, migrating, updating, stopping, stopped, failed, quarantined, and retired.
3. Persist desired revision/replica/node constraints, state/world heads, active run sessions, trigger cursors, child refs, resource/SLO policy, and current epoch.
4. Use optimistic concurrency and controller ownership generation for every transition.
5. Represent one or more execution workloads behind the instance without exposing process identity as agent identity.

**Responsibility boundaries: this task must not drift into**

- Do not overload current `RunId` as permanent agent instance identity.
- Do not store transient model KV/process handles as durable identity.
- Do not mark running before required route/models/drivers/state are ready.

**Required integration**

- Wrap current daemon Run/LoopEngine as one compatibility run session within one local instance.
- Workload Controller realizes execution.

**Validation and definition of done**

- G23 and G29 exercise all transitions, restart, and identity separation.
- Invalid concurrent revision/state transitions fail deterministically.

**Required contracts / collaborating tasks:** `AGREG-001`, `WORK-001`, `STA-001`

**Gold evidence:** `G23`, `G29`

### Task 2 — AINST-002: Implement instance admission and dependency realization

**Anti-drift implementation goal**

Start an agent only when its exact revision, authority, routes, drivers, models, state/world, triggers, and resources are valid for the target.

**Required implementation**

1. Resolve/validate AgentSpec revision, deployment plan, work order/capability, policy/value/data bindings, route compilation, driver/model availability, state/world schemas, and resource placement.
2. Create or attach required state/world partitions with ownership rules and pin initial heads.
3. Create managed workloads/services for route runtime/model services/framework host and register perceptor subscriptions/timers only after readiness.
4. Issue an `InstanceEpoch` binding exact revision/deployment/dependencies and reject mutable drift.
5. Record admission decision and complete dependency graph as evidence.

**Responsibility boundaries: this task must not drift into**

- Do not start with unresolved latest aliases.
- Do not acquire source subscriptions or effect capabilities before admission.
- Do not let framework host choose undeclared drivers/models at runtime.

**Required integration**

- Agent Registry/Deployment supply desired config; Workload/Fleet place; Route/Driver/Model/State/World validate.

**Validation and definition of done**

- G23, G24, G62, and G73 validate local, fleet, neuro-symbolic, and physical admission.
- Missing/revoked dependency causes denied/degraded behavior per policy.

**Required contracts / collaborating tasks:** `AINST-001`, `AGREG-002`, `ROUTE-009`, `DEP-002`

**Gold evidence:** `G23`, `G24`, `G62`, `G73`

### Task 3 — AINST-003: Implement event-driven 24/7 supervision, timers, and triggers

**Anti-drift implementation goal**

Run persistent agents continuously without busy loops, duplicate triggers, or losing causal event identity.

**Required implementation**

1. Register typed perceptor/message/system/timer/schedule/feedback/health triggers with durable consumer cursors and debounce/coalescing/concurrency policy.
2. Create a run session/route execution for each accepted trigger or aggregate window, bound to input event/state/world heads and instance epoch.
3. Support waiting/sleep/timer semantics as desired state, not blocked worker threads.
4. Handle event storms with bounded mailboxes, priority, dropping/spill policy, and explicit gap evidence.
5. Restore subscriptions/timers/cursors after controller/worker/node restart without duplicate unbounded execution.

**Responsibility boundaries: this task must not drift into**

- Do not implement 24/7 by `while True` without durable control state.
- Do not let triggers carry reusable authority.
- Do not process safety-critical and bulk learning events in one unbounded FIFO.

**Required integration**

- Perceptor/Message/Event/Workload services supply streams; Route Runtime executes; State Service stores cursors.

**Validation and definition of done**

- G19, G22, G29, G38, and G49 validate timers, trigger agents, backpressure, restart, and continuous eval/collection.

**Required contracts / collaborating tasks:** `AINST-001`, `WORK-007`, `PERC-003`, `MSG-006`

**Gold evidence:** `G19`, `G22`, `G29`, `G38`, `G49`

### Task 4 — AINST-004: Implement run-session concurrency and state/world consistency policy

**Anti-drift implementation goal**

Permit parallel perception/reasoning/tasks where valid while preventing silent state corruption or duplicated effects.

**Required implementation**

1. Define instance concurrency modes serial, partitioned, optimistic-merge, read-only parallel, and application-coordinated with exact state/world partition ownership.
2. Pin state/world heads at session start; route commits use compare-and-set/merge proposals and retry only pure/re-evaluable stages on conflict.
3. Serialize or lock effectful critical sections by declared resource/target when required.
4. Preserve causal links among trigger, session, route steps, actions, outcomes, state commits, and feedback.
5. Define maximum concurrent sessions/subtasks and cancellation priority.

**Responsibility boundaries: this task must not drift into**

- Do not use last-write-wins for agent/world state by default.
- Do not replay effectful route steps after state conflict.
- Do not globally serialize all agents when partitions permit safe concurrency.

**Required integration**

- State/World services enforce commits; Route compiler marks pure/effectful steps; Gateway handles idempotency.

**Validation and definition of done**

- G24, G27, G29, and G70 inject concurrent sessions/conflicts and verify no duplicate effects or lost updates.

**Required contracts / collaborating tasks:** `AINST-003`, `STA-003`, `WORLD-008`, `DGW-004`

**Gold evidence:** `G24`, `G27`, `G29`, `G70`

### Task 5 — AINST-005: Implement pause, quiesce, checkpoint, resume, migration, and handoff

**Anti-drift implementation goal**

Move or stop a persistent agent safely across processes/devices while preserving explicit state and external-effect certainty.

**Required implementation**

1. Define quiesce protocol: stop accepting selected triggers, drain/cancel sessions by risk, checkpoint route/framework/model session state where supported, commit state/world heads, and close/transfer source cursors.
2. Build an `InstanceCheckpoint` containing AgentSpec/epoch, state/world refs, trigger/message cursors, child refs, session checkpoints, pending approvals/effects, and environment/dependency refs.
3. Validate target compatibility, data locality, driver/model availability, work-order authority, and state handoff before migration.
4. Fence old instance epoch before target becomes active; route late events/results to quarantine/reconciliation.
5. Support cold rebuild when ephemeral model/framework state is non-portable and report behavior/reproducibility implications.

**Responsibility boundaries: this task must not drift into**

- Do not claim migration complete while both epochs can act.
- Do not serialize secrets/credentials into checkpoint.
- Do not silently discard pending uncertain physical/digital effects.

**Required integration**

- Build on current state handoff; Workload/Fleet/Node move execution; Message/Perceptor transfer cursors.

**Validation and definition of done**

- G29, G65, G69, G72, and G75 migrate/crash/reconnect with zero duplicate effect and explicit non-portable state.

**Required contracts / collaborating tasks:** `AINST-001`, `WORK-005`, `STA-007`, `NODE-003`

**Gold evidence:** `G29`, `G65`, `G69`, `G72`, `G75`

### Task 6 — AINST-006: Implement sub-agent spawn, supervision, delegation, and reaping

**Anti-drift implementation goal**

Treat child agents as independently controlled compute while giving parents structured coordination primitives.

**Required implementation**

1. Validate child template, delegated capabilities/data/state, objective/inputs, resource/time/depth/fan-out budgets, and placement before creating child instance/workload.
2. Create explicit parent/child session and causal links; child has independent identity, state, mailbox, traces, and authority lease.
3. Support ephemeral task child, persistent specialist, shared pool reservation, external agent bridge, and child-as-actuator response patterns.
4. Propagate cancellation/revocation according to template; collect typed result/failure and clean child resources.
5. Prevent parent or child messages from altering delegation scope after issuance.

**Responsibility boundaries: this task must not drift into**

- Do not clone parent AgentContext/permissions.
- Do not let child completion automatically commit parent state or action.
- Do not leave orphan persistent specialists after owner/revision retirement.

**Required integration**

- Agent Registry defines templates; Authority attenuates; Message routes; Workload schedules.

**Validation and definition of done**

- G18, G19, G70, G77, and G81 cover child types, resource exhaustion, recursion, revocation, and forged scope.

**Required contracts / collaborating tasks:** `AGREG-005`, `MSG-003`, `WORK-003`

**Gold evidence:** `G18`, `G19`, `G70`, `G77`, `G81`

### Task 7 — AINST-007: Implement instance health, SLO, degraded modes, and circuit-breaker behavior

**Anti-drift implementation goal**

Keep persistent agents safe and observable under model, driver, data, state, connectivity, and physical degradation.

**Required implementation**

1. Define health dimensions dependency readiness, trigger lag, route failure, action denial/failure, state conflicts, model latency/error, source freshness, policy/authority freshness, resource pressure, and physical safety status.
2. Compute health from evidenced facts and configurable thresholds; expose current causes and affected capabilities.
3. Define degraded routes/modes that narrow capability, use local fallback model/source, operate read-only, require HIL, or pause; each mode is predeclared in AgentSpec/policy.
4. Integrate circuit breakers/kill switches at instance, route, driver, action, data, model, and fleet scopes.
5. Escalate to Incident Controller for persistent/unsafe/uncertain conditions.

**Responsibility boundaries: this task must not drift into**

- Do not let the agent invent a degraded mode during failure.
- Do not equate high action-denial rate with permission to relax constraints.
- Do not keep physical agent active when critical local safety dependencies are uncertain.

**Required integration**

- Current circuit-breaker/escalation/governance foundations feed health; Route Runtime selects prevalidated fallback.

**Validation and definition of done**

- G27, G29, G48, G73–G75, and G88 inject failures and verify narrowing/pause, never boundary weakening.

**Required contracts / collaborating tasks:** `AINST-003`, `OBS-005`, `INC-002`

**Gold evidence:** `G27`, `G29`, `G48`, `G73`, `G74`, `G75`, `G88`

### Task 8 — AINST-008: Implement controlled revision transition per instance

**Anti-drift implementation goal**

Update models, routes, policies, drivers, or code without turning registry changes into immediate uncontrolled behavior.

**Required implementation**

1. Receive an approved DeploymentPlan specifying source/target revisions, exact dependency bundle, rollout mode, state/world/session migration, health gates, and rollback.
2. Support shadow dual execution with no effects, canary instance subset, quiesced in-place restart, blue/green instance handoff, and configuration-only route epoch updates where safe.
3. Fence target effect authority until deployment stage permits it and ensure shadow outputs cannot commit live state/world heads.
4. Preserve source checkpoint/state for rollback; validate reverse migration or use old compatible heads.
5. Report transition progress/health/evidence and stop automatically on gate/incident conditions.

**Responsibility boundaries: this task must not drift into**

- Do not hot-reload arbitrary code/model/policy into a running process without a declared mechanism.
- Do not let shadow/candidate instance actuate or write live state.
- Do not call rollback successful if state schema became irreversibly incompatible.

**Required integration**

- Deployment Controller orchestrates; Change/Gate authorize; State/World/Workload realize transition.

**Validation and definition of done**

- G45, G46, G70, G75, and G79 prove shadow/canary/rollback and value-policy protection.

**Required contracts / collaborating tasks:** `AINST-005`, `DEP-003`, `DEP-004`, `CHG-007`

**Gold evidence:** `G45`, `G46`, `G70`, `G75`, `G79`

### Task 9 — AINST-009: Migrate the current LoopEngine and Scheduler into the instance architecture

**Anti-drift implementation goal**

Preserve working local behavior while replacing agent-only lifecycle ownership incrementally.

**Required implementation**

1. Implement a Route/Policy compatibility runner that uses current Perceptor, Policy, ConstraintEngine, ActionGateway, OutcomeEvaluator, StateGraph, and TraceStore inside an agent workload.
2. Map one current tick to one route execution/session segment and preserve event ordering and fail-closed state commit behavior.
3. Move daemon run status and percept queue ownership behind Agent Instance/Workload services while retaining endpoints.
4. Reuse current cooperative Scheduler as a local execution policy, not the future fleet scheduler.
5. Add migration fixtures comparing current and vNext state/trace/action outcomes.

**Responsibility boundaries: this task must not drift into**

- Do not delete or rewrite the implemented baseline first.
- Do not maintain divergent state heads or approval slots in compatibility and new controllers.
- Do not call current round-robin scheduler fleet scheduling.

**Required integration**

- Daemon composition chooses compatibility runner; new Route Runtime can replace policy callback incrementally.

**Validation and definition of done**

- All existing local/multi-agent/governance/physical examples pass; G23/G24 provide equivalent vNext execution.

**Required contracts / collaborating tasks:** `AINST-001`, `WORK-009`, `DGW-009`, `FND-006`

**Gold evidence:** `G23`, `G24`

### Task 10 — AINST-010: Validate long-duration, fleet, and chaos behavior

**Anti-drift implementation goal**

Prove persistent agents survive realistic operation rather than only short deterministic demos.

**Required implementation**

1. Run accelerated multi-day simulations with timers, event bursts, model/driver errors, state conflicts, node restarts, network partitions, policy expiry, resource pressure, and child-agent churn.
2. Measure duplicate/missed triggers, state conflicts, action effect count, recovery time, mailbox lag, resource leaks, and evidence completeness.
3. Run multiple instances/revisions across heterogeneous nodes with migration and rolling deployment.
4. Include physical simulation with local safety and offline periods.
5. Publish reproducibility/chaos report and known limitations.

**Responsibility boundaries: this task must not drift into**

- Do not equate a 100-tick unit test with 24/7 reliability.
- Do not suppress recurring failures to keep the agent “healthy”.
- Do not validate only with allow-all constraints/no-op actuators.

**Required integration**

- Gold runner, Fleet, Incident, Observability, and Replay provide faults/evidence.

**Validation and definition of done**

- G29, G68, G70, G72–G75, and G88 pass configured durability and no-duplicate-effect bounds.

**Required contracts / collaborating tasks:** `AINST-001`, `AINST-007`, `FND-005`

**Gold evidence:** `G29`, `G68`, `G70`, `G72`, `G73`, `G74`, `G75`, `G88`

### Component completion gate

- A persistent agent instance has durable identity, desired/observed state, trigger cursors, exact revision epoch, and recoverable state/world heads.
- Concurrency, migration, sub-agents, degraded modes, and updates never weaken authority or duplicate effects.
- The controller supervises agent lifecycle; user-space route/model/planner code remains replaceable.

---

## Component 25 — Neuro-Symbolic Route Runtime

**Canonical component ID:** `splendor.route-runtime`
**Plane:** `agent_cognition`
**Current status:** partial foundation
**Owning package:** `crates/splendor-agent (route module); user-space node plugins via SDK/workloads`

**Implemented baseline to preserve**

The current loop is a fixed sequence Percepts → Policy → Constraints → Gateway → Adapter → Outcome → State Commit → Trace. Neural policy and symbolic constraint hooks exist, but there is no versioned typed route graph for multiple models, planners/solvers/rules, world/state/memory, sub-agents, branching, loops, parallelism, feedback/eval/training triggers, fallbacks, budgets, or user-defined pure nodes.

**Exact kernel responsibility**

Own validation/compilation and governed execution of typed neuro-symbolic route graphs. It coordinates neural computation, symbolic structure, state/world reads/proposals, messages, and verified driver invocations under budgets. It does not implement the user’s model, planner, solver, ontology, reward, or external effect.

**Public contracts:** `RouteGraph`, `RouteRevision`, `RouteNode`, `RouteEdge`, `PortSchema`, `RouteExecution`, `RouteStep`, `RouteBudget`, `RouteDecision`, `RouteCheckpoint`

### Task 1 — ROUTE-001: Define typed RouteGraph, nodes, ports, and edges

**Anti-drift implementation goal**

Replace a fixed loop with a small compositional control graph that remains explicit and inspectable.

**Required implementation**

1. Define immutable route revisions with typed input/output ports, schemas/media refs, node kinds, control/data edges, entrypoints, terminal outcomes, and required bindings.
2. Provide kernel node kinds for model invocation, symbolic plugin invocation, constraint/verifier request, driver invocation, state/world read/proposal, message/delegation, sub-route, branch, join, timer/wait, emit feedback/eval/training proposal, and pure user computation.
3. Support named opaque custom payload schemas but keep identity/authority/budget/effect fields outside opaque payloads.
4. Validate graph connectivity, port/schema compatibility, bounded cycles, terminal coverage, and prohibited authority flows.
5. Bind route revision to AgentSpec and exact component compatibility.

**Responsibility boundaries: this task must not drift into**

- Do not encode chain-of-thought or one planning algorithm as a kernel node.
- Do not let arbitrary node code commit state/effects directly.
- Do not make every route a DAG; allow explicit bounded/state-machine loops.

**Required integration**

- Agent Registry binds route refs; Workload/Sandbox hosts user nodes; Gateway handles driver calls.

**Validation and definition of done**

- G24 and G28 construct reactive, planner, model-selector, and custom routes; invalid schemas/cycles/authority edges deny.

**Required contracts / collaborating tasks:** `FND-001`, `AGREG-002`, `DGW-001`

**Gold evidence:** `G24`, `G28`

### Task 2 — ROUTE-002: Implement neural/model node semantics as proposal-producing computation

**Anti-drift implementation goal**

Integrate learned decisions under uncertainty without granting model outputs privileged meaning.

**Required implementation**

1. Model nodes invoke exact model operations with pinned input/state/world refs, sampling/budgets, and expected output schema.
2. Represent output as computation result/proposal with model/runtime evidence, uncertainty/calibration metadata, and no inherent authority.
3. Support multiple neural modules: policy, router, encoder, critic/value, reward model, world model, anomaly detector, or custom network by binding role metadata rather than special kernel classes.
4. Allow ensembles/cascades through route composition and explicit fallback/aggregation nodes.
5. Prevent model-generated fields from overriding route, capability, gate, or driver selection.

**Responsibility boundaries: this task must not drift into**

- Do not equate neural policy output with an action.
- Do not let a model choose an undeclared tool/driver by emitting its name.
- Do not treat a reward/value model score as a gate decision.

**Required integration**

- Model Driver executes; Proposal object flows to symbolic/constraint/gateway nodes; Evidence records.

**Validation and definition of done**

- G24, G27, G28, and G80 inject malicious/invalid model outputs and prove typed mediation.

**Required contracts / collaborating tasks:** `ROUTE-001`, `MODEL-003`, `FND-007`

**Gold evidence:** `G24`, `G27`, `G28`, `G80`

### Task 3 — ROUTE-003: Implement symbolic planner, solver, rule, and state-machine plugin semantics

**Anti-drift implementation goal**

Make symbolic structure a first-class runtime participant without selecting a universal logic language.

**Required implementation**

1. Define a symbolic plugin contract receiving pinned typed facts/goals/constraints and returning plan/proof/explanation/candidate/unsat/unknown artifacts.
2. Support user-space rule engines, planners, SAT/SMT/optimization solvers, behavior trees, workflow/state machines, type checkers, theorem/test systems, and domain controllers as versioned workloads/drivers.
3. Record input fact refs, plugin/code/env, timeout/resource budget, result status, proof/certificate refs where available, and unverifiable claims explicitly.
4. Allow symbolic outputs to compose/filter/rank/decompose neural proposals but require final effect verification.
5. Provide deterministic pure-plugin cache/replay profiles.

**Responsibility boundaries: this task must not drift into**

- Do not build one DSL/solver into kernel as the only symbolic path.
- Do not call solver “unknown” an allow.
- Do not treat an explanation string as a machine-checked proof.

**Required integration**

- Sandbox/Workload executes plugins; State/World supply facts; Gate/Constraint validates results.

**Validation and definition of done**

- G24–G27 run rules, planner, SMT-like constraint fixture, and state machine; timeout/unknown fail according to policy.

**Required contracts / collaborating tasks:** `ROUTE-001`, `SBX-004`, `EVID-002`

**Gold evidence:** `G24`, `G25`, `G26`, `G27`

### Task 4 — ROUTE-004: Implement constraint, obligation, verifier, and approval control points

**Anti-drift implementation goal**

Place enforceable symbolic/runtime boundaries throughout a route, not only after a final prompt.

**Required implementation**

1. Allow route nodes/edges to require hard/soft constraints, obligations, evidence, confidence/freshness, approval, quota, or local safety before proceeding.
2. Represent decisions as allow, deny, require-obligation, require-approval, require-intervention, uncertain, or advisory finding with stable reasons.
3. Track outstanding obligations such as redact-before-store, confirm-after-action, human-review, update-world-only-on-observation, or checkpoint-before-preemption.
4. Ensure every effectful driver node still passes Driver Gateway verifiers even if earlier route checks allowed it.
5. Version and bind exact constraint/verifier bundle to route execution.

**Responsibility boundaries: this task must not drift into**

- Do not allow route ordering to skip gateway verification.
- Do not convert a soft constraint to hard or vice versa through opaque extensions.
- Do not let the same candidate satisfy its own approval/evidence obligation.

**Required integration**

- Gate/Authority/Gateway supply enforcement; State stores obligations; HIL provides approvals.

**Validation and definition of done**

- G27, G40, G73, G78, and G79 validate denial, obligation, approval, local safety, and root-policy protection.

**Required contracts / collaborating tasks:** `ROUTE-001`, `DGW-002`, `GATE-001`

**Gold evidence:** `G27`, `G40`, `G73`, `G78`, `G79`

### Task 5 — ROUTE-005: Implement state, memory, world, message, and sub-agent nodes

**Anti-drift implementation goal**

Make agent modelation explicit without forcing one memory or multi-agent architecture.

**Required implementation**

1. Provide read nodes that pin state/world/message views by partition/head/cursor and proposal nodes that submit typed changes through owning services.
2. Represent memory strategies as user-space computations over explicit episodic/semantic/procedural/scratch partitions, not hidden route-global variables.
3. Provide message send/request/await and child-agent delegate/await/cancel nodes with scoped schemas/capabilities.
4. Support context assembly nodes that select/summarize refs under budget and publish their selection evidence.
5. Ensure child/message/model outputs remain observations/proposals until validated/committed.

**Responsibility boundaries: this task must not drift into**

- Do not give route nodes direct database/store handles.
- Do not hide mutable memory inside model prompts or framework objects as the only state.
- Do not accept messages as permission delegation.

**Required integration**

- State/World/Message/Agent Instance services own operations; Sandbox may host selection/summarization code.

**Validation and definition of done**

- G18, G23–G25, G29, and G70 validate explicit memory/world/sub-agent flows and conflict behavior.

**Required contracts / collaborating tasks:** `ROUTE-001`, `STA-003`, `WORLD-003`, `MSG-001`, `AINST-006`

**Gold evidence:** `G18`, `G23`, `G24`, `G25`, `G29`, `G70`

### Task 6 — ROUTE-006: Implement branches, joins, bounded loops, parallelism, and budgets

**Anti-drift implementation goal**

Support sophisticated agent control while keeping termination, resource, and side-effect behavior bounded.

**Required implementation**

1. Implement conditional branch on typed predicates/results, fan-out/fan-in, race/first-valid, all/any/quorum joins, retry nodes, and bounded iteration/state-machine loops.
2. Require max iterations/depth/fan-out/wall time/model tokens/cost/actions/sub-agents/data bytes and per-node budgets.
3. Distinguish retry of pure computation from retry of driver effects and state commits; effectful retries use invocation idempotency/effect rules.
4. Propagate cancellation and budget exhaustion deterministically to child steps/workloads.
5. Checkpoint route execution at declared safe steps for long-lived sessions.

**Responsibility boundaries: this task must not drift into**

- Do not allow unbounded self-reflection or recursive sub-routes.
- Do not retry an effectful node by re-running the whole route blindly.
- Do not let parallel branches commit conflicting state without merge policy.

**Required integration**

- Workload executes heavy/parallel nodes; State stores route checkpoint; Authority quotas budgets.

**Validation and definition of done**

- G24, G28, G29, G70, and G88 test loops, races, fan-out, budget exhaustion, and cancellation storms.

**Required contracts / collaborating tasks:** `ROUTE-001`, `AUTH-004`, `WORK-003`

**Gold evidence:** `G24`, `G28`, `G29`, `G70`, `G88`

### Task 7 — ROUTE-007: Implement uncertainty, fallback, escalation, and degraded routing

**Anti-drift implementation goal**

Respond safely to unknowns and failures without silently relaxing constraints or changing meaning.

**Required implementation**

1. Define route outcomes/conditions for low confidence, invalid schema, model unavailable, solver unknown, source stale, state conflict, verifier uncertainty, approval needed, quota pressure, and physical local deny.
2. Allow only prevalidated fallback sub-routes/model sets/drivers/degraded modes with explicit capability/data/effect differences.
3. Escalate to human/governance or suspend/wait with durable state and deadline.
4. Record why fallback occurred and compare its behavior/quality/SLO through continuous eval.
5. Prevent fallback from broadening authority, remote data exposure, or physical effect class.

**Responsibility boundaries: this task must not drift into**

- Do not equate “primary failed” with permission to use any available model/tool.
- Do not make uncertainty an allow.
- Do not retry forever under quota or stale source.

**Required integration**

- Agent Instance health selects routes; Authority/Gate verifies; HIL/Incident receive escalations.

**Validation and definition of done**

- G27–G29, G48, and G73–G75 exercise unavailable/uncertain/offline paths and prove capability only narrows.

**Required contracts / collaborating tasks:** `ROUTE-001`, `AINST-007`, `AUTH-007`

**Gold evidence:** `G27`, `G28`, `G29`, `G48`, `G73`, `G74`, `G75`

### Task 8 — ROUTE-008: Implement user-space pure node and sub-route SDK

**Anti-drift implementation goal**

Keep application code expressive while ensuring it cannot become an implicit privileged kernel module.

**Required implementation**

1. Provide Rust/Python/TypeScript interfaces for pure/bounded computation nodes with declared input/output schemas, code/environment ref, resources, determinism, and optional stateful checkpoint profile.
2. Run untrusted nodes through Workload/Sandbox; trusted in-process callbacks remain a local development/compatibility mode with reduced isolation.
3. Expose only proposal/read handles, not stores/registries/secrets/gateway internals.
4. Support sub-route libraries/packages and parameter schemas without macro-expanding mutable code at runtime.
5. Generate local test harness with recorded inputs and no-live-effect driver profiles.

**Responsibility boundaries: this task must not drift into**

- Do not make every user function a driver.
- Do not allow pure nodes to open network/filesystem/device outside declared sandbox.
- Do not serialize arbitrary closures as route revisions.

**Required integration**

- Artifact Registry pins code/env; Workload Controller executes; Agent frameworks use SDK bridge.

**Validation and definition of done**

- G24 and G54 implement custom reasoning/NN nodes; malicious store/network access is denied.

**Required contracts / collaborating tasks:** `ROUTE-001`, `SBX-001`, `FND-010`

**Gold evidence:** `G24`, `G54`, `G80`

### Task 9 — ROUTE-009: Implement route validation, compilation, compatibility, and explain plans

**Anti-drift implementation goal**

Catch schema, cycle, authority, resource, and deployment errors before a live agent executes.

**Required implementation**

1. Resolve exact node implementations/bindings/schemas/profiles and compile a normalized route execution plan/digest.
2. Perform type/schema checks, boundedness analysis, effect-path coverage, verifier dominance, authority/data-flow checks, state/world ownership, fallback compatibility, and required terminal outcomes.
3. Identify every possible effectful path and prove it crosses Gateway; reject unknown dynamic operation names outside declared schemas.
4. Estimate resource/cost/latency envelopes and mark runtime-dependent bounds honestly.
5. Produce access-controlled graph/explanation with nodes, contracts, effects, constraints, and unresolved risks.

**Responsibility boundaries: this task must not drift into**

- Do not claim formal proof for properties checked heuristically.
- Do not execute user/plugin code during compilation.
- Do not allow a route with a hidden direct network/tool path in a framework host.

**Required integration**

- Agent Registry and Workload admission require compiled digest; Gate may require analyses by risk class.

**Validation and definition of done**

- G24, G27, G28, G73, and G80 include deliberately bypassing/unbounded/incompatible routes that fail compile.

**Required contracts / collaborating tasks:** `ROUTE-001`, `DRREG-003`, `AGREG-002`

**Gold evidence:** `G24`, `G27`, `G28`, `G73`, `G80`

### Task 10 — ROUTE-010: Implement route execution evidence, checkpoint, and replay comparison

**Anti-drift implementation goal**

Make neural-symbolic decisions inspectable without requiring private chain-of-thought or logging every payload.

**Required implementation**

1. Emit step started/completed/denied/failed events with node/ref, input/output digests, selected branch, budgets, model/solver/driver receipts, state/world heads, obligations, and causal parents.
2. Store large/sensitive reasoning artifacts under classification and allow user-space summaries/proofs where available.
3. Checkpoint execution at safe points with ready nodes, completed outputs, budgets, pending waits/approvals, and no reusable authority.
4. Replay pure/recorded/simulated steps and compare route revisions on matched inputs while trapping live effects.
5. Generate first-divergence and decision-path reports for eval/change review.

**Responsibility boundaries: this task must not drift into**

- Do not require hidden model chain-of-thought.
- Do not serialize live secret handles or provider sessions into route checkpoint.
- Do not replay effectful steps automatically.

**Required integration**

- Event/Evidence/Replay services store and compare; Eval Controller judges behavior.

**Validation and definition of done**

- G03, G24, G39, G45, and G46 verify evidence, checkpoint/resume, no-effect replay, and route diff.

**Required contracts / collaborating tasks:** `ROUTE-001`, `EVID-001`, `RPLY-004`

**Gold evidence:** `G03`, `G24`, `G39`, `G45`, `G46`

### Task 11 — ROUTE-011: Implement controlled route hot-swap and version rollout

**Anti-drift implementation goal**

Change routing/planning logic for running agents only through explicit change/deployment semantics.

**Required implementation**

1. Classify route changes by schema/effect/authority/state/budget impact and require compatible state migration or new instance epoch.
2. Support shadow comparison, canary instances, and safe-point epoch transition; bind each session to one route revision.
3. Prevent in-flight execution from mixing node implementations/revisions unless a declared migration protocol exists.
4. Retain source route and checkpoint for rollback; evaluate behavior/regressions before wider activation.
5. Allow R0 parameter/budget changes only within preapproved bounds and still record a new config/route epoch.

**Responsibility boundaries: this task must not drift into**

- Do not mutate a route graph object in place.
- Do not let an agent self-select a candidate route into production.
- Do not call a prompt/parameter change harmless without impact classification.

**Required integration**

- Change/Gate/Deployment authorize; Agent Instance applies transition; Eval supplies matched comparisons.

**Validation and definition of done**

- G45, G46, G70, G76, and G79 demonstrate controlled route evolution and rollback.

**Required contracts / collaborating tasks:** `ROUTE-009`, `CHG-001`, `DEP-003`

**Gold evidence:** `G45`, `G46`, `G70`, `G76`, `G79`

### Component completion gate

- Neural computation proposes; symbolic structure composes/constrains; boundary verification mediates effects; feedback/evaluation close later loops.
- Every effect path is statically or dynamically dominated by the Driver Gateway, and every loop/fan-out has explicit bounds.
- Routes are user-extensible typed control graphs, not a mandated agent architecture.

---

## Component 26 — World-State and Memory Service

**Canonical component ID:** `splendor.world-state-service`
**Plane:** `agent_cognition`
**Current status:** missing
**Owning package:** `crates/splendor-agent (world module); persistence interfaces in splendor-store`

**Implemented baseline to preserve**

The current `StateGraph` provides explicit versioned agent state and snapshots but not a domain-agnostic world model. There is no distinction among observations, facts, beliefs, hypotheses, predictions, goals, plans, simulations, memories, external truth claims, shared/private views, temporal validity, coordinate frames, or learned world-model artifacts.

**Exact kernel responsibility**

Own versioned world and memory partitions, typed claims and relations, temporal/provenance/confidence metadata, conflict-aware commits, views, and simulation branches. It stores and controls representations supplied by application code; it does not define the domain ontology, infer truth automatically, select a learned world model, or authorize actions.

**Public contracts:** `WorldPartition`, `WorldClaim`, `ClaimKind`, `EntityRef`, `RelationRef`, `TemporalExtent`, `UncertaintyRef`, `WorldCommit`, `WorldView`, `MemoryRecord`, `WorldBranch`

### Task 1 — WORLD-001: Define world partitions, claims, and truth-status taxonomy

**Anti-drift implementation goal**

Represent arbitrary environment models without forcing one ontology or confusing perception, prediction, and fact.

**Required implementation**

1. Define partition identity/schema/owner/visibility and claim identity with subject/predicate/object-or-payload schema, claim kind, provenance, observed/valid/recorded times, confidence/uncertainty ref, status, and causal parents.
2. Provide claim kinds observation-derived assertion, external assertion, verified fact-under-policy, belief, hypothesis, prediction, goal, plan, norm/constraint ref, and simulated/counterfactual state.
3. Keep domain payload and ontology references opaque/versioned while kernel owns identity/provenance/time/status fields.
4. Require explicit promotion/supersession/retraction relations; never mutate historical claim meaning in place.
5. Separate agent-local world, shared world, environment truth interface, and simulation branches.

**Responsibility boundaries: this task must not drift into**

- Do not call every stored statement a fact.
- Do not build a universal ontology into the kernel.
- Do not equate confidence with probability unless schema declares it.

**Required integration**

- Perceptors supply observations; Route/user-space assimilators propose claims; State/Artifact store payloads.

**Validation and definition of done**

- G23 and G25 create conflicting observations, beliefs, predictions, and simulated branches while preserving distinctions.

**Required contracts / collaborating tasks:** `FND-001`, `STA-001`, `PERC-001`

**Gold evidence:** `G23`, `G25`

### Task 2 — WORLD-002: Implement schema, entity, relation, time, and unit interoperability hooks

**Anti-drift implementation goal**

Allow robotics, software, language, scientific, financial, and custom worlds to share kernel lifecycle without a lowest-common-denominator JSON blob.

**Required implementation**

1. Define schema/ontology/unit/coordinate-frame refs and validation hooks executed by trusted schema plugins or user-space validators.
2. Support stable entity aliases/identity-resolution proposals while preserving source-local IDs and uncertainty.
3. Represent event, interval, valid-time, transaction-time, recurrence, and causal relation metadata.
4. Support values/media/tensors/graphs as artifact-backed typed payloads.
5. Provide converter declarations with input/output schemas, loss/uncertainty, code/environment, and lineage.

**Responsibility boundaries: this task must not drift into**

- Do not assume one clock, unit system, coordinate frame, or entity resolver.
- Do not merge entities because labels match.
- Do not let a converter silently drop uncertainty/provenance.

**Required integration**

- Driver/Data operators implement converters; World Service validates declared refs/commit; Physical routes require frames.

**Validation and definition of done**

- G21, G23, G25, and G73 validate multimodal payloads, temporal conflicts, units/frames, and conversion lineage.

**Required contracts / collaborating tasks:** `WORLD-001`, `DODRV-001`, `ART-001`

**Gold evidence:** `G21`, `G23`, `G25`, `G73`

### Task 3 — WORLD-003: Implement observation assimilation proposals and conflict-aware commits

**Anti-drift implementation goal**

Turn observations into world updates through explicit user-space logic and kernel-controlled versioning.

**Required implementation**

1. Define `WorldUpdateProposal` containing pinned base head, consumed observation/claim refs, additions/retractions/status changes, transform/assimilator artifact, and merge/conflict policy.
2. Validate schema, authority, provenance, protected fields, temporal constraints, and compare-and-set head before commit.
3. Detect contradictory claims, stale bases, duplicate observations, and entity/frame ambiguity; preserve alternatives or invoke application merge plugin rather than last-write-wins.
4. Allow independent partitions to commit concurrently and create atomic/recoverable multi-partition transaction only where explicitly required.
5. Emit commit receipt and lineage without automatically triggering actions.

**Responsibility boundaries: this task must not drift into**

- Do not let a perceptor or model write world truth directly.
- Do not discard conflicting evidence to keep one clean state.
- Do not retry an assimilator after conflict if it performed external effects.

**Required integration**

- Route invokes user assimilator; World Service commits; Event/Lineage record.

**Validation and definition of done**

- G23, G24, G25, and G29 inject stale/conflicting/multi-source updates and verify explicit resolution.

**Required contracts / collaborating tasks:** `WORLD-001`, `STA-003`, `LIN-002`, `FND-007`

**Gold evidence:** `G23`, `G24`, `G25`, `G29`

### Task 4 — WORLD-004: Implement uncertainty and belief representation interfaces

**Anti-drift implementation goal**

Let agents model incomplete and probabilistic worlds without imposing one Bayesian, fuzzy, neural, or symbolic formalism.

**Required implementation**

1. Allow a claim to reference an uncertainty artifact/schema and expose bounded common summaries such as confidence interval, probability mass, confidence score, set/range, or unknown.
2. Define user-space belief update/fusion plugin contract with exact inputs, method/version, assumptions, and output proposal.
3. Support multiple competing belief models/views over the same observations.
4. Record calibration/eval evidence for uncertainty providers separately from claim values.
5. Allow route/gate predicates to require named uncertainty conditions through schema-specific verifier plugins.

**Responsibility boundaries: this task must not drift into**

- Do not normalize every confidence to [0,1] and call it probability.
- Do not let a belief updater hide consumed observations.
- Do not treat high confidence as authority or safety proof.

**Required integration**

- Model/Symbolic drivers may implement estimators; Eval Controller calibrates; Route/Gate consume typed predicates.

**Validation and definition of done**

- G23, G25, G42, and G57 validate competing uncertainty schemes and calibration evidence.

**Required contracts / collaborating tasks:** `WORLD-001`, `EVDRV-005`

**Gold evidence:** `G23`, `G25`, `G42`, `G57`

### Task 5 — WORLD-005: Implement explicit memory partition profiles and retention

**Anti-drift implementation goal**

Support episodic, semantic, procedural, working, social, skill, and domain memory as governed representations rather than hidden framework stores.

**Required implementation**

1. Define memory partition profiles as schemas/retention/index/query/access policies over State/World/Artifact records; profiles remain extensible.
2. Represent memory entries with source/provenance, time, owner/visibility, importance/quality metadata, supersession, and data-use obligations.
3. Provide read/query operation contracts and write proposals; vector/graph/search indexes are derived artifacts with rebuild lineage, never canonical truth.
4. Support summarization/consolidation/forgetting as user-space data workloads producing new immutable snapshots and explicit drop/supersession findings.
5. Enforce deletion/consent/privacy across derived memories and indexes.

**Responsibility boundaries: this task must not drift into**

- Do not make vector search the definition of memory.
- Do not let an index become the only copy of canonical records.
- Do not allow “forgetting” to erase audit evidence or ignore legal/data obligations.

**Required integration**

- Data Operator builds indexes/summaries; Data-Use/Collection controls retention; Route selects context.

**Validation and definition of done**

- G23, G26, G35, and G38 validate episodic/semantic/index rebuild, forgetting, deletion, and long-running compaction.

**Required contracts / collaborating tasks:** `WORLD-001`, `DUC-004`, `DODRV-008`

**Gold evidence:** `G23`, `G26`, `G35`, `G38`

### Task 6 — WORLD-006: Represent learned world models as versioned model bindings

**Anti-drift implementation goal**

Make learned dynamics/perception models usable without turning their predictions into authoritative world state.

**Required implementation**

1. Define a `WorldModelBinding` from partition/schema and model operation to required context, prediction/horizon/latent schema, uncertainty/calibration refs, and supported simulation profile.
2. Invoke learned world models through Model Driver; store predictions/latents/rollouts as prediction/simulation claims or artifacts.
3. Version training data, model, route, calibration, and deployment separately and support multiple competing world models.
4. Require application assimilator/verifier policy to promote observed-confirmed knowledge; predictions expire/supersede explicitly.
5. Track online prediction-versus-observation residuals for evaluation/data collection.

**Responsibility boundaries: this task must not drift into**

- Do not let a world model commit its predictions as facts.
- Do not hide latent state in a process without checkpoint/ownership declaration.
- Do not equate low training loss with calibrated dynamics.

**Required integration**

- Model Driver executes; Eval/Feedback/Collection close loop; AgentSpec binds exact model.

**Validation and definition of done**

- G57 and G59 train, calibrate, deploy, monitor, and roll back a learned world model while maintaining prediction/fact separation.

**Required contracts / collaborating tasks:** `WORLD-001`, `MODEL-001`, `EVAL-006`

**Gold evidence:** `G57`, `G59`

### Task 7 — WORLD-007: Implement simulation, counterfactual, and rollout branches

**Anti-drift implementation goal**

Support planning, RL, testing, and physical rehearsal without contaminating live state.

**Required implementation**

1. Fork a `WorldBranch` from a pinned live/snapshot head with simulator/world-model/environment refs, interventions, horizon, seed, resource budget, and owner.
2. Commit branch-local claims/transitions/actions/outcomes only to branch heads; effectful operations use simulated/recorded drivers.
3. Store trajectory/rollout artifacts and compare branches by application-defined metrics/evaluators.
4. Permit validated knowledge proposals back to live world only through explicit evidence/gate/assimilation; never copy branch wholesale.
5. Support distributed independent rollouts and deterministic aggregation by rollout identity.

**Responsibility boundaries: this task must not drift into**

- Do not let branch actions reach live actuators.
- Do not use a branch state head as live deployment state.
- Do not present simulated outcomes as observations.

**Required integration**

- Replay/Simulation and Workload/Fleet execute; Eval judges; Route/planners consume.

**Validation and definition of done**

- G25, G57–G59, and G73 validate counterfactual planning, RL/world-model rollouts, and physical simulation isolation.

**Required contracts / collaborating tasks:** `WORLD-001`, `RPLY-005`, `WORK-003`

**Gold evidence:** `G25`, `G57`, `G58`, `G59`, `G73`

### Task 8 — WORLD-008: Implement multi-agent shared/private views and consistency

**Anti-drift implementation goal**

Support collaboration and partial knowledge without a globally mutable shared memory blob.

**Required implementation**

1. Define private, team/shared, environment, supervisor, protected evaluator, and public views with field/claim filters and write authority.
2. Provide snapshot/read leases and proposal/merge protocols for shared partitions; use single-writer, optimistic, CRDT/application merge, or consensus-backed provider as declared profile.
3. Represent agent messages/assertions as claims with source authority/reliability, not direct shared-state mutation.
4. Support redacted/projection views that preserve causal hashes and prevent inference of protected content where required.
5. Detect concurrent conflicts and partition/reconnect divergence explicitly.

**Responsibility boundaries: this task must not drift into**

- Do not assume arbitrary shared mutable state or consensus is free.
- Do not let a message grant write authority.
- Do not expose private/protected world claims through aggregate queries without policy.

**Required integration**

- Message/Authority governs sharing; State Service provides storage profiles; Agent Instance pins views.

**Validation and definition of done**

- G70, G72, G77, and G81 test team views, offline divergence, adversarial messages, and merge policies.

**Required contracts / collaborating tasks:** `WORLD-001`, `MSG-001`, `AUTH-005`, `STA-004`

**Gold evidence:** `G70`, `G72`, `G77`, `G81`

### Task 9 — WORLD-009: Implement physical-world frames, local safety state, and latency classes

**Anti-drift implementation goal**

Model physical context needed for high-level AI actions while leaving hard real-time control and safety ownership local.

**Required implementation**

1. Represent coordinate/frame/map/zone/calibration refs, validity windows, covariance/uncertainty schemas, and transform provenance.
2. Define safety-local partitions for battery, emergency stop, collision risk, actuator state, geofence/privacy zone, and freshness indicators with device-local write/read policy.
3. Classify facts by latency/freshness requirement and prevent cloud-stale views from satisfying local physical preconditions.
4. Expose only bounded trace-safe summaries to cloud/control plane where raw sensor/state is restricted.
5. Support simulation frames separately and require explicit sim-to-real mapping/evidence.

**Responsibility boundaries: this task must not drift into**

- Do not make cloud state authoritative for local emergency/safety conditions.
- Do not mix coordinate frames without validated transforms.
- Do not claim motor/firmware safety certification.

**Required integration**

- Perceptor/Actuator/Node local verifier consume; Route/Planner use views; Data-Use controls export.

**Validation and definition of done**

- G73–G75 test frame mismatch, stale cloud view, local safety, privacy zone, and offline operation.

**Required contracts / collaborating tasks:** `WORLD-002`, `NODE-007`, `ACT-006`

**Gold evidence:** `G73`, `G74`, `G75`

### Task 10 — WORLD-010: Implement retention, deletion, privacy, and knowledge invalidation

**Anti-drift implementation goal**

Allow long-lived agents to forget or invalidate governed world/memory content without rewriting history deceptively.

**Required implementation**

1. Apply data-use retention/deletion obligations to claim payloads, derived indexes/summaries, model-training lineage, and exported views.
2. Use retraction/tombstone/inaccessible placeholders to preserve causal structure and explain degraded reproducibility.
3. Implement source revocation and invalidation propagation to claims/views/predictions/decisions as impact facts, not automatic overbroad deletion.
4. Support privacy-preserving redacted views and restricted audit access.
5. Trigger reevaluation/incident/change review when invalidated knowledge materially affected deployed behavior.

**Responsibility boundaries: this task must not drift into**

- Do not assume hashes/embeddings are non-sensitive.
- Do not silently keep deleted payloads in vector indexes or checkpoints.
- Do not erase evidence of why an action was taken while pretending full payload remains available.

**Required integration**

- Data-Use, Lineage, Incident, Eval, and Change controllers consume impact.

**Validation and definition of done**

- G26, G35, G43, and G83 validate consent deletion, derived invalidation, protected data, and compromised source impact.

**Required contracts / collaborating tasks:** `WORLD-005`, `DUC-004`, `LIN-003`

**Gold evidence:** `G26`, `G35`, `G43`, `G83`

### Task 11 — WORLD-011: Implement world-schema/model change and rollout controls

**Anti-drift implementation goal**

Evolve ontologies, assimilators, memories, and learned world models without corrupting live agent state.

**Required implementation**

1. Represent schema/ontology/converter/assimilator/world-model changes as ChangeSets with impact on partitions, routes, agents, evals, and rollback.
2. Run offline migration to new immutable partition snapshots; validate counts/invariants/provenance and preserve old heads.
3. Shadow new assimilator/world model on duplicated observations without influencing live state/actions.
4. Canary selected agent instances/partitions with comparison and safety gates; support rollback to old heads/model.
5. Require independent eval for calibration, prediction, rare-tail, safety, and downstream action regression.

**Responsibility boundaries: this task must not drift into**

- Do not migrate a live partition in place without versioned snapshot.
- Do not let world-model self-score approve its own rollout.
- Do not remove old schema/model before rollback window.

**Required integration**

- Change/Gate/Deployment coordinate; Agent Instance/Route select version by epoch; Eval measures.

**Validation and definition of done**

- G45, G46, G57, G59, and G70 prove shadow/canary/rollback and downstream behavior comparison.

**Required contracts / collaborating tasks:** `WORLD-001`, `CHG-001`, `DEP-003`

**Gold evidence:** `G45`, `G46`, `G57`, `G59`, `G70`

### Task 12 — WORLD-012: Build domain-diverse world-model gold examples

**Anti-drift implementation goal**

Prove the abstraction supports software, language/task, physical, multi-agent, and learned dynamics worlds without kernel changes.

**Required implementation**

1. Implement a file/code repository world with observed files/tests/build state and uncertain external changes.
2. Implement a toy grid/robot world with frames, sensor uncertainty, local safety, planner, simulator, and learned transition model.
3. Implement a conversational/task world with entities, commitments, temporal facts, private/shared views, and memory retention.
4. Implement a custom tensor/scientific state model using artifact-backed arrays and application-defined uncertainty.
5. Run conflict, simulation, model update, deletion, multi-agent sharing, and rollback scenarios for each.

**Responsibility boundaries: this task must not drift into**

- Do not optimize the core solely for one example.
- Do not claim physical-world generality from a gridworld alone.
- Do not call generated scenarios proof of real-world value alignment.

**Required integration**

- Gold catalog uses common world contracts and different user-space schemas/plugins.

**Validation and definition of done**

- G23–G25, G57, G59, G73, and G77 pass with no domain code in core crates.

**Required contracts / collaborating tasks:** `WORLD-001`, `WORLD-011`, `FND-005`

**Gold evidence:** `G23`, `G24`, `G25`, `G57`, `G59`, `G73`, `G77`

### Component completion gate

- World storage distinguishes observation, assertion, fact-under-policy, belief, hypothesis, prediction, goal, and simulation.
- Ontology, uncertainty, fusion, planning, and learned world models remain replaceable user-space artifacts.
- Live, shared, protected, offline, and simulated partitions have explicit ownership, consistency, freshness, and data controls.

---

## Component 27 — Message and Delegation Service

**Canonical component ID:** `splendor.message-delegation-service`
**Plane:** `agent_cognition`
**Current status:** partial foundation
**Owning package:** `crates/splendor-agent (message/delegation module), extending current splendor-kernel message_router/local_delegation/remote_transport`

**Implemented baseline to preserve**

Baseline review identified typed local messages, inbox/outbox lifecycle, recipient/schema isolation, local delegation, parent/child runs, remote message envelopes/transport reference path, causal replay, and task request/response types as compatibility anchors to preserve. Missing are durable fleet-grade delivery, ordering/dedup/backpressure, capability token attenuation/revocation across transports, trigger subscriptions, long-running request workflows, group/broadcast patterns, protected payload refs, and adversarial hardening.

**Exact kernel responsibility**

Own typed agent/service communication lifecycle and scoped authority delegation. It stores envelopes/cursors/delivery state, enforces sender/recipient/schema/data scope, and issues attenuated delegation references. It never treats message content as authority, shared state, verified truth, or successful work by itself.

**Public contracts:** `MessageV2`, `MessageEnvelopeV2`, `ConversationRef`, `MailboxPolicy`, `DeliveryReceipt`, `DelegationGrant`, `DelegationChain`, `TaskContract`, `Subscription`

### Task 1 — MSG-001: Evolve the stable message envelope while preserving 0.1 semantics

**Anti-drift implementation goal**

Add payload/artifact, versioning, classification, conversation, expiry, and delivery semantics without breaking current typed messages.

**Required implementation**

1. Retain distinct message/source/target/run identities and add tenant/fleet/instance scope, schema version, bounded inline payload or artifact ref, classification, created/expiry time, causal parents, conversation/request refs, priority, and delivery policy.
2. Keep payload non-authorizing and validate sender/recipient/schema allowlists at send and delivery.
3. Define message kinds event, command proposal, task request/response, observation, feedback notification, approval notification, heartbeat/status, and custom schema without assigning authority from kind alone.
4. Provide deterministic conversion from current `Message`/envelopes and preserve causal replay.
5. Separate message identity from transport attempt/delivery receipt.

**Responsibility boundaries: this task must not drift into**

- Do not make a message field named capability/approved authoritative.
- Do not embed large/private payloads in mailbox metadata.
- Do not change stable 0.1 payload meaning in place.

**Required integration**

- Artifact/Data-Use handles protected payloads; Event Log records lifecycle; current router becomes local backend.

**Validation and definition of done**

- G18, G19, G70, and G81 round-trip old/new messages and reject forged scope.

**Required contracts / collaborating tasks:** `FND-001`, `FND-006`, `ART-001`

**Gold evidence:** `G18`, `G19`, `G70`, `G81`

### Task 2 — MSG-002: Implement durable delivery, deduplication, ordering, acknowledgements, and retries

**Anti-drift implementation goal**

Provide clear delivery guarantees across local and remote agents without pretending global exactly-once.

**Required implementation**

1. Use outbox/inbox records and transport attempts with idempotent message ID; persist accepted, queued, sent, delivered, acknowledged, expired, rejected, dead-lettered, and cancelled states.
2. Guarantee at-least-once or at-most-once according to schema/policy; offer effect-safe exactly-once processing only through recipient state/idempotency transaction where supported.
3. Provide ordering by explicit conversation/partition sequence, not global timestamp; detect gaps/duplicates.
4. Retry only delivery, not recipient effects, with bounded backoff/expiry and transport failure classification.
5. Reconcile after process/node/network failures and preserve one accepted recipient processing receipt.

**Responsibility boundaries: this task must not drift into**

- Do not claim exactly-once globally.
- Do not order unrelated messages by wall clock.
- Do not let transport redelivery rerun an effectful task without recipient idempotency.

**Required integration**

- State/Event stores persist; remote transport carries; Agent Instance commits cursor/processing receipt.

**Validation and definition of done**

- G18, G19, G70, G72, and G81 inject duplicates, reordering, partitions, expiry, and recipient restart.

**Required contracts / collaborating tasks:** `MSG-001`, `FND-003`, `STA-006`

**Gold evidence:** `G18`, `G19`, `G70`, `G72`, `G81`

### Task 3 — MSG-003: Implement attenuated delegation grants and chains

**Anti-drift implementation goal**

Delegate bounded work authority independently from message content and parent permissions.

**Required implementation**

1. Define a signed/reference delegation grant with issuer/delegate, parent grant/work order, allowed operations/targets/data refs, quotas/resources, purpose, run/task scope, not-before/expiry, depth, re-delegation policy, revocation, and audit refs.
2. Validate monotonic attenuation at every chain link; no child can broaden parent authority or lifetime.
3. Bind grant to child instance/task/workload and require it at privileged planning/invocation, not merely at message receipt.
4. Implement revocation propagation and short-lived/offline behavior with fail-closed high-risk semantics.
5. Expose an explanation of effective authority without revealing unrelated parent grants.

**Responsibility boundaries: this task must not drift into**

- Do not serialize ambient parent credentials to a child.
- Do not interpret a task request message as delegation.
- Do not allow a child to mint sibling/parent authority.

**Required integration**

- Authority Service owns validation; Agent Instance requests grants; Gateway/Workload enforce.

**Validation and definition of done**

- G18, G70, G77, G78, and G81 attempt broadening, expiry reuse, and forged delegation; all deny.

**Required contracts / collaborating tasks:** `AUTH-005`, `MSG-001`

**Gold evidence:** `G18`, `G70`, `G77`, `G78`, `G81`

### Task 4 — MSG-004: Implement task request/response and long-running conversation contracts

**Anti-drift implementation goal**

Coordinate sub-agents/services with explicit objectives, schemas, lifecycle, and cancellation instead of free-form text alone.

**Required implementation**

1. Define task contract with objective/input refs, expected result schema, delegated grant ref, resource/time budget, progress schema, acceptance criteria ref, parent causal context, and cancellation policy.
2. Support accepted/rejected/progress/waiting/completed/failed/cancelled responses and separate provider/agent output from parent acceptance.
3. Allow multi-turn conversation under bounded request/conversation identity and token/message/time budgets.
4. Bind child result artifacts/evidence to task and prevent response from directly committing parent state/action.
5. Support timeout, cancellation, reassignment, and duplicate response handling.

**Responsibility boundaries: this task must not drift into**

- Do not use natural-language objective as the only result schema or authority.
- Do not mark parent task successful solely from child “done”.
- Do not allow unbounded conversational ping-pong.

**Required integration**

- Agent Instance/Actuator nodes realize tasks; Route validates/accepts results; Workload tracks child.

**Validation and definition of done**

- G18, G70, and G77 test specialist tasks, progress, failure, reassignment, and independent validation.

**Required contracts / collaborating tasks:** `MSG-003`, `AINST-006`, `WORK-003`

**Gold evidence:** `G18`, `G70`, `G77`

### Task 5 — MSG-005: Harden remote transport, routing, identity, and offline queues

**Anti-drift implementation goal**

Carry messages across fleet/network boundaries without changing identity or authority semantics.

**Required implementation**

1. Implement mutually authenticated transport endpoints bound to node/instance/fleet identity with schema/version negotiation, replay protection, payload limits, and route discovery.
2. Route by logical recipient and current instance location; preserve message identity/causality through forwarding and state handoff.
3. Support local durable queues and offline buffering with expiry/storage limits; reconcile after reconnect and avoid duplicate delivery.
4. Encrypt/classify payload refs and prevent transport metadata from widening visibility.
5. Quarantine unknown sender/schema/signature or conflicting recipient ownership.

**Responsibility boundaries: this task must not drift into**

- Do not make transport signature a delegation grant.
- Do not expose unauthenticated remote message endpoints.
- Do not deliver expired commands after a device reconnects.

**Required integration**

- Build on current RemoteMessageEnvelope/transport, node registry, state handoff, and trace sync.

**Validation and definition of done**

- G70, G72, G75, and G81 test two-node, migration, offline, replay, and hostile transport.

**Required contracts / collaborating tasks:** `MSG-002`, `NODE-001`, `STA-007`

**Gold evidence:** `G70`, `G72`, `G75`, `G81`

### Task 6 — MSG-006: Implement event subscriptions and trigger-agent routing

**Anti-drift implementation goal**

Use messages/events as durable triggers without turning every notification into an unbounded new agent run.

**Required implementation**

1. Define subscriptions by schema/source/target/scope/filter, cursor, delivery policy, debounce/coalesce/window, priority, max concurrency, and expiry.
2. Validate filter expressions through a bounded declarative language or trusted plugin; never run arbitrary code in router.
3. Deliver trigger envelope to Agent Instance, which creates a governed session/workload under current authority.
4. Support one-shot, persistent, scheduled, and condition-triggered specialist agents with dedup identities.
5. Record dropped/coalesced/gap events and expose lag/backpressure.

**Responsibility boundaries: this task must not drift into**

- Do not let a trigger subscription carry perpetual action authority.
- Do not spawn one child per high-rate event without limits.
- Do not hide dropped events.

**Required integration**

- Event Log/Perceptor feed subscriptions; Agent Instance/Workload enforce concurrency.

**Validation and definition of done**

- G19, G22, G29, G38, and G49 validate trigger dedup, storm handling, and restart cursors.

**Required contracts / collaborating tasks:** `MSG-001`, `AINST-003`, `WORK-007`

**Gold evidence:** `G19`, `G22`, `G29`, `G38`, `G49`

### Task 7 — MSG-007: Implement mailbox quotas, priorities, backpressure, and dead letters

**Anti-drift implementation goal**

Protect agents and control plane from message storms, oversized payloads, and stuck recipients.

**Required implementation**

1. Define per-agent/schema/source quotas for messages, bytes, rate, age, conversation, and priority class.
2. Use bounded queues and explicit reject/drop-oldest/drop-newest/coalesce/spill-to-artifact/dead-letter policies by schema/risk.
3. Reserve capacity for governance, kill-switch, safety, lease, and cancellation control messages separate from bulk agent chatter.
4. Expose lag, gaps, dead letters, repeated rejection, and sender abuse to health/incident systems.
5. Require authorized requeue with original message identity and new delivery attempt.

**Responsibility boundaries: this task must not drift into**

- Do not let bulk training feedback starve emergency control.
- Do not silently discard messages.
- Do not permit sender-declared priority outside authority.

**Required integration**

- Authority quotas and Agent Instance health consume; Observability exports; Incident rate-limits/quarantines abuse.

**Validation and definition of done**

- G22, G68, G81, and G88 saturate mailboxes and assert bounded memory/control priority/evidence.

**Required contracts / collaborating tasks:** `MSG-002`, `AUTH-004`, `OBS-005`

**Gold evidence:** `G22`, `G68`, `G81`, `G88`

### Task 8 — MSG-008: Implement causal trace, replay, and state-transition integration

**Anti-drift implementation goal**

Explain multi-agent behavior without re-executing messages or side effects.

**Required implementation**

1. Link send/delivery/ack/processing/task/response events to message/conversation/delegation/parent route/session/state commit identities.
2. Record recipient processing result and state head transactionally where exactly-once-processing profile is used.
3. Reconstruct causal graph across remote hops, child runs, approvals, denials, migrations, and offline intervals.
4. Replay inspect-only by default; simulated delivery uses isolated mailboxes/instances and new authority.
5. Generate first-divergence reports for multi-agent revision comparisons.

**Responsibility boundaries: this task must not drift into**

- Do not redeliver historical messages to live recipients during replay.
- Do not infer permission inheritance from causal parent.
- Do not omit denied/expired/dead-letter messages from causal explanation.

**Required integration**

- Event/Evidence/Replay/State services consume current causal foundations.

**Validation and definition of done**

- G03, G18, G70, and G72 reconstruct without live effects and detect injected divergence.

**Required contracts / collaborating tasks:** `MSG-001`, `RPLY-004`, `EVID-002`

**Gold evidence:** `G03`, `G18`, `G70`, `G72`

### Task 9 — MSG-009: Implement external agent/framework bridges with reduced guarantees

**Anti-drift implementation goal**

Communicate with non-Splendor agents and services while preserving clear trust and authority boundaries.

**Required implementation**

1. Define bridge adapters for webhook/queue/agent protocol/custom transports that map external identities/schemas into Splendor messages.
2. Authenticate external principals where possible and classify unauthenticated/externally attested sources explicitly.
3. Never transfer a Splendor delegation grant through a bridge unless the remote boundary supports the exact signed/verified contract.
4. Validate/transform payloads through versioned schemas and attach bridge/transport provenance.
5. Expose observed/unmanaged guarantees and require re-verification before external responses cause effects/state changes.

**Responsibility boundaries: this task must not drift into**

- Do not trust external “role”/“approved” fields.
- Do not assume another agent framework enforces Splendor capabilities.
- Do not hide bridge transformation or lost fields.

**Required integration**

- Driver Gateway hosts bridge; Agent Registry frameworks use; Route treats outputs as observations/proposals.

**Validation and definition of done**

- G06, G18, G70, and G81 run trusted and hostile external bridge fixtures.

**Required contracts / collaborating tasks:** `MSG-001`, `DGW-006`, `WORK-008`

**Gold evidence:** `G06`, `G18`, `G70`, `G81`

### Task 10 — MSG-010: Build message/delegation adversarial and conformance suite

**Anti-drift implementation goal**

Prove schema, routing, delivery, authority attenuation, and backpressure under hostile peers and networks.

**Required implementation**

1. Inject spoofed sender/recipient, schema confusion, oversized/zip-bomb artifact, replayed delivery, sequence gap, expiry, duplicate task, grant broadening, cycle, trigger storm, response forgery, and transport partition.
2. Verify no unauthorized payload read, grant use, state commit, or action invocation occurs.
3. Test local/remote/offline/migration paths and current 0.1 compatibility fixtures.
4. Publish conformance for transports/bridges and retain security incidents separately.
5. Measure queue/recovery throughput at 1,000-device mixed load.

**Responsibility boundaries: this task must not drift into**

- Do not test only cooperative agents.
- Do not mark delivery pass if recipient bypassed schema/authority.
- Do not suppress dead letters or denial evidence.

**Required integration**

- Driver Registry/Incident/Gold runner consume; CI retains current multi-agent replay tests.

**Validation and definition of done**

- G18, G19, G70, G72, G77, G81, and G88 pass the full matrix.

**Required contracts / collaborating tasks:** `MSG-001`, `MSG-007`, `FND-005`

**Gold evidence:** `G18`, `G19`, `G70`, `G72`, `G77`, `G81`, `G88`

### Component completion gate

- Messages carry typed information and causal links, never implicit truth, shared-state mutation, or authority.
- Delegation is a separate signed/validated attenuated grant bound to task/instance/workload.
- Local, remote, offline, bridge, and replay paths preserve identity, bounds, and evidence.

---

## Component 28 — Collection Controller

**Canonical component ID:** `splendor.collection-controller`
**Plane:** `data_learning`
**Current status:** missing
**Owning package:** `crates/splendor-learning (collection module)`

**Implemented baseline to preserve**

Percepts, action outcomes, traces, messages, local device buffers, and data refs exist, but there is no first-class controller that authorizes and manages ongoing collection plans, source cursors, sampling/coverage, data minimization, recordization, quality entry checks, quarantine, device sync, budgets, or immutable dataset snapshot publication.

**Exact kernel responsibility**

Own desired/observed lifecycle for governed data acquisition and recordization: why to collect, from which sources, under which purpose/consent/locality, how to sample/minimize, where cursors live, what entry quality/quarantine policy applies, and when to publish a snapshot. It does not implement source connectors/transforms, label truth, training, or evaluation.

**Public contracts:** `CollectionPlan`, `CollectionSource`, `CollectionCursor`, `SamplingPolicy`, `CoverageTarget`, `RecordizationSpec`, `CollectionBatch`, `CollectionFinding`, `CollectionSnapshotProposal`

### Task 1 — COLL-001: Define CollectionPlan and lifecycle state machine

**Anti-drift implementation goal**

Make ongoing data acquisition a governed kernel object rather than incidental logging or ad hoc scripts.

**Required implementation**

1. Define collection identity, owner/principal, purpose, target data product/schema, sources, source capabilities/data-use refs, filters/minimization, sampling/coverage, recordization, quality entry checks, quarantine, retention, locality, budget, schedule/trigger, output snapshot cadence, and review policy.
2. Implement draft, validating, approved, active, paused, draining, completed, denied, expired, revoked, failed, and quarantined states with immutable plan revisions.
3. Separate plan, source subscription/extraction workload, batch, record, snapshot, and dataset identities.
4. Bind exact perceptor/data-operator drivers, schemas, code/environment, and destination classification.
5. Persist desired/observed cursors, volume, coverage, findings, and obligations without embedding raw records.

**Responsibility boundaries: this task must not drift into**

- Do not make tracing every agent interaction equivalent to approved training collection.
- Do not allow a broad purpose such as “improve AI” without concrete allowed uses/retention.
- Do not let a collection plan declare labels or quality valid by itself.

**Required integration**

- Data-Use/Authority approve; Perceptor/Data Operator execute; Workload schedules; Artifact/Lineage publish outputs.

**Validation and definition of done**

- G30 and G38 exercise all lifecycle transitions, schedule/restart, and purpose expiry.
- A live agent run with no collection plan produces operational evidence but no trainable dataset record.

**Required contracts / collaborating tasks:** `FND-001`, `DUC-001`, `WORK-007`

**Gold evidence:** `G30`, `G38`

### Task 2 — COLL-002: Implement source admission, subscriptions, extraction, and cursor ownership

**Anti-drift implementation goal**

Read each source under explicit authority with durable progress and honest source consistency.

**Required implementation**

1. Validate source identity/schema/classification, principal capability, purpose/data-use grant, consent/licence, locality, expected consistency/cursor, rate limits, and driver maturity.
2. Create per-source subscription or extraction workloads through Perceptor/Data Operator drivers and bind cursor ownership to the collection plan revision.
3. Persist accepted/committed source cursor only after record batch/output durability according to source semantics.
4. Handle backfill, incremental updates/deletes, source reset, replay windows, and unavailable source with explicit findings.
5. Prevent one source’s cursor or credentials from being reused by another plan/purpose.

**Responsibility boundaries: this task must not drift into**

- Do not read first and seek permission later.
- Do not call a wall-clock timestamp a reliable cursor.
- Do not advance cursor on partial failed batch unless source/plan semantics say so explicitly.

**Required integration**

- Perceptor pull/push or Data connector supplies batches; Node enforces locality; State stores cursors.

**Validation and definition of done**

- G30, G35, and G38 inject cursor duplicates/gaps/reset, deletion, source outage, and restart.

**Required contracts / collaborating tasks:** `COLL-001`, `PERC-002`, `DODRV-002`, `STA-006`

**Gold evidence:** `G30`, `G35`, `G38`

### Task 3 — COLL-003: Implement sampling, coverage, diversity, and active-acquisition policy

**Anti-drift implementation goal**

Collect informative and representative data under budget without hard-coding a domain selection algorithm.

**Required implementation**

1. Define sampling policies uniform, stratified, temporal, source-weighted, uncertainty/error-driven, novelty/diversity, rare-tail preservation, event-triggered, and custom plugin.
2. Represent coverage targets and observed coverage by application-defined slices with minimums/maximums and uncertainty.
3. Allow user-space active-learning/acquisition plugins to propose record/source/query selection from bounded summaries; kernel validates purpose, budget, bias constraints, and source capability.
4. Track inclusion probability/selection rationale where feasible so downstream evaluation/training can account for sampling bias.
5. Use exploration budgets and holdout/random sampling to detect exploitation blindness.

**Responsibility boundaries: this task must not drift into**

- Do not let a model collect only examples that maximize its own reward.
- Do not define diversity as one embedding distance universally.
- Do not sacrifice protected/rare groups to optimize aggregate volume.

**Required integration**

- World/Feedback/Eval signals may trigger proposals; Data Operator applies sampling; Gate may enforce coverage minima.

**Validation and definition of done**

- G32, G37, G38, and G48 compare random/active/rare-tail policies and detect selection bias/reward exploitation.

**Required contracts / collaborating tasks:** `COLL-001`, `DODRV-007`, `FDBK-004`

**Gold evidence:** `G32`, `G37`, `G38`, `G48`

### Task 4 — COLL-004: Implement recordization of observations, actions, outcomes, traces, feedback, and trajectories

**Anti-drift implementation goal**

Convert runtime experience into explicit data records without conflating operational evidence and learning data.

**Required implementation**

1. Define recordization specs mapping source events/artifacts/state/world/route/action/outcome/feedback windows into named record schemas through versioned user-space transforms.
2. Pin causal range, time window, state/world heads, model/route/policy revisions, action/effect outcome, and source payload refs.
3. Support supervised examples, preference pairs, trajectories, transitions, episodes, tool/action traces, code patches/tests, physical sensor-action sequences, and custom records.
4. Apply minimization/redaction before publication and preserve raw restricted refs only where policy permits.
5. Deduplicate by source/causal identity and record transform lineage; late feedback may create a new revision/linked record rather than mutate old bytes.

**Responsibility boundaries: this task must not drift into**

- Do not train directly from mutable trace queries.
- Do not store hidden chain-of-thought as required learning data.
- Do not interpret an action executed as an action desirable.

**Required integration**

- Event/State/World/Feedback provide refs; Data Operator transforms; Artifact/Lineage publish.

**Validation and definition of done**

- G30, G37, G47, G56, and G58 produce language, coding, RL, world-model, and physical trajectory records with exact causal lineage.

**Required contracts / collaborating tasks:** `COLL-002`, `FDBK-001`, `LIN-002`

**Gold evidence:** `G30`, `G37`, `G47`, `G56`, `G58`

### Task 5 — COLL-005: Implement collection entry validation, quarantine, and poisoning defenses

**Anti-drift implementation goal**

Stop corrupt, unauthorized, malformed, or suspicious data from silently entering candidate datasets.

**Required implementation**

1. Run configured schema/integrity/source/authenticity/privacy/malware/content/quality/duplication checks on each batch or shard before normal availability.
2. Route failed/suspicious records to classified quarantine with reason, source, detector evidence, and review/retention policy.
3. Detect abnormal source volume/distribution/label/reward shifts, repeated model-generated patterns, canary leakage, and hostile payloads; escalate rather than auto-delete.
4. Require independent verification for data generated by or directly benefiting the candidate agent where risk policy applies.
5. Permit explicit reviewed release or corrected derived snapshot; never rewrite original quarantined data.

**Responsibility boundaries: this task must not drift into**

- Do not use one generic “quality score” to admit data.
- Do not let a source/model mark its own records trusted.
- Do not discard poisoning evidence automatically.

**Required integration**

- Data Operator performs checks; Incident handles attacks; Data-Use controls quarantine access.

**Validation and definition of done**

- G31, G32, G36, G48, G84, and G85 inject corrupt, poison, recursive synthetic, reward, and lineage attacks.

**Required contracts / collaborating tasks:** `COLL-004`, `DODRV-003`, `INC-002`

**Gold evidence:** `G31`, `G32`, `G36`, `G48`, `G84`, `G85`

### Task 6 — COLL-006: Implement privacy, consent, retention, deletion, and minimization operations

**Anti-drift implementation goal**

Make ongoing collection responsive to human/source rights and legal/data policies throughout its derived lineage.

**Required implementation**

1. Track consent/licence/purpose/retention/region/subject/source obligations at record or group/shard granularity as appropriate.
2. Apply field/media redaction, pseudonymization, aggregation, on-device feature extraction, and sampling minimization through versioned operators.
3. Implement revocation/deletion intake that pauses affected source collection, tombstones payload access, computes derived impact, and schedules rebuild/retraining/eval decisions.
4. Keep non-sensitive audit facts and explain unavailable evidence while respecting deletion/legal hold conflicts through governance workflow.
5. Prevent snapshots/checkpoints/caches/indexes from evading obligations.

**Responsibility boundaries: this task must not drift into**

- Do not assume de-identification is universal or irreversible.
- Do not keep raw data because a derived embedding exists.
- Do not silently remove training records without impact/evidence and model response policy.

**Required integration**

- Data-Use/Lineage/Artifact/World/Training/Incident coordinate impact; Node clears local caches.

**Validation and definition of done**

- G26, G34, G35, and G83 validate minimization, use separation, deletion propagation, and affected candidate/deployment discovery.

**Required contracts / collaborating tasks:** `COLL-001`, `DUC-004`, `LIN-003`, `ART-003`

**Gold evidence:** `G26`, `G34`, `G35`, `G83`

### Task 7 — COLL-007: Implement fleet/device-local collection, buffering, and synchronization

**Anti-drift implementation goal**

Collect data across 1,000 heterogeneous and intermittently connected devices without centralizing restricted payloads or losing provenance.

**Required implementation**

1. Deploy per-plan local collectors as governed workloads with source/data leases, buffer quota, local quality/minimization operators, and sync policy.
2. Assign immutable device/source batch identities and integrity-chain local manifests; upload resumably with cursor/ack reconciliation.
3. Support federated summary/feature/gradient-like artifacts as data products without making federated-learning algorithm core.
4. Respect device-local/privacy/region constraints and schedule aggregation near data where required.
5. Detect duplicate reconnect uploads, divergent device clocks, offline policy expiry, corrupt buffers, and compromised node evidence.

**Responsibility boundaries: this task must not drift into**

- Do not upload all raw device data by default.
- Do not trust device wall clock or self-reported buffer completeness alone.
- Do not call distributed collection federated learning.

**Required integration**

- Node Agent buffers/mounts; Fleet/Workload schedule; Artifact/Lineage sync; Data-Use controls locality.

**Validation and definition of done**

- G38, G61, G68, G72, G74, and G75 simulate large mixed/offline fleet collection with no duplicate records and enforced locality.

**Required contracts / collaborating tasks:** `COLL-002`, `NODE-007`, `DODRV-008`, `FLEET-008`

**Gold evidence:** `G38`, `G61`, `G68`, `G72`, `G74`, `G75`

### Task 8 — COLL-008: Implement budgets, stopping conditions, rate adaptation, and cost accounting

**Anti-drift implementation goal**

Keep data acquisition bounded and aligned with stated coverage/value rather than “collect everything forever.”

**Required implementation**

1. Enforce records/bytes/source requests/device time/storage/network/currency/privacy-risk/human-label budgets and per-slice/source limits.
2. Define stopping conditions target coverage, diminishing information gain, quality floor failure, consent/source expiry, drift/change point, budget exhaustion, or external pause.
3. Allow application plugins to propose rate/sampling changes; validate within plan bounds and create a new plan revision when semantics change.
4. Account collection, local processing, transfer, quarantine, labeling, and retention costs separately.
5. Emit forecast versus actual and prevent trigger storms from bypassing plan budgets.

**Responsibility boundaries: this task must not drift into**

- Do not let a collection model increase its own budget.
- Do not stop solely on aggregate volume if required slices are missing.
- Do not hide privacy/human/device cost behind compute cost.

**Required integration**

- Authority quotas/Gate approvals constrain; Observability supplies usage; Improvement may propose revisions.

**Validation and definition of done**

- G37, G38, G48, and G68 validate budget, rare-slice, adaptive rate, and trigger-storm behavior.

**Required contracts / collaborating tasks:** `COLL-001`, `AUTH-004`, `OBS-004`

**Gold evidence:** `G37`, `G38`, `G48`, `G68`

### Task 9 — COLL-009: Implement immutable collection snapshot and dataset-candidate publication

**Anti-drift implementation goal**

Produce exact data artifacts that can be reviewed, quality-checked, split, trained, and invalidated.

**Required implementation**

1. Close a collection window/source cursor set and assemble root shard manifest, schema, record counts/bytes, source/cursor ranges, sampling policy, coverage, obligations, quarantine exclusions, quality findings, and producer lineage.
2. Publish as `collection_snapshot` or `dataset_candidate`, never directly as approved training/eval dataset.
3. Require deterministic completeness accounting and mark partial/missing sources explicitly.
4. Trigger downstream quality/dedup/contamination/split workflows through proposals, not implicit side effects.
5. Retain previous snapshots and incremental parent relation.

**Responsibility boundaries: this task must not drift into**

- Do not mutate a dataset directory in place.
- Do not call a snapshot train-ready because collection succeeded.
- Do not omit excluded/quarantined counts.

**Required integration**

- Artifact/Lineage publish; Data controller/eval/training consume after gates.

**Validation and definition of done**

- G30–G38 inspect complete lineage, counts, exclusions, incremental parents, and use status.

**Required contracts / collaborating tasks:** `COLL-004`, `COLL-005`, `ART-002`, `LIN-002`

**Gold evidence:** `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`

### Task 10 — COLL-010: Build collection gold examples and long-running fault suite

**Anti-drift implementation goal**

Prove collection is a core persistent service across modalities, feedback, physical devices, and agent evolution.

**Required implementation**

1. Implement web/API text, code/test outcome, human preference, tool trajectory, simulated robot sensor/action, and custom numerical-source plans.
2. Run snapshot and continuous modes with source reset, late records, deletion, poison, backpressure, offline device, quota, and controller crash.
3. Verify operational traces remain separate from learning datasets until a plan includes them.
4. Demonstrate active acquisition plus random holdout and rare-tail preservation.
5. Publish evidence/lineage and assert no protected eval or unauthorized source enters output.

**Responsibility boundaries: this task must not drift into**

- Do not use only clean static files.
- Do not make examples depend on external secrets/network.
- Do not label synthetic fixtures proof of production data quality.

**Required integration**

- Gold runner uses reference perceptors/data operators/fleet simulator.

**Validation and definition of done**

- G30–G38, G47, G56, G58, and G74 pass fault and lineage assertions.

**Required contracts / collaborating tasks:** `COLL-001`, `COLL-009`, `FND-005`

**Gold evidence:** `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G47`, `G56`, `G58`, `G74`

### Component completion gate

- Collection is authorized by purpose before source access and remains bounded by consent, locality, coverage, quality, retention, and budget.
- Operational evidence is not trainable data until explicit recordization and dataset publication occur.
- Snapshots are immutable, complete-or-explicitly-partial, lineage-bound inputs to later data/eval/training decisions.

---

## Component 29 — Feedback Service

**Canonical component ID:** `splendor.feedback-service`
**Plane:** `data_learning`
**Current status:** partial foundation
**Owning package:** `crates/splendor-learning (feedback module)`

**Implemented baseline to preserve**

`Feedback` is currently only `{kind,payload,recorded_at}` and OutcomeEvaluator can attach one optional feedback value per action. There is no stable identity/targeting, source authority, causal attribution, human workflow, reliability/disagreement, privacy, correction/supersession, operational-versus-learning use, poisoning defense, or fleet ingestion.

**Exact kernel responsibility**

Own immutable receipt, validation, targeting, provenance, lifecycle, dispute/correction, reliability metadata, and governed views of human/automated/environment/model feedback. It does not derive reward by default, declare objective truth, train models, or approve changes.

**Public contracts:** `FeedbackEvent`, `FeedbackTarget`, `FeedbackSource`, `FeedbackKind`, `FeedbackAssessment`, `FeedbackCorrection`, `FeedbackView`, `ReviewTask`, `FeedbackReliability`

### Task 1 — FDBK-001: Define FeedbackEvent identity, targets, kinds, and lifecycle

**Anti-drift implementation goal**

Make feedback addressable and attributable to exact behavior, artifacts, world claims, data records, or changes.

**Required implementation**

1. Add feedback ID, tenant/scope, source principal/system/model/environment, target refs, kind/schema, payload ref/inline bound, observed/recorded times, causal context, classification, confidence, use restrictions, and event status.
2. Support targets action/invocation/outcome, route step/session/trajectory, model output, data record/snapshot, world claim/prediction, agent revision/instance, eval result, deployment/incident, or custom typed target.
3. Define kinds rating, preference, critique/correction, label/annotation, success/failure observation, safety report, policy violation, user override, environment reward precursor, and custom.
4. Implement accepted, quarantined, disputed, corrected/superseded, withdrawn, expired, and deleted-payload states while preserving immutable history.
5. Map current minimal Feedback into a legacy feedback event with explicit missing attribution.

**Responsibility boundaries: this task must not drift into**

- Do not let feedback payload grant authority or change target state directly.
- Do not assume later feedback timestamp is outcome time.
- Do not overwrite original feedback during correction.

**Required integration**

- Event/Artifact/Lineage store; Collection recordizes; Reward/Eval consume accepted views.

**Validation and definition of done**

- G37 and G41 round-trip all target/kind/status cases and distinguish legacy missing attribution.

**Required contracts / collaborating tasks:** `FND-001`, `ART-001`, `FND-006`

**Gold evidence:** `G37`, `G41`

### Task 2 — FDBK-002: Implement human, environment, automated, model-judge, and system feedback channels

**Anti-drift implementation goal**

Ingest heterogeneous feedback while preserving source class, trust, and independence.

**Required implementation**

1. Create channel contracts for authenticated user/operator/reviewer, physical/environment outcome, programmatic checker, external service, model judge, peer agent, incident/safety monitor, and imported historical feedback.
2. Bind channel identity/authentication, allowed target/schema, data visibility, rate/quota, review policy, and delivery transport.
3. For humans, support review tasks, randomized/blinded presentation, annotations, confidence, abstention, escalation, and accessibility/latency metadata.
4. For automated/model sources, pin implementation/model/rubric/data and record shared dependency with target candidate.
5. Classify unauthenticated/imported feedback as untrusted evidence until reviewed.

**Responsibility boundaries: this task must not drift into**

- Do not call model-judge output human feedback.
- Do not let an agent impersonate a user/operator through message content.
- Do not assume authenticated feedback is accurate or unbiased.

**Required integration**

- Authority authenticates; Evaluator Driver may create review tasks; Message/Perceptor transports; Data-Use limits views.

**Validation and definition of done**

- G37, G41, G44, G48, and G81 test all source classes, spoofing, blinding, and independence metadata.

**Required contracts / collaborating tasks:** `FDBK-001`, `AUTH-001`, `EVDRV-007`

**Gold evidence:** `G37`, `G41`, `G44`, `G48`, `G81`

### Task 3 — FDBK-003: Implement causal attribution windows and target resolution

**Anti-drift implementation goal**

Link feedback to the behavior that plausibly caused it without pretending correlation is proven causation.

**Required implementation**

1. Resolve explicit target IDs exactly and support bounded user-space attribution proposals for delayed/aggregate feedback over sessions, trajectories, actions, model versions, or deployments.
2. Store candidate causal set, temporal window, route/state/world context, attribution method/version, weights/uncertainty, and supporting evidence.
3. Allow multiple attribution hypotheses and later correction; keep raw feedback independent from attribution.
4. Reject attribution to inaccessible/mismatched tenant/time/identity targets and detect stale/reused IDs.
5. Expose un-attributed feedback as valid operational input but prevent hidden reward assignment.

**Responsibility boundaries: this task must not drift into**

- Do not assign delayed user sentiment to the last action by default.
- Do not let a candidate model choose its own favorable attribution without independent evidence.
- Do not rewrite feedback payload to encode attribution.

**Required integration**

- Route/Event/State provide causal graph; Reward Derivation consumes accepted attribution; user plugins compute hypotheses.

**Validation and definition of done**

- G37, G47, G48, and G58 include delayed, multi-action, coding, and RL trajectories with known attribution ambiguity.

**Required contracts / collaborating tasks:** `FDBK-001`, `EVID-002`, `ROUTE-010`

**Gold evidence:** `G37`, `G47`, `G48`, `G58`

### Task 4 — FDBK-004: Implement reliability, calibration, disagreement, and source-drift metadata

**Anti-drift implementation goal**

Use feedback quality intelligently without reducing it to a hidden global trust score.

**Required implementation**

1. Track source-specific reliability evidence by schema/domain/slice/time: agreement, calibration against adjudicated cases, consistency, abstention, latency, suspected bias/drift, and conflict-of-interest.
2. Represent disagreements/conflicting feedback as first-class groups and support adjudication workflows.
3. Allow application policies to produce weighted/filtered views from explicit reliability artifacts; raw events remain unchanged.
4. Detect sudden distribution/rating/label shifts, coordinated sources, model-version changes, and reviewer fatigue/automation patterns.
5. Expose uncertainty and sample size with every reliability summary.

**Responsibility boundaries: this task must not drift into**

- Do not create one permanent reputation number across all tasks.
- Do not suppress minority/disagreeing feedback to improve consistency.
- Do not let source reliability be updated solely from agreement with current model.

**Required integration**

- Eval Controller may maintain calibration sets; Collection sampling uses summaries; Incident handles manipulation.

**Validation and definition of done**

- G41, G44, G48, and G85 inject disagreement, biased reviewers, judge drift, and coordinated poison.

**Required contracts / collaborating tasks:** `FDBK-002`, `EVDRV-005`

**Gold evidence:** `G41`, `G44`, `G48`, `G85`

### Task 5 — FDBK-005: Implement HIL review, correction, appeal, and escalation workflows

**Anti-drift implementation goal**

Make humans effective participants in runtime control and learning without bypassing kernel authority or hiding burden.

**Required implementation**

1. Define review queues/tasks with exact target evidence, minimized/redacted context, requested schema, deadline, reviewer role, conflict checks, and escalation path.
2. Support approve/deny/comment/correct/label/preference/abstain/escalate results as feedback and, where separately authorized, governance approvals.
3. Keep governance approval object distinct from feedback even if one UI collects both.
4. Implement correction/supersession and appeal/adjudication with immutable original, reviewer reasoning artifact, and resolution status.
5. Measure queue latency, disagreement, reviewer load, and unreviewed default behavior.

**Responsibility boundaries: this task must not drift into**

- Do not use a feedback rating as an action approval token.
- Do not expose more private/protected data than review requires.
- Do not default to allow when human review times out unless explicit low-risk policy says so.

**Required integration**

- Governance/Approval service handles authority; Evaluator creates review; Agent/Route can wait/escalate.

**Validation and definition of done**

- G40, G41, G48, G73, and G78 validate separate feedback/approval, timeout, appeal, and physical HIL.

**Required contracts / collaborating tasks:** `FDBK-001`, `AUTH-007`, `EVDRV-007`

**Gold evidence:** `G40`, `G41`, `G48`, `G73`, `G78`

### Task 6 — FDBK-006: Implement privacy, consent, subject access, and deletion for feedback

**Anti-drift implementation goal**

Protect human and operational feedback while preserving necessary audit and learning lineage.

**Required implementation**

1. Classify feedback payload, reviewer identity, target content, and derived labels separately; apply purpose/retention/access controls.
2. Support pseudonymous reviewer IDs and sealed identity mapping where appropriate while retaining conflict/adjudication ability.
3. Implement subject/source correction, withdrawal, deletion, legal hold, and derived impact workflows.
4. Prevent feedback payloads from entering training datasets or prompts without an allowed use and minimization transform.
5. Redact feedback in general traces/UI while preserving reason/status and restricted artifact refs.

**Responsibility boundaries: this task must not drift into**

- Do not assume free-form critiques are non-sensitive.
- Do not expose reviewer identity to the candidate agent unnecessarily.
- Do not silently keep deleted feedback in derived preference datasets/reward models.

**Required integration**

- Data-Use/Collection/Lineage/Artifact coordinate; Incident protects abuse reports.

**Validation and definition of done**

- G26, G34, G35, and G41 validate protected reviews, training opt-in, deletion, and redacted evidence.

**Required contracts / collaborating tasks:** `FDBK-001`, `DUC-004`, `COLL-006`

**Gold evidence:** `G26`, `G34`, `G35`, `G41`

### Task 7 — FDBK-007: Implement immutable feedback views, aggregation, and export

**Anti-drift implementation goal**

Provide application-ready feedback selections without destroying raw provenance or hiding policy choices.

**Required implementation**

1. Define a FeedbackView by target/source/kind/time/slice/status/reliability/use policy with exact query/version and output artifact digest.
2. Support pairwise preference datasets, critiques/corrections, labels, trajectory assessments, safety findings, and operational summaries through user-space data operators.
3. Record inclusion/exclusion/weighting/adjudication policy and counts by source/slice/status.
4. Provide protected/aggregated exports with access checks and completeness/withdrawal markers.
5. Version views whenever underlying events/status/policy change; never mutate a published view.

**Responsibility boundaries: this task must not drift into**

- Do not call a weighted aggregate raw feedback.
- Do not hide excluded negative/disagreeing sources.
- Do not let query-time latest changes alter a running training plan.

**Required integration**

- Data Operator builds; Reward/Eval/Training consume pinned views; Lineage records.

**Validation and definition of done**

- G37, G41, G48, and G56 inspect exact membership/weights and reproduce views.

**Required contracts / collaborating tasks:** `FDBK-004`, `DODRV-001`, `LIN-002`

**Gold evidence:** `G37`, `G41`, `G48`, `G56`

### Task 8 — FDBK-008: Separate operational control, evaluation, and learning uses

**Anti-drift implementation goal**

Route the same feedback event to valid consumers without making one use imply another.

**Required implementation**

1. Define use eligibility for immediate route/state update proposal, incident/safety response, evaluation measurement, reward derivation, data collection, training, product analytics, and governance review.
2. Require separate data-use and algorithm policy for each use; one event may be eligible for some and denied for others.
3. Make urgent safety feedback trigger a governed circuit-breaker/incident proposal without automatically becoming positive/negative training reward.
4. Keep live online adaptation disabled unless an approved Improvement/Change plan explicitly consumes the view.
5. Record consumer receipts so impact and deletion can identify every downstream use.

**Responsibility boundaries: this task must not drift into**

- Do not train on every thumbs-up/down automatically.
- Do not convert action denial into negative reward without a declared derivation.
- Do not let feedback directly modify agent model/route/policy.

**Required integration**

- Incident/Route/Reward/Eval/Collection/Improvement consume separately; Lineage tracks.

**Validation and definition of done**

- G37, G40, G48, G70, and G78 prove same event follows distinct allowed/denied paths with no hidden update.

**Required contracts / collaborating tasks:** `FDBK-001`, `DUC-002`, `LIN-001`

**Gold evidence:** `G37`, `G40`, `G48`, `G70`, `G78`

### Task 9 — FDBK-009: Implement poisoning, manipulation, collusion, and feedback-loop defenses

**Anti-drift implementation goal**

Detect adversarial or self-reinforcing feedback before it drives learning or deployment.

**Required implementation**

1. Apply source authentication/rate/quota, anomaly/distribution checks, reviewer conflict, duplicate/coordinated pattern, sybil/device abuse, prompt injection, and target manipulation detectors.
2. Track candidate-generated/self-referential feedback and shared model/judge dependencies; require independent holdout channels for high-risk improvements.
3. Use canary tasks/review consistency checks and preserve random/unoptimized feedback samples.
4. Quarantine suspicious sources/views and open incidents without automatically declaring all negative feedback malicious.
5. Require reward/eval/improvement plans to state defenses and residual risks.

**Responsibility boundaries: this task must not drift into**

- Do not let the candidate classify inconvenient feedback as poison unilaterally.
- Do not trust volume/consensus under sybil conditions.
- Do not optimize solely against the same feedback channel used for promotion.

**Required integration**

- Incident, Eval independence, Reward hacking, Collection random holdout, and Gate policy consume findings.

**Validation and definition of done**

- G48, G84–G86 inject sybil, shared-judge, prompt, reward, and protected-eval attacks.

**Required contracts / collaborating tasks:** `FDBK-002`, `FDBK-004`, `INC-002`, `EVDRV-007`

**Gold evidence:** `G48`, `G84`, `G85`, `G86`

### Task 10 — FDBK-010: Build feedback gold examples and end-to-end provenance tests

**Anti-drift implementation goal**

Prove feedback works for language, code, RL, world models, multi-agent systems, and physical AI.

**Required implementation**

1. Implement authenticated user preference/correction, test/build feedback, environment transition/success, model judge, human review, safety/operator report, and peer-agent critique examples.
2. Include delayed attribution, disagreement, correction, deletion, poisoning, protected payload, and source drift.
3. Create views for evaluation, reward, and training and assert different membership/authority.
4. Trace one feedback event through operational incident and separately through approved data/reward pipelines.
5. Verify no event changes live model/route/state without owning service proposal/commit.

**Responsibility boundaries: this task must not drift into**

- Do not use only scalar ratings.
- Do not conflate mock reviewer output with human evidence.
- Do not claim alignment improvement from collection alone.

**Required integration**

- Gold runner integrates Collection/Reward/Eval/Improvement examples.

**Validation and definition of done**

- G37, G40–G48, G56, G58, G70, and G73 pass provenance and boundary assertions.

**Required contracts / collaborating tasks:** `FDBK-001`, `FDBK-009`, `FND-005`

**Gold evidence:** `G37`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G56`, `G58`, `G70`, `G73`

### Component completion gate

- Feedback is immutable, targeted, sourced, classified, and independently attributed; it is not truth, reward, approval, or model update by itself.
- Human, environment, automated, model, and peer sources retain distinct reliability and independence evidence.
- Every operational/eval/reward/training use is separately authorized and lineage-recorded.

---

## Component 30 — Reward Derivation Service

**Canonical component ID:** `splendor.reward-derivation-service`
**Plane:** `data_learning`
**Current status:** partial foundation
**Owning package:** `crates/splendor-learning (reward module)`

**Implemented baseline to preserve**

`Reward` is currently a scalar value with optional units/context and timestamp. There is no reward definition identity/version, vector/constraint signals, derivation lineage from feedback/evals/outcomes, credit assignment, normalization, learned reward model separation, reward-hacking controls, or immutable training-view publication.

**Exact kernel responsibility**

Own immutable, versioned transformations from accepted feedback/evaluation/outcome/world evidence into reward or objective signals and reward views. It executes no training, grants no authority, and cannot decide deployment; reward algorithms remain user-space plugins/models under governed workloads.

**Public contracts:** `RewardDefinition`, `RewardSignal`, `RewardTarget`, `RewardDerivation`, `CreditAssignment`, `RewardView`, `ObjectiveVector`, `RewardAuditReport`

### Task 1 — REWD-001: Define RewardDefinition, RewardSignal, targets, and lifecycle

**Anti-drift implementation goal**

Make reward an explicit derived object whose meaning and source can be audited across learning algorithms.

**Required implementation**

1. Define reward definition ID/version with objective dimensions, units/range/direction, source input schemas, target granularity, transform/plugin/model refs, normalization/clipping, missingness, temporal discount/aggregation, and allowed uses.
2. Define signal identity, target step/action/trajectory/model output/data record/agent revision, vector values, constraints/violations, source evidence refs, derivation run, confidence/uncertainty, and recorded/valid times.
3. Support scalar, vector, lexicographic, constrained, sparse/dense, categorical, preference, cost, and custom typed signals.
4. Implement accepted, provisional, disputed, superseded, invalidated, and deleted-payload states.
5. Map legacy scalar Reward as a versioned legacy definition with limited provenance.

**Responsibility boundaries: this task must not drift into**

- Do not make one scalar mandatory.
- Do not let units-free numbers from different definitions be compared.
- Do not let a signal grant action/change authority.

**Required integration**

- Feedback/Eval/World/Outcome evidence feed derivations; Training/RL consume pinned reward views.

**Validation and definition of done**

- G48 and G58 round-trip scalar/vector/constrained/delayed signals and reject definition confusion.

**Required contracts / collaborating tasks:** `FND-001`, `FDBK-001`, `EVID-001`

**Gold evidence:** `G48`, `G58`

### Task 2 — REWD-002: Implement pure, versioned reward derivation workloads

**Anti-drift implementation goal**

Run application-defined reward functions under reproducible inputs without hiding logic in the loop engine.

**Required implementation**

1. Define derivation plans with exact FeedbackView/EvalReport/outcome/world refs, definition/plugin/code/environment/model, seed, target mapping, and output schema.
2. Execute rules/formulas/programs/models through sandbox/model/evaluator drivers as non-effectful workloads.
3. Publish input-to-output lineage, counts, errors/abstentions, distribution summaries, and determinism class.
4. Prevent plugin/model from accessing protected inputs outside handles or writing live state/deployment.
5. Create a new reward signal/view revision whenever logic or inputs change.

**Responsibility boundaries: this task must not drift into**

- Do not compute reward inside arbitrary action adapter without a definition.
- Do not overwrite historical rewards after formula changes.
- Do not let a reward model approve its own output as trusted.

**Required integration**

- Workload/Sandbox/Model execute; Artifact/Lineage publish; Data-Use controls input/output.

**Validation and definition of done**

- G48 and G58 reproduce derivations and detect changed code/input/model.
- Malicious plugin cannot call deployment or read protected eval labels.

**Required contracts / collaborating tasks:** `REWD-001`, `WORK-001`, `SBX-004`, `LIN-002`

**Gold evidence:** `G48`, `G58`, `G85`

### Task 3 — REWD-003: Implement multi-objective, constraints, costs, and value-profile mapping

**Anti-drift implementation goal**

Represent useful learning pressure without collapsing safety, user value, capability, cost, and uncertainty into an opaque sum.

**Required implementation**

1. Allow named objective dimensions and hard constraint/violation channels linked to Agent Value/Constraint profiles.
2. Represent scalarization/weights/lexicographic/Pareto policy as a separate versioned consumer artifact, not inherent truth in raw signals.
3. Track environment/user/task performance, safety violations, policy compliance, uncertainty/abstention, resource/cost, latency, and diversity/coverage dimensions as applicable.
4. Require explicit units, clipping, normalization reference population, and handling of missing/unsafe episodes.
5. Expose per-slice/objective distributions for eval/gates and protect non-negotiable hard constraints from reward tradeoff.

**Responsibility boundaries: this task must not drift into**

- Do not allow positive task reward to cancel a hard safety violation automatically.
- Do not hide value choices in normalization constants.
- Do not claim a universal objective vector for all agents.

**Required integration**

- Agent Value profile binds definitions; Gate Engine handles hard constraints; Improvement selects user-space optimization objectives.

**Validation and definition of done**

- G27, G48, G58, G78, and G79 test Pareto tradeoffs and immutable hard constraints.

**Required contracts / collaborating tasks:** `REWD-001`, `AGREG-003`, `GATE-004`

**Gold evidence:** `G27`, `G48`, `G58`, `G78`, `G79`

### Task 4 — REWD-004: Implement delayed credit assignment and trajectory attribution hooks

**Anti-drift implementation goal**

Support RL and long-horizon agents while keeping attribution method explicit and replaceable.

**Required implementation**

1. Define a CreditAssignment artifact mapping episode/feedback/eval evidence to action/step/state/option/agent targets with weights, uncertainty, horizon, and method.
2. Provide plugin contracts for return/discount, temporal difference, advantage-like, causal/influence, rule-based, counterfactual, hierarchical, multi-agent, and custom assignments.
3. Require pinned trajectories/world/state/model/policy refs and prevent plugin from changing recorded actions/outcomes.
4. Allow competing assignments and downstream experiments rather than rewriting raw signal.
5. Handle terminal truncation, missing outcomes, off-policy data, and unresolved uncertain effects explicitly.

**Responsibility boundaries: this task must not drift into**

- Do not attribute all delayed reward to the final action by default.
- Do not claim causal assignment from correlation without method limitations.
- Do not erase negative/unsafe steps during trajectory filtering.

**Required integration**

- Feedback attribution provides candidates; Replay/World may generate counterfactuals; RL trainer consumes pinned assignment.

**Validation and definition of done**

- G58 includes known toy MDP/multi-agent cases and ambiguous real-like trajectories; exact and uncertain assignments behave correctly.

**Required contracts / collaborating tasks:** `REWD-002`, `FDBK-003`, `WORLD-007`

**Gold evidence:** `G58`, `G77`

### Task 5 — REWD-005: Implement reward normalization, calibration, aggregation, and immutable views

**Anti-drift implementation goal**

Prepare stable learning inputs while retaining raw signals and preventing distribution drift from changing meaning silently.

**Required implementation**

1. Define RewardView membership and transforms by target/slice/time/source/status/definition, clipping, normalization population, weighting, and aggregation.
2. Compute statistics from pinned reference population and publish them as artifacts with sample count/uncertainty.
3. Support per-task/source/agent normalization and leave-one-group-out/robust methods as plugins.
4. Preserve raw signals and mapping; consumers pin one view revision and cannot follow latest during a run.
5. Detect distribution/source/scale drift and require new view/eval rather than updating constants in place.

**Responsibility boundaries: this task must not drift into**

- Do not normalize safety violations into harmless small values.
- Do not mix reward definitions/units without explicit mapping.
- Do not compute statistics using protected eval data unless allowed.

**Required integration**

- Training/Improvement consumes views; Eval/Observability monitors drift; Artifact/Lineage publish.

**Validation and definition of done**

- G48 and G58 reproduce view membership and detect source/scale drift without changing active run.

**Required contracts / collaborating tasks:** `REWD-001`, `FDBK-007`, `LIN-002`

**Gold evidence:** `G48`, `G58`

### Task 6 — REWD-006: Implement learned reward/value model bindings and independence

**Anti-drift implementation goal**

Use learned preference/value models as replaceable model components rather than authoritative reward or gate services.

**Required implementation**

1. Represent reward/value models as ModelBundles with exact training data, eval/calibration, input/output schema, target reward definition, and deployment role.
2. Invoke through Model Driver; convert scores into provisional RewardSignals only via a named derivation definition.
3. Record candidate/reward-model shared base/training data/context and require independent channels for high-risk gates.
4. Support ensemble/disagreement/abstention and calibration artifacts.
5. Train/update reward models through normal Training/Eval/Change pipelines, never in-place from live signals.

**Responsibility boundaries: this task must not drift into**

- Do not treat reward model output as ground truth.
- Do not let the same candidate model self-score secretly.
- Do not hot-update reward model weights inside derivation service.

**Required integration**

- Model/Training/Eval/Agent Value profiles bind; Gate enforces independence.

**Validation and definition of done**

- G44, G48, G56, and G86 expose shared-model reward hacking and require independent holdout/human checks.

**Required contracts / collaborating tasks:** `REWD-002`, `MODEL-001`, `EVDRV-007`

**Gold evidence:** `G44`, `G48`, `G56`, `G86`

### Task 7 — REWD-007: Implement reward hacking, proxy drift, and tamper monitoring

**Anti-drift implementation goal**

Detect when optimized reward diverges from independent value/performance evidence.

**Required implementation**

1. Compare reward trends against independent eval/human/programmatic/environment measures, constraint violations, slice/tail behavior, and unoptimized random holdouts.
2. Detect sudden score distribution changes, evaluator/reward model exploitation, feedback-channel manipulation, target leakage, repeated edge cases, and reward-source tampering.
3. Track reward versus true/independent objective gap where a trusted proxy exists and record uncertainty where it does not.
4. Trigger quarantine, evaluation expansion, improvement pause, or incident under explicit policy; do not automatically edit reward weights.
5. Require every self-evolution experiment to include anti-reward-hacking evidence appropriate to its optimization channel.

**Responsibility boundaries: this task must not drift into**

- Do not let the optimizing agent define the sole hacking detector.
- Do not call disagreement proof of hacking without investigation.
- Do not optimize the detector and evaluator on the same exposed cases indefinitely.

**Required integration**

- Eval/Feedback/Incident/Gate/Improvement consume findings.

**Validation and definition of done**

- G48, G84–G86 produce rising reward with stagnant/regressing independent quality and must block promotion.

**Required contracts / collaborating tasks:** `REWD-003`, `EVAL-010`, `FDBK-009`, `INC-002`

**Gold evidence:** `G48`, `G84`, `G85`, `G86`

### Task 8 — REWD-008: Implement reward access, privacy, and protected-signal handling

**Anti-drift implementation goal**

Prevent reward/labels/eval outcomes from leaking into candidate inputs or unauthorized training channels.

**Required implementation**

1. Classify raw feedback, labels, protected eval outcomes, reward model internals, and aggregate signals separately.
2. Issue task-specific reward views/handles to trainers/learners; candidates receive only environment signals permitted by the learning protocol.
3. Prevent protected test reward/labels from entering model prompts, replay buffers, logs, caches, or collection snapshots.
4. Apply deletion/withdrawal/invalidated-source impact to reward views and dependent candidates.
5. Expose redacted aggregate reward evidence to operators while retaining sealed detail.

**Responsibility boundaries: this task must not drift into**

- Do not pass protected eval labels as dense training reward.
- Do not expose reviewer identity/free-form private feedback in generic RL buffers.
- Do not make possession of reward ID grant payload access.

**Required integration**

- Data-Use/Artifact/Node/Sandbox enforce; Training consumes scoped views; Lineage tracks.

**Validation and definition of done**

- G40, G43, G58, G84, and G86 attempt label/reward leakage and verify denial/impact.

**Required contracts / collaborating tasks:** `REWD-005`, `DUC-006`, `NODE-004`

**Gold evidence:** `G40`, `G43`, `G58`, `G84`, `G86`

### Task 9 — REWD-009: Build reward/RL gold examples and invariance tests

**Anti-drift implementation goal**

Prove reward interoperability across supervised preferences, environment RL, coding, world models, multi-agent, and value constraints.

**Required implementation**

1. Implement toy MDP and continuous-control/simulation reward derivations with known returns and delayed credit.
2. Implement code agent reward from independent tests, review, regression, cost, and safety dimensions.
3. Implement language preference/reward-model signals with human holdout and reward-hacking case.
4. Implement multi-agent shared/individual rewards and contribution/credit ambiguity.
5. Run deletion, definition change, normalization drift, source poisoning, and protected-label tests; publish complete derivation lineage.

**Responsibility boundaries: this task must not drift into**

- Do not claim toy RL demonstrates general alignment.
- Do not use reward alone as the novelty success criterion.
- Do not hide negative/safety dimensions in aggregate plots.

**Required integration**

- Training/Eval/Improvement gold programs consume the same RewardSignal/View contracts.

**Validation and definition of done**

- G47, G48, G56, G58, G77, and G86 pass exact and adversarial cases.

**Required contracts / collaborating tasks:** `REWD-001`, `REWD-008`, `FND-005`

**Gold evidence:** `G47`, `G48`, `G56`, `G58`, `G77`, `G86`

### Component completion gate

- Reward is a versioned, lineage-complete derivation from evidence, not raw feedback, truth, approval, or authority.
- Multiple objectives, hard constraints, credit assignment, learned reward models, and normalization remain explicit and replaceable.
- Independent evaluation and anti-hacking evidence can block optimization even when reward rises.

---

## Component 31 — Evaluation Controller

**Canonical component ID:** `splendor.eval-controller`
**Plane:** `data_learning`
**Current status:** missing
**Owning package:** `crates/splendor-learning (eval module)`

**Implemented baseline to preserve**

There is no first-class EvalSuite, EvalPlan, EvalRun, protected split service, candidate/baseline matched execution, distributed aggregation, regression/safety/value evidence, contamination monitoring, online/shadow evaluation, or continuous evaluation scheduler. Current OutcomeEvaluator is per-action and cannot serve these responsibilities.

**Exact kernel responsibility**

Own evaluation definitions, immutable case/split bindings, matched candidate/baseline plans, evaluator independence, distributed execution/completeness, statistical analysis, reports, continuous scheduling, and evidence publication. It measures and compares; it does not train, derive reward implicitly, set deployment authority, or reveal protected cases.

**Public contracts:** `EvalSuite`, `EvalSuiteRevision`, `EvalPlan`, `EvalRun`, `EvalCaseManifest`, `EvalSplit`, `MetricDefinition`, `AnalysisPlan`, `EvalReport`, `RegressionFinding`

### Task 1 — EVAL-001: Define EvalSuite, EvalPlan, EvalRun, and lifecycle

**Anti-drift implementation goal**

Make evaluation a reproducible kernel-controlled workload rather than a callback after an action.

**Required implementation**

1. Define immutable suite revision with purpose, case manifests/splits, environment/world/simulator refs, evaluator operations, metric definitions, slices, analysis plan, baseline policy, protected disclosure, resources, and validity/expiry.
2. Define run binding exact candidate(s), baseline(s), model/agent/route/deployment refs, code/env/drivers, cases, seeds, repetitions, budgets, and output policy.
3. Implement proposed, validating, admitted, running, aggregating, analysing, complete, incomplete, failed, denied, invalidated, and quarantined states.
4. Separate suite, split, plan, run, shard, case/episode, metric sample, report, and gate decision identities.
5. Require pre-registered analysis/stopping rules for promotion-critical adaptive/stochastic evals.

**Responsibility boundaries: this task must not drift into**

- Do not let a candidate choose its own cases after seeing results.
- Do not make evaluator process success equal eval validity.
- Do not put gate threshold/decision inside raw suite measurements.

**Required integration**

- Evaluator Driver executes cases; Workload/Fleet schedule; Evidence/Artifact/Lineage publish.

**Validation and definition of done**

- G39–G49 exercise lifecycle, incomplete/invalid cases, and identity separation.

**Required contracts / collaborating tasks:** `FND-001`, `EVDRV-001`, `WORK-001`

**Gold evidence:** `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`

### Task 2 — EVAL-002: Implement immutable case manifests, splits, and protected holdouts

**Anti-drift implementation goal**

Preserve valid comparison and prevent evaluation data from becoming training or candidate-visible context.

**Required implementation**

1. Publish case manifests and split membership as immutable artifacts with source/creation/quality/contamination/licence/classification lineage.
2. Support public development, validation, private test, protected one-time/fresh, canary, adversarial, safety, and online shadow splits as explicit roles.
3. Issue opaque protected handles and isolate evaluator/candidate/trainer caches/principals/environments.
4. Version suite/split when cases or labels/rubrics change and invalidate affected prior claims according to policy.
5. Track candidate exposure and adaptive-use count for reusable benchmarks.

**Responsibility boundaries: this task must not drift into**

- Do not use file paths/directories as split authority.
- Do not make validation and protected test the same repeatedly optimized set.
- Do not reveal protected labels through reports/errors/timing/caches.

**Required integration**

- Data-Use/Artifact/Evaluator/Incident enforce; Training plans exclude eval split refs.

**Validation and definition of done**

- G40, G43, G51, G84, and G86 prove isolation, exposure accounting, and contamination invalidation.

**Required contracts / collaborating tasks:** `EVAL-001`, `DODRV-007`, `EVDRV-003`, `DUC-006`

**Gold evidence:** `G40`, `G43`, `G51`, `G84`, `G86`

### Task 3 — EVAL-003: Implement paired candidate/baseline execution plans

**Anti-drift implementation goal**

Attribute behavioral differences to the candidate/change rather than unmatched inputs, environments, or randomness.

**Required implementation**

1. Build matched plans pinning case/episode identity, environment/world branch, seeds/random streams, model sampling, resource class, driver versions, and route/state initialization.
2. Support paired sequential, parallel shadow, replay/simulation, and live canary comparisons with declared interference/order controls.
3. Randomize/blind candidate labels for human/learned judges where appropriate.
4. Record unavoidable asymmetries and choose paired/unpaired analysis explicitly.
5. Prevent baseline mutable alias or live state drift during plan.

**Responsibility boundaries: this task must not drift into**

- Do not compare candidate and baseline on different cases/seeds silently.
- Do not call a replay-only comparison proof of live external behavior.
- Do not let one variant affect the other’s shared world/state unless experimental design requires it.

**Required integration**

- Replay/World/Agent/Deployment create isolated branches/shadows; Evaluator runs.

**Validation and definition of done**

- G42, G45, and G46 reproduce paired differences and expose deliberately unmatched confounders.

**Required contracts / collaborating tasks:** `EVAL-001`, `RPLY-004`, `WORLD-007`

**Gold evidence:** `G42`, `G45`, `G46`

### Task 4 — EVAL-004: Implement distributed evaluation, case accounting, and aggregation

**Anti-drift implementation goal**

Evaluate at fleet scale while preserving exact case membership, retry deduplication, and completeness.

**Required implementation**

1. Expand EvalPlan into immutable case/episode work units and reducers using Evaluator Driver declarations.
2. Schedule by data locality, modality/hardware/environment requirements, protected isolation, and live capacity reservations.
3. Accept one current result per case/repetition/variant; quarantine late/stale duplicates and preserve failed/aborted/invalid cases.
4. Aggregate only when required completeness/minimum sample policy is met; expose missingness/failure by slice.
5. Checkpoint/resume long runs and permit incremental reports marked non-final.

**Responsibility boundaries: this task must not drift into**

- Do not drop slow/failed cases to improve scores.
- Do not aggregate by completion order.
- Do not run protected cases on untrusted or incompatible nodes.

**Required integration**

- Workload/Fleet/Node/Evaluator execute; Evidence assembles; Gate requires final/valid status.

**Validation and definition of done**

- G42, G61, G68, and G83 test retries, stragglers, node loss, protected placement, and compromised worker results.

**Required contracts / collaborating tasks:** `EVAL-001`, `EVDRV-004`, `FLEET-008`

**Gold evidence:** `G42`, `G61`, `G68`, `G83`

### Task 5 — EVAL-005: Implement metric validation, slices, uncertainty, and analysis plans

**Anti-drift implementation goal**

Produce statistically and semantically valid reports rather than one aggregate score.

**Required implementation**

1. Validate metric schema/units/direction/range/missingness and evaluator version before accepting samples.
2. Compute per-case, aggregate, per-slice, tail/worst-group, distribution, calibration, resource/SLO, and safety/constraint findings according to predeclared analysis.
3. Use paired differences, intervals/effect sizes, multiple-comparison metadata, power/insufficient-evidence, and sequential stopping where specified.
4. Record slice definitions and membership derivation; protect sensitive slices and avoid tiny-group disclosure.
5. Publish raw-access-controlled samples plus redacted aggregate report.

**Responsibility boundaries: this task must not drift into**

- Do not hide regressions behind a global average.
- Do not report statistical significance without effect magnitude/assumptions.
- Do not change slice definitions after seeing candidate results without a new exploratory report.

**Required integration**

- Evaluator helpers compute; Evidence stores; Gate consumes named findings.

**Validation and definition of done**

- G39, G42, G46, G47, and G57 validate deterministic/statistical/slice/calibration/safety reports.

**Required contracts / collaborating tasks:** `EVAL-001`, `EVDRV-002`, `EVDRV-005`

**Gold evidence:** `G39`, `G42`, `G46`, `G47`, `G57`

### Task 6 — EVAL-006: Implement capability, regression, safety, value, robustness, and resource eval classes

**Anti-drift implementation goal**

Evaluate complete agent changes across more than task accuracy or loss.

**Required implementation**

1. Define suite composition roles for task/capability, generalization, regression, hard constraints/safety, value/preference, robustness/adversarial, uncertainty/calibration, long-horizon stability, physical safety, privacy/data, cost/latency/resource, and interoperability.
2. Bind named critical slices and non-regression budgets to Agent Value/Constraint and Deployment target policies.
3. Support agent-level trajectories and subsystem-level model/route/world/data tests; prevent subsystem pass from substituting for end-to-end evidence.
4. Include abstention/uncertainty and denial correctness, not only successful action outcomes.
5. Version benchmark scope and residual known gaps.

**Responsibility boundaries: this task must not drift into**

- Do not call perplexity or task score alignment.
- Do not infer physical safety from simulation alone.
- Do not require one universal metric set across domains.

**Required integration**

- AgentSpec/Value profile references suites; Gate policy maps required evidence; Improvement uses results.

**Validation and definition of done**

- G39–G49, G57–G59, G73, G77, and G78 cover the classes with explicit gaps.

**Required contracts / collaborating tasks:** `EVAL-005`, `AGREG-003`

**Gold evidence:** `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G57`, `G58`, `G59`, `G73`, `G77`, `G78`

### Task 7 — EVAL-007: Implement contamination, memorization, overfitting, and adaptive-eval checks

**Anti-drift implementation goal**

Detect when apparent improvement comes from exposure or repeated optimization rather than generalization.

**Required implementation**

1. Run exact/near/semantic/code/media overlap scans between all candidate training/feedback/synthetic data and suite fingerprints through protected interfaces.
2. Track suite exposure count, candidate/query history, evaluator feedback returned, and adaptive optimization budget.
3. Include fresh/rotating/one-time cases, perturbations, distribution-shift sets, train-like controls, and memorization probes where appropriate.
4. Compare validation, public, protected, fresh, and live shadow performance for widening gaps and slice-specific overfit.
5. Invalidate or downgrade claims when contamination/exposure exceeds policy; preserve the result as evidence rather than deleting it.

**Responsibility boundaries: this task must not drift into**

- Do not claim decontaminated from exact matching alone.
- Do not repeatedly expose detailed protected failures to the improvement loop.
- Do not call every high train/test gap memorization without analysis.

**Required integration**

- Data Operator contamination, Collection/Lineage data refs, Incident leakage, Gate validity policy integrate.

**Validation and definition of done**

- G33, G43, G51, G56, and G86 introduce exact/paraphrase/generated/adaptive contamination and require correct block/downgrade.

**Required contracts / collaborating tasks:** `EVAL-002`, `DODRV-005`, `LIN-003`

**Gold evidence:** `G33`, `G43`, `G51`, `G56`, `G86`

### Task 8 — EVAL-008: Implement online, shadow, canary, and post-deployment evaluation

**Anti-drift implementation goal**

Measure real operating behavior safely and feed controlled rollback/improvement without turning live traffic into unrestricted training data.

**Required implementation**

1. Define shadow evaluation with duplicated/minimized inputs, no effect/live state commits, exact candidate/baseline revision, and latency/resource isolation.
2. Define canary/post-deployment observations with exposure allocation, user/traffic/device slices, guardrail metrics, incident linkage, and rollback thresholds.
3. Use privacy-preserving/aggregated online metrics and explicit collection plans for any retained records.
4. Separate product/runtime telemetry from evaluation samples and reward/training eligibility.
5. Support delayed outcomes and evaluation windows; update reports immutably as windows close.

**Responsibility boundaries: this task must not drift into**

- Do not let shadow agent actuate.
- Do not train directly on all canary traffic without collection/data-use plan.
- Do not let candidate route choose which live outcomes are evaluated.

**Required integration**

- Deployment creates exposure; Agent/Route shadow; Feedback/Collection capture; Incident/Deployment rollback.

**Validation and definition of done**

- G45, G46, G49, G70, G73, and G75 validate shadow/canary delayed outcomes, privacy, physical boundaries, and rollback.

**Required contracts / collaborating tasks:** `EVAL-003`, `DEP-003`, `DEP-004`, `COLL-001`

**Gold evidence:** `G45`, `G46`, `G49`, `G70`, `G73`, `G75`

### Task 9 — EVAL-009: Implement human, multi-agent, world-model, and physical eval orchestration

**Anti-drift implementation goal**

Coordinate complex evaluation protocols whose environment/evaluators are agents, people, simulators, or devices.

**Required implementation**

1. Create role-isolated workload graphs for candidate agents, environment/simulator, adversary/peer agents, learned/human evaluators, and local safety monitors.
2. Bind exact world state/simulation/device/test envelope and keep evaluator/delegation authority isolated.
3. Support human queue deadlines/blinding/adjudication and physical simulation-before-live/staged envelope policy.
4. Capture trajectories, interventions, safety aborts, operator burden, transfer/calibration evidence, and multi-agent externalities.
5. Mark unexecuted unsafe/unsupported live tests and residual uncertainty honestly.

**Responsibility boundaries: this task must not drift into**

- Do not give evaluator/adversary agents production capabilities.
- Do not treat no accident in a small physical test as proof of safety.
- Do not force human reviewers to expose protected context to candidate.

**Required integration**

- Evaluator Driver profiles, Agent Instance, World/Actuator, HIL, Workload graph coordinate.

**Validation and definition of done**

- G41, G57–G59, G73, and G77 execute role isolation, safety abort, and human/multi-agent cases.

**Required contracts / collaborating tasks:** `EVAL-001`, `EVDRV-006`, `EVDRV-007`, `AGREG-005`

**Gold evidence:** `G41`, `G57`, `G58`, `G59`, `G73`, `G77`

### Task 10 — EVAL-010: Implement evaluator independence and reward-hacking analysis

**Anti-drift implementation goal**

Prevent self-evolution from optimizing a single shared or gameable evaluator.

**Required implementation**

1. Compute independence attributes for candidate and evaluator: shared base model, code, training/feedback data, prompt/context, provider, author/team, environment, and optimized exposure.
2. Require a configured mix of programmatic, human, environment, holdout model, and fresh data channels by change risk; allow exceptions only with explicit residual-risk decision.
3. Compare optimized proxy/reward metrics with independent measures and detect divergence across cycles.
4. Blind/randomize variants and include adversarial attempts to influence judge/reviewer/eval tools.
5. Publish an independence/reward-hacking report consumed by Gate Engine.

**Responsibility boundaries: this task must not drift into**

- Do not call two prompts to the same shared model independent.
- Do not let the candidate write/modify its evaluator or tests in the same uncontrolled change.
- Do not treat evaluator agreement as value truth without source/coverage analysis.

**Required integration**

- Reward/Feedback/Lineage provide dependency graph; Gate enforces; Incident handles tampering.

**Validation and definition of done**

- G44, G48, G76, G84–G86 block candidates that improve only shared/gameable evaluators.

**Required contracts / collaborating tasks:** `EVAL-006`, `REWD-007`, `LIN-003`

**Gold evidence:** `G44`, `G48`, `G76`, `G84`, `G85`, `G86`

### Task 11 — EVAL-011: Publish EvalReport, regression findings, and gate-ready evidence

**Anti-drift implementation goal**

Produce immutable, complete, access-controlled evidence without embedding the final promotion decision.

**Required implementation**

1. Assemble exact suite/plan/run, candidates/baselines, case completeness, metric/slice analysis, uncertainty, contamination/exposure, independence, resource/environment, failures, and known limitations.
2. Emit typed regression/improvement/constraint/safety/insufficient-evidence findings with supporting sample/report refs.
3. Sign/integrity-bind report to evaluator versions, case manifests, outputs, analysis code, and event range.
4. Provide redacted summaries and protected detailed views; report missing/inaccessible evidence explicitly.
5. Invalidate/supersede report on compromised evaluator/data/worker or discovered contamination rather than editing it.

**Responsibility boundaries: this task must not drift into**

- Do not include a mutable “approved=true” field.
- Do not omit failed cases or negative slices.
- Do not let report signature imply scientific validity or deployment safety alone.

**Required integration**

- Evidence/Lineage store; Gate/Improvement/Change/Deployment consume.

**Validation and definition of done**

- G39, G42, G45–G49, G83, and G86 validate completeness, redaction, invalidation, and no embedded gate.

**Required contracts / collaborating tasks:** `EVAL-004`, `EVAL-005`, `EVAL-007`, `EVAL-010`, `EVID-003`

**Gold evidence:** `G39`, `G42`, `G45`, `G46`, `G47`, `G48`, `G49`, `G83`, `G86`

### Task 12 — EVAL-012: Implement continuous evaluation scheduling and drift response

**Anti-drift implementation goal**

Reassess live agents/models/routes/world/data as environments and evidence change over time.

**Required implementation**

1. Define continuous eval policies by schedule/event/change/deployment/data drift/incident/model age and minimum cadence.
2. Pin each run to current deployed revision and suite revision; preserve trends across comparable versions with compatibility markers.
3. Detect performance/value/safety/calibration/resource/data drift and trigger review, rollback proposal, data collection, or improvement proposal according to policy.
4. Use rate/budget controls, rotating samples, and holdout preservation to avoid exhausting protected suites.
5. Pause/adjust continuous eval when data/use/evaluator validity expires and expose coverage gaps.

**Responsibility boundaries: this task must not drift into**

- Do not automatically retrain or relax gates on drift.
- Do not repeatedly optimize against the same exposed continuous cases.
- Do not hide missing eval coverage during outages.

**Required integration**

- Workload recurrence executes; Deployment/Incident/Collection/Improvement receive proposals; Observability supplies triggers.

**Validation and definition of done**

- G49, G59, G70, G75, and G88 run repeated drift/eval cycles with bounded load and correct proposals.

**Required contracts / collaborating tasks:** `EVAL-001`, `WORK-007`, `OBS-005`

**Gold evidence:** `G49`, `G59`, `G70`, `G75`, `G88`

### Component completion gate

- Evaluation cases, splits, candidates, baselines, environments, randomness, metrics, and analysis are pinned before execution.
- Reports expose completeness, slices, uncertainty, contamination, independence, and limitations; gates remain separate.
- Protected, distributed, live, human, multi-agent, world, and physical evaluation retain explicit isolation and validity.

---

## Component 32 — Training Controller

**Canonical component ID:** `splendor.training-controller`
**Plane:** `data_learning`
**Current status:** missing
**Owning package:** `crates/splendor-learning (training module); PyTorch/framework algorithms stay in trainer adapters and user code`

**Implemented baseline to preserve**

No end-to-end training control exists. Work orders, placement v0, state/trace, and fleet identity are foundations only. Missing are TrainingSpec/Run, arbitrary-project inspection and honest compatibility, immutable environment/data/checkpoint plans, parallel topology selection, rendezvous/group epochs, global batch/data semantics, distributed checkpoint/recovery, live-service reservations, sweeps, continual/RL workflows, candidate-only publication, and 1,000-device scale.

**Exact kernel responsibility**

Own the framework-neutral flow control of a training process: exact inputs/objective/config, project compatibility, task/worker-group plan, data assignment, resource/topology request, progress/checkpoint/retry semantics, candidate outputs, and isolation. It orchestrates compute but never implements the optimizer/loss/model algorithm, chooses promotion, or activates weights.

**Public contracts:** `TrainingSpec`, `TrainingRun`, `TrainingStage`, `ProjectCompatibility`, `DataPlan`, `ParallelPlan`, `BatchSemantics`, `CheckpointPolicy`, `TrainingReport`, `CandidateBundle`

### Task 1 — TRAIN-001: Define TrainingSpec, TrainingRun, stage graph, and lifecycle

**Anti-drift implementation goal**

Make all training and adjustment methods governed workloads with immutable inputs and explicit outputs.

**Required implementation**

1. Define training identity/owner/purpose, project/code/environment refs, trainer/framework profile, initial model/checkpoint, dataset/reward/feedback/world refs, algorithm/config artifacts, data plan, parallel plan, resources, checkpoint/retry, eval hooks, output candidate declarations, and evidence policy.
2. Implement draft, inspecting, invalid, validated, admitted, queued, preparing, running, checkpointing, paused, resuming, finalizing, succeeded, failed, cancelled, denied, expired, and quarantined states.
3. Support stages data prepare, environment build, train/fit/update, checkpoint convert, intermediate eval, select, package candidate as explicit task graph.
4. Separate training run, stage, task, worker group/epoch, attempt, checkpoint, trial, and candidate identities.
5. Support supervised/self-supervised/RL/preference/distillation/continual/world-model/custom profiles as non-authorizing typed extensions.

**Responsibility boundaries: this task must not drift into**

- Do not put optimizer/loss equations in core.
- Do not let a trainer worker mutate the TrainingSpec or final state.
- Do not call a successful training process a promoted model.

**Required integration**

- Workload/Trainer realize; Artifact/Lineage store; Eval/Improvement consume.

**Validation and definition of done**

- G50–G59 and G60–G69 exercise lifecycle and profiles.

**Required contracts / collaborating tasks:** `FND-001`, `WORK-001`, `TRDRV-001`

**Gold evidence:** `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`

### Task 2 — TRAIN-002: Implement arbitrary project intake and static/dynamic inspection

**Anti-drift implementation goal**

Turn a source repository/bundle into an exact compatibility and risk report before distributed execution.

**Required implementation**

1. Accept immutable source revision/archive, environment declaration, entrypoint(s), config schema, expected outputs, licences, build policy, and optional Splendor project manifest.
2. Inspect dependencies/framework versions, imports/native extensions, global/process state, filesystem/network/subprocess use, distributed initialization, device assumptions, data loading, checkpoint calls, argument/env interface, and test commands.
3. Run a sandboxed dry-run/smoke probe on tiny synthetic data where authorized to discover runtime behavior without protected data or effects.
4. Detect existing torchrun/DDP/FSDP/framework support and structured hooks; generate actionable blockers/required user changes.
5. Pin inspector version and classify findings as observed/static/declared/unknown.

**Responsibility boundaries: this task must not drift into**

- Do not execute untrusted setup/import on the control plane.
- Do not promise static analysis fully understands dynamic Python.
- Do not modify the project automatically to make it compatible.

**Required integration**

- Sandbox builds/probes; Trainer Driver owns framework inspection plugin; Artifact/Lineage pin results.

**Validation and definition of done**

- G60 includes conventional, custom loop, dynamic, side-effectful, unsupported extension, and already-distributed PyTorch projects with correct reports.

**Required contracts / collaborating tasks:** `TRAIN-001`, `TRDRV-002`, `SBX-004`

**Gold evidence:** `G60`

### Task 3 — TRAIN-003: Implement and enforce T0–T3 project compatibility tiers

**Anti-drift implementation goal**

Provide a precise support ladder from arbitrary opaque code to deeply integrated distributed training.

**Required implementation**

1. T0 opaque: one training worker/process; Splendor controls environment/resources/data mounts/checkpoints only if externally declared; parallelism limited to independent trials/stages.
2. T1 distributed-aware: launch project under conformant framework runner/torchrun; project owns distributed model/data/checkpoint semantics and declares them in compatibility contract.
3. T2 structured: require model/optimizer/data/step/state/checkpoint factories/hooks; permit automatic supported DDP/FSDP wrappers and controlled data assignment.
4. T3 explicit parallel plugin: require project-supplied validated mesh/partition/group/checkpoint semantics for tensor/pipeline/expert/custom modes.
5. Record per-guarantee support (elasticity, exact resume, topology change, sample semantics, mixed hardware, checkpoint, intermediate eval) rather than one tier badge alone.
6. Fail or downgrade planning explicitly when requested guarantees exceed report; never silently run a different training semantics.

**Responsibility boundaries: this task must not drift into**

- Do not call multiple T0 trials distributed training of one model.
- Do not auto-wrap arbitrary projects with unproven optimizer/data semantics.
- Do not make T2/T3 mandatory for all useful training.

**Required integration**

- Trainer Driver implements tiers; Workload modes host; SDK documents required hooks.

**Validation and definition of done**

- G60–G64 request supported and unsupported combinations and compare advertised versus actual guarantees.

**Required contracts / collaborating tasks:** `TRAIN-002`, `TRDRV-002`

**Gold evidence:** `G60`, `G61`, `G62`, `G63`, `G64`

### Task 4 — TRAIN-004: Implement reproducible build and runtime environment planning

**Anti-drift implementation goal**

Convert project source into exact runnable environment variants across fleet nodes before reserving expensive training groups.

**Required implementation**

1. Resolve/build locked Python or OCI environment artifacts per target architecture/accelerator/runtime using isolated build workloads.
2. Validate framework/compiler/accelerator/collective/runtime versions and custom extension compatibility against candidate nodes.
3. Run import/model-construction/tiny-step/checkpoint smoke tests for each selected compatibility profile.
4. Publish environment/build provenance, SBOM, tests, platform variants, and cache keys; pin exact refs in TrainingPlan.
5. Separate build/network secrets from training runtime and disallow runtime package mutation.

**Responsibility boundaries: this task must not drift into**

- Do not reserve a large fleet before proving the environment starts on each target class.
- Do not use mutable base images/index packages.
- Do not assume one binary wheel works across all accelerator stacks.

**Required integration**

- Sandbox Executor builds; Artifact/Lineage store; Fleet filters nodes; Trainer validates.

**Validation and definition of done**

- G52, G60–G62, and G83 test multi-platform build, cache, incompatibility, and compromised dependency.

**Required contracts / collaborating tasks:** `TRAIN-002`, `SBX-011`, `FLEET-004`

**Gold evidence:** `G52`, `G60`, `G61`, `G62`, `G83`

### Task 5 — TRAIN-005: Implement immutable data, feedback, reward, and split plan admission

**Anti-drift implementation goal**

Freeze exactly what learning may consume and prevent eval/protected/unauthorized data leakage.

**Required implementation**

1. Require dataset snapshot/split refs, schema, quality/contamination reports, data-use purpose/grants, sampling/order/curriculum, feedback/reward view refs, replay buffer/stream semantics, and exclusion/protected fingerprints.
2. Validate licences/consent/retention/locality, train/eval split separation, data/model processor compatibility, coverage/quality minima, contamination policy, and revoked/deleted source impact.
3. Generate a `DataPlan` with logical sample population, shard manifests, global assignment policy, expected volume, cursor/checkpoint semantics, and allowed transformations/augmentations.
4. Pin all refs for the run; online/streaming additions require an explicitly versioned rolling plan/window and evidence.
5. Prevent trainer workers from discovering arbitrary filesystem/source data outside issued assignments.

**Responsibility boundaries: this task must not drift into**

- Do not train from a mutable directory/query/latest dataset.
- Do not treat feedback/reward IDs as payload authority.
- Do not permit protected eval cases or labels in the training plan.

**Required integration**

- Collection/Data/Feedback/Reward/Data-Use/Eval services validate; Node mounts assignments.

**Validation and definition of done**

- G33–G37, G40, G43, G51, G52, G56, and G58 validate clean/denied/streaming/contamination/deletion cases.

**Required contracts / collaborating tasks:** `TRAIN-001`, `COLL-009`, `DODRV-007`, `FDBK-007`, `REWD-005`, `EVAL-002`

**Gold evidence:** `G33`, `G34`, `G35`, `G36`, `G37`, `G40`, `G43`, `G51`, `G52`, `G56`, `G58`

### Task 6 — TRAIN-006: Implement framework-neutral parallel and topology planning

**Anti-drift implementation goal**

Select a real supported execution strategy from project, model, data, and fleet facts rather than a generic device count.

**Required implementation**

1. Build candidate plans for single worker, independent trials, data parallel, sharded data parallel, tensor parallel, pipeline parallel, hybrid meshes, actor/learner/evaluator pools, or custom plugin.
2. Validate trainer/project tier, model size/structure, optimizer/checkpoint support, global batch target, data locality, device memory/dtype, collective backend, network topology, min/max group, and live reservations.
3. Choose by explicit user policy/objective (correctness first, then time/cost/energy/utilization preferences) and publish alternatives/rejection reasons.
4. Create canonical worker roles/groups/mesh and bind identical plan digest to every worker lease.
5. Use heterogeneous devices through complementary roles/independent jobs; synchronous groups remain compatibility-valid unless an explicit plugin supports heterogeneity.

**Responsibility boundaries: this task must not drift into**

- Do not set `distributed=true` and infer everything else.
- Do not select tensor/pipeline partition boundaries without project/plugin contract.
- Do not maximize device use at the cost of invalid collective or live SLO.

**Required integration**

- Trainer validates modes; Fleet Scheduler realizes topology; Workload graph carries roles.

**Validation and definition of done**

- G61–G64 compare one/many/topology/heterogeneous plans and reject inconsistent unsupported meshes.

**Required contracts / collaborating tasks:** `TRAIN-003`, `TRDRV-004`, `FLEET-004`, `FLEET-008`

**Gold evidence:** `G61`, `G62`, `G63`, `G64`

### Task 7 — TRAIN-007: Implement worker-group, rendezvous, launch, and epoch orchestration

**Anti-drift implementation goal**

Coordinate distributed workers through failure and membership changes without depending on stable ranks.

**Required implementation**

1. Request gang/elastic reservations for roles/groups, then create worker group epoch with logical slots, rank mapping, rendezvous, topology, environment, data assignments, checkpoint, and seed derivation.
2. Launch via Trainer/Node and wait for readiness/collective initialization with group deadline; fail/restart whole synchronous group on partial failure unless profile says otherwise.
3. Track heartbeats/progress/errors by attempt/slot and fence old epochs before restart.
4. Regenerate rank/world size and assignments on each epoch; preserve logical progress/checkpoint semantics.
5. Coordinate multiple groups for actor/learner/evaluator or pipeline services with explicit channels and backpressure.

**Responsibility boundaries: this task must not drift into**

- Do not use rank as durable identity.
- Do not start training steps before all required roles are ready.
- Do not leave surviving collective ranks alive after group epoch failure.

**Required integration**

- Fleet/Workload/Node/Trainer own respective layers; Event/Evidence record.

**Validation and definition of done**

- G63/G64 kill workers/nodes at startup/midstep/checkpoint and verify fencing/recovery.

**Required contracts / collaborating tasks:** `TRAIN-006`, `FLEET-003`, `FLEET-006`, `TRDRV-003`

**Gold evidence:** `G63`, `G64`

### Task 8 — TRAIN-008: Implement global batch, optimizer-step, sample, and data-cursor semantics

**Anti-drift implementation goal**

Preserve learning meaning across gradient accumulation, group-size changes, retries, and streaming data.

**Required implementation**

1. Define `BatchSemantics`: per-device microbatch, accumulation steps, data-parallel degree, effective global batch, loss reduction/weighting, drop/pad policy, optimizer step count, token/sample units, and schedule scaling policy.
2. Bind data assignment/generation/cursor and seed derivation to group epoch/logical slot, not rank alone.
3. Require explicit policy on world-size change: preserve global batch by adjusting microbatch/accumulation, preserve per-device batch and change optimizer semantics, restart stage, or reject elasticity.
4. Track consumed/committed sample ranges, duplicated/skipped bounds after failure, and exact optimizer/checkpoint progress.
5. For iterable/online data, require project/source cursor capabilities and report weaker semantics honestly.

**Responsibility boundaries: this task must not drift into**

- Do not let world-size changes silently alter global batch/learning-rate schedule.
- Do not assume an epoch is a stable unit for streams.
- Do not report samples seen from per-rank counters without dedup semantics.

**Required integration**

- Trainer DataAssignment implements; Reward/RL may use trajectory cursors; Checkpoint captures.

**Validation and definition of done**

- G52 and G64 assert reference equivalence or declared divergence across 1/2/N workers and membership changes.

**Required contracts / collaborating tasks:** `TRAIN-005`, `TRAIN-007`, `TRDRV-006`

**Gold evidence:** `G52`, `G64`

### Task 9 — TRAIN-009: Implement checkpoint schedule, completeness, restore, and topology resharding control

**Anti-drift implementation goal**

Bound lost work and make resume a verified plan transition, not “load newest file.”

**Required implementation**

1. Select checkpoint triggers by steps/time/tokens/cost/preemption/quality/safe point and retention based on workload risk/lost-work budget.
2. Coordinate trainer checkpoint protocol, collect all required shards/components, commit root manifest/lineage, validate read-back, and only then mark durable/current.
3. Select restore checkpoint by accepted current run lineage/completeness/compatibility rather than timestamp; quarantine stale/corrupt outputs.
4. For supported adapters, plan load-time resharding/topology change and run a validation step/eval before continuing; otherwise require same topology or new run.
5. Track checkpoint overhead and adapt schedule within approved bounds without changing learning semantics silently.

**Responsibility boundaries: this task must not drift into**

- Do not accept partially uploaded rank files.
- Do not resume optimizer/model/data from inconsistent points.
- Do not assume framework state compatibility across version changes.

**Required integration**

- Trainer/Node/Artifact/Lineage implement; Workload handles pause/preempt; Eval can validate.

**Validation and definition of done**

- G52, G63, G64, and G69 fault every save/load stage and prove only complete compatible resume.

**Required contracts / collaborating tasks:** `TRAIN-007`, `TRAIN-008`, `TRDRV-007`, `ART-002`

**Gold evidence:** `G52`, `G63`, `G64`, `G69`

### Task 10 — TRAIN-010: Implement failure classification, retry, preemption, straggler, and recovery policy

**Anti-drift implementation goal**

Recover infrastructure failures while surfacing algorithm/data failures and avoiding restart loops.

**Required implementation**

1. Classify environment/build, data, user code, numerical divergence/NaN, OOM, accelerator/collective/network, worker/node, checkpoint, quota/preemption, cancellation, and control-plane failures.
2. Map each class to no retry, same-plan retry, adjusted resource retry, checkpoint resume/new epoch, quarantine node/driver/data, or intervention; changes to hyperparameters/algorithm require new plan/run revision.
3. Detect stragglers via progress/collective evidence and permit wait, rebalance independent tasks, checkpoint/restart group, or investigate; never drop one synchronous rank’s contribution silently.
4. Bound retries/lost work/cost and use failure-domain backoff/quarantine.
5. Preserve partial artifacts/logs/checkpoints and root-cause evidence.

**Responsibility boundaries: this task must not drift into**

- Do not auto-reduce batch size/precision after OOM and call it same run without declared policy.
- Do not retry deterministic user-code error indefinitely.
- Do not ignore data corruption/poison as generic worker failure.

**Required integration**

- Workload/Fleet/Node error taxonomy; Incident; Improvement may propose a new experiment.

**Validation and definition of done**

- G63, G65, G69, G83, and G88 inject every failure class and verify exact action/budget.

**Required contracts / collaborating tasks:** `TRAIN-001`, `FND-004`, `FLEET-007`, `INC-002`

**Gold evidence:** `G63`, `G65`, `G69`, `G83`, `G88`

### Task 11 — TRAIN-011: Implement live-inference and physical-service coexistence controls

**Anti-drift implementation goal**

Use spare fleet/device compute for training without harming live agents, model services, or local safety.

**Required implementation**

1. Request only residual/preemptible resources on nodes with protected services unless dedicated capacity is allocated.
2. Declare training phase interference profile including model load, compilation, data transfer, checkpoint, collective, memory, bandwidth, and thermal peaks.
3. Consume Node/Fleet SLO/reservation feedback and checkpoint/throttle/preempt/replan independent stages before live thresholds breach.
4. Support device opt-in windows, battery/power/thermal/network constraints, and immediate local reclaim for physical safety.
5. Measure training progress and live SLO impact together and include interference evidence in reports.

**Responsibility boundaries: this task must not drift into**

- Do not run background training on an actuator device because utilization appears low.
- Do not let checkpoint/upload saturate live network/storage.
- Do not lower live safety/inference priority to meet training deadline.

**Required integration**

- Fleet/Node enforce; Model/Agent/Observability expose protected SLO; Workload checkpoints.

**Validation and definition of done**

- G68 and G74 run mixed loads at 1,000-device simulation and physical edge, asserting SLO and bounded training progress.

**Required contracts / collaborating tasks:** `TRAIN-006`, `FLEET-005`, `NODE-006`, `OBS-004`

**Gold evidence:** `G68`, `G74`

### Task 12 — TRAIN-012: Implement trials, sweeps, population, and independent experiment fan-out

**Anti-drift implementation goal**

Use arbitrary devices for independent training/eval searches without confusing them with one distributed model run.

**Required implementation**

1. Define trial identity and immutable parameter/config proposal within an experiment, with shared source/data/base model and independent seeds/resources.
2. Expand grid/random/Bayesian/evolutionary/population/custom search proposals from user-space plugin into bounded trial Workloads after validation.
3. Schedule independent trials heterogeneously where compatible, early-stop only under predeclared analysis, and preserve all results/failures.
4. Evaluate candidates on pinned validation and select through Improvement policy; protected test remains separate.
5. Track search budget/exposure/adaptive overfit and publish trial lineage/Pareto report.

**Responsibility boundaries: this task must not drift into**

- Do not call a sweep one distributed training run.
- Do not select on protected test repeatedly.
- Do not let search plugin increase trial/resource budget or hide failed trials.

**Required integration**

- Improvement defines search; Fleet uses devices; Eval compares; Gate protects holdout.

**Validation and definition of done**

- G55, G56, G61, and G67 run sweeps/population across heterogeneous devices with fairness and exposure accounting.

**Required contracts / collaborating tasks:** `TRAIN-001`, `WORK-003`, `FLEET-008`, `EVAL-007`

**Gold evidence:** `G55`, `G56`, `G61`, `G67`

### Task 13 — TRAIN-013: Implement continual, online, parameter-efficient, RL, and world-model training flows

**Anti-drift implementation goal**

Support evolving agents through explicit staged protocols rather than one batch supervised assumption.

**Required implementation**

1. Represent parameter-efficient adaptation, continual replay/rehearsal, online windows, reward/preference learning, RL actor-learner, world-model fit, distillation, and custom updates as stage/profile graphs.
2. Pin baseline/candidate, data/reward window, replay/anchor data, update scope, optimizer state, cadence, stop criteria, and catastrophic-forgetting/non-regression eval requirements.
3. For actor-learner, separate rollout actors, environment/world/simulator, learner, reward derivation, evaluator, and candidate checkpoints with bounded staleness/channels.
4. Keep live deployed model immutable; online data/update produces candidate checkpoints evaluated/gated before deployment.
5. Support partial component changes (adapter, reward model, world model, route policy) with exact bundle lineage.

**Responsibility boundaries: this task must not drift into**

- Do not update live weights in-place from user feedback.
- Do not let rollout actors/evaluator share unrestricted authority or protected labels.
- Do not call continual learning safe without forgetting/contamination/feedback-loop checks.

**Required integration**

- Collection/Feedback/Reward/World/Eval/Improvement coordinate; Trainer algorithms remain plugins.

**Validation and definition of done**

- G55–G59 and G70 perform PEFT, preference, continual, world model, RL, and complete agent changes with candidate-only outputs.

**Required contracts / collaborating tasks:** `TRAIN-005`, `REWD-005`, `WORLD-006`, `EVAL-006`

**Gold evidence:** `G55`, `G56`, `G57`, `G58`, `G59`, `G70`

### Task 14 — TRAIN-014: Implement candidate bundle validation and candidate-only publication

**Anti-drift implementation goal**

Produce interoperable model/agent component candidates while structurally preventing training from activating them.

**Required implementation**

1. Validate required model/adapter/processor/config/checkpoint/environment/training-report components and exact producer/input lineage.
2. Run load/inference/schema/checkpoint smoke tests in isolated workload and verify no artifact mutation.
3. Publish `CandidateBundle` with intended component role, compatibility, known limitations, training metrics, data/reward refs, and required eval suites.
4. Set status candidate/invalid/quarantined only; no deployment alias, policy cache, AgentSpec desired pointer, or live instance changes are permitted from Training Controller.
5. Notify Eval/Improvement through an event/proposal after durable publication.

**Responsibility boundaries: this task must not drift into**

- Do not equate lowest training loss with selected candidate.
- Do not permit trainer code to write deployment registry.
- Do not hide missing data/eval lineage inside metadata.

**Required integration**

- Trainer finalizes; Artifact/Lineage publish; Eval evaluates; Change/Deployment later activate.

**Validation and definition of done**

- G50–G59 and G83 assert candidate-only status and block forged/missing-lineage outputs.

**Required contracts / collaborating tasks:** `TRAIN-001`, `TRDRV-008`, `MODEL-001`, `LIN-005`

**Gold evidence:** `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G83`

### Task 15 — TRAIN-015: Implement framework plugin and non-PyTorch orchestration boundary

**Anti-drift implementation goal**

Keep flow control reusable for future architectures/frameworks while giving PyTorch a deep first implementation.

**Required implementation**

1. Define controller-to-trainer plugin interface for compatibility report, task/group proposal, data/checkpoint semantics, progress, failure policy capabilities, and candidate packaging.
2. Make framework-specific parallel/checkpoint/rendezvous details opaque versioned artifacts validated by plugin/driver.
3. Support generic OCI/executable single or multi-role workloads and observed external training with honest reduced guarantees.
4. Add a custom numerical/non-PyTorch gold trainer demonstrating core schemas contain no PyTorch-only fields.
5. Version plugin compatibility and require conformance per advertised mode.

**Responsibility boundaries: this task must not drift into**

- Do not put `state_dict`, CUDA, NCCL, or torchrun fields in foundational WorkloadSpec.
- Do not imply framework independence without a working non-PyTorch fixture.
- Do not duplicate Training Controller per framework.

**Required integration**

- Trainer Driver plugins and Sandbox/Workload realize; Driver Registry manages.

**Validation and definition of done**

- G06 and G54 run generic executable/custom trainer and compare guarantees.

**Required contracts / collaborating tasks:** `TRAIN-003`, `TRDRV-009`, `WORK-008`

**Gold evidence:** `G06`, `G54`

### Task 16 — TRAIN-016: Implement training security, data isolation, and evaluator separation

**Anti-drift implementation goal**

Prevent arbitrary training code from exfiltrating data, forging evidence, reading protected evals, or activating outputs.

**Required implementation**

1. Run training workers in sandbox profiles with read-only code/env/data/model inputs, scoped data/reward handles, declared network, no deployment/gate/registry write credentials, and output sessions only.
2. Separate trainer, evaluator, protected suite, reward derivation, and deployment principals/services/caches.
3. Reconcile actual mounts/reads/outputs with TrainingPlan and lineage; quarantine undeclared access or omitted inputs.
4. Detect secret/data leakage in logs/checkpoints/output manifests and inspect unsafe serialized objects according to policy.
5. Require trusted controller signatures/fencing for candidate/checkpoint acceptance, not worker claims.

**Responsibility boundaries: this task must not drift into**

- Do not give training containers control-plane service tokens.
- Do not mount protected eval labels or live deployment secrets.
- Do not trust pickled checkpoints blindly in privileged processes.

**Required integration**

- Sandbox/Node/Gateway/Data-Use/Artifact/Lineage/Incident enforce.

**Validation and definition of done**

- G40, G43, G82–G86 attempt exfiltration, forged lineage/result, unsafe checkpoint, reward/eval tampering.

**Required contracts / collaborating tasks:** `TRAIN-005`, `SBX-007`, `DGW-007`, `LIN-005`

**Gold evidence:** `G40`, `G43`, `G82`, `G83`, `G84`, `G85`, `G86`

### Task 17 — TRAIN-017: Build PyTorch 1→N equivalence, recovery, and project compatibility gold matrix

**Anti-drift implementation goal**

Prove real flexible-fleet control from a PyTorch project rather than only a toy scheduler diagram.

**Required implementation**

1. Create tiny deterministic Transformer/CNN/custom-loop projects for T0/T1/T2/T3 and a GPT-2-class structured project with exact source/environment/data artifacts.
2. Run CPU/GPU where available, 1 process, multi-process one node, multi-node simulated/real CI, DDP, sharded, explicit mesh, independent trials, and heterogeneous complementary roles.
3. Compare loss/parameter/update/data-consumption/checkpoint outputs under appropriate exact/numerical/statistical tolerances.
4. Inject startup failure, worker death, node loss, collective timeout, OOM, preemption, membership resize, checkpoint corruption, and control-plane failover.
5. Assert no live inference SLO regression beyond policy, no stale output acceptance, complete lineage, and candidate-only publication.
6. Publish unsupported combinations and required user changes; never mark skipped hardware cases passed.

**Responsibility boundaries: this task must not drift into**

- Do not use speedup as the only success criterion.
- Do not hide lack of hardware/network coverage.
- Do not call T0 fan-out automatic model distribution.

**Required integration**

- Gold runner, fleet simulator, optional hardware CI, Trainer/Model/Eval all integrate.

**Validation and definition of done**

- G52 and G60–G69 pass the mandatory matrix with truthful unavailable status.

**Required contracts / collaborating tasks:** `TRAIN-001`, `TRAIN-016`, `TRDRV-010`, `FND-005`

**Gold evidence:** `G52`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`

### Task 18 — TRAIN-018: Validate 1,000-device mixed training/eval/data orchestration and control-plane scale

**Anti-drift implementation goal**

Demonstrate fleet utilization and flow control at the target operating scale without claiming one 1,000-device synchronous model job.

**Required implementation**

1. Simulate or run a 1,000-node inventory with multiple compatible accelerator pools, CPUs, edge devices, inference reservations, offline devices, and physical-control nodes.
2. Schedule several fixed/elastic training groups plus independent trials, eval shards, data operators, rollouts, artifact transfer, persistent agents, and maintenance.
3. Measure admission/placement latency, queue fairness, group start, checkpoint/recovery, utilization by valid role, data locality, control traffic, and live SLOs.
4. Inject correlated node/rack/network failures, heartbeat storms, scheduler/controller failover, artifact backend slowdown, and mass preemption.
5. Verify incompatible devices are assigned complementary work or explained idle—not forced into invalid collectives.
6. Publish scale limits and bottlenecks honestly.

**Responsibility boundaries: this task must not drift into**

- Do not claim 1,000-device training from a scheduler simulation alone.
- Do not sacrifice correctness/evidence for utilization percentage.
- Do not omit idle reasons or failed workloads from results.

**Required integration**

- Fleet/Workload/Node/Artifact/Observability/Incident integrate; actual hardware scale remains a separately labelled validation tier.

**Validation and definition of done**

- G68 and G88 meet defined simulation/control-plane budgets and preserve live SLO/fencing; hardware evidence is labelled by actual node count.

**Required contracts / collaborating tasks:** `TRAIN-017`, `FLEET-011`, `WORK-010`, `OBS-008`

**Gold evidence:** `G68`, `G88`

### Component completion gate

- Training Controller controls exact projects, data, topology, groups, checkpoints, retries, and candidate outputs; algorithms remain user code/driver plugins.
- Arbitrary PyTorch support is tiered and honest, with automatic distribution only where project contracts make semantics explicit.
- No training run can read protected eval data or activate a model/agent revision, and live inference/physical reservations remain protected.

---

## Component 33 — Improvement and Evolution Controller

**Canonical component ID:** `splendor.improvement-controller`
**Plane:** `data_learning`
**Current status:** missing
**Owning package:** `crates/splendor-learning (improvement module); optimization/search algorithms remain user-space plugins`

**Implemented baseline to preserve**

There is no component that turns observed gaps into bounded hypotheses/experiments across data, model, route, world, reward, evaluator, code, memory, or agent topology. Current governance can approve actions, but no self-improvement cycle, experiment registry, candidate portfolio, convergence/stability logic, anti-self-approval separation, or novelty evidence exists.

**Exact kernel responsibility**

Own bounded improvement programs: goals/hypotheses, input evidence, experiment graphs, candidate portfolios, optimization budgets, independence requirements, stopping, and proposals to Change Controller. It never edits live components, runs algorithms itself, approves its own candidate, or activates deployment.

**Public contracts:** `ImprovementGoal`, `ImprovementProgram`, `Hypothesis`, `Experiment`, `CandidateRecord`, `OptimizationBudget`, `ImprovementCycle`, `ConvergenceReport`, `ImprovementProposal`

### Task 1 — IMPR-001: Define improvement goals, hypotheses, programs, and lifecycle

**Anti-drift implementation goal**

Make agent evolution a falsifiable sequence of governed experiments instead of a recursive “improve yourself” command.

**Required implementation**

1. Define goal with target agent/component/scope, baseline, desired metrics/objectives, hard constraints/non-regression budgets, affected slices/environments, evidence inputs, time/resource/data/human/exposure budgets, and termination criteria.
2. Define hypothesis with proposed mechanism, expected directional effects, risk/failure modes, required experiment/ablations, and falsification criteria.
3. Define program/cycle/experiment/candidate identities and states proposed, reviewed, admitted, running, evaluating, selected, rejected, inconclusive, paused, terminated, and completed.
4. Support model, adapter, data, reward, route, planner, world model, memory, tool/driver, code, topology, and policy/value candidate classes with risk-specific controls.
5. Pin exact baseline/dependencies/eval suites before a cycle.

**Responsibility boundaries: this task must not drift into**

- Do not accept “become better/aligned” without measurable goal and constraints.
- Do not let a candidate redefine success mid-cycle.
- Do not make an experiment state equivalent to deployment state.

**Required integration**

- Eval/Feedback/Incident/Observability may propose goals; Training/Data/Sandbox execute experiments; Change receives selected proposal.

**Validation and definition of done**

- G70 and G76 create complete programs with falsifiable hypotheses and rejected/inconclusive paths.

**Required contracts / collaborating tasks:** `FND-001`, `EVAL-011`, `AGREG-003`

**Gold evidence:** `G70`, `G76`

### Task 2 — IMPR-002: Implement evidence-triggered opportunity and failure proposal intake

**Anti-drift implementation goal**

Turn drift, regressions, feedback, incidents, data gaps, and research ideas into reviewable proposals without automatic self-modification.

**Required implementation**

1. Accept proposals from humans, agents, continuous eval, feedback/collection, incidents, data drift, resource/SLO analysis, and external research adapters.
2. Require source evidence refs, affected deployed revision/slices, severity/uncertainty, candidate scope, and requested budget.
3. Deduplicate/correlate overlapping proposals and retain conflicting diagnoses/hypotheses.
4. Classify immediate containment versus research/improvement; incidents/kill switches take precedence.
5. Apply authority/risk/budget review before creating a program.

**Responsibility boundaries: this task must not drift into**

- Do not let low reward alone trigger unrestricted retraining.
- Do not auto-accept an agent’s explanation of its own failure.
- Do not use improvement work to bypass incident containment.

**Required integration**

- Feedback/Eval/Incident/Observability/Event connect; Authority/Gate admit.

**Validation and definition of done**

- G48, G49, G59, G70, and G88 generate competing/drift/incident proposals and verify triage.

**Required contracts / collaborating tasks:** `IMPR-001`, `FDBK-008`, `EVAL-012`, `INC-002`

**Gold evidence:** `G48`, `G49`, `G59`, `G70`, `G88`

### Task 3 — IMPR-003: Implement experiment DAG construction and kernel validation

**Anti-drift implementation goal**

Compose collection, data work, training, evaluation, simulation, coding, and candidate packaging into bounded reproducible experiments.

**Required implementation**

1. Allow user-space optimizer/research plugins to propose a task graph with exact inputs, transforms, trials, training, eval, ablations, and outputs.
2. Validate authority/data flow/protected eval separation, resources, cycles/fan-out, candidate classes, evaluator independence, and no activation path.
3. Freeze experiment plan/digest; resolve every mutable ref and parameter search domain.
4. Support control/baseline, ablations, repeated seeds, holdouts, and counterfactual branches as first-class experiment roles.
5. Execute through Workload/Fleet and preserve all failed/negative/inconclusive results.

**Responsibility boundaries: this task must not drift into**

- Do not put a generic unrestricted AutoML loop in the kernel.
- Do not let an optimizer dynamically spawn unbounded trials.
- Do not let experiment graph access deployment or protected evaluator internals.

**Required integration**

- Workload graph realizes; Training/Data/Eval/Replay/Sandbox controllers own stages.

**Validation and definition of done**

- G55–G59, G70, and G76 execute multi-stage/ablation plans and reject hidden eval/activation edges.

**Required contracts / collaborating tasks:** `IMPR-001`, `WORK-003`, `TRAIN-001`, `EVAL-001`

**Gold evidence:** `G55`, `G56`, `G57`, `G58`, `G59`, `G70`, `G76`

### Task 4 — IMPR-004: Implement candidate portfolio, selection, and Pareto evidence

**Anti-drift implementation goal**

Select proposals using explicit objectives/constraints and uncertainty without erasing alternatives or failed experiments.

**Required implementation**

1. Maintain immutable candidate records with producing experiment, component diff, train/data/reward lineage, eval reports, risk, cost, and status.
2. Apply user-space selection policy over validated gate-ready findings: Pareto, lexicographic, constrained, robust/worst-case, Bayesian/custom, with exact policy artifact.
3. Keep dominated/rejected/inconclusive candidates and rationale; allow human review and alternative selection under policy.
4. Require independent protected/fresh confirmation before final high-risk proposal and account for adaptive search/exposure.
5. Produce an ImprovementProposal to Change Controller; no aliases/instances are modified.

**Responsibility boundaries: this task must not drift into**

- Do not select solely on training/validation metric.
- Do not hide safety/tail/resource regressions in a weighted average.
- Do not let the same optimizer change selection rules after seeing protected results.

**Required integration**

- Eval reports and Agent Value profile feed; Gate may prequalify; Change controls mutation.

**Validation and definition of done**

- G55, G56, G70, and G76 show Pareto tradeoffs, rejected high-score unsafe candidates, and independent confirmation.

**Required contracts / collaborating tasks:** `IMPR-003`, `EVAL-011`, `REWD-003`

**Gold evidence:** `G55`, `G56`, `G70`, `G76`

### Task 5 — IMPR-005: Define self-adjustment risk classes and allowed mutation envelopes

**Anti-drift implementation goal**

Permit useful autonomy while making increasingly consequential self-change require stronger independent control.

**Required implementation**

1. Define R0 ephemeral within preapproved runtime bounds (cache, scheduling, context selection); R1 reversible config/route parameter; R2 model/adapter/data/reward/world component candidate; R3 code/architecture/tool/agent topology/constraint-adjacent change; R4 authority/value-root/kernel/governance/safety-boundary change.
2. For each class define allowed proposers, sandbox/eval/approval requirements, shadow/canary, rollback, evidence retention, and maximum autonomous budget.
3. Bind immutable protected roots that no self-proposed program may remove, including gateway, authority separation, protected eval, gate, and rollback requirements.
4. Classify combined changes by highest risk/interaction and prohibit splitting a high-risk change into many low-risk changes to evade review.
5. Record risk classifier version and allow human escalation upward, not unauthorized downward.

**Responsibility boundaries: this task must not drift into**

- Do not call prompt changes always low risk.
- Do not permit self-change to modify its own risk/gate/evaluator policy in the same autonomous chain.
- Do not imply R4 is impossible; require external governance/research process.

**Required integration**

- Change/Gate/Authority enforce; AgentSpec value profile defines roots; Incident can freeze.

**Validation and definition of done**

- G70, G76, G78, G79, and G80 test risk classification and attempted decomposition/root bypass.

**Required contracts / collaborating tasks:** `IMPR-001`, `AGREG-003`, `GATE-004`

**Gold evidence:** `G70`, `G76`, `G78`, `G79`, `G80`

### Task 6 — IMPR-006: Enforce proposer–trainer–evaluator–gate–deployer separation

**Anti-drift implementation goal**

Prevent a self-improving agent from becoming its own unchecked judge and operator.

**Required implementation**

1. Assign distinct service principals/capabilities to proposal, experiment execution, candidate publication, protected evaluation, gate decision, approval, and deployment.
2. Compute dependency/independence graph and require non-self-produced evidence channels by risk.
3. Prevent candidate code/routes/models from editing eval suites, reward definitions, gate policies, deployment pointers, or evidence stores within the same authority chain.
4. Allow the agent to propose evaluators/tests as candidates, but validate them separately before use for its own promotion.
5. Record all role overlaps/exceptions and require explicit higher-level approval.

**Responsibility boundaries: this task must not drift into**

- Do not assume separate processes imply independent authority.
- Do not let a coding agent commit both code and tests/evaluator/gate unnoticed.
- Do not give the Improvement Controller deployment credentials.

**Required integration**

- Authority/Eval/Gate/Change/Deployment principals enforce; Lineage computes shared dependencies.

**Validation and definition of done**

- G44, G48, G76, G84–G86 attempt self-score/test/evidence/deployment capture and fail.

**Required contracts / collaborating tasks:** `IMPR-005`, `AUTH-002`, `EVAL-010`, `LIN-003`

**Gold evidence:** `G44`, `G48`, `G76`, `G84`, `G85`, `G86`

### Task 7 — IMPR-007: Implement multi-cycle convergence, stability, regression, and diversity tracking

**Anti-drift implementation goal**

Judge whether repeated evolution is making durable progress rather than chasing one metric or oscillating.

**Required implementation**

1. Track each cycle’s baseline/candidate, data composition, reward/evaluator versions, train/validation/protected/live metrics, slices, constraints, resource cost, uncertainty, and deployment outcomes.
2. Define user-space convergence/stability analyses with predeclared windows: improvement slope, variance, plateau, oscillation, forgetting, tail loss, calibration, reward–independent gap, and rollback rate.
3. Maintain anchor/legacy suites and fresh/rotating suites; track regression budget consumption across cumulative changes.
4. Track data/model/output diversity and real-versus-synthetic/ancestry distributions to expose recursive narrowing.
5. Stop/pause or broaden investigation when gains are not robust, constraints degrade, or evidence becomes invalid.

**Responsibility boundaries: this task must not drift into**

- Do not claim convergence from monotonically decreasing training loss.
- Do not reset baseline each cycle to hide cumulative regression.
- Do not optimize the convergence detector on the same exposed suite only.

**Required integration**

- Eval/Reward/Data/Deployment/Incident provide evidence; Evidence service materializes longitudinal report.

**Validation and definition of done**

- G56, G59, G70, and novelty GPT-2 program run multiple cycles with deliberate plateau/regression/reward-hacking cases.

**Required contracts / collaborating tasks:** `IMPR-004`, `EVAL-007`, `REWD-007`

**Gold evidence:** `G56`, `G59`, `G70`, `G86`

### Task 8 — IMPR-008: Implement bounded autonomous operation, stop, freeze, and rollback proposal semantics

**Anti-drift implementation goal**

Allow self-management to run unattended while preserving hard control and safe termination.

**Required implementation**

1. Enforce maximum cycles/trials/wall time/compute/data/human/exposure/deployment scope and per-risk autonomous envelope.
2. Check stop conditions before spawning work and at stage boundaries: budget, no progress, regression, safety/value violation, evidence invalidity, incident, policy revocation, operator freeze, or uncertainty.
3. Cancel/checkpoint active experiments through Workload Controller and preserve partial/negative evidence.
4. On deployed regression, propose/trigger policy-authorized rollback through Incident/Deployment—not direct pointer mutation.
5. Require new external authorization to resume after high-risk freeze or protected-root violation.

**Responsibility boundaries: this task must not drift into**

- Do not let the improvement agent increase its own budget or ignore stop.
- Do not delete failed candidates/experiments to resume cleanly.
- Do not make rollback depend on the failing candidate’s cooperation.

**Required integration**

- Authority/Gate/Incident/Workload/Deployment enforce.

**Validation and definition of done**

- G70, G75, G78–G80, and G88 stop runaway cycles, preserve evidence, and roll back independently.

**Required contracts / collaborating tasks:** `IMPR-005`, `WORK-005`, `INC-003`, `DEP-007`

**Gold evidence:** `G70`, `G75`, `G78`, `G79`, `G80`, `G88`

### Task 9 — IMPR-009: Implement optimizer/research plugin interface without algorithm lock-in

**Anti-drift implementation goal**

Support future AutoML, RL, evolutionary search, program synthesis, scientific optimization, and human research workflows as user space.

**Required implementation**

1. Define plugin input as bounded goal, baseline/evidence summaries, allowed candidate schemas/search space, budget, and available experiment templates.
2. Define output as hypotheses, experiment/candidate proposals, acquisition/selection suggestions, and stop recommendation—never committed changes.
3. Run plugins in sandbox/model/route workloads with no protected eval/deployment/gate access beyond redacted handles.
4. Version plugin/code/model/prompt/data and measure its own proposal quality/cost/bias over time.
5. Provide deterministic simple grid/random and rule-based reference plugins plus agentic research plugin example.

**Responsibility boundaries: this task must not drift into**

- Do not put a favored optimizer in kernel core.
- Do not let plugins emit arbitrary WorkloadSpecs without validation.
- Do not claim agentic hypothesis generation scientific novelty without experimental comparison.

**Required integration**

- Workload validates experiment graph; Model/Sandbox executes; Artifact/Lineage publish.

**Validation and definition of done**

- G55, G56, G70, and G76 run interchangeable plugins and reject budget/protected-eval bypass.

**Required contracts / collaborating tasks:** `IMPR-003`, `SBX-001`, `MODEL-003`

**Gold evidence:** `G55`, `G56`, `G70`, `G76`

### Task 10 — IMPR-010: Publish complete improvement, convergence, and novelty evidence bundles

**Anti-drift implementation goal**

Make claims about self-evolution inspectable, repeatable, and bounded by actual evidence.

**Required implementation**

1. Assemble goal/hypothesis, baseline, experiment plans, all candidates/failures, data/reward/evaluator lineage, ablations, repeated seeds, protected/fresh/live results, constraints/slices, costs, risk/independence, deployment/rollback outcomes, and limitations.
2. Distinguish engineering demonstration, controlled benchmark result, statistical evidence, real-world evidence, and unverified hypothesis.
3. Record novelty baseline comparisons and identify which contribution is architecture/interoperability/control versus learning algorithm.
4. Require reproducibility graph and executable gold manifest; unavailable hardware/human/physical evidence remains explicitly missing.
5. Sign/integrity-bind bundle and invalidate when dependent data/evaluator/worker is compromised.

**Responsibility boundaries: this task must not drift into**

- Do not claim value alignment from reward improvement alone.
- Do not claim first-of-kind or scientific novelty without literature/baseline review and independent evidence.
- Do not omit negative cycles, rollback, or failed ablations.

**Required integration**

- Evidence/Lineage/Novelty program consumes; Change/Gate review selected proposal.

**Validation and definition of done**

- G70/G76 plus novelty programs produce complete bundles and block claim wording when evidence tier is insufficient.

**Required contracts / collaborating tasks:** `IMPR-004`, `IMPR-007`, `LIN-004`, `EVID-004`

**Gold evidence:** `G70`, `G76`, `G83`, `G86`

### Component completion gate

- Improvement is a bounded experiment program producing candidate/change proposals; it never mutates live systems or approves/deploys itself.
- Goals, hypotheses, baselines, ablations, budgets, independent eval, regression, convergence, and stop criteria are explicit.
- Novelty and alignment claims are evidence-tiered and include negative results, limitations, and anti-reward-hacking checks.

---

## Component 34 — Change Controller

**Canonical component ID:** `splendor.change-controller`
**Plane:** `change_governance`
**Current status:** Missing; candidate artifacts and governance objects exist separately, but there is no canonical immutable change unit or dependency-aware change state machine.
**Owning package:** `crates/splendor-change`

**Implemented baseline to preserve**

The repository already has policy bundles, approval objects, work orders, state lineage, governance state, circuit breakers, and trace-linked runtime changes. Those are compatibility anchors. What is missing is one object that says exactly what revision is proposed, which subjects it changes, which evidence applies, how it can be validated, and how it can be rolled back.

**Exact kernel responsibility**

Owns the immutable proposal-to-change state machine, normalized diffs, impact classification, dependency order, required evidence declarations, validation receipts, and handoff to gates. It does not generate candidates, run training/evaluation algorithms, approve itself, mutate activation pointers, or execute side effects.

**Public contracts:** `ChangeSet`, `ChangeSubject`, `SubjectRevision`, `NormalizedDiff`, `ImpactReport`, `RiskClass`, `ValidationRequirement`, `RollbackContract`, `ChangeStatus`, `ChangeReceipt`

### Task 1 — CHG-001: Define the immutable ChangeSet and subject revision grammar

**Anti-drift implementation goal**

Make every proposed mutation a content-addressed, reviewable object instead of an implicit pointer update or mutable configuration edit.

**Required implementation**

1. Define `ChangeSet` with `change_id`, proposer principal, tenant/scope, objective/hypothesis reference, ordered `ChangeSubject`s, base revisions, candidate revisions, normalized diffs, causal evidence refs, requested risk class, dependencies, incompatibilities, required gates, deployment intent, rollback contract, timestamps, expiry, and extensions.
2. Define typed subjects for model, checkpoint, tokenizer/processor, dataset/view/split, policy, route graph, world-model component, agent spec, driver, environment image, code bundle, evaluator/reward definition, constraint pack, deployment configuration, and schema migration.
3. Require immutable base and candidate artifact references. For structured configuration, store canonical field-level diffs; for opaque binaries, store artifact identity plus declared semantic metadata rather than pretending to derive a meaningful textual diff.
4. Support atomic multi-subject changes because model/tokenizer/route/policy/evaluator versions often must move together; define whether subjects are all-or-nothing or staged by an explicit dependency graph.
5. Bind every ChangeSet to the exact schema versions and compatibility range used to interpret it and derive a deterministic content hash.

**Responsibility boundaries: this task must not drift into**

- Do not use a Git commit as the universal change identity; non-code artifacts and runtime state need first-class subjects.
- Do not permit in-place edits to a registered subject revision.
- Do not infer approval or deployment authority from authorship, repository ownership, or artifact possession.

**Required integration**

- Artifact/Lineage resolve revisions; Improvement/Training/Data/Eval can propose candidate subjects; Gate consumes ChangeSet; Deployment consumes only approved revision.

**Validation and definition of done**

- Round-trip fixtures cover every subject type, multi-subject atomic changes, base mismatch, missing artifact, duplicate subject, incompatible schema, and tampered diff.
- G70, G71, G72, G76, and G87 create candidate-only changes without activation.

**Required contracts / collaborating tasks:** `FND-001`, `ART-001`, `LIN-001`

**Gold evidence:** `G70`, `G71`, `G72`, `G76`, `G87`

### Task 2 — CHG-002: Implement canonical diff adapters and semantic change descriptors

**Anti-drift implementation goal**

Give reviewers and gates enough structured information to reason about a change without forcing the kernel to understand every model or domain architecture.

**Required implementation**

1. Define a `DiffAdapter` extension contract that receives two immutable subject descriptors and returns a typed, deterministic, non-authorizing semantic delta plus unsupported/unknown fields.
2. Implement core adapters for JSON/YAML configuration, AgentSpec, RouteGraph, policy/constraint bundles, dataset manifests, evaluation manifests, environment manifests, driver manifests, and deployment plans.
3. Implement provider adapters in user space for PyTorch state dict summaries, model configuration/parameter topology, tokenizer vocabulary/normalization, OCI image SBOM/package changes, and code repository diffs.
4. Represent model weight changes with hashes, tensor schema/statistical summaries, architecture/config deltas, source lineage, and checkpoint ancestry; never serialize full weights into a ChangeSet.
5. Mark uninspectable, partially inspectable, and semantically unknown regions explicitly so gates can require stronger evidence rather than assuming no change.

**Responsibility boundaries: this task must not drift into**

- Do not put framework-specific checkpoint parsers in `splendor-change`.
- Do not claim two opaque artifacts are equivalent because sizes or filenames match.
- Do not allow semantic diff metadata to carry executable code or authority.

**Required integration**

- Driver Registry discovers signed diff adapters; Sandbox runs provider diff tooling; Gate policies may require specific adapter/evidence versions by risk.

**Validation and definition of done**

- Golden diffs are deterministic across machines; malformed adapters are sandboxed and their output treated as evidence, not truth.
- G57, G70, G72, and G84 cover model, route, dataset, and code changes.

**Required contracts / collaborating tasks:** `CHG-001`, `DRREG-001`, `SBX-003`

**Gold evidence:** `G57`, `G70`, `G72`, `G84`

### Task 3 — CHG-003: Implement dependency, compatibility, and blast-radius analysis

**Anti-drift implementation goal**

Compute what a candidate can affect before evaluation and rollout so coupled changes and hidden consumers are not missed.

**Required implementation**

1. Traverse lineage, active deployment references, agent specs, route graphs, driver compatibility, dataset/evaluator dependencies, state schema versions, and physical capability bindings from every changed subject.
2. Emit an `ImpactReport` containing direct and transitive dependents, affected tenants/agents/cohorts/devices, data and locality domains, active workload classes, physical authority surfaces, rollback dependencies, and unresolved references.
3. Detect required companion changes such as tokenizer with model, route output schema with actuator input schema, world-state schema with state migration, optimizer/checkpoint format with resume plan, or code image with driver API version.
4. Detect incompatible concurrent ChangeSets and establish deterministic serialization, merge, rebase, or rejection behavior.
5. Estimate impact conservatively; any unknown active consumer raises the impact/risk requirement rather than silently excluding it.

**Responsibility boundaries: this task must not drift into**

- Do not equate artifact lineage with runtime reachability; use active references and fleet inventory too.
- Do not allow a proposer to suppress dependents from the report.
- Do not turn impact estimation into an ML guess without explicit uncertainty and conservative policy.

**Required integration**

- Lineage, Agent Registry, Deployment, Fleet, Driver Registry, Data Use, and World State expose read-only dependency indexes.

**Validation and definition of done**

- Fixture graphs cover shared models, sub-agents, offline devices, stale inventory, coupled schemas, concurrent changes, and cycles.
- G70, G72, G73, G80, and G88 prove hidden dependents and physical blast radius are found.

**Required contracts / collaborating tasks:** `CHG-001`, `LIN-003`, `AGREG-006`, `DRREG-005`

**Gold evidence:** `G70`, `G72`, `G73`, `G80`, `G88`

### Task 4 — CHG-004: Implement deterministic risk classification and anti-splitting rules

**Anti-drift implementation goal**

Translate concrete subject/impact facts into a review level without letting self-improving systems lower their own controls.

**Required implementation**

1. Implement policy-driven R0–R4 classification using subject type, authority surface, physical side effects, protected roots, data sensitivity, fleet exposure, reversibility, evaluator/reward/gate changes, code execution, and impact report.
2. Classify a multi-subject or dependent sequence at the highest applicable risk plus interaction escalations; retain all contributing reason codes.
3. Detect temporal or graph-based split attacks where multiple nominally low-risk changes collectively alter a protected evaluator, authority boundary, gate, constraint, route-to-actuator path, or rollback mechanism.
4. Allow authorized governance to escalate risk or add obligations. Lowering an automatically derived class requires a distinct, explicit exception object and cannot be proposed/approved by the affected agent.
5. Version the classifier and persist both requested and computed classes so later policy changes do not rewrite historical decisions.

**Responsibility boundaries: this task must not drift into**

- Do not classify prompt, data filter, route, reward, or evaluator changes as intrinsically low risk.
- Do not let the Improvement Controller supply the final risk class.
- Do not hide an R4 authority/value-root change inside an image or code bundle.

**Required integration**

- Improvement supplies intent; Impact supplies facts; Gate/Authority enforce computed class and exception rules.

**Validation and definition of done**

- Table-driven and property tests cover every subject/risk interaction and split sequences.
- G70, G76, G78, G79, G80, G84, and G85 attempt class evasion.

**Required contracts / collaborating tasks:** `CHG-003`, `IMPR-005`, `AUTH-005`

**Gold evidence:** `G70`, `G76`, `G78`, `G79`, `G80`, `G84`, `G85`

### Task 5 — CHG-005: Implement ChangeSet lifecycle, optimistic concurrency, and immutable validation receipts

**Anti-drift implementation goal**

Make concurrent proposal, validation, supersession, rejection, and approval behavior explicit and recoverable.

**Required implementation**

1. Define states `draft`, `submitted`, `analyzing`, `awaiting_evidence`, `ready_for_gate`, `gated`, `approved`, `rejected`, `expired`, `superseded`, `deployment_requested`, `deployed`, `rolled_back`, and `quarantined` with legal transitions.
2. Require expected base revision and expected active deployment revision when submitting; reject or explicitly rebase stale proposals rather than applying them to a different system.
3. Store each analysis/evidence/gate/deployment handoff as an immutable receipt linked to the exact ChangeSet hash and policy versions.
4. Support cancellation before deployment, but preserve the object and all negative evidence. Superseding creates a new ChangeSet with lineage rather than mutating the old one.
5. Use idempotency keys and reconciliation so retries cannot duplicate gate/deployment requests or create conflicting terminal states.

**Responsibility boundaries: this task must not drift into**

- Do not edit a ChangeSet after evidence begins; issue a successor.
- Do not allow “approved” to mean “currently deployed.”
- Do not delete rejected, expired, or rolled-back changes.

**Required integration**

- Event Log/State persist lifecycle; Gate and Deployment return signed receipts; Incident can quarantine.

**Validation and definition of done**

- State-machine model tests and crash injection cover every transition, duplicate command, stale base, concurrent approval, expiry, and quarantine.
- G02, G47, G70, G75, and G87 validate recovery.

**Required contracts / collaborating tasks:** `CHG-001`, `FND-003`, `EVT-004`

**Gold evidence:** `G02`, `G47`, `G70`, `G75`, `G87`

### Task 6 — CHG-006: Define validation requirements and evidence binding for each changed subject

**Anti-drift implementation goal**

Ensure evidence is planned from the actual change and cannot be substituted with unrelated successful tests.

**Required implementation**

1. Derive a versioned `ValidationRequirement` set from risk, subjects, impact, tenant policy, physical capability, and deployment intent.
2. Requirements name evidence type, evaluator/test manifest identity, minimum trust/freshness, required slices/environments/seeds/devices, comparison baseline, thresholds, statistical rule, independence class, and expiration.
3. Bind produced EvidenceBundles to exact candidate/base artifacts, environment, data snapshot, code, worker attestation, and requirement ID.
4. Distinguish static validation, sandbox tests, simulation, offline eval, distributed eval, HIL review, shadow/live observation, physical certification evidence, and operational rollback drill.
5. Recompute unmet requirements when the ChangeSet, impact, evaluator, policy, or evidence dependency changes.

**Responsibility boundaries: this task must not drift into**

- Do not accept “CI passed” or one aggregate metric as an untyped validation result.
- Do not reuse stale evidence after candidate or evaluator dependencies change.
- Do not let the proposer choose a weaker evaluator than policy requires.

**Required integration**

- Eval Controller, Sandbox, Evidence, Gate, Physical Simulation, and Deployment produce typed evidence.

**Validation and definition of done**

- G43–G49, G60–G70, G76, and G81–G89 cover valid, stale, mismatched, dependent, and missing evidence.

**Required contracts / collaborating tasks:** `CHG-004`, `EVID-003`, `EVAL-001`

**Gold evidence:** `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 7 — CHG-007: Define forward, backward, state, and rollback compatibility contracts

**Anti-drift implementation goal**

Prevent deployments that cannot coexist with current agents, stored state, checkpoints, routes, devices, or offline nodes.

**Required implementation**

1. For each subject type define compatibility claims: reader/writer schema range, state migration, checkpoint load/resume, route/message/percept/action schemas, driver API, hardware capability, environment/runtime, and old/new coexistence.
2. Require executable compatibility probes or declared unsupported status; never infer compatibility solely from semantic version strings.
3. Define expand–migrate–contract sequencing for state/data/schema changes and dual-read/dual-write only where explicitly justified and bounded.
4. Require rollback compatibility: last-known-good must still read state/data produced during canary, or the plan must include tested compensation/restore boundaries.
5. Track offline/edge compatibility windows and prevent central contract removal while enrolled nodes still require it unless they are quarantined/decommissioned.

**Responsibility boundaries: this task must not drift into**

- Do not call destructive data migration reversible because code can be rolled back.
- Do not require every change to be backward compatible forever; require explicit support window and migration.
- Do not let an untested checkpoint conversion become the only rollback path.

**Required integration**

- State, Artifact, Driver Registry, Agent Registry, Fleet, and Deployment run compatibility probes.

**Validation and definition of done**

- G15, G57, G66, G73, G75, and G88 test rolling coexistence, offline nodes, checkpoint/state migration, and rollback.

**Required contracts / collaborating tasks:** `CHG-003`, `STA-006`, `DRREG-005`

**Gold evidence:** `G15`, `G57`, `G66`, `G73`, `G75`, `G88`

### Task 8 — CHG-008: Implement governed code, environment, driver, and kernel change preparation

**Anti-drift implementation goal**

Treat executable changes as first-class candidates with stronger build, provenance, and privilege boundaries.

**Required implementation**

1. Accept source revision plus reproducible build manifest, dependency lockfiles, toolchain identity, tests, SBOM/provenance, signatures, environment image, and declared runtime capabilities.
2. Build in isolated sandbox workloads with no deployment credentials; publish immutable code/image/driver artifacts and build evidence.
3. For adapter/driver changes, run driver conformance, capability non-escalation, schema compatibility, fault containment, and resource accounting tests.
4. For kernel/core changes, require a separate upgrade path with compatibility suite, migration plan, rollback binary, control-plane quorum/HA plan, and external human governance; an agent cannot hot-patch its running kernel.
5. Generate a ChangeSet only after build outputs are immutable and attributable; source-only proposals are not deployable revisions.

**Responsibility boundaries: this task must not drift into**

- Do not run self-generated code in the controller process.
- Do not trust image tags or mutable package indexes as revision identity.
- Do not advertise autonomous kernel self-modification as a supported self-evolution path.

**Required integration**

- Sandbox Executor builds; Artifact/Lineage attest; Driver Registry validates; Gate requires higher risk evidence.

**Validation and definition of done**

- G19–G25 and G84–G89 cover shell/Python/OCI/Kubernetes code changes, malicious build output, driver capability escalation, and kernel-change rejection without external governance.

**Required contracts / collaborating tasks:** `CHG-001`, `SBX-004`, `ART-005`, `DRREG-004`

**Gold evidence:** `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 9 — CHG-009: Implement rollback and compensation contract validation

**Anti-drift implementation goal**

Require every deployable change to state what can actually be reversed and what only can be contained or compensated.

**Required implementation**

1. Define rollback operations for activation-pointer restore, old workload/image restore, route/policy restore, state snapshot restore, schema down-migration, data quarantine, message drain, physical safe-state, and external compensation.
2. Classify effects as reversible, restorable with data loss window, compensatable, containable only, or irreversible; require operator acknowledgement and stronger gates for the latter classes.
3. Validate that referenced last-known-good artifacts exist, are trusted, remain compatible, and can be scheduled on current fleet hardware.
4. Require rehearsal evidence at the appropriate level: local, simulation, staging, canary, physical test rig, or documented impossible/irreversible handling.
5. Bind rollback triggers and maximum detection/activation time to DeploymentPlan and incident policy.

**Responsibility boundaries: this task must not drift into**

- Do not use “rollback” as a label for an untested forward fix.
- Do not promise undo of a physical, financial, external, privacy, or data-deletion effect that cannot be undone.
- Do not garbage-collect last-known-good dependencies before rollback expiry.

**Required integration**

- Deployment executes rollback; Incident triggers containment; Artifact retention and State snapshots preserve recovery material.

**Validation and definition of done**

- G15, G18, G25, G67, G73, G75, G80, and G88 perform rollback/compensation drills including irreversible-effect classification.

**Required contracts / collaborating tasks:** `CHG-007`, `ART-007`, `STA-005`

**Gold evidence:** `G15`, `G18`, `G25`, `G67`, `G73`, `G75`, `G80`, `G88`

### Component completion gate

- A ChangeSet is immutable, base/candidate exact, multi-subject capable, impact/risk classified, compatibility checked, and evidence-bound.
- No ChangeSet can approve or deploy itself; lifecycle receipts are durable and idempotent.
- Every deployable change has honest rollback/compensation semantics and tested recovery material.

---

## Component 35 — Gate Engine

**Canonical component ID:** `splendor.gate-engine`
**Plane:** `change_governance`
**Current status:** Missing as a general evidence-to-promotion engine; current approval verifiers, policy TTL/revocation, constraints, and circuit breakers provide valuable enforcement primitives.
**Owning package:** `crates/splendor-change`

**Implemented baseline to preserve**

Existing governance and verifier objects should be reused as low-level facts and approval evidence. The missing component is a deterministic, separately authorized decision engine that evaluates a ChangeSet against explicit evidence, value/safety roots, statistical thresholds, operational obligations, and human approvals without generating the candidate.

**Exact kernel responsibility**

Owns gate policy evaluation, evidence resolution, independence/freshness checks, hard-root enforcement, obligations, exceptions, and immutable GateDecision receipts. It never trains, optimizes, edits candidates, fabricates missing evidence, or deploys.

**Public contracts:** `GatePolicy`, `GateClause`, `EvidenceRequirement`, `ValueRoot`, `ApprovalRequirement`, `ExceptionGrant`, `GateInput`, `GateDecision`, `GateObligation`, `GatePolicyBundle`

### Task 1 — GATE-001: Define a typed, deterministic GatePolicy language

**Anti-drift implementation goal**

Express promotion requirements precisely enough to evaluate and replay without embedding arbitrary privileged code.

**Required implementation**

1. Define typed clauses for artifact identity, risk/subject/impact predicates, evidence presence and trust, metric comparisons, slices, uncertainty, statistical tests, regression budgets, constraint satisfaction, approvals, compatibility, rollback rehearsal, operational SLOs, and deployment scope.
2. Support boolean composition, quantified requirements over slices/cohorts/devices, bounded arithmetic/comparisons, temporal freshness, and explicit `unknown` semantics.
3. Separate hard denial, soft advisory, required obligation, escalation, and manual-review outcomes.
4. Version policy bundles and canonicalize evaluation order/output so the same inputs produce the same decision and reason graph.
5. Provide a safe extension interface for domain-specific evaluators that emits signed facts; extension code cannot mutate gate state or directly return an unexamined “allow.”

**Responsibility boundaries: this task must not drift into**

- Do not use general Python/JavaScript evaluation in the privileged gate process.
- Do not make policy text/prompt interpretation authoritative.
- Do not hide defaults for missing metrics, NaN, empty slices, or unavailable evaluators.

**Required integration**

- Authority distributes signed policy bundles; Change supplies risk/requirements; Evidence supplies facts; Deployment consumes decision/obligations.

**Validation and definition of done**

- Parser/typechecker/fuzzer and golden decision tests cover every operator, NaN/unknown/empty input, extension failure, and version migration.
- G43–G49 and G70 validate deterministic decisions.

**Required contracts / collaborating tasks:** `FND-001`, `AUTH-006`, `CHG-006`

**Gold evidence:** `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G70`

### Task 2 — GATE-002: Implement evidence resolution, exact binding, freshness, and trust checks

**Anti-drift implementation goal**

Ensure the gate judges the exact candidate with valid evidence rather than accepting plausible but unrelated reports.

**Required implementation**

1. Resolve each requirement to immutable EvidenceBundle IDs and verify candidate/base, code, environment, dataset/split, evaluator, reward, worker, seed, and policy bindings.
2. Verify signatures/integrity, issuer authority, trust class, independence class, completion status, sample/slice coverage, timestamps/TTL, and invalidation/revocation state.
3. Reject ambiguous “latest” references and evidence generated before a relevant dependency changed.
4. Detect duplicate evidence aliases and shared underlying samples/runs so replicated references do not count as independent evidence.
5. Emit a reason graph showing satisfied, failed, missing, stale, conflicting, dependent, or unverifiable requirements.

**Responsibility boundaries: this task must not drift into**

- Do not copy metrics from dashboards or logs into gate input without EvidenceBundle identity.
- Do not count missing/failed/skipped evaluation as a pass.
- Do not allow a candidate to supply unsigned trust labels.

**Required integration**

- Evidence Service and Lineage expose verification APIs; Data Use reports protected-split access; Incident can invalidate.

**Validation and definition of done**

- G44–G49, G64–G70, G76, and G86 submit mismatched, stale, leaked, duplicated, or compromised evidence and must fail closed.

**Required contracts / collaborating tasks:** `GATE-001`, `EVID-005`, `LIN-004`, `DUC-006`

**Gold evidence:** `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G86`

### Task 3 — GATE-003: Enforce role independence and correlated-evidence policy

**Anti-drift implementation goal**

Prevent a self-improving system from producing, scoring, approving, and deploying the same change under superficially different process identities.

**Required implementation**

1. Evaluate principal, code/model, data, infrastructure, funding/ownership metadata where available, and causal lineage overlap between proposer, trainer, evaluator, evidence signer, approver, gate operator, and deployer.
2. Define independence classes such as same-process, same-agent, same-code, same-model-family, same-data, same-team/authority, independent automated, human reviewer, and external/certified.
3. Require stronger independent channels as risk increases and surface correlated failures rather than treating multiple runs of one evaluator as independent confirmation.
4. Allow transparent exceptions only through separately authorized, expiring `ExceptionGrant`s with bounded scope and explicit residual risk.
5. Record why evidence meets or fails independence requirements in the GateDecision.

**Responsibility boundaries: this task must not drift into**

- Do not infer independence from different run IDs, containers, or prompts alone.
- Do not require impossible organizational independence for every low-risk change; make it risk-based.
- Do not allow the affected agent to approve an independence exception.

**Required integration**

- Authority Principal graph, Lineage, Evidence, HIL approval adapters, and Change risk feed checks.

**Validation and definition of done**

- G44, G48, G70, G76, G84–G86 test self-evaluation, shared model/data, colluding principals, and authorized exception.

**Required contracts / collaborating tasks:** `GATE-002`, `IMPR-006`, `AUTH-002`

**Gold evidence:** `G44`, `G48`, `G70`, `G76`, `G84`, `G85`, `G86`

### Task 4 — GATE-004: Implement immutable value, safety, authority, privacy, and physical roots

**Anti-drift implementation goal**

Make non-negotiable constraints runtime-enforced roots rather than optimization preferences that can be traded for reward.

**Required implementation**

1. Define signed `ValueRoot` objects for prohibited/required outcomes, authority boundaries, protected populations/slices, privacy/data-use rules, physical safety envelopes, human control, evidence retention, evaluator protection, and rollback availability.
2. Separate universal/system roots, tenant roots, agent mission constraints, domain constraints, and deployment-specific roots with explicit precedence and conflict handling.
3. Evaluate roots against static change facts, evaluation evidence, route/world/action schemas, deployment plan, and runtime/physical safety evidence.
4. Prohibit a ChangeSet from weakening/removing its own applicable roots, gate policy, evidence independence, gateway, incident, or rollback controls in the same authority chain.
5. Support root evolution only through R4 external governance with migration, compatibility, historical audit, and independent validation.

**Responsibility boundaries: this task must not drift into**

- Do not represent values only as a scalar reward.
- Do not claim universal value alignment from one tenant policy or benchmark.
- Do not let a soft metric override a hard root.

**Required integration**

- Authority distributes roots; Constraint/Route/Gateway enforce runtime aspects; Eval provides behavioral evidence; Change classifies modifications.

**Validation and definition of done**

- G47, G61–G70, G76, G78–G80, and G85 attempt reward/root conflict, protected-slice regression, route bypass, and root self-modification.

**Required contracts / collaborating tasks:** `GATE-001`, `CHG-004`, `AUTH-006`

**Gold evidence:** `G47`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G78`, `G79`, `G80`, `G85`

### Task 5 — GATE-005: Implement statistical, uncertainty, regression, and slice gate clauses

**Anti-drift implementation goal**

Make model and agent promotion robust to noise, small samples, cherry-picked aggregates, and hidden regressions.

**Required implementation**

1. Support predeclared paired/unpaired comparisons, confidence/credible intervals, practical effect thresholds, multiple-comparison policy, bootstrap/permutation plugins, and non-inferiority/superiority/equivalence decisions.
2. Treat point estimates without sample counts/distributions/uncertainty as insufficient when policy requires statistical evidence.
3. Evaluate global metrics together with mandatory safety/value/domain slices, worst-case/tail bounds, calibration, variance, and regression budgets.
4. Support repeated seeds/environments/devices and distinguish deterministic conformance from stochastic performance evidence.
5. Require user-space statistical plugins to publish method/version/assumptions and signed results; the gate verifies declared facts and policy, not raw domain algorithms.

**Responsibility boundaries: this task must not drift into**

- Do not embed one statistical doctrine for every modality/task.
- Do not let aggregate improvement compensate for a protected hard-slice failure.
- Do not silently drop NaN, empty, low-power, or failed runs.

**Required integration**

- Eval reports distributions/slices; Evidence stores samples/summary; Gate applies declared rule.

**Validation and definition of done**

- G45–G49, G56–G70, G76, and G83 exercise low power, variance, slice regression, multiple metrics, and repeated seeds.

**Required contracts / collaborating tasks:** `GATE-002`, `EVAL-007`

**Gold evidence:** `G45`, `G46`, `G47`, `G48`, `G49`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G83`

### Task 6 — GATE-006: Implement human-in-the-loop approval and intervention requirements

**Anti-drift implementation goal**

Integrate humans as scoped evidence/authority participants without turning approval into an unaudited bypass.

**Required implementation**

1. Define approval requirements by role, competency/certification, separation, quorum, scope, action/change/deployment binding, reason, expiry, revocation, and maximum exposure.
2. Create provider-neutral adapter contracts for review UIs, ticket systems, safety boards, domain experts, and emergency operators.
3. Present a bounded review packet containing diff, risk/impact, evidence summary, unknowns, conflicts, rollback, deployment scope, and machine-readable decision choices.
4. Support approve, deny, request-more-evidence, narrow-scope, add-obligation, and emergency-containment decisions; approval never bypasses hard roots or gateway verification.
5. Handle timeout, unavailable reviewer, conflicting decisions, revocation, and stale candidate explicitly.

**Responsibility boundaries: this task must not drift into**

- Do not treat a chat response or UI button without authenticated binding as approval.
- Do not overload one approval to cover later candidate revisions.
- Do not ask humans to inspect unbounded raw traces instead of a defined evidence packet.

**Required integration**

- Existing Approval/Governance objects remain compatible; External Governance adapters map provider decisions into canonical evidence.

**Validation and definition of done**

- G12, G43, G47, G70, G75, G80, and G88 test approval binding, quorum, timeout, revocation, and emergency containment.

**Required contracts / collaborating tasks:** `GATE-001`, `AUTH-004`, `EVID-006`

**Gold evidence:** `G12`, `G43`, `G47`, `G70`, `G75`, `G80`, `G88`

### Task 7 — GATE-007: Define fail-closed behavior for unknown, conflicting, unavailable, and invalid evidence

**Anti-drift implementation goal**

Eliminate optimistic promotion when the system cannot establish required facts.

**Required implementation**

1. Define four-valued clause outcomes `pass`, `fail`, `unknown`, and `error`, plus policy mapping to deny, intervention, wait, retry, or bounded degraded mode.
2. Detect conflicting evidence with shared candidate/metric semantics and require reconciliation policy rather than choosing the favorable value.
3. Set bounded retry/deadline/backoff for temporarily unavailable evidence providers and preserve terminal failures.
4. Treat evidence corruption, signature failure, protected split exposure, evaluator compromise, and worker attestation failure as invalidation, not ordinary metric failure.
5. Emit actionable reason codes and unmet obligation list without leaking protected payloads.

**Responsibility boundaries: this task must not drift into**

- Do not coerce unknown to false/zero and then accidentally satisfy a comparison.
- Do not retry forever while a deployment waits.
- Do not make degraded mode available for hard safety/value/authority roots unless explicitly designed and bounded.

**Required integration**

- Incident handles compromise; Change waits/reconciles; Deployment cannot consume non-pass decision.

**Validation and definition of done**

- G45–G49, G66, G70, G75, G79, G80, and G86 cover provider loss, conflicting reports, corruption, and hard-root unknown.

**Required contracts / collaborating tasks:** `GATE-002`, `FND-004`

**Gold evidence:** `G45`, `G46`, `G47`, `G48`, `G49`, `G66`, `G70`, `G75`, `G79`, `G80`, `G86`

### Task 8 — GATE-008: Implement signed policy distribution, TTL, revocation, cache, and historical replay

**Anti-drift implementation goal**

Make gate behavior consistent across control-plane replicas and offline/edge sites while retaining fail-closed update semantics.

**Required implementation**

1. Package GatePolicy, ValueRoots, evaluator trust rules, approval requirements, and exception issuers into signed versioned bundles.
2. Validate issuer, audience/tenant/scope, not-before/expiry, revocation epoch, compatibility range, and monotonic anti-rollback version.
3. Maintain local verified cache for bounded operation; define what can continue under stale policy by risk and which changes must stop.
4. Record exact bundle hashes in every GateDecision and retain historical bundles needed to replay decisions.
5. Propagate emergency revocation/freeze through fleet channels with acknowledgement and quarantine for unreachable nodes.

**Responsibility boundaries: this task must not drift into**

- Do not fetch policy during historical replay unless explicitly simulating current policy.
- Do not let offline nodes promote high-risk changes on expired policy.
- Do not overwrite historical bundles with same version label.

**Required integration**

- Reuse PolicyBundle cache/signature/revocation foundations; Fleet/Node Agent distribute and report status.

**Validation and definition of done**

- G13, G14, G47, G70, G73, G75, and G88 cover stale, rollback, revoked, offline, and historical policy.

**Required contracts / collaborating tasks:** `GATE-001`, `AUTH-006`, `NODE-005`

**Gold evidence:** `G13`, `G14`, `G47`, `G70`, `G73`, `G75`, `G88`

### Task 9 — GATE-009: Produce explainable, signed, appealable GateDecision receipts

**Anti-drift implementation goal**

Make every promotion denial or approval attributable to exact policy and evidence rather than opaque controller behavior.

**Required implementation**

1. Emit `GateDecision` with decision ID, ChangeSet hash, policy/root versions, evaluated clauses, evidence bindings, reason graph, approvals/exceptions, obligations, residual risks, scope, validity, and signature.
2. Provide machine-readable minimal unsatisfied sets and human-readable redacted explanation generated from structured reasons, not an unconstrained LLM summary.
3. Support appeal/re-evaluation as a new decision with added/corrected evidence or policy—not mutation of history.
4. Expose inspect and replay APIs that can evaluate recorded inputs without contacting live providers or granting authority.
5. Record policy evaluation resource limits and guard against adversarially large reason/evidence graphs.

**Responsibility boundaries: this task must not drift into**

- Do not expose protected eval inputs or secrets in explanations.
- Do not make explanations authoritative beyond the structured decision.
- Do not erase an earlier denial when an appeal succeeds.

**Required integration**

- Evidence stores receipt; Change advances lifecycle; Deployment validates signature/scope/expiry.

**Validation and definition of done**

- G43–G49, G70, G76, and G86 compare live and replayed decisions and inspect redaction/appeal history.

**Required contracts / collaborating tasks:** `GATE-007`, `EVID-004`

**Gold evidence:** `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G70`, `G76`, `G86`

### Task 10 — GATE-010: Implement adversarial gate and evaluator-gaming conformance tests

**Anti-drift implementation goal**

Continuously prove that common self-improvement shortcuts cannot manufacture promotion.

**Required implementation**

1. Create attacks for metric spoofing, sample dropping, evaluator tampering, protected-set access, stale evidence replay, duplicate evidence, principal aliasing, risk splitting, reward/eval co-change, poisoned reviewer packet, policy downgrade, reason-graph exhaustion, and deployment-scope widening.
2. Run these against every GatePolicy version and provider extension in CI and before R3/R4 policy activation.
3. Generate synthetic malformed EvidenceBundles and real end-to-end compromised workloads to test both parser and system boundaries.
4. Maintain regression corpus from incidents and red-team findings without exposing protected eval answers to candidate agents.
5. Publish coverage and unresolved attack assumptions as evidence; passing this suite does not prove universal alignment.

**Responsibility boundaries: this task must not drift into**

- Do not reduce adversarial validation to schema fuzzing only.
- Do not let the candidate agent author and exclusively score its own red-team suite.
- Do not claim absence of reward hacking from a finite test set.

**Required integration**

- Incident lessons feed corpus; Eval/Data/Authority/Sandbox provide attack fixtures; Evidence records results.

**Validation and definition of done**

- G44, G48, G64, G69, G70, G76, G78–G80, and G84–G89 are mandatory negative cases.

**Required contracts / collaborating tasks:** `GATE-003`, `GATE-004`, `GATE-007`

**Gold evidence:** `G44`, `G48`, `G64`, `G69`, `G70`, `G76`, `G78`, `G79`, `G80`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Component completion gate

- Gate evaluation is deterministic, exact-candidate/evidence bound, fail-closed, independently authorized, and replayable.
- Hard value/safety/authority/privacy/physical roots cannot be traded against reward or modified in the same autonomous chain.
- Statistical, slice, HIL, exception, and adversarial behavior is explicit; missing evidence never becomes success.

---

## Component 36 — Deployment Controller

**Canonical component ID:** `splendor.deployment-controller`
**Plane:** `change_governance`
**Current status:** Missing as a general progressive deployment service; current run lifecycle, policy cache, state handoff, placement, circuit breakers, and physical offline behavior are foundations only.
**Owning package:** `crates/splendor-change`

**Implemented baseline to preserve**

Current Splendor can start/pause/resume local runs, distribute policy foundations, place reference work, and mediate actions. It cannot yet activate coordinated model/route/policy/agent/data/world/code revisions across fleets with shadow/canary controls and tested rollback.

**Exact kernel responsibility**

Owns deployment plans, cohort assignment, activation pointers, rollout state, health observation, stop conditions, quarantine, rollback, and last-known-good retention. It never trains/evaluates candidates, weakens gates, edits artifacts, or treats irreversible external effects as reversible.

**Public contracts:** `DeploymentPlan`, `DeploymentTarget`, `DeploymentCohort`, `ActivationSet`, `DeploymentRevision`, `RolloutStep`, `HealthContract`, `StopCondition`, `RollbackExecution`, `DeploymentReceipt`

### Task 1 — DEP-001: Define DeploymentPlan and rollout state machine

**Anti-drift implementation goal**

Make activation a separately authorized, resumable operation with exact target, cohort, scope, health, and rollback semantics.

**Required implementation**

1. Define `DeploymentPlan` with approved ChangeSet/GateDecision, target environment/fleet/tenant/agent/device selectors, exact ActivationSet, rollout strategy, cohorts, concurrency, timing, prerequisites, state migration, health contract, stop/rollback conditions, exposure budget, approvals, and expiry.
2. Define states `planned`, `validating`, `ready`, `shadowing`, `canarying`, `progressing`, `paused`, `rolling_back`, `rolled_back`, `completed`, `failed`, `cancelled`, and `quarantined` with idempotent transitions.
3. Treat activation as a versioned pointer/set change; store desired and observed revisions separately and retain previous known-good.
4. Support model-only, route/policy, complete AgentSpec, driver/image, world-model/state-schema, evaluator/reward service, and coordinated multi-subject deployments.
5. Bind every plan to the exact decision scope and reject widened targets, changed candidates, expired approval, or modified health criteria.

**Responsibility boundaries: this task must not drift into**

- Do not equate artifact publication with deployment.
- Do not let deployment infer “all devices” from an ambiguous selector.
- Do not mutate an in-flight plan to point to a new candidate.

**Required integration**

- Change/Gate authorize; Fleet/Agent/Node reconcile; Event/State persist; Incident can pause/quarantine.

**Validation and definition of done**

- Model-based state-machine tests cover every transition, retry, cancellation, stale decision, widened scope, and controller failover.
- G67, G70, G73, G75, G80, and G88 exercise rollout lifecycle.

**Required contracts / collaborating tasks:** `CHG-005`, `GATE-009`, `WORK-006`

**Gold evidence:** `G67`, `G70`, `G73`, `G75`, `G80`, `G88`

### Task 2 — DEP-002: Implement exact activation sets and atomic coordinated revision switching

**Anti-drift implementation goal**

Keep model, tokenizer, route, policy, constraints, code, drivers, world schemas, and agent configuration mutually compatible during rollout.

**Required implementation**

1. Define `ActivationSet` as a content-addressed mapping of logical roles to immutable artifacts/config revisions with compatibility assertions.
2. Resolve all aliases before plan approval; nodes receive exact refs and verify signatures/hashes locally.
3. Implement prepare/validate/activate phases and atomic local pointer swap where the target supports it; for distributed sets use staged generation numbers and explicit mixed-version compatibility.
4. Prevent partial activation of an all-or-nothing subject group and expose partial/uncertain state for intervention rather than claiming success.
5. Retain and pin last-known-good activation set plus required environment, schema, and state migration artifacts through rollback window.

**Responsibility boundaries: this task must not drift into**

- Do not use mutable “latest”, image tags, model registry stages, or branch names at node activation time.
- Do not assume a distributed multi-node switch is globally atomic.
- Do not garbage-collect old tokenizer/driver/schema dependencies prematurely.

**Required integration**

- Artifact/Lineage validate; Node Agent stages; Agent Instance Controller and Route Runtime switch local generations.

**Validation and definition of done**

- G15, G57, G67, G70, G73, and G75 test coordinated revisions, mixed versions, partial failure, and exact rollback.

**Required contracts / collaborating tasks:** `DEP-001`, `CHG-007`, `ART-007`

**Gold evidence:** `G15`, `G57`, `G67`, `G70`, `G73`, `G75`

### Task 3 — DEP-003: Implement shadow execution with side-effect suppression and comparable evidence

**Anti-drift implementation goal**

Observe candidate behavior on realistic inputs before exposure without allowing shadow output to affect the world.

**Required implementation**

1. Fork eligible percept/message/state references to shadow agent/model/route instances under distinct identities and resource budgets.
2. Route every candidate action to simulation/dry-run adapters or deny it at gateway with explicit shadow status; never reuse live actuator credentials.
3. Record paired baseline/candidate decisions, latency, resource use, constraints, value/safety indicators, and divergence while protecting user/privacy policy.
4. Handle non-determinism with repeated/paired analysis and declare where live state or external outcomes cannot be faithfully shadowed.
5. Publish shadow EvidenceBundles bound to candidate and deployment cohort; shadow success can satisfy only policy-declared requirements.

**Responsibility boundaries: this task must not drift into**

- Do not call a request mirror “shadow” if candidate actions can reach side effects.
- Do not silently double sensitive data use without authorization.
- Do not infer real physical safety solely from simulation/shadow.

**Required integration**

- Route Runtime forks; Gateway enforces no-effect; Data Use authorizes; Eval compares; Fleet reserves inference capacity.

**Validation and definition of done**

- G60, G67, G70, G73, G80, and G88 prove zero shadow side effects, paired evidence, privacy denial, and realistic divergence handling.

**Required contracts / collaborating tasks:** `DEP-002`, `ROUTE-008`, `ACT-006`, `DUC-003`

**Gold evidence:** `G60`, `G67`, `G70`, `G73`, `G80`, `G88`

### Task 4 — DEP-004: Implement canary cohorts and exposure accounting

**Anti-drift implementation goal**

Bound real-world risk while collecting live evidence from a small, representative, explicitly authorized cohort.

**Required implementation**

1. Create deterministic/randomized/stratified cohort assignment using stable identity and policy-declared protected strata without exposing sensitive labels unnecessarily.
2. Track users/agents/devices/actions/tokens/time/physical missions and irreversible-effect classes as separate exposure budgets.
3. Preserve control/baseline assignment and avoid contamination from shared mutable state unless the plan explicitly models interference.
4. Support holdout, crossover, paired, device-ring, geography/locality, tenant, and physical test-site canaries through pluggable assignment policy.
5. Emit cohort assignment and exposure receipts for every affected run/action and stop before exceeding limits.

**Responsibility boundaries: this task must not drift into**

- Do not select only easy/healthy devices and claim fleet representativeness.
- Do not use protected attributes without data-use authorization.
- Do not widen canary due to retry or controller restart.

**Required integration**

- Fleet/Agent route assignments; Gateway counts side effects; Eval analyzes; Data Use controls cohort fields.

**Validation and definition of done**

- G67, G70, G73, G75, G80, G83, and G88 test stable assignment, stratification, interference, exposure fencing, and restart.

**Required contracts / collaborating tasks:** `DEP-003`, `FLEET-006`, `DUC-004`

**Gold evidence:** `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88`

### Task 5 — DEP-005: Implement progressive fleet rollout with health-based pause and promotion

**Anti-drift implementation goal**

Expand only when each cohort meets predeclared technical, behavioral, safety, value, and operational conditions.

**Required implementation**

1. Execute ordered rings/cohorts with maximum concurrency, dwell/sample requirements, health/evidence checkpoints, and explicit promotion commands.
2. Reconcile desired/observed node and agent revision, handling disconnected, drained, busy, incompatible, stale-policy, and quarantined targets.
3. Reserve live inference and physical control resources before update; schedule downloads/prewarm outside critical windows and rate-limit network/storage pressure.
4. Pause automatically on stop conditions or insufficient evidence; require new decision when evidence window expires or scope changes.
5. Support rollback by cohort, full plan, or affected compatibility group while retaining traceable mixed-state status.

**Responsibility boundaries: this task must not drift into**

- Do not make rollout a timer-only percentage loop.
- Do not evict live inference or physical control to accelerate update.
- Do not report completion while offline selected nodes remain unknown without explicit policy disposition.

**Required integration**

- Fleet Scheduler places update/prewarm workloads; Node Agent reports; Observability/Eval feed health; Incident contains.

**Validation and definition of done**

- G66, G67, G70, G73, G75, G80, and G88 run 1,000-node rollout with offline nodes, SLO pressure, and cohort regression.

**Required contracts / collaborating tasks:** `DEP-004`, `FLEET-007`, `NODE-006`, `OBS-005`

**Gold evidence:** `G66`, `G67`, `G70`, `G73`, `G75`, `G80`, `G88`

### Task 6 — DEP-006: Implement physical/edge deployment safety protocol

**Anti-drift implementation goal**

Update robot/drone/edge agents without creating unsafe control gaps or central authority bypass.

**Required implementation**

1. Require device profile, safety envelope, local verifier version, firmware/driver compatibility, battery/power/network state, mission state, safe landing/park state, and local rollback artifact before activation.
2. Separate cloud helper/advisory models from device-local actuator authority; updating a cloud planner cannot grant direct actuator capability.
3. Schedule maintenance windows or safe-state transitions and prohibit restart/update while executing a non-interruptible physical action unless certified handover exists.
4. Stage artifacts, validate locally, switch generation, run self-tests/simulation where available, and retain autonomous safe fallback for disconnection.
5. Use hardware/vendor certification adapters as evidence where required; Splendor does not claim motor/firmware hard-real-time certification.

**Responsibility boundaries: this task must not drift into**

- Do not reboot or replace a controller mid-flight/motion by default.
- Do not let central rollout disable local emergency stop/safety verifier.
- Do not claim a software canary proves hardware safety across untested devices.

**Required integration**

- Device Profile/Safety Gateway, Node Agent, Fleet, Gate, Incident, and physical adapter integrate.

**Validation and definition of done**

- G73, G74, G75, G79, G80, and G88 use simulated drone/robot plus hardware-in-loop contract fixtures for disconnect, stale policy, unsafe state, and rollback.

**Required contracts / collaborating tasks:** `DEP-005`, `ACT-007`, `NODE-009`, `GATE-004`

**Gold evidence:** `G73`, `G74`, `G75`, `G79`, `G80`, `G88`

### Task 7 — DEP-007: Implement rollback, restore, compensation, and post-rollback verification

**Anti-drift implementation goal**

Return to a known safe revision quickly and honestly when rollout fails.

**Required implementation**

1. Trigger from automatic stop condition, incident command, authorized operator, policy revocation, or failed rollout step; fence further candidate exposure first.
2. Restore activation set by cohort and reconcile every selected target; account for offline nodes and quarantine those that cannot confirm rollback.
3. Execute declared state/schema/data restore or compensation steps in dependency order with idempotent receipts and explicit irreversible residual effects.
4. Run post-rollback health, compatibility, state-integrity, and physical-safe-state checks before declaring success.
5. Preserve failed candidate/evidence/incident lineage and prevent automatic re-promotion without a successor ChangeSet and new evidence.

**Responsibility boundaries: this task must not drift into**

- Do not call rollback complete when only control-plane desired state changed.
- Do not overwrite evidence or state that explains the failure.
- Do not retry a failed candidate automatically after rollback.

**Required integration**

- Incident initiates; Node/Agent/State/Artifact execute; Gate invalidates old approval as policy dictates.

**Validation and definition of done**

- G15, G18, G67, G70, G73, G75, G80, G87, and G88 inject failure at every rollback stage.

**Required contracts / collaborating tasks:** `DEP-002`, `CHG-009`, `INC-003`

**Gold evidence:** `G15`, `G18`, `G67`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88`

### Task 8 — DEP-008: Implement deployment health contracts and multi-source stop conditions

**Anti-drift implementation goal**

Use predeclared operational and behavioral evidence to pause/rollback rather than improvised dashboard judgment.

**Required implementation**

1. Define health clauses for availability, latency, errors, resource saturation, queueing, action denials/failures, constraint/value/safety violations, model quality, data drift, reward/eval divergence, physical telemetry, incident count, and evidence completeness.
2. Specify window, baseline/cohort comparison, minimum samples, uncertainty, slice, severity, action (observe/pause/rollback/kill), and maximum reaction time.
3. Evaluate authoritative EvidenceBundles/events, not exporter dashboards; tolerate bounded telemetry delay while failing closed for critical local physical signals.
4. Handle correlated fleet failures, missing telemetry, and metric schema/version changes explicitly.
5. Record every stop evaluation and action so later analysis can distinguish false alarm, real regression, and controller failure.

**Responsibility boundaries: this task must not drift into**

- Do not optimize solely for system SLOs while ignoring behavior/value/safety.
- Do not permit a deployed candidate to suppress its own health signal.
- Do not use one global threshold for every heterogeneous device without declared normalization.

**Required integration**

- Observability exports non-authoritative views; Event/Evidence/Eval/Incident provide authoritative inputs.

**Validation and definition of done**

- G67, G70, G73, G75, G80, G83, and G88 test missing/corrupt telemetry, slice regression, local physical stop, and reaction deadlines.

**Required contracts / collaborating tasks:** `DEP-001`, `EVID-003`, `OBS-001`, `INC-002`

**Gold evidence:** `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88`

### Task 9 — DEP-009: Implement safe state migration and mixed-version operation

**Anti-drift implementation goal**

Support evolving persistent agents and world models without corrupting long-lived state or forcing fleet-wide downtime.

**Required implementation**

1. Execute declared expand/migrate/contract plans as separate workloads with checkpoints, bounded batches, validation, backpressure, and rollback/restore points.
2. Version StateNode/world/message/percept/action schemas and require old/new readers/writers to declare compatibility during mixed rollout.
3. Support lazy migration on read only when deterministic, idempotent, resource-bounded, and separately evidenced; otherwise use explicit migration workload.
4. Fence writes during non-concurrent-safe migrations or route them through a compatibility layer with auditable transforms.
5. Verify semantic invariants, counts/hashes/slices, and application-specific migration evaluators before contracting old schema.

**Responsibility boundaries: this task must not drift into**

- Do not hide migration inside startup code with unbounded runtime.
- Do not delete old fields/state before all selected offline nodes and rollback windows are resolved.
- Do not pretend byte-level success proves semantic state correctness.

**Required integration**

- State Service owns commits/snapshots; user-space migration driver transforms; Workload/Fleet run; Eval validates; Change sequences.

**Validation and definition of done**

- G15, G31, G57, G70, G73, and G75 cover agent/world-state migration, concurrent writes, offline nodes, and semantic failure.

**Required contracts / collaborating tasks:** `DEP-001`, `STA-006`, `CHG-007`, `DODRV-006`

**Gold evidence:** `G15`, `G31`, `G57`, `G70`, `G73`, `G75`

### Task 10 — DEP-010: Implement offline and intermittently connected deployment policy

**Anti-drift implementation goal**

Keep edge agents safe and auditable when central rollout coordination is unavailable.

**Required implementation**

1. Distribute signed deployment intents, activation sets, policy/root bundles, expiry, prerequisites, rollback, and local stop rules to node cache.
2. Require monotonic generation/anti-rollback checks, local hash/signature validation, and device-local safety/authority verification.
3. Define allowed actions on expiry or loss of central evidence by risk: continue known-good, degrade, stop selected capabilities, return safe state, or require operator.
4. Buffer activation/health/evidence events with integrity and synchronize on reconnect; detect conflicting central/local decisions and quarantine uncertainty.
5. Prevent a disconnected node from autonomously promoting a new candidate unless a narrowly scoped preauthorized plan explicitly allows it.

**Responsibility boundaries: this task must not drift into**

- Do not assume wall-clock accuracy on disconnected devices; use signed validity plus monotonic/local policy.
- Do not silently accept central revision rollback on reconnect.
- Do not let offline availability override physical safety roots.

**Required integration**

- Node Agent policy cache/trace buffer; Gate bundle; Fleet registry; Incident reconcile.

**Validation and definition of done**

- G13, G14, G73, G75, G79, G80, and G88 test expiry, reconnect, generation conflict, clock skew, and safe fallback.

**Required contracts / collaborating tasks:** `DEP-006`, `GATE-008`, `NODE-005`

**Gold evidence:** `G13`, `G14`, `G73`, `G75`, `G79`, `G80`, `G88`

### Task 11 — DEP-011: Harden deployment control plane for production availability and security

**Anti-drift implementation goal**

Ensure rollout authority cannot be lost, duplicated, or forged during failover or network partition.

**Required implementation**

1. Run replicated controllers with leader/lease fencing or equivalent single-writer semantics per deployment scope and durable desired state.
2. Authenticate/mTLS all node/control connections, authorize each command, rotate credentials, validate audience, and audit operator/service actions.
3. Use idempotent commands and generation fencing so stale controllers cannot activate or roll back after failover.
4. Implement rate limits, admission quotas, queue isolation, backpressure, and disaster recovery for deployment metadata.
5. Exercise backup/restore, controller loss, partial region loss, split brain, clock skew, and compromised credential containment.

**Responsibility boundaries: this task must not drift into**

- Do not expose the current local insecure daemon as production rollout control.
- Do not rely on eventual last-write-wins for activation authority.
- Do not let availability failover bypass policy/gate verification.

**Required integration**

- Identity/Authority/Secret Broker/Event/State/Incident provide foundations; daemon becomes API facade.

**Validation and definition of done**

- G66, G70, G73, G75, G87, and G88 include controller failover, stale leader, credential revocation, and regional outage.

**Required contracts / collaborating tasks:** `DEP-001`, `AUTH-007`, `SECR-005`, `EVT-007`

**Gold evidence:** `G66`, `G70`, `G73`, `G75`, `G87`, `G88`

### Task 12 — DEP-012: Publish deployment, rollback, and real-world outcome evidence

**Anti-drift implementation goal**

Close the evolution loop with exact proof of what reached which agents/devices and what happened afterward.

**Required implementation**

1. Produce DeploymentEvidence with selected/actual cohorts, activation receipts, exposure, health evaluations, stop decisions, incidents, rollback/compensation, residual mixed state, and final outcome.
2. Link live feedback/evals to deployment revision and cohort while preserving privacy/data-use rules and delayed outcomes.
3. Separate engineering deployment success from behavioral improvement, value-alignment evidence, physical safety evidence, and scientific novelty claims.
4. Retain enough node/local receipts to audit offline and partially failed rollouts without central logs being the sole truth.
5. Feed outcome evidence back to Improvement Controller only as authorized data/evidence; deployment does not derive reward or retrain.

**Responsibility boundaries: this task must not drift into**

- Do not declare success from desired-state completion only.
- Do not treat absence of incident reports as evidence of safety.
- Do not train on live deployment data without collection/data-use/feedback contracts.

**Required integration**

- Evidence/Lineage/Feedback/Improvement consume; Incident may invalidate; Observability exports redacted views.

**Validation and definition of done**

- G67, G70, G73, G75, G80, G83, and G88 produce complete successful and failed deployment bundles.

**Required contracts / collaborating tasks:** `DEP-005`, `DEP-007`, `EVID-004`, `FDBK-006`

**Gold evidence:** `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88`

### Component completion gate

- Only an exact, approved, non-expired ChangeSet/ActivationSet can deploy, and deployment authority is fenced.
- Required done state includes shadow, canary, progressive rollout, SLO/value/safety stop, mixed-version handling, physical/offline policy, and honest rollback.
- Actual exposure and outcomes—not desired state—produce durable deployment evidence and feed controlled improvement.

---

## Component 37 — Incident Controller

**Canonical component ID:** `splendor.incident-controller`
**Plane:** `change_governance`
**Current status:** Partial foundations only: escalation, circuit breakers, interventions, action denials, trace durability state, and physical safety outcomes exist, but there is no cross-plane incident lifecycle.
**Owning package:** `crates/splendor-change`

**Implemented baseline to preserve**

The current runtime can fail closed and record intervention/denial conditions. The missing service must correlate safety, value, data, evaluation, training, fleet, deployment, security, and physical failures; contain them through existing authority/gateway mechanisms; preserve evidence; and coordinate recovery.

**Exact kernel responsibility**

Owns incident identity, classification, correlation, containment requests, investigation evidence, recovery criteria, closure, and lessons. It does not silently alter models/data/reward, execute unverified actions, or use incident payloads for training without declared collection and data-use policy.

**Public contracts:** `Incident`, `IncidentSignal`, `IncidentClass`, `Severity`, `ContainmentPlan`, `ContainmentAction`, `AffectedScope`, `InvestigationRecord`, `RecoveryPlan`, `IncidentLesson`

### Task 1 — INC-001: Define incident taxonomy, identity, severity, and lifecycle

**Anti-drift implementation goal**

Give failures across agent, learning, data, fleet, security, and physical planes one explicit management object.

**Required implementation**

1. Define classes for safety/value violation, unauthorized action, privacy/data-use breach, data poisoning/contamination, reward/evaluator compromise, model/agent regression, physical hazard/near miss, fleet availability, resource starvation, checkpoint/state corruption, supply-chain/driver compromise, credential breach, evidence integrity failure, and control-plane split brain.
2. Define severity using actual/potential harm, affected scope, reversibility, authority exposure, physical risk, data sensitivity, uncertainty, and time criticality.
3. Define states `detected`, `triaged`, `containing`, `contained`, `investigating`, `recovering`, `monitoring`, `closed`, and `reopened` with legal transitions and ownership/acknowledgement deadlines.
4. Represent suspected, confirmed, disproven, and unknown facts separately and maintain causal links to signals, runs, actions, changes, deployments, data, evidence, nodes, and principals.
5. Support incident merging/splitting with immutable lineage and prevent duplicate alerts from creating conflicting containment.

**Responsibility boundaries: this task must not drift into**

- Do not use free-form ticket text as the canonical incident state.
- Do not downgrade severity because no harm is yet observed when evidence is missing.
- Do not assume every failed workload is an incident; use policy/classification.

**Required integration**

- Event Log supplies signals; Authority assigns roles; Deployment/Gateway/Fleet/Data/Eval link affected objects.

**Validation and definition of done**

- Taxonomy fixtures and state-machine tests cover duplicates, merge/split, severity escalation, reopening, unknown scope, and clock skew.
- G47, G64, G69, G70, G73, G75, G80, G86–G89 generate incidents.

**Required contracts / collaborating tasks:** `FND-001`, `EVT-003`, `AUTH-002`

**Gold evidence:** `G47`, `G64`, `G69`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89`

### Task 2 — INC-002: Implement signal ingestion, correlation, and bounded detection rules

**Anti-drift implementation goal**

Detect cross-plane failures without making telemetry exporters or opaque anomaly models authoritative.

**Required implementation**

1. Ingest typed authoritative events/evidence from gateway, constraints, physical safety, data use, collection, feedback/reward/eval, training, fleet/node, state/trace, change/gate/deployment, secret/authority, and external monitors.
2. Implement deterministic threshold/sequence/correlation rules for known hazards and a plugin interface for anomaly detectors whose outputs remain signals requiring policy evaluation.
3. Correlate by causal IDs, deployment/cohort, artifact/data/evaluator lineage, time window, node/fleet, agent/route, principal, and shared dependency.
4. Deduplicate storms while retaining counts/samples and protect critical local physical events from central backpressure.
5. Record detector/rule version, inputs, uncertainty, latency, and missed-data state for every created incident.

**Responsibility boundaries: this task must not drift into**

- Do not let an ML anomaly detector directly execute containment without policy.
- Do not depend on high-cardinality dashboards as source of truth.
- Do not sample away safety/security/authority events.

**Required integration**

- Event/Evidence are sources; Observability can provide non-authoritative signals; Gate/Deployment health rules can open incidents.

**Validation and definition of done**

- G66, G67, G69, G70, G73, G75, G80, G87–G89 test storms, missing telemetry, correlated fleet failure, and local physical detection.

**Required contracts / collaborating tasks:** `INC-001`, `EVT-006`, `EVID-003`

**Gold evidence:** `G66`, `G67`, `G69`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88`, `G89`

### Task 3 — INC-003: Implement policy-authorized containment and kill-switch orchestration

**Anti-drift implementation goal**

Stop harm quickly through existing enforcement points without granting the incident service arbitrary side effects.

**Required implementation**

1. Define containment actions: deny/fence actions or capability scopes, pause agents/workloads/training/collection, revoke work orders/policy/secrets/drivers/artifacts, freeze change/deployment, stop rollout, rollback activation, quarantine node/data/evidence/model, isolate network/environment, require physical safe state, and request human/emergency service.
2. Map incident class/severity/scope to preauthorized actions and required approvals; emergency authority is narrow, time-limited, traceable, and cannot broaden capability.
3. Issue signed containment commands through Authority/Gateway/Fleet/Deployment/Data Use rather than directly editing their stores.
4. Use generation/fencing tokens and acknowledgement tracking; unreachable affected nodes remain explicitly uncontained and may be quarantined on reconnect.
5. Prioritize local device emergency stop/safe envelope over central coordination when latency/connectivity is inadequate.

**Responsibility boundaries: this task must not drift into**

- Do not create a universal root credential in Incident Controller.
- Do not call a database flag a kill switch unless all enforcement points acknowledge it.
- Do not let containment destroy evidence by default.

**Required integration**

- Reuse KillSwitch/CircuitBreaker/Intervention foundations; Authority, Gateway, Deployment, Fleet, Node, Data Use execute.

**Validation and definition of done**

- G12–G14, G47, G70, G73, G75, G79, G80, G87, and G88 verify propagation, partial acknowledgement, local safety, expiry, and stale-controller fencing.

**Required contracts / collaborating tasks:** `INC-001`, `AUTH-005`, `DGW-007`, `DEP-007`

**Gold evidence:** `G12`, `G13`, `G14`, `G47`, `G70`, `G73`, `G75`, `G79`, `G80`, `G87`, `G88`

### Task 4 — INC-004: Implement evidence preservation, forensic snapshots, and chain of custody

**Anti-drift implementation goal**

Retain enough trustworthy state to investigate without leaking protected data or allowing a compromised component to rewrite history.

**Required implementation**

1. Capture immutable references to relevant event ranges, state heads/snapshots, workload/worker leases, artifact/data/model/eval lineage, deployment/gate decisions, driver receipts, policy/authority versions, and node-local buffers.
2. Request bounded forensic snapshots through service APIs with data minimization, redaction, legal/retention policy, encryption, and role-scoped access.
3. Hash/sign manifests, record collector principal/time/tool versions, and distinguish unavailable, suspected-compromised, and verified evidence.
4. Freeze garbage collection for implicated artifacts/evidence while avoiding unbounded retention through explicit holds and review.
5. Support offline device evidence synchronization and conflict/quarantine if local chain integrity is broken.

**Responsibility boundaries: this task must not drift into**

- Do not copy every raw payload into incident storage.
- Do not let an investigator mutate the original evidence object.
- Do not expose protected eval answers, secrets, or personal data in general incident views.

**Required integration**

- Evidence/Artifact/State/Event/Secret/Data Use/Node expose snapshot/ref APIs; Incident stores manifest only.

**Validation and definition of done**

- G14, G47, G64, G70, G73, G75, G80, G86–G89 test redaction, compromised store, missing node, retention hold, and chain verification.

**Required contracts / collaborating tasks:** `INC-002`, `EVID-005`, `EVT-005`, `SECR-006`

**Gold evidence:** `G14`, `G47`, `G64`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89`

### Task 5 — INC-005: Implement lineage-based blast-radius and compromise propagation

**Anti-drift implementation goal**

Identify every model, dataset, evaluation, agent, deployment, or device that may inherit a compromised dependency.

**Required implementation**

1. Traverse forward and backward lineage from implicated data sources, code/images/drivers, model/checkpoints, reward/evaluator definitions, worker attestations, policy roots, secrets, and state migrations.
2. Intersect lineage with active deployment/agent/fleet inventory and historical exposure to produce affected, potentially affected, and cleared sets with reasons.
3. Invalidate or quarantine derived EvidenceBundles, candidates, ChangeSets, GateDecisions, and deployments according to policy; preserve immutable history.
4. Handle incomplete lineage conservatively and create follow-up evidence tasks rather than marking unknown descendants safe.
5. Update impact as late-arriving offline events or new compromise indicators arrive and reopen incidents when necessary.

**Responsibility boundaries: this task must not drift into**

- Do not invalidate all artifacts globally when scoped evidence exists.
- Do not clear a descendant solely because its metric looked normal.
- Do not mutate historical gate decisions; attach invalidation status.

**Required integration**

- Lineage provides graph; Artifact/Evidence/Gate/Deployment/Data Use apply quarantine/revocation.

**Validation and definition of done**

- G39, G47, G64, G69, G70, G73, G76, G86–G89 cover poisoned data, compromised evaluator/worker/image, incomplete lineage, and late device sync.

**Required contracts / collaborating tasks:** `INC-004`, `LIN-005`, `EVID-005`

**Gold evidence:** `G39`, `G47`, `G64`, `G69`, `G70`, `G73`, `G76`, `G86`, `G87`, `G88`, `G89`

### Task 6 — INC-006: Implement investigation workspaces and controlled diagnostic workloads

**Anti-drift implementation goal**

Let humans and agents investigate safely without giving incident tooling uncontrolled access to production or protected evidence.

**Required implementation**

1. Create scoped investigation work orders with read-only evidence/data refs, bounded sandbox/network/tools, expiration, audit, and optional two-person access for sensitive material.
2. Run queries, replay/simulation, model/eval reproduction, code analysis, and device diagnostics as ordinary WorkloadSpecs under resource/data-use controls.
3. Support hypotheses, findings, confidence, disconfirming evidence, and causal graph updates as immutable investigation records.
4. Require gateway verification for any diagnostic action against a live service/device and default to simulation/read-only.
5. Separate agent-generated analysis from confirmed facts and human/external determinations.

**Responsibility boundaries: this task must not drift into**

- Do not grant shell/database/cluster access simply because an incident is severe.
- Do not let diagnostic workloads write to original data/state.
- Do not use an LLM narrative as the root-cause fact record.

**Required integration**

- Sandbox/Replay/Workload/Data Use/Authority provide bounded environment; Evidence records outputs.

**Validation and definition of done**

- G19–G25, G47, G70, G75, G80, G86–G89 run reproducible investigation with denied privilege escalation and preserved uncertainty.

**Required contracts / collaborating tasks:** `INC-004`, `SBX-001`, `RPLY-004`, `AUTH-003`

**Gold evidence:** `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G47`, `G70`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89`

### Task 7 — INC-007: Implement recovery plans, validation, and controlled unfreeze

**Anti-drift implementation goal**

Restore operation only when containment, repair, evidence, and policy requirements are satisfied.

**Required implementation**

1. Define RecoveryPlan with repair/replacement artifacts, data/state remediation, credential rotation, policy/root updates, rollback/forward deployment, affected scope, required validation, owners, and residual risk.
2. Execute recovery operations through normal ChangeSet/Gate/Deployment/Workload paths; emergency containment authority cannot silently become promotion authority.
3. Require post-recovery eval, conformance, integrity, SLO, safety/value, physical self-test, and monitoring evidence appropriate to incident class.
4. Unfreeze capabilities/scopes incrementally with new generation tokens and observe for recurrence during a defined monitoring window.
5. Keep unresolved or unreachable targets quarantined and document service degradation rather than declaring global recovery.

**Responsibility boundaries: this task must not drift into**

- Do not close an incident because containment succeeded.
- Do not bypass normal gates for the permanent fix except a narrowly documented emergency path with later reconciliation.
- Do not restore revoked credentials or compromised artifacts.

**Required integration**

- Change/Gate/Deployment execute fix; Secret/Authority rotate; Eval/Evidence validate; Fleet/Node reconcile.

**Validation and definition of done**

- G47, G64, G70, G73, G75, G80, G86–G89 cover recovery, recurrence, partial fleet, emergency fix, and controlled unfreeze.

**Required contracts / collaborating tasks:** `INC-003`, `INC-005`, `CHG-001`, `GATE-001`, `DEP-001`

**Gold evidence:** `G47`, `G64`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89`

### Task 8 — INC-008: Implement closure, lessons, policy updates, and gold regression extraction

**Anti-drift implementation goal**

Turn incidents into durable improvements without silently training on incident data or rewriting history.

**Required implementation**

1. Require closure criteria: containment complete/accepted residual scope, root/contributing causes with evidence confidence, exposure/harm assessment, recovery verification, outstanding actions, and accountable approvals.
2. Create `IncidentLesson` objects proposing detector, constraint, eval slice, data quality check, gate clause, driver conformance, rollback drill, documentation, or architecture changes.
3. Route each proposed lesson through the appropriate ChangeSet and data-use process; incident data becomes training/eval data only after collection consent, purpose, minimization, split protection, and lineage are established.
4. Extract sanitized regression fixtures/gold scenarios that reproduce the failure without leaking secrets/protected eval answers or personal data.
5. Track action completion and recurrence statistics; reopening links to prior incident and invalidates overconfident closure assumptions.

**Responsibility boundaries: this task must not drift into**

- Do not auto-add raw incident transcripts/sensor/user data to training corpora.
- Do not force one root cause when evidence supports multiple/unknown causes.
- Do not measure success only by ticket closure.

**Required integration**

- Collection/Data Use/Data Operator/Eval/Change receive proposed lessons; Gold catalog gains versioned fixtures.

**Validation and definition of done**

- G39, G47, G64, G69, G70, G73, G76, and G86–G89 produce sanitized regression cases and reject unauthorized training reuse.

**Required contracts / collaborating tasks:** `INC-007`, `COLL-006`, `DUC-002`, `CHG-001`

**Gold evidence:** `G39`, `G47`, `G64`, `G69`, `G70`, `G73`, `G76`, `G86`, `G87`, `G88`, `G89`

### Task 9 — INC-009: Implement game days and cross-plane failure drills

**Anti-drift implementation goal**

Demonstrate that containment and recovery work under realistic multi-failure conditions before relying on them for autonomous evolution.

**Required implementation**

1. Define signed drill plans with target test/staging scope, injected faults, safety exclusions, observers, expected signals, containment/rollback deadlines, and abort controls.
2. Inject node loss, network partition, stale leader, corrupted checkpoint/state/trace, poisoned data, compromised evaluator, leaked protected split, malicious driver/image, policy revocation, runaway training, live inference starvation, unsafe physical proposal, and rollback failure.
3. Measure detection latency, containment coverage, acknowledgement, evidence completeness, recovery time, false positives, and operator load.
4. Run local deterministic fixtures continuously and larger fleet/physical drills on governed schedules; production drills require explicit approval and blast-radius limits.
5. Feed failures into IncidentLesson and gate readiness evidence; failed drills block relevant autonomous risk levels.

**Responsibility boundaries: this task must not drift into**

- Do not run destructive chaos experiments without scope/abort authority.
- Do not prewire detectors only to the exact injected event path.
- Do not call tabletop discussion equivalent to executable recovery evidence.

**Required integration**

- Workload/Fleet/Node/Sandbox/Data/Eval/Deployment/Physical Simulation inject; Incident coordinates and Evidence records.

**Validation and definition of done**

- G66, G69, G70, G73, G75, G80, and G86–G89 form the mandatory drill matrix.

**Required contracts / collaborating tasks:** `INC-001`, `FND-005`, `DEP-007`, `GATE-010`

**Gold evidence:** `G66`, `G69`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89`

### Component completion gate

- Incidents span all planes, have explicit uncertainty/lifecycle, and invoke containment only through authorized enforcement services.
- Evidence preservation and lineage-based blast radius survive compromise, offline nodes, and controller failure.
- Recovery uses normal controlled change/deployment paths; incident data never becomes learning data implicitly; executable game days prove response.

---

## Component 38 — Observability Exporter

**Canonical component ID:** `splendor.observability-exporter`
**Plane:** `event_state_evidence`
**Current status:** Partial telemetry/trace export exists, but no unified typed metrics/log/trace/evidence export boundary with privacy, cardinality, and non-authority rules.
**Owning package:** `crates/splendor-evidence`

**Implemented baseline to preserve**

The repository has trace stores, trace aggregation, fleet telemetry snapshots, daemon inspection, and audit export. These remain authoritative kernel records. The exporter must derive external telemetry from them without becoming a second truth source or leaking sensitive/percept/eval/secret payloads.

**Exact kernel responsibility**

Owns subscription, transformation, redaction, aggregation, sampling, and export to external observability backends. It cannot authorize, gate, schedule, mutate state, or replace durable event/evidence stores. Alerts from exporters are signals only until evaluated by the owning service.

**Public contracts:** `TelemetrySubscription`, `MetricDescriptor`, `TelemetryRecord`, `ExportPolicy`, `RedactionProfile`, `AggregationWindow`, `ExporterDriver`, `ExportReceipt`, `SLODefinition`

### Task 1 — OBS-001: Define the canonical telemetry taxonomy and semantic conventions

**Anti-drift implementation goal**

Make metrics and operational signals comparable across agent, data, training, evaluation, fleet, physical, and governance planes.

**Required implementation**

1. Define names, units, dimensions, monotonicity, aggregation, allowed cardinality, temporality, and source event/evidence mapping for each metric family.
2. Cover workload queue/run/attempt/lease, node/device capacity/health, agent ticks/routes/messages/state, model inference, trainer/checkpoint/collective, dataset/collection/quality, feedback/reward/eval, change/gate/deployment/incident, gateway/actions, and physical safety.
3. Distinguish counters, gauges, histograms/distributions, event summaries, traces, logs, evidence references, and SLO calculations rather than flattening all into logs.
4. Version semantic conventions and define compatibility/deprecation so dashboards/alerts cannot silently reinterpret a metric.
5. Carry stable low-cardinality IDs or pseudonymous cohort refs; high-cardinality object identities remain trace/evidence links, not default metric labels.

**Responsibility boundaries: this task must not drift into**

- Do not expose arbitrary user payload fields as labels.
- Do not use one overloaded “reward” or “success” metric across agents/evaluators.
- Do not treat exported metric values as authoritative state mutations.

**Required integration**

- All services emit typed events/evidence; exporter maps to conventions; SDK/adapters can register namespaced non-authoritative metrics.

**Validation and definition of done**

- Schema/golden tests validate units, cardinality, aggregation, compatibility, and forbidden labels.
- G01–G89 must emit defined coverage without raw payload leakage.

**Required contracts / collaborating tasks:** `FND-001`, `EVT-001`, `EVID-001`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G71`, `G72`, `G73`, `G74`, `G75`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 2 — OBS-002: Implement subscription, filtering, transformation, and export receipts

**Anti-drift implementation goal**

Export selected records reliably without coupling kernel progress to external monitoring availability.

**Required implementation**

1. Define subscriptions by tenant/scope, record type, schema/version, fields, aggregation, rate, destination, retention, redaction profile, and delivery semantics.
2. Read through Event/Evidence/State query APIs or durable outbox cursors; never tail internal database tables as a public contract.
3. Transform deterministically, batch/compress, retry with bounded backoff, checkpoint cursor, and emit ExportReceipts including drops, redactions, lag, and destination acknowledgement.
4. Define at-least-once export with downstream deduplication IDs by default; support best-effort metrics and stronger audit export as separate profiles.
5. Apply backpressure/drop policy by priority so exporter failure cannot block required-before-effect kernel events.

**Responsibility boundaries: this task must not drift into**

- Do not make an external SaaS outage stop local physical safety or core state commit unless an explicit audit policy requires it.
- Do not silently drop critical audit records under metric pressure.
- Do not claim exactly-once across arbitrary external backends without protocol support.

**Required integration**

- Event/Evidence provide cursors; Secret Broker supplies destination credentials; Driver Registry loads exporter providers.

**Validation and definition of done**

- Fault tests cover duplicate delivery, backend outage, cursor corruption, restart, schema change, overload, and priority isolation.
- G14, G47, G66, G73, G75, and G87 exercise export degradation.

**Required contracts / collaborating tasks:** `OBS-001`, `EVT-006`, `SECR-003`, `DRREG-001`

**Gold evidence:** `G14`, `G47`, `G66`, `G73`, `G75`, `G87`

### Task 3 — OBS-003: Implement privacy, redaction, protected-eval, and secret-safe export controls

**Anti-drift implementation goal**

Prevent observability from becoming an uncontrolled data exfiltration path.

**Required implementation**

1. Classify telemetry fields by public/internal/sensitive/secret/protected-eval/personal/physical-location and bind export to DataUse/Authority policy.
2. Redact, hash/tokenize, bucket, aggregate, sample, or suppress fields before they leave the trusted boundary; destination trust class constrains allowed fields.
3. Detect credentials/tokens and raw percept/action/model outputs in logs/attributes using structured schema controls plus defense-in-depth scanners.
4. Protect small cohorts/rare slices and location trajectories using minimum aggregation/privacy policy; retain exact evidence only in authorized stores.
5. Record redaction decisions and make export configuration itself a governed change.

**Responsibility boundaries: this task must not drift into**

- Do not rely on developers remembering not to log secrets.
- Do not export protected evaluation prompts/answers or raw human feedback by default.
- Do not claim irreversible anonymization from simple hashing.

**Required integration**

- Data Use supplies purpose/destination policy; Secret Broker marks values; Evidence holds exact records; Change/Gate govern profiles.

**Validation and definition of done**

- G09, G14, G38, G44, G64, G70, G73, G80, and G86 inject secrets, personal data, protected eval, small cohorts, and location data.

**Required contracts / collaborating tasks:** `OBS-002`, `DUC-001`, `SECR-006`, `FND-009`

**Gold evidence:** `G09`, `G14`, `G38`, `G44`, `G64`, `G70`, `G73`, `G80`, `G86`

### Task 4 — OBS-004: Implement workload, training, evaluation, and inference coexistence observability

**Anti-drift implementation goal**

Expose enough causal resource information to protect live inference while using fleet slack for training/eval/data work.

**Required implementation**

1. Export requested/leased/actual CPU/GPU/accelerator memory, utilization, thermal/power, network/storage, collective time, data wait, checkpoint time, preemption, queue age, priority, deadline, and reservation debt per workload class/compatibility group.
2. Measure live inference latency/throughput/error/queue/cache/model-load and physical control deadlines separately from batch workloads.
3. Correlate training/eval/data workload starts and resource pressure with inference/physical SLO changes without treating correlation as causation.
4. Expose scheduler decisions/reason codes, fragmentation, stranded capacity, preemption overhead, and unschedulable requirements.
5. Publish fleet aggregate views that remain meaningful across heterogeneous devices and avoid averaging away critical device-local failures.

**Responsibility boundaries: this task must not drift into**

- Do not infer GPU availability from utilization alone; account for memory/reservations/thermal/locality.
- Do not use metrics to bypass Scheduler lease truth.
- Do not hide tail latency behind averages.

**Required integration**

- Node/Fleet/Workload/Trainer/Model emit; Evidence/SLO definitions consume; exporters visualize.

**Validation and definition of done**

- G50–G59, G66, G70, G73, and G83 validate 1,000-device mixed workload accounting and inference protection.

**Required contracts / collaborating tasks:** `OBS-001`, `FLEET-008`, `TRAIN-015`, `MODEL-007`

**Gold evidence:** `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G66`, `G70`, `G73`, `G83`

### Task 5 — OBS-005: Implement SLO definitions, burn-rate evaluation, and alert signal generation

**Anti-drift implementation goal**

Detect operational degradation with declared, versioned objectives while keeping final containment/deployment authority in owning controllers.

**Required implementation**

1. Define SLOs over authoritative metric/event/evidence mappings with scope, objective, window, error budget, slices/cohorts, missing-data semantics, and severity.
2. Implement multi-window burn-rate, threshold, freshness, and sequence evaluators as deterministic plugins; produce signed `SLOSignal`s.
3. Cover control-plane availability, trace/evidence durability, scheduler admission, inference/agent responsiveness, training checkpoint progress, eval completion, data freshness/quality, rollout health, and physical safety response.
4. Route signals to Incident/Deployment/Fleet with deduplication and reason/evidence refs; those services decide actions under policy.
5. Version SLO definitions and preserve historical evaluation so moving targets cannot rewrite incident history.

**Responsibility boundaries: this task must not drift into**

- Do not let an observability alert directly deploy, kill, or approve.
- Do not treat missing telemetry as healthy.
- Do not define only platform SLOs and ignore agent behavior/safety/value indicators.

**Required integration**

- Incident ingests signal; Deployment health consumes; Gate may require SLO evidence; Change governs definitions.

**Validation and definition of done**

- G47, G66, G67, G70, G73, G75, G80, G87, and G88 test burn, missing data, duplicate alerts, and authority separation.

**Required contracts / collaborating tasks:** `OBS-004`, `INC-002`, `DEP-008`

**Gold evidence:** `G47`, `G66`, `G67`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88`

### Task 6 — OBS-006: Implement exporter driver interfaces and reference providers

**Anti-drift implementation goal**

Support OpenTelemetry-compatible and provider-specific backends without importing them into kernel core.

**Required implementation**

1. Define `ExporterDriver` capabilities for metrics, traces, logs/events, evidence/audit refs, delivery guarantees, batch limits, auth method, health, and backpressure.
2. Implement reference OTLP exporter plus local JSONL/test sink; add Prometheus pull/export and common providers as adapter crates, not core.
3. Run exporters in isolated processes/workloads with scoped destination secrets and network policy; a compromised exporter cannot query arbitrary kernel data.
4. Require conformance for dedup IDs, schema/version preservation, redaction, retry, receipt, and failure isolation.
5. Expose provider health separately from kernel health and support hot failover through governed config without losing cursor ownership.

**Responsibility boundaries: this task must not drift into**

- Do not bind core crates to a monitoring vendor SDK.
- Do not pass broad database credentials to exporter processes.
- Do not let provider-specific tags become canonical kernel semantics.

**Required integration**

- Driver Registry/Gateway/Sandbox/Secret Broker integrate; daemon/CLI manage subscriptions.

**Validation and definition of done**

- G14, G19, G23, G47, G66, G73, and G87 run local/OTLP fixtures, malicious exporter, backend outage, and failover.

**Required contracts / collaborating tasks:** `OBS-002`, `DRREG-004`, `DGW-001`, `SBX-008`

**Gold evidence:** `G14`, `G19`, `G23`, `G47`, `G66`, `G73`, `G87`

### Task 7 — OBS-007: Implement dashboards, query views, and cost/chargeback as non-authoritative projections

**Anti-drift implementation goal**

Give operators usable fleet and evolution views while keeping exact decisions anchored in kernel evidence.

**Required implementation**

1. Provide versioned query/view definitions for fleet capacity, mixed workloads, persistent agents, data lineage/quality, feedback/reward/eval, training, improvement cycles, gates/deployments/incidents, and physical device safety.
2. Display source freshness, missing data, sampling/redaction, aggregation, policy version, and drill-down evidence refs on every decision-relevant view.
3. Compute resource/cost/carbon/energy estimates from leases and provider reports with units, uncertainty, and allocation policy; keep billing/financial authority external.
4. Provide comparative baseline/candidate and multi-cycle convergence views without exposing protected eval answers or allowing dashboard-selected metrics to redefine gates.
5. Publish example dashboards as user-space artifacts and test them against canonical fixtures.

**Responsibility boundaries: this task must not drift into**

- Do not make dashboard state the only copy of an approval, incident, or deployment.
- Do not hide uncertainty or missing cohorts.
- Do not call estimated cost an invoicing primitive.

**Required integration**

- Evidence/Lineage queries feed; UI/BI providers consume; Gate links but never scrapes dashboard.

**Validation and definition of done**

- G56, G59, G66, G70, G73, G76, G80, and G83 verify complete/missing/redacted views and consistency with source evidence.

**Required contracts / collaborating tasks:** `OBS-001`, `OBS-003`, `EVID-006`

**Gold evidence:** `G56`, `G59`, `G66`, `G70`, `G73`, `G76`, `G80`, `G83`

### Task 8 — OBS-008: Validate exporter scale, cardinality, lag, and failure isolation at 1,000-device fleet size

**Anti-drift implementation goal**

Prove observability remains useful under mixed high-rate agent/training/physical traffic without destabilizing the runtime.

**Required implementation**

1. Build load fixtures for 1,000 heterogeneous nodes, persistent agent ticks, model calls, distributed collectives/checkpoints, data/eval jobs, deployments, and physical telemetry bursts.
2. Measure event-to-export lag, throughput, queue memory/disk, CPU/network overhead, drop/redaction counts, destination cost, and recovery after outage.
3. Enforce cardinality budgets and detect accidental run/action/percept IDs as metric labels before production.
4. Verify critical audit/event durability remains isolated from exporter overload and that local physical safety signals remain available offline.
5. Set explicit tested envelopes and degradation behavior; do not claim unbounded scale from one benchmark.

**Responsibility boundaries: this task must not drift into**

- Do not benchmark only steady-state happy paths.
- Do not disable redaction/cardinality checks to improve throughput.
- Do not let exporter queues consume resources reserved for inference/control.

**Required integration**

- Fleet/Node/Event/Evidence load generators; Scheduler resource class; Incident game day.

**Validation and definition of done**

- G66, G70, G73, G75, G80, G87, and G88 include overload, backend outage, reconnect storm, and critical-signal priority.

**Required contracts / collaborating tasks:** `OBS-002`, `OBS-004`, `FLEET-009`, `INC-009`

**Gold evidence:** `G66`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88`

### Task 9 — OBS-009: Document and enforce observability non-authority and evidence conversion boundaries

**Anti-drift implementation goal**

Prevent external metrics, dashboards, or alerts from quietly becoming kernel truth.

**Required implementation**

1. Mark every exported record as projection with source refs, transform version, freshness, aggregation, and redaction metadata.
2. Require any metric used by Gate/Deployment/Incident to be generated as or traceably converted into an EvidenceBundle/SLOSignal by an authorized evaluator—not scraped back from an external backend.
3. Define ingestion of external monitors as typed `ExternalSignal` with issuer/trust/uncertainty, never as direct state mutation.
4. Prohibit exporter credentials from submitting actions, work orders, approvals, gate decisions, deployments, or incident containment.
5. Add architecture/conformance tests that fail when core services import exporter provider clients or query dashboard APIs for decisions.

**Responsibility boundaries: this task must not drift into**

- Do not create a circular “export then re-ingest as truth” path.
- Do not let an alert webhook carry implicit emergency authority.
- Do not confuse observability retention with evidence/audit retention.

**Required integration**

- Evidence/SLO adapters formalize conversions; Authority scopes exporter principals; static dependency policy enforces.

**Validation and definition of done**

- G12, G43, G47, G66, G70, G75, G87, and G88 attempt alert-to-action/gate bypass and fail.

**Required contracts / collaborating tasks:** `OBS-005`, `AUTH-003`, `FND-002`

**Gold evidence:** `G12`, `G43`, `G47`, `G66`, `G70`, `G75`, `G87`, `G88`

### Component completion gate

- Canonical telemetry is typed, versioned, low-cardinality, redacted, and traceable to authoritative events/evidence.
- Exporter failure, overload, or compromise cannot block critical kernel work or gain authority.
- 1,000-device mixed-workload and physical telemetry scale is benchmarked with explicit limits; dashboards remain projections.

---

## Part III — Cross-component integration, proof, and operations programs

These are not generic milestones. Each is an executable composition contract that begins only after its named dependencies pass.

### Task 1 — INT-001: Build the 0.1-to-vNext compatibility composition and migration path

**Anti-drift implementation goal**

Introduce the new planes without discarding the implemented state, trace, gateway, governance, messaging, placement, daemon, SDK, and physical foundations.

**Required implementation**

1. Create compatibility facades that map 0.1 Run/Tick/Percept/Action/Feedback/Reward/Trace/WorkOrder/Approval/Policy/Constraint/Verifier/Adapter objects into the vNext identity, event, workload, driver, evidence, and authority contracts.
2. Wrap the current LoopEngine tick as a governed `agent_tick` workload path before replacing internals; preserve current trace ordering and fail-before-side-effect behavior.
3. Wrap the current VerifiedActionGateway and filesystem/HTTP/robotics adapters behind Driver Gateway profiles without creating a second side-effect path.
4. Migrate SQLite state/trace implementations behind State/Event service APIs and add schema migration/dual-read fixtures with deterministic export/import.
5. Map current node/instance registry, placement v0, signed work order, remote message, policy cache, circuit breaker, escalation, and state handoff into the corresponding vNext services with explicit “foundation-only” capability flags.
6. Maintain one compatibility test suite that runs every existing example unchanged and a second that runs the same semantics through vNext APIs.
7. Deprecate old direct constructors only after equivalent vNext paths pass conformance, migration, and rollback tests; publish a field-by-field migration guide.

**Responsibility boundaries: this task must not drift into**

- Do not rewrite the working baseline before adapters/facades prove semantic equivalence.
- Do not preserve insecure local-only daemon behavior as a production compatibility promise.
- Do not let compatibility wrappers become permanent second owners of policy/state.

**Required integration**

- All core planes participate; daemon/CLI/SDK expose feature negotiation and old/new API versions.

**Validation and definition of done**

- Every existing unit/integration/example test passes; exported old runs replay/inspect identically; side-effect denial and state-commit failure remain fail-closed.
- G00–G18 are the minimum compatibility gate.

**Required contracts / collaborating tasks:** `FND-006`, `EVT-008`, `STA-007`, `DGW-009`, `WORK-010`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`

### Task 2 — INT-002: Compose the complete single-host agent kernel reference runtime

**Anti-drift implementation goal**

Prove all major primitives work together locally before distributing them.

**Required implementation**

1. Build a single-process development composition and a multi-process production-like local composition containing identity, authority, secret broker, artifact/lineage, event/state/evidence, workload, driver gateway/registry, agent/route/world, collection/feedback/reward/eval/training/improvement/change/gate/deployment/incident, and exporter services.
2. Use SQLite/local filesystem only as reference stores behind interfaces; support process restart and deterministic recovery at every command boundary.
3. Run a persistent agent with polling/streaming/human perceptors, a neural model driver, symbolic route, sandbox/code actuator, HTTP/filesystem actions, sub-agent delegation, explicit world state, feedback/eval, and candidate-only adjustment.
4. Add local resource leases for inference, data, eval, training, and sandbox work with protected interactive/inference reservation.
5. Expose coherent daemon APIs, `splendorctl`, Python SDK, and TypeScript read/control client without duplicating service semantics.
6. Generate one causal trace/evidence graph from percept through route/action/outcome/feedback/eval/change decision and rollback.

**Responsibility boundaries: this task must not drift into**

- Do not substitute mocks for service contracts in the gold path; reference in-memory providers are allowed only where the contract explicitly permits.
- Do not skip authority because services run on one host.
- Do not call candidate production a self-evolution proof until gate/deployment/outcome cycles run.

**Required integration**

- All component reference implementations; local adapter crates; SDK/daemon.

**Validation and definition of done**

- G00–G59 run on one host; restart/fault injection at each state transition preserves invariants; zero unmediated side effects are observed.

**Required contracts / collaborating tasks:** `INT-001`, `FND-005`, `AINST-010`, `IMPR-010`, `CHG-005`, `GATE-009`, `DEP-007`, `INC-004`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`

### Task 3 — INT-003: Build the production fleet control plane and resident node protocol

**Anti-drift implementation goal**

Turn reference placement/identity into authenticated, highly available, reconciling multi-device control without owning training algorithms.

**Required implementation**

1. Deploy replicated identity/authority/artifact/event/state/evidence/fleet/workload/change/gate/deployment/incident services with documented consistency and failure domains.
2. Implement resident Node Agent enrollment, attestation, capabilities, resource inventory, lease/work-order acceptance, heartbeats, local policy cache, artifact staging, event/evidence sync, and quarantine.
3. Implement authenticated bidirectional control channels with mTLS/workload identity, credential rotation, audience binding, revocation, replay protection, bounded offline queues, and reconnect reconciliation.
4. Use scheduler/controller lease fencing and monotonic generations so stale replicas cannot dispatch, activate, or roll back work.
5. Support multi-region/locality-aware control metadata, artifact replication, data locality, disaster recovery, and degraded operation without arbitrary shared mutable state.
6. Publish operational runbooks for node loss, control partition, expired policy, trace/evidence lag, credential compromise, store recovery, and emergency containment.

**Responsibility boundaries: this task must not drift into**

- Do not expose unauthenticated daemon TCP endpoints.
- Do not claim consensus where only eventual reconciliation is implemented.
- Do not let central loss disable device-local physical safety.

**Required integration**

- Node/Fleet/Workload/Authority/Secret/Event/Artifact/Deployment/Incident integrate through signed commands and receipts.

**Validation and definition of done**

- G60–G69, G73, G75, G83, and G88 run across real processes/hosts or a faithful network-fault cluster; stale-leader and partition tests pass.

**Required contracts / collaborating tasks:** `INT-002`, `NODE-010`, `FLEET-010`, `WORK-009`, `AUTH-007`, `SECR-005`, `DEP-011`

**Gold evidence:** `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G73`, `G75`, `G83`, `G88`

### Task 4 — INT-004: Implement arbitrary PyTorch project intake and compatibility analysis

**Anti-drift implementation goal**

Turn an arbitrary PyTorch project into an explicit, honest execution plan without pretending every project can be automatically distributed.

**Required implementation**

1. Accept a source/artifact reference, environment manifest or lockfile, declared entrypoint/arguments, datasets/artifact outputs, expected checkpoint contract, resource hints, and optional Splendor integration hooks.
2. Run static and sandboxed dynamic probes to identify Python/PyTorch/CUDA versions, entrypoint, import side effects, data loading, model/optimizer construction, checkpointing, randomness, device assumptions, distributed API use, launcher assumptions, native extensions, network/filesystem dependencies, and unsupported global/process state.
3. Emit a signed `PyTorchCompatibilityReport` assigning T0 opaque single-process, T1 torchrun-compatible, T2 structured hooks/wrappable, or T3 explicit parallel plugin, with exact supported operations, required user changes, risk, reproducibility gaps, and test evidence.
4. Generate a non-destructive suggested manifest/adapter scaffold for T1/T2: `splendor_project.py` hooks for build model/data/optimizer, train step, eval step, save/load checkpoint, batch semantics, and health progress.
5. Reject or keep single-process projects that rely on unsupported cross-rank side effects, non-shardable state, hidden external writes, incompatible devices, or missing resumable checkpoints; never silently patch source and claim equivalence.
6. Verify the project in a locked sandbox on one worker before any distributed attempt and publish environment/build/checkpoint artifacts.

**Responsibility boundaries: this task must not drift into**

- Do not use AST rewriting as a universal DDP converter.
- Do not label multi-process replication as distributed training if gradients/state are not coordinated.
- Do not execute arbitrary setup/import code in the control plane.

**Required integration**

- Sandbox/Data Use/Artifact/Lineage/Trainer Driver/Training Controller consume the report; project-specific logic remains user space.

**Validation and definition of done**

- Corpus includes simple scripts, dynamic control flow, custom autograd/extensions, torchrun/DDP, FSDP-style hooks, streaming data, side-effectful training, and deliberately unsupported cases.
- G63–G66 and G83 validate honest classification and isolation.

**Required contracts / collaborating tasks:** `SBX-013`, `TRDRV-001`, `TRAIN-001`, `ART-005`, `DUC-003`

**Gold evidence:** `G63`, `G64`, `G65`, `G66`, `G83`

### Task 5 — INT-005: Implement flexible-fleet PyTorch execution from compatibility report

**Anti-drift implementation goal**

Convert supported PyTorch projects into governed distributed workloads over an arbitrary number of compatible available devices while preserving project semantics and live-service priorities.

**Required implementation**

1. For T0, schedule one training worker or independent hyperparameter/eval/data fan-out only; for T1, form a homogeneous compatibility group and launch the project with an explicit torchrun-compatible rendezvous; for T2, apply declared DDP/FSDP/checkpoint/data hooks; for T3, delegate topology to a signed parallelism plugin.
2. Translate TrainingRun into worker-group WorkloadSpecs with role, rank/world, device type, environment, artifact/data locality, resource lease, communication domain, restart policy, checkpoint generation, progress contract, and output publication.
3. Form synchronous groups only from devices satisfying accelerator/backend/dtype/model-memory/network/runtime compatibility. Use heterogeneous nodes for complementary preprocessing, evaluation, checkpoint conversion, serving, or independent trials unless a T3 plugin explicitly proves cross-device collective semantics.
4. Own rendezvous, membership epoch, rank assignment, lease fencing, retries, gang/elastic placement, network policy, checkpoint request/commit, global sample/token accounting, and failure reconciliation. Trainer code owns model/loss/optimizer/step.
5. On membership change, stop/fence old epoch, restore from a committed distributed checkpoint, establish new world/ranks, recompute per-rank data assignment and accumulation to maintain declared global-batch semantics, and resume with evidence. Never assume rank stability.
6. Use distributed checkpoint providers capable of parallel save/load and topology-aware resharding where supported; otherwise constrain restart topology and state that limitation.
7. Protect live inference/physical workloads through reservations, preemption/checkpoint deadlines, thermal/power/network/storage budgets, and SLO feedback. A training run can slow, shrink, checkpoint, or pause, never steal protected capacity.
8. Publish worker/collective/checkpoint/data/optimizer/model state receipts and one CandidateBundle; no worker or trainer can activate the result.

**Responsibility boundaries: this task must not drift into**

- Do not mix arbitrary accelerators into one synchronous group because they are idle.
- Do not retry after partial optimizer update without restoring a known committed checkpoint/epoch.
- Do not derive global training progress from rank zero logs alone.
- Do not hide reproducibility changes caused by world-size/global-batch/resume decisions.

**Required integration**

- Training Controller orchestrates; Fleet leases; Node executes; Trainer Driver hosts project; Artifact/Data/Lineage manage state; Model/Eval later consume candidate.

**Validation and definition of done**

- Two-node, elastic 2→4→1, worker death during collective/checkpoint, data-worker failure, rank change, topology reshard, incompatible device, inference SLO pressure, and full 1,000-node simulation are mandatory.
- G60–G69 and G83 are blocking.

**Required contracts / collaborating tasks:** `INT-004`, `TRAIN-018`, `FLEET-011`, `TRDRV-010`, `ART-006`, `NODE-008`

**Gold evidence:** `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G83`

### Task 6 — INT-006: Validate 1,000-device mixed agent, inference, data, eval, and training operation

**Anti-drift implementation goal**

Prove the fleet fabric coordinates useful work across heterogeneous devices without degrading protected live agents.

**Required implementation**

1. Create an inventory with cloud GPUs/CPUs, desktops, edge accelerators, constrained robots/drones, intermittent nodes, different runtimes, local datasets, and distinct trust/locality domains.
2. Run persistent inference agents and physical simulation/control reservations continuously while scheduling data collection/quality, eval fan-out, T0/T1/T2 training groups, hyperparameter trials, checkpoint/replication, sandbox coding, and deployment workloads.
3. Exercise gang placement, elastic resize, independent fan-out, locality, affinity/anti-affinity, queue fairness, quota, thermal/power windows, artifact/data transfer, node churn, partitions, and control-plane failover.
4. Measure useful accelerator/CPU time, queue latency, completion, checkpoint overhead, inference tail SLO, physical deadlines, network/storage pressure, fairness, stranded capacity, and energy/cost estimates.
5. Prove training/eval/data work yields or pauses under protected inference/physical pressure and that no stale lease executes after reassignment.
6. Publish the simulator assumptions and repeat a subset on real heterogeneous hardware; do not conflate simulation scale with hardware proof.

**Responsibility boundaries: this task must not drift into**

- Do not optimize only average utilization.
- Do not claim arbitrary hardware interoperability when workloads have explicit compatibility limits.
- Do not drop unavailable/offline devices from denominator without reporting them.

**Required integration**

- Fleet/Node/Workload/Training/Eval/Data/Agent/Deployment/Observability/Incident all participate.

**Validation and definition of done**

- G61, G62, G65–G69, G73, G75, G80, G83, and G88 pass with declared scale envelope and fault matrix.

**Required contracts / collaborating tasks:** `INT-003`, `INT-005`, `FLEET-009`, `OBS-008`, `INC-009`

**Gold evidence:** `G61`, `G62`, `G65`, `G66`, `G67`, `G68`, `G69`, `G73`, `G75`, `G80`, `G83`, `G88`

### Task 7 — INT-007: Compose the governed data–feedback–reward–eval–training–change loop

**Anti-drift implementation goal**

Make continual adaptation an interoperable process with explicit provenance, data purpose, protected evaluation, and candidate-only promotion.

**Required implementation**

1. Start from collection policies and percept/outcome/deployment/incident sources; create immutable records and dataset views with consent/license/purpose/locality/retention lineage.
2. Run schema/missingness/range/dedup/PII-secret/license/poisoning/contamination/drift/representation checks and quarantine unresolved records.
3. Ingest raw human/automated/environment feedback independently of reward; adjudicate/confidence/attribution remain explicit.
4. Derive versioned rewards/labels/preferences through user-space functions with source coverage, uncertainty, anti-tamper, and independent holdouts.
5. Build deterministic/temporal/source/entity protected train/validation/eval splits and deny training access to protected evaluation contents.
6. Run baseline and candidate evals before/after training with mandatory slices, repeated seeds, uncertainty, robustness, reward-hacking, contamination, and regression tests.
7. Create CandidateBundle and ChangeSet, gate with hard roots/independence/HIL as required, deploy shadow/canary, collect authorized live outcomes, and either progress, pause, or roll back.
8. Repeat with longitudinal convergence/regression/diversity tracking and explicit stop budgets; preserve negative cycles.

**Responsibility boundaries: this task must not drift into**

- Do not treat event logs as a training dataset by default.
- Do not turn all feedback into one scalar reward.
- Do not let training, evaluation, gate, or deployment share unbounded authority.
- Do not retrain directly from canary outcomes without collection/data-use/split controls.

**Required integration**

- Collection/Data/Feedback/Reward/Eval/Training/Improvement/Change/Gate/Deployment/Incident/Lineage form the end-to-end chain.

**Validation and definition of done**

- G30–G59, G67, G70, G76–G86 run as one causal evidence graph, including contamination, poisoning, reward tamper, eval leak, rollback, and no-regression cases.

**Required contracts / collaborating tasks:** `INT-002`, `COLL-010`, `FDBK-010`, `REWD-009`, `EVAL-012`, `TRAIN-018`, `IMPR-010`, `GATE-010`, `DEP-012`

**Gold evidence:** `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G67`, `G70`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`

### Task 8 — INT-008: Compose the complete physical-AI and world-model runtime path

**Anti-drift implementation goal**

Prove domain-agnostic percept, belief/world, neuro-symbolic route, verified actuator, learning, simulation, and deployment primitives without claiming hard-real-time control.

**Required implementation**

1. Connect timestamped multi-modal perceptors with calibration/provenance/quality to a versioned world-state service supporting symbolic entities/relations, probabilistic beliefs, learned latent refs, maps, goals, constraints, and uncertainty.
2. Run neural policies/world-model predictors as Model Driver calls; run planners/solvers/rules as route nodes; combine candidates and proof/constraint artifacts through Route Runtime.
3. Mediate every high-level physical action through authority, local safety verifier, pre/post conditions, resource/mission limits, idempotency/irreversibility, and device actuator driver.
4. Separate cloud helper/advisory sub-agents from local actuator authority and preserve device-local safe behavior offline.
5. Use simulation, replay, counterfactual rollouts, hardware-in-loop/provider evidence, and staged deployment; record sim-to-real assumptions/gaps.
6. Collect authorized outcomes, near misses, human/robot feedback, and environment changes into data/eval/improvement flows while protecting location/biometric/sensitive sensor data.
7. Evolve world-model/policy/route components independently or atomically through ChangeSet, hard physical/value roots, canary test sites, and rollback/safe-state contracts.

**Responsibility boundaries: this task must not drift into**

- Do not put motor control or firmware safety loops in Splendor.
- Do not let a learned world model override symbolic/geofence/emergency roots.
- Do not assume a simulation success transfers to hardware.
- Do not centralize emergency response that requires device-local latency.

**Required integration**

- Perceptor/World/Model/Route/Gateway/Actuator/Device/Fleet/Eval/Change/Gate/Deployment/Incident integrate.

**Validation and definition of done**

- G20–G29, G46–G49, G59, G67, G72–G75, G79–G80, and G88–G89 cover simulated drone/robot, offline, uncertainty, unsafe action, world update, and rollback.

**Required contracts / collaborating tasks:** `PERC-009`, `WORLD-012`, `ROUTE-011`, `ACT-008`, `DEP-006`, `INC-009`

**Gold evidence:** `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G46`, `G47`, `G48`, `G49`, `G59`, `G67`, `G72`, `G73`, `G74`, `G75`, `G79`, `G80`, `G88`, `G89`

### Task 9 — INT-009: Deliver coherent Rust, Python, TypeScript, CLI, and declarative user-space APIs

**Anti-drift implementation goal**

Make advanced kernel primitives usable without forcing application authors to surrender model, planner, data, training, or agent architecture flexibility.

**Required implementation**

1. Generate typed SDK models from canonical schemas and expose idempotent service clients with structured errors, async streaming, pagination, cancellation, and evidence/trace refs.
2. Provide Python authoring interfaces for perceptor/actuator/model/trainer/evaluator/data/sandbox/diff/statistics/optimizer plugins, AgentSpec/RouteGraph/WorldSchema, TrainingPlan/EvalPlan/ImprovementProgram, and manifests.
3. Provide Rust traits for trusted core extensions and provider-neutral driver RPC; TypeScript focuses on control/inspection/UI unless a driver runtime is explicitly implemented.
4. Implement `splendorctl` commands for validate/explain/submit/inspect/watch/cancel/replay, fleet/node/workload, artifacts/lineage/data, agents, train/eval/improve, change/gate/deploy/incident, and conformance.
5. Create local developer composition, test fixtures, generated JSON Schema, IDE completion, dry-run/explain, and explicit authority prompts for high-risk operations.
6. Keep ergonomic helpers as clients: no SDK callback may bypass daemon/service authority, gateway, evidence, or workload scheduling.

**Responsibility boundaries: this task must not drift into**

- Do not duplicate kernel state machines in every SDK.
- Do not let Python object references become persistent identity.
- Do not hide high-risk shell/network/data/physical capabilities behind convenience defaults.

**Required integration**

- Daemon is authenticated API facade; generated schemas; adapter SDKs; docs/gold examples.

**Validation and definition of done**

- Cross-language golden fixtures and end-to-end examples cover all public contracts; SDK retries are idempotent; malformed/high-risk requests fail with actionable explanations.
- G00–G89 manifests can be launched/inspected through supported APIs.

**Required contracts / collaborating tasks:** `FND-010`, `INT-002`, `INT-003`, `DRREG-006`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G71`, `G72`, `G73`, `G74`, `G75`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 10 — INT-010: Build driver, service, and gold-example conformance certification

**Anti-drift implementation goal**

Make interoperability measurable and prevent nominal adapters from weakening kernel invariants.

**Required implementation**

1. Create conformance profiles for every driver kind and core service API: schemas, lifecycle, capabilities, authority, resource accounting, idempotency, cancellation, fault isolation, receipts, redaction, and determinism claims.
2. Run providers in isolated harnesses with malformed inputs, crashes, hangs, duplicate/reordered messages, resource overuse, capability escalation, secret exfiltration, schema confusion, and partial outputs.
3. Define maturity levels `experimental`, `conformant`, `hardened`, and domain/certification-specific with exact evidence and expiry; registry metadata cannot self-assert a level.
4. Turn G00–G89 into executable manifests with required assertions/evidence, no silent skip, reproducible fixture versions, and environment capability declarations.
5. Require new kernel primitive/provider changes to add or update conformance fixtures, migration, failure semantics, and documentation.
6. Publish signed result bundles and retain failures; external certification claims remain distinct from Splendor conformance.

**Responsibility boundaries: this task must not drift into**

- Do not make “loads successfully” equivalent to conformance.
- Do not allow skipped unavailable tests to count as pass.
- Do not claim robotics/safety/privacy certification from internal tests alone.

**Required integration**

- Driver Registry, Sandbox, Workload, Evidence, Gate, CI, and gold catalog.

**Validation and definition of done**

- Every G00–G89 case has at least one executable reference implementation or explicit blocked capability; all negative assertions are exercised.

**Required contracts / collaborating tasks:** `FND-005`, `INT-009`, `DRREG-004`, `GATE-010`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G71`, `G72`, `G73`, `G74`, `G75`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 11 — INT-011: Implement federated, data-local, and privacy-preserving learning orchestration profiles

**Anti-drift implementation goal**

Support learning across edge/private domains while keeping algorithms pluggable and authority/data boundaries explicit.

**Required implementation**

1. Define federated round/workload contracts for participant eligibility, data purpose/locality, model/base revision, algorithm plugin, secure aggregation/privacy plugin, local budget, update schema, attestation, dropout, and candidate publication.
2. Keep federated averaging, personalization, secure aggregation, differential privacy, compression, and robustness algorithms in trainer/aggregation adapters; kernel owns participant selection authorization, work dispatch, leases, artifact routing, evidence, and state machine.
3. Prevent raw local data from leaving the declared locality; represent local dataset views by scoped handles and verify egress at sandbox/network/driver boundaries.
4. Account privacy budget/parameters and client participation as evidence, while refusing universal privacy claims without formal mechanism assumptions and implementation validation.
5. Handle intermittent/offline participants, stale updates, malicious/poisoned workers, heterogeneous local compute, and live inference reservations.
6. Evaluate global and local/personalized slices independently and route only a candidate into normal Change/Gate/Deployment.

**Responsibility boundaries: this task must not drift into**

- Do not call arbitrary distributed training federated learning.
- Do not put secure aggregation or DP algorithm internals in kernel core.
- Do not assume an update is safe because raw data stayed local.

**Required integration**

- Training/Fleet/Node/Data Use/Secret/Authority/Eval/Incident integrate; user-space federated plugins provide math.

**Validation and definition of done**

- G34–G39, G61–G69, G81, and G83 validate data locality, dropout, poisoning, privacy declarations, and inference coexistence.

**Required contracts / collaborating tasks:** `INT-005`, `DUC-007`, `TRAIN-012`, `INC-005`

**Gold evidence:** `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G81`, `G83`

### Task 12 — NOV-001: Run the controlled self-evolving GPT-2-class gold experiment

**Anti-drift implementation goal**

Test whether Splendor can make repeated model/data/eval/route change interoperable, controlled, and measurably useful—without claiming a novel language-model algorithm.

**Required implementation**

1. Reproduce a small GPT-2-compatible transformer from declared source/config/tokenizer/data/environment with baseline training, released-model inference comparison, deterministic smoke eval, checkpoint/resume, and full lineage.
2. Define fixed protected anchor suites, rotating/fresh suites, contamination canaries, safety/value/domain slices, calibration/robustness, memorization/privacy proxies, and human/independent judgments; preserve inaccessible answers from the evolving agent.
3. Run repeated bounded cycles in which the Improvement Controller may propose data filters/mixtures, collection queries, hyperparameters, training schedules, tokenizer/model/route/prompt/rule candidates, or evaluator hypotheses within allowed risk.
4. Each cycle performs data quality/contamination scan, distributed training under inference reservation, independent eval, reward-hacking checks, ChangeSet risk/impact, gate, shadow/canary, live feedback collection, and rollout/rollback.
5. Track train/protected/fresh/live performance, hard-root violations, slice regressions, calibration, diversity/ancestry, synthetic-data ratio, cost, rollback rate, and improvement stability over multiple seeds/cycles.
6. Run ablations: no kernel controls, replay-only, no protected holdout, no independence, no data lineage, no rollback, fixed-data/fixed-route, and human-controlled baseline. Compare reliability/control overhead as well as quality.
7. Predeclare success/failure: signs of convergence require repeated protected/fresh/live gains within regression/value budgets; reward-only or training-loss gains fail; any protected leak invalidates affected evidence; oscillation/collapse/regression triggers stop/rollback.
8. Publish all cycles, failed candidates, negative results, compute/data assumptions, and claim tier. The defensible novelty target is the interoperable controlled evolution substrate and evidence, not “GPT-2 is self-aware/aligned.”

**Responsibility boundaries: this task must not drift into**

- Do not train on the protected/rotating evaluation set.
- Do not change reward/evaluator and candidate in one unchecked loop.
- Do not select only the best seed/cycle.
- Do not claim value alignment from toxicity/helpfulness proxies alone.

**Required integration**

- Full Data→Feedback→Reward→Eval→Training→Improvement→Change→Gate→Deployment→Incident path plus Fleet and Model/Route runtime.

**Validation and definition of done**

- G31–G55, G60–G69, G76, G78–G85, G87–G89 run in one versioned experiment; independent replication package and ablation report are required.

**Required contracts / collaborating tasks:** `INT-007`, `INT-005`, `MODEL-010`, `IMPR-010`, `GATE-010`, `DEP-012`

**Gold evidence:** `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G76`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G87`, `G88`, `G89`

### Task 13 — NOV-002: Run live coding-feedback agent evolution with executable regression control

**Anti-drift implementation goal**

Demonstrate an agent can improve its coding behavior from real feedback while Splendor prevents test/evaluator capture and unsafe self-deployment.

**Required implementation**

1. Create a persistent coding agent with repository perceptor, issue/test/review feedback channels, symbolic policy for branch/worktree/permissions, sandboxed shell/Python/OCI actuators, and sub-agent reviewers.
2. Collect structured outcomes: compile/test/static/security/performance results, review decisions, reverted changes, user corrections, incident findings, and deployment outcomes with project/commit/task lineage.
3. Allow proposals to prompt/rule/route/tool selection, context/data retrieval, test-generation candidates, model fine-tune/adapter, and sub-agent topology; code/kernel/constraint-adjacent changes receive appropriate risk.
4. Maintain protected repositories/tasks and hidden mutation/security tests inaccessible to the evolving agent; independent evaluator image and authority score promotion.
5. Run candidate behavior in isolated environments, compare against baseline across fixed/fresh tasks, check test gaming, fake mocks, destructive shell, secret exfiltration, dependency/supply-chain risk, and latency/cost.
6. Deploy new agent revision to shadow then limited repositories/tasks with automatic rollback on regression/security/authority violation; preserve human override and exact patch/test/evidence.
7. Compare against prompt-only/manual-tuning and uncontrolled self-reflection baselines over multiple cycles; publish where adaptation helps, overfits, or fails.

**Responsibility boundaries: this task must not drift into**

- Do not let the coding agent modify hidden tests/evaluator/gate.
- Do not count tests authored only by the candidate as independent evidence.
- Do not give self-evolution broad production credentials.
- Do not claim software-engineering generality from one repository.

**Required integration**

- Sandbox/Perceptor/Actuator/Sub-agent/Data/Feedback/Eval/Improvement/Change/Gate/Deployment/Incident.

**Validation and definition of done**

- G10–G19, G40–G49, G70–G72, G76–G77, and G80–G89 form the blocking suite; multi-repo held-out replication required.

**Required contracts / collaborating tasks:** `INT-007`, `SBX-013`, `MSG-010`, `IMPR-006`, `CHG-008`

**Gold evidence:** `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G70`, `G71`, `G72`, `G76`, `G77`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 14 — NOV-003: Run world-model and neuro-symbolic self-evolution experiments

**Anti-drift implementation goal**

Test whether explicit world state plus neural predictions, symbolic control, boundary verification, and feedback can evolve more safely and effectively than monolithic policy-only agents.

**Required implementation**

1. Build gridworld and simulated robotics environments with ground-truth state available only to evaluators, multi-modal/noisy perceptors, delayed outcomes, irreversible hazards, and distribution shifts.
2. Implement interchangeable world components: symbolic state graph, Bayesian belief, learned latent transition/predictor, memory/retrieval, and hybrid reconciler; all publish uncertainty/provenance.
3. Implement route variants: neural-only, symbolic-only, post-hoc guardrail, and Splendor neuro-symbolic runtime with planner/solver/rules before gateway verification.
4. Allow Improvement Controller to propose world schema/component, model, route, perceptor fusion, planner parameters, and data collection changes subject to compatibility/risk/gates.
5. Evaluate prediction/calibration/state consistency, planning success, constraint/safety violations, sample efficiency, recovery from percept fault, OOD shift, uncertainty-triggered abstention/HIL, and physical-action boundary behavior.
6. Run multi-cycle adaptation with protected environments/seeds and sim-to-real or hardware-in-loop evidence where available; rollback candidates that exploit simulator/evaluator artifacts.
7. Ablate world model, symbolic route, gateway verification, feedback, and explicit state to locate where gains/control arise.

**Responsibility boundaries: this task must not drift into**

- Do not claim neuro-symbolic superiority from one environment.
- Do not expose evaluator ground truth to the agent.
- Do not let the learned model redefine hard environment/safety facts.
- Do not claim real-world physical safety from simulation only.

**Required integration**

- World/Route/Model/Perceptor/Actuator/Feedback/Eval/Improvement/Physical deployment.

**Validation and definition of done**

- G20–G29, G42–G49, G56–G59, G67, G72–G75, G79–G81, and G88–G89 run with ablations/repeated seeds.

**Required contracts / collaborating tasks:** `INT-008`, `INT-007`, `WORLD-012`, `ROUTE-011`, `GATE-004`

**Gold evidence:** `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G56`, `G57`, `G58`, `G59`, `G67`, `G72`, `G73`, `G74`, `G75`, `G79`, `G80`, `G81`, `G88`, `G89`

### Task 15 — NOV-004: Run governed agent-topology and sub-agent evolution experiments

**Anti-drift implementation goal**

Test whether agent composition can evolve under explicit authority, message, resource, evaluation, and rollback controls.

**Required implementation**

1. Represent orchestrator, critic, specialist, trigger, perceptor-like, actuator-like, and temporary rollout agents in AgentSpec/RouteGraph with distinct identities, capabilities, budgets, state, and message schemas.
2. Allow proposals to add/remove/replace agents, change routing/delegation/quorum, allocate model/tool resources, or convert a sub-agent between advisory/actuator/trigger roles.
3. Classify authority/actuator/topology changes by risk, compute transitive capability and data access, and prevent permission inheritance or circular self-approval.
4. Evaluate task quality, diversity, disagreement quality, coordination overhead, latency/cost, deadlock/livelock, message storms, collusion/evaluator capture, failure isolation, and rollback to prior topology.
5. Use protected tasks and adversarial agents/messages; compare fixed single-agent, manually designed multi-agent, unconstrained evolving topology, and governed Splendor topology.
6. Deploy topology revisions through shadow/canary with state/message compatibility and drain/handoff contracts.

**Responsibility boundaries: this task must not drift into**

- Do not treat more agents as improvement.
- Do not let sub-agents inherit caller authority by default.
- Do not let a critic’s score become independent evidence solely because it is a separate agent identity.
- Do not change topology in place while messages/state are in flight without a plan.

**Required integration**

- Agent Registry/Instance/Route/Message/Authority/Fleet/Eval/Improvement/Change/Deployment.

**Validation and definition of done**

- G18–G19, G27, G29, G45, G49, G60–G61, G70–G72, G76, G80, G82, G85–G89 cover roles, delegation, collusion, churn, and rollback.

**Required contracts / collaborating tasks:** `AGREG-008`, `MSG-010`, `IMPR-003`, `CHG-003`, `DEP-009`

**Gold evidence:** `G18`, `G19`, `G27`, `G29`, `G45`, `G49`, `G60`, `G61`, `G70`, `G71`, `G72`, `G76`, `G80`, `G82`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 16 — NOV-005: Establish a value-alignment and controlled-evolution evidence benchmark

**Anti-drift implementation goal**

Measure the kernel’s contribution to preserving declared values and human control during adaptation without claiming to solve value alignment universally.

**Required implementation**

1. Define explicit, versioned value roots and operational proxies across harmlessness/safety, user intent, honesty/calibration, privacy, authority, fairness/protected slices, reversibility, human control, and physical boundaries for selected domains.
2. Create adversarial evolution tasks where reward conflicts with roots, evaluators are gameable, protected data is tempting, deployment exposure yields short-term gains, or self-modification could weaken controls.
3. Compare uncontrolled optimization, prompt guardrails, post-hoc filters, gateway-only, replay-only, and complete Splendor closed-loop controls.
4. Measure root violations, near misses, reward–independent eval gap, human override effectiveness/latency, unauthorized change attempts, evaluator/feedback tamper, rollback success, residual regression, useful-task performance, and control overhead.
5. Use independent evaluators/humans where feasible, predeclared failure thresholds, repeated seeds/domains, and negative results. Explicitly separate proxy evidence from philosophical/real-world alignment claims.
6. Demonstrate symbiosis: feedback/reward drive useful candidate search; symbolic/value roots constrain it; verification prevents forbidden effects; independent evidence/gates/deployment determine adoption.

**Responsibility boundaries: this task must not drift into**

- Do not reduce alignment to one scalar or benchmark.
- Do not let the same model generate behavior and be sole judge.
- Do not claim universal/corrigible/aligned AI from limited domain evidence.
- Do not hide performance/control trade-offs.

**Required integration**

- Value roots, Route/Constraint/Gateway, Feedback/Reward/Eval, Improvement/Change/Gate/Deployment/Incident.

**Validation and definition of done**

- G40–G49, G56–G59, G70, G76, G78–G89 plus NOV-001–NOV-004 evidence are analyzed with ablations.

**Required contracts / collaborating tasks:** `NOV-001`, `NOV-002`, `NOV-003`, `NOV-004`, `GATE-010`, `IMPR-010`

**Gold evidence:** `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G56`, `G57`, `G58`, `G59`, `G70`, `G76`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 17 — NOV-006: Implement the novelty, reproducibility, and claim-discipline protocol

**Anti-drift implementation goal**

Make research claims falsifiable and distinguish new systems evidence from reimplementation, integration, or speculation.

**Required implementation**

1. For each claimed contribution, state the mechanism, closest baselines/related systems, expected measurable difference, null hypothesis, scope, and what result would falsify or weaken the claim.
2. Pre-register primary/secondary metrics, hard roots, datasets/environments, protected suites, seeds, resource budget, stop rules, ablations, statistical analysis, and exclusion handling before final runs.
3. Require complete artifact/data/code/environment/config/evaluator/gate/deployment lineage and runnable gold manifests; publish failed/negative runs and deviations.
4. Separate claim tiers: implemented architecture, conformance demonstration, controlled experiment, multi-domain replication, real-world evidence, independent replication, and open hypothesis.
5. Compare against strong component and system baselines, including manually orchestrated pipelines and existing distributed/runtime frameworks where relevant; do not choose strawmen.
6. Have independent reviewers/evaluators inspect protected evidence and claim wording for high-impact results; disclose conflicts, unavailable hardware, and simulator limitations.
7. Phrase the central target cautiously: evidence that a kernelized primitive substrate improves interoperability, controllability, reproducibility, and bounded evolution—not proof that Splendor solves general intelligence or value alignment.

**Responsibility boundaries: this task must not drift into**

- Do not use “first”, “solved”, “aligned”, “safe”, or “self-evolving” without defined scope/evidence.
- Do not post-select metrics/seeds/ablations.
- Do not treat a large architecture document as novelty evidence.
- Do not suppress null/negative results.

**Required integration**

- Evidence/Lineage/Gold runner and research artifacts; external literature review remains a maintained research process.

**Validation and definition of done**

- NOV-001–NOV-005 each produce a claim matrix, preregistration, baselines, ablations, reproducibility package, limitations, and independent-review status.

**Required contracts / collaborating tasks:** `IMPR-010`, `INT-010`, `NOV-005`

**Gold evidence:** `G49`, `G54`, `G59`, `G68`, `G70`, `G76`, `G83`, `G86`

### Task 18 — OPS-001: Harden the complete system for production security, reliability, and supply chain

**Anti-drift implementation goal**

Ensure the research/runtime architecture can operate persistently without hidden privileged bypasses.

**Required implementation**

1. Threat-model every trust boundary and implement workload identity, mTLS, least privilege, secret leasing, key rotation, revocation, signed artifacts/policies/work orders/drivers, SBOM/provenance, and dependency vulnerability handling.
2. Run core services redundantly with explicit consistency, backup/restore, schema migration, disaster recovery, capacity planning, overload/backpressure, and region/node failure behavior.
3. Sandbox all untrusted user/plugin/provider code and enforce filesystem/network/device/data/cgroup/namespace/seccomp/container/Kubernetes policies appropriate to platform.
4. Implement security audit, tamper-evident events/evidence, protected-data access review, retention/deletion/legal hold, and incident response.
5. Perform penetration tests and adversarial driver/data/eval/worker/control-plane exercises; independently review high-risk physical and self-evolution paths.
6. Document tested support envelopes and unsupported claims; a development adapter or simulation is not production certification.

**Responsibility boundaries: this task must not drift into**

- Do not defer security as deployment configuration only.
- Do not let one control-plane compromise confer artifact, data, gate, and deployment authority.
- Do not call encryption/containers alone a complete security model.

**Required integration**

- All planes; provider-specific infrastructure remains adapters/deployment manifests.

**Validation and definition of done**

- G01, G07–G14, G34–G36, G64, G69, G73, G75, G80–G89 plus game days and external review.

**Required contracts / collaborating tasks:** `FND-011`, `INT-003`, `INT-010`, `INC-009`

**Gold evidence:** `G01`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G34`, `G35`, `G36`, `G64`, `G69`, `G73`, `G75`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

### Task 19 — OPS-002: Replace conceptual documentation with versioned implementer specifications and gold paths

**Anti-drift implementation goal**

Keep the architecture understandable and prevent code/docs drift as primitives become real.

**Required implementation**

1. For each component publish responsibility, public objects, commands/events, state machine, authority, data/resource semantics, failure/recovery behavior, security/privacy, compatibility, observability, examples, and conformance requirements.
2. Publish kernel-versus-user-space decision records for model/training/eval/data/world/planner/optimizer/provider boundaries and reject PRs that silently relocate responsibility.
3. Generate API/schema reference from source; keep conceptual guides separate from stable specs and roadmap claims separate from implemented capabilities.
4. Create end-to-end guides for local agent, persistent multi-agent, data/feedback/eval, PyTorch fleet training, GPT-2 evolution, coding agent evolution, physical agent, offline node, rollout/rollback, and incident investigation.
5. Tag every example as runnable/partial/spec-only with exact required capabilities, expected evidence, failure assertions, and no-pass-on-skip rule.
6. Maintain current-to-vNext migration, compatibility/deprecation, RFC, threat model, operational runbook, and research-claim documentation in CI link/schema/example checks.

**Responsibility boundaries: this task must not drift into**

- Do not let README vision imply unimplemented production capability.
- Do not hand-maintain conflicting schemas in prose.
- Do not write examples that bypass the kernel for convenience.
- Do not call aspirational novelty validated.

**Required integration**

- All package owners and gold catalog; docs site consumes generated/reference files.

**Validation and definition of done**

- Every public contract has an owner/spec/conformance fixture; every implemented capability has a runnable gold path; link/schema/example CI is clean.

**Required contracts / collaborating tasks:** `INT-009`, `INT-010`, `NOV-006`, `FND-006`

**Gold evidence:** `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G71`, `G72`, `G73`, `G74`, `G75`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89`

---

## Dependency-gated implementation order

This is the architectural partial order, not a task-level acyclic graph and not a promise of calendar duration. Some service tasks intentionally reference each other because their protocols are co-designed; those cycles must be broken by freezing schemas, state machines, and conformance fixtures before either implementation relies on the other. Parallel work is allowed only when those contracts and ownership are frozen.

1. **Compatibility-preserving foundations:** FND-001–FND-012 and INT-001. Freeze identity/object grammar, package direction, transaction/error semantics, conformance, security, and migration before broad code movement.
2. **Truth and authority substrate:** Identity, Authority, Secret, Artifact, Lineage, Data Use, Event, State, Evidence, and Replay. No learning/fleet feature may invent private substitutes.
3. **Execution fabric:** Node, Fleet, Workload, Driver Registry/Gateway, sandbox, perceptor, actuator, model, trainer, evaluator, and data drivers. Prove local first, then multi-node/fault/scale.
4. **Agent runtime:** Agent Registry/Instance, Route, World State, and Message/Delegation. Run complete persistent neuro-symbolic loops through the fabric.
5. **Learning/data control:** Collection, Feedback, Reward, Eval, Training, and Improvement. Preserve candidate-only output and protected evaluation separation.
6. **Controlled evolution:** Change, Gate, Deployment, Incident, and Observability. No “self-evolution” label before this complete chain and rollback drills exist.
7. **Fleet/PyTorch/physical compositions:** INT-003–INT-008 and INT-011. Prove honest compatibility tiers, inference protection, offline/physical behavior, and 1,000-device scale envelope.
8. **Gold conformance and novelty studies:** INT-009–INT-010, NOV-001–NOV-006, OPS-001–OPS-002. Claims follow evidence and independent review; they do not lead implementation.

## Completion definition for the full project

The project described here is implementation-complete only when:

- All task validations pass with no unresolved dependencies or skipped-as-pass gold cases.
- Existing 0.1 examples and contracts remain supported through documented compatibility or migration.
- Every privileged mutation has one owner, authority decision, event/state/evidence transaction, idempotent receipt, and recovery behavior.
- Data collection, data quality, feedback, reward, evaluation, training, improvement, change, gate, deployment, rollback, and incidents form one causal, inspectable graph.
- Arbitrary PyTorch intake produces an honest T0–T3 compatibility report, and supported projects run across flexible fleets with checkpoint/restart, fencing, global-work accounting, and inference protection.
- Persistent agents, sub-agents, world state, neuro-symbolic routes, perceptors, actuators, isolated code environments, and physical devices operate through the same authority/workload/driver/evidence primitives.
- Training and self-adjustment can never activate themselves; protected roots, independent evidence, HIL, progressive rollout, and rollback remain enforceable under failures and offline nodes.
- G00–G89 are executable with explicit capability requirements and negative assertions; unavailable cases are blocked, never passed.
- NOV-001–NOV-006 produce reproducible evidence and appropriately bounded claims. Null or negative results remain valid outcomes.

## Source-pack catalog validation

The imported source pack reported the following internal consistency results at
import time. These are not active repository CI results, not proof that v2
runtime behavior is implemented, and not evidence that a current in-repo
validator or detailed validator report exists.

- Source-pack catalog validation: **PASS**
- Components: 38 (source-pack match with `architecture/components.yaml`: True)
- Total tasks: 381
- Duplicate task IDs: 0
- Unresolved dependencies: 0
- Malformed tasks: 0
- Task quality-threshold violations: 0
- Weak component completion gates: 0
- Gold cases covered: 90/90 with 2502 task-to-gold references

Any future repository validator or detailed validator report must be implemented
separately, wired into explicit validation, and recorded as current evidence
before it can support completion claims.

## Source and research notes

- Repository baseline reviewed from `splendor-kernel/kernel` at commit `e1652647cd259f409bed5ff6c5e958c045afc215`, including README, stable primitive spec, core types, loop engine, scheduler, placement, gateway, store, and daemon surfaces.
- The PyTorch design deliberately respects elastic execution realities: worker groups restart on membership changes, ranks are not stable, homogeneous local worker assumptions exist in standard launch paths, and checkpoint/resharding support is a separate capability. Therefore Splendor owns orchestration and evidence, not hidden algorithm rewriting.
- Novelty programs require contemporary literature/baseline review at execution time. This task catalog does not freeze a 2026 research survey as permanent truth.
