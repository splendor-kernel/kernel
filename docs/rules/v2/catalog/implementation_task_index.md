> **Status:** Active 0.2/v2 task index. This file indexes the 0.2/v2 catalog of record after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements the described behavior.

# Splendor Agent Kernel — Implementation Task Index

**381 tasks:** 12 foundations, 350 component tasks, and 19 integration/research/operations programs.

The complete requirements, anti-drift boundaries, integrations, and validation criteria are in `complete_implementation_task_catalog.md`.

## Cross-cutting foundations

| # | ID | Task | Required contracts / collaborators |
|---:|---|---|---|
| 1 | `FND-001` | Freeze the vNext object and identity grammar | — |
| 2 | `FND-002` | Define package ownership and enforce dependency direction | `FND-001` |
| 3 | `FND-003` | Implement the command–decision–event transaction pattern | `FND-001` |
| 4 | `FND-004` | Create a single error and denial taxonomy | `FND-001` |
| 5 | `FND-005` | Build the conformance and fault-injection harness before new drivers | `FND-003`, `FND-004` |
| 6 | `FND-006` | Implement schema migration and compatibility discipline | `FND-001`, `FND-002` |
| 7 | `FND-007` | Define the kernel/user-space privilege boundary in code | `FND-001`, `FND-003` |
| 8 | `FND-008` | Create deterministic fixture, clock, randomness, and payload-reference utilities | `FND-001` |
| 9 | `FND-009` | Implement policy-independent audit redaction and protected payload handling | `FND-001`, `FND-007` |
| 10 | `FND-010` | Create end-to-end service APIs and idempotent SDK semantics | `FND-001`, `FND-004`, `FND-006` |
| 11 | `FND-011` | Establish threat models and security invariants per plane | `FND-005`, `FND-007`, `FND-009` |
| 12 | `FND-012` | Create performance budgets and reference-scale benchmarks | `FND-003`, `FND-005`, `FND-008` |

## Component 1 — Identity Registry

`splendor.identity-registry` · `identity_authority` · declared owner: crates/splendor-authority (identity module); schemas in splendor-types; persistence in splendor-store

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `IDR-001` | Implement the unified principal schema and registry state machine | `FND-001`, `FND-003` | `G01`, `G60` |
| 2 | `IDR-002` | Implement proof binding and authentication adapter contracts | `IDR-001`, `FND-011` | `G01`, `G83` |
| 3 | `IDR-003` | Implement node and physical-device ownership/attestation lifecycle | `IDR-001`, `IDR-002` | `G73`, `G74`, `G83` |
| 4 | `IDR-004` | Implement human and governance-principal lifecycle | `IDR-001`, `IDR-002` | `G43`, `G79` |
| 5 | `IDR-005` | Implement registry query, caching, and revocation propagation | `IDR-001`, `FND-003` | `G88` |
| 6 | `IDR-006` | Migrate existing identities without semantic collapse | `IDR-001`, `FND-006` | `G00`, `G03` |

## Component 2 — Authority Service

`splendor.authority-service` · `identity_authority` · declared owner: crates/splendor-authority (capability module); verifier integration in splendor-gateway and splendor-kernel

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `AUTH-001` | Define a composable capability and scope model | `IDR-001`, `FND-001`, `FND-007` | `G01`, `G18`, `G70` |
| 2 | `AUTH-002` | Implement issuance and signed work-order integration | `AUTH-001`, `IDR-002` | `G60`, `G83` |
| 3 | `AUTH-003` | Implement delegation chains and sub-agent authority narrowing | `AUTH-001` | `G18`, `G70`, `G71` |
| 4 | `AUTH-004` | Implement obligations and approval requirements as authority results | `AUTH-001`, `IDR-004` | `G11`, `G43`, `G75`, `G79` |
| 5 | `AUTH-005` | Implement revocation, lease renewal, and offline authority behavior | `AUTH-001`, `FND-003` | `G73`, `G88` |
| 6 | `AUTH-006` | Implement authority decision evidence and explainability | `AUTH-001`, `FND-009` | `G01`, `G03` |
| 7 | `AUTH-007` | Build authority adversarial/property test suites | `AUTH-001`, `AUTH-002`, `AUTH-003`, `AUTH-004`, `AUTH-005` | `G01`, `G18`, `G70`, `G79`, `G80`, `G86`, `G88` |

## Component 3 — Secret Broker

`splendor.secret-broker` · `identity_authority` · declared owner: crates/splendor-authority (secrets module); provider adapters under adapters/secrets-*; node injection in splendor-node

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `SECR-001` | Define opaque secret references and lease contracts | `AUTH-001`, `FND-001` | `G08` |
| 2 | `SECR-002` | Implement node-local secret delivery mechanisms | `SECR-001`, `NODE-003`, `SBX-001` | `G08`, `G82` |
| 3 | `SECR-003` | Implement rotation, revocation, and bounded renewal | `SECR-001`, `AUTH-005` | `G08`, `G88` |
| 4 | `SECR-004` | Implement secret-safe telemetry, redaction, and leak detection | `SECR-002`, `FND-009` | `G82` |
| 5 | `SECR-005` | Implement provider adapters and high-availability semantics | `SECR-001`, `FND-005` | `G07`, `G08` |
| 6 | `SECR-006` | Add secret handling to every external contract and gold example | `SECR-001`, `SECR-002`, `SECR-004` | `G08`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G53`, `G73`, `G74`, `G75`, `G82` |

## Component 4 — Artifact Registry

`splendor.artifact-registry` · `artifact_lineage` · declared owner: crates/splendor-artifacts (registry module); bytes backends via splendor-store/adapters

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `ART-001` | Define artifact kinds, manifests, and content identity | `FND-001`, `FND-008` | `G05` |
| 2 | `ART-002` | Implement transactional publication and quarantine | `ART-001`, `FND-003` | `G17`, `G69` |
| 3 | `ART-003` | Implement access, retention, legal hold, and deletion semantics | `ART-001`, `AUTH-001`, `DUC-001` | `G26`, `G34`, `G35` |
| 4 | `ART-004` | Implement signatures, attestations, and supply-chain metadata | `ART-001`, `IDR-002`, `FND-011` | `G17`, `G83` |
| 5 | `ART-005` | Implement replication, caching, locality, and integrity repair | `ART-002`, `DUC-003` | `G62`, `G69` |
| 6 | `ART-006` | Implement registry query, tags, collections, and compatibility resolution | `ART-001`, `AUTH-001` | `G53`, `G55` |
| 7 | `ART-007` | Migrate existing state snapshots, trace exports, and governed refs | `ART-001`, `FND-006` | `G03`, `G05` |

## Component 5 — Lineage Service

`splendor.lineage-service` · `artifact_lineage` · declared owner: crates/splendor-artifacts (lineage module); graph persistence in splendor-store

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `LIN-001` | Define the lineage relation model and invariants | `ART-001`, `FND-001` | `G05`, `G39` |
| 2 | `LIN-002` | Publish lineage transactionally from every producer | `LIN-001`, `ART-002`, `FND-003` | `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59` |
| 3 | `LIN-003` | Implement lineage closure and impact queries | `LIN-001`, `ART-003` | `G35`, `G83` |
| 4 | `LIN-004` | Build reproducibility and evidence graph materialization | `LIN-001`, `LIN-002`, `FND-008` | `G03`, `G39`, `G42`, `G52`, `G64` |
| 5 | `LIN-005` | Implement lineage integrity, signing, and anti-tamper checks | `LIN-002`, `ART-004`, `NODE-003` | `G83`, `G85` |
| 6 | `LIN-006` | Provide interoperability mappings without diluting kernel semantics | `LIN-001`, `LIN-005` | `G05`, `G17` |

## Component 6 — Data-Use Controller

`splendor.data-use-controller` · `identity_authority` · declared owner: crates/splendor-authority (data_use module); enforcement hooks in artifacts, fabric, learning, gateway, and node agent

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `DUC-001` | Define data classification, purpose, and use operations | `FND-001`, `AUTH-001`, `ART-001` | `G30`, `G34` |
| 2 | `DUC-002` | Implement data-use decision and grant issuance | `DUC-001`, `AUTH-001` | `G34`, `G84` |
| 3 | `DUC-003` | Implement data access leases and mount-level enforcement | `DUC-002`, `NODE-003`, `SBX-007` | `G36`, `G84` |
| 4 | `DUC-004` | Implement retention, deletion, and derivation impact handling | `DUC-002`, `LIN-003`, `ART-003` | `G35`, `G39` |
| 5 | `DUC-005` | Implement locality, federated, and device-resident data policies | `DUC-002`, `FLEET-003` | `G62`, `G67`, `G73` |
| 6 | `DUC-006` | Implement protected-evaluation data isolation | `DUC-003`, `FND-009` | `G36`, `G44`, `G49`, `G78`, `G84` |
| 7 | `DUC-007` | Build data-use audit, policy simulation, and adversarial tests | `DUC-001`, `DUC-002`, `DUC-003`, `DUC-004`, `DUC-006` | `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G84` |

## Component 7 — Event Log

`splendor.event-log` · `event_state_evidence` · declared owner: crates/splendor-evidence (event module); storage engines in splendor-store

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `EVT-001` | Generalize TraceEvent into a versioned EventEnvelope without losing the stable trace line | `FND-001`, `FND-006` | `G00`, `G02`, `G03` |
| 2 | `EVT-002` | Implement partitioned ordering and causal graph semantics | `EVT-001`, `STA-002` | `G68`, `G70`, `G72` |
| 3 | `EVT-003` | Implement durable append, outbox, and acknowledgement semantics | `EVT-001`, `FND-003` | `G02`, `G04`, `G87` |
| 4 | `EVT-004` | Implement subscriptions, cursors, backpressure, and retention-aware resume | `EVT-003`, `FND-009` | `G21`, `G29`, `G48` |
| 5 | `EVT-005` | Implement integrity chaining, remote sync, quarantine, and gap repair | `EVT-003`, `IDR-003`, `ART-005` | `G69`, `G73`, `G83`, `G88` |
| 6 | `EVT-006` | Implement event payload offload, schemas, and privacy boundaries | `EVT-001`, `ART-001`, `FND-009` | `G28`, `G35`, `G82` |
| 7 | `EVT-007` | Implement retention, compaction, archival, and restore | `EVT-003`, `ART-002`, `DUC-004` | `G03`, `G29` |
| 8 | `EVT-008` | Migrate all current trace producers and consumers | `EVT-001`, `EVT-003`, `FND-006` | `G00`, `G02`, `G03` |

## Component 8 — State Service

`splendor.state-service` · `event_state_evidence` · declared owner: crates/splendor-evidence (state semantics) plus splendor-store (persistence); orchestration hooks in splendor-kernel

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `STA-001` | Define named state partitions and explicit ownership | `FND-001`, `AUTH-001` | `G23`, `G26`, `G29` |
| 2 | `STA-002` | Implement compare-and-swap heads, writer leases, and fencing | `STA-001`, `AUTH-001`, `FND-003` | `G02`, `G72` |
| 3 | `STA-003` | Implement immutable commits, snapshots, branches, and declared merge policies | `STA-001`, `ART-001` | `G23`, `G24`, `G25` |
| 4 | `STA-004` | Implement atomic state/event/artifact transition coordination | `STA-002`, `EVT-003`, `ART-002`, `FND-003` | `G02`, `G87` |
| 5 | `STA-005` | Implement distributed handoff, checkpoint, and migration execution | `STA-002`, `STA-003`, `ART-005`, `EVT-005` | `G60`, `G72` |
| 6 | `STA-006` | Implement state schema evolution and controlled migrations | `STA-003`, `WORK-001`, `CHG-003` | `G77`, `G89` |
| 7 | `STA-007` | Implement state query, subscription, retention, and privacy | `STA-001`, `FND-009` | `G26`, `G42` |
| 8 | `STA-008` | Migrate current StateGraph/Store and prove compatibility | `STA-001`, `STA-002`, `FND-006` | `G02`, `G03` |

## Component 9 — Evidence Service

`splendor.evidence-service` · `event_state_evidence` · declared owner: crates/splendor-evidence (evidence module); schemas in splendor-types

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `EVID-001` | Define evidence bundles and typed claim support | `EVT-001`, `ART-001`, `LIN-001` | `G04`, `G05`, `G42`, `G47`, `G83` |
| 2 | `EVID-002` | Implement evidence materialization and causal closure | `EVID-001`, `LIN-003`, `EVT-002` | `G03`, `G39` |
| 3 | `EVID-003` | Implement completeness validators per privileged lifecycle | `EVID-001`, `ART-004`, `LIN-005` | `G44`, `G49`, `G75`, `G78`, `G79`, `G89` |
| 4 | `EVID-004` | Implement redacted, protected, and external evidence views | `EVID-001`, `FND-009` | `G35`, `G43`, `G82`, `G84` |
| 5 | `EVID-005` | Implement evidence verification, signatures, and correction | `EVID-001`, `ART-004`, `IDR-005` | `G83`, `G85` |
| 6 | `EVID-006` | Integrate evidence bundles into gold runner and research claims | `EVID-001`, `EVID-003`, `EVID-005` | `G00`, `G89` |

## Component 10 — Replay/Simulation Service

`splendor.replay-simulation-service` · `event_state_evidence` · declared owner: crates/splendor-evidence (replay module); simulation providers under adapters/simulation-*

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `RPLY-001` | Define replay, re-evaluation, simulation, and counterfactual modes | `EVID-001`, `STA-003`, `FND-007` | `G03` |
| 2 | `RPLY-002` | Implement driver substitution and non-live capability classes | `RPLY-001`, `DRREG-001`, `DGW-001` | `G03`, `G45`, `G73` |
| 3 | `RPLY-003` | Implement deterministic input, clock, randomness, and environment capture | `RPLY-001`, `LIN-004`, `FND-008` | `G39`, `G42`, `G52`, `G64` |
| 4 | `RPLY-004` | Implement divergence and causal comparison reports | `RPLY-003`, `EVID-002` | `G45`, `G46` |
| 5 | `RPLY-005` | Implement counterfactual world/state branches and rollout artifacts | `RPLY-001`, `STA-003`, `WORLD-001` | `G25`, `G57`, `G59`, `G73` |
| 6 | `RPLY-006` | Implement scalable replay/simulation workloads | `RPLY-002`, `WORK-001`, `FLEET-001` | `G61`, `G68` |
| 7 | `RPLY-007` | Prove no-live-effect and compatibility across all drivers | `RPLY-001`, `RPLY-002`, `FND-005` | `G03`, `G45` |

## Component 11 — Node Agent

`splendor.node-agent` · `execution_fabric` · declared owner: crates/splendor-fabric (node_agent module) and `splendor-node` resident binary; host integrations remain adapters

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `NODE-001` | Implement authenticated node bootstrap and renewable membership | `IDR-002`, `AUTH-001`, `FND-006` | `G60`, `G72` |
| 2 | `NODE-002` | Implement measured capability and health inventory | `NODE-001`, `DRREG-001` | `G60`, `G61`, `G62` |
| 3 | `NODE-003` | Implement local resource allocation, leases, and fencing | `NODE-001`, `AUTH-005`, `FND-003` | `G63`, `G65`, `G83` |
| 4 | `NODE-004` | Implement governed artifact cache and data mounts | `NODE-003`, `ART-005`, `DUC-003`, `SECR-002` | `G08`, `G34`, `G62`, `G69` |
| 5 | `NODE-005` | Implement worker launch and process supervision | `NODE-003`, `NODE-004`, `WORK-001`, `SBX-001` | `G04`, `G10`, `G11`, `G12`, `G13`, `G14`, `G52`, `G64`, `G87` |
| 6 | `NODE-006` | Implement local QoS and protected live-capacity reservations | `NODE-003`, `OBS-004`, `FLEET-005` | `G68`, `G74` |
| 7 | `NODE-007` | Implement offline, degraded, and reconnect behavior | `NODE-001`, `NODE-003`, `EVT-006`, `STA-007` | `G72`, `G73`, `G74`, `G75` |
| 8 | `NODE-008` | Implement checkpoint, output, and progress transfer protocol | `NODE-005`, `ART-002`, `LIN-005` | `G52`, `G63`, `G69` |
| 9 | `NODE-009` | Harden the resident boundary and worker isolation | `NODE-005`, `FND-011`, `SBX-007` | `G80`, `G81`, `G82`, `G83` |
| 10 | `NODE-010` | Implement drain, upgrade, restart, and disaster recovery | `NODE-003`, `NODE-005`, `DEP-005` | `G65`, `G68`, `G72` |

## Component 12 — Fleet Scheduler

`splendor.fleet-scheduler` · `execution_fabric` · declared owner: crates/splendor-fabric (scheduler module); provider capacity adapters outside core

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `FLEET-001` | Define the schedulable resource and requirement model | `FND-001`, `NODE-002` | `G09`, `G60`, `G61`, `G62` |
| 2 | `FLEET-002` | Implement durable queues, admission, and scheduling classes | `FLEET-001`, `AUTH-004`, `WORK-002` | `G09`, `G67`, `G68` |
| 3 | `FLEET-003` | Implement reservation, gang admission, and fenced lease issuance | `FLEET-001`, `NODE-003`, `FND-003` | `G63`, `G64`, `G87` |
| 4 | `FLEET-004` | Implement compatibility- and topology-aware placement | `FLEET-001`, `FLEET-003`, `TRDRV-004`, `DUC-003` | `G61`, `G62`, `G64` |
| 5 | `FLEET-005` | Implement protected service reservations and interference-aware co-scheduling | `FLEET-002`, `NODE-006`, `OBS-004` | `G68`, `G74` |
| 6 | `FLEET-006` | Implement elastic worker-group membership and rendezvous control | `FLEET-003`, `TRAIN-008`, `TRAIN-009` | `G64` |
| 7 | `FLEET-007` | Implement preemption, rescheduling, and failure-domain policy | `FLEET-003`, `FND-004`, `INC-002` | `G63`, `G65`, `G87`, `G88` |
| 8 | `FLEET-008` | Implement heterogeneous workload decomposition policy | `WORK-003`, `FLEET-004` | `G61`, `G68`, `G70` |
| 9 | `FLEET-009` | Implement provider capacity and elastic-infrastructure interfaces | `FLEET-002`, `NODE-001`, `ACT-001` | `G66`, `G68` |
| 10 | `FLEET-010` | Implement scheduling explanations, dry runs, and capacity simulation | `FLEET-001`, `EVID-002`, `RPLY-006` | `G62`, `G67` |
| 11 | `FLEET-011` | Harden scheduler reconciliation, availability, and 1,000-node scale | `FLEET-003`, `EVT-006`, `STA-005`, `OBS-008` | `G68`, `G88` |

## Component 13 — Workload Controller

`splendor.workload-controller` · `execution_fabric` · declared owner: crates/splendor-fabric (workload module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `WORK-001` | Implement the canonical WorkloadSpec and lifecycle state machine | `FND-001`, `FND-003`, `FND-007` | `G00`, `G04` |
| 2 | `WORK-002` | Implement validation, planning, and admission receipts | `WORK-001`, `AUTH-003`, `ART-006`, `DUC-002`, `DRREG-003`, `FLEET-001` | `G01`, `G08`, `G09`, `G34`, `G60` |
| 3 | `WORK-003` | Implement task-graph expansion and role semantics | `WORK-001`, `FND-007` | `G18`, `G19`, `G58`, `G61`, `G70` |
| 4 | `WORK-004` | Implement attempts, idempotency, fencing, and result acceptance | `WORK-001`, `FLEET-003`, `NODE-003`, `FND-004` | `G63`, `G65`, `G87`, `G88` |
| 5 | `WORK-005` | Implement pause, checkpoint, resume, cancel, timeout, and expiration | `WORK-004`, `NODE-008`, `ART-002` | `G52`, `G63`, `G69`, `G75`, `G87` |
| 6 | `WORK-006` | Implement progress, checkpoint, output, and terminal result contracts | `WORK-001`, `ART-002`, `LIN-002`, `EVID-001` | `G17`, `G39`, `G47`, `G52`, `G69` |
| 7 | `WORK-007` | Implement continuous, recurring, triggered, and service workloads | `WORK-001`, `EVT-004`, `AUTH-006` | `G19`, `G29`, `G38`, `G49`, `G70` |
| 8 | `WORK-008` | Implement managed, observed, and unmanaged execution modes | `WORK-001`, `LIN-005`, `GATE-002` | `G06`, `G14` |
| 9 | `WORK-009` | Integrate current runs, daemon, CLI, and SDK without duplicate lifecycle owners | `WORK-001`, `FND-006`, `FND-010` | `G04`, `G06` |
| 10 | `WORK-010` | Harden reconciliation, garbage collection, and controller availability | `WORK-004`, `EVT-006`, `STA-005` | `G04`, `G65`, `G87`, `G88` |

## Component 14 — Driver Registry

`splendor.driver-registry` · `driver_boundary` · declared owner: crates/splendor-gateway (registry module) with manifests in splendor-types; concrete drivers remain adapter crates

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `DRREG-001` | Define the universal DriverManifest and operation contract | `FND-001`, `FND-005` | `G07` |
| 2 | `DRREG-002` | Implement registration, installation, and conformance admission | `DRREG-001`, `ART-004`, `LIN-005`, `AUTH-003` | `G07`, `G83` |
| 3 | `DRREG-003` | Implement deterministic compatibility and driver resolution | `DRREG-001`, `DRREG-002`, `AUTH-001` | `G07`, `G15`, `G45`, `G61`, `G73` |
| 4 | `DRREG-004` | Implement driver lifecycle, revocation, deprecation, and rollout | `DRREG-002`, `FND-006`, `DEP-005` | `G65`, `G75`, `G83` |
| 5 | `DRREG-005` | Implement capability discovery and schema/tooling APIs | `DRREG-001`, `FND-010`, `FND-009` | `G00`, `G07` |
| 6 | `DRREG-006` | Build the driver authoring kit and conformance workflow | `DRREG-001`, `FND-005`, `FND-010` | `G07`, `G10`, `G12`, `G13`, `G14`, `G15` |

## Component 15 — Driver Gateway

`splendor.driver-gateway` · `driver_boundary` · declared owner: crates/splendor-gateway (invocation module); current action gateway preserved as compatibility facade

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `DGW-001` | Implement the universal driver invocation state machine | `DRREG-003`, `FND-003`, `FND-007` | `G01`, `G07`, `G15` |
| 2 | `DGW-002` | Implement composable pre-, in-, and post-invocation verifier stages | `DGW-001`, `AUTH-003`, `DUC-002` | `G15`, `G27`, `G73`, `G78`, `G80` |
| 3 | `DGW-003` | Issue scoped invocation handles for secrets, data, artifacts, state, and channels | `DGW-001`, `SECR-002`, `ART-002`, `DUC-003`, `NODE-003` | `G08`, `G16`, `G34`, `G82`, `G83` |
| 4 | `DGW-004` | Implement idempotency, retry, compensation, and effect certainty | `DGW-001`, `FND-004`, `INC-001` | `G15`, `G16`, `G47`, `G87` |
| 5 | `DGW-005` | Implement streaming, flow control, cancellation, and deadlines | `DGW-001`, `FND-008` | `G20`, `G22`, `G23`, `G53`, `G74` |
| 6 | `DGW-006` | Implement secure local and remote driver transports | `DGW-001`, `NODE-001`, `FND-006` | `G07`, `G81` |
| 7 | `DGW-007` | Enforce driver isolation and nested-operation policy | `DGW-003`, `SBX-007`, `AUTH-005`, `INC-003` | `G80`, `G81`, `G82`, `G83`, `G84`, `G85` |
| 8 | `DGW-008` | Implement invocation evidence, redaction, and high-volume separation | `DGW-001`, `EVID-001`, `FND-009` | `G03`, `G15`, `G39`, `G73`, `G82` |
| 9 | `DGW-009` | Migrate current action adapters through the universal gateway | `DGW-001`, `DGW-002`, `FND-006` | `G07`, `G15`, `G73` |

## Component 16 — Perceptor Driver Contract and Reference Drivers

`splendor.perceptor-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; concrete providers in `adapters/perceptors/*`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `PERC-001` | Define the observation envelope, identity, and provenance model | `DRREG-001`, `ART-001`, `FND-008` | `G20`, `G21` |
| 2 | `PERC-002` | Implement pull, push, subscription, and streaming lifecycle profiles | `PERC-001`, `DGW-005`, `WORK-007` | `G20`, `G21`, `G22` |
| 3 | `PERC-003` | Implement ordering, watermarks, deduplication, freshness, and backpressure | `PERC-002`, `EVT-004`, `STA-006` | `G22`, `G29` |
| 4 | `PERC-004` | Implement artifact-backed multimodal payload and transform declarations | `PERC-001`, `ART-002`, `LIN-002`, `DUC-004` | `G21`, `G26` |
| 5 | `PERC-005` | Implement source quality, calibration, uncertainty, and health signals | `PERC-001`, `EVID-002`, `WORLD-003` | `G23`, `G73`, `G74` |
| 6 | `PERC-006` | Enforce data-use, privacy, consent, and source authority at collection time | `PERC-002`, `DUC-001`, `NODE-004` | `G26`, `G34`, `G35`, `G73` |
| 7 | `PERC-007` | Implement live, recorded, simulated, and null execution profiles | `PERC-001`, `RPLY-002` | `G03`, `G23`, `G25`, `G73` |
| 8 | `PERC-008` | Build reference perceptors across software and physical domains | `PERC-001`, `PERC-007`, `DRREG-006` | `G20`, `G21`, `G22`, `G23`, `G73`, `G74` |
| 9 | `PERC-009` | Add perceptor conformance and adversarial validation | `PERC-002`, `PERC-006`, `FND-005` | `G07`, `G20`, `G21`, `G22`, `G23` |

## Component 17 — Actuator Driver Contract and Reference Drivers

`splendor.actuator-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; concrete implementations in `adapters/actuators/*`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `ACT-001` | Define actuator operations and capability semantics | `DRREG-001`, `DGW-001` | `G15`, `G16`, `G73` |
| 2 | `ACT-002` | Implement precondition, postcondition, and outcome observation contracts | `ACT-001`, `DGW-002`, `WORLD-003` | `G15`, `G47`, `G73` |
| 3 | `ACT-003` | Implement idempotent, compensatable, and uncertain-effect operation patterns | `ACT-001`, `DGW-004` | `G15`, `G16`, `G47`, `G87` |
| 4 | `ACT-004` | Implement long-running and streaming actuator operations | `ACT-001`, `DGW-005`, `WORK-005` | `G14`, `G15`, `G73`, `G75` |
| 5 | `ACT-005` | Implement shell, process, database, Kubernetes, and service reference actuators | `ACT-001`, `SBX-001`, `SECR-002` | `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16` |
| 6 | `ACT-006` | Implement physical-device and robot high-level actuator boundary | `ACT-001`, `NODE-006`, `DGW-002`, `WORLD-009` | `G73`, `G74`, `G75`, `G80` |
| 7 | `ACT-007` | Implement sub-agent and trigger-agent actuator profiles | `ACT-001`, `AGREG-005`, `MSG-003`, `AINST-006` | `G18`, `G19`, `G70`, `G81` |
| 8 | `ACT-008` | Implement actuator conformance, simulation, and fault validation | `ACT-001`, `FND-005`, `RPLY-002` | `G07`, `G15`, `G16`, `G45`, `G73` |

## Component 18 — Model Driver Contract and Reference Drivers

`splendor.model-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; implementations in `adapters/models/*`; optional Python helpers in `python/splendor`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `MODEL-001` | Define model manifests, artifacts, operations, and compatibility | `ART-001`, `DRREG-001` | `G53`, `G54` |
| 2 | `MODEL-002` | Implement model load, instance, session, and unload lifecycle | `MODEL-001`, `NODE-003`, `STA-001` | `G53`, `G68` |
| 3 | `MODEL-003` | Implement generic inference request/result and streaming semantics | `MODEL-001`, `DGW-005`, `FND-009` | `G53`, `G54` |
| 4 | `MODEL-004` | Implement local PyTorch/Transformers and remote-provider reference drivers | `MODEL-001`, `MODEL-003`, `SBX-004`, `SECR-002` | `G53`, `G54` |
| 5 | `MODEL-005` | Implement batching, admission, quotas, and latency control | `MODEL-002`, `AUTH-004`, `NODE-006`, `OBS-004` | `G53`, `G68` |
| 6 | `MODEL-006` | Implement explicit model routing inputs and outcome evidence | `MODEL-001`, `ROUTE-001`, `DUC-002` | `G24`, `G28` |
| 7 | `MODEL-007` | Implement adapter, ensemble, and composed-model declarations | `MODEL-001`, `LIN-002`, `TRAIN-014` | `G55` |
| 8 | `MODEL-008` | Enforce inference isolation, data controls, and no-training boundary | `MODEL-002`, `DUC-001`, `COLL-001`, `NODE-004` | `G34`, `G40`, `G43`, `G84` |
| 9 | `MODEL-009` | Implement determinism, caching, and reproducibility profiles | `MODEL-003`, `FND-008`, `RPLY-003` | `G39`, `G42`, `G52`, `G53` |
| 10 | `MODEL-010` | Implement model-driver conformance and conversion examples | `MODEL-001`, `MODEL-004`, `FND-005` | `G07`, `G53`, `G54` |

## Component 19 — Trainer Driver Contract and Framework Adapters

`splendor.trainer-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; framework adapters in `adapters/trainers/*`; Python integration package `splendor-train`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `TRDRV-001` | Define the framework-neutral trainer worker protocol | `DRREG-001`, `WORK-001`, `DGW-001` | `G52`, `G54` |
| 2 | `TRDRV-002` | Define honest project compatibility tiers for arbitrary training projects | `TRDRV-001`, `SBX-004`, `LIN-004` | `G60`, `G61`, `G62`, `G63`, `G64` |
| 3 | `TRDRV-003` | Implement the PyTorch torchrun/elastic launch adapter | `TRDRV-002`, `FLEET-006`, `NODE-005` | `G64` |
| 4 | `TRDRV-004` | Implement DDP, FSDP, tensor, pipeline, and custom parallel adapters | `TRDRV-002`, `TRDRV-003`, `FLEET-004` | `G61`, `G62`, `G63`, `G64` |
| 5 | `TRDRV-005` | Implement structured progress, metric, and safe-point callbacks | `TRDRV-001`, `DGW-005`, `OBS-004` | `G52`, `G63`, `G68` |
| 6 | `TRDRV-006` | Implement data-shard and cursor integration without owning dataset logic | `TRDRV-001`, `DODRV-007`, `TRAIN-008`, `DUC-003` | `G52`, `G56`, `G58`, `G64` |
| 7 | `TRDRV-007` | Implement distributed checkpoint and restore protocol | `TRDRV-004`, `NODE-008`, `ART-002`, `FND-008` | `G52`, `G63`, `G64`, `G69` |
| 8 | `TRDRV-008` | Implement candidate-bundle finalization and publication | `TRDRV-007`, `LIN-002`, `MODEL-001` | `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G83` |
| 9 | `TRDRV-009` | Provide non-PyTorch and custom trainer adapter path | `TRDRV-001`, `WORK-008`, `SBX-005` | `G06`, `G54` |
| 10 | `TRDRV-010` | Build trainer conformance and distributed failure matrix | `TRDRV-001`, `TRDRV-008`, `FND-005` | `G52`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69` |

## Component 20 — Evaluator Driver Contract and Reference Drivers

`splendor.evaluator-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; implementations in `adapters/evaluators/*`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `EVDRV-001` | Define evaluator operation and result schemas | `DRREG-001`, `EVID-001` | `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49` |
| 2 | `EVDRV-002` | Implement modality- and domain-agnostic metric plugin interfaces | `EVDRV-001`, `FND-001` | `G39`, `G42`, `G44`, `G47`, `G57` |
| 3 | `EVDRV-003` | Implement protected-case execution and blind result protocol | `EVDRV-001`, `DUC-006`, `NODE-009`, `DGW-007` | `G40`, `G43`, `G44`, `G84`, `G86` |
| 4 | `EVDRV-004` | Implement distributed case/episode sharding and deterministic aggregation | `EVDRV-001`, `WORK-003`, `FLEET-008` | `G42`, `G61`, `G68` |
| 5 | `EVDRV-005` | Implement statistical, calibration, and uncertainty evaluator helpers | `EVDRV-002`, `EVID-003` | `G42`, `G46` |
| 6 | `EVDRV-006` | Implement interactive, world-model, RL, and physical evaluation profiles | `EVDRV-001`, `RPLY-005`, `WORLD-007`, `ACT-006` | `G47`, `G57`, `G58`, `G59`, `G73`, `G77` |
| 7 | `EVDRV-007` | Implement learned-judge and human-review protocols with independence evidence | `EVDRV-001`, `FDBK-002`, `GATE-003` | `G41`, `G44`, `G48`, `G86` |
| 8 | `EVDRV-008` | Implement evaluator conformance and adversarial validation | `EVDRV-001`, `FND-005` | `G07`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49` |

## Component 21 — Data Operator Driver Contract and Reference Drivers

`splendor.data-operator-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; implementations in `adapters/data/*`

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `DODRV-001` | Define the data operation and record/batch contract | `DRREG-001`, `ART-001`, `LIN-001` | `G30`, `G31` |
| 2 | `DODRV-002` | Implement source connectors, cursors, and snapshot extraction | `DODRV-001`, `PERC-002`, `DUC-003` | `G30`, `G38` |
| 3 | `DODRV-003` | Implement schema, integrity, validity, and distribution quality operators | `DODRV-001`, `EVID-001` | `G31`, `G32` |
| 4 | `DODRV-004` | Implement deduplication, similarity, and leakage-safe grouping operators | `DODRV-001`, `LIN-003`, `DUC-006` | `G32`, `G33`, `G36`, `G43` |
| 5 | `DODRV-005` | Implement contamination, memorization-risk, and overlap scanning | `DODRV-004`, `EVDRV-003` | `G33`, `G43`, `G51`, `G86` |
| 6 | `DODRV-006` | Implement labeling, annotation, enrichment, and synthetic-data operators | `DODRV-001`, `FDBK-001`, `MODEL-003` | `G36`, `G37`, `G48`, `G56` |
| 7 | `DODRV-007` | Implement deterministic split, shard, sampling, and data-assignment operators | `DODRV-004`, `STA-001`, `FND-008` | `G33`, `G39`, `G42`, `G52`, `G64` |
| 8 | `DODRV-008` | Implement distributed data-operation execution and aggregation | `DODRV-001`, `WORK-003`, `FLEET-008` | `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G61`, `G68` |
| 9 | `DODRV-009` | Build data-operator conformance and audit validation | `DODRV-001`, `FND-005`, `LIN-005` | `G07`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38` |

## Component 22 — Sandbox and Executor Driver Contract

`splendor.sandbox-executor-driver` · `driver_boundary` · declared owner: contract in crates/splendor-types and splendor-gateway; implementations in `adapters/executors/*` and Node Agent host backends

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `SBX-001` | Define executor operations, environment specs, and isolation profiles | `DRREG-001`, `NODE-005`, `FND-011` | `G10`, `G11`, `G12`, `G13`, `G14` |
| 2 | `SBX-002` | Implement restricted argv process execution | `SBX-001`, `NODE-009` | `G10` |
| 3 | `SBX-003` | Implement explicit high-risk shell execution | `SBX-001`, `AUTH-007`, `DGW-007` | `G11`, `G80`, `G81`, `G82` |
| 4 | `SBX-004` | Implement reproducible locked Python environments | `SBX-001`, `ART-004`, `LIN-002` | `G12`, `G52`, `G53`, `G54` |
| 5 | `SBX-005` | Implement OCI image execution and build workflows | `SBX-001`, `ART-004`, `NODE-009` | `G13`, `G83` |
| 6 | `SBX-006` | Implement Kubernetes Job and workload execution adapter | `SBX-001`, `WORK-008`, `FLEET-003` | `G14`, `G61`, `G63`, `G66` |
| 7 | `SBX-007` | Implement filesystem, network, process, syscall, IPC, and device isolation | `SBX-001`, `NODE-009` | `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G80`, `G81`, `G82`, `G83` |
| 8 | `SBX-008` | Implement governed mounts, secrets, data handles, and output publication | `SBX-007`, `NODE-004`, `SECR-002`, `ART-002` | `G08`, `G13`, `G17`, `G34`, `G82` |
| 9 | `SBX-009` | Implement resource accounting, limits, deadlines, and cleanup | `SBX-001`, `NODE-003`, `AUTH-004` | `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G63`, `G68` |
| 10 | `SBX-010` | Implement interactive coding and persistent workspace sessions | `SBX-002`, `SBX-004`, `STA-001`, `CHG-008` | `G47`, `G76` |
| 11 | `SBX-011` | Implement environment build, cache, and reproducibility receipts | `SBX-004`, `SBX-005`, `ART-004`, `LIN-002` | `G12`, `G13`, `G52`, `G83` |
| 12 | `SBX-012` | Implement device image and edge workload deployment executor | `SBX-005`, `ACT-006`, `DEP-006` | `G73`, `G74`, `G75` |
| 13 | `SBX-013` | Build executor conformance and cross-backend equivalence tests | `SBX-001`, `SBX-009`, `FND-005` | `G07`, `G10`, `G11`, `G12`, `G13`, `G14`, `G80`, `G81`, `G82`, `G83` |

## Component 23 — Agent Registry

`splendor.agent-registry` · `agent_cognition` · declared owner: crates/splendor-agent (registry module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `AGREG-001` | Define AgentSpec and immutable revision semantics | `FND-001`, `ART-001`, `DRREG-001` | `G23`, `G29` |
| 2 | `AGREG-002` | Define typed component bindings and compatibility validation | `AGREG-001`, `ROUTE-009`, `MODEL-001` | `G24`, `G28`, `G54`, `G55` |
| 3 | `AGREG-003` | Define authority, value, constraint, and data bindings as independent profiles | `AGREG-001`, `AUTH-003`, `GATE-001`, `DUC-001` | `G27`, `G40`, `G78`, `G79`, `G86` |
| 4 | `AGREG-004` | Implement revision derivation, diff, migration, and compatibility history | `AGREG-001`, `CHG-001`, `LIN-001` | `G45`, `G70`, `G76`, `G79` |
| 5 | `AGREG-005` | Implement sub-agent templates and topology constraints | `AGREG-001`, `AUTH-005`, `MSG-003` | `G18`, `G19`, `G70`, `G77`, `G81` |
| 6 | `AGREG-006` | Implement desired-state pointers, ownership, visibility, and lifecycle policy | `AGREG-001`, `DEP-001`, `AUTH-001` | `G70`, `G75`, `G79` |
| 7 | `AGREG-007` | Implement framework bridges and portable import/export | `AGREG-001`, `WORK-008`, `FND-010` | `G06`, `G23`, `G24`, `G54` |
| 8 | `AGREG-008` | Build AgentSpec conformance and anti-drift fixtures | `AGREG-001`, `AGREG-003`, `FND-005` | `G00`, `G23`, `G29`, `G70` |

## Component 24 — Agent Instance Controller

`splendor.agent-instance-controller` · `agent_cognition` · declared owner: crates/splendor-agent (instance module), composed by splendor-kernel

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `AINST-001` | Implement the durable AgentInstance state machine and identities | `AGREG-001`, `WORK-001`, `STA-001` | `G23`, `G29` |
| 2 | `AINST-002` | Implement instance admission and dependency realization | `AINST-001`, `AGREG-002`, `ROUTE-009`, `DEP-002` | `G23`, `G24`, `G62`, `G73` |
| 3 | `AINST-003` | Implement event-driven 24/7 supervision, timers, and triggers | `AINST-001`, `WORK-007`, `PERC-003`, `MSG-006` | `G19`, `G22`, `G29`, `G38`, `G49` |
| 4 | `AINST-004` | Implement run-session concurrency and state/world consistency policy | `AINST-003`, `STA-003`, `WORLD-008`, `DGW-004` | `G24`, `G27`, `G29`, `G70` |
| 5 | `AINST-005` | Implement pause, quiesce, checkpoint, resume, migration, and handoff | `AINST-001`, `WORK-005`, `STA-007`, `NODE-003` | `G29`, `G65`, `G69`, `G72`, `G75` |
| 6 | `AINST-006` | Implement sub-agent spawn, supervision, delegation, and reaping | `AGREG-005`, `MSG-003`, `WORK-003` | `G18`, `G19`, `G70`, `G77`, `G81` |
| 7 | `AINST-007` | Implement instance health, SLO, degraded modes, and circuit-breaker behavior | `AINST-003`, `OBS-005`, `INC-002` | `G27`, `G29`, `G48`, `G73`, `G74`, `G75`, `G88` |
| 8 | `AINST-008` | Implement controlled revision transition per instance | `AINST-005`, `DEP-003`, `DEP-004`, `CHG-007` | `G45`, `G46`, `G70`, `G75`, `G79` |
| 9 | `AINST-009` | Migrate the current LoopEngine and Scheduler into the instance architecture | `AINST-001`, `WORK-009`, `DGW-009`, `FND-006` | `G23`, `G24` |
| 10 | `AINST-010` | Validate long-duration, fleet, and chaos behavior | `AINST-001`, `AINST-007`, `FND-005` | `G29`, `G68`, `G70`, `G72`, `G73`, `G74`, `G75`, `G88` |

## Component 25 — Neuro-Symbolic Route Runtime

`splendor.route-runtime` · `agent_cognition` · declared owner: crates/splendor-agent (route module); user-space node plugins via SDK/workloads

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `ROUTE-001` | Define typed RouteGraph, nodes, ports, and edges | `FND-001`, `AGREG-002`, `DGW-001` | `G24`, `G28` |
| 2 | `ROUTE-002` | Implement neural/model node semantics as proposal-producing computation | `ROUTE-001`, `MODEL-003`, `FND-007` | `G24`, `G27`, `G28`, `G80` |
| 3 | `ROUTE-003` | Implement symbolic planner, solver, rule, and state-machine plugin semantics | `ROUTE-001`, `SBX-004`, `EVID-002` | `G24`, `G25`, `G26`, `G27` |
| 4 | `ROUTE-004` | Implement constraint, obligation, verifier, and approval control points | `ROUTE-001`, `DGW-002`, `GATE-001` | `G27`, `G40`, `G73`, `G78`, `G79` |
| 5 | `ROUTE-005` | Implement state, memory, world, message, and sub-agent nodes | `ROUTE-001`, `STA-003`, `WORLD-003`, `MSG-001`, `AINST-006` | `G18`, `G23`, `G24`, `G25`, `G29`, `G70` |
| 6 | `ROUTE-006` | Implement branches, joins, bounded loops, parallelism, and budgets | `ROUTE-001`, `AUTH-004`, `WORK-003` | `G24`, `G28`, `G29`, `G70`, `G88` |
| 7 | `ROUTE-007` | Implement uncertainty, fallback, escalation, and degraded routing | `ROUTE-001`, `AINST-007`, `AUTH-007` | `G27`, `G28`, `G29`, `G48`, `G73`, `G74`, `G75` |
| 8 | `ROUTE-008` | Implement user-space pure node and sub-route SDK | `ROUTE-001`, `SBX-001`, `FND-010` | `G24`, `G54`, `G80` |
| 9 | `ROUTE-009` | Implement route validation, compilation, compatibility, and explain plans | `ROUTE-001`, `DRREG-003`, `AGREG-002` | `G24`, `G27`, `G28`, `G73`, `G80` |
| 10 | `ROUTE-010` | Implement route execution evidence, checkpoint, and replay comparison | `ROUTE-001`, `EVID-001`, `RPLY-004` | `G03`, `G24`, `G39`, `G45`, `G46` |
| 11 | `ROUTE-011` | Implement controlled route hot-swap and version rollout | `ROUTE-009`, `CHG-001`, `DEP-003` | `G45`, `G46`, `G70`, `G76`, `G79` |

## Component 26 — World-State and Memory Service

`splendor.world-state-service` · `agent_cognition` · declared owner: crates/splendor-agent (world module); persistence interfaces in splendor-store

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `WORLD-001` | Define world partitions, claims, and truth-status taxonomy | `FND-001`, `STA-001`, `PERC-001` | `G23`, `G25` |
| 2 | `WORLD-002` | Implement schema, entity, relation, time, and unit interoperability hooks | `WORLD-001`, `DODRV-001`, `ART-001` | `G21`, `G23`, `G25`, `G73` |
| 3 | `WORLD-003` | Implement observation assimilation proposals and conflict-aware commits | `WORLD-001`, `STA-003`, `LIN-002`, `FND-007` | `G23`, `G24`, `G25`, `G29` |
| 4 | `WORLD-004` | Implement uncertainty and belief representation interfaces | `WORLD-001`, `EVDRV-005` | `G23`, `G25`, `G42`, `G57` |
| 5 | `WORLD-005` | Implement explicit memory partition profiles and retention | `WORLD-001`, `DUC-004`, `DODRV-008` | `G23`, `G26`, `G35`, `G38` |
| 6 | `WORLD-006` | Represent learned world models as versioned model bindings | `WORLD-001`, `MODEL-001`, `EVAL-006` | `G57`, `G59` |
| 7 | `WORLD-007` | Implement simulation, counterfactual, and rollout branches | `WORLD-001`, `RPLY-005`, `WORK-003` | `G25`, `G57`, `G58`, `G59`, `G73` |
| 8 | `WORLD-008` | Implement multi-agent shared/private views and consistency | `WORLD-001`, `MSG-001`, `AUTH-005`, `STA-004` | `G70`, `G72`, `G77`, `G81` |
| 9 | `WORLD-009` | Implement physical-world frames, local safety state, and latency classes | `WORLD-002`, `NODE-007`, `ACT-006` | `G73`, `G74`, `G75` |
| 10 | `WORLD-010` | Implement retention, deletion, privacy, and knowledge invalidation | `WORLD-005`, `DUC-004`, `LIN-003` | `G26`, `G35`, `G43`, `G83` |
| 11 | `WORLD-011` | Implement world-schema/model change and rollout controls | `WORLD-001`, `CHG-001`, `DEP-003` | `G45`, `G46`, `G57`, `G59`, `G70` |
| 12 | `WORLD-012` | Build domain-diverse world-model gold examples | `WORLD-001`, `WORLD-011`, `FND-005` | `G23`, `G24`, `G25`, `G57`, `G59`, `G73`, `G77` |

## Component 27 — Message and Delegation Service

`splendor.message-delegation-service` · `agent_cognition` · declared owner: crates/splendor-agent (message/delegation module), extending current splendor-kernel message_router/local_delegation/remote_transport

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `MSG-001` | Evolve the stable message envelope while preserving 0.1 semantics | `FND-001`, `FND-006`, `ART-001` | `G18`, `G19`, `G70`, `G81` |
| 2 | `MSG-002` | Implement durable delivery, deduplication, ordering, acknowledgements, and retries | `MSG-001`, `FND-003`, `STA-006` | `G18`, `G19`, `G70`, `G72`, `G81` |
| 3 | `MSG-003` | Implement attenuated delegation grants and chains | `AUTH-005`, `MSG-001` | `G18`, `G70`, `G77`, `G78`, `G81` |
| 4 | `MSG-004` | Implement task request/response and long-running conversation contracts | `MSG-003`, `AINST-006`, `WORK-003` | `G18`, `G70`, `G77` |
| 5 | `MSG-005` | Harden remote transport, routing, identity, and offline queues | `MSG-002`, `NODE-001`, `STA-007` | `G70`, `G72`, `G75`, `G81` |
| 6 | `MSG-006` | Implement event subscriptions and trigger-agent routing | `MSG-001`, `AINST-003`, `WORK-007` | `G19`, `G22`, `G29`, `G38`, `G49` |
| 7 | `MSG-007` | Implement mailbox quotas, priorities, backpressure, and dead letters | `MSG-002`, `AUTH-004`, `OBS-005` | `G22`, `G68`, `G81`, `G88` |
| 8 | `MSG-008` | Implement causal trace, replay, and state-transition integration | `MSG-001`, `RPLY-004`, `EVID-002` | `G03`, `G18`, `G70`, `G72` |
| 9 | `MSG-009` | Implement external agent/framework bridges with reduced guarantees | `MSG-001`, `DGW-006`, `WORK-008` | `G06`, `G18`, `G70`, `G81` |
| 10 | `MSG-010` | Build message/delegation adversarial and conformance suite | `MSG-001`, `MSG-007`, `FND-005` | `G18`, `G19`, `G70`, `G72`, `G77`, `G81`, `G88` |

## Component 28 — Collection Controller

`splendor.collection-controller` · `data_learning` · declared owner: crates/splendor-learning (collection module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `COLL-001` | Define CollectionPlan and lifecycle state machine | `FND-001`, `DUC-001`, `WORK-007` | `G30`, `G38` |
| 2 | `COLL-002` | Implement source admission, subscriptions, extraction, and cursor ownership | `COLL-001`, `PERC-002`, `DODRV-002`, `STA-006` | `G30`, `G35`, `G38` |
| 3 | `COLL-003` | Implement sampling, coverage, diversity, and active-acquisition policy | `COLL-001`, `DODRV-007`, `FDBK-004` | `G32`, `G37`, `G38`, `G48` |
| 4 | `COLL-004` | Implement recordization of observations, actions, outcomes, traces, feedback, and trajectories | `COLL-002`, `FDBK-001`, `LIN-002` | `G30`, `G37`, `G47`, `G56`, `G58` |
| 5 | `COLL-005` | Implement collection entry validation, quarantine, and poisoning defenses | `COLL-004`, `DODRV-003`, `INC-002` | `G31`, `G32`, `G36`, `G48`, `G84`, `G85` |
| 6 | `COLL-006` | Implement privacy, consent, retention, deletion, and minimization operations | `COLL-001`, `DUC-004`, `LIN-003`, `ART-003` | `G26`, `G34`, `G35`, `G83` |
| 7 | `COLL-007` | Implement fleet/device-local collection, buffering, and synchronization | `COLL-002`, `NODE-007`, `DODRV-008`, `FLEET-008` | `G38`, `G61`, `G68`, `G72`, `G74`, `G75` |
| 8 | `COLL-008` | Implement budgets, stopping conditions, rate adaptation, and cost accounting | `COLL-001`, `AUTH-004`, `OBS-004` | `G37`, `G38`, `G48`, `G68` |
| 9 | `COLL-009` | Implement immutable collection snapshot and dataset-candidate publication | `COLL-004`, `COLL-005`, `ART-002`, `LIN-002` | `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38` |
| 10 | `COLL-010` | Build collection gold examples and long-running fault suite | `COLL-001`, `COLL-009`, `FND-005` | `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G47`, `G56`, `G58`, `G74` |

## Component 29 — Feedback Service

`splendor.feedback-service` · `data_learning` · declared owner: crates/splendor-learning (feedback module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `FDBK-001` | Define FeedbackEvent identity, targets, kinds, and lifecycle | `FND-001`, `ART-001`, `FND-006` | `G37`, `G41` |
| 2 | `FDBK-002` | Implement human, environment, automated, model-judge, and system feedback channels | `FDBK-001`, `AUTH-001`, `EVDRV-007` | `G37`, `G41`, `G44`, `G48`, `G81` |
| 3 | `FDBK-003` | Implement causal attribution windows and target resolution | `FDBK-001`, `EVID-002`, `ROUTE-010` | `G37`, `G47`, `G48`, `G58` |
| 4 | `FDBK-004` | Implement reliability, calibration, disagreement, and source-drift metadata | `FDBK-002`, `EVDRV-005` | `G41`, `G44`, `G48`, `G85` |
| 5 | `FDBK-005` | Implement HIL review, correction, appeal, and escalation workflows | `FDBK-001`, `AUTH-007`, `EVDRV-007` | `G40`, `G41`, `G48`, `G73`, `G78` |
| 6 | `FDBK-006` | Implement privacy, consent, subject access, and deletion for feedback | `FDBK-001`, `DUC-004`, `COLL-006` | `G26`, `G34`, `G35`, `G41` |
| 7 | `FDBK-007` | Implement immutable feedback views, aggregation, and export | `FDBK-004`, `DODRV-001`, `LIN-002` | `G37`, `G41`, `G48`, `G56` |
| 8 | `FDBK-008` | Separate operational control, evaluation, and learning uses | `FDBK-001`, `DUC-002`, `LIN-001` | `G37`, `G40`, `G48`, `G70`, `G78` |
| 9 | `FDBK-009` | Implement poisoning, manipulation, collusion, and feedback-loop defenses | `FDBK-002`, `FDBK-004`, `INC-002`, `EVDRV-007` | `G48`, `G84`, `G85`, `G86` |
| 10 | `FDBK-010` | Build feedback gold examples and end-to-end provenance tests | `FDBK-001`, `FDBK-009`, `FND-005` | `G37`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G56`, `G58`, `G70`, `G73` |

## Component 30 — Reward Derivation Service

`splendor.reward-derivation-service` · `data_learning` · declared owner: crates/splendor-learning (reward module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `REWD-001` | Define RewardDefinition, RewardSignal, targets, and lifecycle | `FND-001`, `FDBK-001`, `EVID-001` | `G48`, `G58` |
| 2 | `REWD-002` | Implement pure, versioned reward derivation workloads | `REWD-001`, `WORK-001`, `SBX-004`, `LIN-002` | `G48`, `G58`, `G85` |
| 3 | `REWD-003` | Implement multi-objective, constraints, costs, and value-profile mapping | `REWD-001`, `AGREG-003`, `GATE-004` | `G27`, `G48`, `G58`, `G78`, `G79` |
| 4 | `REWD-004` | Implement delayed credit assignment and trajectory attribution hooks | `REWD-002`, `FDBK-003`, `WORLD-007` | `G58`, `G77` |
| 5 | `REWD-005` | Implement reward normalization, calibration, aggregation, and immutable views | `REWD-001`, `FDBK-007`, `LIN-002` | `G48`, `G58` |
| 6 | `REWD-006` | Implement learned reward/value model bindings and independence | `REWD-002`, `MODEL-001`, `EVDRV-007` | `G44`, `G48`, `G56`, `G86` |
| 7 | `REWD-007` | Implement reward hacking, proxy drift, and tamper monitoring | `REWD-003`, `EVAL-010`, `FDBK-009`, `INC-002` | `G48`, `G84`, `G85`, `G86` |
| 8 | `REWD-008` | Implement reward access, privacy, and protected-signal handling | `REWD-005`, `DUC-006`, `NODE-004` | `G40`, `G43`, `G58`, `G84`, `G86` |
| 9 | `REWD-009` | Build reward/RL gold examples and invariance tests | `REWD-001`, `REWD-008`, `FND-005` | `G47`, `G48`, `G56`, `G58`, `G77`, `G86` |

## Component 31 — Evaluation Controller

`splendor.eval-controller` · `data_learning` · declared owner: crates/splendor-learning (eval module)

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `EVAL-001` | Define EvalSuite, EvalPlan, EvalRun, and lifecycle | `FND-001`, `EVDRV-001`, `WORK-001` | `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49` |
| 2 | `EVAL-002` | Implement immutable case manifests, splits, and protected holdouts | `EVAL-001`, `DODRV-007`, `EVDRV-003`, `DUC-006` | `G40`, `G43`, `G51`, `G84`, `G86` |
| 3 | `EVAL-003` | Implement paired candidate/baseline execution plans | `EVAL-001`, `RPLY-004`, `WORLD-007` | `G42`, `G45`, `G46` |
| 4 | `EVAL-004` | Implement distributed evaluation, case accounting, and aggregation | `EVAL-001`, `EVDRV-004`, `FLEET-008` | `G42`, `G61`, `G68`, `G83` |
| 5 | `EVAL-005` | Implement metric validation, slices, uncertainty, and analysis plans | `EVAL-001`, `EVDRV-002`, `EVDRV-005` | `G39`, `G42`, `G46`, `G47`, `G57` |
| 6 | `EVAL-006` | Implement capability, regression, safety, value, robustness, and resource eval classes | `EVAL-005`, `AGREG-003` | `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G57`, `G58`, `G59`, `G73`, `G77`, `G78` |
| 7 | `EVAL-007` | Implement contamination, memorization, overfitting, and adaptive-eval checks | `EVAL-002`, `DODRV-005`, `LIN-003` | `G33`, `G43`, `G51`, `G56`, `G86` |
| 8 | `EVAL-008` | Implement online, shadow, canary, and post-deployment evaluation | `EVAL-003`, `DEP-003`, `DEP-004`, `COLL-001` | `G45`, `G46`, `G49`, `G70`, `G73`, `G75` |
| 9 | `EVAL-009` | Implement human, multi-agent, world-model, and physical eval orchestration | `EVAL-001`, `EVDRV-006`, `EVDRV-007`, `AGREG-005` | `G41`, `G57`, `G58`, `G59`, `G73`, `G77` |
| 10 | `EVAL-010` | Implement evaluator independence and reward-hacking analysis | `EVAL-006`, `REWD-007`, `LIN-003` | `G44`, `G48`, `G76`, `G84`, `G85`, `G86` |
| 11 | `EVAL-011` | Publish EvalReport, regression findings, and gate-ready evidence | `EVAL-004`, `EVAL-005`, `EVAL-007`, `EVAL-010`, `EVID-003` | `G39`, `G42`, `G45`, `G46`, `G47`, `G48`, `G49`, `G83`, `G86` |
| 12 | `EVAL-012` | Implement continuous evaluation scheduling and drift response | `EVAL-001`, `WORK-007`, `OBS-005` | `G49`, `G59`, `G70`, `G75`, `G88` |

## Component 32 — Training Controller

`splendor.training-controller` · `data_learning` · declared owner: crates/splendor-learning (training module); PyTorch/framework algorithms stay in trainer adapters and user code

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `TRAIN-001` | Define TrainingSpec, TrainingRun, stage graph, and lifecycle | `FND-001`, `WORK-001`, `TRDRV-001` | `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69` |
| 2 | `TRAIN-002` | Implement arbitrary project intake and static/dynamic inspection | `TRAIN-001`, `TRDRV-002`, `SBX-004` | `G60` |
| 3 | `TRAIN-003` | Implement and enforce T0–T3 project compatibility tiers | `TRAIN-002`, `TRDRV-002` | `G60`, `G61`, `G62`, `G63`, `G64` |
| 4 | `TRAIN-004` | Implement reproducible build and runtime environment planning | `TRAIN-002`, `SBX-011`, `FLEET-004` | `G52`, `G60`, `G61`, `G62`, `G83` |
| 5 | `TRAIN-005` | Implement immutable data, feedback, reward, and split plan admission | `TRAIN-001`, `COLL-009`, `DODRV-007`, `FDBK-007`, `REWD-005`, `EVAL-002` | `G33`, `G34`, `G35`, `G36`, `G37`, `G40`, `G43`, `G51`, `G52`, `G56`, `G58` |
| 6 | `TRAIN-006` | Implement framework-neutral parallel and topology planning | `TRAIN-003`, `TRDRV-004`, `FLEET-004`, `FLEET-008` | `G61`, `G62`, `G63`, `G64` |
| 7 | `TRAIN-007` | Implement worker-group, rendezvous, launch, and epoch orchestration | `TRAIN-006`, `FLEET-003`, `FLEET-006`, `TRDRV-003` | `G63`, `G64` |
| 8 | `TRAIN-008` | Implement global batch, optimizer-step, sample, and data-cursor semantics | `TRAIN-005`, `TRAIN-007`, `TRDRV-006` | `G52`, `G64` |
| 9 | `TRAIN-009` | Implement checkpoint schedule, completeness, restore, and topology resharding control | `TRAIN-007`, `TRAIN-008`, `TRDRV-007`, `ART-002` | `G52`, `G63`, `G64`, `G69` |
| 10 | `TRAIN-010` | Implement failure classification, retry, preemption, straggler, and recovery policy | `TRAIN-001`, `FND-004`, `FLEET-007`, `INC-002` | `G63`, `G65`, `G69`, `G83`, `G88` |
| 11 | `TRAIN-011` | Implement live-inference and physical-service coexistence controls | `TRAIN-006`, `FLEET-005`, `NODE-006`, `OBS-004` | `G68`, `G74` |
| 12 | `TRAIN-012` | Implement trials, sweeps, population, and independent experiment fan-out | `TRAIN-001`, `WORK-003`, `FLEET-008`, `EVAL-007` | `G55`, `G56`, `G61`, `G67` |
| 13 | `TRAIN-013` | Implement continual, online, parameter-efficient, RL, and world-model training flows | `TRAIN-005`, `REWD-005`, `WORLD-006`, `EVAL-006` | `G55`, `G56`, `G57`, `G58`, `G59`, `G70` |
| 14 | `TRAIN-014` | Implement candidate bundle validation and candidate-only publication | `TRAIN-001`, `TRDRV-008`, `MODEL-001`, `LIN-005` | `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G83` |
| 15 | `TRAIN-015` | Implement framework plugin and non-PyTorch orchestration boundary | `TRAIN-003`, `TRDRV-009`, `WORK-008` | `G06`, `G54` |
| 16 | `TRAIN-016` | Implement training security, data isolation, and evaluator separation | `TRAIN-005`, `SBX-007`, `DGW-007`, `LIN-005` | `G40`, `G43`, `G82`, `G83`, `G84`, `G85`, `G86` |
| 17 | `TRAIN-017` | Build PyTorch 1→N equivalence, recovery, and project compatibility gold matrix | `TRAIN-001`, `TRAIN-016`, `TRDRV-010`, `FND-005` | `G52`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69` |
| 18 | `TRAIN-018` | Validate 1,000-device mixed training/eval/data orchestration and control-plane scale | `TRAIN-017`, `FLEET-011`, `WORK-010`, `OBS-008` | `G68`, `G88` |

## Component 33 — Improvement and Evolution Controller

`splendor.improvement-controller` · `data_learning` · declared owner: crates/splendor-learning (improvement module); optimization/search algorithms remain user-space plugins

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `IMPR-001` | Define improvement goals, hypotheses, programs, and lifecycle | `FND-001`, `EVAL-011`, `AGREG-003` | `G70`, `G76` |
| 2 | `IMPR-002` | Implement evidence-triggered opportunity and failure proposal intake | `IMPR-001`, `FDBK-008`, `EVAL-012`, `INC-002` | `G48`, `G49`, `G59`, `G70`, `G88` |
| 3 | `IMPR-003` | Implement experiment DAG construction and kernel validation | `IMPR-001`, `WORK-003`, `TRAIN-001`, `EVAL-001` | `G55`, `G56`, `G57`, `G58`, `G59`, `G70`, `G76` |
| 4 | `IMPR-004` | Implement candidate portfolio, selection, and Pareto evidence | `IMPR-003`, `EVAL-011`, `REWD-003` | `G55`, `G56`, `G70`, `G76` |
| 5 | `IMPR-005` | Define self-adjustment risk classes and allowed mutation envelopes | `IMPR-001`, `AGREG-003`, `GATE-004` | `G70`, `G76`, `G78`, `G79`, `G80` |
| 6 | `IMPR-006` | Enforce proposer–trainer–evaluator–gate–deployer separation | `IMPR-005`, `AUTH-002`, `EVAL-010`, `LIN-003` | `G44`, `G48`, `G76`, `G84`, `G85`, `G86` |
| 7 | `IMPR-007` | Implement multi-cycle convergence, stability, regression, and diversity tracking | `IMPR-004`, `EVAL-007`, `REWD-007` | `G56`, `G59`, `G70`, `G86` |
| 8 | `IMPR-008` | Implement bounded autonomous operation, stop, freeze, and rollback proposal semantics | `IMPR-005`, `WORK-005`, `INC-003`, `DEP-007` | `G70`, `G75`, `G78`, `G79`, `G80`, `G88` |
| 9 | `IMPR-009` | Implement optimizer/research plugin interface without algorithm lock-in | `IMPR-003`, `SBX-001`, `MODEL-003` | `G55`, `G56`, `G70`, `G76` |
| 10 | `IMPR-010` | Publish complete improvement, convergence, and novelty evidence bundles | `IMPR-004`, `IMPR-007`, `LIN-004`, `EVID-004` | `G70`, `G76`, `G83`, `G86` |

## Component 34 — Change Controller

`splendor.change-controller` · `change_governance` · declared owner: crates/splendor-change

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `CHG-001` | Define the immutable ChangeSet and subject revision grammar | `FND-001`, `ART-001`, `LIN-001` | `G70`, `G71`, `G72`, `G76`, `G87` |
| 2 | `CHG-002` | Implement canonical diff adapters and semantic change descriptors | `CHG-001`, `DRREG-001`, `SBX-003` | `G57`, `G70`, `G72`, `G84` |
| 3 | `CHG-003` | Implement dependency, compatibility, and blast-radius analysis | `CHG-001`, `LIN-003`, `AGREG-006`, `DRREG-005` | `G70`, `G72`, `G73`, `G80`, `G88` |
| 4 | `CHG-004` | Implement deterministic risk classification and anti-splitting rules | `CHG-003`, `IMPR-005`, `AUTH-005` | `G70`, `G76`, `G78`, `G79`, `G80`, `G84`, `G85` |
| 5 | `CHG-005` | Implement ChangeSet lifecycle, optimistic concurrency, and immutable validation receipts | `CHG-001`, `FND-003`, `EVT-004` | `G02`, `G47`, `G70`, `G75`, `G87` |
| 6 | `CHG-006` | Define validation requirements and evidence binding for each changed subject | `CHG-004`, `EVID-003`, `EVAL-001` | `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89` |
| 7 | `CHG-007` | Define forward, backward, state, and rollback compatibility contracts | `CHG-003`, `STA-006`, `DRREG-005` | `G15`, `G57`, `G66`, `G73`, `G75`, `G88` |
| 8 | `CHG-008` | Implement governed code, environment, driver, and kernel change preparation | `CHG-001`, `SBX-004`, `ART-005`, `DRREG-004` | `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89` |
| 9 | `CHG-009` | Implement rollback and compensation contract validation | `CHG-007`, `ART-007`, `STA-005` | `G15`, `G18`, `G25`, `G67`, `G73`, `G75`, `G80`, `G88` |

## Component 35 — Gate Engine

`splendor.gate-engine` · `change_governance` · declared owner: crates/splendor-change

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `GATE-001` | Define a typed, deterministic GatePolicy language | `FND-001`, `AUTH-006`, `CHG-006` | `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G70` |
| 2 | `GATE-002` | Implement evidence resolution, exact binding, freshness, and trust checks | `GATE-001`, `EVID-005`, `LIN-004`, `DUC-006` | `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G86` |
| 3 | `GATE-003` | Enforce role independence and correlated-evidence policy | `GATE-002`, `IMPR-006`, `AUTH-002` | `G44`, `G48`, `G70`, `G76`, `G84`, `G85`, `G86` |
| 4 | `GATE-004` | Implement immutable value, safety, authority, privacy, and physical roots | `GATE-001`, `CHG-004`, `AUTH-006` | `G47`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G78`, `G79`, `G80`, `G85` |
| 5 | `GATE-005` | Implement statistical, uncertainty, regression, and slice gate clauses | `GATE-002`, `EVAL-007` | `G45`, `G46`, `G47`, `G48`, `G49`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G76`, `G83` |
| 6 | `GATE-006` | Implement human-in-the-loop approval and intervention requirements | `GATE-001`, `AUTH-004`, `EVID-006` | `G12`, `G43`, `G47`, `G70`, `G75`, `G80`, `G88` |
| 7 | `GATE-007` | Define fail-closed behavior for unknown, conflicting, unavailable, and invalid evidence | `GATE-002`, `FND-004` | `G45`, `G46`, `G47`, `G48`, `G49`, `G66`, `G70`, `G75`, `G79`, `G80`, `G86` |
| 8 | `GATE-008` | Implement signed policy distribution, TTL, revocation, cache, and historical replay | `GATE-001`, `AUTH-006`, `NODE-005` | `G13`, `G14`, `G47`, `G70`, `G73`, `G75`, `G88` |
| 9 | `GATE-009` | Produce explainable, signed, appealable GateDecision receipts | `GATE-007`, `EVID-004` | `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G70`, `G76`, `G86` |
| 10 | `GATE-010` | Implement adversarial gate and evaluator-gaming conformance tests | `GATE-003`, `GATE-004`, `GATE-007` | `G44`, `G48`, `G64`, `G69`, `G70`, `G76`, `G78`, `G79`, `G80`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89` |

## Component 36 — Deployment Controller

`splendor.deployment-controller` · `change_governance` · declared owner: crates/splendor-change

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `DEP-001` | Define DeploymentPlan and rollout state machine | `CHG-005`, `GATE-009`, `WORK-006` | `G67`, `G70`, `G73`, `G75`, `G80`, `G88` |
| 2 | `DEP-002` | Implement exact activation sets and atomic coordinated revision switching | `DEP-001`, `CHG-007`, `ART-007` | `G15`, `G57`, `G67`, `G70`, `G73`, `G75` |
| 3 | `DEP-003` | Implement shadow execution with side-effect suppression and comparable evidence | `DEP-002`, `ROUTE-008`, `ACT-006`, `DUC-003` | `G60`, `G67`, `G70`, `G73`, `G80`, `G88` |
| 4 | `DEP-004` | Implement canary cohorts and exposure accounting | `DEP-003`, `FLEET-006`, `DUC-004` | `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88` |
| 5 | `DEP-005` | Implement progressive fleet rollout with health-based pause and promotion | `DEP-004`, `FLEET-007`, `NODE-006`, `OBS-005` | `G66`, `G67`, `G70`, `G73`, `G75`, `G80`, `G88` |
| 6 | `DEP-006` | Implement physical/edge deployment safety protocol | `DEP-005`, `ACT-007`, `NODE-009`, `GATE-004` | `G73`, `G74`, `G75`, `G79`, `G80`, `G88` |
| 7 | `DEP-007` | Implement rollback, restore, compensation, and post-rollback verification | `DEP-002`, `CHG-009`, `INC-003` | `G15`, `G18`, `G67`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88` |
| 8 | `DEP-008` | Implement deployment health contracts and multi-source stop conditions | `DEP-001`, `EVID-003`, `OBS-001`, `INC-002` | `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88` |
| 9 | `DEP-009` | Implement safe state migration and mixed-version operation | `DEP-001`, `STA-006`, `CHG-007`, `DODRV-006` | `G15`, `G31`, `G57`, `G70`, `G73`, `G75` |
| 10 | `DEP-010` | Implement offline and intermittently connected deployment policy | `DEP-006`, `GATE-008`, `NODE-005` | `G13`, `G14`, `G73`, `G75`, `G79`, `G80`, `G88` |
| 11 | `DEP-011` | Harden deployment control plane for production availability and security | `DEP-001`, `AUTH-007`, `SECR-005`, `EVT-007` | `G66`, `G70`, `G73`, `G75`, `G87`, `G88` |
| 12 | `DEP-012` | Publish deployment, rollback, and real-world outcome evidence | `DEP-005`, `DEP-007`, `EVID-004`, `FDBK-006` | `G67`, `G70`, `G73`, `G75`, `G80`, `G83`, `G88` |

## Component 37 — Incident Controller

`splendor.incident-controller` · `change_governance` · declared owner: crates/splendor-change

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `INC-001` | Define incident taxonomy, identity, severity, and lifecycle | `FND-001`, `EVT-003`, `AUTH-002` | `G47`, `G64`, `G69`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89` |
| 2 | `INC-002` | Implement signal ingestion, correlation, and bounded detection rules | `INC-001`, `EVT-006`, `EVID-003` | `G66`, `G67`, `G69`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88`, `G89` |
| 3 | `INC-003` | Implement policy-authorized containment and kill-switch orchestration | `INC-001`, `AUTH-005`, `DGW-007`, `DEP-007` | `G12`, `G13`, `G14`, `G47`, `G70`, `G73`, `G75`, `G79`, `G80`, `G87`, `G88` |
| 4 | `INC-004` | Implement evidence preservation, forensic snapshots, and chain of custody | `INC-002`, `EVID-005`, `EVT-005`, `SECR-006` | `G14`, `G47`, `G64`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89` |
| 5 | `INC-005` | Implement lineage-based blast-radius and compromise propagation | `INC-004`, `LIN-005`, `EVID-005` | `G39`, `G47`, `G64`, `G69`, `G70`, `G73`, `G76`, `G86`, `G87`, `G88`, `G89` |
| 6 | `INC-006` | Implement investigation workspaces and controlled diagnostic workloads | `INC-004`, `SBX-001`, `RPLY-004`, `AUTH-003` | `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G47`, `G70`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89` |
| 7 | `INC-007` | Implement recovery plans, validation, and controlled unfreeze | `INC-003`, `INC-005`, `CHG-001`, `GATE-001`, `DEP-001` | `G47`, `G64`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89` |
| 8 | `INC-008` | Implement closure, lessons, policy updates, and gold regression extraction | `INC-007`, `COLL-006`, `DUC-002`, `CHG-001` | `G39`, `G47`, `G64`, `G69`, `G70`, `G73`, `G76`, `G86`, `G87`, `G88`, `G89` |
| 9 | `INC-009` | Implement game days and cross-plane failure drills | `INC-001`, `FND-005`, `DEP-007`, `GATE-010` | `G66`, `G69`, `G70`, `G73`, `G75`, `G80`, `G86`, `G87`, `G88`, `G89` |

## Component 38 — Observability Exporter

`splendor.observability-exporter` · `event_state_evidence` · declared owner: crates/splendor-evidence

| # | ID | Task | Required contracts / collaborators | Gold |
|---:|---|---|---|---|
| 1 | `OBS-001` | Define the canonical telemetry taxonomy and semantic conventions | `FND-001`, `EVT-001`, `EVID-001` | `G00`, `G01`, `G02`, `G03`, `G04`, `G05`, `G06`, `G07`, `G08`, `G09`, `G10`, `G11`, `G12`, `G13`, `G14`, `G15`, `G16`, `G17`, `G18`, `G19`, `G20`, `G21`, `G22`, `G23`, `G24`, `G25`, `G26`, `G27`, `G28`, `G29`, `G30`, `G31`, `G32`, `G33`, `G34`, `G35`, `G36`, `G37`, `G38`, `G39`, `G40`, `G41`, `G42`, `G43`, `G44`, `G45`, `G46`, `G47`, `G48`, `G49`, `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G60`, `G61`, `G62`, `G63`, `G64`, `G65`, `G66`, `G67`, `G68`, `G69`, `G70`, `G71`, `G72`, `G73`, `G74`, `G75`, `G76`, `G77`, `G78`, `G79`, `G80`, `G81`, `G82`, `G83`, `G84`, `G85`, `G86`, `G87`, `G88`, `G89` |
| 2 | `OBS-002` | Implement subscription, filtering, transformation, and export receipts | `OBS-001`, `EVT-006`, `SECR-003`, `DRREG-001` | `G14`, `G47`, `G66`, `G73`, `G75`, `G87` |
| 3 | `OBS-003` | Implement privacy, redaction, protected-eval, and secret-safe export controls | `OBS-002`, `DUC-001`, `SECR-006`, `FND-009` | `G09`, `G14`, `G38`, `G44`, `G64`, `G70`, `G73`, `G80`, `G86` |
| 4 | `OBS-004` | Implement workload, training, evaluation, and inference coexistence observability | `OBS-001`, `FLEET-008`, `TRAIN-015`, `MODEL-007` | `G50`, `G51`, `G52`, `G53`, `G54`, `G55`, `G56`, `G57`, `G58`, `G59`, `G66`, `G70`, `G73`, `G83` |
| 5 | `OBS-005` | Implement SLO definitions, burn-rate evaluation, and alert signal generation | `OBS-004`, `INC-002`, `DEP-008` | `G47`, `G66`, `G67`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88` |
| 6 | `OBS-006` | Implement exporter driver interfaces and reference providers | `OBS-002`, `DRREG-004`, `DGW-001`, `SBX-008` | `G14`, `G19`, `G23`, `G47`, `G66`, `G73`, `G87` |
| 7 | `OBS-007` | Implement dashboards, query views, and cost/chargeback as non-authoritative projections | `OBS-001`, `OBS-003`, `EVID-006` | `G56`, `G59`, `G66`, `G70`, `G73`, `G76`, `G80`, `G83` |
| 8 | `OBS-008` | Validate exporter scale, cardinality, lag, and failure isolation at 1,000-device fleet size | `OBS-002`, `OBS-004`, `FLEET-009`, `INC-009` | `G66`, `G70`, `G73`, `G75`, `G80`, `G87`, `G88` |
| 9 | `OBS-009` | Document and enforce observability non-authority and evidence conversion boundaries | `OBS-005`, `AUTH-003`, `FND-002` | `G12`, `G43`, `G47`, `G66`, `G70`, `G75`, `G87`, `G88` |

## Integration, proof, and operations programs

| # | ID | Task | Required contracts / collaborators |
|---:|---|---|---|
| 1 | `INT-001` | Build the 0.1-to-vNext compatibility composition and migration path | `FND-006`, `EVT-008`, `STA-007`, `DGW-009`, `WORK-010` |
| 2 | `INT-002` | Compose the complete single-host agent kernel reference runtime | `INT-001`, `FND-005`, `AINST-010`, `IMPR-010`, `CHG-005`, `GATE-009`, `DEP-007`, `INC-004` |
| 3 | `INT-003` | Build the production fleet control plane and resident node protocol | `INT-002`, `NODE-010`, `FLEET-010`, `WORK-009`, `AUTH-007`, `SECR-005`, `DEP-011` |
| 4 | `INT-004` | Implement arbitrary PyTorch project intake and compatibility analysis | `SBX-013`, `TRDRV-001`, `TRAIN-001`, `ART-005`, `DUC-003` |
| 5 | `INT-005` | Implement flexible-fleet PyTorch execution from compatibility report | `INT-004`, `TRAIN-018`, `FLEET-011`, `TRDRV-010`, `ART-006`, `NODE-008` |
| 6 | `INT-006` | Validate 1,000-device mixed agent, inference, data, eval, and training operation | `INT-003`, `INT-005`, `FLEET-009`, `OBS-008`, `INC-009` |
| 7 | `INT-007` | Compose the governed data–feedback–reward–eval–training–change loop | `INT-002`, `COLL-010`, `FDBK-010`, `REWD-009`, `EVAL-012`, `TRAIN-018`, `IMPR-010`, `GATE-010`, `DEP-012` |
| 8 | `INT-008` | Compose the complete physical-AI and world-model runtime path | `PERC-009`, `WORLD-012`, `ROUTE-011`, `ACT-008`, `DEP-006`, `INC-009` |
| 9 | `INT-009` | Deliver coherent Rust, Python, TypeScript, CLI, and declarative user-space APIs | `FND-010`, `INT-002`, `INT-003`, `DRREG-006` |
| 10 | `INT-010` | Build driver, service, and gold-example conformance certification | `FND-005`, `INT-009`, `DRREG-004`, `GATE-010` |
| 11 | `INT-011` | Implement federated, data-local, and privacy-preserving learning orchestration profiles | `INT-005`, `DUC-007`, `TRAIN-012`, `INC-005` |
| 12 | `NOV-001` | Run the controlled self-evolving GPT-2-class gold experiment | `INT-007`, `INT-005`, `MODEL-010`, `IMPR-010`, `GATE-010`, `DEP-012` |
| 13 | `NOV-002` | Run live coding-feedback agent evolution with executable regression control | `INT-007`, `SBX-013`, `MSG-010`, `IMPR-006`, `CHG-008` |
| 14 | `NOV-003` | Run world-model and neuro-symbolic self-evolution experiments | `INT-008`, `INT-007`, `WORLD-012`, `ROUTE-011`, `GATE-004` |
| 15 | `NOV-004` | Run governed agent-topology and sub-agent evolution experiments | `AGREG-008`, `MSG-010`, `IMPR-003`, `CHG-003`, `DEP-009` |
| 16 | `NOV-005` | Establish a value-alignment and controlled-evolution evidence benchmark | `NOV-001`, `NOV-002`, `NOV-003`, `NOV-004`, `GATE-010`, `IMPR-010` |
| 17 | `NOV-006` | Implement the novelty, reproducibility, and claim-discipline protocol | `IMPR-010`, `INT-010`, `NOV-005` |
| 18 | `OPS-001` | Harden the complete system for production security, reliability, and supply chain | `FND-011`, `INT-003`, `INT-010`, `INC-009` |
| 19 | `OPS-002` | Replace conceptual documentation with versioned implementer specifications and gold paths | `INT-009`, `INT-010`, `NOV-006`, `FND-006` |

Source-pack catalog validator: **PASS** at import time only. This is not active
repository CI evidence and does not prove that any 0.2/v2 task is implemented.
