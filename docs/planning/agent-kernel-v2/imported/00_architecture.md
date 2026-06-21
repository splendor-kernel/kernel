> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Splendor vNext — Canonical Agent Kernel Architecture

## 1. Definition

**Splendor is a user-space kernel for persistent agents.** It standardizes identity, authority, durable state, typed I/O, schedulable computation, data and model lineage, evaluation, controlled change, and evidence. It does not prescribe the neural architecture, symbolic system, training algorithm, planner, memory strategy, orchestration style, or application framework.

A complete agent may contain LLMs, custom neural networks, classical algorithms, planners, solvers, rules, simulators, human workflows, sub-agents, sensors, and physical actuators. Splendor makes those parts composable and governable without turning them into one mandated framework.

## 2. The boundary in one sentence

> User space may compute anything; it may not silently acquire authority, consume protected resources, mutate governed state, activate a new agent version, or cause an external side effect outside a Splendor kernel boundary.

This is the equivalent of the operating-system distinction between ordinary computation and privileged operations.

## 3. What belongs where

| Layer | Owns | Does not own |
|---|---|---|
| **User space** | Agent logic, prompts, model architectures, planners, solvers, memory algorithms, training algorithms, reward functions, domain code, application UX | Authority, durable activation, unmediated side effects, undisclosed data use |
| **Kernel control plane** | Identity, capabilities, artifacts, lineage, workloads, resource leases, gates, state commits, deployment, audit, rollback | Domain reasoning, model mathematics, optimizer implementation, business workflow |
| **Drivers/providers** | Concrete execution against models, sensors, tools, shells, Python, OCI, Kubernetes, training frameworks, databases, robots, and external services | Granting themselves authority, changing policies, bypassing evidence or gates |
| **Host/fleet substrate** | Unix processes, cgroups, containers, accelerators, network, filesystems, Kubernetes, device runtimes | Splendor's agent semantics and value/governance model |

## 4. Eight orthogonal kernel planes

The architecture is divided by responsibility, not by product feature. Each plane has one reason to change.

| Plane | Single responsibility | Canonical objects |
|---|---|---|
| **1. Identity & Authority** | Decide *who* may request *what*, within which tenant, agent, device, data, time, and budget scope | `Principal`, `Scope`, `CapabilityGrant`, `Approval`, `SecretLease` |
| **2. Artifact & Lineage** | Identify immutable model, dataset, code, policy, eval, checkpoint, environment, and world-state artifacts and their derivation | `ArtifactRef`, `ArtifactManifest`, `LineageEdge`, `DataUseGrant` |
| **3. Event, State & Evidence** | Record ordered facts, versioned state heads, causal links, evidence, and safe replay/simulation inputs | `EventEnvelope`, `StateCommit`, `StateHead`, `EvidenceBundle`, `CausalQuery` |
| **4. Execution Fabric** | Schedule all compute across one or many heterogeneous nodes while protecting latency-critical live services | `WorkloadSpec`, `ResourceRequest`, `ExecutionLease`, `PlacementDecision`, `CheckpointPolicy` |
| **5. Driver Boundary** | Invoke typed external capabilities through replaceable providers with declared safety and lifecycle semantics | `DriverManifest`, `Invocation`, `InvocationResult`, `Cancellation`, `Compensation` |
| **6. Agent Runtime & Routing** | Maintain persistent agent instances, typed percept/action channels, world-state partitions, sub-agent topology, and dynamic neuro-symbolic routes | `AgentSpec`, `AgentInstance`, `RouteSpec`, `DecisionProposal`, `WorldModelSpec`, `Delegation` |
| **7. Data, Feedback, Eval & Learning Control** | Turn observations and outcomes into governed datasets, feedback, eval reports, training runs, and candidate bundles | `CollectionPlan`, `DatasetSnapshot`, `DataQualityReport`, `FeedbackRecord`, `EvalSuite`, `TrainingPlan`, `CandidateBundle` |
| **8. Change & Governance** | Decide whether and how a candidate change becomes active, then shadow, canary, promote, quarantine, revoke, or roll back it | `ChangeSet`, `GatePolicy`, `GateDecision`, `DeploymentPlan`, `RollbackTarget`, `Incident` |

### Why these planes are separate

- Replay belongs to the **evidence plane**. It is important, but it is not the runtime's organizing abstraction.
- Training belongs to the **learning-control plane** as a governed workload. The optimizer remains a driver/user-space implementation.
- Inference, data processing, evaluation, training, simulation, and shell execution all use the **same workload fabric**, preventing six incompatible schedulers.
- Perceptors, actuators, models, trainers, evaluators, and sandboxes all use the **same driver ABI**, preventing six incompatible plugin systems.
- Promotion and rollout are separate from training. A successful training run produces a candidate; it never mutates live agents directly.

## 5. The small generic substrate

Splendor should keep a compact set of generic objects and express AI concepts as typed profiles over them.

### 5.1 Foundational objects

1. `Principal` — tenant, agent, human, service, node, device, or governance authority.
2. `Scope` — the exact tenant/agent/run/device/data boundary for an operation.
3. `CapabilityGrant` — time-, resource-, operation-, and data-scoped authority.
4. `ArtifactRef` — immutable, content-addressed reference with type, version, provenance, and access classification.
5. `EventEnvelope` — append-only fact with identity, causal parents, schema, payload reference, and time.
6. `StateCommit` — atomic transition from one state head to another, backed by immutable artifacts/events.
7. `WorkloadSpec` — schedulable computation with inputs, outputs, resources, priority, isolation, distribution, and recovery semantics.
8. `ExecutionLease` — temporary reservation of resources and authority on a node.
9. `DriverManifest` — operations, schemas, capabilities, side-effect and safety properties, maturity, and compatibility.
10. `Invocation` — one typed request to a driver under a workload, lease, and capability scope.
11. `Proposal` — requested external effect or governed mutation before authorization.
12. `GateDecision` — allow, deny, require approval, defer, quarantine, or allow with explicit obligations.
13. `ChangeSet` — immutable diff from one deployed agent bundle to another.
14. `DeploymentPlan` — shadow/canary/progressive/full activation and rollback policy.
15. `EvidenceBundle` — references to traces, evals, data reports, approvals, incidents, and reproducibility material.

### 5.2 AI and agent profiles

Profiles add semantics without creating an unrelated control system:

- `PerceptEvent` profiles `EventEnvelope`.
- `FeedbackRecord` profiles `EventEnvelope`.
- `ModelArtifact`, `DatasetSnapshot`, `Checkpoint`, `EvalSuite`, `PolicyBundle`, and `WorldSnapshot` profile `ArtifactRef`.
- `InferenceWorkload`, `TrainingWorkload`, `EvalWorkload`, `DataWorkload`, `SimulationWorkload`, and `SandboxWorkload` profile `WorkloadSpec`.
- `PerceptorDriver`, `ActuatorDriver`, `ModelDriver`, `TrainerDriver`, `EvaluatorDriver`, `DataOperatorDriver`, `SandboxDriver`, and `DeviceDriver` profile `DriverManifest`.
- `ActionProposal`, `StateMutationProposal`, `DelegationProposal`, and `SelfChangeProposal` profile `Proposal`.

This yields specialized behavior while preserving one security, scheduling, lineage, and lifecycle model.

## 6. Non-negotiable invariants

1. **No external effect without a proposal, authority check, gate decision, driver invocation, outcome, and evidence record.**
2. **No live model, route, code, value, policy, world-schema, or adapter change without a `ChangeSet` and deployment state machine.**
3. **Training outputs candidates; only change governance activates candidates.**
4. **Feedback is never an unscoped scalar.** It identifies its target, source, provenance, confidence, use policy, and derivation.
5. **Datasets are immutable snapshots.** Mutable sources are converted into versioned snapshots before training or protected evaluation.
6. **Every derived artifact has lineage.** Model checkpoints identify code, environment, data snapshots, base artifacts, hyperparameters, seeds, and parent checkpoints.
7. **Evaluation is independently versioned.** A candidate cannot silently edit the eval suite that judges it.
8. **Protected holdouts are not readable by training workloads.** Access is mediated by evaluator drivers and data-use grants.
9. **Sub-agents inherit no authority by default.** Delegation is explicit, narrower than the parent, expiring, budgeted, trace-linked, and revocable.
10. **Live inference has reserved capacity.** Training, evaluation, data, and sandbox workloads are admitted only under declared interference policies.
11. **Physical effects fail locally closed.** Cloud reasoning may advise, but a device-local safety path controls high-level physical actuation and emergency stop.
12. **Replay executes no side effect by default.** Simulation and counterfactual evaluation use explicit non-live drivers and scopes.
13. **Secrets are leased, not stored in state, prompts, traces, datasets, or action parameters.**
14. **Self-management cannot self-grant capability or weaken its independent gates.**
15. **Unknown schema, identity, authority, or safety state fails closed at privileged boundaries.**

## 7. Canonical online agent flow

The online path is not restricted to one policy callback or one model.

1. A perceptor driver emits a `PerceptEvent` with source identity, schema, provenance, trust/quality metadata, sequence, freshness, and payload reference.
2. The runtime appends the event and exposes it to an `AgentInstance` under a bounded processing lease.
3. User-space code executes an arbitrary dynamic route: neural model calls, symbolic rules, solvers, memory reads, world-model updates, sub-agent calls, or custom compute.
4. Each privileged invocation becomes a typed `Invocation`; each durable or external mutation becomes a `Proposal`.
5. `GatePolicy` combines capabilities, constraints, value policies, safety checks, quotas, data-use rules, approval state, and risk class.
6. Approved proposals invoke drivers. Drivers return typed outcomes, resource use, postconditions, and compensating/rollback references when available.
7. The runtime atomically commits governed state changes and appends causal events.
8. Feedback and evaluations may arrive synchronously or later. They attach to exact output/action/state/model/route versions.
9. Monitoring may open a data, eval, training, or improvement workload; it never mutates the live agent in place.

## 8. Canonical learning and adjustment flow

1. A `CollectionPlan` selects permitted events, percepts, outcomes, feedback, incidents, or external sources.
2. Data operators normalize, redact, deduplicate, label, filter, split, and materialize an immutable `DatasetSnapshot`.
3. Quality and contamination evaluators emit signed/versioned `DataQualityReport` and `ContaminationReport` artifacts.
4. A `TrainingPlan` references exact input artifacts, code/environment, algorithm driver, distribution strategy, resource policy, checkpoint policy, and expected outputs.
5. The execution fabric schedules workers across suitable nodes. Live inference reservations always dominate background leases.
6. The trainer produces checkpoints and a final `CandidateBundle`; every output has full lineage.
7. Independent `EvalRun`s compare the candidate with the current deployment on protected suites, safety cases, world-model tasks, operational SLOs, and regression slices.
8. A `ChangeSet` identifies the exact diff and its risk class.
9. Gates decide denial, more evidence, human review, shadow, canary, progressive rollout, or full activation.
10. Online monitors evaluate the deployment. Breach triggers pause, quarantine, compensation, or rollback to a known-good bundle.

## 9. Full agent modelation

An `AgentSpec` is a declarative control manifest, not the implementation of intelligence. It declares:

- ownership, identities, risk class, lifecycle, and service-level objectives;
- component artifact references and allowed driver operations;
- perceptor and actuator ports;
- model, planner, solver, rule, and custom compute bindings;
- dynamic route templates and permitted route transitions;
- state/world partitions, schemas, writers, readers, retention, replication, and rollback rules;
- sub-agent roles and delegation ceilings;
- data collection, feedback, evaluation, training, and adjustment policies;
- resource budgets, placement constraints, and offline behavior;
- active `PolicyBundle`, `ValueSpec`, and deployment revision.

The implementation can be an imperative Python program, a graph framework, a Rust service, a neural architecture, a symbolic planner, or a composition of all of them. The manifest controls boundaries, not internal thought.

## 10. Neuro-symbolic routing without framework lock-in

Splendor standardizes **typed crossings**, not a mandatory DAG.

User space may route dynamically among:

- neural inference and scoring;
- symbolic rules, constraints, planners, theorem provers, and optimizers;
- world-state reads and proposed updates;
- external retrieval and tools;
- human review;
- sub-agents and critics;
- simulation and rollout workers.

A `RouteSpec` is optional descriptive metadata for validation, placement, visualization, and policy. Imperative routes remain valid, but every model/driver/sub-agent invocation emits a `RouteStepEvent`. The kernel can therefore reconstruct what happened without dictating how the route was coded.

## 11. One execution fabric for every workload

A `WorkloadSpec` declares:

- kind: inference, training, evaluation, data, simulation, sandbox, maintenance, or custom;
- artifact inputs and declared outputs;
- entrypoint driver/operation or hermetic code environment;
- resource requirements and acceptable device classes;
- latency/throughput deadline and scheduling class;
- preemption, checkpoint, retry, and elasticity behavior;
- distribution mode: single, replicated, data parallel, model parallel, pipeline, parameter-server, map/reduce, actor, or custom rendezvous;
- data locality and egress constraints;
- sandbox, network, secret, capability, and data scopes;
- reproducibility fields and evidence requirements;
- interference policy protecting named live services.

This abstraction allows a fleet of 1,000 heterogeneous devices to perform inference, training, evaluation, data work, simulation, and sub-agent tasks without treating each as a separate orchestration product.

## 12. Drivers are the kernel equivalent of device drivers

The kernel owns the ABI and validation rules; providers own implementations.

Examples:

- a PyTorch trainer is a `TrainerDriver`;
- an OpenAI-compatible API or local Transformer runtime is a `ModelDriver`;
- a camera stream is a `PerceptorDriver`;
- HTTP, filesystem, database, and robot commands are `ActuatorDriver` operations;
- shell, Python virtual environments, OCI, and Kubernetes Jobs are `SandboxDriver` or `ExecutorDriver` operations;
- contamination scanning is an `EvaluatorDriver` or `DataOperatorDriver` operation.

A driver manifest declares side effects, idempotency, cancelability, reversibility, compensation, secrets, isolation, supported hardware, schemas, concurrency, maturity, certification, and safety case.

## 13. Self-management and self-evolution

Self-management is a controlled lifecycle, never direct self-editing.

The agent may detect a problem and create an `ImprovementProposal`. Depending on risk, Splendor can authorize data collection, training, route search, prompt/config tuning, code generation, or simulation. Results become candidate artifacts and a `ChangeSet`. Independent gates and deployment policies decide activation.

The system distinguishes:

- R0: reversible runtime tuning;
- R1: prompt, threshold, retrieval, or route changes;
- R2: adapters/fine-tunes/reward-model changes;
- R3: base model, code, dependency, driver, or world-schema changes;
- R4: values, authority, protected evals, physical safety boundaries, or governance changes.

R4 changes are never autonomous by default. An agent cannot reduce the risk class of its own proposal.

## 14. External effect classes

Every operation declares one of these effect classes:

| Class | Example | Required behavior |
|---|---|---|
| `pure` | deterministic transform | Cacheable; no external mutation |
| `read` | database query, sensor snapshot | Data scope and provenance required |
| `reversible` | temporary deployment, staged file update | Explicit rollback target |
| `compensatable` | API purchase with refund operation | Compensation operation and deadline |
| `irreversible` | message sent, destructive physical action | Stronger approval/evidence; no false rollback claim |
| `physical` | robot movement, drone mission | Local safety gate, device authority, emergency-stop semantics |
| `governance` | capability grant, policy revocation | Independent authority and immutable audit |
| `self_change` | model/code/route activation | ChangeSet, eval, deployment, rollback/quarantine |

## 15. Recommended source-tree direction

```text
crates/
  splendor-types/           # stable serialized kernel objects and profile schemas
  splendor-authority/       # principals, capabilities, approvals, secret leases
  splendor-artifacts/       # content addressing, manifests, lineage, data-use grants
  splendor-state/           # events, state heads, commits, causal queries, evidence
  splendor-fabric/          # workloads, resource offers, leases, placement, recovery
  splendor-drivers/         # generic driver ABI, registry, invocation lifecycle
  splendor-agent/           # AgentSpec, instance lifecycle, routes, world partitions
  splendor-learning/        # data, feedback, eval, training, candidate contracts
  splendor-change/          # gates, changesets, rollout, rollback, incidents
  splendor-gateway/         # privileged proposal mediation; action gateway becomes a profile
  splendor-daemon/          # local/fleet API surface
adapters/
  perceptor-*/
  actuator-*/
  model-*/
  trainer-*/
  evaluator-*/
  data-*/
  sandbox-shell/
  sandbox-python/
  executor-oci/
  executor-kubernetes/
  device-*/
python/
  splendor/
    agent.py
    artifacts.py
    data.py
    evals.py
    training.py
    workloads.py
    drivers.py
    change.py
examples/
  gold/
```

Crate boundaries may differ, but responsibilities should not be recombined into a replay-centric loop engine.

## 16. Diagram index

1. Kernel planes and boundaries
2. Core object model and typed profiles
3. Persistent online agent flow
4. Data collection, quality, lineage, and contamination
5. Feedback, evaluation, and alignment evidence
6. Training, candidate, promotion, and rollback
7. Heterogeneous distributed execution fabric
8. Live inference protection on each node
9. Unified driver boundary
10. Agent world model and neuro-symbolic routing
11. Controlled self-management and self-evolution
12. GPT-2 full lifecycle gold example
13. 1,000-device mixed-workload fleet
14. Shell, Python, OCI, and Kubernetes isolation
15. Current implementation to vNext gap map

## 17. Acceptance definition for the architecture

Splendor deserves the kernel name only when all of the following are true:

- the same authority and evidence model governs local and distributed execution;
- inference, data, eval, training, simulation, and sandboxes share one workload contract;
- all external capability providers share one driver lifecycle;
- models and agent frameworks remain replaceable user-space components;
- data provenance, quality, allowed use, and contamination are queryable;
- feedback and evals are first-class causal records, not optional callbacks;
- candidates cannot become live without explicit change control;
- a live agent can run indefinitely, migrate, pause, recover, quarantine, and roll back;
- physical agents retain local safety and offline control;
- gold examples prove every primitive before autonomous self-evolution is enabled.
