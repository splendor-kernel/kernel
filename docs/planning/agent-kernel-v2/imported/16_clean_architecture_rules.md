> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Splendor Clean Architecture Constitution

**Status:** normative architecture rule set for the Splendor agent kernel vNext work.
**Applies to:** Rust workspace, Python SDK/bindings, TypeScript clients, daemon APIs, node binaries, adapters, examples, schemas, persistence, fleet protocols, and generated artifacts.
**Purpose:** prevent architectural drift while Splendor grows from the implemented 0.1 runtime into a complete kernel substrate for persistent neuro-symbolic agents, governed data and feedback, evaluation, distributed learning control, physical AI, and controlled self-evolution.

This is not a generic “entities/use-cases/adapters” template. It defines the package boundaries, dependency directions, mutation ownership, effect paths, impact analysis, and validation obligations for this repository.

---

## 1. The rule behind every other rule

> User-space code may compute anything. It may not silently acquire authority, consume protected data, reserve fleet resources, mutate governed state, activate an artifact, or create an external effect outside a Splendor kernel route.

Splendor is a user-space **agent kernel**, not a framework that owns model mathematics or application cognition. The kernel owns interoperable control primitives around agent work:

- identity, authority, data-use rights, and secrets;
- immutable artifacts and derivation lineage;
- ordered events, versioned state, evidence, and safe replay;
- workloads, resource leases, placement, fencing, and recovery;
- typed driver invocation for models, perceptors, actuators, trainers, evaluators, data operators, and sandboxes;
- persistent agent instances, world-state partitions, messages, delegation, and neuro-symbolic route crossings;
- collection, feedback, reward derivation, evaluation, training flow control, and improvement programs;
- change sets, evidence gates, deployment, rollback, quarantine, and incidents.

User space owns model architectures, optimizers, losses, planners, solvers, ontologies, prompts, memory algorithms, reward functions, evaluation logic, data transforms, training algorithms, application policy, and domain behavior. Those implementations enter Splendor through declared drivers, workloads, routes, artifacts, and proposals.

The architecture is correct only when freedom of user-space computation coexists with kernel control over authority, resource use, durable mutation, external effects, and activation.

---

## 2. Baseline that must be preserved

The current repository already has valuable dependency discipline:

- `splendor-types` contains canonical IDs and serialized primitives and has no internal workspace dependency.
- `splendor-store` depends on `splendor-types` and owns state/trace persistence engines.
- `splendor-gateway` depends on `splendor-types` and mediates actions through verifier and adapter contracts.
- `splendor-kernel` composes types, stores, gateway, state, traces, scheduling, messages, governance hooks, and local/fleet foundations.
- filesystem, HTTP, and robotics adapters depend inward on `splendor-gateway` and `splendor-types`.
- `splendor-daemon`, `splendorctl`, Python bindings, Python SDK, and TypeScript packages expose runtime control surfaces.

The following implemented invariants remain permanent:

1. no side effect bypasses the gateway;
2. policy/model output proposes rather than authorizes;
3. state is explicit and versioned;
4. required trace/evidence failures fail closed before privileged effects;
5. replay does not execute side effects by default;
6. messages do not become permission tokens;
7. work orders narrow authority and do not broaden it;
8. physical actions remain high-level, locally safety-vetoable, and gateway mediated;
9. tenant, agent, run, action, state, trace, message, work-order, approval, fleet, node, and instance identities are distinct.

The new architecture extends these invariants to data, feedback, evaluation, training, fleet compute, agent evolution, deployment, and physical systems. It must not replace them with a parallel incompatible runtime.

---

## 3. Terms used in these rules

### 3.1 Kernel contract

A versioned object, command, event, state transition, port, or protocol whose semantics must remain consistent across Rust, Python, TypeScript, daemon APIs, stores, fleet nodes, adapters, and replay.

### 3.2 Component owner

The single package/module responsible for a state machine or authoritative decision. Ownership means the component defines valid transitions, validates commands, and emits canonical events. It does not mean it stores all bytes or implements every provider.

### 3.3 Provider or driver

A replaceable implementation that executes against a concrete external environment: filesystem, HTTP, model runtime, PyTorch, Kubernetes, Docker, shell, database, sensor, robot, evaluation harness, artifact store, secret service, or observability backend.

### 3.4 Composition root

Code that wires components and ports. It may know concrete implementations but must not duplicate component state machines. `splendor-kernel`, `splendor-daemon`, and `splendor-node` are composition roots at different process boundaries.

### 3.5 Privileged mutation

Any operation that changes authority, data-use rights, governed state, artifact registration, workload state, resource leases, agent state, deployment state, secrets, or the external world.

### 3.6 Effect

Filesystem, network, process, container, cluster, database, device, actuator, credential, model-service, artifact-store, or other externally observable I/O. Persistence engines are effects too, but they are constrained to storage responsibilities.

### 3.7 Impact edge

A compile-time, wire-format, persistence, event, control-flow, authority, artifact-lineage, deployment, or physical-safety relationship through which a code change may affect another component.

---

## 4. Canonical package ownership

| Package or surface | Sole architectural responsibility | Must not own |
|---|---|---|
| `crates/splendor-types` | Behavior-free canonical IDs, schemas, enums, receipts, references, deterministic serialization, compatibility grammar | I/O, stores, scheduling, verification execution, algorithms, provider clients |
| `crates/splendor-store` | Persistence traits and storage engines for already-validated records | Authority, policy, scheduling, lifecycle decisions, promotion, driver selection |
| `crates/splendor-authority` | Principal identity, capability decisions, secret-reference/lease semantics, data-use decisions | Artifact storage, workload placement, model policy, domain cognition |
| `crates/splendor-artifacts` | Artifact registry, immutable manifests, aliases/pointers under change control, derivation lineage | Training, evaluation, deployment approval, raw byte-provider logic |
| `crates/splendor-evidence` | Event ordering, state semantics, evidence bundles, replay/simulation plans, observability export contracts | Live driver execution, deployment decisions, application reasoning |
| `crates/splendor-gateway` | Driver registry and typed verified invocation lifecycle; `ActionGateway` remains a compatibility profile | Concrete providers, placement, training algorithms, agent policy |
| `crates/splendor-fabric` | Node protocol, resource offers, workload lifecycle, placement, leases, membership epochs, fencing, retry/checkpoint coordination | Model/loss/optimizer semantics, agent reasoning, candidate activation |
| `crates/splendor-agent` | Agent registry, persistent instance lifecycle, typed neuro-symbolic routes, world state, messages, delegation | Training algorithms, provider SDKs, deployment approval |
| `crates/splendor-learning` | Collection, feedback, reward derivation, eval orchestration, training flow control, improvement programs | PyTorch internals, model architecture, evaluator mathematics, activation |
| `crates/splendor-change` | Immutable change sets, impact classification, gates, deployment, rollback, quarantine, incidents | Candidate generation, training, evaluator implementation, direct effects |
| `crates/splendor-kernel` | Composition root, invariant wiring, compatibility facade, local embedded runtime | Provider algorithms, duplicate state machines, product policy |
| `crates/splendor-daemon` | Authentication/transport translation, API versioning, process composition | Domain decisions, direct store mutation, duplicate run/workload/change machines |
| `crates/splendorctl` | Operator/developer client for public commands, validation, explain, watch, replay | Hidden privileged paths, direct database edits, alternate runtime semantics |
| `binaries/splendor-node` | Resident node composition: local leases, execution backends, caches, health, trace buffering, device-local safety | Fleet-wide policy, global scheduler, training mathematics |
| `python/splendor` | Generated/typed authoring and client ergonomics | Independent kernel semantics, direct privileged side effects in policy callbacks |
| `python/splendor-train` | User-space hooks that adapt supported Python/PyTorch projects to trainer contracts | Fleet scheduling, authority, candidate activation |
| `typescript/packages/types` | Generated schema-aligned TypeScript contracts | Runtime behavior or independent validation semantics |
| `typescript/packages/client` | Thin daemon/control client | Verifier, gateway, store, replay, or runtime implementation |
| `adapters/*` | Concrete provider/framework/device implementations | Granting authority, selecting their own deployment, changing kernel policy |

One mutation has one owner. A daemon handler, CLI command, SDK wrapper, store implementation, adapter, or test harness must never become a second owner.

---

## 5. Target dependency order

The target graph is a directed acyclic graph. An arrow `A -> B` means package A may directly depend on package B. Reverse edges are forbidden unless explicitly listed as migration debt.

```text
                                   adapters/*
                                       |
                              types + gateway ABI
                                       |
 splendor-daemon / splendorctl / bindings / splendor-node
                                       |
                              splendor-kernel
                                       |
                            splendor-change
                            /      |      \
                    splendor-agent | splendor-learning
                          \        |        /
                         splendor-fabric
                          /      |      \
                 gateway   artifacts   evidence
                       \      |       /
                        splendor-authority
                                |
                         splendor-store
                                |
                         splendor-types
```

This diagram is a partial order, not a requirement that every upper package import every lower package.

### 5.1 Allowed direct internal dependencies

| Source | Allowed direct internal dependencies |
|---|---|
| `splendor-types` | none |
| `splendor-store` | `splendor-types` |
| `splendor-authority` | `splendor-types`, `splendor-store` |
| `splendor-artifacts` | `splendor-types`, `splendor-store`, `splendor-authority` |
| `splendor-evidence` | `splendor-types`, `splendor-store`, `splendor-authority` |
| `splendor-gateway` | `splendor-types`, `splendor-authority`, `splendor-artifacts`, `splendor-evidence` |
| `splendor-fabric` | `splendor-types`, `splendor-store`, `splendor-authority`, `splendor-artifacts`, `splendor-evidence`, `splendor-gateway` |
| `splendor-agent` | `splendor-types`, `splendor-store`, `splendor-authority`, `splendor-artifacts`, `splendor-evidence`, `splendor-gateway`, `splendor-fabric` |
| `splendor-learning` | `splendor-types`, `splendor-store`, `splendor-authority`, `splendor-artifacts`, `splendor-evidence`, `splendor-gateway`, `splendor-fabric` |
| `splendor-change` | all lower core packages, including read-only public interfaces of `splendor-agent` and `splendor-learning` |
| `splendor-kernel` | all core packages; only composition and compatibility code |
| `splendor-daemon` | target: `splendor-kernel`, `splendor-types`; generated API models |
| `splendorctl` | target: public kernel/daemon client and `splendor-types`; adapter dependencies only in an explicit embedded-local composition module |
| `splendor-bindings` | `splendor-kernel`, generated contract types |
| `splendor-node` | `splendor-fabric`, `splendor-gateway`, `splendor-authority`, `splendor-evidence`, `splendor-types`, selected adapters |
| adapter crates | `splendor-types`, `splendor-gateway`; a narrowly versioned node-executor ABI when required |

### 5.2 Why evidence does not depend upward

Replay and evidence often need facts from gateway, fabric, agent, learning, and change. `splendor-evidence` must not import those packages. It owns generic event/state/evidence contracts and produces a `ReplayPlan` or `SimulationPlan`. `splendor-kernel` bridges the plan to non-live drivers and returns results. This prevents `evidence <-> gateway` and `evidence <-> agent` cycles.

### 5.3 Why authority does not depend upward

The authority and data-use services may require artifact classifications, workload facts, or deployment context. Callers provide immutable, trace-linked fact snapshots or use outbound query ports declared by authority and implemented in a composition bridge. `splendor-authority` must not import artifacts, fabric, agent, learning, or change.

### 5.4 Why learning and agent do not depend on each other

Agent execution emits percept, outcome, feedback-target, and evidence events. Learning consumes those events through declared subscriptions. Learning emits candidate artifacts and improvement proposals. Agent execution consumes only activated bundles selected through change/deployment control. Direct `agent <-> learning` imports would create an architectural self-modification cycle and make live inference inseparable from training.

### 5.5 Why change is above learning and agent

Training, evaluation, data work, coding, or agent reasoning may produce candidates. None may activate itself. `splendor-change` is the only package that may decide a candidate is gate-ready and hand an approved deployment plan to activation controllers. It may read agent/learning facts; they must never call back into change internals to approve themselves.

---

## 6. Dependency inversion and bridge rules

Direct dependencies are not always appropriate even when the table permits them.

1. A component that needs a provider defines an outbound port in its owning package.
2. The provider implements that port in `adapters/*`, `splendor-store`, or a process composition module.
3. A component that needs a reverse-direction fact defines a narrow read port or accepts a signed/hashed fact snapshot.
4. `splendor-kernel::bridges` or `splendor-node::bridges` may adapt one component’s public interface to another component’s outbound port.
5. A bridge may translate contracts and retry transport. It must not decide policy or own state.
6. No general `ServiceLocator`, global mutable registry, or untyped callback map is allowed.
7. No “common” crate may collect unrelated business logic to avoid dependency rules.
8. `splendor-types` must not become a trait dumping ground. It contains serialized contracts, not service implementations or provider interfaces.
9. A new bridge is justified only when a direct edge would violate the dependency order or couple a component to a transport/provider.
10. Every bridge has contract tests against both sides and an explicit failure mapping.

---

## 7. Current migration debt and non-expansion rules

The present repository predates the vNext plane crates. Existing code is preserved behind compatibility facades, but new work must not deepen the wrong ownership.

| Current location | Target owner | Migration rule |
|---|---|---|
| `splendor-kernel/src/loop_engine.rs` | `splendor-agent` instance/route runtime plus kernel facade | Fix compatibility defects in place; new persistent-agent, model-session, route, or world-model behavior goes to `splendor-agent` |
| `splendor-kernel/src/scheduler.rs` | `splendor-fabric` local scheduler profile | Do not add fleet training, gang scheduling, leases, or preemption logic to the legacy scheduler |
| `splendor-kernel/src/state.rs` | `splendor-evidence` state service; persistence remains `splendor-store` | New CAS, partition, merge, snapshot, or rollback semantics belong in evidence/state |
| `splendor-kernel/src/trace.rs`, `trace_durability.rs` | `splendor-evidence` | New event/evidence contracts must not be embedded only in the kernel facade |
| `splendor-kernel/src/tenancy.rs` | `splendor-authority` | New principal, capability, data-use, or secret rules belong in authority |
| `message_router.rs`, `local_delegation.rs`, `remote_message_transport.rs` | `splendor-agent` message/delegation service | Preserve wire compatibility; new sub-agent forms and authority delegation belong in agent |
| `node_registry.rs` | `splendor-fabric` | New node offers, leases, placement, epochs, and fencing belong in fabric |
| `fleet_telemetry.rs` | `splendor-evidence` read models plus fabric facts | Do not let telemetry become scheduler authority |
| `policy_cache.rs` | `splendor-authority` distribution/cache contracts and `splendor-change` activation state | Separate authorization policy freshness from deployed agent/model revisions |
| `escalation.rs` | `splendor-change` incident/gate policy; gateway retains immediate verifier result | Do not build a second incident state machine in kernel |
| `splendor-daemon` direct store/gateway dependencies | kernel application-service facade | Existing endpoints may migrate incrementally; new endpoints must call one public application command/query, not stores |
| `splendorctl` direct adapter construction | explicit embedded-local composition only | Remote/operator paths must call public APIs; no hidden bypass |
| hand-written Python runtime semantics | generated schemas/bindings and thin ergonomics | Preserve 0.1 compatibility; do not manually add vNext authority, workload, change, or data-use semantics in Python |

A migration exception requires an entry in `architecture/dependency_policy.json` containing owner, reason, exact edge, affected modules, removal condition, and expiration milestone. “Temporary” without a removal condition is not an exception.

---

## 8. Normative architecture rules

### 8.1 Contract and identity rules

**AR-001 — Rust is the canonical contract source.** Stable serialized kernel contracts originate in `splendor-types`. Python, TypeScript, OpenAPI, fixtures, and documentation are generated or mechanically conformance-checked against it.

**AR-002 — IDs are nominal and non-interchangeable.** Dataset, model, checkpoint, eval, workload, attempt, worker, lease, candidate, change, deployment, incident, route, world-state, and feedback IDs must be distinct newtypes. String aliases that permit accidental substitution are forbidden for privileged objects.

**AR-003 — Authorizing fields are typed.** Authority, scope, approvals, secrets, data-use grants, placement, driver selection, gates, and activation references may not live inside unvalidated `serde_json::Value`, arbitrary maps, or `extensions`.

**AR-004 — Extensions never authorize.** Extensions may carry display, correlation, diagnostics, and external references. They cannot grant capability, select a driver, alter a quota, change a gate, supply a secret, or widen data use.

**AR-005 — Wire hashes have canonical bytes.** Any content-addressed object defines canonical serialization, hash algorithm/version, normalization, and cross-language golden fixtures.

**AR-006 — No ambiguous moving references in execution.** `latest`, mutable branch names, floating container tags, mutable dataset paths, and unpinned model aliases cannot enter a `WorkloadSpec`, `Invocation`, `EvalRun`, `ChangeSet`, or `DeploymentPlan`. Human-friendly aliases resolve to immutable refs before admission.

**AR-007 — Additive is not automatically compatible.** An optional field that changes authorization, interpretation, default behavior, hashing, evaluation, scheduling, or replay requires a versioned contract and migration analysis.

### 8.2 Mutation and state-machine rules

**AR-010 — Every privileged mutation follows command → decision → event → state.** The owner validates identity, authority, expected state, and idempotency; persists required pre-effect evidence; performs the bounded mutation; writes canonical state; emits a terminal event and receipt.

**AR-011 — Every state machine has one owner.** Run, workload, lease, agent instance, message, collection, feedback, eval, training, change, deployment, and incident transitions cannot be split among daemon handlers, stores, adapters, and controllers.

**AR-012 — Stores do not decide transitions.** `splendor-store` may enforce compare-and-swap, uniqueness, integrity, and transaction boundaries. It may not decide whether a workload should retry, an action is allowed, a candidate passes, or an agent may resume.

**AR-013 — No service writes another service’s tables directly.** Cross-component mutation uses a public command or event. Read-only materialized views may be shared only through versioned read contracts.

**AR-014 — State updates are optimistic and explicit.** Governed mutable heads require expected-head/CAS semantics. Blind overwrite is forbidden for agent state, world state, policy activation, deployment, and fleet lease ownership.

**AR-015 — Recovery behavior is part of the contract.** Every mutation defines crash points, idempotency, duplicate delivery handling, timeout semantics, and whether recovery is automatic, compensated, rolled back, quarantined, or requires intervention.

### 8.3 Authority, data-use, and secret rules

**AR-020 — Authentication is not action authority.** Daemon credentials authenticate a caller. Work orders, capabilities, data-use grants, approvals, quotas, and gateway checks authorize bounded operations.

**AR-021 — Authority only narrows across delegation.** Child agents, workers, adapters, and node processes receive subsets of parent authority with independent expiry and revocation.

**AR-022 — Data use is independent of compute authority.** Permission to run inference does not imply permission to train, evaluate, label, export, retain, or inspect raw data. Each purpose is explicit.

**AR-023 — Secrets are references and leases.** Kernel artifacts, events, work orders, traces, and configs contain secret references, never raw long-lived credentials. Node injection is scoped to workload/driver, time-bound, auditable, and revoked on termination.

**AR-024 — Denial and uncertainty fail closed.** An unavailable authority, expired policy, unverifiable grant, ambiguous data classification, stale physical safety state, or missing required evidence cannot degrade to allow.

**AR-025 — Policy cache degradation is declared.** Offline behavior identifies which low-risk operations remain possible, for how long, under what cached version, and which actions are denied or require intervention.

### 8.4 Artifact, lineage, data, feedback, and eval rules

**AR-030 — Artifacts are immutable.** Models, datasets, splits, checkpoints, code bundles, environments, eval suites, route specs, policy bundles, world snapshots, and deployment bundles are content-addressed immutable manifests.

**AR-031 — Mutable pointers are governed state.** An alias such as “active model” is a versioned activation pointer changed only by `splendor-change`, never by an artifact upload or training callback.

**AR-032 — Every derived artifact has lineage.** Lineage includes source artifacts, code/environment, transforms, parameters, seeds, work/attempt IDs, principals, data-use grants, and evidence.

**AR-033 — Dataset snapshots precede training/eval.** Mutable streams and sources are collected into immutable, purpose-scoped snapshots. A training run never reads an unversioned “current data” directory.

**AR-034 — Feedback is not an unscoped scalar.** A feedback record names target, source, subject, context, provenance, confidence, visibility, purpose, retention, evaluator/rubric version, and derivation.

**AR-035 — Rewards are derived artifacts.** Reward derivation identifies the exact feedback inputs, code/rule/model version, normalization, clipping, aggregation, uncertainty, and anti-gaming checks. Raw feedback is retained separately.

**AR-036 — Evaluation is independent and versioned.** Eval suites, judges, rubrics, protected splits, contamination checks, and thresholds are immutable versions. A candidate cannot modify the evaluator used to promote it inside the same change.

**AR-037 — Protected evaluation data is inaccessible to trainers.** Separation is enforced by data-use grants, workloads, node mounts, secret scopes, and audit evidence—not only by convention.

### 8.5 Gateway and driver rules

**AR-040 — All external effects use the Driver Gateway.** Actions, model calls, sensor reads, training processes, data transforms, eval execution, shell/Python/OCI/Kubernetes jobs, artifact-provider operations, and device commands use typed invocations.

**AR-041 — Drivers translate; they do not authorize.** A driver validates its local input and safety preconditions but cannot grant capability, change quotas, select itself, approve deployment, or broaden data access.

**AR-042 — Driver operations declare effect class.** Each operation declares read/write/external/physical semantics, idempotency, cancellation, timeout, retry safety, compensation, resource accounting, data classes, secret needs, and postconditions.

**AR-043 — Unknown operation/schema fails before execution.** Stringly typed “tool names” without a registered manifest and versioned input/output schema cannot reach a provider.

**AR-044 — Provider libraries stay outside core.** PyTorch, Transformers, Kubernetes, Docker, ROS, cloud SDKs, model-provider SDKs, databases, browsers, and hardware libraries belong in adapter or node-backend crates/packages.

**AR-045 — Driver conformance is evidence, not self-attestation.** Registry maturity/certification requires reproducible conformance outputs, failure injection, schema compatibility, cancellation, timeout, quota, secret, and isolation tests.

**AR-046 — Physical drivers preserve local veto.** Cloud/kernel approval cannot bypass device-local emergency stop, collision, geofence, battery, privacy, watchdog, or certified controller constraints.

### 8.6 Execution fabric rules

**AR-050 — All compute is a `WorkloadSpec`.** Inference, training, evaluation, data work, simulation, shell, Python, OCI, Kubernetes, checkpoint conversion, and maintenance use one workload lifecycle.

**AR-051 — Workload orchestration is core; workload algorithms are not.** Splendor owns admission, placement, leases, worker groups, epochs, rendezvous, fencing, retries, checkpoint requests, result collection, and evidence. User code owns mathematical semantics.

**AR-052 — Scheduler does not execute user code.** Fleet scheduler decides placement and leases. Node agents execute through isolated backends and drivers.

**AR-053 — Leases are fenced.** Every attempt/worker invocation carries workload, attempt, lease, node, and membership epoch. Stale workers cannot publish checkpoints, gradients, results, or effects after revocation or group restart.

**AR-054 — Live inference and physical control have protected reservations.** Training/eval/data work may use spare capacity only within declared interference budgets. Preemption, throttling, migration, or denial occurs before live SLO violation.

**AR-055 — Heterogeneity is explicit.** A synchronous collective group is compatibility-homogeneous unless an explicit parallelism plugin proves otherwise. Heterogeneous devices remain usable for preprocessing, eval shards, inference, simulation, conversion, independent trials, and data-local work.

**AR-056 — “Arbitrary PyTorch” has compatibility tiers.** T0 opaque, T1 torchrun-compatible, T2 structured hooks, and T3 explicit parallel plugin are distinct contracts. Splendor must never claim automatic correct distribution when project semantics do not satisfy a tier.

**AR-057 — Global progress survives membership changes.** Training adapters report sample IDs/ranges, optimizer steps, RNG/checkpoint state, and committed progress so retries or elastic restarts do not silently duplicate or skip work.

### 8.7 Agent runtime and neuro-symbolic routing rules

**AR-060 — Neuro-symbolic is a runtime crossing.** Route steps explicitly classify neural inference, symbolic rule/solver, state query/update, human approval, sub-agent delegation, and driver proposal. No mandated planner or graph framework is required.

**AR-061 — Model output is a proposal.** Neural output can become a decision proposal, route value, state hypothesis, or action proposal. It is never direct external authority.

**AR-062 — Symbolic logic has versioned inputs and outputs.** Rules, constraints, planners, solvers, and proofs reference exact versions and emit structured decisions/evidence rather than hidden booleans.

**AR-063 — World state distinguishes belief from fact.** Entries carry provenance, confidence, temporal validity, ownership, conflict status, and verification class. Neural latent state cannot be labeled verified external truth.

**AR-064 — Agent code does not persist private chain-of-thought as a kernel requirement.** Splendor records structured proposals, decisions, tool/model inputs and outputs subject to policy, evidence, rule results, and state transitions. It does not require hidden reasoning text.

**AR-065 — Sub-agents are explicit instances or invocations.** A sub-agent may be a persistent agent, bounded delegated run, trigger target, planner, evaluator, or actuator-like service. Its identity, authority, state, budget, causal parent, and termination are explicit.

**AR-066 — 24/7 agents are supervised state machines.** Startup, admission, running, paused, draining, checkpointing, degraded, intervention, failed, stopped, and upgrade states are owned by the instance controller, not by an unbounded user loop.

### 8.8 Learning, evolution, and change rules

**AR-070 — Training emits candidates only.** A trainer may publish checkpoints, metrics, and a `CandidateBundle`. It cannot move an active alias or update a live agent revision.

**AR-071 — Evaluation emits evidence, not promotion.** An evaluator reports measurements, uncertainty, slices, failures, and provenance. Gate policy decides whether evidence satisfies requirements.

**AR-072 — Improvement proposes experiments.** Search, RL, self-reflection, coding, or optimization logic proposes collection/eval/training/change work. It cannot grant itself resources, data access, or approval.

**AR-073 — Self-change is ordinary governed change with higher scrutiny.** A change generated by the affected agent/model receives no special trust. It records generator lineage and requires independent evidence channels according to risk.

**AR-074 — Activation is an atomic dependency-aware operation.** Model, tokenizer, route, policy, world schema, driver, evaluator, and code versions that must move together are represented in one `ChangeSet` dependency graph.

**AR-075 — Rollback target exists before rollout.** Deployment cannot enter canary/full state without a validated rollback target, state/data compatibility plan, irreversible-effect disclosure, and health gates.

**AR-076 — Value alignment is represented by plural evidence.** No single reward, judge, or human approval proves alignment. Gates declare required independent evidence, disagreement handling, regression budgets, red-team coverage, and abstention/inconclusive behavior.

**AR-077 — Novelty claims are external to pass/fail mechanics.** Gold experiments may establish reproducible improvements in interoperability, control, bounded evolution, or regression management. They must not claim universal alignment, general self-improvement, or novel model algorithms without appropriate evidence and comparison.

### 8.9 API and composition rules

**AR-080 — Daemon handlers are thin.** A handler authenticates/version-checks, parses one command/query, calls one application service, and maps structured errors. It does not open stores, select adapters, advance state machines, or manufacture authority.

**AR-081 — CLI is not a privileged backdoor.** `splendorctl` uses the same public command/query and authority routes as other clients. Embedded-local mode is explicit and still wires the same gateway/services.

**AR-082 — SDKs do not duplicate kernel semantics.** Python and TypeScript validate ergonomic shape and call Rust/daemon contracts. Authorization, state-machine transitions, hashing, and effect rules remain canonical in Rust services.

**AR-083 — Compatibility facades delegate.** `splendor-kernel` may re-export stable 0.1 items and map old calls to new services. It must not keep two divergent implementations alive.

**AR-084 — Examples use public surfaces.** Gold examples cannot reach private stores, call adapters directly, disable verifiers, use hidden fixtures unavailable to users, or treat skipped tests as passes.

---

## 9. External dependency fences

Core packages may use general-purpose libraries for serialization, cryptography, errors, deterministic data structures, time, concurrency, and protocol implementation. They may not import domain/provider runtimes.

### 9.1 Forbidden in `splendor-types`

- async runtimes and web frameworks;
- filesystem, process, socket, database, cloud, model, container, cluster, robotics, or hardware clients;
- `splendor-*` packages;
- nondeterministic global registries.

### 9.2 Forbidden in core policy packages

`splendor-authority`, `artifacts`, `evidence`, `gateway`, `fabric`, `agent`, `learning`, `change`, and `kernel` must not acquire direct dependencies on:

- PyTorch/tch, TensorFlow, JAX, Transformers, ONNX runtime, Candle, model-provider SDKs;
- Kubernetes clients, Docker/Bollard, Nomad, Slurm, Ray, Dask;
- ROS/vendor robot SDKs, drone SDKs, camera/sensor SDKs;
- cloud-specific compute, secret, object-store, or telemetry SDKs;
- application ontologies or vertical-specific packages.

The contract for those systems belongs in core; the implementation belongs in adapters/node backends.

### 9.3 Allowed effect locations

| Effect | Allowed production locations |
|---|---|
| persistence database/files | `splendor-store` engines and artifact-store adapters |
| daemon socket bind | `splendor-daemon` |
| node control socket/process/container/VM | `splendor-node`, executor adapters |
| outbound HTTP/filesystem/tool/device/model calls | registered adapters through gateway |
| cloud/Kubernetes scheduling provider calls | capacity/executor adapters invoked by fabric/node |
| Python/PyTorch process launch | trainer/executor adapters under a workload lease |
| physical command | physical actuator adapter with node-local safety verifier |

A core service may calculate a plan or proposal for an effect. Only an allowed effect location executes it.

---

## 10. Enforcing the architecture

Documentation alone is not enforcement. The following controls are mandatory.

### 10.1 Machine-readable dependency policy

`architecture/dependency_policy.json` is the source for package tiers, allowed edges, path owners, migration exceptions, and impact facets. CI runs:

```bash
python tools/check_architecture_policy.py --policy architecture/dependency_policy.json
```

The checker must fail on:

- unapproved workspace dependency edge;
- internal dependency cycle;
- adapter imported by a core production dependency;
- provider/runtime dependency in a forbidden package;
- missing owner for a changed governed path;
- expired migration exception;
- target package that adds a reverse edge;
- production use of a dev-only adapter dependency.

`cargo metadata` is the graph source. Hand-maintained diagrams are explanatory, not authoritative.

### 10.2 Source import/effect fences

A static scan rejects direct effect APIs outside allowed locations. The scan covers at least:

- `std::fs`, `std::net`, `std::process::Command`;
- `tokio::process`, outbound HTTP clients, database clients;
- Docker/Kubernetes/cloud/robot/model SDK imports;
- direct adapter construction from domain packages;
- direct store-engine construction from daemon handlers.

False positives are resolved by narrowing the detector or adding a precise reviewed exception. Broad path exclusions are forbidden.

### 10.3 Mutation ownership registry

Maintain a machine-readable registry mapping each command, mutable state head, transition family, and canonical event to exactly one component. CI rejects duplicate ownership. Examples:

- `SubmitInvocation` → Driver Gateway;
- `CommitState` → State Service;
- `AdmitWorkload` → Workload Controller/Fleet Scheduler boundary as explicitly split;
- `RecordFeedback` → Feedback Service;
- `StartEvalRun` → Evaluation Controller;
- `StartTrainingRun` → Training Controller;
- `SubmitChangeSet` → Change Controller;
- `AdvanceDeployment` → Deployment Controller.

A transport endpoint and a store method are not owners.

### 10.4 Generated contract checks

CI regenerates JSON Schema, OpenAPI models, Python models, TypeScript types, and golden fixtures. The working tree must remain clean after generation.

Required checks:

```bash
cargo test -p splendor-types
python conformance/0.1/run-conformance.py
python scripts/generate-contracts.py --check
npm run typecheck
```

The exact generator may evolve; the one-source rule may not.

### 10.5 Stable API checks

For the declared public Rust surface:

- run `cargo public-api` diffs;
- run `cargo semver-checks` on release branches;
- compare OpenAPI and schema snapshots;
- require migration notes for any changed persisted/wire contract;
- retain 0.1 compatibility fixtures until the published deprecation policy allows removal.

A compiler-successful change may still be wire-incompatible or semantically unsafe.

### 10.6 State-machine tests

Every owner provides:

1. transition-table tests for every state and command;
2. invalid-transition tests;
3. idempotency/duplicate-delivery tests;
4. crash-point recovery tests;
5. property tests for invariants;
6. event ordering/completeness tests;
7. persistence round-trip tests;
8. concurrency/CAS conflict tests where state is mutable.

State transitions hidden inside HTTP handlers or adapter callbacks automatically fail architecture review.

### 10.7 Effect-path integration tests

Every privileged effect proves the full path:

```text
principal/scope
  -> command
  -> authority + data-use decision
  -> required pre-effect event
  -> gateway invocation
  -> driver
  -> postcondition/outcome
  -> state/artifact update
  -> terminal evidence
```

Negative fixtures must prove that denial, uncertainty, stale lease, expired grant, invalid schema, missing evidence sink, timeout, cancellation, replay mode, and revoked driver prevent the effect.

### 10.8 Failure injection

Required failure points include:

- before/after pre-effect event append;
- before/after external effect;
- before/after state commit;
- worker loss and duplicate worker restart;
- stale membership epoch and revoked lease;
- checkpoint upload interruption;
- authority/data-use service unavailable;
- protected-eval mount failure;
- node disconnect/reconnect;
- rollout health signal loss;
- physical safety uncertainty.

Tests assert explicit recovery or intervention. Silent partial success is forbidden.

### 10.9 Review ownership

- one component owner reviews any state-machine or public-contract change;
- authority, gateway, secrets, data-use, change, and physical-safety changes require a security/safety reviewer;
- cross-plane changes require reviewers from both sides of every new edge;
- stable schema changes require SDK/API owner review;
- novelty/alignment claims require research-method review separate from implementation review.

### 10.10 Exception policy

An exception includes:

```yaml
source: splendor-daemon
target: splendor-store
scope: existing 0.1 run inspection handlers only
owner: <team/person>
reason: compatibility during application-service extraction
introduced: <commit/release>
removal_condition: daemon command/query facade supports the endpoint
expires_by: <milestone/date>
validation: architecture test proving no new handler uses the edge
```

An exception cannot permit gateway bypass, replay side effects, self-approval, raw secret persistence, protected eval leakage, or physical safety bypass.

---

## 11. Validation levels

### V0 — Static architecture

- dependency policy and cycle check;
- import/effect fences;
- path ownership and exception expiry;
- public API/schema diff classification.

### V1 — Contract conformance

- cross-language golden serialization;
- IDs, hashes, enum/version behavior;
- OpenAPI/client conformance;
- 0.1 compatibility suite.

### V2 — Component correctness

- state-machine, property, concurrency, and persistence tests;
- component-level failure injection;
- driver conformance for changed driver contracts.

### V3 — Cross-plane invariants

- authority/data-use/gateway/evidence sequence;
- artifact lineage completeness;
- workload lease/fencing;
- agent route/state/delegation;
- feedback/eval/training candidate flow;
- change/gate/deployment/rollback.

### V4 — System and fleet behavior

- multi-node disconnect/recovery;
- gang/elastic group behavior;
- inference protection under background training/eval/data work;
- node-local cache, policy, and trace sync;
- stale worker/result rejection.

### V5 — Gold examples

Run only the gold cases selected by recursive impact analysis, plus required global invariants. A gold case passes only with retained machine-readable evidence. “Not available,” “skipped,” or “simulated outside the declared mode” is not a pass.

### V6 — Research/novelty evidence

Self-evolution and value-alignment programs require baselines, ablations, multiple seeds where applicable, independent evaluation, contamination controls, confidence/uncertainty, regression budgets, adverse cases, and explicit claim limits.

### V7 — Physical production evidence

Simulation and software-in-the-loop are development evidence. Hardware-in-the-loop, device-specific limits, emergency paths, operational procedures, and external certification are separate requirements before physical production claims.

---

## 12. Change classification

Every pull request declares one or more change facets. The facet drives recursive impact and mandatory validation.

| Facet | Examples | Mandatory impact dimensions |
|---|---|---|
| `private_impl` | internal algorithm without observable contract change | compile callers, component behavior |
| `public_api` | exported Rust/Python/TS method/type | reverse dependencies, examples, docs, semver |
| `wire_schema` | serialized fields/enums/OpenAPI | all producers/consumers, golden fixtures, migration |
| `persistence` | store schema, hash, state node | migrations, replay, rollback, handoff, backup |
| `event_semantics` | event kind/order/payload | emitters, subscribers, evidence, observability, incidents, replay |
| `authority` | capabilities, scopes, approvals, data-use | every protected command/effect, caches, offline behavior |
| `side_effect` | gateway/driver operation | verifiers, adapters, postconditions, compensation, replay |
| `fabric` | workload/lease/placement/protocol | scheduler, node, drivers, checkpoints, SLOs, fleet compatibility |
| `agent_runtime` | routes, instance lifecycle, world state, delegation | state/evidence, gateway, messaging, deployment compatibility |
| `data_feedback` | collection, feedback, reward | lineage, retention, training/eval consumers, gates |
| `evaluation` | suite/judge/report/threshold | protected data, gates, candidate comparisons, claims |
| `training` | controller/adapter/checkpoint | fabric, data, lineage, eval handoff, candidate contract |
| `change_deployment` | change/gate/rollout/rollback | active agents, compatibility, incidents, audit |
| `physical_safety` | device profile/action/safety check | local veto, simulation/HIL, intervention, rollback limits |
| `generated_surface` | Python/TS/OpenAPI output | source contract and all client tests |
| `research_claim` | novelty/alignment statement | experiment provenance, baselines, statistics, claim review |

Unknown facet means high impact, not low impact.

---

## 13. Recursive impact model

A source-code dependency graph is necessary but insufficient. Splendor uses a multi-graph.

### 13.1 Graphs that participate

1. **Package graph:** Cargo/npm/Python imports and re-exports.
2. **Contract graph:** which packages produce, consume, persist, sign, hash, or generate each public schema.
3. **Command graph:** caller → component owner for each command/query.
4. **Event graph:** emitter → subscribers/materialized views/evaluators/incidents/exporters.
5. **State graph:** state writer → readers, migrations, snapshots, replay, rollback, handoff.
6. **Effect graph:** proposal → authority/data-use → gateway → driver → outcome/postcondition.
7. **Artifact-lineage graph:** producer → artifact → downstream datasets/models/evals/candidates/deployments.
8. **Fleet graph:** workload → leases/nodes/worker groups/checkpoints/protocol versions.
9. **Activation graph:** change → deployment → cohorts → agent instances/devices.
10. **Research-evidence graph:** implementation/eval/data versions → result → published claim.

### 13.2 Edge propagation rules

| Edge | Propagate when |
|---|---|
| imports/re-exports | always for compile/public changes |
| serializes/deserializes | field, enum, default, validation, hash, or version semantics change |
| persists/loads | bytes, key, index, transaction, ownership, or lifecycle semantics change |
| emits/subscribes | event kind, order, payload, durability, or absence semantics change |
| calls command/query | input/output/error, authority, idempotency, or behavior changes |
| invokes driver | operation schema, verifier order, timeout, retry, effect, or postcondition changes |
| produces artifact | manifest, lineage, compatibility, or content changes |
| consumes artifact | producer/compatibility/security change can affect consumer |
| grants/validates authority | scope, cache, revocation, uncertainty, or decision behavior changes |
| schedules/leases | resources, priority, interference, membership, fencing, or retry changes |
| deploys/activates | bundle compatibility, cohort, health gate, migration, or rollback changes |
| supports claim | implementation/data/eval/statistical interpretation changes |

### 13.3 Algorithm

```text
INPUT: changed files/symbols, base/head refs, active deployment snapshot (when available)

1. Map every changed path to one package, component owner, stable surface, and initial facets.
2. Reject unowned or multiply owned paths.
3. Build compile reverse-dependency closure.
4. Add contract producers/consumers for changed exported or serialized symbols.
5. Add event subscribers and state readers for changed event/state semantics.
6. Add effect-path participants for authority/gateway/driver changes.
7. Add artifact descendants and active deployment consumers for changed artifacts/providers.
8. Add fleet peers for workload, lease, node protocol, checkpoint, or fencing changes.
9. Add research results/claims that cite affected code, data, eval, or artifacts.
10. Re-run propagation until no new node or facet is added.
11. For each attempted impact cut, require a machine-checkable reason and evidence.
12. Generate required test suites, reviewers, migrations, compatibility work, rollout limits, and documentation updates.
13. Treat unresolved/unknown edges as impacted and block release-level claims.
```

The closure stops because no new nodes/facets are added—not because a reviewer chose an arbitrary depth.

### 13.4 Valid impact cuts

A propagation edge may be cut only when one of these is demonstrated:

- changed symbol is private and observable contracts/events/state/effects are unchanged;
- an adapter/provider contract is unchanged and conformance tests prove substitutability;
- a version boundary isolates old/new schemas and migration/negotiation tests pass;
- a feature is unreachable in the selected deployment and activation graph proves no consumer;
- generated output is byte-identical;
- lineage shows no descendant or deployed consumer;
- a fail-closed gate prevents the changed path from becoming active.

“Probably unaffected,” “only refactor,” “tests passed locally,” and “different team owns it” are not cuts.

### 13.5 Required impact output

Every non-trivial PR produces an impact manifest containing:

```yaml
change_id: <commit-or-pr>
base: <sha>
head: <sha>
changed_paths: []
owners: []
facets: []
direct_packages: []
transitive_packages: []
components: []
stable_contracts: []
events: []
persisted_objects: []
driver_operations: []
artifacts_and_lineage: []
active_deployments: []
physical_surfaces: []
research_results_or_claims: []
required_migrations: []
required_validation: []
required_reviewers: []
impact_cuts:
  - edge: <from -> to>
    reason: <permitted cut>
    evidence: <test/fixture/query>
unresolved_edges: []
```

An empty `unresolved_edges` field is required for merge into a release branch. Development branches may carry explicitly accepted unresolved work only when it cannot activate or weaken invariants.

---

## 14. How to navigate dependencies before changing code

### Step 1 — Find the owner, not merely the file

Use the package map and `architecture/components.yaml`. A file may be in a legacy package while its target owner is elsewhere. Determine:

- current implementation location;
- target component owner;
- public commands/events/state it participates in;
- compatibility facade that must remain stable.

### Step 2 — Inspect direct and reverse compile dependencies

```bash
cargo metadata --format-version 1 > target/architecture/cargo-metadata.json
cargo tree -p <package> --edges normal,build
cargo tree -i <package> --workspace --edges normal,build
```

For a type or re-export:

```bash
rg 'pub use .*<Type>|<Type>' crates python typescript openapi docs examples conformance
```

Do not stop at the importing crate. Follow re-exports into SDKs and daemon models.

### Step 3 — Follow the runtime contract

For a changed command/type, search:

- validation and constructors;
- serializers/deserializers and schema fixtures;
- stores and indexes;
- event kinds and trace ordering;
- daemon request/response models;
- Python/TypeScript representations;
- gold examples and conformance cases.

### Step 4 — Follow the privileged path

For authority, data, action, workload, or deployment changes, draw the exact sequence from principal to outcome. Locate every fail-closed boundary and every durable event. A missing edge is an architecture defect, not an undocumented implementation detail.

### Step 5 — Follow lineage and activation

For model/data/code/eval/driver changes, query or enumerate:

- artifacts produced by the changed component;
- descendants of those artifacts;
- candidates and change sets containing them;
- deployments and agent revisions consuming them;
- active nodes/devices/cohorts;
- claims/evidence generated from them.

### Step 6 — Generate the recursive impact report

```bash
python tools/compute_change_impact.py \
  --policy architecture/dependency_policy.json \
  --base origin/main \
  --head HEAD \
  --format markdown \
  --out target/architecture/impact.md
```

The static report is a lower bound. Runtime lineage/deployment data supplements it for release and incident work.

### Step 7 — Review impact cuts

Every excluded downstream component must have a valid cut. The reviewer should be able to answer, “what exact stable boundary prevents propagation?”

### Step 8 — Run validation selected by facets

The impact report maps facets/components to suites. Add targeted tests before implementation when the change modifies a contract or invariant.

---

## 15. Concrete recursive-impact examples

### Example A — Changing `Feedback`

A field or semantic change in `splendor-types::Feedback` impacts:

1. Rust serialization and stable primitive fixtures;
2. Python and TypeScript generated models;
3. daemon append/read APIs;
4. event-log payload/reference validation;
5. Feedback Service identity, provenance, retention, and target rules;
6. Reward Derivation inputs and lineage;
7. eval and training datasets that consume feedback;
8. Improvement Controller experiment selection;
9. Gate Engine evidence independence and reward-hacking checks;
10. replay/evidence exports and any research result based on old feedback semantics.

The impact may stop before model-driver execution when the invocation contract and activated model remain unchanged. That cut requires tests proving no changed inference input/output contract.

### Example B — Changing `ExecutionLease` or membership epoch

The recursive set includes:

- `splendor-types` wire fixtures;
- Fleet Scheduler lease creation;
- Workload Controller attempt transitions;
- Node Agent admission and revocation;
- Driver Gateway invocation context;
- executor/trainer adapters;
- stale result/checkpoint rejection;
- inference reservation/preemption tests;
- node reconnect/state handoff;
- deployment workloads that rely on leases;
- distributed PyTorch rendezvous and global progress accounting.

A successful unit test in `splendor-fabric` is insufficient.

### Example C — Changing verifier order in `VerifiedActionGateway`

The impact includes action outcomes, approval behavior, quota accounting, circuit breakers, physical safety, adapter execution counts, trace order, replay explanation, daemon responses, Python/TypeScript status expectations, and all effect-path examples. Since order can change denial reasons or whether a provider is reached, it is a semantic and security change even when types compile unchanged.

### Example D — Changing only a GPT-2 trainer adapter

When `DriverManifest`, `TrainingPlan`, checkpoint format, and `CandidateBundle` contract remain unchanged, compile impact can be limited to the adapter, `splendor-train` integration, trainer conformance, Training Controller integration, distributed workload tests, GPT-2 gold examples, and any artifacts/claims produced by the adapter version. Core authority, agent, and change packages need not be modified. Active candidates produced by the old adapter remain linked to the old immutable adapter artifact.

### Example E — Changing the state-node hash algorithm

This is a broad migration affecting state IDs, store indexes, snapshots, trace links, replay, state handoff, world state, agent checkpoints, deployment rollback, offline device sync, evidence bundles, conformance fixtures, and any signatures over state refs. It requires a versioned hash algorithm, dual-read or explicit migration, and rollback proof. A silent algorithm swap is forbidden.

### Example F — Adding a daemon endpoint

A correctly layered endpoint changes daemon routing, generated OpenAPI/client models, authentication scopes, and calls one existing application command/query. A new endpoint that opens `SqliteStateStore`, mutates `RunSlot`, selects an adapter, or advances a deployment is an architecture violation regardless of test coverage.

### Example G — Changing a protected eval split

The split becomes a new immutable dataset/eval artifact. It does not overwrite the prior split. Impact includes data-use grants, contamination analysis, evaluator reports, gate comparability, active improvement programs, and research claims. Existing candidate results remain attached to the old split and cannot be silently reinterpreted under the new one.

---

## 16. Required PR architecture statement

Every PR changing production code answers:

1. **Owner:** which component owns the changed behavior?
2. **Boundary:** is this contract, policy, orchestration, persistence, provider, transport, or user-space algorithm code?
3. **Dependency:** did any direct edge change? Is it allowed by policy?
4. **Mutation:** which state machine and command/event sequence changed?
5. **Effects:** can the change cause I/O, resource use, data access, activation, or physical action?
6. **Recursive impact:** what direct and transitive packages/components/contracts are affected?
7. **Impact cuts:** why are excluded consumers isolated?
8. **Compatibility:** what stable wire/persistence/API behavior changed?
9. **Validation:** which static, component, integration, failure, fleet, gold, and research tests ran?
10. **Rollout:** what gate, canary, rollback, or migration is required?

A PR template may generate these fields from the impact manifest, but the author remains responsible for correctness.

---

## 17. Architecture validation matrix by package

| Changed owner | Minimum suites beyond unit tests |
|---|---|
| `splendor-types` | all language golden fixtures, schema/OpenAPI generation, reverse workspace compile, 0.1 conformance |
| `splendor-store` | migration, transaction/crash, integrity, replay/state round trip, all service repository contracts |
| `splendor-authority` | denial/uncertainty/revocation/cache tests; gateway/fabric/agent/learning/change integration |
| `splendor-artifacts` | hash/immutability/lineage, concurrent registration, alias governance, downstream candidate/deployment lookup |
| `splendor-evidence` | event durability/order, CAS state, replay no-effect, evidence completeness, privacy/export behavior |
| `splendor-gateway` | full effect-path denial/execution/failure/cancel/timeout/postcondition tests; adapter conformance |
| `splendor-fabric` | multi-node placement, lease fencing, worker loss, checkpoint/restart, inference interference, protocol compatibility |
| `splendor-agent` | persistent lifecycle, route typing, state conflict, model/action proposal boundary, delegation narrowing, upgrade/rollback |
| `splendor-learning` | data purpose/lineage, feedback/reward provenance, eval isolation, training candidate-only behavior, improvement limits |
| `splendor-change` | impact requirements, evidence gates, principal separation, shadow/canary, rollback, quarantine, incident integration |
| daemon/client/SDK | auth/version/error mapping, generated contract parity, no duplicated semantics, endpoint E2E |
| adapter | manifest/conformance, isolation, secret/data scope, timeout/cancel/retry, resource accounting, negative provider behavior |
| physical adapter/safety | simulation, stale/unknown safety denial, local veto, disconnect behavior, HIL evidence where claims require it |

---

## 18. Anti-drift review questions

Reject or redesign a change when any answer is “yes”:

- Is a provider/library being added to a core package because it is convenient?
- Is a daemon/CLI/SDK path performing a state transition instead of calling its owner?
- Is a store deciding policy?
- Is an adapter granting itself authority or selecting its own activation?
- Is training/eval/data code bypassing `WorkloadSpec` and fleet leases?
- Is user code reaching filesystem/network/process/device APIs outside a driver invocation?
- Is a new JSON blob carrying privileged semantics without a schema?
- Is a mutable alias used where an immutable artifact ref is required?
- Is feedback/reward missing target, provenance, version, or purpose?
- Is evaluation data visible to training workers?
- Can a candidate activate without a `ChangeSet`, independent gate, deployment plan, and rollback target?
- Can replay or simulation reach live adapters?
- Can stale workers publish after lease/epoch revocation?
- Can cloud approval override device-local safety?
- Does a new dependency create a reverse edge or an unbounded “common” package?
- Is an impact analysis stopping at the changed crate rather than following events, state, lineage, and deployments?
- Is a novelty/alignment claim broader than the evidence and baselines support?

---

## 19. Definition of architectural completion

The clean architecture is not complete because packages have been renamed. It is complete when:

1. every canonical command, state machine, event, and mutable head has one registered owner;
2. the workspace graph matches the dependency policy with no permanent exceptions;
3. all external effects are discoverable through driver manifests and gateway evidence;
4. all compute is admitted and tracked as workloads with leases and recoverable attempts;
5. data, feedback, reward, eval, training, and improvement use immutable artifacts and lineage;
6. agent and learning planes interact through typed events/artifacts, not self-modifying imports;
7. candidate generation and activation are mechanically separated;
8. daemon, CLI, SDK, and bindings are thin facades over canonical services;
9. recursive impact reports include compile, contract, state, event, effect, lineage, deployment, and claim edges;
10. architecture checks fail automatically when a rule is violated;
11. compatibility and migration evidence exists for persisted and public contracts;
12. gold examples prove the architecture under failure, distribution, ongoing evolution, and minimal-regression constraints.

Until all twelve conditions hold, architecture exceptions and missing enforcement must remain visible as debt. They must not be described as completed kernel capability.
