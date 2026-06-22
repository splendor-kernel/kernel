# AGENTS.md — Splendor v2 Implementation Agent Contract

This is the first instruction document for implementation agents working on Splendor.
It exists to keep work aligned with the active **0.2/v2 agent-kernel direction**,
prevent architectural drift, and make every contribution verifiable.

Splendor is a **kernel-grade AI runtime substrate** for persistent governed
agents, neuro-symbolic routes, verified side effects, evidence/replay,
data/feedback/evaluation/training control, fleet execution, physical AI
orchestration, and governed self-evolution.

Splendor runs **on top of Unix-like systems**. It is not a bare-metal OS, not a
chat-agent framework, not an enterprise SaaS product, not a marketplace, and not
a robot hard-real-time controller.

---

## 0. Current source-of-truth posture

### Active execution line

**0.2/v2 is the active execution line.** New implementation, QA,
integration, conformance, gold examples, and GitHub tracking must start from
the v2 rule pack and catalog.

### Compatibility baseline

**0.1 is the implemented compatibility baseline.** Use 0.1 documents when you
need to preserve existing behavior, migrate a current primitive, compare old and
new contracts, or validate backwards compatibility. Do not let 0.1 milestone
tables become the center of new v2 work.

### Catalog status

The v2 catalog is the decomposition and assignment authority for active work;
it is **not** implementation evidence. A row in the catalog, a generated schema,
or a docs-only PR never proves behavior. Behavior is proven only by code,
tests, examples, conformance reports, gold evidence, and retained validation.

---

## 1. Required reading order

Do not skip large files. Read the relevant chunks for your component/task and
record the exact task IDs and gold IDs you used.

### 1.1 Required for every implementation agent

```text
AGENTS.md
/docs/rules/v2/README.md
/docs/rules/v2/catalog/complete_implementation_task_catalog.md
/docs/rules/v2/catalog/implementation_task_index.md
/docs/rules/v2/gold/gold-examples-catalog.md
/docs/rules/splendor_dev_model.md
/docs/rules/sprints_frs_milestones.md
```

### 1.2 Required for v2 architecture/package-boundary work

```text
/docs/rules/v2/architecture/architecture.md
/docs/rules/v2/architecture/core-abstractions.md
/docs/rules/v2/architecture/clean-architecture-rules.md
/docs/rules/v2/architecture/schema-identity-map.md
/docs/rules/v2/architecture/architecture-policy-plan.md
/docs/rules/v2/catalog/architecture/components.yaml
/docs/rules/v2/catalog/architecture/implementation_tasks.yaml
```

### 1.3 Required for gold/conformance/example work

```text
/docs/rules/v2/gold/gold-examples-catalog.md
/docs/rules/v2/gold/gold-conformance-triage.md
/docs/rules/v2/gold/examples/catalog.yaml
/docs/rules/v2/gold/gold-gpt2.md
/docs/rules/v2/gold/gold-distributed-pytorch.md
/docs/rules/v2/gold/gold-world-model.md
/docs/rules/v2/gold/gold-coding-agent.md
```

### 1.4 Required when changing public contracts or compatibility anchors

```text
/docs/rfc/
/docs/reference/
/docs/concepts/
/docs/rules/legacy/0.1-sprints_frs_milestones.md
/docs/rules/verifiable_criteria/main.md
/docs/rules/verifiable_criteria/sprints/
```

### 1.5 Conflict hierarchy

When documents conflict, use this order:

```text
1. AGENTS.md safety and workflow rules
2. accepted RFCs, stable specs, public schemas, public API contracts, release limitations
3. /docs/rules/splendor_dev_model.md and non-negotiable kernel invariants
4. /docs/rules/v2/* for active 0.2/v2 decomposition, task scope, package direction, and gold coverage
5. /docs/rules/sprints_frs_milestones.md as active milestone/sprint entrypoint
6. /docs/reference/* and /docs/concepts/*
7. /docs/guides/* and /examples/*
8. legacy 0.1 roadmap details, unless doing compatibility/migration work
9. issue comments and informal planning notes
```

If a conflict affects a primitive, schema, runtime invariant, or public API,
write or update an RFC before changing behavior.

---

## 2. Splendor v2 mission

Build Splendor into a kernel substrate where learning/evolution, symbolic
control, verified action, feedback/evaluation, fleet execution, physical safety,
and deployment governance interoperate as one kernel-routed process while
preserving user-space freedom.

The v2 kernel must standardize and enforce:

- principal, tenant, fleet, node, instance, agent, workload, run, tick, action,
  state, event, evidence, message, artifact, dataset, model, checkpoint, eval,
  change, deployment, incident, approval, and lease identity;
- authority, delegation, work-order, data-use, secret, approval, and policy
  decisions;
- WorkloadSpec lifecycle, placement, leases, resource accounting, fencing,
  admission, preemption, and recovery;
- driver/gateway invocation, verifier chains, receipts, idempotency, effect
  certainty, and postconditions;
- event/state/evidence integrity, append-only facts, explicit state ownership,
  replay/simulation safety, audit redaction, and observability export;
- artifact identity, lineage, retention, replication, access, and provenance;
- feedback, reward derivation, evaluation, training, improvement, candidate
  publication, gate decisions, rollout, rollback, and incident handling;
- physical/edge high-level orchestration without replacing local safety or
  hard-real-time controllers.

---

## 3. Non-negotiable v2 architecture law

These laws are binding unless a later accepted RFC explicitly changes them.

1. **One mutation owner per concept.** Stores persist; daemon handlers
   translate; SDKs call; exporters project. None become shadow owners of
   service semantics.
2. **One workload grammar.** Agent ticks, inference, training, evaluation,
   data work, simulation, shell/Python/OCI/Kubernetes jobs, migration, and
   maintenance are governed `WorkloadSpec`s with different profiles, not bypass
   systems.
3. **Algorithms remain user space.** Model architecture, optimizer, loss,
   planner, solver, ontology, reward function, evaluator, data transform,
   parallelism strategy, and domain behavior are plugins/adapters/application
   code.
4. **Control remains kernel space.** Identity, authority, data purpose,
   placement, leases, fencing, driver invocation, resource accounting,
   state/event/evidence integrity, change risk, gates, rollout, rollback, and
   incidents are kernel contracts.
5. **All side effects cross the gateway.** Filesystem, HTTP, database, shell,
   Kubernetes, cloud, robot, drone, human workflow, and sub-agent-as-actuator
   calls require typed proposals, verification, idempotency, receipts, and
   outcome evidence.
6. **Feedback is not reward; reward is not evaluation; evaluation is not
   promotion.** Every conversion is versioned, attributable, independently
   gateable, and linked to source evidence.
7. **Training publishes candidates only.** No trainer, optimizer, improvement
   agent, or candidate may activate a model, code, route, policy, data, world,
   or agent revision.
8. **Neuro-symbolic is runtime structure.** Neural decisions, symbolic
   composition/constraints, boundary verification, and feedback/reward are
   explicit cooperating paths, not a marketing label or mandated algorithm.
9. **Physical safety remains local where latency demands it.** Splendor governs
   high-level physical actions and orchestration; it does not replace firmware,
   motor control, hard-real-time loops, or certification.
10. **Self-evolution is proposal plus evidence plus controlled deployment.** It
    is never in-place self-modification or self-approval.

---

## 4. Kernel, adapter, and user-space boundary

### 4.1 Kernel/core owns control contracts

Kernel-space code owns:

- identity and immutable object grammar;
- authority, delegated scope narrowing, work orders, approval requirements,
  data-use grants, and secret-reference semantics;
- state machines for workloads, agents, feedback, reward, eval, training,
  changes, gates, deployments, incidents, and physical interventions;
- gateway and driver invocation protocol, verifier chains, receipts,
  idempotency, quotas, and effect certainty;
- event, state, evidence, replay, audit redaction, and observability contracts;
- scheduling, placement, resource leases, node/fleet status, fencing, and
  recovery;
- compatibility facades from 0.1 primitives into v2 contracts.

### 4.2 Adapters own provider/framework/hardware specifics

Adapters live on top of the core boundary. They implement provider, framework,
hardware, sandbox, model, trainer, evaluator, data, actuator, perceptor,
secret-provider, artifact-store, observability-exporter, cloud, Kubernetes,
Docker, ROS/device, and PyTorch specifics.

Adapters must not:

- execute side effects outside the gateway/driver boundary;
- issue authority, approvals, data-use grants, or deployment activations;
- persist service-owned state machines as shadow owners;
- treat provider success as kernel evidence unless a receipt and event/evidence
  path records it;
- smuggle credentials, authority, data-use, or gate semantics through arbitrary
  JSON, prompts, metadata, or `extensions`.

### 4.3 User-space owns algorithms and domain behavior

User-space code may compute, propose, plan, train, evaluate, simulate, and
transform data, but it does not commit privileged runtime facts. User-space
owns model architectures, optimizers, losses, planners, solvers, ontologies,
reward functions, evaluator math, data transforms, domain policy, and
application behavior.

User-space returns proposals, outputs, artifacts, metrics, reports, or candidate
refs. Kernel services decide whether those can become state commits, evidence,
capabilities, eval reports, candidates, gate decisions, deployments, or incidents.

---

## 5. Package responsibility map for v2

Use the catalog package map unless an accepted RFC changes it.

```text
crates/splendor-types      behavior-free IDs, schemas, enums, receipts, serialization
crates/splendor-kernel     composition root, invariant wiring, local compatibility facade
crates/splendor-authority  identity registry, authority service, secret broker, data-use controller
crates/splendor-artifacts  artifact registry and lineage semantics
crates/splendor-evidence   event log, state service, evidence, replay/simulation, observability export
crates/splendor-fabric     node agent, fleet scheduler, workload controller
crates/splendor-gateway    driver registry and verified driver invocation boundary
crates/splendor-agent      agent registry, instances, routes, world state, messages, delegation
crates/splendor-learning   collection, feedback, reward, eval, training, improvement
crates/splendor-change     changes, gates, deployment, rollback, incidents
crates/splendor-store      persistence traits/engines only; no policy or lifecycle decisions
crates/splendor-daemon     authenticated API translation and process composition
crates/splendorctl         operator/developer CLI over public services
binaries/splendor-node     resident node execution host, cache, safety, fleet protocol
python/splendor            generated clients and user-space authoring hooks
splendor-train             user-space training ergonomics and framework adapters
typescript/packages/*      generated control/inspection/UI clients only
adapters/*                 provider/framework/hardware/sandbox/data/model/driver implementations
```

Do not put PyTorch, Kubernetes, Docker, robotics SDKs, model providers,
optimizers, reward algorithms, domain ontologies, or product-specific workflows
inside core crates.

---

## 6. How to take a v2 task

Every v2 issue/branch/PR must start from the catalog, not from vague sprint
names.

1. Identify the exact catalog task ID, e.g. `FND-001`, `IDR-003`, `DGW-007`,
   `TRAIN-014`, `GATE-006`, or `INT-001`.
2. Read the full task section in
   `/docs/rules/v2/catalog/complete_implementation_task_catalog.md`.
3. Cross-check the structured record in
   `/docs/rules/v2/catalog/architecture/implementation_tasks.yaml`.
4. Read the owning component section and completion gate. Components aggregate
   tasks; they do not replace task-level implementation evidence.
5. Read every required dependency/collaborating task named by the catalog.
6. Read every referenced gold case in
   `/docs/rules/v2/gold/gold-examples-catalog.md` and, when present,
   `docs/rules/v2/gold/examples/catalog.yaml`.
7. State the kernel/user-space/adapter boundary for the task.
8. State non-goals and anti-drift boundaries exactly enough that reviewers can
   detect scope creep.
9. Implement the smallest slice that satisfies the task without fake wiring,
   shadow ownership, or docs-only evidence.
10. Retain validation output and update docs/examples only when behavior truly
    changes.

### GitHub tracking rule

Catalog tracking must be task-granular:

- create or maintain **one issue/sub-issue per catalog task**;
- component issues, when used, are aggregation checklists for their task issues
  and gold evidence, not substitutes for task issues;
- each task issue must include task ID, component/program, owner package,
  required implementation, anti-drift boundaries, integration obligations,
  validation/definition of done, dependencies, and gold IDs;
- do not close a task issue until the implementation evidence required by that
  task exists and is linked.

---

## 7. Gold examples and evidence

Gold examples are executable contracts, not demos and not docs-only checklists.

Every gold case `G00`–`G89` pins a behavior class, acceptance target, and
graduation expectation. A primitive is not kernel-grade until representative
gold examples pass through CI or retained conformance evidence.

Rules:

- task issues list required gold IDs as evidence targets;
- a skipped gold case is `not_exercised`, never passed;
- `specified_not_implemented` is not a pass status;
- catalog validation only proves the catalog is internally consistent;
- do not claim broad compatibility from one happy-path example;
- gold evidence must include positive, denial/failure, replay/simulation, trace,
  state/evidence, cleanup, and compatibility assertions where relevant.

---

## 8. Non-negotiable safety invariants

These block merge if violated.

### 8.1 No side-effect bypass

No side-effectful operation may bypass the gateway/driver boundary. Side effects
include filesystem writes, network calls, database mutations, shell commands,
Kubernetes/cloud operations, ticket/email/webhook calls, artifact publication,
credential use, external service mutation, sub-agent-as-actuator calls, and
robot/device actions.

Read-only operations still require mediation when they touch protected data,
credentials, network, filesystem, tenant resources, external systems, protected
evals, secret refs, device-local safety facts, or privileged artifacts.

### 8.2 Verification before execution

Required verifier categories include tenant, principal/caller identity, work
order, authority/capability, adapter/driver, quota/resource, precondition,
data-use, filesystem/network, secret lease, approval, safety, policy TTL,
postcondition, and compatibility/maturity checks where applicable.

If a required verifier cannot run, fail closed: deny, pause, quarantine, or
request intervention. Never convert uncertainty into allow.

### 8.3 Trace/event/evidence is runtime contract

Meaningful transitions must emit durable events/evidence. At minimum, agent
ticks preserve the stable trace line:

```text
tick.started
percepts.received
state.loaded
policy.invoked
policy.completed
actions.proposed
constraints.evaluated
verification.started
verification.completed
action.executed | action.denied | action.failed | action.needs_approval
outcome.recorded
state.committed
tick.completed
```

v2 workload, driver, artifact, data-use, secret, feedback, eval, training,
candidate, change, gate, deployment, rollback, incident, migration, replay, and
physical-safety transitions must also be event/evidence-linked.

### 8.4 State is explicit, versioned, and owned

Do not introduce hidden mutable state that affects runtime behavior without a
state commit, state reference, artifact ref, evidence bundle, or service-owned
state-machine transition. Only one owner may mutate a state head or lifecycle
concept at a time.

### 8.5 Replay/simulation must not cause live side effects by default

Replay is inspect-only unless explicitly configured for safe simulation or
read-only re-evaluation. Any replay/simulation mode that can touch an external
system must be separately authorized, trace/evidence-linked, and off by default.

### 8.6 Identity separation is mandatory

Do not overload IDs. Keep these distinct:

```text
principal_id tenant_id fleet_id node_id instance_id device_id agent_id
runtime_context_id run_id tick_id workload_id attempt_id worker_id lease_id
action_id invocation_id state_node_id event_id evidence_id message_id
work_order_id approval_id artifact_id dataset_id model_id checkpoint_id
eval_id feedback_id reward_id change_id gate_id deployment_id incident_id
```

### 8.7 No permission or authority laundering

Messages, prompts, metadata, extensions, feedback, reward, evidence,
observability payloads, artifact refs, data refs, model outputs, evaluator
reports, and sub-agent responses are not authority. Delegation must be scoped by
principal, work order, capability, allowed actions/drivers/adapters, data refs,
quotas, expiry, audience, and trace/evidence linkage.

### 8.8 Secure daemon/node communication

Every non-dev request to a daemon, sidecar, node, or manager requires
authenticated caller identity, tenant/fleet binding, endpoint scope, expiry,
audience binding, revocation path, and audit attribution. Caller auth does not
replace signed work orders; signed work orders do not replace gateway
authorization; gateway authorization does not replace adapter/driver receipts.

Local insecure mode is allowed only when explicit, loopback/Unix-socket local,
visibly warned, and impossible to use for fleet/remote/resident-node production.

### 8.9 Physical systems boundary

Splendor governs high-level physical actions and mission orchestration. It must
not replace real-time controllers, firmware safety, motor control, flight
controllers, PLCs, collision avoidance, hard-real-time loops, or certification.
Local safety veto remains authoritative where latency demands it.

---

## 9. Implementation and PR contract

Every issue/PR must include:

```md
## v2 scope
- Catalog task IDs:
- Component/program:
- Plane:
- Owner package:
- Dependencies/collaborators:
- Gold IDs:

## Boundary
- Kernel-owned semantics:
- Adapter/provider responsibilities:
- User-space algorithm responsibilities:
- Explicit non-goals:

## Runtime invariants
- Side effects remain gateway/driver mediated.
- Required verifiers fail closed.
- Events/evidence prove meaningful transitions.
- State/lifecycle ownership is explicit.
- Replay/simulation has no live side effects by default.
- IDs remain distinct.
- Delegation cannot launder authority.
- Physical boundaries remain high-level and local-safety-aware.

## Evidence
- Positive path:
- Denial/failure path:
- Replay/simulation path:
- Trace/event/evidence path:
- State/artifact/lineage path:
- Compatibility/migration path:
- Gold/conformance path:
- Docs/examples updated:
```

Do not merge a PR that cannot truthfully complete this contract or explain why
the incomplete part is intentionally deferred behind an explicit issue.

---

## 10. Validation expectations

Choose the strongest relevant local and CI gates. Important v2 tasks generally
need more than a happy-path unit test.

Use, as applicable:

- unit tests for pure types and state machines;
- integration tests through daemon/service/gateway boundaries;
- denial, revocation, wrong-audience, quota, stale-head, and fail-closed tests;
- fault injection for crash, timeout, duplicate delivery, disk full, corrupt
  artifact, stale lease, process death, and clock skew;
- replay/simulation no-live-effect tests;
- trace/event/evidence completeness assertions;
- artifact/lineage/redaction/access tests;
- mixed-version and migration tests;
- driver conformance and maturity tests;
- gold example execution or explicit `not_exercised` evidence;
- performance/SLO tests where the catalog demands budgets.

Docs-only changes are allowed only when the task is explicitly docs/RFC/planning
work. Docs-only changes must never claim implemented runtime behavior.

---

## 11. PyTorch and learning compatibility

Use the catalog compatibility tiers exactly:

```text
T0 opaque: reproduce locked single-process workload; schedule independent trials/data/eval fan-out.
T1 torchrun-compatible: form worker group, rendezvous, launch, fence epochs, checkpoint/restart, account work.
T2 structured hooks: wrap declared model/data/optimizer/step/checkpoint hooks with supported providers.
T3 explicit parallel plugin: orchestrate signed custom/federated/tensor/pipeline/expert plugin.
```

Do not claim automatic gradient/state distribution, universal source rewriting,
unchanged numerical behavior, or arbitrary heterogeneous collective semantics
without evidence for the exact tier and plugin.

Training publishes candidates only. Evaluation and gates decide whether a
candidate can be promoted; deployment activates only after gates and rollout
controls pass.

---

## 12. Final implementation rule

When in doubt, choose the design that is:

```text
catalog-grounded over vague
kernel-routed over bypassed
explicit over magical
trace/evidence-backed over optimistic
fail-closed over permissive
one-owner over shadow semantics
adapter/user-space freedom over core pollution
schema-stable over fast-changing
gold-proven over docs-claimed
small and composable over broad and clever
```

Splendor v2 must make autonomy, learning, fleet execution, physical action, and
self-evolution auditable, governable, replayable, safely executable, and
interoperable without dictating the AI stack.
