> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# External Entity Contracts

This document states exactly what each external party gives Splendor, what Splendor gives back, and which assumptions are forbidden.

## 1. Application/product code

**Provides**

- tenant and agent declarations;
- objectives, UX, schedules, and work orders;
- domain-specific agent code;
- allowed risk, data, cost, and deployment policy;
- optional human review interfaces.

**Receives**

- agent/run/workload lifecycle;
- typed events, state heads, and outcomes;
- denials and approval requirements;
- artifacts, eval reports, and deployment status;
- causal evidence and incident records.

**Must not assume**

- model success implies authorization;
- hidden shared state;
- direct tool/device access;
- candidate training output becomes active automatically.

## 2. Agent frameworks, planners, and custom architectures

**Provides**

- arbitrary imperative or declarative reasoning;
- prompts, planners, solvers, critics, memory logic, route logic, and sub-agent orchestration;
- typed proposals and state-update requests;
- optional route descriptions.

**Receives**

- percept streams;
- world/state snapshots;
- model/driver invocation handles;
- budgets, deadlines, and capability context;
- proposal/gate APIs;
- trace/evidence hooks.

**Boundary**

Framework code may compute freely inside its workload. It cannot commit governed state, delegate authority, activate components, or execute external effects without kernel operations.

## 3. Model providers and custom neural networks

**Provides**

- `ModelDriver` manifest and implementation;
- model artifact compatibility;
- session/inference/scoring/embedding operations;
- streaming, cancellation, telemetry, and retention semantics;
- runtime and accelerator requirements.

**Receives**

- exact model artifact and invocation contract;
- scoped input artifacts/state;
- inference parameters and output schema;
- latency/compute/cost/data-use budgets;
- secret leases when required.

**Boundary**

The provider cannot retain or train on data unless the data-use grant permits it. Model output cannot grant authority or mutate the active bundle.

## 4. Training systems and algorithm authors

**Provides**

- `TrainerDriver` or hermetic workload entrypoint;
- algorithm/code/environment artifacts;
- compatible distribution/checkpoint semantics;
- metrics and candidate outputs;
- reproducibility declarations.

**Receives**

- frozen dataset snapshots;
- base model/checkpoint artifacts;
- worker/rank/rendezvous context;
- resource leases;
- checkpoint and output publication services;
- event/metric sinks.

**Boundary**

Training may generate candidates. It cannot read protected eval cases, broaden data use, grant capabilities, or deploy its output.

## 5. Data-source owners and data operators

**Provides**

- source identity, ownership, license/consent, sensitivity, residency, and allowed use;
- collection/data-operator drivers;
- transform, labeling, quality, and contamination implementations.

**Receives**

- collection plans and budgets;
- scoped source credentials;
- output schemas and artifact publication;
- lineage/event APIs;
- quarantine and deletion instructions.

**Boundary**

Transforms cannot broaden allowed use or erase provenance. Mutable sources must become immutable snapshots before ordinary training/eval use.

## 6. Evaluators, red teams, and reward systems

**Provides**

- eval suites, cases/generators, metrics, environment, and evaluator drivers;
- protected-case handling;
- report signatures/attestations where required;
- reward derivation artifacts.

**Receives**

- subject/baseline artifacts;
- isolated eval workloads;
- protected data access unavailable to training/candidates;
- report publication and evidence APIs.

**Boundary**

Evaluators measure; promotion policies decide. Reward systems cannot silently replace hard constraints or approvals.

## 7. Humans and governance systems

**Provides**

- feedback, corrections, demonstrations, approvals, denials, appeals, value policies, incident disposition, and change review;
- identity and signature/attestation.

**Receives**

- explanation/evidence bundle;
- exact proposal or changeset diff;
- risk and blast-radius classification;
- relevant alternatives and uncertainties;
- rollout/rollback options;
- accountable audit record.

**Boundary**

Human approval is a scoped input to a gate, not a gateway bypass. Approval expires and can be revoked.

## 8. Fleet nodes and cloud workers

**Provides**

- authenticated node identity;
- driver/runtime versions;
- static capabilities and short-lived resource offers;
- health, utilization, headroom, locality, and connectivity;
- lease and workload status;
- artifact/event synchronization.

**Receives**

- signed workload/lease assignments;
- artifact references and scoped data/secrets;
- placement, checkpoint, preemption, and cancellation instructions;
- policy/value/revocation updates.

**Boundary**

Node registration is not permission to execute arbitrary tenant work. Expired leases stop new privileged operations.

## 9. Physical devices and robots

**Provides**

- device identity and hardware/driver manifests;
- local sensor/perceptor events;
- local safety state and evidence;
- actuator outcomes;
- offline trace/artifact buffer;
- emergency-stop status.

**Receives**

- signed bounded work orders;
- high-level action proposals;
- model/code/container workloads compatible with the device;
- local policy/value/safety artifacts with TTL;
- sync/revocation instructions.

**Boundary**

Device-local safety has final veto. Cloud helper computation cannot acquire direct raw actuator authority.

## 10. Shell, Python, OCI, and Kubernetes executors

**Provides**

- sandbox/executor driver manifest;
- isolation, resource, network, mount, device, lifecycle, and cancellation semantics;
- status/log/output collection;
- environment/image attestation.

**Receives**

- workload entrypoint and immutable environment ref;
- scoped mounts, network, secrets, devices, and resources;
- output contract;
- timeout/cancellation and evidence requirements.

**Boundary**

The executor runs code; it does not decide agent authority, data use, promotion, or physical safety.

## 11. Observability, security, and compliance systems

**Provides**

- monitoring/evidence consumers;
- alert and incident policies;
- retention, privacy, security, and compliance controls;
- scanners and external attestations.

**Receives**

- event/trace streams;
- causal queries;
- artifact and data lineage;
- capability/gate/approval records;
- deployment and incident state;
- quality/eval/training reports.

**Boundary**

Observability cannot mutate runtime behavior except by creating explicit incident, circuit-breaker, governance, or change operations.

## 12. Minimum SDK expectations

A higher-level SDK should expose coherent namespaces rather than one overloaded runtime object:

```text
splendor.identity
splendor.artifacts
splendor.events
splendor.state
splendor.workloads
splendor.drivers
splendor.agents
splendor.data
splendor.feedback
splendor.evals
splendor.training
splendor.change
splendor.fleet
splendor.devices
```

The namespaces compile to the small semantic kernel service surface defined in `01_core_abstractions.md`.
