> **Status:** Active 0.2/v2 architecture rule source. This file guides 0.2/v2 decomposition after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements the described behavior.

# Core Abstractions and State Machines

This document is the normative conceptual model for 0.2/v2. Domain subsystems should reuse these objects instead of inventing parallel identity, scheduling, artifact, or lifecycle mechanisms.

## 1. Design rules

### 1.1 Few generic primitives, rich typed profiles

The kernel should standardize a compact substrate. AI-specific concepts are schema profiles with additional invariants. For example, a checkpoint is an artifact profile; training is a workload profile; feedback is an event profile; activation is a change/deployment transition.

### 1.2 Immutable facts, explicit mutable heads

Artifacts and events are immutable. Mutable concepts—active policy, world state, current model, deployment status—are represented by versioned heads pointing to immutable revisions. Every head move is an atomic `StateCommit` or `DeploymentTransition`.

### 1.3 Separate computation from authority

Successful computation does not grant permission. A model output, training result, evaluator score, human note, or planner proof is evidence. Authority comes only from scoped grants and gate decisions.

### 1.4 Separate candidate production from activation

Any process may produce a candidate artifact if authorized to use the inputs and resources. Only the change plane may activate it.

### 1.5 Describe failure before success

Every object that can execute or mutate declares timeout, cancellation, retry, idempotency, checkpoint, rollback/compensation, and fail-closed behavior. “Best effort” is a policy value, not an undocumented default.

## 2. Foundational object catalog

### 2.1 `Principal`

An authenticated identity that can own, request, approve, execute, or observe work.

```text
PrincipalKind = tenant | agent | human | service | node | device | governance_authority
```

Required semantics:

- globally unambiguous ID within its trust domain;
- issuer and authentication method;
- status: active, suspended, revoked;
- no implicit authority from kind or parentage;
- node and device identities are not agent identities;
- human identity is not approval by itself.

### 2.2 `Scope`

The immutable security and ownership coordinates for an operation.

```text
Scope {
  tenant_id
  agent_id?
  agent_instance_id?
  run_id?
  workload_id?
  node_id?
  device_id?
  data_domains[]
  environment
}
```

A child scope may narrow but never silently broaden its parent. All privileged objects carry a scope or a stable reference to one.

### 2.3 `CapabilityGrant`

A signed, revocable grant that authorizes operations over resources.

```text
CapabilityGrant {
  grant_id
  subject: PrincipalRef
  scope: Scope
  operations[]
  resources[]
  data_use[]
  constraints[]
  budget
  not_before
  expires_at
  delegation_depth
  issuer
  signature
  revocation_ref
}
```

Capabilities are checked at invocation time, not only when a run starts. Cached grants have TTL and degraded-mode rules.

### 2.4 `ArtifactRef` and `ArtifactManifest`

An immutable, content-addressed object. The reference is small; the manifest carries metadata and lineage.

```text
ArtifactRef {
  artifact_id       # digest or digest-bound ID
  media_type
  schema
  size_bytes?
  storage_locations[]
}
```

```text
ArtifactManifest {
  ref
  artifact_kind
  created_by
  created_at
  lineage_parents[]
  code_ref?
  environment_ref?
  data_use_grants[]
  classification
  retention
  encryption
  signatures[]
  extensions
}
```

Artifact kinds include model, model adapter, checkpoint, dataset snapshot, data shard, code bundle, environment image, policy bundle, value spec, route spec, eval suite, eval report, data quality report, contamination report, world snapshot, state snapshot, trace segment, and evidence bundle.

### 2.5 `EventEnvelope`

An append-only causal fact. Large payloads are referenced as artifacts rather than embedded.

```text
EventEnvelope {
  event_id
  schema
  scope
  kind
  producer
  occurred_at
  recorded_at
  causal_parents[]
  correlation_refs[]
  payload_ref? | inline_payload?
  integrity
}
```

Examples: percept received, route step, model invocation, proposal created, gate decision, driver outcome, state committed, feedback recorded, eval completed, checkpoint written, deployment changed, incident opened.

### 2.6 `StateCommit`

An atomic compare-and-swap transition for a named state partition.

```text
StateCommit {
  commit_id
  partition_id
  expected_parent
  next_artifact
  writer
  reason_event
  merge_policy
  created_at
}
```

The commit fails if the expected parent is no longer current unless an explicit merge policy resolves the conflict. There is no hidden in-place mutation.

### 2.7 `WorkloadSpec`

A schedulable computation. Detailed fields are in `03_execution_fabric.md` and the JSON schema.

Core invariant: the scheduler understands resource and lifecycle semantics without needing to understand optimizer mathematics, model architecture, or domain logic.

### 2.8 `ExecutionLease`

A short-lived reservation binding a workload attempt to concrete resources and authority.

```text
ExecutionLease {
  lease_id
  workload_id
  attempt
  node_ids[]
  resource_allocations[]
  capability_grants[]
  secret_leases[]
  starts_at
  expires_at
  renewal_policy
  preemption_policy
}
```

A lease is not a capability to perform arbitrary operations. It grants only the operations declared by the workload and accepted by admission control.

### 2.9 `DriverManifest`

A signed declaration of operations and semantics for a provider. It is covered in `04_drivers_sandboxes_physical.md`.

### 2.10 `Invocation`

One call to one declared driver operation.

```text
Invocation {
  invocation_id
  workload_id
  attempt
  driver_ref
  operation
  input_refs[]
  inline_input?
  output_contract
  scope
  capability_refs[]
  lease_id
  deadline
  idempotency_key?
  trace_context
}
```

The driver returns `accepted`, `running`, `succeeded`, `failed`, `denied`, `cancelled`, `timed_out`, or `uncertain`. “Uncertain” is explicit because an external effect may have occurred even when confirmation failed.

### 2.11 `Proposal`

A request for an externally visible or governed mutation. A proposal contains intent and evidence but no authority to execute.

Profiles:

- `ActionProposal`
- `StateMutationProposal`
- `DelegationProposal`
- `DataUseProposal`
- `ChangeProposal`
- `PhysicalActionProposal`
- `GovernanceProposal`

```text
Proposal {
  proposal_id
  profile
  scope
  proposer
  requested_operation
  inputs[]
  expected_effects[]
  risk_class
  evidence_refs[]
  reversibility
  deadline
}
```

### 2.12 `GateDecision`

A deterministic, inspectable decision over a proposal and evidence set.

```text
GateDecisionStatus = allow | deny | require_approval | defer | quarantine
```

```text
GateDecision {
  decision_id
  proposal_id
  status
  policy_refs[]
  verifier_results[]
  reasons[]
  obligations[]
  approval_requirements[]
  expires_at
  signature
}
```

An obligation is explicit, such as “execute only in simulation,” “redact field X,” “canary at 1%,” or “local human presence required.” Gates do not silently rewrite the proposal.

### 2.13 `ChangeSet`

A content-addressed diff between two agent bundle revisions.

```text
ChangeSet {
  change_set_id
  base_bundle
  candidate_bundle
  changes[]
  risk_class
  expected_benefits[]
  known_risks[]
  evidence_bundle
  rollback_target
  proposer
}
```

Change entries identify exact components: model, adapter, route, prompt, code, rules, value spec, world schema, data policy, eval policy, driver, or resource policy.

### 2.14 `DeploymentPlan`

A stateful activation policy.

```text
DeploymentMode = shadow | canary | progressive | full | offline_only
DeploymentState = proposed | gated | scheduled | shadowing | canarying | promoting |
                  active | paused | quarantined | rolling_back | rolled_back | failed | retired
```

The plan declares traffic/device cohorts, duration, monitoring windows, success criteria, stop conditions, maximum blast radius, and rollback target.

### 2.15 `EvidenceBundle`

A manifest of evidence, not a blob. It may reference:

- trace ranges and causal query results;
- data quality and contamination reports;
- training metrics and checkpoint lineage;
- eval reports and statistical comparisons;
- red-team and safety cases;
- approvals and denials;
- deployment observations;
- incident records;
- environment and code attestations.

## 3. Domain profiles

### 3.1 Agent profiles

- `AgentSpec` — desired declarative composition and control policy.
- `AgentInstance` — running realization on one or more nodes.
- `AgentBundle` — immutable set of component refs activated as a revision.
- `Delegation` — bounded authority for a sub-agent.
- `RouteSpec` — optional static description of possible route steps.
- `RouteStepEvent` — actual dynamic route execution.

### 3.2 World and memory profiles

- `StatePartitionSpec` — schema, writers, readers, retention, consistency, locality.
- `WorldModelSpec` — named state partitions and update/read interfaces.
- `WorldSnapshot` — immutable snapshot of one or more partitions.
- `BeliefUpdateProposal` — proposed update with evidence and uncertainty.

The kernel does not require a particular ontology. It requires typed versioned partitions and provenance.

### 3.3 Data profiles

- `DataSourceSpec`
- `CollectionPlan`
- `DataRecordRef`
- `DatasetSnapshot`
- `DataTransformSpec`
- `DataQualityPolicy`
- `DataQualityReport`
- `ContaminationPolicy`
- `ContaminationReport`
- `AnnotationTask` and `AnnotationRecord`
- `DataUseGrant`
- `DataDeletionRecord`

### 3.4 Learning profiles

- `FeedbackRecord`
- `RewardDerivation`
- `EvalSuite`
- `EvalCaseRef`
- `EvalRun`
- `EvalReport`
- `TrainingPlan`
- `TrainingRun`
- `Checkpoint`
- `CandidateBundle`
- `PromotionPolicy`

### 3.5 Driver profiles

- `PerceptorDriver`
- `ActuatorDriver`
- `ModelDriver`
- `TrainerDriver`
- `EvaluatorDriver`
- `DataOperatorDriver`
- `SandboxDriver`
- `ExecutorDriver`
- `DeviceDriver`
- `SecretProviderDriver`

All profiles use one registration and invocation lifecycle.

## 4. Canonical state machines

### 4.1 Workload state

```text
created -> validated -> queued -> admitted -> leased -> starting -> running
running -> checkpointing -> running
running -> succeeded | failed | cancelled | timed_out | preempted | uncertain
preempted -> queued | failed
failed -> queued (new attempt) | terminal_failed
```

Rules:

- attempt IDs are immutable;
- retries never overwrite prior outcomes;
- a preemptible workload must declare checkpoint or restart behavior;
- `uncertain` blocks automatic retry for non-idempotent effects until reconciled.

### 4.2 Driver invocation state

```text
proposed -> gated -> submitted -> accepted -> running -> terminal
terminal = succeeded | failed | denied | cancelled | timed_out | uncertain
```

Cancellation is a request, not proof that execution stopped. Drivers report cancellation confirmation separately.

### 4.3 Dataset state

```text
source_registered -> collecting -> materializing -> quarantined
quarantined -> quality_checked -> contamination_checked -> approved
approved -> frozen -> used
any pre-frozen state -> rejected
frozen -> deprecated | deletion_pending
```

Training and protected evaluation consume only frozen snapshots unless a policy explicitly allows streaming online-learning data.

### 4.4 Training state

```text
planned -> validated -> queued -> running -> checkpointed* -> completed
completed -> candidate_built -> evaluating -> accepted | rejected | more_evidence
```

Training completion is not deployment success.

### 4.5 Change and deployment state

```text
change_proposed -> evidence_ready -> gated
                         |-> denied
                         |-> approval_required
                         |-> shadow
shadow -> canary -> progressive -> active
any rollout state -> paused | quarantined | rolling_back -> rolled_back
```

### 4.6 Agent instance state

```text
registered -> provisioning -> starting -> healthy
healthy -> degraded | paused | migrating | draining | quarantined | stopping
migrating -> healthy | degraded | failed
stopping -> stopped -> retired
```

A 24/7 agent is not an infinite `while` loop. It is a supervised instance with health, leases, checkpoints, state ownership, failover, and deployment revision.

## 5. State partition taxonomy

To remove ambiguity, state is divided by control semantics rather than by storage technology.

| Partition | Purpose | Typical writer | Rollback rule |
|---|---|---|---|
| `runtime_control` | lifecycle, cursors, leases, health | kernel only | kernel-managed |
| `world_model` | beliefs and environment representation | authorized agent route | versioned, merge-aware |
| `episodic_memory` | ordered experiences | collection/memory code | retention and redaction aware |
| `semantic_memory` | curated knowledge | data/knowledge workloads | artifact versioning |
| `task_state` | goals, plans, progress | agent code | work-order scoped |
| `conversation_state` | user/session interaction | app/agent | privacy and TTL scoped |
| `policy_state` | active bundle and route version | change plane only | deployment rollback |
| `learning_state` | training cursors, optimizer/checkpoint refs | trainer driver | checkpoint lineage |
| `private_scratch` | ephemeral computation | workload | non-durable by default |
| `secrets` | credentials | secret broker only | never normal state |

## 6. Minimal kernel service surface

The public API can be ergonomic, but the semantic operations should remain small:

```text
register_principal
issue_or_revoke_capability
register_artifact
append_event
commit_state
register_driver
submit_workload
renew_or_release_lease
invoke_driver
create_proposal
evaluate_gate
record_feedback
submit_eval
submit_training
create_change_set
start_deployment
transition_deployment
query_evidence
```

Higher-level SDK methods compile to these operations. This mirrors how many rich user-space libraries eventually cross a small set of OS syscalls.

## 7. Error taxonomy

Every API returns stable machine-readable codes with structured context.

- `INVALID_SCHEMA`
- `UNKNOWN_IDENTITY`
- `SCOPE_MISMATCH`
- `CAPABILITY_MISSING`
- `CAPABILITY_EXPIRED`
- `DATA_USE_DENIED`
- `RESOURCE_UNAVAILABLE`
- `INTERFERENCE_BUDGET_EXCEEDED`
- `DRIVER_INCOMPATIBLE`
- `GATE_DENIED`
- `APPROVAL_REQUIRED`
- `STATE_CONFLICT`
- `CHECKPOINT_REQUIRED`
- `NON_IDEMPOTENT_RETRY_BLOCKED`
- `PROTECTED_EVAL_ACCESS_DENIED`
- `CONTAMINATION_POLICY_FAILED`
- `DEPLOYMENT_STOP_CONDITION`
- `PHYSICAL_SAFETY_DENIED`
- `OUTCOME_UNCERTAIN`

Human-readable messages are supplementary. Code must not branch on free-form text.

## 8. Compatibility and evolution

- Serialized objects carry schema version and profile version.
- Additive optional fields are permitted only when non-authorizing.
- Authority, safety, data use, and deployment behavior cannot be changed through opaque extensions.
- Driver compatibility is negotiated from manifest capabilities, schema ranges, and runtime ABI version.
- Stable IDs remain distinct; aliases are migration-only.
- New profile kinds require an RFC, conformance fixtures, and migration semantics.
- Unknown privileged profile kinds fail closed.

## 9. Why this object model scales

The same primitives handle:

- one local agent and a 1,000-node fleet;
- a synchronous inference call and a month-long training run;
- an HTTP request and a drone mission;
- a fixed rule policy and a custom neural architecture;
- a human annotation and an automated evaluator;
- a prompt edit and a base-model replacement;
- deterministic replay and live online adaptation.

The differences live in profiles and policies, not in parallel control planes.
