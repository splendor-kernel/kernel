# RFC 0008 - vNext Data-Use Controller

## Status and Scope

Status: Draft.

Scope: vNext proposal for issue #155. This RFC is non-normative until accepted
and implemented. It does not change current daemon behavior, work-order schemas,
OpenAPI schemas, SDKs, generated artifacts, stable 0.1 references, gateway
behavior, verifier behavior, trace formats, state formats, replay semantics,
data storage, training, evaluation, lineage, retention, or deletion behavior.

Milestone and sprint alignment:

- Milestone: post-0.1 RFC required.
- Current tie-ins: `0.03-S3 - Signed work orders`, `0.04-S5 - Central policy
  distribution`, later data/learning-control RFCs.
- FRs: `FR-0.03-04`, `FR-0.04-08`, `FR-0.1-08`.
- vNext planning refs: `DUC-001` through `DUC-007`.
- Related parent issue: #140.

This document proposes the data-use controller semantics that future
implementation work can map into authority decisions, work orders, artifact
manifests, collection records, training and evaluation controllers, gateway
verifiers, trace/evidence records, replay explanations, conformance fixtures,
and documentation. It intentionally does not present planned vNext behavior as
implemented behavior.

## Motivation

Splendor already models tenants, work orders, policies, gateway verification,
trace events, replay, and locality hints. Those controls are not enough to
answer a separate question: what may this exact data be used for?

The current planning baseline explicitly notes that tenants and work orders can
carry `data_refs`, and placement can carry locality hints, but the kernel does
not yet model collection consent/license, purpose limitation, retention,
training versus evaluation use, derived-data obligations, subject deletion, or
protected-holdout access.

That gap matters because readable data is not automatically trainable,
exportable, retainable, publishable, or usable for protected evaluation. A
future controller needs to separate read authority from purpose-scoped use
authority without turning the kernel into a legal-policy engine, data curation
system, training framework, or evaluation framework.

The vNext data-use controller should make data decisions explicit enough for:

- ordinary inference against permitted context;
- data collection and persistence;
- labeling, deduplication, transformation, and dataset preparation;
- feedback and reward derivation;
- training and tuning;
- protected and non-protected evaluation;
- export, publication, sharing, and incident analysis;
- retention, deletion, derivation impact, and locality rules;
- replay and policy simulation that explain decisions without granting access.

## Primitive Affected

This RFC strengthens the following primitives at the proposal level only:

- verifier;
- work order;
- gateway;
- trace/evidence;
- replay;
- governance;
- docs/tests.

It also affects compatibility planning for future artifact, lineage, collection,
feedback, reward, evaluation, training, fleet, node-agent, sandbox, and
authority-service updates.

## Non-Goals

- No legal-policy engine or jurisdiction-specific legal conclusion in kernel
  docs.
- No runtime permission engine implementation in this RFC.
- No data curation, data cleaning, labeling, training, evaluation, reward,
  lineage, retention, or deletion implementation.
- No OpenAPI, SDK, generated artifact, or stable 0.1 reference change.
- No claim that readable data is trainable, exportable, retainable, publishable,
  or usable for protected evaluation.
- No raw data credentials passed to training, evaluator, agent, policy, or
  adapter code.
- No provider-specific data store, privacy SDK, legal hold product, or data
  catalog product.
- No use of replay, policy simulation, trace export, or audit reports as live
  data-access grants.
- No implementation before accepted RFCs.

## Core Model

The data-use controller answers a purpose-scoped authorization question:

```text
May this requester use these data refs, snapshots, shards, streams, or derived
artifacts for this operation, purpose, workload, audience, locality, retention
plan, and downstream derivation plan at this time?
```

The answer is independent from mere readability. Read access can support
inspection or inference while still denying training, tuning, export,
publication, retention, feedback derivation, reward derivation, protected
evaluation, or incident reuse.

Proposed public contracts:

- `DataClass`
- `DataPurpose`
- `DataUsePolicy`
- `DataUseRequest`
- `DataUseDecision`
- `DataUseGrant`
- `DataAccessLease`
- `RetentionObligation`
- `DeletionImpact`
- `DerivedDataObligation`
- `ProtectedEvaluationAccess`
- `DataUseSimulationReport`

These names are proposal placeholders. Final implementation must version or
migrate schemas through an accepted implementation RFC or schema proposal.

## Data Classification Proposal

Future implementation should support built-in classification labels and custom
policy labels without forcing raw personal content, secret content, or protected
payloads into policy records.

| Class | Proposed meaning | Notes |
| --- | --- | --- |
| `public` | Intended for unrestricted public visibility. | Still may have purpose, license, provenance, or retention limits. |
| `tenant_private` | Visible only within a tenant or explicit sharing boundary. | Tenant visibility is not training authority. |
| `personal` | Associated with an identifiable subject or subject-like record. | Use depends on purpose, consent/license, minimization, and deletion obligations. |
| `sensitive` | Safety, financial, health, private business, location, or comparable sensitive data. | Requires explicit policy and tighter redaction/export rules. |
| `secret` | Credentials, tokens, keys, or secret-like payloads. | Secret values should be handled by secret broker semantics, not by raw data use. |
| `licensed` | Data with contractual/source license restrictions. | Expiry, audience, attribution, and derivative restrictions must be modeled. |
| `synthetic` | Generated or simulated data. | Synthetic status does not automatically remove provenance or privacy obligations. |
| `protected_eval` | Hidden evaluation prompts, answers, judge prompts, scoring code, or protected cases. | Candidate/trainer access is denied except through controlled evaluator protocol. |
| `safety_local` | Physical-device, safety-map, operational, or location data that should remain local by default. | Central sync/export requires explicit policy. |
| `custom_policy_label` | Domain-specific labels supplied by policy artifacts. | Unknown or ambiguous labels fail closed. |

Policy records should reference source, subject, license, consent, provenance,
dataset, shard, stream, artifact, snapshot, and derivation metadata by reference
where possible. They should not copy protected raw payloads into authority,
trace, state, work-order, or public error records.

## Operation and Purpose Separation

The controller must separate operation categories. A grant for one category must
not imply a grant for another.

| Operation | Proposed definition | Must not imply |
| --- | --- | --- |
| `collect` | Acquire or ingest data from a source, stream, user, device, or artifact. | Persistence, training, export. |
| `persist` | Store data beyond transient processing. | Training, retention beyond policy, publication. |
| `inspect` | Human or service read for diagnosis, review, or support. | Training, evaluation, export. |
| `transform` | Normalize, redact, tokenize, convert, summarize, deduplicate, or otherwise derive data. | Publication, training, unrestricted derived use. |
| `label` | Add annotations, judgments, categories, or review outcomes. | Reward derivation, training, evaluator access. |
| `deduplicate` | Compare records to remove or group duplicates. | Leakage-safe grouping or export unless separately granted. |
| `infer` | Use data as runtime context or input for model inference or agent operation. | Training, tuning, retention, evaluation, export. |
| `train` | Use data to update model parameters, adapters, memory, or comparable learned behavior. | Evaluation, deployment, publication. |
| `tune` | Fine-tune, prompt-tune, adapter-tune, preference-tune, or optimize a candidate. | Protected-eval access or production activation. |
| `evaluate` | Measure behavior against cases, suites, or criteria. | Training, promotion, protected answer access. |
| `derive_reward` | Convert feedback, outcomes, labels, or judgments into reward or preference signals. | Training or policy update without a separate grant. |
| `export` | Move data or derived artifacts outside the current runtime/control boundary. | Publication, broad sharing, retained copies. |
| `publish` | Make data, metrics, reports, artifacts, or derived content visible to a wider audience. | Raw export, hidden protected-eval disclosure. |
| `share` | Make data available to another tenant, principal, workload, node, or service. | Cross-tenant persistence or downstream training. |
| `retain` | Keep data or derived artifacts through a retention period. | Use beyond the retention purpose. |
| `delete` | Remove, tombstone, quarantine, revoke, or restrict data and impacted derivatives. | Erasing audit facts needed to prove handling. |
| `incident_analyze` | Use data for bounded incident response, forensics, or remediation. | Training, broad export, indefinite retention. |

Purposes should be versioned policy artifacts with at least:

- purpose ID and version;
- owner/controller;
- allowed operation categories;
- requester and audience bounds;
- data classes and source constraints;
- consent/license/provenance requirements;
- locality and execution-domain requirements;
- retention and deletion obligations;
- derivation and downstream-use obligations;
- protected-evaluation restrictions;
- policy TTL, revocation, supersession, and stale-cache rules.

Vague purpose labels such as `research`, `future use`, `quality improvement`, or
`debugging` should not act as unbounded defaults. They must resolve to explicit
policy artifacts and operation categories before privileged use.

## Data-Use Decisions and Grants

Future implementation should evaluate a `DataUseRequest` against:

- requester principal and authority decision references;
- tenant, agent, run, workload, node, sandbox, evaluator, or trainer identity;
- operation category;
- purpose artifact and version;
- data refs, source selectors, snapshots, shards, streams, or derived artifacts;
- data classes and custom labels;
- source policy, consent, license, provenance, and subject refs;
- audience, tenant, sharing, and export boundary;
- locality and execution trust domain;
- current time, policy TTL, consent/license expiry, and revocation status;
- retention, deletion, and downstream derivation plan;
- protected-evaluation role separation;
- current work-order scope and grant refs.

The result should be one of:

| Result | Required semantics |
| --- | --- |
| `allow` | Exact operation/purpose/data/workload bounds are granted with obligations. |
| `deny` | Use is rejected before data mount, export, persistence, training, evaluation, or side effect. |
| `conditional` | Use may proceed only if obligations such as redaction, aggregation, local execution, human review, evaluator-only lease, deletion propagation, or no-raw-export are satisfied. |
| `needs_intervention` | Human or governance intervention is required; the request does not gain access while pending. |

Grant references should be bounded and auditable:

- immutable data snapshot, shard, stream, source selector, or derived artifact;
- maximum record/time/byte volume where applicable;
- operation and purpose;
- requester, workload, run, node, sandbox, evaluator, or trainer binding;
- audience, locality, and execution-domain constraints;
- retention/deletion/derivation obligations;
- expiry, revocation source, and policy version;
- trace/evidence references and reason codes.

Work orders may carry `data_refs` and grant refs, but `data_refs` alone are not
enough to bypass data-use checks where data use is privileged. A work order
should narrow what a run may attempt; the data-use controller should still
decide whether a specific privileged data use is allowed under current policy.

## Fail-Closed Conditions

The following conditions must deny, pause, or require intervention before
privileged data use:

| Condition | Required behavior |
| --- | --- |
| Missing provenance | Deny privileged use until provenance is supplied or the policy explicitly permits incomplete provenance. |
| Unknown purpose | Deny before use; do not fall back to broad `research`, `debugging`, or `future use`. |
| Ambiguous data class | Deny or route to classification review; do not treat ambiguity as public data. |
| Expired consent/license | Deny new use and evaluate retention/deletion impact. |
| Revoked consent/license/source policy | Deny new use and create impact evidence for affected derivatives. |
| Changed snapshot | Deny existing grants for the new snapshot unless the grant explicitly covers the version change. |
| Locality mismatch | Deny placement, replica, export, or worker selection that violates locality. |
| Protected-eval confusion | Deny when trainer, candidate, agent, policy, or user-provided role text attempts evaluator-only access. |
| Stale policy | Deny high-risk use or follow explicit degraded/offline policy; do not silently broaden permissions. |
| Missing authority decision | Deny; data-use grants do not replace principal/authority checks. |
| Missing work-order compatibility | Deny run/workload use; caller credentials cannot replace work orders. |
| Unknown custom label | Deny until a policy artifact defines the label. |
| Unsatisfied obligation | Deny or pause when redaction, aggregation, locality, retention, review, or deletion obligations cannot be proven. |
| Protected payload leak attempt | Deny, quarantine, or route to intervention without exposing payload in errors. |
| Simulation/replay request asks for live data | Deny; explanation does not grant data access. |

Fail-closed reason codes should be stable and machine-actionable. Human messages
are diagnostics only and must not be parsed as authority or expose protected
payloads.

## Locality, Retention, Deletion, and Derivation

Future implementation should treat locality, retention, deletion, and
derivation as first-class data-use obligations.

Locality planning should support:

- allowed geographic, organizational, tenant, node, sandbox, and device-resident
  execution domains;
- raw-data export prohibition;
- local-only or update-only egress;
- aggregation thresholds and small-cohort leakage controls;
- scheduler predicates and node admission checks derived from grants;
- physical-device trace and sensor sync policies.

Retention planning should support:

- retention deadline and legal/operational hold references;
- retention purpose and maximum retention period;
- payload lifecycle separate from audit/evidence retention;
- explicit handling when data must remain unavailable but audit facts must
  remain provable.

Deletion and derivation impact planning should support:

- source deletion requests and policy revocation;
- impact queries through lineage for raw artifacts, transformed datasets,
  training runs, checkpoints, models, evaluation reports, reward signals, and
  deployments;
- deterministic delete/tombstone/quarantine where possible;
- explicit remediation classes for trained or derived artifacts, such as
  retrain, unlearn by user-space algorithm, restrict, supersede, quarantine, or
  document impossibility;
- no claim of cryptographic deletion from trained models without evidence;
- no erasure of audit facts needed to prove that deletion handling occurred.

## Protected Evaluation

Protected evaluation data needs a stricter role boundary than ordinary
read-protected data.

Future implementation should distinguish:

- evaluation case prompts or inputs;
- answer keys and hidden labels;
- judge prompts, rubric details, scoring code, and secret seeds;
- protected suite identity, version, and digest;
- aggregate and sliced reports safe for release;
- candidate-visible error and feedback surfaces.

Proposed rules:

- Candidate, trainer, policy, or agent code must not receive raw protected
  answers, full hidden case enumeration, judge secrets, or scoring internals.
- Evaluator-only leases should be resolvable only by evaluator-driver identities
  and controlled evaluator protocols.
- Reports should bind to protected suite digests without revealing protected
  payloads.
- Attempts to copy, log, embed, cache, export, or include protected payloads in
  candidate artifacts must deny, quarantine, or require intervention.
- Candidate-selected evaluators cannot satisfy independent gates by themselves.
- Public benchmarks are not protected-eval data merely because they are stored
  in a separate directory.

Protected-eval access confusion is a fail-closed condition. Role text supplied
by user code, trainer code, or candidate artifacts must not become evaluator
authority.

## Work Orders, Authority, and Gateway Interaction

Data-use decisions compose with existing Splendor authority layers. They do not
replace them.

Layer meanings remain distinct:

| Layer | Meaning | Must not become |
| --- | --- | --- |
| Caller authentication | Identifies the app/client principal. | Data-use grant, work-order authority, or gateway approval. |
| Endpoint authorization | Authorizes daemon/API access. | Permission to use arbitrary data for training/eval/export. |
| Signed work order | Authorizes a run, resume, dispatch, or delegated workload scope. | Broad data-use grant. |
| Authority decision | Intersects principal, capability, operation, and delegation scope. | Data-use permission without data policy. |
| Data-use decision | Authorizes a data class/ref/snapshot for an operation and purpose. | Work-order signature, gateway approval, or raw storage credential. |
| Gateway verification | Authorizes side effects through required verifier chains. | Data-purpose policy owner. |
| Adapter/executor | Performs bounded effects after verification. | Authority source or data-use policy owner. |

For future implementation:

- Work orders should carry grant refs or data-use requirements, not unverified
  raw data authority.
- Grant refs should narrow work-order data refs for privileged data use.
- Gateways and verifiers should fail closed when required data-use checks cannot
  complete.
- Trainers, evaluators, collection controllers, feedback services, reward
  services, artifact services, sandboxes, and agents must not issue their own
  data permission for privileged use.
- Raw storage credentials should not be passed to training, evaluator, agent, or
  adapter code. Data access should be mediated by leases or brokered streams
  where future implementation defines them.

## Replay, Simulation, and Audit

Replay and policy simulation are explanation and planning tools. They are not
live access grants.

Future data-use replay should explain:

- which data refs, snapshots, classes, purposes, policy versions, authority
  decisions, work orders, grants, obligations, locality constraints, and reason
  codes existed at decision time;
- why a decision allowed, denied, conditioned, expired, revoked, or required
  intervention;
- how a changed policy would have classified historical requests without
  rewriting historical decisions;
- what lineage impact a revocation, deletion request, locality change, or
  retention change would create.

Required restrictions:

- Replay/simulation must not grant live data access.
- Simulation output must not expose protected payloads, protected-eval answers,
  raw secrets, personal data, or unauthorized lineage details.
- Policy simulation must not rewrite historical decisions.
- Imported traces, receipts, grants, or simulation reports must not become
  authority to mount data, export data, train, evaluate, or execute adapters.
- Side-effectful replay remains forbidden by default.

## Compatibility and Migration Plan

This RFC is a proposal only. Future implementation must decide whether data-use
contracts become a new crate, modules in planned authority/artifact/learning
crates, or versioned additions to existing runtime surfaces.

Future implementation should follow this path:

1. Accept or update this RFC with final contract names, wire shapes, reason
   codes, grant refs, lease refs, trace events, and migration class.
2. Define versioned schemas for `DataClass`, `DataPurpose`, `DataUseRequest`,
   `DataUseDecision`, `DataUseGrant`, `DataAccessLease`,
   `RetentionObligation`, and `DeletionImpact`.
3. Add explicit compatibility behavior for current work orders that only carry
   `data_refs`.
4. Update reference docs and examples only after implementation exists.
5. Add conformance fixtures for allow, deny, conditional, stale policy, expired
   consent/license, changed snapshot, locality mismatch, protected-eval
   leakage, deletion impact, and replay/simulation explanation.
6. Preserve current stable 0.1 behavior unless a versioned migration explicitly
   changes it.

Compatibility risks to track:

| Risk | Mitigation |
| --- | --- |
| Existing `data_refs` are misread as broad data authority. | Treat them as candidate refs narrowed by data-use decisions for privileged use. |
| Purpose names become free-form permissions. | Require versioned purpose artifacts and fail closed on unknown purpose. |
| Read/infer authority drifts into training authority. | Keep operation categories separate and test readable-but-not-trainable denial. |
| Protected-eval payloads leak through errors, trace, logs, or reports. | Use redacted reason codes, suite digests, evaluator-only leases, and canary leak tests. |
| Locality is bypassed for faster compute. | Bind grants to locality and scheduler/node admission predicates. |
| Deletion obligations overclaim model erasure. | Record remediation class and honest limits for derived/trained artifacts. |
| Policy simulation rewrites history. | Keep simulation non-live, separate from historical decision records, and non-authorizing. |

## Trace and Replay Impact

Future implementation should make data-use decisions inspectable without turning
traces into raw-data logs.

Trace/evidence requirements:

- Data-use requests should record requester, workload, operation, purpose, data
  refs or safe digests, policy version, decision result, obligations, reason
  codes, and grant/lease refs where policy permits.
- Trace records must avoid raw protected payloads, secret bytes, protected-eval
  answers, and personal data where not explicitly authorized.
- Denials and intervention paths should be trace-linked to work orders,
  authority decisions, gateway decisions, and policy versions.
- Lease open/close/expiry, bytes/records accessed where safe, locality, and
  actual mount reconciliation should be traceable in future implementation.
- Deletion and retention impacts should preserve audit facts without retaining
  unauthorized payload access.

Replay requirements:

- Replay remains inspect-only by default and must not re-execute side effects or
  remount data.
- Replay should reconstruct data-use decisions and explain allow/deny/condition
  results from recorded policy/evidence.
- Replay may compare proposed policy to historical requests without changing
  historical decisions.
- Replay output must not leak protected payloads or become a live grant.

## Tests Required for Future Implementation

This docs-only RFC requires no runtime tests. Future implementation must include
contract, authority, gateway, trace, replay, lineage, artifact, training,
evaluation, scheduler/locality, and failure-injection coverage.

Minimum future test matrix:

| Test area | Required cases |
| --- | --- |
| Readable but not trainable | Source data can be inspected or inferred against, but `train` and `tune` deny. |
| Purpose separation | Inference, training, evaluation, export, deletion, persistence, and retention grants do not imply one another. |
| Missing provenance | Privileged use denies or routes to intervention. |
| Unknown purpose | Request denies before data mount or persistence. |
| Ambiguous data class | Request denies until classification is resolved. |
| Expired consent/license | New use denies and impact planning is produced. |
| Changed snapshot | Existing grant cannot silently apply to a changed dataset snapshot. |
| Locality mismatch | Scheduler/node/worker selection denies disallowed region, org, tenant, or device locality. |
| Protected-eval leakage | Candidate/trainer cannot access answers, hidden case IDs, judge prompts, scoring code, or protected payload fingerprints. |
| Work-order narrowing | Work-order `data_refs` do not bypass privileged data-use checks. |
| Stale policy | High-risk use denies or follows explicitly configured degraded/offline behavior. |
| Retention and deletion | Impact reports identify raw, derived, checkpoint, model, eval, report, and deployment obligations with honest remediation limits. |
| Replay and simulation | Explanation and policy simulation do not grant access, rewrite history, or expose protected payloads. |
| Mutation/adversarial tests | Removing purpose, locality, consent/license, protected-eval, or stale-policy checks causes gold failures. |

## Docs Required for Future Implementation

Future implementation work should update, at minimum:

- `docs/reference/work-orders.md` if work-order grant refs or data-use
  requirements are added;
- `docs/reference/policy-distribution.md` if policy TTL/revocation behavior
  changes for data use;
- future data-use controller reference docs;
- future artifact, lineage, collection, feedback, reward, evaluation, training,
  sandbox, node, and gateway reference docs where they consume data-use grants;
- conformance fixture docs and release/migration notes.

Until those implementation updates exist and pass validation, this RFC remains a
proposal only.
