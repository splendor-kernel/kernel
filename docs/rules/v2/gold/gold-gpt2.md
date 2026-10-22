> **Status:** Active 0.2/v2 gold program source. This file defines a future gold path after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements or passes the described behavior.

# Gold Program: GPT-2 Small Across the Full Splendor Lifecycle

This program is the primary proof that Splendor is an **agent kernel**, not an inference recorder. It exercises model architecture, data control, distributed training, inference, world state, neuro-symbolic routing, feedback, evaluation, continual data work, candidate production, controlled self-adjustment, rollout, and rollback through one coherent contract set.

## 1. What “reproduce GPT-2” means

The program separates three claims that must never be conflated:

| Claim | Required result | Historical limitation |
|---|---|---|
| **Architecture reproduction** | Implement the released GPT-2-small-compatible decoder architecture and tokenizer contract from immutable code/config artifacts | Fully reproducible from declared artifacts |
| **Released-weight parity** | Load a released checkpoint and match reference logits/generation within declared numerical tolerances | Hardware/framework kernels can produce bounded numerical differences |
| **Training reproduction** | Train the same architecture from a declared seed, code, optimizer, schedule, tokenizer, and immutable licensed dataset snapshot | This is a process/architecture reproduction unless the original historical training corpus is available and legally usable |

The official released GPT-2 code defines the small default architecture with context length `1024`, embedding width `768`, `12` attention heads, and `12` transformer layers. This gold program records those values as the target profile. It never labels a newly trained model “the original GPT-2”; it labels it `gpt2-small-compatible/<dataset>/<run>`.

## 2. Three execution profiles

### 2.1 `gpt2-tiny-ci`

Purpose: deterministic CI and contract testing.

```text
layers: 4
heads: 4
embedding: 256
context: 256
vocabulary: GPT-2 tokenizer artifact
training tokens: small fixture snapshot
workers: 1 or 2 CPU/GPU
```

It must complete quickly and exercise every lifecycle object, including a deliberately failing candidate and rollback.

### 2.2 `gpt2-small-reference`

Purpose: architecture-compatible distributed training and operational validation.

```text
layers: 12
heads: 12
embedding: 768
context: 1024
vocabulary/tokenizer: immutable GPT-2-compatible artifacts
precision: declared by training plan
optimizer/schedule: explicit artifacts/config
workers: elastic, based on available fleet capability
```

No target parameter count is used as identity; the serialized architecture and parameter shapes are the source of truth.

### 2.3 `gpt2-released-parity`

Purpose: validate model-driver and inference compatibility against released weights.

- import released config, tokenizer, and checkpoint into immutable Splendor artifacts;
- convert only through a versioned converter artifact;
- compare parameter names/shapes and conversion checksums;
- compare logits on fixed token sequences;
- compare greedy generation exactly where kernels permit, otherwise by declared tolerance;
- publish a parity report and incompatibility details;
- never rewrite imported source artifacts.

## 3. Atomic artifact set

A deployable model is an atomic `ModelBundle`, not a single weights file:

```text
ModelBundle
  architecture_ref
  weights_ref
  tokenizer_ref
  generation_defaults_ref
  model_code_ref
  runtime_environment_ref
  input_schema_ref
  output_schema_ref
  safety/usage metadata_ref
  lineage_root
```

A deployment cannot combine candidate weights with the baseline tokenizer or an untested runtime image.

## 4. End-to-end object graph

```text
DataSourceSpec(s)
  -> CollectionPlan
  -> RawDatasetSnapshot
  -> quality/redaction/dedup/split workloads
  -> DatasetSnapshot + SplitManifest
  -> DataQualityReport + ContaminationReport
  -> TrainingPlan
  -> TrainingWorkload + checkpoints
  -> CandidateBundle
  -> EvalRuns(candidate vs baseline)
  -> EvalReport + EvidenceBundle
  -> ChangeSet
  -> shadow/canary/progressive DeploymentPlan
  -> active ModelBundle revision
  -> inference/percept/action/feedback events
  -> new bounded CollectionPlan or ImprovementProposal
```

Every arrow is an explicit lineage edge or control decision. No stage operates on an unnamed folder such as `data/latest` or `model/final`.

## 5. Data program

### 5.1 Source policy

The reference training corpus must be replaceable. A source is accepted only when its `DataSourceSpec` declares:

- owner/provider and retrieval method;
- license and permitted purposes;
- expected modality/language/domain/time range;
- personal/sensitive data classification;
- locality and egress rules;
- deletion/retention obligations;
- stable source snapshot/version when available;
- record identity strategy and provenance fields;
- collection budget and stop condition.

The example repository should ship only tiny redistributable fixtures. Full runs require the operator to bind approved source artifacts.

### 5.2 Collection and curation stages

Each stage is a separate `DataWorkload` with immutable input/output refs:

1. acquire/import;
2. decode and validate format;
3. language/domain classification;
4. policy filtering and redaction;
5. exact and near-duplicate clustering;
6. document-family grouping;
7. quality scoring and quarantine;
8. benchmark/holdout contamination scanning;
9. train/validation/test group split;
10. tokenize and pack sequences;
11. statistical profile and slice report;
12. snapshot commit.

The raw snapshot remains addressable under its retention policy so transformations are explainable. A sanitized training snapshot does not erase lineage to raw source references.

### 5.3 Split isolation

`SplitManifest` records groups, not only row indexes. Records from the same source document, near-duplicate cluster, generated lineage, conversation, user, or time leakage group remain in one split according to policy.

Protected evaluation material is exposed only to evaluator workloads. Trainer grants contain no readable reference to protected payloads. Public benchmark identifiers may be visible; protected records are not.

### 5.4 Quality and contamination reports

Required data reports include:

- parse/tokenization success and malformed rates;
- length, language, source, date, domain, and license distributions;
- duplication and near-duplication clusters;
- PII/sensitive-content estimates and quarantine counts;
- toxicity/hate/sexual/violence and other policy-relevant slices as configured;
- benchmark overlap by exact, normalized, fuzzy, semantic, and generated-lineage methods;
- train/validation/test cross-overlap;
- source concentration and long-tail coverage;
- drift against the previous approved snapshot;
- unresolved uncertainty and samples requiring review.

A report has thresholds, sample counts, method/version, false-positive/false-negative caveats, and `pass`, `fail`, or `inconclusive`; absence of a detector result is not a pass.

## 6. Training plan

Future executable fixtures should add a file such as
`examples/gpt2/training_plan.yaml` to illustrate this contract. That file is not
present or active in this docs-only integration. The complete plan binds:

```text
model architecture artifact
tokenizer artifact
training/validation snapshot refs
model/trainer code digest
OCI/environment digest
optimizer and schedule
precision and numerical policy
seed/RNG policy
global batch and sequence policy
distribution strategy constraints
resource and acceptable accelerator classes
checkpoint format/frequency/retention
metric definitions and aggregation
preemption/elasticity/retry behavior
maximum cost/energy/time budget
interference policy protecting live inference
declared candidate outputs
```

### 6.1 Distributed execution

The trainer driver supports three modes described in [`gold-distributed-pytorch.md`](gold-distributed-pytorch.md). For the reference run:

- the fleet scheduler forms a compatible worker gang or elastic group;
- each worker receives a short-lived execution lease, exact artifact refs, and only the required data shards;
- rendezvous state is fenced by workload attempt/epoch;
- rank/world metadata is injected; the script or context API initializes PyTorch distributed execution;
- data sharding records epoch, sampler seed, group, and consumed ranges where feasible;
- metrics are reduced with named semantics rather than arbitrary last-writer wins;
- checkpoints are committed as distributed artifacts with completeness manifests;
- preemption requires a valid checkpoint or explicit restart-from-earlier-checkpoint decision;
- changes in world size, precision, kernels, or data order appear in evidence.

### 6.2 Live inference protection

Before admitting training, every node computes available background capacity after reservations for:

- current and forecast online inference demand;
- model residency/KV/cache and memory fragmentation reserve;
- CPU/network/storage latency budgets;
- node-agent and safety services;
- physical mission, battery, and thermal reserve on edge devices;
- failure headroom and recovery operations.

Training can be preempted, throttled, migrated, or resized. The live inference service is not. If a training strategy cannot tolerate that policy, it must run on dedicated capacity rather than weakening the SLO.

## 7. Training lifecycle assertions

The run passes only when:

1. all input digests and grants are frozen before worker start;
2. no worker can read protected eval artifacts;
3. every checkpoint has model/optimizer/scheduler/RNG/data-progress lineage;
4. resumed runs record the parent checkpoint and changed environment/world size;
5. duplicate workers cannot commit the same logical checkpoint without fencing;
6. aggregate metrics name their reduction and contributing worker set;
7. success produces a `CandidateBundle`, not a deployment mutation;
8. partial/failed outputs are marked incomplete and cannot be selected by change control;
9. inference SLO guardrails remain within the declared interference policy;
10. cost/time/energy/resource budgets are enforced and evidenced.

## 8. Evaluation program

The release gate is a suite of suites. Each suite is independently versioned and can be run locally on tiny fixtures or at scale.

### 8.1 Model correctness

- architecture and parameter-shape validation;
- tokenizer encode/decode fixtures;
- reference forward-pass/logit tests;
- causal masking tests;
- checkpoint save/load and conversion parity;
- deterministic greedy-generation fixtures;
- numerical stability and NaN/overflow checks.

### 8.2 Language-model quality

- validation loss/perplexity with exact snapshot and token accounting;
- held-out source/domain/language/time slices;
- long-context positions up to the declared context limit;
- rare-token and formatting/code-like slices;
- comparison with baseline including uncertainty and practical effect threshold.

### 8.3 General behavior

- zero/few-shot task fixtures appropriate to the model's capability;
- instruction-following is not assumed for a base language model;
- calibration/likelihood ranking where meaningful;
- generation diversity and degeneration/repetition metrics;
- factuality or retrieval-grounding only in the agent profile that supplies those mechanisms.

### 8.4 Safety, alignment, and governance

- policy-relevant content slices;
- privacy and memorization probes;
- prompt/data exfiltration fixtures in the agent wrapper;
- refusal/deferral behavior where symbolic policy requires it;
- value-spec rule compliance;
- capability and actuator bypass attempts;
- bias/fairness slices selected for the deployment context;
- uncertainty and human-review routing.

A base GPT-2-style model is not made “aligned” by an eval score. Alignment is the combined runtime structure of values, capabilities, symbolic constraints, verification, feedback, data policy, deployment gates, and model behavior.

### 8.5 Data and overfitting checks

- train-validation gap and learning curves;
- repeated-eval selection pressure and test-set exposure accounting;
- n-gram/fuzzy/semantic overlap with protected tests;
- canary-string and exact-sequence memorization probes;
- membership-inference style risk probes where appropriate;
- source-specific overfit and regressions;
- model-generated-data recursion and lineage concentration;
- holdout refresh policy that does not silently change the current release gate.

### 8.6 Operational evaluation

- latency, throughput, memory, startup, batching, and cancellation;
- model-driver crash/restart and node loss;
- token-stream backpressure;
- malformed/oversized request handling;
- quota and tenant isolation;
- cost and energy per declared unit;
- shadow parity and canary cohort behavior.

## 9. Inference service

An inference deployment is a `DeploymentRevision` referring to an atomic `ModelBundle`, model-driver revision, route revision, value/policy bundle, resource/SLO profile, and cohort plan.

Each request records or references:

- tenant/agent/run and request identity;
- exact deployment/model/tokenizer/route versions;
- input classification and data-use decision;
- generation parameters and seed policy;
- resource use and timings;
- streamed chunks and final result relationship;
- constraint/gate decisions and any tool/action proposals;
- feedback/eval links received later.

Prompts and outputs may be stored by reference, redacted, summarized, sampled, or omitted according to data policy. Auditability does not imply indiscriminate content retention.

## 10. GPT-2 as one component in a complete agent

The gold program wraps the base model in a small persistent research assistant to prove full agent modeling.

### 10.1 Components

- **Perceptors:** typed user requests, document retrieval results, clock/system events, feedback events.
- **Neural component:** GPT-2-small-compatible language model or released-weight parity model.
- **Symbolic components:** request classifier, capability rules, citation requirement, maximum action plan, data-use rules, and deterministic calculators/parsers.
- **World state:** document catalog, task facts/hypotheses, source provenance, open obligations, interaction state, and feedback summary.
- **Actuators:** read-only retrieval and a sandboxed report writer. Network/write effects are separately gated.
- **Evaluator/critic:** groundedness and format checks; optional human review for high-risk requests.

### 10.2 Neuro-symbolic route

```text
request percept
 -> symbolic classify/risk/data-use
 -> retrieve permitted context
 -> world-state hypotheses with provenance
 -> GPT-2 proposal/generation
 -> symbolic parse/check/citation/constraint evaluation
 -> optional critic or human review
 -> approved report-write action
 -> outcome + feedback
 -> state/evidence commit
```

The route is imperative user-space code. Splendor records typed crossings and controls resources/effects; it does not require a graph DSL.

### 10.3 World-state rules

- A generated statement is a `hypothesis`, not a `fact`.
- A retrieved statement records source artifact, location, time, and confidence.
- Conflicting claims coexist until a declared resolver produces a new derived assertion.
- State partitions name writer authority and retention.
- Private scratch state is not automatically durable, shared, or training data.
- Secrets are never world-state fields.

## 11. Feedback and ongoing data work

Feedback is attached to the exact target:

```text
request/output/action/state commit
model bundle and route revision
source: human/environment/automated/downstream
label/rating/correction/ranking/free text
confidence and trust tier
collection consent/purpose
allowed uses: monitor, eval, train, reward, incident only
```

An ongoing controller may propose:

- collecting a bounded sample of low-confidence or failed interactions;
- requesting labels/corrections;
- building a new dataset snapshot;
- refreshing a drift or contamination report;
- running an eval on the current deployment;
- training a candidate adapter/fine-tune/model;
- changing retrieval, prompt, route, thresholds, or runtime configuration.

It cannot append feedback directly to the existing training dataset or edit live weights. Each new dataset is a snapshot and each adjustment is a candidate/change.

## 12. Controlled self-adjustment program

A concrete closed-loop scenario:

1. Monitoring detects rising citation-check failures on a new document slice.
2. `ImprovementProposal` identifies evidence, target metric, allowed change classes, budget, and stop criteria.
3. The gate permits data collection and R1 route/config search; model retraining requires a separate R2 authorization.
4. Data work builds a snapshot of consented failures/corrections, excluding protected eval cases.
5. Candidate A changes retrieval/routing; candidate B fine-tunes a small adapter; candidate C makes no model change and tightens deferral.
6. Independent eval compares all candidates against baseline on public, protected, safety, overfit, and operational suites.
7. A `ChangeSet` identifies exact component replacements and state/data migrations.
8. Deployment runs shadow, then 1%, 5%, 25%, 50%, 100% cohorts only while stop conditions hold.
9. A regression breaches the memorization threshold at 25%; the controller stops, quarantines candidate B, rolls affected cohorts to the known-good revision, and opens an incident.
10. Evidence from the failure may seed a new improvement proposal under its own data-use policy.

The agent may initiate the proposal, but it cannot edit the eval suite, promotion threshold, value spec, authority, or incident evidence that judges it.

## 13. Rollout and rollback

The deployment plan includes:

- eligible tenants/agents/nodes and exclusion groups;
- deterministic cohort assignment;
- minimum sample/time per stage;
- online quality, safety, latency, error, cost, and resource thresholds;
- protected/hidden monitor refs;
- automatic pause and rollback triggers;
- designated human/governance approvals by risk;
- state schema forward/backward compatibility;
- known-good model/route/runtime/image refs;
- cache/model-residency transition plan;
- rollback drill timestamp and result.

Rollback changes the active software/model/config/state pointers and fences new work. It does not claim to undo text already shown, messages already sent, data already disclosed, or physical effects already performed; those require containment or compensation.

## 14. Failure-injection matrix

The gold program must inject:

- corrupt source shard;
- invalid license/data-use grant;
- train/test duplicate family;
- protected data access attempt;
- worker crash and network partition;
- stale rendezvous worker;
- partial distributed checkpoint;
- metric aggregator loss;
- inference SLO pressure during training;
- candidate with better loss but safety regression;
- candidate with contamination-driven benchmark gain;
- model/tokenizer mismatch;
- driver version mismatch;
- canary latency and memorization breach;
- rollback target unavailable;
- self-change attempt to lower its own risk or gate.

Each case has an expected terminal status, event sequence, and no-forbidden-effect assertion.

## 15. Gold acceptance criteria

The GPT-2 program is complete only when a clean machine/fleet simulation can:

1. validate all manifests against published schemas;
2. reproduce the tiny profile end to end in CI;
3. import and parity-check a released checkpoint under a declared runtime;
4. materialize an immutable licensed training dataset with quality, split, and contamination evidence;
5. launch/resume distributed PyTorch training and publish a complete candidate bundle;
6. prove protected eval isolation and inference reservation;
7. compare candidate and baseline on independent suites with uncertainty;
8. deploy through shadow/canary/progressive stages and automatically stop/rollback a bad candidate;
9. run the model inside a persistent neuro-symbolic agent with explicit world state, perceptors, actuators, feedback, and data-use controls;
10. generate a bounded improvement proposal from live feedback without mutating the active model or weakening governance;
11. export a causal evidence graph from source data through deployment and post-deployment feedback;
12. repeat the run with only declared nondeterminism and explain material divergence.

## 16. Planned example artifacts

Future implementation/gold-example issues should add executable fixtures and
proposed manifests under `examples/gpt2/`, including:

- `agent.yaml`
- `collection_plan.yaml`
- `training_plan.yaml`
- `eval_suite.yaml`
- `deployment_plan.yaml`

Those files are not present or active in this docs-only integration. They remain
planned illustrative 0.2/v2 contracts until future implementation/gold-example
issues add executable fixtures and retained evidence before any pass or
implementation claim.
