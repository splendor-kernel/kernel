> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Gold Validation and Example Catalog

> **Normative purpose:** no public primitive is considered kernel-grade until its corresponding gold examples pass the required graduation tier. Examples are executable contracts, not showcase demos.

## 1. Purpose

The project should not declare broad primitives complete before they are proven by small, inspectable examples. A **gold example** is simultaneously:

- a runnable tutorial;
- an end-to-end acceptance test;
- a cross-language/schema fixture;
- a trace/evidence snapshot;
- a failure and recovery demonstration;
- a compatibility target for future releases.

Each gold example pins code, environment, inputs, expected outputs, required events, state transitions, denial paths, and cleanup behavior.

## 2. Gold-example contract

Every example directory should contain:

```text
README.md                 purpose, threat model, expected result
specs/                    agent/workload/data/eval/training/change manifests
src/                      minimal user-space implementation
tests/                    positive, denial, failure, and recovery tests
fixtures/                 deterministic input and expected artifact manifests
expected-trace.jsonl      required event shape or semantic assertions
expected-lineage.json     required artifact derivation
run.sh / run.py           one-command local execution
fleet/                    optional simulated multi-node topology
SECURITY.md               capabilities, data scope, side effects, cleanup
```

Gold status requires CI execution, not documentation alone.

## 3. Foundation examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G00 | Schema round-trip | Stable IDs/spec/run/artifact/event serialization | Rust/Python/TypeScript round-trip; unknown authorizing fields fail |
| G01 | Authority deny-first | Capability/data/work-order scoping | Missing/expired/revoked/wrong-audience grants fail closed |
| G02 | State and trace transaction | Commit ordering and integrity | State cannot advance after required trace/store failure |
| G03 | Replay inspect-only | Replay remains side-effect free | Adapter invocation count stays zero; causal reconstruction matches |
| G04 | Workload lifecycle | Submit/place/lease/run/checkpoint/cancel | Every transition and attempt is evidenced; retry does not overwrite |
| G05 | Artifact lineage | Content-addressed inputs/outputs | Complete producer/input graph; reference does not grant read |
| G06 | Managed/observed/unmanaged modes | Guarantee boundary | UI/API labels and evidence differ; policy can reject non-managed mode |
| G07 | Driver conformance harness | Common manifest/lifecycle | Health, timeout, cancel, idempotency, schema, denial tests pass |
| G08 | Secret lease | Brokered secret use | Secret absent from trace/artifacts; expiry closes handle |
| G09 | Resource quota | CPU/RAM/network/action limits | Workload throttles/denies with deterministic reason and evidence |

## 4. Environment and actuator examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G10 | Restricted argv command | Safe shell primitive | No ambient shell; mount/network limits; outputs captured and cleaned |
| G11 | Explicit `sh -c` high-risk mode | Separate shell-string authority | Dedicated capability and approval required; injection tests included |
| G12 | Locked Python environment | Reproducible Python execution | Lockfile/image digest pinned; deterministic input/output artifact |
| G13 | OCI coding sandbox | Container isolation | Read-only base, scoped workspace, network deny, cleanup and attestation |
| G14 | Kubernetes Job driver | External scheduler mapping | Splendor identity/lease/lineage maps to concrete K8s UIDs and outputs |
| G15 | HTTP actuator | Idempotency and compensation | Allowlist/rate limit; duplicate key safe; compensation evidence |
| G16 | Database actuator | Data scope and transaction | Row/field scope enforced; rollback/commit paths traced |
| G17 | Artifact publication | Publishing is a side effect | Signature, destination scope, immutable digest, revocation path |
| G18 | Sub-agent as actuator | Typed specialist operation | No permission inheritance; bounded input/output and expiry |
| G19 | Trigger agent | Event-to-work-order path | Trigger conditions, dedup, quota, and no arbitrary run start |

## 5. Perception and world-model examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G20 | Polling perceptor | Freshness/provenance | Expired observation rejected; source health recorded |
| G21 | Streaming perceptor | Backpressure and ordering | Bounded queue, loss/drop policy, cursor checkpoint, resume |
| G22 | Human input perceptor | Authenticated human source | Source identity/trust class and privacy scope preserved |
| G23 | Gridworld symbolic world | World state vs observation | Invalid state update denied; deterministic state lineage |
| G24 | Probabilistic belief state | Belief vs asserted truth | Hypotheses/confidence preserved; corroboration changes belief version |
| G25 | Learned world model | Prediction/outcome linkage | Versioned prediction, rollout artifact, calibration eval |
| G26 | Memory partitions | Episodic/semantic/active-config separation | Active bundle cannot change via memory write; retention enforced |
| G27 | Neuro-symbolic router | Typed neural + rule flow | Model output is proposal; rule denial prevents action; fallback traced |
| G28 | Multi-modal route | Images/audio/text/custom tensors | Schema adapters and model bindings explicit; data scopes preserved |
| G29 | Long-lived event agent | 24/7 lifecycle | Restart/resume, stale-source handling, timers, bounded inbox, drain |

## 6. Data and quality examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G30 | Percept-to-record opt-in | Runtime data is not automatic training data | Only declared sink persists; purpose/data lease required |
| G31 | Source collection | CollectionSpec/Run | Sampling, rate, retention, provenance, failure and resume |
| G32 | Schema and missingness quality | QualitySpec/Report/Gate | Hard failure quarantines; report links exact records/shards |
| G33 | Exact/near dedup | Driver-pluggable quality work | Algorithm version and thresholds recorded; deterministic fixtures |
| G34 | License/consent/purpose gate | Data-policy control | Incompatible records denied even when readable |
| G35 | PII/secret redaction | Transform lineage and security | Original/restricted and redacted artifacts separated; access tested |
| G36 | Train/eval contamination scan | Protected-set isolation | Exact/near leaks detected without exposing hidden answers to trainer |
| G37 | Temporal/source split | Leakage-resistant SplitManifest | Record assignments deterministic and independently verifiable |
| G38 | Annotation/adjudication | Human/model labeling workflow | Redundancy, disagreement, confidence, adjudication provenance |
| G39 | Dataset rebuild | Reproducible immutable versions | Same pinned inputs/config reproduce digest or explain nondeterminism |

## 7. Evaluation and feedback examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G40 | Raw feedback ingestion | FeedbackEvent semantics | Subject/source/trust/causal refs required; no direct model mutation |
| G41 | Reward derivation | Reward provenance | Raw feedback preserved; derivation version pinned; tampering detected |
| G42 | Deterministic eval | EvalSpec/Run/Report | Exact cases, environment, candidate, baseline, metric artifacts |
| G43 | Human pairwise eval | Preference and adjudication | Blinding/randomization, annotator scope, disagreement and confidence |
| G44 | Model-judge eval | Evaluator trust classes | Related/self evaluator flagged; cannot satisfy independent gate alone |
| G45 | Replay comparison | Counterfactual evaluation | Candidate/baseline run on same recorded inputs with no effects |
| G46 | Shadow deployment | Live inputs without effects | Candidate outputs isolated; latency/cost/quality compared |
| G47 | Canary deployment | Bounded live effects | Cohort/blast radius/abort triggers; automatic rollback |
| G48 | Drift monitor | Post-deployment online eval | Data/model/performance drift creates incident/change proposal |
| G49 | Reward-hacking test | Signal independence | Candidate manipulation attempt detected; promotion denied |

## 8. Learning examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G50 | Linear regression lifecycle | Minimal train/eval/promote | Dataset version -> run -> checkpoint -> candidate -> gate -> rollout |
| G51 | MNIST/CIFAR classifier | GPU/CPU model driver | Reproducibility, batching, model artifact, baseline regression |
| G52 | Tiny transformer from scratch | Tokenization/shards/checkpoint | Resume exactness class documented; eval/overfit checks |
| G53 | Released GPT-2 inference | Transformers/model import | Tokenizer/model digests, session isolation, latency/resource evidence |
| G54 | GPT-2 full lifecycle | Data-to-self-adjustment integration | Defined in `10_gold_gpt2.md` |
| G55 | LoRA/fine-tune candidate | Parameter-efficient change | Base/adapter lineage; bundle compatibility; rollback |
| G56 | Contextual bandit RL | Online/offline reward | Episode linkage, exploration policy, safety constraints, off-policy eval |
| G57 | Gridworld PPO | RL actor/evaluator separation | Environment version, seeds, rollouts, checkpoints, policy gate |
| G58 | Preference optimization | Feedback-to-dataset-to-candidate | Raw preferences, curation, reward/eval separation |
| G59 | World-model learning | Prediction model lifecycle | Data quality, calibration, rollout eval, active bundle promotion |

## 9. Distributed and fleet examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G60 | Two-node task lease | Remote identity/lease | Signed work, expiry, output lineage, node rejection path |
| G61 | Heterogeneous eval fan-out | Arbitrary capable devices | Capability-aware case placement and deterministic aggregation |
| G62 | Data locality scheduler | Data-work placement | Minimizes transfer subject to residency/trust; lineage complete |
| G63 | PyTorch script workload | Compatibility mode | Existing script isolated and captured; no false elastic claim |
| G64 | Structured PyTorch DDP-style | TorchTrainProgram + strategy | 1/2/8-worker equivalence tolerance, checkpoint/resume, node failure |
| G65 | Elastic membership | Worker epochs | Membership change legal only by strategy; optimizer/data cursor restored |
| G66 | Inference-protected training | Interference policy | Background work preempts before configured p99/SLO breach |
| G67 | Federated edge training | Intermittent heterogeneous devices | Local data leases, update provenance, aggregation, dropout tolerance |
| G68 | Mixed 1,000-node simulation | Fleet-wide scheduling | Concurrent inference/training/eval/data, partitions, drain, fairness |
| G69 | Artifact replication/recovery | Fleet artifact availability | Digest verification, partial transfer resume, corrupt replica quarantine |

## 10. Multi-agent, physical, and self-evolution examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G70 | Scoped orchestrator/specialists | Multi-agent delegation | Work-order narrowing, budget/expiry, causal result aggregation |
| G71 | Critic sub-agent | Independent judgment | No action authority; related lineage marked; disagreement preserved |
| G72 | Agent migration | State-head handoff | Single writer, checkpoint, lease transfer, no duplicate effects |
| G73 | Simulated drone mission | Physical action boundary | High-level commands, local denial, offline fallback, trace sync |
| G74 | Robot environment launch | Device runs signed image | Resource/safety reservations, device access, cleanup, local preemption |
| G75 | Physical irreversible action | Risk and evidence | Strong approval, no fake rollback, containment/incident path |
| G76 | Prompt/rule self-adjustment | Low/medium-risk change | Candidate, hidden eval, shadow, canary, rollback |
| G77 | Coding feedback adjustment | Live improvement loop | Sandbox, protected tests, patch artifact, change gate, rollback |
| G78 | Model self-training proposal | Data/training/eval independence | Active model cannot select hidden tests or self-promote |
| G79 | Value-change attempt | Critical separation | Ordinary self-change authority denied; special multi-party flow required |

## 11. Security and adversarial examples

| ID | Example | Proves | Gold acceptance |
|---|---|---|---|
| G80 | Prompt/data injection through perceptor | Taint and capability separation | Payload cannot grant authority or bypass route/gateway controls |
| G81 | Malicious dataset poisoning | Quality/quarantine | Poison fixture detected or produces explicit known limitation; no silent admit |
| G82 | Secret exfiltration attempt | Data/secret/network scopes | Denied with evidence; secret absent from artifacts and model prompts where forbidden |
| G83 | Compromised worker | Trust and artifact integrity | Invalid signature/checkpoint rejected; worker quarantined |
| G84 | Eval leakage attempt | Hidden evaluator isolation | Trainer/candidate cannot read protected cases/answers |
| G85 | Reward-channel tampering | Anti-tamper signals | Signature/lineage mismatch invalidates signal; gate denies |
| G86 | Driver schema confusion | Typed ABI | Mismatched schema/version fails before execution |
| G87 | Duplicate irreversible action | Idempotency/replay safety | Retry cannot repeat effect without explicit new authorization |
| G88 | Expired offline policy | Edge fail-safe | Device degrades or stops according to pinned safe policy |
| G89 | Rollout blast-radius breach | Change controller safety | New leases denied, rollout aborted, active version restored |

## 12. Graduation tiers

### Tier A — local contract gold

Runs deterministically on one machine and proves positive/negative paths.

### Tier B — fault gold

Adds process crash, store failure, timeout, cancellation, partial artifact, and resume tests.

### Tier C — distributed gold

Runs on simulated or real multi-node topology with identity, leases, partitions, retries, and aggregation.

### Tier D — adversarial gold

Includes injection, authority, data, secret, reward, eval, and rollback abuse cases.

### Tier E — sustained gold

Runs for an extended period with drift, rotation, rolling upgrade, resource pressure, and recovery.

A primitive should not be called stable for fleet/self-evolution use until its representative examples reach the appropriate tier.

## 13. Conformance strategy

Gold examples should produce semantic assertions rather than byte-identical timestamps/logs. Assertions include:

- required event kinds and causal links;
- exact IDs and artifact digests where deterministic;
- authority and denial reason classes;
- state-head and deployment-version transitions;
- no forbidden adapter calls;
- resource and SLO boundaries;
- cleanup and residual-effect reports;
- cross-language schema equivalence;
- explicit nondeterminism and tolerance ranges.

## 14. Gold coverage ownership

| Contract family | Minimum examples before experimental release | Before stable local release | Before stable fleet/self-management release |
|---|---:|---:|---:|
| Identity, authority, state, events | G00–G09 Tier A | Tier B + adversarial denial tests | Tier C/D |
| Drivers and environments | G07, G10–G19 Tier A | Tier B | Tier C/D for remote executors |
| Agent/world/routing | G20–G29 Tier A | Tier B | Tier C/D/E for resident agents |
| Data control | G30–G39 Tier A | Tier B/D | Tier C/D/E |
| Feedback and evaluation | G40–G49 Tier A/D | Tier B/D | Tier C/D/E |
| Learning | G50–G59 Tier A | Tier B/D | Tier C/D/E |
| Fleet execution | G60–G69 simulation Tier C | fault-injected Tier C | real heterogeneous Tier C/E |
| Self-management and physical AI | G70–G89 Tier A/D | Tier B/C/D | Tier C/D/E with rollback drills |

## 15. CI contract

This pack exposes the schema-validated machine-readable index [`examples/gold/catalog.yaml`](examples/gold/catalog.yaml). It contains each ID, owner, required feature flags, resource class, expected duration class, graduation tiers, and emitted evidence assertions. `tools/generate_gold_catalog.py` keeps the index synchronized with this document, while `tools/validate_gold_catalog.py` enforces contiguous G00–G89 identity, schema validity, assertion references, and status honesty. CI selects examples by capability rather than silently skipping them. A skipped gold case is reported as **not exercised**, never as passed.
