# Gold Conformance Triage

Status: non-normative planning artifact for issue [#138](https://github.com/splendor-kernel/kernel/issues/138). This document does not change the stable 0.1 implementation contract, does not mark any imported gold case as passing, and does not create a gold harness.

Milestone: `Splendor0.1-dev / post-0.1 conformance planning`
Sprint fit: `0.1-S2 - Compatibility test suite`, `0.1-S3 - Adapter maturity model`
FRs: `FR-0.1-04`, `FR-0.1-05`, `FR-0.1-08`
Primitive focus: docs/tests, conformance, action gateway, state graph, trace store, replay, adapters, work orders, governance
Boundary: docs only

## Source Inputs

- `docs/planning/agent-kernel-v2/imported/examples/gold/catalog.yaml`
- `docs/planning/agent-kernel-v2/imported/09_gold_examples_catalog.md`
- `docs/spec/0.1/conformance.md`
- `docs/spec/0.1/adapter-maturity.md`
- `conformance/0.1/fixtures/conformance-cases.json`
- `docs/rules/verifiable_criteria/sprints/0.1-S2-compatibility-test-suite.md`
- `docs/rules/verifiable_criteria/sprints/0.1-S3-adapter-maturity-model.md`

## Non-Goals

- No gold harness implementation.
- No Rust, Python, TypeScript, generated schema, CI, or runtime behavior change.
- No external systems, secrets, production adapters, SaaS systems, live networks, physical hardware, or large fleet tests.
- No production, certification, marketplace, legal approval, physical safety, live robotics, direct actuator, 1,000-node, or self-evolution claim.
- No stable primitive, trace event, state format, daemon API, gateway contract, verifier pipeline, SDK contract, governance semantics, or physical/device action model change.

## Status Rules

All imported catalog entries currently have source status `specified_not_implemented`. This triage therefore records every row as `not_exercised` for current evidence status. `not_exercised` is not a pass. A future change may only mark a gold case `passed` after an executable fixture or harness for that exact catalog revision runs and all required assertions pass.

Classifications mean:

- `current-0.1 candidate`: the case can be reduced to a small local 0.1 conformance or adapter-maturity fixture without changing stable primitives or contacting external systems.
- `later existing milestone work`: the case fits an existing milestone or sprint, but it is not part of the minimum 0.1 executable subset in this planning pass.
- `post-0.1 RFC-required`: the case depends on vNext primitives, services, schemas, drivers, execution fabrics, data/training/change-control planes, sustained fleet behavior, physical hardware claims, or self-evolution semantics that require an RFC before implementation.

## Acceptance Coverage

- The classification table below covers `G00` through `G89` exactly once.
- The minimum 0.1 executable subset is defined in the next section with expected fixtures.
- Every current status is `not_exercised`; no row is marked `passed`.
- Scale, production, certification, physical hardware, and self-evolution cases are deferred unless there is executable evidence in the current branch. There is no such evidence in this branch.
- Adapter maturity references are limited to current manifest evidence and do not imply gold pass status.

## Minimum 0.1 Executable Subset

These candidates are the smallest useful bridge from the imported gold catalog into the existing 0.1 conformance and adapter maturity work. The expected fixtures listed here are not added by this issue; they are the minimum evidence required before the cases can move beyond `not_exercised`.

| Gold case | Expected fixture evidence before exercise |
| --- | --- |
| `G00` | Stable primitive serialization fixture covering Rust/Python/TypeScript round-trip or an equivalent generated-schema contract; unknown authorizing extension fields must fail or remain non-authorizing. |
| `G01` | Work-order and gateway denial matrix for missing, expired, revoked, wrong-audience, and overbroad authority; adapter execution must remain false. |
| `G02` | Trace/state transaction fixture proving required tick order, state commit linkage, trace/store failure behavior, and no tick advancement after failed commit. |
| `G03` | Replay fixture with `mode: inspect_only`, `side_effects_replayed: false`, no adapter/policy/gateway invocation, and causal reconstruction from trace/state only. |
| `G07` | Adapter manifest and lifecycle fixture using existing 0.1 adapter maturity fields; include invalid manifest/schema negative cases and no production adapter claim. |
| `G09` | Quota denial fixture showing deterministic denial before adapter execution, trace-linked verifier reason, and no silent downgrade to allow. |
| `G15` | HTTP adapter fixture using local, secret-free evidence only; prove allowlist, denied destination or method, quota or timeout failure, trace-safe output, and replay suppression. |
| `G18` | Local delegation fixture proving typed message/request boundaries, narrowed permissions, budget/expiry, and no inherited broad caller authority. |
| `G70` | Orchestrator/specialist fixture proving causal result aggregation, per-agent quota/permission scope, and no permission laundering. |
| `G86` | Adapter or driver-schema negative fixture proving schema/version mismatch fails before execution and records the failing primitive/requirement. |
| `G87` | Duplicate side-effect fixture proving retries and replay cannot repeat an irreversible action without a distinct explicit authorization. |

## Adapter Maturity Evidence Boundary

Current evidence-backed adapter maturity material is limited to the 0.1 adapter manifest fixtures and validation path:

- `docs/spec/0.1/fixtures/adapter-manifests/filesystem.json` for `local-safe` manifest evidence.
- `docs/spec/0.1/fixtures/adapter-manifests/http.json` for `network-safe` manifest evidence.
- `docs/spec/0.1/fixtures/adapter-manifests/robotics-simulated-device.json` for simulated `device-safe` manifest evidence only.
- `scripts/validate-adapter-manifests.py` and `conformance/0.1/run-conformance.py` for current fixture validation.

These files can support candidate planning for adapter manifest and negative-schema cases, especially `G07`, `G15`, `G86`, and `G87`. The simulated robotics manifest may inform future `G73`, `G75`, and `G88` work, but it is not a passed gold mission, hardware readiness result, or physical safety certification.

## Classification Table

<!-- gold-classification-table:start -->
| ID | Name | Source status | Evidence status | Classification | Fit / reason |
| --- | --- | --- | --- | --- | --- |
| G00 | Schema round-trip | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S1/S2 stable primitive and schema fixture evidence. |
| G01 | Authority deny-first | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 work-order, gateway, and fail-closed authority fixtures. |
| G02 | State and trace transaction | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 trace ordering, state linkage, and commit-failure fixtures. |
| G03 | Replay inspect-only | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 replay side-effect suppression fixture evidence. |
| G04 | Workload lifecycle | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 signed work-order, run lifecycle, and state handoff work; vNext workload leases remain not exercised. |
| G05 | Artifact lineage | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires artifact service and lineage graph semantics beyond current 0.1 fixture coverage. |
| G06 | Managed/observed/unmanaged modes | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires daemon/control-plane guarantee mode semantics not defined by current 0.1 specs. |
| G07 | Driver conformance harness | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2/S3 adapter manifest and lifecycle conformance fixtures. |
| G08 | Secret lease | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires secret broker and lease semantics outside current 0.1 conformance evidence. |
| G09 | Resource quota | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 quota denial and fail-closed gateway fixtures. |
| G10 | Restricted argv command | specified_not_implemented | not_exercised | post-0.1 RFC-required | No command/shell adapter maturity evidence exists in current 0.1 fixtures. |
| G11 | Explicit sh -c high-risk mode | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires separate high-risk shell authority, approval, and injection harness. |
| G12 | Locked Python environment | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires managed Python execution environment and reproducibility contract. |
| G13 | OCI coding sandbox | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires sandbox executor and container isolation contract beyond current adapters. |
| G14 | Kubernetes Job driver | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires external scheduler/driver mapping and Kubernetes fixture not present in 0.1. |
| G15 | HTTP actuator | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to evidence-backed 0.1-S3 `network-safe` HTTP adapter fixture planning. |
| G16 | Database actuator | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires database adapter, transaction scope, and rollback fixtures not present in 0.1. |
| G17 | Artifact publication | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires artifact publication service and revocation semantics beyond current specs. |
| G18 | Sub-agent as actuator | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 local delegation, typed message, and no-permission-laundering fixtures. |
| G19 | Trigger agent | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.02 local delegation/daemon control plus 0.03 signed work-order path. |
| G20 | Polling perceptor | specified_not_implemented | not_exercised | later existing milestone work | Fits local percept source hardening before broader world-model work. |
| G21 | Streaming perceptor | specified_not_implemented | not_exercised | later existing milestone work | Fits bounded local percept stream, cursor, and replay hardening work. |
| G22 | Human input perceptor | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.02-S0 authenticated caller and percept provenance boundary work. |
| G23 | Gridworld symbolic world | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires world-state service semantics not defined by current stable primitives. |
| G24 | Probabilistic belief state | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires belief/hypothesis state model and versioning RFC. |
| G25 | Learned world model | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires prediction model lifecycle and calibration artifact semantics. |
| G26 | Memory partitions | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires memory partition model beyond current explicit state graph contract. |
| G27 | Neuro-symbolic router | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires route trace grammar and model/rule boundary semantics beyond current policy output. |
| G28 | Multi-modal route | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires multimodal schema adapter and model binding contract. |
| G29 | Long-lived event agent | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 resident lifecycle planning, but sustained 24/7 behavior is not claimed. |
| G30 | Percept-to-record opt-in | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data-use and persistence-purpose plane beyond current percept contract. |
| G31 | Source collection | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires collection run, retention, and dataset lineage semantics. |
| G32 | Schema and missingness quality | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data quality gate/report primitives. |
| G33 | Exact/near dedup | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data-quality algorithm registry and deterministic shard fixtures. |
| G34 | License/consent/purpose gate | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data-policy authorization plane beyond current gateway checks. |
| G35 | PII/secret redaction | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires redaction lineage and restricted artifact access model. |
| G36 | Train/eval contamination scan | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires protected evaluation data isolation and contamination scanner semantics. |
| G37 | Temporal/source split | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires dataset split manifest and independent verification contract. |
| G38 | Annotation/adjudication | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires human adjudication workflow fixtures and authenticated input scope. |
| G39 | Dataset rebuild | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires immutable dataset build/rebuild service semantics. |
| G40 | Raw feedback ingestion | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires feedback service behavior beyond schema-only stable primitive examples. |
| G41 | Reward derivation | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires reward derivation pipeline and anti-tamper evidence model. |
| G42 | Deterministic eval | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires evaluator suite/report primitives beyond current conformance runner. |
| G43 | Human pairwise eval | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires human evaluation workflow and protected adjudication fixtures. |
| G44 | Model-judge eval | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires evaluator trust-class semantics and model-judge isolation. |
| G45 | Replay comparison | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires counterfactual evaluation harness beyond inspect-only replay fixture. |
| G46 | Shadow deployment | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires deployment/shadow traffic semantics not in current conformance suite. |
| G47 | Canary deployment | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires rollout controller, cohort, abort, and rollback contract. |
| G48 | Drift monitor | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires online evaluation, incident, and change-proposal planes. |
| G49 | Reward-hacking test | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires reward/eval independence and adversarial improvement harness. |
| G50 | Linear regression lifecycle | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires training-to-deployment lifecycle and gate semantics. |
| G51 | MNIST/CIFAR classifier | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires model training driver and dataset/eval fixtures. |
| G52 | Tiny transformer from scratch | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires training checkpoint/resume and tokenizer/shard lifecycle. |
| G53 | Released GPT-2 inference | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires model import/inference driver and resource evidence contract. |
| G54 | GPT-2 full lifecycle | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data/training/eval/change integration and self-adjustment safeguards. |
| G55 | LoRA/fine-tune candidate | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires candidate bundle, compatibility, and rollback semantics. |
| G56 | Contextual bandit RL | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires RL reward, exploration, and off-policy evaluation contract. |
| G57 | Gridworld PPO | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires RL environment, rollout, checkpoint, and policy gate semantics. |
| G58 | Preference optimization | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires preference data curation and reward/eval separation. |
| G59 | World-model learning | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires world-model training and active bundle promotion semantics. |
| G60 | Two-node task lease | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 signed remote work order, node identity, and trace-linked message path. |
| G61 | Heterogeneous eval fan-out | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 capability-aware placement in simulated topology. |
| G62 | Data locality scheduler | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 locality-aware placement hints; deeper data-control semantics remain deferred. |
| G63 | PyTorch script workload | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires workload compatibility driver and sandbox execution contract. |
| G64 | Structured PyTorch DDP-style | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires distributed training strategy, accelerator workers, and checkpoint equivalence. |
| G65 | Elastic membership | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires elastic training membership and optimizer/data cursor semantics. |
| G66 | Inference-protected training | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires online inference reservation and training preemption policy. |
| G67 | Federated edge training | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires federated training, aggregation, and heterogeneous edge semantics. |
| G68 | Mixed 1,000-node simulation | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires sustained fleet-scale simulation; no scale evidence exists in this branch. |
| G69 | Artifact replication/recovery | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires fleet artifact replication and corrupt-replica quarantine semantics. |
| G70 | Scoped orchestrator/specialists | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2 local multi-agent delegation and causal graph fixtures. |
| G71 | Critic sub-agent | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires evaluator independence and critic authority semantics beyond local messaging. |
| G72 | Agent migration | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03 state handoff and migration trace semantics. |
| G73 | Simulated drone mission | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.05 simulated physical boundary harness; no hardware or safety certification claim. |
| G74 | Robot environment launch | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires signed image/device environment launch and executor contract beyond current physical docs. |
| G75 | Physical irreversible action | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.04 approval/governance plus 0.05 physical safety simulation; no hardware evidence claim. |
| G76 | Prompt/rule self-adjustment | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires self-change, shadow/canary, and rollback governance RFC. |
| G77 | Coding feedback adjustment | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires sandboxed live improvement loop and protected-test change gate. |
| G78 | Model self-training proposal | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data/training/eval independence and no self-promotion semantics. |
| G79 | Value-change attempt | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires critical value-change authority separation and multi-party flow. |
| G80 | Prompt/data injection through perceptor | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires taint/capability separation and agent-route security grammar. |
| G81 | Malicious dataset poisoning | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires data-quality poisoning fixtures and quarantine semantics. |
| G82 | Secret exfiltration attempt | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires secret broker, network scope, and exfiltration fixture semantics. |
| G83 | Compromised worker | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.03/0.04 node trust, signature rejection, and quarantine planning without attestation claim. |
| G84 | Eval leakage attempt | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires protected evaluator isolation and hidden-case access controls. |
| G85 | Reward-channel tampering | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires reward signal signature/lineage and gate-denial semantics. |
| G86 | Driver schema confusion | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2/S3 adapter schema/version negative fixture evidence. |
| G87 | Duplicate irreversible action | specified_not_implemented | not_exercised | current-0.1 candidate | Maps to 0.1-S2/S3 retry, idempotency, gateway, and replay-safety fixture evidence. |
| G88 | Expired offline policy | specified_not_implemented | not_exercised | later existing milestone work | Fits 0.05 offline policy cache fail-safe behavior. |
| G89 | Rollout blast-radius breach | specified_not_implemented | not_exercised | post-0.1 RFC-required | Requires rollout controller and active-version restore semantics beyond current governance docs. |
<!-- gold-classification-table:end -->

## Deferred Execution Rules

Future gold harness work must preserve these rules before changing any `not_exercised` status:

- Use exact catalog revision identity and do not translate skipped cases into passes.
- Keep all side effects behind the Action Gateway and required verifier chain.
- Record trace events and state references sufficient for replay reconstruction.
- Default replay to inspect-only and never call adapters, external services, middleware, filesystems, networks, devices, or approval systems.
- Keep adapter maturity claims tied to manifests, tests, examples, and conformance outputs that actually exist.
- Treat physical cases as simulation-first. Live hardware, production safety, certification, and direct actuator claims require separate evidence and review.
- Treat large fleet and self-evolution cases as post-0.1 RFC work until their primitives, safety model, and executable harnesses are accepted.
