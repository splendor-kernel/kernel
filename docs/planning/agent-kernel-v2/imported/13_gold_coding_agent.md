> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Gold Program: Coding Agent with Live Feedback and Controlled Adjustment

This program demonstrates a persistent agent that performs coding work in isolated shell/Python/OCI/Kubernetes environments, learns from tests and reviews, and improves its code/model/route configuration without receiving unrestricted host or deployment authority.

## 1. Objective

The coding agent accepts a repository task, inspects a scoped checkout, proposes a patch, runs tools/tests, requests review when required, and publishes a candidate artifact. Splendor controls identities, data/repository scope, sandboxes, network/secrets, resource budgets, tool effects, evidence, evaluation, deployment, and rollback.

The example must support:

- local shell and Python virtual environment;
- hermetic OCI image build/run;
- optional Kubernetes execution provider;
- compiler/linter/static-analysis/test/fuzz/security-eval feedback;
- human review and targeted correction;
- persistent task/world state across restarts;
- sub-agents for test, review, or domain specialization;
- data collection from allowed failures/corrections;
- route/prompt/model/tooling candidate adjustment;
- canary deployment of code or agent revisions;
- incident containment and rollback.

## 2. Authority model

A task work order grants the minimum required operations, for example:

```text
read repository snapshot R
write only sandbox working tree W
run approved shell/python/OCI operations
read declared dependency/cache artifacts
network: denied, package mirror only, or explicit hosts
secret leases: none by default; scoped CI token only if needed
maximum CPU/GPU/memory/storage/time/cost
publish patch/test/evidence artifacts
no merge, production deploy, branch protection edit, secret export, or host shell
```

Repository ownership does not imply deployment authority. A GitHub/Git service driver, CI driver, artifact registry, and deployment driver expose separate operations/capabilities.

## 3. Environment profiles

### 3.1 Shell sandbox

- fresh namespace/container/VM according to risk;
- read-only base repository artifact;
- writable overlay/worktree;
- explicit command allow/deny policy or unrestricted shell *inside* the isolation boundary;
- PID, CPU, memory, disk, file-descriptor, process-count, and time limits;
- declared mounts only;
- egress policy and DNS control;
- no host Docker socket, SSH agent, home directory, cloud metadata, or ambient credentials;
- command, exit, resource, changed-file, and output artifact evidence.

The kernel does not try to understand every shell command. It constrains the environment and mediates operations that cross it.

### 3.2 Python environment

- lockfile/environment artifact and Python/runtime version;
- controlled package index or offline wheels;
- immutable source inputs and writable output path;
- deterministic seeds where relevant;
- imports/file/network/subprocess behavior bounded by the sandbox;
- notebook support only as an interface over the same workload contract.

### 3.3 OCI image

- build context and Dockerfile/build definition are artifacts;
- base images resolve to digests;
- build network/secrets are explicit and non-persistent;
- resulting image has SBOM/provenance/signature/scanner evidence according to policy;
- runtime uses a declared user, seccomp/AppArmor/SELinux/capabilities, mounts, devices, and network;
- image success is not deployment approval.

### 3.4 Kubernetes

A Kubernetes executor maps workload/isolation/resource semantics to a namespace/service account/RBAC, Pod/Job, volumes, network policy, runtime class, priority, and device resources. The task principal cannot submit arbitrary cluster objects unless that is itself the explicitly gated operation.

## 4. Persistent task/world model

State partitions include:

| Partition | Example content |
|---|---|
| `task` | objective, acceptance criteria, constraints, status, open questions |
| `repository` | base commit/artifact, branch policy, allowed paths, dependency graph refs |
| `hypotheses` | suspected causes, confidence, supporting/contradicting evidence |
| `plan` | next experiments/edits and obligations |
| `workspace` | current sandbox/worktree artifact and patch lineage |
| `evaluation` | exact tool/test suite versions and reports |
| `feedback` | review comments, test failures, incident outcomes, allowed uses |
| `learning` | recurring failure clusters and improvement proposals |
| `runtime_control` | inbox cursor, active agent revision, lease, health |

A command transcript is evidence, not the sole task state. The agent can resume from explicit state and artifacts without replaying unsafe commands.

## 5. Neuro-symbolic coding route

```text
task/review/test percept
 -> symbolic scope/risk/acceptance check
 -> repository query and world-state update
 -> neural or custom model diagnosis/plan
 -> symbolic dependency/path/policy checks
 -> sandbox experiment or read operation
 -> feedback parsing and hypothesis update
 -> neural code/patch proposal
 -> deterministic patch/schema/path validation
 -> compile/lint/static/test/fuzz/security eval workloads
 -> critic/sub-agent/human review as required
 -> CandidateBundle(code + environment + reports)
 -> ChangeSet and deployment gate
```

The agent may use an LLM, code model, search algorithm, AST transform, theorem prover, compiler diagnostics, or hand-written logic. Splendor standardizes the privileged crossings and evidence.

## 6. Tool and actuator profiles

- `repo.read`: read tree/blob/diff/history under a scoped repository ref;
- `workspace.apply_patch`: apply a structured patch to the sandbox only;
- `shell.exec`: execute inside the declared environment;
- `python.exec`: execute a module/script/notebook cell in a managed environment;
- `test.run`: run a versioned suite and produce `EvalReport`-compatible artifacts;
- `image.build`: produce an OCI artifact with provenance;
- `git.publish_candidate`: create a candidate commit/patch ref, not merge;
- `review.request`: create a structured human/governance request;
- `deploy.canary`: separate high-risk operation requiring approved `ChangeSet`;
- `rollback.activate`: restore a known-good deployment pointer and fence the candidate.

Each operation declares effect class and idempotency. `shell.exec` is not silently reused as a deployment, secret, or physical-control backdoor.

## 7. Feedback model

Feedback sources include:

- compiler/linter/type/static-analysis diagnostics;
- unit/integration/e2e/property/fuzz tests;
- benchmark/performance/resource reports;
- security scanners and sandbox violations;
- code review comments and approvals;
- production canary metrics/incidents;
- downstream user/task outcomes;
- model/critic confidence and disagreement.

A `FeedbackRecord` attaches to the exact patch, file/range, command/eval, agent/model/route revision, and environment. It declares whether it may be used for this task, future evals, retrieval, prompt/route tuning, supervised training, preference/reward training, or incident analysis.

## 8. Evaluation hierarchy

A candidate code bundle is evaluated in increasing cost/risk:

1. schema/patch/path validation;
2. format/lint/type/static checks;
3. targeted unit tests;
4. full unit/integration tests;
5. property/fuzz/security tests;
6. reproducible build and dependency/SBOM checks;
7. performance/resource regressions;
8. hidden/protected acceptance tests;
9. shadow replay or synthetic workload;
10. canary deployment and online monitors.

The candidate cannot modify hidden/protected tests. Test selection and thresholds are versioned artifacts. Missing or flaky results are explicit rather than converted to pass.

## 9. Live adjustment loop

A concrete scenario:

1. The active coding-agent route repeatedly produces patches that pass unit tests but fail a hidden API-compatibility suite.
2. Monitoring opens an `ImprovementProposal` scoped to route/prompt/retrieval changes (R1) and optionally a small adapter fine-tune (R2), with budget and target metrics.
3. Data collection materializes allowed historical failures, review corrections, and successful counterexamples. Hidden test payloads remain inaccessible; only permitted outcome labels/reason categories may be exposed.
4. Data quality checks remove duplicates, split by repository/task family, and scan overlap with protected evals.
5. Candidate routes/prompts and an optional model adapter are generated in training/search workloads.
6. Independent eval compares them on public, held-out, protected, security, latency, cost, and non-regression suites.
7. A `ChangeSet` replaces only exact route/prompt/model refs and records risk.
8. The new agent revision runs shadow tasks, then a bounded canary cohort.
9. Online monitors detect improved compatibility but a rise in unnecessary file edits. Stop policy pauses promotion.
10. The route candidate is rolled back; evidence opens a narrower follow-up proposal focused on minimal patching.

No active prompt/model/code file is edited in place, and the agent cannot expose the hidden suite to its trainer.

## 10. Code self-change

Changing the coding agent's own implementation is R3:

1. agent proposes a patch against its own code artifact;
2. the patch runs in an isolated environment with no active-service credentials;
3. static, unit, integration, security, conformance, and self-change-specific tests run;
4. a signed image/binary candidate is produced;
5. independent gate verifies the candidate did not alter authority, audit, eval isolation, secret handling, or risk classification outside the allowed diff;
6. shadow/dual-run compares old and new controllers on recorded/synthetic tasks;
7. canary nodes/agents receive the new revision;
8. kill switch and rollback remain controlled by an independent principal/path;
9. old known-good artifacts remain immutable and retrievable.

Generated code never executes in the control-plane host process merely because the agent wrote it.

## 11. Sub-agent patterns

- **Test specialist:** can read candidate/workspace and run tests, but cannot edit.
- **Reviewer/critic:** can read diff/reports and emit structured findings, but cannot merge/deploy.
- **Dependency specialist:** can query approved package metadata and propose updates under network/data policy.
- **Security specialist:** receives isolated artifacts and protected scanner rules; returns evidence.
- **Implementation specialist:** receives one path/task and a writable branch overlay; no production access.

The orchestrator does not proxy all of its authority into specialists.

## 12. Production deployment

A code deployment revision atomically binds:

```text
source/commit artifact
built binary/image artifact
runtime configuration
schema/database migration plan
feature/route flags
secret references (not values)
policy/value/driver dependencies
observability and SLO definitions
rollback target and compatibility
```

Deployment stages validate migration safety, state compatibility, health/readiness, functional metrics, security events, performance, and user/task outcomes. Rollback may require a compensating database/data operation; the plan cannot assume all code changes are reversible.

## 13. Required attacks and failures

- prompt injection in repository contents asks for secrets or broader shell access;
- malicious test/package attempts network/host escape;
- symlink/path traversal outside workspace;
- dependency confusion or floating package/image tag;
- fork bomb/disk exhaustion/long process after cancellation;
- generated patch disables logging/authorization/tests;
- sub-agent attempts merge/deploy;
- hidden test exfiltration attempt;
- flaky test and contradictory review feedback;
- build succeeds but artifact digest/provenance is incomplete;
- canary causes latency/error/security regression;
- rollback requires incompatible state/data migration;
- agent tries to lower its self-change risk class.

## 14. Acceptance criteria

The program passes when it demonstrates:

- isolated shell, Python, OCI, and Kubernetes-provider execution under one workload contract;
- scoped repository/workspace/secret/network authority;
- persistent task/world state and causal evidence;
- neural-symbolic route with compiler/test/static/human feedback;
- candidate publication separated from merge/deployment;
- hidden/protected eval isolation;
- ongoing data collection and quality/contamination checks;
- controlled route/prompt/model adjustment;
- R3 self-code change through independent conformance/gates;
- canary stop, rollback, and incident evidence;
- no host escape, secret leakage, direct production mutation, or authority inheritance.

See `examples/coding_agent/agent.yaml` and `examples/coding_agent/improvement_plan.yaml`.
