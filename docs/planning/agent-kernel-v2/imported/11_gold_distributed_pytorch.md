> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Gold Program: Convert PyTorch Training into Flexible Distributed Splendor Work

Splendor should make a normal PyTorch project runnable on one device, many GPUs, Kubernetes, cloud workers, on-prem nodes, or suitable edge devices **without changing the kernel contract**. It should reduce orchestration work aggressively while remaining honest: arbitrary stateful Python cannot be transformed into correct distributed training by inspection alone.

## 1. Contract boundary

Splendor owns:

- immutable code/environment/data/config binding;
- capability, secret, network, and data-use scopes;
- worker placement, leases, rendezvous, fencing, retries, and preemption;
- live-inference reservations and interference policy;
- checkpoint artifact lifecycle and transfer;
- event/metric/evidence collection;
- output/candidate lineage;
- cancellation and budget enforcement.

The trainer implementation owns:

- model mathematics and forward/backward passes;
- optimizer and scheduler semantics;
- correct distributed strategy integration;
- data ordering/sharding requirements;
- numerical behavior;
- algorithm-specific checkpoint contents.

A `TrainerDriver` bridges the two.

## 2. Three compatibility modes

### Mode A — launcher compatibility

For code already compatible with `torchrun`, DDP, FSDP, tensor/pipeline parallelism, or another explicit strategy.

```bash
splendor train submit training_plan.yaml
```

The driver:

1. resolves code, environment, data, and config digests;
2. obtains a gang/elastic placement;
3. creates a fenced rendezvous;
4. starts one or more processes per worker;
5. supplies rank/world/local-rank/master variables and attempt identity;
6. captures stdout/stderr as bounded logs, plus structured metrics;
7. commits declared checkpoints and outputs;
8. handles worker/node failure according to policy;
9. publishes a `CandidateBundle` on successful completion.

Code modification can be zero when the program is already distributed-correct.

### Mode B — Splendor PyTorch context

For ordinary training loops that can accept small, explicit modifications.

```python
from splendor.pytorch import training_context

with training_context() as ctx:
    dataset = build_dataset(ctx.input_artifact("train"))
    loader = ctx.dataloader(dataset, batch_size=16, shuffle=True)
    model = ctx.wrap_model(build_model(), strategy="auto")
    optimizer = ctx.prepare_optimizer(make_optimizer(model))

    for epoch in ctx.epochs(10):
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            loss = compute_loss(model, batch)
            ctx.backward(loss)
            optimizer.step()
            ctx.report_metric("train/loss", loss, reduction="mean")
            ctx.maybe_checkpoint(
                model=model,
                optimizer=optimizer,
                progress={"epoch": epoch, "step": ctx.global_step},
            )
```

The context provides rank-safe output, distributed samplers, metric reductions, checkpoint coordination, cancellation, and environment facts. The selected distribution plan is recorded and can be constrained by the user.

### Mode C — managed training functions

For maximum portability and strategy search, user code exposes pure or well-scoped hooks:

```python
class Program(TrainingProgram):
    def build_model(self, ctx): ...
    def build_data(self, ctx): ...
    def build_optimizer(self, ctx, model): ...
    def train_step(self, ctx, model, batch): ...
    def evaluate_step(self, ctx, model, batch): ...
    def checkpoint_state(self, ctx): ...
```

The driver may choose DDP, FSDP, tensor parallel, pipeline parallel, mixed plans, gradient accumulation, activation checkpointing, or CPU/offload options within a declared compatibility matrix. Strategy selection itself becomes an artifact and eval target.

## 3. Conversion process

“Convert this PyTorch training” means producing a `TrainingPlan` plus a validated adapter mode, not silently rewriting source code.

### 3.1 Inspect

The converter discovers or requests:

- entrypoint and dependency/environment lock;
- model construction and estimated parameter/state sizes;
- dataset references and access pattern;
- existing distributed initialization;
- global/per-device batch semantics;
- optimizer and checkpoint hooks;
- non-rank-safe filesystem/network side effects;
- random number generators and deterministic requirements;
- accelerator/backend compatibility;
- expected outputs and metrics.

Static inspection produces warnings, not authority. Any inferred field is surfaced for confirmation in the generated plan and recorded in evidence.

### 3.2 Package

- source is materialized as a content-addressed code artifact;
- dependencies are locked into an OCI/venv/environment artifact;
- native/CUDA/runtime requirements are declared;
- writable locations become scoped mounts;
- undeclared host paths and network are denied by default;
- secrets become short-lived leases;
- data inputs remain artifact/data-grant references, not copied ad hoc into the image.

### 3.3 Plan distribution

The trainer driver evaluates plans against model/data/resource constraints:

| Strategy | Appropriate when | Kernel-relevant requirements |
|---|---|---|
| Single device | Model and target batch fit; low overhead desired | One lease; normal checkpoint |
| Replicated DDP | Model fits each device; data parallel scaling | Gang/elastic rendezvous; sharded sampler; all-reduce network |
| FSDP | Parameters/gradients/optimizer state do not fit per device | Homogeneous compatible workers; distributed checkpoint |
| Tensor parallel | Individual layers/operations require sharding | Low-latency topology and fixed group semantics |
| Pipeline parallel | Layer partitions and micro-batching are viable | Stage placement, pipeline schedule, failure semantics |
| Hybrid | Large model/fleet and topology warrant combination | Explicit process mesh/topology artifact |
| Parameter server | Sparse/asynchronous or legacy algorithm | Staleness and consistency policy |
| Federated/custom | Data cannot move or algorithm is specialized | Aggregation/privacy/attestation driver contract |

`auto` means “choose among declared-safe strategies using measured/probed constraints,” not “parallelize arbitrary code magically.”

### 3.4 Validate

Before a scaled run, Splendor executes staged probes:

1. import/build-only;
2. one device, one batch;
3. checkpoint round-trip;
4. two processes on one node;
5. two nodes if requested;
6. short loss/gradient parity against single-device baseline;
7. worker-loss/restart probe if elastic;
8. resource and inference-interference probe;
9. full run admission.

The plan can require human approval when parity or numerical drift exceeds tolerance.

## 4. Global batch semantics

A common source of silent training change is confusing per-rank and global batch size. The plan must declare:

```text
micro_batch_per_device
gradient_accumulation_steps
data_parallel_degree
global_batch_size
last_batch/drop policy
sequence/token batch semantics
learning-rate scaling policy
```

The controller checks the identity:

```text
global_batch = micro_batch_per_device
             × gradient_accumulation_steps
             × data_parallel_degree
```

for strategies where this formula applies. A world-size change must either preserve global batch or create an explicit resumed-plan revision with its consequences.

## 5. Dataset sharding and exactly-what-was-trained

The minimum contract records:

- dataset snapshot and split digests;
- shard/group assignment algorithm version;
- epoch and sampler seeds;
- world size and rank membership per attempt;
- drop/repeat policy;
- checkpointed data progress;
- sample/token counts consumed;
- known duplicate/skip ranges after failure, if exact continuation is impossible.

Exactly-once sample consumption is not promised when the algorithm/runtime cannot guarantee it. The evidence states the achieved semantics.

## 6. Checkpoint protocol

A distributed checkpoint is complete only after a manifest commits:

```text
checkpoint_id
parent_checkpoint_id?
workload/attempt/step identities
model state parts
optimizer state parts
scheduler/scaler state
RNG states
sampler/data progress
training-plan and environment refs
worker/process mesh
integrity digests
completeness and compatibility metadata
```

Workers upload parts to a staging namespace. A coordinator commits the immutable manifest only when required parts and integrity checks pass. Stale attempts are fenced from committing a newer logical step.

Resume validation checks code/model/optimizer/schema compatibility. An intentional change creates a new training-plan revision and lineage edge; it is not hidden as a normal resume.

## 7. Elasticity

A training plan declares one of:

- `fixed`: world size cannot change;
- `restart_elastic`: restart from last valid checkpoint with a permitted new world size;
- `in_place_elastic`: trainer supports membership changes at declared safe points;
- `best_effort_map`: independent shards/tasks can join/leave freely.

It also declares minimum/maximum workers, rendezvous timeout, maximum restarts, batch adjustment policy, and which failures are retryable. The scheduler does not guess algorithm safety.

## 8. Heterogeneous fleets

An arbitrary capable device may contribute only when its offer satisfies the workload contract:

- accelerator/backend and required operations;
- memory, compute, network, storage, and topology;
- runtime/driver/environment compatibility;
- data locality and policy;
- uptime/preemption/battery/thermal class;
- attestation/trust level;
- available background capacity after local reservations.

Heterogeneous devices are best used by matching work shape:

- compatible GPU groups for synchronous training;
- CPU/edge nodes for tokenization, quality scans, evaluation shards, simulations, or independent rollouts;
- intermittent devices for idempotent map tasks or federated/custom algorithms;
- high-bandwidth clusters for tightly coupled tensor/FSDP groups;
- device-local inference and safety retain priority.

Splendor should maximize useful fleet work, not force every device into one all-reduce group.

## 9. 1,000-device scheduling example

A notional mixed fleet:

```text
100 latency-critical inference nodes
120 tightly connected training GPUs
280 general GPU/accelerator nodes
350 CPU/desktop/edge nodes
100 robot/drone computers with mission reservations
50 control/storage/evaluation nodes
```

The scheduler hierarchy:

1. node agents publish bounded resource offers, not continuous raw telemetry;
2. regional/site schedulers aggregate offers and locality constraints;
3. global admission assigns workload budgets/classes and selects regions/groups;
4. local schedulers issue leases and form rendezvous groups;
5. node agents enforce cgroups/container/device/network/data boundaries;
6. inference and physical reservations remain local hard constraints;
7. background training/data/eval leases are revoked or resized as live demand rises.

Example concurrent work:

- online GPT-2 inference replicas;
- one 64-GPU training group;
- several 8-GPU fine-tunes;
- 500 independent eval shards;
- tokenization and contamination scans across CPUs;
- RL simulation rollouts on spare accelerators;
- code/shell sandboxes on isolated workers;
- robot-side perception and safety with no background work during mission peaks.

## 10. Inference interference policy

Each live service publishes an `InterferenceBudget`:

```text
reserved accelerator memory and compute fraction
reserved CPU, storage IOPS, network, power, and thermal headroom
latency/error/queue SLOs and forecast window
minimum resident replicas and failure headroom
allowed colocated workload classes
preemption deadline and checkpoint grace
measurement source and confidence
```

Admission evaluates predicted and measured interference. Runtime monitors can throttle/preempt background leases before the live SLO is breached. Nodes may impose stricter local policy.

## 11. Metrics

Metrics are typed records:

```text
name
value and unit
step/epoch/token count
reduction semantics: sum/mean/min/max/histogram/custom
weight/sample count
worker/group identity
time window
model/data/training-plan refs
```

A metric aggregator does not average averages without weights. Missing workers/slices remain visible. Logs are diagnostics; promotion gates consume versioned eval/metric artifacts, not regexes over stdout.

## 12. Rank-safe side effects

The adapter provides helpers and static/runtime checks for:

- single-writer artifact publication;
- rank-specific temporary paths;
- deduplicated external logging;
- distributed barriers only at declared safe points;
- no direct deployment API in training capability scope;
- no arbitrary outbound network unless declared;
- cancellation and signal handling;
- node-local cache with digest verification.

Unrecognized side effects force launcher mode to be marked `unverified` or require a stronger sandbox/gate.

## 13. Kubernetes mapping

A Kubernetes executor may map:

- `WorkloadSpec` to Jobs, Pods, PodGroups/gang scheduling resources, Services for rendezvous, ConfigMaps for non-secret config, Secrets through a broker/CSI path, volumes/artifact fetchers, and priority classes;
- `ExecutionLease` to admitted pod/resource bindings;
- node capabilities/locality to labels, affinities, taints/tolerations, device allocation, and runtime classes;
- preemption/checkpoint policy to priority, disruption, grace, and controller behavior.

Kubernetes is an execution provider. Splendor retains agent/data/model/change semantics and verifies that provider translation did not broaden authority or report success before output/evidence commit.

## 14. Gold tests

The distributed PyTorch gold program must pass:

1. one-device run and checkpoint;
2. two-process DDP loss/gradient parity;
3. two-node launch and rendezvous fencing;
4. global-batch invariant check;
5. rank-safe output assertion;
6. worker crash and restart from complete checkpoint;
7. rejection of partial/stale checkpoint;
8. fixed-workload rejection of world-size change;
9. elastic-workload declared world-size change;
10. protected data access denial;
11. live-inference pressure causing training throttle/preemption without SLO breach;
12. heterogeneous node exclusion and useful reassignment to eval/data work;
13. candidate bundle publication with complete lineage;
14. denial of direct deployment from trainer scope;
15. local, OCI, Kubernetes, and synthetic-fleet executions producing equivalent logical evidence.

## 15. Example material

- `examples/distributed_pytorch/training_plan.yaml`
- `code_examples/train_tiny_transformer.py`
- `proposed_api/python/splendor_vnext/pytorch_adapter.py`
- `proposed_api/python/tests/test_pytorch_adapter.py`

The included adapter code is a contract/reference planner; it does not replace PyTorch's distributed runtime.
