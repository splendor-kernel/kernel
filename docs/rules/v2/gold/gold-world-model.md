> **Status:** Active 0.2/v2 gold program source. This file defines a future gold path after the higher-priority safety, accepted-RFC, stable-spec, public-contract, and release-limitation hierarchy. It is not evidence that the repository implements or passes the described behavior.

# Gold Program: Agent and World Modeling with Neural and Symbolic Components

This program proves that Splendor can host a complete, persistent agent architecture without reducing “agent state” to a callback-local JSON object. The reference environment is a small warehouse/gridworld simulation that can later map to a robot driver without changing high-level contracts.

## 1. Gold objective

The agent must:

- receive asynchronous visual, position, inventory, battery, task, and human percepts;
- maintain explicit facts, hypotheses, uncertainty, goals, obligations, and episodic history;
- use a learned perception/transition/value component alongside symbolic maps, constraints, and planning;
- run simulations/rollouts without reaching live actuators;
- delegate bounded subtasks to specialist agents;
- act through verified high-level commands;
- learn from outcomes and human corrections;
- produce candidate model/route/world-schema changes without modifying the live agent in place;
- continue through restart, disconnection, late percepts, and conflicting observations.

## 2. World model is not one object

“World model” is an overloaded term. Splendor should distinguish:

| Object | Meaning | Example |
|---|---|---|
| `WorldSchema` | Types, fields, relations, constraints, temporal rules | `Robot`, `Shelf`, `Zone`, `at(robot, zone)` |
| `WorldStateHead` | Current governed version pointer | `warehouse/world@rev-81` |
| `WorldAssertion` | Fact, hypothesis, prediction, goal, or obligation with provenance | “aisle-3 blocked, confidence .82” |
| `WorldSnapshot` | Immutable materialization for restore/eval/simulation | state at tick 41,002 |
| `LatentState` | Model-specific internal representation artifact/reference | perception embedding, transition hidden state |
| `TransitionModel` | Learned or symbolic predictor of next-state distribution | action-conditioned dynamics model |
| `ObservationModel` | Mapping from external evidence to hypotheses | camera detector + calibration |
| `PlannerModel` | Search/optimization policy over world hypotheses | A*, MCTS, neural planner |
| `MemoryIndex` | Search structure over episodic/semantic artifacts | vector/graph index revision |

The kernel standardizes identity, provenance, ownership, state transitions, access, and evidence. User-space code chooses representation and algorithms.

## 3. State partitions

The example agent declares:

| Partition | Contents | Writer | Readers | Rollback/retention |
|---|---|---|---|---|
| `runtime_control` | lifecycle, inbox cursor, active revision, health | instance controller | kernel controllers | strong rollback; durable |
| `world_facts` | verified map/pose/inventory facts | world-state service after evidence/gates | planner, safety, UI | versioned; conflict-aware |
| `world_hypotheses` | uncertain detections/predictions | route/world components | planner, evaluators | TTL and confidence decay |
| `goals_obligations` | tasks, deadlines, promises, approvals | task/governance components | route, humans | explicit completion/cancel |
| `episodic_memory` | event/episode refs and summaries | memory policy | route/eval/data controller | retention/data policy |
| `semantic_memory` | derived knowledge artifacts/index refs | governed data/model workloads | route | immutable index revisions |
| `policy_state` | planner/controller state | policy component | route | deployed revision compatibility |
| `learning_state` | drift, feedback aggregates, improvement status | learning controllers | monitors/gates | not action authority |
| `private_scratch` | ephemeral implementation-local work | current workload only | same workload | non-durable by default |
| `secrets` | no state payload; secret references only | secret broker | authorized boundary | leased and non-exportable |

Partition declarations include schema, writer principal/operation, conflict strategy, replication/locality, retention, export/training policy, and migration compatibility.

## 4. Assertion model

Every governed assertion contains:

```text
assertion_id
kind: fact | hypothesis | prediction | goal | obligation | constraint | preference
subject/predicate/object or typed payload
effective time and observation time
provenance event/artifact refs
producer component/model/route revision
confidence and calibration context
validity/TTL and revalidation rule
supporting and contradicting assertion refs
scope and visibility
data-use/training policy
status: active | superseded | retracted | expired | disputed
```

A camera classifier emits a hypothesis. A calibrated localization pipeline plus device evidence may produce a fact under policy. A language model statement never becomes a fact merely because it is fluent.

## 5. Perception flow

1. Perceptor drivers emit typed events with source clock, sequence, freshness, calibration/quality, and payload refs.
2. The event service orders by receipt while preserving source/event time.
3. A fusion workload consumes an explicit window and current world head.
4. Neural components produce detections/embeddings/distributions.
5. Symbolic checks enforce type, geometry, temporal, and domain constraints.
6. The route proposes new/retracted assertions with evidence and expected world head.
7. The world-state service validates writer scope and commits atomically or returns a conflict.
8. Late or contradictory evidence follows the declared reconciliation policy; it does not silently overwrite history.

## 6. Neuro-symbolic decision route

The canonical route is illustrative, not mandatory:

```text
trigger (task/percept/timer)
 -> load bounded world view + obligations
 -> symbolic risk/task classification
 -> neural observation/semantic interpretation
 -> assertion proposal and world-state commit
 -> symbolic goal decomposition
 -> neural heuristic/value/candidate generation
 -> planner/solver search under hard constraints
 -> simulation/transition-model rollouts
 -> critic/evaluator and uncertainty check
 -> human review when obligation/risk demands
 -> high-level ActionProposal
 -> capability + policy + physical safety gates
 -> actuator driver
 -> outcome/percepts/feedback
 -> state/evidence commit
```

Each crossing emits a `RouteStepEvent` with inputs/outputs by reference, component version, workload/invocation, duration/resource usage, and causal parents. The event can omit private internal reasoning while preserving externally relevant decisions and evidence.

## 7. Hard, soft, and learned control

- **Hard invariants** are fail-closed conditions: geofence, collision envelope, forbidden zone, capability, maximum load, emergency stop.
- **Obligations** require follow-up or escalation: obtain approval, return to dock, notify operator, revalidate stale map.
- **Soft preferences** contribute to optimization: energy, travel time, task priority, comfort.
- **Learned scores** estimate uncertainty, value, transition, perception, or feasibility; they do not override hard rules.
- **Human decisions** are scoped evidence and may authorize only what their role/scope permits.

The planner receives these as typed inputs so a high neural score cannot accidentally erase a symbolic veto.

## 8. Simulation and rollouts

A rollout is a `SimulationWorkload` with:

- exact starting `WorldSnapshot`;
- model/planner/policy/route revisions;
- environment/transition artifacts and seeds;
- horizon, branch/budget, termination rules;
- simulated driver namespace and `simulation` effect class;
- output trajectory/reward/risk artifacts;
- no capability accepted by live actuator drivers.

Rollouts may support planning, RL data, counterfactual evaluation, failure analysis, or candidate comparison. Simulated outcomes are not reported as real-world facts.

## 9. RL support

The gold program includes a small RL loop:

1. active policy revision produces versioned simulation or environment rollouts;
2. each trajectory records policy/model/world/env versions and behavior probabilities where needed;
3. environment outcomes, human corrections, and safety events become feedback—not automatically rewards;
4. a versioned `RewardDerivation` creates task, safety, efficiency, and uncertainty signals with separate channels;
5. a trainer driver runs PPO/offline/value/model-based/custom algorithm in user space;
6. output is a policy/model `CandidateBundle`;
7. protected eval includes held-out layouts/seeds, safety adversaries, distribution shift, and real/simulation gap;
8. change/deployment controllers shadow/canary the candidate;
9. online safety remains symbolic/local even if the learned policy regresses.

Training algorithms remain drivers/user space; trajectory, data-use, reward, eval, candidate, and activation primitives are kernel contracts.

## 10. Sub-agents

Reference roles:

- **Task planner:** decomposes warehouse objective.
- **Perception specialist:** interprets ambiguous observations.
- **Route critic:** searches for constraint/risk failures.
- **Inventory specialist:** reads a narrow inventory scope.
- **Human liaison:** creates structured review requests.

The parent issues a `DelegationGrant` with target agent, allowed operations/data refs, maximum work/resources/time, permitted return schema, and expiry. The child receives no actuator capability unless explicitly required and cannot redelegate beyond the ceiling.

A sub-agent may act as:

- an invoked service/actuator-like specialist;
- a perceptor/monitor that emits observations;
- an independently scheduled persistent agent;
- a one-shot sandbox workload;
- a critic/evaluator with isolated data access.

All patterns use typed messages, causality, and explicit authority.

## 11. Physical transition

The same high-level contract can target simulation or a robot:

```text
warehouse.motion.v1
  navigate_to(zone)
  pick(item, shelf)
  place(item, station)
  stop(reason)
```

Simulation driver:

- predicts/emulates outcome;
- uses simulation capability;
- can accelerate time;
- cannot access physical device endpoints.

Robot driver:

- requires device-scoped capability/lease;
- runs device-local pre/post safety verification;
- maps only high-level operations to local autonomy/controller APIs;
- exposes emergency/degraded/telemetry state;
- buffers evidence during disconnection;
- rejects expired/cloud-helper/simulation authority.

Low-level motor control and hard real-time safety remain in certified/local systems, not the cloud agent kernel.

## 12. Feedback, data, and continual improvement

Sources include task success, collision/near-miss, time/energy, operator correction, inventory mismatch, perception uncertainty, plan infeasibility, and downstream task failure.

The learning controller can create bounded plans for:

- collecting disputed/low-confidence observations;
- labeling/correcting world assertions;
- updating perception or transition models;
- changing route/planner heuristics;
- refreshing map/schema/index artifacts;
- retraining policy/value/reward models;
- adding a symbolic invariant after an incident.

Each proposal states its target metric/value objective, allowed change class, data uses, risk, budget, protected evals, rollout plan, and stop/rollback criteria.

## 13. Required eval suites

- perception accuracy/calibration by source, lighting, zone, object, and drift slice;
- world-state consistency, conflict handling, TTL, late-data behavior;
- transition-model multi-step error and uncertainty;
- planner success/cost and hard-constraint compliance;
- held-out layout/object/task generalization;
- adversarial/noisy/missing sensor cases;
- simulation-to-real gap or simulation perturbation robustness;
- sub-agent authority and message-schema attacks;
- offline/disconnected/lease-expiry behavior;
- action postcondition and incident recovery;
- latency/resource/thermal behavior on device;
- catastrophic forgetting and data contamination after updates.

## 14. Failure scenarios

1. Camera says aisle clear; proximity sensor says blocked.
2. Localization event arrives late after the robot moved.
3. Learned planner proposes a shorter path through a forbidden zone.
4. Transition model is overconfident outside training layouts.
5. Parent delegates inventory read; child attempts robot move.
6. Cloud connection drops after plan approval but before action.
7. Policy cache expires during a mission.
8. Training workload causes thermal pressure on a robot computer.
9. World-schema candidate cannot read old snapshots.
10. Canary policy increases task success but near-miss rate rises.
11. Rollback restores software but a physical item is already misplaced.
12. Agent attempts to mark a hypothesis as fact without qualifying evidence.

Each has a declared safe outcome and evidence assertion.

## 15. Acceptance criteria

The program passes when it can demonstrate:

- explicit world partitions and conflict-safe commits;
- facts/hypotheses/predictions/goals/obligations with provenance;
- arbitrary neural-symbolic route code with typed crossings;
- simulation rollouts that cannot reach live actuators;
- RL data/training/eval/candidate lifecycle;
- narrow sub-agent delegation;
- restart/disconnection/late-event correctness;
- local physical veto and emergency stop in simulation;
- ongoing feedback/data work and a controlled candidate update;
- progressive rollout and rollback with honest physical-effect semantics;
- complete causal lineage from percept through assertion, plan, action, outcome, feedback, training, and deployment.

Future implementation/gold-example issues should add an illustrative `AgentSpec`
fixture such as `examples/world_model/agent.yaml`. That file is not present or
active in this docs-only integration and cannot support a pass or implementation
claim until executable fixtures and retained evidence exist.
