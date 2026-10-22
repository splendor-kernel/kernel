# Splendor Active Roadmap, FRs, and Sprint Rules

**Date:** 2026-06-22
**Audience:** Splendor implementation agents, architecture agents, runtime agents, SDK agents, orchestration agents, integration agents, and review agents.
**Primary intent:** Define the active 0.2/v2 implementation, QA, integration, and gold-example execution entrypoint while preserving the implemented 0.1 baseline.

---

## 0. Source-of-Truth Position

Splendor remains an **AI autonomy runtime kernel / management layer**, not a
chat-agent framework, not an enterprise SaaS control plane, and not a robot's
hard real-time controller.

The runtime model remains:

```text
Percepts -> Policy -> Constraints -> Gateway -> Adapter -> Outcome -> State Commit -> Trace
```

The active work line is now `0.2/v2`. The `0.01-0.1` line is the implemented and
stable baseline. Full baseline sprint history and acceptance context are
preserved in
[`docs/rules/legacy/0.1-sprints_frs_milestones.md`](legacy/0.1-sprints_frs_milestones.md).

This file intentionally does not repeat all legacy 0.01-0.1 sprint detail. It is
the current active roadmap entrypoint.

---

## 1. Current Status

| Line | Status | Rule |
| --- | --- | --- |
| `0.01-dev` through `0.05-dev` | Historical development milestones that fed the baseline | Keep acceptance history in the legacy roadmap; do not delete it. |
| `0.1-dev` | Implemented/stable primitive baseline and compatibility line | Preserve compatibility unless current code and test evidence plus accepted RFC/migration work say otherwise. |
| `0.2/v2` | Active implementation, QA, integration, and gold-example execution line | Use `docs/rules/v2/` for decomposition, sprint sequencing, catalog coverage, and gold planning after higher-priority constraints. |

Moving 0.2/v2 material into `docs/rules/v2/` changes planning authority and file
organization only. It does not mean proposed 0.2/v2 runtime behavior is
implemented.

---

## 2. Source Hierarchy

For all work, follow this conflict order:

1. `AGENTS.md`.
2. `docs/rules/splendor_dev_model.md`.
3. `docs/rules/verifiable_criteria/main.md` and applicable sprint/acceptance rule packs.
4. This active roadmap entrypoint.
5. Accepted RFCs, stable specs, release limitations, and public API/schema contracts.
6. `docs/rules/v2/*` for active 0.2/v2 decomposition, sprint sequencing, and catalog coverage.
7. `docs/rules/legacy/0.1-sprints_frs_milestones.md` for preserved baseline detail and acceptance history.
8. Reference docs, guides, examples, and comments where they do not conflict with higher-priority sources.

`docs/rules/v2/` is authoritative only for 0.2 decomposition, sprint sequencing,
and catalog coverage. It cannot override accepted RFCs, stable specs, public
schemas, public API contracts, release limitations, AGENTS safety invariants,
gateway/verifier contracts, or RFC requirements.

---

## 3. Active Rule Pack

Required for 0.2/v2 work:

```text
docs/rules/v2/README.md
docs/rules/v2/0.2-execution-sprints.md
docs/rules/v2/catalog/complete_implementation_task_catalog.md
docs/rules/v2/catalog/implementation_task_index.md
docs/rules/v2/architecture/schema-identity-map.md
docs/rules/v2/gold/gold-conformance-triage.md
```

Supporting v2 details remain under:

```text
docs/rules/v2/architecture/
docs/rules/v2/catalog/
docs/rules/v2/gold/
```

These files preserve the large v2 catalog, architecture, gold, and machine-readable
source material. Do not summarize away or delete that detail.

---

## 4. Implementation-Agent Workflow

Every task must state:

```text
Milestone: Splendor0.2-dev / 0.2/v2 active execution
Sprint: V2-...
Functional requirements touched: FR-0.2-...
V2 catalog task IDs touched: FND-..., IDR-..., AUTH-..., etc.
Primitives strengthened: ...
```

If a task cannot be tied to at least one `FR-0.2-*` bridge ID and at least one
v2 sprint/task ID, do not implement it yet. If the task is purely legacy 0.1
maintenance, cite the legacy FR from
[`docs/rules/legacy/0.1-sprints_frs_milestones.md`](legacy/0.1-sprints_frs_milestones.md)
and explain why it is not 0.2/v2 work.

Before coding, declare non-goals and confirm that the change preserves:

- gateway mediation for all side effects;
- verifier fail-closed behavior;
- explicit state commits;
- append-only trace contract;
- safe replay by default;
- identity separation;
- no permission laundering;
- secure daemon/client communication;
- high-level physical/device boundary.

---

## 5. 0.2/v2 Functional Requirement Bridge

0.2/v2 work must cite both applicable `FR-0.2-*` IDs and exact v2 sprint/task IDs
from `docs/rules/v2/`.

| ID | Requirement | Primary v2 sprint groups |
| --- | --- | --- |
| FR-0.2-01 | Establish foundations for schema compatibility, non-authorizing extensions, package ownership, failure taxonomy, conformance harness scope, migration fixtures, redaction, security invariants, and performance budgets. | `V2-FND-*` |
| FR-0.2-02 | Implement identity, authority, secret-reference, and data-use controls without widening tenant, agent, run, or gateway authority. | `V2-IA-*` |
| FR-0.2-03 | Implement artifact, lineage, event, state, evidence, replay/simulation, and observability services with explicit state, append-only traces, safe replay, and retained evidence. | `V2-AL-*`, `V2-ESE-*` |
| FR-0.2-04 | Implement execution fabric and driver boundaries for workloads, nodes, placement, leases, driver registry/gateway, sandbox/executor, model, trainer, evaluator, data, perceptor, actuator, and physical-safety profiles. | `V2-EF-*`, `V2-DB-*` |
| FR-0.2-05 | Implement agent runtime, route/world state, message, and delegation services while preserving scoped authority, trace-linked causality, explicit state, and no permission laundering. | `V2-AG-*` |
| FR-0.2-06 | Implement data collection, feedback, reward derivation, evaluation, training, and improvement controls with separated authority and candidate-only training outputs. | `V2-DL-*` |
| FR-0.2-07 | Implement change, gate, deployment, rollback, and incident controls with evidence-backed activation, rollback, and no self-approval. | `V2-CG-*` |
| FR-0.2-08 | Implement gold/conformance, security, performance, compatibility, and operations coverage that proves 0.2 behavior without treating skipped or specified-only cases as passing. | `V2-INT-*`, `V2-NOV-*`, gold `G00`-`G89` |

---

## 6. Active Sprint Model

The detailed sprint model lives in
[`docs/rules/v2/0.2-execution-sprints.md`](v2/0.2-execution-sprints.md). It groups
12 foundations, 38 component owners, 350 component tasks, 19
integration/research/operations programs, and 90 gold cases into reviewable
sprint slices.

Do not create 381 one-task GitHub issues. Future issue creation should happen as
bounded child issues linked to the appropriate #141-#155 epic or successor epic.
This docs-preparation assignment must not create GitHub issues.

Each 0.2/v2 implementation PR or issue should include:

- one or more `FR-0.2-*` IDs;
- one or more `V2-*` sprint IDs;
- exact catalog task IDs;
- relevant gold IDs where applicable;
- evidence required before closure;
- explicit non-goals.

Do not close a 0.2/v2 task from documentation alone. Closure requires retained
implementation evidence: code, tests, docs/examples, migration notes when needed,
and validation output for the exact behavior.

---

## 7. 0.1 Baseline Preservation

The legacy baseline docs remain required context for compatibility work:

```text
docs/rules/legacy/0.1-sprints_frs_milestones.md
docs/spec/0.1/
docs/rules/verifiable_criteria/
docs/releases/known-limitations.md
```

0.2/v2 work may extend or migrate baseline primitives only through accepted RFCs
where required, compatibility fixtures, and explicit migration notes. It must not
silently break 0.1 examples, clients, conformance fixtures, state formats, trace
contracts, gateway semantics, verifier behavior, or replay safety.

---

## 8. Non-Goals For This Active Roadmap

```text
no deletion of legacy 0.01-0.1 detail
no runtime implementation claim from moved docs
no 381 issue explosion
no side-effect bypass
no hidden mutable state
no replay side effects by default
no permission laundering through shared or specialist agents
no direct low-level physical control
no self-activation by training, evaluation, or improvement loops
no enterprise SaaS/control-plane product buildout inside the kernel
```

---

## 9. PR Template For Active Work

```md
# PR Title

## Milestone and Sprint

- Milestone:
- Sprint:
- FRs / v2 catalog task IDs:
- Primitives strengthened:

## Summary

Describe the smallest primitive-aligned change.

## Non-Goals

-
-

## Runtime Loop Impact

- Percepts:
- Policy:
- Constraints / verifiers:
- Gateway:
- Adapters / drivers:
- Outcomes:
- State:
- Trace:
- Replay:

## Security / Isolation Impact

- Tenant scope:
- Agent scope:
- Run scope:
- Workload / node / instance scope:
- Quotas:
- Permissions:
- Fail-closed paths:

## Tests And Evidence

- Positive path:
- Denial path:
- Failure path:
- Trace path:
- State path:
- Replay path:
- Compatibility path:
- Gold/conformance path:

## Docs / Examples

- Updated docs:
- Updated examples:
- Migration notes:

## Review Checklist

[ ] No side-effect bypass.
[ ] Trace events are complete.
[ ] State transition is explicit.
[ ] Replay behavior is safe.
[ ] Verifier failure fails closed.
[ ] 0.1 compatibility impact is documented.
[ ] 0.2/v2 catalog task IDs and evidence are linked.
[ ] Scope did not leak outside the active sprint.
```

---

## 10. Suggested Issue Labels

```text
milestone/0.2-dev
primitive/gateway
primitive/verifier
primitive/state-graph
primitive/trace-store
primitive/replay
primitive/message
primitive/work-order
primitive/fleet
primitive/governance
primitive/adapter
primitive/sdk
primitive/physical-edge
risk/security
risk/compatibility
risk/distributed-state
risk/physical-safety
risk/side-effects
risk/replay
type/schema
type/runtime
type/sdk
type/docs
type/test
type/example
```

Legacy labels and older sprint IDs remain documented in
[`docs/rules/legacy/0.1-sprints_frs_milestones.md`](legacy/0.1-sprints_frs_milestones.md)
for baseline maintenance.

---

## 11. Final Sequencing Rule

Correct current order:

```text
preserve 0.1 baseline compatibility
  -> use accepted RFCs/stable specs/public contracts for schema/API changes
  -> execute 0.2/v2 foundations
  -> implement 0.2/v2 component slices
  -> prove behavior through tests, integration, and gold/conformance evidence
  -> update docs/examples and migration notes
```

Do not jump from catalog rows directly to runtime-complete claims. Splendor must
remain explicit over magical, traceable over convenient, fail-closed over
permissive, and local-correct before distributed.
