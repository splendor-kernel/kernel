# Splendor Agent Kernel v2 Planning Pack

> **Status:** vNext planning import. This directory is not part of the stable
> Splendor 0.1 implementation contract and is not evidence that the current
> repository implements the behavior described here.

This directory integrates the documentation pack imported from the user-supplied
local archive:

```text
splendor_agent_kernel_v2(3).zip
```

Source archive SHA-256:

```text
b6ac990ee4027fc881ac656e629a498c3e53385d12c15e150f426c7166fa27bf
```

The imported material describes a proposed post-0.1 direction for Splendor as a
user-space agent kernel with stronger identity, authority, artifact lineage,
event/state/evidence, execution fabric, driver boundary, agent runtime,
learning-control, and change/governance planes.

## Authority and scope

The following remain authoritative until an RFC is accepted and implemented:

1. `AGENTS.md`
2. `docs/rules/splendor_dev_model.md`
3. `docs/rules/sprints_frs_milestones.md`
4. `docs/rules/verifiable_criteria/*`
5. `docs/spec/0.1/*`
6. `docs/releases/known-limitations.md`

The imported docs deliberately do **not** change stable 0.1 schemas, daemon API
semantics, gateway behavior, verifier behavior, state/trace formats, replay
semantics, physical/edge safety boundaries, or current crate ownership.

## Reading order

Start with these files:

1. [`../README.md`](../README.md) — planning-document rules.
2. [`../../rfc/0006-agent-kernel-v2-lifecycle.md`](../../rfc/0006-agent-kernel-v2-lifecycle.md) — RFC framing for this import.
3. [`imported/00_architecture.md`](imported/00_architecture.md) — vNext architecture overview.
4. [`imported/01_core_abstractions.md`](imported/01_core_abstractions.md) — proposed object model.
5. [`imported/16_clean_architecture_rules.md`](imported/16_clean_architecture_rules.md) — proposed architecture constitution; non-normative in this repository until accepted by RFC.
6. [`imported/15_implementation_task_index.md`](imported/15_implementation_task_index.md) — navigable index for the 381-task catalog.
7. [`imported/14_complete_implementation_task_catalog.md`](imported/14_complete_implementation_task_catalog.md) — full source task catalog.

## Imported source material

- `imported/*.md` — wrapped source-pack markdown with a status banner.
- `imported/architecture/components.yaml` — proposed component registry.
- `imported/architecture/implementation_tasks.yaml` — machine-readable task catalog.
- `imported/architecture/dependency_policy.proposed.json` — proposed dependency policy; not active CI policy.
- `imported/architecture/change_impact_manifest.proposed.schema.json` — proposed impact manifest schema.
- `imported/examples/gold/catalog.yaml` — proposed gold example catalog. Entries are specified future contracts, not passing tests.
- `diagrams/*.svg` — rendered diagrams that were actually present in the archive.
- `validation/*.md` inside `imported/validation/` — validation of the source pack, not validation of repository implementation.
- `import-manifests/*.sha256` — source-pack provenance manifests. These are not
  current-file integrity checks after repository wrapping, banner insertion, and
  path renaming.

The archive also contained generator/checker scripts under `tools/`. Those were
not imported as executable repository tooling in this docs-only integration. If
Splendor adopts any of those tools, that work should be a separate PR with tests,
CI wiring, rollback notes, and architecture-rule acceptance criteria.

## Non-goals for this import

- No new Rust crates or package moves.
- No stable schema changes.
- No daemon API changes.
- No replacement of the Action Gateway with a new runtime path.
- No implementation claim for training, fleet-scale execution, universal driver
  fabric, self-evolution, production robotics, or adapter certification.
- No CI enforcement of the proposed dependency policy yet.

## Known import caveats

- The source pack uses vNext terms such as `Driver Gateway`, `WorkloadSpec`,
  `EventEnvelope`, and `StateCommit`. In current stable docs, side effects still
  go through `ActionRequest`, the Action Gateway, verifiers, and adapters.
- The source pack assumes a wider post-0.1 component map than the repository
  currently implements. Treat those packages/components as proposals requiring
  RFCs.
- The source pack's diagram index referenced additional Mermaid, DOT, SVG, and
  PNG assets that were not present in the archive. Only present SVGs were
  imported under [`diagrams/`](diagrams/).
- The gold examples are specified planning contracts. They are not conformance
  evidence until runnable harnesses exist and pass.

## How this should become implementation work

Use GitHub issues and RFCs to convert this pack into bounded work:

1. Map vNext concepts to existing milestone/sprint IDs and FRs.
2. Mark each proposed change as an extension, migration, replacement, or
   post-0.1 RFC requirement.
3. Define acceptance criteria with success, denial, failure, trace, state,
   replay, compatibility, and fail-closed evidence.
4. Implement in the normal milestone order: local correctness → multi-agent and
   daemon control → resident/fleet foundation → governance → physical/edge →
   stable spec evolution.

## Initial issue plan

The 381 imported catalog tasks are intentionally grouped into reviewable epics
and planning issues rather than copied into hundreds of separate tickets:

Issue links use GitHub's current canonical repository URL for this repository.

- [#135](https://github.com/splendor-kernel/kernel/issues/135) — Epic: Align v2 agent-kernel catalog with current Splendor roadmap.
- [#136](https://github.com/splendor-kernel/kernel/issues/136) — Plan vNext schema and identity grammar without breaking 0.1 primitives.
- [#137](https://github.com/splendor-kernel/kernel/issues/137) — Plan machine-enforced architecture ownership and dependency policy.
- [#138](https://github.com/splendor-kernel/kernel/issues/138) — Triage v2 gold examples into 0.1 conformance and post-0.1 suites.
- [#139](https://github.com/splendor-kernel/kernel/issues/139) — Plan idempotent service/API semantics for vNext without daemon drift.
- [#140](https://github.com/splendor-kernel/kernel/issues/140) — Epic: vNext identity, authority, data-use, and secrets plane.
- [#141](https://github.com/splendor-kernel/kernel/issues/141) — Epic: vNext event, state, evidence, replay, and observability plane.
- [#142](https://github.com/splendor-kernel/kernel/issues/142) — Epic: vNext workload fabric, node, fleet, lease, and scheduler plane.
- [#143](https://github.com/splendor-kernel/kernel/issues/143) — Epic: vNext driver registry, gateway, and driver profiles.
- [#144](https://github.com/splendor-kernel/kernel/issues/144) — Epic: vNext agent runtime, messages, delegation, routes, and world-state.
- [#145](https://github.com/splendor-kernel/kernel/issues/145) — Epic: vNext data, feedback, reward, evaluation, training, and improvement plane.
- [#146](https://github.com/splendor-kernel/kernel/issues/146) — Epic: vNext change, gate, deployment, rollback, and incident plane.
