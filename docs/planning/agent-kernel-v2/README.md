# Splendor Agent Kernel v2 Import Provenance

> **Status:** Provenance and archival import notes only. Active 0.2/v2 execution
> rules now live under [`docs/rules/v2/`](../../rules/v2/). This directory is no
> longer an active execution-rule entrypoint.

This directory originally integrated the documentation pack imported from the
user-supplied local archive:

```text
splendor_agent_kernel_v2(3).zip
```

Source archive SHA-256:

```text
b6ac990ee4027fc881ac656e629a498c3e53385d12c15e150f426c7166fa27bf
```

The imported material describes the v2 direction for Splendor as a user-space
agent kernel with stronger identity, authority, artifact lineage,
event/state/evidence, execution fabric, driver boundary, agent runtime,
learning-control, and change/governance planes.

## Active Rule Entrypoint

Do not use this planning directory as an active execution rule source. Use these
files for active 0.2/v2 work:

1. [`../../rules/v2/README.md`](../../rules/v2/README.md) - 0.2/v2 rule-pack entrypoint.
2. [`../../rules/v2/0.2-execution-sprints.md`](../../rules/v2/0.2-execution-sprints.md) - grouped execution sprints for issues #141-#155.
3. [`../../rules/v2/catalog/complete_implementation_task_catalog.md`](../../rules/v2/catalog/complete_implementation_task_catalog.md) - v2 catalog of record.
4. [`../../rules/v2/catalog/implementation_task_index.md`](../../rules/v2/catalog/implementation_task_index.md) - compact task index.
5. [`../../rules/v2/architecture/schema-identity-map.md`](../../rules/v2/architecture/schema-identity-map.md) - 0.1 to 0.2/v2 schema compatibility map.
6. [`../../rules/v2/gold/gold-conformance-triage.md`](../../rules/v2/gold/gold-conformance-triage.md) - gold/conformance triage.

## Imported source material

- `imported/06_external_contracts.md` - imported source material retained as provenance.
- `imported/proposed_api/` - imported proposed API material retained as provenance.
- `imported/validation/` - validation of the source pack, not validation of repository implementation.
- `diagrams/*.svg` — rendered diagrams that were actually present in the archive.
- `import-manifests/*.sha256` — source-pack provenance manifests. These are not
  current-file integrity checks after repository wrapping, banner insertion, and
  path renaming.

The archive also contained generator/checker scripts under `tools/`. Those were
not imported as executable repository tooling in this docs-only integration. If
Splendor adopts any of those tools, that work should be a separate PR with tests,
CI wiring, rollback notes, and architecture-rule acceptance criteria.

## Moved Active Material

The active execution, catalog, architecture, and gold rule material was moved to
`docs/rules/v2/` so 0.2/v2 work has an unambiguous rule-pack location.

Moved examples:

- `imported/14_complete_implementation_task_catalog.md` -> `../../rules/v2/catalog/complete_implementation_task_catalog.md`
- `imported/15_implementation_task_index.md` -> `../../rules/v2/catalog/implementation_task_index.md`
- `gold-conformance-triage.md` -> `../../rules/v2/gold/gold-conformance-triage.md`
- `0.1-vnext-schema-identity-map.md` -> `../../rules/v2/architecture/schema-identity-map.md`
- `architecture-policy-plan.md` -> `../../rules/v2/architecture/architecture-policy-plan.md`

## Evidence Boundary

Moving active material to `docs/rules/v2/` makes it authoritative for 0.2/v2
decomposition and sprint planning. It does not make 0.2/v2 runtime behavior
implemented. Each 0.2/v2 task still needs implementation, tests, docs/examples,
and retained validation evidence before completion can be claimed.

## Known Import Caveats

- The source pack's diagram index referenced additional Mermaid, DOT, SVG, and PNG assets that were not present in the archive. Only present SVGs remain under [`diagrams/`](diagrams/).
- Gold examples are specified contracts. They are not conformance evidence until runnable harnesses exist and pass.

## Initial issue plan

The 381 imported catalog tasks are intentionally grouped into reviewable epics
and planning issues rather than copied into hundreds of separate tickets:

Issue links use GitHub's current canonical repository URL for this repository.

- [#135](https://github.com/splendor-kernel/kernel/issues/135) — Epic: Align v2 agent-kernel catalog with current Splendor roadmap.
- [#136](https://github.com/splendor-kernel/kernel/issues/136) — Plan vNext schema and identity grammar without breaking 0.1 primitives.
- [#137](https://github.com/splendor-kernel/kernel/issues/137) — Plan machine-enforced architecture ownership and dependency policy.
- [#138](https://github.com/splendor-kernel/kernel/issues/138) — Triage v2 gold examples into 0.1 conformance and 0.2/v2 suites.
- [#139](https://github.com/splendor-kernel/kernel/issues/139) — Plan idempotent service/API semantics for vNext without daemon drift.
- [#140](https://github.com/splendor-kernel/kernel/issues/140) — Epic: vNext identity, authority, data-use, and secrets plane; see draft [`RFC 0008`](../../rfc/0008-vnext-identity-authority-data-use-secrets-plane.md).
- [#141](https://github.com/splendor-kernel/kernel/issues/141) — Epic: vNext event, state, evidence, replay, and observability plane.
- [#142](https://github.com/splendor-kernel/kernel/issues/142) — Epic: vNext workload fabric, node, fleet, lease, and scheduler plane.
- [#143](https://github.com/splendor-kernel/kernel/issues/143) — Epic: vNext driver registry, gateway, and driver profiles.
- [#144](https://github.com/splendor-kernel/kernel/issues/144) — Epic: vNext agent runtime, messages, delegation, routes, and world-state.
- [#145](https://github.com/splendor-kernel/kernel/issues/145) — Epic: vNext data, feedback, reward, evaluation, training, and improvement plane.
- [#146](https://github.com/splendor-kernel/kernel/issues/146) — Epic: vNext change, gate, deployment, rollback, and incident plane.
