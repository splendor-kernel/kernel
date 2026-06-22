# Splendor 0.2 / v2 Rule Pack

> **Status:** Active 0.2/v2 execution rule pack. Splendor 0.1 is the
> implemented/stable baseline. 0.2/v2 work is now active and must use this rule
> pack for decomposition, sprint sequencing, and gold/conformance planning.

This directory contains the active 0.2/v2 execution rules moved out of the old
planning import directory. The move changes planning authority and file
organization only. It does not make any 0.2/v2 runtime behavior implemented.

Some imported source material still uses the historical term `vNext`. In active
rules, read that as the 0.2/v2 planning vocabulary unless the file is explicitly
marked as provenance or archival import material.

## Source Hierarchy

For 0.2/v2 work, follow this order:

1. `AGENTS.md` for non-negotiable runtime invariants and repository-wide agent instructions.
2. `docs/rules/splendor_dev_model.md` for the Splendor runtime model.
3. `docs/rules/verifiable_criteria/*` for applicable acceptance and conformance criteria.
4. `docs/rules/sprints_frs_milestones.md` for milestone discipline.
5. Accepted RFCs, stable specs, release limitations, and public API/schema contracts for implementation-specific contracts.
6. `docs/rules/v2/README.md` and `docs/rules/v2/0.2-execution-sprints.md` for active 0.2/v2 decomposition and sprint order.
7. `docs/rules/v2/catalog/complete_implementation_task_catalog.md` and `docs/rules/v2/catalog/implementation_task_index.md` for component/task/gold coverage.
8. `docs/rules/v2/architecture/*` and `docs/rules/v2/gold/*` for architecture and gold-case detail.
9. Reference docs, guides, examples, and comments for implementation detail where they do not conflict with higher-priority sources.

If this rule pack conflicts with the safety invariants in `AGENTS.md` or the
core runtime model in `docs/rules/splendor_dev_model.md`, the safety invariant
wins. If this rule pack conflicts with an accepted RFC, stable spec, public
schema, public API contract, release limitation, gateway/verifier contract, or
RFC requirement, that higher-priority contract wins. Open an RFC or docs issue
before changing a primitive, public schema, trace event, state format, daemon
API, gateway contract, verifier pipeline, SDK contract, governance semantic, or
physical/device action model.

## Active Work Statement

0.1 is the implemented/stable baseline for compatibility and conformance. 0.2 is
the active execution line for v2 work. The 0.2 rule pack exists to turn the v2
catalog into bounded implementation, RFC, conformance, documentation, and gold
evidence assignments.

The catalog is authoritative only for 0.2 decomposition, sprint sequencing, and
catalog coverage. It cannot override accepted RFCs, stable specs, public
schemas, public API contracts, release limitations, AGENTS safety invariants,
gateway/verifier contracts, or RFC requirements. It is not implementation
evidence. A v2 task is complete only after code, tests, docs/examples, migration
notes where needed, and retained validation evidence prove the exact behavior.

## Issue Tracking Expectations

The catalog intentionally contains hundreds of detailed tasks. Do not create 381
one-task GitHub issues. Future tracking should use bounded child issues linked to
the relevant #141-#155 epic or successor epic, with each issue naming the
applicable `FR-0.2-*` bridge IDs, `V2-*` sprint IDs, catalog task IDs, gold IDs
where relevant, and required evidence.

Do not close a 0.2/v2 task because it is listed in this rule pack. Closure
requires retained implementation evidence for the exact behavior: code, tests,
docs/examples, migration notes when needed, and validation output.

## Directory Map

- `0.2-execution-sprints.md` - grouped sprint plan for issues #141-#155 and the 0.2/v2 task graph.
- `catalog/complete_implementation_task_catalog.md` - catalog of record for v2 components, tasks, dependency gates, and gold evidence.
- `catalog/implementation_task_index.md` - compact index for the 381 catalog tasks.
- `catalog/component_responsibility_matrix.md` - ownership matrix for v2 components.
- `catalog/architecture/` - machine-readable component/task/dependency-policy source files.
- `architecture/` - active v2 architecture rules, schema/identity map, and ownership policy plan.
- `gold/` - gold conformance triage, gold program documents, and machine-readable gold catalog.
- `security/` - bounded FND-011 security threat/invariant mapping fixtures; partial evidence only, not G80-G89 pass status.

## Safety Guardrails

Every 0.2/v2 task must preserve these rules:

- No side-effectful action bypasses the Action Gateway, verifier chain, and adapter/driver boundary.
- Verifier, policy, identity, work-order, approval, trace, state, quota, data-use, capability, and safety uncertainty fails closed.
- State remains explicit, versioned, trace-linked, and replayable.
- Replay remains inspect-only or safe simulation by default and does not execute live side effects.
- Tenant, agent, runtime context, run, tick, action, state, trace, message, work-order, approval, artifact, fleet, node, instance, workload, lease, model, change, deployment, and incident identities remain distinct.
- Messages, feedback, rewards, observability, evidence, and extension fields are not authority.
- Training, evaluation, improvement, change, gate, deployment, and incident roles stay separated; training publishes candidates only.
- Physical/device work stays high-level, bounded, and locally safety-vetoable. Splendor does not replace hard real-time controllers.

## Evidence Boundary

Moving these files into `docs/rules/v2/` means they are active 0.2 execution
rules. It does not mean the proposed crates, services, schemas, driver profiles,
learning-control flows, fleet behavior, physical behavior, or self-evolution
programs exist in code.

Gold cases remain `not_exercised` until exact executable fixtures or harnesses
run and pass with retained evidence. A skipped or unavailable gold case is never
a pass.
