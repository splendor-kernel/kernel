# RFC 0006 — Agent Kernel v2 Planning Import

## Motivation

The imported `splendor_agent_kernel_v2` documentation pack describes the broader
0.2/v2 direction for Splendor as a user-space kernel for persistent agents. It
adds planning detail around identity and authority, artifact lineage,
event/state/evidence, execution fabric, driver boundaries, agent runtime and
routing, feedback/evaluation/learning control, and change governance.

This RFC records how the pack enters the repository without drifting the current
implementation contract or overstating implemented capability.

## Primitive affected

This RFC is docs/planning only. It does not directly change a stable primitive.
Future RFCs may affect:

- identity and authority;
- action gateway / future driver boundary;
- state graph and trace store;
- replay and evidence;
- messages and delegation;
- work orders and fleet identity;
- adapters and driver profiles;
- feedback, reward, evaluation, and learning-control primitives;
- governance and change/deployment state.

## Schema/API proposal

No stable schema or API is changed by this import.

The original import provenance is stored under:

```text
docs/planning/agent-kernel-v2/
```

The active execution rules derived from that import now live under:

```text
docs/rules/v2/
```

0.1 schemas remain the implemented/stable baseline in `docs/spec/0.1/*`. Runtime
safety rules and sprint acceptance criteria remain in `docs/rules/*`.

## Migration plan

There is no runtime migration in this PR. Follow-up planning issues should:

1. map each vNext object to current stable primitives;
2. classify changes as additive extension, compatible migration, breaking
   replacement, or 0.2/v2 RFC requirement;
3. define fixtures and compatibility tests before implementation;
4. preserve Action Gateway mediation, trace/state/replay guarantees, fail-closed
   behavior, and identity separation throughout any migration.

## Compatibility impact

This is a documentation import with no public runtime compatibility impact.

The highest compatibility risk is interpretive: maintainers might treat v2 rule
docs as implemented behavior. To prevent that, the v2 rule pack, README, RFC,
and known-limitations docs all state that active decomposition rules are not
implementation evidence.

## Security impact

No security boundary changes in this PR.

Future implementation work spawned by this pack is security-sensitive because it
touches authority, secrets, data-use, driver invocation, physical actions,
deployment, and self-management. Those follow-ups must include security review,
negative tests, revocation/expiry handling, and fail-closed behavior.

## Trace/replay impact

No trace or replay behavior changes in this PR.

Future event/evidence/replay proposals must preserve these invariants:

- trace events are runtime contract data, not logs;
- state commits are explicit and versioned;
- replay does not execute side effects by default;
- denied, failed, paused, approved, migrated, and delegated transitions are
  trace-linked.

## Tests required

For this docs-only import:

- parse imported YAML/JSON planning files;
- run `git diff --check`;
- run the existing conformance suite if the local environment supports it.

For future implementation RFCs:

- unit, contract, integration, negative, trace, state, replay, compatibility,
  and fail-closed tests based on the affected sprint criteria.

## Docs required

This RFC is accompanied by:

- `docs/planning/README.md`;
- `docs/planning/agent-kernel-v2/README.md`;
- active 0.2/v2 rules under `docs/rules/v2/`;
- `docs/planning/agent-kernel-v2/README.md` provenance redirect;
- `docs/releases/known-limitations.md` note clarifying active-rule and
  non-implementation status.
