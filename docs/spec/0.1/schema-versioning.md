# Splendor 0.1 Schema Versioning Policy

This document defines compatibility expectations for stable 0.1 primitive
schemas documented in `docs/spec/0.1/primitives.md`.

## Version Labels

- Stable primitive documents are versioned as `0.1`.
- Existing wire schemas keep explicit strings such as `splendor.work_order.v1`,
  `splendor.governance_state.v1`, and `splendor.message.<name>.v1`.
- New stable wire schemas should use `splendor.<primitive>.vN` naming.
- Experimental or future internals must be marked experimental and must not be
  described as stable 0.1 behavior.

## Compatibility Contract

Within the 0.1 line, implementers may rely on stable primitive names, required
field names, documented enum values, identity separation, non-authorizing
extension policy, replay no-side-effect defaults, and Action Gateway mediation
for side effects.

The 0.1 line does not guarantee undocumented Rust internals, private helpers,
storage backends, fleet scheduling, approval UI, robotics certification, or
marketplace/admin-product semantics.

## Breaking Changes

- Removing or renaming a required field.
- Changing field meaning, identity scope, or authority semantics.
- Collapsing distinct identities such as `agent_id` and `instance_id`.
- Removing enum values or changing serialized spelling.
- Changing fail-closed behavior into allow behavior.
- Letting extensions authorize actions, adapters, permissions, approvals,
  credentials, work orders, policies, quotas, or verifier outcomes.
- Making replay execute side effects by default.
- Allowing side-effectful actions to bypass the Action Gateway.
- Turning `trace_id` from compatibility alias into a distinct public identity.
- Replacing explicit state nodes with hidden mutable state.

Breaking changes require a new major schema version or an RFC with migration
guidance before they can be exposed as stable.

## Non-Breaking Changes

- Adding an optional field with fail-closed or inert default behavior.
- Adding a trace event for newly implemented behavior while preserving required
  tick ordering.
- Adding an enum value only when consumers are documented to handle unknown
  values or the enum is explicitly extension-friendly.
- Adding a wrapper that preserves wrapped primitive identity, run scope, trace
  linkage, and authority semantics.
- Accepting a dev-era alias as input while continuing to emit the stable field
  name.
- Adding non-authorizing metadata inside an explicit `extensions` object.
- Tightening validation from ambiguous allow to fail-closed denial when the old
  behavior was not documented as stable authorization.

## Deprecation Policy

- Deprecated fields must have a documented replacement and migration path.
- Stable serializers should emit the replacement field.
- Deserializers may accept aliases for a migration window, but aliases must not
  create distinct runtime identity or authority.
- Removing a deprecated field from accepted input is breaking unless it happens
  in a new major schema version.

Current deprecations:

| Deprecated | Replacement | Guidance |
| --- | --- | --- |
| `trace_id` | `trace_event_id` | Emit `trace_event_id`; accept `trace_id` only as an input alias where implemented. |
| TypeScript `TraceId` alias | `TraceEventId` | Keep alias for source compatibility; new stable docs should use `TraceEventId`. |
| Rust `StateCommit.node_id` public wording | `state_node_id` | Public schemas and docs use `state_node_id`; Rust may keep implementation field names. |

## Extension Compatibility

Extensions are intentionally narrow. A schema change that allows extensions to
carry authority is breaking and unsafe.

Allowed extension data includes display hints, external reference IDs,
correlation IDs, non-sensitive diagnostics, and implementation metadata that does
not affect authorization or execution.

Reserved extension keys include identity fields, permission fields, adapter
authority, credentials, signatures, work orders, approvals, policy bundles,
quotas, verifier outcomes, and gateway routing fields.

## Migration Expectations

Schema migrations must document source and target versions, field changes,
identity impact, authority/security impact, trace/replay impact, state graph
impact, and required tests or fixtures.

Migration tools must not silently authorize side effects, grant approvals, issue
work orders, alter state heads, or rewrite trace identity as part of schema
conversion.

## Parity and Validation

0.1-S1 includes a lightweight stable example manifest and focused TypeScript test
coverage to prove the stable primitive list, required fields, enum references,
and extension restrictions are present. This is not the full 0.1-S2 conformance
suite.

The S1 validator checks concrete stable examples and Rust/TypeScript/Python
schema-facing parity where this repository exposes those surfaces. It does not
claim adapter certification, daemon compatibility, generated schemas, or the full
cross-implementation conformance matrix planned for 0.1-S2.

0.1-S2 now includes a bounded compatibility fixture matrix v0 in
`conformance/0.1/run-conformance.py`. The matrix is partial FND-006 evidence for
current stable examples, additive non-authorizing extensions, fail-closed
rejection of authorizing/security-critical extension fields, and the implemented
`trace_id` input alias with stable `trace_event_id` output. It is not a `G00` or
`G72` pass, and it does not implement version negotiation, storage migration,
rolling upgrades, or agent migration.
