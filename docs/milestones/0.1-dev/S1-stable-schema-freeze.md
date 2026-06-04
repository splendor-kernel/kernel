# 0.1-S1 - Stable Schema Freeze

## Objective

Freeze the first stable 0.1 primitive schema contract so implementers can build
against documented public schemas without relying on undocumented internals.

## Functional Scope

- Added `docs/spec/0.1/primitives.md` for stable primitive purpose, identity,
  required fields, optional fields, extension rules, trace/state, replay, and
  security notes.
- Added `docs/spec/0.1/schema-versioning.md` for breaking/non-breaking changes,
  deprecation, migration, and extension compatibility.
- Added `docs/spec/0.1/stable-primitive-examples.json` as a lightweight S1
  example manifest with concrete examples for every stable primitive.
- Added focused TypeScript and Python validation for the S1 docs, fixture,
  required fields, enum values, and extension restrictions.
- Added schema-facing TypeScript and Python constants for stable primitive names,
  required fields, enum values, and reserved extension keys.

## Non-Goals

- No runtime behavior changes.
- No full 0.1-S2 conformance suite.
- No generated schema pipeline.
- No fleet consensus, marketplace, admin SaaS, production robotics
  certification, or real-time control claims.
- No new side-effect path, verifier behavior, adapter behavior, or daemon API.

## Public Contracts Changed

- New stable 0.1 docs/spec public schema contract.
- New lightweight stable primitive example manifest.
- Documentation of dev-era aliases, including `trace_id` as an input alias for
  `trace_event_id` where implemented.

No production runtime, daemon, gateway, or adapter behavior was changed by this
sprint. The TypeScript and Python additions are schema-facing constants used for
parity validation.

## Runtime Primitive Impact

| Primitive | Impact |
| --- | --- |
| Percept | Stable schema documented. |
| Policy | Stable schema documented. |
| Gateway | No behavior change; gateway boundary documented. |
| Verifier | Stable schema documented. |
| State graph | Stable StateNode public schema documented. |
| Trace store | Stable TraceEvent public schema and alias migration documented. |
| Replay | Inspect-only/no side-effect default documented. |
| Message | Stable schema documented. |
| Work order | Stable schema documented. |
| Governance | Approval schema documented as stable governance primitive. |
| Adapter | Stable boundary schema documented. |
| Feedback | Stable schema documented. |
| Reward | Stable schema documented. |

## Trace Behavior

- No new trace event classes.
- No changed event fields.
- The stable contract requires `trace_event_id`, `run_id`, `sequence`,
  `timestamp`, `identity`, and `kind` for TraceEvent.
- `trace_id` is documented only as a compatibility input alias where existing
  deserializers support it.

## State Behavior

- No state nodes are created by this sprint.
- No state head update behavior changed.
- Stable docs define public StateNode/commit fields including `state_node_id`,
  parent linkage, state hash, optional snapshot references, trace linkage, and
  tenant/agent/run scope.
- State commit failure behavior remains unchanged.

## Gateway and Verifier Behavior

- No new gateway or verifier checks.
- Stable docs require side-effectful actions to stay behind Action Gateway and
  verifier enforcement.
- Stable docs require extension fields to be non-authorizing and unable to carry
  permissions, credentials, work orders, approvals, adapter authority, quotas, or
  verifier bypass data.

## Replay Behavior

- No replay implementation changed.
- Stable docs preserve replay as inspect/reconstruct/compare/simulate by default.
- Replay must not execute adapters, dispatch physical actions, grant approvals,
  contact revocation services, or mutate live state heads by default.

## Tests and Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| contract | Validate stable primitive docs and fixture cover required S1 primitives, fields, identity, enum values, and extensions. | `npm test` includes `0.1-S1 stable primitive docs and example manifest are aligned`. |
| parity | Validate TypeScript/Python schema constants match the stable fixture, while TypeScript parity tests continue checking Rust structs/enums. | `npm test`; `python -m pytest python/tests/test_runtime.py`. |
| negative | Validate extension reserved keys include authority-bearing keys and examples do not authorize through extensions or unknown top-level authority fields. | TypeScript and Python fixture validators. |
| docs | Validate required docs are present and mention breaking/non-breaking changes plus deprecations. | `npm test`; `git diff --check`. |

## Example or Fixture

- `docs/spec/0.1/stable-primitive-examples.json`
- `docs/spec/0.1/primitives.md`
- `docs/spec/0.1/schema-versioning.md`

## Future Extension Notes

- 0.1-S2 can build the broader conformance suite using the S1 manifest as a seed,
  but should not treat this fixture as full conformance.
- 0.1-S3 adapter maturity can reference the Adapter primitive's gateway-mediated,
  non-authorizing extension language.
- Future schema versions can add optional fields or wrappers only if identity,
  trace linkage, state explicitness, replay safety, and gateway enforcement are
  preserved.
