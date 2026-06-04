# 0.1-S6 — Migration And Release

## Objective

Finalize the Splendor0.1-dev migration and release documentation so users can
move from 0.01-dev through 0.05-dev development contracts to the first stable 0.1
primitive compatibility line without unsupported production or certification
claims.

## Functional Scope

- Added 0.1 release notes, migration guide, compatibility policy, changelog entry,
  and this sprint evidence document.
- Documented renamed, changed, removed, and non-stabilized dev fields/API
  surfaces with concrete stable replacements or removal reasons.
- Documented release validation commands, docs/examples review targets, known
  limitations, and human-only release tag checklist.
- Preserved stable example discovery for local runtime and daemon client paths.

## Non-Goals

- No actual git tag creation without human authorization.
- No 1.0 production release claim.
- No production remote daemon, fleet scheduler, autoscaler, marketplace, enterprise
  support policy, adapter certification, production robotics safety certification,
  or hard real-time control claim.
- No new runtime primitive, daemon endpoint, SDK behavior, adapter behavior, trace
  event, state schema, or replay mode.

## Public Contracts Changed

- Added `docs/releases/0.1-dev.md`.
- Added `docs/releases/0.1-migration.md`.
- Added `docs/releases/compatibility-policy.md`.
- Updated `CHANGELOG.md` with a 0.1-dev release entry.
- Updated release-status/limitations documentation for 0.1 consistency.

No runtime schema, API, SDK, CLI, daemon endpoint, trace event, gateway verifier,
or adapter contract was changed by this sprint.

## Runtime Primitive Impact

| Primitive | Impact |
| --- | --- |
| Percept | Documentation only; no schema change. |
| Policy | Documentation only; Python policies still propose actions only. |
| Gateway | Documentation reinforces no side-effect bypass. |
| Verifier | Documentation reinforces fail-closed verifier behavior. |
| State graph | Migration docs standardize public `state_node_id` wording and required state linkage. |
| Trace store | Migration docs standardize `trace_event_id` and runtime-contract trace wording. |
| Replay | Documentation reinforces inspect-only/no-side-effect defaults. |
| Message | Migration docs clarify messages do not grant authority. |
| Work order | Migration docs map broad dev authorization aliases to `WorkOrderEnvelope` fields. |
| Governance | Documentation clarifies approval evidence is not a gateway bypass. |

## Trace Behavior

- No new trace event classes.
- No changed trace event fields.
- Release docs require stable docs/examples to use `trace_event_id` and preserve
  append-only ordered trace semantics.

## State Behavior

- No new state nodes or state-head behavior.
- Migration docs require stable public state records to include state ownership,
  parent, hash, timestamp, and trace linkage where applicable.

## Gateway And Verifier Behavior

- No new checks or denial reasons.
- Release and migration docs restate that caller credentials, endpoint scopes, and
  signed work orders do not replace gateway/verifier authorization for side
  effects.

## Replay Behavior

- No new replay mode.
- Release and migration docs restate that replay is inspect-only by default and
  must not call adapters, filesystems, networks, governance systems, cloud helpers,
  or physical middleware.

## Tests And Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| Contract | 0.1 primitive compatibility fixtures | `python conformance/0.1/run-conformance.py` |
| Contract | Adapter maturity manifests | `python scripts/validate-adapter-manifests.py` |
| Client | TypeScript stable client/types behavior | `npm test` after `npm ci` if needed |
| SDK | Python local runtime stable behavior | `python -m pytest python/tests/test_runtime.py -q` |
| Daemon example | Stable local daemon example path | `cargo test -p splendor-daemon` |
| Docs hygiene | Whitespace/conflict check | `git diff --check` |

The PR for this sprint records observed command results. The release notes include
the same command set as the release validation checklist.

Observed S6 validation on 2026-06-04:

| Command | Result |
| --- | --- |
| `python conformance/0.1/run-conformance.py` | Pass: 24 cases, 0 failed. |
| `python scripts/validate-adapter-manifests.py` | Pass: 3 adapter manifests validated. |
| `npm ci` | Pass: 5 packages installed, 0 vulnerabilities. |
| `npm test` | Pass: 22 TypeScript tests. |
| `python -m pytest python/tests/test_runtime.py -q` | Pass: 24 Python tests. |
| `cargo test -p splendor-daemon` | Pass: daemon unit, integration, and doc test targets. |
| `git diff --check` | Pass: no whitespace errors. |

## Example Or Fixture

Stable example entry points:

- `docs/operations/local-runtime.md`
- `docs/operations/runtime-daemon.md`
- `examples/local-basic-loop/README.md`
- `examples/daemon-client-local/README.md`
- `examples/typescript-daemon-client/README.md`

## Known Limitations

- The 0.1 conformance suite is primitive compatibility evidence, not complete
  post-implementation use-case E2E acceptance.
- The current daemon does not actively negotiate API versions or reject
  unsupported version headers.
- Local insecure daemon mode remains local-only development behavior.
- Physical/edge support remains contract and simulation focused, not production
  hardware certification.

## Future Extension Notes

Future releases can add production remote auth, fleet scheduling, adapter
certification workflow, or physical hardware certification only through separate
milestones, validation, and release notes. Those extensions must preserve 0.1
identity separation, gateway mediation, fail-closed verification, explicit state,
append-only trace, and replay no-side-effect defaults.
