# S4 SDK and API Stabilization

## Objective

Stabilize the Splendor0.1-dev Rust, Python, daemon, and TypeScript integration
surface so clients and adapters can target clearly named public contracts without
depending on undocumented internals.

## Functional Scope

- Named stable public APIs for Rust traits/types, Python SDK, runtime daemon API,
  TypeScript types, and TypeScript daemon client.
- Named non-stable/internal surfaces that are not promised by 0.1.
- Documented compatibility guarantees, deprecation policy, daemon version-header
  expectations, and current version-negotiation limitation.
- Documented stable error shapes for daemon errors, client transport errors,
  validation failures, conformance failures, and gateway/action outcomes.
- Aligned stable examples and validation guidance with the S2 conformance suite.

## Non-Goals

- No runtime behavior changes.
- No production OAuth/OIDC/PKI server.
- No stable native Node binding.
- No browser runtime guarantee.
- No fleet scheduler, marketplace, enterprise UI, or physical safety
  certification claim.
- No undocumented API compatibility promise.

## Public Contracts Changed

- Added `docs/spec/0.1/api-stability.md`.
- Added `docs/sdk/python/stable-0.1.md`.
- Added `docs/sdk/typescript/stable-0.1.md`.
- Updated `docs/reference/runtime-daemon-api.md` with 0.1 compatibility headers,
  stable error-shape guidance, and explicit negotiation limitation.
- Updated SDK and example docs to point stable users at 0.1 surfaces.

No schema fields, trace event names, daemon endpoints, gateway outcomes, Rust
public types, Python source, TypeScript source, or OpenAPI schemas were changed.

## Runtime Primitives Touched

- SDK/API.
- Action gateway.
- Verifier.
- Trace store.
- State graph.
- Replay.
- Work order.
- Docs/tests.

## Trace Events Added Or Changed

No trace event names or runtime trace fields were added or changed.

The stabilization docs reaffirm that daemon audit events, action verification
events, action outcomes, state commits, replay summaries, and message/work-order
events remain the evidence source for runtime behavior.

## State Behavior Added Or Changed

No state graph behavior was added or changed.

The stable API documentation preserves existing state behavior: state commits are
explicit, versioned, trace-linked, and replay-inspectable; failed commits prevent
next-tick advancement where runtime code implements that behavior.

## Verifier/Gateway Behavior Added Or Changed

No gateway or verifier runtime behavior was added or changed.

The stable API documentation preserves layered daemon authorization and states
that caller tokens do not authorize arbitrary actions. Side effects remain
authorized only by the Action Gateway and verifier chain.

## Replay Behavior

Replay remains inspect-only by default. The stable API documentation states that
Python replay, daemon replay, TypeScript client replay calls, and conformance
fixtures must not invoke adapters, filesystems, networks, databases, shell
commands, devices, or external services.

## Failure Behavior

Stable failure handling is documented for:

- daemon API errors with `code`, `message`, and `details`;
- TypeScript `SplendorClientError` transport/response failures;
- Python validation exceptions and recorded action outcomes;
- gateway statuses `executed`, `denied`, `failed`, `needs_approval`, and
  `needs_intervention`;
- conformance report failures with case, primitive, requirement, path, status,
  and message.

## Test Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| conformance | Validate 0.1 stable primitive fixture compatibility and fail-closed/replay expectations | `python conformance/0.1/run-conformance.py` |
| docs whitespace | Validate patch cleanliness | `git diff --check` |

`npm test` was not required for this sprint change because TypeScript source,
package tests, and generated type fixtures were not modified.

`python -m pytest python/tests/test_runtime.py -q` was not required for this
sprint change because Python source and Python SDK constants were not modified.

## Example Commands Or Fixtures

- `python conformance/0.1/run-conformance.py`
- `examples/python-sdk-basic/README.md`
- `examples/typescript-daemon-client/README.md`
- `examples/daemon-client-local/README.md`
- `docs/spec/0.1/api-stability.md`

## Future Extension Notes

- Future daemon work may implement active version negotiation for
  `X-Splendor-API-Version`; until then, docs must continue to describe the header
  as a compatibility declaration rather than negotiated behavior.
- Future native Node bindings must be documented separately before becoming
  stable.
- Future SDK helpers may be additive if they preserve identity, state, trace,
  gateway, verifier, quota, work-order, and replay invariants.
