# UC-E2E-S7 Data Isolation Artifacts

## Objective

Validate data-local analysis, artifact creation/publication, and cross-tenant isolation through executable public manager and resident daemon boundaries.

## Functional Scope

- Signed Tenant A orchestrator and specialist work orders with explicit data refs.
- Data-local VPC placement and dispatch through the central manager API.
- Shared specialist message delegation with scoped work-order authority.
- Gateway-mediated data fixture reads, internal artifact creation, and approval-gated external publish.
- Redacted trace export and inspect-only replay/audit evidence.

## Non-Goals

- No enterprise data workspace UI.
- No broad data catalog product.
- No artifact marketplace or external SaaS artifact store.
- No broad inherited specialist credentials.
- No S8 replay migration suite, S9 failure injection, or S10 final journey.

## Public Contracts Changed

- The existing daemon `ResourceBoundaryVerifier` hook is used by resident runs to enforce signed work-order data refs and tenant-scoped artifact refs.
- The central manager message route accepts stable task request/response schemas in addition to proposal messages and rejects payload data-ref/permission smuggling.
- No new endpoint paths were added.

## Runtime Primitives Touched

- tenant isolation
- data refs/data-scope verifier
- work order
- shared specialist delegation
- message routing
- artifact adapter metadata
- trace redaction
- approval flow
- gateway/verifier chain
- state graph
- replay/audit

## Trace Events Added Or Changed

No new `TraceEventKind` variant was added. S7 acceptance maps existing verifier/action/audit events to required evidence:

- `work_order.accepted`
- `data_scope.verified`
- `data_scope.denied`
- `message.sent`
- `message.received`
- `message.denied`
- `artifact.created`
- `artifact.publish.needs_approval`
- `artifact.publish.executed`
- `artifact.publish.denied`
- `trace.exported.redacted`
- `state.committed`
- `replay.explained`

## State Behavior

Specialist and orchestrator runs commit explicit state nodes through the resident daemon run loop. Replay uses committed state and trace evidence only.

## Verifier/Gateway Behavior

The data/artifact verifier denies data refs outside the signed work order and rejects artifact refs outside the tenant path before adapter execution.

## Replay Behavior

Replay remains `inspect_only` with side effects disabled by default. S7 asserts replay does not republish external artifacts, rewrite internal artifacts, or reveal raw protected fixture payloads.

## Failure Behavior

S7 fail-closed evidence covers Tenant B data ref reads, manager credential action laundering, message smuggling, missing trace redaction policy, publish without approval, cross-tenant replay, and artifact path collision.

## Test Evidence

Run:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S7
```

The scenario writes evidence under:

```text
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S7/
```

## Future Extension Notes

S8 may reuse the S7 exported trace/state/artifact metadata for broader replay, audit, compatibility, and migration validation.
