# UC-E2E-S7 Data Isolation Artifacts

## Objective

Validate data-local analysis, artifact creation/publication, and cross-tenant isolation through executable public manager and resident daemon boundaries.

AUTH-004c migrates S7's approval compatibility path from raw grant plus lifecycle
resume to exact challenge plus authority-obligation receipt re-evaluation.

## Functional Scope

- Per-instance signed Tenant A work orders split into exact specialist data-read,
  orchestrator internal-artifact, orchestrator publish, request-message, and
  response-message authority profiles.
- Data-local VPC placement and dispatch through the central manager API using the
  canonical S4 node/instance registration identities, refreshed through explicit
  node and instance heartbeats before dispatch.
- Verified VPC TLS plus fresh one-request bearer credentials; body/header caller
  projections and audit attribution mirror the verified credential and never
  replace it as proof.
- Shared specialist request/response messages with parent/child run binding and
  separately admitted action authority; message payloads remain non-authorizing.
- Gateway-mediated data fixture reads, internal artifact creation, and a direct
  publish-only resident run whose exact policy action pauses for approval and is
  retried through `POST /actions` with one manager-issued authority-obligation
  receipt. Approval request and grant use fresh fleet-bound, exact-audience,
  one-scope manager bearers and record the full daemon-issued challenge.
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
- `run.resumed`
- `trace.exported.redacted`
- `state.committed`
- `replay.explained`

## State Behavior

Specialist data-read, orchestrator internal-artifact, and orchestrator
publish-only runs commit explicit state nodes through the resident daemon run
loop. The S7 `state-export.json` remains the specialist head consumed by S8;
`state-heads.json` retains the additional exact-run heads. Replay uses committed
state and trace evidence only. The receipt-bearing publish retry does not run a
second tick or advance the publish state head; it changes the run from
`waiting_for_approval` to `running` after exactly one adapter execution.

## Verifier/Gateway Behavior

The data/artifact verifier denies data refs outside the exact specialist work
order and rejects artifact refs outside the tenant path before adapter
execution. Every resident call uses the acceptance CA and a fresh scoped bearer.
All five work orders are signed with the generated VPC work-order secret and use
one action, one adapter, and one permission; no local work-order key or
multi-adapter compatibility profile is used. The approval manager receives the
complete exact challenge and returns one trace-linked receipt. S7 then preserves
the pending action ID, name, params, effective adapter, original `requested_at`,
quota, and preconditions on `POST /actions`; raw `ApprovalEvidence` and lifecycle
`/resume` are not used as execution authority.

## Replay Behavior

Replay remains `inspect_only` with side effects disabled by default. S7 asserts replay does not republish external artifacts, rewrite internal artifacts, or reveal raw protected fixture payloads.

## Failure Behavior

S7 fail-closed evidence covers Tenant B data ref reads, manager credential
projection laundering, message smuggling, missing trace redaction policy,
publish without approval, cross-tenant replay, and artifact path collision. The
resident-security report also proves verified TLS, fresh bearer correlation IDs,
credential/audit mirroring, and secret/bearer redaction. The manager approval
report separately proves fresh one-use manager bearers, exact scope/fleet/audience
binding, response trace correlation, and absence of retained bearer bytes.

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
