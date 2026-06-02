# External Governance Adapter Contract

Sprint `0.04-S6` defines the provider-neutral boundary that lets Harmony or any
other external control plane issue scoped work orders, approval decisions, and
artifact references without owning Splendor runtime enforcement.

The adapter is a bridge, not an authority shortcut:

```text
external control plane
  -> signed scoped work order / approval decision / artifact reference
  -> Splendor daemon or runtime boundary
  -> existing work-order validation, approval verifier, Action Gateway, state, trace
```

Splendor remains source of truth for ticks, verifier decisions, side-effect
authorization, state graph commits, trace events, replay, and gateway execution.

## Public contracts

Rust contracts live in `splendor-types`:

- `ExternalGovernanceAdapterContract`
- `ExternalGovernanceEndpoints`
- `ExternalGovernanceReference`
- `ExternalGovernanceWorkOrderBridge`
- `ExternalApprovalDecision`
- `ExternalApprovalMapping`
- `ExternalGovernanceAdapterFailure`
- `ExternalTraceRange`
- `GovernedArtifactRef`

TypeScript contracts live in `@splendor/types` with the same field names.

Schema versions:

```text
splendor.external_governance_adapter.v1
splendor.governed_artifact_ref.v1
```

## Endpoint contract

The endpoint map is intentionally provider-neutral. A Harmony-compatible adapter
can use the default names, while another control plane can rename the paths and
still produce the same Splendor objects.

| Contract field | Harmony-compatible path | Purpose |
| --- | --- | --- |
| `work_orders` | `/splendor/work-orders/{work_order_id}` | Fetch or receive a signed scoped work order. |
| `action_gateway` | `/splendor/action-gateway` | Submit action requests back to Splendor's gateway; it does not execute externally. |
| `approvals` | `/splendor/approvals` | Receive external approval grants or denials. |
| `traces` | `/splendor/traces` | Export trace events or summaries. |
| `state_commits` | `/splendor/state-commits` | Export state commit references. |
| `artifact_refs` | `/splendor/artifacts` | Export trace-linked artifact references. |

Endpoint strings are validated as local route paths. Scheme-relative paths such as
`//host/path`, absolute URLs, parent-directory segments, whitespace/control
characters, and backslashes are rejected. Endpoint names do not grant authority and
do not replace daemon caller authentication, endpoint scopes, signed work-order
validation, or gateway verification.

## Scoped work-order bridge

`ExternalGovernanceWorkOrderBridge` accepts only signed `WorkOrderEnvelope`
payloads. The bridge validates schema shape, detached signature metadata, issuer,
trace linkage, and non-authoritative context metadata.

The bridge deliberately does **not** accept broad user credentials. Credential-like
or authority-like context keys such as `credential`, `accessToken`, `oauth_token`,
`jwt`, `bearer`, `cookie`, `session`, `secret`, `authorization`, `work_order`,
`signature`, `allowed_permissions`, or `approval_token` fail closed, including
nested metadata objects.

The runtime still performs full work-order validation with the configured keyring,
expiry check, revocation path, tenant/agent/run compatibility check, placement
compatibility, and trace emission before creating or resuming a run.

## Approval decision mapping

External approval decisions map into first-class governance objects:

| External decision | Splendor object | Required fields |
| --- | --- | --- |
| `granted` | `ApprovalGrant` | explicit action `scope`, `expires_at`, `issuer`, `trace`, `reason` |
| `denied` | `ApprovalDenial` | explicit `scope`, `expires_at`, `issuer`, `trace`, `reason` |

These governance objects are trace/replay facts. They do not execute adapters by
themselves. A side-effectful action must still re-enter the existing daemon and
`VerifiedActionGateway` path with scoped approval evidence and pass all verifier,
quota, policy, adapter, and postcondition checks.

External approval grants must be action-scoped. This prevents an external control
plane from accidentally creating a global, tenant-wide, agent-wide, or adapter-wide
blanket approval. External denials may be broader because they are fail-closed and
do not authorize execution.

If the external adapter cannot fetch or validate a decision, the result is
`ExternalApprovalMapping::AdapterFailure`. That mapping contains no approval grant
and must be treated as fail-closed: deny, pause, or request intervention according
to the caller's runtime context.

## Artifact reference mapping

`GovernedArtifactRef` gives product control planes a stable way to index artifacts
without making Splendor an artifact-registry product. Every artifact reference
includes:

- `artifact_id`;
- optional `version`;
- `source_refs`;
- `run_id`;
- `state_node_id`;
- `trace_range.start_trace_event_id` and `trace_range.end_trace_event_id`;
- `approval_state`;
- optional `approval_id`;
- optional external reference;
- explicit `export_targets`.

When `approval_state` is `granted`, `denied`, `expired`, or `revoked`,
`approval_id` is required so external artifact records cannot claim an approval
state without a Splendor approval object. Artifact references do not mutate state.
They point back to explicit state graph nodes and append-only traces that prove
artifact provenance and approval status.

## Trace behavior

The adapter contract does not add new trace event variants in `0.04-S6`. It maps
external inputs to existing traceable primitives:

- signed work-order intake still emits `WorkOrderAccepted` or `WorkOrderRejected`;
- approval decisions map to existing `approval.granted` or `approval.denied`
  governance lifecycle events;
- adapter failure should be recorded as a denial/intervention/audit fact by the
  receiving runtime path;
- artifact references carry explicit trace ranges for replay and audit.

## State behavior

No hidden mutable state is introduced. Work orders and approval decisions carry
scope and trace references. Artifact references identify the `state_node_id` that
already exists in the state graph. A control plane may index that reference, but it
does not become state owner.

## Replay behavior

Replay remains inspect-only. It can reconstruct:

- which external work-order reference was bridged into a signed Splendor work
  order;
- whether an external approval was mapped to grant, denial, or fail-closed adapter
  failure;
- which run/state/trace range produced an artifact reference.

Replay does not contact Harmony or any control plane, refresh credentials, issue
new approvals, resume runs, call adapters, or execute side effects.

## Failure behavior

The adapter contract fails closed on:

- unsupported schema versions;
- unsigned work-order envelopes;
- missing issuer or trace linkage;
- malformed endpoint paths;
- credential-like or authority-like context metadata;
- approval grants with broad non-action scope;
- approval expiry not after creation;
- governance scope and trace run mismatches;
- missing artifact source refs;
- terminal artifact approval states without `approval_id`;
- nil trace IDs in artifact trace ranges.

## Non-goals

- No Harmony admin UI.
- No billing, organization, workspace, or marketplace implementation.
- No OAuth/OIDC/PKI product.
- No approval queue or workflow engine.
- No new side-effect path outside the Action Gateway.
- No replacement for daemon caller authentication or signed work-order validation.

## Verification

Reference tests:

```bash
cargo test -p splendor-types external_governance
npm test
```
