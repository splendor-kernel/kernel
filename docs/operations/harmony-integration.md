# Operating Harmony Or External Control-Plane Integration

This guide describes the provider-neutral external control-plane pattern. Harmony
is one possible provider. Splendor remains the runtime kernel: work orders,
gateway verification, state commits, trace events, replay, and side-effect
boundaries stay in Splendor.

## Maturity And Limits

- Required adapter maturity: `governance-aware` for approval/control-plane bridges; `network-safe` if the bridge performs bounded network calls.
- Stable primitives: signed `WorkOrder`, scoped `Approval`, trace-linked artifact references, daemon/API security boundary, replay/audit evidence.
- Limitations: no Harmony-specific kernel dependency, no enterprise SaaS manual, no billing/admin UI, no universal approval queue, no broad user credential delegation, and no external control plane bypass around the Action Gateway.

## Setup

Run the provider-neutral bridge checks:

```bash
cargo test -p splendor-types external_governance
npm test
```

Use `examples/harmony-governance-bridge/README.md` for schema fixtures. The same `splendor.external_governance_adapter.v1` schema can describe Harmony endpoints or another provider's endpoints.

## Run Path

1. The external control plane issues or serves a signed, scoped `WorkOrderEnvelope`.
2. Splendor validates work-order signature, expiry, revocation, tenant, agent, run, data refs, placement, actions, adapters, permissions, and quotas before run start/resume.
3. Splendor executes the runtime loop locally or on the selected resident boundary.
4. Approval requests are emitted as trace-linked governance events.
5. The external control plane returns action-scoped approval grant or denial evidence.
6. Splendor feeds that evidence into the approval verifier and Action Gateway. Approval evidence never executes the action directly.
7. Splendor emits trace-linked state commits, outcomes, audit records, and artifact references for external indexing.

## Trace And State Inspection

External systems should index Splendor evidence rather than replace it:

- `run_id` for the runtime execution instance;
- `state_node_id` for explicit state graph provenance;
- trace range or `trace_event_id` references for action, approval, denial, and artifact lifecycle;
- `approval_id` and approval state when publishing governed artifacts;
- source data references and artifact IDs.

Replay remains a Splendor inspection path. External providers must not use replay to re-issue approvals, call external endpoints, publish artifacts, or execute adapters.

## Failure Handling

- Missing or broad work-order authority fails closed.
- Bridge payloads containing secrets, user credentials, access tokens, cookies, nested `allowed_permissions`, or approval tokens in context are rejected by the reference fixtures.
- External approval failure maps to `adapter_failure` or denial/intervention evidence; it must not invent a grant.
- A Harmony bearer token, UI session, or user credential must not authorize Splendor actions.
- Approval grants must be action-scoped; global, tenant, agent, or adapter grants are blanket authority and are rejected by the contract.

## Teardown

The bridge fixture tests do not create external resources. If running a local daemon alongside a control-plane mock, stop the daemon with `Control-C` and remove only mock-generated local files.

## Provider-Neutral Boundary

Harmony may own enterprise product concerns such as UI, organizations, approval queue UX, artifact registry UX, and data-space UX. Splendor owns runtime primitives: percepts, policies, gateway, verifiers, outcomes, explicit state, trace, replay, messages, quotas, approvals, and work-order enforcement.

## References

- `examples/harmony-governance-bridge/README.md`
- `docs/reference/daemon-security-boundary.md`
- `docs/reference/work-orders.md`
- `docs/reference/approval-verifier.md`
- `docs/reference/audit-export.md`
- `docs/spec/0.1/api-stability.md`
