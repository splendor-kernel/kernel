# Harmony Governance Bridge

Harmony can integrate with Splendor as an external governance/control-plane
consumer. Harmony may provide enterprise product concerns; Splendor keeps runtime
enforcement.

## Boundary split

Harmony may own:

- organization, workspace, and user/group UI;
- approval queue UX;
- artifact registry UX;
- connector configuration UX;
- enterprise policy authoring UI;
- billing and admin consoles.

Splendor owns:

- tenant, agent, run, tick, action, state, trace, and approval identity;
- signed work-order validation;
- approval verifier behavior;
- Action Gateway enforcement;
- state graph commits;
- append-only trace events;
- replay and audit reconstruction.

Harmony must not provide broad user credentials to Splendor runs. It should issue
scoped, signed work orders and approval decisions that map to Splendor governance
objects.

## Endpoint mapping

The Harmony-compatible route names are the default values for
`ExternalGovernanceEndpoints`:

| Harmony route | Splendor contract field |
| --- | --- |
| `GET /splendor/work-orders/:id` | `work_orders` |
| `POST /splendor/action-gateway` | `action_gateway` |
| `POST /splendor/traces` | `traces` |
| `POST /splendor/state-commits` | `state_commits` |
| `POST /splendor/approvals` | `approvals` |
| `POST /splendor/artifacts` | `artifact_refs` |

These names are a thin mapping. A non-Harmony control plane can rename endpoints
while reusing the same Splendor schema and validation behavior.

## Work-order rule

Harmony should issue a `WorkOrderEnvelope` with:

- `allowed_actions`;
- `allowed_adapters`;
- `allowed_permissions`;
- `data_refs`;
- quotas;
- expiry;
- detached signature metadata.

The external bridge checks that signature metadata is present and rejects
credential-like context fields. The receiving Splendor runtime still validates the
signature against its keyring, checks expiry/revocation, validates tenant/agent/run
compatibility, and emits work-order traces before the run can start or resume.

## Approval rule

Harmony approval decisions map as follows:

```text
Harmony approval granted
  -> ExternalApprovalDecision { decision = granted }
  -> ApprovalGrant { scope, expires_at, issuer, trace }
  -> existing approval verifier / gateway path

Harmony approval denied
  -> ExternalApprovalDecision { decision = denied }
  -> ApprovalDenial { scope, expires_at, issuer, trace }
  -> denied or paused runtime path; no adapter execution
```

If Harmony is unavailable or returns a malformed response, the bridge produces
`ExternalApprovalMapping::AdapterFailure`. That mapping does not contain an
approval grant and cannot execute an action.

Harmony approval grants must be scoped to one Splendor action. Tenant-wide,
agent-wide, global, or adapter-wide grants are rejected as broad authority. Harmony
may still send broader denials because denials fail closed and do not authorize
execution.

## Artifact rule

Harmony artifact records should store Splendor provenance through
`GovernedArtifactRef`:

```text
Harmony Artifact
 ├── artifact_id
 ├── version
 ├── source_refs
 ├── splendor_run_id          -> run_id
 ├── splendor_state_node_id   -> state_node_id
 ├── splendor_trace_range     -> trace_range
 ├── approval_state
 └── publication_targets      -> export_targets
```

This lets Harmony index artifacts while Splendor remains source of truth for the
state and trace evidence that produced them.

If Harmony marks an artifact as `granted`, `denied`, `expired`, or `revoked`, it
must include the Splendor `approval_id`; otherwise the artifact reference is
rejected to avoid approval-state spoofing.

## Replay and audit

Replay is inspect-only. It may explain Harmony work-order references, approval
grant/denial mappings, adapter failures, and artifact trace ranges. It does not
call Harmony, retry approvals, refresh credentials, publish artifacts, or execute
adapters.

## Required tests

```bash
cargo test -p splendor-types external_governance
npm test
```
