# 0.04-S6 — External Governance Adapter

## Objective

Implement the 0.04-S6 control-plane adapter contract so Harmony or another
external governance system can bridge scoped work orders, approval decisions, and
artifact references into Splendor without owning runtime enforcement or becoming a
product-specific kernel dependency.

## Functional scope

- Adds provider-neutral external governance adapter schemas in Rust and
  TypeScript.
- Adds a Harmony-compatible endpoint skeleton that can be renamed by other control
  planes without changing Splendor runtime objects.
- Validates scoped signed work-order bridge shape and rejects broad credential or
  authority metadata.
- Maps external approval grants and denials to first-class `ApprovalGrant` and
  `ApprovalDenial` governance objects with explicit scope, expiry, issuer, and
  trace linkage.
- Requires external approval grants to be action-scoped so external control planes
  cannot create blanket approval authority.
- Represents external adapter failure as a non-authorizing fail-closed mapping.
- Adds `GovernedArtifactRef` for trace-linked artifact references with run, state,
  trace, approval, and source reference fields.

## Non-goals

- No Harmony admin UI.
- No billing, org, workspace, user/group, or marketplace product model.
- No approval workflow engine or approval queue implementation.
- No OAuth/OIDC/PKI product or broad credential broker.
- No new daemon endpoint or side-effect path outside the existing Action Gateway.
- No 0.04-S7 governance replay/audit engine changes.

## Public contracts changed

- Rust `splendor-types`:
  - `ExternalGovernanceAdapterContract`
  - `ExternalGovernanceEndpoints`
  - `ExternalGovernanceReference`
  - `ExternalGovernanceWorkOrderBridge`
  - `ExternalApprovalDecision`
  - `ExternalApprovalMapping`
  - `ExternalGovernanceAdapterFailure`
  - `ExternalTraceRange`
  - `GovernedArtifactRef`
  - `EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION`
  - `GOVERNED_ARTIFACT_REF_SCHEMA_VERSION`
- TypeScript `@splendor/types` mirrors those contracts.
- Documentation:
  - `docs/integrations/governance-adapter.md`
  - `docs/integrations/harmony.md`
  - `examples/harmony-governance-bridge/README.md`

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Percept | none |
| Policy | none |
| Gateway | external decisions remain inputs to existing gateway verification; no bypass added |
| Verifier | approval decisions map to objects consumed by existing approval verifier paths |
| State graph | artifact references point to explicit `state_node_id`; no hidden state added |
| Trace store | external work-order, approval, failure, and artifact facts carry trace linkage; no new event variants |
| Replay | inspect-only reconstruction from mapped objects and artifact trace ranges |
| Message | none |
| Work order | signed scoped work-order bridge shape added; work-order validation remains unchanged |
| Governance | external approval grant/denial/failure mapping added |

## Trace behavior

No new trace event class is introduced. The adapter contract uses existing trace
classes and trace links:

- work-order bridge feeds existing `WorkOrderAccepted` / `WorkOrderRejected` paths;
- external grants map to `approval.granted` governance objects;
- external denials map to `approval.denied` governance objects;
- adapter failure carries trace linkage and must be recorded as a denial,
  intervention, or audit fact by the receiving runtime path;
- artifact references include an explicit trace range.

## State behavior

No state graph format change is introduced. `GovernedArtifactRef` records the
state node that already represents the artifact-producing transition. External
control planes may index that reference but do not gain state ownership.

## Gateway and verifier behavior

- Work-order bridge shape validation rejects unsigned envelopes and credential-like
  metadata before a runtime attempts run creation or resume.
- Approval grant/denial mappings do not execute adapters. A grant must be
  action-scoped and remains subject to the existing approval verifier and all
  gateway checks.
- Adapter failure maps to `ExternalApprovalMapping::AdapterFailure`, which contains
  no approval grant and therefore cannot authorize side effects.
- Denials and malformed scope fail closed.

## Replay behavior

Replay can inspect external references, approval grant/denial mappings, fail-closed
adapter failures, and artifact trace ranges. Replay does not contact external
control planes, issue approvals, resume runs, call gateways, publish artifacts, or
execute adapters.

## Failure behavior

- Unsupported schema versions reject.
- Unsigned work-order bridge rejects.
- Endpoint paths, issuer/source, and trace linkage are required.
- Credential-like metadata rejects as a permission-laundering risk.
- Scheme-relative, absolute, parent-directory, whitespace/control-character, or
  backslash endpoint paths reject.
- Broad external approval grant scopes reject.
- Approval expiry must be after creation.
- Governance scope and trace run mismatches reject.
- Missing artifact source references reject.
- Terminal artifact approval states without `approval_id` reject.
- Nil artifact trace range IDs reject.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | provider-neutral contract and Harmony/generic endpoint mapping | `cargo test -p splendor-types external_governance` |
| unit | scoped signed work-order bridge and broad credential rejection | `cargo test -p splendor-types external_governance` |
| unit | external approval grant/denial mapping with scope/expiry/issuer/trace | `cargo test -p splendor-types external_governance` |
| negative | adapter failure cannot approve by default | `cargo test -p splendor-types external_governance` |
| negative | credential aliases, broad grants, invalid endpoints, and spoofed artifact approval states fail closed | `cargo test -p splendor-types external_governance` |
| contract | TypeScript schema parity and artifact/failure shape | `npm test` |

## Example or fixture

See `examples/harmony-governance-bridge/README.md` for a Harmony-compatible JSON
walkthrough and equivalent generic control-plane mapping.

## Future extension notes

Later governance replay/audit work can index `ExternalApprovalMapping` and
`GovernedArtifactRef` in richer explanations without changing the adapter contract.
Later fleet/control-plane work can replace local route names with authenticated
remote transports while preserving the same signed work-order, approval, and
artifact reference schemas.
