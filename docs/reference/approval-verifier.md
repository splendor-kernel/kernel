# Approval Verifier

The approval verifier is the gateway verifier for actions that must pause until
a trusted owning service satisfies an exact approval obligation. It strengthens the `approval`,
`verifier`, `action gateway`, `trace store`, and `replay` primitives without
introducing an approval queue UI, notification system, escalation engine, circuit
breaker, or workflow DSL.

Approval is an enforcement input, not a side-effect bypass. A raw
`ApprovalEvidence`, including a granted object returned by a manager, is
compatibility/replay data and cannot authorize an effect. The successful path
retries the exact challenged action with an `AuthorityObligationReceipt`; the
gateway validates and claims that receipt using trusted process configuration and
still requires identity, live authority, tenant policy, quota, precondition,
adapter, safety, and postcondition checks before execution.

## Public contracts

Rust contracts live in `splendor_types::approval` and `splendor_gateway`:

- `ApprovalPolicy`
- `ApprovalEvidence`
- `ApprovalChallenge`
- `ApprovalDecision`
- `ApprovalTraceContext`
- `AuthorityObligationReceipt`
- `AuthorityObligationReceiptLedger`
- `AuthorityObligationReceiptClock`
- `InMemoryAuthorityObligationReceiptLedger`
- `ApprovalVerifier`
- `PolicyApprovalVerifier`
- `LocalAuthorityObligationVerifier`

### ApprovalPolicy

`ApprovalPolicy` declares when an action must pause before adapter execution.
Its wire object is closed: unknown fields fail deserialization rather than being
treated as future authority or governance configuration.

| Field | Purpose |
| --- | --- |
| `schema_version` | Currently `splendor.approval_policy.v1`. |
| `policy_id` | Stable local/control-boundary identifier. |
| `tenant_id` | Tenant where the policy applies. |
| `agent_id` | Optional agent scope; absent means all tenant agents. |
| `action_name` | Optional action-name scope. |
| `adapter` | Optional adapter scope. |
| `required_permission` | Optional permission that triggers approval. |
| `side_effect_class` | Optional side-effect class that triggers approval. |
| `risk_level` | Trace-visible risk label. |
| `reason` | Explanation recorded when approval is required. |
| `expires_at` | Optional policy expiry. Expired policies fail closed as intervention. |

### ApprovalEvidence

`ApprovalEvidence` carries legacy grant/denial facts from an external approval
boundary. It remains decodable for compatibility, fail-closed decisions, trace,
and replay, but it is not authority.

| Field | Purpose |
| --- | --- |
| `schema_version` | Currently `splendor.approval_evidence.v1`. |
| `approval_id` | Approval identity distinct from run/action/trace/message IDs. |
| `tenant_id`, `agent_id`, `run_id` | Required scope. |
| `action_id` | Optional exact action identity scope. Either this or `action_name` is required when presented to the gateway. |
| `action_name` | Optional action-name scope. Either this or `action_id` is required when presented to the gateway. |
| `adapter` | Optional adapter scope in the serialized object; required when the gateway action has an adapter. |
| `decision` | `Granted` or `Denied`; `Granted` still requires a trusted receipt. |
| `reason` | Optional approver/control-boundary explanation. |
| `issued_at`, `expires_at` | Audit and expiry timestamps. |
| `revoked` | Revocation marker. Revoked evidence denies. |
| `trace_event_id` | Optional trace linkage; it does not make the object trusted. |

### ApprovalChallenge and receipt

An approval-required `ActionOutcome` carries an `ApprovalChallenge` with schema
`splendor.approval_challenge.v1`. It binds one immutable approval ID to the exact
tenant, agent, run, action ID/name/payload, effective adapter, authority subject,
conditional decision and obligation IDs, policy, receipt audience, request/action/
decision digests, original `requested_at`, and expiry. The challenge is
behavior-free and non-authorizing.

The local manager records that exact challenge. A successful grant returns both a
legacy `ApprovalEvidence` projection and one raw `AuthorityObligationReceipt`.
Only the receipt can satisfy the obligation, and only after the daemon's
`LocalAuthorityObligationVerifier` validates issuer, audience, key, signature,
revocation source, expiry, subject, decision, obligation, and all challenge
digests using trusted configuration not supplied in request JSON.

### Trusted local configuration

Resident daemon and manager processes require
`SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE`. Both processes must receive
the same owner-only regular file:

```json
{
  "schema_version": "splendor.authority_obligation_receipt_config.v1",
  "issuer_principal_id": "<non-nil-principal-uuid>",
  "audience_prefix": "splendor.daemon.run",
  "key_id": "<local-key-id>",
  "validation_secret_base64url": "<at-least-32-decoded-bytes>",
  "revocation_ref": "<configured-revocation-source-id>"
}
```

The file is secret-bearing and must not be accepted from an API request, logged,
or embedded in a challenge/receipt. Invalid, missing, non-regular, symlinked, or
over-permissive resident configuration fails startup closed. Local-dev mode uses
an explicit local default unless the file override is set; it is not production
trust. Current receipt claims are in-memory and are not restart durable.

`InMemoryAuthorityObligationReceiptLedger` also owns its trusted-time source. Its
production `Default` samples system UTC. For each validate, claim, or revoke it
first acquires the ledger mutex and then samples that clock exactly once; the same
under-lock observation controls receipt authentication time, global rollback
detection, expiry latching, lifecycle validation, and claim/revoke linearization.
The `now` argument retained on `AuthorityObligationReceiptLedger` methods is a
legacy source-compatibility input and is ignored by this built-in implementation.
Therefore caller scheduling inversion cannot manufacture rollback, while an
actual authority-clock observation below the process-global maximum still fails
closed. Clock unavailability also fails closed. There is no tolerance window,
per-receipt rollback watermark, `Instant`-only replacement, or durability claim.

The acceptance manager additionally requires the owner-only
`SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE`. Approval request, grant, deny, and
revoke accept only a fresh closed-profile Ed25519 bearer whose audience is
`urn:splendor:manager:<manager_id>`, whose sole binding is the configured fleet,
and whose exact endpoint scope is `splendor.approvals.manage`. The verified
projection must exactly match the request credential and audit principal/
credential identity mirrors. Missing or
stale verifier state, forged/expired/revoked/wrong-target proof, mirror mismatch,
or JTI replay fails before approval state or audit mutation and before receipt
issuance. Bearer, signature, raw JTI, and key material are not logged or retained
as acceptance evidence.

Manager approval trust must bind the exact client subject and must not contain
the outbound resident-dispatch signer public key. `risk_level` is optional and
must equal the challenge exactly, including `null`/absence. Approval records keep
the compatibility `issued_by` field and add separate `requested_by` and optional
`decided_by` attribution. Audit events retain only the domain-separated `sha256:`
credential correlation, never bearer or raw JTI data.

This is a bounded `local_acceptance` correction, not full manager security:
manager TLS, all other inbound manager endpoints, hot trust reload, remote
revocation propagation, and restart-durable JTI/receipt ledgers remain out of
scope.

### Manager-to-resident policy admission

The acceptance manager's `SubmitWorkOrderRequest` has an additive, default-empty
`approval_policies` list. This list is manager-owned governance configuration,
not a field in the signed `WorkOrder` v1 payload and not action authority.
Admission accepts at most 64 policies and requires:

- schema `splendor.approval_policy.v1` and no unknown policy fields;
- exact signed-work-order tenant and absent-or-exact signed agent;
- action, adapter, and permission selectors that are absent or contained by the
  signed work-order allowlists;
- unique, trimmed, control-free policy IDs of at most 128 bytes;
- a trimmed, control-free reason of at most 1024 bytes and optional risk level of
  at most 128 bytes;
- optional expiry in the future and no later than work-order expiry.

The manager stores the exact ordered set with a separate digest beside the
accepted work-order envelope. Re-submitting the same work-order ID with a changed
policy set fails with `work_order_approval_policies_replacement`. Dispatch cannot
provide a replacement: it sends only the retained policies to the resident
`CreateRunRequest`, leaves `policy_actions` empty, and preserves the signed
allowed action/adapter/permission profile. Consequently a policy can require an
approval pause but cannot make an otherwise unauthorized action executable.
This storage and the surrounding acceptance-manager API remain process-local and
are not a production-authenticated policy service.

## Verification lifecycle

For each `ActionRequest`, the gateway calls `ApprovalVerifier` before adapter
execution:

1. If no policy matches, approval is `NotRequired` and the normal verifier chain
   continues. If more than one policy matches, all matching policies are scanned
   for unsupported schema or expiry before any grant can allow execution.
2. If a policy matches and no trusted receipt is present, the live authority
   decision is narrowed to one `ApprovalRequired` obligation. The gateway returns
   `ActionStatus::NeedsApproval` with the exact challenge and does not call the
   adapter. A matching raw legacy grant returns
   `approval_obligation_receipt_required`, not execution.
3. On an exact action retry, the policy verifier defers the grant decision to the
   authority-obligation verifier. That verifier regenerates the current
   conditional decision, validates and exactly matches the receipt, and atomically
   claims it immediately before pre-effect evidence and adapter invocation. The
   built-in ledger's authority-owned UTC observation is sampled under the same
   mutex that linearizes that claim against revocation.
4. Raw denial/expiry/revocation or wrong-scope legacy evidence still fails closed.
   A waiting run accepts raw denial only on the exact pending `/actions` retry,
   without a receipt, so `PolicyApprovalVerifier` can emit the denial outcome and
   trace; it can never execute the adapter.
   Forged, replayed, expired, wrong-audience, wrong-subject, changed-payload, or
   otherwise mismatched receipts also fail closed without adapter execution.
5. If either verifier cannot safely complete, such as an expired or unsupported-schema
   approval policy, it returns `ActionStatus::NeedsIntervention` and does not call
   the adapter.

## Daemon pause/resume behavior

`CreateRunRequest.approval_policies` installs local approval policies into the
run gateway. They may be supplied directly by an authorized create caller or by
the immutable acceptance-manager admission/dispatch path above. When a tick
proposes an approval-required action, `POST
/runs/{run_id}/start` returns `RunStatus::WaitingForApproval` and the run records
`RunPaused { reason: "waiting_for_approval" }`.

`POST /runs/{run_id}/resume` does not carry successful approval anymore. From
`waiting_for_approval`, raw evidence is rejected with
`legacy_approval_evidence_non_authorizing`, receipt-bearing resume is rejected
with `approval_receipt_resume_not_supported`, and a receipt-free resume is
rejected with `approval_exact_action_retry_required`. None runs a scheduler tick
or advances state.

The caller instead submits `POST /actions` with the challenge's exact `action_id`,
tenant/agent/run, action payload, effective adapter, quota, preconditions,
`requested_at`, causal trace link, and the manager-issued
`authority_obligation_receipts`. Any mismatch returns
`approval_challenge_retry_mismatch`. A successful exact retry executes once,
records `RunResumed`, clears the pending challenge, and changes the run to
`running` without starting another scheduler tick. The process-local receipt
ledger rejects reuse, including a freshly signed receipt with the same semantic
issuer/audience/subject/decision/obligation/request/approval coordinates.
An exact retry carrying raw `Denied` evidence and no receipt is evaluated by the
same policy verifier, records denial/replay evidence, leaves adapter calls at
zero, and transitions the run to the matching terminal denial/expiry state.
After adapter execution, `RunResumed` is compare-and-transitioned only if the run
is still `waiting_for_approval` with the same pending challenge; concurrent
cancel/stop or challenge replacement wins.

## Post-grant receipt revocation

The manager retains the exact raw receipt returned by a grant and its immutable
resident instance/run target. Revoking a granted approval calls:

```text
POST /runs/{run_id}/approval-receipts/{receipt_id}/revoke
scope: splendor.approval_receipts.revoke
```

The resident validates the exact signed receipt and its
`splendor.daemon.approval_receipt.v2:instance:<instance_id>:run:<run_id>` audience,
then atomically races revocation against the gateway's one-use claim. A known
`revoked` or `already_revoked` acknowledgement completes manager revocation. An
already claimed receipt returns `approval_receipt_revocation_too_late`; transport,
identity, acknowledgement, or effect uncertainty leaves dispatch blocked rather
than pretending revocation succeeded. Both resident and manager ledgers remain
process-local in this slice.

## Trace events

Approval transitions are trace events, not out-of-band logs:

| Rust variant | Canonical event class | Purpose |
| --- | --- | --- |
| `ActionNeedsApproval` | `action.needs_approval` | Action paused before adapter execution. |
| `ApprovalRequested` | `approval.requested` | Policy-created approval request scope. |
| `ApprovalGranted` | `approval.granted` | A trusted receipt was validated and matched at the gateway. |
| `ApprovalDenied` | `approval.denied` | Denial, unsupported schema, or wrong-scope evidence was rejected. |
| `ApprovalExpired` | `approval.expired` | Expired approval evidence was rejected. |
| `ApprovalRevoked` | `approval.revoked` | Revoked approval evidence was rejected. |

Each approval lifecycle event carries `ApprovalTraceContext`, including
`approval_id`, tenant, agent, run, action, adapter, decision, reason, policy/risk
metadata where available, expiry, and revocation state.

## Replay behavior

Replay remains inspect-only. `ReplayResponse.approval_events` reconstructs approval
request/grant/denial/expiry/revocation facts from stored traces and includes the
trace event ID and sequence for each approval transition. Replay does not call the
approval verifier, re-check revocation, resume the run, or execute adapters.

## Failure modes

- Missing trusted receipt evidence for an approval-required action returns
  `NeedsApproval` and pauses the run.
- Lifecycle resume from `waiting_for_approval` returns one of the stable `409`
  migration errors above and does not tick.
- Wrong tenant, agent, run, action, or adapter scope denies.
- Manager admission rejects policies outside signed work-order scope, duplicate
  policy IDs, expired/overlong policies, and same-ID policy replacement.
- Unsupported approval evidence schema denies; unsupported approval policy schema
  requires intervention.
- Raw granted evidence cannot execute; raw denial/expiry/revocation remains
  fail-closed compatibility input.
- Missing trusted receipt configuration/ledger/challenge state, receipt expiry,
  trusted-clock unavailability or rollback, replay, signature failure, trace
  failure, or exact-binding mismatch cannot execute adapters.
- Wrong resident target/audience revocation is rejected without poisoning the
  receipt's real target; claim/revoke races have exactly one winner.
- Approval verifier uncertainty fails closed as `NeedsIntervention`.
- Trace or state persistence failures remain fail-closed according to the runtime
  loop and daemon contracts.

## Minimal example

```text
start run -> NeedsApproval + ApprovalChallenge; adapter calls = 0
request/grant exact challenge at trusted manager -> AuthorityObligationReceipt
POST /actions with exact challenged request + receipt -> Executed; adapter calls = 1
repeat receipt or alter payload -> denied; adapter calls remain 1
revoke an unclaimed granted receipt -> acknowledged known revocation; later retry denied
POST /runs/{run_id}/resume with raw evidence or receipt -> 409; no tick/state advance
```
