# Action Gateway

The action gateway is the kernel boundary for side-effectful operations. It
accepts `ActionRequest` payloads, performs verification, executes adapters, and
returns `ActionOutcome` results.

## ActionId

`ActionId` is a UUID-backed identifier assigned to each action submission.

## ActionRequest

**Fields**
- `action_id` (`ActionId`): action identifier.
- `tenant_id` (`TenantId`): tenant owning the action.
- `agent_id` (`AgentId`): agent submitting the action.
- `run_id` (`RunId`): run that scopes the action and trace events.
- `tick_id` (`Option<TickId>`): scheduler tick identity; direct daemon actions omit it.
- `action` (`Action`): requested operation.
- `adapter` (`Option<String>`): adapter identifier requested.
- `quota_usage` (`QuotaUsage`): quota usage estimate.
- `satisfied_preconditions` (`Vec<String>`): preconditions satisfied by state.
- `requested_at` (`OffsetDateTime`): submission timestamp.
- `approval_evidence` (`Option<ApprovalEvidence>`): legacy grant/denial fact used
  only for compatibility, fail-closed handling, trace, and replay. A raw grant is
  non-authorizing.
- `authority_obligation_evidence` (`Option<GatewayAuthorityObligationEvidence>`):
  compatibility envelope for a conditional decision and raw receipts. Raw fields
  remain non-authorizing until trusted validation.
- `authority_obligation_receipts` (`Vec<AuthorityObligationReceipt>`): raw
  owning-service receipts that the configured authority verifier must validate,
  exactly match to the current live decision, and claim before effect.

## ActionOutcome

**Fields**
- `action_id` (`ActionId`): action identifier.
- `status` (`ActionStatus`): execution classification.
- `verification` (`VerificationResult`): pre-execution verification result.
- `post_verification` (`Option<VerificationResult>`): post-execution verification result.
- `output` (`Option<serde_json::Value>`): adapter output payload.
- `error` (`Option<String>`): error message when denied or failed.
- `approval_challenge` (`Option<ApprovalChallenge>`): exact non-authorizing
  challenge returned for `NeedsApproval`.
- `completed_at` (`OffsetDateTime`): completion timestamp.

`ActionStatus` variants:
- `Executed` — action completed successfully.
- `Denied` — verification denied the action.
- `NeedsApproval` — approval is required and the adapter was not executed.
- `NeedsIntervention` — a verifier or runtime boundary could not safely complete
  and failed closed for operator/runtime intervention.
- `Failed` — adapter execution failed.

## ApprovalVerifier

`ApprovalVerifier::verify_approval(request, adapter, now)` evaluates the scoped
approval boundary before adapter execution. The reference implementation,
`PolicyApprovalVerifier`, uses static `ApprovalPolicy` entries to require an
`ApprovalRequired` authority obligation. `ApprovalEvidence` remains a
non-authorizing compatibility input; successful approval requires a trusted
exact receipt.

Approval verification outcomes:

- `NotRequired`: no approval policy applies; normal gateway checks continue.
- `Required`: an applicable policy requires approval; the gateway returns
  `ActionStatus::NeedsApproval` and does not call the adapter.
- `Granted`: compatibility/custom verifier result; it never makes a raw
  `ApprovalEvidence` sufficient authority.
- `Deferred`: a receipt was supplied and final permission is deferred to the
  trusted authority-obligation verifier immediately before effect.
- `Denied`: supplied evidence denied the action, expired, was revoked, used an
  unsupported schema version, or did not match tenant, agent, run, action, or
  adapter scope. The gateway returns `ActionStatus::Denied` and does not call the
  adapter.
- `NeedsIntervention`: the approval verifier cannot safely decide, such as an
  expired or unsupported-schema approval policy. The gateway returns
  `ActionStatus::NeedsIntervention` and does not call the adapter.

## ActionAdapter

`ActionAdapter::execute(request)` performs the side effect and returns an
`AdapterResult`.

**AdapterResult fields**
- `output` (`serde_json::Value`): adapter output payload.
- `satisfied_postconditions` (`Vec<String>`): postconditions satisfied by execution.

## TenantAccess

`TenantAccess` supplies permission and quota checks for the gateway:

- `verify_policy(tenant_id, action, adapter) -> VerificationResult`
- `verify_quota(tenant_id, agent_id, usage) -> VerificationResult`

## InvariantEvaluator

`InvariantEvaluator` checks action pre/postconditions against satisfied
conditions.

## VerifiedActionGateway

`VerifiedActionGateway` runs identity, live authority, approval obligation,
permission, quota, safety, and invariant checks before executing adapters and
evaluates postconditions after execution. It
first validates `action_id`, `tenant_id`, `agent_id`, and `run_id`; missing or nil
identity returns a denied `ActionOutcome` with reason `identity_invalid` and does
not call adapters. Approval-required, denied, expired, revoked, wrong-scope,
unsupported-schema, forged, replayed, or exact-binding-mismatched approval
decisions/receipts also stop before adapter execution. Receipt validation is not
enough by itself: the gateway re-evaluates the current conditional authority
decision and atomically claims a one-use receipt immediately before durable
pre-effect evidence and adapter invocation.

For physical actions, the gateway rejects forbidden low-level action names such
as motor PWM, raw actuator writes, firmware safety bypass, flight-controller
internals, collision-avoidance bypass, or emergency-stop bypass before adapter
execution. Unknown actions marked as physical are also denied before execution.

0.04-S3 escalation handling may convert a denied verifier result into
`NeedsIntervention` after the gateway has failed closed. This preserves the
gateway invariant: uncertain verifier results must not silently allow adapter
execution.

0.04-S4 adds a circuit-breaker verifier step. After the gateway resolves the
registered adapter ID and before policy/quota checks or adapter execution, it
evaluates configured tripped circuit breakers. A matching breaker returns
`ActionStatus::Denied` with reason `circuit_breaker_tripped`; missing
fleet/node/instance identity for a tripped runtime-scoped breaker fails closed
with `circuit_breaker_scope_unknown`. Adapter execution is skipped for all
breaker denials.

`VerifiedActionGateway::verify_runtime_admission()` can be used by local config
or management paths to reject new work for global, fleet, node, or instance
breakers before local agents are registered.

Authority action digests preserve the existing
`splendor.gateway.authority_action_binding.v1` bytes for nonphysical actions.
Live physical actions use the domain-separated
`splendor.gateway.authority_action_binding.physical.v2` profile and bind the
server-derived physical resource kind and exact registered node ID. Missing
physical coordinates fail closed; attaching a physical coordinate to a
nonphysical action also fails closed. Request JSON cannot set this trusted
`ActionRequest` field; kernel composition derives it after path/profile/run
matching and the emitted approval challenge retains it for exact retry.

0.05-S5 adds a local physical safety verifier stage. For high-level physical
actions, `VerifiedActionGateway::set_safety_verifier(...)` installs a
`SafetyVerifier` that runs after approval/quota verification and before adapter
execution. Safety denial returns `Denied`; safety uncertainty or a missing
required safety verifier returns `NeedsIntervention`. In both cases adapter
execution is skipped. Post-execution safety verification can mark an already
executed physical action `Failed` via `post_verification` when the adapter result
reports an unsafe physical outcome. Safety evidence uses
`splendor.safety_evidence.v1` and records status references, thresholds, zones,
and reason codes without raw sensor blobs.

## ActionGateway

Synchronous gateway interface:

```
submit(ActionRequest) -> ActionOutcome
```

## AsyncActionGateway

Async wrapper with identical semantics.

## UnimplementedGateway

Placeholder gateway that always returns `GatewayError::Unimplemented`.

## GatewayError

- `Unimplemented`
- `VerificationFailed(reason)`
- `AdapterFailed(reason)`

## Example

```rust
use splendor_gateway::{ActionGateway, ActionRequest, UnimplementedGateway};
use splendor_types::{Action, SideEffectClass};
use time::OffsetDateTime;

let gateway = UnimplementedGateway::default();
let request = ActionRequest {
    action_id: Default::default(),
    tenant_id: splendor_types::TenantId::new(),
    agent_id: splendor_types::AgentId::new(),
    run_id: splendor_types::RunId::new(),
    tick_id: None,
    action: Action {
        name: "noop".into(),
        params: serde_json::json!({}),
        side_effect_class: SideEffectClass::ReadOnly,
        cost_estimate: None,
        required_permissions: vec![],
        preconditions: vec![],
        postconditions: vec![],
    },
    adapter: None,
    quota_usage: splendor_types::QuotaUsage::single_action(),
    satisfied_preconditions: vec![],
    requested_at: OffsetDateTime::now_utc(),
    physical_action_resource_coordinate: None,
    approval_evidence: None,
    authority_obligation_evidence: None,
    authority_obligation_receipts: vec![],
};
assert!(ActionGateway::submit(&gateway, request).is_err());
```
