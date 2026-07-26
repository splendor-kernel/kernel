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
evaluates postconditions after execution. Its first operation is the bounded raw
credential ingress guard described below. It then validates `action_id`,
`tenant_id`, `agent_id`, and `run_id`; missing or nil
identity returns a denied `ActionOutcome` with reason `identity_invalid` and does
not call adapters. Approval-required, denied, expired, revoked, wrong-scope,
unsupported-schema, forged, replayed, or exact-binding-mismatched approval
decisions/receipts also stop before adapter execution. Receipt validation is not
enough by itself: the gateway re-evaluates the current conditional authority
decision and atomically claims a one-use receipt immediately before durable
pre-effect evidence and adapter invocation.

### Raw credential ingress guard

`splendor-gateway` owns one pure, always-on denial guard for the existing
`Action` / `ActionRequest` path. The guard runs before identity validation,
adapter lookup, authority/broker/provider evaluation, verifier calls, pre-effect
recording, or adapter execution. Kernel and daemon pre-persistence ingresses call
the same Gateway-owned implementation; they do not maintain independent key or
content rules.

The guard recursively checks action fields, param keys and values, requested
adapter, satisfied-precondition strings, free-form raw approval-evidence fields,
and free-form strings in raw authority obligation receipts. Approval-evidence and
receipt screening is content denial only: it neither validates the object nor
turns it into authority. Case/separator-normalized
credential coordinates include authorization/proxy authorization, common
`authKey`/`apiToken`/`X-API-Key`/`X-Auth-Token`/`Private-Token`/`authz` aliases,
password/passwd, token/API key, Vault/Consul token environment coordinates,
Kubernetes `secretKeyRef`, client secret, private key, cookie/set-cookie,
secret/credential, connection-string/DSN, provider environment-password aliases,
presigned signature coordinates such as `X-Amz-Signature`, URL userinfo, and
equivalent nested map/list content. Credential material in an object key is
screened as content as well as by normalized key name.

Neutral-key strings are denied when they contain a complete bounded Basic/Bearer
authorization form, PEM private-key block, boundary-delimited provider token,
embedded generic secret reference, or unambiguous credential URL/DSN/assignment
form. Closed selector-plus-material objects such as `{ "name": "VAULT_TOKEN",
"value": "..." }` are screened against the same Gateway-owned credential-key
grammar, excluding the intentionally ambiguous generic `token` selector and
non-ASCII labels. Generic schema descriptions such as `{ "name": "token",
"type": "string" }` are not treated as credential material merely from their
label. Lexical boundaries are complement-based and Unicode-safe: Unicode
alphanumeric characters continue a surrounding word, while ASCII or Unicode
punctuation/separators delimit authorization, provider-token, reference, and
assignment syntax. Basic tokens are locally base64-decoded within the scanner
limit and deny only when the decoded credential has the required colon structure;
short valid Basic/Bearer credentials still deny. A valid bounded credential
prefix ending at punctuation is denied even when that punctuation is also legal
inside the broader Basic, Bearer, provider, or reference alphabet. Provider
profiles use provider-specific prefixes, realistic minimum/maximum lengths, and
alphabets—including exact legacy `sk-` and named modern variants rather than one
broad `sk-` family. Ordinary prose such as `Basic planning`, standalone
`hf_transformer`, and resource paths such as `models/hf_transformer` or
`models/sk-learn-sentiment-classifier-v2` remain accepted.

URL scanning extracts bounded candidates instead of treating surrounding prose as
part of a scheme. It separates a structurally valid numeric authority port before
screening the once-decoded host. Hosts must be nonempty bounded reg-name/IPv4-style
names, parsed IPv6 literals with optional zone IDs, or valid IPvFuture literals;
ports must use a raw structural colon and fit `u16`; an encoded colon is never
promoted into a port separator. Raw and once-encoded IP-literal brackets receive
equivalent candidate parsing, and scoped IPv6 `%25` zone delimiters accept bounded
unreserved zone IDs. A preceding URL cannot suppress a later assignment/reference.
The guard also screens
decoded path/fragment components, standalone and URL form/query names and values,
plus-as-space values, encoded non-URL spans beside even
comma-adjacent benign URLs, query-bearing secret refs, and nested credential URLs
with a maximum nesting depth of four. Each form/percent layer is decoded once;
residual valid escapes or ambiguous encodings fail closed while an intentional
literal percent encoded as `%25` remains ordinary content. Thus `see
https://example.invalid/docs` remains accepted while encoded refs, presigned
signatures, provider tokens in authorities or paths, and nested credential URLs
deny. Object keys containing non-ASCII/confusable characters or residual percent
escapes after one bounded decode also fail closed.

Top-level numeric `params.bytes` content is always a strict credential-capable
coordinate, independent of action labels, declared side-effect class, optional
adapter routing, or later registry lookup. It requires bounded integer bytes and
unambiguous UTF-8;
UTF-8 BOM, UTF-16LE/BE, invalid UTF-8, NUL/control data, non-array, non-integer,
out-of-range, or over-budget shapes fail closed. Credential-free bounded UTF-8
bodies remain accepted. Numeric arrays under other field names retain ordinary
non-byte semantics.

All inspected raw and decoded string and object-key coordinates must also be
unambiguous text. UTF BOM markers and non-whitespace control/NUL characters fail
closed before a string can enter traces, persistence, safety evidence, or an
adapter. Tabs and ordinary line endings remain valid credential-free text.

The Gateway also exposes the same recursive bounded value entry point for an
owning service to screen a complete closed JSON envelope. The daemon uses it for
`DeviceRuntimeProfile`; Gateway owns detection vocabulary while the daemon remains
profile schema/mutation owner.

Traversal is bounded to depth 16, 2,048 inspected nodes, 16 KiB per string/key,
and 64 KiB cumulative inspected UTF-8 bytes. A cap overflow returns the same
fieldless, non-serializable `RawCredentialInputDenied`; its `Display` and `Debug`
are exactly `raw_credential_input_denied` and retain no key, value, path, parser
detail, or derived digest. The matching `ActionOutcome` is `Denied`, has no
output/artifacts, and uses only that fixed reason/error.

Persisting callers must use `raw_credential_denied_action()` for every action
trace associated with this denial. The projection is constant: it retains action
identity only in the enclosing trace identity/outcome and replaces all
requester-controlled action fields with `credential_input_suppressed` plus the
fixed suppression marker. The original denied action must never be traced.

This is a bounded denial-only compatibility barrier. It does not claim exhaustive
high-entropy, arbitrary encoded, encrypted/compressed, or split-secret detection;
does not implement RFC 0012's operation-specific `CredentialIngressProfile` or
the future repository scanner; and does not create a typed secret requirement,
broker permit, provider invocation, material delivery, or exception registry.
Generic `secret_ref_id` fields and ref-like strings are denied because the stable
generic action schema is not a typed C03 requirement path.

### Adapter-result persistence barrier

Immediately after `ActionAdapter::execute` returns successfully,
`VerifiedActionGateway` submits the complete `AdapterResult.output` plus its
satisfied-postcondition strings to the same Gateway-owned bounded scanner. The
scan occurs before invariant or safety post-verification and before any output
can enter `ActionOutcome`, traces, daemon responses, state, export, or replay.
Persisted JSON screening includes strings and keys, root numeric byte arrays, and
selected `bytes`, `body`, and `contents` numeric-byte envelopes, including the
current filesystem and HTTP result shapes. Declared JSON bodies must parse,
textual bodies must be unambiguous UTF-8, and scanner/parser/resource uncertainty
fails closed.

A match or uncertainty after adapter entry is not a pre-effect denial. The
Gateway returns `ActionStatus::Failed`, keeps the already-safe pre-verification
result, sets `post_verification` to a denial whose only reason is
`raw_credential_output_suppressed`, sets `error` to that same code, and omits
output. This does not claim that the adapter effect was rolled back or never
happened and does not authorize blind retry. Adapter errors continue to use
their existing fixed `adapter failed` projection and never expose
provider-controlled text.

The companion pure percept/state guards share this scanner owner. Percepts are
screened before trace/policy/queue retention. Policy-selected state declared as
JSON or text is strictly parsed/decoded before commit; genuinely opaque binary
state remains compatible and carries no encrypted/compressed absence claim.
This bounded compatibility barrier is not RFC 0012's per-lease streaming leak
detector, output-drain, incident, or quarantine owner.

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
