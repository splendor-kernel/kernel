# Runtime Daemon API Reference

The runtime daemon API is the local control boundary for Splendor runs. In the
0.1 compatibility line, the stable endpoint names and request/response shapes are
documented here. The OpenAPI document remains versioned to the current runtime
daemon API metadata and carries a separate 0.1 compatibility note.
The implementation remains foundation-oriented and is not a fleet manager or
generic auth provider. Accepted RFC 0011 adds one production-real resident caller
profile; explicit local development remains a separate loopback-only mode.

Historically this surface was introduced in 0.02-S5. 0.1 stabilizes the public
daemon boundary without promising private handler internals.

## Stable 0.1 compatibility boundary

Stable 0.1 daemon clients may rely on:

- endpoint names listed in the endpoint summary;
- JSON request/response shapes documented by OpenAPI and reference docs;
- structured daemon errors with `code`, `message`, and `details`;
- endpoint scopes from the daemon security boundary;
- signed, unexpired, unrevoked work-order requirement for run create/resume;
- gateway-mediated `/actions` submissions;
- inspect-only replay default;
- no silent fallback to unauthenticated non-dev communication.

Executable public client coverage for UC-E2E-S2 now includes the raw documented
HTTP path, `@splendor/client`, `python.splendor.daemon_client.SplendorDaemonClient`,
and `splendorctl daemon request`. Each client path creates a run from a signed
work order, appends a percept, starts a tick, submits the allowed action through
`POST /actions`, reads state/traces, exports traces, requests inspect-only replay,
and cancels the run. These clients are wrappers around daemon endpoints only; they
do not execute adapters directly or treat management credentials as action
authority.

Stable 0.1 clients must not rely on private Rust handler names, in-memory run slot
layout, local queue internals, exact test fixture IDs, native Node bindings,
browser runtime execution, production OAuth/PKI behavior, or remote fleet
transport.

## Version headers and negotiation

Stable clients should send:

```text
X-Splendor-API-Version: 0.1
X-Splendor-Client: <client-name>
```

The current TypeScript client sends `X-Splendor-API-Version` and lets callers
override the value. Its default remains `0.02-dev`, and daemon capabilities still
advertise the current runtime daemon API line until the daemon actively validates
0.1 compatibility headers.

Current limitation: the daemon route implementation does not actively negotiate
API versions or reject unsupported `X-Splendor-API-Version` values. Compatibility
is therefore validated through the OpenAPI contract, SDK docs/tests, and the 0.1
conformance suite, not by runtime version negotiation.

Future active negotiation must fail closed on unsupported versions and document
accepted version ranges before becoming stable.

The Python daemon client and `splendorctl daemon request` send the same version
and client attribution headers. `splendorctl daemon request` is intentionally
narrow and local: it accepts only explicit `http://127.0.0.1`, `localhost`, or
loopback daemon URLs, requires a caller token, supports caller-credential header
files for read requests, and requires JSON body files containing credentials for
mutating requests. It is a daemon-management wrapper, not a gateway bypass.

## Layered daemon authorization

Daemon communication must preserve these layers:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run checks -> gateway verification
```

A caller token authenticates the app. A signed work order authorizes run creation
or resume. Production-local run admission converts the already validated signed
work order into one opaque live C02 authority handle through the kernel facade.
The Action Gateway authorizes side effects only after that handle allows the
typed action, effective adapter, and every required permission. Existing copied
allowlists may narrow but cannot independently allow. No layer replaces the
others.

Run admission also derives one immutable trusted action profile per action. The
profile binds the action to its effective adapter and exact permission set before
any requester or policy candidate reaches live authority evaluation. An omitted
`RegisteredAction.required_permissions` field means the full signed work-order
permission set. When present, the field must contain that same complete set,
without duplicates and with at most 64 entries; it cannot narrow authority
operations. Because the current work-order schema has independent action and
adapter lists but no signed exact pairing, a work order allowing multiple adapters
is rejected with `ambiguous_work_order_action_adapter_profile` rather than trusting
a caller-selected Cartesian pair.

The runtime daemon API was originally the 0.02-S5 local control boundary for
Splendor runs.
It exposes a minimal HTTP surface for creating, starting, pausing, resuming,
stopping/cancelling, inspecting, exporting traces, replaying, and safely
submitting actions to a local runtime.

This API strengthens the `SDK/API`, `runtime context`, `percept`, `state graph`,
`trace store`, `action gateway`, and `replay` primitives. It is local-only and
foundation-oriented; it is not a fleet manager or production auth provider.

## Endpoint summary

| Method | Path | Purpose | Scope |
| --- | --- | --- | --- |
| `POST` | `/runs` | Create a local run from a signed work order | `splendor.runs.create` |
| `GET` | `/runs/{run_id}` | Inspect local run status | `splendor.runs.read` |
| `POST` | `/runs/{run_id}/start` | Execute one local scheduler tick | `splendor.runs.start` |
| `POST` | `/runs/{run_id}/pause` | Mark a local run paused | `splendor.runs.pause` |
| `POST` | `/runs/{run_id}/resume` | Resume a paused run and execute one tick | `splendor.runs.resume` |
| `POST` | `/runs/{run_id}/stop` | Mark a local run stopped | `splendor.runs.stop` |
| `POST` | `/runs/{run_id}/cancel` | Cancel a local run while preserving trace/state evidence | `splendor.runs.stop` |
| `POST` | `/runs/{run_id}/percepts` | Append a daemon-submitted percept queue entry | `splendor.percepts.append` |
| `POST` | `/runs/{run_id}/policies/sync` | Sync or mark failure for the run policy bundle cache | `splendor.policies.sync` |
| `POST` | `/runs/{run_id}/approval-receipts/{receipt_id}/revoke` | Revoke one exact retained approval receipt at its owning resident ledger | `splendor.approval_receipts.revoke` |
| `GET` | `/runs/{run_id}/state-head` | Return latest committed state node metadata | `splendor.state.read` |
| `POST` | `/state-snapshots/export` | Export the current state head as a trace-linked v0 handoff | `splendor.state.handoff` |
| `POST` | `/state-snapshots/import` | Experimental loopback-local import; resident mode denies until source proof exists | `splendor.state.handoff` |
| `GET` | `/runs/{run_id}/traces` | Read ordered trace records; requires `redaction_policy` | `splendor.traces.read` |
| `POST` | `/runs/{run_id}/traces/export` | Export ordered trace records with redaction policy and integrity metadata | `splendor.traces.read` |
| `POST` | `/runs/{run_id}/replay` | Start inspect-only replay summary | `splendor.replay.create` |
| `POST` | `/actions` | Submit an action through the run gateway | `splendor.actions.submit` |
| `GET` | `/health` | Read local daemon health | `splendor.health.read` |
| `GET` | `/version` | Read daemon/runtime/schema compatibility metadata | `splendor.health.read` |
| `GET` | `/capabilities` | Read local daemon capabilities | `splendor.capabilities.read` |

The OpenAPI description is maintained in
[`openapi/splendor-runtime-daemon.yaml`](../../openapi/splendor-runtime-daemon.yaml).

`GET /capabilities` returns `service_profiles` with truthful maturity labels for
the current daemon surface. The local run API is reported as implemented for the
0.1 compatibility line, bounded create-run idempotency v0 is reported as
experimental for `POST /runs` only, physical/device endpoints are reported as
simulated, and v2 watch streams plus G00/G06 evidence remain unavailable/not
exercised until an executable fixture proves them. Capability labels are
discovery metadata, not action or work-order authority.

## Local transport and security

The reference daemon binary binds to `127.0.0.1:8077` and emits a visible warning
that explicit local-only insecure dev mode is active. Non-dev callers must use
the daemon security contract from
[`daemon-security-boundary.md`](daemon-security-boundary.md): authenticated caller
identity, endpoint scope, tenant binding, audience binding, expiry, revocation,
and mutating-call audit attribution.

Resident startup is explicit. `SPLENDOR_DAEMON_MODE=resident` requires a valid
non-nil `SPLENDOR_INSTANCE_ID`, `SPLENDOR_CALLER_TRUST_FILE`, owner-only
`SPLENDOR_WORK_ORDER_KEYRING_FILE` and `SPLENDOR_POLICY_KEYRING_FILE`, plus
`SPLENDOR_TLS_CERT_FILE` and owner-only `SPLENDOR_TLS_KEY_FILE`. It serves TLS and
does not inherit local-development caller, work-order, or policy trust. Missing,
empty, malformed, stale, or unsafe inputs abort/fail closed. `local_dev` is
explicit, warning-logged, and loopback-only; unknown mode values fail startup.

Resident requests use `Authorization: Bearer` with the accepted closed Ed25519
profile from [RFC 0011](../rfc/0011-resident-caller-auth-and-dispatch.md). The
body/header `CallerCredential` and `AuditAttribution` objects are compatibility
mirrors only. They must exactly match the verified projection and cannot supply
proof. Resident middleware carries verified context internally and can supply
the compatibility projection when wire mirrors are omitted; supplied mirrors
remain equality checks only. `401` responses include the bounded `WWW-Authenticate` Bearer challenge;
scope, tenant, and mirror mismatches return `403`.
For mutating requests, the verified JTI is atomically consumed before handler
mutation; reuse returns `caller_token_replayed`. Reads may reuse an unexpired
token. The projected `credential_id` is a bounded domain-separated `sha256:`
correlation digest, never raw JTI, and middleware replaces caller-supplied audit
time with its server authentication timestamp before trace recording.

Run creation, run resume, and state handoff require signed, unexpired, unrevoked,
scoped work orders. The daemon checks work-order tenant, run scope where
applicable, and agent compatibility for run creation. Resume and state import
additionally require the original `work_order_id` and the exact canonical
work-order payload admitted at creation, normalized to the resolved `run_id`; a
newly signed broader or otherwise changed work order is rejected. Caller
credentials and the exact target work order are still insufficient for resident
state import: resident mode requires source-authenticated handoff proof that v0
does not provide and returns `state_handoff_proof_unavailable`. Caller credentials
never authorize actions directly. A cryptographically valid exact-profile import
for an unknown run receives the same proof-unavailable response rather than a
run-not-found oracle;
`/actions` always submits to the `VerifiedActionGateway` path with
`GatewayVerificationState::Required`.

When `CreateRunRequest.policy_bundle_required` is true, the daemon also requires
a signed policy bundle and rejects invalid, future-issued, expired, revoked,
malformed, or incompatible bundles before policy invocation or adapter execution
can occur.
The endpoint and request/response shapes are unchanged, but daemon-visible policy
errors now also include monotonic cache reasons such as
`policy_cache_install_rollback`, `policy_cache_install_conflict`, and scoped
revocation mismatch reasons. A failed candidate cannot reconnect a disconnected
cache.
Run caches are bound to the run tenant+agent. Exact active retry cannot
reconnect, and active refresh must advance both current authority and any trusted
revocation watermark. The daemon prepares cache mutation, persists required
acceptance/connectivity/revocation events, then commits. Trace failure leaves
prior active-install authority/connectivity unchanged. Matching revocation trace
failure additionally latches the exact pending watermark and denies
`policy_evidence_unavailable`; durable retry reconciles it. Mutation goes through
the cache's high-level traced methods, not public plan/commit seams. A partial
prepared/non-authorizing trace may remain and does not by itself prove commit.

## Run lifecycle

`POST /runs` creates an in-memory local run slot with:

- one tenant context;
- one agent runtime context;
- an in-memory trace store;
- an in-memory state store;
- a queued perceptor for daemon-submitted percepts;
- a scheduler containing one loop engine;
- a `VerifiedActionGateway` with explicitly registered local adapters;
- immutable action/adapter/exact-permission profiles derived from the validated
  work order and explicit registrations;
- one opaque live C02 run-authority handle admitted only from
  `ValidatedWorkOrder` (not a raw request payload);
- the admitted work-order identity and a domain-separated digest of its canonical
  payload bound to the resolved run, used only to prevent authority substitution
  on resume;
- one shared-runtime pre-effect authority evidence recorder;
- optional `approval_policies` evaluated by the gateway approval verifier.

The global run registry stores only shared references to per-run synchronized
state. Request handlers clone the reference and release the registry lock before
inspecting or mutating a run. Direct and physical action handlers also release
the per-run state lock before gateway verification, pre-effect evidence, and
adapter execution; the live final authority permit, not a broad daemon lock,
linearizes an effect against terminal closure.

`CreateRunRequest` also requires non-blank `request_id` and `idempotency_key`.
The request ID is correlation only and remains distinct from `run_id` and
`work_order_id`. The daemon owns a bounded in-memory create-run idempotency ledger
scoped by caller/principal, tenant, agent, work order, resolved run ID, and the
creation request fingerprint. The first accepted request returns an
`idempotency_receipt_id`; an exact retry with the same key and scope returns the
same run and receipt with `duplicate: true` and does not create another run slot.
Reusing an idempotency key for a different scope fails closed with
`create_run_idempotency_scope_mismatch`; public error details intentionally omit
raw attempted/existing scope fields and caller identifiers.
The stable caller scope contains principal identity but not ephemeral bearer
credential/JTI correlation ID, so a safe retry can present a fresh one-use token
without changing the durable idempotency scope.
Create-run request fingerprints and idempotency receipt hashes use
domain-separated BLAKE3. The earlier FNV representation is not emitted.

After work-order and caller authentication, but before request fingerprinting,
idempotency lookup/receipt creation, run-authority admission, run-slot insertion,
state creation, or trace creation, the daemon screens every configured
`policy_actions` candidate, including its raw authority-obligation receipt
strings, with the Gateway-owned raw credential guard. Receipt screening occurs
before the receipt bytes can enter the creation fingerprint, idempotency scope,
static policy, run slot, state, or trace; Authority remains the sole receipt
validator. A match, ambiguity, or scanner-budget overflow returns HTTP `400` with only
`raw_credential_input_denied`. The error has null details and does not reflect a
key, value, path, parser error, digest, or configured action. Exact retries remain
clean rejections; no idempotency receipt or run ID has been reserved, so a later
credential-free request may use the same idempotency key normally.

`CreateRunRequest.approval_policies` installs local approval policies for the run.
`LifecycleRequest.approval_evidence` and `SubmitActionRequest.approval_evidence`
remain decodable for compatibility and fail-closed trace/replay handling, but a
raw grant is never action authority. `SubmitActionRequest.authority_obligation_receipts`
carries raw owning-service receipts to trusted daemon-side validation; lifecycle
resume cannot consume them.

`start` and `resume` execute exactly one scheduler tick. This keeps the local
daemon deterministic while proving the daemon boundary. Continuous/background
scheduling is not introduced here. `start` accepts only `pending` or `running`;
it cannot be used to bypass signed-work-order checks for a paused run. `resume`
executes a tick only from `paused` and requires the original bound work-order
payload described above. Requests targeting `waiting_for_approval` are migration-
safe rejections and do not tick; that state progresses only through an exact
receipt-bearing `/actions` retry.

Run statuses are:

```text
created
running
waiting_for_approval
paused
denied
expired
stopped
failed
```

When a tick returns an approval-required action, its `ActionOutcome` includes a
full `splendor.approval_challenge.v1` challenge. The daemon records
`RunPaused { reason: "waiting_for_approval" }`, stores that exact challenge, and
returns `waiting_for_approval`. A trusted manager records the challenge and may
issue one `AuthorityObligationReceipt`. The caller must retry the exact pending
action through `/actions`, preserving action ID, tenant/agent/run, payload,
effective adapter, quota, preconditions, and original `requested_at` while adding
the receipt and causal trace link. Changed coordinates return
`409 approval_challenge_retry_mismatch`. Successful execution records
`RunResumed`, clears the challenge, and returns the run to `running` without a
new scheduler tick or state-head advance.

`/runs/{run_id}/resume` rejects raw evidence with
`legacy_approval_evidence_non_authorizing`, rejects receipts with
`approval_receipt_resume_not_supported`, and otherwise returns
`approval_exact_action_retry_required` while waiting. These are deliberate
fail-closed migration errors.

Direct `/actions` and run-bound physical action submissions normally admit
gateway work only while the run is `pending` or `running`. `waiting_for_approval`
admits only the exact pending receipt-bearing retry described above or an exact
receipt-free retry carrying raw `Denied` evidence for fail-closed verifier
tracing; missing raw
challenge state fails closed. Other actions in that state and effects while
paused, interrupted, resuming, completed, failed, cancelled, denied, or expired
return a `409` lifecycle/approval code before adapter execution. Terminal transitions close live authority
admission before publishing terminal status. A final permit acquired before that
closure may complete, but no later permit can be acquired; stop/cancel release
per-run state before waiting for those earlier permits to quiesce. Unrelated runs
remain inspectable while an earlier effect or lifecycle wait is blocked. Action
completion records cannot overwrite a terminal lifecycle status published while
the effect was in flight.

After run/tenant/agent scope and caller authentication, direct and physical
handlers apply the same Gateway-owned raw credential guard before run-authority
admission/binding, approval-state mutation, safety/simulator work, or an action
payload trace. A denied submission returns HTTP `200` with a fixed
`ActionOutcome.status = Denied` and reason/error
`raw_credential_input_denied`. The daemon records caller audit attribution and
the normal verification-started, verification-completed, denied, and outcome
sequence, but every action-bearing event uses the constant suppression
projection. It does not persist the original action, call the Gateway wrapper,
authority/broker/provider, adapter, or device simulator, or change pending
approval authority. Caller authentication credentials are validated by the
daemon security boundary and are not treated as workload action data by this
guard.

Authenticated `POST /devices/profiles` applies tenant/node scope validation first,
then serializes and recursively screens the complete caller-supplied
`DeviceRuntimeProfile` through the Gateway-owned bounded value guard before device
profile validation, audit, or profile-map mutation. This includes capabilities,
allowed/forbidden action strings, every nested constraint/status string and object
key, policy-cache strings, trace-buffer strings, zone refs, and caller-supplied
registration metadata. Rejection is HTTP `400` with fixed null-detail
`raw_credential_input_denied`; the profile cannot subsequently be read or copied
into safety evidence. Closed selector-plus-material coordinates for specific
provider/header/environment aliases, standalone form representations, and raw or
decoded BOM/NUL/control ambiguity receive the same denial as direct credential
forms. Generic schema labels such as `name=token` remain ordinary metadata.
Credential-free profiles preserve registration/read and physical execution behavior.

The physical handler additionally screens every caller-controlled string in
`SafetyContext` (`allowed_zone_refs`, `zone_ref`, and cloud-helper proposal ID)
and attached operator-intervention evidence after authenticated tenant/run scope
validation but before physical authority binding, safety snapshot/evidence,
physical traces, Gateway construction, or simulator access. The operator
intervention request/grant/deny handlers screen their free-form IDs, action,
reason, decision-expiry metadata at the same authenticated boundary before
device audit or intervention-record mutation. Operator endpoint rejection uses
HTTP `400` with the same fixed, null-detail denial; physical action rejection
uses the fixed suppressed `ActionOutcome` above.

Residual incomplete behavior: direct and physical raw-input denials for an
otherwise authenticated, run-scoped request still precede full lifecycle/quota
admission so the raw payload cannot enter Authority. A waiting or closed run can
therefore append a bounded fixed denial event group. No raw field is retained and
no Gateway/adapter/simulator effect occurs, but denial-rate/lifecycle admission
remains nonblocking follow-up rather than a completion claim for SECR-004/006.

Raw approval evidence is admitted by the kernel before daemon audit, runtime
trace, lifecycle, or gateway mutation. Active runs reject all raw grants and
denials at that boundary. The only raw-evidence exception is the exact pending
`waiting_for_approval` retry carrying a fail-closed `Denied`, expired, or revoked
decision with no obligation receipts; it can record a terminal denial but cannot
reach adapter execution.

The resident receipt-revocation endpoint accepts a closed versioned request with
the exact retained raw receipt and a bounded reason. It requires an authenticated
caller bound to the run tenant and the dedicated
`splendor.approval_receipts.revoke` scope. The path receipt ID, receipt signature,
resident instance/run audience, approval ID, and ledger coordinate must match.
The process-local ledger atomically linearizes claim versus revoke: `revoked` or
`already_revoked` returns a typed acknowledgement with `effect_certainty=known`;
an already claimed receipt returns `409 approval_receipt_revocation_too_late`.
After scope and audience authentication, an unknown run and an existing run
outside the caller's tenant both return the same `404 invalid_run` shape; wrong
scope remains `403` and wrong caller-token audience remains `401`.
This endpoint does not claim restart-durable revocation storage.

## Percept ingestion

`POST /runs/{run_id}/percepts` accepts a `Percept` only when the schema and
provenance source match the run's allowlist. Accepted percepts are consumed by
the run's queued perceptor on the next tick and appear in the normal
`PerceptsReceived` trace event, matching SDK/CLI perceptor ingestion semantics.

The daemon also records a `PerceptsAppended` trace event through the run's trace
runtime, preserving trace sequence continuity before the next tick.

## State-head behavior

`GET /runs/{run_id}/state-head` returns the latest state node committed by the
loop engine. The daemon verifies the state node exists in the backing state store
through `StateStore::get_node` before returning metadata.

Response fields include:

- `state_node_id`;
- `parent_state_node_ids`;
- `data_hash`;
- commit timestamp;
- optional state label.

## State handoff behavior

`POST /state-snapshots/export` is a trace-recorded export boundary. Import is a
mutating boundary only on explicit loopback `local_dev`; resident import is
fail-closed before mutation. Both endpoints require authenticated caller scope
`splendor.state.handoff`, matching tenant/run binding, audit attribution, and
signed run-bound work-order authority. Export revalidates the envelope retained
from run admission and rejects a request-level work-order ID or resident source
instance mismatch.

Export accepts `receiver_instance_id` and `previous_state_node_id`; the latter
is the receiver head expected before import (`null` requires no receiver head).
The source scheduler/loop/state-graph owner snapshots its current head and emits
`splendor.state_handoff.v0` plus `state.handoff.exported`.

Import request bodies include both `handoff` and the signed `work_order`
envelope. The envelope must cryptographically validate and exactly match the
target run's admitted work-order identity and canonical payload. In resident
mode those necessary checks are followed by a stable
`503 state_handoff_proof_unavailable` response with
`details.disposition = needs_intervention`. The v0 payload has no accepted source
signature/evidence proof, and its source trace ID is only caller-carried linkage.
The denial occurs before schema/hash/head/replay processing and before any state
store, state head, or run trace mutation. It records a bounded resident-only
`state_handoff.proof_denied` security audit fact containing the fixed endpoint,
method, server time, and redacted credential correlation; the diagnostic buffer
retains at most 1,024 facts and contains no raw bearer or JTI.

Only explicit loopback `local_dev` compatibility routes import through the target
scheduler and loop engine; the daemon does not mutate the backing state store
directly. A successful local-dev import records
`state.handoff.imported` before publishing the new daemon state head. Validation,
store, or trace failure fails closed. Trace failure restores the prior live graph,
agent head, and state bytes; a replayed import leaves the imported head unchanged.

This is a security compatibility correction to the earlier incomplete import
request. Clients must still send the exact signed target `work_order`, but that
does not authorize resident import. Successful resident import remains unavailable
until STA-005/EVT-005/EVID-005 supply accepted source-authenticated manifest,
source event/evidence verification, and durable replay semantics.

## Trace behavior

Trace responses return `TraceRecord` values from the run's trace store. Records
are returned in monotonic sequence order. Range reads use `start` inclusive and
`end` exclusive semantics from `TraceStore::read_range`. `GET /runs/{run_id}/traces`
and `POST /runs/{run_id}/traces/export` both require an explicit
`redaction_policy`; the export response also includes a deterministic
`integrity_hash` summary over the returned trace chain.
Resident audit records retain only the bounded domain-separated `sha256:`
`credential_id` correlation digest described above; arbitrary credential IDs
and credential material remain redacted. This permits central trace sync to
verify the resident's original hash chain without exposing bearer or JTI bytes.
For resident daemon configuration, run trace identities carry the configured
`instance_id`; local development retains the existing unset placement identity.

Lifecycle and daemon-specific events added for 0.02-S5:

```text
DaemonAudit
RunPaused
RunResumed
RunStopped
PerceptsAppended
```

`DaemonAudit { endpoint, audit }` is emitted for accepted mutating daemon calls
after S0 security validation and before the runtime mutation, preserving caller
identity and credential correlation attribution in the run trace. Resident audit
timestamps are server-owned; caller-supplied compatibility timestamps are not
persisted.

Trace export is a POST audit boundary even though it uses the trace-read scope:
its request body must include non-null `credential` and `audit_attribution`, and
the audit principal and `credential_id` must match the caller credential.

Policy distribution events added in 0.04-S5:

```text
PolicyBundleAccepted
PolicyBundleRejected
PolicySyncFailed
PolicyExpired
PolicyRevoked
```

Policy sync emits daemon audit attribution for `splendor.policies.sync`. A sync
failure records `PolicySyncFailed`; the prior cached bundle remains installed.
A matching trusted revocation candidate may additionally tombstone and block
that prior bundle, while unrelated or older revocations cannot mutate it.

Action submissions through `/actions` emit normal action trace events:

```text
ActionVerificationStarted
ActionVerificationCompleted
ActionNeedsApproval | ActionNeedsIntervention | ActionExecuted | ActionDenied | ActionFailed
OutcomeRecorded
```

For an allowed C02-protected effect, `ActionVerificationCompleted` is durably
appended by the gateway after all pre-effect verifiers allow, after an atomic
final authority permit re-check, and after final receipt validation plus atomic
one-use claim, but before the adapter is called. The permits are
held through evidence recording and adapter execution. Expiry or revocation
before permit acquisition denies; revocation closes new admission and waits for
earlier permitted effects to leave the adapter boundary. Its
`result.artifacts.authority` contains only redacted typed
decision summaries/digests and `pre_effect_recorded: true`. Append failure returns
`NeedsIntervention` and the adapter count remains unchanged. The loop and daemon
do not append a second post-effect completion event for that action.

Scheduler actions copy the scheduler `tick_id` into the gateway request. Their
verification-started, exactly one verification-completed, and terminal action
events therefore retain one tick identity in order. Direct `/actions` requests
remain outside a scheduler tick and do not fabricate a tick ID. Direct and
run-bound physical requests allocate the effective action ID before verification;
their started, single completed, terminal, and outcome records share the exact
run/tenant/agent/action identity through the run's common trace cursor.
Raw credential denials preserve that identity/order while replacing every
request-controlled action field with the constant safe projection before the
first action trace.
Their caller-supplied quota estimate is untrusted: the daemon normalizes it to at
least one action and one millisecond before quota verification. See
[`quotas.md`](quotas.md) for the current reconciliation limitation.

`SubmitActionRequest.authority_obligation_receipts` and daemon policy candidates
accept raw owning-service receipts only. A requester-supplied authority decision
is not current authority. When the live C02 evaluation is conditional, the
gateway regenerates the current action decision and passes it with the raw
receipts to `LocalAuthorityObligationVerifier`; missing, forged, stale, revoked,
replayed, extra/missing per-decision, or mismatched receipts fail closed. Raw
receipts are first checked against the complete current conditional-decision set;
no unknown decision receipt is ignored. They are then partitioned by exact
decision ID only after receipt IDs have been checked for global uniqueness, capped
at 64 per action request, validated only after all blocking verifiers and the final
authority check, and claimed atomically as one collection. Claim is the receipt
effect linearization point: expiry after claim does not cancel that exact in-flight
effect, while durable trace failure burns the receipt and still prevents adapter
execution. Trusted time is monotonic and observed expiry is latched, so clock
rollback cannot reactivate an unclaimed receipt. The current authority-owned
ledger is shared by verifier instances within one process-local run; it is
in-memory and does not claim process-restart durability.
They are not fresh authority. For a matching approval policy, the daemon narrows
the already-allowed live run decision to one exact `ApprovalRequired` obligation;
it never accepts a requester-supplied decision. The local manager can issue that
one receipt from the recorded challenge. Other owning-service receipt workflows,
production trust, and durable revocation/replay storage remain downstream work.

For create-run compatibility admission, a non-empty request-level
`allowed_permissions` list must equal the complete signed work-order permission
profile. Subset narrowing is rejected because the executable trusted action
profile is exact; omission continues to select the complete signed profile.

Approval flows may also emit `ApprovalRequested`, `ApprovalGranted`,
`ApprovalDenied`, `ApprovalExpired`, and `ApprovalRevoked`. These are verifier
facts only; they do not authorize adapter execution outside the gateway.

## Replay behavior

`POST /runs/{run_id}/replay` is inspect-only. It reads trace records, validates
that sequence numbers are contiguous and run-scoped, and returns a replay summary
with event counts, `approval_events`, and `authority_decisions` reconstructed from
durable verification records. Allowed decisions are recorded before the effect;
denials are recorded without any adapter effect. Authority summaries contain typed operation
classification, status, normalized reason codes, matched grant/obligation IDs,
and redacted decision digests; they omit concrete operation names and grant
payloads. Replay does not invoke perceptors, policies, authority evaluators,
receipt issuers/validators, gateways, verifiers, or adapters, and cannot repeat filesystem, network,
database, webhook, shell, or external-service side effects.
Raw credential denials therefore replay only the already-sanitized projection
and fixed outcome; replay cannot recover the denied input or invoke a provider or
adapter.

Replay request bodies must include non-null `credential` and
`audit_attribution`; both principal identity and `credential_id` are validated
before replay evidence is read.

`approval_events` reports approval lifecycle events with lifecycle label,
approval context, optional reason, trace event ID, and sequence. It explains why
approval was required and what grant, denial, unsupported schema, expiry, or
revocation changed the outcome without resuming the run or executing an adapter.

## Structured errors

All daemon errors use this JSON shape:

```json
{
  "code": "invalid_run",
  "message": "run was not found",
  "details": { "run_id": "..." }
}
```

Required 0.02-S5 failures include:

| Condition | HTTP | Code |
| --- | --- | --- |
| Missing/invalid resident bearer, key/JTI revocation, stale trust, or clock rollback | `401` | bounded caller-auth reason code plus `WWW-Authenticate` |
| Reused resident bearer JTI on a mutating request | `401` | `caller_token_replayed` before handler mutation |
| Verified bearer has wrong endpoint scope/tenant or mismatched metadata mirror | `403` | daemon security or mirror mismatch code |
| Invalid run | `404` | `invalid_run` |
| Malformed percept body | `400` | `malformed_percept` |
| Invalid policy bundle | `400` or `403` | policy validation reason code |
| Unauthorized or missing scope/action trace link | `403` | daemon security error code |
| Runtime unavailable | `503` | `runtime_unavailable` |
| Resume from `waiting_for_approval` with raw `ApprovalEvidence` | `409` | `legacy_approval_evidence_non_authorizing` |
| Resume from `waiting_for_approval` with obligation receipts | `409` | `approval_receipt_resume_not_supported` |
| Resume from `waiting_for_approval` without approval material | `409` | `approval_exact_action_retry_required` |
| Non-exact `/actions` retry while waiting for approval | `409` | `approval_exact_action_retry_required` or `approval_challenge_retry_mismatch` |
| Pending challenge unavailable while retrying | `503` | `approval_challenge_unavailable` |
| Direct/physical effect from another non-capable lifecycle state | `409` | `run_not_effect_capable` |
| Configured create-run action contains/ambiguously resembles raw credentials or exceeds scanner bounds | `400` | `raw_credential_input_denied`; no run/idempotency/state/trace mutation |
| Authenticated direct/physical action contains/ambiguously resembles raw credentials or exceeds scanner bounds | `200` | fixed `ActionOutcome.status = Denied`, reason `raw_credential_input_denied`, safe traces only |
| Start/resume from an incompatible lifecycle state | `409` | `invalid_run_state` |
| Resume with a different original work-order ID | `403` | `resume_work_order_identity_mismatch` |
| Resume with changed canonical work-order payload | `403` | `resume_work_order_payload_mismatch` |
| Gateway denial | `200` with `ActionOutcome.status = Denied` | action outcome |
| Governance intervention required | `200` with `ActionOutcome.status = NeedsIntervention` | action outcome |
| Multiple unsigned action/adapter pairings | `400` | `ambiguous_work_order_action_adapter_profile` |
| Narrowed registered permission profile | `400` | `trusted_action_profile_permission_mismatch` |
| Duplicate/oversized registered permissions | `400` | `registered_action_required_permissions_duplicate` / `registered_action_required_permissions_limit_exceeded` |

Gateway denials are action outcomes, not HTTP transport failures, because the
gateway successfully evaluated and denied the requested action.

Stable client handling rules:

- parse `code` as the programmatic daemon error discriminator;
- treat `message` as human-readable diagnostics, not an authorization fact;
- treat `details` as structured diagnostics whose exact keys may vary by code;
- never include bearer bytes in logs or client errors; `@splendor/client` redacts
  the exact configured token even if a transport or hostile response reflects it;
- handle HTTP `503 runtime_unavailable` as fail-closed runtime unavailability;
- handle gateway `Denied`, `NeedsApproval`, and `NeedsIntervention` as action
  outcomes where adapter execution did not occur;
- never retry side-effectful actions blindly after transport, verifier, gateway,
  state, or trace failures.

Client transport errors that happen before a daemon response should use the
client's stable error wrapper. For `@splendor/client`, this is
`SplendorClientError` with `status: 0` and `code: "network_error"`.

Conformance failures use the report shape documented in
`docs/spec/0.1/conformance.md` and include `case_id`, `primitive`,
`requirement`, `path`, `status`, and `message`.

## Compatibility notes

This reference is part of the 0.1 stable compatibility surface for documented
daemon endpoints and error shapes. It does not stabilize private Rust internals,
generic production authentication infrastructure, native Node bindings, browser
runtime behavior, fleet scheduling, or undocumented API fields. The closed
resident caller profile and mirror migration are governed by accepted RFC 0011.

The additive exact raw-receipt, registered-action permission profile, optional
gateway `tick_id`, and replay-authority-summary fields are the bounded v2 C02
production-local integration. Receipt and registered-action profile objects are
closed in Rust/OpenAPI, and TypeScript/OpenAPI contract tests retain field parity.
The current compatibility admission uses
synthetic opaque local principal IDs because daemon admission does not yet receive
C01 issuer/subject proof facts. A downstream C01 provider must replace this seam
with `issue_work_order_capability_grant`; no full OAuth/PKI, remote revocation
watch, future Artifact/Driver/Data-Use/Evidence/Fleet plane, physical helper-plan
adoption, or gold completion is claimed here. The current local run-effect path
and resident-mode cryptographic caller, TLS, scope/trace-identity, and
manager-dispatch composition are bounded non-gold component evidence under
accepted RFC 0011. This is an `IDR-002a` compatibility profile, not full
C01/IDR-002 or production manager inbound authentication. C02 and C01 gold
targets remain explicitly `not_exercised`.

Run 0.1 conformance validation from the repository root:

```bash
python conformance/0.1/run-conformance.py
```

The conformance suite proves stable fixture compatibility for runtime loop order,
gateway paths, trace/state/replay behavior, messages, work orders, governance,
adapter manifests, and S1 primitive examples. It is not a production use-case E2E
or physical safety certification claim.

## Non-goals

- No remote node registry.
- No fleet scheduling.
- No production OAuth/OIDC/PKI server.
- No approval queue UI, notification system, new escalation or circuit-breaker
  management API, or workflow DSL.
- No background resident scheduler.
- No native Node binding or browser runtime guarantee.
