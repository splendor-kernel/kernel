# RFC 0009 - Principal Registry Contract

## Status and Scope

Status: Draft, with a bounded local `IDR-001` implementation evidence slice
allowed when it preserves the non-claims below.

Scope: 0.2/v2 Principal Registry child RFC for C01,
`splendor.identity-registry`. This RFC remains a Draft contract. This repository
branch includes only a bounded local `IDR-001` Rust evidence slice: behavior-free
principal contracts in `splendor-types`, an in-memory storage/CAS seam in
`splendor-store`, and lifecycle decisions in `splendor-authority`. That local
slice does not change stable 0.1 schemas, daemon APIs, OpenAPI schemas, SDKs,
generated artifacts, Action Gateway behavior, verifier behavior, trace formats,
state formats, replay semantics, work-order validation, node registration
behavior, or runtime permission enforcement.

Acceptance of this RFC is required before implementing or claiming a stable,
durable, daemon-integrated Principal Registry service, proof-verifier adapter
contract, revocation propagation service, or migration mode. Bounded local
`IDR-001` slices may implement Rust contracts, storage seams, and lifecycle
tests as experimental evidence only. Until exact executable gold fixtures pass,
all C01 gold targets remain `not_exercised`.

This RFC preserves the non-claims in
`docs/rules/v2/foundation-readiness.md`. It does not claim full C01
implementation, full `IDR-001` completion, issue closure, a stable production
Principal Registry service, or any gold pass status.

This RFC is the Principal Registry child-RFC draft for the older RFC 0008 / #152
gate. Current implementation tracking remains the C01 aggregate #181 and child
task issues #232 through #237.

## Binding

| Item | Binding in this RFC | Evidence status |
| --- | --- | --- |
| Aggregate issue | #181, `0.2/v2 component: C01 splendor.identity-registry - Identity Registry` | Contract target only; not closed by this RFC. |
| Child issues | #232 `IDR-001`, #233 `IDR-002`, #234 `IDR-003`, #235 `IDR-004`, #236 `IDR-005`, #237 `IDR-006` | #232 has bounded local evidence only; no child issue is complete. |
| Sprint | `V2-IA-1 - Principal Registry` | RFC prerequisite target only. |
| FR bridge | `FR-0.2-02`: identity, authority, secret-reference, and data-use controls without widening tenant, agent, run, or gateway authority | This RFC covers identity registry planning only. |
| Component | `splendor.identity-registry` | Contract target only. |
| Owner packages | `splendor-types` for behavior-free contracts, `splendor-authority` for registry lifecycle decisions, `splendor-store` for persistence/CAS only | Current bounded local slice follows this ownership; stable durable service remains future work. |
| Gold targets | `G00`, `G01`, `G03`, `G43`, `G60`, `G73`, `G74`, `G79`, `G83`, `G88` | `not_exercised` until executable fixtures/harnesses pass. |

## Motivation

The v2 catalog requires Splendor to represent every actor that can own, request,
approve, execute, or attest agent work. Current 0.1-compatible contracts already
keep tenant, agent, fleet, node, instance, run, message, work-order, approval,
and governance IDs distinct, but there is no accepted contract for a unified
principal lifecycle service.

Without an explicit Principal Registry contract, implementation could drift in
unsafe ways:

- collapse `principal_id` into `tenant_id`, `agent_id`, `node_id`, or
  `instance_id`;
- treat identity existence as operational authority;
- put permissions, data-use grants, secret references, or work-order scope into
  identity metadata;
- infer stable identity from display names, IP addresses, serial numbers, or
  untyped external subjects;
- replace daemon authentication, work-order validation, or gateway verification
  before denial and migration fixtures exist;
- claim C01 or gold completion from docs-only work.

This RFC defines a narrow Principal Registry contract that later implementation
can exercise with tests, fixtures, events, replay, migration, and gold evidence.

## Primitives Affected

This RFC strengthens planning for these primitives only:

- principal identity;
- fleet/node/instance/device identity;
- tenant/agent/run compatibility bindings;
- proof binding and revocation planning;
- trace, event, and evidence planning;
- replay and migration planning;
- docs/tests.

No side effects are introduced by this RFC. No adapter, daemon endpoint, gateway,
verifier, policy, work-order, state, trace, replay, Python, TypeScript, OpenAPI,
or Rust runtime behavior changes in this RFC.

## Non-Goals

- No OAuth server, identity-provider product, full PKI management, fleet mTLS
  rollout, hardware-attestation product, or enterprise IAM system.
- No production authentication middleware or daemon authentication replacement.
- No Action Gateway, verifier pipeline, adapter, driver, work-order, approval,
  policy, data-use, secret-broker, or authority-service implementation.
- No permissions, allowed actions, allowed adapters, allowed permissions,
  capability grants, data-use grants, data refs, secret refs, work-order refs,
  approval tokens, quotas, policy refs, gateway bypass hints, or adapter
  selection in principal metadata or extensions.
- No raw credential material, private keys, bearer tokens, signatures,
  passwords, biometric payloads, secret bytes, or long-lived provider payloads in
  principal records, lifecycle events, trace records, state, prompts, artifacts,
  logs, or exported evidence.
- No collapse of `principal_id` with `tenant_id`, `fleet_id`, `node_id`,
  `instance_id`, `device_id`, `agent_id`, `run_id`, `workload_id`,
  `message_id`, `work_order_id`, `approval_id`, `event_id`, or `state_node_id`.
- No claim that display names, email addresses, hostnames, IP addresses, robot
  serial numbers, Kubernetes node names, OIDC subjects, mTLS subjects, or local
  Unix usernames are stable Splendor principal keys by themselves.
- No gold pass claim for `G00`, `G01`, `G03`, `G43`, `G60`, `G73`, `G74`,
  `G79`, `G83`, or `G88`.
- No #181, #232, #233, #234, #235, #236, #237, C01, or IDR completion or closure
  claim.

## Contract Overview

The Principal Registry owns identity existence, proof bindings, lifecycle,
status, ownership coordinates, rotation, revocation, and identity query. It does
not grant operational capability merely because a principal exists.

Layer meanings remain separate:

| Layer | Meaning | Must not become |
| --- | --- | --- |
| Principal Registry | Identifies who or what exists, current lifecycle status, and bound proof refs. | Authority to execute work or use data/secrets. |
| Authentication adapter | Verifies a provider-specific proof and maps it to a principal binding. | Authorization for daemon actions or gateway effects. |
| Authority Service | Decides capability, scope, delegation, data-use, obligations, expiry, and revocation. | Identity provider or proof verifier. |
| Signed work order | Authorizes run creation, resume, dispatch, or delegated scope. | Permanent principal authority or gateway approval. |
| Action Gateway | Mediates side effects after required verifier checks. | Optional client-side check or registry lookup. |

A principal can exist while having no authority grants. An active principal can
still be denied by work-order validation, authority decisions, data-use policy,
approval requirements, quota, local safety, verifier uncertainty, gateway checks,
or policy TTL.

## Principal Contract

These records are the bounded local Rust contracts for this experimental
`IDR-001` slice where implemented in `splendor-types`. They are not stable
Python, TypeScript, OpenAPI, daemon, store-durability, event-log, or trace
schemas.

### `PrincipalId`

`PrincipalId` is a distinct nominal ID. It must not be serialized or accepted as
any other Splendor ID type.

Required properties:

| Property | Requirement |
| --- | --- |
| Type | Nominal `PrincipalId`, not a string alias for privileged use. |
| Nil handling | Nil, empty, or malformed IDs fail closed for registration and privileged lookup. |
| Stability | Stable for one registry principal history. |
| Scope | Does not replace `tenant_id`, `agent_id`, `node_id`, `instance_id`, `run_id`, or any existing typed ID. |

### `PrincipalKind`

`PrincipalKind` identifies what type of actor the principal represents. It does
not grant authority by itself.

Proposed initial values:

| Kind | Meaning | Guardrail |
| --- | --- | --- |
| `tenant` | A tenant authority boundary represented as a principal for attribution and migration. | `tenant_id` remains the tenant scope and cannot be replaced by `principal_id`. |
| `human` | A human user, operator, annotator, approver, or reviewer. | Human identity is not approval by itself. |
| `service` | A daemon client, CLI, sidecar, control plane, or product integration principal. | Caller credentials authenticate apps; they do not grant agent action authority. |
| `agent` | A Splendor agent identity. | `agent_id` remains distinct and scoped by tenant/run/work order. |
| `runtime_instance` | A running Splendor instance. | `instance_id` is not a node, agent, tenant, or workload ID. |
| `node` | A physical, virtual, or logical host. | Node identity is not physical device identity. |
| `physical_device` | A robot, drone, humanoid, sensor package, actuator boundary, or edge device. | Device identity never bypasses local safety or grants actuator authority. |
| `governance_authority` | A governance or approval authority source. | Governance identity does not equal a valid approval decision. |
| `external_provider` | An external identity or attestation provider reference. | Provider identity does not own Splendor runtime authority. |
| `workload` | A workload or execution-boundary identity used for attribution. | Workload identity is not a run, lease, or proof of resource ownership by itself. |

Unknown or unsupported `PrincipalKind` values fail closed at privileged
boundaries until a versioned contract defines safe handling.

### `PrincipalStatus`

Allowed statuses:

| Status | Meaning | Privileged behavior |
| --- | --- | --- |
| `pending` | Registered but not yet active for privileged use. | Deny new privileged effects unless a future accepted bootstrap flow explicitly permits a narrow operation. |
| `active` | Current principal revision is eligible to be considered by authority decisions. | Still not sufficient authority by itself. |
| `suspended` | Temporarily blocked from new privileged use. | Deny new privileged effects; allow only documented containment, audit, cleanup, or appeal operations. |
| `revoked` | Terminally invalid for new privileged use. | Deny new privileged effects; no resurrection to active. |

### `Principal`

Proposed fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `principal_id` | yes | Distinct `PrincipalId`. |
| `kind` | yes | `PrincipalKind`. |
| `status` | yes | `PrincipalStatus`. |
| `revision` | yes | Current `IdentityRevision`. |
| `owner_tenant_id` | where applicable | Tenant ownership coordinate; not a permission grant. |
| `owner_fleet_id` | where applicable | Fleet ownership coordinate for nodes, instances, devices, or workload boundaries. |
| `bindings` | yes | Non-authorizing `PrincipalBinding` values to existing typed IDs or proof subjects. |
| `proof_refs` | where applicable | `PrincipalProofRef` values and proof digests; no raw proof material. |
| `display` | optional | Human-facing labels and descriptions only. |
| `metadata` | optional | Non-authorizing metadata only, subject to reserved-key rejection. |
| `created_at` | yes | Creation timestamp. |
| `updated_at` | yes | Last status or binding/proof revision timestamp. |
| `superseded_by` | optional | Replacement `PrincipalId` when supersession is recorded. |
| `migration` | optional | Compatibility migration data for 0.1 IDs; non-authorizing. |

`Principal` records are not permission records. They may be inputs to authority
decisions, but they cannot by themselves authorize runs, messages, work-order
scope, data use, secret access, adapter execution, physical action, approval,
deployment, or state mutation.

### `PrincipalBinding`

`PrincipalBinding` maps a principal to existing typed identity coordinates or
external proof subjects without replacing those identities.

Required binding rules:

| Rule | Requirement |
| --- | --- |
| Typed IDs remain typed | `TenantId`, `FleetId`, `NodeId`, `InstanceId`, `AgentId`, `RunId`, `WorkloadId`, `DeviceId`, and related IDs remain distinct binding variants, not untyped strings. |
| Existing IDs remain visible | Migration may add principal refs, but current 0.1 IDs remain visible in APIs, traces, work orders, messages, state, and replay until an accepted migration changes that. |
| Display is not identity | `display_name`, labels, aliases, contact hints, hostnames, IPs, and serial-number text cannot be stable registry keys. |
| External subject is scoped | External subject bindings must include provider, issuer, subject, audience or trust domain when applicable, and proof kind. |
| Duplicate external subject fails | A second active binding for the same canonical provider/issuer/subject/audience tuple fails deterministically unless an accepted transfer/supersession flow proves uniqueness and records history. |
| Binding is not authority | A binding is attribution and lookup data only; it does not grant permission, data use, secret use, adapter access, approval, or gateway execution. |

Proposed binding variants:

| Variant | Bound typed value | Notes |
| --- | --- | --- |
| `tenant_id` | `TenantId` | Used for compatibility and attribution; does not replace tenant scope. |
| `fleet_id` | `FleetId` | Used for fleet-scoped node/device ownership. |
| `node_id` | `NodeId` | Host identity binding. |
| `instance_id` | `InstanceId` | Runtime process identity binding. |
| `agent_id` | `AgentId` | Agent identity binding. |
| `runtime_context_id` | `RuntimeContextId` | Runtime context binding if present in the implementation slice. |
| `run_id` | `RunId` | Attribution and migration query coordinate only, not an actor identity binding for the first implementation slice and not a run authority token. |
| `workload_id` | `WorkloadId` | Future v2 workload attribution, if implemented. |
| `device_id` | `DeviceId` | Physical or edge device identity binding, if implemented. |
| `client_principal` | `AppPrincipal` or `ClientPrincipal` compatibility value | Existing daemon caller identity compatibility, not registry-backed authority by itself. |
| `external_subject` | Provider/issuer/subject/audience tuple | Canonicalized for duplicate detection; never used alone as a stable Splendor key. |

### `PrincipalProofRef`

`PrincipalProofRef` is a reference to evidence that a principal controls or is
linked to a credential, key, provider subject, local OS identity, device
attestation, governance source, or workload boundary. It never contains raw
credential material.

Proposed fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `proof_ref_id` | yes | Stable proof-reference identity within a principal. |
| `proof_kind` | yes | `unix_peer`, `mtls_subject`, `oidc_subject`, `service_account`, `device_attestation`, `governance_provider`, `workload_boundary`, or accepted future kind. |
| `provider` | where applicable | Provider or verifier namespace. |
| `issuer` | where applicable | Issuer or trust anchor reference. |
| `subject` | where applicable | Provider subject identifier or local subject reference. |
| `audience` | where applicable | Intended Splendor daemon, instance, fleet, node, or manager audience. |
| `key_id` | optional | Key or credential identifier, never key bytes. |
| `assurance_class` | optional | Future verifier assurance level. |
| `not_before` | optional | Earliest valid time, if supplied by proof contract. |
| `expires_at` | optional | Latest valid time, if supplied by proof contract. |
| `revoked_at` | optional | Revocation time for the proof binding. |
| `proof_digest` | yes | Digest over canonical proof descriptor/evidence, excluding secret or credential bytes. |
| `digest_algorithm` | yes | Hash algorithm/version for `proof_digest`. |
| `evidence_ref` | optional | Redacted evidence reference, artifact ref, event ref, or verifier receipt. |

`proof_digest` proves stable reference to proof evidence. It must not be a raw
token, private key, bearer string, signature payload, password hash for reuse, or
secret-derived value that can be used as a credential.

### `IdentityRevision`

`IdentityRevision` is the optimistic concurrency and history coordinate for a
principal.

Required semantics:

| Rule | Requirement |
| --- | --- |
| Monotonic revision | Each accepted lifecycle, binding, proof, rotation, suspension, revocation, or supersession event increments the principal revision. |
| CAS updates | Mutating commands must provide `expected_revision` or equivalent. Stale revision fails without changing current state. |
| Immutable history | Every revision record is immutable after append. |
| Current pointer | One mutable current pointer identifies the latest revision and status. |
| Store role | The store may enforce uniqueness, append-only history, transaction boundaries, and CAS. It must not decide lifecycle legality. |
| Owner role | `splendor-authority` owns lifecycle decisions. Daemon handlers, SDKs, stores, adapters, and gateway code must not duplicate the state machine. |

### `IdentityLifecycleEvent`

`IdentityLifecycleEvent` is the proposed event/evidence record for registry
mutations. This RFC does not claim current `EventEnvelope` implementation and
does not change current `TraceEvent` variants.

Proposed fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `identity_event_id` | yes | Distinct lifecycle event identity. |
| `principal_id` | yes | Principal affected by the event. |
| `previous_revision` | yes, except create | Revision before the transition. |
| `new_revision` | yes | Revision after the transition. |
| `event_kind` | yes | Lifecycle event kind. |
| `previous_status` | where applicable | Previous status. |
| `new_status` | where applicable | New status. |
| `actor_principal_id` | where available | Principal that requested or approved the mutation. |
| `request_id` | optional | Future idempotency or command request identity. |
| `reason_code` | yes | Structured reason for the transition. |
| `binding_digest` | optional | Digest of binding changes when present. |
| `proof_digest` | optional | Digest of proof changes when present. |
| `evidence_refs` | optional | Redacted evidence references only. |
| `occurred_at` | yes | Logical occurrence timestamp. |
| `recorded_at` | yes | Persistence timestamp. |

Allowed lifecycle event kinds for this RFC:

| Event kind | Meaning |
| --- | --- |
| `principal.registered` | Principal history created, normally in `pending`. |
| `principal.activated` | Status changed from `pending` or `suspended` to `active` when allowed. |
| `principal.suspended` | Status changed to `suspended`. |
| `principal.revoked` | Status changed to terminal `revoked`. |
| `principal.proof_rotated` | Proof binding changed without replacing the principal. |
| `principal.binding_added` | Binding added after validation and duplicate checks. |
| `principal.binding_removed` | Binding removed or retired while preserving history. |
| `principal.superseded` | Principal linked to a replacement principal. |
| `principal.query_denied` | Privileged query denied due to missing/invalid/stale identity or policy. |

### Query Keys

Future registry implementations should support only explicit query keys. Free
text search is not a privileged identity resolution path.

| Query key | Required result behavior |
| --- | --- |
| `principal_id` | Exact lookup. Missing or revoked status returned explicitly according to caller visibility policy. |
| `principal_id + expected_revision` | Exact lookup with revision freshness check. Stale or missing revision fails closed for privileged use. |
| `binding` | Exact typed binding lookup. Ambiguous or duplicate binding is an integrity failure. |
| `external_subject` | Exact canonical provider/issuer/subject/audience lookup. Display-only subject strings are not enough. |
| `owner_tenant_id` | Lists principals owned by a tenant subject to caller visibility policy. |
| `owner_fleet_id` | Lists fleet, node, instance, or device principals subject to caller visibility policy. |
| `kind + status` | Operational query only; cannot authorize by itself. |
| `proof_digest` | Verification/audit lookup only; digest must not be used as a bearer credential. |
| `migration_source_id` | Compatibility lookup from old typed IDs to principal bindings. Ambiguity fails migration. |

## Lifecycle State Machine

The baseline state machine is:

```text
pending -> active -> suspended -> revoked
pending -> revoked
active -> revoked
suspended -> active
suspended -> revoked
```

Forbidden transitions:

```text
revoked -> pending
revoked -> active
revoked -> suspended
active -> pending
suspended -> pending
```

Rules:

| Rule | Requirement |
| --- | --- |
| Create | Registration creates immutable history and current pointer, normally with `pending` status unless a future accepted bootstrap path proves immediate activation. |
| Activate | Activation requires valid proof binding, ownership coordinates, no duplicate external subject binding, and expected revision. |
| Suspend | Suspension denies new privileged use while preserving audit, containment, and possible future reactivation. |
| Revoke | Revocation is terminal for new privileged use. A replacement requires a new `PrincipalId` plus supersession link. |
| Rotate proof | Proof rotation appends a new revision, retires or revokes old proof refs, and preserves prior proof history. |
| Supersede | Supersession records a replacement principal without rewriting old attribution. |
| CAS | Every transition requires `expected_revision`; stale update fails without mutating the current pointer. |
| Immutable history | History records are append-only; current pointer is the only mutable registry pointer. |
| Failure atomicity | If event/evidence append or store CAS fails, the current pointer must remain unchanged. |

Revoked principals may remain queryable for audit and replay according to
visibility policy, but they cannot be used for new privileged operations.

## Metadata and Extension Rules

Principal metadata and extensions are optional display, diagnostics,
correlation, and external-reference data. They are never authorizing.

Allowed examples:

| Field class | Example |
| --- | --- |
| Display | `display_name`, `description`, `contact_label`. |
| Diagnostics | `source_system`, `import_batch`, `operator_note_ref`. |
| Correlation | `external_record_ref`, `case_id`, `asset_tag_ref`. |
| Privacy-safe provider hints | Redacted provider account hint or pseudonymous annotation handle. |

Reserved keys are rejected in metadata and extensions at every nesting depth.
Reserved keys include:

```text
principal_id tenant_id fleet_id node_id instance_id device_id agent_id run_id
workload_id runtime_context_id action_id invocation_id state_node_id event_id
message_id work_order_id approval_id artifact_id dataset_id model_id
authority capability grant scope scope_type permission permissions
allowed_actions allowed_adapters allowed_permissions data_ref data_refs data_use
policy policy_bundle work_order approval approval_token signature credential
secret secret_ref token adapter quota verifier gateway driver invocation
lease proof_digest proof_ref private_key password bearer mfa biometric
```

Rules:

| Rule | Required behavior |
| --- | --- |
| No authority in metadata | Metadata cannot grant capability, scope, work-order authority, approval, data use, secret use, adapter selection, quota, policy, verifier outcome, or gateway bypass. |
| No secret material | Metadata cannot contain secret bytes, tokens, private keys, passwords, bearer strings, raw credential payloads, or reusable credential digests. |
| No raw proof material | Proof refs and digests belong in typed proof fields only; metadata cannot carry raw mTLS/OIDC/JWT/attestation payloads. |
| No ID override | Metadata cannot override top-level typed IDs, bindings, owner coordinates, status, revision, or event identity. |
| Unknown metadata is non-authorizing | Unknown non-reserved keys may be preserved for display/correlation only and ignored by privileged decisions. |
| Reserved-key rejection | Reserved-key presence in metadata or extensions rejects the record or update before privileged use. |

## Integration Plan by IDR Task

This section maps catalog tasks to implementation slices. The current branch
implements only a bounded local `IDR-001` contract/lifecycle/storage evidence
slice. It does not claim full implementation of any task.

| Task | Future implementation plan | Anti-drift constraints | Required future evidence |
| --- | --- | --- | --- |
| `IDR-001` | Current bounded local slice adds behavior-free principal contracts, lifecycle state machine in `splendor-authority`, store history/current-pointer CAS, and typed binding compatibility helpers. | No permissions/data-use/secret refs in metadata; no ID collapse; no display/external subject as stable key; no daemon/auth/gateway/work-order integration. | Local tests cover principal kind registration, lifecycle transitions, proof rotation, suspension, revocation, duplicate binding rejection, nil-ID rejection, reserved metadata rejection, credential-like proof-material rejection, and CAS failure behavior. Event Log integration, Authority Service input wiring, and G01/G60 registry-backed evidence remain future work. |
| `IDR-002` | Add provider-neutral proof verifier and authenticated-principal contracts, then local Unix peer and test mTLS verifiers before optional external adapters. | No OAuth/PKI product in kernel; no bearer strings from action params/prompts; TLS success is authentication only. | Wrong audience, issuer, subject, expired proof, rotated key, revoked principal, stale proof cache, local insecure-mode restrictions. |
| `IDR-003` | Add node and physical-device ownership/attestation lifecycle using node/instance/device principals and compatibility with existing registration records. | No identity from IP, Kubernetes node name, or serial text alone; no cloud override of local emergency stop; sensor identity is not actuator authority. | Node reimage/new binding, stale lease fencing, quarantine, device/node separation, physical-safety local-veto evidence. |
| `IDR-004` | Add human and governance-principal lifecycle for approvals, annotations, overrides, and value changes. | No raw biometrics or unnecessary provider payloads; group membership alone grants no capability; self-approval forbidden where policy forbids it. | Two-person value-change denial, stale membership denial, pseudonymous annotation auditability, separation-of-duty evidence. |
| `IDR-005` | Add exact-ID and binding queries, bounded caches, revision snapshots, watches, revocation fan-out, and freshness behavior by risk class. | No indefinitely stale active status; registry reads must not bottleneck pure computation; partial propagation must be visible. | Revocation during long workload, stale cache denial, partition/offline behavior, propagation acknowledgements. |
| `IDR-006` | Add deterministic migration from existing tenant, agent, node, instance, and governance issuer IDs to principal records, with dual-read/single-write and later dual-write/registry-required modes behind flags. | No human/service inference from free-form metadata; no historical attribution rewrite; local examples may use explicit synthetic principals. | Historical replay preserves tenant/agent/run IDs, ambiguous mapping fails, migration audit report, old IDs remain visible. |

## Event, Evidence, Trace, and Replay Expectations

This RFC does not implement `EventEnvelope`, does not add `TraceEventKind`
variants, and does not alter the current trace store. The following expectations
are future implementation requirements.

Event/evidence expectations:

| Expectation | Future requirement |
| --- | --- |
| Lifecycle events | Every accepted registry mutation appends an immutable lifecycle event before or atomically with current-pointer movement. |
| Denial events | Failed registration, duplicate binding, stale revision, wrong audience, expired proof, revoked principal, unknown kind, and ambiguous migration produce structured denial evidence. |
| Redaction | Events include proof digests and evidence refs only, never credential bytes or secret material. |
| Causality | Lifecycle events link to request IDs, actor principal refs, work-order/evidence refs where applicable, and future EventEnvelope causal parents when implemented. |
| Integrity | Store/event failures fail closed before current pointer movement or privileged use. |
| Audit visibility | Revoked/superseded identities remain explainable without allowing new privileged use. |

Trace expectations:

| Trace area | Future requirement |
| --- | --- |
| Daemon/API attribution | Mutating daemon calls record caller principal/revision or denial reason without replacing endpoint scopes or work orders. |
| Authority input | Authority decisions include principal status, revision, proof freshness, and cache freshness evidence. |
| Work-order compatibility | Work-order validation remains trace/audit attributable and cannot be bypassed by principal status. |
| Gateway compatibility | Gateway traces continue to prove verification before adapter execution. Principal status is an input, not a gateway replacement. |
| Migration | Migration emits audit records for generated principal bindings, ambiguous mappings, skipped records, and operator decisions. |

Replay expectations:

| Replay mode | Future requirement |
| --- | --- |
| Historical replay | Preserves recorded 0.1 tenant/agent/run IDs and may show optional principal bindings when present. |
| Inspect-only default | Does not call live registry, proof verifiers, revocation services, daemon endpoints, adapters, drivers, networks, filesystems, secret providers, or physical devices by default. |
| Current-policy comparison | May compare historical principal status to current status only if clearly labeled as comparison, not original evidence. |
| Unsafe live lookup | Any live identity/proof lookup for simulation must be separately gated, non-default, and unable to cause side effects. |
| Denial explanation | Explains why a historical identity operation was allowed, denied, suspended, revoked, or marked ambiguous using recorded evidence. |

## Migration and Compatibility Plan

Migration from 0.1-compatible identity records must be additive until accepted
implementation and fixtures prove otherwise.

Rules:

| Rule | Requirement |
| --- | --- |
| Preserve old IDs | `tenant_id`, `agent_id`, `fleet_id`, `node_id`, `instance_id`, `run_id`, `message_id`, `work_order_id`, `approval_id`, `trace_event_id`, and `state_node_id` remain valid and visible. |
| Do not rewrite traces | Historical trace records and IDs are never rewritten to fit new principal records. |
| Add bindings | Principal refs are added as compatibility bindings or supplemental refs, not replacements for stable fields. |
| Deterministic migration | Deterministic principal records may be created for existing explicit tenant/agent/node/instance/governance issuer IDs. |
| Ambiguity fails | Ambiguous, orphaned, or duplicate mappings fail migration and require operator resolution; no silent best-effort identity inference. |
| Dual-read path | Early migration may read old IDs and optional principal bindings while writing current stable IDs. |
| Dual-write path | Later migration may write both stable IDs and principal refs after fixtures prove parity. |
| Registry-required mode | Production registry-required mode is allowed only after accepted implementation evidence and rollback plan. |
| Compatibility fixtures | Fixtures must prove stable serialization, migration success, migration ambiguity denial, replay identity preservation, and unknown authorizing metadata rejection. |

Compatibility with existing daemon security:

- `AppPrincipal` and `ClientPrincipal` remain caller-auth contracts until future
  `IDR-002` work replaces daemon-specific parsing with an authentication adapter
  and registry lookup.
- Caller authentication remains distinct from work-order authorization and gateway
  verification.
- Local dev insecure mode restrictions remain unchanged and explicit.

Compatibility with node/instance registry:

- Existing `NodeId` and `InstanceId` remain distinct identities.
- Node/instance registration records may become principal bindings in future
  implementation.
- Registration does not authorize work by itself.

Compatibility with work orders and gateway:

- Signed, scoped, expiring, revocable work orders remain required for run
  creation/resume/dispatch where required today.
- Principal status cannot broaden work-order allowlists, data refs, adapters,
  permissions, placement, quotas, expiry, revocation, or signature semantics.
- Gateway verification remains mandatory for side effects.

## Security and Fail-Closed Matrix

| Case | Required behavior | Future evidence target |
| --- | --- | --- |
| Nil or malformed `PrincipalId` | Reject registration, lookup for privileged use, and lifecycle mutation. | Contract negative test. |
| Unknown `PrincipalKind` | Deny privileged operation; do not infer from metadata, display, or external subject. | Schema and privileged-boundary test. |
| Missing binding for privileged caller | Reject non-dev privileged request before mutation. | Daemon/API negative test. |
| Duplicate external subject binding | Fail deterministically; leave existing current pointer unchanged. | Registry uniqueness test. |
| Display name or alias used as key | Reject privileged lookup or mark ambiguous; no best-effort matching. | Query negative fixture. |
| Revoked principal | Deny new privileged effects; allow only audit/containment paths defined by policy. | Revocation and gateway-denial test. |
| Suspended principal | Deny new privileged effects unless a documented containment/cleanup operation applies. | Suspension denial test. |
| Stale `IdentityRevision` | CAS failure with no mutation. | Concurrency/CAS test. |
| Store append failure | Fail closed; current pointer remains unchanged. | Store failure injection. |
| Event/evidence append failure | Fail closed before current pointer movement or privileged use. | Event/evidence failure injection. |
| Wrong audience proof | Reject authentication result or privileged binding. | Proof verifier negative test. |
| Expired proof | Reject authentication result and prevent proof cache reuse. | Expiry test. |
| Revoked proof | Reject authentication result and prevent proof cache reuse. | Revocation test. |
| Stale proof cache | Deny high-risk operation or refresh; no indefinite stale active status. | Cache freshness test. |
| Registry unavailable | Deny new privileged effects; only declared low-risk cached reads may continue. | Outage/offline policy test. |
| Metadata contains reserved key | Reject record/update before privileged use. | Metadata rejection test. |
| Metadata contains secret or credential material | Reject/quarantine according to accepted redaction policy; never serialize into public evidence. | Secret/credential leak test. |
| Ambiguous migration | Fail migration and emit audit item; require operator resolution. | Migration negative fixture. |
| Historical replay with principal refs missing | Replay old tenant/agent/run identities and mark principal binding absent; no live lookup by default. | Replay compatibility fixture. |
| Principal active but no work order/capability | Deny operation requiring work order/capability. | Authority deny-first `G01` target. |
| Principal active but gateway verifier unavailable | Deny, pause, or intervention; adapter execution remains false. | Gateway/verifier failure test. |

## Validation Matrix

This Draft RFC previously required only repository validation as a docs-only
change. The bounded local `IDR-001` Rust slice in this branch requires the local
unit, architecture, workspace, and conformance commands listed below. Future
integration beyond this slice must provide executable evidence before changing
any gold status from `not_exercised`.

| Area | Required future validation | Gold target status |
| --- | --- | --- |
| Principal schema | Rust canonical contract tests, serialization fixtures, cross-language generated or checked schemas where public surfaces change, reserved metadata rejection. | `G00` remains `not_exercised`. |
| Lifecycle state machine | Register, activate, suspend, revoke, proof rotate, supersede, reject revoked resurrection, stale CAS no-mutation. | `G01` remains `not_exercised`. |
| Authority deny-first integration | Active principal without valid work order/capability/gateway verification still denies and adapter execution remains false. | `G01` remains `not_exercised`. |
| Replay compatibility | Historical traces keep tenant/agent/run IDs, optional principal bindings reconstruct causality, adapter invocation count remains zero. | `G03` remains `not_exercised`. |
| Human/governance principals | Two-person value-change or approval flow rejects self-approval and stale membership. | `G43` and `G79` remain `not_exercised`. |
| Fleet/node identity | Registry-backed nodes preserve distinct node/instance/principal identities, signed work and node rejection paths are evidenced. | `G60` remains `not_exercised`. |
| Physical/device identity | Device and node identities remain distinct; local safety veto and offline fallback remain authoritative. | `G73` and `G74` remain `not_exercised`. |
| Compromised worker | Invalid signature/checkpoint rejection and quarantine preserve principal/node attribution. | `G83` remains `not_exercised`. |
| Offline/revocation freshness | Expired offline policy or stale identity cache degrades or denies according to pinned safe policy. | `G88` remains `not_exercised`. |
| Migration | Deterministic migration succeeds for explicit IDs, ambiguous migration fails, old API IDs remain visible, historical replay unchanged. | `G00` and `G03` remain `not_exercised`. |

Minimum future command families, once code exists:

```text
cargo fmt --check
cargo test -p splendor-types identity
cargo test -p splendor-types schema_extensions
cargo test -p splendor-store identity
cargo test -p splendor-authority identity
cargo test -p splendor-authority
python3 conformance/0.1/run-conformance.py --format json
```

If daemon, Python, TypeScript, OpenAPI, or generated schemas are touched in a
future implementation, that implementation must also run the relevant API/client
generation, typecheck, contract, and compatibility gates.

## Acceptance Checklist for This RFC

This draft is ready for review only if all items below are true:

| Check | Status required |
| --- | --- |
| Draft status | The RFC says `Draft` and does not describe proposed behavior as implemented. |
| Scope binding | #181, #232-#237, `V2-IA-1`, `FR-0.2-02`, and gold targets are named as future evidence targets only. |
| Non-goals | OAuth/PKI product, permissions/data-use/secret refs in metadata, daemon auth replacement, gateway changes, gold pass claims, and issue closure claims are explicitly excluded. |
| Principal contract | `PrincipalId`, `Principal`, `PrincipalKind`, `PrincipalStatus`, `PrincipalBinding`, `PrincipalProofRef`, proof digest, `IdentityRevision`, lifecycle event, and query keys are specified. |
| Lifecycle | Pending, active, suspended, revoked, rotation, supersession, no revoked resurrection, CAS, immutable history, and current pointer are specified. |
| Binding semantics | Existing typed IDs remain distinct bindings; display/external subject is not a stable key; duplicate external subject binding fails. |
| Metadata | Metadata cannot authorize, cannot contain secret bytes/raw credentials, and rejects reserved keys. |
| IDR plan | `IDR-001..IDR-006` future integration plan is included. |
| Event/replay | Event/evidence/trace/replay expectations are defined without claiming current `EventEnvelope` implementation. |
| Migration | 0.1 IDs and historical traces remain valid; ambiguous migration fails. |
| Fail-closed matrix | Nil ID, unknown kind, duplicate binding, revoked principal, stale revision/cache, wrong audience, expired proof, and ambiguous migration are covered. |
| Gold honesty | Gold status remains `not_exercised` until executable evidence exists. |

## Future Implementation PR Checklist

Future implementation PRs that claim any part of `IDR-001..IDR-006` must include:

| Area | Required PR evidence |
| --- | --- |
| v2 scope | Catalog task IDs, component, plane, owner package, FR IDs, dependencies, gold IDs, and explicit non-goals. |
| Ownership | `splendor-types` owns behavior-free contracts, `splendor-authority` owns lifecycle decisions, `splendor-store` owns persistence/CAS only, daemon handlers remain thin. |
| Runtime invariants | Principal existence is not authorization; work orders and gateway remain required; side effects remain gateway-mediated; replay remains no-live-effect by default. |
| Schema and IDs | `PrincipalId` and all existing typed IDs remain nominal and non-interchangeable. |
| Metadata safety | Reserved-key rejection and no authority/secret/raw credential material in metadata are tested. |
| Positive tests | Register every principal kind, bind existing typed IDs, activate, suspend, revoke, rotate proof, supersede, and query by exact key. |
| Denial tests | Nil ID, duplicate external subject, unknown kind, revoked/suspended principal, wrong audience, expired proof, stale proof cache, stale revision, ambiguous migration. |
| Failure tests | Store append failure, event/evidence failure, CAS conflict, revocation propagation uncertainty, registry outage. |
| Trace/event/evidence | Lifecycle events, denial events, proof digests, redacted evidence refs, audit attribution, and no credential leakage. |
| Replay | Historical replay preserves 0.1 IDs, does not call live registry/proof/gateway/adapter services by default, and labels current-policy comparison. |
| Migration | Dual-read/single-write and later modes are feature-gated, reversible or explicitly forward-only, and covered by fixtures. |
| Gold/conformance | `not_exercised` is preserved unless exact executable gold fixtures pass and retained evidence is attached. |
| Docs | Docs/examples are updated only for implemented behavior; no examples imply production Principal Registry readiness before evidence exists. |

## Open Questions for Acceptance Review

These questions must be answered before implementation can claim a stable
Principal Registry surface:

| Question | Why it matters |
| --- | --- |
| Which principal kinds are in the first accepted implementation slice? | Avoids pulling all IDR tasks into `IDR-001`. |
| Is the first store durable or in-memory only? | Determines whether evidence can claim more than local contract behavior. |
| What event owner records identity lifecycle before `EventEnvelope` exists? | Prevents false claims about current trace/event implementation. |
| Which daemon caller identities map to registry principals first? | Avoids unsafe daemon auth replacement in `IDR-001`. |
| What is the exact migration flag sequence for `IDR-006`? | Prevents silent production switch to registry-required mode. |
| Which gold fixtures are executable in the first implementation PR? | Prevents docs-only or partial tests from becoming gold pass claims. |

## Summary

This RFC defines the Principal Registry contract needed to unblock later C01
implementation while preserving Splendor's identity separation, authority
separation, work-order requirements, gateway enforcement, event/evidence
integrity, replay safety, migration compatibility, and gold evidence honesty.

It is intentionally not code, not a stable service claim, not a daemon auth
replacement, not an authority service, not a gateway change, and not gold
evidence.
