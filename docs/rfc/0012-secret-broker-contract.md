# RFC 0012 - Secret Broker Contract

## Status and Binding

**Status:** Proposed for acceptance

**Compatibility line:** Additive experimental 0.2/v2 contract over the stable
0.1 gateway, trace, state, replay, work-order, and identity invariants

**Component:** C03 `splendor.secret-broker`

**Sprint:** `V2-IA-3 - Secret Broker`

**Functional requirements:** `FR-0.2-02`, `FR-0.2-08`

This RFC is the proposed C03 child contract for aggregate issue
[#183](https://github.com/splendor-kernel/kernel/issues/183) and task issues
[#245](https://github.com/splendor-kernel/kernel/issues/245) through
[#250](https://github.com/splendor-kernel/kernel/issues/250). Historical issue
#154 was a planning tracker; its closure did not accept a Secret Broker
contract or prove implementation.

This is a docs-only proposal. It does not implement a secret broker, add a
public schema, create a provider adapter, change the Action Gateway, change a
daemon endpoint, migrate a trace or state store, exercise a gold example, or
close any C03 issue. Acceptance authorizes implementation against this contract
in dependency-safe slices. Each implementation slice still requires code,
denial and failure tests, compatibility evidence, production-path wiring, and
the exact gold evidence required by its task.

| Binding | Scope | Evidence status |
| --- | --- | --- |
| `SECR-001` / #245 | Opaque refs, lease contracts, provider port | Contract target only; not implemented. |
| `SECR-002` / #246 | Node-local delivery and cleanup | Contract target; blocked on `NODE-003` and `SBX-001`. |
| `SECR-003` / #247 | Renewal, rotation, revocation, offline behavior | Contract target; no production watch or node propagation. |
| `SECR-004` / #248 | Pre-persistence leak barrier and quarantine | Contract target; blocked on `FND-009` and missing output/event/artifact/incident owners. |
| `SECR-005` / #249 | Provider adapters and HA semantics | Contract target; no provider package exists. |
| `SECR-006` / #250 | External contracts, SDKs, scanner, examples | Contract target; no external gold owner is complete. |
| Gold | `G07`, `G08`, `G10`-`G17`, `G53`, `G73`-`G75`, `G82`, `G88` | `specified_not_implemented` / `not_exercised`; this RFC does not change those statuses. |

## Decision

Splendor represents credential use through opaque references, short-lived
leases, non-resolving delivery metadata, and redacted access evidence. Secret
material is never a serializable kernel contract and never enters action
parameters, prompts, percepts, messages, work orders, state snapshots, generic
trace payloads, artifacts, datasets, public errors, or SDK responses.

The Authority Service is the one owner of Secret Broker lifecycle and mutation
semantics. It defines a Rust-only outbound `SecretProvider` port. Concrete
provider adapters implement that port under `adapters/secrets-*`. Provider SDKs
and provider-specific locators stay outside core. A resident node/executor
realizes delivery and cleanup only for the exact placed, fenced execution
boundary.

A `SecretRef`, `SecretLeaseRequest`, `SecretLease`, access event, provider
receipt, or message is not authority to execute an action. Required authority,
data-use, work-order, quota, policy, approval, safety, network/filesystem,
secret-lease, and compatibility verifiers still run through the existing Action
Gateway. Provider fetch and material delivery occur only after placement and
after the gateway has issued a private final permit. The permit remains held
through provider access, delivery, driver execution, and the point where effect
certainty is known. No SDK, provider, node, daemon handler, or adapter can mint
or reconstruct it.

## Baseline and Non-Claims

The current repository has no `SecretRef`, `SecretLeaseRequest`, `SecretLease`,
`SecretDeliveryHandle`, `SecretProvider`, `SecretAccessEvent`, secret-provider
adapter, resident executor, or pre-persistence leak barrier. Current trace and
state stores persist supplied payloads before daemon read-time redaction. That
redaction is useful output hygiene but is not a safe secret-ingress boundary.

Therefore:

- C03 cannot pass secret material through current `Action.params`, policy
  output, percepts, messages, adapter output, errors, state, or trace and rely on
  later redaction;
- current filesystem and HTTP adapters are not secret-delivery implementations;
- current caller bearer tokens, work-order verification keys, trust files, and
  startup keyring configuration are app/runtime bootstrap credentials, not
  workload-visible Secret Broker values;
- current inspect-only replay is preserved but has no C03 reconstruction model;
- current C01/C02 local evidence is a prerequisite seam, not full C03 authority;
- this RFC makes no perfect-memory-erasure, production-vault, production-node,
  production-HA, or physical-safety certification claim.

## Ownership and Dependency Direction

One concept has one owner.

| Surface | Owns | Must not own |
| --- | --- | --- |
| `splendor-types` | Behavior-free nominal IDs, closed enums, refs, requests, leases, receipts, redacted events, deterministic serialization | Provider behavior, secret material, policy, I/O, lifecycle transitions |
| `splendor-authority::secrets` | Ref and lease lifecycle, authority intersection, expiry, maximum use, renewal, rotation, revocation, provider routing decisions, private validated wrappers | Vendor SDKs, node execution, gateway replacement, artifact/event storage |
| `splendor-gateway` | Existing verified invocation path, secret-lease verifier, private final permit retention, effect certainty | Secret lifecycle state, provider routing, material resolution, delivery cleanup |
| `adapters/secrets-*` | Provider-specific fetch/renew/revoke/audit translation through the authority-owned port | Granting authority, choosing broader fallback, public errors, durable broker state |
| resident node/executor | Exact-boundary delivery, OS/orchestrator controls, close/unmount/revoke, restricted local detectors | General secret storage, fleet policy, authority evaluation, alternate effect path |
| `splendor-store` / future evidence stores | Persistence of already-safe refs, revisions, receipts, events, and CAS state | Redaction policy, provider access, lifecycle legality, secret bytes |
| daemon, CLI, Python, TypeScript | Closed transport translation, opaque helper ergonomics, inspection of safe receipts | Material resolution, client-side authority, shadow lifecycle, insecure fallback |

`SecretProvider` is not a serialized public type. The catalog's public-contract
shorthand names the provider boundary; architecture rules require the owning
component to define the outbound Rust port. Putting provider behavior in
`splendor-types` would turn it into a trait dumping ground and is rejected.
`splendor-authority` does not import a gateway type: the kernel/node composition
bridge separately holds the opaque authority-validated lease handle and the
gateway-owned final permit, rechecks both, and only then invokes the
authority-owned provider port. The bridge translates; it does not decide
authority, lifecycle, routing, or delivery policy.

## Contract Rules

All C03 serialized records use snake_case fields, RFC3339 UTC timestamps, and
closed schema names of the form `splendor.secret.<record>.v1`. All structs deny
unknown top-level fields. C03 v1 defines no `extensions`, metadata map,
arbitrary JSON field, raw provider error, free-form locator, or value field.

Unknown schema versions, unknown enum values, malformed or nil IDs, duplicate
set entries, empty required sets, invalid time windows, zero use limits, and
unbounded strings fail before privileged use. Preserving an unknown record as
opaque historical data is allowed; interpreting it as authority is not.

Canonical wire rules are fixed for v1:

- UUID-backed IDs use lowercase hyphenated canonical UUID text and reject nil;
- revisions, generations, fencing epochs, counters, and durations are positive
  JSON integers no greater than `9007199254740991`, except `uses_claimed`, which
  may be zero;
- timestamps are UTC RFC3339 with `Z`, no offset spelling, and no leap-second
  input; ordering uses authority-owned time rather than caller timestamps;
- `provider_namespace` and `logical_name` are 1 through 128 ASCII characters
  matching `[a-z][a-z0-9._-]*`;
- opaque provider version/correlation values are 1 through 128 printable ASCII
  characters, contain no control/space characters, URI scheme delimiter, path
  separator, or query/fragment delimiter, and are never interpreted as locators;
- delivery lists contain at most five unique values, data-use grant lists at
  most 16 unique IDs, and causal-parent lists at most 16 unique event IDs;
- reason/error values are closed enum spellings, not caller/provider strings.

Where a C03 idempotency or integrity digest is required, canonical bytes are
RFC 8785 JSON Canonicalization Scheme bytes for the complete closed record,
prefixed by its exact schema name and one zero byte. The digest is BLAKE3 and is
rendered as `blake3:<lowercase hex>`. Secret material, material-derived hashes,
provider requests, private permits, delivery endpoints, and detector keys are
never digest inputs. Cross-language fixtures must pin every canonical byte and
digest before a wire surface is exposed.

### Nominal identities

The following C03-owned IDs are UUID-backed nominal newtypes in
`splendor-types` when implemented:

| Serialized field | Rust type | Meaning |
| --- | --- | --- |
| `secret_ref_id` | `SecretRefId` | One logical secret reference history. |
| `secret_lease_request_id` | `SecretLeaseRequestId` | One idempotent lease command identity. |
| `secret_lease_id` | `SecretLeaseId` | One lease lifecycle. |
| `delivery_handle_id` | `SecretDeliveryHandleId` | One node-local delivery-handle lifecycle; not a bearer value. |
| `delivery_receipt_id` | `SecretDeliveryReceiptId` | One immutable delivery/cleanup receipt. |
| `secret_access_event_id` | `SecretAccessEventId` | One immutable C03 access event. |
| `secret_provider_id` | `SecretProviderId` | One configured provider adapter/routing identity. |
| `provider_audit_id` | `SecretProviderAuditId` | One sanitized provider operation receipt. |
| `secret_audience_id` | `SecretAudienceId` | Domain-separated ID derived from the trusted target binding. |
| `detector_registration_id` | `SecretDetectorRegistrationId` | Restricted node-local detector registration reference. |

C03 consumes, but does not own, `PrincipalId`, `TenantId`, `AgentId`, `RunId`,
`WorkloadId`, `NodeId`, `InstanceId`, `ActionId`, `TraceEventId`,
`WorkOrderId`, `CapabilityGrantId`, and `AuthorityDecisionId`. FND/fabric/node
owners must supply distinct nominal `WorkloadAttemptId`, `PlacementDecisionId`,
`ExecutionLeaseId`, `SandboxId`, `ProcessBoundaryId`, and `InvocationId` before
the corresponding production integration can land. C03 must not emulate any of
those with `RunId`, `WorkloadId`, a string, or metadata.

`SecretProviderVersionRef`, `SecretProviderCorrelationId`, and
`SecretLeakToken` are validated opaque newtypes, not IDs or locators. They obey
the bounds above. A `SecretLeakToken` is generated only by the restricted
node-local detector and is scoped so that equality is meaningful only within
the same tenant, lease, and detector generation.

Revisions and fencing epochs are non-zero unsigned counters, not IDs.
`secret_ref_revision`, `secret_lease_revision`, `revocation_generation`, and
`fencing_epoch` are never interchangeable.

### Closed enums

These spellings are the complete v1 sets. New values require a new compatible
schema profile or RFC amendment; privileged consumers do not guess.

| Enum | v1 values |
| --- | --- |
| `SecretClassification` | `authentication_credential`, `signing_material`, `encryption_material`, `private_configuration`, `opaque_secret` |
| `SecretDeliveryMethod` | `inherited_fd`, `tmpfs_file`, `one_shot_local_socket`, `orchestrator_projected_secret`, `environment_variable` |
| `SecretUseIntent` | `authenticate`, `sign`, `encrypt`, `decrypt`, `derive_session`, `bootstrap_transport` |
| `SecretPurpose` | `external_service_access`, `data_source_access`, `artifact_store_access`, `model_provider_access`, `orchestrator_access`, `device_service_access`, `cryptographic_operation` |
| `SecretAudienceKind` | `driver_process`, `sandbox_process`, `orchestrator_workload`, `device_local_driver` |
| `SecretOfflineBehavior` | `deny`, `continue_existing_until_expiry` |
| `SecretLeaseStatus` | `issued`, `active`, `revocation_pending`, `revoked`, `expired`, `closing`, `cleanup_uncertain`, `closed`, `quarantined` |
| `SecretDeliveryStatus` | `allocated`, `ready`, `active`, `closing`, `closed`, `cleanup_uncertain`, `quarantined` |
| `SecretCleanupStatus` | `not_required`, `completed`, `uncertain`, `quarantined` |
| `SecretProviderHealthStatus` | `healthy`, `degraded`, `unavailable`, `circuit_open` |
| `SecretProviderCircuitState` | `closed`, `open`, `half_open` |
| `SecretProviderLatencyBucket` | `lt_10_ms`, `ms_10_to_49`, `ms_50_to_249`, `ms_250_to_999`, `gte_1000_ms`, `unknown` |
| `SecretProviderOperation` | `fetch`, `renew`, `revoke`, `audit` |
| `SecretProviderOutcome` | `succeeded`, `denied`, `unavailable`, `failed`, `effect_uncertain` |
| `SecretAccessOutcome` | `allowed`, `denied`, `succeeded`, `failed`, `needs_intervention`, `effect_uncertain`, `quarantined` |
| `SecretLeakRepresentation` | `plain`, `base64`, `base64url`, `percent_encoded`, `split_chunk`, `log_injection` |
| `SecretAccessEventKind` | `lease_requested`, `lease_denied`, `lease_issued`, `delivery_requested`, `provider_fetch_started`, `provider_fetch_completed`, `delivery_ready`, `delivery_activated`, `use_claimed`, `use_completed`, `renewed`, `rotated`, `revocation_requested`, `revoked`, `expired`, `cleanup_started`, `closed`, `cleanup_uncertain`, `leak_detected`, `quarantined` |

`environment_variable` is present only for explicit compatibility. Its presence
in the enum is not permission to use it.

### `SecretRef`

Schema: `splendor.secret.ref.v1`.

| Field | Required | Contract |
| --- | --- | --- |
| `schema_version` | yes | Exact schema constant. |
| `secret_ref_id` | yes | Stable logical reference identity. |
| `secret_ref_revision` | yes | Non-zero immutable revision; current-head movement uses CAS. |
| `tenant_id` | yes | Exact owner tenant. |
| `secret_provider_id` | yes | Broker-configured provider identity, never a provider endpoint. |
| `provider_namespace` | yes | Bounded broker namespace label; no URL, filesystem path, account ID, vault path, or credential. |
| `logical_name` | yes | Bounded non-sensitive broker alias; not a provider-resolvable locator. |
| `provider_version_ref` | yes | Opaque immutable provider version reference for this ref revision. |
| `classification` | yes | Closed `SecretClassification`. |
| `allowed_delivery_methods` | yes | Non-empty unique set; `environment_variable` alone is invalid. |
| `lease_policy` | yes | Explicit finite policy described below. |
| `offline_behavior` | yes | Closed offline rule. |
| `created_at` | yes | Revision creation time. |
| `disabled_at` | no | When present, no new lease may be issued at or after this time. |

`provider_namespace`, `logical_name`, and `provider_version_ref` are broker
coordinates, not external locators. The authority owner resolves them through a
private provider-routing table. A request, SDK, action parameter, work order,
artifact, trace, or provider error cannot supply or override that table. A
provider-specific URI, mount path, account/project identifier, key path, token,
or SDK request object is forbidden in `SecretRef`.

`lease_policy` is a closed `SecretLeasePolicy` containing:

- `max_lease_duration_seconds`: positive, finite, and required;
- `max_continuous_lifetime_seconds`: positive, finite, required, and not less
  than the single-lease maximum;
- `max_uses`: positive and required;
- `renewable`: explicit boolean;
- `clock_skew_tolerance_seconds`: zero through 30 inclusive; expiry itself has
  no post-expiry grace.

There is no implicit unlimited duration, unlimited use, automatic renewal, or
offline issuance default. A deployment may impose stricter global ceilings.

Rotation appends a new `SecretRef` revision with the same `SecretRefId`, a new
opaque `provider_version_ref`, and a CAS move of the current revision. Artifact
or workload manifests can continue to name `SecretRefId`; every lease records
the exact revision and provider version it received.

### `SecretUseRequirement`

Schema: `splendor.secret.use_requirement.v1`.

This behavior-free proposal is the only way workload, driver, action, or SDK
contracts request secret use. It contains:

- `schema_version`, exactly `splendor.secret.use_requirement.v1`;
- `secret_ref_id`;
- `intent: SecretUseIntent`;
- `purpose: SecretPurpose`;
- a non-empty ordered preference list of `SecretDeliveryMethod`;
- `requested_duration_seconds` and `requested_max_uses`, each positive and
  narrowing the ref policy;
- `required`: always `true` in v1; optional best-effort secret use is not
  defined.

It contains no provider identity, ref revision, lease ID, target identity,
authority decision, delivery handle, locator, value, bytes, fallback, or
environment name. It is a request, not authority. C03 requirements cannot be
hidden in `Action.params`, prompt text, arbitrary metadata, or `extensions`.

For stable 0.1 compatibility, implementation must use the versioned wrapper
`splendor.gateway.action_request_with_secrets.v1`. Its only fields are
`schema_version`, the unchanged `action_request`, and `secret_requirements`
containing one through 16 closed requirements. Duplicate requirement tuples
`(secret_ref_id, intent, purpose)` reject. The wrapper is normalized into the
same Action Gateway and cannot define another adapter path. Its own canonical
digest binds the complete ordered requirement list, and the final permit binds
both that digest and the unchanged action-request digest. The existing
`ActionRequest` canonical bytes and hashes remain unchanged. Future v2
`Invocation` profiles may carry the same typed list after their own accepted
contract; no arbitrary JSON alias is accepted.

### Execution and authority bindings

`SecretExecutionBinding` uses schema
`splendor.secret.execution_binding.v1` and contains:

- its exact `schema_version`;
- exact `tenant_id`, `workload_id`, and `attempt_id`;
- optional `agent_id` and `run_id`, both required when the workload is an agent
  run and forbidden when not applicable;
- exact `driver_operation: DriverOperationRef`;
- exact `node_id`, `instance_id`, `placement_decision_id`,
  `execution_lease_id`, `sandbox_id`, and `process_boundary_id`;
- exact non-zero `fencing_epoch`;
- `audience_kind` and a trusted, domain-separated `secret_audience_id` derived
  from all target coordinates.

The target audience is derived by the node/gateway composition after placement.
Caller JSON cannot choose it. `driver_process` and `device_local_driver` require
the exact registered driver process. `sandbox_process` requires the exact child
process and sandbox. `orchestrator_workload` requires the exact projected
workload/sandbox identity and later process admission; it is not a namespace-wide
mount.

`SecretAuthorityBinding` uses schema
`splendor.secret.authority_binding.v1` and contains:

- its exact `schema_version`;
- exact `principal_id`, `capability_grant_id`, and `authority_decision_id`;
- optional `work_order_id`, required for a run whose admission requires a work
  order;
- `data_use_binding`, a closed tagged value that is either
  `not_applicable` with no IDs or `granted` with one through 16 distinct typed
  `DataUseGrantId` values issued by the Data-Use Controller;
- exact positive `authority_revision`, `policy_revision`, and
  `revocation_snapshot_generation`;
- the causal `TraceEventId` for the recorded authority decision.

`not_applicable` is an evaluated result, not a caller default. It is valid only
when the authority/data-use composition records that neither the secret purpose,
provider access, nor protected target data requires a data-use grant. C03
consumes `DataUseGrantId` but does not define or issue it.

The serialized binding is evidence only. Implementations accept it for live
lease issuance only when wrapped by private authority-owned validated types.
Raw deserialization cannot construct authority.

### `SecretLeaseRequest`

Schema: `splendor.secret.lease_request.v1`.

| Field | Required | Contract |
| --- | --- | --- |
| `schema_version` | yes | Exact schema constant. |
| `secret_lease_request_id` | yes | Idempotency identity. |
| `secret_ref_id` | yes | Requested logical reference. |
| `expected_secret_ref_revision` | yes | Exact currently observed revision; stale requests deny rather than silently rotating. |
| `execution_binding` | yes | Exact placed and fenced target. |
| `authority_binding` | yes | Exact validated authority evidence references. |
| `intent` | yes | Closed use intent. |
| `purpose` | yes | Closed use purpose. |
| `delivery_methods` | yes | Non-empty ordered subset of ref policy. |
| `not_before` | yes | Earliest lease use. |
| `expires_at` | yes | Requested finite expiry. |
| `max_uses` | yes | Positive requested maximum. |
| `requested_at` | yes | Authority-owned observation time. |
| `causal_event_id` | yes | Trace/event causality; not authorization. |

The request has no `value`, `bytes`, `data`, `payload`, `secret`, `token`,
`password`, `credential`, locator, provider request, fallback route, arbitrary
metadata, or extensions field. It is valid only after placement; a pre-placement
planner may carry `SecretUseRequirement`, never a lease request.

### `SecretLease`

Schema: `splendor.secret.lease.v1`.

| Field | Required | Contract |
| --- | --- | --- |
| `schema_version` | yes | Exact schema constant. |
| `secret_lease_id` | yes | One lease lifecycle. |
| `secret_lease_request_id` | yes | Original idempotent request. |
| `secret_lease_revision` | yes | Non-zero CAS revision. |
| `secret_ref_id` | yes | Logical ref. |
| `secret_ref_revision` | yes | Exact ref revision approved. |
| `provider_version_ref` | yes | Opaque exact version approved; no locator. |
| `execution_binding` | yes | Immutable exact target. |
| `authority_binding` | yes | Immutable issuance evidence refs. |
| `intent`, `purpose` | yes | Exact approved use. |
| `allowed_delivery_methods` | yes | Narrowed non-empty set. |
| `status` | yes | Closed lease state. |
| `starts_at`, `expires_at` | yes | Exact active window. |
| `continuous_lifetime_started_at` | yes | Original chain start; renewal cannot reset it. |
| `max_continuous_expires_at` | yes | Absolute renewal ceiling. |
| `max_uses`, `uses_claimed` | yes | Positive maximum and atomic counter. |
| `revocation_generation` | yes | Non-zero generation checked at every claim/delivery. |
| `issued_at` | yes | Authority-owned issuance time. |
| `renewed_from_lease_id` | no | Immediate predecessor when renewed. |
| `rotated_from_handle_id` | no | Previous handle when a rotation cutover is prepared. |
| `last_event_id` | yes | Latest canonical lifecycle event. |

A lease contains no delivery endpoint, provider locator, provider SDK response,
material digest, value commitment, key ID usable at the provider, or reusable
credential. A lease is still not an action permit.

### `SecretDeliveryHandle`

Schema: `splendor.secret.delivery_handle.v1`.

The serialized handle is safe metadata, not the resolver capability. It contains
only:

- `schema_version`, exactly `splendor.secret.delivery_handle.v1`;
- `delivery_handle_id`, `secret_lease_id`, and non-zero
  `delivery_generation`;
- exact `execution_binding` and `secret_audience_id`;
- selected `delivery_method` and closed `status`;
- `allocated_at`, optional `ready_at`, and `expires_at`;
- `revocation_generation` and `last_event_id`.

It has no filesystem path, file descriptor number, socket name, environment
variable name, orchestrator object name, mount name, provider locator, nonce,
token, capability bytes, or resolution method. The actual FD, mount, socket,
projection, or environment assignment is a non-serializable node-local object
held by the executor and bound to the target OS/orchestrator identity. Looking
up a `delivery_handle_id` outside that process boundary always denies.

### `SecretDeliveryReceipt`

Schema: `splendor.secret.delivery_receipt.v1`.

The immutable receipt contains `schema_version`, `delivery_receipt_id`,
`delivery_handle_id`, `secret_lease_id`, exact `execution_binding`,
`delivery_method`, `delivery_status`, `allocated_at`, optional `ready_at`,
optional `activated_at`, optional `close_requested_at`, optional `closed_at`,
`cleanup_status`, optional bounded `error_code` when not complete, optional
`detector_registration_id` when leak detection was installed,
`effect_certainty`, `causal_event_id`, and `terminal_event_id`.

C03 v1 deliberately does not serialize a raw, salted, or unkeyed value hash.
Such commitments can verify low-entropy secrets or enter shared canonical hash
bytes. The catalog's "where safe" commitment requirement is represented by a
restricted node-local keyed detector registration. Shared receipts contain only
its opaque ID. A future transferable commitment profile requires an RFC
amendment and a threat analysis.

### Provider health and audit records

`SecretProviderHealth` uses `splendor.secret.provider_health.v1` and contains
its exact `schema_version`, `secret_provider_id`, positive route-policy revision,
`SecretProviderHealthStatus`, `SecretProviderCircuitState`,
`SecretProviderLatencyBucket`, consecutive-failure count,
`observed_at`/`valid_until`, and a safe reason code. It contains no provider
endpoint, tenant secret name, SDK error, response body, account identifier, or
credential. `valid_until` is later than `observed_at`; an expired observation is
unavailable, never healthy by default.

`SecretProviderAuditReceipt` uses `splendor.secret.provider_audit.v1` and
contains its exact `schema_version`, `provider_audit_id`, provider ID, operation,
outcome, tenant ID,
SecretRef/lease IDs only after visibility is established, opaque provider
correlation ID, started/completed times, retry count, effect certainty, safe
reason code, and causal event ID. Provider correlation IDs are bounded,
sanitized, non-authorizing, and omitted from public/tenant views when provider
policy marks them restricted.

### `SecretAccessEvent`

Schema: `splendor.secret.access_event.v1`.

This is the canonical redacted C03 lifecycle/event payload. It contains:

| Field | Required | Contract |
| --- | --- | --- |
| `schema_version` | yes | Exact `splendor.secret.access_event.v1`. |
| `secret_access_event_id` | yes | Immutable event identity. |
| `kind` | yes | Closed `SecretAccessEventKind`. |
| `outcome` | yes | Closed `SecretAccessOutcome`. |
| `occurred_at`, `recorded_at` | yes | Authority/event-owned times. |
| `causal_parent_event_ids` | yes | Zero through 16 unique parent IDs. |
| `tenant_id`, `principal_id`, `workload_id`, `attempt_id` | yes | Exact authority/execution scope. |
| `agent_id`, `run_id` | conditional | Both present for an agent run; both absent otherwise. |
| `action_id`, `invocation_id` | conditional | At least one exact effect coordinate for delivery/use events; absent for ref-only lifecycle events. |
| `driver_operation` | conditional | Required for lease, delivery, provider, and use events. |
| `node_id`, `instance_id`, `sandbox_id`, `process_boundary_id`, `secret_audience_id` | conditional | Required after placement; absent for a pre-placement denial. |
| `secret_ref_id`, `secret_ref_revision` | visibility-gated | Both present only after reader visibility is established. |
| `secret_lease_id`, `delivery_handle_id` | conditional and visibility-gated | Present after the corresponding object exists. |
| `intent`, `purpose` | conditional | Required for lease, delivery, provider, and use events. |
| `delivery_method` | conditional | Required once selected. |
| `uses_claimed`, `max_uses`, `revocation_generation` | conditional | Required once a lease exists. |
| `error_code` | conditional | Required for non-success, absent for success; no free-form reason. |
| `retry_class`, `effect_certainty` | yes | Existing closed failure-taxonomy values. |
| `delivery_receipt_id`, `provider_audit_id`, `leak_token` | conditional | Safe references/tokens only. |

It never contains ref logical name, provider namespace/version/locator, provider
error text, material digest, secret-derived canonical hash, detector key,
delivery endpoint, environment name, action parameters, value, or bytes.

Cross-tenant, unknown-ref, and unauthorized callers receive one outward
`secret_not_available` result with the same response shape and timing bucket.
The restricted security event records the attempted tenant/principal and a
tenant-keyed request correlation token, not the candidate `SecretRefId` or an
existence bit. Tenant/operator projections omit provider audit correlation and
any ref identity the viewer cannot access.

## Provider Port

`splendor-authority::secrets` defines a Rust-only outbound `SecretProvider`
trait with the semantic operations `fetch`, `renew`, `revoke`, and `audit`.
Each operation accepts a private, non-serializable validated request carrying
the exact provider route, lease, target, authority revision, deadline, and audit
correlation. Raw public contracts cannot construct that request. The request
does not import or replace the gateway permit; the kernel/node bridge may call
the port only while it separately retains the live final permit.

`fetch` and `renew` return a non-cloneable, non-serializable, redacted-debug
`SecretMaterial` plus a safe provider receipt. `SecretMaterial` is consumed once
by the node delivery bridge, is zeroized on drop where the platform supports it,
and is never exposed by an accessor returning an owned `String`, `Vec<u8>`, JSON,
or SDK payload. Zeroization reduces exposure; it is not a perfect erasure claim
for copies made by provider libraries, kernels, hypervisors, devices, or
untrusted target code.

The closed provider error variants are:

```text
unavailable
timeout_before_send
rate_limited
version_not_available
revoked
integrity_failure
unsupported_provider_version
effect_uncertain
internal_failure
```

Errors may carry only a sanitized provider code and opaque audit ID. Raw SDK
errors, response headers/bodies, request dumps, endpoints, locators, credentials,
or material are discarded at the adapter boundary. Unknown provider failures map
to `internal_failure`, `not_retryable`, and `effect_uncertain` until a narrower
mapping proves otherwise.

Provider adapters:

- depend inward on the authority-owned port and behavior-free types;
- do not import vendor SDKs into `splendor-authority`, `splendor-gateway`, or
  `splendor-kernel`;
- do not authorize, renew authority, choose fallback, or mark their own
  conformance/maturity;
- never cache material beyond the active lease and target process lifetime;
- never expose a direct resolve API to SDKs, policies, daemon clients, or agent
  code outside the authorized target boundary.

## Authority and Gateway Sequence

The only live sequence is:

```text
typed SecretUseRequirement
  -> placement + execution lease + fencing
  -> authority evaluates exact SecretLeaseRequest
  -> SecretLease issued without fetching material
  -> existing Action Gateway and every required verifier
  -> private final gateway permit
  -> durable secret.delivery.requested/secret.provider.fetch.started evidence
  -> provider fetch under the retained permit
  -> node-local delivery to the exact target
  -> driver/adapter effect under the same gateway invocation
  -> postconditions + outcome/effect certainty
  -> cleanup/close or quarantine
  -> terminal access, state, trace, and receipt evidence
```

Required rules:

1. Policy, user space, SDKs, and drivers may propose a typed requirement only.
2. The Authority Service validates the ref, principal, work order/capability,
   applicable data-use decisions, workload attempt, operation, placement,
   fencing, audience, purpose, intent, time, and uses before issuing a lease.
3. Lease issuance does not fetch or deliver material and does not execute an
   action.
4. The gateway revalidates live lease revision, target binding, revocation,
   expiry, use budget, policy, and all existing verifier categories immediately
   before its final permit.
5. Required pre-effect evidence must be durable before provider I/O. If trace,
   event, state, or evidence durability is unavailable, no provider call or
   adapter effect occurs.
6. Provider access is a declared credential-use sub-effect of the one gateway
   invocation. It is not a second gateway, hidden adapter call, or broker bypass.
7. The private permit is retained and rechecked through delivery and immediately
   before adapter execution. It is never serialized or returned to callers.
8. Postcondition and outcome handling remains in the existing gateway. Secret
   cleanup is additionally mandatory even when the adapter fails, times out,
   is cancelled, or has uncertain effect.

Raw `SecretLease`, handle metadata, provider receipts, approval text, messages,
and ref IDs cannot substitute for the private validated wrappers and permit.

## Lifecycle and Concurrency

### Command, decision, event, state

| Command | Decision | Required event/state result |
| --- | --- | --- |
| Register/update ref | Allow or structured deny after CAS, provider-route policy, and classification validation | Append ref revision event, then CAS current ref head. |
| Request lease | Allow or deny after complete binding/authority checks | `lease_requested`, then `lease_denied` or immutable lease plus `lease_issued`. |
| Request delivery | Allow or deny after final gateway permit | Durable `secret.delivery.requested` and `secret.provider.fetch.started` before provider I/O. |
| Activate/use | Atomic use claim or deny | Increment `uses_claimed`, activate handle, append `use_claimed`; no effect on failed claim. |
| Renew | Allow only from live current lease with fresh authority and same attempt | New lease ID/revision chain and `renewed`; old lease closes at cutover. |
| Rotate ref/material | Allow only through ref CAS plus non-overlap cutover | New ref revision/new handle, `rotated`, old handle close. |
| Revoke | Scope-match and increment revocation generation | `revocation_requested`, deny new claims, push/ack where available, `revoked` or uncertainty. |
| Expire | Authority clock reaches exact expiry | Deny new claims, close handle, `expired`. |
| Close/cleanup | Idempotent target cleanup | `cleanup_started`, then `closed`, `cleanup_uncertain`, or `quarantined`. |
| Leak detected | Fail or quarantine; never success by silent redaction | `leak_detected`, revoke/close as policy requires, then `quarantined` and restricted incident ref. |

### Lease state machine

Allowed baseline transitions are:

```text
issued -> active -> closing -> closed
issued -> revoked | expired | quarantined
active -> revocation_pending -> revoked -> closing -> closed
active -> expired -> closing -> closed
active -> quarantined
closing -> cleanup_uncertain | closed | quarantined
cleanup_uncertain -> closed | quarantined
```

Terminal `closed` and `quarantined` leases cannot return to active. A revoked or
expired lease cannot be renewed, rotated into use, or resurrected. Cleanup may
continue after expiry/revocation but has containment authority only; it cannot
perform the original driver effect.

### Idempotency and CAS

- `SecretLeaseRequestId` is the lease idempotency key. An exact canonical
  duplicate returns the original lease/denial. Reuse with changed bytes is a
  conflict and creates no new lease.
- Ref, lease, handle, revocation, and cleanup mutations require an expected
  revision or generation. A stale CAS changes nothing.
- `max_uses` is enforced by an atomic check-and-increment immediately before
  exposure/use. Concurrent claims have one ordered winner at the last use.
- For FD, tmpfs, projected, or environment delivery, activation counts as one
  exposure; C03 cannot count arbitrary operations performed by untrusted code
  after exposure. One-shot socket retrieval counts each successful retrieval.
  Driver profiles must state which exposure model they use.
- Each workload attempt requests a fresh lease by default. A retry cannot reuse
  a prior attempt's lease, handle, audience, or process binding.
- Authority-owned trusted time tracks the maximum observed clock. Clock
  unavailability, rollback, or uncertainty beyond the ref's maximum 30-second
  tolerance denies issuance/renewal/use. Expiry has no grace period.
- If a provider or irreversible driver operation may have occurred but no exact
  receipt exists, effect certainty is `uncertain`; no automatic retry, failover,
  renewal, or new credential changes that fact.

## Delivery and Cleanup

### Mechanisms

| Method | Required boundary | Mandatory controls |
| --- | --- | --- |
| `inherited_fd` | Exact child process | Anonymous/non-path FD where possible, close-on-exec except exact child handoff, no parent/sibling inheritance, close on terminal state. |
| `tmpfs_file` | Exact sandbox/process | Node-owned tmpfs, owner-only mode, no workspace/image layer, no persisted mount metadata containing material, unmount/unlink on terminal state. |
| `one_shot_local_socket` | Exact process/audience | Node-local peer identity check, one successful bounded read per claim, no network listener, close and erase queue after delivery. |
| `orchestrator_projected_secret` | Exact placed workload | Orchestrator-native ephemeral projection, immutable target UID binding, no generated manifest containing material, deletion/ack on terminal state. |
| `environment_variable` | Exact process | Separately authorized high-risk compatibility, fresh process only, capture/debug/core-dump suppression, no persisted environment snapshot, immediate process termination for cleanup. |

Environment delivery is off by default even when listed by a `SecretRef`. It
requires an exact driver declaration, an authority obligation/receipt dedicated
to environment exposure, a fresh process boundary, and policy approval. No
compatibility fallback converts FD/file/socket/projection failure into an
environment variable.

### Exposure controls and honest limits

Before activation, node/executor integration must configure, where the platform
supports it:

- core dumps and crash dumps disabled or routed through the leak barrier;
- debugger/ptrace access denied outside the exact trusted operator policy;
- stdout/stderr, process args, environment snapshots, manifests, metrics, and
  debug bundles scanned before persistence;
- child inheritance denied unless the child is the exact bound process;
- workspace, image-layer, artifact, swap, page-dump, and generic cache writes
  denied for secret material;
- target termination, FD/socket closure, unmount/deletion, detector teardown,
  and revocation acknowledgement on completion, cancellation, expiry,
  quarantine, node drain, or process crash.

Splendor cannot prove erasure from an untrusted process after it has read the
credential, from copied process/container memory, from a provider SDK, from a
hypervisor, or from hardware. The receipt reports the controls applied and
cleanup certainty. Uncertain cleanup is not success: it quarantines the target,
denies new leases there, and emits incident-worthy restricted evidence.

## Renewal, Rotation, Revocation, and Offline Behavior

### Renewal

- Renewal always re-evaluates current principal, capability/work order,
  data-use, workload attempt, driver operation, placement, fencing, audience,
  purpose, intent, provider health, policy, and revocation state.
- The ref must be explicitly renewable. The new expiry must fit both the ref's
  single-lease duration and the original chain's
  `max_continuous_expires_at`.
- Renewal does not reset continuous lifetime, use count policy, attempt identity,
  or authority expiry. It cannot outlive any required authority, execution lease,
  data-use decision, policy, or work order.
- Renewal creates a new lease and delivery handle. It does not mutate provider
  bytes in place or expose both credentials to one target.

### Rotation

Ref rotation appends a new ref revision. A running workload receives it only
through a new lease and handle. Cutover must prove non-overlap: the old handle is
closed and inaccessible before the new handle becomes active for the same target.
If a platform cannot prove that order, rotation uses a fresh process/attempt or
fails closed. A zero-downtime service may shift traffic between separately
fenced old and new processes; one request/process may not receive both versions.

### Revocation

Revocation can target ref, lease, principal, workload, attempt, driver operation,
node, instance, deployment, or incident scope. The Authority Service increments
the generation and denies new claims before sending node/provider revocation.
Nodes acknowledge exact generation and target. Missing, stale, partitioned, or
ambiguous acknowledgement leaves revocation/cleanup uncertain and quarantines
the target for new secret-bearing work.

Revocation cannot undo a completed irreversible effect. An in-flight operation
uses the gateway's recorded effect certainty and declared cancellation semantics.
It is never retried merely because a new credential exists.

### Offline

Default offline behavior is `deny`. `continue_existing_until_expiry` permits an
already active local delivery to continue only while all cached authority,
execution lease, fencing, policy, data-use, revocation snapshot, target binding,
and secret lease remain fresh and the operation is explicitly low risk. It
never issues, renews, rotates, fails over, or extends a lease offline. High-risk,
network-mutation, publication, deployment, physical-actuation, and irreversible
operations deny or require local intervention when freshness is uncertain.
Expiry closes the handle even while disconnected.

## Provider Routing and Availability

Routing is an authority-owned deterministic policy keyed by tenant,
classification, locality, provider maturity, and ref. A ref revision pins its
provider route and provider version. Requesters cannot submit a route, endpoint,
fallback provider, or trust downgrade.

The first implementation providers are:

- deterministic in-memory provider for tests only;
- explicit local-development file/OS-keychain provider, restricted to loopback
  or local process use and never enabled by production default.

No repository/image default master key, test credential, automatic local-dev
fallback, or production enablement is permitted.

Production provider adapters remain future work. Their rules are:

- bounded connect/operation deadlines, bounded retries only for operations with
  known no-effect or provider-declared idempotency, latency buckets, health,
  circuit state, and sanitized audit correlation;
- no material cache beyond the exact active lease and process boundary;
- failover only before delivery and only to a route explicitly proven equivalent
  in tenant, secret identity/version, scope, classification, locality, trust,
  maturity, audit, and revocation semantics;
- no failover after an uncertain fetch/revoke/renew or an uncertain irreversible
  driver effect;
- no fallback from a restricted provider to a less trusted, broader, older,
  cross-region, cross-tenant, local-dev, or environment-based route;
- circuit-open and provider-unavailable responses reveal no secret existence
  across tenant/visibility boundaries.

## Pre-Persistence Leak Barrier

Read-time export redaction is insufficient because it allows secret material to
enter durable trace/state bytes. C03 live mode requires a pre-persistence barrier
on every path that can carry target-controlled or provider-controlled bytes.

### Detector model

- The node registers per-lease keyed detectors in a restricted local service at
  delivery time. Raw material and detector keys never leave the node process
  boundary.
- Detectors cover exact bytes plus policy-approved structured representations,
  bounded common encodings, chunk-boundary/split forms, and log-injection/control
  variants. Tests use synthetic canaries, never real credentials.
- A match creates a stable, versioned, domain-separated `SecretLeakToken` scoped
  to tenant, lease, detector generation, and representation class. It is not an
  unkeyed secret hash, provider value commitment, bearer, or cross-tenant token.
- The central event receives only the leak token, source process/output
  coordinates, representation class, quarantine state, and restricted incident
  ref. It cannot resolve the token to bytes.

### Mandatory scan points

Scanning happens before persistence or publication of:

- action params and typed invocation inputs;
- percept, message, prompt, model-request, policy-output, and tool-result payloads;
- stdout/stderr, process args, environment captures, crash/core/debug bundles,
  command metadata, and sandbox results;
- trace/event/evidence payloads, state patches/snapshots, artifacts/manifests,
  datasets, checkpoints, observability exports, and public errors;
- provider errors, adapter results, postcondition evidence, incident summaries,
  and replay exports.

A scan match, scanner unavailability, detector-registration failure, ambiguous
partial scan, or output too large for the declared bounded scanner policy cannot
be silently redacted and marked successful. Policy chooses fail, quarantine, and
incident/revocation actions from a closed risk profile; every choice preserves a
non-success outcome for the affected output.

### Limits and false positives

The barrier does not claim visibility into arbitrary encrypted, compressed,
hashed, steganographic, hardware-private, or otherwise opaque payloads unless a
separate data-use policy authorizes inspection and the declared decoder succeeds.
Unknown coverage is recorded as unknown, not clean.

Structured false-positive exceptions are versioned, exact schema/path rules with
owner, reason, expiry, and test evidence. An allowlist cannot contain raw values,
wildcard an entire action/workload/output object, disable scanning for secret-like
fields, or convert scanner uncertainty into success. User-provided data that
resembles a credential is quarantined or handled by an approved exact exception;
it is never copied into a global detector allowlist.

## Trace, State, Artifact, and Replay Contract

### Event order and durability

For a successful use, C03 events appear around the existing gateway trace in
this order:

```text
secret.lease.requested
secret.lease.issued
verification.started
verification.completed
secret.delivery.requested
secret.provider.fetch.started
secret.provider.fetch.completed
secret.delivery.ready
secret.use.claimed
secret.delivery.activated
action.executed | action.failed
secret.use.completed
secret.cleanup.started
secret.delivery.closed | secret.cleanup.uncertain | secret.quarantined
outcome.recorded
state.committed
tick.completed
```

A denial emits `secret.lease.denied` or a normal verification denial and never
emits provider fetch/delivery events. `secret.delivery.requested` and
`secret.provider.fetch.started` must be durable before provider I/O. A required
terminal append failure after possible external effect returns uncertain effect,
retains/quarantines cleanup state, and never reports success.

The exact trace-name mapping for every `SecretAccessEventKind` is:

```text
lease_requested          -> secret.lease.requested
lease_denied             -> secret.lease.denied
lease_issued             -> secret.lease.issued
delivery_requested       -> secret.delivery.requested
provider_fetch_started   -> secret.provider.fetch.started
provider_fetch_completed -> secret.provider.fetch.completed
delivery_ready           -> secret.delivery.ready
delivery_activated       -> secret.delivery.activated
use_claimed              -> secret.use.claimed
use_completed            -> secret.use.completed
renewed                  -> secret.lease.renewed
rotated                  -> secret.ref.rotated
revocation_requested     -> secret.revocation.requested
revoked                  -> secret.lease.revoked
expired                  -> secret.lease.expired
cleanup_started          -> secret.cleanup.started
closed                   -> secret.delivery.closed
cleanup_uncertain        -> secret.cleanup.uncertain
leak_detected            -> secret.leak.detected
quarantined              -> secret.quarantined
```

These event names and meanings are part of this proposed contract. Renaming or
reinterpreting one after acceptance requires compatibility treatment; a generic
log message is not equivalent evidence.

### Safe persistence

- Broker state persists ref/lease revisions, counters, revocation generations,
  routing refs, handles, receipts, safe events, and CAS heads only.
- Agent state may persist a `SecretRefId` requirement. It may not persist a
  lease, delivery handle, endpoint, provider mapping, detector, or material.
- Artifact/workload manifests may persist `SecretRefId` and typed use
  requirements so rotation does not rewrite immutable manifests. They may not
  persist active lease/handle IDs or provider locators.
- Generic traces carry redacted `SecretAccessEvent` projections only. Restricted
  provider/detector/incident facts use access-controlled evidence records.
- Secret material, direct/unkeyed value digests, provider request bytes, and
  provider material never participate in shared canonical serialization, state
  hashes, artifact IDs, idempotency digests, or public evidence digests. The
  approved keyed `SecretLeakToken` is a non-resolving detection label, not value
  material or a value commitment; when included in an event it is excluded from
  IDs and idempotency/evidence digests.
- Historical 0.1 trace/state bytes are not rewritten. Existing read-time
  redaction remains for compatibility but is never cited as C03 leak prevention.

### Replay

Replay remains inspect-only by default. It reconstructs recorded ref revisions,
lease decisions, target bindings, provider outcomes, use claims, revocations,
cleanup, leak/quarantine, and effect certainty from safe records.

Replay never:

- fetches, resolves, renews, rotates, revokes, or audits a live provider;
- reopens a delivery handle, target FD, mount, socket, projection, or process;
- re-registers a detector using historical material;
- treats a ref, lease, access event, provider receipt, or historical allow as
  current authority;
- executes a gateway, adapter, driver, network, filesystem, device, or incident
  side effect.

Current-policy comparison uses recorded safe facts or explicit synthetic
fixtures and is labeled counterfactual. It cannot claim to reproduce unavailable
secret material or original provider state.

## SDK, External Contract, and Static Scan Rules

Rust is the canonical source for behavior-free C03 serialized contracts.
OpenAPI, TypeScript, and Python surfaces are generated or mechanically
conformance-checked only when an implementation exposes them. Hand-written SDK
semantics cannot decide authority or resolve material.

Allowed SDK ergonomics return only:

- `SecretRefId` / typed `SecretUseRequirement` builders;
- lease status and redacted access/delivery receipts for authorized inspection;
- structured denial and cleanup/quarantine status.

There is no SDK method named or behaving as `get_secret`, `resolve_secret`,
`read_secret_value`, `secret_bytes`, or equivalent. There is no standalone
daemon endpoint that returns a secret value or a user-resolvable handle. Node
resolution is internal to the retained gateway/executor path.

Caller bearer tokens used to authenticate daemon clients, owner-only trust and
keyring files used at process startup, and local fixture-only work-order
verification material are not workload Secret Broker contracts. They stay in
their existing closed security configuration and are never copied into
`SecretRef`, action params, examples, workload specs, or user-space helpers.

The future CI scanner uses schema `splendor.secret_field_scan.v1` and rejects
normalized credential-like keys and value-bearing forms in authorizing or
executable workload, action, driver, example, manifest, and gold files. At
minimum it recognizes `password`, `passwd`, `api_key`, `apikey`, `token`,
`secret`, `client_secret`, `private_key`, `credential`, `authorization`,
`cookie`, `connection_string`, and `dsn`, including case/separator variants and
nested paths.

Scanner exceptions require exact schema, exact field path, owner, reason,
expiry, and scanner version. They are allowed only for closed app-caller
authentication or trust-bootstrap schemas and synthetic detector fixtures. They
cannot apply to `Action.params`, policy/percept/message payloads, workload secret
requirements, provider output, driver manifests, external examples, or gold
inputs. A skipped/unavailable scanner is not passing evidence.

Every driver manifest eventually declares whether target code sees material,
which delivery mechanisms it supports, child-inheritance/debug/capture policy,
cleanup guarantees, offline support, effect/idempotency class, and relevant
conformance evidence. Examples use synthetic canaries and local deterministic
providers; no example depends on a real cloud credential.

## Compatibility, Migration, and Rollout

C03 v1 is experimental 0.2/v2 surface, not a new stable 0.1 primitive. It is
additive alongside stable 0.1 IDs and records and preserves all existing
identity, work-order, gateway, trace ordering, state graph, and replay rules.

| Facet | Compatibility rule |
| --- | --- |
| Stable `ActionRequest` | Unchanged. Secret-aware calls use the versioned wrapper and normalize into the same gateway. |
| Action params | Continue rejecting credentials. A `SecretRef` string in params is non-authorizing and invalid for live C03 use. |
| Work orders/capabilities | Remain required and may only narrow. C03 fields are not smuggled through extensions. |
| Trace/state | Historical bytes and IDs remain unchanged. New C03 event profiles are additive and safe-only. |
| Rust | `splendor-types` is canonical for serialized records; authority owns behavior and private validated wrappers. |
| OpenAPI/TS/Python | Added only with mechanical parity and no material-returning API. Old clients may ignore inspection-only records but cannot authorize unknown versions. |
| Stores | New C03 tables/records are separate and versioned. Existing arbitrary payload stores are not C03-safe until the pre-persistence barrier is wired. |
| Replay | Existing inspect-only behavior remains; C03 records add explanation only. |

No privileged consumer accepts unknown C03 versions or enum values. Generic
readers may preserve them as opaque historical data. No `extensions` field,
arbitrary map, alias, optional authorizing field, default, or schema negotiation
may change secret authority.

Initial implementation is behind an explicit `secret_broker_v1` runtime/feature
gate that defaults off. Enabling live issuance requires compatible Authority,
Gateway, node/executor, provider, event/evidence, pre-persistence barrier, and
scanner versions. Mixed-version nodes that cannot understand the exact contract
deny secret-bearing placement.

Rollback first stops new issuance, then revokes/closes or quarantines every
active handle, persists terminal evidence, and only then disables provider/node
components. Downgrade must not leave a live handle that the older runtime cannot
revoke or explain. Historical records remain readable as opaque non-authorizing
evidence.

## Failure Taxonomy and Threat Model

`SecretErrorCode` is closed in v1:

```text
invalid_schema_version
malformed_request
secret_not_available
secret_ref_disabled
wrong_tenant
wrong_principal
wrong_agent
wrong_run
wrong_workload
wrong_attempt
wrong_node
wrong_instance
wrong_sandbox
wrong_process_boundary
wrong_audience
wrong_driver_operation
wrong_purpose
wrong_intent
delivery_method_not_allowed
authority_missing
authority_stale
authority_revoked
work_order_missing
work_order_expired
work_order_revoked
data_use_missing
data_use_stale
data_use_revoked
placement_missing
placement_stale
fencing_stale
lease_not_yet_valid
lease_expired
lease_revoked
max_uses_exhausted
handle_unknown_or_closed
provider_unavailable
provider_effect_uncertain
cleanup_uncertain
leak_detected
scan_unavailable
replay_forbidden
clock_unavailable
clock_rollback
clock_skew_exceeded
concurrent_update
evidence_unavailable
internal_invariant_violation
```

Public callers receive only visibility-safe codes such as
`secret_not_available`, `provider_unavailable`, `cleanup_uncertain`, or a
generic denied/needs-intervention result. Restricted evidence may retain the
exact internal code. Errors use the existing `ErrorCategory`, `RetryClass`, and
`EffectCertainty` contracts; they never include raw provider text.

| Error family | `ErrorCategory` | Retry/effect rule |
| --- | --- | --- |
| Malformed/version/binding/delivery mismatch | `invalid_input` or `unauthorized` | `not_retryable`, `none` |
| Expired or revoked authority/work-order/data-use/lease | `expired` or `revoked` | `retry_with_new_authorization` only for a new request/attempt, `none` |
| Stale ref/placement/fencing/concurrent CAS | `stale_head` or `conflict` | same idempotency key may retry only after reading the current revision, `none` |
| Explicit provider unavailable before send | `unavailable` | bounded same-idempotency retry if policy permits, `none` |
| Provider or driver effect uncertainty | `uncertain` | `not_retryable` automatically, `uncertain` |
| Leak or scanner denial | `protected_data_denial` or `unavailable` | `not_retryable` until containment/new evidence, `none` |
| Cleanup uncertainty | `uncertain` | explicit same-target containment/reconciliation only, `uncertain` |
| Evidence/clock/internal invariant unavailable | `unavailable`, `uncertain`, or `internal_invariant_violation` | fail closed; never implicit allow |

| Threat or failure | Required behavior |
| --- | --- |
| Wrong tenant or hidden ref guess | Uniform `secret_not_available`; no existence, provider, name, version, or timing oracle. |
| Wrong principal/agent/run/workload/attempt | Deny before lease issuance or provider I/O. |
| Wrong node/instance/sandbox/process/audience | Deny and invalidate any mismatched handle; no locator is returned. |
| Wrong driver operation/purpose/intent | Deny; no wildcard or provider-specific reinterpretation. |
| Missing/stale/revoked authority or data-use | Deny or intervention; no cached high-risk allow. |
| Missing/expired/revoked work order | Deny run-bound issuance/use before provider I/O. |
| Missing/stale placement or fencing | Deny; old attempts/nodes cannot reuse a lease. |
| Provider outage/circuit open | Deny or bounded same-trust failover only under the rules above. |
| Provider response uncertain | Record uncertainty; no blind retry/failover and no adapter execution. |
| Lease not active/expired/revoked/max-use | Atomic deny before exposure/effect. |
| Unknown/closed handle | Uniform deny; never attempt provider lookup from handle metadata. |
| Cleanup uncertain | Quarantine target, deny new leases, record restricted incident-worthy evidence. |
| Leak match or scanner unavailable | Fail/quarantine/revoke by closed policy; never silently redact to success. |
| Replay requests live resolution | Reject as `replay_forbidden`; adapter/provider invocation count remains zero. |
| Clock rollback/skew/unavailable | Deny issuance, renewal, and use; do not extend expiry. |
| Trace/event/evidence unavailable | Fail closed before provider/effect; after possible effect, report uncertainty and quarantine cleanup. |

## Validation and Acceptance Plan

Contract acceptance and implementation evidence are separate gates.

### V0 - RFC and catalog integrity

- Independent architecture, security, contract, and compatibility review accepts
  this RFC without changing task or gold status.
- Documentation links, catalog parsing, architecture policy, whitespace, and
  status scans pass.
- V0 authorizes implementation planning only. It closes no SECR task.

### V1 - Behavior-free contracts

- Add nominal IDs and closed Rust records with `deny_unknown_fields`.
- Positive round trips plus negative serialization/property fixtures prove no
  value/bytes/locator/raw-error field can enter C03 contracts.
- Prove nominal ID non-interchangeability, exact version rejection, canonical
  bytes, cross-language/OpenAPI parity where exposed, and stable 0.1 preservation.
- Gold remains `not_exercised`.

### V2 - Authority lifecycle and deterministic providers

- Implement one authority-owned state machine, validated wrappers, CAS,
  idempotency, use counts, expiry, renewal/rotation/revocation, and sanitized
  event construction.
- Add deterministic memory and explicit local-development providers behind the
  outbound port; cover outage, wrong version, cross-tenant guesses, circuit,
  retry, and no-cache rules.
- This is bounded local evidence until the real gateway/node path exists. It
  does not pass `G07` or `G08` by itself.

### V3 - Gateway, node delivery, and leak barrier

- Requires real `NODE-003`/sandbox/process/fencing owners and `FND-009`-aligned
  pre-persistence integration.
- Test all delivery methods, explicit environment denial/approval, wrong-boundary
  denial, process crash, cancellation, expiry, node quarantine, cleanup
  uncertainty, provider and trace failure, revocation races, and atomic last use.
- Use synthetic canaries to test plain, common encoded, split/chunked, and
  log-injection forms across params, prompts, stdout/stderr, state, trace,
  artifacts, errors, debug bundles, and observability before persistence.
- Execute exact `G08` and `G82` fixtures before claiming those results.

### V4 - External contracts and owner adoption

- Generate/check Rust, OpenAPI, TypeScript, and Python parity for each exposed
  profile; prove SDK helpers cannot read material.
- Enable the versioned static scanner and exact allowlist contract in CI.
- Each real driver owner adopts requirements, delivery, cleanup, and evidence in
  its production path; mocks are limited to the provider boundary.
- Execute owner-specific gold rather than marking a C03 umbrella fixture passed:

| Owner/adoption | Gold targets |
| --- | --- |
| Driver registry/provider conformance | `G07` |
| Secret Broker baseline | `G08` |
| Shell/Python/OCI/Kubernetes/HTTP/database/artifact owners | `G10`-`G17` |
| Model driver | `G53` |
| Device/executor/change owners | `G73`-`G75` |
| Authority/secret adversarial owner | `G82` |

### V5 - Sustained, offline, and release evidence

- Rotation in a sustained service proves no request/process receives both old
  and new credentials.
- Partition, stale policy/revocation, node restart, clock rollback, provider
  failover, crash, pressure, and cleanup quarantine evidence passes.
- Exact `G88` offline behavior and all remaining task-specific gold assertions
  pass with retained reports.
- Mixed-version rollout/rollback and migration fixtures prove unknown privileged
  contracts fail closed and historical 0.1 replay remains side-effect free.

An exact gold run is `passed` only when the catalog revision ran and every
required assertion passed. Skipped, unavailable, specified-only, partial, or
mock-only cases remain `not_exercised`.

### Issue closure

- #245 closes only after the complete `SECR-001` contract/provider-port/gateway
  integration and required `G08` evidence exist.
- #246 closes only after real node/sandbox delivery and cleanup plus `G08`/`G82`.
- #247 closes only after sustained renewal/rotation/revocation/offline evidence
  plus `G08`/`G88`.
- #248 closes only after all required pre-persistence owners and `G82` evidence.
- #249 closes only after provider conformance/HA evidence plus `G07`/`G08`.
- #250 closes only after every listed external owner and gold case is executable
  and passing.
- #183 closes last, after all six issues and all aggregate gold requirements are
  linked. RFC acceptance alone closes none of them.

## Implementation Order and Prerequisites

If accepted, implementation proceeds in this order:

1. V1 behavior-free C03 IDs/contracts and negative serialization fixtures.
2. Authority-owned lifecycle, validated wrappers, and outbound provider port.
3. Bounded renewal/revocation and deterministic/dev-local providers.
4. Same-gateway typed requirement, lease verifier, and retained-permit wiring.
5. Rust/OpenAPI/TypeScript/Python parity and static scanner for surfaces that
   actually exist.
6. Only after prerequisite owners land: node delivery/cleanup, pre-persistence
   leak barrier, external drivers/examples, and executable gold.

Known prerequisite boundaries remain explicit:

- C01/C02 and `FND-001`, `FND-005`, and `FND-009` have useful local seams but
  are not catalog-wide completion evidence.
- `NODE-003` #302 and `SBX-001` #400 are required before production delivery.
- applicable Data-Use Controller decisions (C06 #186 and its task issues) are
  required when secret use protects purpose-controlled data/provider access.
- event/evidence, artifact, observability, sandbox output, and incident owners
  are required for complete leak quarantine and export evidence.
- driver, model, device, executor, change, and gold owners must adopt C03; the
  Secret Broker cannot fake their production paths.

No C03 implementation may create substitute node, sandbox, artifact, evidence,
incident, or data-use state machines inside `splendor-authority`, the daemon, or
the store to bypass these prerequisites.

## Explicit Non-Goals

- No vendor vault product, general credential-management UI, OAuth/PKI server,
  enterprise secret inventory, or broad key-management product.
- No raw secret value, bytes, reusable digest, provider response, direct locator,
  ambient token/password field, or material-returning SDK/API.
- No second authority evaluator, gateway, verifier path, adapter invocation path,
  replay effect path, global service locator, or mutable global secret store.
- No default environment-variable delivery, automatic compatibility fallback,
  production default master key, or real-cloud dependency in examples.
- No arbitrary user-code handle resolution outside the exact process boundary.
- No promise of perfect erasure from process/container memory, provider SDKs,
  kernels, hypervisors, hardware, copied encrypted payloads, or untrusted code.
- No full `NODE-*`, `SBX-*`, Data-Use, Artifact, Event/Evidence, Observability,
  Incident, Driver, Model, Fleet, or physical implementation in this RFC.
- No stable 0.1 primitive replacement, existing hash rewrite, trace/state
  migration, issue closure, component completion, or gold pass claim.

## Acceptance Checklist

Independent reviewers should recommend acceptance only if all are true:

- The status remains proposed until the repository's acceptance process records
  an accepted date and decision.
- Public records are closed, versioned, byte-free, locator-free, and
  non-authorizing.
- IDs, target binding, authority binding, audience, purpose, intent, duration,
  uses, placement, fencing, and revocation are explicit and distinct.
- `SecretProvider` is an authority-owned Rust outbound port, not a serialized
  type or provider SDK in core.
- Provider fetch/delivery occurs only after the existing gateway's final permit
  and required pre-effect durability.
- Delivery, cleanup, renewal, rotation, revocation, offline, HA, leak, replay,
  compatibility, and threat behavior is fail closed and testable.
- Current read-time redaction is explicitly insufficient for live C03.
- External SDK/scanner rules distinguish caller/bootstrap credentials from
  workload secrets and never expose material.
- V0-V5 and issue/gold closure rules prevent docs or bounded local tests from
  becoming false completion evidence.
- Deferred owner boundaries and non-goals remain explicit.
