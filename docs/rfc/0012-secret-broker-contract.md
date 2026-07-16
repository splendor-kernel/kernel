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

Authority is also the sole durable mutation owner for secret refs, leases,
exposure aggregates, use attempts, and secret-action submission records. The
gateway owns the live effect session but advances those records only through a
narrow authority command/CAS port. Gateway typestates, daemon handlers, stores,
providers, nodes, adapters, and reconcilers never write Authority tables
directly. An authority-owned `SecretActionReconciler` is the only crash-recovery
writer: it may complete already-recorded cleanup or terminal evidence, but it
cannot call a provider, node target operation, or adapter again.

A `SecretRef`, `SecretLeaseRequest`, `SecretLease`, access event, provider
receipt, or message is not authority to execute an action. Required authority,
data-use, work-order, quota, policy, approval, safety, network/filesystem,
secret-lease, and compatibility verifiers still run through the existing Action
Gateway. Provider fetch and material delivery occur only after placement and
after the gateway has issued a private final permit, atomically reserved the
exact requirement-specific use attempts, and durably recorded every claim. The
permit remains held through provider access, delivery, driver execution, and the
point where effect certainty is known. No SDK, provider, node, daemon handler, or adapter can mint
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
| `splendor-authority::secrets` | Ref, lease, exposure-aggregate, use-attempt, and outer submission lifecycle; authority intersection; expiry; maximum use; renewal; rotation; revocation; provider routing decisions; private validated wrappers; crash reconciliation commands | Vendor SDKs, node execution, gateway replacement, artifact/event storage |
| `splendor-gateway` | Existing verified invocation path, secret-lease verifier, private final permit retention, effect certainty | Secret lifecycle state, provider routing, material resolution, delivery cleanup |
| `adapters/secrets-*` | Provider-specific fetch/renew/revoke/audit translation through the authority-owned port | Granting authority, choosing broader fallback, public errors, durable broker state |
| resident node/executor | Exact-boundary delivery, OS/orchestrator controls, close/unmount/revoke, restricted local detectors | General secret storage, fleet policy, authority evaluation, alternate effect path |
| `splendor-store` / future evidence stores | Persistence of already-safe refs, revisions, receipts, events, and CAS state | Redaction policy, provider access, lifecycle legality, secret bytes |
| daemon, CLI, Python, TypeScript | Closed transport translation, opaque helper ergonomics, inspection of safe receipts | Material resolution, client-side authority, shadow lifecycle, insecure fallback |

`SecretProvider` is not a serialized public type. The catalog's public-contract
shorthand names the provider boundary; architecture rules require the owning
component to define the outbound Rust port. Putting provider behavior in
`splendor-types` would turn it into a trait dumping ground and is rejected.

Acceptance of this RFC proposes one narrow dependency-policy specialization:

```text
adapters/secrets-* -> splendor-authority + splendor-types
```

Only a crate whose repository path is `adapters/secrets-*` and whose package is
registered as a secret provider may use that pair. It may not depend directly on
`splendor-gateway`, `splendor-kernel`, `splendor-store`, `splendor-daemon`, a
node binary, another adapter, or a vendor-neutral "common" broker crate. Ordinary
action adapters keep the current `splendor-gateway + splendor-types` rule. The
first provider implementation must update the active dependency checker in the
same change: classification must test the secret-provider path before the generic
adapter rule, allow exactly the two edges above, and add self-test fixtures that
reject a normal adapter importing authority and a secret provider importing each
forbidden package. This proposed exception is inactive while this RFC remains
Proposed and adds no current dependency edge.

`splendor-gateway` owns one injected, private Rust `SecretEffectOrchestrator`
port and the complete `SecretEffectSession<'permit>` state machine. The port is
not an all-in-one adapter call. `VerifiedActionGateway::submit` opens a session
only for a validated secret-aware wrapper after every normal verifier and final
permit acquisition. The session then owns, in order, the requirement-specific
use-attempt reservations, attempt-bound target allocations, provider calls, node delivery,
driver continuation, detector, postcondition continuation, cleanup guards,
sealed publication candidates, and terminal classification. No other component
may advance or finalize the session.

The closed staged ABI is:

```text
VerifiedActionGateway::submit_with_secrets(validated_wrapper)
  -> SecretEffectSession::reserve_all_uses(...)
  -> SecretEffectSession::allocate_all_targets_and_controls(...)
  -> SecretEffectSession::acquire_all_provider_material(...)
  -> SecretEffectSession::invoke_driver(
       SecretDeliveryContext<'session>,
       &mut GatewayPostconditionContinuation<'session> {
         accept_delivery_control_attestation(...)
         verify_postconditions(borrowed_opaque_response_view)
         scan_into_private_candidates(proposed_public_projections)
       })
  -> byte-free driver terminal after driver-owned buffers are wiped
  -> SecretEffectSession::drain_scan_and_seal(...)
  -> SecretEffectSession::cleanup_and_wipe(...)
  -> SecretEffectSession::normalize_for_outer_recorder(
       secret_aware_adapter_entered,
       target_operation_started,
       provider_effect_certainty,
       node_effect_certainty,
       target_effect_certainty,
       ...)
```

Every transition consumes the prior typestate and returns the next, or enters
the same terminal cleanup path. The gateway retains the final permit and session
owner throughout. The orchestrator and node bridge receive scoped borrows only.
The provider receives one private validated provider request. The driver receives
one consumed delivery context. The postcondition verifier receives a bounded
borrowed view while raw response/error bytes remain driver-owned and opaque. The
outer recorder receives only a non-serializable `SecretSubmitCompletion` with a
sealed public projection, stable final status, separate adapter-entry and target-
start facts, separate provider, node, and target effect certainty, conservative
outer effect certainty, and terminal recording instructions. Secret material,
unsealed driver output/error bytes,
provider requests, delivery endpoints, detector state, permits, and cleanup
capabilities cross none of those boundaries.

All intermediate allows, denials, provider results, driver results, cleanup
states, and postcondition decisions are private `SecretSubmitProgress` typestates,
not partial `ActionOutcome`s and not terminal receipts. A secret-wrapper denial
before session creation is normalized into a pre-effect
`SecretSubmitCompletion`; a denial after reservation follows cleanup first. Only
the common terminal normalizer may construct/release the stable public
`ActionOutcome`, after terminal receipt/action evidence commits. Thus no direct or
tick path can serialize an early status and later revise it.

Secret-aware target registrations use an additive private Rust
`SecretAwareActionAdapter` ABI. Its one invocation receives the unchanged
`&ActionRequest`, a consumed `SecretDeliveryContext<'session>`, and the borrowed
gateway-owned postcondition continuation. The adapter must consume the context
exactly once through `resolve_and_deliver`; it cannot resolve from a ref, lease,
handle, or endpoint. Before returning, it passes a borrowed opaque response view
and proposed public projection to the continuation, then wipes/drops its raw
response and error buffers. The gateway, not the adapter, invokes and decides
postconditions, and the continuation completes before the adapter invocation
returns. Missing, duplicate, late, or panicking continuation use fails closed and
enters cleanup.

Entry into `SecretAwareActionAdapter` is the stable adapter-execution boundary.
`NeedsIntervention` is permitted only before that method is entered. Once method
entry occurs, every non-success is `Failed`, including delivery resolution,
cancellation, timeout, panic before target start, target failure, postcondition,
scan/seal, cleanup, and terminal uncertainty. Method entry does not imply that
the target operation started: the immutable terminal record carries both
`secret_aware_adapter_entered` and `target_operation_started`. Tests and metrics
count them independently. This preserves the stable 0.1 meaning of
`NeedsIntervention` without pretending that inner target start is adapter entry.

`SecretDeliveryContext<'session>` and every provider material/projection,
delivery-control typestate, opaque driver response view, continuation, and seal
are sealed Rust types that are `!Send`, `!Sync`, non-`'static`, non-cloneable,
non-serializable, and redacted for `Debug`. They cannot be placed in trait-object
storage or sent to an unrelated thread/task. Forgetting or leaking a borrowed
context cannot retain material or cleanup authority: the gateway session remains
the independent owner and fences/cleans the target when the driver call returns,
unwinds, is cancelled, or reaches its deadline. Panic-abort or process death is
reconciled from the durable reservation and target generation by the node
supervisor and is never success.

A registration is either the existing `ActionAdapter` or the secret-aware ABI,
never both for the same canonical operation. Requests with no secret requirement
continue to use the stable adapter ABI unless that operation's adopted credential
ingress profile requires a denial. A secret-aware request makes exactly one
driver invocation. Direct provider resolution, daemon/SDK resolution,
pre-gateway delivery, provider fetch before use reservation, and reconstructing
a context from serialized metadata are forbidden.

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
- timestamps use exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ`, with six fractional
  decimal digits, UTC `Z`, and no leap second or offset spelling; values not
  exactly representable at microsecond precision reject rather than round;
  ordering uses authority-owned time rather than caller timestamps;
- `provider_namespace` and `logical_name` are 1 through 128 ASCII characters
  matching `[a-z][a-z0-9._-]*`;
- opaque provider version/correlation values are 1 through 128 printable ASCII
  characters, contain no control/space characters, URI scheme delimiter, path
  separator, or query/fragment delimiter, and are never interpreted as locators;
- every C03 string field is ASCII. Schema constants, enum spellings, IDs,
  reason codes, opaque values, and labels reject non-ASCII, control characters,
  Unicode confusables, and normalization-equivalent alternatives; C03 performs
  no Unicode normalization before validation or hashing;
- delivery lists contain at most five unique values, data-use grant lists at
  most 16 unique IDs, and causal-parent lists at most 16 unique causal refs;
- reason/error values are closed enum spellings, not caller/provider strings.

Array semantics are field-specific and fixed before JCS:

- semantic sets are sorted before serialization: delivery-method sets by exact
  ASCII enum spelling and typed-ID sets by the 16 canonical UUID network-order
  bytes; duplicates reject before sorting;
- `SecretUseRequirement.delivery_methods`,
  `SecretLeaseRequest.delivery_methods`, and the wrapper's
  `secret_requirements` are true preference/request order and preserve input
  order; changing that order changes canonical bytes;
- `causal_parent_refs` is true causal order, not a set. The event owner supplies
  already-recorded run parents in ascending local event sequence and management
  parents in their owner-defined durable sequence. Parents from different
  streams then order by exact tag and canonical nominal ID bytes. Consumers
  preserve that order and reject duplicates, run/tag mismatch, or a parent that
  is not already durable.

Where a C03 idempotency or content/integrity digest is required, validation,
fixed timestamp spelling, and the field-specific array rules run first. Canonical
bytes are then RFC 8785 JSON Canonicalization Scheme bytes for the named closed
projection, prefixed by its exact schema name and one zero byte. The digest is
BLAKE3 and is rendered as `blake3:<lowercase hex>`. Secret material,
material-derived hashes, provider requests, private permits, delivery endpoints,
and detector keys are never digest inputs. A leak token is excluded from
authorizing, content-addressed, and idempotency digests, but is covered by the
event integrity chain as specified below. Cross-language fixtures must pin every
canonical byte and digest before a wire surface is exposed.

### Nominal identities

The following C03-owned IDs are UUID-backed nominal newtypes in
`splendor-types` when implemented:

| Serialized field | Rust type | Meaning |
| --- | --- | --- |
| `secret_ref_id` | `SecretRefId` | One logical secret reference history. |
| `secret_action_submission_id` | `SecretActionSubmissionId` | One durable outer direct/tick secret-action mutation and terminal intent. |
| `secret_action_idempotency_key` | `SecretActionIdempotencyKey` | Direct caller's canonical UUID idempotency key; not action identity or authority. |
| `secret_lease_request_id` | `SecretLeaseRequestId` | One idempotent lease command identity. |
| `secret_lease_id` | `SecretLeaseId` | One lease lifecycle. |
| `delivery_handle_id` | `SecretDeliveryHandleId` | One node-local delivery-handle lifecycle; not a bearer value. |
| `delivery_receipt_id` | `SecretDeliveryReceiptId` | One immutable outer secret-effect terminal receipt. |
| `delivery_control_attestation_id` | `SecretDeliveryControlAttestationId` | One immutable terminal driver-to-gateway delivery-control attestation. |
| `secret_access_event_id` | `SecretAccessEventId` | One immutable C03 access event. |
| `secret_provider_id` | `SecretProviderId` | One configured provider adapter/routing identity. |
| `provider_audit_id` | `SecretProviderAuditId` | One sanitized provider operation receipt. |
| `provider_control_invocation_id` | `SecretProviderControlInvocationId` | One gateway-mediated provider control effect. |
| `node_control_invocation_id` | `SecretNodeControlInvocationId` | One gateway-mediated resident-node control effect. |
| `node_control_receipt_id` | `SecretNodeControlReceiptId` | One immutable node-control terminal receipt. |
| `bootstrap_source_binding_id` | `SecretBootstrapSourceBindingId` | One route-bound private bootstrap credential-source binding. |
| `secret_audience_id` | `SecretAudienceId` | Domain-separated ID derived from the trusted target binding. |
| `detector_registration_id` | `SecretDetectorRegistrationId` | Restricted node-local detector registration reference. |
| `secret_exposure_lineage_id` | `SecretExposureLineageId` | Authority-owned parent exposure aggregate/lineage; never caller-selected. |
| `secret_use_attempt_id` | `SecretUseAttemptId` | One gateway-owned reserved use attempt, distinct from workload attempt and action/invocation. |
| `secret_ref_mutation_command_id` | `SecretRefMutationCommandId` | Idempotency identity for register/update/disable. |
| `secret_renewal_command_id` | `SecretRenewalCommandId` | Idempotency identity for one renewal intent. |
| `secret_rotation_command_id` | `SecretRotationCommandId` | Idempotency identity for one rotation/cutover intent. |
| `secret_revocation_command_id` | `SecretRevocationCommandId` | Idempotency identity for one scoped revocation. |
| `secret_cleanup_command_id` | `SecretCleanupCommandId` | Idempotency identity for expire/cleanup. |
| `secret_containment_command_id` | `SecretContainmentCommandId` | Idempotency identity for leak containment. |
| `secret_use_claim_id` | `SecretUseClaimId` | One atomic exposure/use claim. |

C03 consumes, but does not own, `PrincipalId`, `TenantId`, `AgentId`, `RunId`,
`WorkloadId`, `FleetId`, `NodeId`, `InstanceId`, `ActionId`, `TraceEventId`,
`WorkOrderId`, `CapabilityGrantId`, and `AuthorityDecisionId`. FND/fabric/node
owners must supply distinct nominal `WorkloadAttemptId`, `PlacementDecisionId`,
`ExecutionLeaseId`, `SandboxId`, `ProcessBoundaryId`, `InvocationId`,
`DataUseGrantId`, `DriverOperationRef`, `SecretCredentialSlotId`, `EvidenceId`,
`ManagementEventId`, `DeploymentId`, and `IncidentId` before
the corresponding production integration can land. C03 must not emulate any of
those with `RunId`, `WorkloadId`, a string, or metadata.

`SecretProviderVersionRef` and `SecretProviderCorrelationId` are validated
opaque newtypes, not IDs or locators. `SecretLeakToken` has the fixed keyed
construction specified by the detector contract and is not a caller-selected
opaque string.

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
| `SecretProviderOperation` | `fetch`, `renew`, `revoke`, `audit`, `active_probe` |
| `SecretProviderOutcome` | `succeeded`, `denied`, `unavailable`, `failed`, `effect_uncertain` |
| `SecretAccessOutcome` | `allowed`, `denied`, `succeeded`, `failed`, `needs_intervention`, `effect_uncertain`, `quarantined` |
| `SecretLeakRepresentation` | `plain`, `base64`, `base64url`, `percent_encoded`, `split_chunk`, `log_injection` |
| `SecretDeliveryControlKind` | `core_dump`, `ptrace_debug`, `child_inheritance`, `output_capture`, `swap_page_dump`, `generic_cache`, `orchestrator_projection` |
| `SecretDeliveryControlStatus` | `applied`, `not_applicable`, `unsupported`, `failed` |
| `SecretAccessSubjectKind` | `ref_administration`, `lease_execution`, `delivery_execution`, `provider_control`, `node_control`, `containment` |
| `SecretAccessEventKind` | `ref_registered`, `ref_updated`, `ref_disabled`, `ref_mutation_denied`, `lease_requested`, `lease_denied`, `lease_issued`, `delivery_requested`, `delivery_denied`, `provider_fetch_started`, `provider_fetch_completed`, `provider_control_requested`, `provider_control_completed`, `node_control_requested`, `node_control_completed`, `delivery_ready`, `delivery_activated`, `use_claimed`, `use_denied`, `use_completed`, `renewed`, `renewal_denied`, `rotated`, `rotation_denied`, `revocation_requested`, `revocation_denied`, `revoked`, `revocation_uncertain`, `expired`, `cleanup_started`, `closed`, `cleanup_uncertain`, `leak_detected`, `containment_started`, `containment_completed`, `containment_failed`, `quarantined` |

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
| `allowed_credential_bindings` | yes | Non-empty exact driver-operation, nominal slot, destination-schema, and destination-digest authorizations. Wildcards are forbidden. |
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

Each `allowed_credential_bindings` entry is a closed
`splendor.secret.credential_authorization.v1` value containing one canonical
`DriverOperationRef`, one owner-defined `SecretCredentialSlotId`, one exact
driver-owned destination schema/version, and a non-empty sorted set of approved
destination digests. There is no any-origin, any-account, any-cluster,
any-database, any-device, any-artifact, any-model-endpoint, field-class, or
operation-class wildcard. Changing an approved sink requires a new ref revision
and fresh authority; it cannot be supplied through action params or metadata.

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
- one nominal `credential_slot_id: SecretCredentialSlotId` declared by the exact
  registered driver operation;
- `intent: SecretUseIntent`;
- `purpose: SecretPurpose`;
- a non-empty ordered preference list of `SecretDeliveryMethod`;
- `requested_duration_seconds` and `requested_max_uses`, each positive and
  narrowing the ref policy;
- `required`: always `true` in v1; optional best-effort secret use is not
  defined.

It contains no independently caller-supplied destination, provider identity, ref
revision, lease ID, target identity, authority decision, delivery handle,
locator, value, bytes, fallback, or environment name. It is a request, not
authority. C03 requirements cannot be hidden in `Action.params`, prompt text,
arbitrary metadata, or `extensions`.

### Nominal credential slot and destination binding

The Driver Registry/Gateway owner, not C03 or a caller, defines
`SecretCredentialSlotId` and a versioned credential-sink declaration for each
adopted `DriverOperationRef`. A declaration contains a non-empty unique slot set,
the secret classifications/intents permitted per slot, and one closed
driver-owned destination projection schema per slot. Examples of required exact
projection coordinates include HTTPS origin plus service/account, database
service/cluster/database/account, orchestrator cluster/namespace/service account,
artifact service/repository/account, model service/endpoint/account, device and
device-local service, or cryptographic service/account/resource. A coarse
`network`, `authorization_header`, `connection_auth`, or operation-class label is
not a destination projection.

After action schema validation, the registered driver projection function derives
the destination only from the validated action parameters and trusted registered
resource bindings. It returns a private typed `ValidatedCredentialDestination`,
whose owner schema has no arbitrary map or extensions. Request JSON cannot supply
the projection, its digest, a trusted account/origin/cluster/device override, or a
different projection function. Missing projection support, ambiguous parameters,
an unregistered schema version, or disagreement between action, trusted resource,
and projection denies before lease issuance, provider I/O, node control, or
adapter entry.

The safe binding record is
`splendor.secret.credential_destination_binding.v1` and contains exactly its
schema version, canonical `driver_operation`, `credential_slot_id`, positive
`driver_declaration_revision`, exact `destination_schema`, and
`destination_digest`. The digest follows the C03 prefix/JCS/BLAKE3 rule over the
complete closed driver-owned projection. The complete validated projection is
available only to Authority/Gateway through a private typed wrapper; common
records carry the exact schema/digest binding, not an untyped projection.

Normalization creates one
`splendor.secret.bound_use_requirement.v1` per proposed requirement, containing
the complete original `SecretUseRequirement` plus the destination binding. The
ref revision and current Authority decision must authorize that exact operation,
slot, and destination digest. The same binding is then immutable in the lease
request, lease, use claim, final permit, delivery context/handle, use-attempt
summary, receipt/evidence, and parent exposure aggregate. Multi-secret delivery
is indexed only by `SecretCredentialSlotId`; ordered position is never a lookup
key. Slot IDs must be unique in one action. Reordering requirements changes the
wrapper digest but cannot swap delivery because the adapter resolves each
context by its declared slot ID. Wrong, missing, duplicate, reordered-to-a-
different-sink, or wrong-origin/service/account/cluster/database/device/artifact/
model-endpoint bindings deny before provider I/O.

### Versioned direct and tick secret-action surface

Stable `Action`, `ActionRequest`, `ActionOutcome`, `ActionStatus`, `/actions`, and
plain `ActionCandidate` bytes and meanings do not change. C03 adds these closed
v1 surfaces instead:

- `splendor.gateway.secret_action_candidate.v1` is the tagged policy/tick
  candidate. It contains `schema_version`, `kind=secret_action`, the unchanged
  `Action`, the current candidate adapter/quota/precondition/request-time/
  approval-receipt/delegated-grant fields, and one through 16 ordered
  `SecretUseRequirement` values. Policy may omit action ID and requested time;
  the kernel allocates them once before submission-ledger claim and retains them
  for every duplicate observation.
- `splendor.gateway.action_request_with_secrets.v1` is the private normalized
  gateway wrapper. Its only fields are `schema_version`, the unchanged
  `ActionRequest`, and one through 16 ordered bound requirements. Duplicate slot
  IDs or duplicate `(secret_ref_id, slot_id, intent, purpose)` tuples reject. It
  enters the existing Action Gateway only; it is not a second adapter path.
- `POST /v2/secret-actions` with exact header
  `X-Splendor-API-Version: 0.2-secret-actions.v1` accepts only
  `splendor.daemon.submit_secret_action.v1`. The closed body contains its schema,
  required canonical `secret_action_idempotency_key`, required non-nil
  `action_id`, `run_id`, `tenant_id`, `agent_id`, required run-scoped
  `causal_trace_event_id`, unchanged `Action`, adapter, normalized quota usage,
  satisfied preconditions, required original `requested_at`, optional existing
  approval evidence, zero through 64 existing authority-obligation receipts,
  and one through 16 ordered secret requirements. Authentication/audit context is
  middleware-derived, not body authority. Existing receipt references are
  revalidated evidence inputs under the unchanged gateway contract; they cannot
  supply C03 authority, lease, target, destination, or delivery coordinates.
- The POST requires authenticated caller identity, `splendor.actions.submit`,
  caller-token tenant/audience/expiry/revocation validation, exact run visibility,
  and caller attribution under the existing daemon security contract. Body
  tenant/agent/run/action values must match that trusted context; mismatch denies
  before outer acceptance and reveals no submission/ref/provider state.
- The direct daemon normalizer derives authenticated principal, security
  audience, admitted workload/attempt, placement, target, destination bindings,
  and unchanged `ActionRequest` server-side. The body has no workload/attempt,
  lease, ref revision, provider, target, authority decision, destination,
  audience, delivery method selection, handle, endpoint, permit, or node-control
  coordinate. Unknown fields reject.

The tick idempotency input is server-derived as BLAKE3 under schema
`splendor.secret.tick_candidate_key.v1` over exact `run_id`, `tick_id`, zero-based
candidate ordinal, and the canonical policy-output candidate digest before
server-assigned action/time fields. The direct input is the caller's canonical
UUID `SecretActionIdempotencyKey`. Both normalize into the same durable outer
submission contract below. An `ActionId` scopes the action and detects key reuse,
but is not by itself effect idempotency.
The tick recorder must already have durably recorded that exact policy output and
ordinal before deriving the key. Crash recovery reuses those bytes and never
reinvokes policy to synthesize a replacement candidate for the same tick.

Lookup precedes allocation of duplicate server-owned coordinates. The trusted
dedupe partition is authenticated principal, tenant, run, stable submission
security audience, and direct key or tick key. If it exists, normalization reuses
the row's pinned workload/attempt, action/time, destination, wrapper, and effect
coordinate only to compare canonical equality and return historical state after
current visibility validation; it does not re-admit or rebuild authority. If it
does not exist, normal admission derives those values once. A restart, migration,
or newly current workload attempt therefore cannot turn the same outer key into a
fresh effect. The separate unique effect-coordinate index also rejects a new key
for the same action/invocation.

The response/lookup schema is
`splendor.daemon.secret_action_submission_response.v1`, containing exactly
`schema_version`, `secret_action_submission_id`, submission state, `duplicate`,
stable `retry_class`, conservative `outer_effect_certainty`, optional
`poll_after_ms` as an integer from 100 through 5,000 inclusive, and terminal
fields. State `terminal` requires both the unchanged
nested `ActionOutcome` and its complete committed `SecretDeliveryReceipt`; those
fields are forbidden in every other state. `accepted`/`in_progress` returns HTTP
202 and permits only same-key transport retry or authenticated lookup.
`uncertain`/`reconciling` returns HTTP 202 with `not_retryable`, no
`ActionOutcome`, and no claim that a terminal receipt exists. Terminal returns
HTTP 200. `GET /v2/secret-actions/submissions/{secret_action_submission_id}` uses
the same API version, authenticated caller, `splendor.actions.submit` scope,
tenant/run/security-audience visibility, and response schema. Hidden or unknown
IDs use the uniform not-available profile.

Unknown API versions return `426 unsupported_api_version`; unknown body/schema
versions return `400 invalid_schema_version`; authentication and scope failures
return the existing `401`/`403` profiles; unavailable C03/foreign-owner
compatibility returns `503 secret_action_profile_unavailable`. All occur before
outer acceptance and have zero C03/provider/node/adapter effect. Once accepted,
all gateway denials and failures use the terminal response contract. If the
submission or receipt store cannot prove the committed terminal receipt, callers
receive/surface `secret_action_receipt_unavailable`, `not_retryable`, and
`outer_effect_certainty=uncertain`; they may poll or reconcile the same submission
but must not create a new key/action or resubmit the effect.

For nonterminal responses, `outer_effect_certainty` is the conservative current
snapshot from durable provider/node/target facts. Before a boundary can have
been crossed its value is `none`; after possible crossing, a missing required
fact is `uncertain`, never guessed `none`. `poll_after_ms` is allowed only for
`accepted|in_progress|uncertain|reconciling`. `duplicate` is true only when this
request found the pre-existing stable dedupe row and false for its creating
request and direct authenticated lookups.

Existing plain `/actions` and plain policy candidates cannot invoke an adopted
secret-capable operation with raw credentials, ref-like strings, or hidden
requirements. The operation's live ingress profile denies those forms before
persistence/provider/adapter effects. A plain request is accepted only when the
registered operation declares no credential slot for that mode.

### Canonical wrapper and outer submission digests

The normalized wrapper digest uses the exact projection schema
`splendor.gateway.action_request_with_secrets_digest.v1` with exactly three
fields: `schema_version`, `gateway_action_request_digest`, and
`bound_secret_requirements`. `gateway_action_request_digest` is the existing
gateway `canonical_gateway_authority_action_digest` output for the unchanged
request, including its full canonical `Action` and exact original
`requested_at`; the C03 projection contains that nested digest, not a second copy
or reinterpretation of the full action. The requirement array contains complete
bound requirements in caller/policy preference order. Each nested destination is
the exact schema/digest binding above. JCS object-key order applies; array order is
preserved; the C03 schema-prefix/zero-byte/BLAKE3 rule applies.

Direct requests must supply `requested_at`. For tick proposals that omit it, the
kernel records one authority-owned `first_accepted_requested_at` before computing
the unchanged gateway action digest and reuses it from the submission ledger on
duplicates. No retry recomputes time. Transport observation, authentication,
accepted, completed, and reconciliation timestamps are excluded from semantic
digest equality.

`outer_idempotency_digest` uses projection
`splendor.secret.outer_idempotency_input_digest.v1` with exactly
`schema_version` and `input`, where `input` is tagged
`direct {secret_action_idempotency_key}` or
`tick {tick_candidate_key_digest}`. It uses the common prefix/JCS/BLAKE3 rule;
the direct UUID and tick digest never share an untagged byte domain.

The outer submission digest uses
`splendor.secret.action_submission_semantic_projection.v1` with exactly:
`schema_version`, `outer_idempotency_digest`, authenticated
`principal_id`, `tenant_id`, exact run/workload/attempt binding, exact tagged
action-or-invocation effect coordinate, `wrapper_digest`, and server-derived
`submission_security_audience`. The audience is exactly
`daemon_deployment {deployment_id}` for direct calls or
`kernel_run {run_id, workload_id}` for tick calls. Both survive process restart;
transient instance/node/connection coordinates are forbidden because they could
partition duplicate detection after a crash. Caller tokens, JTI/
credential correlation, audit timestamps, generated submission/receipt/event
IDs, and result times are excluded. Every included typed ID uses canonical bytes;
no display string or metadata alias participates.

Before exposure, V1/V4 must add one shared golden fixture family at
`conformance/fixtures/secrets/action-submission-v1/` containing the complete
stable gateway action input, bound requirements, exact prefixed canonical bytes,
wrapper digest, tick-key bytes/digest, outer direct/tick projection bytes/digests,
and changed-order/time/body negatives. Rust is canonical; OpenAPI, Python, and
TypeScript must reproduce every byte and digest. A generated or skipped fixture
is not evidence.

### Durable outer submission and terminal-intent ledger

Authority claims one durable `SecretActionSubmissionId` after closed-schema,
caller/scope, feature/owner compatibility, run/workload/attempt, action ID,
driver declaration, slot, and server-derived destination validation, but before
any C03/action terminal event, use reservation, provider I/O, node control,
secret-aware adapter entry, or target operation. The trusted lookup key is the
stable dedupe partition above. The claimed row additionally pins workload,
attempt, effect coordinate, wrapper digest, submission digest, and every server-
derived binding used by semantic equality. No caller bytes choose the ledger
partition or replace pinned coordinates.

`SecretActionSubmissionState` is closed:

```text
accepted -> in_progress -> terminal
accepted | in_progress -> uncertain -> reconciling -> terminal
uncertain | reconciling -> uncertain
```

`terminal` means the immutable receipt and exactly one matching outer terminal
`action.*` event committed atomically. `uncertain` means some effect or required
terminal fact cannot be proved. `reconciling` means the authority-owned
reconciler holds the one claim to finish cleanup or append the recorded terminal
intent; it is not permission to repeat an effect.

For each accepted submission, ledger uniqueness enforces exactly one all-or-none
use-attempt batch and exactly one terminal receipt/action-event pair. A denial
after acceptance but before reservation has one terminal pair with an empty use-
attempt set. A batch reservation stores its complete ordered attempt IDs on the
submission before any provider/node/adapter call; it cannot be replaced by fresh
attempts. The effect coordinate is also unique: the same action/invocation ID
with a different key or
semantic digest conflicts instead of creating another effect.

An exact same-key/same-digest/same-scope duplicate revalidates authenticated
visibility, then returns or refers to the original accepted/in-progress,
uncertain/reconciling, or terminal result. It emits no second use claim, provider
call, node control, adapter entry, target operation, terminal action event, or
receipt. Same key with changed bytes/scope/audience, or same action/invocation
with a new key, returns `secret_action_idempotency_conflict`, effect `none` for
that conflicting observation, and HTTP 409 after visibility validation; it does
not mutate the original record. A conflict that would disclose a hidden original
uses the uniform not-available profile instead.

Before trying the atomic terminal append, Authority stores an immutable safe
`splendor.secret.action_terminal_intent.v1` containing exactly its schema,
`secret_action_submission_id`, `outer_idempotency_digest`, `wrapper_digest`,
`submission_digest`, effect coordinate, completion digest,
adapter-entry/target-start facts, final status, all three effect-certainty
dimensions and conservative outer certainty, ordered use summaries, outer
cleanup/postcondition status, optional bounded error code, publishability plus
sealed-output and complete sealed-`ActionOutcome` digests, ordered
C03 event refs, intended receipt/event IDs, and Authority completion time. Its
`terminal_intent_digest` is the common prefix/JCS/BLAKE3 digest of that complete
closed record. It contains no output bytes, material, endpoint, permit, or raw
error. In the same Authority transaction, a private pending-outcome record keyed
only by `SecretActionSubmissionId` stores the complete scan-approved unchanged
`ActionOutcome` canonical bytes and digest; it is not caller-addressable or
released before terminal commit. Reconciliation verifies that digest before
releasing the original outcome. Missing/mismatched pending bytes are uncertainty,
never outcome reconstruction from receipt fields. If append acknowledgement is
lost or fails, the submission becomes `uncertain` with that intent retained.
Reconciliation may idempotently append only those exact bytes through the unique
outbox/receipt/event keys and
then mark `terminal`; it cannot rerun verification as a new submission, allocate
new use attempts, call provider/node/adapter/target, or manufacture success. A
missing/corrupt intent, unavailable receipt, uncertain append, or ledger read
fails closed as non-retryable uncertainty and quarantines affected exposure.

The `completion_digest` uses projection
`splendor.secret.submit_completion_digest.v1` containing exactly its schema,
`secret_action_submission_id`, `outer_idempotency_digest`, `wrapper_digest`,
`submission_digest`, effect coordinate, adapter-entry/target-
start facts, all three certainty dimensions and outer certainty, final status,
ordered use summaries, cleanup/postcondition status, publishability/sealed-output
and sealed-`ActionOutcome` digests, optional bounded error code, and ordered C03
event refs. Generated receipt/event IDs, completion time, and the completion
digest itself are excluded. The common prefix/JCS/BLAKE3 rule
applies. Thus retry/reconciliation compares exact terminal meaning without a
timestamp or generated-ID cycle.

The sealed outcome digest is BLAKE3 over exact RFC 8785 bytes of the complete
unchanged stable `ActionOutcome`, prefixed by
`splendor.gateway.action_outcome_digest.v1` and one zero byte. Its existing array
order and exact fixed timestamp spelling are preserved; C03 adds no field or
reinterpretation. Rust/OpenAPI/Python/TypeScript golden fixtures pin those bytes.

### Canonical driver operation identity

Every C03 declaration, driver manifest entry, authority decision, lease request,
action wrapper normalization, gateway registration lookup, driver dispatch,
revocation target, access event, receipt, and canonical/hash projection uses one
nested `DriverOperationRef`. Independent `driver`, `operation`,
`operation_semantics`, adapter-name, or display-string comparisons are forbidden.
The exact v1 JSON form is:

```json
{
  "driver": "example_driver",
  "operation": "example_operation",
  "schema_version": "splendor.driver.operation.v1"
}
```

The owner-supplied type validates the exact schema constant and registered
canonical driver/operation names before C03 sees it. For C03 canonicalization the
two names are non-empty 1-128 character ASCII identifiers matching
`[a-z][a-z0-9._-]*`; no Unicode normalization, alias, case folding, display
format, stringified JSON, or operation-semantics side field participates. JCS of
the nested object above is the sole comparison and hash source. An owner with an
incompatible canonical representation must land an accepted compatibility
amendment before C03 integration rather than translating at the broker boundary.

### Execution and authority bindings

`SecretExecutionBinding` uses schema
`splendor.secret.execution_binding.v1` and contains:

- its exact `schema_version`;
- exact `tenant_id`, `workload_id`, and `attempt_id`;
- optional `agent_id` and `run_id`, both required when the workload is an agent
  run and forbidden when not applicable;
- exact `driver_operation: DriverOperationRef`;
- exact `fleet_id`, `node_id`, `instance_id`, `placement_decision_id`,
  `execution_lease_id`, `sandbox_id`, and `process_boundary_id`;
- exact non-zero `fencing_epoch`;
- `audience_kind` and a trusted, domain-separated `secret_audience_id` derived
  from all target coordinates.

Audience derivation is fixed. The UUIDv5 namespace is
`d7385f8a-75f4-5b6c-8f1e-2b3c4d5e6f70`. The UUIDv5 name bytes are ASCII
`splendor.secret.audience.v1`, one zero byte, then JCS bytes for this exact
projection in field-name canonical order:

```json
{
  "schema_version": "splendor.secret.audience_derivation.v1",
  "tenant_id": "<TenantId>",
  "workload_id": "<WorkloadId>",
  "attempt_id": "<WorkloadAttemptId>",
  "agent_run_binding": {"kind": "not_applicable"},
  "driver_operation": {
    "driver": "example_driver",
    "operation": "example_operation",
    "schema_version": "splendor.driver.operation.v1"
  },
  "fleet_id": "<FleetId>",
  "node_id": "<NodeId>",
  "instance_id": "<InstanceId>",
  "placement_decision_id": "<PlacementDecisionId>",
  "execution_lease_id": "<ExecutionLeaseId>",
  "sandbox_id": "<SandboxId>",
  "process_boundary_id": "<ProcessBoundaryId>",
  "fencing_epoch": 1,
  "audience_kind": "driver_process"
}
```

`agent_run_binding` is exactly either `{"kind":"not_applicable"}` or
`{"kind":"agent_run","agent_id":"<AgentId>","run_id":"<RunId>"}`.
The nested `driver_operation` is the exact canonical object above, not its JSON
string, display value, adapter name, or three independently compared fields. The
derived audience ID itself is excluded. UUIDv5 is used only for deterministic
nominal identity, not as an authority signature or secret commitment. Derivation
cannot be implemented until every foreign field above has its owner-supplied
canonical nominal type and `DriverOperationRef` representation.

The target audience is derived by the node/gateway composition after placement.
Caller JSON cannot choose it. `driver_process` and `device_local_driver` require
the exact registered driver process. `sandbox_process` requires the exact child
process and sandbox. `orchestrator_workload` requires the exact projected
workload/sandbox identity and later process admission; it is not a namespace-wide
mount.

`SecretCausalRef` is a closed tagged union used anywhere C03 requires a causal
event:

```text
run_trace { run_id, trace_event_id }
management_event { management_event_id }
```

The two variants are not interchangeable. `run_trace` must reference an already
durable stable run trace event whose `run_id` matches. `management_event` consumes
an owner-defined nominal `ManagementEventId` from the future Event/Evidence
management stream and is required for startup, periodic health, expiry, incident,
shutdown, and other controls that do not belong to a run. The current stable
`ManagementAuditEvent` has no nominal event ID, so the management variant and
every dependent background control remain unimplementable and disabled until its
owner lands an accepted compatible ID/integrity/visibility contract. C03 never
creates a fake `RunId`, `TraceEventId`, or string substitute.

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
- one exact `causal_ref: SecretCausalRef` for the recorded authority decision.

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
| `bound_use_requirement` | yes | Complete original requirement plus exact nominal slot and server-derived destination binding. |
| `execution_binding` | yes | Exact placed and fenced target. |
| `authority_binding` | yes | Exact validated authority evidence references. |
| `intent` | yes | Closed use intent. |
| `purpose` | yes | Closed use purpose. |
| `delivery_methods` | yes | Non-empty ordered subset of ref policy. |
| `not_before` | yes | Earliest lease use. |
| `expires_at` | yes | Requested finite expiry. |
| `max_uses` | yes | Positive requested maximum. |
| `requested_at` | yes | Authority-owned observation time. |
| `causal_ref` | yes | Closed run-trace or management-event causality; not authorization. Lease execution requires the matching run-trace variant when run-bound. |

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
| `credential_destination_binding` | yes | Exact operation, nominal slot, driver declaration revision, destination schema, and digest approved. |
| `execution_binding` | yes | Immutable exact target. |
| `authority_binding` | yes | Immutable issuance evidence refs. |
| `intent`, `purpose` | yes | Exact approved use. |
| `allowed_delivery_methods` | yes | Narrowed non-empty set. |
| `status` | yes | Closed lease state. |
| `starts_at`, `expires_at` | yes | Exact active window. |
| `continuous_lifetime_started_at` | yes | Original chain start; renewal cannot reset it. |
| `max_continuous_expires_at` | yes | Absolute renewal ceiling. |
| `max_uses`, `uses_claimed` | yes | Positive maximum and atomic counter. |
| `secret_exposure_lineage_id` | yes | Authority-owned semantic lineage described below. |
| `exposure_lineage_revision` | yes | Non-zero CAS revision for aggregate lineage accounting. |
| `refresh_generation` | yes | Non-zero authority generation for provider/ref/lease selection; stale writers cannot rebase after reservation. |
| `revocation_generation` | yes | Non-zero generation checked at every claim/delivery. |
| `issued_at` | yes | Authority-owned issuance time. |
| `renewed_from_lease_id` | no | Immediate predecessor when renewed. |
| `rotated_from_handle_id` | no | Previous handle when a rotation cutover is prepared. |
| `last_event_id` | yes | Latest canonical lifecycle event. |

A lease contains no delivery endpoint, provider locator, provider SDK response,
material digest, value commitment, key ID usable at the provider, or reusable
credential. A lease is still not an action permit.
Its `max_uses`/`uses_claimed` are lease-local bounds and never exceed the current
parent aggregate. The parent aggregate remains authoritative across lease
replacement; a serialized lease snapshot cannot restore or widen parent state.

### `SecretDeliveryHandle`

Schema: `splendor.secret.delivery_handle.v1`.

The serialized handle is safe metadata, not the resolver capability. It contains
only:

- `schema_version`, exactly `splendor.secret.delivery_handle.v1`;
- `delivery_handle_id`, `secret_lease_id`, `secret_use_attempt_id`, non-zero
  `lineage_target_generation`, and non-zero `delivery_generation`;
- exact `credential_destination_binding`;
- exactly one tagged `effect_coordinate` containing `action_id` or
  `invocation_id`;
- exact `execution_binding` and `secret_audience_id`;
- selected `delivery_method`, positive `exposure_method_child_revision`, and
  closed `status`;
- `allocated_at`, optional `ready_at`, and `expires_at`;
- `revocation_generation` and `last_event_id`.

It has no filesystem path, file descriptor number, socket name, environment
variable name, orchestrator object name, mount name, provider locator, nonce,
token, capability bytes, or resolution method. The actual FD, mount, socket,
projection, or environment assignment is a non-serializable node-local object
held by the executor and bound to the target OS/orchestrator identity. Looking
up a `delivery_handle_id` outside that process boundary always denies.

### Delivery-control attestation and terminal receipt

Delivery readiness and final action outcome are separate immutable facts. A
prepared control set is not a receipt and cannot claim terminal action status.

`SecretDeliveryControlEvidenceRef` uses schema
`splendor.secret.delivery_control_evidence_ref.v1`. It is a closed restricted
object containing exactly `evidence_id: EvidenceId`, `tenant_id`,
`secret_lease_id`, `secret_use_attempt_id`, `delivery_handle_id`,
`delivery_generation`, complete execution binding, `secret_audience_id`,
`credential_destination_binding`, `delivery_method`, positive
`exposure_method_child_revision`, one `control_kind`,
`control_config_digest`, `attester_id`, `observed_at`, and `causal_ref`. The
evidence owner validates existence,
integrity, visibility, attester authority, freshness, and every exact binding
before returning a private wrapper. A URI, string, raw `EvidenceId`, stale
wrapper, wrong-process record, or copied reference cannot authorize activation.

The driver-to-gateway handoff is a non-serializable
`SecretDeliveryControlAttestation<'session>`. The node creates a prepared control
typestate before exposure; the driver consumes it during `resolve_and_deliver`;
and, after the one target operation returns but before the adapter invocation
returns, the gateway accepts the immutable terminal attestation before
postcondition verification. It contains the attestation ID,
lease/use-attempt/handle/generation IDs, exact effect coordinate and execution
binding, method and method-child revision, detector registration ID when
installed, driver-returned time,
`target_effect_certainty`, and exactly one result per
`SecretDeliveryControlKind` sorted by enum spelling. Each result contains only
`kind`, `required`, `status`, and the
typed restricted evidence ref when `status=applied`. It contains no final
`ActionStatus`, outer terminal event ID, material, endpoint, output, error text,
or platform diagnostic. A required control with `not_applicable`, `unsupported`,
or `failed`, a missing/duplicate/stale result, or a wrong-binding evidence ref
fails closed. No terminal receipt exists at `delivery_ready`,
`delivery_activated`, driver return, or postcondition start.

After the live handoff completes, the gateway may persist only the closed safe
`splendor.secret.delivery_control_attestation_record.v1` projection containing
the same IDs, statuses, typed evidence refs, times, and target effect certainty.
The live borrowed typestate itself remains non-serializable. The terminal receipt
may reference only an integrity-validated record ID.

`SecretDeliveryReceipt` uses schema `splendor.secret.delivery_receipt.v1` and is
the separate terminal receipt for one secret-aware outer action/invocation. The
common outer recorder creates it exactly once in the same atomic append/outbox
unit as the one outer terminal `action.*` event. It contains exactly:

- `schema_version`, `delivery_receipt_id`, `secret_action_submission_id`,
  `outer_idempotency_digest`, `wrapper_digest`, `submission_digest`, `tenant_id`,
  canonical `driver_operation`, server-derived submission security audience, and
  one tagged action/invocation effect coordinate;
- zero through 16 `use_attempt_summaries` in the exact bound-requirement order;
  each summary contains one unique use-attempt ID, slot/destination binding,
  lease ID, and the durable `use_claimed` event ref; selected method/method-child
  revision and unique handle/target/delivery generation are present exactly when
  their child objects were created; it also contains optional provider audit ID, optional
  final delivery status required exactly when a handle exists, required cleanup
  status, zero through 20 unique node-control receipt IDs in
  durable operation order, summary `node_effect_certainty`, attestation ID only
  after adapter target return, and optional detector registration ID;
- `secret_aware_adapter_entered`, `target_operation_started`,
  batch-level `provider_effect_certainty`, `node_effect_certainty`,
  `target_effect_certainty`,
  `outer_cleanup_status: SecretCleanupStatus`, and
  `postcondition_status` from the closed set
  `not_run|allowed|denied|uncertain`;
- exact stable outer `final_action_status`, conservative
  `outer_effect_certainty`, optional bounded
  error code, whether a sealed public output is publishable after commit, and its
  safe BLAKE3 digest when publishable;
- `ordered_c03_event_refs`, `outer_terminal_event_id`, and `completed_at`.

A denial after outer acceptance but before reservation has an empty summary
array, both adapter/target booleans false, provider, node, and target certainty
`none`, outer cleanup `not_required`, and the matching stable pre-entry status.
Once reservation
commits, summary cardinality is exactly the number of bound requirements and
there is exactly one summary per unique use attempt; every created handle appears
in exactly that summary and nowhere else. A reserved attempt that fails before
provider remains listed and consumed. Duplicate IDs, summaries sorted by ID
instead of requirement order, missing summaries, extra summaries, or a handle
without its one use attempt reject receipt construction. Each summary's node-
control receipt list is exactly every control committed for that use attempt,
ordered by durable invocation sequence. Each v1 operation occurs at most once
plus at most one fresh same-target reconciliation that references its prior
uncertain receipt. A second uncertainty leaves the outer submission uncertain
without a terminal receipt. A missing, unrelated, duplicate invocation, invalid
operation sequence, or reordered receipt rejects.

`ordered_c03_event_refs` contains `SecretCausalRef` values for every C03 event
committed for this submission, with no duplicate, omission, or unrelated event.
It is ordered by the Authority/event-owner durable append sequence, never caller
timestamp or ID, and has at
most 1,024 entries for the fixed v1 grammar and 16-requirement maximum. A path
whose complete event set would exceed that bound denies before reservation;
events cannot be dropped to fit a receipt. The V1/V4 maximum fixture uses 16
requirements, one unique summary per requirement in requirement order, and the
largest valid method/reconciliation event/control path under the 1,024 cap. It pins
the full receipt bytes, which must not exceed 512 KiB, and proves that reordering
summaries/event refs, repeating a use/handle/event ID, or omitting a created
handle fails validation. Static admission rejects a path whose declared maximum
cannot fit that durable-receipt bound before reservation.

Provider, node, and target certainty are independent stable `EffectCertainty`
values. Receipt-level node certainty is the conservative maximum across every
linked node-control receipt; it is `none` only when every node operation is
proved no-send/no-effect.
Receipt-level provider certainty is the conservative maximum across every
requirement/provider audit in the fixed batch. Only an objectively proved
no-send provider failure with no earlier sent fetch in that batch is provider
`none`. An authenticated provider request for which any byte was sent is at least
`known` when its response is definitive and is `uncertain` when send/result state
is ambiguous. Target certainty is `none` until `target_operation_started`; a
definitive target return is `known`, and an ambiguous return/cancellation is
`uncertain`. `outer_effect_certainty` is the conservative maximum under
`none < known < uncertain` across provider, node, and target certainty, and is
promoted to `uncertain` by delivery/cleanup uncertainty. A proved provider no-
send after known node preparation can therefore have provider/target `none` but
outer `known`. Terminal append/read uncertainty
produces no receipt and the submission response reports outer `uncertain`; if
reconciliation later proves/commits the exact retained receipt, that receipt's
effect certainty remains derived from the actual provider/node/target/cleanup
facts.

Before secret-aware adapter entry, valid non-success statuses remain `Denied`,
`NeedsApproval`, or `NeedsIntervention` according to stable rules. Once
`secret_aware_adapter_entered=true`, `final_action_status` is only `Executed` or
`Failed`; a delivery failure or panic before target start is `Failed` with target
certainty `none`. Cleanup, postcondition, scan, evidence, cancellation, or
revocation uncertainty after entry cannot be misrepresented as
`NeedsIntervention`. Receipt validation rejects any mismatch with adapter-entry,
target-start, certainty, outer event, or status. If the atomic terminal append
cannot commit, no receipt and no public `ActionOutcome` is released; the durable
submission remains `uncertain` with error `terminal_evidence_blocked` and retains
the terminal intent for reconciliation.

Both the live attestation and terminal receipt are immutable. No earlier
delivery event embeds a mutable receipt or a promised terminal event ID.
`receipt_digest` is the common prefix/JCS/BLAKE3 digest of the complete
`splendor.secret.delivery_receipt.v1` record under projection schema
`splendor.secret.delivery_receipt_digest.v1`; no receipt field is omitted.

The <=2-KiB hot lookup record is separate from the full durable receipt.
Its `trusted_partition_digest` uses the common prefix/JCS/BLAKE3 rule and closed
projection `splendor.secret.action_submission_partition_digest.v1` containing
exactly `schema_version`, authenticated `principal_id`, `tenant_id`, `run_id`,
submission security audience, and `outer_idempotency_digest`. It is a restricted
index key, not authority or a public correlation value.
`splendor.secret.action_submission_hot_index.v1` contains exactly its schema,
trusted-partition digest, `secret_action_submission_id`, submission state,
submission semantic digest, optional terminal-intent digest, and, only after
terminal commit, receipt ID, receipt digest, final status, and outer certainty.
It contains no use summary, event list, evidence, output, provider/node detail,
or error text and is never itself terminal evidence. The complete immutable
receipt, terminal intent, and pending/outcome record live in quota-controlled
durable storage, have no 2-KiB claim, and remain authenticated/queryable after
hot-index eviction. A hot hit is only a pointer/state summary; current caller
visibility and durable receipt integrity are revalidated before any result is
returned.

C03 v1 deliberately does not serialize a raw, salted, or unkeyed value hash.
Such commitments can verify low-entropy secrets or enter shared canonical hash
bytes. The catalog's "where safe" commitment requirement is represented by a
restricted node-local keyed detector registration. Shared receipts contain only
its opaque ID. A future transferable commitment profile requires an RFC
amendment and a threat analysis.

### Provider health and audit records

`SecretProviderTrustScope` is closed and tagged. C03 v1 permits exactly
`tenant {tenant_id}`. A `shared_trust_domain` tag is reserved but invalid in v1;
no route, bootstrap profile, control, receipt, event, health observation, or
visibility rule may accept it. Supporting shared provider identities requires an
accepted owner-defined nominal `TrustDomainId`, authority/isolation semantics,
and a versioned C03 amendment. Implementations cannot use a string trust-domain
label or fabricate a tenant as a substitute.

`SecretProviderHealth` uses `splendor.secret.provider_health.v1` and contains
its exact `schema_version`, `provider_trust_scope`, `secret_provider_id`, positive route-policy revision,
`SecretProviderHealthStatus`, `SecretProviderCircuitState`,
`SecretProviderLatencyBucket`, consecutive-failure count,
`observed_at`/`valid_until`, and a safe reason code. It contains no provider
endpoint, tenant secret name, SDK error, response body, account identifier, or
credential. `valid_until` is later than `observed_at`; an expired observation is
unavailable, never healthy by default.

`SecretProviderAuditReceipt` uses `splendor.secret.provider_audit.v1` and
contains its exact `schema_version`, `provider_audit_id`, provider ID, operation,
outcome, exact `provider_trust_scope`,
SecretRef/lease IDs only after visibility is established, opaque provider
correlation ID, started/completed times, retry count, effect certainty, safe
reason code, and `causal_ref`. Provider correlation IDs are bounded,
sanitized, non-authorizing, and omitted from public/tenant views when provider
policy marks them restricted.

`SecretProviderHealth` is derived only from unexpired prior gateway control/fetch
receipts or a gateway-mediated `active_probe`. Passive capability inspection may
report configured support but cannot report live health. A background timestamp,
direct SDK check, cached provider string, or missing/expired receipt cannot move
health to `healthy` or close a circuit.

### `SecretAccessEvent`

Schema: `splendor.secret.access_event.v1`.

This is the canonical redacted C03 lifecycle/event payload. Its common fields
are exactly `schema_version`, `secret_access_event_id`, `kind`, `outcome`,
`occurred_at`, `recorded_at`, ordered `causal_parent_refs: SecretCausalRef[]`, one tagged
`subject`, and the conditional safe fields allowed by the matrix below. It has no
extensions or arbitrary payload.

`subject` is exactly one closed tagged variant:

- `ref_administration`: `tenant_id`, `actor_principal_id`,
  `authority_decision_id`, `secret_ref_id`, and optional
  `secret_ref_revision` only. Workload, attempt, driver, target, action,
  invocation, lease, and handle coordinates are forbidden.
- `lease_execution`: `tenant_id`, `principal_id`, `workload_id`, `attempt_id`,
  exact `agent_run_binding`, `driver_operation`, complete
  `execution_binding`, complete `authority_binding`, one `secret_ref_scope`, and
  optional `secret_lease_id` only. `secret_ref_scope` is exactly `visible
  {secret_ref_id, secret_ref_revision}` or `hidden
  {tenant_request_correlation_token}`. `hidden` is valid only for a denied
  pre-object event after visibility failure and contains no candidate ref or
  existence bit. Action,
  invocation, and handle coordinates are forbidden.
- `delivery_execution`: the same fields as `lease_execution`, but
  `secret_lease_id` is required, plus exactly one `effect_coordinate` and optional
  `delivery_handle_id`. `secret_use_attempt_id` is required except for a
  pre-reservation `use_denied`, where it is forbidden and
  `secret_use_claim_id` is required instead. No other event carries a use claim
  ID. `effect_coordinate` is
  exactly `{"kind":"action","action_id":...}` or
  `{"kind":"invocation","invocation_id":...}`, never both. The invocation
  form cannot be implemented before its foreign owner supplies `InvocationId`.
- `provider_control`: exact `provider_trust_scope`, `actor_principal_id`,
  complete current `authority_binding`, `secret_provider_id`, `route_policy_revision`,
  `provider_control_invocation_id`, `provider_operation`, and optional visible
  `secret_ref_id`/revision or lease ID only when that object was authorized and
  the operation requires it. It has no action, target adapter, process,
  audience, handle, endpoint, bootstrap identity, or material coordinate.
- `node_control`: exact `tenant_id`, actor principal, complete
  current authority binding, node-control invocation ID, closed operation, and
  the complete typed node-control target binding. It has no provider request,
  material, endpoint, raw OS handle, or fabricated run coordinate.
- `containment`: `tenant_id`, `actor_principal_id`,
  `authority_decision_id`, and one `SecretContainmentTarget` from the closed
  command grammar below. Any workload/attempt/target coordinates occur only
  inside that target variant; fabricated placeholder coordinates are forbidden.

The only conditional safe fields outside `subject` are `delivery_method`,
`uses_claimed`, `max_uses`, `revocation_generation`,
`delivery_control_attestation_id`, `provider_audit_id`,
`node_control_receipt_id`, `leak_token`,
`error_code`, `retry_class`, and `effect_certainty`. `allowed` and `succeeded` are success outcomes: they forbid
`error_code` and `retry_class`. Every `denied`, `failed`,
`needs_intervention`, `effect_uncertain`, or `quarantined` event requires both
fields. `effect_certainty` is forbidden unless the matrix requires it. `N` means
the field group is forbidden; `R` means required; `O` means optional only after
the referenced object exists.

| Kind | Subject | Allowed outcome | Delivery | Counters | Attestation/audit/node receipt/token | Effect certainty |
| --- | --- | --- | --- | --- | --- | --- |
| `ref_registered` | `ref_administration` with revision | `succeeded` | N | N | N | N |
| `ref_updated` | `ref_administration` with revision | `succeeded` | N | N | N | N |
| `ref_disabled` | `ref_administration` with revision | `succeeded` | N | N | N | N |
| `ref_mutation_denied` | `ref_administration`, revision optional | `denied` | N | N | N | N |
| `lease_requested` | `lease_execution`, no lease ID | `allowed` | N | N | N | N |
| `lease_denied` | `lease_execution`, no lease ID | `denied` | N | N | N | N |
| `lease_issued` | `lease_execution` with lease ID | `succeeded` | N | R | N | N |
| `delivery_requested` | `delivery_execution`, handle optional | `allowed` | R | R | N | N |
| `delivery_denied` | `delivery_execution`, handle optional | `denied` | O | R | N | N |
| `provider_fetch_started` | `delivery_execution` with handle | `allowed` | R | R | N | N |
| `provider_fetch_completed` | `delivery_execution` with handle | `succeeded`, `failed`, `effect_uncertain` | R | R | R provider audit | R |
| `provider_control_requested` | `provider_control` | `allowed` | N | N | N | N |
| `provider_control_completed` | `provider_control` | `succeeded`, `failed`, `effect_uncertain` | N | N | R provider audit | R |
| `node_control_requested` | `node_control` | `allowed` | R when handle-bound | N | N | N |
| `node_control_completed` | `node_control` | `succeeded`, `failed`, `effect_uncertain` | R when handle-bound | N | R node-control receipt | R |
| `delivery_ready` | `delivery_execution` with handle | `succeeded`, `failed` | R | R | N | `known` on success; `none` on failure before exposure |
| `delivery_activated` | `delivery_execution` with handle | `succeeded`, `failed`, `effect_uncertain` | R | R | N | R |
| `use_claimed` | `delivery_execution`, handle optional | `allowed` | R | R | N | N |
| `use_denied` | `delivery_execution`, handle optional | `denied` | O | R | N | N |
| `use_completed` | `delivery_execution` with handle | `succeeded`, `failed`, `effect_uncertain` | R | R | R attestation after driver invoke, otherwise N | R |
| `renewed` | `lease_execution` with new lease ID | `succeeded` | N | R | N | N |
| `renewal_denied` | `lease_execution` with old lease ID | `denied` | N | R | N | N |
| `rotated` | `delivery_execution` with new handle | `succeeded` | R | R | O attestation | `known` |
| `rotation_denied` | `delivery_execution`, old handle optional | `denied`, `needs_intervention` | O | R | N | N |
| `revocation_requested` | `containment` | `allowed` | N | N | N | N |
| `revocation_denied` | `containment` | `denied`, `needs_intervention` | N | N | N | N |
| `revoked` | `containment` | `succeeded` | N | N | O provider audit | `known` |
| `revocation_uncertain` | `containment` | `effect_uncertain`, `needs_intervention` | N | N | R provider audit when a provider call began | `uncertain` |
| `expired` | `lease_execution` with lease ID | `succeeded` | N | R | N | N |
| `cleanup_started` | `delivery_execution` with handle | `allowed` | R | R | O attestation | N |
| `closed` | `delivery_execution` with handle | `succeeded` | R | R | O attestation | `known` |
| `cleanup_uncertain` | `delivery_execution` with handle | `needs_intervention`, `effect_uncertain` | R | R | O attestation | R |
| `leak_detected` | `containment` targeting lineage/lease/handle/process | `failed` | N | N | R leak token | `known` |
| `containment_started` | `containment` | `allowed` | N | N | R leak token | N |
| `containment_completed` | `containment` | `succeeded` | N | N | R leak token | `known` |
| `containment_failed` | `containment` | `needs_intervention`, `effect_uncertain` | N | N | R leak token | R |
| `quarantined` | `containment` | `quarantined` | N | N | O attestation/audit, R leak token only for leak quarantine | R |

Every success row and every execution row with an existing lease/handle requires
`secret_ref_scope=visible` in the restricted canonical event. Only
`lease_denied` may use the hidden variant; provider-control active probes have no
ref scope. Generic tenant/public traces use a
separate closed `splendor.secret.access_event_projection.v1` containing exactly
`schema_version`, `secret_access_event_id`, `tenant_id`, `kind`, `outcome`,
`occurred_at`, `recorded_at`, `tenant_request_correlation_token`, optional
`safe_error_family` from the exact set `not_available`, `unavailable`, `failed`,
`uncertain`, `quarantined`, and `needs_intervention`, required for every
non-success and forbidden for success, and optional `effect_certainty` only when
the matrix requires it. It contains no canonical subject,
object/target/provider ID, causal parent, retry class, attestation, leak token,
node-control receipt, counter, method, or extension. Authorized restricted
inspection returns the complete canonical event instead; no facade emits a
partially stripped canonical event.

The causal-ref tag selects the owner stream without changing stable
`TraceEvent`: `run_trace` appends the safe projection to the matching run stream;
`management_event` appends the restricted C03 fact through the accepted
management event/evidence owner and may expose only the tenant projection above.
Provider/node startup, health, expiry, incident, shutdown, and reconciliation
work with no run must use `management_event`. They do not allocate a run merely
to satisfy tracing. Until the management owner supplies nominal IDs, ordering,
integrity, and visibility, those non-run live controls remain gated off.

For rows permitting more than one non-success outcome, the failure taxonomy fixes
the choice: a proven no-effect policy denial is `denied`; a known failed operation
is `failed`; unknown external state is `effect_uncertain`; required operator work
is `needs_intervention`; and an applied containment fence is `quarantined`.
Where effect certainty is required, `succeeded` after provider/delivery/driver
work is `known`, `effect_uncertain` is `uncertain`, a proven pre-effect failure is
`none`, an authenticated/sent provider call with a definitive failure is
`known`, and cleanup/containment intervention after possible exposure is
`uncertain` until a receipt proves `known`. No other pairing validates.
Validators are generated from this matrix, not hand-written looser profiles.
`SecretAccessOutcome` describes the internal lifecycle fact and is never copied
by spelling into stable `ActionStatus`. For an action-owned event, the outer
status always follows the adapter-entry rule: an internal cleanup/revocation/
containment `needs_intervention` after adapter entry still produces outer
`Failed`, while the separate run/control fact requests operator work.
Every event kind requires one positive canonical fixture and negative fixtures
for the wrong subject tag, invalid outcome, every missing required group, every
present forbidden group, success with failure-only fields, and noncanonical
ordering/timestamp input.

The event never contains ref logical name, provider namespace/version/locator,
provider error text, material digest, secret-derived canonical hash, detector
key, delivery endpoint, environment name, action parameters, value, or bytes.

Visibility is evaluated from authenticated trusted tenant/principal context
before an idempotency-ledger lookup that can disclose state and before all
provider or node I/O. An absent ref, hidden existing ref, disabled ref, stale
revision, wrong tenant, mismatched idempotency key, and unauthorized ref all use
HTTP `404`, code `secret_not_available`, content type `application/json`, and the
exact body `{"code":"secret_not_available","message":"secret is not available","details":{}}`
right-padded with ASCII spaces to 256 bytes. Non-HTTP facades expose the same code
and no additional fields. From completed caller authentication and closed-schema
parse to response-header readiness, the local conformance profile pads each case
into the 20-40 ms class using a monotonic clock. Under at most 50 concurrent
requests and 70% host CPU utilization, 10,000 warm-cache observations per case
must have median differences no greater than 2 ms and two-sample Kolmogorov-
Smirnov `D <= 0.05`; otherwise live C03 activation fails. Load outside that
profile may return one uniform service-unavailable response before object lookup,
never a faster object-specific result. Restricted security evidence uses
`tenant_request_correlation_token = "trc1_" + base64url_no_pad(HMAC-SHA-256(
tenant_audit_key, "splendor.secret.request_correlation.v1" || 0x00 ||
request_id || 0x00 || secret_access_event_id))`. Tenant audit keys are distinct,
256-bit CSPRNG-generated, versioned, access controlled, and rotated without
rewriting history. Raw provider correlation and candidate `SecretRefId` are
absent from public/tenant projections and cannot correlate two tenants.

The `request_id` HMAC input is never an undefined generic string. It is the 16
canonical UUID bytes of `SecretRefMutationCommandId` for ref administration,
`SecretLeaseRequestId` for lease request/issuance/denial,
`SecretUseAttemptId` for delivery/use/cleanup except pre-reservation `use_denied`,
which uses `SecretUseClaimId`; `SecretProviderControlInvocationId` for provider
control, `SecretNodeControlInvocationId` for node control, and the
applicable renewal/rotation/revocation/cleanup/
containment command ID for those event families. An event without exactly one
applicable nominal ID is invalid.

## Provider Port

`splendor-authority::secrets` defines a Rust-only outbound `SecretProvider`
trait with semantic operations `fetch`, `renew`, `revoke`, `audit`, and
`active_probe`. No authority, node, daemon, SDK, background task, health loop,
incident handler, provider adapter, or replay path may invoke one directly.
Every method accepts a private validated request carrying the exact route,
operation, provider trust scope, authority revision, deadline,
idempotency/effect profile, and audit
correlation. `fetch` additionally requires the already-durable use reservation,
use-attempt ID, lease, exact target generation, and fencing. Raw public contracts
cannot construct any request.

`fetch` is available only inside a gateway-owned `SecretEffectSession` borrowing
the live action final permit. It returns one private tagged
`SecretProviderFetchResult` plus a safe provider receipt. The result is either
`material(SecretMaterial)` for FD,
tmpfs, or one-shot socket delivery, or
`node_projection(SecretProviderProjectionSession<'request>)` for the exact
provider-native projection profile. Both variants are non-cloneable,
non-serializable, redacted-debug, bound to the validated provider request, and
consumed once while the orchestrator separately retains the borrowed gateway
permit. The projection session is not a locator or bearer and
can be consumed only by the registered node-local provider plugin for the exact
execution binding. `SecretMaterial` is consumed once by the node delivery bridge,
is zeroized on drop where the platform supports it, and is never exposed by an
accessor returning an owned `String`, `Vec<u8>`, JSON, or SDK payload. Zeroization
reduces exposure; it is not a perfect erasure claim for copies made by provider
libraries, kernels, hypervisors, devices, or untrusted target code.

Every provider result/audit fact records whether request send was proved absent,
proved sent with a definitive result, or ambiguous. Provider effect certainty is
therefore `none`, `known`, or `uncertain` respectively. HTTP status, provider
denial, rate limit, or version-not-available after authenticated send is `known`,
not `none`; those calls may consume provider audit, rate, cost, or credential-use
effects. Unknown adapter/provider failure remains `uncertain`. No caller,
provider error string, or retry policy can downgrade this classification.

`renew`, `revoke`, `audit`, and `active_probe` are provider control effects.
They never return material and never fabricate an `ActionRequest` or target
adapter call. Authority owns the closed
`splendor.secret.provider_control_plan.v1` record containing exactly
`provider_control_invocation_id`, operation, exact `provider_trust_scope`,
`secret_provider_id`, route-policy revision, optional visible ref/lease scope
required by the operation, expected ref/lease/refresh/revocation generations,
complete current authority binding, operation deadline, closed retry profile,
requested/expiry times, and `causal_ref`. The gateway validates that plan and
constructs a private `splendor.secret.provider_control_request.v1` wrapper only
after provider-control authorization, route/bootstrap, policy, quota, deadline,
revocation, and evidence verifiers allow and durable
`secret.provider.control.requested` evidence exists.

The distinct private gateway control-invocation profile acquires an
operation-scoped final permit, calls exactly one provider method, and returns a
closed `splendor.secret.provider_control_result.v1` to Authority. The safe result
contains only invocation/provider/operation IDs, exact provider trust scope,
outcome, retry count, effect certainty, sanitized provider audit ID/code,
started/completed times, and `causal_ref`. Authority alone applies any resulting lease/ref/revocation state
CAS after `secret.provider.control.completed` is durable. The provider result is
not authority and cannot mark itself renewed, revoked, or healthy.

Control calls have the same 2-second connect, 5-second operation, and 6-second
total ceilings as fetch. At most one 100-ms retry occurs inside the same gateway
invocation and only after proven no-send or for an accepted provider-idempotent
operation keyed by `provider_control_invocation_id`; post-send uncertainty never
retries or fails over. Gateway/control re-entry is forbidden: a provider method
cannot submit an action, invoke another provider operation, recursively call the
gateway, or synchronously trigger health/revocation work. Deferred follow-up is
a new authorized control plan and invocation.

Passive capability inspection may read immutable in-process registration
metadata without credentials, filesystem/network/provider I/O, clock refresh,
or provider-derived health and is not a control effect. Any DNS lookup,
connection, authenticated request, file/keychain access, token refresh, provider
status request, or synthetic transaction is an `active_probe` and must use the
gateway control profile. Startup, periodic health, expiry, incident, and shutdown
workers submit plans with `management_event` causality unless a real run event
caused the control; they do not call providers or invent a run. Missing authorization,
pre-effect evidence, permit, deadline, result evidence, or effect certainty fails
closed and cannot update health to `healthy`.

The closed provider error variants are:

```text
unavailable
timeout_before_send
rate_limited
version_not_available
revoked
integrity_failure
unsupported_provider_version
unsupported_operation
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
- expose no independent timer/background worker that performs provider I/O;
  scheduled renew/revoke/audit/probe work re-enters through a fresh gateway
  control plan.

### Resident node-control gateway profile

Resident-node mutation is not a provider operation. A
`SecretProviderControlPlan` cannot fence a process, create/close a handle, mount
or delete a projection, or acknowledge node revocation. Those effects use the
separate closed `splendor.secret.node_control_plan.v1` profile and never fabricate
an `ActionRequest` or provider call.

`SecretNodeControlOperation` is exactly:

```text
prepare_delivery
activate_delivery
fence_target
terminate_process
close_handle
close_local_socket
unmount_tmpfs
delete_projection
attest_absent
acknowledge_revocation
```

The plan contains exactly `schema_version`, `node_control_invocation_id`, one
operation, exact `tenant_id`, actor principal and complete current
authority binding, optional `secret_action_submission_id` required when the
control belongs to an accepted action, exact `causal_ref`, operation deadline,
closed retry profile, requested/expiry times, and one complete
`SecretNodeControlTargetBinding`. That target binding contains exact `fleet_id`,
`node_id`, `instance_id`, `workload_id`, `attempt_id`, `sandbox_id`,
`process_boundary_id`, fencing epoch, exposure-lineage ID/revision, target
generation, use-attempt ID, lease ID, handle ID, delivery generation, delivery
method and method-child revision, credential slot/destination binding, and
revocation generation. A closed
operation-specific tag marks which coordinates are acted on; coordinates remain
present for equality and evidence. Caller JSON, provider output, incident
metadata, and replay cannot choose or rewrite them.
For `prepare_delivery`, Authority preallocates the nominal target generation,
handle ID, and delivery generation under the parent/use-attempt CAS before plan
construction; this creates no node/OS object. Only the permitted node operation
may realize them.

The gateway validates node-control authority, exact current placement/execution
lease/fence, node/instance registration and health, lease/lineage/revocation
state, deadline, operation compatibility, idempotency, and evidence availability.
It durably appends `secret.node.control.requested`, then issues one private
operation-scoped permit to the registered resident node bridge. For an action-
owned control this is a child of the already-held secret-action permit and outer
submission; it does not recursively submit to the gateway. A standalone
revocation/reconciliation control uses its own gateway control invocation and an
already-durable management causal event.

The node bridge performs exactly the permitted operation and returns a private
validated result. The gateway records pre/post restricted evidence and creates
one immutable `splendor.secret.node_control_receipt.v1` with receipt/invocation/
operation IDs, complete target binding, outcome, retry count, started/completed
times, effect certainty, pre/post evidence IDs, safe reason code, and causal ref.
It then durably appends `secret.node.control.completed`. Authority may advance
lease/lineage/revocation state only from that validated durable receipt. A node
acknowledgement, OS return code, provider receipt, or management intent alone is
not success.

Node effect certainty follows the same closed send rule: `none` requires proof
that no node-control bytes were sent and no local mutation was possible; `known`
requires a definitive bound result plus required post-evidence; missing,
ambiguous, or lost send/result/evidence is `uncertain`. A safe error string or
apparently idempotent OS state cannot downgrade uncertainty.

The node-control idempotency key is the trusted tuple of tenant ID,
operation, invocation ID, complete target binding, authority revision, deadline,
and canonical plan digest. Exact duplicate bytes return the original in-progress
or terminal receipt. Changed bytes conflict with no new effect. A local control
deadline is at most 10 seconds and revocation acknowledgement at most 5 seconds.
At most one 100-ms retry occurs under the same invocation only when the bridge
proves no control bytes were sent. C03 v1 permits no automatic post-send retry for
any node-control operation, including nominally idempotent close/fence/delete/
attest operations, because acknowledgement/evidence is part of the effect.
Ambiguous send/ack is `uncertain`, is never failed over to another node/instance/
process, and quarantines the target and parent exposure aggregate until a fresh
authorized same-target reconciliation plan obtains known absence/success
evidence without replaying the uncertain command.

Node-control re-entry is forbidden. The node bridge cannot invoke a provider,
submit an action/control, allocate broader authority, call another node, or emit
the outer action terminal event. Authority, daemon, incident, expiry, health,
shutdown, replay, and background workers submit plans only; they never call node
or OS/orchestrator mutation APIs directly. Missing authority, target coordinate,
deadline, pre/post evidence, receipt, effect certainty, or acknowledgement fails
closed and cannot emit `secret.revoked` or `secret.delivery.closed`.

`NODE-003` and `SBX-001` own the resident execution/process ABI and must accept
the complete target, permit, result, receipt, and trap-test contract above before
implementation. Event/Evidence must accept the management causal and restricted
pre/post evidence contracts. Until those owner contracts and nominal IDs are
accepted and implemented, every C03 live node-delivery, cleanup, revocation,
reconciliation, V3-V5, and associated gold gate remains disabled. C03 cannot
create substitute node/sandbox/process owners to bypass that prerequisite.

### Provider bootstrap identity and transport trust

Provider-service authentication is a separate non-workload bootstrap boundary.
It is never delivered through `SecretRef`, `SecretLease`, action params, the
target delivery context, or a workload environment. Each configured route has a
closed, owner-supplied tagged `SecretProviderBootstrapProfile`. This trusted
startup record is not a public/SDK/workload schema. Every tag has exactly the
common fields `schema_version=splendor.secret.provider_bootstrap_profile.v1`,
`profile_revision`, `secret_provider_id`, `route_policy_revision`, exact
tenant-only `provider_trust_scope`, `provider_namespace`,
`not_before`, `expires_at`, and `revocation_generation`, plus exactly one profile:

| Profile tag | Required fields and permitted behavior |
| --- | --- |
| `network_service` | Requires `provider_account`, `provider_audience`, non-empty sorted `allowed_origins` and `allowed_cidrs`, one closed `credential_source_profile` below, `revocation_source_id`, `ca_profile_id`, `sdk_profile_id`, and `sdk_profile_digest`. It alone permits DNS/TLS/network provider calls. |
| `local_file` | Requires `local_dev=true`, absolute owner-only `root`, immutable tuple-to-relative-file mapping digest, effective user ID, maximum 64-KiB read, and `platform=unix`. It permits descriptor-relative local file access only. Every network/CA/audience/account/SDK/bootstrap-credential field is forbidden. |
| `os_keychain` | Requires `local_dev=true`, fixed startup-supplied application ID, access-group ID, service namespace, effective user/session binding, immutable tuple-to-persistent-reference mapping digest, `interactive_prompts=false`, `enumeration=false`, and maximum 64-KiB value. Request fields cannot supply account/service/access-group labels. Network fields are forbidden. Unsupported ownership/session isolation rejects startup. |
| `test_memory` | Requires `local_dev=true`, `synthetic_canaries_only=true`, deterministic fixture-set digest, and test-process identity. It permits in-process fixture access only and forbids all network, file, keychain, account, identity, CA, SDK, and provider credential fields. |

Unknown tags, missing/extra/cross-tag fields, an empty required network set, or a
local tag outside explicit local-dev/test composition rejects route registration.
Static startup validation parses safe route metadata only and performs no
provider, network, file, or keychain I/O. A configured `network_service` route
cannot be advertised or accept work until startup submits a gateway-mediated
`active_probe` that constructs and validates the exact private source handle; a
missing/mismatched handle, source I/O uncertainty, or failed probe fails startup
closed. Probe uncertainty is not healthy. `local_file` and `os_keychain` support `fetch`, sanitized `audit`,
and `active_probe`; provider-side `renew`/`revoke` return the closed
`unsupported_operation`/known-no-effect result while Authority still
fences leases and node handles. `test_memory` supports only its declared
deterministic fixture operations. No tag falls back to another.

All non-path string coordinates are 1-128 printable ASCII without control/space
characters; origins/CIDRs and local paths use their exact parsers and canonical
forms. Lists are non-empty, duplicate-free semantic sets.
One bootstrap identity may serve multiple routes only when those routes have the
same exact tenant trust scope, namespace, account, audience, locality, and revocation
policy. Cross-tenant or broader-account sharing rejects startup.

For `network_service`, `credential_source_profile` is a closed tagged safe route
record. Its `bootstrap_source_binding_id` identifies one immutable private
startup binding and exactly one of:

- `workload_identity`: exact issuer, provider account, subject, audience,
  broker/provider-service `PrincipalId`, workload-identity binding ID,
  identity version, and refresh-owner `PrincipalId`. The broker identity is never
  the target workload identity. Only the named refresh owner may refresh inside
  the same gateway provider invocation; no background refresh thread or ambient
  metadata/default identity source is permitted.
- `owner_file`: immutable route-to-owner-opened-descriptor mapping ID, effective
  user ID, required owner-only mode, maximum 64-KiB read, and ownership/mode proof
  schema. The trusted private mapping names the configured file; request and safe
  route records contain no path. Construction under the startup control permit
  opens one bounded regular file with Unix `O_NOFOLLOW`, verifies effective-user
  ownership and no group/world bits on that descriptor, and rejects devices,
  FIFOs, sockets, symlinks, directories, link-count mismatch, path replacement,
  or a descriptor not equal to the immutable route mapping.
- `os_keychain`: exact application ID, access-group ID, service namespace,
  effective user/session binding, and one immutable persistent-reference binding
  ID/digest, with `interactive_prompts=false` and `enumeration=false`. The actual
  persistent reference is present only in trusted private startup configuration.
  Construction resolves exactly that reference; account/service search,
  enumeration, prompt, default keychain, other session/user, or broad access
  group is forbidden.

The serializable route contains only the safe tagged metadata and binding IDs/
digests above. The opened descriptor, persistent reference, workload-identity
token source, refresh capability, SDK credential object, authorization header,
and credential material are sealed, non-cloneable, non-serializable, redacted-
debug private handles retained only by the gateway-controlled provider route.
They never enter config export, state, traces, receipts, errors, action params,
work orders, or target delivery. Provider SDK environment/profile/home-directory/
metadata-server/default credential chains are explicitly disabled. If the exact
route-bound handle cannot be constructed, refreshed by its named owner, or
matched to provider account/audience/trust scope, startup fails; no other source
tag or provider route is tried.

Environment variables, CLI values, request fields, action params, provider
redirects, and target-delivered credentials are forbidden bootstrap sources.
Network bootstrap identities have an
explicit rotation overlap no longer than the provider's maximum request timeout;
revocation or expired/unknown trust closes the route before send. Bootstrap
credentials, provider authorization headers, and SDK credential objects are never
forwarded to the target, another provider route, logs, errors, audit receipts, or
failover.

`network_service` routes obey all of these rules before any send:

- origins are configured as exact `https://host:port` origins with no userinfo,
  path other than `/`, query, or fragment;
- TLS chain, hostname, SNI, configured public/private CA policy, and provider
  audience all validate; certificate or trust uncertainty has known no-effect;
- redirects and environment proxy discovery are disabled by default. A provider
  profile cannot enable redirect following; an explicit fixed proxy, if a later
  accepted profile permits one, is itself an allowlisted authenticated origin and
  may not receive provider credentials through redirect behavior;
- DNS is resolved before send, every answer must fall inside the route's exact
  configured CIDR policy, mixed allowed/denied answers reject, and the selected
  address is pinned for the connection while certificate verification still uses
  the configured hostname. Loopback, unspecified, multicast, link-local,
  cloud-metadata, and changed/rebound addresses reject;
- connect timeout is at most 2 seconds, one provider operation is at most 5
  seconds, total provider orchestration is at most 6 seconds, response headers
  are at most 32 KiB, material is at most 64 KiB, and sanitized non-material
  responses are at most 1 MiB;
- at most one retry is permitted, after 100 ms, and only when the adapter proves
  no request bytes were sent or the provider's accepted operation profile proves
  same-request idempotency. Post-send uncertainty never retries or fails over.

The adapter pins a reviewed provider SDK/library version whose maturity evidence
covers TLS behavior, redirect/proxy configuration, response limits, debug/error
redaction, timeout/effect classification, and dependency/supply-chain policy.
Missing origin, identity, CA, revocation, SDK maturity, DNS policy, or bounded
response state fails before send. Provider health cannot override any bootstrap
or transport denial.

## Authority and Gateway Sequence

The only secret-aware target-effect sequence is:

```text
versioned direct request or tagged tick SecretUseRequirement candidate
  -> authenticate + closed-schema validation
  -> registered-operation raw-ingress profile + server-derived slot/destination
  -> placement + execution lease + fencing
  -> durable outer SecretActionSubmissionId claim
  -> authority evaluates exact SecretLeaseRequest
  -> SecretLease issued without fetching material
  -> existing Action Gateway and every required verifier
  -> private final gateway permit
  -> create one SecretUseAttemptId per ordered requirement
  -> atomic all-or-none use/lineage reservations + durable secret.use.claimed
     for every requirement
  -> typed node-control plans allocate one parent-aggregate target generation,
     process boundary, fence, controls, detector, and handle per use attempt
  -> durable secret.delivery.requested/secret.provider.fetch.started evidence
  -> exactly one provider fetch per requirement in canonical requirement order
  -> enter SecretAwareActionAdapter and set secret_aware_adapter_entered=true
  -> driver-local resolve_and_deliver consumes slot-indexed SecretDeliveryContext
  -> set target_operation_started=true immediately before target driver effect
  -> exactly one target operation inside the still-live adapter invocation
  -> adapter passes immutable terminal SecretDeliveryControlAttestation and a
     borrowed opaque response view to the gateway continuation
  -> gateway postconditions and response-projection scanning run inside that continuation
  -> adapter wipes raw response/error buffers and returns a byte-free terminal
  -> secret.use.completed
  -> target termination, output drain, decoder finalization, and final seal
  -> immediate delivery/material/detector wipe/cleanup, close or quarantine
  -> non-serializable SecretSubmitCompletion after cleanup certainty is known
  -> Authority records immutable outer terminal intent
  -> common terminal normalizer atomically records one terminal receipt and one
     outer action terminal event, then marks outer submission terminal
  -> release sealed public ActionOutcome, then path-specific outcome/state suffix
```

Required rules:

1. Policy, user space, SDKs, and drivers may propose a typed requirement only.
2. The Authority Service validates the ref, principal, work order/capability,
   applicable data-use decisions, workload attempt, operation, placement,
   fencing, audience, purpose, intent, time, and uses before issuing a lease.
3. Lease issuance does not fetch or deliver material and does not execute an
   action.
4. The gateway revalidates live lease/ref/lineage revisions, refresh and
   revocation generations, exact target, expiry, aggregate use budget, policy,
   and all existing verifier categories immediately before its final permit.
5. Through the Authority command/CAS port, the gateway session atomically
   reserves the one submission-owned use attempt for every ordered requirement
   as an all-or-none batch, increments every affected lease
   and aggregate counter, and durably appends each `secret.use.claimed` before
   target material allocation or provider I/O. A conflict/denial in any member
   aborts the whole batch. Losing final-use races append only `use_denied`; their
   provider/material/driver counters remain zero. Every committed reservation is
   conservatively consumed.
6. A target generation, process boundary, fence, detector, controls, and handle
   are allocated only for each reserved use attempt through typed node-control
   permits. Required pre-effect
   evidence is durable before provider I/O. If allocation, trace, event, state,
   evidence, or detector durability is unavailable, no provider or driver call
   occurs; cleanup still records the consumed reservation.
7. Each requirement has exactly one provider fetch in canonical requirement
   order under the one gateway session, only after every reservation and
   target/control allocation succeeds. A failure cleans already acquired private
   material, skips later fetches and the driver, and consumes all reservations.
   Provider fetch is a declared credential-use sub-effect. It
   is not a second gateway, hidden adapter call, or broker bypass.
8. The private permit is retained and rechecked through provider access,
   slot-indexed driver-local delivery, immediately before adapter entry and target
   invoke, the terminal control
   attestation, gateway-owned postconditions, scanning/sealing, output drain,
   wiping, and cleanup classification. Every callee receives only the scoped
   borrow/linear value named by the staged ABI.
9. The driver owns raw provider/target response and error buffers. While they are
   still opaque and driver-owned, it lends the gateway continuation a bounded
   postcondition view and proposed public projections. The gateway decides
   postconditions and scans output, sanitized error, and postcondition evidence
   into private candidates before the driver wipes/drops raw buffers. After the
   adapter returns byte-free, the session drains every delayed target source,
   finalizes decoders, and seals the complete publication set. No generic JSON or
   error string crosses or leaves the session before final sealing.
10. Cleanup is mandatory on success, denial after reservation, provider failure,
    driver failure, postcondition failure, cancellation, timeout, unwind, or
    uncertain effect. The session owns cleanup independently of the context and
    driver. An uncertain or failed drop/wipe/control step is cleanup uncertainty,
    never success. Panic-abort/process death leaves the durable attempt for node
    reconciliation and quarantine.
11. Stable public `ActionStatus` values and meanings do not change. Before entry
    into `SecretAwareActionAdapter`, verifier/policy denial is `Denied`, approval
    is `NeedsApproval`, and unresolved provider/allocation/cancellation/runtime
    failure is `NeedsIntervention`; all mean adapter execution did not occur.
    Once the method is entered, complete success is `Executed` and every
    delivery, target, postcondition, scan, cancellation, timeout, cleanup,
    evidence, or revocation failure/uncertainty is `Failed`, even when the target
    operation never started. Provider/target/outer effect certainty remains
    explicit and independent of this status. Post-effect
    intervention/quarantine is a separate C03/run fact, not a false
    `NeedsIntervention` action status.
12. `SecretSubmitCompletion` is consumed by one shared terminal normalizer used
    by tick and direct submissions. It authenticates the sealed bytes, checks the
    status/adapter-entry/target-start/provider-node-target-certainty matrix, verifies
    the durable terminal intent, and atomically appends exactly
    one `SecretDeliveryReceipt` and exactly one outer terminal `action.*` event.
    A failed postcondition emits only `action.failed`, never `action.executed`
    followed by `action.failed`. This one-terminal rule is the explicit
    experimental wrapper correction; stable non-secret submissions remain
    byte-for-byte unchanged pending any broader trace migration.
13. A tick-owned action then emits `outcome.recorded`, performs its explicit state
    commit, and emits `tick.completed`. A direct action emits
    `outcome.recorded` only and invents no tick or state event. Both paths use the
    same normalizer and receipt. Gateway session/orchestrator, provider, node,
    and driver emit no outer `action.*` event.
14. If the atomic receipt/outer-terminal append is blocked after a possible
    effect, the private result is `terminal_evidence_blocked`: no serializable
    `ActionOutcome`, `outcome.recorded`, state commit, direct success response, or
    next tick is allowed. The outer submission becomes uncertain. Authority's
    reconciler may commit the one exact terminal-intent pair using the original
    ordered use-attempt batch; it cannot call provider/node/adapter/target again,
    allocate another attempt, or create a second terminal fact.

Raw `SecretLease`, handle metadata, provider receipts, approval text, messages,
and ref IDs cannot substitute for the private validated wrappers and permit.

## Lifecycle and Concurrency

### Command, decision, event, state

Authority-internal commands are closed private Rust records. They are never
daemon/SDK payloads and raw deserialization cannot construct their validated
wrappers. Every command has exactly one nominal command ID, exact schema, one
`SecretCommandActorBinding`, one target, required CAS coordinates, one causal
ref, and authority-owned `observed_at`. `SecretCommandActorBinding` contains
only `tenant_id`, `actor_principal_id`, a complete current
`SecretAuthorityBinding`, and `causal_ref`; its principal and tenant must
equal the authority binding. The live command accepts only a private current
authority wrapper, never the serialized binding alone.

The closed command shapes are:

`SecretRefSpec` is the command-only semantic proposal containing exactly
`secret_ref_id`, `tenant_id`, `secret_provider_id`, `provider_namespace`,
`logical_name`, `provider_version_ref`, `classification`, sorted exact
`allowed_credential_bindings`, sorted `allowed_delivery_methods`, `lease_policy`,
and `offline_behavior`. Revision,
creation/disable time, current-head status, and generated event identity are
authority results and are absent.

| Command schema | Required fields beyond actor binding and `observed_at` |
| --- | --- |
| `splendor.secret.ref_mutation_command.v1` | `secret_ref_mutation_command_id`; `operation=register|update|disable`; complete `SecretRefSpec` for register/update and absent for disable; exact `secret_ref_id` for disable; `expected_current_revision` absent for register and required for update/disable. |
| `splendor.secret.renewal_command.v1` | `secret_renewal_command_id`; `secret_lease_id`; `expected_secret_lease_revision`; `expected_exposure_lineage_revision`; `expected_refresh_generation`; `expected_revocation_generation`; complete fresh same-attempt `execution_binding`; requested `starts_at`, `expires_at`, and `max_uses`; predecessor `last_event_id`. |
| `splendor.secret.rotation_command.v1` | `secret_rotation_command_id`; `secret_ref_id`; `expected_secret_ref_revision`; complete next `SecretRefSpec`; old `secret_lease_id`, `expected_secret_lease_revision`, `expected_refresh_generation`, `delivery_handle_id`, and `expected_delivery_generation` when cutting over a live target; complete fresh `execution_binding`; predecessor `last_event_id`. |
| `splendor.secret.revocation_command.v1` | `secret_revocation_command_id`; one `SecretRevocationTarget`; `expected_revocation_generation`; `reason_code`; predecessor `last_event_id`. |
| `splendor.secret.expire_cleanup_command.v1` | `secret_cleanup_command_id`; `operation=expire|cleanup`; one `SecretCleanupTarget`; `expected_secret_lease_revision`; `expected_revocation_generation`; optional `expected_delivery_generation` required by a delivery target; predecessor `last_event_id`. |
| `splendor.secret.containment_command.v1` | `secret_containment_command_id`; one `SecretContainmentTarget`; `containment=quarantine_and_revoke|quarantine_only`; `secret_leak_token`; all target revisions/generations; predecessor `last_event_id`. |
| `splendor.secret.use_claim_command.v1` | `secret_use_claim_id`; exact `secret_action_submission_id`; submission-owned fresh `secret_use_attempt_id`; one exact action/invocation effect coordinate; exact credential slot/destination binding; `secret_lease_id`; `expected_secret_lease_revision`; `secret_exposure_lineage_id`; `expected_exposure_lineage_revision`; complete execution binding; `expected_refresh_generation`; `expected_revocation_generation`; predecessor `last_event_id`. No delivery handle exists before this reservation commits. |

The target unions are exact:

- `SecretRevocationTarget` is one of `ref {secret_ref_id,
  expected_secret_ref_revision}`, `lease {secret_lease_id,
  expected_secret_lease_revision}`, `principal {principal_id}`, `workload
  {workload_id}`, `attempt {workload_id, attempt_id}`, `driver_operation
  {driver_operation}`, `node {node_id}`, `instance {instance_id}`, `deployment
  {deployment_id}`, `incident {incident_id}`, or `exposure_lineage
  {secret_exposure_lineage_id, expected_exposure_lineage_revision}`.
- `SecretCleanupTarget` is `lease {secret_lease_id}` or `delivery
  {secret_lease_id, delivery_handle_id, process_boundary_id}`.
- `SecretContainmentTarget` is `ref {secret_ref_id, secret_ref_revision}`,
  `lease {secret_lease_id, secret_lease_revision}`, `delivery
  {secret_lease_id, delivery_handle_id, delivery_generation}`, `process
  {workload_id, attempt_id, process_boundary_id}`, or `exposure_lineage
  {secret_exposure_lineage_id, exposure_lineage_revision}`.

Foreign `attempt_id`, `driver_operation`, `deployment_id`, `incident_id`, and
other non-C03 coordinates above use only nominal owner-supplied types. A command
variant cannot compile or be exposed before its owner contract lands; C03 does
not create string substitutes.

| Command | Decision | Required event/state result |
| --- | --- | --- |
| Register/update/disable ref | Allow or structured deny after CAS, provider-route policy, and classification validation | `ref_registered`, `ref_updated`, `ref_disabled`, or `ref_mutation_denied`; immutable revision and CAS current ref head. |
| Request lease | Allow or deny after complete binding/authority checks | `lease_requested`, then `lease_denied` or immutable lease plus `lease_issued`. |
| Request delivery | Allow or deny after final gateway permit | Durable `delivery_requested`/`provider_fetch_started`, or `delivery_denied`, before provider I/O. |
| Activate/use | Atomic lineage use claim or deny | Atomically increment counters/revisions and append `use_claimed`, or append `use_denied` with no effect. |
| Renew | Allow only from live current lineage with fresh authority and a fresh process boundary | New lease/revision chain and `renewed`, or `renewal_denied`; old target is fenced. |
| Rotate ref/material | Allow only through ref CAS plus fresh-process cutover | New ref revision/new handle and `rotated`, or `rotation_denied`; old target is fenced. |
| Revoke | Scope-match and increment revocation generation | `revocation_requested`, deny new claims, push/ack where available, then `revoked` or explicit uncertainty; invalid scope emits `revocation_denied`. |
| Expire | Authority clock reaches exact expiry | Deny new claims, close handle, `expired`. |
| Close/cleanup | Idempotent target cleanup | `cleanup_started`, then `closed`, `cleanup_uncertain`, or `quarantined`. |
| Leak detected | Fail or quarantine; never success by silent redaction | `leak_detected`, `containment_started`, then `containment_completed` or `containment_failed`, and `quarantined` when the fence applies. |

### Use-attempt ledger and stale refresh writers

Authority is the sole mutation owner of the durable use-attempt ledger. Gateway
session typestates call its narrow command/CAS port and never write storage
tables. Its closed states are `prepared`, `reserved`, `target_allocated`,
`provider_started`, `delivered`, `adapter_entered`, `target_started`,
`target_returned`, `postverified`, `cleaning`, and
`terminal`. Each row binds the fresh `SecretUseAttemptId`, exact effect
coordinate, outer submission ID, credential slot/destination, lease/lineage IDs
and expected revisions, refresh/revocation
generations, canonical operation, execution binding, target generation when
allocated, last event, and booleans proving whether reservation, provider,
material, delivery, adapter-entry, or target-operation boundaries were crossed.
State advances only by Authority CAS commands; missing/ambiguous state is treated
as crossed, not safe to retry. Authority commands also advance every
post-reservation state. The authority-owned `SecretActionReconciler` alone claims
crash reconciliation. It can submit fresh typed same-target node cleanup/control
plans and append retained terminal intent, but cannot repeat provider or target
effects.

A writer whose `expected_refresh_generation` is stale is rejected. It cannot
overwrite a newer lease/provider selection, cannot continue provider/delivery,
and cannot reuse that use-attempt ID after `reserved`. It cleans/discards any
private material, conservatively consumes the committed reservation, and retries
only through a fresh authorized `SecretUseAttemptId` and fresh current
generations. The one narrow same-ID rebase exception is observable ledger state
`prepared` with all of `reservation_committed=false`, `target_allocated=false`,
`provider_started=false`, `material_staged=false`, `delivery_started=false`,
`secret_aware_adapter_entered=false`, and `target_operation_started=false`. A
fresh `SecretUseClaimId` with the same use-attempt ID
and current refresh generation may CAS that prepared row before any event other
than the original prepared audit fact; the stale command ID and bytes remain an
immutable denial. If any flag, durable evidence, or store read is missing or
uncertain, the exception is forbidden. Tests must cover both the exact exception
and every crossed-boundary rejection.

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

- Every command ID, including `SecretLeaseRequestId`, is looked up only inside a
  trusted ledger key of exact tenant, principal, workload and attempt when
  applicable, command kind, and nominal command ID. Caller-supplied scope bytes
  cannot select another ledger partition.
- Before any lookup that can reveal a prior result, the authority owner
  revalidates the current authenticated caller, work order/capability, data-use
  decision, placement, execution lease, fencing, revocation, visibility, and
  target compatibility. This validation occurs before provider/node I/O. A
  cached success is a historical non-authorizing receipt only; it cannot rebuild
  a validated lease wrapper, delivery context, permit, or live allow and cannot
  skip gateway revalidation.
- Idempotency equality uses schema
  `splendor.secret.semantic_idempotency_projection.v1`: command schema and kind,
  trusted ledger scope, command ID, and every command field listed above except
  authority/event-owned `observed_at`, `requested_at`, `occurred_at`,
  `recorded_at`, generated result timestamps, and authority-generated result IDs.
  `SecretLeaseRequest` uses the same rule: its `requested_at` is excluded and all
  other request fields, including `causal_ref`, remain. Excluded fields are
  never accepted from caller bytes as semantic substitutes.
- The first accepted observation time, first canonical semantic digest, and first
  terminal/in-progress result are retained. The same ID and semantic projection
  observed later returns only that original historical receipt after current
  validation. A changed semantic projection conflicts and creates no effect.
  Hidden, cross-tenant, wrong-principal, wrong-workload/attempt, not-found, and
  conflict states all use the uniform `secret_not_available` outward profile;
  restricted evidence alone distinguishes them.
- Every expected revision/generation is part of the semantic projection. An
  exact retry of a stale command returns its first stale denial/receipt. Reusing
  that command ID with a refreshed expected value conflicts. Except for the
  explicitly prepared/unreserved use-attempt rebase above, a caller that reads a
  current revision/generation must submit a fresh nominal command ID; a crossed
  use attempt also requires a fresh `SecretUseAttemptId`.
- Ref, lease, handle, revocation, and cleanup mutations require an expected
  revision or generation. Exposure lineage mutations additionally require
  `expected_exposure_lineage_revision`. A stale CAS changes no state, counter,
  event head, idempotency result, provider state, or target state.
- A successful use claim is one authority/store transaction that checks the
  outer submission and lease/lineage/refresh/revocation generations, creates the
  submission-owned reserved use-attempt row, increments lease `uses_claimed`, increments
  the exposure-lineage aggregate count, increments both lease and lineage
  revisions, appends the canonical `use_claimed` event, and makes that event the
  `last_event_id`. If the canonical event store is separate, the same transaction
  writes a unique outbox record and delivery waits for its durable append
  acknowledgement. No target allocation, provider call, material instance, or
  exposure occurs before counter commit and durable event.
  Concurrent final-use claims have exactly one winner; a loser appends only its
  separate denial event and never changes the successful claim.
- Reservation consumes one aggregate use for FD, tmpfs, projected, or
  environment delivery even when a later pre-exposure stage fails. C03 cannot
  count arbitrary operations performed by untrusted code after exposure. A
  one-shot socket requires a distinct reserved use attempt per successful
  retrieval. Driver profiles must state which exposure model they use.
- Each workload attempt requests a fresh lease by default. A retry cannot reuse
  a prior attempt's lease, handle, audience, process binding, or use attempt, but
  it does not thereby reset the stable exposure-lineage budget.
- Authority-owned trusted time tracks the maximum observed clock. Clock
  unavailability, rollback, or uncertainty beyond the ref's maximum 30-second
  tolerance denies issuance/renewal/use. Expiry has no grace period.
- If provider send, node control, or target operation may have occurred but no
  exact receipt proves its dimension, that dimension and outer effect certainty
  are `uncertain`; no automatic retry, failover, renewal, new key, or new
  credential changes that fact. Terminal-evidence uncertainty independently
  withholds every outcome and reports outer uncertainty until exact
  reconciliation.

Crash and duplicate recovery is closed: before reservation, an exact command
retry may produce no effect; after reservation, the use remains consumed and the
ledger resumes cleanup/reconciliation without provider, node effect, or target
replay. After provider/node/target effect but before terminal evidence, the
attempt remains `effect_uncertain` and quarantined until reconciliation. Recovery
never creates a second effect, reuses a use-attempt ID, or reconstructs a trusted
wrapper from a stored serialized result.

### Parent exposure aggregate, method children, and limits

Authority derives one stable parent exposure aggregate from the registered
driver declaration and server-derived credential destination, never caller JSON.
The private semantic parent key is exactly:

```text
tenant_id
secret_ref_id + secret_ref_revision
principal_id
workload_id
canonical DriverOperationRef
SecretCredentialSlotId + credential destination schema/digest
intent + purpose
```

Delivery method is deliberately absent. `WorkloadAttemptId`, action/invocation
ID, placement/execution lease, fleet/node/instance/sandbox/process IDs, fencing
epoch, audience, handle, FD/socket/mount/connection identity, provider request,
and authority/revocation revisions are also absent. They are child bindings and
cannot reset exposure continuity. Coarse destination/field/access classes may
remain non-authorizing driver metadata for observability, but never replace the
exact slot/destination key or participate as a weaker authorization comparison.

The existing authority-generated `SecretExposureLineageId` identifies this
parent `SecretExposureAggregate`. Every selected method creates or reuses a
method-specific child containing only the selected method and controls that
narrow the parent. FD, socket, tmpfs, projected, and any future method children
share the parent's use counters/maximum, continuous lifetime/deadline,
process-taint/quarantine history, refresh/revocation generations, revision, and
one-active-or-pending-target exclusion. Switching methods requires a fresh lease
decision and may narrow controls, but cannot create another parent, reset state,
or overlap target generations.

The closed durable parent schema is `splendor.secret.exposure_aggregate.v1` and
contains exactly its schema, lineage ID, every parent-key field above, positive
aggregate max uses, uses claimed, continuous start/deadline, sorted method-child
records, optional one pending/active target generation, process-taint and
quarantine state, refresh/revocation generations, revision, and last event ID.
Each `splendor.secret.exposure_method_child.v1` record contains only its schema,
parent lineage ID, selected delivery method, exact narrowed control-profile
digest, created time, revision, and `status: SecretDeliveryStatus`; it has no
independent counter,
deadline, taint, or target-generation namespace. Neither schema contains material
or a delivery endpoint. Method children sort by exact delivery-method enum
spelling and duplicate methods reject.

Authority first constructs a closed private `SecretExposureCeilingSet` from
validated owner decisions. It contains required ref-policy, bound-requirement,
and lease-request use/time ceilings plus separate tagged
`ceiling {max_uses, expires_at}|not_applicable` values for current work order,
capability grant, authority decision, provider route, execution lease, and
driver-slot target. `not_applicable` is accepted only from that constraint's
owner, never request JSON. On first admission under parent-key CAS, Authority sets
`continuous_lifetime_started_at = max(authority_observed_at,
first_approved_lease_request.not_before)` and computes:

```text
aggregate_max_uses = min(
  ref_revision.lease_policy.max_uses,
  first_approved_requirement.requested_max_uses,
  first_approved_lease_request.max_uses,
  each applicable current work-order max_uses,
  each applicable current capability max_uses,
  each applicable current authority-decision max_uses,
  each applicable current provider-route max_uses,
  each applicable current execution-lease max_uses,
  each applicable current driver-slot-target max_uses
)

max_continuous_expires_at = min(
  continuous_lifetime_started_at + ref_revision.lease_policy.max_continuous_lifetime_seconds,
  continuous_lifetime_started_at + first_approved_requirement.requested_duration_seconds,
  first_approved_lease_request.expires_at,
  each applicable current work-order expires_at,
  each applicable current capability expires_at,
  each applicable current authority-decision expires_at,
  each applicable current provider-route expires_at,
  each applicable current execution-lease expires_at,
  each applicable current driver-slot-target expires_at
)
```

Each applicable owner returns an explicit finite ceiling; a missing, zero,
unbounded, stale, or ambiguous applicable ceiling denies aggregate creation. The
first requirement/request values are the exact bound values approved for the
CAS winner, not caller replacements observed later. The resulting positive use
ceiling, start, and future deadline are pinned on the parent before lease issue.

For a later lease, Authority builds the same fresh ceiling set. A requirement or
lease request whose requested max/deadline exceeds the pinned parent returns
`exposure_aggregate_widening_denied`; renewed owner authority that is merely
broader does not widen the parent and is not by itself an error. Authority then
computes the same minimum from the later request and current owner ceilings. An
equal result preserves the parent. A stricter result may move it only through
explicit `expected_exposure_lineage_revision` CAS. `aggregate_max_uses` may never
increase and cannot narrow below `uses_claimed`; the continuous start never
changes and the deadline may never move later. Narrowing below consumed state
rejects without mutation. A deadline narrowed to current/past Authority time
denies the lease and starts normal expiry/cleanup; it does not rewrite prior
facts. No refreshed policy/authority/provider/target value can silently clip a
broader request, extend the parent, or create a sibling parent.

Concurrent first leases linearize on parent creation. The loser rereads the
winner's aggregate: it may CAS a still-valid stricter ceiling, preserve exact
values, or deny a widening/conflicting request; it cannot create a sibling parent.
Partial consumption remains counted during narrowing. Renewal, retries in a new
workload attempt, duplicate transport, provider failover, handle close/reopen,
lease reissue, and delivery-method switch preserve parent counters, start,
deadline, taint, and target exclusion. Only a new ref revision or genuinely new
owner-issued `WorkloadId` plus fresh authority creates a new parent; neither may
be caller-minted as a retry escape.

Each reserved use deterministically allocates the next positive
`lineage_target_generation = prior + 1` under the parent CAS, regardless of
method child. The child record binds that generation to one use attempt, workload
attempt, outer submission/effect coordinate, method, and complete process/
audience/fence/slot/destination target. The generation cannot become active until
the prior target across every method child is fenced and cleanup is terminal;
uncertainty quarantines the parent. Same-attempt renewal and later-attempt retry
allocate a fresh child but preserve every parent fact. Rotation to a new ref
revision creates a new parent only after the old target is fenced as required by
the rotation contract.

## Delivery and Cleanup

### Mechanisms

| Method | Required boundary | Mandatory controls |
| --- | --- | --- |
| `inherited_fd` | Exact child process | Anonymous/non-path FD where possible, close-on-exec except exact child handoff, no parent/sibling inheritance, close on terminal state. |
| `tmpfs_file` | Exact sandbox/process | Node-owned tmpfs, owner-only mode, no workspace/image layer, no persisted mount metadata containing material, unmount/unlink on terminal state. |
| `one_shot_local_socket` | Exact process/audience | Node-local peer identity check, one successful bounded read per claim, no network listener, close and erase queue after delivery. |
| `orchestrator_projected_secret` | Exact placed workload and admitted process | Provider-native node-local reference/CSI-like projection only; immutable workload UID, no material in an orchestrator API object, etcd, control-plane audit, manifest, workload spec, or generated file; deletion/ack on terminal state. |
| `environment_variable` | Exact fresh process | Reserved compatibility value only; live v1 activation always denies pending a separate accepted amendment. |

The required delivery-control matrix is fixed. `R` requires `status=applied` and
restricted evidence before activation; `O` permits `not_applicable` only when the
control truly cannot carry material for that method. `unsupported` or `failed`
is non-success for every row.

| Method | core dump | ptrace/debug | child inheritance | output capture | swap/page dump | generic cache | orchestrator projection |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inherited_fd` | R | R | R | R | R | R | O |
| `tmpfs_file` | R | R | R | R | R | R | O |
| `one_shot_local_socket` | R | R | R | R | R | R | O |
| `orchestrator_projected_secret` | R | R | R | R | R | R | R |
| `environment_variable` | R | R | R | R | R | R | O, but the method still denies in v1 |

Projected delivery has one permitted material flow. The orchestrator consumes a
private `SecretProviderProjectionSession` through the provider's reviewed
node-local plugin; the session carries the provider-native opaque reference and
exact workload/process binding without exposing either to callers. The plugin
completes the one already-authorized gateway `fetch` on the node and projects
material through a node-local reference/CSI-like mount. Its provider I/O remains
inside that same session/permit/deadline and cannot run from a plugin watcher,
reconciler, background task, or second provider call. Neither Splendor nor the plugin creates or
updates a Kubernetes Secret, generic orchestrator secret object, API payload,
etcd record, control-plane audit body, workload manifest, or environment object.
The generic `fetch -> SecretMaterial -> orchestrator API` flow is forbidden. If
a provider cannot perform provider-native node-local projection without such a
control-plane copy, this method is `unsupported`; policy may select FD, tmpfs, or
one-shot socket before fetch, never fall back after material exposure.

`environment_variable` remains in the enum only to reserve compatibility. No
accepted authority obligation/receipt contract currently proves environment
exposure, so C03 v1 always denies with
`environment_exposure_contract_unaccepted`, even when a ref and driver list the
method. Enabling it requires a separately accepted RFC amendment that versions
the exact obligation, receipt, process-capture controls, generated surfaces, and
gold fixtures. Until that amendment is accepted and implemented, V1-V5 cannot
claim environment success. No fallback converts another delivery failure into an
environment variable.

### Exposure controls and honest limits

Before activation, node/executor integration must configure and prove every
required control; "where supported" is not an allow path:

- core dumps and crash dumps disabled or routed through the leak barrier;
- debugger/ptrace access denied outside the exact trusted operator policy;
- stdout/stderr, process args, environment snapshots, manifests, metrics, and
  debug bundles scanned before persistence;
- child inheritance denied unless the child is the exact bound process;
- workspace, image-layer, artifact, swap, page-dump, and generic cache writes
  denied for secret material;
- target termination, FD/socket closure, unmount/deletion, and revocation
  acknowledgement on completion, cancellation, expiry, quarantine, node drain,
  or process crash.

The detector registration, process quarantine fence, and delivery context remain
live through target termination, complete stdout/stderr/adapter-output drain,
bounded decoder finalization, every trace/state/event/artifact/dataset/error/
observability persistence or publication decision, and cleanup evidence. No
target-controlled bytes may be released after detector teardown. Detector
key destruction and deregistration occur only after the final scan has no pending
overlap bytes and every publication decision is terminal. Before teardown, the
barrier seals the exact scan-approved public output bytes, sanitized public error
projection, and postcondition evidence plus their BLAKE3 integrity digests in a
private non-cloneable `SealedSecretActionProjection`. Later outer action/outcome
recording may consume only those exact bytes after verifying every digest; raw
driver response/error/postcondition bytes never enter `ActionOutcome`, traces, or
errors. No later adapter/provider/target callback can alter or append bytes. The
stable non-secret path remains unchanged. `secret.delivery.closed` is the last
C03 delivery event. If output is opaque, too large, truncated, decoder-incomplete,
or cannot be drained within the bound below, it is quarantined and the action is
not successful. Cleanup uncertainty keeps the fence and detector available for
reconciliation or records why secure retention is impossible; it never emits
`closed`.

Splendor cannot prove erasure from an untrusted process after it has read the
credential, from copied process/container memory, from a provider SDK, from a
hypervisor, or from hardware. The receipt reports the controls applied and
cleanup certainty. Uncertain cleanup is not success: it quarantines the target,
denies new leases there, and emits incident-worthy restricted evidence.

`SecretMaterial`, provider projection sessions, delivery contexts, opaque driver
views, decoder overlaps, detector keys, and unsealed/sealed buffers have explicit
zeroizing/drop implementations where their representation permits it. Drop is a
defense in depth, not lifecycle authority: the gateway session invokes bounded
cleanup explicitly and records its result. Unwind runs the same guard. Failed or
skipped cleanup/drop, `mem::forget`, task cancellation, process death, or
panic-abort cannot produce success; the independently owned session/supervisor
fences and reconciles the durable target. No drop error is serialized with raw
bytes.

Activation permanently taints the exact `ProcessBoundaryId` for that secret
exposure lineage. Handle close, unmount, socket EOF, cleanup acknowledgement, or
process claims do not prove copied bytes disappeared and cannot clear the taint.
Renewed or rotated material for that lineage requires a fresh fenced process
boundary. Renewal remains in the same workload attempt; rotation may create a
fresh attempt but cannot reset the old ref revision's lineage. Same-process
cutover is denied in C03 v1. A future exception requires a separately accepted trusted
non-material-exposing proxy profile proving target code never receives either
material version; handle-close inference alone can never satisfy it.

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
- Renewal creates a new lease and target generation for a fresh fenced process
  boundary inside the same `WorkloadAttemptId` and carries the exact exposure
  parent aggregate/lineage ID, method-child controls, counters, deadline, refresh
  history, and taint forward. It
  does not mutate provider bytes in place. A process
  tainted by prior activation cannot receive the renewed material.

### Rotation

Ref rotation appends a new ref revision. A running workload receives it only
through a new lease and handle in a fresh fenced process/attempt. The old process
is fenced and terminated before traffic moves; closing its handle is necessary
but never proof that copied old material disappeared. A zero-downtime service may
shift traffic between separately fenced old and new processes; one process may
not receive both versions. Same-process rotation always denies in C03 v1.

### Revocation

Revocation can target ref, lease, principal, workload, attempt, driver operation,
node, instance, deployment, or incident scope. The Authority Service increments
the generation and denies new claims before submitting any node/provider
revocation as a typed gateway control effect. Authority/node/incident code never
calls the provider directly.
Nodes acknowledge exact generation and target. Missing, stale, partitioned, or
ambiguous acknowledgement leaves revocation/cleanup uncertain and quarantines
the target for new secret-bearing work.

`secret.revoked` is emitted only after every required local fence and
provider/node acknowledgement is durably known successful. A timeout, ambiguous
send, missing acknowledgement, terminal evidence failure, or stale generation
emits `secret.revocation.uncertain`, keeps lease state
`revocation_pending`, records the control invocation/provider audit ID and effect
certainty, and quarantines affected targets. Recovery first re-reads current
generation and provider audit through a newly authorized gateway control
invocation; it never rewrites the uncertain event as success, retries an
uncertain non-idempotent revoke, or unquarantines before a new known terminal
receipt.

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

All local provider profiles require explicit `local_dev` runtime mode. If the
local composition exposes a daemon, it uses only a loopback listener or
Unix-domain socket; the in-process test provider opens no listener. Their
constructors reject resident, remote, fleet, production, and unknown modes;
production composition does not register them and capability advertisement omits
them. A mode cannot be selected by a
workload, work order, action, provider route, or environment fallback. The
in-memory provider accepts synthetic canaries only and is unavailable outside
tests/local development.

The development file provider has one startup-configured absolute root owned by
the effective user and not group/world accessible. Broker configuration maps
`(provider_namespace, logical_name, provider_version_ref)` to a bounded relative
file name; requesters never supply a path. Unix access opens the root directory,
uses descriptor-relative `openat` with `O_NOFOLLOW`, rejects absolute paths,
empty segments, `.`/`..`, symlinks at every component, hard links with link count
other than one, and anything except an owner-only regular file. Devices, FIFOs,
sockets, directories, and files outside the opened root deny. Reads are bounded
to 64 KiB. Non-Unix builds may use only the exact tagged `os_keychain` profile:
the immutable startup mapping resolves the broker tuple to one persistent
reference under the configured application/access group/service namespace and
effective user/session. Enumeration, requester-supplied labels, interactive
prompts, broad access groups, cross-user/session lookup, and values over 64 KiB
deny. A platform that cannot enforce those properties fails startup and cannot
claim keychain support. Paths, contents, persistent references, and keychain
diagnostics are redacted from `Debug`, errors, events, and receipts.

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

### FND-012 activation budgets

`secret_broker_v1` cannot enter live mode until an accepted FND-012 evidence
record proves all budgets below on the production composition. These are maximum
or minimum v1 conformance bounds; deployments may be stricter but not looser:

| Resource | Required v1 bound |
| --- | --- |
| Material and provider response | 64 KiB material maximum; 32 KiB headers and 1 MiB sanitized non-material response maximum. |
| Provider time/retry | 2 s connect, 5 s operation, 6 s total; at most one 100 ms known-no-effect/idempotent retry; none after uncertain send. |
| Gateway overhead | Secret orchestration excluding provider and target-driver time has p95 <= 25 ms and p99 <= 50 ms over 10,000 operations. |
| Persistent detector material | At most 64 active/pending detector registrations per node and 16 per tenant/node; at most 512 KiB per detector including the 64-KiB material/pattern, keyed matcher tables, enabled representation decoders, and metadata; 32 MiB node / 8 MiB tenant ceiling. |
| Concurrent invocation/overlap | At most 16 secret-aware invocations per node and 4 per tenant/node; at most 8 simultaneously open scanned sources per invocation; each source retains at most 256 KiB shared overlap across all detectors; 32 MiB node / 8 MiB tenant ceiling. |
| Detector throughput | At least 100 MiB/s aggregate on the activation hardware for declared representations, measured with 4 KiB through 1 MiB chunks and the maximum active detector set. |
| Streaming/backpressure | At most 1 MiB unscanned queued bytes per invocation; 16 MiB node / 4 MiB tenant ceiling; producers block or the output quarantines, never bypasses scanning. |
| Idempotency/replay state | At most 4,096 hot command/use-attempt/submission-index entries per node and 1,024 per tenant/node, at most 2 KiB each; 8 MiB node / 2 MiB tenant ceiling. Full terminal intents, receipts, and pending sealed outcomes are excluded from the hot-entry size claim; each receipt is at most 512 KiB, outcomes obey the existing output bound, and all use quota-controlled durable storage. Durable records obey configured tenant retention/byte quotas and are never silently deleted to admit work. |
| Fixed restricted metadata | At most 8 MiB node / 2 MiB tenant for lineage indexes, control plans, and admission bookkeeping. |
| Total restricted node/tenant memory | 96 MiB node and 24 MiB per tenant/node for the five ledgers above; no category may borrow from another. There are at most 16 requirements per action. |
| Output drain | 30 s maximum after target exit/cancel; timeout quarantines and prevents terminal success/publication. |
| Local cleanup | 10 s maximum for FD/socket close, unlink/unmount, projection deletion acknowledgement, and detector finalization; timeout is cleanup uncertainty. |
| Provider revoke acknowledgement | 5 s maximum; timeout remains effect-uncertain and cannot report revoked success. |
| Soak | 24 hours, at least 100,000 lease/use/cleanup cycles, maximum cardinality for at least one hour, zero leaked canaries, zero duplicate effects, zero unbounded queue growth, and memory after cleanup within 5% of the post-warmup baseline. |

The static admission inequality is mandatory and uses configured maxima, not
observed averages:

```text
(64 detectors * 512 KiB)
+ (16 invocations * 8 sources * 256 KiB overlap)
+ (16 invocations * 1 MiB queued)
+ (4096 hot entries * 2 KiB)
+ 8 MiB fixed metadata
= 96 MiB node maximum

(16 detectors * 512 KiB)
+ (4 invocations * 8 sources * 256 KiB overlap)
+ (4 invocations * 1 MiB queued)
+ (1024 hot entries * 2 KiB)
+ 2 MiB fixed metadata
= 24 MiB tenant/node maximum
```

The representation implementation must prove a maximum-size secret with every
enabled plain/base64/base64url/percent/split/log-injection matcher fits the
512-KiB persistent cap; streaming decoders share one source overlap rather than
copying 256 KiB per detector. If that proof fails, configured cardinality is
reduced until both equations hold; coverage is never reduced silently.

Admission first reserves tenant slots/bytes, then node slots/bytes, ordered by
the authority event sequence and `SecretUseAttemptId`; a loser denies before
provider I/O. Active detector, overlap, queue, use-attempt, and cleanup state is
never evicted. Detector/overlap state releases only after terminal drain, final
scan, cleanup evidence, and key destruction. A hot terminal submission-index entry may be
evicted in deterministic `(completed_at, SecretActionSubmissionId canonical
UUID bytes)` order only after its
durable idempotency/receipt record is confirmed and remains queryable. Durable
quota/storage uncertainty denies new admission before use reservation; it never
drops old semantics or disables active detection.

The activation report records hardware, provider profile, concurrency, latency
histograms, cardinalities, memory high-water mark, detector throughput,
backpressure, drain/cleanup outcomes, and failures. Missing, skipped, simulated
outside the declared profile, or over-budget evidence keeps the feature gate off
and is not FND-012 or gold completion.

## Pre-Persistence Leak Barrier

Read-time export redaction is insufficient because it allows secret material to
enter durable trace/state bytes. C03 live mode requires a pre-persistence barrier
on every path that can carry target-controlled or provider-controlled bytes.

### Detector model

- The node generates a fresh 256-bit detector key from an operating-system CSPRNG
  for each `(tenant_id, secret_lease_id, detector_generation)`. Keys are never
  reused across a tenant, lease, generation, process restart, or node. CSPRNG
  failure denies delivery. Raw material and detector keys never leave the node
  process boundary, are page-locked where supported, have redacted `Debug`, and
  are destroyed only after the final barrier/closed ordering below.
- Detectors cover exact bytes plus policy-approved structured representations,
  bounded common encodings, chunk-boundary/split forms, and log-injection/control
  variants. Tests use synthetic canaries, never real credentials.
- Detector comparisons and token equality checks use constant-time primitives
  with respect to candidate material length after the bounded representation
  decoder selects a fixed-length candidate. No public path reports match offset,
  prefix length, candidate count, or representation-specific timing.
- `SecretLeakToken` is exactly `slt1_` followed by unpadded base64url of all 32
  bytes of `HMAC-SHA-256(detector_key, input)`. `input` is ASCII
  `splendor.secret.leak_token.v1`, one zero byte, then JCS bytes of the exact
  projection `{schema_version, tenant_id, secret_lease_id,
  detector_registration_id, detector_generation, representation}`. It contains
  no material. The per-generation key makes equal canaries unlinkable across
  tenants, leases, generations, nodes, and restarts while preserving equality
  within the one detector/representation scope. The token is not a provider
  value commitment, bearer, or offline verifier.
- The central restricted event receives only the leak token, exact
  `SecretUseAttemptId`, its one action/invocation effect coordinate, delivery
  handle/generation and source process/output coordinates, representation class,
  quarantine state, and restricted incident ref. Cleanup evidence uses the same
  use-attempt/effect/handle tuple. It cannot resolve the token to bytes, and a
  mismatched/missing tuple rejects rather than becoming uncorrelated evidence.

Streaming detection retains an overlap of `max_encoded_pattern_bytes - 1`, with
`max_encoded_pattern_bytes` capped at 256 KiB and each source record/chunk capped
at 1 MiB. It detects every split across up to 64 adjacent chunks or records and
finalizes pending decoder state only after output drain. More fragmented,
truncated, oversized, decoder-ambiguous, compressed, encrypted, or otherwise
opaque secret-exposed output is quarantined as uncovered rather than labeled
clean. The 64-chunk bound is a declared detection limit, not an allowlist.

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
be silently redacted and marked successful. C03 v1 has one disposition: quarantine
the output and process boundary, fail the action, deny new lineage claims, revoke
the affected lease, append containment evidence, and request incident handling
when that owner exists. Cleanup or incident unavailability leaves
`needs_intervention`; it never weakens containment or becomes success.

### Limits and false positives

The barrier does not claim visibility into arbitrary encrypted, compressed,
hashed, steganographic, hardware-private, or otherwise opaque payloads unless a
separate data-use policy authorizes inspection and the declared decoder succeeds.
Unknown coverage is recorded as unknown and quarantined for any output from a
secret-exposed process; it cannot be persisted/published or produce action
success.

Structured false-positive exceptions are versioned, exact schema/path rules with
owner, reason, expiry, and test evidence. An allowlist cannot contain raw values,
wildcard an entire action/workload/output object, disable scanning for secret-like
fields, or convert scanner uncertainty into success. User-provided data that
resembles a credential is quarantined or handled by an approved exact exception;
it is never copied into a global detector allowlist.

The event hash chain or access-controlled event MAC covers the exact leak token
when the token is stored in the event. A projection that cannot expose the token
stores an access-controlled commitment to the complete token and covers that
commitment instead. Token/commitment substitution, removal, or representation
change must break event integrity. Exclusion from content IDs and idempotency
digests never excludes it from event integrity.

## Trace, State, Artifact, and Replay Contract

### Event order and durability

For a successful use, internal C03 evidence and the existing outer action trace
appear in this order:

```text
secret.lease.requested
secret.lease.issued
verification.started
verification.completed
secret.use.claimed
secret.delivery.requested
secret.provider.fetch.started
secret.provider.fetch.completed
secret-aware adapter method entered; Authority sets secret_aware_adapter_entered
secret.delivery.ready
secret.delivery.activated
immediately before target call, Authority sets target_operation_started
target operation returns while adapter retains opaque driver-owned response
terminal SecretDeliveryControlAttestation accepted inside adapter invocation
gateway postcondition verification + response scan through borrowed continuation
adapter wipes raw response/error buffers and returns byte-free terminal
secret.use.completed
target termination + bounded output drain
decoder finalization + all pre-persistence/publication decisions + final seal
secret.cleanup.started
OS/projection cleanup + final detector scan
detector key destruction/deregistration
secret.delivery.closed | secret.cleanup.uncertain | secret.quarantined
gateway returns private SecretSubmitCompletion
atomic SecretDeliveryReceipt + exactly one action.executed | action.failed
sealed public ActionOutcome released
outcome.recorded
state.committed + tick.completed (tick path only)
```

A lease/verifier denial emits `secret.lease.denied` or the normal verification
denial, no use attempt, and no provider/delivery event. A use-budget/CAS loser
emits `secret.use.denied` and no provider/delivery event. After reservation,
every failure retains `secret.use.claimed`; it never refunds by omission.
`secret.use.claimed`, `secret.delivery.requested`, and
`secret.provider.fetch.started` must be durable at their declared boundaries
before provider I/O. Provider failure, cancellation, or timeout before adapter
entry uses the same cleanup/terminal-normalizer path with both entry/start facts
false. Delivery resolution, cancellation, or panic after entry uses it with
adapter entry true and target start false, and normalizes the action to `Failed`.

A required append failure before provider/driver effect prevents that effect. A
required C03 append failure after possible effect retains/quarantines cleanup
state and cannot become success. An atomic terminal receipt/action append failure
produces `terminal_evidence_blocked`, not an `ActionOutcome`, and prevents
`outcome.recorded`, state commit, direct success response, and next-tick
advancement until reconciliation. Exactly one common outer recorder emits the
one terminal `action.*` event. Provider, node, gateway session/orchestrator, and
driver code emit none. Direct submissions stop after `outcome.recorded` and do
not fabricate `state.committed` or `tick.completed`.

Provider controls use the separate order `secret.provider.control.requested` ->
final control permit -> exactly one provider call -> sanitized provider audit ->
`secret.provider.control.completed` -> authority CAS/lifecycle event. Missing
pre-effect evidence prevents the call; missing post-effect evidence leaves the
control invocation effect-uncertain and cannot update authority state to success.

Node controls use the separate order `secret.node.control.requested` -> final
node-control permit -> exactly one bound resident-node operation -> pre/post
restricted evidence plus immutable receipt -> `secret.node.control.completed` ->
Authority CAS/lifecycle event. Missing pre-effect evidence prevents node entry;
missing or ambiguous post-effect evidence quarantines the exact target/parent and
cannot advance lease, cleanup, or revocation state to success.

The exact trace-name mapping for every `SecretAccessEventKind` is:

```text
ref_registered           -> secret.ref.registered
ref_updated              -> secret.ref.updated
ref_disabled             -> secret.ref.disabled
ref_mutation_denied      -> secret.ref.mutation_denied
lease_requested          -> secret.lease.requested
lease_denied             -> secret.lease.denied
lease_issued             -> secret.lease.issued
delivery_requested       -> secret.delivery.requested
delivery_denied          -> secret.delivery.denied
provider_fetch_started   -> secret.provider.fetch.started
provider_fetch_completed -> secret.provider.fetch.completed
provider_control_requested -> secret.provider.control.requested
provider_control_completed -> secret.provider.control.completed
node_control_requested     -> secret.node.control.requested
node_control_completed     -> secret.node.control.completed
delivery_ready           -> secret.delivery.ready
delivery_activated       -> secret.delivery.activated
use_claimed              -> secret.use.claimed
use_denied               -> secret.use.denied
use_completed            -> secret.use.completed
renewed                  -> secret.lease.renewed
renewal_denied           -> secret.lease.renewal_denied
rotated                  -> secret.ref.rotated
rotation_denied          -> secret.ref.rotation_denied
revocation_requested     -> secret.revocation.requested
revocation_denied        -> secret.revocation.denied
revoked                  -> secret.revoked
revocation_uncertain     -> secret.revocation.uncertain
expired                  -> secret.lease.expired
cleanup_started          -> secret.cleanup.started
closed                   -> secret.delivery.closed
cleanup_uncertain        -> secret.cleanup.uncertain
leak_detected            -> secret.leak.detected
containment_started      -> secret.containment.started
containment_completed    -> secret.containment.completed
containment_failed       -> secret.containment.failed
quarantined              -> secret.quarantined
```

These event names and meanings are part of this proposed contract. Renaming or
reinterpreting one after acceptance requires compatibility treatment; a generic
log message is not equivalent evidence.

### Safe persistence

- Broker state persists ref/lease/lineage revisions, refresh/revocation
  generations, outer submission/terminal-intent and use-attempt ledgers, hot
  submission indexes, routing refs, handles, safe attestation records, full
  terminal receipts, pending scan-approved outcome records, safe events, and CAS
  heads only.
- Agent state may persist a `SecretRefId` requirement. It may not persist a
  lease, delivery handle, endpoint, provider mapping, detector, or material.
- Artifact/workload manifests may persist `SecretRefId` and typed use
  requirements so rotation does not rewrite immutable manifests. They may not
  persist active lease/handle IDs or provider locators.
- Generic traces carry only closed
  `splendor.secret.access_event_projection.v1` values. Canonical
  `SecretAccessEvent`, provider, detector, and incident facts use
  access-controlled evidence records.
- Secret material, direct/unkeyed value digests, provider request bytes, and
  provider material never participate in shared canonical serialization, state
  hashes, artifact IDs, idempotency digests, or public evidence digests. The
  approved keyed `SecretLeakToken` is a non-resolving detection label, not value
  material or a value commitment. It is excluded from authorizing,
  content-addressed, and idempotency digests but included directly, or through
  its protected commitment, in the event integrity chain/MAC.
- Historical 0.1 trace/state bytes are not rewritten. Existing read-time
  redaction remains for compatibility but is never cited as C03 leak prevention.

### Replay

Replay remains inspect-only by default. It reconstructs recorded ref revisions,
lease decisions, target bindings, provider outcomes, use claims, revocations,
cleanup, leak/quarantine, and effect certainty from safe records.

Replay never:

- fetches, resolves, renews, rotates, revokes, audits, or actively probes a live
  provider;
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

### Live legacy credential-ingress denial

Static migration scanning is supplemental. Every C03-adopted credential-capable
canonical `DriverOperationRef` must register a server-owned closed
`CredentialIngressProfile` before either its stable `ActionRequest` or
secret-aware registration can enter live placement. The profile binds the exact
operation/input schema and enumerates all generic coordinates that may carry
credentials: arbitrary `Action.params`, URL/userinfo/query, HTTP headers/cookies/
body, database/model/artifact connection objects, command/environment material,
nested maps/lists, and driver-equivalent payloads. It includes case/separator key
normalization, URL/connection parsing, known credential syntax/content rules,
and an exact requirement that secret-bearing modes use the typed wrapper.

Before adapter selection/execution, provider access, persistence, or any other
effect, the gateway applies the profile to both stable and wrapped submissions.
Known raw credential fields including authorization/proxy-authorization,
password/passwd, token/api-key/client-secret/private-key, cookie/set-cookie,
DSN/connection string, URL userinfo, environment credentials, their
case/separator/nested aliases, and equivalent generic payload coordinates deny
with zero adapter/provider calls. Neutral-key values matching the mandatory
content scanner also deny. A ref-like string in a generic coordinate is not a
typed requirement. Scanner/profile absence, parse ambiguity, unsupported
encoding, or profile/schema mismatch fails closed.

A non-secret exception is permitted only as an owner-versioned exact
schema-and-field-path rule with operation, value grammar, proof that the field is
not credential/provider bootstrap material, reason, expiry, and negative tests.
It cannot wildcard a body/header/environment/map, permit a credential-looking
value, or apply to authorization/cookie/userinfo/password/token/private-key/
connection coordinates. The driver maturity/C03 feature gate stays off until
every known legacy credential mode is denied or migrated; no compatibility shim
may forward raw credentials temporarily. Operations proven not credential-capable
retain their stable path but still reject fields forbidden by their own input
schema.

The future CI scanner uses schema `splendor.secret_field_scan.v1` and rejects
normalized credential-like keys and value-bearing forms in authorizing or
executable workload, action, driver, example, manifest, and gold files. At
minimum it recognizes `password`, `passwd`, `api_key`, `apikey`, `token`,
`secret`, `client_secret`, `private_key`, `credential`, `authorization`,
`cookie`, `connection_string`, and `dsn`, including case/separator variants and
nested paths.

Safe reference recognition is structural, built in, and not an exception. The
owner-schema path registry maintained by `SECR-006` lists every exact owner
schema/version/path allowed to embed a complete C03 ref or use-requirement
subrecord. A
field named `secret_ref_id` is safe only when a schema-valid closed C03 record
or registry-listed exact embedded C03 subrecord requires a canonical
`SecretRefId` at that exact path. A
`secret_requirements` list is safe only as the exact field in
`splendor.gateway.action_request_with_secrets.v1`, and every element must be an
exact `splendor.secret.use_requirement.v1` object with no unknown fields. The
same names in `Action.params`, policy/percept/message payloads, arbitrary JSON,
unknown schemas, unregistered manifest paths, metadata, extensions, provider
output, or a wrapper that merely copies the schema string are not recognized and
fail closed. A safe
reference record containing a value, bytes, locator, environment name, provider
request, or unknown field also fails.

Scanner exceptions require exact schema, exact field path, owner, reason,
expiry, and scanner version. They are allowed only for closed app-caller
authentication or trust-bootstrap schemas, synthetic detector fixtures, or the
exact adopted-operation non-secret ingress rule above. That last rule may name
one exact executable schema/path only when its bounded value grammar cannot carry
credential material; mandatory content scanning still runs. It cannot apply to
authorization/cookie/userinfo/password/token/private-key/connection coordinates,
wildcard `Action.params`/body/environment/maps, policy/percept/message payloads,
workload secret requirements, provider output, external examples, or gold
inputs. A skipped/unavailable scanner is not passing evidence.

CI also runs a repository-content scanner over tracked source, fixtures,
generated outputs, docs examples, archives, and manifests. It detects known
credential formats, PEM/private-key blocks, high-entropy token candidates,
provider key prefixes, and encoded private material even under neutral field
names. Its only content allowlist is an exact path plus digest for documented
synthetic canaries or public test vectors; entries have owner, reason, expiry,
scanner version, and regeneration test. A changed digest, expired entry, skipped
scan, unavailable engine/rules, unreadable archive, or generated-file omission is
failure. Schema and content scanners are both mandatory; neither substitutes for
the other.

`SECR-006` owns the future repository implementation path
`scripts/security/check-secret-contracts.py`, its owner-schema path registry,
synthetic allowlist registry, and CI invocation. Until that tracked command and
its fail-closed fixtures exist, V4 and live C03 adoption remain incomplete; a
developer-local or external scanner is not substitute evidence.

A driver cannot enter V4 adoption or live C03 placement until its manifest
declares whether target code sees material, which delivery mechanisms it
supports, child-inheritance/debug/capture policy, cleanup guarantees, offline
support, effect/idempotency class, and relevant conformance evidence. Examples
use synthetic canaries and local deterministic providers; no example depends on
a real cloud credential.

## Compatibility, Migration, and Rollout

C03 v1 is experimental 0.2/v2 surface, not a new stable 0.1 primitive. It is
additive alongside stable 0.1 IDs and records and preserves all existing
identity, work-order, gateway authority, state graph, and replay rules. It does
not change the stable public `ActionStatus` enum. Its versioned secret-aware
wrapper explicitly normalizes postcondition/cleanup results to one terminal
action event rather than inheriting the current non-secret double-terminal
postcondition trace; the non-secret path is unchanged.

| Facet | Compatibility rule |
| --- | --- |
| Stable `ActionRequest` | Wire shape/hash unchanged. Secret-aware calls use the versioned wrapper and normalize into the same gateway. An adopted credential-capable operation also applies its server-owned ingress denial profile to stable submissions before adapter execution. |
| Action params | Raw credential-bearing params, headers, bodies, URLs, cookies, connection objects, environment material, and equivalent generic payloads deny before adapter/provider execution for every adopted operation. Typed requirements are the only C03 path; exact non-secret exceptions are narrow, versioned, expiring owner rules. |
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
Gateway/orchestrator, node/executor, provider bootstrap/transport,
event/evidence, pre-persistence barrier, schema/content scanner, every required
foreign nominal-ID owner, and FND-012 budget evidence. Mixed-version nodes that
cannot understand the exact contract deny secret-bearing placement. The
environment delivery value remains denied independently of this gate.

Rollback first stops new issuance, then revokes/closes or quarantines every
active handle, persists terminal evidence, and only then disables provider/node
components. Downgrade must not leave a live handle that the older runtime cannot
revoke or explain. Historical records remain readable as opaque non-authorizing
evidence.

## Failure Taxonomy and Threat Model

`SecretErrorCode` is closed in v1:

```text
invalid_schema_version
unsupported_api_version
malformed_request
secret_action_profile_unavailable
secret_action_receipt_unavailable
secret_action_idempotency_conflict
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
wrong_credential_slot
credential_destination_mismatch
credential_destination_unauthorized
wrong_purpose
wrong_intent
raw_credential_input_denied
delivery_method_not_allowed
environment_exposure_contract_unaccepted
delivery_control_unsupported
delivery_control_failed
exposure_lineage_active
exposure_lineage_exhausted
exposure_aggregate_widening_denied
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
provider_bootstrap_invalid
provider_bootstrap_source_mismatch
provider_transport_untrusted
provider_effect_uncertain
node_control_unavailable
node_control_effect_uncertain
target_effect_uncertain
stale_refresh_generation
detector_capacity_exhausted
cleanup_uncertain
leak_detected
scan_unavailable
output_coverage_unknown
replay_forbidden
clock_unavailable
clock_rollback
clock_skew_exceeded
concurrent_update
evidence_unavailable
terminal_evidence_blocked
internal_invariant_violation
```

Public callers receive only visibility-safe codes such as
`secret_not_available`, `provider_unavailable`, `cleanup_uncertain`, or a
generic denied/needs-intervention result. Restricted evidence may retain the
exact internal code. Errors use the existing `ErrorCategory`, `RetryClass`, and
`EffectCertainty` contracts; they never include raw provider text.

| Error family | `ErrorCategory` | Retry and split-certainty rule |
| --- | --- | --- |
| Malformed/unknown version/slot/destination/delivery mismatch before outer acceptance | `invalid_input`, `incompatible_schema`, or `unauthorized` | `not_retryable`; no submission or effect exists. |
| Exact outer duplicate | Original category | Return/refer to the original submission/receipt and all original certainty dimensions; never create another effect. |
| Outer key/action reuse with changed bytes | `conflict` | `not_retryable`; the conflicting observation has no effect and cannot alter/disclose the original beyond the visibility-safe profile. |
| Missing/corrupt terminal receipt or intent | `uncertain` | `not_retryable`; outer certainty `uncertain`, same-submission lookup/reconciliation only. |
| Expired or revoked authority/work-order/data-use/lease | `expired` or `revoked` | `retry_with_new_authorization` only for a new request/attempt, `none` |
| Stale ref/placement/fencing/refresh/concurrent CAS | `stale_head` or `conflict` | exact same-ID retry returns the first denial; changed expected values require a fresh command ID, and any reserved/crossed use requires a fresh use-attempt ID; only the proved prepared/unreserved exception may retain the use-attempt ID, `none` |
| Aggregate exhausted or attempted widening | `quota_exceeded` or `conflict` | `not_retryable`; preserves parent counters/start/deadline, provider/node/target `none`. |
| Explicit provider unavailable with every send proved absent | `unavailable` | bounded same-invocation retry if policy permits; provider/target `none`, outer is the conservative node/cleanup maximum. |
| Provider request sent with definitive failure | Exact mapped `unavailable`, `driver_failure`, `timeout`, `revoked`, `integrity_failure`, `quota_exceeded`, or `incompatible_schema` | No automatic outer resubmit; provider `known`, target `none`, outer at least `known`. |
| Provider send/result uncertainty | `uncertain` | `not_retryable`; provider and outer `uncertain`, target `none` when adapter was not entered. |
| Node-control uncertainty | `uncertain` | same-target authorized reconciliation only; provider unchanged, node/outer `uncertain`, target follows its independent start facts, parent quarantined. |
| Adapter delivery failure before target start | `unavailable` or `internal_invariant_violation` | Final action `Failed`; target `none`; outer is the conservative provider/node/target/cleanup maximum. |
| Target definitive failure | Exact mapped `driver_failure`, `timeout`, `cancellation`, `postcondition_failure`, `unsafe`, or `integrity_failure` | Final action `Failed`; target `known`, outer at least `known`; no blind outer resubmit. |
| Target send/result uncertainty | `uncertain` | Final action `Failed`, `not_retryable`; target and outer `uncertain`. |
| Leak or post-target scanner denial | `protected_data_denial` or `unavailable` | `not_retryable` until containment/new evidence; preserve provider/node/target dimensions and derive outer conservatively, never reset to `none`. |
| Cleanup uncertainty | `uncertain` | explicit same-target containment/reconciliation only, `uncertain` |
| Evidence/clock/internal invariant unavailable | `unavailable`, `uncertain`, or `internal_invariant_violation` | fail closed; never implicit allow |

| Threat or failure | Required behavior |
| --- | --- |
| Wrong tenant or hidden ref guess | Uniform `secret_not_available`; no existence, provider, name, version, or timing oracle. |
| Wrong principal/agent/run/workload/attempt | Deny before lease issuance or provider I/O. |
| Wrong node/instance/sandbox/process/audience | Deny and invalidate any mismatched handle; no locator is returned. |
| Wrong driver operation/purpose/intent | Deny; no wildcard or provider-specific reinterpretation. |
| Wrong/reordered credential slot or wrong origin/service/account/cluster/database/device/artifact/model destination | Deny before lease, provider, node, or adapter work; request order never selects a slot and caller bytes never select the trusted destination. |
| Missing/stale/revoked authority or data-use | Deny or intervention; no cached high-risk allow. |
| Missing/expired/revoked work order | Deny run-bound issuance/use before provider I/O. |
| Missing/stale placement or fencing | Deny; old attempts/nodes cannot reuse a lease. |
| Raw credential in an adopted legacy/generic payload | Deny at live ingress with zero provider/adapter calls and no compatibility fallback. |
| Dropped direct/tick response or exact duplicate observation | Resolve the existing outer submission and original use-attempt/terminal pair; no second reservation, provider/node/adapter/target call, or terminal event. |
| Same outer key or action/invocation with changed bytes/key | Conflict without mutating or repeating the original effect. |
| Provider outage/circuit open | Deny or bounded same-trust failover only under the rules above. |
| Provider response uncertain | Record uncertainty; no blind retry/failover and no adapter execution. |
| Provider request sent with definitive failure | Record provider `known`, target `none`, and outer at least `known`; never report `none`. |
| Network bootstrap default chain, wrong file/keychain/workload identity, or route mismatch | Fail route startup/probe closed; no ambient fallback, provider send, or cross-route identity use. |
| Provider renew/revoke/audit/active health requested outside gateway control | Reject; direct provider invocation count remains zero. |
| Node fence/terminate/close/unmount/delete/attest/revocation acknowledgement outside node-control gateway profile | Reject; direct node/OS/orchestrator mutation count remains zero. |
| Lease not active/expired/revoked/max-use | Atomic deny before exposure/effect. |
| Unknown/closed handle | Uniform deny; never attempt provider lookup from handle metadata. |
| Cleanup uncertain | Quarantine target, deny new leases, record restricted incident-worthy evidence. |
| Leak match or scanner unavailable | Fail/quarantine/revoke by closed policy; never silently redact to success. |
| Replay requests live resolution | Reject as `replay_forbidden`; adapter/provider invocation count remains zero. |
| Clock rollback/skew/unavailable | Deny issuance, renewal, and use; do not extend expiry. |
| Trace/event/evidence unavailable | Fail closed before provider/effect; after possible effect, report uncertainty and quarantine cleanup. |
| Terminal receipt/action append unavailable | Release no `ActionOutcome`; block direct response/tick/state advancement and reconcile without provider/driver replay. |
| Delivery method switch on the same parent key | Preserve aggregate use/deadline/taint and one-target exclusion; a method child may narrow but cannot reset or overlap. |

### End-to-end lifecycle/failure matrix

This matrix is normative for both direct and tick submission and prevents a
failure handler from inventing a different status or bypass path:

| Path | Provider / node certainty | Adapter entries / target starts | Stable outer result | Mandatory terminal behavior |
| --- | --- | --- | --- | --- |
| Allowed | `known / known` | 1 / 1 | `Executed`; target/outer `known` | All reservations precede every fetch; postconditions allow, projections seal, cleanup is known, and one receipt/action event precedes the path suffix. |
| Authentication/closed-schema/raw-ingress/owner-compatibility failure before outer acceptance | `none / none` | 0 / 0 | No C03 `ActionOutcome`; visibility-safe transport error | No submission, receipt, action event, provider/node/adapter/target call, or persistence of rejected raw bytes. |
| Accepted authority/verifier denial before reservation | `none / none` | 0 / 0 | `Denied`, or `NeedsApproval` for approval only; target/outer `none` | Empty use-attempt batch and one matching terminal pair; no provider/delivery event. |
| Accepted verifier/runtime unavailability before reservation | `none / none` | 0 / 0 | `NeedsIntervention`; target/outer `none` | Empty use-attempt batch and one matching terminal pair; fail closed with no provider/node/adapter/target work. |
| Use-budget/CAS/resource loser | `none / none` | 0 / 0 | `Denied`; target/outer `none` | `use_denied` names the claim, the receipt batch is empty, and no provider/material/node-target/adapter call occurs. |
| Provider failure with every send proved absent after target preparation | `none / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer is node/cleanup maximum | Reservations stay consumed; bounded same-invocation provider retry only when permitted, then cleanup and one terminal pair. |
| Provider request sent with a definitive failure, or an earlier batch fetch sent successfully | `known / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative and never `none` | Skip later fetches and adapter entry, sanitize audit facts, clean staging, and do not report effect `none`. |
| Provider send/result uncertainty | `uncertain / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer `uncertain` | No retry/failover/later fetch/adapter call; quarantine/reconcile, with one terminal pair only if terminal evidence commits. |
| Allocation/node-control failure before provider or adapter entry | `none / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative | Consume committed reservations, clean/quarantine exact target state, and never call provider or enter the adapter. |
| Delivery resolution failure or panic after adapter entry but before target start | `known / known` | 1 / 0 | `Failed`; target `none`, outer conservative | Adapter entry is execution under stable semantics; cleanup runs and one failed terminal pair commits. |
| Target returns definitive failure | `known / known` | 1 / 1 | `Failed`; target/outer `known` | Accept terminal control attestation, scan/seal safe error/evidence, cleanup, and one failed terminal pair. |
| Target result is ambiguous | `known|uncertain / known|uncertain` | 1 / 1 | `Failed`; target/outer `uncertain` | No automatic retry; drain, quarantine/reconcile, clean, and commit one failed pair when evidence permits. |
| Postcondition denied/uncertain | Each from durable receipts | 1 / 1 | `Failed`; target `known|uncertain`, outer conservative | No `action.executed`; seal failure evidence, cleanup, and one failed terminal pair. |
| Scan/seal/output-coverage failure after target return | Each from durable receipts | 1 / 1 | `Failed`; target `known|uncertain`, outer conservative | Quarantine unpublishable bytes/process, retain detector through cleanup, and commit one failed pair; never release partially scanned output. |
| Cancellation/timeout before adapter entry | Each from durable send facts | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative | Stop acquisition/delivery, consume reservations, cleanup/quarantine, and commit one terminal pair. |
| Cancellation/timeout after entry but before target start | Each from durable send facts | 1 / 0 | `Failed`; target `none`, outer conservative | Entry fact forbids `NeedsIntervention`; cleanup/quarantine and one failed terminal pair. |
| Cancellation/timeout after target start | Each from durable send facts | 1 / 1 | `Failed`; target/outer `known|uncertain` | Drain within bounds, scan/seal, cleanup/quarantine, one failed terminal pair, and no blind retry. |
| Provider/node/adapter unwind or panic | Each from durable send facts | Exactly from durable entry/start facts | `NeedsIntervention` only at 0 adapter entries; otherwise `Failed` | Gateway guard owns cleanup. Missing facts are treated as crossed/uncertain; panic-abort/process death uses supervisor reconciliation and cannot emit success. |
| Cleanup/drop/wipe failure | Each from durable send facts | Exactly from durable entry/start facts | `NeedsIntervention` at 0 entries; otherwise `Failed`; outer `uncertain` | Retain detector/fence where possible, emit cleanup uncertainty/quarantine, and commit one non-success pair. |
| Terminal receipt/action append failure | Preserve all dimensions | Preserve both facts | No public `ActionOutcome`; outer `uncertain` | Keep the immutable terminal intent and `terminal_evidence_blocked`; no outcome/state/direct success/next tick until one-pair reconciliation, with no repeated effect. |
| Revocation acknowledgement uncertainty | Independent provider/control facts | In-flight action preserves its entry/start facts | Control `effect_uncertain`; action status follows adapter-entry fact | Keep `revocation_pending`, emit `revocation_uncertain`, quarantine, and use a fresh authorized same-target control invocation for reconciliation. |

## Validation and Acceptance Plan

Contract acceptance and implementation evidence are separate gates.

### V0 - RFC and catalog integrity

- Independent architecture, security, contract, and compatibility review accepts
  this RFC without changing task or gold status.
- Documentation links, catalog parsing, architecture policy, whitespace, and
  status scans pass.
- V0 authorizes implementation planning only. It closes no SECR task.

### V1 - Behavior-free contracts in dependency order

V1a is C03-owned pre-placement grammar only:

- Add C03-owned ref, requirement, provider, detector, event, command, outer
  submission/idempotency/receipt, exposure-lineage, bootstrap-binding, and node-
  control IDs plus closed enums, `SecretRef`, `SecretLeasePolicy`, and
  `SecretUseRequirement` with `deny_unknown_fields`.
- Do not add `WorkloadAttemptId`, `PlacementDecisionId`, `ExecutionLeaseId`,
  `SandboxId`, `ProcessBoundaryId`, `InvocationId`, `DataUseGrantId`, `EvidenceId`,
  `DriverOperationRef`, deployment ID, or incident ID. C03 cannot expose a lease,
  execution binding, delivery, or command variant that requires one of those
  foreign types during V1a.

V1b starts only after FND/fabric, NODE, SBX, DGW, DUC, Event/Evidence,
change, and incident owners land and accept the exact nominal IDs needed by each
type. It then adds `SecretExecutionBinding`, `SecretAuthorityBinding`, lease
request/lease, delivery handle/control attestation/full terminal receipt/hot
index/evidence ref, versioned direct/tick submission and response records,
provider and node control plan/result/receipt, closed command target variants,
and tagged access-event subjects. Compile-time fixtures prove every foreign ID,
including `SecretCredentialSlotId`, `ManagementEventId`, and `EvidenceId`, is
non-interchangeable and imported from its owner rather than minted by C03.

Both phases require positive round trips and negative fixtures proving no
value/bytes/locator/raw-error field can enter C03 records. Rust/Python/TypeScript
goldens pin fixed-six-digit timestamps, ASCII rejection, every set permutation,
meaningful preference/causal order changes, UUIDv5 audience bytes, semantic
idempotency bytes, wrapper/outer direct/tick digest bytes, leak-token generation/
key separation, and token-integrity tampering. The 16-requirement maximum fixture
separately pins the <=2-KiB hot index and complete larger durable receipt,
summary/event order, uniqueness, and cardinality. Every event kind has the
positive/negative validator fixtures required
by its matrix. Cross-language fixtures use the exact nested
`DriverOperationRef` object and reject display/stringified/side-field forms in
declarations, manifests, authorization, dispatch, and evidence. Stable 0.1
`ActionRequest` bytes/hashes remain unchanged. Gold
remains `not_exercised`.

### V2 - Authority lifecycle and deterministic providers

- Implement one authority-owned state machine, validated wrappers, CAS,
  closed command grammar, semantic idempotency, authorized lookup ordering,
  outer submission/terminal-intent ledger and reconciler, parent exposure
  aggregates with method children, atomic lease/aggregate use claims, expiry,
  same-attempt renewal, rotation/revocation, use-attempt ledger, refresh CAS,
  deterministic target generations, process taint, and matrix-valid event construction.
- Add deterministic memory and explicit local-development providers behind the
  outbound port; prove they cannot initialize or advertise in resident/remote/
  production mode. Cover safe-root owner/mode/no-follow/regular-file and
  symlink/FIFO/device/out-of-root denial, outage, wrong version, cross-tenant
  guesses, circuit, retry, no-cache rules, and positive/negative fixtures for
  every tagged bootstrap profile. Network workload-identity, owner-file, and OS-
  keychain source fixtures prove exact route binding, refresh ownership,
  descriptor/mode proof, application/access-group/service/user/session/persistent-
  reference binding, and disabled SDK default chains. Cross-tag fields, local
  network attempts, wrong source binding, keychain enumeration/prompt/broad-scope
  use, ambient lookup, and empty network trust fields reject startup or the
  gateway control probe.
- Idempotency/CAS tests cover same semantic retry at a later authority time,
  changed semantic bytes, stale revision with zero mutation, current-authority
  revalidation before disclosure, uniform hidden/conflict/not-found responses,
  zero trusted-wrapper reconstruction, crash points, concurrent final use, and
  many distinct request IDs racing one exposure lineage without resetting use or
  continuous lifetime. Parent-aggregate tests cover concurrent first leases with
  different ceilings, exact preserve, later narrowing, widening denial, narrowing
  below partial consumption, renewal, new attempt, method switch, rotation/new ref
  revision, and new owner-issued workload. Stale refresh tests prove same command
  ID conflicts after
  changed generation, reserved attempts require fresh use-attempt IDs, and the
  exact prepared/unreserved exception alone may preserve one.
- This is bounded local evidence until the real gateway/node path exists. It
  does not pass `G07` or `G08` by itself.

### V3 - Gateway, node delivery, and leak barrier

- Requires real `NODE-003`/sandbox/process/fencing owners and `FND-009`-aligned
  pre-persistence integration.
- Atomically update the dependency guard with the exact secret-provider exception
  and fixtures rejecting every broader provider/ordinary-adapter edge.
- A production-path integration test proves durable outer submission claim ->
  final verification -> use reservation -> target/control allocation -> durable
  pre-provider evidence
  -> borrowed permit -> provider -> driver-local `resolve_and_deliver` -> exactly
  one target driver invoke -> terminal control attestation -> gateway-owned
  postcondition over opaque driver-owned response -> scan output/error/
  postcondition into private candidates -> raw-buffer wipe -> delayed-source drain/decoder
  finalization/final seal -> cleanup -> common terminal normalizer ->
  final outcome. Multi-requirement tests prove all reservations precede the first
  provider call and a provider failure skips later fetches/driver execution. With
  `max_uses=1`, racing attempts on one lineage produce exactly one claim,
  provider call, material instance, delivery, and driver call.
- Direct and tick dropped-response/duplicate tests cover pre-reservation denial,
  reservation, provider send, adapter entry, target start, cleanup, and terminal-
  append boundaries. Same key/body/scope resolves one submission, one fixed use-
  attempt batch, one effect, and one terminal pair; changed bytes/key or changed
  action/invocation coordinate conflicts. Reconciliation appends only retained
  terminal-intent bytes and never re-enters provider/node/adapter/target.
- A compile/prototype test proves session typestates and `!Send + !Sync`
  context/attestation/view/seal lifetimes cannot serialize, clone, escape to
  unrelated tasks, or enter `'static` storage. Panic, cancellation, timeout, and
  forgotten-context tests prove the gateway owner still cleans/quarantines.
- Trap providers prove daemon, SDK, policy, replay, authority, incident, health,
  node, direct adapter setup, and non-secret calls cannot invoke provider methods.
  Renew/revoke/audit/active-probe tests each traverse the gateway control profile
  once with authorization, deadlines, bounded retry, pre/post evidence, no target
  adapter, and no recursive invocation.
- Trap node bridges prove Authority, daemon, incident, replay, expiry, shutdown,
  reconciler, and background paths cannot mutate resident node/OS/orchestrator
  state directly. Every prepare/activate/fence/terminate/close/unmount/delete/
  attest/revocation acknowledgement crosses one typed node-control permit and
  receipt; timeout/ambiguous acknowledgement quarantines without alternate-node
  failover or false success.
- Exact trace/order tests cover success, adapter failure, cancellation,
  postcondition failure, terminal append failure, cleanup uncertainty, and
  quarantine for both tick and direct submission. Every released outcome has
  exactly one matching terminal receipt and one outer `action.*` terminal event;
  direct paths invent no tick/state events; terminal-evidence blockage releases
  no outcome or state advancement. Tests count
  `SecretAwareActionAdapter` method entry separately from target-operation start
  for delivery failure, panic/cancellation before target start, target failure,
  postcondition/scan/cleanup failure, and success. Every post-entry non-success is
  `Failed`; `Denied`/`NeedsApproval`/`NeedsIntervention` prove zero adapter entries
  and zero target starts.
- Provider fixtures prove no-send=`none`, sent-definitive=`known`, and ambiguous=
  `uncertain` independently from node-control receipt and target certainty; the
  outer receipt takes the conservative maximum across all three and never
  retries/fails over after uncertainty.
- Test FD, tmpfs, socket, and provider-native node-local projection plus mandatory
  control evidence, unsupported/failed control denial, explicit environment
  denial, wrong boundary, process crash, cancellation, expiry, node quarantine,
  revocation races, and atomic last use. An intentionally retaining process proves
  same-process renewal/rotation denies and a separately fenced fresh process is
  required. Switching methods preserves one parent counter/deadline/taint and
  cannot overlap target generations. Wrong/missing/reordered slot and wrong exact
  origin/service/account/cluster/database/device/artifact/model destination deny
  before provider I/O. Orchestrator API/etcd/audit/manifest captures contain no
  canary.
- Use synthetic canaries to test plain, common encoded, split/chunked, and
  log-injection forms at every declared chunk boundary across params, prompts,
  delayed stdout/stderr after exit, state, trace, artifacts, errors, debug
  bundles, and observability before persistence. Scanner outage, oversized/
  opaque output, drain timeout, and detector teardown races quarantine with no
  success. Token tampering breaks integrity.
- Execute exact `G08` and `G82` fixtures before claiming those results.

### V4 - External contracts and owner adoption

- Generate/check Rust, OpenAPI, TypeScript, and Python parity for each exposed
  profile; prove SDK helpers cannot read material. The tagged tick candidate,
  `POST /v2/secret-actions`, authenticated submission lookup, unchanged nested
  `ActionOutcome`, complete terminal receipt, unsupported-version behavior, and
  direct/tick canonical golden bytes must match exactly across all four surfaces.
- Enable both the structural schema scanner and repository content/entropy/
  private-key scanner at `scripts/security/check-secret-contracts.py` in CI.
  Positive fixtures cover exact typed ref/requirement shapes at registered owner
  paths in Rust/OpenAPI/TypeScript/Python/manifests. Negative fixtures cover
  aliases, case/separator variants, nested value keys, `Action.params`, unknown
  and fake-schema wrappers, neutral-key PEM/token/base64, changed/expired
  synthetic allowlists, and scanner unavailability.
- Every adopted credential-capable operation installs its live ingress profile.
  Stable HTTP/database/model/artifact/shell payload tests cover direct,
  case/separator, nested, URL-userinfo, authorization/cookie, connection,
  environment, and neutral-key credential forms and prove denial before any
  provider/adapter/persistence call. Exact non-secret exception fixtures prove no
  wildcard or credential-shaped value is admitted.
- Production provider-boundary tests cover least-privilege tenant/namespace/
  account/audience bootstrap, shared/broad identity rejection, rotation/
  revocation, origin allowlisting, proxy/redirect refusal, DNS rebinding,
  loopback/link-local/metadata denial, wrong certificate/hostname/CA, response
  bounds, SDK diagnostic redaction, and zero fallback after uncertainty.
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
- Revocation uncertainty retains `revocation_pending`, emits only
  `secret.revocation.uncertain`, stays quarantined, and recovers through a new
  authorized gateway control invocation before any `secret.revoked` fact.
- The exact cross-tenant 404/body/256-byte/timing/statistical criterion passes,
  with zero provider/node calls and tenant-keyed correlation. Every FND-012
  latency, cardinality, timeout/retry, detector throughput/memory/backpressure,
  output-drain, cleanup, and 24-hour soak budget passes on the activation
  composition. Worst-case 64-KiB material with every enabled representation at
  64 detectors and 16 concurrent invocations satisfies the 96-MiB node and
  24-MiB tenant equations; overflow admission deterministically denies before
  provider I/O and never evicts active detector state. Missing evidence keeps
  `secret_broker_v1` off.
- The 16-requirement maximum receipt/event fixture remains queryable after hot-
  index eviction, while every hot command/use-attempt/submission-index record is
  <=2 KiB. Dropped responses and duplicate observations throughout the 24-hour
  soak produce zero duplicate reservations, provider/node/adapter/target effects,
  receipts, or terminal events.
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

1. V1a C03-owned pre-placement IDs, refs, use requirements, canonical fixtures,
   and scanner grammar only.
2. Land accepted owner-defined nominal IDs and canonical contracts from
   FND/fabric, NODE, SBX, DGW, DUC, Event/Evidence, change, and incident work.
   This includes `ManagementEventId` and the NODE-003/SBX-001 target/permit/
   result/evidence ABI. C03 does not add substitutes.
3. V1b bound execution/authority/lease/delivery/event/command contracts and
   cross-language matrix fixtures.
4. Authority-owned lifecycle, durable outer submission/terminal-intent ledger and
   reconciler, stable parent exposure aggregates/method children/target
   generations, use-attempt/idempotency/CAS behavior, validated wrappers, and
   outbound provider port.
5. Gateway provider-control profile plus tagged deterministic/dev-local providers
   with mode/file/keychain safety and the atomic narrow dependency specialization.
6. Same-gateway wrapper, secret-lease and live credential-ingress verifiers,
   staged session, borrowed permit, driver-local delivery ABI, postcondition
   continuation, terminal normalizer, and direct/tick recorder integration.
7. Only after real NODE/SBX/FND-009 owners land: delivery/control evidence,
   pre-persistence detector and output drain, production provider bootstrap/
   transport, external drivers/examples, FND-012 activation evidence, and gold.

Known prerequisite boundaries remain explicit:

- C01/C02 and `FND-001`, `FND-005`, and `FND-009` have useful local seams but
  are not catalog-wide completion evidence.
- Accepted compatible `NODE-003` #302 and `SBX-001` #400 contracts are required
  before node-control/delivery implementation; their production evidence is
  required before live activation.
- FND/fabric/DGW owners must supply `WorkloadAttemptId`,
  `PlacementDecisionId`, `ExecutionLeaseId`, `InvocationId`, and
  `DriverOperationRef`; Event/Evidence must supply `EvidenceId` and nominal
  `ManagementEventId` plus management ordering/integrity/visibility; NODE/SBX must
  supply `SandboxId` and `ProcessBoundaryId`; DUC must supply `DataUseGrantId`;
  change/incident owners supply their revocation-target IDs. C03 cannot expose
  dependent variants first.
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
- No live v1 environment-variable delivery before its separate accepted
  amendment, automatic compatibility fallback, production default master key,
  or real-cloud dependency in examples.
- No arbitrary user-code handle resolution outside the exact process boundary.
- No promise of perfect erasure from process/container memory, provider SDKs,
  kernels, hypervisors, hardware, copied encrypted payloads, or untrusted code.
- No full `NODE-*`, `SBX-*`, Data-Use, Artifact, Event/Evidence, Observability,
  Incident, Driver, Model, Fleet, or physical implementation in this RFC.
- No stable 0.1 primitive replacement, existing hash rewrite, trace/state
  migration, public `ActionStatus` change, issue closure, component completion,
  or gold pass claim.

## Acceptance Checklist

Independent reviewers should recommend acceptance only if all are true:

- The status remains proposed until the repository's acceptance process records
  an accepted date and decision.
- Public records are closed, versioned, byte-free, locator-free, and
  non-authorizing.
- IDs, target binding, authority binding, audience, purpose, intent, duration,
  uses, placement, fencing, and revocation are explicit and distinct.
- Direct and tick ingress use only the additive versioned candidate/endpoint and
  response/lookup schemas. Stable `Action`, `ActionRequest`, `ActionOutcome`,
  `ActionStatus`, `/actions`, and plain candidate bytes/meanings remain unchanged,
  and missing terminal receipt always means non-retryable uncertainty.
- Authority claims one durable outer submission before C03 terminal evidence,
  reservation, provider/node work, or adapter entry. Exact duplicates resolve its
  fixed batch/result; changed bytes/key/action conflict; pre-reservation denial
  has an empty batch; terminal append recovery never replays an effect.
- `SecretProvider` is an authority-owned Rust outbound port, not a serialized
  type or provider SDK in core; only the exact secret-provider dependency
  specialization is proposed.
- The one staged gateway session atomically reserves and durably records every
  requirement-specific use, allocates their attempt-bound target/fence/control
  sets, and only then fetches/delivers through a
  non-serializable driver-local context and exactly one driver invoke.
- Raw driver response/error data remains opaque and driver-owned while the
  gateway runs postconditions; output/error/postcondition projections are scanned
  before raw-buffer wipe, then the complete drained publication set is finally
  sealed before delivery/detector cleanup and public release. Cancellation,
  timeout, panic, process death, and cleanup failure enter the same fail-closed
  session path.
- Stable outcome meanings are preserved. Tick and direct actions use one
  terminal normalizer; every released terminal outcome has exactly one matching
  immutable receipt and outer action event, while terminal-evidence blockage
  releases no outcome/state advancement.
- `NeedsIntervention` proves zero `SecretAwareActionAdapter` entries. Adapter
  method entry and target-operation start are separate durable facts; every non-
  success after entry is `Failed`, including delivery resolution before target
  start and postcondition/scan/cleanup/terminal uncertainty.
- Provider, node, and target certainty are separate receipt fields. A boundary is
  `none` only with proof that it was not sent/started and no effect was possible;
  sent/started with a definitive result is at least `known`, and ambiguity is
  `uncertain`. Receipt outer certainty is their conservative maximum including
  delivery/cleanup uncertainty. Missing terminal evidence releases no receipt
  and reports submission uncertainty instead.
- The delivery-control handoff is a typed immutable attestation with exact typed
  evidence refs and no promised final status; the separate terminal receipt is
  bound to the final outer action status and exact action/invocation/use attempts.
- Authority commands, semantic idempotency, CAS/use transactions, parent exposure
  aggregates/method children/target generations, stale-refresh rule, tagged event
  subjects, event
  field matrix, canonical sets/order, nested `DriverOperationRef`, audience
  derivation, and leak tokens are closed and fixture-generatable.
- Exposure lineage excludes retry/process/invocation/audience/fence/connection
  and delivery-method coordinates. Every method child shares one parent counter,
  deadline, taint/quarantine, and target exclusion. Initial use/deadline ceilings
  are exact minima of ref, first approved requirement/request, authority/work-
  order, provider, and target constraints; later CAS may preserve/narrow but
  never widen, extend, reset consumed use/start, or overlap a target.
- Every secret is bound by nominal driver-owned credential slot and server-
  derived exact destination schema/digest through ref authority, requirement,
  lease, claim, permit, context/handle, evidence/receipt, and parent aggregate.
  Multi-secret lookup never uses list position.
- Provider renew/revoke/audit/active probes are typed gateway-mediated control
  effects with authorization, deadlines, bounded retry, non-recursion, receipts,
  trace/audit, and explicit revocation-uncertain recovery. Passive inspection is
  side-effect-free registration metadata only.
- Provider control uses closed run-trace or owner-defined management-event
  causality and tenant-only provider trust scope in v1; no fake run/tenant/shared
  trust label is accepted. Non-run controls stay disabled until the management
  event owner contract exists.
- Resident-node prepare/activate/fence/terminate/close/unmount/delete/attest/
  revocation acknowledgement uses the separate typed gateway node-control ABI.
  Direct node mutation is forbidden, uncertain acknowledgement quarantines, and
  every live node gate remains disabled until accepted NODE-003/SBX-001 and
  Event/Evidence owner contracts exist.
- Delivery, cleanup, renewal, rotation, revocation, offline, HA, leak, replay,
  compatibility, and threat behavior is fail closed and testable.
- Process taint, delivery-control evidence, detector/output-drain lifetime,
  route-bound workload-identity/owner-file/keychain bootstrap profiles with SDK
  default chains disabled, tagged local profiles, dev/keychain restrictions,
  uniform privacy responses, and the arithmetic FND-012 detector/invocation/
  idempotency ledger are explicit; admission cannot evict active detection.
- The <=2-KiB hot submission index contains only lookup/state/digest/terminal
  pointers; full immutable terminal intents/receipts use quota-controlled durable
  storage. Summary and event order/uniqueness/cardinality are fixed and covered by
  the 16-requirement maximum fixture.
- Current read-time redaction is explicitly insufficient for live C03.
- External SDK/scanner rules distinguish caller/bootstrap credentials from
  workload secrets and never expose material. Every adopted credential-capable
  operation rejects raw credential-bearing generic params/headers/bodies/URLs/
  environment material before adapter/provider execution, with only exact
  owner-versioned non-secret exceptions.
- V0-V5 and issue/gold closure rules prevent docs or bounded local tests from
  becoming false completion evidence.
- Deferred owner boundaries and non-goals remain explicit.
