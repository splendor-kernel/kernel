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
| `SECR-002` / #246 | Node-local delivery and cleanup | Contract target; blocked on `NODE-003`, `SBX-001`, and `SBX-007` for every material-exposed target. |
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
exposure aggregates, use attempts, secret-action submission and approval-
continuation records, provider-control invocation records, containment reserves,
and non-observation consumed-effect tombstones. It coordinates node-control
invocation state only through the accepted NODE/SBX owner contract and never
shadows that owner's node state or result ABI. The gateway owns the live effect
session but advances those records only through a
narrow authority command/CAS port. Gateway typestates, daemon handlers, stores,
providers, nodes, adapters, and reconcilers never write Authority tables
directly. An authority-owned `SecretActionReconciler` is the only crash-recovery
writer for outer submissions/use attempts: it may complete already-recorded
cleanup or terminal evidence, but it cannot call a provider, node target
operation, or adapter again. The separate authority-owned
`SecretProviderControlReconciler` is the only recovery writer for provider-control
rows; it may commit retained result/evidence/terminal-intent bytes or request a
fresh separately authorized read-only audit plan, but it cannot repeat the
original provider method. One owner-compatible `SecretNodeControlReconciler`
similarly finishes retained node result/evidence/terminal bytes or requests a
fresh separately authorized read-only attestation; it never resends or infers
success for the original uncertain node mutation. The provider/bootstrap owner
separately owns the private canonical backing-source registry and its permanent
one-route claims.

The Event/Evidence tick recorder is the sole owner of the immutable preclaim
tick-candidate observation, its mutable link-versus-expiry claim row, link
receipt, marker reservation, and expiry tombstone defined below. Authority may
read its validated private projection and request the one exact link CAS but
cannot create, replace, or repair any of those records. The observation owner
cannot claim an Authority submission or invoke a gateway, provider, node,
adapter, target, network, filesystem, or keychain effect. This separate owner is
a hard tick-path prerequisite; C03 cannot substitute a private Authority table or
change stable `CandidatesProposed { actions }` bytes.

A `SecretRef`, `SecretLeaseRequest`, `SecretLease`, access event, provider
receipt, or message is not authority to execute an action. Required authority,
data-use, work-order, quota, policy, approval, safety, network/filesystem,
secret-lease, and compatibility verifiers still run through the existing Action
Gateway. Provider fetch and material delivery occur only after placement and
after the gateway has issued a private final permit, atomically reserved the
exact requirement-specific containment units and use attempts, and durably
recorded every claim. The
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
| `splendor-authority::secrets` | Ref, lease, exposure-aggregate, use-attempt, outer submission, and provider-control invocation lifecycle; authority intersection; expiry; maximum use; renewal; rotation; revocation; provider routing decisions; private validated wrappers; crash reconciliation commands | Vendor SDKs, node execution, gateway replacement, artifact/event storage |
| `splendor-gateway` | Existing verified invocation path, secret-lease verifier, private final permit retention, effect certainty | Secret lifecycle state, provider routing, material resolution, delivery cleanup |
| `adapters/secrets-*` | Provider-specific fetch/renew/revoke/audit translation through the authority-owned port | Granting authority, choosing broader fallback, public errors, durable broker state |
| resident node/executor | Exact-boundary delivery, OS/orchestrator controls, close/unmount/revoke, restricted local detectors | General secret storage, fleet policy, authority evaluation, alternate effect path |
| future Event/Evidence tick recorder | Immutable preclaim tick-candidate observation, ordering, integrity, visibility, retention, duplicate conflict, orphan reconciliation | Authority submission claim, policy reinvocation, gateway/provider/node/target effects, stable trace-payload rewrite |
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
the Gateway-owned `GatewaySecretTerminalNormalizer` may construct the complete
stable `ActionOutcome` meaning. It constructs and seals one private immutable
pending canonical byte sequence from the already-sealed projections before the
Authority terminal transaction. Authority persists those bytes and their digest
under the submission ID; it does not reinterpret the stable outcome. The daemon
response projector may release those exact bytes only after the terminal
receipt/action evidence commits and current result-read authorization succeeds;
after material exposure it releases only the fixed restricted suppression
envelope and never those internal outcome/receipt bytes.
Thus construction/sealing is private before append, publication is after append,
and no direct or tick path can serialize an early status and later revise it.

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

For `material_exposed`, the proposed-public-projection argument is a sealed
zero-capacity variant. The adapter may provide raw captured bytes only to the
private detector/incident path described below; it cannot propose an output,
error, postcondition value, artifact, state patch, trace payload, or result
choice. Any adapter ABI that permits such a value for that exposure profile is
incompatible and cannot register.

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
| `secret_provider_route_id` | `SecretProviderRouteId` | One immutable configured provider route; distinct routes never share a bootstrap handle. |
| `provider_audit_id` | `SecretProviderAuditId` | One sanitized provider operation receipt. |
| `provider_control_invocation_id` | `SecretProviderControlInvocationId` | One gateway-mediated provider control effect. |
| `secret_tick_candidate_observation_id` | `SecretTickCandidateObservationId` | One immutable Event/Evidence-owned preclaim observation of one tick candidate. |
| `secret_tick_candidate_observation_link_receipt_id` | `SecretTickCandidateObservationLinkReceiptId` | One immutable Event/Evidence-owned receipt proving that one observation won the link-versus-expiry CAS for one exact proposed outer submission. |
| `secret_approval_continuation_id` | `SecretApprovalContinuationId` | One immutable continuation of one exact approval challenge inside an existing outer submission; never a second action or effect identity. |
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
| `secret_containment_reserve_id` | `SecretContainmentReserveId` | One pre-exposure non-borrowable containment reservation; not a quota credit or authority. |
| `secret_reconciliation_claim_id` | `SecretReconciliationClaimId` | One nominal provider/node reconciliation-claim identity; it is not permission to repeat an effect. |
| `secret_consumed_effect_tombstone_id` | `SecretConsumedEffectTombstoneId` | One immutable permanent consumed-identity/effect marker. |
| `secret_permanent_auxiliary_identity_marker_id` | `SecretPermanentAuxiliaryIdentityMarkerId` | One immutable permanent non-reuse marker for one containment auxiliary identity. |
| `secret_retired_authority_domain_marker_id` | `SecretRetiredAuthorityDomainMarkerId` | One immutable permanent deny marker for one retired authority domain. |

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
| `SecretDeliveryExposureProfile` | `trusted_injection`, `material_exposed` |
| `SecretTickCandidateClaimState` | `unclaimed`, `linked_to_exact_submission`, `expired` |
| `SecretNodeControlRetryProfile` | `no_retry`, `one_no_send_retry_100ms` |
| `SecretMaterialExposedPublicationDisposition` | `target_publication_suppressed` |
| `SecretDeliveryControlKind` | `core_dump`, `ptrace_debug`, `child_inheritance`, `output_capture`, `swap_page_dump`, `generic_cache`, `orchestrator_projection`, `trusted_injection_boundary`, `destination_network_egress`, `filesystem_sink_egress`, `ipc_egress`, `child_process_egress`, `proxy_egress`, `alternate_mount_egress` |
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
driver-owned destination schema/version, one exact
`SecretDeliveryExposureProfile`, and a non-empty sorted set of approved
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
`driver_declaration_revision`, exact `destination_schema`,
`destination_digest`, and `delivery_exposure_profile`. The digest follows the
C03 prefix/JCS/BLAKE3 rule over the
complete closed driver-owned projection. The complete validated projection is
available only to Authority/Gateway through a private typed wrapper; common
records carry the exact schema/digest binding, not an untyped projection.

Normalization creates one
`splendor.secret.bound_use_requirement.v1` per proposed requirement, containing
the complete original `SecretUseRequirement` plus the destination binding. The
ref revision and current Authority decision must authorize that exact operation,
slot, destination digest, and exposure profile. The same binding is then immutable in the lease
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

- `splendor.gateway.action_request_with_secrets.v1` is the private normalized
  gateway wrapper. Its only fields are `schema_version`,
  `action_request` containing the unchanged `ActionRequest`, and
  `bound_secret_requirements` containing one through 16 ordered bound
  requirements. Duplicate slot
  IDs or duplicate `(secret_ref_id, slot_id, intent, purpose)` tuples reject. It
  enters the existing Action Gateway only; it is not a second adapter path.
- `POST /v2/secret-actions` with exact header
  `X-Splendor-API-Version: 0.2-secret-actions.v1` accepts only
  `splendor.daemon.submit_secret_action.v1`. Its complete request contract is
  defined below; there is no prose-only or implementation-local request variant.
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

The canonical Rust source for the proposed public body is the future
`splendor_types::secrets::SubmitSecretActionRequest`, not a private daemon
handler struct. It mechanically generates OpenAPI component
`SubmitSecretActionRequest`, Python
`splendor.types.SubmitSecretActionRequest`, and TypeScript
`SubmitSecretActionRequest`. Those names describe future implementation targets;
this RFC adds none of them. The exact serialized field table is:

| Field | Wire type and bound | Presence and owner |
| --- | --- | --- |
| `schema_version` | ASCII constant `splendor.daemon.submit_secret_action.v1` | Required; client emits the exact constant. |
| `secret_action_idempotency_key` | Non-nil canonical `SecretActionIdempotencyKey` UUID | Required; client selects it once for this direct submission. It is not authority or an `ActionId`. |
| `action_id` | Non-nil stable `ActionId` UUID | Required; client preserves it across an exact retry. Server allocation is forbidden on this endpoint. |
| `run_id` | Non-nil stable `RunId` UUID | Required; client mirror must equal the authenticated current run. |
| `tenant_id` | Non-nil stable `TenantId` UUID | Required; client mirror must equal middleware and run scope. |
| `agent_id` | Non-nil stable `AgentId` UUID | Required; client mirror must equal the run agent. |
| `causal_trace_event_id` | Non-nil stable `TraceEventId` UUID | Required; client supplies an already-durable event in this exact run. It is linkage, not authority. |
| `action` | Complete unchanged stable 0.1 `Action` object | Required; client supplies it. Its stable nested fields and bytes are not renamed or reinterpreted. Raw credential ingress rejects before outer claim. |
| `adapter` | ASCII identifier, 1-128 characters, `[a-z][a-z0-9._-]*` | Optional by absence only; client may omit it for server registry resolution. `null` is invalid and absence is not a wildcard. |
| `quota_usage` | Complete unchanged stable `QuotaUsage` object | Required; client supplies all seven fields. `actions` and `http_requests` are integers in the stable `u32` range; the other five fields are integers from zero through `9007199254740991`. |
| `satisfied_preconditions` | Ordered array of 0-64 unique ASCII strings, each 1-128 characters | Required, including `[]`; client supplies it and order is semantic. |
| `requested_at` | Exact fixed-six-digit C03 RFC3339 UTC timestamp | Required; client preserves the original value across every exact retry. Server defaulting or replacement is forbidden. |
| `approval_evidence` | Complete unchanged stable `ApprovalEvidence` object | Optional by absence only; client may supply legacy fail-closed evidence. A raw grant is non-authorizing. `null` is invalid. |
| `authority_obligation_receipts` | Ordered array of 0-64 complete unchanged stable `AuthorityObligationReceipt` objects | Required, including `[]`; client supplies raw non-authorizing receipts. Receipt IDs are globally unique in the array and order is preserved. |
| `secret_requirements` | Ordered array of 1-16 complete `splendor.secret.use_requirement.v1` objects | Required; client supplies typed proposals. Slot IDs and `(secret_ref_id, credential_slot_id, intent, purpose)` tuples are unique. |

No field has an implicit default. The only legal absences are `adapter` and
`approval_evidence`; every other field is required. Explicit `null`, unknown
fields, duplicate object keys at any request-object level, duplicate set entries,
an invalid nested stable object, an over-bound array/string/integer, malformed or
nil identity, and a complete request over 2 MiB reject before authentication-
dependent object lookup, outer claim, persistence of rejected bytes, provider/
node/adapter/target work, or any other effect. Raw JSON parsing must detect
duplicate keys rather than applying first-key or last-key wins. The body never
contains `credential`, `audit_attribution`, principal, work order, capability,
data-use grant, workload/attempt, tick, physical resource coordinate, placement,
lease, provider, target, destination, audience, handle, permit, endpoint,
delivery method selection, arbitrary metadata, or `extensions`. Middleware and
the current run/authority owners derive and validate those values.

Client quota bytes are retained for equality, then the direct normalizer applies
the unchanged stable daemon floor of `actions >= 1` and
`action_duration_ms >= 1` exactly once before constructing `ActionRequest`.
Other quota fields are not invented. The row stores both the exact accepted
client request digest and the complete normalized quota. Thus `actions=0` and
`actions=1` are different accepted-request bytes even if both normalize to one;
same-key reuse between them conflicts rather than collapsing through a default.
Adapter absence is likewise retained as absence in the request digest while the
resolved effective adapter is pinned separately in the wrapper and challenge.

The exact relationship to stable `SubmitActionRequest` is additive and
non-mutating:

| New v2 field/rule | Stable mapping used by the daemon | Compatibility rule |
| --- | --- | --- |
| Required `action_id`, run/tenant/agent, action, adapter, preconditions, `requested_at`, approval evidence, receipts | The same stable fields, with `action_id=Some`, `requested_at=Some`, and the same optional/array values | Stable field names, nested bytes, null behavior, and `/actions` remain unchanged. |
| `causal_trace_event_id` | Stable `causal_trace_id=Some(the same TraceEventId)` | The new schema uses the canonical current name; no stable output or alias is rewritten. |
| Complete client `quota_usage` | Server-normalized complete stable `quota_usage=Some(...)` | The stable floor runs once. No missing/null default is accepted by the new schema. |
| Middleware caller/audit context | Stable resident middleware supplies or equality-checks its existing credential/audit compatibility projection | The new body cannot authenticate itself. |
| `secret_action_idempotency_key` and `secret_requirements` | No fields are added to stable `SubmitActionRequest`; they enter the C03 outer key and private bound-requirement wrapper | Stable `/actions` bytes and ordinary action semantics remain unchanged. |
| Tick/physical coordinates | Direct stable request has no tick ID; any physical resource coordinate remains server-derived | Request JSON cannot create either coordinate. |

Two named request digests prevent approval evidence from weakening ordinary
changed-byte conflict. `splendor.daemon.submit_secret_action_ingress_digest.v1`
contains exactly its schema plus every field in the table, including tagged
adapter/approval absence and every complete raw receipt, in stated array order.
It is the exact-duplicate ingress oracle. The separate
`splendor.daemon.submit_secret_action_request_digest.v1` contains exactly its
schema, idempotency key, action/run/tenant/agent/causal IDs, complete action,
tagged adapter binding, exact client quota, ordered preconditions, requested time,
and ordered complete secret requirements; it excludes approval evidence and
authority-obligation receipts because they are non-authorizing verifier inputs.
Both use the common C03 prefix/JCS/BLAKE3 rule. Outside the one challenge-bound
continuation defined below, same-key change to either digest, to any receipt, or
to any raw evidence conflicts. Continuation must preserve the second digest and
uses a separately named receipt digest; it never treats that exclusion as general
receipt mutability.

V1/V4 request goldens include the minimum and maximum legal object, both legal
absence forms, exact quota-floor normalization, every integer/string/list bound,
all 16 requirements and 64 receipts, and exact Rust/OpenAPI/Python/TypeScript JCS
bytes and both digests. Negative goldens cover missing required fields, explicit
null for every field, omitted versus empty required arrays, zero/over-maximum and
maximum-plus-one values, malformed/nil IDs, changed action/adapter/quota/
precondition/time/requirement/causal fields, receipt reordering/duplication,
unknown and duplicate keys, forbidden authority/credential fields, oversized
bodies, and same-key raw bytes that normalize to the same stable quota. None may
reach an outer claim or effect.

The tagged policy/tick candidate is the new, additive
`splendor.gateway.secret_action_candidate.v1`. It does not inherit a Rust,
OpenAPI, Python, or TypeScript plain-candidate layout. Its complete serialized
field contract is:

| Field | Wire type and bound | Presence and owner |
| --- | --- | --- |
| `schema_version` | ASCII string constant `splendor.gateway.secret_action_candidate.v1` | Required; emitted by the C03 candidate serializer. |
| `kind` | ASCII string constant `secret_action` | Required; emitted by the C03 candidate serializer. |
| `action_id` | Non-nil stable `ActionId` UUID | Optional by absence only. Policy may preserve an already assigned ID; otherwise the kernel assigns one only after preclaim observation. JSON `null` is invalid. |
| `action` | Complete unchanged stable 0.1 `Action` object | Required; supplied by policy. Its stable field names, nested `SideEffectClass`, array order, optional `cost_estimate`, and JSON `params` bytes are not renamed or reinterpreted. Raw/secret-bearing params fail the ingress and pre-persistence barriers before observation. |
| `adapter` | ASCII identifier, 1-128 characters, `[a-z][a-z0-9._-]*` | Optional by absence only; supplied by policy. Absence means server registry resolution, not a wildcard. JSON `null` is invalid. |
| `quota_usage` | Complete stable `QuotaUsage` object | Required after policy-host normalization. `actions` and `http_requests` are JSON integers in the stable `u32` range; the other five fields are JSON integers from zero through `9007199254740991`. `actions` is exactly one for this one candidate. |
| `satisfied_preconditions` | Ordered array of 0-64 unique ASCII strings, each 1-128 characters | Required; supplied by policy. Order is semantic and preserved. |
| `requested_at` | Exact fixed-six-digit C03 RFC3339 UTC timestamp | Optional by absence only. Policy may preserve an original request time; otherwise the kernel assigns it only after observation. JSON `null` is invalid. |
| `authority_obligation_receipts` | Ordered array of 0-64 complete unchanged stable `AuthorityObligationReceipt` objects | Required, including an empty array. Policy/daemon composition may carry raw non-authorizing receipts; the live gateway revalidates them. Order is preserved and changing it changes candidate identity. |
| `delegated_capability_grant_id` | Non-nil nominal `CapabilityGrantId` UUID | Optional by absence only; supplied only by the trusted delegation composition for the policy output. JSON `null` is invalid. |
| `secret_requirements` | Ordered array of 1-16 complete `splendor.secret.use_requirement.v1` objects | Required; supplied by policy through the typed C03 builder. Slot IDs and `(secret_ref_id, credential_slot_id, intent, purpose)` tuples are unique. |

No other top-level field is legal. In particular, `approval_evidence`,
`authority_obligation_evidence`, tenant/agent/run/workload/attempt identity,
destination, lease, provider, delivery, permit, endpoint, raw secret, material,
arbitrary metadata, and `extensions` are forbidden. This preserves the stable
rule that policy output containing raw `ApprovalEvidence` fails before action
evaluation. Every optional top-level value uses absence only; explicit JSON
`null` rejects. Unknown fields and duplicate object keys reject. Complete
canonical candidate bytes are capped at 1 MiB; oversized candidates fail before
observation or outer claim.

Policy-host helpers must finish defaulting before producing this object. In
particular, a missing plain-candidate usage estimate becomes the complete stable
`QuotaUsage::single_action()` value and a missing receipt list becomes `[]`.
After serialization, the kernel may validate but may not silently default or
rewrite an observed field. The only post-observation normalizations are allocation
of an absent `action_id`, allocation of an absent `requested_at`, trusted
run/workload/attempt/placement bindings, registered adapter resolution for an
absent adapter, destination derivation, and construction of the unchanged
`ActionRequest`; all are pinned in the outer row and are not tick-key inputs.

Cross-language relation to stable plain candidates is exact and non-mutating:

| Existing surface | Mapping into the new candidate before observation | Compatibility rule |
| --- | --- | --- |
| Rust kernel `ActionCandidate` | `action_id`, `action`, `adapter`, `usage -> quota_usage`, `satisfied_preconditions`, `requested_at`, `authority_obligation_receipts`, and `delegated_capability_grant_id`; raw `approval_evidence` must be absent; typed `secret_requirements` comes only from the additive C03 variant. | Existing struct and serialization, where any, remain unchanged. A plain candidate without the additive typed requirements cannot invoke a secret slot. |
| OpenAPI/daemon `DaemonActionCandidate` | `null`/missing `action_id`, `adapter`, or `requested_at` maps to canonical absence before C03 serialization; `null`/missing `quota_usage` maps to the complete single-action default; absent receipt list maps to `[]`; delegated grant is absent. | Existing OpenAPI bytes still accept their documented nulls. The generated C03 type itself rejects null and is a separate schema. |
| Python `ActionCandidate` | `action`, `adapter`, `usage -> quota_usage`, and `satisfied_preconditions`; action/time/delegated grant are absent and receipts are `[]` unless a future generated C03 builder explicitly supplies supported fields. | The stable Python dataclass is unchanged and cannot hide requirements in `Action.params`. |
| TypeScript daemon candidate | Same mapping as the OpenAPI source from which it is generated. | Stable TypeScript fields remain unchanged; the future C03 generated type uses this table exactly. |

The candidate semantic digest has the named closed projection
`splendor.gateway.secret_action_candidate_digest.v1`. Its object contains exactly
these fields: `schema_version` with that digest-schema constant,
`candidate_schema_version`, `kind`, `action_id_binding`, complete unchanged
`action`, `adapter_binding`, complete `quota_usage`, ordered
`satisfied_preconditions`, `requested_at_binding`, ordered complete
`authority_obligation_receipts`, `delegated_capability_grant_binding`, and ordered
complete `secret_requirements`. Each optional binding is always present in the
digest projection and is exactly `{"kind":"absent"}` or a closed present form:

```json
{
  "kind": "present",
  "action_id": "<ActionId>"
}
```

The present field is respectively `action_id`, `adapter`, `requested_at`, or
`delegated_capability_grant_id`. No other field is legal in a binding. An absent
policy value remains the tagged absence in this digest even after the server
assigns action/time or resolves an adapter. A policy-supplied `requested_at` is
included in its exact fixed timestamp spelling; server assignment, observation,
authentication, claim, completion, and reconciliation times are excluded. Arrays
retain the order stated above. Validation and optional tagging run before RFC
8785 JCS; then the exact ASCII prefix
`splendor.gateway.secret_action_candidate_digest.v1`, one zero byte, and the JCS
bytes are hashed with BLAKE3. No secret material, secret-derived digest, provider
request, endpoint, permit, detector key, or server-assigned absent value enters
the projection. Changed field values, changed array order, present-versus-absent,
`null`, unknown fields, or a different timestamp spelling produce a different
digest or reject; implementations never coerce them into equality.

The tick idempotency key uses projection
`splendor.secret.tick_candidate_key.v1` with exactly `schema_version`, `run_id`,
`tick_id`, zero-based `candidate_ordinal`, and
`candidate_semantic_digest`. The candidate digest field accepts only the output
of `splendor.gateway.secret_action_candidate_digest.v1`; it never hashes an
implementation-local candidate, retained candidate bytes, policy name, action
ID/time assigned after observation, or another digest profile. The common C03
prefix/JCS/BLAKE3 rule produces `tick_candidate_key_digest`. The direct input is
the caller's canonical UUID `SecretActionIdempotencyKey`. Both normalize into the
same durable outer submission contract below. An `ActionId` scopes the action and
detects key reuse, but is not by itself effect idempotency.

#### Durable preclaim tick observation

The Event/Evidence tick recorder owns the immutable restricted record
`splendor.secret.tick_candidate_observation.v1`. The complete field table is:

| Field | Wire type and bound | Contract |
| --- | --- | --- |
| `schema_version` | Exact record constant | Required. |
| `secret_tick_candidate_observation_id` | Non-nil `SecretTickCandidateObservationId` | Required nominal observation identity, allocated once by the owner. |
| `tenant_id`, `agent_id`, `run_id` | Exact non-nil stable nominal IDs | Required and equal to the active runtime context. |
| `tick_id` | Stable `TickId` integer, 0 through `9007199254740991` | Required. |
| `candidate_ordinal` | JSON integer, 0-255 | Required zero-based position in a policy output containing at most 256 total candidates and at most 16 C03 candidates. |
| `policy_output_identity` | Closed object described below | Required. |
| `policy_output_digest` | C03 policy-output candidate-manifest digest below | Required. |
| `candidate_canonical_bytes_b64url` | Unpadded base64url of the complete RFC 8785 bytes of `splendor.gateway.secret_action_candidate.v1`, decoded length 1 byte through 1 MiB | Required; decoding and recanonicalization must reproduce exactly the retained bytes. |
| `retained_candidate_digest` | Exact named retained-candidate digest below | Required and recomputed from the complete retained canonical bytes before any link or expiry transition. |
| `candidate_semantic_digest` | Exact named candidate digest above | Required and recomputed from the decoded candidate before use. |
| `recorded_sequence` | Positive Event/Evidence owner sequence no greater than `9007199254740991` | Required and strictly monotonic in its owner partition. |
| `recorded_at` | Owner-assigned fixed-six-digit C03 timestamp | Required. |
| `retention_policy_revision` | Positive Event/Evidence policy revision no greater than `9007199254740991` | Required and pinned when the batch commits. |
| `unclaimed_expires_at` | Owner-assigned fixed-six-digit C03 timestamp | Required; computed by the exact policy below and immutable. |

`policy_output_identity` contains exactly non-nil `run_id`, `tick_id` in the
range above, `policy_name` as 1-128 ASCII characters matching
`[A-Za-z0-9._:-]+`, non-nil `policy_completed_trace_event_id`, and
`policy_completed_trace_sequence` from zero through `9007199254740991`. The
event ID/sequence must identify the
already-durable stable `PolicyCompleted` event for the same run/tick/policy. The
`policy_output_digest` is the C03 prefix/JCS/BLAKE3 digest of projection
`splendor.secret.policy_output_candidate_manifest_digest.v1`, containing exactly
its schema, that `policy_output_identity`, `total_candidate_count` from 0 through
256, and `secret_candidates`: a 1-16 element ordered array of every C03
candidate in the policy output as
`{candidate_ordinal, candidate_semantic_digest}`. Ordinals are strictly
increasing and unique, each ordinal is less than `total_candidate_count`, and
that count is at least the C03 array length. No C03 candidate in the policy
output may be omitted. This digest deliberately names the complete C03
candidate manifest, not arbitrary next-state/rationale bytes and not a claim to
hash an implementation-local `PolicyDecision`.

The observation contains no secret material, uncontrolled secret-derived data,
next-state bytes, rationale, provider request, destination projection, endpoint,
permit, detector key, or raw error. Before append, the exact candidate passes the
closed schema, adopted-operation raw-ingress profile, and pre-persistence scanner;
scanner absence, ambiguous coverage, or any secret match fails closed without
persisting the candidate. Unknown fields, `null`, duplicate keys, noncanonical
base64url, byte/digest mismatch, wrong policy event, or an invalid ordinal reject.

`retained_candidate_digest` uses the closed projection
`splendor.secret.tick_retained_candidate_digest.v1` containing exactly its schema
and `candidate_canonical_bytes_b64url`. Validation first decodes, recanonicalizes,
and byte-compares the complete candidate; the common prefix/JCS/BLAKE3 rule then
applies. This digest identifies the immutable retained payload, while
`candidate_semantic_digest` identifies candidate meaning. Neither may substitute
for the other.

The immutable observation payload is separate from the Event/Evidence-owned
mutable `splendor.secret.tick_candidate_claim_state.v1` row. That row contains
exactly its schema, observation ID, owner partition digest, retained-candidate and
candidate-semantic digests, fixed `unclaimed_expires_at`, closed `state`, positive
`owner_revision`, positive `last_transition_sequence`, and one state-dependent
binding:

| Claim state | Required binding | Forbidden binding |
| --- | --- | --- |
| `unclaimed` | none | link receipt and expiry tombstone |
| `linked_to_exact_submission` | `link_receipt {secret_tick_candidate_observation_link_receipt_id, observation_link_receipt_digest}` | expiry tombstone |
| `expired` | `expiry_tombstone {secret_consumed_effect_tombstone_id, tombstone_integrity_digest}` | link receipt |

Event/Evidence exposes one private owner command to race those terminal
transitions. Link input contains the observation ID, owner partition digest,
immutable retained-candidate and candidate-semantic digests, exact proposed
`SecretActionSubmissionId`, `outer_idempotency_digest`, `wrapper_digest`,
`submission_digest`, fixed expiry, and expected owner revision. The owner samples
its trusted monotonic UTC under the same serializable transaction that checks and
CASes the row. A link may win only when owner time is strictly before
`unclaimed_expires_at`; at or after the exact boundary only expiry may win.
Storage, clock, revision, or transaction uncertainty produces neither winner and
fails closed.

A winning link atomically advances the row to
`linked_to_exact_submission`, increments owner revision/sequence, appends
restricted `secret.tick_candidate.linked`, and stores immutable
`splendor.secret.tick_candidate_observation_link_receipt.v1`. The receipt contains
exactly its schema and nominal receipt ID; observation ID; tenant, agent, run,
tick, and ordinal; owner partition digest; retained-candidate and candidate-
semantic digests; proposed submission ID; outer-idempotency, wrapper, and
submission digests; fixed expiry; winning owner revision/sequence; and
`linked_at`. Its named
`splendor.secret.tick_candidate_observation_link_receipt_digest.v1` projection
contains the digest schema, the receipt record schema as
`link_receipt_schema_version`, and every other receipt field. The digest output
is external and excluded. Exact duplicate link input returns the same receipt;
any changed submission ID or digest is
`secret_tick_candidate_observation_conflict` and cannot create another receipt.

Expiry CASes the same `unclaimed` row. Its winner first inserts and verifies the
exact observation-domain permanent tombstone defined below, then atomically
advances the claim state to `expired` and appends restricted
`secret.tick_candidate.expired`. Only after those durable facts may retained
candidate bytes be deleted. An expiry winner permits no Authority outer row,
reservation, provider/node/adapter/target work, or effect. A link winner prevents
unclaimed expiry and pins the immutable payload, claim row, link receipt, and
marker reservations through outer terminal/uncertain retention and permanent
tombstone rules.

Authority may insert a tick outer row only after validating a durable winning
link receipt against the current immutable observation and the exact proposed
outer bytes. The outer row stores the receipt ID/digest. Missing, corrupt,
unavailable, wrong-revision, or mismatched receipt state denies and quarantines;
an outer row without that exact receipt is an invalid storage invariant and may
not execute or be repaired by inference. A crash after link but before outer
insert leaves a linked-only orphan. Only explicit recovery of the same run/tick,
same proposed submission ID, and same retained-candidate, candidate-semantic,
outer-idempotency, wrapper, and submission digests may complete it after all
current Authority checks. A generic observation reconciler, policy reinvocation,
changed submission, fresh ID, or later tick cannot complete or cause an effect.
If exact recovery never succeeds, the linked payload remains pinned until the
run-domain retirement protocol proves no outer/effect exists and commits the
link/tombstone audit; timeout or garbage collection cannot turn it back into
`unclaimed` or `expired`.

Ordering and recovery are exact:

1. Policy returns, and the stable `PolicyCompleted` trace append succeeds.
2. The tick recorder validates/scans every C03 candidate, reserves one permanent-
   marker slot per observation, and atomically appends all of that output's
   observation records plus their `unclaimed` claim-state rows as one all-or-none
   Event/Evidence batch. It then emits the
   unchanged stable `CandidatesProposed { actions: Vec<Action> }`; no C03 metadata
   is added to that stable payload.
3. When an observed candidate reaches submission, the kernel reloads the retained
   bytes, recanonicalizes them, recomputes both digests, and derives the tick key
   only from the named candidate digest and fixed run/tick/ordinal above.
4. After all normal preclaim validation that cannot disclose/effect external
   state, Authority proposes the fixed submission ID and complete outer digests;
   the Event/Evidence link CAS and durable receipt are the next mutation. Only
   then may Authority insert that exact outer row. No reservation, provider/node/
   adapter/target work may intervene.
5. Observation, scanner, required stable trace, batch acknowledgement, or digest
   failure causes no outer claim, use reservation, provider/node call, adapter
   entry, target effect, network/filesystem/keychain access, outcome, or state
   advancement.
6. A crash after observation reuses only the retained canonical bytes. An
   explicitly resumed same run/tick may continue normal validation, obtain or
   revalidate the exact link receipt, and insert only its receipt-bound outer row
   under current authority; it never invokes policy again or synthesizes a
   replacement candidate. If the rest of the tick cannot be safely resumed, it
   fails closed after reconciling any already-linked/claimed submission.
7. Uniqueness is `(run_id, tick_id, candidate_ordinal)`. An exact duplicate with
   the same policy identity/digest, candidate bytes/digest, tenant, and agent
   returns the original observation ID/sequence. Any changed byte or binding is
   `secret_tick_candidate_observation_conflict` and cannot claim an outer row.
8. A generic Event/Evidence orphan reconciler may verify, retain, CAS-expire an
   unclaimed observation, or quarantine a linked-only observation but cannot call
   Authority or cause an effect. Only explicit same-tick runtime recovery under
   current authority can proceed from the exact link receipt to outer insertion.

The tick path remains disabled until Event/Evidence accepts and implements this
nominal identity, immutable record, atomic batch, ordering, integrity,
visibility, retention, duplicate, and orphan-reconciliation contract. A private
kernel map, stable trace payload extension, or Authority-owned shadow record is
not a compatible substitute.
Observation retention is owner-clocked and exact. Event/Evidence samples its
trusted monotonic UTC once for the atomic batch and uses that value as
`recorded_at`. Let `tick_deadline` be the already-admitted run/tick deadline. The
owner computes:

```text
minimum_recovery = recorded_at + 5 minutes
deadline_recovery = tick_deadline + 60 seconds
unclaimed_expires_at = max(minimum_recovery, deadline_recovery)
maximum_recovery = recorded_at + 24 hours
```

If `unclaimed_expires_at > maximum_recovery`, the whole observation batch rejects
before append because the admitted tick cannot fit the v1 recovery policy. Before
`unclaimed_expires_at`, explicit same-tick recovery may win the link CAS under all
current checks. At or after that exact timestamp, an unclaimed observation can
never link, claim an outer row, or create an effect, even if the run/tick deadline
is later changed. Link and expiry CAS the same owner row, so exactly one terminal
state wins. At the exact boundary expiry is the only legal winner. The expiry
winner follows the tombstone-before-delete transaction above. Eligible deletion
order is `(unclaimed_expires_at, run_id canonical UUID bytes, tick_id,
candidate_ordinal)`. A linked observation ignores unclaimed expiry for deletion
and remains until its submission and tick satisfy terminal retention and their
permanent non-reuse tombstones exist. Policy revision, owner clock, link receipt,
tombstone, or storage uncertainty fails closed and never drops an active linked
record. Replay may inspect the immutable observation, claim-state history, link
receipt, or expired tombstone but cannot CAS, insert an outer row, or cause an
effect.

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

The POST and lookup response is the one closed schema
`splendor.daemon.secret_action_submission_response.v1`.

The lookup route is exactly `GET
/v2/secret-actions/submissions/{secret_action_submission_id}` with no request
body. It accepts only the canonical non-nil path ID and the same exact API-version
header as POST. `splendor.actions.submit` permits only the original principal's
minimal restricted status view on GET; it never releases historical full result
or receipt content. Every full GET, including one by the original principal, and
every delegated/operator inspection requires
`splendor.secret_actions.results.read`. All paths still apply the result-
authorization rules below before choosing a view.

Its enums are closed:

```text
SecretActionSubmissionState = accepted | in_progress | awaiting_approval |
  continuing | uncertain | reconciling | cancelled | terminal
SecretActionResponseView = full | restricted
SecretActionReceiptDisposition = not_committed | complete | withheld
SecretActionResponseReason = effect_state_uncertain | terminal_evidence_blocked |
  secret_action_receipt_unavailable | reconciliation_in_progress |
  approval_continuation_cancelled
SecretActionRedactionReason = current_result_authority_unavailable |
  material_exposed_target_publication_suppressed
```

Its complete field contract is:

| Field | Type/bound | Presence |
| --- | --- | --- |
| `schema_version` | Exact response schema constant | Required in every response. |
| `secret_action_submission_id` | Non-nil nominal ID | Required. |
| `state` | Closed `SecretActionSubmissionState` | Required. |
| `view` | Closed `SecretActionResponseView` | Required. |
| `duplicate` | JSON boolean | Required. `true` only for a POST that found the original dedupe row; creating POST and every GET return `false`. |
| `retry_class` | Unchanged stable lowercase `RetryClass` | Required. |
| `outer_effect_certainty` | Unchanged stable lowercase `EffectCertainty` | Required in both views. |
| `provider_effect_certainty`, `node_effect_certainty`, `target_effect_certainty` | Unchanged stable lowercase `EffectCertainty` | Required in `full`; forbidden in `restricted`. |
| `receipt_disposition` | Closed `SecretActionReceiptDisposition` | Required. |
| `reason_code` | Closed `SecretActionResponseReason` | Required only for `uncertain`, `reconciling`, or `cancelled`; forbidden otherwise. |
| `poll_after_ms` | JSON integer 100-5,000 inclusive | Required for `accepted`, `in_progress`, `awaiting_approval`, `continuing`, `uncertain`, and `reconciling`; forbidden for `cancelled` and `terminal`. |
| `action_outcome` | Complete unchanged stable `ActionOutcome` object | Required for `terminal/full` and `awaiting_approval/full`; forbidden otherwise. The awaiting form is exactly the stable challenge outcome and does not change its bytes or status meaning. |
| `delivery_receipt` | Complete committed `splendor.secret.delivery_receipt.v1` | Required only for `terminal/full`; forbidden otherwise. |
| `approval_continuation_id` | Non-nil nominal `SecretApprovalContinuationId` | Required only for `awaiting_approval/full`; forbidden otherwise. It is correlation, not authority. |
| `approval_id` | Non-nil stable `ApprovalId` | Required only for `awaiting_approval/full`; forbidden otherwise. |
| `approval_challenge_expires_at` | Exact fixed-six-digit C03 timestamp | Required only for `awaiting_approval/full`; forbidden otherwise. |
| `redaction_reason` | Closed `SecretActionRedactionReason` | Required only for `restricted`; forbidden for `full`. |

Every optional-by-state response field uses absence only; explicit `null` is
invalid. Unknown fields, duplicate keys, unknown enum values, a nonterminal
outcome other than the exact `awaiting_approval/full` challenge outcome, any
nonterminal delivery receipt, a terminal full response missing either nested
object, or a restricted response containing split certainty, output, outcome,
receipt, use, approval identity, provider, node, target, destination, detector,
or evidence metadata is invalid. An awaiting full `action_outcome` must have
stable status `NeedsApproval`, the same action and approval IDs as the immutable
continuation, one complete exact challenge, zero effect, and no output or post-
verification.
The exact state/view matrix is:

| State | HTTP | Retry | Outer/split certainty | Poll | Receipt disposition | Outcome/receipt |
| --- | --- | --- | --- | --- | --- | --- |
| `accepted` | 202 | `retry_with_same_idempotency_key` for `full`; `not_retryable` for `restricted` | Current outer; all three current split values only in `full` | Required | `not_committed` | Forbidden |
| `in_progress` | 202 | `retry_with_same_idempotency_key` for `full`; `not_retryable` for `restricted` | Current durable values | Required | `not_committed` | Forbidden |
| `awaiting_approval/full` | 202 | `retry_with_same_idempotency_key` | Outer and every split value exactly `none` | Required | `not_committed` | Exact stable `NeedsApproval` outcome plus all three approval-continuation fields required; delivery receipt forbidden |
| `awaiting_approval/restricted` | 202 | `not_retryable` | Outer exactly `none`; split values forbidden | Required | `not_committed` | Outcome, receipt, and all approval-continuation fields forbidden |
| `continuing` | 202 | `not_retryable` | Current durable values; split values only in `full` | Required | `not_committed` | Outcome, receipt, and approval-continuation fields forbidden; the one receipt claim is already in progress |
| `uncertain` | 202 | `not_retryable` | Outer exactly `uncertain`; current split values only in `full` | Required | `not_committed` | Forbidden; `reason_code` is `effect_state_uncertain`, `terminal_evidence_blocked`, or `secret_action_receipt_unavailable` |
| `reconciling` | 202 | `not_retryable` | Outer exactly `uncertain`; current split values only in `full` | Required | `not_committed` | Forbidden; `reason_code=reconciliation_in_progress` |
| `cancelled` | 200 | `not_retryable` | Outer exactly `none`; split values only in `full` and all exactly `none` | Forbidden | `not_committed` | Outcome, receipt, and approval-continuation fields forbidden; `reason_code=approval_continuation_cancelled` required |
| `terminal/full` | 200 | Exact sealed terminal retry classification; `Executed` is `not_retryable` | Exact receipt values | Forbidden | `complete` | Both complete nested objects required |
| `terminal/restricted` | 200 | `not_retryable` | Exact outer value only for authority redaction; fixed `uncertain` for material-exposed suppression | Forbidden | `withheld` | Both forbidden; exact applicable redaction reason required |

For `awaiting_approval/full`, `retry_with_same_idempotency_key` means the stable
exact pending-action retry on `/actions`; the daemon reloads the original C03 key
server-side. It never means POSTing changed receipt bytes to
`/v2/secret-actions`, creating a new outer key, or retrying an effect after the
continuation claim.

A full nonterminal shape is therefore exactly:

```json
{
  "schema_version": "splendor.daemon.secret_action_submission_response.v1",
  "secret_action_submission_id": "<SecretActionSubmissionId>",
  "state": "in_progress",
  "view": "full",
  "duplicate": true,
  "retry_class": "retry_with_same_idempotency_key",
  "outer_effect_certainty": "known",
  "provider_effect_certainty": "known",
  "node_effect_certainty": "known",
  "target_effect_certainty": "none",
  "receipt_disposition": "not_committed",
  "poll_after_ms": 250
}
```

An uncertain full shape is exactly the same common/full field set with
`state=uncertain`, `retry_class=not_retryable`,
`outer_effect_certainty=uncertain`, the three current split certainty fields,
`receipt_disposition=not_committed`, one allowed `reason_code`, and required
`poll_after_ms`. `reconciling` has the same shape with
`reason_code=reconciliation_in_progress`. A terminal full shape removes poll and
reason and adds exactly the fields named `action_outcome` and
`delivery_receipt`, each containing its complete unchanged/closed object.

A terminal restricted response is exactly:

```json
{
  "schema_version": "splendor.daemon.secret_action_submission_response.v1",
  "secret_action_submission_id": "<SecretActionSubmissionId>",
  "state": "terminal",
  "view": "restricted",
  "duplicate": false,
  "retry_class": "not_retryable",
  "outer_effect_certainty": "known",
  "receipt_disposition": "withheld",
  "redaction_reason": "current_result_authority_unavailable"
}
```

Every restricted nonterminal shape adds only its state-required poll/reason to
that common restricted field set and uses `receipt_disposition=not_committed`; it
never uses null placeholders. `cancelled` is a final no-effect state rather than a
stable `ActionStatus`; it therefore has no poll, outcome, or delivery receipt and
cannot be mistaken for a completed adapter attempt.

After any `material_exposed` delivery, creating POST, duplicate POST, and every
GET return only one fixed `terminal/restricted` envelope at the predeclared
publication boundary: `duplicate` follows only creating-versus-duplicate
transport history, `retry_class=not_retryable`,
`outer_effect_certainty=uncertain`, `receipt_disposition=withheld`, and
`redaction_reason=material_exposed_target_publication_suppressed`. Outcome,
receipt, split certainty, reason, poll, output, error, target timing, evidence,
incident, and cleanup fields are forbidden. Even the original principal or a
dedicated result reader cannot obtain a full result. The fixed internal stable
`Failed` action outcome and restricted security/incident evidence remain owner
records; ordinary result APIs, trace projections, state, artifacts, and SDKs do
not expose them as target-selected data. A pre-exposure denial may still use its
ordinary full/restricted rule because target code never received material.

Response media type is exactly `application/json`. The request body and retained
candidate obey the daemon's 2-MiB request cap; the unchanged nested
`ActionOutcome` canonical bytes are capped at 1 MiB for this new endpoint, the
receipt is capped at 512 KiB, the complete full response is capped at 2 MiB, and
the restricted response is capped at 4 KiB. Scan/seal must produce a failed
no-output outcome before terminal commit rather than truncate protected output
to fit. Pre-commit serialization ambiguity or inability to prove the terminal
pair leaves the row uncertain and returns that authorized nonterminal view. An
unexpected post-commit response serialization/integrity failure returns `503
secret_action_receipt_unavailable` without a partial envelope, does not mutate
terminal state, and permits only same-submission lookup after repair; it never
authorizes a new key/effect.

Both routes require exact header
`X-Splendor-API-Version: 0.2-secret-actions.v1`. The POST additionally requires
`Content-Type: application/json`; any other request media type is `415
unsupported_media_type`. Unknown API versions return `426`; unsupported C03 body
schema returns `400`; malformed/unknown-field/null/size failures return `400` or
`413` as applicable; same-visible-key changed semantics returns `409`; profile or
owner unavailability before acceptance returns `503`. Authentication failures use
the existing `401`; endpoint-scope failures use existing `403`; hidden/unknown
submission IDs and unauthorized original-object conflicts use the uniform padded
`404 secret_not_available` profile. Every non-2xx body uses the unchanged stable
daemon `ApiError {code,message,details}` shape, contains no C03 object or certainty
metadata, and has `details={}` for privacy-sensitive 404/409 cases.

The future Rust source schema must generate or mechanically pin the OpenAPI,
Python, and TypeScript response types, exact required/forbidden matrices, enum
spellings, HTTP/content-type mapping, and canonical fixtures. Generated C03
clients fail closed on unknown fields/enums or an invalid state/view combination;
they do not reinterpret a partial body as terminal.

All pre-acceptance transport/schema/profile failures above have zero C03,
provider, node, adapter, target, network, filesystem, or keychain effect. Once
accepted, gateway denials/failures use the terminal contract only when the exact
terminal pair commits. If the submission or receipt store cannot prove that
pair, the response is `uncertain`, `reason_code` is
`secret_action_receipt_unavailable` or `terminal_evidence_blocked`, retry is
`not_retryable`, and outer certainty is `uncertain`. A caller may poll or invoke
authorized reconciliation for the same submission; it must not create a new
key/action or resubmit the effect. Before a boundary can have been crossed its
certainty is `none`; after possible crossing, a missing required fact is
`uncertain`, never guessed `none`.

#### Submission result authorization

`splendor.actions.submit` authorizes submission to the gateway; it is not a
historical full-result or secret-receipt read scope. Every outer row stores the
exact `original_principal_id` from authenticated middleware in its trusted
partition. Possession or secrecy of `SecretActionSubmissionId`, an action ID,
idempotency key, trace ID, or run ID is never authorization.

The immediate POST response and same-key POST recovery may return `view=full` to
the original principal only after one current result-read decision
validates all of: authenticated original principal equality; caller credential
tenant, daemon audience, expiry, and revocation; exact run visibility and current
run-result policy; output classification/visibility; required data-use grants and
purposes; current work-order/capability scope, expiry, and revocation; submission
security audience; receipt visibility; and any owner-defined restricted-evidence
policy. Every input is current at response release. The stored historical allow,
terminal receipt, pending outcome, action-submit scope, or prior data-use grant
cannot satisfy this decision.
This full-view rule is additionally subject to the material-exposed suppression
override above: once material was delivered to target code, no principal or scope
can receive the complete outcome/receipt through these routes.

The additive endpoint historical/inspection scope is exactly
`splendor.secret_actions.results.read`. A delegated support/operator principal
or the original principal may request a full GET only with that dedicated scope, current exact
tenant/run/submission/result/output/data-use authority, credential/work-order/
capability/revocation checks, and server-owned audit attribution recording the
inspector principal, submission ID, policy/authority revisions, view released,
and result. The scope is not implied by `splendor.actions.submit`, trace/state
read, tenant membership, operator role text, or a broad wildcard. It cannot
authorize a live action, material resolution, unredacted raw driver output, or a
result whose current data-use/output policy denies the inspector.

If the original principal is authenticated and visible to the submission but
one current full-result check no longer allows protected output or restricted C03
metadata, POST and GET return only the closed `restricted` view. An explicitly
scoped inspector whose current inspection policy permits existence/status but
withholds result content receives the same view. It proves accepted/in-progress/
uncertain/reconciling/terminal state, conservative outer certainty, and
non-retryability without exposing the stable outcome, final action status, split
provider/node/target certainty, complete receipt, use attempts, lease/ref,
destination, provider/node/target, detector, evidence, output, error, or reason
for the authority change. The sole redaction reason is the generic
`current_result_authority_unavailable` on this authority-change path;
material-exposed suppression uses its separate fixed reason and reveals no
authority-change or target-result fact.

An original principal using only `splendor.actions.submit` on GET receives this
restricted view even when current full-result checks would otherwise pass; it
must use the dedicated read scope for historical full content. An unrelated
principal, including a second principal in the same tenant/run with
only `splendor.actions.submit`, receives the uniform padded `404
secret_not_available` response before any full/restricted object state is
revealed. An unknown ID is indistinguishable. A caller lacking either submit
scope for its own recovery path or the dedicated inspection scope receives the
existing endpoint-level `403` before object lookup. Every protected full-result
release and every restricted inspection is audit-attributed; audit append failure
withholds the result and fails closed. These rules apply identically if authority
changes between effect completion and the immediate creating POST response or
between duplicate lookup and response serialization.

Existing plain `/actions` and plain policy candidates cannot invoke an adopted
secret-capable operation with raw credentials, ref-like strings, or hidden
requirements. The operation's live ingress profile denies those forms before
persistence/provider/adapter effects. A plain request is accepted only when the
registered operation declares no credential slot for that mode. The sole
exception is the stable exact-action approval retry: while the run has the exact
pending C03 challenge, `/actions` may continue that already-claimed parent by
loading its immutable requirements and original key server-side under the
continuation protocol above. It cannot initiate a secret action, accept new
requirements, create another key/parent/effect coordinate, or bypass any current
gateway verifier.

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

Direct requests must supply `requested_at`. For observed tick proposals that omit
it, lookup first reuses any existing row. On a miss, the outer-claim transaction
allocates one authority-owned `first_accepted_requested_at`, constructs the
unchanged gateway action digest/wrapper from that value, and pins all three in the
new row atomically. A uniqueness loser rereads the winner and never recomputes
time or wrapper bytes. Transport observation, authentication, completion, and
reconciliation timestamps are excluded from semantic digest equality.

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
stable gateway action input, the complete additive candidate and every optional-
binding form, bound requirements, exact prefixed canonical bytes, candidate/
policy-manifest/wrapper/tick-key bytes and digests, preclaim observation, and
outer direct/tick projection bytes/digests. Negative goldens change each field,
array order, candidate ordinal, policy event, timestamp spelling, and optional
present/absent form; submit explicit null, unknown/duplicate fields, mismatched
retained bytes/digests, oversized bytes, and same observation key with changed
bytes. Rust is canonical; OpenAPI, Python, and TypeScript must reproduce every
byte and digest. A generated or skipped fixture is not evidence.

### Durable outer submission and terminal-intent ledger

Authority claims one durable `SecretActionSubmissionId` after closed-schema,
caller/scope, feature/owner compatibility, run/workload/attempt, action ID,
driver declaration, slot, and server-derived destination validation, but before
any C03/action terminal event, use reservation, provider I/O, node control,
secret-aware adapter entry, or target operation. The trusted lookup key is the
stable dedupe partition above. The claimed row additionally pins workload,
attempt, effect coordinate, `original_principal_id`, wrapper digest, submission
digest, and every server-derived binding used by semantic equality. A tick row
also pins its `secret_tick_candidate_observation_id`, policy-output identity/
digest, candidate ordinal, retained-candidate digest, tick-key digest,
`secret_tick_candidate_observation_link_receipt_id`, and
`observation_link_receipt_digest`. Before insert, Authority validates that the
Event/Evidence claim row is `linked_to_exact_submission` and that the immutable
receipt binds this exact proposed submission ID plus the retained-candidate,
candidate-semantic, outer-idempotency, wrapper, and submission digests. The
outer insert is forbidden before that durable winning receipt. A row found
without it, or with a missing/corrupt/uncertain receipt, is invalid, denied, and
quarantined rather than repaired or executed. The claim reads the observation
through the Event/Evidence-owned private contract but never copies secret-bearing
or uncontrolled bytes into Authority.
No caller bytes choose the ledger partition or replace pinned coordinates.

`SecretActionSubmissionState` is closed:

```text
accepted -> in_progress -> terminal
accepted | in_progress -> awaiting_approval -> continuing -> terminal
awaiting_approval -> terminal | cancelled
continuing -> uncertain | terminal
accepted | in_progress -> uncertain -> reconciling -> terminal
uncertain | reconciling -> uncertain
```

`terminal` means the immutable delivery receipt and exactly one matching final
effect-terminal `action.executed|action.denied|action.failed|action.needs_intervention`
event committed atomically. `awaiting_approval` means the current gateway attempt
ended in stable `NeedsApproval` with no effect while this same parent submission
remains continuable. `continuing` means the one exact receipt continuation is
claimed and has not yet reached the final terminal pair. `cancelled` means run
lifecycle cancellation won before that claim and permanently closed the parent
with no effect. `uncertain` means some effect or required
terminal fact cannot be proved. `reconciling` means the authority-owned
reconciler holds the one claim to finish cleanup or append the recorded terminal
intent; it is not permission to repeat an effect.

For each accepted submission that reaches effect-terminal `terminal`, ledger
uniqueness enforces exactly one all-or-none use-attempt batch and exactly one
final delivery-receipt/effect-terminal-event pair. A denial after acceptance but
before reservation, other than the initial
approval challenge, has one final pair with an empty use-attempt set. The initial
approval challenge instead has one stable attempt-terminal `ActionOutcome`, one
`action.needs_approval` event, one `approval.requested` event, and no
`SecretDeliveryReceipt`; the parent moves to `awaiting_approval` in the same
atomic unit and may produce at most one later final pair under the protocol below.
A parent cancelled before continuation has no use-attempt batch, effect, final
receipt, or final effect-terminal event.
A batch reservation stores its complete ordered attempt IDs on the
submission before any provider/node/adapter call; it cannot be replaced by fresh
attempts. The effect coordinate is also unique: the same action/invocation ID
with a different key or
semantic digest conflicts instead of creating another effect.

An exact same-key/same-digest/same-scope duplicate first applies the principal and
current-policy result authorization above, then returns or refers to the original
accepted/in-progress/awaiting/continuing, uncertain/reconciling, cancelled, or
terminal full/restricted view. It
emits no second use claim, provider call, node control, adapter entry, target
operation, terminal action event, or receipt. Same key with changed bytes/scope/
audience, changed tick observation, or same action/invocation with a new key,
returns `secret_action_idempotency_conflict`, effect `none` for that conflicting
observation, and HTTP 409 only to an authorized original-object viewer; it does
not mutate the original record. A conflict that would disclose a hidden original
uses the uniform not-available profile instead.

#### Exact challenge-bound approval continuation

The stable approval contract is not rewritten. The first gateway attempt may
return a complete unchanged stable `ActionOutcome` with
`ActionStatus::NeedsApproval`; that attempt is terminal and the adapter count is
zero. It does not make the C03 parent effect-terminal. Before releasing that
outcome, Authority atomically persists the exact challenge outcome/event facts,
the immutable continuation record below, and parent state
`awaiting_approval`. Failure of any member releases no challenge response and
leaves a no-effect uncertain parent for same-submission repair only.

The immutable restricted record
`splendor.secret.approval_continuation.v1` contains exactly:

- its schema, one fresh `secret_approval_continuation_id`, and the existing
  `secret_action_submission_id`;
- trusted-partition digest, original authenticated `principal_id`, `tenant_id`,
  `agent_id`, `run_id`, optional original `tick_id`, exact workload/attempt,
  submission security audience, and the one action/invocation effect coordinate;
- complete unchanged original `Action`, effective adapter, complete normalized
  `QuotaUsage`, ordered satisfied preconditions, original `requested_at`, original
  causal trace input, and the complete ordered bound secret requirements including
  every exact slot/destination/exposure binding;
- one closed `origin`: `direct` with original
  `secret_action_idempotency_key`, direct ingress digest, and direct semantic
  request digest, or `tick` with observation ID, policy-output identity/digest,
  original run/tick/ordinal, candidate semantic digest, tick-key digest, and
  retained-candidate digest;
- original `outer_idempotency_digest`, `wrapper_digest`, and `submission_digest`;
- the complete unchanged stable `ApprovalChallenge`, its named digest below,
  exact `approval_id`, `authority_decision_id`, `obligation_id`, receipt audience,
  policy ID/revision, optional risk label, canonical request/gateway-action/
  authority-decision digests, and challenge `expires_at`;
- original work-order, capability, data-use, authority, policy, and revocation-
  snapshot IDs/revisions that must be revalidated currently rather than reused as
  authority;
- exact stable challenge `ActionOutcome` digest, `action.needs_approval` event
  ref, `approval.requested` event ref, first accepted time, and the closed
  continuation expiry/revocation policy; and
- literal zero-effect facts: no use-attempt batch, provider/node/adapter/target
  entry, target generation, handle, material, delivery, terminal receipt, or
  continuation-created state-head advance, and all four certainty dimensions
  `none`; any original tick suffix remains the separate unchanged stable fact.

No field is optional except the tick binding/risk label and owner authorities
that are genuinely not applicable; each uses an explicit closed
`not_applicable|present` tag, never null or omission. The record has no raw secret,
provider request, endpoint, permit, material-derived value, output, or raw error.
`splendor.secret.approval_challenge_digest.v1` hashes the complete unchanged
challenge with that schema prefix under the common JCS/BLAKE3 rule. The digest
output is external to the challenge and is never hashed recursively.

The separate Authority-owned
`splendor.secret.approval_continuation_state.v1` row contains exactly its schema,
continuation/submission/approval IDs, challenge digest, state, Authority revision,
last transition event ref, and conditional fields
`continuation_receipt_digest`, `receipt_claim_ref`, `final_delivery_receipt_id`,
`final_outer_event_ref`, and `completed_at`. Its closed states and fields are:

```text
awaiting_receipt -> claimed -> terminal
awaiting_receipt -> denied | expired | revoked | cancelled
claimed -> terminal | effect_uncertain
effect_uncertain -> terminal
```

`awaiting_receipt` forbids every conditional field. `claimed` requires exactly
one continuation-receipt digest and durable approval-owner claim ref and forbids
final fields. `denied|expired|revoked` requires the exact final no-effect
delivery-receipt/event linkage and completion time; `cancelled` requires only its
unique run-cancellation event and completion time because no second action
outcome is fabricated. `effect_uncertain` preserves the claim and any immutable
send/result/intent pointers from the parent; it cannot replace them. `terminal`
requires the final delivery receipt/event IDs and completion time. Null,
replacement pointers, a second claim, or state regression reject.

The continuation receipt digest is the named closed projection
`splendor.secret.approval_continuation_receipt_digest.v1`. It contains exactly its
schema, continuation/submission/approval IDs, challenge digest, obligation and
authority-decision IDs, original semantic request or candidate digest, original
wrapper/submission digests, `receipt_id`, and the complete unchanged raw
`AuthorityObligationReceipt` including its validation object. It excludes the
digest output itself. Validation runs first; the exact schema prefix, zero byte,
JCS, and BLAKE3 then apply. The raw receipt remains non-authorizing input. Only a
trusted approval owner may return a private validated wrapper and atomically
claim its one semantic issuer/audience/subject/decision/obligation/request/
approval coordinate for this exact continuation.

C03 approval continuation has this one ingress and no second public secret
action shape: the caller submits the unchanged stable `POST /actions` exact-action
retry required by the approval contract. The daemon matches its pending
run/action/challenge to exactly one C03 parent, then loads the immutable C03
requirements and key from that parent. The stable request must preserve action
ID, tenant/agent/run, complete action, effective adapter, normalized quota,
ordered preconditions, original `requested_at`, and original causal trace input.
It may add only the exact receipt, or the stable receipt-free raw denial/expiry/
revocation evidence. It cannot supply or replace secret requirements, key,
observation, workload, target, destination, or current authority. A direct
continuation advances under the original direct key, `outer_idempotency_digest`,
and direct semantic request digest. A tick continuation advances under the
original observation/run/tick/ordinal, candidate and tick-key digests. It never
invokes policy, creates a candidate/observation, starts another tick, or advances
a state head.

The sole key/effect-coordinate exception is narrow: one parent may record the
zero-effect challenge attempt and one child continuation under the same original
outer key and same action effect coordinate. It does not permit a second parent,
key, action/invocation, use-attempt batch, provider call, node operation, target
generation, adapter entry, destination, or final receipt/event pair. The unique
effect index contains `(secret_action_submission_id,
secret_approval_continuation_id)` only for this exact challenge child and still
rejects every different-key or different-coordinate claim.

Current runtime authority remains mandatory. Immediately before the continuation
claim, the daemon/gateway revalidate authenticated original principal, run
lifecycle, exact current work order/capability/data-use/policy/revocation state,
the complete current conditional authority decision, every ordinary verifier,
and the challenge/receipt expiry and audience through trusted configuration. A
receipt, challenge, submission ID, or approval grant alone never authorizes an
effect. Raw grants, changed action/time/adapter/quota/preconditions/causal input/
requirements, wrong issuer/audience/subject/decision/obligation/request/approval,
expired/revoked/forged receipts, a new principal, a new key, or a new effect
coordinate deny or conflict before reservation/provider/node/adapter/target work.

The current process-local stable receipt ledger is not restart-durable. C03 live
approval-required use therefore remains disabled until the approval/Authority
owner accepts a compatible durable claim/revoke contract that returns
`claimed_by_this_continuation` for an exact crash retry and never treats it as a
fresh claim. The parent CAS `awaiting_approval -> continuing`, continuation CAS
`awaiting_receipt -> claimed`, and owner receipt claim linearize in one durable
unit or through an accepted transactionally recoverable owner protocol before
pre-effect evidence. No runtime may approximate that prerequisite with an
in-memory flag or receipt possession.

Duplicate, race, and recovery behavior is exact:

1. Response loss after challenge returns the same awaiting response and challenge
   after current result authorization; it creates no second challenge or event.
2. The first exact valid receipt that durably claims the continuation wins.
   Exact redelivery of that receipt returns the existing continuing/terminal/
   uncertain state. A different or semantically reissued receipt for the same
   challenge conflicts and has zero effect.
3. Raw exact denial/expiry/revocation with no receipt may win only from
   `awaiting_receipt`; it records the stable fail-closed final outcome with an
   empty use batch. Raw grant cannot claim or execute.
4. Run cancel/stop, challenge expiry, receipt revocation, work-order/data-use/
   policy/authority revocation, and receipt claim are CAS-raced. A close/revoke/
   expiry winner prevents claim and effect. A claim winner does not bypass the
   final current checks; later cancellation closes new permits and may turn an
   already-crossed path into the existing conservative failure/uncertainty path.
5. Crash before claim leaves `awaiting_receipt`. Crash after the owner claim but
   before any effect resumes only when the owner proves the claim belongs to this
   same continuation/digest; it never claims another receipt. Crash after any
   provider/node/adapter/target boundary follows the parent uncertainty and
   terminal-intent rules with no replay.
6. Terminal append/CAS acknowledgement loss uses the one retained parent terminal
   intent, pending outcome, final IDs, and continuation claim. Response loss after
   terminal returns the original final outcome/receipt after current result
   authorization. Neither case performs another verifier-to-effect cycle.

V2/V3/V4 fixtures cover direct and tick challenge -> exact receipt -> one effect,
raw denial with zero effects, exact duplicate receipt before/after claim and
terminal response loss, competing receipts, changed every bound field, wrong/new
principal and effect coordinate, expiry/revocation/cancel races, work-order/data-
use/policy revocation, crash before/after challenge append and continuation claim,
terminal append/CAS loss, and tick continuation with zero policy/tick/state-head
increments. Every positive case has one initial `NeedsApproval` attempt, at most
one later adapter/target effect, and one final delivery receipt; every negative
case has zero such effects.

Before trying the atomic terminal append, the Gateway-owned
`GatewaySecretTerminalNormalizer` constructs the stable `ActionOutcome` once from
the sealed publication/error projection, validates the status/entry/start/
certainty matrix, and seals its complete canonical bytes and digest in a private
non-serializable handoff. Authority cannot construct or change those stable
bytes. For `material_exposed` those bytes are the fixed suppression projection
and contain no target-selected value. Authority then stores an immutable safe
`splendor.secret.action_terminal_intent.v1` containing exactly its schema,
`secret_action_submission_id`, `outer_idempotency_digest`, `wrapper_digest`,
`submission_digest`, effect coordinate, completion digest,
adapter-entry/target-start facts, final status, all three effect-certainty
dimensions and conservative outer certainty, ordered use summaries, outer
cleanup/postcondition status, optional bounded error code, the complete closed
`publication_binding` plus its permitted trusted-injection sealed-output digest,
and complete sealed-`ActionOutcome` digest, ordered
C03 event refs, intended receipt/event IDs, and Authority completion time. Its
`terminal_intent_digest` is the common prefix/JCS/BLAKE3 digest of that complete
closed record. It contains no output bytes, material, endpoint, permit, or raw
error. In the same Authority transaction, a private pending-outcome record keyed
only by `SecretActionSubmissionId` persists the exact Gateway-sealed complete
validated unchanged `ActionOutcome` canonical bytes and digest; Authority
owns record durability, not outcome semantics. The record is not caller-
addressable or released before terminal commit. The daemon response projector
verifies that digest and current result authorization before releasing the
original outcome. Missing/mismatched pending bytes are uncertainty, never outcome
reconstruction from receipt fields. If append acknowledgement is
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
ordered use summaries, cleanup/postcondition status, complete
`publication_binding`, its permitted trusted-injection sealed-output digest,
sealed-`ActionOutcome` digest, optional bounded error code, and ordered C03
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
| `credential_destination_binding` | yes | Exact operation, nominal slot, driver declaration revision, destination schema/digest, and exposure profile approved. |
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
- `delivery_handle_id`, `secret_lease_id`, `secret_use_attempt_id`, exact
  `secret_exposure_lineage_id`, non-zero `lineage_target_generation`, and
  non-zero `delivery_generation`;
- exact `credential_destination_binding`;
- exactly one tagged `effect_coordinate` containing `action_id` or
  `invocation_id`;
- exact `execution_binding` and `secret_audience_id`;
- selected `delivery_method`, positive `exposure_method_child_revision`, and
  closed `status`, plus the exact exposure/enforcement profile binding;
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
`secret_exposure_lineage_id`, `lineage_target_generation`,
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
lease/use-attempt/handle IDs, exposure-lineage ID, target/delivery generations,
exact effect coordinate and execution
binding, method and method-child revision, detector registration ID when
installed, exact delivery exposure profile, enforcement-profile schema/revision/
digest, ordered `SecretEgressEvidenceRef` values for every reached phase,
driver-returned time,
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
  lease ID, exposure-lineage ID, and the durable `use_claimed` event ref;
  selected method/method-child
  revision and unique handle/target/delivery generation are present exactly when
  their child objects were created; it also contains optional provider audit ID, optional
  final delivery status required exactly when a handle exists, required cleanup
  status, zero through 20 unique node-control receipt IDs in
  durable operation order, summary `node_effect_certainty`, attestation ID only
  after adapter target return, optional detector registration ID, exact exposure
  profile, enforcement-profile digest when material was staged, and ordered
  egress evidence IDs for every reached exposure/send/terminal phase;
- `secret_aware_adapter_entered`, `target_operation_started`,
  batch-level `provider_effect_certainty`, `node_effect_certainty`,
  `target_effect_certainty`,
  `outer_cleanup_status: SecretCleanupStatus`, and
  `postcondition_status` from the closed set
  `not_run|allowed|denied|uncertain`;
- exact stable outer `final_action_status`, conservative
  `outer_effect_certainty`, optional bounded error code, and one closed
  `publication_binding`: `trusted_injection` carries `publishable` plus an exact
  `sealed_output_digest` present only when publishable; `material_exposed`
  carries only `disposition=target_publication_suppressed` and forbids output,
  error, artifact, state, trace, and result digests;
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
For `trusted_injection`, receipt validation proves the complete injector and
actual-destination pre-send evidence and forbids any fact that target code
received material. For `material_exposed`, it requires the accepted
SBX-007/NODE/SBX enforcement profile plus every applicable pre/post egress
evidence ref; a missing raw-socket/DNS/proxy/filesystem/IPC/child/alternate-mount
barrier fact is receipt-invalid and cannot produce terminal success.

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

Once a `material_exposed` target receives material, its target return, exit code,
signal, stdout/stderr/result bytes, result shape, error choice, and completion
timing never choose a public field. The gateway holds external completion until
the immutable driver-declared material-exposure publication deadline, terminates
the target at that boundary if needed, and constructs the one fixed internal
stable projection:
`final_action_status=Failed`, `output` absent, exact bounded error code
`material_exposed_publication_suppressed`, and publication disposition
`target_publication_suppressed`; `postcondition_status=not_run`. Result APIs
release only the fixed terminal/restricted envelope above, never that internal
outcome or receipt. Broker-owned pre-exposure denials retain their ordinary stable
status because target code had no material. Trusted terminal-store uncertainty
may withhold any body under the existing non-retryable uncertainty rule, but
target return, cleanup outcome, or captured bytes cannot select a different
payload. Material-exposed postconditions never inspect a target result or
captured byte.

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
trusted-partition digest, `secret_action_submission_id`,
`state: SecretActionSubmissionState`,
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
its exact `schema_version`, `provider_trust_scope`, `secret_provider_id`,
`secret_provider_route_id`, positive route-policy revision,
`SecretProviderHealthStatus`, `SecretProviderCircuitState`,
`SecretProviderLatencyBucket`, consecutive-failure count,
`observed_at`/`valid_until`, and a safe reason code. It contains no provider
endpoint, tenant secret name, SDK error, response body, account identifier, or
credential. `valid_until` is later than `observed_at`; an expired observation is
unavailable, never healthy by default.

`SecretProviderAuditReceipt` uses `splendor.secret.provider_audit.v1` and
contains its exact `schema_version`, `provider_audit_id`, provider ID, route ID,
route-policy revision, operation, outcome, exact `provider_trust_scope`,
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
  `secret_provider_route_id`, `provider_control_invocation_id`,
  `provider_operation`, and optional visible
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
route ID/revision, operation, provider trust scope, authority revision, deadline,
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
`secret_provider_id`, exact `secret_provider_route_id`, route-policy revision,
one closed `target_scope`, expected generations required by that target,
complete current authority binding, operation deadline, closed retry profile,
requested/expiry times, and `causal_ref`. `target_scope` is exactly
`provider_route` with no ref/lease fields, `secret_ref` with visible
`secret_ref_id`, expected ref revision and refresh/revocation generations, or
`secret_lease` with visible ref/lease IDs and expected ref/lease/refresh/
revocation generations. `active_probe` requires `provider_route`; `renew`
requires `secret_lease`; `revoke` requires `secret_ref|secret_lease`; `audit`
declares exactly the scope it inspects. Unknown fields, nulls, missing or
cross-tag fields reject.

`SecretProviderControlRetryProfile` is closed to `no_retry` and
`one_no_send_retry_100ms`. The latter permits one retry only while the ledger is
`in_progress` and the adapter proves zero request bytes left; no operation,
including a provider-declared idempotent one, has a post-send retry profile in
v1.

`provider_control_plan_digest` uses the named closed projection
`splendor.secret.provider_control_plan_digest.v1`. It contains exactly its digest
schema, `plan_schema_version`, `provider_control_invocation_id`, operation,
complete `provider_trust_scope`, `secret_provider_id`,
`secret_provider_route_id`, route-policy revision, the complete closed tagged
`target_scope`, complete current authority binding, operation deadline, retry
profile, requested time, expiry, and causal ref. Every target variant includes
its tag and all fields named above; cross-tag fields are absent, never null. All
nominal/generated IDs and all three times are included in canonical owner format;
no observation, completion, or retry-attempt time is added. The common C03
prefix/JCS/BLAKE3 rule applies. No plan field is omitted and no provider request,
result, endpoint, bootstrap, or digest output bytes are added. The trusted
partition digest uses
closed projection `splendor.secret.provider_control_partition_digest.v1` with
exactly its schema, authenticated actor `principal_id`,
`provider_trust_scope`, `secret_provider_route_id`, operation, and
`provider_control_invocation_id`. Credential/JTI correlation, node/instance,
timestamps, and caller strings are excluded. Caller fields cannot select another
partition.

#### Durable provider-control invocation ledger

Authority claims one durable
`splendor.secret.provider_control_invocation.v1` row after closed plan/current
authorization/route compatibility validation but before
`secret.provider.control.requested`, provider bootstrap source access, DNS,
network, keychain/file access, permit acquisition, or provider I/O. Its fields are
exactly `schema_version`, trusted partition digest,
`provider_control_invocation_id`, `provider_control_plan_digest`, exact provider
trust scope/provider ID/route ID/route-policy revision, operation, complete
target scope, authority revision, causal ref, operation deadline, retry profile,
state, first accepted time, expiry, last Authority revision, and conditional
terminal/reconciliation pointers below. It contains no credential, bootstrap
handle, provider request, endpoint, SDK object, raw response/error, or material.

The conditional row fields are named exactly `requested_event_ref`,
`pre_evidence_ids`, `send_boundary_recorded_at`,
`provider_control_result_digest`, `provider_audit_id`, `post_evidence_ids`,
`provider_control_terminal_intent_digest`, `completed_event_ref`,
`authority_lifecycle_event_refs`, and `reconciliation_claim`. `accepted` forbids
all of them. `in_progress` requires the requested event and a 1-16 element ordered
pre-evidence list and forbids the rest. `sent_uncertain` additionally requires
the write-ahead send time and forbids the result/audit/post/terminal fields.
`sent_known` preserves that send time and requires one complete immutable result
bundle: result digest, audit ID, and a 1-16 element ordered post-evidence list. A
partial bundle rejects. `reconciling` preserves all fields from its prior state
and requires the closed
`reconciliation_claim {secret_reconciliation_claim_id, actor_principal_id,
authority_revision, claimed_at, expires_at}`; it cannot replace result/evidence
bytes. If exact safe result bytes
were retained under the invocation's unique result key before a row-state CAS was
lost, reconciliation may validate them and atomically add the complete immutable
bundle while moving to `sent_known`; otherwise that bundle remains absent. A
separately authorized audit may explain current provider state but cannot
populate the original retained-result bundle or terminalize the original
uncertain operation by inference. `terminal` requires result, audit, both evidence lists, terminal-intent
digest, completed event, and the ordered Authority lifecycle event refs and
forbids a reconciliation claim. It preserves `send_boundary_recorded_at` exactly
when the retained result's effect certainty is `known|uncertain`; a terminal
proved-no-send result has certainty `none` and forbids that field.

Event refs are exact restricted `SecretCausalRef` values, evidence lists contain
nominal `EvidenceId` values, audit uses nominal `SecretProviderAuditId`, digests
use the common fixed C03 `blake3:<lowercase hex>` encoding, and every time uses
the fixed-six-digit C03 timestamp. The reconciliation claim's expiry is after its
claim time and no later than the operation's bounded reconciliation deadline. Every
optional-by-state field uses absence only; null, unknown fields, changed pointers,
duplicate evidence IDs, or reordered event/evidence lists reject.

`SecretProviderControlInvocationState` is closed:

```text
accepted -> in_progress -> terminal
in_progress -> sent_uncertain -> sent_known -> terminal
sent_uncertain | sent_known -> reconciling
reconciling -> sent_uncertain | sent_known | terminal
```

`accepted` proves only the row claim. `in_progress` proves requested evidence and
the operation permit exist but no request byte can yet have left. Immediately
before the first possible provider request byte, Authority CASes to
`sent_uncertain` as a conservative write-ahead boundary. A proved no-send result
may terminalize from `in_progress`; once `sent_uncertain` is durable, recovery
never re-enters the provider method. A definitive safe control result, including
a closed `effect_uncertain` result when send/result ambiguity is itself final,
stores the complete safe result/audit bytes and moves to `sent_known`; a missing
result, process loss, or missing post-send fact remains `sent_uncertain`.
`reconciling` is a one-owner lease to complete retained evidence/state, not
permission to repeat the operation.

Before terminal state, Authority stores immutable
`splendor.secret.provider_control_terminal_intent.v1` with exactly its schema,
`provider_control_invocation_id`, `provider_control_plan_digest`,
`trusted_partition_digest`, provider trust scope/provider ID/route ID/route-
policy revision/operation/complete target scope, authority revision and causal
ref, final closed result outcome/retry count/effect certainty/safe reason, exact
`provider_audit_id`, `provider_control_result_digest`, `requested_event_ref`,
ordered 1-16 `pre_evidence_ids`, ordered 1-16 `post_evidence_ids`, intended
`completed_event_ref`, ordered 0-16 `authority_lifecycle_event_refs`, and
`completed_at`. It has no generic `invocation_digest` field and does **not**
contain its own digest. The separate quota-
controlled safe result record retains the complete canonical
`splendor.secret.provider_control_result.v1` bytes. Both are immutable,
byte-free, and restricted. `terminal` means the exact completed control event,
audit/result, terminal intent, and any resulting Authority CAS/lifecycle event
are committed under unique IDs; a provider response by itself is not terminal.

`provider_control_terminal_intent_digest` is computed only from named projection
`splendor.secret.provider_control_terminal_intent_digest.v1`. That projection
contains exactly `schema_version` set to the digest schema plus every terminal-
intent field above, with the intent's record schema carried as
`terminal_intent_schema_version`. The target tag, all result enums, generated
`provider_control_invocation_id`, both plan/partition digests, audit/event/
evidence IDs, ordered arrays, causal ref, and exact `completed_at` are included.
There is no inferred or implementation-local invocation digest. There are no
optional fields: a no Authority
lifecycle-event path uses `authority_lifecycle_event_refs=[]`; other arrays retain
their required cardinality. Null, reordered IDs, duplicate IDs, a changed time,
or a changed tag rejects or changes the digest. The digest output itself is
explicitly excluded and cannot occur in the intent, projection, result, evidence,
or audit. Validation runs before the common schema-prefix/zero-byte/JCS/BLAKE3
rule. The output is stored only in the invocation row and compact hot-index
terminal pointer; no record recursively hashes a field that contains that output.

Lookup by trusted partition always precedes provider bootstrap or I/O. Exact same
invocation/plan bytes return or refer to the original accepted/in-progress,
sent-uncertain/sent-known, reconciling, or terminal state/result and issue no
second requested event, permit, bootstrap read/refresh, DNS/network request,
provider call, audit receipt, or lifecycle mutation. Same invocation with any
changed plan/route/target/authority/deadline/retry/causal byte returns
`provider_control_idempotency_conflict` and leaves the original row unchanged.
Hidden or cross-principal scope uses the uniform not-available profile.

Crash and response-loss behavior is exact for `renew`, `revoke`, `audit`, and
`active_probe`:

1. Crash before claim has no row/effect; an authorized fresh delivery may claim.
2. Crash after claim but before requested evidence resumes from the same row and
   retained plan, with no provider I/O yet.
3. Crash in `in_progress` may retry permit/evidence setup only while durable facts
   prove no send; it cannot change plan bytes.
4. Crash/response loss at or after `sent_uncertain` never invokes the original
   provider method again, even for audit/probe or a provider claiming idempotency.
5. A retained definitive result in `sent_known` is completed from exact retained
   bytes. Completed-event/evidence/Authority-CAS acknowledgement loss uses unique
   outbox keys and the terminal intent; it never repeats the provider call.
6. If current state must be inspected, Authority may submit a separate newly
   authorized read-only `audit` control with a fresh invocation ID and its own
   ledger. It cannot masquerade as or replay the uncertain renew/revoke/probe;
   inability to prove the original result preserves uncertainty/quarantine.
7. Response loss after terminal returns the original safe result after current
   visibility validation; it never allocates a second invocation.

The complete invocation row, plan, intent, result/audit, and evidence are durable
quota-controlled records outside the hot-memory equation. The separate compact
`splendor.secret.provider_control_hot_index.v1` contains exactly:

| Field | Cardinality and rule |
| --- | --- |
| `schema_version` | Exact hot-index constant. |
| `trusted_partition_digest` | One fixed C03 digest. |
| `provider_control_invocation_id` | One non-nil nominal ID; it is also the sole durable invocation lookup pointer. |
| `state` | One closed `SecretProviderControlInvocationState`. |
| `provider_control_plan_digest` | One fixed C03 digest. |
| `send_disposition` | Exactly `no_send`, `sent_known`, or `sent_uncertain`, consistent with durable state. |
| `result_pointer` | Exactly `{"kind":"absent"}` or `{"kind":"present","provider_control_result_digest":...,"provider_audit_id":...}`. Present only for durable `sent_known|terminal` with the complete bundle. |
| `terminal_pointer` | Exactly `{"kind":"absent"}` or `{"kind":"present","provider_control_terminal_intent_digest":...,"completed_event_ref":...}`. Present only for durable `terminal`. |

No list, full plan/result/intent, target scope, evidence, lifecycle events,
authority binding, provider endpoint, error, output, credential, material, or
reconciliation lease appears in the hot index. Every field is required; the two
pointers use explicit tags and no null. The maximum valid fixture is generated
from this exact schema with terminal state, both present pointers, the longest
valid `sent_uncertain` disposition, the `run_trace` causal-ref variant, four
71-byte C03 digests (partition, plan, result, and terminal intent), and four
canonical UUIDs (invocation, audit, run, and trace event). Its RFC 8785 encoding
is exactly 902 bytes, below the 1,024-byte profile and common 2-KiB hot-entry
ceilings. V1 pins that complete byte sequence and length; the size proof must be
generated from the canonical schema fixture rather than a hand-maintained field
count. Adding a field or longer owner representation requires a new profile and
revised FND-012 proof.

Active `accepted`, `in_progress`, `sent_uncertain`, `sent_known`, or
`reconciling` durable rows and hot entries cannot be evicted. A terminal hot entry
may evict only after its permanent consumed-effect tombstone and durable plan,
intent, result/audit, event/evidence, and Authority state satisfy the retention
contract below. Storage, tombstone, or quota uncertainty denies a new claim
before requested evidence/source access/provider I/O and never drops active
uncertainty. V1 fixtures pin absent/present pointers, every state/disposition
combination, changed digest/pointer conflicts, forbidden full-record fields, and
the exact 902-byte maximum fixture under the 1,024-byte ceiling. V3 fault fixtures
prove response/event/CAS loss resolves
the same durable row through this index without a second provider method.

After a new claim, the gateway validates the retained plan and constructs a
private `splendor.secret.provider_control_request.v1` wrapper only after
provider-control authorization, exact route/bootstrap, policy, quota, deadline,
revocation, and evidence verifiers allow and durable
`secret.provider.control.requested` evidence exists. The request carries the
ledger/plan digest and cannot be constructed from a duplicate delivery that is
already `sent_uncertain`, `sent_known`, `reconciling`, or `terminal`.

The distinct private gateway control-invocation profile acquires an
operation-scoped final permit, calls exactly one provider method, and returns a
closed `splendor.secret.provider_control_result.v1` to Authority. The safe result
contains only invocation/provider/route/operation IDs and route revision, exact provider trust scope,
outcome, retry count, effect certainty, sanitized provider audit ID/code,
started/completed times, and `causal_ref`. Authority alone applies any resulting lease/ref/revocation state
CAS after `secret.provider.control.completed` is durable. The provider result is
not authority and cannot mark itself renewed, revoked, or healthy.

Control calls have the same 2-second connect, 5-second operation, and 6-second
total ceilings as fetch. At most one 100-ms retry occurs inside the same gateway
invocation and only while the ledger is `in_progress` and the adapter proves no
request byte was sent. Provider-declared idempotency does not authorize a second
control send in v1. `sent_uncertain`, `sent_known`, and post-send uncertainty
never retry or fail over. Gateway/control re-entry is forbidden: a provider method
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

`SecretNodeControlRetryProfile` is the closed wire enum named in the common enum
table. `no_retry` permits one bridge attempt and `retry_count=0` only.
`one_no_send_retry_100ms` permits at most one retry after exactly 100 ms, under
the same invocation/plan/target bytes, only while the owner row remains
`in_progress` and the owner result/evidence proves that zero bridge bytes left
and no local mutation was possible. Its terminal `retry_count` is zero or one.
Unknown values, a retry count above one, a changed plan/target/permit, missing
no-send evidence, or a retry at/after the write-ahead `sent_uncertain` transition
is invalid. No profile permits post-send retry, alternate-node/instance failover,
or duplicate-delivery-driven resend.

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

`node_control_plan_digest` uses named closed projection
`splendor.secret.node_control_plan_digest.v1`. It contains exactly its digest
schema, `plan_schema_version`, `node_control_invocation_id`, operation,
`tenant_id`, actor principal, complete current authority binding, an explicit
`secret_action_submission_binding` tagged `not_applicable|present`, causal ref,
operation deadline, retry profile, requested/expiry times, complete target
binding, and operation-specific tag. All nominal IDs, revisions, generations,
times, authority fields, and target coordinates are included. Optional action
ownership uses the explicit tag; null and omitted tags reject. The digest output,
backend data, evidence/result IDs, and observation/completion times are excluded.
Validation then the common schema-prefix/zero-byte/JCS/BLAKE3 rule apply. V1b
goldens pin each operation/tag, changed target/revision/deadline/authority/time,
optional action ownership, duplicate/unknown field, and exact canonical bytes.

The trusted node-control partition digest uses closed projection
`splendor.secret.node_control_partition_digest.v1` containing exactly its schema,
authenticated actor principal, tenant, node, instance,
`secret_exposure_lineage_id`, operation, `node_control_invocation_id`, and target
generation. Caller token/JTI, request
transport, timestamps, backend handles, and caller strings are excluded. The
complete target-binding digest is the common C03 digest of the complete closed
target under `splendor.secret.node_control_target_binding_digest.v1`; no target
field is omitted.

#### Durable node-control invocation and terminal-recovery ledger

The accepted compatible NODE/SBX owner contract must provide one Authority-
coordinated durable invocation ledger before V1b or any live node path. Authority
claims `splendor.secret.node_control_invocation.v1` after closed plan/current
authorization/target compatibility validation but before
`secret.node.control.requested`, pre-evidence acquisition, permit issuance,
resident bridge bytes, node/OS/orchestrator I/O, or mutation. The row contains
exactly its schema, trusted partition digest, invocation ID, plan digest, target-
binding digest, operation, tenant/node/instance/exposure-lineage/target-generation
coordinates, authority revision, causal ref, operation deadline, exact
`SecretNodeControlRetryProfile`, requested/expiry/first-accepted times, state,
last Authority revision, and the conditional fields below.
It contains no material, credential, endpoint, raw OS handle, backend request/
response/error, output, or free-form metadata.

Conditional fields are exactly `requested_event_ref`, ordered 1-16
`pre_evidence_ids`, `send_boundary_recorded_at`, `node_control_result_digest`,
ordered 1-16 `post_evidence_ids`, `node_control_terminal_intent_digest`,
`node_control_receipt_id`, `completed_event_ref`, ordered 0-16
`authority_lifecycle_event_refs`, and `reconciliation_claim`. Every state uses
absence, never null, for forbidden fields:

| State | Required conditional fields | Forbidden conditional fields |
| --- | --- | --- |
| `accepted` | none | all |
| `in_progress` | requested event, pre-evidence | send/result/post/intent/receipt/completed/lifecycle/reconciliation |
| `no_send` | requested event, pre-evidence, complete result digest and post-evidence proving no send | send boundary, terminal fields, reconciliation |
| `sent_uncertain` | requested event, pre-evidence, write-ahead send time | result/post/terminal fields; reconciliation unless transitioning |
| `sent_known` | requested event, pre-evidence, send time, complete result digest and post-evidence | terminal fields, reconciliation |
| `reconciling` | every immutable field from its prior state plus one claim | any replacement result/evidence/send fact or terminal field not already retained |
| `terminal` | requested/pre evidence, result/post evidence, terminal-intent digest, receipt ID, completed event, lifecycle refs; send time exactly when result disposition was sent | reconciliation claim |

`reconciliation_claim` contains exactly `secret_reconciliation_claim_id`, actor
principal, authority revision, claimed time, expiry, and prior state/digest. Its
expiry is later than claim and
no later than the bounded reconciliation deadline. A unique CAS permits one
reconciler. Duplicate evidence IDs, reordered lists, replacement pointers,
state-field mismatch, unknown fields, or clock/storage uncertainty fail closed.

The closed state graph is:

```text
accepted -> in_progress -> no_send -> terminal
in_progress -> sent_uncertain -> sent_known -> terminal
accepted | in_progress | no_send | sent_uncertain | sent_known -> reconciling
reconciling -> no_send | sent_uncertain | sent_known | terminal
```

`accepted` proves only the pre-effect unique claim. `in_progress` proves the
requested event/pre-evidence/final permit are durable and no resident bridge byte
may yet leave. Immediately before the first possible bridge byte, Authority CASes
to `sent_uncertain` and records the write-ahead time. A definitive owner result is
retained exactly once: proved no-send moves through `no_send`; any sent result,
including a final `effect_uncertain` classification, moves through `sent_known`.
Missing bridge response, node loss, or missing post-evidence remains
`sent_uncertain`. Once the write-ahead boundary is durable, no recovery path ever
replays the original node mutation.

The accepted owner schema dependency is exact. NODE/SBX owns
`splendor.node.secret_control_result.v1`, not C03. It contains exactly its schema,
invocation ID, operation, target-binding digest, `outcome`, `retry_count`,
exact `retry_profile: SecretNodeControlRetryProfile`, `send_disposition`,
`effect_certainty`, `reason_code`, started/completed times, and ordered pre/post
evidence IDs. `outcome` is closed to
`succeeded|denied|failed|effect_uncertain`; `send_disposition` is
`no_send|sent_known|sent_uncertain`; and `reason_code` is closed to
`completed|authority_denied|target_mismatch|stale_fence|unsupported_operation|
capacity_unavailable|timeout_before_send|node_unavailable_before_send|
backend_failure|result_uncertain|evidence_unavailable`. The per-operation owner
matrix must require/forbid evidence and map every backend result without free
text. `none` certainty requires `no_send`; `known` requires a definitive sent or
no-send result with complete evidence; ambiguity requires `uncertain`. Its named
owner digest includes every field and excludes its digest output. Until NODE/SBX
accepts and implements that exact schema, enums, matrix, digest, and backend
mapping, C03 cannot register a node bridge or enter V1b/live use.

Before terminal state, Authority stores immutable
`splendor.secret.node_control_terminal_intent.v1` containing exactly its schema,
partition/plan/target/result digests, invocation/operation/tenant/node/instance/
exposure-lineage/target-generation coordinates, authority revision and causal
ref, exact closed outcome/send disposition/effect certainty/retry count/reason,
exact retry profile, requested event,
ordered pre/post evidence IDs, intended receipt/completed-event IDs, ordered
Authority lifecycle event refs, and completed time. It does not contain its own
digest. Named projection
`splendor.secret.node_control_terminal_intent_digest.v1` contains exactly its
digest schema plus every intent field, carrying the intent record schema as
`terminal_intent_schema_version`; it includes every generated ID and the exact
completed time and excludes only the digest output. Common validation/JCS/BLAKE3
rules apply. The output exists only in the invocation/hot-index terminal pointer.

The compact `splendor.secret.node_control_hot_index.v1` contains exactly its
schema, partition digest, invocation ID, state, plan digest, target-binding
digest, send disposition, an absent/present result pointer containing only result
digest, and an absent/present terminal pointer containing only terminal-intent
digest plus receipt ID. It has no target object, evidence list, result, intent,
backend, error, or reconciliation claim. Explicit tags replace null. Its maximum
canonical fixture is at most 1,024 bytes, below the common 2-KiB hot-entry ceiling;
the complete invocation/plan/result/intent/receipt/evidence records are outside
the hot-memory equation and separately quota controlled.

The gateway validates node-control authority, exact current placement/execution
lease/fence, node/instance registration and health, lease/lineage/revocation
state, deadline, operation compatibility, idempotency, containment reserve, and
evidence availability. Only after the durable claim does it append
`secret.node.control.requested`, acquire pre-evidence, move to `in_progress`, and
issue one private operation-scoped permit to the registered resident node bridge.
For an action-owned control this is a child of the already-held secret-action
permit and outer submission; it does not recursively submit to the gateway. A
standalone revocation/reconciliation control uses its own gateway control
invocation and an already-durable management causal event.

The accepted NODE/SBX owner contract, not a C03 backend or daemon handler, remains
the sole owner of `SecretNodeControlResult`, `SecretNodeControlOutcome`, and
`SecretNodeControlReasonCode`; the exact required wire profile above is its
prerequisite seam. C03 imports the accepted nominal owner types unchanged into
its gateway validator and receipt. Free-form backend strings, inferred errno/
exit/HTTP codes, boolean success, missing reason, or C03-local aliases are
invalid.

The node bridge performs exactly the permitted operation once and returns that
private validated owner result. The gateway retains its exact safe bytes under
the invocation's unique result key, records post restricted evidence, and creates
one immutable `splendor.secret.node_control_receipt.v1` with receipt/invocation/
operation IDs, complete target binding, outcome, retry count, started/completed
times, exact retry profile, effect certainty, pre/post evidence IDs, safe reason
code, and causal ref.
It then durably appends `secret.node.control.completed`. Authority may advance
lease/lineage/revocation state only from that validated durable receipt. A node
acknowledgement, OS return code, provider receipt, or management intent alone is
not success.

Node effect certainty follows the same closed send rule: `none` requires proof
that no node-control bytes were sent and no local mutation was possible; `known`
requires a definitive bound result plus required post-evidence; missing,
ambiguous, or lost send/result/evidence is `uncertain`. A safe error string or
apparently idempotent OS state cannot downgrade uncertainty.

The node-control idempotency key is the trusted partition plus invocation and
canonical plan digests. Exact duplicate bytes return or refer to the original
accepted/in-progress/no-send/sent-known/sent-uncertain/reconciling/terminal state,
result, and receipt with zero second requested event, permit, bridge send, local
mutation, evidence, receipt, or Authority lifecycle change. Changed bytes
including a changed retry profile conflict with no new effect and never replace
the original row. A local control
deadline is at most 10 seconds and revocation acknowledgement at most 5 seconds.
Only `one_no_send_retry_100ms` permits the one retry under the exact rule above;
`no_retry` never does. C03 v1 permits no automatic post-send retry for any node-
control operation, including nominally idempotent close/fence/delete/attest
operations, because acknowledgement/evidence is part of the effect.
Ambiguous send/ack is `uncertain`, is never failed over to another node/instance/
process, and quarantines the target and parent exposure aggregate. Reconciliation
may validate exact retained result/evidence bytes and finish their unique terminal
intent/event/CAS. If current state must be inspected, Authority may submit only a
separately authorized read-only `attest_absent` current-state plan with a fresh
invocation ID, the same exposure lineage and target generation, its own durable
ledger, and no mutation permission. It may guide containment/new authority but
cannot replay, overwrite,
or infer-terminalize the original uncertain command. Inability to prove original
effect state preserves uncertainty.

Crash and response-loss behavior is exact: before claim an authorized delivery
may claim; after claim/before requested evidence it resumes the same row; in
`in_progress` permit/evidence setup may repeat only while no-send is durable; at
or after write-ahead `sent_uncertain` the bridge operation never re-enters; exact
retained result/evidence completes through `no_send|sent_known`; completed-event,
receipt, Authority-CAS, or response loss uses unique pointers and terminal intent.
Only one reconciler may write recovery state. Active accepted/in-progress/no-send/
sent-known/sent-uncertain/reconciling rows, their hot entries, target generations,
and their containment reserve are non-evictable. Terminal compaction requires the
permanent tombstone below. Quota/storage/reserve uncertainty rejects a new claim
before requested evidence or node I/O and never removes active uncertainty.

Node-control re-entry is forbidden. The node bridge cannot invoke a provider,
submit an action/control, allocate broader authority, call another node, or emit
the outer action terminal event. Authority, daemon, incident, expiry, health,
shutdown, replay, and background workers submit plans only; they never call node
or OS/orchestrator mutation APIs directly. Missing authority, target coordinate,
deadline, pre/post evidence, receipt, effect certainty, or acknowledgement fails
closed and cannot emit `secret.revoked` or `secret.delivery.closed`.

`NODE-003` and `SBX-001` own the resident execution/process ABI and must accept
the complete target, durable invocation/send/terminal ledger, plan and terminal-
intent digests, hot index, permit, exact result/outcome/reason/retry-profile
schema, receipt,
read-only attestation, containment reserve, and trap/fault-test contract above
before V1b or implementation. Event/Evidence must accept the management causal
and restricted pre/post evidence contracts. Until those owner contracts and
nominal IDs are
accepted and implemented, every C03 live node-delivery, cleanup, revocation,
reconciliation, V3-V5, and associated gold gate remains disabled. C03 cannot
create substitute node/sandbox/process owners to bypass that prerequisite.
Every `material_exposed` path additionally requires accepted and implemented
`SBX-007` deny-all egress isolation and evidence owner contracts. Its
absence disables material exposure even if NODE-003/SBX-001 are otherwise ready;
only a conforming `trusted_injection` path that keeps bytes out of general target
code may proceed.

### Provider bootstrap identity and transport trust

Provider-service authentication is a separate non-workload bootstrap boundary.
It is never delivered through `SecretRef`, `SecretLease`, action params, the
target delivery context, or a workload environment. Each configured route has a
closed, owner-supplied tagged `SecretProviderBootstrapProfile`. This trusted
startup record is not a public/SDK/workload schema. Every tag has exactly the
common fields `schema_version=splendor.secret.provider_bootstrap_profile.v1`,
`profile_revision`, `secret_provider_id`, `secret_provider_route_id`,
`route_policy_revision`, exact
tenant-only `provider_trust_scope`, `provider_namespace`, `provider_locality` as
1-64 ASCII characters matching `[a-z][a-z0-9._-]*`,
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
`active_probe` whose Authority provider-control ledger is claimed before it
constructs and validates the exact private source handle; a
missing/mismatched handle, source I/O uncertainty, or failed probe fails startup
closed. Probe uncertainty is not healthy. `local_file` and `os_keychain` support `fetch`, sanitized `audit`,
and `active_probe`; provider-side `renew`/`revoke` return the closed
`unsupported_operation`/known-no-effect result while Authority still
fences leases and node handles. `test_memory` supports only its declared
deterministic fixture operations. No tag falls back to another.

All non-path string coordinates are 1-128 printable ASCII without control/space
characters; origins/CIDRs and local paths use their exact parsers and canonical
forms. Lists are non-empty, duplicate-free semantic sets.
Cross-route bootstrap source or SDK credential-handle sharing is forbidden in
v1. Each `SecretProviderRouteId` owns exactly one private route-handle instance;
each `network_service` route additionally owns one route-local
`SecretBootstrapSourceBindingId`. Each handle/binding belongs to exactly one
route ID. Even two byte-identical route profiles must construct different non-
aliasing handles and, for network routes, different source-binding IDs. A
process-global SDK credential singleton, copied pointer/reference, shared refresh object, shared
opened descriptor, shared keychain persistent reference handle, or source-binding
ID reused by two routes is invalid.

The private handle registry key is the complete closed projection
`splendor.secret.bootstrap_route_handle_binding.v1`: route ID, provider ID,
profile and route-policy revisions, exact provider trust scope and namespace,
profile tag, complete source tag/binding, account/audience and workload issuer/
subject/identity/refresh-owner binding when applicable, owner-descriptor mapping
and ownership proof binding when applicable, keychain application/access-group/
service/user/session/persistent-reference binding when applicable, provider locality,
origins/CIDRs, CA profile, SDK profile/digest, revocation source/generation, and
not-before/expiry. Missing/not-applicable values are closed profile tags, never
null/defaults. The registry enforces one unique route ID and private object
identity per route plus one unique source-binding ID per `network_service` route.
Any attempted alias/reuse or mismatch fails
startup before opening/refreshing a source, DNS, file/keychain access, SDK
initialization, probe evidence, or provider send. Future sharing requires a
separate accepted contract; v1 defines no sharing set or exception.

Route IDs, source-binding IDs, mapping IDs, wrapper/object identity, pointers,
descriptors, and byte-identical configuration are not backing-source identity.
The provider/bootstrap owner must first operate one durable private
`BootstrapBackingSourceRegistry`. `BootstrapBackingSourceId` is a private non-nil
nominal UUID allocated only by that registry; it is not a public `splendor-types`
ID, request/config-export field, bearer, provider coordinate, or source-derived
hash. The registry has a global uniqueness constraint over one private canonical
backing-source identity and permits exactly one active route owner.

Canonical private source identities are closed by tag:

| Source tag | Complete alias identity |
| --- | --- |
| `workload_identity` | Exact issuer, provider account, subject, audience, broker/service principal, token authority, refresh authority/owner, semantic credential-source identity, token-exchange identity, and cache namespace/identity. Distinct token or refresh wrapper objects with the same tuple are one backing source. |
| `owner_file` | Immutable owner mapping plus platform-stable backing resource identity supplied by the installation owner: filesystem/mount identity, device, inode/file identity, and generation/version equivalent; effective owner and access generation are included. Separate paths, hard links, mappings, or descriptors resolving to that identity are one backing source. |
| `os_keychain` | Application, access group, service namespace, effective user/session, persistent item identity, item generation, and access-policy identity. Distinct queries, references, or wrapper handles resolving to that item are one backing source. |
| `sdk_credential_cache` | Provider/SDK profile and version, provider account/audience, semantic credential-source identity, token/refresh authority, cache implementation, cache namespace/key, persistence backend, user/session, and cache generation. Distinct SDK clients, token objects, or memory/disk caches resolving the same credential/cache source are one backing source. |

Every network source also carries one explicit
`sdk_credential_cache_binding`: either tagged `not_applicable` with the SDK's
default/environment/home/metadata caches proved disabled, or tagged `present`
with the complete `sdk_credential_cache` identity and its own backing-source ID.
`not_applicable` cannot hide an SDK-created singleton or cache. If a source and
SDK cache ultimately share token/refresh authority or credential storage, both
resolve to the same private alias group and cannot be split across routes.

Canonical identity enrollment is a separate privileged, gateway-mediated owner
installation transaction. It may derive file/keychain/platform identity under a
non-reading metadata permit, but no route may enroll or choose its own source ID.
Before route registration or startup, the route must atomically claim its already-
enrolled backing-source ID and canonical identity digest in the registry. No
route source open/stat/probe, descriptor creation, keychain resolve, token/cache
lookup, refresh, SDK initialization, DNS, provider evidence, or provider I/O is
permitted before that unique claim. A platform that cannot obtain owner-attested
stable file/item/cache identity without route source access is unsupported until
an accepted owner enrollment mechanism exists; it does not probe first and claim
later.

After claim and before any credential read, a file route opens the exact no-follow
descriptor and verifies descriptor-derived device/inode/generation/mount identity
against the claimed owner record in one TOCTOU-safe sequence. A keychain route
verifies the persistent item ID/generation and user session; workload identity
and SDK routes verify token/refresh/cache authority. Any replacement or mismatch
quarantines the route and never rebinds the claim. Two distinct route IDs,
bindings, wrappers, maps, paths, FDs, keychain references, token objects, or
caches that resolve to one canonical identity cause the later registration to
fail before source/provider access, even when all route config bytes are equal.

Registry lifecycle is `enrolled -> claimed -> retiring -> retired`. Process
crash does not release `claimed`; restart may recover it only for the same route,
profile/route-policy revisions, canonical identity digest, and registry
generation. Hot reload cannot move a claimed source to another route. Release
requires owner-authorized permanent route removal, confirmed source/route
revocation, no active or uncertain fetch/control/lease/exposure row, terminal
cleanup, a durable source-release audit, and CAS to `retired`. The retired
backing-source ID and canonical alias identity remain tombstoned and are never
assigned to another route; a genuinely new owner-enrolled source generation gets
a new ID. Registry corruption, unavailability, stale generation, ambiguous
platform identity, or release-audit failure fails startup and all new provider
work closed.

For `network_service`, `credential_source_profile` is a closed tagged safe route
record. Its `bootstrap_source_binding_id` identifies one immutable private
startup binding for that one `secret_provider_route_id` and exactly one of:

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

Startup negative fixtures vary, one at a time, provider ID, route ID/revision,
source tag/binding ID, workload issuer/subject/identity/refresh owner, owner
descriptor mapping, keychain persistent-reference binding, origin/CIDR, CA
profile, SDK profile/digest, locality, revocation source/generation, and private
object identity. They also use distinct wrappers/source IDs that resolve to the
same workload principal/token/refresh/cache source, separate mappings/paths/FDs
to the same file resource identity, separate keychain mappings to the same item,
and separate SDK clients/caches over the same credential source. Every cross-
route alias/reuse rejects before source access or provider send; equality of every
other byte or inequality of every wrapper ID does not permit sharing. Crash/
restart fixtures recover only the same route claim, and hot reassignment remains
denied until permanent retirement without reusing the backing-source ID.

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
  no request bytes were sent or, for `fetch` only, the provider's accepted
  operation profile proves same-request idempotency. Provider controls retain
  their stricter no-post-send-retry ledger rule. Post-send uncertainty never
  retries or fails over.

The adapter pins a reviewed provider SDK/library version whose maturity evidence
covers TLS behavior, redirect/proxy configuration, response limits, debug/error
redaction, timeout/effect classification, and dependency/supply-chain policy.
Missing origin, identity, CA, revocation, SDK maturity, DNS policy, or bounded
response state fails before send. Provider health cannot override any bootstrap
or transport denial.

## Authority and Gateway Sequence

The only secret-aware target-effect sequence is:

```text
versioned direct request or exact Event/Evidence-observed tagged tick candidate
  -> authenticate + closed-schema validation
  -> tick only: reload/recanonicalize retained candidate and named digest
  -> registered-operation raw-ingress profile + server-derived slot/destination
  -> placement + execution lease + fencing
  -> derive direct/tick outer key; no policy reinvocation or candidate rewrite
  -> tick only: Event/Evidence link CAS wins before expiry and returns the exact
     durable submission/digest-bound receipt
  -> durable outer SecretActionSubmissionId claim
  -> authority evaluates exact SecretLeaseRequest
  -> SecretLease issued without fetching material
  -> existing Action Gateway and every required verifier
  -> approval only: persist exact challenge continuation and return stable
     NeedsApproval with zero effect, or exact receipt continuation re-enters here
  -> private final gateway permit
  -> create one SecretUseAttemptId per ordered requirement
  -> reserve one non-borrowable SecretContainmentReserve unit per use attempt
  -> atomic all-or-none use/lineage reservations + durable secret.use.claimed
     for every requirement
  -> typed node-control plans allocate one parent-aggregate target generation,
     process boundary, fence, exposure/egress controls, detector, and handle per use attempt
  -> durable secret.delivery.requested/secret.provider.fetch.started evidence
  -> exactly one provider fetch per requirement in canonical requirement order
  -> enter SecretAwareActionAdapter and set secret_aware_adapter_entered=true
  -> driver-local resolve_and_deliver consumes slot-indexed SecretDeliveryContext
  -> trusted injection: fresh actual-destination pre-send barrier; or material
     exposure: all SBX-007 network/IPC/proxy/child/external-filesystem egress is
     deny-all and only private broker scratch remains
  -> set target_operation_started=true immediately before target driver effect
  -> exactly one target operation inside the still-live adapter invocation
  -> adapter passes immutable terminal SecretDeliveryControlAttestation and a
     borrowed opaque response view to the gateway continuation
  -> trusted injection only: gateway postconditions and response-projection scan;
     material exposure: fixed suppression projection and private incident scan
  -> adapter wipes raw response/error buffers and returns a byte-free terminal
  -> secret.use.completed
  -> target termination, output drain, decoder finalization, and final seal
  -> immediate delivery/material/detector wipe/cleanup, close or quarantine
  -> non-serializable SecretSubmitCompletion after cleanup certainty is known
  -> GatewaySecretTerminalNormalizer constructs/seals private pending ActionOutcome
  -> Authority records immutable pending outcome + outer terminal intent
  -> common terminal path atomically records one terminal receipt and one final
     effect-terminal action event, then marks outer submission terminal
  -> trusted injection: release sealed public ActionOutcome; material exposure:
     release only fixed terminal/restricted suppression envelope
  -> path-specific outcome/state suffix
```

Required rules:

1. Policy, user space, SDKs, and drivers may propose a typed requirement only. A
   tick candidate must first use the closed additive candidate and durable
   observation contract; policy reinvocation cannot replace observed bytes.
2. The Authority Service validates the ref, principal, work order/capability,
   applicable data-use decisions, workload attempt, operation, placement,
   fencing, audience, purpose, intent, time, and uses before issuing a lease.
3. Lease issuance does not fetch or deliver material and does not execute an
   action.
4. The gateway revalidates live lease/ref/lineage revisions, refresh and
    revocation generations, exact target, expiry, aggregate use budget, policy,
    and all existing verifier categories immediately before its final permit. A
    first approval challenge follows the immutable continuation fork and returns
    before reserve/use/provider/node/adapter work. Continuation revalidates every
    current input and claims only the exact owner receipt before returning here.
5. Through the Authority command/CAS port, the gateway session atomically
    reserves one complete non-borrowable containment unit and the one submission-
    owned use attempt for every ordered requirement as an all-or-none batch,
    increments every affected lease
   and aggregate counter, and durably appends each `secret.use.claimed` before
   target material allocation or provider I/O. A conflict/denial in any member
    aborts the whole batch before node/provider work. Losing final-use races
    append only `use_denied`; their
   provider/material/driver counters remain zero. Every committed reservation is
   conservatively consumed.
6. A target generation, process boundary, fence, detector, exposure/egress
   controls, and handle
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
   slot-indexed driver-local delivery, exact exposure-profile admission,
   immediately before adapter entry and every credential-bearing send/target
   invoke, the terminal control
   attestation, gateway-owned postconditions, scanning/sealing, output drain,
   wiping, and cleanup classification. Every callee receives only the scoped
   borrow/linear value named by the staged ABI.
9. The driver owns raw provider/target response and error buffers. For
   `trusted_injection`, while they are still opaque and driver-owned, it lends the
   gateway continuation a bounded postcondition view and proposed public
   projections; the gateway scans them before the driver wipes/drops raw buffers.
   For `material_exposed`, the continuation accepts no proposed projection or
   target-result postcondition: captured bytes flow only to private detector/
   incident processing and the fixed suppression projection is selected before
   exposure. After the adapter returns byte-free, the session drains every
   delayed target source and finalizes decoders. No generic JSON, error string,
   result choice, exit code, target timing, artifact, state patch, or trace payload
   crosses or leaves the session.
10. Cleanup is mandatory on success, denial after reservation, provider failure,
    driver failure, postcondition failure, cancellation, timeout, unwind, or
    uncertain effect. The session owns cleanup independently of the context and
    driver. An uncertain or failed drop/wipe/control step is cleanup uncertainty,
    never success. Panic-abort/process death leaves the durable attempt for node
    reconciliation and quarantine.
11. Stable public `ActionStatus` values and meanings do not change. Before entry
    into `SecretAwareActionAdapter`, verifier/policy denial is `Denied`, approval
    is `NeedsApproval`, and unresolved provider/allocation/cancellation/runtime
    failure is `NeedsIntervention`; all mean adapter execution did not occur. The
    stable `NeedsApproval` gateway attempt may leave only the C03 parent in
    `awaiting_approval`; it is never revised in place. The exact receipt retry is
    a separately recorded continuation under the same parent/action coordinate,
    not a new status or scheduler tick.
    Once the method is entered, complete `trusted_injection` success is
    `Executed` and every delivery, target, postcondition, scan, cancellation,
    timeout, cleanup, evidence, or revocation failure/uncertainty is `Failed`,
    even when the target operation never started. Once material is exposed, the
    internal stable result is always the fixed `Failed` suppression projection
    regardless of target return, while public result APIs return only the fixed
    terminal/restricted suppression envelope; restricted lifecycle evidence still
    records actual effect certainty. Provider/target/outer effect certainty
    remains explicit in restricted owner records. Post-effect
    intervention/quarantine is a separate C03/run fact, not a false
    `NeedsIntervention` action status.
12. `SecretSubmitCompletion` is consumed by the Gateway-owned
    `GatewaySecretTerminalNormalizer` shared by tick and direct submissions. It
    authenticates the sealed bytes, constructs and seals the one private pending
    stable `ActionOutcome`, checks the
    status/adapter-entry/target-start/provider-node-target-certainty/publication
    matrix, including the one fixed material-exposed suppression projection,
    verifies Authority persisted those exact pending bytes and terminal intent,
    and atomically appends exactly one `SecretDeliveryReceipt` and exactly one
    final effect-terminal `action.*` event. An approval parent may already have
    exactly one zero-effect `action.needs_approval` attempt event; that event has
    no delivery receipt and is not rewritten.
    A failed postcondition emits only `action.failed`, never `action.executed`
    followed by `action.failed`. This one-terminal rule is the explicit
    experimental wrapper correction; stable non-secret submissions remain
    byte-for-byte unchanged pending any broader trace migration.
13. A tick-owned action that did not pause for approval then emits
    `outcome.recorded`, performs its explicit state commit, and emits
    `tick.completed`. The original approval-required tick completes its unchanged
    stable challenge suffix. Its later receipt continuation and a direct action
    emit `outcome.recorded` only and invent no new tick or state event. All paths
    use the same final normalizer and receipt. Gateway session/orchestrator,
    provider, node, and driver emit no outer `action.*` event.
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
  {secret_lease_id, secret_exposure_lineage_id, lineage_target_generation,
  delivery_handle_id, process_boundary_id}`.
- `SecretContainmentTarget` is `ref {secret_ref_id, secret_ref_revision}`,
  `lease {secret_lease_id, secret_lease_revision}`, `delivery
  {secret_lease_id, secret_exposure_lineage_id, lineage_target_generation,
  delivery_handle_id, delivery_generation}`, `process
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

### Permanent non-reuse, retention, and compaction

No accepted identity or effect coordinate may become a fresh lookup miss after a
full record, receipt, result, evidence bundle, or hot index reaches configured
retention. Before any such deletion, Authority, or Event/Evidence solely for its
tick observation, writes one immutable compact
`splendor.secret.consumed_effect_tombstone.v1`. The record contains exactly its
schema, nominal `secret_consumed_effect_tombstone_id`, one complete closed
`domain_binding` below, one domain-valid `disposition`, one named
`disposition_digest`, one complete `authority_domain`, one
`marker_slot_binding`, `consumed_at`, `compacted_at`, and one
`previous_marker_binding`. `compacted_at >= consumed_at`.
`marker_slot_binding` is exactly `normal {slot_id}` or
`containment_emergency {secret_containment_reserve_id,slot_ordinal,slot_class}`
for the primary consumed identity. The emergency form must match a durable pre-
exposure reservation and cannot be invented at compaction.
`previous_marker_binding` is exactly `genesis` or
`present {previous_marker_id,previous_marker_integrity_digest}` in the same
trusted partition/authority domain. Null, omission of a required tag, unknown or
cross-tag fields, and an out-of-sequence previous marker reject.
`previous_marker_id` is itself a closed tag containing exactly one nominal
consumed-effect tombstone, permanent auxiliary marker, or retired-domain marker
ID; untagged UUIDs are invalid.

The tagged `domain_binding` union is complete:

| Tag | Trusted partition and consumed identity | Required accepted binding digests | Effect coordinate | Allowed disposition and named disposition digest |
| --- | --- | --- | --- | --- |
| `direct_outer` | `trusted_partition_digest` from `splendor.secret.action_submission_partition_digest.v1`; direct idempotency key and submission ID | exact direct ingress digest, direct semantic request digest, outer-idempotency digest, wrapper digest, and submission digest | original closed action-or-invocation effect coordinate | `terminal|effect_uncertain`; `splendor.secret.outer_tombstone_disposition_digest.v1` |
| `tick_outer` | the same submission partition profile; observation ID, submission ID, run/tick/ordinal | policy-output digest, retained-candidate digest, candidate-semantic digest, tick-key digest, observation-link-receipt digest, outer-idempotency digest, wrapper digest, and submission digest | original closed action-or-invocation effect coordinate | `terminal|effect_uncertain`; `splendor.secret.outer_tombstone_disposition_digest.v1` |
| `approval_challenge_continuation` | original submission partition digest; continuation, submission, approval, obligation, and authority-decision IDs plus explicit `receipt_id_binding=absent|present` | approval-challenge digest, approval-continuation semantic digest, original wrapper digest, original submission digest, and `continuation_receipt_digest_binding=absent|present` matching the receipt-ID tag | complete original action/invocation coordinate plus exact challenge/obligation coordinate | `terminal|effect_uncertain|cancelled|denied|expired|revoked`; `splendor.secret.approval_continuation_tombstone_disposition_digest.v1` |
| `provider_control` | `splendor.secret.provider_control_partition_digest.v1`; provider-control invocation ID | provider-control plan digest and trusted partition digest | provider trust scope, provider ID, route ID/revision, operation, and complete target-scope digest | `terminal|effect_uncertain`; `splendor.secret.provider_control_tombstone_disposition_digest.v1` |
| `node_control_target_generation` | `splendor.secret.node_control_partition_digest.v1`; node-control invocation ID, exposure-lineage ID, and target generation | node-control plan digest, target-binding digest, and trusted partition digest | tenant/node/instance, exposure-lineage ID, target generation, operation, and target-binding digest | `terminal|effect_uncertain`; `splendor.secret.node_control_tombstone_disposition_digest.v1` |
| `tick_observation` | `splendor.secret.tick_candidate_observation_partition_digest.v1`; observation ID and run/tick/ordinal | policy-output, retained-candidate, and candidate-semantic digests | `observation {run_id,tick_id,candidate_ordinal}`; never an action/invocation | `expired_unclaimed|linked_submission_terminal|linked_submission_uncertain`; `splendor.secret.tick_observation_tombstone_disposition_digest.v1` |

Emergency non-primary identities use the separate closed
`splendor.secret.permanent_auxiliary_identity_marker.v1`. It contains exactly its
schema, nominal `secret_permanent_auxiliary_identity_marker_id`, complete parent
authority domain, parent primary tombstone ID/integrity
digest, containment reserve ID, slot ordinal/class, one closed
`auxiliary_identity`, `claimed_at`, `marked_at`, and previous-marker binding. The
identity is exactly one of `provider_reconciliation_claim`,
`node_reconciliation_claim`, `delivery_control_attestation`,
`terminal_delivery_receipt`, `cleanup_command`, `consumed_tombstone`, or
`incident`, each with its matching nominal ID and no cross-tag field. Its named
`splendor.secret.permanent_auxiliary_identity_marker_integrity_digest.v1`
projection contains the digest schema, marker record schema, and every other
field; the output is external. Exact duplicate bytes return the same marker;
changed parent, reserve, slot, class, identity, time, or chain pointer conflicts
and quarantines the parent domain. This closed marker, not an open tombstone tag,
keeps every claimed auxiliary ID non-reusable after its full owner record is
deleted. Its maximum canonical size is 2 KiB and the maximum fixture is pinned.

`splendor.secret.tick_candidate_observation_partition_digest.v1` contains
exactly its schema, tenant ID, agent ID, and run ID. The approval-continuation
semantic digest uses named projection
`splendor.secret.approval_continuation_semantic_digest.v1`, containing its digest
schema plus every immutable `splendor.secret.approval_continuation.v1` field in
the continuation section except the digest output; no implementation-local
summary may substitute.
`splendor.secret.provider_control_target_scope_digest.v1` contains exactly its
schema and the complete closed tagged provider-control `target_scope` from the
accepted plan, including every tag-specific ID/revision/generation; it excludes
the digest output. The provider tombstone effect coordinate uses only this named
digest, never an implementation-local target summary.

The named disposition projections are closed rather than a generic terminal
status hash:

- `splendor.secret.outer_tombstone_disposition_digest.v1` contains its schema,
  submission ID, exact disposition, final stable status binding, outer effect
  certainty, terminal-intent digest binding, delivery-receipt ID/digest binding,
  outer-terminal-event binding, and complete publication binding. A terminal
  disposition requires every present terminal field; `effect_uncertain` requires
  explicit absent/present tags for each retained pointer and outer certainty
  `uncertain`.
- `splendor.secret.approval_continuation_tombstone_disposition_digest.v1`
  contains its schema, continuation/submission/approval/obligation IDs, exact
  disposition, challenge outcome/event bindings, receipt claim/digest binding,
  final delivery-receipt/outer-event bindings, and completion-time binding.
  `cancelled` requires only its run-cancellation event; `denied|expired|revoked`
  require the exact no-effect final pair; `terminal|effect_uncertain` preserve
  their exact claimed-receipt and final/uncertain pointers.
- `splendor.secret.provider_control_tombstone_disposition_digest.v1` contains
  its schema, invocation ID, exact disposition, result outcome, retry count,
  effect certainty, provider-audit ID, result digest, terminal-intent digest,
  completed-event ref, and ordered Authority lifecycle-event refs. Terminal
  requires the complete retained bundle; uncertainty uses explicit pointer tags
  and certainty `uncertain`.
- `splendor.secret.node_control_tombstone_disposition_digest.v1` contains its
  schema, invocation ID, exposure-lineage ID, target generation, exact retry
  profile, disposition, owner outcome, retry count, send disposition, effect
  certainty, result/terminal-intent/receipt/completed-event bindings, and ordered
  Authority lifecycle-event refs. Terminal requires the complete retained
  bundle; uncertainty preserves every known pointer and uses explicit absence.
- `splendor.secret.tick_observation_tombstone_disposition_digest.v1` contains its
  schema, observation ID, claim-state terminal revision/sequence, exact
  disposition, expiry, expiry-tombstone binding, and a link-receipt/submission
  binding. `expired_unclaimed` requires the expiry tombstone and forbids link/
  submission fields. A linked disposition requires the exact link receipt and
  submission ID/digest tuple and forbids an expiry winner.

Every disposition projection is validated, JCS-encoded, and hashed under its own
exact schema prefix by the common C03 rule. Its output is stored as
`disposition_digest` in the tombstone and is not a projection input. There is no
field or profile named `accepted_semantic_digest` or `terminal_status_digest`;
implementations cannot select one digest by convention. Tombstones contain no
protected output, target-controlled status/error, action params, complete secret
requirements, ref/lease/handle/provider metadata beyond the minimum closed
route/effect coordinate, evidence body, raw receipt, credential, material,
endpoint, locator, or error. Maximum canonical size is 2 KiB and V1 pins every
maximum tag.

`tombstone_integrity_digest` is the output of closed projection
`splendor.secret.consumed_effect_tombstone_integrity_digest.v1`, containing
exactly its digest schema, the record schema as `tombstone_schema_version`,
tombstone ID, complete domain binding, disposition, disposition digest, complete
authority domain, marker-slot binding, both times, and previous-marker binding.
The digest output is external and excluded. The authoritative marker index stores
the tombstone ID/digest and enforces one hash chain per trusted partition plus
authority domain. Missing, forked, reordered, or mismatched chain state is
corruption and fails closed.

`authority_domain` is exactly one of:

```text
run { tenant_id, run_id }
provider_route {
  provider_trust_scope, secret_provider_id, secret_provider_route_id,
  route_policy_revision
}
node_generation {
  tenant_id, node_id, instance_id, secret_exposure_lineage_id,
  target_generation
}
```

Direct/tick outer, approval, and observation tags require their matching run
domain; provider control requires its exact route domain; node control requires
the exact lineage-scoped node-generation domain. Independent lineages on the same
node may each use generation `1` and have different domains, partition digests,
marker chains, lookup keys, and retirement decisions. A handle, use attempt,
node plan/result/receipt, cleanup command, restart/migration record, or compaction
record lacking the same lineage ID is invalid and quarantines rather than
retiring another lineage.

Long-term marker capacity is distinct from ordinary durable records and from the
containment emergency marker pool defined by FND-012 below. Each node configures
positive `max_unretired_consumed_identities_node` and each active tenant/node
configures an equal-or-lower `max_unretired_consumed_identities_tenant`; normal-
pool minima are 4,096 and 1,024. At 2 KiB per marker, normal non-borrowable floors
are at least 8 MiB node and 2 MiB per tenant/node. Before accepting a normal
outer, continuation, provider-control, node-control, or observation identity, the
owner reserves one normal slot from both scopes. A containment identity instead
must claim its exact already-reserved emergency slot and cannot consume normal
capacity. A retired-domain marker remains in the same pool/slot class as the
individual markers it replaces. Full or uncertain capacity rejects the new
identity before acceptance/effect; it never deletes an existing marker or
borrows the other pool.

The lookup rule is fail closed and precedes coordinate allocation, current
attempt derivation, policy/provider/node work, or effect:

- an exact ID/partition/effect/digest tombstone returns only the original safe
  terminal/uncertain/cancelled/expired disposition while full records exist, or
  the restricted non-retryable `consumed_effect_retired` result after protected
  records expire; it never recreates output, authority, a receipt, or a wrapper;
- the same ID or effect coordinate with a changed digest returns the domain's
  idempotency conflict; hidden scope uses the uniform not-available profile;
- `effect_uncertain` remains uncertain permanently unless the original retained
  terminal intent completes under its unique IDs; deletion never converts it to
  no-effect; and
- missing, corrupt, unavailable, stale, or ambiguously replicated tombstone state
  denies every new effect in that partition. It is never treated as a miss.

After protected/full records are deleted, equality is exactly the complete
domain binding, disposition digest, effect coordinate, authority domain, marker-
slot binding, and integrity-chain position above. An incoming exact duplicate
must reproduce every required accepted binding digest and returns only the same
restricted disposition. Any changed accepted field or digest is the domain's
idempotency conflict. A different identity with the same effect coordinate is
also conflict through the permanent effect index. Missing incoming comparator
fields, an unknown old schema, or inability to verify the chain denies; no owner
reconstructs equality from deleted bytes.

Outer direct/tick submissions retain both key and action/invocation coordinates;
approval tombstones retain challenge and semantic receipt coordinates; provider
controls retain invocation/route/target plan coordinates; node controls retain
invocation/target generation; expired unclaimed observations retain their
observation/candidate digest. `SecretActionIdempotencyKey`, observation,
submission, continuation, approval/challenge, provider-control, node-control,
action/invocation, and target-generation identities are never reused, including
after process restart or authority-domain retirement.

Compaction order is deterministic and transactional:

1. Active, nonterminal, reconciling, awaiting-approval, continuing, or uncertain
   rows and their reserve/evidence are ineligible for destructive compaction.
2. For an eligible full terminal or expired-unclaimed record, validate its
   partition, semantic digest, effect coordinate, disposition, and terminal
   intent/receipt/event integrity.
3. Insert-or-verify the exact tombstone under unique domain/identity/effect keys
   and durably append `secret.retention.tombstone_committed` with owner, policy
   revision, source record digest, and no protected payload.
4. Re-read and verify the tombstone from the authoritative store. Only then may
   configured retention remove protected output, full plan/result/intent/
   evidence, observation candidate bytes, or the hot pointer, in that order.
5. Append `secret.retention.full_record_deleted`; append failure leaves the
   tombstone and conservative deletion-pending state and cannot rearm work.

Eligible records order by `(compacted_at eligibility time, domain enum spelling,
trusted_partition_digest, consumed nominal UUID bytes)`. Quota pressure rejects
new outer/control/observation claims before deleting, weakening, or rearming a
tombstone. Tombstone storage and its write budget are non-borrowable containment
capacity and are excluded from user retention quotas.

Individual tombstones survive hot/full retention until the owning authority
domain is permanently retired. Retirement requires current Authority plus the
run/provider-route/node owner, a closed signed/typed retirement decision, proof
that no active/uncertain/continuable row or exposure exists, and a durable
`splendor.secret.retired_authority_domain_marker.v1` deny marker plus audit event.
The trusted retirement-partition digest is the common C03 digest of exact
projection `splendor.secret.retired_authority_domain_partition_digest.v1`, which
contains only its schema and the complete closed authority domain above.
That marker contains exactly its schema, nominal
`secret_retired_authority_domain_marker_id`, complete authority domain, trusted
retirement-partition digest, positive final owner generation/revision, retirement
`retirement_authority_decision_id: AuthorityDecisionId`, ordered 1-16 unique
`EvidenceId` values, `retired_at`, positive
`replaced_marker_count`, first and last replaced primary-or-auxiliary marker
IDs/integrity digests, marker-slot binding, and previous-marker binding. It has no optional or
free-form field and no protected output, secret-use metadata, evidence body,
target result, credential, or error.

`retired_domain_marker_integrity_digest` uses exact projection
`splendor.secret.retired_authority_domain_marker_integrity_digest.v1`, containing
its digest schema, marker record schema, and every other marker field; the digest
output is external and excluded. Uniqueness is the complete authority domain.
Exact duplicate retirement bytes return the same marker/digest; a changed final
revision, decision, evidence order, marker range/count, slot, chain pointer, or
time conflicts and quarantines the domain. Marker range/count includes every
primary tombstone and permanent auxiliary identity marker in canonical chain
order. Marker commit and its integrity digest
are atomic. After verification, every request in the retired domain rejects
before per-ID lookup or effect; individual tombstones may then be deleted in
canonical chain order, but IDs and the domain can never be reopened or reassigned.
Retirement marker corruption, fork, or unavailability denies the complete domain.
The retired marker's maximum canonical size is 2 KiB; V1 pins the 16-evidence
maximum, every authority-domain tag, and both previous-marker variants.

Replay reads full records, tombstones, and retired-domain markers as historical
facts only. It reports whether duplicate safety comes from a full row, compact
tombstone, or retired-domain deny marker and never calls policy, claims an ID,
restores protected output, or performs provider/node/adapter/target work.
Retention fixtures expire full records for every direct/tick outer, approval
continuation/challenge, provider control, node control/target generation, and
unclaimed observation; exact and changed duplicates across restart still return
original safe disposition/conflict with zero effects. Corruption/unavailability,
concurrent compaction/duplicate, quota exhaustion, deletion-audit failure, and
domain retirement/reopen attempts all fail closed. Canonical fixtures pin every
domain tag, every named disposition projection/integrity digest, required/
forbidden field matrix, exact/changed post-deletion equality, and two independent
lineages with the same node/instance/generation where retiring one never affects
the other.

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
method child. The Authority-owned `SecretUseAttempt` row is the sole generation
binding owner: it binds that generation to one use attempt, workload attempt,
outer submission/effect coordinate, method, and complete process/audience/fence/
slot/destination target. After `prepare_delivery`, the one
`SecretDeliveryHandle` repeats the exact use-attempt/generation/target binding for
validation and cleanup; it does not create a namespace. The
`SecretExposureMethodChild` records only method/control-profile state and never
owns a target generation. A mismatch between parent active/pending generation,
use-attempt row, handle, or node-control target is uncertainty and quarantines;
recovery reads those same records and cannot allocate a competing generation.
The generation cannot become active until the prior target across every method
child is fenced and cleanup is terminal; uncertainty quarantines the parent.
Same-attempt renewal and later-attempt retry allocate a fresh use attempt and
generation but preserve every parent fact. Rotation to a new ref
revision creates a new parent only after the old target is fenced as required by
the rotation contract.

## Delivery and Cleanup

### Delivery exposure and egress profiles

Destination metadata is not sufficient enforcement after material exists. Every
registered driver slot selects exactly one immutable
`SecretDeliveryExposureProfile`; request, policy, provider, and target code cannot
change it. The profile, driver declaration revision, exact destination binding,
and required control-profile digest are carried through ref authorization, bound
requirement, lease, use attempt, permit, delivery handle/context, node-control
target, attestation, receipt, and parent aggregate.

`trusted_injection` is the preferred profile. Secret bytes never enter user code,
general-purpose target code, its addressable buffers, arguments, environment,
filesystem, IPC, child process, model prompt, or output. A driver-owned typed
client, local credential-injecting proxy, cryptographic service, or device-local
service retains the material and injects it only into the exact nominal
credential slot while sending to the approved validated destination. Immediately
before every credential-bearing send, the gateway-owned continuation consumes a
fresh `trusted_injection_boundary` pre-send evidence ref and revalidates the
actual origin/service/account/resource/device, route revision, TLS/peer identity,
selected IP, DNS answers, fixed proxy identity, redirect state, and transport
binding against the destination projection. Redirects are disabled. DNS
rebinding, a changed or mixed answer set, environment/system proxy discovery,
proxy failover, alternate origin/account/database/model endpoint/device/resource,
credential forwarding, and transport re-resolution outside that exact binding
deny before send. A connection pool or cached channel may be reused only while
the evidence owner proves the exact pinned peer/destination and current
revocation/fence; uncertainty closes it. The driver-owned injector cannot expose
an accessor returning material to target code.

`material_exposed` means the exact bound target process may observe bytes. It is
allowed only when accepted compatible `SBX-007`, `NODE-003`, `SBX-001`, and
Event/Evidence owner contracts define and implement one closed
`SecretMaterialExposureEnforcementProfile` for the exact sandbox/process,
destination, slot, and target generation. In C03 v1 that profile is local-
processing-only and enforces **deny-all material egress** before acquisition and
through cleanup. Destination authorization remains bound evidence but grants the
material-exposed process no right to send there.

The host/runtime owner must prove all of these before provider acquisition:

- no network namespace route, DNS, raw/managed socket, packet interface, fixed or
  discovered proxy, loopback/control/metadata endpoint, provider-facing channel,
  or credential-backed network authentication is reachable;
- no Unix/domain socket, pipe to another process, shared memory, signal payload,
  local RPC, clipboard, device channel, or other IPC egress is reachable;
- no fork/exec/clone, child process, helper, inherited descriptor, debugger, or
  process-control path can carry material outside the one admitted process;
- no workspace, output mount, artifact/data mount, host path, externally writable
  filesystem, procfs, device, alternate mount, remount, bind mount, image layer,
  or persisted cache can receive material; and
- no namespace, syscall, capability, local service, or runtime API bypasses those
  denials.

The only writable storage is private broker-owned scratch inside the exact
accepted sandbox/target generation. It is not mounted into a workspace, output,
artifact, sibling, child, helper, or external process; its configured maximum is
the already admitted per-invocation 1-MiB captured-output queue plus the bounded
64-KiB delivery object, and overflow quarantines rather than spills. Captured
stdout, stderr, result, crash, exit, signal, and timing bytes remain inside this
private scratch solely for detector and restricted incident-evidence processing.
They are never returned or persisted in an ordinary outcome, error, state,
trace, event projection, artifact, dataset, checkpoint, observability export, or
replay export, even when every bounded detector reports no match. After detector
finalization, the owner wipes them; uncertainty quarantines the scratch under the
existing incident-retention rule and still releases no byte. Scratch is never an
outbound credential slot or publication path.

C03 v1 has no target-controlled declassifier. A material-exposed registration
therefore fixes before exposure one broker-owned publication deadline and the
single `target_publication_suppressed` terminal projection. Early target exit,
chosen delay, exit status, output length/content, valid JSON shape, error/result
branch, and chunk schedule neither release a response early nor select its
fields. A workload that needs returned target data, an artifact/state patch, or
network/IPC authentication must instead use `trusted_injection`, where target
code never sees material, or wait for a separately accepted trusted-declassifier/
noninterference owner contract. This RFC does not design or authorize that future
contract.

Any operation that needs outbound credential use, including HTTP/database/model/
artifact/orchestrator/device authentication, must use `trusted_injection`. There,
material remains in a driver-owned protocol-aware injector and may appear only in
the exact nominal credential slot of the complete actual request for the exact
revalidated destination. Wrong header, query, path, body, protocol frame, account,
resource, redirect, DNS answer, proxy, peer, or transport binding denies before
send. Those destination/slot mediation responsibilities never move to general-
purpose material-exposed code.

The enforcement owner places an unskippable zero-byte deny barrier on every
attempted network, IPC, proxy, child, externally writable filesystem, mount,
device, or helper operation. A destination allowlist, library hook, prompt,
environment hint, driver declaration, output scanner, after-send DLP, or post-hoc
cleanup is not enforcement. The target receives bytes only after all deny-all and
private-scratch evidence is durable. If any backend cannot prove deny-all before
provider acquisition/exposure, that profile denies; there is no destination-
allowlisted or degraded material-exposed mode in v1.

`SecretEgressEvidenceRef` uses closed schema
`splendor.secret.egress_evidence_ref.v1` and contains exactly `schema_version`,
`evidence_id`, `tenant_id`, `secret_action_submission_id`,
`secret_use_attempt_id`, `delivery_handle_id`, target/delivery generations,
`secret_exposure_lineage_id`, complete execution and credential-destination
bindings, exposure profile,
enforcement-profile schema/revision/digest, one phase from
`pre_exposure|pre_send|post_send|terminal_absence`, optional
`attempted_operation_sequence`, one control kind from the seven egress/injection
control kinds below, one closed `disposition` from
`control_installed|allowed_nominal_slot|denied_zero_bytes|control_closed`,
`observed_at`, and `causal_ref`.
`attempted_operation_sequence` is a positive JSON integer no greater than
`9007199254740991`, required for `pre_send|post_send`, equal within a matched
pair, and forbidden for `pre_exposure|terminal_absence`; null is invalid.
Evidence is restricted and byte-free. The Evidence owner validates attester,
integrity, freshness, phase order, exact destination/target binding, and actual
host/transport state before returning a private wrapper. A URI, raw evidence ID,
copied record, user assertion, stale observation, missing phase, or digest-only
claim cannot satisfy a barrier.

Evidence phases are not implementation-selected. Every applicable control has a
`pre_exposure` fact before material delivery and a `terminal_absence` fact after
its enforcement object is closed; terminal absence proves control/handle closure,
not erasure from target memory. `trusted_injection_boundary`,
`destination_network_egress`, `ipc_egress`, and `proxy_egress` additionally have
one fresh `pre_send` and one matching `post_send` fact for each attempted
credential-bearing write; only its exact injector may use
`allowed_nominal_slot`. Under `material_exposed`, every attempted network,
filesystem, IPC, child-process, proxy, device, helper, or alternate-mount sink has
one fresh `pre_send` decision and one matching `post_send` fact, both bound to
`denied_zero_bytes`, before a later attempt. An `allowed_nominal_slot` disposition
under material exposure is invalid. The typed owner evidence behind each ref must
prove the operation was intercepted before any payload byte; an after-send scan
cannot create that fact. Phase
order is fixed by owner sequence, and evidence is unique by
`(secret_use_attempt_id, delivery_handle_id, target_generation, control_kind,
phase, attempted_operation_sequence)`. Missing, duplicate, reordered, or
cross-attempt phase evidence fails closed.

The exposure-profile control matrix is closed. `R` means `status=applied` with
matching typed evidence; `N/A` means `status=not_applicable` only with the applied
profile boundary evidence proving target code never received material.

| Profile | trusted injection boundary | destination network egress | filesystem sink egress | IPC egress | child-process egress | proxy egress | alternate-mount egress |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `trusted_injection` | R | R for a network destination, otherwise N/A | N/A | N/A | N/A | R for a configured fixed proxy, otherwise N/A | N/A |
| `material_exposed` | N/A | R deny-all | R deny-all except private broker scratch | R deny-all | R deny-all | R deny-all | R deny-all |

Shell, Python, OCI, Kubernetes, model, data, and other general-purpose code may
receive material only under `material_exposed` with that complete accepted owner
profile. Otherwise the driver must use `trusted_injection` without exposing bytes
or deny before provider acquisition/delivery. Neither profile grants low-level
physical actuator access: a physical destination remains a registered high-level
device service behind local safety veto and real-time control boundaries.

Any denied/uncertain pre-send barrier, unexpected DNS/proxy/peer/route change,
alternate-sink attempt, missing post evidence, or owner-control loss immediately
blocks all further work, fences/quarantines the exact process and parent exposure,
revokes/closes delivery, retains detectors through bounded drain, records typed
containment evidence, and prevents success/publication. Cleanup cannot relabel a
possible exfiltration as absent. Replay inspects these records only and cannot
open a socket, resolve DNS, inspect a live mount/process, recreate a proxy, or
re-run a barrier.

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
- for `trusted_injection`, stdout/stderr, process args, environment snapshots,
  manifests, metrics, and debug bundles scanned before ordinary persistence; for
  `material_exposed`, captured target bytes remain private detector/incident input
  and are never ordinarily persisted regardless of scan result;
- child inheritance denied unless the child is the exact bound process;
- workspace, image-layer, artifact, swap, page-dump, and generic cache writes
  denied for secret material;
- target termination, FD/socket closure, unmount/deletion, and revocation
  acknowledgement on completion, cancellation, expiry, quarantine, node drain,
  or process crash.

The detector registration, process quarantine fence, and delivery context remain
live through target termination, complete stdout/stderr/adapter-output drain,
bounded decoder finalization, every trace/state/event/artifact/dataset/error/
observability persistence or publication decision, and cleanup evidence. Detector
key destruction and deregistration occur only after the final scan has no pending
overlap bytes and every publication decision is terminal.

For `trusted_injection`, before teardown the barrier may seal exact scan-approved
public output bytes, sanitized public error projection, and postcondition evidence
plus their BLAKE3 integrity digests in a private non-cloneable
`SealedSecretActionProjection`. Later outer recording consumes only those exact
bytes after verifying every digest. For `material_exposed`, that sealed type has
no byte-bearing variant: it contains only the fixed broker-owned suppression
disposition, fixed stable failure/error projection, and bounded control counters
whose values are fixed by the admitted profile rather than target output. Raw
target/driver response, error, postcondition, exit, and timing bytes never enter
`ActionOutcome`, ordinary traces/events, state, artifacts, or errors. No scan
result can promote them to publishable. Restricted detector/incident owners may
retain only the keyed leak token, closed representation/control enums, nominal
evidence/incident IDs, and fixed bounded counters; raw captured bytes remain
private until wiped or quarantined and are unavailable through result inspection.
No later adapter/provider/target callback can alter or append public bytes. The
stable non-secret path remains unchanged. `secret.delivery.closed` is the last
C03 delivery event. Opaque, transformed, too-large, truncated, decoder-incomplete,
or undrained material-exposed output changes only restricted containment handling,
never the fixed public projection. Cleanup uncertainty keeps the fence and
detector available for reconciliation or records why secure retention is
impossible; it never emits `closed` or a target-derived result.

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
That new read-only audit has a fresh provider-control invocation ID and durable
ledger; it cannot reuse or terminalize the uncertain revoke by inference. The
original revoke row remains immutable and is never sent again.

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
  known no-effect or, for fetch only, provider-declared idempotency; provider
  controls retain the stricter no-post-send-retry ledger rule; latency buckets,
  health, circuit state, and sanitized audit correlation;
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
| Idempotency/replay state | At most 4,096 hot command/use-attempt/submission-index/provider-control/node-control entries per node and 1,024 per tenant/node, at most 2 KiB each; 8 MiB node / 2 MiB tenant ceiling. Active outer/approval/provider/node uncertainty cannot be evicted. Exact provider/node hot schemas are at most 1,024 bytes. Full terminal intents, receipts, plans/results/audits/evidence, pending sealed outcomes, permanent tombstones, and retired-domain markers are excluded from the hot-entry size claim and use separately controlled durable storage. Each delivery receipt is at most 512 KiB; outcomes obey the endpoint bound. Retention never deletes a tombstone or active uncertainty to admit work. |
| Normal permanent non-reuse marker store | Configure positive node and active-tenant maxima with minima 4,096/1,024 unretired normal identities. At 2 KiB per tombstone or retired-domain marker, non-borrowable normal floors are at least 8 MiB node / 2 MiB tenant. One normal slot is reserved before each accepted non-containment identity; exhaustion denies before effect. Normal identities cannot consume emergency slots. |
| Emergency permanent-marker store | Every containment unit atomically reserves exactly 17 typed emergency marker slots before exposure: 2 provider-control invocations, 8 node-control invocations, 2 reconciler claims, 1 delivery-control attestation, 1 terminal delivery receipt, 1 cleanup command, 1 consumed tombstone, and 1 incident identity. For 64 node/16 tenant units this is 1,088/272 slots and exact separate hard 2,176/544-KiB floors at 2 KiB each. Used slots remain charged after tombstone commit; unused slots return only on verified reserve release. Domain retirement may replace same-domain used markers but never reopen an ID. |
| Tick observation durability | At most 16 C03 observations per policy output and 1 MiB canonical candidate bytes per observation, hence at most 16 MiB candidate bytes in one atomic batch. The Event/Evidence writer streams the quota-controlled durable batch without retaining a second hot copy. Unclaimed expiry is exactly 5 minutes minimum, `tick_deadline + 60 seconds`, and 24 hours maximum under the recorded policy revision. Link and expiry CAS the same owner row; at/after expiry only the winning digest tombstone remains effect-ineligible, while a winning exact link receipt pins candidate bytes through outer terminal/retention. This durable budget is excluded from the in-memory equation below and storage uncertainty rejects the whole batch before outer claim. |
| Fixed restricted metadata | At most 8 MiB node / 2 MiB tenant for lineage indexes, control plans, and admission bookkeeping. |
| Non-borrowable containment hot reserve | Preprovision 64 `SecretContainmentReserve` units per node and 16 per active tenant/node. Each unit has 14 entries at at most 2 KiB; 1,792 KiB node and 448 KiB tenant are rounded up to hard 2 MiB node / 512 KiB tenant pools. Normal work cannot consume them. |
| Non-borrowable containment durable reserve | Each reserve unit owns exactly 4,768 KiB durable bytes, 552 event/evidence credits, and one incident credit under the exact derivation below. Floors are 298 MiB/35,328 event-evidence/64 incident credits per node and 74.5 MiB/8,832 event-evidence/16 incident credits per active tenant/node. Tombstone/retirement transactions debit this reserve, while retained markers remain charged to the separate typed emergency marker store. |
| Total restricted node/tenant memory | 98 MiB node and 24.5 MiB per tenant/node: 96/24 MiB normal plus 2/0.5 MiB containment hot reserve. No category or tenant may borrow containment capacity. There are at most 16 requirements per action. Durable reserve bytes are storage admission, not resident-memory claims. |
| Output drain | 30 s maximum after target exit/cancel. Trusted-injection timeout quarantines and prevents terminal success/publication. Material-exposed bytes are never publishable; timeout changes restricted containment evidence only and retains the fixed suppression projection. |
| Local cleanup | 10 s maximum for FD/socket close, unlink/unmount, projection deletion acknowledgement, and detector finalization; timeout is cleanup uncertainty. |
| Provider revoke acknowledgement | 5 s maximum; timeout remains effect-uncertain and cannot report revoked success. |
| Soak | 24 hours, at least 100,000 lease/use/cleanup cycles, maximum cardinality for at least one hour, zero leaked canaries, zero target-controlled material-exposed publication, zero duplicate effects, zero unbounded queue growth, and memory after cleanup within 5% of the post-warmup baseline. |

The static admission inequality is mandatory and uses configured maxima, not
observed averages:

```text
(64 detectors * 512 KiB)
+ (16 invocations * 8 sources * 256 KiB overlap)
+ (16 invocations * 1 MiB queued)
+ (4096 hot entries * 2 KiB)
+ 8 MiB fixed metadata
= 96 MiB normal node maximum
+ 2 MiB non-borrowable containment hot reserve
= 98 MiB total node maximum

(16 detectors * 512 KiB)
+ (4 invocations * 8 sources * 256 KiB overlap)
+ (4 invocations * 1 MiB queued)
+ (1024 hot entries * 2 KiB)
+ 2 MiB fixed metadata
= 24 MiB normal tenant/node maximum
+ 512 KiB non-borrowable containment hot reserve
= 24.5 MiB total tenant/node maximum

64 node reserve units * 14 entries * 2 KiB = 1,792 KiB <= 2 MiB
16 tenant reserve units * 14 entries * 2 KiB = 448 KiB <= 512 KiB

64 node reserve units * 17 emergency marker slots * 2 KiB
  = 2,176 KiB emergency marker floor
16 tenant reserve units * 17 emergency marker slots * 2 KiB
  = 544 KiB emergency marker floor

64 node reserve units * 4,768 KiB durable = 298 MiB durable floor
16 tenant reserve units * 4,768 KiB durable = 74.5 MiB durable floor
64 node reserve units * 552 event/evidence = 35,328 credits
16 tenant reserve units * 552 event/evidence = 8,832 credits
```

The representation implementation must prove a maximum-size secret with every
enabled plain/base64/base64url/percent/split/log-injection matcher fits the
512-KiB persistent cap; streaming decoders share one source overlap rather than
copying 256 KiB per detector. If that proof fails, configured cardinality is
reduced until both equations hold; coverage is never reduced silently.

`SecretContainmentReserve` is an Authority-owned durable reservation keyed by
tenant/node, outer submission, use attempt, and exposure lineage. Its target-
generation binding is exactly `absent` at reservation and is CASed once to
`present` when typed node allocation creates that generation; it can never be
replaced or cleared. One unit has exactly two provider-control credits (`revoke`
plus read-only `audit`), eight node-control credits (fence, terminate, close
handle, close socket, unmount, delete projection, attest absence, acknowledge
revocation), two reconciler-claim credits, two terminal/tombstone hot credits,
552 durable event/evidence entries, one incident entry, 4,768 KiB durable bytes,
and 17 typed emergency marker slots. An inapplicable operation leaves its credits
and marker slots unused; they cannot be reassigned to normal work or another
exposure. A backend whose declared worst case exceeds any unit dimension is
inadmissible until a stricter profile or larger accepted budget exists.

The 552 event/evidence credits are exact maximum cardinality, not margin:

```text
per provider or node control:
  1 requested event
  + 16 pre-evidence records
  + 16 post-evidence records
  + 1 completed event
  + 16 Authority lifecycle-event records
  = 50

2 provider controls * 50 = 100
8 node controls * 50 = 400

non-control reserve slots:
  16 exposure lifecycle/control-attestation records
  + 12 cleanup/revocation/containment records
  + 6 outer terminal/publication-suppression records
  + 8 tombstone/compaction/retirement/deletion records
  + 6 provider/node reconciliation claim/start/completion records
  + 4 incident/reserve-release records
  = 52

100 + 400 + 52 = 552 event/evidence records per containment unit
```

The 52 non-control slots are closed by those category/count pairs and cannot be
borrowed across categories. The 16 exposure slots are exactly reserve claim, use
reservation, target allocation, pre-exposure control attestation, provider
acquisition, delivery prepared, delivery activated, target started, target
stopped, output drained, detector finalized, provider released, node released,
delivery closed, exposure released, and final control attestation. The 12 cleanup
slots are exactly leak signal, quarantine, revoke request/result, fence request/
result, terminate, handle close, socket close, unmount, projection delete, and
absence acknowledgement. The six outer terminal slots are terminal intent,
pending outcome, receipt, action event, outcome record, and publication
suppression. The eight retention slots are tombstone request, commit, verification,
full-record deletion, retirement decision, retired marker, marker verification,
and individual-marker deletion. The six reconciliation slots are claim, start,
and completion for each of provider and node. The final four are incident request,
incident record, reserve-release request, and reserve-release completion. A path
needing a second record for any fixed slot is over profile and denies new exposure
before reservation rather than dropping evidence. Emergency records that cannot
fit the ordinary outer receipt's declared event-ref maximum remain in the
restricted management/incident stream; the outer remains uncertain/quarantined
and no record is omitted or target-controlled outcome released.

The 4,768-KiB durable reservation follows maximum canonical sizes:

```text
552 event/evidence records * 4 KiB                  = 2,208 KiB
10 provider/node plan+row+result+intent+receipt
  bundles * 64 KiB                                  =   640 KiB
pending stable ActionOutcome bytes                  = 1,024 KiB
outer delivery receipt                              =   512 KiB
outer terminal intent                               =    64 KiB
delivery-control attestation record                 =    64 KiB
incident record                                     =    64 KiB
2 reconciliation bundles * 32 KiB                   =    64 KiB
reserve/cleanup/tombstone/retirement state aggregate=   128 KiB
                                                       ---------
                                                       4,768 KiB
```

Each listed maximum is a schema admission bound. A future larger record or
additional record kind requires a new accepted profile and revised FND-012
equations; compression, average size, and an unexplained safety margin cannot
substitute for the declared maximum.

The 17 emergency marker slots are likewise exact: 2 provider-control invocation
IDs + 8 node-control invocation IDs + 2 `SecretReconciliationClaimId` values + 1
delivery-control attestation ID + 1 terminal delivery-receipt ID + 1 cleanup-
command ID + 1 consumed-tombstone ID + 1 incident ID. Each slot has a fixed class
and ordinal in the reserve. Before accepting one of those identities,
Authority atomically CASes the matching unused slot to
`claimed {nominal_identity,authority_domain}`; a normal identity or different
class cannot claim it. The identity's tombstone transaction atomically changes
that slot to `charged {permanent_marker_id,marker_integrity_digest}`, where the
marker is the primary consumed-effect tombstone or exact auxiliary marker above.
A charged slot
remains in the emergency marker store after reserve release. Verified domain
retirement may replace same-domain charged markers with one same-pool retired-
domain marker and return only excess slots; it never moves a charge to the normal
pool or permits reuse.

Admission first proves the configured node and active-tenant reserve floors, then
atomically reserves one complete unit, all 17 emergency marker slots, durable
bytes, event/evidence credits, and incident credit per proposed use attempt before
use claim, node preparation, provider acquisition, material exposure, adapter
entry, or target work. For `N` requirements it requires `N` available tenant
units and `N` available node units; partial reservation rolls back with no effect.
Tenant normal slots/bytes, node normal slots/bytes, tenant emergency marker/unit,
and node emergency marker/unit are acquired in that order, then ordered by
Authority event sequence and canonical use-attempt ID. Historical charged
emergency markers count against their separate pool; if fewer than all 17 slots
remain, new exposure stops before reserve/use/provider/node/adapter work. A loser
denies/quarantines new exposure before any such work.

Emergency controls still traverse current authority, gateway, permit, evidence,
and exact provider/node ledgers, but debit the bound reserve rather than normal
work quota. They remain available when action/control hot quotas, normal durable
tenant quotas, or uncertain workload rows are full. Normal work, provider fetch,
ordinary audits/health probes, and an unrelated uncertain row cannot borrow,
evict, resize, or consume the pool. Reserve-floor loss, storage uncertainty, or a
failed reserve audit stops all new acquisition/exposure and reports health/
incident evidence. Marker corruption or unavailability fails closed and
quarantines use, but it never treats an already durable reserve as absent,
releases its slots, or reallocates them; repair/reconciliation resumes from the
same reserve/slot rows. Existing containment never requires an unreserved normal
marker slot.

The reservation survives process/node restart and remains bound through provider
revoke/audit, node fence/terminate/close/unmount/delete/attest, detector drain,
scan/seal, cleanup, terminal intent/receipt/event, incident append, reconciliation,
and consumed-effect tombstone commit. It releases only when provider and node
effect state, revocation, cleanup, terminal evidence, and tombstone are all known
terminal and no reconciler/incident write remains. Any uncertainty retains the
unit; retirement requires the same fail-closed domain process. Release is an
Authority CAS plus durable `secret.containment_reserve.released` audit, never a
timeout or garbage-collector inference. Release returns only still-unused marker
slots and unused durable/event/incident credits. Every claimed identity remains
reserved, and every charged permanent tombstone remains charged to its exact
emergency slot; releasing other capacity never makes it evictable. Restart and
reconciliation rebuild available/unused/claimed/charged arithmetic from durable
reserve/slot rows. A mismatch, lost row, double claim, or negative balance fails
closed without dropping the reserve. Permanent lineage-scoped domain retirement
follows the closed marker protocol above before any charged slot can return.

Active detector, overlap, queue, use-attempt, approval continuation, provider/node
control, cleanup, tombstone, and containment-reserve state is never evicted.
Detector/overlap state releases only after terminal drain, final scan, cleanup
evidence, and key destruction. A hot terminal index may evict in deterministic
retention order only after its full record and permanent tombstone verify. Durable
quota/storage uncertainty denies new admission before use reservation; it never
drops old semantics, active detection, or emergency capacity.

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
clean. The 64-chunk bound is a declared detection limit, not an allowlist. These
matchers detect known accidental representations; they do not prove
noninterference for malicious code and never authorize publication from a
`material_exposed` target.

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

For `trusted_injection`, the driver-owned pre-send barrier scans/classifies the
complete outbound request projection before the injector inserts material; the
only permitted material-bearing span is the nominal credential slot for the
exact revalidated destination. All other outbound bytes and any redirect/proxy/
DNS change deny. For `material_exposed`, the SBX-007 host egress controls mediate
every attempted network/IPC/proxy/child/helper/external-filesystem/mount operation
and deny it with zero emitted bytes; only private broker scratch exists. Post-
persistence scanning is additional defense and cannot substitute for that pre-
operation deny-all enforcement.

For `material_exposed`, scanning captured target bytes is incident detection only.
The scanner receives those bytes through a private non-serializable source and
returns no target-derived public projection. Match, no-match, unknown coverage,
decoder success/failure, output length, and chunk boundaries cannot alter the
fixed public outcome, error, artifact, state, trace, or timing-release choice.
Ordinary persistence receives no captured byte or target-selected digest.

A scan match, scanner unavailability, detector-registration failure, ambiguous
partial scan, or output too large for the declared bounded scanner policy cannot
be silently redacted and marked successful. C03 v1 has one disposition: quarantine
the output and process boundary, fail the action, deny new lineage claims, revoke
the affected lease, append containment evidence, and request incident handling
when that owner exists. Cleanup or incident unavailability leaves
`needs_intervention`; it never weakens containment or becomes success.

### Limits and false positives

The barrier does not claim visibility into arbitrary encrypted, compressed,
hashed, steganographic, custom-XOR/table/alphabet, schema-bit, error-choice,
timing-choice, hardware-private, or otherwise opaque derivations. A separate
data-use policy may authorize additional inspection but cannot prove malicious-
code noninterference or authorize material-exposed publication. Unknown coverage
is recorded only in restricted incident evidence and quarantined for a secret-
exposed process; no captured byte, match choice, or coverage result is persisted
or published through ordinary surfaces or produces action success.

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
tick path only: stable policy.completed
tick path only: restricted secret.tick_candidate.observed (separate Event/Evidence record)
tick path only: unchanged stable actions.proposed
tick path only: Event/Evidence link CAS + restricted secret.tick_candidate.linked
tick path only: exact link receipt validated + Authority outer row inserted
secret.lease.requested
secret.lease.issued
verification.started
verification.completed
non-borrowable containment reserve committed for every requirement
secret.use.claimed
secret.delivery.requested
secret.provider.fetch.started
secret.provider.fetch.completed
secret-aware adapter method entered; Authority sets secret_aware_adapter_entered
secret.delivery.ready
secret.delivery.activated
exposure-profile pre-send barriers/evidence become durable before each send
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
trusted injection: sealed public ActionOutcome released
material exposure: fixed terminal/restricted suppression envelope released
outcome.recorded
state.committed + tick.completed (tick path only)
```

An approval-required first attempt has this exact compatible fork after
`verification.completed`: atomically persist the immutable continuation and
stable challenge outcome, emit `action.needs_approval` and
`approval.requested`, move the parent to `awaiting_approval`, release the stable
outcome, and complete the ordinary path suffix. It has no reserve, use claim,
provider/node/adapter/target work, or delivery receipt. A later exact stable
`/actions` continuation emits daemon audit, `verification.started`, current
authority/approval revalidation, durable one-use receipt claim,
`approval.granted`, and parent `continuing` before the reserve/use sequence above.
It reuses the original action/tick causal identity but emits no new
`tick.started`, percept/state load, policy, candidate observation,
`actions.proposed`, state commit, or `tick.completed`. Exact raw denial/expiry/
revocation emits the matching approval fact and one final no-effect action pair;
cancel-first emits only the existing run cancellation plus the C03 cancelled
state and fabricates no action outcome.

The additive observation is not a new stable `TraceEventKind` payload and does
not alter `PolicyCompleted` or `CandidatesProposed { actions }` serialization.
Its validated causal ref links it to the stable run trace. A direct submission
has no policy/tick observation and begins at normal direct authentication/
admission. Observation append failure prevents all later C03/action work.

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
one final effect-terminal `action.*` event; an approval parent may additionally
have the earlier zero-effect stable `action.needs_approval` attempt event and no
other action event. Provider, node, gateway session/orchestrator, and driver code
emit none. Direct submissions stop after `outcome.recorded`; approval
continuations, including tick-origin continuations, do not fabricate
`state.committed` or `tick.completed`.

Provider controls use the separate order Authority ledger claim ->
`secret.provider.control.requested` -> final control permit -> write-ahead
`sent_uncertain` -> at most one provider call -> retained safe result/audit ->
`sent_known` when definitive -> immutable terminal intent ->
`secret.provider.control.completed` -> authority CAS/lifecycle event -> terminal.
Missing pre-effect evidence prevents the call; missing post-effect evidence
retains sent uncertainty and cannot update authority state to success. Duplicate
delivery or response loss resolves the same ledger row and never repeats the
provider method.

Node controls use the separate order Authority unique invocation/plan claim ->
`secret.node.control.requested` plus pre-evidence -> `in_progress` -> final node-
control permit -> either a proved-no-send result and `no_send`, or write-ahead
`sent_uncertain` -> at most one bound resident-node operation -> retained exact
owner result plus post-evidence -> `sent_known`; either result path then writes
the immutable terminal intent and receipt ->
`secret.node.control.completed` -> Authority CAS/lifecycle event -> `terminal`.
Missing pre-effect evidence prevents node entry; missing/ambiguous post-effect
evidence stays sent-uncertain and quarantines the exact target/parent. Duplicate,
response/event/CAS loss resolves this row through one reconciler and never repeats
the operation. A fresh read-only `attest_absent` has its own invocation and cannot
rewrite the uncertain original.

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

The separate preclaim profile name is exactly
`secret.tick_candidate.observed`; it maps only to
`splendor.secret.tick_candidate_observation.v1` in the restricted Event/Evidence
stream and is not a `SecretAccessEventKind` or stable `TraceEventKind`.
The same owner stream uses `secret.tick_candidate.linked` only for the winning
link CAS/receipt and `secret.tick_candidate.expired` only for the winning expiry
CAS/tombstone. Their owner sequences are strictly later than `observed`; a link
is strictly before Authority outer insertion, while expiry forbids that insertion.
They are not stable `TraceEventKind` values and cannot be synthesized from an
Authority row.

These event names and meanings are part of this proposed contract. Renaming or
reinterpreting one after acceptance requires compatibility treatment; a generic
log message is not equivalent evidence.

### Safe persistence

- Broker state persists ref/lease/lineage revisions, refresh/revocation
  generations, outer submission/terminal-intent, approval-continuation, use-
  attempt, provider-control, and node-control invocation/terminal-intent ledgers;
  compact hot indexes; containment reserves; backing-source claims; permanent
  consumed-effect tombstones and retired-domain markers; routing refs; handles;
  safe attestation/egress-evidence records; full terminal receipts; safe control
  results/audits; pending validated outcome records; safe events; and CAS heads
  only. Event/Evidence separately owns the immutable safe preclaim tick-candidate
  observations, mutable claim-state rows, immutable link receipts, and expiry
  tombstones.
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
cleanup, leak/quarantine, approval continuation, provider/node control ledger
states, containment reserves, backing-source ownership, full/tombstoned preclaim
observations plus claim-state/link receipts, consumed-effect tombstones/retired
domains, exposure profiles/egress evidence, publication-suppression dispositions,
and effect certainty from safe records. It never exposes material-exposed captured
bytes or reconstructs a target-selected result.

Replay never:

- fetches, resolves, renews, rotates, revokes, audits, or actively probes a live
  provider;
- reopens a delivery handle, target FD, mount, socket, projection, or process;
- re-registers a detector using historical material;
- treats a ref, lease, access event, provider receipt, or historical allow as
  current authority;
- executes a gateway, adapter, driver, network, filesystem, device, or incident
  side effect.
- re-invokes policy to replace an observed candidate, CAS-links or expires an
  observation, creates/replays a link receipt or Authority outer row, repeats a
  provider-control method, resolves DNS, opens a proxy,
  claims an approval receipt or containment reserve, repeats a node control,
  reopens a retired identity/domain, or probes a live process/mount/IPC/network
  egress boundary.

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
- the exact full/restricted secret-action response after server-side principal,
  current-policy, data-use, work-order/revocation, visibility, and dedicated
  inspection-scope checks; material-exposed submissions always use the fixed
  terminal/restricted suppression view after exposure;
- structured denial and cleanup/quarantine status.

There is no SDK method named or behaving as `get_secret`, `resolve_secret`,
`read_secret_value`, `secret_bytes`, or equivalent. There is no standalone
daemon endpoint that returns a secret value or a user-resolvable handle. Node
resolution is internal to the retained gateway/executor path.

SDKs cannot treat `splendor.actions.submit` or a submission UUID as result-read
authority, cannot request full view as a body/query flag, and cannot locally
upgrade `restricted` to `full`. The generated inspection helper requires the
dedicated `splendor.secret_actions.results.read` scope and preserves server audit
attribution; default same-key recovery remains original-principal-bound.

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
`secret_requirements`/`bound_secret_requirements` list is safe only at its exact
registered path in `splendor.gateway.secret_action_candidate.v1`,
`splendor.gateway.action_request_with_secrets.v1`, or
`splendor.daemon.submit_secret_action.v1`, and every element must be the exact
required `splendor.secret.use_requirement.v1` or bound-requirement object with no
unknown fields. The preclaim `candidate_canonical_bytes_b64url` field is safe
only in `splendor.secret.tick_candidate_observation.v1` after decode,
recanonicalization, digest equality, raw-ingress, and pre-persistence scanning of
the complete nested candidate. The
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
declares one exact exposure profile per credential slot, whether target code sees
material, which delivery mechanisms it supports, its destination projection and
pre-send barrier, required SBX-007 enforcement/evidence profile when material is
exposed, child-inheritance/debug/capture/egress policy, cleanup guarantees,
offline support, effect/idempotency class, and relevant conformance evidence. Examples
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
| Plain action candidates | Rust `ActionCandidate`, OpenAPI/daemon `DaemonActionCandidate`, Python `ActionCandidate`, and existing TypeScript bytes remain unchanged. The additive tagged C03 candidate has its own complete field/null/digest contract and is observed separately before tick claim. |
| Action params | Raw credential-bearing params, headers, bodies, URLs, cookies, connection objects, environment material, and equivalent generic payloads deny before adapter/provider execution for every adopted operation. Typed requirements are the only C03 path; exact non-secret exceptions are narrow, versioned, expiring owner rules. |
| Work orders/capabilities | Remain required and may only narrow. C03 fields are not smuggled through extensions. |
| Trace/state | Historical bytes and IDs remain unchanged. New C03 event profiles are additive and safe-only. |
| Material-exposed results | Stable 0.1 `ActionOutcome` schema is unchanged. The C03 wrapper uses its existing `Failed`, absent output, and bounded error fields for one fixed suppression projection; it never serializes target-selected output/error/artifact/state/trace/result data. A future declassifier requires a separate accepted versioned contract. |
| Tombstones/retirement | Additive C03-only closed domain tags, named disposition/integrity digests, and lineage-scoped node domains preserve exact duplicate/conflict meaning after full-record deletion; they do not rewrite stable store records. |
| Node retry | `SecretNodeControlRetryProfile` is additive C03/NODE owner ABI with exactly `no_retry|one_no_send_retry_100ms`; it appears in plan/result/intent/receipt canonical bytes and never changes stable adapter retry behavior. |
| Rust | `splendor-types` is canonical for serialized records; authority owns behavior and private validated wrappers. |
| OpenAPI/TS/Python | Added only with mechanical parity and no material-returning API. The response full/restricted matrices and dedicated result-inspection scope are generated from Rust. Old clients may ignore inspection-only records but cannot authorize unknown versions. |
| Stores | New C03 Authority records and Event/Evidence-owned preclaim observations are separate and versioned. Existing arbitrary payload stores are not C03-safe until the pre-persistence barrier is wired. Authority cannot shadow-own tick observations and Event/Evidence cannot claim submissions/effects. |
| Replay | Existing inspect-only behavior remains; C03 records add explanation only. |

No privileged consumer accepts unknown C03 versions or enum values. Generic
readers may preserve them as opaque historical data. No `extensions` field,
arbitrary map, alias, optional authorizing field, default, or schema negotiation
may change secret authority.
The proposed `splendor.secret_actions.results.read` scope applies only to the new
v2 lookup route. It does not rename, widen, or reinterpret any stable 0.1 daemon
scope; specifically, stable `splendor.actions.submit` remains submit-only.

Initial implementation is behind an explicit `secret_broker_v1` runtime/feature
gate that defaults off. Enabling live issuance requires compatible Authority,
Gateway/orchestrator, node/executor, provider bootstrap/transport,
event/evidence including tick observations, pre-persistence barrier,
schema/content scanner, every required foreign nominal-ID owner, and FND-012
budget evidence. `material_exposed` additionally requires the accepted SBX-007
deny-all egress enforcement/evidence profile plus the zero target-publication
ABI. Mixed-version nodes that
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
unsupported_media_type
malformed_request
secret_action_profile_unavailable
secret_action_receipt_unavailable
secret_action_idempotency_conflict
approval_continuation_conflict
approval_continuation_unavailable
approval_continuation_cancelled
secret_tick_candidate_observation_conflict
secret_tick_candidate_observation_expired
consumed_effect_retired
idempotency_tombstone_unavailable
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
material_exposure_profile_unavailable
material_exposed_publication_suppressed
destination_egress_denied
destination_egress_uncertain
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
provider_bootstrap_cross_route_alias
provider_bootstrap_backing_source_alias
provider_transport_untrusted
provider_effect_uncertain
provider_control_idempotency_conflict
node_control_unavailable
node_control_idempotency_conflict
node_control_effect_uncertain
target_effect_uncertain
stale_refresh_generation
detector_capacity_exhausted
containment_reserve_exhausted
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
| Tick observation append/scan/digest/byte mismatch, changed duplicate, or link-receipt failure | `integrity_failure`, `unavailable`, or `conflict` | `not_retryable`; no receipt-bound outer claim or effect exists, policy is not reinvoked, and the generic observation reconciler cannot submit it. Link-only recovery is exact same-tick/same-submission only. |
| Observation link versus expiry | No error for the link winner; otherwise `expired`, `conflict`, or `unavailable` | Owner-clocked CAS on one row has exactly one winner. Expiry winner tombstones before payload deletion and permits no outer/effect; link winner returns the one immutable receipt and prevents unclaimed expiry. Clock/store/revision uncertainty admits neither. |
| Exact outer duplicate | Original category | Return/refer to the original submission/receipt and all original certainty dimensions; never create another effect. |
| Outer key/action reuse with changed bytes | `conflict` | `not_retryable`; the conflicting observation has no effect and cannot alter/disclose the original beyond the visibility-safe profile. |
| Approval parent awaiting exact receipt | Original `NeedsApproval` category | Return the immutable challenge/awaiting view. Exact receipt retry alone may claim the one continuation after current checks; no new parent/key/tick exists. |
| Approval receipt duplicate or changed continuation | Original category or `conflict` | Exact duplicate returns continuing/final state with zero second claim/effect; competing receipt or any changed bound field is `not_retryable` and effect `none`. Raw grant never executes. |
| Missing/corrupt terminal receipt or intent | `uncertain` | `not_retryable`; outer certainty `uncertain`, same-submission lookup/reconciliation only. |
| Full record compacted with exact tombstone | `expired` or original `uncertain` | Return restricted `consumed_effect_retired`/original uncertainty; never treat as miss, recreate protected output, or authorize an effect. Changed digest remains conflict. |
| Tombstone or retired-domain marker unavailable/corrupt | `unavailable` or `integrity_failure` | Fail closed before allocation/effect; `not_retryable` until authoritative storage is repaired. Quota cannot delete the marker. |
| Expired or revoked authority/work-order/data-use/lease | `expired` or `revoked` | `retry_with_new_authorization` only for a new request/attempt, `none` |
| Stale ref/placement/fencing/refresh/concurrent CAS | `stale_head` or `conflict` | exact same-ID retry returns the first denial; changed expected values require a fresh command ID, and any reserved/crossed use requires a fresh use-attempt ID; only the proved prepared/unreserved exception may retain the use-attempt ID, `none` |
| Aggregate exhausted or attempted widening | `quota_exceeded` or `conflict` | `not_retryable`; preserves parent counters/start/deadline, provider/node/target `none`. |
| Explicit provider unavailable with every send proved absent | `unavailable` | bounded same-invocation retry if policy permits; provider/target `none`, outer is the conservative node/cleanup maximum. |
| Provider request sent with definitive failure | Exact mapped `unavailable`, `driver_failure`, `timeout`, `revoked`, `integrity_failure`, `quota_exceeded`, or `incompatible_schema` | No automatic outer resubmit; provider `known`, target `none`, outer at least `known`. |
| Provider send/result uncertainty | `uncertain` | `not_retryable`; provider and outer `uncertain`, target `none` when adapter was not entered. |
| Exact provider-control duplicate | Original category | Return/refer to the original ledger state/result; no second requested event, bootstrap read, provider call, audit, or Authority mutation. |
| Provider-control invocation reused with changed plan bytes | `conflict` | `not_retryable`; changed observation effect `none`; original remains hidden or unchanged. |
| Provider-control sent uncertainty or post-effect evidence loss | `uncertain` | `not_retryable`; original method never re-enters. Reconcile retained bytes or submit a separately authorized read-only audit with a fresh invocation. |
| Exact node-control duplicate | Original category | Return/refer to original accepted/in-progress/no-send/sent-known/sent-uncertain/reconciling/terminal state; no second requested event, bridge send, mutation, evidence, receipt, or Authority CAS. |
| Node-control invocation reused with changed plan bytes | `conflict` | `not_retryable`; changed delivery has effect `none`; original remains unchanged/hidden. |
| Node-control uncertainty | `uncertain` | One reconciler may finish retained bytes; original mutation never re-enters. Only a fresh separately authorized read-only same-target attestation may inspect current state; parent remains quarantined. |
| Containment reserve, emergency marker allowance, or floor unavailable | `quota_exceeded` or `unavailable` | Stop new exposure before use/provider/node/adapter work. Already-reserved revoke/fence/cleanup/terminal/tombstone writes retain their exact durable slots; corruption quarantines but cannot discard/reassign a reserve. |
| Material exposure owner/profile or egress evidence unavailable | `unavailable`, `unsafe`, or `uncertain` | Deny before provider acquisition/exposure when possible; after exposure, block send, fail/quarantine, revoke/cleanup, and never retry or report success. |
| Material-exposed network/proxy/DNS/filesystem/IPC/child/helper/alternate-mount attempt, including correct destination but wrong slot | `unauthorized`, `unsafe`, or `protected_data_denial` | Deny all with typed zero-byte evidence, fail/quarantine target and parent, and preserve actual certainty; no destination allowlist or after-send DLP can allow it. |
| Material-exposed target output/result/error/exit/timing choice, including custom XOR/table/alphabet, schema-valid JSON bits, error choice, and chunked covert output | `protected_data_denial`; fixed `SecretErrorCode=material_exposed_publication_suppressed` | Internal stable status/error/publication disposition is fixed before exposure; public APIs return only the fixed terminal/restricted envelope with output/outcome/receipt/artifact/state/trace fields absent and no early release. Captured bytes remain private detector/incident input and are wiped/quarantined. Pattern no-match never authorizes publication. |
| Adapter delivery failure before target start | `unavailable` or `internal_invariant_violation` | Final action `Failed`; target `none`; outer is the conservative provider/node/target/cleanup maximum. |
| Trusted-injection target definitive failure | Exact mapped `driver_failure`, `timeout`, `cancellation`, `postcondition_failure`, `unsafe`, or `integrity_failure` | Final action `Failed`; target `known`, outer at least `known`; no blind outer resubmit. |
| Trusted-injection target send/result uncertainty | `uncertain` | Final action `Failed`, `not_retryable`; target and outer `uncertain`. |
| Leak or post-target scanner denial | `protected_data_denial` or `unavailable` | `not_retryable` until containment/new evidence; preserve provider/node/target dimensions and derive outer conservatively, never reset to `none`. Material exposure retains its fixed public suppression envelope. |
| Cleanup uncertainty | `uncertain` | Explicit same-target containment/reconciliation only. Material exposure retains its fixed public suppression envelope while actual uncertainty remains restricted owner evidence. |
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
| Tick observation missing/corrupt or same ordinal changed | Fail before outer claim; policy is not reinvoked, stable trace bytes are unchanged, and orphan reconciliation cannot cause effects. |
| Observation link/expiry race before, at, or after recorded expiry | CAS the same Event/Evidence row. Strictly before expiry either exact link may win or expiry later wins; at/after the boundary only expiry may win. Expiry commits/verifies its digest tombstone before deterministic payload deletion and creates no outer/effect; link wins pin exact receipt/payload through outer retention. |
| Crash with observation only, link only, or purported outer only | Observation-only may exact-resume before expiry. Link-only may complete only the same run/tick/submission/digests after current Authority revalidation. An outer lacking the exact durable receipt is invalid/quarantined and never executes. No generic reconciler or policy reinvocation repairs either state. |
| Dropped direct/tick response or exact duplicate observation | Resolve the existing outer submission and original use-attempt/terminal pair; no second reservation, provider/node/adapter/target call, or terminal event. |
| Same outer key or action/invocation with changed bytes/key | Conflict without mutating or repeating the original effect. |
| Exact approval challenge receipt after `NeedsApproval` | Continue the same parent once through stable `/actions`, preserve original direct key or tick observation/digests, revalidate current authority, and create at most one adapter/target effect. |
| Approval duplicate/competing receipt, crash, cancel, expiry, or revocation | Exact duplicate resolves the one continuation; competing/changed receipt denies; cancel/revoke/expiry wins prevent claim; post-claim crash uses only the same durable claim and terminal intent. |
| Retry after full dedupe record expiry or authority-domain retirement | Tombstone or retired-domain marker rejects before allocation/effect. Exact/changed bytes never become a fresh miss and IDs are never reused. |
| Same-tenant/run principal presents another principal's submission ID | `splendor.actions.submit` alone receives uniform not-available; only original-principal current authority or dedicated current audited inspection can receive full/restricted status. |
| Original principal's work-order/data-use/result visibility expires or is revoked before response | Return restricted non-retryable state only; withhold stable output and restricted receipt metadata on immediate, duplicate, and lookup paths. |
| Provider outage/circuit open | Deny or bounded same-trust failover only under the rules above. |
| Provider response uncertain | Record uncertainty; no blind retry/failover and no adapter execution. |
| Provider request sent with definitive failure | Record provider `known`, target `none`, and outer at least `known`; never report `none`. |
| Network bootstrap default chain, wrong file/keychain/workload identity, or route mismatch | Fail route startup/probe closed; no ambient fallback, provider send, or cross-route identity use. |
| Cross-route bootstrap source/SDK handle alias, including byte-identical profiles | Canonical backing-source registry rejects startup before any route source probe/access; distinct wrappers, mappings, FDs, items, token objects, or caches over one source remain aliases. |
| Provider renew/revoke/audit/active health requested outside gateway control | Reject; direct provider invocation count remains zero. |
| Duplicate or response-lost provider renew/revoke/audit/active probe | Resolve the Authority ledger; exact bytes return original state/result, changed bytes conflict, sent uncertainty never re-enters the method, and post-effect loss uses retained bytes or a new authorized read-only audit. |
| Node fence/terminate/close/unmount/delete/attest/revocation acknowledgement outside node-control gateway profile | Reject; direct node/OS/orchestrator mutation count remains zero. |
| Node-control retry after proved no-send versus after write-ahead send | Only `one_no_send_retry_100ms` permits one same-plan retry after exactly 100 ms with owner proof of zero bridge bytes/local mutation. `no_retry`, missing proof, changed bytes, or any `sent_uncertain|sent_known` state permits no resend or failover. |
| Normal/uncertain quotas or normal marker slots filled after exposure | The unit's non-borrowable durable credits and 17 typed emergency marker slots admit the exact control/evidence/terminal/tombstone sequence. New exposure stops first; no existing reserve, active state, or marker is evicted/reassigned. |
| Independent lineages share node/instance/generation number | Node domain, handle, plan, result, receipt, marker, cleanup, restart/migration, and retirement also bind the nominal exposure-lineage ID. Retirement of lineage A generation 1 cannot conflict with, compact, or deny lineage B generation 1. |
| Lease not active/expired/revoked/max-use | Atomic deny before exposure/effect. |
| Unknown/closed handle | Uniform deny; never attempt provider lookup from handle metadata. |
| Cleanup uncertain | Quarantine target, deny new leases, record restricted incident-worthy evidence. |
| Leak match or scanner unavailable | Fail/quarantine/revoke by closed policy; never silently redact to success. |
| Material-exposed code attempts raw socket, DNS rebinding, proxy, filesystem, IPC, child-process, alternate-mount, or alternate-origin/account/resource exfiltration | SBX-007/Node pre-send and host controls block bytes before they leave, then fence/quarantine/revoke and record typed evidence; absent enforcement denies material before provider acquisition. |
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
| Trusted-injection allowed | `known / known` | 1 / 1 | `Executed`; target/outer `known` | All reservations precede every fetch; postconditions allow, projections seal, cleanup is known, and one receipt/action event precedes the path suffix. |
| Authentication/closed-schema/raw-ingress/owner-compatibility failure before outer acceptance | `none / none` | 0 / 0 | No C03 `ActionOutcome`; visibility-safe transport error | No submission, receipt, action event, provider/node/adapter/target call, or persistence of rejected raw bytes. |
| Tick policy trace/observation/scan/digest/batch failure before outer claim | `none / none` | 0 / 0 | No C03 `ActionOutcome`; tick fails closed | No outer row/effect/state advancement; exact retained bytes are reused only by explicit same-tick recovery, never policy reinvocation or orphan reconciliation. |
| Accepted authority/verifier denial before reservation | `none / none` | 0 / 0 | `Denied`; target/outer `none` | Empty use-attempt batch and one matching final pair; no provider/delivery event. |
| Initial approval challenge | `none / none` | 0 / 0 | Stable attempt-terminal `NeedsApproval`; C03 parent `awaiting_approval` | Atomically persist immutable continuation plus one `action.needs_approval`/`approval.requested` and challenge outcome; no reserve, batch, delivery receipt, provider/node/adapter/target work, or effect-terminal parent. |
| Exact approval receipt continuation | From the later actual path | At most 1 / 1 across the parent | Stable final result from the one continued gateway attempt | Same parent/key/action/tick observation and requirements; current checks plus one durable receipt claim, no policy/new tick/state advance, and exactly one final pair. |
| Approval denial/expiry/revocation/cancel or competing receipt | `none / none` before claim | 0 / 0 | Stable no-effect denial pair, or C03 `cancelled` with no fabricated action outcome | Exact raw fail-closed evidence may close awaiting parent; changed/competing receipt conflicts; cancel/revoke/expiry winner prevents claim. |
| Accepted verifier/runtime unavailability before reservation | `none / none` | 0 / 0 | `NeedsIntervention`; target/outer `none` | Empty use-attempt batch and one matching terminal pair; fail closed with no provider/node/adapter/target work. |
| Use-budget/CAS/normal-resource loser | `none / none` | 0 / 0 | `Denied`; target/outer `none` | `use_denied` names the claim, the receipt batch is empty, and no provider/material/node-target/adapter call occurs. |
| Containment reserve unavailable/below floor | `none / none` | 0 / 0 | `NeedsIntervention`; target/outer `none` | Stop before use/provider/node/adapter work. Existing reserved revoke/fence/cleanup/terminal/tombstone writes remain admitted under the non-borrowable pool. |
| Provider failure with every send proved absent after target preparation | `none / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer is node/cleanup maximum | Reservations stay consumed; bounded same-invocation provider retry only when permitted, then cleanup and one terminal pair. |
| Provider request sent with a definitive failure, or an earlier batch fetch sent successfully | `known / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative and never `none` | Skip later fetches and adapter entry, sanitize audit facts, clean staging, and do not report effect `none`. |
| Provider send/result uncertainty | `uncertain / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer `uncertain` | No retry/failover/later fetch/adapter call; quarantine/reconcile, with one terminal pair only if terminal evidence commits. |
| Allocation/node-control failure before provider or adapter entry | `none / known|uncertain` | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative | Consume committed reservations, clean/quarantine exact target state, and never call provider or enter the adapter. |
| Required material-exposure/SBX-007 or egress profile unavailable before provider acquisition | `none / none|known` | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative | Deny material acquisition/delivery, consume any committed reservation, clean preparation, and do not degrade to uncontrolled user-code exposure. |
| Delivery resolution failure or panic after adapter entry but before target start | `known / known` | 1 / 0 | `Failed`; target `none`, outer conservative | Adapter entry is execution under stable semantics; cleanup runs and one failed terminal pair commits. |
| Trusted-injection actual-destination/DNS/proxy pre-send barrier denial after entry | `known / known` | 1 / 0 | `Failed`; target `none`, outer conservative | No credential-bearing bytes leave; fence/cleanup and record typed denial evidence. |
| Material-exposed network/filesystem/IPC/child/proxy/helper/alternate-mount attempt, including approved destination with wrong header/query/path/body/frame | Each from durable receipts | 1 / 1 | `Failed`; target/outer `known|uncertain` | Deny-all host barrier proves zero emitted bytes, target/parent quarantine, lease revokes, drain/scan/cleanup run, and no success/output publication occurs. After-send DLP cannot pass the case. |
| Material-exposed target returns any result/error/output/exit choice | Each from durable receipts | 1 / 1 | Fixed `Failed` suppression projection; target certainty remains restricted evidence | No target byte/digest/artifact/state/trace/error leaves, no early result release occurs, and scan result cannot alter the projection. Cleanup/incident handling may vary only in restricted owner evidence. |
| Trusted-injection target returns definitive failure | `known / known` | 1 / 1 | `Failed`; target/outer `known` | Accept terminal control attestation, scan/seal safe error/evidence, cleanup, and one failed terminal pair. |
| Trusted-injection target result is ambiguous | `known|uncertain / known|uncertain` | 1 / 1 | `Failed`; target/outer `uncertain` | No automatic retry; drain, quarantine/reconcile, clean, and commit one failed pair when evidence permits. |
| Trusted-injection postcondition denied/uncertain | Each from durable receipts | 1 / 1 | `Failed`; target `known|uncertain`, outer conservative | No `action.executed`; seal failure evidence, cleanup, and one failed terminal pair. Material-exposed postconditions never consume target results. |
| Scan/seal/output-coverage failure after target return | Each from durable receipts | 1 / 1 | `Failed`; target `known|uncertain`, outer conservative | Trusted-injection bytes quarantine with no partial release. Material-exposed bytes were never publishable and retain the same fixed suppression projection while restricted containment records the failure. |
| Cancellation/timeout before adapter entry | Each from durable send facts | 0 / 0 | `NeedsIntervention`; target `none`, outer conservative | Stop acquisition/delivery, consume reservations, cleanup/quarantine, and commit one terminal pair. |
| Cancellation/timeout after entry but before target start | Each from durable send facts | 1 / 0 | `Failed`; target `none`, outer conservative | Entry fact forbids `NeedsIntervention`; cleanup/quarantine and one failed terminal pair. |
| Cancellation/timeout after target start | Each from durable send facts | 1 / 1 | `Failed`; target/outer `known|uncertain` | Drain within bounds, scan/seal, cleanup/quarantine, one failed terminal pair, and no blind retry. |
| Provider/node/adapter unwind or panic | Each from durable send facts | Exactly from durable entry/start facts | `NeedsIntervention` only at 0 adapter entries; otherwise `Failed` | Gateway guard owns cleanup. Missing facts are treated as crossed/uncertain; panic-abort/process death uses supervisor reconciliation and cannot emit success. |
| Cleanup/drop/wipe failure | Each from durable send facts | Exactly from durable entry/start facts | `NeedsIntervention` at 0 entries; otherwise `Failed`; outer `uncertain` | Retain detector/fence where possible, emit cleanup uncertainty/quarantine, and commit one non-success pair. |
| Pending-outcome/terminal receipt/action append failure | Preserve all dimensions | Preserve both facts | No public `ActionOutcome`; outer `uncertain` | Keep the Gateway-sealed immutable pending bytes and Authority terminal intent with `terminal_evidence_blocked`; no outcome/state/direct success/next tick until one-pair reconciliation, with no repeated effect or outcome reconstruction. |
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
  submission/idempotency/receipt, approval-continuation, exposure-lineage,
  bootstrap-binding, and node-control IDs plus closed enums, `SecretRef`,
  `SecretLeasePolicy`, and
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
approval continuation/claim/receipt-digest records, provider control plan/
invocation/terminal-intent/result/hot-index records, node control plan/invocation/
terminal-intent/hot-index/receipt records importing the sole owner-defined exact
`SecretNodeControlResult`/outcome/reason/retry-profile types, containment reserve
with typed emergency marker slots, consumed-effect tombstone/retired-domain
marker, private backing-source registry seam, the Event/Evidence-owned tick-
candidate observation/claim-state/link-receipt/expiry-tombstone records, exposure/
egress evidence refs, closed command target variants, and tagged access-event
subjects. Compile-time fixtures prove every foreign ID,
including `SecretCredentialSlotId`, `ManagementEventId`, and `EvidenceId`, is
non-interchangeable and imported from its owner rather than minted by C03.

Both phases require positive round trips and negative fixtures proving no secret
value/material/locator/raw-error field can enter C03 records. The explicitly safe
base64url preclaim candidate bytes must pass the raw-ingress/pre-persistence
barrier and reproduce the closed candidate exactly. Rust/OpenAPI/Python/
TypeScript goldens pin every direct request and candidate field and optional
absence/presence form,
fixed-six-digit timestamps, ASCII/null/unknown-field rejection, every set
permutation, meaningful preference/receipt/causal order changes, candidate/
policy-manifest/tick-key bytes, exact observation link-versus-expiry CAS/receipt
at before/at/after boundaries, duplicate-observation conflict, UUIDv5 audience
bytes, semantic idempotency bytes, wrapper/outer direct/tick/approval/provider/
node plan and terminal-intent digest bytes, every full/restricted response state
matrix, every closed tombstone/disposition/retired-marker tag and integrity chain,
leak-token generation/key separation, and token-integrity tampering. Provider
terminal goldens contain the nominal invocation ID plus explicit plan/partition
digests and no inferred invocation digest. Node goldens include the exact retry
profile in plan/result/intent/receipt. The 16-requirement maximum fixture
separately pins the 902-byte provider hot-index maximum, every <=2-KiB hot index,
complete larger durable receipt, summary/event order, uniqueness, and cardinality.
Every event kind has the positive/negative validator fixtures required by its
matrix. Cross-language fixtures use the exact nested
`DriverOperationRef` object and reject display/stringified/side-field forms in
declarations, manifests, authorization, dispatch, and evidence. Stable 0.1
`Action`, `ActionCandidate`, `ActionRequest`, `ActionOutcome`, trace, and state
bytes/hashes remain unchanged. Gold
remains `not_exercised`.

### V2 - Authority lifecycle and deterministic providers

- Implement one authority-owned state machine, validated wrappers, CAS,
  closed command grammar, semantic idempotency, authorized lookup ordering,
  outer submission/terminal-intent and challenge-bound approval-continuation
  ledgers/reconciler, provider-control invocation/terminal-intent/hot-index
  ledger, permanent consumed-effect tombstones/retired-domain markers,
  containment-reserve accounting, parent exposure
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
  gateway control probe. A durable private canonical backing-source registry
  claims one route before every source access and survives crash/retirement.
  Cross-route alias fixtures vary provider/route ID,
  source tag/binding, issuer/subject/refresh owner, descriptor mapping, keychain
  persistent ref, origin/CIDR, CA, SDK digest, locality, and revocation. Every
  mismatch and byte-identical multi-route handle reuse rejects before source
  access/provider send. Separate wrappers, mappings, FDs, keychain references,
  workload-token objects, and SDK caches resolving to the same backing identity
  also reject before source access; hot reassignment and retired-ID reuse reject.
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
- Provider-control tests cover exact duplicate and changed-byte conflict for
  `renew`, `revoke`, `audit`, and `active_probe`; crash/response loss before
  claim, before send, at write-ahead sent uncertainty, after provider return,
  after safe result/audit, after completed-event append, after Authority CAS, and
  after terminal response. Every exact duplicate produces one provider call and
  original state/result; sent uncertainty never re-enters; post-effect loss uses
  retained bytes or a fresh separately authorized read-only audit. Canonical
  fixtures pin every terminal-intent field, exact prefixed bytes/digest, both hot-
  index pointer variants, and the generated 902-byte maximum record.
- Retention tests compact full direct/tick outer, approval challenge/
  continuation, provider-control, node-control/target-generation, and expired
  observation records. Exact/changed duplicates across restart hit the tombstone
  or retired-domain marker and cause zero new effects; every named disposition
  digest and integrity-chain byte is pinned. Corruption, deletion pressure,
  concurrent compaction, and domain reopen fail closed. Two lineages on one
  node/instance each use target generation 1; compacting/retiring one leaves the
  other's handles, controls, lookup, cleanup, and retirement authority unchanged.
- Result-authorization tests use principals A and B in the same tenant/run. A
  receives full immediate/duplicate POST only while current result/output/data-
  use/work-order/revocation policy allows; submit-only GET is always restricted,
  and full GET requires the dedicated scope. Revoked/expired authority yields
  restricted state on creating, duplicate, and authorized GET responses. B with
  only `splendor.actions.submit` receives the uniform not-available response; B
  with the dedicated read scope still needs current exact inspection policy and
  audit, and receives full or restricted exactly by that decision.
- This is bounded local evidence until the real gateway/node path exists. It
  does not pass `G07` or `G08` by itself.

### V3 - Gateway, node delivery, and leak barrier

- Requires real `NODE-003`/`SBX-001` process/fencing owners, accepted `SBX-007`
  deny-all material-exposure isolation, the exact owner-defined node-control
  result/outcome/reason/retry-profile types and durable invocation/send/terminal ledger,
  durable approval-owner claim/revoke recovery, Event/Evidence tick-observation/
  link-versus-expiry/management/pre-post evidence ownership, containment reserve
  including emergency marker slots, and
  `FND-009`-aligned pre-persistence integration.
- Atomically update the dependency guard with the exact secret-provider exception
  and fixtures rejecting every broader provider/ordinary-adapter edge.
- A tick production-path integration test proves stable `policy.completed` ->
  all-or-none immutable candidate observation -> unchanged stable
  `actions.proposed` -> retained-byte/digest validation -> tick-key derivation ->
  Event/Evidence link-versus-expiry CAS -> exact durable link receipt -> Authority
  outer submission claim. Direct begins at its versioned ingress. Both
  then prove
  final verification -> non-borrowable containment reservation -> use reservation
  -> target/control allocation -> durable
  pre-provider evidence
  -> borrowed permit -> provider -> driver-local `resolve_and_deliver` -> exactly
  one target driver invoke -> terminal control attestation -> trusted-injection
  gateway postcondition/public-projection scan or material-exposed fixed
  suppression/private incident scan -> raw-buffer wipe -> delayed-source drain/
  decoder finalization/final seal -> cleanup -> common terminal normalizer ->
  final outcome. Multi-requirement tests prove all reservations precede the first
  provider call and a provider failure skips later fetches/driver execution. With
  `max_uses=1`, racing attempts on one lineage produce exactly one claim,
  provider call, material instance, delivery, and driver call.
- Direct and tick dropped-response/duplicate tests cover pre-reservation denial,
  plus tick crash before observation, after observation/before link, link-only,
  outer-only invariant injection, after receipt-bound outer claim, reservation,
  provider send, adapter entry, target start, cleanup,
  pending-outcome seal, and terminal-append boundaries. Observation failure has
  no outer row/effect; same-tick/same-submission recovery alone may complete a
  winning link after current revalidation, without policy; expiry winner and
  orphan reconciliation have zero effect. An outer lacking its exact receipt is
  quarantined and cannot execute. In a non-approval final case, same key/
  body/scope resolves one submission, one fixed use-attempt batch, one effect, and
  one terminal pair; changed bytes/key or changed
  action/invocation coordinate conflicts. Reconciliation appends only retained
  terminal-intent bytes and never re-enters provider/node/adapter/target.
- Deterministic observation barriers race link and expiry strictly before, exactly
  at, and after `unclaimed_expires_at`; exactly one same-row CAS wins. Fixtures
  inject response loss, owner restart, clock/store/revision uncertainty, link-only
  crash, expiry tombstone before payload deletion, corrupt/missing receipt, and an
  impossible outer-only row. Expiry yields zero outer/effects; exact link-only
  recovery can create only its original outer after current revalidation.
- Direct and tick approval fixtures prove one initial stable `NeedsApproval`
  attempt leaves the parent `awaiting_approval`, then exact stable `/actions`
  retry preserves the original direct key/request digest or tick observation/
  run/tick/ordinal/candidate digest, claims one owner receipt, and executes at
  most once without policy, new tick, or state-head advance. Raw grant, changed
  action/time/adapter/quota/precondition/causal input/requirement, wrong/new
  principal/effect coordinate, competing/expired/revoked receipt, cancel,
  work-order/data-use/policy revocation, crash before/after claim, terminal append
  loss, and response loss follow the exact no-effect/recovery matrix.
- A compile/prototype test proves session typestates and `!Send + !Sync`
  context/attestation/view/seal lifetimes cannot serialize, clone, escape to
  unrelated tasks, or enter `'static` storage. Panic, cancellation, timeout, and
  forgotten-context tests prove the gateway owner still cleans/quarantines.
- Trap providers prove daemon, SDK, policy, replay, authority, incident, health,
  node, direct adapter setup, and non-secret calls cannot invoke provider methods.
  Renew/revoke/audit/active-probe tests each traverse the gateway control profile
  once with an Authority ledger claim before requested evidence/I/O,
  authorization, deadlines, no-send-only bounded retry, write-ahead sent state,
  pre/post evidence, no target adapter, and no recursive invocation. Exact
  duplicate, changed bytes, sent-known, sent-uncertain, provider return, completed-
  event loss, Authority-CAS loss, and response loss prove no repeated method.
- Trap node bridges prove Authority, daemon, incident, replay, expiry, shutdown,
  reconciler, and background paths cannot mutate resident node/OS/orchestrator
  state directly. Every prepare/activate/fence/terminate/close/unmount/delete/
  attest/revocation acknowledgement crosses one typed node-control permit and
  owner-defined closed result plus C03 receipt; backend strings/OS-code inference
  reject. Faults before claim/requested evidence/write-ahead send, after send,
  after node return/result/evidence/receipt/completed event/Authority CAS, and
  response loss prove one mutation. Exact duplicates return original state;
  changed plans conflict; sent uncertainty never resends; one reconciler or a
  fresh read-only absence/current-state attestation cannot infer-terminalize the
  original. Timeout/ambiguous acknowledgement quarantines without alternate-node
  failover or false success. `no_retry` proves one bridge attempt only;
  `one_no_send_retry_100ms` proves exactly one same-plan retry only after owner
  no-send evidence and exactly 100 ms. Missing evidence, changed retry profile,
  or any write-ahead sent state produces zero retry. Canonical result/intent/
  receipt bytes include the same profile.
- Exact trace/order tests cover success, adapter failure, cancellation,
  postcondition failure, terminal append failure, cleanup uncertainty, and
  quarantine for both tick and direct submission. Every released final effect-
  terminal outcome has exactly one matching terminal receipt and one final
  effect-terminal `action.*` event. Approval cases additionally have exactly one
  prior released zero-effect `action.needs_approval` with no receipt;
  direct paths invent no tick/state events; terminal-evidence blockage releases
  no outcome or state advancement. Pending-outcome append failure preserves the
  exact Gateway-sealed bytes under Authority ownership and never reconstructs an
  outcome from receipt fields. Tests count
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
  cannot overlap target generations. Crash recovery proves the parent pending/
  active generation, Authority use-attempt row, delivery handle, and node target
  agree; mismatch quarantines and no method child or reconciler allocates a
  competing generation. Wrong/missing/reordered slot and wrong exact
  origin/service/account/cluster/database/device/artifact/model destination deny
  before provider I/O. Orchestrator API/etcd/audit/manifest captures contain no
  canary.
- For `trusted_injection`, exact approved destination sends succeed while wrong
  slot/origin/account/resource, redirect, DNS rebinding, proxy change, alternate
  peer, and transport re-resolution deny before credential-bearing bytes leave.
  For `material_exposed`, shell/Python/OCI/Kubernetes canary targets attempt raw
  sockets, direct DNS, environment/application proxies, externally writable
  filesystem/output/alternate mounts, Unix sockets/pipes/shared memory IPC,
  child/helper process/fd inheritance, and material in the correct destination's
  wrong header, query, path, body, or protocol frame. Accepted SBX-007 deny-all
  controls prove zero bytes left for every attempt with typed pre/post evidence,
  quarantine/cleanup, and no publication. Captured target bytes remain only in
  bounded private broker scratch for detector/incident handling and are wiped or
  quarantined; no scanned/sealed target-output publication exists. Additional
  targets emit custom XOR/table transforms, custom alphabets, secret bits in valid
  JSON values, selectable error/result branches, chosen exit codes/delays, and
  chunked low-bandwidth covert output. Every case records the same fixed internal
  suppression status and returns the same terminal/restricted envelope at the
  fixed release boundary with absent outcome/receipt/output/artifact/state/trace
  fields. Missing enforcement denies before provider acquisition/
  delivery; destination allowlists, pattern no-match, after-send DLP, and cleanup
  alone never pass the case.
- Pressure fixtures fill every normal hot/durable quota and active-uncertainty
  allowance plus every normal marker slot after an exposure has atomically
  reserved its unit, then exercise provider revoke/audit, node fence/terminate/close/
  unmount/delete/attest, cleanup, terminal evidence, incident, reconciliation,
  and tombstone/retirement commit from the non-borrowable reserve. All 17 typed
  marker slots, 552 event/evidence slots, and 4,768 KiB byte categories are driven
  to their exact maxima. New exposure stops first, every already-reserved write
  retains its slot through restart, used/unused release and domain retirement are
  verified, and no active/tombstone/reserve row is evicted or reassigned.
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
  `splendor.daemon.submit_secret_action.v1` fixtures pin every field/type/bound,
  required/absence/null/default rule, client-versus-server quota normalization,
  stable `SubmitActionRequest` mapping, unknown/duplicate/forbidden field, minimum/
  maximum object, changed-field conflict, and ingress/semantic digest. Candidate
  fixtures pin every exact field/type/bound, null-versus-absence,
  optional tag, order, timestamp, candidate/policy/tick digest, retained
  observation byte, expiry/tombstone, and stable plain-candidate mapping. Response
  fixtures pin all eight states in full/restricted views, every required/forbidden
  field, awaiting challenge/cancelled behavior, complete/
  withheld receipt, split/outer certainty, duplicate/poll/retry behavior,
  content type, HTTP status, size cap, and unknown-field/enum negatives. For
  material exposure, all four clients decode only the fixed terminal/restricted
  suppression envelope with no `ActionOutcome` or receipt; no helper can request
  or decode a target-derived projection.
- Public API authorization fixtures use two same-tenant/run principals and cover
  creating POST, duplicate POST, and GET. Submit-only B never receives A's full
  or restricted object; submit-only A receives restricted GET only; exact
  current dedicated original/inspector read authority is audited;
  expiry/revocation of result/output/data-use/work-order authority withholds
  output/restricted receipt metadata while returning safe non-retryable status
  only to an existence-authorized caller. UUID knowledge is never sufficient.
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
  account/audience bootstrap, all cross-route private-handle alias/reuse
  and canonical backing-source alias rejection (including byte-identical profiles,
  same inode/item/principal/token/cache), broad identity rejection, rotation/
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
- Partition, stale policy/revocation, node restart, clock rollback, approval/
  provider/node duplicate and response loss, compaction/reuse, backing-source
  alias, egress-control loss, crash, pressure, result-authority revocation, and
  cleanup quarantine evidence passes.
- Revocation uncertainty retains `revocation_pending`, emits only
  `secret.revocation.uncertain`, stays quarantined, and recovers through a new
  authorized gateway control invocation before any `secret.revoked` fact.
- The exact cross-tenant 404/body/256-byte/timing/statistical criterion passes,
  with zero provider/node calls and tenant-keyed correlation. Every FND-012
  latency, cardinality, timeout/retry, detector throughput/memory/backpressure,
  output-drain, cleanup, and 24-hour soak budget passes on the activation
  composition. Worst-case 64-KiB material with every enabled representation at
  64 detectors and 16 concurrent invocations satisfies the 98-MiB node and
  24.5-MiB tenant equations including the 2-MiB/512-KiB hot containment pools,
  plus the 298-MiB/74.5-MiB durable reserve floors, normal minimum 8-MiB/2-MiB
  marker stores, and emergency 2,176/544-KiB marker floors. The report proves
  35,328/8,832 event-evidence credits and all 17 marker classes per unit. Overflow admission
  deterministically denies before provider/node/adapter work and never evicts
  active detector/control/tombstone state. Missing evidence keeps
  `secret_broker_v1` off.
- Sustained trusted-injection/material-exposed canary runs continuously attempt
  raw socket/DNS/proxy/filesystem/IPC/child/helper/alternate-mount and correct-
  destination wrong-slot egress. No forbidden byte leaves; material exposure has
  no outbound credential use, and evidence/host-control loss denies or
  quarantines. Custom transform/alphabet/valid-JSON/error/exit/timing/chunked
  output remains zero-publication with one fixed release projection. Provider/
  node-control hot/durable pressure never evicts active or
  uncertain rows; duplicate delivery across restart produces no second provider
  or node operation.
- The 16-requirement maximum receipt/event fixture remains queryable after hot-
  index eviction, while every hot command/use-attempt/submission-index/provider-
  control/node-control record is
  <=2 KiB. Dropped responses and duplicate observations throughout the 24-hour
  soak produce zero duplicate reservations, provider/node/adapter/target effects,
  receipts, or final terminal events. Full-record expiry throughout the soak
  retains exact tombstone/conflict behavior and observation link-versus-expiry
  before/at/after the boundary is deterministic. Full normal-quota and normal-
  marker exhaustion followed by revoke/fence/cleanup/terminal/tombstone work
  uses the existing reserve while new exposure denies. Independent lineage-
  generation retirement and exact/changed post-deletion equality remain correct.
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
   This includes `ManagementEventId`, the Event/Evidence preclaim observation
   owner with exact claim-state/link-receipt/expiry CAS/tombstones, durable
   approval receipt claim/revoke
   recovery, the NODE-003/SBX-001 target/permit plus sole closed node-control
   result/outcome/reason/retry-profile and invocation/send/terminal ABI, and
   SBX-007 deny-all exposure enforcement/evidence plus zero target-publication
   ABI for material-exposed targets. C03 does not add substitutes.
3. V1b bound execution/authority/lease/delivery/event/command contracts and
   cross-language matrix fixtures.
4. Authority-owned lifecycle; durable outer submission/approval-continuation/
   terminal-intent ledger and reconciler; provider/node control invocation/
   terminal-intent/hot-index ledgers; permanent tombstones/retired domains;
   containment reserves; stable parent exposure aggregates/method children/
   target generations; use-attempt/idempotency/CAS behavior; validated wrappers;
   and outbound provider port.
5. Gateway provider-control profile plus tagged deterministic/dev-local providers
   with the canonical backing-source registry, mode/file/keychain safety, and the
   atomic narrow dependency specialization.
6. Same-gateway wrapper, secret-lease and live credential-ingress verifiers,
   staged session, borrowed permit, driver-local delivery ABI, postcondition
   continuation, Gateway-owned pending-outcome terminal normalizer, principal/
   current-policy result views, closed direct request generation, exact stable
   approval continuation, and direct/tick observation/recorder integration.
7. Only after real NODE/SBX/SBX-007/FND-009 owners land: delivery/control/egress evidence,
   pre-persistence detector and output drain, production provider bootstrap/
   transport, external drivers/examples, FND-012 activation evidence, and gold.

Known prerequisite boundaries remain explicit:

- C01/C02 and `FND-001`, `FND-005`, and `FND-009` have useful local seams but
  are not catalog-wide completion evidence.
- Accepted compatible `NODE-003` #302 and `SBX-001` #400 contracts are required
  before node-control/delivery implementation. They must own the exact durable
  invocation/send/result/terminal/reconciler contract, not only a backend result;
  their production evidence is required before live activation.
- Accepted compatible `SBX-007` network/filesystem/process/syscall/IPC/device
  isolation and typed evidence proving deny-all egress is required before any
  `material_exposed` driver can enter V3-V5 or live activation. General-purpose
  target code is denied material without it and never gets destination-allowlisted
  outbound credential use. It also receives no target-controlled result channel;
  returned-data workloads use trusted injection or a future separately accepted
  declassifier/noninterference owner contract.
- The approval/Authority owner must supply restart-durable exact-continuation
  claim/revoke ownership and crash recovery. The current process-local stable
  receipt ledger cannot authorize live C03 approval-required effects.
- FND/fabric/DGW owners must supply `WorkloadAttemptId`,
  `PlacementDecisionId`, `ExecutionLeaseId`, `InvocationId`, and
  `DriverOperationRef`; Event/Evidence must supply `EvidenceId` and nominal
  `ManagementEventId` plus preclaim tick-observation claim/link/expiry and
  management ordering/integrity/visibility; NODE/SBX must
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
- No trusted declassifier, information-flow proof, malicious-code noninterference
  claim, or target-selected material-exposed publication contract in v1.
- No cross-route bootstrap source/SDK credential-handle sharing contract in v1;
  even byte-identical routes use distinct bindings and private handles.
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
  and missing final receipt means non-retryable uncertainty except for the exact
  zero-effect awaiting-approval or cancelled states.
- `splendor.daemon.submit_secret_action.v1` has one complete canonical Rust field/
  type/bound/presence/null/default contract, exact stable `SubmitActionRequest`
  mapping, client-versus-server normalization, unknown/duplicate rejection,
  minimum/maximum fixtures, and separate ingress/semantic digests. Generated
  OpenAPI/Python/TypeScript bytes must match before exposure.
- The additive tick candidate has one complete field/type/bound/null/unknown-
  field contract across Rust/OpenAPI/Python/TypeScript. Its named candidate
  digest encodes every semantic field, order, timestamp, and optional absence;
  the tick key consumes only that named digest for candidate meaning.
- Event/Evidence owns one immutable safe preclaim observation with complete
  retained candidate bytes/digest, policy-output identity/digest, run/tick/
  ordinal, sequence/time, duplicate conflict, and orphan no-effect semantics plus
  a separate mutable `unclaimed -> linked_to_exact_submission|expired` owner row.
  Stable `CandidatesProposed` bytes do not change; observation failure prevents
  outer claim/effects and recovery never reinvokes policy. Owner clock, recorded
  policy revision, 5-minute/deadline+60-second/24-hour expiry, boundary behavior,
  exact submission/digest-bound link receipt, same-row CAS, same-tick link-only
  recovery, deterministic tombstone-before-delete, and invalid outer-only denial
  are exact.
- Every POST/lookup state has one exact full/restricted response matrix and HTTP/
  content-type contract. Same-key full recovery is original-principal and current-
  policy bound; historical/delegated inspection requires the dedicated exact
  scope, current output/data-use/work-order/revocation visibility, and audit.
  Submit-only unrelated principals receive uniform not-available, while an
  existence-authorized caller without result visibility receives only restricted
  non-retryable status.
- Authority claims one durable outer submission before C03 terminal evidence,
  reservation, provider/node work, or adapter entry; a tick outer may be inserted
  only after its exact durable Event/Evidence link receipt validates. Exact
  duplicates resolve its fixed batch/result; changed bytes/key/action conflict;
  pre-reservation denial has an empty batch; terminal append recovery never replays
  an effect.
- A stable initial `NeedsApproval` remains terminal for that gateway attempt but
  atomically leaves the same C03 parent `awaiting_approval`. One immutable
  challenge-bound continuation preserves original principal/run/tick/workload/
  action/adapter/quota/preconditions/time/requirements and every digest. Only the
  exact current owner receipt may claim once through stable `/actions`; direct
  keeps its key, tick keeps its observation, and no new tick/policy/effect
  coordinate exists. Duplicate/crash/cancel/revoke/expiry paths are closed.
- `SecretProvider` is an authority-owned Rust outbound port, not a serialized
  type or provider SDK in core; only the exact secret-provider dependency
  specialization is proposed.
- The one staged gateway session atomically reserves and durably records every
  requirement-specific containment unit and use, allocates their attempt-bound
  target/fence/control sets, and only then fetches/delivers through a
  non-serializable driver-local context and exactly one driver invoke.
- Raw driver response/error data remains opaque and driver-owned. Trusted
  injection may run gateway postconditions and scan a proposed projection before
  raw-buffer wipe, then seal the complete drained publication set before public
  release. Material exposure accepts no target-result postcondition/projection;
  captured bytes remain private detector/incident input, never ordinary
  state/trace/artifact/error/output, and are wiped/quarantined. Cancellation,
  timeout, panic, process death, and cleanup failure enter the same fail-closed
  session path.
- Stable outcome meanings are preserved. Tick and direct actions use one
  Gateway-owned terminal normalizer that constructs/seals the private pending
  stable outcome; Authority owns its durable record and terminal intent. Every
  released terminal outcome has exactly one matching immutable receipt and outer
  action event, while pending/terminal append blockage releases no outcome/state
  advancement or reconstructed substitute.
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
- `trusted_injection` keeps bytes out of target code and revalidates the actual
  exact destination, redirect/DNS/proxy/transport immediately before send.
  `material_exposed` requires accepted SBX-007/NODE/SBX deny-all network,
  filesystem, IPC, child, proxy, and alternate-mount enforcement with typed pre/
  post evidence; otherwise general-purpose target delivery denies before
  provider acquisition. After exposure, one fixed broker-owned `Failed`/absent-
  output/suppression projection is recorded internally and one fixed terminal/
  restricted envelope is released at the fixed boundary; custom XOR,
  table, alphabet, valid-JSON-bit, error/result/exit/timing, and chunked output
  cannot choose any public/persistent value. Exfiltration attempts quarantine and
  never become success through cleanup. Workloads needing returned data or
  credentialed network/IPC use trusted injection or a future separately accepted
  declassifier contract.
- Provider renew/revoke/audit/active probes are typed gateway-mediated control
  effects with an Authority ledger claimed before evidence/bootstrap/provider I/O,
  canonical plan equality, authorization, deadlines, no-send-only bounded retry,
  non-recursion, immutable terminal intents/results/receipts, and explicit
  sent-uncertain recovery. Exact duplicates never call the provider again;
  post-effect loss uses retained bytes or a new authorized read-only audit.
  Passive inspection is side-effect-free registration metadata only.
- Provider terminal intent uses the named non-self-referential digest projection;
  it explicitly contains invocation ID, plan digest, and partition digest, with no
  inferred invocation digest. The digest output exists only in invocation/hot
  pointers. The exact generated 902-byte <=1-KiB
  provider hot index contains only partition/invocation/state/plan/send/result/
  terminal pointers and excludes every full plan/result/intent/evidence record.
- Provider control uses closed run-trace or owner-defined management-event
  causality and tenant-only provider trust scope in v1; no fake run/tenant/shared
  trust label is accepted. Non-run controls stay disabled until the management
  event owner contract exists.
- Resident-node prepare/activate/fence/terminate/close/unmount/delete/attest/
  revocation acknowledgement uses the separate typed gateway node-control ABI.
  A named plan digest and unique durable invocation claim precede requested
  evidence/I/O; exact `no_retry|one_no_send_retry_100ms` appears in plan/result/
  intent/receipt bytes; write-ahead send, exact owner result, terminal intent, hot
  index, one reconciler, duplicate/response-loss/CAS recovery, and no resend after
  uncertainty are required. The accepted NODE/SBX owner supplies the sole exact
  result/outcome/reason vocabulary; backend strings or inferred OS codes are
  invalid. Direct node mutation is forbidden, uncertain acknowledgement
  quarantines, and every live node gate remains disabled until accepted owner
  contracts exist.
- The Authority use-attempt row is the sole target-generation binding owner; the
  delivery handle repeats its exposure-lineage ID and generation, and method
  children own no competing generation namespace. Node plans/results/receipts,
  cleanup, restart/migration, tombstones, and retirement preserve that lineage;
  independent lineages with generation 1 never collide. Recovery mismatch
  quarantines rather than allocating a sibling.
- Direct/tick, approval, provider, node, and observation IDs/effect coordinates
  have a closed tagged tombstone union with exact per-domain accepted bindings,
  effect coordinates, named disposition digests, authority domains, slot sources,
  and integrity chain. Retired-domain marker fields/digest are exact. Full-record
  expiry never becomes a miss; exact/changed equality remains deterministic after
  deletion, corrupt/unavailable dedupe denies, retired domains reject before
  lookup, quota cannot delete/rearm markers, and replay remains no-effect.
- Delivery, cleanup, renewal, rotation, revocation, offline, HA, retention, leak,
  replay, compatibility, and threat behavior is fail closed and testable.
- Process taint, delivery-control evidence, detector/output-drain lifetime,
  route-bound workload-identity/owner-file/keychain bootstrap profiles with SDK
  default chains disabled, canonical private backing-source uniqueness, and one-
  route ownership even across distinct wrappers/FDs/items/tokens/caches and byte-
  identical routes, tagged local profiles, dev/keychain restrictions, uniform
  privacy responses, and the arithmetic FND-012 detector/invocation/idempotency
  ledger are explicit.
- Material-exposed processing has network, IPC, proxy, child/helper, and external-
  filesystem egress deny-all and no credential-backed outbound use. Only private
  broker scratch exists for bounded leak/incident scanning; target-controlled
  bytes are never sealed for publication. Outbound credential use
  requires trusted injection's exact actual destination and nominal slot; wrong
  header/query/path/body/frame attempts emit zero bytes.
- Before every exposure, a non-borrowable reserve covers worst-case provider
  revoke/audit, node fence/terminate/close/unmount/delete/attest, cleanup,
  terminal/evidence/incident/reconciliation/tombstone work. Normal quota cannot
  consume it; unavailable reserve stops new work first; release waits for known
  terminal cleanup/revocation. It atomically includes 17 typed emergency marker
  slots, exactly 552 event/evidence credits, and 4,768 KiB durable bytes per unit;
  normal identities cannot borrow those slots and release returns only unused
  capacity. FND-012 proves 98/24.5-MiB hot totals, 298/74.5-MiB durable
  containment floors, normal minimum 8/2-MiB marker stores, and emergency
  2,176/544-KiB marker floors.
- The <=2-KiB hot submission/provider/node-control indexes contain only lookup/
  state/digest/terminal pointers; active uncertainty cannot be evicted and full
  immutable terminal intents/receipts/results use quota-controlled durable
  storage. Summary and event order/uniqueness/cardinality are fixed and covered
  by the 16-requirement maximum fixture.
- Current read-time redaction is explicitly insufficient for live C03.
- External SDK/scanner rules distinguish caller/bootstrap credentials from
  workload secrets and never expose material. Every adopted credential-capable
  operation rejects raw credential-bearing generic params/headers/bodies/URLs/
  environment material before adapter/provider execution, with only exact
  owner-versioned non-secret exceptions.
- V0-V5 and issue/gold closure rules prevent docs or bounded local tests from
  becoming false completion evidence.
- Deferred owner boundaries and non-goals remain explicit.
