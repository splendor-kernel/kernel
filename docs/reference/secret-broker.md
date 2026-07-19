# Secret Broker Reference

## Status

**status/incomplete — C03 V1a identities, owner-independent pre-placement
grammar, and behavior-free trusted-send control vocabulary only.**

The current implementation adds 40 behavior-free nominal UUID identity types,
seven closed enums, a strictly validated opaque `SecretProviderVersionRef`, and
a valid-by-construction `SecretLeasePolicy` in `splendor-types`. It does not
implement `SecretRef`, `SecretUseRequirement`, a provider port, a broker or lease
lifecycle, lease or delivery records, secret material handling,
Gateway/daemon/API/SDK integration, a scanner, side effects, feature activation,
issue closure, or gold evidence. No generated public surface is claimed.

## Purpose and boundary

These values reserve distinct identities and closed policy vocabulary for later
C03 contracts without creating those contracts or their allocation owners.
Possessing an identity, enum value, provider version reference, or lease policy
does not authorize access, delivery, publication, reconciliation, retry,
renewal, or any other operation. The implemented values contain no secret
material, provider locator, credential, authority, lifecycle, or runtime state.

## Canonical identity contract

Each implemented identity type:

- is a distinct Rust newtype backed by a non-nil UUID;
- parses and deserializes only lowercase hyphenated canonical UUID text;
- serializes and displays as that exact 36-character representation;
- supports checked `TryFrom<Uuid>` construction, rejecting nil;
- provides `as_uuid`, equality, hashing, and UUID network-byte ordering; and
- reports bounded errors that do not include the rejected candidate.

Uppercase, compact, braced, URN, whitespace-padded, malformed, nil, null,
boolean, numeric, object, and array inputs fail closed. These rules are additive
and do not tighten or otherwise change the stable 0.1 UUID identity types.

## Implemented pre-placement primitives

The following enums are closed to their exact lowercase snake-case v1 values:

| Type | Values |
| --- | --- |
| `SecretClassification` | `authentication_credential`, `signing_material`, `encryption_material`, `private_configuration`, `opaque_secret` |
| `SecretDeliveryMethod` | `inherited_fd`, `tmpfs_file`, `one_shot_local_socket`, `orchestrator_projected_secret`, `environment_variable` |
| `SecretUseIntent` | `authenticate`, `sign`, `encrypt`, `decrypt`, `derive_session`, `bootstrap_transport` |
| `SecretPurpose` | `external_service_access`, `data_source_access`, `artifact_store_access`, `model_provider_access`, `orchestrator_access`, `device_service_access`, `cryptographic_operation` |
| `SecretOfflineBehavior` | `deny`, `continue_existing_until_expiry` |
| `SecretDeliveryExposureProfile` | `trusted_injection`, `material_exposed` |
| `SecretDeliveryControlKind` | `core_dump`, `ptrace_debug`, `child_inheritance`, `output_capture`, `swap_page_dump`, `generic_cache`, `orchestrator_projection`, `trusted_injection_boundary`, `destination_network_egress`, `filesystem_sink_egress`, `ipc_egress`, `child_process_egress`, `proxy_egress`, `alternate_mount_egress` |

These enums serialize and deserialize only as the exact string values above.
Case changes, unknown strings, externally tagged objects, and every non-string
form reject with fixed non-reflecting errors. Their Rust ordering compares exact
ASCII wire spellings rather than declaration order.

`environment_variable` is compatibility vocabulary only. Its presence grants no
permission and does not add delivery behavior.

`SecretDeliveryControlKind` is the C03-owned trusted-send control vocabulary for
future driver credential-sink declarations. A value describes a control kind
only; it does not prove that a control is present, grant delivery authority, or
add broker, driver, registry, Gateway, or runtime behavior.

`SecretProviderVersionRef` is an opaque 1-to-128-byte string containing only
printable non-space ASCII. It rejects `/`, `\\`, `?`, `#`, and `:`, so a URI
scheme, path, query, or fragment cannot enter the type. It is never normalized,
resolved, or exposed through locator/provider helpers. Construction,
`TryFrom<String>`, `FromStr`, and deserialization all use the same validation.
Borrowed input is validated before allocation, while `TryFrom<String>` retains
the validated allocation; errors are bounded and do not retain candidate text.

`SecretLeasePolicy` is a closed object with five required fields and no schema
field or defaults:

| Field | Rule |
| --- | --- |
| `max_lease_duration_seconds` | Integer `1..=9007199254740991`. |
| `max_continuous_lifetime_seconds` | Same bounds and not less than `max_lease_duration_seconds`. |
| `max_uses` | Integer `1..=9007199254740991`. |
| `renewable` | Required boolean. |
| `clock_skew_tolerance_seconds` | Integer `0..=30`; it creates no post-expiry grace. |

Its fields are private. Checked construction and custom strict deserialization
through a private closed input are the only public/wire construction paths;
getters expose the validated policy. Missing, duplicate, unknown, null,
wrong-type, out-of-range, and invalid relationship forms reject without
candidate-policy reflection.

## Implemented identity inventory

| Area | Types |
| --- | --- |
| Reference, lease, delivery | `SecretRefId`, `SecretLeaseRequestId`, `SecretLeaseId`, `SecretDeliveryHandleId`, `SecretDeliveryReceiptId`, `SecretDeliveryControlAttestationId` |
| Outer action | `SecretActionSubmissionId`, `SecretActionIdempotencyKey`, `SecretApprovalContinuationId`, `SecretOuterAdmissionCapacityBindingId` |
| Provider and bootstrap | `SecretProviderId`, `SecretProviderRouteId`, `SecretProviderAuditId`, `SecretProviderControlInvocationId`, `SecretBootstrapSourceBindingId` |
| Event, node, audience, detector | `SecretAccessEventId`, `SecretTickCandidateObservationId`, `SecretTickCandidateObservationLinkReceiptId`, `SecretNodeControlInvocationId`, `SecretNodeControlReceiptId`, `SecretAudienceId`, `SecretDetectorRegistrationId` |
| Exposure, use, commands | `SecretExposureLineageId`, `SecretUseAttemptId`, `SecretRefMutationCommandId`, `SecretRenewalCommandId`, `SecretRotationCommandId`, `SecretRevocationCommandId`, `SecretCleanupCommandId`, `SecretContainmentCommandId`, `SecretUseClaimId`, `SecretContainmentReserveId` |
| Publication, reconciliation, retirement | `SecretPublicationPreparationId`, `SecretPublicationAuthorizationId`, `SecretPublicationPrepareReceiptId`, `SecretReconciliationClaimId`, `SecretConsumedEffectTombstoneId`, `SecretPermanentAuxiliaryIdentityMarkerId`, `SecretRetiredAuthorityDomainDenyHeadId`, `SecretRetirementManifestId` |

`PhysicalMetadataBudgetSigningKeyId`, `SecretTerminalizationLeaseId`,
`SecretCredentialSlotId`, and all other foreign-owner or V1b identities remain
unimplemented.

## Minimal examples

```rust
use splendor_types::{SecretIdParseError, SecretRefId};

let id: SecretRefId = "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001".parse()?;
assert_eq!(
    serde_json::to_string(&id)?,
    "\"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001\""
);

let nil = SecretRefId::parse("00000000-0000-0000-0000-000000000000");
assert_eq!(nil, Err(SecretIdParseError::Nil));
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust
use splendor_types::{SecretLeasePolicy, SecretProviderVersionRef};

let version: SecretProviderVersionRef = "release-001".parse()?;
assert_eq!(version.as_str(), "release-001");

let policy = SecretLeasePolicy::try_new(300, 3600, 10, true, 5)?;
assert_eq!(policy.max_lease_duration_seconds(), 300);
assert_eq!(policy.clock_skew_tolerance_seconds(), 5);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Lifecycle, trace, and replay

No lifecycle is implemented. Creating or parsing an ID, provider version
reference, enum, or lease policy does not create a corresponding record or
lease. This slice emits no trace/evidence event, changes no state, and performs
no side effect. Consequently there is no C03 runtime replay path; the values may
only round-trip as behavior-free contracts in code that explicitly uses them.

## Failure and security behavior

Malformed or noncanonical input returns `SecretIdParseError::InvalidFormat`;
canonical nil input and nil UUID construction return `SecretIdParseError::Nil`.
Neither error contains candidate input. There is no unchecked `From<Uuid>`,
`Default`, random allocator, audience derivation, authority check, or provider
behavior on these types.

Provider version reference failures distinguish empty, over-bound,
non-printable/non-ASCII, and forbidden-locator-delimiter categories without
retaining rejected text. Lease policy failures identify only the violated fixed
range or relationship; strict serde failures do not echo unknown keys or field
values. No implemented primitive contains a secret value/material/byte field,
provider request, raw provider error, credential, token, password, or API key.

## Compatibility and versioning

The symbols are additive experimental 0.2/v2 Rust exports. The closed enum
spellings, opaque version-reference wire string, and five-field policy object are
the bounded C03 contract for this slice. Existing 0.1 ID constructors,
permissive parsing/deserialization behavior, serialized bytes, and aliases remain
unchanged. Future records that use these values still require their owning
contracts and compatible versioning. In particular, the owner-defined
`SecretCredentialSlotId` and exact driver credential-sink authorization,
trusted-send profile, and destination binding remain external blockers for a
complete `SecretRef` and `SecretUseRequirement`.
