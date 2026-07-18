# Secret Broker Reference

## Status

**status/incomplete — C03 V1a identity grammar only.**

The current implementation adds 40 behavior-free nominal UUID identity types in
`splendor-types`. It does not implement `SecretRef`, `SecretUseRequirement`, a
provider port, a broker lifecycle, lease or delivery records, secret material
handling, gateway/daemon/API/SDK integration, a scanner, side effects, issue
closure, or gold evidence. No generated public surface is claimed.

## Purpose and boundary

These types reserve distinct identities for later C03 contracts without
creating those contracts or their allocation owners. Possessing an identity
does not authorize access, delivery, publication, reconciliation, retry, or any
other operation. The types contain UUID identity only; they contain no secret
material, provider locator, credential, authority, lifecycle, or runtime state.

## Canonical contract

Each implemented type:

- is a distinct Rust newtype backed by a non-nil UUID;
- parses and deserializes only lowercase hyphenated canonical UUID text;
- serializes and displays as that exact 36-character representation;
- supports checked `TryFrom<Uuid>` construction, rejecting nil;
- provides `as_uuid`, equality, hashing, and UUID network-byte ordering; and
- reports bounded errors that do not include the rejected candidate.

Uppercase, compact, braced, URN, whitespace-padded, malformed, nil, null,
boolean, numeric, object, and array inputs fail closed. These rules are additive
and do not tighten or otherwise change the stable 0.1 UUID identity types.

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

## Minimal example

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

## Lifecycle, trace, and replay

No lifecycle is implemented. Creating or parsing an ID does not create a
corresponding record. This slice emits no trace/evidence event, changes no state,
and performs no side effect. Consequently there is no C03 runtime replay path;
the values may only round-trip as identity scalars in code that explicitly uses
them.

## Failure and security behavior

Malformed or noncanonical input returns `SecretIdParseError::InvalidFormat`;
canonical nil input and nil UUID construction return `SecretIdParseError::Nil`.
Neither error contains candidate input. There is no unchecked `From<Uuid>`,
`Default`, random allocator, audience derivation, authority check, or provider
behavior on these types.

## Compatibility and versioning

The symbols are additive experimental 0.2/v2 Rust exports. Existing 0.1 ID
constructors, permissive parsing/deserialization behavior, serialized bytes, and
aliases remain unchanged. Future records that use these identities still require
their owning contracts and compatible versioning. In particular,
`SecretCredentialSlotId` and the exact driver credential-sink binding remain
external owner blockers for `SecretRef` and `SecretUseRequirement`.
