# Secret Broker Reference

## Status

**status/incomplete — C03 V1a identities, owner-independent pre-placement
grammar, behavior-free trusted-send control vocabulary, and non-authorizing
secret-use requirement grammar only.**

The current implementation adds 40 behavior-free nominal UUID identity types,
seven closed enums, a strictly validated opaque `SecretProviderVersionRef`, a
valid-by-construction `SecretLeasePolicy`, and the strict
`SecretUseRequirement` v1 Rust contract in `splendor-types`. The requirement
imports the Driver Registry-owned `SecretCredentialSlotId`. It does not
implement `SecretRef`, credential authorization, a provider port, a broker or
lease lifecycle, lease or delivery records, secret material handling,
Gateway/daemon/API/SDK integration, a scanner, side effects, feature activation,
issue closure, or gold evidence. No generated public surface is claimed.

## Purpose and boundary

These values reserve distinct identities and closed policy vocabulary and let
typed callers describe a non-authorizing secret-use requirement without creating
an authority, lease, provider, or allocation owner.
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

## Secret-use requirement contract

`SecretUseRequirement` is the additive experimental Rust representation of
`splendor.secret.use_requirement.v1`. Its fields are private. `try_new` accepts
already typed values, while `from_json_slice` is the sole imported, persisted,
rehydrated, or otherwise untrusted byte ingress. The validated type implements
`Serialize` but intentionally does not implement public generic `Deserialize`.

| Field | Rule |
| --- | --- |
| `schema_version` | Exactly `splendor.secret.use_requirement.v1`. |
| `secret_ref_id` | Strict non-nil canonical `SecretRefId`. |
| `credential_slot_id` | Strict non-nil canonical Driver Registry-owned `SecretCredentialSlotId`. |
| `intent` | Exact closed `SecretUseIntent` string. |
| `purpose` | Exact closed `SecretPurpose` string. |
| `delivery_methods` | One through five unique `SecretDeliveryMethod` values in caller preference order. |
| `requested_duration_seconds` | Integer `1..=9007199254740991`. |
| `requested_max_uses` | Integer `1..=9007199254740991`. |
| `required` | Exactly `true`; best-effort secret use is not defined in v1. |

Delivery preferences are not sorted or silently deduplicated. Their order is
preserved and changes canonical bytes; a duplicate fails closed. Serialization
uses the exact closed nine-field shape in RFC 8785 member order. Missing,
duplicate, unknown, null, wrong-type, false, malformed-ID, unknown-enum, empty,
over-bound, zero, and safe-integer-overflow inputs reject. Error variants expose
only bounded fixed codes and retain no rejected candidate text.

Before constructing its private wire input, `from_json_slice` performs one
duplicate-aware JSON preflight with these exact v1 limits:

| Resource | Maximum |
| --- | ---: |
| Raw encoded JSON | 1,024 bytes |
| Object/array depth, root at depth 1 | 2 |
| Decoder tokens (container delimiters, names, scalar values) | 26 |
| Object members across the document | 9 |
| Array elements across the document | 5 |
| Decoded bytes per member name or string | 36 |

These limits are specific to the closed nine-field, maximum-five-method schema.
The generated legal maximum is 465 compact bytes and reaches every structural
limit except raw encoded bytes, where bounded room remains for harmless
whitespace and equivalent JSON escapes. Cap-plus-one, malformed UTF-8/JSON,
duplicate names at any object depth, unknown root fields, overlong decoded
names/strings, and whitespace or escape bombs fail closed. Parser details,
locations, rejected keys/values, and source chains are not exposed.

The requirement contains no secret material, provider locator, destination,
target, authority, declaration revision, lease, delivery handle, fallback, or
environment name. It does not construct or consume
`SecretRef.allowed_credential_bindings`; possession or successful parsing grants
no authority.

## Implemented identity inventory

| Area | Types |
| --- | --- |
| Reference, lease, delivery | `SecretRefId`, `SecretLeaseRequestId`, `SecretLeaseId`, `SecretDeliveryHandleId`, `SecretDeliveryReceiptId`, `SecretDeliveryControlAttestationId` |
| Outer action | `SecretActionSubmissionId`, `SecretActionIdempotencyKey`, `SecretApprovalContinuationId`, `SecretOuterAdmissionCapacityBindingId` |
| Provider and bootstrap | `SecretProviderId`, `SecretProviderRouteId`, `SecretProviderAuditId`, `SecretProviderControlInvocationId`, `SecretBootstrapSourceBindingId` |
| Event, node, audience, detector | `SecretAccessEventId`, `SecretTickCandidateObservationId`, `SecretTickCandidateObservationLinkReceiptId`, `SecretNodeControlInvocationId`, `SecretNodeControlReceiptId`, `SecretAudienceId`, `SecretDetectorRegistrationId` |
| Exposure, use, commands | `SecretExposureLineageId`, `SecretUseAttemptId`, `SecretRefMutationCommandId`, `SecretRenewalCommandId`, `SecretRotationCommandId`, `SecretRevocationCommandId`, `SecretCleanupCommandId`, `SecretContainmentCommandId`, `SecretUseClaimId`, `SecretContainmentReserveId` |
| Publication, reconciliation, retirement | `SecretPublicationPreparationId`, `SecretPublicationAuthorizationId`, `SecretPublicationPrepareReceiptId`, `SecretReconciliationClaimId`, `SecretConsumedEffectTombstoneId`, `SecretPermanentAuxiliaryIdentityMarkerId`, `SecretRetiredAuthorityDomainDenyHeadId`, `SecretRetirementManifestId` |

`SecretCredentialSlotId` is implemented by the behavior-free Driver Registry
credential-sink contract and is imported rather than shadowed by C03.
`PhysicalMetadataBudgetSigningKeyId`, `SecretTerminalizationLeaseId`, and all
other foreign-owner or V1b identities remain unimplemented.

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

```rust
use splendor_types::{
    SecretCredentialSlotId, SecretDeliveryMethod, SecretPurpose, SecretRefId,
    SecretUseIntent, SecretUseRequirement,
};

let requirement = SecretUseRequirement::try_new(
    "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001".parse::<SecretRefId>()?,
    "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4101".parse::<SecretCredentialSlotId>()?,
    SecretUseIntent::Authenticate,
    SecretPurpose::ExternalServiceAccess,
    vec![SecretDeliveryMethod::InheritedFd],
    300,
    1,
    true,
)?;
assert!(requirement.required());

let encoded = serde_json::to_vec(&requirement)?;
let parsed = SecretUseRequirement::from_json_slice(&encoded)?;
assert_eq!(parsed, requirement);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Lifecycle, trace, and replay

No lifecycle is implemented. Creating or parsing an ID, provider version
reference, enum, lease policy, or use requirement does not create a secret
reference, authority, lease, or delivery. This slice emits no trace/evidence
event, changes no state, and performs no side effect. Consequently there is no
C03 runtime replay path; the values may only round-trip as behavior-free
contracts in code that explicitly uses them.

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
values. Secret-use requirement failures are fixed code-only categories; its
bounded byte parser and private wire input prevent malformed IDs, enum
candidates, schema candidates, keys, parser details, and wrong scalar types from
being reflected. No implemented primitive contains a
secret value/material/byte field, provider request, raw provider error,
credential value, token, password, or API key.

## Compatibility and versioning

The symbols are additive experimental 0.2/v2 Rust exports. The closed enum
spellings, opaque version-reference wire string, five-field policy object, and
nine-field `SecretUseRequirement` object are the bounded C03 contract for this
slice. Removing public generic `Deserialize` in favor of the sole bounded
`from_json_slice` ingress is the pre-release security correction for this new
experimental type; its canonical serialized bytes are unchanged. Existing 0.1
ID constructors, permissive parsing/deserialization behavior, serialized bytes,
and aliases remain unchanged. Existing C03 pre-placement and Driver Registry
credential-sink fixture bytes are also unchanged. Future records that use these
values still require
their owning contracts and compatible versioning. In particular, complete
revision-bearing credential authorization, approved destination binding,
`SecretRef`, Authority/Gateway/runtime consumption, and historical migration
remain blocked on their separately accepted C03 contract and owner prerequisites.
