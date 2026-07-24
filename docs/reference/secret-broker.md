# Secret Broker Reference

## Status

**status/incomplete — first process-local Secret Broker owner slice, with no
material delivery or production durability.**

The current implementation retains the behavior-free C03 identities,
pre-placement grammar, revision-bound `SecretRefV2`, and historical-v1 read/deny
views described below. It now also provides additive process-local lease
request/snapshot/access-evidence contracts, an Authority-owned broker lifecycle,
an outbound Rust `SecretProvider` port, a zeroizing non-serializable material
wrapper, and a deterministic test/local-development memory provider.

This is bounded progress for `SECR-001`, `SECR-003`, and `SECR-005`. It does not
implement RFC 0012's complete durable lease, exposure-lineage, delivery,
provider-control, node-control, outer-submission, or terminal publication
records. It adds no provider invocation from the broker, material-returning
broker API, Gateway session, resident delivery, persistence, daemon/API/SDK
surface, scanner, production provider, issue closure, or gold pass. The reduced
wire-safe records use explicit `*.local.v1` schema names and do not masquerade as
the complete RFC 0012 wire schemas. `G08` and `G88` remain `not_exercised`.

## Purpose and boundary

The behavior-free values reserve distinct identities and closed policy
vocabulary. The process-local broker is the sole mutation owner for the bounded
lease lifecycle implemented here. Possessing an identity, ref, request,
snapshot, access event, handle ID, or provider version does not authorize secret
use. Every issue, claim, renewal, and revocation call requires current Authority
evaluation over the exact tenant, principal, workload, operation, destination,
placement, audience, ref revision/version, intent, and purpose binding.

## Implemented process-local owner slice

### Safe contracts

`splendor-types` exports four checked, serialize-only local contracts:

| Type | Local schema | Role |
| --- | --- | --- |
| `SecretLeaseUseBinding` | `splendor.secret.lease_use_binding.local.v1` | Exact tenant/principal/workload, Driver operation/declaration/slot/destination, exposure profile, node/instance/audience, ref revision/version, intent, and purpose binding. |
| `SecretLeaseRequest` | `splendor.secret.lease_request.local.v1` | One idempotent request retaining the complete `SecretUseRequirement`, finite window, and request time. |
| `SecretLeaseSnapshot` | `splendor.secret.lease_snapshot.local.v1` | Read-only safe lease state, counters, renewal lineage times, selected delivery method, and event/handle IDs. |
| `SecretAccessEvidence` | `splendor.secret.access_evidence.local.v1` | Ref-only issuance, claim, denial, renewal, and revocation evidence. |

All fields are private and construction is checked. These values implement
`Serialize`, not generic `Deserialize`, and contain no material, provider
locator/request/response, delivery endpoint, bearer capability, arbitrary JSON,
or raw error. They are non-authorizing process-local projections, not the full
RFC 0012 durable contracts.

### Broker lifecycle

`ProcessLocalSecretBroker` in `splendor-authority` is explicitly process-local
and non-restart-durable. Immutable startup configuration supplies validated
`SecretRefV2` records, matching provider registrations, a trusted clock, an ID
source, and a required event sink. Duplicate refs/providers and refs without a
matching provider fail construction.

The owner supports:

- `issue_lease`: validates an unused request ID, current exact ref revision and
  provider version, Driver credential destination, delivery preference, finite
  policy bounds, trusted time, and current cached Authority plus revocation
  evidence before emitting evidence and committing the lease;
- `claim_use`: atomically checks an opaque live handle, every immutable binding,
  exact start/expiry, current Authority, revocation, and the finite use count,
  then returns only an opaque non-serializable `SecretDeliveryClaim`;
- `renew_lease`: preserves the original continuous-lifetime start and use count,
  narrows the remaining maximum, requires a contiguous finite window and current
  Authority, emits evidence before mutation, then supersedes the old handle;
- `revoke_lease`: closes local admission and increments the revocation generation
  before attempting terminal evidence, so event failure can never reactivate the
  handle; a same-handle retry may complete pending terminal evidence; and
- `inspect_lease` and `replay`: clone safe snapshots/evidence only, without time
  reads, ID allocation, authority evaluation, provider calls, or lifecycle
  mutation.

The live `SecretDeliveryHandle` and `SecretDeliveryClaim` have private
capability nonces, private construction, fixed redacted `Debug`, and no `Clone`
or `Serialize`. Generated identity reuse fails closed rather than replacing an
existing lease, handle, claim, or event.

### Provider boundary and test adapter

`splendor-authority::SecretProvider` is an object-safe outbound Rust port with
`fetch`, `renew`, `revoke`, `audit`, and `health` methods. Fetch/control request
types have private construction. Provider errors are closed fixed codes and
discard vendor text. `SecretMaterial` is bounded, non-empty,
non-cloneable/non-serializable, redacted under `Debug`, and backed by
`zeroize::Zeroizing<Vec<u8>>`; zeroization reduces exposure but is not a
perfect-erasure claim.

The broker lifecycle in this slice only registers provider ports and never
invokes them. A future Gateway-owned live session must construct the private
request and retain its permit before provider access or delivery is possible.

`splendor-adapter-secrets-memory` is a deterministic provider for tests and
explicit local development. Construction rejects resident, remote, fleet,
production, and unknown modes. Synthetic entries are exactly keyed by provider,
tenant, ref ID/revision, and provider version; cross-tenant/wrong-version lookup,
outage, revoked versions, duplicate insertion, and invalid material fail with
fixed redacted errors. Rotation installs a new exact version and revokes the old
entry. The adapter opens no listener, reads no environment fallback, and exposes
no public independent resolve method.

The dependency guard recognizes `adapters/secrets-*` before the ordinary adapter
rule and permits exactly `splendor-authority` plus `splendor-types`. It rejects
direct dependencies on Gateway, kernel, store, daemon, node, or another adapter.

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

## Revision-bound secret-reference contract

RFC 0014 adds two behavior-free Rust schemas without changing the accepted v1
bytes in place:

| Type | Exact schema | Purpose |
| --- | --- | --- |
| `SecretCredentialAuthorizationV2` | `splendor.secret.credential_authorization.v2` | Binds one exact Driver operation, positive declaration revision, credential slot, destination schema, exposure/trusted-send profile, and one-to-sixteen approved destination digests. |
| `SecretRefV2` | `splendor.secret.ref.v2` | Binds one positive ref revision and provider/version/classification/policy metadata to one-to-sixteen unique v2 authorization coordinates. |

Both types have private fields, checked constructors, deterministic `Serialize`,
fixed code-only errors, and no generic `Deserialize`. Imported, persisted, or
otherwise untrusted bytes must use `from_json_slice`. One duplicate-aware
preflight validates JSON and enforces every resource bound before strict private
wire construction:

| Resource | Authorization v2 | Secret ref v2 / historical v1 |
| --- | ---: | ---: |
| Raw JSON bytes | 8,192 | 65,536 |
| Container depth, root at 1 | 8 | 12 |
| Decoder tokens | 128 | 2,048 |
| Object members | 32 | 384 |
| Array elements | 32 | 512 |
| Decoded UTF-8 bytes per name/string | 256 | 256 |

Unknown, missing, duplicate, null, wrong-kind, malformed, over-bound, and
noncanonical values fail in RFC 0014's fixed precedence. Errors retain no input,
candidate, parser location, or source chain. Decimal revisions must be positive
safe JSON integer tokens; signs, leading zeroes, fractions, exponents, strings,
and values above `9007199254740991` reject. The ref rejects duplicate
authorization binding keys even when their approved digest sets differ or only
overlap. Delivery methods form a unique semantic set and
`environment_variable` alone is invalid.

Validation rejects before normalization. Destination digests, trusted-send
controls, authorization entries, and delivery methods then use RFC 0014's exact
canonical set ordering. Compact serialization is the RFC 8785 JCS byte sequence.
The checked-in fixtures are:

- `crates/splendor-types/tests/fixtures/secrets/v2/authorization-v2-same-revision.json`
- `crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-same-revision.json`
- `crates/splendor-types/tests/fixtures/secrets/v2/authorization-v2-legal-maximum.json`
- `crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-legal-maximum.json`

The legal-maximum fixtures independently pin every semantic maximum. Their
canonical byte lengths and BLAKE3 hashes are 2,237 bytes /
`6576988eddba3e8368783447a58ae48739a5c67779019aac247a2cd03ef5f49d`
and 37,041 bytes /
`af2f77f6e7b0f87c2ba845a095b3ef391934409d21da485e041c18bfc8625f19`,
respectively.

`compare_secret_credential_authorization_v2` is a pure comparison against one
already-supplied validated `DriverOperationCredentialSinksV1`. It checks, in
order, operation, declaration revision, slot, destination schema, exposure,
trusted-send profile, containing-ref classification, and requirement intent. It
performs no lookup, lifecycle/current-head selection, purpose or Authority
evaluation, persistence, provider access, or I/O. `Matched` is not authority,
proof, evidence, a decision, permit, lease, or cache value; comparison results
and mismatch codes are intentionally non-serializable.

## Historical v1 read/deny views

`HistoricalSecretRefV1::from_json_slice` accepts only the frozen RFC 0014 v1
shape through the ref ingress budget and strict private-wire parser. It never
routes history into a live type. Historical entries are sorted by canonical JCS
bytes, assigned stable zero-based source ordinals, and expose the exact
domain-separated BLAKE3 entry and ref digests required for later proof-bound
migration. The fixture is
`crates/splendor-types/tests/fixtures/secrets/v2/historical-secret-ref-v1.json`.

Historical view types serialize deterministically but do not implement generic
`Deserialize`, live-type conversion, migration, lookup, Authority evaluation, or
current-head selection. `live_denial()` always returns the fieldless
`historical_revisionless_authorization_live_denied` result. No implementation
infers a current Driver declaration revision from v1 history.

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

```rust
use splendor_types::{HistoricalSecretRefV1, SecretRefV2};

let live_bytes = include_bytes!(
    "../../crates/splendor-types/tests/fixtures/secrets/v2/secret-ref-v2-same-revision.json"
);
let secret_ref = SecretRefV2::from_json_slice(live_bytes)?;
assert_eq!(secret_ref.secret_ref_revision(), 2);

let historical_bytes = include_bytes!(
    "../../crates/splendor-types/tests/fixtures/secrets/v2/historical-secret-ref-v1.json"
);
let historical = HistoricalSecretRefV1::from_json_slice(historical_bytes)?;
assert_eq!(
    historical.live_denial().to_string(),
    "historical_revisionless_authorization_live_denied"
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Lifecycle, trace, and replay

Creating or parsing a value, including a v2 ref or local lease request, does not
make it current or grant authority. Only `ProcessLocalSecretBroker` mutates the
bounded local lifecycle, and it accepts only startup-configured current v2 refs.
Historical v1 views always deny and never enter the broker.

The injected `SecretBrokerEventSink` receives structured ref-only evidence for
issuance, claim, denial, renewal, and revocation. It is an event seam, not a log.
This slice does not claim durable Event/Evidence integration: successful sink
append is required before issuance, claim, or renewal mutation, while revocation
first commits its absorbing local denial and records terminal evidence
afterward. Sink failure returns `secret_broker_evidence_unavailable`; for
revocation, the handle remains unusable and pending evidence can be retried.

`replay()` returns the broker's already-recorded safe local lease snapshots and
events in deterministic lease-ID and append order. Replay is inspect-only and
does not read the clock, allocate IDs, evaluate Authority, invoke a provider,
claim a use, renew/revoke a lease, or perform a side effect. This is not durable
cross-process reconstruction, and restart invalidates live handles and claims.

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
being reflected. Revision-bound ref and authorization parser failures expose
only RFC 0014's closed fixed codes. `Debug` for validated v2 and historical
records emits only a fixed type label; comparison `Display`/`Debug` emits only
`matched` or one fixed mismatch code. Rejected candidates and approved
destination coordinates are not retained in errors or source chains. No
serializable primitive contains a secret value/material/byte field, provider
request, raw provider error, credential value, token, password, or API key.

Broker failures are closed fixed codes. Wrong tenant, principal, workload,
operation, slot, destination, node, instance, audience, purpose, intent, ref, or
provider version never reaches a provider. Missing/expired/revoked/stale
Authority or revocation evidence denies. Exact expiry has no grace, clock
rollback denies without reactivation, non-microsecond or unavailable trusted
time fails closed, and a poisoned state lock cannot continue. Required denial
evidence failure remains a denial and returns evidence unavailability rather
than the underlying oracle-sensitive reason.

The provider material type is the only implemented primitive containing secret
bytes. It is deliberately non-serializable and lives only behind the outbound
provider port; the broker has no method that returns it. Public/debug/error/event
surfaces are covered by canary tests. The memory provider duplicates material
into one zeroizing return allocation only when its private provider request path
is invoked; this owner slice never invokes that path.

## Compatibility and versioning

The symbols are additive experimental 0.2/v2 Rust exports. The closed enum
spellings, opaque version-reference wire string, five-field policy object, and
nine-field `SecretUseRequirement` object are the bounded C03 contract for this
slice. Removing public generic `Deserialize` in favor of the sole bounded
`from_json_slice` ingress is the pre-release security correction for this new
experimental type; its canonical serialized bytes are unchanged. Existing 0.1
ID constructors, permissive parsing/deserialization behavior, serialized bytes,
and aliases remain unchanged. Existing C03 pre-placement and Driver Registry
credential-sink fixture bytes are also unchanged. RFC 0014's authorization/ref
v2 schemas are additive experimental successors; revision-less v1 remains
historical read/deny only and there is no dual live-reader fallback. Persisted
records and bytes remain unchanged.

The new lease/binding/snapshot/access-evidence records are explicitly local v1
profiles. They do not claim compatibility with RFC 0012's complete canonical
`SecretLeaseRequest`, `SecretLease`, `SecretDeliveryHandle`, or
`SecretAccessEvent` schemas, and no generic wire ingress or generated client is
published for them. The broker and memory provider are Rust-only process-local
surfaces. Durable persistence, complete Authority/Gateway consumption,
historical migration execution, provider control ledgers, node delivery,
daemon/API/SDK surfaces, and generated schemas remain downstream work requiring
their separately accepted owner contracts and production-path evidence.
