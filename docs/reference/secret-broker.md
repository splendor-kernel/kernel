# Secret Broker Reference

## Status

**status/incomplete — first process-local Secret Broker owner slice plus a
bounded generic pre-persistence barrier, with no material delivery or production
durability.**

The current implementation retains the behavior-free C03 identities,
pre-placement grammar, revision-bound `SecretRefV2`, and historical-v1 read/deny
views described below. It also provides additive `ProcessLocal*` lease, binding,
and access-evidence exports, an internal Authority-owned broker prototype, an
outbound Rust `ProcessLocalSecretProvider` port with request-bound session-local
results, an explicitly feature-gated test/local-development memory provider, and
an explicitly feature-gated Unix local-file provider for tests and local
development.
The broker lifecycle, constructors, authority context, handles, grants, claims,
clocks/ID sources, limits, mutation errors, inspection, and replay are all
crate-private. There is no callable production lease API or complete live secret
permit in this slice.

This is bounded progress for `SECR-001`, `SECR-003`, and `SECR-005`, plus a
denial/failure-only pre-persistence slice of `SECR-004`/`SECR-006`. It does not
implement RFC 0012's complete durable lease, exposure-lineage, delivery,
provider-control, node-control, outer-submission, or terminal publication
records. It adds no provider invocation from the broker, material-returning
broker API, Gateway session, resident delivery, persistence, daemon/API/SDK
secret surface, complete profile/repository/leak scanner, production provider,
issue closure, or gold pass. The reduced
wire-safe records use explicit `*.local.v1` schema names and do not masquerade as
the complete RFC 0012 wire schemas. `G07`, `G08`, and `G82` remain
`not_exercised`.

## Purpose and boundary

The behavior-free values reserve distinct identities and closed policy
vocabulary. The crate-private process-local prototype is the sole mutation owner
for the bounded lease lifecycle exercised by Authority unit tests. Possessing an identity, ref, request,
snapshot, access event, handle ID, or provider version does not authorize secret
use. Lease issuance, internal use reservation, renewal, and revocation require
current Authority evaluation over the exact tenant, principal, workload,
operation and current Driver declaration, destination and trusted-send profile,
placement, audience, ref revision/provider version, intent, and purpose binding.
The Authority context constructor is crate-private and there is no production
composition path in this slice; external callers cannot manufacture one from
arbitrary coordinates.

## Implemented generic credential ingress and persistence barrier

The existing stable generic action path now has an always-on, Gateway-owned,
pre-persistence barrier. `VerifiedActionGateway` applies it first, and the kernel
tick, daemon configured-run admission, direct action, physical action, policy
distribution, and trace-durability wrappers call the same pure implementation
before any earlier owner could persist or reflect an untrusted action.

The bounded guard recognizes RFC 0012's normalized authorization/password/token/
API-key/client-secret/private-key/cookie/secret/credential/connection/DSN and
structured cloud/device environment coordinates in nested action data and object
keys, URL userinfo/authority/path/query and quoted/spaced assignment forms, plus
structurally decoded Basic, short Bearer, PEM, provider-specific realistically
bounded punctuation-delimited tokens, credential URL/DSN, and embedded/encoded
generic ref-like content under neutral keys. Closed selector-plus-material
coordinate objects for credential aliases are normalized by the same owner grammar
without treating the generic `token` selector or non-ASCII schema labels as credentials.
Unicode alphanumeric characters continue words; all punctuation/separator
characters delimit credential syntax without a finite ASCII delimiter allowlist.
A valid bounded token/reference prefix is denied at punctuation even when that
punctuation also belongs to the surrounding credential alphabet.
URL/form handling covers standalone fields and encoded non-URL spans adjacent to
URLs, including decoded host content after structural numeric-port separation and
bare query-name content, with explicit nested/decode bounds and one decode per
layer. Authority validation accepts bounded reg-name/IPv4-style hosts, parsed
IPv6/zone or IPvFuture literals, and raw-colon `u16` ports; percent decoding never
creates a structural port separator. Malformed or ambiguously encoded authorities
fail closed while preserving
literal-percent forms, ordinary embedded URLs, and provider-like resource names.
It also screens free-form raw approval-evidence and receipt strings,
physical/operator envelope strings, complete device-profile values/keys, and
every top-level numeric `params.bytes` body,
independent of action labels or adapter routing. Every inspected raw or decoded
string rejects BOM and NUL/control ambiguity; numeric bytes additionally require
unambiguous UTF-8, so UTF-16 and invalid encodings fail closed. This screening
never validates receipt authority. It denies malformed parsed
coordinates and depth/node/string/cumulative-byte overflow with the sole fixed
reason `raw_credential_input_denied`. Its error type is fieldless,
non-serializable, and non-reflecting. Denied action traces use one constant
suppression projection; raw input never enters candidate/action traces, outcome
feedback, daemon request fingerprints, create-run idempotency receipts, physical
safety evidence, device profiles/status/audit, operator records, or
adapters/simulators. Complete-token grammar preserves ordinary Basic prose and
provider-looking resource paths.

The same scanner owner now exposes pure barriers for persisted percept, state,
and adapter-result envelopes:

- every collected percept shares one bounded scan across `schema`, `payload`,
  provenance source, and provenance detail before `PerceptsReceived`, policy
  invocation, or daemon queue retention;
- policy-selected next-state bytes, content type, and optional state label share
  one screen immediately after policy return and before `PolicyCompleted`,
  action processing, `OutcomeRecorded`, or a state write. Declared JSON must
  parse and declared text must be unambiguous UTF-8; malformed JSON, ambiguous
  textual encodings, detected content, and scanner overflow fail the tick with
  only `raw_credential_input_denied`;
- `AdapterResult.output` and satisfied-postcondition strings are screened
  immediately after one adapter return and before invariant/safety
  post-verifiers, `ActionOutcome`, action/outcome traces, daemon responses, or
  state. A detection returns stable `ActionStatus::Failed`, absent output, and
  a post-verification denial plus error containing only
  `raw_credential_output_suppressed`. This means the adapter was entered and
  does not claim rollback, no effect, or safe retry.

Persisted JSON scanning covers strings/object keys plus root numeric byte arrays
and selected `bytes`, `body`, and `contents` byte-envelope coordinates, including
current filesystem/HTTP result shapes. Bounded benign JSON, text,
filesystem/HTTP results, and genuinely opaque binary state remain compatible.
Explicit text/JSON ambiguity fails closed. Invalid non-text binary bytes may
remain opaque; the barrier does not claim visibility inside encrypted,
compressed, custom-encoded, or otherwise opaque state.

This barrier is intentionally not the complete RFC 0012
`CredentialIngressProfile`: it has no operation-specific owner-schema registry,
positive typed-wrapper recognition, non-secret exception registry, exhaustive
entropy/encoded/split or per-lease live detector, repository CI scanner,
quarantine/incident workflow, or live broker/provider/material path.
Generic `SecretRef`-looking data is denied rather than upgraded into authority.
Typed secret delivery remains unavailable.

## Implemented process-local owner slice

### Safe contracts

`splendor-types` exports four checked, serialize-only local contracts under
explicit process-local names:

| Type | Local schema | Role |
| --- | --- | --- |
| `ProcessLocalSecretLeaseUseBinding` | `splendor.secret.lease_use_binding.local.v1` | Exact tenant/principal/workload, Driver operation/declaration/slot/destination, exposure and trusted-send profile, node/instance/audience, ref revision/provider version, intent, and purpose binding. |
| `ProcessLocalSecretLeaseRequest` | `splendor.secret.lease_request.local.v1` | One idempotent request retaining the complete `SecretUseRequirement`, finite window, and request time. |
| `ProcessLocalSecretLeaseSnapshot` | `splendor.secret.lease_snapshot.local.v1` | Read-only safe lease state, counters, renewal lineage times, selected delivery method, and event/handle IDs. |
| `ProcessLocalSecretAccessEvidence` | `splendor.secret.access_evidence.local.v1` | Ref-only issuance, internal claim, denial, renewal, and revocation evidence. |

All fields are private and construction is checked. Access evidence admits only
the closed lease-request, use-attempt, renewal, or revocation event family that
matches its typed command ID; a cross-family pair fails with the fixed
`invalid_evidence_shape` code. These values implement `Serialize`, not generic
`Deserialize`, and contain no material, provider
locator/request/response, delivery endpoint, bearer capability, arbitrary JSON,
or raw error. They are non-authorizing process-local projections, not the full
RFC 0012 durable contracts. Their crate-root schema constants likewise use the
`PROCESS_LOCAL_SECRET_*` prefix; no reduced canonical-name alias is exported.

### Broker lifecycle

The internal broker prototype in `splendor-authority::secrets` is explicitly
process-local and non-restart-durable. It is configured for exactly one tenant;
nil tenant IDs, mixed-tenant refs, and cross-tenant bindings fail closed.
Production compilation fixes it to the local system UTC clock and random UUID
source. Custom synchronous clock/ID sources and narrowed limits are available
only to same-module tests. Immutable startup configuration supplies validated
`SecretRefV2` records and matching provider registrations. Duplicate
refs/providers, refs without a matching provider, invalid limits, and
over-capacity configuration fail construction.

The owner supports:

- `issue_lease`: validates the exact current ref/provider/Driver declaration,
  destination and trusted-send profile, delivery preference, finite policy
  bounds, trusted time, and cached Authority plus revocation state before one
  atomic lease/evidence/command commit;
- internal `claim_use`: atomically checks an opaque live handle, every immutable
  binding, exact start/expiry, current Authority and revocation state, and the
  finite use count, then retains only an opaque non-serializable claim carrying
  expiry and revocation generation; no public pre-Gateway claim API exists;
- `renew_lease`: accepts a request prepared at `starts_at <=` broker-observed
  trusted time, uses that observed time as the effective immediate cutover,
  preserves the original continuous-lifetime start and consumed-use count,
  narrows lineage limits, and invalidates the old handle only in the same atomic
  commit that installs the replacement and its evidence;
- `revoke_lease`: atomically commits local admission closure, revocation
  generation, terminal command result, and ref-only evidence without invoking a
  provider; and
- internal `inspect_lease` and bounded `replay_page`: inspect safe local
  snapshots/evidence without time reads, ID allocation, Authority evaluation,
  provider calls, or lifecycle mutation. No public visibility/replay surface is
  exposed before a trusted visibility policy exists.

Issue, internal claim, renewal, and revocation command keys are derived from the
crate-owned trusted context and scoped only by command kind, nominal command ID,
and trusted tenant/principal/workload. Lease-request reuse uses the same trusted
scope. Node, instance, audience, and every other placement/binding field remain
in semantic equality, so the same nominal ID under another valid placement
conflicts instead of selecting a new partition. Caller request bytes cannot
select a ledger partition. Current authenticated Authority/capability/revocation
evaluation occurs before SecretRef/current-Driver, command, or handle lookup.

The broker stores an explicit
`splendor.secret.semantic_idempotency_projection.v1` digest containing command
kind/ID, trusted ledger scope, and the complete lease request except
`requested_at`; renewal additionally binds the old opaque handle metadata. A
successful terminal record contains only a small integrity-bound pointer to
already committed historical non-authorizing evidence. The pointer binds the
expected command, event kind/outcome, and complete safe event integrity without
retaining a handle, snapshot, claim, or capability nonce. The first success
alone returns a newly minted live opaque capability. An exact currently-visible
retry, including one with only a different `requested_at`, returns the original
historical receipt or denial and creates no ID, evidence, lease/use counter, or
result timestamp. It still samples trusted time for current Authority
evaluation, and that valid observation obeys the monotonic high-water fence.
Changed reuse, hidden hit/miss, unauthorized scope, and conflict all return the
same `secret_not_available` outward code.

Default finite ceilings cover refs, providers, active and retained leases,
command records, local evidence, generated identities, and replay page size.
Explicit test limits may narrow those defaults. Exhaustion fails closed instead
of switching to an unbounded path. Transaction preparation currently clones the
whole local owner state so lifecycle/evidence/idempotency commit together; that
cost is deliberately bounded by these hard ceilings and covered by narrow-limit
tests. Elapsed active leases no longer consume the active-admission count,
although retained history and command identities are never evicted unsafely.

The crate-private live delivery handle and internal delivery claim have private
capability nonces, private construction, fixed redacted `Debug`, and no `Clone`
or `Serialize`. Generated identity reuse fails closed rather than replacing an
existing lease, handle, claim, or event.

### Provider boundary and test adapter

`splendor-authority::ProcessLocalSecretProvider` is an object-safe outbound Rust
port with `fetch`, `renew`, `revoke`, `audit`, and `health` methods.
Fetch/control request types have private construction. Provider errors are
closed fixed codes and discard vendor text. A successful fetch result is
borrowed from its exact request and validates matching request-digest audit
evidence. Its private material storage is bounded, non-empty,
non-cloneable/non-serializable, redacted,
`!Send`, `!Sync`, and backed by `zeroize::Zeroizing<Vec<u8>>`. The result exposes
only material length and safe audit evidence; no byte or `into_parts` escape is
available. Zeroization reduces exposure but is not a perfect-erasure claim.
Provider audit evidence, provider health evidence, and the memory provider use
fixed redacted `Debug` output with no tenant, ref, provider, version, digest, or
timestamp coordinates.
All reduced provider request/result/evidence/error symbols and schema constants
are exported under `ProcessLocal*` / `PROCESS_LOCAL_*` names.

The broker lifecycle in this slice only registers provider ports and never
invokes them. A future Gateway-owned live session must construct the private
request and retain its permit before provider access or delivery is possible.

`splendor-adapter-secrets-memory` is `publish = false` and compiles for consumers
only with the explicit `memory-secret-provider` feature (tests enable the source
through `cfg(test)`). Construction rejects resident, remote, fleet, production,
and unknown modes. Synthetic entries are finite and exactly keyed by provider,
tenant, ref ID/revision, and provider version; cross-tenant/wrong-version lookup,
outage, duplicate insertion, invalid material, and poisoned state fail with
fixed redacted errors. Rotation and provider-port revocation remove the old
entry so its zeroizing storage is dropped. The adapter opens no listener, reads
no environment fallback, and exposes no public independent resolve method.

`splendor-adapter-secrets-local-file` is also `publish = false`, has empty
default features, and compiles for consumers only with the explicit
`local-file-secret-provider` feature (its own unit tests use `cfg(test)`). Its
constructor accepts only explicit `Test` or `LocalDevelopment`, one canonical
absolute trusted root, and one finite exact provider/tenant/ref/revision/version
to relative-file map. Resident, remote, fleet, production, and unknown modes;
empty or over-capacity maps; duplicate coordinates; path aliases; absolute,
noncanonical, or traversing children; and implicit current/home/environment
configuration all fail closed. Root and relative paths are capped at 4,096 Unix
bytes, components at 255 bytes, root depth at 128 components, and relative depth
at 64 components.

The Unix implementation opens the trusted root one component at a time and
retains its descriptor. Every configured fetch is descriptor-relative with
`O_NOFOLLOW`, `O_CLOEXEC`, and nonblocking final-file open. The root and mapped
intermediate directories must belong to the effective user and expose no
group/other access. Final descriptors must be effective-user-owned regular
single-link files with no group/other access and a size from 1 through 65,536
bytes. Device, inode, size, mode, owner, link count, modification time, and
change time are pinned at construction and rechecked before and after a bounded
read. Missing, replaced, relinked, permission-changed, empty, oversized,
non-regular, symlinked, or poisoned state returns only fixed provider/config
codes. OS diagnostics, roots, relative paths, coordinates, and material are not
rendered by adapter `Debug` or errors. Transient failed-read buffers are
zeroized; this reduces exposure and is not a perfect-erasure claim.

Fetch is available only through the existing private-construction Authority
provider port and returns the existing request-borrowed result with only length
and audit access. Sanitized `audit` validates the exact registered descriptor
identity without reading bytes. `active_probe` reports a passive boolean for the
exact mapping; provider-side `renew` and `revoke` return
`unsupported_operation` and never modify or delete the file. A separate
default-off Authority test-support feature constructs legitimate requests only
inside Authority and returns safe length/audit/health observations, never a
request object or material bytes. The dependency guard pins that feature to
dev-only use, pins the adapter's empty default feature and narrow dependency
closure, and rejects every normal release-graph consumer. The normal daemon
dependency graph contains no development secret provider.

This development adapter is not daemon- or Gateway-composed and does not claim
the durable bootstrap-backing-source registry, route enrollment, provider
control ledger, production keychain/network provider, timeout, circuit breaker,
routing, failover, HA, issue completion, or Gold behavior required by full
`SECR-005`. `G07` and `G08` remain `not_exercised`.

The dependency guard recognizes `adapters/secrets-*` before the ordinary adapter
rule and permits only `splendor-authority` plus `splendor-types` as direct
internal dependencies. It rejects direct dependencies on Gateway, kernel, store,
daemon, node, or another adapter; the local-file provider additionally has a
closed `libc`/`zeroize` external production dependency set.

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

`environment_variable` is compatibility vocabulary only. The current v1 broker
prototype always filters it, even when both a ref and request list it. A later
safe requested method may be selected in caller order; an environment-only
intersection denies with the uniform restricted outward profile.

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

let id: SecretRefId = "11111111-1111-4111-8111-111111111111".parse()?;
assert_eq!(
    serde_json::to_string(&id)?,
    "\"11111111-1111-4111-8111-111111111111\""
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
    "11111111-1111-4111-8111-111111111111".parse::<SecretRefId>()?,
    "22222222-2222-4222-8222-222222222222".parse::<SecretCredentialSlotId>()?,
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
make it current or grant authority. Only the crate-private broker prototype
mutates the bounded local lifecycle, and it accepts only startup-configured
current v2 refs for its single tenant. Historical v1 views always deny and never
enter the broker.

The broker owns a bounded in-memory sequence of structured ref-only evidence for
issuance, internal claim, denial, renewal, and revocation. There is no external
evidence callback. Test-only injected clock and ID-source callbacks run without
either broker mutex; mutation admission is temporarily closed while they run,
reentrant mutation fails closed, and callback panic becomes a fixed broker
failure without poisoning lifecycle state. Every valid trusted-clock sample is
latched immediately into a one-way maximum-observed-time fence. Later ID,
evidence, or lifecycle preparation failure may leave the command/effect
unchanged, but cannot roll that security fence back. Lifecycle state, evidence,
generated-ID reservations, and terminal idempotency records are otherwise
prepared against a bounded cloned state and committed together. This is local
owner evidence, not durable Event/Evidence integration.

Internal `replay_page(cursor, limit)` returns at most the configured number of
already-recorded safe snapshots/events in deterministic lease-ID and append
order. Replay is inspect-only and does not read the clock, allocate IDs,
evaluate Authority, invoke a provider, claim a use, renew/revoke a lease, or
perform a side effect. It is deliberately non-public until a trusted visibility
policy exists. This is not durable cross-process reconstruction, and restart
invalidates live handles and internal claims.

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

Broker failures are internal closed fixed codes. Wrong tenant, principal,
workload, operation, slot, destination, node, instance, audience, purpose,
intent, ref, provider version, hidden command hit/miss, and semantic conflict
never reach a provider and share `secret_not_available` where disclosure would
create an oracle. Missing/expired/revoked/stale Authority or revocation evidence
denies before prior-result disclosure. Exact expiry has no grace, clock
rollback denies without reactivation, non-microsecond or unavailable trusted
time fails closed, and a poisoned state lock cannot continue. Evidence or
generated-ID exhaustion returns a fixed failure without partially committing
the command or lifecycle transition; an already-observed monotonic time
high-water remains latched. Recorded mismatch evidence uses the
caller-supplied binding without linking it to an existing lease or handle, which
avoids a target-existence oracle.

The private provider material storage is the only implemented value containing
secret bytes. It is deliberately request-borrowed, non-serializable, `!Send`, and
`!Sync`, and lives only inside a fetch result behind the outbound provider port;
the broker has no method that returns it and the result has no byte escape.
Public/debug/error/evidence surfaces are covered by canary tests. The memory
provider duplicates material into one zeroizing request-lifetime allocation only
when its private provider request path is invoked; this owner slice never invokes
that path.

Raw action credential guard failures expose only
`raw_credential_input_denied`; cap overflow, normalized coordinate, candidate
content, URL/DSN parser ambiguity, source path, and any candidate-derived digest
are deliberately indistinguishable. Direct and physical denials make zero
run-authority, provider, pre-effect, adapter, or simulator calls. Inspect-only
replay reads only the fixed sanitized denial and never reruns the guard as a
positive secret path or resolves material.

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

The ingress barrier changes acceptance of credential-bearing values within the
unchanged stable `Action` / `ActionRequest` wire shape; it adds no field, trace
variant, `ActionStatus`, daemon wire object, or generated SDK type. Existing
credential-free actions retain their prior path. The fixed safe projection is
used only for newly denied runtime traces; historical trace bytes are not
rewritten.

The `ProcessLocalSecretLease*` and `ProcessLocalSecretAccess*` exports are
explicitly local v1 profiles. They do not claim compatibility with RFC 0012's
complete canonical `SecretLeaseRequest`, `SecretLease`, `SecretDeliveryHandle`,
or `SecretAccessEvent` schemas, and no generic wire ingress or generated client
is published for them. Only the provider port and feature-gated memory provider
are Rust adapter surfaces; the lifecycle prototype is not exported from
`splendor-authority`. The memory provider additionally requires an explicit
non-default feature. Durable persistence, a callable lease lifecycle, public
visibility/replay, complete Authority/Gateway composition and provider
invocation, historical migration execution, provider control ledgers, node
delivery, daemon/API/SDK surfaces, and generated schemas remain downstream work
requiring their separately accepted owner contracts and production-path
evidence.
