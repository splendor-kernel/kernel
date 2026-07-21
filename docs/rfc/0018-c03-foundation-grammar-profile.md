# RFC 0018 - C03 Foundation Grammar Profile

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`427028b9fff0fe7d2337095bdb9093fd0966ea0cb4e1e68c8b1ae89a3cf5ae69`

**Compatibility line:** Additive experimental 0.2/v2 grammar profile preserving
the stable 0.1 contracts and the accepted RFC 0012 through RFC 0017 contracts

**Catalog task:** bounded C03 prerequisite slice of `FND-001` / [#220](https://github.com/splendor-kernel/kernel/issues/220)

**Owner package:** behavior-free grammar in `crates/splendor-types`; semantic
owners remain those assigned by RFC 0015, RFC 0016, and RFC 0017

**Gold target:** `G00`, which remains `specified_not_implemented` and
`not_exercised`

**Normative inputs:**
[RFC 0012](0012-secret-broker-contract.md),
[RFC 0013](0013-driver-operation-credential-sink-contract.md),
[RFC 0014](0014-revision-bound-secret-credential-authorization.md),
[RFC 0015](0015-event-state-evidence-ownership-and-durability-contract.md),
[RFC 0016](0016-driver-registry-admission-lifecycle-evidence.md),
[RFC 0017](0017-authority-historical-secret-ref-evidence.md), the stable
[0.1 primitive contract](../spec/0.1/primitives.md), and the active v2
[schema and identity map](../rules/v2/architecture/schema-identity-map.md)

This RFC is documentation only. It changes no Rust type, public schema,
generated artifact, Store format, owner package, daemon API, SDK, CLI, runtime
behavior, Event, State, Evidence, Registry, Authority, C03 record, task status,
gold status, conformance status, or release claim. Acceptance authorizes only the
dependency-safe implementation slices and exact stops below.

## Decision

Splendor will freeze one bounded C03 foundation grammar profile before any
behavior-free Slice 1 implementation from RFC 0015, RFC 0016, or RFC 0017.

The accepted and directly implementable part of this profile owns only:

- nominal non-interchangeable IDs;
- closed enum spellings and collision-safe reservations for later record
  schemas;
- common schema-coordinate and compatibility rules;
- canonical timestamp, integer, string, collection, JSON, and digest-wire rules,
  plus collision-safe owner-attestation enum/purpose reservations;
- finite untrusted-ingress and canonical-output ceilings;
- the primitive wire types from which later exact coordinates, references,
  requests, outcomes, and receipts may be built; and
- the Rust-source/generated-surface and cross-language fixture plan.

It owns no I/O, allocation, persistence, authority, currentness, trust decision,
durability decision, lifecycle transition, resource policy, redaction policy,
owner lookup, retry, recovery execution, replay execution, or side effect.

The profile is deliberately smaller than full `FND-001`. **Acceptance of this
RFC authorizes only Slice 1 common lexical, nominal ID, closed enum, digest-wire,
budget, non-authority, and compatibility primitives.** The record-family tables
below reserve semantic names and candidate schema strings for collision review;
they are not registered public schemas and do not authorize a Rust record,
parser, canonical bytes, digest projection, persisted value, or generated
surface. Each record family requires an accepted owner-specific grammar annex
that fixes every field name, nominal type, required/optional rule, nested
discriminant, collection rule, parser API, budget assignment, and digest field.

This RFC does not freeze the
broad v2 `Principal`, universal `Scope`, `ArtifactRef`, `WorkloadSpec`,
`ExecutionLease`, universal `DriverManifest`, universal `Invocation`, universal
`Proposal`, `ChangeSet`, or `DeploymentPlan`. It does not close #220. Those
families require their own accepted owner and compatibility contracts.

## Behavior-Free and Non-Authority Law

Every serializable value in this RFC is an untrusted behavior-free value.
Successful construction, parsing, validation, canonicalization, serialization,
hashing, equality, possession, lookup, or signature-shape validation grants no:

- caller identity, capability, work-order scope, approval, policy, data-use,
  secret, quota, lease, safety, Gateway, driver, adapter, or side-effect
  authority;
- Event writer authority, State writer binding, live State head, Registry
  admission, Registry activation, Registry currentness, Authority allow, C03
  migration decision, or ref-head mutation;
- trusted owner issuance, current key status, historical truth, evidence
  completeness, claim correctness, durability, or publication success; or
- permission to dereference a payload, owner record, artifact, lineage record,
  evidence item, Registry coordinate, or Authority coordinate.

A value named `receipt`, `coordinate`, `evidence`, `complete`, `demonstrated`,
`active`, `current`, `durable`, `signed`, or `attested` remains a caller-supplied
assertion until its semantic owner independently validates the exact source,
owner, trust/key-status, audience, canonical bytes, digest, current state, and
applicable owner contract. `splendor-types` defines no conversion from a wire
value to a permit, trusted receipt, current handle, durability proof, historical
proof, or live head.

When an owner later validates such a value, the result is an owner-specific
sealed, non-serializable handle in the owner package. That handle cannot be
constructed, deserialized, cloned from wire bytes, exported by generated SDKs,
or recreated from a receipt/digest after restart without re-entering the exact
owner validation path. The behavior-free record remains distinct from the
trusted handle.

## Exact Bounded Scope and Dependency Map

| Source | This RFC freezes | This RFC does not complete |
| --- | --- | --- |
| `FND-001` / #220 | The C03-required nominal, closed, canonical, bounded behavior-free profile below | Broad v2 object grammar, runtime integration, generated parity, `G00`, or task completion |
| RFC 0015 Slice 1 prerequisite | IDs, enums, canonical primitives, digest-wire framing, record-name reservations, and 0.1 compatibility rules | Exact record fields/bytes/projections, `splendor-evidence`, owner decisions, Store behavior, durability, current heads, replay execution, or runtime wiring |
| RFC 0016 Slices 1-2 prerequisite | Registry IDs, lifecycle spellings, exact RFC 0013 declaration-digest framing, record-name reservations, and source/finalization acyclicity | Exact record fields/bytes/projections, projection fingerprint construction, external owner facts, Registry behavior, activation, persistence, current query, or C03 use |
| RFC 0017 Slices 1-2 prerequisite | Authority historical IDs, origin spellings, exact RFC 0014 reuse, record-name reservations, source/finalization acyclicity, and an attestation-profile reservation | Exact record fields/bytes/projections, attestation construction/verification, Authority eligibility, policy/data-use meaning, trust/key registry, resource accounting, `FND-009`, persistence, publication, view release, or migration |

The following remain separate hard stops:

| Dependency | Retained ownership and stop |
| --- | --- |
| `FND-003` / #222 | Transaction ordering, independent-owner reservation, outbox/inbox recovery, crash winners, and cross-owner linearization. Grammar cannot make two commits atomic. |
| `FND-006` / #225 | Compatibility class, N-1/N/N+1 behavior, persisted migration, downgrade/rollback, generator rollout, and mixed-version qualification. Unknown future values remain non-live. |
| `FND-009` / #228 | Policy-independent classification, deterministic redaction, read authorization, and privileged export. This RFC defines no redaction or read decision. |
| `EVT-002` / #272 | Transferable Event writer epochs, handoff, live cutover, and rollback. This profile permits only RFC 0015's fixed local writer values. |
| Artifact, Lineage, conformance, trust, resource, audit, policy, data-use, deployment, and Authority owners | Their facts remain externally owned. A Registry or Authority source schema that needs an unresolved owner fact cannot be implemented or persisted by inventing a generic substitute. |

## Compatibility and Existing-Type Reuse

This RFC never changes an existing public type or its standalone serde behavior.

| Existing value | Required treatment |
| --- | --- |
| `TenantId`, `PrincipalId`, `AgentId`, `RunId`, `WorkloadId`, `NodeId`, `InstanceId`, `ArtifactId`, `StatePartitionId`, and other accepted IDs | Reuse the existing nominal Rust type. New bounded parent parsers require exact lowercase hyphenated non-nil UUID text before retaining it, and every checked constructor revalidates non-nil typed values. Existing standalone permissive behavior is not silently hardened in place. |
| `TraceEventId` | The RFC 0015 0.1 compatibility profile uses exactly this ID and `TraceEventId::from_run_sequence`. It mints no native `EventId`. |
| stable `TraceEvent` | Preserve exact ID, sequence, timestamp, identity, kind, payload, event hash, export bytes, and tick ordering. Envelope-only fields never enter stable bytes. |
| `StateNodeId` and stable `StateNode` | Preserve the existing content identity and stable lineage projection. No `StateCommitId` is introduced. |
| RFC 0013 values | Reuse `DriverOperationRef`, `SecretCredentialSlotId`, `DriverOperationCredentialSinksV1`, sink entries, trusted-send profiles, destination digests, validators, and exact canonical declaration bytes without wrappers or alternate serializers. |
| RFC 0014 values | Reuse historical/ref-v2 values, canonical bytes, source-entry composite identity, ordinals, proof-bundle array rules, exact eighteen-member objects, and all accepted digest domains unchanged. |
| `ContentHash` | Remains the stable 0.1 value. It is not the privileged digest ABI for this profile because its public algorithm/value fields are too broad. |
| `schema_extensions` | Remains valid only for existing schemas that explicitly permit non-authorizing metadata. Every new privileged record in this RFC forbids `extensions`. |

For stable Trace compatibility, `occurred_at` is the exact existing
`TraceEvent.timestamp` value and stable serializer output. It is not rewritten
through the new timestamp profile. Owner-only `recorded_at` and every native
owner timestamp use the new profile.

## Common Closed-Wire Rules

### Object closure and version handling

Every **new top-level record introduced by a later accepted RFC 0018 grammar
annex** is a non-empty closed JSON object with one required `schema_version`
whose value is exactly its registered constant. This rule does not add a member
to an inherited stable 0.1, RFC 0013, or RFC 0014 object, or to an accepted
nested value whose own contract fixes another exact shape. In particular, RFC
0013 sink/trusted-send objects and RFC 0014's exact eighteen-member proof-bundle
objects remain unchanged.

Before semantic lookup or construction, bounded ingress for a newly registered
record rejects:

- missing, duplicate, unknown, alias, side, `extensions`, or defaulted members;
- null where any member is expected;
- a wrong or unknown version, profile, enum, owner, algorithm, purpose, or
  audience;
- scalar/object/array coercion, stringified JSON, case folding, whitespace
  trimming, Unicode normalization, or numeric conversion; and
- over-bound raw, decoded, nested, token, member, element, string, or canonical
  output content.

Unknown future schema bytes may be retained only by a separately accepted
`FND-006` bounded opaque historical container. Such bytes are non-live and
cannot be parsed as this version, negotiated downward, defaulted, used for owner
lookup, or converted into current authority or proof.

Final validated privileged records implement deterministic `Serialize` but not
generic `Deserialize`. Untrusted API, import, persisted, replay, and migration
bytes enter only through the record family's duplicate-aware bounded
`from_json_slice` parser and private wire visitors. Checked constructors apply
the same semantic validation to already typed values, including canonical
non-nil checks for reused existing IDs. No daemon, Store adapter, SDK, test,
serde helper, or compatibility path may bypass that ingress.

### `CanonicalSchemaIdV1`

Schema constants in this RFC are ASCII strings of `1..=128` bytes matching:

```text
^[a-z][a-z0-9._-]*\.v[1-9][0-9]*$
```

Only exact constants registered by this RFC or a later accepted annex are
accepted at privileged boundaries. Candidate strings in the reserved registry
below are not registered by appearance alone. The lexical type does not make an
unregistered schema usable.

### `CanonicalLabelV1` and `FoundationGrammarCodeV1`

Security-sensitive names, kinds, purposes, audiences, relation kinds, and code
values are `1..=128` ASCII bytes matching:

```text
^[a-z][a-z0-9._-]*$
```

Free-form reason text, provider errors, locators, paths, URLs, shell fragments,
tokens, secrets, credentials, private chain-of-thought, and arbitrary metadata
are not labels and are forbidden in this profile.

`FoundationGrammarCodeV1` is local to this bounded grammar and is not an alias or
replacement for the existing FND-004 `ReasonCode`, whose accepted lexical rules
remain unchanged. No conversion between them is provided.

### `CanonicalTimestampV1`

The exact wire form is 27 ASCII bytes:

```text
YYYY-MM-DDTHH:MM:SS.ffffffZ
```

Rules:

- year is `0001..=9999` and the complete date/time is calendar-valid;
- UTC `Z` is mandatory; offsets and lower-case `z` reject;
- exactly six fractional digits are mandatory; values are neither rounded nor
  padded from a different precision;
- seconds are `00..=59`; leap seconds reject; and
- leading/trailing whitespace and alternate RFC3339 spellings reject.

Lexicographic order of valid values is chronological. A timestamp is evidence
of the named owner's observation only; it proves neither causality nor
currentness.

### Canonical integers

Every newly introduced zero-inclusive integer is an original JSON token matching
exactly `0|[1-9][0-9]*`. `CanonicalPositiveRevisionV1` instead matches exactly
`[1-9][0-9]*`. Validation occurs on the original token before conversion to a
language integer or floating-point value. Every minus-prefixed token, including
`-0`, plus sign, fraction, exponent, and leading zero other than the single token
`0` rejects.

| Profile | Range |
| --- | ---: |
| `CanonicalCountV1` | `0..=9007199254740991` |
| `CanonicalPositiveRevisionV1` | `1..=9007199254740991` |
| `CanonicalOrdinalV1` | `0..=9007199254740991` |
| `CanonicalSequenceV1` | `0..=9007199254740991` |

Owner increments use checked arithmetic. Overflow, wraparound, or an attempt to
serialize a larger value denies before mutation. Stable 0.1 integer behavior is
not changed; compatibility projections preserve existing bytes.

### Canonical JSON

Validation and duplicate rejection occur before normalization. Complete
validated records serialize as RFC 8785 JSON Canonicalization Scheme bytes.
Ordinary compact Rust `Serialize` output is the canonical-byte API and must equal
the pinned JCS bytes; fields are emitted in JCS member-name order. There is no
second serializer whose output may diverge.

Canonical bytes contain UTF-8 JSON only, with no BOM, insignificant whitespace,
trailing newline, float, non-finite number, or implementation-specific escaping.
Strings compare by exact UTF-8 bytes. No Unicode normalization or case folding is
performed. Fields that do not explicitly allow Unicode use the ASCII profiles
above.

## Nominal Identity Registry

### New-ID wire and API contract

Every new ID below is a distinct Rust newtype over one non-nil UUID. Wire text is
exactly 36 lowercase ASCII bytes in canonical hyphenated form. Uppercase,
compact, braced, URN, padded, nil, numeric, null, byte-array, map, and sequence
forms reject.

New ID types provide strict `parse`/`FromStr`, checked `TryFrom<Uuid>`, exact
`Serialize`, ordering by UUID network bytes where ordering is required, and
fixed non-reflecting parse errors. They provide no `Default`, random `new`,
unchecked `From<Uuid>`, string alias, cross-type conversion, or generic ID
wrapper. Allocation belongs to the semantic owner and deterministic fixture
factory, not `splendor-types`.

Coincident UUID bytes across distinct types confer no equality or relationship.
They may not be coerced or substituted. Where RFC 0015-0017 requires distinct
records, owner validation additionally rejects coincident allocated identities
for those records.

### Event, State, Evidence, and Replay IDs

```text
EventId
EventPartitionId
EventAppendCommandId
EventAppendIdempotencyKey
EventAppendReceiptId
EventAppendBatchCommandId
EventAppendBatchAcknowledgementId
FixedLocalEventWriterRecordId
OwnerOutboxEntryId
EventPublicationCommandId
EventInboxRecordId
EventPublicationAcknowledgementId
EventAppendRecoveryId

StateWriterActivationCommandId
StateWriterActivationIdempotencyKey
StateWriterActivationReceiptId
StateWriterBindingId
StateMutationCommandId
StateMutationIdempotencyKey
StateCommitReceiptId
StateCommitRecoveryId

EvidenceRequirementId
EvidenceItemId
EvidenceBundleId
EvidenceClaimId
EvidenceCommitCommandId
EvidenceCommitIdempotencyKey
EvidenceCommitReceiptId
EvidenceViewId
EvidenceCommitRecoveryId
ReplayPlanId
SimulationPlanId
```

`EventId` is used only by native owner-record profiles. The 0.1 compatibility
profile uses `TraceEventId` directly. A State commit continues to use
`StateNodeId`. RFC 0014 `source_entry_identity` remains exactly the composite
`(SecretRefId, positive source secret_ref_revision, source_entry_ordinal)` and
is never replaced by a UUID.

### Driver Registry IDs

```text
DriverDefinitionId
DriverVersionId
RegistryInstallationId
RegistryDeclarationBindingId
RegistryDeclarationRevisionFenceId
RegistryAdmissionCommandId
RegistryAdmissionId
RegistryActivationCommandId
RegistryActivationId
RegistryLifecycleTransitionCommandId
RegistryLifecycleTransitionId
RegistryLifecycleHeadId
RegistryAdmissionEvidenceCommandId
RegistryAdmissionEvidenceId
RegistryCurrentObservationQueryId
RegistryCurrentObservationId
RegistryPublicationFinalizationCommandId
RegistryPublicationFinalizationId
RegistryOutboxIntentId
RegistryImportCommandId
RegistryRecoveryCommandId
```

Definition, version, installation, binding, fence, admission, activation,
transition, head, per-slot evidence, current observation, finalization, outbox,
import, and recovery identities never alias one another, an endpoint identity,
an RFC 0013 operation/slot, an Event/Evidence identity, or a C03 identity.

Registry command/query identities are their sole permanent idempotency identity,
as required by RFC 0016. No second optional idempotency key is introduced.

### Authority historical-evidence IDs

```text
AuthorityHistoricalEvidenceId
AuthorityHistoricalProofSetClaimId
AuthorityHistoricalNativeEvidenceCommandId
AuthorityHistoricalImportCommandId
AuthorityHistoricalPublicationFinalizationCommandId
AuthorityHistoricalPublicationFinalizationId
AuthorityHistoricalOutboxIntentId
AuthorityHistoricalRecoveryCommandId
OwnerAttestationId
AttestationKeyId
```

Authority command identities are family-specific permanent identities. An
evidence ID, source-entry identity, ref ID, work-order ID, digest, trace ID, or
ordinal cannot substitute for one.

## Closed Enum Registry

No enum below has an unknown/other string or integer form. A future value needs a
new schema version and `FND-006` compatibility decision.

| Enum | Exact values |
| --- | --- |
| `EventProfileV1` | `trace_event_compatibility_v0_1`, `owner_record_v1` |
| `EventDurabilityClassV1` | `required_before_effect`, `required_after_effect`, `best_effort_telemetry`, `derived_export_only` |
| `DurabilityLevelV1` | `memory_only`, `transaction_committed`, `storage_barrier_confirmed` |
| `FixedLocalEventWriterStatusV1` | `active`, `quarantined`, `closed` |
| `EffectCertaintyV1` | `no_effect`, `effect_succeeded`, `effect_failed`, `effect_partial`, `effect_uncertain` |
| `SubEffectCertaintyV1` | `succeeded`, `failed`, `uncertain` |
| `StateWriterPolicyV1` | `single_fenced_writer` |
| `StateMergePolicyV1` | `forbidden`, `fast_forward_only` |
| `StateWriterActivationKindV1` | `initial_local`, `renew_same_writer`, `handoff` |
| `EvidenceCompletenessV1` | `complete`, `incomplete`, `inaccessible`, `corrupt`, `unavailable` |
| `EvidenceSupportLevelV1` | `demonstrated`, `bounded`, `inconclusive`, `contradicted`, `unavailable` |
| `RegistryLifecycleStateV1` | `admitted`, `active`, `stale`, `revoked`, `quarantined` |
| `RegistryRevisionFenceStateV1` | `not_revoked`, `revoked` |
| `OwnerPublicationRecoveryStateV1` | `claimed`, `source_committed`, `awaiting_publication`, `finalized`, `outcome_uncertain` |
| `AuthorityHistoricalOriginKindV1` | `native_issuance`, `native_ref_mutation`, `attested_import` |
| `VisibilityClassV1` | `public`, `tenant`, `restricted`, `secret`, `protected_eval`, `safety_local`, `legal_hold` |
| `OwnerAttestationAlgorithmV1` | `ed25519` |
| `OwnerAttestationAudienceV1` | `c03_migration` |
| `OwnerAttestationPurposeV1` | `event_append_receipt`, `state_commit_receipt`, `evidence_commit_receipt`, `registry_admission_source`, `registry_activation_source`, `registry_lifecycle_transition_source`, `registry_c03_slot_evidence_source`, `registry_current_observation_source`, `registry_publication_finalization`, `authority_historical_source`, `authority_publication_finalization` |
| `OwnerAttestationSubjectOwnerV1` | `splendor.event-log`, `splendor.state-service`, `splendor.evidence-service`, `splendor.driver-registry`, `splendor.authority-service` |

`VisibilityClassV1` is representation only. `FND-009` owns classification,
redaction, read, and export behavior. `OwnerAttestation*` values are signature
grammar only. Trust and key-status owners decide whether any attestation is
acceptable.

## Reserved Schema and Record-Family Registry

The names and candidate schema strings below are reserved to prevent independent
implementations from choosing colliding spellings. **They are not registered
public schemas and are not implementable from this RFC alone.** The listed
member families are mandatory design inputs, not exact wire fields. An accepted
owner-specific annex must replace each family list with a complete field table:
exact JSON member name, Rust nominal type, required/optional/conditional rule,
nested discriminant and schema, collection and uniqueness rules, checked
constructor validation, bounded parser API, assigned budget, every digest field,
and exact digest projection. Until then, no bytes, parser, constructor, persisted
record, generated binding, or public constant may use the candidate schema.

A family that names an unresolved external-owner fact remains blocked rather
than using an arbitrary map, generic string reference, permissive fake, or test
DTO that can escape into production.

### Event records

| Semantic family | Reserved candidate `schema_version` | Required annex inputs |
| --- | --- | --- |
| `EventPartitionV1` | `splendor.event.partition.v1` | partition ID, profile, exact tenant/run/owner scope, descriptor revision/digest |
| `EventAppendIntentV1` | `splendor.event.append_intent.v1` | profile, producer, scope, partition, occurred time, kind schema/kind, exactly one typed inline payload or accepted immutable payload reference, causal parents, correlation refs, profile-permitted producer event ID/sequence, durability floor, command/audit correlation, idempotency key |
| `EventEnvelopeV1` | `splendor.event.envelope.v1` | profile, profile-conditioned event ID, partition, sequence, fixed writer epoch/fence, producer/scope, occurred/recorded times, kind schema/kind, payload, causal/correlation refs, visibility, durability class, integrity, intent digest |
| `FixedLocalEventWriterRecordV1` | `splendor.event.fixed_local_writer_record.v1` | record ID/revision/digest, owner/producer/scope/audience, partition/process/Store identity, positive epoch, fence digest, created/expiry time, status, prior/current cursor and integrity, deployment-policy revision |
| `EventAppendRequestV1` | `splendor.event.append_request.v1` | command ID, complete intent/digest, expected next sequence, previous digest or genesis, fixed writer record/revision/epoch/fence, idempotency key/digest, request digest, durability floor, bounded command/causal/audit refs |
| `EventAppendReceiptV1` | `splendor.event.append_receipt.v1` | receipt ID, intent/request/idempotency digests, event coordinate, writer epoch/fence, prior/current integrity, all durability floors/achieved level/backend policy, owner identity/revision/commit time, visibility |
| `EventAppendBatchIntentV1` | `splendor.event.append_batch_intent.v1` | batch command ID, one same-partition/same-producer/same-writer/same-durability ordered append-intent array, one expected sequence/previous digest, batch digest |
| `EventAppendBatchAcknowledgementV1` | `splendor.event.append_batch_acknowledgement.v1` | acknowledgement ID, batch command/request digest, ordered intent digests, sequence range, prior/final integrity, exact ordered per-item receipts, owner/durability/integrity |
| `OwnerOutboxEntryV1` | `splendor.event.owner_outbox_entry.v1` | outbox ID, source owner/transaction/revision/digest/scope, immutable publication command/digest/key, destination owner/audience, trust/key-status coordinate, bounded attempt state and `pending|acknowledged|quarantined` status |
| `EventPublicationCommandV1` | `splendor.event.publication_command.v1` | command ID, authenticated source owner/producer/scope/transaction, one append or constrained batch, complete intent/request/source digests, destination/audience, expiry, trust/key-status coordinate |
| `EventInboxRecordV1` | `splendor.event.inbox_record.v1` | inbox ID, destination owner, command identity/digest, transport/source binding, first-seen time, append result, original receipt refs |
| `EventPublicationAcknowledgementV1` | `splendor.event.publication_acknowledgement.v1` | acknowledgement ID, command/inbox transaction binding, exact append receipts or terminal result, owner/tenant/audience/trust/key status/expiry, acknowledgement digest/attestation |
| `EventCoordinateV1` | `splendor.event.coordinate.v1` | profile, profile-conditioned event ID, partition, sequence, writer epoch, event schema, canonical event digest, append receipt ID/digest |

The committed envelope's `event_id` field is `TraceEventId` only for
`trace_event_compatibility_v0_1` and `EventId` only for `owner_record_v1`.
Parent parsing resolves the nominal type from the closed profile and forbids
cross-profile conversion. Every `EventCoordinateV1` repeats that exact profile;
the profile is included in the coordinate digest and selects the nominal event
ID type. A bare UUID plus event schema cannot recover or substitute the type.

### State records

| Semantic family | Reserved candidate `schema_version` | Required annex inputs |
| --- | --- | --- |
| `StatePartitionV1` | `splendor.state.partition.v1` | existing partition ID, owner component/principal, tenant and optional typed scope, state schema/classification, writer/reader/retention/merge policy, profile, descriptor revision/digest |
| `StateHeadV1` | `splendor.state.head.v1` | partition, positive head revision, optional current `StateNodeId`/state hash for genesis, current writer epoch, last Event coordinate |
| `WriterEligibilityFactsV1` | `splendor.state.writer_eligibility_facts.v1` | external owner coordinate, authority/lease generation/status, principal/instance/scope/partition, expected head, transition-schema ceiling, validity, audience, revocation source, policy revision, digest |
| `StateWriterActivationCommandV1` | `splendor.state.writer_activation_command.v1` | command/idempotency IDs and digests, partition descriptor/head/writer expectations, requested writer/schema ceiling, complete eligibility/current status, activation kind and handoff facts when applicable, expiry/audience/causal/audit refs, durability floor |
| `StateWriterActivationReceiptV1` | `splendor.state.writer_activation_receipt.v1` | receipt and command/idempotency digests, eligibility owner/record/generation, partition/head, prior/new writer records/status, new epoch/fence, principal/instance/schema ceiling/expiry, Event receipt, all durability facts, owner revision/time |
| `StateWriterBindingV1` | `splendor.state.writer_binding.v1` | binding ID, partition, writer record revision, writer principal/instance, positive epoch/fence, transition-schema ceiling, validity, owner revision/digest |
| `StateMutationRequestV1` | `splendor.state.mutation_request.v1` | command/idempotency IDs and digest, partition descriptor, exact expected head, exact writer binding/revision/epoch/fence, expected external status generation, closed transition schema, typed payload or accepted immutable ref, ordered parents, next hash, commit metadata, causal Event/Evidence inputs, durability/audit |
| `StateCommitReceiptV1` | `splendor.state.commit_receipt.v1` | receipt and request digest, partition/descriptor, previous/new heads, `StateNodeId`/hash/snapshot presence, writer/status generation/fence, exact required Event receipt, all durability facts, owner revision/time |
| `StateCommitCoordinateV1` | `splendor.state.commit_coordinate.v1` | partition/descriptor/head revision, node/hash, writer epoch/fence, required Event coordinate, commit receipt ID/digest |

`handoff` is an interface value, not an implemented path. It rejects before
mutation until the accepted external eligibility and `FND-003` linearization
contracts exist.

### Evidence and replay records

| Semantic family | Reserved candidate `schema_version` | Required annex inputs |
| --- | --- | --- |
| `EvidenceRequirementV1` | `splendor.evidence.requirement.v1` | requirement ID, purpose/claim schema, subject type, mandatory/optional typed item requirements/cardinality/freshness, classification ceiling, accepted owner/schema versions, integrity requirements, policy revision/digest |
| `EvidenceItemV1` | `splendor.evidence.item.v1` | item ID, closed item variant, owning component, exact owner schema/identity/coordinate/digest, tenant/scope, visibility, availability; no copied protected payload |
| `EvidenceClaimV1` | `splendor.evidence.claim.v1` | claim ID/schema/subject/evaluator/method/policy, supporting/contradicting item IDs, support level |
| `EvidenceBundleV1` | `splendor.evidence.bundle.v1` | bundle ID, owner revision, requirement/subject, canonical item results, issuer/evaluator, creation time, completeness, canonical claims, visibility/redaction-policy reference, optional profile-required attestation coordinate, bundle digest |
| `EvidenceCommitRequestV1` | `splendor.evidence.commit_request.v1` | command/idempotency IDs and digest, authenticated source owner/scope/audience, subject/requirement, caller-significant ordered item owner/receipt/attestation coordinates, proposed claims/evaluator, durability/audit |
| `EvidenceCommitReceiptV1` | `splendor.evidence.commit_receipt.v1` | receipt/bundle/command/idempotency identities/digests, Evidence owner/trust/key/attestation, scope/audience/subject/requirement/evaluator/visibility, complete ordered item/source/receipt/result and claim/support binding, completeness, bundle/integrity/owner revision/time, all durability facts |
| `EvidenceBundleCoordinateV1` | `splendor.evidence.bundle_coordinate.v1` | bundle/requirement/subject/completeness/digest, owner revision, mandatory commit receipt ID/digest, achieved durability, required attestation coordinate |
| `EvidenceViewV1` | `splendor.evidence.view.v1` | view ID, source coordinate, viewer scope, redaction policy/version, included coordinates, explicit omitted/inaccessible statuses, view digest |
| `ReplayPlanV1` | `splendor.replay.plan.v1` | plan ID, inspect/read-only mode, access-filtered immutable inputs, detached output contract, explicit no-live-owner/no-live-driver/no-live-head constraints |
| `SimulationPlanV1` | `splendor.simulation.plan.v1` | plan ID, detached input/state coordinates, explicit non-live implementations, bounded output contract, explicit no-live authority/effect/head constraints |

Evidence item variants are closed to RFC 0015's Event coordinate/range, State
coordinate, Artifact reference, Lineage reference, Authority/approval/gate/
Registry decision reference, environment/runtime fact, metric/evaluation, and
incident/intervention families. A variant whose external owner grammar is not
accepted remains unconstructible for persisted or privileged use.

### Driver Registry records

| Semantic family | Reserved candidate `schema_version` | Required Registry annex inputs |
| --- | --- | --- |
| `DriverRegistryInstallationScopeV1` | `splendor.driver.registry.installation_scope.v1` | installation ID, tenant, immutable deployment/locality/trust coordinate and scope digest |
| `DriverDeclarationBindingV1` | `splendor.driver.registry.declaration_binding.v1` | binding ID, exact RFC 0013 operation/revision, complete declaration bytes/digest, every sink byte/fingerprint, complete projection-contract fingerprint, publisher and publication-authority coordinates, owner revision/time/integrity |
| `DriverDeclarationRevisionFenceV1` | `splendor.driver.registry.declaration_revision_fence.v1` | fence ID, exact binding key, state, revision/integrity, dedicated revocation source when revoked |
| `DriverRegistryAdmissionCommandV1` | `splendor.driver.registry.admission_command.v1` | command ID, trusted actor/publisher/registrar/work-order/scope, definition/version/installation, exact declaration/binding/fence, complete external proof coordinates, compatibility/resource/durability/causal/audit inputs, semantic digest |
| `DriverRegistryAdmissionSourceV1` | `splendor.driver.registry.admission_source.v1` | admission ID, complete normalized command semantics, owner revision/time/integrity, source digest, initial `admitted` generation, resource disposition, outbox intent; no downstream acknowledgement/finalization |
| `DriverRegistryActivationCommandV1` | `splendor.driver.registry.activation_command.v1` | command ID, target admission/expected head/binding/fence, current publisher facts, narrowed activation and deployment/gate/rollout proof coordinates, current external proof/resource/durability inputs, semantic digest |
| `DriverRegistryActivationSourceV1` | `splendor.driver.registry.activation_source.v1` | activation ID, prior/new state/generation, admission/target/deployment proof binding, authority/resource facts, owner revision/time/integrity, outbox intent; no downstream acknowledgement/finalization |
| `DriverRegistryLifecycleHeadV1` | `splendor.driver.registry.lifecycle_head.v1` | head ID, admission ID/digest, current lifecycle state/generation, source record revision/digest, integrity |
| `DriverRegistryLifecycleTransitionCommandV1` | `splendor.driver.registry.lifecycle_transition_command.v1` | command ID, actor/work-order/target-state authority, admission, exact expected head/state/generation, target state, revocation-fence coordinate when applicable, cause/resource/durability/causal/audit inputs, semantic digest |
| `DriverRegistryLifecycleTransitionSourceV1` | `splendor.driver.registry.lifecycle_transition_source.v1` | transition ID, prior/new state/generation/head, admission/cause/authority/resource binding, owner revision/time/integrity, outbox intent; no downstream acknowledgement/finalization |
| `RegistryAdmissionEvidenceV1` | `splendor.driver.registry.c03_slot_evidence.v1` | evidence ID, exact tenant/installation/admission/binding/fence/publisher coordinate, operation/revision/declaration, one exact slot/sink/fingerprint, historical `active` generation/activation/deployment facts, exact external proof/resource coordinates, owner revision/time/integrity/outbox; no C03 ref/decision or downstream acknowledgement/finalization |
| `DriverRegistryCurrentObservationQueryV1` | `splendor.driver.registry.current_observation_query.v1` | query ID and complete expected Registry coordinate from RFC 0016, caller/scope/audience, resource/publication inputs, semantic digest |
| `DriverRegistryCurrentObservationSourceV1` | `splendor.driver.registry.current_observation_source.v1` | observation ID, complete exact current coordinate/fence/publisher/head/generation and external-current facts, owner verification time/revision/integrity, resource disposition/outbox; no downstream acknowledgement/finalization |
| `DriverRegistryPublicationFinalizationV1` | `splendor.driver.registry.publication_finalization.v1` | finalization ID/command, exact fixed source identity/digest/family/outbox, exact Event/Evidence coordinates/receipts, durability/completeness/trust/key status, resource disposition, release state, owner revision/time/integrity |
| `DriverRegistryOutboxIntentV1` | `splendor.driver.registry.outbox_intent.v1` | outbox ID, source family/identity/digest, exact destination profiles/audience, command identities, durability, owner transaction/revision |
| `DriverRegistryRecoveryV1` | `splendor.driver.registry.recovery.v1` | recovery command, exact retained command/source/outbox/finalization coordinates, recovery state, owner revision/integrity; no alternate identities or semantics |

External Artifact, Lineage, conformance, Authority, trust/key, resource, audit,
and deployment facts in these records must use their separately accepted exact
nominal types and schemas. The Registry implementation stops at a typed port
until each exists. This RFC does not authorize a generic `OwnerFactRef`, string
coordinate, arbitrary JSON, fake, filename, tag, or Registry-local copy.

### Authority historical records

| Semantic family | Reserved candidate `schema_version` | Required Authority annex inputs |
| --- | --- | --- |
| `HistoricalSecretCredentialAuthorizationEntryIdentityV1` | `splendor.authority.historical_secret_ref_entry_identity.v1` | exact existing `SecretRefId`, positive source revision, zero-based canonical source ordinal |
| `AuthorityHistoricalSecretRefEvidenceSourceV1` | `splendor.authority.historical_secret_ref_evidence.v1` | evidence ID, exact RFC 0014 source ref/entry bytes/identity/ordinal/digests, origin, complete historical allow facts from RFC 0017's fact table, exact RFC 0016 per-slot Registry binding, owner/resource/audit/visibility facts, outbox intent, source digest/attestation output retained outside canonical source payload |
| `AuthorityHistoricalSecretRefProofSetClaimV1` | `splendor.authority.historical_secret_ref_proof_set_claim.v1` | proof-set ID, exact source ref/revision/digest/count, ordered one-entry/one-evidence/source-digest bindings, complete forward/reverse uniqueness projection, resource/integrity facts |
| `AuthorityHistoricalNativeEvidenceCommandV1` | `splendor.authority.historical_secret_ref_native_evidence_command.v1` | native command ID, authenticated owner/caller/scope/audience, exact retained native issuance/ref-mutation source transaction, complete ref/entry set, Registry bindings, resource/publication/audit inputs, semantic digest |
| `AuthorityHistoricalImportCommandV1` | `splendor.authority.historical_secret_ref_import_command.v1` | import command ID, authenticated dedicated import authority/scope/audience, exact historical bytes, source-owner provenance/attestation and trust/key status, complete ref/entry set, Registry bindings, resource/publication/audit inputs, semantic digest |
| `AuthorityHistoricalSecretRefPublicationFinalizationV1` | `splendor.authority.historical_secret_ref_publication_finalization.v1` | finalization ID/command, exact fixed source identity/digest/source transaction/outbox, exact Event/Evidence coordinates/receipts and ordered bindings, durability/completeness/trust/key status, resource disposition/release state, owner revision/time/integrity |
| `AuthorityHistoricalOutboxIntentV1` | `splendor.authority.historical_secret_ref_outbox_intent.v1` | outbox ID, exact source entry/evidence identity/digest, Event/Evidence profiles/audience/commands/durability, owner transaction/revision |
| `AuthorityHistoricalRecoveryV1` | `splendor.authority.historical_secret_ref_recovery.v1` | recovery command, exact retained proof-set/source/outbox/finalization coordinates and state, owner revision/integrity; no alternate identity or semantics |

The Authority source's exact semantic facts are the complete table in RFC 0017
`One Immutable Source Record Per Canonical Entry`. No applicable fact may move
into an extension, side table, hidden join, current lookup, or generic owner
reference. If an external owner type is unresolved, construction stops.

RFC 0014's migration proof bundle remains an ordered array of objects with
exactly its accepted eighteen required non-null members. This RFC adds no member,
alias, extension, owner receipt, attestation, or finalization field.

## Collection and Cardinality Registry

Every array is declared either `ordered` or `semantic_set`. Ordered arrays retain
input semantic order and are never sorted. Semantic sets reject duplicates before
sorting and sort by the exact key below. Absence, empty, and null are distinct;
null is always forbidden. An empty collection is accepted only where the table
explicitly allows zero.

For identity-bearing elements, duplicate detection is independent from sorting:
the same nominal identity with changed content or digest is a permanent binding
conflict, not two set members. The same element cannot appear in both sides of a
disjoint pair such as mandatory/optional or supporting/contradicting. An
owner-specific annex must name the nominal identity key, semantic conflict key,
sort key, and every required cross-set disjointness check separately.

| Collection | Kind and exact v1 bound | Canonical key |
| --- | --- | --- |
| RFC 0015 append batch | ordered `1..=256` | append order and contiguous sequence |
| RFC 0015 partial sub-effects | ordered `1..=256` | declared sub-effect order |
| Event causal parents | semantic set `0..=64` | complete relation kind then Event-coordinate JCS bytes |
| Event correlation refs | semantic set `0..=64` | complete typed-reference JCS bytes |
| Command causal/audit refs | semantic set `0..=64` | complete typed-reference JCS bytes |
| State parent `StateNodeId`s | ordered `0..=64`; profile may require at least one | accepted parent order; never sorted or deduplicated into another `StateNodeId` |
| Evidence mandatory/optional requirements | disjoint semantic sets `0..=256` each | requirement ID then complete requirement JCS bytes |
| Evidence commit-request item/source bindings | caller-significant ordered `0..=256`; at least one when profile requires | accepted request order; presence and order are idempotency/digest significant |
| Owner-materialized Evidence bundle item results | semantic set `0..=256`; at least one when profile requires | item ID then complete item-result JCS bytes |
| Evidence claims | semantic set `0..=64` | complete claim JCS bytes |
| Supporting/contradicting item IDs | disjoint semantic sets `0..=256` each | nominal UUID network bytes |
| Reason and obligation codes | semantic sets `0..=64` each | exact ASCII bytes |
| Accepted typed external-owner coordinates in one source | semantic set `0..=256` | exact owner-specific nominal identity, then complete accepted coordinate JCS bytes; same identity with changed bytes conflicts |
| RFC 0013 declaration sinks/sets | inherited exact RFC 0013 bounds, maximum 16 sinks | inherited RFC 0013 keys |
| RFC 0014 authorization/digest sets | inherited exact RFC 0014 bounds, maximum 16 | inherited RFC 0014 keys |
| RFC 0014/0017 proof entries | ordered `1..=16`, exactly source entry count | contiguous `source_entry_ordinal` |
| RFC 0016 per-slot evidence | exactly one distinct record for each admitted sink, therefore `1..=16` | RFC 0013 slot network bytes |

These are v1 security ceilings. A deployment/profile may tighten them. Raising a
ceiling changes accepted bytes/resource exposure and requires a new schema
version plus compatibility/security review.

## Untrusted-Ingress Budgets

Counts include unknown and duplicate content before rejection. Decoder-token
accounting matches the inherited RFC 0013 rule: one token for each object or
array open, each object or array close, each object member name, and each scalar
value. Commas and colons are not tokens. An array element has no additional
element token beyond the token(s) for its value; object-member and array-element
totals are independent counters. Thus `{}` and `[]` each use two tokens,
`{"a":1}` uses four, `[1]` uses three, `{"a":[]}` uses five, and
`[{"a":1}]` uses six. Nesting counts the root as depth one. Decoded string
bytes count after escape processing.

| Budget profile | Raw bytes | Depth | Tokens | Members | Elements | One decoded string | Canonical output |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `small_record_v1` | 65,536 | 16 | 4,096 | 1,024 | 1,024 | 1,024 | 65,536 |
| `owner_source_v1` | 262,144 | 24 | 16,384 | 4,096 | 4,096 | 4,096 | 262,144 |
| `batch_or_proof_set_v1` | 8,388,608 | 32 | 524,288 | 131,072 | 131,072 | 4,096 | 8,388,608 |

IDs, digests, schema IDs, labels, timestamps, and signatures retain their exact
smaller lexical widths. Event typed inline payload canonical bytes are
`1..=16,384`; larger payloads require a separately accepted immutable Artifact
reference and access policy.

These are available budget classes, not assignments to the reserved record
families. Every owner-specific grammar annex must map each registered schema to
exactly one class and prove by calculation and fixtures that the schema's legal
maximum fits its raw, decoded, and canonical ceilings. No record becomes
implementable while that assignment or proof is absent. A later annex is
expected to assign batches/proof sets to the large class, ordinary commands and
coordinates to the small class, and owner source/finalization records to the
owner-source class, but this expectation is not a registered schema rule.

Preflight enforces byte/depth/token/member/element/string limits before generic
record decoding. Over-bound inputs return one fixed grammar error and are not
partially retained, hashed, logged, or normalized. Streaming readers stop after
at most ceiling-plus-one bytes and never buffer an unbounded candidate before
denial.

## Digest Registry and Acyclic Projections

### Nominal digest wire

Every privileged digest is a distinct Rust newtype over `[u8; 32]` with exact
wire form:

```text
blake3:<64 lowercase hexadecimal characters>
```

The value is exactly 71 ASCII bytes. Uppercase, missing/alternate prefix,
alternate algorithm, wrong width, whitespace, null, and non-string forms reject.
New digest types expose no `Default`, public algorithm field, unchecked string
constructor, cross-family conversion, or generic `ContentHash` conversion.

Unless an inherited RFC explicitly says otherwise, construction is:

```text
canonical_projection = RFC8785_JCS(complete closed projection)
digest_input = UTF8(exact domain) || 0x00 || canonical_projection
digest_bytes = BLAKE3-256(digest_input)
wire = "blake3:" || lowercase_hex(digest_bytes)
```

`BLAKE3-256` is unkeyed standard BLAKE3 with a 32-byte output. No newline, BOM,
surrounding JSON string, implicit length, alternate algorithm, or hidden field is
added.

### Reserved nominal digest families

The following names are reserved for owner-specific annexes. Except for
`RegistryDeclarationDigest`, whose bytes and domain are complete below, they are
not implementable merely because they appear in this list:

```text
EventIntentDigest
EventAppendRequestDigest
EventAppendBatchDigest
EventAppendIdempotencyKeyDigest
EventEnvelopeDigest
EventAppendReceiptDigest
EventWriterFenceDigest
EventWriterRecordDigest
EventPublicationCommandDigest
EventPublicationAcknowledgementDigest
StatePartitionDigest
StateWriterEligibilityDigest
StateWriterActivationCommandDigest
StateWriterActivationIdempotencyKeyDigest
StateWriterFenceDigest
StateMutationRequestDigest
StateMutationIdempotencyKeyDigest
StateCommitReceiptDigest
EvidenceRequirementDigest
EvidenceItemDigest
EvidenceBundleDigest
EvidenceCommitRequestDigest
EvidenceCommitIdempotencyKeyDigest
EvidenceCommitReceiptDigest
EvidenceViewDigest
RegistryInstallationScopeDigest
RegistryDeclarationDigest
RegistryProjectionContractFingerprint
RegistryDeclarationBindingDigest
RegistryDeclarationRevisionFenceDigest
RegistryAdmissionCommandDigest
RegistryAdmissionDigest
RegistryActivationCommandDigest
RegistryActivationDigest
RegistryLifecycleTransitionCommandDigest
RegistryLifecycleTransitionDigest
RegistryLifecycleHeadDigest
RegistryAdmissionEvidenceDigest
RegistryCurrentObservationQueryDigest
RegistryCurrentObservationDigest
RegistryPublicationFinalizationDigest
RegistryPublicationFinalizationCommandDigest
AuthorityHistoricalSourceDigest
AuthorityHistoricalProofSetClaimDigest
AuthorityHistoricalNativeEvidenceCommandDigest
AuthorityHistoricalImportCommandDigest
AuthorityHistoricalPublicationFinalizationDigest
AuthorityHistoricalPublicationFinalizationCommandDigest
OwnerAttestationPayloadDigest
```

Before any reserved digest appears in code, persistence, or generated surfaces,
an accepted annex must provide a closed manifest row for every digest-bearing
field:

```text
record schema and exact field name
  -> one nominal digest type
  -> exact domain bytes
  -> exact closed included-field projection
  -> exact excluded fields and reason
  -> output location
  -> inherited compatibility exception, if any
```

The manifest is exhaustive rather than "at least" extensible. CI must reject a
duplicate domain, an unregistered digest field/type, or a projection dependency
cycle.

### Domain and projection table

| Digest family | Exact domain and projection |
| --- | --- |
| RFC 0013 destination digest | Inherited destination-schema domain and complete validated projection; unchanged. |
| RFC 0014 historical/target entry and ref digests | Inherited exact RFC 0014 schema domains and complete canonical values; unchanged. |
| `RegistryDeclarationDigest` | Domain `splendor.driver.operation_credential_sinks.v1`; projection is the exact existing RFC 0013 canonical declaration bytes, treated as the already-canonical payload. This creates a Registry-owned binding without changing RFC 0013 bytes or claiming RFC 0013 defined a digest. |
| `RegistryProjectionContractFingerprint` reservation | Intended domain `splendor.driver.registry.projection_contract_fingerprint.v1`; the exact closed projection remains unregistered and unconstructible until every projection-owner contract and its annex row are accepted. |
| complete record digests | Required future pattern: the record's registered schema domain and exact annex projection. This row is not a substitute for field-level manifest rows. |
| Event envelope integrity | Required future pattern: include the exact previous integrity field and exclude the exact current output/attestation fields named by the annex. No implementation is authorized by this summary. |
| source-record digests | Required future pattern: fixed source only; exact annex field names must exclude own output, attestations over it, downstream acknowledgements/finalization, and mutable delivery metadata. |
| finalization digests | Required future pattern: complete finalization excluding exact own output/attestation fields named by the annex. |
| request/command/idempotency digests | Required future pattern: complete normalized semantics, presence/absence, and identity namespace; exact fields and distinct nominal type are annex-owned. |
| owner attestation payload digest reservation | Intended domain `splendor.contract.owner_attestation.ed25519.v1`; exact construction remains blocked with the attestation record below. |

Only the RFC 0013 and RFC 0014 inherited rows plus
`RegistryDeclarationDigest` are complete digest constructions accepted by this
RFC. Summary-pattern rows do not authorize a record digest.

No source payload contains its own digest, a signature over its digest, a
downstream acknowledgement, or its publication finalization. No finalization is
an input to the Event/Evidence records that it acknowledges. No sibling source,
receipt, current-observation receipt, admission receipt, per-slot receipt, or
finalization can substitute for another family.

The mandatory graph is:

```text
fixed owner source payload and source digest
  -> owner-local outbox over that fixed source
  -> Event acknowledgement over the fixed source
  -> Evidence acknowledgement over the fixed source and Event receipt
  -> immutable owner publication finalization over exact acknowledgements
  -> separately authorized release/currentness decision
```

Self-digests, source/finalization cycles, acknowledgement backedges, sibling
receipt reuse, mutable-attempt inputs, and a finalization that mutates its source
are invalid contract shapes.

## Reserved C03 Owner Attestation Profile

This section reserves the intended C03 profile and prevents a local implementation
from selecting a different algorithm, purpose, or subject. It is **not a
registered or constructible record** until an accepted annex provides the exact
typed key-status coordinate, registers every subject schema/digest row below,
and defines trust-owner verification/revocation behavior. It does not implement
cryptography, trust roots, key lifecycle, or verification.

`OwnerAttestationV1` has exact schema
`splendor.contract.owner_attestation.ed25519.v1` and these required members:

```text
algorithm
attestation_id
audience
key_id
key_status_coordinate
purpose
schema_version
signature
signed_at
subject_digest
subject_owner
subject_schema
```

Object members serialize in JCS order. `algorithm` is `ed25519` and `audience`
is `c03_migration`. `purpose` is one exact registered purpose above.
`subject_owner`, `subject_schema`, and nominal `subject_digest` bind the exact
owner/family. `signed_at` is `CanonicalTimestampV1` and is not currentness.
`key_status_coordinate` must be a separately accepted exact typed trust-owner
coordinate; until that owner exists, C03 verification remains blocked.

The purpose/subject registry is closed:

| Purpose | Exact subject owner | Exact reserved subject schema | Exact reserved digest type |
| --- | --- | --- | --- |
| `event_append_receipt` | `splendor.event-log` | `splendor.event.append_receipt.v1` | `EventAppendReceiptDigest` |
| `state_commit_receipt` | `splendor.state-service` | `splendor.state.commit_receipt.v1` | `StateCommitReceiptDigest` |
| `evidence_commit_receipt` | `splendor.evidence-service` | `splendor.evidence.commit_receipt.v1` | `EvidenceCommitReceiptDigest` |
| `registry_admission_source` | `splendor.driver-registry` | `splendor.driver.registry.admission_source.v1` | `RegistryAdmissionDigest` |
| `registry_activation_source` | `splendor.driver-registry` | `splendor.driver.registry.activation_source.v1` | `RegistryActivationDigest` |
| `registry_lifecycle_transition_source` | `splendor.driver-registry` | `splendor.driver.registry.lifecycle_transition_source.v1` | `RegistryLifecycleTransitionDigest` |
| `registry_c03_slot_evidence_source` | `splendor.driver-registry` | `splendor.driver.registry.c03_slot_evidence.v1` | `RegistryAdmissionEvidenceDigest` |
| `registry_current_observation_source` | `splendor.driver-registry` | `splendor.driver.registry.current_observation_source.v1` | `RegistryCurrentObservationDigest` |
| `registry_publication_finalization` | `splendor.driver-registry` | `splendor.driver.registry.publication_finalization.v1` | `RegistryPublicationFinalizationDigest` |
| `authority_historical_source` | `splendor.authority-service` | `splendor.authority.historical_secret_ref_evidence.v1` | `AuthorityHistoricalSourceDigest` |
| `authority_publication_finalization` | `splendor.authority-service` | `splendor.authority.historical_secret_ref_publication_finalization.v1` | `AuthorityHistoricalPublicationFinalizationDigest` |

Every row remains a reservation until its record and digest annex is accepted.
No purpose may select another owner, subject schema, digest family, or generic
digest parser.

`signature` is the canonical RFC 4648 base64url encoding without padding of
exactly 64 Ed25519 signature bytes: exactly 86 ASCII characters from
`[A-Za-z0-9_-]`. Parsing decodes exactly 64 bytes and re-encodes byte-for-byte to
the supplied text. Padding, malformed/non-zero trailing bits, alternate
alphabet, or any noncanonical equivalent rejects.
The signed message is:

```text
UTF8("splendor.contract.owner_attestation.ed25519.v1") || 0x00 ||
RFC8785_JCS({
  algorithm, attestation_id, audience, key_id, key_status_coordinate,
  purpose, schema_version, signed_at, subject_digest, subject_owner,
  subject_schema
})
```

The `signature` member is excluded from the signed payload. Algorithm, key type,
purpose, audience, owner, schema, subject digest, or key-status substitution
fails. No algorithm negotiation or fallback exists in v1.

A syntactically valid attestation is not trusted. Verification requires the
separately accepted trust owner, exact public key, owner authorization for the
purpose, audience, key validity interval, status/revision/revocation, and source
contract. The later trust contract must require strict RFC 8032 Ed25519
verification, canonical public-key/signature encodings, scalar `S < L`, and
rejection of malformed or small-order inputs; permissive cross-library fallback
is forbidden. Unavailable trust status fails closed. Local private wrappers may
satisfy only RFC 0015's explicitly local profile and can never be converted into
this C03 attestation.

## Privacy, Protected Data, and References

New grammar values contain no raw secret, secret-derived digest, credential,
token, private key, provider request/error, provider-resolvable locator,
delivery endpoint, permit, lease material, approval token, protected evaluation
case identifier, unrestricted protected payload, private chain-of-thought, or
free-form provider detail.

Hashing is not redaction. Low-entropy or enumeration-sensitive digests remain
restricted and stay out of generic logs, metrics, errors, traces, examples,
discovery, crash bundles, and unauthorized views. IDs and references do not grant
read or resolution authority.

New restricted digest, attestation, owner-coordinate, source, receipt, and
finalization values do not derive full-value `Debug` and do not implement an
implicit full-value `Display`. `Debug` emits only the type and `<redacted>`;
authorized canonical serialization uses the explicit serializer, and tests use
an explicit fixture-only wire accessor. Existing RFC 0013/0014 public formatting
is unchanged, but callers remain responsible for its accepted visibility rules.

This RFC does not define a generic external-owner coordinate that can stand in
for Artifact, Lineage, conformance, Authority, trust, resource, audit, policy,
data-use, or deployment facts. A consuming record pins the exact accepted owner
type and schema. If that contract does not exist, persisted construction and live
composition are unsupported. Deterministic owner tests may use private typed
test ports, but test values are not serializable proof or runtime evidence.

## Fixed Grammar Errors

Untrusted parsers return closed code-only failures:

```text
invalid_contract_shape
invalid_contract_version
invalid_contract_identity
invalid_contract_timestamp
invalid_contract_integer
invalid_contract_digest
invalid_contract_signature
invalid_contract_bound
invalid_contract_binding
```

When one input violates multiple rules, parsers choose the first applicable code
in this exact order:

1. raw/depth/token/member/element/string/canonical budget ->
   `invalid_contract_bound`;
2. JSON syntax, duplicate/missing/unknown/alias/side member, null, wrong value
   kind, or coercion -> `invalid_contract_shape`;
3. schema/profile/version -> `invalid_contract_version`;
4. nominal identity -> `invalid_contract_identity`;
5. timestamp -> `invalid_contract_timestamp`;
6. integer token/range -> `invalid_contract_integer`;
7. digest wire or registered digest-field type -> `invalid_contract_digest`;
8. signature wire/profile -> `invalid_contract_signature`;
9. collection/cardinality or field-specific bound not caught by preflight ->
   `invalid_contract_bound`; and
10. cross-field, uniqueness, disjointness, or semantic binding ->
    `invalid_contract_binding`.

An owner-specific annex may add internal codes only at a fixed stage without
changing this outward precedence.

`Display` and `Debug` emit only the code. Errors retain and expose no candidate,
field value, path, member index, line/column, nested parser error, source chain,
owner existence, digest, key, coordinate, count, or retry advice. Owner mutation
and read surfaces map these internal grammar failures into their separately
accepted non-reflecting denial profiles; these codes are not a public existence
oracle.

## Rust Source of Truth and Generated Surfaces

Rust validated types in `splendor-types` are the canonical contract source.
Python, TypeScript, JSON Schema, OpenAPI models, fixtures, and docs may be
generated only from one reviewed contract manifest derived from those accepted
types and constants. Generated clients contain no owner decisions, hashing
authority, trust verification, persistence, Gateway behavior, or independent
runtime semantics.

The implementation must provide:

1. one checked schema/ID/enum/digest registry from Rust constants;
2. deterministic generation with pinned tool versions, locked and checksummed
   generator dependency graphs, a reviewed generator source/binary digest, and
   no network access;
3. a generated manifest containing input contract revision, generator digest,
   dependency-lock digest, and output digests;
4. clean-tree regeneration checks;
5. independent golden-byte and digest reproduction rather than generator
   self-validation only; and
6. cross-language positive and negative fixtures with identical accept/reject
   and canonical-byte results.

The planned generated evidence root is
`conformance/0.2/c03-foundation/v1/`. Its `manifest.json` is the generated
manifest; `golden/`, `positive/`, and `negative/` hold independent fixtures. The
planned check command is:

```text
python scripts/generate-c03-foundation-contracts.py --check
```

Neither path nor command is active until an implementation PR creates and tests
it under `FND-006`. Rust owns source contracts; generated Python output belongs
under `python/splendor`, generated TypeScript under
`typescript/packages/types`, and generated API models under their existing API
owner. No generated output becomes an independent source.

No generated surface is published before `FND-006` accepts its compatibility,
versioning, migration, downgrade, and rollback behavior. Hand-edited generated
artifacts fail validation.

## Sequenced Implementation Plan and Stops

### Slice 1 - Common lexical, ID, digest, and bound primitives

Scope:

- add strict new-ID and nominal digest macros privately in `splendor-types`;
- implement the exact timestamp, integer, schema/label, digest-wire,
  collection, ingress-budget, and error primitives;
- add only the IDs and common enums needed by the next dependency-safe family;
- expose only `RegistryDeclarationDigest` as a new constructible record digest;
  every other reserved record digest and the attestation record wait for an
  accepted exact annex;
- preserve existing IDs and RFC 0012-0014 bytes unchanged; and
- perform no I/O, owner behavior, package split, Store, daemon, SDK, or runtime
  wiring.

Required tests:

- canonical/noncanonical/nil/cross-type identity fixtures and compile-fail
  substitution tests;
- timestamp boundaries, invalid dates, leap second, offsets, precision, and year
  boundaries;
- JSON integer token and safe-range boundaries, including rejection of `-0`,
  every other minus-prefixed token, `+0`, leading zeroes, fractions, exponents,
  and ceiling-plus-one;
- digest prefix/width/case/algorithm tests plus independent inherited and
  `RegistryDeclarationDigest` BLAKE3 fixtures;
- exact ceiling and ceiling-plus-one parser budgets, with decoder-token fixtures
  for `{}`, `[]`, `{"a":1}`, `[1]`, `{"a":[]}`, and `[{"a":1}]`;
- no candidate reflection in errors; and
- stable RFC 0013/0014 byte and digest fixtures unchanged;
- stable `TraceEventId`/bytes and ordered-parent `StateNodeId` derivation fixtures
  unchanged; and
- compile/API evidence that final privileged records cannot acquire generic
  `Deserialize` or bypass their bounded parser in a later annex.

Stop if a type would imply owner behavior, a public existing type must change,
or the exact record family still needs an unresolved external-owner type.

### Slice 2 - RFC 0015 exact grammar annex and behavior-free values

First accept an owner-specific annex containing the complete exact field,
parser, budget, collection, and digest manifest required by this RFC. Then scope
and tests follow RFC 0015 Slice 1, using this common profile. Implement one
family at a time with canonical fixtures, compatibility projection,
receipt/source substitutions, non-authority API evidence, and no I/O.

Stop on `FND-003`, `FND-006`, `FND-009`, `EVT-002`, Artifact/Lineage, Authority
eligibility, Store, or owner-service behavior. Do not create
`splendor-evidence` in this slice.

### Slice 3 - Registry exact grammar annex and behavior-free values

Accept the complete Registry field/parser/budget/digest annex, but only after its
exact external-owner types have separately become accepted. Then implement only
the registered Registry-owned closed fields. Reuse RFC 0013 values/bytes exactly. Test
declaration digest, projection fingerprint, nominal separation, source/digest/
finalization cycles, lifecycle spellings, and no authority conversion.

Stop rather than invent Artifact, Lineage, conformance, publisher/registrar/
activation/revocation Authority, trust/key, resource, audit, deployment, Event,
or Evidence types or semantics.

### Slice 4 - Authority exact grammar annex and historical values

Accept the complete Authority and attestation field/parser/budget/digest annex,
then implement only after every mandatory RFC 0014, RFC 0016, trust/key, resource,
policy/data-use, audit, Event/Evidence, and applicable `FND-009` typed dependency
exists. Preserve one entry/one evidence identity and complete proof-set framing.

Stop on any `local.v1` conversion, hidden join, generic owner reference,
historical-to-current conversion, missing fact, or broad Authority replacement.

### Slice 5 - Generation and `G00`

After `FND-006` acceptance, generate parity surfaces and run independent
Rust/Python/TypeScript round trips, unknown-authorizing-field denial, canonical
bytes/digests, and stable compatibility fixtures. `G00` remains not exercised
until its real public harness runs and retained evidence is linked.

No slice may claim owner durability, Registry/Authority currentness, C03 proof,
task completion, or live behavior from behavior-free tests.

## Required Acceptance and Security Matrix

| Area | Required review or later executable evidence |
| --- | --- |
| Identity | Exact strict text, nil denial through bytes and typed constructors, nominal compile separation, no unchecked/default/random constructor, no cross-family conversion, distinct owner allocations where required. |
| Closed schemas | Before any record annex is accepted: exact fields/types/presence/discriminants and no generic `Deserialize`; then missing/null/duplicate/unknown/alias/side/extension and N-1/N+1 forms reject before lookup with no downgrade or fallback. |
| Canonical bytes | Rust/Python/TypeScript produce identical RFC 8785 bytes; parse/serialize is idempotent; stable RFC 0013/0014/TraceEvent bytes remain exact. |
| Time/numbers | Every boundary and alternate spelling rejects consistently; legacy compatibility values remain unchanged. |
| Collections | Every semantic-set permutation yields one value; same nominal ID with changed content conflicts; disjoint sets cannot overlap; ordered arrays retain order; absent/empty/null do not collapse; stable State parent order/identity remains unchanged. |
| Digests | Before any record digest is implemented: exact field-to-type/domain/projection manifest and cycle check; then independent producer verifies every domain and one-byte/schema/domain/presence change while self-reference, sibling receipt, and source/finalization cycles cannot form. |
| Attestation | Remains unconstructible until exact trust coordinate and record/digest annexes exist; then wrong algorithm/key/purpose/audience/owner/schema/subject/key status and noncanonical base64/Ed25519 forms deny, while syntax alone grants no trust. |
| Non-authority | No serializable value converts to permit, trusted receipt, current handle, durability proof, historical proof, live head, Registry admission/currentness, Authority allow, or C03 migration. |
| Historical/current | Historical source, prior `active`, prior current observation, replay/import output, timestamp, generation, or opaque future value cannot become current/live. |
| Bounds | Exact schema-to-budget assignment plus maximum-fit proof before record implementation; ceiling/ceiling-plus-one raw/depth/token/member/element/string/canonical and collection fixtures; duplicate/unknown bombs count before rejection. |
| Privacy | Synthetic canary secrets and low-entropy candidates never appear in canonical values, digests, errors, `Debug`/`Display`, logs, metrics, fixtures, generated examples, or source chains. |
| Generation | Reproducible offline generation, clean tree, pinned manifest, independent gold producer, no hand edits or network. |
| Architecture | `splendor-types` remains behavior-free; stores, daemon, SDKs, bridges, C03, Registry, Authority, and test ports do not become shadow owners. |

## Non-Goals and Explicit Non-Claims

This RFC does not implement, authorize, or claim:

- full `FND-001`, `FND-003`, `FND-006`, `FND-009`, `EVT-002`, RFC 0015,
  RFC 0016, RFC 0017, Event, State, Evidence, Registry, Authority, or C03
  completion;
- registration or implementation of any reserved Event/State/Evidence, Registry,
  Authority, finalization, receipt, coordinate, or attestation record before its
  exact owner-specific annex is accepted;
- broad v2 foundational objects outside the exact C03 dependency profile;
- any owner service, package split, repository, Store engine/schema/migration,
  transaction, current lookup, resource policy, trust/key registry, redaction,
  read/export policy, daemon route, SDK, CLI, or side effect;
- transferable Event writers, live legacy cutover, Registry rollout/selection,
  driver invocation, Authority issuance/import execution, proof-bound migration,
  target allocation, ref-head CAS, secret lease/use, provider/node/Gateway access,
  or replay with live effects;
- a generic external-owner fact that substitutes for an unresolved owner
  contract;
- cross-store atomicity, distributed exactly-once, currentness from a timestamp,
  latest/newest lookup, historical-to-live conversion, signature-shaped trust,
  fake durability, or automatic retry of uncertainty;
- publication of generated schemas before `FND-006` acceptance and parity;
- closure of #220 or any dependent issue, component completion, conformance,
  `G00` or any gold pass, release readiness, production readiness, durability,
  certification, or self-acceptance.

## Acceptance Effect

If accepted through independent architecture/compatibility, security/privacy,
and contract review, this document authorizes only Slice 1 common lexical,
nominal ID, closed enum, digest-wire, budget, non-authority, and compatibility
primitives. Record-family names and schema strings remain collision reservations,
not registered schemas. Acceptance changes no runtime and closes no task.

Acceptance must confirm stable 0.1 and RFC 0012-0014 byte preservation; exact
nominal identity separation; the requirement that future records be exact,
closed, no-extension, bounded-parser-only contracts; canonical timestamp,
safe-integer, JCS, collection, and digest-wire primitives; the closed Ed25519
attestation reservation and trust stop; acyclic source-to-finalization
requirements; no grammar-to-authority/durability/currentness conversion; no
generic external-owner substitute; finite ingress; privacy and non-reflecting
errors; reproducible cross-language generation; every dependency stop; and every
non-claim above.

Code may then proceed only with Slice 1 primitives and
`RegistryDeclarationDigest`. No record or other record digest may proceed until
its complete field types, parser, budget, collection, digest, and trust bindings
are accepted in an owner-specific annex. If an external owner, compatibility,
transaction, redaction, trust, resource, or canonical-byte question remains
unresolved, implementation stops rather than inventing a local answer.
