# RFC 0025 - Fixed-Local Event Append Owner Annex

## Status and Binding

**Status:** Proposed

**Date:** 2026-07-23

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program/component:** `V2-FND-0 Foundations` and Event Log

**Primary catalog task:** `FND-003` / issue #222

**Supporting catalog task:** `EVT-001` / issue #271

**Functional requirement bridge:** `FR-0.2-01`, `FR-0.2-02`, `FR-0.2-03`,
and `FR-0.2-08`

**Verification bridge:** `V2-FND-0` and `V2-IA-3`

**Gold targets:** `G00`, `G02`, `G03`, and `G08`; all remain
`specified_not_implemented` / `not_exercised`

**Semantic mutation owner:** `splendor-evidence::event`

**Mechanical Store owner:** `splendor-store`, limited in this annex to one
bounded deterministic process-local memory adapter

**Normative inputs:** [RFC 0015](0015-event-state-evidence-ownership-and-durability-contract.md),
[RFC 0018](0018-c03-foundation-grammar-profile.md),
[RFC 0019](0019-command-decision-event-outbox-recovery-contract.md), and
[RFC 0020](0020-c03-foundation-compatibility-migration-profile.md)

This RFC is a documentation-only proposal. It changes no runtime, public type,
schema registration, Store format, dependency, daemon route, SDK, generated
surface, task status, issue status, conformance status, Gold status, or release
claim. Code remains blocked until this RFC is accepted through independent
architecture/compatibility and security/privacy review.

## Decision

This annex defines only two implementation slices:

1. behavior-free closed Event grammar and canonical derivations; and
2. deterministic Event-owner semantics over one bounded in-memory Store whose
   complete lifetime is contained in one running Splendor process.

The owner profile is exactly:

```text
command_family = event.append.owner_record_v1
profile = owner_record_v1
partition_kind = agent_run
kind = foundation.no_effect
kind_schema = splendor.event.foundation_no_effect.v1
external_effect_required = false
store_profile = deterministic_memory_v1
achieved_durability = memory_only
writer_epoch = 1
```

It supports one fresh partition, one process-bound writer, one contentless typed
payload, one append per command, exact duplicate recognition, opaque conflict,
bounded process-local inspection, and no external effect. The Event owner's own
in-memory state mutation is the RFC 0019 owner-local no-effect transaction. It is
not operation `O`, adapter execution, or permission to mutate another owner.

The proposal does **not** authorize SQLite, filesystem persistence, writable
reopen, restart recovery, terminal writer records, backup, restore, migration,
forward repair, or production durability. A real SQLite adapter remains blocked
on a separately accepted storage/resource annex. Consequently this RFC makes no
claim that a result survives process death, host failure, rollback, or restart.

This narrowing is deliberate. It leaves an implementable grammar and owner
state machine without inventing a durable identity, anti-rollback authority,
ambiguous-commit recovery rule, or incomplete storage security contract.

## Scope and Non-Goals

The only registered top-level record schemas are:

```text
splendor.event.partition.v1
splendor.event.append_intent.v1
splendor.event.envelope.v1
splendor.event.fixed_local_writer_record.v1
splendor.event.append_request.v1
splendor.event.append_receipt.v1
```

The only registered nested payload schema is:

```text
splendor.event.foundation_no_effect.v1
```

This RFC does not define or authorize:

- State, Evidence, ReplayPlan, Registry, Authority, audit, C03, Artifact,
  Lineage, trust, data-use, policy, approval, lease, or resource-service records;
- `trace_event_compatibility_v0_1` as a live new-store append profile;
- arbitrary JSON, a generic map, a payload reference, a broad event-kind
  registry, or any secret-bearing payload;
- batch, outbox, inbox, publication, acknowledgement, subscription, retention,
  compaction, remote transport, or an external operation `O`;
- a persistent writer lifecycle, `closed` or `quarantined` writer status,
  writer renewal, rotation, transfer, higher epoch, handoff, or second writer;
- a filesystem path, SQLite database, WAL/SHM files, database attachment,
  checkpoint, backup, restore, migration, writable restart, or recovery scan;
- daemon, HTTP, SDK, CLI, Python, TypeScript, JSON Schema, OpenAPI, or generated
  client surfaces;
- live migration or dual write from an existing 0.1 Trace/State database; or
- completion of `FND-003`, `EVT-001`, C03, any Gold case, conformance, or
  production readiness.

The RFC 0015 batch, outbox, inbox, publication, coordinate, and public recovery
families remain unregistered. They cannot be approximated with a one-item batch,
private table DTO, generic string reference, or `serde_json::Value`.

## Ownership and Package Direction

| Layer | Exact responsibility in this slice | Forbidden responsibility |
| --- | --- | --- |
| `splendor-types` | Behavior-free nominal IDs/digests, closed records, bounded parsers, checked constructors, JCS serialization, and pure record/digest projections including exact `C` | ID/time allocation, live admission, private `D`, duplicate/conflict interpretation, Store calls, receipt trust, process lifecycle, or replay execution |
| `splendor-evidence::event` | Authenticate caller facts, issue the sealed live handle, allocate all new live IDs/times, own writer legality, construct private `D`, materialize envelope/receipt, interpret Store observations, apply error precedence, latch uncertainty, and expose process-local receipt/inspection handles | Provider behavior, another owner's state, public transport, arbitrary payload registration, SQLite, or writable restart |
| `splendor-store` | Implement a mechanical bounded-memory transaction over owner-prepared canonical bytes, exact unique keys, CAS fields, and owner-supplied capacity charge | Construct `C` or `D`, allocate owner identities/times, decide duplicate/conflict/retry/recovery, select latest state, trust a receipt, or own lifecycle policy |
| `splendor-kernel` | No implementation in the two authorized slices; a later composition may wire the private owner only after separate review | Event mutation ownership, independent trace writes, stable Trace conversion, daemon exposure, or production success claims |
| Replay/inspection | Read a bounded immutable range through the Event-owner private inspection port during the same process lifetime or from detached test fixtures | Append, repair, activate retained bytes, reconcile uncertainty, claim durability, or emit a live event |

`PreparedEventAppendDecisionV1`, duplicate/conflict interpretation, uncertainty
latching, and process-local receipt trust live only in `splendor-evidence::event`.
They are not helpers in `splendor-types` and are not Store DTO semantics. Store
results report only mechanical observations such as exact rows, CAS mismatch,
capacity failure, failure-before-swap, or unknown swap disposition; the Event
owner alone maps those observations to `EventAppendOutcomeV1`.

## Threat Model and Trust Boundaries

The slice assumes an authenticated in-process composition caller but treats that
producer as potentially malicious within its tenant/run scope. It also treats
all parser bytes, typed parser outputs, Store bytes/index assertions, detached
fixtures, duplicate claims, receipts without a sealed handle, clocks/CSPRNG when
unavailable, allocator failures, cancellation, and Store fault observations as
untrusted. A wrong tenant/run/audience/process value is adversarial, not a caller
mistake that may be corrected by lookup.

The trusted computing base is limited to the Event-owner module, its private type
constructors and handle provenance, authenticated composition context, available
owner CSPRNG/clock, and the mechanical atomicity of the bounded Store swap. Store
does not become trusted for semantic interpretation; owner revalidates retained
canonical bytes and digests. This annex protects against cross-scope substitution,
UUID/timestamp smuggling, changed duplicate reuse, existence/error oracles,
unbounded allocation/work, valid-prefix reactivation, and success after uncertain
mutation. Arbitrary memory corruption or code execution inside the Splendor
process is outside this grammar-only/memory-owner slice and cannot be used to
claim production security.

## Common Wire and API Rules

All registered records inherit RFC 0018 exactly:

- closed non-empty JSON objects with one exact `schema_version`;
- duplicate-aware bounded `from_json_slice(&[u8])` ingress before semantic
  lookup;
- checked `try_new` construction for typed inputs;
- RFC 8785 JCS bytes from `canonical_bytes()`;
- deterministic `Serialize` but no generic `Deserialize` on final privileged
  records;
- exact lowercase, hyphenated, non-nil UUID text for IDs;
- exact `CanonicalTimestampV1`, canonical safe integers, labels, schema IDs,
  digest wire, and fixed non-reflecting grammar errors; and
- no unknown, alias, side, `extensions`, defaulted, null, float, generic map,
  or arbitrary JSON member.

`from_json_slice` preflights and rejects over-bound bytes before generic record
decoding. It does not retain, hash, normalize, log, or reflect rejected input.
Nested values are parsed only through their parent record's bounded visitor or a
private fixture parser. Parsing proves grammar only; it never creates a value
eligible for the live owner path.

Every new ID, digest, record, fields builder, private `C`/`D` value, sealed live
handle, Store plan/result/error, owner outcome, and inspection value implements
`Debug` and, where present, `Display` as only its type or error-class name plus
`<redacted>`. No formatting or error source exposes UUID bytes, timestamps,
canonical bytes, digests, tenant/run/principal values, Store keys, allocator
addresses, filesystem paths, provider text, or nested source errors. Canonical
wire access is an explicit method, never formatting behavior.

## Live Admission and Provenance

The public bounded parsers are required for deterministic grammar and historical
fixture tests. Their accepted UUIDs and timestamps are untrusted assertions and
cannot be passed to `append_no_effect`.

Live admission instead uses a private, non-serializable
`LiveEventAppendHandleV1` issued only by `splendor-evidence::event`. Issuance:

1. accepts an already authenticated producer principal plus trusted tenant and
   run context from composition, not request bytes;
2. checks the exact process-bound partition handle and fixed profile;
3. reserves one volatile call/scratch slot before revealing Store existence;
4. allocates fresh `EventAppendCommandId` and
   `EventAppendIdempotencyKey` with the owner CSPRNG;
5. samples one owner clock value used for both `occurred_at` and
   `audit_requested_at` in this contentless profile;
6. binds the handle to the exact current `InstanceId`, partition, producer,
   command family, monotonic issuance generation, and owner nonce;
7. fixes a one-second monotonic handle expiry no later than writer expiry; and
8. materializes `EventAppendIntentV1` and `EventAppendRequestV1` only inside the
   Event owner.

The handle exposes no constructor, parser, serializer, raw UUID/timestamp
setter, field mutation, `From` conversion, or clone into another owner/process.
An exact in-process retry before handle expiry borrows the same sealed handle. A
producer cannot choose new-schema UUID or timestamp bytes and therefore cannot
smuggle secrets or PII through those fields. Existing tenant, run, and principal
IDs are trusted typed runtime context supplied before this command; they are
never accepted from the proposal payload. Owner-created partition, writer,
Store, Event, and receipt IDs follow the same private issuance rule.

The owner clock is a trusted process-local wall/monotonic pair. It retains the
maximum observed wall time. Unavailable time or wall/monotonic rollback latches
`failed_no_append`. An owner time at/after writer expiry latches opaque
`conflict`. Either latch lasts for the rest of the process. There is no persisted
clock claim and no restart path.

The owner CSPRNG is non-blocking at this boundary. Allocation permits at most two
16-byte samples per independently allocated UUID to handle a nil, duplicate, or
cross-type collision. A second rejection or unavailable CSPRNG returns
`failed_no_append`; allocation never loops or falls back to time, counters,
producer bytes, a weaker RNG, or a derived digest.

## Nominal Types and Closed Values

### IDs

The following RFC 0018 reservations become registered only for this annex:

```text
EventId
EventPartitionId
EventAppendCommandId
EventAppendIdempotencyKey
EventAppendReceiptId
FixedLocalEventWriterRecordId
```

This annex also registers `CombinedLocalStoreId` solely as the volatile identity
of one fresh bounded-memory Store. It is not durable, a filesystem identity, a
generic Store registry, or authority to reopen bytes.

Every ID is a distinct newtype over one non-nil UUID with RFC 0018's exact wire
and API restrictions. `splendor-types` provides no `Default`, random `new`,
unchecked `From<Uuid>`, cross-type conversion, or generic ID wrapper. The owner
derives only `EventId` and `EventAppendReceiptId` after `C`; every other new live
ID is owner-allocated independently before `C`.

```text
event_namespace = UUIDv5(UUID_NAMESPACE_OID,
                         UTF8("splendor.event.owner_record_v1.event_id"))
EventId = UUIDv5(event_namespace,
                 raw32(DecisionKey) || 0x00 || UTF8("logical_owner_event"))

receipt_namespace = UUIDv5(UUID_NAMESPACE_OID,
                           UTF8("splendor.event.owner_record_v1.receipt_id"))
EventAppendReceiptId = UUIDv5(receipt_namespace,
                              raw32(DecisionKey) || 0x00 || UTF8("append_receipt"))
```

UUIDv5 construction uses RFC 4122/RFC 9562 network-order UUID bytes exactly.
Coincident UUID bytes across any two nominal types in one request reject even
though Rust types already prevent substitution.

### Digests

The following are distinct nominal `[u8; 32]` digest newtypes with RFC 0018's
exact `blake3:<64 lowercase hex>` wire and redacted formatting:

```text
EventPartitionDigest
EventIntentDigest
EventAppendIdempotencyKeyDigest
EventAppendRequestDigest
EventAppendDecisionKeyDigest
EventAppendDecisionFingerprintDigest
EventEnvelopeDigest
EventAppendReceiptDigest
EventWriterFenceDigest
EventWriterRecordDigest
```

Digest equality never substitutes for retained canonical-byte equality.

### Enums and fixed constants

| Rust type or field | Exact accepted value in this slice |
| --- | --- |
| `EventAppendCommandFamilyV1` | `event.append.owner_record_v1` |
| `EventProfileV1` | `owner_record_v1` |
| `EventPartitionKindV1` | `agent_run` |
| `EventDurabilityClassV1` | `required_after_effect` |
| every durability floor and result | `memory_only` |
| `FixedLocalEventWriterStatusV1` | `active` only; there is no terminal record state or transition |
| `FixedLocalEventStoreProfileV1` | `deterministic_memory_v1` only |
| `VisibilityClassV1` | `restricted` |
| `EventLogicalRoleV1` | `logical_owner_event` |
| `EventAppendDecisionDispositionV1` | `append` |
| `EventAttemptDispositionV1` | `no_attempt` |
| `EventDispatchFenceDispositionV1` | `no_dispatch_fence` |
| `owner_component` | `splendor.event-log` |
| `owner_audience` | `splendor.event-log` |
| `kind_schema` | `splendor.event.foundation_no_effect.v1` |
| `kind` | `foundation.no_effect` |

`trace_event_compatibility_v0_1`, `transaction_committed`, and
`storage_barrier_confirmed` may remain reserved grammar spellings elsewhere but
are not admitted by any live value in this profile. Unknown/future values reject;
there is no `other` or fallback.

### Fixed nested values

`FoundationNoEffectEventPayloadV1` has exact canonical JSON:

```json
{"schema_version":"splendor.event.foundation_no_effect.v1"}
```

It has no optional member, content, extension, map, reference, bytes, or text.

`ExpectedEventBaseV1` is one closed internally tagged union:

```json
{"kind":"genesis"}
```

or:

```json
{"event_digest":"blake3:<64-lowercase-hex>","kind":"previous","sequence":0}
```

`genesis` is required exactly when `expected_next_sequence == 0`. `previous` is
required otherwise; its sequence is exactly `expected_next_sequence - 1`.

Four distinct zero-sized collection wrappers serialize only as `[]` and expose
no element constructor, insertion API, generic `Vec<T>` conversion, or non-empty
parser result:

```text
EmptyEventCausalParentsV1
EmptyEventCorrelationRefsV1
EmptyEventCommandCausalRefsV1
EmptyEventAuditRefsV1
```

## Exact Record Tables

Every table is exhaustive. Null never represents absence. Source member order is
immaterial after duplicate rejection; canonical output uses JCS order.

### `EventPartitionV1`

Schema: `splendor.event.partition.v1`; budget: `small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `descriptor_digest` | `EventPartitionDigest` | Required; recomputed from every other member. |
| `descriptor_revision` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required trusted owner context. |
| `partition_id` | `EventPartitionId` | Required owner-issued ID. |
| `partition_kind` | `EventPartitionKindV1` | Required exact `agent_run`. |
| `producer_principal_id` | existing `PrincipalId` | Required exact authenticated producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `run_id` | existing `RunId` | Required trusted run context. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `tenant_id` | existing `TenantId` | Required trusted tenant context. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |

### `EventAppendIntentV1`

Schema: `splendor.event.append_intent.v1`; budget: `small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `audit_principal_id` | existing `PrincipalId` | Required; equals authenticated producer. |
| `audit_requested_at` | `CanonicalTimestampV1` | Required owner-issued time; equals `occurred_at`. |
| `causal_parents` | `EmptyEventCausalParentsV1` | Required exact empty array. |
| `command_id` | `EventAppendCommandId` | Required owner-issued command ID. |
| `correlation_refs` | `EmptyEventCorrelationRefsV1` | Required exact empty array. |
| `idempotency_key` | `EventAppendIdempotencyKey` | Required owner-issued independent key. |
| `kind` | `CanonicalLabelV1` | Required exact `foundation.no_effect`. |
| `kind_schema` | `CanonicalSchemaIdV1` | Required exact fixed payload schema. |
| `occurred_at` | `CanonicalTimestampV1` | Required owner-observed occurrence time from the sealed handle. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `payload` | `FoundationNoEffectEventPayloadV1` | Required exact one-member object. |
| `producer_principal_id` | existing `PrincipalId` | Required exact authenticated producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `requested_durability` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `run_id` | existing `RunId` | Required exact trusted run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `tenant_id` | existing `TenantId` | Required exact trusted tenant. |

Producer event ID, sequence, recorded time, writer values, receipt, owner
revision, and external-effect values are forbidden.

### `FixedLocalEventWriterRecordV1`

Schema: `splendor.event.fixed_local_writer_record.v1`; budget:
`small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `backend_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `created_at` | `CanonicalTimestampV1` | Required owner-issued process time. |
| `current_event_digest` | `EventEnvelopeDigest` | Absent at genesis; required with current sequence. |
| `current_sequence` | `CanonicalSequenceV1` | Absent at genesis; required after first append. |
| `deployment_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `deployment_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `expires_at` | `CanonicalTimestampV1` | Required owner time, `1..=3,600` seconds after creation. |
| `fence_digest` | `EventWriterFenceDigest` | Required owner-derived process fence. |
| `last_recorded_at` | `CanonicalTimestampV1` | Absent at genesis; otherwise current envelope time. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required exact partition owner. |
| `owner_profile_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `prior_event_digest` | `EventEnvelopeDigest` | Absent at genesis/sequence `0`; otherwise predecessor digest. |
| `prior_sequence` | `CanonicalSequenceV1` | Absent at genesis/sequence `0`; otherwise current minus one. |
| `process_instance_id` | existing `InstanceId` | Required exact identity of the currently running process; never durable deployment identity. |
| `producer_principal_id` | existing `PrincipalId` | Required exact producer. |
| `run_id` | existing `RunId` | Required exact run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `status` | `FixedLocalEventWriterStatusV1` | Required exact `active`; no other value or status transition exists. |
| `store_id` | `CombinedLocalStoreId` | Required owner-issued volatile Store identity. |
| `store_profile` | `FixedLocalEventStoreProfileV1` | Required exact `deterministic_memory_v1`. |
| `tenant_id` | existing `TenantId` | Required exact tenant. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `writer_record_digest` | `EventWriterRecordDigest` | Required; recomputed over every other member. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required owner-issued writer ID. |
| `writer_record_revision` | `CanonicalPositiveRevisionV1` | Starts at `1`; increments exactly once per append only. |

`InstanceId` retains its repository meaning: one running Splendor runtime
process/instance, random per instance. No value in this record is a durable
deployment slot. Retained bytes from a dead process are inspection-only.

For an append at sequence `s`, the next writer record moves the old current
sequence/digest into `prior_*`, writes `s` and the new envelope digest into
`current_*`, sets `last_recorded_at`, and increments the record revision exactly
once. Checked arithmetic failure denies before Store mutation.

For accepted appends:

```text
created_at <= occurred_at <= recorded_at < expires_at
last_recorded_at <= recorded_at  (when present)
```

### `EventAppendRequestV1`

Schema: `splendor.event.append_request.v1`; budget: `small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `audit_refs` | `EmptyEventAuditRefsV1` | Required exact empty array. |
| `causal_refs` | `EmptyEventCommandCausalRefsV1` | Required exact empty array. |
| `command_family` | `EventAppendCommandFamilyV1` | Required exact `event.append.owner_record_v1`. |
| `command_id` | `EventAppendCommandId` | Required; equals intent command ID. |
| `expected_base` | `ExpectedEventBaseV1` | Required exact genesis/previous condition. |
| `expected_next_sequence` | `CanonicalSequenceV1` | Required expected CAS value. |
| `idempotency_key` | `EventAppendIdempotencyKey` | Required; equals intent key. |
| `idempotency_key_digest` | `EventAppendIdempotencyKeyDigest` | Required owner recomputation. |
| `intent` | `EventAppendIntentV1` | Required complete intent. |
| `intent_digest` | `EventIntentDigest` | Required owner recomputation. |
| `partition` | `EventPartitionV1` | Required complete partition assertion. |
| `partition_digest` | `EventPartitionDigest` | Required exact descriptor digest. |
| `request_digest` | `EventAppendRequestDigest` | Required recomputation from exact `C`; excluded from `C`. |
| `requested_durability` | `DurabilityLevelV1` | Required exact `memory_only`; equals intent. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `writer_record` | `FixedLocalEventWriterRecordV1` | Required current process-local writer assertion. |
| `writer_record_digest` | `EventWriterRecordDigest` | Required exact writer digest. |

Event ID, receipt ID, recorded time, achieved durability, updated writer state,
Decision key/fingerprint, operation bytes/key, and adapter/effect fields are
forbidden. Live request construction is owner-only through the sealed handle.

The behavior-free request constructor and parser enforce these exact laws before
returning an untrusted grammar value; the live owner repeats them before lookup:

- command family is exact, and command ID, idempotency key, requested durability,
  partition ID, tenant, run, and producer agree across request, intent,
  partition, and writer record;
- owner principal, audience, component, profile, and visibility agree across all
  records that carry them;
- partition, intent, idempotency-key, writer-record, and request digests
  independently recompute under their nominal domains;
- genesis requires absent current/prior cursor and integrity fields plus
  `expected_next_sequence == 0`;
- non-genesis requires expected-base sequence/digest equal to writer current and
  `expected_next_sequence == current_sequence + 1`;
- writer status/profile/process/epoch are exact `active`,
  `deterministic_memory_v1`, current `InstanceId`, and `1`; and
- every differently typed ID in one request has different UUID bytes.

### `EventEnvelopeV1`

Schema: `splendor.event.envelope.v1`; budget: `small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `causal_parents` | `EmptyEventCausalParentsV1` | Required exact empty array. |
| `command_family` | `EventAppendCommandFamilyV1` | Required exact `event.append.owner_record_v1`. |
| `command_id` | `EventAppendCommandId` | Required exact accepted command. |
| `correlation_refs` | `EmptyEventCorrelationRefsV1` | Required exact empty array. |
| `decision_fingerprint` | `EventAppendDecisionFingerprintDigest` | Required exact derivation. |
| `decision_key` | `EventAppendDecisionKeyDigest` | Required exact derivation. |
| `durability_class` | `EventDurabilityClassV1` | Required exact `required_after_effect`. |
| `effective_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `event_digest` | `EventEnvelopeDigest` | Required; recomputed over every other member. |
| `event_id` | `EventId` | Required owner derivation from Decision key. |
| `intent_digest` | `EventIntentDigest` | Required exact intent digest. |
| `kind` | `CanonicalLabelV1` | Required exact `foundation.no_effect`. |
| `kind_schema` | `CanonicalSchemaIdV1` | Required exact fixed payload schema. |
| `logical_event_role` | `EventLogicalRoleV1` | Required exact `logical_owner_event`. |
| `occurred_at` | `CanonicalTimestampV1` | Required exact owner-issued intent time. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required exact owner. |
| `owner_revision` | `CanonicalPositiveRevisionV1` | Required post-append writer revision. |
| `partition_digest` | `EventPartitionDigest` | Required exact partition digest. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `payload` | `FoundationNoEffectEventPayloadV1` | Required exact fixed payload. |
| `previous_event_digest` | `EventEnvelopeDigest` | Absent at sequence `0`; required otherwise. |
| `producer_principal_id` | existing `PrincipalId` | Required exact producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `recorded_at` | `CanonicalTimestampV1` | Required owner time sampled before memory commit. |
| `request_digest` | `EventAppendRequestDigest` | Required exact command semantic digest. |
| `run_id` | existing `RunId` | Required exact run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `sequence` | `CanonicalSequenceV1` | Required expected next sequence. |
| `tenant_id` | existing `TenantId` | Required exact tenant. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `writer_fence_digest` | `EventWriterFenceDigest` | Required exact process fence. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required exact writer. |
| `writer_record_revision_before` | `CanonicalPositiveRevisionV1` | Required pre-append revision. |

The envelope excludes its own digest input, receipt, updated writer digest, and
all downstream values.

### `EventAppendReceiptV1`

Schema: `splendor.event.append_receipt.v1`; budget: `small_record_v1`.

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `achieved_durability` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `attempt_disposition` | `EventAttemptDispositionV1` | Required exact `no_attempt`. |
| `backend_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `caller_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `command_family` | `EventAppendCommandFamilyV1` | Required exact `event.append.owner_record_v1`. |
| `command_id` | `EventAppendCommandId` | Required exact command. |
| `committed_at` | `CanonicalTimestampV1` | Required exact envelope recorded time. |
| `decision_fingerprint` | `EventAppendDecisionFingerprintDigest` | Required exact fingerprint. |
| `decision_key` | `EventAppendDecisionKeyDigest` | Required exact key. |
| `deployment_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `deployment_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `dispatch_fence_disposition` | `EventDispatchFenceDispositionV1` | Required exact `no_dispatch_fence`. |
| `durability_class` | `EventDurabilityClassV1` | Required exact `required_after_effect`. |
| `effective_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `event_digest` | `EventEnvelopeDigest` | Required exact committed envelope digest. |
| `event_id` | `EventId` | Required exact Event ID. |
| `idempotency_key_digest` | `EventAppendIdempotencyKeyDigest` | Required exact key digest. |
| `intent_digest` | `EventIntentDigest` | Required exact intent digest. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required exact owner. |
| `owner_profile_durability_floor` | `DurabilityLevelV1` | Required exact `memory_only`. |
| `owner_revision` | `CanonicalPositiveRevisionV1` | Required post-append revision. |
| `partition_digest` | `EventPartitionDigest` | Required exact partition digest. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `previous_event_digest` | `EventEnvelopeDigest` | Absent at sequence `0`; required otherwise. |
| `producer_principal_id` | existing `PrincipalId` | Required exact producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `receipt_digest` | `EventAppendReceiptDigest` | Required; recomputed over every other member. |
| `receipt_id` | `EventAppendReceiptId` | Required owner derivation from Decision key. |
| `request_digest` | `EventAppendRequestDigest` | Required exact request digest. |
| `run_id` | existing `RunId` | Required exact run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `sequence` | `CanonicalSequenceV1` | Required exact committed sequence. |
| `tenant_id` | existing `TenantId` | Required exact tenant. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `writer_fence_digest` | `EventWriterFenceDigest` | Required exact process fence. |
| `writer_record_digest_after` | `EventWriterRecordDigest` | Required exact updated writer digest. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required exact writer. |
| `writer_record_revision_after` | `CanonicalPositiveRevisionV1` | Required before revision plus one. |
| `writer_record_revision_before` | `CanonicalPositiveRevisionV1` | Required exact request revision. |

The receipt proves only a process-local memory commit. It cannot satisfy a
durable Event, State, Evidence, C03, action, publication, or production contract.

## Parser and Retained-Byte Budgets

All six records use RFC 0018 `small_record_v1`: raw bytes `65,536`, depth `16`,
tokens `4,096`, members `1,024`, elements `1,024`, one decoded string `1,024`,
and canonical output `65,536`. Lower ceilings are mandatory:

| Record/value | Maximum depth | Maximum total members | Maximum array elements | Canonical ceiling |
| --- | ---: | ---: | ---: | ---: |
| `EventPartitionV1` | 1 | 13 | 0 | 2,048 bytes |
| `EventAppendIntentV1` | 2 | 18 | 0 | 4,096 bytes |
| `FixedLocalEventWriterRecordV1` | 1 | 28 | 0 | 4,096 bytes |
| `EventAppendRequestV1` | 3 | 79 | 0 | 16,384 bytes |
| `EventEnvelopeV1` | 2 | 37 | 0 | 8,192 bytes |
| `EventAppendReceiptV1` | 1 | 42 | 0 | 8,192 bytes |
| exact retained `C` | 3 | 78 | 0 | 16,384 bytes |
| private retained `D` | 2 | 29 | 0 | 8,192 bytes |

Counts include nested object members, required empty arrays, and the one-member
payload. Unknown and duplicate members count before rejection. `C` is the
request projection without `request_digest`, so its maximum member count is
exactly one below the complete request.

Retained `C` reconstruction must decode through
`EventAppendRequestV1::from_json_slice` under the request raw/depth/token/member/
string/canonical bounds, verify that re-projection is byte-identical, then derive
`C`. Retained `D` uses an owner-private duplicate-aware visitor with raw and
canonical ceiling `8,192`, depth `2`, tokens `256`, members `29`, elements `0`,
and decoded-string ceiling `128`. It has no generic `serde_json::Value` path.
Ceiling and plus-one fixtures cover every dimension independently.

The behavior-free public APIs are:

| Type | Untrusted parser | Typed construction | Canonical/digest API |
| --- | --- | --- | --- |
| `EventPartitionV1` | `from_json_slice` | `try_new(EventPartitionV1Fields)` | `canonical_bytes`; `descriptor_digest` |
| `EventAppendIntentV1` | `from_json_slice` | `try_new(EventAppendIntentV1Fields)` | `canonical_bytes`; `intent_digest` |
| `FixedLocalEventWriterRecordV1` | `from_json_slice` | `try_new(FixedLocalEventWriterRecordV1Fields)` | `canonical_bytes`; `writer_record_digest` |
| `EventAppendRequestV1` | `from_json_slice` | `try_new(EventAppendRequestV1Fields)` | `canonical_bytes`; `command_bytes`; `request_digest` |
| `EventEnvelopeV1` | `from_json_slice` | `try_new(EventEnvelopeV1Fields)` | `canonical_bytes`; `event_digest` |
| `EventAppendReceiptV1` | `from_json_slice` | `try_new(EventAppendReceiptV1Fields)` | `canonical_bytes`; `receipt_digest` |

The `*Fields` values are typed parameter structs, not serializable records, and
have no defaults. Their constructors and every parser return untrusted grammar
values; only `splendor-evidence::event` can bind owner-created values to a sealed
live handle. `splendor-types` exposes no `D` type or constructor.

`canonical_bytes()` is fixture/offline convenience and may allocate only outside
an active Event owner. Every record additionally exposes pure
`canonical_len()` and `write_canonical_into(&mut [u8])`, which either write the
exact JCS length into sufficient caller storage or return the fixed
`invalid_contract_bound` grammar error without modifying the destination. The live
owner and private inspection path must use fixed record representations,
caller-provided scratch/arena slices, and streaming BLAKE3; they never call an
allocating convenience API after pool creation.

## Digest Manifest and Acyclic Derivation

Unless a row names RFC 0019's inherited formula, each digest is:

```text
BLAKE3-256(UTF8(exact_domain) || 0x00 || RFC8785_JCS(exact_projection))
```

| Output/type | Exact domain | Exact included projection | Exact exclusions |
| --- | --- | --- | --- |
| `EventPartitionDigest` | `splendor.event.partition.v1` | Every partition member except descriptor digest | Own output only |
| `EventIntentDigest` | `splendor.event.append_intent.v1` | Complete intent including empty arrays and fixed payload | None |
| `EventAppendIdempotencyKeyDigest` | `splendor.event.append_idempotency_key.v1` | Object containing exactly `command_family`, `idempotency_key`, `owner_audience`, `owner_component`, `owner_principal_id`, `partition_id`, `producer_principal_id`, `run_id`, and `tenant_id` | Every later value |
| `EventAppendRequestDigest` | `splendor.fnd003.command-semantics.v1` | Exact `C` below | Request digest and every later value |
| `EventAppendDecisionKeyDigest` | `splendor.fnd003.decision-key.v1` | Exact `C` below | Every derived key/digest and owner output |
| `EventAppendDecisionFingerprintDigest` | `splendor.fnd003.decision-fingerprint.v1` | RFC 0019 formula over Decision key and exact private `D` | Fingerprint and every later value |
| `EventWriterFenceDigest` | `splendor.event.fixed_local_writer_fence.v1` | Object containing exactly `backend_policy_revision`, `created_at`, `deployment_policy_revision`, `expires_at`, `owner_audience`, `owner_component`, `owner_principal_id`, `partition_id`, `process_instance_id`, `producer_principal_id`, `run_id`, `store_id`, `store_profile`, `tenant_id`, `writer_epoch`, and `writer_record_id` | Mutable cursor/status/revision and later values |
| `EventWriterRecordDigest` | `splendor.event.fixed_local_writer_record.v1` | Every writer member except writer digest | Own output only |
| `EventEnvelopeDigest` | `splendor.event.envelope.v1` | Every envelope member except event digest | Own output and later values |
| `EventAppendReceiptDigest` | `splendor.event.append_receipt.v1` | Every receipt member except receipt digest | Own output only |

### Exact `C`

`C` is the JCS object formed from every `EventAppendRequestV1` member except
`request_digest`. It therefore contains exact
`command_family = event.append.owner_record_v1`, command and owner-issued
idempotency identities, complete intent/partition/writer records and their
digests, expected base/sequence, requested durability, audit/causal empties, and
all presence distinctions. There is no wrapper, newline, default, hidden field,
or side-table semantic.

`C` excludes request digest, Decision key/fingerprint, `O`, operation key,
Event/receipt IDs, recorded/commit time, envelope/receipt bytes, achieved
durability, updated writer state, Store observations, and every value derived
from them.

Action, tick, work-order, capability, approval, data-use, secret, lease,
Artifact, payload-reference, and external audit-reference fields are inapplicable
and schema-forbidden in this no-effect profile. Their canonical absence is the
absence of those members, not null, empty strings, default IDs, empty objects, or
hidden context. A profile admitting any such semantic requires another accepted
owner annex.

```text
EventAppendRequestDigest = BLAKE3-256(
  UTF8("splendor.fnd003.command-semantics.v1") || 0x00 || C
)

EventAppendDecisionKeyDigest = BLAKE3-256(
  UTF8("splendor.fnd003.decision-key.v1") || 0x00 || C
)
```

The command namespace is exactly:

```text
(owner_component = splendor.event-log,
 tenant_id,
 command_family = event.append.owner_record_v1,
 producer_principal_id,
 owner_audience = splendor.event-log,
 command_id)
```

The permanent process-local idempotency scope is exactly:

```text
(tenant_id, command_family, producer_principal_id,
 partition_id, idempotency_key)
```

### Exact private `D`

After owner admission and current-writer checks,
`splendor-evidence::event` constructs private retained JCS with exactly these 29
members:

```text
backend_policy_revision
command_family = event.append.owner_record_v1
command_id
command_semantic_digest
decision_key
deployment_policy_revision
disposition = append
durability_class = required_after_effect
effective_durability_floor = memory_only
event_id
expected_base
expected_next_sequence
external_effect_required = false
intent_digest
logical_event_role = logical_owner_event
owner_audience = splendor.event-log
owner_component = splendor.event-log
owner_principal_id
partition_digest
partition_id
producer_principal_id
profile = owner_record_v1
run_id
tenant_id
writer_epoch = 1
writer_fence_digest
writer_record_digest
writer_record_id
writer_record_revision_before
```

`PreparedEventAppendDecisionV1` has no public schema, parser, serializer, or
caller constructor. Its private canonical method and retained decoder live only
in `splendor-evidence::event`. It is never implemented in `splendor-types` or
interpreted by Store.

`D` excludes its fingerprint, `O`, operation key, recorded/commit time,
achieved durability, updated writer record, Store transaction identity,
envelope digest, receipt, and every later value.

```text
EventAppendDecisionFingerprintDigest = BLAKE3-256(
  UTF8("splendor.fnd003.decision-fingerprint.v1") || 0x00 ||
  raw32(EventAppendDecisionKeyDigest) || 0x00 || D
)
```

There is no `O`. Operation keys, attempts, dispatch fences, provider status, and
effect certainty are structurally absent.

### Dependency graph

```text
owner-issued command/idempotency/partition/writer identities and times
  -> partition/intent/idempotency/writer-current digests
  -> C (including command_family)
  -> request digest and Decision key
  -> owner-derived EventId
  -> private D (including command_family)
  -> Decision fingerprint
  -> owner recorded_at and envelope (including command_family)
  -> envelope digest
  -> updated writer record and digest
  -> receipt ID and receipt (including command_family)
  -> receipt digest
  -> one process-local memory swap
```

Required graph fixtures reject direct, indirect, optional, default-value, and
cross-family cycles. Independent fixtures mutate every `C` member and nested
presence once; each mutation changes both request digest and Decision key.
Fixtures also remove or change `command_family` independently in request, `C`,
`D`, envelope, receipt, idempotency projection, and namespace; every mutation
rejects or changes every dependent digest as applicable.

## Process-Lifetime Writer Contract

`create_process_local_partition` receives trusted composition context and the
current process `InstanceId`. Event owner allocates Store/partition/writer IDs,
samples creation/expiry time, derives the fence, creates revision `1` with exact
status `active`, and asks Store to install one complete genesis image in one
atomic memory swap.

A proved pre-swap creation failure returns no writer and may retry only with the
same still-live private creation handle. Unknown creation disposition returns no
writer, latches the Event owner unavailable, and discards the arena at process
shutdown; it has no lookup, receipt, activation, or recovery path.

The writer guard and all Store bytes exist only in that process. The current
`InstanceId` is random per running process as required by the stable identity
contract. Process termination irrevocably ends write authority. There is no API
to serialize a live handle, reopen retained bytes, reuse the old `InstanceId`,
restore a Store image, activate a fixture, renew expiry, alter epoch/fence, or
create a second writer.

This rule closes valid-prefix rollback: no historical prefix can become writable
because no bytes from any prior process can activate at all. A copied, restored,
older, newer, or byte-identical image is inspect-only and has no live handle.
Acceptance of this RFC does not assert an external monotonic anti-rollback fact.

`active` is the only writer-record status. Fail-closed process conditions use a
private volatile owner latch, not a writer-record transition. Once latched for
clock failure, invariant failure, or unknown commit disposition, every later
append in that process returns the exact original non-success class (`conflict`,
`failed_no_append`, or `append_outcome_uncertain`) without Store mutation. No
`active -> closed`, `active -> quarantined`, reactivation, or terminalization
transaction is claimed.

## Owner Append Protocol

The private application operations are semantically equivalent to:

```text
issue_live_no_effect_handle(authenticated_context, process_partition_handle)
  -> EventAppendAdmissionOutcomeV1

append_no_effect(&LiveEventAppendHandleV1)
  -> EventAppendOutcomeV1
```

`EventAppendAdmissionOutcomeV1` is also sealed and total:

```text
issued(LiveEventAppendHandleV1)
conflict
resource_exhausted
failed_no_append
```

It has no malformed-input case because issuance accepts only typed trusted
composition context; untrusted bytes terminate at the grammar parser. Its
`conflict`, `resource_exhausted`, and `failed_no_append` cases use the same
precedence and outward profiles as the append outcome.

`EventAppendOutcomeV1` is a sealed, total owner result:

```text
appended(ProcessLocalEventAppendReceiptHandleV1)
duplicate(ProcessLocalEventAppendReceiptHandleV1)
conflict
rejected(FoundationGrammarError)
resource_exhausted
failed_no_append
append_outcome_uncertain
```

There is no wildcard, generic internal error, panic-to-success conversion,
implicit retry, or missing resource case. The receipt handle is bound to the
current Event owner and `InstanceId`; it is non-serializable and cannot satisfy a
privileged or durable receipt requirement.

### Total precedence

Owner evaluation uses the first matching row in this exact order:

| Precedence | Condition | Exact outcome |
| ---: | --- | --- |
| 1 | Process writer latch is unavailable from a prior call | Return that latch's exact original `conflict`, `failed_no_append`, or `append_outcome_uncertain` class; never success |
| 2 | Owner CSPRNG or trusted clock is unavailable/rolled back, or cancellation is already set | `failed_no_append` |
| 3 | Sealed handle is expired, or its provenance/nonce/generation/process binding, authenticated principal, tenant, run, audience, partition, producer, or command family differs or is absent | `conflict` |
| 4 | Owner-materialized record fails closed grammar, canonical, digest, cross-field, or provenance invariant | `rejected(FoundationGrammarError)` for this call; latch `failed_no_append` as an owner invariant fault |
| 5 | Volatile call/rate/scratch/work budget cannot be reserved | `resource_exhausted` before history lookup |
| 6 | Command/idempotency lookup returns two exact complete matching bindings and all retained bytes/digests validate | `duplicate(original process-local receipt handle)` |
| 7 | Lookup returns changed, partial, missing-pair, same-digest/different-byte, wrong-scope, corrupt, or inaccessible binding | `conflict`; integrity/access uncertainty also latches unavailable |
| 8 | Current writer/base/revision/digest/epoch/fence/expiry/process/Store or expected sequence differs | `conflict`; writer expiry latches this class |
| 9 | New retained arena/cardinality reservation cannot fit or checked arithmetic overflows | `resource_exhausted` |
| 10 | Mechanical Store proves failure before the atomic image swap | `failed_no_append` |
| 11 | Mechanical Store cannot prove whether its one image swap happened | `append_outcome_uncertain`; latch unavailable permanently; no receipt/recovery |
| 12 | Mechanical Store confirms the exact image swap and owner validates the committed image | `appended(process-local handle)` |

Equivalent concurrent calls that lose the swap may perform one exact retained
lookup and return row 6. Changed calls return row 7. Owner never fetches a latest
cursor and rebases. `resource_exhausted` is therefore represented consistently in
issuance, append outcome, Store observation mapping, tests, and any future
transport mapping.

Hidden, absent, wrong-tenant, wrong-run, wrong-audience, stale, fenced,
substituted, and unauthorized current-coordinate cases all select the same row 3,
7, or 8 `conflict` class. The owner performs the same bounded normalization and
redacted diagnostic path for all of them; no existence bit or winning coordinate
is returned.

### One mechanical memory transaction

For a new command, Event owner constructs all final canonical bytes and one
private owner `PreparedEventAppendDecisionV1`, then projects only opaque byte
slots, exact key bytes, CAS scalars, and a capacity charge into
`splendor-store`'s behavior-free `MemoryCompareAndSwapPlanV1`. The mechanical
Store operation:

1. locks the one Store writer guard;
2. compares exact command/idempotency absence and every owner-supplied writer CAS
   field;
3. verifies the owner-supplied arena charge fits without allocating;
4. copies canonical `C`, private `D`, envelope, receipt, and next writer bytes
   into an unused reserved arena region;
5. builds the fixed-capacity index entries and bounded next root metadata in
   scratch space; and
6. publishes the new root/index generation with one non-panicking pointer swap
   before releasing the guard.

Bytes copied before step 6 are unreachable reservation debt, not visible rows.
The Store never parses semantic fields or chooses an outcome. It reports exact
mechanical observations and borrowed retained bytes to the owner. A fault before
step 6 proves no append. Step 6 is deliberately one infallible in-process swap;
fault-injection retains an `unknown` result to prove fail-closed mapping, but no
unknown result can later produce success or writable recovery. A panic crossing
the Store boundary is caught by composition, mapped to unknown, and latches the
owner unavailable.

The complete CAS domain is:

```text
store_id, store_profile = deterministic_memory_v1, tenant_id,
partition_id, partition_digest,
writer_record_id, writer_record_revision, writer_record_digest,
status = active, process_instance_id, producer_principal_id,
writer_epoch = 1, fence_digest,
current_sequence/current_event_digest or genesis,
deployment_policy_revision = 1, backend_policy_revision = 1,
expires_at > recorded_at,
arena_generation, retained_count, retained_bytes
```

The mechanical root has only these fixed-capacity indexes and opaque values:

| Index | Exact key | Opaque retained value supplied by Event owner |
| --- | --- | --- |
| writer history | `(writer_record_id, writer_record_revision)` | canonical writer bytes and digest |
| current writer | `partition_id` | exact writer CAS tuple and history coordinate |
| command | complete command namespace | retained `C`, request digest, private `D`, fingerprint, Event ID, receipt ID, and arena charge |
| idempotency | complete process-local idempotency scope | exact command namespace and retained `C` coordinate |
| decision | `decision_key` | exact command namespace and retained `C` coordinate |
| event | `(partition_id, sequence)` | Event ID, Decision key, envelope digest, and canonical envelope bytes |
| event identity | `event_id` | exact event coordinate and Decision key |
| receipt | `receipt_id` | command namespace, Decision key, event coordinate, receipt digest, and canonical receipt bytes |

Index columns are mechanical assertions. Event owner decodes and validates them
against retained canonical bytes before any duplicate or inspection result.

## Physical Resource Contract

The deterministic memory profile has actual process-wide physical bounds, not
only logical-byte counters. At fresh creation it reserves these non-growable
pools; allocation failure is `resource_exhausted` and creates no writer:

| Resource | Exact ceiling |
| --- | ---: |
| Event Store arena, including canonical bytes and all indexes | 16,777,216 bytes |
| Eight owner parser/materialization scratch slots | 8 x 262,144 bytes |
| Event-owned heap total | 18,874,368 bytes |
| Event-owned stack per admitted call | 65,536 bytes |
| Event-owned stack across eight admitted calls | 524,288 bytes |
| Total accounted Event memory | 19,398,656 bytes |
| Event Stores/arenas per process | 1 |
| Outstanding sealed live handles | 8, each with one-second monotonic expiry |
| Concurrent admitted calls | 8 |
| Concurrent Store writers | 1 |
| Fresh partitions per Store | 1 |
| Committed appends per partition/Store | 256 |
| Retained canonical bytes inside the arena | 12,582,912 bytes |
| Calls per producer/partition per monotonic second | 64 |
| Calls per Store per monotonic second | 128 |

The one process Event owner rejects creation of a second Store/arena. Each live
handle retains one call/scratch reservation until append completion, explicit
drop, or expiry; expiry releases the slot but never reuses its UUIDs. After pool
creation, every Event-owned heap allocation, retained index, decoded record,
canonical buffer, fixture reconstruction, and Store image must draw from these
pools with no system-allocator fallback. Fixed-capacity index entries and arena
offsets replace independently growing maps/vectors. Checked reservation of the
complete next image happens before write. Instrumented allocator tests must prove
zero out-of-pool allocation after creation and exact ceiling/plus-one denial.
Stack use is bounded by non-recursive visitors at depth `16`; a test thread with
the stated stack ceiling must pass all maximum fixtures.

Every admitted call consumes one token from both token buckets before lookup.
Refill occurs only in complete monotonic seconds, never above capacity. Duplicate
and conflict calls cannot bypass volatile resource admission. Exact duplicates
consume no retained arena charge. Unknown swap disposition retains its reserved
arena region as unusable debt until process exit; it is never reclaimed for a
new append.

The owner records exact canonical lengths plus fixed index/image capacities in
the Store plan. Arena capacity, retained canonical-byte capacity, cardinality,
scratch, stack, rate, and checked integer ceilings are independent fail-closed
gates.

### SQLite and persistent storage blocker

No SQLite code slice is authorized. A future storage/resource annex must be
accepted before a real adapter or writable reopen can be implemented. It must at
minimum define and test:

- secure parent-directory and file ownership, creation mode, descriptor-relative
  opens, no symlink/hard-link traversal, inode/device/link-count validation, and
  path replacement behavior for database, WAL, and SHM files;
- exact SQLite build, VFS, locking, transaction, `PRAGMA` set/readback, page,
  journal, synchronization, checkpoint, and barrier operation/result contracts;
- conservative simultaneous physical database/WAL/SHM/temp/index/backup/
  checkpoint/recovery byte and file-descriptor admission, disk-full behavior,
  retained uncertainty debt, and global process/tenant ceilings;
- immutable backup, isolated restore, restore drill, owner/tenant/fence binding,
  valid-prefix anti-rollback authority, old-writer denial, and no second writer;
- exact commit-ambiguity reconciliation with executable operations and outcomes,
  or permanent non-writable intervention when disposition cannot be proved;
- bounded startup/recovery scans, resumable checkpoints, cancellation, trusted
  clocks, memory/CPU/deadline budgets, corrupt/missing history, and forward
  repair; and
- RFC 0020 N-1/N/N+1, rollback-read, migration, retention, redaction, and
  security/privacy evidence.

Until that annex is accepted, symbols such as `sqlite_wal_full_v1`,
`open_for_write`, `resume_writer`, `recover_commit`, `restore_and_activate`, or a
privileged durability receipt are stop violations for this profile.

## Failure and Non-Oracle Mapping

| Point or fault | Required result |
| --- | --- |
| Invalid raw historical fixture | RFC 0018 fixed grammar error; never enters live owner path. |
| Invalid/foreign/stale sealed handle or scope | Opaque `conflict`; zero Store mutation. |
| Volatile or retained resource ceiling | `resource_exhausted`; zero new visible record. |
| Concurrent exact command | One append; exact loser receives original process-local receipt as `duplicate`. |
| Concurrent changed command | At most one append; loser receives opaque `conflict`. |
| Mechanical failure proved before swap | `failed_no_append`; exact handle may retry while writer remains available. |
| Unknown swap disposition, panic, or cancellation crossing swap | `append_outcome_uncertain`; no receipt; writer unavailable for process lifetime. |
| Missing/corrupt retained C/D/envelope/writer/receipt/index | Opaque conflict plus unavailable latch; never a fresh miss. |
| Clock unavailable/rollback | `failed_no_append` latch; no time replacement. |
| Handle or writer expiry | Opaque `conflict`; writer expiry latches that class. |
| Process death | All write authority and memory results end; no reopen or recovery. |
| Detached fixture/replay corruption | Inspection failure only; never activation or repair. |

No public route is registered. To prevent a future adapter from improvising an
existence oracle, this annex fixes the minimum failure projection it would have
to adopt before separate transport acceptance:

| Internal failure class | HTTP status | Exact UTF-8 JSON body code |
| --- | ---: | --- |
| `rejected` | 400 | `event_append_invalid` |
| `conflict`, including all hidden/absent/wrong-scope/stale/fenced/substituted cases | 404 | `event_append_unavailable` |
| `resource_exhausted` | 429 | `event_append_resource_exhausted` |
| `failed_no_append` or `append_outcome_uncertain` | 503 | `event_append_unavailable` |

Each body is exactly `{"code":"<table-value>"}\n`. The response headers are
lowercase `content-type: application/json`, `cache-control: no-store`, the
computed exact `content-length`, and protocol-required `date`. `date` is generated
once per one-second response bucket before semantic evaluation and is identical
for all classes in that bucket. `server`, `retry-after`, `etag`, location, custom
IDs, and diagnostic headers are forbidden. Every failure class
uses the same preallocated serialization path and a release window of 20 through
40 milliseconds from receipt of the final bounded request byte, before any
authentication, scope, history, or currentness decision, measured by the trusted
monotonic clock. If an implementation cannot guarantee that closed window under
its declared concurrency ceiling, it must not enable the route. A missed window
closes the connection through the same path for every class and records only a
redacted local counter. Success/duplicate transport and receipt visibility
remain undefined and blocked, so this profile does not itself register HTTP
behavior.

The internal owner may distinguish the total outcomes for trusted composition;
it may not expose candidate bytes, sequence, cursor, epoch, digest, existence,
tenant activity, allocator state, path, source chain, or retry advice.

## Visibility, Privacy, and Diagnostics

Every partition, writer, envelope, receipt, private Decision, command binding,
and inspection fact is `restricted`. This annex exposes no range endpoint,
export, subscription, generic trace endpoint, conflict detail, or generated
client. Holding an ID, digest, record, or process-local receipt grants no read,
append, authority, durability, State, Evidence, C03, or effect permission.

The fixed payload cannot represent content. Raw credentials, tokens, private
keys, provider text, locators, approvals, leases, permits, protected-evaluation
identifiers, arbitrary metadata, chain-of-thought, payload refs, and
secret-derived digests are forbidden. Owner-issued live IDs/times close the
remaining variable-field smuggling path. Untrusted parser fixtures must use
synthetic public test values and remain redacted in failures, snapshots, logs,
metrics, and diffs.

Owner diagnostics are closed counters by static class only. They contain no
record, field path, nested source, UUID, timestamp, digest, canonical bytes,
tenant/run/principal, Store offset, memory address, or operating-system data.
Tests format every new public/private type and every failure branch with planted
secret sentinels and require no sentinel or canonical fragment to appear.

## Bounded Inspection and Replay

There is no startup activation or recovery scan. During the same process,
private inspection may read a caller-specified exact coordinate range from the
current owner. Detached canonical fixtures may be inspected by the same pure
validators but can never create a live handle.

One inspection call is bounded by all of:

| Budget | Exact ceiling |
| --- | ---: |
| Records | 64 |
| Canonical bytes examined | 4,194,304 |
| Work units (`bytes + 1,024 * records`) | 4,259,840 |
| Scratch memory | one 262,144-byte reserved slot |
| Wall deadline | 100 milliseconds from entry |
| Cancellation polling | before each record and every 65,536 examined bytes |

The owner captures one high-water coordinate at call start. It validates exact
sequence, prior digest, command namespace, `C`, private `D`, Decision key/
fingerprint, envelope, writer revision, receipt, and arena charge in order. A
page cannot skip a coordinate or claim partition completeness unless it reaches
the captured high-water. Budget exhaustion, cancellation, unavailable/rolled
back monotonic clock, deadline, missing row, or corrupt row returns no complete
page claim and performs zero mutation. Pagination requires the exact next
coordinate and prior digest returned in a sealed inspection cursor; cursors are
process-bound, expire after 1 second, and are never authority or write handles.

Inspection never opens a write transaction, appends, repairs, latches a new
writer, reconciles uncertainty, allocates owner IDs/times, invokes Gateway,
adapter, provider, network, filesystem, State, Evidence, outbox, inbox, or status
operation, or turns history into currentness/durability.

## Stable 0.1 Compatibility

This proposal is `storage`, `behavioral`, and `security_critical` under RFC 0020
because it fixes new owner bytes, hash/key projections, duplicate/error meaning,
and restricted receipt handling. It is not a transport change or an implemented
persistent-storage migration. The newly specified canonical records may be
retained only in the bounded process-local adapter or fixtures until another
accepted annex defines persistent storage.

Stable `TraceEvent`, `TraceEventKind`, `TraceEventId::from_run_sequence`, event
sequence, timestamp, identity context, payload, hash, export, required tick
order, and inspect-only replay remain byte-for-byte under their existing
contracts. There is no `TraceEvent`/`owner_record_v1` conversion in either
direction:

```text
decide_event_conversion(source_schema, source_bytes, target_schema)
  -> unsupported
```

| Source | New parser/live owner | Stable 0.1 Trace consumer |
| --- | --- | --- |
| Exact `owner_record_v1` grammar | Parser may validate untrusted bytes; live use still requires owner-issued handle | No adapter; conversion is `unsupported` |
| Stable 0.1 `TraceEvent` | Reject for live append; existing legacy reader may inspect in place | Existing stable behavior unchanged |
| Unknown/N+1 owner record | Reject; no opaque live retention | No conversion or downgrade |

No N-1 schema exists for `owner_record_v1`. Its complete direct version matrix
is:

| Source role | N-1 consumer | N consumer | N+1 consumer |
| --- | --- | --- | --- |
| N-1 (nonexistent) | No parser or live value exists | `reject_fail_closed`; no adapter exists | No current contract can authorize it |
| N (`owner_record_v1`) | Reject live use and downgrade | Parse exact N as untrusted grammar; live admission still requires a sealed owner handle | Future consumer may accept only through its own accepted direct matrix |
| N+1/unknown | Reject; no opaque archive is registered | Reject without dropping/defaulting unknowns | Outside this RFC |

| Operation at the N boundary | Exact disposition |
| --- | --- |
| Parse/validate | Only exact N uses the bounded parser and complete digest/binding checks. |
| Live admission | Parser output is never live; only the process owner can issue the sealed handle. |
| Canonical output | Exact N emits only registered JCS bytes; no alias output exists. |
| Inspect/replay | Exact N process bytes or detached fixtures may use bounded inspection; neither becomes writable/current. |
| Downgrade/conversion | Always typed `unsupported`; no field dropping, defaulting, or identity reminting. |
| Rollback-read | Keep the exact pure N parser/validators; no writer activation follows. |
| Generated parity | No generated surface is authorized. |
| Storage | One process-local memory adapter only; no reopen, import, backup, restore, or persistent migration. |
| Transport | No transport is registered; the failure profile is only a mandatory gate for a future annex. |

`decide_event_conversion` returns typed `unsupported` for every source/target
pair. Parsing exact N under its own parser is identity validation, not conversion.

The stable `InstanceId` contract is preserved exactly. It identifies one running
process and is never described as durable or reused after restart. This annex
adds no durable writer/deployment-slot identity. If a future persistent writer
needs such an identity, it requires a distinct nominal type, compatibility
matrix, ownership law, and accepted RFC; it must not reinterpret `InstanceId`.

Rollback of an implementation means stop using the process-local owner and keep
stable 0.1 behavior unchanged. No old/new dual write, cutover, import-as-live,
backup activation, or writer reactivation exists.

## Sequenced Implementation Plan

Each slice is a separate PR after acceptance. Passing one slice does not
authorize the next or change any Gold status.

### Slice 1 - Behavior-free Event grammar

Implement in `splendor-types` only:

- the new IDs, digest types, closed enums, fixed payload, six records, bounded
  parsers, checked constructors, JCS bytes, exact `C`, digest projections, and
  unsupported conversion function;
- exact member/cardinality fixtures: request `79`, envelope `37`, receipt `42`,
  retained `C` `78`, and no public/private `D` type in this crate; and
- no allocation, clock read, live handle, current writer selection, private `D`,
  duplicate/conflict logic, Store, kernel, daemon, SDK, generated output, or I/O.

Required tests include canonical positive fixtures; every malformed/unknown/
duplicate/null/alias member; every ID/digest substitution; every `C` and digest
projection mutation; command-family omission/change at every dependent site;
all graph-cycle classes; exact bounds and plus one; redacted formatting with
sentinels; and unchanged stable 0.1 fixtures.

### Slice 2 - Event owner and deterministic memory Store

Implement:

- sealed handle issuance, private `D`, total outcome mapping, duplicate/conflict
  interpretation, volatile unavailable latch, and bounded inspection in
  `splendor-evidence::event`;
- only the mechanical fixed-arena transaction adapter and fault observations in
  `splendor-store`;
- exact process `InstanceId` binding and no reopen/restart API; and
- no kernel, daemon, SDK, transport, SQLite, filesystem, or privileged receipt.

Required tests include first append/exact duplicate; changed command/key;
wrong-scope/stale/fence/process/currentness conflicts; owner-issued ID/time
provenance; secret sentinel rejection/redaction; one-winner concurrency; every
total outcome and precedence overlap; exact rate/cardinality/arena/scratch/stack/
work/deadline ceiling and plus one; zero post-creation allocator fallback; fault
before/at/after swap; unknown outcome permanently withholding success; absence of
terminal transitions and reopen/recovery symbols; bounded cancellation/clock
rollback; and inspection with zero mutation/effects.

### Blocked future storage work

Real SQLite, writable restart, durable receipts, backup/restore, ambiguity
reconciliation, anti-rollback, forward repair, and kernel composition are not a
third slice of this RFC. They require the separately accepted annex and complete
evidence listed in the SQLite blocker section. Implementing any of them from this
proposal is a stop violation.

## No-Go Review

Implementation must stop if any of these becomes true:

- exact `command_family` is absent or differs in request, `C`, private `D`,
  envelope, receipt, namespace, idempotency projection, fixture, or dependent
  digest;
- `EventAppendOutcomeV1` omits `resource_exhausted`, has a wildcard, or maps
  overlapping failures outside the fixed precedence;
- `closed`, `quarantined`, terminal transition, reactivation, or persistent
  lifecycle state is added;
- unknown mutation disposition can yield a receipt, retry, writable recovery,
  or later trusted success;
- `InstanceId` is reused or redefined as a durable deployment/writer identity;
- retained bytes, a valid prefix, copy, backup, restore, or fixture can reopen a
  writer;
- a producer can choose live new-schema UUID/timestamp bytes or bypass the sealed
  provenance handle;
- physical memory/resource bounds are replaced by logical bytes alone, pools can
  grow/fallback, or SQLite appears before its accepted annex;
- private `D`, duplicate/conflict/uncertainty decisions, or receipt trust moves
  into `splendor-types`, Store, kernel, daemon, SDK, or a test fake;
- hidden/absent/wrong-scope/stale/fenced/substituted cases vary in body, headers,
  timing class, diagnostics, or existence detail;
- retained `C`/`D` or inspection lacks exact decode, memory, work, deadline,
  cancellation, and clock bounds;
- formatting, errors, logs, metrics, fixtures, or nested sources expose a
  sensitive field, path, offset, canonical fragment, or planted sentinel;
- SQLite path/link/permission, PRAGMA/VFS, physical capacity, backup/restore,
  anti-rollback, ambiguity, or forward-repair requirements are treated as
  implemented by this RFC;
- stable 0.1 bytes/types/order change, conversion is inferred, or old/new stores
  dual-write/cut over; or
- replay/inspection writes, repairs, reconciles, activates, or calls a live
  effect path.

## Review Correction Matrix

| Rejected-head finding | Binding correction in this proposal |
| --- | --- |
| Command family outside `C` | Exact field now appears in request, `C`, private `D`, envelope, receipt, namespace, idempotency digest, counts, graph, and tests. |
| Outcome omitted resource exhaustion | Total outcome and ordered mapping include `resource_exhausted` at volatile and retained admission. |
| Unreachable terminal statuses | Writer enum admits only `active`; no persistent terminal transition exists. |
| Vague ambiguous SQLite recovery | SQLite is blocked; unknown memory swap never yields success and permanently disables writes for the process. |
| Durable reinterpretation of `InstanceId` | Writer binds the current random process identity; no reopen/reuse or durable slot is claimed. |
| Valid-prefix rollback | No historical bytes can activate; every new process starts unrelated fresh volatile state. |
| UUID/timestamp smuggling | Event owner issues every new live ID/time through a sealed provenance-bound handle; parsers are grammar-only. |
| Logical-only SQLite capacity | Process memory uses fixed non-growable arena/scratch/stack/cardinality bounds; real SQLite requires a separate physical-resource annex. |
| Semantic logic in types/Store | Private `D` and every semantic outcome remain in `splendor-evidence::event`; types are pure and Store is mechanical. |
| Error oracle and incomplete precedence | One total precedence plus fixed opaque status/body/header/timing eligibility profile is specified. |
| Incomplete RFC 0020 storage dossier | Real storage is explicitly gated on path/link/permission, PRAGMA/VFS, capacity, backup/restore, anti-rollback, repair, and migration evidence. |
| Unbounded retained decode/replay | Exact C/D parser and inspection byte/member/work/memory/deadline/cancellation/clock limits are fixed. |
| Diagnostic leakage | All new public/private values and Store/owner faults have redacted formatting and sentinel tests. |

## Validation and Gold Status

Proposal review must verify:

- every record has one exhaustive field table, exact parser budget, canonical
  rule, digest row, and mechanically checked member count;
- exact `command_family` propagation and all dependent mutations are tested;
- no contradictory SQLite, writable restart, terminal writer, recovery-success,
  durable `InstanceId`, or production receipt claim remains;
- Markdown headings/fences/tables/relative links, `git diff --check`, dependency
  policy self/current checks, stable conformance, and
  `cargo fmt --all -- --check` remain clean; and
- no repository file other than this RFC changes in the proposal commit.

Acceptance or static validation registers only this bounded proposal. It does
not execute `G00`, `G02`, `G03`, or `G08`; all remain
`specified_not_implemented` / `not_exercised`. The contentless memory-only path
does not prove Secret Broker operation, State/Event atomicity, durable Event
storage, stable Trace migration, public replay, or production conformance.

## Acceptance Effect

If independently accepted, this RFC clears RFC 0018 grammar reservations and the
RFC 0019 owner-annex gate only for Slice 1 and Slice 2 exactly as bounded above.
It authorizes no SQLite or writable-restart implementation.

Acceptance alone changes no behavior, accepts no implementation, closes no task
or issue, enables no C03 path, and changes no compatibility, conformance, Gold,
or release status. Any broader payload, persistent Store, stable Trace writer
migration, State/Evidence composition, external effect, public API, or
transferable writer requires its own accepted contract and evidence.
