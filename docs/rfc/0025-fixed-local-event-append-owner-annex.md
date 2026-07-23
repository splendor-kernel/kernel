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

**Persistence owner:** `splendor-store`, limited to owner-approved transaction,
uniqueness, compare-and-swap, integrity, durability, and recovery mechanics

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

This annex registers the smallest Event-owner contract that can exercise one
truthful local append transaction:

- one new local SQLite database created for this profile;
- one fresh `agent_run` partition that has never had another writer;
- one fixed, non-transferable local writer at epoch `1`;
- one `owner_record_v1` Event profile;
- one exact typed, contentless `foundation.no_effect` inline payload;
- one append per command, with no batch, outbox, inbox, external effect,
  adapter, driver, State mutation, or Evidence mutation;
- one owner-materialized envelope and immutable receipt;
- permanent command and idempotency history;
- expected sequence, previous digest, writer-record revision, epoch, and fence
  compare-and-swap in one SQLite transaction; and
- inspect-only owner replay with no live write or effect.

"No external effect" means no adapter, provider, network, external filesystem,
device, database, message transport, State head, or another semantic owner is
invoked. The Event owner's own local SQLite persistence is the bounded mutation
being specified; it is not an Action Gateway bypass or an external operation
`O` under RFC 0019.

This annex deliberately does not make arbitrary JSON, generic maps, stable
`TraceEvent`, C03 records, secrets, owner references, or Artifact references
valid payloads. The fixed payload proves owner ordering and durability without
creating a data-smuggling surface. A useful service event kind needs its own
accepted typed payload annex before admission.

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
- a batch append, source outbox, destination inbox, publication command,
  acknowledgement, subscription, cursor platform, retention, compaction, or
  remote transport;
- an external-effect decision, operation `O`, operation idempotency key,
  dispatch attempt, Gateway permit, dispatch claim, entry-consumption latch,
  effect certainty, partial inventory, compensation, or status lookup;
- writer renewal, rotation, transfer, higher epoch, handoff, import-as-live,
  cutover, rollback, or second writer before `EVT-002`;
- live migration or dual write from an existing 0.1 Trace/State database;
- a daemon, SDK, CLI, Python, TypeScript, JSON Schema, or OpenAPI surface;
- a broad producer migration or a public conflict-detail/read API; or
- completion of `FND-003`, `EVT-001`, C03, a Gold case, conformance, or
  production readiness.

The RFC 0015 batch, outbox, inbox, publication, coordinate, and public recovery
families remain unregistered. They cannot be approximated with a one-item batch,
private table DTO, generic string reference, or `serde_json::Value`.

## Ownership and Package Direction

| Layer | Exact responsibility in this slice | Forbidden responsibility |
| --- | --- | --- |
| `splendor-types` | Behavior-free nominal IDs/digests, closed records, bounded parsers, checked constructors, JCS serialization, and pure digest/derivation helpers | Allocation, clock reads, current writer selection, append decisions, SQLite, replay execution, or authority |
| `splendor-evidence::event` | Authenticate the internal caller facts supplied by composition, own partition/writer legality, construct `C` and `D`, assign owner fields, select durability, materialize envelope/receipt, interpret Store outcomes, quarantine, and expose sealed trusted receipt handles | Provider behavior, another owner's state, public transport, or arbitrary payload registration |
| `splendor-store` | Persist already owner-approved bytes, enforce unique indexes and exact CAS predicates, supply one real transaction, execute SQLite durability mechanics, and support exact lookup/recovery | Schema/authority/policy decisions, latest-sequence rebasing, retry decisions, record construction, or receipt trust |
| `splendor-kernel` | Compose one internal fresh-local no-effect path and preserve existing 0.1 facades unchanged | Event mutation ownership, independent trace write, State coupling, daemon business logic, or dual write |
| Replay/inspection | Read immutable owner records through an Event-owner read port in tests and restricted local operation | Append, reconcile, quarantine, claim work, refresh currentness, or emit a live event |

The Store API accepts an owner-prepared append plan plus exact CAS inputs. It
does not accept a caller-built trusted receipt or decide whether a request is a
duplicate, legal, current, visible, or safe. `TraceStore::append`, its current
payload hash, and daemon in-memory composition are compatibility inputs only and
cannot implement this owner contract.

## Common Wire and API Rules

All new records inherit RFC 0018 exactly:

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
The RFC 0018 error precedence and nine outward codes are unchanged. All record,
digest, and receipt `Debug` output is the type name plus `<redacted>`; canonical
wire access is explicit.

Nested values are parsed only through their parent record's bounded visitor or a
private fixture parser. They do not create alternate public ingress paths.

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

This annex additionally registers `CombinedLocalStoreId` solely as the nominal
identity of the fresh SQLite database bound by the Event writer. It is not a
generic Store registry, State identity, Evidence identity, or authority value.

Every ID is a distinct newtype over one non-nil UUID with RFC 0018's exact wire
and API restrictions. `splendor-types` provides no `Default`, random `new`,
unchecked `From<Uuid>`, cross-type conversion, or generic ID wrapper.

Allocation rules are exact:

- the local composition root asks the Event owner to allocate
  `CombinedLocalStoreId`, `EventPartitionId`, and
  `FixedLocalEventWriterRecordId` before fresh-store creation;
- an authenticated producer supplies independently allocated
  `EventAppendCommandId` and `EventAppendIdempotencyKey`; neither may be derived
  from `C` or any digest;
- Event owner derives `EventId` and `EventAppendReceiptId` from the accepted
  RFC 0019 `DecisionKey`; and
- coincident UUID bytes across any two nominal types are rejected for one
  request even though the Rust types already prevent substitution.

The exact deterministic owner derivations are:

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

The RFC 4122/RFC 9562 UUIDv5 byte construction is used with UUID network bytes.
These values are owner outputs, not caller-selected assertions.

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

`EventAppendRequestDigest` is the RFC 0019 command semantic digest for this
owner. `EventAppendDecisionKeyDigest` and
`EventAppendDecisionFingerprintDigest` are owner-nominal representations of the
RFC 0019 internal roles. Nominal equality does not cross digest families.

### Enums and fixed constants

| Rust type or field | Exact accepted value in this slice |
| --- | --- |
| `EventProfileV1` | `owner_record_v1` |
| `EventPartitionKindV1` | `agent_run` |
| `EventDurabilityClassV1` | `required_after_effect` |
| `DurabilityLevelV1` | `memory_only`, `transaction_committed`, `storage_barrier_confirmed`; record-specific floors below further restrict use |
| `FixedLocalEventWriterStatusV1` | `active`, `quarantined`, `closed` |
| `FixedLocalEventStoreProfileV1` | `deterministic_memory_v1`, `sqlite_wal_full_v1` |
| `VisibilityClassV1` | record value is exactly `restricted` |
| `EventLogicalRoleV1` | `logical_owner_event` |
| `EventAppendDecisionDispositionV1` | `append` |
| `EventAttemptDispositionV1` | `no_attempt` |
| `EventDispatchFenceDispositionV1` | `no_dispatch_fence` |
| `owner_component` | `splendor.event-log` |
| `owner_audience` | `splendor.event-log` |
| `kind_schema` | `splendor.event.foundation_no_effect.v1` |
| `kind` | `foundation.no_effect` |

`trace_event_compatibility_v0_1` remains a valid RFC 0018 enum spelling but is
not admitted by any new record in this annex. Unknown and future values reject;
there is no `other` or fallback.

### Fixed nested values

`FoundationNoEffectEventPayloadV1` has exact canonical JSON:

```json
{"schema_version":"splendor.event.foundation_no_effect.v1"}
```

It has no optional members, content field, extensions, map, reference, bytes, or
text. It cannot carry a secret, credential, protected payload, authority,
business fact, provider result, C03 value, or private reasoning.

`ExpectedEventBaseV1` is one closed internally tagged union:

```json
{"kind":"genesis"}
```

or:

```json
{"event_digest":"blake3:<64-lowercase-hex>","kind":"previous","sequence":0}
```

The `previous` form uses `EventEnvelopeDigest` and `CanonicalSequenceV1`.
`genesis` is required exactly when `expected_next_sequence == 0`.
`previous` is required exactly when `expected_next_sequence > 0`, and its
`sequence` must equal `expected_next_sequence - 1`. Null or mixed forms reject.

Four distinct zero-sized collection wrappers serialize only as `[]`:

```text
EmptyEventCausalParentsV1
EmptyEventCorrelationRefsV1
EmptyEventCommandCausalRefsV1
EmptyEventAuditRefsV1
```

They have no element constructor, insertion API, generic `Vec<T>` conversion,
or non-empty parser result. Their nominal separation prevents an empty
collection accepted for one role from being substituted for another.

## Exact Record Tables

Every table is exhaustive. "Forbidden" means the member must be absent; null
never represents absence. Field order in source is immaterial after duplicate
rejection, while canonical output uses JCS member order.

### `EventPartitionV1`

Schema: `splendor.event.partition.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `descriptor_digest` | `EventPartitionDigest` | Required; recomputed from the projection below. |
| `descriptor_revision` | `CanonicalPositiveRevisionV1` | Required and exactly `1`. This slice has no descriptor mutation. |
| `owner_audience` | `CanonicalLabelV1` | Required exact constant `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact constant `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required, canonical, non-nil, and different from every differently typed ID. |
| `partition_id` | `EventPartitionId` | Required; allocated by Event owner before creation. |
| `partition_kind` | `EventPartitionKindV1` | Required exact `agent_run`. |
| `producer_principal_id` | existing `PrincipalId` | Required; exact producer allowed for this fixed partition. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `run_id` | existing `RunId` | Required canonical non-nil run scope. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `tenant_id` | existing `TenantId` | Required canonical non-nil tenant scope. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |

The partition descriptor is immutable. `partition_id`, tenant, run, producer,
owner, kind, profile, visibility, and revision cannot be inferred from a latest
row or changed after creation.

### `EventAppendIntentV1`

Schema: `splendor.event.append_intent.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `audit_principal_id` | existing `PrincipalId` | Required; equals the authenticated producer for this internal slice. It is attribution, not authority. |
| `audit_requested_at` | `CanonicalTimestampV1` | Required; equals `occurred_at` in this fixed profile and is audit correlation, not trusted owner time. |
| `causal_parents` | `EmptyEventCausalParentsV1` | Required exact empty array. Event-coordinate parents remain blocked. |
| `command_id` | `EventAppendCommandId` | Required; equals the enclosing request command. |
| `correlation_refs` | `EmptyEventCorrelationRefsV1` | Required exact empty array. Generic references are forbidden. |
| `idempotency_key` | `EventAppendIdempotencyKey` | Required; independently allocated before `C`. |
| `kind` | `CanonicalLabelV1` | Required exact `foundation.no_effect`. |
| `kind_schema` | `CanonicalSchemaIdV1` | Required exact `splendor.event.foundation_no_effect.v1`. |
| `occurred_at` | `CanonicalTimestampV1` | Required producer observation time. It is not currentness or owner commit time. |
| `partition_id` | `EventPartitionId` | Required; equals the enclosing partition. |
| `payload` | `FoundationNoEffectEventPayloadV1` | Required exact one-member object above. A payload reference is forbidden. |
| `producer_principal_id` | existing `PrincipalId` | Required; equals partition producer and authenticated producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `requested_durability` | `DurabilityLevelV1` | Required caller floor. It may tighten but never lower trusted floors. |
| `run_id` | existing `RunId` | Required; equals partition run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `tenant_id` | existing `TenantId` | Required; equals partition tenant. |

Producer event ID, producer sequence, recorded time, writer values, visibility,
integrity, effective/achieved durability, owner revision, receipt, and any
external-effect value are forbidden. The owner computes `EventIntentDigest` over
the complete canonical intent.

### `FixedLocalEventWriterRecordV1`

Schema: `splendor.event.fixed_local_writer_record.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `backend_policy_revision` | `CanonicalPositiveRevisionV1` | Required; exact configured SQLite or deterministic-test backend policy revision. |
| `created_at` | `CanonicalTimestampV1` | Required owner time from fresh creation. |
| `current_event_digest` | `EventEnvelopeDigest` | Absent at genesis; required with `current_sequence`. |
| `current_sequence` | `CanonicalSequenceV1` | Absent at genesis; required after the first append. |
| `deployment_durability_floor` | `DurabilityLevelV1` | Required trusted deployment floor. SQLite production value is `storage_barrier_confirmed`. |
| `deployment_policy_revision` | `CanonicalPositiveRevisionV1` | Required trusted policy revision. |
| `expires_at` | `CanonicalTimestampV1` | Required, strictly after `created_at` by `1..=86,400` seconds; immutable and non-renewable. |
| `fence_digest` | `EventWriterFenceDigest` | Required owner-derived fixed fence. |
| `last_recorded_at` | `CanonicalTimestampV1` | Absent at genesis; required after first append and equals the current envelope `recorded_at`. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required; equals partition owner. |
| `owner_profile_durability_floor` | `DurabilityLevelV1` | Required `transaction_committed` for SQLite production; exact `memory_only` for the deterministic test profile. |
| `partition_id` | `EventPartitionId` | Required; equals partition. |
| `prior_event_digest` | `EventEnvelopeDigest` | Absent at genesis and after sequence `0`; required after sequence `1` or later. |
| `prior_sequence` | `CanonicalSequenceV1` | Absent at genesis and after sequence `0`; otherwise exactly `current_sequence - 1`. |
| `process_instance_id` | existing `InstanceId` | Required durable runtime-instance identity, not an OS PID or per-start random value. |
| `producer_principal_id` | existing `PrincipalId` | Required; equals partition producer. |
| `run_id` | existing `RunId` | Required; equals partition run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `status` | `FixedLocalEventWriterStatusV1` | Required. Append requires `active`; `quarantined` and `closed` are terminal. |
| `store_id` | `CombinedLocalStoreId` | Required; equals the database metadata identity. |
| `store_profile` | `FixedLocalEventStoreProfileV1` | Required; production is `sqlite_wal_full_v1`, deterministic tests use `deterministic_memory_v1`. |
| `tenant_id` | existing `TenantId` | Required; equals partition tenant and store tenant. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required and exactly `1`. |
| `writer_record_digest` | `EventWriterRecordDigest` | Required; recomputed over every other member. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required; allocated by Event owner before creation. |
| `writer_record_revision` | `CanonicalPositiveRevisionV1` | Required; starts at `1` and increments by exactly one per append or terminal status transition. |

For an append at sequence `s`, the next writer record moves the old
`current_sequence/current_event_digest` into `prior_*`, writes `s` and the new
envelope digest into `current_*`, sets `last_recorded_at`, and increments the
record revision. Checked arithmetic failure denies before mutation.

For every accepted append, owner time and producer time satisfy:

```text
created_at <= occurred_at <= recorded_at < expires_at
last_recorded_at <= recorded_at          (when last_recorded_at is present)
```

The owner does not rewrite or round producer time. A violation rejects before
mutation. Equal owner timestamps are allowed because partition sequence, not
wall time, defines order.

### `EventAppendRequestV1`

Schema: `splendor.event.append_request.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `audit_refs` | `EmptyEventAuditRefsV1` | Required exact empty array. Audit attribution is the typed principal in the intent. |
| `causal_refs` | `EmptyEventCommandCausalRefsV1` | Required exact empty array. |
| `command_id` | `EventAppendCommandId` | Required; equals `intent.command_id`. |
| `expected_base` | `ExpectedEventBaseV1` | Required; exact genesis/previous condition above. |
| `expected_next_sequence` | `CanonicalSequenceV1` | Required expected CAS value; zero means genesis. |
| `idempotency_key` | `EventAppendIdempotencyKey` | Required; equals `intent.idempotency_key`. |
| `idempotency_key_digest` | `EventAppendIdempotencyKeyDigest` | Required; owner recomputes before lookup. |
| `intent` | `EventAppendIntentV1` | Required complete intent. |
| `intent_digest` | `EventIntentDigest` | Required; owner recomputes from `intent`. |
| `partition` | `EventPartitionV1` | Required complete immutable partition assertion. |
| `partition_digest` | `EventPartitionDigest` | Required; equals `partition.descriptor_digest`. |
| `request_digest` | `EventAppendRequestDigest` | Required; owner recomputes from `C`, which excludes this member. |
| `requested_durability` | `DurabilityLevelV1` | Required; equals `intent.requested_durability`. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `writer_record` | `FixedLocalEventWriterRecordV1` | Required complete current writer assertion. It is untrusted until owner lookup and CAS. |
| `writer_record_digest` | `EventWriterRecordDigest` | Required; equals `writer_record.writer_record_digest`. |

Event ID, receipt ID, recorded time, effective or achieved durability, owner
revision, new writer revision, current envelope digest, Decision key/fingerprint,
operation bytes/key, and any adapter/effect field are forbidden.

Request construction also enforces all of these equalities before lookup:

- command ID, idempotency key, requested durability, partition ID, tenant, run,
  and producer agree across request, intent, partition, and writer record;
- owner principal/audience/component, profile, and visibility agree across
  partition and writer record;
- partition, intent, idempotency-key, writer-record, and request digests
  independently recompute;
- genesis requires absent writer current/prior cursor and integrity plus
  `expected_next_sequence == 0`;
- non-genesis requires expected-base sequence/digest equal to writer current and
  `expected_next_sequence == current_sequence + 1`; and
- the request's writer status may parse as a historical value, but only `active`
  is append-admissible.

Any mismatch is `invalid_contract_binding` before Store mutation. The owner still
revalidates the asserted current writer bytes against durable current state in
the committing CAS.

### `EventEnvelopeV1`

Schema: `splendor.event.envelope.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `causal_parents` | `EmptyEventCausalParentsV1` | Required exact empty array, copied from intent. |
| `command_id` | `EventAppendCommandId` | Required exact accepted command. |
| `correlation_refs` | `EmptyEventCorrelationRefsV1` | Required exact empty array, copied from intent. |
| `decision_fingerprint` | `EventAppendDecisionFingerprintDigest` | Required exact RFC 0019 derivation. |
| `decision_key` | `EventAppendDecisionKeyDigest` | Required exact RFC 0019 derivation. |
| `durability_class` | `EventDurabilityClassV1` | Required exact `required_after_effect`. This names the owner-commit gate despite there being no external effect. |
| `effective_durability_floor` | `DurabilityLevelV1` | Required strictest configured floor. |
| `event_digest` | `EventEnvelopeDigest` | Required; recomputed over every other envelope member. |
| `event_id` | `EventId` | Required owner derivation from `DecisionKey`. |
| `intent_digest` | `EventIntentDigest` | Required exact admitted intent digest. |
| `kind` | `CanonicalLabelV1` | Required exact `foundation.no_effect`. |
| `kind_schema` | `CanonicalSchemaIdV1` | Required exact fixed payload schema. |
| `logical_event_role` | `EventLogicalRoleV1` | Required exact `logical_owner_event`. |
| `occurred_at` | `CanonicalTimestampV1` | Required exact intent occurrence time. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required exact partition/writer owner. |
| `owner_revision` | `CanonicalPositiveRevisionV1` | Required and equal to the post-append writer-record revision. |
| `partition_digest` | `EventPartitionDigest` | Required exact partition descriptor digest. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `payload` | `FoundationNoEffectEventPayloadV1` | Required exact fixed payload. |
| `previous_event_digest` | `EventEnvelopeDigest` | Absent at sequence `0`; required at sequence greater than `0` and equal to expected/current prior digest. |
| `producer_principal_id` | existing `PrincipalId` | Required exact authenticated producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `recorded_at` | `CanonicalTimestampV1` | Required Event-owner time sampled inside the append transaction. |
| `request_digest` | `EventAppendRequestDigest` | Required exact command semantic digest. |
| `run_id` | existing `RunId` | Required exact partition run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `sequence` | `CanonicalSequenceV1` | Required exact accepted `expected_next_sequence`. |
| `tenant_id` | existing `TenantId` | Required exact partition tenant. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `writer_fence_digest` | `EventWriterFenceDigest` | Required exact current writer fence. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required exact current writer record. |
| `writer_record_revision_before` | `CanonicalPositiveRevisionV1` | Required exact pre-append writer-record revision. |

An envelope contains no receipt, updated writer-record digest, downstream
acknowledgement, publication finalization, or own-digest input. Those exclusions
keep the graph acyclic.

### `EventAppendReceiptV1`

Schema: `splendor.event.append_receipt.v1`

Budget: `small_record_v1`

| JSON member | Nominal Rust type | Presence and validation |
| --- | --- | --- |
| `achieved_durability` | `DurabilityLevelV1` | Required and at least the effective floor. Production is `storage_barrier_confirmed`. |
| `attempt_disposition` | `EventAttemptDispositionV1` | Required exact `no_attempt`. |
| `backend_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact writer/backend policy revision. |
| `caller_durability_floor` | `DurabilityLevelV1` | Required exact request floor. |
| `command_id` | `EventAppendCommandId` | Required exact accepted command. |
| `committed_at` | `CanonicalTimestampV1` | Required and exactly equal to envelope `recorded_at`. |
| `decision_fingerprint` | `EventAppendDecisionFingerprintDigest` | Required exact Decision fingerprint. |
| `decision_key` | `EventAppendDecisionKeyDigest` | Required exact Decision key. |
| `deployment_durability_floor` | `DurabilityLevelV1` | Required exact trusted deployment floor. |
| `deployment_policy_revision` | `CanonicalPositiveRevisionV1` | Required exact trusted deployment policy revision used by `D`. |
| `dispatch_fence_disposition` | `EventDispatchFenceDispositionV1` | Required exact `no_dispatch_fence`. |
| `durability_class` | `EventDurabilityClassV1` | Required exact `required_after_effect`. |
| `effective_durability_floor` | `DurabilityLevelV1` | Required maximum of the three floors. |
| `event_digest` | `EventEnvelopeDigest` | Required exact committed envelope digest. |
| `event_id` | `EventId` | Required exact committed event ID. |
| `idempotency_key_digest` | `EventAppendIdempotencyKeyDigest` | Required exact permanent key digest. |
| `intent_digest` | `EventIntentDigest` | Required exact admitted intent digest. |
| `owner_audience` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_component` | `CanonicalLabelV1` | Required exact `splendor.event-log`. |
| `owner_principal_id` | existing `PrincipalId` | Required exact Event owner. |
| `owner_profile_durability_floor` | `DurabilityLevelV1` | Required exact trusted profile floor. |
| `owner_revision` | `CanonicalPositiveRevisionV1` | Required exact post-append writer/owner revision. |
| `partition_digest` | `EventPartitionDigest` | Required exact partition descriptor digest. |
| `partition_id` | `EventPartitionId` | Required exact partition. |
| `previous_event_digest` | `EventEnvelopeDigest` | Absent at sequence `0`; required otherwise. |
| `producer_principal_id` | existing `PrincipalId` | Required exact producer. |
| `profile` | `EventProfileV1` | Required exact `owner_record_v1`. |
| `receipt_digest` | `EventAppendReceiptDigest` | Required; recomputed over every other receipt member. |
| `receipt_id` | `EventAppendReceiptId` | Required owner derivation from `DecisionKey`. |
| `request_digest` | `EventAppendRequestDigest` | Required exact command semantic digest. |
| `run_id` | existing `RunId` | Required exact run. |
| `schema_version` | `CanonicalSchemaIdV1` | Required exact schema constant. |
| `sequence` | `CanonicalSequenceV1` | Required exact committed sequence. |
| `tenant_id` | existing `TenantId` | Required exact tenant. |
| `visibility` | `VisibilityClassV1` | Required exact `restricted`. |
| `writer_epoch` | `CanonicalPositiveRevisionV1` | Required exact `1`. |
| `writer_fence_digest` | `EventWriterFenceDigest` | Required exact writer fence. |
| `writer_record_digest_after` | `EventWriterRecordDigest` | Required exact updated writer record digest. |
| `writer_record_id` | `FixedLocalEventWriterRecordId` | Required exact writer identity. |
| `writer_record_revision_after` | `CanonicalPositiveRevisionV1` | Required and exactly one greater than `writer_record_revision_before`. |
| `writer_record_revision_before` | `CanonicalPositiveRevisionV1` | Required exact request revision. |

Attempt identity, invocation progress, recovery/dispatch fence, claimant,
dispatch claim, entry consumption, cancellation, operation key, effect certainty,
partial inventory, State head, Artifact, Evidence, outbox, inbox, and
acknowledgement fields are forbidden. The receipt proves only this Event owner
commit at its declared durability.

## Parser and Budget Manifest

All six records use `small_record_v1`: raw bytes `65,536`, depth `16`, tokens
`4,096`, members `1,024`, elements `1,024`, one decoded string `1,024`, and
canonical output `65,536`. Record-specific lower canonical ceilings are also
enforced:

| Record | Maximum depth | Maximum total members including nested records | Maximum array elements | Record-specific canonical ceiling |
| --- | ---: | ---: | ---: | ---: |
| `EventPartitionV1` | 1 | 13 | 0 | 2,048 bytes |
| `EventAppendIntentV1` | 2 | 18 | 0 | 4,096 bytes |
| `FixedLocalEventWriterRecordV1` | 1 | 28 | 0 | 4,096 bytes |
| `EventAppendRequestV1` | 3 | 78 | 0 | 16,384 bytes |
| `EventEnvelopeV1` | 2 | 36 | 0 | 8,192 bytes |
| `EventAppendReceiptV1` | 1 | 41 | 0 | 8,192 bytes |

The counts include all required empty arrays and the fixed one-member payload.
Unknown and duplicate members count before rejection. Every variable scalar is
bounded by an inherited 27-byte timestamp, 36-byte UUID, 71-byte digest,
128-byte schema/label, or safe integer. Therefore each legal maximum fits the
assigned common budget with at least a four-times canonical margin for the
largest request. Ceiling and ceiling-plus-one fixtures must independently verify
raw, depth, token, member, element, decoded-string, common canonical, and
record-specific canonical limits.

No payload has a `16,384`-byte generic inline allowance in this profile; the only
payload is the exact fixed object. The broader RFC 0018 inline-payload ceiling
does not create an admission path.

The exact behavior-free APIs are:

| Type | Untrusted parser | Typed construction | Canonical/digest API |
| --- | --- | --- | --- |
| `EventPartitionV1` | `EventPartitionV1::from_json_slice` | `EventPartitionV1::try_new(EventPartitionV1Fields)` | `canonical_bytes`; `descriptor_digest` |
| `EventAppendIntentV1` | `EventAppendIntentV1::from_json_slice` | `EventAppendIntentV1::try_new(EventAppendIntentV1Fields)` | `canonical_bytes`; `intent_digest` |
| `FixedLocalEventWriterRecordV1` | `FixedLocalEventWriterRecordV1::from_json_slice` | `FixedLocalEventWriterRecordV1::try_new(FixedLocalEventWriterRecordV1Fields)` | `canonical_bytes`; `writer_record_digest` |
| `EventAppendRequestV1` | `EventAppendRequestV1::from_json_slice` | `EventAppendRequestV1::try_new(EventAppendRequestV1Fields)` | `canonical_bytes`; `command_bytes` for exact `C`; `request_digest` |
| `EventEnvelopeV1` | `EventEnvelopeV1::from_json_slice` | `EventEnvelopeV1::try_new(EventEnvelopeV1Fields)` | `canonical_bytes`; `event_digest` |
| `EventAppendReceiptV1` | `EventAppendReceiptV1::from_json_slice` | `EventAppendReceiptV1::try_new(EventAppendReceiptV1Fields)` | `canonical_bytes`; `receipt_digest` |

Each parser signature is
`from_json_slice(input: &[u8]) -> Result<Self, FoundationGrammarError>`; each
constructor returns that same result type; each canonical method returns
`Vec<u8>`; and each digest method returns its nominal digest type. The six
`*Fields` builders are behavior-free typed parameter structs, are not
serializable records, and expose no defaults. Constructing an envelope or
receipt remains an untrusted assertion; only Event-owner validation creates a
trusted handle.

## Digest Manifest and Acyclic Derivation

Unless a row names the RFC 0019 exception, each digest uses RFC 0018's exact
construction:

```text
BLAKE3-256(UTF8(exact_domain) || 0x00 || RFC8785_JCS(exact_projection))
```

| Output/type and every record field using it | Exact domain | Exact included projection | Exact exclusions |
| --- | --- | --- | --- |
| `EventPartitionDigest`; `EventPartitionV1.descriptor_digest`, request, `D`, envelope, and receipt partition digest | `splendor.event.partition.v1` | Every `EventPartitionV1` member except `descriptor_digest` | Own output only |
| `EventIntentDigest`; request, `D`, envelope, and receipt `intent_digest` | `splendor.event.append_intent.v1` | Complete `EventAppendIntentV1` including explicit empty arrays and fixed payload | No exclusion; intent has no digest member |
| `EventAppendIdempotencyKeyDigest`; request/receipt `idempotency_key_digest` | `splendor.event.append_idempotency_key.v1` | JCS object containing exactly `idempotency_key`, `owner_audience`, `owner_component`, `owner_principal_id`, `partition_id`, `producer_principal_id`, `run_id`, and `tenant_id` | Intent/request digests and every later value; permanent Store binding supplies changed-request conflict |
| `EventAppendRequestDigest`; `request.request_digest`, envelope/receipt `request_digest`, and `D.command_semantic_digest` | inherited exact `splendor.fnd003.command-semantics.v1` | Exact `C` defined below | `request_digest`, Decision key/fingerprint, `O`, operation key, event/receipt owner outputs, achieved durability, and Store values |
| `EventAppendDecisionKeyDigest`; `D`, envelope, and receipt `decision_key` | inherited exact `splendor.fnd003.decision-key.v1` | Exact `C` | Every derived digest/key and owner output |
| `EventAppendDecisionFingerprintDigest`; envelope/receipt `decision_fingerprint` | inherited exact `splendor.fnd003.decision-fingerprint.v1` | RFC 0019 formula over `raw32(DecisionKey)`, `0x00`, and exact `D` | Fingerprint itself, `O`, operation key, envelope/receipt/Store outputs |
| `EventWriterFenceDigest`; writer/request, `D`, envelope, and receipt fence fields | `splendor.event.fixed_local_writer_fence.v1` | JCS object containing exactly `backend_policy_revision`, `created_at`, `deployment_policy_revision`, `expires_at`, `owner_audience`, `owner_component`, `owner_principal_id`, `partition_id`, `process_instance_id`, `producer_principal_id`, `run_id`, `store_id`, `store_profile`, `tenant_id`, `writer_epoch`, and `writer_record_id` from fresh creation | Fence output, mutable cursor, status, record revision/digest, and later values |
| `EventWriterRecordDigest`; `writer_record.writer_record_digest`, request duplicate field, `D.writer_record_digest`, and receipt after digest | `splendor.event.fixed_local_writer_record.v1` | Every writer-record member except `writer_record_digest` | Own output only; no receipt or downstream value |
| `EventEnvelopeDigest`; envelope `event_digest`, writer prior/current digests, request expected base, receipt event digests | `splendor.event.envelope.v1` | Every envelope member except `event_digest` | Own output, receipt, updated writer-record digest, acknowledgement, and finalization |
| `EventAppendReceiptDigest`; receipt `receipt_digest` | `splendor.event.append_receipt.v1` | Every receipt member except `receipt_digest` | Own output only |

Digest equality never replaces retained canonical-byte equality. Same digest with
changed bytes is an integrity conflict that quarantines the partition.

### Exact `C`

`C` is the JCS object formed from every `EventAppendRequestV1` member except
`request_digest`, with no wrapper, newline, default, or hidden field. Thus it
includes the independently fixed command/idempotency identities, full intent,
intent digest, full partition and descriptor digest, exact expected sequence and
base, full asserted writer record and digest, requested durability, audit/causal
empty-array presence, owner/tenant/producer/run/audience bindings transitively,
and all presence distinctions.

Mutable current lookup results, trusted owner time, achieved durability, updated
writer revision, Event ID, recorded time, envelope digest, receipt, and Store
transaction values are not in `C`.

Action identity and work-order, capability, approval, data-use, secret, lease,
Artifact, payload-reference, and external audit-reference fields are
schema-forbidden in this internal no-effect profile. Their canonical absence is
the absence of those members, not null, empty strings, default IDs, side tables,
or hidden context. A profile that admits any such semantic needs a new schema and
complete owner annex.

The command namespace is fixed before `C` as:

```text
(owner_component = splendor.event-log,
 tenant_id,
 command_family = event.append.owner_record_v1,
 producer_principal_id,
 owner_audience = splendor.event-log,
 command_id)
```

The caller and owner idempotency identity are the same nominal
`EventAppendIdempotencyKey` in this direct internal profile. It is independently
allocated before `C`; Event owner does not derive a second key. The permanent
idempotency lookup scope is:

```text
(tenant_id, producer_principal_id, partition_id, idempotency_key)
```

Then:

```text
EventAppendRequestDigest = BLAKE3-256(
  UTF8("splendor.fnd003.command-semantics.v1") || 0x00 || C
)

EventAppendDecisionKeyDigest = BLAKE3-256(
  UTF8("splendor.fnd003.decision-key.v1") || 0x00 || C
)
```

### Exact `D`

After exact current partition/writer and preliminary cardinality checks, Event
owner constructs one internal, non-public, retained JCS object
with exactly these members:

```text
backend_policy_revision
command_id
command_semantic_digest
decision_key
deployment_policy_revision
disposition = append
durability_class = required_after_effect
effective_durability_floor
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

The private Rust value is `PreparedEventAppendDecisionV1`; it has no schema
constant, public parser, general serializer, daemon/SDK representation, or
caller constructor. Its owner-controlled canonical-byte method emits the exact
object above for retention and independent fixtures.

`deployment_policy_revision` is the sole Event-owner policy revision for this
fixed profile; `backend_policy_revision` independently identifies Store
durability mechanics. Neither may be caller-selected or inferred from latest.

No Gateway or external verifier result exists in `D`: this operation performs
only the Event owner's authenticated local mutation and has no external action.
Grammar, identity, tenant/audience, fixed-writer, resource, and Store checks are
owner admission/transition rules. Adding an external verifier or effect boundary
requires a new Decision profile rather than an omitted or empty result set.

`D` excludes its fingerprint, `O`, operation idempotency key, recorded/commit
time, achieved durability, updated writer record, Store transaction identity,
envelope digest, and receipt. The fingerprint is:

```text
EventAppendDecisionFingerprintDigest = BLAKE3-256(
  UTF8("splendor.fnd003.decision-fingerprint.v1") || 0x00 ||
  raw32(EventAppendDecisionKeyDigest) || 0x00 || D
)
```

### No `O`

This profile has `external_effect_required = false`; `O`,
`OperationIdempotencyKey`, dispatch attempt, effect certainty, and all related
fields are structurally absent and forbidden. The Event append transaction is
RFC 0019's no-effect owner transaction. Adding an `O` placeholder, empty bytes,
zero digest, default key, or synthetic no-effect operation is a contract error,
not forward compatibility.

### Dependency graph and required cycle fixtures

The only dependency order is:

```text
independent command/idempotency/partition/writer identities
  -> partition/intent/idempotency/writer-current digests
  -> C
  -> request digest and Decision key
  -> owner-derived EventId
  -> D
  -> Decision fingerprint
  -> owner time and envelope
  -> envelope digest
  -> updated writer record and digest
  -> receipt ID, receipt, and receipt digest
  -> one SQLite commit
```

The contract manifest and CI graph check must reject at least:

- direct self-input: `request_digest` in `C`, fingerprint in `D`, envelope
  digest in its projection, or receipt digest in its projection;
- indirect input: envelope/receipt/updated-writer digest feeding `D`, or receipt
  feeding envelope/writer;
- command-key cycle: deriving command or idempotency identity from `C`, request
  digest, or Decision key;
- optional cycle: conditionally adding a derived field only for non-genesis;
- default cycle: replacing a forbidden derived field with zero, empty, null, or
  a default before hashing; and
- cross-family substitution: any generic `ContentHash`, sibling digest, or same
  raw bytes under another nominal type.

The dependency-manifest fixture set is named and fixed as follows. Rejection is
a build/test failure before a wire value exists, so it introduces no public error
code.

| Fixture | Deliberate graph mutation | Required result |
| --- | --- | --- |
| `event_append_graph_acyclic_genesis` | Exact graph above with genesis base | Accept; independent topological sort is unique up to independent pre-`C` digests |
| `event_append_cycle_c_direct` | Add `request_digest -> C` | Reject direct cycle |
| `event_append_cycle_d_direct` | Add `decision_fingerprint -> D` | Reject direct cycle |
| `event_append_cycle_envelope_indirect` | Add `event_digest -> D`; existing `D -> fingerprint -> envelope -> event_digest` closes the cycle | Reject indirect cycle |
| `event_append_cycle_receipt_backedge` | Add `receipt_digest -> envelope`; existing `envelope -> event_digest -> receipt -> receipt_digest` closes the cycle | Reject indirect cycle |
| `event_append_cycle_optional_previous` | Add receipt or updated-writer digest to `D` only when previous base is present | Reject conditional cycle for both absent and present fixtures |
| `event_append_cycle_default_zero` | Add zero/empty/default Decision key to `C` and replace it after hashing | Reject default/post-hoc cycle |
| `event_append_cross_digest_same_bytes` | Substitute any same-byte sibling nominal digest | Reject nominal binding before hashing |

Independent fixtures must mutate every `C` member and every nested presence
distinction one at a time. Each mutation changes request digest and Decision key.
A trusted current clock or Store availability change leaves `C` stable but may
deny or change owner processing.

## Fixed Writer Creation and Restart

### Fresh creation

The internal owner operation is
`create_fresh_local_partition(FreshLocalEventPartitionSpecV1)`. The spec is a
non-serializable application value containing exact authenticated owner and
producer principals, tenant, run, durable `InstanceId`, owner-allocated store,
partition, and writer IDs, immutable expiry, backend/deployment policy revisions,
and trusted durability floors. It carries no caller-selected epoch, fence,
cursor, status, digest, or owner revision.

One SQLite `BEGIN IMMEDIATE` transaction verifies all of these are genesis:

- store metadata has no tenant, partition, writer, command, event, receipt, or
  resource rows;
- `CombinedLocalStoreId` is not already bound to different database metadata;
- partition and writer IDs have never been used; and
- the database schema and backend policy are exact current versions.

Event owner fixes descriptor revision `1`, writer revision `1`, epoch `1`,
`active`, absent cursors/integrity/last-recorded time, fixed floors, and the
derived fence/record digests. The transaction inserts store metadata, partition,
writer current/history, and initial resource counters all-or-none. No append
receipt is issued for creation. Creation uncertainty uses the same IDs and exact
lookup; it never allocates replacements.

### Process and Store binding

`process_instance_id` is a durable runtime-instance identity configured before
database creation and reused by the same deployment across an ordinary process
restart. It is not PID, boot time, host name, path, or a newly generated startup
UUID. The SQLite database holds one immutable `CombinedLocalStoreId` in owner
metadata.

The runtime must acquire the SQLite/VFS exclusive writer lock domain before
activating this Event owner and hold one process-local owner guard for its
lifetime. Lock acquisition does not replace transaction CAS. A copied database,
different store ID, different durable instance ID, unavailable lock state, or
evidence that two processes may have used the binding quarantines the store; this
fixed-local profile offers no split-brain recovery.

Admission therefore requires a local deployment guarantee that the database and
its lock domain cannot be byte-copied, separately mounted, or activated in a
second filesystem namespace while live. This profile cannot detect an
undisclosed concurrent offline clone. If that guarantee is unavailable, the
writer is unsupported; fleet, shared-volume, container-replica, and transferable
operation wait for `EVT-002`.

### Restart

Restart may resume only after all of these succeed without mutation:

1. open the exact database under `sqlite_wal_full_v1`;
2. validate SQLite schema/version and immutable store metadata;
3. validate the complete partition descriptor and digest;
4. validate every retained writer-history revision through the current record;
5. validate current record ID, producer, tenant, run, owner, Store, durable
   instance, epoch `1`, fence, status `active`, expiry, cursor, and integrity;
6. verify command/idempotency/event/receipt unique bindings and the complete
   event digest chain through the current cursor;
7. verify no unresolved append outcome or resource-accounting gap exists; and
8. verify trusted current time is not earlier than `last_recorded_at` and is
   strictly before `expires_at`.

Any missing, corrupt, ambiguous, rolled-back, expired, closed, quarantined,
same-epoch/different-fence, process-mismatched, Store-mismatched, or alternate-
writer fact refuses activation. When the database remains safely writable, the
owner may durably move `active -> quarantined`; otherwise startup stays closed
without claiming the transition persisted.

There is no operation to renew expiry, increment epoch, rotate fence, change
producer/process/Store, reactivate a terminal status, transfer, hand off, cut
over, import as live, or roll back. Such a symbol in owner, Store, kernel, daemon,
SDK, or test code is an `EVT-002` stop violation.

## Owner Append Protocol

The Event-owner application operation is internal and semantically equivalent to:

```text
append_no_effect(
  authenticated_producer,
  EventAppendRequestV1
) -> EventAppendOutcomeV1
```

`EventAppendOutcomeV1` is a sealed owner result, not a registered wire record:

```text
appended(TrustedEventAppendReceipt)
duplicate(TrustedEventAppendReceipt)
conflict
rejected(FoundationGrammarError)
failed_no_append
append_outcome_uncertain(PrivateRecoveryHandle)
```

The trusted receipt is non-serializable and is created only by validating the
stored receipt and all bound records. Its behavior-free receipt value may be
returned only through a later accepted API; this RFC registers no transport.

### Admission before lookup

Before existence-sensitive command or idempotency lookup, owner code validates:

- authenticated internal principal equals intent producer and audit principal;
- exact tenant, run, owner audience, partition scope, and local deployment;
- all bounded grammar and digest fields;
- fixed payload and absence of prohibited payload/reference material;
- current process/Store guard; and
- finite in-flight/rate admission below.

Failure has no Event-store mutation. Mutation authority does not grant a read of
current sequence, writer state, or conflict detail.

### Exact duplicate and changed duplicate

After admission, Event owner looks up both permanent bindings:

```text
command namespace -> retained C, Decision key, D, fingerprint, event, receipt
idempotency scope -> command namespace and retained C
```

- If neither exists, processing may continue.
- If both resolve to the same complete retained `C`, owner recomputes and
  validates every digest, envelope, writer revision, and receipt, reapplies
  current response visibility, and returns the original trusted receipt as
  `duplicate`. It writes nothing and allocates no ID, time, revision, or bytes.
- If either exists with changed bytes, changed binding, only one side exists,
  same digest/different bytes, wrong owner/tenant/producer, or inconsistent
  receipt, the result is opaque conflict or quarantine. No append occurs.
- Missing, corrupt, inaccessible, or uncertain history is never a fresh miss.

### One transaction and one visibility point

For a new command, owner code begins one Store transaction, obtains the trusted
transaction clock, and performs these steps in order:

1. Recheck no command/idempotency binding exists.
2. Read and byte/digest-validate exact immutable store/partition metadata and the
   complete current writer record.
3. Compare tenant, run, producer, owner, audience, Store, process instance,
   profile, active status, unexpired time, deployment/backend revisions, epoch
   `1`, fence, writer-record ID/revision/digest, expected next sequence, and
   expected previous digest or genesis.
4. Check canonical safe-integer increments for sequence and owner/writer
   revision.
5. Compute the effective durability floor.
6. Construct `D`, Event ID, Decision fingerprint, owner `recorded_at`, envelope,
   envelope digest, next writer record/digest, receipt ID, receipt, and receipt
   digest in the acyclic order above.
7. Compute the exact retained resource charge from those final canonical bytes
   and reserve it by CAS against partition/store counters.
8. Insert the permanent command/idempotency binding and retained `C`/`D` bytes.
9. Insert the immutable envelope and immutable receipt.
10. Insert the next writer-history row and CAS the current writer pointer from
    every expected field to the next revision/cursor/integrity.
11. Commit once under the configured SQLite durability policy.

The exact CAS comparison domain is:

```text
store_id, store_profile, tenant_id,
partition_id, partition_digest,
writer_record_id, writer_record_revision, writer_record_digest,
status = active, process_instance_id, producer_principal_id,
writer_epoch = 1, fence_digest,
current_sequence/current_event_digest or genesis,
deployment_policy_revision, backend_policy_revision,
expires_at > transaction_recorded_at,
resource_counter_revisions and admitted charge
```

All immutable inserts and that CAS are in one SQLite transaction and one
database. A unique-index or CAS loser rolls the whole transaction back. A loser
may then perform only an exact command/idempotency lookup: complete byte equality
returns the original receipt as duplicate; every other winner returns opaque
conflict. Owner code never fetches a latest cursor and retries the append. No
reader, response, duplicate result, replay view, cursor, or owner receipt exposes
the new event before successful commit and required barrier confirmation. Any
partial visible command/event/writer/receipt state is an invariant violation and
quarantines the database.

The storage adapter may choose physical column encodings, but its migration must
provide these exact mechanical relations and uniqueness domains; no relation may
carry policy or infer owner semantics:

| Mechanical relation | Required primary/unique bindings |
| --- | --- |
| store metadata | One row keyed by `CombinedLocalStoreId`; immutable store profile and tenant; current resource-counter revision |
| partitions | Primary `EventPartitionId`; unique complete descriptor digest/bytes binding |
| writer history | Primary `(FixedLocalEventWriterRecordId, writer_record_revision)`; immutable bytes/digest |
| writer current pointer | Primary `EventPartitionId`; exact current writer ID/revision/digest and CAS fields |
| command bindings | Unique complete command namespace and unique Decision key; retained `C`, request digest, `D`, fingerprint, event ID, receipt ID, and charge |
| idempotency bindings | Unique `(tenant_id, producer_principal_id, partition_id, idempotency_key)`; exact command namespace and retained `C` binding |
| envelopes | Primary `(partition_id, sequence)`; unique Event ID, Decision key, and immutable envelope digest/bytes |
| receipts | Primary receipt ID; unique command namespace, Decision key, event coordinate, and immutable receipt digest/bytes |
| resource charges | Primary command namespace; exact non-negative charge included in partition/store CAS totals |

All owner records are retained as canonical bytes plus the typed index columns
needed for exact uniqueness/CAS. Indexed columns are assertions validated against
decoded canonical bytes on read and recovery; they are not an alternate truth.

## SQLite Durability Contract

The production adapter is a newly created local database with fixed profile
`sqlite_wal_full_v1`:

```text
journal_mode = WAL
synchronous = FULL
foreign_keys = ON
trusted_schema = OFF
application_id = 0x53504c45
user_version = 1
page_size = 4096
busy_timeout = 0
locking_mode = EXCLUSIVE
```

The adapter uses one serialized writer connection per `CombinedLocalStoreId`,
`BEGIN IMMEDIATE`, checked statements, and SQLite unique indexes/CAS predicates.
It must reject a VFS or build that cannot truthfully report successful FULL sync.
It performs no provider I/O and never attaches an existing Trace or State
database.

For the first implementation, `backend_policy_revision` and
`deployment_policy_revision` are both exactly `1`. A changed pragma, transaction
meaning, durability floor, limit, or writer policy requires a new reviewed
revision and RFC 0020 compatibility decision; numeric increase is not automatic
compatibility.

The minimum production floors are:

```text
owner_profile_durability_floor = transaction_committed
deployment_durability_floor = storage_barrier_confirmed
effective_floor = max(owner profile, deployment, caller)
achieved_durability = storage_barrier_confirmed
```

The deterministic in-memory port always records `memory_only`, is test-only, and
uses `memory_only` for all three floors. It can return a sealed test receipt but
cannot produce a trusted privileged receipt. It may not be selected by production
configuration or a caller.

For normal success, SQLite `COMMIT` and its configured VFS FULL synchronization
must return success before the owner validates/releases the receipt. A queue,
mutex, row insert before commit, WAL write without the configured sync result,
checkpoint request, log line, exporter acknowledgement, or current readable row
does not by itself prove the receipt's durability.

If commit acknowledgement is lost or SQLite reports an ambiguous outcome, no
success is returned. Recovery reopens the exact database and request:

- a complete committed transaction is validated from the permanent binding,
  envelope, writer row, receipt, counters, and chain, then a current successful
  FULL barrier is required before releasing the original receipt;
- proved rollback/absence permits retry of the exact same request and owner IDs;
  or
- inability to prove either disposition quarantines the partition.

This is local SQLite durability under the selected OS/VFS contract. It is not a
remote replica, quorum, hardware certification, cross-store transaction, or
power-loss guarantee beyond what the tested VFS and device truthfully provide.

## Resource Contract

This profile is deliberately finite. Trusted store configuration fixes these
maximums before creation and callers cannot raise them:

| Resource | Exact ceiling |
| --- | ---: |
| Fresh partitions per database | 1 |
| Tenants per database | 1 |
| Committed appends per partition | 250,000 |
| Committed appends per database | 250,000 |
| Permanently charged logical bytes per partition | 2,147,483,648 |
| Permanently charged logical bytes per database | 2,147,483,648 |
| Concurrent owner append calls per database | 32 |
| Concurrent Store write transactions per database | 1 |
| Admitted calls per producer/partition per monotonic second | 64 |
| Admitted calls per database per monotonic second | 256 |

Rate and concurrency guards run after authentication but before history lookup;
duplicates cannot bypass them. Rate uses the process monotonic clock. A restart
begins with zero available rate tokens and admits work only after one complete
monotonic second, so restart cannot create an immediate full bucket. The durable
cardinality/byte counters are the authoritative retained-capacity gates.

Each rate guard is a token bucket whose capacity equals its table ceiling, whose
refill occurs only in whole elapsed monotonic seconds at that same number of
tokens per second, and whose token count never exceeds capacity. Every admitted
new, duplicate, or conflicting call consumes one token from both applicable
buckets. Exhaustion returns the same bounded resource class before lookup.

Before source claim inside the append transaction, Event owner computes:

```text
append_charge =
  byte_len(C) + byte_len(D) +
  byte_len(EventEnvelopeV1 canonical bytes) +
  byte_len(next FixedLocalEventWriterRecordV1 canonical bytes) +
  byte_len(EventAppendReceiptV1 canonical bytes) +
  4096
```

The fixed `4096` is the owner policy's logical index/recovery allowance per
append. Logical accounting is not a claim about exact SQLite page usage; SQLite
disk-full and configured database limits remain independent fail-closed gates.
The command binding stores the exact charge. Store and partition counters are
CAS-updated in the same transaction as the append.

Fresh creation initially charges the canonical partition bytes, canonical
genesis writer-record bytes, and one fixed `4096`-byte store/partition index
allowance against both byte ceilings. That charge commits with creation or not at
all.

Exact duplicates consume no new retained charge. A proved rollback consumes no
permanent charge. A possibly committed transaction remains unavailable for new
work until same-request reconciliation proves whether its charge committed.
Committed commands, idempotency bindings, Decisions, envelopes, writer history,
receipts, integrity links, and charges have no TTL and are non-evictable in this
slice. Compaction, deletion, ID reuse, treating missing history as fresh, or
freeing uncertain debt is forbidden. At any ceiling or arithmetic overflow the
new append is rejected before mutation; existing history remains readable to the
owner recovery path.

## Failure, Recovery, and Error Contract

| Point or fault | Required result |
| --- | --- |
| Grammar/auth/scope/resource admission before transaction | Fixed rejection or resource exhaustion; zero Store mutation. |
| Fresh creation transaction failure | All creation rows absent, original complete creation present, or quarantine; reuse the same allocated IDs only. |
| Stale sequence/previous digest/writer revision/epoch/fence/status/expiry | Opaque conflict; zero append and no latest-value rebase. |
| Concurrent equivalent append | One transaction wins; loser validates and returns the one original receipt as duplicate. |
| Concurrent changed append | At most one winner; loser receives opaque conflict and no bytes from the winner. |
| Unique-index/CAS conflict | Whole transaction rolls back; no partial command, event, writer, receipt, or charge. |
| Disk full or transaction error with proved rollback | `failed_no_append`; exact request may retry with no replacement identity. |
| Sync/barrier failure or unknown commit outcome | No success; same-request recovery only; partition unavailable or quarantined until proved. |
| Process kill before commit | SQLite recovery proves rollback or complete commit; no partial visibility. |
| Process kill after durable commit before response | Exact duplicate lookup validates and returns the original receipt unchanged. |
| Receipt bytes missing/corrupt/mismatched | No duplicate success; quarantine and intervention. |
| Event chain or writer-history gap | Stop activation/replay/recovery; quarantine. |
| Clock unavailable, before prior owner time, or at/after expiry | No append; clock rollback/ambiguity quarantines as applicable. |
| In-memory deterministic port restart | No durability claim; fixture restarts from explicitly supplied deterministic state only. |

The only outward mutation distinctions are fixed `rejected`, `conflict`,
`resource_exhausted`, `failed_no_append`, and `append_outcome_uncertain` semantic
classes. They are not new public wire codes. Hidden, absent, wrong-tenant,
wrong-audience, stale, fenced, same-ID/changed-bytes, and unauthorized current
coordinate cases use one bounded opaque conflict profile. Errors expose no
candidate bytes, field path, sequence, cursor, epoch, digest, existence bit,
tenant activity, Store path, provider text, source chain, or retry advice.
Detailed diagnostics require a future FND-009-governed owner query.

Automatic recovery performs only exact owner-local SQLite reads, integrity
validation, barrier confirmation, same-transaction retry after proved absence,
and terminal quarantine. It allocates no replacement IDs, changes no bytes,
selects no latest value, creates no writer, and invokes no Gateway, adapter,
status operation, outbox, inbox, State, Evidence, or external service.

There is no background recovery queue or resumable mutation scan in this slice.
Startup validation opens one SQLite read transaction, captures the current writer
coordinate as its high-water, and checks every integer sequence from genesis
through that high-water in order. An empty page cannot complete a non-empty
range, and any gap closes activation. Same-request reconciliation addresses one
exact command namespace under the fixed writer guard; it is not replay or a
cursor that can skip unresolved work.

## Visibility, Privacy, and FND-009 Boundary

Every new partition, writer, envelope, receipt, Decision, command binding, and
recovery fact is `restricted`. This annex exposes no range read, export,
subscription, generic trace endpoint, conflict detail, or generated client.

The only reads allowed before FND-009 are:

- owner-internal current-record and exact-command lookup after authenticated
  tenant/producer/audience admission;
- startup/recovery validation of the exact local Store; and
- deterministic test inspection through a private typed port.

Holding an Event ID, partition ID, digest, receipt value, or duplicate result
grants no read, append, authority, currentness, State, Evidence, C03, or effect
permission. FND-009 must separately define classification, redaction, authorized
views, timing behavior, export, and public inspection before any broader read.

The grammar cannot represent raw secret material because the only payload has no
content. It also forbids raw credentials, tokens, private keys, provider
request/error text, provider-resolvable locators, approval/lease/permit material,
protected-evaluation identifiers, arbitrary metadata, private chain-of-thought,
generic payload references, and secret-derived digests. A compatibility bridge
may not smuggle any such value through stable `TraceEvent` JSON, labels, errors,
correlation refs, or Store diagnostics.

## Replay

The private inspect-only replay operation reads a bounded exact partition range
from the owner port and verifies partition/writer history, sequence, previous
digest, envelope digest, command/Decision binding, receipt, and resource charge.
It returns detached typed inspection results only to the authorized local test or
future FND-009 view boundary.

Replay never:

- opens a write transaction;
- appends, repairs, quarantines, compacts, or advances a cursor;
- claims recovery work or invokes same-request reconciliation;
- creates a writer/fence, Event ID, receipt, or trusted handle;
- invokes Gateway, adapter, provider, network, external filesystem, State,
  Evidence, outbox, inbox, or status operation; or
- turns history into currentness, authority, durability, C03 proof, or a live
  event.

Missing or corrupt history remains unavailable/corrupt; replay does not infer
genesis or fabricate absence.

## Stable 0.1 Compatibility and Migration

Under RFC 0020 this proposal's primary compatibility class is `storage` because
it registers new persisted owner bytes, transaction/CAS meaning, durability, and
writer fencing. Additional classes are `behavioral` and `security_critical`
because duplicate/conflict/recovery behavior and tenant/receipt/integrity
binding affect privileged mutation. It is not a transport change: no endpoint,
message, capability advertisement, or generated client is registered.

Stable `TraceEvent`, `TraceEventKind`, `TraceEventId::from_run_sequence`, event
sequence, timestamp, identity context, variant spelling, payload, existing hash,
export, required tick order, and inspect-only replay remain byte-for-byte under
their existing contracts. This RFC changes none of those types or serializers.

The only stable 0.1 projection in this annex is the existing identity projection:

```text
project_stable_trace_v0_1(event: TraceEvent)
  -> the existing production TraceEvent serializer bytes
```

It emits no envelope field, allocates no Event ID, recalculates no stable event
hash, changes no alias/output spelling, and performs no new-store write. It is a
compatibility characterization fixture, not an adapter from `owner_record_v1`.
Because RFC 0018 makes `EventId` and `TraceEventId` profile-dependent nominal
types, inventing such a cross-profile projection here would violate identity and
canonical-byte law.

The compatibility matrix is exact:

| Source | New owner-record parser/live owner | Stable 0.1 Trace consumer |
| --- | --- | --- |
| New `owner_record_v1` record (N) | `accept_current` only after all owner checks | No adapter; live and historical conversion are `unsupported` |
| Stable 0.1 `TraceEvent` | `reject_fail_closed` for live append; an existing legacy reader may inspect it in place | Existing stable behavior, including the exact `trace_id` input alias where already implemented |
| Unknown/N+1 owner record | Reject live; no opaque retention is registered here | No conversion or downgrade |

For the `owner_record_v1` boundary itself, no N-1 schema exists. If this annex is
accepted and its grammar is implemented, these are all nine source/consumer
roles:

| Source role | N-1 consumer | N consumer | N+1 consumer |
| --- | --- | --- | --- |
| N-1 (nonexistent) | No parser or live value exists | `reject_fail_closed`; no adapter is registered | No current RFC can authorize it |
| N (`owner_record_v1`) | Reject live and downgrade; only the retained N reader may perform rollback-read | `accept_current` only through the exact bounded parser and complete owner checks | A future consumer may accept only through its own accepted direct matrix; this RFC grants nothing |
| N+1/unknown | Reject live; no opaque archive is registered here | Reject live without dropping/defaulting unknowns | Outside this RFC |

| Operation at the N owner boundary | Exact disposition |
| --- | --- |
| Parse/validate | Only exact N uses the bounded parser and all digest/binding checks; N-1 and N+1 reject. |
| Live admission | Exact N proceeds only to owner checks; parsing grants no append authority. |
| Canonical output | Exact N emits only the registered JCS bytes; no alias output exists. |
| Inspect/replay | Exact N owner bytes may be inspected under the restricted no-effect path; stable Trace stays with its own adapter; unknown bytes are not retained here. |
| Downgrade/conversion | Always `unsupported`; no field dropping or identity reminting. |
| Rollback-read | Retain the exact N parser, records, and owner integrity checks after writes stop. No writer reactivation follows. |
| Generated parity | No generation or publication in this slice. |
| Storage | Fresh N database only; no rewrite, attachment, live import, or in-place migration. |
| Transport | No transport is registered; privileged dispatch rejects before this owner boundary. |

The required deterministic migration-decision function for this storage and
behavioral change is:

```text
decide_event_conversion(source_schema, source_bytes, target_schema)
  -> unsupported
```

for every source/target pair except identity parsing of the same exact current
owner record by its owner parser. It performs no I/O. In particular, there is no
stable `TraceEvent -> owner_record_v1`, `owner_record_v1 -> TraceEvent`, N-1 to
N, N to N-1, or N+1 conversion.

The first kernel composition adds one separate internal fresh-local
`append_no_effect` facade. It does not replace `TraceSink`, call
`TraceStore::append`, project the owner record as `TraceEvent`, or independently
write legacy trace bytes. Existing Trace/State databases stay on their current
writers and remain inspect-only inputs to any future migration work. The new
database begins empty and has one truth. No live legacy cutover, attached
database transaction, dual write, shadow read model, import-as-live, or rollback
writer is permitted.

After new owner bytes exist, rollback means stop new appends and retain exact
owner read/recovery support. It cannot delete permanent history, reactivate a
legacy writer, change the writer binding, or reinterpret records. A future
`trace_event_compatibility_v0_1` owner path requires its own accepted field,
payload-safety, projection, State/Event transaction, and cutover review.

An immutable SQLite backup or checkpoint may be produced only through a future
operator-approved local backup procedure that captures a transaction-consistent
image and its owner integrity manifest. In this slice, a restored or copied image
is inspect-only: it cannot activate because writer transfer, Store replacement,
and proof that the original writer is permanently fenced are unavailable before
`EVT-002`. Restore drills may verify exact schema, bytes, chain, receipts, and
resource counters but perform zero append. No online migration, forward repair,
or backup clone is a second writer.

## Sequenced Implementation Plan

Each slice is a separate PR after acceptance. Passing one slice does not
authorize the next, and no slice changes a Gold status by itself.

### Slice 1 - Behavior-free Event grammar

Scope:

- implement only the IDs, digest types, enums, fixed payload, six records,
  bounded parsers, checked constructors, JCS bytes, digest manifest, pure `C`/`D`
  helpers, and unsupported conversion function in `splendor-types`;
- retain exact independent canonical/digest fixtures; and
- perform no I/O, allocation, clock read, owner behavior, Store, kernel, daemon,
  SDK, generated output, or live compatibility routing.

Required tests:

- positive canonical round trips and independent JCS/BLAKE3/UUIDv5 fixtures;
- every missing/null/duplicate/unknown/alias/side/extension/wrong-type member;
- ID nil/noncanonical/cross-type and digest prefix/width/case/cross-family cases;
- exact conditionals for genesis/previous integrity and writer cursor history;
- every `C` and digest-projection one-field/presence mutation;
- direct, indirect, optional, and default-value cycle rejection;
- exact common and record-specific ceiling/ceiling-plus-one fixtures;
- synthetic secret/provider/protected values are unrepresentable and absent from
  errors/Debug/fixtures; and
- stable 0.1 Trace bytes, IDs, event hashes, ordering, and replay fixtures remain
  unchanged while every cross-profile conversion returns `unsupported`.

Stop if any record needs a generic map/value, unresolved external owner, public
payload registry, generated surface, changed stable type, or owner behavior.

### Slice 2 - Event owner and deterministic Store port

Scope:

- create `splendor-evidence::event` after package/dependency review;
- implement fresh creation, owner admission, `C`/`D`, materialization, duplicate,
  conflict, quarantine, resource, and inspect-only replay semantics;
- use a deterministic fault-injectable in-memory Store port that truthfully
  reports only `memory_only`; and
- expose only internal application ports.

Required tests:

- positive append, exact duplicate, changed command/idempotency conflict,
  expected-sequence/previous-digest conflict, and one-winner concurrency;
- stale revision, status, expiry, process, Store, epoch, and fence denial;
- fresh creation/restart with same IDs and all mismatch/uncertainty denials;
- higher epoch, different fence, rotation, renewal, handoff, transfer, cutover,
  rollback, import-as-live, and second-writer APIs are absent or reject;
- resource exact-ceiling/ceiling-plus-one, overflow, duplicate coalescing,
  retained charge, and uncertain-debt behavior;
- failure before each prepared write yields no visible fact; uncertainty never
  fabricates a trusted receipt; and
- replay performs zero mutation/effect calls.

Stop on any privileged durability claim, SQLite behavior, external effect,
State/Evidence semantics, transferable writer, public read/API, or broad event
kind.

### Slice 3 - Real combined-local SQLite adapter

Scope:

- implement the storage-only tables and exact one-transaction append primitive
  in `splendor-store`;
- create only a fresh `sqlite_wal_full_v1` database and Event tables within the
  combined-local topology;
- implement exact unique indexes, CAS predicates, resource counters, FULL
  barrier handling, startup validation, and same-request recovery; and
- retain existing Trace/State databases untouched.

Required tests:

- real positive append/duplicate/restart and original receipt byte equality;
- concurrent equivalent and conflicting writers with one SQLite winner;
- stale sequence, previous digest, record revision/digest, epoch/fence, status,
  process, Store, expiry, and resource counter CAS failures;
- process kill, modeled power loss, disk full, statement/commit error, FULL sync
  error, lost request, and lost response before/at/after every insert/CAS/commit
  boundary;
- no receipt before barrier, no partial visibility, and exact uncertainty
  reconciliation/quarantine;
- permanent command/idempotency/writer/event/receipt/resource history across
  restart, with deletion/compaction never creating a fresh miss;
- chain corruption, missing row, same digest/changed bytes, cross-tenant row, and
  Store copy/mismatch close activation; and
- Store fault code never selects owner retry, policy, visibility, or transition.

Stop if one truthful SQLite transaction cannot contain all command, Decision,
envelope, writer, receipt, and counter facts, or if the VFS cannot provide the
declared barrier. Do not attach or coordinate an existing Trace/State database.

### Slice 4 - One fresh-local kernel composition

Scope:

- compose one internal no-external-effect owner append path in
  `splendor-kernel` against the real new SQLite adapter;
- keep current `TraceSink`, `TraceStore`, StateGraph, daemon, SDK, and stable tick
  writer behavior unchanged; and
- expose no new public transport.

Required tests:

- one fresh partition append reaches owner, SQLite, barrier, and trusted receipt;
- owner/parser/CAS/durability/resource failures return no success and cause zero
  Gateway, adapter, provider, State, Evidence, node, or external calls;
- restart and response loss return the original receipt without new IDs/times;
- inspect-only replay makes zero writes/effects;
- stable 0.1 trace/state/export/replay conformance remains unchanged; and
- instrumentation proves no legacy/new dual write or database attachment.

Stop before current kernel tick/action/state events route through the new owner,
before daemon/SDK exposure, and before any C03 producer consumes the path. A
later typed event-kind and compatibility annex must authorize each such route.

The required test categories are complete per slice:

| Slice | Positive | Denial | Failure | Restart | Replay | Compatibility |
| --- | --- | --- | --- | --- | --- | --- |
| 1 - grammar | Canonical construct/parse/digest | Malformed, substitution, cycle, and over-bound | Deterministic parser/digest error precedence | Not applicable by proof: no I/O or retained state exists | Pure historical fixture parsing only; zero owner call | Stable Trace identity bytes and unsupported conversion |
| 2 - owner/test port | First append and exact duplicate | Stale writer, changed duplicate, terminal status, and capacity | Inject every Store-port boundary and uncertainty | Exact fixed binding resumes; mismatch closes | Private inspect plan makes zero writes | Stable types untouched; memory receipt cannot become privileged |
| 3 - SQLite | Real append/duplicate/barrier | Every unique/CAS/currentness mismatch | Kill, disk, transaction, sync, and response loss | Full startup chain and same-request recovery | SQLite read transaction only; zero mutation | Fresh database only; existing Trace/State bytes and stores untouched |
| 4 - kernel | One internal end-to-end append | Owner rejection reaches no effect path | Owner/Store/barrier failures release no success | Original receipt after process/response loss | Kernel inspect path makes zero live calls | Current conformance unchanged and no dual write |

## RFC 0018 and RFC 0019 No-Go Review

Implementation must stop if any of these becomes true:

- a field, nominal type, conditional, collection, parser, budget, canonical byte,
  schema, digest projection, or exclusion differs from this annex;
- a producer can supply Event ID, sequence output, recorded time, envelope
  digest, receipt, achieved durability, owner revision, or updated writer data;
- a generic JSON/map/payload/reference, secret-bearing value, unknown event kind,
  or unresolved external-owner fact becomes admissible;
- command/idempotency identities derive from `C` or a later value, any derived
  value feeds an earlier projection, or cycle fixtures/manifest checks are absent;
- `O`, an operation key, attempt, Gateway permit, effect certainty, outbox,
  inbox, batch, or another owner is added to this no-effect profile;
- conservative cardinality/byte reservation is absent or permanent/uncertain
  history can be evicted to regain capacity;
- append facts use separate commits, attached databases, a process mutex, ordered
  writes, or an in-memory queue while being described as atomic/durable;
- expected sequence, previous digest, writer revision/digest, epoch, or fence is
  absent, inferred as latest, or checked outside the committing CAS only;
- a response/duplicate/replay view exposes the append before required durability;
- missing/corrupt/unavailable history becomes genesis or a fresh identity;
- restart can change process/Store/writer/epoch/fence, terminal status can
  reactivate, or `EVT-002` lifecycle leaks into the profile;
- stable 0.1 bytes/types/order change, a conversion is inferred, or old/new
  stores dual-write or cut over;
- replay writes, reconciles, quarantines, appends, repairs, or calls any live
  owner/effect path;
- `splendor-types`, Store, kernel, daemon, SDK, replay, or a test fake becomes a
  second semantic owner; or
- required positive, denial, failure, restart, replay, compatibility, privacy,
  concurrency, and real-SQLite fault evidence is missing.

## Validation and Gold Status

Proposal review must verify:

- every RFC 0018 reserved family used here has one exhaustive field table,
  parser/budget assignment, canonical rule, and digest row;
- every RFC 0019 no-go gate applicable to a no-effect owner-local mutation is
  explicitly cleared or retained as a stop;
- Markdown structure and links, `git diff --check`, dependency policy, current
  stable conformance, and `cargo fmt --all -- --check` remain clean; and
- no file other than this new RFC changes in the repository proposal.

Acceptance or static validation would register only this bounded contract and
authorize the dependency-safe code slices above. It would not execute `G00`,
`G02`, `G03`, or `G08`. Those Gold cases remain `specified_not_implemented` /
`not_exercised` until their real production-path harnesses and retained evidence
exist. In particular, the fixed contentless payload and no-effect path do not prove
Secret Broker operation, State/Event atomicity, general Event compatibility, or
replay conformance beyond their later exact tests.

## Acceptance Effect

If independently accepted, this RFC becomes the exact owner annex for only the
fixed-local, fresh-partition, `owner_record_v1`, no-external-effect Event append
slice. It clears the RFC 0018 grammar reservation and RFC 0019 owner-annex gate
only for the records and code sequence named here.

Acceptance alone changes no behavior, accepts no implementation, closes no task
or issue, enables no C03 path, and changes no compatibility, conformance, Gold,
or release status. Any broader payload, stable Trace writer migration, State or
Evidence composition, cross-owner publication, external effect, public API, or
transferable writer requires its own accepted contract and evidence.
