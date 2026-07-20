# RFC 0015 - Event, State, and Evidence Ownership and Durability Contract

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-20

**Accepted proposal SHA-256:**
`e326858c973177eedc235b1de353bbc2e21f40d6958f91deea67cf9d0fcd626f`

**Compatibility line:** Additive experimental 0.2/v2 owner contract preserving
the stable 0.1 trace, state, and inspect-only replay contracts

**Component:** Event, State, and Evidence plane

**Owner package:** future `crates/splendor-evidence`; behavior-free contract
grammar in `crates/splendor-types`; persistence engines in
`crates/splendor-store`

**Catalog and issue scope:** package prerequisite `FND-002` / [#221](https://github.com/splendor-kernel/kernel/issues/221),
plus only the C03-required portions of `EVT-001` / [#271](https://github.com/splendor-kernel/kernel/issues/271),
`EVT-003` / [#273](https://github.com/splendor-kernel/kernel/issues/273),
`STA-001` / [#279](https://github.com/splendor-kernel/kernel/issues/279),
`STA-002` / [#280](https://github.com/splendor-kernel/kernel/issues/280), and
`EVID-001` / [#287](https://github.com/splendor-kernel/kernel/issues/287)

**Primitive strengthened:** event log, state service, evidence service, and
safe replay/simulation planning

**Normative compatibility inputs:** [RFC 0006](0006-agent-kernel-v2-lifecycle.md),
[RFC 0012](0012-secret-broker-contract.md),
[RFC 0013](0013-driver-operation-credential-sink-contract.md),
[RFC 0014](0014-revision-bound-secret-credential-authorization.md), and the
[stable 0.1 primitive contract](../spec/0.1/primitives.md)

**Informative implementation context:**
[RFC 0010](0010-authority-service-contract.md) is `Status: Draft` and is used
only to understand current Authority implementation and compatibility seams. It
is not an accepted normative dependency of this RFC.

**Separately authorized blocker:** transferable Event writer epochs, handoff,
and live legacy cutover require `EVT-002` / [#272](https://github.com/splendor-kernel/kernel/issues/272).
This RFC does not absorb or authorize that task.

This RFC is a proposed, documentation-only prerequisite. It changes no runtime,
package graph, persistence format, public schema, generated artifact, daemon API,
SDK, CLI, trace, state head, replay result, Authority record, Registry record, or
C03 record. It does not close an issue, complete a catalog task or component,
exercise a gold case, or authorize a side effect. Acceptance would authorize only
the bounded implementation sequence and ownership rules specified below.

## Decision

Splendor will have one semantic owner for Event, State, Evidence, and
Replay/Simulation planning: `splendor-evidence`.

- `splendor-types` owns behavior-free nominal values, closed schemas, receipts,
  coordinates, references, deterministic serialization, and compatibility
  grammar. It performs no I/O and makes no lifecycle, authority, durability, or
  replay-execution decision.
- `splendor-evidence` owns event validation and ordering, append and durability
  semantics, state-partition mutation and fencing semantics, evidence
  completeness and claim-support semantics, redacted evidence views, and
  replay/simulation plans.
- `splendor-store` owns persistence traits and engines. It may enforce an
  owner-supplied transaction, uniqueness constraint, integrity check, expected
  sequence, compare-and-swap, and fencing token. It does not decide which event
  is required, whether a state transition is legal, whether evidence is
  complete, whether an effect may retry, or whether replay may execute.
- `splendor-kernel` is the composition root and stable 0.1 compatibility facade.
  It delegates to the owner and must not retain a divergent event, state,
  evidence, or replay state machine.
- `splendor-daemon`, SDKs, bindings, and CLIs authenticate or translate closed
  commands and queries. They do not open owner stores to mutate records and do
  not infer durability, current heads, evidence support, or authority.
- Authority, Registry, and C03 produce or consume immutable owner-issued facts.
  They do not append Event rows, move State heads, manufacture Evidence
  completeness, issue Event receipts, or become shadow durability owners.

An event, state coordinate, append receipt, cursor, evidence item, evidence
bundle, digest, replay report, or simulation result is never authority. Current
caller identity, work order, capability, data-use, policy, approval, quota,
safety, Gateway, and verifier requirements remain independently mandatory.

## Motivation

The stable 0.1 runtime has useful foundations, but its current package seams do
not satisfy the owner contract required by C03:

- `TraceStore::append` returns an assigned `u64`, not a receipt that proves the
  requested event identity, expected sequence, writer epoch, integrity link, and
  configured durability were accepted.
- the current state graph writes immutable nodes but keeps one process-local
  mutable head without a named partition, expected-head CAS, writer lease, or
  fencing epoch;
- the current loop can commit and expose a new state head before appending the
  corresponding stable `StateCommitted` event, so an append failure can leave
  state and trace inconsistent; and
- no `splendor-evidence` package exists. Current trace, state, governance, and
  telemetry records are source material, not an owner-issued evidence service.

Accepted RFC 0012 assigns C03 preclaim observations, stable event publication,
and evidence facts to Event/Evidence, and assigns state-node/head visibility to
State Service. Accepted RFC 0014 requires immutable Authority and Registry proof
records for proof-bound migration. C03 cannot legally implement those contracts
by adding private kernel maps, Authority shadow tables, direct Store semantics,
or daemon logic. This RFC establishes the prerequisite owner and minimum public
coordinates without pulling the full Event, State, or Evidence platforms into
C03.

## Exact Bounded Scope and Dependency Status

This RFC defines prerequisites, not full catalog-task completion.

| Task | Bounded contract established here | Explicitly not completed here |
| --- | --- | --- |
| `FND-002` / #221 | One package and mutation owner for Event, State, Evidence, and replay plans; dependency direction and compatibility facade rule | Crate creation, full plane split, all package README/CODEOWNERS work, generated surfaces, and complete architecture enforcement |
| `EVT-001` / #271 | Versioned `EventEnvelope` family and exact stable `TraceEvent` compatibility profile | Migration of all producers, all service event kinds, fleet ordering, subscriptions, retention, and full event platform |
| `EVT-002` / #272 | Separately authorized blocker only; the bounded profile in this RFC is non-transferable and local | Transferable Event writer lifecycle, epoch/fence allocation, handoff, live cutover/rollback, remote import, and task implementation |
| `EVT-003` / #273 | Expected-sequence/fence append request, durable receipt, idempotency, bounded outbox/inbox, and effect-certainty outcomes | Full `EventStore`, every backend, all service outboxes, broad delivery ecosystem, and all fault-injection completion evidence |
| `STA-001` / #279 | Named state partition, explicit owner/scope/schema/classification, and mandatory expected head | All standard domain profiles, world-state semantics, retention platform, arbitrary state service, and domain ontology |
| `STA-002` / #280 | CAS head movement, writer epoch/fence validation, immutable commit, explicit conflict, and no-mutation results | Authority lease issuance, fleet handoff, automatic merge, every controller adoption, and complete migration evidence |
| `EVID-001` / #287 | Typed bundle/item/claim/completeness/support grammar, authenticated durable commit contract, and immutable owner references | Materialization service implementation, portable trust/signature infrastructure, causal closure, every requirement profile, Artifact/Lineage implementation, and gate adoption |

The following required collaborators remain unmet or separately owned:

| Dependency | Why it remains separate and blocking |
| --- | --- |
| `FND-001` | Owns canonical nominal ID and schema grammar. This RFC does not redefine existing IDs or independently finalize new ID wire forms. |
| `FND-003` | Owns the generic command-decision-event transaction pattern and recoverable cross-owner mutation protocol, including independently owned authority-revocation-versus-State-CAS races. This RFC defines only the minimum owner-local append and state/event atomicity requirement and cannot make an independently committed owner snapshot current by copying it into State. |
| `FND-006` | Owns broad schema migration, generated parity, and compatibility discipline. This RFC pins the 0.1 projection but does not complete cross-language migration. |
| `EVT-002` / #272 | Owns transferable Event partition-writer records, epoch/fence lifecycle, handoff, and live cutover/rollback. Before it is separately accepted and implemented, this RFC permits only a fixed non-transferable local writer profile for fresh partitions. |
| `AUTH-001` | Owns capability/authority semantics and eligibility/revocation facts. State validates those facts and exclusively allocates its writer epoch/fence; neither Evidence nor the external authority fact grants a State writer. |
| `ART-001` | Owns immutable artifact identity, manifests, access, and lifecycle. Artifact references remain opaque and cannot be dereferenced or treated as proof until that owner exists. |
| `LIN-001` | Owns lineage identities and derivation facts. Lineage references remain opaque and dependency-bound. |

No implementation may label this RFC as completion evidence for any task in
these tables. Any slice that requires an unmet collaborator stops at the public
port or opaque reference described here.

## Ownership and Dependency Direction

One mutation has one owner.

| Surface | Owns here | Must not own here |
| --- | --- | --- |
| `splendor-types` | Behavior-free IDs whose grammar remains owned by FND-001, closed request/outcome/receipt/reference values, strict bounds, deterministic serialization | I/O, current-head lookup, ordering decisions, lease validation, evidence evaluation, retry, quarantine, replay execution |
| `splendor-evidence::event` | Event profiles, partition ordering, append validation, idempotency interpretation, durability requirements, integrity links, owner receipts, inbox reconciliation | Authority, mutable State heads, external effects, provider transport, analytics warehouse behavior |
| `splendor-evidence::state` | Partition descriptors, writer acceptance, expected-head/fence validation, immutable commit semantics, head CAS, state/event composition | Authority grant issuance, domain reasoning, hidden merge, Artifact or Lineage ownership, run lifecycle |
| `splendor-evidence::evidence` | Requirement profiles, typed items, completeness, bounded claims, support levels, visibility/redacted views | Authority, approval, quality/alignment decisions, artifact lifecycle, lineage truth, gate pass/promotion |
| `splendor-evidence::replay` | Inspect/read-only reconstruction and explicit non-live replay/simulation plans | Live adapter/driver invocation, live head mutation, lease acquisition, authority refresh, provider lookup |
| `splendor-store` | Atomic persistence primitives, transactions, WAL/sync implementation, uniqueness, CAS, integrity storage, read ranges | Event-kind policy, transition legality, evidence support, retry policy, owner clocks, redaction decisions |
| `splendor-kernel` | Wiring, owner facade, stable 0.1 projections, local composition, fail-closed coordination | Duplicate Event/State/Evidence semantics or a second mutable head/event sequence |
| daemon, SDK, CLI, bindings | Authenticated transport, command/query translation, safe display | Direct Store mutation, authority inference, durability claims, client-side evidence completion |
| Authority and Registry | Their own immutable decision/admission facts and owner-specific evidence payloads | Event append receipts, State heads, generic Evidence completeness, C03 state |
| C03 | Secret-specific commands, records, authority intersection, and proof-bound migration after all prerequisites | Event/State/Evidence owner rows, Registry rows, generic receipt fabrication, hidden proof joins |

The intended internal dependency direction is:

```text
splendor-types
    <- splendor-store
    <- splendor-evidence
    <- splendor-kernel
    <- daemon / CLI / bindings
```

`splendor-evidence` may define outbound ports for Authority status or opaque
Artifact/Lineage resolution, but it must not import upward packages to acquire
their semantics. Composition bridges supply authenticated immutable snapshots or
narrow read ports. A bridge translates and maps failures; it never becomes an
owner.

## Normative Contract Rules

The following words are normative:

- **durable** means the configured storage guarantee named in an owner-issued
  receipt was reached, not merely that bytes entered a process queue;
- **current** means selected by an explicit owner query or expected-head/fence
  operation, never by caller inference from the numerically largest record;
- **effect certainty** records what is known about an external effect and is not
  inferred from event publication success;
- **quarantine** is a fail-closed owner state that forbids automatic effect
  repetition and live publication until a separately authorized recovery or
  intervention resolves the uncertainty; and
- **reference** means an immutable coordinate plus integrity binding. Possession
  of a reference grants neither visibility nor mutation authority.

All privileged public contracts are closed, bounded, versioned schemas. Unknown,
duplicate, null where prohibited, unbounded, wrong-identity, cross-tenant,
stale-head, stale-fence, wrong-audience, corrupt-digest, or unsupported privileged
fields fail before persistence or mutation. No authorizing field may be hidden in
`extensions`, arbitrary maps, or unbounded JSON.

The minimum public contract families authorized for later implementation are:

| Family | Behavior-free values in `splendor-types` | Semantic owner in `splendor-evidence` |
| --- | --- | --- |
| Event | `EventAppendIntent`, `EventEnvelope`, `EventPartition`, `EventCoordinate`, `EventAppendRequest`, `EventAppendOutcome`, `EventAppendReceipt`, `EventAppendBatchIntent`, `EventAppendBatchAcknowledgement`, `EventDurability`, `EventIntegrity`, bounded publication command/acknowledgement values | Intent admission, owner envelope materialization, partition order, fixed local writer check, idempotency, durability, integrity, append outcome, inbox reconciliation |
| State | `StatePartition`, `StateHead`, `WriterEligibilityFacts`, `StateWriterActivationCommand`, `StateWriterActivationOutcome`, `StateWriterActivationReceipt`, `StateWriterBinding`, `StateMutationRequest`, `StateMutationOutcome`, `StateCommitReceipt`, `StateCommitCoordinate` | Partition policy, trusted eligibility acceptance, writer epoch/fence activation, expected-head validation, immutable commit, head CAS, state/event composition |
| Evidence | `EvidenceRequirement`, `EvidenceItem`, `EvidenceBundle`, `EvidenceCompleteness`, `EvidenceClaim`, `EvidenceSupportLevel`, `EvidenceCommitRequest`, `EvidenceCommitOutcome`, `EvidenceCommitReceipt`, `EvidenceBundleCoordinate`, `EvidenceView` | Requirement evaluation, completeness, claim-support ceiling, authenticated durable commit, owner-reference validation, access-filtered/redacted view construction |
| Replay/simulation | `ReplayPlan`, `SimulationPlan`, result/report references | Inspect/read-only planning, detached simulation constraints, live-effect and live-head prohibition |

These are contract-family names, not accepted stable wire spellings. Existing
nominal IDs are reused exactly where the compatibility profile requires them.
Any new nominal ID, schema constant, canonical byte grammar, or cross-language
binding remains blocked on `FND-001` and `FND-006`; implementations may not fill
that gap with string aliases or private duplicate types.

## Event Contract

### Producer intent and owner envelope

The producer submits a closed `EventAppendIntent`; it does not construct or
persist a committed `EventEnvelope`. The intent contains only producer-owned
facts:

- intent schema/profile, authenticated producer, tenant/scope, and intended
  partition;
- occurred time, kind schema/kind, bounded typed payload or opaque safe payload
  reference, causal parents, and correlation references;
- a producer-fixed event identity and sequence only when the registered profile
  requires them, including the stable 0.1 compatibility profile;
- caller-requested durability, which is a floor that may only tighten owner and
  deployment policy; and
- command/audit correlation plus one idempotency key.

The canonical intent digest covers every immutable intent field, including
presence versus absence, producer-fixed identity/sequence when permitted,
payload bytes/reference, causal fields, and requested durability. It excludes
owner-assigned `recorded_at`, sequence or event identity when owner-assigned,
integrity outputs, achieved durability, and receipts. The same idempotency key
and intent digest identify one append forever. The same key with changed intent
bytes is a permanent conflict.

After authenticating and validating the intent, Event owner materializes the
versioned committed `EventEnvelope` in the append transaction. The owner assigns
`recorded_at`, the next sequence, Event identity where the profile does not
require a producer-fixed identity, the previous/current integrity link, effective
durability, owner revision, and committed visibility metadata. A producer-fixed
identity or sequence is accepted only when the profile defines its derivation and
the owner verifies exact equality before mutation. The owner never trusts a
producer-supplied recorded time, integrity value, latest cursor, or achieved
durability.

The first implementation must use an explicit versioned envelope rather than
mutate stable `TraceEvent` in place. Its minimum committed fields are:

| Field family | Required rule |
| --- | --- |
| `schema_version` and `profile` | Closed envelope version and one registered owner profile. Unknown privileged profiles reject. |
| `event_id` | One nominal event identity allocated by Event owner unless a registered compatibility profile requires an exactly validated producer-fixed identity. For the 0.1 profile it is exactly the existing `TraceEventId`; no second identity is minted. New identity grammar waits for `FND-001`. |
| `partition` | Typed partition identity and exact tenant/run/owner scope. It never implies authority. |
| `sequence` | Owner-assigned monotonic `u64` within the partition, except an exactly validated compatibility sequence. It is not a fleet-global order. |
| `writer_epoch` and `fence` | Exact current fixed local writer binding checked in the append transaction. Transfer, rotation, handoff, and cutover remain blocked on separately authorized `EVT-002`; this field does not authorize them. |
| `producer` and `scope` | Exact authenticated producer reference and bounded identity scope. Producer identity does not grant event or action authority. |
| `occurred_at` and `recorded_at` | Distinct timestamps. Occurrence time is producer evidence; recorded time is assigned by Event owner in the append transaction and cannot establish causality by itself. |
| `kind_schema` and `kind` | Registered owner kind and closed payload schema. Event kinds cannot carry hidden authority. |
| `payload` | Exactly one bounded inline typed payload or immutable opaque payload reference. Protected payload copying is forbidden. |
| `causal_parents` | Bounded immutable event coordinates with relation types. Missing or inaccessible parents remain explicit. |
| `correlation_refs` | Bounded non-authorizing references for queries. They do not affect order or permission. |
| `visibility` | Closed classification and audience policy reference enforced on reads and projections. |
| `durability_class` | Owner-validated `required_before_effect`, `required_after_effect`, `best_effort_telemetry`, or `derived_export_only`; producer input cannot weaken it. |
| `integrity` | Event-owner-derived canonical envelope digest, previous-partition digest when applicable, algorithm/version, and owner integrity revision. |
| `intent_digest` | Exact canonical digest of the admitted producer intent from which this envelope was materialized. |

The envelope must not contain raw secrets, private chain-of-thought, credentials,
approval tokens, live capability material, unrestricted protected payloads, or
provider-specific arbitrary data. A payload reference is not permission to
dereference the target.

### Fixed local partition-writer profile

Before separately authorized `EVT-002`, Event owner supports only a fresh
partition's durable `FixedLocalEventWriterRecord`. It binds owner principal,
authenticated producer, tenant/scope/audience, partition, process instance,
combined Store identity/profile, fixed positive epoch, opaque fence digest,
created/expiry time, status `active | quarantined | closed`, prior/current
cursor and integrity, record revision/digest, and deployment-policy revision.
Creation is an expected-genesis all-or-none owner transaction. The profile has
no command that chooses a higher epoch, rotates a fence, transfers a writer, or
adopts a legacy partition.

Every append and inbox transaction compares the exact current record revision,
status, producer, Store identity, epoch/fence, cursor, and integrity in the same
transaction that materializes the envelope. A same-epoch/different-fence writer,
expired/closed/quarantined record, process/Store mismatch, or uncertain record
lookup appends nothing and quarantines as applicable. `closed` and `quarantined`
never return to `active` in this profile. Restart can resume only the same durable
record, process trust binding, and Store after proving no alternate writer was
admitted. Transferable lifecycle, higher-epoch acceptance, handoff, cutover, and
rollback remain wholly owned by future `EVT-002` / #272.

### Stable `TraceEvent` compatibility profile

`TraceEventCompatibilityProfileV0_1` is the required compatibility projection.
For every stable 0.1 trace event:

1. The producer intent carries the complete stable `TraceEvent` compatibility
   value; Event owner derives or validates all envelope bindings rather than
   trusting a caller-built envelope.
2. `event_id` is exactly `TraceEvent.trace_event_id` and must equal the stable
   derivation from run and sequence.
3. The partition is the `agent_run` compatibility partition for the exact
   `run_id`.
4. `sequence` is exactly `TraceEvent.sequence`; migration never renumbers it.
5. `occurred_at` is exactly `TraceEvent.timestamp`; owner-assigned
   `recorded_at` remains envelope metadata and is not inserted into stable bytes.
6. Scope and identity preserve the complete `TraceEvent.identity` values.
7. Kind and payload preserve the exact `TraceEventKind` variant, field names,
   values, and serialized spelling.
8. The stable serializer and export projection emit the same 0.1 `TraceEvent`
   bytes. Envelope-only fields are not injected into those bytes.
9. Existing event hashes remain valid historical integrity facts. An envelope
   integrity layer may bind them but cannot rewrite or reinterpret them.

The required tick line remains exactly, in order:

```text
tick.started
percepts.received
state.loaded
policy.invoked
policy.completed
actions.proposed
constraints.evaluated
verification.started
verification.completed
[escalation.triggered]
action.executed | action.denied | action.failed | action.needs_approval | action.needs_intervention | (action.executed -> action.failed)
outcome.recorded
state.committed
tick.completed
```

Existing Rust variant names and public event spellings remain the source for that
stable line. This RFC does not rename a `TraceEventKind`, change deterministic
`TraceEventId::from_run_sequence`, alter run-local ordering, or add C03 metadata
to `CandidatesProposed { actions }`. New C03 or v2 events are separate typed
profiles linked causally to stable events. Brackets above mean the existing
optional `EscalationTriggered` position, not a newly required event. The action
segment is not always one exclusive terminal event: `ActionNeedsIntervention` is
stable, and an adapter output followed by post-verification failure emits stable
`ActionExecuted` followed by `ActionFailed` before `OutcomeRecorded`.
Compatibility projection, replay, and tests must preserve that exact two-event
order rather than collapse it to one status.

### Append request

`EventAppendRequest` contains exactly the following semantic families:

- one complete producer `EventAppendIntent` and its canonical intent digest;
- the exact partition and `expected_next_sequence`, including zero for genesis;
- the expected previous integrity digest or explicit genesis marker;
- the fixed non-transferable local writer profile identity, epoch, and fencing
  binding accepted when the fresh partition was created;
- one caller-supplied idempotency key bound to the producer, partition, operation,
  canonical intent digest, and canonical request digest;
- the caller-requested durability floor; and
- bounded authenticated command, causal, and audit attribution references.

Event owner validates the intent/request, computes effective durability,
materializes the complete envelope, and commits it through Store. It does not
accept a producer-built committed envelope, read a latest sequence and silently
retry, or substitute current writer data for an expected binding. A stale
sequence, local epoch/fence, previous digest, or changed idempotent request is a
conflict with no append. Transferable writer activation, handoff, or cutover is
not available through this request and remains blocked on `EVT-002`.

### Durability guarantees

The first contract slice supports these result levels:

| Level | Meaning | Privileged use |
| --- | --- | --- |
| `memory_only` | Accepted by a deterministic in-memory test engine; process loss may lose it | Tests and explicitly non-durable local simulation only; never satisfies required privileged evidence |
| `transaction_committed` | Owner store transaction committed under the configured crash-recovery contract | May satisfy a required event only when the deployment policy explicitly names this level |
| `storage_barrier_confirmed` | Transaction committed and the configured backend synchronization barrier returned success | Required when the event profile or deployment policy demands storage synchronization |

Effective minimum durability is:

```text
max(owner event-profile floor, deployment floor, caller-requested floor)
```

The ordering of levels is `memory_only < transaction_committed <
storage_barrier_confirmed`. Owner profile and deployment floors are trusted
configuration inputs fixed before the append request. A caller may request a
stricter level but cannot select, override, omit, or downgrade either trusted
floor. `required_before_effect`, privileged State/Event composition, durable
Evidence used by C03, and any profile that says durable can never resolve to
`memory_only`.

The receipt names every input floor, the effective configured floor, achieved
level, and backend policy revision. The owner returns success only when achieved
durability is at least the effective floor. Queued, buffered, replicating, or
exporter-accepted bytes are not durable unless the selected level explicitly and
truthfully defines them as such. A remote replica or quorum is not implied by
either local level.

### Append receipt and outcomes

`EventAppendReceipt` is immutable and contains:

- receipt schema/version and nominal receipt identity authorized by `FND-001`;
- exact intent digest, request digest, and idempotency-key digest;
- event ID, partition, sequence, writer epoch, and fencing digest;
- previous and committed event integrity digests;
- owner-profile, deployment, caller, effective configured, and achieved
  durability levels plus backend policy revision;
- owner identity/revision and owner-assigned commit time; and
- the exact visibility/classification reference of the stored event.

The closed append outcome family is:

| Outcome | Semantics |
| --- | --- |
| `appended(receipt)` | New event committed at the exact requested coordinate and durability. |
| `duplicate(original_receipt)` | The same idempotency key, request digest, event ID, and canonical bytes were already committed. The original receipt is returned unchanged. |
| `conflict` | Expected sequence, previous digest, local epoch/fence, event identity, or idempotency binding differs. No append occurred. The mutation result is opaque unless a separate restricted conflict-detail query is authorized. |
| `rejected(code)` | Closed schema, scope, visibility, bound, or policy validation failed before Store mutation. |
| `failed_no_append(code)` | Store proved no append committed. |
| `append_outcome_uncertain(recovery_ref)` | Store cannot prove commit or absence. No success receipt is fabricated; the partition is quarantined until same-request lookup/reconciliation resolves it. |

An uncertain append cannot be retried under a new event ID, sequence,
idempotency key, or payload. Recovery queries the same owner using the retained
request identity and digest. An `EventAppendReceipt`, cursor, or duplicate result
never authorizes a caller, state transition, or external effect.

Before selecting a detailed conflict result or looking up current coordinates,
the owner authenticates dedicated Event read authority for the exact tenant,
scope, partition, and audience and emits audit attribution. Without that read
authority, absent, hidden, wrong-tenant, wrong-audience, stale, fenced, and
same-ID/changed-request cases return one non-reflecting `conflict` profile with no
cursor, sequence, epoch, hash, existence bit, distinguishable header, or
finer-grained timing class. Authorized owner diagnostics use a separate audited
`EventConflictDetail` view; mutation authority alone cannot obtain it.

## Transactional Outbox and Inbox Boundary

Cross-owner publication uses at-least-once delivery with idempotent consumption.
It does not claim distributed exactly-once or a transaction spanning independent
stores.

The minimum behavior-free family is:

- `OwnerOutboxEntry`: source owner, source transaction/revision, immutable
  publication command, canonical command digest, idempotency key, source tenant,
  scope, authenticated source principal/producer, destination owner/audience,
  transport/key-status binding, attempt metadata, and state `pending |
  acknowledged | quarantined`;
- `EventPublicationCommand`: one authenticated source-owner command containing
  either one append intent or the constrained batch below, complete intent and
  request digests, source transaction identity/revision/digest, destination
  owner/audience, expiry, key/trust status reference, and no self-asserted
  authority;
- `EventInboxRecord`: destination owner, exact authenticated command
  identity/digest, transport principal, source owner/producer/tenant/scope/source
  transaction, first-seen time, append result, and original receipt references;
  and
- `EventPublicationAcknowledgement`: Event-owner-authenticated immutable binding
  from the command and inbox transaction to every original append receipt or one
  terminal rejection/conflict result, including owner identity, tenant, audience,
  key/trust status, expiry, and acknowledgement digest.

### Constrained first-slice batch

`EventAppendBatchIntent` contains `1..=256` ordered append intents; an owner
profile may lower but never raise that bound. Every item must target the same
partition, authenticated producer, tenant/scope, durability profile, and one
current fixed local writer-record revision and epoch/fence. Expected sequences
are contiguous from the batch's one `expected_next_sequence`, and the first
expected previous digest chains through each owner-materialized envelope in
order.

Event owner validates and materializes every item before mutation, then commits
the batch idempotency record, all envelopes, all integrity links, and the one
batch acknowledgement in one all-or-none owner transaction. When the batch
arrives through cross-owner publication, that same Event transaction also
commits the authenticated inbox dedupe record and publication acknowledgement;
a direct owner-local pre-effect batch does not invent an inbox record. The batch
acknowledgement binds the batch command/request digest, ordered intent digests,
sequence range, previous/final integrity digests, and one exact
`EventAppendReceipt` per item. No receipt is returned before the whole
transaction reaches effective durability.

Any item rejection, conflict, wrong partition/producer/epoch/fence, sequence gap,
or changed duplicate causes zero batch appends and zero per-item receipts. Store
uncertainty quarantines the complete batch and partition; no item is reported as
committed or retried separately. Exact duplicate recovery returns the original
complete acknowledgement and exact ordered receipt set. This batch contract does
not support mixed partitions, epochs, writers, durability policies, partial
success, transfer, handoff, or live legacy cutover.

The source service writes its own state change and unique outbox row in one
source-owner transaction when publication follows a source mutation. Delivery is
at least once. Before dedupe lookup or persistence, Event owner validates a
private trusted wrapper or signature/attestation and requires exact equality
among authenticated transport/service principal, source owner, producer,
tenant/scope, source transaction/revision/digest, destination owner/audience,
command identity/digest, key/trust status, expiry/revocation state, and every
append intent/request digest. Self-described fields never establish those facts.
Wrong owner, tenant, audience, producer, destination, transport principal,
expired/revoked/untrusted key, changed bytes, or unavailable authentication
fails closed, appends nothing, persists no untrusted command/inbox bytes, and
keeps source completion quarantined. A separately authorized transport-security
audit may retain only non-reflecting safe attribution and reason codes.

Event owner commits inbox deduplication and Event append in the one Event-owner
transaction described above. Exact duplicate delivery returns the original
authenticated acknowledgement. Same command ID or idempotency key with changed
bytes is a permanent invariant conflict and quarantines the command. A lost
acknowledgement causes authenticated lookup or redelivery of the same command; it
never causes new event bytes or a second source mutation. The source validates
Event owner identity, tenant, audience, command/inbox transaction digest, every
receipt, key/trust status, expiry/revocation, and acknowledgement authentication
before any completion visibility opens. A forged, stale, untrusted, mismatched,
or unavailable acknowledgement leaves source completion closed and quarantined.

If source state and outbox cannot share one local atomic boundary, the source
mutation must remain uncommitted or unavailable until an explicit `FND-003`
recoverable protocol exists. If Event inbox and Event append cannot share one
local atomic boundary, the append path is unsupported and fails closed. No
implementation may describe two independent Store commits as a transaction.

Outbox backlog, failed delivery, retention pressure, and acknowledgement
uncertainty are visible owner states. They are never silently dropped or reported
as completed. Cross-boundary delivery is at-least-once; idempotent handling and
unique event identity prevent duplicate semantic mutation.

## Permanent Privileged Idempotency and Non-Reuse

In this bounded slice, privileged Event/State/Evidence intent keys, command IDs,
event IDs, source transaction coordinates, inbox/outbox IDs, original receipts,
effect invocation coordinates, and their canonical request/semantic digests have
no TTL and are not compacted, evicted, recycled, or reused. Restart, response
loss, archive pressure, retention policy, and an unavailable lookup never turn a
used or possibly used identity into a fresh miss. Unavailable history is
uncertainty and fails closed.

Any later retention protocol requires a separately accepted contract that first
commits and verifies an immutable non-reuse tombstone or deny head before source
history is removed. That record binds the trusted owner and partition, nominal
identity, tenant/scope/audience, complete request/semantic digest, original
coordinate/result or explicit uncertainty, retention generation, predecessor
integrity, and tombstone integrity. It contains no prohibited source payload.
Exact replay after tombstoning returns the retained terminal result or permanent
duplicate disposition; changed replay remains permanent conflict. Missing,
corrupt, inaccessible, or uncertain tombstone state denies and cannot allocate a
replacement identity.

## Effect Certainty and Quarantine

Every privileged operation that may cause an external effect records one closed
certainty state:

| State | Meaning |
| --- | --- |
| `no_effect` | The owner proved the adapter/driver/provider boundary was not entered or proved no effect occurred. |
| `effect_succeeded` | A trusted bounded result proves the one identified effect succeeded. |
| `effect_failed` | A trusted bounded result proves the identified effect failed with no successful or uncertain sub-effect. |
| `effect_partial` | The operation produced a typed bounded set containing at least one successful sub-effect and at least one failed or uncertain sub-effect. |
| `effect_uncertain` | Timeout, process loss, provider ambiguity, or missing trustworthy result prevents proving success or failure. |

`effect_partial` carries `1..=256` ordered `SubEffectResult` values; the driver
profile may lower that bound. Each value binds a nominal sub-effect identity,
parent invocation/action and idempotency identity, operation/schema, target
coordinate digest, certainty `succeeded | failed | uncertain`, reversibility and
compensation references where declared, trusted provider/adapter receipt, and
causal event coordinate. A top-level `effect_failed` cannot hide a successful or
uncertain sub-effect. A top-level `effect_uncertain` is used when even the
complete sub-effect inventory cannot be trusted.

Effect certainty is independent of event durability. An effect can be known to
have succeeded while its required-after-effect publication remains pending; that
operation is not publicly complete and remains quarantined. An irreversible
`effect_uncertain` or uncertain sub-effect is never rewritten as success or
failure. Retry eligibility is independent of the top-level success/failure label.
No failed, partial, or uncertain operation or sub-effect repeats automatically
unless the retained exact driver/invocation contract proves that retrying that
exact unresolved set under the same invocation and idempotency identity is safe,
does not repeat a successful sub-effect, and still satisfies current authority,
permit, quota, expiry, and safety checks. A fresh invocation, action, request,
event, sub-effect, or idempotency identity is never a retry. Recovery may inspect
the retained invocation or call a separately authorized idempotent status
operation when the driver contract defines one. Any irreversible, unenumerated,
or uncertain sub-effect requires quarantine and intervention rather than retry.

## State Contract

### Named partition

`StatePartition` is a closed immutable descriptor with:

- nominal partition identity;
- exact owner component and owner principal/agent reference;
- tenant plus optional agent, run, workload, or other typed scope;
- state schema identity/version and content classification;
- writer policy, reader policy, retention policy, and declared merge policy;
- partition profile; and
- descriptor revision/digest.

The mutable `StateHead` is separate and contains the partition identity,
positive head revision, optional current `StateNodeId` for genesis, current
state hash when present, current writer epoch, and last committed event
coordinate. A query may return descriptor and head together, but callers cannot
mutate either by submitting a reconstructed aggregate.

The minimum live writer policy is `single_fenced_writer`. The minimum merge
policies are `forbidden` and `fast_forward_only`. Arbitrary JSON merge,
last-writer-wins, caller-selected partition, hidden global memory, and automatic
privileged conflict resolution are forbidden. Broader branch/merge policy is
`STA-003`, not this RFC.

### State-owned writer activation, epoch, and fence

Authority/Agent/Workload owners supply authenticated immutable
`WriterEligibilityFacts`. Those facts bind their owner, authority/lease
generation and status, principal plus agent/workload instance, tenant/scope,
partition, expected head, allowed transition schemas, not-before/expiry,
audience, revocation source, validation policy revision, and canonical digest.
They establish eligibility only. They do not contain or select the State-current
writer epoch/fence and cannot move a State head.

State owner exclusively creates a live writer through
`StateWriterActivationCommand`. The command contains:

- command identity, canonical command digest, and permanent idempotency key;
- exact partition descriptor revision, expected current head, and expected
  current State-writer record revision/status;
- requested writer principal plus agent/workload instance and transition-schema
  ceiling;
- complete owner-authenticated eligibility facts and current
  authority/lease-status generation;
- activation kind `initial_local | renew_same_writer | handoff`; for `handoff`,
  an authenticated handoff-eligibility fact binding the previous and requested
  writer, partition, expected writer/head revisions, source generation/status,
  and handoff command digest;
- requested expiry, owner audience, causal event, and audit attribution; and
- requested durability floor.

These activation kinds fix a closed owner interface; they do not imply that all
paths are currently implementable. `initial_local` may execute only after an
accepted eligibility-owner contract lets its authoritative current-status record
participate in each local Store transaction for State activation and later head
CAS. `renew_same_writer` and `handoff` have the same requirement or require
an accepted `FND-003` cross-owner protocol. Copying, caching, or preflighting an
independently committed status record inside State does not meet this rule. If the
eligibility owner commits in another process, store, or transaction and no
accepted `FND-003` protocol exists, every live activation or renewal that depends
on that owner is unsupported and fails closed.

`handoff` remains an interface stop until the separately owned Authority/Agent/
Workload facts and an accepted same-transaction or `FND-003` handoff protocol
exist. Its owner semantics are nevertheless fixed: external facts establish only
the two writers' eligibility and ordered handoff intent; they never propose the
next epoch or fence. Once a legal linearization path exists, State owner samples
its clock, validates freshness and current status, checks the expected
writer/head state, atomically and permanently fences the previous binding,
allocates the next positive epoch and opaque fence, persists the one
State-current writer record and its required transition event, and returns a
`StateWriterActivationReceipt` only after effective durability. The receipt
binds the command/idempotency digests, eligibility owner/record/generation,
partition/head, previous and new writer revisions/status, newly allocated
epoch/fence digest, principal/instance/schema ceiling, expiry, event receipt,
owner-profile/deployment/caller/effective/achieved durability and backend policy,
and owner revision/time. It is not Authority and cannot be used outside the
bound partition. Until the prerequisite handoff facts and protocol are accepted,
the owner rejects `handoff` before mutation; no implementation may approximate it
with local mutexes, cached status, caller-selected epochs, or independent record
updates.

State activation and mutation use the same strictest-floor durability rule as
Event: the effective floor is the maximum owner-profile, deployment, and caller
floor. Caller input may tighten but never downgrade owner or deployment policy,
and no live writer binding or committed State head is issued from `memory_only`.

The closed activation outcome is `activated(receipt) |
duplicate(original_receipt) | conflict | eligibility_denied(code) |
failed_no_activation(code) | activation_outcome_uncertain(recovery_ref)`.
An eligibility denial code is available only when the caller also has dedicated
authority to read that exact eligibility/status fact; otherwise it maps to the
same opaque `conflict`. Detailed current writer/head facts likewise require
dedicated State read authority and an audited restricted query. Uncertainty
quarantines the partition and same command; no replacement epoch, fence,
command, or idempotency identity may be allocated.

The resulting private `StateWriterBinding` is the only epoch/fence accepted by
State mutation CAS. Once State commits a higher epoch, every lower epoch and any
same-epoch/different-fence binding is permanently fenced even if its external
lease has not expired. Replay, simulation, imported snapshots, evidence bundles,
external eligibility records, and process-local mutexes cannot create a live
binding.

### Revocation and CAS linearization

Authority/lease generation is distinct from State writer epoch. Preflight
validation alone is insufficient. The State head CAS must atomically consume the
current State-owned writer record and a current trusted authority/lease status
generation. This is legal only when either:

1. a local composition bridge lets the eligibility owner validate and commit its
   authoritative status/revocation record while State validates and commits its
   writer fence and head in the same Store transaction, without either owner
   interpreting or rewriting the other's semantics; or
2. an accepted `FND-003` cross-owner protocol defines authenticated commands,
   ordering, recovery, and the exact linearization winner.

An authoritative revocation, expiry transition, or ownership handoff and the
resulting revocation/fence committed in the State-visible shared transaction
before the head CAS wins and denies the mutation with no visible node, event,
head, or receipt. A higher State epoch or fence committed before the CAS likewise
wins. State owner evaluates an expiry boundary using the transaction's trusted
clock. A stale status snapshot, generation mismatch, unavailable owner/status
source, uncertain transaction, or lack of one of the two legal linearization
paths makes live mutation unsupported and fails closed or quarantines the
partition.

The local bridge is composition, not a projection-owned substitute for
Authority. It may pass closed authenticated facts and a shared transaction
handle, but the eligibility owner must decide and persist its own authoritative
generation/status in that transaction; State decides and persists only its
writer/head records. A State-side cached or consumed-generation projection, even
if authenticated and monotonic, cannot prove that an independently owned
revocation did not win concurrently. Same generation with changed source bytes,
generation regression, missing revocation history, uncertain owner
participation, or transaction uncertainty quarantines and denies. This RFC does
not claim generic cross-owner revocation linearization; every independent-owner
race remains blocked on accepted `FND-003` and the relevant owner contracts.

### State mutation request

`StateMutationRequest` contains:

- command identity, canonical request digest, and permanent idempotency key;
- exact partition descriptor revision;
- exact expected head revision and expected `StateNodeId` or explicit genesis;
- exact State-issued `StateWriterBinding`, writer record revision, epoch/fence,
  and current trusted authority/lease-status generation;
- one closed transition schema and typed state payload or opaque immutable
  payload reference;
- parent node identities, next state hash, and immutable commit metadata;
- causal event/evidence inputs from which State owner derives the required
  compatibility event and complete cross-binding; and
- requested durability and audit attribution.

The expected head is mandatory. Absence never means "use latest". The model or
caller cannot choose a broader partition or writer. The supplied authority-status
generation is an expected compare field, not proof of currentness; State verifies
it through one legal transaction/protocol path at CAS. Protected payload bytes
are admitted only after schema, classification, access, and pre-persistence
secret checks.

### Immutable commit and CAS result

The committed node preserves the stable 0.1 `StateNode` identity and lineage:
`state_node_id`, tenant, agent, run, parents, state hash, trace linkage,
snapshot/reference where applicable, and creation time remain representable and
projectable. Additive v2 metadata binds partition, descriptor revision, head
revision, writer epoch/fence digest, transition schema, and evidence/event
coordinates without changing historical 0.1 node bytes.

The closed result family is:

| Result | Semantics |
| --- | --- |
| `committed(receipt)` | Immutable node, required event, and head CAS reached effective durability at the exact expected head/fence. |
| `duplicate(original_receipt)` | The exact command/request digest already committed; no new node, event, head revision, or time is allocated. |
| `conflict` | Expected revision/node, writer record, authority generation, epoch/fence, command, or idempotency binding is stale or different; no mutation. The mutation response is opaque. |
| `lease_denied(code)` | Writer binding is absent, expired, revoked, unavailable, wrong-scope, or wrong-schema; no mutation. A detailed code is returned only with dedicated authority to read that exact status; otherwise this maps to opaque `conflict`. |
| `rejected(code)` | Closed schema, parent, hash, classification, or transition validation failed; no mutation. |
| `failed_no_mutation(code)` | Store proved the immutable node/event/head transaction did not commit. |
| `commit_outcome_uncertain(recovery_ref)` | Store cannot prove commit or absence; partition is quarantined and same-command recovery is required. |

The `StateCommitReceipt` binds command/request digest, partition, descriptor
revision, previous and new heads, immutable node identity, state hash, exact
snapshot reference identity/digest or absence, writer epoch/fence,
authority-status generation, required event append receipt and digest,
owner-profile/deployment/caller/effective/achieved durability and backend policy,
owner revision, and commit time. It is evidence of one state transition, not
authority to make another.

Detailed actual head, writer revision, authority generation, or epoch is
available only from a separate audited `StateConflictDetail` query after exact
tenant/partition read authorization. Without that authority, absent, hidden,
wrong-tenant, wrong-audience, stale-head, stale-fence, revoked, and
same-ID/changed-request cases return the same non-reflecting `conflict` body,
status, headers, and bounded timing class.

### Owner-derived `StateCommitted` binding

The mutation caller never supplies a committed `StateCommitted` event. In the
atomic State/Event transaction, State owner derives the immutable state node,
new head, stable compatibility event, envelope, and a complete owner-internal
cross-binding from the one accepted request. The binding covers partition and
descriptor revision; tenant, agent, run, and tick where applicable; previous and
new head revisions/IDs; node ID, state hash, snapshot reference identity/digest
or absence; current authority generation, State writer record revision, epoch,
and fence digest; command, request, and idempotency digests; stable event ID,
sequence, kind, payload, identity context, causal fields, previous/current
integrity; and intent and envelope digests.

For the stable profile, State owner derives exact
`TraceEventKind::StateCommitted { state_hash, snapshot_id }`, exact
`TraceIdentityContext.state_node_id`, and exact `TraceEventId` from run and the
transaction's next sequence. Envelope-only metadata carries the additional
partition/head/epoch/command binding without changing stable bytes. If a
compatibility adapter supplies any proposed stable field, the owner treats it as
an assertion and validates byte-for-byte and semantic equality across every
field above before Store mutation. Any mismatch creates no node, event, head,
receipt, visibility, or next tick.

### State/event atomicity

For the first local implementation, immutable node persistence, required stable
`StateCommitted` append, and head CAS must use one Store transaction supplied to
and interpreted by State/Event owner code. The transaction checks expected head
and current State writer record/fence plus the linearly current authority-status
generation, derives and cross-binds the node/event, writes the immutable node and
event, advances the head, and returns both receipts only after effective
durability. Any failure commits none of those visible facts.

If a deployment uses independent State and Event stores without a shared atomic
engine boundary, this local operation is unsupported until `FND-003` or a later
accepted RFC defines a recoverable publication barrier. Such a deployment must
fail closed before a live head move. It must not move the head and then append
best-effort, append a false `StateCommitted` before CAS, or call two commits
"atomic". A prepared immutable node may exist only as owner-internal non-live
state and cannot be returned as current, admitted to the next tick, or projected
as `StateCommitted`. Existing deployments with separate trace and state
databases remain inspect-only migration sources; this RFC authorizes no live
atomic cutover between them.

## Evidence Contract

### Evidence requirements and items

`EvidenceRequirement` is a versioned closed profile containing a purpose/claim
schema, subject type, mandatory and optional typed item requirements,
cardinality, freshness rules, access/classification ceiling, accepted owner and
schema versions, integrity requirements, and evaluation policy revision.

`EvidenceItem` is a closed tagged union. The minimum reference variants are:

- exact Event coordinate or bounded partition range plus owner receipts;
- exact State partition/head/commit coordinate plus state hash and owner receipt;
- opaque Artifact identity/version/digest reference;
- opaque Lineage edge/closure identity/version/digest reference;
- opaque Authority, approval, gate, or Registry decision evidence reference;
- bounded environment/runtime fact reference;
- typed metric/evaluation reference; and
- incident/intervention reference.

Each item names its owning component, schema/version, immutable identity,
canonical digest, tenant/scope, visibility classification, and availability
status. An item does not copy raw protected source payloads. Artifact, Lineage,
Authority, Registry, and gate item payload semantics remain owned by their
respective contracts. `splendor-evidence` validates references and requirement
fit; it does not recreate those records or declare their underlying decisions
true.

### Bundle, completeness, claim, and support

`EvidenceBundle` contains:

- bundle identity, schema/version, owner revision, and canonical bundle digest;
- exact subject and purpose/requirement profile reference;
- ordered typed item references and item-result codes;
- issuer/evaluator references and creation time;
- completeness result;
- zero or more typed bounded claims;
- visibility/classification and redaction policy reference; and
- optional owner attestation/signature references when a later contract requires
  them.

That optional bundle-level attestation is profile-specific. It does not replace
the mandatory authenticated `EvidenceCommitReceipt` required for every durable
bundle coordinate below.

`EvidenceCompleteness` is one of:

| Result | Meaning |
| --- | --- |
| `complete` | Every mandatory requirement is present, accessible to this evaluation, schema-compatible, and integrity-valid. This is not a quality, safety, authority, or gate pass. |
| `incomplete` | One or more mandatory items are missing, stale, wrong-version, truncated, or not supplied. Missing requirement codes are explicit. |
| `inaccessible` | Required source existence may be known, but current audience/tenant policy forbids evaluation. It is never silently omitted. |
| `corrupt` | An identity, digest, owner receipt, or integrity check failed. The bundle cannot support a positive claim. |
| `unavailable` | A required owner cannot currently answer. Unavailability is not absence and never becomes complete. |

`EvidenceClaim` is a bounded typed statement naming claim schema/version, exact
subject, evaluator/issuer, evaluation method/policy version, supporting and
contradicting item identities, and one support level:

```text
demonstrated | bounded | inconclusive | contradicted | unavailable
```

`demonstrated` means only that the named requirement and evaluator contract
support the exact bounded statement. It does not mean universally correct,
aligned, safe, authorized, approved, or deployable. A bundle cannot assert more
support than its item results permit. Missing mandatory evidence produces
`incomplete` and cannot be normalized to pass. "Trace exists" is not correctness,
and private chain-of-thought is never required evidence.

### Authenticated durable Evidence commit

A caller submits `EvidenceCommitRequest`, not a committed bundle coordinate or
receipt. The request binds:

- authenticated caller/source owner, tenant, scope, intended audience, command
  identity, permanent idempotency key, and canonical request digest;
- exact subject identity/digest and requirement profile identity/revision;
- ordered item identities, owner/schema revisions, source coordinates/digests,
  and source owner receipts/attestations required by the profile;
- proposed bounded claims and evaluator/issuer references; and
- caller-requested durability floor plus audit attribution.

Evidence owner authenticates the source and audience, resolves only authorized
source references, validates every owner/digest/schema/integrity binding,
evaluates item results, computes completeness and support ceilings, orders the
accepted items/claims canonically, materializes the bundle, computes its digest,
and commits the bundle plus permanent idempotency record in one owner
transaction. Callers cannot assert `complete`, `demonstrated`, owner revision,
bundle identity/digest, achieved durability, or trusted attestation. Same
idempotency identity plus changed subject, requirement, item order/content,
claim, source receipt, audience, or request bytes is a permanent conflict.

The closed `EvidenceCommitOutcome` is:

| Outcome | Semantics |
| --- | --- |
| `committed(receipt, coordinate)` | The exact owner-materialized bundle and permanent idempotency record reached effective durability. |
| `duplicate(original_receipt, original_coordinate)` | The exact request was already committed; original immutable values are returned. |
| `conflict` | Identity/request/substitution conflict; no bundle committed. Mutation callers receive no source-existence detail. |
| `rejected(code)` | Authentication, authorization, source, schema, completeness-policy, classification, or integrity validation failed before commit. |
| `failed_no_commit(code)` | Store proved no bundle or idempotency mutation committed. |
| `commit_outcome_uncertain(recovery_ref)` | Commit or absence cannot be proven; request and owner domain are quarantined for same-command recovery. |

Evidence mutation performs tenant/scope/audience authorization before source or
idempotency lookup. Without separate audited Evidence read authority, absent,
hidden, wrong-tenant/audience, changed-source, and same-ID/changed-request cases
return the same opaque `conflict` response with no source identity, bundle
coordinate, digest, completeness, existence bit, distinct header, or finer timing
class. Restricted `EvidenceConflictDetail` is an owner query, not a mutation
outcome.

`EvidenceCommitReceipt` is a durable owner-authenticated closed record binding:

- receipt/bundle/command identities, permanent idempotency and request digests;
- Evidence owner principal, service instance, trust root/key/attestation
  identity, key status/revision, authentication algorithm/profile, and receipt
  integrity/signature or private trusted-wrapper binding;
- tenant, scope, audience, subject identity/digest, requirement profile/revision,
  evaluator/issuer, and visibility/classification;
- the complete ordered item identity, source-owner, source-receipt, and
  source-attestation identities and digests; source trust/key status; item
  digest/result set; complete ordered claims/support; and exact completeness
  result;
- canonical bundle digest, predecessor/current integrity, owner commit revision
  and time; and
- owner-profile, deployment, caller, effective configured, and achieved
  durability plus backend policy revision.

The same strictest-floor durability rule used by Event applies. General local
profiles may use a private owner-validated authenticated wrapper rather than a
portable signature, but such a receipt is usable only inside that exact trust
boundary. Any external or C03 proof profile requires an independently verifiable
owner signature/attestation and current accepted trust/key-status path. A
memory-only, unsigned, untrusted, expired/revoked-key, wrong-owner,
wrong-tenant/scope/audience, substituted-source, uncertain, or unverifiable
receipt is not a durable Evidence coordinate and cannot satisfy privileged or
C03 proof.

Commit uncertainty is resolved only by authenticated same-request lookup using
the retained command/idempotency/request digest. Recovery returns the original
receipt/coordinate, proves no commit, or remains quarantined. It never creates a
replacement bundle/receipt identity, changes item order or completeness, or
treats unavailable history as fresh.

### Durable evidence coordinates

The owner issues immutable coordinates sufficient for later C03 proof binding:

- `EventCoordinate`: event identity, partition, sequence, writer epoch, event
  schema, canonical event digest, and append receipt reference;
- `StateCommitCoordinate`: partition, descriptor/head revision, state node and
  state hash, writer epoch/fence digest, required event coordinate, and commit
  receipt reference; and
- `EvidenceBundleCoordinate`: bundle identity, requirement profile/version,
  subject digest, completeness code, canonical bundle digest, owner revision,
  mandatory `EvidenceCommitReceipt` identity/digest, achieved durability, and
  required authentication/attestation reference for its trust profile.

Exact names and nominal ID wire forms that do not already exist wait for
`FND-001`. Coordinates never use a bare digest, cursor, timestamp, database row,
or "latest" lookup as identity. They are immutable facts and cannot move a live
head, authorize C03 migration, or grant payload visibility by themselves.
`complete`, `demonstrated`, a bare bundle digest, an `EvidenceView`, or an
in-memory/local-only coordinate cannot substitute for the authenticated durable
commit receipt required by the consuming profile.

### Visibility and redacted views

Every append, state read, evidence build, materialization, export, and replay
query enforces tenant, scope, audience, classification, purpose, and visibility
before returning payloads. A caller that holds a coordinate still needs current
read authority.

Redaction produces an owner-issued `EvidenceView` that binds the source bundle
coordinate, viewer scope, redaction policy/version, included item coordinates,
explicit omitted/inaccessible item statuses, and view digest. It never edits the
source bundle, hides contradictory evidence as absent, or turns an incomplete
bundle into complete. A view receipt is not authority.

Secrets and prohibited protected values are rejected before Event, State, or
Evidence persistence. Post-read redaction, encrypted storage, hash-only storage,
or later deletion is not a substitute for the ingress barrier. References and
digests are used instead of protected payload copies; even a digest is forbidden
when it is derived from secret material or creates an uncontrolled disclosure.

## Privileged Mutation Ordering and Crash Semantics

### Required ordering

For a privileged external effect, the composition root follows this order:

1. Authenticate the caller and validate command schema, identity, scope,
   initial work-order/capability, data-use, policy, approval, quota, and owner
   state needed to admit verification. Unavailable required checks deny, pause,
   quarantine, or request intervention.
2. Fix command, action/invocation, idempotency, event, and causal identities and
   canonical request digests. Retries reuse them.
3. Run the complete Gateway/verifier chain, including final-live Authority,
   work-order, lease, approval, quota, policy, data-use, secret, safety,
   capability, and adapter checks. On allow, Gateway retains the private final
   effect permit/session across the next step; it does not expose a reusable
   bearer receipt. A verifier cannot treat Event or Evidence as authority.
4. For an allow, while the final permit remains held; for a deny, approval, or
   intervention result, before returning: submit one constrained same-partition
   all-or-none batch containing the stable `verification.started`,
   `verification.completed`, and every owner-required decision/pre-effect event
   in their semantic order. Obtain owner receipts at effective durability. Any
   rejection, failure, uncertainty, or, on the allow path, permit
   expiry/revocation or loss of the held session invalidates/withholds execution
   and prevents adapter entry.
5. Immediately after durable append, enter at most the one bounded adapter/driver
   invocation while the same final permit/session is still live. No caller,
   daemon, queue, or later request may reconstruct that permit from receipts.
6. Record the trusted result, typed sub-effects, and explicit effect-certainty
   state. An ambiguous
   result becomes `effect_uncertain` and is quarantined.
7. Append required terminal events and, when state changes, perform the atomic
   State/Event transaction at the exact expected head/fence.
8. Return or publish a terminal result only after every required event, state
   head, and owner receipt reaches effective durability. Otherwise retain the
   known effect result privately and quarantine publication/retry.

For a denied/intervention/approval result, step 4 durably records the complete
verification decision and terminal pre-effect event before return; no effect
permit reaches adapter entry. For a privileged state-only mutation, the same
current verifier/authority principle applies, then State owner validates exact
writer/status/head state and performs the immutable node, owner-derived event,
and head CAS in one supported atomic boundary. No external effect occurs.

### Crash-point table

| Crash or uncertainty point | Required recovery and visible result |
| --- | --- |
| Before command/idempotency claim | No command fact or effect exists. An authenticated retry may submit the same logical request and establish one identity. |
| After command claim, before or during verifier evaluation | Resume only the retained command and identities. No adapter/driver entry is allowed. Uncertain or unavailable required verifier records no allow. |
| After final permit creation, before/during pre-effect batch append | No effect. The private permit remains held only in the live Gateway session. Append rejection/failure/uncertainty invalidates it. Process loss destroys it; recovery reruns all current verification under the same command/invocation identities. |
| After durable pre-effect receipts, before adapter entry | No effect. The same live session may enter the adapter only if the retained permit remains current. Process loss or permit expiry/revocation requires same-command re-verification; receipts never recreate authority. |
| During external invocation | Use the retained invocation and driver idempotency contract. If absence/success/failure cannot be proven, record `effect_uncertain`, quarantine, and do not repeat an irreversible effect. |
| After known or partial effect, before terminal append | Retain exact top-level and sub-effect certainty privately. Recover publication under the same identities only. Repeat no successful/uncertain sub-effect; retry only when the retained exact contract proves the unresolved set safe. Public completion remains closed. |
| During append transaction | Query the same request/receipt identity. If commit or absence cannot be proven, quarantine the partition; never allocate a replacement event. |
| During atomic State/Event commit | Query the same state command. Either original receipt is returned, no mutation is proven, or the partition is quarantined. A partial visible head/event is an invariant violation. |
| After immutable node preparation but before supported atomic commit | The node is detached owner-internal data, not current state and not a `StateCommitted` fact. Same-command recovery may reuse it; no next tick starts. |
| After committed head/event, before response | Exact duplicate returns the original commit and append receipts. No new node, event, revision, timestamp, or effect is allocated. |
| After outbox commit, before Event inbox append | Redeliver the same command at least once. Source visibility follows its declared barrier and never assumes delivery from enqueue alone. |
| After Event append, before acknowledgement reaches source | Destination returns the original inbox result/receipts for the same command. Source never publishes changed bytes. |
| Recovery state corrupt, exhausted, or owner unavailable | Fail closed and require intervention. Never infer success, use latest, silently retry, or repair by writing another owner's table. |

Required-before-effect append failure causes no external effect. State/Event
commit failure prevents state advancement, next-tick admission, and successful
terminal publication. Required-after-effect failure cannot undo or deny a known
irreversible effect; it records the truthful certainty, withholds completion, and
quarantines recovery. No best-effort event is acceptable as the only record of a
privileged transition.

## Replay and Simulation

`splendor-evidence::replay` produces a `ReplayPlan` or `SimulationPlan` from
access-filtered immutable Event, State, Evidence, and opaque Artifact references.
It does not call live owners during plan execution unless a separately
authorized read-only query is explicitly part of the plan.

The default mode is inspect-only. It may reconstruct stable trace order, state
lineage, append and commit outcomes, evidence completeness, message causality,
and effect certainty. Read-only policy/verifier re-evaluation and safe simulation
must use explicit non-live implementations and detached state. Replay and import
cannot:

- execute an adapter/driver/provider, network, filesystem, database, device, or
  external service;
- acquire a writer lease/fence or mutate a live State head;
- append a live event as though historical work happened again;
- refresh authority, approval, policy, work order, secret, or data-use state;
- convert historical evidence into current authority; or
- resolve `effect_uncertain` by assumption.

Stable 0.1 trace export and replay fixtures continue to consume the exact
`TraceEvent` projection. An envelope, imported state snapshot, evidence bundle,
or replay result is historical input only.

## C03 Prerequisite and Non-Ownership Boundary

This RFC provides only the generic owner coordinates C03 needs later:

- a durable Event coordinate and append receipt for a fixed event or owner
  record;
- a State partition/head coordinate with expected-head CAS and fencing;
- a typed Evidence item and bundle coordinate that preserves an Authority or
  Registry owner-specific evidence identity/digest plus an authenticated durable
  Evidence commit receipt; and
- explicit append, commit, publication, effect-certainty, and quarantine
  outcomes.

It does not define the Registry admission evidence schema, Authority historical
evidence schema, Registry lifecycle generation, C03 source/target proof bundle,
secret tick observation, C03 terminalization lease, secret publication protocol,
or proof-bound migration command. RFC 0014 remains authoritative for the exact
Authority/Registry/C03 proof join and migration ordering. Future Registry RFC
0016 and Authority RFC 0017 must define their own immutable record schemas and
owner attestations without redefining Event durability, State CAS/fencing, or
generic Evidence completeness.

C03 may later store owner-issued coordinates in its own records and require exact
cross-record equality. It may not mint those coordinates, infer them from a
database join, use a bare digest or timestamp as proof, mutate Event/State rows,
or treat Evidence completeness as migration authority. Authority remains the
sole migration decision owner. Registry remains the sole owner of Registry
admission/lifecycle facts. Event/State/Evidence proves only what was durably
recorded and what the named requirement supports.

For RFC 0014 proof-bound migration, a generic bundle, `complete`,
`demonstrated`, view, Event receipt, State receipt, or Evidence commit receipt is
never sufficient by itself. C03 must validate the exact RFC 0014 Authority
historical evidence record and owner authentication/attestation, the exact Driver
Registry admission/lifecycle evidence record and owner
authentication/attestation, the Evidence receipt's ordered source bindings, and
every required three-way identity/digest/scope/revision/lifecycle equality. A
memory-only, unsigned, untrusted, wrong-owner, wrong-tenant/scope/audience,
expired/revoked-key, substituted-source, incomplete, inaccessible, corrupt,
unavailable, or uncertain bundle/receipt denies migration with no live head move.

The C03 tick and migration paths remain disabled until:

1. this RFC is accepted;
2. the required behavior-free grammar and owner package slices exist;
3. durable append and State CAS/fencing pass their failure tests;
4. accepted `FND-003` ordering/recovery exists whenever State currentness or
   migration crosses independently committed owner/store boundaries;
5. separately authorized `EVT-002` writer/handoff work exists for any
   transferable Event writer or live legacy cutover the path needs;
6. Registry and Authority owner contracts, authenticated records, and trust paths
   exist;
7. the C03-specific integration has a separately reviewed implementation; and
8. stable 0.1 trace/state/replay compatibility tests pass.

A private C03/Authority table, kernel map, daemon projection, direct
`splendor-store` call, stable `TraceEvent` payload extension, or best-effort log
is not a substitute.

## Compatibility and Migration Plan

There is no flag-day replacement and no silent dual truth.

### Stable contracts preserved

- Existing `TraceEvent`, `TraceEventKind`, `TraceEventId`, run-local sequence,
  timestamp, identity context, event payload spelling, integrity facts, exports,
  and required tick order remain readable and projectable.
- Existing `TraceStore`/`AsyncTraceStore` callers and SQLite/in-memory records
  remain readable during migration. Their direct append interface is not
  sufficient for new privileged owner operations.
- Existing `StateNodeId`, parent lineage, state hash, runtime identity metadata,
  trace link, snapshot references, and state handoff records remain readable.
- Existing `StateGraph` read behavior remains available through a kernel
  compatibility projection. New owner writes are available only for fresh
  partitions created in the supported combined Store topology; this RFC does not
  live-migrate an existing separate state database.
- Existing trace export and inspect-only replay fixtures continue to observe the
  0.1 projection, not envelope implementation metadata.

### Sequenced migration

1. **Inventory and fixtures:** freeze representative stable 0.1 trace/state
   bytes, event hashes, ordering, state lineage, exports, replay reports, and
   failure cases before changing production wiring. Inventory does not make a
   record safe to import.
2. **Additive grammar:** add behavior-free versioned contract types and pure
   0.1 conversion/projection tests. No Store, kernel, daemon, or SDK writer
   changes occur in this step.
3. **Owner service:** create `splendor-evidence` and its ports. In-memory
   deterministic implementations prove owner semantics but are not privileged
   durability.
4. **Store adapter:** implement a new combined local SQLite engine capable of the
   owner-required Event and State transaction, expected sequence/head/fence,
   authenticated inbox/outbox, durability, integrity, permanent idempotency, and
   crash recovery while keeping semantic decisions out of Store. Existing
   separate databases are not silently attached to this transaction.
5. **Fresh-partition kernel facade:** route one bounded local path for a newly
   created partition through the owner and combined engine. Stable `TraceStore`
   and `StateGraph` facades project from that one canonical write; they do not
   independently dual-write or claim transfer from a legacy writer.
6. **Safe inspect-only import:** before copying any legacy record, run the
   versioned classification, schema, access, and pre-persistence leak scan over
   every payload-bearing trace/state field. A safe classified record may be
   copied with exact historical bytes, IDs, sequence, hashes, parents, and
   timestamps and receives only a historical non-live import receipt. It cannot
   acquire a writer binding or current authority.
7. **Quarantine unsafe legacy records:** a prohibited, secret-bearing, protected
   beyond the migration purpose, corrupt, or unclassifiable record is not copied
   into the new Event/State/Evidence store, gets no privileged durability or
   Evidence receipt, satisfies no C03 proof, and is excluded from generic
   replay/export. The legacy source remains in place under a separately
   authorized restricted forensic policy. The new store may retain only a
   non-reflecting quarantine result in an owner-restricted migration ledger with
   a safe source coordinate and reason code, never the prohibited bytes or an
   unsafe secret-derived digest. Generic reads cannot observe that ledger or use
   its presence as an existence oracle.
8. **No live legacy cutover:** current 0.1 trace and state databases are separate.
   Until separately authorized `EVT-002` supplies transferable Event writer
   handoff and accepted `FND-003` supplies the required cross-store/owner
   recovery and revocation ordering, they remain inspect-only migration sources.
   No marker, compatibility facade, import, or local mutex may switch an existing
   live partition, start a second writer, or claim atomic rollback.
9. **Dependent adoption:** Registry, Authority, and then C03 consume owner-issued
   immutable references in separately reviewed slices. They never backfill or
   rewrite the owner history.

If any safe projection differs in stable ID, sequence, kind, payload, order,
state parent/hash/link, or inspect-only replay behavior, import stops and the
source remains quarantined/read-only. Rollback before persisted new bytes may
remove an experimental slice. After a fresh owner partition has persisted bytes,
rollback may stop new mutation and retain read support, but it cannot activate a
legacy writer, move the writer, renumber facts, delete idempotency history, or
claim live rollback without the later `EVT-002`/`FND-003` protocols.

### Bounded non-transferable local Event writer

Before `EVT-002`, Event owner may create a fresh partition with one fixed
non-transferable local writer profile bound to one authenticated producer, tenant,
scope, process instance, combined Store identity, partition, epoch, opaque fence,
and deployment lifetime. The profile has no activate, rotate, transfer, renew,
handoff, import-as-live, cutover, rollback, or second-writer operation. Restart is
allowed only when the same Store and exact writer binding are recovered and no
other writer could have been admitted; uncertainty quarantines the partition.

This profile can prove local append/CAS mechanics and stable projection for fresh
partitions. It cannot preserve a live existing 0.1 writer through migration,
satisfy C03 proof-bound migration where transferable ownership is required,
serve fleet/resident transfer, or claim any part of `EVT-002` implementation.

## Security and Privacy

- All mutating calls require authenticated caller or internal principal,
  tenant/scope/audience checks, expiry where applicable, and audit attribution.
- Required authority, work order, policy, approval, quota, data-use, secret,
  safety, network/filesystem, capability, and postcondition verifiers remain
  independent. Event/Evidence never replaces them.
- Unknown privileged schema/profile/kind, unavailable required owner, missing
  append receipt, stale sequence/head/fence, unresolved effect certainty, and
  corrupt integrity fail closed.
- Event, State, and Evidence ingress uses bounded closed schemas and rejects
  prohibited material before persistence. Error codes and receipts do not echo
  rejected payloads.
- Tenant and visibility checks apply to payloads, references, cursors, conflict
  results, ranges, receipts, views, export, replay, and materialization.
- Mutation conflicts disclose no cursor, head, epoch, hash, existence bit, or
  tenant activity without separate dedicated read authority and audit. Hidden,
  absent, wrong-tenant/audience, stale, fenced, and substitution responses use one
  opaque profile and bounded timing class.
- Protected sources are represented by immutable references and approved
  digests, not copied into generic events or bundles. Access to a ref does not
  imply access to its target.
- Redacted views bind their source and omissions. Post-read redaction does not
  cure unsafe persistence.
- Private chain-of-thought is not a required or accepted generic Evidence item.
- Append receipts, state receipts, cursors, evidence bundles, support levels,
  digests, and replay results are non-authorizing.
- Outbox/inbox commands and acknowledgements require authenticated owner,
  producer, tenant, source-transaction, destination, audience, key/status, and
  complete intent binding before dedupe, append, or source visibility.
- Privileged idempotency/non-reuse records are permanent in this slice. Missing,
  compacted, corrupt, or unavailable history is never a fresh identity.
- Legacy bytes are classified and scanned before copy. Prohibited, secret-bearing,
  over-classified, corrupt, or unclassifiable records remain restricted in place
  and never enter new generic replay/export or C03 proof.
- C03 Evidence requires a durable authenticated commit receipt plus exact trusted
  RFC 0014 Authority/Registry source records; completeness or a bare digest is
  never enough.
- Replay remains inspect-only by default and cannot use historical authority or
  execute live side effects.

## Sequenced Implementation Plan, Tests, and Stop Conditions

Each slice is independently reviewable. Passing one slice does not authorize
skipping the next slice's dependencies or tests.

### Slice 1 - Behavior-free contract grammar

Scope:

- additive closed Event intent/envelope/append/batch/receipt/coordinate, State
  partition/eligibility/activation/binding/request/receipt/coordinate, and
  Evidence requirement/item/bundle/claim/commit/receipt/coordinate values in
  `splendor-types`;
- pure validation, canonical serialization, bounds, and 0.1
  TraceEvent/StateNode projection helpers; and
- no I/O, package owner service, Store, daemon, SDK, or runtime wiring.

Tests:

- positive canonical round trips and deterministic bytes;
- unknown/duplicate/null/oversize/wrong-ID/wrong-scope rejection;
- intent/envelope ownership and canonical digest tests reject caller-supplied
  recorded time, owner sequence/identity/integrity, and durability downgrade;
- Event, State activation/commit, and Evidence receipts cannot be constructed for
  mismatched request, owner, source, item, completeness, or commit digests;
- stable 0.1 trace IDs, sequences, kinds, payloads, event hashes, state IDs,
  parents, hashes, trace links, optional `escalation.triggered` position,
  `action.needs_intervention`, and post-verification
  `action.executed -> action.failed` project unchanged;
- independent mutation of every State/`StateCommitted` cross-binding field
  rejects with no valid value;
- missing mandatory Evidence items produce `incomplete`, and memory-only,
  unsigned/untrusted, wrong-owner/tenant/audience, missing or changed source
  attestation, revoked-key, or uncertain receipts cannot form a privileged/C03
  coordinate;
- opaque conflict values contain no current cursor/head/epoch/existence data; and
- receipts, refs, and bundles expose no authority conversion.

Stop conditions:

- stop until this RFC is accepted;
- stop on any new nominal ID or canonical-byte question still owned by
  `FND-001`;
- stop on any broad generated/migration requirement still owned by `FND-006`;
  and
- do not create `splendor-evidence`, change dependencies, or expose external
  APIs in this slice.

### Slice 2 - Owner service package

Scope:

- create `splendor-evidence` only after accepted package/dependency review;
- define Event, State, Evidence, and Replay/Simulation application ports and
  state machines;
- use deterministic in-memory test ports to prove semantics; and
- keep Authority, Artifact, Lineage, Gateway, daemon, and C03 behind narrow
  immutable fact/reference ports.

Tests:

- ordered append, expected-sequence conflict, idempotent duplicate, changed-byte
  conflict, stale epoch/fence denial, and uncertain append quarantine;
- fixed local Event writer restart recovers only the exact process/Store binding;
  process or Store mismatch, same epoch/different fence, caller-selected higher
  epoch, rotation, renewal, handoff, cutover, rollback, old/new dual-writer
  attempt, lost writer-record acknowledgement, and clock/status uncertainty all
  append nothing and fail closed before `EVT-002`;
- constrained same-partition/same-writer contiguous batch all-or-none behavior,
  complete duplicate acknowledgement, and whole-batch uncertainty;
- outbox/inbox wrong-principal, cross-tenant, wrong-audience, stale/revoked key,
  changed-command, forged-ack, and acknowledgement-loss denial/recovery;
- named partition isolation, expected-head CAS, one-winner concurrency, stale
  writer denial, State-owned activation, same-transaction
  revoke/expiry/higher-epoch versus CAS winners, detached replay/import denial,
  and no mutation on conflict;
- independently committed owner revocation, stale status snapshot, unavailable
  eligibility owner, or uncertain owner participation cannot be linearized by a
  State projection and leaves live activation/mutation unsupported pending
  `FND-003`;
- Evidence complete/incomplete/inaccessible/corrupt/unavailable and support-level
  ceilings plus authenticated durable commit/duplicate/conflict/uncertainty;
- permanent idempotency across restart, retention attempts, lost receipts,
  exact/changed replay, and corrupt/missing history;
- visibility filtering; byte/status/header and bounded timing-class equivalence
  for absent, hidden, wrong-tenant/audience, stale, fenced, and substituted
  opaque conflicts; audited restricted conflict views; and redacted-view omission
  integrity; and
- inspect-only ReplayPlan cannot select a live driver or writer.

Stop conditions:

- no production durability claim from in-memory tests;
- no Authority lease issuance before `AUTH-001`;
- no transferable Event writer, handoff, cutover, rollback, or `EVT-002`
  implementation;
- no live State mutation without the same-transaction status bridge or accepted
  `FND-003` protocol;
- no cached/projection-only status bridge is described or tested as equivalent to
  current independently owned authority;
- no Artifact/Lineage dereference before `ART-001`/`LIN-001`; and
- no daemon, SDK, C03, or broad producer migration.

### Slice 3 - Store adapter and durability

Scope:

- add persistence traits/engines only for owner-approved records;
- implement one combined local SQLite engine first with explicit transactions,
  WAL/sync policy, constrained batches, expected sequence/head/epoch/fence,
  authority-status generation, uniqueness, integrity, permanent idempotency,
  authenticated inbox/outbox persistence, Evidence commits, and crash recovery;
  and
- retain deterministic in-memory Store behavior clearly labeled
  `memory_only`.

Tests:

- power loss/process kill/disk full/commit error/sync error at every append,
  inbox, outbox, state node, event, and head-CAS boundary;
- no receipt before configured durability;
- owner/deployment durability floors cannot be downgraded by caller input;
- same-request recovery returns one original receipt;
- append, batch, State activation/commit, and Evidence uncertainty quarantine
  without replacement IDs;
- duplicate authenticated delivery causes one semantic append/mutation and forged
  delivery/acknowledgement causes none;
- State/Event owner derivation and every cross-field substitution fail atomically;
- revoke/expiry/status-generation/higher-epoch races inside the legal shared
  authoritative transaction have one winner; equivalent races against an
  independent owner are rejected as unsupported without `FND-003`;
- fixed local Event writer restart/lost-ack recovery preserves one binding, while
  same-epoch/different-fence, higher-epoch, handoff, cutover, rollback, and a
  second writer remain impossible before `EVT-002`;
- idempotency history survives restart and rejects deletion/compaction as fresh;
- Store enforces owner-supplied CAS but never decides transition policy; and
- corruption, integrity mismatch, stale sequence/head/fence, and cross-tenant
  reads fail closed.

Stop conditions:

- if node/event/head cannot share the required local atomic Store boundary, the
  state mutation path remains unsupported;
- if current authority/revocation status cannot linearize in that transaction or
  through accepted `FND-003`, live mutation remains unsupported;
- no exactly-once, cross-store atomicity, remote quorum, fleet sync, retention,
  or subscription claim; and
- no transferable writer or live legacy cutover before separately authorized
  `EVT-002` and required `FND-003` protocols.

### Slice 4 - Kernel compatibility and atomic composition

Scope:

- route one fresh-partition local kernel trace/state path through the owner and
  combined Store;
- preserve stable `TraceStore`, `StateGraph`, trace export, and replay facades as
  projections from one canonical owner write;
- run the full live verifier/final-authority chain, retain the final Gateway
  permit, then append verification and required-before-effect events in one
  all-or-none Event batch while that permit remains held, invalidating execution
  on append failure; and
- make state node, stable `StateCommitted`, and head CAS one supported local
  atomic operation.

Tests:

- complete stable tick line and exact 0.1 trace fixture equivalence, including
  optional escalation position, intervention, and post-verification
  executed-then-failed ordering;
- denied/verifier-failed/pre-effect-store-failed actions make zero adapter calls;
- verification-completed/pre-effect append occurs after the full final-live
  verifier allow and before adapter entry while the same permit is retained;
- permit-loss/expiry/revocation before adapter entry makes zero adapter calls and
  receipts cannot recreate the permit;
- state/event failure leaves old head current, starts no next tick, and reports
  no successful commit;
- failed/partial/uncertain sub-effects retain exact typed certainty, repeat no
  successful sub-effect, and retry only the same invocation when its retained
  contract proves the exact retry safe;
- known effect plus terminal-store failure is truthfully retained and withheld,
  never rewritten as no effect;
- restart and duplicate response return retained receipts without new IDs/times;
- safe legacy records preserve bytes/order/lineage in inspect-only import;
  synthetic secret, credential, protected-eval, PII, corrupt, and unclassifiable
  values across every payload-bearing trace/state field produce zero new-store
  payload bytes, no privileged receipt/C03 proof, and no generic replay/export;
- existing separate trace/state databases cannot enter live cutover, dual-write,
  or rollback topology; and
- inspect-only replay makes zero live adapter/owner mutations.

Stop conditions:

- no silent dual write or per-partition writer overlap;
- no live migration from separate legacy databases and no transferable writer
  without `EVT-002` plus required `FND-003` protocol;
- no daemon handler or Store becomes a second owner;
- no broad EventEnvelope producer migration; and
- no C03 path until Registry/Authority dependencies and independent security
  review are complete.

### Slice 5 - Dependent Registry, Authority, and C03 adoption

Scope:

- Registry RFC 0016 defines Registry-owned immutable admission/lifecycle
  evidence;
- Authority RFC 0017 defines Authority-owned historical/migration evidence;
- C03 later binds those owner records through generic Event/Evidence coordinates
  and uses State expected-head/fencing; and
- each owner retains its own commands, tables, receipts, and reconciliation.

Tests:

- exact owner-ID/digest/scope/revision equality and substitution denials;
- missing/inaccessible/stale/corrupt owner evidence produces incomplete/denied,
  never pass;
- memory-only, unsigned/untrusted, wrong owner/tenant/audience, changed
  subject/requirement/item set, missing exact RFC 0014 source attestation, or
  uncertain Evidence commit denies C03 use;
- stale head/fence and append failure create no C03 live migration;
- Event/Evidence unavailability creates no Authority or Registry shadow record;
- proof-bound migration reuses exact retained command identities across crash
  recovery and never invokes provider, node, Gateway, or driver effects; and
- stable trace/state/replay compatibility remains green.

Stop conditions:

- no Registry or Authority schema is defined by this RFC or the generic owner;
- no C03 migration, secret tick observation, or terminalization behavior is
  implemented under this assignment;
- no issue/task/component/gold completion claim without exact implementation and
  retained executable evidence.

## Required Review and Validation for Later Code

Every implementation slice requires independent architecture and security
review. Relevant tests include positive, denial, failure, restart, duplicate,
stale sequence, stale head, stale fence, revoke/expiry/CAS races, disk/sync
failure, non-downgradable durability, atomic batch failure, authenticated
outbox/inbox, permanent idempotency, partial/uncertain effects, Evidence receipt
and source-attestation substitution, opaque conflict equivalence, safe legacy
quarantine, unsupported independent-owner revocation races, `EVT-002` lifecycle
stops, visibility/redaction, inspect-only replay, compatibility projection, and
dependency-direction evidence. A passing static architecture check or docs-only
RFC is never runtime evidence.

Gold targets named by the catalog, including `G00`, `G02`, `G03`, `G04`, `G05`,
`G23`, `G26`, `G29`, `G42`, `G47`, `G72`, `G83`, and `G87`, remain
`not_exercised` until their exact executable harnesses run and retain passing
evidence. This RFC does not change any gold status.

## Non-Goals and Explicit Non-Claims

This RFC does not implement or authorize:

- broad `EventEnvelope` producer/consumer migration;
- fleet-global ordering, remote trace sync, subscriptions, cursor platform,
  backpressure, retention, compaction, archive, or observability product;
- an analytics warehouse, arbitrary topic bus, arbitrary state service, global
  mutable memory, automatic merge, or distributed consensus;
- a full outbox ecosystem, distributed exactly-once delivery, cross-store
  atomicity, or remote durability quorum;
- a cross-owner revocation/CAS protocol, projection-based substitute, or any
  implementation/completion of `FND-003`;
- transferable Event writer activation, handoff, live cutover/rollback, or any
  implementation/completion of `EVT-002` / #272;
- Artifact Registry, Lineage Service, Authority, Registry, gate, approval,
  workload, run, or agent lifecycle schemas;
- raw protected-payload storage, secret storage, private chain-of-thought, or
  post-read redaction as an ingress control;
- driver/Gateway changes, provider execution, side-effect bypass, or automatic
  retry of failed, partial, or uncertain effects without retained exact
  same-invocation retry-safety proof;
- daemon endpoints, SDK/client surfaces, CLI commands, generated schemas,
  package dependencies, Store migrations, or runtime code;
- RFC 0012 C03 tick observations, terminalization, projection, publication, or
  secret lifecycle records;
- RFC 0014 proof-bound C03 runtime migration or its Authority/Registry record
  schemas;
- full `FND-002`, `EVT-001`, `EVT-002`, `EVT-003`, `STA-001`, `STA-002`, or
  `EVID-001` completion;
- any component completion, issue closure, gold pass, conformance pass, release
  readiness, or production certification; or
- self-acceptance of this RFC.

## Acceptance Effect

If accepted by the repository's independent RFC process, this document becomes
the owner and migration contract for the bounded slices above. Acceptance alone
still changes no behavior. Code may proceed only in dependency-safe slices with
the required tests, documentation, compatibility fixtures, retained validation,
and stop conditions. Until then, current stable 0.1 runtime behavior remains the
only implemented contract.
