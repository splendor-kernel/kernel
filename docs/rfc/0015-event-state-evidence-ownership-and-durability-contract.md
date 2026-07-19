# RFC 0015 - Event, State, and Evidence Ownership and Durability Contract

## Status and Binding

**Status:** Proposed

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
[RFC 0010](0010-authority-service-contract.md),
[RFC 0012](0012-secret-broker-contract.md),
[RFC 0013](0013-driver-operation-credential-sink-contract.md),
[RFC 0014](0014-revision-bound-secret-credential-authorization.md), and the
[stable 0.1 primitive contract](../spec/0.1/primitives.md)

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
| `EVT-003` / #273 | Expected-sequence/fence append request, durable receipt, idempotency, bounded outbox/inbox, and effect-certainty outcomes | Full `EventStore`, every backend, all service outboxes, broad delivery ecosystem, and all fault-injection completion evidence |
| `STA-001` / #279 | Named state partition, explicit owner/scope/schema/classification, and mandatory expected head | All standard domain profiles, world-state semantics, retention platform, arbitrary state service, and domain ontology |
| `STA-002` / #280 | CAS head movement, writer epoch/fence validation, immutable commit, explicit conflict, and no-mutation results | Authority lease issuance, fleet handoff, automatic merge, every controller adoption, and complete migration evidence |
| `EVID-001` / #287 | Typed bundle/item/claim/completeness/support grammar and immutable owner references | Materialization service, causal closure, signatures, every requirement profile, Artifact/Lineage implementation, and gate adoption |

The following required collaborators remain unmet or separately owned:

| Dependency | Why it remains separate and blocking |
| --- | --- |
| `FND-001` | Owns canonical nominal ID and schema grammar. This RFC does not redefine existing IDs or independently finalize new ID wire forms. |
| `FND-003` | Owns the generic command-decision-event transaction pattern and recoverable cross-owner mutation protocol. This RFC defines only the minimum owner-local append and state/event atomicity requirement. |
| `FND-006` | Owns broad schema migration, generated parity, and compatibility discipline. This RFC pins the 0.1 projection but does not complete cross-language migration. |
| `AUTH-001` | Owns capability/authority semantics and the authority facts used to issue or revoke a writer lease. Evidence validates a supplied trusted lease/fence; it does not grant one. |
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
| Event | `EventEnvelope`, `EventPartition`, `EventCoordinate`, `EventAppendRequest`, `EventAppendOutcome`, `EventAppendReceipt`, `EventDurability`, `EventIntegrity`, bounded publication command/acknowledgement values | Profile admission, partition order, writer epoch/fence, idempotency, durability, integrity, append outcome, inbox reconciliation |
| State | `StatePartition`, `StateHead`, `WriterLease`, `WriterFence`, `StateMutationRequest`, `StateMutationOutcome`, `StateCommitReceipt`, `StateCommitCoordinate` | Partition policy, trusted lease/fence acceptance, expected-head validation, immutable commit, head CAS, state/event composition |
| Evidence | `EvidenceRequirement`, `EvidenceItem`, `EvidenceBundle`, `EvidenceCompleteness`, `EvidenceClaim`, `EvidenceSupportLevel`, `EvidenceBundleCoordinate`, `EvidenceView` | Requirement evaluation, completeness, claim-support ceiling, owner-reference validation, access-filtered/redacted view construction |
| Replay/simulation | `ReplayPlan`, `SimulationPlan`, result/report references | Inspect/read-only planning, detached simulation constraints, live-effect and live-head prohibition |

These are contract-family names, not accepted stable wire spellings. Existing
nominal IDs are reused exactly where the compatibility profile requires them.
Any new nominal ID, schema constant, canonical byte grammar, or cross-language
binding remains blocked on `FND-001` and `FND-006`; implementations may not fill
that gap with string aliases or private duplicate types.

## Event Contract

### Event envelope family

The public contract is a versioned `EventEnvelope` family. The first
implementation must use an explicit versioned type rather than mutate
stable `TraceEvent` in place. Its minimum semantic fields are:

| Field family | Required rule |
| --- | --- |
| `schema_version` and `profile` | Closed envelope version and one registered owner profile. Unknown privileged profiles reject. |
| `event_id` | One nominal event identity. For the 0.1 compatibility profile it is exactly the existing `TraceEventId`; no second identity is minted. New identity grammar waits for `FND-001`. |
| `partition` | Typed partition identity and exact tenant/run/owner scope. It never implies authority. |
| `sequence` | Monotonic `u64` within the partition. It is not a fleet-global order. |
| `writer_epoch` and `fence` | Positive owner epoch plus opaque fencing binding for a live ordered writer. Stable local compatibility may use a non-transferable local epoch profile; it cannot satisfy fleet or C03 authority. |
| `producer` and `scope` | Exact authenticated producer reference and bounded identity scope. Producer identity does not grant event or action authority. |
| `occurred_at` and `recorded_at` | Distinct timestamps. Occurrence time is producer-supplied evidence; recorded time is owner-assigned and cannot establish causality by itself. |
| `kind_schema` and `kind` | Registered owner kind and closed payload schema. Event kinds cannot carry hidden authority. |
| `payload` | Exactly one bounded inline typed payload or immutable opaque payload reference. Protected payload copying is forbidden. |
| `causal_parents` | Bounded immutable event coordinates with relation types. Missing or inaccessible parents remain explicit. |
| `correlation_refs` | Bounded non-authorizing references for queries. They do not affect order or permission. |
| `visibility` | Closed classification and audience policy reference enforced on reads and projections. |
| `durability_class` | `required_before_effect`, `required_after_effect`, `best_effort_telemetry`, or `derived_export_only`. |
| `integrity` | Canonical event digest, previous-partition digest when applicable, algorithm/version, and any owner integrity revision. |

The envelope must not contain raw secrets, private chain-of-thought, credentials,
approval tokens, live capability material, unrestricted protected payloads, or
provider-specific arbitrary data. A payload reference is not permission to
dereference the target.

### Stable `TraceEvent` compatibility profile

`TraceEventCompatibilityProfileV0_1` is the required compatibility projection.
For every stable 0.1 trace event:

1. `event_id` is exactly `TraceEvent.trace_event_id`.
2. The partition is the `agent_run` compatibility partition for the exact
   `run_id`.
3. `sequence` is exactly `TraceEvent.sequence`; migration never renumbers it.
4. `occurred_at` is exactly `TraceEvent.timestamp`.
5. Scope and identity preserve the complete `TraceEvent.identity` values.
6. Kind and payload preserve the exact `TraceEventKind` variant, field names,
   values, and serialized spelling.
7. The stable serializer and export projection emit the same 0.1 `TraceEvent`
   bytes. Envelope-only fields are not injected into those bytes.
8. Existing event hashes remain valid historical integrity facts. An envelope
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
action.executed | action.denied | action.failed | action.needs_approval
outcome.recorded
state.committed
tick.completed
```

Existing Rust variant names and public event spellings remain the source for that
stable line. This RFC does not rename a `TraceEventKind`, change deterministic
`TraceEventId::from_run_sequence`, alter run-local ordering, or add C03 metadata
to `CandidatesProposed { actions }`. New C03 or v2 events are separate typed
profiles linked causally to stable events.

### Append request

`EventAppendRequest` contains exactly the following semantic families:

- one complete validated `EventEnvelope`;
- the exact partition and `expected_next_sequence`, including zero for genesis;
- the expected previous integrity digest or explicit genesis marker;
- the writer epoch and fencing binding;
- one caller-supplied idempotency key bound to the producer, partition, operation,
  and canonical request digest;
- the requested durability guarantee and event durability class; and
- bounded command, causal, and audit attribution references.

The owner validates the complete envelope and request before calling Store. It
does not read a latest sequence and silently retry with that value. A stale
sequence, epoch, fence, previous digest, or changed idempotent request is a
conflict with no append.

### Durability guarantees

The first contract slice supports these result levels:

| Level | Meaning | Privileged use |
| --- | --- | --- |
| `memory_only` | Accepted by a deterministic in-memory test engine; process loss may lose it | Tests and explicitly non-durable local simulation only; never satisfies required privileged evidence |
| `transaction_committed` | Owner store transaction committed under the configured crash-recovery contract | May satisfy a required event only when the deployment policy explicitly names this level |
| `storage_barrier_confirmed` | Transaction committed and the configured backend synchronization barrier returned success | Required when the event profile or deployment policy demands storage synchronization |

The request names the minimum level. The receipt names both configured and
achieved levels plus the backend policy revision. The owner returns success only
when achieved durability is at least the requested level. Queued, buffered,
replicating, or exporter-accepted bytes are not durable unless the selected level
explicitly and truthfully defines them as such. A remote replica or quorum is not
implied by either local level.

### Append receipt and outcomes

`EventAppendReceipt` is immutable and contains:

- receipt schema/version and nominal receipt identity authorized by `FND-001`;
- exact request digest and idempotency-key digest;
- event ID, partition, sequence, writer epoch, and fencing digest;
- previous and committed event integrity digests;
- configured and achieved durability levels and backend policy revision;
- owner identity/revision and owner-assigned commit time; and
- the exact visibility/classification reference of the stored event.

The closed append outcome family is:

| Outcome | Semantics |
| --- | --- |
| `appended(receipt)` | New event committed at the exact requested coordinate and durability. |
| `duplicate(original_receipt)` | The same idempotency key, request digest, event ID, and canonical bytes were already committed. The original receipt is returned unchanged. |
| `conflict(actual_cursor)` | Expected sequence, previous digest, epoch/fence, event identity, or idempotency binding differs. No append occurred. The returned cursor is non-authorizing and access-filtered. |
| `rejected(code)` | Closed schema, scope, visibility, bound, or policy validation failed before Store mutation. |
| `failed_no_append(code)` | Store proved no append committed. |
| `append_outcome_uncertain(recovery_ref)` | Store cannot prove commit or absence. No success receipt is fabricated; the partition is quarantined until same-request lookup/reconciliation resolves it. |

An uncertain append cannot be retried under a new event ID, sequence,
idempotency key, or payload. Recovery queries the same owner using the retained
request identity and digest. An `EventAppendReceipt`, cursor, or duplicate result
never authorizes a caller, state transition, or external effect.

## Transactional Outbox and Inbox Boundary

Cross-owner publication uses at-least-once delivery with idempotent consumption.
It does not claim distributed exactly-once or a transaction spanning independent
stores.

The minimum behavior-free family is:

- `OwnerOutboxEntry`: source owner, source transaction/revision, immutable
  publication command, canonical command digest, idempotency key, destination
  owner/audience, attempt metadata, and state `pending | acknowledged |
  quarantined`;
- `EventPublicationCommand`: one or a bounded batch of complete append requests
  whose event IDs and bytes were fixed by the source owner before publication;
- `EventInboxRecord`: destination owner, command identity/digest, source owner,
  first-seen time, append result, and original receipt references; and
- `EventPublicationAcknowledgement`: immutable binding from the command to every
  original append receipt or one terminal rejection/conflict result.

The source service writes its own state change and unique outbox row in one
source-owner transaction when publication follows a source mutation. Delivery is
at least once. Event owner commits inbox deduplication and event append in one
Event-owner transaction. Exact duplicate delivery returns the original
acknowledgement. Same command ID or idempotency key with changed bytes is an
invariant conflict and quarantines the command. A lost acknowledgement causes
lookup or redelivery of the same command; it never causes new event bytes or a
second source mutation.

If source state and outbox cannot share one local atomic boundary, the source
mutation must remain uncommitted or unavailable until an explicit `FND-003`
recoverable protocol exists. If Event inbox and Event append cannot share one
local atomic boundary, the append path is unsupported and fails closed. No
implementation may describe two independent Store commits as a transaction.

Outbox backlog, failed delivery, retention pressure, and acknowledgement
uncertainty are visible owner states. They are never silently dropped or reported
as completed. Cross-boundary delivery is at-least-once; idempotent handling and
unique event identity prevent duplicate semantic mutation.

## Effect Certainty and Quarantine

Every privileged operation that may cause an external effect records one closed
certainty state:

| State | Meaning |
| --- | --- |
| `no_effect` | The owner proved the adapter/driver/provider boundary was not entered or proved no effect occurred. |
| `effect_succeeded` | A trusted bounded result proves the one identified effect succeeded. |
| `effect_failed` | A trusted bounded result proves the one identified effect did not succeed; partial effects are separately represented. |
| `effect_uncertain` | Timeout, process loss, provider ambiguity, or missing trustworthy result prevents proving success or failure. |

Effect certainty is independent of event durability. An effect can be known to
have succeeded while its required-after-effect publication remains pending; that
operation is not publicly complete and remains quarantined. An irreversible
`effect_uncertain` result is never rewritten as success or failure. It is never
retried automatically under a fresh invocation, action, request, event, or
idempotency identity. Recovery may only inspect the retained invocation and
query a separately authorized idempotent status operation when such an operation
is part of the driver contract. Otherwise intervention is required.

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

### Writer lease, epoch, and fence

The behavior-free `WriterLease` and `WriterFence` family represents the
validated writer binding consumed by State owner. It contains:

- lease/reference identity and immutable digest;
- issuing owner and authority evidence reference;
- principal plus agent/workload instance binding;
- exact partition and expected head revision/node;
- positive writer epoch and opaque fencing token digest;
- allowed transition schema set;
- not-before, expiry, audience, and revocation/status evidence; and
- validation time and validation policy revision.

Authority/Agent/Workload owners issue, renew, or revoke their grants under later
contracts. State Service alone decides whether the supplied binding is current
for its partition and whether its epoch/fence may move that head. Missing,
expired, revoked, unavailable, wrong-audience, wrong-partition, wrong-schema,
stale-epoch, or ambiguous lease evidence denies with no mutation. A
process-local mutex is not a writer lease. Replay, simulation, imported
snapshots, evidence bundles, and state references cannot acquire a live writer
binding.

The owner allocates monotonically increasing epochs for ownership handoff. Once a
higher epoch is accepted, every lower epoch remains fenced even if its original
expiry has not elapsed. Fencing is checked in the same Store CAS that moves the
head; a preflight check alone is insufficient.

### State mutation request

`StateMutationRequest` contains:

- command identity, canonical request digest, and idempotency key;
- exact partition descriptor revision;
- exact expected head revision and expected `StateNodeId` or explicit genesis;
- validated writer lease/reference, epoch, and fence;
- one closed transition schema and typed state payload or opaque immutable
  payload reference;
- parent node identities, next state hash, and immutable commit metadata;
- causal event/evidence references and required `StateCommitted` compatibility
  event; and
- requested durability and audit attribution.

The expected head is mandatory. Absence never means "use latest". The model or
caller cannot choose a broader partition or writer. Protected payload bytes are
admitted only after schema, classification, access, and pre-persistence secret
checks.

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
| `committed(receipt)` | Immutable node, required event, and head CAS reached configured durability at the exact expected head/fence. |
| `duplicate(original_receipt)` | The exact command/request digest already committed; no new node, event, head revision, or time is allocated. |
| `head_conflict(actual_head)` | Expected revision/node is stale; no mutation. Actual head is access-filtered and non-authorizing. |
| `fenced(actual_epoch)` | Writer epoch/fence is stale or invalid; no mutation. |
| `lease_denied(code)` | Writer binding is absent, expired, revoked, unavailable, wrong-scope, or wrong-schema; no mutation. |
| `rejected(code)` | Closed schema, parent, hash, classification, or transition validation failed; no mutation. |
| `failed_no_mutation(code)` | Store proved the immutable node/event/head transaction did not commit. |
| `commit_outcome_uncertain(recovery_ref)` | Store cannot prove commit or absence; partition is quarantined and same-command recovery is required. |

The `StateCommitReceipt` binds command/request digest, partition, descriptor
revision, previous and new heads, immutable node and state hash, writer
epoch/fence, required event append receipt, achieved durability, owner revision,
and commit time. It is evidence of one state transition, not authority to make
another.

### State/event atomicity

For the first local implementation, immutable node persistence, required stable
`StateCommitted` append, and head CAS must use one Store transaction supplied to
and interpreted by State/Event owner code. The transaction checks expected head
and current fence, writes the immutable node and event, advances the head, and
returns both receipts only after configured durability. Any failure commits
none of those visible facts.

If a deployment uses independent State and Event stores without a shared atomic
engine boundary, this local operation is unsupported until `FND-003` or a later
accepted RFC defines a recoverable publication barrier. Such a deployment must
fail closed before a live head move. It must not move the head and then append
best-effort, append a false `StateCommitted` before CAS, or call two commits
"atomic". A prepared immutable node may exist only as owner-internal non-live
state and cannot be returned as current, admitted to the next tick, or projected
as `StateCommitted`.

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

### Durable evidence coordinates

The owner issues immutable coordinates sufficient for later C03 proof binding:

- `EventCoordinate`: event identity, partition, sequence, writer epoch, event
  schema, canonical event digest, and append receipt reference;
- `StateCommitCoordinate`: partition, descriptor/head revision, state node and
  state hash, writer epoch/fence digest, required event coordinate, and commit
  receipt reference; and
- `EvidenceBundleCoordinate`: bundle identity, requirement profile/version,
  subject digest, completeness code, canonical bundle digest, owner revision,
  and optional attestation reference.

Exact names and nominal ID wire forms that do not already exist wait for
`FND-001`. Coordinates never use a bare digest, cursor, timestamp, database row,
or "latest" lookup as identity. They are immutable facts and cannot move a live
head, authorize C03 migration, or grant payload visibility by themselves.

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
   work-order/capability, data-use, policy, approval, quota, and current owner
   state. Unavailable required checks deny, pause, quarantine, or request
   intervention.
2. Fix command, action/invocation, idempotency, event, and causal identities and
   canonical request digests. Retries reuse them.
3. Append every `required_before_effect` event and obtain owner receipts at the
   configured durability. Failure or uncertainty prevents Gateway/adapter entry.
4. Run the complete Gateway/verifier chain against current inputs. A verifier
   cannot treat an Event or Evidence receipt as authority.
5. Execute at most the one bounded adapter/driver invocation under its retained
   effect identity and idempotency contract.
6. Record the trusted result and explicit effect-certainty state. An ambiguous
   result becomes `effect_uncertain` and is quarantined.
7. Append required terminal events and, when state changes, perform the atomic
   State/Event transaction at the exact expected head/fence.
8. Return or publish a terminal result only after every required event, state
   head, and owner receipt reaches configured durability. Otherwise retain the
   known effect result privately and quarantine publication/retry.

For a privileged state-only mutation, steps 1-3 still apply where pre-decision
evidence is required, then State owner validates the exact expected head/fence
and performs the immutable node, required event, and head CAS in one supported
atomic boundary. No external effect occurs.

### Crash-point table

| Crash or uncertainty point | Required recovery and visible result |
| --- | --- |
| Before command/idempotency claim | No command fact or effect exists. An authenticated retry may submit the same logical request and establish one identity. |
| After command claim, before required-before-effect append | Resume only the retained command and identities. No adapter/driver entry is allowed. |
| After pre-effect receipt, before Gateway entry | No effect. Same-command recovery may revalidate current authority and either continue or append a terminal denial/cancellation. |
| During verifier evaluation | No effect. Uncertain or unavailable required verifier fails closed and records no allow. |
| During external invocation | Use the retained invocation and driver idempotency contract. If absence/success/failure cannot be proven, record `effect_uncertain`, quarantine, and do not repeat an irreversible effect. |
| After known effect, before terminal append | Retain `effect_succeeded` or `effect_failed` privately. Recover publication under the same identities only; never execute the effect again. Public completion remains closed. |
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
  Registry owner-specific evidence identity and digest; and
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

The C03 tick and migration paths remain disabled until:

1. this RFC is accepted;
2. the required behavior-free grammar and owner package slices exist;
3. durable append and State CAS/fencing pass their failure tests;
4. Registry and Authority owner contracts and records exist;
5. the C03-specific integration has a separately reviewed implementation; and
6. stable 0.1 trace/state/replay compatibility tests pass.

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
- Existing `StateGraph` behavior remains available through a kernel
  compatibility facade for stable local 0.1 callers while its writes delegate to
  the one State owner.
- Existing trace export and inspect-only replay fixtures continue to observe the
  0.1 projection, not envelope implementation metadata.

### Sequenced migration

1. **Inventory and fixtures:** freeze representative stable 0.1 trace/state
   bytes, event hashes, ordering, state lineage, exports, replay reports, and
   failure cases before changing production wiring.
2. **Additive grammar:** add behavior-free versioned contract types and pure
   0.1 conversion/projection tests. No Store, kernel, daemon, or SDK writer
   changes occur in this step.
3. **Owner service:** create `splendor-evidence` and its ports. In-memory
   deterministic implementations prove owner semantics but are not privileged
   durability.
4. **Store adapter:** implement owner-required SQLite transaction, expected
   sequence/fence, inbox/outbox, durability, integrity, and crash recovery while
   keeping persistence decisions out of Store.
5. **Kernel facade:** route one bounded local path through the owner. Stable
   `TraceStore` and `StateGraph` facades project from that one canonical write;
   they do not independently dual-write.
6. **One-time import:** when existing databases need owner metadata, an explicit
   versioned importer validates each legacy record, preserves original bytes,
   IDs, sequence, hashes, parents, and timestamps, and emits a migration report.
   Imported facts are historical and cannot acquire a live writer lease.
7. **Cutover:** per partition, one durable cutover marker selects exactly one
   canonical writer. Before the marker, the legacy compatibility adapter owns
   writes through the owner facade; after it, the new owner store does. Both
   writers are never active for the same partition.
8. **Dependent adoption:** Registry, Authority, and then C03 consume owner-issued
   immutable references in separately reviewed slices. They never backfill or
   rewrite the owner history.

If any projection differs in stable ID, sequence, kind, payload, order, state
parent/hash/link, or inspect-only replay behavior, cutover stops. Rollback before
persisted new bytes may remove an experimental slice. After new owner bytes
exist, rollback retains read support and moves writers only through another
explicit fenced migration; it never makes duplicate legacy and new writers
current.

### Local compatibility writer

The existing local-only runtime may use an owner-issued, non-transferable local
writer epoch tied to one process instance and one explicit partition. This
preserves local 0.1 operation while adding expected-sequence/head checks. It is
not a fleet lease, cannot survive transfer as live authority, cannot satisfy C03
proof-bound migration, and cannot be used when `AUTH-001` or distributed fencing
is required.

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
- Protected sources are represented by immutable references and approved
  digests, not copied into generic events or bundles. Access to a ref does not
  imply access to its target.
- Redacted views bind their source and omissions. Post-read redaction does not
  cure unsafe persistence.
- Private chain-of-thought is not a required or accepted generic Evidence item.
- Append receipts, state receipts, cursors, evidence bundles, support levels,
  digests, and replay results are non-authorizing.
- Replay remains inspect-only by default and cannot use historical authority or
  execute live side effects.

## Sequenced Implementation Plan, Tests, and Stop Conditions

Each slice is independently reviewable. Passing one slice does not authorize
skipping the next slice's dependencies or tests.

### Slice 1 - Behavior-free contract grammar

Scope:

- additive closed Event append/receipt/coordinate, State
  partition/head/request/receipt/coordinate, and Evidence
  requirement/item/bundle/claim/coordinate values in `splendor-types`;
- pure validation, canonical serialization, bounds, and 0.1
  TraceEvent/StateNode projection helpers; and
- no I/O, package owner service, Store, daemon, SDK, or runtime wiring.

Tests:

- positive canonical round trips and deterministic bytes;
- unknown/duplicate/null/oversize/wrong-ID/wrong-scope rejection;
- event receipt and state receipt cannot be constructed for mismatched
  request/commit digests;
- stable 0.1 trace IDs, sequences, kinds, payloads, event hashes, state IDs,
  parents, hashes, and trace links project unchanged;
- missing mandatory Evidence items produce `incomplete`; and
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
- named partition isolation, expected-head CAS, one-winner concurrency, stale
  writer denial, detached replay/import denial, and no mutation on conflict;
- Evidence complete/incomplete/inaccessible/corrupt/unavailable and support-level
  ceilings;
- visibility filtering and redacted-view omission integrity; and
- inspect-only ReplayPlan cannot select a live driver or writer.

Stop conditions:

- no production durability claim from in-memory tests;
- no Authority lease issuance before `AUTH-001`;
- no Artifact/Lineage dereference before `ART-001`/`LIN-001`; and
- no daemon, SDK, C03, or broad producer migration.

### Slice 3 - Store adapter and durability

Scope:

- add persistence traits/engines only for owner-approved records;
- implement SQLite first with explicit transactions, WAL/sync policy, bounded
  batches, expected sequence/epoch/fence, uniqueness, integrity, read range,
  inbox/outbox persistence, and crash recovery; and
- retain deterministic in-memory Store behavior clearly labeled
  `memory_only`.

Tests:

- power loss/process kill/disk full/commit error/sync error at every append,
  inbox, outbox, state node, event, and head-CAS boundary;
- no receipt before configured durability;
- same-request recovery returns one original receipt;
- append uncertainty and state uncertainty quarantine without replacement IDs;
- duplicate delivery causes one semantic append/mutation;
- Store enforces owner-supplied CAS but never decides transition policy; and
- corruption, integrity mismatch, stale sequence/head/fence, and cross-tenant
  reads fail closed.

Stop conditions:

- if node/event/head cannot share the required local atomic Store boundary, the
  state mutation path remains unsupported;
- no exactly-once, cross-store atomicity, remote quorum, fleet sync, retention,
  or subscription claim; and
- no production cutover until compatibility fixtures pass.

### Slice 4 - Kernel compatibility and atomic composition

Scope:

- route one local kernel trace/state path through the owner;
- preserve stable `TraceStore`, `StateGraph`, trace export, and replay facades as
  projections from one canonical owner write;
- make required-before-effect append fail before adapter entry; and
- make state node, stable `StateCommitted`, and head CAS one supported local
  atomic operation.

Tests:

- complete stable tick line and exact 0.1 trace fixture equivalence;
- denied/verifier-failed/pre-effect-store-failed actions make zero adapter calls;
- state/event failure leaves old head current, starts no next tick, and reports
  no successful commit;
- irreversible timeout becomes `effect_uncertain`, is quarantined, and is not
  retried under a new identity;
- known effect plus terminal-store failure is truthfully retained and withheld,
  never rewritten as no effect;
- restart and duplicate response return retained receipts without new IDs/times;
- legacy database import and rollback preserve bytes/order/lineage; and
- inspect-only replay makes zero live adapter/owner mutations.

Stop conditions:

- no silent dual write or per-partition writer overlap;
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
stale sequence, stale head, stale fence, disk/sync failure, effect uncertainty,
visibility/redaction, inspect-only replay, compatibility projection, and
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
- Artifact Registry, Lineage Service, Authority, Registry, gate, approval,
  workload, run, or agent lifecycle schemas;
- raw protected-payload storage, secret storage, private chain-of-thought, or
  post-read redaction as an ingress control;
- driver/Gateway changes, provider execution, side-effect bypass, or automatic
  retry of uncertain irreversible effects;
- daemon endpoints, SDK/client surfaces, CLI commands, generated schemas,
  package dependencies, Store migrations, or runtime code;
- RFC 0012 C03 tick observations, terminalization, projection, publication, or
  secret lifecycle records;
- RFC 0014 proof-bound C03 runtime migration or its Authority/Registry record
  schemas;
- full `FND-002`, `EVT-001`, `EVT-003`, `STA-001`, `STA-002`, or `EVID-001`
  completion;
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
