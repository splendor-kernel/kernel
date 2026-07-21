# RFC 0020 - C03 Foundation Compatibility and Migration Profile

## Status and Binding

**Status:** Accepted planning contract

**Date:** 2026-07-21

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`a1e94f7df3e2778bf9e1e3724a54398e1141831ef54045ad8d969a93f5c9b561`

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program:** `V2-FND-0 Foundations`

**Catalog task:** `FND-006` / [issue #225](https://github.com/splendor-kernel/kernel/issues/225)

**Required dependencies:** `FND-001` and `FND-002`

**Primary functional requirements:** `FR-0.2-01` and `FR-0.2-08`

**Constrained and preserved requirements:** `FR-0.2-02` and the stable 0.1
compatibility line

**Gold targets:** `G00` and `G72`

**Gold status:** both remain `specified_not_implemented` / `not_exercised`;
this RFC changes no status

**Normative inputs:** [AGENTS.md](../../AGENTS.md), the
[active roadmap](../rules/sprints_frs_milestones.md), the
[v2 task catalog](../rules/v2/catalog/complete_implementation_task_catalog.md),
the [machine-readable task catalog](../rules/v2/catalog/architecture/implementation_tasks.yaml),
the [foundation readiness checkpoint](../rules/v2/foundation-readiness.md), the
[clean architecture rules](../rules/v2/architecture/clean-architecture-rules.md),
the [0.1 schema versioning policy](../spec/0.1/schema-versioning.md), the
[0.1 to 0.2/v2 schema and identity map](../rules/v2/architecture/schema-identity-map.md),
[RFC 0012](0012-secret-broker-contract.md),
[RFC 0018](0018-c03-foundation-grammar-profile.md), and
[RFC 0019](0019-command-decision-event-outbox-recovery-contract.md)

This RFC is documentation-only and planning-only. It changes no Rust or Store
behavior, public or generated contract, compatibility enum, schema
registration, protocol, capability endpoint, daemon route, SDK, migration,
owner record, persistence format, task status, issue status, conformance status,
Gold status, or release claim. It does not complete `FND-006`, `G00`, `G72`,
C03, or any dependent task.

## Decision and Summary

Splendor adopts one bounded compatibility and migration discipline for the C03
foundation boundary. It applies now only as a planning rule over:

- the implemented stable 0.1 contracts, including explicitly implemented
  adapters and aliases;
- the implemented RFC 0018 Slice 1A behavior-free lexical and declaration-digest
  values; and
- future owner-specific C03 records, protocols, generated surfaces, and Store
  migrations only after their separate accepted annexes register exact schemas,
  owners, explicitly pinned canonical bytes, and legality.

Every change has exactly one primary semantic compatibility class from the six
closed classes in this RFC. If multiple classes apply, the change must satisfy
the union of their obligations and use the most restrictive disposition. An
unknown or unclassified change is treated as `security_critical` and
`reject_fail_closed` for live use.

Every input receives exactly one of four closed dispositions:
`accept_current`, `accept_alias_emit_canonical`, `reject_fail_closed`, or
`preserve_opaque_non_live`. Parsing, lexical validity, preservation, capability
advertisement, historical explanation, and possession of a digest or receipt do
not establish registration, currentness, trust, authority, durability, or
permission to execute.

No component may silently coerce N-1, N, N+1, alias, absent, null, defaulted,
unknown, historical, or opaque bytes into another semantic version. Unknown
authorizing or security-critical content never drops, defaults, narrows by
guessing, or downgrades into an allow.

## Current Truth

The following inventory is the complete implementation truth relevant to this
RFC. Planning tables and reserved names are not implementation evidence.

| Surface | Current truth | Compatibility consequence |
| --- | --- | --- |
| Stable 0.1 primitive contracts | Stable names, required fields, documented enums, distinct identities, non-authorizing extension policy, Gateway mediation, explicit State, ordered Trace, and side-effect-free replay defaults are implemented compatibility inputs. Some stable 0.1 and accepted owner contracts explicitly pin exact bytes; other serializers expose current observed production serialization without a repository-wide canonical-byte registration. | Existing meanings and explicitly pinned bytes stay unchanged. Other output is characterized as observed production serialization/behavior and is not elevated by this RFC into a newly registered canonical contract. Replacement requires an accepted RFC, a new registered version or explicit adapter, and retained fixtures. |
| Stable aliases and adapters | [`trace.rs`](../../crates/splendor-types/src/trace.rs) implements `TraceEvent` acceptance of `trace_id` as an input alias for `trace_event_id` and emits only `trace_event_id`. The stable docs also retain explicit source-compatibility guidance such as TypeScript `TraceId` to `TraceEventId` and public `StateCommit.node_id` wording to `state_node_id`; these do not create second runtime identities. | Only an alias or adapter explicitly documented and implemented for the exact boundary may be used. No transitive or spelling-based alias inference is allowed. |
| Non-authorizing extensions | [`schema_extensions.rs`](../../crates/splendor-types/src/schema_extensions.rs) and its focused tests recursively reject reserved identity, authority, credential, work-order, approval, policy, quota, verifier, Gateway, driver, and related keys for schemas that already permit extensions. | This is a reusable guard, not proof that every schema admits extensions and not a complete FND-006 classifier. A closed schema remains closed. |
| RFC 0018 Slice 1A | [`foundation_grammar.rs`](../../crates/splendor-types/src/foundation_grammar.rs) implements `CanonicalSchemaIdV1`, `CanonicalLabelV1`, `FoundationGrammarCodeV1`, `CanonicalTimestampV1`, `CanonicalCountV1`, `CanonicalOrdinalV1`, `CanonicalSequenceV1`, `CanonicalPositiveRevisionV1`, the nine `FoundationGrammarError` values, and `RegistryDeclarationDigest` for the exact RFC 0013 declaration domain. | These values are additive, experimental, behavior-free, and incomplete. They grant no schema registration, owner lookup, authority, currentness, trust, durability, persistence, or live replay use. |
| RFC 0018 reserved families | Event, State, Evidence, Registry, Authority, publication, finalization, receipt, coordinate, attestation, and recovery names and candidate schema strings are collision reservations only. | They are not registered or live. No parser, record, constant, persistence row, generated binding, compatibility rule, or migration may be derived from the reservation without an accepted owner annex. |
| Partial PR #608 evidence | The [0.1 compatibility fixtures](../../conformance/0.1/fixtures/conformance-cases.json) and [validator](../../conformance/0.1/run-conformance.py) characterize current stable examples, accepted non-authorizing extensions where allowed, fail-closed authorizing/security-critical extension rejection, and the implemented `trace_id` alias with canonical output. | This is partial `FND-006` fixture evidence only. Its static fixture checks are not the full production parser/serializer matrix and do not pass `G00` or `G72`. |
| Current protocol version reporting | Existing version strings, including any current `/version` response, are advisory implementation information. | They are not a compatibility offer, capability matrix, negotiation result, currentness proof, or permission to send a privileged schema. |
| Generated C03 surfaces | No RFC 0018 Python, TypeScript, OpenAPI, or JSON Schema publication is authorized or implemented by this RFC. | Publication remains blocked. A generated file or candidate schema cannot bootstrap its own acceptance. |
| Storage migration and cutover | No FND-006 SQLite online migration, owner-record migration, State/Trace split-store cutover, or rolling-upgrade protocol is authorized by this RFC. | Existing stores remain under their current contracts. Historical bytes are not silently rewritten and old/new writers are not run in parallel. |

The [foundation readiness checkpoint](../rules/v2/foundation-readiness.md) calls
the existing class rules and fixture matrix foundation-ready for bounded follow-
on contract work. It explicitly leaves version negotiation, online storage
migration, rolling upgrade, full FND completion, and Gold evidence out of scope.
This RFC preserves that truth.

## Terminology

**Semantic owner** means the one component that defines the meaning, legal
transitions, currentness, and authoritative use of a contract. Storage location
or transport handling does not transfer ownership.

**Schema registration** means an accepted owner contract has fixed the exact
schema/domain/version, fields, parser, owner, compatibility class, live
disposition, and every canonical byte projection used for identity, digest,
authority, or receipts. For a legacy stable 0.1 surface, the contract also
identifies which output bytes are explicitly pinned and which remain observed
production serialization. Lexical validity is not registration.

**Current** means the exact schema/version and owner state admitted for a named
operation at the decision instant after all currentness, tenant, audience,
authority, trust, expiry, revocation, and compatibility checks. It does not mean
newest by string, timestamp, file order, or release number.

**N** means the exact current registered schema or protocol role for one named
owner boundary. It is not a repository-wide version and does not imply that all
families advance together.

**N-1** means the one explicitly supported predecessor for that same owner
boundary. A stable alias may occupy an N-1 input role only where its exact
adapter is accepted and implemented.

**N+1** means a future or otherwise unsupported successor relative to that
boundary. Current code cannot infer its meaning from lexical form or a numeric
suffix.

**Live admission** means eligibility to participate in current authority,
Gateway verification, owner mutation, current State, key derivation, receipt
validation, dispatch, or effectful execution.

**Historical inspection** means access-controlled decoding or bounded opaque
display for explanation and audit. It is not live admission or current
authority.

**Canonical output** means the one registered byte representation emitted by the
accepted serializer for the selected schema/domain/version. Alias bytes are
never canonical output.

**Observed production serialization** means the exact output currently produced
by a production serializer where no stable 0.1 or accepted owner contract has
explicitly pinned those bytes as canonical. Characterization may record and
regression-test that output, but this RFC does not register it, make it a digest
ABI, or promise byte stability beyond the governing contract.

**Migration-decision function** means an executable, deterministic owner port or
pure function over the exact accepted source bytes and declared target contract.
It returns either exact owner-validated migration output under that target or a
typed fail-closed `unsupported` or conflict disposition. Those result labels are
semantic only unless an accepted owner annex pins their wire form. The function
performs no I/O, owner mutation, current-State change, Gateway call, or side
effect.

**Downgrade** means producing an older semantic contract from a newer one for a
consumer. Dropping fields or selecting older-looking defaults is a downgrade
even when the resulting JSON parses.

**Rollback-read** means retaining a reader or exact adapter that can inspect
bytes written before or during a cutover. It does not reactivate an old writer or
old head.

**Opaque non-live data** means bounded bytes plus trusted storage metadata that
the current implementation does not semantically interpret. Opaque data is not
a generic extension path.

The class and disposition labels in this RFC are semantic terms. They do not
register Rust enum variants, schema constants, JSON strings, error codes, daemon
fields, or fixture spellings. A later internal fixture may pin exact spellings
only in its separately reviewed Slice 1 contract.

## Ownership

| Surface | Owner posture |
| --- | --- |
| `splendor-types` | May hold behavior-free IDs, closed schemas, enums, receipts, references, deterministic serialization, and compatibility grammar after acceptance. It does not decide compatibility legality, currentness, migration eligibility, trust, or live disposition. |
| Semantic service owners | Classify changes to their own meaning; register exact schema/domain/version; decide whether an adapter is lawful; define migration, downgrade, replay, currentness, and rollback behavior; issue owner-bound evidence. |
| `splendor-kernel` | Composes owners, wires invariant checks, and exposes compatibility facades. It may not become a second owner or preserve divergent implementations as dual truth. |
| `splendor-store` | Supplies backend-neutral persistence, backup, checkpoint, CAS, fencing, durability, and resumability mechanics for owner-approved plans. It never decides that bytes are semantically compatible, migratable, current, or safe to downgrade. |
| `splendor-daemon`, node, SDKs, CLIs, and adapters | Parse or translate accepted contracts, advertise owner-issued capability facts, and call owner services. They never decide compatibility legality, silently negotiate, invent defaults, or bypass an owner/Gateway denial. |
| Generators | Reproduce accepted Rust contracts and evidence manifests deterministically. Generated output is not an owner, source of truth, or authority. |
| Replay and inspection | Decode through exact historical adapters or preserve opaque bytes. They do not migrate, commit, dispatch, recover, or create currentness. |

A compatibility decision that changes authority, currentness, owner mutation,
State, Trace/Event/Evidence, receipts, key derivation, protocol admission, or
storage meaning belongs to the semantic owner even when the mechanical code is
in a parser, Store adapter, daemon handler, generator, or SDK.

## Normative Scope and Non-Goals

This RFC defines:

- six closed semantic compatibility classes and their minimum obligations;
- four closed input dispositions and their non-authority rules;
- an N-1/N/N+1 decision matrix for stable 0.1 and implemented RFC 0018 Slice 1A
  values;
- change-dossier, canonical identity, history, replay, generation, future
  negotiation, storage cutover, mixed-version messaging, security, resource,
  adoption, and evidence laws; and
- the only implementation slice that acceptance may authorize.

This RFC does not define or authorize:

- a public compatibility class or disposition enum;
- a new schema registry, owner record, migration record, checkpoint record,
  protocol field, capability response, daemon endpoint, or generated package;
- registration or implementation of any RFC 0018 reserved record family;
- a universal owner envelope, compatibility map, migration function, or receipt;
- protocol negotiation for daemon, node, driver, message, work order, policy,
  artifact, or workload boundaries;
- SQLite online migration, a State/Trace split-store cutover, owner-record
  migration, rolling upgrade, dual write, or distributed migration;
- a new State head, Event/Trace kind, Evidence contract, Gateway path, verifier
  result, owner state machine, or recovery worker;
- public Python, TypeScript, OpenAPI, or JSON Schema C03 publication;
- FND-003 runtime implementation, RFC 0019 owner records, or outbox/inbox
  implementation;
- completion of `FND-006`, issue #225, C03, any task, any issue, any sprint, any
  Gold case, or any release gate; or
- a claim that stable 0.1 and C03 Slice 1A are one wire protocol or one version
  sequence.

## Six Closed Semantic Compatibility Classes

Every change must receive one primary class before implementation or generation.
The owner must classify semantics, not file names or diff size. A change can
carry additional classes when it crosses boundaries; all applicable obligations
accumulate. No seventh class, `internal`, `misc`, `safe`, or `test-only` escape
hatch exists for an observable contract change.

### `additive_non_authorizing`

**Meaning:** adds information that cannot affect identity, authority, trust,
currentness, policy, defaults, validation outcomes, owner mutation, hashing,
idempotency, scheduling, resource admission, receipt validity, replay behavior,
or side effects.

**Owner:** the semantic owner of the containing contract, with the contract owner
for its serialization. `splendor-types` may encode the accepted value but does
not classify it independently.

**Examples:** an optional display hint or external correlation reference inside
an already extension-capable stable schema; an inspection-only diagnostic that
is excluded from all canonical authority and identity projections; an explicit
input alias that emits the existing canonical field and creates no second ID.

**Mandatory obligations:** owner review; collision and extension-policy review;
proof that absence, presence, null, ordering, and unknown handling are inert;
canonical-output fixtures; unknown-field negatives; replay no-effect coverage;
and an impact check for every serializer, consumer, Store reader, and generated
surface. An RFC is required if a higher-priority rule already requires one, if
the public stable shape changes, or if inertness cannot be proved. Otherwise an
owner-approved contract note may suffice.

**Migration and downgrade:** no live semantic migration may be necessary. Older
consumers may ignore only a field explicitly declared ignorable by their
accepted contract. Otherwise the input is rejected or preserved opaque non-live.
Dropping the field during downgrade is legal only when its documented meaning is
provably inert and it is excluded from canonical identity and digest projections.

**Replay:** may display or preserve the field under access policy but cannot let
it alter reconstruction, explanation conclusions, current State, or execution.

**Default severity and escalation:** low only after proof. Escalate immediately
to `additive_authorizing`, `behavioral`, or `security_critical` if any consumer
uses the value in a decision, digest, key, default, currentness test, or effect
path.

An additive non-authorizing field cannot later become authorizing without a new
classification, registered version, dossier, migration analysis, and fixtures.
Historical bytes keep their original non-authorizing meaning forever.

### `additive_authorizing`

**Meaning:** adds a field, enum value, variant, capability, scope, allowlist,
limit, approval, policy, trust, currentness, safety, or other input that can
change a privileged allow, deny, pause, route, resource, or mutation decision,
even when the field is optional.

**Owner:** the semantic authority or lifecycle owner whose decision changes. The
Gateway, daemon, Store, SDK, adapter, or generator cannot classify or adopt the
change on that owner's behalf.

**Examples:** a new work-order permission; a new accepted approval or capability
kind; an optional field that enables a driver or widens data use; a new
authorizing message/workload/policy variant.

**Mandatory obligations:** accepted RFC or owner annex; security and owner
review; a complete change dossier; a new registered schema/domain/version unless
the accepted contract explicitly reserves an extension point with fail-closed
unknown semantics; an executable deterministic migration-decision function and
fixtures even when live migration is unlawful; downgrade and rollback behavior;
replay behavior; owner/tenant/audience/schema/digest binding; production parser/
serializer fixtures; negative unknown and stale-client tests; and retained
compatibility evidence. A prose-only no-migration decision is insufficient. An
unlawful conversion deterministically returns typed fail-closed `unsupported`.

**Migration and downgrade:** absence never means allow unless that exact default
was already registered. Older consumers reject live use. No field may be dropped,
defaulted, renamed into a known allow, or moved into `extensions`. Downgrade is
normally unsupported; a lawful narrowing adapter requires owner proof that the
result has equal or less authority and preserves identity, audit, and denial.

**Replay:** historical authorizing input explains a historical decision only.
It cannot recreate current authority or a Gateway permit.

**Default severity and escalation:** high. Escalate to `security_critical` when
the change affects credentials, trust, revocation, cross-tenant scope, protected
data, physical safety, verifier bypass resistance, or unknown-value behavior.

### `behavioral`

**Meaning:** changes interpretation or observable behavior without necessarily
changing serialized shape. This includes defaults, validation order, error/
denial meaning, event ordering, currentness, retry, replay, scheduling,
canonicalization, hash input, state transition, or effect certainty.

**Owner:** the component that owns the changed decision or state machine.

**Examples:** changing an absent field from deny to allow; reordering verifiers;
changing alias conflict handling; changing a State transition; interpreting a
historical fact as current; changing whether replay contacts a status service.

**Mandatory obligations:** accepted RFC or owner annex; owner and compatibility
review; security review for privileged paths; complete change dossier; explicit
old/new semantic truth table; an executable deterministic migration-decision
function and fixtures even when a version split makes live migration unlawful;
downgrade, rollback, replay, and fault behavior; fixture and matrix updates; and
retained production-path evidence. A prose-only version split or no-migration
decision is insufficient. Unsupported conversion returns a typed fail-closed
result. Compiler and static-schema parity are insufficient.

**Migration and downgrade:** changed semantics require a new registered schema,
domain, protocol version, or independently selected behavior version. Existing
bytes retain old meaning under the old adapter. Silent reinterpretation is
forbidden. A downgrade must prove the old behavior remains safe; otherwise it is
rejected.

**Replay:** selects the exact historical behavior version or remains opaque.
Current code cannot reinterpret an old decision under new defaults and call the
result historical truth.

**Default severity and escalation:** high. Treat as `security_critical` whenever
the behavioral difference can authorize, suppress required evidence, weaken
denial, alter trust/currentness, or repeat an effect.

### `storage`

**Meaning:** changes persisted bytes, keys, indexes, hash domains, ownership,
transaction boundaries, durability, backup/restore, compaction, retention,
writer fencing, State heads, Event/Trace ordering, Evidence coordinates, or
recovery interpretation.

**Owner:** the semantic owner decides legality and meaning. `splendor-store`
owns only accepted backend-neutral mechanics and concrete storage engines.

**Examples:** owner-record schema migration; a State-node hash change; changing
an outbox key; adding a migration checkpoint; moving State and Trace data;
changing compaction so history can disappear.

**Mandatory obligations:** accepted owner RFC/annex plus migration/cutover annex;
storage and semantic-owner review; complete change dossier; exact source/target
schemas and digests; immutable backup; resumable checkpoints; CAS/fence plan;
idempotent rerun and conflict behavior; durability receipts; restoration and
forward-repair drills; fault injection; capacity/retention accounting; replay and
rollback-read fixtures; and RFC 0019 outbox/recovery consistency. When semantic
conversion is in scope, an executable deterministic migration-decision function
must return exact owner-validated target output or typed fail-closed
`unsupported`/conflict. When conversion is not in scope, the same function
deterministically returns `unsupported`; prose alone is not sufficient.

**Migration and downgrade:** no in-place semantic rewrite without immutable
source evidence. One writer and one truth are mandatory. After new bytes exist,
rollback means stop, read, recover, or forward repair; it does not reactivate an
old writer or old head. Missing/corrupt history is uncertainty, not empty state.

**Replay:** reads exact historical schema/adapters and performs zero writes,
claims, compaction, repair, or head movement.

**Default severity and escalation:** high. Escalate to `security_critical` when
keys, authority, tenant boundaries, trust, receipts, secret/protected data,
retention, or uncertainty can change.

### `transport`

**Meaning:** changes wire framing, endpoint/request/response shape, media type,
protocol sequencing, capability advertisement, message delivery, acknowledgement
kind, timeout/retry, node/driver ABI, or source/destination compatibility.

**Owner:** the semantic owner of the operation and the transport contract owner.
The daemon, node, SDK, or adapter translates but does not decide legality.

**Examples:** daemon API version negotiation; a new message envelope version;
driver capability ranges; changed outbox acknowledgement kind; work-order or
policy protocol version.

**Mandatory obligations:** accepted RFC/owner annex; protocol and semantic-owner
review; complete change dossier; explicit N-1/N/N+1 matrix; source/destination
schema and key binding; stale-client and wrong-audience negatives; timeout,
duplicate, reorder, loss, and retry tests; generated parity when exposed; and
retained mixed-version evidence. If transport adaptation converts semantics, an
executable deterministic migration-decision function and fixtures return exact
owner-validated target output or typed fail-closed `unsupported`/conflict. If no
semantic conversion is accepted, the function deterministically returns
`unsupported`.

**Migration and downgrade:** advertisement is not acceptance. A negotiated
result must select one exact registered contract before privileged bytes are
sent. Unknown variants and omitted security fields reject. No nearest-version,
string comparison, optimistic fallback, or client-selected weakening is allowed.

**Replay:** historical envelopes may be inspected through their exact adapter
but are not redispatched or acknowledged.

**Default severity and escalation:** high. Escalate to `security_critical` when
authentication, authorization, work orders, policies, receipts, data, secrets,
safety, or effect certainty cross the transport.

### `security_critical`

**Meaning:** changes or could ambiguously affect identity, tenant isolation,
authority, credentials, secrets, signatures, trust/key status, revocation,
approval, data-use, protected data, verifier/Gateway enforcement, safety,
currentness, canonical authority digests, receipts, uncertainty, or downgrade
resistance.

**Owner:** the semantic security owner plus every affected mutation owner. No
single transport, Store, SDK, generator, or adapter owner can approve it alone.

**Examples:** unknown authorizing fields; a new signature algorithm; accepting
an old revoked capability; secret-derived digests in logs; cross-tenant migration
checkpoints; receipt substitution; insecure fallback; a stale client omitting a
required security field.

**Mandatory obligations:** accepted RFC/owner annex; independent security and
privacy review; complete change dossier; explicit threat model; fail-closed
unknown behavior; exact canonical/domain/version bindings; migration, downgrade,
rollback, replay, and recovery rules; adversarial production-path fixtures;
cross-tenant substitution tests; capacity and retention proof; and retained
evidence. Any semantic conversion uses the executable deterministic migration-
decision function; absent an accepted exact conversion it returns typed fail-
closed `unsupported` or conflict. When semantic conversion is out of scope, that
same function deterministically returns `unsupported`. No static assertion,
prose-only no-migration decision, or generated schema alone suffices.

**Migration and downgrade:** no automatic downgrade. Unknown, stale, expired,
revoked, untrusted, incomplete, or unverifiable values deny or require
intervention. A feature flag cannot weaken the contract or enable an insecure
fallback.

**Replay:** never creates trust, currentness, a permit, a receipt handle, or a
live decision. Protected historical content remains access controlled.

**Default severity and escalation:** critical and release-blocking for the
affected path. Unclassified changes receive this treatment until the owner proves
a less restrictive class.

## Closed Disposition Semantics

### `accept_current`

The input exactly matches one registered schema/domain/version and passes the
current owner's complete parser, canonical, identity, tenant, audience, trust,
expiry, revocation, currentness, compatibility, and operation-specific checks.
It may proceed to the next owner or Gateway check. The disposition itself grants
no authority, trust, mutation, persistence, receipt validity, or side effect.

Output uses the exact registered current contract: explicitly pinned canonical
bytes where the contract pins them, or the current observed production
serializer where the stable 0.1 contract does not make a byte pin. A current
parser must not normalize a different semantic version into this disposition.

### `accept_alias_emit_canonical`

The input uses one exact documented alias at one accepted ingress boundary. The
adapter maps it to the existing canonical identity and meaning, then all normal
current checks run. Output, persistence, digest input, idempotency input, receipt
binding, and re-export use only canonical bytes.

An alias creates no second identity, schema, field, version, authority source,
or currentness source. Supplying alias and canonical forms together is ambiguous
and rejects unless the accepted parser contract already defines one duplicate-
aware behavior; equality by value does not make duplicate members safe. Alias
acceptance is not transitive to nested objects, other endpoints, generated
clients, or future versions.

### `reject_fail_closed`

The input is not eligible for live parse/validation or fails any required check.
No target-owner mutation, current-State/head change, success or authority
evidence, outbox/inbox claim, Gateway/adapter/provider/status call, receipt
acceptance, current cache update, or side effect may follow. Rejected bytes must
not supply or derive runtime IDs, authority, canonical authority digests,
idempotency keys, receipt digests, or live correlation.

Rejection uses only the existing owner-approved incompatibility/denial/audit
evidence path. That path records exactly the owner-required bounded, redacted,
capacity-charged denial facts at accepted durability, with authenticated caller
attribution and server-generated correlation where correlation is required. It
does not persist protected rejected bytes or manufacture target-owner success,
mutation, currentness, or authority evidence. This RFC does not define or imply
an audit or denial wire schema.

If owner policy requires denial evidence and the accepted evidence path cannot
record it, the operation remains fail closed under that policy. Evidence failure
never converts rejection into allow, fallback, retry with weaker checks, or an
unrecorded target mutation.

Unknown authorizing or security-critical values, versions, fields, variants,
defaults, or omissions always receive this disposition for live use.

### `preserve_opaque_non_live`

A separately accepted bounded historical container may retain exact unknown or
unsupported bytes, source schema text, owner/tenant/storage coordinates, capture
time, byte length, integrity digest, visibility, and provenance without claiming
semantic validation. Preservation must be access controlled, capacity charged,
immutable, and distinguish malformed, unavailable, corrupt, and unsupported
states where the owner contract can do so truthfully.

Opaque bytes are never current and never authority. They must not enter the
Gateway, owner mutation, current State, key or ID derivation, idempotency,
signature/receipt validation, live replay, policy evaluation, capability
selection, downgrade, migration output, or generated current object merely
because they were retained. They may be displayed only as allowed by the
historical read/redaction contract or exported as exact opaque evidence.

`CanonicalSchemaIdV1` proves lexical form only. A lexically valid value is not
registered, supported, negotiated, trusted, or current. In particular, a
different final `.vN` suffix does not imply an adjacent or compatible schema.

## N-1, N, and N+1 Matrix

### Version roles for the bounded scope

| Family | N-1 role | N role | N+1 role |
| --- | --- | --- | --- |
| Stable 0.1 records | Only an explicitly implemented predecessor alias/adapter for that exact record. In current evidence, `trace_id` is the implemented `TraceEvent` input alias for canonical `trace_event_id`; no broad predecessor schema is inferred. | The exact implemented stable 0.1 parser/behavior and its current production serializer. Bytes are canonical only where stable 0.1 or an accepted owner contract explicitly pins them; otherwise output is observed production serialization. | Any unknown future stable record version, field, enum, or semantic successor. It has no current live admission. |
| RFC 0018 Slice 1A values | No predecessor grammar is registered by this RFC. Stable 0.1 values that Slice 1A deliberately reuses remain their own stable contracts, not an implicit C03 N-1. | The exact implemented Slice 1A lexical/error/integer/timestamp values and `RegistryDeclarationDigest` construction described in Current Truth. | Any future lexical profile, enum value, digest domain, record, parser, or candidate RFC 0018 reserved family not separately accepted and implemented. |
| RFC 0018 reserved record families | None. | None. Reservation is not N. | None for live use. Candidate names remain owner-annex blocked rather than becoming N+1 parsable records. |

### Every source/consumer pairing

This table is per named owner boundary. Compatibility is non-transitive. A
pairwise adapter, a path through N, or fixtures for each edge never authorize an
N-1-to-N+1 conversion.

| Source role | N-1 consumer | N consumer | N+1 consumer |
| --- | --- | --- | --- |
| N-1 | May process under its own then-current contract only while that writer/consumer is still lawfully active. It does not establish N currentness. | `accept_alias_emit_canonical` or an explicit N-1-to-N adapter only; otherwise `reject_fail_closed` for live use or `preserve_opaque_non_live` for accepted history. Stable current case: `trace_id` may map only to `trace_event_id`. | Requires a separately owner-accepted direct N-1-to-N+1 disposition or adapter that fixes exact source and target contracts and direct fixtures. Composed chains, pairwise adapters, path existence, and pairwise fixtures never imply or authorize this pairing. |
| N | No silent downgrade. The N-1 consumer rejects live input; an external historical store may preserve exact bytes opaque. A separately accepted narrowing adapter is required before any N-1 live use. | `accept_current` only after all owner checks. Output uses N's explicitly pinned canonical bytes where defined and N's observed production serialization otherwise. | The future N+1 consumer may accept N only if its accepted matrix names N exactly. Current RFC acceptance cannot pre-authorize that future decision. |
| N+1 | Current rules cannot authorize this pairing. Reject live input or preserve exact bytes opaque under an accepted historical container. | Reject live input or preserve exact bytes opaque. Never drop unknown authorizing/security fields to make N. | Outside this RFC. A future owner annex defines the then-current N+1 behavior; this RFC grants none. |

### Operation matrix

| Operation | N-1 input at N boundary | N input at N boundary | N+1/unknown input at N boundary |
| --- | --- | --- | --- |
| Parse | Parse only through the exact predecessor adapter. Stable `TraceEvent` may accept `trace_id`; Slice 1A has no predecessor parser. | Use the exact production parser or checked constructor for the registered contract. | A bounded envelope parser may identify enough to reject or retain opaque bytes; it must not invoke the N semantic parser by coercion. |
| Validate | Revalidate the complete N object after adaptation; predecessor validation is not sufficient. | Apply all current schema, identity, tenant, audience, trust, expiry, currentness, bound, digest, and owner rules. | No live semantic validation. Lexical schema validation is not registration. |
| Live admission | Only with an explicit adapter and all N checks. | Eligible for subsequent owner/Gateway checks; not automatically authorized. | `reject_fail_closed`. Unknown authorizing/security-critical values never drop/default/coerce into allow. |
| Canonical/observed output | Emit the N target's explicitly pinned canonical bytes where its contract pins them; otherwise emit only the target's characterized production serializer output. Alias bytes never emit or persist as canonical. | Emit explicitly pinned canonical bytes where the contract defines them. Otherwise characterize current production serializer output without registering it as canonical. | Emit no current object. Opaque export, if allowed, preserves exact original bytes and labels them non-live. |
| Inspect/replay | Decode with the exact historical adapter or retain opaque; no currentness. | Inspect using the exact N contract; no live effect. | Preserve opaque non-live or report unsupported/corrupt truthfully; never guess. |
| Downgrade | Not applicable at N ingress; any N-1 re-emission requires an accepted reverse adapter and cannot recreate deprecated alias output by default. | No downgrade unless the owner dossier proves an exact safe mapping. | Forbidden by current rules. Dropping unknowns is not downgrade safety. |
| Rollback-read | Retain the exact N-1 reader/adapter and immutable bytes where required. | Retain N reader and canonical fixtures. | Opaque read only until a future adapter is accepted. |
| Generated parity | Existing stable generated surfaces remain as currently contracted. Exact byte parity is required where their stable/owner contract pins bytes; otherwise parity characterizes observed production serialization and behavior. Slice 1A has no generated C03 surface. | Rust is the contract source for accepted implemented values, but byte canonicality exists only where the accepted contract explicitly pins it. Publication remains blocked by this RFC. | No generation. A generated artifact cannot register N+1. |
| Storage | Existing bytes remain under their exact schema. An adapter may read without rewriting unless a cutover annex authorizes migration. | Persist only where the current owner contract already permits it. Slice 1A lexical values do not authorize owner records or new tables. | Do not write into live owner tables. A separately accepted opaque archive may retain bounded exact bytes. |
| Transport | Existing stable endpoint behavior remains; aliases are boundary-specific. | Send only after exact protocol acceptance, not version-string optimism. No C03 negotiation exists now. | Reject before privileged dispatch or preserve outside the live transport path. |

N-1, N, and N+1 labels do not weaken canonical identity. An adapter must preserve
or explicitly remap the one owner identity according to an accepted plan; it
cannot mint a sibling identity merely because the source spelling differs.

## Change Dossier

Every `additive_authorizing`, `behavioral`, `storage`, `transport`, or
`security_critical` change requires one accepted dossier before implementation,
generation, migration, or rollout. The dossier may be an RFC or an owner annex
where the governing RFC permits an annex, but it must be independently reviewed
and immutable by accepted revision.

The dossier must contain:

1. The semantic owner, affected primitive/record/operation, class or classes,
   active line, task/issue binding, dependencies, and explicit non-goals.
2. Exact old and new registered schema/domain/version coordinates, field and
   presence rules, enum/variant sets, parser APIs, and explicitly pinned
   canonical bytes. For stable 0.1 surfaces without a byte pin, identify observed
   production serialization/behavior without calling it newly canonical.
3. Every authorizing, security, identity, owner, tenant, audience, currentness,
   expiry, trust, policy, data-use, safety, and digest field.
4. A field-by-field and one-field-mutation semantic comparison, including
   absence, null, default, alias, order, unknown, duplicate, and over-bound cases.
5. The owner-issued compatibility matrix for parse, validate, live admission,
   canonical output, inspect/replay, downgrade, rollback-read, storage,
   transport, and generated parity.
6. An executable deterministic migration-decision function/port plus fixtures.
   For every `additive_authorizing` or `behavioral` change it must return either
   exact owner-validated output under the accepted target contract or typed fail-
   closed `unsupported`/conflict, including source/target identity and digest
   bindings. `storage`, `transport`, and `security_critical` changes require the
   same whenever semantic conversion is in scope; otherwise the function
   deterministically returns `unsupported`. Prose-only no-migration decisions are
   insufficient. Result labels remain semantic unless an owner annex pins wire.
7. Downgrade behavior, including the exact proof that authority cannot widen and
   unknown security fields cannot disappear into allow.
8. Replay/history behavior, exact historical adapter retention, and proof of
   zero write, dispatch, recovery, Gateway, status, adapter, outbox, and head
   effects.
9. Fixture updates using production parsers/serializers, negative fixtures,
   mixed-version cases, fault cases, stale clients, and retained output paths.
10. Owner, tenant, audience, schema, canonical digest, command/idempotency key,
    source/destination key, receipt, and acknowledgement-kind binding where
    applicable.
11. Storage backup, checkpoint, CAS/fence, durability receipt, rollback-read,
    forward-repair, capacity, retention, and restore-drill plans when persisted
    bytes are affected.
12. Deployment stops, activation gates, observability without protected-data
    leakage, responsible reviewers, and evidence retention period.

An `additive_non_authorizing` change still requires an owner inventory,
collision and extension-policy review, canonical/unknown fixtures, and a written
proof that it cannot affect decisions, hashes, keys, currentness, replay, or
effects. Any later authorizing use is a new change and must be reclassified; the
old bytes cannot be reinterpreted in place.

No dossier may use generated output, a Store table, a daemon DTO, an SDK model,
or a compatibility fixture as the source that defines owner semantics.

The migration-decision function is characterization and decision logic, not
migration execution. Returning exact target output does not write it, make it
current, grant authority, or bypass target-owner validation, storage cutover, or
Gateway checks.

## Canonical and Identity Laws

1. Each registered contract has one canonical serializer and one exact schema/
   domain/version coordinate. Old and new serializers must not produce alternate
   IDs, digests, command keys, idempotency keys, receipts, State hashes, or Event
   identities from aliases, defaults, absent-versus-null collapse, map ordering,
   numeric coercion, case folding, Unicode normalization, or field reordering.
2. Alias input is removed before canonical identity derivation and emits only the
   canonical field. Alias and canonical spellings never create two identities.
3. Required absence, optional absence, null, empty, zero, false, and default are
   distinct unless the registered schema explicitly proves otherwise. A
   serializer cannot insert a new default into old canonical bytes silently.
4. Every privileged digest binds its nominal digest type, schema, semantic
   domain, version, exact canonical projection, and required owner/tenant/
   audience coordinates. A generic content hash cannot substitute for a nominal
   authority, registry, command, receipt, or migration digest.
5. Changed semantics require a new registered schema/domain/version even when
   the JSON shape is byte-identical. Changed canonical bytes or digest projection
   require an explicit migration and identity impact decision.
6. Old explicitly pinned canonical bytes retain their old schema meaning. Where
   stable 0.1 pins behavior but not all serializer bytes, current output remains
   observed production serialization rather than a canonical ABI created by this
   RFC. New code may explain old values through the old adapter but may not
   reinterpret them under new defaults.
7. Unknown, opaque, malformed, or unregistered bytes cannot be hashed into live
   authority, idempotency, current State, owner keys, receipts, or migration
   outputs merely because they were preserved or have a valid-looking digest.
8. A `CanonicalSchemaIdV1` value is compared against one exact registered
   constant. Splitting version suffixes, selecting a nearest version, or treating
   lexical adjacency as compatibility is forbidden.
9. Cross-type IDs remain non-interchangeable even when their UUID bytes match.
   Migration preserves nominal type or uses an accepted explicit mapping; string
   aliases and generic UUID substitution are forbidden.
10. Stable 0.1 `TraceEvent` IDs/bytes/order and other exact byte projections that
    stable 0.1 explicitly pins, State node IDs/parents/hashes/links, and RFC 0013/
    0014 accepted canonical bytes remain unchanged in this RFC. Other stable 0.1
    serializer output is characterized without a new global byte-stability claim.

## Replay and Historical Read Laws

1. Historical bytes decode only under the exact historical schema and adapter
   that defined their meaning. If that adapter is absent, untrusted, or cannot
   prove the complete record, the bytes remain `preserve_opaque_non_live` or are
   reported unavailable/corrupt; they are never coerced into N.
2. Historical explanation states what the historical owner record and accepted
   evidence said at that time. It is not a current authority, trust, key-status,
   policy, work-order, approval, State-head, Registry-currentness, or Gateway
   decision.
3. Inspect/replay never migrates bytes, writes owner records, advances cursors or
   heads, claims recovery work, drains outboxes, acknowledges inboxes, invokes
   the Gateway, calls an adapter/provider/status/cancellation operation, or
   repairs/compacts storage.
4. Replay never mints a permit, trusted receipt handle, current capability,
   owner lease, migration checkpoint, or durability proof from serialized data.
5. Read-only re-evaluation uses explicitly detached inputs and outputs. It cannot
   publish the result as historical truth or current authority.
6. Replay of an alias records and emits the canonical identity without changing
   immutable source evidence. The source bytes may remain available as an
   access-controlled historical attachment when the owner contract requires it.
7. Unknown historical authorizing/security-critical fields are not ignored for
   a live reconstruction. The record remains non-live even if all known fields
   would otherwise allow.
8. Missing or corrupt history is uncertainty. Replay must not synthesize a fresh
   state, reset an idempotency key, infer no effect, or treat an absent receipt as
   denial or success.
9. Access control, privacy, redaction, retention, and oracle resistance apply to
   historical reads. Hashing or opaque preservation is not redaction.

## Generated Surface Gate

Rust source in `splendor-types` is the canonical contract source only for
accepted and implemented values. That source status does not make every stable
0.1 serializer output globally canonical: exact bytes are canonical only where
stable 0.1 or an accepted owner contract explicitly pins them. For other stable
0.1 values, generation may characterize current production serialization and
behavior without registering a new canonical-byte ABI. RFC 0018 Slice 1A's
implemented values retain their explicitly accepted serialization rules. RFC
0018 reserved families, candidate schema strings, planning labels in this RFC,
and future owner records are not generator inputs.

A future generator slice must satisfy all of these requirements before any
publication review:

1. One reviewed machine-readable contract manifest is deterministically derived
   from accepted Rust types and exact registered constants.
2. The manifest binds source repository revision, source-contract content hash,
   contract/profile version, generator source or binary digest, pinned tool
   versions, dependency-lock digest, and every output digest.
3. Generation runs offline with network access disabled and a locked,
   checksummed dependency graph.
4. Identical accepted input produces byte-for-byte identical generated output,
   ordering, line endings, schema IDs, fixtures, and manifest on every supported
   environment. A fixture labels bytes canonical only when the source contract
   explicitly pins them; otherwise it labels them observed production output.
5. Independent positive, boundary, one-field mutation, alias, duplicate,
   unknown-field, unknown-enum, unknown-version, stale-client, and authorizing-
   field negative fixtures validate production parsers and serializers rather
   than generator self-assertions only.
6. Generation writes to a fresh staging directory, validates all outputs and
   digests there, and atomically replaces the complete output set only after all
   checks pass. Failure leaves the prior published set unchanged; partial output
   is never current.
7. Clean-tree regeneration and generated-manifest parity are mandatory. Hand
   edits, partial regeneration, untracked outputs, or divergent per-language
   semantics fail validation.
8. Python, TypeScript, OpenAPI, JSON Schema, daemon models, and docs remain
   projections. They cannot implement owner decisions, authority, hashing,
   migration legality, protocol negotiation, or fallback.
9. Omitted required security fields, stale clients, and unknown authorizing
   values fail closed at the Rust/owner boundary even if a client-side model
   accepted or omitted them.

This RFC does not authorize Python, TypeScript, OpenAPI, or JSON Schema
publication. Cross-language generation remains a later explicit slice after the
owner schemas, compatibility decisions, and publication review are accepted.

## Future Protocol Negotiation Contract

No protocol negotiation is implemented or authorized here, and this RFC adds no
negotiation fields. A future protocol RFC must define owner-issued capability
matrices independently for daemon, node, driver, message, work-order, policy,
artifact, and workload boundaries.

Every future matrix must bind:

- issuing semantic owner and exact operation/profile;
- exact supported schema and protocol versions, with any range represented as a
  reviewed finite set of exact versions at the acceptance decision;
- implementation and accepted-contract digests where required;
- tenant and audience scope where relevant;
- caller, fleet, node, instance, driver, work-order, policy, artifact, workload,
  or message peer identities required by that boundary;
- issue time, expiry, revocation/currentness source, trust/key status, and
  attestation where required;
- required security fields and prohibited fallback;
- the exact selected version and disposition; and
- retained negotiation evidence that is non-authorizing by itself.

Capability advertisement means only that a peer claims support. It is not
negotiated acceptance, owner registration, currentness, trust, work-order
authority, Gateway permission, or proof that a migration is legal. Selection
must occur through the owner contract, choose one exact common registered
version, and fail closed when there is no exact safe intersection.

Current `/version` strings and package versions are advisory only. They must not
be parsed as capability ranges, used to infer schemas, or treated as permission
to send privileged fields. No nearest-version fallback, optimistic send,
client-selected downgrade, insecure feature-flag fallback, or omission of
unknown security fields is allowed.

## Storage Migration and Cutover Laws

### Semantic legality versus Store mechanics

The semantic owner defines whether a record can be migrated, the exact
source/target meanings, owner/tenant bindings, currentness, writer handoff,
conflict behavior, and legal cutover. `splendor-store` may expose backend-neutral
mechanics for immutable backup, bounded scan, resumable checkpoint, CAS, unique
binding, writer fence, durability barrier, receipt, restore, and conflict
reporting. Store code cannot decide semantic compatibility, invent defaults,
select a target version, advance an owner head, or turn corrupt history into
fresh state.

### Required migration plan

Before any persisted migration, the accepted owner annex must fix:

1. Exact source and target schema/domain/version constants, explicitly pinned
   canonical bytes and observed source serialization where applicable, semantic
   digests, key projections, and owner/tenant/audience coordinates.
2. A complete inventory and immutable, integrity-verified backup that is
   restorable independently of the target writer.
3. The executable deterministic migration-decision function and fixtures. It
   selects exact owner-validated target output or typed fail-closed
   `unsupported`/conflict before any migration execution. When target output is
   selected, a separate deterministic migration execution function has a
   retained code/version/digest and fixture set.
4. A resumable, owner/tenant/source/target-bound checkpoint with stable ordering,
   pinned high-water mark, expected cursor, processed key range, counts, digests,
   errors, and current writer-fence generation.
5. Idempotent rerun semantics: exact duplicate work returns the original result;
   changed source bytes, target bytes, function digest, owner, tenant, range, or
   checkpoint binding is a conflict.
6. Expected-head/CAS and writer-fence rules for every mutable head, source claim,
   target commit, and final cutover. A stale worker cannot publish target bytes or
   advance a head.
7. Durability receipts for backup, checkpoint, target writes, verification,
   source fence, and final cutover, each bound to owner, tenant, schema, digest,
   backend policy, and achieved durability.
8. RFC 0019-consistent source/outbox, destination/inbox, acknowledgement-kind,
   recovery, uncertainty, non-reuse, and retained-debt behavior where independent
   owners or stores participate.
9. Complete post-migration validation of counts, ordered identities, canonical
   bytes/digests, references, Event/Trace/State links, receipts, indexes, privacy,
   capacity, and historical readability before current visibility.
10. Rollback-read and forward-repair plans, operator stops, restore drills,
    retention, capacity ceilings, and evidence retention.

### Cutover and rollback

Exactly one writer owns a live head or record family at a time. Dual truth, dual
write, best-effort mirroring, and two independently advancing heads are
forbidden. A target may be staged and verified while the source remains the sole
writer only when the owner annex proves how the final delta is fenced and
validated. The source writer is durably and permanently fenced before the target
writer becomes current.

The cutover CAS binds the exact source head/fence/digest, target head/fence/
digest, owner, tenant, migration function, checkpoint, backup, and required
receipts. Failure or uncertainty opens no writer. A successful cutover makes the
old writer permanently ineligible for that lineage.

After new bytes or a target head become visible, rollback means:

- stop new work;
- keep both exact readers and immutable evidence;
- recover or quarantine unresolved RFC 0019 work;
- restore a read-only view where lawful; and
- repair forward under a new accepted command and fence.

Rollback never reactivates the old writer, returns the old head as current,
forgets new command/idempotency/effect history, rewrites receipts, or treats an
old identity as unused. If the target semantics cannot continue safely, the
system remains stopped or requires intervention.

Missing, inaccessible, compacted, or corrupt source, checkpoint, backup,
receipt, outbox, inbox, or target history is uncertainty, not a fresh State or a
safe retry. It remains charged and blocks cutover or requires owner-authenticated
recovery.

SQLite online migration, migration between separate State and Trace databases,
and rolling upgrade are separately annex-gated no-go areas. This RFC provides
their laws but does not authorize their design or implementation.

## Mixed-Version Messaging, Outbox, Inbox, and Receipts

Every mixed-version command or message path must bind the exact:

- source owner, tenant, audience, schema/version, canonical command bytes,
  semantic digest, source owner key, and source barrier;
- destination owner, tenant, audience, schema/version, canonical command bytes,
  semantic digest, destination owner key, and admission result;
- transport/message identity, causal parent, work-order/policy/currentness facts,
  compatibility decision, and selected exact protocol version;
- inbox dedupe identity and immutable first accepted bytes;
- acknowledgement identity, schema/version, acknowledgement kind, both source
  and destination keys, command digest, inbox transaction, and owner/trust/
  expiry/currentness binding; and
- terminal receipt identity, schema/version, owner/tenant/audience, exact
  attempted or no-attempt disposition, effect certainty, State/Event/Evidence
  coordinates, durability, and finalization binding.

Command-acceptance acknowledgement proves only durable destination acceptance
and deduplication on an effectful destination. An effectful destination may emit
it only after one durable transaction records permanent dedupe, the exact
destination command/Decision and source/effect intent, complete accepted
reservations, and `not_started`. It contains no terminal logical mutation,
external-effect result, State/head result, terminal owner receipt, or
`MutationReceipt`, and it cannot open terminal result or mutation visibility.

A no-external-effect destination has no separate command-acceptance barrier. It
must return only a terminal-finalization acknowledgement after its complete
owner mutation or no-attempt disposition, required Event/Trace/Evidence facts,
State/artifact/head results where applicable, receipts, and durability have
finalized through the truthful same-store transaction or accepted recoverable
publication barrier required by RFC 0019.

For an effectful destination, terminal acknowledgement follows only after RFC
0019 effect observation and terminal finalization. The source barrier declares
the one exact permitted acknowledgement kind. Command acceptance is invalid for
every barrier that requires a mutation, effect, result, terminal receipt,
publication, or finalization, and it cannot become or substitute for terminal
acknowledgement or recovery completion.

A receipt from a sibling command, different schema version, different owner,
tenant, audience, source/destination key, attempt, fence, acknowledgement kind,
or durability class cannot substitute even if every other field and digest
matches. Receipt shape and possession do not establish trust; the owner validates
the complete binding and reconstructs any internal trusted handle.

N-1/N/N+1 dispatch follows the owner matrix before enqueue and again at
destination admission/currentness where required. A compatibility decision
cannot outlive its expiry, trust, policy, work-order, or owner state. Unknown or
downgraded authorizing values deny. Opaque messages are not put in a live inbox.

Migration and recovery obey RFC 0019 effect certainty. Duplicate delivery
returns or resumes the original exact result. Changed bytes conflict. Missing or
uncertain acknowledgement/receipt history cannot infer no effect or authorize a
new attempt. Replay makes zero claims, acknowledgements, status calls, dispatches,
or recovery writes.

## Security, Privacy, and Resource Laws

| Risk | Required law |
| --- | --- |
| Downgrade attack | A client, peer, operator, feature flag, or fallback cannot select a weaker version than the owner-approved exact intersection. No intersection denies. Downgrade evidence is retained. |
| Unknown authorizing value | Unknown fields, enums, variants, versions, defaults, aliases, and omissions deny live use. They are never ignored or coerced into a known allow. |
| Rejection evidence | Rejected bytes cause zero target mutation/currentness/success/authority evidence, zero Gateway/adapter/provider/status/effect, and no rejected-byte-derived IDs, authority, or digests. Only the existing owner-approved bounded, redacted, capacity-charged denial/audit evidence path may record authenticated attribution, server-generated correlation, and exact required denial facts at accepted durability. Required evidence failure remains fail closed. |
| Cross-tenant substitution | Migration checkpoints, backups, rows, keys, capability matrices, messages, acknowledgements, and receipts bind tenant and owner. Wrong-tenant equality is rejection, not dedupe. |
| Forged or sibling receipt | Full owner/tenant/audience/schema/version/key/command/attempt/fence/kind/durability/trust/currentness validation is mandatory. Shape, signature syntax, or matching payload digest alone is insufficient. |
| Feature flag or insecure fallback | Flags may keep a feature off or select an already accepted deployment path. They cannot weaken validation, enable anonymous/unauthenticated negotiation, admit stale clients, or bypass an owner/Gateway denial. |
| Protected data | Historical, migration, fixture, error, diff, log, metric, backup, and opaque views remain classification- and access-controlled. A compatibility report cannot expose protected payloads to prove parity. |
| Secret-derived digest | Raw secrets, credentials, tokens, private keys, approval tokens, or reusable secret-derived digests do not enter canonical contracts, compatibility keys, logs, fixtures, manifests, metrics, or generic receipts. Hashing is not redaction. |
| Capacity and retention | Worst-case source, target, backup, checkpoint, outbox, inbox, receipt, opaque history, recovery, quarantine, non-reuse, and tombstone bytes/records are admitted and charged before work. Uncertain or possibly committed history is not evicted to regain capacity. |
| Identity reuse | A migrated, retired, failed, uncertain, or rolled-back identity never becomes a fresh miss. Permanent command, idempotency, writer-fence, receipt, and effect bindings survive compaction according to the owner contract. |
| Partial cutover | Partial target bytes are non-current. Source remains sole writer until the one final cutover CAS; after it, source is permanently fenced. Uncertain cutover opens neither writer. |
| Restore | Restore uses an immutable verified backup, isolated target, exact schema adapters, owner/tenant binding, and current fence checks. A restore drill must prove no ID/head rollback, duplicate effect, lost uncertainty, or cross-tenant exposure. |
| Oracle resistance | Unsupported, absent, wrong-tenant, corrupt, and unauthorized historical inputs use the owner's non-reflecting response and bounded timing/cardinality profile. Diagnostics do not reveal owner existence, protected fields, or digest candidates. |

Security and privacy reviews must include adversarial one-field mutations,
cross-tenant/cross-owner substitutions, stale/revoked/expired inputs, capability
advertisement lies, backup/checkpoint tampering, response loss, and resource
exhaustion. A successful happy-path round trip is not sufficient.

## Adoption Sequence

Adoption is intentionally incremental and stops at every unmet owner or evidence
gate.

1. Accept this planning RFC through architecture/compatibility and security/
   privacy review without changing implementation or status claims.
2. Perform the separately reviewed bounded offline Slice 1 characterization
   authorized by the Acceptance Effect below, limited to existing stable 0.1 and
   RFC 0018 Slice 1A production Rust parsers, checked constructors, serializers,
   and non-authority checks. It records parser acceptance/rejection and exact
   explicitly pinned or observed serialization only; it exercises no live
   disposition.
3. Retain machine-readable positive and negative results and review any mismatch
   as current-truth evidence; do not paper over it with a fixture-only validator.
   Expected live-disposition cases remain marked `not_exercised`, including
   structurally valid stale, wrong-owner, wrong-tenant, and wrong-audience inputs.
4. For any new owner record, accept the RFC 0018 owner grammar annex and the
   complete change dossier before adding a type, parser, persistence row, or
   generated projection.
5. For any owner mutation or recovery path, accept the RFC 0019 owner annexes and
   prove command, decision, event, State, outbox/inbox, receipt, effect certainty,
   resource, and replay behavior.
6. For any generated surface, accept a separate generator/publication slice and
   pass deterministic offline parity gates before publication.
7. For any protocol, accept a separate negotiation RFC and mixed-version matrix
   before adding fields or advertising support.
8. For any persisted migration, accept a backend and owner cutover annex, run
   backup/restore and fault evidence, and prove one-writer fencing before touching
   live bytes.
9. Qualify rolling deployment only after exact N-1/N/N+1 production paths,
   stale-client behavior, resource limits, recovery, and forward repair pass with
   retained evidence.
10. Update task/issue/Gold status only from the separate completion process after
    all required implementation and evidence exists. RFC acceptance and Slice 1
    characterization alone change no status.

## Acceptance Matrix, Tests, and Gold Map

The required tests below are future gates unless explicitly included in the
bounded Acceptance Effect. Static JSON assertion-only validators are not
sufficient where a production Rust parser or serializer exists.

| Area | Required executable evidence |
| --- | --- |
| Production parse/serialize | Feed exact bytes to production Rust parsers/checked constructors and serialize accepted values through production serializers. Compare explicitly pinned exact bytes where the governing contract pins them; otherwise record exact observed production output/behavior without calling it canonical. Parser success proves no live disposition. Fixture metadata cannot substitute for execution. |
| Live disposition | In a future owner-integrated test, run the exact owner, tenant, audience, trust, expiry, revocation, currentness, policy, and operation checks before asserting any of the four dispositions. Offline Slice 1 marks every expected live-disposition case `not_exercised`. Structurally/canonically valid stale, wrong-owner, wrong-tenant, and wrong-audience objects may parse but cannot receive or prove `accept_current`. |
| Canonical mutation | Mutate every field and presence category one at a time, including schema/domain/version, owner, tenant, audience, identity, digest, order, absent/null/empty/default, alias, and numeric/token spelling. Assert parser/constructor behavior, explicitly pinned or observed serialization as applicable, and no alternate ID/key/digest. Live disposition remains a separate owner-integrated assertion. |
| Unknowns | Unknown top-level/nested fields, enums, variants, versions, algorithms, acknowledgement kinds, owners, and authorizing/security values fail closed for live use; accepted opaque preservation remains non-live. |
| Aliases | Where the production parser implements an alias, alias-only parser acceptance emits the explicitly documented canonical-only output; alias plus canonical, nested alias, wrong endpoint alias, changed value, and alias-derived identity/key cases reject as specified. Structural alias behavior does not prove `accept_alias_emit_canonical` as a live disposition. |
| N-1/N/N+1 | Exercise all nine source/consumer pairings per owner boundary and every operation row: parse, validate, admission, output, inspect/replay, downgrade, rollback-read, generation, storage, and transport. N-1-to-N+1 tests require a direct owner-accepted disposition/adapter and exact direct fixtures; pairwise adapters, a path through N, and composed fixture success are negative and never imply compatibility. |
| Migration decision | For every additive-authorizing and behavioral change, execute the deterministic migration-decision function over exact source/target cases and require owner-validated target output or typed fail-closed `unsupported`/conflict. Storage/transport/security-critical cases do the same when conversion is in scope and deterministically return `unsupported` otherwise. Prose-only no-migration cases fail. |
| Stable 0.1 | Stable examples retain required fields, IDs, State/Trace links, Gateway denial, replay behavior, and exact bytes only where stable 0.1 or an accepted owner contract pins them. Other outputs are observed production serialization. Existing `trace_id` alias evidence runs through the production `TraceEvent` serde path and retains its documented canonical output. |
| RFC 0018 Slice 1A | Exact lexical boundaries, timestamps, integer tokens/ranges, error non-reflection, declaration bytes/domain/digest, wrong domain, schema lexical-not-registration, and no authority/persistence behavior. Reserved families remain unconstructible. |
| Cross-language parity | Future gate only: Rust/Python/TypeScript and exposed OpenAPI/JSON Schema projections produce identical results and rejects, including exact canonical bytes where explicitly pinned and matching observed production serialization where not pinned. No Gold credit or publication follows before the separate generator slice. |
| Stale clients | Omitted required security fields, older exhaustive enums, unsupported media/schema versions, advisory `/version` use, and attempted insecure fallback deny without effect. |
| Reject evidence | Every rejected input produces zero target-owner mutation/current State/success/authority evidence, zero Gateway/adapter/provider/status/effect, and no IDs/authority/digests derived from rejected bytes. Assert exactly the existing owner-required bounded denial facts with authenticated caller/server-generated correlation, accepted durability, capacity charge, redaction, and protected rejected bytes absent. Required denial-evidence failure remains fail closed. No new audit schema is assumed. |
| Mixed-version messaging | Exact source/destination schema/key binding, duplicates, reorder, loss, expiry, wrong audience, incompatible peer, changed bytes, sibling/wrong-version receipt substitution, and restart recovery. A no-external-effect destination emits no command acceptance and requires terminal-finalization acknowledgement. An effectful destination may emit command acceptance only after durable dedupe/source/effect intent; fixtures prove it has no terminal logical mutation/effect result/`MutationReceipt`, opens no terminal visibility, and cannot satisfy a terminal barrier. Terminal acknowledgement follows finalization, and the source accepts only its declared exact kind. |
| Replay | Inspect/read-only paths perform zero Store writes, migrations, outbox/inbox claims, acknowledgements, Gateway permits, status/cancellation calls, adapter/provider calls, recovery progress, or head changes. Historical explanation remains non-authorizing. |
| Storage migration | Immutable backup, restore, resumable checkpoint, exact source/target validation, CAS/fence races, process kill, disk full, corrupt history, response loss, idempotent rerun, conflict, one writer, partial cutover, uncertain cutover, forward repair, and old-writer denial. |
| Rollback | After new bytes, stopping and rollback-read succeed while old writer/head reactivation, identity reuse, uncertainty deletion, receipt rewrite, and duplicate effects remain impossible. |
| Cross-tenant substitution | Substitute tenant/owner across record, checkpoint, backup, outbox, inbox, capability, acknowledgement, receipt, and opaque history; every case rejects without leaking existence or data. |
| Capacity/history loss | Ceiling/ceiling-plus-one source/target/backup/checkpoint/outbox/inbox/opaque/recovery retention; no eviction of uncertain facts; missing/corrupt/compacted history remains uncertainty and cannot become fresh state. |
| Restore drills | Restore an immutable backup into isolation, validate all digests/links/fences, prove current writer selection, and demonstrate no cross-tenant data, old-head currentness, duplicate dispatch, or lost effect uncertainty. |

### Gold mapping

| Gold | Future assertion mapping | Status after this RFC |
| --- | --- | --- |
| `G00` | Stable IDs/spec/run/artifact/event serialization; production Rust and future generated language round trips; exact bytes where explicitly pinned and observed production serialization elsewhere; unknown authorizing fields fail closed; aliases emit their documented canonical form; Slice 1A lexical values do not imply schema registration; parser success does not prove a live disposition. | `specified_not_implemented` / `not_exercised` |
| `G72` | Owner-bound State-head handoff or migration with exact source/target schemas, one writer, immutable checkpoint/backup, CAS/fencing, no duplicate effects, historical read, crash recovery, old-writer denial, and forward repair. | `specified_not_implemented` / `not_exercised` |

The bounded Slice 1 characterization may create future assertion inputs for
`G00`; all live-disposition expectations remain `not_exercised`. It is not the
public cross-language Gold harness and cannot pass `G00`.
This RFC authorizes no storage or agent migration, so it creates no `G72`
execution evidence.

## Compatibility and RFC Impact

This RFC is additive planning over stable 0.1 and the accepted RFC 0018 Slice 1A
implementation. It preserves:

- stable 0.1 identity, wire, alias, Gateway, verifier, State, Trace, replay,
  work-order, and non-authorizing-extension semantics;
- RFC 0018 behavior-free/non-authority law, implemented Slice 1A scope, reserved
  family stops, Rust-source rule, owner annexes, and generated-publication gate;
- RFC 0019 one-owner, canonical command, outbox/inbox, acknowledgement,
  effect-certainty, recovery, historical, and no-dual-truth laws; and
- RFC 0012 mixed-version fail-closed, historical opaque-read, rollback-stop, and
  task/Gold status posture without adopting its future C03 surfaces.

This RFC fixes the bounded FND-006 planning decisions only for classification,
dispositions, bounded version roles, dossier requirements, and future gates. It
does not register their serialized form. Any public schema, trace-event semantic
change, State format, Gateway/verifier change, daemon/SDK change, owner record,
protocol, generated publication, or persisted migration still requires its own
accepted RFC or owner annex and complete implementation evidence.

If this RFC conflicts with a stable 0.1 contract or a more specific accepted
owner RFC, the stable/specific contract governs its existing scope. A future
change must amend the conflict explicitly; it cannot use this general profile to
weaken a specific owner rule.

## No-Go Gates

Implementation, generation, migration, or rollout must not start, or must stop,
when any applicable condition is true:

- the semantic owner, tenant, audience, schema/domain/version, explicitly pinned
  canonical bytes or observed-output status, digest projection, authorizing
  fields, or currentness source is unresolved;
- a change is unclassified, classified by file location only, or uses a class
  outside the closed six;
- a live input has no one closed disposition or depends on best-effort fallback;
- lexical `CanonicalSchemaIdV1` validity, a candidate RFC 0018 schema string, a
  generated file, or capability advertisement is treated as registration;
- unknown authorizing/security-critical content can be ignored, defaulted,
  coerced, dropped, or downgraded into allow;
- an alias emits alias bytes, creates another identity/key/digest, accepts an
  unreviewed boundary, or conflicts ambiguously with canonical input;
- stable 0.1 observed production serializer output is described as globally
  registered canonical bytes without an explicit stable or owner-contract pin;
- parser or checked-constructor success is treated as `accept_current` or any
  other live disposition without the exact owner-integrated tenant, audience,
  trust, expiry, revocation, currentness, policy, and operation checks;
- N-1-to-N+1 compatibility is inferred from pairwise adapters, a path through N,
  composed execution, or pairwise fixtures instead of a separately owner-
  accepted direct disposition/adapter with exact direct fixtures;
- changed semantics reuse an existing schema/domain/version or reinterpret old
  bytes under new defaults;
- opaque bytes can enter live authority, Gateway, owner mutation, current State,
  key/idempotency derivation, receipt validation, migration output, or live
  replay;
- historical explanation is treated as current trust, authority, policy,
  approval, work-order, Registry state, State head, or effect certainty;
- replay can write, migrate, claim, acknowledge, recover, dispatch, call status/
  cancellation, invoke the Gateway/adapter/provider, or advance a head;
- an authorizing, behavioral, storage, transport, or security-critical change
  lacks an accepted complete dossier and production-path fixtures;
- an additive-authorizing or behavioral change lacks an executable deterministic
  migration-decision function and fixtures, relies on a prose-only no-migration
  decision, or returns anything other than exact owner-validated target output or
  typed fail-closed `unsupported`/conflict; a storage, transport, or security-
  critical conversion lacks the same decision, or fails to return deterministic
  `unsupported` when conversion is out of scope;
- an additive non-authorizing field can affect a decision, canonical identity,
  digest, key, default, resource, replay, or effect, or is later reinterpreted
  without reclassification;
- generated inputs include unimplemented/reserved values; generation is online,
  nondeterministic, partially staged, hand edited, or lacks source/tool/output
  digests and independent negatives;
- Python, TypeScript, OpenAPI, or JSON Schema C03 publication is proposed under
  this RFC alone;
- a `/version` string or package version is used as a negotiation result;
- a protocol lacks owner-issued exact capability matrices, tenant/audience/
  expiry/currentness/trust binding, or stale-client fail-closed behavior;
- a daemon, node, driver, SDK, adapter, generator, bridge, or Store decides
  compatibility legality instead of the semantic owner;
- migration lacks exact source/target contracts, immutable backup, resumable
  owner/tenant-bound checkpoint, CAS/fence, durability receipt, idempotent
  conflict behavior, restore drill, or retained evidence;
- two writers or heads can be current, any dual-write path can diverge, or the
  old writer can reactivate after cutover;
- rollback after new bytes can forget history, return an old head as current,
  reuse an identity, or repeat an effect instead of stopping and repairing
  forward;
- missing/corrupt history can become a fresh miss or inferred no effect;
- SQLite online migration, split State/Trace cutover, or rolling upgrade is
  attempted without its separate accepted annex;
- a no-external-effect destination emits a separate command-acceptance
  acknowledgement or lacks terminal-finalization acknowledgement; an effectful
  destination emits command acceptance before durable dedupe/source/effect
  intent, includes a terminal logical mutation/effect result/`MutationReceipt`,
  or opens terminal visibility; command acceptance satisfies any mutation/effect/
  result/finalization barrier; the source barrier does not declare one exact
  permitted acknowledgement kind; or a sibling/wrong-version/wrong-kind receipt
  can substitute;
- rejection suppresses owner-required denial evidence, emits target-owner
  mutation/currentness/success/authority evidence, derives an ID/authority/digest
  from rejected bytes, calls the Gateway/adapter/provider/status path, causes an
  effect, persists protected rejected bytes, or turns required denial-evidence
  failure into allow;
- protected data, secrets, secret-derived digests, or cross-tenant details can
  leak through fixtures, manifests, errors, logs, metrics, backups, checkpoints,
  or historical views;
- uncertain/possibly committed records can be evicted to regain capacity;
- tests only inspect static fixture declarations despite an available production
  parser/serializer; or
- required compatibility, failure, privacy, resource, replay, restore, and
  mixed-version evidence is missing.

## Open Owner Annexes

This RFC intentionally leaves the following work open and implementation-
blocking:

| Annex | Must define before implementation |
| --- | --- |
| Slice 1 characterization contract | Exact fixture schema/spellings, production parser/checked-constructor/serializer entry points, stable 0.1 and Slice 1A inventory, explicitly pinned versus observed-output labels, parser acceptance/rejection, non-authority checks, and expected-live-disposition cases marked `not_exercised`, including valid stale/wrong-owner/wrong-tenant/wrong-audience inputs. It defines no owner integration or live disposition output. |
| RFC 0018 owner-record grammar annexes | Exact fields, nominal types, presence/null rules, parser APIs, bounds, collection semantics, canonical bytes, digest domains/projections, owner/tenant/audience bindings, and non-authority APIs for each reserved family. |
| Owner compatibility dossiers | Per-owner semantic classes, N-1/N/N+1 matrix, direct non-transitive adapters, executable deterministic migration-decision function with exact target-output or typed fail-closed `unsupported`/conflict results, downgrade, replay, rollback-read, fixtures, and retained evidence. |
| Generator/publication annex | Offline deterministic toolchain, source/tool/dependency/output digests, atomic staging, independent cross-language negatives, package ownership, release gate, and stale-client policy. |
| Protocol negotiation annex | Exact owner-issued capability matrix schemas and state, peer/tenant/audience/trust/currentness/expiry binding, exact selection, transport failures, downgrade resistance, and evidence for each protocol family. |
| Mixed-version outbox/inbox annex | Destination external-effect classification; no-effect terminal-only acknowledgement; effectful durable command-acceptance contents and exclusions; RFC 0019 terminal-finalization acknowledgement; source barrier's exact permitted kind; source/destination keys; receipt validation; duplicates, loss, reorder, restart, and wrong-kind denial. |
| Rejection evidence annex | Existing owner-approved bounded denial/audit path, required denial facts, authenticated caller and server-generated correlation, redaction, protected-byte exclusion, capacity charge, accepted durability, evidence-failure policy, and proof of zero target mutation/effect. It must not invent a universal audit schema. |
| Storage migration mechanics annex | Backend-neutral backup/checkpoint/CAS/fence/durability/restore ports and error behavior without semantic legality decisions. |
| Owner storage/cutover annex | Exact source/target owner records, executable migration-decision function, deterministic execution function for accepted target output, key/identity/head mapping, one-writer cutover, RFC 0019 recovery, rollback-read, forward repair, capacity, and restore evidence. |
| SQLite online migration annex | SQLite locking, transaction/barrier, backup, checkpoint, process-crash, disk-full, schema-version, reader/writer, and operational stop behavior. |
| State/Trace split-store annex | Independent owner/source/destination transactions, stable Trace/State links, no-dual-truth cutover, recovery, replay, and rollback-read. |
| Rolling-upgrade annex | Fleet cohorts, exact peer matrices, admission/fencing, stale worker/client rejection, live SLOs, rollback stop, forward repair, and mixed-version retained evidence. |
| Opaque historical container annex | Exact bounded container, owner/tenant/provenance/integrity/visibility, capacity/retention, corruption states, access/redaction, export, and proof that bytes cannot enter live paths. |

No open annex may be filled by an arbitrary map, generic string reference,
private Store row, daemon DTO, generated model, permissive fake, or fixture that
escapes into production.

## Acceptance Effect

Acceptance authorizes only a separately reviewed, bounded, offline Slice 1
characterization of already implemented stable 0.1 contracts and RFC 0018 Slice
1A values. That slice must use production Rust parsers, checked constructors, and
serializers plus machine-readable positive and negative fixtures. Its executable
claims are limited to parser/constructor acceptance or rejection, exact
explicitly pinned serialization or exact observed production serialization, and
non-authority checks. Observed stable 0.1 output is not newly registered as
canonical.

Slice 1 may contain machine-readable expected-disposition cases and may fix the
six class and four disposition spellings as non-public behavior-free evidence
labels. Every live-disposition status remains `not_exercised` unless the exact
owner-integrated tenant, audience, trust, expiry, revocation, currentness, policy,
and operation checks run in a later authorized slice. Parser or checked-
constructor success can never output or prove `accept_current`. Fixtures must
include structurally valid stale, wrong-owner, wrong-tenant, and wrong-audience
objects that parse where the production parser permits but remain
`not_exercised` for live disposition. This RFC authorizes no owner integration.

Candidate files for that later Slice 1 are focused `splendor-types` tests plus
fixtures and a validator under `conformance/0.2/c03-foundation/v1`. This RFC does
not create those files. The slice makes no daemon, Store, runtime, Gateway,
owner-service, protocol, SDK, or generated-surface change.

Acceptance does not authorize generated publication; a public compatibility
enum or schema; Python, TypeScript, OpenAPI, or JSON Schema C03 output; protocol
negotiation; capability fields; storage migration or cutover; owner records;
RFC 0019/FND-003 runtime; online SQLite work; State/Trace migration; rolling
upgrade; issue #225 closure; FND-006 completion; C03 completion; or any task,
issue, sprint, Gold, conformance, release, durability, or production completion
claim.

`G00` and `G72` remain `specified_not_implemented` / `not_exercised`. Only a
later independently reviewed implementation with retained executable evidence
may change those statuses.
