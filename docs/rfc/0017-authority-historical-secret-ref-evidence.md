# RFC 0017 - Authority Historical SecretRef Evidence

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-20

**Accepted proposal SHA-256:**
`84d17b944a0be0e3edcf0a763db2c07a14d849eab8343fdc78193fe7249d9a09`

**Compatibility line:** Additive experimental 0.2/v2 Authority owner contract
preserving the stable 0.1 authority, work-order, Gateway, trace, state, replay,
and identity contracts and the accepted RFC 0012 through RFC 0016 contracts

**Component:** `splendor.authority-service`, with the C03 Secret Broker as the
RFC 0014 migration consumer

**Owner:** Authority Service in `crates/splendor-authority`; behavior-free
grammar may later live in `crates/splendor-types` only after its foundation
owners accept the exact grammar

**Sprint:** `V2-IA-2 - Authority Decisions And Scoped Delegation`, as a bounded
prerequisite for `V2-IA-3 - Secret Broker`

**Catalog and issue scope:** only the C03-required portions of `AUTH-002` /
[#239](https://github.com/splendor-kernel/kernel/issues/239) and `AUTH-006` /
[#243](https://github.com/splendor-kernel/kernel/issues/243)

**Functional requirements:** constrains `FR-0.2-02` and `FR-0.2-08`

**Primitive strengthened:** Authority issuance/import decision evidence,
historical explanation, and the Authority side of RFC 0014 proof-bound
migration

**Normative dependencies:**
[RFC 0014](0014-revision-bound-secret-credential-authorization.md),
[RFC 0015](0015-event-state-evidence-ownership-and-durability-contract.md), and
[RFC 0016](0016-driver-registry-admission-lifecycle-evidence.md), while
[RFC 0012](0012-secret-broker-contract.md) and
[RFC 0013](0013-driver-operation-credential-sink-contract.md) remain normative
through RFC 0014

**Required collaborating dependency:** before any restricted/redacted view or
privileged export implementation, the applicable `FND-009` policy-independent
classification, deterministic redaction, read-access, and privileged-export
contract must be separately accepted and implemented. This RFC does not
complete `FND-009`.

**Informative implementation context:**
[RFC 0010](0010-authority-service-contract.md) is `Status: Draft`. It describes
the current bounded `AUTH-002a` issuance bridge and `AUTH-006a` local decision
evidence but is not an accepted normative dependency of this RFC.

This RFC is a documentation-only proposal. It creates no runtime, package,
schema, nominal ID, digest profile, persistence format, Event or Evidence
record, daemon route, SDK, CLI, generated surface, migration command, target
allocation, ref-head CAS, Gateway path, or side effect. It closes no issue or
catalog task, completes no component, exercises no gold case, and changes no
conformance status.

The record-family names used below are semantic handles for ownership and
review. Except for names already frozen by accepted RFC 0014, they are not Rust
symbols, wire field names, schema constants, ID spellings, digest domains,
signature algorithms, daemon methods, or generated API names. `FND-001` and
`FND-006` remain the owners of those unresolved contracts.

## Decision

Authority is the sole semantic owner of immutable historical issuance/import
decision evidence for an exact RFC 0014 historical `SecretRef` source entry and
of the separate Authority publication finalization that opens that evidence for
restricted proof use.

For every canonical source entry in one validated `HistoricalSecretRefV1`,
Authority must produce exactly one distinct immutable Authority historical
source record with one distinct `authority_historical_evidence_id` and
`authority_historical_evidence_digest`. That source record binds:

- the exact historical source ref and one canonical entry;
- the complete eligible native issuance/ref-mutation allow or separately
  authorized attested historical import allow that Authority actually made;
- the exact Authority, actor, subject, work-order, capability, policy, data-use,
  purpose, audience, obligation, reason, freshness, and revocation facts used by
  that allow;
- the exact RFC 0016 per-slot Registry evidence record and complete Registry
  coordinate to which the allow was bound; and
- Authority owner provenance, integrity/trust, resource-accounting, audit, and
  publication-intent facts.

Authority evidence for one source entry cannot prove another source entry,
even within the same ref and even when the two entries contain coincident
values. One Authority evidence identity cannot serve two entries. One entry
cannot select multiple Authority evidence records.

The immutable source payload is fixed before downstream publication. Authority
commits the source payload, permanent proof-binding/non-reuse indexes, complete
resource accounting, and one owner-local outbox intent atomically. Event and
Evidence owners then bind the already-fixed source identity and digest under RFC
0015. Authority finally commits a separate immutable publication finalization
that binds the exact acknowledgements and gates restricted visibility. No Event,
Evidence, acknowledgement, receipt, or finalization mutates the source or enters
its digest input.

The historical evidence proves only what the named Authority decision recorded
at its original decision time. It is never current authority. It cannot satisfy
a capability, grant, work order, approval, data-use decision, secret lease,
Gateway verifier, provider access, Registry currentness, C03 migration decision,
or final ref-head CAS. RFC 0014 remains the sole contract for the migration
command, exact proof bundles, source-to-target transform, target allocation,
current-generation checks, and head CAS.

## Exact Bounded Scope

| Catalog task | Bounded target in this RFC | Explicitly not completed here |
| --- | --- | --- |
| `AUTH-002` / #239 | C03-required immutable evidence for an exact eligible Authority-native issuance/ref-mutation allow or a separately authorized attested historical import allow. | General issuer service completion, all signed work-order integration, renewable/non-renewable issuance, Workload Controller/Node Agent adoption, `G60`, or `G83`. |
| `AUTH-006` / #243 | C03-required exact historical decision facts, Authority-record semantic projection and omission meaning, immutable original explanation, current-policy comparison boundary, release decision, and generic Evidence Service handoff. Any view/export implementation remains gated on the applicable accepted and implemented `FND-009` contract. | Full decision-evidence platform, historical policy archive, every Authority decision family, public explain API, any claim of completing `FND-009`, `G01`, or `G03`. |
| RFC 0014 prerequisite | Authority-owned per-entry source record and publication finalization needed by the frozen C03 proof join. | Migration execution, target ref allocation/append, current ref-head mutation, or live credential use. |

The bounded family covers only historical RFC 0014 source-entry evidence. It
does not turn every current Authority decision into this record, define a broad
authority event platform, or authorize arbitrary legacy backfill.

## Current Baseline and Contract Gap

Current `splendor-authority::issuance` implements a bounded local `AUTH-002a`
bridge. It validates a signed `WorkOrderEnvelope`, issuer and subject principals,
issuer workload-admission authority, and work-order scope before constructing a
validated capability grant. Its result is not an immutable RFC 0014 per-entry
historical record, has no exact historical `SecretRef` source entry, has no RFC
0016 per-slot evidence binding, and has no RFC 0015 durable publication.

Current `splendor-authority::evidence` implements bounded local `AUTH-006a`
inspection artifacts under exact schema string:

```text
splendor.authority.decision_evidence.local.v1
```

That local record deliberately marks exact request/scope and protected operation
binding as missing or withheld. Its safe digest omits facts required by RFC 0014,
it has no exact historical ref/entry or Registry evidence binding, and it has no
independently verifiable durable Evidence Service receipt. It remains useful
local compatibility evidence, but it is never eligible RFC 0014 proof and is not
upgraded, wrapped, reinterpreted, or migrated in place by this RFC.

Current issuance also uses a local validation digest shaped as
`work_order:<id>`. That value is not the immutable signed work-order digest,
Authority decision evidence, Registry evidence, or a proof join. It cannot
satisfy this contract. Neither can a current Registry lookup, unsigned row,
filename, database join, matching counter, matching operation name, trace row,
or post-hoc reconstruction.

RFC 0015 and RFC 0016 are accepted planning contracts, not current runtime
evidence that the owner packages, persistence, trust roots, receipts, Registry
lifecycle, or currentness protocol exist. This RFC must not describe those
dependencies as implemented.

## Ownership and Dependency Direction

One concept has one semantic owner.

| Surface | Owns under this RFC | Must not own under this RFC |
| --- | --- | --- |
| `crates/splendor-authority` | Eligibility of native issuance/ref-mutation and attested import origins; exact historical allow semantics; one immutable source record per canonical entry; permanent proof-binding/idempotency indexes; Authority resource admission/accounting; Authority outbox intent; Authority publication finalization; Authority-record semantic projection, omission meaning, and release decisions; Authority recovery decisions. | Policy-independent field/payload classification, deterministic redaction, generic read/export access primitives, privileged-export records, RFC 0014 migration command/target/head semantics, Registry facts, generic Event/Evidence durability, Store policy, Gateway execution, provider or node effects. |
| `crates/splendor-types` | Future behavior-free closed values, strict validation, deterministic serialization, and nominal identities only after accepted `FND-001`/`FND-006` grammar. | Authority eligibility, decision evaluation, currentness, I/O, durability, lifecycle, or migration execution. |
| future `crates/splendor-evidence` | RFC 0015 Event append, Evidence commit, completeness, authenticated receipts, source-reference validation, durability, visibility primitives, and replay plans. | Authority decision meaning, historical-origin eligibility, Registry lifecycle truth, RFC 0014 migration authority, or Authority resource policy. |
| `crates/splendor-store` | Generic persistence primitives and engines for owner-approved immutable rows, transactions, uniqueness, CAS, outbox state, indexes, and integrity storage. | Authority policy, import eligibility, evidence completeness, publication release, currentness, retention legality, or recovery decisions. |
| future `crates/splendor-gateway::registry` | RFC 0016 declaration binding, admission, per-slot C03 Registry evidence, lifecycle/fence/currentness, Registry publication finalization, and Registry resource accounting. | Authority source-entry decision, approved destination set, C03 migration, generic Evidence completeness, or Authority counters. |
| applicable `FND-009` owner contract | Policy-independent field/payload classification, deterministic redaction preserving identity/causal facts, read-access primitives, and privileged-export Event/Artifact requirements. | Authority decision meaning, mandatory Authority proof facts, omission meaning, proof release eligibility, or C03 migration authority. |
| RFC 0014 C03/Authority migration owner | Exact frozen proof-bundle validation, bijective target transform, target allocation/append, final all-current checks, and source-head CAS. | Minting or repairing Authority/Registry/Event/Evidence records; inferring missing proof; rewriting history. |
| daemon, SDK, CLI, bindings | Future authenticated transport translation and safe restricted display after separately accepted contracts. | Direct Store mutation, evidence construction, import eligibility, currentness inference, client-side authority, or alternate migration. |
| callers, importers, policies, messages, work orders | May submit closed proposals and owner references where a later accepted command permits. | Self-attestation, owner selection, committed-record construction, proof completion, resource-policy choice, or authority creation. |

Authority may define narrow outbound ports for authenticated Registry,
Event/Evidence, policy, data-use, work-order, capability, identity/trust, audit,
and resource-reservation facts. Composition bridges may authenticate and
translate those ports. A bridge does not interpret another owner's state,
manufacture currentness, write owner tables, or become a second decision owner.

## Semantic Contract Families

The following handles define minimum meanings only. Their exact grammar remains
blocked on the named foundation owners.

| Semantic family | Minimum meaning |
| --- | --- |
| Authority historical source record | One immutable Authority-owned record for one exact RFC 0014 canonical source entry and one eligible issuance-or-import allow. |
| Historical source proof-set claim | One Authority-owned all-entry claim for the complete canonical entry set of one exact historical source ref. It prevents partial entry creation from becoming migration proof and is not an RFC 0014 bundle member. |
| Permanent entry proof-binding index | One non-reusable mapping from exact source-entry identity to the one source semantics, Authority evidence identity/digest, and Registry binding retained forever or represented by an accepted immutable deny tombstone. |
| Reverse evidence-identity index | One permanent uniqueness check proving one Authority evidence identity/digest pair names only one canonical source entry and one source semantics. |
| Native historical origin | An exact Authority issuance/ref-mutation allow whose authoritative retained decision and source transaction created or approved the exact historical entry. |
| Attested import origin | A separately authorized Authority import allow over exact validated historical bytes and independently verifiable provenance; it records import truth and never fabricates unavailable original issuance facts. |
| Authority publication finalization | One immutable Authority record binding a fixed source identity/digest to exact RFC 0015 Event/Evidence acknowledgements, resource disposition, and restricted release state. |
| Restricted Authority proof inspection view | One Authority-defined semantic projection containing every fact mandatory for RFC 0014 validation or an explicit unavailable/inaccessible disposition, rendered and access-filtered only through the applicable accepted `FND-009` primitives. It grants access to the named source/finalization but is not a replacement owner record or standalone proof. |
| Redacted Authority history view | One Authority-defined non-proof projection whose omission meaning is fixed by Authority and whose classification, deterministic redaction, read checks, and privileged export use the applicable accepted `FND-009` primitives; it cannot satisfy migration. |
| Current-policy comparison | A separate inspect-only result comparing the immutable original decision with an explicitly labeled current or counterfactual evaluation without rewriting or relabeling the original. |
| Owner recovery state | Private Authority state for exact same-command/source/publication reconciliation. It is not a historical decision status, current authority, or migration result. |

## Eligible Historical Origins

### Native Authority issuance or ref mutation

A native origin is eligible only when Authority can authenticate its own retained
source transaction and prove that the exact decision:

1. evaluated the exact source ref and canonical source entry;
2. was made by the Authority owner under the exact operation, scope, purpose,
   audience, actor, issuer, subject, work-order, capability, policy, data-use,
   obligation, and revocation facts retained in the source record;
3. ended in the closed Authority allow status applicable to creation or mutation
   of that exact historical ref entry;
4. bound the exact positive declaration revision and exact RFC 0016 per-slot
   Registry evidence/coordinate before the source entry became eligible;
5. retained owner provenance, integrity, trust/key-status, resource, and audit
   facts; and
6. is not a reconstruction from `local.v1`, a generic decision, current state,
   a ref row alone, or matching values discovered later.

An allow for workload admission, grant issuance, generic secret use, a different
ref revision, another entry, or another Registry generation is not eligible
merely because it names the same principal, work order, operation, slot, or
digest.

### Separately authorized attested historical import

An imported origin is eligible only when all of these independently pass:

1. the import command has its own authenticated actor, exact tenant/ref scope,
   Authority-service audience, dedicated import operation, current work order,
   capability, policy, data-use, expiry, revocation, and audit authority;
2. the imported historical source ref and every entry pass the exact RFC 0014
   bounded historical parser, canonicalization, source identity, ordinal, and
   digest rules before any durable claim;
3. the source Authority/export owner, provenance object, immutable source
   coordinates, and attestation are independently authenticated under an
   accepted purpose-separated trust and key-status path usable by C03;
4. the attestation binds the exact historical source bytes, source ref digest,
   source entry identity/ordinal/bytes/digest, and every original fact it claims;
5. the importing Authority makes and retains a distinct import allow decision
   over that exact attested package and the exact RFC 0016 Registry binding;
6. the source record clearly distinguishes imported provenance from native
   issuance and retains both the source attestation facts and the actual import
   decision facts; and
7. all Authority and downstream resource reservations succeed before claim.

Import never upgrades unauthenticated history. If original issuance facts cannot
be authenticated, the source record must state that those facts are unavailable
and must not present the import decision as the original issuance decision. The
import can be eligible only to the extent that an accepted source-owner
attestation contract independently proves every fact required by this profile.
If that contract or any required fact is absent, import remains non-live
historical inspection and cannot produce RFC 0014 proof.

A caller statement, importer signature over self-described facts, generic file
signature, current Authority decision, `local.v1` record, work-order string,
unsigned export, filename, database row, foreign key, join, timestamp, matching
number, or recomputed digest is never an eligible attestation.

### Origin status and later revocation

The original closed allow status is immutable historical fact. Later principal,
credential, issuer, subject, capability, work-order, policy, data-use, Authority,
Registry, source-owner, attestation-key, or trust-root revocation does not edit or
delete that fact. It may make the record ineligible for a new migration or
restricted release under current policy. Uncertainty has the same fail-closed
effect on new privileged use while preserving restricted history.

## One Immutable Source Record Per Canonical Entry

### Complete source and entry binding

Each Authority historical source record binds all semantic facts in this table.
Presence, absence, and ordered/set semantics are part of the binding. A future
grammar may split these into closed nested values, but it may not omit an
applicable fact or move one into an extension.

| Fact family | Required semantic facts |
| --- | --- |
| Source ref | Exact `SecretRefId`, positive source `secret_ref_revision`, complete validated canonical `HistoricalSecretRefV1` bytes, exact RFC 0014 `source_ref_digest`, exact tenant, and complete canonical entry count. |
| Source entry | Exact `source_entry_identity`, zero-based canonical `source_entry_ordinal`, complete canonical historical entry bytes, exact RFC 0014 `source_entry_digest`, canonical operation, exact slot, destination schema, exposure profile, trusted-send profile, and complete sorted approved destination digest set. |
| Origin classification | Exact native issuance/ref-mutation or attested import origin; no implicit, unknown, generic, or reconstructed origin is eligible. |
| Authority decision | Exact eligible issuance-or-import decision identity and revision, closed allow status, owner decision time, complete canonical request/decision semantic digest, bounded canonical reason codes and explanation, and explicit decision profile/version. |
| Authenticated parties | Exact tenant; actor/caller principal and caller credential identity/status/revision/revocation generation; issuer principal and proof/key/trust status where distinct; exact subject principal; and every required delegation parent or service principal reference. |
| Operation and scope | Exact typed Authority operation, complete evaluated scope, secret-ref/entry operation, purpose, service audience, and every narrowing locality, time, budget, data, driver, or resource dimension applicable to the allow. |
| Work order | Exact work-order identity, immutable digest, revision, issue/expiry status, audience, signing owner/key/trust status, and revocation generation used at decision time. |
| Capability/grant | Exact capability/grant identity, revision/digest, issuer/subject, parent chain or explicit absence, operation/scope intersection, obligations, validity interval, audience, and revocation status/generation used at decision time. |
| Policy and data use | Exact policy identity/revision/digest and current-at-decision status; exact data-use decision/grant identity, revision/digest, purpose/scope, expiry, and revocation generation; explicit absence only where the accepted decision profile proves the fact inapplicable. |
| Obligations and reasons | Complete bounded obligation identities/types and exact satisfied owner-receipt references where required, plus normalized reason/explanation facts. A conditional, unsatisfied, inaccessible, or uncertain obligation cannot be normalized to allow. |
| Freshness/current-at-decision | Exact ref-head/refresh, Authority, policy, capability, work-order, data-use, revocation-snapshot, principal/credential, cache, and offline/TTL revisions or generations observed for the original decision, with their owner status and observation time. Historical freshness never implies currentness at migration time. |
| Registry join | Exact RFC 0016 per-slot Registry evidence identity/digest; Registry tenant, installation identity/scope digest, admission identity/digest, permanent declaration-binding identity/digest, declaration digest, canonical operation, positive declaration revision, exact slot and sink-entry binding, lifecycle state `active`, lifecycle generation, revision-fence observation, and Registry source/finalization references required by that owner contract. |
| Owner provenance and integrity | Authority owner principal/service instance, owner revision/time, source profile/version, predecessor integrity, source digest and source-owner receipt/attestation output retained alongside the fixed payload, and purpose-separated signer/attestation/key/trust-status references required for independent C03 verification. |
| Resource facts | Exact effective Authority resource-policy revision, semantic-coalescing result, all Authority reservation/accounting identities, worst-case retained and downstream publication obligation, consumed/releasable disposition, retained debt, and checked-overflow result. |
| Audit and visibility | Authenticated cause/correlation references, decision/import audit reference, source classification, proof audience, visibility policy/revision, and the owner-local audit obligation. No protected payload is copied to satisfy these facts. |
| Publication intent | One owner-local outbox intent identity and exact Event/Evidence profiles, subject binding, requested durability floor, and destination owner/audience. No downstream acknowledgement or finalization is included. |

No field family above is permission by itself. A source record that cannot
represent an applicable owner fact is incomplete and ineligible; a side table,
hidden join, log, current lookup, or view cannot repair it.

### Protected-data exclusion

The source, finalization, outbox, Event/Evidence payloads, views, audits, errors,
and accounting records contain no secret material, secret-derived digest,
provider credential, provider request/error, provider-resolvable locator,
delivery endpoint, permit, lease material, approval token, private key, raw
signature secret, protected evaluation case identifier, private chain-of-thought,
or unrestricted protected payload. Authority defines which Authority semantic
facts are mandatory and what omission means; it does not redefine `FND-009`
policy-independent classification, deterministic redaction, read access, or
privileged-export behavior.

Exact operation/scope/purpose facts are retained as closed owner facts or safe
immutable references under restricted classification. Raw policy bodies,
arbitrary metadata, free-form reason text, and protected source payloads are not
copied. A digest is not a redaction mechanism; a low-entropy, secret-derived, or
enumeration-sensitive digest is forbidden unless an accepted owner contract
explicitly permits that exact restricted use and proves it is not secret-derived.

### Canonical source and digest boundary

The future source payload must be one closed, bounded, deterministic canonical
value. Its bytes include every immutable source fact above that the accepted
grammar assigns to the payload. They exclude:

- the source payload's own digest output;
- any source-owner signature, attestation, or current-integrity output computed
  from that already-fixed payload or source digest;
- Event coordinates, append receipts, or acknowledgements;
- Evidence bundle coordinates, commit receipts, completeness outputs, or
  acknowledgements;
- Authority publication-finalization identity, bytes, digest, revision, or time;
- later current-policy comparisons, currentness observations, migration results,
  target refs, or head-CAS results; and
- mutable Store/outbox delivery-attempt metadata.

The source digest and any owner signature/attestation over it are envelope/output
metadata retained atomically with the fixed payload; neither recursively enters
the payload it authenticates. The exact digest domain, algorithm, output type,
canonical timestamp grammar, schema string, and wire representation remain
blocked on `FND-001` and `FND-006`. An implementation-local hash is not
acceptable. RFC 0014's already accepted source-ref and source-entry digest
constructions remain unchanged; this RFC does not redefine them.

### Complete ref-set atomicity

For a historical ref with one or more canonical source entries, Authority must
first validate the complete ref and every entry. In one Authority transaction it
must then:

1. claim the complete historical source-ref proof set;
2. enforce one distinct source/evidence identity per canonical entry;
3. insert-or-compare every permanent forward and reverse proof binding;
4. fix every source payload and digest;
5. retain the complete resource reservation/accounting/debt projection; and
6. commit one distinct owner-local outbox intent for each fixed source.

Any entry validation, eligibility, trust, Registry binding, uniqueness,
resource, canonicalization, or Store failure commits none of those source rows,
indexes, or outboxes. Publication may progress independently for recovery, but
RFC 0014 consumption requires every canonical source entry to have its exact
finalized Authority record and proof bundle. A partially finalized ref is not
migration-proven and cannot produce a partial target.

The proof-set claim is Authority-internal completeness state. It does not add a
nineteenth RFC 0014 proof-bundle member or replace RFC 0014's bundle count,
proof-bundle array ordering by `source_entry_ordinal`, and bijection checks.

## Permanent Proof Binding, Idempotency, and Non-Reuse

Authority maintains both directions of permanent uniqueness:

1. one exact source-entry identity maps forever to one source ref/entry digest,
   complete decision/origin semantics, exact Registry binding, Authority
   evidence identity/digest, source transaction, and terminal or uncertain
   disposition; and
2. one Authority evidence identity/digest maps forever to only that source-entry
   identity and semantics.

The stable command namespace for native evidence creation, import, finalization,
and recovery must include authenticated tenant, authenticated actor or internal
service principal, Authority service audience, command family, and one
family-specific nominal command identity. Exact wire identities remain blocked
on `FND-001`; a request ID, trace ID, evidence ID, ref ID, work-order ID, digest,
or entry ordinal cannot be reused as an implementation shortcut.

After authentication, visibility, dedicated-scope checks, request-rate
enforcement, semantic coalescing, and complete resource reservation, the first
accepted command atomically retains its complete normalized semantics and one
owner first-observation fact. Exact duplicate delivery or response loss resumes
or returns only the original source/finalization/result. It allocates no new
identity, revision, timestamp, source byte, digest, outbox, Event, or Evidence
record.

The same stable command identity with any changed semantic byte is a permanent
conflict. Independently, the same source-entry identity with changed source,
decision/origin, Authority, Registry, trust, resource, or audit semantics is a
permanent proof-binding conflict even under a fresh command identity. A fresh
command, import package, work order, actor, principal, tenant, ref, or Registry
query cannot overwrite, fork, or bypass an existing binding.

Full privileged records and non-reuse markers have no TTL under this bounded
contract. Retention may remove payload only after a separately accepted protocol
commits an immutable non-reuse tombstone/deny head that binds the owner and
partition, stable key, source-entry and evidence identities, complete semantic
digest, original result or uncertainty, predecessor integrity, resource debt,
and retention generation. Exact replay returns the retained disposition;
changed replay remains conflict. Missing, corrupt, inaccessible, compacted, or
uncertain history is never a fresh miss.

## Event, Evidence, and Publication Finalization

RFC 0015 is the sole owner of generic Event/Evidence durability,
completeness, receipts, and coordinates. Authority follows this acyclic graph:

```text
Authority validation and finite reservation
  -> atomic Authority proof-set/source/index/resource/outbox commit
  -> authenticated RFC 0015 Event append over fixed source identity/digest
  -> authenticated RFC 0015 Evidence commit over fixed source and Event receipt
  -> immutable Authority publication finalization over exact acknowledgements
  -> fresh restricted visibility and migration-proof release checks
```

The source transaction and its outbox must share one local atomic Authority
boundary. Event owner commits inbox deduplication and append under RFC 0015.
Evidence owner commits its bundle and permanent idempotency under RFC 0015.
Cross-owner delivery is at least once with exact duplicate recovery; this RFC
does not claim distributed exactly-once or a transaction spanning independent
stores.

Authority validates the authenticated Event acknowledgement and Evidence commit
receipt before finalization. The finalization binds at least the already-fixed
source identity/digest, source transaction and outbox identities, exact Event
coordinate/receipt, exact Evidence bundle coordinate/commit receipt, achieved
durability and completeness, ordered source bindings, owner identities and
trust/key status, consumed resource reservations and retained debt, and one
Authority finalization identity/revision/time and release disposition.

Finalization is append-only and never edits the source. Its digest is not a
prerequisite of the Event/Evidence records it acknowledges. A later audit event
about finalization is another non-gating source and cannot recursively enter the
finalization it describes.

If Authority source state and outbox cannot share one supported transaction, the
source operation is unsupported and fails before claim. If independent
Authority/Event/Evidence stores lack an accepted `FND-003` recovery/publication
barrier, external proof release is unsupported. Queue acceptance, buffered
bytes, unacknowledged outbox state, a generic trace row, memory-only evidence, a
bare digest, `complete`, `demonstrated`, or a database transaction ID is not
publication success.

## Frozen RFC 0014 Proof Bundle

RFC 0014 orders the proof-bundle array by `source_entry_ordinal`. Each closed
bundle object contains exactly these eighteen required non-null members, listed
below in RFC 0014's presentation sequence for cross-RFC equality review:

```text
source_entry_identity
source_entry_ordinal
source_entry
source_entry_digest
authority_historical_evidence_id
authority_historical_evidence_digest
registry_admission_evidence_id
registry_admission_evidence_digest
registry_installation_id
registry_installation_scope_digest
registry_admission_id
registry_admission_digest
registry_declaration_digest
registry_lifecycle_generation
proven_driver_declaration_revision
target_entry_ordinal
target_entry
target_entry_digest
```

This RFC adds no nineteenth member, side field, extension, receipt field,
finalization field, owner field, trust field, resource field, currentness field,
or alternate bundle version. Unknown, missing, null, duplicate, alias, side, or
extension members reject under RFC 0014 before owner lookup. JSON object member
encounter order is not an additional parser rule. Deterministic object
serialization follows RFC 0014's accepted RFC 8785 canonicalization contract;
only the proof-bundle array order is caller-significant here.

### Direct field equality

The following comparisons use only the frozen bundle members and complete
dereferenced owner source records. They are direct proof validation, not hidden
joins.

| Bundle facts | Direct required equality |
| --- | --- |
| `source_entry_identity`, `source_entry_ordinal`, `source_entry`, `source_entry_digest` | Equal the exact canonical entry selected from the command's complete historical source ref and the same facts in the one dereferenced Authority historical source record. |
| `authority_historical_evidence_id`, `authority_historical_evidence_digest` | Equal the dereferenced Authority source record's distinct identity and digest, whose digest recomputes over its fixed canonical source payload under the accepted future profile. |
| `registry_admission_evidence_id`, `registry_admission_evidence_digest` | Equal the exact per-slot RFC 0016 Registry source record named by the Authority record and the dereferenced Registry record. |
| `registry_installation_id`, `registry_installation_scope_digest` | Equal the Registry coordinate in both the Authority record and the exact Registry record. |
| `registry_admission_id`, `registry_admission_digest` | Equal the immutable admission coordinate in both owner records. |
| `registry_declaration_digest` | Equal the complete declaration digest in both the Authority source record and exact per-slot Registry source record. Validation of the Registry record against the permanent declaration binding is transitive. |
| `registry_lifecycle_generation` | Equal the historical active generation in both owner records; it remains subject to a separate final current check. |
| `proven_driver_declaration_revision` | Equal the positive revision in the source-bound Authority decision, the Registry record, and the only revision inserted into the mapped target entry. |
| Operation and slot inside `source_entry` | Equal the operation/slot in the Authority source record and exact per-slot Registry record. They are existing closed source-entry facts, not new top-level bundle members. |
| `target_entry_ordinal`, `target_entry`, `target_entry_digest` | Satisfy RFC 0014's exact bijective shape-preserving transform and digest rules for the mapped source entry and proven revision. |

Every source entry, Authority identity/digest, Registry identity/digest, and
target entry appears exactly once under RFC 0014's proof-bundle array ordering
and bijection rules. Swapping array elements, omitting, duplicating, reusing,
splitting, merging, or mapping an entry many-to-one or one-to-many denies before
target allocation.

### Transitive owner validation

The following facts are mandatory but are not members of the frozen bundle. The
verifier reaches them only by dereferencing the exact directly named owner
records and validating each owner's accepted contracts.

| Transitive validation | Required check |
| --- | --- |
| Authority source origin | Native issuance/ref-mutation or attested import eligibility; exact allow decision; complete actor/issuer/subject, operation/scope/purpose/audience, work-order, capability, policy, data-use, obligation, reason, freshness, and current-at-decision facts. |
| Authority source integrity | Canonical source digest, predecessor/current integrity, source-owner provenance, distinct entry/evidence identity, permanent proof binding, and no source mutation. |
| Authority owner trust | Independently verifiable Authority owner attestation/signature, purpose and audience, owner/service identity, trust root, key identity/type/status/revision/validity/revocation, and accepted C03 verification profile. A local private wrapper is insufficient for C03 proof. |
| Authority publication | Exact Authority outbox, RFC 0015 Event coordinate/receipt, Evidence bundle coordinate/commit receipt, ordered source binding, durability/completeness, and immutable Authority finalization for this one source digest. |
| Registry source | RFC 0016 permanent declaration binding, publisher/publication authority, per-slot source integrity, active historical lifecycle fact, exact slot-entry bytes/fingerprint, Artifact/Lineage/conformance/compatibility references, and owner resource facts. |
| Registry owner trust | Registry source/finalization, Event/Evidence receipts, Registry signer/owner trust and key-status path, and non-substitution among admission, activation, per-slot, transition, and current-observation publications. |
| Generic Evidence | RFC 0015 source-owner/receipt equality, ordered item binding, completeness, integrity, achieved durability, owner authentication/attestation, visibility, and no memory-only/unsigned/untrusted/uncertain coordinate. |
| Resource status | Authority and Registry records remain fully accounted, reservations/debt are not corrupt or uncertain, and no owner claims another owner's capacity semantics. |
| Currentness | RFC 0014 final all-current Authority/ref checks and RFC 0016 exact Registry current binding/fence/publisher/lifecycle checks through one supported linearization path. |

An admission receipt cannot substitute for a per-slot receipt, and a per-slot
receipt cannot substitute for a current-observation receipt. Authority and
Registry evidence identities are distinct. Event and Evidence receipts from one
source or family cannot finalize another. A recomputed outer wrapper does not
make an untrusted inner owner record valid.

A bare digest, timestamp, signature without its owner/key-status path, current
head, generic decision, completeness label, Store row, foreign key, join result,
operation lookup, manifest, filename, image tag, source order, or coincident
number proves none of these facts.

## Historical Proof Is Never Authority

Possession, visibility, successful parsing, valid integrity, complete Evidence,
or exact RFC 0014 equality grants no current permission. Authority historical
evidence cannot:

- create, renew, or widen a capability or delegated grant;
- authorize a work order, approval, data use, policy, secret lease, provider
  fetch, node delivery, Gateway permit, adapter/driver invocation, or side
  effect;
- make a Registry admission current, clear a declaration-revision fence, or
  reactivate a stale/revoked/quarantined lifecycle;
- select a declaration by latest, numeric order, alias, digest, or presence;
- make a historical source ref live, allocate a target, or move a ref head;
- resolve current or uncertain owner state by assumption; or
- convert replay, import, redaction, or policy comparison into a live decision.

Every future live action still requires the complete RFC 0012 Authority,
work-order, data-use, quota, approval, lease, safety, Gateway, verifier,
postcondition, trace, and state path. Every migration still requires RFC 0014's
fresh migration decision and final CAS.

## Currentness, Revocation, and Final Migration CAS

Historical source publication is not a currentness service. A current-policy
comparison is not a current Authority decision. An RFC 0016 current observation
is a preflight fact only. No successful preflight, old allow, cache hit,
historical active generation, or prior current-observation release can win over a
later revocation or lifecycle transition.

Immediately before RFC 0014's migration head CAS, the RFC 0014 owner must
atomically revalidate, or revalidate through an accepted `FND-003` protocol, all
of these exact expected facts:

- source ref ID/revision/digest is still the exact current head at the
  expected head and refresh generations;
- authenticated actor/subject, Authority operation/scope/purpose/audience, and
  migration authority still match;
- Authority decision, policy, capability/grant, work order, data-use decision,
  approval/obligation where applicable, principal/credential, signer/trust, and
  every relevant revocation generation remain current;
- the retained Authority source/finalization and proof-binding/non-reuse history
  remain valid, visible, trusted, fully accounted, and non-uncertain;
- every exact RFC 0016 tenant/installation/admission/per-slot evidence,
  declaration binding, positive revision, declaration digest, slot, active
  lifecycle generation, activation/deployment/gate/rollout fact, publisher and
  publication-authority fact, owner-global revision fence, signer/trust fact,
  resource status, and publication finalization remains current; and
- target append and expected-head facts remain exactly those retained by RFC
  0014's one migration command.

The expected source head remains RFC 0014's exact four-member value:

```text
secret_ref_id
secret_ref_revision
secret_ref_digest
secret_ref_head_generation
```

The Authority/ref expected-current set remains RFC 0014's exact ten counters:

```text
secret_ref_head_generation
secret_ref_refresh_generation
authority_revision
policy_revision
revocation_snapshot_generation
capability_grant_revision
work_order_revision
work_order_revocation_generation
data_use_decision_revision
data_use_revocation_generation
```

Each proof bundle's separate `registry_lifecycle_generation` remains bound to
its exact RFC 0016 record and final current Registry recheck. These accepted
names do not add an Authority historical source field or a nineteenth proof-
bundle member.

These checks must participate in the same supported authoritative transaction as
the head CAS without either owner rewriting the other's semantics, or in the
accepted `FND-003` command/ordering/recovery protocol that defines the exact
linearization winner. A preflight RPC, copied status snapshot, current timestamp,
cached generation, or two independent commits described as atomic is
insufficient.

A ref-head change, Authority/policy/capability/work-order/data-use revocation,
principal or key revocation, Registry `active -> stale|revoked|quarantined`
transition, global declaration-revision fence, publisher/publication-authority
revocation, or resource/trust uncertainty that commits before the supported
final CAS wins and prevents target-head movement. If the CAS commits first under
the accepted RFC 0014/FND-003 ordering, that migration result remains subject to
all later RFC 0012 live-use checks; this RFC creates no post-migration lease or
use authority.

Later revocation preserves immutable restricted history and original
explanation. It does not rewrite the source, Event, Evidence, or finalization.
Current release and migration eligibility can still deny.

## Visibility, Redaction, Audit, and Oracle Resistance

Authentication, endpoint or internal-operation scope, exact tenant/ref binding,
Authority-service audience, current caller credential, work order, capability,
data-use, policy, revocation, and dedicated historical-read or migration-proof
authority must pass before any existence-sensitive source, proof-binding,
idempotency, Registry, Event, Evidence, finalization, or resource lookup.

Authority owns only the exact semantic projection for its records, the meaning
of mandatory versus omitted Authority facts, and the final Authority release
decision. The applicable accepted and implemented `FND-009` contract owns and
must supply policy-independent field/payload classification, deterministic
redaction, read-access enforcement primitives, and privileged-export Event and
Artifact requirements. Authority consumes those primitives and policy inputs; it
does not duplicate their policy engine or record ownership.

This RFC does not invent a new external scope string or daemon response profile.
RFC 0014's existing migration/history visibility rules remain controlling for
that surface. Any future standalone Authority evidence query requires a
separately accepted daemon/security contract and must preserve one
non-reflecting profile for hidden, absent, wrong-tenant, wrong-principal,
wrong-scope, wrong-audience, conflict, incomplete, inaccessible, stale, revoked,
corrupt, untrusted, exhausted, unavailable, and uncertain results.

No outward mutation or read result may reveal existence, source/entry count,
ordinal, owner identity, decision status, Registry coordinate, digest,
generation, signer, key, trust root, conflict reason, resource balance, lookup
count, or retry advice through body, status, headers, timing class, logs, metrics,
or error/source chains without the dedicated authorized view.

Every restricted or redacted view requires the accepted `FND-009` read check and
a durable audit commit before bytes are released. When bytes are exported, its
required privileged-export Event and Artifact must also commit. Those records
bind inspector identity, tenant/ref, operation/scope, purpose, audience, current
Authority/policy/work-order/capability/data-use/revocation generations,
source/finalization coordinates, view kind and redaction policy, result, and
owner time without copying protected source payloads. Required audit or export
reservation/commit failure withholds the view. Mutation authority alone does not
grant proof-read authority.

A restricted C03 proof inspection view either exposes every mandatory Authority
source, owner trust/key-status, publication, and Registry-binding fact or fails
closed. The verifier still validates the exact source and finalization records;
the view is not a substitute owner record or proof by itself.
A redacted view binds its exact source/finalization, viewer scope, included
facts, explicit omitted/inaccessible facts, redaction policy/revision, and view
integrity. Redaction never turns incomplete into complete, inaccessible into
absent, historical into current, or a non-proof view into migration proof.

Source/entry bytes, approved destination digests, policy/data-use coordinates,
work-order/capability details, Registry admission/declaration coordinates,
attestation/key status, and conflict/resource facts stay out of generic trace,
metrics, logs, discovery/list responses, crash bundles, and unauthorized errors.
Dedicated restricted evidence is not a generic observability escape hatch.

## Replay, Historical Re-evaluation, Policy Comparison, and Import

Replay is inspect-only by default. With current read authority, it may
reconstruct retained source decisions, canonical entry binding, proof-set
completeness, publication/recovery state, later revocations, and RFC 0014 direct
or transitive mismatch explanations. Replay-plan construction may use only
authenticated, access-filtered read/query ports to obtain the exact immutable
bytes permitted by current read authority. The resulting plan is detached and
non-live; plan execution cannot use those ports to mutate, refresh, publish, or
contact a live effect boundary.

An inspect-only historical-policy re-evaluation may exist only after an accepted
policy archive and evaluator contract can load the exact historical policy and
all required historical inputs. Its output is a separate labeled
counterfactual/re-evaluation record. A current-policy comparison likewise labels
the immutable original, the separately evaluated current/counterfactual result,
the policy/evaluator versions, unavailable facts, and differences. Neither path
changes the original source, decision, reasons, status, digest, Event/Evidence,
finalization, or migration eligibility.

If the exact historical policy or any required input is absent, inaccessible,
untrusted, revoked for the comparison purpose, or unavailable, the comparison
reports that bounded condition. It must not evaluate only current policy and call
the output the original decision. Current `compare_authority_evidence` remains a
local comparison of already-recorded `local.v1` artifacts and is not this
historical re-evaluation or proof contract.

After authorized read/query and detached-plan construction, replay, generic
evidence/history import or export inspection, simulation, re-evaluation, and
comparison cannot:

- claim or finalize a command, source, proof binding, outbox, Event, Evidence,
  audit, resource reservation, target, or head;
- refresh Authority, principal, work-order, capability, policy, data-use,
  approval, Registry, trust, or key status;
- contact a provider, node, Gateway, adapter, driver, network, filesystem,
  database, owner repository, publication port, or external effect service
  during detached execution;
- issue a grant, lease, permit, currentness receipt, or migration decision;
- allocate or free owner capacity, reset counters/debt, or bypass semantic
  coalescing; or
- treat a historical active/allowed fact as live.

The separately authorized attested Authority import origin defined above is a
distinct privileged mutation family, not replay or generic evidence import. It
may claim an Authority historical source only through its authenticated command,
complete pre-claim admission, and acyclic publication path. It is the only
Authority-owned import mutation in this RFC.

Generic replay/history import is transient only. Under current read authority it
may parse, validate, and use exact supplied or access-filtered bytes solely as
detached non-live plan input. It creates no Authority source, non-proof record,
import record, quarantine record, proof-set claim, binding/non-reuse index,
outbox, Event/Evidence publication, finalization, import-specific audit result,
currentness fact, target, or head mutation, and retains no bytes or provenance
under this RFC. Independently required read/export audit belongs to the
applicable `FND-009` owner and does not make the import persistent.

Persistent non-proof inspection or quarantine requires a separately accepted
owner and contract outside RFC 0017. Any such future record is not
Authority-owned proof state under this contract, can never enter Authority proof
or non-reuse indexes, cannot be selected by RFC 0014, and cannot be upgraded into
RFC 0014 proof by attaching a current decision, provenance, attestation, or
reconstructed join. If that separate owner contract is absent, persistence is
unsupported rather than silently assigned to Authority.

## Finite Resource Admission, Isolation, and Retained Debt

No privileged Authority operation in this family may durably claim a command,
proof set, source entry, evidence identity, proof binding, outbox, finalization,
audit view, attested-import source, tombstone, or recovery mutation until finite
owner-resource admission succeeds. Generic replay/history import creates none of
these retained objects.

The effective Authority policy has finite hard bounds for all of these classes:

- request rate and burst/concurrency;
- in-flight proof-set, per-ref, per-entry, attested-import, publication, audit, and
  recovery work;
- retained command, proof-set, source, binding, finalization, view,
  non-reuse-marker, and tombstone cardinality;
- raw validated ingress where later permitted, canonical source/finalization,
  index, outbox, audit, tombstone, and total retained bytes/capacity;
- outbox and downstream Event/Evidence/audit backlog;
- downstream Event append, Evidence commit, audit append, inbox,
  deduplication, receipt, acknowledgement, and recovery reservations; and
- committed, possibly committed, uncertain, quarantined, and retained
  publication/non-reuse debt.

Every class is enforced at minimum across the combined authenticated tenant,
principal, source ref, source entry, command family, and global Authority scopes.
All applicable scopes must pass. Per-scope isolation, reserved capacity, and
backpressure prevent one tenant, principal, ref, entry, or family from consuming
all shared capacity. Isolated capacity cannot override the global safety ceiling.

Authority owns its effective resource policy, counters, reservations, semantic
coalescing, debt, and admission decision. Work orders, capability grants, and
deployment policy may narrow Authority limits but cannot widen/reset owner
counters. Event, Evidence, audit, Registry, and Store owners keep their own
accounting semantics. This RFC defines no numeric default, window algorithm,
wire field, configuration API, external-owner quota rule, or Store retention
policy.

Before durable claim, Authority computes a conservative complete worst-case
obligation for every Authority source/index/outbox/finalization/audit/recovery/
tombstone record and every required downstream publication/audit obligation. It
uses an accepted same-owner transaction or multi-owner reservation/compensation
protocol to reserve that obligation. If independent owners cannot reserve before
claim and no accepted `FND-003` protocol proves compensatable accounting, the
operation is unsupported and fails closed.

After authentication/visibility and request-rate enforcement, semantic
coalescing occurs before permanent allocation. A fresh command or attested-import
command ID for an exact unchanged semantic request resumes the original retained
path where family freshness/release rules permit; it does not force duplicate
permanent history. Coalescing is tenant/principal/ref/entry/family/audience
scoped and cannot reveal or reuse another scope's record.

Transient generic import parsing remains subject to finite authenticated
request, parser, byte, concurrency, and read/query limits, but it creates no
permanent Authority reservation, retained debt, or compensating release. A
separate persistent inspection/quarantine owner must define and account for its
own resources under its separately accepted contract.

Arithmetic is checked and non-wrapping. Missing, stale, unavailable, overflowed,
corrupt, or uncertain policy, counter, capacity, reservation, debt, or downstream
accounting fails before claim. Capacity denial creates no source, binding,
outbox, Event, Evidence, finalization, audit result, or tombstone and cannot turn
a permanent conflict or uncertain prior use into allow.

Committed or possibly committed records, non-reuse markers, lost
acknowledgements, publication backlog, and uncertain outcomes remain charged
until an accepted reconciliation or retention protocol proves exact disposition.
Compensation releases only demonstrably unconsumed reservation after
owner-authenticated proof of absence. Restart restores the exact policy revision,
counters, reservations, debt, isolation partitions, coalescing indexes, and
non-reuse history before new work; unavailable recovery state fails closed rather
than starting empty.

## Failure and Race Semantics

### Fail-closed outcomes

These are semantic dispositions, not wire error codes.

| Failure | Required result |
| --- | --- |
| Authentication, scope, tenant/ref visibility, audience, work order, capability, policy, data-use, expiry, or revocation fails | No existence-sensitive lookup or durable claim; one non-reflecting denial. |
| Historical parser, canonical source identity/ordinal/digest, or complete ref-set validation fails | No proof-set/source/index/outbox mutation; rejected bytes are not retained in generic surfaces. |
| Native origin is not exact or original Authority state is unavailable | Origin is ineligible; no reconstruction or `local.v1` upgrade. |
| Attested-import provenance/attestation, source-owner trust, or original facts are missing or untrusted | Attested import denies; generic transient import cannot produce proof; no original-issuance claim is fabricated. |
| Registry evidence or any exact three-way coordinate mismatches | The entry is unproven; no target allocation or partial ref proof. |
| Same command changed, source-entry binding changed, or evidence identity reused | Permanent conflict; no replacement identity or fork. |
| Resource reservation, checked arithmetic, or downstream accounting fails | No durable claim or owner/downstream write. |
| Authority source transaction proves no commit | Reservation is compensated only with proof of absence; an exact retry may use the same command. |
| Authority source transaction outcome is uncertain | Same command/proof set is quarantined for lookup; no replacement source or identity. |
| Event append or Evidence commit rejects/fails | Source remains immutable and restricted/unfinalized; no success or proof visibility. |
| Event/Evidence outcome or acknowledgement is uncertain | Same downstream command is reconciled; no new source, Event, Evidence, or finalization identity. |
| Finalization validation or Store commit fails/uncertain | Source stays restricted; same-finalization recovery only. |
| Durable audit-before-view fails | View bytes are withheld. |
| Owner/key/trust status is revoked, expired, inaccessible, or uncertain | History may remain inspectable under policy, but privileged proof release and migration deny. |
| Final currentness or head CAS conflicts | RFC 0014 retains truthful stale/conflict result; no live target head is inferred. |
| Replay/comparison/generic evidence or history import attempts mutation or external effect | Reject before effect; zero Authority proof/head/provider/Gateway mutations. A required FND-009 read/export audit remains separately owned and non-authorizing. The separately authorized attested Authority import follows its privileged command path above. |

### Race winners

| Race | Required winner |
| --- | --- |
| Concurrent exact duplicate source commands | One source/proof-set transaction wins; every exact duplicate resumes the original. |
| Concurrent changed semantics under one command or source-entry binding | The first retained binding is permanent; changed contenders conflict and create no durable loser record beyond finite non-reflecting security/audit policy. |
| Source transaction versus Event delivery | Source and outbox must commit first; Event cannot append a source that is not authenticated and fixed. |
| Event append versus acknowledgement loss | Event's original inbox/receipt wins; redelivery returns it and cannot append changed bytes. |
| Evidence commit versus acknowledgement loss | Evidence's original coordinate/receipt wins; no replacement completeness or bundle identity. |
| Publication finalization versus later revocation | Finalization may preserve historical publication, but revocation wins for any later privileged release or migration eligibility required to be current. |
| Original historical allow versus later policy comparison | Original evidence stays unchanged; comparison is separately labeled and has no authority to rewrite it. |
| Preflight current success versus later Authority/Registry revocation | Revocation or lifecycle/fence transition committed before the final supported CAS wins. |
| Final RFC 0014 CAS versus current-owner transition | The accepted same-transaction or `FND-003` protocol defines one winner; absent that protocol, migration is unsupported. |
| Retention/compaction versus duplicate lookup | Permanent non-reuse/tombstone history wins; absence or uncertainty never becomes a fresh identity. |

## Crash Recovery and Same-Command Reconciliation

Exactly one Authority-owned reconciler may advance retained owner-local recovery
state by CAS after all dependencies exist. It never acts as replay and never
creates current authority. It may invoke only the retained authenticated
same-command Authority repository port and the RFC 0015 Event/Evidence
publication or query ports named by the table below. Concrete composition
adapters may perform the storage and transport required to realize those ports
under their accepted owner, authentication, idempotency, resource, durability,
and `FND-003` contracts. These narrowly bounded same-command recovery operations
are not permission for direct infrastructure access or unrelated effects.

| Crash or loss point | Sole permitted recovery |
| --- | --- |
| Before resource reservation and stable claim | No owner state exists; an authenticated request may begin admission. |
| After reservation, before claim | Recover or release only the exact reservation after proving no claim; do not allocate source facts. |
| During atomic proof-set/source/index/resource/outbox commit | Query the same transaction/command. Recover the original complete set, prove no commit, or remain uncertain; never create a partial replacement set. |
| After source/outbox commit, before Event append | Redeliver only the retained authenticated outbox command for each fixed source identity/digest. |
| After Event append, before Authority receives acknowledgement | Query/redeliver the same Event command and validate the original receipt. |
| After Event acknowledgement, before Evidence commit | Submit only the retained Evidence command over the same source and Event receipt. |
| After Evidence commit, before Authority receives receipt | Query/redeliver the same Evidence command and validate the original coordinate/receipt. |
| During Authority finalization | Query the same finalization transaction. Recover its original immutable bytes or remain uncertain; no alternate finalization. |
| After finalization, before audited view/response | Reauthenticate, rerun current visibility/release checks, commit the required audit, and return only the retained original view/result. |
| Recovery state corrupt, dependency unavailable, or reconciliation exhausted | Fail closed and require intervention; never infer success, latest, or absence. |

The reconciler cannot select a different source ref/entry, Authority or Registry
record, command, outbox, Event, Evidence, finalization, audit, or resource
identity; change source/decision/Registry bytes; invoke policy as though it were
the original decision; refresh currentness; allocate a target; or move a ref
head. It cannot access Store, network, filesystem, database, queue, or transport
infrastructure directly; only the exact retained repository/publication/query
ports above may cross those boundaries through composition adapters. It cannot
call a provider, node, Gateway, business adapter, driver effect path, or any
unrelated business, control-plane, or external effect.

## Compatibility, Migration, and Rollback

This contract is additive and experimental. It changes none of these accepted or
stable surfaces:

- RFC 0012 `SecretRef` v1 historical bytes, secret request/lease/provider rules,
  and no-secret-persistence requirements;
- RFC 0013 `DriverOperationRef`, declaration, slot, sink entry, trusted-send
  profile, canonical bytes, and destination digest semantics;
- RFC 0014 historical parser, source identity/ordinal/digest, v2 target grammar,
  exact eighteen-member proof bundle, migration command, target allocation,
  state machine, current generations, or head CAS;
- RFC 0015 Event/State/Evidence ownership, durability, receipt, completeness,
  visibility, replay, and recovery semantics;
- RFC 0016 Registry declaration binding, admission, per-slot evidence,
  lifecycle/fence/currentness, finalization, resource, import, or replay
  semantics;
- current `splendor.authority.decision_evidence.local.v1`, current issuance
  behavior, and current Rust/Python/TypeScript/OpenAPI contracts; and
- stable 0.1 Action Gateway, verifier, trace, state, replay, work-order,
  approval, identity, daemon, SDK, CLI, and adapter behavior.

There is no silent dual truth. Existing `local.v1`, issuance results, ref rows,
trace rows, database joins, or Registry compatibility paths are not backfilled
or treated as this source record. Historical data may enter only the explicit
native-origin or attested-import rules above. Unknown future schemas remain
opaque non-live history and fail closed at privileged boundaries.

Before any released or persisted implementation, an experimental implementation
may be removed. Once Authority source/finalization bytes or external consumers
exist, rollback must preserve exact restricted read/deny, original
integrity/provenance, permanent proof binding, and non-reuse/resource debt.
Rollback cannot reinterpret `local.v1`, delete evidence needed by RFC 0014,
clear a conflict/tombstone, make historical evidence current, or restore a
revoked Registry or Authority generation.

## Sequenced Implementation Plan, Tests, and Stops

Every slice is separately reviewed. Passing a slice does not authorize a later
owner dependency, live route, or completion claim.

### Slice 1 - Foundation and owner-contract freeze

Scope:

- accept the required `FND-001` nominal identity, closed schema, canonical
  digest, timestamp, bound, signature/attestation, and error grammar;
- accept `FND-006` cross-version, generated parity, persisted migration,
  downgrade, and rollback rules;
- preserve RFC 0014's exact source bytes, proof-bundle array semantics, closed
  eighteen-name object membership, and RFC 8785 canonical bytes; and
- consume, rather than invent, accepted identity/principal, policy, data-use,
  work-order/capability, audit, applicable `FND-009` classification/redaction/
  read/export, trust/key-status, resource-accounting, Event/Evidence, Registry,
  and `FND-003` owner contracts.

Tests and evidence:

- cross-language canonical fixtures for every newly frozen behavior-free value;
- exact RFC 0014 proof-bundle array order, closed object eighteen-name set,
  RFC 8785 canonical bytes, and source-entry byte preservation;
- dependency and ownership matrices proving no copied external-owner semantics;
- N-1/N/N+1 read/deny and rollback fixtures; and
- threat-model review of self-attestation, substitution, historical-authority,
  final-CAS race, owner/key substitution, oracle, and resource-exhaustion paths.

Stop conditions:

- stop on any unresolved wire name, nominal ID, digest domain/algorithm,
  signature algorithm, timestamp, bound, external-owner fact, or compatibility
  rule;
- stop rather than define a Registry, Event/Evidence, policy, data-use, audit,
  resource, or trust/key-status substitute inside Authority; and
- no public/generated surface before parity and migration fixtures pass.

### Slice 2 - Behavior-free Authority historical values

Scope:

- add only accepted closed values, strict bounded parsers, checked constructors,
  deterministic serialization, exact Authority semantic projections and
  omission values consumed by `FND-009`, and code-only non-reflecting errors to
  `splendor-types`;
- reuse RFC 0014 and RFC 0016 owner values exactly; and
- expose no I/O, Authority service, repository, import execution,
  Event/Evidence call, migration, daemon, SDK, CLI, or generated surface not
  already accepted.

Tests and evidence:

- positive, unknown, duplicate, null, oversize, wrong-ID, wrong-owner,
  wrong-tenant/scope/audience, and protected-payload grammar fixtures;
- nominal non-interchangeability among source entry, Authority evidence,
  Registry evidence, Event, Evidence, finalization, command, audit, and C03
  identities;
- canonical source excludes its own digest and all downstream receipts;
- one-entry/one-evidence identity and complete multi-entry set fixtures; and
- compile/API evidence of no unchecked constructor, generic authorizing map,
  extension authority, `local.v1` conversion, live-authority conversion, or
  duplicate policy-independent classification/redaction/read/export primitive.

Stop conditions:

- no behavior-free implementation while exact grammar owners are unresolved;
- no `local.v1` mutation, alias, wrapper-as-proof, or broad Authority evidence
  replacement; and
- no runtime, repository, or owner behavior in this slice.

### Slice 3 - Deterministic Authority owner state machine

Scope:

- implement native/attested-import eligibility, complete source fact validation,
  proof-set atomicity, permanent forward/reverse binding, semantic coalescing,
  finite Authority resource admission/accounting, source/finalization
  separation, restricted view decisions, and same-command recovery decisions
  only in `splendor-authority`;
- define narrow owner repository and external-fact ports; and
- use deterministic in-memory ports without claiming external trust,
  persistence, durability, currentness, or live migration.

Tests and evidence:

- exact native allow and exact independently attested import allow positives;
- self-attested, reconstructed, `local.v1`, unsigned, generic-decision,
  `work_order:<id>`, wrong-origin, and missing-original-fact denials;
- independently mutate every source, entry, decision, actor/issuer/subject,
  operation/scope/purpose/audience, work-order, capability, policy, data-use,
  obligation, reason, freshness/generation, Registry, provenance, trust,
  resource, audit, and outbox fact and deny;
- exact duplicate returns one original; changed command/source/decision/Registry
  semantics permanently conflict; evidence identity cannot serve two entries;
- multi-entry all-or-none source creation, permutation, duplicate, omission,
  swap, and concurrent-winner tests;
- finite rate/concurrency/cardinality/bytes/backlog/debt across tenant,
  principal, ref, entry, family, and global scopes with isolation, coalescing,
  overflow denial, and restart-state requirements; and
- no Event/Evidence, Registry, target, head, Gateway, provider, node, adapter,
  driver, network, or filesystem call.

Stop conditions:

- in-memory tests prove only deterministic Authority semantics;
- no permissive fake may stand in for live external-owner trust/currentness;
- no persistence/publication/attested-import release or C03 use while owner
  dependencies remain unmet; and
- no generic history-import persistence, non-proof record, or quarantine owner
  in Authority.

### Slice 4 - Repository adapter and acyclic durability

Scope:

- implement the Authority-owned repository port through a composition adapter
  using generic Store primitives, without moving Authority decisions into Store;
- persist the atomic proof-set/source/index/resource/outbox transaction,
  permanent non-reuse history, recovery state, and separate finalization; and
- coordinate authenticated Event/Evidence commits under RFC 0015 and accepted
  `FND-003`, retaining source -> acknowledgement -> finalization direction.

Tests and evidence:

- process kill, power loss, disk full, commit/sync failure, duplicate delivery,
  changed duplicate, acknowledgement loss, backlog, corruption, and restart at
  every claim/source/index/resource/outbox/Event/Evidence/finalization boundary;
- no success before effective durability and finalization; no caller downgrade;
- source canonical bytes never contain source digest, receipt, or finalization;
- exact acknowledgement binds one fixed source and cannot finalize a sibling
  entry/source/family;
- permanent proof binding, non-reuse, tombstone, retained debt, coalescing, and
  isolation survive restart and retention pressure;
- same-command recovery preserves all original IDs, bytes, digests, times,
  reservations, receipts, and finalization;
- recovery invokes only the exact retained authenticated Authority repository
  and RFC 0015 Event/Evidence publication/query ports; composition adapters may
  perform their required storage/transport, while direct infrastructure,
  changed-command, alternate-owner, policy/currentness refresh, and unrelated
  effect calls deny; and
- Store and composition bridges map failures but decide no Authority, Registry,
  Evidence, release, or recovery semantics.

Stop conditions:

- if Authority source state and outbox cannot share one local transaction, stop;
- if complete multi-owner obligations cannot be reserved or independent
  Event/Evidence publication lacks accepted `FND-003`, stop before claim; and
- no distributed exactly-once, cross-store atomicity, production durability, or
  C03 migration claim beyond retained executable evidence.

### Slice 5 - Native/attested-import integration and restricted inspection

Scope:

- compose only accepted production owner ports for native issuance/ref mutation,
  attested historical import, identity/principal, work order/capability, policy,
  data use, audit, trust/key status, Registry, resource, Event, and Evidence;
- consume the applicable accepted and implemented `FND-009` classification,
  deterministic redaction, read-access, and privileged-export primitives while
  keeping only Authority-record semantic projection, omission meaning, and
  release decisions in Authority;
- issue one distinct source/finalization per canonical entry only after complete
  ref-set admission; and
- expose restricted/redacted owner queries only after pre-lookup authorization,
  durable audit, and non-oracle conformance.

Tests and evidence:

- native/attested-import source-owner, attestation, key purpose/audience/status,
  revocation, policy/data-use/work-order/capability, and Registry substitution
  matrices;
- imported provenance preserves its real import decision and cannot claim
  unauthenticated original issuance;
- every restricted view contains all mandatory proof facts or denies; every
  redacted view binds omissions and remains non-proof;
- FND-009 classification/redaction/read/export fixtures preserve Authority
  identity and mandatory causal facts, enforce the same read policy, record each
  privileged export, and prove Authority has no duplicate generic policy engine;
- hidden/absent/wrong-tenant/principal/scope/audience/conflict/stale/revoked/
  corrupt/exhausted/unavailable cases have equivalent outward behavior under the
  later accepted daemon profile;
- audit failure withholds every view; no protected/secret-derived payload appears
  in source, finalization, Event/Evidence, audit, logs, metrics, errors, or crash
  bundles; and
- replay, transient generic import inspection, historical re-evaluation, and
  current-policy comparison remain labeled, immutable, detached, and zero-effect;
  generic import retains no Authority record, and any separately owned persistent
  non-proof/quarantine record cannot enter proof indexes, be selected by RFC
  0014, or be upgraded into proof.

Stop conditions:

- no external API until its authentication, scope, generated parity, and
  non-oracle profile are separately accepted and tested;
- no restricted/redacted view or privileged-export implementation until the
  applicable `FND-009` contract and executable owner boundary are accepted,
  implemented, and integrated;
- no persistent generic history-import inspection/quarantine until a separate
  non-Authority owner contract is accepted; that owner remains outside RFC 0017
  and cannot write Authority proof or non-reuse indexes;
- no C03 proof release without independently verifiable owner attestation and
  current accepted trust/key-status validation; and
- no RFC 0014 target allocation or head CAS in this slice.

### Slice 6 - RFC 0014 proof consumption and final current CAS

Scope:

- preserve the proof-bundle array ordered by `source_entry_ordinal`, each closed
  bundle object's exact eighteen-member name set, and RFC 0014/RFC 8785
  deterministic object serialization without an encounter-order parser rule;
- validate direct bundle equality, then transitive Authority/Registry source,
  trust, publication, Event/Evidence, resource, and currentness facts; and
- integrate only through RFC 0014's retained migration command/state machine and
  accepted same-transaction or `FND-003` final-CAS protocol.

Tests and evidence:

- exact eighteen-member object accepted regardless of JSON object encounter
  order and canonicalized under RFC 8785; missing, null, duplicate, alias,
  extension, reordered proof-bundle array sequence, and nineteenth-member forms
  rejected;
- each direct member mutation and each transitive source/attestation/key/Event/
  Evidence/finalization/resource/currentness mutation denies independently;
- one source entry binds one Authority record, one distinct Registry per-slot
  record, one target entry, and no reused identity/digest;
- admission, activation, per-slot, transition, and current-observation receipts
  cannot substitute for one another;
- every ref-head, Authority, policy, work-order, capability, data-use,
  principal/credential, trust/key, Registry binding/fence/publisher/lifecycle,
  and resource revocation race at preflight, release, and final CAS has the
  accepted winner and no live target head on denial;
- crash and acknowledgement loss reuse exact RFC 0014 and owner identities and
  never allocate a second target or invoke a side effect; and
- stable 0.1, RFC 0013, RFC 0014 grammar, RFC 0015 compatibility, RFC 0016, and
  current Authority fixtures remain unchanged.

Stop conditions:

- no Authority/C03 implementation before every required owner runtime,
  trust/key-status path, finite accounting protocol, and linearization path
  exists;
- no mock, broad evidence row, hidden side table, database join, cached latest,
  preflight-only currentness, direct Store call, or `local.v1` object satisfies
  proof; and
- no full `AUTH-002`, `AUTH-006`, C03, task, component, conformance, gold,
  release, durability, or production claim from this bounded adoption.

## Contract Acceptance Matrix

The later implementation suites must retain at least this evidence. Listing a
test here is not execution evidence.

| Area | Required acceptance evidence |
| --- | --- |
| Exact source | Canonical historical ref/entry positive; mutate ID, revision, source bytes/digest, ordinal, entry bytes/digest, operation, slot, destination schema, exposure, trusted-send profile, and every approved digest independently. |
| Origin | Exact native allow and attested import allow; deny self-attestation, reconstructed issuance, wrong source owner, missing provenance, wrong import authority, and fabricated original facts. |
| Decision | Mutate decision ID/revision/status/time/profile/request digest, actor/issuer/subject, operation/scope/purpose/audience, reasons, obligations, and every current-at-decision fact; only the exact closed allow is eligible. |
| Authority dependencies | Mutate work-order ID/digest/revision/expiry/revocation, capability ID/revision/digest/chain/scope/revocation, policy ID/revision/status, data-use ID/revision/purpose/revocation, principal/credential status, freshness, and generations. |
| Registry join | Mutate per-slot evidence ID/digest, tenant, installation/scope, admission/digest, permanent declaration binding, declaration digest/revision, operation, slot/sink entry, lifecycle state/generation, revision fence, publisher authority, and Registry finalization. |
| Owner trust | Mutate Authority/Registry owner, service instance, signer, key ID/type/purpose/audience/status/revision/validity/revocation, attestation, source integrity, and trust root; recomputed but untrusted wrappers deny. |
| Frozen bundle | Reproduce the proof-bundle array ordered by `source_entry_ordinal`; require each closed object to have the exact eighteen names; accept JSON object encounter-order variation through RFC 8785 canonicalization; reject every missing/null/duplicate/alias/side/extension/nineteenth member; keep direct equality separate from transitive validation. |
| Bijection | Multi-entry permutation, omission, duplication, swap, evidence reuse, one-to-many, many-to-one, target ordinal, target bytes/digest, and cross-revision changes deny with no partial target. |
| Publication | Source/outbox atomicity, exact Event/Evidence source binding, distinct family receipts, effective durability, completeness, finalization, no cycles, no finalization mutation, and no success from queue/bare digest/local memory. |
| Idempotency | Exact duplicate at every state returns one original; changed command/source/decision/Registry semantics conflict; forward/reverse indexes and tombstones survive restart, retention, response loss, and concurrent callers. |
| Resource admission | Exact ceiling/ceiling-plus-one after accepted numeric policy exists for rate, concurrency, cardinality, bytes/capacity, outbox/backlog, downstream reservations, retained debt, every isolation scope, overflow, restart, and compensation. |
| Visibility/privacy | Pre-lookup auth, uniform non-reflecting denials, accepted `FND-009` field classification/deterministic redaction/read-policy/privileged-export integration, Authority-owned semantic projection/omission/release decisions only, durable audit-before-view, mandatory restricted fields, redacted omission integrity, no secret/protected/low-entropy leakage, and no generic observability exposure. |
| Currentness/races | Revoke or change every ref/Authority/policy/work-order/capability/data-use/principal/key/Registry/fence/publisher/lifecycle/resource generation between source, preflight, release, and final CAS; earlier committed invalidation wins. |
| Recovery | Crash before/after reservation, claim, source/index/outbox, Event, Evidence, finalization, audit, and response; only same-command recovery through the retained Authority repository and RFC 0015 publication/query ports occurs; concrete adapters perform only required storage/transport; direct infrastructure, changed bytes/owners, currentness refresh, and unrelated effects deny; uncertainty never allocates replacement identity. |
| Replay/comparison/generic import | Authorized access-filtered read/query during detached-plan construction only; inspect-only reconstruction; exact historical versus current/counterfactual labels; unavailable historical policy is not rewritten; generic import is transient, cannot self-attest, persist under Authority, or mutate proof state; detached execution has zero owner/head/Gateway/provider/node/driver effects. A separately accepted persistent non-proof owner remains outside RFC 0017 and can never enter proof indexes or upgrade to proof. The separately authorized attested Authority import is tested as its distinct privileged command family. |
| Compatibility | Current `local.v1`, issuance, RFC 0012-0016, stable Rust/Python/TypeScript/OpenAPI, dependency policy, formatting, and stable conformance remain unchanged. |

Independent architecture/compatibility and security review are required before
every code slice. Review must specifically cover permission laundering,
self-attestation, source/Registry substitution, evidence-to-authority conversion,
owner/key substitution, revocation/CAS races, cycle formation, fake durability,
resource exhaustion, cross-tenant oracles, replay/import mutation, and protected
payload leakage.

## Gold and Validation Status

This proposed RFC exercises no gold. `G01`, `G03`, `G60`, and `G83`, and every
C03 gold named by RFC 0012, remain `specified_not_implemented` /
`not_exercised`. Current 0.1 conformance, static dependency checks, docs review,
and local `AUTH-002a`/`AUTH-006a` tests are compatibility inputs only and are not
gold or runtime evidence for this contract.

Every later code slice requires the strongest applicable unit, property,
concurrency, persistence, fault-injection, integration, privacy, compatibility,
replay, conformance, and gold gates. Skipped or unavailable validation is not a
pass.

## Non-Goals and Explicit Non-Claims

This RFC does not implement, authorize, or claim:

- runtime code, package/dependency change, Store schema, public schema, nominal
  ID, canonical digest domain, signature algorithm, numeric default, daemon/API
  route, SDK, CLI, OpenAPI, JSON Schema, Python, TypeScript, generated artifact,
  reference doc, guide, example, or changelog;
- mutation or semantic upgrade of `splendor.authority.decision_evidence.local.v1`,
  current issuance, RFC 0012/0014 values or bytes, RFC 0015 records, RFC 0016
  records, or stable 0.1 surfaces;
- an Authority issuer service, general issuance/ref-mutation runtime, policy
  archive, historical re-evaluation engine, Evidence Service, Registry runtime,
  audit service, `FND-009` classification/redaction/read/export implementation,
  trust/key registry, or resource-accounting runtime;
- RFC 0014 migration command implementation, target allocation/append, ref-head
  CAS, target ref construction, secret lease/use, Gateway verifier, provider
  access, node delivery, adapter/driver invocation, or any external side effect;
- an FND-001/FND-006 wire spelling, ID grammar, timestamp grammar, digest
  algorithm/domain, owner signature profile, external-owner contract, error
  code, response body/status/timing profile, or generated parity rule;
- an `FND-003` transaction/recovery protocol, cross-store atomicity,
  distributed exactly-once delivery, automatic retry of uncertain work, or
  currentness from copied snapshots;
- numeric Authority/Event/Evidence/audit/Registry/Store resource limits,
  external-owner accounting/retention semantics, unlimited permanent storage,
  or operational capacity readiness;
- public or generic exposure of source entries, approved destination digests,
  policy/data-use facts, Registry coordinates, trust/key facts, resource
  balances, or protected payloads;
- persistence or owner selection for generic non-proof history import,
  inspection, or quarantine records;
- closure of #239, #243, any RFC 0014/C03 issue, any catalog task or component,
  conformance completion, release readiness, durability, production readiness,
  certification, or implementation completion;
- `G01`, `G03`, `G60`, `G83`, any C03 gold pass, or any other gold pass; or
- self-acceptance, approval, or merge of this RFC.

## Acceptance Effect

This document must remain Proposed until independent architecture/compatibility,
security/privacy, and contract reviews confirm:

- one Authority owner and no shadow Authority, Registry, Event/Evidence, Store,
  daemon, SDK, CLI, bridge, or C03 semantics;
- exact eligible native/attested-import origins, complete per-entry facts, distinct
  identities, all-entry atomic source creation, and permanent proof binding;
- unchanged RFC 0014 source grammar, proof-bundle array ordering by
  `source_entry_ordinal`, each closed object's exact eighteen names, and RFC 8785
  canonical serialization without an object encounter-order rule, with direct
  equality separated from transitive owner/receipt/currentness validation and no
  nineteenth member;
- acyclic source/outbox -> Event/Evidence -> immutable finalization ordering,
  truthful durability, same-command recovery, and no cross-store overclaim;
- historical-proof non-authority, immutable original explanation, labeled
  current-policy comparison, detached inspect-only replay/transient generic
  history import, no Authority-owned generic import persistence, the distinct
  authorized attested-import path, and final-CAS current rechecks under RFC
  0014/accepted `FND-003`;
- restricted visibility, durable audit-before-view, non-reflecting conflicts,
  Authority-only projection/omission/release semantics, mandatory applicable
  `FND-009` owner primitives, independently verifiable owner trust/key status,
  and no secret/protected payload leakage;
- finite multi-scope resource admission, isolation, semantic coalescing,
  retained debt, checked overflow, restart, and retention/non-reuse semantics
  without invented numeric or external-owner rules; and
- every dependency stop, implementation slice, test matrix, compatibility rule,
  gold status, and non-claim is explicit and internally consistent.

If later accepted through the repository's independent RFC process, this
document becomes only the semantic owner and dependency contract for the bounded
slices above. Acceptance alone still changes no runtime, closes no task, and
authorizes no implementation past an unmet stop.
