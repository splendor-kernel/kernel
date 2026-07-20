# RFC 0016 - Driver Registry Admission, Lifecycle, and C03 Evidence

## Status and Binding

**Status:** Proposed

**Compatibility line:** Additive experimental 0.2/v2 owner contract preserving
the stable 0.1 Action Gateway, adapter, trace, state, replay, work-order, and
identity contracts

**Component:** `splendor.driver-registry`

**Owner:** future `crates/splendor-gateway::registry`; behavior-free values may
later live in `crates/splendor-types` only after their grammar dependencies are
accepted

**Sprint:** `V2-DB-1 - Driver Registry And Gateway`

**Catalog and issue scope:** only the C03-required portions of `DRREG-001` /
[#331](https://github.com/splendor-kernel/kernel/issues/331), `DRREG-002` /
[#332](https://github.com/splendor-kernel/kernel/issues/332), and `DRREG-004` /
[#334](https://github.com/splendor-kernel/kernel/issues/334)

**Functional requirements:** primary `FR-0.2-04`; constrains `FR-0.2-02` and
`FR-0.2-08`

**Primitive strengthened:** Driver Registry admission, lifecycle currentness,
and owner evidence

**Normative dependencies:** [RFC 0013](0013-driver-operation-credential-sink-contract.md),
[RFC 0014](0014-revision-bound-secret-credential-authorization.md), and
[RFC 0015](0015-event-state-evidence-ownership-and-durability-contract.md)

**Compatibility context:** [RFC 0012](0012-secret-broker-contract.md) and the
stable 0.1 Action Gateway and adapter contracts

This RFC is a proposed, documentation-only contract. It creates no Registry,
schema, package, Store, daemon endpoint, SDK, CLI command, generated surface,
runtime admission, lifecycle transition, currentness receipt, or C03 migration.
It closes no issue or catalog task and changes no gold or conformance status.

## Decision

The Driver Registry will be the sole semantic owner of the minimum immutable
admission, lifecycle, and exact-current evidence that RFC 0014 proof-bound C03
migration requires.

The bounded coordinate is one exact tenant-scoped installation, one immutable
admission, one canonical RFC 0013 `DriverOperationRef`, one positive RFC 0013
declaration revision, and one exact credential-sink entry in the complete RFC
0013 declaration. The Registry will admit that coordinate only from
authenticated registrar authority and independently verified immutable
Artifact, Lineage, conformance, and runtime-compatibility facts. It will assign
one immutable admission identity and one monotonic lifecycle generation.

The C03 live state vocabulary needed by this RFC is `active`, `stale`, and
`revoked`. A fail-closed `quarantined` state is also reserved only for Registry
integrity or outcome uncertainty. Only the exact current `active` generation may
produce C03 current-lifecycle evidence. No name, alias, endpoint, tag, latest
head, newest number, retained old record, or matching digest may substitute for
the complete coordinate.

RFC 0014 remains the sole owner of the C03 source-entry, target-entry, approved
destination, Authority migration, and final ref-head CAS semantics. RFC 0015
remains the sole owner of generic Event and Evidence durability, completeness,
receipts, and coordinates. This RFC defines only Registry-owned facts and how
those facts must be bound into those owner contracts.

## Exact Bounded Scope

This RFC establishes only the following contract targets:

| Catalog task | Bounded target in this RFC | Not completed by this RFC |
| --- | --- | --- |
| `DRREG-001` / #331 | Reuse the exact accepted RFC 0013 operation credential-sink declaration as the operation declaration admitted for C03. | Universal `DriverManifest`, all driver kinds, all operation semantics, alias migration, full conformance kit, and `G07`. |
| `DRREG-002` / #332 | Authenticated immutable admission for one exact installation, operation, declaration revision, implementation/projector artifact set, and evidence set. | General registration platform, node endpoint inventory, installation health, self-test service, maturity promotion, discovery, or resolution. |
| `DRREG-004` / #334 | C03-required `active`, `stale`, `revoked`, and uncertainty quarantine generation semantics, exact current query, and immutable history. | Deprecation, disabled/retired policy, side-by-side rollout, canary, health comparison, rollback, running-workload containment, or full lifecycle completion. |

This RFC does not define a universal `DriverManifest`. It does not define driver
selection or resolution. It does not make a Registry admission selectable by the
Gateway. It does not define endpoint registration. It does not implement any
part of a rollout controller. The terms below are bounded semantic families, not
claims that the catalog tasks are complete.

## Current Baseline and External Stops

The current repository has the accepted and implemented behavior-free RFC 0013
grammar in `crates/splendor-types::driver`. It has the existing stable
`DriverOperationRef`, `SecretCredentialSlotId`,
`DriverOperationCredentialSinksV1`, `DriverOperationCredentialSinkV1`,
`DriverTrustedSendProfileV1`, strict declaration parsing, positive declaration
revision, and canonical declaration bytes.

The current `VerifiedActionGateway` has only a private map from action name to
`AdapterRegistration`. `register_adapter` replaces a map value, and submission
looks up an action name and optional adapter identifier. That map has no
authenticated admission, immutable declaration history, Artifact/Lineage proof,
lifecycle generation, exact current query, or Registry evidence owner. It is not
the Driver Registry described here.

There is no `splendor-evidence` or `splendor-artifacts` package in the current
workspace. RFC 0015 is an accepted planning contract, not implemented Event or
Evidence owner behavior. Current state/trace stores and Authority code are
compatibility inputs, not substitutes for the missing owners.

Live Registry admission, initial activation, lifecycle mutation, current-proof
issuance, and C03 consumption must stop until all applicable dependencies below
are accepted and implemented. A foundation-readiness marker, test double,
private table, unsigned row, filename, image tag, or current compatibility seam
does not satisfy a stop.

| Dependency | Required before live behavior | Why this RFC cannot substitute |
| --- | --- | --- |
| `FND-001` | Exact nominal IDs, closed schemas, canonical digest profiles, timestamp rules, bounds, and canonical bytes for every new Registry command, record, receipt, and evidence family. | This RFC intentionally does not freeze unresolved wire spellings or invent string aliases. |
| `FND-006` | Compatibility class, schema/version negotiation, persisted migration, generated parity, downgrade, replay, and mixed-version rules for the new families. | Current compatibility fixtures are partial foundation evidence, not the required Registry migration contract. |
| `FND-005` | Independently issued, immutable, signed or owner-authenticated conformance evidence tied to the exact implementation/projector artifacts, environment, suite, and result. | Current adapter tests and manifest validation are not an independent `ConformanceReport`, certification, or `G07` pass. |
| `ART-001` and `ART-004` | Immutable artifact identity/version/digest plus trusted producer/build attestation, signature validation, key rotation, and revocation status for every implementation and projector artifact. | Registry cannot manufacture artifact identity, trust a filename/tag, or accept driver self-attestation. |
| `LIN-001`, `LIN-002`, and `LIN-005` | Immutable producer relations, transactionally published producer receipts, controller-known input/output reconciliation, integrity/signing, anti-tamper status, and current trust facts. | Registry may retain owner refs but cannot infer lineage from names or correct an untrusted producer story. |
| `AUTH-001` and `AUTH-003`, or a separately accepted registrar contract | One explicit typed registrar operation and exact tenant/installation/operation scope, current work-order binding, delegation narrowing, expiry, audience, and revocation behavior. | Caller authentication, ownership, driver identity, or generic operator text is not registrar authority. |
| RFC 0015 runtime slices, including `EVT-003`, `EVID-001`, and the C03 trust profile | Behavior-free Event/Evidence values, owner package behavior, authenticated durable commit receipts, integrity/signature path, completeness, visibility, and Store durability. | Registry cannot mint Event/Evidence coordinates or call a current trace row durable proof. |
| `FND-003` | Accepted recovery and linearization protocol for independent Registry/Event/Evidence stores and for current Artifact/Lineage/conformance/Authority revocation races that cannot share one authoritative transaction. | An outbox is not cross-store atomicity, and copying a current-status snapshot does not linearize a later revocation. |
| `DEP-005` | Driver activation rollout, canary, health stop, promotion, and rollback ownership where any live installation can become active. | The narrow C03 state machine below is not a rollout controller and cannot activate production installations by itself. |

Any implementation slice stops at its narrow port when one of these owners cannot
supply the required fact. No Registry-local artifact, lineage, registrar,
conformance, Event, Evidence, transaction, or rollout substitute is permitted.

## Ownership and Dependency Direction

One mutation has one owner.

| Surface | Owns under this RFC | Must not own under this RFC |
| --- | --- | --- |
| `crates/splendor-types` | Future behavior-free nominal values, closed records, strict parsing, deterministic serialization, and canonical projections only after `FND-001` and `FND-006` freeze the exact grammar. | Registry I/O, admission decisions, lifecycle transitions, currentness, evidence completeness, artifact/lineage/authority decisions, driver selection, or Gateway execution. |
| `crates/splendor-gateway::registry` | Sole admission validation, immutable admission semantics, lifecycle state machine, generation allocation, expected-generation CAS interpretation, exact current query, Registry-owned evidence projection, command idempotency, and Registry recovery decisions. | Concrete provider behavior, C03 authority, Artifact/Lineage truth, Event/Evidence durability, Store policy, driver invocation, rollout, or endpoint health ownership. |
| `crates/splendor-store` | Persistence traits/engines for owner-approved immutable records, unique indexes, permanent non-reuse markers, transactions, CAS, outbox rows, integrity storage, and exact reads. | Registrar policy, admission legality, lifecycle transition legality, current-proof eligibility, evidence completeness, retry policy, or latest selection. |
| future `crates/splendor-evidence` | RFC 0015 Event append, Evidence commit, durability, integrity, completeness, authenticated receipts, restricted views, and replay plans. | Registry admission/lifecycle meaning, Artifact/Lineage truth, registrar authority, C03 migration authority, or driver invocation. |
| Artifact and Lineage owners | Immutable artifact identity/attestation and producer/integrity/signing/current-trust facts supplied through narrow authenticated ports. | Registry admission, Registry lifecycle, C03 migration, or self-certification. |
| Authority | Authenticated registrar operation/scope, work order, audience, delegation, expiry, revocation, and C03 migration decision supplied through narrow authenticated ports. | Registry state, Registry evidence, Event/Evidence durability, or driver self-admission. |
| daemon, SDK, CLI, bindings | Authentication and endpoint-scope enforcement, closed command/query translation, client ergonomics, safe restricted display. | Direct Store mutation, admission/lifecycle decisions, currentness inference, alternate lookup, client-side authority, or hidden Registry ownership. |
| C03 / Authority migration owner | Exact consumption of Registry admission/current evidence during RFC 0014 proof validation and final migration CAS. | Mutating Registry state, minting Registry evidence, inferring a generation, or repairing missing proof. |
| driver, adapter, endpoint, node | Supply untrusted proposals or separately owner-attested implementation facts where a later contract permits them. | Admitting, activating, attesting, certifying, selecting, or authorizing themselves. |

Registry defines narrow outbound ports for authenticated current Authority,
Artifact, Lineage, conformance, and Event/Evidence operations. Composition may
bridge those ports. A bridge may authenticate, translate, and map failures; it
cannot decide admission or mutate another owner's records.

## Exact RFC 0013 Reuse

This RFC imports without copying, renaming, widening, wrapping, or translating:

- the existing `DriverOperationRef` and
  `validate_driver_operation_ref_v1` boundary;
- `DriverOperationCredentialSinksV1` and its exact positive
  `driver_declaration_revision`;
- `DriverOperationCredentialSinkV1` and `SecretCredentialSlotId`;
- `DriverTrustedSendProfileV1`, including the exact trusted-injection and
  not-applicable forms;
- the complete normalized RFC 0013 declaration bytes produced by ordinary
  compact serialization; and
- the RFC 0013 destination projection and
  `DriverCredentialDestinationDigest` semantics, without authorizing projector
  execution.

Registry admission consumes one already validated RFC 0013 declaration and its
exact canonical bytes. It selects a sink only by exact
`SecretCredentialSlotId`, then binds the complete canonical sink-entry bytes. It
does not create a second operation coordinate, slot grammar, profile grammar,
declaration DTO, manifest field, or canonical serializer.

RFC 0013 intentionally defines no declaration digest. This RFC requires a later
FND-001-owned canonical digest profile over the exact RFC 0013 canonical
declaration bytes and a distinct fingerprint profile over the exact canonical
sink-entry bytes. The digest algorithms, domain separators, nominal digest
types, schema constants, and wire spellings remain blocked on `FND-001` and
`FND-006`. They must not be filled by an implementation-local hash or database
column. The bytes being bound are already fixed by RFC 0013; this RFC does not
change them.

## Semantic Contract Families

The names in this section are semantic handles for review and later type design.
They are not accepted Rust symbol names, schema constants, JSON fields, HTTP
paths, error codes, or generated API spellings. `FND-001` and `FND-006` own that
future grammar.

| Semantic family | Minimum meaning |
| --- | --- |
| Registry installation scope | One immutable tenant-bound installation identity and exact deployment/locality/trust scope digest. It is distinct from a global driver definition/version and from every endpoint instance. |
| Authenticated admission command | One permanently identified registrar command binding trusted actor context, exact installation, exact operation declaration, immutable artifacts, owner attestations, conformance, compatibility, and required durability. |
| Immutable admission record | One owner-issued, content-bound acceptance of the exact installation/operation/revision/artifact/evidence coordinate, with immutable owner time/revision and no mutable endpoint or lifecycle field. |
| Lifecycle transition command and record | One authenticated expected-generation CAS request and one immutable owner transition fact binding prior/new state and generation plus cause evidence. |
| Lifecycle head | The sole mutable Registry pointer for one immutable admission coordinate, containing its exact current state, generation, record revision/digest, and integrity binding. |
| Exact currentness query | One authenticated, visibility-checked query over the complete admission coordinate and expected lifecycle generation. It has no name, latest, alias, endpoint, or fallback mode. |
| Exact current lifecycle evidence | One owner-issued, access-filtered, durable observation that the exact immutable admission is still the exact current `active` generation at an owner verification time. It is non-authorizing and cannot replace the final owner recheck. |
| Restricted Registry view | One audited access-filtered projection for authorized diagnostics or historical inspection. Redaction preserves explicit omission/inaccessibility and never converts incomplete proof into current proof. |

## Identity Separation and Exact Coordinates

The following concepts remain distinct even when values happen to be equal:

1. **Global driver definition and version** identifies one immutable logical
   implementation release and its Artifact/Lineage facts. It is not an
   installation, endpoint, operation, declaration revision, or admission.
2. **Installation identity and scope** identifies one tenant-bound installed
   realization and its exact scope. It is not an endpoint instance. Reinstalling
   or changing scope requires the later owner contract's distinct installation
   treatment; this RFC permits no mutable scope.
3. **Endpoint instance** identifies a concrete process, socket, service, node, or
   transport realization. Endpoint health and locators are not part of the C03
   admission coordinate or evidence defined here.
4. **Operation declaration identity** is the exact canonical RFC 0013
   `DriverOperationRef`, positive declaration revision, complete declaration
   bytes/digest, exact slot ID, and complete sink-entry bytes/fingerprint.
5. **Admission identity** is the Registry owner's immutable acceptance of one
   exact installation and operation declaration coordinate under one exact set
   of verified source facts.
6. **Lifecycle generation** is an owner-assigned monotonic counter for one
   admission. It is not a declaration revision, artifact version, owner
   revision, Event sequence, Evidence revision, endpoint generation, or C03 ref
   revision.

The C03 proof coordinate is exactly one tenant scope, installation identity and
scope digest, admission identity and digest, canonical operation bytes, positive
declaration revision, complete declaration digest, exact slot-entry bytes or
fingerprint, lifecycle state `active`, and one lifecycle generation. Name-only,
endpoint-only, alias, tag, mutable head, latest, newest numeric revision, bare
digest, timestamp, or coincident counter equality proves nothing.

## Authenticated Admission

### Trusted outer binding

Authentication and endpoint-scope authorization occur before command claim,
installation/admission lookup, artifact/lineage/conformance lookup, or any
response that could reveal Registry state. The Registry owner derives and binds
all of these from trusted context or owner-authenticated facts:

- actor principal and credential identity, current credential status and
  revocation generation;
- exact tenant;
- Registry service audience;
- exact signed work order identity, immutable digest/revision, expiry, and
  revocation generation;
- exact registrar operation and tenant/installation/operation scope;
- Authority decision identity/revision and current revocation inputs; and
- audit attribution and owner first-observation time.

These values may be mirrored in a future transport body only for byte-for-byte
equality checking. Untrusted body fields, metadata, extensions, driver
declarations, node reports, endpoint claims, or adapter configuration cannot
establish or widen them.

### Normalized admission semantics

One admission command has one permanent nominal command identity that is also
its idempotency identity. There is no second optional idempotency key. Its
normalized semantics bind at least:

- the complete trusted outer binding above;
- the exact global driver definition/version identity;
- the exact Registry installation identity and immutable scope digest;
- the exact canonical RFC 0013 `DriverOperationRef`;
- the positive RFC 0013 declaration revision;
- the complete canonical RFC 0013 declaration bytes and required declaration
  digest;
- every canonical sink-entry byte sequence and fingerprint in that declaration,
  including the exact entry selected for later C03 proof;
- every immutable implementation and destination-projector artifact identity,
  version, content digest, and manifest digest applicable to that declaration;
- exact Artifact attestation identity/digest, signer/builder/producer trust and
  current key/revocation status references;
- exact Lineage producer receipt, required relation set, integrity/signing
  identity/digest, and current anti-tamper status references;
- exact independent conformance evidence identity/digest, suite/profile/version,
  environment, implementation/projector bindings, result, issuer, and current
  trust/revocation status;
- exact supported runtime/ABI/platform compatibility facts and the current
  compatibility-policy revision;
- requested Event/Evidence profiles and durability floor, which may tighten but
  never weaken owner or deployment floors; and
- bounded causal and audit references.

An unknown, missing, inaccessible, stale, revoked, self-issued where independence
is required, wrong-owner, wrong-tenant, wrong-audience, changed, incompatible,
corrupt, unsigned/untrusted, or uncertain fact rejects admission. A driver,
adapter, endpoint, publisher, builder, test harness, or node cannot be both the
subject and the required independent registrar/conformance attestor.

### Immutable admission record

The Registry owner materializes the immutable admission record. The caller does
not supply a committed record, admission digest, owner revision/time, lifecycle
generation, Event receipt, Evidence receipt, or success result.

The record binds all normalized semantics plus:

- one owner-assigned immutable admission identity;
- one owner-assigned admission revision and commit time;
- the canonical admission record digest and predecessor/current integrity
  binding required by the accepted FND/Event/Evidence profiles;
- exact source-owner receipt and attestation identities/digests used in the
  decision;
- the authenticated allow decision and registrar/work-order binding;
- the exact owner transaction/command semantic digest;
- the required Registry decision Event coordinate and append receipt; and
- the required Registry admission Evidence bundle coordinate, commit receipt,
  achieved durability, and trust/key-status binding.

The record is append-only. Endpoint instance, endpoint address, provider locator,
installation health, current lifecycle state, current generation, approved C03
destination set, secret ref, lease, or mutable alias is not an admission-record
field. Those concepts either belong to another owner or to the separate
lifecycle head.

Registry enforces one immutable admission per exact installation/global-version/
operation/declaration-revision coordinate. A distinct command with byte-for-byte
equal normalized semantics may resolve to the existing admission after full
authorization and equality checks; it cannot create a second admission. The same
coordinate with changed declaration, sink entry, artifact, attestation, lineage,
conformance, compatibility, installation scope, or trusted binding is a permanent
conflict. It cannot overwrite or repair the original record.

### Initial active generation

A successful admission creates the immutable admission and its initial
`active` lifecycle head as one Registry-owner mutation. The owner assigns the
first positive generation. Neither caller nor Store chooses it. The admission is
not externally successful or current-queryable until all required Registry
records and RFC 0015 Event/Evidence commits have reached the effective durability
floor.

If that all-or-none owner mutation cannot be combined with the required
Event/Evidence boundary or recovered through accepted `FND-003`, live admission
is unsupported. A pending row, queued event, memory-only result, or best-effort
append is not active admission.

## Lifecycle and Generation CAS

### State semantics

The C03-required state semantics are:

| State | Meaning for this RFC |
| --- | --- |
| `active` | The exact admission passed every required source and compatibility check and has not been superseded by a later Registry lifecycle transition. Only this exact current generation may produce C03 current evidence. |
| `stale` | The admission remains immutable and inspectable, but a source, compatibility, policy, or lifecycle fact no longer permits new C03 use. It is non-live. |
| `revoked` | The admission is permanently forbidden for new live use. History remains immutable. It is terminal. |
| `quarantined` | Registry integrity, source-currentness, Store outcome, Event/Evidence publication, or recovery uncertainty prevents a trustworthy live decision. It is non-live and fail-closed. |

`active` is assigned only by the initial successful admission. The allowed
forward transitions are:

```text
active -> stale | revoked | quarantined
stale -> revoked | quarantined
quarantined -> revoked
revoked -> no state
```

There is no `stale -> active`, `quarantined -> active`, or `revoked -> active`
shortcut in this bounded contract. A later valid implementation must perform a
new authenticated admission with a new immutable admission identity and complete
fresh proof. It cannot reuse the revoked admission, declaration revision, command
identity, evidence identity, or old active record as new authority.

### Transition command and immutable record

Every lifecycle transition is a separately authenticated command with one
permanent nominal command/idempotency identity. Its normalized semantics bind:

- trusted actor, tenant, Registry audience, exact work order, and explicit
  lifecycle/registrar authority outside untrusted body fields;
- the complete immutable admission coordinate and admission digest;
- exact expected current lifecycle state, generation, head revision/digest, and
  integrity binding;
- one exact allowed target state;
- bounded owner-authenticated cause evidence, including current source-owner
  status/revocation facts where applicable;
- required Event/Evidence profile, durability, causal, and audit inputs; and
- no caller-provided owner time, next generation, next head revision, or success
  receipt.

An accepted transition atomically compares the expected lifecycle head, assigns
exactly the next monotonic generation without wraparound, appends one immutable
transition record, and CAS-moves the sole lifecycle head. The transition record
binds prior and new state, prior and new generation, admission identity/digest,
cause evidence, command/semantic digest, actor/authority/work-order references,
owner revision/time, integrity, and required Event/Evidence coordinates and
receipts.

History is never edited. A no-op target is not an accepted transition and
allocates no generation. An exact duplicate returns the original transition and
generation. A stale expected state/generation or changed duplicate commits
nothing. Store enforces the owner-supplied CAS but does not decide transition
legality.

### Race winners

The Registry lifecycle-head transaction is the Registry linearization point.

1. An `active -> stale|revoked|quarantined` transition durably committed before
   a currentness head read wins. The read cannot emit active evidence.
2. A currentness read that observes an active generation must compare that exact
   generation again before releasing its success result after Event/Evidence
   acknowledgement. If a transition won meanwhile, the active result is
   withheld. Any already committed observation remains restricted historical
   evidence only.
3. A transition committed after current evidence release but before RFC 0014's
   final Authority migration CAS still wins. Authority must recheck the exact
   Registry generation through the owner-supported linearization path in that
   final CAS. The retained current evidence cannot override it.
4. A stale preflight, cache, old admission record, prior active evidence,
   numerically equal generation from another admission, or earlier successful
   query never wins over the current lifecycle head.
5. If a current Artifact, Lineage, conformance, signer, registrar, work-order, or
   other independent-owner revocation race cannot participate in one authoritative
   transaction or an accepted `FND-003` protocol, live admission, transition,
   current-proof issuance, and final C03 use are unsupported and fail closed.
   Copying a source status into Registry does not prove that a newer source
   transition did not win.

This RFC does not define containment of already running workloads or driver
rollout. Those semantics remain with their catalog owners and `DEP-005`.

## Exact Current Query and Evidence

### Query rules

Authentication, dedicated endpoint/read scope, exact tenant, Registry audience,
installation visibility, admission visibility, and audit authority are checked
before object, command-idempotency, lifecycle-head, source-owner, Event, or
Evidence lookup.

The C03 currentness query names the complete expected Registry coordinate:

- tenant scope;
- installation identity and immutable scope digest;
- admission identity and admission digest;
- canonical RFC 0013 operation bytes;
- positive declaration revision and complete declaration digest;
- exact slot ID and sink-entry bytes/fingerprint; and
- expected `active` lifecycle generation.

The owner performs exact-key lookup only. It does not expose a query by driver
name, operation name alone, global version alone, endpoint, alias, tag, latest,
current-without-expected-coordinate, newest number, declaration digest alone, or
partial prefix. It does not fall back to another installation, admission,
revision, slot, generation, artifact, or endpoint.

Before issuing active evidence, Registry revalidates the immutable admission and
its integrity, exact current lifecycle head, required current source-owner
trust/revocation facts, Registry evidence-signing/trust state, and required
Event/Evidence availability through the accepted owner boundaries. Any mismatch
or uncertainty produces no active evidence.

### Current lifecycle evidence

One successful query returns one owner-issued, access-filtered immutable current
lifecycle evidence value. It binds at least:

- evidence identity, profile/version, canonical digest, and Registry owner
  integrity or signature-chain identity;
- exact tenant and Registry audience/visibility binding;
- exact installation identity and scope digest;
- exact admission identity, admission digest, and immutable admission-evidence
  identity/digest;
- exact canonical operation bytes, positive declaration revision, complete
  declaration digest, exact slot ID, and sink-entry bytes/fingerprint;
- current lifecycle state `active` and the exact observed generation;
- exact lifecycle-head revision/digest and Registry owner revision observed by
  the query;
- owner-assigned current verification time and current trust/key-status
  references;
- current source-owner status/revocation references required by the admission
  profile;
- exact Registry query/issuance semantic digest and permanent nominal query
  identity;
- required Registry Event coordinate and append receipt; and
- RFC 0015 Evidence bundle coordinate, authenticated commit receipt, achieved
  durability, completeness, and attestation binding.

The effective durability floor is the strictest Registry-profile, deployment,
and caller-requested floor under RFC 0015. `memory_only`, queue acceptance,
unacknowledged outbox state, an unsigned bundle, a bare digest, or a database read
is never current lifecycle evidence for C03.

Current lifecycle evidence is an observation, not a capability, approval,
registrar grant, migration decision, Gateway permit, driver selection, or secret
authority. Its verification time does not give it a grace period. It cannot be
refreshed by replay or reused as proof that the generation stayed current after
issuance.

Current-proof issuance has one permanent nominal query identity. An exact
duplicate resumes or returns only the original immutable result and its original
verification time after current visibility checks. It never creates a later time
or silently refreshes authority. Changed semantics under that identity conflict.
A caller requiring a later observation uses a new nominal query identity and
still receives no authority from it.

### Restricted and redacted views

Detailed admission, transition, currentness, conflict, and source-trust facts are
available only through a separate dedicated read scope and an audited restricted
view. The view binds source record/evidence coordinates, viewer tenant/scope,
redaction policy/revision, included fields, explicit omitted or inaccessible
fields, owner revision, and view digest. Audit commit failure withholds the view.

Redaction cannot omit a mandatory C03 coordinate and still label the proof
complete or current. An access-filtered C03 consumer either receives every
mandatory Registry coordinate and trusted receipt or fails closed.

## Immutable Registry Admission Evidence for RFC 0014

Registry emits one owner-specific immutable admission-evidence record through the
RFC 0015 Event/Evidence owner. The record asserts only Registry-owned facts. Its
Artifact, Lineage, and conformance entries are exact source references and
receipts that Registry verified; Registry does not reissue those owners' claims.

The C03 proof projection binds exactly these semantic facts:

- Registry evidence identity, profile/schema version, canonical evidence digest,
  and Registry owner integrity or signature-chain identity;
- exact tenant scope;
- exact installation identity and immutable scope digest;
- immutable admission identity and admission digest;
- exact canonical RFC 0013 `DriverOperationRef` bytes;
- exact positive RFC 0013 declaration revision;
- complete canonical RFC 0013 declaration digest;
- exact `SecretCredentialSlotId` plus complete canonical sink-entry bytes and
  fingerprint;
- lifecycle state `active` and the exact monotonic lifecycle generation observed
  for the migration proof;
- exact immutable implementation/projector Artifact source refs, versions,
  digests, and Artifact attestation refs/digests;
- exact Lineage producer, integrity, and signing source refs/digests;
- exact independent conformance source identity/digest and compatibility-policy
  reference; and
- exact RFC 0015 Registry decision Event coordinate/receipt and admission
  Evidence bundle coordinate/commit receipt, owner revision, durability,
  completeness, trust/key-status, and commit time.

The evidence contains no C03 `SecretRef`, source-entry identity, source-entry
digest, source approved-destination set, source classification, C03 provider
coordinate, purpose, Authority decision, migration command, target entry, target
ref, lease, permit, delivery handle, or C03 current-head decision. It contains no
endpoint instance or provider locator. Registry never attests those facts.

The admission evidence is immutable historical evidence that the admission was
active at the named generation and was durably recorded. It is not currentness
by itself. A later stale, revoked, or quarantined transition does not rewrite or
delete it; the exact current query and final Authority CAS prevent live reuse.

## RFC 0014 Three-Way Proof Binding

RFC 0014 remains authoritative for source/target C03 grammar and migration. This
RFC supplies the missing Registry owner side of its proof join.

For every migrated C03 source entry, all Registry coordinates must match
byte-for-byte across:

1. the exact RFC 0014 proof bundle and its complete source/target entry binding;
2. the exact Authority historical evidence record that binds that C03 source
   entry and approved-destination set to one Registry evidence identity/digest
   and Registry coordinate;
3. the exact immutable Registry admission record and Registry admission-evidence
   record; and
4. the exact Registry current lifecycle evidence and final owner currentness
   recheck.

The required equality includes tenant, installation identity/scope digest,
admission identity/digest, Registry evidence identity/digest, canonical operation
bytes, positive declaration revision, complete declaration digest, exact slot ID
and sink-entry bytes/fingerprint, lifecycle state `active`, lifecycle generation,
and every required RFC 0015 Event/Evidence coordinate, receipt, integrity,
durability, and trust binding. The Authority record additionally owns the C03
source facts; Registry records must not copy or attest them.

A bare digest, timestamp, signature without its key/status path, database row,
foreign key, join result, query result, current head, endpoint, operation lookup,
manifest, filename, image tag, source order, matching number, or declaration byte
similarity is insufficient. Evidence identity cannot substitute for evidence
digest, and neither can substitute for the complete record and owner receipt.

Current lifecycle evidence is non-authorizing and is a preflight input only.
Immediately before the RFC 0014 Authority migration head CAS, Authority must
recheck the exact admission and generation as current `active` through the
Registry owner and an accepted same-transaction or `FND-003` protocol. If a
stale/revoked/quarantined transition or required external revocation committed
first, it wins and migration commits no target head.

Missing, hidden, inaccessible, stale, revoked, quarantined, incomplete, corrupt,
wrong-owner, wrong-tenant/scope/audience, untrusted, expired/revoked-key,
substituted, unavailable, or uncertain Registry or RFC 0015 evidence denies with
no C03 migration, provider access, node call, Gateway/adapter/driver invocation,
lease, delivery, or other side effect.

## Permanent Idempotency, Crash Recovery, and Non-Reuse

### Permanent command identity

Admission, lifecycle transition, and current-proof issuance each use one
family-specific nominal command/query identity as their sole idempotency
identity. Stable lookup is derived from authenticated tenant, authenticated actor
or service principal where applicable, command family, and that nominal
identity. Work order, admission, expected generation, evidence digest, request
ID, trace ID, and body fields are deliberately not substitutes for or alternate
lookup identities.

After authentication, visibility, and dedicated-scope checks, the first accepted
observation atomically claims that stable identity and retains the complete
normalized semantic projection/digest plus owner first-observation time. The
same identity and same normalized semantics returns or resumes only the original
result. Any changed semantic byte, including changed work order, authority,
scope, declaration, artifact, evidence, expected generation, cause, audience, or
durability request, is a permanent conflict before a second admission,
transition, generation, current-proof record, Event, or Evidence result is
created.

Full records and their non-reuse markers have no TTL in this contract. Retention
may remove payloads only after an accepted protocol durably commits an immutable
non-reuse tombstone binding the stable key, semantic digest, original result or
uncertainty, owner/integrity chain, and retention generation. Missing, corrupt,
inaccessible, compacted, or uncertain history never becomes a fresh miss.

### Unknown commit state

If Registry Store cannot prove commit or absence, the exact command and every
already allocated coordinate enter quarantine. Registry returns no success,
allocates no replacement command/admission/evidence identity, chooses no new
generation or timestamp, and does not retry under changed bytes. Recovery queries
the same command and transaction identity and may only:

- return the original retained result and coordinates;
- prove no mutation and resume the one original command under its retained
  semantics; or
- remain quarantined and require intervention.

Once an admission identity, owner time/revision, lifecycle generation, Event
identity, Evidence identity, or canonical record bytes are allocated and
retained, every recovery path reuses them exactly. An immutable admission or
transition found without its required integrity/Event/Evidence binding is
quarantined, never inferred complete or repaired by a new row.

Inspect-only replay is not the reconciler. A sole Registry-owned reconciler may
advance retained owner-local states by CAS after all dependencies exist, but it
cannot allocate alternate identities, change semantics, reauthorize a registrar,
select latest, call a driver, invoke the Gateway, perform C03 migration, or infer
an external owner's current state.

## Event, Evidence, and Outbox Ordering

RFC 0015 owns Event/Evidence contracts and durability. Registry owns the source
mutation and its truthful completion barrier.

No successful admission, lifecycle transition, or current-proof receipt may be
returned, published, discovered, or consumed by C03 before:

1. the Registry owner has committed the required immutable Registry records,
   lifecycle head/CAS where applicable, command idempotency state, and canonical
   owner result at the effective Registry durability floor;
2. every required Registry decision/transition/current-observation Event has
   reached the effective RFC 0015 Event durability floor; and
3. every required owner-specific Registry Evidence bundle and authenticated
   `EvidenceCommitReceipt` has reached the effective RFC 0015 Evidence durability
   floor with complete exact source bindings.

When Registry and Event/Evidence share one supported Store transaction, owner
code may commit only the records each owner defines while the Store provides the
atomic boundary. Neither owner interprets or rewrites the other's semantics.

When they use independent stores, Registry writes its source mutation and one
unique owner-local outbox command in the same Registry transaction. Event/Evidence
uses authenticated inbox deduplication and at-least-once delivery, returns the
original acknowledgement for an exact duplicate, and permanently conflicts on a
same identity with changed bytes. Registry opens success/current visibility only
after validating the exact owner acknowledgement and performing any required
final lifecycle-head recheck.

That independent-store path remains blocked until accepted `FND-003` recovery
defines the publication barrier and all crash winners. No implementation may
call two commits atomic, claim distributed exactly-once, acknowledge queueing as
durability, drop backlog, or infer success from an absent acknowledgement. If
Registry state and its outbox cannot share one local atomic transaction, the
source mutation is unsupported and fails closed.

An Event or Evidence receipt proves only its owner's durable record. It does not
grant registrar authority, make an admission legal, keep a lifecycle generation
current, authorize C03 migration, or permit a Gateway/provider effect.

## Security, Privacy, and Oracle Resistance

- All privileged schemas are closed and bounded after `FND-001`; unknown,
  duplicate, null, over-bound, wrong-version, or authorizing extension fields
  fail before lookup or mutation.
- Registry records and evidence contain no credential, token, API key, raw
  secret, secret-derived hash, provider request/error, mutable endpoint, provider
  locator, protected payload, approval token, Gateway permit, lease material, or
  driver result payload.
- Registrar authority, caller identity, tenant, audience, work order, expiry,
  and revocation are trusted outer bindings. A driver, adapter, manifest,
  endpoint, node report, Event, Evidence bundle, message, or body field cannot
  grant or broaden them.
- Artifact signatures, Lineage signatures, conformance attestations, Registry
  evidence signatures, and their trust/key-status/revocation chains are distinct.
  One valid signature cannot satisfy another owner or purpose. Unavailable or
  revoked key status fails closed.
- A driver or adapter cannot admit, activate, attest, certify, or provide current
  lifecycle evidence for itself. A node self-test cannot become independent
  conformance evidence.
- Authentication, exact tenant/scope/audience/visibility, and audit authority
  precede existence-sensitive lookup. Hidden, absent, wrong-tenant, wrong-scope,
  wrong-audience, stale, revoked, quarantined, conflict, corrupt, and unavailable
  cases use one non-reflecting outward denial profile. Exact status, existence,
  coordinate, digest, generation, signer, source, and conflict reason are not
  revealed by body shape, status/header choice, lookup count, retry advice,
  metric label, or a finer timing class.
- The exact outward status/body/padding/timing profile belongs to a later daemon
  security contract. This RFC does not freeze a wire response. That contract
  must test byte/status/header and bounded timing equivalence before external
  exposure.
- Declaration, admission, artifact, slot-entry, and evidence digests may be
  low-entropy or enumeration-sensitive. They do not appear in generic logs,
  metrics, errors, traces, discovery, list responses, crash bundles, or
  unauthorized views. Hashing is not redaction.
- Restricted views require dedicated read authority and durable audit. They bind
  omissions and never hide contradictory or unavailable facts as absent.
- Registry current evidence, RFC 0015 completeness, Event presence, a Store row,
  or an Artifact/Lineage reference is not authority.
- No admission, transition, query, evidence build, replay, or recovery path may
  call a provider, driver, adapter, node target, network, filesystem, device, or
  Gateway side effect.
- No shared agent, daemon, SDK, CLI, bridge, Store, or evidence service may
  inherit or launder registrar, tenant, work-order, C03, or Gateway permission.

## Compatibility and Historical Import

This contract is additive and experimental. It changes no stable 0.1 type,
adapter registration, Gateway verifier order, action lookup, trace event, state
node, replay result, daemon route, SDK, CLI, or persisted database.

The following are not retroactive Registry admission proof:

- current `VerifiedActionGateway::register_adapter` entries, action-name lookup,
  trusted action profiles, or successful adapter execution;
- RFC 0013 declarations, canonical fixtures, destination projection fixtures,
  or behavior-free comparison success;
- existing adapter manifests, capability documents, conformance JSON, tests, or
  maturity labels;
- filenames, binary paths, package versions, image names or floating tags,
  process endpoints, node inventories, configuration maps, or provider metadata;
- existing database rows, trace rows, state nodes, hashes, timestamps, foreign
  keys, or joins; or
- any driver-provided registration, self-test, signature, evidence, or
  currentness assertion.

Historical inspection or import may preserve exact validated bytes and their
original provenance under a non-live classification. It cannot mark an imported
declaration or adapter `active`, allocate a live generation, mint Registry
admission/current evidence, or make C03 migration possible unless the complete
new authenticated admission path verifies every required immutable/current owner
fact and commits the new owner records.

There is no dual Registry owner and no dual-write bridge. Existing stable
adapter registration continues only as the existing compatibility path. It does
not populate Registry records, and Registry does not infer records from it. A
later Gateway adoption requires its own accepted invocation/selection contract
and migration evidence.

Unknown future Registry schemas remain opaque historical data and fail closed at
privileged boundaries. Once Registry bytes are released or persisted, rollback
must retain exact read/deny and non-reuse history. Rollback cannot reinterpret an
old adapter registration as admission, restore a revoked generation, select an
older active record, or delete evidence needed by RFC 0014 replay/audit.

## Replay and Simulation

Replay is inspect-only by default. With current read authority it may reconstruct:

- the retained admission command and immutable admission decision;
- lifecycle transitions and generation ordering;
- currentness observations as historical observations at their original owner
  time/revision;
- Event/Evidence publication and crash-recovery state; and
- RFC 0014 proof equality or mismatch explanations over retained records.

Replay, import, simulation, and policy comparison cannot admit a driver,
transition or reactivate a lifecycle, allocate a generation, refresh Artifact,
Lineage, conformance, Authority, key, or Registry current state, emit a live
currentness receipt, move a Registry head, select or invoke a driver, call an
endpoint, issue a Gateway permit, or perform C03 migration. A historical active
record remains historical. A non-live simulation must use detached state and can
produce only explicitly non-authorizing results.

## Sequenced Implementation Plan, Tests, and Stops

Every slice is separately reviewed. Passing one slice does not satisfy a later
owner dependency or authorize a live route.

### Slice 1 - Dependency and grammar freeze

Scope:

- accept and implement the required `FND-001` nominal/schema/digest grammar and
  `FND-006` compatibility/migration rules;
- preserve RFC 0013 types, validation, and canonical bytes exactly;
- accept/implement the required Artifact, Lineage, registrar Authority,
  independent conformance, RFC 0015 `EVT-003`/`EVID-001` Event/Evidence,
  `FND-003`, and `DEP-005` contracts; and
- define no Registry code while a required owner coordinate remains unresolved.

Tests and evidence:

- cross-language canonical fixtures for every newly frozen behavior-free value;
- exact RFC 0013 declaration and sink-entry byte reuse, with no second serializer
  or operation/slot/profile type;
- compatibility classification, N-1/N/N+1 read/deny, rollback, and persisted
  migration fixtures;
- Artifact/Lineage/conformance/registrar trust and revocation fixtures; and
- retained evidence that every named dependency is implemented rather than
  docs-claimed.

Stop conditions:

- stop on any unresolved ID, schema, digest, canonical-byte, timestamp, bound,
  error, generated parity, or migration question owned by `FND-001`/`FND-006`;
- stop if conformance is self-attested or lacks exact artifact/environment/suite
  binding;
- stop if Artifact, Lineage, registrar Authority, RFC 0015 runtime, `FND-003`, or
  `DEP-005` remains incomplete for the intended live path.

### Slice 2 - Behavior-free Registry values

Scope:

- add only the accepted closed values, strict parsing, deterministic
  serialization, canonical projections, and code-only non-reflecting errors to
  `splendor-types`;
- expose no service trait, Store, current lookup, lifecycle decision, daemon,
  SDK, CLI, generated surface, or I/O; and
- retain exact RFC 0013 values rather than wrappers or copies.

Tests and evidence:

- positive, unknown/duplicate/null/oversize/wrong-ID/wrong-owner/wrong-scope
  grammar fixtures;
- nominal compile-time non-interchangeability among command, installation,
  admission, lifecycle, Event, Evidence, endpoint, and C03 identities;
- canonical bytes/digests and complete coordinate mutation tests; and
- API tests proving no unchecked constructor, generic authorizing map,
  `extensions` authority, alternate declaration parser, or authority conversion.

Stop conditions:

- no behavior-free implementation before this RFC and the exact grammar owners
  are accepted;
- no generated/external surface before `FND-006` parity and migration fixtures;
- no runtime or Store behavior in this slice.

### Slice 3 - Registry owner state machine

Scope:

- implement admission, immutable records, lifecycle transition legality,
  permanent command identity, exact current-query interpretation, and recovery
  decisions only in `splendor-gateway::registry`;
- use deterministic in-memory ports to prove owner semantics; and
- keep Artifact, Lineage, conformance, Authority, Store, and Event/Evidence behind
  narrow authenticated ports.

Tests and evidence:

- complete valid admission and exact duplicate return one admission/generation;
- same command or admission coordinate with changed trusted or semantic bytes
  conflicts before a second record;
- wrong registrar/work order/tenant/audience/installation/operation/revision,
  tampered artifact, revoked signer, incomplete lineage, self-attested
  conformance, or incompatible runtime denies;
- initial active generation, every allowed transition, every forbidden reverse
  or no-op transition, exact generation increment, overflow denial, stale CAS,
  and one-winner concurrent CAS;
- transition-before-query and transition-before-final-recheck winners, with old
  active evidence denied for live use;
- unknown commit and missing idempotency history quarantine without replacement
  identity; and
- no adapter, provider, Gateway, network, filesystem, node, or C03 call.

Stop conditions:

- in-memory tests are semantic evidence only and cannot claim durability or live
  admission;
- no production activation, public composition, or current proof while any
  external stop remains unmet;
- no hidden local source-owner state or projection is accepted as current fact.

### Slice 4 - Store and Event/Evidence durability

Scope:

- add Store traits/engines only for owner-approved immutable records, head CAS,
  permanent non-reuse, outbox, and exact recovery reads;
- implement Registry/Event/Evidence owner coordination under RFC 0015
  `EVT-003`/`EVID-001` and accepted `FND-003`; and
- keep semantic decisions in Registry and durability/completeness decisions in
  Event/Evidence.

Tests and evidence:

- process kill, power loss, disk full, commit/sync error, dropped acknowledgement,
  duplicate delivery, changed duplicate, backlog, and corruption at every claim,
  admission, head, transition, outbox, Event, Evidence, and response boundary;
- no success before effective durability and no caller downgrade;
- exact duplicate recovery returns original IDs, bytes, generations, times, and
  receipts;
- Registry state/outbox and Event/Evidence inbox/commit atomicity are each
  truthful, with at-least-once delivery and no distributed exactly-once claim;
- source-owner revocation races use the accepted linearization protocol or deny
  as unsupported; and
- Store never decides admission, transition, currentness, or retry.

Stop conditions:

- if Registry state and outbox cannot share one source transaction, stop;
- if independent Event/Evidence publication lacks accepted `FND-003`, stop;
- if any external current-status race cannot be linearized, keep live behavior
  unsupported and fail closed.

### Slice 5 - Exact current query and Registry evidence

Scope:

- implement pre-lookup authentication/visibility, exact-key query, restricted
  view, owner current-proof materialization, final release recheck, and Registry
  admission/current Evidence profiles; and
- expose no resolution, selection, invocation, endpoint detail, or broad
  discovery API.

Tests and evidence:

- exact active coordinate succeeds only after required Event/Evidence durability;
- mutate independently every tenant/installation/scope/admission/operation/
  revision/declaration/slot/generation/source-receipt/key-status coordinate and
  deny;
- no latest, alias, endpoint, prefix, bare-digest, numeric, or fallback lookup;
- hidden/absent/wrong-tenant/scope/audience/stale/revoked/quarantined/conflict/
  corrupt/unavailable cases have equivalent outward body/status/header/timing
  behavior under the later daemon profile;
- restricted views require separate scope and durable audit and preserve
  omission/inaccessibility;
- Event/Evidence unsigned, memory-only, wrong-owner, changed-source,
  incomplete, corrupt, unavailable, or uncertain results deny; and
- replay cannot issue or refresh a current proof.

Stop conditions:

- no external API until the outward non-oracle profile and generated parity are
  accepted and tested;
- no current success while required owner key/revocation or source-currentness is
  unavailable;
- no C03 adoption in this slice.

### Slice 6 - Authority and C03 adoption

Scope:

- Authority historical evidence and migration owner adopt the exact RFC 0014
  three-way binding in their separately accepted contract;
- C03 consumes complete Registry admission and current evidence through owner
  ports and performs the final Registry current-generation recheck in its
  migration CAS; and
- stable Gateway/provider/node paths remain uncalled by migration.

Tests and evidence:

- exact positive proof binds one source entry to one Authority record, Registry
  admission/evidence, current evidence, and target entry;
- every Registry identity/digest/scope/operation/revision/declaration/slot/
  generation/Event/Evidence substitution denies;
- stale/revoked/quarantined transition at every preflight/final-CAS race wins;
- unavailable/corrupt/inaccessible owner evidence, acknowledgement loss, Store
  uncertainty, or final CAS conflict creates no live target head;
- crash recovery reuses the exact RFC 0014 command and Registry evidence and
  performs no provider, node, Gateway, adapter, or driver effect; and
- stable 0.1 Action Gateway, trace, state, replay, and RFC 0013 fixtures remain
  unchanged.

Stop conditions:

- no Authority/C03 implementation before its own separately accepted evidence
  contract and all owner runtimes exist;
- no mock, broad evidence row, database join, hidden side table, cached latest,
  or direct Store call satisfies owner evidence;
- no task/component/gold completion claim from this bounded adoption.

## Gold and Validation Status

This proposed RFC does not exercise or pass `G07`, `G08`, `G65`, `G75`, or
`G83`. They remain `specified_not_implemented` / `not_exercised` until their
exact executable harnesses run and retain evidence. Static architecture checks,
current 0.1 conformance, RFC 0013 fixtures, deterministic in-memory tests, and a
docs-only RFC are not gold evidence.

Every later code slice requires independent architecture/compatibility and
security review plus the strongest applicable unit, property, concurrency,
persistence, failure-injection, integration, compatibility, replay, privacy, and
gold gates. Unavailable or skipped validation is not a pass.

## Non-Goals and Explicit Non-Claims

This RFC does not implement or claim:

- runtime code, a package/dependency change, Store schema, daemon/API route, SDK,
  CLI command, OpenAPI, JSON Schema, Python, TypeScript, generated artifact,
  reference doc, guide, example, or changelog;
- stable wire spellings, nominal ID formats, schema constants, digest domains,
  timestamp grammar, error codes, response profile, or migration codec for the
  semantic families above;
- a universal `DriverManifest`, broad `DRREG-001`, registration platform,
  endpoint inventory, health service, discovery, deterministic resolution,
  driver selection, invocation, or full `DRREG-002`;
- deprecation, disabled/retired state, canary, rollout, promotion, rollback,
  running-workload containment, or full `DRREG-004`/`DEP-005`;
- Artifact Registry, Lineage Service, conformance certification, registrar
  Authority, Event/State/Evidence runtime, `FND-003`, or compatibility/migration
  owner implementation;
- destination projector execution, Gateway consumption, provider access, node
  delivery, adapter migration, secret lease/use, C03 migration, or any external
  side effect;
- copied or renamed RFC 0013 grammar, a second canonical serializer, C03 fields
  in Registry evidence, a hidden side table, private latest lookup, adapter
  self-registration as proof, or direct Store/daemon ownership;
- cross-store atomicity, distributed exactly-once delivery, automatic retry of
  uncertain work, or reconstruction of missing currentness;
- public exposure of credentials, endpoints, provider locators, approved
  destination digests, C03 classification/purpose/lease state, Authority
  decisions, or target refs through Registry evidence;
- closure of #331, #332, #334, any catalog task/component, or any issue;
- `G07`, `G08`, `G65`, `G75`, `G83`, conformance completion, release readiness,
  production readiness, or certification; or
- self-acceptance of this RFC.

## Acceptance Effect

If accepted through independent architecture/compatibility, security, and
contract review, this document becomes only the semantic owner and dependency
contract for the bounded slices above. Acceptance alone changes no behavior and
does not authorize implementation past an unmet stop.

Review must confirm exact RFC 0013 reuse, one Registry owner, complete external
blocker visibility, immutable admission, monotonic expected-generation CAS,
race winners, permanent idempotency/non-reuse, truthful RFC 0015 durability,
strict RFC 0014 proof equality, non-oracle visibility, inspect-only replay,
compatibility with the stable adapter path, and all non-claims. Any accepted
implementation still requires its own code, tests, retained validation, and
dependency-safe review.
