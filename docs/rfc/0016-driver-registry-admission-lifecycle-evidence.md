# RFC 0016 - Driver Registry Admission, Lifecycle, and C03 Evidence

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-20

**Accepted proposal SHA-256:**
`f7490e110cc83d27f067e3bc2ee45dad538c8f763b58725116b70366fda210df`

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

The bounded admission coordinate is one exact tenant-scoped installation, one
canonical RFC 0013 `DriverOperationRef`, one positive RFC 0013 declaration
revision, and the complete declaration with every credential-sink entry. The
Registry admits that declaration-wide coordinate only from separately
owner-authenticated declaration-publisher/operation-namespace authority and
tenant/installation registrar authority, plus independently verified immutable
Artifact, Lineage, conformance, and runtime-compatibility facts. Admission
creates one immutable, non-live `admitted` record and generation; it selects no
slot and grants no activation authority.

Independently of command idempotency and every tenant/installation admission,
Registry retains one permanent owner-global RFC 0013 declaration binding keyed
exactly by canonical `(DriverOperationRef, positive
driver_declaration_revision)`. It retains the complete canonical declaration
bytes, immutable projection-contract fingerprint, exact publisher principal, and
publication-authority evidence. A fresh command, admission, tenant, installation,
or proof set cannot change or bypass that binding.

Live `active` state requires a separate target-specific activation command,
narrower activation authority, and exact deployment, gate, and rollout evidence
from `DEP-005` or a later accepted activation-owner contract. An active
declaration-wide admission can project one distinct immutable C03 Registry
evidence record for each exact RFC 0013 sink entry. The remaining C03 lifecycle
states are `stale`, `revoked`, and irreversible `quarantined`. Only an exact
current `active` generation whose declaration-revision fence is not revoked and
its exact per-slot evidence may support C03. A stale admission is never
reactivated; a fresh admission for the unchanged revision is possible only from
the exact permanent binding and complete fresh proofs. Revocation permanently
fences the revision across all admissions and identities; return to live use
requires a fresh positive RFC 0013 declaration revision unless a later
separately accepted RFC amends RFC 0013.

Command, publication, or acknowledgement uncertainty is not lifecycle
`quarantined`; it is a private recoverable owner state that cannot open external
visibility. No name, alias, endpoint, tag, latest head, newest number, retained
old record, or matching digest may substitute for the complete coordinate.
Every privileged Registry family is also subject to owner-enforced finite
request, concurrency, retained-cardinality, and byte/capacity budgets before any
durable claim or source allocation. Fresh nominal identities cannot bypass those
budgets or force duplicate permanent history.

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
| `DRREG-004` / #334 | C03-required `admitted`, `active`, `stale`, `revoked`, and irreversible fail-closed quarantine generation semantics, exact current query, and immutable history. | Deprecation, disabled/retired policy, side-by-side rollout, canary, health comparison, rollback, running-workload containment, or full lifecycle completion. |

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

Public grammar stops until `FND-001` and `FND-006` freeze the required values.
Deterministic, non-live owner state-machine tests may proceed after those
behavior-free contracts and narrow test ports exist; they do not require fake
live implementations of every collaborating owner. Composed admission
publication, activation, lifecycle mutation, current-proof issuance, and C03
consumption must stop until each dependency applicable to that live slice is
accepted and implemented. A foundation-readiness marker, test double, private
table, unsigned row, filename, image tag, or compatibility seam does not satisfy
a live stop.

| Dependency | Required before live behavior | Why this RFC cannot substitute |
| --- | --- | --- |
| `FND-001` | Exact nominal IDs, closed schemas, canonical digest profiles, timestamp rules, bounds, and canonical bytes for every new Registry command, record, receipt, and evidence family. | This RFC intentionally does not freeze unresolved wire spellings or invent string aliases. |
| `FND-006` | Compatibility class, schema/version negotiation, persisted migration, generated parity, downgrade, replay, and mixed-version rules for the new families. | Current compatibility fixtures are partial foundation evidence, not the required Registry migration contract. |
| `FND-005` | Independently issued, immutable, signed or owner-authenticated conformance evidence tied to the exact implementation/projector artifacts, environment, suite, and result. | Current adapter tests and manifest validation are not an independent `ConformanceReport`, certification, or `G07` pass. |
| `ART-001` and `ART-004` | Immutable artifact identity/version/digest plus trusted producer/build attestation, signature validation, key rotation, and revocation status for every implementation and projector artifact. | Registry cannot manufacture artifact identity, trust a filename/tag, or accept driver self-attestation. |
| `LIN-001`, `LIN-002`, and `LIN-005` | Immutable producer relations, transactionally published producer receipts, controller-known input/output reconciliation, integrity/signing, anti-tamper status, and current trust facts. | Registry may retain owner refs but cannot infer lineage from names or correct an untrusted producer story. |
| `AUTH-001` and `AUTH-003`, or separately accepted declaration-publisher/registrar/activation/revision-revocation contracts | One typed declaration-publication/operation-namespace operation over the exact canonical operation/revision/definition/declaration/projection coordinate, one explicit typed registrar operation, a distinct narrower target-specific activation operation, and dedicated owner-global declaration-revision revocation authority; exact scopes, owner-defined work-order/causal binding, delegation narrowing, expiry, audience, key status, and revocation behavior. | Caller authentication, Artifact/Lineage producer provenance, ownership, driver identity, registrar authority, installation-local lifecycle authority, activation authority, revision-revocation authority, conformance, or generic operator text is not declaration-publication authority. This RFC does not freeze pending Authority wire grammar. |
| Separately accepted Registry resource-policy/accounting contract and executable conformance | Owner-configured finite rate, burst/concurrency, retained-record/cardinality, byte/capacity, reservation, debt, isolation, backpressure, recovery, and retention accounting; Authority/work-order constraints where applicable; and a truthful multi-owner reservation/compensation protocol. | This RFC defines required enforcement semantics but no wire grammar, numeric defaults, Store policy, Authority decision shape, or Event/Evidence quota/retention behavior. |
| RFC 0015 runtime slices, including `EVT-003`, `EVID-001`, and the C03 trust profile | Behavior-free Event/Evidence values, owner package behavior, authenticated durable commit receipts, integrity/signature path, completeness, visibility, and Store durability. | Registry cannot mint Event/Evidence coordinates or call a current trace row durable proof. |
| `FND-003` | Accepted recovery and linearization protocol for independent Registry/Event/Evidence stores and for current Artifact/Lineage/conformance/Authority revocation races that cannot share one authoritative transaction. | An outbox is not cross-store atomicity, and copying a current-status snapshot does not linearize a later revocation. |
| `DEP-005` | Driver activation rollout, canary, health stop, promotion, and rollback ownership where any live installation can become active. | The narrow C03 state machine below is not a rollout controller and cannot activate production installations by itself. |

Any live implementation slice stops at its narrow port when one of these owners
cannot supply the required fact. A deterministic in-memory port may test a
closed Registry decision before live composition, but its result is explicitly
non-live and cannot satisfy owner availability, durability, currentness, or C03
proof. No Registry-local declaration-publication authority, artifact, lineage,
registrar, quota constraint, conformance, Event, Evidence, transaction, gate,
deployment, or rollout substitute is permitted.

## Ownership and Dependency Direction

One mutation has one owner.

| Surface | Owns under this RFC | Must not own under this RFC |
| --- | --- | --- |
| `crates/splendor-types` | Future behavior-free nominal values, closed records, strict parsing, deterministic serialization, and canonical projections only after `FND-001` and `FND-006` freeze the exact grammar. | Registry I/O, admission decisions, lifecycle transitions, currentness, evidence completeness, artifact/lineage/authority decisions, driver selection, or Gateway execution. |
| `crates/splendor-gateway::registry` | Sole permanent RFC 0013 declaration binding and revision-revocation fence, publisher/registrar validation, admission validation, immutable admission semantics, activation/lifecycle state machine, Registry resource admission/reservation/accounting, semantic coalescing, generation allocation, expected-generation CAS interpretation, repository/application ports, exact current query, per-slot Registry evidence projection, publication finalization, command idempotency, and Registry recovery decisions. | Declaration-publication Authority, Authority quota/work-order constraint semantics, concrete provider behavior, C03 authority, Artifact/Lineage truth, Event/Evidence admission/durability/retention, Store policy, driver invocation, gate/rollout decisions, or endpoint health ownership. |
| `crates/splendor-store` | Generic persistence primitives/engines that a composition-owned Registry repository adapter may use for immutable records, unique indexes, transactions, CAS, counters/reservations, outbox rows, integrity storage, and exact reads. | A Registry repository trait, publisher/registrar policy, quota/resource policy, admission legality, activation/lifecycle legality, current-proof eligibility, publication completeness, retry policy, or latest selection. |
| future `crates/splendor-evidence` | RFC 0015 Event append, Evidence commit, owner-side admission/deduplication, durability, integrity, completeness, authenticated receipts, restricted views, retention, and replay plans. | Registry admission/lifecycle/resource-accounting meaning, Artifact/Lineage truth, publisher/registrar authority, C03 migration authority, or driver invocation. |
| Artifact and Lineage owners | Immutable artifact identity/attestation and producer/integrity/signing/current-trust facts supplied through narrow authenticated ports. | Registry admission, Registry lifecycle, C03 migration, or self-certification. |
| Authority | Owner-authenticated declaration-publisher principal and declaration-publication/operation-namespace operation/scope, authenticated registrar operation/scope, separately narrowed target-specific activation operation/scope, dedicated owner-global declaration-revision revocation operation/scope, applicable quota/work-order constraints, audience, delegation, expiry, key/revocation state, and C03 migration decision supplied through narrow authenticated ports. | Registry state, Registry counters/reservations, Registry evidence, Event/Evidence admission/durability/retention, gate/rollout decisions, or driver self-admission. |
| daemon, SDK, CLI, bindings | Authentication and endpoint-scope enforcement, closed command/query translation, client ergonomics, safe restricted display. | Direct Store mutation, admission/lifecycle decisions, currentness inference, alternate lookup, client-side authority, or hidden Registry ownership. |
| C03 / Authority migration owner | Exact consumption of per-slot Registry/current evidence during RFC 0014 proof validation and final migration CAS. | Mutating Registry state, minting Registry evidence, inferring a generation, or repairing missing proof. |
| driver, adapter, endpoint, node | Supply untrusted proposals or separately owner-attested implementation facts where a later contract permits them. | Admitting, activating, attesting, certifying, selecting, or authorizing themselves. |

Registry defines narrow outbound ports for authenticated current publisher,
registrar, activation, revision-revocation, quota/work-order Authority facts;
Artifact, Lineage, and conformance facts; and Event/Evidence operations.
Composition may bridge those ports. A bridge may authenticate, translate, and
map failures; it cannot decide Registry admission/resource policy or mutate
another owner's records.

Registry also defines its repository port in `splendor-gateway::registry`.
Because the target dependency policy forbids a direct dependency from
`splendor-gateway` to `splendor-store`, a process-composition adapter that is
allowed to depend on both implements that port with generic `splendor-store`
primitives. Registry does not import Store, Store does not import Gateway, and
the adapter owns no Registry semantics. Contract tests cover the Registry port,
generic persistence behavior, CAS/outbox failure mapping, and the absence of a
second mutation owner.

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
exact canonical bytes. Admission is declaration-wide: it binds every entry,
including each exact `SecretCredentialSlotId` and complete canonical sink-entry
bytes, and selects none. A later C03 projection selects one entry only by its
exact slot ID and binds that entry under a distinct per-slot Registry evidence
identity. Registry does not create a second operation coordinate, slot grammar,
profile grammar, declaration DTO, manifest field, or canonical serializer.

Before any installation admission, Registry checks the permanent owner-global
binding whose exact key is the canonical RFC 0013 `(DriverOperationRef, positive
driver_declaration_revision)`. The value retains the complete canonical RFC 0013
declaration bytes, every canonical sink entry, and the immutable complete
projection-contract fingerprint. The key has no tenant, installation, principal,
command, admission, artifact-proof, or evidence-proof component. Exact duplicate
binding is reusable only as immutable non-authorizing input to a separately
authenticated admission; it is not admission, activation, currentness, or C03
authority.

RFC 0013 intentionally defines no declaration digest. This RFC requires a later
FND-001-owned canonical digest profile over the exact RFC 0013 canonical
declaration bytes and a distinct immutable projection-contract fingerprint
profile over the declaration-wide ordered sink contracts. That fingerprint must
bind every exact canonical sink-entry byte and each sink's separately accepted
immutable projection semantics; changing any sink entry or projection contract
changes the binding and conflicts under the same key. The digest algorithms,
domain separators, nominal digest types, schema constants, and wire spellings
remain blocked on `FND-001` and `FND-006`. They must not be filled by an
implementation-local hash or database column. The declaration bytes being bound
are already fixed by RFC 0013; this RFC does not change them or locally define an
external projection owner's semantics.

## Semantic Contract Families

The names in this section are semantic handles for review and later type design.
They are not accepted Rust symbol names, schema constants, JSON fields, HTTP
paths, error codes, or generated API spellings. `FND-001` and `FND-006` own that
future grammar.

| Semantic family | Minimum meaning |
| --- | --- |
| Registry installation scope | One immutable tenant-bound installation identity and exact deployment/locality/trust scope digest. It is distinct from a global driver definition/version and from every endpoint instance. |
| Declaration-publication authority input | One current owner-authenticated publisher principal and typed operation-namespace/publication Authority fact for the exact canonical operation/revision/definition/declaration/projection coordinate and Registry audience. It is external Authority evidence, not Registry-created authority. |
| Permanent RFC 0013 declaration binding | One owner-global immutable index entry keyed exactly by canonical `(DriverOperationRef, positive driver_declaration_revision)`, retaining the complete canonical RFC 0013 declaration bytes, every sink entry, the immutable complete projection-contract fingerprint, exact publisher identity, and initial publication-authority evidence/status observations. It is not command idempotency, publication authority, or installation admission. |
| Declaration-revision revocation fence | One permanent owner-global terminal fence for the exact RFC 0013 declaration-binding key. Once revoked, no command, installation, admission, proof set, replay, or import can return that revision to live use. |
| Registry resource reservation and debt | One owner-controlled pre-claim decision and retained accounting projection covering the complete worst-case Registry plus downstream publication obligation under finite multi-scope budgets. It grants no Authority and does not define Event/Evidence owner accounting. |
| Authenticated admission command | One permanently identified registrar command binding trusted actor context, exact installation, the complete operation declaration and every sink, immutable artifacts, owner attestations, conformance, compatibility, and required durability. It grants no activation authority. |
| Immutable admission source record | One owner-issued, content-bound, non-live acceptance of the exact installation/declaration/artifact/evidence coordinate, with immutable owner time/revision and an initial `admitted` generation. It contains no downstream Event/Evidence receipt. |
| Activation command and source record | One separately authenticated target-state command with narrowed activation authority and exact deployment/gate/rollout evidence, plus one immutable expected-generation CAS fact moving `admitted` to `active`. |
| Lifecycle transition command and source record | One authenticated expected-generation CAS request and one immutable owner transition fact binding prior/new state and generation plus cause evidence. It never performs activation. |
| Lifecycle head | The sole mutable Registry pointer for one immutable admission coordinate, containing its exact current state, generation, record revision/digest, and integrity binding. |
| Per-slot C03 Registry evidence | One immutable Registry-owned source record per exact admission, active generation, and RFC 0013 sink entry. RFC 0014's frozen `registry_admission_evidence_id` and digest name this per-slot record without changing its 18-member bundle. |
| Exact currentness query | One authenticated, visibility-checked query over the complete admission coordinate and expected lifecycle generation. It has no name, latest, alias, endpoint, or fallback mode. |
| Exact current-observation source record | One owner-issued, access-filtered immutable observation that the exact admission and per-slot evidence are still the exact current `active` generation at an owner verification time. It contains no downstream publication receipt and cannot replace the final owner recheck. |
| Publication finalization record | One separate immutable Registry record binding an already-fixed source identity/digest to exact downstream Event/Evidence acknowledgements and opening the family-specific result for external visibility. It never mutates the source. |
| Command/publication recovery state | Private owner state for claimed, source-committed, awaiting-publication, outcome-uncertain, or finalized work. It is not a Registry lifecycle state and grants no live visibility. |
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
4. **Declaration-publisher principal and publication-authority evidence** are
   owner-authenticated external Authority facts for the exact global operation
   namespace and publication coordinate. They are distinct from the admission
   actor/registrar, Artifact/Lineage producers, activation actor, revision
   revoker, and C03 authority. Even if one principal independently holds more
   than one role, each typed decision and scope remains separately required.
5. **RFC 0013 declaration-binding key** is exactly the canonical
   `(DriverOperationRef, positive driver_declaration_revision)` pair. Its
   owner-global binding permanently retains the complete canonical declaration
   bytes, immutable projection-contract fingerprint, publisher identity, and
   publication-authority evidence and has a distinct terminal revocation fence.
6. **Operation declaration identity** is that exact key plus its permanently
   bound complete declaration bytes/digest, every canonical sink entry, and
   immutable projection-contract fingerprint. It is declaration-wide.
7. **Admission identity** is the Registry owner's immutable acceptance of one
   exact installation and operation declaration coordinate under one exact set
   of verified source facts. It is neither the permanent declaration binding nor
   its revision fence.
8. **Per-slot C03 evidence identity** identifies one exact slot-entry projection
   under one exact admission and active lifecycle generation. It is not the
   declaration-wide admission identity and cannot be reused for another slot.
9. **Lifecycle generation** is an owner-assigned monotonic counter for one
   admission. It is not a declaration revision, artifact version, owner
   revision, Event sequence, Evidence revision, endpoint generation, or C03 ref
   revision.

The C03 proof coordinate is exactly one tenant scope, installation identity and
scope digest, admission identity and digest, canonical operation bytes, positive
declaration revision, complete declaration digest, exact slot-entry bytes or
fingerprint, distinct per-slot Registry evidence identity/digest, lifecycle
state `active`, and one lifecycle generation. Name-only, endpoint-only, alias,
tag, mutable head, latest, newest numeric revision, bare digest, timestamp, or
coincident counter equality proves nothing.

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
- exact owner-authenticated declaration-publisher principal/credential and
  current credential, signing-key, trust, expiry, and revocation status;
- typed declaration-publication/operation-namespace Authority operation and
  decision/evidence identity, digest, and revision for the exact canonical
  `DriverOperationRef`,
  positive declaration revision, global driver definition/version, complete
  declaration digest/bytes, immutable projection-contract fingerprint, Registry
  audience, and owner-defined publication work-order/causal context;
- exact registrar operation and tenant/installation/operation scope;
- registrar Authority decision identity/revision and current revocation inputs;
- exact effective Registry resource-policy identity/revision plus any narrower
  owner-authenticated Authority/work-order resource constraints; and
- audit attribution and owner first-observation time.

These values may be mirrored in a future transport body only for byte-for-byte
equality checking. Untrusted body fields, metadata, extensions, driver
declarations, node reports, endpoint claims, or adapter configuration cannot
establish or widen them.

Declaration-publication authority is independently required even when the same
principal also has registrar or another role. Tenant registrar, installation
lifecycle, activation, revision revocation, driver self-claim, Artifact/Lineage
producer provenance, conformance, generic ownership/operator text, or an
untrusted body field cannot satisfy, derive, or delegate it. Resource policy and
accounting state are Registry-owned; Authority/work-order facts may narrow but
cannot reset or widen them, and caller fields cannot choose either policy.

### Normalized admission semantics

One admission command has one permanent nominal command identity that is also
its idempotency identity. There is no second optional idempotency key. Its
normalized semantics bind at least:

- the complete trusted outer binding above;
- exact publisher-to-operation/declaration/projection ownership binding and
  current publication-authority evidence identity/digest/revision/status;
- the exact global driver definition/version identity;
- the exact Registry installation identity and immutable scope digest;
- the exact canonical RFC 0013 `DriverOperationRef`;
- the positive RFC 0013 declaration revision;
- the complete canonical RFC 0013 declaration bytes and required declaration
  digest;
- every canonical sink-entry byte sequence and fingerprint in that declaration,
  with no selected admission slot;
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
- exact effective Registry resource-policy revision, semantic-coalescing result,
  worst-case retained-record/byte/publication obligation, and owner reservation
  references required before durable allocation;
- requested Event/Evidence profiles and durability floor, which may tighten but
  never weaken owner or deployment floors; and
- bounded causal and audit references.

An unauthorized, wrong-operation/revision/definition/declaration/fingerprint/
audience, expired, revoked, substituted, inaccessible, stale, self-issued where
independence is required, wrong-owner, wrong-tenant, changed, incompatible,
corrupt, unsigned/untrusted, or uncertain publisher, Authority, source, resource,
or accounting fact rejects admission. A driver, adapter, endpoint, builder, test
harness, or node cannot self-assert a required independent registrar/conformance
fact. A declaration publisher does not become a registrar or conformance attestor
by holding publication authority. Producer provenance never substitutes for
publication authority.

After authentication, exact current publisher/publication-authority validation,
required declaration/projection-owner validation, semantic coalescing, and
finite resource reservation, but before any durable command claim or installation
admission source, Registry performs exact-key insert-or-compare against the
permanent RFC 0013 declaration-binding index and checks its owner-global
revocation fence. The first valid binding is retained permanently. The same key
with a changed publisher, changed publication operation/scope semantics,
declaration bytes, any changed sink entry, or any changed projection-contract
fingerprint is a permanent conflict. Later current Authority decisions/status
observations may have new owner identities or revisions only when the Authority
owner authenticates them as successors for the exact retained publisher and
unchanged publication coordinate; they do not replace the retained initial
evidence. A revoked fence is a permanent live-admission denial. These checks
occur for every command and fresh proof set; changing nominal command or
admission identity, tenant, installation, actor, artifact set, or evidence set
cannot create a miss. Unauthorized, mismatched, revoked, expired, uncertain, or
concurrent losing publication claims and resource denials create no binding,
fence, command claim, admission source/head, outbox, Event, Evidence, or
finalization record. The outward denial remains non-reflecting under this RFC's
oracle rules.

### Immutable admission source record

The Registry owner materializes the immutable admission source record. The
caller does not supply a committed record, admission digest, owner
revision/time, lifecycle generation, Event receipt, Evidence receipt,
publication finalization, or success result.

The record binds all normalized semantics plus:

- one owner-assigned immutable admission identity;
- one owner-assigned admission revision and commit time;
- canonical admission source bytes and predecessor/current integrity binding
  required by the accepted FND profiles, with the source digest computed over
  those fixed bytes and retained alongside rather than inside them;
- exact source-owner receipt and attestation identities/digests used in the
  decision;
- exact declaration-publisher principal, publication-authority evidence
  identity/digest/revision, current-at-admission credential/key/trust/expiry/
  revocation observations, and owner-defined publication work-order/causal
  binding;
- the authenticated allow decision and distinct registrar/work-order binding;
- exact Registry resource-policy revision, multi-scope reservation/accounting
  identities, worst-case record/byte/publication obligation, and retained debt;
- the exact owner transaction/command semantic digest;
- the initial non-live lifecycle state `admitted` and owner-assigned first
  positive generation; and
- one owner-local outbox intent identity and required publication profiles,
  fixed atomically with the source record but no downstream acknowledgement.

The source record and its canonical digest contain no Registry publication
finalization, Event coordinate/receipt, Evidence bundle coordinate/receipt, or
digest that recursively depends on them. Its canonical bytes are fixed first;
the atomically committed outbox intent references that already-fixed source
identity/digest.

The record is append-only. Endpoint instance, endpoint address, provider locator,
installation health, approved C03 destination set, secret ref, lease, or mutable
alias is not an admission-record field. Current lifecycle state/generation live
only in the separate lifecycle head; the source record retains only its initial
`admitted` fact. The remaining concepts belong to another owner.

Command idempotency uniqueness is the stable command key; declaration
immutability is independently enforced by the permanent RFC 0013 binding key.
The same command with byte-for-byte equal normalized semantics resumes or
returns its one original admission after publication and release checks; changed
semantics under that command permanently conflict. A separately authorized new
command may create a new immutable installation admission for the same revision
only when the permanent declaration binding matches exactly, its global revision
fence is not revoked, current publisher/publication authority and key/revocation
status are revalidated, complete fresh Artifact, Lineage, conformance,
compatibility, registrar Authority, and source proofs pass, semantic coalescing
confirms a distinct admission is actually required, and every finite resource
budget/reservation passes. Its own publication follows the acyclic path below;
any later move to `active` separately requires complete fresh activation proofs.
The reused binding and publisher evidence are non-authorizing, and the new
admission neither overwrites nor reactivates an older admission.

### Non-live admitted generation

A successful admission source transaction creates the immutable declaration-wide
admission and its initial non-live `admitted` lifecycle head. The owner assigns
the first positive generation; neither caller nor a persistence adapter chooses
it. No per-slot C03 evidence is active or externally consumable from admission
alone.

Admission success becomes externally visible only after its distinct publication
finalization record proves the required Registry source durability and RFC 0015
Event/Evidence acknowledgements. Even then the result means only `admitted`, not
selectable, deployed, active, current, or C03-eligible. A pending source row,
queued event, memory-only result, unfinalized outbox, or admission-only authority
cannot create `active` state.

## Lifecycle and Generation CAS

### State semantics

The C03-required state semantics are:

| State | Meaning for this RFC |
| --- | --- |
| `admitted` | The declaration-wide admission is immutable, published, and non-live. It grants no selection, deployment, activation, or C03 authority. |
| `active` | The exact admission passed every required source and compatibility check, has not been superseded by a later Registry lifecycle transition, its owner-global declaration-revision fence is not revoked, and required publisher/publication authority remains current. Only this exact current generation may produce C03 current evidence. |
| `stale` | The admission remains immutable and inspectable, but a source, compatibility, policy, or lifecycle fact no longer permits new C03 use. It is non-live. |
| `revoked` | The admission is permanently forbidden for new live use, and the exact RFC 0013 declaration revision is terminally fenced across every admission. History remains immutable. |
| `quarantined` | A committed Registry integrity, security, safety, or source-trust decision irreversibly prevents live use. It is non-live and distinct from recoverable command/publication uncertainty. |

A lifecycle-head CAS may commit before its publication finalization. Until that
family's finalization and release checks pass, the committed source/head is
private and cannot be represented externally as admitted, active, current, or
successful. This private publication state does not add another lifecycle value.

`active` is assigned only by the separately authorized activation operation
below. The allowed forward transitions are:

```text
admitted -> active | stale | revoked | quarantined
active -> stale | revoked | quarantined
stale -> revoked | quarantined
quarantined -> revoked
revoked -> no state
```

There is no `stale -> active`, `quarantined -> active`, `revoked -> active`, or
`active -> active` shortcut in this bounded contract. An old admission in any of
those non-live states is never reactivated. A separately authorized new
admission may use the same positive revision after stale or quarantined history
only under a new immutable admission identity and command identity, with an exact
match to the permanent declaration binding, a not-revoked owner-global revision
fence, and complete fresh source and activation proofs. It cannot reuse the old
command, admission, per-slot evidence, lifecycle generation, or active record as
new authority. Once the revision fence is revoked, no new admission can become
active under that revision; a fresh positive RFC 0013 declaration revision is
required unless a later separately accepted RFC amends RFC 0013. C03 always
binds exactly one admission, per-slot evidence identity, and active generation.

### Activation command and source record

Activation is a distinct typed expected-generation CAS operation whose sole
target state is `active`. Its stable command namespace and normalized semantics
bind all of these:

- authenticated tenant, authenticated activation actor/service principal,
  Registry service audience, command family, and permanent nominal command ID;
- exact target installation, declaration-wide admission source/publication
  identities/digests, expected `admitted` generation/head digest, and target
  deployment scope;
- exact permanent RFC 0013 declaration binding, immutable projection-contract
  fingerprint, and expected not-revoked declaration-revision fence;
- exact retained declaration-publisher/publication-authority evidence plus fresh
  current publication-authority decision/status and publisher credential,
  signing-key, expiry, trust, and revocation facts;
- a target-specific activation operation and narrower Authority decision that
  cannot be satisfied by registrar/admission authority;
- exact deployment plan, independent gate decisions, rollout/canary status,
  health-stop state, policy revision, and owner receipts from `DEP-005` or a
  separately accepted activation contract;
- current Artifact, Lineage, conformance, compatibility, signer/key/revocation,
  work-order, and Authority status required by the activation profile;
- exact effective Registry resource-policy revision and complete activation,
  head, outbox, publication, Event, and Evidence reservation/accounting facts;
- required durability, publication, causal, and audit inputs.

Missing, wrong-target, overbroad, stale, revoked, inaccessible, unsigned,
unfinalized, uncertain, publisher-invalid, or resource-unreserved
activation/deployment/gate/rollout evidence denies before lifecycle CAS.
Admission-only, registrar-only, or publication-only authority cannot invoke,
delegate, or satisfy activation.

An accepted activation source transaction compares the exact `admitted` head
and exact not-revoked declaration-revision fence in the same Registry
linearization, assigns the next monotonic generation without wraparound, appends
one immutable activation source record, atomically CAS-moves the sole lifecycle
head to `active`, and commits one owner-local outbox intent. The source record
binds the prior/new state and generation, permanent declaration-binding and
fence observation, retained publisher/publication-authority coordinate and fresh
status observations, exact admission/target/deployment/gate/rollout evidence,
narrowed authority, resource-policy/reservation/debt references, command semantic
digest, owner revision/time, and integrity. It contains no downstream
Event/Evidence receipt or publication finalization. `active` remains externally
unusable until the separate activation publication finalization commits, and
every release rechecks the exact head, declaration binding, revision fence,
publisher status, and all current owner facts.

### Transition command and source record

Every non-activation lifecycle transition is a separately authenticated command
with one permanent nominal command/idempotency identity. Its normalized
semantics bind:

- authenticated actor/service principal, tenant, Registry audience, exact work
  order, and explicit target-state lifecycle authority outside untrusted body
  fields;
- the complete immutable admission coordinate and admission digest;
- exact expected current lifecycle state, generation, head revision/digest, and
  integrity binding;
- one exact allowed target state;
- for target `revoked`, the exact permanent RFC 0013 declaration-binding key and
  dedicated owner-global declaration-revision revocation operation/Authority
  scope; tenant/installation-local lifecycle or registrar authority cannot
  satisfy or delegate it;
- bounded owner-authenticated cause evidence, including current source-owner
  status/revocation facts;
- required Event/Evidence profile, durability, causal, and audit inputs;
- exact effective Registry resource-policy revision and complete transition,
  head/fence, outbox, publication, Event, and Evidence reservation/accounting;
- no caller-provided owner time, next generation, next head revision, or success
  receipt.

An accepted transition atomically compares the expected lifecycle head, assigns
exactly the next monotonic generation without wraparound, appends one immutable
transition source record, CAS-moves the sole lifecycle head, and commits one
owner-local outbox intent. The transition source record binds prior and new
state, prior and new generation, admission identity/digest, cause evidence,
command/semantic digest, actor/authority/work-order references, resource-policy/
reservation/debt references, owner revision/time, and integrity. It contains no
downstream Event/Evidence receipt or publication finalization.

An accepted transition to `revoked` also atomically and irreversibly sets the
owner-global revision fence for the admission's exact permanent RFC 0013 binding
key. It can commit only after the dedicated declaration-revision revocation
authority above passes; an installation-scoped actor cannot launder local
withdrawal into a global fence. There is no installation-local-only `revoked`
state in this contract: installation-local loss of live eligibility uses `stale`
or, for the defined integrity/security cases, `quarantined`. The fence immediately
denies activation, current proof, C03 final use, and fresh admission for every
other admission under that key even if their immutable history or lifecycle
heads have not yet been annotated. Publication finalization may expose the
transition record, but it is not permission to defer or reverse the fence. A
`stale` or `quarantined` transition does not by itself revoke the global revision
fence.

History is never edited. A no-op target is not an accepted transition and
allocates no generation. An exact duplicate resumes the original publication and
may release the original transition only after its finalization and current
visibility checks. A stale expected state/generation or changed duplicate
commits nothing. The Registry repository adapter enforces the owner-supplied CAS
through generic Store primitives but does not decide transition legality.

### Race winners

The Registry lifecycle-head transaction is the Registry linearization point.

1. An `active -> stale|revoked|quarantined` transition durably committed before
   a currentness head read wins. The read cannot emit active evidence.
   A committed revision fence also wins across all other admissions under its
   exact RFC 0013 binding key, regardless of their command/admission identities.
2. A currentness read that observes an active generation must compare that exact
   generation and every current activation/deployment/source fact again before
   releasing its success result after publication finalization. If a transition
   or external revocation won meanwhile, the active result is withheld. Any
   already committed observation remains restricted historical evidence only.
3. A transition committed after current evidence release but before RFC 0014's
   final Authority migration CAS still wins. Authority must recheck the exact
   Registry generation through the owner-supported linearization path in that
   final CAS. The retained current evidence cannot override it.
4. A stale preflight, cache, old admission record, prior active evidence,
   numerically equal generation from another admission, or earlier successful
   query never wins over the current lifecycle head.
   A fresh command/admission identity never wins over the permanent declaration
   binding or a committed owner-global revision fence.
5. If a current Artifact, Lineage, conformance, signer, registrar, work-order, or
   declaration-publisher/publication-authority, activation/deployment/gate/rollout
   or other independent-owner revocation race cannot participate in one
   authoritative transaction or an accepted `FND-003` protocol, activation,
   current-proof issuance, and final C03 use are unsupported and fail closed.
   Copying a source status into Registry does not prove that a newer source
   transition did not win.
6. Command/publication outcome uncertainty never changes the lifecycle head by
   itself. Recovery may finalize and release only the original operation if its
   exact source transaction committed, no later lifecycle transition won, and
   every family-specific current fact passes a fresh recheck. Otherwise it stays
   private/uncertain or returns opaque denial. It never performs reactivation.

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
- permanent RFC 0013 declaration-binding key/record digest, immutable complete
  projection-contract fingerprint, and expected not-revoked revision fence;
- exact per-slot C03 Registry evidence identity/digest;
- canonical RFC 0013 operation bytes;
- positive declaration revision and complete declaration digest;
- exact slot ID and sink-entry bytes/fingerprint; and
- expected `active` lifecycle generation plus exact activation
  source/finalization identities/digests.

The owner performs exact-key lookup only. It does not expose a query by driver
name, operation name alone, global version alone, endpoint, alias, tag, latest,
current-without-expected-coordinate, newest number, declaration digest alone, or
partial prefix. It does not fall back to another installation, admission,
revision, slot, generation, artifact, or endpoint.

Before issuing active evidence, Registry revalidates the immutable admission and
its publication finalization/integrity, exact activation source/finalization,
exact permanent declaration binding and not-revoked revision fence, exact
current lifecycle head, target deployment/gate/rollout status, required
publisher/publication-authority/credential/key/expiry/revocation facts,
Artifact/Lineage/conformance/compatibility/registrar/activation Authority and
work-order facts, per-slot evidence publication, Registry signing/trust state,
finite request and retained-capacity budgets, complete current-observation
reservation, and required Event/Evidence availability through the accepted owner
boundaries. Any mismatch, exhaustion, or uncertainty produces no active evidence
and no durable query claim/source/outbox/Event/Evidence record.

### Current lifecycle evidence

One successful query first commits one owner-issued, access-filtered immutable
current-observation source record. It binds at least:

- current-observation identity, profile/version, canonical source digest, and
  Registry owner integrity or signature-chain identity;
- exact tenant and Registry audience/visibility binding;
- exact installation identity and scope digest;
- exact admission identity, admission digest, and immutable per-slot C03
  Registry evidence identity/digest;
- exact permanent RFC 0013 declaration-binding identity/digest, immutable
  projection-contract fingerprint, and observed not-revoked revision-fence
  revision/integrity binding;
- exact retained declaration-publisher/publication-authority evidence coordinate
  and fresh current publication-authority decision/status plus publisher
  credential/key/trust/expiry/revocation observations;
- exact canonical operation bytes, positive declaration revision, complete
  declaration digest, exact slot ID, and sink-entry bytes/fingerprint;
- current lifecycle state `active` and the exact observed generation;
- exact lifecycle-head revision/digest and Registry owner revision observed by
  the query;
- owner-assigned current verification time and current trust/key-status
  references;
- current source-owner status/revocation references required by the admission
  profile;
- exact activation source/finalization, deployment, gate, rollout, and narrowed
  activation-authority references required by the live profile;
- exact Registry resource-policy revision, semantic-freshness decision,
  reservation/accounting identities, worst-case publication obligation, and
  retained debt; and
- exact Registry query/issuance semantic digest, permanent nominal query
  identity, owner revision/time, integrity, and owner-local outbox intent.

The current-observation source record and its digest contain no Event receipt,
Evidence bundle coordinate/receipt, or current-observation publication
finalization. Event/Evidence owners bind the already-fixed observation digest.
A distinct immutable current-observation publication finalization then binds
those acknowledgements and is the only publication record that can open release.
It is distinct from admission, activation, lifecycle-transition, and per-slot
C03-evidence publication records; none of their acknowledgements are required to
be equal.

The effective durability floor is the strictest Registry-profile, deployment,
and caller-requested floor under RFC 0015. `memory_only`, queue acceptance,
unacknowledged outbox state, an unsigned bundle, a bare digest, or a database read
is never current lifecycle evidence for C03.

Current lifecycle evidence is an observation, not a capability, approval,
registrar grant, migration decision, Gateway permit, driver selection, or secret
authority. Its verification time does not give it a grace period. It cannot be
refreshed by replay or reused as proof that the generation stayed current after
issuance.

Current-proof issuance has one permanent nominal query identity and this closed
private state machine:

```text
claimed -> source_committed -> awaiting_publication -> finalized
   |              |                    |
   +--------------+--------------------+-> outcome_uncertain
```

`outcome_uncertain` is command/publication recovery state, not lifecycle
`quarantined`. Recovery may return to `awaiting_publication` or `finalized` only
for the same retained claim, source bytes, and downstream commands.

Every initial or duplicate release through the current endpoint reauthenticates
the caller and rechecks exact visibility, lifecycle head/generation, activation
and deployment/gate/rollout evidence, Artifact/Lineage/conformance/compatibility,
Authority/work-order status, the permanent declaration binding and owner-global
revision fence, current publisher/publication-authority/key/revocation status,
every other signer/key/revocation fact, per-slot evidence, resource reservation,
and current-observation publication finalization. If any local transition,
global revision fence, publisher/Authority revocation, resource-accounting
uncertainty, or other external revocation won, the endpoint returns only the
uniform opaque current denial. It never returns an old immutable observation
typed as current. That observation remains available only through separately
authorized, durably audited historical inspection.

An exact duplicate that still passes every release check returns only the
original immutable result and original verification time. An exact semantically
unchanged request under a fresh nominal query identity is coalesced to that same
result when the accepted freshness policy permits; the fresh identity is not
durably claimed merely to duplicate history. Neither path creates a later time or
silently refreshes authority. Changed semantics under an already accepted
identity conflict. A genuinely later observation is created only when currentness
semantics require a fresh owner verification and all rate, concurrency,
cardinality, byte/capacity, isolation, and publication reservations pass; a new
query identity alone neither proves freshness nor grants authority.

### Restricted and redacted views

Detailed admission, transition, currentness, conflict, and source-trust facts are
available only through a separate dedicated read scope and an audited restricted
view. The view binds source record/evidence coordinates, viewer tenant/scope,
redaction policy/revision, included fields, explicit omitted or inaccessible
fields, owner revision, and view digest. Audit commit failure withholds the view.

Redaction cannot omit a mandatory C03 coordinate and still label the proof
complete or current. An access-filtered C03 consumer either receives every
mandatory Registry coordinate and trusted receipt or fails closed.

## Per-Slot C03 Registry Evidence for RFC 0014

The declaration-wide admission source record selects no sink. After a separately
authorized activation reaches one exact `active` generation and its distinct
publication finalization commits, Registry rechecks current publisher/publication
authority and key/revocation status, compares the permanent declaration binding
and not-revoked owner-global revision fence, and reserves the complete per-slot
Registry/Event/Evidence publication obligation in the same accepted
linearization/accounting protocol that commits each per-slot source. It then
materializes one distinct immutable C03 evidence source record for each exact RFC
0013 sink entry required for C03 proof. The records share the same admission and
declaration but each has a different owner-assigned evidence identity and digest
bound to exactly one `SecretCredentialSlotId` and complete sink-entry
bytes/fingerprint. Evidence identity/digest reuse across slots, admissions, or
generations is forbidden.

RFC 0014's frozen field names `registry_admission_evidence_id` and
`registry_admission_evidence_digest` refer to this per-slot Registry evidence
record. This RFC does not rename those members or add another proof-bundle field.
The record asserts only Registry-owned facts. Artifact, Lineage, conformance,
activation, deployment, and gate entries are exact source references and owner
receipts that Registry verified; Registry does not reissue those owners' claims.

Each per-slot C03 evidence source record binds exactly these semantic facts:

- distinct Registry evidence identity, profile/schema version, and Registry
  owner integrity or signature-chain identity; its canonical evidence digest is
  envelope/output metadata computed after the canonical source payload is fixed
  and is excluded from that payload;
- exact tenant scope;
- exact installation identity and immutable scope digest;
- immutable declaration-wide admission identity and admission digest;
- exact permanent RFC 0013 declaration-binding identity/digest and immutable
  complete projection-contract fingerprint;
- exact retained declaration-publisher/publication-authority evidence coordinate
  and fresh current publication-authority decision/status plus publisher
  credential/key/trust/expiry/revocation observations;
- exact canonical RFC 0013 `DriverOperationRef` bytes;
- exact positive RFC 0013 declaration revision;
- complete canonical RFC 0013 declaration digest;
- one exact `SecretCredentialSlotId` plus its complete canonical sink-entry bytes
  and fingerprint;
- lifecycle state `active` and the exact monotonic lifecycle generation observed
  for the migration proof;
- exact not-revoked owner-global declaration-revision fence revision and
  integrity binding observed for the migration proof;
- exact activation source/finalization and deployment/gate/rollout source
  references for that target;
- exact immutable implementation/projector Artifact identities, versions,
  content and manifest digests, plus Artifact attestation identities/digests and
  signer/key/revocation references;
- exact Lineage producer receipts, required relation set, integrity/signing
  identities/digests, and current anti-tamper references;
- exact independent conformance identity/digest, suite/profile/version,
  environment, result, issuer, current trust/revocation references, and
  compatibility-policy reference;
- exact Registry resource-policy revision, reservation/accounting identities,
  worst-case per-slot publication obligation, and retained debt; and
- owner revision/time, trust/key status, source-record integrity, publication
  profile, and owner-local outbox intent.

The per-slot source record and canonical digest contain no generic Event
coordinate/receipt, Evidence bundle coordinate/commit receipt, or publication
finalization. Event/Evidence commits bind the already-fixed per-slot record
digest. A separate immutable per-slot publication finalization binds those
downstream acknowledgements and opens that evidence identity/digest for RFC 0014
use. One slot's finalization cannot publish another slot's record.

The evidence contains no C03 `SecretRef`, source-entry identity, source-entry
digest, source approved-destination set, source classification, C03 provider
coordinate, purpose, Authority migration decision, migration command, target
entry, target ref, lease, permit, delivery handle, or C03 current-head decision.
It contains no endpoint instance or provider locator. Registry never attests
those facts.

The per-slot evidence is immutable historical evidence that one exact sink entry
under the declaration-wide admission was active at the named generation and was
published durably. It is not currentness by itself. A later stale, revoked, or
quarantined transition does not rewrite or delete it; the exact current query and
final Authority CAS prevent live reuse. A later owner-global revision fence
denies every per-slot record under that declaration revision, including records
from different commands, installations, admissions, or generations.

## RFC 0014 Three-Way Proof Binding

RFC 0014 remains authoritative for source/target C03 grammar and migration. This
RFC supplies the missing Registry owner side of its proof join.

RFC 0014's proof bundle remains exactly the following eighteen non-null members,
with its existing closed parsing, ordering, bijection, and no-reuse rules:

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

This RFC adds no nineteenth member, extension, side field, receipt field, or
alternate bundle version. Any such change requires a separately accepted RFC
0014 amendment.

For every migrated C03 source entry, direct byte equality from that exact bundle
to the dereferenced per-slot Registry evidence record is limited to the Registry
members RFC 0014 actually carries: Registry evidence identity/digest,
installation identity/scope digest, admission identity/digest, complete
declaration digest, lifecycle generation, and the proven declaration revision.
The closed `source_entry` supplies the canonical operation and exact slot for the
existing RFC 0014 validation; those values must also equal the Authority
historical record and dereferenced per-slot Registry evidence. The Authority
record additionally owns the C03 source-entry identity/digest, complete approved
destination set, and source decision; Registry records do not copy or attest
those facts.

That operation/slot comparison is RFC 0014's existing validation of the closed
`source_entry` and dereferenced owner records. It does not create another
top-level direct Registry member in the frozen proof bundle.

Event/Evidence coordinates, append/commit receipts, publication-finalization
identities, durability, completeness, integrity, signer, and key-status paths are
validated transitively, not compared as nonexistent bundle members. The verifier
must dereference the exact authenticated Authority record and exact per-slot
Registry evidence source record, verify each source digest, then verify each
record's own acyclic publication finalization and RFC 0015 receipts bind that
already-fixed source digest. Admission, activation, per-slot evidence, lifecycle
transition, and current-observation publication records are distinct. Their
Event/Evidence coordinates and receipts are never required to equal one another.
The dereferenced Registry record must also validate against the permanent RFC
0013 declaration binding, its not-revoked owner-global revision fence, and current
owner-authenticated publisher/publication-authority/key/revocation status; these
are transitive owner checks and add no member to RFC 0014's frozen bundle.

The complete proof therefore combines direct equality for the frozen eighteen
members with transitive owner-record/receipt validation. A hidden database join,
unverified receipt reference, current-query publication receipt substituted for
per-slot evidence publication, or per-slot evidence reused for another canonical
source entry is a denial.

A bare digest, timestamp, signature without its key/status path, database row,
foreign key, join result, query result, current head, endpoint, operation lookup,
manifest, filename, image tag, source order, matching number, or declaration byte
similarity is insufficient. Evidence identity cannot substitute for evidence
digest, and neither can substitute for the complete record and owner receipt.

Current lifecycle evidence is non-authorizing and is a preflight input only.
Immediately before the RFC 0014 Authority migration head CAS, Authority must
recheck the exact admission, per-slot evidence, generation, activation,
deployment/gate/rollout status, permanent declaration binding, not-revoked
owner-global revision fence, current publisher/publication-authority/key/
revocation status, finite resource/accounting status, and external trust facts as
current `active` through the Registry owner and an accepted same-transaction or
`FND-003` protocol. If a stale/revoked/quarantined transition, global revision
fence, publisher revocation/uncertainty, accounting uncertainty, or required
external revocation committed first, it wins and migration commits no target
head.

The final C03 check validates that the retained Registry proof records and their
publication obligations remain fully accounted and non-uncertain; it does not
require unused Registry capacity for a record already reserved and committed.
Authority remains sole owner of resource admission/accounting for its migration
command and target-head CAS. Registry does not allocate or clear Authority
capacity through this transitive check.

Missing, hidden, inaccessible, stale, revoked, quarantined, incomplete, corrupt,
wrong-owner, wrong-tenant/scope/audience, untrusted, expired/revoked-key,
substituted, unavailable, or uncertain Registry or RFC 0015 evidence denies with
no C03 migration, provider access, node call, Gateway/adapter/driver invocation,
lease, delivery, or other side effect.

## Finite Resource Admission, Isolation, and Retained Debt

No privileged Registry operation may durably claim a nominal identity, allocate
an owner value, commit a source/head/fence/outbox/finalization/tombstone, or cause
an Event/Evidence publication obligation until owner-enforced finite resource
admission succeeds. This applies to declaration binding, admission, activation,
lifecycle transition, per-slot evidence, current observation, outbox delivery,
publication finalization, historical import, recovery that needs a new owner
record, and every associated Event/Evidence obligation.

The effective Registry policy has finite hard bounds for all of these resource
classes:

- request rate and burst/concurrency;
- retained privileged-record and non-reuse-marker cardinality;
- retained canonical/source/outbox/finalization/tombstone bytes and total
  storage/capacity debt; and
- in-flight Registry plus downstream Event/Evidence publication reservations,
  backlog, and recovery work.

Every class is enforced at minimum per authenticated tenant, principal, canonical
operation, command/query family, and global Registry. Combined scopes all apply;
passing one does not bypass another. Per-scope reserved capacity, isolation, and
backpressure must prevent one tenant, principal, operation, or family from
consuming every shared slot or starving unrelated allowed work. A global limit is
not a substitute for tenant/operation isolation, and isolated capacity cannot
override the global safety ceiling.

Registry owns its effective resource policy, counters, reservations, semantic
coalescing, and admission decision. A separately accepted contract must define
the policy/configuration owner, update authorization, accounting grammar,
reservation lifecycle, clock/window semantics where rate windows exist,
overflow behavior, debt reconciliation, and executable conformance. Authority
and signed work orders may impose narrower constraints; they do not own Registry
counters and cannot widen, reset, or erase Registry policy. Callers cannot choose
limits, claim exemptions, reset windows/debt, supply accounting outcomes, or
trade one scope against another. This RFC intentionally specifies no numeric
default, wire field, schema constant, algorithm, or operator control plane.

Before durable allocation, Registry computes a conservative complete worst-case
obligation for the operation: every Registry claim, identity, source, head/fence,
outbox, finalization, integrity, non-reuse/tombstone, recovery, and retained-byte
record, resource-accounting entry, and required non-reflecting security/audit
obligation plus every required Event append, Evidence commit,
inbox/deduplication, receipt, and acknowledgement obligation. It then uses an
accepted owner protocol to reserve/account that complete obligation atomically or
compensatably. Registry cannot define Event/Evidence or audit-owner quota,
deduplication, retention, or capacity semantics; those owners independently admit
and account their records and return authenticated reservation/acceptance facts
through their accepted contracts. Audit/accounting denial paths are themselves
finite, isolated, and semantically coalesced; a rejected-request flood cannot
create unbounded per-request durable audit history.

No downstream owner write may escape the reserved obligation. If independent
owners cannot reserve before Registry claim, or no accepted `FND-003` protocol
can prove compensatable all-owner accounting, the operation is unsupported and
fails closed before the claim. Compensation may release only demonstrably
unconsumed reservation after owner-authenticated proof of absence. A committed or
possibly committed write, non-reuse marker, publication debt, lost response, or
uncertain owner outcome remains charged until the accepted reconciliation or
retention protocol proves its exact disposition. Reservation failure after a
source exists is a contract violation, not permission to publish unaccounted work
or delete the source.

Missing, stale, unavailable, overflowed, corrupt, or uncertain policy, counter,
reservation, capacity, or downstream accounting state fails closed before any
new durable allocation. Arithmetic is checked and overflow denies. Capacity or
quota exhaustion creates no claim, binding, fence, source/head, outbox,
finalization, Event, Evidence, or tombstone result. It cannot convert a permanent
binding conflict, missing/corrupt history, or uncertain prior use into allow.
Existence-sensitive resource denials use the same opaque outward profile as other
Registry denials; detailed accounting is restricted and durably audited.

After authentication/visibility and request-rate enforcement, Registry performs
semantic deduplication/coalescing before deciding that permanent storage is
needed. A fresh nominal identity for an exact unchanged semantic request does not
force a new permanent command record: it resumes or reuses the original retained
path/result when family-specific freshness and release checks permit. A fresh
admission is created only when the installation/source semantics genuinely
require a distinct admission under this RFC. A new current observation is created
only when the accepted currentness policy requires a later owner verification.
Both require all finite budgets and complete reservation. Coalescing is scoped by
authenticated tenant/principal/audience/family visibility and cannot reveal or
reuse another scope's record.

Retention cannot make permanent history or resource debt reusable. Payload
compaction requires the accepted tombstone protocol below and may change current
retained-byte charge only from the proven removed payload to the exact retained
tombstone charge; it never resets cumulative debt or quota history, erases a
consumed reservation, clears backlog/debt, widens capacity, or turns a used/
uncertain identity into a miss. Restart recovers the exact policy revision,
counters, reservations, debt, isolation partitions, and coalescing/non-reuse
indexes before accepting work. Unavailable recovery state fails closed rather
than starting empty.

## Permanent Declaration Binding, Idempotency, Crash Recovery, and Non-Reuse

### Permanent RFC 0013 binding and global revocation fence

Registry retains one owner-global declaration-binding index distinct from every
command-idempotency index, tenant/installation admission index, lifecycle head,
and proof/evidence index. Its exact key is the canonical RFC 0013 pair:

```text
(DriverOperationRef, positive driver_declaration_revision)
```

The key is validated with RFC 0013's exact nested operation grammar and positive
revision rule. It has no tenant, installation, principal, command, admission,
proof, or artifact component. The retained immutable value includes the complete
canonical RFC 0013 declaration bytes and declaration digest, every ordered
canonical sink-entry byte/fingerprint, the immutable complete
projection-contract fingerprint, exact owner-authenticated declaration-publisher
principal, publication-authority evidence identity/digest/revision, initial
current credential/key/trust/expiry/revocation observations, owner-defined
publication work-order/causal binding, and owner revision/time/integrity. The
canonical declaration bytes, projection-contract fingerprint, publisher, and
publication-authority coordinate are permanent payload, not compactable command
detail. The companion monotonic revision fence is a distinct owner record indexed
by the same exact key; it is not mutable content inside the immutable binding.

Only a separately owner-authenticated declaration publisher with current typed
publication/operation-namespace Authority for the exact canonical operation,
positive revision, global definition/version, complete declaration bytes/digest,
immutable projection-contract fingerprint, Registry audience, Authority
decision/revision, expiry/key/revocation state, and owner-defined work-order/
causal context may create the first binding. This authority passes before finite
resource reservation and before insert-or-compare. Registry then performs atomic
insert-if-absent or complete exact comparison before committing an installation
admission source. For the first binding, its unique-index insert and the accepted
admission claim/source/head/outbox commit share one Registry transaction and one
complete resource reservation; a changed or unauthorized concurrent candidate
loses before its binding, fence, command claim, or admission source commits.

An exact duplicate binding may be consumed as non-authorizing immutable input to
a separately authenticated admission only after current publisher/publication
authority and finite resource admission pass again. Under the same key, a changed
publisher, changed publication operation/scope semantics, declaration bytes, any
changed sink-entry byte/fingerprint, or any changed projection-contract
fingerprint permanently conflicts before a second admission/source/head/outbox
exists. A later current Authority evidence identity/revision is valid only as an
owner-authenticated successor/status observation for the exact retained
publisher and unchanged coordinate; it never overwrites the initial evidence.
Fresh nominal command/admission IDs, another tenant or installation, and fresh
Artifact/Lineage/conformance/registrar proofs cannot bypass, overwrite, or fork
the binding. Tenant registrar, lifecycle, activation, revision-revocation,
driver/self-claim, producer provenance, conformance, ownership, or generic
operator authority cannot initialize it. Unauthorized, wrong-scope, expired,
revoked, uncertain, or losing publication claims create no Registry or
Event/Evidence record.

The companion owner-global revision fence is atomically created as not revoked
with the first binding and may move only once to terminal `revoked`. An accepted
Registry revocation under any admission for that exact key atomically sets it,
but only with dedicated owner-global declaration-revision revocation authority;
tenant/installation lifecycle authority is insufficient. Once set, no fresh
command, admission, activation, evidence projection, current query, duplicate
release, replay, import, or C03 final CAS may return the revision to live use.
Historical records remain readable through restricted inspection. Returning a
release to live use requires a new positive `driver_declaration_revision` and
therefore a new exact RFC 0013 binding key, unless a later separately accepted
RFC explicitly amends RFC 0013.

Missing, corrupt, inaccessible, compacted, or uncertain binding/fence history is
never treated as a fresh key or not-revoked result. Admission, activation,
per-slot evidence issuance, current release, and C03 final use fail closed. The
same fail-closed rule applies to missing, revoked, expired, inaccessible, or
uncertain current publisher/publication-authority/key status. Publisher
revocation or uncertainty is not authority to clear, replace, or rewrite the
permanent binding; it denies live use and is handled by the already-defined
owner-authorized stale/revoked/quarantined lifecycle path. If a revision-fence
transaction cannot prove commit or absence, every admission under that exact key
remains globally non-live until recovery resolves the same transaction without
replacement identity or semantics.

Staleness remains admission-local and non-live. A stale admission cannot be
reactivated. A separately authenticated fresh admission may use the same revision
only when the permanent binding compares exactly, the global revision fence is
not revoked, current publisher/publication authority and key/revocation status
pass, semantic coalescing proves a new admission is required, all finite budgets
and reservations pass, and every fresh admission source, trust, and publication
proof passes. It creates a new admission/generation/evidence path and derives no
authority from the stale record. A later return to `active` independently
requires every fresh publisher, deployment, activation, resource, publication,
and release proof.

### Permanent command identity

Declaration binding, admission, activation, non-activation lifecycle transition,
per-slot C03 evidence issuance, current observation, publication finalization,
outbox delivery, import, recovery mutation, and every other privileged internal
Registry operation each use one family-specific nominal command/query identity as
their sole idempotency identity after semantic coalescing and resource admission
determine that a durable operation is required.

Every stable key unconditionally binds this complete namespace:

```text
authenticated tenant
authenticated actor or internal service principal
command/query family
Registry service audience
family-specific nominal identity
```

There is no anonymous, tenant-only, family-only, or principal-optional form.
Cross-principal, cross-tenant, cross-audience, or cross-family reuse of the same
nominal bytes addresses a different stable key and never reaches another key's
record. Credential identity/status, work order, authority decision, admission,
expected generation, evidence digest, request ID, trace ID, and body fields are
not alternate lookup identities; where part of normalized semantics, any change
under one stable key is a permanent conflict.

After authentication, visibility, dedicated-scope and publisher checks,
request-rate enforcement, semantic coalescing, and complete resource reservation,
the first accepted operation atomically claims that stable identity and retains
the complete normalized semantic projection/digest, resource-policy/reservation/
debt projection, and owner first-observation time. All owner-assigned admission,
activation, transition, per-slot evidence, current observation, finalization,
outbox identities; owner times/revisions; lifecycle generations; and canonical
source bytes are either deterministically derived from the retained claim or
allocated and retained in the same atomic claim/source transaction. No allocator
result or downstream write may escape before that retention/accounting boundary.

A crash before durable retention cannot consume an identity and later allocate a
replacement. A claim-keyed allocator or deterministic derivation must return the
same candidate on recovery; an outcome-uncertain transaction is queried by its
same claim/transaction identity before any retry. The caller, persistence
adapter, outbox worker, Event owner, and Evidence owner cannot choose or replace
Registry-owned values.

The same stable key and same normalized semantics resumes only the original
source/publication path. Release of its original result still requires the
family-specific fresh checks in this RFC. Any changed semantic byte, including
changed credential, work order, authority, scope, declaration, artifact,
evidence, expected generation, cause, audience, or durability request, is a
permanent conflict before a second source record, generation, publication,
Event, or Evidence result is created.

Full records and their non-reuse markers have no TTL in this contract. Retention
may remove payloads only after an accepted protocol durably commits an immutable
non-reuse tombstone binding the stable key, semantic digest, original result or
uncertainty, owner/integrity chain, and retention generation. Missing, corrupt,
inaccessible, compacted, or uncertain history never becomes a fresh miss.
Tombstones and retained uncertainty remain charged cardinality/debt; compaction
cannot reset quotas, isolation accounting, rate history, or cumulative consumed
obligations. A future accepted owner contract may account only the exact current
payload-to-tombstone byte difference while preserving cumulative debt and
identity non-reuse.

### Command and publication outcome uncertainty

If the Registry repository port or a downstream owner cannot prove commit or
absence, the exact command enters private `outcome_uncertain` recovery state.
This state is not lifecycle `quarantined`, does not move the lifecycle head, and
is never externally visible as success/currentness. Registry allocates no
replacement command/admission/evidence/finalization identity, generation, time,
or source bytes and does not retry under changed semantics. Its complete
reservation and possibly consumed Registry/Event/Evidence debt remain charged;
uncertainty cannot free capacity or authorize unaccounted retry.

For a revocation command, uncertainty about the atomic lifecycle/fence commit is
also uncertainty about live eligibility for every admission under the exact
declaration-binding key. All such live paths deny until recovery of that same
transaction proves the retained result; a fresh command cannot infer absence or
clear the fence.

Recovery queries the same stable key, claim, source transaction, outbox command,
and downstream idempotency identities. It may only:

- recover the original retained source and continue its original publication;
- prove no source mutation and resume the same retained/deterministic claim;
- recover the original finalization and consider family-specific release; or
- remain `outcome_uncertain` and require intervention.

Before releasing a recovered admission, activation, transition, per-slot
evidence, or current observation, Registry rechecks authentication/visibility,
the exact lifecycle head, current publisher/publication authority and key/
revocation status, retained resource policy/reservation/debt, and every
family-specific current source, activation/deployment, trust, key, and revocation
fact. If a later lifecycle transition, publisher revocation, resource-accounting
uncertainty, or other external revocation won, the original immutable record
remains historical and the live/current endpoint returns opaque denial. Recovery
never performs activation or reactivation.

An immutable source record found without its required integrity or publication
finalization stays private and incomplete; it is never inferred complete or
repaired with new identities. Inspect-only replay is not the reconciler. A sole
Registry-owned reconciler may advance retained owner-local recovery/publication
state by CAS after all dependencies exist, but it cannot allocate alternate
identities, change semantics, reauthorize a caller, select latest, call a driver,
invoke the Gateway, perform C03 migration, or infer an external owner's current
state.

## Event, Evidence, and Outbox Ordering

RFC 0015 owns Event/Evidence contracts and durability. Registry owns source
mutations, owner-local outbox intent, and the separate Registry publication
finalization that truthfully gates external visibility. Every admission,
activation, lifecycle transition, per-slot C03 evidence, and current-observation
operation follows this acyclic graph:

1. Registry authenticates/authorizes, validates current publisher authority where
   required, enforces request limits, coalesces semantic duplicates, computes the
   complete worst-case multi-owner obligation, and obtains the accepted finite
   reservations before any durable claim. Event/Evidence owners retain their own
   independent admission/accounting decisions.
2. Registry claims the stable key, fixes canonical source bytes, computes the
   source digest, and atomically commits the immutable source record, required
   lifecycle head/CAS, command/resource state, and one owner-local outbox intent
   that references that already-fixed source identity/digest.
3. Event owner accepts an authenticated idempotent append whose subject is that
   exact source identity/digest and returns its append receipt only after the
   required durability floor.
4. Evidence owner accepts an authenticated idempotent commit that binds that
   same source identity/digest, required Event receipt and source-owner facts,
   then returns its bundle coordinate/receipt only after required completeness,
   integrity, and durability.
5. Registry validates those exact acknowledgements and commits a separate
   immutable publication finalization record binding the fixed source
   identity/digest, outbox identity, Event coordinate/receipt, Evidence bundle
   coordinate/receipt, achieved durability/completeness, owner trust/key status,
   consumed reservation/debt, finalization identity/revision/time, and
   family-specific release state.
6. Registry performs the family-specific fresh head/source/publisher/revocation/
   resource checks and only then releases success or current visibility. Every
   duplicate release repeats those checks.

Every source uses a non-self-referential owner envelope. Canonical source payload
bytes exclude their own digest and all downstream acknowledgements; Registry
computes the digest only after those bytes are fixed and retains the identity,
payload, and digest atomically. An outbox intent may carry its preassigned
identity in the source payload, but the outbox row that references the resulting
source digest is a distinct atomically committed record. No source digest,
outbox digest, Event receipt, Evidence receipt, or finalization digest recursively
contains itself.

In particular, a per-slot record's canonical evidence digest field is
envelope/output metadata over its already-fixed canonical source payload. The
field is excluded from that payload and therefore cannot participate in its own
digest input.

The source record, per-slot C03 evidence source, current-observation source, and
their canonical digests contain none of their own downstream acknowledgements or
publication-finalization values. Finalization never mutates a source record. Its
own digest is not recursively made a prerequisite of the Event/Evidence commits
that it records; any later audit event about finalization is a separate
non-gating source operation.

Admission, activation, lifecycle transition, per-slot evidence, and current
observation each have distinct outbox commands, Event/Evidence commits, and
publication finalizations. A receipt from one family/source cannot finalize
another. Queue acceptance, unacknowledged outbox state, memory-only state, a bare
digest, or a generic database row is never publication success.

When Registry and Event/Evidence share one supported persistence transaction,
the owners may commit their separately owned records through a composition
boundary while retaining the source-before-acknowledgement digest graph. Neither
owner interprets or rewrites the other's semantics. When they use independent
stores, the Registry source record and outbox intent share one local atomic
transaction; Event/Evidence use authenticated inbox deduplication and
at-least-once delivery. Registry finalizes only after validating the original
acknowledgements.

The independent-store path remains blocked until accepted `FND-003` recovery
defines the publication barrier and all crash winners. No implementation may
call two commits atomic, claim distributed exactly-once, acknowledge queueing as
durability, drop backlog, or infer success from an absent acknowledgement. If
Registry source state and its outbox cannot share one local atomic transaction,
the source mutation is unsupported and fails closed.

An Event, Evidence, or Registry publication-finalization receipt proves only its
bounded durable record. It does not grant registrar/activation authority, make
an admission legal, keep a lifecycle generation current, authorize C03
migration, or permit a Gateway/provider effect.

## Security, Privacy, and Oracle Resistance

- All privileged schemas are closed and bounded after `FND-001`; unknown,
  duplicate, null, over-bound, wrong-version, or authorizing extension fields
  fail before lookup or mutation.
- Registry records and evidence contain no credential, token, API key, raw
  secret, secret-derived hash, provider request/error, mutable endpoint, provider
  locator, protected payload, approval token, Gateway permit, lease material, or
  driver result payload.
- Declaration-publication/operation-namespace, registrar, activation, and
  revision-revocation authority; caller and publisher identity; tenant, audience,
  work order, target scope, expiry, key status, and revocation are trusted outer
  bindings. A driver, adapter, Artifact/Lineage producer fact, conformance report,
  manifest, endpoint, node report, Event, Evidence bundle, message, or body field
  cannot grant, substitute, delegate, or broaden them.
- Artifact signatures, Lineage signatures, conformance attestations, Registry
  evidence signatures, and their trust/key-status/revocation chains are distinct.
  One valid signature cannot satisfy another owner or purpose. Unavailable or
  revoked key status fails closed.
- A driver or adapter cannot publish an operation namespace, admit, activate,
  attest, certify, or provide current lifecycle evidence for itself. A node
  self-test cannot become independent conformance evidence.
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
- Registry resource policy is finite and owner-controlled. Caller-selected
  limits, fresh-ID quota bypass, cross-tenant capacity borrowing, unaccounted
  downstream writes, counter overflow, missing restart state, and compaction as
  quota reset fail closed before durable allocation.
- No admission, activation, transition, query, evidence build, replay, or
  recovery path may call a provider, driver, adapter, node target, network,
  filesystem, device, or Gateway side effect.
- No shared agent, daemon, SDK, CLI, bridge, Store, or evidence service may
  inherit or launder declaration-publication, registrar, activation, revision-
  revocation, tenant, work-order, quota constraint, C03, or Gateway permission.

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
declaration or adapter `admitted` or `active`, allocate a live generation, mint
Registry admission/per-slot/current evidence, or make C03 migration possible.
Only the complete new authenticated declaration-wide admission path may create a
new non-live admission; only the separate narrowed activation path with current
deployment/gate/rollout proof may create `active`; and only the per-slot and
current publication paths may support RFC 0014.

Import itself is a privileged resource-admitted family. Before persisting any
import record, Registry applies finite rate/concurrency/cardinality/byte/capacity
and isolation budgets and reserves its complete retained/audit/publication debt.
Quota exhaustion or accounting uncertainty imports nothing. Fresh import IDs,
chunking, restart, or compaction cannot bypass semantic coalescing, non-reuse, or
charged debt.

Import validates every retained Registry admission and per-slot record against
the permanent RFC 0013 declaration binding, retained publisher/publication-
authority evidence, and preserves/consults the terminal revision fence. A
revoked publisher or fence does not rewrite valid history; it classifies all such
history as non-live. Import cannot establish publication authority, seed an
alternate binding, treat absent/corrupt binding history as a fresh miss, clear a
revoked publisher/fence, reset resource debt, or use imported/fresh command or
admission IDs to admit changed same-revision bytes. A historical non-Registry
declaration is not itself a binding; only the authenticated exact path above may
establish one before a non-live admission.

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

- the permanent RFC 0013 declaration binding and global revision-fence history;
- retained publisher/publication-authority status observations and Registry
  resource-policy/reservation/debt history;
- the retained admission command and immutable admission decision;
- lifecycle transitions and generation ordering;
- currentness observations as historical observations at their original owner
  time/revision;
- Event/Evidence publication and crash-recovery state; and
- RFC 0014 proof equality or mismatch explanations over retained records.

Replay, import, simulation, and policy comparison cannot admit or activate a
driver, transition or reactivate a lifecycle, allocate a generation, refresh
Artifact, Lineage, conformance, Authority, key, or Registry current state, emit a
live currentness receipt, move a Registry head, select or invoke a driver, call
an endpoint, issue a Gateway permit, or perform C03 migration. A historical
active record remains historical. A non-live simulation must use detached state
and can produce only explicitly non-authorizing results. They cannot create,
replace, clear, or weaken a declaration binding or revision fence; mismatch,
missing history, or revoked history remains a non-live denial. They also cannot
establish/refresh publisher authority, reserve/free capacity, reset counters or
debt, bypass semantic coalescing, or cause Event/Evidence accounting or writes.

## Sequenced Implementation Plan, Tests, and Stops

Every slice is separately reviewed. Passing one slice does not satisfy a later
owner dependency or authorize a live route.

### Slice 1 - Grammar and port-contract freeze

Scope:

- accept and implement the required `FND-001` nominal/schema/digest grammar and
  `FND-006` compatibility/migration rules;
- preserve RFC 0013 types, validation, complete declaration bytes, and every
  sink-entry byte exactly;
- freeze only behavior-free Registry values and narrow owner ports needed for
  deterministic tests; those external-owner test ports consume already accepted
  behavior-free Artifact, Lineage, and Authority contracts by exact reference
  and do not define, copy, or freeze those owners' semantics, schemas, digests,
  decisions, or lifecycle locally; and
- record Artifact, Lineage, declaration-publisher/registrar/activation/revision-
  revocation Authority, Registry quota/resource policy and accounting,
  conformance, `EVT-003`/`EVID-001`, `FND-003`, and `DEP-005` as later
  live-composition stops, not prerequisites to pure state-machine tests.

Tests and evidence:

- cross-language canonical fixtures for every newly frozen behavior-free value;
- exact RFC 0013 declaration and sink-entry byte reuse, with no second serializer
  or operation/slot/profile type;
- permanent declaration-binding key/value and terminal revision-fence fixtures,
  including changed same-revision bytes, sink entries, and projection fingerprint
  denial across fresh command/admission/tenant/installation identities;
- exact external publisher/publication-authority and resource-policy test-port
  references, proving no Registry-local Authority, Event/Evidence, or numeric
  quota grammar is frozen;
- compatibility classification, N-1/N/N+1 read/deny, rollback, and persisted
  migration fixtures; and
- dependency matrix proving which owner port blocks each live slice.

Stop conditions:

- stop on any unresolved ID, schema, digest, canonical-byte, timestamp, bound,
  error, generated parity, or migration question owned by `FND-001`/`FND-006`;
- stop rather than invent an Artifact, Lineage, Authority, conformance, or other
  external-owner behavior-free contract that has not already been accepted;
- stop on any unresolved publisher/operation-namespace Authority, Registry
  resource-policy/config/accounting, multi-owner reservation/compensation,
  isolation, backpressure, retention/debt, or executable-conformance contract;
- no live owner is represented by a permissive fake or docs claim; and
- no external/generated surface before its parity and migration fixtures pass.

### Slice 2 - Behavior-free Registry values

Scope:

- add only accepted closed values, strict parsing, deterministic serialization,
  canonical projections, and code-only non-reflecting errors to
  `splendor-types`;
- expose no service trait, repository, current lookup, lifecycle decision,
  daemon, SDK, CLI, generated surface, or I/O; and
- retain exact RFC 0013 values rather than wrappers or copies.

Tests and evidence:

- positive, unknown/duplicate/null/oversize/wrong-ID/wrong-owner/wrong-scope
  grammar fixtures;
- nominal non-interchangeability among admission, activation, lifecycle,
  per-slot evidence, publication, Event, Evidence, endpoint, and C03 identities;
- canonical bytes/digests and complete coordinate mutation tests; and
- no unchecked constructor, generic authorizing map, `extensions` authority,
  alternate declaration parser, or authority conversion.

Stop conditions:

- no behavior-free implementation before this RFC and exact grammar owners are
  accepted; and
- no runtime, repository adapter, or live owner behavior in this slice.

### Slice 3 - Deterministic Registry owner state machine

Scope:

- implement declaration-wide non-live admission, activation/lifecycle legality,
  permanent RFC 0013 declaration binding and global revision fence, per-slot
  evidence projection, finite Registry resource admission/accounting and semantic
  coalescing, source/finalization separation, permanent command identity,
  current-release interpretation, and recovery decisions only in
  `splendor-gateway::registry`;
- define the Registry-owned repository/application port; and
- use deterministic in-memory owner ports to prove semantics without claiming
  external trust, durability, currentness, or live composition.

Tests and evidence:

- a two-or-more-slot declaration creates one admission and distinct per-slot C03
  evidence identities/digests without duplicate admission or slot conflict;
- admission creates only `admitted`; admission/registrar authority cannot
  activate; correct target-specific activation authority is narrower;
- tenant-only registrar, lifecycle, activation, revision-revocation,
  driver/self-claim, Artifact/Lineage producer, conformance, ownership, and
  generic operator facts cannot initialize the owner-global binding;
- exact owner-authenticated publisher/publication authority succeeds only for its
  canonical operation, positive revision, global definition/version, declaration
  bytes/digest, projection fingerprint, Registry audience, current decision/key/
  expiry/revocation state, and owner-defined work-order/causal context;
- wrong, revoked, substituted, cross-tenant, wrong-operation/revision/definition/
  declaration/fingerprint/audience, expired, uncertain, registrar-only, or
  concurrent losing publisher claims create no binding, fence, command claim,
  admission source/head, outbox, Event, Evidence, or finalization;
- when two tenants concurrently propose different bytes/fingerprints for one
  operation/revision, tenant-only registrar claims create nothing, only the exact
  publisher/namespace-authorized claim may win, and every loser creates no
  durable owner/publication record;
- wrong/missing target, activation, deployment, gate, rollout, health-stop, or
  current policy evidence denies before CAS;
- same command/same semantics resumes one source; changed semantics conflict;
  cross-command changed declaration bytes, changed sink entries, or changed
  projection fingerprint conflict under the permanent RFC 0013 binding key, and
  fresh command/admission IDs cannot bypass that conflict;
- a stale admission remains non-live; a separately authorized fresh command may
  create a new admission for the exact same binding only while the revision fence
  is not revoked and complete fresh proofs pass, without reactivating stale or
  quarantined history;
- revocation under any admission globally fences the revision, so fresh command,
  admission, tenant, installation, activation, evidence, and query identities all
  deny that revision and only a fresh positive declaration revision can return a
  release to live use;
- installation-local or registrar authority cannot set the global revision
  fence; only the dedicated declaration-revision revocation operation can, while
  local loss of eligibility follows `stale` or `quarantined` semantics;
- every allowed/forbidden transition, generation increment/overflow, stale CAS,
  and one-winner concurrent CAS;
- lifecycle `quarantined` is irreversible while command/publication
  `outcome_uncertain` can only resume the same source/finalization and never
  reactivate;
- same nominal ID under another principal, tenant, audience, or family cannot
  collide with or reveal the original stable key;
- fresh-ID floods of semantically unchanged admissions/current observations are
  rate-limited and coalesced without new permanent claims; genuinely fresh work
  proceeds only when currentness/semantics require it and every finite budget
  passes;
- finite rate, burst/concurrency, retained-cardinality, and byte/capacity budgets
  enforce tenant, principal, operation, family, and global scopes with isolation,
  reserved capacity, and backpressure; one scope cannot starve another;
- missing/stale/unavailable/overflowed/uncertain accounting, quota exhaustion,
  or capacity exhaustion fails before allocation and cannot convert conflict,
  missing history, or prior uncertainty into allow;
- crash at every claim/allocation/retention point reuses the same deterministic
  or atomically retained IDs, times, revisions, generations, and source bytes;
- duplicate current release after every local lifecycle transition and simulated
  Artifact/Lineage/conformance/Authority/key/work-order/activation/deployment
  revocation returns opaque denial, while historical inspection remains scoped;
  and
- no adapter, provider, Gateway, network, filesystem, node, or C03 call.

Stop conditions:

- in-memory tests are semantic evidence only and cannot claim persistence,
  admission publication, activation, current proof, or owner availability;
- no hidden local source-owner state is accepted as a live current fact; and
- no production composition while the applicable owner dependencies are unmet.

### Slice 4 - Repository adapter and acyclic Event/Evidence durability

Scope:

- implement the Registry-owned repository port in a composition adapter using
  generic `splendor-store` primitives, with no direct dependency from
  `splendor-gateway` to `splendor-store` and no Store semantic ownership;
- persist atomic claim/source/head/outbox transactions and separate immutable
  publication finalizations, plus the permanent declaration-binding index and
  atomic global revision fence, finite resource policy/counters/reservations/
  debt, isolation partitions, and semantic coalescing/non-reuse indexes; and
- coordinate authenticated Event/Evidence commits under RFC 0015 and accepted
  `FND-003`, retaining source -> acknowledgement -> finalization direction.

Tests and evidence:

- source canonical digest never contains its Event/Evidence receipt or
  finalization, every per-slot evidence digest is excluded from its own canonical
  source payload, and every receipt binds the exact already-fixed source digest;
- admission, activation, transition, each per-slot evidence record, and current
  observation use distinct source/outbox/receipt/finalization identities;
- process kill, power loss, disk full, commit/sync error, dropped acknowledgement,
  duplicate delivery, changed duplicate, backlog, and corruption at every claim,
  allocation, source, head, outbox, Event, Evidence, finalization, recheck, and
  response boundary;
- concurrent first bindings with changed same-revision bytes/fingerprints have
  one publisher-authorized unique-index winner and no unauthorized/losing
  binding, fence, command claim, admission source, or outbox, while crash recovery
  cannot orphan or replace the winning permanent binding or revision fence;
- an uncertain revocation/fence commit globally denies live use under that key
  until same-transaction recovery proves the retained result; fresh identities
  cannot infer absence or clear uncertainty;
- no success before effective durability/finalization and no caller downgrade;
- exact duplicate recovery preserves original IDs, bytes, generations, times,
  source digests, resource reservations/debt, and acknowledgements;
- restart, concurrent callers, lost response, fresh-ID flood, per-tenant/
  principal/operation isolation, quota-accounting uncertainty, downstream
  reservation loss, backlog, and exact capacity exhaustion preserve finite
  accounting and fail closed without unaccounted owner writes;
- retention/compaction/tombstone tests preserve non-reuse and charged cardinality/
  debt across restart; no payload removal resets quota or creates a fresh miss;
- Registry source/outbox and Event/Evidence inbox/commit atomicity are each
  truthful, with at-least-once delivery and no distributed exactly-once claim;
- contract tests prove the composition adapter maps generic Store failures but
  never decides admission, activation, transition, currentness, or retry; and
- source-owner races use accepted linearization or deny as unsupported.

Stop conditions:

- if Registry source state and outbox cannot share one local transaction, stop;
- if independent Event/Evidence publication lacks accepted `FND-003`, stop;
- if complete worst-case Registry/Event/Evidence obligations cannot be reserved
  under accepted owner accounting and compensated only with proof of absence,
  stop before durable claim;
- if any external current-status race cannot be linearized, keep live behavior
  unsupported and fail closed.

### Slice 5 - Live activation, per-slot evidence, and exact current query

Scope:

- compose Artifact, Lineage, declaration-publisher/registrar/activation/revision-
  revocation/quota-constraint Authority, Registry resource-policy/accounting,
  independent conformance, RFC 0015, and `DEP-005` owner ports only after their
  applicable contracts/runtimes exist;
- implement pre-lookup authorization, declaration-wide admission publication,
  narrowed activation, distinct per-slot evidence publication, exact current
  observation/finalization, every-release recheck, and restricted history; and
- expose no resolution, selection, invocation, endpoint detail, or broad
  discovery API.

Tests and evidence:

- exact active coordinate succeeds only after admission, activation, per-slot,
  and current-observation finalizations reach required durability and the exact
  permanent declaration binding, current publisher/publication authority,
  not-revoked global fence, and finite resource accounting validate;
- multi-slot publication cannot swap/reuse slot evidence or finalization;
- mutate independently tenant, installation/scope, admission, operation,
  revision, declaration, slot, generation, activation/deployment/gate/rollout,
  source/finalization receipt, signer/key/status, or audience and deny;
- admission-only/registrar authority, broader sibling-target authority, wrong
  target, and permission-laundered activation all deny;
- duplicate current release after stale, revoked, lifecycle quarantine, Artifact
  revocation, publisher/publication-authority/key revocation, Lineage anti-tamper
  change, conformance revocation, Authority/work-order revocation,
  activation/gate/rollout withdrawal, resource-accounting uncertainty, or
  Registry key revocation returns one opaque current denial and never the old
  current object;
- fresh-ID current queries and fresh admissions cannot bypass a changed permanent
  binding or globally revoked revision; stale fresh-admission succeeds only for
  the exact unchanged binding, a not-revoked fence, and complete fresh proofs;
- no latest, alias, endpoint, prefix, bare-digest, numeric, or fallback lookup;
- hidden/absent/wrong-tenant/scope/audience/conflict/corrupt/unavailable cases
  have equivalent outward body/status/header/timing behavior under the later
  daemon profile;
- quota/capacity denial, publisher mismatch/revocation, and first-writer conflict
  retain that same existence-safe outward profile;
- restricted views require separate scope and durable audit; and
- replay cannot issue, refresh, activate, or release a current proof.

Stop conditions:

- no live activation until narrowed activation authority plus exact
  `DEP-005`/gate/rollout evidence and race protocol exist;
- no external API until non-oracle behavior and generated parity are accepted and
  tested;
- no current success while any required owner fact is unavailable or uncertain;
  and
- no C03 adoption in this slice.

### Slice 6 - Exact RFC 0014 Authority and C03 adoption

Scope:

- preserve RFC 0014's exact closed eighteen-member proof bundle;
- Authority/C03 validate its explicit direct fields, then transitively
  dereference exact authenticated Registry/Authority source records and each
  record's own acyclic publication finalization/receipts; and
- perform the final Registry generation and all-current-facts recheck in the
  migration CAS without calling stable Gateway/provider/node paths.

Tests and evidence:

- exact 18-member parse accepts the canonical object and rejects a missing,
  null, duplicate, alias, reordered proof-bundle sequence, extension, or
  nineteenth member;
- direct equality is limited to frozen proof fields while Event/Evidence and
  publication receipts validate transitively; admission/per-slot/current
  receipts cannot substitute for one another, and permanent declaration binding
  plus current publisher/publication-authority, resource-accounting, and global
  revision-fence checks remain transitive owner validation without a nineteenth
  RFC 0014 field;
- one source entry binds one Authority record, one distinct per-slot Registry
  evidence source/finalization, one current observation, and one target entry;
- independently mutate implementation and projector Artifact identity, version,
  content digest, manifest digest, attestation identity, signer, key, and
  revocation status and deny;
- independently mutate Lineage producer, relation set, receipt, integrity,
  signing, and anti-tamper status and deny;
- independently mutate conformance suite/profile/version, environment,
  implementation/projector binding, result, issuer, trust, and revocation status
  and deny, including a recomputed but untrusted outer wrapper;
- every tenant/installation/admission/evidence/operation/revision/declaration/
  slot/generation/direct-field/transitive-receipt substitution denies;
- stale/revoked/quarantined or every named external revocation at preflight,
  current duplicate release, publication-finalization release, and final CAS
  wins with no target head;
- wrong/substituted/revoked/uncertain publisher authority or accounting/capacity
  state at preflight, current release, or final CAS wins with no target head;
- globally revoked-revision denial wins across fresh command/admission/evidence
  identities, while stale fresh-admission evidence is accepted only from the
  exact permanent binding, a not-revoked fence, and complete fresh proofs;
- acknowledgement loss, repository uncertainty, or final CAS conflict creates no
  live target head and recovery reuses exact identities; and
- stable 0.1 Gateway, trace, state, replay, and RFC 0013 fixtures remain
  unchanged with no provider/node/adapter/driver effect.

Stop conditions:

- no Authority/C03 implementation before its separately accepted evidence
  contract and all required owner runtimes/linearization paths exist;
- no mock, broad evidence row, database join, hidden side table, cached latest,
  or direct Store call satisfies owner evidence; and
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
- Artifact Registry, Lineage Service, conformance certification,
  declaration-publisher/registrar/activation/revision-revocation/quota-constraint
  Authority, Registry quota/config/accounting runtime, Event/State/Evidence
  runtime, `FND-003`, or compatibility/migration owner implementation;
- destination projector execution, Gateway consumption, provider access, node
  delivery, adapter migration, secret lease/use, C03 migration, or any external
  side effect;
- copied or renamed RFC 0013 grammar, a second canonical serializer, C03 fields
  in Registry evidence, a hidden side table, private latest lookup, adapter
  self-registration as proof, or direct Store/daemon ownership;
- cross-store atomicity, distributed exactly-once delivery, automatic retry of
  uncertain work, or reconstruction of missing currentness;
- numeric quota defaults, quota/config wire grammar, operator quota APIs,
  Event/Evidence accounting or retention semantics, or a claim that permanent
  storage is unlimited or operationally implemented;
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
blocker visibility, publisher/operation-namespace authority before permanent
binding, permanent RFC 0013 declaration binding and global terminal revision
fence, finite multi-scope resource admission/accounting and semantic coalescing,
declaration-wide non-live admission, separately authorized activation, distinct
per-slot C03 evidence, monotonic expected-generation CAS, irreversible lifecycle
versus recoverable command quarantine, acyclic source/Event/Evidence/finalization
ordering, every-release current rechecks, permanent idempotency/non-reuse, strict
RFC 0014 direct/transitive proof validation, architecture-safe repository
inversion, external-owner port non-ownership, non-oracle visibility, inspect-only
replay, compatibility with the stable adapter path, and all non-claims. Any
accepted implementation still requires its own code, tests,
retained validation, and dependency-safe review.
