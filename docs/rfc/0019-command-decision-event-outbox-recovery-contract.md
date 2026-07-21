# RFC 0019 - Command-Decision-Event, Outbox, and Recovery Contract

## Status and Binding

**Status:** Accepted planning contract

**Date:** 2026-07-21

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`6fd479fd6c9392466b63b41ae719a2a8d1e5870d442ce48cdd954c9e282fb55d`

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program/component:** `V2-FND-0 Foundations`

**Functional requirement bridge:** `FR-0.2-01`

**Catalog task:** `FND-003`

**Required dependency:** `FND-001`

**Plane:** cross-plane kernel transaction protocol

**Ownership posture:** behavior-free future internal contracts may live in
`splendor-types`; composition and invariant wiring belongs in `splendor-kernel`;
service crates retain semantic mutation ownership; `splendor-store` only
persists owner-validated records and enforces owner-supplied persistence
primitives

**0.1 compatibility inputs:** `FR-0.01-02` through `FR-0.01-05` and
`0.01-H2` trace/replay hardening behavior are preserved compatibility inputs,
not the active execution binding

**Gold targets:** `G02`, `G04`, `G15`, `G47`, `G75`, `G87`

**Gold status:** all remain `specified_not_implemented` / `not_exercised`; this
RFC changes no status

**Primitives strengthened:** action gateway, verifier, adapter, outcome, state
graph, trace store, and replay

**Normative compatibility inputs:**
[RFC 0015](0015-event-state-evidence-ownership-and-durability-contract.md),
[RFC 0016](0016-driver-registry-admission-lifecycle-evidence.md),
[RFC 0017](0017-authority-historical-secret-ref-evidence.md), and
[RFC 0018](0018-c03-foundation-grammar-profile.md)

This RFC is documentation-only and implementation-gating. It changes no runtime,
crate, package, dependency, persistence format, migration, daemon route,
TypeScript surface, Python surface, public schema, generated artifact, State,
Trace, Event, Evidence, Registry, Authority, audit, or C03 record. It does not
authorize implementation, close `FND-003`, complete any task or sprint, exercise
a gold case, or establish production readiness.

The names in this RFC are internal protocol roles and semantic operations. The
catalog names `CommandEnvelope`, `DecisionRecord`, and `MutationReceipt` map to
the internal role contracts below, but they are not Rust symbols, serialized
records, JSON fields, schema constants, public envelopes, daemon methods, SDK
values, or stable wire spellings. They may become internal Rust contracts only
in a separately authorized implementation slice. This RFC does not register
their public or wire form or create a universal replacement for an owner-defined
command, event, state, evidence, or receipt contract. Exact owner records remain
blocked on accepted owner-specific grammar annexes under RFC 0018 and `FND-001`.

## Summary

Splendor will use one owner-scoped command transaction protocol for privileged
mutations. The protocol fixes a command's canonical meaning, computes a
deterministic pre-effect decision, durably records every required intent and
pre-effect fact, dispatches at most one logical operation under one durable
idempotency identity, commits owner state and required event/trace evidence at
one declared durable commit point, and recovers the original operation after
crash or response loss.

The guarantee is exactly-once **logical owner commit**, not exactly-once network
delivery and not exactly-once external effect:

- one accepted command namespace binds permanently to one canonical command and
  one owner-scoped `DecisionKey`;
- one owner-scoped `DecisionKey` can advance that owner head and commit its one
  logical owner event at most once;
- exact duplicate delivery resumes or returns the original trusted result;
- changed bytes under the same command namespace fail closed as conflict;
- cross-owner delivery is at least once through a durable outbox and a
  destination inbox that permanently deduplicates its distinct destination key;
  a no-effect destination may commit terminal mutation in that inbox transaction,
  while an effectful destination commits only acceptance and then follows its own
  effect phases;
- an external effect has its own independent certainty lifecycle; and
- a timeout or crash around an external call is `effect_uncertain` unless the
  adapter contract can prove the exact result under the same durable operation
  key.

No process may infer atomicity across independent stores. A deployment must use
either one truthful same-store owner transaction or the explicit outbox/inbox
recovery mode in this RFC. If neither mode can satisfy the required commit,
ordering, receipt, and recovery laws, the operation is unsupported and fails
closed.

## Active Program and Compatibility Binding

This is an active `0.2/v2` planning contract in `V2-FND-0 Foundations` for
catalog task `FND-003`, dependent on `FND-001`. It defines the cross-plane
transaction protocol that later owner-specific implementation slices must obey.
It does not pull daemon, fleet, public schema, generated-client, or product
surfaces into the foundation task.

| Binding | Required effect of this RFC |
| --- | --- |
| `FR-0.2-01` | Establish the foundation transaction, failure, recovery, compatibility, and conformance posture without fake atomicity or docs-only completion. |
| `V2-FND-0 Foundations` | Own the cross-plane planning contract and keep owner-specific behavior in its service owner. |
| `FND-003` | Define command-decision-event ordering, outbox/inbox recovery, durability classes, and effect uncertainty without claiming catalog completion. |
| `FND-001` | Supply accepted canonical object/identity grammar and owner-annex inputs; unresolved bytes block implementation. |
| `FR-0.01-02` through `FR-0.01-05` | Preserve the 0.1 loop, gateway, State/Trace, durability, and safe replay behavior as compatibility obligations, not active functional requirements. |
| `0.01-H2` | Preserve trace/replay hardening evidence as a compatibility gate, not an active sprint assignment. |

The 0.1 line remains the compatibility baseline. The 0.2/v2 line is the active
execution line. Separately reviewed code and retained tests are still required
before any v2 behavior exists; this RFC does not change runtime behavior by
description.

## Terminology

**Owner** means the one semantic mutation owner for the state or lifecycle being
changed. A Store persists owner-approved facts but does not become their owner.

**Owner kind** means the closed owner identity selected by an accepted owner
contract, such as State, Event/Trace, Registry, Authority, or audit. This RFC
does not register its wire spelling.

**Command namespace** means the stable lookup tuple containing owner kind,
tenant, command family, authenticated actor or internal principal, owner service
audience, and the owner-specific command or action identity. It is independent
of a payload digest and prevents changed bytes from becoming a fresh command.

**Canonical owner bytes** means non-empty deterministic bytes produced by an
already accepted owner grammar, or opaque bytes supplied by an owner whose
accepted annex fixes their complete semantic projection and canonicalization.
This RFC never canonicalizes an unresolved owner object itself.

**Decision** means the deterministic owner and verifier conclusion fixed before
any external effect. A Decision may allow, deny, require intervention, or select
a bounded no-effect mutation. It is not adapter output.

**Logical owner event** means the one immutable owner mutation fact associated
with a `DecisionKey`. Required pre-effect and terminal stable trace events remain
separate ordered evidence and do not create a second owner mutation for that key.

**Durable commit point** means the exact owner-defined transaction and configured
storage barrier named by an owner receipt. Queue acceptance, process memory, a
log line, and an unacknowledged outbox row are not that commit point unless the
owner contract explicitly and truthfully defines the row itself as the committed
source fact.

**Trusted receipt** means an owner-validated, owner-bound internal handle proving
only that the named owner commit reached its declared durability. A serializable
receipt is untrusted input until the owner validates it and reconstructs that
handle.

**Exactly-once logical commit** means one semantic owner event, one state/head
advancement where applicable, and one original commit receipt for one accepted
`DecisionKey`, despite duplicate delivery or response loss.

**Effect certainty** means what is durably known about one external invocation.
It is independent from command commit, event durability, business correctness,
authority, and postcondition success.

**Command-acceptance acknowledgement** means the destination durably accepted
and deduplicated an effectful destination command and its source/effect intent.
It proves no adapter entry, terminal mutation, effect certainty, final owner
commit, or `MutationReceipt`.

**Terminal acknowledgement** means the destination's owner-validated response
after terminal finalization. For a no-effect destination it may be created in the
inbox/mutation transaction. For an effectful destination it exists only after
that destination completes Phases 3 through 8.

**Recovery/dispatch fence** means the current durable owner- and tenant-scoped
monotonic generation binding one dispatch claimant to one command attempt. It is
distinct from a Store writer fence and is checked by the durable entry-consumption
latch before provider handoff.

**Entry-consumption latch** means the durable one-winner owner CAS that moves one
exact attempt from `dispatch_claimed` to `entry_consumed`. It binds the same owner,
tenant, recovery/dispatch-fence generation, claimant, attempt, and claim domain as
stale-claim invalidation; consumes/latches the exact claim and private one-use
permit; and is the only state from which the bounded synchronous provider handoff
may begin. These labels are semantic states, not new wire enums or schemas.

## Normative Scope

This RFC defines only:

- internal roles for command context, deterministic decision, append intent,
  trusted receipt, effect observation, and owner-scoped coordination;
- exact internal BLAKE3 derivation laws over accepted canonical owner bytes;
- separate durable-command lifecycle, invocation-progress, and accepted
  effect-certainty laws;
- same-store and cross-owner outbox/inbox execution modes;
- expected-head, duplicate, append-conflict, and one-winner concurrency laws;
- crash recovery, no-gap scans, fencing, redispatch, and intervention rules;
- semantic error categories for later owner mapping;
- integration obligations for the local gateway, adapters, State, Trace, replay,
  Registry, Authority, and audit owners; and
- implementation acceptance evidence and no-go gates.

## Non-Goals and Explicit Non-Claims

This RFC does not define or authorize:

- an Event, State, Evidence, Registry, Authority, audit, or C03 owner schema;
- a universal public serializable command, decision, event, outbox, inbox,
  cursor, fence, effect, or receipt envelope;
- a public or generated dispatch-attempt identity, lineage, progress, or
  certainty schema;
- a new crate, package, dependency edge, Store engine, table, migration, daemon
  route, SDK, CLI, Python type, TypeScript type, JSON Schema, OpenAPI model, or
  generated artifact;
- cross-store ACID, distributed transactions, consensus, remote quorum, or
  exactly-once transport delivery;
- exactly-once external effects, automatic same-command retry after
  `effect_failed`, `effect_partial`, or `effect_uncertain`, or provider success
  inferred from a missing response;
- a generic authority, identity, historical-proof, currentness, trust,
  classification, redaction, resource-accounting, or owner-fact record;
- replacement of RFC 0015 Event/State/Evidence ownership, durability, receipt,
  outbox/inbox, effect-certainty, or replay rules;
- mutation of stable `TraceEvent`, `TraceEventKind`, `StateNode`, or existing
  state/trace bytes;
- a trace event rename or unsupported trace-causality field;
- broad migration from separate legacy State and Trace stores;
- task, issue, sprint, component, conformance, gold, release, durability, or
  production completion; or
- self-acceptance of this RFC.

## Core Invariants

### One owner and one command binding

1. One semantic mutation has exactly one owner.
2. The first accepted command namespace permanently binds the complete canonical
   command bytes, their `DecisionKey`, and the resulting disposition.
3. Exact duplicate bytes under that namespace resume or return only the original
   path and original trusted receipt/result.
4. Changed bytes, changed owner kind, changed tenant, changed actor, changed
   audience, or changed operation under that namespace are a permanent conflict.
5. Missing, corrupt, inaccessible, compacted, or uncertain command history is
   not a fresh miss. It requires recovery or intervention.

### Decision before effect

1. The complete Decision is deterministic from authenticated context, accepted
   canonical command bytes, expected durable base/head, current verifier inputs,
   and owner policy revision.
2. Decision construction performs no external effect.
3. Every dispatch attempt runs the complete final-live Gateway/verifier chain
   before its required-before-effect evidence is appended or a dispatch claim is
   committed.
4. An unavailable required verifier, owner, durability barrier, or currentness
   check denies, pauses, quarantines, or requests intervention.
5. No receipt, event coordinate, prior decision, or replay record recreates a
   Gateway permit or current authority.

### Durable intent before dispatch

1. The exact outbox/effect intent and operation idempotency key reach the
   required durability before adapter entry.
2. The complete final-live verifier chain returns an allow and a private
   non-reconstructible permit/session first.
3. While that same permit/session remains held, the attempt's ordered
   verification, Decision, and other required-before-effect evidence reaches RFC
   0015's effective durability.
4. Only after that append succeeds does an independent pre-call transaction
   commit the exact dispatch claim for the bounded attempt.
5. A second independent pre-call transaction durably CASes the exact claim from
   `dispatch_claimed` to `entry_consumed` while the same private permit remains
   live. The CAS rechecks every mutable dispatch-time verifier fact and the exact
   owner/tenant/fence/attempt/claim domain and consumes/latches that claim and
   permit before provider handoff.
6. The bounded synchronous adapter/provider handoff begins only after that CAS
   commits, outside every Store transaction. It begins immediately and cannot be
   deliberately delayed, queued, or requeued after the latch.
7. A dispatcher cannot change any command, Decision, target, parameters,
   authority context, operation key, or unresolved attempt while recovering
   work.
8. Denial, intervention, permit loss, or a proved pre-entry veto produces
   terminal `no_effect` evidence for that attempt and no adapter entry.
9. The entry-consumption CAS and the stale-claim/status-no-effect invalidation CAS
   compare and mutate the same exact unconsumed claim state. Exactly one may win.
   If invalidation wins, entry consumption fails and the stale worker makes zero
   adapter/provider calls. If entry consumption wins, invalidation fails and
   cannot authorize another attempt.
10. After `entry_consumed`, a provider status that currently reports no effect is
    insufficient because the latched handoff may still send. Only authoritative
    terminal result proof or an accepted atomic cancellation/non-entry protocol
    that makes the consumed dispatch token permanently unusable can establish
    `no_effect`; otherwise crash, pause, timeout, or ambiguity is
    `effect_uncertain`.
11. If the owner/adapter cannot enforce this durable latch, immediate bounded
    handoff, one-winner invalidation race, and terminal cancellation law, dispatch
    is unsupported and fails closed.

### Commit and visibility

1. The owner commits one logical owner event per owner-scoped `DecisionKey`.
2. Where state changes, immutable node persistence, required
   `state.committed`/`StateCommitted` evidence, and expected-head CAS are one
   supported same-store transaction or an explicit recoverable publication
   barrier. Two independent commits are never called atomic.
3. No response, read model, next tick, or duplicate result exposes a new State
   head before required State and Trace evidence is durable.
4. An accepted effect-certainty observation does not make the owner command
   complete. Required terminal evidence, state, and owner receipt still must
   commit.
5. An owner receipt proves only its named durable commit. It proves no business
   truth, identity, authority, historical fact, currentness, independent proof
   of `effect_succeeded`, or permission to perform another action.

### Recovery and replay

1. Recovery uses the original command namespace, canonical bytes,
   owner-scoped Decision key, owner logical-event identity, operation key,
   unresolved attempt identity/lineage, and receipts.
2. Recovery never silently rebases to the latest head, sequence, policy, or
   owner record.
3. This generic contract authorizes no automatic same-command continuation after
   `effect_failed`, `effect_partial`, or `effect_uncertain`. Such outcomes
   finalize truthfully or quarantine/request intervention.
4. Only durable trusted `no_effect`, plus a current-fence CAS disposition of the
   prior latch domain, may open the ordinary next bounded dispatch attempt. For an
   unconsumed claim the CAS invalidates every old claimant/claim. After
   `entry_consumed`, ordinary stale-claim invalidation is forbidden; only accepted
   authoritative terminal cancellation/non-entry proof that makes the consumed
   token unusable can supply the required disposition. Fresh authorization is
   still mandatory.
5. Replay is inspect/simulate/read-only by default and never claims a dispatch
   fence, drains an outbox, calls an adapter, or advances a live head.
6. Recovery is an owner mutation path with current authorization and fencing; it
   is not replay.

## Internal Role Contracts

The following are semantic role contracts. Exact fields and serialization remain
owner-annex work.

| FND-003 catalog name | Semantic internal role in this RFC |
| --- | --- |
| `CommandEnvelope` | The validated CommandContext-equivalent input and accepted canonical command bytes. It carries command identity and intent into one owner; it is not a universal wire envelope. |
| `DecisionRecord` | The deterministic pre-effect Decision and stable fingerprint. It records no adapter result and performs no effect. |
| `MutationReceipt` | The shared internal receipt semantic interface backed by one owner-specific trusted receipt. It proves only the named durable owner commit. |

These names may become internal Rust contracts only in a separately authorized
slice after their owner inputs are accepted. They do not authorize a public,
serialized, generated, daemon, SDK, Python, or TypeScript schema.

### CommandEnvelope and CommandContext semantic role

Every owner coordinator accepts a validated internal context that carries or
references all of these semantic facts:

- exact owner kind and owner service audience;
- authenticated tenant, principal, and actor or internal service principal;
- exact closed authority and resource scope applicable to the command;
- owner-specific stable command family and command identity;
- distinct caller-supplied idempotency identity where an accepted caller
  contract defines one, plus an owner-stable idempotency identity supplied or
  allocated independently, or derived only from an accepted owner-annex pre-`C`
  projection that excludes every `C`-derived digest or key;
- exact action identity for an action mutation;
- agent, run, tick, and trace correlation where applicable;
- complete causal parents and correlation references accepted by the owner;
- exact expected durable base, state head, event sequence, lifecycle generation,
  or explicit genesis as required by that owner;
- exact owner-kind binding for every expected base/head and target;
- the exact requested operation and immutable operation parameters or accepted
  owner reference;
- exact work-order, capability, approval, data-use, secret, and lease references
  supplied as immutable command semantics, including explicit absence;
- mutable current work-order, authority, verifier, policy, quota, safety,
  data-use, approval, secret, lease, capability, and adapter evaluation inputs
  required for the Decision or final-live attempt evaluation, kept separate from
  canonical command bytes;
- accepted canonical owner command bytes and the annex/profile that defines
  them; and
- required durability floor and audit attribution.

No absent expected head means "use latest." No correlation identity substitutes
for a command identity. Coincident ID bytes across identity types confer no
relationship.

This role is the semantic mapping of catalog `CommandEnvelope`. It must carry the
FND-003 principal, scope, idempotency, expected-head/base, causal-parent, and
requested-operation requirements without becoming a universal owner record.

### DecisionRecord and Decision semantic role

A Decision is an immutable deterministic pre-effect result. Its owner canonical
bytes must bind:

- the `DecisionKey` and complete command semantic digest;
- owner kind, tenant, command family, command/action identity, and expected
  durable base/head;
- the exact allow, deny, intervention, or bounded no-effect disposition;
- complete verifier result identities/revisions and closed reason codes;
- owner policy, durability, and compatibility revisions used;
- the proposed logical owner event and state/head intent, or explicit absence;
- every required pre-effect and terminal trace/event role;
- whether an external effect is required;
- when an effect is required, the complete immutable owner operation semantics
  from which `O` will later be canonicalized, but not `O` itself or any
  `DecisionFingerprint`- or `OperationIdempotencyKey`-derived value.

After those canonical Decision bytes are fixed, the owner derives and attaches
the stable Decision fingerprint below. The fingerprint is not a field or input
of `D` and canonical Decision bytes do not bind their own derived fingerprint.

Owner-assigned commit time, Store transaction identity, append sequence,
achieved durability, adapter result, invocation progress, accepted effect
certainty, final head, and receipts are not Decision inputs. No external effect
has occurred when the Decision exists.
This is the semantic mapping of catalog `DecisionRecord`; exact owner proof bytes
and persistence remain annex-owned.

### Dispatch-attempt semantic role

Every effectful command uses a finite owner-governed lineage of same-command
dispatch attempts. A dispatch-attempt identity is an internal semantic identity,
not a public ID type or serializable schema. Its owner annex must bind:

- exact owner kind, tenant, command namespace, owner-scoped `DecisionKey`,
  Decision fingerprint, and operation idempotency key;
- one owner-retained attempt identity, positive checked ordinal, and previous
  attempt identity or explicit first-attempt marker;
- exact recovery/dispatch-fence owner kind, tenant, owner scope, monotonic
  generation, and claimant identity under which the attempt was allocated;
- the owner-configured finite attempt ceiling fixed before source claim;
- exact final-live verifier evaluation identity/digest and ordered result set;
- ordered required-before-effect verification/Decision event identities and
  receipts for this attempt;
- private permit/session correlation bound to that exact owner/tenant fence and
  claimant, which cannot recreate or serialize the permit;
- dispatch-claim coordinate or explicit absence;
- durable entry-consumption coordinate and disposition, including explicit
  unconsumed, consumed, invalidated-before-consumption, or authoritatively
  cancelled-after-consumption semantics as applicable;
- independent invocation progress and accepted effect certainty; and
- terminal attempt evidence and causal link to any next attempt.

Recovery reuses an unresolved attempt. It may allocate the next bounded attempt
only after the prior attempt has durable trusted `no_effect` proof and the
current-fence CAS has durably invalidated every unconsumed prior claimant and
dispatch claim, or an accepted terminal cancellation has made an already consumed
dispatch token unusable, while keeping the same command bytes, Decision,
owner-scoped key, operation bytes, and operation idempotency key and obtaining
fresh current authorization. A deny,
`needs_intervention`, verifier unavailability, permit loss, or entry-time veto is
terminal `no_effect` evidence for that attempt only when no adapter entry/effect
is proved. Attempt exhaustion fails closed and requires intervention.

Per-attempt verification, denial, permit-loss, dispatch, observation, and
terminal evidence may have owner-governed stable event identities under this
bounded lineage. Those events never replace the command's one owner logical
event, create a second State advancement, or authorize another attempt.

### CommittedEvent and append intent

`CommittedEvent` is a semantic role for one immutable owner mutation fact. An
owner append intent supplies either an already accepted immutable typed payload
or opaque owner canonical bytes. It also binds:

- stable owner-assigned or owner-validated event identity;
- exact `DecisionKey` and Decision fingerprint;
- owner kind, tenant, owner partition, command/action identity, and command
  semantic digest;
- expected sequence/base/head and previous integrity where the owner requires
  them;
- immutable payload or payload reference;
- causal parents and correlation references using current accepted fields;
- required durability class; and
- one logical event role.

The same `DecisionKey` may have required pre-effect and terminal trace evidence,
but it has only one logical owner mutation event. An owner annex must distinguish
the logical event from trace evidence without introducing duplicate head
advancement. The same event identity or `(DecisionKey, logical-event-role)` with
changed bytes is a permanent append conflict.

### MutationReceipt and owner trusted receipt semantic role

A successful owner commit returns a sealed trusted receipt handle. The owner may
later define a serializable receipt only through its accepted annex. Validation
of either form must bind at least:

- exact owner kind, owner identity/revision, tenant, scope, and audience;
- command namespace, owner-scoped `DecisionKey`, command semantic digest, and
  Decision fingerprint; a cross-owner inbox/acknowledgement additionally binds
  both `SourceDecisionKey` and `DestinationDecisionKey`, exact acknowledgement
  kind, and declared source barrier causally;
- exactly one attempted or no-attempt semantic disposition under the conditional
  presence law below;
- previous and committed durable base/head or explicit no-head mutation;
- logical event identity/digest and required trace/event receipt references;
- state or artifact reference and digest where applicable;
- effective and achieved durability plus backend policy revision;
- owner commit revision/time; and
- receipt integrity or trusted-wrapper binding.

An attempted receipt binds the exact bounded attempt lineage, recovery/dispatch-
fence owner/tenant scope and generation, claimant, dispatch-claim coordinate or
explicit attempted-before-claim disposition, entry-consumption coordinate and
disposition, invocation progress, accepted effect certainty, any terminal
cancellation or prior-claim invalidation, and the trusted bounded sub-effect
inventory reference when partial.

A no-attempt receipt binds canonical explicit `no_attempt` and
`no_dispatch_fence` dispositions. Attempt lineage, invocation progress, fence,
claimant, claim, entry-consumption, and cancellation fields are absent and
forbidden; the command outcome remains separately bound and no attempted effect
certainty is synthesized. `no_attempt` and `no_dispatch_fence` are semantic labels,
not new wire enums or schemas. Attempted/no-attempt substitution or mixed presence
is a receipt-validation failure.

The receipt does not prove the Decision was wise, the underlying business fact
is true, the actor remains authorized, a historical record is current, an
external effect independently succeeded beyond the bound trusted observation, or
a caller may execute anything. Accepted effect certainty requires its separate
trusted proof and state.

An effectful destination's command-acceptance acknowledgement is not a
`MutationReceipt` and cannot be validated or consumed as one. Only its later
terminal acknowledgement may carry the destination's finalized owner receipt.

Catalog `MutationReceipt` maps to a shared internal semantic interface that may
be consumed by artifact, workload, driver, data, eval, training, change,
deployment, and incident services. That interface exposes only the common
validated meaning needed for composition:

- owner kind, tenant/scope, command family, and owner-scoped `DecisionKey`
  binding;
- original or duplicate disposition;
- the validated conditional attempted/no-attempt disposition, exposing attempt,
  fence, claim, entry-consumption, progress, certainty, and inventory semantics
  only for an attempted receipt;
- previous and committed owner coordinate or explicit no-head mutation;
- logical event and required trace/evidence receipt references;
- effective and achieved durability;
- separate command disposition and applicable effect certainty, with no attempted
  effect certainty synthesized for a no-attempt receipt; and
- a sealed owner-specific trusted receipt handle or validated owner reference.

The shared interface does not normalize, copy, or reinterpret owner proof bytes;
select an owner transition; validate owner-specific business truth; or serialize
as one cross-service public record. Each consuming service validates and retains
its own transition semantics and accepted owner-specific proof. A future internal
Rust interface requires a separately authorized slice and cannot be generated or
exposed as a daemon/SDK contract from this RFC.

### Owner-scoped durable coordinator

The design-level coordinator exposes owner-scoped semantic operations equivalent
to:

```text
inspect_command_namespace(context, owner_command_bytes)
prepare_decision(context, owner_command_bytes)
commit_same_store(prepared_decision, owner_append_and_state_intents)
commit_source_and_outbox(prepared_decision, owner_outbox_intents)
begin_or_resume_dispatch_attempt(decision_key, operation_key, prior_attempt, recovery_fence)
append_attempt_pre_effect_evidence(attempt, final_live_evaluation, permit_ref, recovery_fence)
record_dispatch_claim(attempt, operation_key, current_gateway_permit_ref, recovery_fence)
consume_adapter_entry_latch(attempt, claim, operation_key, current_gateway_permit_ref, recovery_fence)
invalidate_unconsumed_dispatch_claim(attempt, claim, recovery_fence, trusted_no_effect_proof)
terminally_cancel_consumed_entry(attempt, claim, consumed_entry, trusted_cancellation_proof)
record_effect_observation(attempt, operation_key, trusted_effect_proof)
finalize_owner_commit(decision_key, expected_base, append_and_state_intents)
lookup_original_result(command_namespace, decision_key)
scan_recovery(owner_scope, recovery_fence, cursor, high_water, limit)
advance_recovery_progress(recovery_fence, expected_cursor, accounted_work)
```

This is not a public trait or wire API. A later implementation may use different
symbols, but it must preserve these separations:

- owner application code decides command and transition legality;
- the Gateway and verifiers decide whether effect dispatch is permitted;
- the adapter owns provider-specific invocation and trusted effect proof;
- Store adapters supply transactions, uniqueness, CAS, durability, and scans;
- Store adapters do not decide replay, retries, authority, transition legality,
  or whether an uncertain effect is safe to repeat; and
- the coordinator never accepts a caller-built committed event or trusted
  receipt.

## Exact Derivation Laws

### Acyclic construction order

Every owner annex must define and implement this exact acyclic order:

1. Independently assign or validate the command namespace, caller idempotency
   identity, and owner idempotency identity. The owner identity must be supplied
   or allocated independently, or derived from an owner-annex pre-`C` projection
   that excludes `C` and every `C`-derived digest or key.
2. Canonicalize `C` only after those identities are fixed. `C` excludes
   `CommandSemanticDigest`, `DecisionKey`, `DecisionFingerprint`,
   `OperationIdempotencyKey`, and every value derived from them.
3. Derive `CommandSemanticDigest` and `DecisionKey` independently from the final
   `C`.
4. Canonicalize `D` with the exact `DecisionKey` and command semantic digest.
   `D` excludes `DecisionFingerprint`, `OperationIdempotencyKey`, and every value
   derived from either. Because `O` binds `DecisionFingerprint`, `D` also excludes
   `O` bytes and instead binds the complete immutable pre-`O` operation semantics.
   Derive and attach `DecisionFingerprint` only after `D` is final.
5. Canonicalize `O` with the exact `DecisionKey` and
   `DecisionFingerprint`. `O` excludes `OperationIdempotencyKey` and every value
   derived from it. Derive and attach `OperationIdempotencyKey` only after `O` is
   final.

No later digest, key, canonical byte string, receipt, or Store-assigned value may
feed an earlier step. Every owner annex must include an explicit dependency-graph
cycle check and fixtures proving that no direct, indirect, optional-field, or
default-value path violates this order.

### Canonical-byte precondition

Let `C` be the complete non-empty canonical owner command bytes produced at step
2. Let `D` be the complete non-empty canonical owner Decision bytes produced at
step 4, including `DecisionKey` but excluding `DecisionFingerprint` and
`OperationIdempotencyKey`. Let `O` be the complete non-empty canonical owner
operation bytes produced at step 5 for one external effect, including
`DecisionKey` and `DecisionFingerprint` but excluding
`OperationIdempotencyKey`.

`C`, `D`, and `O` are valid inputs only when an accepted owner annex fixes their
complete semantic projection and canonicalization, or when an already accepted
contract supplies those exact opaque canonical bytes. They must each include
exact owner kind and tenant.

`C` must include every immutable command semantic and all presence/absence
distinctions:

- owner kind and owner service audience;
- tenant, principal, and actor or internal service principal;
- exact closed requested scope;
- command family and command identity;
- caller idempotency identity and owner idempotency identity, each with explicit
  presence or absence according to the accepted owner contract;
- action identity;
- semantic agent, run, and tick correlation where applicable;
- complete causal parents;
- exact expected durable base, State head, Event sequence, lifecycle generation,
  or explicit genesis required by the owner;
- exact owner-bound target;
- requested operation and immutable parameters or accepted immutable reference;
- work-order, capability, approval, data-use, secret, and lease references
  supplied by the command, each with exact presence or absence;
- caller-requested durability floor and audit attribution; and
- every other owner-annex immutable semantic whose presence or absence changes
  the command.

`C` contains none of `CommandSemanticDigest`, `DecisionKey`,
`DecisionFingerprint`, `OperationIdempotencyKey`, or any value derived from
them. An owner idempotency identity derived from `C`, from a digest/key of `C`,
or from any later `D`/`O` value is cyclic and invalid.

Mutable current verifier status, revision, revocation state, evaluation result,
trusted time, quota balance, policy status, secret/lease status, or adapter
availability is not part of `C`. Those values are Decision/evaluation inputs and
are bound in `D` or in the specific dispatch attempt's final-live evaluation
evidence. This separation keeps the command key stable while requiring fresh
current authorization at every attempt. `D` and `O` must repeat the owner-kind
and tenant binding and bind the owner-scoped `DecisionKey` they consume. `D`
binds the complete pre-`O` operation semantics; `O` then binds those same
semantics plus the final `DecisionFingerprint` without feeding its bytes back
into `D`.

The later canonical-command acceptance suite must hold all other values constant
and independently mutate each category above: owner kind/audience;
tenant/principal/actor; requested scope; command family/identity; caller
idempotency presence/value; owner idempotency presence/value; action identity;
agent/run/tick semantic correlation; each causal parent and its presence; each
expected base/head/sequence/generation/genesis value and presence; owner-bound
target; operation; immutable parameter/reference and presence; each supplied
work-order/capability/approval/data-use/secret/lease reference and presence;
requested durability; audit attribution; and every owner-annex optional semantic.
Each change must change `C`, its command semantic digest, and its owner-scoped
Decision key. Independently changing only a mutable current evaluation fact must
leave `C` and that key unchanged while changing the applicable Decision or
attempt-evaluation evidence.

This RFC does not define field names or a fallback encoding for `C`, `D`, or
`O`. If those bytes are unresolved, the owner implementation is blocked. It must
not use debug text, ad hoc JSON, database concatenation, log text, protobuf wire
order, a generic map, or a private serializer as a substitute. It also must not
resolve a dependency cycle by omitting, zeroing, defaulting, or post-hoc mutating
a derived field.

All digests below use unkeyed standard BLAKE3 with exactly 32 output bytes. The
domain text is exact ASCII/UTF-8, followed by one `0x00`. `raw32(X)` means the 32
digest bytes, not hexadecimal or the `blake3:` wire form.

### Command semantic digest

```text
CommandSemanticDigest = BLAKE3-256(
  UTF8("splendor.fnd003.command-semantics.v1") || 0x00 || C
)
```

### DecisionKey

```text
DecisionKey = BLAKE3-256(
  UTF8("splendor.fnd003.decision-key.v1") || 0x00 || C
)
```

The command semantic digest and `DecisionKey` intentionally use distinct domains
even though both consume `C`. They are distinct internal roles and cannot be
substituted.

For cross-owner publication, the generic derivation is applied independently to
each owner's accepted canonical bytes:

```text
SourceDecisionKey = DecisionKey(C_source)
DestinationDecisionKey = DecisionKey(C_destination)
```

`C_source` includes the source owner kind/audience and source command semantics.
`C_destination` includes the destination owner kind/audience and destination
command semantics. Therefore the source and destination keys are semantically
distinct even if a cryptographic collision made their raw bytes coincide; such a
collision is an integrity conflict. These names are internal roles, not public
nominal types or wire fields.

The source may deterministically compute the expected destination key only from
the exact accepted destination canonical bytes and this formula. Otherwise it
must receive that key through the accepted destination admission contract before
source claim. The destination always recomputes and validates its own key and
runs its own Decision; it never adopts `SourceDecisionKey` as its own.

### Decision fingerprint

```text
DecisionFingerprint = BLAKE3-256(
  UTF8("splendor.fnd003.decision-fingerprint.v1") || 0x00 ||
  raw32(DecisionKey) || 0x00 || D
)
```

### Operation idempotency key

```text
OperationIdempotencyKey = BLAKE3-256(
  UTF8("splendor.fnd003.operation-idempotency-key.v1") || 0x00 ||
  raw32(DecisionKey) || 0x00 ||
  raw32(DecisionFingerprint) || 0x00 || O
)
```

These domain strings and formulas are internal protocol laws, not registration
of public nominal digest types or RFC 0018 owner record schemas. A future owner
annex must decide how, if at all, the values are represented in that owner's
closed record.

### Collision and comparison law

Digest equality never replaces canonical-byte equality for a retained command.
The owner retains or can integrity-verify the complete accepted `C`, `D`, and
`O` under its durability/retention contract. If a namespace or digest resolves
to changed canonical bytes, the result is a permanent command or integrity
conflict, not a duplicate. A collision suspicion quarantines the owner scope and
requires security intervention. A fresh identity cannot bypass that state.

## Separate Lifecycle and Certainty Tracks

The durable command lifecycle, per-attempt invocation progress, and accepted
effect-certainty outcome are independent semantic tracks. No track proves either
other track.

### Durable command lifecycle

The following are semantic states, not a wire enum:

| State | Meaning |
| --- | --- |
| `unclaimed` | No durable owner command binding is known. Absence is usable only when the owner can prove it, not when history is unavailable. |
| `prepared` | A deterministic in-memory Decision exists. No durable claim, visibility, or effect permission follows. |
| `source_committed` | The command namespace, canonical bytes, Decision, logical source intent, and required owner-local outbox intents reached the owner-defined source durability. |
| `awaiting_effect` | Required-before-effect acknowledgements are valid and the command may seek a fresh Gateway dispatch permit. Invocation progress and accepted effect certainty remain separate. |
| `awaiting_finalization` | The command has a durable no-effect result or a durable trusted effect observation, but terminal owner state/event/trace commit is not yet complete. |
| `committed` | The one logical owner event, state/head change where applicable, required terminal evidence, and original trusted receipt reached the owner commit point. |
| `recovery_required` | Commit, publication, receipt, or effect disposition cannot be safely advanced automatically under current proof. External success is not implied. |

Allowed progress is forward for the original command only:

```text
unclaimed -> prepared -> source_committed
source_committed -> awaiting_effect | awaiting_finalization
awaiting_effect -> awaiting_finalization
awaiting_finalization -> committed
any durable uncertainty -> recovery_required
recovery_required -> the one proven original state | recovery_required
```

A no-effect mutation may atomically move from `prepared` to `committed`. A denial
or intervention Decision can likewise commit its one terminal result without an
effect. `recovery_required` is private fail-closed state and cannot be returned as
success.

### Invocation progress

Invocation progress records protocol advancement for one bounded dispatch
attempt. It is not effect certainty. These are semantic states, not a wire enum:

| Progress | Meaning |
| --- | --- |
| `not_started` | This attempt has no durable dispatch claim. It may already have terminal `no_effect` evidence from denial, intervention, permit loss, or an entry-time veto. |
| `dispatch_claimed` | The independent pre-call dispatch-claim transaction committed for the exact attempt and operation key. It does not prove adapter entry or any effect result. |
| `entry_consumed` | A separate durable CAS consumed/latched the exact claim and private one-use permit in the owner/tenant/fence/attempt/claim domain. Exactly one bounded synchronous handoff may now proceed; effect certainty remains absent/pending. |
| `observation_recorded` | A post-call or terminal-no-effect transaction durably recorded one accepted RFC 0015 effect-certainty outcome and its trusted proof. |
| `finalized` | Final owner state/event/trace and the original MutationReceipt committed. This progress state does not change the accepted effect certainty. |

The permitted progress is:

```text
not_started -> observation_recorded -> finalized
not_started -> dispatch_claimed
dispatch_claimed -- winning invalidation CAS; no handoff --> observation_recorded -> finalized
not_started -> dispatch_claimed -> entry_consumed -> observation_recorded -> finalized
```

Before `observation_recorded`, accepted effect certainty is absent/pending. A
crash before `entry_consumed` makes zero provider calls and may become
`no_effect` only through the winning unconsumed-claim invalidation CAS. A crash,
pause, timeout, or ambiguity after `entry_consumed` requires recovery to record
`effect_uncertain` unless the accepted provider/idempotency protocol proves an
exact terminal result or atomically cancels the consumed dispatch token so no
late send can occur. A current provider status of no effect is not that proof.
Progress never substitutes for the terminal observation.

### Accepted effect certainty

The closed effect-certainty outcomes are imported from RFC 0015 and remain
independent from invocation progress:

| Certainty | Required meaning |
| --- | --- |
| `no_effect` | Trusted proof establishes that adapter entry did not occur or that no effect occurred. This is the only certainty that may permit a later bounded attempt after fresh authorization and the required latch-domain disposition: current-fence invalidation of every unconsumed prior claimant/claim, or authoritative terminal cancellation/non-entry proof that makes an already consumed token unusable. |
| `effect_succeeded` | Trusted bounded proof establishes that the exact operation succeeded under the same operation key. It never repeats. |
| `effect_failed` | Trusted bounded proof establishes that the exact operation failed and that no successful or uncertain sub-effect is hidden. |
| `effect_partial` | A trusted complete bounded inventory contains at least one successful sub-effect and at least one failed or uncertain sub-effect. Successful sub-effects never repeat. |
| `effect_uncertain` | Call entry, result, or the complete sub-effect inventory cannot be proved after timeout, process loss, malformed/missing proof, provider ambiguity, or unavailable protected status lookup. Blind retry is forbidden. |

`effect_partial` carries an ordered trusted inventory of `1..=256` sub-effects;
an owner or driver profile may lower but never raise that ceiling. Every item
binds its sub-effect identity, parent operation and operation idempotency key,
exact target and operation, certainty `succeeded | failed | uncertain`, declared
reversibility and compensation references where applicable, trusted
receipt/proof, and causal evidence. The inventory is complete for the invocation
under the accepted driver contract.

A top-level `effect_failed` cannot hide a successful or uncertain sub-effect. An
untrusted, incomplete, over-bound, duplicate, reordered where order is semantic,
or internally inconsistent inventory yields `effect_uncertain`, not
`effect_failed` or a narrowed partial result. `effect_partial` never means the
successful subset may repeat.

This generic FND-003 contract authorizes no whole-operation or sub-effect
continuation after accepted `effect_failed`, `effect_partial`, or
`effect_uncertain`. The owner finalizes the truthful outcome when terminal facts
can be made durable, or quarantines and requests intervention. The generic
dispatch-attempt lineage cannot reinterpret any of those outcomes as permission
for another call.

A later owner/driver annex may authorize such continuation only through a
separately accepted finite **sub-effect recovery-attempt lineage**. That annex
must preserve the original command, invocation, operation idempotency key, and
sub-effect bindings; require fresh complete final-live verification, ordered
required-before-effect evidence, an independent dispatch claim, and a durable
same-domain entry-consumption latch for every recovery attempt; reserve complete
worst-case capacity; define both entry-versus-invalidation orderings,
authoritative consumed-token cancellation, and crash/fence-loss recovery at every
boundary; accumulate immutable receipts and complete inventories without
rewriting prior observations; and prove that no successful sub-effect can repeat.
The effect label alone never selects or authorizes that lineage. Until the annex
exists, continuation is unsupported.

Compensation is a distinct separately authorized command/operation with its own
Decision and evidence. It cannot erase, rewrite, or fake rollback of the original
failed, partial, uncertain, or successful effect.

Any intentional repetition of an irreversible whole effect requires distinct
explicit authorization and a new command with a new owner-scoped Decision key;
it is not a retry of the original command and cannot reuse its operation key as
permission.

Once a terminal `effect_uncertain` observation is committed, it is not rewritten
by assumption. Any later accepted status evidence is a separate owner-governed
fact under an annex and cannot erase the original uncertainty or authorize a new
attempt unless it durably proves `no_effect` for the complete prior attempt.

Command `committed` does not imply `effect_succeeded`: denied, `no_effect`,
`effect_failed`, `effect_partial`, and `effect_uncertain` outcomes may be
truthfully committed. Likewise,
`effect_succeeded` does not imply command `committed`: terminal event/state/trace
durability may still be pending.

## Protocol Phases

### Phase 0 - Authenticate and admit

Before command-history lookup that could reveal existence, the owner validates
authenticated principal, tenant, audience, command family, work order, endpoint
or internal scope, request bounds, and current revocation status. The owner then
independently assigns or validates the exact command namespace and caller/owner
idempotency identities under the acyclic construction order below.

An exact existing binding returns the original path only after tenant, owner,
audience, and receipt validation. A changed binding fails closed. Unavailable
history yields `recovery_required`, never a new claim.

Before any source claim, the owner also obtains conservative accepted resource
reservation/accounting for the worst-case command history, source/outbox,
destination inbox/receipt admission where applicable, all bounded attempts and
their evidence, recovery/dispatch-fence records, dispatch claim,
entry-consumption/cancellation dispositions, effect observation including maximum
partial inventory, finalization,
unresolved/quarantine history, permanent non-reuse, and future tombstone debt.
Cross-owner source claim additionally requires an
owner-authenticated destination capacity admission for the exact destination
command or the operation is unsupported. Reservation is not destination command
acceptance, authority, or mutation success.

### Phase 1 - Prepare the deterministic Decision

The owner follows the exact acyclic derivation order: canonicalize `C`; derive
the command semantic digest and owner-scoped `DecisionKey`; run the Decision-time
verifier evaluation; canonicalize `D`; derive and attach the Decision
fingerprint; then, where an effect is required, canonicalize `O` and derive and
attach its operation idempotency key. It also fixes the exact expected durable
base/head, owner kind, action identity, causal references, owner policy, logical
event intent, state intent, and required trace roles. This evaluation does not
replace the later complete final-live attempt evaluation.

Preparation performs no adapter call, no external lookup not already governed by
an accepted read port, and no durable mutation. Repeating preparation over the
same accepted inputs produces identical bytes and keys.

### Phase 2 - Commit source and required outbox intent

For an effectful or cross-owner command, one owner transaction commits:

- the permanent command namespace and canonical-byte binding;
- the deterministic Decision and fingerprint;
- the fixed logical source or append intent;
- every required owner-local outbox intent;
- invocation progress `not_started` with effect certainty absent/pending where
  applicable;
- complete accepted resource reservations, retained debt, and recovery
  references required by the owner; and
- the bounded attempt ceiling and operation key, but no dispatch attempt result,
  final-live allow, permit, dispatch claim, or effect observation.

If source state and its outbox cannot share one owner-local atomic transaction,
the mode is unsupported and fails before source commit. No dispatcher may infer
intent from a Decision that exists only in memory.

When required pre-effect evidence belongs to another owner, source commit alone
does not open dispatch. The outbox/inbox path must return and validate the exact
acknowledgement kind declared by that source barrier. A command-acceptance
acknowledgement can satisfy only an explicitly admission-specific barrier; it
cannot prove required evidence was appended, an effect occurred, a destination
mutation finalized, or a terminal result exists.

### Phase 3 - Final-live verification and attempt evidence

The dispatcher begins or resumes the one unresolved bounded attempt only under
the current durable recovery/dispatch-fence generation for the exact owner,
tenant, owner scope, command, attempt, and claimant, then runs the complete
final-live Gateway/verifier chain. The evaluation includes every mutable
dispatch-time authority, work-order, lease, approval, quota, policy, data-use,
secret, safety, capability, adapter, and fence fact, including current revocation
generations, owner status, trusted time, permit expiry, and claimant ownership.
Required unavailability is non-allowing.

On allow, Gateway retains one private non-serializable permit/session bound to
that exact owner/tenant recovery/dispatch-fence generation and claimant. While
that same permit remains held, the coordinator durably appends this attempt's ordered
`verification.started`, final verifier results, Decision/allow evidence, and all
other required-before-effect evidence. Cross-owner Event/Evidence publication
must return and validate its durable acknowledgement while the permit remains
held. No receipt recreates the permit.

Those names identify semantic evidence roles, not permission to duplicate or
extend the stable 0.1 `TraceEvent` line. The compatibility projection emits the
existing stable tick events, IDs, bytes, and order exactly once as required by
RFC 0015. Additional bounded-attempt facts, when needed, use a separately
accepted owner-native Event/Evidence profile causally linked to that stable line;
they do not inject attempt fields into stable payloads or repeat stable events.
Until an owner annex can prove that mapping, an attempt requiring additional
evidence is unsupported.

On deny, intervention, verifier unavailability, append failure/uncertainty, or
permit loss/expiry before claim, the adapter is not entered. The owner appends
ordered terminal no-effect evidence for that attempt and records accepted
certainty `no_effect` only when it can prove no entry/effect. Otherwise the
attempt remains recovery-required. A later attempt is possible only from durable
`no_effect`, the required prior latch-domain disposition, the same command/
Decision/operation key, finite remaining attempt budget, and fresh authorization.
That disposition is current-fence invalidation of every unconsumed old
claimant/claim, or authoritative terminal cancellation that makes an already
consumed dispatch token unusable.

### Phase 4 - Commit the independent pre-call dispatch claim

After required-before-effect evidence is durable and while the same permit is
still held, a separate Store transaction CASes this attempt's invocation progress
from `not_started` to `dispatch_claimed`. The claim binds owner kind, tenant,
owner-scoped Decision key, attempt identity/lineage, operation idempotency key,
adapter/driver revision, target/operation digest, required evidence receipts,
permit/session correlation, resource reservation, recovery/dispatch-fence owner
scope and generation, claimant identity, and dispatch fence. The CAS succeeds
only if that claimant still owns the current owner/tenant fence generation.

This transaction contains no provider call and no post-call observation. Claim
failure or uncertainty causes no adapter entry. The claim is not a reusable
permit and cannot authorize delayed invocation.

### Phase 5 - Consume the durable entry latch and invoke

Immediately after the dispatch claim commits and while the same private
permit/session remains live, a second independent Store transaction CASes
invocation progress from `dispatch_claimed` to `entry_consumed`. This CAS is the
adapter-entry linearization point. It validates and binds the exact owner, tenant,
owner scope, recovery/dispatch-fence generation, claimant, attempt, dispatch claim,
operation key, and permit correlation; atomically consumes/latches that exact
claim and private one-use permit; and rechecks every mutable final-live verifier
fact listed in Phase 3. The durable latch does not serialize or recreate the
private permit.

The entry-consumption CAS and a current-fence stale-claim/status-no-effect
invalidation CAS both compare the same exact `dispatch_claimed`, unconsumed state.
Exactly one can commit. If invalidation commits first, the entry CAS fails and A
makes zero adapter/provider calls. If entry consumption commits first, the
invalidation CAS fails: B cannot invalidate the claim, accept a current
status-derived no-effect result as permission, or open another attempt.

After `entry_consumed`, A owns exactly one bounded synchronous handoff. The
adapter/provider handoff begins immediately after the latch commit and outside
every Store transaction. It cannot be deliberately delayed, queued, requeued, or
reconstructed by recovery. A crash, pause, timeout, or lost response before the
observation commits is `effect_uncertain` unless an accepted provider/idempotency
protocol terminally proves the exact result or atomically cancels the consumed
dispatch token so it is permanently unusable and no late send can occur. A
provider status that merely reports no effect at the time of lookup is
insufficient after entry consumption because A may still send later.

If any latch fact changed, the permit expired, revocation won, the claimant lost
before consumption, or the durable CAS cannot complete, no handoff begins. If the
owner/adapter cannot enforce this same-domain one-winner latch, immediate bounded
handoff, and authoritative cancellation protocol, dispatch is unsupported and
fails closed.

### Phase 6 - Commit the post-call effect observation

The adapter returns a bounded trusted receipt or immutable proof reference that
the owner validates against owner kind, tenant, owner-scoped Decision key,
attempt identity, operation key, adapter identity/revision, exact operation,
target, parameters digest, and complete sub-effect inventory. A process-local
result is insufficient.

A distinct post-call transaction records invocation progress
`observation_recorded` and exactly one accepted certainty: `no_effect`,
`effect_succeeded`, `effect_failed`, `effect_partial`, or `effect_uncertain`.
`effect_partial` stores or immutably references the complete trusted bounded
ordered inventory. Failure/uncertainty cannot hide successful or uncertain
sub-effects. Timeout, malformed receipt, incomplete/untrusted inventory,
receipt-validation failure, protected status unavailability, or crash before a
different certainty is proved records `effect_uncertain`.

Observation may share the following final owner transaction only when one
truthful post-call Store transaction can atomically persist the complete trusted
observation, logical event, terminal evidence, State/head mutation, and receipt.
It never shares a transaction across provider I/O or with the pre-call claim.

### Phase 7 - Finalize owner state, event, trace, and outcome

Using the original expected durable base/head, the owner validates that no
conflicting winner has advanced the head or event identity. It then performs the
one owner commit:

- commit the immutable logical owner event;
- append required terminal trace/event evidence;
- persist the outcome, attempt lineage, invocation progress, accepted effect
  certainty, and trusted proof/inventory reference where applicable;
- persist the immutable state node or artifact reference where applicable;
- CAS the owner head exactly once; and
- create the original trusted commit receipt.

For State, RFC 0015's node, required `StateCommitted`, and head-CAS ordering is
mandatory. Append or CAS conflict does not silently rebase. An accepted
`effect_succeeded` observation plus finalization conflict remains truthful
effect evidence with command recovery
required; it is not rewritten as no effect or safely retried.

### Phase 8 - Release response

The response exposes a new head or terminal command result only after required
durability and receipt validation. A duplicate repeats current read/visibility
checks and returns the original receipt/result unchanged. It allocates no new
owner logical event, state node, head revision, timestamp, operation key, or
effect. Owner-governed per-attempt evidence is permitted only while recovering
an unresolved attempt or after a prior attempt is durably `no_effect` under the
bounded lineage rules; it is not duplicate final-result allocation.

## Same-Store Atomic Mode

Same-store mode is allowed only when every owner whose fact must be atomic can
participate in one real transaction boundary while retaining its own semantics.
The common Store supplies transaction, uniqueness, CAS, ordering, integrity, and
durability primitives. It does not decide owner policy.

### No-effect transaction

For a denied, intervention, read-only recorded outcome, or owner-local no-effect
mutation, one transaction may commit command binding, Decision, logical event,
state node/head, required trace, outcome, idempotency history, and receipt. Any
failure commits none of the visible facts. Because no dispatch attempt exists,
the receipt uses canonical semantic dispositions `no_attempt` and
`no_dispatch_fence`; attempt, progress, fence, claimant, claim, entry-consumption,
and cancellation fields are absent and forbidden.

### Effectful transaction sequence

No database transaction can include an external effect atomically. Effectful
same-store mode uses these distinct boundaries in order:

1. source/intent transaction: command/Decision binding, durable outbox/effect
   intent, invocation progress `not_started`, reservations/debt,
   recovery/dispatch-fence obligation, and attempt ceiling;
2. final-live evaluation followed by a durable ordered required-before-effect
   append while the owner/tenant/fence-bound private permit remains held;
3. independent pre-call dispatch-claim transaction: progress becomes
   `dispatch_claimed` for the exact attempt;
4. independent entry-consumption transaction: the exact same-domain claim and
   one-use permit are durably latched and progress becomes `entry_consumed`;
5. immediate bounded synchronous adapter/provider handoff and external call,
   outside every Store transaction;
6. post-call effect-observation transaction: progress becomes
   `observation_recorded` with one accepted effect certainty and trusted proof;
   and
7. final owner transaction: logical event, terminal evidence, outcome, State
   commit/head CAS, progress `finalized`, and original trusted MutationReceipt.

Counting owner command persistence boundaries, an effectful flow requires at
least four Store commits when the post-call observation and final owner commit
truthfully share one transaction: source, dispatch claim, entry consumption, and
combined observation/finalization. Otherwise it requires at least five: source,
dispatch claim, entry consumption, observation, and finalization. Required-before-
effect Event/Evidence append transactions are additional unless already counted
as separately required owner publication; cross-owner outbox/inbox/
acknowledgement/finalization transactions are also additional as applicable.
Four/five is a lower bound, never permission to skip durable attempt evidence.

The dispatch claim, entry-consumption latch, and post-call observation are
pairwise distinct Store transactions. The external call is never bracketed by an
open Store transaction. Observation and finalization may share only one truthfully
supported post-call transaction after the complete trusted result exists and all
participating owner facts can commit atomically without false cross-owner claims.

### Same-store admission gate

Before implementation, the owner must identify the exact transaction manager,
participating owner repositories, durability level, sync/barrier behavior,
conflict mapping, crash-recovery guarantee, and receipt proof. Attaching two
databases, nesting transactions, ordering two commits, or using one process mutex
does not satisfy this mode.

## Cross-Owner Outbox/Inbox Mode

Cross-owner mode provides recoverable publication, not cross-store atomicity.

### Source owner transaction

The source owner atomically commits its fixed source/Decision state and one
unique outbox intent for each required destination publication. Each outbox
binds the already-fixed source identity/digest, source owner kind/audience,
tenant, source transaction/revision, complete source command namespace/canonical
bytes/digest, `SourceDecisionKey`, source idempotency identity, exact destination
owner/audience, complete destination command namespace/canonical bytes/digest,
expected `DestinationDecisionKey` or its exact deterministic derivation,
accepted destination capacity-admission reference, expiry/trust status where
applicable, required durability, and exactly one declared acknowledgement barrier
kind: command acceptance or terminal finalization. Each source-to-destination
edge carries its applicable semantically distinct source/destination key pair and
acknowledgement barrier. Multiple outboxes for one source command retain the same
`SourceDecisionKey`; every destination recomputes its own
`DestinationDecisionKey`. The source remains private or incomplete until every
declared acknowledgement/finalization barrier is satisfied.

A no-effect destination requires the terminal-finalization barrier because its
inbox and terminal owner mutation must either commit in one complete truthful
same-store transaction or remain incomplete behind the explicit recoverable
publication barrier. The command-acceptance barrier is valid only for an
effectful destination and proves only durable admission of that destination
command.

The destination capacity admission must cover the conservative destination
inbox, Decision, acknowledgement-kind records, duplicate/non-reuse, and recovery
obligation for that exact destination command. For a no-effect destination it
also covers every required pre/terminal Event/Trace/Evidence fact, outcome,
immutable State/artifact references, exact State/head CAS, logical owner event,
all publication-barrier records and owner receipts where required, terminal
acknowledgement, final `MutationReceipt`, and no-attempt disposition. For an
effectful destination it covers source/effect intent, every bounded ordinary
attempt, ordered evidence, recovery/dispatch fences, claim, entry-consumption
latch and any terminal cancellation, observation, terminal mutation, terminal
acknowledgement/receipt, and quarantine debt. It is not destination command
acceptance. If it cannot be obtained before source claim, the cross-owner path is
unsupported. If it expires after source commit, source outbox/backlog and all
possibly consumed debt remain retained while same-command recovery reacquires
admission or requests intervention; the source cannot drop work or erase debt.

### Destination admission and key validation

The destination authenticates transport/source principal, source owner kind,
tenant, source audience/transaction/command/digest/`SourceDecisionKey`, exact
destination owner/audience/command namespace/canonical bytes/digest, expected
`DestinationDecisionKey`, capacity admission, and trust/revocation status before
dedupe lookup or persistence. It then runs its own owner admission and
deterministic Decision transaction over `C_destination`, recomputes
`DestinationDecisionKey`, and rejects any mismatch. It never reuses
`SourceDecisionKey` as its own key or treats source allow as destination allow.

### No-effect destination transaction

Only when the destination Decision requires no external effect may its terminal
path use either one truthful same-store transaction or an explicitly declared
recoverable publication barrier. The same-store transaction must atomically
commit:

- the permanent inbox dedupe binding;
- the destination command/Decision binding and
  `DestinationDecisionKey`;
- every owner-required pre-effect and terminal Event/Trace/Evidence fact;
- the terminal outcome;
- every immutable State node or artifact reference and digest required by the
  Decision;
- the exact State/head or owner-coordinate CAS where applicable;
- the destination owner's one logical event/append/mutation at its exact expected
  sequence/head;
- the original terminal acknowledgement and destination `MutationReceipt`
  binding both owner-scoped keys, terminal acknowledgement kind, and their causal
  source-to-destination relation; and
- the canonical no-attempt receipt disposition `no_attempt` plus
  `no_dispatch_fence`, with every attempt/progress/fence/claimant/claim/entry/
  cancellation field absent.

If any required fact belongs to an owner or repository that cannot participate in
that truthful transaction, the destination must use the explicit outbox/inbox
publication barrier. Its first owner-local transaction retains the permanent
inbox, command/Decision, fixed logical intents, complete reservations, and every
required outbox intent. The barrier then publishes each required Event/Trace/
Evidence, outcome, State/artifact, head/coordinate, logical-event, and durability
fact through its owner and validates every original owner receipt. No separate
commits are called atomic. The destination withholds terminal acknowledgement and
`MutationReceipt` until the entire declared barrier is durably satisfied and the
terminal receipt validates all required owner receipts.

If neither one same-store transaction nor that complete recoverable barrier is
available, the no-effect destination path is unsupported and fails closed. Exact
redelivery returns the original terminal acknowledgement only after terminal
completion. Changed bytes under the same source command or idempotency identity
permanently conflict and quarantine the work.

### Effectful destination acceptance and finalization

When the destination Decision requires an external effect, its inbox transaction
commits only:

- the permanent inbox dedupe binding;
- the destination command/Decision and `DestinationDecisionKey` binding;
- the fixed destination source/effect intent and required owner-local outbox
  intents;
- complete reservations, recovery references, bounded attempt ceiling, and
  invocation progress `not_started` with effect certainty absent/pending; and
- one original command-acceptance acknowledgement binding both owner-scoped keys,
  the acceptance kind, and their causal source-to-destination relation.

That acceptance transaction commits no external effect, logical terminal
mutation, terminal effect certainty, final State/head, terminal
acknowledgement, or `MutationReceipt`. The destination then follows Phases 3
through 8 under its own owner semantics. Only terminal finalization may create
the destination's terminal acknowledgement and `MutationReceipt`. Exact
redelivery before terminal finalization returns the original command-acceptance
acknowledgement and resumes the same destination command; after finalization it
returns the original acknowledgement required by the source barrier. It never
creates a second inbox binding, command, attempt, effect, logical mutation, or
receipt.

`SourceDecisionKey` commits only the source owner's logical event.
`DestinationDecisionKey` commits only the destination owner's logical event,
which remains uncommitted after effectful command acceptance. Neither key
advances, deduplicates, authorizes, or receipts the other owner's mutation.

### Source acknowledgement and finalization

The source validates destination owner, tenant, audience, source and inbox
transaction digests, source command/digest/`SourceDecisionKey`, destination
command/digest/`DestinationDecisionKey`, exact causal binding, declared source
barrier, returned acknowledgement kind, every receipt applicable to that kind,
destination capacity disposition, achieved durability, and trust/key status
before marking the outbox barrier satisfied or opening any corresponding source
visibility. A forged, stale, wrong-owner, wrong-tenant, wrong-audience,
wrong-key, wrong-kind, changed, expired, revoked, unavailable, or uncertain
acknowledgement leaves that source barrier closed.

Command acceptance can satisfy only an explicitly admission-specific source
barrier. It never opens terminal destination visibility and never proves a
logical mutation, adapter entry, effect certainty, final result, or
`MutationReceipt`. A source barrier requiring destination evidence, mutation,
effect, result, or finalization requires the exact terminal acknowledgement.
When publication is required after effect, accepted effect certainty remains
private until terminal publication and finalization complete. Backlog, lost
acceptance or terminal acknowledgements, and quarantine are visible owner
recovery states and are never dropped as success.

Delivery is at least once. Exactly-once logical destination mutation follows
from permanent inbox binding, stable event identity, expected-head/sequence CAS,
terminal finalization, and exact duplicate return, not from command acceptance
or exactly-once transport.

## Recovery Protocol

### Sole recovery authority

Each owner scope has at most one effective recovery writer under a durable
recovery fence. Multiple workers may scan, but only the current fenced worker may
claim or advance a work item. Every initial or recovery dispatch attempt binds
that current fence's owner kind, tenant, owner scope, generation, and claimant in
its lineage, private permit/session correlation, dispatch claim, and
entry-consumption latch. A stale fence performs no mutation. A stale claimant
whose entry is unconsumed makes zero adapter/provider calls; a handoff already
latched by `entry_consumed` follows the single-winner handoff/cancellation law and
cannot be invalidated into permission for another attempt.

Recovery authenticates its principal and tenant/owner scope, revalidates current
policy and Gateway requirements before any dispatch, and uses only owner
repository plus exact outbox/inbox/status-query ports. It does not call another
owner's Store directly.

Acquiring a newer fence makes every prior unconsumed claimant stale, but does not
by itself prove `no_effect` or authorize another attempt. Before an unconsumed
claim can yield `no_effect` or open the next ordinary attempt, the current fenced
worker must commit one invalidation CAS that validates the exact old owner,
tenant, fence, attempt, claim, claimant, and `dispatch_claimed` state; proves
entry was not consumed; records the trusted no-effect proof; and durably
invalidates the old claimant and claim. That CAS and the entry-consumption CAS
have the same comparison domain, are mutually exclusive, and have exactly one
winner. CAS failure or uncertainty opens no attempt.

After `entry_consumed`, the stale-claim invalidation CAS must fail. A current
provider status of no effect cannot be accepted as permission because the latched
handoff may still send. Only an accepted authoritative terminal result or atomic
cancellation/non-entry operation that makes the consumed dispatch token
permanently unusable can resolve the attempt to `no_effect`; otherwise recovery
records `effect_uncertain` or remains fail-closed.

### Cursor, fence, high-water, and no-gap law

Every owner recovery implementation must provide owner-defined internal cursor,
fence, high-water, and progress concepts. This RFC does not define their
serialized record.

The implementation contract is:

1. Acquire or renew one durable owner-scope recovery fence with a monotonic
   fencing value and expiry/health policy fixed by the owner.
2. Pin a scan to exact owner kind, tenant, partition/scope, durable start cursor,
   captured high-water coordinate, and fence.
3. Return candidates in one owner-defined stable total order from immediately
   after the durable cursor through the captured high-water, with no omitted
   committed coordinate.
4. Bind every page token to owner kind, tenant, partition/scope, start cursor,
   high-water, fence, and query profile. It cannot be reused across any binding.
5. Advance durable progress only by expected-cursor CAS under the current fence.
6. In the same progress transaction, record each traversed item as resolved,
   terminally quarantined, or durably placed in an exact unresolved-work index
   that retains its original command and next admissible recovery action.
7. Never advance across an unaccounted gap. If the Store cannot prove the next
   coordinate, complete page, or captured high-water, progress stops.
8. Mark a scan interval complete only when every coordinate in the interval is
   durably accounted for. Empty pages do not imply completion unless the owner
   proves the no-gap range is empty through the high-water.
9. On restart, resume from the durable cursor and unresolved-work index under a
   fresh fence. Process memory is not progress.

An owner whose persistence model cannot provide stable ordering, high-water
capture, no-gap enumeration, fenced CAS progress, and retained unresolved work
cannot run automatic recovery.

### Deterministic resume and redispatch

Recovery recomputes or loads the original canonical bytes and verifies every
digest before action. It may:

- return the original committed receipt/result;
- redeliver the exact outbox command;
- query the exact destination inbox, command-acceptance acknowledgement,
  terminal acknowledgement, or receipt while validating both
  `SourceDecisionKey` and `DestinationDecisionKey` and the declared source
  barrier/acknowledgement kind;
- resume the one unresolved attempt and its exact ordered evidence/dispatch
  claim/entry-consumption/observation path without recreating a consumed handoff;
- allocate the next bounded attempt only after durable `no_effect` for the prior
  attempt, the required durable unconsumed-claim invalidation or authoritative
  consumed-token cancellation disposition, the same command/Decision/operation
  key, and fresh current authorization;
- run a separately authorized Gateway/driver-mediated exact status operation for
  the same `dispatch_claimed` or `entry_consumed` attempt and operation key,
  while treating current no-effect status after `entry_consumed` as
  non-authorizing;
- persist a recovered trusted `no_effect`, `effect_succeeded`, `effect_failed`,
  `effect_partial`, or `effect_uncertain` observation and finalize the original
  command;
- finalize a truthful failed/partial/uncertain outcome or quarantine and request
  intervention without another effect call; or
- leave the operation in `recovery_required` and request intervention.

It may not allocate alternate command, Decision, owner logical-event, operation,
receipt, state-node, head, or outbox identities; change bytes; select latest;
silently rebase; downgrade durability; infer an absent effect; invoke a different
adapter/target; repeat a successful sub-effect; or invoke any whole-operation or
sub-effect continuation after `effect_failed`, `effect_partial`, or
`effect_uncertain` under the generic dispatch-attempt lineage. Owner-governed
per-attempt verification/terminal event identities are permitted only for the
unresolved attempt or a valid next attempt after durable prior `no_effect`; they
are not replacement logical events. A separately accepted sub-effect
recovery-attempt annex is a distinct bounded protocol and is unavailable by
default.

### Entry-consumption and stale-claim invalidation race

The required race has one exact comparison domain and two mutually exclusive
outcomes. Worker A may commit a dispatch claim and race its entry-consumption CAS
against Worker B, which owns the new current recovery/dispatch fence and attempts
to invalidate A's exact unconsumed claim with trusted no-effect proof. Both CASes
compare owner, tenant, owner scope, prior/current fence generation as applicable,
claimant, attempt, claim, operation key, and invocation progress
`dispatch_claimed`. Exactly one can win.

If A wins, progress durably becomes `entry_consumed` and A owns the one bounded
synchronous provider handoff. B's invalidation CAS fails. B cannot invalidate the
claim, accept a status-derived current no-effect result as permission, or open a
next attempt. Crash, pause, timeout, or ambiguity before observation is
`effect_uncertain` unless an accepted provider/idempotency protocol terminally
proves the exact result or atomically cancels the consumed token so no late send
can occur.

If B wins before entry consumption, B durably invalidates A's claimant/claim and
may record trusted `no_effect`. A's entry-consumption CAS fails and A makes zero
adapter/provider calls. Only after that durable disposition and fresh
authorization may the bounded next attempt be allocated. Failure or uncertainty
of either CAS opens no attempt.

A live external status lookup is itself a protected read/effect operation. It
requires its own current Gateway/driver authorization, operation identity,
network/filesystem/credential/data-use checks where applicable, bounded result,
trace/evidence, and certainty. Only a pure owner-local lookup of already retained
trusted proof avoids that Gateway path.

### Duplicate receipt handling

An exact duplicate acknowledgement or receipt is accepted only after full owner,
tenant, audience, source command and `SourceDecisionKey`, destination command and
`DestinationDecisionKey` where applicable, declared source barrier and exact
acknowledgement kind, conditional attempted/no-attempt disposition, payload
digest, expected base/head, event/state coordinate, durability, and integrity
validation. An attempted receipt must validate exact attempt lineage,
recovery/dispatch-fence, claimant, claim, entry-consumption/cancellation
disposition, operation key, invocation progress, accepted effect certainty, and
partial inventory when present. A no-attempt receipt must validate canonical
`no_attempt` and `no_dispatch_fence` while rejecting every attempt, progress,
fence, claimant, claim, entry-consumption, or cancellation field. A command-acceptance
acknowledgement is validated as nonterminal and cannot substitute for a terminal
acknowledgement or `MutationReceipt`. The original immutable value is retained
and returned unchanged. A second nominal receipt for the same commit, same
receipt ID with changed bytes, wrong acknowledgement kind, wrong attempt/key
pair, attempted/no-attempt substitution or mixed presence, or a sibling owner's
receipt is a validation failure and quarantines completion.

### Append conflict and uncertainty

A stale expected sequence/head, previous-integrity mismatch, event-identity
collision, changed `(DecisionKey, logical-event-role)` bytes, changed
`(DecisionKey, attempt-identity, ordered-attempt-event-role)` bytes, or same
idempotency identity with changed append bytes yields append conflict and no
append. The coordinator does not fetch latest and retry.

If Store cannot prove append commit or absence, recovery queries the same append
identity and bytes. It returns the original receipt, proves no append and resumes
the same request, or remains uncertain. It never allocates a replacement event.

## Concurrency Laws

1. Every mutable owner head uses an exact expected version, generation, event
   sequence, state head, or explicit genesis compare-and-swap.
2. A missing expected value never means current or latest.
3. Concurrent equivalent commands converge on one retained command binding and
   one original result.
4. Concurrent conflicting commands have one deterministic Store/CAS winner. A
   loser receives opaque conflict and creates no duplicate advancement.
5. One owner-scoped `DecisionKey` produces at most one logical event for that
   owner and one owner-head advancement. Required trace evidence may contain
   multiple ordered per-attempt events but cannot advance owner state twice.
6. The same command identity with changed canonical bytes conflicts even if it
   computes a different `DecisionKey`.
7. The same `DecisionKey` with changed Decision or operation bytes is an integrity
   conflict.
8. A stale head, stale event sequence, stale writer fence, or stale
   recovery/dispatch fence never rebases automatically. A stale unconsumed
   dispatch claimant makes zero adapter/provider calls. An already
   `entry_consumed` handoff remains the one latched handoff and blocks stale-claim
   invalidation from opening another attempt.
9. One command has at most one unresolved dispatch attempt. A new bounded attempt
   can win allocation only after the previous attempt's durable `no_effect`
   observation, its durable latch-domain disposition, and fresh authorization.
   The disposition is invalidation of every unconsumed old claimant/claim or
   authoritative terminal cancellation of an already consumed token; concurrent
   allocators have one CAS winner.
10. Worker A's entry-consumption CAS and Worker B's stale-claim/no-effect
    invalidation CAS compare the same exact owner/tenant/fence/attempt/claim and
    `dispatch_claimed` state. Exactly one wins; neither may be implemented as a
    check followed by a separate write.
11. If B wins before entry consumption, A's entry CAS fails and A makes zero
    adapter/provider calls. If A wins, B's invalidation fails, current status of
    no effect is non-authorizing, and B cannot open another attempt. A crash or
    pause after A wins remains uncertain absent terminal result or authoritative
    cancellation that makes the consumed token unusable.
12. `effect_succeeded` or successful sub-effects do not win a state-head race by
     themselves. The final expected-head CAS may conflict, leaving truthful
     effect evidence plus recovery/intervention and no repeated success.
13. A no-effect destination uses either one complete same-store terminal
    transaction or an explicit recoverable publication barrier that withholds
    terminal acknowledgement until every owner-required fact and receipt
    validates. An effectful destination inbox instead shares one transaction with
    destination command/Decision/source-effect intent and `not_started`, then
    follows Phases 3 through 8. Neither path permits duplicate delivery to create
    a second destination command, effect, event, or head advancement.
14. An owner or tenant mismatch is checked before duplicate success is released,
     preventing cross-owner or cross-tenant receipt/key reuse.
15. Overflow, exhausted sequence/attempt space, or unavailable concurrency state fails
     closed before mutation.

## Crash and Duplicate Matrix

| Point | Durable facts that may exist | Required recovery and visible result |
| --- | --- | --- |
| Before resource admission or prepare | No command/attempt owner state. | An authenticated request may seek the same conservative reservations and prepare the same canonical command. No effect or success is inferred. |
| After reservation, before source claim | Only exact owner-authenticated reservations may exist. | Release only with proof no source claim occurred; otherwise retain charged uncertainty. Allocate no command or attempt facts. |
| After prepare, before source transaction | Deterministic in-memory Decision only. | Recompute identical owner-scoped key/Decision from accepted bytes. No adapter entry and no durable success. |
| During source/outbox transaction | Commit or absence may be uncertain. | Query the same command/source transaction. Recover all original source/outbox/reservation facts, prove no commit and retry the same transaction, or enter `recovery_required`. No partial visibility. |
| After durable outbox enqueue | Source Decision and outbox are durable; destination/effect may be pending. | Redeliver only the exact destination command with `SourceDecisionKey` and expected `DestinationDecisionKey`. Enqueue is not destination commit, effect certainty, or public completion. |
| During effectful destination acceptance transaction | Inbox/command/Decision/source-effect intent/`not_started` acceptance may have committed or not. | Query or redeliver the exact destination command. Return the original command-acceptance acknowledgement, prove no acceptance and retry only that transaction, or quarantine. No terminal mutation, effect, or `MutationReceipt` is inferred. |
| After effectful destination acceptance, before Phase 3 | Permanent inbox, destination key, source/effect intent, reservations, `not_started`, and command-acceptance acknowledgement are durable. | Resume the same destination command under its own current fence and Phases 3-8. Acceptance can satisfy only an admission-specific source barrier. |
| During no-effect destination terminal transaction or publication barrier | Inbox/Decision, required pre/terminal Event/Trace/Evidence, outcome, State/artifact refs, head/coordinate CAS, logical event, terminal acknowledgement, or receipt may be incomplete or uncertain. | Recover the same transaction or each exact declared outbox/inbox publication and owner receipt. Withhold terminal acknowledgement and `MutationReceipt` until every required fact reaches durability and validates; never call separate commits atomic. |
| After complete no-effect destination finalization, before terminal acknowledgement reaches source | The complete same-store transaction or publication barrier, both-key causal binding, canonical no-attempt disposition, and original terminal receipt are durable. | Exact redelivery/lookup returns the original terminal acknowledgement; no second append or head advance. Source validates both keys, terminal kind, every required owner receipt, and no-attempt presence law. |
| After effectful destination finalization, before terminal acknowledgement reaches source | Destination effect observation, logical mutation/head, terminal evidence, and original `MutationReceipt` are durable. | Exact redelivery/lookup returns the original terminal acknowledgement. Command acceptance cannot substitute, and no effect or finalization repeats. |
| During final-live verification | No permit or only a private live session bound to the current owner/tenant recovery/dispatch fence exists; invocation progress remains `not_started`. | Deny/intervention/unavailability/fence loss appends terminal attempt `no_effect` evidence when absence is proved. No dispatch claim or adapter entry. |
| During required-before-effect append | Private permit is held; attempt evidence commit may be uncertain. | Invalidate/withhold dispatch, recover the same append, and record no-effect only if no entry is proved. Receipts never recreate the permit. |
| After pre-effect evidence, before dispatch claim | Ordered attempt evidence is durable; private permit or recovery/dispatch fence may expire or be revoked. | If permit/current facts/fence ownership remain live, commit the independent claim. Otherwise append terminal `no_effect`; no adapter entry. |
| During dispatch-claim transaction | Pre-call claim commit or absence may be uncertain; exact owner/tenant fence generation and claimant are bound; no provider call is in the transaction. | Query the same attempt/claim. Prove no claim and resume with fresh final-live evaluation, recover the original claim under the current fence, or require recovery. Do not observe an effect in this transaction. |
| After dispatch claim, before entry-consumption CAS | Progress is `dispatch_claimed`; the exact claim is durable and provably unconsumed; effect certainty is absent/pending. | A may attempt entry consumption only with the same live permit and current facts. Otherwise the current fenced worker CAS-invalidates the exact unconsumed claim and records trusted `no_effect`. No provider call occurs; CAS uncertainty opens nothing. |
| During entry-consumption CAS | Entry consumption may have committed or not; the same owner/tenant/fence/attempt/claim state is also the stale-invalidation comparison domain. | Query the exact latch state. Begin no handoff until A's committed `entry_consumed` winner is proved. If unconsumed, make zero provider calls and resolve only through the same-domain CAS; never infer a winner from timeout. |
| Worker B invalidation wins before A entry consumption | A's claim was `dispatch_claimed` and unconsumed; B owns the current fence and commits trusted no-effect plus claimant/claim invalidation. | A's entry CAS fails and A makes zero adapter/provider calls. B may later allocate the bounded next attempt only under fresh authorization. |
| Worker A entry consumption wins before B invalidation | Progress is durably `entry_consumed`; the exact claim and one-use permit are latched for A's one bounded handoff. | B's invalidation CAS fails. B cannot use current status-derived no-effect, invalidate the claim, or open another attempt. A begins the immediate bounded synchronous handoff. |
| After `entry_consumed`, before provider send | A owns a consumed token but the provider may currently report no effect and no observation exists. | Current no-effect status is insufficient because A may send later. Record `effect_uncertain` unless authoritative terminal result proof exists or accepted atomic cancellation/non-entry makes the consumed token permanently unusable; recovery never queues or reconstructs the handoff. |
| During bounded synchronous handoff/call or after timeout/ambiguous response | Entry is consumed and provider activity or result may be unknown; certainty is absent/pending. | Commit `effect_uncertain` unless an authorized exact same-key protocol terminally proves another certainty or authoritative cancellation proves no late send can occur. Otherwise quarantine/intervene. |
| After partial provider activity | Some sub-effects may have succeeded, failed, or become uncertain. | Commit trusted complete `effect_partial` inventory or `effect_uncertain` if inventory is incomplete/untrusted. Never repeat a successful sub-effect. |
| After provider success/failure, before observation commit | Process may know a result but no durable accepted certainty exists. | Same-attempt proof/status recovery only. Absent trusted proof becomes `effect_uncertain`; do not call again blindly. |
| During post-call observation transaction | Observation commit or absence may be uncertain. | Query the same attempt/observation. Recover original certainty/inventory, prove no observation and reconcile same attempt, or quarantine. No provider call, dispatch claim, or entry-consumption latch shares this transaction. |
| After durable observation, before final receipt | Progress is `observation_recorded`; exact certainty/proof exists. | Finalize state/event/trace under the original expected head. Never repeat `effect_succeeded` or successful partial sub-effects. CAS conflict preserves truthful effect evidence. |
| During combined post-call observation/finalization | Only a truthfully supported all-or-none post-call Store transaction may combine them. | Recover the same transaction as original observation+receipt, prove no commit and reconcile, or quarantine. It contains no provider I/O or pre-call claim. |
| During separate final owner commit | Commit or absence may be uncertain. | Query the same owner-scoped key and commit identity. Return original receipt, prove no commit and resume same finalization, or quarantine. |
| After owner durable commit, before response | Original logical event/state/head/trace and receipt exist; attempted receipts contain exact latch/effect binding while no-attempt receipts contain canonical absent attempt/fence disposition. | Exact duplicate validates the conditional presence law and returns the original trusted receipt/result unchanged. No replacement owner IDs, State, operation, or effect. |
| Exact duplicate command | Same namespace and canonical bytes. | Resume the one unresolved attempt without recreating a consumed handoff, or return the original result. A new attempt is allowed only after durable prior `no_effect`, the required unconsumed-claim invalidation or consumed-token cancellation disposition, and fresh authorization. |
| Conflicting duplicate | Same namespace with changed bytes, or same key/event/attempt/receipt identity with changed binding. | Permanent opaque conflict; no fallback, append, head move, effect, or replacement owner logical identity. |
| Recovery cursor/fence lost or corrupt | Work may exist but no trustworthy progress proof exists. | Stop automatic recovery and require intervention. Never restart from zero, skip to latest, or evict charged debt. |

## Semantic Error Taxonomy

These are internal semantic classes for owner mapping. They are not public error
codes or a new serialized error schema.

| Class | Required meaning and disposition |
| --- | --- |
| `malformed_input` | Closed grammar, canonical bytes, bound, identity, or cross-field validation failed before mutation. |
| `stale_durable_base` | Expected state head, event sequence, generation, writer fence, or source revision differs. No rebase or mutation. |
| `command_conflict` | One stable command namespace is already bound to changed canonical semantics, owner, tenant, actor, audience, or operation. Permanent fail-closed conflict. |
| `append_conflict` | Owner logical-event identity, bounded attempt/event identity-role binding, expected sequence, previous integrity, or append idempotency binding differs. No append. |
| `durability_unavailable` | Required transaction or storage barrier cannot be reached or proven. No success receipt. |
| `trace_commit_failure` | Required trace/event fact did not commit. Before effect, the held permit cannot proceed to a dispatch claim or entry-consumption latch; after an observed effect, completion is withheld and recovery required. |
| `state_commit_failure` | Immutable node/event/head transaction did not commit or is uncertain. No new head or next tick is exposed. |
| `dispatch_claim_uncertain` | Pre-call claim commit or absence cannot be proved. No adapter entry is authorized; same-attempt lookup is required. |
| `entry_consumption_uncertain` | The durable entry-consumption CAS commit or absence cannot be proved. Begin no handoff, perform no stale-claim invalidation, and open no next attempt until exact latch state is recovered; if consumption committed and terminal result/cancellation is unavailable, certainty is `effect_uncertain`. |
| `dispatch_linearization_unavailable` | The owner cannot durably consume the exact claim/permit in the same owner/tenant/fence/attempt/claim CAS domain as stale invalidation, cannot begin immediate bounded handoff, or cannot terminally cancel a consumed token. Dispatch is unsupported and closed. |
| `stale_dispatch_claimant` | The unconsumed attempt, permit, claim, claimant, or recovery/dispatch-fence generation is no longer current. Make zero adapter/provider calls; stale state cannot prove `no_effect` or open another attempt without the winning invalidation CAS. An already consumed latch follows its separate uncertainty/cancellation law. |
| `effect_failed` | Trusted proof shows the exact invocation failed with no hidden successful or uncertain sub-effect. Commit a truthful failed outcome when terminal evidence can be made durable; the generic protocol performs no continuation. |
| `effect_partial` | Trusted complete bounded inventory proves mixed sub-effect certainty. The generic protocol performs no continuation; finalize truthfully or quarantine/intervene. |
| `effect_uncertain` | Entry or result cannot be proved. Quarantine/intervene; no generic continuation and no success claim. |
| `protected_status_lookup_denied_or_unavailable` | A live external status operation lacks current Gateway/driver authorization, protected-read verification, or a trustworthy result. It cannot resolve effect uncertainty. |
| `recovery_required` | Original disposition cannot safely advance without same-command reconciliation or intervention. |
| `owner_mismatch` | Owner kind, owner identity, destination, audience, or owner-scoped coordinate differs. No duplicate success or receipt reuse. |
| `acknowledgement_kind_mismatch` | Command acceptance, terminal acknowledgement, or declared source barrier differs. The source barrier remains closed; acceptance never substitutes for terminal result. |
| `receipt_validation_failure` | Receipt authentication, owner/tenant/key/source/result/durability/integrity binding or attempted/no-attempt presence law is absent, changed, forged, stale, mixed, substituted, or unavailable. Completion stays closed. |
| `verification_denied_or_unavailable` | A required verifier denied or could not establish allow. No effect dispatch. |
| `resource_exhausted` | Conservative source/destination/attempt/claim/entry-consumption/cancellation/observation/finalization/recovery/non-reuse capacity reservation denies before new durable allocation. Existing possibly committed or uncertain debt remains charged. |
| `internal_invariant_violation` | A partial visible commit, duplicate advancement, cross-tenant reuse, or impossible transition is observed. Quarantine affected scope and require security/operational intervention. |

Outward error mapping must remain non-reflecting where existence or tenant data is
sensitive. Provider text, credentials, protected payload, keys, exact head,
cursor, event existence, or retry advice must not leak through generic errors.

## Ordering and Durability Laws

The RFC 0015 ordering remains controlling:

1. Authenticate, validate schema/scope, and obtain conservative owner and
   destination capacity admission before source claim.
2. Follow the acyclic construction order to fix command, Decision, owner
   logical-event, operation, and causal identities, then commit the source/intent
   transaction.
3. Begin or resume one bounded attempt under the current owner/tenant
   recovery/dispatch fence, run the complete final-live Gateway/verifier chain,
   and retain its fence-bound private permit/session.
4. While that same permit remains held, durably append the attempt's ordered
   verification/Decision and all other required-before-effect evidence.
5. Commit the independent pre-call dispatch-claim transaction for that attempt,
   claimant, and current recovery/dispatch-fence generation.
6. Commit the independent durable entry-consumption CAS in the same exact owner/
   tenant/fence/attempt/claim domain as stale invalidation, consuming/latching the
   claim and same private one-use permit against every required mutable fact.
7. Only after that latch commits, immediately begin the bounded synchronous
   adapter/provider handoff outside Store transactions; never deliberately delay,
   queue, requeue, or reconstruct it.
8. Commit a post-call observation containing invocation progress and one accepted
   RFC 0015 effect certainty, including complete partial inventory where needed.
9. Append terminal evidence and atomically commit State node plus required
   `StateCommitted` evidence plus head CAS where state changes.
10. Return a result or expose a new head only after every required owner receipt
   reaches effective durability.

Same-store atomicity is preferred for owner facts that must become visible
together. Independent stores use source/outbox followed by either a no-effect
destination inbox/terminal commit or an effectful destination
inbox/command-acceptance commit followed by that destination's Phases 3-8 and
terminal acknowledgement, then the exact declared source barrier/finalization.
No document, metric, response, or test may describe either chain as a cross-store
atomic transaction or treat command acceptance as terminal completion.

Source/intent, dispatch claim, entry consumption, external call, effect
observation, and final owner commit are distinct boundaries. Observation and
finalization may share one truthful post-call transaction; no transaction may
combine dispatch claim, entry consumption, or post-call observation with each
other, and no transaction may remain open across provider I/O.

Required-before-effect failure causes no effect. Required-after-effect failure
cannot undo or erase `effect_succeeded` or successful partial sub-effects; it
withholds completion and recovers the same terminal publication. Deny,
intervention, permit loss, or proved entry veto records ordered `no_effect`
attempt evidence. Trace and State durability are runtime contract, not
best-effort logging.

## Integration by Owner and Primitive

### StateStore and State owner

- `StateStore` supplies owner-approved immutable writes, expected-head CAS,
  transactions, durability, and exact lookup. It does not decide transition
  legality or latest-head rebasing.
- State owner derives the immutable node and required State trace/event binding
  from the accepted Decision.
- Node persistence, required `StateCommitted`, and head CAS share the RFC 0015
  supported transaction or remain unsupported pending an explicit outbox
  publication barrier.
- State commit failure keeps the old head current and prevents the next tick.

### TraceStore and Event/Trace owner

- Trace accepts owner append intents, not caller-built committed receipts.
- Stable 0.1 event IDs, sequence, kinds, identity context, payload spelling, and
  ordering remain unchanged.
- The stable 0.1 tick line emits its existing events exactly once. Additional
  bounded-attempt evidence uses a separately accepted owner-native profile and
  causal links; it never adds attempt fields to, repeats, or reorders stable
  `TraceEvent` bytes.
- New correlation uses existing identity/correlation fields and a bounded
  structured payload accepted by the event owner. This RFC does not add or use
  unsupported `generated_by` or `derived_from` fields.
- Required pre-effect and terminal events are durable according to RFC 0015,
  with exact duplicate receipt return and no latest-sequence retry. Per-attempt
  verification events bind attempt identity, ordinal, prior-attempt causality,
  and ordered role without creating another owner logical event.

### Gateway and verifiers

- Gateway runs the complete final-live verifier chain before the attempt's
  required-before-effect append and fails closed on unavailability.
- The private final permit/session is retained across that append, the
  independent dispatch-claim commit, and durable entry-consumption CAS. It binds
  exact owner, tenant, owner scope, recovery/dispatch-fence generation, claimant,
  attempt, and claim. Receipts and claims cannot reconstruct it.
- The entry-consumption CAS atomically consumes/latches the permit and exact claim
  under the accepted owner protocol against current authority, work order, lease,
  approval, quota, policy, data-use, secret, safety, capability, adapter,
  revocation, expiry, and current recovery/dispatch-fence ownership. It races in
  the same domain as stale-claim invalidation. A stale unconsumed claimant makes
  zero adapter/provider calls; a consumed latch cannot be invalidated into a new
  attempt. Without that durable linearization, Gateway does not dispatch.
- The bounded synchronous handoff starts immediately after the latch and outside
  Store transactions. Current no-effect status after consumption is
  non-authorizing unless authoritative cancellation makes the consumed token
  unusable and prevents every late send.
- Recovery re-runs all current checks for any valid next attempt. Every live
  external status operation is separately Gateway/driver-mediated and authorized;
  only pure owner-local retained-proof lookup is exempt.
- A historical Decision or durable event never becomes current authority.

### Adapter execution

- Each adapter operation consumes exactly one operation idempotency key and must
  declare whether it supports provider idempotency, exact status lookup,
  same-key reconciliation, partial-effect enumeration, and trusted receipt
  validation. Same-key reconciliation is an evidence capability, not dispatch
  authority.
- The coordinator independently commits invocation progress `dispatch_claimed`
  and then `entry_consumed` in separate Store transactions before call entry; it
  never combines either transaction with observation.
- Exact status and same-key capabilities support reconciliation only; they do not
  authorize generic continuation after `effect_failed`, `effect_partial`, or
  `effect_uncertain`. Such continuation requires the separately accepted finite
  sub-effect recovery-attempt annex above.
- Adapter success is not owner commit. The proof/reference must be durable and
  validated before `effect_succeeded` and owner finalization.
- Partial adapters return a complete trusted ordered `1..=256` or tighter
  inventory. They never hide successful/uncertain sub-effects under
  `effect_failed`, and they never repeat a successful sub-effect.

### Outcome

- Outcome records command disposition and separate effect certainty without
  collapsing the two state machines.
- Invocation progress and accepted effect certainty remain separate. Before
  terminal observation, certainty is pending rather than inferred from progress.
- `no_effect`, `effect_failed`, `effect_partial`, and `effect_uncertain` cannot be
  reported as whole-operation executed success.
- `effect_succeeded` or successful partial sub-effects plus terminal persistence
  failure remain truthful observed effects with command recovery required.

### Replay

- Replay reconstructs command binding, Decision, ordered events, state/head
  transition, receipts, source/destination keys, attempt lineage, invocation
  progress, recovery/dispatch-fence generations, dispatch claims,
  entry-consumption/invalidation/cancellation dispositions, outbox/inbox
  progress, command-acceptance versus terminal acknowledgement, effect certainty,
  and partial inventory from access-filtered immutable facts.
- Replay never drains outboxes, claims recovery fences, creates dispatch claims
  or entry-consumption latches, calls adapters/status/cancellation operations,
  refreshes authority, or mutates live heads.
- Simulation uses detached state and explicit non-live adapters only.

### Registry owner

- Registry retains its own command, lifecycle, source, outbox, finalization,
  currentness, and receipt semantics under RFC 0016.
- This coordinator may sequence those owner operations only after a Registry
  annex supplies accepted canonical command/Decision/operation bytes and exact
  receipt validation.
- A Registry receipt proves only its bounded owner commit. It is not Gateway,
  C03, Authority, activation, or currentness permission.

### Authority owner

- Authority retains its own decision, proof-binding, source, outbox,
  finalization, and historical evidence semantics under RFC 0017.
- Historical evidence remains historical and non-authorizing.
- Independent Authority revocation versus State/Registry CAS requires a
  separately accepted owner-specific linearization annex using this protocol;
  copied snapshots do not satisfy it.

### Audit owner

- Audit is a distinct owner. Required audit-before-release must use a truthful
  same-store owner transaction or outbox/inbox barrier.
- Audit receipt validation binds exact owner kind, tenant, subject, action,
  Decision/result, visibility, and durability.
- This RFC does not define an audit event or receipt schema. Until an accepted
  audit annex exists, any flow requiring durable audit before release is blocked.

## Replay and Recovery Separation

Replay is a query/planning path. Recovery is a fenced mutation path. They cannot
share a method that conditionally dispatches based on a flag.

Replay may explain:

- why source and destination command namespaces bound to their distinct
  owner-scoped Decision keys;
- which verifier results produced the Decision;
- each bounded attempt's ordered final-live verification evidence, invocation
  progress, accepted effect certainty, and partial inventory;
- whether source/outbox, inbox/append, dispatch claim, entry consumption,
  stale-claim invalidation or consumed-token cancellation, effect observation,
  and final owner commit reached durability;
- why a duplicate returned the original result or a changed duplicate
  conflicted;
- which expected-head or append conflict won; and
- why certainty is pending or is `no_effect`, `effect_succeeded`,
  `effect_failed`, `effect_partial`, or `effect_uncertain`.

Replay cannot resolve `effect_uncertain` by assumption. It cannot produce a trusted
receipt from serialized bytes without owner validation, turn history into
authority, or emit a live event representing replayed work.

## Event and Evidence Durability Classification

Every Event, Trace, or Evidence append intent participating in an FND-003 command
must have exactly one owner-assigned durability class fixed in the Decision. The
class determines its transaction role and visibility deadline; the owner's
separate configured storage durability level determines the barrier that must be
reached. A caller may request a stricter storage level but may not select or
downgrade the class.

The hyphenated class names below are normative semantic labels, not enum or wire
spellings. An owner-specific annex must reuse or map to its already accepted
closed grammar without this RFC registering another serialized value.

| Class | What it may gate | Durability deadline | Failure behavior |
| --- | --- | --- | --- |
| `required-before-effect` | Gateway release into one adapter/driver/external-effect boundary. It may also gate a denial/intervention response when the decision itself must be evidenced before return. | Must reach the owner and deployment effective durability floor before durable entry consumption or the gated response. | Invalidate or withhold the private Gateway permit, make zero adapter calls, expose no success, and recover only the same append/command. Uncertainty fails closed. |
| `required-after-effect` | Terminal outcome publication, owner commit receipt, new State head visibility, next-tick admission, and public success after an effect or bounded mutation. It never authorizes the effect that preceded it. | Must reach the effective durability floor after trusted effect observation and before any gated terminal result/head is released. | Preserve truthful effect certainty privately, withhold completion/head/next tick, and require same-command publication/finalization recovery. Never rewrite `effect_succeeded` or successful partial sub-effects as absent or repeat them merely because publication failed. |
| `best-effort telemetry` | Operational observation only. It cannot gate or satisfy command admission, authority, verification, effect permission, owner commit, State head movement, receipt validation, audit obligation, replay proof, or recovery progress. | No privileged transaction deadline. Delivery may occur only after the authoritative facts it describes and under finite owner resource policy. | Drop, defer, or report bounded telemetry failure according to owner policy without changing the authoritative command result. It cannot be the only record of a meaningful transition or privileged mutation. |
| `derived/export-only` | Completion of the particular derived view or export only. It cannot gate the source command, external effect, source owner commit, currentness, or authority. | The source facts must already be durable. The derived/export owner applies its own durability before claiming that export complete. | Mark only the derived/export operation unavailable, failed, or recovery-required. Do not mutate, backfill, reinterpret, or weaken the authoritative source facts. |

The classification is phase-specific, not a linear quality scale.
`required-after-effect` cannot satisfy a `required-before-effect` obligation.
Neither `best-effort telemetry` nor `derived/export-only` can satisfy either
required class, become transaction proof, establish currentness, or substitute
for an owner receipt. A required State, Trace, denial, verification, outcome,
audit, or recovery fact cannot be relabeled as telemetry or derived data because
a backend is unavailable.

Owner and deployment policy may strengthen a class's storage durability or add
another required fact. Caller input, adapters, Store, exporters, recovery
workers, and compatibility projections cannot weaken the class fixed by the
semantic owner. Any classification uncertainty is treated as the stricter
applicable required gate or blocks the operation pending an accepted owner annex;
it never defaults to best effort.

## Durability and Non-Authority Boundary

Each owner annex must name its durability levels and the minimum effective floor.
The caller may request stricter durability but cannot lower owner or deployment
policy. Success requires achieved durability at least equal to that floor.

The following never prove owner durability:

- entering a process queue;
- an in-memory Decision;
- writing log text;
- sending a message;
- receiving a transport acknowledgement;
- observing a database connection commit without the owner receipt contract;
- a best-effort trace/export;
- a bare digest, timestamp, cursor, or highest numeric revision; or
- a provider response not durably bound to the operation key.

No command, Decision, event, outbox, inbox, cursor, fence, effect proof, receipt,
state coordinate, trace coordinate, or replay report is authority, identity,
approval, business truth, historical proof, or currentness merely by existing.
Every consuming owner validates exact owner, tenant, scope, audience, trust,
integrity, durability, and current policy independently.

## Security and Privacy

### Replay and command confusion

Command family, owner kind, tenant, actor/internal principal, owner audience, and
command/action identity are part of the stable namespace and canonical bytes.
Cross-family or cross-owner substitution cannot address an existing command.
Replay bytes cannot enter the recovery dispatcher.

### Collision and changed-byte conflict

Owners compare retained canonical bytes as well as BLAKE3 outputs. Changed bytes
under one namespace, `DecisionKey`, event identity, operation key, or receipt
identity permanently conflict. Collision suspicion quarantines rather than
selecting a winner by hash alone.

### Forged receipts

Receipt validation occurs before duplicate success, outbox acknowledgement,
accepted effect certainty, finalization, or head release. Wrong owner, tenant, audience,
source transaction, command, key, event/state coordinate, durability, integrity,
trust status, or signature/trusted-wrapper binding fails closed. A receipt from a
sibling operation cannot finalize another. Attempted and no-attempt receipts are
mutually exclusive: mixed fields, omitted canonical no-attempt dispositions, or
attempt/fence/claim/entry fields on a no-attempt receipt fail validation.

### Ambiguous effect outcomes

Timeout, process loss, provider ambiguity, incomplete sub-effect inventory,
missing trusted receipt, or protected status unavailability produces
`effect_uncertain`. The generic protocol neither reports success nor performs
another effect call. `effect_failed` and `effect_partial` likewise provide no
generic same-command continuation authority.
`effect_partial` retains every known successful, failed, and uncertain sub-effect
in the bounded trusted inventory; it is not collapsed into failure. Exactly-once
effect language is prohibited unless the exact adapter/idempotency service
contract and fault tests prove it for the same durable key and operation.

### Protected status lookup

Every live external status lookup is a separately authorized Gateway/driver-
mediated operation. This includes read-only network, filesystem, database,
provider, credential-bearing, secret-bearing, tenant-resource, or protected-data
queries. It requires its own command/action identity, current authority/work
order/data-use/secret/network/filesystem/quota/policy/safety checks, operation
idempotency and certainty contract, trace/evidence, bounded response, and
fail-closed handling. A status endpoint cannot become an ungoverned retry oracle.

Only pure owner-local lookup of already retained trusted proof, with no external
I/O, credential use, protected dereference, or another owner's currentness
query, avoids the Gateway. An unavailable or denied protected lookup leaves the
original attempt `effect_uncertain` or recovery-required; it does not prove
`no_effect`. Before entry consumption, trusted no-effect proof opens no next
attempt until the same-domain current-fence CAS durably invalidates every prior
unconsumed claimant and claim. After `entry_consumed`, a status response that
currently says no effect remains non-authorizing because the latched handoff may
send later. Only authoritative terminal result or accepted atomic cancellation/
non-entry proof that makes the consumed token unusable can resolve that state to
`no_effect`.

Any live cancellation of an `entry_consumed` token is itself a separately
authorized Gateway/driver-mediated control effect. It binds the exact owner,
tenant, fence, attempt, claim, entry-consumption coordinate, operation key, and
current authority; emits required evidence; and is accepted as `no_effect` only
when the owner/adapter protocol atomically makes the token permanently unusable
and proves no late send can occur. Best-effort cancellation, request acceptance,
or unavailable cancellation leaves `effect_uncertain`.

### Owner and tenant confusion

Every command, key derivation input, outbox/inbox binding, effect proof,
recovery/dispatch cursor/fence, attempt lineage, permit correlation, dispatch
claim, entry-consumption/invalidation/cancellation disposition, and receipt
validation includes exact owner kind and tenant. Owner/tenant mismatch is checked
before existence-sensitive lookup where possible and always before result release
or entry consumption. No tenant can receive another tenant's original duplicate
receipt or use another tenant's claimant fence or consumed token.

### Fail-open recovery

Missing history, unavailable Store, corrupt cursor, stale recovery/dispatch
fence, scan gap, unbounded backlog, exhausted attempt budget, or unavailable
owner leaves work pending/quarantined. A stale unconsumed claimant makes zero
adapter/provider calls. An already consumed latch is
never invalidated into a fresh attempt and remains under its one-handoff/
cancellation certainty law. Recovery never starts with an empty ledger, skips to
latest, allocates replacement owner identities, reconstructs or requeues a
consumed handoff, or changes `effect_failed`, `effect_partial`, or
`effect_uncertain` into generic continuation authority.

### Resource exhaustion

Before source claim, each later owner implementation must conservatively compute
and obtain accepted accounting/reservation for the complete worst-case retained
obligation. The obligation includes command and idempotency history; source and
outbox; destination capacity admission, inbox, Decision, command-acceptance and
terminal acknowledgements, no-effect destination publication-barrier facts and
owner receipts, logical mutation, outcome, immutable State/artifact refs,
head/coordinate CAS, and receipt where applicable; every bounded ordinary attempt
and ordered verification event; recovery/dispatch-fence generations and
invalidations; dispatch claim; entry-consumption latch and terminal cancellation;
maximum effect observation and `effect_partial` inventory; terminal Event/State/
Evidence and finalization; recovery cursors/indexes;
unresolved/quarantine records; permanent non-reuse; and future tombstone debt.
Any separately accepted sub-effect recovery-attempt annex must add its complete
finite worst-case lineage, evidence, claims, entry-consumption latches,
consumed-token cancellations, observations, accumulated immutable receipts/
inventories, both fence-race outcomes, and quarantine debt before enabling that
path.

Limits apply at least by tenant, principal, owner kind, command family, target or
destination owner, and global owner scope, with finite request rate, concurrency,
retained cardinality, bytes, backlog, and Store capacity. Fresh IDs, new attempts,
duplicates, status queries, reconciliation, and any separately annexed recovery
attempts cannot bypass semantic coalescing or accounting.

A cross-owner source must carry an accepted owner-authenticated destination
capacity admission for the exact destination command and worst-case obligation,
or source claim is unsupported. Destination admission does not grant command
authority. If it expires after source commit, the source retains the fixed
outbox, backlog, reservation/debt, and recovery obligation while attempting
same-command re-admission; expiry never drops work or converts debt into absence.

Committed, possibly committed, `effect_uncertain`, partial, quarantined,
unresolved, non-reuse, and tombstone facts remain charged until an accepted
owner-authenticated reconciliation or retention protocol proves exact
disposition. They cannot be evicted, compacted to a fresh miss, or forgotten to
regain capacity. Compensation releases only demonstrably unconsumed reservation
after proof no owner write occurred. Missing, stale, corrupt, overflowed, or
uncertain accounting fails closed before new allocation.

### Sensitive data

Canonical bytes, Decisions, trace payloads, outbox/inbox entries, receipts,
errors, logs, metrics, and recovery diagnostics must not contain raw secrets,
credentials, provider tokens, private keys, approval tokens, private
chain-of-thought, unrestricted protected payloads, or secret-derived digests.
Hashing is not redaction. Owner references grant no dereference permission.

## Adoption and Migration Sequence

No code is authorized by this RFC. A later implementation proposal must proceed
in this order and stop at every unmet gate:

1. **Owner inventory:** identify each command family, semantic owner, expected
   durable base/head, source and destination canonical commands, mutable
   dispatch-time facts, current mutation path, trace/state ordering, external
   effect and protected-status boundaries, resource obligations, and Store
   topology. Inventory is not implementation.
2. **Owner annexes:** accept exact owner-specific canonical command, Decision,
   operation, bounded attempt lineage, invocation-progress, effect-certainty/
   partial-inventory, dispatch-claim/entry-consumption/invalidation/cancellation,
   append-intent, conditional attempted/no-attempt receipt-validation,
   error-mapping, durability, and resource contracts. Reuse accepted owner bytes;
   do not define a universal envelope.
3. **Resource admission proof:** define conservative worst-case source and
   destination reservations, retained uncertain/quarantine/non-reuse/tombstone
   debt, expiry/backlog handling, isolation, and proof-of-absence compensation.
   Stop before source claim when destination capacity cannot be admitted.
4. **Pure derivation fixtures:** independently reproduce the exact acyclic
   namespace/idempotency -> `C` -> command digest/Decision key -> `D` -> Decision
   fingerprint -> `O` -> operation-key order, BLAKE3 laws, exhaustive one-field
   command projection changes, distinct source/destination keys, cycle rejection,
   stable duplicate/conflict behavior, owner/tenant binding, and collision-safe
   byte comparisons without I/O.
5. **Topology proof:** select same-store or cross-owner mode per mutation and
   document source/outbox, attempt-evidence, dispatch-claim, entry-consumption,
   observation, finalization, complete no-effect inbox/terminal transaction or
   publication barrier versus effectful inbox/acceptance plus Phases 3-8,
   acknowledgement-kind barriers, and the four/five-commit lower bound.
   Unsupported legacy split stores remain read/replay-only.
6. **Owner coordinator tests:** implement one bounded local owner path behind
   owner-owned ports with deterministic Store faults. No daemon, SDK, or public
   schema widening.
7. **Gateway/adapter conformance:** prove complete final-live evaluation before
   evidence, same-permit retention through append/claim/entry consumption,
   same-domain one-winner entry-versus-invalidation CAS, immediate bounded
   handoff, authoritative consumed-token cancellation, exact operation-key
   handling, separately authorized protected status lookup, partial inventory,
   and zero live effect during replay.
8. **Persistence and recovery:** prove durability barriers, source/outbox,
   destination no-effect terminal and effectful acceptance modes, exact
   acknowledgement-kind barriers,
   independently committed dispatch claim and entry consumption, post-call
   observation, optional truthful observation/finalization combination, no-gap
   scans, attempt reuse/allocation, fencing, both Worker A/Worker B CAS orderings,
   post-entry/pre-send failure, conditional no-attempt receipt validation, exact
   duplicate receipt return, and fault recovery at every boundary.
9. **Bounded v2 adoption:** route only one separately authorized fresh local
   partition/command family through the accepted coordinator. Preserve stable
   0.1 Trace/State compatibility projections and avoid dual writes.
10. **Legacy handling:** keep existing separate State/Trace databases inspect-only
   until a separately accepted migration/cutover contract proves writer handoff,
   compatibility, rollback, and no dual truth.
11. **Dependent owners:** Registry, Authority, and audit adopt only their own
     accepted annexes and retained tests. No owner implementation is inferred from
     this generic planning contract.

No step above authorizes sub-effect continuation after `effect_failed`,
`effect_partial`, or `effect_uncertain`. That path remains blocked until the
separate finite sub-effect recovery-attempt annex and all of its retained evidence
are accepted.

After persisted bytes exist, rollback may stop new work and retain read/recovery
support. It cannot delete permanent command bindings, forget
`effect_uncertain`/`effect_partial` history, reactivate a legacy writer, return an
old head as current, or turn a used identity into a fresh miss.

## Required Implementation Acceptance Tests

Listing these tests is not execution evidence. Before any code is authorized, a
later implementation proposal must identify exact fixtures, commands, backends,
and retained outputs for all applicable rows.

| Area | Required evidence |
| --- | --- |
| Canonical derivation | Independent BLAKE3 reproduction for command digest, owner-scoped Decision keys, Decision fingerprint, and operation key. Prove the exact namespace/idempotency -> `C` -> command digest/key -> `D` -> fingerprint -> `O` -> operation-key order; reject direct/indirect/optional/default cycles; prove each derived value is absent from earlier bytes; independently mutate every `C` category and presence distinction; mutable current evaluation changes leave `C` stable but change Decision/attempt evidence. |
| Cross-owner keys | Source and destination canonical bytes derive distinct semantic keys; outbox, inbox, command-acceptance and terminal acknowledgements, and terminal owner receipts bind both keys and exact acknowledgement kind causally; destination reruns owner admission/Decision; wrong/reused/substituted key, wrong acknowledgement kind, or source-allow-as-destination-allow denies. |
| Durability classification | Each required-before, required-after, telemetry, and derived/export fixture exercises its exact gate and deadline; class downgrade and cross-class substitution deny; telemetry/derived data cannot form authority, transaction proof, currentness, or a required receipt. |
| Owner grammar stop | Attempted use of unresolved owner encodings, debug text, arbitrary JSON/maps, or unregistered schemas is rejected before persistence. |
| Duplicate and conflict | Exact duplicate before/after every phase resumes one unresolved attempt without recreating a consumed handoff or returns one original receipt; changed duplicate, same digest with changed bytes, replacement owner logical-event/state/operation identity, changed attempt/latch event, attempted/no-attempt substitution, and sibling receipt substitution fail closed. |
| Attempt lineage | One unresolved attempt per command; ordered verifier/pre-effect/terminal evidence; exact owner/tenant recovery/dispatch-fence generation, claimant, claim, and entry-consumption disposition; deny/intervention/permit/fence loss produces `no_effect` only when absence is proved; a new ordinary attempt requires durable prior `no_effect`, durable invalidation of an unconsumed claim or authoritative cancellation of a consumed token, same command/Decision/operation key, fresh authorization, finite capacity, and one CAS winner. |
| Concurrency | Equivalent callers converge; conflicting callers have one CAS/unique-index winner; stale head/sequence/fence loses; source/destination keys advance only their owners; no silent rebase or duplicate advancement. A entry-consumption and B stale-claim/no-effect invalidation race in the same exact domain. Fault tests force each ordering: B wins, A's entry CAS fails, and A makes zero calls; A wins, B's invalidation fails, current status-derived no-effect opens nothing, and only terminal result or authoritative consumed-token cancellation can resolve uncertainty. CAS failure/uncertainty opens nothing. |
| Transaction boundaries | Fault injection proves source, required-before append, independent dispatch claim, independent entry consumption, external handoff/call, post-call observation, and final owner boundaries. At least four owner Store commits occur when observation/finalization truthfully share, otherwise five, plus Event/Evidence/cross-owner transactions. No provider I/O occurs inside a Store transaction; claim, entry consumption, and observation are pairwise distinct. |
| Source/outbox | Process kill, disk full, sync failure, and response loss prove source plus outbox atomicity, declared acceptance-versus-terminal barrier, and accepted worst-case reservation; enqueue or command acceptance alone never opens terminal effect/result/completion; destination-admission expiry retains backlog and debt. |
| Inbox/commit | No-effect destination fixtures prove either one complete transaction or an explicit recoverable publication barrier containing permanent inbox/Decision, every required pre/terminal Event/Trace/Evidence fact, outcome, immutable State/artifact refs, exact head/coordinate CAS, logical owner event, terminal acknowledgement, no-attempt disposition, and terminal receipt at required durability. Independently fault each fact, owner receipt, barrier delivery, and final validation; every failure withholds terminal acknowledgement and never calls separate commits atomic. Effectful fixtures prove one inbox+command/Decision/source-effect-intent+`not_started` acceptance transaction, no terminal receipt at acceptance, subsequent Phases 3-8, and terminal acknowledgement only after finalization. Duplicate/redelivered/changed/forged/wrong-owner/wrong-tenant/wrong-key/wrong-kind cases never create a second command, effect, mutation, or receipt. |
| Final-live Gateway ordering | Complete final-live chain runs first; same owner/tenant/fence/attempt/claim-bound private permit remains held across ordered required-before append, independent claim, and entry-consumption CAS; claim/entry failure, append failure, permit loss/expiry/revocation, pre-consumption fence loss, or verifier denial makes zero adapter/provider calls and terminal no-effect evidence where proved. |
| Entry linearization | The durable `dispatch_claimed -> entry_consumed` CAS binds and consumes/latches the exact claim and private permit while rechecking every authority/work-order/lease/approval/quota/policy/data-use/secret/safety/capability/adapter/revocation/expiry fact and current owner/tenant recovery/dispatch-fence claimant. It is mutually exclusive with same-domain stale invalidation. Handoff starts only after commit, synchronously and outside Store transactions, with no deliberate delay/requeue. Missing latch/handoff/cancellation support fails closed. |
| Invocation and certainty separation | Progress fixtures cover `not_started`, `dispatch_claimed`, `entry_consumed`, `observation_recorded`, and `finalized` independently from pending or accepted `no_effect`, `effect_succeeded`, `effect_failed`, `effect_partial`, and `effect_uncertain`. Pre-consumption crash makes zero calls and requires winning invalidation; post-consumption/pre-send crash is uncertain unless exact terminal result or authoritative token cancellation proves no late send. Current no-effect status alone is rejected after consumption. |
| Partial effects and compensation | Exact `1`, `256`, and owner-lowered bounds; ordered inventory substitution/omission/duplicate/over-bound/untrusted cases; failed cannot hide success/uncertainty; generic recovery after `effect_failed`, `effect_partial`, or `effect_uncertain` makes zero continuation calls; truthful finalization or quarantine/intervention follows; compensation/abort/rollback is a distinct authorized command and never fake undo. A future sub-effect recovery annex must separately prove finite lineage, original command/invocation/idempotency binding, fresh verification, ordered evidence, independent claims and entry-consumption latches, complete capacity, both latch/invalidation orderings, consumed-token cancellation, crash/fence recovery, accumulated immutable receipts/inventory, and no successful repeat. |
| Protected status lookup | Network, credential, filesystem, database, provider, tenant-resource, and protected-data status reads and consumed-token cancellation require separate Gateway/driver authorization and evidence; denial/unavailability cannot prove no-effect. Pure retained owner-local proof lookup performs no external I/O. A current no-effect result after `entry_consumed` cannot invalidate the claim or open another attempt; only terminal result or authoritative cancellation that atomically makes the token unusable and prevents late send may resolve it. Best-effort cancellation remains uncertain. |
| Adapter idempotency | Same-key exact status behavior is fault-injected against a real conformance adapter for reconciliation only. Generic recovery makes zero continuation calls after failed/partial/uncertain certainty. Any future same-key sub-effect continuation is tested only under its separately accepted finite recovery-attempt annex. |
| Effect/finalization split | `effect_succeeded` or partial success plus terminal Trace/State failure is retained with `recovery_required`; recovery finalizes without repeating successful work. `effect_failed`, `effect_partial`, and `effect_uncertain` remain truthful. |
| State/Trace ordering | Required stable tick line remains ordered; new head is invisible until node, required `StateCommitted`, head CAS, terminal outcome, and trace durability satisfy RFC 0015. |
| Recovery scan | Ceiling and multi-page scans prove owner/tenant/fence/high-water binding, expected-cursor CAS, no gaps, unresolved-index accounting, stale-fence denial, restart resume, dispatch-claimant fencing, and no empty-page completion bug. |
| Receipt validation | Attempted receipts require exact attempt lineage, fence, claimant, claim, entry-consumption/invalidation/cancellation disposition, progress, certainty, and inventory where applicable. No-attempt receipts require canonical `no_attempt`/`no_dispatch_fence` and forbid every attempt/progress/fence/claimant/claim/entry/cancellation field. Forged, changed, wrong-owner, wrong-tenant, wrong-audience, wrong-source/destination key, wrong source barrier/acknowledgement kind, attempted/no-attempt substitution or mixed presence, wrong durability, stale-key, corrupt, and sibling receipts cannot release success. Command acceptance cannot validate as terminal receipt. |
| Resource admission | Worst-case command/source/outbox/destination/inbox/acceptance/no-effect-publication-barrier/terminal-receipt/attempt/evidence/fence/claim/entry-consumption/cancellation/observation/finalization/recovery/quarantine/non-reuse/tombstone reservation at ceiling and ceiling-plus-one; expiry retains backlog/debt; possibly committed or uncertain state cannot be evicted for capacity; compensation needs proof of absence. A future sub-effect recovery annex reserves its complete finite lineage before enablement. |
| Fail-closed faults | Store unavailable, durability barrier failure, corrupt history, cursor loss, scan gap, append/claim/entry-consumption/observation uncertainty, both entry-versus-invalidation orderings, post-entry/pre-send process loss, authoritative-cancellation failure, every no-effect destination terminal-fact/barrier failure, exhausted attempts, resource exhaustion, destination admission expiry, and receipt uncertainty remain closed and require recovery/intervention. |
| Replay | Inspect, simulation, and read-only re-evaluation make zero outbox claims, recovery progress writes, Gateway permits, adapter/status calls, live appends, or head mutations. |
| Privacy and oracle resistance | Synthetic secrets and cross-tenant coordinates do not appear in canonical values, receipts, trace payloads, errors, logs, metrics, timing classes, or recovery diagnostics; hidden/absent/conflict cases use the accepted non-reflecting profile. |
| Compatibility | Stable 0.1 trace IDs/bytes/order, State node IDs/parents/hashes/links, replay output, Gateway denial behavior, and existing inspect-only records remain unchanged. |
| Architecture | `splendor-types` is behavior-free, `splendor-kernel` only composes/invariant-wires, each service crate retains its semantic mutation owner, and `splendor-store`, daemon, SDK, bridge, replay, adapter, and test fake do not become shadow owners or bypass the Gateway. |

Fault injection must cover process kill, power loss where the backend can model
it, disk full, transaction failure, sync/barrier failure, timeout, lost request,
lost response, duplicate delivery, reordered delivery, wrong acknowledgement
kind, stale recovery/dispatch fence, both Worker A/Worker B entry-versus-
invalidation CAS orderings, post-entry/pre-send pause or process loss, concurrent
CAS, consumed-token cancellation failure, corrupt attempted/no-attempt receipt,
each no-effect destination terminal fact and barrier receipt, and owner
unavailability. Skipped or unavailable evidence is not a pass.

## Gold and Validation Status

The exact FND-003 Gold targets are `G02`, `G04`, `G15`, `G47`, `G75`, and
`G87`. Every target remains `specified_not_implemented` / `not_exercised`.

| Gold target | Exact future FND-003 acceptance mapping |
| --- | --- |
| `G02` | Trace or Store failure prevents State/head advancement and successful receipt release. |
| `G04` | Every lifecycle transition and bounded dispatch attempt is evidenced; duplicate/resumption handling preserves one transition and the original receipt rather than duplicating advancement. |
| `G15` | Allowlist and rate-limit enforcement, duplicate-key safety, truthful partial effects, and separately evidenced compensation behavior. Any sub-effect continuation is future owner/driver-annex evidence, not authorization from this RFC. |
| `G47` | Bounded cohort/blast radius plus separately authorized abort and rollback transactions; no rollback claim erases or fakes undo of an external effect. |
| `G75` | Strong approval before effect, truthful irreversible `effect_uncertain`, containment/incident path, and no fake rollback. |
| `G87` | Duplicate delivery or replay cannot repeat an irreversible effect; distinct explicit new authorization creates a new command and is not retry. |

This proposed documentation-only RFC executes no harness, supplies no retained
runtime evidence, passes no Gold target, and changes no Gold, conformance, task,
component, or release status. The acceptance-test matrix above is a future
implementation gate only. Static review, `git diff --check`, canonical examples,
or acceptance of this RFC cannot change those statuses.

## Compatibility and RFC Impact

This RFC is additive planning only. It preserves:

- stable 0.1 Action Gateway, verifier, adapter, outcome, State, Trace, replay,
  identity, and tick-order contracts;
- RFC 0015 Event/State/Evidence owner and durability semantics;
- RFC 0016 Registry owner and lifecycle semantics;
- RFC 0017 Authority historical-evidence non-authority semantics; and
- RFC 0018 common canonical grammar, digest-wire, annex, and non-authority rules.

An implementation of any public schema, trace-event rename, State format,
Gateway contract, verifier pipeline, daemon/SDK surface, or owner wire record
requires its own accepted RFC/annex and compatibility plan. The internal domain
separators in this RFC do not register serializable digest types or permit a
generated surface.

Legacy direct State and Trace writes remain compatibility inputs, not proof that
they satisfy this transaction protocol. No dual-write bridge may claim one
canonical result while two owners can diverge.

## No-Go Gates for Implementation

Implementation must not start, or must stop, when any applicable gate is true:

- an owner kind, tenant binding, command namespace, expected durable base/head,
  or action identity is absent or ambiguous;
- command namespace or caller/owner idempotency identity is assigned from `C` or
  any `C`-derived digest/key instead of independently or from an accepted acyclic
  pre-`C` projection;
- canonical command bytes omit any immutable command category or presence/
  absence distinction required by this RFC, or include mutable current verifier
  results/status as command identity;
- `C` includes any `C`-derived digest/key; `D` includes
  `DecisionFingerprint`, `OperationIdempotencyKey`, or `O` bytes; `O` includes
  `OperationIdempotencyKey`; a later derived value feeds an earlier projection;
  or the owner annex lacks cycle checks and fixtures;
- canonical command, Decision, or operation bytes lack an accepted owner annex;
- code would register a universal command/decision/event/receipt envelope from
  this RFC;
- an Event/State/Evidence, Registry, Authority, or audit owner schema is being
  invented locally;
- `splendor-types` would perform owner behavior, `splendor-kernel` would become a
  service mutation owner, a service crate would surrender its transition
  semantics, or `splendor-store` would decide command/transition legality;
- a required event/evidence fact lacks one of the four semantic durability
  classes, is downgraded, or is satisfied by telemetry/derived data;
- conservative worst-case source and destination resource reservation/accounting
  is absent, destination capacity admission is unavailable for a cross-owner
  command, or possibly committed/uncertain/quarantined/non-reuse debt can be
  evicted to regain capacity;
- source mutation and source outbox cannot share one owner-local transaction;
- a no-effect destination lacks either one truthful same-store terminal
  transaction or an explicitly declared recoverable publication barrier covering
  permanent inbox/Decision, every required pre/terminal Event/Trace/Evidence fact,
  outcome, immutable State/artifact refs, exact head/coordinate CAS, logical owner
  event, terminal acknowledgement, no-attempt disposition, every required owner
  receipt, and final `MutationReceipt` at required durability;
- any no-effect destination terminal fact above commits separately without its
  declared outbox/inbox barrier, a separate commit is called atomic, or terminal
  acknowledgement is released before every owner receipt validates;
- an effectful destination inbox transaction omits permanent dedupe,
  destination command/Decision/source-effect intent, `DestinationDecisionKey`,
  complete reservations, `not_started`, or command-acceptance acknowledgement;
  or it falsely includes terminal mutation/effect/`MutationReceipt`;
- an effectful destination does not follow Phases 3-8 after acceptance, or emits
  terminal acknowledgement/receipt before terminal finalization;
- a cross-owner outbox, inbox, acknowledgement, or receipt uses one ambiguous
  `DecisionKey`, lets destination reuse the source key/allow, or fails to bind
  both owner-scoped keys and exact destination command bytes;
- a source outbox omits its exact acceptance-versus-terminal barrier, accepts the
  wrong acknowledgement kind, or lets command acceptance satisfy destination
  evidence, effect, result, terminal visibility, or `MutationReceipt`;
- a proposed same-store mode is actually two commits, attached independent
  databases, a process mutex, or an unproven transaction manager;
- dispatch claim, entry consumption, and post-call observation are not pairwise
  distinct, provider I/O occurs inside a Store transaction, or the effectful path
  omits the four/five owner Store-commit lower bound plus required publication
  transactions;
- a response would expose a new State head before required State/Trace evidence
  is durable;
- final-live Gateway/verifier evaluation does not run first, its private permit
  is not retained across ordered required-before-effect append and the separate
  dispatch claim and entry-consumption CAS, or the permit/attempt/claim/latch omit
  exact owner/tenant recovery/dispatch-fence generation and claimant;
- entry consumption is not a durable CAS in the same exact owner/tenant/fence/
  attempt/claim and `dispatch_claimed` comparison domain as stale-claim
  invalidation, the two CASes can both win or neither has a recoverable winner, or
  either is implemented as a check followed by a separate write;
- the entry-consumption CAS fails to consume/latch the exact claim and private
  one-use permit while rechecking authority, work order, lease, approval, quota,
  policy, data-use, secret, safety, capability, adapter, revocation, permit-expiry,
  and current claimant-fence facts;
- provider handoff starts before durable `entry_consumed`, occurs inside a Store
  transaction, is deliberately delayed/queued/requeued or reconstructed after
  the latch, or an unconsumed stale claimant can call the adapter/provider;
- after `entry_consumed`, stale-claim invalidation can succeed, current provider
  status reporting no effect can authorize `no_effect` or another attempt, or
  uncertainty is cleared without terminal result proof or authoritative atomic
  cancellation/non-entry proof that makes the consumed token unusable and
  prevents every late send;
- the owner/adapter cannot enforce the durable latch, immediate bounded
  synchronous handoff, one-winner invalidation race, and consumed-token
  cancellation protocol;
- invocation progress and accepted effect certainty are collapsed into one state
  machine, a provider-handoff path omits `entry_consumed` between
  `dispatch_claimed` and `observation_recorded`, a no-handoff branch lacks its
  winning invalidation disposition, or certainty is inferred from progress before
  observation;
- accepted certainty `effect_succeeded` can be marked without durable trusted
  proof/reference;
- `effect_partial` lacks a trusted complete bounded ordered sub-effect inventory,
  `effect_failed` hides a successful/uncertain sub-effect, or a successful
  sub-effect can repeat;
- generic recovery would make another whole-operation or sub-effect call after
  `effect_failed`, `effect_partial`, or `effect_uncertain`;
- a future sub-effect continuation lacks a separately accepted finite owner/
  driver recovery-attempt annex preserving original command/invocation/
  idempotency bindings, fresh final-live verification, ordered evidence,
  independent dispatch claims and entry-consumption latches, complete capacity,
  both latch/invalidation orderings, consumed-token cancellation, crash/fence
  recovery, accumulated immutable receipts/inventory, and proof no successful
  sub-effect repeats;
- recovery allocates a new attempt before durable prior `no_effect`, changes the
  command/Decision/operation key, exceeds the owner attempt bound, omits fresh
  current authorization, or lacks the required durable unconsumed-claim
  invalidation or consumed-token terminal-cancellation disposition under the
  current owner/tenant recovery/dispatch fence;
- before entry consumption, status-derived `no_effect` can open another attempt
  before current-fence CAS durably fences the prior claimant/claim; after entry
  consumption, that invalidation can win or nonterminal current status can open
  another attempt; or Worker A can call the adapter after Worker B won
  invalidation;
- a live external status lookup bypasses Gateway/driver mediation, network/
  credential/protected-read checks, its own evidence/certainty, or fail-closed
  authorization;
- a live consumed-token cancellation bypasses Gateway/driver mediation, exact
  latch/operation binding, current authorization, required evidence, or atomic
  proof that the token is unusable and no late send can occur;
- an adapter or provider is described as exactly-once without fault-injected
  evidence for the exact operation and durable key;
- duplicate handling can allocate a replacement owner logical event, state node,
  head revision, receipt, timestamp, outbox command, operation key, or effect;
- an attempted receipt omits attempt lineage, fence, claimant, claim,
  entry-consumption/invalidation/cancellation disposition, progress, or certainty;
  a no-attempt receipt omits canonical `no_attempt`/`no_dispatch_fence`, contains
  any attempt/progress/fence/claimant/claim/entry/cancellation field; or either
  receipt disposition can substitute for the other;
- owner-governed per-attempt event identities are used outside the one unresolved
  attempt or a valid bounded next attempt after durable prior `no_effect`;
- changed duplicate bytes can be treated as a new command;
- append or head conflict can silently fetch latest and rebase;
- recovery lacks a durable owner/tenant-bound fence, pinned high-water, stable
  order, no-gap scan, expected-cursor CAS, dispatch-claimant binding/invalidation,
  entry-consumption/cancellation disposition, or unresolved-work accounting;
- unavailable/corrupt idempotency, receipt, cursor, fence, or effect history can
  be treated as absent;
- replay can claim work, create an entry-consumption latch, dispatch effects, call
  a status/cancellation operation, append live evidence, or mutate a live head;
- receipt validation omits owner kind, tenant, both cross-owner keys where
  applicable, source barrier/acknowledgement kind, conditional attempted/no-
  attempt presence, or the applicable attempt/fence/claim/entry/progress/
  certainty/inventory binding;
- Store, daemon, SDK, adapter, replay, or a composition bridge becomes a second
  semantic owner;
- the design claims cross-store atomicity, exactly-once delivery, exactly-once
  external effects, currentness from copied snapshots, or authority from a
  receipt; or
- required fault, concurrency, compatibility, privacy, and replay acceptance
  evidence is missing.

## Open Owner Annexes

This RFC intentionally leaves the following owner-specific work open and
implementation-blocking:

| Annex | Must define before owner code |
| --- | --- |
| Canonical derivation annex | Independent command namespace and caller/owner idempotency assignment or accepted pre-`C` projection; exact `C` -> command digest/Decision key -> `D` -> Decision fingerprint -> `O` -> operation-key dependencies and exclusions; complete semantic projections; explicit cycle analysis; and direct/indirect/optional/default cycle fixtures. |
| State/Trace local transaction annex | Exact accepted command/Decision/operation bytes, owner logical event versus bounded per-attempt trace roles, ordered attempt and entry-consumption evidence, complete no-effect destination transaction or recoverable publication barrier, State/event/head transaction, post-call observation/finalization combination rules, conditional attempted/no-attempt receipt validation, stable 0.1 projection, and backend fault contract for every required fact. |
| Gateway/adapter effect annex | Bounded ordinary attempt identity/lineage, exact operation bytes, complete final-live verifier set, owner/tenant recovery/dispatch-fence and claimant binding, private permit retention, independent dispatch claim, durable same-domain entry-consumption versus stale-invalidation CAS, immediate bounded synchronous handoff, authoritative consumed-token cancellation/non-entry proof, both race orderings, post-entry/pre-send failure, invocation progress, RFC 0015 certainty, idempotency/status capabilities, separately authorized protected status lookup, trusted effect proof, partial-effect inventory, compensation references, and uncertainty intervention. It authorizes no continuation after failed/partial/uncertain certainty. |
| Sub-effect recovery-attempt annex | Separately accepted finite lineage for any continuation after `effect_failed`, `effect_partial`, or `effect_uncertain`; original command/invocation/operation-idempotency/sub-effect binding; fresh complete final-live verification; ordered required-before-effect and terminal evidence; independent dispatch claim and durable entry-consumption latch per recovery attempt; same-domain invalidation race with both orderings; authoritative consumed-token cancellation; complete worst-case capacity; recovery/dispatch fencing; crash recovery at every boundary; accumulated immutable receipts and inventories; terminal truth preservation; and proof no successful sub-effect repeats. Absent this annex, continuation is unsupported. |
| Event outbox/inbox annex | Exact source and destination canonical commands/keys, destination capacity admission, declared acceptance-versus-terminal source barrier, complete no-effect inbox/terminal same-store transaction or explicit recoverable publication barrier covering every required Event/Trace/Evidence, outcome, State/artifact, head/coordinate, logical-event, acknowledgement, owner-receipt, no-attempt, and durability fact; effectful inbox/command-acceptance transaction followed by Phases 3-8; exact acknowledgement kinds; both-key causal binding; append conflict; conditional terminal receipt; trust; resource; retention; and recovery bindings consistent with RFC 0015/0018. |
| Resource/accounting annex | Conservative source/destination/acceptance/no-effect-publication-barrier/terminal-acknowledgement/attempt/fence/claim/entry-consumption/cancellation/observation/finalization/recovery/non-reuse/tombstone reservation, optional separately accepted finite sub-effect recovery-lineage obligation, finite multi-scope limits, expiry/backlog, retained debt, isolation, restart, proof-of-absence compensation, and non-eviction of uncertain history. |
| Registry adoption annex | Registry-owned canonical inputs, lifecycle expected-generation winner, publication finalization, receipt validation, and independent-owner race handling without changing RFC 0016 records. |
| Authority adoption annex | Authority-owned canonical inputs, revocation/CAS winner, historical non-authority, publication finalization, receipt validation, and no change to RFC 0017 records. |
| Audit owner annex | Audit command/event/receipt ownership, audit-before-release ordering, visibility, non-oracle behavior, durability, outbox/inbox, and recovery. |
| Recovery storage annex | Owner-defined cursor/fence/high-water/progress types, stable ordering proof, no-gap query contract, exact owner/tenant dispatch claimant, same-domain entry-consumption versus claim-invalidation CAS, authoritative consumed-token cancellation disposition, both Worker A/Worker B race orderings, post-entry/pre-send uncertainty, unresolved-attempt/work index, protected status operation boundary, retention/non-reuse, charged capacity/debt, and operational intervention. |
| Compatibility annex | Persisted-version classification, N-1/N/N+1 behavior, rollback/read support, generated parity where later relevant, and legacy split-store migration/cutover stops. |

None of these annexes may be filled by a generic map, string reference, private
wire record, permissive fake, or direct Store table. An unresolved owner schema
remains unresolved.

## Acceptance Effect

If accepted through independent architecture/compatibility, security/privacy,
and contract review, this RFC becomes only the implementation-gating semantic
contract for active `0.2/v2` `V2-FND-0 Foundations` planning under `FND-003`.
The 0.1 FR-0.01-02 through FR-0.01-05 and 0.01-H2 behavior remain compatibility
obligations only. Acceptance alone changes no behavior, authorizes no code, and
changes no Gold or catalog status.

Any later implementation still requires accepted owner annexes, a separately
reviewed dependency-safe slice, the complete acceptance evidence above, retained
validation output, compatibility documentation, and confirmation that every
No-Go gate is clear. Until then, the stable current runtime contract remains the
only operative behavior.
