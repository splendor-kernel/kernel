# Architecture Policy Plan for Issue #137

> **Status:** Active 0.2/v2 architecture-policy planning rule for issue #137.
> This document does not change the stable Splendor 0.1 baseline, does not make
> `catalog/architecture/dependency_policy.proposed.json` active CI policy, and
> does not claim that v2 package ownership is implemented.

## Issue And Fit

| Field | Value |
| --- | --- |
| Issue | [#137 Plan machine-enforced architecture ownership and dependency policy](https://github.com/splendor-kernel/kernel/issues/137) |
| Parent | [#135 Epic: Align v2 agent-kernel catalog with current Splendor roadmap](https://github.com/splendor-kernel/kernel/issues/135) |
| Milestone | `Splendor0.2-dev` / v2 active execution with 0.1 baseline compatibility |
| Primary sprint fit | `0.1-S2 - Compatibility test suite` |
| Primary FR fit | `FR-0.1-05`, `FR-0.1-08` |
| Related downstream fit | `FR-0.1-03` for runtime compatibility, `FR-0.1-06` for migration policy |
| Primitives strengthened | docs/tests planning for gateway, verifier, state graph, trace store, replay, messages, work orders, SDK/API compatibility |
| Boundary | docs only |

This plan turns the v2 architecture material into bounded 0.2 architecture
policy work. It preserves the current authoritative order: `AGENTS.md`, core
`docs/rules/*` safety documents, 0.1 stable specs, release notes, accepted RFCs,
then this v2 rule pack for active decomposition.

## Source Inputs

| Source | Used For |
| --- | --- |
| `AGENTS.md` repository ownership guide | Current authoritative package ownership and Splendor invariants |
| `docs/rules/splendor_dev_model.md` | Runtime-kernel boundary, secure daemon boundary, Rust/Python/TypeScript responsibilities |
| `docs/rules/sprints_frs_milestones.md` | 0.1 milestone and FR fit, no cross-milestone leakage |
| `docs/rules/verifiable_criteria/sprints/0.1-S2-compatibility-test-suite.md` | Conformance-suite scope and non-goals |
| `docs/spec/0.1/conformance.md` | Stable 0.1 conformance categories and fixture boundary |
| `docs/rules/v2/README.md` | Active 0.2/v2 rule-pack entrypoint and evidence boundary |
| `docs/rules/v2/architecture/clean-architecture-rules.md` | v2 ownership, dependency order, mutation-owner rules, enforcement ideas |
| `docs/rules/v2/catalog/architecture/components.yaml` | v2 component owners and must-never-do clauses |
| `docs/rules/v2/catalog/architecture/dependency_policy.proposed.json` | Proposed machine-readable policy shape, migration exceptions, path owners, facets |
| Root `Cargo.toml`, `package.json`, and `python/pyproject.toml` | Current package/workspace evidence |

## Non-Goals

- No Rust, Python, TypeScript, OpenAPI, conformance, or CI behavior changes.
- No crate moves, package splits, generated-contract changes, or broad refactor.
- No enforcement of `dependency_policy.proposed.json` as CI or accepted policy.
- No runtime behavior change, schema change, or CI enforcement from this docs-only move.
- No replacement of the current Action Gateway, verifier chain, state graph, trace store, replay, work-order, or identity invariants.
- No claim that proposed 0.2/v2 packages such as `splendor-authority`, `splendor-evidence`, `splendor-fabric`, `splendor-agent`, `splendor-learning`, or `splendor-change` exist today.
- No certification, marketplace, product UI, full fleet scheduler, full workflow engine, or physical production safety claim.

## Current Package Ownership Vs Proposed V2 Ownership

The current ownership column follows `AGENTS.md` and the current workspace
manifests. The proposed v2 ownership column follows the imported planning pack
and is RFC-required before implementation.

| Current package or surface | Current ownership | Current evidence | Proposed v2 ownership | RFC and migration boundary |
| --- | --- | --- | --- | --- |
| `crates/splendor-types` | Canonical IDs, serialized primitives, deterministic schema contracts | `AGENTS.md`; root `Cargo.toml`; `splendor-types` has no internal workspace dependency | Remains `splendor-types` as behavior-free canonical contracts | Any new authorizing field, public schema, ID grammar, or generated fixture is RFC-required and must preserve 0.1 compatibility or define migration |
| `crates/splendor-store` | State graph, trace store, persistence traits and SQLite engines | `AGENTS.md`; `splendor-store` depends on `splendor-types` and `rusqlite` | Persistence engines remain storage-only; state, event, evidence, and replay semantics move toward `splendor-evidence`/state service | Splitting semantic state/event ownership from persistence is RFC-required; store must not decide transitions, authority, retries, or approvals |
| `crates/splendor-gateway` | Action gateway, verifier pipeline, action outcomes, adapter contracts | `AGENTS.md`; current gateway depends on `splendor-types` only | Driver Gateway and Driver Registry own typed verified invocation lifecycle; current `ActionGateway` remains a compatibility profile | Any rename or expansion of the gateway contract is RFC-required; no side-effect path may bypass current verifier/gateway semantics during migration |
| `crates/splendor-kernel` | Runtime loop, scheduler, tenancy, runtime context, state/trace integration, message/fleet/governance foundations | `AGENTS.md`; current kernel depends on types, store, gateway | Composition root and compatibility facade; proposed splits target authority, evidence, fabric, agent, learning, and change owners | Every split from kernel is RFC-required; kernel facade must delegate to one owner and must not keep divergent state machines alive |
| `crates/splendor-daemon` | Runtime daemon API and process composition boundary | `AGENTS.md` daemon/API guidance; current daemon depends on kernel, gateway, store, types | Authenticated transport translation, API versioning, process composition | Direct store/gateway dependency is migration debt only; new handlers must call one public application command/query and must not own mutations |
| `crates/splendorctl` | CLI workflows for run execution, trace export, replay, and local embedded ergonomics | `AGENTS.md`; current CLI depends on kernel, gateway, store, types, filesystem adapter, HTTP adapter | Operator/developer client over public command/query routes; embedded-local composition isolated explicitly | Direct store/gateway/adapter construction is an exception only for existing embedded-local mode; ordinary operator paths must not become backdoors |
| `adapters/filesystem`, `adapters/http`, `adapters/robotics` | Gated adapter implementations that execute only after gateway verification | `AGENTS.md`; adapter crates depend inward on `splendor-gateway` and `splendor-types` | Concrete provider or driver implementations under the driver boundary | Adapter changes that add operation classes, effect semantics, secrets, physical actions, or maturity claims require RFC or accepted adapter contract changes |
| `python/bindings` | Rust/Python boundary | `AGENTS.md`; current Cargo member `splendor-bindings` depends on `splendor-kernel` | Thin native boundary over canonical Rust contracts | Any Python binding that exposes new 0.2/v2 authority, workload, gateway, state, or replay semantics requires SDK/API RFC and parity tests |
| `python/splendor` | Python SDK callbacks and local ergonomics; Python proposes but Rust enforces | `AGENTS.md`; `python/pyproject.toml` package `splendor` | Generated or schema-aligned authoring and client ergonomics | SDK must not implement independent kernel semantics, privileged side effects, or direct adapter execution; migration waits for generated contract plan |
| `typescript/packages/types` | Schema-aligned TypeScript contracts | `AGENTS.md`; `@splendor/types` package manifest | Generated TypeScript contracts from canonical schemas | Generation and compatibility must be accepted before making this an architecture check; no runtime behavior belongs here |
| `typescript/packages/client` | Thin daemon/control client | `AGENTS.md`; `@splendor/client` depends on `@splendor/types` | Thin daemon/control client over authenticated APIs | Client must not implement verifier, gateway, store, replay, or state-machine behavior; daemon API breaking changes require RFC |
| `conformance/0.1` and `docs/spec/0.1/conformance.md` | Stable primitive fixture evidence for 0.1 compatibility | `0.1-S2` criteria and conformance spec | Architecture check evidence can feed conformance reports later | Static architecture checks are not a substitute for positive, denial, failure, trace, state, replay, and fail-closed conformance cases |
| `docs/rules/v2/*` | Active 0.2/v2 rule pack | `docs/rules/v2/README.md` says v2 rules guide decomposition but are not implementation evidence | Source for 0.2 assignments and RFCs | Runtime behavior still requires accepted RFCs where needed, code, tests, docs, and validation evidence |

## Proposed Package Splits And RFC Boundary

All proposed package splits below are RFC-required. A future PR must not create
the package and then backfill the RFC; the RFC must define ownership, migration,
compatibility, security, trace/replay impact, and tests first.

| Proposed split or new package | Current source of behavior | Target owner from imported planning | RFC trigger | Minimal migration boundary |
| --- | --- | --- | --- | --- |
| `splendor-authority` | Kernel tenancy, daemon auth checks, policy cache, work-order authority fields | Identity, capability, data-use, secret-reference and lease semantics | New authority primitive, daemon API scope semantics, work-order compatibility, verifier pipeline impact | Keep current caller/work-order/gateway layers intact; move decisions behind a kernel facade only after denial and revocation tests exist |
| `splendor-evidence` | Kernel trace/state/replay modules plus store-backed persistence | Event ordering, state semantics, evidence bundles, replay/simulation plans | Trace event semantic changes, state graph format changes, replay behavior changes | Store remains persistence; evidence owns semantics; 0.1 state/trace/replay fixtures stay valid or get explicit migration fixtures |
| `splendor-fabric` | Kernel scheduler, node registry, fleet telemetry, remote transport foundations | Workloads, nodes, placement, leases, fencing, checkpoint coordination | Distributed identity, workload/lease schema, placement protocol, retry and checkpoint semantics | Local runtime remains correct first; no fleet scheduling behavior enters stable policy without 0.03+ acceptance coverage |
| `splendor-agent` | Kernel loop engine, message router, local delegation, runtime context modules | Agent instances, routes, world state, messages, delegation | Runtime context or message semantics change, parent/child run changes, delegation authority changes | Kernel facade remains stable; message/delegation authority remains narrower-only and trace-linked |
| `splendor-artifacts` | Current artifact references live mostly as primitive refs and examples | Artifact registry, immutable manifests, derivation lineage | New artifact primitive, storage contract, lineage, mutable alias governance | Artifact creation/publish remains gateway-mediated; no artifact upload may activate or approve itself |
| `splendor-learning` | No stable 0.1 training/eval control plane package | Collection, feedback, reward, eval, training, improvement control | New data/feedback/eval/training primitive or generated schema | Training/eval code is user/provider-side until an RFC defines candidate-only behavior, data-use grants, and conformance evidence |
| `splendor-change` | Governance hooks and escalation/circuit-breaker foundations | Change sets, gates, deployment, rollback, quarantine, incidents | Governance semantics, approval/circuit-breaker changes, deployment activation | Candidate generation and activation must remain separated; no self-approval or missing-evidence success |
| `splendor-node` or resident node binary | Daemon/runtime process plus future fleet/device foundations | Resident node composition, leases, caches, health, trace buffering, device-local safety | New resident-node API, fleet registration, node identity, physical/edge action model | Must preserve signed work orders, local safety veto, trace buffering, and no direct low-level robot control |
| Driver Gateway expansion | Current Action Gateway and adapters | Driver registry plus typed invocation lifecycle for all provider effects | Gateway contract change, adapter maturity surface, operation manifest schema | Current `ActionRequest`/`ActionOutcome` compatibility remains until migration fixtures prove replacement or version negotiation |

## Minimal Architecture-Policy Check Spec

This is a proposed future check. It must not be wired into CI until an RFC accepts
the policy file location, schema, exception owners, and rollout mode.

### Inputs

| Input | Status |
| --- | --- |
| Accepted dependency policy file, future path such as `architecture/dependency_policy.json` | Required before CI enforcement |
| Cargo workspace metadata | Required for Rust package edges |
| npm workspace/package metadata | Required for TypeScript package edges |
| Python package metadata and import scan | Required only after Python owner policy is accepted |
| Path-owner registry | Required for changed-path ownership checks |
| Mutation-owner registry | Required for command/state/event duplicate-owner checks |
| Migration exception registry | Required for temporary edges and expiry checks |

### Checks

| Check | What it verifies | Failure condition |
| --- | --- | --- |
| Workspace edge check | Internal package dependencies match accepted allowed edges | Unapproved internal dependency, reverse edge, or dependency cycle |
| Adapter inward-dependency check | Adapter crates/packages depend only on accepted contracts such as types/gateway | Adapter imports kernel, daemon, agent, learning, change, or another forbidden owner |
| Provider dependency fence | Provider/runtime libraries stay in adapters, store engines, daemon transport, node executors, or explicit allowed locations | Core package imports a forbidden provider/runtime dependency |
| Path owner check | Changed governed paths map to exactly one owner | Unowned path or multiply owned path outside accepted docs/examples exceptions |
| Migration exception check | Temporary exceptions have owner, reason, exact scope, exit criteria, and expiry | Missing owner, vague scope, expired exception, or exception that expands authority |
| Mutation-owner check | Each command, mutable state head, transition family, and canonical event has one owner | Daemon, store, adapter, SDK, CLI, or test harness becomes a second owner |
| Effect import smoke check | Direct filesystem/network/process/device/model effect APIs appear only in accepted effect locations | New direct effect path outside gateway/store/daemon/node/adapter boundaries |
| Facet classification check | Changed owner maps to required validation facets | Unknown facet without high-impact classification or required validation note |

### Deliberate Non-Checks

| Non-check | Reason |
| --- | --- |
| Does not enforce `dependency_policy.proposed.json` as current CI policy | The proposed policy file is not active CI until RFC acceptance |
| Does not require proposed v2 crates to exist | Missing proposed crates are not failures before package-split RFCs |
| Does not prove runtime correctness | Static checks cannot replace conformance tests for gateway, trace, state, replay, messages, work orders, governance, and adapters |
| Does not certify adapters or physical systems | Adapter maturity and physical safety need separate conformance and safety evidence |
| Does not infer semantic ownership from folder names alone | Ownership must come from accepted path and mutation-owner registries |
| Does not ban existing scoped migration debt | Temporary exceptions are allowed only when named, owned, scoped, and exit-bound |
| Does not classify every docs-only rule-pack change as production impact | Docs-only changes remain non-runtime unless they change accepted rules/specs |
| Does not replace RFC, security review, or release compatibility review | Policy checks are a lower bound, not the whole review process |

## Current FND-002 Baseline Guard

The repository currently wires a bounded smoke guard at
`scripts/architecture/check-dependency-policy.py` and CI runs it in the Rust job.
This implemented guard is narrower than the proposed future architecture-policy
check above:

- it reads Cargo metadata, checks direct non-dev Rust workspace dependency
  allowlists for the current 0.1 crates/adapters only, and checks all direct
  internal Rust workspace dependency edges for cycles;
- it rejects internal dependency cycles and obvious wrong-direction/provider
  non-dev edges, such as an adapter depending on `splendor-kernel` or
  `splendor-types` depending on `splendor-store`;
- it preserves documented migration seams for `splendor-daemon`, `splendorctl`,
  and `splendor-bindings`;
- it does not enforce `dependency_policy.proposed.json`, does not require
  proposed v2 plane crates to exist, and does not prove full FND-002 completion.

Treat failures from this script as current-baseline architecture regressions.
Treat passing output as only lower-bound evidence that the existing Rust package
graph has not drifted in the checked direction.

## Duplicate Mutation-Owner Prohibition

One privileged mutation must have exactly one owner. This rule applies to current
0.1 packages and to any v2 split.

| Surface | Allowed role | Prohibited duplicate-owner behavior |
| --- | --- | --- |
| Daemon handlers | Authenticate, authorize endpoint scope, parse one command/query, call one application service, map structured errors | Opening stores directly to advance state, selecting adapters, manufacturing authority, deciding retries, or implementing run/workload/change transitions |
| Stores | Enforce persistence, uniqueness, integrity, transaction, and CAS boundaries | Deciding policy, approval, retry, resume, adapter selection, workload admission, or candidate promotion |
| Adapters/drivers | Translate approved invocations to concrete providers and report outcomes; deny on local safety preconditions where applicable | Granting capability, widening data access, selecting deployment, approving itself, mutating kernel state directly, bypassing gateway verification |
| Python SDK | Authoring/client ergonomics and policy proposals | Direct privileged side effects in policy callbacks, independent verifier/gateway/state/replay semantics, broad inherited permissions |
| TypeScript types/client | Generated/schema-aligned types and thin daemon client | Runtime implementation, local state-machine transitions, verifier decisions, direct store/gateway behavior |
| CLI | Public command/query client and explicit embedded-local composition where allowed | Hidden privileged backdoor, direct database edits for ordinary operator paths, alternate runtime semantics |
| Tests/examples | Contract and scenario evidence through public surfaces | Private store mutation or direct adapter calls presented as user-visible runtime behavior |

The future mutation-owner registry should include at least these rows before CI
enforcement begins.

| Mutation family | Current owner | Proposed v2 owner | Notes |
| --- | --- | --- | --- |
| `SubmitAction` and action outcome | `splendor-gateway` | Driver Gateway | Adapter execution remains impossible before verification |
| State commit and state head update | `splendor-kernel` plus `splendor-store` persistence today | Evidence/State Service plus store persistence | Store is not the transition decider |
| Trace event append and ordering | `splendor-kernel` plus `splendor-store` persistence today | Evidence/Event Log | Trace is runtime contract, not logging |
| Run/tick lifecycle | `splendor-kernel` | Agent Instance Controller through kernel facade | Kernel facade must not keep a duplicate divergent loop |
| Message delivery/delegation | `splendor-kernel` local message/delegation modules | Message/Delegation Service | Messages must not become permission tokens |
| Work-order admission | `splendor-kernel`/daemon boundary today | Authority plus fabric/agent admission as defined by RFC | Signed, scoped, non-expired, non-revoked work orders remain required |
| Daemon API endpoint mutation | No endpoint is owner by itself | Thin daemon over application command/query | Endpoint cannot be second owner |

## Migration Exceptions

These exceptions are proposed tracking entries. They are not blanket permission to
add new reverse edges or direct mutation paths.

| Exception ID | Current edge or location | Owner | Allowed scope | Exit criteria |
| --- | --- | --- | --- | --- |
| `MIG-137-DAEMON-STORES-GATEWAY` | `splendor-daemon -> splendor-store`, `splendor-daemon -> splendor-gateway` | Daemon/API owner with kernel facade owner | Existing 0.1 daemon composition and handlers only | Every mutating endpoint calls a public kernel application command/query; handler modules do not open stores, select adapters, or advance state machines; architecture check blocks new direct handler use |
| `MIG-137-CLI-EMBEDDED-LOCAL` | `splendorctl -> splendor-store`, `splendorctl -> splendor-gateway`, `splendorctl -> splendor-adapter-filesystem`, `splendorctl -> splendor-adapter-http` | CLI owner with kernel facade owner | Existing embedded-local CLI workflows only | Local composition is isolated behind an explicit embedded-local module; ordinary remote/operator commands use public APIs; new direct store/adapter usage outside that module fails policy |
| `MIG-137-KERNEL-MONOLITH-FACADE` | `splendor-kernel` owns runtime, scheduling, tenancy, state/trace facades, messages, fleet/governance hooks today | Kernel owner plus future RFC owners | Compatibility fixes and 0.1 invariant maintenance only | Accepted RFCs define authority/evidence/fabric/agent/change splits; kernel delegates to one owner per mutation; 0.1 conformance and migration fixtures pass |
| `MIG-137-SDK-HANDWRITTEN-ERGONOMICS` | `python/splendor` and `typescript/packages/*` contain hand-written ergonomic surfaces | SDK/API owner with types owner | Stable 0.1 ergonomics and client calls only | Generated or schema-parity contract is accepted; SDKs remain thin; checks reject privileged side effects and independent kernel semantics |
| `MIG-137-ADAPTER-MATURITY-GAP` | Adapter crates execute filesystem, HTTP, and robotics effects through current gateway contracts | Adapter boundary owner with gateway owner | Existing 0.1 adapter contracts and examples only | Driver manifest/maturity RFC is accepted; adapter conformance includes denial, failure, timeout/retry, secret/data scope, replay suppression, and physical local-veto evidence where relevant |

An exception cannot permit gateway bypass, replay side effects, self-approval,
raw secret persistence, direct low-level physical control, protected-data leakage,
or permission laundering. If an exception needs any of those, the design is
invalid rather than temporarily allowed.

## Acceptance Criteria Coverage

| Issue #137 acceptance item | Covered by |
| --- | --- |
| Compare current package ownership and proposed v2 ownership in a table | `Current Package Ownership Vs Proposed V2 Ownership` |
| Mark proposed crate/package split as RFC-required with migration boundary | `Proposed Package Splits And RFC Boundary` |
| Specify minimal architecture-policy check, including checks and deliberate non-checks | `Minimal Architecture-Policy Check Spec` |
| Prohibit daemon handlers, stores, adapters, SDKs, and CLIs from becoming duplicate mutation owners | `Duplicate Mutation-Owner Prohibition` |
| Give migration exceptions owners and exit criteria | `Migration Exceptions` |

## Reviewer Guidance

- Treat this as a planning artifact, not accepted architecture policy.
- Confirm future implementation PRs still follow `AGENTS.md`, `docs/rules/*`, and `docs/spec/0.1/*` first.
- Require RFCs before accepting package splits, public schema changes, gateway contract changes, verifier pipeline changes, daemon API breaking changes, SDK breaking changes, distributed identity changes, governance semantic changes, or physical/device action model changes.
- Reject any architecture-policy implementation that makes the imported proposed JSON normative without an accepted RFC and a migration plan.
