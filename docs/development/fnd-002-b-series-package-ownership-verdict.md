# FND-002 B-Series Package Ownership and Responsibility Verdict

**Date:** 2026-07-24

**Scope:** `FR-0.2-01`, `V2-FND-0`, bounded `FND-002` provider-ownership correction

**Status:** Bounded architecture correction accepted; merge readiness remains subject to full validation and required CI

## Verdict

The B-series correction has a sound bounded architecture direction. It removes
concrete acceptance-provider behavior from the production daemon, makes the
production daemon explicitly adapterless, keeps adapter execution behind the
gateway, and adds a fail-closed lower-bound guard for the current Rust package
graph.

Final code review found and the follow-up correction resolved two deterministic
contradictions in the migrated acceptance harness. S6 now verifies the bounded
gateway error instead of provider-private text. S9 now compares the stable
provider effect-state projection around replay while retaining the complete
signed evidence envelopes as audit artifacts.

The repository is **not yet fully organized around one semantic owner per
responsibility**. Important pre-existing ownership and client-boundary defects
remain and are listed below. This change must therefore be described as partial
FND-002 progress, not clean-architecture completion.

## Decision basis

The assessment applies the package map and one-owner rules in:

- `AGENTS.md`;
- `docs/rules/v2/architecture/architecture.md`;
- `docs/rules/v2/architecture/clean-architecture-rules.md`;
- `docs/rules/v2/architecture/architecture-policy-plan.md`; and
- `docs/rules/v2/catalog/complete_implementation_task_catalog.md` (`FND-002`).

The key tests are:

1. one package decides each privileged transition or state machine;
2. transports translate and composition roots wire, rather than own service
   semantics;
3. stores persist already-validated records;
4. provider-specific effects remain outside core packages and execute only
   through the gateway;
5. public compatibility surfaces delegate rather than create shadow runtimes;
6. enforceable dependency rules are checked mechanically and fail closed; and
7. tests exercise the production-selected path, including denial and failure.

## Responsibility map after this correction

| Surface | Responsibility | Verdict |
| --- | --- | --- |
| `crates/splendor-types` | Behavior-free canonical IDs and serialized contracts | Correct inward dependency target. A duplicate public `RunStatus` remains in the daemon. |
| `crates/splendor-store` | Persistence traits and engines | Remains the persistence boundary; broader state/evidence ownership migration is outside this correction. |
| `crates/splendor-authority` and `crates/splendor-kernel` | Authority decisions, invariant wiring, and the compatibility runtime facade | Action authority remains kernel-routed. Local-run lifecycle ownership is still split with daemon state. |
| `crates/splendor-gateway` | Verifier chain and the sole adapter-invocation boundary | Correct owner for verified execution. Adapter failures are projected conservatively rather than treated as known-safe successes or retries. |
| `crates/splendor-daemon` | Authenticated transport translation and process composition | Improved: production composition is adapterless and accepts only injected adapter mappings. Not yet thin enough because it still owns local-run lifecycle state. |
| `tests/e2e/use-cases/acceptance-host` | Unpublished outer composition for concrete acceptance adapters | Correct owner for this test-only provider behavior. It is not part of the production daemon or a public runtime package. |
| `tests/e2e/use-cases/fixtures` | Acceptance-only provider protocol, profiles, receipts, and retained-evidence verification | Correctly isolated as conformance infrastructure; it does not establish a production provider protocol or durability guarantee. |
| `scripts/architecture/check-dependency-policy.py` | Current Cargo package identity, dependency, cycle, provider-owner, and daemon-shape guard | Valid lower-bound enforcement. It is deliberately not a universal source-effect or semantic-owner checker. |
| `python/splendor` | Public Python client and stable compatibility runtime | Still contains unresolved transport risk and a separate Python execution owner; neither is corrected here. |
| `typescript/packages/*` | Canonical client/type surfaces | Remains a thin-client comparison surface; no TypeScript responsibility migration is part of this correction. |

## Accepted improvements

### 1. Production daemon no longer owns a concrete acceptance provider

`crates/splendor-daemon/src/process.rs` separates
`run_adapterless` from `run_with_action_adapters`. The production binary in
`crates/splendor-daemon/src/main.rs` selects `run_adapterless`; it does not
construct a fake action adapter, a device simulator transport, or a provider
success response.

Concrete acceptance behavior now lives under
`tests/e2e/use-cases/acceptance-host`. The dedicated host constructs the
acceptance adapter and passes it through the daemon's non-authorizing
`ConfiguredActionAdapters` composition input. Dedicated Docker acceptance
stages include the host and fixture material; the production stage does not.

This establishes the intended direction:

```text
unpublished acceptance host
  -> daemon composition input
    -> gateway verification
      -> injected acceptance adapter
        -> acceptance-only provider process
```

It does not create an adapter bypass: an injected adapter remains inert until
the gateway has completed the required verifier path.

### 2. Missing providers fail before run mutation

Daemon admission checks the configured action-adapter set before constructing
run trace/state/runtime records. Missing direct-policy or physical-action
providers return `action_adapter_unavailable` rather than selecting a recording
adapter or fabricated success path.

`crates/splendor-daemon/tests/runtime_daemon_api_tests.rs` covers the denial and
asserts that neither a run nor the create-idempotency record is committed.

### 3. Gateway provider failure remains conservative

`crates/splendor-gateway/src/lib.rs` bounds adapter-provided failure text and
retains an unknown/non-retryable/uncertain taxonomy when the adapter cannot
provide stronger trusted evidence. Provider failure does not silently become an
allow, a retryable effect, or a known no-effect result.

### 4. Acceptance evidence is explicit and scoped

The acceptance host and fixture provider use a closed private-v3 operation
profile, scoped credentials, signed provider receipts, bounded process-epoch
replay state, and retained-evidence verification. Scenario expectations and
semantic retry identities are explicit.

These mechanisms strengthen acceptance evidence only. They do **not** claim a
public provider protocol, restart-durable anti-replay, production PKI, or
exactly-once external effects.

### 5. Current Rust package policy is mechanically guarded

`scripts/architecture/check-dependency-policy.py` checks exact governed package
identities, allowed internal edges, cycles, provider-client placement, and the
adapterless daemon shape. Its self-tests cover duplicate identity, same-name
substitution, path, exclusion, cycle, and policy-order cases.

The guard is intentionally scoped to the current Cargo graph. Python imports,
TypeScript references, runtime-loaded code, and general semantic ownership
require their own checks; this script does not pretend to prove them.

## Residual findings and disposition

| Severity | Finding | Disposition |
| --- | --- | --- |
| High security | The public Python daemon client does not yet enforce the accepted RFC 0011 bearer-transport boundary for URL, redirect, and reflected-error handling. | Rejected correction attempts were removed from this change. Repair in a separately reviewed security slice; do not describe the client as hardened. |
| Critical architecture / compatibility gated | Stable Python `KernelRuntime` directly executes registered callbacks and independently owns enforcement, state, trace, and replay behavior. | Requires an accepted compatibility/RFC migration into one Rust/daemon owner. Do not remove or silently redirect the stable surface in this correction. |
| High architecture | Daemon `RunSlot` owns status, pending approval, and transition decisions while the kernel authority handle separately owns effect admission. Trace failure can leave inspectable lifecycle state and effect authority out of sync. | Move local-run lifecycle decisions behind one kernel compatibility owner in a later bounded correction. This blocks any thin-handler or one-lifecycle-owner claim. |
| Medium contract ownership | `RunStatus` is duplicated in `splendor-daemon` and `splendor-types`, with a manual identity conversion and stale reference vocabulary. | Preserve the daemon import path through a compatibility re-export in a later contract-checked change. |
| Medium packaging | `splendor-bindings` imports `splendor.runtime` but does not declare the `splendor` distribution as a runtime dependency. | Add the packaging edge and clean-wheel installation evidence separately; the production image is not currently selecting this optional facade. |
| Blocked design | Durable caller-attributed denial before run creation lacks accepted Event/Audit owner and durability contracts. | RFC 0025 remains Draft/blocked and grants no implementation authority. It is not part of this change. |

## Corrected acceptance defects

### S6 requires text that the gateway deliberately removes

`crates/splendor-gateway/src/lib.rs` converts an adapter-controlled
`AdapterError::Failed` message to the stable public error `adapter failed`.
This is intentional: provider text must not become trusted public outcome
evidence.

`tests/e2e/use-cases/scenarios/uc_e2e_s6_physical_edge/run.py` and the S6 checks
in `tests/e2e/use-cases/reporting/aggregate_report.py` now require exactly that
bounded public error and reject retained provider-private reason text. The
reporting fixture follows the real gateway contract, and a regression mutation
test proves that an unredacted private reason fails validation.

### S9 compares evidence reads instead of effect state

Every provider-evidence read intentionally receives a fresh request nonce and a
new signed snapshot sequence. S9 now applies the same stable provider
effect-state projection used by the other migrated scenarios when constructing
its replay before/after counters. The complete signed reads remain in
`action-provider-evidence.json`; only the no-side-effect comparison excludes
per-read freshness fields. Regression coverage proves that freshness changes
compare equal while an effect-counter change does not.

## Validation boundary

The accepted correction has local evidence for:

- dependency-policy self-tests and current-tree policy checks;
- workspace unit and integration tests;
- daemon, gateway, acceptance-host, fixture, reporting, and anti-drift tests;
- static Docker/Compose topology checks;
- native S2 functional execution with no replay adapter invocation; and
- formatting, lint, contract, conformance, and documentation checks.

Docker was unavailable during closeout. Container-backed S2/S5/S6/S7/S9/S10,
container isolation, and `G00` are therefore `not_exercised`, not passed. Native
S2 evidence is `functional_only` and must not be used as role-isolation proof.
Inherited workspace dependency advisories also remain a disclosed limitation.

The focused S6/S9 reporting regression suite passes after the corrections. Full
container-backed scenario claims remain limited to the validation actually run
and the required CI result.

## PR claim boundary

This correction **may claim**:

- bounded `FR-0.2-01` / `FND-002` progress;
- an adapterless production daemon;
- concrete acceptance-provider composition in an unpublished outer host;
- fail-closed missing-provider admission before run mutation;
- conservative gateway handling of provider failures; and
- lower-bound enforcement of the current Cargo package graph.

These remain bounded architecture claims. The S6/S9 contradictions are
corrected, but unavailable checks must still be reported as `not_exercised`
rather than inferred from focused tests.

It **must not claim**:

- repository-wide clean architecture or complete `FND-002`;
- a secure or remediated public Python daemon client;
- one canonical local-run lifecycle owner;
- elimination of all duplicate contracts or undeclared package edges;
- a public or restart-durable provider receipt protocol;
- container isolation, Docker-backed use-case completion, or `G00`; or
- accepted or implemented RFC 0025 behavior.

## Final organization judgment

The changed provider path now has a defensible owner and dependency direction:
production composition is adapterless, concrete provider behavior is outside
the daemon, verification remains in the gateway, and acceptance evidence is
isolated from public runtime claims. That slice is materially better organized
and can be reviewed independently. Its acceptance assertions now match the
implemented gateway redaction and replay-effect boundaries.

The repository as a whole still has significant ownership debt. The next
highest-value corrections are the public Python bearer boundary and the split
daemon/kernel lifecycle owner, followed by canonical `RunStatus` ownership and
the Python bindings package edge. Those findings should remain explicit rather
than being hidden behind a broad architecture-complete label.
