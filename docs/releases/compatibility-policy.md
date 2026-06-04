# Splendor 0.1 Compatibility Policy

This policy summarizes the compatibility guarantee for the Splendor 0.1 stable
primitive line. It complements `docs/spec/0.1/schema-versioning.md` and
`docs/spec/0.1/api-stability.md`.

## Stable Compatibility Surface

0.1 patch compatibility covers documented public contracts only:

- stable primitive names, required fields, identity separation, extension rules,
  and enum values in `docs/spec/0.1/primitives.md`;
- schema versioning and deprecation rules in
  `docs/spec/0.1/schema-versioning.md`;
- named Rust, Python, TypeScript, and daemon API surfaces in
  `docs/spec/0.1/api-stability.md`;
- conformance report shape and fixture expectations in
  `docs/spec/0.1/conformance.md`;
- adapter maturity metadata and validation rules in
  `docs/spec/0.1/adapter-maturity.md`;
- operational behavior documented in `docs/operations/`.

Undocumented internals, private helpers, in-memory store implementations,
scheduler internals, test fixtures outside conformance, and package internals are
not stable even if they are currently visible in source.

## Patch Release Expectations

Patch releases in the 0.1 line must not:

- remove or rename stable required fields;
- change stable serialized enum spelling;
- collapse distinct identities such as `agent_id`, `run_id`, `trace_event_id`,
  `state_node_id`, `message_id`, `work_order_id`, `node_id`, or `instance_id`;
- convert fail-closed denial, pause, or intervention behavior into allow;
- let side-effectful actions bypass the Action Gateway;
- make replay execute side effects by default;
- let extensions grant permissions, approvals, credentials, work orders,
  policies, quotas, verifier outcomes, adapter routing, or gateway authority;
- remove stable daemon endpoints without a documented replacement;
- make SDK clients silently fall back to unauthenticated daemon communication;
- turn `trace_id` into a distinct public identity instead of a migration alias.

Patch releases may:

- add optional non-authorizing fields;
- accept dev-era aliases as input while continuing to emit stable names;
- add stricter validation that fails closed;
- add trace events for newly implemented behavior while preserving required
  ordering;
- add SDK convenience wrappers that preserve identity, scope, trace, state,
  gateway, verifier, quota, work-order, and replay semantics;
- clarify docs and examples without widening production claims.

## Minor 0.1-Compatible Releases

Minor releases that remain compatible with 0.1 may add documented optional
capabilities, endpoint parameters, SDK helpers, adapter manifest fields, or
conformance cases when older clients can ignore them safely or fail closed.

Minor releases must not use optional fields to create hidden authority, hidden
state ownership, direct side-effect execution, replay side effects, or permission
inheritance.

Breaking schema/API changes require a new version or RFC-backed migration path.

## Experimental Or Future Surface

The following are outside the stable 0.1 guarantee:

- production OAuth/OIDC provider, PKI management, fleet mTLS rollout, node
  bootstrap, universal transport negotiation, production remote daemon, or remote
  fleet authorization rollout;
- production fleet scheduler, autoscaler, multi-region placement optimizer,
  distributed consensus, arbitrary shared distributed memory, CRDT merge engine,
  or production migration orchestration;
- native Node/N-API binding, browser runtime, TypeScript runtime enforcement, or
  generated code internals not named as stable;
- enterprise SaaS surfaces, billing, admin console, marketplace, approval queue
  UI, broad workflow engine, enterprise IAM integration, or product-specific
  Harmony implementation;
- adapter marketplace, legal/vendor certification, production support policy, or
  physical safety certification;
- live hardware readiness, hard real-time robot control, motor control, raw
  actuator writes, firmware safety bypass, flight-controller replacement, PLC
  replacement, or ROS/native driver replacement.

## Deprecations And Migration

Deprecations must document:

- deprecated name;
- stable replacement;
- first release where the deprecation is documented;
- migration guidance;
- whether serializers still emit the old field;
- whether deserializers still accept the old field;
- removal target, if any.

Current migration guidance is in `docs/releases/0.1-migration.md`.

## Validation Baseline

Compatibility claims for a 0.1 patch or release candidate should include:

```bash
python conformance/0.1/run-conformance.py
python scripts/validate-adapter-manifests.py
npm test
python -m pytest python/tests/test_runtime.py -q
git diff --check
```

Run focused daemon/example validation when daemon or client docs are touched:

```bash
cargo test -p splendor-daemon
```

Passing these commands is release evidence for stable primitive compatibility. It
is not complete post-implementation use-case E2E acceptance and must not be
represented as production fleet, adapter certification, or physical safety
certification evidence.
