# UC-E2E-S8 Replay, Audit, Compatibility, Migration

## 1. Objective

Validate the 0.1 acceptance path for replay, audit explanation, schema compatibility, and migration by consuming real machine-readable outputs from prior use-case scenarios and proving that replay remains non-side-effectful by default.

Milestone: `Splendor0.1-dev` post-implementation acceptance.
Sprint: `UC-E2E-S8`.
FRs: `FR-0.1-01` through `FR-0.1-08`, with replay, trace, state, governance, physical/edge, and API compatibility evidence imported from prior milestones.

## 2. Functional Scope

S8 imports trace, state, replay, audit, and schema evidence from `UC-E2E-S1`, `UC-E2E-S3`, `UC-E2E-S4`, `UC-E2E-S5`, `UC-E2E-S6`, and `UC-E2E-S7` under `tests/e2e/use-cases/scenarios/uc_e2e_s8_replay_audit_compat/`.

The scenario validates trace chain digests, state hashes, clean-workspace import, inspect-only replay, read-only re-evaluation, policy comparison, verifier explanation, supported dev-fixture migration to the 0.1 stable line, generated Rust/Python/TypeScript type parity evidence, and audit package export.

## 3. Non-Goals

- No replay mode executes side effects by default.
- No production external credential is accepted for replay.
- No broad historical migration is claimed beyond documented supported dev fixtures.
- No private runtime helper is used to claim E2E correctness.
- No S9 failure-injection or S10 final-journey coverage is claimed.

## 4. Public Contracts Changed

The harness command now accepts:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8
```

The aggregate report now recognizes S8 as executable and keeps only S9-S10 blocked/not-yet-covered after S0-S8 pass.

S8 uses the public acceptance artifact boundary from prior scenarios: `scenario-report.json`, `trace-export.jsonl`, `state-export.json`, `replay-report.json`, `audit-report.json`, and schema parity artifacts. It does not call private Rust internals.

## 5. Runtime Primitives Touched

- `replay`
- `trace store`
- `state graph`
- `audit`
- `schema compatibility`
- `migration`
- `SDK/API/types`
- `docs/tests`

## 6. Trace Events Added Or Changed

S8 requires machine-readable evidence for:

- `replay.started`
- `replay.completed`
- `replay.failed`
- `replay.adapter_suppressed`
- `replay.policy_compared`
- `replay.verifier_explained`
- `trace.imported`
- `trace.rejected`
- `state.imported`
- `state.rejected`
- `schema.migrated`
- `schema.rejected`
- `audit.exported`

These are emitted by the S8 scenario evidence package and validated by `aggregate_report.py`.

## 7. State Behavior Added Or Changed

S8 copies prior `state-export.json` artifacts into `artifacts/UC-E2E-S8/clean-import-workspace/`, validates their exported state hashes against scenario-level state hashes, and rejects a tampered state copy with `state_hash_mismatch` before replay continuation.

## 8. Verifier/Gateway Behavior Added Or Changed

S8 does not introduce a new gateway path. It explains prior verifier decisions from public scenario artifacts for approvals, ordinary denials, quota failures, work-order rejection, data-scope denial, and safety denial. Audit export fails if any required negative path omits reason codes.

## 9. Replay Behavior

S8 validates four replay modes without side effects:

- inspect-only replay;
- read-only re-evaluation;
- policy comparison;
- verifier explanation.

Side-effectful replay requests are rejected unless separately gated and explicitly marked. S8 records the negative case `side_effectful_replay_mode_rejected_without_gate` and verifies `side_effects_allowed_default: false`.

## 10. Failure Behavior

S8 validates these fail-closed paths:

- tampered trace chain rejected;
- state hash mismatch rejected;
- unsupported schema version rejected with migration guidance;
- side-effectful replay mode rejected without a gate;
- real external credential replay rejected;
- generated schema mismatch fails compatibility gate;
- audit export cannot omit denial reason codes.

## 11. Test Evidence

Primary command:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8
```

Aggregate command:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

Expected S8 artifacts include:

- `artifacts/UC-E2E-S8/trace-import-report.json`
- `artifacts/UC-E2E-S8/state-import-report.json`
- `artifacts/UC-E2E-S8/tamper-report.json`
- `artifacts/UC-E2E-S8/replay-report.json`
- `artifacts/UC-E2E-S8/schema-migration-report.json`
- `artifacts/UC-E2E-S8/audit-package.json`
- `artifacts/UC-E2E-S8/trace-export.jsonl`

## 12. Example Commands Or Fixtures

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8
python3 tests/e2e/use-cases/reporting/aggregate_report.py \
  --root . \
  --report-dir target/splendor-e2e/use-case-acceptance \
  --scenario UC-E2E-S8 \
  --mode scenario \
  --compose-file tests/e2e/use-cases/docker-compose.acceptance.yml
```

## 13. Future Extension Notes

S9 must add failure injection, quota pressure, bounded retry, and fail-closed reliability evidence. S10 must add the final cross-component journey. S8 intentionally leaves both blocked/not-yet-covered.
