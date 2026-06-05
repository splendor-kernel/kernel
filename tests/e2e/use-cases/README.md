# Use-Case E2E Acceptance Harness

This directory contains the foundational `UC-E2E-S0` harness for later use-case
acceptance scenarios. S0 validates the harness, report contract, deterministic
fixtures, OpenAPI contract visibility, and anti-drift gates. It does **not**
implement or mark S1-S10 scenario behavior as passing.

## Commands

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only
bash scripts/e2e/verify-use-case-acceptance.sh --contract-only
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

`--reuse-build` is accepted for compose-backed runs. `--inside-compose` is an
internal guard used by the `e2e-runner` service.

## Evidence

Reports are written under:

```text
target/splendor-e2e/use-case-acceptance/report.json
target/splendor-e2e/use-case-acceptance/report.md
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S0/
```

Report generation fails if required S0 evidence artifacts are absent.

## Compose topology

`docker-compose.acceptance.yml` provides active S0 fake boundary services plus
future service roles under the `future-scenarios` profile. The current daemon
binary binds `127.0.0.1` inside its own container for explicit local-dev mode,
so S0 does not weaken daemon defaults to make cross-container calls work.
Later scenarios must add guarded daemon topology only when authenticated caller
identity, scoped work orders, and gateway enforcement can be exercised safely.

## Anti-drift rules

The scanner fails closed on:

- private-helper-only E2E claims;
- direct adapter execution in scenario code;
- undocumented endpoint strings;
- anonymous non-dev daemon/fleet calls;
- replay success claims without side-effect suppression evidence;
- allowed low-level physical actions such as `set_motor_pwm` or firmware bypass.

Negative fixtures under `anti_drift/fixtures/negative/` prove those failures.

## Status text for loop tracker

`UC-E2E-S0` adds the acceptance harness entry point, deterministic fixture seed,
compose topology skeleton, OpenAPI contract status report, anti-drift scanner
self-tests, and report aggregation. S1-S10 remain blocked/not-yet-covered until
their scenario PRs add executable public-boundary evidence.
