# Use-Case E2E Acceptance Harness

This directory contains the foundational `UC-E2E-S0` harness and the
`UC-E2E-S1` local governed action loop scenario. S0 validates the harness,
report contract, deterministic fixtures, OpenAPI contract visibility, and
anti-drift gates. S1 validates a local CLI-driven governed loop through the real
gateway, HTTP/filesystem adapters, state graph, trace store, and inspect-only
replay suppression.

## Commands

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only
bash scripts/e2e/verify-use-case-acceptance.sh --contract-only
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

`--scenario UC-E2E-S0` and `--all` run through Docker Compose and fail if Docker
Compose is unavailable. Static-only execution is limited to `--contract-only`
and `--anti-drift-only`. `--reuse-build` is accepted for compose-backed runs.
`--inside-compose` is an internal guard used by the `e2e-runner` service.

## Evidence

Reports are written under:

```text
target/splendor-e2e/use-case-acceptance/report.json
target/splendor-e2e/use-case-acceptance/report.md
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S0/
```

Report generation fails if required S0/S1 evidence artifacts are absent or
empty; the harness does not create green placeholder trace/state/replay/audit
evidence.

## Compose topology

`docker-compose.acceptance.yml` provides active S0 service roles: runner, local
daemon, central manager placeholder, resident node placeholders, device sim,
fake external services, telemetry sink, and toxiproxy. The local daemon remains
loopback-only; compose makes the runner share the daemon container network
namespace so it can call documented `/health` and `/capabilities` on
`127.0.0.1` without publishing daemon ports or binding all interfaces. The S0
probe supplies schema-aligned caller credentials for those read-only endpoints.
S1 uses `splendorctl` as the documented public boundary. It signs a scoped local
work order, runs HTTP and filesystem actions through the real action gateway,
exports trace/state evidence through CLI commands, and runs inspect-only replay
while checking that the HTTP fixture counter and artifact checksum do not change.
S1 deliberately does not add remote messaging, fleet placement, governance
approval workflows, or physical/edge actions.

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
self-tests, and report aggregation. `UC-E2E-S1` adds executable local governed
loop evidence. S2-S10 remain blocked/not-yet-covered until their scenario PRs add
executable public-boundary evidence.
