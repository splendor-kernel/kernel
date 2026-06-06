# Use-Case E2E Acceptance Harness

This directory contains the foundational `UC-E2E-S0` harness plus implemented
use-case scenarios through `UC-E2E-S10`. S0 validates the harness, report
contract, deterministic fixtures, OpenAPI contract visibility, and anti-drift
gates. S1 validates a local CLI-driven governed loop through the real gateway,
HTTP/filesystem adapters, state graph, trace store, and inspect-only replay
suppression. S2 validates the local management API/client contract. S3 validates
local multi-agent delegation and typed communication through documented public
crate APIs plus `splendorctl replay` causal graph output. S4-S10 progressively
cover fleet dispatch, governance, physical/edge safety, data-local artifacts,
replay/audit/schema compatibility, failure injection, and the final
cross-component acceptance journey.

## Commands

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only
bash scripts/e2e/verify-use-case-acceptance.sh --contract-only
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S0
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S2
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S3
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S4
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S5
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S6
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S7
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S8
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10
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
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S1/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S2/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S3/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S4/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S5/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S6/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S7/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S8/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S9/
target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S10/
```

Report generation fails if required implemented-scenario evidence artifacts are
absent or empty; the harness does not create green placeholder
trace/state/replay/audit evidence.

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
The negative branch proves URL allowlist and sandbox path traversal denials occur
as `action.denied` gateway outcomes with adapter non-execution evidence, and uses
deterministic trace/state failure injection to prove fail-closed behavior.
S1 deliberately does not add remote messaging, fleet placement, governance
approval workflows, or physical/edge actions.

S3 uses `crates/splendor-kernel/examples/uc_e2e_s3_multi_agent_delegation.rs` as
an executable public-crate acceptance path. It creates orchestrator and specialist
agent runtime contexts under one tenant, delegates a typed
`splendor.message.task_request.v1`, runs a specialist child run with narrower
authority, commits child and parent state, sends/consumes a typed
`splendor.message.task_response.v1`, and executes the orchestrator's internal
artifact action through the real action gateway. Negative branches cover
specialist external publish denial, unauthorized recipient rejection, unsupported
schema rejection before delivery, overbroad delegated permission/data-ref
smuggling denial, cross-tenant delegation rejection, and specialist quota
exhaustion without mutating the orchestrator ledger. Replay evidence is generated
by `splendorctl replay` and written to `replay-report.json` and
`message-causal-graph.json` with `side_effects_replayed=false`.

S3 deliberately remains local-only. It does not add or claim daemon message API
coverage, remote transport, central fleet management, governance workflows,
distributed state migration, or physical/edge behavior.

S10 is the final cross-component journey. It runs after its dependency scenarios
and validates a bounded field-intelligence package through public manager,
daemon, message, governance, device, trace, state, replay, and CLI signing
boundaries. Required S10 evidence includes API contract status, topology hash,
registry acceptance (`registry-report.json`), run/action/state/trace/message/
work-order/approval/node/instance/policy/circuit-breaker/kill-switch/artifact
IDs, trace/state exports, replay/audit explanations, anti-drift results, and an
FR/primitive coverage matrix. Required event evidence is accepted only when it is
backed by exported runtime traces, manager audit rows, or public API response
artifacts and is correlated to S10 run/work-order/message/node/instance or
governance IDs. The journey keeps cloud helpers proposal-only, telemetry
observational, replay side-effect-free by default, and physical actions
high-level only.

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
loop evidence. `UC-E2E-S2` adds executable management API/client contract
evidence. `UC-E2E-S3` adds executable local multi-agent delegation and replay
causal graph evidence. `UC-E2E-S4` through `UC-E2E-S10` add executable
public-boundary evidence for fleet, governance, physical/edge, data isolation,
replay/audit/schema compatibility, failure injection, and final cross-component
acceptance.
