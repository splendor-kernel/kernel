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
daemon, acceptance manager, TLS resident nodes, an ephemeral resident-auth
fixture initializer, a controlled receipt-bearing action provider, fake external
services, telemetry sink, and toxiproxy. Local and resident roles use the
dedicated `acceptance-action-host` image target, not the production daemon image.
That unpublished host composes a closed fixture adapter set with a local provider;
the production `splendor-daemon` remains adapterless. One checked-in private-v3
manifest owns all 18 operation profiles. The initializer generates distinct
owner-only HMAC request credentials for local, cloud, VPC, and edge hosts, plus
a provider-only Ed25519 receipt key. Request credentials additionally bind exact
fixture artifact/data references or the provisioned physical node where those
resources apply. Each host mounts only its scoped request credential and the raw
receipt public key. The root runner receives root-owned runner-only evidence
material and performs a signed read/verification smoke before scenarios start.
Its short-lived HMAC request binds method, path, query, view, reader, audience,
provider epoch, timestamp, and nonce; the signed response repeats that binding
and a monotonic snapshot sequence. The runner cannot authenticate `/actions` or
forge a receipt. It also generates test-only
caller/work-order/policy keys and a TLS certificate in role-specific volumes; no
generated private material is written to source or evidence artifacts. The local daemon remains
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
`splendor.message.task_request.v2`, runs a specialist child run with narrower
authority, commits child and parent state, sends/consumes a typed
`splendor.message.task_response.v1`, and executes the orchestrator's internal
artifact action through the real action gateway. Negative branches cover
specialist external publish denial, unauthorized recipient rejection, malformed
current-v2 task-request rejection before delivery, overbroad delegated
permission/data-ref smuggling denial, cross-tenant delegation rejection, and
specialist quota exhaustion without mutating the orchestrator ledger. Replay
evidence is generated by `splendorctl replay` and written to `replay-report.json` and
`message-causal-graph.json` with `side_effects_replayed=false`.

S3 deliberately remains local-only. It does not add or claim daemon message API
coverage, remote transport, central fleet management, governance workflows,
distributed state migration, or physical/edge behavior.

S4 dispatches a signed, run-bound, single-adapter work order through the
acceptance manager to the actual resident TLS listener. The manager verifies the
fixture CA/hostname and mints fresh one-scope Ed25519 caller tokens; direct S4
state/trace/replay calls use the same closed bearer profile. Remote proposal
messaging uses a second narrow signed work order so work-order v1 pairings are
not inferred from unsigned metadata. The manager's own inbound API remains
explicit acceptance-only and is not production-authenticated.

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
high-level only. S2, S5, S6, S7, S9, and S10 retain provider-returned fixture
records and authenticated signed observations, including the envelope, public
key fingerprint/material, exact request binding, and decoded snapshot. Only
S5/S6/S7/S10 route those observations through the canonical externally anchored
aggregate verifier. On that path, retained key material is compare-only:
aggregation requires the setup-owned provider public-key path and checked-in
scenario expectations, and fails closed when either trust input is absent or
does not match. It also requires the exact reader scope, one signing
key/provider epoch, unique nonces, and increasing sequences within the retained
report chain. S2/S9 retain signed observations for scenario diagnostics, but
their aggregate loaders do not currently apply that canonical external trust
path; an S9 report alone is not cryptographic proof of retry behavior. Live
sequence replay detection is bounded process-local state; it is not durable
across verifier process restart and makes no durable anti-replay claim.
S5/S6/S7/S10 use one canonical private-v3 projection for marker, artifact,
data/SQL, sensor, and physical output families.
The acceptance host verifies provider-origin receipts before parsing their payloads,
then enforces manifest-selected status, output-family, digest, coordinate, and
postcondition predicates. These fixture receipts remain adapter outcomes rather
than kernel authority. Deduplication is bounded to one provider process epoch;
a provider restart requires host restart/rebinding and makes no restart-durable
exactly-once claim. There is no private-v2 negotiation or fallback. Static
Compose validation is not a runtime pass; Docker scenarios are `not_exercised`
when the Docker daemon is unavailable.

`run-native-acceptance-host-s2.sh` is a functional fallback only. It removes its
entire dedicated runtime tree before generating only the local request role, and
retained reports label native execution `functional_only` and Docker isolation
`not_exercised`. Because provider and host share the invoking Unix identity, the
native run is never evidence of provider-private-key or compromised-host
isolation.

Independent aggregation re-derives the migrated approval contracts from retained
API traffic rather than scenario summary booleans. S5 proves active raw-evidence
rejection and acknowledged resident receipt revocation without tick, state, or
adapter effects. S6 proves physical v2 server-node binding, wrong-node pre-claim
rejection, one safety-verified execution, and replay denial. S10 proves manager
submit/dispatch ordering, exact receipt retry, active raw rejection, both
claim/revoke race outcomes, and token/signature-free retained evidence. Retained
authority-receipt signatures are a blocking aggregation failure.

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
