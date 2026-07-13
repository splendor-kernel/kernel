# Splendor Containerized E2E Acceptance Harness

**Date:** 2026-06-02
**Status:** Proposed harness specification for post-implementation use-case validation
**Intended repository placement:** `docs/development/containerized-use-case-e2e-harness.md`
**Companion acceptance pack:** [`docs/rules/verifiable_criteria/use-case-e2e-through-0.1.md`](../rules/verifiable_criteria/use-case-e2e-through-0.1.md)

This document specifies the containerized harness required to run Splendor's full use-case E2E acceptance sprints after all implementation sprints are complete.

---

## 1. Required repository layout

```text
scripts/e2e/
  verify-use-case-acceptance.sh
  collect-use-case-evidence.sh
  assert-no-product-drift.sh
  assert-api-contract.sh

tests/e2e/use-cases/
  docker-compose.acceptance.yml
  README.md
  fixtures/
    tenants/
    work-orders/
    caller-credentials/
    policies/
    messages/
    data-refs/
    device-profiles/
    external-services/
    replay/
  scenarios/
    uc_e2e_s0_harness/
    uc_e2e_s1_local_loop/
    uc_e2e_s2_management_api/
    uc_e2e_s3_multi_agent_delegation/
    uc_e2e_s4_fleet_dispatch/
    uc_e2e_s5_governance/
    uc_e2e_s6_physical_edge/
    uc_e2e_s7_data_isolation_artifacts/
    uc_e2e_s8_replay_audit_compat/
    uc_e2e_s9_failure_injection/
    uc_e2e_s10_final_journey/
  reporting/
    report.schema.json
    aggregate_report.py
    render_report_md.py
  contract/
    openapi_contract_test.py
    schema_parity_test.py
    ts_client_contract.test.ts
    python_sdk_contract_test.py
  anti_drift/
    forbidden_scope_patterns.txt
    required_boundary_assertions.toml
    scan_results.schema.json
```

---

## 2. Required aggregate command

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

Supported narrower commands:

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S1
bash scripts/e2e/verify-use-case-acceptance.sh --contract-only
bash scripts/e2e/verify-use-case-acceptance.sh --anti-drift-only
bash scripts/e2e/verify-use-case-acceptance.sh --reuse-build
```

Every mode must still run in containers unless it is explicitly a static repository scan.

---

## 3. Docker Compose topology skeleton

The exact image names may change, but the service roles must remain stable. The
following is an architectural sketch, not a runnable copy. The executable source
is `tests/e2e/use-cases/docker-compose.acceptance.yml`. In that composition the
local daemon sets explicit `local_dev`, the manager sets explicit
`local_acceptance` plus outbound signer/keyring/CA file paths, and resident nodes
set explicit instance/trust/work-order/policy/TLS files. An initializer generates
test-only material into an untracked volume before those services start; resident
URLs use HTTPS and no resident inherits local development keys.

```yaml
services:
  e2e-runner:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["bash", "scripts/e2e/verify-use-case-acceptance.sh", "--inside-compose", "--all"]
    environment:
      SPLENDOR_E2E_MODE: "acceptance"
      SPLENDOR_E2E_REPORT_DIR: "/workspace/target/splendor-e2e/use-case-acceptance"
      SPLENDOR_DAEMON_URL: "http://splendor-daemon-local:8080"
      SPLENDOR_MANAGER_URL: "http://central-manager:8081"
      SPLENDOR_HTTP_FIXTURE_URL: "http://fake-http-service:8082"
      SPLENDOR_ARTIFACT_FIXTURE_URL: "http://fake-artifact-store:8083"
      SPLENDOR_GOVERNANCE_FIXTURE_URL: "http://fake-governance-plane:8084"
      SPLENDOR_TELEMETRY_FIXTURE_URL: "http://fake-telemetry-sink:8085"
    depends_on:
      - splendor-daemon-local
      - central-manager
      - resident-cloud-node
      - resident-vpc-node
      - resident-edge-node
      - device-sim
      - fake-http-service
      - fake-artifact-store
      - fake-governance-plane
      - fake-telemetry-sink
      - toxiproxy
    volumes:
      - ../..:/workspace
      - e2e-state:/workspace/target/splendor-e2e

  splendor-daemon-local:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["splendor-daemon", "--config", "/fixtures/local-daemon.yaml"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  central-manager:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["splendor-manager", "--config", "/fixtures/central-manager.yaml"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  resident-cloud-node:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["splendor-daemon", "--resident-node", "--config", "/fixtures/cloud-node.yaml"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  resident-vpc-node:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["splendor-daemon", "--resident-node", "--config", "/fixtures/vpc-node.yaml"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  resident-edge-node:
    build:
      context: ../..
      dockerfile: Dockerfile
    command: ["splendor-daemon", "--resident-node", "--config", "/fixtures/edge-node.yaml"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  device-sim:
    image: python:3.12-slim
    command: ["python", "/fixtures/device-sim/server.py"]
    volumes:
      - ./fixtures:/fixtures:ro

  fake-http-service:
    image: python:3.12-slim
    command: ["python", "/fixtures/external-services/http_fixture.py"]
    volumes:
      - ./fixtures:/fixtures:ro

  fake-artifact-store:
    image: python:3.12-slim
    command: ["python", "/fixtures/external-services/artifact_store.py"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  fake-governance-plane:
    image: python:3.12-slim
    command: ["python", "/fixtures/external-services/governance_plane.py"]
    volumes:
      - ./fixtures:/fixtures:ro

  fake-telemetry-sink:
    image: python:3.12-slim
    command: ["python", "/fixtures/external-services/telemetry_sink.py"]
    volumes:
      - ./fixtures:/fixtures:ro
      - e2e-state:/var/lib/splendor

  toxiproxy:
    image: ghcr.io/shopify/toxiproxy:latest

volumes:
  e2e-state:
```

---

## 4. Runner phases

The runner must execute phases in this order:

1. **Build and version capture**
   - `cargo metadata`
   - Rust crate versions
   - Python package version
   - TypeScript package version
   - OpenAPI schema version
   - Docker image digest/topology hash

2. **Static anti-drift scan**
   - no scenario test claims E2E while importing private runtime helpers;
   - no direct adapter execution from scenario code;
   - no anonymous non-dev daemon/fleet calls;
   - no test endpoint outside OpenAPI/contract allowlist;
   - no forbidden physical action in allowed fixture lists;
   - no replay side-effect mode as default;
   - no product-scope terms used as required acceptance behavior: marketplace, billing, universal memory, bare metal, chat-first UX, real-time motor control.

3. **API contract validation**
   - OpenAPI 3.1 parse;
   - required operation IDs exist;
   - schemas include required fields and stable enums;
   - generated TypeScript/Python/Rust fixture parity;
   - request/response validation for all scenario traffic;
   - undocumented endpoint detection.

4. **Component readiness**
   - local daemon ready;
   - central manager ready;
   - resident nodes registered or ready to register;
   - fake external services ready;
   - device simulator ready;
   - fault proxy ready.

5. **Scenario execution**
   - run S0 through S10 independently;
   - preserve scenario artifacts;
   - stop on blocking invariant failure;
   - continue on ordinary scenario failure only when collecting comparison evidence is explicitly configured.

6. **Replay/audit execution**
   - collect trace/state exports from scenario outputs;
   - run inspect-only replay;
   - run policy comparison and verifier explanation where applicable;
   - assert no side effects during replay.

7. **Report aggregation**
   - write `report.json`;
   - render `report.md`;
   - include FR/primitive/component/API coverage;
   - include blocking failure list;
   - include artifact paths and checksums.

---

## 5. Required test technologies

Use the repository's real stack. The exact test frameworks may vary, but all layers must be represented:

| Layer | Required evidence |
| --- | --- |
| Rust | Integration tests for runtime/gateway/state/trace/replay/fleet/governance/device contracts through public crates or daemon paths. |
| Python | SDK policy/perceptor/constraint/trace subscription and client workflows; no direct privileged side effects. |
| TypeScript | `@splendor/types` and `@splendor/client` schema/client parity with OpenAPI and daemon behavior. |
| OpenAPI | Contract parse, operation coverage, request/response validation, schema evolution checks. |
| CLI | `splendorctl` run/trace/state/replay and management workflows where applicable. |
| Docker | Standard compose topology and report artifacts from clean environment. |
| External fixtures | HTTP/artifact/governance/telemetry/device simulator beyond Splendor boundaries only. |

---

## 6. Anti-drift scan rules

Static and runtime anti-drift checks must cover at least:

### Forbidden default behavior

```text
side_effect_without_gateway
verifier_failure_allows_action
trace_write_failure_allows_side_effect
state_commit_failure_advances_tick
replay_executes_adapter_by_default
management_token_authorizes_action
telemetry_authorizes_action_or_placement
health_authorizes_action_or_placement
capabilities_authorizes_action_or_placement
specialist_inherits_broad_permissions
raw_physical_action_accepted
anonymous_non_dev_request_accepted
```

### Forbidden product drift as acceptance requirement

```text
bare-metal kernel
chat-first architecture
enterprise SaaS UI
billing / marketplace
universal distributed mutable memory
full distributed consensus requirement
per-agent Docker image as default model
real-time robotics controller
raw motor control
production robotics certification claim
```

### Required boundary evidence

```text
public API or CLI or SDK path used
work order validated before run creation
action gateway invoked before adapter execution
verifier results recorded
trace events emitted
state node committed
replay side effects suppressed
caller attribution present for mutating API calls
redaction policy present for trace export
message schema validated before delivery
state handoff hash validated
approval token scoped and expiry checked
safety verifier executed before physical action
```

---

## 7. Evidence artifacts

Each scenario must write a subdirectory:

```text
target/splendor-e2e/use-case-acceptance/artifacts/<scenario-id>/
  scenario-report.json
  commands.log
  api-traffic.ndjson
  trace-export.jsonl
  state-export.json
  replay-report.json
  audit-report.json
  anti-drift-results.json
  stdout.log
  stderr.log
```

Scenario-specific optional artifacts:

```text
message-causal-graph.json
fleet-telemetry.json
placement-explanation.json
approval-flow.json
device-safety-evidence.json
trace-sync-report.json
schema-migration-report.json
fault-injection-report.json
```

---

## 8. Failure-mode matrix

| Failure mode | Must happen |
| --- | --- |
| Unsigned work order | Reject before run start; trace/audit reason. |
| Expired work order | Reject create/resume/dispatch. |
| Wrong audience | Reject before use. |
| Missing caller credential | Reject outside explicit local-dev mode. |
| Wrong scope | Reject endpoint call. |
| Gateway skipped | Block test; acceptance failure. |
| Verifier unavailable | Deny, pause, or intervention; never allow. |
| Adapter failure | Record failed outcome and trace; no fake success. |
| Trace write failure | Fail closed for side-effectful action. |
| State commit failure | Do not advance next tick. |
| Replay side-effect attempt | Reject by default and record reason. |
| Unsupported message schema | Reject before delivery. |
| Unauthorized recipient | Delivery denied/failure state. |
| Remote message duplicate | Idempotency prevents double apply. |
| Stale node heartbeat | Placement denied or policy-degraded with explanation. |
| State hash mismatch | Reject import/handoff/replay. |
| Expired approval | Cannot resume/execute. |
| Circuit breaker active | Matching action denied. |
| Kill switch active | Matching run/action cancelled or blocked. |
| Raw motor command | Reject at schema/adapter boundary. |
| Policy cache expired offline | Deny high-risk actions or request intervention. |
| Trace sync tamper | Detect and reject sync/import. |
| Cross-tenant data ref | Deny before adapter execution. |
| Missing trace redaction policy | Reject trace export. |

---

## 9. CI integration

Recommended CI jobs:

```yaml
jobs:
  use-case-e2e-acceptance:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - name: Build acceptance images
        run: docker compose -f tests/e2e/use-cases/docker-compose.acceptance.yml build
      - name: Run acceptance suite
        run: bash scripts/e2e/verify-use-case-acceptance.sh --all
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: splendor-use-case-e2e-acceptance
          path: target/splendor-e2e/use-case-acceptance
```

This job may be expensive compared with sprint-local tests, so it can be required for release candidates and scheduled nightly runs while scenario-level subsets run on pull requests that touch relevant boundaries.

---

## 10. Acceptance report review rubric

A reviewer should be able to answer these from the report alone:

- What source revision and container topology were tested?
- Which FRs and primitives were covered?
- Which public API operations were exercised?
- Which clients were used: CLI, Python, TypeScript, raw OpenAPI-validated HTTP?
- Which actions were allowed, denied, failed, paused, or required approval/intervention?
- Which state nodes and trace events prove the result?
- Did replay suppress side effects?
- Were caller credentials, work orders, approvals, and endpoint scopes validated?
- Were messages typed, delivered, denied, and replay-reconstructed?
- Were fleet/node/instance identities distinct and trace-linked?
- Did telemetry remain non-authoritative?
- Did physical/edge tests avoid low-level control?
- Which anti-drift rules passed or failed?
- What artifacts can be inspected manually?

---

## 11. Blocking acceptance failures

The acceptance suite must return non-zero when:

- any S0 anti-drift gate fails;
- OpenAPI/contract validation fails;
- generated schema parity fails;
- any scenario lacks positive, negative, or replay evidence;
- any scenario uses private helpers for E2E claims;
- any side effect bypasses gateway;
- any required verifier fail-open is observed;
- replay executes side effects by default;
- a raw physical action is accepted;
- trace/state evidence is missing or inconsistent;
- report generation fails.

---

## 12. Final harness rule

Containerized use-case acceptance is not a replacement for unit, integration, conformance, or sprint-specific tests. It is the final proof that those completed surfaces work together without product drift, unsafe shortcuts, or incomplete management/communication contracts.
