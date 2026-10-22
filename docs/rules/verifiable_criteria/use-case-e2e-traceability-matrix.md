# Splendor Use-Case E2E Traceability Matrix

**Date:** 2026-06-02
**Status:** Proposed traceability matrix for post-implementation acceptance
**Intended repository placement:** `docs/rules/verifiable_criteria/use-case-e2e-traceability-matrix.md`

This matrix connects post-implementation use-case acceptance sprints to Splendor primitives, milestones, functional requirement groups, public APIs, and required evidence. It is designed for management and engineering review.

---

## 1. Scenario-to-component coverage

| Scenario | Runtime | Gateway | Verifiers | State | Trace | Replay | CLI | Python | TS | OpenAPI | Daemon | Messages | Fleet | Governance | Physical/Edge | Adapters |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S0 Harness | Partial | Boundary check | Boundary check | Evidence schema | Evidence schema | Evidence schema | Yes | Yes | Yes | Yes | Yes | Check | Check | Check | Check | Check |
| S1 Local loop | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Optional | Yes | No | No | No | No | FS, HTTP |
| S2 API contract | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Optional | Optional | No | Action path only |
| S3 Multi-agent | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Yes | Yes | Optional | Yes | Yes | No | No | No | FS/data fixture |
| S4 Fleet | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Yes | Yes | Yes | Yes | Yes | Optional | No | HTTP/artifact fixture |
| S5 Governance | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Yes | Yes | Yes | Optional | Yes | Yes | No | Artifact/governance |
| S6 Physical/edge | Yes | Yes | Safety | Yes | Yes | Yes | Optional | Optional | Optional | Yes | Yes | Yes | Yes | Yes | Yes | Device sim |
| S7 Data/artifacts | Yes | Yes | Data scope | Yes | Yes | Yes | Optional | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Optional | Data/artifact |
| S8 Replay/audit/compat | Yes | Suppression | Explanation | Import/export | Import/export | Yes | Yes | Yes | Yes | Yes | Yes | Causal graph | Trace sync | Audit | Explanation | Suppressed |
| S9 Failure injection | Yes | Yes | Yes | Failure | Failure | Yes | Optional | Optional | Optional | Optional | Yes | Failure | Failure | Failure | Failure | Faulted |
| S10 Final journey | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | All available |

---

## 2. Milestone and FR coverage

| Milestone | Functional requirement theme | Required scenario coverage |
| --- | --- | --- |
| `0.01-dev` | local loop, identities, percept-policy-constraint-gateway-verifier-adapter-outcome-state-trace, permissions/quotas, persistent state, append-only trace, replay, Python SDK, CLI | S1 is primary; S2 validates daemon/clients; S8 validates replay/compat; S9 validates failure; S10 validates aggregate. |
| `0.02-dev` | message schema, local router, inbox/outbox, trace-linked messages, delegation, per-agent isolation, daemon API, TypeScript client, multi-agent replay | S3 is primary; S2 validates API/client; S7 validates shared specialist/data isolation; S8 validates replay; S10 validates aggregate. |
| `0.03-dev` | distributed IDs, node/instance registry, capabilities, signed work orders, remote dispatch, heartbeat, trace aggregation, remote messages, state handoff, telemetry | S4 is primary and proves resident export plus fail-closed import without source proof; S8 validates local trace/state import/export; S9 validates stale/failure behavior; S10 validates aggregate. |
| `0.04-dev` | governance outcomes, approvals, pause/resume, escalation, circuit breakers, kill switch, policy TTL, external governance adapter, audit/replay | S5 is primary; S7 validates data/artifact approval; S8 validates audit/replay; S9 validates failure races; S10 validates aggregate. |
| `0.05-dev` | device profiles, physical capability model, offline policy cache, local trace buffer, robotics adapter interface, high-level actions only, safety verifier, operator intervention, cloud-helper proposals | S6 is primary; S8 validates replay/audit; S9 validates offline/failure; S10 validates aggregate. |
| `0.1-dev` | stable primitive specs, versioning, runtime compatibility, adapter maturity, conformance, migration, operational docs, hard invariant guarantees | S0, S2, S8, S9, and S10 are primary. |

---

## 3. Primitive coverage matrix

| Primitive | Minimum scenario evidence |
| --- | --- |
| Tenant | S1 tenant sandbox, S7 cross-tenant denial, S10 aggregate. |
| Agent | S1 single agent, S3 orchestrator/specialist, S7 shared specialist. |
| Runtime context | S1 local, S3 local multi-agent, S4 resident node, S6 edge node. |
| Run | S1 run lifecycle, S2 management API, S5 pause/resume/cancel, S10 final journey. |
| Tick | S1 required tick trace events and state progression failure. |
| Percept | S1 append percept, S2 API percept append, S10 aggregate. |
| Policy | S1 policy hook, S5 policy TTL, S6 offline cache. |
| Constraint | S1 URL/path constraints, S6 geofence/privacy constraints. |
| Action request | S1 allowed/denied action, S5 approval-needed action, S6 high-level physical action. |
| Action outcome | S1 executed/denied/failed, S5 needs_approval, S6 needs_intervention. |
| Verifier | S1 standard chain, S5 approval verifier, S6 safety verifier, S9 unavailable verifier. |
| Adapter | S1 HTTP/FS, S5 artifact/governance, S6 device sim, S9 failure. |
| Quota | S1 quota exhaustion, S3 per-agent ledger, S9 quota pressure. |
| State graph | S1 commits, S4 resident export/proof denial, S8 local import/export/tamper, S10 aggregate. |
| Trace store | S1 required events, S4 aggregation, S8 integrity/import, S10 aggregate. |
| Message | S3 local typed messages, S4 remote messages, S7 shared specialist, S10 aggregate. |
| Replay | S1 inspect-only, S3 causal graph, S5 governance explanation, S8 compatibility, S10 final. |
| Work order | S2 local create, S4 signed dispatch, S7 data refs, S10 aggregate. |
| Approval | S5 grant/deny/expiry/revoke, S7 artifact publish, S10 aggregate. |
| Fleet identity | S4 node/instance registration, S10 aggregate. |
| Node registry | S4 registry, S6 device node, S9 stale node. |
| Governance | S5 workflows, S9 races, S10 aggregate. |
| Device profile | S6 edge/drone sim, S10 aggregate. |
| SDK/API | S2 API/client parity, S0 harness, S10 aggregate. |
| Docs/tests | S0 report and anti-drift gates, S8 compatibility docs evidence. |

---

## 4. Management and communication API coverage

| API group | Required scenarios |
| --- | --- |
| Health/version/capabilities | S0, S2, S4, S10. |
| Run lifecycle | S1, S2, S5, S10. |
| Percepts | S1, S2, S10. |
| Actions | S1, S2, S5, S6, S9, S10. |
| State head/snapshot/handoff | S1, S2, S4, S8, S10. |
| Traces/export/sync | S1, S2, S4, S8, S10. |
| Replay | S1, S2, S3, S5, S6, S8, S10. |
| Messages/local/remote/causal graph | S3, S4, S7, S10. |
| Work orders | S2, S4, S7, S10. |
| Fleet registry/placement/telemetry | S4, S6, S9, S10. |
| Governance policy/approval/circuit/kill/audit | S5, S7, S9, S10. |
| Device profile/safety/operator/trace buffer | S6, S9, S10. |

---

## 5. Evidence required for management review

The final acceptance report must include a human-readable executive section with:

- source revision and acceptance suite version;
- container topology hash;
- list of scenarios and pass/fail status;
- public API contract status;
- generated Rust/Python/TypeScript schema parity status;
- scenario-level positive/negative/replay summary;
- anti-drift status;
- top blocking failures, if any;
- links or paths to trace/state/audit artifacts;
- explicit statement that telemetry/health/capabilities did not authorize actions;
- explicit statement that replay did not execute side effects by default;
- explicit statement that physical/edge tests used only high-level bounded actions;
- explicit statement that no enterprise SaaS, marketplace, chat-first, bare-metal, universal memory, or real-time robotics controller behavior was treated as product acceptance scope.

---

## 6. Final traceability rule

No scenario can be counted toward FR or primitive coverage unless it produces machine-readable evidence for success, denial/fail-closed behavior, replay/audit behavior, and anti-drift checks.
