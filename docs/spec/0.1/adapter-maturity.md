# Adapter Maturity Model

Milestone: `Splendor0.1-dev`
Sprint: `0.1-S3 - Adapter maturity model`
FRs: `FR-0.1-04`, `FR-0.1-08`

This document defines evidence-based adapter maturity for the 0.1 stable primitive line. It is a technical compatibility and safety model, not a marketplace, legal certification, vendor approval workflow, production support promise, or physical safety certification program.

Adapters remain execution boundaries behind the Action Gateway. A maturity level never grants authority by itself; it documents the evidence required before an operator, runtime config, or future conformance suite may treat an adapter as suitable for a given deployment class.

## Non-Goals

- No public marketplace or ranking system.
- No legal certification, production support attestation, or vendor approval workflow.
- No approval UI, billing flow, enterprise SaaS workflow, or Harmony-specific dependency.
- No new runtime execution path outside `VerifiedActionGateway`.
- No claim that any adapter is production safe solely because it has metadata.
- No direct physical actuator authority, motor control, firmware safety bypass, collision-avoidance bypass, or cloud direct actuator authority.

## Levels

The maturity levels are exactly:

- `experimental`
- `local-safe`
- `network-safe`
- `governance-aware`
- `device-safe`

The levels are capability classes, not a strict linear ladder. For example, a local filesystem adapter can be `local-safe` without being `network-safe`, while a simulated robotics adapter can target `device-safe` only when it also satisfies the physical safety requirements below.

## Common Requirements

Every adapter manifest must prove these requirements before claiming any level above `experimental`:

| Area | Requirement |
| --- | --- |
| Gateway | All side-effectful and protected read actions execute only through `VerifiedActionGateway` or the stable gateway contract. |
| Verifiers | Required verifier categories are declared, including tenant, agent permission, adapter, quota, precondition, data-scope, filesystem/network where applicable, approval where applicable, safety where applicable, policy TTL where applicable, and postcondition where applicable. |
| Trace | Action request, verification start/completion, execution, denial, failure, approval/intervention, outcome, and postcondition evidence map to existing trace events. |
| Replay | Replay is inspect-only by default and must not call adapters, external services, filesystems, networks, devices, approval systems, or middleware. |
| Quotas | Quota dimensions are declared and denied before adapter execution when exceeded. |
| Scope | Data, filesystem, network, tenant, agent, run, adapter, and action scopes are explicit. No ambient credentials or inherited broad permissions are allowed. |
| Failure | Missing identity, missing verifier, unsupported action, wrong scope, invalid parameters, quota exhaustion, unavailable verifier, trace/state durability failure, and adapter failure fail closed with denial, failure, approval need, or intervention need as appropriate. |
| Evidence | The manifest points to docs, tests, examples, or conformance outputs that prove the claimed behavior. |

Experimental adapters may lack some evidence, but must be labeled `experimental` and must not claim stable, production, governance-aware, network-safe, local-safe, or device-safe readiness.

## Level Requirements

### experimental

Purpose: early adapter development and local investigation.

Requirements:

- Declare adapter identity, supported actions, side-effect classes, required verifiers, known scopes, limitations, and evidence gaps.
- Route any side-effectful examples through the gateway or clearly mark examples as non-runtime development code that is not suitable for delegated Splendor runs.
- Mark replay behavior as inspect-only unless a separately gated safe simulation mode is explicitly documented.
- Declare whether actions touch filesystem, network, external services, credentials, governance, or physical/device surfaces.
- Deny unsupported actions instead of silently ignoring or downgrading them.

Required evidence:

- Metadata manifest with `maturity_level: "experimental"`.
- Minimal syntax/schema validation of the manifest.
- Documentation of known gaps and prohibited claims.

Prohibited claims:

- Stable, production-ready, certified, approved, marketplace-ready, governance-aware, network-safe, local-safe, or device-safe.
- Safe for untrusted tenants or broad delegated work orders without additional evidence.
- Physical safety, live hardware readiness, or direct cloud-to-actuator authority.

Gateway/verifier/quota/scope behavior:

- Gateway use is required for side effects, but verifier coverage may be incomplete if the manifest says so.
- Missing required verifiers fail closed where the adapter is used through the runtime.
- Quotas and scopes must be declared even if tests are pending.

Failure expectations:

- Unsupported or ambiguous actions deny or fail before side effects.
- Any unavailable required verifier must deny or require intervention, never allow.

### local-safe

Purpose: adapters that affect local resources within a bounded local runtime scope, such as sandboxed filesystem access.

Requirements:

- Satisfy all common requirements.
- Restrict local effects to explicit tenant, agent, run, sandbox, path, process, or host scopes.
- Prohibit path traversal, absolute-path escape, shell injection, ambient host mutation, and credential leakage where applicable.
- Declare filesystem or local resource quota dimensions, including read/write bytes, action count, duration, object count, or equivalent bounded units.
- Require filesystem/local data-scope verifier coverage where applicable.
- Produce trace-safe outputs that avoid leaking secrets or unbounded raw local data.

Required evidence:

- Unit or integration tests for allowed local action, denied out-of-scope action, quota or size rejection, unsupported action, and adapter failure.
- Trace/replay documentation showing local side effects are not replayed.
- Example manifest and bounded example configuration.

Prohibited claims:

- Network-safe, governance-aware, device-safe, production-certified, or suitable for arbitrary host filesystem access unless separately proven.
- Access to paths, processes, credentials, or host resources outside declared scopes.

Gateway/verifier/quota/scope behavior:

- Side effects execute only after gateway identity, tenant/agent permission, adapter, quota, precondition, filesystem/data-scope, and postcondition checks allow.
- Denied local actions do not reach adapter execution.

Failure expectations:

- Invalid path/scope, missing tenant sandbox, quota exhaustion, unsupported action, or verifier uncertainty denies or requires intervention before execution.

### network-safe

Purpose: adapters that perform bounded network calls or external service reads/writes.

Requirements:

- Satisfy all common requirements.
- Declare allowed schemes, hosts/domains, methods, ports if applicable, request/response byte limits, timeout limits, header/body handling, credential boundaries, and tenant-specific network scopes.
- Require network egress, data-scope, tenant, agent permission, adapter, quota, precondition, policy TTL, and postcondition verifier coverage where applicable.
- Declare whether each action is read-only, network read, network write, external mutation, webhook, database mutation, or credential use.
- Avoid logging or tracing raw secrets, authorization headers, tokens, cookies, or unbounded response bodies.
- Declare retry/idempotency behavior and prohibit blind retries for non-idempotent side effects.

Required evidence:

- Tests or fixtures for allowlisted destination, denied destination, method rejection, request/response size limit, timeout or adapter failure, quota denial, and replay side-effect suppression.
- Documentation of egress/data-scope policy and trace-safe output shape.
- Example manifest and bounded example configuration.

Prohibited claims:

- Governance-aware or device-safe unless those additional requirements are met.
- Open internet egress, wildcard credential use, arbitrary webhook mutation, or production external-service certification based only on network-safe metadata.

Gateway/verifier/quota/scope behavior:

- Network actions execute only after gateway identity, policy, adapter, network egress, data-scope, quota, approval if required, and postcondition checks allow.
- Egress scope mismatch, missing allowlist, unsupported method, or class mismatch denies before execution.

Failure expectations:

- DNS/network failures, remote errors, timeout, response too large, missing credentials, verifier uncertainty, or trace/state durability failure are recorded as denied, failed, or needs-intervention outcomes without hidden continuation.

### governance-aware

Purpose: adapters that can participate in approval, intervention, circuit-breaker, audit, and replay explanation semantics for higher-risk work.

Requirements:

- Satisfy `local-safe` or `network-safe` requirements for the resource class they touch.
- Declare action classes and risk levels that require approval, intervention, policy TTL, escalation, circuit-breaker, or kill-switch checks.
- Require approval verifier coverage for approval-required actions and circuit-breaker verifier coverage for scoped breakers where applicable.
- Preserve adapter/action scope in approval evidence; omitted action or adapter scope is not a wildcard grant.
- Emit or map to trace events for `action.needs_approval`, `action.needs_intervention`, `action.denied`, `action.failed`, approval lifecycle events, circuit-breaker denials, and outcomes.
- Replay governance decisions from trace only; replay must not call approval services, clear breakers, re-submit actions, notify humans, or execute adapters.

Required evidence:

- Tests or examples for approval-required pause before execution, valid scoped approval re-evaluation, denied/expired/revoked/wrong-scope approval fail-closed behavior, circuit-breaker denial before execution, and governance replay explanation.
- Documentation of governance scope and provider-neutral behavior.

Prohibited claims:

- Product approval UI, enterprise workflow engine, Harmony dependency, legal compliance certification, or incident automation platform.
- Approval evidence as a gateway bypass.

Gateway/verifier/quota/scope behavior:

- Governance checks remove or pause authority; they do not grant broad permissions or bypass tenant policy, quotas, work orders, or data-scope checks.
- Circuit breakers and approval denials prevent adapter execution.

Failure expectations:

- Approval verifier uncertainty, expired policy, unknown breaker scope, missing runtime identity for scoped breakers, unsupported evidence schema, or governance state conflict denies or requires intervention.

### device-safe

Purpose: adapters that mediate high-level bounded physical/device actions through local middleware while real-time controllers and firmware remain authoritative.

Requirements:

- Satisfy common requirements plus governance-aware behavior where high-risk physical actions require approval or intervention.
- Support only high-level bounded physical actions such as `read_battery`, `read_sensor_summary`, `read_map`, `move_to_waypoint`, `return_to_base`, `dock`, `inspect_zone`, `capture_image`, `pause_mission`, `resume_mission`, `request_operator_override`, `notify_operator`, and `upload_trace_summary`.
- Reject raw actuator writes, `set_motor_pwm`, firmware safety bypass, flight-controller internals, collision-avoidance bypass, emergency-stop bypass, low-level motor control, and unknown actions marked as physical.
- Require local safety verifier integration before adapter execution and postcondition safety verification where applicable.
- Keep cloud helpers advisory. Cloud adapters or planners may propose routes or artifacts, but local device Splendor must verify and gate bounded actions before middleware execution.
- Record trace-safe safety evidence references, thresholds, zones, and reason codes without raw sensor blobs, camera frames, lidar packets, or controller internals.

Required evidence:

- Tests or simulation harness evidence for allowed high-level action, forbidden low-level action denial before execution, missing/uncertain safety verifier fail-closed behavior, unsafe route/action denial, operator intervention/override request, trace-safe evidence, and replay side-effect suppression.
- Documentation of physical boundary, middleware boundary, and no-production-certification limitation.

Prohibited claims:

- Production robotics safety certification, flight certification, hardware readiness, motor control, flight-controller replacement, PLC replacement, ROS/native driver replacement, hard real-time stabilization, cloud teleoperation, or direct cloud-to-actuator authority.

Gateway/verifier/quota/scope behavior:

- Physical actions execute only after gateway identity, tenant/agent permission, adapter, quota, precondition, approval if required, local safety, data-scope, and postcondition checks allow.
- Missing or uncertain safety verifier returns `needs_intervention` or denial before execution.

Failure expectations:

- Forbidden action, unknown physical action, emergency stop, geofence failure, low battery, collision risk, privacy-zone conflict, missing sensor/status evidence, middleware error, verifier uncertainty, or trace/state durability failure fails closed and records evidence.

## Adapter Metadata Schema

Adapter metadata is a JSON document. Example manifests live under `docs/spec/0.1/fixtures/adapter-manifests/`.

Required top-level fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `schema_version` | string | Must be `splendor.adapter_manifest.v1` for this sprint. |
| `adapter` | object | Stable adapter identity. |
| `maturity_level` | string | One of the five maturity levels defined above. |
| `supported_actions` | array | Action names, side-effect classes, params scope summary, permissions, and risk. |
| `required_verifiers` | array | Verifier categories required before execution. |
| `quota_dimensions` | array | Quota counters the adapter consumes or requires. |
| `trace_behavior` | object | Trace events and evidence emitted or required. |
| `replay_behavior` | object | Default replay mode and side-effect suppression statement. |
| `scopes` | object | Data, network, filesystem, credential, tenant, agent, run, and adapter scope. |
| `governance_support` | object | Approval, circuit-breaker, intervention, policy TTL, and audit support. |
| `physical_device_safety` | object | Physical/device boundary fields; use `not_applicable` when irrelevant. |
| `limitations` | array | Current limitations and prohibited claims. |
| `evidence` | array | References to docs, tests, examples, or validation commands. |

Recommended shape:

```json
{
  "schema_version": "splendor.adapter_manifest.v1",
  "adapter": {
    "id": "filesystem",
    "name": "Filesystem Adapter",
    "version": "0.1-dev",
    "crate": "splendor-adapter-filesystem",
    "owner": "splendor-runtime",
    "description": "Sandboxed filesystem access behind the Action Gateway."
  },
  "maturity_level": "local-safe",
  "supported_actions": [
    {
      "name": "read_file",
      "side_effect_class": "filesystem.read",
      "required_permissions": ["filesystem.read"],
      "required_preconditions": [],
      "postconditions": [],
      "params_scope": "tenant sandbox relative path",
      "risk": "bounded_local_read"
    }
  ],
  "required_verifiers": [
    "tenant",
    "agent_permission",
    "adapter",
    "quota",
    "precondition",
    "data_scope",
    "filesystem",
    "postcondition"
  ],
  "quota_dimensions": ["actions", "filesystem_read_bytes"],
  "trace_behavior": {
    "required_events": ["verification.started", "verification.completed", "action.executed", "action.denied", "action.failed", "outcome.recorded"],
    "evidence": "Trace-safe paths, byte counts, verifier reasons, and postcondition references only."
  },
  "replay_behavior": {
    "default_mode": "inspect_only",
    "side_effects_replayed": false,
    "notes": "Replay reads trace/state facts only and does not call the adapter."
  },
  "scopes": {
    "tenant_scope": "required",
    "agent_scope": "required",
    "run_scope": "required",
    "data_scope": "declared per action",
    "filesystem_scope": "tenant sandbox",
    "network_scope": "not_applicable",
    "credential_scope": "not_applicable"
  },
  "governance_support": {
    "approval": "not_required_by_default",
    "circuit_breakers": ["adapter", "action", "action_class", "tenant", "agent"],
    "policy_ttl": "runtime_policy_dependent",
    "audit_attribution": "via gateway trace identity"
  },
  "physical_device_safety": {
    "status": "not_applicable"
  },
  "limitations": ["No production support or legal certification claim."],
  "evidence": [
    {"type": "doc", "ref": "docs/reference/action-gateway.md"}
  ]
}
```

## Validation

The lightweight validation script checks JSON syntax, required top-level fields, allowed maturity names, and basic action/verifier/evidence shape:

```bash
python scripts/validate-adapter-manifests.py
```

This script is not a certification process. Future conformance work may consume the manifests and add deeper runtime tests.

## Compatibility Notes

- `splendor.adapter_manifest.v1` is a 0.1 development schema candidate intended for stable paths and names before 0.1 release finalization.
- Metadata documents do not change runtime behavior or authorize adapters.
- Existing gateway, verifier, trace, quota, replay, governance, and physical-action references remain authoritative for runtime semantics.
- If 0.1-S1 schema-freeze wording changes before merge, align field names without changing the maturity level names.
