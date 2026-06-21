# Known Limitations

## 0.01-dev local-only constraints

- Runs execute inside one local Splendor instance.
- 0.03-S2 includes a minimal in-memory resident node/instance registry, but there
  is no central manager, remote work-order dispatch, placement engine, or trace
  aggregation protocol.
- There is no local multi-agent router or typed message delivery in 0.01-dev.
- There is no daemon API or TypeScript client in 0.01-dev.
- Replay is inspect-only and local; there is no cross-instance replay.

## Governance limitations through 0.05-dev

- 0.04-dev includes approval gating, deterministic escalation, circuit breakers,
  policy TTL/revocation checks, external governance adapter contracts, and
  inspect-only governance replay/audit.
- There is still no approval UI, approval queue product, notification platform,
  workflow DSL, ticketing integration, or enterprise IAM integration.
- Circuit breakers are limited to the 0.04-S4 local config/gateway reference path;
  there is no monitoring automation, predictive safety model, or UI dashboard.
- Kill-switch state is modeled and traceable, but central kill-switch propagation
  to resident instances remains future work.
- 0.04-S5 includes run-scoped signed policy bundle distribution, TTL checks,
  revocation handling, and degraded cached-policy enforcement. There is still no
  fleet-wide policy distribution service, authoring UI, global policy consensus,
  or production PKI/key management.
- The external governance adapter is a provider-neutral contract boundary. It does
  not make Harmony or any other product the source of runtime enforcement.

## Physical/edge limitations through 0.05-dev

- 0.05-dev includes development primitives for physical/edge orchestration:
  device profiles, physical capability validation, offline policy cache behavior,
  local trace buffer and reconnect sync, a high-level robotics adapter contract,
  safety verifier API, advisory cloud-helper pattern, and a physical simulation
  harness.
- The 0.05 physical/edge surface is contract and simulation focused. It does not
  certify production robot, drone, humanoid, industrial, or edge-device readiness.
- Physical actions remain high-level, bounded, and mediated by the Action Gateway
  and local safety verifier chain before adapter execution.
- There is no hard real-time robot control, motor control, raw actuator write,
  firmware safety bypass, flight-controller replacement, PLC replacement,
  low-level sensor-fusion system, ROS/native device-driver implementation, live
  flight testing, or production robotics safety certification claim.
- Cloud helpers are advisory by default. They may return proposals, artifacts, or
  typed messages, but they do not receive direct actuator authority; local device
  Splendor validation and gateway/safety checks remain authoritative.

## Adapter maturity

- 0.01 includes filesystem and HTTP adapters as local baseline adapters.
- 0.1-S3 adds an evidence-based adapter maturity model with levels for
  `experimental`, `local-safe`, `network-safe`, `governance-aware`, and
  `device-safe` adapters. This is a technical documentation and metadata model,
  not a marketplace, vendor approval workflow, legal certification, production
  support promise, or physical safety certification claim.
- Broad adapter ecosystem mechanics, adapter marketplace workflows, and legal or
  product certification processes are not included.

## Compatibility

- 0.01-dev through 0.05-dev schemas are provisional development contracts.
- 0.1-dev defines the first stable primitive compatibility line for the documented
  primitive schemas, SDK/API boundary, conformance fixtures, adapter maturity
  metadata, operational guides, migration policy, and compatibility policy.
- 0.1-dev does not stabilize undocumented Rust internals, private helpers,
  in-memory stores, production remote daemon authentication, production fleet
  scheduling, adapter certification, marketplace behavior, production robotics
  safety certification, or hard real-time control.
- The current daemon can carry API version metadata, but it does not actively
  negotiate API versions or reject unsupported version headers. Treat this as a
  documented limitation, not a production protocol guarantee.

## Agent-kernel v2 planning import

- `docs/planning/agent-kernel-v2/` contains imported vNext planning material for
  a broader post-0.1 agent-kernel direction.
- That planning material is non-normative until specific RFCs are accepted and
  implemented. It does not replace the stable 0.1 primitive specs, current
  `docs/rules/*` roadmap, Action Gateway contract, state/trace/replay
  invariants, or physical/edge safety boundaries.
- Proposed concepts such as a universal driver gateway, workload fabric,
  evidence service, learning-control plane, and self-management lifecycle remain
  future planning surfaces. They are not current production capabilities or
  conformance evidence.
