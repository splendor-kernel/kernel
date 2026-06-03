# Known Limitations

## 0.01-dev local-only constraints

- Runs execute inside one local Splendor instance.
- 0.03-S2 includes a minimal in-memory resident node/instance registry, but there
  is no central manager, remote work-order dispatch, placement engine, or trace
  aggregation protocol.
- There is no local multi-agent router or typed message delivery in 0.01-dev.
- There is no daemon API or TypeScript client in 0.01-dev.
- Replay is inspect-only and local; there is no cross-instance replay.

## Governance limitations through 0.04-dev

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

## Physical/edge not included

- No device node profiles.
- No robotics adapter contract.
- No safety verifier API.
- No full physical/edge offline policy cache or local trace reconnect sync.
- No production robotics safety certification claim.

## Adapter maturity

- 0.01 includes filesystem and HTTP adapters as local baseline adapters.
- Broad adapter ecosystem and adapter certification levels are not included.

## Compatibility

- 0.01-dev through 0.04-dev schemas are provisional development contracts.
- 0.1-dev will define the first stable primitive compatibility line.
