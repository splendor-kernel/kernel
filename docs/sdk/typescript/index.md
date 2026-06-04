# TypeScript SDK Surface

The TypeScript surface provides schema-aligned packages for control-plane and
daemon clients. TypeScript is not a Splendor runtime and does not execute
policies, verifiers, gateways, adapters, state commits, trace persistence, or
replay.

For the stable 0.1 public TypeScript surface, see
[`stable-0.1.md`](stable-0.1.md). Historical 0.02-S6 wording describes where the
packages were introduced, not a separate stable compatibility line.

## Packages

| Package | Purpose |
| --- | --- |
| `@splendor/types` | Canonical TypeScript interfaces for daemon-facing Splendor schemas. |
| `@splendor/client` | Thin authenticated HTTP client for the runtime daemon API. |

Both packages are in `typescript/packages/` and are documented for the 0.1 stable
schema/API surface. The current `@splendor/client` default API header remains
`0.02-dev` until daemon-side active version negotiation is implemented; callers
targeting a documented 0.1 daemon may pass `apiVersion: "0.1"` explicitly.

## Schema coverage

`@splendor/types` exports the Sprint 0.02-S6 criteria types:

- `Message`
- `RunConfig`
- `Percept`
- `ActionRequest`
- `ActionOutcome`
- `TraceEvent`
- `StateHead`

It also exports supporting identity aliases, quota, verification, replay, and
daemon security-boundary metadata used by the client. The package contains only
types and static schema metadata for parity tests; it contains no kernel runtime
logic.

## Development commands

From the repository root:

```bash
npm ci
npm run build
npm run typecheck
npm test
npm run coverage
```

The tests use local fixtures and `fetch` stubs. They do not require fleet
infrastructure or a running Splendor daemon.

## Runtime boundary

TypeScript clients can submit requests to a daemon. The daemon and Rust runtime
remain responsible for:

- tenant, agent, run, state, trace, action, and message identity enforcement;
- signed work-order validation;
- endpoint scope authorization;
- gateway and verifier execution;
- state graph commits;
- append-only trace events;
- replay without side effects.

The TypeScript packages must never be used as proof that an action was verified
or executed. Only daemon/runtime trace and gateway outcomes carry that authority.
