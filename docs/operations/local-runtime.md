# Operating The Local Runtime

This guide shows the stable 0.1 local runtime path for running one governed loop,
inspecting trace/state evidence, replaying without side effects, and cleaning up
local artifacts.

## Maturity And Limits

- Required adapter maturity: `local-safe` for bounded filesystem/local-resource side effects.
- Stable surface: `splendorctl`, Python local SDK methods named in `docs/spec/0.1/api-stability.md`, trace/state/replay primitives, and the 0.1 conformance suite.
- Limitations: local runtime only; no fleet scheduler, production daemon transport, approval UI, physical hardware readiness, or marketplace/admin product surface.
- Local developer fixtures may use `allow_unsigned_local_run: true`; resident, daemon, or distributed runs should use signed work orders.

## Setup

From the repository root:

```bash
cargo build -p splendorctl
rm -f ./examples/local-basic-loop/data/trace.db ./examples/local-basic-loop/data/state.db ./examples/local-basic-loop/data/tick_*.txt
```

Optional stable API-surface checks:

```bash
python conformance/0.1/run-conformance.py
python scripts/validate-adapter-manifests.py
```

## Run Path

Run one local tick:

```bash
./target/debug/splendorctl run --config ./examples/local-basic-loop/config.yaml --cycles 1
```

Expected behavior:

- the policy proposes a filesystem action;
- the action enters the Action Gateway;
- tenant, permission, adapter, quota, and precondition checks run before adapter execution;
- the filesystem adapter writes `examples/local-basic-loop/data/tick_1.txt` only after verification allows;
- state and trace records are committed.

The complete smoke path is documented in `examples/local-basic-loop/README.md` and can also be run with:

```bash
bash scripts/verify-0.01-baseline.sh
```

## Trace And State Inspection

Export the ordered run trace:

```bash
./target/debug/splendorctl trace export --db ./examples/local-basic-loop/data/trace.db --run 22222222-2222-2222-2222-222222222222
```

Inspect the state head:

```bash
./target/debug/splendorctl state head --db ./examples/local-basic-loop/data/trace.db --run 22222222-2222-2222-2222-222222222222
```

Replay inspect-only:

```bash
./target/debug/splendorctl replay --db ./examples/local-basic-loop/data/trace.db --state-db ./examples/local-basic-loop/data/state.db --run 22222222-2222-2222-2222-222222222222
```

Replay reconstructs recorded trace/state evidence and must report no repeated filesystem adapter execution.

## Failure Handling

- Missing work-order authority is rejected unless the config explicitly enables local-only unsigned development mode.
- Gateway denial records `ActionDenied` and skips adapter execution.
- State commit failure prevents advancement to the next tick.
- Trace persistence failure at a required side-effect boundary fails closed.
- Replay failures are inspection failures; replay must not run policies, verifiers, gateways, adapters, filesystem writes, network calls, or external side effects.

## Teardown

Remove local example output:

```bash
rm -f ./examples/local-basic-loop/data/trace.db ./examples/local-basic-loop/data/state.db ./examples/local-basic-loop/data/tick_*.txt
```

## References

- `docs/getting-started/local-runtime.md`
- `docs/reference/runtime-loop.md`
- `docs/reference/action-gateway.md`
- `docs/reference/state-graph.md`
- `docs/reference/trace-events.md`
- `docs/reference/replay.md`
- `examples/local-basic-loop/README.md`
