# Positive S0 Boundary Manifest

This use-case acceptance fixture drives Splendor through public API, CLI, or SDK
boundaries. Mutating daemon requests include caller attribution and scoped work
orders. Replay evidence records `inspect_only` mode with `side_effects_allowed: false`
and `adapter_suppressed` artifacts. Physical fixtures allow only high-level bounded
actions such as `read_battery`, `inspect_zone`, and `return_to_base`.

Documented API examples:

- GET /health
- GET /capabilities
- POST /runs
- POST /runs/{run_id}/replay
