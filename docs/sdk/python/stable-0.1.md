# Python SDK Stable 0.1 Surface

The Python SDK stable 0.1 surface is a local runtime ergonomics layer for
proposing actions, registering callbacks, inspecting traces, and running
inspect-only replay. It is not an enforcement bypass and not a daemon client.

## Stable Imports

```python
from splendor import (
    Action,
    ActionCandidate,
    CANONICAL_ID_FIELDS,
    Constraint,
    KernelRuntime,
    KernelRuntimeConfig,
    Percept,
    QuotaPolicy,
    QuotaUsage,
    STABLE_0_1_ENUM_VALUES,
    STABLE_0_1_PRIMITIVES,
    STABLE_0_1_REQUIRED_FIELDS,
    STABLE_0_1_RESERVED_EXTENSION_KEYS,
    VerificationResult,
)
```

These names are exported from `splendor.__all__` and are the stable Python SDK
entry points for 0.1 examples and tests.

## Stable Local Runtime Methods

`KernelRuntime` stable methods:

- `create_tenant(...)`
- `create_agent(...)`
- `register_perceptor(agent_id, callback)`
- `register_policy(agent_id, callback)`
- `register_constraints(agent_id, callback)`
- `register_adapter(adapter_id, callback)`
- `subscribe_traces(run_id, callback)`
- `tail_traces(run_id)`
- `replay_run(run_id)`
- `run_once(agent_id)`
- `agent_run_id(agent_id)`

Policies propose actions. Adapters are invoked only by `run_once` after tenant,
adapter, permission, quota, precondition, constraint, and gateway-style checks.

## Stable Primitive Constants

The SDK exposes stable constants aligned with `docs/spec/0.1/primitives.md`:

- `CANONICAL_ID_FIELDS`
- `STABLE_0_1_PRIMITIVES`
- `STABLE_0_1_REQUIRED_FIELDS`
- `STABLE_0_1_RESERVED_EXTENSION_KEYS`
- `STABLE_0_1_ENUM_VALUES`

These constants are schema-facing documentation aids and fixture parity checks.
They do not grant permissions, authorize adapters, issue work orders, or bypass
verification.

## Stable Error Handling

Programmatic callers should handle:

- action outcomes through `outcome.action_outcomes[*].status` values
  `executed`, `denied`, `failed`, `needs_approval`, and `needs_intervention` when
  the runtime records a gateway outcome;
- `ValueError` for invalid identities, malformed action/percept data, invalid
  quotas, replay sequence mismatch, or other validation failures;
- `KeyError` or callback-raised exceptions only as local callback/input errors,
  not as authorization success.

Adapter failures after verification are recorded as `failed` outcomes. Denied
actions do not call adapters.

## Replay Contract

`replay_run(run_id)` returns a copy of recorded trace events after validating run
scope and contiguous sequence ordering. It does not invoke perceptors, policies,
constraints, verifiers, adapters, filesystems, networks, databases, shell commands,
or external services.

## Compatibility And Deprecation

Stable 0.1 patch releases will not remove the stable imports or stable method
names listed above. Additive helpers may be introduced when they preserve
identity, state, trace, gateway, verifier, quota, and replay semantics.

Deprecated stable Python SDK names must document a replacement and migration path
before removal. Removing a stable import or method requires a new major SDK/API
version or RFC-backed migration.

## Non-Stable Python Surface

The following are internal or dev-only:

- underscored helper functions such as `_new_uuid` and `_trace_event_id`;
- private dataclass fields and callback storage;
- exact in-memory storage layout;
- callback invocation details beyond the documented runtime loop;
- test-only fixtures and examples not marked stable;
- daemon/client communication, production authentication, native Node bindings,
  browser runtime behavior, fleet scheduling, and physical safety certification.

## Stable Example

Use `examples/python-sdk-basic/` for the stable local SDK path:

```bash
PYTHONPATH=python python examples/python-sdk-basic/example.py
```

The example keeps side effects behind `KernelRuntime.run_once`, records allowed,
denied, and failed outcomes, and demonstrates replay without repeating adapter
side effects.

## Conformance Command

Run the repository 0.1 conformance suite from the root:

```bash
python conformance/0.1/run-conformance.py
```

This validates stable primitive fixture compatibility and replay/gateway
fail-closed expectations. It does not replace Python unit tests for SDK runtime
behavior.
