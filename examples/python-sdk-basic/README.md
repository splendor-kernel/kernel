# Python SDK Basic

This example demonstrates the stable 0.1 Python local SDK surface without
bypassing the kernel boundary. Policy code proposes actions; adapters are invoked
only via `KernelRuntime.run_once` after policy, quota, permission, precondition,
and constraint checks.

Stable API reference: `docs/sdk/python/stable-0.1.md`.

## Run

```bash
PYTHONPATH=python python examples/python-sdk-basic/example.py
```

Expected output includes:

```text
statuses ['executed', 'denied', 'failed']
```

The replay line is produced by `KernelRuntime.replay_run(run_id)`, which returns
stored trace events without invoking policy or adapters again.
