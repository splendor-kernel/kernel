> **Moved:** The active 0.2/v2 implementation task catalog now lives at
> [`docs/rules/v2/catalog/complete_implementation_task_catalog.md`](../../../rules/v2/catalog/complete_implementation_task_catalog.md).

# Complete Implementation Task Catalog — Compatibility Redirect

This path is preserved because older planning references and agent prompts may
still point to `docs/planning/agent-kernel-v2/imported/14_complete_implementation_task_catalog.md`.

Agents must read the active catalog from:

```text
docs/rules/v2/catalog/complete_implementation_task_catalog.md
```

For structured extraction and GitHub issue generation, use:

```text
docs/rules/v2/catalog/architecture/implementation_tasks.yaml
docs/rules/v2/catalog/implementation_task_index.md
docs/rules/v2/gold/gold-examples-catalog.md
docs/rules/v2/gold/examples/catalog.yaml
```

The catalog remains a required-work decomposition and assignment source. It is
not implementation evidence until each task's required implementation,
anti-drift boundaries, integrations, validation criteria, and gold evidence have
passed with retained proof.
