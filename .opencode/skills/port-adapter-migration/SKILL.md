---
name: port-adapter-migration
description: "Port and Adapter Migration: Use when you need to migrate a real dependency boundary to a narrow application port and infrastructure adapter."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/port-adapter-migration.md"
---

# Port and Adapter Migration

## Purpose

Migrate a real dependency boundary to a narrow application port and infrastructure adapter.

## Params

```yaml
  BOUNDARY_NAME: "<value>"
  CALLERS: "<value>"
  IMPLEMENTATIONS: "<value>"
  COMPOSITION_ROOT: "<value>"
  TEST_SCOPE: "<value>"
```

## Use When

- Application imports infrastructure
- Production service needs wiring
- A compatibility seam needs narrowing

## Inputs

- Current callers
- Concrete implementation
- Existing tests
- Composition root

## Procedure

- Confirm the boundary is real: multiple environments, external system, determinism need, or integration seam.
- Define the smallest port that matches caller needs, not the full implementation surface.
- Place the port in the owner layer according to repo convention.
- Move external-system code into infrastructure adapter or reuse an existing adapter.
- Wire the adapter in composition root without adding a broad catch-all dependency.
- Update tests: fake the port in application tests; exercise real adapter in integration tests when practical.
- Remove obsolete direct imports and package deps.
- Update docs/service inventory if the service classification changes.

## Outputs

- Port interface
- Adapter implementation
- Composition wiring
- Tests
- Inventory update

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- No empty ports
- No one-method interface unless it protects a real boundary
- No production mock adapter

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Callers depend on the port
- Production uses real adapter
- Tests no longer rely on hidden globals
