---
name: service-inventory-build
description: "Service Inventory Build: Use when you need to create or refresh a service/module inventory that records purpose, production wiring, tests, and current classification."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/service-inventory-build.md"
---

# Service Inventory Build

## Purpose

Create or refresh a service/module inventory that records purpose, production wiring, tests, and current classification.

## Params

```yaml
  SERVICE_ROOTS: "<value>"
  INVENTORY_PATH: "<value>"
  ENTRYPOINTS: "<value>"
  SPLENDOR_ROOT: "<value>"
```

## Use When

- Service audit start
- Before deleting code
- Before wiring work
- Before final handoff

## Inputs

- Source tree
- Package exports
- Docs
- Config
- Tests
- Routes
- Composition root

## Procedure

- List candidate services, modules, packages, adapters, workers, clients, and UI service facades.
- For each candidate, capture path, owner layer, public exports, docs references, and tests.
- Do not decide unused status from imports alone.
- For each service, create an inventory entry with purpose, expected entry point, actual entry point, registration, config/env, data dependencies, tests, classification, evidence, and next action.
- Mark uncertain entries as `needs-investigation` instead of guessing.
- Update existing entries rather than duplicating them.
- Link related issues and PRs.
- Keep the inventory terse but factual.

## Outputs

- Service inventory markdown
- Machine-readable service list if configured
- Issue links

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not classify from name alone
- Do not delete without issue history
- Do not ignore docs/config/runtime references

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Reviewed services have classifications
- Unwired or risky services have next actions
- Future agents can tell what exists and why
