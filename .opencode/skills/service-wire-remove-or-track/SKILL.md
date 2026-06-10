---
name: service-wire-remove-or-track
description: "Service Wire, Remove, or Track Decision: Use when you need to decide whether to integrate, remove, deprecate, or track a service based on evidence and risk."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/service-wire-remove-or-track.md"
---

# Service Wire, Remove, or Track Decision

## Purpose

Decide whether to integrate, remove, deprecate, or track a service based on evidence and risk.

## Params

```yaml
  SERVICE_NAME: "<value>"
  CLASSIFICATION: "<value>"
  RISK_LEVEL: "<value>"
  OWNER_LAYER: "<value>"
  ISSUE_ID: "<value>"
```

## Use When

- After service classification
- Planning implementation
- Reviewing cleanup PR

## Inputs

- Inventory entry
- Call graph
- Tests
- Docs
- Config
- Issue history

## Procedure

- If purposeful and bounded, prefer wiring production path with tests.
- If duplicate-replaced, deprecate or remove only after callers and docs are updated.
- If scaffold-only and misleading, remove low-risk placeholders or open a tracking issue.
- If dead-remove-candidate, verify no runtime/config/test/docs/migration references and consider a deprecation PR before deletion.
- If blocked, document external dependency and safe fallback behavior.
- If uncertain, track investigation instead of changing behavior.
- For every decision, update issue, inventory, and handoff.
- Require validation that the decision did not break exports, contracts, config, or tests.

## Outputs

- Decision record
- Implementation or issue
- Inventory update

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not delete risky code in the same PR that discovers it
- Do not wire service without config/observability when needed
- Do not leave purpose unknown

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Decision is reversible or safe
- Risk is explicit
- Project truth improves
