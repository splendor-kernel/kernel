---
name: database-change
description: "Database Change: Use when you need to implement database changes that are deployable, reversible or intentionally forward-only, and tested."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/database-change.md"
---

# Database Change

## Purpose

Implement database changes that are deployable, reversible or intentionally forward-only, and tested.

## Params

```yaml
  MIGRATION_PATH: "<value>"
  REPOSITORY_FILES: "<value>"
  ROLLBACK_POLICY: "<value>"
  DATA_RISK: "<value>"
```

## Use When

- Schema changes
- Repository changes
- Data migrations
- Release readiness

## Inputs

- Migrations
- Repository code
- Tests
- Deploy docs
- Seed data

## Procedure

- Determine whether the change is additive, destructive, data-moving, or ordering-sensitive.
- Prefer backward-compatible additive migrations when possible.
- Check migration numbering/order and runner behavior.
- Update repository queries and contract assumptions together.
- Add tests or migration verification for new columns/tables/constraints when practical.
- Document forward-only assumptions and operational risk.
- Verify local/test DB setup uses the new migration path.
- Update seed/test fixtures that depend on schema.

## Outputs

- Migration file
- Repository updates
- Tests/verification
- Risk notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not rename/drop data without migration plan
- Do not rely on local DB state
- Do not forget rollback/forward-only note

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Migration applies in order
- Runtime code matches schema
- Deploy risk is explicit
