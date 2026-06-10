---
name: database-migration-qa
description: "Database Migration QA: Use when you need to validate database migrations and repository behavior after schema changes."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/database-migration-qa.md"
---

# Database Migration QA

## Purpose

Validate database migrations and repository behavior after schema changes.

## Params

```yaml
  MIGRATION_FILES: "<value>"
  DB_SETUP_COMMANDS: "<value>"
  REPOSITORY_TESTS: "<value>"
  DEPLOY_POLICY: "<value>"
```

## Use When

- Database changes
- Repository changes
- Release readiness
- Migration ordering issues

## Inputs

- Migration files
- DB runner
- Repository code
- Tests
- Fixtures

## Procedure

- Check migration filenames/IDs/order and runner semantics.
- Apply migrations in a clean test/local database when practical.
- Verify repository code matches new schema.
- Run tests covering new constraints, defaults, indexes, and data transformations.
- Check rollback/forward-only documentation.
- Verify seed/fixture data still loads.
- Record commands and environment limitations.
- Block merge on likely deploy-breaking migration order or destructive change without plan.

## Outputs

- Migration QA evidence
- Repository test results
- Deploy risk notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not trust an already-migrated local DB only
- Do not ignore duplicate migration numbers if operationally risky
- Do not hide destructive changes

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Migrations apply predictably
- Runtime code matches schema
- Risk is explicit
