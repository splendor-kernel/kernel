---
name: api-business-logic-scan
description: "API Business Logic Scan: Use when you need to detect business workflows living in HTTP route handlers instead of application/domain use cases."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/api-business-logic-scan.md"
---

# API Business Logic Scan

## Purpose

Detect business workflows living in HTTP route handlers instead of application/domain use cases.

## Params

```yaml
  API_ROOTS: "<value>"
  APPLICATION_ROOTS: "<value>"
  ROUTE_PATTERNS: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Reviewing API changes
- Architecture discovery
- Large route files
- When routes coordinate persistence/services directly

## Inputs

- API route files
- Use case files
- Composition root
- Tests

## Procedure

- List route handlers and their responsibilities.
- Identify handlers that parse/auth/map only versus handlers that decide business rules or orchestrate persistence/external services.
- Look for direct repository, database, client, policy, or workflow coordination in routes.
- Check whether corresponding application use cases or ports already exist.
- Classify each finding as violation, acceptable thin adapter, transitional seam, or needs-investigation.
- Propose a vertical migration: route maps request, use case owns workflow, infra owns external systems.
- Require tests that verify the behavior at the use-case or route integration level.
- Track broad route files for concern-splitting only when extraction has a coherent boundary.

## Outputs

- API logic findings
- Migration candidates
- Issue updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not move HTTP concerns into application
- Do not create one-use interfaces with no boundary value
- Do not break existing API contracts

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Findings distinguish mapping from business behavior
- Migration direction is bounded
- Routes are not refactored for style alone
