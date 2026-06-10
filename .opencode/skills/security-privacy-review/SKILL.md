---
name: security-privacy-review
description: "Security and Privacy Review: Use when you need to catch security, privacy, and policy regressions in implementation work."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/security-privacy-review.md"
---

# Security and Privacy Review

## Purpose

Catch security, privacy, and policy regressions in implementation work.

## Params

```yaml
  TOUCHED_AREAS: "<value>"
  DATA_CLASSES: "<value>"
  AUTH_MODEL: "<value>"
  SCAN_COMMANDS: "<value>"
```

## Use When

- Auth/policy changes
- External integrations
- Data access
- Logging changes
- Release readiness

## Inputs

- Diff
- Threat model if available
- Auth checks
- Logs
- Tests
- Secrets scans

## Procedure

- Identify sensitive data, privileged actions, and trust boundaries touched by the change.
- Verify authentication and authorization occur at the correct boundary.
- Check for policy/governance shortcut paths.
- Ensure logs/errors do not expose secrets, tokens, PII, or internal stack details.
- Check dependency and config changes for unsafe defaults.
- Run available secret/security scans.
- Add tests for unauthorized, forbidden, and cross-tenant/resource access where relevant.
- Escalate unclear policy/security decisions to human sync.

## Outputs

- Security review notes
- Tests/scans
- Issues for risks

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not weaken auth for test convenience
- Do not commit secrets
- Do not suppress security scans without tracking

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- No obvious auth/policy bypass remains
- Sensitive data is handled deliberately
- Security checks are documented
