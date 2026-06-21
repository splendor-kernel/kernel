---
name: configuration-management
description: "Configuration Management: Use when you need to handle runtime configuration and environment variables safely and predictably."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/configuration-management.md"
---

# Configuration Management

## Purpose

Handle runtime configuration and environment variables safely and predictably.

## Params

```yaml
  CONFIG_KEYS: "<value>"
  ENVIRONMENTS: "<value>"
  OWNER_PACKAGE: "<value>"
  DEFAULTS_POLICY: "<value>"
```

## Use When

- Adding services
- Feature flags
- External integrations
- Deployment readiness

## Inputs

- Config source
- Env docs
- Validation code
- Tests
- Deploy manifests

## Procedure

- List required and optional config keys.
- Define safe defaults for local/test and explicit requirements for production.
- Validate config at startup or composition boundary according to project convention.
- Keep secrets out of code, logs, docs examples, and state capsule.
- Make disabled/missing config behavior explicit.
- Add tests for required, optional, invalid, and disabled config paths.
- Update runbooks/env examples without real secrets.
- Ensure config ownership stays in infrastructure/composition, not domain.

## Outputs

- Config validation
- Tests
- Docs/env example update

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not read env deep in domain/application unless convention allows
- Do not make optional services fail mandatory startup
- Do not hardcode credentials

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Config failures are early and clear
- Production cannot silently use unsafe defaults
- Secrets are protected
