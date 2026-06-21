---
name: application-infrastructure-leak-scan
description: "Application Infrastructure Leak Scan: Use when you need to find application-layer code that imports or directly owns infrastructure behavior."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/application-infrastructure-leak-scan.md"
---

# Application Infrastructure Leak Scan

## Purpose

Find application-layer code that imports or directly owns infrastructure behavior.

## Params

```yaml
  APPLICATION_ROOTS: "<value>"
  INFRA_MARKERS: "<value>"
  EXTERNAL_CLIENT_MARKERS: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Architecture discovery
- PR review of use cases
- Service wiring fixes

## Inputs

- Application source
- Infrastructure source
- Package manifests
- Import graph

## Procedure

- Scan application code for database clients, HTTP frameworks, filesystem/network clients, queue clients, object storage clients, SDK implementations, env access, and infra packages.
- Separate pure DTO/schema imports from concrete implementation imports.
- Check whether an application port already exists for each leaked dependency.
- When no port exists, decide whether creating one improves testability/integration or would be abstraction theater.
- For real violations, propose moving implementation to infrastructure and injecting a narrow port.
- Verify composition root can wire the new adapter without broad service locator drift.
- Add or update tests with fake ports only at application test boundaries.
- Record any allowed exceptions and the reason.

## Outputs

- Leak report
- Port/adaptor migration candidates
- Issue updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not wrap every helper in a port
- Do not keep infra imports in application behind renamed files
- Do not fake production adapters

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Violations have exact imports or API calls
- Port proposals are narrow and useful
- No unnecessary abstractions are added
