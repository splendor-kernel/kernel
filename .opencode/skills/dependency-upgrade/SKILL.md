---
name: dependency-upgrade
description: "Dependency Upgrade: Use when you need to upgrade dependencies with controlled risk, compatibility evidence, and rollback clarity."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/dependency-upgrade.md"
---

# Dependency Upgrade

## Purpose

Upgrade dependencies with controlled risk, compatibility evidence, and rollback clarity.

## Params

```yaml
  DEPENDENCY: "<value>"
  FROM_VERSION: "<value>"
  TO_VERSION: "<value>"
  CHANGELOG_SOURCE: "<value>"
  VALIDATION_COMMANDS: "<value>"
```

## Use When

- Security updates
- Framework/library upgrades
- Tooling upgrades
- Build failures from stale deps

## Inputs

- package manifests
- Lockfile
- Release notes/changelog
- Tests
- CI config

## Procedure

- Determine why the upgrade is needed: security, compatibility, bugfix, platform requirement, or cleanup.
- Inspect breaking changes and migration notes from the dependency source when available.
- Upgrade the smallest coherent set of packages.
- Update lockfile and generated artifacts as required by repo convention.
- Run typecheck/build/tests that cover affected paths.
- Check runtime entry points for configuration or API changes.
- Record rollback path and known risks.
- Do not combine large dependency upgrades with unrelated refactors.

## Outputs

- Updated dependency files
- Validation evidence
- Risk/rollback note

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not blindly bump major versions
- Do not ignore peer dependency warnings
- Do not hide lockfile churn

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Upgrade reason is clear
- Affected code paths validated
- Rollback is understandable
