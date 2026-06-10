---
name: dependency-drift-scan
description: "Dependency Drift Scan: Use when you need to compare package manifests, actual imports, project references, and architecture rules."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/dependency-drift-scan.md"
---

# Dependency Drift Scan

## Purpose

Compare package manifests, actual imports, project references, and architecture rules.

## Params

```yaml
  PACKAGE_GLOB: "<value>"
  TSCONFIG_GLOB: "<value>"
  INTERNAL_SCOPE: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Clean arch discovery
- Build graph cleanup
- Package refactors
- PR review touching deps

## Inputs

- package.json files
- tsconfig files
- Source imports
- Architecture rule map

## Procedure

- Collect internal package names and workspace relationships.
- Parse dependencies, devDependencies, peerDependencies, and optionalDependencies.
- Parse TypeScript project references.
- Scan actual source imports and re-exports.
- Flag package dependency with no source/build/test reason.
- Flag source import missing package dependency or project reference.
- Flag project reference with no source/build reason.
- Exclude documented tooling, generator, test-only, or build-only dependencies.
- Fix mechanical drift when safe and create issues for risky drift.

## Outputs

- Dependency drift report
- Safe manifest/tsconfig fixes
- Issue updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not remove build-only deps blindly
- Do not ignore dev/test dependency contexts
- Do not confuse path aliases with packages

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Build graph matches source graph or exceptions are documented
- Architecture drift is visible
