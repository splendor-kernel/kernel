---
name: package-export-drift-scan
description: "Package Export Drift Scan: Use when you need to ensure package exports match intended public APIs and do not expose stale or fake surfaces."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/package-export-drift-scan.md"
---

# Package Export Drift Scan

## Purpose

Ensure package exports match intended public APIs and do not expose stale or fake surfaces.

## Params

```yaml
  PACKAGE_ROOTS: "<value>"
  INTERNAL_SCOPE: "<value>"
  EXPORT_POLICY: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Package cleanup
- Service inventory
- SDK/UI package review
- Before deletion

## Inputs

- package.json exports
- index files
- Source imports
- Docs
- Tests

## Procedure

- List each package’s public exports and barrel files.
- Find exported symbols/files with no production/test/docs usage.
- Find used symbols that are not exported through intended public entry points.
- Flag exports that expose scaffold-only, test-only, internal, or deprecated modules.
- Check whether consumers import internal paths that should be public API or should be forbidden.
- Update exports when ownership is clear.
- Create issues for breaking export changes or ambiguous public API decisions.
- Update docs when public package surface changes.

## Outputs

- Export drift report
- Export fixes/issues
- Public API notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not break external/public consumers silently
- Do not export testkits from production package root
- Do not hide public API changes

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Public surface is intentional
- Stale/fake exports are tracked or removed
- Consumers use intended paths
