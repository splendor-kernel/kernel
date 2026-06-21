---
name: import-boundary-scan
description: "Import Boundary Scan: Use when you need to find wrong-direction imports and package boundary violations."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/import-boundary-scan.md"
---

# Import Boundary Scan

## Purpose

Find wrong-direction imports and package boundary violations.

## Params

```yaml
  SOURCE_ROOTS: "<value>"
  INTERNAL_SCOPE: "<value>"
  ALLOWLIST_PATH: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Clean Architecture discovery
- PR review touching imports
- Dependency drift investigations

## Inputs

- Source files
- package.json files
- tsconfig references
- Architecture rule map

## Procedure

- Build a list of internal packages and layer roots.
- Scan static imports and re-exports, including index barrels.
- Classify each import by source layer, target layer, and package.
- Flag wrong-direction imports according to the rule map.
- Check whether flagged imports are allowed transitional exceptions.
- Find cycles or broad barrels that hide wrong-direction dependencies.
- For each violation, record source file, imported module, owning packages, and why it matters.
- Do not fix automatically unless the migration path is obvious and bounded.

## Outputs

- Import boundary report
- Issue updates for real violations
- False-positive notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not rely only on package names
- Do not ignore re-exports
- Do not miss test-only exceptions

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Every finding has exact file/import evidence
- Allowed exceptions are documented
- No speculative violations are filed
