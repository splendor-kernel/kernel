---
name: tsconfig-reference-drift-scan
description: "TSConfig Reference Drift Scan: Use when you need to keep TypeScript project references aligned with actual package relationships."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/tsconfig-reference-drift-scan.md"
---

# TSConfig Reference Drift Scan

## Purpose

Keep TypeScript project references aligned with actual package relationships.

## Params

```yaml
  TSCONFIG_GLOB: "<value>"
  SOURCE_ROOTS: "<value>"
  INTERNAL_SCOPE: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Monorepo build issues
- Dependency graph cleanup
- Architecture migration

## Inputs

- tsconfig files
- Source imports
- Package manifests
- Build scripts

## Procedure

- Parse every `references` array.
- Map each reference to package/root and actual source imports.
- Flag references with no import/build reason.
- Flag source imports that lack required references.
- Check consistency between tsconfig references and package dependencies.
- Consider generated types, build ordering, test projects, and composite packages before removing references.
- Apply safe mechanical fixes or create issues for ambiguous references.
- Run typecheck/build or project-specific architecture checks after changes.

## Outputs

- TS reference drift report
- Safe tsconfig fixes
- Issue updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not remove references needed for generated/build output
- Do not trust source imports alone
- Do not skip validation after tsconfig changes

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Project references are explainable
- Build graph drift is reduced
- False positives are documented
