---
name: compatibility-seam-review
description: "Compatibility Seam Review: Use when you need to review broad shims and compatibility adapters to keep them from becoming permanent architecture traps."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/compatibility-seam-review.md"
---

# Compatibility Seam Review

## Purpose

Review broad shims and compatibility adapters to keep them from becoming permanent architecture traps.

## Params

```yaml
  SEAM_FILES: "<value>"
  TARGET_BOUNDARIES: "<value>"
  REMOVAL_ISSUE_LABEL: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Large repository adapters
- Legacy route repositories
- Migration shims
- Broad composition roots

## Inputs

- Seam source files
- Call graph
- Issue tracker
- Migration docs

## Procedure

- Identify the seam’s purpose: backward compatibility, strangler migration, test helper, or accidental abstraction.
- Map callers, delegated targets, and bounded contexts hidden behind the seam.
- Check whether new code is still being added to the seam instead of narrow ports/use cases.
- Identify safe extraction candidates by cohesive context or use case.
- Require a removal or shrink plan when the seam is intentionally temporary.
- Do not remove the seam until replacement production paths are wired and validated.
- Create issues for new work that expands the seam without justification.
- Update migration plan with current seam size, risks, and next extraction.

## Outputs

- Seam map
- Shrink/removal issues
- Migration plan update

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not delete compatibility code prematurely
- Do not normalize accidental broad interfaces
- Do not split by line count alone

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The seam’s status is explicit
- New growth is controlled
- Replacement work is sequenced
