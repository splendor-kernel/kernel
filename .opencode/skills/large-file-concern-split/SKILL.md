---
name: large-file-concern-split
description: "Large File Concern Split: Use when you need to split large or mixed-concern files only when extracting coherent behavior improves maintainability."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/large-file-concern-split.md"
---

# Large File Concern Split

## Purpose

Split large or mixed-concern files only when extracting coherent behavior improves maintainability.

## Params

```yaml
  TARGET_FILE: "<value>"
  CONCERN_MAP: "<value>"
  MAX_DIFF_RISK: "<value>"
  VALIDATION_COMMANDS: "<value>"
```

## Use When

- Large route/use-case/repository files
- Files with repeated merge conflicts
- Files mixing bounded contexts

## Inputs

- Target file
- Tests
- Imports/callers
- Architecture docs

## Procedure

- Map responsibilities inside the file before changing it.
- Group code by behavior/use case/repository concern, not by arbitrary helper type.
- Choose the smallest extraction that lowers risk and preserves behavior.
- Keep public API stable unless an intentional change is required.
- Move tests with behavior when needed and add focused tests for extracted pieces.
- Avoid churn-only reordering or formatting.
- Run targeted tests and architecture checks after extraction.
- Update split plan or issue with what remains.

## Outputs

- Extracted coherent files
- Updated imports/tests
- Remaining split plan

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not split solely because of line count
- Do not create barrel cycles
- Do not introduce new abstractions without need

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Behavior is preserved
- File concern boundaries are clearer
- Diff is reviewable
