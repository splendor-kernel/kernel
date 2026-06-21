---
name: ci-validation-review
description: "CI Validation Review: Use when you need to read CI results and distinguish real failures, environment failures, and irrelevant checks."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/ci-validation-review.md"
---

# CI Validation Review

## Purpose

Read CI results and distinguish real failures, environment failures, and irrelevant checks.

## Params

```yaml
  PR_ID: "<value>"
  REQUIRED_CHECKS: "<value>"
  CI_PROVIDER: "<value>"
  RERUN_POLICY: "<value>"
```

## Use When

- Final PR
- Sub-agent PR review
- After local validation
- Before merge

## Inputs

- CI check results
- Logs
- Local validation log
- Changed files

## Procedure

- List all required and relevant optional checks.
- Open failing logs and identify root cause category: code, test flake, environment, dependency, permission, unrelated baseline.
- Compare CI failures to local results.
- Rerun only when failure plausibly flaky or environment-related and policy allows.
- Require code/test fixes for deterministic failures.
- Record skipped/unavailable checks and risk.
- Do not merge with unknown failing checks.
- Update PR and state capsule with CI status.

## Outputs

- CI review notes
- Fix/rerun decisions
- Merge readiness status

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not ignore red required checks
- Do not blame flake without evidence
- Do not rerun endlessly

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- CI status is understood
- Failures are not hand-waved
- Merge decision is evidence-backed
