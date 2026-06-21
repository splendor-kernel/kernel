---
name: pr-review
description: "PR Review: Use when you need to review PRs for real completeness across correctness, integration, architecture, tests, UI, and maintainability."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/pr-review.md"
---

# PR Review

## Purpose

Review PRs for real completeness across correctness, integration, architecture, tests, UI, and maintainability.

## Params

```yaml
  PR_ID: "<value>"
  ISSUE_ID: "<value>"
  REVIEW_MODE: "<value>"
  BASE_BRANCH: "<value>"
  RISK_LEVEL: "<value>"
```

## Use When

- Every sub-agent PR
- Final PR readiness review
- Regression fixes

## Inputs

- PR diff
- Issue acceptance criteria
- Validation evidence
- Repo conventions
- Service inventory

## Procedure

- Read the issue and assignment before reviewing the diff.
- Check whether the PR solves the stated problem without expanding scope unnecessarily.
- Inspect production wiring, not just tests.
- Check architecture dependency direction and package/export/config drift.
- Check success, failure, and integration tests.
- Check whether mocks stay at valid test boundaries.
- For UI, check cognitive load, accessibility, empty/loading/error states, and user flow validation.
- Require fixes for hidden TODOs, placeholders, fake services, brittle assumptions, or incomplete validation.
- Approve only when the diff is reviewable, integrated, and evidence-backed.

## Outputs

- Review decision
- Fix requests or approval
- Updated tracker

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not approve because tests pass alone
- Do not ignore missing docs/config/schema updates
- Do not allow architecture drift to move elsewhere

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- PR is approved with evidence or blocked with clear asks
- Issue state remains truthful
