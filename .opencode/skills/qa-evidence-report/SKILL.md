---
name: qa-evidence-report
description: "QA Evidence Report: Use when you need to produce concise, credible validation evidence for PRs and handoff."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/qa-evidence-report.md"
---

# QA Evidence Report

## Purpose

Produce concise, credible validation evidence for PRs and handoff.

## Params

```yaml
  RUN_ID: "<value>"
  PR_ID: "<value>"
  VALIDATION_LOG: "<value>"
  USER_QA_LOG: "<value>"
  KNOWN_RISKS: "<value>"
```

## Use When

- Final PR
- Sub-agent PR
- Handoff
- Issue closure

## Inputs

- Validation commands
- CI results
- User-flow QA
- Issue criteria

## Procedure

- Group validation into passed, failed, not run, and blocked.
- For each command, include exact command and result.
- For not-run checks, include reason, risk, and alternative validation.
- For user-flow QA, include steps and observed result.
- For known failures accepted as non-blocking, include why and linked issue.
- Keep evidence factual and concise.
- Do not bury critical failures under long summaries.
- Reuse this report in PR body, issue close comments, and handoff.

## Outputs

- QA evidence section
- Issue close evidence
- Handoff validation block

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not say “validated” without evidence
- Do not hide not-run checks
- Do not overquote logs

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Readers can trust what was and was not validated
- Risk is visible
- No validation is overstated
