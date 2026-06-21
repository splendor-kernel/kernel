---
name: issue-triage
description: "Issue Triage: Use when you need to use GitHub issues as the actionable source of truth while avoiding duplicates and stale claims."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/issue-triage.md"
---

# Issue Triage

## Purpose

Use GitHub issues as the actionable source of truth while avoiding duplicates and stale claims.

## Params

```yaml
  ISSUE_SELECTOR: "<value>"
  LABELS: "<value>"
  CREATE_ALLOWED: "<value>"
  UPDATE_ALLOWED: "<value>"
  CLOSE_ALLOWED: "<value>"
```

## Use When

- Discovery produces findings
- Planning a workstream
- Reviewing completed work
- Before final report

## Inputs

- Open/closed issues
- Findings with evidence
- Repo trackers
- PR history

## Procedure

- Search open and closed issues by label, path, symbol, short title, and likely aliases.
- Group findings into existing issue, new issue needed, obsolete, blocked, or needs-investigation.
- For existing issues, verify whether the evidence is still current on latest code.
- Create a new issue only when the finding is distinct and evidence-backed.
- Update issues with current file paths, command output, risk, and acceptance criteria.
- Close only after merge to `<DEV_BRANCH>` or proof that the issue is obsolete on latest base.
- Every close comment must include PR/commit, validation evidence, and remaining follow-up if any.
- Use labels for severity, category, blocked status, and ownership.

## Outputs

- Created/updated/closed issue list
- Issue map JSON
- Triage notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not delete issues
- Do not close because tests pass if integration remains wrong
- Do not create speculative issues

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- No duplicate issues are created
- Issue state matches code reality
- Every active issue has a next action
