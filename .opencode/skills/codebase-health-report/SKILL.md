---
name: codebase-health-report
description: "Codebase Health Report: Use when you need to produce an evidence-backed snapshot of maintainability, architecture, QA, service integration, and operational debt."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/codebase-health-report.md"
---

# Codebase Health Report

## Purpose

Produce an evidence-backed snapshot of maintainability, architecture, QA, service integration, and operational debt.

## Params

```yaml
  REPORT_PATH: "<value>"
  SCOPE: "<value>"
  SEVERITY_MODEL: "<value>"
  INPUT_REPORTS: "<value>"
```

## Use When

- Periodic maintenance
- After discovery loop
- Before planning larger cleanup
- Executive/project health update

## Inputs

- Findings
- Validation logs
- Issue tracker
- Service inventory
- Dependency reports

## Procedure

- Collect verified findings from architecture, service, dependency, QA, release, and operational skills.
- Group by P0/P1/P2/P3 and by category.
- Distinguish fixed, still present, newly discovered, blocked, deferred, and needs-investigation.
- Include exact issue/PR links and file paths for key findings.
- Highlight trends: recurring drift, broad seams, unintegrated services, weak tests, fragile release evidence.
- Recommend the next 3–7 bounded actions, not a giant rewrite.
- Store report in the repo or state capsule according to durability needs.
- Update issue backlog based on report findings.

## Outputs

- Health report
- Prioritized backlog
- Handoff summary

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not inflate severity
- Do not hide blocked items
- Do not turn report into untracked TODO list

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Report is evidence-backed
- Actions are bounded
- No speculative panic or false certainty
