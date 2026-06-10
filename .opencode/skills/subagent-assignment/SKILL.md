---
name: subagent-assignment
description: "Sub-Agent Assignment: Use when you need to give implementation agents enough context to solve one task correctly without redefining scope."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/subagent-assignment.md"
---

# Sub-Agent Assignment

## Purpose

Give implementation agents enough context to solve one task correctly without redefining scope.

## Params

```yaml
  ISSUE_ID: "<value>"
  OBJECTIVE: "<value>"
  BRANCH: "<value>"
  BASE_BRANCH: "<value>"
  RELEVANT_FILES: "<value>"
  VALIDATION_COMMANDS: "<value>"
  OUT_OF_SCOPE: "<value>"
```

## Use When

- Delegating any non-trivial code task
- Parallelizing work
- Reassigning failed or incomplete work

## Inputs

- Issue body
- Evidence
- Relevant docs
- Architecture rules
- Known risks

## Procedure

- State the objective as one bounded outcome.
- List exact evidence: file paths, symbols, failing behavior, drift, or missing wiring.
- List relevant files and modules to inspect first.
- Define architecture constraints and service-integration expectations.
- Specify out-of-scope work and forbidden shortcuts.
- Require tests for realistic success and failure paths.
- Require docs/config/schema/export updates when applicable.
- Require a final report with what changed, validation, risks, and PR summary draft.

## Outputs

- Assignment message
- Branch/worktree instructions
- Acceptance criteria

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not delegate vague “clean this up” work
- Do not omit known risks
- Do not let sub-agents target dev directly

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Sub-agent can work without guessing
- Scope is bounded
- Validation and shortcuts are explicit
