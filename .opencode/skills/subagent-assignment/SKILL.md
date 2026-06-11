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

Give implementation agents enough context to solve one task correctly without redefining scope or losing state across compaction.

## Params

```yaml
  TASK_IDS: "<value>"
  ISSUE_ID: "<value>"
  ASSIGNMENT_ID: "<stable assignment id>"
  OBJECTIVE: "<value>"
  BRANCH: "<value>"
  BASE_BRANCH: "<value>"
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
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
- Task-scoped state capsule

## Procedure

- State the objective as one bounded outcome.
- Assign a stable `<ASSIGNMENT_ID>` and create `<STATE_FILES_ROOT>/subagents/<assignment-id>/assignment.md`.
- Include exact `STATE_ROOT` and `STATE_FILES_ROOT`; require the sub-agent to read root state files before coding and after compaction.
- List exact evidence: file paths, symbols, failing behavior, drift, or missing wiring.
- List relevant files and modules to inspect first.
- Define architecture constraints and service-integration expectations.
- Specify out-of-scope work and forbidden shortcuts.
- Require tests for realistic success and failure paths.
- Require docs/config/schema/export updates when applicable.
- Require the sub-agent to write `handoff.md`, `validation.md`, and `diff-notes.md` under `<STATE_FILES_ROOT>/subagents/<assignment-id>/`.
- Require a final report with what changed, validation, risks, state files updated, and PR summary draft.

## Outputs

- Assignment message
- `<STATE_FILES_ROOT>/subagents/<assignment-id>/assignment.md`
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
- Do not let sub-agents invent a separate state root for the same task range

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Sub-agent can work without guessing
- Scope is bounded
- State-root and output-file paths are explicit
- Validation and shortcuts are explicit
