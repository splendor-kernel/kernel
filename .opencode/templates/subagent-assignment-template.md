# Sub-Agent Assignment Template

## Assignment

Issue:
Task IDs:
Assignment ID:
Objective:
Branch:
Base branch:
State root:
State files root:

## Required State Files

Read before coding and after compaction:

```text
<STATE_ROOT>/rules-lock.md
<STATE_ROOT>/run-context.md
<STATE_ROOT>/current-loop.md
<STATE_ROOT>/issue-map.json
<STATE_ROOT>/assignment-board.md
<STATE_ROOT>/validation-log.md
<STATE_ROOT>/decisions.md
<STATE_ROOT>/handoff.md
<STATE_ROOT>/compaction-checkpoint.md
<STATE_FILES_ROOT>/subagents/<assignment-id>/assignment.md
```

Write before final response and before compaction:

```text
<STATE_FILES_ROOT>/subagents/<assignment-id>/handoff.md
<STATE_FILES_ROOT>/subagents/<assignment-id>/validation.md
<STATE_FILES_ROOT>/subagents/<assignment-id>/diff-notes.md
```

## Verified Evidence

- File/path:
- Command/import/service evidence:
- Why this matters:

## Context

Architecture rules:
Existing conventions:
Related docs/issues/PRs:
Related services:
UI/user-flow considerations:
Splendor considerations, if any:

## Scope

Required:
Out of scope:
Dependencies:

## Acceptance Criteria

- [ ] Behavior is preserved or intentional change is documented.
- [ ] Production wiring is real and not bypassed.
- [ ] Tests cover realistic success/failure/integration behavior.
- [ ] Mocks are only used at valid test boundaries.
- [ ] Config/schema/migration/docs/exports are updated if relevant.
- [ ] No placeholders, fake implementations, hidden TODOs, or untracked follow-up.
- [ ] State files are updated under the task-scoped state root.

## Validation

Commands:
User-flow QA:
Integration checks:
Architecture/security checks:

## Forbidden Shortcuts

- No mock replacing required production behavior.
- No isolated component without integration.
- No folder-only migration.
- No silent deletion of purposeful services.
- No hidden follow-up.
- No closing issue before merge evidence exists.
- No broad project-level state root.
- No repo-tracked temp handoff/report unless explicitly required.

## Expected Output

What changed:
Validation:
State files updated:
Risks:
PR summary draft:
