---
name: local-validation-gates
description: "Local Validation Gates: Use when you need to run the strongest available local checks and report exactly what passed, failed, or could not run."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/local-validation-gates.md"
---

# Local Validation Gates

## Purpose

Run the strongest available local checks and report exactly what passed, failed, or could not run.

## Params

```yaml
  REQUIRED_COMMANDS: "<value>"
  OPTIONAL_COMMANDS: "<value>"
  ENVIRONMENT_NOTES: "<value>"
  STATE_ROOT: "<value>"
```

## Use When

- Before sub-agent PR merge
- Before final PR
- Before dev merge
- After conflict resolution

## Inputs

- Repo scripts
- Package manager
- Validation log
- Changed files

## Procedure

- Run `git status --short` first.
- Run required repo checks such as lint, architecture, secrets, security shortcut, contract, typecheck, test, build, and e2e when available.
- Record exact command, result, duration when useful, and failure excerpt.
- If a command cannot run, record reason, risk, and alternative validation.
- Do not claim full validation when tooling/dependencies/environment are missing.
- Rerun affected checks after fixes or conflict resolution.
- Store results in validation log and PR body.
- Keep local validation separate from CI validation; both matter.

## Outputs

- Validation log
- PR validation section
- Blocker list

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not ignore failing checks
- Do not say “all tests pass” unless they did
- Do not hide environment limitations

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Every relevant check has a truthful status
- Failures are fixed or block merge
- Unavailable checks have risk notes
