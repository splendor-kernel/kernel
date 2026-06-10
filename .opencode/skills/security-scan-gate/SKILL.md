---
name: security-scan-gate
description: "Security Scan Gate: Use when you need to run and interpret security/secret/shortcut checks before integration or release."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/security-scan-gate.md"
---

# Security Scan Gate

## Purpose

Run and interpret security/secret/shortcut checks before integration or release.

## Params

```yaml
  SCAN_COMMANDS: "<value>"
  CHANGED_FILES: "<value>"
  RISK_AREAS: "<value>"
  ESCALATION_POLICY: "<value>"
```

## Use When

- Before final PR
- Security-sensitive changes
- Config/logging/external service changes

## Inputs

- Repo security scripts
- Changed files
- Logs
- Validation policy

## Procedure

- Run available secret scans, security shortcut scans, dependency audit, and repo-specific policy checks.
- Inspect failures instead of suppressing them.
- Check changed files manually for secrets, tokens, debug bypasses, auth skips, broad permissions, unsafe logs, and test shortcuts leaking to production.
- Determine if findings are real, false positive, or baseline.
- Fix real findings immediately or block merge.
- Document false positives with allowlist only through project-approved mechanism.
- Escalate unclear auth/policy questions.
- Record exact scan commands and outcomes.

## Outputs

- Security validation log
- Fixes/issues
- Merge decision input

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not commit secrets
- Do not suppress scans casually
- Do not merge known auth/policy bypass

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- No known security shortcut is introduced
- Scans are truthful
- False positives are documented
