---
name: service-classification-decision
description: "Service Classification Decision: Use when you need to choose the correct lifecycle classification and next action for a service."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/service-classification-decision.md"
---

# Service Classification Decision

## Purpose

Choose the correct lifecycle classification and next action for a service.

## Params

```yaml
  SERVICE_NAME: "<value>"
  PURPOSE_EVIDENCE: "<value>"
  WIRING_EVIDENCE: "<value>"
  RISK_LEVEL: "<value>"
```

## Use When

- After purpose/wiring checks
- Before issue creation
- Before deletion or wiring

## Inputs

- Purpose inference
- Wiring check
- Mock check
- Docs/tests/config evidence

## Procedure

- Select exactly one primary classification: integrated-live, integrated-behind-feature-flag, implemented-not-wired, mock-only, test-only, scaffold-only, duplicate-replaced, dead-remove-candidate, purposeful-but-blocked, or needs-investigation.
- Record evidence for why alternatives were rejected.
- For integrated-live, verify tests/docs are adequate.
- For behind-feature-flag, document flag/config path.
- For implemented-not-wired, create issue or wire if bounded.
- For mock-only, create high-priority issue when production behavior is expected.
- For scaffold-only, remove if misleading and low-risk or track as planned.
- For dead-remove-candidate, require strong evidence and issue history before deletion.
- For purposeful-but-blocked, record exact blocker and safe next step.

## Outputs

- Classification entry
- Next action
- Issue/PR update

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not classify as dead when docs/config/migrations suggest purpose
- Do not classify mock-only as integrated
- Do not leave needs-investigation without a concrete query/task

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Classification is defensible
- Risky decisions are not hidden
- Next action matches classification
