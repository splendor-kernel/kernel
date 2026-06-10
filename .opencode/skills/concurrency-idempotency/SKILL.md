---
name: concurrency-idempotency
description: "Concurrency and Idempotency: Use when you need to protect production workflows from duplicate requests, races, retries, and partial failure."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/concurrency-idempotency.md"
---

# Concurrency and Idempotency

## Purpose

Protect production workflows from duplicate requests, races, retries, and partial failure.

## Params

```yaml
  WORKFLOW: "<value>"
  STATE_TRANSITIONS: "<value>"
  RETRY_POLICY: "<value>"
  DEDUP_KEY: "<value>"
```

## Use When

- Runtime jobs
- Payments/approvals/actions
- Webhook/API mutations
- External calls
- Queue workers

## Inputs

- Workflow code
- Database constraints
- Job/queue config
- Tests
- Logs

## Procedure

- Identify critical state transitions and side effects.
- Determine which operations may be retried, duplicated, reordered, or run concurrently.
- Add idempotency keys, unique constraints, compare-and-set, locks, or state guards according to project patterns.
- Ensure external calls are not repeated unsafely after partial failure.
- Add tests for duplicate submission, concurrent execution, retry after failure, and stale state when practical.
- Log enough correlation data to debug duplicates without leaking secrets.
- Document any accepted at-least-once behavior.
- Keep idempotency logic in application/domain where business state matters, infrastructure where transport-specific.

## Outputs

- Idempotency guard
- Concurrency tests
- Operational notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not rely on UI disabling buttons for idempotency
- Do not assume single worker unless enforced
- Do not make locks too broad without reason

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Duplicate work is safe or explicitly bounded
- State transitions are predictable
- Retries are understood
