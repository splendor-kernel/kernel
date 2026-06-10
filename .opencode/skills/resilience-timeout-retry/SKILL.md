---
name: resilience-timeout-retry
description: "Resilience, Timeout, and Retry: Use when you need to make external and distributed interactions robust without hiding failures."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/resilience-timeout-retry.md"
---

# Resilience, Timeout, and Retry

## Purpose

Make external and distributed interactions robust without hiding failures.

## Params

```yaml
  DEPENDENCY: "<value>"
  TIMEOUT_POLICY: "<value>"
  RETRY_POLICY: "<value>"
  FALLBACK_POLICY: "<value>"
```

## Use When

- External clients
- Workers/jobs
- Network calls
- Release hardening

## Inputs

- Client code
- Config
- Tests
- Error handling
- Observability

## Procedure

- Identify dependency failure modes: timeout, rate limit, 5xx, auth failure, invalid response, partial success.
- Set or verify timeouts at the boundary.
- Use retries only for transient failures and only with bounded attempts/backoff.
- Ensure non-idempotent operations are not retried unsafely.
- Define fallback behavior: fail closed, degrade gracefully, queue for retry, or block.
- Add tests for timeout, retryable failure, non-retryable failure, and fallback.
- Log retry/fallback events with correlation IDs.
- Document operational knobs if configurable.

## Outputs

- Timeout/retry config
- Failure tests
- Operational docs if needed

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not retry everything
- Do not swallow permanent failures
- Do not add infinite waits

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Dependencies fail predictably
- Retries are safe and bounded
- Failures remain visible
