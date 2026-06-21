---
name: feature-flag-config-check
description: "Feature Flag and Config Check: Use when you need to verify services and features controlled by flags/config are discoverable, safe, and correctly wired."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/feature-flag-config-check.md"
---

# Feature Flag and Config Check

## Purpose

Verify services and features controlled by flags/config are discoverable, safe, and correctly wired.

## Params

```yaml
  FEATURE_NAME: "<value>"
  CONFIG_ROOTS: "<value>"
  ENV_DOCS: "<value>"
  COMPOSITION_ROOTS: "<value>"
  DEFAULT_POLICY: "<value>"
```

## Use When

- Feature behind flag
- Service appears dormant
- Config/env changes
- Release readiness

## Inputs

- Config code
- Env docs
- Deployment manifests
- Composition root
- Tests

## Procedure

- Find config keys, env vars, feature flags, defaults, and validation rules.
- Determine default behavior in local, test, staging, and production profiles when visible.
- Check whether disabled state is safe and enabled state wires real services.
- Verify missing/invalid config produces clear errors where required.
- Ensure docs/runbooks mention required config for production behavior.
- Add tests for enabled, disabled, and invalid config paths when practical.
- Update service inventory classification to integrated-behind-feature-flag when correct.
- Flag flags that permanently hide unfinished features without issue tracking.

## Outputs

- Config/flag evidence
- Updated docs/tests
- Inventory classification

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not treat a feature flag as proof of integration
- Do not fail hard on optional local-only config unless required
- Do not leave secret examples in docs

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Feature activation path is known
- Defaults are safe
- Production enablement does not rely on tribal knowledge
