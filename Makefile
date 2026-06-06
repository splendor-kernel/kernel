.PHONY: e2e-acceptance

e2e-acceptance:
	bash scripts/e2e/verify-use-case-acceptance.sh --all
