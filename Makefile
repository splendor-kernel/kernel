.PHONY: e2e-acceptance security-secret-contracts

e2e-acceptance:
	bash scripts/e2e/verify-use-case-acceptance.sh --all

security-secret-contracts:
	python3 scripts/security/check-secret-contracts.py --self-test
	python3 scripts/security/check-secret-contracts.py
