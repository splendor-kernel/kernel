.PHONY: e2e-acceptance security-secret-contracts

e2e-acceptance:
	bash scripts/e2e/verify-use-case-acceptance.sh --all

security-secret-contracts:
	@set -eu; \
	sha="$$(git rev-parse HEAD)"; \
	/usr/bin/python3 -I scripts/security/check-secret-contracts.py --git-tree "$${sha}"; \
	sandbox="$$(mktemp -d)"; \
	trap 'rm -rf "$${sandbox}"' EXIT; \
	git archive "$${sha}" | tar -x -C "$${sandbox}"; \
	cd "$${sandbox}"; \
	git init -q; \
	git add --all; \
	env -i HOME="$${sandbox}" PATH="/usr/bin:/bin" /usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test
