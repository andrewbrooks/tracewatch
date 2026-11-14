# Standard tasks. Everything runs through uv, so there is nothing to activate.
.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help setup lint format typecheck test check secrets audit-deps audit build

help: ## List the available tasks
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

setup: ## Install locked dependencies and enable the pre-commit hook
	$(UV) sync --locked
	git config core.hooksPath .githooks

lint: ## Lint and check formatting (what CI runs)
	$(UV) run --no-sync ruff check .
	$(UV) run --no-sync ruff format --check .

format: ## Format the code in place
	$(UV) run --no-sync ruff format .

typecheck: ## Type-check src/ with mypy
	$(UV) run --no-sync mypy

test: ## Unit tests (no Docker needed)
	$(UV) run --no-sync pytest -q

check: lint typecheck test ## Everything CI checks, except the browser suite

secrets: ## Scan the repository history for secrets
	gitleaks detect --redact --no-banner

audit-deps: ## Check locked dependencies for known vulnerabilities
	$(UV) audit --preview-features audit-command

audit: ## Pre-publication audit of the tree and every commit
	python3 -I tools/audit.py

build: ## Build the wheel and sdist into dist/
	$(UV) build
