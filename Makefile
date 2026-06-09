# ADEPT developer task runner. Requires `uv` (https://docs.astral.sh/uv/).
.DEFAULT_GOAL := help
.PHONY: help install install-all lint format typecheck test check mcp agent dac eval clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install base + dev dependencies (fast; for foundation work)
	uv sync --group dev

install-all: ## Install every component extra + dev (full environment)
	uv sync --all-extras --group dev

lint: ## Lint with ruff
	uv run ruff check adept tests

format: ## Auto-format with ruff
	uv run ruff format adept tests
	uv run ruff check --fix adept tests

typecheck: ## Static type-check with mypy
	uv run mypy adept

test: ## Run the test suite
	uv run pytest

check: lint typecheck test ## Run lint + types + tests (CI gate)

mcp: ## Run the MCP server
	uv run adept-mcp

agent: ## Run the agent CLI chatbot
	uv run adept

dac: ## Run the detection-as-code CLI
	uv run adept-dac --help

eval: ## Run the offline detection-quality evaluation (golden cases)
	uv run adept-eval rules

clean: ## Remove caches and build artifacts
	rm -rf .mypy_cache .ruff_cache .pytest_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
