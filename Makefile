.PHONY: help install install-dev lint format type-check test test-cov clean build pre-commit-install demo test-workflows

# Default target
help:
	@echo "OWASP Agentic AI Scanner - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install        Install production dependencies"
	@echo "  install-dev    Install development dependencies"
	@echo ""
	@echo "Quality:"
	@echo "  lint              Run ruff linter"
	@echo "  format            Format code with ruff"
	@echo "  type-check        Run mypy type checking"
	@echo "  pre-commit        Run all checks (lint, type-check, test)"
	@echo "  pre-commit-install Install pre-commit git hooks"
	@echo ""
	@echo "Testing:"
	@echo "  test           Run tests"
	@echo "  test-cov       Run tests with coverage"
	@echo ""
	@echo "Build:"
	@echo "  build          Build distribution packages"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  demo           Run scanner demo on example vulnerable code"
	@echo "  scan           Run scanner on example path"
	@echo ""
	@echo "CI/CD:"
	@echo "  test-workflows Test GitHub workflow changes locally"

# Setup
install:
	uv sync

install-dev:
	uv sync --all-extras
	uv run pre-commit install

pre-commit-install:
	uv run pre-commit install

# Quality
lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

type-check:
	uv run mypy src

pre-commit: format lint type-check test
	@echo "All checks passed!"

# Testing
test:
	uv run pytest tests/

test-cov:
	uv run pytest tests/ --cov=src/owasp_agentic_scanner --cov-report=term-missing --cov-report=html

# Build
build:
	uv build

clean:
	@echo "Cleaning up build artifacts and cache files..."
	# Python build artifacts
	rm -rf dist/ build/ develop-eggs/ downloads/ eggs/ .eggs/ lib/ lib64/ parts/ sdist/ var/ wheels/
	rm -rf *.egg-info/ .installed.cfg *.egg
	# Virtual environments
	rm -rf .venv/ venv/ env/
	# Python bytecode
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.py[cod]" -delete 2>/dev/null || true
	find . -type f -name "*$$py.class" -delete 2>/dev/null || true
	find . -type f -name "*.so" -delete 2>/dev/null || true
	# Testing and coverage
	rm -rf .pytest_cache/ .tox/ .nox/ htmlcov/ .coverage coverage.xml
	# Type checking and linting
	rm -rf .mypy_cache/ .ruff_cache/
	# Scanner cache
	rm -rf .owasp-cache/
	# Logs
	find . -type f -name "*.log" -delete 2>/dev/null || true
	# OS files
	find . -type f -name ".DS_Store" -delete 2>/dev/null || true
	find . -type f -name "Thumbs.db" -delete 2>/dev/null || true
	# IDE files
	find . -type f -name "*.swp" -delete 2>/dev/null || true
	find . -type f -name "*.swo" -delete 2>/dev/null || true
	find . -type f -name "*~" -delete 2>/dev/null || true
	# Scan results
	find . -type f -name "*.sarif" -delete 2>/dev/null || true
	rm -f results.json dataverse-agent-security-report.json
	@echo "Clean complete!"

# Usage examples
demo:
	@echo "Running OWASP Agentic AI Scanner Demo on example vulnerable code..."
	@echo ""
	uv run owasp-scan scan examples/ --verbose

scan:
	uv run owasp-scan scan . --rules goal_hijack,code_execution

# CI/CD Testing
test-workflows:
	@echo "Testing GitHub workflow changes locally..."
	@bash scripts/test-security-workflow.sh
