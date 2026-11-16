PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PIPELINEGUARD := $(BIN)/pipelineguard
ADVISORY_DB := src/pipelineguard/advisories/osv-fixture.json

.PHONY: help install test lint format audit check demo demo-vulnerable demo-clean build clean

help:
	@echo "Targets:"
	@echo "  install           Create $(VENV) and install the project with dev extras"
	@echo "  test              Run the pytest suite"
	@echo "  lint              Run ruff check and format --check"
	@echo "  format            Apply ruff formatting and safe fixes"
	@echo "  audit             Run bandit over src"
	@echo "  check             Run lint, audit and tests"
	@echo "  demo-vulnerable   Scan the vulnerable example and expect exit code 1"
	@echo "  demo-clean        Scan the clean example and expect exit code 0"
	@echo "  build             Build a wheel and sdist"
	@echo "  clean             Remove caches and build output"

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

format:
	$(BIN)/ruff check --fix src tests
	$(BIN)/ruff format src tests

audit:
	$(BIN)/bandit -q -r src

check: lint audit test

demo-vulnerable:
	@$(PIPELINEGUARD) scan examples/vulnerable-repo --offline \
		--advisory-db $(ADVISORY_DB) --no-color; \
	code=$$?; \
	if [ "$$code" -eq 1 ]; then \
		echo "expected gate failure (exit 1)"; \
	else \
		echo "unexpected exit code $$code"; exit 1; \
	fi

demo-clean:
	$(PIPELINEGUARD) scan examples/clean-repo --offline --advisory-db $(ADVISORY_DB) --no-color

build:
	$(BIN)/python -m pip install --upgrade build
	$(BIN)/python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pipelineguard-cache -prune -exec rm -rf {} +
