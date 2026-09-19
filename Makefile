# Convenience wrapper around the scripts in ./scripts. Everything works without make too.
PY ?= .venv/bin/python

.PHONY: help install test fast lint fmt e2e run dev-users check-config clean

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'

install:         ## create .venv and install runtime + dev dependencies
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

test:            ## lint + types + tests + coverage (the single command)
	scripts/check.sh

fast:            ## same, without coverage
	scripts/check.sh --fast

lint:            ## ruff + mypy only
	$(PY) -m ruff format --check app tests scripts migrations
	$(PY) -m ruff check app tests scripts migrations
	$(PY) -m mypy

fmt:             ## apply formatting and safe lint fixes
	$(PY) -m ruff format app tests scripts migrations
	$(PY) -m ruff check --fix app tests scripts migrations

e2e:             ## everything including the Playwright browser tests
	scripts/check.sh --e2e

dev-users:       ## write config/users.dev.yaml with throwaway passwords
	$(PY) scripts/make_dev_users.py

run:             ## run the app locally in dry-run mode on http://127.0.0.1:8080
	SCREENTIME_CONFIG=config/config.dev.yaml SCREENTIME_USERS=config/users.dev.yaml \
	$(PY) -m uvicorn app.main:app --host 127.0.0.1 --port 8080

check-config:    ## validate the development configuration
	SCREENTIME_CONFIG=config/config.dev.yaml SCREENTIME_USERS=config/users.dev.yaml $(PY) -m app --check-config

clean:           ## remove caches and coverage output
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml .coverage
