#!/usr/bin/env bash
# One command for everything: formatting, lint, strict typing, shell syntax, tests + coverage.
#
#   scripts/check.sh            # full run (this is what `make test` calls)
#   scripts/check.sh --fast     # skip coverage measurement
#   scripts/check.sh --no-e2e   # skip the Playwright browser tests
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PY=${PYTHON:-.venv/bin/python}
[ -x "$PY" ] || { echo "No virtualenv at .venv: run 'make install' (or see README Quick Start)" >&2; exit 1; }

FAST=0
E2E=1
for arg in "$@"; do
    case "$arg" in
        --fast) FAST=1 ;;
        --no-e2e) E2E=0 ;;
        *) echo "unknown option: $arg" >&2; exit 64 ;;
    esac
done

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step "ruff format"
"$PY" -m ruff format --check app tests scripts migrations
step "ruff lint"
"$PY" -m ruff check app tests scripts migrations
step "mypy (strict)"
"$PY" -m mypy
step "shell syntax"
for f in deploy/*.sh scripts/*.sh; do bash -n "$f"; done
sh -n deploy/pfsense-screenctl.sh

MARK=()
[ "$E2E" -eq 0 ] && MARK=(-m "not e2e")
step "pytest"
if [ "$FAST" -eq 1 ]; then
    "$PY" -m pytest -q "${MARK[@]}"
else
    "$PY" -m pytest -q "${MARK[@]}" --cov=app --cov-branch \
        --cov-report=term-missing:skip-covered --cov-report=xml --cov-fail-under=85
fi
printf '\nAll checks passed.\n'
