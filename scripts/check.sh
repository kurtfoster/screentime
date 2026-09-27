#!/usr/bin/env bash
# One command for everything: formatting, lint, strict typing, shell syntax, tests + coverage.
#
#   scripts/check.sh                    # full run (this is what `make test` calls)
#   scripts/check.sh --fast             # skip coverage measurement
#   scripts/check.sh --no-e2e           # skip the Playwright browser tests
#   scripts/check.sh --profile trixie   # Python 3.13 + the Raspberry Pi OS Trixie library
#                                       # versions (constraints/trixie.txt) in .venv-trixie;
#                                       # implies --no-e2e. Set PYTHON313 to choose the interpreter.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FAST=0
E2E=1
PROFILE=default
while [ $# -gt 0 ]; do
    case "$1" in
        --fast) FAST=1; shift ;;
        --no-e2e) E2E=0; shift ;;
        --profile) PROFILE=${2:-}; shift 2 || { echo "--profile needs a value" >&2; exit 64; } ;;
        --profile=*) PROFILE=${1#--profile=}; shift ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

case "$PROFILE" in
    default)
        PY=${PYTHON:-.venv/bin/python}
        [ -x "$PY" ] || { echo "No virtualenv at .venv: run 'make install' (or see README Quick Start)" >&2; exit 1; }
        ;;
    trixie)
        # Playwright is a development-only tool and is not part of the parity check.
        E2E=0
        PY313=${PYTHON313:-python3.13}
        command -v "$PY313" >/dev/null 2>&1 || {
            echo "The trixie profile needs Python 3.13 ($PY313 not found). Install it, set PYTHON313," >&2
            echo "or run it in a container (as you, not root: the pfSense wrapper tests need that):" >&2
            echo "  podman run --rm --userns=keep-id -e HOME=/tmp -v \"\$PWD:/src:Z\" -w /src \\" >&2
            echo "    docker.io/library/python:3.13-slim-trixie scripts/check.sh --profile trixie" >&2
            exit 1
        }
        VENV=.venv-trixie
        STAMP=$VENV/.constraints
        if [ ! -x "$VENV/bin/python" ] || ! cmp -s constraints/trixie.txt "$STAMP" 2>/dev/null \
            || [ pyproject.toml -nt "$STAMP" ]; then
            printf '\n\033[1m== building %s (%s)\033[0m\n' "$VENV" "$("$PY313" -V)"
            "$PY313" -m venv --clear "$VENV"
            "$VENV/bin/python" -m pip install --quiet --upgrade pip
            "$VENV/bin/python" -m pip install --quiet -c constraints/trixie.txt -e ".[dev]"
            cp constraints/trixie.txt "$STAMP"
        fi
        PY=$VENV/bin/python
        "$PY" -m app --check-deps
        ;;
    *) echo "unknown profile: $PROFILE (expected default or trixie)" >&2; exit 64 ;;
esac

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
