#!/usr/bin/env bash
# The mobile acceptance tests (plan 8.3) in WebKit, the engine behind Safari on iPhone and iPad.
# Playwright's WebKit needs Ubuntu libraries, so this runs in Playwright's own container image,
# whose browsers match the Playwright release pinned here. Chromium runs locally in check.sh.
#
#   scripts/check_webkit.sh            # tests/e2e/test_mobile.py on WebKit and Chromium
#   scripts/check_webkit.sh -k ipad    # extra pytest arguments are passed through
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PLAYWRIGHT_VERSION=1.63.0
IMAGE=mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-noble
ENGINE=${CONTAINER_ENGINE:-podman}
command -v "$ENGINE" >/dev/null 2>&1 || { echo "$ENGINE not found (set CONTAINER_ENGINE)" >&2; exit 1; }

# As you, not root. The image has no venv module, so dependencies go to a throwaway user site
# inside the container. The image provides the browsers (/ms-playwright); the Playwright
# package is pinned to the same release so they match.
exec "$ENGINE" run --rm --userns=keep-id -e HOME=/tmp -e PYTHONUSERBASE=/tmp/pyuser \
    -v "$PWD:/src:Z" -w /src "$IMAGE" bash -c '
    set -euo pipefail
    pip install --quiet --user --break-system-packages --no-warn-script-location \
        ".[dev]" "playwright=='"$PLAYWRIGHT_VERSION"'"
    python3 -m pytest -q -p no:cacheprovider -m e2e tests/e2e/test_mobile.py "$@"
' bash "$@"
