"""Small bridge between async request handling and the synchronous SQLite services."""

from __future__ import annotations

from collections.abc import Callable

import anyio.to_thread

# anyio's default is 40 worker threads. One core gains nothing from more than a few, and each
# idle thread still holds a stack; fewer threads also bound memory under a burst of requests.
WORKER_THREADS = 8


def limit_worker_threads(tokens: int = WORKER_THREADS) -> None:
    """Cap blocking work (SQLite, password checks) for the running event loop."""
    anyio.to_thread.current_default_thread_limiter().total_tokens = tokens


async def run_sync[**P, R](func: Callable[P, R], /, *args: P.args, **kwargs: P.kwargs) -> R:
    """Run blocking database work in a worker thread (contextvars are propagated)."""
    return await anyio.to_thread.run_sync(lambda: func(*args, **kwargs))
