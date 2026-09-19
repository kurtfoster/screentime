"""Small bridge between async request handling and the synchronous SQLite services."""

from __future__ import annotations

from collections.abc import Callable

import anyio.to_thread


async def run_sync[**P, R](func: Callable[P, R], /, *args: P.args, **kwargs: P.kwargs) -> R:
    """Run blocking database work in a worker thread (contextvars are propagated)."""
    return await anyio.to_thread.run_sync(lambda: func(*args, **kwargs))
