"""FastAPI application factory.

``uvicorn app.main:app`` works because ``app`` is resolved lazily from the environment
(``SCREENTIME_CONFIG`` / ``SCREENTIME_USERS``); invalid configuration therefore stops the
service at startup with a clear message rather than serving half-configured.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.audit import configure_logging
from app.config import ConfigError, config_paths_from_env, load_all
from app.context import AppContext, build_context
from app.deps import ApiError, LoginRequired, client_ip, render
from app.routes import api, auth, child, health, parent
from app.runtime import limit_worker_threads
from app.version import VERSION

log = logging.getLogger("screentime.app")

BASE_DIR = Path(__file__).resolve().parent

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)


def _mmss(seconds: int) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 60}:{seconds % 60:02d}"


def _log_request(request: Request, status: int, started: float) -> None:
    """One structured line per request. Path only: never query strings, headers or cookies."""
    path = request.url.path
    if path.startswith("/static/"):
        return
    routine = path in {"/child/live", "/parent/live"} or path.startswith("/health/")
    log.log(
        logging.DEBUG if routine else logging.INFO,
        "request method=%s path=%s status=%d ms=%d ip=%s",
        request.method,
        path,
        status,
        int((time.monotonic() - started) * 1000),
        client_ip(request),
    )


def create_app(ctx: AppContext, *, run_background: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        limit_worker_threads()
        log.info(
            "starting screentime-controller version=%s mode=%s", VERSION, ctx.config.firewall.mode
        )
        await ctx.orchestrator.startup()
        if run_background:
            ctx.scheduler.start()
        try:
            yield
        finally:
            if run_background:
                await ctx.scheduler.stop()
            ctx.db.dispose()

    app = FastAPI(
        title="Screen-Time Controller",
        version=VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.ctx = ctx
    app.state.templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    app.state.templates.env.auto_reload = False  # templates never change while running
    app.state.templates.env.globals["version"] = VERSION
    app.state.templates.env.globals["app_name"] = "Screen Time"
    app.state.templates.env.filters["mmss"] = _mmss

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        started = time.monotonic()
        response = await call_next(request)
        _log_request(request, response.status_code, started)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.url.path.startswith("/static/"):
            # Never cache authenticated HTML/API state (spec section 20).
            response.headers["Cache-Control"] = "no-store"
        return response

    def wants_json(request: Request) -> bool:
        return request.url.path.startswith("/api/")

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError) -> Response:
        if wants_json(request):
            return JSONResponse(
                {"ok": False, "reason": exc.reason, "message": exc.message, **exc.extra},
                status_code=exc.status,
            )
        return render(
            request,
            "error.html",
            {"status": exc.status, "message": exc.message, "principal": None},
            exc.status,
        )

    @app.exception_handler(LoginRequired)
    async def login_required_handler(request: Request, exc: LoginRequired) -> Response:
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> Response:
        if wants_json(request):
            return JSONResponse(
                {
                    "ok": False,
                    "reason": "INVALID_REQUEST",
                    "message": "That request was not valid.",
                },
                status_code=422,
            )
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(404)
    async def not_found(request: Request, exc: Any) -> Response:
        if wants_json(request):
            return JSONResponse(
                {"ok": False, "reason": "NOT_FOUND", "message": "Not found."}, status_code=404
            )
        return HTMLResponse("Not found", status_code=404)

    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    for module in (auth, child, parent, api, health):
        app.include_router(module.router)
    return app


def create_app_from_env() -> FastAPI:
    config_path, users_path = config_paths_from_env()
    try:
        config, users = load_all(config_path, users_path)
    except ConfigError as exc:
        raise SystemExit(exc.render()) from exc
    ctx = build_context(config, users)
    return create_app(ctx)


def __getattr__(name: str) -> Any:
    """Lazily build ``app`` so importing this module for tests never touches the filesystem."""
    if name == "app":
        instance = create_app_from_env()
        globals()["app"] = instance
        return instance
    raise AttributeError(name)
