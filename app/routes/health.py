"""Liveness/readiness for local supervision, and the PWA plumbing routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from app.deps import ctx_of, is_local_client, render
from app.runtime import run_sync
from app.version import VERSION

router = APIRouter()
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@router.get("/health/live", include_in_schema=False)
async def live(request: Request) -> Response:
    if not is_local_client(request):
        return JSONResponse({"status": "not found"}, status_code=404)
    return JSONResponse({"status": "ok", "version": VERSION})


@router.get("/health/ready", include_in_schema=False)
async def ready(request: Request) -> Response:
    if not is_local_client(request):
        return JSONResponse({"status": "not found"}, status_code=404)
    ctx = ctx_of(request)
    db_ok = await run_sync(ctx.db.check)
    firewall_ok = not ctx.enforcement.degraded
    ok = db_ok and firewall_ok
    return JSONResponse(
        {
            "status": "ready" if ok else "degraded",
            "database": "ok" if db_ok else "error",
            "firewall": "ok" if firewall_ok else "degraded",
            "version": VERSION,
        },
        status_code=200 if ok else 503,
    )


@router.get("/service-worker.js", include_in_schema=False)
async def service_worker() -> Response:
    # Served from the root so its scope covers the whole app.
    return FileResponse(
        STATIC_DIR / "service-worker.js",
        media_type="text/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


@router.get("/offline", response_class=HTMLResponse, include_in_schema=False)
async def offline(request: Request) -> Response:
    return render(request, "offline.html", {"principal": None})
