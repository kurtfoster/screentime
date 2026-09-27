"""Parent dashboard, live fragment and diagnostics."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select

from app.auth import Principal
from app.db import current_revision
from app.deps import ctx_of, parent_page, render
from app.models import AuditEvent, FirewallEvent
from app.runtime import run_sync
from app.runtime_deps import dependency_report
from app.version import VERSION
from app.views import ParentView

router = APIRouter()


async def _build(request: Request) -> ParentView:
    ctx = ctx_of(request)

    clock_synchronised = ctx.enforcement.clock_synchronised()

    def build() -> ParentView:
        locked = [name for name, _ in ctx.auth.locked_children()]
        with ctx.db.session() as session:
            return ctx.views.parent_view(
                session,
                ctx.clock.now(),
                degraded=ctx.enforcement.degraded,
                degraded_error=ctx.enforcement.last_error or "",
                locked=locked,
                clock_synchronised=clock_synchronised,
            )

    return await run_sync(build)


@router.get("/parent", response_class=HTMLResponse)
async def parent_dashboard(
    request: Request, principal: Principal = Depends(parent_page)
) -> Response:
    view = await _build(request)
    return render(
        request,
        "parent.html",
        {"view": view, "principal": principal, "csrf_token": principal.csrf_token},
    )


@router.get("/parent/live", response_class=HTMLResponse)
async def parent_live(
    request: Request, k: str = "", principal: Principal = Depends(parent_page)
) -> Response:
    view = await _build(request)
    if k and k == view.state_key:
        return Response(status_code=204)
    return render(request, "_parent_live.html", {"view": view, "principal": principal})


@router.get("/parent/diagnostics", response_class=HTMLResponse)
async def diagnostics(request: Request, principal: Principal = Depends(parent_page)) -> Response:
    ctx = ctx_of(request)
    now = ctx.clock.now()

    def load() -> dict[str, Any]:
        with ctx.db.session() as session:
            fw_events = session.scalars(
                select(FirewallEvent).order_by(FirewallEvent.id.desc()).limit(25)
            ).all()
            audit = session.scalars(
                select(AuditEvent).order_by(AuditEvent.id.desc()).limit(25)
            ).all()
        return {
            "db_ok": ctx.db.check(),
            "revision": current_revision(ctx.db),
            "fw_events": fw_events,
            "audit": audit,
            "dependencies": dependency_report(),
        }

    data = await run_sync(load)
    enforcement = ctx.enforcement
    resolver = ctx.resolver
    context = {
        "principal": principal,
        "csrf_token": principal.csrf_token,
        "version": VERSION,
        "now_local": ctx.calendar.local(now),
        "logical_day": ctx.calendar.logical_day(now),
        "timezone": ctx.config.timezone,
        "firewall_mode": ctx.config.firewall.mode,
        "degraded": enforcement.degraded,
        "last_error": enforcement.last_error,
        "last_contact": ctx.firewall.last_success_at,
        "desired": sorted(enforcement.desired),
        "actual": sorted(enforcement.actual) if enforcement.actual is not None else None,
        "pending_kills": sorted(getattr(enforcement, "_pending_kills", set())),
        "resolver": resolver,
        "hosts": sorted(resolver.hosts.values(), key=lambda h: (h.service, h.host)),
        "unresolved": resolver.unresolved(),
        "stale": resolver.stale(),
        "push_enabled": ctx.notifier.enabled,
        "fmt": ctx.calendar.local,
        **data,
    }
    return render(request, "diagnostics.html", context)
