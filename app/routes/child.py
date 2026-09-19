"""Child dashboard page and its live fragment."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.auth import Principal
from app.deps import child_page, ctx_of, render
from app.runtime import run_sync
from app.views import ChildView

router = APIRouter()


async def _build(request: Request, principal: Principal) -> ChildView:
    ctx = ctx_of(request)
    assert principal.child_id is not None
    child_id = principal.child_id

    def build() -> ChildView:
        with ctx.db.session() as session:
            return ctx.views.child_view(
                session, child_id, ctx.clock.now(), degraded=ctx.enforcement.degraded
            )

    return await run_sync(build)


@router.get("/child", response_class=HTMLResponse)
async def child_dashboard(request: Request, principal: Principal = Depends(child_page)) -> Response:
    view = await _build(request, principal)
    return render(
        request,
        "child.html",
        {"view": view, "principal": principal, "csrf_token": principal.csrf_token},
    )


@router.get("/child/live", response_class=HTMLResponse)
async def child_live(
    request: Request, k: str = "", principal: Principal = Depends(child_page)
) -> Response:
    view = await _build(request, principal)
    if k and k == view.state_key:
        return Response(
            status_code=204
        )  # unchanged: htmx leaves the DOM (and any form input) alone
    return render(request, "_child_live.html", {"view": view, "principal": principal})
