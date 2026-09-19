"""JSON command API (spec section 16). Every route authorises server-side and checks CSRF."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.auth import Principal
from app.deps import (
    ApiError,
    any_api,
    child_api,
    client_ip,
    ctx_of,
    parent_api,
    rate_limit,
    status_for,
)
from app.models import SessionRecord
from app.notifications import SubscriptionError
from app.policy import Reason
from app.runtime import run_sync
from app.schemas import (
    AddParticipantRequest,
    ExtendRequest,
    GrantRequest,
    PushSubscribeRequest,
    PushUnsubscribeRequest,
    StartRequest,
    TvStartRequest,
)
from app.sessions import CommandResult

router = APIRouter(prefix="/api")


def _session_json(s: SessionRecord) -> dict[str, Any]:
    return {
        "id": s.id,
        "group_id": s.group_id,
        "child_id": s.child_id,
        "device_id": s.device_id,
        "type": s.session_type,
        "status": s.status,
        "start_at": s.start_at.isoformat(),
        "planned_end_at": s.planned_end_at.isoformat() if s.planned_end_at else None,
        "reserved_minutes": s.reserved_minutes,
        "until_stopped": s.until_stopped,
    }


def respond(res: CommandResult) -> JSONResponse:
    if res.ok:
        body: dict[str, Any] = {
            "ok": True,
            "reason": str(res.reason),
            "message": res.message,
            "duplicate": res.duplicate,
            "sessions": [_session_json(s) for s in res.sessions],
        }
        if res.ineligible:
            body["ineligible"] = res.ineligible
        return JSONResponse(body)
    return JSONResponse(
        {
            "ok": False,
            "reason": str(res.reason),
            "message": res.message,
            "ineligible": res.ineligible,
        },
        status_code=status_for(res.reason),
    )


# --- child ---------------------------------------------------------------------------


@router.post("/child/session/start")
async def child_start(
    request: Request, body: StartRequest, principal: Principal = Depends(child_api)
) -> JSONResponse:
    ctx = ctx_of(request)
    assert principal.child_id is not None
    rate_limit(request, principal, "child-start")
    participants: list[str] = []
    for sibling in body.participants:
        if sibling.child_id == principal.child_id or sibling.child_id not in ctx.config.children:
            raise ApiError(422, Reason.NOT_FOUND, "Unknown person.")
        ok = await run_sync(
            ctx.auth.verify_child_credentials,
            sibling.child_id,
            sibling.password,
            client_ip(request),
        )
        if not ok:
            raise ApiError(403, "SIBLING_AUTH_FAILED", "That password is not right.")
        participants.append(sibling.child_id)
    res = await ctx.orchestrator.start_child_session(
        principal.child_id,
        body.device_id,
        body.minutes,
        participants=tuple(participants),
        idempotency_key=body.request_id,
    )
    return respond(res)


@router.post("/child/session/{session_id}/stop")
async def child_stop(
    request: Request, session_id: int, principal: Principal = Depends(child_api)
) -> JSONResponse:
    res = await ctx_of(request).orchestrator.stop_session(
        session_id, actor=principal.username, role="child", child_id=principal.child_id
    )
    return respond(res)


@router.post("/child/session/{session_id}/extend")
async def child_extend(
    request: Request,
    session_id: int,
    body: ExtendRequest | None = None,
    principal: Principal = Depends(child_api),
) -> JSONResponse:
    assert principal.child_id is not None
    mode = body.mode if body else "eligible"
    res = await ctx_of(request).orchestrator.extend_session(
        session_id, principal.child_id, mode=mode
    )
    return respond(res)


@router.post("/child/shared/{session_id}/add-participant")
async def child_add_participant(
    request: Request,
    session_id: int,
    body: AddParticipantRequest,
    principal: Principal = Depends(child_api),
) -> JSONResponse:
    ctx = ctx_of(request)
    assert principal.child_id is not None
    if body.child_id == principal.child_id or body.child_id not in ctx.config.children:
        raise ApiError(422, Reason.NOT_FOUND, "Unknown person.")
    ok = await run_sync(
        ctx.auth.verify_child_credentials, body.child_id, body.password, client_ip(request)
    )
    if not ok:
        raise ApiError(403, "SIBLING_AUTH_FAILED", "That password is not right.")
    res = await ctx.orchestrator.add_participant(session_id, principal.child_id, body.child_id)
    return respond(res)


# --- parent --------------------------------------------------------------------------


def _known_child(request: Request, child_id: str) -> str:
    if child_id not in ctx_of(request).config.children:
        raise ApiError(404, Reason.NOT_FOUND, "Unknown child.")
    return child_id


@router.post("/parent/child/{child_id}/grant")
async def parent_grant(
    request: Request, child_id: str, body: GrantRequest, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    res = await ctx_of(request).orchestrator.parent_grant(
        _known_child(request, child_id),
        body.minutes,
        principal.username,
        idempotency_key=body.request_id,
    )
    return respond(res)


@router.post("/parent/child/{child_id}/end-today")
async def parent_end_today(
    request: Request, child_id: str, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    res = await ctx_of(request).orchestrator.end_today(
        _known_child(request, child_id), principal.username
    )
    return respond(res)


@router.post("/parent/child/{child_id}/clear-day-lock")
async def parent_clear_lock(
    request: Request, child_id: str, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    res = await ctx_of(request).orchestrator.clear_day_lock(
        _known_child(request, child_id), principal.username
    )
    return respond(res)


@router.post("/parent/tv/{device_id}/start")
async def parent_tv_start(
    request: Request,
    device_id: str,
    body: TvStartRequest,
    principal: Principal = Depends(parent_api),
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    if body.until_stopped == (body.minutes is not None):
        raise ApiError(422, Reason.INVALID_DURATION, "Choose either minutes or until stopped.")
    res = await ctx_of(request).orchestrator.start_tv(
        device_id,
        None if body.until_stopped else body.minutes,
        principal.username,
        idempotency_key=body.request_id,
    )
    return respond(res)


@router.post("/parent/session/{session_id}/stop")
async def parent_stop_session(
    request: Request, session_id: int, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    res = await ctx_of(request).orchestrator.stop_session(
        session_id, actor=principal.username, role="parent"
    )
    return respond(res)


@router.post("/parent/override/{override_id}/revoke")
async def parent_revoke_override(
    request: Request, override_id: int, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    rate_limit(request, principal, "parent-action")
    res = await ctx_of(request).orchestrator.revoke_override(override_id, principal.username)
    return respond(res)


@router.post("/parent/lockouts/{username}/reset")
async def parent_reset_lockout(
    request: Request, username: str, principal: Principal = Depends(parent_api)
) -> JSONResponse:
    ctx = ctx_of(request)
    child = ctx.config.child_id_for_username(username)
    if child is None:
        raise ApiError(404, Reason.NOT_FOUND, "Unknown child login.")
    reset = await run_sync(ctx.auth.reset_lockout, username, principal.username)
    return JSONResponse({"ok": True, "reset": reset, "reason": "OK", "message": "Login unlocked."})


# --- push (any signed-in user) ---------------------------------------------------------


@router.get("/push/public-key")
async def push_public_key(
    request: Request, principal: Principal = Depends(any_api)
) -> JSONResponse:
    notifier = ctx_of(request).notifier
    return JSONResponse({"enabled": notifier.enabled, "public_key": notifier.public_key})


@router.post("/push/subscribe")
async def push_subscribe(
    request: Request, body: PushSubscribeRequest, principal: Principal = Depends(any_api)
) -> JSONResponse:
    notifier = ctx_of(request).notifier
    if not notifier.enabled:
        raise ApiError(409, "PUSH_DISABLED", "Notifications are not enabled on this controller.")
    try:
        await run_sync(
            notifier.subscribe, principal.username, principal.role, body.endpoint, body.keys
        )
    except SubscriptionError as exc:
        raise ApiError(422, "INVALID_SUBSCRIPTION", str(exc)) from exc
    return JSONResponse({"ok": True, "reason": "OK", "message": "Alerts are on."})


@router.post("/push/unsubscribe")
async def push_unsubscribe(
    request: Request, body: PushUnsubscribeRequest, principal: Principal = Depends(any_api)
) -> JSONResponse:
    await run_sync(ctx_of(request).notifier.unsubscribe, principal.username, body.endpoint)
    return JSONResponse({"ok": True, "reason": "OK", "message": "Alerts are off."})
