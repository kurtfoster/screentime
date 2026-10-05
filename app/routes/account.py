"""Password changes (plan 7.1, D7, D8): your own, a child's, and the other parent's.

Every change needs a password from the person making it: the current one for your own, and
a parent's own password before they set someone else's (ASVS V2 re-authentication). Wrong
passwords count toward the lockout exactly as failed sign-ins do. After a change the user is
signed out everywhere; changing your own password gives this device a fresh session.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from app.accounts import Account, AccountError
from app.audit import record_audit
from app.auth import COOKIE_NAME, Principal
from app.deps import (
    ApiError,
    LoginRequired,
    client_ip,
    csrf_ok,
    ctx_of,
    parent_api,
    parent_page,
    principal_or_none,
    rate_limit,
    render,
)
from app.models import TYPE_CHILD
from app.policy import Reason
from app.runtime import run_sync
from app.schemas import SetPasswordRequest

router = APIRouter()

_FIELD = 256  # form fields are bounded before any hashing; the policy allows 128 characters


def _any_page(request: Request) -> Principal:
    principal = principal_or_none(request)
    if principal is None:
        raise LoginRequired
    return principal


def _password_page(
    request: Request,
    principal: Principal,
    *,
    message: str = "",
    done: bool = False,
    status: int = 200,
) -> Response:
    ctx = ctx_of(request)
    return render(
        request,
        "account_password.html",
        {
            "principal": principal,
            "csrf_token": principal.csrf_token,
            "message": message,
            "done": done,
            "min_length": ctx.config.security.password_min_length,
        },
        status,
    )


def _audit_denied(request: Request, actor: str, subject: str, why: str) -> None:
    ctx = ctx_of(request)
    with ctx.db.session(write=True) as session:
        record_audit(session, ctx.clock.now(), actor, "password_change", subject, "denied", why=why)


@router.get("/account/password", response_class=HTMLResponse)
async def change_password_form(
    request: Request, done: int = 0, principal: Principal = Depends(_any_page)
) -> Response:
    return _password_page(request, principal, done=bool(done))


@router.post("/account/password")
async def change_password(
    request: Request,
    current_password: str = Form(max_length=_FIELD),
    new_password: str = Form(max_length=_FIELD),
    confirm_password: str = Form(max_length=_FIELD),
    csrf_token: str = Form(default="", max_length=100),
    principal: Principal = Depends(_any_page),
) -> Response:
    ctx = ctx_of(request)
    if not csrf_ok(principal, csrf_token):
        return _password_page(
            request, principal, message="Security check failed. Try again.", status=403
        )
    ip = client_ip(request)
    if not await run_sync(ctx.auth.verify_password, principal.username, current_password, ip):
        await run_sync(
            _audit_denied, request, principal.username, principal.username, "wrong current password"
        )
        locked = await run_sync(ctx.auth.lockout_for, principal.username, ip) is not None
        message = (
            "Too many wrong passwords. Wait, or ask a parent to unlock you."
            if locked
            else "Your current password is not right."
        )
        return _password_page(request, principal, message=message, status=429 if locked else 403)
    if new_password != confirm_password:
        return _password_page(
            request, principal, message="The two new passwords do not match.", status=422
        )
    try:
        account = await run_sync(
            ctx.accounts.set_password, principal.username, new_password, principal.username
        )
    except AccountError as exc:
        return _password_page(request, principal, message=str(exc), status=422)
    # Every session was revoked, this one included: give this device a fresh one (rotation).
    cookie, _ = await run_sync(ctx.auth.issue_session, account, ip, event="session_rotated")
    response = RedirectResponse("/account/password?done=1", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        cookie,
        max_age=ctx.config.security.session_ttl_minutes * 60,
        httponly=True,
        samesite="lax",
        secure=ctx.config.security.secure_cookies,
        path="/",
    )
    return response


# --- parents setting other people's passwords ------------------------------------------------


def _settable(request: Request, principal: Principal, username: str) -> Account:
    """A configured child, or another parent. Your own password goes through /account/password."""
    ctx = ctx_of(request)
    account = ctx.accounts.get(username)
    if account is None or not account.enabled:
        raise ApiError(404, Reason.NOT_FOUND, "Unknown login.")
    if account.username == principal.username:
        raise ApiError(
            422, "USE_CHANGE_PASSWORD", "To change your own password, use Change password."
        )
    if account.role == TYPE_CHILD and account.child_id not in ctx.config.children:
        raise ApiError(404, Reason.NOT_FOUND, "Unknown login.")
    return account


@router.get("/parent/user/{username}/password", response_class=HTMLResponse)
async def set_password_form(
    request: Request, username: str, principal: Principal = Depends(parent_page)
) -> Response:
    account = await run_sync(_settable, request, principal, username)
    return render(
        request,
        "set_password.html",
        {
            "principal": principal,
            "csrf_token": principal.csrf_token,
            "account": account,
            "min_length": ctx_of(request).config.security.password_min_length,
        },
    )


@router.post("/api/parent/user/{username}/password")
async def set_password(
    request: Request,
    username: str,
    body: SetPasswordRequest,
    principal: Principal = Depends(parent_api),
) -> JSONResponse:
    ctx = ctx_of(request)
    rate_limit(request, principal, "parent-action")
    account = await run_sync(_settable, request, principal, username)
    ip = client_ip(request)
    if not await run_sync(ctx.auth.verify_password, principal.username, body.parent_password, ip):
        await run_sync(
            _audit_denied, request, principal.username, username, "re-authentication failed"
        )
        if await run_sync(ctx.auth.lockout_for, principal.username, ip) is not None:
            raise ApiError(
                429, "LOCKED", "Too many wrong passwords from this device. Wait a while."
            )
        raise ApiError(403, "REAUTH_FAILED", "Your own password is not right.")
    if body.new_password != body.confirm_password:
        raise ApiError(422, "PASSWORD_MISMATCH", "The two new passwords do not match.")
    try:
        await run_sync(ctx.accounts.set_password, username, body.new_password, principal.username)
    except AccountError as exc:
        raise ApiError(422, "PASSWORD_REJECTED", str(exc)) from exc
    return JSONResponse(
        {
            "ok": True,
            "reason": "OK",
            "message": f"Password set for {account.display_name}. They have been signed out.",
        }
    )


@router.get("/account/parents", response_class=HTMLResponse)
async def parents_list(request: Request, principal: Principal = Depends(parent_page)) -> Response:
    ctx = ctx_of(request)
    parents = await run_sync(ctx.accounts.parents)
    return render(
        request,
        "parents.html",
        {
            "principal": principal,
            "csrf_token": principal.csrf_token,
            "parents": parents,
            "fmt": ctx.calendar.format_local,
        },
    )
