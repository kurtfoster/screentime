"""Login, logout and the role-aware root redirect."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.auth import COOKIE_NAME
from app.deps import client_ip, csrf_ok, ctx_of, principal_or_none, render
from app.runtime import run_sync

router = APIRouter()


def _login_page(request: Request, message: str = "", status: int = 200) -> Response:
    ctx = ctx_of(request)
    return render(
        request,
        "login.html",
        {"message": message, "login_token": ctx.auth.new_login_token(), "principal": None},
        status_code=status,
    )


@router.get("/", include_in_schema=False)
async def root(request: Request) -> Response:
    principal = principal_or_none(request)
    if principal is None:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/parent" if principal.is_parent else "/child", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> Response:
    if principal_or_none(request) is not None:
        return RedirectResponse("/", status_code=303)
    return _login_page(request)


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(max_length=64),
    password: str = Form(max_length=256),
    login_token: str = Form(max_length=200),
) -> Response:
    ctx = ctx_of(request)
    if not ctx.auth.check_login_token(login_token):
        return _login_page(request, "That page expired. Please try again.", 400)
    result = await run_sync(ctx.auth.login, username, password, client_ip(request))
    if not result.ok or result.cookie is None or result.principal is None:
        return _login_page(request, result.message, 429 if result.locked_until else 401)
    response = RedirectResponse(
        "/parent" if result.principal.is_parent else "/child", status_code=303
    )
    response.set_cookie(
        COOKIE_NAME,
        result.cookie,
        max_age=ctx.config.security.session_ttl_minutes * 60,
        httponly=True,
        samesite="lax",
        secure=ctx.config.security.secure_cookies,
        path="/",
    )
    return response


@router.post("/logout")
async def logout(request: Request, csrf_token: str = Form(default="", max_length=100)) -> Response:
    ctx = ctx_of(request)
    principal = principal_or_none(request)
    if principal is not None and csrf_ok(principal, csrf_token):
        await run_sync(ctx.auth.logout, request.cookies.get(COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
