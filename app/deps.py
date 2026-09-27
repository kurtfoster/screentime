"""Request helpers: context access, client address, principals and CSRF."""

from __future__ import annotations

import hmac
import ipaddress
from typing import Any

from fastapi import Request
from fastapi.responses import Response

from app.auth import COOKIE_NAME, Principal
from app.context import AppContext
from app.policy import Reason


class ApiError(Exception):
    """A request that must be answered with a specific status and machine-readable reason."""

    def __init__(self, status: int, reason: Reason | str, message: str, **extra: Any) -> None:
        self.status = status
        self.reason = str(reason)
        self.message = message
        self.extra = extra
        super().__init__(message)


class LoginRequired(Exception):
    """An HTML page was requested without a valid session."""


_STATUS_FOR_REASON: dict[Reason, int] = {
    Reason.NOT_FOUND: 404,
    Reason.FORBIDDEN: 403,
    Reason.INVALID_DURATION: 422,
    Reason.UNKNOWN_DEVICE: 404,
    Reason.ENFORCEMENT_DEGRADED: 503,
    Reason.ENFORCEMENT_FAILED: 503,
    Reason.CLOCK_NOT_SYNCED: 503,
}


def status_for(reason: Reason) -> int:
    return _STATUS_FOR_REASON.get(reason, 409)


def ctx_of(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def client_ip(request: Request) -> str:
    """Peer address, or X-Real-IP when (and only when) the peer is a trusted proxy."""
    ctx = ctx_of(request)
    peer = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    if peer in ctx.config.security.trusted_proxies:
        forwarded = request.headers.get("x-real-ip", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            return peer
    return peer


def is_local_client(request: Request) -> bool:
    try:
        address = ipaddress.ip_address(client_ip(request))
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def principal_or_none(request: Request) -> Principal | None:
    if getattr(request.state, "principal_resolved", False):
        cached: Principal | None = request.state.principal
        return cached
    principal = ctx_of(request).auth.resolve(request.cookies.get(COOKIE_NAME))
    request.state.principal = principal
    request.state.principal_resolved = True
    return principal


def csrf_ok(principal: Principal, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(supplied or "", principal.csrf_token)


def _api_principal(request: Request, role: str) -> Principal:
    principal = principal_or_none(request)
    if principal is None:
        raise ApiError(401, "UNAUTHENTICATED", "Please sign in again.")
    if principal.role != role:
        raise ApiError(403, Reason.FORBIDDEN, "You are not allowed to do that.")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not csrf_ok(
        principal, request.headers.get("x-csrf-token")
    ):
        raise ApiError(403, "CSRF", "Security check failed. Reload the page and try again.")
    return principal


def child_api(request: Request) -> Principal:
    principal = _api_principal(request, "child")
    assert principal.child_id is not None
    return principal


def parent_api(request: Request) -> Principal:
    return _api_principal(request, "parent")


def any_api(request: Request) -> Principal:
    principal = principal_or_none(request)
    if principal is None:
        raise ApiError(401, "UNAUTHENTICATED", "Please sign in again.")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not csrf_ok(
        principal, request.headers.get("x-csrf-token")
    ):
        raise ApiError(403, "CSRF", "Security check failed. Reload the page and try again.")
    return principal


def page_principal(request: Request, role: str) -> Principal:
    principal = principal_or_none(request)
    if principal is None:
        raise LoginRequired
    if principal.role != role:
        raise ApiError(403, Reason.FORBIDDEN, "This page is not available to you.")
    return principal


def child_page(request: Request) -> Principal:
    return page_principal(request, "child")


def parent_page(request: Request) -> Principal:
    return page_principal(request, "parent")


def rate_limit(request: Request, principal: Principal, bucket: str) -> None:
    if not ctx_of(request).action_limiter.allow(f"{bucket}:{principal.username}"):
        raise ApiError(429, "RATE_LIMITED", "Too many requests. Wait a moment and try again.")


def render(
    request: Request, template: str, context: dict[str, Any], status_code: int = 200
) -> Response:
    response: Response = request.app.state.templates.TemplateResponse(
        request, template, context, status_code=status_code
    )
    return response
