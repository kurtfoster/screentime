"""pfSense's two requests (plan 6.3, 6.5): fetch the desired state, acknowledge what it applied.

Neither uses a browser session, so neither is subject to the session or CSRF checks; they
are on the explicit allowlist that a test guards. Instead each request must come from
``firewall.host`` (nginx enforces the same address) and carry the bearer token, whose
SHA-256 is compared in constant time. The token is never logged.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response

from app.deps import client_ip, ctx_of
from app.firewall import token
from app.firewall.protocol import MAX_DOCUMENT_BYTES, ProtocolError, parse_applied
from app.firewall.pull import PullFirewallAdapter
from app.runtime import run_sync

router = APIRouter(prefix="/firewall/v1")
log = logging.getLogger("screentime.firewall")

# Paths reachable without a browser session or CSRF token: guarded by a test.
SESSIONLESS_PATHS = frozenset({"/firewall/v1/desired", "/firewall/v1/applied"})

_NO_STORE = {"Cache-Control": "no-store"}
_TEXT = "text/plain; charset=us-ascii"


class _Rejected(Exception):
    def __init__(self, status: int, why: str) -> None:
        self.status = status
        self.why = why


def _authorise(request: Request) -> PullFirewallAdapter:
    ctx = ctx_of(request)
    if ctx.pull is None:
        raise _Rejected(404, "firewall.mode is not pfsense_pull")
    source = client_ip(request)
    if source != ctx.config.firewall.host:
        raise _Rejected(403, f"source {source} is not firewall.host")
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme != "Bearer" or not token.check(ctx.config.storage.data_dir, presented.strip()):
        raise _Rejected(401, "missing or wrong bearer token")
    return ctx.pull


def _reject(request: Request, exc: _Rejected) -> Response:
    # The reason and the source only: never the Authorization header or the body.
    log.warning(
        "firewall request rejected path=%s status=%d ip=%s reason=%s",
        request.url.path,
        exc.status,
        client_ip(request),
        exc.why,
    )
    return PlainTextResponse("refused\n", status_code=exc.status, headers=_NO_STORE)


@router.get("/desired", include_in_schema=False)
async def desired(request: Request) -> Response:
    ctx = ctx_of(request)
    try:
        pull = _authorise(request)
    except _Rejected as exc:
        return _reject(request, exc)
    now = ctx.clock.now()
    pull.note_fetch(now)
    if not ctx.enforcement.clock_synchronised():
        # A controller that cannot tell the time is a broken one (plan 5.5): pfSense keeps
        # its leases, times them itself, and fails open after its grace period.
        return PlainTextResponse("clock not synchronised\n", status_code=503, headers=_NO_STORE)
    await ctx.enforcement.publish()
    return Response(pull.document(), media_type=_TEXT, headers=_NO_STORE)


@router.post("/applied", include_in_schema=False)
async def applied(request: Request) -> Response:
    ctx = ctx_of(request)
    try:
        pull = _authorise(request)
    except _Rejected as exc:
        return _reject(request, exc)
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_DOCUMENT_BYTES:
            return _reject(request, _Rejected(413, "acknowledgement too large"))
    try:
        ack = parse_applied(body)
    except ProtocolError as exc:
        return _reject(request, _Rejected(400, f"malformed acknowledgement: {exc}"))
    now = ctx.clock.now()
    state = await run_sync(pull.record_ack, ack, now)
    ctx.enforcement.record_applied(state, now)
    if ctx.alerts is not None:
        await run_sync(ctx.alerts.record_failopen, ack, now)
    return Response(status_code=204, headers=_NO_STORE)
