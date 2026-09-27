"""Browser fixtures: a real uvicorn server (in a thread) driven by a FakeClock, plus Chromium."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api")

import uvicorn
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

from app.clock import FakeClock
from app.config import UserCfg
from app.context import AppContext, build_context
from app.firewall.dry_run import DryRunFirewallAdapter
from app.main import create_app
from app.passwords import hash_password
from app.timers import Scheduler
from tests.conftest import at, make_config

PASSWORDS = {"child8": "e2e-child8-pw", "child12": "e2e-child12-pw", "parents": "e2e-parents-pw"}


@dataclass
class LiveApp:
    base_url: str
    ctx: AppContext
    clock: FakeClock
    firewall: DryRunFirewallAdapter


# Module scope on purpose: sync Playwright keeps an event loop running while it is open, which
# would break the asyncio.run()-based tests in other modules if it lived for the whole session.
@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as pw:
        try:
            instance = pw.chromium.launch()
        except Exception as exc:  # Chromium not installed / cannot run on this platform
            pytest.skip(
                f"Chromium unavailable ({exc.__class__.__name__}); run `playwright install chromium`"
            )
        yield instance
        instance.close()


@pytest.fixture(scope="session")
def hashes() -> dict[str, str]:
    return {name: hash_password(pw) for name, pw in PASSWORDS.items()}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def live_app(tmp_path: Path, hashes: dict[str, str]) -> Iterator[LiveApp]:
    config = make_config(
        tmp_path,
        notifications={"browser_push_enabled": False, "warning_minutes": 5},
    )
    users = {
        "child8": UserCfg(role="child", child_id="child8", password_hash=hashes["child8"]),
        "child12": UserCfg(role="child", child_id="child12", password_hash=hashes["child12"]),
        "parents": UserCfg(role="parent", password_hash=hashes["parents"]),
    }
    clock = FakeClock(at(10, 0))
    firewall = DryRunFirewallAdapter()
    ctx = build_context(config, users, adapter=firewall, clock=clock, dns=_NoDns())  # type: ignore[arg-type]
    ctx.scheduler = Scheduler(
        ctx.orchestrator,
        ctx.resolver,
        config,
        ctx.maintenance,
        tick_seconds=0.2,
        reconcile_seconds=0.5,
    )
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(ctx, run_background=True), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "server did not start"
    try:
        yield LiveApp(f"http://127.0.0.1:{port}", ctx, clock, firewall)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


class _NoDns:
    async def resolve(self, host: str) -> Any:
        raise RuntimeError("no DNS in browser tests")


def open_page(
    browser: Browser, *, width: int = 390, height: int = 844
) -> tuple[BrowserContext, Page]:
    context = browser.new_context(viewport={"width": width, "height": height})
    page = context.new_page()
    page.on("dialog", lambda dialog: dialog.accept())  # confirm() prompts on destructive buttons
    return context, page


def sign_in(page: Page, app: LiveApp, user: str) -> None:
    page.goto(f"{app.base_url}/login")
    page.fill('input[name="username"]', user)
    page.fill('input[name="password"]', PASSWORDS[user])
    page.click('button[type="submit"]')
    page.wait_for_url(lambda url: not url.endswith("/login"))


def wait_until(check: Any, timeout: float = 5.0) -> None:
    """Poll ``check`` until it is truthy; the background scheduler runs every fraction of a second."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError(f"condition not met within {timeout:.1f}s")
