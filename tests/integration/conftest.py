"""Integration fixtures: a real FastAPI app over a temp SQLite DB, FakeClock and dry-run firewall."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.clock import FakeClock
from app.config import UserCfg
from app.context import AppContext, build_context
from app.firewall.dry_run import DryRunFirewallAdapter
from app.firewall.resolver import DnsAnswer, DnsFailure
from app.main import create_app
from tests.conftest import at, make_config

PASSWORDS = {"child8": "pw-child8-x", "child12": "pw-child12-x", "parents": "pw-parents-x"}
IPAD, IPHONE, KIDS_TV, LOUNGE_TV = (
    "192.168.12.30",
    "192.168.12.31",
    "192.168.12.40",
    "192.168.12.41",
)


@pytest.fixture(scope="session")
def user_hashes() -> dict[str, str]:
    return {name: hash_password(pw) for name, pw in PASSWORDS.items()}


class FakeDns:
    """Scriptable DNS: host -> DnsAnswer or an exception to raise."""

    def __init__(self) -> None:
        self.answers: dict[str, DnsAnswer | Exception] = {}

    async def resolve(self, host: str) -> DnsAnswer:
        result = self.answers.get(host, DnsFailure("NXDOMAIN"))
        if isinstance(result, Exception):
            raise result
        return result


class FakePush:
    def __init__(self) -> None:
        self.sent: list[tuple[dict[str, Any], dict[str, str]]] = []
        self.raise_with: Exception | None = None

    def send(self, subscription_info: dict[str, Any], payload: dict[str, str]) -> None:
        if self.raise_with:
            raise self.raise_with
        self.sent.append((subscription_info, payload))


@dataclass
class AppEnv:
    ctx: AppContext
    client: TestClient
    clock: FakeClock
    firewall: DryRunFirewallAdapter
    dns: FakeDns
    push: FakePush
    tmp_path: Path

    def call(self, coro_fn: Any, *args: Any) -> Any:
        """Run an async callable on the app's own event loop."""
        return self.client.portal.call(coro_fn, *args)  # type: ignore[union-attr]

    def tick(self) -> Any:
        return self.call(self.ctx.orchestrator.tick)

    def reconcile(self) -> Any:
        return self.call(self.ctx.enforcement.reconcile)

    def set(self, hour: int, minute: int = 0, **kw: Any) -> None:
        self.clock.set(at(hour, minute, **kw))

    def new_client(self) -> TestClient:
        return TestClient(self.client.app, client=("127.0.0.1", 50000))  # type: ignore[arg-type]


class Session:
    """A logged-in browser session: cookie jar plus the CSRF token for API calls."""

    def __init__(self, client: TestClient, username: str, password: str | None = None) -> None:
        self.client = client
        self.username = username
        page = client.get("/login")
        token = re.search(r'name="login_token" value="([^"]+)"', page.text)
        assert token, page.text
        resp = client.post(
            "/login",
            data={
                "username": username,
                "password": password or PASSWORDS[username],
                "login_token": token.group(1),
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303, resp.text
        landing = client.get(resp.headers["location"])
        match = re.search(r'name="csrf-token" content="([^"]+)"', landing.text)
        assert match
        self.csrf = match.group(1)

    def post(self, url: str, json: dict[str, Any] | None = None, *, csrf: bool = True) -> Any:
        headers = {"X-CSRF-Token": self.csrf} if csrf else {}
        return self.client.post(url, json=json if json is not None else {}, headers=headers)

    def get(self, url: str) -> Any:
        return self.client.get(url)


@contextmanager
def open_env(
    tmp_path: Path,
    hashes: dict[str, str],
    *,
    start_hour: int = 10,
    start_minute: int = 0,
    **overrides: Any,
) -> Iterator[AppEnv]:
    overrides.setdefault("notifications", {"browser_push_enabled": True, "warning_minutes": 5})
    config = make_config(tmp_path, **overrides)
    users = {
        "child8": UserCfg(role="child", child_id="child8", password_hash=hashes["child8"]),
        "child12": UserCfg(role="child", child_id="child12", password_hash=hashes["child12"]),
        "parents": UserCfg(role="parent", password_hash=hashes["parents"]),
    }
    clock = FakeClock(at(start_hour, start_minute))
    firewall = DryRunFirewallAdapter()
    dns, push = FakeDns(), FakePush()
    ctx = build_context(config, users, adapter=firewall, clock=clock, dns=dns, push_sender=push)  # type: ignore[arg-type]
    app = create_app(ctx, run_background=False)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield AppEnv(ctx, client, clock, firewall, dns, push, tmp_path)


@pytest.fixture
def env_factory(tmp_path: Path, user_hashes: dict[str, str]) -> Iterator[Callable[..., AppEnv]]:
    """Build extra app environments with custom config/clock; all are closed at test end."""
    stack = ExitStack()

    def make(**kwargs: Any) -> AppEnv:
        return stack.enter_context(open_env(tmp_path, user_hashes, **kwargs))

    yield make
    stack.close()


@pytest.fixture
def app_env(env_factory: Callable[..., AppEnv]) -> AppEnv:
    return env_factory()


@pytest.fixture
def child8(app_env: AppEnv) -> Session:
    return Session(app_env.new_client(), "child8")


@pytest.fixture
def child12(app_env: AppEnv) -> Session:
    return Session(app_env.new_client(), "child12")


@pytest.fixture
def parent(app_env: AppEnv) -> Session:
    return Session(app_env.new_client(), "parents")
