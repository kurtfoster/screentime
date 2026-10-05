"""Mobile acceptance criteria for the daily screens (plan 8.3), on Chromium and WebKit.

Every daily page, at every viewport: no sideways scrolling, every control at least 44 x 44
CSS px, labels at least 14 px and body text at least 16 px. Then the "without scrolling"
criteria for the parent page on an iPad and an iPhone SE, and the child page on an iPhone SE.

The heights are the plan's screen sizes. In Safari with its toolbars showing, less is visible;
as a Home Screen app the whole screen is. The manual check at Gate C covers real devices.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.conftest import Engine, LiveApp, open_device, sign_in
from tests.e2e.viewport_audit import VIEWPORTS, above_the_fold, audit

pytestmark = pytest.mark.e2e


def _start_child_session(app: LiveApp) -> None:
    assert app.ctx.sessions.start_child_session("child8", "ipad", 30).ok


def _start_tv(app: LiveApp) -> None:
    assert app.ctx.sessions.start_tv("lounge_tv", 30, "parents").ok


def _in_warning_window(app: LiveApp) -> None:
    _start_child_session(app)
    app.clock.advance(minutes=26)  # 4 minutes left: the +15 extension is offered


# page name -> (user or None, setup, path)
PAGES: dict[str, tuple[str | None, Callable[[LiveApp], None] | None, str]] = {
    "login": (None, None, "/login"),
    "child-idle": ("child8", None, "/child"),
    "child-active": ("child8", _start_child_session, "/child"),
    "child-extension": ("child8", _in_warning_window, "/child"),
    "parent-idle": ("parents", None, "/parent"),
    "parent-active": (
        "parents",
        lambda app: (_start_child_session(app), _start_tv(app)),
        "/parent",
    ),
    "change-password": ("child8", None, "/account/password"),
}


def open_as(engine: Engine, app: LiveApp, viewport: str, page_name: str) -> Page:
    descriptor, width, height = VIEWPORTS[viewport]
    user, setup, path = PAGES[page_name]
    if setup:
        setup(app)
    _, page = open_device(engine, descriptor, width, height)
    if user:
        sign_in(page, app, user)
    page.goto(f"{app.base_url}{path}")
    page.wait_for_load_state("networkidle")
    return page


@pytest.mark.parametrize("viewport", list(VIEWPORTS))
@pytest.mark.parametrize("page_name", list(PAGES))
def test_daily_pages_fit_every_viewport(
    engine: Engine, live_app: LiveApp, viewport: str, page_name: str
) -> None:
    page = open_as(engine, live_app, viewport, page_name)
    result = audit(page)
    assert result.problems == [], f"{engine.name} {viewport} {page_name}: {result.problems}"
    page.context.close()


def test_parent_on_ipad_portrait_sees_everything_without_scrolling(
    engine: Engine, live_app: LiveApp
) -> None:
    page = open_as(engine, live_app, "820x1180", "parent-active")
    for selector in ("#now-heading", ".dash-now", ".grants button", ".tv-buttons button"):
        assert above_the_fold(page, selector) == [], selector
    page.context.close()


def test_parent_on_iphone_se_sees_right_now_and_the_first_grants(
    engine: Engine, live_app: LiveApp
) -> None:
    page = open_as(engine, live_app, "375x667", "parent-active")
    assert above_the_fold(page, ".dash-now") == []
    assert above_the_fold(page, ".child-card:first-child .grants button") == []
    result = audit(page)
    # Two children and active sessions: the whole page is at most two screens.
    assert result.height <= 2 * result.screen, (result.height, result.screen)
    page.context.close()


def test_child_on_iphone_se_can_start_without_scrolling(engine: Engine, live_app: LiveApp) -> None:
    page = open_as(engine, live_app, "375x667", "child-idle")
    for selector in (
        ".hero .big",
        ".choices.devices .choice",
        ".choices.durations",
        "#start-form button[type=submit]",
    ):
        assert above_the_fold(page, selector) == [], selector
    page.context.close()


def test_child_on_iphone_se_sees_the_countdown_and_stop(engine: Engine, live_app: LiveApp) -> None:
    page = open_as(engine, live_app, "375x667", "child-active")
    expect(page.get_by_role("button", name="STOP NOW")).to_be_visible()
    for selector in (".timer", "button.btn-danger.btn-large"):
        assert above_the_fold(page, selector) == [], selector
    page.context.close()


def test_header_fits_and_the_account_menu_opens_at_320(engine: Engine, live_app: LiveApp) -> None:
    page = open_as(engine, live_app, "320x568", "parent-idle")
    header = page.locator(".topbar")
    assert header.bounding_box()["height"] < 80  # type: ignore[index]  # one line, no wrapping
    page.get_by_text("Account", exact=True).click()
    for item in ("Change password", "Parents", "Diagnostics", "Sign out"):
        expect(page.locator(".menu-panel").get_by_text(item, exact=True)).to_be_visible()
    assert audit(page).problems == []
    page.context.close()


def test_confirmation_is_a_toast_at_the_bottom(engine: Engine, live_app: LiveApp) -> None:
    page = open_as(engine, live_app, "375x667", "child-idle")
    page.get_by_role("button", name="START SCREEN TIME").click()
    toast = page.locator("#flash .toast")
    expect(toast).to_be_visible()
    box = toast.bounding_box()
    assert box is not None and box["y"] > 667 / 2  # bottom half, not over the page top
    expect(toast).to_be_hidden(timeout=6000)  # confirmations go after 4 s
    page.context.close()
