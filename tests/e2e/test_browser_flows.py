"""Critical flows in a real browser (spec section 4: Playwright for a small set of critical flows)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from playwright.sync_api import Browser, expect
from sqlalchemy import select

from app.models import SessionRecord
from tests.e2e.conftest import PASSWORDS, LiveApp, open_page, sign_in, wait_until

pytestmark = pytest.mark.e2e
IPAD, KIDS_TV = "192.168.12.30", "192.168.12.40"
SLOW = 8000  # ms: the e2e app polls every 2-3 seconds


def sessions(app: LiveApp) -> list[SessionRecord]:
    with app.ctx.db.session() as db:
        return list(db.scalars(select(SessionRecord).order_by(SessionRecord.id)))


def test_child_starts_and_stops_a_session(browser: Browser, live_app: LiveApp) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    expect(page.get_by_text("2h", exact=False).first).to_be_visible()
    expect(
        page.locator('input[name="minutes"][value="30"]')
    ).to_be_checked()  # 30 is the visible default
    expect(page.locator('input[name="device_id"]').first).to_be_checked()

    page.get_by_role("button", name="START SCREEN TIME").click()
    expect(page.locator(".timer")).to_be_visible()
    expect(page.get_by_text("Now using")).to_be_visible()
    expect(page.get_by_text("Ends at 10:30")).to_be_visible()
    assert live_app.firewall.active == {IPAD}
    before = page.locator(".js-countdown").inner_text()
    page.wait_for_timeout(2200)
    assert page.locator(".js-countdown").inner_text() != before  # the countdown is live

    page.get_by_role("button", name="STOP NOW").click()
    expect(page.locator("#start-form")).to_be_visible(timeout=SLOW)
    assert live_app.firewall.active == set()
    assert sessions(live_app)[0].status == "completed"
    ctx.close()


def test_extension_is_offered_in_the_warning_window(browser: Browser, live_app: LiveApp) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    page.get_by_role("button", name="START SCREEN TIME").click()
    expect(page.locator(".timer")).to_be_visible()
    expect(page.get_by_role("button", name="+15 minutes")).to_have_count(0)  # not yet

    live_app.clock.advance(minutes=25)
    page.reload()
    expect(page.get_by_text("Time is nearly up.")).to_be_visible()
    page.get_by_role("button", name="+15 minutes").click()
    expect(page.get_by_text("Ends at 10:45")).to_be_visible(timeout=SLOW)
    assert sessions(live_app)[0].reserved_minutes == 45
    ctx.close()


def test_parent_grant_and_end_today_are_reflected_for_the_child(
    browser: Browser, live_app: LiveApp
) -> None:
    child_ctx, child = open_page(browser)
    parent_ctx, parent = open_page(browser)
    sign_in(child, live_app, "child8")
    sign_in(parent, live_app, "parents")
    child_card = parent.get_by_role("region", name="Child 8")

    child_card.get_by_role("button", name="+15", exact=True).click()
    expect(child_card.get_by_text("2h 15m")).to_be_visible(timeout=SLOW)
    child.reload()
    expect(child.get_by_text("2h 15m")).to_be_visible()

    child.get_by_role("button", name="START SCREEN TIME").click()
    expect(child.locator(".timer")).to_be_visible()
    child_card.get_by_role("button", name="END TODAY").click()  # confirm() is auto-accepted
    expect(child_card.get_by_text("Ended for today")).to_be_visible(timeout=SLOW)
    expect(child_card.get_by_role("button", name="CLEAR DAY LOCK")).to_be_visible()
    assert live_app.firewall.active == set()

    expect(child.get_by_text("Screen time has finished for today.").first).to_be_visible(
        timeout=SLOW
    )
    expect(child.get_by_role("button", name="START SCREEN TIME")).to_be_disabled()

    child_card.get_by_role("button", name="CLEAR DAY LOCK").click()
    expect(child_card.get_by_role("button", name="CLEAR DAY LOCK")).to_have_count(0, timeout=SLOW)
    child_ctx.close()
    parent_ctx.close()


def test_parent_starts_and_stops_a_tv(browser: Browser, live_app: LiveApp) -> None:
    ctx, parent = open_page(browser)
    sign_in(parent, live_app, "parents")
    tv = parent.get_by_role("group", name="Start Kids TV")
    tv.get_by_role("button", name="30", exact=True).click()
    expect(parent.get_by_text("Parent: ends 10:30")).to_be_visible(timeout=SLOW)
    assert live_app.firewall.active == {KIDS_TV}
    parent.get_by_role("button", name="Stop", exact=True).first.click()
    expect(parent.get_by_text("Parent: ends 10:30")).to_have_count(0, timeout=SLOW)
    assert live_app.firewall.active == set()
    ctx.close()


def test_shared_tv_needs_the_siblings_password(browser: Browser, live_app: LiveApp) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    expect(page.locator("#watchers")).to_be_hidden()
    page.locator('input[name="device_id"][value="kids_tv"]').check()
    expect(page.get_by_text("Who is watching?")).to_be_visible()
    expect(
        page.locator("#watchers input[disabled]")
    ).to_be_checked()  # the signed-in child cannot be unticked
    page.locator('input[name="sibling"][value="child12"]').check()
    password = page.locator('input[name="pw_child12"]')
    expect(password).to_be_visible()

    password.fill("not-the-password")
    page.get_by_role("button", name="START SCREEN TIME").click()
    expect(page.locator("#flash")).to_contain_text("password is not right")
    assert sessions(live_app) == []

    password.fill(PASSWORDS["child12"])
    page.get_by_role("button", name="START SCREEN TIME").click()
    expect(page.locator(".timer")).to_be_visible(timeout=SLOW)
    assert {s.child_id for s in sessions(live_app)} == {"child8", "child12"}
    expect(page.get_by_text("Watching: Child 8, Child 12")).to_be_visible()
    ctx.close()


def test_cutoff_message_is_shown_after_1830(browser: Browser, live_app: LiveApp) -> None:
    live_app.clock.advance(hours=8, minutes=35)  # 18:35
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    expect(page.get_by_text("Kids TV ends: 18:30")).to_be_visible()
    expect(page.get_by_text("Kids TV is finished for today (it stops at 18:30).")).to_be_visible()
    expect(page.locator('input[name="device_id"][value="kids_tv"]')).to_be_disabled()
    expect(page.locator('input[name="device_id"][value="lounge_tv"]')).to_be_enabled()
    ctx.close()


def test_offline_state_hides_start_controls(browser: Browser, live_app: LiveApp) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    expect(page.get_by_role("button", name="START SCREEN TIME")).to_be_visible()
    ctx.set_offline(True)
    expect(page.locator("#offline-banner")).to_be_visible(timeout=SLOW)
    expect(page.locator("#offline-banner")).to_contain_text("Screen Time controller unavailable")
    expect(page.get_by_role("button", name="START SCREEN TIME")).to_be_hidden()
    ctx.set_offline(False)
    expect(page.locator("#offline-banner")).to_be_hidden(timeout=SLOW)
    expect(page.get_by_role("button", name="START SCREEN TIME")).to_be_visible()
    ctx.close()


def test_service_worker_caches_static_assets_but_never_session_pages(
    browser: Browser, live_app: LiveApp
) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    page.evaluate("navigator.serviceWorker.ready.then(() => true)")
    page.reload()  # now controlled by the worker
    page.wait_for_function("navigator.serviceWorker.controller !== null")
    cached = page.evaluate(
        """async () => {
            const out = {};
            for (const p of ['/offline', '/static/css/app.css', '/child', '/child/live', '/api/push/public-key']) {
                out[p] = !!(await caches.match(p));
            }
            return out;
        }"""
    )
    assert cached["/offline"] and cached["/static/css/app.css"]
    assert not cached["/child"] and not cached["/child/live"] and not cached["/api/push/public-key"]

    ctx.set_offline(True)
    page.goto(f"{live_app.base_url}/child")
    expect(page.get_by_role("heading", name="Screen Time controller unavailable")).to_be_visible()
    expect(page.get_by_role("button", name="START SCREEN TIME")).to_have_count(
        0
    )  # no stale Start control
    ctx.set_offline(False)
    ctx.close()


@pytest.mark.parametrize("user", ["child8", "parents"])
def test_mobile_layout_has_no_sideways_scroll_and_large_touch_targets(
    browser: Browser, live_app: LiveApp, user: str
) -> None:
    ctx, page = open_page(browser, width=375, height=667)
    sign_in(page, live_app, user)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    heights = page.evaluate(
        """() => [...document.querySelectorAll('button, a.btn')].filter(e => e.offsetParent !== null)
                 .map(e => [e.textContent.trim(), Math.round(e.getBoundingClientRect().height)])"""
    )
    assert heights and all(h >= 44 for _, h in heights), [x for x in heights if x[1] < 44]
    assert (
        page.locator('meta[name="viewport"]')
        .get_attribute("content")
        .startswith("width=device-width")
    )
    assert page.locator('link[rel="manifest"]').count() == 1
    ctx.close()


def test_session_survives_a_page_reload_and_shows_the_right_end_time(
    browser: Browser, live_app: LiveApp
) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child12")
    page.locator('input[name="minutes"][value="60"]').check(force=True)
    page.get_by_role("button", name="START SCREEN TIME").click()
    expect(page.get_by_text("Ends at 11:00")).to_be_visible()
    page.reload()
    expect(page.get_by_text("Ends at 11:00")).to_be_visible()
    live_app.clock.advance(minutes=61)
    page.reload()
    expect(page.locator("#start-form")).to_be_visible(timeout=SLOW)  # it ended on its own
    wait_until(
        lambda: live_app.firewall.active == set()
    )  # the scheduler revokes within a tick or two
    assert (
        timedelta(minutes=59)
        < sessions(live_app)[0].actual_end_at - sessions(live_app)[0].start_at
        <= timedelta(minutes=60)
    )
    ctx.close()


def test_hidden_dashboards_stop_polling_and_refresh_when_shown(
    browser: Browser, live_app: LiveApp
) -> None:
    ctx, page = open_page(browser)
    sign_in(page, live_app, "child8")
    polls: list[str] = []
    page.on("request", lambda r: polls.append(r.url) if "/child/live" in r.url else None)
    page.evaluate(
        "Object.defineProperty(document, 'hidden', {configurable: true, get: () => true});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    page.wait_for_timeout(4000)  # longer than the 3 s idle interval
    assert polls == []
    page.evaluate(
        "Object.defineProperty(document, 'hidden', {configurable: true, get: () => false});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    page.wait_for_timeout(500)
    assert len(polls) >= 1  # refreshed at once, without waiting for the next poll
    ctx.close()
