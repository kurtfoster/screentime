"""Layout audit for the daily screens (plan 8.1 and 8.3), shared by the mobile tests.

One function per question, each answered in the page itself so Chromium and WebKit are
measured the same way:

* sideways overflow: the document is wider than the viewport;
* small targets: a visible control smaller than 44 x 44 CSS px;
* small text: visible text under 14 px (labels), or body and form text under 16 px (iOS
  zooms into inputs below 16 px);
* above the fold: whether an element's bottom edge is inside the first screen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from playwright.sync_api import Page

MIN_TARGET_PX = 44
MIN_LABEL_PX = 14
MIN_BODY_PX = 16

# Each viewport from plan 8.3, with the Playwright descriptor that supplies a matching iOS
# user agent, touch and pixel ratio. The plan's sizes win where the descriptor differs.
VIEWPORTS: dict[str, tuple[str, int, int]] = {
    "320x568": ("iPhone SE", 320, 568),
    "375x667": ("iPhone SE (3rd gen)", 375, 667),
    "393x852": ("iPhone 15", 393, 852),
    "667x375": ("iPhone SE (3rd gen) landscape", 667, 375),
    "820x1180": ("iPad (gen 7)", 820, 1180),
    "1180x820": ("iPad (gen 7) landscape", 1180, 820),
}

_AUDIT_JS = """
({minTarget, minLabel, minBody}) => {
  const shown = (el) => {
    const s = getComputedStyle(el);
    if (s.display === "none" || s.visibility === "hidden") return false;
    const r = el.getBoundingClientRect();
    // Off-screen on purpose (the skip link until focused) is not shown.
    return r.width > 0 && r.height > 0 && r.right > 0 && r.bottom > -window.scrollY;
  };
  const describe = (el) => {
    const text = (el.innerText || el.value || el.getAttribute("aria-label") || el.name || "").trim();
    return `${el.tagName.toLowerCase()}${el.className ? "." + String(el.className).split(" ")[0] : ""} "${text.slice(0, 30)}"`;
  };
  const doc = document.documentElement;
  const overflow = Math.max(0, doc.scrollWidth - doc.clientWidth);

  const controls = document.querySelectorAll(
    'a[href], button, input:not([type="hidden"]), select, textarea, summary');
  const smallTargets = [];
  for (const el of controls) {
    if (!shown(el)) continue;
    // A visually hidden radio covers its tile: measure the tile the finger actually hits.
    const target = el.matches('input[type="radio"], input[type="checkbox"]') && el.closest("label")
      ? el.closest("label") : el;
    const r = target.getBoundingClientRect();
    if (r.width < minTarget - 0.5 || r.height < minTarget - 0.5)
      smallTargets.push(`${describe(el)} ${Math.round(r.width)}x${Math.round(r.height)}`);
  }

  const smallText = [];
  for (const el of document.body.querySelectorAll("*")) {
    const own = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!own || !shown(el)) continue;
    const size = parseFloat(getComputedStyle(el).fontSize);
    if (size < minLabel - 0.05) smallText.push(`${describe(el)} ${size}px`);
  }
  const body = ["body", "input", "select", "textarea",
                "p:not(.small):not(.label):not(.hint):not(.choice-note)"];
  for (const el of document.querySelectorAll(body.join(","))) {
    if (el !== document.body && !shown(el)) continue;
    const size = parseFloat(getComputedStyle(el).fontSize);
    if (size < minBody - 0.05) smallText.push(`${describe(el)} ${size}px (body text)`);
  }
  return {overflow, smallTargets, smallText, height: doc.scrollHeight, screen: window.innerHeight};
}
"""


@dataclass(frozen=True)
class Audit:
    overflow: int
    small_targets: list[str]
    small_text: list[str]
    height: int
    screen: int

    @property
    def problems(self) -> list[str]:
        found = [f"sideways overflow of {self.overflow}px"] if self.overflow else []
        found += [f"target under {MIN_TARGET_PX}px: {t}" for t in self.small_targets]
        return found + [f"text too small: {t}" for t in self.small_text]


def audit(page: Page) -> Audit:
    raw: dict[str, Any] = page.evaluate(
        _AUDIT_JS, {"minTarget": MIN_TARGET_PX, "minLabel": MIN_LABEL_PX, "minBody": MIN_BODY_PX}
    )
    return Audit(
        overflow=int(raw["overflow"]),
        small_targets=list(raw["smallTargets"]),
        small_text=list(raw["smallText"]),
        height=int(raw["height"]),
        screen=int(raw["screen"]),
    )


def above_the_fold(page: Page, selector: str) -> list[str]:
    """Every element matching ``selector`` that is not wholly inside the first screen."""
    below: list[str] = page.evaluate(
        """(sel) => [...document.querySelectorAll(sel)]
            .filter((el) => el.getBoundingClientRect().height > 0)
            .filter((el) => el.getBoundingClientRect().bottom + window.scrollY > window.innerHeight + 0.5)
            .map((el) => `${(el.innerText || "").trim().slice(0, 30)} bottom=${Math.round(el.getBoundingClientRect().bottom + window.scrollY)}`)""",
        selector,
    )
    if not page.locator(selector).count():
        return [f"{selector}: nothing matched"]
    return below
