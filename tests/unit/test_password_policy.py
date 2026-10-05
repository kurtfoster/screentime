"""New-password rules (plan 7.1, D9): short is allowed, guessable is not."""

from __future__ import annotations

import pytest

from app.common_passwords import COMMON_PASSWORDS
from app.password_policy import password_problem


@pytest.mark.parametrize(
    "password",
    ["7392", "blue whale", "Rosé 4ever", "kj!3", "  sp aces  ", "xy" * 64, "日本語の"],
)
def test_short_but_unguessable_passwords_are_accepted(password: str) -> None:
    assert password_problem(password, "child8", 4) is None


@pytest.mark.parametrize(
    ("password", "needle"),
    [
        ("abc", "at least 4"),
        ("x" * 129, "at most 128"),
        ("child8", "same as the username"),
        ("CHILD8", "same as the username"),
        ("1111", "one character repeated"),
        ("aaaaaa", "one character repeated"),
        ("1234", "straight sequence"),
        ("abcd", "straight sequence"),
        ("4321", "straight sequence"),
        ("DCBA", "straight sequence"),
        ("2013", "too common"),  # a year: the first guess for a birthday
        ("password", "too common"),
        ("Qwerty", "too common"),
        ("2580", "too common"),  # straight down the middle of a keypad
    ],
)
def test_guessable_passwords_are_refused(password: str, needle: str) -> None:
    problem = password_problem(password, "child8", 4)
    assert problem is not None and needle in problem


def test_the_minimum_follows_configuration() -> None:
    assert password_problem("k9!x", "kurt", 4) is None
    assert "at least 12" in (password_problem("k9!x", "kurt", 12) or "")
    assert password_problem("q", "kurt", 1) is None  # one character is not "repeated"


def test_composed_and_decomposed_forms_count_the_same() -> None:
    # "é" decomposed is two code points; NFC makes it one, so "café" is 4 characters either way.
    assert password_problem("café", "kurt", 4) is None
    assert password_problem("café", "kurt", 5) is not None


def test_the_blocklist_is_about_two_hundred_short_entries() -> None:
    assert 150 <= len(COMMON_PASSWORDS) <= 300
    assert all(entry == entry.casefold() and len(entry) <= 12 for entry in COMMON_PASSWORDS)
    assert {"1950", "1999", "2030", "0000", "letmein"} <= COMMON_PASSWORDS
