"""Rules for a new password (plan 7.1). Pure functions: the web routes and the admin CLI share them.

Any characters are allowed, including spaces, and there are no composition rules. Because the
minimum is short (D9), the guessable cases are refused instead: the username, one repeated
character, a straight sequence, and the common-password list.
"""

from __future__ import annotations

from itertools import pairwise

from app.common_passwords import COMMON_PASSWORDS
from app.config import PASSWORD_MAX_LENGTH
from app.passwords import normalise


def _is_straight_sequence(text: str) -> bool:
    """``1234``, ``abcd``, ``4321``: every step is +1, or every step is -1 (three or more characters)."""
    if len(text) < 3:
        return False
    steps = {ord(b) - ord(a) for a, b in pairwise(text)}
    return steps in ({1}, {-1})


def password_problem(password: str, username: str, min_length: int) -> str | None:
    """Why ``password`` may not be used, as a message for the person choosing it, or None."""
    value = normalise(password)
    if len(value) < min_length:
        return f"Use at least {min_length} characters."
    if len(value) > PASSWORD_MAX_LENGTH:
        return f"Use at most {PASSWORD_MAX_LENGTH} characters."
    folded = value.casefold()
    if folded == username.casefold():
        return "The password cannot be the same as the username."
    if len(folded) > 1 and len(set(folded)) == 1:
        return "The password cannot be one character repeated."
    if _is_straight_sequence(folded):
        return "The password cannot be a straight sequence such as 1234 or abcd."
    if folded in COMMON_PASSWORDS:
        return "That password is too common. Choose another."
    return None
