"""Password hashing across argon2-cffi versions (21.1 on Raspberry Pi OS, 25.x on PyPI)."""

from __future__ import annotations

from app.auth import hash_password, verify_password


def test_hash_round_trip_and_wrong_password() -> None:
    stored = hash_password("correct horse")
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse")
    assert not verify_password(stored, "battery staple")


def test_malformed_hash_is_a_failed_login_not_a_crash() -> None:
    # argon2-cffi 21.1 raises InvalidHash here; 23+ raises InvalidHashError (the same class).
    assert not verify_password("$argon2id$v=19$m=1,t=1,p=1$bad$bad", "anything")
    assert not verify_password("not-a-hash", "anything")
