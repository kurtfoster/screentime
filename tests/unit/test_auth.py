"""Password hashing across argon2-cffi versions (21.1 on Raspberry Pi OS, 25.x on PyPI)."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.config import PasswordHashCfg
from app.passwords import PasswordHashing, hash_password, verify_password
from tests.conftest import ARGON_HASH, BASE_CONFIG


def argon2_parameters(stored_hash: str) -> tuple[int, int, int]:
    params = dict(part.split("=") for part in stored_hash.split("$")[3].split(","))
    return int(params["m"]), int(params["t"]), int(params["p"])


ROOT = Path(__file__).resolve().parents[2]


def test_hash_round_trip_and_wrong_password() -> None:
    stored = hash_password("correct horse")
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse")
    assert not verify_password(stored, "battery staple")


def test_malformed_hash_is_a_failed_login_not_a_crash() -> None:
    # argon2-cffi 21.1 raises InvalidHash here; 23+ raises InvalidHashError (the same class).
    assert not verify_password("$argon2id$v=19$m=1,t=1,p=1$bad$bad", "anything")
    assert not verify_password("not-a-hash", "anything")


def test_parameters_are_explicit_and_default_to_the_owasp_minimum() -> None:
    assert argon2_parameters(hash_password("x" * 8)) == (19456, 2, 1)
    custom = PasswordHashing(PasswordHashCfg(memory_kib=32768, time_cost=3, parallelism=2))
    assert argon2_parameters(custom.hash("x" * 8)) == (32768, 3, 2)


@pytest.mark.parametrize(
    "values", [{"memory_kib": 19455}, {"time_cost": 1}, {"parallelism": 0}, {"memory_kib": 4096}]
)
def test_parameters_below_the_owasp_minimum_are_rejected(values: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        PasswordHashCfg(**values)


def test_legacy_hashes_still_verify() -> None:
    # v1.0 hashed with argon2-cffi 25 defaults (m=65536, t=3, p=4); those users can still sign in.
    legacy = PasswordHashing(PasswordHashCfg(memory_kib=65536, time_cost=3, parallelism=4))
    stored = legacy.hash("old password")
    assert PasswordHashing().verify(stored, "old password")


def test_unknown_user_costs_one_verify_against_a_lazy_dummy_hash() -> None:
    hashing = PasswordHashing()
    assert hashing._dummy is None  # nothing is hashed at construction (or import)
    assert hashing.verify(None, "guess") is False
    dummy = hashing._dummy
    assert dummy is not None and argon2_parameters(dummy) == (19456, 2, 1)
    assert hashing.last_verify_seconds is not None and hashing.last_verify_seconds > 0
    assert hashing.verify(None, "guess") is False and hashing._dummy == dummy  # created once


def test_verification_is_serialised_across_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    active, peak = 0, 0
    lock = threading.Lock()

    class SlowHasher:
        def verify(self, stored: str, password: str) -> bool:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return True

    first, second = PasswordHashing(), PasswordHashing()  # the slot is process-wide
    for hashing in (first, second):
        monkeypatch.setattr(hashing, "_hasher", SlowHasher())
    threads = [
        threading.Thread(target=h.verify, args=("stored", "pw")) for h in (first, second) * 3
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1


def test_needs_rehash_follows_the_configured_parameters() -> None:
    hashing = PasswordHashing()
    assert not hashing.needs_rehash(hash_password("pw-123456"))
    assert hashing.needs_rehash(ARGON_HASH)  # v1.0 parameters: m=65536, t=3, p=4
    assert not hashing.needs_rehash("not-a-hash")  # a broken hash is a failed login, not a crash


def test_passwords_are_nfc_normalised() -> None:
    composed, decomposed = "caf\u00e9-pw", "cafe\u0301-pw"  # é typed two different ways
    assert composed != decomposed
    assert verify_password(hash_password(composed), decomposed)
    assert verify_password(hash_password(decomposed), composed)


def test_an_empty_hash_costs_a_dummy_verify_and_never_matches() -> None:
    """An account with no password set looks exactly like an unknown user."""
    hashing = PasswordHashing()
    assert hashing.verify("", "") is False
    assert hashing._dummy is not None


def test_calibrate_reports_each_candidate(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump(BASE_CONFIG))
    env = {k: v for k, v in os.environ.items() if k != "SCREENTIME_CONFIG"}
    run = subprocess.run(
        [sys.executable, "-m", "app", "--config", cfg, "--calibrate-hash"],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=True,
        timeout=120,
    )
    assert "m=19456  t=2 p=1" in run.stdout and "(configured)" in run.stdout
    assert "v1.0 default" in run.stdout
