#!/usr/bin/env python3
"""Installer smoke test: every runtime dependency imports and its native code runs on this CPU.

A package built for the wrong ARM architecture (ARMv7 code on a Raspberry Pi 1's ARMv6) dies
with "Illegal instruction" (exit code 132) the first time its native code runs, not when it
is installed. deploy/install.sh runs this before it touches systemd, so a bad package stops
the install instead of the service. Each step's name is printed before it runs, so the last
line printed names the culprit.

Usage:  /opt/screentime/venv/bin/python /opt/screentime/app/scripts/smoke_test.py
"""

from __future__ import annotations

import base64
import importlib
import sqlite3
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MODULES = [
    "yaml",
    "jinja2",
    "pydantic",
    "pydantic_core",
    "sqlalchemy",
    "sqlalchemy.orm",
    "alembic",
    "argon2",
    "cryptography.hazmat.primitives.asymmetric.ec",
    "py_vapid",
    "http_ece",
    "dns.asyncresolver",
    "python_multipart",
    "starlette",
    "fastapi",
    "uvicorn",
]


def load(module: str) -> None:
    importlib.import_module(module)


def step(name: str, action: Callable[[], str | None]) -> None:
    print(f"  {name} ...", end=" ", flush=True)
    started = time.perf_counter()
    detail = action()
    print(
        f"ok ({time.perf_counter() - started:.2f} s){f'  {detail}' if detail else ''}", flush=True
    )


def check_argon2() -> str:
    from app.passwords import PasswordHashing

    hashing = PasswordHashing()
    stored = hashing.hash("smoke-test-password")
    if not hashing.verify(stored, "smoke-test-password") or hashing.verify(stored, "wrong"):
        raise SystemExit("argon2 verification gave the wrong answer")
    cfg = hashing.cfg
    return (
        f"verify took {hashing.last_verify_seconds:.2f} s at "
        f"m={cfg.memory_kib}, t={cfg.time_cost}, p={cfg.parallelism}"
    )


def check_cryptography() -> None:
    import os

    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    if a.exchange(ec.ECDH(), b.public_key()) != b.exchange(ec.ECDH(), a.public_key()):
        raise SystemExit("ECDH P-256 shared secrets differ")
    key, nonce = AESGCM.generate_key(bit_length=128), os.urandom(12)
    if AESGCM(key).decrypt(nonce, AESGCM(key).encrypt(nonce, b"x", None), None) != b"x":
        raise SystemExit("AES-GCM round trip failed")
    token = Fernet(Fernet.generate_key())
    if token.decrypt(token.encrypt(b"x")) != b"x":
        raise SystemExit("Fernet round trip failed")
    signer = Ed25519PrivateKey.generate()
    signer.public_key().verify(signer.sign(b"x"), b"x")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def check_web_push() -> None:
    import http_ece
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from app.push import WebPushSender

    browser = ec.generate_private_key(ec.SECP256R1())
    public = browser.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    auth = b"0123456789abcdef"
    body = WebPushSender.encrypt(b'{"t":1}', _b64(public), _b64(auth))
    plain = http_ece.decrypt(body, private_key=browser, auth_secret=auth, version="aes128gcm")
    if plain != b'{"t":1}':
        raise SystemExit("Web Push payload round trip failed")


def check_config_parsing() -> str:
    import yaml

    from app.config import load_config

    load_config(ROOT / "config" / "config.example.yaml")  # pydantic-core validation
    return "C YAML loader" if hasattr(yaml, "CSafeLoader") else "pure-Python YAML loader (slower)"


def check_sqlite() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        con = sqlite3.connect(Path(tmp) / "smoke.db")
        mode = con.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('x')")
        con.commit()
        con.close()
    if mode != "wal":
        raise SystemExit(f"SQLite could not enable WAL (got {mode})")
    return f"SQLite {sqlite3.sqlite_version}"


def check_versions() -> str:
    from app.runtime_deps import check_dependencies

    failed = [f"{s.name}: {s.problem}" for s in check_dependencies() if not s.ok]
    if failed:
        raise SystemExit("dependency versions too old: " + "; ".join(failed))
    return "all at or above the pyproject floors"


def main() -> int:
    print(f"Smoke test on Python {sys.version.split()[0]} ({sys.platform})", flush=True)
    for name in MODULES:
        step(f"import {name}", lambda name=name: load(name))  # type: ignore[misc]
    step("argon2id hash and verify", check_argon2)
    step("cryptography: ECDH, AES-GCM, Fernet, Ed25519", check_cryptography)
    step("web push encryption round trip", check_web_push)
    step("configuration parsing", check_config_parsing)
    step("sqlite WAL", check_sqlite)
    step("dependency versions", check_versions)
    step("import the web application", lambda: load("app.main"))
    print("Smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
