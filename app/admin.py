"""Administration from the shell when the web UI is unavailable (spec section 25).

Everything goes through the same services as the web application, so policy, audit and
firewall reconciliation behave identically. Run as the ``screentime`` user, e.g.

    sudo -u screentime /opt/screentime/venv/bin/python scripts/admin_cli.py status
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.config import ConfigError, config_paths_from_env, load_all
from app.context import AppContext, build_context
from app.models import SESSION_ACTIVE, AuditEvent, DayLock, ParentOverride, SessionRecord
from app.policy import format_duration
from app.resources import ResourceSnapshot, load_status_file
from app.sessions import CommandResult
from app.state import allowance_summary
from app.version import VERSION

Out = Callable[[str], None]


def _fmt(ctx: AppContext, when: Any) -> str:
    return "-" if when is None else str(ctx.calendar.local(when).strftime("%a %d %b %H:%M:%S"))


def _print_resources(ctx: AppContext, out: Out) -> None:
    """The running service's own snapshot: tick lag and verify times live only in its memory."""
    path = ctx.monitor.status_file
    data = load_status_file(path)
    try:
        if data is None:
            raise TypeError
        if isinstance(data.get("load"), list):
            data["load"] = tuple(data["load"])
        snap = ResourceSnapshot(**data)
    except TypeError:
        out(f"Resources: no snapshot at {path} (is the service running?)")
        return
    out(f"Resources (service snapshot taken {snap.taken_at}):")
    for label, value in snap.lines():
        out(f"  {label + ':':34} {value}")


def cmd_status(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    now = ctx.clock.now()
    day = ctx.calendar.logical_day(now)
    out(f"Screen-Time Controller {VERSION}")
    out(f"Local time {_fmt(ctx, now)} ({ctx.config.timezone}); logical day {day}")
    out(f"Firewall mode: {ctx.config.firewall.mode}")
    _print_resources(ctx, out)
    with ctx.db.session() as db:
        for child_id, child in ctx.config.children.items():
            s = allowance_summary(db, ctx.config, ctx.calendar, child_id, now)
            out("")
            out(f"{child.display_name} ({child_id})")
            out(
                f"  allowance: base {format_duration(s.base_seconds)} "
                f"+ adjustments {s.adjustment_seconds // 60}m - used {format_duration(s.charged_seconds)} "
                f"= {format_duration(s.remaining_seconds)} remaining"
            )
            locks = db.scalars(
                select(DayLock).where(
                    DayLock.child_id == child_id,
                    DayLock.logical_day == day,
                    DayLock.cleared_at.is_(None),
                )
            ).all()
            out(
                f"  day lock:  {'ACTIVE since ' + _fmt(ctx, locks[0].created_at) if locks else 'none'}"
            )
            overrides = db.scalars(
                select(ParentOverride).where(
                    ParentOverride.child_id == child_id,
                    ParentOverride.revoked_at.is_(None),
                    ParentOverride.ends_at > now,
                )
            ).all()
            for o in overrides:
                out(f"  override:  #{o.id} until {_fmt(ctx, o.ends_at)} ({o.note})")
            for sess in db.scalars(
                select(SessionRecord).where(
                    SessionRecord.child_id == child_id, SessionRecord.status == SESSION_ACTIVE
                )
            ):
                out(
                    f"  active:    #{sess.id} {sess.device_id} until {_fmt(ctx, sess.planned_end_at)}"
                )
        tv_sessions = db.scalars(
            select(SessionRecord).where(
                SessionRecord.status == SESSION_ACTIVE, SessionRecord.session_type == "parent"
            )
        ).all()
        out("")
        out(
            "Parent TV sessions: "
            + (
                ", ".join(
                    f"#{s.id} {s.device_id} until {_fmt(ctx, s.planned_end_at)}"
                    for s in tv_sessions
                )
                or "none"
            )
        )
    out("Devices: " + ", ".join(f"{i}={d.ip}" for i, d in ctx.config.devices.items()))
    return 0


def cmd_devices(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    for dev_id, d in ctx.config.devices.items():
        owner = f" owner={d.owner}" if d.owner else ""
        cutoff = f" weekday_cutoff={d.weekday_cutoff:%H:%M}" if d.weekday_cutoff else ""
        out(f"{dev_id:16} {d.ip:15} {d.type}{owner}{cutoff}{'' if d.enabled else ' DISABLED'}")
    return 0


def cmd_sessions(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    with ctx.db.session() as db:
        stmt = select(SessionRecord).order_by(SessionRecord.id.desc()).limit(args.limit)
        if not args.all:
            stmt = select(SessionRecord).where(SessionRecord.status == SESSION_ACTIVE)
        rows = db.scalars(stmt).all()
    if not rows:
        out("no sessions")
    for s in rows:
        out(
            f"#{s.id:<5} {s.status:<18} {(s.child_id or 'parent'):<8} {s.device_id:<15} "
            f"{_fmt(ctx, s.start_at)} -> {_fmt(ctx, s.planned_end_at)} "
            f"charged={s.charged_seconds // 60}m reason={s.end_reason or '-'}"
        )
    return 0


def cmd_audit(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    with ctx.db.session() as db:
        rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(args.limit)).all()
    for e in reversed(rows):
        out(
            f"{_fmt(ctx, e.timestamp)}  {e.actor:<10} {e.event_type:<22} {e.subject:<18} {e.result:<7} {e.details_json}"
        )
    return 0


def _report(res: CommandResult, out: Out, done: str) -> int:
    if res.ok:
        out(done + (f" ({res.message})" if res.message else ""))
        return 0
    out(f"FAILED [{res.reason}]: {res.message}")
    return 1


def _known_child(ctx: AppContext, child_id: str) -> str | None:
    return child_id if child_id in ctx.config.children else None


def cmd_grant(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    if _known_child(ctx, args.child) is None:
        out(f"unknown child {args.child!r}; choose from {', '.join(ctx.config.children)}")
        return 2
    res = asyncio.run(ctx.orchestrator.parent_grant(args.child, args.minutes, "admin-cli"))
    return _report(res, out, f"granted +{args.minutes} minutes to {args.child}")


def cmd_end_today(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    if _known_child(ctx, args.child) is None:
        out(f"unknown child {args.child!r}")
        return 2
    res = asyncio.run(ctx.orchestrator.end_today(args.child, "admin-cli"))
    return _report(res, out, f"ended today for {args.child}")


def cmd_clear_lock(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    if _known_child(ctx, args.child) is None:
        out(f"unknown child {args.child!r}")
        return 2
    res = asyncio.run(ctx.orchestrator.clear_day_lock(args.child, "admin-cli"))
    return _report(res, out, f"cleared day lock for {args.child}")


def cmd_end_session(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    res = asyncio.run(ctx.orchestrator.stop_session(args.id, actor="admin-cli", role="parent"))
    return _report(res, out, f"ended session #{args.id}")


def cmd_end_all(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    async def run() -> CommandResult:
        res = await asyncio.to_thread(ctx.sessions.end_all_sessions, "admin-cli")
        if args.reconcile:
            await ctx.orchestrator._reconcile_quietly(res.ended_device_ids)
        return res

    return _report(asyncio.run(run()), out, "ended every active session")


def cmd_tv(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    minutes = None if args.minutes == "until-stopped" else int(args.minutes)
    res = asyncio.run(ctx.orchestrator.start_tv(args.device, minutes, "admin-cli"))
    return _report(res, out, f"{args.device} enabled for {args.minutes}")


def cmd_enable_device(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    async def run() -> CommandResult:
        res = await asyncio.to_thread(
            ctx.sessions.enable_device, args.device, args.minutes, "admin-cli"
        )
        if res.ok and args.reconcile:
            await ctx.orchestrator._reconcile_quietly()
        return res

    return _report(asyncio.run(run()), out, f"{args.device} forced on for {args.minutes} minutes")


def cmd_unlock(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    reset = ctx.auth.reset_lockout(args.username, "admin-cli")
    out(f"unlocked {args.username}" if reset else f"{args.username} was not locked")
    return 0


def cmd_reconcile(ctx: AppContext, args: argparse.Namespace, out: Out) -> int:
    async def run() -> int:
        try:
            result = await ctx.enforcement.reconcile()
        except Exception as exc:
            out(f"RECONCILE FAILED: {exc}")
            return 1
        out(
            f"desired={sorted(result.desired)} added={sorted(result.added)} "
            f"removed={sorted(result.removed)} killed={sorted(result.killed)}"
        )
        if args.education:
            pushed = await ctx.resolver.refresh()
            out(
                f"education table: {len(pushed)} addresses; unresolved={[s.host for s in ctx.resolver.unresolved()]}"
            )
        return 0

    return asyncio.run(run())


def build_parser() -> argparse.ArgumentParser:
    default_config, default_users = config_paths_from_env()
    parser = argparse.ArgumentParser(
        prog="admin_cli.py", description="Screen-Time Controller administration"
    )
    parser.add_argument("--config", type=Path, default=default_config)
    parser.add_argument("--users", type=Path, default=default_users)
    parser.add_argument(
        "--no-reconcile", dest="reconcile", action="store_false", help="do not touch the firewall"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="policy state for every child").set_defaults(func=cmd_status)
    sub.add_parser("devices", help="list configured devices").set_defaults(func=cmd_devices)
    p = sub.add_parser("sessions", help="list sessions (active by default)")
    p.add_argument("--all", action="store_true")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_sessions)
    p = sub.add_parser("audit", help="recent audit events")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_audit)
    p = sub.add_parser("grant", help="add minutes (+ override window) for a child")
    p.add_argument("child")
    p.add_argument("minutes", type=int)
    p.set_defaults(func=cmd_grant)
    for name, func, text in (
        ("end-today", cmd_end_today, "end screen time today for a child"),
        ("clear-lock", cmd_clear_lock, "clear a child's day lock"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("child")
        p.set_defaults(func=func)
    p = sub.add_parser("end-session", help="stop one session")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_end_session)
    sub.add_parser("end-all", help="stop every active session").set_defaults(func=cmd_end_all)
    p = sub.add_parser("tv", help="parent TV grant")
    p.add_argument("device")
    p.add_argument("minutes", help="minutes, or 'until-stopped'")
    p.set_defaults(func=cmd_tv)
    p = sub.add_parser("enable-device", help="force a device on for a window")
    p.add_argument("device")
    p.add_argument("minutes", type=int)
    p.set_defaults(func=cmd_enable_device)
    p = sub.add_parser("unlock", help="reset a login lockout")
    p.add_argument("username")
    p.set_defaults(func=cmd_unlock)
    p = sub.add_parser("reconcile", help="converge pfSense on the database now")
    p.add_argument("--education", action="store_true", help="also refresh the education allowlist")
    p.set_defaults(func=cmd_reconcile)
    return parser


def main(argv: list[str] | None = None, *, ctx: AppContext | None = None, out: Out = print) -> int:
    args = build_parser().parse_args(argv)
    if ctx is None:
        try:
            config, users = load_all(args.config, args.users)
        except ConfigError as exc:
            print(exc.render(), file=sys.stderr)
            return 2
        ctx = build_context(config, users, enable_push=False)
    status: int = args.func(ctx, args, out)
    return status
