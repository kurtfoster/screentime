#!/usr/bin/env python3
"""Generate the PWA icons (a white clock on blue) using only the standard library.

Run once; the PNGs are committed. Usage: python scripts/make_icons.py
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "app" / "static" / "icons"
BLUE = (29, 78, 216)
WHITE = (255, 255, 255)


def dist_to_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def coverage(x: float, y: float, scale: float) -> float:
    """1.0 where the clock glyph is, else 0.0. Coordinates are 0..1 across the icon."""
    cx = cy = 0.5
    r = math.hypot(x - cx, y - cy)
    ring = scale * 0.30 >= r >= scale * 0.235
    hour = dist_to_segment(x, y, cx, cy, cx, cy - scale * 0.15) <= scale * 0.022
    minute = dist_to_segment(x, y, cx, cy, cx + scale * 0.115, cy + scale * 0.065) <= scale * 0.022
    dot = r <= scale * 0.04
    return 1.0 if ring or hour or minute or dot else 0.0


def png(size: int, scale: float) -> bytes:
    ss = 3  # supersampling for smooth edges
    rows = bytearray()
    for py in range(size):
        rows.append(0)
        for px in range(size):
            acc = 0.0
            for sy in range(ss):
                for sx in range(ss):
                    acc += coverage(
                        (px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size, scale
                    )
            a = acc / (ss * ss)
            rows.extend(int(BLUE[i] + (WHITE[i] - BLUE[i]) * a) for i in range(3))

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return (
            struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    targets = {
        "icon-192.png": (192, 1.0),
        "icon-512.png": (512, 1.0),
        "apple-touch-icon.png": (180, 1.0),
        "icon-maskable-512.png": (512, 0.8),  # glyph kept inside the maskable safe zone
    }
    for name, (size, scale) in targets.items():
        (OUT / name).write_bytes(png(size, scale))
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
