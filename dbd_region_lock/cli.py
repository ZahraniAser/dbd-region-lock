"""Command-line interface: python -m dbd_region_lock <command>."""

from __future__ import annotations

import argparse
import sys

from . import core, detect, regions, resolver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dbd-region-lock", description=__doc__)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("gui", help="open the desktop app (default)")
    sub.add_parser("regions", help="list regions with current latency")
    lock_p = sub.add_parser("lock", help="lock the game to one region")
    lock_p.add_argument("region", choices=list(regions.BY_CODE))
    lock_p.add_argument("--exe", help="path to the DBD shipping executable (auto-detected on Windows)")
    sub.add_parser("unlock", help="remove the lock")
    sub.add_parser("status", help="show which regions are blocked")

    args = parser.parse_args(argv)

    if args.command in (None, "gui"):
        from .gui import run

        run()
        return 0

    if args.command == "regions":
        for r in regions.REGIONS:
            ms = resolver.measure_latency(r)
            print(f"{r.code:<16} {r.name:<28} {f'{ms:.0f} ms' if ms is not None else 'unreachable'}")
        return 0

    if args.command == "lock":
        exe = args.exe or detect.find_dbd_exe()
        if not exe and sys.platform == "win32":
            print("Could not find Dead by Daylight. Pass --exe <path to DeadByDaylight-*-Shipping.exe>.")
            return 1
        for warning in core.lock(args.region, str(exe or "")):
            print(f"warning: {warning}")
        print(f"Locked to {args.region}. Restart the game if it is running.")
        return 0

    if args.command == "unlock":
        core.unlock()
        print("Lock removed. All regions are reachable again.")
        return 0

    if args.command == "status":
        blocked = core.status()
        print(f"Blocked: {', '.join(blocked)}" if blocked else "Not locked.")
        return 0

    return 1
