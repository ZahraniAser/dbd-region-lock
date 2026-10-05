"""Lock / unlock operations shared by the GUI and CLI."""

from __future__ import annotations

import os
import subprocess
import sys

from . import regions, resolver
from .firewall import get_firewall


def lock(region_code: str, exe: str) -> list[str]:
    """Block every region except `region_code` for `exe`. Returns warnings."""
    blocked = regions.others(region_code)
    ips = resolver.resolve_regions(blocked)
    # A shared IP between the kept region and a blocked one would cut off the
    # kept region too, so never block anything the kept region resolves to.
    keep_ips = resolver.resolve_regions([regions.get(region_code)])[region_code]
    ips = {code: region_ips - keep_ips for code, region_ips in ips.items()}
    return get_firewall().apply(exe, ips)


def unlock() -> None:
    get_firewall().remove()


def status() -> list[str]:
    return get_firewall().blocked_regions()


def locked_region(blocked: list[str]) -> str | None:
    """The one region left unblocked, if the firewall rules pin exactly one."""
    kept = [r.code for r in regions.REGIONS if r.code not in blocked]
    return kept[0] if blocked and len(kept) == 1 else None


def game_running(exe: str) -> bool:
    """True if the DBD executable is running (Windows only; False elsewhere)."""
    if sys.platform != "win32" or not exe:
        return False
    name = os.path.basename(exe)
    result = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return name.lower() in result.stdout.lower()
