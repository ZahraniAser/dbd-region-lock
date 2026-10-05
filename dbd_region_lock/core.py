"""Lock / unlock operations shared by the GUI and CLI."""

from __future__ import annotations

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
