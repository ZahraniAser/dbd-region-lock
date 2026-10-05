"""AWS's published address ranges per region, for Strict mode.

Strict mode blocks every Amazon address of the other regions for the game's
executable, so it can neither measure nor connect to them by any route, not
just through the GameLift ping beacons.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from pathlib import Path

from .state import state_path

IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

# Dead by Daylight's own backend (login, store, matchmaking: steam/egs/grdk.live.bhvrdbd.com)
# runs in us-east-1, so that region is never range-blocked or the game could not log in.
# Its downloads come through CloudFront, which is listed as GLOBAL and never blocked either.
BACKEND_REGIONS = frozenset({"us-east-1"})


def cache_path() -> Path:
    return state_path().with_name("ip-ranges.json")


def ranges_by_region(data: dict) -> dict[str, list[str]]:
    """Region -> its IPv4 and IPv6 prefixes, merged so overlapping/adjacent ones collapse."""
    v4: dict[str, list] = {}
    v6: dict[str, list] = {}
    for p in data.get("prefixes", []):
        v4.setdefault(p["region"], []).append(ipaddress.ip_network(p["ip_prefix"]))
    for p in data.get("ipv6_prefixes", []):
        v6.setdefault(p["region"], []).append(ipaddress.ip_network(p["ipv6_prefix"]))
    out = {}
    for region in set(v4) | set(v6):
        nets = list(ipaddress.collapse_addresses(v4.get(region, [])))
        nets += list(ipaddress.collapse_addresses(v6.get(region, [])))
        out[region] = [str(n) for n in nets]
    return out


def load(timeout: float = 20.0) -> dict[str, list[str]]:
    """Fresh ranges from AWS, cached on disk; the cached copy is used when offline."""
    cache = cache_path()
    try:
        with urllib.request.urlopen(IP_RANGES_URL, timeout=timeout) as response:
            raw = response.read()
        data = json.loads(raw)
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(raw)
    except (OSError, ValueError):
        try:
            data = json.loads(cache.read_bytes())
        except (OSError, ValueError):
            raise RuntimeError("Could not download AWS's address list (needed for Strict mode). "
                               "Check your internet connection, or turn Strict off.") from None
    return ranges_by_region(data)


def strict_block_list(keep: str, regions: list[str], all_ranges: dict[str, list[str]]) -> dict[str, list[str]]:
    """Ranges to block for the game: every listed region except the kept one and the backend region."""
    return {code: all_ranges.get(code, []) for code in regions if code != keep and code not in BACKEND_REGIONS}
