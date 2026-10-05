"""Steer mode: make every other region look far away instead of unreachable.

Blocking leaves the game with no latency for the other regions, and the
matchmaker may then fall back to a default region. Steer instead points every
other region's beacon hostnames (via the hosts file) at the beacon of a
genuinely distant "decoy" region. The game then measures a complete set of
latencies in which the chosen region is clearly the best.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import regions, resolver

# The decoy should be at least this much slower than the chosen region, or
# steering can't make the chosen region stand out.
MIN_MARGIN_MS = 50


@dataclass
class Plan:
    kept: str
    decoy: str
    kept_ms: float
    decoy_ms: float
    ping_ips: list[str]  # decoy beacon addresses that answered (IPv4), plus its IPv6 ones
    endpoint_ips: list[str]  # decoy gamelift.<region>.amazonaws.com addresses
    entries: list[tuple[str, str]]  # (ip, hostname) lines for the hosts file
    warnings: list[str]


def _best_ping(ips: set[str]) -> tuple[float | None, list[str]]:
    """Lowest UDP beacon latency over `ips`, and the IPv4 addresses that answered."""
    answered = {}
    for ip in sorted(ips):
        if ":" in ip:
            continue
        ms = resolver.udp_ping(ip)
        if ms is not None:
            answered[ip] = ms
    return (min(answered.values()) if answered else None), sorted(answered)


def entries_for(kept: str, decoy: str, ping_ips: list[str], endpoint_ips: list[str]) -> list[tuple[str, str]]:
    """Point every region except `kept` and `decoy` at the decoy's beacon and endpoint."""
    out = []
    for region in regions.REGIONS:
        if region.code in (kept, decoy):
            continue
        endpoint, ping = region.beacon_hosts
        out += [(ip, ping) for ip in ping_ips]
        out += [(ip, endpoint) for ip in endpoint_ips]
    return out


def plan(kept: str) -> Plan:
    regions.get(kept)
    hosts = [h for r in regions.REGIONS for h in r.beacon_hosts]
    found = resolver.resolve_hosts(hosts)
    ping_ips = {r.code: found[r.beacon_hosts[1]] for r in regions.REGIONS}

    with ThreadPoolExecutor(max_workers=len(regions.REGIONS)) as pool:
        results = dict(zip(ping_ips, pool.map(_best_ping, ping_ips.values())))

    kept_ms, _ = results[kept]
    if kept_ms is None:
        raise RuntimeError(f"{regions.get(kept).city}'s beacon does not answer pings from this PC, so it can't be "
                           "steered to. Your network may block UDP port 7770.")

    # The decoy needs a working beacon and an endpoint to point the other names at.
    candidates = {
        code: ms for code, (ms, answered) in results.items()
        if code != kept and ms is not None and answered and found[regions.get(code).beacon_hosts[0]]
    }
    if not candidates:
        raise RuntimeError("No other region's beacon answers from this PC, so there is nothing to steer with.")
    decoy = max(candidates, key=candidates.get)
    decoy_ms = candidates[decoy]
    decoy_region = regions.get(decoy)

    decoy_ping_ips = results[decoy][1] + sorted(ip for ip in ping_ips[decoy] if ":" in ip)
    decoy_endpoint_ips = sorted(found[decoy_region.beacon_hosts[0]])

    warnings = []
    if decoy_ms - kept_ms < MIN_MARGIN_MS:
        warnings.append(f"Every other region is close to {regions.get(kept).city} in ping from here "
                        f"({kept_ms:.0f} ms vs {decoy_ms:.0f} ms), so steering may not make it stand out.")
    return Plan(kept, decoy, kept_ms, decoy_ms, decoy_ping_ips, decoy_endpoint_ips,
                entries_for(kept, decoy, decoy_ping_ips, decoy_endpoint_ips), warnings)
