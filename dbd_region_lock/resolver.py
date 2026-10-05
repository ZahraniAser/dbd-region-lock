"""Resolve beacon hostnames to IPs and measure latency to each region."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .regions import Region

# Beacon DNS answers rotate, so resolve several times and union the results.
RESOLVE_ROUNDS = 3


def resolve_host(host: str, rounds: int = RESOLVE_ROUNDS) -> set[str]:
    ips: set[str] = set()
    for _ in range(rounds):
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue
        for family, _, _, _, sockaddr in infos:
            if family in (socket.AF_INET, socket.AF_INET6):
                ips.add(sockaddr[0])
    return ips


def resolve_regions(regions: list[Region]) -> dict[str, set[str]]:
    """Map region code -> every IP its beacon hosts resolved to."""
    jobs = [(r.code, h) for r in regions for h in r.beacon_hosts]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda job: (job[0], resolve_host(job[1])), jobs)
    out: dict[str, set[str]] = {r.code: set() for r in regions}
    for code, ips in results:
        out[code] |= ips
    return out


def measure_latency(region: Region, timeout: float = 2.0) -> float | None:
    """Round-trip time in ms of a TCP handshake to the region's beacon, or None."""
    host = region.beacon_hosts[0]
    start = time.perf_counter()
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            pass
    except OSError:
        return None
    return (time.perf_counter() - start) * 1000
