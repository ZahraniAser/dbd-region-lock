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


BEACON_PORT = 7770  # GameLift ping beacons echo any UDP payload sent here


def udp_ping(ip: str, port: int = BEACON_PORT, timeout: float = 2.5) -> float | None:
    """Round-trip ms of a UDP echo from a GameLift beacon (what the game itself measures), or None."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            start = time.perf_counter()
            sock.send(b"ping")
            sock.recv(512)
        except OSError:
            return None
    return (time.perf_counter() - start) * 1000


def tcp_ping(host: str, port: int = 443, timeout: float = 2.0) -> float | None:
    """Round-trip ms of a TCP handshake, or None."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return None
    return (time.perf_counter() - start) * 1000


def measure_latency(region: Region) -> float | None:
    """Ping the region's beacon over UDP 7770 like the game does.

    Falls back to a TCP handshake with the region's GameLift endpoint when UDP
    gets no answer (some networks drop it), so the app still shows a number.
    """
    beacon = region.beacon_hosts[1]
    try:
        ip = socket.getaddrinfo(beacon, BEACON_PORT, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except (socket.gaierror, IndexError):
        ip = None
    ms = udp_ping(ip) if ip else None
    return ms if ms is not None else tcp_ping(region.beacon_hosts[0])
