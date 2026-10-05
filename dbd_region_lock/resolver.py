"""Resolve beacon hostnames to IPs and measure latency to each region."""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .regions import Region

# Each beacon name sits on a small pool of addresses (2 IPv4 + 2 IPv6), but a
# DNS answer carries only one of each, and a resolver's cache keeps repeating the
# same answer. So ask several independent resolvers, over a few rounds, until
# the pool stops growing. Missing one address leaves that region reachable.
MIN_ROUNDS = 3
STABLE_ROUNDS = 2  # stop after this many rounds with nothing new
MAX_ROUNDS = 5
ROUND_DELAY = 0.3

# Encrypted DNS answers can't be faked by the hosts file or a local DNS proxy
# (such as Acrylic), and different providers return different parts of the pool.
DOH_PROVIDERS = (
    "https://cloudflare-dns.com/dns-query?name={name}&type={type}",
    "https://dns.google/resolve?name={name}&type={type}",
)


def usable(ip: str) -> bool:
    """Real internet addresses only: drops 0.0.0.0, loopback and LAN answers from DNS blockers."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def system_lookup(host: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return set()
    return {sockaddr[0] for family, _, _, _, sockaddr in infos if family in (socket.AF_INET, socket.AF_INET6)}


def _doh_query(url: str, timeout: float) -> set[str]:
    request = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            answers = json.load(response).get("Answer", [])
    except (OSError, ValueError):
        return set()
    return {a["data"] for a in answers if a.get("type") in (1, 28) and isinstance(a.get("data"), str)}


def doh_lookup(host: str, timeout: float = 3.0) -> set[str]:
    """A and AAAA records from each DNS-over-HTTPS provider, queried in parallel; failures are skipped."""
    urls = [t.format(name=host, type=rtype) for t in DOH_PROVIDERS for rtype in ("A", "AAAA")]
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        return set().union(*pool.map(lambda url: _doh_query(url, timeout), urls))


# Public resolvers asked directly over plain DNS (UDP 53). Each keeps its own
# cache and hands out a different part of a beacon's address pool.
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222")
QTYPES = {"A": 1, "AAAA": 28}


def build_query(host: str, qtype: int, query_id: int = 0x1D1D) -> bytes:
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # recursion desired, one question
    name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in host.rstrip(".").split(".")) + b"\0"
    return header + name + struct.pack(">HH", qtype, 1)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return pos + 2
        pos += 1 + length


def parse_response(data: bytes) -> set[str]:
    """Addresses from the A/AAAA records in a DNS response (CNAMEs are skipped)."""
    _, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if flags & 0x000F:  # non-zero RCODE (e.g. NXDOMAIN)
        return set()
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(data, pos) + 4
    ips = set()
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlength]
        if rtype == 1 and rdlength == 4:
            ips.add(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == 28 and rdlength == 16:
            ips.add(socket.inet_ntop(socket.AF_INET6, rdata))
        pos += rdlength
    return ips


def direct_lookup(host: str, server: str, qtype: int, timeout: float = 1.5) -> set[str] | None:
    """Addresses from one resolver; None when it did not answer at all (vs. an empty answer)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(build_query(host, qtype), (server, 53))
            data, _ = sock.recvfrom(4096)
        except OSError:
            return None
    try:
        return parse_response(data)
    except (struct.error, IndexError):
        return set()


def public_lookup(host: str) -> set[str]:
    """Ask every public resolver once for A and AAAA; unreachable ones are skipped."""
    return resolve_hosts([host], rounds=1, use_doh=False)[host]


QUERY_WORKERS = 24  # cap on DNS questions in flight; more just gets answers dropped


def resolve_hosts(hosts: list[str], rounds: int = MAX_ROUNDS, use_doh: bool = True) -> dict[str, set[str]]:
    """Every usable address of each host, from the system resolver plus public ones.

    Works in rounds over all hosts at once so the number of DNS questions in
    flight stays bounded, and stops once a few rounds in a row find nothing new.
    Public resolvers that never answer (some ISPs block them) are dropped after
    the first round so they don't slow every later round down.
    """
    found: dict[str, set[str]] = {h: set() for h in hosts}
    servers = list(PUBLIC_RESOLVERS)
    quiet = 0
    with ThreadPoolExecutor(max_workers=QUERY_WORKERS) as pool:
        for round_no in range(rounds):
            jobs = [(h, None, lambda h=h: system_lookup(h)) for h in hosts]
            jobs += [(h, srv, lambda h=h, s=srv, q=qt: direct_lookup(h, s, q))
                     for h in hosts for srv in servers for qt in QTYPES.values()]
            if use_doh and round_no < 2:
                jobs += [(h, None, lambda h=h: doh_lookup(h)) for h in hosts]
            answered: set[str] = set()
            new = False
            for (host, server, _), ips in zip(jobs, pool.map(lambda job: job[2](), jobs)):
                if ips is None:
                    continue
                if server:
                    answered.add(server)
                ips = {ip for ip in ips if usable(ip)} - found[host]
                if ips:
                    found[host] |= ips
                    new = True
            servers = [srv for srv in servers if srv in answered]
            quiet = 0 if new else quiet + 1
            if round_no + 1 >= min(MIN_ROUNDS, rounds) and quiet >= STABLE_ROUNDS:
                break
            if round_no + 1 < rounds:
                time.sleep(ROUND_DELAY)
    return found


def resolve_host(host: str) -> set[str]:
    return resolve_hosts([host])[host]


def resolve_regions(regions: list[Region]) -> dict[str, set[str]]:
    """Map region code -> every IP its beacon hosts resolved to."""
    found = resolve_hosts([h for r in regions for h in r.beacon_hosts])
    return {r.code: set().union(*(found[h] for h in r.beacon_hosts)) for r in regions}


BEACON_PORT = 7770  # GameLift ping beacons echo any UDP payload sent here


def udp_ping(ip: str, port: int = BEACON_PORT, timeout: float = 2.5) -> float | None:
    """Round-trip ms of a UDP echo from a GameLift beacon (what the game itself measures), or None."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        # Creating the socket can fail too (e.g. IPv6 on a PC without IPv6), so it's inside the try.
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
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
