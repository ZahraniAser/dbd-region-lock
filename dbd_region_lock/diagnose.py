"""Self-check: finds the usual reasons a region lock does not hold."""

from __future__ import annotations

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import core, detect, hostsfile, regions, resolver, state

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
SYMBOLS = {OK: "✔", WARN: "⚠", FAIL: "✖", INFO: "•"}


@dataclass
class Check:
    level: str
    text: str


def _powershell(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=20,
    )
    return result.stdout.strip()


def windows_firewall_checks() -> list[Check]:
    checks = []
    try:
        profiles = _powershell('Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }')
        off = [line.split("=")[0] for line in profiles.splitlines() if line.endswith("=False")]
        if off:
            checks.append(Check(FAIL, f"Windows Firewall is OFF for: {', '.join(off)}. Turn it on, or the block rules do nothing."))
        elif profiles:
            checks.append(Check(OK, "Windows Firewall is on."))
    except (OSError, subprocess.SubprocessError):
        checks.append(Check(INFO, "Could not read Windows Firewall state."))
    try:
        products = _powershell(
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct "
            '-ErrorAction SilentlyContinue | ForEach-Object { "$($_.productState)|$($_.displayName)" }'
        )
        on, off = third_party_firewalls(products)
        if on:
            checks.append(Check(FAIL, f"{', '.join(on)} is running its own firewall, so Windows Firewall rules are "
                                      "ignored. Turn its firewall off (keep its antivirus) and press Lock again."))
        if off:
            checks.append(Check(OK, f"{', '.join(off)} firewall is off, so Windows Firewall is in charge."))
    except (OSError, subprocess.SubprocessError):
        pass
    return checks


def third_party_firewalls(output: str) -> tuple[list[str], list[str]]:
    """Split Security Center firewall products into (enabled, disabled) by their productState.

    productState is a 24-bit code whose middle byte says whether the product is
    on: 0x10 (or 0x11) = enabled, 0x00 (or 0x01) = disabled.
    """
    on, off = [], []
    for line in output.splitlines():
        state, _, name = line.partition("|")
        try:
            enabled = (int(state) >> 8) & 0x10
        except ValueError:
            continue
        (on if enabled else off).append(name.strip())
    return sorted(set(on)), sorted(set(off))


def dns_checks(kept: str | None) -> list[Check]:
    """Catch DNS tricks (Acrylic DNS Proxy, router or hosts redirects) that fight the lock."""
    checks = []
    redirected, missing = [], []
    for region in regions.REGIONS:
        host = region.beacon_hosts[1]
        answer = resolver.system_lookup(host)
        if not answer:
            missing.append(region.city)
        elif not any(resolver.usable(ip) for ip in answer):
            redirected.append(region.city)
    if redirected:
        checks.append(Check(FAIL, f"Your DNS points these regions' beacons at a fake/local address: {', '.join(redirected)}. "
                                  "Undo Acrylic DNS Proxy or any hosts/router redirect."))
    if missing:
        level = FAIL if kept and regions.get(kept).city in missing else WARN
        checks.append(Check(level, f"Your DNS returns nothing for: {', '.join(missing)}. A DNS blocker (Acrylic DNS "
                                   "Proxy, Pi-hole, router) is probably hiding them; undo it."))
    if not redirected and not missing:
        checks.append(Check(OK, "DNS resolves every region's beacon normally."))
    try:
        cleaned, removed = hostsfile.strip_gamelift(hostsfile.hosts_path().read_text(encoding="utf-8", errors="ignore"))
        if removed and not hostsfile.has_managed():  # Steer mode's own entries are expected
            checks.append(Check(WARN, f"Your hosts file has {removed} GameLift entries. Press Lock again to remove them."))
    except OSError:
        pass
    return checks


def _reachable(ips: set[str]) -> bool:
    return any(resolver.udp_ping(ip, timeout=1.5) is not None for ip in ips)


def lock_checks(kept: str, saved: state.LockState | None) -> list[Check]:
    checks = []
    current = resolver.resolve_regions(list(regions.REGIONS))
    blocked_now = {code: ips for code, ips in current.items() if code != kept}

    if saved:
        missing = {ip for ips in blocked_now.values() for ip in ips} - saved.blocked_ips - current[kept]
        if missing:
            checks.append(Check(FAIL, f"{len(missing)} beacon address(es) of other regions are not blocked yet. "
                                      "Close the game and press Lock again."))
        else:
            checks.append(Check(OK, "Every beacon address of the other regions is in the block list."))

    if saved and saved.strict_exe:
        checks.append(Check(OK, "Strict is on: every other region's Amazon servers are blocked for the game "
                                "(N. Virginia always stays open, because the game's login servers are there)."))
    elif sys.platform == "win32":
        checks.append(Check(INFO, "Strict is off. If you still land in other regions, tick Strict and press Lock again."))

    all_apps = saved is not None and not saved.exe
    if all_apps or sys.platform != "win32":
        with ThreadPoolExecutor(max_workers=16) as pool:
            leaks = [code for code, hit in zip(blocked_now, pool.map(_reachable, blocked_now.values())) if hit]
        if leaks:
            names = ", ".join(regions.get(c).city for c in leaks)
            checks.append(Check(FAIL, f"Still reachable despite the block: {names}. The firewall is not enforcing the "
                                      "rules (see the firewall checks above)."))
        else:
            checks.append(Check(OK, "Live test: every other region's beacon is unreachable."))
    else:
        checks.append(Check(INFO, "Rules apply to the game only, so this app can't test them live. "
                                  "Switch on 'Block for all apps' to verify."))
        if saved and "windowsapps" in saved.exe.lower():
            checks.append(Check(FAIL, "This is the Microsoft Store / Xbox version: rules limited to its .exe are not "
                                      "applied by Windows. Switch on 'Block for all apps'."))

    kept_ips = current[kept]
    if not kept_ips:
        checks.append(Check(FAIL, f"{regions.get(kept).city}'s beacon has no address, so the game can't measure it."))
    elif _reachable(kept_ips):
        ms = resolver.measure_latency(regions.get(kept))
        checks.append(Check(OK, f"{regions.get(kept).city} answers" + (f" ({ms:.0f} ms)." if ms else ".")))
    else:
        checks.append(Check(WARN, f"{regions.get(kept).city}'s beacon does not answer UDP pings from this PC. If the "
                                  "game can't measure any region it falls back to its default one. Your network may "
                                  "block UDP port 7770."))
    return checks


def steer_checks(kept: str, saved: state.LockState) -> list[Check]:
    checks = []
    decoy = regions.get(saved.decoy)
    decoy_ips = resolver.resolve_hosts(list(decoy.beacon_hosts))
    decoy_all = set().union(*decoy_ips.values())
    checks.append(Check(INFO, f"Steer mode: every other region is pointed at {decoy.city}'s beacon so it looks far away."))

    not_steered = []
    for region in regions.REGIONS:
        if region.code in (kept, decoy.code):
            continue
        answer = {ip for ip in resolver.system_lookup(region.beacon_hosts[1]) if ":" not in ip}
        if not answer or not answer <= decoy_all:
            not_steered.append(region.city)
    if not_steered:
        checks.append(Check(FAIL, f"Not steered on this PC: {', '.join(not_steered)}. Something overrides the hosts "
                                  "file (a DNS tool or VPN). Press Lock again, or undo that tool."))
    else:
        checks.append(Check(OK, f"Every other region resolves to {decoy.city} on this PC."))

    decoy_ms = min((ms for ip in decoy_ips[decoy.beacon_hosts[1]] if ":" not in ip
                    for ms in [resolver.udp_ping(ip, timeout=1.5)] if ms is not None), default=None)
    kept_ms = resolver.measure_latency(regions.get(kept))
    if decoy_ms is None:
        checks.append(Check(FAIL, f"{decoy.city}'s beacon stopped answering, so the other regions would look "
                                  "unreachable again. Close the game and press Lock again."))
    elif kept_ms is not None and decoy_ms - kept_ms < 50:
        checks.append(Check(WARN, f"{regions.get(kept).city} ({kept_ms:.0f} ms) isn't much faster than the "
                                  f"steered regions ({decoy_ms:.0f} ms), so it may not stand out."))
    else:
        detail = f" ({kept_ms:.0f} ms vs {decoy_ms:.0f} ms for every other region)" if kept_ms else ""
        checks.append(Check(OK, f"{regions.get(kept).city} is clearly the best region the game can measure{detail}."))
    return checks


def _safe(name: str, fn, *args) -> list[Check]:
    """Run one group of checks; a crash in it becomes a line in the report instead of ending the check."""
    try:
        return fn(*args)
    except Exception as exc:
        return [Check(WARN, f"The {name} check could not run: {exc}")]


def run() -> list[Check]:
    checks: list[Check] = []
    if detect.game_running():
        checks.append(Check(INFO, "Dead by Daylight is running (fine for checking; close it before changing region)."))
    if sys.platform == "win32":
        checks += _safe("firewall", windows_firewall_checks)

    active, kept = core.status()
    saved = state.load()
    kept = kept or (saved.region if saved else None)
    checks += _safe("DNS", dns_checks, kept)
    if not active:
        checks.append(Check(INFO, "No lock is active."))
    elif not kept:
        checks.append(Check(WARN, "A lock is active but the chosen region is unknown. Press Lock again."))
    else:
        if saved and saved.mode == "steer" and saved.decoy:
            checks.append(Check(OK, f"Lock is active (Steer): {regions.get(kept).name} should be the best region."))
            checks += _safe("steer", steer_checks, kept, saved)
        else:
            checks.append(Check(OK, f"Lock is active: only {regions.get(kept).name} is allowed."))
            checks += _safe("block", lock_checks, kept, saved)
    return checks


def report(checks: list[Check]) -> str:
    return "\n".join(f"{SYMBOLS[c.level]} {c.text}" for c in checks)
