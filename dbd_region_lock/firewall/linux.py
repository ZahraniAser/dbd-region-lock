"""Linux backend (nftables), for DBD running under Steam Proton.

Proton runs the game inside Wine, so there is no reliable per-executable match
like Windows has. Instead a dedicated nftables table drops outbound traffic to
the other regions' GameLift beacon IPs. Those addresses only serve GameLift
latency pings, so blocking them system-wide does not affect anything else.
Rules live until removed or until reboot.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess

TABLE = "dbd_region_lock"


def ruleset(blocked: dict[str, set[str]]) -> str:
    v4, v6 = set(), set()
    for ips in blocked.values():
        for ip in ips:
            (v6 if ipaddress.ip_address(ip).version == 6 else v4).add(ip)

    lines = [f"table inet {TABLE} {{"]
    for name, kind, ips in (("blocked4", "ipv4_addr", v4), ("blocked6", "ipv6_addr", v6)):
        lines.append(f"  set {name} {{")
        lines.append(f"    type {kind}")
        if ips:
            lines.append(f"    elements = {{ {', '.join(sorted(ips))} }}")
        lines.append("  }")
    lines += [
        "  chain output {",
        "    type filter hook output priority 0; policy accept;",
        "    ip daddr @blocked4 drop",
        "    ip6 daddr @blocked6 drop",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def add_elements(blocked: dict[str, set[str]]) -> str:
    """nft commands that add IPs to the existing sets."""
    v4 = sorted(ip for ips in blocked.values() for ip in ips if ipaddress.ip_address(ip).version == 4)
    v6 = sorted(ip for ips in blocked.values() for ip in ips if ipaddress.ip_address(ip).version == 6)
    lines = []
    if v4:
        lines.append(f"add element inet {TABLE} blocked4 {{ {', '.join(v4)} }}")
    if v6:
        lines.append(f"add element inet {TABLE} blocked6 {{ {', '.join(v6)} }}")
    return "\n".join(lines) + "\n" if lines else ""


def _privileged(args: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return args
    for helper in ("pkexec", "sudo"):
        if shutil.which(helper):
            return [helper, *args]
    return args


class LinuxFirewall:
    def is_admin(self) -> bool:
        # Not required up front: nft is run through pkexec/sudo when needed.
        return True

    def apply(self, exe: str, blocked: dict[str, set[str]]) -> list[str]:
        if not shutil.which("nft"):
            raise RuntimeError("nftables (the 'nft' command) is not installed")
        warnings = [f"{code}: no beacon IPs resolved, region left unblocked" for code, ips in blocked.items() if not ips]
        # Delete-then-create in one transaction so a re-apply replaces the old lock.
        script = f"add table inet {TABLE}\ndelete table inet {TABLE}\n" + ruleset(blocked)
        result = subprocess.run(_privileged(["nft", "-f", "-"]), input=script, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"nft failed: {result.stderr.strip()}")
        return warnings

    def can_refresh(self) -> bool:
        # Each nft call outside root would pop a password prompt, so only refresh silently as root.
        return os.geteuid() == 0

    def add(self, exe: str, blocked: dict[str, set[str]]) -> None:
        script = add_elements(blocked)
        if not script:
            return
        result = subprocess.run(_privileged(["nft", "-f", "-"]), input=script, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"nft failed: {result.stderr.strip()}")

    def add_ranges(self, exe: str, ranges: dict[str, list[str]]) -> None:
        # Without a per-program match, blocking whole AWS regions would break much of the web.
        raise RuntimeError("Strict mode is only available on Windows.")

    def remove(self) -> None:
        subprocess.run(_privileged(["nft", "delete", "table", "inet", TABLE]), capture_output=True, text=True)

    def blocked_regions(self) -> list[str]:
        # Region names are not stored in the nft table; report whether a lock exists.
        result = subprocess.run(_privileged(["nft", "list", "table", "inet", TABLE]), capture_output=True, text=True)
        return ["(locked)"] if result.returncode == 0 else []
