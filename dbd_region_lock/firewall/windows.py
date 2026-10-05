"""Windows Defender Firewall backend (netsh advfirewall).

One outbound block rule per blocked region. By default the rules cover every
program (the beacon IPs serve nothing but GameLift latency pings); optionally
they are scoped with program= to the DBD executable only. Rules persist across
reboots until removed.
"""

from __future__ import annotations

import subprocess
import sys
import time

from ..regions import REGIONS

RULE_PREFIX = "DBD Region Lock"


def rule_name(region_code: str) -> str:
    return f"{RULE_PREFIX} - {region_code}"


def add_rule_args(region_code: str, exe: str, ips: set[str]) -> list[str]:
    """netsh arguments for one block rule. An empty `exe` blocks these IPs for every program."""
    args = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name(region_code)}",
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
        "protocol=any",
        f"remoteip={','.join(sorted(ips))}",
    ]
    if exe:
        args.insert(-1, f"program={exe}")
    return args


def delete_rule_args(region_code: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name(region_code)}"]


def _run(args: list[str]) -> subprocess.CompletedProcess:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.run(args, capture_output=True, text=True, creationflags=flags)


def _add_rule(region_code: str, exe: str, ips: set[str]) -> None:
    # Windows Firewall occasionally fails with a transient "error (0x2)"; retry a few times.
    for _ in range(3):
        result = _run(add_rule_args(region_code, exe, ips))
        if result.returncode == 0:
            return
        time.sleep(0.3)
    raise RuntimeError(f"netsh failed for {region_code}: {result.stdout.strip() or result.stderr.strip()}")


class WindowsFirewall:
    def is_admin(self) -> bool:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def apply(self, exe: str, blocked: dict[str, set[str]]) -> list[str]:
        """Replace any existing lock with block rules for `blocked`. Returns warnings."""
        self.remove()
        warnings = []
        for code, ips in blocked.items():
            if not ips:
                warnings.append(f"{code}: no beacon IPs resolved, region left unblocked")
                continue
            _add_rule(code, exe, ips)
        return warnings

    def can_refresh(self) -> bool:
        return True

    def add(self, exe: str, blocked: dict[str, set[str]]) -> None:
        """Add rules for more IPs without touching existing ones, so the block never lapses."""
        for code, ips in blocked.items():
            if ips:
                _add_rule(code, exe, ips)

    def remove(self) -> None:
        # netsh exits non-zero when no rule matches; that is fine here. Deleting by
        # name removes every rule with that name, including ones added by add().
        for region in REGIONS:
            _run(delete_rule_args(region.code))

    def blocked_regions(self) -> list[str]:
        return [
            r.code
            for r in REGIONS
            if _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name(r.code)}"]).returncode == 0
        ]
