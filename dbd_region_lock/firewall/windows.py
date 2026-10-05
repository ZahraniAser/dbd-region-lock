"""Windows Defender Firewall backend (netsh advfirewall).

One outbound block rule per blocked region, scoped with program= to the DBD
executable, so nothing else on the machine is affected. Rules persist across
reboots until removed.
"""

from __future__ import annotations

import subprocess
import sys

from ..regions import REGIONS

RULE_PREFIX = "DBD Region Lock"


def rule_name(region_code: str) -> str:
    return f"{RULE_PREFIX} - {region_code}"


def add_rule_args(region_code: str, exe: str, ips: set[str]) -> list[str]:
    return [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name(region_code)}",
        "dir=out",
        "action=block",
        "enable=yes",
        "profile=any",
        "protocol=any",
        f"program={exe}",
        f"remoteip={','.join(sorted(ips))}",
    ]


def delete_rule_args(region_code: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name(region_code)}"]


def _run(args: list[str]) -> subprocess.CompletedProcess:
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    return subprocess.run(args, capture_output=True, text=True, creationflags=flags)


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
            result = _run(add_rule_args(code, exe, ips))
            if result.returncode != 0:
                raise RuntimeError(f"netsh failed for {code}: {result.stdout.strip() or result.stderr.strip()}")
        return warnings

    def remove(self) -> None:
        # netsh exits non-zero when no rule matches; that is fine here.
        for region in REGIONS:
            _run(delete_rule_args(region.code))

    def blocked_regions(self) -> list[str]:
        return [
            r.code
            for r in REGIONS
            if _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name(r.code)}"]).returncode == 0
        ]
