"""Remembers the active lock (region and blocked IPs) between app runs.

The firewall stays the source of truth for whether a lock exists; this file
only adds what the firewall cannot tell us cheaply: which region was chosen
(on Linux) and which IPs are already blocked (so a refresh only adds new ones).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def state_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "dbd-region-lock" / "state.json"


@dataclass
class LockState:
    region: str
    exe: str = ""  # beacon rules apply to this program; "" = every program
    blocked_ips: set[str] = field(default_factory=set)
    strict_exe: str = ""  # Strict mode: whole regions blocked for this program; "" = off
    mode: str = "block"  # "block" (firewall) or "steer" (hosts redirects to a distant decoy region)
    decoy: str = ""  # steer mode: the region every other region is pointed at


def load(path: Path | None = None) -> LockState | None:
    try:
        data = json.loads((path or state_path()).read_text(encoding="utf-8"))
        return LockState(data["region"], data.get("exe", ""), set(data.get("blocked_ips", [])),
                         data.get("strict_exe", ""), data.get("mode", "block"), data.get("decoy", ""))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save(state: LockState, path: Path | None = None) -> None:
    path = path or state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"region": state.region, "exe": state.exe, "blocked_ips": sorted(state.blocked_ips),
            "strict_exe": state.strict_exe, "mode": state.mode, "decoy": state.decoy}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def clear(path: Path | None = None) -> None:
    try:
        (path or state_path()).unlink()
    except FileNotFoundError:
        pass
