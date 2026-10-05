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
    exe: str = ""
    blocked_ips: set[str] = field(default_factory=set)


def load(path: Path | None = None) -> LockState | None:
    try:
        data = json.loads((path or state_path()).read_text(encoding="utf-8"))
        return LockState(data["region"], data.get("exe", ""), set(data.get("blocked_ips", [])))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save(state: LockState, path: Path | None = None) -> None:
    path = path or state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"region": state.region, "exe": state.exe, "blocked_ips": sorted(state.blocked_ips)}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def clear(path: Path | None = None) -> None:
    try:
        (path or state_path()).unlink()
    except FileNotFoundError:
        pass
