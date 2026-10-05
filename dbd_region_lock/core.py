"""Lock / unlock operations shared by the GUI and CLI."""

from __future__ import annotations

import threading

from . import detect, hostsfile, regions, resolver, state
from .firewall import get_firewall


# Lock, unlock and the background refresh must never change the firewall at the same time.
_firewall_lock = threading.Lock()


class GameRunningError(RuntimeError):
    """Changing the firewall while DBD runs risks an Easy Anti-Cheat flag, so it is refused."""

    def __init__(self):
        super().__init__("Close Dead by Daylight first. Changing region while the game is running can flag Easy Anti-Cheat.")


def _require_game_closed() -> None:
    if detect.game_running():
        raise GameRunningError()


def _clean_hosts() -> list[str]:
    try:
        removed = hostsfile.clean()
    except OSError:
        # Not writable (no root on Linux, or antivirus / Controlled Folder Access on Windows).
        return [f"Your hosts file ({hostsfile.hosts_path()}) has GameLift entries from another tool "
                "that could not be removed automatically. Remove them, or they will interfere with the lock."]
    return [f"Removed {removed} leftover GameLift entries from your hosts file (backup saved)."] if removed else []


def _block_lists(region_code: str) -> dict[str, set[str]]:
    blocked = regions.others(region_code)
    ips = resolver.resolve_regions(blocked)
    # A shared IP between the kept region and a blocked one would cut off the
    # kept region too, so never block anything the kept region resolves to.
    keep_ips = resolver.resolve_regions([regions.get(region_code)])[region_code]
    return {code: region_ips - keep_ips for code, region_ips in ips.items()}


def _lock(region_code: str, exe: str) -> list[str]:
    """Block every region except `region_code` for `exe`. Returns notes and warnings."""
    _require_game_closed()
    notes = _clean_hosts()
    ips = _block_lists(region_code)
    notes += get_firewall().apply(exe, ips)
    state.save(state.LockState(region_code, exe, set().union(*ips.values())))
    return notes


def _unlock() -> list[str]:
    _require_game_closed()
    notes = _clean_hosts()
    get_firewall().remove()
    state.clear()
    return notes


def _refresh() -> int:
    """Block beacon IPs that rotated in since the lock was set. Returns how many were added.

    Only ever adds rules, so the block is never lifted, and does nothing while
    the game is running (no firewall changes mid-session).
    """
    current = state.load()
    firewall = get_firewall()
    if not current or not firewall.can_refresh() or detect.game_running():
        return 0
    fresh = {code: ips - current.blocked_ips for code, ips in _block_lists(current.region).items()}
    added = sum(len(ips) for ips in fresh.values())
    if added:
        firewall.add(current.exe, fresh)
        current.blocked_ips |= set().union(*fresh.values())
        state.save(current)
    return added


def status() -> tuple[bool, str | None]:
    """(lock active, locked region code if known)."""
    blocked = get_firewall().blocked_regions()
    if not blocked:
        return False, None
    saved = state.load()
    return True, locked_region(blocked) or (saved.region if saved else None)


def locked_region(blocked: list[str]) -> str | None:
    """The one region left unblocked, if the firewall rules pin exactly one."""
    kept = [r.code for r in regions.REGIONS if r.code not in blocked]
    return kept[0] if blocked and len(kept) == 1 else None


def lock(region_code: str, exe: str) -> list[str]:
    with _firewall_lock:
        return _lock(region_code, exe)


def unlock() -> list[str]:
    with _firewall_lock:
        return _unlock()


def refresh() -> int:
    with _firewall_lock:
        return _refresh()
