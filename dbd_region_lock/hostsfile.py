"""GameLift entries in the hosts file.

Other region tools leave gamelift redirects behind that fight the lock, so
they are removed on lock and unlock. Steer mode writes its own redirects,
inside a marked block, so they can always be found and removed again.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

GAMELIFT_HOST = re.compile(r"^gamelift(-ping)?\.[a-z0-9-]+\.(amazonaws\.com|api\.aws)\.?$", re.IGNORECASE)
BACKUP_SUFFIX = ".dbd-region-lock.bak"
BLOCK_START = "# BEGIN DBD Region Lock (managed, removed on Unlock)"
BLOCK_END = "# END DBD Region Lock"


def hosts_path() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def strip_gamelift(text: str) -> tuple[str, int]:
    """Return `text` without GameLift hostnames, and how many were removed.

    Only hostname tokens are dropped; a line keeps its other hostnames and is
    removed only when nothing but its IP would remain. Comments are untouched.
    """
    out, removed = [], 0
    for line in text.splitlines(keepends=True):
        if line.strip() in (BLOCK_START, BLOCK_END):
            continue
        body, hash_, comment = line.partition("#")
        tokens = body.split()
        if len(tokens) < 2:
            out.append(line)
            continue
        ip, names = tokens[0], tokens[1:]
        kept = [n for n in names if not GAMELIFT_HOST.match(n)]
        if len(kept) == len(names):
            out.append(line)
            continue
        removed += len(names) - len(kept)
        if kept:
            newline = "\n" if line.endswith("\n") else ""
            tail = f" {hash_}{comment.rstrip(chr(10)).rstrip(chr(13))}" if hash_ else ""
            out.append(" ".join([ip, *kept]) + tail + newline)
    return "".join(out), removed


def clean(path: Path | None = None) -> int:
    """Remove GameLift entries from the hosts file. Returns how many were removed.

    A backup is written next to the file before it is changed. Raises
    PermissionError when entries exist but the file is not writable.
    """
    path = path or hosts_path()
    try:
        original = path.read_text(encoding="utf-8", errors="surrogateescape")
    except FileNotFoundError:
        return 0
    cleaned, removed = strip_gamelift(original)
    if not removed:
        return 0
    shutil.copyfile(path, path.with_name(path.name + BACKUP_SUFFIX))
    path.write_text(cleaned, encoding="utf-8", errors="surrogateescape")
    flush_dns()
    return removed


def has_managed(path: Path | None = None) -> bool:
    try:
        return BLOCK_START in (path or hosts_path()).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def write_managed(entries: list[tuple[str, str]], path: Path | None = None) -> None:
    """Replace every GameLift entry with `entries` ((ip, hostname) pairs) in a marked block."""
    path = path or hosts_path()
    try:
        original = path.read_text(encoding="utf-8", errors="surrogateescape")
    except FileNotFoundError:
        original = ""
    cleaned, _ = strip_gamelift(original)
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"
    block = [BLOCK_START, *(f"{ip} {host}" for ip, host in entries), BLOCK_END]
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if original and not backup.exists():
        backup.write_text(original, encoding="utf-8", errors="surrogateescape")
    path.write_text(cleaned + "\n".join(block) + "\n", encoding="utf-8", errors="surrogateescape")
    flush_dns()


def flush_dns() -> None:
    if sys.platform == "win32":
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
