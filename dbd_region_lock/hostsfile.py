"""Strip GameLift redirects other region tools leave in the hosts file.

Hosts-file region changers point gamelift hostnames at one region's IP. Left
behind, those entries fight the firewall lock (the game would ping the wrong
address), so they are removed on lock and unlock.
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
    if sys.platform == "win32":
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return removed
