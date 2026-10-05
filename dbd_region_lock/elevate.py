"""Relaunch elevated on Windows, since firewall rules need administrator rights."""

from __future__ import annotations

import os
import subprocess
import sys


def ensure_admin() -> None:
    if sys.platform != "win32":
        return
    import ctypes

    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    if getattr(sys, "frozen", False):
        params = subprocess.list2cmdline(sys.argv[1:])
        workdir = None
    else:
        params = subprocess.list2cmdline(["-m", "dbd_region_lock", *sys.argv[1:]])
        # Elevated processes start in System32; run from the folder holding the package.
        workdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # SW_SHOWNORMAL = 1. Returns > 32 on success; the user may decline the UAC prompt.
    if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, workdir, 1) > 32:
        sys.exit(0)
    sys.exit("Administrator rights are required to change firewall rules.")
