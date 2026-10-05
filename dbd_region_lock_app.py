"""Entry point for the packaged Windows .exe (see build_windows.bat)."""

import sys

from dbd_region_lock.cli import main
from dbd_region_lock.elevate import ensure_admin

if __name__ == "__main__":
    ensure_admin()
    sys.exit(main())
