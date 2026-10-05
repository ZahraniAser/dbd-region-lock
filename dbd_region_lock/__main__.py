import sys

from .cli import main
from .elevate import ensure_admin

if __name__ == "__main__":
    # Listing regions needs no privileges; everything else touches the firewall.
    if sys.argv[1:2] != ["regions"]:
        ensure_admin()
    sys.exit(main())
