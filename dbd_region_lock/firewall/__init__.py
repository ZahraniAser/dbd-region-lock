import sys


def get_firewall():
    if sys.platform == "win32":
        from .windows import WindowsFirewall

        return WindowsFirewall()
    if sys.platform.startswith("linux"):
        from .linux import LinuxFirewall

        return LinuxFirewall()
    raise RuntimeError(f"Unsupported platform: {sys.platform}")
