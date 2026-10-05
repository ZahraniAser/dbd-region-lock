"""Locate the Dead by Daylight executable on Windows."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Relative to the game's install folder.
SHIPPING_EXES = (
    "DeadByDaylight-Win64-Shipping.exe",  # Steam
    "DeadByDaylight-EGS-Shipping.exe",  # Epic Games Store
    "DeadByDaylight-WinGDK-Shipping.exe",  # Microsoft Store / Game Pass
)
BINARIES_DIR = Path("DeadByDaylight") / "Binaries"
BINARY_SUBDIRS = ("Win64", "WinGDK")


def steam_library_dirs(steam_root: Path) -> list[Path]:
    """Every Steam library folder listed in libraryfolders.vdf."""
    libs = [steam_root]
    vdf = steam_root / "steamapps" / "libraryfolders.vdf"
    try:
        text = vdf.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return libs
    for raw in re.findall(r'"path"\s+"([^"]+)"', text):
        path = Path(raw.replace("\\\\", "\\"))
        if path not in libs:
            libs.append(path)
    return libs


def _steam_roots() -> list[Path]:
    roots = []
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
                roots.append(Path(winreg.QueryValueEx(key, "SteamPath")[0]))
        except OSError:
            pass
        for env in ("ProgramFiles(x86)", "ProgramFiles"):
            if os.environ.get(env):
                roots.append(Path(os.environ[env]) / "Steam")
    return roots


def candidate_install_dirs() -> list[Path]:
    dirs: list[Path] = []
    for root in _steam_roots():
        for lib in steam_library_dirs(root):
            dirs.append(lib / "steamapps" / "common" / "Dead by Daylight")
    if sys.platform == "win32":
        for env in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(env):
                dirs.append(Path(os.environ[env]) / "Epic Games" / "DeadByDaylight")
        dirs.append(Path("C:/XboxGames/Dead by Daylight/Content"))
    return dirs


def find_shipping_exe(install_dir: Path) -> Path | None:
    for sub in BINARY_SUBDIRS:
        for exe in SHIPPING_EXES:
            path = install_dir / BINARIES_DIR / sub / exe
            if path.is_file():
                return path
    return None


def find_dbd_exe() -> Path | None:
    for install_dir in candidate_install_dirs():
        exe = find_shipping_exe(install_dir)
        if exe:
            return exe
    return None


def _windows_process_names() -> set[str]:
    import subprocess

    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return {line.split('","')[0].strip('"').lower() for line in result.stdout.splitlines() if line}


def _linux_cmdlines() -> list[str]:
    # Under Proton the game runs inside Wine, so look for the .exe name in command lines.
    out = []
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                out.append((proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore"))
            except OSError:
                continue
    return out


def game_running() -> bool:
    """True if any Dead by Daylight build (Steam, Epic, Microsoft Store) is running."""
    names = {exe.lower() for exe in SHIPPING_EXES}
    if sys.platform == "win32":
        return bool(names & _windows_process_names())
    if sys.platform.startswith("linux"):
        return any(name in cmd.lower() for cmd in _linux_cmdlines() for name in names)
    return False
