"""Desktop app: dark themed region picker built on tkinter (ships with Python)."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox

from . import __version__, core, detect, diagnose, regions, resolver, state

# Colours. Change these to restyle the whole app.
BG = "#0f1115"
PANEL = "#171a21"
CARD = "#1d212a"
CARD_HOVER = "#252a35"
BORDER = "#2a2f3a"
ACCENT = "#d61f2c"
ACCENT_HOVER = "#ef3340"
TEXT = "#e6e8ee"
MUTED = "#8b93a7"
GOOD = "#22c55e"
OK = "#eab308"
BAD = "#ef4444"

# Ping thresholds in ms for green / yellow; anything slower is red.
PING_GOOD = 80
PING_OK = 150
CARD_COLUMNS = 3
TITLE = "DBD Region Lock"
GAME_CHECK_MS = 3000  # how often to look for a running game
REFRESH_MS = 300_000  # how often to block beacon IPs that changed


def ping_colour(ms: float | None) -> str:
    if ms is None:
        return MUTED
    return GOOD if ms < PING_GOOD else OK if ms < PING_OK else BAD


def elide(text: str, limit: int = 64) -> str:
    return text if len(text) <= limit else text[: limit // 2 - 2] + " … " + text[-(limit // 2 - 1):]


class Fonts:
    def __init__(self, root: tk.Tk):
        families = set(tkfont.families(root))
        family = next((f for f in ("Segoe UI", "Inter", "Cantarell", "DejaVu Sans") if f in families), "TkDefaultFont")
        self.title = (family, 18, "bold")
        self.heading = (family, 10, "bold")
        self.body = (family, 10)
        self.small = (family, 9)
        self.card_title = (family, 11, "bold")
        self.button = (family, 10, "bold")


def make_button(parent, text, command, fonts: Fonts, primary=False) -> tk.Button:
    bg, hover = (ACCENT, ACCENT_HOVER) if primary else (CARD, CARD_HOVER)
    btn = tk.Button(
        parent, text=text, command=command, font=fonts.button, cursor="hand2",
        bg=bg, fg=TEXT, activebackground=hover, activeforeground=TEXT,
        disabledforeground=MUTED, relief="flat", bd=0, highlightthickness=0, padx=16, pady=8,
    )
    btn.bind("<Enter>", lambda _: btn["state"] != "disabled" and btn.config(bg=hover))
    btn.bind("<Leave>", lambda _: btn.config(bg=bg))
    return btn


class RegionCard(tk.Frame):
    """Clickable card showing one region and its live ping."""

    def __init__(self, master, region: regions.Region, fonts: Fonts, on_click):
        super().__init__(master, bg=CARD, highlightthickness=2, highlightbackground=BORDER, cursor="hand2")
        self.region = region
        self.selected = False
        self.hovered = False

        self.name = tk.Label(self, text=region.city, font=fonts.card_title, bg=CARD, fg=TEXT, anchor="w")
        self.badge = tk.Label(self, text="", font=fonts.small, bg=CARD, fg=ACCENT, anchor="e")
        self.code = tk.Label(self, text=region.code, font=fonts.small, bg=CARD, fg=MUTED, anchor="w")
        self.ping = tk.Label(self, text="…", font=fonts.heading, bg=CARD, fg=MUTED, anchor="e")
        self.name.grid(row=0, column=0, sticky="w", padx=(12, 4), pady=(8, 0))
        self.badge.grid(row=0, column=1, sticky="e", padx=(4, 12), pady=(8, 0))
        self.code.grid(row=1, column=0, sticky="w", padx=(12, 4), pady=(0, 8))
        self.ping.grid(row=1, column=1, sticky="e", padx=(4, 12), pady=(0, 8))
        self.columnconfigure(0, weight=1)

        for widget in (self, self.name, self.badge, self.code, self.ping):
            widget.bind("<Button-1>", lambda _: on_click(region.code))
            widget.bind("<Enter>", lambda _: self._hover(True))
            widget.bind("<Leave>", self._maybe_leave)

    def _maybe_leave(self, _):
        # Moving onto a child label fires <Leave> on the frame; only un-hover when truly outside.
        under = self.winfo_containing(*self.winfo_pointerxy())
        if under is None or not str(under).startswith(str(self)):
            self._hover(False)

    def _hover(self, on: bool):
        self.hovered = on
        self._paint()

    def _paint(self):
        bg = CARD_HOVER if self.hovered or self.selected else CARD
        self.config(bg=bg, highlightbackground=ACCENT if self.selected else BORDER)
        for widget in (self.name, self.badge, self.code, self.ping):
            widget.config(bg=bg)

    def set_selected(self, on: bool):
        self.selected = on
        self._paint()

    def set_active(self, on: bool):
        self.badge.config(text="● LOCKED" if on else "")

    def set_ping(self, ms: float | None, pending=False, blocked=False):
        if blocked:
            self.ping.config(text="BLOCKED", fg=ACCENT)
            return
        text = "…" if pending else (f"{ms:.0f} ms" if ms is not None else "n/a")
        self.ping.config(text=text, fg=MUTED if pending else ping_colour(ms))


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.fonts = Fonts(root)
        self.selected: str | None = None
        self.locked: str | None = None  # the one region left open, when known
        self.lock_active = False  # any lock rules present
        self.game_running = False
        self.busy_now = False
        self.pings: dict[str, float | None] = {}
        self.exe = tk.StringVar(value=str(detect.find_dbd_exe() or ""))
        # Blocking the beacons for every program is the reliable default (and lets the
        # app verify the block); keep the game-only choice from an earlier lock.
        saved = state.load()
        self.all_apps = tk.BooleanVar(value=not (saved and saved.exe))

        root.title(f"{TITLE} {__version__}")
        root.configure(bg=BG)

        outer = tk.Frame(root, bg=BG, padx=22, pady=18)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)

        self._build_header(outer).grid(row=0, column=0, sticky="ew")
        self._build_game_row(outer).grid(row=1, column=0, sticky="ew", pady=(16, 0))
        self._build_regions(outer).grid(row=2, column=0, sticky="nsew", pady=(16, 0))
        outer.rowconfigure(2, weight=1)
        self._build_footer(outer).grid(row=3, column=0, sticky="ew", pady=(16, 0))
        # Never let the window shrink below what the cards need.
        root.update_idletasks()
        root.minsize(max(720, root.winfo_reqwidth()), root.winfo_reqheight())

        self.game_banner = tk.Label(
            outer, text="Dead by Daylight is running. Close it to change region (changing mid-game can flag Easy Anti-Cheat).",
            font=self.fonts.heading, bg=OK, fg=BG, padx=12, pady=8, anchor="w", justify="left", wraplength=680,
        )
        self.banner_row = 4

        self.refresh_ping()
        self.set_busy(True, "Checking firewall rules…")
        self.background(core.status, self.on_status)
        self.root.after(0, self.watch_game)
        self.root.after(REFRESH_MS, self.refresh_lock)

    # Layout --------------------------------------------------------------

    def _build_header(self, parent) -> tk.Frame:
        header = tk.Frame(parent, bg=BG)
        header.columnconfigure(0, weight=1)
        tk.Label(header, text=TITLE.upper(), font=self.fonts.title, bg=BG, fg=TEXT).grid(row=0, column=0, sticky="w")
        tk.Label(
            header, text="Pick where you play. Every other region's ping beacon gets firewall-blocked.",
            font=self.fonts.body, bg=BG, fg=MUTED,
        ).grid(row=1, column=0, sticky="w")
        self.pill = tk.Label(header, text="CHECKING…", font=self.fonts.heading, bg=CARD, fg=MUTED, padx=12, pady=6)
        self.pill.grid(row=0, column=1, rowspan=2, sticky="e")
        return header

    def _build_game_row(self, parent) -> tk.Frame:
        row = tk.Frame(parent, bg=PANEL, padx=14, pady=10)
        row.columnconfigure(1, weight=1)
        tk.Label(row, text="GAME", font=self.fonts.heading, bg=PANEL, fg=MUTED).grid(row=0, column=0, sticky="w", padx=(0, 12))
        self.game_label = tk.Label(row, font=self.fonts.body, bg=PANEL, fg=TEXT, anchor="w")
        self.game_label.grid(row=0, column=1, sticky="ew")
        if sys.platform == "win32":
            make_button(row, "Change…", self.browse, self.fonts).grid(row=0, column=2, sticky="e", padx=(12, 0))
            tk.Checkbutton(
                row, text="Block for all apps (recommended: works for every DBD version and can be verified with Check)",
                variable=self.all_apps, command=self._show_game, font=self.fonts.small, bg=PANEL, fg=TEXT,
                selectcolor=CARD, activebackground=PANEL, activeforeground=TEXT, highlightthickness=0, bd=0,
                anchor="w",
            ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self._show_game()
        return row

    def _build_regions(self, parent) -> tk.Frame:
        panel = tk.Frame(parent, bg=BG)
        self.cards: dict[str, RegionCard] = {}
        row = 0
        for area in regions.AREAS:
            tk.Label(panel, text=area.upper(), font=self.fonts.heading, bg=BG, fg=MUTED).grid(
                row=row, column=0, columnspan=CARD_COLUMNS, sticky="w", pady=(10 if row else 0, 6)
            )
            row += 1
            in_area = [r for r in regions.REGIONS if r.area == area]
            for i, region in enumerate(in_area):
                card = RegionCard(panel, region, self.fonts, self.select)
                card.grid(row=row + i // CARD_COLUMNS, column=i % CARD_COLUMNS, sticky="ew", padx=4, pady=4)
                self.cards[region.code] = card
            row += -(-len(in_area) // CARD_COLUMNS)
        for col in range(CARD_COLUMNS):
            panel.columnconfigure(col, weight=1, uniform="cards")
        return panel

    def _build_footer(self, parent) -> tk.Frame:
        footer = tk.Frame(parent, bg=BG)
        footer.columnconfigure(3, weight=1)
        self.lock_btn = make_button(footer, "LOCK REGION", self.on_lock, self.fonts, primary=True)
        self.unlock_btn = make_button(footer, "Unlock all", self.on_unlock, self.fonts)
        self.best_btn = make_button(footer, "Pick best ping", self.pick_best, self.fonts)
        self.check_btn = make_button(footer, "Check", self.on_check, self.fonts)
        self.ping_btn = make_button(footer, "Refresh ping", self.refresh_ping, self.fonts)
        self.lock_btn.grid(row=0, column=0, sticky="w")
        self.unlock_btn.grid(row=0, column=1, padx=8)
        self.best_btn.grid(row=0, column=2)
        self.check_btn.grid(row=0, column=4, sticky="e", padx=(0, 8))
        self.ping_btn.grid(row=0, column=5, sticky="e")
        self.status = tk.Label(footer, font=self.fonts.body, bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=680)
        self.status.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(12, 0))
        return footer

    # State ---------------------------------------------------------------

    def _show_game(self):
        if sys.platform != "win32":
            self.game_label.config(text="Linux / Proton: GameLift beacons are blocked system-wide.", fg=TEXT)
        elif self.exe.get():
            self.game_label.config(text=elide(self.exe.get()), fg=TEXT)
        else:
            self.game_label.config(text="Not found. Click Change… and pick DeadByDaylight-*-Shipping.exe", fg=OK)

    def _show_lock(self):
        for code, card in self.cards.items():
            card.set_active(code == self.locked)
        if self.locked:
            self.pill.config(text=f"LOCKED · {regions.get(self.locked).city.upper()}", bg=ACCENT, fg=TEXT)
        elif self.lock_active:
            self.pill.config(text="LOCKED", bg=ACCENT, fg=TEXT)
        else:
            self.pill.config(text="UNLOCKED", bg=CARD, fg=GOOD)

    def select(self, code: str):
        if self.busy_now:
            return
        self.selected = code
        for c, card in self.cards.items():
            card.set_selected(c == code)
        self.lock_btn.config(text=f"LOCK TO {regions.get(code).city.upper()}")

    def set_busy(self, on: bool, message: str | None = None, colour: str = MUTED):
        self.busy_now = on
        self._update_buttons()
        if message is not None:
            self.status.config(text=message, fg=colour)

    def _update_buttons(self):
        changes_blocked = self.busy_now or self.game_running
        for btn in (self.lock_btn, self.unlock_btn):
            btn.config(state="disabled" if changes_blocked else "normal")
        self.best_btn.config(state="disabled" if self.busy_now else "normal")
        self.check_btn.config(state="disabled" if self.busy_now else "normal")

    def background(self, work, done, failed=None):
        """Run `work` off the UI thread, then `done(result)` on it; errors go to `failed` or are shown."""

        def runner():
            try:
                result = work()
            except Exception as exc:
                self.root.after(0, failed or self.on_error, exc)
                return
            self.root.after(0, done, result)

        threading.Thread(target=runner, daemon=True).start()

    # Events --------------------------------------------------------------

    def on_error(self, exc: Exception):
        self.set_busy(False, f"Error: {exc}", BAD)
        messagebox.showerror(TITLE, str(exc))

    def on_status(self, result: tuple[bool, str | None]):
        self.lock_active, self.locked = result
        self._show_lock()
        self.set_busy(False, "Locked. Pick another region to switch, or Unlock all." if self.lock_active
                      else "Close the game, pick a region, press Lock, then launch the game.")
        if self.locked:
            self.select(self.locked)
        if self.lock_active:
            self.refresh_ping()  # re-ping now that blocked regions can be labelled as such

    def browse(self):
        path = filedialog.askopenfilename(
            title="Select DeadByDaylight-*-Shipping.exe",
            filetypes=[("Dead by Daylight", "DeadByDaylight-*-Shipping.exe"), ("Programs", "*.exe")],
        )
        if path:
            self.exe.set(path.replace("/", "\\"))
            self._show_game()

    def refresh_ping(self):
        for card in self.cards.values():
            card.set_ping(None, pending=True)

        def ping(region):
            ms = resolver.measure_latency(region)
            self.pings[region.code] = ms
            blocked = ms is None and self.lock_active and self.locked not in (None, region.code)
            self.root.after(0, lambda: self.cards[region.code].set_ping(ms, blocked=blocked))

        for region in regions.REGIONS:
            threading.Thread(target=ping, args=(region,), daemon=True).start()

    def pick_best(self):
        measured = {code: ms for code, ms in self.pings.items() if ms is not None}
        if not measured:
            self.status.config(text="Still measuring ping, try again in a moment.", fg=MUTED)
            return
        self.select(min(measured, key=measured.get))

    def watch_game(self):
        """Poll for a running game and block region changes while it runs."""

        def done(running: bool):
            if running != self.game_running:
                self.game_running = running
                if running:
                    self.game_banner.grid(row=self.banner_row, column=0, sticky="ew", pady=(12, 0))
                else:
                    self.game_banner.grid_remove()
                self._update_buttons()
            self.root.after(GAME_CHECK_MS, self.watch_game)

        def failed(_exc):
            self.root.after(GAME_CHECK_MS, self.watch_game)

        self.background(detect.game_running, done, failed)

    def refresh_lock(self):
        """Every few minutes, block beacon IPs that changed (never while the game runs)."""

        def done(added: int):
            if added:
                self.status.config(text=f"Lock refreshed: blocked {added} new beacon address(es).", fg=MUTED)
            self.root.after(REFRESH_MS, self.refresh_lock)

        def failed(_exc):
            self.root.after(REFRESH_MS, self.refresh_lock)

        if self.lock_active and not self.game_running and not self.busy_now:
            self.background(core.refresh, done, failed)
        else:
            self.root.after(REFRESH_MS, self.refresh_lock)

    def on_lock(self):
        if not self.selected:
            self.status.config(text="Click a region card first.", fg=OK)
            return
        exe = "" if self.all_apps.get() else self.exe.get().strip()
        if sys.platform == "win32" and not self.all_apps.get() and not exe:
            self.status.config(text="Choose the game executable first (Change…), or tick 'Block for all apps'.", fg=OK)
            return
        code = self.selected
        self.set_busy(True, f"Locking to {regions.get(code).name}: finding every beacon address (can take up to 30 s)…")

        def done(notes):
            self.locked, self.lock_active = code, True
            self._show_lock()
            lines = [f"Locked to {regions.get(code).name}. Launch the game; you will only match in this region."]
            self.set_busy(False, "\n".join(lines + notes), GOOD)
            self.refresh_ping()

        self.background(lambda: core.lock(code, exe), done)

    def on_unlock(self):
        self.set_busy(True, "Removing lock…")

        def done(notes):
            self.locked, self.lock_active = None, False
            self._show_lock()
            self.set_busy(False, "\n".join(["Unlocked. The game can use every region again."] + notes), GOOD)
            self.refresh_ping()

        self.background(core.unlock, done)

    def on_check(self):
        self.set_busy(True, "Checking firewall, DNS and the block itself (about 30 s)…")

        def done(checks):
            self.set_busy(False, "Check finished.")
            CheckDialog(self.root, checks, self.fonts)

        self.background(diagnose.run, done)


class CheckDialog(tk.Toplevel):
    """Results of the self-check, colour-coded, with a button to copy them."""

    COLOURS = {diagnose.OK: GOOD, diagnose.WARN: OK, diagnose.FAIL: BAD, diagnose.INFO: MUTED}

    def __init__(self, master, checks: list[diagnose.Check], fonts: Fonts):
        super().__init__(master, bg=BG, padx=18, pady=16)
        self.title(f"{TITLE}: check")
        self.report = diagnose.report(checks)
        failed = sum(c.level == diagnose.FAIL for c in checks)
        summary = f"{failed} problem(s) found." if failed else "No problems found."
        tk.Label(self, text=summary, font=fonts.card_title, bg=BG, fg=BAD if failed else GOOD).pack(anchor="w")
        text = tk.Text(self, width=86, height=min(22, 3 + 2 * len(checks)), wrap="word", bg=PANEL, fg=TEXT,
                       font=fonts.body, relief="flat", padx=10, pady=8, highlightthickness=0)
        for level, colour in self.COLOURS.items():
            text.tag_configure(level, foreground=colour)
        for check in checks:
            text.insert("end", diagnose.SYMBOLS[check.level] + " ", check.level)
            text.insert("end", check.text + "\n\n")
        text.config(state="disabled")
        text.pack(fill="both", expand=True, pady=(10, 12))
        buttons = tk.Frame(self, bg=BG)
        buttons.pack(fill="x")
        make_button(buttons, "Copy report", self.copy, fonts).pack(side="left")
        make_button(buttons, "Close", self.destroy, fonts).pack(side="right")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(f"{TITLE} {__version__} check\n{self.report}")


def icon_path() -> Path:
    # PyInstaller unpacks bundled files to sys._MEIPASS; from source, use the repo's assets folder.
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / "assets" / "icon.ico"


def run():
    root = tk.Tk()
    if sys.platform == "win32" and icon_path().is_file():
        root.iconbitmap(default=str(icon_path()))
    App(root)
    root.mainloop()
