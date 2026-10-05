"""Tkinter desktop app."""

from __future__ import annotations

import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__, core, detect, regions, resolver


class App(ttk.Frame):
    def __init__(self, root: tk.Tk):
        super().__init__(root, padding=12)
        self.root = root
        root.title(f"DBD Region Lock {__version__}")
        root.minsize(560, 520)
        self.grid(sticky="nsew")
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # Game executable (Windows only: rules are scoped to it).
        self.exe_var = tk.StringVar(value=str(detect.find_dbd_exe() or ""))
        if sys.platform == "win32":
            exe_box = ttk.LabelFrame(self, text="Dead by Daylight executable", padding=8)
            exe_box.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            exe_box.columnconfigure(0, weight=1)
            ttk.Entry(exe_box, textvariable=self.exe_var).grid(row=0, column=0, sticky="ew")
            ttk.Button(exe_box, text="Browse…", command=self.browse).grid(row=0, column=1, padx=(6, 0))
            if not self.exe_var.get():
                ttk.Label(
                    exe_box,
                    text="Not found automatically. Pick DeadByDaylight-*-Shipping.exe "
                    "(…\\DeadByDaylight\\Binaries\\Win64).",
                    foreground="#b45309",
                    wraplength=500,
                ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # Region list with live latency.
        box = ttk.LabelFrame(self, text="Pick the region to play in", padding=8)
        box.grid(row=1, column=0, sticky="nsew")
        self.rowconfigure(1, weight=1)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(box, columns=("name", "ping"), show="headings", selectmode="browse", height=15)
        self.tree.heading("name", text="Region")
        self.tree.heading("ping", text="Ping")
        self.tree.column("name", width=360)
        self.tree.column("ping", width=90, anchor="e")
        for r in regions.REGIONS:
            self.tree.insert("", "end", iid=r.code, values=(f"{r.name}  [{r.code}]", "…"))
        self.tree.grid(row=0, column=0, sticky="nsew")

        buttons = ttk.Frame(self)
        buttons.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.lock_btn = ttk.Button(buttons, text="Lock to selected region", command=self.on_lock)
        self.unlock_btn = ttk.Button(buttons, text="Unlock (all regions)", command=self.on_unlock)
        self.ping_btn = ttk.Button(buttons, text="Refresh ping", command=self.refresh_ping)
        self.lock_btn.pack(side="left")
        self.unlock_btn.pack(side="left", padx=6)
        self.ping_btn.pack(side="right")

        self.status_var = tk.StringVar(value="Checking firewall…")
        ttk.Label(self, textvariable=self.status_var, wraplength=530).grid(row=3, column=0, sticky="w", pady=(10, 0))

        self.refresh_ping()
        self.background(core.status, self.show_status)

    # Helpers -------------------------------------------------------------

    def background(self, work, done=None):
        """Run `work` off the UI thread, then `done(result)` or show the error on it."""

        def runner():
            try:
                result = work()
            except Exception as exc:  # surfaced to the user, not swallowed
                self.root.after(0, self.fail, exc)
                return
            if done:
                self.root.after(0, done, result)

        threading.Thread(target=runner, daemon=True).start()

    def busy(self, on: bool):
        for btn in (self.lock_btn, self.unlock_btn):
            btn.state(["disabled"] if on else ["!disabled"])

    def fail(self, exc: Exception):
        self.busy(False)
        self.status_var.set(f"Error: {exc}")
        messagebox.showerror("DBD Region Lock", str(exc))

    def show_status(self, blocked: list[str]):
        self.busy(False)
        if not blocked:
            self.status_var.set("Not locked: the game can use every region.")
            return
        kept = [r.code for r in regions.REGIONS if r.code not in blocked]
        if sys.platform == "win32" and len(kept) == 1:
            self.status_var.set(f"Locked to {regions.get(kept[0]).name} [{kept[0]}].")
            self.tree.selection_set(kept[0])
        else:
            self.status_var.set("A region lock is active.")

    # Actions -------------------------------------------------------------

    def browse(self):
        path = filedialog.askopenfilename(
            title="Select DeadByDaylight-*-Shipping.exe",
            filetypes=[("Dead by Daylight", "DeadByDaylight-*-Shipping.exe"), ("Executables", "*.exe")],
        )
        if path:
            self.exe_var.set(path.replace("/", "\\"))

    def refresh_ping(self):
        for r in regions.REGIONS:
            self.tree.set(r.code, "ping", "…")

        def ping(region):
            ms = resolver.measure_latency(region)
            text = f"{ms:.0f} ms" if ms is not None else "blocked / n/a"
            self.root.after(0, self.tree.set, region.code, "ping", text)

        for r in regions.REGIONS:
            threading.Thread(target=ping, args=(r,), daemon=True).start()

    def on_lock(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("DBD Region Lock", "Select a region first.")
            return
        code = selection[0]
        exe = self.exe_var.get().strip()
        if sys.platform == "win32" and not exe:
            messagebox.showwarning("DBD Region Lock", "Choose the Dead by Daylight executable first.")
            return
        self.busy(True)
        self.status_var.set(f"Locking to {code}…")

        def done(warnings):
            self.busy(False)
            msg = f"Locked to {regions.get(code).name} [{code}]. Restart the game if it is running."
            if warnings:
                msg += "\n" + "\n".join(warnings)
            self.status_var.set(msg)

        self.background(lambda: core.lock(code, exe), done)

    def on_unlock(self):
        self.busy(True)
        self.status_var.set("Removing lock…")

        def done(_):
            self.busy(False)
            self.status_var.set("Not locked: the game can use every region. Restart the game if it is running.")

        self.background(core.unlock, done)


def run():
    root = tk.Tk()
    App(root)
    root.mainloop()
