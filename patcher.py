import argparse
from datetime import datetime
from pathlib import Path
import queue
import sys
import threading

from engine import VERSION, patch
from static_container import ContainerError


def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    root = tk.Tk()
    root.title(f"FH6 Offline Patcher {VERSION}")
    root.geometry("760x510")
    root.minsize(640, 460)
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="FH6 Offline Patcher", font=("Segoe UI", 19, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Create a patched EXE from your original game files.").pack(anchor="w", pady=(4, 16))
    variables = {name: tk.StringVar() for name in ("exe", "game", "out")}
    controls, events, cancel = [], queue.Queue(), threading.Event()
    working = False

    def browse(key):
        if key == "exe":
            value = filedialog.askopenfilename(title="Select a clean FH6 EXE", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
            if value:
                path = Path(value)
                variables["exe"].set(value)
                variables["game"].set(str(path.parent))
                variables["out"].set(str(path.parent / ("FH6-patched-" + datetime.now().strftime("%Y%m%d-%H%M%S"))))
        else:
            value = filedialog.askdirectory(title="Select original game folder" if key == "game" else "Select the parent for a new output folder")
            if value:
                variables[key].set(value if key == "game" else str(Path(value) / ("FH6-patched-" + datetime.now().strftime("%Y%m%d-%H%M%S"))))

    for key, label in (("exe", "Original EXE"), ("game", "Original game folder"), ("out", "New output folder")):
        ttk.Label(frame, text=label).pack(anchor="w")
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(3, 10))
        entry = ttk.Entry(row, textvariable=variables[key])
        entry.pack(side="left", fill="x", expand=True)
        button = ttk.Button(row, text="Browse…", command=lambda k=key: browse(k))
        button.pack(side="right", padx=(8, 0))
        controls.extend((entry, button))
    ttk.Label(frame, text="Supported patterns are discovered and checked in your files. Changed or\nambiguous patterns are refused. Newer builds have not yet been game-tested.").pack(anchor="w", pady=(0, 12))
    status = tk.StringVar(value="Select a clean EXE to begin.")
    ttk.Label(frame, textvariable=status, wraplength=700).pack(anchor="w", fill="x", pady=(0, 8))
    bar = ttk.Progressbar(frame, mode="indeterminate")
    bar.pack(fill="x")
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=(16, 0))

    def start():
        nonlocal working
        values = {key: value.get().strip() for key, value in variables.items()}
        if not all(values.values()):
            messagebox.showerror("Select files", "Select the original EXE, game folder, and a new output folder.", parent=root)
            return
        working = True
        cancel.clear()
        for control in controls:
            control.configure(state="disabled")
        start_button.configure(state="disabled")
        cancel_button.configure(state="normal")
        bar.start(12)

        def progress(message):
            if cancel.is_set():
                raise ContainerError("Cancelled before output publication")
            events.put(("progress", message))

        def run():
            try:
                report = patch(values["exe"], values["game"], values["out"], progress)
                events.put(("done", f"Created {report['action_count']} verified patches.\n{Path(values['out']).absolute() / 'forzahorizon6.exe'}"))
            except Exception as error:
                events.put(("error", str(error)))
        threading.Thread(target=run, daemon=False).start()

    start_button = ttk.Button(row, text="Create patched EXE", command=start)
    start_button.pack(side="left")
    cancel_button = ttk.Button(row, text="Cancel", command=cancel.set, state="disabled")
    cancel_button.pack(side="left", padx=(8, 0))

    def poll():
        nonlocal working
        try:
            while True:
                kind, message = events.get_nowait()
                status.set(message)
                if kind != "progress":
                    working = False
                    bar.stop()
                    for control in controls:
                        control.configure(state="normal")
                    start_button.configure(state="normal")
                    cancel_button.configure(state="disabled")
                    if kind == "error":
                        messagebox.showerror("Patch not created", message, parent=root)
        except queue.Empty:
            pass
        root.after(100, poll)

    def close():
        if working:
            cancel.set()
            status.set("Cancelling. The current validation step must finish before closing.")
        else:
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", close)
    poll()
    root.mainloop()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='Create an offline patched FH6 EXE from original game files.')
    parser.add_argument("exe", type=Path, nargs="?", help="Original FH6 EXE")
    parser.add_argument("--game-dir", type=Path, help="Directory containing matching original support files (default: EXE folder)")
    parser.add_argument("--out-dir", type=Path, help="New output directory; existing paths are never overwritten")
    parser.add_argument("--gui", action="store_true", help="Open the file-selection window")
    parser.add_argument("--version", action="version", version=f"FH6 Offline Patcher {VERSION}")
    args = parser.parse_args(argv)
    if args.gui or (args.exe is None and args.game_dir is None and args.out_dir is None):
        return gui()
    if args.exe is None or args.out_dir is None:
        parser.error("EXE and --out-dir are required in command-line mode")
    try:
        report = patch(args.exe, args.game_dir or args.exe.parent, args.out_dir,
                       lambda message: print(message, flush=True))
        print(f"Created: {args.out_dir.absolute() / 'forzahorizon6.exe'}")
        print(f"Verified patches: {report['action_count']}\nSHA256: {report['output_sha256']}")
        return 0
    except (ContainerError, OSError, ValueError, KeyError) as error:
        print(f"Patch refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
