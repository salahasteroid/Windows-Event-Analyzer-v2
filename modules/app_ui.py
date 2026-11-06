import os
import queue
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tkinter import (
    END,
    Button,
    Frame,
    Label,
    StringVar,
    Tk,
    filedialog,
    messagebox,
)
from tkinter.scrolledtext import ScrolledText

from modules.paths import get_reports_dir


class _QueueWriter:

    def __init__(self, output_queue):
        self.output_queue = output_queue

    def write(self, text):
        if text:
            self.output_queue.put(("output", text))
        return len(text)

    def flush(self):
        pass


class EventAnalyzerApp:

    def __init__(self, root, analyze, initial_evtx=None):
        self.root = root
        self.analyze = analyze
        self.output_queue = queue.Queue()
        self.running = False

        root.title("Windows Event Analyzer")
        root.geometry("800x560")
        root.minsize(620, 400)

        toolbar = Frame(root, padx=12, pady=12)
        toolbar.pack(fill="x")

        self.live_button = Button(
            toolbar,
            text="Analyze Windows System Log",
            command=lambda: self.start_analysis(None),
        )
        self.live_button.pack(side="left", padx=(0, 8))

        self.evtx_button = Button(
            toolbar,
            text="Open EVTX File...",
            command=self.select_evtx_file,
        )
        self.evtx_button.pack(side="left", padx=(0, 8))

        self.reports_button = Button(
            toolbar,
            text="Open Reports Folder",
            command=self.open_reports_folder,
        )
        self.reports_button.pack(side="left", padx=(0, 8))

        self.dashboard_button = Button(
            toolbar,
            text="Open Dashboard",
            command=self.open_dashboard,
        )
        self.dashboard_button.pack(side="left")

        self.status = StringVar(value="Ready. Choose an analysis option.")
        status_label = Label(
            root,
            textvariable=self.status,
            anchor="w",
            padx=12,
        )
        status_label.pack(fill="x", pady=(0, 8))

        self.output = ScrolledText(
            root,
            wrap="word",
            state="disabled",
            padx=10,
            pady=8,
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.root.after(100, self.poll_output)

        if initial_evtx:
            self.root.after(
                250,
                self.start_analysis,
                Path(initial_evtx),
            )

    def select_evtx_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a Windows Event Log file",
            filetypes=[
                ("Windows Event Log files", "*.evtx"),
                ("All files", "*.*"),
            ],
        )

        if file_path:
            self.start_analysis(Path(file_path))

    def start_analysis(self, evtx_file):
        if self.running:
            return

        if evtx_file is not None and not evtx_file.is_file():
            messagebox.showerror(
                "File not found",
                f"The selected EVTX file does not exist:\n{evtx_file}",
                parent=self.root,
            )
            return

        self.running = True
        self.set_buttons_enabled(False)
        self.status.set("Analyzing events...")
        self.output.configure(state="normal")
        self.output.delete("1.0", END)
        self.output.configure(state="disabled")

        worker = threading.Thread(
            target=self.run_analysis,
            args=(evtx_file,),
            daemon=True,
        )
        worker.start()

    def run_analysis(self, evtx_file):
        writer = _QueueWriter(self.output_queue)

        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                self.analyze(evtx_file)
        except Exception:
            error_details = traceback.format_exc()
            self.output_queue.put(("output", error_details))

            try:
                reports_dir = get_reports_dir()
                reports_dir.mkdir(parents=True, exist_ok=True)
                error_path = reports_dir / "error.log"
                error_path.write_text(error_details, encoding="utf-8")
                self.output_queue.put(
                    ("output", f"\nError details saved to {error_path}\n")
                )
            except OSError as log_error:
                self.output_queue.put(
                    ("output", f"\nCould not save error log: {log_error}\n")
                )

            self.output_queue.put(("finished", False))
        else:
            self.output_queue.put(("finished", True))

    def poll_output(self):
        while True:
            try:
                message_type, value = self.output_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "output":
                self.output.configure(state="normal")
                self.output.insert(END, value)
                self.output.see(END)
                self.output.configure(state="disabled")
            elif message_type == "finished":
                self.running = False
                self.set_buttons_enabled(True)
                if value:
                    self.status.set(
                        f"Analysis complete. Reports: {get_reports_dir()}"
                    )
                else:
                    self.status.set(
                        "Analysis failed. See the error details below."
                    )
                    messagebox.showerror(
                        "Analysis failed",
                        "Event analysis failed. Details are shown in the "
                        "output and saved to reports\\error.log when possible.",
                        parent=self.root,
                    )

        self.root.after(100, self.poll_output)

    def set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        self.live_button.configure(state=state)
        self.evtx_button.configure(state=state)
        self.reports_button.configure(state=state)
        self.dashboard_button.configure(state=state)

    def open_reports_folder(self):
        reports_dir = get_reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(reports_dir))
        except OSError as error:
            messagebox.showerror(
                "Could not open reports folder",
                str(error),
                parent=self.root,
            )

    def open_dashboard(self):
        dashboard_path = get_reports_dir() / "dashboard.html"

        if not dashboard_path.is_file():
            messagebox.showinfo(
                "Dashboard not generated",
                "Run an analysis first to generate the dashboard.",
                parent=self.root,
            )
            return

        try:
            os.startfile(str(dashboard_path))
        except OSError as error:
            messagebox.showerror(
                "Could not open dashboard",
                str(error),
                parent=self.root,
            )


def run_app(analyze, initial_evtx=None):
    root = Tk()
    EventAnalyzerApp(root, analyze, initial_evtx)
    root.mainloop()
