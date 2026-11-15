import ipaddress
import os
import queue
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import (
    END,
    Button,
    BooleanVar,
    Checkbutton,
    Entry,
    Frame,
    Label,
    LabelFrame,
    StringVar,
    Tk,
    filedialog,
    messagebox,
)
from tkinter.scrolledtext import ScrolledText

from modules.paths import get_reports_dir
from modules.event_levels import DEFAULT_EVENT_LEVELS, EVENT_LEVEL_NAMES


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
        self.cancellation_event = None
        self.collection_finished_event = threading.Event()
        self.output_segments = []
        self.current_output_level = None

        root.title("Windows Event Analyzer")
        root.geometry("1000x700")
        root.minsize(760, 520)

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

        self.stop_button = Button(
            toolbar,
            text="Stop Collection (Esc)",
            command=self.stop_collection,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=(0, 8))

        now = datetime.now().replace(microsecond=0)
        start_default = now - timedelta(hours=24)
        period_frame = Frame(root, padx=12)
        period_frame.pack(fill="x", pady=(0, 8))

        Label(
            period_frame,
            text="Start (local time):",
        ).pack(side="left")
        self.start_time = StringVar(
            value=start_default.strftime("%Y-%m-%d %H:%M:%S")
        )
        self.start_time_entry = Entry(
            period_frame,
            textvariable=self.start_time,
            width=19,
        )
        self.start_time_entry.pack(side="left", padx=(6, 12))

        Label(
            period_frame,
            text="End (local time):",
        ).pack(side="left")
        self.end_time = StringVar(
            value=now.strftime("%Y-%m-%d %H:%M:%S")
        )
        self.end_time_entry = Entry(
            period_frame,
            textvariable=self.end_time,
            width=19,
        )
        self.end_time_entry.pack(side="left", padx=6)

        levels_frame = LabelFrame(
            root,
            text="Levels to collect",
            padx=12,
            pady=6,
        )
        levels_frame.pack(fill="x", padx=12, pady=(0, 8))
        self.level_vars = {}
        self.level_checkbuttons = []
        for level, level_name in EVENT_LEVEL_NAMES.items():
            variable = BooleanVar(
                value=level in DEFAULT_EVENT_LEVELS
            )
            checkbutton = Checkbutton(
                levels_frame,
                text=level_name,
                variable=variable,
            )
            checkbutton.pack(side="left", padx=(0, 10))
            self.level_vars[level] = variable
            self.level_checkbuttons.append(checkbutton)

        remote_frame = LabelFrame(
            root,
            text="Remote System Log (optional)",
            padx=10,
            pady=6,
        )
        remote_frame.pack(fill="x", padx=12, pady=(0, 8))

        Label(remote_frame, text="Computer IP:").grid(
            row=0,
            column=0,
            sticky="w",
            padx=(0, 4),
        )
        self.remote_ip = StringVar()
        self.remote_ip_entry = Entry(
            remote_frame,
            textvariable=self.remote_ip,
            width=16,
        )
        self.remote_ip_entry.grid(row=0, column=1, padx=(0, 12))

        Label(remote_frame, text="Domain:").grid(
            row=0,
            column=2,
            sticky="w",
            padx=(0, 4),
        )
        self.remote_domain = StringVar()
        self.remote_domain_entry = Entry(
            remote_frame,
            textvariable=self.remote_domain,
            width=16,
        )
        self.remote_domain_entry.grid(row=0, column=3, padx=(0, 12))

        Label(remote_frame, text="Username:").grid(
            row=0,
            column=4,
            sticky="w",
            padx=(0, 4),
        )
        self.remote_username = StringVar()
        self.remote_username_entry = Entry(
            remote_frame,
            textvariable=self.remote_username,
            width=18,
        )
        self.remote_username_entry.grid(row=0, column=5, padx=(0, 12))

        Label(remote_frame, text="Password:").grid(
            row=0,
            column=6,
            sticky="w",
            padx=(0, 4),
        )
        self.remote_password = StringVar()
        self.remote_password_entry = Entry(
            remote_frame,
            textvariable=self.remote_password,
            width=18,
            show="*",
        )
        self.remote_password_entry.grid(row=0, column=7)

        Label(
            remote_frame,
            text=(
                "Use only on systems you are authorized to administer. "
                "Remote Event Log Management must be enabled. For a local "
                "account, leave Domain blank. For a domain account, enter "
                "the domain name or use a UPN."
            ),
            anchor="w",
            justify="left",
            wraplength=940,
        ).grid(
            row=1,
            column=0,
            columnspan=8,
            sticky="w",
            pady=(6, 0),
        )

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

        result_levels_frame = LabelFrame(
            root,
            text="Show in results",
            padx=12,
            pady=4,
        )
        result_levels_frame.pack(fill="x", padx=12, pady=(0, 8))
        self.result_level_vars = {}
        self.result_level_checkbuttons = []
        for level, level_name in EVENT_LEVEL_NAMES.items():
            variable = BooleanVar(value=True)
            checkbutton = Checkbutton(
                result_levels_frame,
                text=level_name,
                variable=variable,
                command=self.render_output,
            )
            checkbutton.pack(side="left", padx=(0, 10))
            self.result_level_vars[level] = variable
            self.result_level_checkbuttons.append(checkbutton)

        self.output = ScrolledText(
            root,
            wrap="word",
            state="disabled",
            padx=10,
            pady=8,
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        root.bind("<Escape>", self.stop_collection)
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

        try:
            start_time = datetime.strptime(
                self.start_time.get().strip(),
                "%Y-%m-%d %H:%M:%S",
            ).astimezone()
            end_time = datetime.strptime(
                self.end_time.get().strip(),
                "%Y-%m-%d %H:%M:%S",
            ).astimezone()
        except ValueError:
            messagebox.showerror(
                "Invalid time range",
                "Enter start and end times as YYYY-MM-DD HH:MM:SS "
                "using local time.",
                parent=self.root,
            )
            return

        if start_time > end_time:
            messagebox.showerror(
                "Invalid time range",
                "The start time must be earlier than or equal to the end time.",
                parent=self.root,
            )
            return

        selected_levels = tuple(
            level
            for level, variable in self.level_vars.items()
            if variable.get()
        )
        if not selected_levels:
            messagebox.showerror(
                "No event levels selected",
                "Select at least one event level to analyze.",
                parent=self.root,
            )
            return

        remote_ip = self.remote_ip.get().strip()
        remote_username = self.remote_username.get().strip()
        remote_domain = self.remote_domain.get().strip()
        remote_password = self.remote_password.get()
        remote_fields = (
            remote_ip,
            remote_username,
            remote_domain,
            remote_password,
        )
        remote_options = None

        if evtx_file is not None and any(remote_fields):
            messagebox.showerror(
                "Remote options not applicable",
                "Clear the remote computer and credential fields to analyze "
                "an EVTX file.",
                parent=self.root,
            )
            return

        if remote_ip:
            try:
                remote_ip = str(ipaddress.ip_address(remote_ip))
            except ValueError:
                messagebox.showerror(
                    "Invalid computer IP",
                    "Enter a valid IPv4 or IPv6 address.",
                    parent=self.root,
                )
                return

            if not remote_username or not remote_password:
                messagebox.showerror(
                    "Remote credentials required",
                    "Enter a username and password for the remote computer.",
                    parent=self.root,
                )
                return

            remote_options = {
                "computer": remote_ip,
                "username": remote_username,
                "domain": remote_domain or None,
                "password": remote_password,
            }
        elif any(remote_fields):
            messagebox.showerror(
                "Remote computer required",
                "Enter a computer IP when using remote credentials.",
                parent=self.root,
            )
            return

        self.running = True
        self.cancellation_event = threading.Event()
        self.collection_finished_event.clear()
        self.set_buttons_enabled(False)
        self.status.set("Collecting events...")
        self.output_segments = []
        self.current_output_level = None
        for variable in self.result_level_vars.values():
            variable.set(True)
        self.output.configure(state="normal")
        self.output.delete("1.0", END)
        self.output.configure(state="disabled")

        worker = threading.Thread(
            target=self.run_analysis,
            args=(
                evtx_file,
                start_time,
                end_time,
                selected_levels,
                remote_options,
                self.cancellation_event,
            ),
            daemon=True,
        )
        self.remote_password.set("")
        worker.start()

    def run_analysis(
        self,
        evtx_file,
        start_time,
        end_time,
        selected_levels,
        remote_options,
        cancellation_event
    ):
        writer = _QueueWriter(self.output_queue)

        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                self.analyze(
                    evtx_file,
                    start_time,
                    end_time,
                    selected_levels=selected_levels,
                    remote_options=remote_options,
                    cancellation_event=cancellation_event,
                    result_level_callback=lambda level: (
                        self.output_queue.put(("event_level", level))
                    ),
                    collection_finished_callback=(
                        self.signal_collection_finished
                    ),
                )
        except Exception:
            self.output_queue.put(("event_level", None))
            self.signal_collection_finished()
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

            self.output_queue.put(("finished", "failed"))
        else:
            result = (
                "cancelled"
                if cancellation_event.is_set()
                else "success"
            )
            self.output_queue.put(("finished", result))

    def poll_output(self):
        while True:
            try:
                message_type, value = self.output_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "output":
                self.output_segments.append(
                    (self.current_output_level, value)
                )
                if self.is_output_level_visible(self.current_output_level):
                    self.output.configure(state="normal")
                    self.output.insert(END, value)
                    self.output.see(END)
                    self.output.configure(state="disabled")
            elif message_type == "event_level":
                self.current_output_level = value
            elif message_type == "collection_finished":
                self.stop_button.configure(state="disabled")
                if (
                    self.cancellation_event is not None
                    and not self.cancellation_event.is_set()
                ):
                    self.status.set("Processing collected events...")
            elif message_type == "finished":
                self.running = False
                self.set_buttons_enabled(True)
                self.current_output_level = None
                if value == "success":
                    self.status.set(
                        f"Analysis complete. Reports: {get_reports_dir()}"
                    )
                elif value == "cancelled":
                    self.status.set(
                        "Collection stopped. Partial results were discarded."
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

    def is_output_level_visible(self, level):
        return (
            level is None
            or self.result_level_vars[level].get()
        )

    def render_output(self):
        visible_output = "".join(
            text
            for level, text in self.output_segments
            if self.is_output_level_visible(level)
        )
        self.output.configure(state="normal")
        self.output.delete("1.0", END)
        self.output.insert(END, visible_output)
        self.output.see(END)
        self.output.configure(state="disabled")

    def stop_collection(self, event=None):
        if event is not None and event.keysym != "Escape":
            return

        if (
            not self.running
            or self.cancellation_event is None
            or self.collection_finished_event.is_set()
        ):
            return

        self.cancellation_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("Stopping collection...")

    def signal_collection_finished(self):
        self.collection_finished_event.set()
        self.output_queue.put(("collection_finished", None))

    def set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        self.live_button.configure(state=state)
        self.evtx_button.configure(state=state)
        self.stop_button.configure(state="disabled" if enabled else "normal")
        self.start_time_entry.configure(state=state)
        self.end_time_entry.configure(state=state)
        for checkbutton in self.level_checkbuttons:
            checkbutton.configure(state=state)
        for checkbutton in self.result_level_checkbuttons:
            checkbutton.configure(state=state)
        self.remote_ip_entry.configure(state=state)
        self.remote_domain_entry.configure(state=state)
        self.remote_username_entry.configure(state=state)
        self.remote_password_entry.configure(state=state)
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
