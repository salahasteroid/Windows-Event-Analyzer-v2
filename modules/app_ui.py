import os
import queue
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
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

from modules.event_channels import SUPPORTED_LOGS
from modules.paths import get_reports_dir
from modules.remote_check import check_remote_connection
from modules.remote_summary import generate_remote_summary
from modules.version import __version__
from modules.event_levels import DEFAULT_EVENT_LEVELS, EVENT_LEVEL_NAMES
from modules.event_reader import get_recent_events
from modules.remote_settings import (
    forget_remote_settings,
    load_remote_settings,
    save_remote_settings,
)
from modules.remote_targets import (
    MAX_PARALLEL_REMOTE_TARGETS,
    parse_remote_targets,
    remote_report_dir,
)


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
        self.preferred_dashboard_path = None

        try:
            remote_settings = load_remote_settings()
            remote_settings_error = None
        except (OSError, ValueError) as error:
            remote_settings = {
                "targets": [],
                "domain": "",
                "remember_targets": True,
                "remember_domain": True,
            }
            remote_settings_error = str(error)

        root.title(f"Windows Event Analyzer {__version__}")
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

        self.remote_button = Button(
            toolbar,
            text="Analyze Remote PCs",
            command=lambda: self.start_analysis(
                None,
                remote_mode=True,
            ),
        )
        self.remote_button.pack(side="left", padx=(0, 8))

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

        logs_frame = LabelFrame(
            root,
            text=(
                "Logs to analyze (Security needs administrator rights and "
                "ignores the level selection)"
            ),
            padx=12,
            pady=6,
        )
        logs_frame.pack(fill="x", padx=12, pady=(0, 8))
        self.log_vars = {}
        self.log_checkbuttons = []
        for log_name in SUPPORTED_LOGS:
            variable = BooleanVar(value=log_name == "System")
            checkbutton = Checkbutton(
                logs_frame,
                text=log_name,
                variable=variable,
            )
            checkbutton.pack(side="left", padx=(0, 10))
            self.log_vars[log_name] = variable
            self.log_checkbuttons.append(checkbutton)
        self.selected_logs = ("System",)

        remote_frame = LabelFrame(
            root,
            text="Remote System Log (optional)",
            padx=10,
            pady=6,
        )
        remote_frame.pack(fill="x", padx=12, pady=(0, 8))

        Label(remote_frame, text="Computer IPs (one per line):").grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(0, 4),
        )
        self.remote_targets = ScrolledText(
            remote_frame,
            width=34,
            height=4,
            wrap="word",
        )
        self.remote_targets.grid(
            row=1,
            column=0,
            columnspan=2,
            rowspan=3,
            sticky="nsew",
            padx=(0, 16),
        )
        if remote_settings["targets"]:
            self.remote_targets.insert(
                "1.0",
                "\n".join(remote_settings["targets"]),
            )

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
            width=24,
        )
        self.remote_domain_entry.grid(
            row=0,
            column=3,
            sticky="ew",
            padx=(0, 12),
        )
        self.remote_domain.set(remote_settings["domain"])

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
            width=20,
        )
        self.remote_username_entry.grid(
            row=0,
            column=5,
            sticky="ew",
            padx=(0, 12),
        )

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
            width=20,
            show="*",
        )
        self.remote_password_entry.grid(
            row=0,
            column=7,
            sticky="ew",
        )

        self.remember_targets = BooleanVar(
            value=remote_settings["remember_targets"]
        )
        self.remember_targets_checkbutton = Checkbutton(
            remote_frame,
            text="Remember IP list",
            variable=self.remember_targets,
        )
        self.remember_targets_checkbutton.grid(
            row=4,
            column=0,
            sticky="w",
            pady=(6, 0),
        )

        self.remember_domain = BooleanVar(
            value=remote_settings["remember_domain"]
        )
        self.remember_domain_checkbutton = Checkbutton(
            remote_frame,
            text="Remember domain",
            variable=self.remember_domain,
        )
        self.remember_domain_checkbutton.grid(
            row=4,
            column=1,
            sticky="w",
            pady=(6, 0),
        )

        self.forget_remote_button = Button(
            remote_frame,
            text="Forget saved IPs/domain",
            command=self.forget_saved_remote_values,
        )
        self.forget_remote_button.grid(
            row=4,
            column=2,
            columnspan=2,
            sticky="w",
            pady=(6, 0),
        )

        self.test_remote_button = Button(
            remote_frame,
            text="Test connection",
            command=self.test_remote_connection,
        )
        self.test_remote_button.grid(
            row=4,
            column=4,
            columnspan=2,
            sticky="w",
            pady=(6, 0),
        )

        Label(
            remote_frame,
            text=(
                "Use only on systems you are authorized to administer. "
                "Remote Event Log Management must be enabled. Enter IPs "
                "separated by new lines, commas, or semicolons. Collections "
                f"run in parallel (up to {MAX_PARALLEL_REMOTE_TARGETS} PCs). "
                "Credentials are shared for this run and passwords are "
                "never saved. Leave Domain blank for local accounts."
            ),
            anchor="w",
            justify="left",
            wraplength=940,
        ).grid(
            row=5,
            column=0,
            columnspan=8,
            sticky="w",
            pady=(6, 0),
        )
        remote_frame.columnconfigure(1, weight=1)
        remote_frame.columnconfigure(3, weight=1)
        remote_frame.columnconfigure(5, weight=1)
        remote_frame.columnconfigure(7, weight=1)

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

        root.bind_all("<Escape>", self.stop_collection, add="+")
        self.root.after(100, self.poll_output)

        if initial_evtx:
            self.root.after(
                250,
                self.start_analysis,
                Path(initial_evtx),
            )

        if remote_settings_error:
            self.root.after(
                100,
                lambda: messagebox.showerror(
                    "Could not load saved remote settings",
                    remote_settings_error,
                    parent=self.root,
                ),
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

    def start_analysis(self, evtx_file, remote_mode=False):
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

        selected_logs = tuple(
            name
            for name, variable in self.log_vars.items()
            if variable.get()
        )
        if not selected_logs:
            messagebox.showerror(
                "No log selected",
                "Select at least one log to analyze.",
                parent=self.root,
            )
            return
        self.selected_logs = selected_logs

        remote_username = self.remote_username.get().strip()
        remote_domain = self.remote_domain.get().strip()
        remote_password = self.remote_password.get()
        remote_targets = []
        remote_options = None

        if remote_mode:
            try:
                remote_targets = parse_remote_targets(
                    self.remote_targets.get("1.0", "end")
                )
            except ValueError as error:
                messagebox.showerror(
                    "Invalid remote target list",
                    str(error),
                    parent=self.root,
                )
                return

            if not remote_targets:
                messagebox.showerror(
                    "Remote targets required",
                    "Enter one or more authorized computer IP addresses.",
                    parent=self.root,
                )
                return

            if not remote_username or not remote_password:
                messagebox.showerror(
                    "Remote credentials required",
                    "Enter a username and password for the remote computers.",
                    parent=self.root,
                )
                return

            remote_options = {
                "username": remote_username,
                "domain": remote_domain or None,
                "password": remote_password,
            }

            try:
                save_remote_settings(
                    remote_targets,
                    remote_domain,
                    self.remember_targets.get(),
                    self.remember_domain.get(),
                )
            except OSError as error:
                messagebox.showerror(
                    "Could not save remote preferences",
                    str(error),
                    parent=self.root,
                )
                return

        self.running = True
        self.cancellation_event = threading.Event()
        self.collection_finished_event.clear()
        self.set_buttons_enabled(False)
        if remote_targets:
            self.status.set(
                f"Collecting events from {len(remote_targets)} remote PC(s)..."
            )
        else:
            self.status.set("Collecting events...")
        self.output_segments = []
        self.current_output_level = None
        self.preferred_dashboard_path = None
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
                remote_targets,
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
        remote_targets,
        cancellation_event
    ):
        writer = _QueueWriter(self.output_queue)

        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                if remote_targets:
                    self.run_remote_analysis(
                        start_time,
                        end_time,
                        selected_levels,
                        remote_options,
                        remote_targets,
                        cancellation_event,
                    )
                    return

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
                    logs=self._logs(),
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

    def run_remote_analysis(
        self,
        start_time,
        end_time,
        selected_levels,
        remote_options,
        remote_targets,
        cancellation_event,
    ):
        collected_events = {}
        failures = []
        worker_count = min(
            MAX_PARALLEL_REMOTE_TARGETS,
            len(remote_targets),
        )

        print(
            f"Collecting from {len(remote_targets)} remote PC(s) "
            f"with up to {worker_count} concurrent connections."
        )

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    self._collect_logs,
                    target,
                    start_time,
                    end_time,
                    selected_levels,
                    remote_options,
                    cancellation_event,
                ): target
                for target in remote_targets
            }

            for future in as_completed(futures):
                target = futures[future]
                try:
                    collected_events[target] = future.result()
                    print(
                        f"Collected {len(collected_events[target])} event(s) "
                        f"from {target}."
                    )
                except Exception as error:
                    failures.append(target)
                    print(
                        f"Collection failed for {target}: {error}"
                    )

        self.signal_collection_finished()

        if cancellation_event.is_set():
            print(
                "\nCollection stopped. Partial results were discarded; "
                "no reports were generated."
            )
            self.output_queue.put(("finished", "cancelled"))
            return

        if not collected_events:
            self.output_queue.put(("finished", "failed"))
            return

        successful_hosts = 0
        reports_root = get_reports_dir()
        host_results = []

        for target in remote_targets:
            if target not in collected_events:
                continue
            if cancellation_event.is_set():
                break

            host_reports = remote_report_dir(reports_root, target)
            host_options = {
                **remote_options,
                "computer": target,
            }
            print(
                "\n"
                + "=" * 80
                + f"\nAnalyzing collected events from {target}\n"
            )

            try:
                host_summary = self.analyze(
                    None,
                    start_time,
                    end_time,
                    selected_levels=selected_levels,
                    remote_options=host_options,
                    cancellation_event=cancellation_event,
                    result_level_callback=lambda level: (
                        self.output_queue.put(("event_level", level))
                    ),
                    collected_events=collected_events[target],
                    output_dir=host_reports,
                    logs=self._logs(),
                )
            except Exception as error:
                host_results.append(
                    {"computer": target, "summary": None, "error": str(error)}
                )
                failures.append(target)
                print(
                    f"Analysis failed for {target}: {error}\n"
                    f"{traceback.format_exc()}"
                )
                continue

            successful_hosts += 1
            if isinstance(host_summary, dict):
                host_results.append(
                    {"computer": target, "summary": host_summary,
                     "error": None}
                )
            self.output_queue.put(
                ("dashboard", str(host_reports / "dashboard.html"))
            )

        if host_results and len(remote_targets) > 1:
            try:
                page = generate_remote_summary(
                    host_results, reports_root / "remote"
                )
                print(f"\nComparison of all computers: {page}")
            except OSError as error:
                print(f"\nCould not write the comparison page: {error}")

        if cancellation_event.is_set():
            result = "cancelled"
        elif successful_hosts == 0:
            result = "failed"
        elif failures:
            result = "partial"
        else:
            result = "success"

        self.output_queue.put(("finished", result))

    def _logs(self):
        return self.__dict__.get("selected_logs", ("System",))

    def _collect_logs(
        self,
        target,
        start_time,
        end_time,
        selected_levels,
        remote_options,
        cancellation_event,
    ):
        """Events of every selected log from one remote computer."""

        events = []

        for log_name in self._logs():
            kwargs = {}
            if log_name != "System":
                kwargs["log_name"] = log_name
            events.extend(
                get_recent_events(
                    start_time=start_time,
                    end_time=end_time,
                    levels=selected_levels,
                    remote_options={**remote_options, "computer": target},
                    cancellation_event=cancellation_event,
                    **kwargs,
                )
            )

        return events

    def test_remote_connection(self):
        """Try the first target with the typed credentials."""

        try:
            targets = parse_remote_targets(
                self.remote_targets.get("1.0", "end")
            )
        except ValueError as error:
            messagebox.showerror(
                "Invalid remote target list", str(error), parent=self.root
            )
            return

        if not targets:
            messagebox.showerror(
                "Remote targets required",
                "Enter a computer IP address to test.",
                parent=self.root,
            )
            return

        options = {
            "computer": targets[0],
            "username": self.remote_username.get().strip(),
            "domain": self.remote_domain.get().strip() or None,
            "password": self.remote_password.get(),
        }
        self.status.set(f"Testing connection to {targets[0]}...")

        def work():
            ok, message = check_remote_connection(options)
            self.root.after(0, lambda: self._show_connection_result(ok, message))

        threading.Thread(target=work, daemon=True).start()

    def _show_connection_result(self, ok, message):
        self.status.set("Ready")
        (messagebox.showinfo if ok else messagebox.showerror)(
            "Connection test", message, parent=self.root
        )

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
                if (
                    self.cancellation_event is not None
                    and not self.cancellation_event.is_set()
                ):
                    self.status.set("Processing collected events...")
            elif message_type == "dashboard":
                self.preferred_dashboard_path = Path(value)
            elif message_type == "finished":
                self.running = False
                self.set_buttons_enabled(True)
                self.current_output_level = None
                if value == "success":
                    if self.preferred_dashboard_path is not None:
                        self.status.set(
                            "Remote analysis complete. Reports: "
                            f"{get_reports_dir() / 'remote'}"
                        )
                    else:
                        self.status.set(
                            f"Analysis complete. Reports: {get_reports_dir()}"
                        )
                elif value == "partial":
                    self.status.set(
                        "Some remote PCs failed. Successful reports are saved "
                        f"under {get_reports_dir() / 'remote'}."
                    )
                elif value == "cancelled":
                    self.status.set(
                        "Analysis stopped. Partial results were discarded."
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
            or self.cancellation_event.is_set()
        ):
            return

        self.cancellation_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("Stopping analysis...")
        if event is not None:
            return "break"

    def signal_collection_finished(self):
        self.collection_finished_event.set()
        self.output_queue.put(("collection_finished", None))

    def set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        self.live_button.configure(state=state)
        self.evtx_button.configure(state=state)
        self.remote_button.configure(state=state)
        self.stop_button.configure(state="disabled" if enabled else "normal")
        self.start_time_entry.configure(state=state)
        self.end_time_entry.configure(state=state)
        for checkbutton in self.level_checkbuttons:
            checkbutton.configure(state=state)
        for checkbutton in self.result_level_checkbuttons:
            checkbutton.configure(state=state)
        self.remote_targets.configure(state=state)
        self.remote_domain_entry.configure(state=state)
        self.remote_username_entry.configure(state=state)
        self.remote_password_entry.configure(state=state)
        self.remember_targets_checkbutton.configure(state=state)
        self.remember_domain_checkbutton.configure(state=state)
        self.forget_remote_button.configure(state=state)
        self.test_remote_button.configure(state=state)
        for checkbutton in self.log_checkbuttons:
            checkbutton.configure(state=state)
        self.reports_button.configure(state=state)
        self.dashboard_button.configure(state=state)

    def forget_saved_remote_values(self):
        if not messagebox.askyesno(
            "Forget saved remote values",
            "Remove the saved IP list and domain from this PC?",
            parent=self.root,
        ):
            return

        try:
            forget_remote_settings()
        except OSError as error:
            messagebox.showerror(
                "Could not forget saved values",
                str(error),
                parent=self.root,
            )
            return

        self.remote_targets.delete("1.0", END)
        self.remote_domain.set("")
        self.remember_targets.set(False)
        self.remember_domain.set(False)
        self.status.set("Saved remote IPs and domain were forgotten.")

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
        dashboard_path = self.preferred_dashboard_path
        if dashboard_path is None or not dashboard_path.is_file():
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
