"""Command-line (unattended) mode, e.g. for Windows Task Scheduler.

Exit codes: 0 finished, 1 health score below --fail-below,
2 bad arguments or a failed run, 3 some remote computers failed.
"""

import argparse
import io
import os
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from modules.diagnostics import write_diagnostics
from modules.event_channels import SUPPORTED_LOGS
from modules.event_filter import parse_event_ids, split_list
from modules.exporters import normalize_export_formats
from modules.paths import get_reports_dir, get_user_data_dir
from modules.remote_summary import generate_remote_summary
from modules.remote_targets import parse_remote_targets, remote_report_dir
from modules.update_check import check_for_update
from modules.version import __version__

LEVEL_NAMES = {
    "critical": 1,
    "error": 2,
    "warning": 3,
    "information": 4,
    "verbose": 5,
}


def build_parser():

    parser = argparse.ArgumentParser(
        prog="WindowsEventAnalyzer",
        description="Analyze Windows event logs without the window.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--check-update", action="store_true",
                        help="Look for a newer release on GitHub and exit.")
    parser.add_argument("--logs", default="System",
                        help="Comma list of: " + ", ".join(SUPPORTED_LOGS))
    parser.add_argument("--hours", type=float, default=24,
                        help="Analyze the last N hours (default 24).")
    parser.add_argument("--start", help="Start time, ISO 8601 (UTC if no zone).")
    parser.add_argument("--end", help="End time, ISO 8601 (UTC if no zone).")
    parser.add_argument("--levels", default="critical,error,warning",
                        help="Comma list of: " + ", ".join(LEVEL_NAMES))
    parser.add_argument("--evtx", help="Analyze a saved .evtx file instead.")
    parser.add_argument("--hosts-file",
                        help="Text file with one remote computer IP per line.")
    parser.add_argument("--hosts", help="Remote computer IPs, comma separated.")
    parser.add_argument("--user", help="Remote username.")
    parser.add_argument("--domain", help="Remote domain.")
    parser.add_argument("--password-env", default="WEA_PASSWORD",
                        help="Environment variable holding the remote "
                             "password (default WEA_PASSWORD). Passwords "
                             "are never taken from the command line.")
    parser.add_argument("--output-dir", help="Where reports are written.")
    parser.add_argument("--event-ids", help="Only these IDs, e.g. 41,7000-7040.")
    parser.add_argument("--exclude-event-ids", help="Skip these IDs.")
    parser.add_argument("--sources", help="Only these providers, comma list.")
    parser.add_argument("--keywords", help="Only events containing these words.")
    parser.add_argument("--export", default="",
                        help="Extra files: csv, json (comma list).")
    parser.add_argument("--xml", choices=["per_event", "combined", "none"],
                        default="per_event", help="How raw XML is exported.")
    parser.add_argument("--syslog", metavar="HOST[:PORT]",
                        help="Forward events to a syslog/SIEM server.")
    parser.add_argument("--syslog-protocol", choices=["udp", "tcp"],
                        default="udp")
    parser.add_argument("--email-to", help="Send the dashboard to these "
                                           "addresses (comma list).")
    parser.add_argument("--email-from", help="Sender address.")
    parser.add_argument("--smtp", metavar="HOST[:PORT]",
                        help="SMTP server (default port 587 with STARTTLS).")
    parser.add_argument("--smtp-user")
    parser.add_argument("--smtp-password-env", default="WEA_SMTP_PASSWORD")
    parser.add_argument("--fail-below", type=int, metavar="SCORE",
                        help="Exit with code 1 if the health score is lower.")
    parser.add_argument("--quiet", action="store_true",
                        help="Print only the result lines.")
    return parser


def _parse_time(text):

    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _host_port(text, default_port):

    host, _, port = text.rpartition(":")

    if host and port.isdigit() and ":" not in host:
        return host, int(port)

    return text, default_port


def parse_levels(text):

    levels = []

    for name in split_list(text):
        key = name.lower()
        if key not in LEVEL_NAMES:
            raise ValueError(f"Unknown level '{name}'.")
        levels.append(LEVEL_NAMES[key])

    return levels


def read_hosts(args):

    text = args.hosts or ""

    if args.hosts_file:
        text += " " + Path(args.hosts_file).read_text(encoding="utf-8")

    return parse_remote_targets(text) if text.strip() else []


def send_email(args, subject, body, attachment, smtp_class=smtplib.SMTP,
               environ=None):
    """Mail the dashboard. Raises on failure; the caller reports it."""

    host, port = _host_port(args.smtp, 587)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = args.email_from or args.smtp_user
    message["To"] = ", ".join(split_list(args.email_to))
    message.set_content(body)

    if attachment is not None and Path(attachment).exists():
        message.add_attachment(
            Path(attachment).read_bytes(),
            maintype="text",
            subtype="html",
            filename=Path(attachment).name,
        )

    with smtp_class(host, port, timeout=30) as server:
        server.starttls(context=ssl.create_default_context())
        password = (os.environ if environ is None else environ).get(
            args.smtp_password_env
        )
        if args.smtp_user and password:
            server.login(args.smtp_user, password)
        server.send_message(message)


def _ensure_streams():
    """A windowed .exe has no console; keep print() from failing."""

    if sys.stdout is not None and sys.stderr is not None:
        return None

    log_dir = get_user_data_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log = open(log_dir / "last_run.log", "w", encoding="utf-8")

    if sys.stdout is None:
        sys.stdout = log
    if sys.stderr is None:
        sys.stderr = log

    return log


def run_cli(argv, analyze, environ=None, smtp_class=smtplib.SMTP):
    """Parse arguments, run the analysis and return an exit code."""

    environ = os.environ if environ is None else environ
    log = _ensure_streams()

    try:
        return _run(argv, analyze, environ, smtp_class)
    finally:
        if log is not None:
            log.close()


def _run(argv, analyze, environ, smtp_class):

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exit_request:
        return int(exit_request.code or 0)

    if args.check_update:
        result = check_for_update()
        if "error" in result:
            print(f"Update check failed: {result['error']}")
            return 2
        print(
            f"Version {result['current']}; latest {result['latest']}"
            + (f" - download: {result['url']}" if result["newer"]
               else " - up to date.")
        )
        return 0

    try:
        levels = parse_levels(args.levels)
        logs = split_list(args.logs)
        event_ids = parse_event_ids(args.event_ids) if args.event_ids else None
        exclude_ids = (
            parse_event_ids(args.exclude_event_ids)
            if args.exclude_event_ids else None
        )
        formats = normalize_export_formats(split_list(args.export))
        hosts = read_hosts(args)
        end = _parse_time(args.end) if args.end else datetime.now(timezone.utc)
        start = (
            _parse_time(args.start) if args.start
            else end - timedelta(hours=args.hours)
        )
        if hosts and args.evtx:
            raise ValueError("--evtx cannot be combined with remote hosts.")
        if hosts and not (args.user and environ.get(args.password_env)):
            raise ValueError(
                f"Remote hosts need --user and the password in the "
                f"{args.password_env} environment variable."
            )
        if args.email_to and not args.smtp:
            raise ValueError("--email-to needs --smtp.")
        syslog = None
        if args.syslog:
            host, port = _host_port(args.syslog, 514)
            syslog = {"host": host, "port": port,
                      "protocol": args.syslog_protocol}
    except (ValueError, OSError) as error:
        print(f"Error: {error}")
        return 2

    common = dict(
        start_time=start,
        end_time=end,
        selected_levels=levels,
        logs=logs,
        event_ids=event_ids,
        exclude_event_ids=exclude_ids,
        sources=split_list(args.sources) or None if args.sources else None,
        keywords=split_list(args.keywords) or None if args.keywords else None,
        export_formats=formats,
        xml_mode=args.xml,
        syslog=syslog,
    )
    reports_dir = Path(args.output_dir) if args.output_dir else get_reports_dir()

    jobs = []

    if hosts:
        for host in hosts:
            jobs.append((host, dict(
                common,
                remote_options={
                    "computer": host,
                    "username": args.user,
                    "password": environ[args.password_env],
                    "domain": args.domain,
                },
                output_dir=remote_report_dir(reports_dir, host),
            )))
    else:
        jobs.append(("local", dict(
            common,
            evtx_file=args.evtx,
            output_dir=reports_dir if args.output_dir else None,
        )))

    results = []
    sink = io.StringIO()

    for name, kwargs in jobs:
        try:
            if args.quiet:
                from contextlib import redirect_stdout
                with redirect_stdout(sink):
                    summary = analyze(**kwargs)
            else:
                summary = analyze(**kwargs)
            results.append({"computer": name, "summary": summary,
                            "error": None if summary else "no result"})
        except Exception as error:
            print(f"{name}: failed - {error}")
            try:
                import traceback

                path = write_diagnostics(
                    reports_dir, traceback.format_exc(), {"Computer": name}
                )
                print(f"Support file: {path}")
            except OSError:
                pass
            results.append({"computer": name, "summary": None,
                            "error": str(error)})

    if hosts:
        page = generate_remote_summary(results, reports_dir / "remote")
        print(f"Comparison page: {page}")

    failed = [r for r in results if not r["summary"]]
    done = [r for r in results if r["summary"]]

    for result in done:
        summary = result["summary"]
        print(
            f"{result['computer']}: health score {summary['health_score']}, "
            f"{summary['event_count']} event(s), "
            f"{summary['critical']} critical, {summary['high']} high."
        )

    if args.email_to and done:
        worst = min(done, key=lambda r: r["summary"]["health_score"])
        dashboard = Path(worst["summary"]["report_dir"]) / "dashboard.html"
        try:
            send_email(
                args,
                f"Windows Event Analyzer: lowest health score "
                f"{worst['summary']['health_score']}",
                "\n".join(
                    f"{r['computer']}: {r['summary']['health_score']}"
                    for r in done
                ),
                dashboard,
                smtp_class,
                environ,
            )
            print("Email sent.")
        except Exception as error:
            print(f"Email failed: {error}")

    if not done:
        return 2

    if failed:
        code = 3
    else:
        code = 0

    if args.fail_below is not None and any(
        r["summary"]["health_score"] < args.fail_below for r in done
    ):
        return 1

    return code
