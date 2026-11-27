import types
from pathlib import Path

import pytest

from modules import cli
from modules.remote_check import check_remote_connection
from modules.remote_summary import generate_remote_summary
from modules.update_check import check_for_update, is_newer, parse_version


def summary(score, report_dir, computer="local"):
    return {"computer": computer, "health_score": score, "event_count": 3,
            "critical": 1, "high": 2, "findings": [{"title": "Disk <b>"}],
            "report_dir": str(report_dir)}


class Recorder:
    def __init__(self, scores=None, fail=()):
        self.calls, self.scores, self.fail = [], scores or {}, fail

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        computer = (kwargs.get("remote_options") or {}).get("computer", "local")
        if computer in self.fail:
            raise RuntimeError("unreachable")
        out = kwargs.get("output_dir") or Path("reports")
        return summary(self.scores.get(computer, 95), out, computer)


# ---- CLI
def test_local_run_passes_options_and_exit_zero(tmp_path, capsys):
    analyze = Recorder()
    code = cli.run_cli(
        ["--logs", "System,Security", "--hours", "6", "--levels", "error",
         "--event-ids", "41,7000-7001", "--export", "csv", "--xml", "none",
         "--output-dir", str(tmp_path)], analyze)
    call = analyze.calls[0]
    assert code == 0
    assert call["logs"] == ["System", "Security"]
    assert call["selected_levels"] == [2]
    assert call["event_ids"] == {41, 7000, 7001}
    assert call["export_formats"] == ("csv",) and call["xml_mode"] == "none"
    hours = (call["end_time"] - call["start_time"]).total_seconds() / 3600
    assert hours == pytest.approx(6)
    assert "health score 95" in capsys.readouterr().out


def test_fail_below_exit_code(tmp_path):
    assert cli.run_cli(["--fail-below", "90", "--output-dir", str(tmp_path)],
                       Recorder({"local": 80})) == 1
    assert cli.run_cli(["--fail-below", "70", "--output-dir", str(tmp_path)],
                       Recorder({"local": 80})) == 0


@pytest.mark.parametrize("argv", [
    ["--levels", "loud"],
    ["--logs", "Setup"],
    ["--export", "xlsx"],
    ["--event-ids", "x"],
    ["--hosts", "192.0.2.1"],                      # no user/password
    ["--hosts", "not-an-ip", "--user", "u"],
    ["--email-to", "a@b.c"],                       # no --smtp
    ["--evtx", "a.evtx", "--hosts", "192.0.2.1", "--user", "u"],
])
def test_bad_arguments_return_2(argv, capsys):
    analyze = Recorder()
    env = {"WEA_PASSWORD": "pw"} if "--user" in argv else {}
    # the invalid-logs case is rejected by main(), which we simulate
    if argv[:1] == ["--logs"]:
        from modules.event_channels import normalize_logs

        def analyze(**kw):
            normalize_logs(kw["logs"])
    assert cli.run_cli(argv, analyze, environ=env) == 2


def test_remote_hosts_password_from_environment_and_summary(tmp_path, capsys):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.1\n192.0.2.2\n192.0.2.3\n")
    analyze = Recorder({"192.0.2.1": 40, "192.0.2.2": 90}, fail={"192.0.2.3"})
    code = cli.run_cli(
        ["--hosts-file", str(hosts), "--user", "admin", "--domain", "corp",
         "--output-dir", str(tmp_path / "out")],
        analyze, environ={"WEA_PASSWORD": "secret"})
    assert code == 3
    assert analyze.calls[0]["remote_options"] == {
        "computer": "192.0.2.1", "username": "admin",
        "password": "secret", "domain": "corp"}
    page = (tmp_path / "out" / "remote" / "summary.html").read_text("utf-8")
    assert page.index("192.0.2.1") < page.index("192.0.2.2")   # worst first
    assert "Not analyzed" in page and "unreachable" in page
    assert "secret" not in capsys.readouterr().out + page


def test_all_failed_returns_2(tmp_path):
    assert cli.run_cli(["--output-dir", str(tmp_path)],
                       Recorder(fail={"local"})) == 2


def test_email_sent_with_dashboard(tmp_path):
    (tmp_path / "dashboard.html").write_text("<html></html>")
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["server"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): sent["tls"] = True
        def login(self, user, password): sent["login"] = (user, password)
        def send_message(self, message): sent["message"] = message

    code = cli.run_cli(
        ["--output-dir", str(tmp_path), "--email-to", "a@x.com,b@x.com",
         "--smtp", "mail.example.com:2525", "--smtp-user", "bot",
         "--email-from", "bot@x.com"],
        Recorder(), environ={"WEA_SMTP_PASSWORD": "pw"}, smtp_class=FakeSMTP)
    assert code == 0
    assert sent["server"] == ("mail.example.com", 2525) and sent["tls"]
    assert sent["login"] == ("bot", "pw")
    assert sent["message"]["To"] == "a@x.com, b@x.com"
    assert list(sent["message"].iter_attachments())[0].get_filename() == "dashboard.html"


def test_email_failure_does_not_change_exit_code(tmp_path):
    class Broken:
        def __init__(self, *a, **k): raise OSError("no route")

    assert cli.run_cli(["--output-dir", str(tmp_path), "--email-to", "a@x.com",
                        "--smtp", "h"], Recorder(), smtp_class=Broken) == 0


def test_quiet_hides_analysis_output(tmp_path, capsys):
    def noisy(**kwargs):
        print("DETAILS")
        return summary(90, tmp_path)

    cli.run_cli(["--quiet", "--output-dir", str(tmp_path)], noisy)
    out = capsys.readouterr().out
    assert "DETAILS" not in out and "health score 90" in out


def test_no_password_argument_exists():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--password", "x"])


def test_help_and_version_exit_zero(capsys):
    assert cli.run_cli(["--version"], Recorder()) == 0


def test_syslog_option_parsed(tmp_path):
    analyze = Recorder()
    cli.run_cli(["--syslog", "10.0.0.9:6514", "--syslog-protocol", "tcp",
                 "--output-dir", str(tmp_path)], analyze)
    assert analyze.calls[0]["syslog"] == {
        "host": "10.0.0.9", "port": 6514, "protocol": "tcp"}


# ---- remote summary escaping
def test_remote_summary_escapes_html(tmp_path):
    path = generate_remote_summary(
        [{"computer": "<script>", "summary": None, "error": "<b>x</b>"},
         {"computer": "192.0.2.5", "summary": summary(60, tmp_path / "h"),
          "error": None}], tmp_path)
    html = path.read_text("utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Disk &lt;b&gt;" in html


# ---- update check
def test_version_compare():
    assert parse_version("v2.10.1") == (2, 10, 1)
    assert parse_version("latest") is None
    assert is_newer("v2.10.0", "2.9.9")
    assert not is_newer("2.1", "2.1.0")
    assert not is_newer("junk", "2.1.0")


def test_check_for_update_with_fake_fetch():
    result = check_for_update(lambda: {"tag_name": "v99.0.0", "html_url": "u"})
    assert result["newer"] and result["url"] == "u"
    assert "error" in check_for_update(lambda: {"tag_name": "nightly"})

    def boom():
        raise OSError("offline")

    assert check_for_update(boom) == {"error": "offline"}


# ---- remote connection check
def fake_evtlog(fail_at=None):
    def step(name):
        def run(*args):
            if name == fail_at:
                raise OSError("RPC server unavailable")
            return object()
        return run
    return types.SimpleNamespace(
        EvtOpenSession=step("open"), EvtQuery=step("query"),
        EvtNext=step("next"), EvtRpcLogin=1, EvtRpcLoginAuthNegotiate=2,
        EvtQueryReverseDirection=3)


def test_remote_check():
    options = {"computer": "192.0.2.1", "username": "u", "password": "p"}
    assert check_remote_connection(options, fake_evtlog())[0]
    ok, reason = check_remote_connection(options, fake_evtlog("query"))
    assert not ok and "RPC server unavailable" in reason
    ok, reason = check_remote_connection({"computer": "x"}, fake_evtlog())
    assert not ok and "password" in reason.lower()
    ok, reason = check_remote_connection(
        {**options, "password": "hunter2"}, fake_evtlog("open"))
    assert not ok and "hunter2" not in reason
