from modules.analyzer import analyze_event
from modules.diagnostics import build_diagnostics, short_error, write_diagnostics
from modules.insights import event_insights

OFFLINE = {"status": "skipped"}


def data(**fields):
    return [{"name": k, "value": v} for k, v in fields.items()]


def test_event_41_bugcheck_is_named_and_hex():
    lines = event_insights({"EventID": 41, "Data": data(
        BugcheckCode="10", PowerButtonTimestamp="0")})
    assert "0x0000000a" in lines[0] and "IRQL_NOT_LESS_OR_EQUAL" in lines[0]


def test_event_41_zero_values_point_to_power():
    lines = event_insights({"EventID": 41, "Data": data(
        BugcheckCode="0", PowerButtonTimestamp="0")})
    assert any("power cut or hardware" in line for line in lines)


def test_event_41_power_button():
    lines = event_insights({"EventID": 41, "Data": data(
        BugcheckCode="0", PowerButtonTimestamp="1327")})
    assert any("power button" in line for line in lines)


def test_service_events_use_positional_fields():
    failed = event_insights({"EventID": 7000, "Data": data(
        param1="Print Spooler",
        param2="The service did not respond in a timely fashion.")})
    assert "Print Spooler" in failed[0] and "timely" in failed[0]
    timeout = event_insights({"EventID": 7009, "Data": data(
        param1="30000", param2="Foo Service")})
    assert "Foo Service" in timeout[0]


def test_service_name_from_message_when_data_is_missing():
    lines = event_insights({"EventID": 7034, "Data": [],
        "Message": "The Spooler service terminated unexpectedly."})
    assert "Spooler" in lines[0]


def test_new_service_from_risky_path_is_flagged():
    risky = event_insights({"EventID": 7045, "Data": data(
        ServiceName="Updater", ImagePath=r"C:\Users\bob\AppData\Roaming\u.exe",
        AccountName="LocalSystem")})
    assert any(line.startswith("WARNING") for line in risky)
    normal = event_insights({"EventID": 7045, "Data": data(
        ServiceName="Backup", ImagePath=r"C:\Program Files\Backup\b.exe")})
    assert not any(line.startswith("WARNING") for line in normal)


def test_failed_logon_and_lockout():
    lines = event_insights({"EventID": 4625, "Data": data(
        TargetUserName="amy", IpAddress="10.0.0.7", LogonType="10",
        SubStatus="0xC000006A")})
    assert "amy" in lines[0] and "10.0.0.7" in lines[0] and "RDP" in lines[0]
    assert lines[1] == "Reason: wrong password."
    lockout = event_insights({"EventID": 4740, "Data": data(
        TargetUserName="amy", TargetDomainName="PC-9")})
    assert "PC-9" in lockout[0]


def test_dcom_components():
    lines = event_insights({"EventID": 10016, "Data": data(
        param4="{AAAA}", param5="{BBBB}")})
    assert "{AAAA}" in lines[0] and "{BBBB}" in lines[0]


def test_unknown_or_broken_events_never_raise():
    assert event_insights({"EventID": 99999}) == []
    assert event_insights({"EventID": "x"}) == []
    assert event_insights({"EventID": 41, "Data": [None, 5]}) == []


def test_analysis_carries_insights():
    result = analyze_event(
        {"EventID": 41, "Source": "Microsoft-Windows-Kernel-Power", "Level": 1,
         "Data": data(BugcheckCode="0", PowerButtonTimestamp="0")},
        online_lookup=OFFLINE)
    assert result["insights"]


def test_short_error_and_diagnostics_file(tmp_path):
    trace = "Traceback (most recent call last):\n  File x\nKeyError: 'Level'\n"
    assert short_error(trace) == "KeyError: 'Level'"
    assert short_error("") == "Unknown error"
    path = write_diagnostics(tmp_path, trace, {"Logs": "System"})
    text = path.read_text(encoding="utf-8")
    assert "KeyError: 'Level'" in text and "Logs: System" in text
    assert "Version: " in text and "Database: " in text
    assert "password" not in build_diagnostics().casefold()
