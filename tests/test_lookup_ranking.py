"""Ranking tested with titles and addresses returned by Microsoft Learn."""

from modules.internet_lookup import rank_results

L = "https://learn.microsoft.com"


def result(title, path, description=""):
    return {"title": title, "url": L + path, "description": description}


EVENT_10016 = [
    result("The application-specific permission settings do not grant Local "
           "Activation permission for the COM Server application with CLSID - "
           "Microsoft Q&A", "/answers/a/13059640"),
    result("DCOM event ID 10016 is logged in Windows",
           "/troubleshoot/windows-client/application-management/"
           "event-10016-logged-when-accessing-dcom",
           "Workaround for event 10016 logged when accessing DCOM components."),
]

EVENT_7000 = [
    result("The Windows Trace Session Manager service does not start and "
           "Event ID 7000 occurs",
           "/troubleshoot/windows-client/system-management-components/x",
           "Service Control Manager timeout."),
    result("Event ID 7000 and SQL Server doesn't start",
           "/troubleshoot/sql/database-engine/startup-shutdown/event-id-7000-fail-start"),
    result("Resolve common errors for the Intune Exchange Connector",
           "/troubleshoot/mem/intune/x", "Event 7000 or 7041 service won't start"),
]

EVENT_41 = [
    result("Advanced troubleshooting for Event ID 41: \"The system has "
           "rebooted without cleanly shutting down first\"",
           "/troubleshoot/windows-client/performance/event-id-41-restart",
           "Kernel-Power Event ID 41 unexpected restart."),
    result("Kernel-Power error 41 - Microsoft Q&A", "/answers/a/12229916"),
]


def test_forum_posts_are_never_returned():
    ranked = rank_results(EVENT_10016, 10016, "Microsoft-Windows-DistributedCOM")
    assert [r["url"].split("/")[3] for r in ranked] == ["troubleshoot"]


def test_dcom_article_is_high_confidence():
    best = rank_results(EVENT_10016, 10016, "Microsoft-Windows-DistributedCOM")[0]
    assert best["confidence"] == "high"


def test_event_41_article_is_high_confidence():
    ranked = rank_results(EVENT_41, 41, "Microsoft-Windows-Kernel-Power")
    assert len(ranked) == 1 and ranked[0]["confidence"] == "high"


def test_product_articles_for_a_generic_id_are_not_high():
    ranked = rank_results(EVENT_7000, 7000, "Service Control Manager")
    by_title = {r["title"][:20]: r["confidence"] for r in ranked}
    assert by_title["The Windows Trace Se"] in ("high", "medium")
    assert by_title["Event ID 7000 and SQ"] == "medium"
    assert all(r["confidence"] != "high" for r in ranked if "SQL" in r["title"])
    # the article that is about the Service Control Manager ranks first
    assert ranked[0]["title"].startswith("The Windows Trace")


def test_unrelated_and_foreign_hosts_are_dropped():
    results = [
        result("Something about Event ID 99", "/x"),
        {"title": "Event ID 41 phishing", "url": "https://evil.example/x"},
        {"title": "Event ID 41", "url": "http://learn.microsoft.com/x"},
        "junk",
    ]
    assert rank_results(results, 41, "Microsoft-Windows-Kernel-Power") == []


def test_id_only_in_description_is_low_confidence():
    ranked = rank_results(
        [result("Troubleshoot unexpected reboots using system event logs",
                "/troubleshoot/windows-server/x",
                "Kernel-Power logs Event ID 41 after a dirty shutdown.")],
        41, "Microsoft-Windows-Kernel-Power")
    assert ranked[0]["confidence"] == "low"
