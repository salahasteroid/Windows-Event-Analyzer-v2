"""Quick check that a remote computer's Event Log can be reached."""


def check_remote_connection(remote_options, win32evtlog=None, log_name="System"):
    """Returns (True, message) or (False, reason). Never raises.

    Opens the remote Event Log session and reads one record, which proves
    the address, credentials, firewall and permissions all work.
    """

    if win32evtlog is None:
        try:
            import win32evtlog
        except ImportError:
            return False, "Windows Event Log access is not available here."

    computer = remote_options.get("computer")
    username = remote_options.get("username")
    password = remote_options.get("password")
    domain = remote_options.get("domain") or None

    if not computer or not username or not password:
        return False, "Enter the computer IP, username and password."

    try:
        session = win32evtlog.EvtOpenSession(
            (
                computer,
                username,
                domain,
                password,
                win32evtlog.EvtRpcLoginAuthNegotiate,
            ),
            win32evtlog.EvtRpcLogin,
            0,
            0,
        )
        handle = win32evtlog.EvtQuery(
            log_name,
            win32evtlog.EvtQueryReverseDirection,
            "*",
            session,
        )
        win32evtlog.EvtNext(handle, 1, 1000)
    except Exception as error:
        return False, f"Could not read {log_name} on {computer}: {error}"

    return True, f"Connected to {computer}."
