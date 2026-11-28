"""Facts read from an event's own data, so the advice is about THIS event.

The built-in definition says what an Event ID means in general; these
lines say what this particular event reported (which service, which bug
check, which account). Every function returns plain sentences and never
raises, because a surprise in one event must not break an analysis.
"""

import re

from modules.database_loader import load_error_code_database, normalize_error_code

_SERVICE_FIELDS = {
    # Event ID: (position of the service name, position of the reason)
    7000: (1, 2), 7001: (1, 3), 7009: (2, None), 7011: (2, None),
    7023: (1, 2), 7024: (1, 2), 7031: (1, None), 7034: (1, None),
}

_LOGON_STATUS = {
    "0xc000006a": "wrong password",
    "0xc0000064": "the account name does not exist",
    "0xc000006d": "logon failed (wrong user name or password)",
    "0xc0000234": "the account is locked out",
    "0xc0000072": "the account is disabled",
    "0xc0000070": "the account is not allowed to log on from this computer",
    "0xc000006f": "the account is not allowed to log on at this time",
    "0xc0000071": "the password has expired",
    "0xc0000133": "the clocks of the two computers are too far apart",
}

_LOGON_TYPE = {
    "2": "at the keyboard", "3": "over the network (file share, etc.)",
    "4": "batch job", "5": "service", "7": "unlocking the screen",
    "8": "network with clear-text password", "10": "Remote Desktop (RDP)",
    "11": "cached credentials",
}

_RISKY_PATHS = ("\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\",
                "powershell", "cmd.exe", "wscript", "mshta", "\\downloads\\")


def _field(event, name, position=None):
    """A data value by its name, or by position (param1, Field 1...)."""

    wanted = {name.casefold()}

    if position is not None:
        wanted.update({f"param{position}", f"field {position}"})

    for index, item in enumerate(event.get("Data") or [], start=1):

        if isinstance(item, dict):
            key = str(item.get("name", "")).casefold()
            value = str(item.get("value", "")).strip()
        else:
            key, value = f"field {index}", str(item).strip()

        if key in wanted and value:
            return value

    return None


def _bugcheck(event):

    raw = _field(event, "BugcheckCode")

    if raw is None or not raw.isdigit():
        return []

    code = int(raw)
    lines = []

    if code == 0:
        lines.append(
            "BugcheckCode is 0: Windows did not record a blue-screen code."
        )
    else:
        key = normalize_error_code(f"0x{code:x}")
        known = load_error_code_database().get(key)
        text = f"BugcheckCode {code} is {key}"
        text += (
            f": {known['description']}. {known['recommendation']}."
            if known else
            ". Look this stop code up in Microsoft's bug check reference."
        )
        lines.append(text)

    button = _field(event, "PowerButtonTimestamp")

    if button is not None and button.isdigit():
        if int(button) > 0:
            lines.append(
                "PowerButtonTimestamp is set: the power button was held to "
                "force the shutdown (the PC was probably frozen)."
            )
        elif code == 0:
            lines.append(
                "No blue-screen code and no power-button press: this "
                "points to a power cut or hardware fault rather than "
                "software."
            )

    return lines


def _service(event):

    positions = _SERVICE_FIELDS[event["EventID"]]
    name = _field(event, "param", positions[0])
    reason = (
        _field(event, "param", positions[1]) if positions[1] else None
    )

    if name is None:
        match = re.search(
            r"(?:The |for the )(.+?) service", event.get("Message", "")
        )
        name = match.group(1) if match else None

    if name is None:
        return []

    line = f"The service involved is \"{name}\""

    if reason:
        line += f", and Windows reported: {reason}"

    return [line + "."]


def _new_service(event):

    name = _field(event, "ServiceName", 1)
    path = _field(event, "ImagePath", 2)
    account = _field(event, "AccountName", 5)

    if name is None and path is None:
        return []

    line = f"A new service \"{name or '?'}\" was installed"

    if path:
        line += f" to run {path}"
    if account:
        line += f" as {account}"

    lines = [line + ". Confirm that this installation was expected."]

    if path and any(word in path.casefold() for word in _RISKY_PATHS):
        lines.append(
            "WARNING: it runs from a user-writable folder or through a "
            "script host, which is a common sign of malware. Verify it."
        )

    return lines


def _failed_logon(event):

    account = _field(event, "TargetUserName")
    source = _field(event, "IpAddress")
    logon_type = _field(event, "LogonType")
    status = (
        _field(event, "SubStatus") or _field(event, "Status") or ""
    ).casefold()

    lines = []

    if account:
        line = f"Failed logon for \"{account}\""
        if source and source != "-":
            line += f" from {source}"
        if logon_type in _LOGON_TYPE:
            line += f", {_LOGON_TYPE[logon_type]}"
        lines.append(line + ".")

    if status in _LOGON_STATUS:
        lines.append(f"Reason: {_LOGON_STATUS[status]}.")

    return lines


def _lockout(event):

    account = _field(event, "TargetUserName", 1)
    caller = _field(event, "TargetDomainName", 2)

    if account is None:
        return []

    line = f"Account \"{account}\" was locked out"

    if caller:
        line += f"; the lockouts came from the computer {caller}"

    return [line + ". Check that computer for old saved passwords or a script."]


def _dcom(event):

    clsid = _field(event, "param", 4)
    appid = _field(event, "param", 5)

    if not (clsid or appid):
        return []

    return [
        f"Component CLSID {clsid or '?'}, APPID {appid or '?'}. "
        "Only look into it if an application using this component fails."
    ]


_HANDLERS = {
    41: _bugcheck,
    4625: _failed_logon,
    4740: _lockout,
    7045: _new_service,
    10016: _dcom,
}
_HANDLERS.update({event_id: _service for event_id in _SERVICE_FIELDS})


def event_insights(event):
    """Sentences about this specific event; an empty list when none apply."""

    try:
        handler = _HANDLERS.get(int(event.get("EventID")))
        return handler(event) if handler else []
    except Exception:
        return []
