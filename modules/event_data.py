import re


_GUID_PATTERN = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)


def extract_event_data(root, ns):
    event_data = root.find(
        ".//e:EventData",
        ns
    )

    if event_data is None:
        return []

    data = []

    for index, item in enumerate(event_data, start=1):
        if item.text:
            data.append({
                "name": item.attrib.get("Name") or f"Field {index}",
                "value": item.text
            })

    return data


def get_event_data_value(item):
    if isinstance(item, dict):
        return str(item.get("value", ""))
    return str(item)


def format_event_data_item(item, index):
    if isinstance(item, dict):
        name = item.get("name") or f"Field {index}"
    else:
        name = f"Field {index}"

    value = get_event_data_value(item)
    explanation = ""

    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        decimal_value = int(value, 16)
        explanation = f" (hex number; regular number: {decimal_value:,})"
    elif re.fullmatch(r"[A-Za-z]:", value):
        explanation = " (drive letter)"
    elif _GUID_PATTERN.fullmatch(value):
        explanation = " (unique Windows identifier)"

    return f"{name}: {value}{explanation}"
