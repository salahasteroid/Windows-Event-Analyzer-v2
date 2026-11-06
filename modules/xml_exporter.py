from datetime import datetime

from modules.paths import get_reports_dir


def export_xml(event):

    output_dir = get_reports_dir() / "xml"
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    file_path = (
        output_dir
        / f"Event_{event['EventID']}_{timestamp}.xml"
    )

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            event["RawXML"]
        )

    return str(file_path)