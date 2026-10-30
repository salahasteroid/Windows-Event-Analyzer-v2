import os
from datetime import datetime


def export_xml(event):

    os.makedirs(
        "reports/xml",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    file_name = (
        f"reports/xml/"
        f"Event_{event['EventID']}_{timestamp}.xml"
    )

    with open(
        file_name,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            event["RawXML"]
        )

    return file_name