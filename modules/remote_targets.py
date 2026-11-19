import ipaddress
import re


MAX_REMOTE_TARGETS = 20
MAX_PARALLEL_REMOTE_TARGETS = 5


def parse_remote_targets(value):

    targets = []

    for candidate in re.split(r"[\s,;]+", value.strip()):
        if not candidate:
            continue

        try:
            target = str(ipaddress.ip_address(candidate))
        except ValueError as error:
            raise ValueError(
                f"'{candidate}' is not a valid IPv4 or IPv6 address."
            ) from error

        if target not in targets:
            targets.append(target)

        if len(targets) > MAX_REMOTE_TARGETS:
            raise ValueError(
                f"Enter no more than {MAX_REMOTE_TARGETS} target IP addresses."
            )

    return targets


def remote_report_dir(reports_dir, computer):

    address = ipaddress.ip_address(computer)
    safe_address = address.compressed.replace(":", "_").replace("%", "_")
    return reports_dir / "remote" / f"host-{safe_address}"
