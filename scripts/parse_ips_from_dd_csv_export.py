import csv
from typing import Any

import re

CSV_FILEPATH = ".data/extract-2024-07-20T03_46_25.084Z.csv"

NGINX_ACCESS_LOG_REGEX_PATTERN = r'\[(?P<date>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+"(?P<http_method>\w+)\s+(?P<http_host>\S+)\s+(?P<http_url>\S+)"\s+(?P<http_status_code>\d{3})\s+(?P<network_body_bytes_sent>\d+)\s+"(?P<http_referrer>\S+)"\s+"(?P<http_user_agent>.+)"'

# Find urls starting their query string with & and not ?
INVALID_QUERY_PARAM_URL_REGEX_PATTERN = r"^/[^?]*&.*$"


def parse_nginx_access_log(val: str) -> dict[str, Any]:
    match = re.match(NGINX_ACCESS_LOG_REGEX_PATTERN, val)
    if match:
        return match.groupdict()
    else:
        raise ValueError(f"Failed to parse: {val}")


def is_ddos_request(log_attributes: dict[str, Any]) -> bool:
    # look for urls like /abc&def=1
    url_match = re.match(
        INVALID_QUERY_PARAM_URL_REGEX_PATTERN,
        log_attributes["http_url"],
    )
    if not url_match:
        return False

    return True


def main() -> int:
    failed_to_parse = 0
    deduplicated_ips: set[str] = set()
    with open(CSV_FILEPATH) as f:
        csv_reader = csv.DictReader(f)
        for line in csv_reader:
            try:
                log_attributes = parse_nginx_access_log(line["Message"])
            except ValueError:
                failed_to_parse += 1
                continue

            if is_ddos_request(log_attributes):
                deduplicated_ips.add(log_attributes["ip"])
                print(
                    "DDOS request detected",
                    log_attributes["http_method"],
                    log_attributes["http_url"],
                )
                # TODO: auto-report to abuseipdb
            else:
                pass  # print("Normal request", log_attributes["http_url"])

    # Write to a file for use in cloudflare to block the ips
    # (For use here: https://i.cmyui.xyz/twZwfdhmIys.png)
    with open(".data/ddos_ips.txt", "w") as f:
        for ip in deduplicated_ips:
            f.write(f"{ip}\n")

    print(f"Wrote {len(deduplicated_ips)} IPs to .data/ddos_ips.txt")
    if failed_to_parse:
        print(f"Failed to parse {failed_to_parse} lines")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
