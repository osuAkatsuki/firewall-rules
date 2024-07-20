import csv
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

# TODO: potentially set this up as a nightly cron & fetch logs from datadog apis

CSV_FILEPATH = ".data/extract-2024-07-20T06_41_06.609Z.csv"

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


@dataclass
class DDoSRequest:
    ip: str
    http_method: str
    http_host: str
    http_url: str
    http_status_code: int
    http_referrer: str
    http_user_agent: str
    timestamp: datetime


def main() -> int:
    failed_to_parse = 0
    ddos_requests_by_ip: defaultdict[str, list[DDoSRequest]] = defaultdict(list)
    with open(CSV_FILEPATH) as f:
        csv_reader = csv.DictReader(f)
        for line in csv_reader:
            try:
                log_attributes = parse_nginx_access_log(line["Message"])
            except ValueError:
                failed_to_parse += 1
                continue

            if is_ddos_request(log_attributes):
                ddos_request = DDoSRequest(
                    ip=log_attributes["ip"],
                    http_method=log_attributes["http_method"],
                    http_host=log_attributes["http_host"],
                    http_url=log_attributes["http_url"],
                    http_status_code=int(log_attributes["http_status_code"]),
                    http_referrer=log_attributes["http_referrer"],
                    http_user_agent=log_attributes["http_user_agent"],
                    timestamp=datetime.strptime(
                        log_attributes["date"], "%d/%b/%Y:%H:%M:%S %z"
                    ),
                )
                ddos_requests_by_ip[log_attributes["ip"]].append(ddos_request)
                print(
                    "DDoS request detected",
                    "{timestamp} {ip} {http_method} {http_host} {http_url}".format(
                        **asdict(ddos_request)
                    ),
                )
            else:
                pass  # print("Normal request", log_attributes["http_url"])

    # Write to a file for use in cloudflare to block the ips
    # (For use here: https://i.cmyui.xyz/twZwfdhmIys.png)
    with open(".data/ddos_ips.txt", "w") as f:
        for ip in ddos_requests_by_ip:
            f.write(f"{ip}\n")

    # TODO: auto-report to abuseipdb

    print(f"Wrote {len(ddos_requests_by_ip)} IPs to .data/ddos_ips.txt")
    if failed_to_parse:
        print(f"Warning: Failed to parse {failed_to_parse} lines")

    return 0


if __name__ == "__main__":
    exit(main())
