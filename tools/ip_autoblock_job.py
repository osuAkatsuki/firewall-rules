import ipaddress
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

import settings
from adapters import cloudflare
from adapters import datadog

# TODO: potentially set this up as a nightly cron

# Find urls starting their query string with & and not ?
INVALID_QUERY_PARAM_URL_REGEX_PATTERN = r"^/[^?]*&.*$"


def is_ddos_request(log_attributes: dict[str, Any]) -> bool:
    # look for urls like /abc&def=1
    url_match = re.match(
        INVALID_QUERY_PARAM_URL_REGEX_PATTERN,
        log_attributes["http"]["url"],
    )
    if not url_match:
        return False

    return True


@dataclass
class DDoSRequest:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    http_method: str
    http_host: str
    http_url: str
    http_status_code: int
    http_referrer: str
    http_user_agent: str
    timestamp: datetime


def main() -> int:
    datadog_logs = datadog.get_datadog_logs(
        events_from="now-1h",
        events_to="now",
        query="service:rev-proxy",
    )
    print(f"Received {len(datadog_logs)} logs from Datadog")

    ddos_requests_by_ip: defaultdict[str, list[DDoSRequest]] = defaultdict(list)
    for datadog_log in datadog_logs:
        log_attributes = datadog_log["attributes"].get("attributes")
        if log_attributes is None:
            continue  # non-access log

        if is_ddos_request(log_attributes):
            ddos_request = DDoSRequest(
                ip=ipaddress.ip_address(log_attributes["network"]["client"]["ip"]),
                http_method=log_attributes["http"]["method"],
                http_host=log_attributes["http"]["host"],
                http_url=log_attributes["http"]["url"],
                http_status_code=int(log_attributes["http"]["status_code"]),
                http_referrer=log_attributes["http"]["referrer"],
                http_user_agent=log_attributes["http"]["user_agent"],
                timestamp=datetime.fromtimestamp(log_attributes["date"] / 1000),
            )
            ddos_requests_by_ip[log_attributes["network"]["client"]["ip"]].append(
                ddos_request
            )
        else:
            pass  # print("Normal request", log_attributes["http_url"])
    print(f"Parsed {len(datadog_logs)} requests from logs")

    ipv4_addresses: list[str] = [
        ip
        for ip in ddos_requests_by_ip
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    ]

    cloudflare.add_list_items(
        list_id=settings.CLOUDFLARE_DDOS_IPS_LIST_ID,
        items=ipv4_addresses,
    )
    print(f"Added {len(ipv4_addresses)} IPs to Cloudflare block list")

    # TODO: auto-report ips to abuseipdb

    return 0


if __name__ == "__main__":
    exit(main())
