import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

import settings
from adapters import cloudflare
from adapters import datadog

# TODO: potentially set this up as a nightly cron

# Find urls starting their query string with & and not ?
INVALID_QUERY_PARAM_URL_REGEX_PATTERN = r"^/[^?]*&.*$"


@dataclass
class NetworkRequest:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    http_method: str
    http_host: str
    http_url: str
    http_status_code: int
    http_referrer: str
    http_user_agent: str
    timestamp: datetime

    def is_ddos_request(self) -> bool:
        # look for urls like /abc&def=1
        url_match = re.match(
            INVALID_QUERY_PARAM_URL_REGEX_PATTERN,
            self.http_url,
        )
        if not url_match:
            return False

        return True


def main() -> int:
    datadog_logs = datadog.get_datadog_logs(
        events_from="now-1h",
        events_to="now",
        query="service:rev-proxy",
    )
    print(f"Received {len(datadog_logs)} logs from Datadog")

    malicious_requests_by_ip: defaultdict[str, list[NetworkRequest]] = defaultdict(list)
    for datadog_log in datadog_logs:
        log = datadog_log["attributes"].get("attributes")
        if log is None:
            continue  # non-access log

        request = NetworkRequest(
            ip=ipaddress.ip_address(log["network"]["client"]["ip"]),
            http_method=log["http"]["method"],
            http_host=log["http"]["host"],
            http_url=log["http"]["url"],
            http_status_code=int(log["http"]["status_code"]),
            http_referrer=log["http"]["referrer"],
            http_user_agent=log["http"]["user_agent"],
            timestamp=datetime.fromtimestamp(log["date"] / 1000),
        )

        if request.is_ddos_request():
            malicious_requests_by_ip[log["network"]["client"]["ip"]].append(request)
        else:
            pass  # print("Normal request", log_attributes["http_url"])
    print(f"Parsed {len(datadog_logs)} requests from logs")

    malicious_ipv4_addresses: list[str] = [
        ip
        for ip in malicious_requests_by_ip
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    ]

    cloudflare.add_list_items(
        list_id=settings.CLOUDFLARE_DDOS_IPS_LIST_ID,
        items=malicious_ipv4_addresses,
    )
    print(
        f"Added {len(malicious_ipv4_addresses)} malicious IPs to Cloudflare block list"
    )

    # TODO: auto-report ips to abuseipdb

    return 0


if __name__ == "__main__":
    exit(main())
