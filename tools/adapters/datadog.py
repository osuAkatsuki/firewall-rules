from typing import Any

import httpx

import settings

API_REQUEST_PAGE_SIZE = 1000

http_client = httpx.Client(base_url="https://api.datadoghq.com/api")


def get_datadog_logs(
    events_from: str,
    events_to: str,
    query: str,
) -> list[dict[str, Any]]:
    datadog_logs: list[dict[str, Any]] = []
    cursor = None
    while True:
        response = http_client.post(
            "/v2/logs/events/search",
            headers={
                "Content-Type": "application/json",
                "DD-API-KEY": settings.DATADOG_API_KEY,
                "DD-APPLICATION-KEY": settings.DATADOG_APPLICATION_KEY,
            },
            json={
                "filter": {
                    "from": events_from,
                    "to": events_to,
                    "query": query,
                },
                "page": {
                    "limit": API_REQUEST_PAGE_SIZE,
                    "cursor": cursor,
                },
                "sort": "timestamp",
            },
            timeout=httpx.Timeout(timeout=25.0),
        )
        response.raise_for_status()

        response_data = response.json()
        datadog_logs.extend(response_data["data"])

        next_page = response_data["meta"].get("page")
        if next_page:
            cursor = next_page["after"]
        else:
            break

    return datadog_logs
