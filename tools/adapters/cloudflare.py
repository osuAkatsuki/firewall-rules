import httpx

import settings

CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com"

http_client = httpx.Client(base_url=CLOUDFLARE_API_BASE_URL)


def add_list_items(list_id: str, items: list[str]) -> None:
    if not items:
        return None

    response = http_client.post(
        f"/client/v4/accounts/{settings.CLOUDFLARE_ACCOUNT_ID}/rules/lists/{list_id}/items",
        headers={
            "X-Auth-Email": "josh@akatsuki.gg",
            "X-Auth-Key": settings.CLOUDFLARE_GLOBAL_API_KEY,
        },
        json=[{"ip": ip} for ip in items],
    )
    response.raise_for_status()
    return None
