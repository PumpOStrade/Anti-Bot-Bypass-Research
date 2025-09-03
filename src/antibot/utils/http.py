"""Shared HTTP client setup using curl_cffi for TLS fingerprint impersonation."""

from curl_cffi.requests import AsyncSession

from antibot.config import settings


def create_client(impersonate: str = "chrome131", proxy: str | None = None) -> AsyncSession:
    """Create an async HTTP client that impersonates a real browser's TLS fingerprint.

    Args:
        impersonate: Browser to impersonate (e.g. 'chrome131', 'chrome124', 'safari17_5').
        proxy: Optional proxy URL (e.g. 'socks5://host:port').
    """
    kwargs = {
        "impersonate": impersonate,
        "timeout": settings.request_timeout,
        "headers": {
            "User-Agent": settings.default_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
        },
    }
    if proxy:
        kwargs["proxy"] = proxy
    return AsyncSession(**kwargs)


async def fetch_page(url: str, impersonate: str = "chrome131", proxy: str | None = None) -> tuple[object, str]:
    """Fetch a page and return (response, page_source)."""
    async with create_client(impersonate, proxy=proxy) as client:
        response = await client.get(url, allow_redirects=True)
        return response, response.text
