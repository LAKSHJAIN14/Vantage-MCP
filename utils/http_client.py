"""Shared async HTTP client factory for all pentesting tools."""

import httpx

DEFAULT_TIMEOUT = 15.0
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


def get_client(
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    proxy: str | None = None,
    extra_headers: dict | None = None,
) -> httpx.AsyncClient:
    """Create an httpx.AsyncClient configured for pentesting use."""
    headers = {**DEFAULT_HEADERS}
    if extra_headers:
        headers.update(extra_headers)

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        verify=verify_ssl,
        headers=headers,
        proxy=proxy,
    )
