"""Shared async HTTP client factory and session manager for all pentesting tools.

This module provides:
- A configurable httpx.AsyncClient factory (`get_client`) used by every tool.
- A singleton `SessionManager` that stores authentication cookies so that
  once a user logs in via the `authenticate` tool, **all** subsequent HTTP
  requests automatically carry those session cookies.

Internal implementation detail — tools import `get_client` and `session_manager`
from this module and never create raw httpx clients directly.
"""

from __future__ import annotations

import httpx

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Session Manager — singleton that persists cookies across tool calls
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages authentication state (cookies) for the entire server session.

    After a successful `authenticate()` call the cookies are stored here and
    automatically merged into every `get_client()` call so that protected
    endpoints become accessible to all tools.
    """

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}
        self._is_authenticated: bool = False
        self._login_url: str | None = None

    # -- public API --------------------------------------------------------

    def store_cookies(self, cookies: dict[str, str], login_url: str) -> None:
        """Save cookies obtained from a successful login."""
        self._cookies.update(cookies)
        self._is_authenticated = True
        self._login_url = login_url

    def get_cookies(self) -> dict[str, str]:
        """Return the current session cookies (empty dict if not logged in)."""
        return dict(self._cookies)

    @property
    def is_authenticated(self) -> bool:
        return self._is_authenticated

    @property
    def login_url(self) -> str | None:
        return self._login_url

    def clear(self) -> None:
        """Wipe all stored cookies and reset authentication state."""
        self._cookies.clear()
        self._is_authenticated = False
        self._login_url = None


# Module-level singleton — shared by all tools in the process.
session_manager = SessionManager()


# ---------------------------------------------------------------------------
# Client factory
# ---------------------------------------------------------------------------

def get_client(
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    proxy: str | None = None,
    extra_headers: dict | None = None,
    extra_cookies: dict | None = None,
) -> httpx.AsyncClient:
    """Create an ``httpx.AsyncClient`` configured for pentesting use.

    The client automatically includes any session cookies stored by the
    ``SessionManager`` so that authenticated endpoints are reachable.

    Args:
        timeout: Request timeout in seconds (default 15).
        follow_redirects: Whether to follow HTTP redirects (default True).
        verify_ssl: Whether to verify TLS certificates (default True).
        proxy: Optional HTTP/SOCKS proxy URL.
        extra_headers: Additional headers merged on top of the defaults.
        extra_cookies: Additional cookies merged on top of session cookies.

    Returns:
        A configured ``httpx.AsyncClient`` context manager.
    """
    headers = {**DEFAULT_HEADERS}
    if extra_headers:
        headers.update(extra_headers)

    # Merge session cookies with any per-request extras
    cookies = {**session_manager.get_cookies()}
    if extra_cookies:
        cookies.update(extra_cookies)

    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        verify=verify_ssl,
        headers=headers,
        cookies=cookies,
        proxy=proxy,
    )
