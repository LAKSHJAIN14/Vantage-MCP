"""authenticate() — Login to a web application and persist session cookies.

PURPOSE
-------
Many web applications require authentication before sensitive endpoints and
functionality are exposed. This tool performs a login request, captures the
session cookies (Set-Cookie headers), and stores them in a global session
manager so that **every subsequent tool call** (fingerprint, find_routes,
test_sqli, test_xss, etc.) automatically sends those cookies.

HOW IT WORKS
------------
1. Sends a POST request to the login URL with the supplied credentials.
2. Captures all ``Set-Cookie`` response headers.
3. Stores them in the ``SessionManager`` singleton from ``utils.http_client``.
4. All future ``get_client()`` calls automatically include those cookies.

WHEN TO USE
-----------
- The target requires authentication to access most pages.
- The user has provided valid credentials (username/password or API token).
- You want to test **authenticated** attack surfaces (post-login pages,
  admin panels, user dashboards, API endpoints behind auth).
- You found SQLi or a way to login then login using that and then test for more vulnerabilities.  

Call this tool **once** early in the pentest workflow (after fingerprinting,
before route discovery) so that route crawling and vulnerability testing
can reach authenticated pages.
"""

import json

from utils.http_client import get_client, session_manager


async def authenticate(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: str = "",
    login_method: str = "form",
) -> str:
    """Log in to a web application and store the session cookies for all tools.

    Performs a POST request to the login URL with the provided credentials,
    captures session cookies from the response, and stores them globally so
    every subsequent tool call is authenticated.

    Args:
        login_url: The login form action URL (e.g., https://example.com/login).
        username: The username or email to log in with.
        password: The password to log in with.
        username_field: The form field name for the username (default "username").
            Common alternatives: "email", "user", "login", "uid".
        password_field: The form field name for the password (default "password").
            Common alternatives: "pass", "passwd", "pwd".
        extra_fields: Additional form fields as URL-encoded string
            (e.g., "csrf_token=abc123&remember=1"). Useful for CSRF tokens or
            hidden fields discovered during fingerprinting / route discovery.
        login_method: How to send credentials — "form" for URL-encoded POST body
            (application/x-www-form-urlencoded), or "json" for JSON POST body
            (application/json). Default "form".

    Returns:
        JSON string confirming login status: success/failure, cookies received,
        final redirect URL, and session state.
    """
    # Build credential payload
    form_data: dict[str, str] = {
        username_field: username,
        password_field: password,
    }

    # Parse extra fields if provided
    if extra_fields:
        from urllib.parse import parse_qs
        for key, values in parse_qs(extra_fields, keep_blank_values=True).items():
            form_data[key] = values[0]

    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        try:
            if login_method.lower() == "json":
                resp = await client.post(
                    login_url,
                    json=form_data,
                )
            else:
                resp = await client.post(
                    login_url,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        except Exception as e:
            return json.dumps({
                "error": f"Login request failed: {e}",
                "login_url": login_url,
            }, indent=2)

    # Extract cookies from response
    cookies_received: dict[str, str] = {}
    for cookie_header in resp.headers.get_list("set-cookie"):
        # Parse cookie name=value from the Set-Cookie header
        parts = cookie_header.split(";")[0]  # ignore attributes
        if "=" in parts:
            name, value = parts.split("=", 1)
            cookies_received[name.strip()] = value.strip()

    # Also capture cookies from the httpx cookie jar
    for name, value in resp.cookies.items():
        cookies_received[name] = value

    # Store cookies in the session manager
    if cookies_received:
        session_manager.store_cookies(cookies_received, login_url)

    # Determine success heuristics
    status = resp.status_code
    final_url = str(resp.url)
    success_indicators = [
        status in (200, 302, 303),
        len(cookies_received) > 0,
        "login" not in final_url.lower() or final_url != login_url,
    ]
    likely_success = sum(success_indicators) >= 2

    return json.dumps({
        "login_url": login_url,
        "final_url": final_url,
        "status_code": status,
        "cookies_received": list(cookies_received.keys()),
        "cookie_count": len(cookies_received),
        "session_stored": session_manager.is_authenticated,
        "likely_success": likely_success,
        "hint": (
            "Cookies are now stored and will be sent with ALL subsequent tool "
            "calls. Use find_routes() to discover authenticated endpoints."
            if likely_success
            else "Login may have failed. Check credentials, field names, and "
                 "whether a CSRF token is required (check the login page source "
                 "with curl_request first)."
        ),
    }, indent=2)
