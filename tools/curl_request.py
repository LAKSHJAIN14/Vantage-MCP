"""curl_request() — General-purpose HTTP request tool (like curl for the LLM).

PURPOSE
-------
This tool is the LLM's equivalent of ``curl``. It can send arbitrary HTTP
requests to any URL and return the full response (status, headers, body).
Use it whenever you need to:

- **Fetch page content** to understand the application structure.
- **Read HTML source** to find hidden form fields, CSRF tokens, or comments.
- **Hit API endpoints** to inspect JSON responses or error messages.
- **Verify a vulnerability** by manually crafting a specific request.
- **Follow up on findings** from other tools to gather more context.

HOW IT WORKS
------------
Wraps ``httpx.AsyncClient`` from the shared HTTP client module. Automatically
includes session cookies if the user has authenticated via the ``authenticate``
tool.

CURL QUICK REFERENCE (for context)
-----------------------------------
This tool mirrors common curl functionality:

    curl [URL]                        → curl_request(url="...")
    curl -X POST [URL]                → curl_request(url="...", method="POST")
    curl -d "key=val" [URL]           → curl_request(url="...", method="POST", body="key=val")
    curl -H "Auth: Bearer tok" [URL]  → curl_request(url="...", headers='{"Auth":"Bearer tok"}')
    curl -b "session=abc" [URL]       → curl_request(url="...", cookies='{"session":"abc"}')
    curl -L [URL]                     → follow_redirects is True by default
    curl -k [URL]                     → SSL verification is disabled by default

WHEN TO USE
-----------
- Before testing a parameter: fetch the page to see what parameters exist.
- To read login pages and find CSRF tokens before calling ``authenticate``.
- To inspect API responses, error pages, or admin panels.
- To verify exploitation by sending a crafted request and reading the response.
- Anytime the LLM needs more context about what a URL returns.
"""

import json

from utils.http_client import get_client


_MAX_BODY_LENGTH = 50_000  # Truncate very large responses


async def curl_request(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    content_type: str = "",
    cookies: str = "",
    follow_redirects: bool = True,
    timeout: float = 15.0,
    max_response_length: int = 50000,
) -> str:
    """Send an HTTP request to any URL and return the full response.

    This is a general-purpose HTTP tool — the LLM's equivalent of ``curl``.
    Use it to fetch pages, inspect responses, read source code, hit APIs,
    or verify vulnerabilities with crafted requests.

    Session cookies from a prior ``authenticate()`` call are automatically
    included. Any additional cookies passed here are merged on top.

    Args:
        url: The target URL to request (e.g., https://example.com/api/users).
        method: HTTP method — GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
            (default "GET").
        headers: Extra request headers as a JSON object string
            (e.g., '{"Authorization": "Bearer token123"}').
            These are merged with default browser-like headers.
        body: Request body string. For form data use URL-encoded format
            (key=val&key2=val2). For JSON, pass the JSON string and set
            content_type to "application/json".
        content_type: Content-Type header for the request body
            (e.g., "application/json", "application/x-www-form-urlencoded").
            If omitted and body is provided, defaults to
            "application/x-www-form-urlencoded".
        cookies: Extra cookies as a JSON object string
            (e.g., '{"debug": "true"}'). Merged with session cookies.
        follow_redirects: Whether to follow HTTP redirects (default True).
        timeout: Request timeout in seconds (default 15).
        max_response_length: Max characters of response body to return
            (default 50000). Prevents overwhelming the LLM with huge pages.

    Returns:
        JSON string containing: status_code, response_headers, body (possibly
        truncated), final_url, redirect_history, and content_length.
    """
    method = method.upper()

    # Parse optional JSON arguments
    extra_headers: dict = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            return json.dumps({"error": f"Invalid JSON in headers: {headers}"}, indent=2)

    extra_cookies: dict = {}
    if cookies:
        try:
            extra_cookies = json.loads(cookies)
        except json.JSONDecodeError:
            return json.dumps({"error": f"Invalid JSON in cookies: {cookies}"}, indent=2)

    # Set content type if body is provided
    if body and content_type:
        extra_headers["Content-Type"] = content_type
    elif body and "Content-Type" not in extra_headers:
        extra_headers["Content-Type"] = "application/x-www-form-urlencoded"

    async with get_client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify_ssl=False,
        extra_headers=extra_headers,
        extra_cookies=extra_cookies,
    ) as client:
        try:
            resp = await client.request(
                method=method,
                url=url,
                content=body if body else None,
            )
        except Exception as e:
            return json.dumps({
                "error": f"Request failed: {e}",
                "url": url,
                "method": method,
            }, indent=2)

    # Build response
    response_body = resp.text
    truncated = False
    cap = min(max_response_length, _MAX_BODY_LENGTH)
    if len(response_body) > cap:
        response_body = response_body[:cap]
        truncated = True

    # Collect redirect history
    redirect_chain = []
    for r in resp.history:
        redirect_chain.append({
            "url": str(r.url),
            "status": r.status_code,
        })

    return json.dumps({
        "url": url,
        "final_url": str(resp.url),
        "method": method,
        "status_code": resp.status_code,
        "response_headers": dict(resp.headers),
        "body": response_body,
        "body_truncated": truncated,
        "content_length": len(resp.text),
        "redirect_history": redirect_chain,
    }, indent=2)
