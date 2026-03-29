"""check_headers() — Security header audit for a target URL.

PURPOSE
-------
Audits HTTP response headers for security best practices. Missing security
headers are among the most common web application findings and can enable
or amplify other vulnerabilities (e.g., missing CSP makes XSS more impactful).

HOW IT WORKS
------------
Uses ``httpx`` to fetch the target URL and checks for the presence/absence
of 10 security-critical response headers, plus flags information-disclosure
headers that should be removed.

HEADERS CHECKED (based on OWASP Secure Headers Project)
--------------------------------------------------------
**Security headers (should be present):**
- ``Strict-Transport-Security`` (HSTS) — enforces HTTPS
- ``Content-Security-Policy`` (CSP) — controls resource loading
- ``X-Content-Type-Options`` — prevents MIME-type sniffing
- ``X-Frame-Options`` — prevents clickjacking
- ``X-XSS-Protection`` — legacy XSS filter
- ``Referrer-Policy`` — controls referrer leakage
- ``Permissions-Policy`` — restricts browser features (camera, mic, etc.)
- ``Cross-Origin-Opener-Policy`` (COOP) — isolates browsing context
- ``Cross-Origin-Resource-Policy`` (CORP) — resource sharing control
- ``Cross-Origin-Embedder-Policy`` (COEP) — embedding control

**Information disclosure headers (should be removed):**
- ``Server`` — reveals web server software and version
- ``X-Powered-By`` — reveals backend framework
- ``X-AspNet-Version`` — reveals ASP.NET version
- ``X-AspNetMvc-Version`` — reveals ASP.NET MVC version

WHEN TO USE
-----------
- Run on every target as part of the standard assessment.
- Results are important for the final report and for vulnerability chaining
  (e.g., missing ``HttpOnly`` on cookies + XSS = session hijacking).

REFERENCE
---------
OWASP Secure Headers Project:
https://owasp.org/www-project-secure-headers/
"""

import json

from utils.http_client import get_client

# ---------------------------------------------------------------------------
# Expected security headers and their descriptions
# ---------------------------------------------------------------------------

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "Content-Security-Policy": {
        "description": "Controls resources the browser is allowed to load",
        "severity": "HIGH",
        "recommendation": "Implement a strict CSP. At minimum: default-src 'self'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking via iframes",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (still useful for older browsers)",
        "severity": "LOW",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block'",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "MEDIUM",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "description": "Controls browser features available to the page",
        "severity": "MEDIUM",
        "recommendation": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context to prevent cross-origin attacks",
        "severity": "LOW",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin'",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource sharing at a resource level",
        "severity": "LOW",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin'",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls embedding of cross-origin resources",
        "severity": "LOW",
        "recommendation": "Add 'Cross-Origin-Embedder-Policy: require-corp'",
    },
}

# Headers that should NOT be present (information disclosure)
BAD_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


async def check_headers(url: str) -> str:
    """Audit security-related HTTP response headers for a target URL.

    Checks for the presence or absence of important security headers,
    flags missing headers with severity ratings and recommendations,
    and identifies information-disclosure headers that should be removed.

    Args:
        url: The target URL to audit (e.g., https://example.com).

    Returns:
        JSON string with audit results, missing headers, and recommendations.
    """
    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        try:
            resp = await client.get(url)
        except Exception as e:
            return json.dumps({"error": f"Failed to reach {url}: {e}"}, indent=2)

    headers = dict(resp.headers)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    present: list[dict] = []
    missing: list[dict] = []

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() in headers_lower:
            present.append({
                "header": header_name,
                "value": headers_lower[header_name.lower()],
                "description": info["description"],
                "status": "PRESENT",
            })
        else:
            missing.append({
                "header": header_name,
                "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"],
                "status": "MISSING",
            })

    # Information disclosure headers
    info_disclosure: list[dict] = []
    for bad in BAD_HEADERS:
        if bad.lower() in headers_lower:
            info_disclosure.append({
                "header": bad,
                "value": headers_lower[bad.lower()],
                "recommendation": f"Remove or suppress the '{bad}' header to reduce information leakage",
            })

    return json.dumps({
        "target": url,
        "status_code": resp.status_code,
        "present_headers": present,
        "missing_headers": missing,
        "information_disclosure": info_disclosure,
    }, indent=2)
