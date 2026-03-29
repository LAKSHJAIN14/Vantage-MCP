"""fingerprint() — Technology & framework fingerprinting via response analysis.

PURPOSE
-------
Identifies the technology stack of a target web application by analyzing
HTTP response headers, cookies, HTML meta tags, and probing well-known
technology-specific paths. This is the **first tool to use** in any pentest.

HOW IT WORKS
------------
Uses ``httpx`` (via the shared HTTP client) to:

1. **Fetch the main page** and analyze response headers for server software,
   framework-specific headers (``X-Powered-By``, ``X-AspNet-Version``, etc.),
   and CDN/proxy indicators (Cloudflare, Varnish, AWS CloudFront).
2. **Analyze cookies** — session cookie names reveal the backend
   (``PHPSESSID`` → PHP, ``JSESSIONID`` → Java, ``connect.sid`` → Express).
3. **Parse HTML meta tags** — the ``<meta name="generator">`` tag often
   reveals CMS name and version (WordPress, Drupal, etc.).
4. **Probe known paths** — requests paths like ``/wp-login.php``,
   ``/admin/login/``, ``/.git/HEAD``, ``/.env`` to detect specific
   technologies and critical exposures.

WHEN TO USE
-----------
- **Always run first** — fingerprinting results inform which vulnerability
  tests to prioritize.
- Results from this tool help you understand what template engine to expect
  (for SSTI), what database might be in use (for SQLi), and what
  framework-specific vulnerabilities to look for.
"""

import json
import re
from urllib.parse import urljoin

from utils.http_client import get_client

# ---------------------------------------------------------------------------
# Signature maps
# ---------------------------------------------------------------------------

# Header → Technology mapping
HEADER_SIGNATURES: dict[str, str] = {
    "X-Powered-By": "x-powered-by",
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Generator": "generator",
    "X-Drupal-Cache": "Drupal",
    "X-Drupal-Dynamic-Cache": "Drupal",
    "X-Django-Debug": "Django",
    "X-Varnish": "Varnish Cache",
    "X-Cache": "CDN/Caching Layer",
    "CF-RAY": "Cloudflare",
    "X-Amz-Cf-Id": "AWS CloudFront",
    "X-Vercel-Id": "Vercel",
    "X-Netlify-Request-Id": "Netlify",
    "X-Turbo-Charged-By": "LiteSpeed",
}

# Cookie name → Technology
COOKIE_SIGNATURES: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Servlet/JSP)",
    "ASP.NET_SessionId": "ASP.NET",
    "connect.sid": "Node.js (Express)",
    "laravel_session": "Laravel (PHP)",
    "csrftoken": "Django",
    "_csrf_token": "Phoenix/Rails",
    "rack.session": "Ruby (Rack)",
    "XSRF-TOKEN": "Angular / Laravel",
    "_session_id": "Ruby on Rails",
    "ci_session": "CodeIgniter",
    "wordpress_logged_in": "WordPress",
    "wp-settings": "WordPress",
    "grafana_session": "Grafana",
}

# Paths to probe for further fingerprinting
PROBE_PATHS: list[dict[str, str]] = [
    {"path": "/robots.txt", "tech": "General (robots.txt present)"},
    {"path": "/sitemap.xml", "tech": "General (sitemap.xml present)"},
    {"path": "/wp-login.php", "tech": "WordPress"},
    {"path": "/wp-admin/", "tech": "WordPress"},
    {"path": "/administrator/", "tech": "Joomla"},
    {"path": "/user/login", "tech": "Drupal"},
    {"path": "/admin/login/", "tech": "Django Admin"},
    {"path": "/.env", "tech": "Exposed .env file (CRITICAL)"},
    {"path": "/.git/HEAD", "tech": "Exposed .git directory (CRITICAL)"},
    {"path": "/server-status", "tech": "Apache mod_status"},
    {"path": "/elmah.axd", "tech": "ASP.NET ELMAH error log"},
    {"path": "/graphql", "tech": "GraphQL endpoint"},
    {"path": "/api/swagger.json", "tech": "Swagger/OpenAPI"},
    {"path": "/swagger-ui.html", "tech": "Swagger UI"},
]


async def fingerprint(url: str) -> str:
    """Identify technologies, frameworks, cookies, and server info for a target URL.

    Analyzes HTTP response headers, cookies, HTML meta tags, and probes common
    technology-specific paths to build a comprehensive technology profile of
    the target. This should be the **first tool called** in any pentest
    engagement.

    Session cookies from a prior ``authenticate()`` call are automatically
    included.

    Args:
        url: The target URL to fingerprint (e.g., https://example.com).

    Returns:
        JSON string containing:
        - ``server``: Web server software (Apache, Nginx, etc.)
        - ``technologies``: All detected technologies and frameworks.
        - ``cookies``: Cookie details with security flag analysis.
        - ``meta_generator``: CMS generator tag if found.
        - ``probed_paths``: Results of probing known tech-specific paths.
    """
    results: dict = {
        "target": url,
        "server": None,
        "technologies": [],
        "cookies": [],
        "meta_generator": None,
        "probed_paths": [],
        "headers_raw": {},
    }

    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        # ------------------------------------------------------------------
        # 1. Main page response analysis
        # ------------------------------------------------------------------
        try:
            resp = await client.get(url)
        except Exception as e:
            return json.dumps({"error": f"Failed to reach {url}: {e}"}, indent=2)

        headers = dict(resp.headers)
        results["headers_raw"] = headers

        # Server header
        if "server" in headers:
            results["server"] = headers["server"]
            results["technologies"].append(f"Server: {headers['server']}")

        # Signature headers
        for header_name, tech_label in HEADER_SIGNATURES.items():
            val = headers.get(header_name.lower())
            if val:
                label = f"{tech_label}: {val}" if tech_label == "x-powered-by" or tech_label == "generator" else tech_label
                results["technologies"].append(label)

        # ------------------------------------------------------------------
        # 2. Cookie analysis
        # ------------------------------------------------------------------
        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_info: dict = {"raw": cookie_header}
            # Extract cookie name
            name = cookie_header.split("=")[0].strip()
            cookie_info["name"] = name

            # Flags
            lower = cookie_header.lower()
            cookie_info["httponly"] = "httponly" in lower
            cookie_info["secure"] = "secure" in lower
            # SameSite
            m = re.search(r"samesite\s*=\s*(\w+)", lower)
            cookie_info["samesite"] = m.group(1) if m else "not set"

            # Technology inference
            for sig, tech in COOKIE_SIGNATURES.items():
                if sig.lower() in name.lower():
                    cookie_info["technology"] = tech
                    if tech not in [t for t in results["technologies"]]:
                        results["technologies"].append(f"Cookie fingerprint: {tech}")
                    break

            results["cookies"].append(cookie_info)

        # ------------------------------------------------------------------
        # 3. HTML meta generator tag
        # ------------------------------------------------------------------
        body = resp.text
        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if gen_match:
            results["meta_generator"] = gen_match.group(1)
            results["technologies"].append(f"Meta generator: {gen_match.group(1)}")

        # ------------------------------------------------------------------
        # 4. Probe common technology paths
        # ------------------------------------------------------------------
        for probe in PROBE_PATHS:
            probe_url = urljoin(url, probe["path"])
            try:
                r = await client.get(probe_url)
                if r.status_code == 200:
                    results["probed_paths"].append(
                        {"path": probe["path"], "status": 200, "tech": probe["tech"]}
                    )
                    if probe["tech"] not in results["technologies"]:
                        results["technologies"].append(probe["tech"])
            except Exception:
                pass

    # De-duplicate technologies
    results["technologies"] = list(dict.fromkeys(results["technologies"]))
    # Remove raw headers from final output to keep it concise
    del results["headers_raw"]

    return json.dumps(results, indent=2)
