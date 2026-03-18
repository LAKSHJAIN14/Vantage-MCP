"""find_routes() — Discover endpoints via crawling + gobuster CLI for directory brute-forcing."""

import asyncio
import json
import os
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.http_client import get_client

# Path to the bundled common wordlist (fallback if gobuster's default isn't available)
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common.txt")

# Default gobuster wordlist path (standard Kali/SecLists location)
GOBUSTER_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# Regex patterns to extract API-like paths from inline JS
JS_PATH_PATTERNS = [
    re.compile(r"""["'](\/api\/[^"'\s]+)["']"""),
    re.compile(r"""["'](\/v\d+\/[^"'\s]+)["']"""),
    re.compile(r"""fetch\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""axios\.\w+\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""\.get\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""\.post\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""\.put\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""\.delete\(\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""href\s*=\s*["'](\/[^"'\s]+)["']"""),
    re.compile(r"""action\s*=\s*["'](\/[^"'\s]+)["']"""),
]


def _same_origin(base: str, target: str) -> bool:
    """Check if target URL is same-origin as base."""
    bp = urlparse(base)
    tp = urlparse(target)
    return tp.netloc == "" or tp.netloc == bp.netloc


def _normalize(base: str, href: str) -> str | None:
    """Resolve a potentially relative URL; return None if off-origin."""
    full = urljoin(base, href)
    if _same_origin(base, full):
        return full
    return None


async def _crawl_page(client, url: str) -> dict:
    """Crawl a single page and extract links, forms, and JS paths."""
    found: dict = {"links": set(), "forms": [], "js_paths": set()}

    try:
        resp = await client.get(url)
    except Exception:
        return found

    if "text/html" not in resp.headers.get("content-type", ""):
        return found

    soup = BeautifulSoup(resp.text, "lxml")

    # <a href>
    for tag in soup.find_all("a", href=True):
        resolved = _normalize(url, tag["href"])
        if resolved:
            found["links"].add(resolved)

    # <form action>
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        resolved = _normalize(url, action) if action else url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
            })
        found["forms"].append({
            "action": resolved,
            "method": method,
            "inputs": inputs,
        })

    # <script src>
    for script in soup.find_all("script", src=True):
        resolved = _normalize(url, script["src"])
        if resolved:
            found["links"].add(resolved)

    # <link href>
    for link in soup.find_all("link", href=True):
        resolved = _normalize(url, link["href"])
        if resolved:
            found["links"].add(resolved)

    # Inline JS path extraction
    for script in soup.find_all("script", src=False):
        if script.string:
            for pattern in JS_PATH_PATTERNS:
                for match in pattern.findall(script.string):
                    full = _normalize(url, match)
                    if full:
                        found["js_paths"].add(full)

    return found


async def _run_gobuster(url: str, wordlist: str | None = None, extra_args: str = "") -> dict:
    """Run gobuster dir mode via CLI and parse the output.

    Args:
        url: Target URL to brute-force.
        wordlist: Path to wordlist file. Uses default common.txt locations if None.
        extra_args: Additional gobuster arguments (e.g., "-x php,html -t 50").

    Returns:
        Dict with gobuster results or error info.
    """
    # Determine wordlist path
    if wordlist:
        wl = wordlist
    elif os.path.exists(GOBUSTER_DEFAULT_WORDLIST):
        wl = GOBUSTER_DEFAULT_WORDLIST
    else:
        # Use our bundled wordlist
        wl = os.path.abspath(WORDLIST_PATH)

    cmd = f"gobuster dir -u {url} -w {wl} -q --no-color {extra_args}"

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    except asyncio.TimeoutError:
        return {"error": "gobuster timed out after 120 seconds", "command": cmd}
    except FileNotFoundError:
        return {"error": "gobuster is not installed or not in PATH. Install it with: sudo apt install gobuster", "command": cmd}

    stdout_text = stdout.decode(errors="replace").strip()
    stderr_text = stderr.decode(errors="replace").strip()

    if proc.returncode != 0 and not stdout_text:
        return {
            "error": f"gobuster exited with code {proc.returncode}",
            "stderr": stderr_text,
            "command": cmd,
        }

    # Parse gobuster output lines like:
    # /admin                (Status: 302) [Size: 218]
    results = []
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line or line.startswith("="):
            continue
        # Try to parse structured output
        match = re.match(
            r"(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]",
            line,
        )
        if match:
            results.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)),
            })
        else:
            # Fallback: just include the raw line
            results.append({"raw": line})

    return {
        "command": cmd,
        "results_count": len(results),
        "results": results,
    }


async def find_routes(
    url: str,
    use_gobuster: bool = False,
    depth: int = 2,
    gobuster_wordlist: str | None = None,
    gobuster_extra_args: str = "",
) -> str:
    """Discover all routes/endpoints on a target web application.

    Crawls the target site by following links, parsing forms, and extracting
    API paths from inline JavaScript. Optionally runs gobuster for directory
    brute-forcing.

    Args:
        url: The target base URL (e.g., https://example.com).
        use_gobuster: If True, also run gobuster dir for path brute-forcing.
        depth: How many levels deep to recursively crawl (default 2).
        gobuster_wordlist: Custom wordlist path for gobuster. Falls back to
            /usr/share/wordlists/dirb/common.txt then bundled wordlist.
        gobuster_extra_args: Extra CLI args to pass to gobuster (e.g., "-x php,html -t 50").

    Returns:
        JSON string with discovered routes, forms, and gobuster results.
    """
    all_links: set[str] = set()
    all_forms: list[dict] = []
    all_js_paths: set[str] = set()
    visited: set[str] = set()
    gobuster_output: dict = {}

    async with get_client(follow_redirects=True, verify_ssl=False) as client:
        # BFS crawl
        queue = [(url, 0)]
        while queue:
            current_url, current_depth = queue.pop(0)
            if current_url in visited or current_depth > depth:
                continue
            visited.add(current_url)

            page = await _crawl_page(client, current_url)
            all_links.update(page["links"])
            all_forms.extend(page["forms"])
            all_js_paths.update(page["js_paths"])

            # Queue new same-origin links for next depth
            if current_depth < depth:
                for link in page["links"]:
                    if link not in visited and _same_origin(url, link):
                        parsed = urlparse(link)
                        ext = os.path.splitext(parsed.path)[1].lower()
                        if ext in ("", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp"):
                            queue.append((link, current_depth + 1))

    # Run gobuster (optional)
    if use_gobuster:
        gobuster_output = await _run_gobuster(url, gobuster_wordlist, gobuster_extra_args)

    # Build output
    routes = sorted(set(
        urlparse(u).path for u in all_links if urlparse(u).path
    ))
    js_routes = sorted(set(
        urlparse(u).path for u in all_js_paths if urlparse(u).path
    ))

    result = {
        "target": url,
        "crawled_pages": len(visited),
        "routes_found": routes,
        "js_extracted_routes": js_routes,
        "forms": all_forms,
    }

    if use_gobuster:
        result["gobuster"] = gobuster_output

    return json.dumps(result, indent=2, default=str)
