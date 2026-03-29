"""test_sqli() — SQL injection testing via sqlmap CLI.

PURPOSE
-------
Detects SQL injection vulnerabilities by running ``sqlmap`` — the industry-
standard automated SQL injection tool — against a target URL and parameter.

HOW IT WORKS
------------
Wraps the ``sqlmap`` command-line tool:
1. Builds a sqlmap command with the target URL, parameter, and options.
2. Runs sqlmap in ``--batch`` (non-interactive) mode with ``--flush-session``.
3. Parses the stdout output to extract: vulnerable parameters, injection
   types (boolean-blind, time-blind, UNION, error-based, stacked queries),
   detected DBMS, and raw findings.

SQLMAP CLI REFERENCE
--------------------
sqlmap is a powerful SQL injection tool. Key options that can be passed via
``extra_args``:

    --level=<1-5>       Test thoroughness (1=basic, 5=exhaustive)
    --risk=<1-3>        Risk of tests (1=safe, 3=OR-based/heavy queries)
    -p <param>          Specific parameter to test
    --data=<data>       POST data string
    --dbms=<dbms>       Force backend DBMS (mysql, postgresql, mssql, oracle, sqlite)
    --threads=<n>       Number of concurrent threads (default 1, max 10)
    --technique=<tech>  SQL injection techniques to test:
                          B=Boolean-blind, T=Time-blind, U=UNION,
                          E=Error-based, S=Stacked queries
    --prefix=<prefix>   Injection payload prefix
    --suffix=<suffix>   Injection payload suffix
    --tamper=<script>   Tamper scripts for WAF bypass (e.g., space2comment,
                          randomcase, between)
    --dbs               Enumerate databases
    --tables            Enumerate tables
    --dump              Dump table contents
    --os-shell          Attempt OS command execution
    --cookie=<cookie>   HTTP Cookie header value
    --random-agent      Use random User-Agent header
    --proxy=<proxy>     Use a proxy (http://host:port)
    --tor               Use Tor anonymity network

REQUIREMENTS
------------
``sqlmap`` must be installed and available in PATH.
Install: ``sudo apt install sqlmap`` or ``pip install sqlmap``

WHEN TO USE
-----------
- Test every parameter discovered by ``find_routes()`` that interacts with
  a database (search, login, product IDs, filters, etc.).
- Start with ``level=1, risk=1`` for speed. Increase if initial scan is
  clean but the parameter looks database-backed.
- Use ``--dbms=mysql`` (via extra_args) if fingerprinting revealed the DBMS.
"""

import asyncio
import json
import re
import tempfile

# ---------------------------------------------------------------------------
# sqlmap CLI wrapper
# ---------------------------------------------------------------------------


async def test_sqli(
    url: str,
    param: str = "",
    data: str = "",
    method: str = "GET",
    level: int = 1,
    risk: int = 1,
    extra_args: str = "",
    timeout: int = 180,
) -> str:
    """Test for SQL injection vulnerabilities using sqlmap.

    Runs sqlmap via command line against the specified URL/parameter and
    returns the parsed results.

    Args:
        url: The target URL. For GET, include the query string (e.g.,
            http://example.com/page?id=1). For POST, provide the base URL.
        param: Specific parameter to test (optional; sqlmap auto-detects if omitted).
        data: POST data string (e.g., "user=admin&pass=test"). When provided,
            sqlmap will test as POST regardless of the method argument.
        method: HTTP method hint — "GET" or "POST" (default "GET").
            If data is provided, POST is used automatically.
        level: sqlmap --level (1-5). Higher = more payloads tested (default 1).
        risk: sqlmap --risk (1-3). Higher = more aggressive tests (default 1).
        extra_args: Additional sqlmap arguments (e.g., "--dbms=mysql --threads=4").
        timeout: Max seconds to let sqlmap run before killing it (default 180).

    Returns:
        JSON string with sqlmap findings.
    """
    # Build the sqlmap command as a safe argument list — never pass
    # user-controlled strings through a shell to avoid command injection.
    cmd_args: list[str] = [
        "sqlmap",
        "-u", url,
        "--batch",                     # Non-interactive
        f"--level={level}",
        f"--risk={risk}",
        "--flush-session",             # Fresh scan every time
        "--disable-coloring",
    ]

    if param:
        cmd_args.extend(["-p", param])

    if data:
        cmd_args.extend(["--data", data])

    if extra_args:
        # Safely tokenize extra_args without shell interpretation
        import shlex
        cmd_args.extend(shlex.split(extra_args))

    # Human-readable command string for logging only (not executed)
    import shlex as _shlex
    cmd_display = " ".join(_shlex.quote(a) for a in cmd_args)

    # Run sqlmap via exec (no shell) — safe from injection
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return json.dumps({
            "error": f"sqlmap timed out after {timeout} seconds",
            "command": cmd_display,
            "hint": "Try increasing the timeout or narrowing the test with -p <param>",
        }, indent=2)
    except FileNotFoundError:
        return json.dumps({
            "error": "sqlmap is not installed or not in PATH. Install it with: sudo apt install sqlmap",
            "command": cmd_display,
        }, indent=2)

    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")

    if proc.returncode != 0 and not stdout_text.strip():
        return json.dumps({
            "error": f"sqlmap exited with code {proc.returncode}",
            "stderr": stderr_text.strip(),
            "command": cmd_display,
        }, indent=2)

    # Parse sqlmap output
    results = _parse_sqlmap_output(stdout_text)
    results["command"] = cmd_display

    return json.dumps(results, indent=2)


def _parse_sqlmap_output(output: str) -> dict:
    """Parse sqlmap stdout into a structured result dict."""

    result: dict = {
        "vulnerable_params": [],
        "injection_types": [],
        "dbms": None,
        "is_vulnerable": False,
        "raw_findings": [],
        "errors": [],
    }

    lines = output.splitlines()

    for line in lines:
        line_stripped = line.strip()

        # Detect vulnerable parameter
        # sqlmap prints: "Parameter: id (GET)" or similar
        param_match = re.search(
            r"Parameter:\s+(\S+)\s+\((\w+)\)",
            line_stripped,
        )
        if param_match:
            result["vulnerable_params"].append({
                "param": param_match.group(1),
                "method": param_match.group(2),
            })

        # Detect injection type
        # e.g., "Type: boolean-based blind"
        type_match = re.search(r"Type:\s+(.+)", line_stripped)
        if type_match:
            result["injection_types"].append(type_match.group(1).strip())

        # Detect DBMS
        # e.g., "back-end DBMS: MySQL >= 5.0"
        dbms_match = re.search(
            r"back-end DBMS:\s+(.+)",
            line_stripped,
            re.IGNORECASE,
        )
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()

        # Detect vulnerability confirmation
        if "is vulnerable" in line_stripped.lower() or "injectable" in line_stripped.lower():
            result["is_vulnerable"] = True

        # Capture sqlmap findings/info lines (skip noise)
        if line_stripped.startswith("[") and any(
            marker in line_stripped
            for marker in ["[INFO]", "[WARNING]", "[CRITICAL]", "[ERROR]"]
        ):
            result["raw_findings"].append(line_stripped)

        # Capture critical errors
        if "[CRITICAL]" in line_stripped:
            result["errors"].append(line_stripped)

    # If we found injection types, it's vulnerable
    if result["injection_types"]:
        result["is_vulnerable"] = True

    # De-duplicate injection types
    result["injection_types"] = list(dict.fromkeys(result["injection_types"]))

    return json.dumps(result, indent=2)
