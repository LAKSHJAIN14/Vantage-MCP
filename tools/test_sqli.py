"""test_sqli() — SQL injection testing via sqlmap CLI."""

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
    # Build the sqlmap command
    cmd_parts = [
        "sqlmap",
        f"-u \"{url}\"",
        "--batch",                    # Non-interactive
        f"--level={level}",
        f"--risk={risk}",
        "--flush-session",            # Fresh scan every time
        "--disable-coloring",
    ]

    if param:
        cmd_parts.append(f"-p {param}")

    if data:
        cmd_parts.append(f"--data=\"{data}\"")

    if extra_args:
        cmd_parts.append(extra_args)

    cmd = " ".join(cmd_parts)

    # Run sqlmap
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return json.dumps({
            "error": f"sqlmap timed out after {timeout} seconds",
            "command": cmd,
            "hint": "Try increasing the timeout or narrowing the test with -p <param>",
        }, indent=2)
    except FileNotFoundError:
        return json.dumps({
            "error": "sqlmap is not installed or not in PATH. Install it with: sudo apt install sqlmap",
            "command": cmd,
        }, indent=2)

    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")

    if proc.returncode != 0 and not stdout_text.strip():
        return json.dumps({
            "error": f"sqlmap exited with code {proc.returncode}",
            "stderr": stderr_text.strip(),
            "command": cmd,
        }, indent=2)

    # Parse sqlmap output
    results = _parse_sqlmap_output(stdout_text)
    results["command"] = cmd

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

    return result
