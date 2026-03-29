"""suggest_code_fix() — Guide the security scanner to review source code and suggest vulnerability fixes.

This is a **structured analysis tool** designed for use alongside a GitHub MCP server.
When called with vulnerability details, it returns formal instructions
for the agent to:
1. Use GitHub MCP tools to fetch the relevant source code
2. Identify the root cause
3. Suggest a fix with before/after code
4. Format the response as a PR review comment
"""

import json


async def suggest_code_fix(
    vulnerability_type: str,
    endpoint: str,
    param: str,
    evidence: str,
    repo_owner: str = "",
    repo_name: str = "",
    file_path_hint: str = "",
) -> str:
    """Generate instructions to review source code and suggest a fix for a found vulnerability.

    Call this tool after finding a vulnerability to get structured guidance on
    using the GitHub MCP server to fetch source code, identify the root cause,
    and produce a PR-ready fix suggestion.

    This tool works best when a GitHub MCP server is also connected, giving
    the agent access to `get_file_contents`, `search_code`, etc.

    Args:
        vulnerability_type: The type of vulnerability found (e.g., "SQL Injection",
            "XSS", "SSTI", "Missing Security Headers", "Information Disclosure").
        endpoint: The affected endpoint/route (e.g., "/api/users?id=1").
        param: The vulnerable parameter (e.g., "id", "search", "username").
        evidence: The evidence from the scan — payload used, response snippet,
            or tool output that confirms the vulnerability.
        repo_owner: GitHub repository owner (e.g., "acme-corp"). If empty,
            the agent should ask the user.
        repo_name: GitHub repository name (e.g., "web-app"). If empty,
            the agent should ask the user.
        file_path_hint: Optional hint about which source file handles this
            endpoint (e.g., "src/controllers/users.py"). If empty, the agent
            should search the codebase.

    Returns:
        Structured instructions for the automated agent to fetch code, analyze, and
        produce a PR comment with the fix.
    """
    repo_block = ""
    if repo_owner and repo_name:
        repo_block = f"**Repository:** `{repo_owner}/{repo_name}`"
    else:
        repo_block = "**Repository:** Ask the user for the GitHub repo (owner/name) if not already known."

    search_block = ""
    if file_path_hint:
        search_block = f"""
### Step 1 — Fetch the Source File
Use the GitHub MCP tool `get_file_contents` to fetch: `{file_path_hint}`
from the repo `{repo_owner}/{repo_name}`.
"""
    else:
        search_block = f"""
### Step 1 — Find the Relevant Source Code
Use the GitHub MCP tool `search_code` to find the code handling this endpoint:
- Search query: `"{endpoint.split('?')[0].split('/')[-1]}"` or `"{param}"` in the repo.
- Look for route definitions, controller functions, or request handlers that match `{endpoint}`.
- Common patterns to search for:
  - `@app.route("{endpoint.split('?')[0]}")` (Flask)
  - `router.get("{endpoint.split('?')[0]}")` (Express)
  - `def {endpoint.split('?')[0].split('/')[-1]}` (Django)
  - `{param}` used in SQL queries, template rendering, or HTML output.

Once found, use `get_file_contents` to fetch the full file.
"""

    # Vulnerability-specific fix guidance
    fix_patterns = {
        "sql injection": {
            "cause": "User input is concatenated directly into SQL queries without parameterization.",
            "fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
            "example_bad": f'query = f"SELECT * FROM users WHERE {param} = \'{{{param}}}\'"',
            "example_good": f'cursor.execute("SELECT * FROM users WHERE {param} = %s", ({param},))',
        },
        "xss": {
            "cause": "User input is reflected in HTML output without encoding/escaping.",
            "fix": "HTML-encode all user input before rendering. Use template auto-escaping. Apply Content-Security-Policy.",
            "example_bad": f'return f"<p>Results for: {{{param}}}</p>"',
            "example_good": f'from markupsafe import escape\nreturn f"<p>Results for: {{escape({param})}}</p>"',
        },
        "ssti": {
            "cause": "User input is passed directly into a template engine for rendering.",
            "fix": "Never pass user input as template source. Use templates with variable substitution instead.",
            "example_bad": f'return render_template_string({param})',
            "example_good": f'return render_template("results.html", query={param})',
        },
    }

    vuln_lower = vulnerability_type.lower()
    fix_info = None
    for key, val in fix_patterns.items():
        if key in vuln_lower:
            fix_info = val
            break

    fix_block = ""
    if fix_info:
        fix_block = f"""
### Common Root Cause for {vulnerability_type}
**Why it happens:** {fix_info['cause']}
**How to fix:** {fix_info['fix']}

**Typical vulnerable code:**
```python
{fix_info['example_bad']}
```

**Fixed code:**
```python
{fix_info['example_good']}
```
"""
    else:
        fix_block = f"""
### Root Cause Analysis for {vulnerability_type}
Look for where `{param}` is received from the request and how it's used.
Check if it's sanitized, validated, or escaped before being used in sensitive operations.
"""

    instructions = f"""# Source Code Review: {vulnerability_type} on `{endpoint}`

{repo_block}

## Vulnerability Details
- **Type:** {vulnerability_type}
- **Endpoint:** `{endpoint}`
- **Parameter:** `{param}`
- **Evidence:** {evidence}
{search_block}
### Step 2 — Identify the Root Cause
In the source code, trace the flow of the `{param}` parameter:
1. Where is it received? (request handler, query param, form data)
2. Is it validated or sanitized?
3. Where is it used in a dangerous operation? (SQL query, template render, HTML output, shell command)
{fix_block}
### Step 3 — Write the Fix

Produce a fix and format your response as a **PR review comment** using this exact structure:

---

## 🔒 Security Fix: {vulnerability_type} in `{endpoint}`

**Severity:** [Critical/High/Medium based on impact]
**Parameter:** `{param}`
**Found by:** Vantage automated security scan

### Issue
[One-paragraph description of the vulnerability and its impact]

### Root Cause
[Point to the exact line(s) of code and explain why it's vulnerable]

### Suggested Fix

```diff
- [vulnerable code line]
+ [fixed code line]
```

### Additional Recommendations
- [Input validation recommendations]
- [Defense-in-depth measures]
- [Related security headers or config changes]

### References
- [Link to OWASP page for this vuln type]
- [Link to framework-specific secure coding guide]

---

Make sure the diff is VALID and applies to the actual code you found in the repo.
"""
    return instructions
