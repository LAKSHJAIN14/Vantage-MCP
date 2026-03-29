"""guide_chain_vulnerabilities() — Analyze findings for vulnerability chains.

This is an **analysis integration tool**: when called with a summary of all findings,
it returns instructions that guide the automated agent to identify multi-step attack
chains where individual vulnerabilities combine for higher impact.

Named 'guide_chain_vulnerabilities' to be invoked after testing is done.
"""

import json


async def guide_chain_vulnerabilities(
    findings_summary: str,
) -> str:
    """Analyze all pentest findings to identify vulnerability chains and escalation paths.

    Call this tool AFTER all vulnerability testing is complete. Pass in a
    summary of every finding from fingerprint, SQLi, SSTI, XSS, and header
    checks. Returns a structured analysis framework for chaining vulns.

    Args:
        findings_summary: A text summary of all findings so far. Include:
            vulnerability type, affected endpoint, parameter, severity,
            and any relevant details (e.g., "XSS on /search?q= reflected
            unescaped", "Missing HttpOnly on PHPSESSID cookie").

    Returns:
        A structured chain analysis prompt with specific chains to investigate
        based on the actual findings provided.
    """
    analysis = f"""# Vulnerability Chain Analysis

## Your Findings
{findings_summary}

## Analysis Instructions

Look at every finding above and map out how they connect. For each combination, ask:
"Can finding A make finding B worse, or vice versa?"

### Chain Patterns to Check Against Your Findings

**1. XSS + Weak Cookie Flags → Session Hijacking → Account Takeover**
- Do you have XSS (reflected or stored) on any endpoint?
- Did `check_headers` or `fingerprint` show cookies WITHOUT `HttpOnly`?
- If BOTH → attacker steals session cookie via `document.cookie` → full account takeover.
- Severity escalation: XSS (Medium) + No HttpOnly (Low) = Account Takeover (Critical).

**2. SQLi + Admin Panel → Full Takeover**
- Did `test_sqli` find injection anywhere?
- Did `find_routes` discover an admin panel (`/admin`, `/wp-admin`, `/dashboard`)?
- If BOTH → dump credentials via SQLi → login to admin panel → control everything.
- Next step: Use `test_sqli` with `extra_args="--dbs --tables"` to enumerate.

**3. SSTI → RCE + No CSP → Data Exfiltration**
- Did `test_ssti` confirm template injection (computed values in response)?
- Is CSP missing from `check_headers`?
- If BOTH → execute server code AND exfiltrate data to external server.
- Severity: Always Critical.

**4. Information Disclosure → Targeted Attacks**
- Did `fingerprint` find exposed `.env`, `.git/HEAD`, or debug mode?
- Any specific framework version detected?
- Leaked secrets enable: targeted CVE exploitation, credential reuse, source code access.
- If you find a credential through information disclosure then you should use that to authenticate and then continue pentesting on authenticated endpoints as well

**5. Missing CSRF + Any Auth-Based Action → Forged Actions**
- Are there forms WITHOUT CSRF tokens (check `find_routes` form data)?
- Combined with XSS → wormable attack that propagates through users.

**6. XSS + Open Redirect → Phishing**
- XSS on a trusted domain + redirect capability = convincing phishing.

**7. Multiple SQLi Points → Lateral Movement**
- SQLi on multiple endpoints? Different databases might be accessible.
- Can you pivot from one SQLi to access other tables/databases?

**8. Known CVE + Detected Version → Direct Exploitation**
- Did `cve_lookup` find any active CVEs for detected technologies?
- Known CVE with public exploit → potentially Critical without any other vuln needed.

## Output Structure

For each chain you identify, respond with:

| Chain | Vulns Combined | Attack Path | Impact | Severity |
|-------|---------------|-------------|--------|----------|
| [Name] | [List] | [Steps] | [What attacker achieves] | [Critical/High/Medium] |

Then for each chain, detail:
1. **Prerequisites** — what the attacker needs
2. **Steps** — exact sequence of exploitation
3. **Impact** — what they gain
4. **Remediation** — fix the weakest link to break the chain

## Additional Tests to Suggest

Based on the chains found, recommend specific follow-up tests the user should run
(e.g., "Re-test /login with `test_sqli` at level=5 to confirm credential dump capability").
"""
    return analysis
