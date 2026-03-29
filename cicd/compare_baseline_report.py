"""compare_baseline_report() — Compare current findings against a previous baseline.

This is a **structured analysis tool** that takes a baseline pentest report and current
scan findings, then returns instructions for the automated agent to:
1. Identify which old vulnerabilities are now fixed
2. Identify which vulnerabilities persist
3. Identify any new vulnerabilities
4. Instruct the agent to re-test every baseline vulnerability
"""

import json


async def compare_baseline_report(
    baseline_report: str,
    current_findings: str,
    target_url: str = "",
) -> str:
    """Compare current scan findings against a previous baseline report.

    Call this tool when the user provides a previous pentest report and wants
    to check if vulnerabilities have been fixed after code changes. This tool
    returns instructions for performing a delta analysis and re-testing.

    If a baseline report is provided, the automated agent should RE-TEST every
    vulnerability from that report using the appropriate Vantage tools to
    confirm whether they've been fixed.

    Args:
        baseline_report: The previous/baseline penetration test report
            (full text — markdown, JSON, or plain text). This contains the
            vulnerabilities that were previously found.
        current_findings: Current scan results from this session's tool runs.
            Concatenate outputs from fingerprint, test_sqli, test_xss, etc.
        target_url: The target URL being tested (for context).

    Returns:
        Structured instructions for performing the comparison analysis
        and producing a delta report.
    """
    instructions = f"""# Baseline Comparison Analysis

## Inputs Provided
- **Target:** {target_url or "See baseline report"}
- **Baseline report:** {len(baseline_report)} characters provided
- **Current findings:** {len(current_findings)} characters provided

## Step 1 — Parse the Baseline Report

Extract every vulnerability from the baseline report. For each one, note:
- Vulnerability type (SQLi, XSS, SSTI, header issue, etc.)
- Affected endpoint and parameter
- Severity rating
- Payload or evidence that was used

List them in a table:

| # | Type | Endpoint | Parameter | Severity | Baseline Evidence |
|---|------|----------|-----------|----------|-------------------|
| 1 | ... | ... | ... | ... | ... |

## Step 2 — Re-Test Every Baseline Vulnerability

**CRITICAL: Do not just compare text — actively RE-TEST each baseline finding.**

For EACH vulnerability from the baseline:
1. Run the appropriate Vantage tool with the SAME or similar parameters:
   - SQLi → `test_sqli(url, param)` with same level/risk
   - XSS → `test_xss(url, param)` with same method
   - SSTI → `test_ssti(url, param)` with same method
   - Headers → `check_headers(url)`
   - Use `curl_request()` to manually verify with the exact baseline payload
2. Record whether the vulnerability is:
   - ✅ **FIXED** — no longer exploitable
   - ❌ **PERSISTS** — still vulnerable
   - ⚠️ **PARTIALLY FIXED** — some payloads blocked but others still work
   - 🔄 **CHANGED** — endpoint moved or parameter renamed (needs investigation)

## Step 3 — Identify New Vulnerabilities

Compare current findings against the baseline:
- Any finding in current results that was NOT in the baseline = **NEW vulnerability**
- Pay attention to:
  - New endpoints that didn't exist before
  - Parameters that were safe before but are now vulnerable
  - New security header regressions

## Step 4 — Produce the Delta Report

Format the output as:

### Remediation Status

| # | Vulnerability | Endpoint | Baseline Severity | Status | Notes |
|---|--------------|----------|-------------------|--------|-------|
| 1 | ... | ... | ... | ✅ Fixed / ❌ Persists / ⚠️ Partial | ... |

### New Vulnerabilities (Not in Baseline)

| # | Type | Endpoint | Parameter | Severity | Evidence |
|---|------|----------|-----------|----------|----------|
| 1 | ... | ... | ... | ... | ... |

### Summary
- **Baseline vulnerabilities:** [total count]
- **Fixed:** [count] ✅
- **Persisting:** [count] ❌
- **Partially fixed:** [count] ⚠️
- **New vulnerabilities found:** [count] 🆕
- **Overall security posture change:** [Improved / Degraded / Mixed]

### Recommendations
- Prioritized list of what still needs to be fixed
- Any regression areas that need attention

## Reference Data

### Baseline Report
```
{baseline_report[:5000]}{"... [truncated]" if len(baseline_report) > 5000 else ""}
```

### Current Findings
```
{current_findings[:5000]}{"... [truncated]" if len(current_findings) > 5000 else ""}
```
"""
    return instructions
