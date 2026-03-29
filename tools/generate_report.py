"""generate_report() — Guide the LLM to output a structured tabular report in chat.

This is a **tool-as-prompt**: when called, it returns strict formatting
instructions. The LLM then uses its own capabilities to format the findings
into a beautiful markdown table directly in the chat interface, instead of
making a secondary API call.
"""

import json


async def generate_report() -> str:
    """Get formatting instructions to present pentest findings to the user.

    Call this tool at the VERY END of the pentest, after all tests are
    complete and chains have been analyzed. It gives you the exact markdown
    structure you MUST use to present the final results to the user in the
    chat interface.

    Returns:
        Structured formatting instructions for the final report.
    """
    instructions = """# Final Report Formatting Instructions

You have completed the pentest. Now, you must present the results directly to the user in this chat.
Do NOT use a secondary API to generate the report. You will write the report yourself using the exact structure below.

## Required Format

Use this exact Markdown structure for your next response:

---

# 🛡️ Vantage Security Assessment Report

**Target:** `[insert target URL]`
**Execution Time:** `[insert rough estimate, e.g., "Just now"]`

## 📊 Coverage Summary

Create a comprehensive table showing EVERYTHING you tested, including clean results. This proves test coverage.

| Endpoint | Parameter | Test Performed | Result | Severity |
|----------|-----------|----------------|--------|----------|
| `/login` | `username` | SQL Injection | Vulnerable - time-based blind | 🔴 Critical |
| `/login` | `password` | SQL Injection | Clean | 🟢 OK |
| `/search` | `q` | XSS | Reflected (unescaped) | 🟠 High |
| `/` | `-` | Security Headers | Missing CSP, HSTS | 🟡 Medium |

*(Add a row for every parameter and test type you performed)*

## 🚨 Detailed Findings

For each vulnerability found (excluding Clean results), provide:

### [1] [Vulnerability Name] on `[Endpoint]`
- **Severity:** [Critical / High / Medium / Low / Info]
- **Parameter:** `[param name]`
- **Evidence:** 
  ```http
  [Insert the exact payload used and a short snippet of the response]
  ```
- **Impact:** [What an attacker could do]
- **Remediation:** [How to fix it]

### [2] ...

## 🔗 Attack Chains
*(If you found any vulnerability chains using `guide_chain_vulnerabilities`, list them here. Otherwise omit this section).*

## 🔒 Security Headers Audit

| Header | Status | Risk |
|--------|--------|------|
| `Content-Security-Policy` | [Missing/Present] | [Risk] |
| `X-Frame-Options` | [Missing/Present] | [Risk] |

## 🛠️ Next Steps & Recommendations
1. [Highest priority fix]
2. [Second priority fix]
3. ...

---

**CRITICAL RULE:** Do not invent findings. Base the tables strictly on the actual tool outputs you received during this session.
"""
    return instructions
