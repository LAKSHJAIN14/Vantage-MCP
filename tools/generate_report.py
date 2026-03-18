"""generate_report() — Send all findings to an LLM to produce a pentest report."""

import json
import os

from openai import AsyncOpenAI

# ---------------------------------------------------------------------------
# Config — reads from environment variables
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "gpt-4o-mini"

REPORT_SYSTEM_PROMPT = """You are an expert penetration testing report writer.

You will receive the raw results from multiple black-box web pentesting tools
(fingerprinting, route discovery, SQL injection tests, SSTI tests, XSS tests,
security header audits, etc.).

Your job is to analyze ALL the findings and produce a clear, professional
penetration testing report in Markdown format with the following sections:

1. **Executive Summary** — Brief overview of the assessment and key risks found.
2. **Target Information** — What was tested, technologies detected.
3. **Findings** — Each vulnerability or issue found, rated by severity
   (Critical / High / Medium / Low / Informational). Include:
   - Description of the issue
   - Evidence from the tool output
   - Potential impact
   - Remediation recommendation
4. **Security Posture Summary** — Overall assessment of the target's security.
5. **Recommendations** — Prioritized list of fixes.

Be thorough but concise. Base everything strictly on the provided tool outputs —
do not fabricate findings. If a tool found nothing, note that the test was clean."""


async def generate_report(
    findings: str,
    target_url: str,
    model: str = "",
) -> str:
    """Send all tool findings to an LLM and return the generated pentest report.

    Sends the raw output from all pentesting tools to an LLM with a
    report-writing prompt. The LLM analyzes the findings and produces a
    structured penetration testing report.

    Args:
        findings: All collected tool outputs as a single string (JSON or text).
            Concatenate the results from fingerprint, find_routes, test_sqli,
            test_ssti, test_xss, check_headers, etc.
        target_url: The URL of the target that was assessed.
        model: LLM model to use (default: gpt-4o-mini). Set OPENAI_MODEL env
            var to override globally.

    Returns:
        The LLM-generated penetration testing report as a markdown string.

    Environment Variables:
        OPENAI_API_KEY: Required. Your OpenAI API key (or compatible provider key).
        OPENAI_BASE_URL: Optional. Custom base URL for OpenAI-compatible APIs
            (e.g., http://localhost:11434/v1 for Ollama).
        OPENAI_MODEL: Optional. Default model override.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL", None)
    use_model = model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL)

    if not api_key:
        return json.dumps({
            "error": "OPENAI_API_KEY environment variable is not set.",
            "hint": (
                "Set it before starting the server: export OPENAI_API_KEY='sk-...'\n"
                "For Ollama, also set: export OPENAI_BASE_URL='http://localhost:11434/v1'"
            ),
        }, indent=2)

    client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    user_message = (
        f"## Target\n{target_url}\n\n"
        f"## Raw Tool Outputs\n\n{findings}"
    )

    try:
        response = await client.chat.completions.create(
            model=use_model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
        )
        report = response.choices[0].message.content
        return report

    except Exception as e:
        return json.dumps({
            "error": f"LLM API call failed: {e}",
            "model": use_model,
            "base_url": base_url or "https://api.openai.com/v1",
        }, indent=2)
