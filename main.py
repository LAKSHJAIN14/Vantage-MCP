"""Vantage-MCP — Black-box web pentesting MCP server.

Run with:
    uv run python main.py              # HTTP streaming on port 5000
    uv run python main.py --stdio      # stdio mode (for Claude Desktop)
"""

import sys

import dotenv
dotenv.load_dotenv()

from fastmcp import FastMCP

# Core tools
from tools.fingerprint import fingerprint
from tools.find_routes import find_routes
from tools.test_sqli import test_sqli
from tools.test_ssti import test_ssti
from tools.test_xss import test_xss
from tools.check_headers import check_headers
from tools.cve_lookup import cve_lookup

# Utility tools
from tools.curl_request import curl_request
from tools.authenticate import authenticate

# Analysis & Reporting tools
from tools.generate_report import generate_report

# Strategy & Guidance Tools
from prompts.guide_pentest_workflow import guide_pentest_workflow
from prompts.guide_chain_vulnerabilities import guide_chain_vulnerabilities
from tools.get_vulnerability_knowledge import get_vulnerability_knowledge

# CI/CD & Integration
from cicd.suggest_code_fix import suggest_code_fix
from cicd.compare_baseline_report import compare_baseline_report

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Vantage",
    instructions=(
        "Vantage is a black-box web penetration testing toolkit. "
        "ALWAYS call guide_pentest_workflow() FIRST when starting a new pentest — "
        "it gives you the optimal testing strategy. "
        "Use the available tools to fingerprint targets, discover routes, "
        "test for SQL injection, SSTI, XSS, audit security headers, and "
        "generate structured pentest reports. "
        "Use cve_lookup() to check detected framework versions for known vulnerabilities. "
        "Use authenticate() when the user provides credentials. "
        "Use curl_request() for manual HTTP requests. "
        "When encountering WAFs or complex filters, call get_vulnerability_knowledge() "
        "to search the built-in knowledge base for advanced bypass techniques. "
        "After testing, call guide_chain_vulnerabilities() to find attack chains. "
        "Use suggest_code_fix() to generate PR-ready fix suggestions. "
        "Use compare_baseline_report() when the user provides a previous report. "
        "Only test targets you have explicit authorization to test."
    ),
)

# ---------------------------------------------------------------------------
# Register tools
# ---------------------------------------------------------------------------

# Core scanning tools
mcp.tool(fingerprint)
mcp.tool(find_routes)
mcp.tool(test_sqli)
mcp.tool(test_ssti)
mcp.tool(test_xss)
mcp.tool(check_headers)
mcp.tool(cve_lookup)

# Utility tools
mcp.tool(curl_request)
mcp.tool(authenticate)

# Reporting & analysis tools
mcp.tool(generate_report)
mcp.tool(suggest_code_fix)
mcp.tool(compare_baseline_report)

# Strategy / guidance tools
mcp.tool(guide_pentest_workflow)
mcp.tool(guide_chain_vulnerabilities)
mcp.tool(get_vulnerability_knowledge)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http", host="0.0.0.0", port=5000)
