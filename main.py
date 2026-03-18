"""Vantage-MCP — Black-box web pentesting MCP server.

Run with:
    uv run python main.py              # HTTP streaming on port 5000
    uv run python main.py --stdio      # stdio mode (for Claude Desktop)
"""

import sys

import dotenv
dotenv.load_dotenv()

from fastmcp import FastMCP

from tools.fingerprint import fingerprint
from tools.find_routes import find_routes
from tools.test_sqli import test_sqli
from tools.test_ssti import test_ssti
from tools.test_xss import test_xss
from tools.check_headers import check_headers
from tools.generate_report import generate_report

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Vantage",
    instructions=(
        "Vantage is a black-box web penetration testing toolkit. "
        "Use the available tools to fingerprint targets, discover routes, "
        "test for SQL injection, SSTI, XSS, audit security headers, and "
        "generate structured pentest reports. "
        "Always start with fingerprint() and find_routes() before testing "
        "for specific vulnerabilities. Only test targets you have explicit "
        "authorization to test."
    ),
)

# ---------------------------------------------------------------------------
# Register tools
# ---------------------------------------------------------------------------

mcp.tool(fingerprint)
mcp.tool(find_routes)
mcp.tool(test_sqli)
mcp.tool(test_ssti)
mcp.tool(test_xss)
mcp.tool(check_headers)
mcp.tool(generate_report)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http", host="0.0.0.0", port=5000)

