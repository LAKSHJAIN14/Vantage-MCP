# 🕵️‍♂️ Vantage MCP

**An Intelligent, Black-Box Web Penetration Testing MCP Server**

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/Powered%20by-FastMCP-ff69b4.svg)](https://github.com/fastmcp/fastmcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hackathon](https://img.shields.io/badge/Hackathon-Ready-brightgreen.svg)]()

<p align="center">
  Vantage is an AI-driven, automated security toolkit built on the Model Context Protocol (MCP). It equips LLMs with professional-grade penetration testing tools to discover, analyze, and report web vulnerabilities autonomously.
</p>

</div>

---

## 1. Description

**Vantage** transforms any MCP-compatible Large Language Model (like Claude Desktop) into a sophisticated application security engineer. By providing an arsenal of black-box testing tools directly to the LLM's context, Vantage allows the AI to strategically footprint targets, probe for common vulnerabilities (SQLi, XSS, SSTI), evaluate security headers, and formulate complex attack chains. It acts as the ultimate bridge between advanced AI reasoning and practical web security analysis.

## 2. Working of Agent

The Vantage Agent operates through a strategic, autonomous feedback loop powered by the Model Context Protocol:

1. **Strategy Formulation:** The LLM initiates a session by invoking `guide_pentest_workflow()`, which establishes a structured attack plan.
2. **Reconnaissance:** The agent utilizes `fingerprint()` and `find_routes()` to map the target's attack surface and technology stack.
3. **Targeted Exploitation:** Based on the discovered stack, it executes context-aware attacks using tools like `test_sqli()`, `test_ssti()`, and `test_xss()`. If a WAF or filter is encountered, it queries `get_vulnerability_knowledge()` for bypass techniques.
4. **Analysis & Chaining:** After probing, it runs `guide_chain_vulnerabilities()` to connect isolated flaws into high-impact attack chains. It also references `cve_lookup()` to match framework versions with known public exploits.
5. **Actionable Reporting:** Finally, the agent invokes `generate_report()` and `suggest_code_fix()` to deliver a beautifully structured, developer-ready Markdown report with PR-ready mitigation code.

## 3. Features

- **🧠 AI-Driven Strategy:** Built-in guidance tools prompt the LLM to test methodically rather than randomly.
- **🔍 Comprehensive Reconnaissance:** Automated endpoint discovery and framework fingerprinting.
- **🛡️ Core Vulnerability Scanning:** - SQL Injection (SQLi)
  - Server-Side Template Injection (SSTI)
  - Cross-Site Scripting (XSS)
- **📚 Advanced Threat Intelligence:** CVE lookup capabilities and an internal vulnerability knowledge base for bypassing WAFs and complex filters.
- **⛓️ Attack Chaining:** Intelligently identifies how multiple low-severity bugs can be chained for critical impact.
- **🔐 Authenticated Testing:** Support for providing credentials to test behind login portals.
- **CI/CD Integration:** Capable of generating PR-ready code fixes (`suggest_code_fix()`) and comparing current findings against historical baselines (`compare_baseline_report()`).
- **📊 Beautiful Reports:** Automatically generates structured, easy-to-read penetration testing reports with severity mappings and remediation steps.

## 4. Getting Started

### 4.1 Prerequisites

Before installing Vantage, ensure you have the following installed:
- **Python:** `3.12` or higher
- **Package Manager:** `uv` (Recommended for fast dependency resolution)
- **LLM Client:** An MCP-compatible client like [Claude Desktop](https://claude.ai/download)

### 4.2 Installation

Clone the repository and install the dependencies:

```bash
# Clone the repository
git clone [https://github.com/lakshjain14/vantage-mcp.git](https://github.com/lakshjain14/vantage-mcp.git)
cd vantage-mcp

# Install dependencies using uv
uv sync
````

### 4.3 Configuration

Vantage requires certain environment variables (e.g., API keys for LLM features or external lookup tools).

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

*Populate the `.env` file with your specific keys (such as `OPENAI_API_KEY` or custom testing tokens).*

### 4.4 Running Locally

Vantage supports two transport modes depending on how you wish to connect your AI agent.

**Mode A: HTTP Streaming (For Web/Remote Clients)**

```bash
uv run python main.py
```

*This starts the server on `0.0.0.0:5000`.*

**Mode B: STDIO Mode (For Desktop Clients like Claude)**

```bash
uv run python main.py --stdio
```

## 5\. Usage

To use Vantage with **Claude Desktop**, you need to add it to your `claude_desktop_config.json` file:

```json
{
  "mcpServers": {
    "vantage-mcp": {
      "command": "uv",
      "args": [
        "run",
        "python",
        "/absolute/path/to/vantage-mcp/main.py",
        "--stdio"
      ]
    }
  }
}
```

Once connected, simply prompt your LLM:

> *"I need to run a black-box security assessment on `http://localhost:8080`. Start by outlining a pentest workflow, fingerprint the application, and test the `/search` and `/login` endpoints for vulnerabilities. At the end, generate a full markdown report."*

## 6\. Deployment

To deploy Vantage for team use or CI/CD pipelines:

1.  **Docker:** Containerize the application using a `Dockerfile` that installs `uv` and exposes port `5000`.
2.  **Cloud Hosting:** Deploy to any platform supporting standard Python HTTP servers (AWS EC2, Render, DigitalOcean). Ensure network rules permit Vantage to access the target testing environments securely.
3.  **Authentication:** If hosting via HTTP, wrap the server in a reverse proxy (like Nginx) and enforce authentication to prevent unauthorized users from utilizing your pentesting toolkit.

## 7\. Project Status

🚧 **Hackathon Prototype / Active Development**
This project is currently in active development. While core scanning modules (SQLi, XSS, SSTI) and the LLM reporting pipeline are functional, continuous improvements are being made to payload evasion techniques and CI/CD integrations.


## 9\. Project License

Distributed under the MIT License. See `LICENSE` for more information.

## 10\. References

  - [Model Context Protocol (MCP) Documentation](https://modelcontextprotocol.io/)
  - [FastMCP Framework](https://www.google.com/url?sa=E&source=gmail&q=https://github.com/fastmcp/fastmcp)
  - [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

