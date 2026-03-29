"""cve_lookup() — Query NVD/GitHub to find active CVEs for detected technologies."""

import httpx

async def cve_lookup(technology: str, version: str = "") -> str:
    """Look up active CVEs for a specific technology and version.

    Call this tool after fingerprint() finds a specific framework, CMS,
    or server software version. It queries the NVD (National Vulnerability Database)
    or GitHub Advisory Database to find known vulnerabilities.

    Args:
        technology: The name of the software/framework (e.g., "WordPress", "nginx").
        version: The exact version string found (e.g., "5.8.1", "1.18.0").
            If no version was found, leave empty to get general recent CVEs.

    Returns:
        A list of matching CVEs with severity, description, and links to exploits.
    """
    # Use the official NIST NVD API (National Vulnerability Database)
    # Allows 5 requests per 30 seconds without an API key.
    search_term = technology
    if version:
        search_term += f" {version}"
        
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}"
    
    # We'll use our built-in http_client just to reuse the same user-agent,
    # but NVD explicitly requires a User-Agent, so we ensure one is passed.
    from utils.http_client import get_client
    
    headers = {"User-Agent": "Vantage-MCP/1.0"}
    
    try:
        async with get_client() as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
            
            if resp.status_code == 403:
                return "NVD API rate limit exceeded (5 requests per 30 seconds without a key). Please wait a moment and try again, or search manually."
                
            if resp.status_code != 200:
                return f"Could not fetch CVEs from NVD API (Status: {resp.status_code}). Please use a different tool or search the web manually for '{technology} {version} exploits'."
                
            data = resp.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                return f"No known CVEs found for `{technology} {version}` in the NVD database."
                
            # Format top 5 CVEs
            output = [f"### Top CVEs for {technology} {version} (Total: {total_results})\n"]
            
            # The NVD API already returns relevant matches, we just take the first 5
            for item in vulnerabilities[:5]:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "Unknown ID")
                
                # Try to extract CVSS V3 score
                cvss_score = "N/A"
                metrics = cve_data.get("metrics", {})
                
                # Check different possible metric formats
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")
                
                # Find English description
                descriptions = cve_data.get("descriptions", [])
                summary = "No description"
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value")
                        break
                        
                output.append(f"**{cve_id}** (CVSS: {cvss_score})")
                output.append(f"{summary}\n")
                
            return "\n".join(output)
            
    except httpx.TimeoutException:
        return "NVD API request timed out. This often happens if NVD is overloaded. Please try again later."
    except Exception as e:
        return f"Error connecting to NVD CVE database: {e}"
