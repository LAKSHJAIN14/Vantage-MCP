# Advanced Server-Side Request Forgery (SSRF)

## Typical Bypasses
1. **DNS Rebinding (TOCTOU)**:
   - Problem: The server resolves your domain, verifies it's not `127.0.0.1` (Time-Of-Check), then resolves it again to fetch (Time-Of-Use).
   - Solution: Configure an authoritative DNS server to respond with a safe IP first, but switch the TTL to 0 and respond with `127.0.0.1` on the second query.
2. **Host Header SSRF**:
   - Problem: URL parameter SSRF is blocked.
   - Solution: Set the HTTP `Host` header to an internal IP (e.g., `Host: 127.0.0.1:8080`) while making a request to the external application. Sometimes reverse proxies blindly route based on the host.
3. **HTTP Redirect Chain Bypass (cURL)**:
   - Problem: The application blocks internal IP text formats (e.g., `127.0.0.1`, `0.0.0.0`, `localhost`).
   - Solution: Provide an external server URL you control (`http://evil.com`). Your server responds with HTTP `302 Found` to `http://127.0.0.1/admin`. If the application follows redirects (e.g., cURL with `-L`), it fetches the internal page!
4. **Encoding & Obfuscation**:
   - Decimal IP: `http://2130706433/` (= `127.0.0.1`).
   - Octal IP: `http://0177.0.0.1/`.
   - Hex IP: `http://0x7f000001/`.

## High-Value SSRF Targets
- **Cloud Metadata APIs**:
  - AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  - GCP: `http://metadata.google.internal/computeMetadata/v1/` (`Metadata-Flavor: Google` header required).
- **Internal Services**:
  - Redis: `dict://127.0.0.1:6379/stats`
  - Kubernetes / Docker Sockets if mapped locally.
  - Management UI (Elasticsearch `9200`, Tomcat `8080`).

## Blind SSRF Exfiltration
If the response isn't returned to the user:
- Use **Timing Attacks**: See if `127.0.0.1:22` times out differently than `127.0.0.1:80`. Port scan the internal network!
- Use **OOB (Out-of-Bound) XXE**: If you can trigger XXE, use SSRF to ping an external server you control to confirm the payload executed.
