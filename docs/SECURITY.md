# Security Policy & Audit Report — PhishGuard

PhishGuard analyzes untrusted, potentially malicious URLs submitted by users. Because the application interacts with external network resources to inspect domains, it is treated as **security-sensitive software**.

---

## 1. Threat Model & Mitigations

| Threat Category | Potential Attack Vector | PhishGuard Defense Mechanism | Status |
| :--- | :--- | :--- | :--- |
| **Server-Side Request Forgery (SSRF)** | Attacker submits `http://127.0.0.1:5000` or `http://169.254.169.254` to access internal services or cloud metadata. | Hostnames and IPs are resolved and validated via `is_safe_public_host()` before initiating socket connections in redirect analysis and SSL inspection. Non-global IPs are blocked. | **Mitigated & Verified** |
| **DNS Rebinding** | Malicious DNS returns a public IP during initial check, then resolves to `127.0.0.1` on subsequent requests. | Host resolution is re-audited at every redirect hop; non-public destination IPs trigger immediate connection aborts. Socket connection timeouts are restricted (3s connect, 5s read). | **Mitigated** |
| **Credential / Userinfo Leakage** | URLs containing `user:pass@evil.com` submitted to exfiltrate credentials or bypass hostname filters. | `analyze_redirects()` explicitly parses `parsed.username` and `parsed.password`, rejecting embedded credentials with an explicit security block. | **Mitigated & Verified** |
| **Redirect Loop / Resource Exhaustion (DoS)** | Attacker crafts a cyclical redirect chain (`A -> B -> A`) or excessive redirect hops. | Hard limit of 5 redirect hops enforced. Once hop 5 is reached, redirect analysis halts with `excessive_redirects: true`. | **Mitigated & Verified** |
| **Cross-Site Scripting (XSS)** | Malicious URLs containing `<script>alert(1)</script>` or encoded payloads rendered in the browser DOM. | Frontend renders dynamic values using DOM `textContent`, `replaceChildren()`, or explicit `escapeHTML()` sanitization. Input is never evaluated via `eval()` or unescaped `innerHTML`. | **Mitigated & Verified** |
| **Scheme Exploitation** | Submission of dangerous schemes (`javascript:`, `file:///`, `data:`, `ftp://`). | Scheme whitelist strictly enforces `http` and `https`. All alternate schemes are rejected at request validation with HTTP 400. | **Mitigated & Verified** |
| **API Secret Leakage** | `VIRUSTOTAL_API_KEY` printed in application logs, exception traces, or committed to version control. | Secrets are loaded exclusively from `.env`. Exception handlers log error types (e.g., `requests.RequestException`) rather than request headers or URLs containing query tokens. `.env` is ignored by Git. | **Mitigated & Verified** |
| **Debug Console Exposure** | Flask debug mode exposing interactive PIN debugger in production environments. | Server startup reads `FLASK_DEBUG` from environment variables, defaulting to `debug=False` and binding to `127.0.0.1`. | **Mitigated & Verified** |

---

## 2. In-Depth SSRF Defense Implementation

### 2.1 Public Host Validation (`is_safe_public_host`)
Before contacting any host for SSL inspection or redirect analysis, the hostname is resolved via `socket.getaddrinfo()` and every returned IP address is inspected using Python's `ipaddress` module:

```python
def is_safe_public_host(hostname):
    try:
        if not hostname:
            return False

        clean_host = hostname.strip("[]")
        ip_addresses = socket.getaddrinfo(clean_host, None, type=socket.SOCK_STREAM)

        if not ip_addresses:
            return False

        for address in ip_addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                not ip.is_global
                or ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False

        return True
    except (socket.gaierror, ValueError, OSError):
        return False
```

### 2.2 Prohibited Address Ranges
The filter rejects all:
- **Loopback Addresses:** `127.0.0.0/8`, `::1`
- **Private RFC 1918 Ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Link-Local / Cloud Metadata:** `169.254.0.0/16`, `fe80::/10` (AWS, GCP, Azure metadata at `169.254.169.254` blocked)
- **Multicast & Reserved:** `224.0.0.0/4`, `240.0.0.0/4`, `fc00::/7`
- **Unspecified / Zero Addresses:** `0.0.0.0`, `::`
- **Alternate IP Representations:** Decimal integers (e.g., `2130706433`), octal, and hex notation resolve through the OS resolver and are caught by the address filter.

### 2.3 SSL/TLS Socket Guard
Earlier versions of `check_ssl_certificate()` attempted a direct TLS handshake on port 443 without inspecting the destination host. This has been resolved by enforcing `is_safe_public_host()` prior to socket creation:

```python
clean_domain = domain.rstrip(".").strip("[]")
if not is_safe_public_host(clean_domain):
    return {
        "checked": False,
        "valid": False,
        "message": "SSL certificate inspection blocked: host is not a verified public host."
    }
```

---

## 3. Privacy & Threat Intelligence Considerations

1. **Submitting URLs to VirusTotal:** Submitting live URLs to VirusTotal shares the URL telemetry with external security vendors. When handling private, internal, or confidential URLs containing sensitive query tokens, users should be aware that third-party vendors inspect submissions.
2. **Passive vs Active Inspection:**
   - Heuristics, Punycode, and keyword inspections are 100% passive (offline).
   - DNS lookups query public recursive resolvers (`1.1.1.1`).
   - SSL and redirect tracing issue minimal HEAD/GET requests with a generic user-agent (`PhishGuard/1.0`).

---

## 4. Verification & Automated Security Tests

Automated regression tests in `tests/test_redirect_security.py` and `tests/test_security_regressions.py` verify:
- Rejection of private IPv4 and IPv6 destinations
- Blocking of cloud metadata endpoints (`169.254.169.254`)
- Rejection of loopback hosts (`localhost`, `127.0.0.1`, `[::1]`)
- Detection and alerting on HTTPS-to-HTTP protocol downgrades
- Rejection of URLs with embedded credentials
- Rejection of unsupported schemes
- Enforcement of the 5-hop redirect boundary
