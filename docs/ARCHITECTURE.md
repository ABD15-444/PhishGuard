# System Architecture — PhishGuard

PhishGuard is a real-time cybersecurity URL analysis and phishing attack detection system. It employs a multi-signal, defense-in-depth architecture combining lexical heuristics, network infrastructure auditing, cryptographic certificate validation, redirect tracking, and external threat intelligence.

---

## 1. High-Level Architecture

PhishGuard decouples user interface, request validation, heuristic evaluation, external network probes, and threat telemetry aggregation into distinct layers.

```
                      +-----------------------------------+
                      |   Modern Web Dashboard (Frontend) |
                      |    (HTML5 / Vanilla CSS / JS)     |
                      +-----------------+-----------------+
                                        | POST /api/scan { url }
                                        v
                      +-----------------+-----------------+
                      |     Flask API Gateway (app.py)    |
                      |   - Input sanitization & IDNA     |
                      |   - Scheme & Hostname validation  |
                      |   - SSRF & Private IP Guard       |
                      +-----------------+-----------------+
                                        |
     +----------------------------------+----------------------------------+
     |                                  |                                  |
     v                                  v                                  v
+----+-------------------+    +---------+-----------+    +-----------------+------------------+
| Lexical Analysis Engine|    | Network & Protocol  |    | Threat Intelligence Integration    |
| - URL & Path Length    |    | - DNS Lookup (1.1.1.1)|   | - VirusTotal v3 URL Submission     |
| - Keyword Combos       |    | - RDAP Registration |    | - Asynchronous Analysis Retrieval  |
| - Punycode (xn--)      |    | - TLS / SSL (Port443)|   | - Provisional vs Completed States  |
| - IP Host Detection    |    | - Redirect Tracer   |    | - Detection Threshold Evaluation   |
| - @ Symbol & Symbols   |    |   (Hop & Downgrades)|    |                                    |
+----+-------------------+    +---------+-----------+    +-----------------+------------------+
     |                                  |                                  |
     +----------------------------------+----------------------------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |   Risk Aggregator & Verdict Engine|
                      |   - Heuristic Scoring (0-100)     |
                      |   - VT Threat Floor (30, 60, 85)  |
                      |   - Transparent Factor Explanations|
                      |   - Calibrated Verdict Assessment |
                      +-----------------+-----------------+
                                        | JSON Response
                                        v
                      +-----------------+-----------------+
                      |   Client Presentation & Reporting |
                      +-----------------------------------+
```

---

## 2. Core Processing Pipeline

### 2.1 Request Validation & Normalization
1. **JSON Payload Inspection:** Ensures requests are well-formed JSON containing a non-empty `url` string.
2. **Scheme Normalization:** Prepends `https://` if no scheme is specified. Strictly restricts allowable schemes to `http` and `https`. Unsupported schemes (e.g., `file://`, `ftp://`, `javascript:`) are rejected immediately.
3. **Hostname Validation:** Parses hostnames using RFC-compliant IDNA conversion. Validates label lengths (<=63 chars) and total hostname length (<=253 chars). Allows alphanumeric characters, hyphens, and underscores in subdomains.
4. **Port Validation:** Validates that explicit ports are within legal ranges (1–65535).

### 2.2 Heuristic Feature Evaluation
The heuristic engine evaluates static URL characteristics without issuing external requests to untrusted targets:
- **URL Length:** Scores long URLs (>100 characters: +10; >200 characters: +20).
- **Direct IP Address:** Assigns +25 points when the host is a raw IPv4/IPv6 address rather than a domain.
- **Embedded Userinfo / @ Symbol:** Assigns +20 points when `@` is present in the URL.
- **Subdomain Count:** Analyzes labels preceding the registered domain (+10 points for 3 subdomains, +15 points for >=4).
- **Suspicious TLD:** Assesses risky or frequently abused top-level domains (+15 points for `.tk`, `.xyz`, `.top`, `.click`, `.gq`, `.ml`, `.cf`).
- **Phishing Keywords:** Evaluates high-risk tokens (e.g., `login`, `verify`, `account`, `wallet`, `bank`). Multiple concurrent keywords trigger an additional combination penalty (+15 points).
- **Punycode (IDN):** Flags `xn--` prefixes often used in homograph impersonation attacks (+15 points).
- **HTTPS Absence:** Flags plain HTTP URLs (+10 points).

### 2.3 Network & Cryptographic Probing
All network operations are executed through the `safe_service_call` wrapper with strict timeouts and resource cleanup:
- **DNS Resolution (`check_dns`):** Queries Cloudflare's public resolver (`1.1.1.1`) for `A`, `AAAA`, `MX`, `NS`, and `CNAME` records with a 3-second timeout and 5-second lifetime.
- **IP Intelligence (`get_ip_intelligence`):** Resolves IP addresses or accepts direct IP inputs, extracting network addressing details.
- **Geolocation (`get_ip_geolocation`):** Queries `ipapi.co` for public IP addresses, retrieving ASN, ISP, country, and city coordinates.
- **RDAP Registration (`get_rdap_information`):** Queries `rdap.org` for domain creation date, expiration date, and registrar identity, computing domain age.
- **SSL/TLS Inspection (`check_ssl_certificate`):** Validates certificate chains against `certifi` CA bundle. Checks expiration dates, remaining days of validity, issuer organization, and subject common name.
- **Redirect Tracing (`analyze_redirects`):** Traverses HTTP 3xx redirect chains hop-by-hop up to a maximum of 5 hops. Detects HTTPS-to-HTTP protocol downgrades and loop conditions.

### 2.4 External Threat Intelligence (VirusTotal)
- Integrates with the VirusTotal v3 REST API via `VIRUSTOTAL_API_KEY`.
- Submits URLs via `POST /api/v3/urls` and inspects analysis status via `GET /api/v3/analyses/{id}`.
- Distinguishes between `queued` / `in-progress` states (provisional counts) and `completed` states.
- Ensures absent API keys or service outages fail gracefully without crashing scans.

### 2.5 Risk Aggregation & Threshold Logic
PhishGuard applies rule-based threshold scoring:
- **Score 0 to 29:** **SAFE** (No major suspicious characteristics detected).
- **Score 30 to 59:** **SUSPICIOUS** (URL displays multiple heuristic anomalies or suspicious threat telemetry).
- **Score 60 to 100:** **HIGH RISK** (URL exhibits strong indicators of phishing, severe lexical risk, or confirmed malicious detections).

**VirusTotal Scoring Adjustments:**
- `>= 3 malicious detections:` Minimum score floor of **85** (HIGH RISK).
- `>= 1 malicious detection:` Minimum score floor of **60** (HIGH RISK).
- `>= 1 suspicious detection (0 malicious):` Minimum score floor of **30** (SUSPICIOUS).
- `Queued / In-Progress:` Does not modify score; provisional counts are flagged in UI.

---

## 3. Safe Service Call Boundary

To ensure application stability under external network degradation, every external service is invoked through `safe_service_call`:

```python
def safe_service_call(function, *args, fallback=None):
    try:
        return function(*args)
    except Exception:
        app.logger.exception("Analysis service failed: %s", getattr(function, "__name__", "unknown"))
        return fallback
```

This prevents network timeouts, DNS errors, or API outages from propagating into unhandled HTTP 500 errors.

---

## 4. Frontend-Backend Contract

### POST `/api/scan`
**Request Payload:**
```json
{
  "url": "https://example.com"
}
```

**Response Structure (HTTP 200):**
```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "protocol": "https",
  "path": "/",
  "url_length": 19,
  "risk_score": 0,
  "verdict": "SAFE",
  "verdict_message": "No major suspicious characteristics were detected.",
  "risk_factors": [],
  "reasons": ["URL length appears normal", "Domain uses a common TLD"],
  "domain_info": {
    "registered_domain": "example.com",
    "subdomain": "",
    "tld": "com"
  },
  "rdap_info": {
    "available": true,
    "creation_date": "1995-08-14",
    "expiration_date": "2025-08-13",
    "domain_age_days": 11388,
    "registrar": "RESERVED-Internet Assigned Numbers Authority"
  },
  "dns_resolves": true,
  "dns_records": { "A": ["93.184.215.14"], "AAAA": ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },
  "dns_security": { "domain_resolves": true, "has_ipv4": true, "has_ipv6": true, "findings": [] },
  "ssl_info": { "checked": true, "valid": true, "issuer": "DigiCert Global Root G2", "days_until_expiry": 180 },
  "redirect_info": { "checked": true, "redirect_count": 0, "final_url": "https://example.com", "https_downgrade": false },
  "ip_info": { "domain": "example.com", "resolved": true, "ipv4_addresses": ["93.184.215.14"] },
  "geo_info": { "city": "Norwell", "country": "United States", "organization": "EDGECAST" },
  "virustotal_info": { "available": true, "status": "completed", "malicious": 0, "suspicious": 0, "harmless": 72 }
}
```
