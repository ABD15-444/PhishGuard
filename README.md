# PhishGuard — Real-Time Phishing Attack Detection & URL Analysis Tool

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.1-black.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-59%20Passing-brightgreen.svg)]()
[![Security Audit](https://img.shields.io/badge/Security-SSRF%20Hardened-emerald.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)]()

> **PhishGuard** is an open-source cybersecurity URL analysis platform engineered for real-time phishing detection, threat intelligence aggregation, and forensic URL inspection. Developed for college cybersecurity demonstrations, technical project evaluations, and security research.

---

## 1. Project Overview & Problem Statement

Phishing attacks remain the primary initial access vector across modern cyber incidents. Traditional defenses frequently rely on static blacklists, which lag behind newly registered and dynamically generated domains.

**PhishGuard** addresses this gap by combining **multi-signal heuristic evaluation**, **network infrastructure verification**, **cryptographic certificate auditing**, **hop-by-hop redirect tracing**, and **asynchronous threat intelligence telemetry** into a unified diagnostic platform.

### Objectives:
- Provide instantaneous, multi-layered risk evaluation without executing remote code or probe untrusted servers unsafely.
- Prevent Server-Side Request Forgery (SSRF) and DNS rebinding attacks when scanning hostile URLs.
- Deliver transparent, interpretable risk scores (0–100) and point-by-point explanations.
- Preserve graceful degradation when third-party threat feeds or network lookups are unavailable.

---

## 2. Key Features

- **Lexical & Structural URL Inspection:**
  - URL length and path character analysis.
  - Direct IP-based host detection (IPv4 / IPv6).
  - Suspicious `@` credential obfuscation detection.
  - Subdomain count and multi-label depth inspection.
  - High-risk TLD filtering (`.tk`, `.xyz`, `.top`, `.click`, `.gq`, `.ml`, `.cf`).
  - Sensitive keyword and combination detection (`login`, `verify`, `account`, `bank`, `wallet`).
  - Internationalized Domain Name (IDN) Punycode homograph detection (`xn--`).
  - Plaintext HTTP protocol downgrade detection.
- **Network & DNS Infrastructure Auditing:**
  - Public DNS record extraction (`A`, `AAAA`, `MX`, `NS`, `CNAME`) querying Cloudflare DNS (`1.1.1.1`).
  - Autonomous System Number (ASN), ISP, and IP geolocation intelligence via `ipapi.co`.
  - Domain age calculation, creation date, expiration date, and registrar lookup via RDAP (`rdap.org`).
- **Cryptographic & Protocol Security:**
  - Automated SSL/TLS certificate chain verification against the `certifi` Mozilla CA bundle.
  - Certificate expiry countdown, issuer organization, subject, and domain match verification.
  - Step-by-step redirect tracing (max 5 hops) with loop protection and HTTPS-to-HTTP downgrade detection.
- **Threat Intelligence Aggregation:**
  - VirusTotal v3 REST API integration.
  - Accurate distinction between queued/provisional analyses and completed reports.
  - Dynamic score floor adjustment based on verified malicious and suspicious vendor counts.
- **Modern High-Tech User Interface:**
  - Sleek dark-mode cybersecurity dashboard with glassmorphism and subtle glowing accents.
  - 1-click test preset pills for smooth live demonstrations.
  - Animated radar scanning state with real-time diagnostic checklist.
  - Accessible, fully responsive grid layout.

---

## 3. System Architecture

```
                    +------------------------------------+
                    |        Web Dashboard Client        |
                    |   (HTML5 / Modern CSS / Vanilla JS)|
                    +-----------------+------------------+
                                      | POST /api/scan { url }
                                      v
                    +-----------------+------------------+
                    |    Flask Gateway & SSRF Guard      |
                    |   - Scheme & Hostname Sanitization |
                    |   - is_safe_public_host() filter   |
                    +-----------------+------------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
       v                              v                              v
+------+---------------+      +-------+-------------+      +---------+---------------+
| Lexical Analysis     |      | Network & Security  |      | Threat Intelligence     |
| - URL & Path Length  |      | - DNS Resolution    |      | - VirusTotal v3 API     |
| - Keywords & Combos  |      | - RDAP Registration |      | - Engine Detection Hits |
| - Punycode & IP Host |      | - TLS / SSL Handshake|     | - Threat Score Floors   |
| - Scheme Flags       |      | - Redirect Tracing  |      |                         |
+------+---------------+      +-------+-------------+      +---------+---------------+
       |                              |                              |
       +------------------------------+------------------------------+
                                      |
                                      v
                    +-----------------+------------------+
                    | Risk Aggregator & Verdict Engine   |
                    |   - Scores: 0-29 SAFE              |
                    |   - Scores: 30-59 SUSPICIOUS       |
                    |   - Scores: 60-100 HIGH RISK       |
                    +-----------------+------------------+
                                      | JSON Response
                                      v
                    +-----------------+------------------+
                    |   Dashboard Results Presentation   |
                    +------------------------------------+
```

Detailed technical documentation:
- [System Architecture](file:///Users/abrahamdavid/Desktop/PhishGuard/docs/ARCHITECTURE.md)
- [Security Policy & SSRF Audit](file:///Users/abrahamdavid/Desktop/PhishGuard/docs/SECURITY.md)
- [Testing Strategy & Test Suite](file:///Users/abrahamdavid/Desktop/PhishGuard/docs/TESTING.md)
- [Machine Learning Research & Evaluation](file:///Users/abrahamdavid/Desktop/PhishGuard/docs/ML_EVALUATION.md)

---

## 4. Technologies Used

- **Backend:** Python 3.12, Flask 3.1, Werkzeug
- **Networking & Cryptography:** `requests`, `dnspython`, `certifi`, `urllib.parse`, `ipaddress`, `socket`, `ssl`
- **Domain Extraction:** `tldextract`
- **Frontend:** Semantic HTML5, Vanilla CSS3 (Custom Design System, Flexbox/Grid, Glassmorphism), Modern JavaScript (ES6+ `async/await`, Fetch API)
- **Experimental Machine Learning:** `scikit-learn`, `pandas`, `numpy`, `joblib`
- **Testing:** Python `unittest` framework, `unittest.mock`

---

## 5. Directory Structure

```text
PhishGuard/
├── app.py                            # Flask server and analysis engine
├── requirements.txt                  # Python dependencies
├── .env.example                      # Configuration template (keys kept out of Git)
├── .gitignore                        # Security and repository hygiene filters
├── templates/
│   └── index.html                    # Modern cybersecurity dashboard
├── static/
│   ├── style.css                     # Custom design system & animations
│   └── script.js                     # Frontend API interaction & DOM controller
├── tests/                            # Automated test suite (59 passing tests)
│   ├── test_risk_engine.py           # Threshold boundaries and VirusTotal floors
│   ├── test_risk_explanations.py     # Heuristic explanation consistency
│   ├── test_url_validation.py        # Scheme, port, and hostname validation
│   ├── test_redirect_security.py     # SSRF defense, loop prevention, protocol checks
│   ├── test_external_service_failures.py # Error containment boundaries
│   ├── test_security_regressions.py  # SSL SSRF guard, direct IP intelligence, underscores
│   └── test_ml_pipeline.py           # Feature extraction schema and inference tests
├── docs/                             # Technical documentation
│   ├── ARCHITECTURE.md               # Pipeline and component specifications
│   ├── SECURITY.md                   # Threat model and SSRF protections
│   ├── TESTING.md                    # Test execution instructions and coverage
│   └── ML_EVALUATION.md              # ML confounding investigation and findings
├── evaluate_detection.py             # Synthetic functional evaluation runner
├── evaluation_urls.csv               # Functional test dataset (30 URLs)
├── ml_features.py                    # 17-feature lexical URL extractor
├── ml_large_feature_names.json       # Feature schema specification
├── predict_url.py                    # Offline experimental ML inference tool
├── baseline_url_length.py            # Single-feature length baseline script
├── test_feature_sensitivity.py       # Sensitivity and perturbation auditor
├── analyze_model_misses.py           # Diagnostic script for active phishing false negatives
└── extract_urls_for_investigation.py # Diagnostic dataset builder
```

---

## 6. Installation & Setup (macOS)

### 6.1 Prerequisites
- macOS 12+ (Apple Silicon or Intel)
- Python 3.12+ installed (`python3 --version`)
- Node.js (optional, for frontend syntax checks)

### 6.2 Clone and Setup Environment
```bash
# 1. Clone repository
git clone https://github.com/ABD15-444/PhishGuard.git
cd PhishGuard

# 2. Create Python virtual environment
python3 -m venv venv

# 3. Activate virtual environment
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### 6.3 Configure Environment Variables
PhishGuard operates completely without external keys for local heuristics, DNS, RDAP, SSL, and redirect inspections. To enable live VirusTotal threat telemetry:

```bash
# Copy template to .env
cp .env.example .env

# Open .env and add your free VirusTotal API key:
# VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

> **Security Note:** Never commit your `.env` file to version control. The `.gitignore` file is configured to protect your secrets.

---

## 7. Starting the Application

Activate your virtual environment and start the Flask web server:

```bash
source venv/bin/activate
python3 app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000/
```

---

## 8. Running Automated Tests

Run the complete 59-test automated suite:

```bash
source venv/bin/activate
python3 -m unittest discover -s tests -v
```

Run static syntax checks:
```bash
python3 -m py_compile app.py
node --check static/script.js
```

---

## 9. Running the Detection Evaluation

Run the offline synthetic detection evaluation:

```bash
source venv/bin/activate
python3 evaluate_detection.py
```

### Evaluation Output:
```text
PHISHGUARD SYNTHETIC FUNCTIONAL BENCHMARK (30 URLs)
============================================================
Methodology: Offline repeatable functional suite using mocked external services.
Dataset Scope: 10 synthetic phishing URLs, 20 curated legitimate URLs.
Limitation: Establishes rule-engine correctness; does not imply 100% production accuracy.
============================================================
True positives (TP):  10
True negatives (TN):  20
False positives (FP): 0
False negatives (FN): 0
Accuracy:             100.00%
Precision:            100.00%
Recall:               100.00%
F1-score:             100.00%
```

---

## 10. Risk Score Interpretation

| Risk Score Range | Verdict | Interpretation & Recommended User Action |
| :---: | :---: | :--- |
| **0 – 29** | **SAFE** | No significant risk indicators flagged by heuristics or threat intelligence. Safe for normal interaction. |
| **30 – 59** | **SUSPICIOUS** | Multiple anomalies detected (e.g., suspicious keywords, abnormal subdomains, or unconfirmed threat hits). Exercise caution before entering credentials. |
| **60 – 100** | **HIGH RISK** | Critical phishing indicators detected (e.g., direct IP hosting, homograph Punycode, confirmed VirusTotal vendor malicious detections). Do not visit or enter credentials. |

---

## 11. Safe Demonstration URLs for Live Evaluation

The following examples can be safely used during academic presentations:

1. **Clean Public Domain (Expected: SAFE, Score ~0):**
   `https://www.wikipedia.org/`
2. **Synthetic Phishing Heuristics (Expected: SUSPICIOUS, Score ~30-35):**
   `https://paypal.example/login/verify-account`
3. **Direct IP Host Indicator (Expected: SAFE/SUSPICIOUS depending on TLD, flags raw IP heuristic):**
   `http://192.0.2.1`

*(Active malicious URLs have been defanged in documentation to prevent accidental user access).*

---

## 12. Limitations & Future Work

- **Live Site Cloaking:** Advanced phishing kits inspect client user-agents and IP addresses, redirecting security crawlers to benign pages. Future iterations can integrate headless browser sandboxing with DOM screenshot perceptual hashing.
- **Machine Learning Integration:** As documented in [docs/ML_EVALUATION.md](file:///Users/abrahamdavid/Desktop/PhishGuard/docs/ML_EVALUATION.md), offline lexical ML models suffer from source-label bias on popular domain lists. Training an unbiased model on deep path-balanced datasets remains an active research direction.
- **SPF / DMARC / DKIM Email Authentication:** Extending the tool to analyze raw phishing email headers in addition to URLs.

---

## 13. License

This project is licensed under the MIT License — see the repository for details.
