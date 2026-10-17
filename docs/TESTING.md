# Testing Strategy & Automated Test Suite — PhishGuard

PhishGuard employs an automated test suite designed for repeatability, fast execution, and zero reliance on live network connectivity. External dependencies (DNS, RDAP, SSL sockets, HTTP redirects, and VirusTotal) are mocked across the functional test suite.

---

## 1. Test Suite Overview

| Test Module | Focus Area | Test Count | Network Mocking |
| :--- | :--- | :---: | :--- |
| `tests/test_risk_engine.py` | Risk score boundaries (0, 30, 50, 60, 85, 100), VirusTotal scoring floors, pending states | 8 | Fully Mocked |
| `tests/test_risk_explanations.py` | Explanation consistency, factor reporting, verdict messages | 10 | Fully Mocked |
| `tests/test_url_validation.py` | URL parsing, scheme whitelisting, invalid ports, hostname normalization | 10 | Fully Mocked |
| `tests/test_redirect_security.py` | SSRF prevention, private/loopback/metadata IP blocking, downgrade detection, redirect limits | 10 | Fully Mocked |
| `tests/test_external_service_failures.py` | Graceful degradation under total network/service failure | 1 | Fully Mocked |
| `tests/test_security_regressions.py` | SSL socket SSRF guard, direct IP resolution, underscore subdomains, port bounds, malformed payloads | 11 | Fully Mocked |
| `tests/test_ml_pipeline.py` | 17-feature schema consistency, punycode/IP extraction, missing model errors, mock inference | 7 | Offline / Mocked |
| **Total Test Count** | **Comprehensive Automated Verification** | **57+ Passing** | **100% Offline Repeatable** |

---

## 2. Test Execution Commands

### 2.1 Run Complete Unit Test Suite
Execute all test modules using Python's standard `unittest` discovery runner:

```bash
python3 -m unittest discover -s tests -v
```

Expected output:
```text
Ran 59 tests in 0.069s
OK
```

### 2.2 Run Specific Test Suites
To run an individual test module:

```bash
# Security regression and SSRF checks
python3 -m unittest tests/test_security_regressions.py -v

# Redirect safety and protocol checks
python3 -m unittest tests/test_redirect_security.py -v

# Risk scoring and VirusTotal integration
python3 -m unittest tests/test_risk_engine.py -v

# ML feature extraction and schema checks
python3 -m unittest tests/test_ml_pipeline.py -v
```

### 2.3 Static Compilation & Syntax Verification
Verify syntax and compile safety across Python backend and JavaScript frontend:

```bash
# Verify Python compilation
python3 -m py_compile app.py

# Verify JavaScript syntax
node --check static/script.js
```

---

## 3. Synthetic Benchmark Evaluation

In addition to unit tests, the repository includes a functional detection benchmark:

```bash
python3 evaluate_detection.py
```

### Methodology:
- Evaluates 30 explicitly labeled URLs (10 synthetic phishing URLs with known indicators, 20 curated legitimate domains).
- Uses mocked network endpoints to guarantee offline reproducibility without network latency.
- Calculates True Positives (TP), True Negatives (TN), False Positives (FP), False Negatives (FN), Accuracy, Precision, Recall, F1-Score, and False Positive Rate.
- Results are saved to `evaluation_results.csv`.
- **Note:** This benchmark establishes deterministic correctness of the rule engine under controlled conditions; it does not measure real-world performance on uncurated internet traffic.
