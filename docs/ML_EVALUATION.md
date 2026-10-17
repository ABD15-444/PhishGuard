# Machine Learning Investigation & Evaluation Report — PhishGuard

This report documents the experimental machine-learning pipeline developed alongside PhishGuard's rule-based detector, evaluates its empirical performance, analyzes critical failure modes, and presents the formal engineering rationale for keeping ML out of the production scanning pipeline.

---

## 1. Experimental ML Architecture

The experimental pipeline was created to evaluate whether a Random Forest classifier trained on lexical URL features could supplement or replace rule-based heuristics.

### 1.1 Canonical Feature Extractor (`ml_features.py`)
The extractor processes input URLs offline and yields 17 numerical features:

| Index | Feature Name | Description | Type |
| :---: | :--- | :--- | :---: |
| 1 | `url_length` | Total character count of the URL | Integer |
| 2 | `hostname_length` | Character count of the fully qualified domain name | Integer |
| 3 | `path_length` | Character count of the URL path component | Integer |
| 4 | `dot_count` | Number of `.` characters in the full URL | Integer |
| 5 | `hyphen_count` | Number of `-` characters in the full URL | Integer |
| 6 | `at_symbol` | Presence of `@` in the URL (1 = present, 0 = absent) | Binary |
| 7 | `https` | Presence of HTTPS scheme (1 = HTTPS, 0 = HTTP) | Binary |
| 8 | `ip_address` | Direct IPv4 or IPv6 address indicator (1 = IP, 0 = domain) | Binary |
| 9 | `subdomain_count` | Number of subdomain labels extracted via `tldextract` | Integer |
| 10 | `keyword_count` | Count of matching sensitive/suspicious tokens | Integer |
| 11 | `digit_count` | Total numeric digit characters in the URL | Integer |
| 12 | `special_character_count`| Count of non-alphanumeric characters | Integer |
| 13 | `has_punycode` | Presence of internationalized `xn--` prefix | Binary |
| 14 | `has_port` | Presence of an explicit non-standard port | Binary |
| 15 | `has_query` | Presence of a URL query string (`?key=val`) | Binary |
| 16 | `entropy` | Shannon entropy across URL character distribution | Float |
| 17 | `encoded_character_count`| Count of percent-encoded triplets (`%20`, etc.) | Integer |

The schema order is strictly defined in `ml_large_feature_names.json`.

---

## 2. Dataset Construction & Source-Label Confounding

The experimental model was trained on a combined dataset:
- **Phishing Source (Label 1):** Verified online phishing URLs collected from PhishTank.
- **Legitimate Source (Label 0):** Popular top domains extracted from the Tranco top-sites list.

A domain-clean split was established to eliminate exact hostname overlap between training and test sets (15,652 train rows, 3,913 test rows).

### 2.1 The Confounding Factor
Despite removing overlapping hostnames, an audit of the underlying URL distributions revealed severe source-label confounding:

1. **Path Distribution Discrepancy:**
   - **Legitimate records (Tranco):** **100.0%** had no path (`path_length == 1`, e.g., `https://example.com/`).
   - **Phishing records (PhishTank):** **65.8%** had inner paths containing tokens, directories, and file extensions.
2. **`www.` Prefix Distribution:**
   - **Legitimate records:** Only 5 out of 7,710 records (0.06%) had a `www.` prefix.
   - **Phishing records:** 313 out of 7,942 records (3.94%) had a `www.` prefix.

Because the data sources were formatted differently, the model learned to classify **data sources** rather than genuine phishing characteristics.

---

## 3. Baseline Model Comparison

To quantify the degree to which superficial lexical features dominated model training, a trivial single-feature baseline was evaluated on `ml_test.csv` using URL length alone (`baseline_url_length.py`):

```
Decision Rule: If len(url) > 26 then PHISHING else LEGITIMATE
```

### Measured Test Metrics:
- **Accuracy:** **91.92%**
- **Precision:** **87.93%**
- **Recall:** **93.61%**
- **F1-Score:** **90.68%**
- **Confusion Matrix:**
  - True Negatives: 2,060
  - False Positives: 211
  - False Negatives: 105
  - True Positives: 1,537

This confirms that approximately 92% of the Random Forest's apparent 98.5% accuracy was achievable simply by measuring character length, proving that test-set metrics were heavily inflated by dataset formatting artifacts.

---

## 4. Feature Sensitivity & Model Fragility

Using `test_feature_sensitivity.py`, feature perturbations were evaluated on candidate URLs:

| Variation Tested on `https://paypal-banking.pro/` | Predicted Phishing Probability | Shift vs Baseline |
| :--- | :---: | :---: |
| **Baseline URL** | **5.71%** (Predicted Safe) | — |
| Subdomain count set to 1 | **69.50%** (Predicted Phishing) | **+63.79%** |
| URL length increased by 4 chars | **34.50%** (Suspicious) | **+28.79%** |
| Hostname length increased by 4 chars | **49.33%** (Suspicious) | **+43.62%** |
| HTTPS disabled (HTTP) | **60.88%** (Predicted Phishing) | **+55.17%** |

The model exhibited extreme fragility: minor, harmless syntactical variations inverted the classifier's output entirely.

---

## 5. Model Failure Diagnosis on Threat Intelligence Evidence

When evaluated against 120 URLs with independent VirusTotal threat telemetry (`virustotal_batch_evidence.csv` and `analyze_model_misses.py`), the model failed catastrophically on active phishing domains:

| URL | Source | VT Malicious Detections | ML Phishing Probability | ML Prediction |
| :--- | :--- | :---: | :---: | :---: |
| `https://transparenzregister.cc/` | PhishTank Validation | **17** | **1.17%** | **LEGITIMATE (False Negative)** |
| `https://cdaifa.com` | PhishTank Validation | **16** | **42.00%** | **LEGITIMATE (False Negative)** |
| `https://olxhit.com/` | Fresh Tranco Candidate | **10** | **0.00%** | **LEGITIMATE (False Negative)** |
| `https://vip555ku.com/` | Fresh Tranco Candidate | **1 + 2 Suspicious** | **2.00%** | **LEGITIMATE (False Negative)** |
| `https://cognitoforms.com/` | Fresh Tranco Candidate | 1 | 0.00% | LEGITIMATE |
| `https://indonesiaku.space/` | Fresh Tranco Candidate | 1 | 0.00% | LEGITIMATE |

### Root Cause Analysis:
Every single missed phishing attack was hosted at the **root domain** (`path_length == 1`, `subdomain_count == 0`, `keyword_count == 0`, `url_length < 32`). Because the model had learned that root URLs without paths originate from Tranco, it assigned near-zero phishing probabilities to dangerous domains flagged by 10 to 17 security engines on VirusTotal.

---

## 6. Engineering Decision

Based on this empirical investigation:
1. **The machine-learning model MUST NOT be integrated into PhishGuard's live risk-scoring engine.** Integrating it would introduce severe false negatives on root phishing domains and generate erratic score fluctuations on harmless URL formatting variations.
2. **The ML pipeline is preserved as an experimental research module.** All dataset preparation scripts, feature extractors, sensitivity tests, and model inspectors are retained for academic study and research reproducibility.
3. **The production PhishGuard application relies strictly on its deterministic multi-signal rule engine** (lexical heuristics, DNS integrity, RDAP domain age, TLS certificate validation, redirect tracking, and VirusTotal threat intelligence).
