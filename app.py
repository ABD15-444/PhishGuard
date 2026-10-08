from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import ipaddress
import tldextract
import dns.resolver

app = Flask(__name__)


# ========================================
# HOME PAGE
# ========================================
@app.route("/")
def home():
    return render_template("index.html")


# ========================================
# 1. URL LENGTH CHECK
# ========================================
def check_url_length(url):

    length = len(url)

    if length > 200:
        return 20, "URL is extremely long"

    elif length > 100:
        return 10, "URL is unusually long"

    else:
        return 0, "URL length appears normal"


# ========================================
# 2. IP ADDRESS CHECK
# ========================================
def check_ip_address(domain):

    try:

        ipaddress.ip_address(domain)

        return (
            25,
            True,
            "URL uses an IP address instead of a domain name"
        )

    except ValueError:

        return (
            0,
            False,
            "URL uses a domain name"
        )


# ========================================
# 3. @ SYMBOL CHECK
# ========================================
def check_at_symbol(url):

    if "@" in url:

        return (
            20,
            True,
            "URL contains an @ symbol, which may hide the actual destination"
        )

    return (
        0,
        False,
        "URL does not contain an @ symbol"
    )


# ========================================
# 4. SUBDOMAIN CHECK
# ========================================
def check_subdomains(domain):

    extracted = tldextract.extract(domain)

    subdomain = extracted.subdomain

    if not subdomain:

        return (
            0,
            0,
            "URL does not contain subdomains"
        )

    subdomain_parts = subdomain.split(".")

    subdomain_count = len(subdomain_parts)

    if subdomain_count >= 4:

        return (
            15,
            subdomain_count,
            "URL contains a very large number of subdomains"
        )

    elif subdomain_count == 3:

        return (
            10,
            subdomain_count,
            "URL contains multiple subdomains"
        )

    else:

        return (
            0,
            subdomain_count,
            "URL contains a normal number of subdomains"
        )


# ========================================
# 5. SUSPICIOUS TLD CHECK
# ========================================
def check_suspicious_tld(domain):

    suspicious_tlds = {
        "tk",
        "top",
        "xyz",
        "click",
        "gq",
        "ml",
        "cf"
    }

    extracted = tldextract.extract(domain)

    tld = extracted.suffix.lower()

    if tld in suspicious_tlds:

        return (
            10,
            True,
            f"Domain uses a potentially suspicious TLD: .{tld}"
        )

    return (
        0,
        False,
        "Domain uses a common TLD"
    )


# ========================================
# 6. SUSPICIOUS KEYWORD CHECK
# ========================================
def check_suspicious_keywords(url):

    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "password",
        "confirm",
        "update",
        "bank",
        "wallet",
        "payment"
    ]

    url_lower = url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url_lower:

            found_keywords.append(keyword)

    # No suspicious keywords
    if not found_keywords:

        return (
            0,
            [],
            "No suspicious keywords detected"
        )

    # 5 points per keyword
    # Maximum 20 points
    score = min(
        len(found_keywords) * 5,
        20
    )

    return (
        score,
        found_keywords,
        "Suspicious keywords detected: "
        + ", ".join(found_keywords)
    )


# ========================================
# 7. PUNYCODE CHECK
# ========================================
def check_punycode(domain):

    domain_lower = domain.lower()

    if "xn--" in domain_lower:

        return (
            15,
            True,
            "Domain contains Punycode, which may indicate a look-alike domain"
        )

    return (
        0,
        False,
        "Domain does not contain Punycode"
    )
# ========================================
# 8. HTTPS CHECK
# ========================================
def check_https(protocol):

    if protocol == "https":

        return (
            0,
            True,
            "URL uses HTTPS"
        )

    return (
        5,
        False,
        "URL does not use HTTPS"
    )

# ========================================
# DNS CHECK
# ========================================
def check_dns(domain):
    records = {}

    record_types = ["A", "AAAA", "MX", "NS", "CNAME"]

    for record_type in record_types:

        try:
            answers = dns.resolver.resolve(domain, record_type)

            records[record_type] = [
                str(answer) for answer in answers
            ]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            records[record_type] = []

        except Exception:
            records[record_type] = []

    dns_resolves = any(
        len(records[record_type]) > 0
        for record_type in record_types
    )

    return dns_resolves, records
# ========================================
# 10. RISK VERDICT
# ========================================
def get_risk_verdict(score):

    if score >= 60:

        return (
            "HIGH RISK",
            "The URL contains multiple suspicious characteristics."
        )

    elif score >= 30:

        return (
            "SUSPICIOUS",
            "The URL contains some characteristics commonly associated with phishing."
        )

    else:

        return (
            "SAFE",
            "No major suspicious characteristics were detected."
        )


# ========================================
# SCAN URL
# ========================================
@app.route("/api/scan", methods=["POST"])
def scan_url():

    # --------------------------------
    # GET REQUEST DATA
    # --------------------------------

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({
            "error": "URL is required"
        }), 400


    # --------------------------------
    # GET URL
    # --------------------------------

    url = data["url"].strip()


    # --------------------------------
    # CHECK EMPTY URL
    # --------------------------------

    if not url:

        return jsonify({
            "error": "Please enter a URL"
        }), 400


    # --------------------------------
    # ADD HTTPS IF PROTOCOL MISSING
    # --------------------------------

    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url


    # --------------------------------
    # PARSE URL
    # --------------------------------

    parsed = urlparse(url)


    # --------------------------------
    # CHECK HOSTNAME
    # --------------------------------

    if not parsed.hostname:

        return jsonify({
            "error": "Invalid URL"
        }), 400


    # ========================================
    # RUN ALL DETECTION METHODS
    # ========================================

    # --------------------------------
    # URL LENGTH
    # --------------------------------

    length_score, length_reason = \
        check_url_length(url)


    # --------------------------------
    # IP ADDRESS
    # --------------------------------

    ip_score, is_ip, ip_reason = \
        check_ip_address(
            parsed.hostname
        )


    # --------------------------------
    # @ SYMBOL
    # --------------------------------

    at_score, has_at_symbol, at_reason = \
        check_at_symbol(url)


    # --------------------------------
    # SUBDOMAIN
    # --------------------------------

    subdomain_score, subdomain_count, subdomain_reason = \
        check_subdomains(
            parsed.hostname
        )


    # --------------------------------
    # SUSPICIOUS TLD
    # --------------------------------

    tld_score, suspicious_tld, tld_reason = \
        check_suspicious_tld(
            parsed.hostname
        )


    # --------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------

    keyword_score, found_keywords, keyword_reason = \
        check_suspicious_keywords(url)


    # --------------------------------
    # PUNYCODE
    # --------------------------------

    punycode_score, has_punycode, punycode_reason = \
        check_punycode(
            parsed.hostname
        )
    # --------------------------------
    # HTTPS CHECK
    # --------------------------------

    https_score, is_https, https_reason = \
        check_https(parsed.scheme)

    # --------------------------------
    # DNS CHECK
    # --------------------------------
    dns_resolves, dns_records = check_dns(parsed.hostname)


    # ========================================
    # COMBINE RISK SCORES
    # ========================================

    risk_factors = []


    if length_score > 0:

        risk_factors.append({
            "feature": "URL Length",
            "score": length_score,
            "reason": length_reason
        })


    if ip_score > 0:

        risk_factors.append({
            "feature": "IP Address",
            "score": ip_score,
            "reason": ip_reason
        })


    if at_score > 0:

        risk_factors.append({
            "feature": "@ Symbol",
            "score": at_score,
            "reason": at_reason
        })


    if subdomain_score > 0:

        risk_factors.append({
            "feature": "Subdomains",
            "score": subdomain_score,
            "reason": subdomain_reason
        })


    if tld_score > 0:

        risk_factors.append({
            "feature": "Suspicious TLD",
            "score": tld_score,
            "reason": tld_reason
        })


    if keyword_score > 0:

        risk_factors.append({
            "feature": "Suspicious Keywords",
            "score": keyword_score,
            "reason": keyword_reason
    })


    if punycode_score > 0:

        risk_factors.append({
            "feature": "Punycode",
            "score": punycode_score,
            "reason": punycode_reason
        })


    if https_score > 0:

        risk_factors.append({
            "feature": "HTTPS",
            "score": https_score,
            "reason": https_reason
        })


# Calculate total score
    score = sum(
        factor["score"]
        for factor in risk_factors
    )


# Limit score to 100
    score = min(score, 100)


    # ========================================
    # CREATE EXPLANATIONS
    # ========================================

    reasons = []


    # URL length
    reasons.append(length_reason)


    # IP address
    if is_ip:

        reasons.append(ip_reason)


    # @ symbol
    if has_at_symbol:

        reasons.append(at_reason)


    # Subdomain
    if subdomain_count > 0:

        reasons.append(subdomain_reason)


    # Suspicious TLD
    if suspicious_tld:

        reasons.append(tld_reason)


    # Suspicious keywords
    if found_keywords:

        reasons.append(keyword_reason)


    # Punycode
    if has_punycode:

        reasons.append(punycode_reason)
    #https
    if not is_https:
        reasons.append(https_reason)


    # ========================================
    # LIMIT SCORE TO 100
    # ========================================

    score = min(score, 100)
    # --------------------------------
    # GET FINAL VERDICT
    # --------------------------------

    verdict, verdict_message = \
        get_risk_verdict(score)


    # ========================================
    # RETURN RESULT
    # ========================================

    return jsonify({

        "message":
            "URL analyzed successfully",

        "url":
            url,

        "domain":
            parsed.hostname,

        "protocol":
            parsed.scheme,

        "path":
            parsed.path,

        "url_length":
            len(url),

        "risk_score":
            score,
        "dns_resolves": dns_resolves,
        "dns_records": dns_records,

        "reasons":
            reasons,

        "is_ip_address":
            is_ip,

        "has_at_symbol":
            has_at_symbol,

        "subdomain_count":
            subdomain_count,

        "suspicious_tld":
            suspicious_tld,

        "found_keywords":
            found_keywords,

        "has_punycode":
            has_punycode,
        "is_https": is_https,
        "risk_factors": risk_factors,
        "verdict": verdict,
        "verdict_message": verdict_message,
    })


# ========================================
# START SERVER
# ========================================
if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )