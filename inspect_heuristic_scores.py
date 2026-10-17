
import csv
from unittest.mock import patch

import app as phishguard


def inspect_url(url):
    from urllib.parse import urlparse

    parsed = urlparse(url)
    domain = parsed.hostname

    length_score, _ = phishguard.check_url_length(url)
    ip_score, _, _ = phishguard.check_ip_address(domain)
    at_score, _, _ = phishguard.check_at_symbol(url)
    subdomain_score, subdomain_count, _ = (
        phishguard.check_subdomains(domain)
    )
    tld_score, suspicious_tld, _ = (
        phishguard.check_suspicious_tld(domain)
    )
    keyword_score, found_keywords, _ = (
        phishguard.check_suspicious_keywords(url)
    )
    punycode_score, has_punycode, _ = (
        phishguard.check_punycode(domain)
    )
    https_score, is_https, _ = (
        phishguard.check_https(parsed.scheme)
    )

    combination_score = 15 if len(found_keywords) >= 3 else 0

    scores = {
        "url_length": length_score,
        "ip_address": ip_score,
        "at_symbol": at_score,
        "subdomains": subdomain_score,
        "suspicious_tld": tld_score,
        "keywords": keyword_score,
        "keyword_combination": combination_score,
        "punycode": punycode_score,
        "https": https_score,
    }

    total = min(sum(scores.values()), 100)
    verdict, _ = phishguard.get_risk_verdict(total)

    return scores, total, verdict, {
        "domain": domain,
        "subdomain_count": subdomain_count,
        "suspicious_tld": suspicious_tld,
        "keywords": found_keywords,
        "punycode": has_punycode,
        "https": is_https,
    }


def main():
    with open(
        "detector_comparison_results.csv",
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    missed = [
        row for row in rows
        if row["actual_label"] == "1"
        and row["rule_based_prediction"] == "0"
    ]

    print(f"Missed phishing-labelled URLs: {len(missed)}")
    print("Inspecting the first 20 examples.\n")

    for row in missed[:20]:
        url = row["url"]
        scores, total, verdict, details = inspect_url(url)

        print("=" * 75)
        print("URL:", url)
        print("Domain:", details["domain"])
        print("Individual scores:", scores)
        print("Total heuristic score:", total)
        print("Verdict:", verdict)
        print("Detected keywords:", details["keywords"])
        print("Subdomain count:", details["subdomain_count"])


if __name__ == "__main__":
    main()
