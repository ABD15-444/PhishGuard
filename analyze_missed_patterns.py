
import csv
from collections import Counter
from urllib.parse import urlparse
import re

def main():
    with open(
        "detector_comparison_results.csv",
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    missed = [
        row["url"]
        for row in rows
        if row["actual_label"] == "1"
        and row["rule_based_prediction"] == "0"
    ]

    hosting_suffixes = (
        "firebaseapp.com", "web.app", "wixstudio.com",
        "netlify.app", "vercel.app", "weebly.com",
        "github.io", "gitbook.io", "pages.dev",
        "weebly.com", "plutio.com", "start.page",
    )

    patterns = Counter()

    for url in missed:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        if any(host == suffix or host.endswith("." + suffix)
               for suffix in hosting_suffixes):
            patterns["Shared hosting/platform domain"] += 1

        if len(host) >= 30:
            patterns["Long hostname"] += 1

        if host.count("-") >= 2:
            patterns["Hyphen-heavy hostname"] += 1

        if re.search(r"\d{4,}", host):
            patterns["Four or more consecutive digits in hostname"] += 1

        if len(path) >= 40:
            patterns["Long URL path"] += 1

        if query:
            patterns["Has query parameters"] += 1

        if "%" in url:
            patterns["Percent-encoded characters"] += 1

        if "@" in url:
            patterns["@ symbol"] += 1

    print("Missed phishing-labelled URLs:", len(missed))
    print("\nOverlapping URL patterns:")
    for pattern, count in patterns.most_common():
        print(f"{pattern}: {count}")

if __name__ == "__main__":
    main()
