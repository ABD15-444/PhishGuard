
import csv
from pathlib import Path
from urllib.parse import urlsplit

INPUT_FILE = Path("verified_online (1).csv")
OUTPUT_FILE = Path("phishing_urls_clean.csv")


def valid_http_url(value):
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
            and not any(char.isspace() for char in value)
        )
    except ValueError:
        return False


def main():
    seen_urls = set()
    cleaned_rows = []
    skipped = 0

    with INPUT_FILE.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        reader = csv.DictReader(file)

        required = {"phish_id", "url", "verified", "online"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(
                f"Missing required columns. Found: {reader.fieldnames}"
            )

        for row in reader:
            url = (row.get("url") or "").strip()
            verified = (row.get("verified") or "").strip().lower()
            online = (row.get("online") or "").strip().lower()

            if verified != "yes" or online != "yes":
                skipped += 1
                continue

            if not valid_http_url(url):
                skipped += 1
                continue

            normalized_url = url.lower()

            if normalized_url in seen_urls:
                skipped += 1
                continue

            seen_urls.add(normalized_url)

            cleaned_rows.append({
                "url": url,
                "label": 1,
                "source": "phishtank",
                "phish_id": (row.get("phish_id") or "").strip(),
            })

    with OUTPUT_FILE.open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["url", "label", "source", "phish_id"],
        )
        writer.writeheader()
        writer.writerows(cleaned_rows)

    print("PhishTank preparation complete")
    print("Clean phishing URLs:", len(cleaned_rows))
    print("Skipped records:", skipped)
    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
