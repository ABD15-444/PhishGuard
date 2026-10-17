
import csv
from pathlib import Path
from urllib.parse import urlsplit

INPUT_FILE = Path("tranco_domains.csv")
OUTPUT_FILE = Path("legitimate_urls_candidates.csv")

# Keep the first 10,000 ranked domains for this initial experiment.
MAX_DOMAINS = 10_000


def valid_domain(domain):
    domain = domain.strip().lower()

    if not domain or len(domain) > 253:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    try:
        parsed = urlsplit("https://" + domain)
        hostname = parsed.hostname

        if not hostname or hostname != domain:
            return False

        if any(not label for label in hostname.split(".")):
            return False

        return all(
            len(label) <= 63
            and label[0] != "-"
            and label[-1] != "-"
            and all(char.isalnum() or char == "-" for char in label)
            for label in hostname.split(".")
        )
    except ValueError:
        return False


def main():
    seen = set()
    rows = []
    invalid = 0

    with INPUT_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)

        for row in reader:
            if not row or len(row) < 2:
                invalid += 1
                continue

            rank, domain = row[0].strip(), row[1].strip().lower()

            if not rank.isdigit() or not valid_domain(domain):
                invalid += 1
                continue

            if domain in seen:
                continue

            seen.add(domain)

            rows.append({
                "url": "https://" + domain + "/",
                "label": 0,
                "source": "tranco_candidate",
                "rank": rank,
            })

            if len(rows) >= MAX_DOMAINS:
                break

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["url", "label", "source", "rank"],
        )
        writer.writeheader()
        writer.writerows(rows)

    print("Legitimate candidate preparation complete")
    print("Candidate domains:", len(rows))
    print("Invalid rows skipped:", invalid)
    print("Output:", OUTPUT_FILE)
    print("Note: Tranco popularity is not proof of safety.")


if __name__ == "__main__":
    main()
