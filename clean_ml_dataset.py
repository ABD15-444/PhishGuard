
import csv
from pathlib import Path
from urllib.parse import urlsplit

INPUT_FILE = Path("ml_dataset.csv")
OUTPUT_FILE = Path("ml_dataset_domain_clean.csv")


def get_hostname(url):
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def main():
    with INPUT_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    domains_by_label = {"0": set(), "1": set()}

    for row in rows:
        label = row["label"].strip()
        if label in domains_by_label:
            hostname = get_hostname(row["url"])
            if hostname:
                domains_by_label[label].add(hostname)

    overlapping_domains = (
        domains_by_label["0"] & domains_by_label["1"]
    )

    cleaned_rows = []
    removed = 0

    for row in rows:
        hostname = get_hostname(row["url"])

        if hostname in overlapping_domains:
            removed += 1
            continue

        cleaned_rows.append(row)

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["url", "label", "source"],
        )
        writer.writeheader()
        writer.writerows(cleaned_rows)

    print("Overlapping domains removed:", len(overlapping_domains))
    print("Rows removed:", removed)
    print("Rows remaining:", len(cleaned_rows))
    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
