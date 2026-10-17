
import csv
import random
from pathlib import Path

PHISHING_FILE = Path("phishing_urls_clean.csv")
LEGITIMATE_FILE = Path("legitimate_urls_candidates.csv")
OUTPUT_FILE = Path("ml_dataset.csv")

SAMPLES_PER_CLASS = 10_000
RANDOM_SEED = 42


def read_rows(path):
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def main():
    phishing_rows = read_rows(PHISHING_FILE)
    legitimate_rows = read_rows(LEGITIMATE_FILE)

    if len(phishing_rows) < SAMPLES_PER_CLASS:
        raise ValueError("Not enough phishing URLs.")

    if len(legitimate_rows) < SAMPLES_PER_CLASS:
        raise ValueError("Not enough legitimate candidates.")

    random.seed(RANDOM_SEED)

    phishing_sample = random.sample(phishing_rows, SAMPLES_PER_CLASS)
    legitimate_sample = random.sample(legitimate_rows, SAMPLES_PER_CLASS)

    combined = []

    for row in phishing_sample:
        combined.append({
            "url": row["url"],
            "label": 1,
            "source": row["source"],
        })

    for row in legitimate_sample:
        combined.append({
            "url": row["url"],
            "label": 0,
            "source": row["source"],
        })

    random.shuffle(combined)

    # Remove exact URL duplicates across the two classes.
    unique_rows = []
    seen = set()

    for row in combined:
        key = row["url"].strip().lower()
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(row)

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["url", "label", "source"],
        )
        writer.writeheader()
        writer.writerows(unique_rows)

    counts = {
        "legitimate candidates": sum(r["label"] == 0 for r in unique_rows),
        "phishing": sum(r["label"] == 1 for r in unique_rows),
    }

    print("Dataset created:", OUTPUT_FILE)
    print("Total unique URLs:", len(unique_rows))
    print("Class counts:", counts)
    print("Random seed:", RANDOM_SEED)
    print(
        "Caution: Tranco entries are candidates, not independently "
        "verified legitimate URLs."
    )


if __name__ == "__main__":
    main()
