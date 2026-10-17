
import csv
from collections import Counter
from experimental_rules import inspect_url


def main():
    with open(
        "detector_comparison_results.csv",
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    missed = []

    for row in rows:
        if row["actual_label"] != "1":
            continue

        result = inspect_url(row["url"])

        if result["experimental_verdict"] == "NO_ADDITIONAL_SIGNALS":
            missed.append(row["url"])

    print("Phishing-labelled URLs with no experimental signals:", len(missed))
    print("\nFirst 30 examples:")

    for url in missed[:30]:
        print(url)


if __name__ == "__main__":
    main()
