
import csv
import random
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

INPUT_FILE = Path("ml_dataset_domain_clean.csv")
TRAIN_FILE = Path("ml_train.csv")
TEST_FILE = Path("ml_test.csv")

TEST_FRACTION = 0.20
RANDOM_SEED = 42


def get_domain(url):
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def main():
    with INPUT_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    # Group rows by exact hostname so a hostname cannot cross splits.
    groups = defaultdict(list)
    for row in rows:
        domain = get_domain(row["url"])
        if domain:
            groups[domain].append(row)

    domains = list(groups)
    random.Random(RANDOM_SEED).shuffle(domains)

    target_test_rows = round(len(rows) * TEST_FRACTION)
    test_rows = []
    train_rows = []

    for domain in domains:
        group = groups[domain]

        if len(test_rows) < target_test_rows:
            test_rows.extend(group)
        else:
            train_rows.extend(group)

    # Ensure both classes occur in both sets.
    for name, split in [("train", train_rows), ("test", test_rows)]:
        labels = {row["label"] for row in split}
        if labels != {"0", "1"}:
            raise ValueError(
                f"{name} split does not contain both classes: {labels}"
            )

    def write_rows(path, split):
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["url", "label", "source"],
            )
            writer.writeheader()
            writer.writerows(split)

    write_rows(TRAIN_FILE, train_rows)
    write_rows(TEST_FILE, test_rows)

    train_domains = {get_domain(r["url"]) for r in train_rows}
    test_domains = {get_domain(r["url"]) for r in test_rows}

    print("Training rows:", len(train_rows))
    print("Testing rows:", len(test_rows))
    print("Training labels:", {
        label: sum(r["label"] == label for r in train_rows)
        for label in ("0", "1")
    })
    print("Testing labels:", {
        label: sum(r["label"] == label for r in test_rows)
        for label in ("0", "1")
    })
    print("Domain overlap:", len(train_domains & test_domains))
    print("Files:", TRAIN_FILE, TEST_FILE)


if __name__ == "__main__":
    main()
