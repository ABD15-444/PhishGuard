
import csv
from collections import Counter

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from experimental_rules import inspect_url


def main():
    with open(
        "detector_comparison_results.csv",
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    actual = [int(row["actual_label"]) for row in rows]
    predictions = []
    review_count = 0

    for row in rows:
        result = inspect_url(row["url"])
        verdict = result["experimental_verdict"]

        if verdict == "REVIEW":
            review_count += 1

        # For this diagnostic only, treat REVIEW as a positive signal.
        predictions.append(
            1 if verdict == "SUSPICIOUS" else
            1 if verdict == "REVIEW" else 0
        )

    print("URLs evaluated:", len(rows))
    print("Experimental verdict counts:")

    verdict_counts = Counter(
        inspect_url(row["url"])["experimental_verdict"]
        for row in rows
    )
    for verdict, count in verdict_counts.items():
        print(f"  {verdict}: {count}")

    print("\nExperimental rules (REVIEW counted as positive)")
    print(f"Accuracy:  {accuracy_score(actual, predictions):.4f}")
    print(f"Precision: {precision_score(actual, predictions, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(actual, predictions, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(actual, predictions, zero_division=0):.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(actual, predictions, labels=[0, 1]))

    print(
        "\nCaution: labels are dataset-derived, and REVIEW is treated "
        "as a positive prediction only for this experiment."
    )


if __name__ == "__main__":
    main()
