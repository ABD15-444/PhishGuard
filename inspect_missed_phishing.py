
import csv
from collections import Counter

with open("detector_comparison_results.csv", newline="", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))

missed = [
    row for row in rows
    if row["actual_label"] == "1"
    and row["rule_based_prediction"] == "0"
]

print("Missed phishing-labelled URLs:", len(missed))
print("ML detected among missed:", Counter(
    row["ml_prediction"] for row in missed
))

print("\nFirst 20 examples:")
for row in missed[:20]:
    print(row["url"])
