
import csv
from collections import Counter

with open("detector_comparison_results.csv", newline="", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))

actual_phishing = [r for r in rows if r["actual_label"] == "1"]
actual_legitimate = [r for r in rows if r["actual_label"] == "0"]

print("Accepted URLs:", len(rows))
print("Actual phishing labels:", len(actual_phishing))
print("Actual legitimate labels:", len(actual_legitimate))

print("\nRule-based predictions:")
print(Counter(r["rule_based_prediction"] for r in rows))

print("\nML predictions:")
print(Counter(r["ml_prediction"] for r in rows))

