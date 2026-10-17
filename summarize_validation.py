
import pandas as pd

INPUT_FILE = "virustotal_batch_evidence.csv"
OUTPUT_FILE = "validation_evidence_summary.csv"

df = pd.read_csv(INPUT_FILE)

print("=== PHISHGUARD VALIDATION EVIDENCE SUMMARY ===")
print("Total records:", len(df))
print("Unique URLs:", df["url"].nunique())

print("\n--- By source and evidence classification ---")
print(pd.crosstab(
    df["source"],
    df["evidence_classification"],
    margins=True
))

print("\n--- VirusTotal report status ---")
print(df["vt_status"].value_counts().to_string())

print("\n--- Records requiring follow-up ---")
follow_up = df[df["evidence_classification"].isin([
    "needs_review",
    "insufficient_evidence"
])]

print("Follow-up records:", len(follow_up))

# Save counts by source, status, and evidence classification.
summary = (
    df.groupby(
        ["source", "vt_status", "evidence_classification"],
        dropna=False
    )
    .size()
    .reset_index(name="count")
)

summary.to_csv(OUTPUT_FILE, index=False)
print("\nSummary saved to:", OUTPUT_FILE)
print(
    "\nNote: These are evidence categories, "
    "not independently verified labels."
)
