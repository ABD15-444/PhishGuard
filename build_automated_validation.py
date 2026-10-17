import pandas as pd

INPUT = "virustotal_batch_evidence.csv"
OUTPUT = "automated_validation_subset.csv"
SUMMARY = "automated_validation_summary.csv"

df = pd.read_csv(INPUT)

# Keep only URLs with positive phishing evidence.
# Everything else remains unverified rather than being
# incorrectly labelled as legitimate.
df["validation_label"] = pd.NA
df.loc[
    df["evidence_classification"] == "phishing_supported",
    "validation_label"
] = 1

df["validation_status"] = "excluded_uncertain"

df.loc[
    df["evidence_classification"] == "phishing_supported",
    "validation_status"
] = "phishing_supported"

# Save all records so no evidence is lost.
df.to_csv(OUTPUT, index=False)

summary = (
    df.groupby(["source", "validation_status"])
    .size()
    .reset_index(name="count")
)

summary.to_csv(SUMMARY, index=False)

print("Automated validation files created.")
print(f"Input URLs: {len(df)}")
print(f"Phishing-supported: {(df['validation_status'] == 'phishing_supported').sum()}")
print(f"Excluded as uncertain: {(df['validation_status'] == 'excluded_uncertain').sum()}")

print("\nBreakdown:")
print(summary.to_string(index=False))

print("\nFiles:")
print(OUTPUT)
print(SUMMARY)