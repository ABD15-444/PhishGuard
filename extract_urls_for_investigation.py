import pandas as pd

INPUT = "ml_evidence_comparison.csv"
OUTPUT = "urls_for_investigation.csv"

df = pd.read_csv(INPUT)

# The nine phishing-evidence disagreements
disagreements = df[
    df["comparison"] == "disagreement_review"
].copy()

disagreements["investigation_reason"] = (
    "VirusTotal supports phishing, but ML predicts legitimate"
)

# Tranco candidates predicted as phishing
tranco_flags = df[
    (df["source"] == "fresh_tranco_candidate")
    & (df["ml_prediction"] == 1)
].copy()

if len(tranco_flags) == 0:
    # Check detector_comparison_results for popular domains flagged as phishing
    try:
        det_df = pd.read_csv("detector_comparison_results.csv")
        flagged_tranco = det_df[
            (det_df["actual_label"] == 0)
            & (det_df["rule_based_prediction"] == 1)
        ].copy()
        
        tranco_flags = pd.DataFrame({
            "url": flagged_tranco["url"],
            "source": "tranco_candidate",
            "ml_prediction": flagged_tranco["ml_prediction"],
            "ml_phishing_probability": None,
            "evidence_classification": "flagged_popular_domain",
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "comparison": "rule_based_false_positive",
            "investigation_reason": "Popular-domain candidate predicted as phishing by rule-based detector"
        })
    except Exception as e:
        print("Note: detector_comparison_results.csv not found or unreadable:", e)

result = pd.concat(
    [disagreements, tranco_flags],
    ignore_index=True
)

# Remove duplicate URLs while preserving the first reason
result = result.drop_duplicates(subset=["url"])

columns = [
    "url",
    "source",
    "ml_prediction",
    "ml_phishing_probability",
    "evidence_classification",
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "comparison",
    "investigation_reason",
]

result[columns].to_csv(OUTPUT, index=False)

print("Investigation export created")
print("Unique URLs:", len(result))
print("\nReasons:")
print(result["investigation_reason"].value_counts().to_string())
print("\nSaved:", OUTPUT)