import pandas as pd
import joblib

from ml_features import extract_url_features

EVIDENCE_FILE = "automated_validation_subset.csv"
MODEL_FILE = "phishguard_large_model.joblib"
OUTPUT_FILE = "ml_evidence_comparison.csv"

df = pd.read_csv(EVIDENCE_FILE)
model = joblib.load(MODEL_FILE)

import json

with open("ml_large_feature_names.json", "r") as f:
    feature_names = json.load(f)

import numpy as np

features = np.asarray(
    [
        [extract_url_features(url)[name] for name in feature_names]
        for url in df["url"]
    ],
    dtype=float
)

predictions = model.predict(features)
probabilities = model.predict_proba(features)

classes = list(model.classes_)
phishing_index = classes.index(1)

df["ml_prediction"] = predictions
df["ml_phishing_probability"] = probabilities[:, phishing_index]

df["comparison"] = "uncertain_evidence"

supported = df["validation_status"] == "phishing_supported"

df.loc[
    supported & (df["ml_prediction"] == 1),
    "comparison"
] = "agreement_phishing"

df.loc[
    supported & (df["ml_prediction"] == 0),
    "comparison"
] = "disagreement_review"

df.to_csv(OUTPUT_FILE, index=False)

print("ML vs VirusTotal evidence comparison")
print("=" * 45)
print(df["comparison"].value_counts().to_string())

print("\nBreakdown by source:")
print(
    pd.crosstab(df["source"], df["comparison"]).to_string()
)

print(f"\nSaved: {OUTPUT_FILE}")