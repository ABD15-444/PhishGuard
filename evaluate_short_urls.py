
import json
import joblib
import numpy as np
import pandas as pd

from ml_features import extract_url_features

df = pd.read_csv("ml_test.csv")
df["url_length"] = df["url"].astype(str).str.len()

short_urls = df[df["url_length"] < 30].copy()

model = joblib.load("phishguard_large_model.joblib")

with open("ml_large_feature_names.json", "r") as file:
    feature_names = json.load(file)

features = []

for url in short_urls["url"]:
    extracted = extract_url_features(url)
    features.append([
        extracted.get(name, 0)
        for name in feature_names
    ])

X = np.asarray(features, dtype=float)
predictions = model.predict(X)

short_urls["predicted_label"] = predictions

print("SHORT-URL EVALUATION")
print("-" * 45)
print("Total short URLs:", len(short_urls))
print("\nActual labels:")
print(short_urls["label"].value_counts().sort_index())

print("\nPredictions by actual label:")
print(pd.crosstab(
    short_urls["label"],
    short_urls["predicted_label"],
    rownames=["Actual"],
    colnames=["Predicted"],
    margins=True
))

missed = short_urls[
    (short_urls["label"] == 1) &
    (short_urls["predicted_label"] == 0)
]

print("\nPhishing URLs predicted as legitimate:", len(missed))
print("\nFirst 20 missed URLs:")
print(missed[["url", "url_length"]].head(20).to_string(index=False))

print("\nDetailed analysis of missed URLs:")

missed = missed.copy()
missed["phishing_probability"] = model.predict_proba(
    np.asarray([
        [
            extract_url_features(url).get(name, 0)
            for name in feature_names
        ]
        for url in missed["url"]
    ], dtype=float)
)[:, 1]

print(
    missed[["url", "url_length", "phishing_probability"]]
    .sort_values("phishing_probability")
    .to_string(index=False)
)
