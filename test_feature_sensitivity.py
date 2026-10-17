
import json
import joblib
import numpy as np

from ml_features import extract_url_features

model = joblib.load("phishguard_large_model.joblib")

with open("ml_large_feature_names.json", "r") as file:
    feature_names = json.load(file)

url = "https://paypal-banking.pro/"
features = extract_url_features(url)

def predict(feature_values):
    X = np.asarray(
        [[feature_values.get(name, 0) for name in feature_names]],
        dtype=float,
    )
    return model.predict_proba(X)[0][1]

print("Baseline URL:", url)
print(f"Baseline probability: {predict(features):.2%}")

tests = {
    "Baseline": {},
    "Subdomain count set to 1": {"subdomain_count": 1},
    "Dot count set to 2": {"dot_count": 2},
    "Hostname length increased by 4": {
        "hostname_length": features["hostname_length"] + 4
    },
    "URL length increased by 4": {
        "url_length": features["url_length"] + 4
    },
    "HTTPS disabled": {"https": 0},
}

print("\nFEATURE SENSITIVITY")
print("-" * 50)

for label, changes in tests.items():
    modified = features.copy()
    modified.update(changes)
    print(f"{label:35} {predict(modified):.2%}")
