
import csv
import json
import joblib
import numpy as np

from ml_features import extract_url_features

model = joblib.load("phishguard_large_model.joblib")

with open("ml_large_feature_names.json", "r") as file:
    feature_names = json.load(file)

urls = [
    "https://paypal-banking.pro",
    "https://paypal-banking.pro/",
    "https://www.paypal-banking.pro",
    "https://www.paypal-banking.pro/",
    "http://paypal-banking.pro/",
    "https://paypal-banking.pro/login",
    "https://fide-litiy.cyou/",
    "https://fide-lltny.cyou/",
]

results = []

for url in urls:
    features = extract_url_features(url)
    X = np.asarray(
        [[features.get(name, 0) for name in feature_names]],
        dtype=float,
    )

    probability = float(model.predict_proba(X)[0][1])

    results.append({
        "url": url,
        "phishing_probability": round(probability, 6),
        "predicted_label": (
            "phishing" if model.predict(X)[0] == 1 else "legitimate"
        ),
    })

with open("url_variant_evaluation.csv", "w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=results[0].keys())
    writer.writeheader()
    writer.writerows(results)

for result in results:
    print(
        f'{result["phishing_probability"]:>8.2%}  '
        f'{result["predicted_label"]:>11}  {result["url"]}'
    )

print("\nSaved: url_variant_evaluation.csv")
