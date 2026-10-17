
import json
import joblib
import numpy as np

from ml_features import extract_url_features

model = joblib.load("phishguard_large_model.joblib")

with open("ml_large_feature_names.json", "r") as file:
    feature_names = json.load(file)

urls = [
    "https://www.paypal-banking.pro",
    "https://paypal-banking.pro/",
    "https://paypal.me/",
    "https://fide-litiy.cyou/",
    "https://fide-lltny.cyou/",
]

for url in urls:
    features = extract_url_features(url)

    X = np.asarray(
        [[features.get(name, 0) for name in feature_names]],
        dtype=float,
    )

    prediction = int(model.predict(X)[0])
    phishing_probability = model.predict_proba(X)[0][1]

    print(f"\nURL: {url}")
    print("Predicted class:", "PHISHING" if prediction == 1 else "LEGITIMATE")
    print(f"Phishing probability: {phishing_probability:.2%}")
