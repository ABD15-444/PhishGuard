
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
]

for url in urls:
    features = extract_url_features(url)
    X = np.asarray(
        [[features.get(name, 0) for name in feature_names]],
        dtype=float,
    )

    probability = model.predict_proba(X)[0][1]

    print(f"{url:45} {probability:8.2%}")
