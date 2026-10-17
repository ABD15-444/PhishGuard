
import json
import joblib
import numpy as np

from ml_features_hostname_experiment import (
    extract_experimental_features,
)

model = joblib.load("phishguard_hostname_experiment.joblib")

with open("ml_hostname_experiment_features.json", "r") as file:
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

for url in urls:
    features = extract_experimental_features(url)

    X = np.asarray(
        [[features.get(name, 0) for name in feature_names]],
        dtype=float,
    )

    probability = model.predict_proba(X)[0][1]
    prediction = "PHISHING" if probability >= 0.5 else "LEGITIMATE"

    print(f"{probability:8.2%}  {prediction:11}  {url}")
