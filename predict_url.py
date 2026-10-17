"""Offline URL phishing prediction using the experimental machine-learning model.

Demonstrates lexical feature extraction and experimental inference.
This module is strictly experimental and does NOT override live security verdicts.
"""

import os
import json
import sys
import joblib

from ml_features import extract_url_features

DEFAULT_MODEL = "phishguard_large_model.joblib" if os.path.exists("phishguard_large_model.joblib") else "phishguard_model.joblib"
DEFAULT_FEATURES = "ml_large_feature_names.json" if os.path.exists("ml_large_feature_names.json") else "ml_feature_names.json"

MODEL_PATH = os.getenv("PHISHGUARD_MODEL_PATH", DEFAULT_MODEL)
FEATURES_PATH = os.getenv("PHISHGUARD_FEATURES_PATH", DEFAULT_FEATURES)


def predict_url(url, model_path=None, features_path=None):
    """Predict phishing probability for a URL using the experimental model.

    Returns:
        dict: Containing prediction, probability, verdict, and feature vector.
    Raises:
        FileNotFoundError: If model or feature list is not found.
        ValueError: If feature schema is incompatible.
    """
    m_path = model_path or MODEL_PATH
    f_path = features_path or FEATURES_PATH

    if not os.path.exists(m_path):
        raise FileNotFoundError(f"Model file not found: {m_path}")

    if not os.path.exists(f_path):
        raise FileNotFoundError(f"Feature schema file not found: {f_path}")

    model = joblib.load(m_path)

    with open(f_path, "r", encoding="utf-8") as file:
        feature_names = json.load(file)

    features = extract_url_features(url)
    missing = [name for name in feature_names if name not in features]
    if missing:
        raise ValueError(f"Feature extraction schema missing required features: {missing}")

    row = [[features[name] for name in feature_names]]

    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]
    classes = list(model.classes_)

    if 1 in classes:
        phishing_index = classes.index(1)
        probability = float(probabilities[phishing_index])
    else:
        probability = float(prediction)

    verdict = "PHISHING" if prediction == 1 else "LEGITIMATE"

    result = {
        "url": url,
        "prediction": prediction,
        "verdict": verdict,
        "probability": probability,
        "features": features,
        "disclaimer": "Experimental model only. This is not a verified security verdict."
    }

    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python3 predict_url.py "https://example.com/login"')
        raise SystemExit(1)

    target_url = sys.argv[1]
    try:
        res = predict_url(target_url)
        print(f"URL: {res['url']}")
        print(f"ML prediction: {res['verdict']}")
        print(f"Model phishing probability: {res['probability']:.2%}")
        print(f"Note: {res['disclaimer']}")
    except Exception as err:
        print(f"Error during ML prediction: {err}", file=sys.stderr)
        raise SystemExit(1)
