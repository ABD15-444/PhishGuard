
import json
from pathlib import Path

import joblib
import pandas as pd

from ml_features import extract_url_features

BASE = Path(__file__).resolve().parent

DATA_FILE = BASE / "virustotal_batch_evidence.csv"
MODEL_FILE = BASE / "phishguard_large_model.joblib"
FEATURE_FILE = BASE / "ml_large_feature_names.json"
OUTPUT_FILE = BASE / "validation_predictions.csv"


def main():
    df = pd.read_csv(DATA_FILE)

    model = joblib.load(MODEL_FILE)

    with open(FEATURE_FILE, "r", encoding="utf-8") as file:
        feature_names = json.load(file)

    records = []

    for _, row in df.iterrows():
        features = extract_url_features(str(row["url"]))

        feature_row = [
            features.get(name, 0)
            for name in feature_names
        ]

        import numpy as np

        feature_row = np.asarray(feature_row, dtype=float).reshape(1, -1)

        prediction = int(model.predict(feature_row)[0])
        probabilities = model.predict_proba(feature_row)[0]
        classes = list(model.classes_)

        phishing_probability = (
            float(probabilities[classes.index(1)])
            if 1 in classes
            else 0.0
        )

        records.append({
            "url": row["url"],
            "source": row["source"],
            "vt_status": row["vt_status"],
            "evidence_classification": row["evidence_classification"],
            "ml_prediction": prediction,
            "ml_prediction_label": (
                "phishing" if prediction == 1 else "legitimate"
            ),
            "ml_phishing_probability": round(
                phishing_probability, 4
            ),
        })

    results = pd.DataFrame(records)
    results.to_csv(OUTPUT_FILE, index=False)

    print("URLs analyzed:", len(results))
    print("\nML predictions:")
    print(results["ml_prediction_label"].value_counts().to_string())

    print("\nPredictions by evidence classification:")
    print(pd.crosstab(
        results["evidence_classification"],
        results["ml_prediction_label"],
        margins=True,
    ).to_string())

    print("\nSaved:", OUTPUT_FILE.name)
    print(
        "\nNOTE: These are predictions compared with evidence categories, "
        "not validated accuracy metrics."
    )


if __name__ == "__main__":
    main()
