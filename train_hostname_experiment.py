
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

from ml_features_hostname_experiment import (
    extract_experimental_features,
)

TRAIN_FILE = Path("ml_train.csv")
TEST_FILE = Path("ml_test.csv")
MODEL_FILE = Path("phishguard_hostname_experiment.joblib")
FEATURE_FILE = Path("ml_hostname_experiment_features.json")


def build_features(urls, feature_names=None):
    rows = [
        extract_experimental_features(url)
        for url in urls
    ]

    frame = pd.DataFrame(rows)

    if feature_names is not None:
        frame = frame.reindex(columns=feature_names, fill_value=0)

    return frame


def main():
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE)

    X_train_frame = build_features(train["url"])
    feature_names = X_train_frame.columns.tolist()

    X_test_frame = build_features(
        test["url"],
        feature_names,
    )

    X_train = X_train_frame.to_numpy(dtype=float)
    X_test = X_test_frame.to_numpy(dtype=float)

    y_train = train["label"].astype(int).to_numpy()
    y_test = test["label"].astype(int).to_numpy()

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("\n--- Hostname experiment ---")
    print("Training URLs:", len(train))
    print("Testing URLs:", len(test))
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(
        f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}"
    )
    print(f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

    print("\nConfusion matrix (0=legitimate candidate, 1=phishing):")
    print(confusion_matrix(y_test, predictions))

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Legitimate candidate", "Phishing"],
            zero_division=0,
        )
    )

    joblib.dump(model, MODEL_FILE)

    with open(FEATURE_FILE, "w") as file:
        json.dump(feature_names, file, indent=2)

    print("Model saved to:", MODEL_FILE)
    print("Features saved to:", FEATURE_FILE)
    print("\nExperimental only; not integrated into app.py.")


if __name__ == "__main__":
    main()
