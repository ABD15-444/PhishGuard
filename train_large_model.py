
import csv
import json
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from ml_features import extract_url_features

TRAIN_FILE = Path("ml_train.csv")
TEST_FILE = Path("ml_test.csv")
MODEL_FILE = Path("phishguard_large_model.joblib")
FEATURES_FILE = Path("ml_large_feature_names.json")


def load_rows(path):
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    for row in rows:
        row["label"] = int(row["label"])
        if row["label"] not in (0, 1):
            raise ValueError(f"Invalid label in {path}: {row}")

    return rows


def make_features(rows, feature_names=None):
    feature_dicts = [
        extract_url_features(row["url"])
        for row in rows
    ]

    if feature_names is None:
        feature_names = list(feature_dicts[0].keys())

    X = [
        [features[name] for name in feature_names]
        for features in feature_dicts
    ]
    y = [row["label"] for row in rows]

    return X, y, feature_names


def main():
    train_rows = load_rows(TRAIN_FILE)
    test_rows = load_rows(TEST_FILE)

    X_train, y_train, feature_names = make_features(train_rows)
    X_test, y_test, _ = make_features(test_rows, feature_names)

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    print(f"Training URLs: {len(train_rows)}")
    print(f"Testing URLs: {len(test_rows)}")

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("\n--- Experimental evaluation ---")
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(
        f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}"
    )
    print(
        f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}"
    )
    print(f"F1-score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

    print("\nConfusion matrix (labels: 0=legitimate candidate, 1=phishing):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

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
    FEATURES_FILE.write_text(
        json.dumps(feature_names, indent=2),
        encoding="utf-8",
    )

    print(f"Model saved to: {MODEL_FILE}")
    print(f"Features saved to: {FEATURES_FILE}")
    print(
        "\nCAUTION: These results are experimental. "
        "Tranco domains are not independently verified as safe, "
        "and class labels are correlated with dataset source."
    )


if __name__ == "__main__":
    main()
