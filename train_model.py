
import csv
import json
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from ml_features import extract_url_features


DATASET_PATH = Path("ml_training_urls.csv")
MODEL_PATH = Path("phishguard_model.joblib")
FEATURES_PATH = Path("ml_feature_names.json")



def load_dataset():
    urls = []
    labels = []

    with DATASET_PATH.open("r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)

        for row in reader:
            if not row:
                continue

            # Skip the CSV header row.
            if row[0].strip().lower() == "url":
                continue

            if len(row) != 3:
                raise ValueError(f"Invalid dataset row: {row}")

            url, label, source = row

            try:
                label = int(label.strip())
            except ValueError:
                raise ValueError(f"Invalid label in dataset row: {row}")

            if label not in (0, 1):
                raise ValueError(f"Invalid label: {label}")
            if not url.strip():
                raise ValueError("Dataset contains an empty URL.")

            if not source.strip():
                raise ValueError(f"Dataset row has an empty source: {row}")

            urls.append(url.strip())
            labels.append(label)
    if len(urls) != len(set(urls)):
        raise ValueError("Dataset contains duplicate URLs.")

    if len(set(labels)) < 2:
        raise ValueError("The dataset must contain both classes.")

    return urls, labels



def main():
    urls, labels = load_dataset()

    print(f"Total URLs: {len(urls)}")
    print(f"Legitimate URLs: {labels.count(0)}")
    print(f"Phishing URLs: {labels.count(1)}")

    if len(urls) < 50:
        print(
            "\nWARNING: This dataset is very small. "
            "Results are experimental and do not demonstrate "
            "real-world phishing detection accuracy."
        )

    features = [extract_url_features(url) for url in urls]
    feature_names = list(features[0].keys())
    X = [[row[name] for name in feature_names] for row in features]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        labels,
        test_size=0.30,
        random_state=42,
        stratify=labels,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print("\n--- Experimental holdout evaluation ---")
    print(f"Training samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.2%}")
    print("\nConfusion matrix (labels: 0=legitimate, 1=phishing):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    # Save the model for later experiments; do not integrate it into
    # the live scanner until it has been validated on better data.
    import joblib

    joblib.dump(model, MODEL_PATH)
    FEATURES_PATH.write_text(
        json.dumps(feature_names, indent=2),
        encoding="utf-8",
    )

    print(f"\nExperimental model saved to: {MODEL_PATH}")
    print(f"Feature names saved to: {FEATURES_PATH}")


if __name__ == "__main__":
    main()
