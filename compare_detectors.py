
import csv
import json
import joblib
import numpy as np

from unittest.mock import patch
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

import app as phishguard
from ml_features import extract_url_features


TEST_FILE = "ml_test.csv"
MODEL_FILE = "phishguard_large_model.joblib"
FEATURE_FILE = "ml_large_feature_names.json"


def load_test_data():
    urls, labels = [], []

    with open(TEST_FILE, newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            urls.append(row["url"])
            labels.append(int(row["label"]))

    return urls, np.array(labels)


def rule_based_prediction(client, url):
    """Run the real scanner while disabling external network calls."""
    parsed_hostname = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    parsed_hostname = parsed_hostname.split(":")[0]

    with (
        patch.object(phishguard, "get_ip_intelligence", return_value={
            "domain": parsed_hostname,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "resolved": False,
            "message": "Mocked evaluation",
        }),
        patch.object(phishguard, "get_ip_geolocation", return_value=None),
        patch.object(phishguard, "check_dns", return_value=(
            False,
            {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
            {"domain_resolves": False, "has_ipv4": False,
             "has_ipv6": False, "has_nameservers": False,
             "has_mail_servers": False, "lookup_status": {},
             "findings": ["Mocked evaluation"]},
        )),
        patch.object(phishguard, "get_domain_information", return_value={
            "registered_domain": parsed_hostname,
            "subdomain": "",
            "tld": "",
        }),
        patch.object(phishguard, "get_rdap_information", return_value={
            "available": False, "message": "Mocked evaluation",
        }),
        patch.object(phishguard, "check_ssl_certificate", return_value={
            "checked": False, "valid": False, "message": "Mocked evaluation",
        }),
        patch.object(phishguard, "analyze_redirects", return_value={
            "checked": False, "redirect_count": 0, "final_url": url,
            "https_downgrade": False, "excessive_redirects": False,
            "findings": [],
        }),
        patch.object(phishguard, "check_virustotal", return_value={
            "available": False, "message": "Disabled during evaluation",
        }),
    ):
        response = client.post("/api/scan", json={"url": url})

    if response.status_code != 200:
        raise RuntimeError(
            f"Rule-based scan failed for {url}: "
            f"{response.status_code} {response.get_data(as_text=True)}"
        )

    verdict = response.get_json()["verdict"]
    return 0 if verdict == "SAFE" else 1


def print_metrics(name, actual, predicted):
    print(f"\n=== {name} ===")
    print(f"Accuracy:  {accuracy_score(actual, predicted):.4f}")
    print(f"Precision: {precision_score(actual, predicted, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(actual, predicted, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(actual, predicted, zero_division=0):.4f}")
    print("Confusion matrix [ [TN, FP], [FN, TP] ]:")
    print(confusion_matrix(actual, predicted, labels=[0, 1]))


def main():
    urls, actual = load_test_data()

    model = joblib.load(MODEL_FILE)
    with open(FEATURE_FILE, encoding="utf-8") as file:
        feature_names = json.load(file)

    X = np.array([
        [extract_url_features(url)[name] for name in feature_names]
        for url in urls
    ])
    ml_predictions = model.predict(X).astype(int)

    client = phishguard.app.test_client()
    rule_predictions = []

    
    rule_predictions = []
    valid_indices = []
    invalid_urls = []

    for index, (url, label) in enumerate(zip(urls, actual), start=1):
        try:
            prediction = rule_based_prediction(client, url)
            rule_predictions.append(prediction)
            valid_indices.append(index - 1)

        except RuntimeError as error:
            invalid_urls.append({
                "url": url,
                "actual_label": int(label),
                "error": str(error),
            })

        if index % 250 == 0:
            print(f"Processed {index}/{len(urls)} URLs")

    valid_actual = actual[valid_indices]
    rule_predictions = np.array(rule_predictions)
    valid_ml_predictions = ml_predictions[valid_indices]

    print(f"\nTotal test URLs: {len(urls)}")
    print(f"Valid for rule-based comparison: {len(valid_indices)}")
    print(f"Rejected by scanner: {len(invalid_urls)}")

    print_metrics(
        "Rule-based detector (VirusTotal disabled)",
        valid_actual,
        rule_predictions,
    )
    print_metrics(
        "ML detector (same valid URLs)",
        valid_actual,
        valid_ml_predictions,
    )

    with open(
        "detector_comparison_results.csv",
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)
        writer.writerow([
            "url", "actual_label", "rule_based_prediction", "ml_prediction",
        ])
        writer.writerows(zip(
            np.array(urls, dtype=object)[valid_indices],
            valid_actual,
            rule_predictions,
            valid_ml_predictions,
        ))

    with open("detector_rejected_urls.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["url", "actual_label", "error"],
        )
        writer.writeheader()
        writer.writerows(invalid_urls)

    print("\nSaved valid comparison to detector_comparison_results.csv")
    print("Saved rejected URLs to detector_rejected_urls.csv")


    rule_predictions = np.array(rule_predictions)

    
    print(f"\nTotal test URLs: {len(urls)}")
    print(f"Valid for comparison: {len(valid_indices)}")
    print(f"Rejected by scanner: {len(invalid_urls)}")

    print_metrics(
        "Rule-based detector (VirusTotal disabled)",
        valid_actual,
        rule_predictions,
    )

    print_metrics(
        "ML detector (same valid URLs)",
        valid_actual,
        valid_ml_predictions,
    )


    with open("detector_comparison_results.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "url", "actual_label", "rule_based_prediction",
            "ml_prediction",
        ])
        writer.writerows(zip(urls, actual, rule_predictions, ml_predictions))

    print("\nPer-URL results saved to detector_comparison_results.csv")
    print(
        "\nCaution: evaluation labels are dataset-derived; "
        "results do not establish real-world accuracy."
    )


if __name__ == "__main__":
    main()
