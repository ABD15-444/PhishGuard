
import csv
from collections import Counter
from unittest.mock import patch

import app as phishguard


CSV_FILE = "evaluation_urls.csv"


def evaluate():
    results = []
    counts = Counter()
    failed_scans = []

    with open(CSV_FILE, "r", newline="", encoding="utf-8") as file:
        dataset = list(csv.DictReader(file))

    
    if not dataset:
        print("The CSV dataset is empty.")
        return

    required_columns = {"url", "label", "source"}

    if not required_columns.issubset(dataset[0].keys()):
        print(
            "Invalid CSV format. Required columns: "
            "url,label,source"
        )
        return

    for line_number, row in enumerate(dataset, start=2):
        url = row.get("url", "").strip()
        label = row.get("label", "").strip()

        if not url:
            print(f"Missing URL on CSV line {line_number}.")
            return

        if label not in {"0", "1"}:
            print(
                f"Invalid label on CSV line {line_number}: "
                f"{label!r}. Labels must be 0 or 1."
            )
            return


    for row in dataset:
        url = row["url"].strip()
        actual = int(row["label"])

        # Mock external services so no real network requests occur.
        dns_records = {
            "A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []
        }
        dns_security = {
            "domain_resolves": True,
            "has_ipv4": True,
            "has_ipv6": False,
            "has_nameservers": True,
            "has_mail_servers": False,
            "lookup_status": {},
            "findings": []
        }

        with (
            patch.object(
                phishguard, "check_dns",
                return_value=(True, dns_records, dns_security)
            ),
            patch.object(
                phishguard, "get_domain_information",
                return_value={}
            ),
            patch.object(
                phishguard, "get_rdap_information",
                return_value={"available": False}
            ),
            patch.object(
                phishguard, "check_ssl_certificate",
                return_value={"checked": False}
            ),
            patch.object(
                phishguard, "analyze_redirects",
                return_value={
                    "checked": True,
                    "redirect_count": 0,
                    "redirect_chain": [],
                    "final_url": url,
                    "https_downgrade": False,
                    "excessive_redirects": False,
                    "error": None,
                    "findings": []
                }
            ),
            patch.object(
                phishguard, "get_ip_intelligence",
                return_value={
                    "domain": "example",
                    "ipv4_addresses": [],
                    "ipv6_addresses": [],
                    "resolved": True,
                    "message": "Mocked for evaluation"
                }
            ),
            patch.object(
                phishguard, "get_ip_geolocation",
                return_value={"available": False}
            ),
            patch.object(
                phishguard, "check_virustotal",
                return_value={
                    "available": False,
                    "status": "unavailable",
                    "message": "Mocked for evaluation"
                }
            )
        ):
            response = phishguard.app.test_client().post(
                "/api/scan",
                json={"url": url}
            )

        
        if response.status_code != 200:
            failed_scans.append({
                "url": url,
                "http_status": response.status_code
            })

            print(f"Could not evaluate: {url}")
            print(f"HTTP status: {response.status_code}")
            print("This URL is excluded from the classification metrics.")
            continue

        data = response.get_json()
        score = int(data["risk_score"])
        verdict = data["verdict"]

        # SAFE = predicted legitimate; other verdicts = predicted phishing.
        predicted = 0 if verdict == "SAFE" else 1

        if actual == 1 and predicted == 1:
            counts["TP"] += 1
        elif actual == 0 and predicted == 0:
            counts["TN"] += 1
        elif actual == 0 and predicted == 1:
            counts["FP"] += 1
        else:
            counts["FN"] += 1

        results.append({
            "url": url,
            "actual": actual,
            "predicted": predicted,
            "score": score,
            "verdict": verdict
        })

    if not results:
        print("No URLs were evaluated successfully.")
        return

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]
    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    false_positive_rate = (
        fp / (fp + tn) if fp + tn else 0
    )

    print("\nPHISHGUARD DETECTION EVALUATION")
    print("=" * 48)

    for item in results:
        actual_label = "PHISHING" if item["actual"] else "LEGITIMATE"
        print(
            f'{actual_label:10} | {item["verdict"]:10} | '
            f'Score: {item["score"]:3} | {item["url"]}'
        )

    print("\nCONFUSION MATRIX")
    print(f"True positives (TP):  {tp}")
    print(f"True negatives (TN):  {tn}")
    print(f"False positives (FP): {fp}")
    print(f"False negatives (FN): {fn}")

    print("\nMETRICS")
    print(f"Evaluated URLs:       {total}")
    print(f"Successful scans:    {len(results)}")
    print(f"Failed scans:        {len(failed_scans)}")
    print(f"Total dataset URLs:  {len(dataset)}")
    print(f"Accuracy:             {accuracy:.2%}")
    print(f"Precision:            {precision:.2%}")
    print(f"Recall:               {recall:.2%}")
    print(f"F1-score:             {f1:.2%}")
    print(f"False-positive rate:  {false_positive_rate:.2%}")

    # Save the individual predictions for review.
    with open(
        "evaluation_results.csv", "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "url", "actual", "predicted", "score", "verdict"
            ]
        )
        writer.writeheader()
        writer.writerows(results)

    print("\nDetailed results saved to evaluation_results.csv")


if __name__ == "__main__":
    evaluate()
