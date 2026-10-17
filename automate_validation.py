
import os
import time
import base64
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

# --------------------------------------------------
# Configuration
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

INPUT_FILE = PROJECT_DIR / "independent_validation_candidates.csv"
OUTPUT_FILE = PROJECT_DIR / "virustotal_batch_evidence.csv"

API_URL = "https://www.virustotal.com/api/v3/urls"

# Conservative public API pacing.
REQUEST_INTERVAL = 16
TIMEOUT = 40

# Start small. Increase only after checking API quota.
BATCH_SIZE = 40
RANDOM_SEED = 42

SOURCES = [
    "fresh_tranco_candidate",
    "phishtank_validation",
]


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def get_url_id(url):
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def classify_evidence(status, malicious, suspicious):
    if status != "report_retrieved":
        return "insufficient_evidence"

    malicious = malicious or 0
    suspicious = suspicious or 0

    if malicious > 0:
        return "phishing_supported"

    if suspicious > 0:
        return "needs_review"

    return "uncertain"


def load_previous_results():
    if not OUTPUT_FILE.exists():
        return pd.DataFrame()

    try:
        previous = pd.read_csv(OUTPUT_FILE)
        if "url" not in previous.columns:
            print("WARNING: Existing output has no URL column.")
            return pd.DataFrame()
        return previous
    except (OSError, pd.errors.ParserError) as exc:
        print("WARNING: Could not read previous output:", type(exc).__name__)
        return pd.DataFrame()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        print("ERROR: VIRUSTOTAL_API_KEY is not configured.")
        return

    if not INPUT_FILE.exists():
        print("ERROR: Input file not found:", INPUT_FILE.name)
        return

    df = pd.read_csv(INPUT_FILE)

    required = {"url", "label", "source"}
    if not required.issubset(df.columns):
        print("ERROR: Input CSV must contain:", sorted(required))
        return

    df = df[df["source"].isin(SOURCES)].copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df.drop_duplicates(subset=["url"])

    previous = load_previous_results()

    completed_urls = set()
    if not previous.empty:
        if "vt_status" in previous.columns:
            # Retry transient failures and rate-limited requests.
            retryable = {
                "request_error",
                "rate_limited",
                "api_access_error",
                "http_429",
                "http_500",
                "http_502",
                "http_503",
                "http_504",
            }
            completed_urls = set(
                previous.loc[
                    ~previous["vt_status"].isin(retryable), "url"
                ].astype(str)
            )
        else:
            completed_urls = set(previous["url"].astype(str))

    pending = df[~df["url"].isin(completed_urls)].copy()

    if pending.empty:
        print("No new URLs to process.")
        print("Existing results:", len(previous))
        return

    # Sample fairly across sources for this run.
    samples = []
    for source in SOURCES:
        subset = pending[pending["source"] == source]
        if subset.empty:
            continue

        n = min(BATCH_SIZE // len(SOURCES), len(subset))
        if n:
            samples.append(
                subset.sample(n=n, random_state=RANDOM_SEED)
            )

    if not samples:
        print("No URLs selected.")
        return

    batch = pd.concat(samples, ignore_index=True)
    print("New URLs selected:", len(batch))
    print(batch["source"].value_counts().to_string())

    results = []
    headers = {"x-apikey": api_key}
    stop = False

    with requests.Session() as session:
        session.headers.update(headers)

        for position, (_, row) in enumerate(batch.iterrows(), start=1):
            url = row["url"]

            record = {
                "url": url,
                "provisional_label": row["label"],
                "source": row["source"],
                "vt_status": "unknown",
                "malicious": None,
                "suspicious": None,
                "harmless": None,
                "undetected": None,
                "last_analysis_date": None,
                "evidence_classification": "insufficient_evidence",
                "evidence_note": "",
            }

            print(f"Checking {position}/{len(batch)}")

            try:
                response = session.get(
                    f"{API_URL}/{get_url_id(url)}",
                    timeout=TIMEOUT,
                )

                if response.status_code == 200:
                    payload = response.json()
                    attrs = payload.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})

                    record["malicious"] = stats.get("malicious")
                    record["suspicious"] = stats.get("suspicious")
                    record["harmless"] = stats.get("harmless")
                    record["undetected"] = stats.get("undetected")
                    record["last_analysis_date"] = attrs.get(
                        "last_analysis_date"
                    )

                    record["vt_status"] = "report_retrieved"
                    record["evidence_note"] = (
                        "Existing VirusTotal report; "
                        "not independently verified ground truth."
                    )

                elif response.status_code == 404:
                    record["vt_status"] = "no_existing_report"
                    record["evidence_note"] = (
                        "No existing report found; no scan submitted."
                    )

                elif response.status_code == 429:
                    record["vt_status"] = "rate_limited"
                    record["evidence_note"] = "API rate limit reached."
                    results.append(record)
                    stop = True
                    print("Rate limit reached; stopping.")
                    break

                elif response.status_code in (401, 403):
                    record["vt_status"] = "api_access_error"
                    record["evidence_note"] = (
                        f"API returned HTTP {response.status_code}."
                    )
                    results.append(record)
                    stop = True
                    print("API access error; stopping.")
                    break

                else:
                    record["vt_status"] = f"http_{response.status_code}"
                    record["evidence_note"] = "Report retrieval failed."

            except requests.Timeout:
                record["vt_status"] = "request_error"
                record["evidence_note"] = "Timeout; safe to retry later."

            except requests.RequestException as exc:
                record["vt_status"] = "request_error"
                record["evidence_note"] = type(exc).__name__

            except ValueError:
                record["vt_status"] = "request_error"
                record["evidence_note"] = "Invalid JSON response."

            record["evidence_classification"] = classify_evidence(
                record["vt_status"],
                record["malicious"],
                record["suspicious"],
            )
            results.append(record)

            # Persist progress after every URL so interruption is recoverable.
            combined = pd.concat(
                [previous, pd.DataFrame(results)],
                ignore_index=True,
            )
            combined = combined.drop_duplicates(
                subset=["url"], keep="last"
            )
            combined.to_csv(OUTPUT_FILE, index=False)

            if stop:
                break

            if position < len(batch):
                time.sleep(REQUEST_INTERVAL)

    combined = pd.concat(
        [previous, pd.DataFrame(results)],
        ignore_index=True,
    ).drop_duplicates(subset=["url"], keep="last")

    combined.to_csv(OUTPUT_FILE, index=False)

    print("\nBATCH COMPLETE")
    print("Results saved:", OUTPUT_FILE.name)
    print("Total saved URLs:", len(combined))

    if not combined.empty:
        print("\nEvidence classifications:")
        print(
            combined["evidence_classification"]
            .value_counts()
            .to_string()
        )
        print("\nStatuses:")
        print(combined["vt_status"].value_counts().to_string())


if __name__ == "__main__":
    main()
