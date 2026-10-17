
import pandas as pd
from urllib.parse import urlparse

SOURCE_FILE = "tranco_validation_download.csv"
TRAIN_FILE = "ml_train.csv"
TEST_FILE = "ml_test.csv"
OUTPUT_FILE = "validation_legitimate_candidates.csv"


def normalize_host(value):
    try:
        value = str(value).strip()
        if not value:
            return None

        parsed = urlparse(
            value if "://" in value else "//" + value
        )
        host = parsed.hostname
        return host.lower().rstrip(".") if host else None

    except ValueError:
        return None


def main():
    # Read Tranco's rank,domain format.
    tranco = pd.read_csv(
        SOURCE_FILE,
        header=None,
        names=["rank", "domain"],
        dtype=str
    )

    tranco["domain"] = (
        tranco["domain"].fillna("").str.strip().str.lower()
    )
    tranco["hostname"] = tranco["domain"].map(normalize_host)
    tranco = tranco.dropna(subset=["hostname"])
    tranco = tranco[tranco["hostname"] != ""]
    tranco = tranco.drop_duplicates(subset=["hostname"])

    # Read existing training and test data.
    train = pd.read_csv(TRAIN_FILE)
    test = pd.read_csv(TEST_FILE)

    used_hosts = set(train["url"].map(normalize_host).dropna())
    used_hosts.update(test["url"].map(normalize_host).dropna())

    # Exclude hostnames already used in training or testing.
    candidates = tranco[
        ~tranco["hostname"].isin(used_hosts)
    ].copy()

    # Exclude hostnames appearing in the PhishTank feed.
    phishing = pd.read_csv("phishing_urls_clean.csv")
    phishing_hosts = set(
        phishing["url"].map(normalize_host).dropna()
    )

    before_phishing_filter = len(candidates)
    candidates = candidates[
        ~candidates["hostname"].isin(phishing_hosts)
    ].copy()

    print(
        "Candidates removed due to PhishTank overlap:",
        before_phishing_filter - len(candidates)
    )

    candidates["url"] = "https://" + candidates["hostname"] + "/"
    candidates["label"] = 0
    candidates["source"] = "fresh_tranco_candidate"

    candidates[["url", "label", "source", "rank"]].to_csv(
        OUTPUT_FILE, index=False
    )

    print("Fresh Tranco domains:", len(tranco))
    print("Existing hostnames excluded:",
          len(tranco) - len(candidates))
    print("Remaining candidates:", len(candidates))
    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
