
import pandas as pd
from urllib.parse import urlparse

def host(url):
    try:
        return (urlparse(str(url).strip()).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

train = pd.read_csv("ml_train.csv")
test = pd.read_csv("ml_test.csv")
phishing = pd.read_csv("phishing_urls_clean.csv")
legitimate = pd.read_csv("validation_legitimate_candidates.csv")

blocked_hosts = set(train["url"].map(host))
blocked_hosts.update(test["url"].map(host))
blocked_hosts.update(legitimate["url"].map(host))
blocked_hosts.discard("")

phishing["hostname"] = phishing["url"].map(host)
phishing = phishing[
    phishing["hostname"].ne("")
    & ~phishing["hostname"].isin(blocked_hosts)
].copy()

# Keep one URL per hostname for a domain-separated evaluation.
phishing = phishing.drop_duplicates(subset=["hostname"])
phishing["label"] = 1
phishing["source"] = "phishtank_validation"

legitimate["hostname"] = legitimate["url"].map(host)
legitimate = legitimate.drop_duplicates(subset=["hostname"]).copy()

# Reserve a manageable initial candidate set.
legitimate = legitimate.head(1830).copy()
legitimate["label"] = 0

validation = pd.concat(
    [
        legitimate[["url", "label", "source"]],
        phishing[["url", "label", "source"]],
    ],
    ignore_index=True,
)

validation.to_csv("independent_validation_candidates.csv", index=False)

print("Legitimate candidates:", len(legitimate))
print("Phishing candidates:", len(phishing))
print("Total candidate rows:", len(validation))
print("Output: independent_validation_candidates.csv")
