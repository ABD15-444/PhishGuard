
import pandas as pd
from urllib.parse import urlparse

def host(url):
    try:
        parsed = urlparse(str(url).strip())
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

validation = pd.read_csv("validation_legitimate_candidates.csv")
phishing = pd.read_csv("phishing_urls_clean.csv")
train = pd.read_csv("ml_train.csv")
test = pd.read_csv("ml_test.csv")

validation_hosts = set(validation["url"].map(host)) - {""}
phishing_hosts = set(phishing["url"].map(host)) - {""}
train_hosts = set(train["url"].map(host)) - {""}
test_hosts = set(test["url"].map(host)) - {""}

print("Validation candidates:", len(validation_hosts))
print("Overlap with PhishTank:", len(validation_hosts & phishing_hosts))
print("Overlap with training:", len(validation_hosts & train_hosts))
print("Overlap with testing:", len(validation_hosts & test_hosts))

overlap = validation_hosts & phishing_hosts
if overlap:
    print("\nSample overlapping hostnames:")
    for hostname in sorted(overlap)[:20]:
        print(hostname)

