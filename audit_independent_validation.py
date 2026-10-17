
import pandas as pd
from urllib.parse import urlparse

FILE = "independent_validation_candidates.csv"

df = pd.read_csv(FILE)

def host(url):
    try:
        return (urlparse(str(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

df["hostname"] = df["url"].map(host)

train = pd.read_csv("ml_train.csv")
test = pd.read_csv("ml_test.csv")

train_hosts = set(train["url"].map(host))
test_hosts = set(test["url"].map(host))
validation_hosts = set(df["hostname"]) - {""}

print("Rows:", len(df))
print("\nLabel counts:")
print(df["label"].value_counts().sort_index())

print("\nSource counts:")
print(df["source"].value_counts())

print("\nDuplicate URLs:", df["url"].duplicated().sum())
print("Duplicate hostnames:", df["hostname"].duplicated().sum())
print("Missing URLs:", df["url"].isna().sum())
print("Missing hostnames:", (df["hostname"] == "").sum())

print("\nHostname overlap with training:",
      len(validation_hosts & train_hosts))
print("Hostname overlap with testing:",
      len(validation_hosts & test_hosts))

print("\nSample rows:")
print(df[["url", "label", "source"]].head(10).to_string(index=False))
