
import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("ml_train.csv")

def get_hostname(url):
    parsed = urlparse(str(url))
    return (parsed.hostname or "").lower()

df["hostname"] = df["url"].apply(get_hostname)
df["has_www"] = df["hostname"].str.startswith("www.")
df["has_subdomain"] = df["hostname"].apply(
    lambda host: len(host.split(".")) > 2
)

print("www prefix by source:")
print(pd.crosstab(df["source"], df["has_www"], margins=True))

print("\nSubdomains by source:")
print(pd.crosstab(df["source"], df["has_subdomain"], margins=True))

print("\nAverage URL length by source:")
print(df.groupby("source")["url"].apply(
    lambda urls: urls.astype(str).str.len().mean()
).round(2))

