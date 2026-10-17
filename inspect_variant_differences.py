
from ml_features import extract_url_features

urls = [
    "https://paypal-banking.pro",
    "https://www.paypal-banking.pro",
    "http://paypal-banking.pro/",
    "https://paypal-banking.pro/login",
]

results = {
    url: extract_url_features(url)
    for url in urls
}

feature_names = list(next(iter(results.values())).keys())

print("FEATURE DIFFERENCES")
print("-" * 90)

for name in feature_names:
    values = [results[url][name] for url in urls]

    if len(set(values)) > 1:
        print(f"\n{name}")
        for url, value in zip(urls, values):
            print(f"  {value!s:8} {url}")
