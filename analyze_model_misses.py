import pandas as pd

from ml_features import extract_url_features

df = pd.read_csv("urls_for_investigation.csv")

rows = []

for _, row in df.iterrows():
    features = extract_url_features(row["url"])

    rows.append({
        "url": row["url"],
        "source": row["source"],
        "ml_phishing_probability": row["ml_phishing_probability"],
        "vt_malicious": row["malicious"],
        "url_length": features["url_length"],
        "hostname_length": features["hostname_length"],
        "path_length": features["path_length"],
        "dot_count": features["dot_count"],
        "subdomain_count": features["subdomain_count"],
        "keyword_count": features["keyword_count"],
        "digit_count": features["digit_count"],
        "entropy": features["entropy"],
    })

result = pd.DataFrame(rows)
result = result.sort_values(
    "vt_malicious", ascending=False
)

print(result.to_string(index=False))
result.to_csv("model_miss_feature_analysis.csv", index=False)

print("\nSaved: model_miss_feature_analysis.csv")