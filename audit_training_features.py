
import pandas as pd
from ml_features import extract_url_features

df = pd.read_csv("ml_train.csv")

print("Training dataset columns:", df.columns.tolist())
print("\nLabel counts:")
print(df["label"].value_counts().sort_index())

rows = []

for _, row in df.iterrows():
    features = extract_url_features(row["url"])
    features["label"] = int(row["label"])
    rows.append(features)

features_df = pd.DataFrame(rows)

means = features_df.groupby("label").mean(numeric_only=True).T
means.columns = ["Legitimate (0)", "Phishing (1)"]

means["Absolute difference"] = (
    means["Phishing (1)"] - means["Legitimate (0)"]
).abs()

print("\nLargest differences between classes:")
print(
    means.sort_values("Absolute difference", ascending=False)
    .head(10)
    .round(3)
    .to_string()
)
