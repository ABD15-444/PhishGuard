
import pandas as pd

df = pd.read_csv("ml_test.csv")
df["url_length"] = df["url"].astype(str).str.len()

short_phishing = df[
    (df["label"] == 1) &
    (df["url_length"] < 30)
]

print("Short phishing URLs:", len(short_phishing))
print("\nFirst 30 examples:\n")

columns = [
    column for column in ["url", "source", "label"]
    if column in short_phishing.columns
]

print(
    short_phishing[columns]
    .head(30)
    .to_string(index=False)
)
