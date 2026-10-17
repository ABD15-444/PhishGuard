
import pandas as pd

df = pd.read_csv("ml_train.csv")
df["url"] = df["url"].astype(str)

df["hostname"] = (
    df["url"]
    .str.replace(r"^https?://", "", regex=True)
    .str.split("/").str[0]
    .str.split("?").str[0]
    .str.lower()
)

df["has_www"] = df["hostname"].str.startswith("www.")

print("Training label counts by www prefix:")
print(pd.crosstab(df["has_www"], df["label"], margins=True))

print("\nURL examples with www:")
print(
    df[df["has_www"]][["url", "label", "source"]]
    .head(20)
    .to_string(index=False)
)

print("\nURL examples without www:")
print(
    df[~df["has_www"]][["url", "label", "source"]]
    .head(20)
    .to_string(index=False)
)
