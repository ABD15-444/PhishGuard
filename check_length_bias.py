
import pandas as pd

df = pd.read_csv("ml_test.csv")

df["url_length"] = df["url"].astype(str).str.len()

print("Average URL length by label:")
print(df.groupby("label")["url_length"].mean().round(2))

print("\nURL length percentiles by label:")
print(
    df.groupby("label")["url_length"]
    .quantile([0.25, 0.50, 0.75, 0.90])
    .unstack()
    .round(1)
    .to_string()
)

print("\nURL lengths under 30 characters:")
print(
    df[df["url_length"] < 30]
    .groupby("label")
    .size()
    .rename("count")
    .to_string()
)

print("\nURL lengths of 30 characters or more:")
print(
    df[df["url_length"] >= 30]
    .groupby("label")
    .size()
    .rename("count")
    .to_string()
)
