
import pandas as pd

filename = "validation_label_review.csv"
df = pd.read_csv(filename)

print("Total URLs:", len(df))
print("\nColumns:", df.columns.tolist())

for column in ["reviewed_label", "review_notes"]:
    print(f"\n{column} counts:")
    print(df[column].value_counts(dropna=False).to_string())

reviewed = (
    df["reviewed_label"].notna()
    & df["reviewed_label"].astype(str).str.strip().ne("")
)

print("\nReview completion:")
print("Reviewed:", int(reviewed.sum()))
print("Not reviewed:", int((~reviewed).sum()))

print("\nExamples of completed reviews:")
print(
    df.loc[reviewed, ["url", "label", "source",
                      "reviewed_label", "review_notes"]]
    .head(10)
    .to_string(index=False)
)
