import pandas as pd

source_file = "validation_label_review.csv"
output_file = "manual_review_worklist.csv"

df = pd.read_csv(source_file)

df["reviewed_label"] = ""
df["review_notes"] = ""

df["review_status"] = "pending"

df.to_csv(output_file, index=False)

print(f"Created: {output_file}")
print(f"URLs to review: {len(df)}")
print("\nColumns:")
print(df.columns.tolist())
print("\nReview status:")
print(df["review_status"].value_counts().to_string())