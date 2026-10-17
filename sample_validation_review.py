
import pandas as pd

df = pd.read_csv("independent_validation_candidates.csv")

# Sample 100 URLs from each source for manual label review.
samples = []

for source in ["fresh_tranco_candidate", "phishtank_validation"]:
    subset = df[df["source"] == source]
    n = min(100, len(subset))
    samples.append(
        subset.sample(n=n, random_state=42)
        [["url", "label", "source"]]
    )

review = pd.concat(samples, ignore_index=True)
review["reviewed_label"] = ""
review["review_notes"] = ""

review.to_csv("validation_label_review.csv", index=False)

print("Review rows:", len(review))
print("Output: validation_label_review.csv")
print("\nSource counts:")
print(review["source"].value_counts())
