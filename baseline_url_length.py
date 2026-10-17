
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

train = pd.read_csv("ml_train.csv")
test = pd.read_csv("ml_test.csv")

# Fit a simple threshold using training data only.
lengths = train["url"].astype(str).str.len()
labels = train["label"].astype(int)

thresholds = range(10, 101)
best_threshold = None
best_f1 = -1

for threshold in thresholds:
    predictions = (lengths >= threshold).astype(int)
    score = f1_score(labels, predictions, zero_division=0)

    if score > best_f1:
        best_f1 = score
        best_threshold = threshold

test_lengths = test["url"].astype(str).str.len()
y_test = test["label"].astype(int)
predictions = (test_lengths >= best_threshold).astype(int)

print("Length threshold:", best_threshold)
print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
print("Precision:", round(precision_score(y_test, predictions, zero_division=0), 4))
print("Recall:", round(recall_score(y_test, predictions, zero_division=0), 4))
print("F1:", round(f1_score(y_test, predictions, zero_division=0), 4))
print("Confusion matrix:")
print(confusion_matrix(y_test, predictions))
