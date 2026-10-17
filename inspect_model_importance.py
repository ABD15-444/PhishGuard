
import json
import joblib

MODEL_FILE = "phishguard_large_model.joblib"
FEATURE_FILE = "ml_large_feature_names.json"

model = joblib.load(MODEL_FILE)

with open(FEATURE_FILE, "r") as file:
    feature_names = json.load(file)

importances = model.feature_importances_

ranked_features = sorted(
    zip(feature_names, importances),
    key=lambda item: item[1],
    reverse=True,
)

print("\nFEATURE IMPORTANCE")
print("-" * 45)

for name, importance in ranked_features:
    print(f"{name:30} {importance:.4f}")
