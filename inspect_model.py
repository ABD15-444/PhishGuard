
import json
import joblib

MODEL_PATH = "phishguard_model.joblib"
FEATURES_PATH = "ml_feature_names.json"

model = joblib.load(MODEL_PATH)

with open(FEATURES_PATH, "r", encoding="utf-8") as file:
    feature_names = json.load(file)

importances = model.feature_importances_

ranked_features = sorted(
    zip(feature_names, importances),
    key=lambda item: item[1],
    reverse=True,
)

print("Top URL features used by the experimental model:\n")

for name, importance in ranked_features[:10]:
    print(f"{name:30s} {importance:.4f}")
