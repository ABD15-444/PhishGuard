import json
import joblib

from ml_features import extract_url_features

MODEL_FILE = "phishguard_large_model.joblib"
FEATURE_FILE = "ml_large_feature_names.json"

model = joblib.load(MODEL_FILE)

with open(FEATURE_FILE, "r") as f:
    feature_names = json.load(f)

sample = extract_url_features("https://example.com/")
extractor_names = list(sample.keys())

print("MODEL FEATURE AUDIT")
print("=" * 45)
print("Model expects:", model.n_features_in_, "features")
print("JSON contains:", len(feature_names), "feature names")
print("Extractor produces:", len(extractor_names), "features")

print("\nJSON and extractor have the same feature names:",
      set(feature_names) == set(extractor_names))

print("JSON and extractor have the same order:",
      feature_names == extractor_names)

print("\nFeatures in JSON but not extractor:",
      sorted(set(feature_names) - set(extractor_names)))

print("\nFeatures in extractor but not JSON:",
      sorted(set(extractor_names) - set(feature_names)))

if (
    model.n_features_in_ == len(feature_names)
    and feature_names == extractor_names
):
    print("\nRESULT: Feature alignment checks passed.")
else:
    print("\nRESULT: Feature alignment needs investigation.")