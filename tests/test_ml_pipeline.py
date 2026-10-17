"""Automated tests for the experimental ML feature extraction and inference pipeline."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from ml_features import extract_url_features
import predict_url


class MLPipelineTests(unittest.TestCase):

    def test_feature_extractor_returns_17_canonical_features(self):
        """Extractor must return all 17 canonical features required by the ML models."""
        url = "https://www.example.com/login?token=123#anchor"
        features = extract_url_features(url)

        expected_features = [
            "url_length",
            "hostname_length",
            "path_length",
            "dot_count",
            "hyphen_count",
            "at_symbol",
            "https",
            "ip_address",
            "subdomain_count",
            "keyword_count",
            "digit_count",
            "special_character_count",
            "has_punycode",
            "has_port",
            "has_query",
            "entropy",
            "encoded_character_count"
        ]

        self.assertEqual(len(features), 17)
        for key in expected_features:
            self.assertIn(key, features)
            self.assertIsInstance(features[key], (int, float))

    def test_feature_extractor_matches_schema_json(self):
        """Keys from extract_url_features must strictly match ml_large_feature_names.json."""
        schema_path = "ml_large_feature_names.json"
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                schema = json.load(f)
            features = extract_url_features("https://paypal.com/verify")
            self.assertEqual(list(features.keys()), schema)

    def test_feature_extractor_detects_ip_and_punycode(self):
        """Direct IP and Punycode indicators must be accurately set."""
        ip_url = "http://192.0.2.1:8080/path"
        ip_feats = extract_url_features(ip_url)
        self.assertEqual(ip_feats["ip_address"], 1)
        self.assertEqual(ip_feats["has_port"], 1)
        self.assertEqual(ip_feats["https"], 0)

        puny_url = "https://xn--e1afmkfd.xn--p1ai/"
        puny_feats = extract_url_features(puny_url)
        self.assertEqual(puny_feats["has_punycode"], 1)
        self.assertEqual(puny_feats["https"], 1)

    def test_feature_extractor_handles_empty_input_safely(self):
        """Malformed or empty URL inputs must not raise exceptions."""
        feats = extract_url_features("")
        self.assertEqual(feats["url_length"], 0)
        self.assertEqual(feats["entropy"], 0.0)

    def test_predict_url_raises_file_not_found_on_missing_model(self):
        """Inference should cleanly raise FileNotFoundError when model path is non-existent."""
        with self.assertRaises(FileNotFoundError):
            predict_url.predict_url("https://example.com", model_path="non_existent_model.joblib")

    def test_predict_url_raises_value_error_on_incompatible_schema(self):
        """Inference should reject schema files missing required features."""
        fake_schema = ["unknown_feature_abc", "url_length"]
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(fake_schema))), \
             patch("joblib.load", return_value=MagicMock()):
            with self.assertRaises(ValueError) as ctx:
                predict_url.predict_url("https://example.com", features_path="fake_schema.json")
            self.assertIn("missing required features", str(ctx.exception).lower())

    def test_predict_url_inference_mock(self):
        """Verify full inference flow with a mocked scikit-learn classifier."""
        mock_model = MagicMock()
        mock_model.predict.return_value = [1]
        mock_model.predict_proba.return_value = [[0.15, 0.85]]
        mock_model.classes_ = [0, 1]

        with patch("os.path.exists", return_value=True), \
             patch("joblib.load", return_value=mock_model):
            res = predict_url.predict_url("https://malicious-test.example/login")
            self.assertEqual(res["prediction"], 1)
            self.assertEqual(res["verdict"], "PHISHING")
            self.assertAlmostEqual(res["probability"], 0.85)
            self.assertIn("Experimental model only", res["disclaimer"])


if __name__ == "__main__":
    unittest.main()
