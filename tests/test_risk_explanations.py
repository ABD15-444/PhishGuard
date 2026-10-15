"""Automated tests for PhishGuard's risk-scoring endpoint.

These tests mock VirusTotal and network-dependent checks. They do not submit
URLs to VirusTotal or visit suspicious websites.

Run from the project folder with:
    python3 -m unittest discover -s tests -v
"""
import unittest
from unittest.mock import patch

import app as phishguard


class RiskEngineTests(unittest.TestCase):
    def setUp(self):
        self.client = phishguard.app.test_client()
        self.patches = [
            patch.object(phishguard, "get_ip_intelligence", return_value={
                "domain": "example.com",
                "ipv4_addresses": [],
                "ipv6_addresses": [],
                "resolved": False,
                "message": "Mocked for unit test",
            }),
            patch.object(phishguard, "get_ip_geolocation", return_value=None),
            patch.object(phishguard, "check_url_length", return_value=(0, "URL length appears normal")),
            patch.object(phishguard, "check_ip_address", return_value=(0, False, "URL uses a domain name")),
            patch.object(phishguard, "check_at_symbol", return_value=(0, False, "URL does not contain an @ symbol")),
            patch.object(phishguard, "check_subdomains", return_value=(0, 0, "URL contains a normal number of subdomains")),
            patch.object(phishguard, "check_suspicious_tld", return_value=(0, False, "Domain uses a common TLD")),
            patch.object(phishguard, "check_suspicious_keywords", return_value=(0, [], "No suspicious keywords detected")),
            patch.object(phishguard, "check_punycode", return_value=(0, False, "Domain does not contain Punycode")),
            patch.object(phishguard, "check_https", return_value=(0, True, "URL uses HTTPS")),
            patch.object(phishguard, "check_dns", return_value=(True, {"A": ["192.0.2.1"], "AAAA": [], "MX": [], "NS": [], "CNAME": []}, {"domain_resolves": True, "has_ipv4": True, "has_ipv6": False, "has_nameservers": False, "has_mail_servers": False, "lookup_status": {}, "findings": []})),
            patch.object(phishguard, "get_domain_information", return_value={"registered_domain": "example.com", "subdomain": "", "tld": "com"}),
            patch.object(phishguard, "get_rdap_information", return_value={"available": False, "message": "Mocked for unit test"}),
            patch.object(phishguard, "check_ssl_certificate", return_value={"checked": False, "valid": False, "message": "Mocked for unit test"}),
            patch.object(phishguard, "analyze_redirects", return_value={"checked": True, "redirect_count": 0, "final_url": "https://example.com", "https_downgrade": False, "findings": []}),
        ]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def scan_with_virustotal(self, vt_result, url="https://example.com"):
        with patch.object(phishguard, "check_virustotal", return_value=vt_result):
            response = self.client.post("/api/scan", json={"url": url})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    def test_clean_url_stays_safe(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 0,
            "suspicious": 0, "harmless": 63, "undetected": 30,
            "message": "Mocked completed analysis",
        })
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "SAFE")

    def test_heuristic_score_of_50_is_suspicious(self):
        with patch.object(phishguard, "check_url_length", return_value=(50, "Mock heuristic risk")):
            result = self.scan_with_virustotal({
                "available": True, "status": "completed", "malicious": 0,
                "suspicious": 0, "message": "Mocked completed analysis",
            })
        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["verdict"], "SUSPICIOUS")

    def test_one_malicious_detection_sets_minimum_score_60(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 1,
            "suspicious": 0, "message": "Mocked completed analysis",
        })
        self.assertEqual(result["risk_score"], 60)
        self.assertEqual(result["verdict"], "HIGH RISK")
        self.assertTrue(any("VirusTotal" in reason for reason in result["reasons"]))
        self.assertTrue(any(f["feature"] == "VirusTotal Threat Intelligence" for f in result["risk_factors"]))

    def test_three_malicious_detections_sets_minimum_score_85(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 3,
            "suspicious": 0, "message": "Mocked completed analysis",
        })
        self.assertEqual(result["risk_score"], 85)
        self.assertEqual(result["verdict"], "HIGH RISK")
        self.assertTrue(any(f["feature"] == "VirusTotal Threat Intelligence" for f in result["risk_factors"]))

    def test_suspicious_only_sets_minimum_score_30(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 0,
            "suspicious": 1, "message": "Mocked completed analysis",
        })
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["verdict"], "SUSPICIOUS")
        self.assertTrue(any("VirusTotal" in reason for reason in result["reasons"]))
        self.assertTrue(any(f["feature"] == "VirusTotal Threat Intelligence" for f in result["risk_factors"]))

    def test_unavailable_virustotal_does_not_change_heuristic_score(self):
        result = self.scan_with_virustotal({
            "available": False, "message": "Mocked unavailable service",
        })
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "SAFE")
        self.assertFalse(any(f["feature"] == "VirusTotal Threat Intelligence" for f in result["risk_factors"]))

    def test_pending_virustotal_does_not_change_heuristic_score(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "queued", "malicious": 5,
            "suspicious": 2, "message": "Mocked queued analysis",
        })
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "SAFE")

    def test_final_score_is_capped_at_100(self):
        with patch.object(phishguard, "check_url_length", return_value=(100, "Mock maximum heuristic risk")):
            result = self.scan_with_virustotal({
                "available": True, "status": "completed", "malicious": 3,
                "suspicious": 0, "message": "Mocked completed analysis",
            })
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["verdict"], "HIGH RISK")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


    def test_malicious_detection_explanation_is_consistent(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 1,
            "suspicious": 0, "message": "Mocked completed analysis",
        })
        vt_factor = next(
            factor for factor in result["risk_factors"]
            if factor["feature"] == "VirusTotal Threat Intelligence"
        )
        self.assertIn("1 malicious", vt_factor["reason"])
        self.assertTrue(any("1 malicious" in reason for reason in result["reasons"]))
        self.assertIn("incorporates VirusTotal threat intelligence", result["verdict_message"])

    def test_three_malicious_detections_have_matching_explanations(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 3,
            "suspicious": 0, "message": "Mocked completed analysis",
        })
        vt_factor = next(
            factor for factor in result["risk_factors"]
            if factor["feature"] == "VirusTotal Threat Intelligence"
        )
        self.assertIn("3 malicious", vt_factor["reason"])
        self.assertTrue(any("3 malicious" in reason for reason in result["reasons"]))
        self.assertIn("incorporates VirusTotal threat intelligence", result["verdict_message"])

    def test_suspicious_detection_explanation_is_consistent(self):
        result = self.scan_with_virustotal({
            "available": True, "status": "completed", "malicious": 0,
            "suspicious": 2, "message": "Mocked completed analysis",
        })
        vt_factor = next(
            factor for factor in result["risk_factors"]
            if factor["feature"] == "VirusTotal Threat Intelligence"
        )
        self.assertIn("2 suspicious", vt_factor["reason"])
        self.assertTrue(any("2 suspicious" in reason for reason in result["reasons"]))
        self.assertIn("incorporates VirusTotal threat intelligence", result["verdict_message"])

    def test_virustotal_does_not_claim_score_increase_when_heuristics_are_higher(self):
        with patch.object(phishguard, "check_url_length", return_value=(70, "Mock high heuristic risk")):
            result = self.scan_with_virustotal({
                "available": True, "status": "completed", "malicious": 1,
                "suspicious": 0, "message": "Mocked completed analysis",
            })
        self.assertEqual(result["risk_score"], 70)
        self.assertFalse(
            "incorporates VirusTotal threat intelligence" in result["verdict_message"]
        )
        vt_factor = next(
            factor for factor in result["risk_factors"]
            if factor["feature"] == "VirusTotal Threat Intelligence"
        )
        self.assertEqual(vt_factor["score"], 0)
        self.assertTrue(any("1 malicious" in reason for reason in result["reasons"]))



if __name__ == "__main__":
    unittest.main(verbosity=2)
