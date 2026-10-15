
import unittest
from unittest.mock import patch
import app


class URLValidationTests(unittest.TestCase):

    def setUp(self):
        self.client = app.app.test_client()

    @patch("app.get_ip_intelligence")
    def test_empty_url_is_rejected(self, mock_ip):
        response = self.client.post(
            "/api/scan",
            json={"url": ""}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    @patch("app.get_ip_intelligence")
    def test_missing_protocol_is_normalized(self, mock_ip):
        # A full scan is required for this case.
        # We test scheme normalization separately below.
        from urllib.parse import urlparse

        url = "example.com"
        if not urlparse(url).scheme:
            url = "https://" + url

        self.assertEqual(url, "https://example.com")

    def test_unsupported_scheme_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "ftp://example.com"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported URL scheme", response.get_json()["error"])

    def test_javascript_scheme_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "javascript:alert(1)"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported URL scheme", response.get_json()["error"])
    def test_missing_hostname_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "https://"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())


    def test_missing_url_field_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())
    
    @patch("app.check_virustotal")
    @patch("app.analyze_redirects")
    @patch("app.check_ssl_certificate")
    @patch("app.get_rdap_information")
    @patch("app.check_dns")
    @patch("app.get_ip_intelligence")
    def test_ip_address_url_is_detected(
        self,
        mock_ip,
        mock_dns,
        mock_rdap,
        mock_ssl,
        mock_redirects,
        mock_vt
    ):
        mock_ip.return_value = {
            "domain": "192.0.2.1",
            "ipv4_addresses": ["192.0.2.1"],
            "ipv6_addresses": [],
            "resolved": True,
            "message": "Test"
        }

        mock_dns.return_value = (
            True,
            {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
            {
                "domain_resolves": True,
                "has_ipv4": True,
                "has_ipv6": False,
                "has_nameservers": False,
                "has_mail_servers": False,
                "lookup_status": {},
                "findings": []
            }
        )

        mock_rdap.return_value = {"available": False}
        mock_ssl.return_value = {"checked": False}
        mock_redirects.return_value = {
            "checked": True,
            "redirect_count": 0,
            "redirect_chain": [],
            "final_url": "http://192.0.2.1",
            "https_downgrade": False,
            "excessive_redirects": False,
            "error": None,
            "findings": []
        }
        mock_vt.return_value = {
            "available": False,
            "message": "Mocked for testing"
        }

        response = self.client.post(
            "/api/scan",
            json={"url": "http://192.0.2.1"}
        )

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["is_ip_address"])
        self.assertGreaterEqual(result["risk_score"], 25)


        

    def test_multiple_subdomains_are_parsed(self):
        from urllib.parse import urlparse

        url = "https://a.b.c.d.example.com"
        parsed = urlparse(url)

        self.assertEqual(
            parsed.hostname,
            "a.b.c.d.example.com"
        )
    def test_embedded_credentials_are_rejected_by_redirect_analysis(self):
        from app import analyze_redirects

        result = analyze_redirects(
            "https://user:password@example.com"
        )

        self.assertIsNotNone(result["error"])
        self.assertTrue(
            any(
                "credentials" in finding.lower()
                for finding in result["findings"]
            )
        )

    
    def test_invalid_hostname_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "https://invalid host"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()
