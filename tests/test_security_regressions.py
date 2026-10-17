"""Security regression and vulnerability prevention tests for PhishGuard.

Covers SSRF prevention in SSL/TLS checks, direct IP intelligence resolution,
underscore subdomains in legitimate and phishing URLs, port edge cases,
and strict verdict threshold enforcement.
"""

import socket
import unittest
from unittest.mock import patch, MagicMock

import app as phishguard


class SecurityRegressionTests(unittest.TestCase):

    def setUp(self):
        self.client = phishguard.app.test_client()

    def test_ssl_check_blocks_private_ip_ssrf(self):
        """SSL certificate check must not initiate sockets to private IPs."""
        with patch("socket.create_connection") as mock_conn:
            with patch.object(phishguard, "is_safe_public_host", return_value=False):
                result = phishguard.check_ssl_certificate("127.0.0.1")

            self.assertFalse(result["checked"])
            self.assertFalse(result["valid"])
            self.assertIn("blocked", result["message"].lower())
            mock_conn.assert_not_called()

    def test_ssl_check_blocks_cloud_metadata_ip_ssrf(self):
        """SSL certificate check must reject link-local cloud metadata addresses."""
        with patch("socket.create_connection") as mock_conn:
            with patch.object(phishguard, "is_safe_public_host", return_value=False):
                result = phishguard.check_ssl_certificate("169.254.169.254")

            self.assertFalse(result["checked"])
            self.assertFalse(result["valid"])
            mock_conn.assert_not_called()

    def test_ssl_check_handles_empty_or_none_domain(self):
        """SSL check should safely return unavailable state if domain is None or empty."""
        result_none = phishguard.check_ssl_certificate(None)
        self.assertFalse(result_none["checked"])
        result_empty = phishguard.check_ssl_certificate("")
        self.assertFalse(result_empty["checked"])

    def test_is_safe_public_host_blocks_unspecified_ips(self):
        """0.0.0.0 and :: must be rejected as non-public hosts."""
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", 0))
            ]
        ):
            self.assertFalse(phishguard.is_safe_public_host("0.0.0.0"))

    def test_is_safe_public_host_handles_bracketed_ipv6(self):
        """Bracketed IPv6 addresses such as [::1] must be correctly parsed and blocked."""
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))
            ]
        ):
            self.assertFalse(phishguard.is_safe_public_host("[::1]"))

    def test_direct_ipv4_intelligence_resolves_without_dns(self):
        """Direct IPv4 inputs should be recognized immediately without DNS NXDOMAIN errors."""
        res = phishguard.get_ip_intelligence("8.8.8.8")
        self.assertTrue(res["resolved"])
        self.assertIn("8.8.8.8", res["ipv4_addresses"])
        self.assertEqual(res["ipv6_addresses"], [])

    def test_direct_ipv6_intelligence_resolves_without_dns(self):
        """Direct IPv6 inputs should populate ipv6_addresses."""
        res = phishguard.get_ip_intelligence("2001:4860:4860::8888")
        self.assertTrue(res["resolved"])
        self.assertIn("2001:4860:4860::8888", res["ipv6_addresses"])

    def test_hostname_with_underscores_is_accepted(self):
        """Hostnames containing underscores in subdomains must not trigger 400 errors."""
        with patch.object(phishguard, "get_ip_intelligence", return_value={"ipv4_addresses": []}), \
             patch.object(phishguard, "check_dns", return_value=(False, {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []}, {"findings": []})), \
             patch.object(phishguard, "get_domain_information", return_value={}), \
             patch.object(phishguard, "get_rdap_information", return_value={"available": False}), \
             patch.object(phishguard, "check_ssl_certificate", return_value={"checked": False}), \
             patch.object(phishguard, "analyze_redirects", return_value={"checked": False, "redirect_count": 0, "findings": []}), \
             patch.object(phishguard, "check_virustotal", return_value={"available": False}):

            response = self.client.post(
                "/api/scan",
                json={"url": "https://coinbase_x_login.godaddysites.com/"}
            )

            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data["domain"], "coinbase_x_login.godaddysites.com")

    def test_invalid_port_returns_400(self):
        """Out-of-range port numbers must receive a clear 400 validation error."""
        response = self.client.post(
            "/api/scan",
            json={"url": "https://example.com:99999"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid hostname or port", response.get_json()["error"])

    def test_risk_verdict_threshold_exact_boundaries(self):
        """Verify strict adherence to 0-29 SAFE, 30-59 SUSPICIOUS, 60+ HIGH RISK."""
        self.assertEqual(phishguard.get_risk_verdict(0)[0], "SAFE")
        self.assertEqual(phishguard.get_risk_verdict(29)[0], "SAFE")
        self.assertEqual(phishguard.get_risk_verdict(30)[0], "SUSPICIOUS")
        self.assertEqual(phishguard.get_risk_verdict(59)[0], "SUSPICIOUS")
        self.assertEqual(phishguard.get_risk_verdict(60)[0], "HIGH RISK")
        self.assertEqual(phishguard.get_risk_verdict(100)[0], "HIGH RISK")

    def test_malformed_json_payload_handled_safely(self):
        """Posting invalid or non-JSON payloads should return 400 rather than 500."""
        response = self.client.post(
            "/api/scan",
            data="not json at all",
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()
