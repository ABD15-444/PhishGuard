import unittest
from unittest.mock import patch
import app


class ExternalServiceFailureTests(unittest.TestCase):

    def setUp(self):
        self.client = app.app.test_client()

    @patch("app.check_virustotal", side_effect=Exception("VT unavailable"))
    @patch("app.analyze_redirects", side_effect=Exception("Redirect failure"))
    @patch("app.check_ssl_certificate", side_effect=Exception("SSL failure"))
    @patch("app.get_rdap_information", side_effect=Exception("RDAP failure"))
    @patch("app.check_dns", side_effect=Exception("DNS failure"))
    @patch("app.get_ip_intelligence", side_effect=Exception("IP lookup failure"))
    def test_external_service_exceptions_do_not_crash_scan(
        self,
        mock_ip,
        mock_dns,
        mock_rdap,
        mock_ssl,
        mock_redirects,
        mock_vt
    ):
        response = self.client.post(
            "/api/scan",
            json={"url": "https://example.com"}
        )

        # The API should return a valid HTTP response, not an
        # unhandled server error.
        self.assertNotEqual(response.status_code, 500)

        # If the API returns a response, it should be valid JSON.
        self.assertIsNotNone(response.get_json())


if __name__ == "__main__":
    unittest.main()
