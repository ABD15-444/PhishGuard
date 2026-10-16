
import socket
import unittest
from unittest.mock import patch

import app as phishguard


class PublicHostSecurityTests(unittest.TestCase):

    def test_loopback_ip_is_rejected(self):
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("127.0.0.1", 0))
            ]
        ):
            self.assertFalse(
                phishguard.is_safe_public_host("localhost")
            )

    def test_private_ip_is_rejected(self):
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("192.168.1.10", 0))
            ]
        ):
            self.assertFalse(
                phishguard.is_safe_public_host("internal.example")
            )

    def test_link_local_ip_is_rejected(self):
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("169.254.169.254", 0))
            ]
        ):
            self.assertFalse(
                phishguard.is_safe_public_host("metadata.example")
            )

    def test_hostname_with_mixed_public_and_private_ips_is_rejected(self):
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("10.0.0.5", 0))
            ]
        ):
            self.assertFalse(
                phishguard.is_safe_public_host("mixed.example")
            )

    def test_dns_resolution_failure_is_rejected(self):
        with patch.object(
            phishguard.socket,
            "getaddrinfo",
            side_effect=socket.gaierror("DNS lookup failed")
        ):
            self.assertFalse(
                phishguard.is_safe_public_host("unresolvable.example")
            )


    @patch.object(phishguard, "is_safe_public_host")
    @patch.object(phishguard.requests, "get")
    def test_private_redirect_destination_is_blocked(
        self, mock_get, mock_safe_host
    ):
        mock_safe_host.side_effect = [True, False]
        mock_get.return_value.status_code = 302
        mock_get.return_value.headers = {
            "Location": "http://127.0.0.1/admin"
        }

        result = phishguard.analyze_redirects(
            "https://public.example/"
        )

        self.assertEqual(mock_get.call_count, 1)
        self.assertIsNotNone(result["error"])

    @patch.object(phishguard, "is_safe_public_host", return_value=True)
    @patch.object(phishguard.requests, "get")
    def test_https_downgrade_is_detected(
        self, mock_get, mock_safe_host
    ):
        mock_get.side_effect = [
            type("Response", (), {
                "status_code": 302,
                "headers": {"Location": "http://public.example/page"},
                "close": lambda self: None
            })(),
            type("Response", (), {
                "status_code": 200,
                "headers": {},
                "close": lambda self: None
            })()
        ]

        result = phishguard.analyze_redirects(
            "https://public.example/"
        )

        self.assertTrue(result["https_downgrade"])

    @patch.object(phishguard, "is_safe_public_host", return_value=True)
    @patch.object(phishguard.requests, "get")
    def test_unsupported_redirect_scheme_is_blocked(
        self, mock_get, mock_safe_host
    ):
        mock_get.return_value.status_code = 302
        mock_get.return_value.headers = {
            "Location": "javascript:alert(1)"
        }

        result = phishguard.analyze_redirects(
            "https://public.example/"
        )

        self.assertEqual(mock_get.call_count, 1)
        self.assertIsNotNone(result["error"])

    @patch.object(phishguard, "is_safe_public_host", return_value=True)
    @patch.object(phishguard.requests, "get")
    def test_redirect_limit_is_enforced(
        self, mock_get, mock_safe_host
    ):
        mock_get.return_value.status_code = 302
        mock_get.return_value.headers = {"Location": "/next"}
        mock_get.return_value.close = lambda: None

        result = phishguard.analyze_redirects(
            "https://public.example/",
            max_redirects=2
        )

        self.assertTrue(result["excessive_redirects"])
        self.assertLessEqual(result["redirect_count"], 2)

    @patch.object(phishguard, "is_safe_public_host", return_value=True)
    @patch.object(phishguard.requests, "get")
    def test_redirect_chain_is_recorded(
        self, mock_get, mock_safe_host
    ):
        mock_get.side_effect = [
            type("Response", (), {
                "status_code": 302,
                "headers": {"Location": "/destination"},
                "close": lambda self: None
            })(),
            type("Response", (), {
                "status_code": 200,
                "headers": {},
                "close": lambda self: None
            })()
        ]

        result = phishguard.analyze_redirects(
            "https://public.example/"
        )

        self.assertEqual(result["redirect_count"], 1)
        self.assertEqual(len(result["redirect_chain"]), 1)

if __name__ == "__main__":
    unittest.main()
