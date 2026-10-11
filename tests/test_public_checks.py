"""Offline behavior and boundary tests. All responses and DNS answers are fake."""

import hashlib
import io
import json
import socket
import ssl
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

from scripts import common
from scripts.check_headers import check_headers
from scripts.check_tls import check_tls


PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))


class HeadersOnlyStream(io.BytesIO):
    """Header lines may be consumed, but any body read fails the test."""

    def read(self, *args, **kwargs):
        raise AssertionError("The public check must not read the response body")

    def readinto(self, *args, **kwargs):
        raise AssertionError("The public check must not read the response body")


class HostBoundaryTests(unittest.TestCase):
    def test_normalizes_dns_case_and_root_dot(self):
        self.assertEqual(common.validate_host("ExAmPlE.COM."), "example.com")

    def test_rejects_urls_credentials_paths_ports_and_ip_literals_before_dns(self):
        invalid = (
            "", "localhost", "127.0.0.1", "::1", "https://example.com",
            "user:password@example.com", "example.com/private", "example.com:443",
            "example.com?token=secret", "example.com#fragment", "example.com\r\nX: y",
            " example.com", "example.com ", "example..com", "-bad.example",
            "example.com..", "\u00e9xample.com", "\u212a.example.com", "a" * 64 + ".com",
        )
        with patch("scripts.common.socket.getaddrinfo") as resolver:
            for host in invalid:
                with self.subTest(host=host), self.assertRaises(ValueError):
                    common.public_endpoint(host)
            resolver.assert_not_called()

    def test_blocks_non_public_and_multicast_answers_before_connection(self):
        blocked = (
            "127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "192.0.2.1", "224.0.0.1", "240.0.0.1",
            "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "4000::1",
        )
        for address in blocked:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
            answer = (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)
            with self.subTest(address=address), patch(
                "scripts.common.socket.getaddrinfo", return_value=[PUBLIC, answer]
            ), patch("scripts.common.socket.socket") as create_socket:
                with self.assertRaises(ValueError):
                    common.open_verified_tls("example.com")
                create_socket.assert_not_called()

    def test_empty_dns_answer_is_an_error(self):
        with patch("scripts.common.socket.getaddrinfo", return_value=[]):
            with self.assertRaisesRegex(ValueError, "no usable"):
                common.public_endpoint("example.com")

    def test_accepts_public_ipv6(self):
        answer = (
            socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
            ("2606:4700:4700::1111", 443, 0, 0),
        )
        with patch("scripts.common.socket.getaddrinfo", return_value=[answer]):
            self.assertEqual(common.public_endpoint("example.com"), answer)


class TransportTests(unittest.TestCase):
    def test_pins_checked_address_and_preserves_tls_hostname(self):
        raw, tls, context = MagicMock(), MagicMock(), MagicMock()
        context.wrap_socket.return_value = tls
        with patch("scripts.common.socket.getaddrinfo", return_value=[PUBLIC]) as resolver, patch(
            "scripts.common.socket.socket", return_value=raw
        ) as create_socket, patch(
            "scripts.common.ssl.create_default_context", return_value=context
        ) as create_context:
            self.assertIs(common.open_verified_tls("EXAMPLE.COM"), tls)
        resolver.assert_called_once_with(
            "example.com", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        create_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.connect.assert_called_once_with(("8.8.8.8", 443))
        raw.settimeout.assert_called_once_with(5)
        create_context.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com")

    def test_certificate_failure_closes_socket_without_retry(self):
        raw, context = MagicMock(), MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate rejected")
        with patch("scripts.common.socket.getaddrinfo", return_value=[PUBLIC]), patch(
            "scripts.common.socket.socket", return_value=raw
        ), patch("scripts.common.ssl.create_default_context", return_value=context):
            with self.assertRaises(ssl.SSLCertVerificationError):
                common.open_verified_tls("example.com")
        raw.connect.assert_called_once()
        raw.close.assert_called_once()
        context.wrap_socket.assert_called_once()

    def test_connect_failure_closes_socket_without_retry(self):
        raw = MagicMock()
        raw.connect.side_effect = TimeoutError("timed out")
        with patch("scripts.common.socket.getaddrinfo", return_value=[PUBLIC]), patch(
            "scripts.common.socket.socket", return_value=raw
        ), patch("scripts.common.ssl.create_default_context"):
            with self.assertRaises(TimeoutError):
                common.open_verified_tls("example.com")
        raw.connect.assert_called_once()
        raw.close.assert_called_once()


class HeaderObservationTests(unittest.TestCase):
    def observe(self, response_bytes):
        tls = MagicMock()
        tls.__enter__.return_value = tls
        tls.makefile.return_value = HeadersOnlyStream(response_bytes)
        with patch("scripts.check_headers.open_verified_tls", return_value=tls) as connect, patch(
            "scripts.common.socket.getaddrinfo", side_effect=AssertionError("No real DNS")
        ), patch("scripts.common.socket.socket", side_effect=AssertionError("No real network")):
            result = check_headers("example.com")
        connect.assert_called_once_with("example.com")
        tls.sendall.assert_called_once()
        request = tls.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"HEAD / HTTP/1.1\r\n"))
        self.assertIn(b"Host: example.com\r\n", request)
        self.assertIn(b"Connection: close\r\n", request)
        self.assertNotIn(b"Authorization:", request)
        self.assertNotIn(b"Cookie:", request)
        self.assertTrue(request.endswith(b"\r\n\r\n"))
        return result

    def test_redirect_is_not_followed_and_cookies_and_body_are_not_reported(self):
        result = self.observe(
            b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/private\r\n"
            b"Strict-Transport-Security: max-age=31536000\r\n"
            b"Set-Cookie: session=synthetic-secret\r\nContent-Length: 16\r\n\r\n"
            b"synthetic-body!!"
        )
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["security_headers"]["Strict-Transport-Security"], "max-age=31536000")
        self.assertIn("Content-Security-Policy", result["missing_headers"])
        serialized = json.dumps(result)
        for excluded in ("synthetic-secret", "synthetic-body", "Location", "127.0.0.1"):
            self.assertNotIn(excluded, serialized)

    def test_method_not_allowed_is_recorded_without_get_fallback(self):
        result = self.observe(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(result["status"], 405)
        self.assertEqual(len(result["missing_headers"]), 6)

    def test_case_insensitive_header_names(self):
        result = self.observe(
            b"HTTP/1.1 200 OK\r\nx-content-type-options: nosniff\r\nContent-Length: 0\r\n\r\n"
        )
        self.assertEqual(result["security_headers"]["X-Content-Type-Options"], "nosniff")


class TLSObservationTests(unittest.TestCase):
    def test_reports_negotiation_and_certificate_without_application_traffic(self):
        tls = MagicMock()
        tls.__enter__.return_value = tls
        cert = {"notBefore": "Jan  1 00:00:00 2026 GMT", "notAfter": "Jan  1 00:00:00 2027 GMT"}
        tls.getpeercert.side_effect = lambda binary_form=False: b"synthetic DER" if binary_form else cert
        tls.version.return_value = "TLSv1.3"
        tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        with patch("scripts.check_tls.open_verified_tls", return_value=tls) as connect:
            result = check_tls("example.com")
        connect.assert_called_once_with("example.com")
        self.assertEqual(result["tls_version"], "TLSv1.3")
        self.assertEqual(result["certificate"]["not_after"], cert["notAfter"])
        self.assertEqual(result["certificate"]["sha256"], hashlib.sha256(b"synthetic DER").hexdigest())
        tls.send.assert_not_called()
        tls.sendall.assert_not_called()
        tls.makefile.assert_not_called()


class CommandTests(unittest.TestCase):
    def test_success_prints_json_and_returns_zero(self):
        output = io.StringIO()
        with patch("sys.argv", ["check", "--host", "example.com"]), redirect_stdout(output):
            code = common.run_cli(lambda host: {"host": host}, "Test")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue()), {"host": "example.com"})

    def test_network_error_returns_one_with_json_on_stderr(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch("sys.argv", ["check", "--host", "example.com"]), redirect_stdout(
            output
        ), redirect_stderr(errors):
            code = common.run_cli(MagicMock(side_effect=TimeoutError("timed out")), "Test")
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(json.loads(errors.getvalue()), {"error": "timed out"})

    def test_no_default_target(self):
        check = MagicMock()
        with patch("sys.argv", ["check"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                common.run_cli(check, "Test")
        self.assertEqual(raised.exception.code, 2)
        check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
