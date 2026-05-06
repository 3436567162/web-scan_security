import os
import runpy
import socket
import time
import unittest
from unittest.mock import patch

import app as app_module


def fail_if_scanned(_url):
    raise AssertionError("scan modules should not be called for rejected URLs")


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module._LAST_SCAN_BY_CLIENT.clear()
        self.client = app_module.app.test_client()
        self.scan_modules_patch = patch.object(
            app_module,
            "SCAN_MODULES",
            [("sentinel", fail_if_scanned)],
        )
        self.scan_modules_patch.start()
        self.addCleanup(self.scan_modules_patch.stop)

    def post_scan(self, url):
        return self.client.post("/api/scan", json={"url": url})

    def test_scan_rejects_loopback_and_private_addresses(self):
        rejected_urls = [
            "http://localhost",
            "http://127.0.0.1",
            "http://127.42.0.1",
            "http://[::1]",
            "http://10.0.0.5",
            "http://172.16.0.5",
            "http://192.168.1.10",
        ]

        for url in rejected_urls:
            with self.subTest(url=url):
                response = self.post_scan(url)

                self.assertEqual(400, response.status_code)

    def test_scan_rejects_link_local_multicast_and_reserved_addresses(self):
        rejected_urls = [
            "http://169.254.1.1",
            "http://224.0.0.1",
            "http://240.0.0.1",
        ]

        for url in rejected_urls:
            with self.subTest(url=url):
                response = self.post_scan(url)

                self.assertEqual(400, response.status_code)

    def test_scan_rejects_domain_when_dns_resolution_fails(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            response = self.post_scan("http://does-not-resolve.example")

        self.assertEqual(400, response.status_code)

    def test_scan_allows_public_http_url_without_real_scanning(self):
        with patch(
            "socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
        ), patch.object(
            app_module,
            "SCAN_MODULES",
            [("sentinel", lambda _url: [])],
        ):
            response = self.post_scan("example.com")

        self.assertEqual(200, response.status_code)
        self.assertEqual("http://example.com", response.get_json()["url"])

    def test_scan_rate_limits_same_client(self):
        with patch(
            "socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
        ), patch.object(
            app_module,
            "SCAN_MODULES",
            [("sentinel", lambda _url: [])],
        ), patch("app.time.monotonic", side_effect=[100.0, 101.0]):
            first = self.client.post(
                "/api/scan",
                json={"url": "example.com"},
                environ_overrides={"REMOTE_ADDR": "203.0.113.9"},
            )
            second = self.client.post(
                "/api/scan",
                json={"url": "example.com"},
                environ_overrides={"REMOTE_ADDR": "203.0.113.9"},
            )

        self.assertEqual(200, first.status_code)
        self.assertEqual(429, second.status_code)

    def test_normalize_url_rejects_blank_and_non_http_schemes(self):
        invalid_urls = ["", "   ", "ftp://example.com", "javascript:alert(1)"]

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    app_module.normalize_url(url)

    def test_normalize_url_adds_http_when_scheme_is_missing(self):
        self.assertEqual("http://example.com", app_module.normalize_url("example.com"))
        try:
            url_with_port_and_path = app_module.normalize_url("example.com:8080/path")
        except ValueError as exc:
            self.fail(f"normalize_url rejected URL without scheme: {exc}")

        self.assertEqual(
            "http://example.com:8080/path",
            url_with_port_and_path,
        )

    def test_app_run_defaults_to_localhost_and_debug_off(self):
        with patch.dict(os.environ, {}, clear=True), patch("flask.Flask.run") as run:
            runpy.run_module("app", run_name="__main__")

        run.assert_called_once_with(debug=False, host="127.0.0.1", port=5000)

    def test_app_run_uses_flask_environment_overrides(self):
        env = {
            "FLASK_HOST": "0.0.0.0",
            "FLASK_PORT": "8080",
            "FLASK_DEBUG": "true",
        }

        with patch.dict(os.environ, env, clear=True), patch("flask.Flask.run") as run:
            runpy.run_module("app", run_name="__main__")

        run.assert_called_once_with(debug=True, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    unittest.main()
