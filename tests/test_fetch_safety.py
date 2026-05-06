import socket
import unittest
from unittest.mock import patch

import requests

from scanner import crawler


def make_response(status_code, headers=None, url="https://example.test/"):
    response = requests.Response()
    response.status_code = status_code
    response.url = url
    response._content = b""
    if headers:
        response.headers.update(headers)
    return response


class LargeStreamResponse:
    def __init__(self, chunks, url="https://example.test/large"):
        self.status_code = 200
        self.url = url
        self.headers = {}
        self.is_redirect = False
        self.encoding = "utf-8"
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=1, decode_unicode=False):
        del chunk_size, decode_unicode
        for chunk in self._chunks:
            yield chunk

    def close(self):
        self.closed = True


class FetchSafetyTests(unittest.TestCase):
    def public_dns(self, hostname, *_args, **_kwargs):
        if hostname == "example.test":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 443),
                )
            ]
        if hostname == "metadata.test":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("169.254.169.254", 80),
                )
            ]
        raise socket.gaierror

    @patch("socket.getaddrinfo")
    @patch("scanner.crawler.requests.get")
    def test_fetch_rejects_private_initial_target(self, mock_get, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.public_dns

        result = crawler.fetch("http://169.254.169.254/latest/meta-data")

        self.assertIsNone(result)
        mock_get.assert_not_called()

    @patch("socket.getaddrinfo")
    @patch("scanner.crawler.requests.get")
    def test_fetch_rejects_redirect_to_private_target(self, mock_get, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.public_dns

        def fake_get(_url, **kwargs):
            response = make_response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data"},
            )
            for hook in kwargs["hooks"]["response"]:
                hook(response)
            return response

        mock_get.side_effect = fake_get

        result = crawler.fetch("https://example.test/start")

        self.assertIsNone(result)

    @patch("socket.getaddrinfo")
    @patch("scanner.crawler.requests.get")
    def test_fetch_respects_scan_request_budget(self, mock_get, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.public_dns
        mock_get.return_value = make_response(200)

        with crawler.request_budget(1):
            first = crawler.fetch("https://example.test/first")
            second = crawler.fetch("https://example.test/second")

        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(1, mock_get.call_count)

    @patch("socket.getaddrinfo")
    @patch("scanner.crawler.requests.get")
    def test_fetch_rejects_oversized_response_bodies(self, mock_get, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = self.public_dns
        size_limit = getattr(crawler, "MAX_RESPONSE_BYTES", 1024)
        chunks = [
            b"a" * (size_limit // 2),
            b"b" * (size_limit // 2),
            b"c",
        ]
        response = LargeStreamResponse(chunks)
        mock_get.return_value = response

        result = crawler.fetch("https://example.test/large")

        self.assertIsNone(result)
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
