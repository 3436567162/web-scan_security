import unittest
from unittest.mock import patch

import requests

from scanner import crawler
from scanner import open_redirect
from scanner import security_headers


def make_response(status_code, body="", headers=None):
    response = requests.Response()
    response.status_code = status_code
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    if headers:
        response.headers.update(headers)
    return response


class FalsyRedirectResponse:
    status_code = 302
    headers = {"Location": "https://evil.com/callback"}

    def __bool__(self):
        return False


class FetchRedirectTests(unittest.TestCase):
    @patch("scanner.crawler.requests.get")
    @patch("scanner.crawler.validate_public_http_url", return_value=None)
    def test_fetch_follows_redirects_by_default(self, _mock_validate, mock_get):
        response = make_response(200)
        mock_get.return_value = response

        result = crawler.fetch("https://example.test/")

        self.assertIs(result, response)
        self.assertTrue(mock_get.call_args.kwargs["allow_redirects"])

    @patch("scanner.crawler.requests.get")
    @patch("scanner.crawler.validate_public_http_url", return_value=None)
    def test_fetch_allows_caller_to_disable_redirects(self, _mock_validate, mock_get):
        response = make_response(200)
        mock_get.return_value = response

        result = crawler.fetch("https://example.test/", allow_redirects=False)

        self.assertIs(result, response)
        self.assertFalse(mock_get.call_args.kwargs["allow_redirects"])

    @patch("scanner.crawler.requests.post")
    @patch("scanner.crawler.validate_public_http_url", return_value=None)
    def test_fetch_post_allows_caller_to_disable_redirects(self, _mock_validate, mock_post):
        response = make_response(200)
        mock_post.return_value = response

        result = crawler.fetch(
            "https://example.test/login",
            method="POST",
            allow_redirects=False,
        )

        self.assertIs(result, response)
        self.assertFalse(mock_post.call_args.kwargs["allow_redirects"])


class ResponseTruthinessTests(unittest.TestCase):
    @patch("scanner.crawler.fetch")
    def test_extract_forms_uses_4xx_response_body(self, mock_fetch):
        mock_fetch.return_value = make_response(
            404,
            '<form action="/submit" method="post">'
            '<input name="username" value="alice">'
            "</form>",
        )

        forms = crawler.extract_forms("https://example.test/missing")

        self.assertEqual(forms[0]["action"], "https://example.test/submit")
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(forms[0]["inputs"][0]["name"], "username")

    @patch("scanner.crawler.fetch")
    def test_extract_links_uses_4xx_response_body(self, mock_fetch):
        mock_fetch.return_value = make_response(
            404,
            '<a href="/next">next</a><a href="https://other.test/out">out</a>',
        )

        links = crawler.extract_links("https://example.test/missing")

        self.assertEqual(links, ["https://example.test/next"])

    @patch("time.sleep")
    @patch("scanner.open_redirect.fetch")
    def test_open_redirect_processes_non_none_falsey_response(self, mock_fetch, _):
        mock_fetch.return_value = FalsyRedirectResponse()

        results = open_redirect.check_open_redirect(
            "https://example.test/login?next=/home"
        )

        self.assertEqual(results[0]["type"], "high")
        self.assertIn("evil.com", results[0]["detail"])

    @patch("scanner.security_headers.fetch")
    def test_security_headers_uses_4xx_response_headers(self, mock_fetch):
        mock_fetch.return_value = make_response(404)

        results = security_headers.check_security_headers("https://example.test/missing")

        self.assertTrue(results)
        self.assertNotEqual([], results)


class OpenRedirectTests(unittest.TestCase):
    @patch("time.sleep")
    @patch("scanner.crawler.requests.get")
    @patch("scanner.crawler.validate_public_http_url", return_value=None)
    def test_open_redirect_fetches_without_following_redirects(self, _mock_validate, mock_get, _):
        mock_get.return_value = make_response(
            302,
            headers={"Location": "https://evil.com/callback"},
        )

        results = open_redirect.check_open_redirect(
            "https://example.test/login?next=/home"
        )

        self.assertEqual(results[0]["type"], "high")
        self.assertIn("evil.com", results[0]["detail"])
        self.assertFalse(mock_get.call_args_list[0].kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
