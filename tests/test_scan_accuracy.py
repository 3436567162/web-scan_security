import unittest
from unittest.mock import patch

from scanner import dir_traversal, xss_scanner


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class SensitivePathAccuracyTests(unittest.TestCase):
    def test_sensitive_path_rules_have_structured_severity(self):
        for rule in dir_traversal.SENSITIVE_PATHS:
            with self.subTest(rule=rule):
                self.assertIsInstance(rule, dict)
                self.assertIn(rule["severity"], {"info", "low", "medium", "high"})

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_public_metadata_paths_are_not_reported_as_medium(self, mock_fetch, _mock_sleep):
        def fake_fetch(url):
            if url.endswith("/robots.txt"):
                return FakeResponse(text="User-agent: *\nDisallow: /private\n")
            if url.endswith("/sitemap.xml"):
                return FakeResponse(text="<urlset>" + ("<url><loc>/</loc></url>" * 4) + "</urlset>")
            if url.endswith("/.well-known/security.txt"):
                return FakeResponse(text="Contact: mailto:security@example.test\n" + ("policy " * 12))
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")
        metadata_results = [
            item
            for item in results
            if any(path in item["detail"] for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"))
        ]

        self.assertEqual(len(metadata_results), 3)
        self.assertTrue(all(item["type"] in {"info", "low"} for item in metadata_results))

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_sql_backup_keeps_higher_risk_severity(self, mock_fetch, _mock_sleep):
        def fake_fetch(url):
            if url.endswith("/backup.sql"):
                return FakeResponse(text="CREATE TABLE users (id int, password varchar(255));\n" * 2)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")
        backup_result = next(item for item in results if "/backup.sql" in item["detail"])

        self.assertIn(backup_result["type"], {"medium", "high"})


class XssAccuracyTests(unittest.TestCase):
    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    @patch("scanner.xss_scanner.extract_forms")
    def test_text_alert_in_url_response_is_not_high(
        self,
        mock_extract_forms,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_forms.return_value = []
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, payload: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(text="<p>Example text mentions alert(1), but no HTML payload.</p>")

        results = xss_scanner.check_xss("https://example.test/search?q=test")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    @patch("scanner.xss_scanner.extract_forms")
    def test_encoded_payload_in_url_response_is_not_high(
        self,
        mock_extract_forms,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_forms.return_value = []
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, payload: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(text="&lt;script&gt;alert(1)&lt;/script&gt;")

        results = xss_scanner.check_xss("https://example.test/search?q=test")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    @patch("scanner.xss_scanner.extract_forms")
    def test_text_alert_in_form_response_is_not_high(
        self,
        mock_extract_forms,
        mock_extract_params,
        _mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_params.return_value = {}
        mock_extract_forms.return_value = [
            {
                "action": "https://example.test/comment",
                "method": "POST",
                "inputs": [{"name": "comment", "type": "text", "value": ""}],
            }
        ]
        mock_fetch.return_value = FakeResponse(text="<p>Stored help text: call alert(1) in examples.</p>")

        results = xss_scanner.check_xss("https://example.test/comment")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    @patch("scanner.xss_scanner.extract_forms")
    def test_raw_xss_payload_in_url_response_is_high(
        self,
        mock_extract_forms,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_forms.return_value = []
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, payload: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(text=f"<html>{xss_scanner.XSS_PAYLOADS[0]}</html>")

        results = xss_scanner.check_xss("https://example.test/search?q=test")

        self.assertTrue(any(item["type"] == "high" for item in results))


if __name__ == "__main__":
    unittest.main()
