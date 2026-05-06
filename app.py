"""Web Vulnerability Scanner - Flask Application."""

import os
import time
from urllib.parse import urlparse

import urllib3
from flask import Flask, render_template, request, jsonify

from scanner.crawler import budget_exhausted, request_budget
from scanner.cors_check import check_cors
from scanner.dir_traversal import check_dir_traversal
from scanner.info_gather import gather_info
from scanner.open_redirect import check_open_redirect
from scanner.security_headers import check_security_headers
from scanner.sqli_scanner import check_sqli
from scanner.url_safety import validate_public_http_url
from scanner.xss_scanner import check_xss

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
SCAN_REQUEST_LIMIT = 60
CLIENT_SCAN_COOLDOWN_SECONDS = 5.0
_LAST_SCAN_BY_CLIENT = {}


def normalize_url(url):
    """Ensure URL has an allowed scheme."""
    if not isinstance(url, str):
        raise ValueError("Invalid URL")

    url = url.strip()
    if not url:
        raise ValueError("URL is required")

    parsed = urlparse(url)
    if parsed.scheme:
        if parsed.scheme.lower() in {"http", "https"}:
            return url

        if "://" not in url:
            prefix, _, suffix = url.partition(":")
            port_text = suffix.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if prefix and port_text.isdigit():
                return "http://" + url

        raise ValueError("Only http and https URLs are allowed")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url
def validate_scan_url(url):
    validate_public_http_url(url)


def get_client_id():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(client_id):
    now = time.monotonic()
    last_seen = _LAST_SCAN_BY_CLIENT.get(client_id)
    if last_seen is not None and now - last_seen < CLIENT_SCAN_COOLDOWN_SECONDS:
        return True

    _LAST_SCAN_BY_CLIENT[client_id] = now
    return False


def parse_debug_env(value):
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_run_config():
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = parse_debug_env(os.environ.get("FLASK_DEBUG", ""))
    return host, port, debug


SCAN_MODULES = [
    ("信息收集", gather_info),
    ("安全响应头", check_security_headers),
    ("SQL注入", check_sqli),
    ("XSS跨站脚本", check_xss),
    ("目录遍历与敏感文件", check_dir_traversal),
    ("开放重定向", check_open_redirect),
    ("CORS配置", check_cors),
]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "请输入目标URL"}), 400

    try:
        url = normalize_url(data["url"])
        validate_scan_url(url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    client_id = get_client_id()
    if is_rate_limited(client_id):
        return jsonify({"error": "请求过于频繁，请稍后再试"}), 429

    results = {}

    with request_budget(SCAN_REQUEST_LIMIT):
        for module_name, scan_func in SCAN_MODULES:
            try:
                module_results = scan_func(url)
                results[module_name] = module_results
            except Exception as e:
                results[module_name] = [{
                    "type": "error",
                    "title": f"{module_name} 扫描出错",
                    "detail": str(e),
                }]

            if budget_exhausted():
                results.setdefault(module_name, []).append({
                    "type": "error",
                    "title": "扫描预算已耗尽",
                    "detail": "单次扫描的外部请求数已达到上限，后续模块已跳过。",
                })
                break

    # Summary
    total_high = 0
    total_medium = 0
    total_low = 0
    for module_results in results.values():
        for r in module_results:
            if r.get("type") == "high":
                total_high += 1
            elif r.get("type") == "medium":
                total_medium += 1
            elif r.get("type") == "low":
                total_low += 1

    return jsonify({
        "url": url,
        "results": results,
        "summary": {
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
    })


if __name__ == "__main__":
    run_host, run_port, run_debug = get_run_config()
    app.run(debug=run_debug, host=run_host, port=run_port)
