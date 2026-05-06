"""XSS (Cross-Site Scripting) detection for reflected XSS."""

import re
import time
from .crawler import fetch, extract_forms, extract_params, inject_param

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

# Dangerous unencoded HTML/script fragments. Plain text "alert(1)" is
# intentionally excluded because it does not prove executable reflection.
DANGEROUS_HTML_PATTERNS = [
    re.compile(r"<\s*script\b[^>]*>.*?alert\s*\(\s*1\s*\).*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]+\s+on(?:error|load)\s*=\s*['\"]?alert\s*\(\s*1\s*\)", re.IGNORECASE),
    re.compile(r"<[^>]+\s+(?:href|src)\s*=\s*['\"]?javascript\s*:\s*alert\s*\(\s*1\s*\)", re.IGNORECASE),
]


def check_xss(url):
    """Check URL parameters and forms for XSS vulnerabilities."""
    results = []
    results.extend(_check_url_params(url))
    results.extend(_check_forms(url))
    return results


def _check_url_params(url):
    """Test URL query parameters for reflected XSS."""
    results = []
    params = extract_params(url)
    if not params:
        return results

    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(url, param_name, payload)
            resp = fetch(test_url)
            if resp is None:
                continue

            time.sleep(0.2)

            if _has_unencoded_xss_reflection(resp.text, payload):
                results.append({
                    "type": "high",
                    "title": "XSS跨站脚本漏洞 (GET参数)",
                    "detail": (
                        f"参数 '{param_name}' 存在反射型XSS\n"
                        f"Payload: {payload}\n"
                        f"Payload被原样返回到页面中"
                    ),
                    "url": test_url,
                })
                break

    return results


def _check_forms(url):
    """Test form inputs for reflected XSS."""
    results = []
    forms = extract_forms(url)
    if not forms:
        return results

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                continue

            for payload in XSS_PAYLOADS:
                data = {}
                for field in form["inputs"]:
                    if field["name"] == inp["name"]:
                        data[field["name"]] = payload
                    elif field["type"] not in ("submit", "button"):
                        data[field["name"]] = field.get("value", "test")

                try:
                    if form["method"] == "POST":
                        resp = fetch(form["action"], method="POST", data=data)
                    else:
                        resp = fetch(form["action"], params=data)
                except Exception:
                    continue

                if resp is None:
                    continue

                time.sleep(0.2)

                if _has_unencoded_xss_reflection(resp.text, payload):
                    results.append({
                        "type": "high",
                        "title": "XSS跨站脚本漏洞 (表单)",
                        "detail": (
                            f"表单字段 '{inp['name']}' 存在反射型XSS\n"
                            f"表单Action: {form['action']}\n"
                            f"Method: {form['method']}\n"
                            f"Payload: {payload}"
                        ),
                    })
                    break

    return results


def _has_unencoded_xss_reflection(body, payload):
    """Return True only for raw payload or executable-looking HTML reflection."""
    if not body:
        return False

    if payload in body:
        return True

    return any(pattern.search(body) for pattern in DANGEROUS_HTML_PATTERNS)
