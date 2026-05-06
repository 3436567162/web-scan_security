"""SQL Injection detection based on error-based injection."""

import time
from urllib.parse import urlparse, parse_qs, urlencode

from .crawler import fetch, extract_forms, extract_params, inject_param

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND '1'='1", "1 AND 1=1--"]

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "sqlstate",
    "pg_query",
    "pg_exec",
    "sqlite3",
    "sql command not properly ended",
    "quoted string not properly terminated",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-",
    "postgresql",
    "syntax error",
    "sqlite_error",
    "sqlalchemy",
    "database error",
    "db2 sql error",
    "microsoft access",
    "jdbc",
    "odbc",
]


def check_sqli(url):
    """Check URL parameters and forms for SQL injection vulnerabilities."""
    results = []
    results.extend(_check_url_params(url))
    results.extend(_check_forms(url))
    return results


def _check_url_params(url):
    """Test URL query parameters for SQL injection."""
    results = []
    params = extract_params(url)
    if not params:
        return results

    original_resp = fetch(url)
    if original_resp is None:
        return results
    original_text = original_resp.text

    for param_name in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_param(url, param_name, payload)
            resp = fetch(test_url)
            if resp is None:
                continue

            time.sleep(0.2)  # Rate limiting

            # Check for SQL errors in response
            resp_lower = resp.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if pattern in resp_lower and pattern not in original_text.lower():
                    results.append({
                        "type": "high",
                        "title": "SQL注入漏洞 (GET参数)",
                        "detail": (
                            f"参数 '{param_name}' 存在SQL注入风险\n"
                            f"Payload: {payload}\n"
                            f"匹配错误信息: {pattern}"
                        ),
                        "url": test_url,
                    })
                    break
            else:
                continue
            break  # Found one payload for this param, move to next

    return results


def _check_forms(url):
    """Test form inputs for SQL injection."""
    results = []
    forms = extract_forms(url)
    if not forms:
        return results

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                continue

            for payload in SQLI_PAYLOADS:
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

                resp_lower = resp.text.lower()
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in resp_lower:
                        results.append({
                            "type": "high",
                            "title": "SQL注入漏洞 (表单)",
                            "detail": (
                                f"表单字段 '{inp['name']}' 存在SQL注入风险\n"
                                f"表单Action: {form['action']}\n"
                                f"Method: {form['method']}\n"
                                f"Payload: {payload}\n"
                                f"匹配错误信息: {pattern}"
                            ),
                        })
                        break
                else:
                    continue
                break

    return results
