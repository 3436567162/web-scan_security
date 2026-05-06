"""Open redirect vulnerability detection."""

from urllib.parse import urlparse, parse_qs, urlencode
from .crawler import fetch, extract_params

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%00.example.com",
    "/\\evil.com",
    "https://evil.com/",
    "////evil.com",
]

REDIRECT_PARAM_NAMES = [
    "url", "redirect", "next", "return", "returnto", "return_to",
    "redirect_uri", "redirect_url", "go", "out", "view", "to",
    "continue", "dest", "destination", "redir", "redirect_to",
    "checkout_url", "return_url", "rurl", "forward",
]


def check_open_redirect(url):
    """Check for open redirect vulnerabilities in URL parameters."""
    results = []
    params = extract_params(url)

    # Check all query parameters
    redirect_params = list(params.keys())

    # Also check common redirect param names even if not present
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param_name in REDIRECT_PARAM_NAMES:
        if param_name in redirect_params:
            redirect_params.remove(param_name)
            redirect_params.insert(0, param_name)

    # Test each parameter
    tested = set()
    for param_name in redirect_params:
        if param_name in tested:
            continue
        tested.add(param_name)

        for payload in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = parsed._replace(
                query=urlencode(test_params, doseq=True)
            ).geturl()

            resp = fetch(test_url, allow_redirects=False)
            if resp is None:
                continue

            import time
            time.sleep(0.2)

            # Check for redirect to our payload
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    results.append({
                        "type": "high",
                        "title": "开放重定向漏洞",
                        "detail": (
                            f"参数 '{param_name}' 存在开放重定向\n"
                            f"Payload: {payload}\n"
                            f"重定向到: {location}"
                        ),
                    })
                    break

    # Also check path-based redirects
    path_payloads = ["/evil.com", "/\\/evil.com"]
    for payload in path_payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
        resp = fetch(test_url, allow_redirects=False)
        if resp is None:
            continue

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if "evil.com" in location:
                results.append({
                    "type": "high",
                    "title": "开放重定向漏洞 (路径)",
                    "detail": f"路径级重定向到外部域: {location}",
                })
                break

        import time
        time.sleep(0.2)

    if not results:
        results.append({
            "type": "pass",
            "title": "开放重定向检查通过",
            "detail": "未发现开放重定向漏洞",
        })

    return results
