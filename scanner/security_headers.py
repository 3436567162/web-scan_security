"""Check for missing or misconfigured HTTP security headers."""

from .crawler import fetch


REQUIRED_HEADERS = {
    "X-Frame-Options": {
        "severity": "medium",
        "desc": "防止点击劫持攻击。建议设置为 DENY 或 SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "desc": "防止MIME类型嗅探。建议设置为 nosniff",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "desc": "防止XSS和数据注入攻击。建议配置严格的CSP策略",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "desc": "强制HTTPS连接。建议设置为 max-age=31536000; includeSubDomains",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "desc": "浏览器XSS过滤器。建议设置为 1; mode=block",
    },
    "Referrer-Policy": {
        "severity": "low",
        "desc": "控制Referer头信息泄露。建议设置为 strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "desc": "控制浏览器功能权限（摄像头、麦克风等）",
    },
}


def check_security_headers(url):
    """Check for missing and misconfigured security headers."""
    results = []
    resp = fetch(url)
    if resp is None:
        return results

    headers = resp.headers

    # Check missing headers
    for header_name, info in REQUIRED_HEADERS.items():
        value = headers.get(header_name)
        if not value:
            results.append({
                "type": info["severity"],
                "title": f"缺少安全头: {header_name}",
                "detail": info["desc"],
            })

    # Check CORS wildcard
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        results.append({
            "type": "medium",
            "title": "CORS配置: Access-Control-Allow-Origin 为 *",
            "detail": "允许任意来源跨域访问，可能导致敏感数据泄露",
        })

    # Check HSTS strength
    hsts = headers.get("Strict-Transport-Security", "")
    if hsts and "max-age" in hsts:
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if max_age < 31536000:
                results.append({
                    "type": "low",
                    "title": "HSTS max-age 过短",
                    "detail": f"当前值: {max_age}秒，建议至少31536000秒（1年）",
                })
        except (ValueError, IndexError):
            pass

    # Check X-Frame-Options value
    xfo = headers.get("X-Frame-Options", "").upper()
    if xfo and xfo not in ("DENY", "SAMEORIGIN"):
        results.append({
            "type": "low",
            "title": "X-Frame-Options 配置不当",
            "detail": f"当前值: {xfo}，建议设置为 DENY 或 SAMEORIGIN",
        })

    # Check cookie security flags
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        if "httponly" not in cookies.lower():
            results.append({
                "type": "low",
                "title": "Cookie缺少HttpOnly标志",
                "detail": "Cookie未设置HttpOnly，可能被XSS攻击窃取",
            })
        if "secure" not in cookies.lower():
            results.append({
                "type": "low",
                "title": "Cookie缺少Secure标志",
                "detail": "Cookie未设置Secure，可能通过HTTP明文传输",
            })

    # Check if HTTP redirects to HTTPS
    if url.startswith("http://"):
        https_url = url.replace("http://", "https://", 1)
        resp_https = fetch(https_url)
        if resp_https is None or resp_https.status_code != 200:
            results.append({
                "type": "medium",
                "title": "未配置HTTPS重定向",
                "detail": "站点未将HTTP流量重定向到HTTPS",
            })

    if not results:
        results.append({
            "type": "pass",
            "title": "安全响应头检查通过",
            "detail": "所有关键安全头均已正确配置",
        })

    return results
