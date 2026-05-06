"""Information gathering: server fingerprint, tech stack, CMS detection."""

from urllib.parse import urlparse
from .crawler import fetch


def gather_info(url):
    """Gather basic information about the target."""
    results = []
    resp = fetch(url)
    if resp is None:
        return [{"type": "info", "title": "连接失败", "detail": f"无法访问目标 {url}"}]

    headers = resp.headers
    server = headers.get("Server", "未知")
    powered_by = headers.get("X-Powered-By", "未知")
    status = resp.status_code

    results.append({
        "type": "info",
        "title": "服务器信息",
        "detail": f"服务器: {server} | X-Powered-By: {powered_by} | 状态码: {status}"
    })

    # Detect tech stack from headers and body
    tech = _detect_tech(headers, resp.text)
    if tech:
        results.append({
            "type": "info",
            "title": "技术栈识别",
            "detail": ", ".join(tech)
        })

    # Detect CMS
    cms = _detect_cms(url, resp.text, headers)
    if cms:
        results.append({
            "type": "info",
            "title": "CMS识别",
            "detail": cms
        })

    # Detect HTTP methods
    try:
        import requests as req
        opt = req.options(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10, verify=False)
        allow = opt.headers.get("Allow", "")
        if allow:
            results.append({
                "type": "info",
                "title": "允许的HTTP方法",
                "detail": allow
            })
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                results.append({
                    "type": "low",
                    "title": "危险HTTP方法启用",
                    "detail": f"服务器启用了可能危险的方法: {', '.join(dangerous)}"
                })
    except Exception:
        pass

    # Detect admin paths
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    admin_paths = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/manager"]
    for path in admin_paths:
        resp_admin = fetch(base + path)
        if resp_admin is not None and resp_admin.status_code == 200 and len(resp_admin.text) > 100:
            results.append({
                "type": "low",
                "title": "管理后台路径",
                "detail": f"发现管理路径: {base + path} (状态码: {resp_admin.status_code})"
            })
            break

    return results


def _detect_tech(headers, body):
    """Detect technology stack from headers and body content."""
    tech = []
    powered = headers.get("X-Powered-By", "").lower()
    server = headers.get("Server", "").lower()

    if "php" in powered or "php" in server:
        tech.append("PHP")
    if "asp.net" in powered or "asp.net" in server:
        tech.append("ASP.NET")
    if "express" in powered:
        tech.append("Node.js/Express")
    if "django" in body.lower() or "csrfmiddlewaretoken" in body:
        tech.append("Django")
    if "flask" in body.lower():
        tech.append("Flask")
    if "laravel" in body.lower() or "laravel_session" in headers.get("Set-Cookie", ""):
        tech.append("Laravel")
    if "spring" in powered.lower() or "jsessionid" in headers.get("Set-Cookie", "").lower():
        tech.append("Java/Spring")
    if "nginx" in server:
        tech.append("Nginx")
    if "apache" in server:
        tech.append("Apache")
    if "iis" in server:
        tech.append("IIS")

    return tech


def _detect_cms(url, body, headers):
    """Detect common CMS platforms."""
    body_lower = body.lower()
    cookies = headers.get("Set-Cookie", "").lower()

    if "wp-content" in body_lower or "wp-includes" in body_lower or "wordpress" in cookies:
        return "WordPress"
    if "joomla" in body_lower or "joomla" in cookies:
        return "Joomla"
    if "drupal" in body_lower or "drupal" in cookies:
        return "Drupal"
    if "shopify" in body_lower:
        return "Shopify"
    if "wix.com" in body_lower:
        return "Wix"

    return None
