"""Directory traversal and sensitive file detection."""

from urllib.parse import urlparse
from .crawler import fetch


def _path_rule(path, description, severity):
    return {"path": path, "description": description, "severity": severity}


SENSITIVE_PATHS = [
    _path_rule("/robots.txt", "robots.txt 文件", "info"),
    _path_rule("/.git/config", "Git配置文件泄露", "high"),
    _path_rule("/.git/HEAD", "Git仓库泄露", "high"),
    _path_rule("/.env", "环境配置文件泄露", "high"),
    _path_rule("/.htaccess", "Apache配置文件泄露", "high"),
    _path_rule("/web.config", "IIS配置文件泄露", "high"),
    _path_rule("/phpinfo.php", "PHP信息页面", "medium"),
    _path_rule("/info.php", "PHP信息页面", "medium"),
    _path_rule("/server-status", "Apache状态页面", "medium"),
    _path_rule("/server-info", "Apache信息页面", "medium"),
    _path_rule("/.DS_Store", "macOS目录文件泄露", "high"),
    _path_rule("/backup.sql", "数据库备份文件", "high"),
    _path_rule("/backup.zip", "备份压缩包", "high"),
    _path_rule("/db.sql", "数据库备份文件", "high"),
    _path_rule("/dump.sql", "数据库导出文件", "high"),
    _path_rule("/wp-config.php.bak", "WordPress配置备份", "high"),
    _path_rule("/config.php.bak", "PHP配置备份", "high"),
    _path_rule("/.svn/entries", "SVN仓库泄露", "high"),
    _path_rule("/.hg/dirstate", "Mercurial仓库泄露", "high"),
    _path_rule("/crossdomain.xml", "跨域策略文件", "low"),
    _path_rule("/sitemap.xml", "站点地图", "info"),
    _path_rule("/.well-known/security.txt", "安全联系信息", "info"),
    _path_rule("/admin/", "管理后台目录", "medium"),
    _path_rule("/wp-admin/", "WordPress管理后台", "medium"),
    _path_rule("/api/", "API端点", "medium"),
    _path_rule("/debug/", "调试页面", "medium"),
    _path_rule("/test/", "测试页面", "medium"),
    _path_rule("/console", "控制台页面", "medium"),
]

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Linux密码文件", "root:"),
    ("..\\..\\..\\windows\\win.ini", "Windows配置文件", "[fonts]"),
    ("....//....//....//etc/passwd", "双写绕过", "root:"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "URL编码绕过", "root:"),
]

DIRECTORY_LISTING_MARKERS = [
    "index of /",
    "directory listing for",
    "<title>directory listing",
    "parent directory",
]


def check_dir_traversal(url):
    """Check for sensitive files, directory listing, and path traversal."""
    results = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    results.extend(_check_sensitive_files(base))
    results.extend(_check_directory_listing(base))
    results.extend(_check_path_traversal(url))

    return results


def _check_sensitive_files(base):
    """Probe for common sensitive files."""
    results = []
    found = []

    for rule in SENSITIVE_PATHS:
        path = rule["path"]
        test_url = base + path
        resp = fetch(test_url)
        if resp is None:
            continue

        if resp.status_code == 200 and len(resp.text) > 10:
            # Verify it's not a generic error page
            if _is_valid_content(resp.text, path):
                found.append({
                    "severity": rule["severity"],
                    "detail": f"{rule['description']}: {test_url}",
                })

        import time
        time.sleep(0.1)

    if found:
        for item in found:
            results.append({
                "type": item["severity"],
                "title": "敏感文件/路径暴露",
                "detail": item["detail"],
            })
    else:
        results.append({
            "type": "pass",
            "title": "敏感文件扫描通过",
            "detail": "未发现常见敏感文件暴露",
        })

    return results


def _check_directory_listing(base):
    """Check if directory listing is enabled."""
    results = []
    test_paths = ["/", "/images/", "/uploads/", "/files/", "/assets/", "/static/"]

    for path in test_paths:
        resp = fetch(base + path)
        if resp is None:
            continue

        resp_lower = resp.text.lower()
        for marker in DIRECTORY_LISTING_MARKERS:
            if marker in resp_lower:
                results.append({
                    "type": "medium",
                    "title": "目录列表开启",
                    "detail": f"路径 {base + path} 开启了目录列表功能",
                })
                break

        import time
        time.sleep(0.1)

    return results


def _check_path_traversal(url):
    """Test for path traversal vulnerabilities."""
    results = []
    parsed = urlparse(url)

    # Find path segments that might be injectable
    path = parsed.path
    if not path or path == "/":
        return results

    segments = path.strip("/").split("/")
    if len(segments) < 1:
        return results

    # Try injecting into the last path segment
    for payload, desc, marker in TRAVERSAL_PAYLOADS:
        new_path = "/" + "/".join(segments[:-1]) + "/" + payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
        if parsed.query:
            test_url += f"?{parsed.query}"

        resp = fetch(test_url)
        if resp is None:
            continue

        if marker in resp.text:
            results.append({
                "type": "high",
                "title": "路径遍历漏洞",
                "detail": f"在路径中发现目录遍历 ({desc})\n测试URL: {test_url}",
            })
            break

        import time
        time.sleep(0.2)

    return results


def _is_valid_content(body, path):
    """Check if the response is real content vs a generic error page."""
    body_lower = body.lower()

    # Common error page indicators
    error_indicators = ["404 not found", "page not found", "error 404", "not found"]
    for indicator in error_indicators:
        if indicator in body_lower and len(body) < 2000:
            return False

    # Specific checks
    if path.endswith(".git/config"):
        return "[core]" in body or "repositoryformatversion" in body_lower
    if path.endswith(".git/HEAD"):
        return "ref:" in body
    if path.endswith(".env"):
        return "=" in body and len(body) < 10000
    if path.endswith("/robots.txt"):
        return "user-agent" in body_lower or "disallow" in body_lower
    if path.endswith("/sitemap.xml"):
        return "<urlset" in body_lower or "<sitemapindex" in body_lower
    if path.endswith("/.well-known/security.txt"):
        security_directives = [
            "contact:",
            "expires:",
            "encryption:",
            "policy:",
            "acknowledgments:",
            "hiring:",
        ]
        return any(directive in body_lower for directive in security_directives)
    if path.endswith("/crossdomain.xml"):
        return "<cross-domain-policy" in body_lower

    return len(body) > 50
