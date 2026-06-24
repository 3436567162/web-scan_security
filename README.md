# VulnScanner — 登录网址漏洞扫描工具

一个轻量级、纯 Python 的 Web 登录页漏洞扫描工具，扫描后自动生成 JSON + HTML 报告。
**仅用于授权的安全测试、CTF、教学与自检场景。**

> 致谢：本项目由 AI 编程助手（Claude Code / 智谱 GLM）辅助开发。

## 功能

| 检测项 | 说明 |
|--------|------|
| 安全响应头 | HSTS / X-Frame-Options / CSP / X-Content-Type-Options / Referrer-Policy / Permissions-Policy / X-XSS-Protection / COOP / CORP |
| Cookie 安全 | Secure / HttpOnly / SameSite 属性 |
| SSL/TLS | HTTPS 启用、TLS 版本、证书有效期 |
| 表单枚举 | 自动识别登录表单与字段 |
| SQL 注入（错误回显） | 多数据库错误特征 + 多闭合方式 payload（16+ 载荷） |
| SQL 注入（时间盲注） | SLEEP / IF / WAITFOR / pg_sleep 延迟探测 |
| SQL 注入（布尔盲注） | 恒真 vs 恒假响应差异比对 |
| NoSQL / LDAP / XPath 注入 | 错误回显特征识别 + 注入载荷 |
| XSS 探测 | URL 参数反射 + GET 表单字段反射（14 种探针，含编码/标签绕过） |
| 目录遍历 | `../` / 编码绕过 / Windows+Unix / 系统文件特征识别 |
| 命令注入 | 时间盲注探测（sleep / ping / 反引号 / $()） |
| CRLF / 响应头注入 | 头部注入载荷 + 回显校验 |
| 弱口令 / 默认凭据 | 常见默认账密字典登录尝试 |
| 用户名枚举 | 合法名 vs 不存在名 的错误提示差异分析 |
| 敏感路径 | robots.txt / .git / .env / 备份文件 / phpMyAdmin / Swagger 等 34 项 |
| **漏洞利用取证（可选）** | 发现可确认漏洞后，主动利用并提取后台信息（见下） |

## 漏洞利用取证（可选，侵入性）

启用方式：GUI 勾选「⚠ 发现漏洞时尝试利用 / 进入后台取证」，或 CLI 加 `--exploit`。
**仅在已获书面授权时使用**——该阶段会主动提交利用载荷 / 用已知凭据登录后台。
仅做只读探测，不执行任何写操作。

发现可确认漏洞时，会尝试：

- **SQL 注入 → UNION 提取**：枚举查询列数、定位可回显列，提取 `version()` /
  `database()` / `current_user()` / 主机名 / 当前库的表名（只读）。
- **默认/弱口令 → 登录后台**：用确认有效的凭据登录，跟随跳转进入后台，
  抓取会话 Cookie、后台链接、邮箱、疑似账号名、配置项等可见信息。
- **XSS 执行验证**：对反射点生成可执行载荷，用 headless 浏览器（Edge/Chrome）
  实际加载目标页，通过回连到本机的回调服务器确认 JS 是否真实执行（而非仅反射）。
  命中即确认为「执行验证 XSS」，并捕获 `document.cookie`（证明会话窃取影响）。
  回调仅发往 `127.0.0.1`，不涉及第三方或真实用户；未安装 selenium 时自动降级为反射检测。

提取到的信息会作为独立的「后台取证 / 漏洞利用证据」章节，呈现在
**JSON / HTML / PDF** 三份报告中。

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
# 基本用法
python vuln_scanner.py https://example.com/login

# 跳过部分检测
python vuln_scanner.py https://example.com/login --no-sql --no-paths

# 自定义超时与 User-Agent
python vuln_scanner.py https://example.com/login --timeout 15 --ua "Mozilla/5.0 ..."

# 指定报告目录
python vuln_scanner.py https://example.com/login --out ./my_reports
```

参数：
- `url`：目标登录页 URL
- `--timeout`：请求超时秒数（默认 10）
- `--no-sql` / `--no-xss` / `--no-paths`：跳过对应检测
- `--ua`：自定义 User-Agent
- `--out`：报告输出目录（默认 `reports`）

## 输出

- 终端：彩色摘要，按严重级别排序
- `reports/<host>_<timestamp>.json`：结构化报告
- `reports/<host>_<timestamp>.html`：可视化 HTML 报告（可浏览器打开）
- `reports/<host>_<timestamp>.pdf`：PDF 报告（适合存档与分享，支持中文）

严重级别：`critical`（严重） > `high`（高危） > `medium`（中危） > `low`（低危） > `info`（信息）

## ⚠️ 法律与伦理声明

本工具仅供授权场景使用。对未取得书面授权的目标进行扫描属于违法行为，
使用者须自行承担全部法律责任。扫描结果需结合人工复核确认。

## GUI / EXE 版本

### 图形界面运行

```bash
python gui.py
```

界面功能：URL 输入、检测项勾选（注入 / XSS / 敏感路径 / 弱口令）、超时与 UA 设置、
开始/停止扫描、实时日志、结果表格（按级别着色）、严重级别统计、一键打开 JSON/HTML/PDF 报告。

### 打包为单文件 EXE

```bash
export PYINSTALLER_DISABLE_ISOLATION=1   # Anaconda 环境需禁用隔离子进程
pyinstaller --noconfirm --onefile --windowed --name "VulnScanner" \
    --add-data "C:/Windows/Fonts/simhei.ttf;." gui.py
```

产物：`dist/VulnScanner.exe`（约 30 MB，无需安装 Python 即可运行）。
在 Windows 资源管理器双击即可启动图形界面。
