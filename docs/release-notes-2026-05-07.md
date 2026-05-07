# Release Notes - 2026-05-07

## 发布范围

本次版本完成了针对当前 Web 扫描项目的一轮安全加固、扫描准确性收紧、结果结构增强和前端结果展示补强。

## 主要更新

### 1. 服务端安全加固

- 限制 `/api/scan` 只接受公网 `http/https` 目标，阻断常见 SSRF 目标。
- 增加单客户端扫描冷却时间。
- 增加单次扫描的外部请求预算。
- 限制响应体读取大小，降低被滥用和资源耗尽风险。
- Flask 默认仅绑定 `127.0.0.1`，并通过环境变量控制 `host/port/debug`。

### 2. 扫描结果结构增强

- 保持原有 `results[module] = [...]` 结构兼容。
- 增加 `scan_metadata`：
  - `started_at`
  - `finished_at`
  - `duration_ms`
  - `request_budget_limit`
  - `request_budget_exhausted`
  - `modules_run`
  - `modules_skipped`
- 增加结果标准化层，兼容保留：
  - `type`
  - `title`
  - `detail`
- 新增可选字段：
  - `severity`
  - `status`
  - `confidence`
  - `evidence`
  - `remediation`
  - `module`

### 3. 扫描准确性收紧

#### XSS

- 不再把普通字符串反射直接打成高危。
- 高危判定要求 payload 落入可执行上下文。
- 为命中结果补充 evidence / remediation。

#### SQLi

- GET 与表单两条路径都采用基线响应对比。
- 去掉弱泛化特征，改为更偏数据库特征的错误信号。
- 为高危命中补充 evidence / remediation。

#### Open Redirect

- 改为按最终目标 origin 判断是否真正外跳。
- 不再因为路径或参数里出现 `evil.com` 字样就误报高危。

#### Sensitive Files / Traversal

- 敏感文件检测增加更具体的内容指纹。
- HTML fallback / 统一 200 页面不再轻易算真实命中。
- 二进制高价值目标补充了更具体的标志：
  - ZIP：`PK` 系列魔数
  - `.DS_Store`：`Bud1` / `DSDB`
  - `.hg/dirstate`：二进制样式内容约束

#### Security Headers

- 统一缺失头的严重度口径。
- `X-XSS-Protection` 降为信息或低风险，不再抬高风险级别。
- HSTS 仅在 HTTPS 目标下评估。
- HTTP 到 HTTPS 的判断改为看 HTTP 首跳是否正确重定向，而不是要求 HTTPS 页面本身必须成功返回。

### 4. 前端展示增强

- 增量支持结果展示：
  - `confidence`
  - `status`
  - `evidence`
  - `remediation`
  - `scan_metadata`
- 保持原页面结构和模块结果折叠方式不变。
- 修复了可见文本拼接中的一个潜在 DOM XSS sink。

## 验证结果

### 自动化验证

- 全量单元测试：`55` 项通过
- Python 编译检查：`19` 个文件通过

### 运行验证

- 服务实例启动正常
- 首页可访问
- `/api/scan` 可返回增强后的结构
- 使用 Edge 完成了一次真实浏览器 smoke check

截图产物：

- [edge-smoke-2026-05-07.png](/C:/Users/hongke/OneDrive/Desktop/测试/web-scan-main/web-scan-main/output/playwright/edge-smoke-2026-05-07.png)

## 打包与推送

- 当前发布包：
  - [web-scan-main-release.zip](/C:/Users/hongke/OneDrive/Desktop/测试/web-scan-main/web-scan-main-release.zip)
- 已推送远端仓库：
  - [3436567162/web-scan](https://github.com/3436567162/web-scan)
- 推送提交：
  - `ea8f999 feat: harden scanner accuracy and reporting`

## 已清理项

- 本地临时目录 `deploy-web-scan` 已删除
- 本地测试服务 `5001` / `5002` 已停止
