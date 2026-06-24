"""
gui.py
======
VulnScanner 图形界面（tkinter）。
提供：URL 输入、检测项开关、超时设置、开始/停止、实时日志、
结果表格、严重级别统计、一键打开 JSON/HTML/PDF 报告。

可直接运行（python gui.py），也可由 PyInstaller 打包为 exe。
"""

from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk, messagebox

# 让打包后的 exe 也能找到同目录模块
if getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(sys.executable))

import vuln_scanner  # noqa: E402

APP_TITLE = "VulnScanner 登录网址漏洞扫描工具"
APP_VERSION = "1.3"

SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
SEV_COLOR = {
    "critical": "#7b1fa2", "high": "#c62828", "medium": "#f9a825",
    "low": "#1565c0", "info": "#455a64",
}


class ScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.report = None
        self.last_files = {}  # type: dict[str,str]
        self.cancel_flag = {"stop": False}

        self._build_ui()
        self._refresh_button_state(running=False)

    # -- UI 构建 --------------------------------------------------------

    def _build_ui(self) -> None:
        self.root.title(APP_TITLE)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        # 顶部：目标输入 + 操作
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill="x")

        ttk.Label(top, text="目标登录页 URL：").pack(side="left")
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(top, textvariable=self.url_var)
        url_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        url_entry.bind("<Return>", lambda _e: self.start_scan())

        self.scan_btn = ttk.Button(top, text="▶ 开始扫描", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 4))
        self.stop_btn = ttk.Button(top, text="■ 停止", command=self.stop_scan)
        self.stop_btn.pack(side="left")

        # 选项区
        opts = ttk.LabelFrame(self.root, text="检测项 / 选项", padding=8)
        opts.pack(fill="x", padx=10, pady=(6, 4))

        self.var_sql = tk.BooleanVar(value=True)
        self.var_xss = tk.BooleanVar(value=True)
        self.var_paths = tk.BooleanVar(value=True)
        self.var_creds = tk.BooleanVar(value=True)
        self.var_exploit = tk.BooleanVar(value=False)

        for txt, var in [("SQL/注入", self.var_sql),
                         ("XSS 反射", self.var_xss),
                         ("敏感路径", self.var_paths),
                         ("弱口令", self.var_creds)]:
            ttk.Checkbutton(opts, text=txt, variable=var).pack(side="left", padx=4)

        # 新增注入项
        self.var_ssti = tk.BooleanVar(value=True)
        self.var_ssrf = tk.BooleanVar(value=True)
        self.var_redirect = tk.BooleanVar(value=True)
        self.var_upload = tk.BooleanVar(value=True)
        inj_row = tk.Frame(opts)
        inj_row.pack(side="left", padx=4)
        for txt, var in [("SSTI", self.var_ssti), ("SSRF", self.var_ssrf),
                         ("开放重定向", self.var_redirect), ("文件上传", self.var_upload)]:
            ttk.Checkbutton(inj_row, text=txt, variable=var).pack(side="left", padx=3)

        exploit_frame = tk.Frame(opts)
        exploit_frame.pack(side="left", padx=6)
        self.exploit_cb = tk.Checkbutton(
            exploit_frame, text="⚠ 利用/后台取证",
            variable=self.var_exploit, fg="#c62828",
            activeforeground="#c62828", selectcolor="#fff8e1",
            command=self._on_exploit_toggle)
        self.exploit_cb.pack(side="left")

        ttk.Label(opts, text="超时:").pack(side="left", padx=(10, 2))
        self.timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(opts, from_=3, to=60, width=4,
                    textvariable=self.timeout_var).pack(side="left")

        ttk.Label(opts, text="爬虫深度:").pack(side="left", padx=(8, 2))
        self.crawl_depth_var = tk.IntVar(value=0)
        ttk.Spinbox(opts, from_=0, to=5, width=3,
                    textvariable=self.crawl_depth_var).pack(side="left")
        ttk.Label(opts, text="最大页数:").pack(side="left", padx=(8, 2))
        self.crawl_max_var = tk.IntVar(value=15)
        ttk.Spinbox(opts, from_=1, to=200, width=4,
                    textvariable=self.crawl_max_var).pack(side="left")

        # 认证配置区
        auth = ttk.LabelFrame(self.root, text="认证后扫描（可选）", padding=6)
        auth.pack(fill="x", padx=10, pady=(4, 2))
        ttk.Label(auth, text="登录URL:").pack(side="left")
        self.login_url_var = tk.StringVar()
        ttk.Entry(auth, textvariable=self.login_url_var, width=22).pack(side="left", padx=3)
        ttk.Label(auth, text="账号:").pack(side="left", padx=(4, 0))
        self.login_user_var = tk.StringVar()
        ttk.Entry(auth, textvariable=self.login_user_var, width=12).pack(side="left", padx=3)
        ttk.Label(auth, text="密码:").pack(side="left", padx=(4, 0))
        self.login_pwd_var = tk.StringVar()
        ttk.Entry(auth, textvariable=self.login_pwd_var, width=12, show="*").pack(side="left", padx=3)
        ttk.Label(auth, text="用户字段:").pack(side="left", padx=(6, 0))
        self.login_uf_var = tk.StringVar(value="username")
        ttk.Entry(auth, textvariable=self.login_uf_var, width=9).pack(side="left", padx=3)
        ttk.Label(auth, text="密码字段:").pack(side="left", padx=(4, 0))
        self.login_pf_var = tk.StringVar(value="password")
        ttk.Entry(auth, textvariable=self.login_pf_var, width=9).pack(side="left", padx=3)
        ttk.Label(auth, text="或 Cookie:").pack(side="left", padx=(8, 0))
        self.cookie_var = tk.StringVar()
        ttk.Entry(auth, textvariable=self.cookie_var, width=24).pack(side="left", padx=3)

        # 中部：日志 + 结果（左右分栏）
        body = ttk.PanedWindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=4)

        # 日志区
        log_frame = ttk.LabelFrame(body, text="实时日志", padding=4)
        body.add(log_frame, weight=1)
        self.log_text = tk.Text(log_frame, height=18, wrap="word", state="disabled",
                                bg="#1e1e1e", fg="#d4d4d4", insertbackground="#d4d4d4",
                                font=("Consolas", 9))
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        # 结果区
        result_frame = ttk.LabelFrame(body, text="扫描结果", padding=4)
        body.add(result_frame, weight=2)

        cols = ("sev", "title", "desc", "url")
        self.tree = ttk.Treeview(result_frame, columns=cols, show="headings", height=18)
        self.tree.heading("sev", text="级别")
        self.tree.heading("title", text="问题")
        self.tree.heading("desc", text="描述")
        self.tree.heading("url", text="URL")
        self.tree.column("sev", width=60, anchor="center")
        self.tree.column("title", width=200)
        self.tree.column("desc", width=320)
        self.tree.column("url", width=180)
        tree_scroll = ttk.Scrollbar(result_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        # 标签样式
        self.tree.tag_configure("critical", background="#fbe9f3")
        self.tree.tag_configure("high", background="#ffebee")
        self.tree.tag_configure("medium", background="#fff8e1")
        self.tree.tag_configure("low", background="#e3f2fd")
        self.tree.tag_configure("info", background="#eceff1")

        # 底部：统计 + 报告按钮
        bottom = ttk.Frame(self.root, padding=(10, 6))
        bottom.pack(fill="x")
        self.summary_var = tk.StringVar(value="尚未扫描")
        ttk.Label(bottom, textvariable=self.summary_var,
                  font=("Microsoft YaHei", 10, "bold")).pack(side="left")

        ttk.Button(bottom, text="打开 JSON", command=lambda: self._open("json")).pack(side="right", padx=2)
        ttk.Button(bottom, text="打开 HTML", command=lambda: self._open("html")).pack(side="right", padx=2)
        ttk.Button(bottom, text="打开 PDF", command=lambda: self._open("pdf")).pack(side="right", padx=2)
        ttk.Button(bottom, text="打开报告目录", command=self._open_dir).pack(side="right", padx=2)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.status_var,
                  relief="sunken", anchor="w").pack(fill="x", side="bottom")

        # 提示
        self.log("欢迎使用 VulnScanner。本工具仅用于授权安全测试。\n")
        self.log("输入目标登录页 URL，勾选检测项，点击“开始扫描”。\n\n")

    # -- 日志 -----------------------------------------------------------

    def log(self, msg: str) -> None:
        """线程安全地写入日志。"""
        self.root.after(0, self._append_log, msg)

    def _append_log(self, msg: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + ("" if msg.endswith("\n") else "\n"))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -- 扫描控制 -------------------------------------------------------

    def _refresh_button_state(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.scan_btn.configure(state=state)
        for w in (self.url_var,):  # 仅示意
            pass
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _on_exploit_toggle(self) -> None:
        if self.var_exploit.get():
            ok = messagebox.askyesno(
                "利用取证 - 高风险确认",
                "你即将启用【漏洞利用 / 后台取证】功能。\n\n"
                "该功能在发现可确认漏洞后，会主动提交利用载荷、用已知凭据登录后台"
                "并提取信息（数据库版本/用户表/后台内容等）。\n\n"
                "这属于侵入性操作，仅可对你拥有书面测试授权的目标使用。\n"
                "继续？")
            if not ok:
                self.var_exploit.set(False)

    def start_scan(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("提示", "请输入目标 URL")
            return
        if not url.lower().startswith(("http://", "https://")):
            if messagebox.askyesno("提示", "目标未使用 http(s):// 前缀，是否自动补全为 https://？"):
                url = "https://" + url
                self.url_var.set(url)
            else:
                return

        # 确认授权
        if not messagebox.askyesno(
                "授权确认",
                "确认你已获得对该目标的书面测试授权？\n\n"
                "对未授权目标进行扫描属于违法行为，使用者须自行承担全部法律责任。"):
            return

        # 清空旧结果
        self.tree.delete(*self.tree.get_children())
        self.last_files = {}
        self.cancel_flag["stop"] = False
        self._refresh_button_state(running=True)
        self.status_var.set("扫描中…")

        auth = None
        if self.login_url_var.get().strip() and self.login_user_var.get().strip():
            auth = {
                "login_url": self.login_url_var.get().strip(),
                "user_field": self.login_uf_var.get().strip() or "username",
                "pwd_field": self.login_pf_var.get().strip() or "password",
                "user": self.login_user_var.get().strip(),
                "password": self.login_pwd_var.get(),
            }
        cookie = self.cookie_var.get().strip() or None
        scanner = vuln_scanner.VulnScanner(
            url, timeout=self.timeout_var.get(), ua=self.ua_var.get(),
            do_sql=self.var_sql.get(), do_xss=self.var_xss.get(),
            do_paths=self.var_paths.get(), do_creds=self.var_creds.get(),
            do_exploit=self.var_exploit.get(),
            crawl_depth=self.crawl_depth_var.get(),
            crawl_max_pages=self.crawl_max_var.get(),
            auth=auth, cookie=cookie,
            do_ssti=self.var_ssti.get(), do_ssrf=self.var_ssrf.get(),
            do_redirect=self.var_redirect.get(), do_upload=self.var_upload.get(),
            on_log=self.log, cancel=lambda: self.cancel_flag["stop"],
        )

        def worker():
            self.report = scanner.run()
            self.root.after(0, self._scan_done)

        threading.Thread(target=worker, daemon=True).start()

    def stop_scan(self) -> None:
        self.cancel_flag["stop"] = True
        self.log("[!] 已请求停止，等待当前探测完成…")
        self.status_var.set("正在停止…")

    def _scan_done(self) -> None:
        self._refresh_button_state(running=False)
        if self.report is None:
            self.status_var.set("扫描失败")
            return
        self._render_results(self.report)
        # 保存报告
        try:
            json_p, html_p, pdf_p = vuln_scanner.save_reports(self.report, "reports")
            self.last_files = {"json": json_p, "html": html_p, "pdf": pdf_p}
        except Exception as e:
            messagebox.showerror("报告保存失败", str(e))
        self.status_var.set("扫描完成")

    def _render_results(self, report) -> None:
        for f in report.sorted_findings():
            self.tree.insert("", "end",
                             values=(SEV_LABEL.get(f.severity, f.severity),
                                     f.title, f.description, f.url),
                             tags=(f.severity,))
        s = report.by_severity
        total = sum(s.values())
        exploit_part = ""
        if getattr(report, "exploits", None):
            ok = sum(1 for e in report.exploits if e.success)
            exploit_part = f"    |    利用取证 {len(report.exploits)} 次（成功 {ok}）"
        self.summary_var.set(
            f"合计 {total} 项    "
            f"严重 {s['critical']}   高危 {s['high']}   中危 {s['medium']}   "
            f"低危 {s['low']}   信息 {s['info']}{exploit_part}")
        self.log(f"\n[+] 扫描完成，共 {total} 项发现（严重 {s['critical']} / 高危 {s['high']} / "
                 f"中危 {s['medium']} / 低危 {s['low']} / 信息 {s['info']}）\n")
        if getattr(report, "exploits", None):
            self.log("\n=== 后台取证 / 漏洞利用证据 ===")
            for ev in report.exploits:
                tag = "[成功]" if ev.success else "[未成功]"
                self.log(f"{tag} {ev.technique}  ({ev.target})")
                for k, v in ev.data.items():
                    vstr = ", ".join(v) if isinstance(v, list) else str(v)
                    self.log(f"    - {k}: {vstr[:140]}")
                if ev.excerpt:
                    self.log(f"    摘录: {ev.excerpt[:180]}")
            self.log("")

    # -- 报告打开 -------------------------------------------------------

    def _open(self, kind: str) -> None:
        path = self.last_files.get(kind, "")
        if not path or not os.path.exists(path):
            messagebox.showinfo("提示", f"暂无 {kind.upper()} 报告，请先完成一次扫描。")
            return
        try:
            webbrowser.open("file://" + os.path.abspath(path))
        except Exception as e:
            messagebox.showerror("打开失败", str(e))

    def _open_dir(self) -> None:
        rep = os.path.abspath("reports")
        os.makedirs(rep, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(rep)  # type: ignore[attr-defined]
            else:
                webbrowser.open("file://" + rep)
        except Exception as e:
            messagebox.showerror("打开失败", str(e))


def main() -> int:
    root = tk.Tk()
    # 主题
    try:
        style = ttk.Style()
        style.theme_use("clam")
    except Exception:
        pass
    ScannerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
