"""
gui.py — VulnScanner 图形界面（MinerU 风格：暗色侧栏 + 卡片式主区 + 主题化控件）。

依赖：ttkbootstrap（现代主题；缺失时自动回退到标准 ttk）。
"""

from __future__ import annotations

import os
import sys
import threading
import webbrowser

if getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(sys.executable))

import tkinter as tk
from tkinter import messagebox

import ttkbootstrap as ttk
HAVE_TTB = True

import vuln_scanner  # noqa: E402

APP_TITLE = "VulnScanner"
APP_SUBTITLE = "登录网址漏洞扫描"
APP_VERSION = "1.4"

SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}

# 品牌色
SIDEBAR_BG = "#0e2a47"
SIDEBAR_FG = "#ffffff"
ACCENT = "#2f6fed"


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.report = None
        self.last_files = {}
        self.cancel_flag = {"stop": False}
        self.anim_running = False
        self._dot_phase = 0
        self._txt_phase = 0
        self.live_sev = {k: 0 for k in SEV_LABEL}
        self._build_ui()
        self._refresh_button_state(running=False)

    # -- 主题 ----------------------------------------------------------
    @staticmethod
    def _make_root():
        return ttk.Window(themename="litera", title=f"{APP_TITLE} · {APP_SUBTITLE}",
                          size=(1180, 760), minsize=(960, 620))

    # -- UI 构建 --------------------------------------------------------
    def _build_ui(self):
        # —— 顶部品牌栏（浅色，MinerU 风格）——
        header = tk.Frame(self.root, bg="#ffffff", height=58)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Frame(header, bg="#e3e8ef", height=1).pack(side="bottom", fill="x")
        tk.Label(header, bg="#ffffff", fg=ACCENT, text="◢ VulnScanner",
                 font=("Microsoft YaHei", 14, "bold")).pack(side="left", padx=18)
        tk.Label(header, bg="#ffffff", fg="#6b7280", text=APP_SUBTITLE,
                 font=("Microsoft YaHei", 9)).pack(side="left", pady=(0, 0))

        # 右侧：状态灯 + 状态文字 + 概览
        right = tk.Frame(header, bg="#ffffff")
        right.pack(side="right", padx=18)
        self.summary_var = tk.StringVar(value="尚未扫描")
        tk.Label(right, bg="#ffffff", fg="#374151", textvariable=self.summary_var,
                 font=("Microsoft YaHei", 9)).pack(side="right", padx=(14, 0))
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(right, bg="#ffffff", fg="#374151", textvariable=self.status_var,
                 font=("Microsoft YaHei", 9)).pack(side="right")
        self.dot_canvas = tk.Canvas(right, bg="#ffffff", width=12, height=12,
                                    highlightthickness=0)
        self.dot_canvas.pack(side="right", padx=(0, 6))
        self.dot_id = self.dot_canvas.create_oval(2, 2, 10, 10, fill="#3ddc84", outline="")

        # 主区
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=16, pady=(12, 14))

        # 底部报告按钮（先 pack 到底，避免被 body 挤掉）
        footer = ttk.Frame(main)
        footer.pack(side="bottom", fill="x", pady=(8, 0))
        ttk.Button(footer, text="打开 JSON", bootstyle="secondary" if HAVE_TTB else None,
                   command=lambda: self._open("json")).pack(side="right", padx=3)
        ttk.Button(footer, text="打开 HTML", bootstyle="secondary" if HAVE_TTB else None,
                   command=lambda: self._open("html")).pack(side="right", padx=3)
        ttk.Button(footer, text="打开 PDF", bootstyle="secondary" if HAVE_TTB else None,
                   command=lambda: self._open("pdf")).pack(side="right", padx=3)
        ttk.Button(footer, text="报告目录", bootstyle="secondary" if HAVE_TTB else None,
                   command=self._open_dir).pack(side="right", padx=3)

        # 进度条（扫描中不确定模式动画）
        self.progress = ttk.Progressbar(main, mode="indeterminate",
                                        bootstyle="primary" if HAVE_TTB else None)
        self.progress.pack(fill="x", pady=(0, 10))
        self.progress.stop()

        # 主体：左配置栏 + 右结果区
        body = ttk.Panedwindow(main, orient="horizontal", bootstyle="primary" if HAVE_TTB else None)
        body.pack(fill="both", expand=True)
        config_frame = ttk.Frame(body, width=400)
        body.add(config_frame, weight=0)
        config_frame.pack_propagate(False)
        work_frame = ttk.Frame(body)
        body.add(work_frame, weight=1)
        self.body = body

        # —— 卡片1：扫描目标（居中主卡）——
        hero = ttk.LabelFrame(config_frame, text="  扫描目标  ")
        hero.pack(fill="x")
        row = ttk.Frame(hero)
        row.pack(fill="x", padx=12, pady=12)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(row, textvariable=self.url_var)
        url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        url_entry.bind("<Return>", lambda _e: self.start_scan())
        self.scan_btn = ttk.Button(row, text="开始扫描", bootstyle="primary" if HAVE_TTB else None,
                                   command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(row, text="停止", bootstyle="danger" if HAVE_TTB else None,
                                   command=self.stop_scan)
        self.stop_btn.pack(side="left")

        # —— 卡片2：检测项与设置 ——
        opts = ttk.LabelFrame(config_frame, text="  检测项与设置  ")
        opts.pack(fill="x", pady=(10, 0))

        self.var_sql = tk.BooleanVar(value=True)
        self.var_xss = tk.BooleanVar(value=True)
        self.var_ssti = tk.BooleanVar(value=True)
        self.var_ssrf = tk.BooleanVar(value=True)
        self.var_redirect = tk.BooleanVar(value=True)
        self.var_upload = tk.BooleanVar(value=True)
        self.var_paths = tk.BooleanVar(value=True)
        self.var_creds = tk.BooleanVar(value=True)
        checks = [("SQL 注入", self.var_sql), ("XSS 反射", self.var_xss),
                  ("SSTI", self.var_ssti), ("SSRF", self.var_ssrf),
                  ("开放重定向", self.var_redirect), ("文件上传", self.var_upload),
                  ("敏感路径", self.var_paths), ("弱口令", self.var_creds)]
        grid = ttk.Frame(opts)
        grid.pack(fill="x", padx=12, pady=(10, 0))
        for i, (txt, var) in enumerate(checks):
            r, c = divmod(i, 2)
            ttk.Checkbutton(grid, text=txt, variable=var).grid(row=r, column=c, sticky="w", padx=6, pady=3)

        setrow = ttk.Frame(opts)
        setrow.pack(fill="x", padx=12, pady=(8, 4))
        ttk.Label(setrow, text="超时").pack(side="left")
        self.timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(setrow, from_=3, to=60, width=4, textvariable=self.timeout_var).pack(side="left", padx=(4, 12))
        ttk.Label(setrow, text="深度").pack(side="left")
        self.crawl_depth_var = tk.IntVar(value=0)
        ttk.Spinbox(setrow, from_=0, to=5, width=3, textvariable=self.crawl_depth_var).pack(side="left", padx=(4, 12))
        ttk.Label(setrow, text="页数").pack(side="left")
        self.crawl_max_var = tk.IntVar(value=15)
        ttk.Spinbox(setrow, from_=1, to=200, width=4, textvariable=self.crawl_max_var).pack(side="left", padx=(4, 12))
        self.var_exploit = tk.BooleanVar(value=False)
        ttk.Checkbutton(setrow, text="⚠ 利用取证", variable=self.var_exploit,
                        command=self._on_exploit_toggle).pack(side="left", padx=(4, 0))
        uarow = ttk.Frame(opts)
        uarow.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Label(uarow, text="UA").pack(side="left")
        self.ua_var = tk.StringVar(value=vuln_scanner.DEFAULT_UA)
        ttk.Entry(uarow, textvariable=self.ua_var).pack(side="left", fill="x", expand=True, padx=(6, 0))

        # —— 卡片3：认证后扫描（两行排布，避免拥挤）——
        auth = ttk.LabelFrame(config_frame, text="  认证后扫描（可选）  ")
        auth.pack(fill="x", pady=(10, 0))
        ar1 = ttk.Frame(auth); ar1.pack(fill="x", padx=12, pady=(10, 4))
        ttk.Label(ar1, text="登录URL").pack(side="left")
        self.login_url_var = tk.StringVar()
        ttk.Entry(ar1, textvariable=self.login_url_var).pack(side="left", fill="x", expand=True, padx=(6, 14))
        ttk.Label(ar1, text="账号").pack(side="left")
        self.login_user_var = tk.StringVar()
        ttk.Entry(ar1, textvariable=self.login_user_var, width=14).pack(side="left", padx=(6, 14))
        ttk.Label(ar1, text="密码").pack(side="left")
        self.login_pwd_var = tk.StringVar()
        ttk.Entry(ar1, textvariable=self.login_pwd_var, width=14, show="*").pack(side="left", padx=(6, 12))
        ar2 = ttk.Frame(auth); ar2.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Label(ar2, text="用户字段").pack(side="left")
        self.login_uf_var = tk.StringVar(value="username")
        ttk.Entry(ar2, textvariable=self.login_uf_var, width=12).pack(side="left", padx=(6, 14))
        ttk.Label(ar2, text="密码字段").pack(side="left")
        self.login_pf_var = tk.StringVar(value="password")
        ttk.Entry(ar2, textvariable=self.login_pf_var, width=12).pack(side="left", padx=(6, 14))
        ttk.Label(ar2, text="或 Cookie").pack(side="left", padx=(6, 2))
        self.cookie_var = tk.StringVar()
        ttk.Entry(ar2, textvariable=self.cookie_var).pack(side="left", fill="x", expand=True, padx=(6, 0))

        # —— 结果区：上下双栏（日志 / 结果），各占全宽 ——
        paned = ttk.Panedwindow(work_frame, orient="vertical", bootstyle="primary" if HAVE_TTB else None)
        paned.pack(fill="both", expand=True, pady=(0, 6))

        log_frame = ttk.Frame(paned)
        paned.add(log_frame, weight=1)
        ttk.Label(log_frame, text="实时日志", bootstyle="secondary" if HAVE_TTB else None).pack(anchor="w")
        self.log_text = tk.Text(log_frame, wrap="word", state="disabled",
                                bg="#11171f", fg="#d6deeb", insertbackground="#d6deeb",
                                font=("Consolas", 9), padx=10, pady=8, borderwidth=0)
        log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

        result_frame = ttk.Frame(paned)
        paned.add(result_frame, weight=2)
        ttk.Label(result_frame, text="结果列表", bootstyle="secondary" if HAVE_TTB else None).pack(anchor="w")
        cols = ("sev", "title", "desc", "url")
        self.tree = ttk.Treeview(result_frame, columns=cols, show="headings", bootstyle="primary" if HAVE_TTB else None)
        self.tree.heading("sev", text="级别")
        self.tree.heading("title", text="问题")
        self.tree.heading("desc", text="描述")
        self.tree.heading("url", text="URL")
        self.tree.column("sev", width=56, anchor="center")
        self.tree.column("title", width=180)
        self.tree.column("desc", width=300)
        self.tree.column("url", width=180)
        ts = ttk.Scrollbar(result_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=ts.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ts.pack(side="right", fill="y")
        for tag, bg in [("critical", "#fbe9f3"), ("high", "#ffebee"),
                        ("medium", "#fff8e1"), ("low", "#e3f2fd"), ("info", "#eceff1")]:
            self.tree.tag_configure(tag, background=bg)
        self.paned = paned

        self.log("欢迎使用 VulnScanner。本工具仅用于授权安全测试。\n输入目标 URL，配置检测项，点击「开始扫描」。\n\n")

    # -- 日志 ----------------------------------------------------------
    def log(self, msg):
        self.root.after(0, self._append_log, msg)

    def _append_log(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + ("" if msg.endswith("\n") else "\n"))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -- 控制 ----------------------------------------------------------
    def _refresh_button_state(self, running):
        self.scan_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        if not running:
            self.status_var.set("就绪" if self.report is None else "完成")

    # -- 动态效果 ------------------------------------------------------
    DOT_RUN = ["#2f6fed", "#7aa6f5", "#c9d8fb"]

    def _anim_start(self):
        self.anim_running = True
        self._dot_phase = 0
        self._txt_phase = 0
        try:
            self.progress.start(12)
        except Exception:
            pass
        self._pulse_dot()
        self._anim_status()

    def _anim_stop(self):
        self.anim_running = False
        try:
            self.progress.stop()
        except Exception:
            pass
        self.dot_canvas.itemconfig(self.dot_id, fill="#3ddc84")

    def _pulse_dot(self):
        if not self.anim_running:
            return
        c = self.DOT_RUN[self._dot_phase % len(self.DOT_RUN)]
        self.dot_canvas.itemconfig(self.dot_id, fill=c)
        self._dot_phase += 1
        self.root.after(300, self._pulse_dot)

    def _anim_status(self):
        if not self.anim_running:
            return
        dots = "." * (self._txt_phase % 4)
        self.status_var.set(f"扫描中{dots}")
        self._txt_phase += 1
        self.root.after(400, self._anim_status)

    def _on_finding_thread(self, finding):
        """扫描器工作线程回调 → 转到 UI 线程实时插入。"""
        self.root.after(0, lambda f=finding: self._live_finding(f))

    def _live_finding(self, finding):
        """发现一条即实时插入结果表 + 更新侧栏计数。"""
        self.tree.insert("", "end",
                         values=(SEV_LABEL.get(finding.severity, finding.severity),
                                 finding.title, finding.description, finding.url),
                         tags=(finding.severity,))
        self.live_sev[finding.severity] = self.live_sev.get(finding.severity, 0) + 1
        total = sum(self.live_sev.values())
        s = self.live_sev
        self.summary_var.set(
            f"实时发现 {total} · 严重{s.get('critical',0)} 高危{s.get('high',0)} "
            f"中危{s.get('medium',0)} 低危{s.get('low',0)} 信息{s.get('info',0)}")

    def _on_exploit_toggle(self):
        if self.var_exploit.get():
            ok = messagebox.askyesno(
                "利用取证 - 高风险确认",
                "你将启用【漏洞利用 / 后台取证】。该功能在发现可确认漏洞后会主动提交利用载荷、"
                "用已知凭据登录后台并提取信息（数据库版本/用户表/后台内容等）。\n\n"
                "这属于侵入性操作，仅可对你拥有书面测试授权的目标使用。\n继续？")
            if not ok:
                self.var_exploit.set(False)

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("提示", "请输入目标 URL")
            return
        if not url.lower().startswith(("http://", "https://")):
            if messagebox.askyesno("提示", "目标未使用 http(s):// 前缀，是否自动补全 https://？"):
                url = "https://" + url
                self.url_var.set(url)
            else:
                return
        if not messagebox.askyesno("授权确认",
                                   "确认你已获得对该目标的书面测试授权？\n对未授权目标扫描属违法行为。"):
            return

        self.tree.delete(*self.tree.get_children())
        self.last_files = {}
        self.live_sev = {k: 0 for k in SEV_LABEL}
        self.cancel_flag["stop"] = False
        self._refresh_button_state(running=True)
        self.summary_var.set("扫描进行中…")
        self._anim_start()

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
            crawl_depth=self.crawl_depth_var.get(), crawl_max_pages=self.crawl_max_var.get(),
            auth=auth, cookie=cookie,
            do_ssti=self.var_ssti.get(), do_ssrf=self.var_ssrf.get(),
            do_redirect=self.var_redirect.get(), do_upload=self.var_upload.get(),
            on_log=self.log, on_finding=self._on_finding_thread,
            cancel=lambda: self.cancel_flag["stop"],
        )

        def worker():
            self.report = scanner.run()
            self.root.after(0, self._scan_done)

        threading.Thread(target=worker, daemon=True).start()

    def stop_scan(self):
        self.cancel_flag["stop"] = True
        self.log("[!] 已请求停止，等待当前探测完成…")
        self.status_var.set("正在停止…")

    def _scan_done(self):
        self._anim_stop()
        self._refresh_button_state(running=False)
        if self.report is None:
            self.status_var.set("扫描失败")
            return
        self._finalize(self.report)
        try:
            json_p, html_p, pdf_p = vuln_scanner.save_reports(self.report, "reports")
            self.last_files = {"json": json_p, "html": html_p, "pdf": pdf_p}
        except Exception as e:
            messagebox.showerror("报告保存失败", str(e))
        self.status_var.set("扫描完成")
        # 双栏并排，日志与结果均可见，无需切页

    def _finalize(self, report):
        """扫描结束：用权威计数更新侧栏（结果表已实时填充，不重复插入）。"""
        s = report.by_severity
        total = sum(s.values())
        exploit_part = ""
        if getattr(report, "exploits", None):
            ok = sum(1 for e in report.exploits if e.success)
            exploit_part = f"｜利用取证 {len(report.exploits)}(成功 {ok})"
        self.summary_var.set(
            f"合计 {total} · 严重{s['critical']} 高危{s['high']} "
            f"中危{s['medium']} 低危{s['low']} 信息{s['info']}{exploit_part}")
        self.log(f"\n[+] 扫描完成，共 {total} 项发现。\n")

    # -- 报告 ----------------------------------------------------------
    def _open(self, kind):
        path = self.last_files.get(kind, "")
        if not path or not os.path.exists(path):
            messagebox.showinfo("提示", f"暂无 {kind.upper()} 报告，请先完成一次扫描。")
            return
        try:
            webbrowser.open("file://" + os.path.abspath(path))
        except Exception as e:
            messagebox.showerror("打开失败", str(e))

    def _open_dir(self):
        rep = os.path.abspath("reports")
        os.makedirs(rep, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(rep)  # type: ignore[attr-defined]
            else:
                webbrowser.open("file://" + rep)
        except Exception as e:
            messagebox.showerror("打开失败", str(e))


def main():
    root = ScannerApp._make_root()
    ScannerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
