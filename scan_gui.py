# -*- coding: utf-8 -*-
"""服务器综合漏洞扫描器 · 图形界面入口（无 cmd 黑窗口）。

双击 ``漏洞扫描器.exe`` 直接打开本窗口（PyInstaller ``--windowed``）：

* 填写目标 → 「开始扫描」，后台线程执行，日志与风险统计实时刷新
* 每次扫描自动归档到 ``reports/history.json`` 并刷新 ``reports/index.html``
* 中部「报告详情」标签页在应用内渲染报告（格式化视图 / JSON 原文），不跳外部浏览器
* 双击历史记录、或扫描完成自动切换，即可在窗口内查看当次完整报告详情
* 历史索引 / 最近报告也在窗口内查看；「在浏览器中打开」只是可选备用

源码运行：``python scan_gui.py``（或 pythonw，完全无控制台）。
可选命令行参数：``--target 1.2.3.4`` 预填目标，``--scan`` 启动后自动开始扫描。
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import traceback
from typing import Any, Dict, List, Optional, Sequence

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:  # pragma: no cover - 极端环境下给出可诊断提示
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]

from scanner import guitask, history, reportview, utils
from scanner.models import ScanReport
from scanner.utils import default_reports_dir

APP_TITLE = "服务器综合漏洞扫描器 v1.2 · 图形界面"
FONT = ("Microsoft YaHei", 9)
FONT_BOLD = ("Microsoft YaHei", 10, "bold")
FONT_TITLE = ("Microsoft YaHei", 15, "bold")
MONO = ("Consolas", 9)

SEVERITIES = (
    ("critical", "严重", "#b91c1c"),
    ("high", "高危", "#ea580c"),
    ("medium", "中危", "#ca8a04"),
    ("low", "低危", "#2563eb"),
    ("info", "信息", "#64748b"),
)

HISTORY_COLUMNS = (
    ("time", "扫描时间", 145),
    ("target", "目标", 150),
    ("ip", "IP", 115),
    ("critical", "严重", 52),
    ("high", "高危", 52),
    ("medium", "中危", 52),
    ("low", "低危", 52),
    ("info", "信息", 52),
    ("total", "合计", 55),
    ("duration", "耗时", 65),
    ("report", "报告文件", 240),
)

STACK_CHOICES = ("all", "java", "go", "cpp", "python", "nginx", "openresty", "nodejs",
                 "php", "dotnet", "java,nodejs", "nginx,openresty", "php,dotnet",
                 "php,nodejs", "java,php,dotnet")
PORT_CHOICES = ("all", "base", "mail", "database", "ai", "media", "ecommerce")


def _enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass


def _fatal(message: str) -> None:
    """tkinter 不可用时（windowed 无 stdout）仍能告知用户原因。"""
    try:
        out_dir = default_reports_dir()
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "gui_error.txt"), "w", encoding="utf-8") as fh:
            fh.write(message)
    except Exception:  # noqa: BLE001
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
                0, message, "漏洞扫描器启动失败", 0x10)
        except Exception:  # noqa: BLE001
            pass


def _split_extra(text: str) -> List[str]:
    """把「高级参数」按空白切分，保留引号内的空格与 Windows 反斜杠。"""
    parts = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', text.strip())
    return [p.strip("\"'") for p in parts if p.strip("\"'")]


class ScannerApp:
    """主窗口。所有扫描在工作线程执行，通过队列把事件送回 Tk 主线程。"""

    def __init__(self, root: "tk.Tk", events: "queue.Queue", target: str = "",
                 autostart: bool = False):
        self.root = root
        self.events = events
        self.out_dir = default_reports_dir()
        self._records: List[Dict[str, Any]] = []
        self._totals = {key: 0 for key, _, _ in SEVERITIES}
        self._last_html = ""
        self._current_html = ""
        self._current_json = ""
        self._worker: Optional[threading.Thread] = None
        self.cancel = threading.Event()

        self.root.title(APP_TITLE)
        self.root.geometry("1120x860")
        self.root.minsize(960, 700)
        try:
            ttk.Style().theme_use("vista")
        except Exception:  # noqa: BLE001
            pass
        self.root.columnconfigure(0, weight=1)
        for row, weight in ((3, 3), (4, 2)):
            self.root.rowconfigure(row, weight=weight)

        self._init_vars()
        self._build_header()
        self._build_form()
        self._build_status()
        self._build_log()
        self._build_history()
        self._build_footer()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Return>", lambda _event: self._start_scan())
        if target:
            self.target_var.set(target)
            self.target_entry.focus_set()
        self._refresh_history()
        self._append_log("就绪。输入 IP / 域名后点击「开始扫描」，或双击下方历史记录在「报告详情」中查看报告。")
        self._append_log(f"报告与历史记录目录：{self.out_dir}")
        self._poll()
        if autostart and target:
            self.root.after(300, self._start_scan)

    # ------------------------------------------------------------------ #
    # 界面构建
    # ------------------------------------------------------------------ #
    def _init_vars(self) -> None:
        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar()
        self.threads_var = tk.StringVar(value="200")
        self.stack_var = tk.StringVar(value="all")
        self.port_cat_var = tk.StringVar(value="all")
        self.extra_var = tk.StringVar()
        self.processes_var = tk.StringVar(value="0")
        self.async_var = tk.StringVar(value="64")
        self.mp_var = tk.BooleanVar(value=True)
        self.coro_var = tk.BooleanVar(value=True)
        self.skip_web_var = tk.BooleanVar(value=False)
        self.shallow_var = tk.BooleanVar(value=False)
        self.local_audit_var = tk.BooleanVar(value=False)
        self.auto_open_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="就绪 · 等待扫描")
        self.count_var = tk.StringVar(value="")
        self.report_title_var = tk.StringVar(value="尚未选择报告")
        self.view_var = tk.StringVar(value="格式化视图")
        self.summary_labels: Dict[str, "tk.Label"] = {}
        self.total_label: Optional["tk.Label"] = None

    def _build_header(self) -> None:
        frame = ttk.Frame(self.root, padding=(14, 10, 14, 4))
        frame.grid(row=0, column=0, sticky="ew")
        ttk.Label(frame, text="服务器综合漏洞扫描器", font=FONT_TITLE,
                  foreground="#1e3a8a").pack(side="left")
        ttk.Label(frame,
                  text="端口 / 服务 / Web / 系统 / PHP2Shell / Java·Go·C++·Python·Nginx·OpenResty·Node.js·PHP·.NET",
                  font=FONT, foreground="#64748b").pack(side="left", padx=(12, 0))
        ttk.Label(frame, text="仅限自有或已获书面授权的资产", font=FONT,
                  foreground="#b91c1c").pack(side="right")

    def _build_form(self) -> None:
        box = ttk.LabelFrame(self.root, text=" 扫描设置 ", padding=(12, 8, 12, 10))
        box.grid(row=1, column=0, sticky="ew", padx=14, pady=4)
        box.columnconfigure(1, weight=1)
        box.columnconfigure(3, weight=1)

        ttk.Label(box, text="扫描目标：", font=FONT_BOLD).grid(row=0, column=0, sticky="w", pady=4)
        self.target_entry = ttk.Entry(box, textvariable=self.target_var, font=FONT)
        self.target_entry.grid(row=0, column=1, columnspan=3, sticky="ew", pady=4)
        ttk.Label(box, text="IP / 域名 / URL，多个用空格或逗号分隔", font=FONT,
                  foreground="#94a3b8").grid(row=0, column=4, sticky="w", padx=(8, 0))

        self.start_btn = ttk.Button(box, text="开始扫描", command=self._start_scan)
        self.start_btn.grid(row=0, column=5, sticky="ew", padx=(10, 0), ipadx=12, ipady=3)
        self.stop_btn = ttk.Button(box, text="停止", command=self._stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=6, sticky="ew", padx=(6, 0), ipadx=12, ipady=3)

        ttk.Label(box, text="端口范围：", font=FONT).grid(row=1, column=0, sticky="w", pady=3)
        ttk.Entry(box, textvariable=self.ports_var, font=FONT).grid(
            row=1, column=1, sticky="ew", pady=3)
        ttk.Label(box, text="并发数：", font=FONT).grid(row=1, column=2, sticky="e", padx=(12, 4))
        ttk.Entry(box, textvariable=self.threads_var, font=FONT, width=8).grid(
            row=1, column=3, sticky="w", pady=3)
        ttk.Label(box, text="留空 = 内置 227 个端口", font=FONT,
                  foreground="#94a3b8").grid(row=1, column=4, columnspan=3, sticky="w", padx=(8, 0))

        ttk.Label(box, text="技术栈：", font=FONT).grid(row=2, column=0, sticky="w", pady=3)
        ttk.Combobox(box, textvariable=self.stack_var, values=STACK_CHOICES,
                     font=FONT, width=20).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Label(box, text="端口类别：", font=FONT).grid(row=2, column=2, sticky="e", padx=(12, 4))
        ttk.Combobox(box, textvariable=self.port_cat_var, values=PORT_CHOICES,
                     font=FONT, width=16).grid(row=2, column=3, sticky="w", pady=3)
        ttk.Label(box, text="可手动输入逗号组合，如 java,nodejs", font=FONT,
                  foreground="#94a3b8").grid(row=2, column=4, columnspan=3, sticky="w", padx=(8, 0))

        opts = ttk.Frame(box)
        opts.grid(row=3, column=0, columnspan=7, sticky="w", pady=(6, 0))
        ttk.Checkbutton(opts, text="跳过 Web 扫描", variable=self.skip_web_var).pack(side="left")
        ttk.Checkbutton(opts, text="浅速扫描（不做深度路径探测）",
                        variable=self.shallow_var).pack(side="left", padx=(14, 0))
        ttk.Checkbutton(opts, text="附加本机系统审计",
                        variable=self.local_audit_var).pack(side="left", padx=(14, 0))
        ttk.Checkbutton(opts, text="完成后自动在窗口内查看报告",
                        variable=self.auto_open_var).pack(side="left", padx=(14, 0))

        conc = ttk.Frame(box)
        conc.grid(row=4, column=0, columnspan=7, sticky="w", pady=(5, 0))
        ttk.Label(conc, text="并发模型：", font=FONT_BOLD).pack(side="left")
        ttk.Label(conc, text="进程(0=自动)", font=FONT).pack(side="left")
        ttk.Entry(conc, textvariable=self.processes_var, width=6, font=FONT).pack(
            side="left", padx=(4, 10))
        ttk.Label(conc, text="协程并发", font=FONT).pack(side="left")
        ttk.Entry(conc, textvariable=self.async_var, width=6, font=FONT).pack(
            side="left", padx=(4, 10))
        ttk.Checkbutton(conc, text="启用多进程", variable=self.mp_var).pack(side="left")
        ttk.Checkbutton(conc, text="启用协程", variable=self.coro_var).pack(side="left", padx=(10, 0))
        ttk.Label(conc, text="多线程由上方「并发数」控制", font=FONT,
                  foreground="#94a3b8").pack(side="left", padx=(10, 0))

        ttk.Label(box, text="高级参数：", font=FONT).grid(row=5, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(box, textvariable=self.extra_var, font=FONT).grid(
            row=5, column=1, columnspan=6, sticky="ew", pady=(6, 0))
        ttk.Label(box, text="与命令行一致，例如：--stack-categories nodejs --web-timeout 3 "
                            "--jar-dirs \"C:\\opt;C:\\apps\"",
                  font=FONT, foreground="#94a3b8").grid(
            row=6, column=1, columnspan=6, sticky="w")

    def _build_status(self) -> None:
        outer = ttk.Frame(self.root)
        outer.grid(row=2, column=0, sticky="ew", padx=14, pady=4)
        box = ttk.Frame(outer, padding=(0, 6, 8, 4))
        box.pack(side="left")
        ttk.Label(box, text="状态：", font=FONT_BOLD).pack(side="left")
        ttk.Label(box, textvariable=self.status_var, font=FONT,
                  foreground="#1d4ed8").pack(side="left")
        self.progress = ttk.Progressbar(box, mode="indeterminate", length=170)
        self.progress.pack(side="left", padx=(12, 0))

        summary = ttk.LabelFrame(outer, text=" 本次结果 ", padding=(12, 6, 12, 8))
        summary.pack(side="right")
        for key, label, color in SEVERITIES:
            cell = ttk.Frame(summary)
            cell.pack(side="left", padx=(10, 0))
            ttk.Label(cell, text=label, font=FONT, foreground=color).pack()
            value = tk.Label(cell, text="0", font=("Microsoft YaHei", 12, "bold"), fg=color)
            value.pack()
            self.summary_labels[key] = value
        cell = ttk.Frame(summary)
        cell.pack(side="left", padx=(10, 0))
        ttk.Label(cell, text="合计", font=FONT, foreground="#0f172a").pack()
        self.total_label = tk.Label(cell, text="0", font=("Microsoft YaHei", 12, "bold"),
                                    fg="#0f172a")
        self.total_label.pack()

    def _build_log(self) -> None:
        """中部笔记本：扫描日志 + 应用内报告详情（不再跳外部浏览器）。"""
        notebook = ttk.Notebook(self.root)
        notebook.grid(row=3, column=0, sticky="nsew", padx=14, pady=4)
        self.notebook = notebook
        log_tab = ttk.Frame(notebook)
        notebook.add(log_tab, text=" 扫描日志 ")
        self._build_log_tab(log_tab)
        self.report_tab = ttk.Frame(notebook)
        notebook.add(self.report_tab, text=" 报告详情（窗口内查看） ")
        self._build_report_tab(self.report_tab)

    def _build_log_tab(self, box) -> None:
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.log_text = tk.Text(box, wrap="none", font=MONO, height=14,
                               bg="#0f172a", fg="#e2e8f0", insertbackground="#e2e8f0",
                               relief="flat", padx=8, pady=6)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(box, orient="vertical", command=self.log_text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(box, orient="horizontal", command=self.log_text.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.log_text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set,
                                state="disabled")
        bar = ttk.Frame(box)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Button(bar, text="清空日志", command=self._clear_log).pack(side="right")
        ttk.Label(bar, text="日志与报告同时写入 reports/ 目录", font=FONT,
                  foreground="#94a3b8").pack(side="left")

    def _build_report_tab(self, tab) -> None:
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        bar = ttk.Frame(tab, padding=(8, 6, 8, 4))
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Label(bar, textvariable=self.report_title_var, font=FONT_BOLD,
                  foreground="#1e3a8a").pack(side="left")
        ttk.Button(bar, text="在浏览器中打开", command=self._open_current_in_browser).pack(
            side="right", padx=(6, 0))
        view = ttk.Combobox(bar, textvariable=self.view_var,
                            values=("格式化视图", "JSON 原文"), state="readonly",
                            width=12, font=FONT)
        view.pack(side="right", padx=(6, 0))
        view.bind("<<ComboboxSelected>>", lambda _event: self._render_report())
        ttk.Label(bar, text="视图：", font=FONT).pack(side="right")

        self.report_text = tk.Text(tab, wrap="word", font=FONT, bg="#ffffff", fg="#0f172a",
                                   relief="flat", padx=16, pady=12, spacing1=1)
        self.report_text.grid(row=1, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(tab, orient="vertical", command=self.report_text.yview)
        yscroll.grid(row=1, column=1, sticky="ns")
        self.report_text.configure(yscrollcommand=yscroll.set, state="disabled")
        self._configure_report_tags()
        self._render_report()

    def _configure_report_tags(self) -> None:
        text = self.report_text
        text.tag_configure("h1", font=("Microsoft YaHei", 14, "bold"),
                           foreground="#1e3a8a", spacing1=8, spacing3=6)
        text.tag_configure("h2", font=("Microsoft YaHei", 11, "bold"),
                           foreground="#1d4ed8", spacing1=10, spacing3=4)
        text.tag_configure("sep", foreground="#cbd5e1")
        text.tag_configure("note", foreground="#9a3412", background="#fff7ed",
                           spacing1=3, spacing3=3)
        text.tag_configure("dim", foreground="#64748b")
        text.tag_configure("strong", font=FONT_BOLD, foreground="#0f172a")
        text.tag_configure("label", font=FONT_BOLD, foreground="#2563eb")
        text.tag_configure("value", foreground="#0f172a")
        text.tag_configure("mono", font=MONO, foreground="#475569")
        text.tag_configure("th", font=("Consolas", 9, "bold"), foreground="#1e3a8a")
        text.tag_configure("hint", foreground="#64748b")

    def _render_report(self) -> None:
        """把当前 HTML 报告渲染进 Text；宽表格自动转成字段卡片。"""
        text = self.report_text
        text.configure(state="normal")
        text.delete("1.0", "end")
        if not self._current_html or not os.path.isfile(self._current_html):
            text.insert("end", "尚未选择报告\n\n", "h1")
            text.insert("end",
                        "在下方「扫描历史记录」中双击任意一行，即可在这里直接查看该次扫描的完整报告详情；\n"
                        "扫描结束后也会自动切换过来。\n\n"
                        "右上角可切换「格式化视图 / JSON 原文」，或在浏览器中打开原始 HTML（完整网页样式）。\n",
                        "hint")
        elif self.view_var.get() == "JSON 原文":
            if self._current_json and os.path.isfile(self._current_json):
                with open(self._current_json, "r", encoding="utf-8") as fh:
                    text.insert("end", fh.read(), "mono")
            else:
                text.insert("end", "该文档没有对应的 JSON 原文（历史索引页只有 HTML）。\n", "hint")
        else:
            try:
                with open(self._current_html, "r", encoding="utf-8") as fh:
                    fragments = reportview.format_blocks(reportview.parse_html(fh.read()))
                for fragment, tag in fragments:
                    if tag and tag.startswith("c_") and tag not in text.tag_names():
                        text.tag_configure(tag, foreground=tag[2:], font=FONT_BOLD)
                    text.insert("end", fragment, (tag,) if tag else ())
                if not fragments:
                    text.insert("end", "报告内容为空，可切换「JSON 原文」查看。\n", "hint")
            except Exception as exc:  # noqa: BLE001
                text.insert("end", f"渲染报告失败：{exc}\n可切换「JSON 原文」或在浏览器中打开。\n",
                            "hint")
        text.configure(state="disabled")
        text.see("1.0")

    def _show_report(self, html_path: str, title: str = "") -> None:
        """在应用窗口内打开一份报告（不启动外部浏览器）。"""
        path = os.path.abspath(html_path)
        if not os.path.isfile(path):
            messagebox.showwarning("报告不存在", f"未找到报告文件：\n{path}")
            return
        self._current_html = path
        json_path = os.path.splitext(path)[0] + ".json"
        self._current_json = json_path if os.path.isfile(json_path) else ""
        self.report_title_var.set(title or os.path.basename(path))
        self.view_var.set("格式化视图")
        self._render_report()
        self.notebook.select(self.report_tab)

    def _open_current_in_browser(self) -> None:
        if not self._current_html:
            messagebox.showinfo("提示", "请先选择一份报告。")
            return
        if not history.open_in_browser(self._current_html):
            messagebox.showwarning("无法打开", f"请手动双击打开：\n{self._current_html}")

    def _build_history(self) -> None:
        box = ttk.LabelFrame(self.root,
                             text=" 扫描历史记录（双击一行，在上方「报告详情」中直接查看） ",
                             padding=(8, 6, 8, 8))
        box.grid(row=4, column=0, sticky="nsew", padx=14, pady=4)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        columns = tuple(c[0] for c in HISTORY_COLUMNS)
        self.tree = ttk.Treeview(box, columns=columns, show="headings", height=8)
        for key, heading, width in HISTORY_COLUMNS:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, anchor="center" if key not in
                             ("time", "target", "ip", "report") else "w", stretch=False)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(box, orient="horizontal", command=self.tree.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.bind("<Double-1>", lambda _event: self._open_selected_report())
        self.tree.tag_configure("odd", background="#f8fafc")

        bar = ttk.Frame(box)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(bar, textvariable=self.count_var, font=FONT,
                  foreground="#475569").pack(side="left")
        for text, command in (("查看选中报告详情", self._open_selected_report),
                              ("历史索引（窗口内）", self._open_index),
                              ("最近报告（窗口内）", self._open_latest),
                              ("打开报告目录", self._open_folder),
                              ("刷新", self._refresh_history)):
            ttk.Button(bar, text=text, command=command).pack(side="right", padx=(6, 0))

    def _build_footer(self) -> None:
        ttk.Label(self.root, text="所有探针均为只读、非破坏性请求；仅可用于授权资产的合规安全评估。",
                  font=FONT, foreground="#94a3b8").grid(
            row=5, column=0, sticky="w", padx=16, pady=(2, 8))

    # ------------------------------------------------------------------ #
    # 扫描控制
    # ------------------------------------------------------------------ #
    def _build_argv(self) -> List[str]:
        raw = self.target_var.get().strip()
        targets = [item for item in re.split(r"[\s,;]+", raw) if item]
        if not targets:
            raise ValueError("请先填写扫描目标（IP / 域名，多个用空格或逗号分隔）")
        try:
            threads = int(self.threads_var.get().strip() or "200")
            if not 1 <= threads <= 2000:
                raise ValueError
        except ValueError:
            raise ValueError("并发数必须是 1-2000 之间的整数")

        argv = list(targets)
        ports = self.ports_var.get().strip()
        if ports:
            argv += ["-p", ports]
        try:
            processes = int(self.processes_var.get().strip() or "0")
            async_limit = int(self.async_var.get().strip() or "64")
            if not 0 <= processes <= 8 or not 1 <= async_limit <= 1024:
                raise ValueError
        except ValueError:
            raise ValueError("进程数需为 0-8，协程并发需为 1-1024 的整数")
        argv += ["-t", str(threads), "--processes", str(processes),
                 "--async-limit", str(async_limit)]
        if not self.mp_var.get():
            argv.append("--no-multiprocessing")
        if not self.coro_var.get():
            argv.append("--no-async")
        argv += ["--categories", self.port_cat_var.get().strip() or "all"]
        argv += ["--stack-categories", self.stack_var.get().strip() or "all"]
        if self.skip_web_var.get():
            argv.append("--skip-web")
        if self.shallow_var.get():
            argv.append("--shallow")
        if self.local_audit_var.get():
            argv.append("--local-audit")
        extra = _split_extra(self.extra_var.get())
        if extra:
            argv += extra
        argv += ["-o", self.out_dir]
        return argv

    def _start_scan(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo("正在扫描", "已有扫描任务在运行，请等待完成或先点击「停止」。")
            return
        try:
            argv = self._build_argv()
        except ValueError as exc:
            messagebox.showwarning("参数有误", str(exc))
            return

        self.cancel.clear()
        self._totals = {key: 0 for key, _, _ in SEVERITIES}
        for label in self.summary_labels.values():
            label.configure(text="0")
        if self.total_label is not None:
            self.total_label.configure(text="0")
        self._last_html = ""
        self._clear_log()
        self._set_busy(True)
        self.status_var.set("扫描中 · 请稍候")
        self._append_log("启动扫描任务：" + " ".join(argv))
        self._worker = threading.Thread(target=self._worker_main, args=(argv,), daemon=True)
        self._worker.start()

    def _worker_main(self, argv: Sequence[str]) -> None:
        try:
            results = guitask.run_scan(
                argv,
                log=lambda line: self.events.put(("log", line)),
                cancel=self.cancel,
                on_report=lambda rep, paths: self.events.put(("report", rep, paths)),
            )
            self.events.put(("done", results, None))
        except Exception as exc:  # noqa: BLE001
            self.events.put(("done", [], exc))

    def _stop_scan(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            return
        self.cancel.set()
        self.stop_btn.configure(state="disabled")
        self.status_var.set("正在停止（完成当前目标后结束）")

    def _set_busy(self, busy: bool) -> None:
        self.start_btn.configure(state="disabled" if busy else "normal")
        self.stop_btn.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _on_close(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            if not messagebox.askokcancel("退出", "扫描仍在进行，确定要退出程序吗？"):
                return
            self.cancel.set()
        self.root.destroy()

    # ------------------------------------------------------------------ #
    # 事件轮询（Tk 主线程）
    # ------------------------------------------------------------------ #
    def _poll(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._append_log(event[1])
                elif kind == "report":
                    self._on_report(event[1], event[2])
                elif kind == "done":
                    self._on_done(event[1], event[2])
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _on_report(self, rep: ScanReport, paths: Dict[str, str]) -> None:
        counts = rep.severity_counts()
        for key, value in counts.items():
            self._totals[key] = self._totals.get(key, 0) + value
        for key, _, _ in SEVERITIES:
            self.summary_labels[key].configure(text=str(self._totals.get(key, 0)))
        if self.total_label is not None:
            self.total_label.configure(text=str(sum(self._totals.values())))
        self._last_html = os.path.abspath(paths.get("html", ""))
        self._refresh_history()
        if self.auto_open_var.get() and self._last_html and os.path.isfile(self._last_html):
            self._show_report(self._last_html, title=f"{rep.target} · 本次扫描报告")

    def _on_done(self, results: List[ScanReport], error: Optional[BaseException]) -> None:
        self._set_busy(False)
        self._refresh_history()
        if error is not None:
            message = str(error) or type(error).__name__
            self._append_log("[错误] " + message)
            self._append_log(traceback.format_exc())
            self.status_var.set("扫描失败：" + message)
            messagebox.showerror("扫描失败", message)
            return
        stopped = self.cancel.is_set()
        total = sum(self._totals.values())
        self.status_var.set(f"{'已停止' if stopped else '扫描完成'} · "
                            f"{len(results)} 个目标 · {total} 条发现")
        self._append_log("可双击下方「扫描历史记录」中的任意一行，在本窗口「报告详情」里查看当次完整报告。")

    # ------------------------------------------------------------------ #
    # 日志 / 历史
    # ------------------------------------------------------------------ #
    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", str(text) + "\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _refresh_history(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._records = history.load_records(self.out_dir)
        for idx, rec in enumerate(self._records):
            counts = rec.get("summary") or {}
            values = (
                rec.get("time", ""), rec.get("target", ""), rec.get("ip", ""),
                counts.get("critical", 0), counts.get("high", 0), counts.get("medium", 0),
                counts.get("low", 0), counts.get("info", 0), rec.get("total", 0),
                f"{rec.get('duration', 0)}s", rec.get("html", ""),
            )
            self.tree.insert("", "end", iid=str(idx), values=values,
                             tags=("odd",) if idx % 2 else ())
        self.count_var.set(f"共 {len(self._records)} 次扫描 · {self.out_dir}")

    def _selected_record(self) -> Optional[Dict[str, Any]]:
        selection = self.tree.selection()
        if not selection:
            return None
        try:
            return self._records[int(selection[0])]
        except (ValueError, IndexError):
            return None

    def _open_record_html(self, rec: Dict[str, Any]) -> None:
        name = str(rec.get("html") or "")
        path = os.path.join(self.out_dir, name)
        if not name or not os.path.isfile(path):
            messagebox.showwarning("报告不存在", f"未找到该次扫描的 HTML 报告：\n{path}")
            return
        self._show_report(path, title=f"{rec.get('target', '')} · {rec.get('time', '')}")

    def _open_selected_report(self) -> None:
        rec = self._selected_record()
        if rec is None:
            messagebox.showinfo("提示", "请先在历史记录列表中选中一行（双击可在窗口内查看报告）。")
            return
        self._open_record_html(rec)

    def _open_index(self) -> None:
        path = history.write_index(self.out_dir)
        self._show_report(path, title=f"扫描历史索引（共 {len(self._records)} 次）")

    def _open_latest(self) -> None:
        path = history.latest_report(self.out_dir)
        if not path:
            messagebox.showinfo("提示", "暂无扫描记录，请先执行一次扫描。")
            return
        self._show_report(path, title="最近一次扫描报告")

    def _open_folder(self) -> None:
        os.makedirs(self.out_dir, exist_ok=True)
        if not history.open_folder(self.out_dir):
            messagebox.showwarning("无法打开", f"请手动打开目录：\n{self.out_dir}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    _enable_dpi_awareness()
    if tk is None:
        _fatal("无法加载 tkinter。请使用官方 Python 安装包（安装时勾选 tcl/tk），"
               "或重新运行「生成exe.bat」打包图形界面版。")
        return 1

    events: "queue.Queue" = queue.Queue()
    guitask.install_io(lambda line: events.put(("log", line)))
    utils.set_no_console(True)

    args = list(sys.argv[1:] if argv is None else argv)
    target = ""
    autostart = False
    for i, item in enumerate(args):
        if item == "--target" and i + 1 < len(args):
            target = args[i + 1]
        elif item.startswith("--target="):
            target = item.split("=", 1)[1]
        elif item == "--scan":
            autostart = True

    root = tk.Tk()
    ScannerApp(root, events, target=target, autostart=autostart)
    root.mainloop()
    return 0


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # PyInstaller --windowed 下多进程端口分片必须
    raise SystemExit(main())
