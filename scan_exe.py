# -*- coding: utf-8 -*-
"""命令行 / 菜单交互入口（可选的 ``--console`` 版 exe 打包目标）。

主程序是 ``scan_gui.py``：图形界面、``--windowed``、双击不出现 cmd 黑窗口。
本文件只供「漏洞扫描器-命令行版.exe」以及脚本 / 定时任务使用：

无参数启动时进入菜单：扫描 / 查看历史记录 / 打开最近报告 / 打开报告目录。
带参数启动时与命令行完全等价，例如：
    漏洞扫描器-命令行版.exe 192.168.1.10
    漏洞扫描器-命令行版.exe --history
    漏洞扫描器-命令行版.exe example.com --stack-categories java,nginx

所有报告与历史记录都写在 exe 同目录的 reports 下：
    reports/index.html     历史记录索引页（列出每次扫描，可点开当次报告）
    reports/history.json   结构化历史记录
    reports/report_*.html  每次扫描的完整报告
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from scanner import cli, history
from scanner.utils import default_reports_dir

TITLE = """
======================================================================
                    服务器综合漏洞扫描器  v1.2
     端口 / 服务 / Web / 系统 / PHP2Shell / Java·Go·C++·Python·Nginx·OpenResty·Node.js·PHP·.NET
======================================================================
"""


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def _open_file(path: str) -> None:
    full = os.path.abspath(path)
    if history.open_in_browser(full):
        print(f"  已打开：{full}")
    else:
        print(f"  无法自动打开，请手动双击：{full}")


def _recent(out_dir: str, limit: int = 5) -> str:
    records = history.load_records(out_dir)
    if not records:
        return "  最近记录：暂无（选择 1 执行一次扫描后会自动出现在这里）"
    lines = [f"  最近记录（共 {len(records)} 次）："]
    for item in records[:limit]:
        s = item.get("summary") or {}
        lines.append(
            f"    {item.get('time', '')}  {str(item.get('target', ''))[:28]:<28} "
            f"严重 {s.get('critical', 0)} / 高危 {s.get('high', 0)} / 合计 {item.get('total', 0)}"
            f"   {item.get('html', '')}"
        )
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    _configure_console()
    args = list(sys.argv[1:] if argv is None else argv)
    if args:  # 带参数：完全兼容命令行用法
        return cli.main(args)

    out_dir = default_reports_dir()
    print(TITLE)
    while True:
        print(f"  报告/记录目录：{out_dir}")
        print(_recent(out_dir))
        print()
        print("  1  扫描新目标（自动打开当次报告）")
        print("  2  查看全部历史扫描记录（打开 index.html）")
        print("  3  打开最近一次扫描报告")
        print("  4  打开报告目录")
        print("  0  退出")
        print("-" * 70)
        try:
            choice = input("请选择 [0-4]（直接回车=退出）: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("", "0", "q", "quit", "exit", "退出"):
            return 0
        if choice == "1":
            print("\n请输入要扫描的 IP 或域名（多个用空格/逗号分隔）；扫描结束后输入 n 返回菜单。\n")
            try:
                cli.main([])
            except KeyboardInterrupt:
                print("\n已取消扫描。")
            print()
        elif choice == "2":
            index = history.write_index(out_dir)
            history.print_records(out_dir, 20)
            _open_file(index)
            print()
        elif choice == "3":
            latest = history.latest_report(out_dir)
            if latest:
                _open_file(latest)
            else:
                print("  暂无扫描记录，请先选择 1 执行一次扫描。")
            print()
        elif choice == "4":
            history.open_folder(out_dir)
            print(f"  已打开目录：{out_dir}\n")
        else:
            print("  无效选择，请输入 0-4。\n")


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # 命令行版 exe 同样支持多进程端口分片
    raise SystemExit(main())
