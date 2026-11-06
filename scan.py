# -*- coding: utf-8 -*-
"""服务器漏洞扫描器入口：输入 IP 或域名即可自动完成全部扫描。

用法示例：
    python scan.py 192.168.1.10
    python scan.py example.com
    python scan.py https://example.com              # 也接受 URL，会自动取主机名
    python scan.py                                  # 不带参数时会提示输入目标
    python scan.py 10.0.0.5 -p 22,80,443            # 可选：自定义端口
"""

import multiprocessing
import sys

from scanner.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # 支持多进程端口分片（含 PyInstaller 冻结版）
    sys.exit(main())
