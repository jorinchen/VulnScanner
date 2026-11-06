# -*- coding: utf-8 -*-
"""一键把扫描器打包成 Windows 图形界面 exe（双击运行，无 cmd 黑窗口）。

用法：
    python build_exe.py              # 图形界面版 + 命令行版
    python build_exe.py --gui-only   # 只生成图形界面版（更快）

依赖 PyInstaller（脚本会自动尝试安装），运行时本身仍然只用 Python 标准库。
产物：
    漏洞扫描器.exe                 主程序：--windowed 图形界面，双击即打开应用窗口
    漏洞扫描器-命令行版.exe        可选：--console 命令行 / 菜单版，供脚本调用
    dist/VulnScanner.exe           GUI 原始输出
    dist/VulnScannerCLI.exe        CLI 原始输出
    reports/                       程序运行时生成的报告与历史记录目录
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GUI_NAME = "VulnScanner"
CLI_NAME = "VulnScannerCLI"
GUI_SCRIPT = "scan_gui.py"
CLI_SCRIPT = "scan_exe.py"
GUI_EXE = "漏洞扫描器.exe"
CLI_EXE = "漏洞扫描器-命令行版.exe"


def run(cmd) -> int:
    print(">", " ".join(str(x) for x in cmd), flush=True)
    try:
        return subprocess.run([str(x) for x in cmd], cwd=str(ROOT)).returncode
    except OSError as exc:
        print(f"命令执行失败：{exc}")
        return 1


def build(entry: str, name: str, windowed: bool, clean: bool = True) -> bool:
    mode = "--windowed" if windowed else "--console"
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile", mode,
        "--name", name,
        "--distpath", "dist",
        "--workpath", f"build_{name}",
        "--specpath", ".",
    ]
    if clean:
        cmd.append("--clean")
    cmd.append(entry)
    if run(cmd) != 0:
        print(f"打包失败：{entry}（{mode}）")
        return False
    suffix = ".exe" if os.name == "nt" else ""
    source = ROOT / "dist" / (name + suffix)
    if not source.is_file():
        print(f"未找到打包产物：{source}")
        return False
    target = ROOT / (GUI_EXE if windowed else CLI_EXE)
    shutil.copy2(source, target)
    print(f"  已生成：{target}")
    return True


def main() -> int:
    if sys.version_info < (3, 8):
        print("需要 Python 3.8 或更高版本。")
        return 1

    gui_only = "--gui-only" in sys.argv[1:]
    steps = 3 if gui_only else 4

    try:
        import PyInstaller  # noqa: F401
        print(f"[1/{steps}] 已检测到 PyInstaller。")
    except ImportError:
        print(f"[1/{steps}] 未检测到 PyInstaller，正在安装（需要联网）...")
        if run([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"]) != 0:
            print("安装失败。请手动执行：python -m pip install pyinstaller 后重试。")
            return 1

    for name in (GUI_NAME, CLI_NAME):
        spec = ROOT / f"{name}.spec"
        if spec.is_file():
            try:
                spec.unlink()
            except OSError:
                pass

    print(f"[2/{steps}] 正在打包图形界面主程序（--windowed，约需 1-3 分钟）...")
    if not build(GUI_SCRIPT, GUI_NAME, windowed=True, clean=True):
        return 1

    step = 3
    if not gui_only:
        print(f"[{step}/{steps}] 正在打包可选命令行版（--console）...")
        if not build(CLI_SCRIPT, CLI_NAME, windowed=False, clean=False):
            return 1
        step += 1

    print(f"[{step}/{steps}] 完成。")
    print()
    print(f"  图形界面主程序：{ROOT / GUI_EXE}   ← 双击这个，打开应用窗口")
    if not gui_only:
        print(f"  命令行版（可选）：{ROOT / CLI_EXE}")
    print(f"  报告目录：{ROOT / 'reports'}   （exe 同目录，自动创建）")
    print(f"  历史索引：{ROOT / 'reports' / 'index.html'}")
    print()
    print("图形界面版启动后：填写目标 → 开始扫描；双击历史记录在窗口内「报告详情」直接查看报告。")
    print("命令行版用法：漏洞扫描器-命令行版.exe 192.168.1.10 --stack-categories nodejs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
