# -*- coding: utf-8 -*-
"""一键把扫描器打包成 Windows exe，产物统一输出到 dist/ 目录。

用法：
    python build_exe.py              # 图形界面版 + 命令行版
    python build_exe.py --gui-only   # 只生成图形界面版（更快）

依赖 PyInstaller（脚本会自动尝试安装），运行时本身仍然只用 Python 标准库。
产物（全部在 dist/ 下）：
    dist/漏洞扫描器.exe              主程序：--windowed 图形界面，双击即打开应用窗口
    dist/漏洞扫描器-命令行版.exe      可选：--console 命令行 / 菜单版，供脚本调用
    reports/                          程序运行时生成的报告与历史记录目录
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"

GUI_SCRIPT = "scan_gui.py"
CLI_SCRIPT = "scan_exe.py"

# PyInstaller 内部使用的名字（保持 ASCII，避免中文名出现在构建中间目录里引发兼容问题）
GUI_NAME = "VulnScanner"
CLI_NAME = "VulnScannerCLI"

# 最终对外产物名（中文，便于用户直接识别）
GUI_EXE = "漏洞扫描器.exe"
CLI_EXE = "漏洞扫描器-命令行版.exe"


def run(cmd) -> int:
    print(">", " ".join(str(x) for x in cmd), flush=True)
    try:
        return subprocess.run([str(x) for x in cmd], cwd=str(ROOT)).returncode
    except OSError as exc:
        print(f"命令执行失败：{exc}")
        return 1


def ensure_pyinstaller(steps: int) -> bool:
    try:
        import PyInstaller  # noqa: F401
        print(f"[1/{steps}] 已检测到 PyInstaller。")
        return True
    except ImportError:
        pass

    print(f"[1/{steps}] 未检测到 PyInstaller，正在安装（需要联网）...")
    if run([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"]) == 0:
        return True

    print("  pip 不可用，尝试引导安装 pip ...")
    run([sys.executable, "-m", "ensurepip", "--upgrade"])
    if run([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"]) == 0:
        return True

    print("安装失败。请手动执行：python -m pip install pyinstaller 后重试。")
    return False


def build(entry: str, name: str, final_name: str, windowed: bool, clean: bool = True) -> bool:
    mode = "--windowed" if windowed else "--console"
    work = BUILD / name
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile", mode,
        "--name", name,
        "--distpath", str(DIST),
        "--workpath", str(work),
        "--specpath", str(work),
    ]
    if clean:
        cmd.append("--clean")
    cmd.append(entry)
    if run(cmd) != 0:
        print(f"打包失败：{entry}（{mode}）")
        return False

    suffix = ".exe" if os.name == "nt" else ""
    source = DIST / (name + suffix)
    if not source.is_file():
        print(f"未找到打包产物：{source}")
        return False

    target = DIST / final_name
    if target.exists():
        try:
            target.unlink()
        except OSError as exc:
            print(f"无法覆盖旧文件 {target}：{exc}")
            return False
    source.rename(target)
    print(f"  已生成：{target}")
    return True


def clean_stale() -> None:
    """清理历史遗留在项目根目录的 spec 文件与旧版本 exe（产物统一放 dist）。"""
    for name in (GUI_NAME, CLI_NAME):
        spec = ROOT / f"{name}.spec"
        if spec.is_file():
            try:
                spec.unlink()
            except OSError:
                pass
    for name in (GUI_EXE, CLI_EXE):
        stale = ROOT / name
        if stale.is_file():
            print(f"  检测到根目录旧产物，已忽略（产物统一输出到 dist）：{stale.name}")


def main() -> int:
    if sys.version_info < (3, 8):
        print("需要 Python 3.8 或更高版本。")
        return 1

    gui_only = "--gui-only" in sys.argv[1:]
    steps = 3 if gui_only else 4

    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    clean_stale()

    if not ensure_pyinstaller(steps):
        return 1

    print(f"[2/{steps}] 正在打包图形界面主程序（--windowed，约需 1-3 分钟）...")
    if not build(GUI_SCRIPT, GUI_NAME, GUI_EXE, windowed=True, clean=True):
        return 1

    step = 3
    if not gui_only:
        print(f"[{step}/{steps}] 正在打包可选命令行版（--console）...")
        if not build(CLI_SCRIPT, CLI_NAME, CLI_EXE, windowed=False, clean=False):
            return 1
        step += 1

    print(f"[{step}/{steps}] 完成。")
    print()
    print(f"  图形界面主程序：{DIST / GUI_EXE}   ← 双击这个，打开应用窗口")
    if not gui_only:
        print(f"  命令行版（可选）：{DIST / CLI_EXE}")
    print(f"  报告目录：{ROOT / 'reports'}   （与源码目录同级，自动创建）")
    print(f"  历史索引：{ROOT / 'reports' / 'index.html'}")
    print()
    print("图形界面版启动后：填写目标 → 开始扫描；双击历史记录在窗口内「报告详情」直接查看报告。")
    print("命令行版用法：漏洞扫描器-命令行版.exe 192.168.1.10 --stack-categories nodejs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
