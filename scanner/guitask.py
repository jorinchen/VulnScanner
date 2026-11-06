# -*- coding: utf-8 -*-
"""图形界面 / 无控制台环境下的扫描任务。

PyInstaller ``--windowed``（或 pythonw）启动时 ``sys.stdin`` / ``sys.stdout`` /
``sys.stderr`` 可能是 ``None``，直接调用 :func:`scanner.cli.main` 会在
``input()`` / ``print()`` / ``sys.stdin.isatty()`` 处抛异常，也不会有任何输出。

本模块把「不依赖终端」的扫描流程抽成 :func:`run_scan`，供 GUI 在后台线程调用：

    results = run_scan(["127.0.0.1", "--skip-web"], log=print, cancel=event)

特点：

* 所有 ``print`` 与 ``logging`` 输出重定向到 ``log`` 回调（GUI 日志区实时显示）
* 不询问「是否继续扫描」、不自动弹浏览器（由界面决定）
* 每个目标完成后写 JSON / HTML 报告，并追加 ``history.json``、刷新 ``index.html``
* ``cancel`` 为 ``threading.Event``，在目标之间协作式停止
* 子进程调用自动加 ``CREATE_NO_WINDOW``，避免扫描时闪出 cmd 黑窗口
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import cli, history, report as report_mod, utils
from .models import ScanReport
from .utils import default_reports_dir

LogCallback = Callable[[str], None]
ReportCallback = Callable[[ScanReport, Dict[str, str]], None]


# --------------------------------------------------------------------------- #
# 无控制台 IO
# --------------------------------------------------------------------------- #
class _DummyStdin:
    """windowed 模式下替代 None，让 isatty()/input() 相关代码安全返回。"""

    encoding = "utf-8"

    def isatty(self) -> bool:
        return False

    def readline(self) -> str:
        return ""

    def read(self, *args: Any) -> str:
        return ""

    def fileno(self) -> int:
        raise OSError("no stdin in GUI mode")


class _LogWriter:
    """把 print() 的碎片写入按行合并后交给回调（线程安全）。"""

    def __init__(self, emit: LogCallback):
        self._emit = emit
        self._buffer = ""
        self._lock = threading.Lock()
        self.encoding = "utf-8"

    def set_emit(self, emit: LogCallback) -> None:
        with self._lock:
            self._emit = emit

    def current_emit(self) -> LogCallback:
        with self._lock:
            return self._emit

    def write(self, text: str) -> int:
        if not text:
            return 0
        pending: List[str] = []
        with self._lock:
            self._buffer += str(text)
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                line = line.rstrip("\r")
                if line:
                    pending.append(line)
        for line in pending:
            self._emit(line)
        return len(text)

    def flush(self) -> None:
        with self._lock:
            rest = self._buffer.strip()
            self._buffer = ""
        if rest:
            self._emit(rest)

    def isatty(self) -> bool:
        return False

    def reconfigure(self, **kwargs: Any) -> None:
        return None


@dataclass
class _IOState:
    stdout: Any
    stderr: Any
    stdin: Any
    writer: Optional[_LogWriter]
    old_emit: Optional[LogCallback]
    no_console: bool


def install_io(emit: LogCallback) -> _IOState:
    """保证三个标准流可用，并把 print / logging 输出接到 emit。

    可重复调用：已安装 :class:`_LogWriter` 时只更新回调，不丢弃缓冲。
    返回状态供 :func:`restore_io` 还原。
    """
    writer = sys.stdout if isinstance(sys.stdout, _LogWriter) else _LogWriter(emit)
    old_emit = writer.current_emit()
    state = _IOState(
        stdout=sys.stdout,
        stderr=sys.stderr,
        stdin=sys.stdin,
        writer=writer,
        old_emit=old_emit,
        no_console=utils.NO_CONSOLE,
    )
    writer.set_emit(emit)
    sys.stdout = writer
    sys.stderr = writer
    if sys.stdin is None:
        sys.stdin = _DummyStdin()
    utils.set_no_console(True)
    return state


def restore_io(state: _IOState) -> None:
    sys.stdout, sys.stderr, sys.stdin = state.stdout, state.stderr, state.stdin
    if state.writer is not None and state.old_emit is not None:
        state.writer.set_emit(state.old_emit)
    utils.set_no_console(state.no_console)


class _CallbackHandler(logging.Handler):
    """不依赖 sys.stderr 的日志 handler（windowed 下 stderr 为 None）。"""

    def __init__(self, emit: LogCallback):
        super().__init__()
        self._emit = emit
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._emit(self.format(record))
        except Exception:  # noqa: BLE001
            pass


def _setup_logging(emit: LogCallback, verbose: bool = False) -> None:
    root = logging.getLogger()
    root.handlers[:] = [_CallbackHandler(emit)]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


# --------------------------------------------------------------------------- #
# 扫描任务
# --------------------------------------------------------------------------- #
def _noop(_text: str) -> None:
    return None


def run_scan(
    argv: Sequence[str],
    log: Optional[LogCallback] = None,
    cancel: Optional[threading.Event] = None,
    on_report: Optional[ReportCallback] = None,
) -> List[ScanReport]:
    """执行一次（可多目标）扫描，返回每个目标的 :class:`ScanReport`。

    ``argv`` 与命令行参数完全等价（目标 + 选项），由 :func:`scanner.cli.build_parser`
    解析，因此 GUI 与 CLI 的规则、端口表、报告格式始终一致。
    """
    emit: LogCallback = log or _noop
    state = install_io(emit)
    results: List[ScanReport] = []
    try:
        args = cli.build_parser().parse_args(list(argv))
        # 无终端环境：禁止交互询问 / 自动打开浏览器 / 把 JSON 打到 stdout
        args.no_ask = True
        args.no_open = True
        args.stdout_json = False
        _setup_logging(emit, bool(args.verbose))

        targets = list(args.targets)
        if not targets:
            raise ValueError("未指定扫描目标")
        out_dir = os.path.abspath(args.out or default_reports_dir())
        os.makedirs(out_dir, exist_ok=True)
        args.out = out_dir

        emit("服务器综合漏洞扫描器 v1.2 · 图形界面模式")
        emit("仅可用于自有或已获书面授权的资产；所有探针均为只读、非破坏性请求。")
        emit(f"报告目录：{out_dir}")
        emit(f"本次目标（{len(targets)} 个）：{', '.join(targets)}")
        emit("-" * 78)

        # print_console 等 print 输出单独捕获，与全局 stdout 状态解耦
        with contextlib.redirect_stdout(_LogWriter(emit)):
            for index, target in enumerate(targets, 1):
                if cancel is not None and cancel.is_set():
                    emit("已收到停止请求，剩余目标不再扫描。")
                    break
                emit(f"[{index}/{len(targets)}] 开始扫描 {target} ...")
                rep = cli.scan_target(target, args, index=index, total=len(targets))
                if rep is None:
                    emit(f"[{index}/{len(targets)}] {target} 无法解析，已跳过。")
                    continue
                report_mod.print_console(rep)
                paths = report_mod.write_reports(rep, out_dir)
                emit(f"报告已生成：{os.path.abspath(paths['json'])}")
                emit(f"报告已生成：{os.path.abspath(paths['html'])}")
                if not args.no_history:
                    try:
                        history.add_record(rep, paths, out_dir, command=" ".join(argv))
                        emit(f"已写入扫描记录：{history.index_path(out_dir)}")
                    except Exception as exc:  # noqa: BLE001
                        emit(f"[警告] 写入扫描历史记录失败：{exc}")
                results.append(rep)
                if on_report is not None:
                    try:
                        on_report(rep, paths)
                    except Exception as exc:  # noqa: BLE001
                        emit(f"[警告] 界面回调整体异常：{exc}")

        totals = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for rep in results:
            for key, value in rep.severity_counts().items():
                totals[key] += value
        emit("-" * 78)
        emit("扫描结束：" + "  ".join(f"{k}={v}" for k, v in totals.items())
             + f"  合计={sum(totals.values())}")
        if not args.no_history:
            emit(f"历史记录索引：{history.index_path(out_dir)}"
                 f"（共 {len(history.load_records(out_dir))} 次扫描）")
        return results
    finally:
        restore_io(state)
