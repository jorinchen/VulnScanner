# -*- coding: utf-8 -*-
"""通用工具：日志、目标解析、网络、并发、版本比较与命令执行。"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("vulnscanner")

# GUI / --windowed 模式下没有控制台：调用 java/node/nmap 等命令行工具时必须
# 加 CREATE_NO_WINDOW，否则每次采集版本都会闪出一个 cmd 黑窗口。
NO_CONSOLE = False


def set_no_console(value: bool = True) -> None:
    global NO_CONSOLE
    NO_CONSOLE = bool(value)


SEVERITY_CN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

_NUM_RE = re.compile(r"\d+")


def setup_logging(verbose: bool = False) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


# --------------------------------------------------------------------------- #
# 运行路径（兼容 PyInstaller 冻结后的 exe）
# --------------------------------------------------------------------------- #
def app_dir() -> str:
    """程序所在目录：exe 模式取 exe 所在目录，源码模式取项目根目录。

    onefile 模式下 __file__ 指向临时解压目录，报告必须写到 exe 旁边才能长期保留。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_reports_dir() -> str:
    """默认报告/历史记录目录：程序同目录下的 reports/。"""
    return os.path.join(app_dir(), "reports")


# --------------------------------------------------------------------------- #
# 目标解析
# --------------------------------------------------------------------------- #
def normalize_target(target: str) -> str:
    """去掉 scheme / 路径 / 端口，返回纯主机部分。"""
    t = target.strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/")[0].split("?")[0]
    if "@" in t:
        t = t.rsplit("@", 1)[-1]
    t = t.strip("[]")
    if t.count(":") == 1:
        t = t.split(":")[0]
    return t


def resolve(target: str) -> Tuple[str, Optional[str]]:
    """返回 (ip, hostname)。"""
    host = normalize_target(target)
    try:
        ipaddress.ip_address(host)
        try:
            name = socket.gethostbyaddr(host)[0]
        except Exception:
            name = None
        return host, name
    except ValueError:
        ip = socket.gethostbyname(host)
        return ip, host


def local_ip_addresses() -> set:
    """获取本机所有可能的 IP（含回环与首选出口地址），用于判断是否扫描本机。"""
    ips = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:  # noqa: BLE001
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))  # UDP connect 不发包，仅用于取出口地址
        ips.add(sock.getsockname()[0])
        sock.close()
    except Exception:  # noqa: BLE001
        pass
    return ips


def is_local_address(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


# --------------------------------------------------------------------------- #
# 版本比较
# --------------------------------------------------------------------------- #
def version_tuple(version: str, max_parts: int = 6) -> Tuple[int, ...]:
    """把 '1.9.5p2' / '2.4.49-1ubuntu1' 这类字符串转成可比较的数字元组。"""
    if not version:
        return ()
    return tuple(int(x) for x in _NUM_RE.findall(version)[:max_parts])


def in_ranges(version: str, ranges: Sequence[Tuple[str, str]]) -> bool:
    """判断版本是否落在 [lo, hi) 区间列表中的任意一个。'*' 表示任意版本。"""
    if not version:
        return False
    v = version_tuple(version)
    if not v:
        return False
    for lo, hi in ranges:
        if lo == "*":
            return True
        a, b = version_tuple(lo), version_tuple(hi)
        if not a:
            continue
        if b:
            if a <= v < b:
                return True
        elif v == a:
            return True
    return False


# --------------------------------------------------------------------------- #
# 命令执行
# --------------------------------------------------------------------------- #
def run_command(cmd: Sequence[str], timeout: int = 20) -> Tuple[int, str, str]:
    kwargs = {}
    if sys.platform == "win32" and (NO_CONSOLE or sys.stdout is None or sys.stderr is None):
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(
            list(cmd),
            capture_output=True,
            timeout=timeout,
            text=True,
            errors="replace",
            shell=False,
            **kwargs,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def command_exists(name: str) -> bool:
    code, _, _ = run_command([name, "--version"], timeout=8)
    return code != 127


# --------------------------------------------------------------------------- #
# 网络
# --------------------------------------------------------------------------- #
def tcp_connect(host: str, port: int, timeout: float = 1.0, source: str = "") -> Optional[socket.socket]:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except Exception:  # noqa: BLE001
        return None


def recv_some(sock: socket.socket, timeout: float = 1.5, bufsize: int = 4096) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(bufsize)
    except Exception:  # noqa: BLE001
        return b""


def send_recv(
    host: str,
    port: int,
    payload: bytes = b"",
    timeout: float = 2.0,
    read_first: bool = True,
    bufsize: int = 4096,
) -> bytes:
    """连接 -> （可选）读 banner -> 发探针 -> 再读，返回累计字节。"""
    sock = tcp_connect(host, port, timeout)
    if sock is None:
        return b""
    try:
        data = b""
        if read_first:
            data = recv_some(sock, timeout, bufsize)
        if payload:
            try:
                sock.sendall(payload)
            except Exception:  # noqa: BLE001
                return data
            data += recv_some(sock, timeout, bufsize)
        return data
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def ssl_context(verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED
    return ctx


def safe_text(data: bytes, limit: int = 400) -> str:
    try:
        return data.decode("utf-8", errors="replace")[:limit]
    except Exception:  # noqa: BLE001
        return ""


def map_parallel(func: Callable, items: Iterable, workers: int = 50) -> List:
    """并发执行并收集结果；单个任务异常不影响整体。"""
    results: List = []
    items = list(items)
    if not items:
        return results
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(func, item) for item in items]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug("子任务异常: %s", exc)
    return results
