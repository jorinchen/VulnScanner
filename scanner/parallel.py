# -*- coding: utf-8 -*-
"""混合并发层：多进程 + 多线程 + 多协程（纯标准库）。

三种模型各自负责最合适的部分：

* **多进程**：把端口表切片交给 ``ProcessPoolExecutor``，绕开 GIL 与单个阻塞连接的
  相互影响；目标/端口规模较小时自动降级，避免进程启动开销。
* **多线程**：每个进程内用 ``ThreadPoolExecutor`` 做阻塞 socket connect；
  服务指纹、Web 端口扫描同样走线程池。
* **多协程**：``asyncio`` + ``open_connection`` + ``Semaphore``，批量发起只读 HTTP GET
  （技术栈暴露面探测、Web 敏感路径探测），一次事件循环里并发上百个请求。

PyInstaller ``--onefile --windowed`` 下 Windows 使用 spawn 子进程，入口脚本需调用
``multiprocessing.freeze_support()``（``scan_gui.py`` / ``scan.py`` / ``scan_exe.py`` 已处理）。
任何进程池异常都会自动降级为单进程 + 多线程，不会让扫描失败。
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("vulnscanner")

PROCESS_THRESHOLD = 64          # 端口数少于此值时不启动多进程
MAX_PROCESSES = 8
DEFAULT_ASYNC_LIMIT = 64
UA = "Mozilla/5.0 (compatible; VulnScanner/1.2)"


@dataclass
class ParallelConfig:
    processes: int = 0              # 0 = 自动
    threads: int = 200
    async_limit: int = DEFAULT_ASYNC_LIMIT
    allow_processes: bool = True
    allow_async: bool = True

    @classmethod
    def from_args(cls, args: Any) -> "ParallelConfig":
        return cls(
            processes=int(getattr(args, "processes", 0) or 0),
            threads=int(getattr(args, "threads", 200) or 200),
            async_limit=max(1, int(getattr(args, "async_limit", DEFAULT_ASYNC_LIMIT)
                                   or DEFAULT_ASYNC_LIMIT)),
            allow_processes=not bool(getattr(args, "no_multiprocessing", False)),
            allow_async=not bool(getattr(args, "no_async", False)),
        )


def resolve_processes(config: ParallelConfig, task_count: int) -> int:
    """按任务规模决定进程数；frozen 单文件 exe 下保守一些，避免重复解压开销。"""
    if not config.allow_processes or task_count < PROCESS_THRESHOLD:
        return 1
    if config.processes > 0:
        wanted = config.processes
    elif getattr(sys, "frozen", False):
        wanted = 2
    else:
        wanted = min(4, max(2, (os.cpu_count() or 2)))
    return max(1, min(wanted, MAX_PROCESSES, max(1, task_count // 32)))


def describe(config: ParallelConfig, port_count: int, probe_count: int = 0) -> str:
    procs = resolve_processes(config, port_count)
    coroutines = probe_count if config.allow_async and probe_count else 0
    return (f"并发模型：多进程 {procs}（端口分片） / 多线程 {config.threads}（连接探测）"
            f" / 多协程 {config.async_limit}（HTTP 只读探针，本次 {coroutines} 个）"
            + ("" if config.allow_processes else " [多进程已禁用]")
            + ("" if config.allow_async else " [协程已禁用]"))


# --------------------------------------------------------------------------- #
# 多进程 + 多线程：端口扫描
# --------------------------------------------------------------------------- #
def _connect_state(host: str, port: int, timeout: float) -> Tuple[int, str]:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return port, "open"
    except socket.timeout:
        return port, "filtered"
    except (ConnectionRefusedError, OSError):
        return port, "closed"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


def _port_chunk(job: Tuple[str, List[int], float, int]) -> List[Tuple[int, str]]:
    """进程池 worker：每个分片内部再开线程池（多进程 × 多线程）。"""
    host, chunk, timeout, workers = job
    if not chunk:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(chunk)))) as pool:
        futures = [pool.submit(_connect_state, host, port, timeout) for port in chunk]
        return [future.result() for future in futures]


def scan_ports_hybrid(
    host: str,
    ports: Sequence[int],
    timeout: float,
    workers: int,
    config: ParallelConfig,
) -> List[Tuple[int, str]]:
    """返回 ``[(端口, open/closed/filtered)]``；进程池失败时自动降级。"""
    unique = list(dict.fromkeys(int(p) for p in ports))
    if not unique:
        return []
    procs = resolve_processes(config, len(unique))
    if procs > 1:
        chunks = [unique[i::procs] for i in range(procs)]
        jobs = [(host, chunk, timeout, max(1, workers // procs)) for chunk in chunks]
        try:
            with ProcessPoolExecutor(max_workers=procs) as pool:
                results = [item for part in pool.map(_port_chunk, jobs) for item in part]
            LOGGER.info("多进程端口扫描：%d 个进程 × 每进程 %d 线程，共 %d 个端口",
                        procs, max(1, workers // procs), len(unique))
            return results
        except Exception as exc:  # noqa: BLE001 - spawn 不可用时必须能继续扫描
            LOGGER.warning("多进程端口扫描不可用，已自动降级为多线程：%s", exc)
    return _port_chunk((host, unique, timeout, max(1, workers)))


def map_threads(func, items: Sequence[Any], workers: int) -> List[Any]:
    """保序的线程池 map，用于服务指纹 / Web 端口扫描。"""
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        return list(pool.map(func, items))


# --------------------------------------------------------------------------- #
# 多协程：批量只读 HTTP GET
# --------------------------------------------------------------------------- #
@dataclass
class HttpTask:
    host: str
    port: int
    path: str = "/"
    use_tls: bool = False
    server_hostname: Optional[str] = None
    timeout: float = 6.0
    max_body: int = 4096
    label: Any = None                 # 调用方自带的元信息，原样返回


@dataclass
class HttpResult:
    task: HttpTask
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _read_limited(reader: asyncio.StreamReader, limit: int, timeout: float) -> bytes:
    chunks: List[bytes] = []
    total = 0
    try:
        while total < limit:
            chunk = await asyncio.wait_for(reader.read(min(8192, limit - total)), timeout)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass  # 已读到的部分仍然可用（Connection: close 通常让服务端主动断开）
    return b"".join(chunks)


async def _fetch(task: HttpTask, semaphore: asyncio.Semaphore) -> HttpResult:
    writer = None
    async with semaphore:
        try:
            hostname = task.server_hostname or task.host
            host_header = (hostname if task.port in (80, 443) else f"{hostname}:{task.port}")
            kwargs = {}
            if task.use_tls:
                kwargs = {"ssl": _tls_context(), "server_hostname": hostname}
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(task.host, task.port, **kwargs), task.timeout)
            request = (
                f"GET {task.path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {UA}\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("utf-8", errors="replace"))
            await asyncio.wait_for(writer.drain(), task.timeout)
            raw = await _read_limited(reader, task.max_body + 8192, task.timeout)
            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            status = 0
            headers: Dict[str, str] = {}
            if lines and lines[0]:
                parts = lines[0].split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status = int(parts[1])
                for line in lines[1:]:
                    if b":" in line:
                        key, value = line.split(b":", 1)
                        headers[key.decode("latin-1").strip().lower()] = value.decode(
                            "latin-1").strip()
            return HttpResult(task=task, status=status, headers=headers,
                              body=body[:task.max_body])
        except Exception as exc:  # noqa: BLE001
            return HttpResult(task=task, error=f"{type(exc).__name__}: {exc}")
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass


async def http_get_batch(tasks: Sequence[HttpTask], limit: int = DEFAULT_ASYNC_LIMIT) -> List[HttpResult]:
    """在一个事件循环里并发执行所有只读 GET，返回结果顺序与 tasks 一致。"""
    if not tasks:
        return []
    semaphore = asyncio.Semaphore(max(1, limit))
    return list(await asyncio.gather(*(_fetch(task, semaphore) for task in tasks)))


def run_async(coro) -> Any:
    """同步代码调用协程；若当前线程已有事件循环，则放到独立线程执行。"""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def http_get_batch_sync(tasks: Sequence[HttpTask], limit: int = DEFAULT_ASYNC_LIMIT) -> List[HttpResult]:
    return run_async(http_get_batch(tasks, limit))
