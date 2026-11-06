# -*- coding: utf-8 -*-
"""命令行入口。"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from . import history, osaudit, php2shell, portscan, report as report_mod, stackscan
from .models import Finding, PortInfo, ScanReport, ServiceInfo
from .serviceprobe import probe_services
from .stackdb import STACK_CATEGORIES, STACK_CN
from .utils import LOGGER, default_reports_dir, local_ip_addresses, resolve, setup_logging
from .vulndb import RULES, match_rules, stack_rule_counts
from .webscan import HTTP_PORTS, scan_web_ports

BANNER = r"""
  ____                          __     __                _
 / ___|  ___ _ ____   _____ _ __\ \   / /_ _ _ __  _ __ | | ___ _ __
 \___ \ / _ \ '__\ \ / / _ \ '__|\ \ / / _` | '_ \| '_ \| |/ _ \ '__|
  ___) |  __/ |   \ V /  __/ |    \ V / (_| | | | | | | | |  __/ |
 |____/ \___|_|    \_/ \___|_|     \_/ \__,_|_| |_|_| |_|_|\___|_|

 服务器综合漏洞扫描器 v1.2 —— 端口 / 服务 / Web / 系统 / PHP2Shell
             Java · Go · C/C++ · Python · Nginx · OpenResty · Node.js · PHP · .NET 技术栈漏洞
"""

NOTICE = (
    "用法：python scan.py <IP 或域名>    （不带参数运行时会提示输入目标）\n"
    "自动流程：端口扫描 -> 服务指纹 -> 试探性连接 -> Web/App 扫描 -> "
    "技术栈漏洞扫描 -> 操作系统审计 -> 生成报告\n"
    "技术栈：Java/JVM、Go、C/C++ 运行库、Python、Nginx、OpenResty、Node.js、PHP、.NET 的版本 CVE 与暴露面检测\n"
    "并发：多进程分片（端口）+ 多线程（连接）+ 多协程（只读 HTTP 探针），可用 --processes / --async-limit 调整\n"
    "全量检测：无论组件版本是否命中规则，全部探针与配置核查都执行，并给出可见的检测结论\n"
    "提示：仅可用于您拥有所有权或已获得书面授权的资产；所有探针均为只读、非破坏性请求。\n"
)

# 高风险端口提示（端口 -> 标题, 等级, 修复建议）
RISKY_PORTS = {
    21: ("FTP 端口开放（明文传输）", "medium", "改用 SFTP/FTPS，禁用匿名登录"),
    23: ("Telnet 端口开放（明文传输）", "high", "关闭 Telnet，改用 SSH"),
    69: ("TFTP 端口开放", "medium", "若无必要请关闭 TFTP"),
    111: ("rpcbind 端口开放", "medium", "限制访问来源，关闭不必要的 RPC 服务"),
    135: ("MS RPC 端口开放", "medium", "限制访问来源"),
    137: ("NetBIOS 名称服务端口开放", "medium", "关闭 NetBIOS over TCP/IP"),
    139: ("NetBIOS 会话端口开放", "medium", "关闭 NetBIOS，确认 SMBv1 已禁用"),
    445: ("SMB 端口开放", "high", "安装 MS17-010 补丁、禁用 SMBv1 并限制来源 IP"),
    512: ("rexec 端口开放（明文，可被利用）", "high", "关闭 r 系列服务，改用 SSH"),
    513: ("rlogin 端口开放（明文）", "high", "关闭 rlogin，改用 SSH"),
    514: ("rsh/syslog 端口开放", "medium", "关闭 rsh；限制 syslog 接收来源"),
    1433: ("MSSQL 端口开放", "medium", "限制来源 IP，禁用 sa 账户或设置强口令"),
    1521: ("Oracle 监听端口开放", "medium", "限制来源 IP 并加固口令"),
    2049: ("NFS 端口开放", "medium", "配置 /etc/exports 最小权限并限制来源"),
    3306: ("MySQL 端口开放", "medium", "限制来源 IP，禁止 root 远程登录"),
    3389: ("RDP 远程桌面端口开放", "medium", "启用 NLA、限制来源 IP、配置账户锁定策略"),
    5432: ("PostgreSQL 端口开放", "medium", "限制来源 IP，正确配置 pg_hba.conf"),
    5900: ("VNC 端口开放", "medium", "设置强口令并仅允许内网/VPN 访问"),
    6379: ("Redis 端口开放", "high", "设置 requirepass/ACL 并绑定内网地址"),
    9200: ("Elasticsearch 端口开放", "high", "启用安全认证并限制访问来源"),
    11211: ("Memcached 端口开放", "high", "仅监听内网，避免被用于 DDoS 反射放大"),
    2181: ("ZooKeeper 端口开放", "medium", "启用 SASL 认证并限制来源"),
    2375: ("Docker Remote API 端口开放", "critical", "关闭 2375，改用 TLS 双向认证的 2376"),
    10255: ("Kubelet 只读端口开放", "high", "关闭 10255 只读端口"),
    10000: ("Webmin 管理端口开放", "medium", "限制来源 IP 并加固口令"),
    27017: ("MongoDB 端口开放", "high", "启用 --auth 并绑定内网地址"),
    # ---- 邮件 ----
    25: ("SMTP 端口开放", "low", "确认未开放中继，启用 STARTTLS 与 SPF/DKIM/DMARC"),
    110: ("POP3 端口开放（明文）", "low", "改用 POP3S(995)，禁用明文认证"),
    143: ("IMAP 端口开放（明文）", "low", "改用 IMAPS(993)，禁用明文认证"),
    4190: ("ManageSieve 端口开放", "low", "限制来源并启用 TLS"),
    7071: ("Zimbra 管理端口开放", "medium", "限制来源 IP 并加固管理员口令"),
    # ---- 数据库 ----
    1521: ("Oracle 监听端口开放", "medium", "限制来源 IP 并加固口令"),
    5433: ("PostgreSQL(5433) 端口开放", "medium", "限制来源 IP"),
    5984: ("CouchDB 端口开放", "high", "配置管理员口令，关闭 admin party"),
    7474: ("Neo4j 端口开放", "medium", "修改默认口令并限制来源"),
    8086: ("InfluxDB 端口开放", "medium", "启用认证并限制来源"),
    8123: ("ClickHouse HTTP 端口开放", "high", "设置用户口令并限制来源"),
    8529: ("ArangoDB 端口开放", "medium", "启用认证并限制来源"),
    9000: ("9000 端口开放（MinIO/ClickHouse/Registry）", "medium", "确认用途并设置强口令/限制来源"),
    9042: ("Cassandra 端口开放", "medium", "启用认证并限制来源"),
    26257: ("CockroachDB 端口开放", "medium", "启用认证并限制来源"),
    50000: ("DB2 端口开放", "medium", "限制来源 IP 并加固口令"),
    # ---- AI 大模型 / 推理 / 向量库 ----
    11434: ("Ollama 大模型服务端口开放", "high", "绑定 127.0.0.1 或加认证网关，禁止公网访问"),
    1234: ("LM Studio 推理端口开放", "high", "仅监听回环地址或加认证网关"),
    7860: ("Gradio / SD WebUI 端口开放", "medium", "设置访问口令或仅内网监听"),
    8265: ("Ray Dashboard 端口开放", "high", "限制来源 IP 并启用 Dashboard 鉴权"),
    8888: ("Jupyter Notebook 端口开放", "medium", "设置 token/口令并绑定内网"),
    6006: ("TensorBoard 端口开放", "low", "仅内网监听或加反向代理认证"),
    6333: ("Qdrant 向量库端口开放", "high", "启用 API Key 并禁止公网访问"),
    19530: ("Milvus 向量库端口开放", "high", "启用认证并绑定内网"),
    9997: ("Xinference 端口开放", "high", "限制来源 IP 并启用认证"),
    8188: ("ComfyUI 端口开放", "medium", "设置访问口令或仅内网监听"),
    21001: ("FastChat 控制器端口开放", "medium", "限制来源 IP 并启用认证"),
    # ---- 流媒体 / 短视频直播 ----
    554: ("RTSP 端口开放（视频流）", "high", "配置鉴权，避免被匿名拉流"),
    8554: ("RTSP(8554) 端口开放", "high", "配置鉴权并限制来源"),
    1935: ("RTMP 推拉流端口开放", "medium", "配置推流/拉流鉴权与 IP 白名单"),
    1985: ("SRS 管理 API 端口开放", "high", "配置 http_api 鉴权并限制来源"),
    3478: ("STUN/TURN 端口开放", "medium", "启用 TURN 鉴权，防止被用作反射放大"),
    5060: ("SIP 端口开放", "medium", "启用注册鉴权并限制来源 IP"),
    9710: ("SRT 传输端口开放", "medium", "配置加密与鉴权"),
    # ---- 电商 / 业务中间件 ----
    1099: ("Java RMI 端口开放", "high", "禁止对外，存在反序列化利用风险"),
    2379: ("etcd 端口开放", "critical", "启用客户端证书认证并限制来源"),
    6443: ("Kubernetes API 端口开放", "high", "启用鉴权并限制来源 IP"),
    5601: ("Kibana 端口开放", "medium", "启用安全认证"),
    7001: ("WebLogic 端口开放", "high", "修改控制台口令并限制管理口"),
    8161: ("ActiveMQ 管理台端口开放", "high", "修改默认口令并限制来源"),
    8848: ("Nacos 端口开放", "critical", "开启鉴权并替换默认密钥"),
    8983: ("Solr 端口开放", "high", "启用认证并禁止 8983 对外"),
    9001: ("Supervisor 管理台端口开放", "high", "设置口令并仅内网监听"),
    9090: ("Prometheus 端口开放", "medium", "限制来源并加反向代理认证"),
    9092: ("Kafka 端口开放", "medium", "启用 SASL/SSL 与 ACL"),
    9100: ("node-exporter 端口开放", "low", "仅允许内网采集器访问"),
    9876: ("RocketMQ 端口开放", "medium", "启用 ACL 鉴权并限制来源"),
    9990: ("JBoss/WildFly 管理端口开放", "high", "删除默认管理用户或限制来源"),
    10911: ("RocketMQ Broker 端口开放", "medium", "启用 ACL 并限制来源"),
    15672: ("RabbitMQ 管理台端口开放", "high", "修改默认 guest/guest 并限制来源"),
    16010: ("HBase Master Web 端口开放", "medium", "启用认证或仅内网访问"),
    20880: ("Dubbo 服务端口开放", "high", "关闭 QoS/telnet 或配置鉴权"),
    50070: ("HDFS NameNode Web 端口开放", "high", "启用 Kerberos 认证，禁止对外"),
    61616: ("ActiveMQ 消息端口开放", "medium", "启用认证并限制来源"),
    # ---- Node.js 调试端口 ----
    9229: ("Node.js Inspector 调试端口开放（可远程执行代码）", "critical",
           "禁止 --inspect 监听 0.0.0.0，仅绑定 127.0.0.1 并用防火墙限制 9229"),
    5858: ("Node.js 旧版调试端口开放", "high",
           "关闭旧 debug 端口，改用 --inspect 并仅绑定回环地址"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="服务器漏洞扫描器：操作系统 / 服务 / Web 应用 / 端口 / 试探性连接",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="扫描目标：IP、域名或 URL（不填则交互式输入）")
    parser.add_argument("-p", "--ports", default="", help="端口列表，如 '80,443,8000-8100'")
    parser.add_argument("--top-ports", type=int, default=0, help="扫描常见端口的前 N 个（默认使用内置端口表）")
    parser.add_argument(
        "--categories", default="all",
        help="端口类别（逗号分隔）：base 基础, mail 邮件, database 数据库, ai 大模型/推理/向量库, "
             "media 流媒体/直播, ecommerce 电商中间件；默认 all（全部）",
    )
    parser.add_argument("--list-ports", action="store_true", help="打印内置端口分类表后退出")
    parser.add_argument("--list-rules", action="store_true", help="打印内置漏洞规则库（按技术栈分组）后退出")
    parser.add_argument("-t", "--threads", type=int, default=200, help="端口扫描并发线程数（默认 200）")
    parser.add_argument("--processes", type=int, default=0,
                        help="多进程数：端口表切片并行扫描（0=自动，frozen exe 默认 2，最大 8）")
    parser.add_argument("--async-limit", type=int, default=64,
                        help="协程并发上限：批量只读 HTTP GET 探针（默认 64）")
    parser.add_argument("--no-multiprocessing", action="store_true",
                        help="禁用多进程，仅使用多线程 + 协程")
    parser.add_argument("--no-async", action="store_true",
                        help="禁用协程，HTTP 探测回退为同步逐条请求")
    parser.add_argument("--timeout", type=float, default=1.0, help="端口连接超时秒数（默认 1.0）")
    parser.add_argument("--service-timeout", type=float, default=2.5, help="服务探测超时秒数（默认 2.5）")
    parser.add_argument("--web-timeout", type=float, default=6.0, help="Web 请求超时秒数（默认 6.0）")
    parser.add_argument("--skip-port-scan", action="store_true", help="跳过端口扫描（配合 -p 使用）")
    parser.add_argument("--skip-web", action="store_true", help="跳过 Web 应用扫描")
    parser.add_argument("--shallow", action="store_true", help="Web 扫描不做敏感路径深度探测")
    parser.add_argument("--php2shell-verify", action="store_true",
                        help="PHP2Shell 无害验证：对 PHP 站点执行 echo md5(随机串) 确认是否可执行代码"
                             "（不执行系统命令、不写文件）")
    parser.add_argument("--aggressive", action="store_true", help="等价于 --php2shell-verify")
    parser.add_argument("--local-audit", action="store_true", help="对本机操作系统做补丁/配置审计")
    parser.add_argument("--no-os-guess", action="store_true", help="不做远端操作系统识别")
    parser.add_argument("--no-stack-scan", action="store_true",
                        help="跳过技术栈漏洞扫描（Java / Go / C++ / Python / Nginx / OpenResty / "
                             "Node.js / PHP / .NET）")
    parser.add_argument("--stack-categories", default="all",
                        help="技术栈类别（逗号分隔）：java / go / cpp / python / nginx / openresty / "
                             "nodejs / php / dotnet，默认 all")
    parser.add_argument("--stack-local", action="store_true",
                        help="强制采集本机运行时与依赖版本（扫描本机目标时默认已开启）")
    parser.add_argument("--jar-dirs", default="",
                        help="额外扫描的 Java/Go/Python 依赖目录，多个用分号分隔（如 C:\\opt;C:\\apps）")
    parser.add_argument("-o", "--out", default=default_reports_dir(),
                        help="报告与历史记录目录（默认：程序同目录 reports/）")
    parser.add_argument("--history", action="store_true",
                        help="查看全部历史扫描记录（打印列表并打开 index.html）后退出")
    parser.add_argument("--open-latest", action="store_true", help="打开最近一次扫描的 HTML 报告后退出")
    parser.add_argument("--no-history", action="store_true", help="本次扫描不写入历史记录")
    parser.add_argument("--records-limit", type=int, default=20,
                        help="--history 打印的记录条数（默认 20）")
    parser.add_argument("--open-history", action="store_true", help="扫描结束后自动打开历史记录索引页")
    parser.add_argument("--no-html", action="store_true", help="仅输出 JSON 报告")
    parser.add_argument("--no-open", action="store_true", help="不自动打开报告 / 历史索引页")
    parser.add_argument("--no-ask", action="store_true",
                        help="扫描结束后不再询问是否继续（脚本 / 定时任务用）")
    parser.add_argument("--stdout-json", action="store_true", help="将 JSON 报告打印到标准输出")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("-y", "--yes", action="store_true", help="兼容选项（现在默认即自动开始扫描）")
    return parser


CATEGORY_CN = {
    "base": "基础服务/远程管理/Web",
    "mail": "邮件服务",
    "database": "数据库",
    "ai": "AI 大模型/推理/向量库",
    "media": "流媒体/短视频直播",
    "ecommerce": "电商/业务中间件",
}


def _print_port_table() -> None:
    print("内置端口分类表（默认全部扫描，可用 --categories 选择）\n")
    for name, ports in portscan.PORT_CATEGORIES.items():
        print(f"[{name}] {CATEGORY_CN.get(name, name)}  共 {len(ports)} 个")
        line = ""
        for p in ports:
            item = f"{p}({portscan.COMMON_SERVICES.get(p, '')})"
            if len(line) + len(item) > 108:
                print("   " + line)
                line = ""
            line += item + " "
        if line:
            print("   " + line)
        print()
    print(f"合计去重端口：{len(portscan.TOP_PORTS)} 个")


def _print_rules() -> None:
    counts = stack_rule_counts()
    print(f"内置漏洞规则共 {len(RULES)} 条（技术栈规则 {sum(counts.values())} 条）\n")
    for name in STACK_CATEGORIES:
        items = [r for r in RULES if r.category == name]
        print(f"[{name}] {STACK_CN.get(name, name)}  共 {len(items)} 条")
        for rule in items:
            print(f"   {rule.id:<24} {rule.severity:<9} {rule.name}")
        print()
    others = [r for r in RULES if r.category not in STACK_CATEGORIES]
    print(f"[base] 操作系统 / Web / 通用中间件  共 {len(others)} 条")
    for rule in others:
        print(f"   {rule.id:<24} {rule.severity:<9} {rule.name}")
    print("\n提示：版本匹配类结论可能受发行版补丁向后移植影响，请结合 changelog 二次确认。")


def _choose_ports(args) -> List[int]:
    if args.ports:
        return portscan.parse_ports(args.ports)
    if args.top_ports:
        return portscan.top_ports(args.top_ports)
    names = [c for c in str(args.categories or "all").split(",") if c.strip()]
    return portscan.ports_by_categories(names)


def _port_from_target(target: str) -> Optional[int]:
    """从 'example.com:8443' / 'https://example.com:8443' 中取出显式端口。"""
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", target.strip())
    host_part = text.split("/")[0].split("?")[0]
    if "@" in host_part:
        host_part = host_part.rsplit("@", 1)[-1]
    if host_part.count(":") != 1:  # 排除 IPv6
        return None
    try:
        port = int(host_part.rsplit(":", 1)[1])
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _ask_targets() -> List[str]:
    """未给出目标时，交互式询问要扫描的 IP 或域名。"""
    if not sys.stdin.isatty():
        LOGGER.error("请提供扫描目标，例如：python scan.py 192.168.1.10")
        return []
    try:
        raw = input("请输入要扫描的 IP 或域名（多个用空格/逗号分隔）: ").strip()
    except (EOFError, KeyboardInterrupt):
        return []
    if not raw:
        return []
    return [item for item in re.split(r"[\s,;]+", raw) if item]


def _ask_continue() -> Optional[List[str]]:
    """扫描结束后询问是否继续；返回下一批目标，None 表示退出。"""
    if not sys.stdin.isatty():
        return None
    try:
        raw = input("\n是否继续扫描下一个目标？[y=继续 / 直接输入 IP 或域名 / n=退出]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return None
    low = raw.lower()
    if low in ("n", "no", "q", "quit", "exit", "否", "退出"):
        return None
    if low in ("y", "yes", "是", "继续"):
        return _ask_targets() or None
    # 直接把输入当作下一个目标
    return [item for item in re.split(r"[\s,;]+", raw) if item] or None


def _open_report(path: str) -> None:
    """用系统默认浏览器打开报告 / 索引页（失败不影响扫描结果）。"""
    try:
        full = os.path.abspath(path)
        if history.open_in_browser(full):
            print(f"  已打开：{full}")
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("打开报告失败：%s", exc)


def scan_target(target: str, args, index: int = 1, total: int = 1) -> Optional[ScanReport]:
    started_dt = datetime.now()
    t0 = time.time()
    try:
        ip, hostname = resolve(target)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("无法解析目标 %s：%s", target, exc)
        return None

    LOGGER.info("[%d/%d] 目标 %s -> %s", index, total, target, ip)
    rep = ScanReport(target=target, ip=ip, hostname=hostname, started=started_dt.strftime("%Y-%m-%d %H:%M:%S"))

    # ---------------- 端口扫描 ----------------
    ports: List[int] = _choose_ports(args)
    explicit_port = _port_from_target(target)
    if explicit_port and explicit_port not in ports:
        ports = sorted(set(ports) | {explicit_port})
    if args.skip_port_scan:
        rep.ports = [PortInfo(port=p, state="open") for p in ports]
    else:
        rep.ports = portscan.scan_ports(
            ip, ports, workers=args.threads, timeout=args.timeout,
            processes=int(getattr(args, "processes", 0) or 0),
            allow_processes=not bool(getattr(args, "no_multiprocessing", False)),
        )
    open_ports = [p.port for p in rep.ports if p.state == "open"]
    rep.ports = [p for p in rep.ports if p.state == "open"]  # 报告中仅保留开放端口
    if open_ports:
        LOGGER.info("开放端口：%s", ", ".join(str(p) for p in open_ports))

    # ---------------- 服务指纹 + 试探性连接 ----------------
    if open_ports:
        LOGGER.info("识别服务指纹并进行试探性连接...")
        services = probe_services(ip, open_ports, timeout=args.service_timeout)
        rep.services = services
        for svc in services:
            if svc.unauth:
                rep.add(Finding(
                    title=svc.extra.get("unauth_title", "服务未授权访问"),
                    severity=svc.extra.get("unauth_severity", "high"),
                    category="service",
                    target=f"{ip}:{svc.port}",
                    detail=f"{svc.name or ''} {svc.product or ''} {svc.version or ''} 在 {svc.port} 端口无需认证即可访问".strip(),
                    evidence=svc.banner[:300],
                    remediation=svc.extra.get("unauth_fix", "配置强认证并限制访问来源"),
                ))
            if svc.product and svc.version:
                for rule in match_rules(svc.product, svc.version):
                    rep.add(Finding(
                        title=rule.name, severity=rule.severity, category="service",
                        target=f"{ip}:{svc.port}", cve=rule.id,
                        detail=f"检测到 {svc.product} {svc.version}"
                               + ("（发行版可能已向后移植补丁，需二次确认）" if rule.confirm else ""),
                        evidence=svc.banner[:300],
                        remediation=rule.remediation, reference=rule.reference,
                    ))
            note = svc.extra.get("note", "")
            if note and not svc.unauth:
                rep.add(Finding(
                    title=f"{svc.port} 端口服务安全性提示", severity="info", category="service",
                    target=f"{ip}:{svc.port}", detail=note,
                ))
            risky = RISKY_PORTS.get(svc.port)
            if risky and not svc.unauth:
                title, sev, fix = risky
                rep.add(Finding(
                    title=title, severity=sev, category="port",
                    target=f"{ip}:{svc.port}",
                    detail=f"{svc.name or 'unknown'} 服务对外监听"
                           + (f"（{svc.product} {svc.version}）" if svc.product else ""),
                    evidence=svc.banner[:200], remediation=fix,
                ))

    # ---------------- Web / App 扫描 ----------------
    if not args.skip_web and open_ports:
        http_ports = [
            p for p in open_ports
            if p in HTTP_PORTS
            or any(s.port == p and ("http" in (s.name or "") or "HTTP" in (s.banner or "")) for s in rep.services)
        ]
        if http_ports:
            # 域名目标下，同一 IP 可能承载多个虚拟主机，因此域名与 IP 各扫一遍：
            #   1) http(s)://<域名>   —— Host 头与 TLS SNI 使用域名
            #   2) http(s)://<IP>     —— 直接用 IP 访问（默认站点/证书）
            vhosts: List[Optional[str]] = []
            if hostname and hostname.lower() != ip.lower():
                vhosts.append(hostname)
            vhosts.append(None)

            for vhost in vhosts:
                label = vhost or ip
                LOGGER.info("扫描 Web 应用（%s）：%s", label, ", ".join(str(p) for p in http_ports))
                web_infos, web_findings = scan_web_ports(
                    ip, http_ports, timeout=args.web_timeout, deep=not args.shallow,
                    server_hostname=vhost,
                    async_limit=int(getattr(args, "async_limit", 64) or 64),
                    allow_async=not bool(getattr(args, "no_async", False)),
                )
                rep.web.extend(web_infos)
                for f in web_findings:
                    rep.add(f)
                # PHP2Shell 检测（PHP 站点 getshell 入口）
                for info in web_infos:
                    parsed = urlparse(info.url)
                    w_port = parsed.port or (443 if info.scheme == "https" else 80)
                    w_tls = info.scheme == "https"
                    php_findings, php_summary = php2shell.scan_php2shell(
                        ip, w_port, w_tls, args.web_timeout, info.url, info=info,
                        server_hostname=vhost,
                        verify=bool(args.php2shell_verify or args.aggressive),
                    )
                    for f in php_findings:
                        rep.add(f)
                    # 无论是否识别为 PHP 都记录，报告中体现"已检测"
                    rep.php2shell.append(php_summary)
                # Web 组件版本与 CVE 匹配（Jenkins / Tomcat / phpMyAdmin 等）
                for info in web_infos:
                    for tech in info.technologies:
                        if "=" in tech:
                            key, value = tech.split("=", 1)
                            if key.lower() == "x-jenkins" and value:
                                for rule in match_rules("jenkins", value):
                                    rep.add(Finding(
                                        title=rule.name, severity=rule.severity, category="web",
                                        target=info.url, cve=rule.id, detail=f"Jenkins {value}",
                                        remediation=rule.remediation, reference=rule.reference,
                                    ))
            # 域名与 IP 访问结果不同，提示可能存在虚拟主机/配置差异
            if len(vhosts) == 2 and len({w.status for w in rep.web}) > 1:
                rep.add(Finding(
                    title="以域名与以 IP 访问返回不同结果", severity="info", category="web",
                    target=f"{hostname} / {ip}",
                    detail="同一 IP 对不同 Host 头返回不同内容，说明存在虚拟主机配置，"
                           "请确认每个站点都已被扫描并单独加固",
                ))

    # ---------------- 技术栈漏洞扫描 ----------------
    if not args.no_stack_scan:
        stack_local = bool(args.stack_local or args.local_audit or ip in local_ip_addresses())
        LOGGER.info("扫描技术栈漏洞（Java / Go / C++ / Python / Nginx / OpenResty / Node.js / "
                    "PHP / .NET 全量探测）...")
        try:
            components, stack_findings, checks = stackscan.scan_stacks(
                ip=ip,
                hostname=hostname,
                web_infos=rep.web,
                services=rep.services,
                local=stack_local,
                web_timeout=args.web_timeout,
                deep=not args.shallow,
                categories=args.stack_categories,
                jar_dirs=[d.strip() for d in str(args.jar_dirs or "").split(";") if d.strip()],
                async_limit=int(getattr(args, "async_limit", 64) or 64),
                allow_async=not bool(getattr(args, "no_async", False)),
            )
            rep.stacks.extend(components)
            rep.stack_checks = checks
            for finding in stack_findings:
                rep.add(finding)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("技术栈扫描异常（不影响其他结果）：%s", exc)

    # ---------------- 操作系统审计 ----------------
    if args.local_audit or ip in local_ip_addresses():
        os_info, os_findings = osaudit.local_audit()
        rep.os_info.update(os_info)
        for f in os_findings:
            rep.add(f)
    elif not args.no_os_guess:
        guess = osaudit.remote_os_guess(ip, rep.services, use_nmap=True)
        rep.os_info = {"remote_guess": guess}
        if guess.get("nmap"):
            LOGGER.info("nmap 识别结果：%s", " | ".join(guess["nmap"][:3]))

    rep.finished = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rep.duration = time.time() - t0
    return rep


def main(argv: Optional[List[str]] = None) -> int:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if args.list_ports:
        _print_port_table()
        return 0
    if args.list_rules:
        _print_rules()
        return 0

    # 历史记录查看（不需要扫描目标，直接退出）
    if args.history or args.open_latest:
        index = history.write_index(args.out)
        if args.history:
            history.print_records(args.out, args.records_limit)
            print(f"历史记录索引：{index}")
            if not args.no_open and sys.stdin.isatty():
                _open_report(index)
        else:
            latest = history.latest_report(args.out)
            if not latest:
                print("暂无扫描记录，请先执行一次扫描。")
            else:
                print(f"最近一次报告：{latest}")
                if not args.no_open and sys.stdin.isatty():
                    _open_report(latest)
        return 0

    print(BANNER)
    print(NOTICE)
    try:
        from . import parallel
        LOGGER.info(parallel.describe(parallel.ParallelConfig.from_args(args),
                                      len(_choose_ports(args))))
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("并发配置提示失败：%s", exc)

    targets = list(args.targets)
    if not targets:
        targets = _ask_targets()
    if not targets:
        return 2

    reports = []
    while True:
        for i, target in enumerate(targets, 1):
            try:
                rep = scan_target(target, args, index=i, total=len(targets))
            except KeyboardInterrupt:
                LOGGER.warning("用户中断扫描。")
                break
            if rep is None:
                continue
            reports.append(rep)
            report_mod.print_console(rep)
            paths = report_mod.write_reports(rep, args.out)
            print(f"报告已生成：\n  JSON: {os.path.abspath(paths['json'])}")
            if not args.no_html:
                print(f"  HTML: {os.path.abspath(paths['html'])}")
                if not args.no_open and sys.stdin.isatty():
                    _open_report(paths["html"])
            if not args.no_history:
                try:
                    history.add_record(rep, paths, args.out, command=" ".join(sys.argv))
                except Exception as exc:  # noqa: BLE001
                    LOGGER.warning("写入扫描历史记录失败：%s", exc)
            if args.stdout_json:
                print(report_mod.to_json(rep))

        if reports:
            total_counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
            for r in reports:
                for k, v in r.severity_counts().items():
                    total_counts[k] += v
            print("\n全部目标汇总：" + "  ".join(f"{k}={v}" for k, v in total_counts.items()))
            if not args.no_history:
                print(f"扫描记录索引：{history.index_path(os.path.abspath(args.out))}"
                      f"（共 {len(history.load_records(args.out))} 次扫描，可直接打开查看全部历史）")

        if args.no_ask:
            break
        nxt = _ask_continue()
        if not nxt:
            break
        targets, reports = nxt, []

    if args.open_history and not args.no_history and not args.no_open and sys.stdin.isatty():
        _open_report(history.index_path(os.path.abspath(args.out)))
    if not args.no_ask and sys.stdin.isatty():
        print("\n扫描结束。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
