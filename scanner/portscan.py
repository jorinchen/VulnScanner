# -*- coding: utf-8 -*-
"""TCP 端口扫描（connect 扫描，无需管理员权限）。"""

from __future__ import annotations

import socket
import time
from typing import Dict, List, Optional, Sequence

from .models import PortInfo
from . import parallel
from .utils import LOGGER, map_parallel

# 常见服务端口表（用于端口名猜测）
COMMON_SERVICES = {
    7: "echo", 9: "discard", 13: "daytime", 19: "chargen", 20: "ftp-data", 21: "ftp",
    22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 49: "tacacs", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin",
    514: "rshell/syslog", 515: "lpd", 520: "rip", 587: "submission", 593: "http-rpc-epmap",
    623: "ipmi", 626: "serialnumberd", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware", 989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "msrpc", 1026: "msrpc", 1027: "msrpc", 1029: "msrpc", 1080: "socks",
    1194: "openvpn", 1433: "mssql", 1434: "mssql-m", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 1900: "upnp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 2379: "etcd",
    2380: "etcd-peer", 3128: "squid", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp",
    3690: "svn", 4369: "epmd", 4444: "msf/malware", 4500: "ipsec-nat", 5000: "http-alt",
    5001: "iperf", 5432: "postgresql", 5601: "kibana", 5631: "pcanywhere",
    5672: "amqp", 5900: "vnc", 5901: "vnc-1", 5984: "couchdb", 5985: "winrm-http",
    5986: "winrm-https", 6000: "x11", 6379: "redis", 6443: "k8s-api", 6666: "irc",
    5858: "node-debug", 9229: "node-inspector",
    6667: "irc", 7001: "weblogic", 7002: "weblogic-ssl", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp13", 8080: "http-proxy", 8081: "http-alt",
    8088: "hadoop", 8161: "activemq", 8443: "https-alt", 8500: "consul",
    8545: "ethereum-jsonrpc", 8880: "http-alt", 8888: "http-alt", 9000: "fastcgi/php-fpm",
    9001: "tor/supervisor", 9042: "cassandra", 9090: "prometheus", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch-transport", 9418: "git",
    10000: "webmin", 10250: "kubelet", 10255: "kubelet-ro", 11211: "memcached",
    15672: "rabbitmq-mgmt", 16379: "redis-alt", 27017: "mongodb", 27018: "mongodb",
    28017: "mongodb-http", 50000: "db2", 50070: "hadoop-namenode",
    # ---- 邮件 ----
    26: "smtp-alt", 109: "pop2", 220: "imap3", 2525: "smtp-alt", 4190: "manage-sieve",
    7071: "zimbra-admin", 10024: "amavis", 10025: "smtp-filter",
    # ---- 数据库 ----
    1522: "oracle-alt", 1830: "oracle-m", 2638: "sybase", 3050: "firebird",
    3307: "mysql-alt", 3358: "mysql-alt", 5433: "postgresql-alt", 6380: "redis-alt",
    7000: "cassandra", 7474: "neo4j", 8086: "influxdb", 8123: "clickhouse-http",
    8529: "arangodb", 9160: "cassandra-thrift", 26257: "cockroachdb", 27019: "mongodb",
    # ---- AI 大模型 / 向量库 / 推理服务 ----
    1234: "lm-studio", 11434: "ollama", 11435: "ollama-alt", 19530: "milvus",
    19531: "milvus-alt", 21001: "fastchat-controller", 21002: "fastchat-worker",
    6006: "tensorboard", 6333: "qdrant", 6334: "qdrant-grpc", 7860: "gradio/sd-webui",
    7861: "gradio", 8002: "vllm-alt", 8188: "comfyui", 8265: "ray-dashboard",
    8501: "streamlit", 8889: "jupyter-alt", 9997: "xinference",
    # ---- 流媒体 / 短视频直播 ----
    554: "rtsp", 8554: "rtsp-alt", 1935: "rtmp", 1985: "srs-api", 3478: "stun",
    3479: "stun-alt", 5060: "sip", 5061: "sip-tls", 5080: "sip-alt", 9710: "srt",
    10000: "sip/gb28181", 10008: "easydarwin", 10080: "srs-http", 11935: "rtmp-alt",
    # ---- 电商 / 业务中间件 ----
    1099: "java-rmi", 2888: "zookeeper-peer", 3888: "zookeeper-leader",
    50010: "hdfs-datanode", 50075: "hdfs-http", 8020: "hdfs-namenode",
    8480: "hadoop", 8600: "consul-dns", 8983: "solr", 9060: "websphere",
    9080: "websphere", 9091: "pushgateway", 9100: "node-exporter", 9848: "nacos-grpc",
    9849: "nacos-alt", 9876: "rocketmq", 9990: "jboss-mgmt", 10909: "rocketmq",
    10911: "rocketmq", 16010: "hbase-master", 19888: "hadoop-jobhistory",
    20880: "dubbo", 20881: "dubbo-alt", 25672: "rabbitmq", 61616: "activemq",
}

# 分类端口表：默认扫描全部类别，也可用 --categories 只选其中几类
PORT_CATEGORIES: Dict[str, List[int]] = {
    # 基础服务 / 远程管理 / 文件共享 / 通用 Web
    "base": [
        7, 9, 13, 19, 20, 21, 22, 23, 37, 49, 53, 67, 68, 69, 79, 80, 88, 111, 113,
        119, 123, 135, 137, 138, 139, 161, 162, 179, 389, 427, 443, 445, 464, 500,
        512, 513, 514, 515, 520, 523, 548, 593, 623, 626, 631, 636, 873, 902, 989,
        990, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1720, 1723, 1883, 1900,
        2049, 2082, 2083, 3128, 3268, 3389, 3690, 4369, 4444, 4500, 5001, 5631,
        5900, 5901, 5902, 5985, 5986, 6000, 6666, 6667, 8008, 8009, 8080, 8081,
        8443, 8545, 8880, 8888, 9418, 10000, 5858, 9229,
    ],
    # 邮件服务
    "mail": [
        25, 26, 109, 110, 143, 220, 465, 587, 993, 995, 2095, 2096, 2525, 4190,
        7071, 10024, 10025,
    ],
    # 各类数据库
    "database": [
        1433, 1434, 1521, 1522, 1830, 2638, 3050, 3306, 3307, 3358, 5432, 5433,
        5984, 6379, 6380, 7000, 7001, 7474, 8086, 8123, 8529, 9000, 9042, 9160,
        9200, 9300, 11211, 12000, 2379, 2380, 26257, 27017, 27018, 27019, 28017,
        50000,
    ],
    # AI 大模型 / 推理服务 / 向量数据库
    "ai": [
        1234, 21001, 21002, 19530, 19531, 3000, 3001, 5000, 5001, 6006, 6333, 6334,
        7860, 7861, 8000, 8001, 8002, 8008, 8080, 8082, 8188, 8265, 8500, 8501,
        8888, 8889, 9997, 11434, 11435,
    ],
    # 流媒体 / 短视频直播（RTMP、RTSP、SIP、WebRTC、SRT、GB28181）
    "media": [
        554, 8554, 1935, 1985, 3478, 3479, 5060, 5061, 5080, 8880, 9710, 10000,
        10008, 10080, 11935,
    ],
    # 电商 / 互联网业务中间件与后台（容器编排、消息队列、检索、监控、大数据）
    "ecommerce": [
        1099, 2181, 2888, 3888, 5601, 5672, 61616, 7001, 7002, 8020, 8088, 8161,
        8480, 8600, 8848, 8983, 9001, 9060, 9080, 9090, 9091, 9092, 9093, 9100,
        9848, 9849, 9876, 9990, 10250, 10255, 10909, 10911, 15672, 16010, 19888,
        20880, 20881, 2375, 2376, 25672, 50010, 50070, 50075, 6443,
    ],
}

CATEGORY_ALIASES = {
    "all": "all", "基础": "base", "base": "base", "系统": "base",
    "mail": "mail", "email": "mail", "邮件": "mail", "邮箱": "mail",
    "db": "database", "database": "database", "数据库": "database",
    "ai": "ai", "llm": "ai", "大模型": "ai", "人工智能": "ai", "模型": "ai",
    "media": "media", "video": "media", "stream": "media", "短视频": "media",
    "直播": "media", "流媒体": "media",
    "ecom": "ecommerce", "ecommerce": "ecommerce", "电商": "ecommerce", "业务": "ecommerce",
}

# 默认端口表 = 所有类别的并集
TOP_PORTS = sorted({p for ports in PORT_CATEGORIES.values() for p in ports})


def available_categories() -> List[str]:
    return list(PORT_CATEGORIES.keys())


def ports_by_categories(names: Sequence[str]) -> List[int]:
    """按类别名（支持别名/中文）取端口并集；'all' 或空表示全部。"""
    if not names:
        return list(TOP_PORTS)
    picked: set = set()
    for raw in names:
        token = str(raw).strip()
        key = CATEGORY_ALIASES.get(token.lower()) or CATEGORY_ALIASES.get(token)
        if key == "all":
            return list(TOP_PORTS)
        if key is None:
            LOGGER.warning("忽略未知端口类别：%s", raw)
            continue
        picked.update(PORT_CATEGORIES[key])
    return sorted(picked) if picked else list(TOP_PORTS)


def parse_ports(spec: str) -> List[int]:
    """解析端口表达式：'80,443,8000-8100'。"""
    ports = set()
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                lo, hi = int(start), int(end)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def top_ports(count: int = 200) -> List[int]:
    """返回常见端口列表（不足时用连续端口补齐）。"""
    count = max(1, min(count, 65535))
    ports = list(dict.fromkeys(TOP_PORTS))
    if len(ports) >= count:
        return sorted(ports[:count])
    extra = [p for p in range(1, 65536) if p not in set(ports)]
    return sorted(ports + extra[: count - len(ports)])


def _probe_port(args) -> PortInfo:
    host, port, timeout = args
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return PortInfo(port=port, state="open", service=COMMON_SERVICES.get(port, ""))
    except socket.timeout:
        return PortInfo(port=port, state="filtered", service=COMMON_SERVICES.get(port, ""))
    except (ConnectionRefusedError, OSError):
        return PortInfo(port=port, state="closed", service=COMMON_SERVICES.get(port, ""))
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


def scan_ports(
    host: str,
    ports: Sequence[int],
    workers: int = 200,
    timeout: float = 1.0,
    progress: bool = True,
    processes: int = 0,
    allow_processes: bool = True,
) -> List[PortInfo]:
    """混合并发 TCP connect 扫描：多进程分片 + 每进程内多线程探测。"""
    ports = list(ports)
    if not ports:
        return []
    started = time.time()
    config = parallel.ParallelConfig(processes=processes, threads=workers,
                                     allow_processes=allow_processes)
    LOGGER.info("扫描 %s 的 %d 个端口（并发 %d，超时 %.1fs）...",
                host, len(ports), workers, timeout)
    LOGGER.info(parallel.describe(config, len(ports)))
    raw = parallel.scan_ports_hybrid(host, ports, timeout, workers, config)
    results = [PortInfo(port=p, state=state, service=COMMON_SERVICES.get(p, ""))
               for p, state in raw]
    results.sort(key=lambda r: r.port)
    opened = [r for r in results if r.state == "open"]
    filtered = [r for r in results if r.state == "filtered"]
    LOGGER.info(
        "端口扫描完成：开放 %d，过滤/无响应 %d，耗时 %.1fs",
        len(opened), len(filtered), time.time() - started,
    )
    return results


def nmap_available() -> Optional[str]:
    from .utils import run_command

    code, out, _ = run_command(["nmap", "--version"], timeout=8)
    if code == 0:
        return out.splitlines()[0] if out else "nmap"
    return None
