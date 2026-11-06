# -*- coding: utf-8 -*-
"""服务指纹识别 + 试探性连接（只读探测，不做任何破坏性操作）。

所有探针均为只读命令（PING / stats / 匿名登录探测 / HTTP GET 等），
用于发现"未授权访问"类风险，不会写入或修改目标数据。
"""

from __future__ import annotations

import os
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import ServiceInfo
from .portscan import COMMON_SERVICES
from .utils import LOGGER, safe_text, send_recv, tcp_connect

# 端口 -> 主动探针（部分服务不会主动发送 banner）
PROBE_PAYLOADS: Dict[int, bytes] = {
    21: b"",
    22: b"",
    23: b"",
    25: b"EHLO scanner.invalid\r\n",
    26: b"EHLO scanner.invalid\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: scanner.invalid\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    220: b"a001 CAPABILITY\r\n",
    443: b"",
    465: b"",
    587: b"EHLO scanner.invalid\r\n",
    993: b"",
    995: b"",
    2525: b"EHLO scanner.invalid\r\n",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: scanner.invalid\r\n\r\n",
    8086: b"GET /ping HTTP/1.0\r\nHost: scanner.invalid\r\n\r\n",
    8123: b"GET / HTTP/1.0\r\nHost: scanner.invalid\r\n\r\n",
    11211: b"stats\r\n",
    27017: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}

# 端口 -> 未授权访问探测（名称, 载荷, 成功特征正则, 等级, 修复建议）
UNAUTH_CHECKS: Dict[int, Tuple[str, bytes, bytes, str, str]] = {
    6379: ("Redis 未授权访问", b"INFO\r\n", rb"redis_version|# Server|loading:0", "high",
           "启用 requirepass / ACL，并仅监听内网地址"),
    11211: ("Memcached 未授权访问", b"stats\r\n", rb"STAT ", "high",
            "仅监听内网，启用 SASL 或防火墙限制 11211 端口"),
    2181: ("ZooKeeper 未授权访问（四字命令可用）", b"srvr\r\n", rb"Zookeeper version|Latency min", "medium",
           "启用 SASL 认证并限制 2181 端口访问来源"),
    873: ("rsync 未授权访问", b"#list\r\n", rb"@RSYNCD", "medium",
          "配置 rsync 认证与 hosts allow，禁止对外暴露"),
    9200: ("Elasticsearch 未授权访问", b"GET / HTTP/1.0\r\n\r\n",
           rb"cluster_name|lucene_version|You Know, for Search", "high",
           "启用 X-Pack/OpenSearch Security 并限制访问来源"),
    2375: ("Docker Remote API 未授权访问", b"GET /version HTTP/1.0\r\n\r\n",
           rb"ApiVersion|\"Version\":|Docker", "critical",
           "改用 2376 TLS 端口并做双向证书认证，禁止 2375 对外"),
    2376: ("Docker TLS API 可达", b"GET /version HTTP/1.0\r\n\r\n",
           rb"ApiVersion|Docker", "low",
           "确认已启用双向证书认证并限制来源 IP"),
    10250: ("Kubelet API 未授权访问", b"GET /pods HTTP/1.0\r\n\r\n",
            rb"\"items\"|kubelet", "critical",
            "启用 kubelet 认证授权（--anonymous-auth=false）"),
    10255: ("Kubelet 只读端口未授权访问", b"GET /pods HTTP/1.0\r\n\r\n",
            rb"\"items\"|\"kind\"", "high",
            "关闭 10255 只读端口或限制来源"),
    27017: ("MongoDB 未授权访问", b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            rb"MongoDB|mongodb|buildInfo", "high",
            "启用 --auth 并绑定内网地址"),
    28017: ("MongoDB HTTP 状态接口暴露", b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            rb"MongoDB|buildInfo", "medium",
            "关闭 mongod 的 httpinterface 与 rest 选项"),
    5900: ("VNC 无需认证即可连接", b"", rb"RFB ", "high",
           "设置 VNC 强口令，仅限 VPN/内网访问"),
    21: ("FTP 允许匿名登录", b"USER anonymous\r\nPASS anonymous@example.com\r\n",
         rb"230 ", "medium",
         "关闭匿名登录（anonymous_enable=NO）"),
    25: ("SMTP 开放中继风险（可查询）", b"VRFY root\r\n", rb"250 |252 ", "low",
         "禁用 VRFY/EXPN，配置中继鉴权"),
    4848: ("GlassFish 管理接口暴露", b"GET / HTTP/1.0\r\n\r\n", rb"GlassFish|Sun Java System", "medium",
           "修改管理员口令并限制管理口访问"),
    8161: ("ActiveMQ 管理台暴露", b"GET / HTTP/1.0\r\n\r\n", rb"ActiveMQ", "medium",
           "修改默认口令 admin/admin 并限制访问"),
    15672: ("RabbitMQ 管理台暴露", b"GET / HTTP/1.0\r\n\r\n", rb"RabbitMQ Management", "medium",
            "修改默认口令 guest/guest 并限制访问"),
    8500: ("Consul 未授权访问", b"GET /v1/agent/self HTTP/1.0\r\n\r\n", rb"Config|Member", "medium",
           "启用 ACL Token 并限制 8500 端口"),
    2379: ("etcd 未授权访问", b"GET /version HTTP/1.0\r\n\r\n", rb"etcdserver|etcdcluster", "high",
           "启用 etcd 客户端证书认证"),
    8443: ("HTTPS 管理接口暴露", b"GET / HTTP/1.0\r\nHost: scanner.invalid\r\n\r\n", rb"", "info", ""),
    # ---- 流媒体 / 直播 ----
    554: ("RTSP 流媒体未授权访问（可直接拉流）",
          b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: VulnScanner/1.0\r\n\r\n",
          rb"RTSP/1\.0\s+200", "high",
          "为 RTSP 配置鉴权（用户名/口令或 IP 白名单），禁止对公网开放"),
    1935: ("RTMP 服务可匿名完成握手（推/拉流未鉴权）", b"", rb"", "medium",
           "配置 RTMP publish/play 鉴权与 IP 白名单，避免被非法推流或盗链"),
    # SIP：TARGET 会在运行时替换为目标地址
    5060: ("SIP 服务可匿名响应（可能被恶意注册/盗打）",
           b"OPTIONS sip:scanner@TARGET SIP/2.0\r\n"
           b"Via: SIP/2.0/UDP scanner.invalid;branch=z9hG4bKscan1\r\n"
           b"Max-Forwards: 70\r\nTo: <sip:scanner@TARGET>\r\n"
           b"From: <sip:scanner@scanner.invalid>;tag=scan1\r\n"
           b"Call-ID: scan1@scanner.invalid\r\nCSeq: 1 OPTIONS\r\n"
           b"Contact: <sip:scanner@scanner.invalid>\r\nContent-Length: 0\r\n\r\n",
           rb"SIP/2\.0\s+(200|180|100)", "medium",
           "启用 SIP 注册鉴权、限制来源 IP 并关闭国际/高费号段呼出"),
    # ---- 电商 / RPC 框架 ----
    20880: ("Dubbo 服务未授权访问（Telnet 可枚举服务并调用）", b"ls\r\n",
            rb"dubbo>|PROVIDER|CONSUMER|service", "high",
            "关闭 Dubbo QoS/telnet 端口或配置鉴权，禁止 20880 对外暴露"),
}

# 端口族：同类服务的备用端口复用主端口的探测规则
PORT_FAMILY: Dict[int, int] = {
    26: 25, 2525: 25, 587: 25,
    3307: 3306, 3358: 3306,
    5433: 5432,
    6380: 6379,
    11435: 11434,
    7861: 7860,
    8889: 8888,
    8554: 554,
    20881: 20880,
    27018: 27017, 27019: 27017,
    8082: 8000,
    19531: 19530,
    10080: 1985,
}

# 需要特殊交互（非规则匹配）的探测：端口 -> 判定函数
SPECIAL_CHECKS: Dict[int, Callable[[str, int, float], bool]] = {}

# 基于 HTTP 的未授权访问探测
# 端口 -> [(路径, 命中正则(空表示仅看 2xx), 标题, 等级, 修复建议), ...]
HTTP_UNAUTH_PROBES: Dict[int, List[Tuple[str, str, str, str, str]]] = {
    # ---------- AI 大模型 / 推理 / 向量库 ----------
    11434: [("/api/tags", r'"models"|"digest"', "Ollama 大模型接口未授权访问", "high",
             "禁止 11434 对外：绑定 127.0.0.1 或加反向代理认证/防火墙")],
    1234: [("/v1/models", r'"data"|"object"', "LM Studio 本地大模型接口未授权访问", "high",
            "仅在回环地址监听，或加认证网关")],
    8000: [
        ("/v1/models", r'"data"\s*:|"object"\s*:\s*"list"', "vLLM / OpenAI 兼容推理接口未授权访问",
         "high", "为推理接口增加 API Key 或网关鉴权，限制来源 IP"),
        ("/api/v1/heartbeat", r"nanosecond|heartbeat", "Chroma 向量库未授权访问", "medium",
         "启用 Chroma 认证并仅监听内网"),
    ],
    8001: [("/v2/health/ready", r"", "Triton Inference Server 未授权访问", "medium",
            "限制 8001 端口来源并启用网关鉴权")],
    8188: [("/", r"ComfyUI|comfy", "ComfyUI 未授权访问", "medium",
            "设置 ComfyUI 访问口令或仅内网监听")],
    8265: [("/", r"Ray|ray", "Ray 集群 Dashboard 未授权访问", "high",
            "限制 8265 端口来源 IP，启用 Ray Dashboard 鉴权")],
    7860: [("/", r"Gradio|Stable Diffusion|sd-webui", "Gradio/SD WebUI 未授权访问", "medium",
            "设置 --gradio-auth 或反向代理认证")],
    8888: [("/", r"jupyter|Jupyter", "Jupyter Notebook 未授权访问（缺少 token/口令）", "high",
            "设置 NotebookApp.token/密码，绑定内网并用 SSH 隧道访问")],
    8501: [("/", r"Streamlit|streamlit", "Streamlit 应用未授权访问", "low",
            "为 Streamlit 配置认证或仅内网访问")],
    6006: [("/", r"TensorBoard|tensorboard", "TensorBoard 未授权访问", "medium",
            "仅内网监听或加反向代理认证")],
    9997: [("/", r"Xinference|xinference", "Xinference 未授权访问", "high",
            "限制 9997 端口来源 IP 并启用认证")],
    6333: [("/collections", r'"collections"|"result"', "Qdrant 向量库未授权访问", "high",
            "启用 Qdrant API Key 并禁止公网访问")],
    8080: [("/v1/meta", r'"version"|"weaviate"', "Weaviate 向量库未授权访问", "high",
            "启用 Weaviate 认证并限制来源")],
    3000: [
        ("/api/health", r"Grafana|grafana|\"database\"", "Grafana 未授权访问（注意默认 admin/admin）",
         "medium", "修改 Grafana 默认口令并限制访问来源"),
        ("/", r"Open WebUI|open-webui", "Open WebUI 未授权访问", "medium",
            "设置管理员账号并限制访问来源"),
    ],
    5000: [("/", r"MLflow|mlflow", "MLflow 未授权访问", "medium",
            "为 MLflow 配置认证与访问控制")],
    # ---------- 电商 / 中间件 / 监控 ----------
    8848: [("/nacos/v1/auth/users?pageNo=1&pageSize=10", r'"username"|"totalCount"|"pageItems"',
            "Nacos 未授权访问（可列出用户/配置）", "critical",
            "开启 Nacos 鉴权（nacos.core.auth.enabled=true）并修改默认密钥与口令")],
    8983: [("/solr/admin/cores?wt=json", r'"status"|"name"', "Solr Admin API 未授权访问", "high",
            "为 Solr 启用认证并禁止 8983 对外")],
    7001: [("/console", r"WebLogic|Console", "WebLogic 控制台未授权访问", "high",
            "修改控制台口令并限制管理口来源 IP")],
    9990: [("/", r"JBoss|WildFly|Management", "JBoss/WildFly 管理台未授权访问", "high",
            "删除默认管理用户或限制 9990 端口来源")],
    9001: [("/", r"Supervisor|supervisor", "Supervisor 管理台未授权访问", "high",
            "设置用户名口令并仅内网监听")],
    9100: [("/metrics", r"node_|go_", "node-exporter 指标接口未授权暴露", "low",
            "限制 9100 端口仅内网采集器访问")],
    9090: [("/-/healthy", r"Prometheus is Healthy|Prometheus", "Prometheus 未授权访问", "medium",
            "限制 9090 端口来源，必要时加反向代理认证")],
    5601: [("/api/status", r'"status"', "Kibana 未授权访问", "medium",
            "启用 Elasticsearch/Kibana 安全认证")],
    8161: [("/", r"ActiveMQ", "ActiveMQ 管理台未授权访问（默认 admin/admin）", "high",
            "修改默认口令并限制 8161 端口来源")],
    15672: [("/", r"RabbitMQ", "RabbitMQ 管理台未授权访问（默认 guest/guest）", "high",
             "删除/修改默认 guest 账户并限制来源")],
    9000: [("/minio/health/live", r"", "MinIO 对象存储未授权访问", "high",
            "设置 MINIO_ROOT_PASSWORD 强口令并限制来源")],
    # ---------- 数据库 HTTP 接口 ----------
    8123: [("/?query=SELECT%20version()", r"\d+\.\d+\.\d+", "ClickHouse HTTP 接口未授权访问", "high",
            "为 ClickHouse 设置用户口令并限制 8123 来源")],
    8086: [("/ping", r"", "InfluxDB 未授权访问", "medium",
            "启用 InfluxDB 认证并限制 8086 来源")],
    5984: [("/_all_dbs", r"\[", "CouchDB 未授权访问（可列出全部数据库）", "high",
            "配置 CouchDB 管理员口令（禁用 admin party）")],
    7474: [("/", r"neo4j|Neo4j", "Neo4j 浏览器未授权访问", "medium",
            "修改 neo4j 默认口令并限制来源")],
    2379: [("/version", r'"etcdserver"|"etcdcluster"', "etcd 未授权访问", "critical",
            "启用 etcd 客户端证书认证并限制来源")],
    # ---------- 流媒体 ----------
    1985: [("/api/v1/streams", r'"streams"|"code"\s*:\s*0', "SRS 流媒体管理 API 未授权访问", "high",
            "配置 SRS http_api 鉴权并限制 1985 端口来源")],
    # ---- Node.js 调试端口 ----
    9229: [("/json/list", r'"id"\s*:|"type"\s*:\s*"page"|"webSocketDebuggerUrl"',
            "Node.js Inspector 调试端口未授权访问（可通过 DevTools 协议执行任意代码）", "critical",
            "禁止 --inspect 监听 0.0.0.0，仅绑定 127.0.0.1，并用防火墙限制 9229")],
    5858: [("/json/list", r'"id"\s*:|"webSocketDebuggerUrl"',
            "Node.js 旧版调试端口未授权访问", "high",
            "关闭旧 debug 端口，改用 --inspect 并仅绑定回环地址")],
}

# 端口 -> (路径, 版本正则(含分组))
HTTP_VERSION_PROBES: Dict[int, Tuple[str, str]] = {
    11434: ("/api/version", r'"version"\s*:\s*"([^"]+)"'),
    8265: ("/api/version", r'"ray_version"\s*:\s*"([^"]+)"'),
    6333: ("/", r'"version"\s*:\s*"([\d.]+)"'),
    8123: ("/?query=SELECT%20version()", r"(\d+\.\d+\.\d+[\w.-]*)"),
    8086: ("/ping", r"(?i)X-Influxdb-Version:\s*([\d.]+)"),
    5984: ("/", r'"version"\s*:\s*"([\d.]+)"'),
    7474: ("/", r'"version"\s*:\s*"([\d.]+)"'),
    8983: ("/solr/admin/info/system?wt=json", r'"solr-spec-version"\s*:\s*"([\d.]+)"'),
    2379: ("/version", r'"etcdserver"\s*:\s*"([\d.]+)"'),
}

# HTTP 探测命中后用于标注产品名（辅助报告展示）
PORT_PRODUCT_HINTS: Dict[int, str] = {
    11434: "ollama", 1234: "lm-studio", 8000: "vllm", 8001: "triton", 8002: "vllm",
    8188: "comfyui", 8265: "ray", 7860: "gradio", 8888: "jupyter", 8501: "streamlit",
    6006: "tensorboard", 9997: "xinference", 6333: "qdrant", 8080: "weaviate",
    3000: "grafana", 8848: "nacos", 8983: "solr", 7001: "weblogic", 9990: "jboss",
    9001: "supervisor", 9100: "node-exporter", 9090: "prometheus", 5601: "kibana",
    8161: "activemq", 15672: "rabbitmq", 9000: "minio", 8123: "clickhouse",
    8086: "influxdb", 5984: "couchdb", 7474: "neo4j", 2379: "etcd", 1985: "srs",
    5000: "mlflow", 19530: "milvus", 9229: "node-inspector", 5858: "node-debug",
}

# 优先使用 TLS 的端口
TLS_FIRST_PORTS = {443, 6443, 8443, 9443, 10250, 2376, 5061}

# 端口 -> 补充说明（仅提示，不判定为未授权）
SERVICE_NOTES: Dict[int, str] = {
    25: "SMTP 服务：确认未开启开放中继（VRFY/EXPN 已禁用），启用 STARTTLS 并配置 SPF/DKIM/DMARC",
    26: "SMTP 服务（备用端口）：确认中继鉴权与 TLS 配置",
    110: "POP3 明文传输：建议改用 POP3S(995) 并禁用明文认证",
    143: "IMAP 明文传输：建议改用 IMAPS(993) 并禁用明文认证",
    465: "SMTPS 端口：确认 TLS 配置正确",
    587: "邮件提交端口：必须启用 STARTTLS 与发信鉴权",
    993: "IMAPS 端口：确认 TLS 版本不低于 1.2",
    995: "POP3S 端口：确认 TLS 版本不低于 1.2",
    4190: "ManageSieve 端口：限制来源并启用 TLS",
    7071: "Zimbra 管理端口：限制来源 IP 并加固管理员口令",
    1433: "MSSQL：限制来源 IP，禁用 sa 或设置强口令",
    1521: "Oracle 监听：限制来源 IP 并加固口令，关闭不必要的 TNS 服务",
    3306: "MySQL：限制来源 IP，禁止 root 远程登录，禁用 old_passwords",
    5432: "PostgreSQL：正确配置 pg_hba.conf 限制来源",
    27017: "MongoDB：启用 --auth 并绑定内网地址",
    9200: "Elasticsearch：启用安全认证并限制来源",
    1935: "RTMP 直播端口：配置推流/拉流鉴权，避免被非法推流",
    554: "RTSP 端口：配置鉴权，避免摄像头/视频流被匿名拉取",
    5060: "SIP 端口：启用注册鉴权并限制来源 IP，防止盗打与恶意注册",
    3478: "STUN/TURN 端口：启用 TURN 鉴权，避免被用作反射放大",
    8848: "Nacos：必须开启鉴权并替换默认密钥",
    2181: "ZooKeeper：启用 SASL 认证并限制来源",
    9092: "Kafka：启用 SASL/SSL 认证与 ACL",
    9876: "RocketMQ：启用 ACL 鉴权并限制来源",
    20880: "Dubbo：关闭 QoS/telnet 或配置鉴权，防止通过 telnet 调用服务",
    1099: "Java RMI 注册端口：禁止对外，存在反序列化利用风险",
    10250: "Kubelet API：关闭匿名访问（--anonymous-auth=false）",
    6443: "Kubernetes API：启用鉴权并限制来源 IP",
    16010: "HBase Master Web：启用认证或仅内网访问",
    50070: "HDFS NameNode Web：启用 Kerberos 认证，禁止对外",
    5000: "5000 端口常用于 Docker Registry 或推理服务，请确认用途并限制来源",
    3000: "3000 端口常用于 Grafana/Open WebUI 等后台，确认已设置强口令",
}

# 指纹正则：(正则, 产品名, 版本分组序号, 服务名)
FINGERPRINTS: List[Tuple[bytes, str, int, str]] = [
    (rb"OpenSSH[_-]?([\d.]+p?\d*)", "openssh", 1, "ssh"),
    (rb"SSH-[\d.]+-libssh[_-]?([\d.]+)", "libssh", 1, "ssh"),
    (rb"vsftpd\s*([\d.]+)", "vsftpd", 1, "ftp"),
    (rb"ProFTPD\s*([\d.]+)", "proftpd", 1, "ftp"),
    (rb"FileZilla Server\s*([\d.]+)", "filezilla", 1, "ftp"),
    (rb"pure-ftpd", "pure-ftpd", 0, "ftp"),
    (rb"220.*Microsoft FTP Service", "ms-ftpd", 0, "ftp"),
    (rb"Postfix", "postfix", 0, "smtp"),
    (rb"Exim\s*([\d.]+)", "exim", 1, "smtp"),
    (rb"Sendmail\s*([\w./]+)", "sendmail", 1, "smtp"),
    (rb"Dovecot", "dovecot", 0, "imap/pop3"),
    # Java / Go / Python 组件需放在通用 Apache 规则之前，避免 "Apache Tomcat/9.x" 被识别成 httpd
    (rb"Server:\s*Apache\s*Tomcat/?([\d.]*)", "tomcat", 1, "http"),
    (rb"Server:\s*Apache-Coyote/[\d.]+", "tomcat", 0, "http"),
    (rb"Server:\s*Apache/?([\d.]*)", "httpd", 1, "http"),
    (rb"Server:\s*nginx/?([\d.]*)", "nginx", 1, "http"),
    (rb"Server:\s*Microsoft-IIS/?([\d.]*)", "iis", 1, "http"),
    (rb"Server:\s*openresty/?([\d.]*)", "openresty", 1, "http"),
    (rb"Server:\s*lighttpd/?([\d.]*)", "lighttpd", 1, "http"),
    (rb"Server:\s*Envoy", "envoy", 0, "http"),
    (rb"Server:\s*Werkzeug/([\d.]+)", "werkzeug", 1, "http"),
    (rb"Server:\s*gunicorn/([\d.]+)", "gunicorn", 1, "http"),
    (rb"Server:\s*TornadoServer/([\d.]+)", "tornado", 1, "http"),
    (rb"Python/([\d.]+)", "python", 1, "http"),
    (rb"Java/([\d._]+)", "openjdk", 1, "http"),
    (rb"X-Powered-By:\s*PHP/?([\d.]*)", "php", 1, "http"),
    (rb"X-Powered-By:\s*ASP\.NET", "aspnetcore", 0, "http"),
    (rb"X-AspNet-Version:\s*([\d.]+)", "dotnet", 1, "http"),
    (rb"X-AspNetMvc-Version:\s*([\d.]+)", "aspnetcore", 1, "http"),
    (rb"Server:\s*Microsoft-IIS/([\d.]+)", "iis", 1, "http"),
    (rb"Server:\s*Kestrel", "aspnetcore", 0, "http"),
    (rb"X-Powered-By:\s*Express", "express", 0, "http"),
    (rb"X-Powered-By:\s*Next\.js|Next\.js", "next", 0, "http"),
    (rb"X-Powered-By:\s*Nuxt", "nuxt", 0, "http"),
    (rb"X-Powered-By:\s*Nest|NestJS", "nestjs", 0, "http"),
    (rb"X-Jenkins:\s*([\d.]+)", "jenkins", 1, "http"),
    (rb"Apache[- ]Tomcat/?([\d.]*)", "tomcat", 1, "http"),
    (rb"Jetty\(?([\d.]*)", "jetty", 1, "http"),
    (rb"WebLogic", "weblogic", 0, "http"),
    (rb"JBoss|WildFly", "jboss", 0, "http"),
    (rb"Elasticsearch", "elasticsearch", 0, "http"),
    (rb"Docker", "docker", 0, "docker"),
    (rb"etcdserver", "etcd", 0, "etcd"),
    (rb"redis_version:([\d.]+)", "redis", 1, "redis"),
    (rb"MongoDB", "mongodb", 0, "mongodb"),
    (rb"RFB\s*([\d.]+)", "vnc", 1, "vnc"),
    (rb"MySQL", "mysql", 0, "mysql"),
    (rb"MariaDB", "mariadb", 0, "mysql"),
    (rb"PostgreSQL", "postgresql", 0, "postgresql"),
    (rb"@RSYNCD:\s*([\d.]+)", "rsync", 1, "rsync"),
    (rb"Zookeeper version:\s*([\d.]+)", "zookeeper", 1, "zookeeper"),
    (rb"Microsoft Windows", "windows", 0, ""),
    (rb"Ubuntu", "ubuntu", 0, ""),
    (rb"Debian", "debian", 0, ""),
    (rb"CentOS", "centos", 0, ""),
    # ---- 邮件 ----
    (rb"220\s+\S+\s+ESMTP\s+Postfix", "postfix", 0, "smtp"),
    (rb"220\s+\S+\s+ESMTP\s+Exim\s*([\d.]+)", "exim", 1, "smtp"),
    (rb"\+OK.*Dovecot", "dovecot", 0, "pop3"),
    (rb"\* OK.*Dovecot", "dovecot", 0, "imap"),
    (rb"\+OK.*Courier", "courier", 0, "pop3"),
    (rb"\* OK.*Cyrus", "cyrus", 0, "imap"),
    (rb"Zimbra", "zimbra", 0, "mail"),
    # ---- 数据库 ----
    (rb"ClickHouse", "clickhouse", 0, "clickhouse"),
    (rb"InfluxDB", "influxdb", 0, "influxdb"),
    (rb"CouchDB|\"couchdb\"", "couchdb", 0, "couchdb"),
    (rb"Neo4j", "neo4j", 0, "neo4j"),
    (rb"\"neo4j_version\"\s*:\s*\"([\d.]+)\"", "neo4j", 1, "neo4j"),
    (rb"ArangoDB", "arangodb", 0, "arangodb"),
    (rb"Elasticsearch", "elasticsearch", 0, "elasticsearch"),
    # ---- AI 大模型 / 推理 / 向量库 ----
    (rb"Ollama|ollama", "ollama", 0, "ollama"),
    (rb"ComfyUI|comfy", "comfyui", 0, "comfyui"),
    (rb"Gradio", "gradio", 0, "gradio"),
    (rb"Jupyter|jupyter", "jupyter", 0, "jupyter"),
    (rb"ray_version|Ray Dashboard|raylet", "ray", 0, "ray"),
    (rb"Qdrant|qdrant", "qdrant", 0, "qdrant"),
    (rb"Xinference|xinference", "xinference", 0, "xinference"),
    (rb"Milvus", "milvus", 0, "milvus"),
    (rb"TensorBoard|tensorboard", "tensorboard", 0, "tensorboard"),
    (rb"MLflow", "mlflow", 0, "mlflow"),
    (rb"Streamlit", "streamlit", 0, "streamlit"),
    (rb"Stable Diffusion|sd-webui|AUTOMATIC1111", "sd-webui", 0, "sd-webui"),
    (rb"Open WebUI|open-webui", "open-webui", 0, "open-webui"),
    (rb"vLLM", "vllm", 0, "vllm"),
    # ---- 流媒体 ----
    (rb"RTSP/1\.0\s+200", "rtsp", 0, "rtsp"),
    (rb"Wowza|WowzaStreamingEngine", "wowza", 0, "rtmp"),
    (rb"SRS/|srs/", "srs", 0, "rtmp"),
    (rb"SIP/2\.0\s+200", "sip", 0, "sip"),
    (rb"Asterisk|FreeSWITCH|OpenSIPS|Kamailio", "sip-server", 0, "sip"),
    (rb"EasyDarwin", "easydarwin", 0, "rtsp"),
    # ---- 电商 / 中间件 ----
    (rb"RabbitMQ", "rabbitmq", 0, "rabbitmq"),
    (rb"ActiveMQ", "activemq", 0, "activemq"),
    (rb"Apache Solr|Solr", "solr", 0, "solr"),
    (rb"Nacos", "nacos", 0, "nacos"),
    (rb"Kibana", "kibana", 0, "kibana"),
    (rb"Grafana", "grafana", 0, "grafana"),
    (rb"Prometheus", "prometheus", 0, "prometheus"),
    (rb"MinIO|minio", "minio", 0, "minio"),
    (rb"Dubbo", "dubbo", 0, "dubbo"),
    (rb"RocketMQ", "rocketmq", 0, "rocketmq"),
    (rb"Hadoop", "hadoop", 0, "hadoop"),
    (rb"HBase", "hbase", 0, "hbase"),
    (rb"Supervisor", "supervisor", 0, "supervisor"),
]


def _parse_mysql(data: bytes) -> Tuple[str, str]:
    """解析 MySQL/MariaDB 握手包中的版本字符串。

    报文结构：3 字节长度 + 1 字节序号 + 1 字节协议版本 + NUL 结尾的版本字符串。
    """
    if len(data) < 7:
        return "", ""
    idx = data.find(b"\x00", 5)
    if idx <= 5:
        return "", ""
    raw = data[5:idx].decode("utf-8", errors="replace")
    if not re.match(r"^\d+\.\d", raw):
        return "", ""
    product = "mariadb" if "mariadb" in raw.lower() else "mysql"
    return product, raw


def _parse_redis(data: bytes) -> Tuple[str, str]:
    match = re.search(rb"redis_version:([\d.]+)", data)
    if match:
        return "redis", match.group(1).decode()
    if b"+PONG" in data:
        return "redis", ""
    return "", ""


def _vnc_no_auth(host: str, port: int, timeout: float) -> bool:
    """VNC：读取安全类型，判断是否允许无认证连接。"""
    sock = tcp_connect(host, port, timeout)
    if sock is None:
        return False
    try:
        banner = sock.recv(64)
        if not banner.startswith(b"RFB "):
            return False
        sock.sendall(banner)  # 客户端回应相同版本
        sock.settimeout(timeout)
        info = sock.recv(64)
        if len(info) < 2:
            return False
        count = info[0]
        types = list(info[1:1 + count])
        return 1 in types  # 1 = None（无认证）
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def _rtmp_handshake(host: str, port: int, timeout: float) -> bool:
    """RTMP：发送 C0+C1，若服务端回 S0(0x03) 说明可匿名完成握手。"""
    sock = tcp_connect(host, port, timeout)
    if sock is None:
        return False
    try:
        c0c1 = bytes([0x03]) + (0).to_bytes(4, "big") + (0).to_bytes(4, "big") + os.urandom(1528)
        sock.sendall(c0c1)
        data = sock.recv(3073)
        return data[:1] == b"\x03"
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


SPECIAL_CHECKS[5900] = _vnc_no_auth
SPECIAL_CHECKS[1935] = _rtmp_handshake


def fingerprint(data: bytes, port: int) -> Tuple[str, str, str]:
    """从 banner/响应中识别服务名、产品与版本。"""
    name = COMMON_SERVICES.get(port, "")
    product, version = "", ""

    if port == 3306 and data:
        product, version = _parse_mysql(data)
    if port in (6379, 16379) and data:
        product, version = _parse_redis(data)

    for pattern, prod, group, svc in FINGERPRINTS:
        match = re.search(pattern, data, re.IGNORECASE)
        if not match:
            continue
        if not product:
            product = prod
        if group and not version and match.groups():
            try:
                version = match.group(group).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                version = ""
        if svc:
            name = svc
        break
    return name, product, version


def _http_unauth(host: str, port: int, timeout: float) -> Optional[Tuple[str, str, str, str]]:
    """基于 HTTP 的未授权访问探测，返回 (标题, 等级, 修复建议, 证据)。"""
    from .webscan import http_request

    specs = HTTP_UNAUTH_PROBES.get(port) or HTTP_UNAUTH_PROBES.get(PORT_FAMILY.get(port, 0), [])
    if not specs:
        return None
    schemes = (True, False) if port in TLS_FIRST_PORTS else (False, True)
    for path, pattern, title, severity, fix in specs:
        for use_tls in schemes:
            status, headers, body, err = http_request(
                host, port, path, use_tls=use_tls, timeout=timeout, max_body=8192
            )
            if not status:
                continue  # 换一种协议再试
            if 200 <= status < 300:
                text = safe_text(body, 8192)
                if not pattern or re.search(pattern, text, re.IGNORECASE):
                    evidence = text[:180].replace("\n", " ")
                    return title, severity, fix, f"GET {'https' if use_tls else 'http'}://{host}:{port}{path} -> {status} | {evidence}"
            break  # 已有响应但未命中，无需再换协议
    return None


def _http_version(host: str, port: int, timeout: float) -> str:
    """通过 HTTP 接口补全服务版本。"""
    from .webscan import http_request

    spec = HTTP_VERSION_PROBES.get(port) or HTTP_VERSION_PROBES.get(PORT_FAMILY.get(port, 0))
    if not spec:
        return ""
    path, pattern = spec
    schemes = (True, False) if port in TLS_FIRST_PORTS else (False, True)
    for use_tls in schemes:
        status, headers, body, err = http_request(
            host, port, path, use_tls=use_tls, timeout=timeout, max_body=8192
        )
        if not status:
            continue
        # 先在响应体中匹配，再在响应头中匹配（避免把 Server 头里的版本号当成服务版本）
        body_text = safe_text(body, 8192)
        head_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
        for text in (body_text, head_text):
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        break
    return ""


def probe_service(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
    """对单个开放端口做指纹识别与试探性连接。"""
    family = PORT_FAMILY.get(port, port)
    payload = PROBE_PAYLOADS.get(port, PROBE_PAYLOADS.get(family, b""))
    data = send_recv(host, port, payload=payload, timeout=timeout)
    if not data:
        # 兜底：再发一个空探针
        data = send_recv(host, port, payload=b"", timeout=timeout, read_first=True)

    name, product, version = fingerprint(data, port)
    info = ServiceInfo(
        port=port,
        name=name or COMMON_SERVICES.get(port, "unknown"),
        product=product,
        version=version,
        banner=safe_text(data, 300),
    )

    # 试探性连接 1：基于协议的未授权访问检测
    check = UNAUTH_CHECKS.get(port) or UNAUTH_CHECKS.get(family)
    if check:
        title, probe, expect, severity, fix = check
        resp = b""
        special = SPECIAL_CHECKS.get(port) or SPECIAL_CHECKS.get(family)
        if special is not None:
            hit = special(host, port, timeout)
        else:
            if b"TARGET" in probe:
                probe = probe.replace(b"TARGET", host.encode("utf-8", "ignore"))
            resp = send_recv(host, port, payload=probe, timeout=timeout)
            hit = bool(expect) and bool(re.search(expect, resp, re.IGNORECASE))
        if hit:
            info.unauth = True
            info.extra["unauth_title"] = title
            info.extra["unauth_severity"] = severity
            info.extra["unauth_fix"] = fix
            # 从 INFO 响应中补全 Redis 版本
            if family in (6379,) and not info.version:
                m = re.search(rb"redis_version:([\d.]+)", resp)
                if m:
                    info.version = m.group(1).decode("utf-8", errors="replace")
            LOGGER.warning("  [!] %s:%d %s", host, port, title)

    # 试探性连接 2：基于 HTTP 的未授权访问检测（AI/中间件/数据库 HTTP 接口）
    if not info.unauth and (port in HTTP_UNAUTH_PROBES or family in HTTP_UNAUTH_PROBES):
        try:
            hit = _http_unauth(host, port, timeout)
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("HTTP 探测 %s:%d 异常：%s", host, port, exc)
            hit = None
        if hit:
            title, severity, fix, evidence = hit
            info.unauth = True
            info.extra["unauth_title"] = title
            info.extra["unauth_severity"] = severity
            info.extra["unauth_fix"] = fix
            info.extra["unauth_evidence"] = evidence
            if not info.banner:
                info.banner = evidence[:300]
            if not info.product:
                info.product = PORT_PRODUCT_HINTS.get(port) or PORT_PRODUCT_HINTS.get(family, "")
            LOGGER.warning("  [!] %s:%d %s", host, port, title)

    # 通过 HTTP 接口补全版本
    if not info.version and (port in HTTP_VERSION_PROBES or family in HTTP_VERSION_PROBES):
        try:
            ver = _http_version(host, port, timeout)
        except Exception:  # noqa: BLE001
            ver = ""
        if ver:
            info.version = ver
            if not info.product:
                info.product = PORT_PRODUCT_HINTS.get(port) or PORT_PRODUCT_HINTS.get(family, "")

    # 补充说明
    note = SERVICE_NOTES.get(port) or SERVICE_NOTES.get(family, "")
    if port in (135, 139, 445):
        note = "Windows 网络共享/SMB 端口，建议确认 SMBv1 已禁用并安装 MS17-010 补丁"
    elif port == 3389:
        note = "远程桌面端口，建议仅允许 VPN 访问并启用 NLA 与账户锁定策略"
    elif port == 23:
        note = "Telnet 明文传输，建议关闭并改用 SSH"
    elif port in (5900, 5901, 5902):
        note = (note + " VNC 建议置于内网或 VPN 后").strip()
    if note:
        info.extra["note"] = note
    return info


def probe_services(host: str, ports: List[int], timeout: float = 2.0, workers: int = 30) -> List[ServiceInfo]:
    from .utils import map_parallel

    def _task(port: int) -> ServiceInfo:
        return probe_service(host, port, timeout)

    results = map_parallel(_task, ports, workers=workers)
    results.sort(key=lambda s: s.port)
    return results
