# -*- coding: utf-8 -*-
"""Web / App 应用漏洞扫描（非破坏性请求）。

检测内容：HTTPS、TLS 配置、安全响应头、Cookie 属性、敏感文件/目录、
管理后台暴露、HTTP 方法、目录列表、中间件版本 CVE 匹配等。
"""

from __future__ import annotations

import http.client
import re
import ssl
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import parallel
from .models import Finding, WebInfo
from .utils import LOGGER, safe_text, ssl_context
from .vulndb import match_rules, normalize_product

# 可能承载 HTTP 服务的端口
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8880, 8888, 9000, 9090, 9200, 9443, 80}

SECURITY_HEADERS = {
    "content-security-policy": ("缺少 Content-Security-Policy 响应头", "low",
                                "配置 CSP 以降低 XSS 影响面"),
    "x-frame-options": ("缺少 X-Frame-Options 响应头（点击劫持风险）", "low",
                        "添加 X-Frame-Options: SAMEORIGIN 或 CSP frame-ancestors"),
    "x-content-type-options": ("缺少 X-Content-Type-Options 响应头", "low",
                               "添加 X-Content-Type-Options: nosniff"),
    "referrer-policy": ("缺少 Referrer-Policy 响应头", "info",
                        "添加 Referrer-Policy: no-referrer-when-downgrade 或更严格策略"),
    "permissions-policy": ("缺少 Permissions-Policy 响应头", "info",
                           "按需声明 Permissions-Policy"),
}

# 敏感路径：(路径, 命中正则, 说明, 等级, 修复建议)
SENSITIVE_PATHS = [
    ("/.git/config", r"\[core\]|repositoryformatversion", "Git 仓库配置文件泄露", "critical",
     "禁止 Web 目录访问 .git，或删除站点目录下的 .git"),
    ("/.git/HEAD", r"ref:\s*refs/heads", "Git 目录可访问", "high", "删除或屏蔽 .git 目录"),
    ("/.svn/entries", r"svn|dir", "SVN 元数据泄露", "high", "删除或屏蔽 .svn 目录"),
    ("/.env", r"(APP_|DB_|SECRET|API_KEY|PASSWORD|TOKEN)\w*=", "环境变量/密钥文件泄露", "critical",
     "禁止访问 .env，立即轮换其中的密钥"),
    ("/.DS_Store", r"Bud1", ".DS_Store 文件泄露", "low", "删除站点目录中的 .DS_Store"),
    ("/web.config", r"<configuration", "web.config 配置文件泄露", "medium", "禁止下载配置文件"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo 信息泄露", "medium", "删除 phpinfo 页面"),
    ("/info.php", r"phpinfo\(\)|PHP Version", "phpinfo 信息泄露", "medium", "删除 phpinfo 页面"),
    ("/server-status", r"Apache Server Status", "Apache server-status 暴露", "medium",
     "限制 /server-status 仅内网可访问"),
    ("/server-info", r"Apache Server Information", "Apache server-info 暴露", "medium",
     "关闭 mod_info 或限制访问"),
    ("/manager/html", r"Tomcat|Tomcat Web Application Manager", "Tomcat 管理台暴露", "high",
     "删除管理台或限制来源 IP 并加固口令"),
    ("/actuator", r"\"_links\"|actuator", "Spring Boot Actuator 暴露", "high",
     "限制 actuator 端点访问范围"),
    ("/actuator/env", r"propertySources|\"profiles\"", "Actuator env 配置泄露（含凭据）", "critical",
     "关闭 env/heapdump 等高危端点"),
    ("/actuator/heapdump", r"", "Actuator heapdump 暴露", "critical", "关闭 heapdump 端点"),
    ("/swagger-ui.html", r"swagger", "Swagger 接口文档暴露", "low", "生产环境关闭 Swagger UI"),
    ("/v2/api-docs", r"swagger|\"paths\"", "API 文档暴露", "low", "生产环境关闭 API 文档"),
    ("/jmx-console", r"JBoss|JMX", "JBoss JMX 控制台暴露", "high", "删除 JMX 控制台或加访问控制"),
    ("/solr/", r"Solr Admin|Solr", "Solr 管理台暴露", "medium", "为 Solr 增加认证"),
    ("/backup.sql", r"CREATE TABLE|INSERT INTO|-- MySQL", "数据库备份文件泄露", "critical",
     "删除备份文件并禁止下载"),
    ("/db.sql", r"CREATE TABLE|INSERT INTO", "数据库备份文件泄露", "critical", "删除备份文件"),
    ("/www.zip", r"", "站点源码压缩包泄露", "high", "删除源码压缩包"),
    ("/backup.zip", r"", "备份压缩包泄露", "high", "删除备份压缩包"),
    ("/elmah.axd", r"Error Log|ELMAH", "ASP.NET 错误日志暴露", "medium", "限制 ELMAH 访问"),
    ("/trace.axd", r"Application Trace", "ASP.NET 跟踪信息暴露", "medium", "关闭 trace.axd"),
    ("/admin", r"<form|login|password", "管理后台可访问", "info", "限制后台访问来源并启用双因子"),
    ("/wp-login.php", r"WordPress", "WordPress 登录页暴露", "info", "限制后台访问并加固口令"),
    ("/xmlrpc.php", r"XML-RPC server accepts", "WordPress XML-RPC 接口开启", "low",
     "未使用请关闭 XML-RPC"),
    ("/robots.txt", r"Disallow", "robots.txt 暴露目录结构", "info", "检查是否泄露敏感路径"),
    ("/crossdomain.xml", r"cross-domain-policy", "crossdomain.xml 配置过宽", "low",
     "限制 allow-access-from 域名"),
    # ---- Java / Go / Python / Nginx 技术栈特有路径 ----
    ("/application.yml", r"spring:|datasource:|password:", "Spring Boot 配置文件泄露", "critical",
     "禁止 Web 目录访问 application.yml / bootstrap.yml，并立即轮换其中的凭据"),
    ("/bootstrap.yml", r"spring:|nacos:|password:", "Spring Boot 引导配置泄露", "critical",
     "禁止 Web 目录访问配置文件，并轮换凭据"),
    ("/api-docs", r"swagger|openapi|\"paths\"", "Swagger/OpenAPI 接口文档暴露", "low",
     "生产环境关闭接口文档或加访问控制"),
    ("/v3/api-docs", r"swagger|openapi|\"paths\"", "Swagger v3 接口文档暴露", "low",
     "生产环境关闭接口文档或加访问控制"),
    ("/nginx.conf", r"server\s*\{|listen\s+\d+|location\s+/", "Nginx 配置文件泄露", "critical",
     "禁止 Web 目录访问 nginx.conf 等配置文件"),
    ("/debug/vars", r"cmdline|memstats|\"goroutines\"", "Go expvar 运行时变量暴露", "medium",
     "关闭 expvar 端点或仅允许内网访问"),
]

TECH_PATTERNS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"/sites/all/modules|Drupal", "Drupal"),
    (r"Joomla|option=com_", "Joomla"),
    (r"ThinkPHP", "ThinkPHP"),
    (r"Laravel|XSRF-TOKEN", "Laravel"),
    (r"Django|csrfmiddlewaretoken", "Django"),
    (r"Spring|Whitelabel Error Page", "Spring"),
    (r"Express|node", "Node.js/Express"),
    (r"jQuery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"phpMyAdmin", "phpMyAdmin"),
    (r"Jenkins", "Jenkins"),
    (r"Grafana", "Grafana"),
    (r"Kibana", "Kibana"),
    (r"React|__NEXT_DATA__", "React/Next.js"),
    (r"Vue|data-v-", "Vue.js"),
    (r"Whitelabel Error Page|springfox|Spring Boot Actuator", "Spring Boot"),
    (r"Apache Tomcat|Tomcat Web Application Manager|Apache-Coyote", "Tomcat"),
    (r"Jetty|Eclipse Jetty", "Jetty"),
    (r"JBoss|WildFly", "JBoss/WildFly"),
    (r"WebLogic", "WebLogic"),
    (r"Struts2|Apache Struts", "Struts2"),
    (r"Welcome to OpenResty|openresty", "OpenResty"),
    (r"Welcome to nginx|nginx/", "Nginx"),
    (r"Werkzeug Debugger|The requested URL was not found|Flask", "Flask"),
    (r"FastAPI|Swagger UI|openapi.json", "FastAPI"),
    (r"Gunicorn|gunicorn", "Gunicorn"),
    (r"/debug/pprof|goroutine profile|Types of profiles", "Go"),
    (r"Nacos", "Nacos"),
    (r"__NEXT_DATA__|_next/static|Next\.js", "Next.js"),
    (r"NestJS|Nest", "NestJS"),
    (r"Nuxt|__NUXT__", "Nuxt"),
    (r"Koa|koa", "Koa"),
    (r"Fastify", "Fastify"),
    (r"Socket\.IO|socket\.io", "Socket.IO"),
    (r"Powered by Express|Express\.js", "Node.js/Express"),
    # ---- PHP / .NET 页面与响应头特征 ----
    (r"X-Powered-By:\s*PHP|PHPSESSID|PHP Version|Zend Engine|phpinfo\(\)", "PHP"),
    (r"Symfony|symfony", "Symfony"),
    (r"CodeIgniter|ci_session", "CodeIgniter"),
    (r"PHPUnit|phpunit", "PHPUnit"),
    (r"composer/installed|Composer", "Composer"),
    (r"__VIEWSTATE|__EVENTVALIDATION|__EVENTTARGET|aspnetForm|ASP\.NET|X-AspNet-Version", "ASP.NET"),
    (r"Microsoft-IIS|IIS \d|ASP.NET Core|Kestrel", ".NET"),
    (r"_framework/blazor|Blazor", "Blazor"),
    (r"signalr|SignalR", "SignalR"),
    (r"Umbraco|Sitecore|Orchard", "Umbraco"),
]


def http_request(
    host: str,
    port: int,
    path: str = "/",
    method: str = "GET",
    use_tls: bool = False,
    timeout: float = 6.0,
    headers: Optional[Dict[str, str]] = None,
    max_body: int = 8192,
    server_hostname: Optional[str] = None,
    body: Optional[bytes] = None,
) -> Tuple[int, Dict[str, str], bytes, str]:
    """轻量 HTTP 客户端，返回 (状态码, 响应头, 响应体, 错误信息)。

    host           实际连接的地址（通常是解析后的 IP）
    server_hostname用于 SNI 与 Host 请求头，即"以域名访问"该 IP（虚拟主机场景）
    body           请求体（用于 POST 探测）
    """
    hdrs = {"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"}
    if server_hostname:
        hdrs["Host"] = server_hostname if port in (80, 443) else f"{server_hostname}:{port}"
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        hdrs.setdefault("Content-Length", str(len(body)))
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        if use_tls:
            conn.connect()
            # 手动 wrap：连接走 IP，但 SNI 使用域名，确保取到正确的虚拟主机证书
            conn.sock = ssl_context().wrap_socket(
                conn.sock, server_hostname=server_hostname or host
            )
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read(max_body)
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, body, ""
    except Exception as exc:  # noqa: BLE001
        return 0, {}, b"", f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _hostname_matches(san: List[str], hostname: str) -> bool:
    """按 SAN 列表判断证书是否覆盖访问域名（支持单级通配）。"""
    if not san:
        return True
    host = hostname.lower().rstrip(".")
    for name in san:
        name = str(name).lower().rstrip(".")
        if name.startswith("*."):
            if host.endswith(name[1:]) and host.count(".") == name.count("."):
                return True
        elif name == host:
            return True
    return False


def _detect_tls(
    host: str, port: int, timeout: float = 6.0, server_hostname: Optional[str] = None
) -> Dict[str, Any]:
    """获取证书信息并尝试协商低版本 TLS。"""
    info: Dict[str, Any] = {}
    sni = server_hostname or host
    sock = None
    try:
        ctx = ssl_context()
        sock = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(sock, server_hostname=sni)
        info["version"] = tls.version()
        cipher = tls.cipher()
        if cipher:
            info["cipher"] = cipher[0]
            info["cipher_bits"] = cipher[2]
        cert = tls.getpeercert() or {}
        info["subject"] = str(cert.get("subject", ""))
        info["issuer"] = str(cert.get("issuer", ""))
        info["not_after"] = cert.get("notAfter", "")
        info["not_before"] = cert.get("notBefore", "")
        info["self_signed"] = cert.get("subject") == cert.get("issuer")
        san = cert.get("subjectAltName", ())
        info["san"] = [v for _, v in san][:10]
        info["sni"] = sni
        info["hostname_matches"] = _hostname_matches(info["san"], sni)
        try:
            tls.close()
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"{type(exc).__name__}: {exc}"
        return info

    # 低版本协议支持探测
    for label, attr in (("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1")):
        try:
            low = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            low.check_hostname = False
            low.verify_mode = ssl.CERT_NONE
            setattr(low, "minimum_version", getattr(ssl.TLSVersion, "TLSv1" if attr == "TLSv1" else "TLSv1_1"))
            setattr(low, "maximum_version", getattr(ssl.TLSVersion, "TLSv1" if attr == "TLSv1" else "TLSv1_1"))
            s = socket.create_connection((host, port), timeout=timeout)
            low_sock = low.wrap_socket(s, server_hostname=sni)
            low_sock.close()
            info[f"supports_{label}"] = True
        except Exception:  # noqa: BLE001
            info[f"supports_{label}"] = False
    return info


def _follow(
    host: str,
    port: int,
    use_tls: bool,
    timeout: float,
    server_hostname: Optional[str] = None,
) -> Tuple[int, Dict[str, str], bytes, str, str]:
    """请求根路径并跟随最多 3 次跳转，返回 (状态, 头, 体, 最终路径, 错误)。"""
    path = "/"
    for _ in range(3):
        status, headers, body, err = http_request(
            host, port, path, use_tls=use_tls, timeout=timeout, server_hostname=server_hostname
        )
        if err:
            return status, headers, body, path, err
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location", "")
            if not loc:
                return status, headers, body, path, ""
            if loc.startswith("http"):
                parsed = urlparse(loc)
                if parsed.netloc and parsed.netloc.split(":")[0] not in (host,):
                    return status, headers, body, path, ""
                path = parsed.path or "/"
            else:
                path = loc
            continue
        return status, headers, body, path, ""
    return status, headers, body, path, ""


def scan_web(
    host: str,
    port: int,
    timeout: float = 6.0,
    deep: bool = True,
    server_hostname: Optional[str] = None,
    async_limit: int = 64,
    allow_async: bool = True,
) -> Tuple[WebInfo, List[Finding]]:
    """扫描单个 HTTP(S) 端口。

    host            实际连接的 IP
    server_hostname 以该域名访问（写入 Host 头与 TLS SNI），None 表示直接用 IP 访问
    """
    findings: List[Finding] = []
    vhost = server_hostname or host
    use_tls = port in (443, 8443, 9443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{vhost}:{port}" if port not in (80, 443) else f"{scheme}://{vhost}"

    status, headers, body, final_path, err = _follow(
        host, port, use_tls, timeout, server_hostname
    )
    if err and not status:
        # 尝试切换协议
        use_tls = not use_tls
        scheme = "https" if use_tls else "http"
        base = f"{scheme}://{vhost}:{port}" if port not in (80, 443) else f"{scheme}://{vhost}"
        status, headers, body, final_path, err = _follow(
            host, port, use_tls, timeout, server_hostname
        )
        if err and not status:
            return WebInfo(url=base, vhost=server_hostname or ""), findings

    text = safe_text(body, 8192)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    info = WebInfo(
        url=base,
        scheme=scheme,
        vhost=server_hostname or "",
        status=status,
        title=(title_match.group(1).strip()[:120] if title_match else ""),
        server=headers.get("server", ""),
        powered_by=headers.get("x-powered-by", ""),
        headers=headers,
    )

    # 技术栈识别
    for pattern, tech in TECH_PATTERNS:
        if re.search(pattern, text, re.I) or re.search(pattern, headers.get("x-powered-by", ""), re.I):
            if tech not in info.technologies:
                info.technologies.append(tech)
    for header_name in ("x-generator", "x-drupal-cache", "x-aspnet-version", "x-jenkins", "x-redirect-by"):
        if headers.get(header_name):
            info.technologies.append(f"{header_name}={headers[header_name]}")

    target = f"{base}{final_path}"

    # 1) 版本信息泄露
    if info.server:
        findings.append(Finding(
            title="Web 服务版本信息泄露", severity="low", category="web", target=target,
            detail=f"Server 响应头暴露中间件信息：{info.server}",
            evidence=f"Server: {info.server}",
            remediation="隐藏或修改 Server 响应头（server_tokens off / ServerTokens Prod）",
        ))
    if info.powered_by:
        findings.append(Finding(
            title="X-Powered-By 暴露后端技术栈", severity="low", category="web", target=target,
            detail=f"X-Powered-By: {info.powered_by}",
            evidence=f"X-Powered-By: {info.powered_by}",
            remediation="关闭 expose_php 或移除 X-Powered-By 响应头",
        ))
    for header_name in ("x-aspnet-version", "x-aspnetmvc-version", "x-jenkins", "x-runtime"):
        if headers.get(header_name):
            findings.append(Finding(
                title=f"{header_name} 暴露实现细节", severity="low", category="web", target=target,
                detail=f"{header_name}: {headers[header_name]}",
                remediation="移除该响应头",
            ))

    # 2) 中间件版本 CVE 匹配
    candidates: List[Tuple[str, str]] = []
    if info.server:
        m = re.match(r"\s*([\w-]+)/?([\d.]*)", info.server)
        if m:
            candidates.append((m.group(1), m.group(2)))
    if info.powered_by:
        m = re.match(r"\s*([\w-]+)/?([\d.]*)", info.powered_by)
        if m:
            candidates.append((m.group(1), m.group(2)))
    for product, version in candidates:
        if not version:
            continue
        # PHP 版本 CVE 统一由 php2shell 模块处理（含 phpinfo 来源、缓解配置核查与 SAPI 提示），
        # 此处跳过以免同一漏洞在报告里出现两次
        if normalize_product(product).startswith("php"):
            continue
        for rule in match_rules(product, version):
            findings.append(Finding(
                title=rule.name, severity=rule.severity, category="web", target=target,
                cve=rule.id,
                detail=f"检测到 {product} {version}，命中已知漏洞规则"
                       + ("（发行版可能已向后移植补丁，需二次确认）" if rule.confirm else ""),
                evidence=f"Server/X-Powered-By: {info.server or info.powered_by}",
                remediation=rule.remediation, reference=rule.reference,
            ))

    # 3) 安全响应头
    for header_name, (title, sev, fix) in SECURITY_HEADERS.items():
        if header_name not in headers:
            findings.append(Finding(
                title=title, severity=sev, category="web", target=target,
                detail=f"响应中未发现 {header_name}", remediation=fix,
            ))
    if use_tls and "strict-transport-security" not in headers:
        findings.append(Finding(
            title="缺少 HSTS 响应头", severity="medium", category="web", target=target,
            detail="HTTPS 站点未声明 Strict-Transport-Security",
            remediation="添加 Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ))

    # 4) Cookie 属性
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        if "httponly" not in low:
            findings.append(Finding(
                title="Cookie 缺少 HttpOnly 属性", severity="low", category="web", target=target,
                detail=set_cookie[:200], remediation="为会话 Cookie 增加 HttpOnly",
            ))
        if use_tls and "secure" not in low:
            findings.append(Finding(
                title="Cookie 缺少 Secure 属性", severity="medium", category="web", target=target,
                detail=set_cookie[:200], remediation="为会话 Cookie 增加 Secure",
            ))
        if "samesite" not in low:
            findings.append(Finding(
                title="Cookie 缺少 SameSite 属性", severity="low", category="web", target=target,
                detail=set_cookie[:200], remediation="设置 SameSite=Lax 或 Strict",
            ))

    # 5) HTTP 未强制跳转 HTTPS
    if not use_tls and status == 200:
        findings.append(Finding(
            title="HTTP 明文访问未提供跳转", severity="low", category="web", target=target,
            detail="站点可通过明文 HTTP 访问且未跳转到 HTTPS",
            remediation="配置 301 跳转至 HTTPS 并启用 HSTS",
        ))

    # 6) OPTIONS 方法
    m_status, m_headers, _, m_err = http_request(
        host, port, final_path, method="OPTIONS", use_tls=use_tls, timeout=timeout,
        server_hostname=server_hostname,
    )
    allow = m_headers.get("allow", "")
    if allow:
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m.upper() in allow.upper()]
        if dangerous:
            sev = "high" if "PUT" in dangerous else "medium"
            findings.append(Finding(
                title=f"启用了危险的 HTTP 方法：{', '.join(dangerous)}", severity=sev,
                category="web", target=target,
                detail=f"Allow: {allow}",
                remediation="在 Web 服务器中禁用不必要的 HTTP 方法（TRACE/PUT/DELETE）",
            ))

    # 7) CORS 配置
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append(Finding(
            title="CORS 允许任意来源", severity="medium", category="web", target=target,
            detail="Access-Control-Allow-Origin: *",
            remediation="限制为可信域名，并避免与 Allow-Credentials 同时使用",
        ))

    # 8) 目录列表
    if re.search(r"<title>Index of /|Directory listing for", text, re.I):
        findings.append(Finding(
            title="目录列表已开启", severity="medium", category="web", target=target,
            detail="页面返回了目录索引", remediation="关闭 autoindex / 目录浏览",
        ))

    # 9) 敏感路径：协程批量只读 GET，所有路径都探测，不因组件版本是否命中而跳过
    if deep:
        tasks = [parallel.HttpTask(
            host=host, port=port, path=path, use_tls=use_tls,
            server_hostname=server_hostname, timeout=timeout, max_body=4096,
            label=(path, pattern, title, sev, fix),
        ) for path, pattern, title, sev, fix in SENSITIVE_PATHS]
        if allow_async:
            batch = parallel.http_get_batch_sync(tasks, async_limit)
        else:
            batch = []
            for task in tasks:
                p_status, p_headers, p_body, p_err = http_request(
                    host, port, task.path, method="GET", use_tls=use_tls,
                    timeout=timeout, max_body=4096, server_hostname=server_hostname,
                )
                batch.append(parallel.HttpResult(task=task, status=p_status,
                                                 headers=p_headers, body=p_body,
                                                 error=p_err))
        for res in batch:
            path, pattern, title, sev, fix = res.task.label
            if res.status != 200:
                continue
            body_text = safe_text(res.body, 4096)
            if pattern and not re.search(pattern, body_text, re.I):
                continue
            findings.append(Finding(
                title=title, severity=sev, category="web", target=f"{base}{path}",
                detail=f"HTTP {res.status} 可访问 {path}",
                evidence=body_text[:200],
                remediation=fix,
            ))
        LOGGER.info("Web 敏感路径：%d 个只读 GET（协程并发 %d）",
                    len(tasks), async_limit if allow_async else 0)

    # 10) TLS 配置
    if use_tls:
        tls_info = _detect_tls(host, port, timeout, server_hostname=server_hostname)
        info.tls = tls_info
        if tls_info.get("error"):
            findings.append(Finding(
                title="TLS 握手异常", severity="medium", category="web", target=base,
                detail=tls_info["error"], remediation="检查证书链与协议配置",
            ))
        else:
            if server_hostname and tls_info.get("hostname_matches") is False:
                findings.append(Finding(
                    title="TLS 证书与访问域名不匹配", severity="medium", category="web", target=base,
                    detail=f"以 {server_hostname} 访问时，证书未覆盖该域名",
                    evidence=f"subject={tls_info.get('subject')} san={tls_info.get('san')}",
                    remediation="为该域名签发并部署正确的证书",
                ))
            if tls_info.get("supports_TLSv1.0"):
                findings.append(Finding(
                    title="服务器支持 TLS 1.0（已废弃）", severity="medium", category="web", target=base,
                    detail="TLS 1.0 已被 RFC 8996 废弃", remediation="禁用 TLS 1.0/1.1，仅保留 TLS 1.2+",
                ))
            if tls_info.get("supports_TLSv1.1"):
                findings.append(Finding(
                    title="服务器支持 TLS 1.1（已废弃）", severity="medium", category="web", target=base,
                    remediation="禁用 TLS 1.0/1.1，仅保留 TLS 1.2+",
                ))
            if tls_info.get("cipher_bits") and tls_info["cipher_bits"] < 128:
                findings.append(Finding(
                    title="使用了弱加密套件", severity="high", category="web", target=base,
                    detail=f"协商套件：{tls_info.get('cipher')}（{tls_info['cipher_bits']} 位）",
                    remediation="禁用 EXPORT/RC4/3DES 等弱套件",
                ))
            if tls_info.get("self_signed"):
                findings.append(Finding(
                    title="使用了自签名证书", severity="medium", category="web", target=base,
                    detail=f"subject={tls_info.get('subject')}",
                    remediation="更换为受信任 CA 签发的证书",
                ))
            not_after = tls_info.get("not_after", "")
            if not_after:
                try:
                    import datetime

                    # 去掉末尾时区名（GMT），统一按 UTC 朴素时间比较
                    stamp = " ".join(not_after.split()[:-1])
                    expire = datetime.datetime.strptime(stamp, "%b %d %H:%M:%S %Y")
                    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    delta = (expire - now_utc).days
                    if delta < 0:
                        findings.append(Finding(
                            title="TLS 证书已过期", severity="high", category="web", target=base,
                            detail=f"证书过期时间：{not_after}", remediation="立即续签证书",
                        ))
                    elif delta <= 30:
                        findings.append(Finding(
                            title=f"TLS 证书即将过期（{delta} 天）", severity="medium", category="web",
                            target=base, detail=f"证书过期时间：{not_after}", remediation="尽快续签证书",
                        ))
                except Exception:  # noqa: BLE001
                    pass

    LOGGER.info("  Web 扫描完成：%s（%s，状态码 %s）", base, info.title or "无标题", status)
    return info, findings


def scan_web_ports(
    host: str,
    ports: List[int],
    timeout: float = 6.0,
    deep: bool = True,
    server_hostname: Optional[str] = None,
    async_limit: int = 64,
    allow_async: bool = True,
) -> Tuple[List[WebInfo], List[Finding]]:
    """多端口走线程池并发；每个端口内部的敏感路径走 asyncio 协程。"""
    ports = list(dict.fromkeys(ports))
    if not ports:
        return [], []

    def _one(port: int) -> Tuple[WebInfo, List[Finding]]:
        return scan_web(host, port, timeout=timeout, deep=deep,
                        server_hostname=server_hostname,
                        async_limit=async_limit, allow_async=allow_async)

    results = parallel.map_threads(_one, ports, min(len(ports), 8))
    web_infos = [info for info, _ in results if info.status]
    findings = [finding for _, group in results for finding in group]
    if len(ports) > 1:
        LOGGER.info("Web 端口扫描：%d 个端口由线程池并发（每端口内再走协程批量探测）", len(ports))
    return web_infos, findings
