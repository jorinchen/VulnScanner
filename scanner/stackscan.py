# -*- coding: utf-8 -*-
"""技术栈漏洞扫描：Java / Go / C/C++ / Python / Nginx / OpenResty / Node.js / PHP / .NET。

四路数据来源，统一走 vulndb 的离线版本规则匹配：

1. 远端服务指纹：banner、Server / X-Powered-By / X-AspNet-Version 响应头、页面技术栈特征；
2. 远端只读探测：状态页、pprof、调试控制台、Actuator/Druid、WEB-INF、
   PHP 的 phpinfo/.env/composer.json 与 ASP.NET 的 trace.axd/web.config/elmah.axd 等暴露面；
3. 本地运行时与依赖：java/go/python/gcc/nginx/openresty/node/php/composer/dotnet 版本、
   pip / npm / composer / NuGet 包、requirements.txt / go.mod / pom.xml / package.json /
   composer.json / *.csproj / packages.config / project.assets.json 等；
4. 本地 Nginx / OpenResty 配置核查（server_tokens / autoindex / lua_code_cache 等）。

所有远端请求都是只读 GET，不上传、不写入、不执行任何代码、不做漏洞利用。
本地采集只执行 `--version` 一类查询命令并读取文本文件，不修改系统。
"""

from __future__ import annotations

import json
import os
import platform
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from . import parallel
from .models import Finding, ServiceInfo, WebInfo
from .osaudit import installed_packages
from .stackdb import STACK_CATEGORIES, STACK_CN, STACK_RULES
from .utils import LOGGER, run_command, safe_text
from .vulndb import RULES, match_rules, normalize_product
from .webscan import http_request

# 产品名（含发行版包别名）-> 所属技术栈
PRODUCT_STACK: Dict[str, str] = {}
for _rule in STACK_RULES:
    for _product in _rule["products"]:
        PRODUCT_STACK.setdefault(_product, _rule["category"])

# 部分框架只有指纹、没有独立版本规则，仍需归入正确的技术栈
PRODUCT_STACK.update({
    "nuxt": "nodejs", "nestjs": "nodejs", "koa": "nodejs", "fastify": "nodejs",
    "vue": "nodejs", "react": "nodejs", "yarn": "nodejs", "pnpm": "nodejs",
    "aspnet": "dotnet", "aspnetcore": "dotnet", "iis": "dotnet", "mono": "dotnet",
    "php-fpm": "php", "php-cgi": "php", "zend": "php",
})

KNOWN_PRODUCTS: Set[str] = {p for r in RULES for p in r.products}

STACK_ALIASES = {
    "all": "all", "*": "all", "全部": "all",
    "java": "java", "jvm": "java", "jdk": "java", "spring": "java", "java生态": "java",
    "go": "go", "golang": "go", "go语言": "go",
    "cpp": "cpp", "c++": "cpp", "c": "cpp", "c/c++": "cpp", "c语言": "cpp",
    "python": "python", "py": "python", "cpython": "python",
    "nginx": "nginx", "openresty": "openresty", "lua": "openresty",
    "nodejs": "nodejs", "node": "nodejs", "npm": "nodejs", "js": "nodejs",
    "javascript": "nodejs", "frontend": "nodejs", "前端": "nodejs",
    "php": "php", "php7": "php", "php8": "php", "composer": "php",
    "laravel": "php", "thinkphp": "php", "drupal": "php", "wordpress": "php",
    "phpmyadmin": "php", "phpunit": "php", "php生态": "php",
    "dotnet": "dotnet", ".net": "dotnet", "net": "dotnet", "aspnet": "dotnet",
    "asp.net": "dotnet", "aspnetcore": "dotnet", "csharp": "dotnet", "c#": "dotnet",
    "nuget": "dotnet", "clr": "dotnet", "netcore": "dotnet",
}


def parse_stacks(text: str) -> Set[str]:
    """解析 --stack-categories 参数；'all' 表示全部启用。"""
    names = [x.strip().lower() for x in str(text or "all").split(",") if x.strip()]
    result: Set[str] = set()
    for name in names:
        mapped = STACK_ALIASES.get(name)
        if mapped == "all":
            return set(STACK_CATEGORIES)
        if mapped:
            result.add(mapped)
        else:
            LOGGER.warning("未知的技术栈类别：%s（可选：%s）", name, ", ".join(STACK_CATEGORIES))
    return result or set(STACK_CATEGORIES)


def _stack_of(product: str) -> str:
    return PRODUCT_STACK.get(normalize_product(product), "")


def _clean_version(version: str) -> str:
    """去掉发行版修订后缀与版本前缀：'1.1.1f-1ubuntu2.24' -> '1.1.1f'。"""
    value = (version or "").strip().lstrip("vV=>~^< ")
    return re.split(r"[-+~]", value)[0].strip()


def _openresty_nginx_version(version: str) -> str:
    """OpenResty x.y.z.N 的前三段通常就是捆绑的 Nginx 版本。"""
    parts = (version or "").split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ""


class _Collector:
    """汇总组件清单与漏洞发现，并按 (产品, 版本, 位置) 去重。"""

    def __init__(self, active: Set[str]):
        self.active = active
        self.all_stacks = active == set(STACK_CATEGORIES)
        self.components: List[Dict[str, Any]] = []
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, str, str]] = set()
        self._finding_keys: Set[Tuple[str, str, str]] = set()

    def add(
        self,
        product: str,
        version: str,
        source: str,
        target: str,
        stack: str = "",
        emit_findings: bool = True,
        package_name: str = "",
    ) -> None:
        name = normalize_product(product)
        if not name:
            return
        version = _clean_version(version)
        guessed = stack or _stack_of(name)
        hits = match_rules(name, version) if version else []
        if not guessed:
            for rule in hits:
                if rule.category in STACK_CATEGORIES:
                    guessed = rule.category
                    break
        if guessed and guessed not in self.active:
            return
        if not guessed and not self.all_stacks:
            return

        key = (name, version, target)
        if key not in self._seen:
            self._seen.add(key)
            self.components.append({
                "stack": guessed or "other",
                "stack_cn": STACK_CN.get(guessed, "通用组件"),
                "product": name,
                "version": version or "版本未知",
                "source": source,
                "target": target,
                "cves": [r.id for r in hits],
                "max_severity": _max_severity(hits),
                # 无论版本是否命中规则，都留下明确的检测结论
                "check_status": (
                    f"命中 {len(hits)} 条版本规则" if hits else
                    ("版本未知，已做指纹/暴露面检测" if not version else
                     f"已比对 {len(RULES)} 条规则，未命中")
                ),
                "rules_checked": len(RULES) if version else 0,
                "checked": True,
            })
        if not emit_findings:
            return
        for rule in hits:
            fkey = (rule.id, name, target)
            if fkey in self._finding_keys:
                continue
            self._finding_keys.add(fkey)
            show_name = package_name or name
            title = (f"{rule.name}（{show_name} {version}）" if package_name else rule.name)
            self.findings.append(Finding(
                title=title,
                severity=rule.severity,
                category=rule.category,
                target=target,
                cve=rule.id,
                detail=(f"已安装 {show_name}={version}，命中已知漏洞规则"
                        if package_name else f"检测到 {name} {version}，命中已知漏洞规则")
                       + ("（来源：" + source + "）" if source else "")
                       + ("（发行版可能已向后移植补丁，需结合 changelog 二次确认）" if rule.confirm else ""),
                evidence=f"{source}: {name} {version}".strip(),
                remediation=rule.remediation,
                reference=rule.reference,
            ))


def _max_severity(rules: Sequence[Any]) -> str:
    order = ("critical", "high", "medium", "low", "info")
    found = [r.severity for r in rules]
    return next((s for s in order if s in found), "info")


# --------------------------------------------------------------------------- #
# 远端：服务指纹 / 响应头 / 页面技术栈
# --------------------------------------------------------------------------- #
# (正则, 产品名, 版本分组号)；版本分组为 0 表示只识别产品、不取版本
SERVER_PATTERNS: List[Tuple[str, str, int]] = [
    (r"nginx/([\d.]+)", "nginx", 1),
    (r"openresty/([\d.]+)", "openresty", 1),
    (r"Apache\s*Tomcat/([\d.]+)", "tomcat", 1),
    (r"Apache-Coyote/[\d.]+", "tomcat", 0),
    (r"Jetty\(?([\d.]+)", "jetty", 1),
    (r"Apache/([\d.]+)", "httpd", 1),
    (r"Werkzeug/([\d.]+)", "werkzeug", 1),
    (r"gunicorn/([\d.]+)", "gunicorn", 1),
    (r"TornadoServer/([\d.]+)", "tornado", 1),
    (r"Python/([\d.]+)", "python", 1),
    (r"Java/([\d._]+)", "openjdk", 1),
    (r"JBoss|WildFly", "jboss", 0),
    (r"WebLogic", "weblogic", 0),
    (r"\bGo\b|GoAhead", "go", 0),
    (r"Microsoft-IIS/([\d.]+)", "iis", 1),
    # ---- Node.js / npm 生态 ----
    (r"X-Powered-By:\s*Express", "express", 0),
    (r"X-Powered-By:\s*Next\.js|Next\.js", "next", 0),
    (r"X-Powered-By:\s*Nuxt|Nuxt", "nuxt", 0),
    (r"X-Powered-By:\s*Nest|NestJS", "nestjs", 0),
    (r"X-Powered-By:\s*Koa|Koa", "koa", 0),
    (r"X-Powered-By:\s*Fastify|Fastify", "fastify", 0),
    (r"(?:Server|X-Powered-By):\s*Node\.js/?([\d.]*)", "node", 1),
    # ---- PHP / .NET 指纹 ----
    (r"X-Powered-By:\s*PHP/?([\d.]*)", "php", 1),
    (r"X-Powered-By:\s*(?:ASP\.NET|ASP.NET)\s*/?([\d.]*)", "aspnetcore", 1),
    (r"Server:\s*Microsoft-IIS/([\d.]+)", "iis", 1),
    (r"X-AspNet-Version:\s*([\d.]+)", "dotnet", 1),
    (r"X-AspNetMvc-Version:\s*([\d.]+)", "aspnetcore", 1),
    (r"X-Powered-By:\s*Blazor|Blazor", "aspnetcore", 0),
]

HEADER_PRODUCTS = {
    "x-jenkins": "jenkins",
    "x-aspnet-version": "dotnet",
    "x-aspnetmvc-version": "aspnetcore",
    "x-aspnetmvc": "aspnetcore",
}

TECH_TO_PRODUCT = {
    "Django": ("django", "python"),
    "Flask": ("flask", "python"),
    "Werkzeug": ("werkzeug", "python"),
    "Jinja2": ("jinja2", "python"),
    "FastAPI": ("starlette", "python"),
    "Gunicorn": ("gunicorn", "python"),
    "Spring": ("spring-core", "java"),
    "Spring Boot": ("spring-core", "java"),
    "Tomcat": ("tomcat", "java"),
    "Jetty": ("jetty", "java"),
    "Jenkins": ("jenkins", "java"),
    "Struts2": ("struts2", "java"),
    "WebLogic": ("weblogic", "java"),
    "JBoss/WildFly": ("jboss", "java"),
    "Nacos": ("nacos", "java"),
    "Nginx": ("nginx", "nginx"),
    "OpenResty": ("openresty", "openresty"),
    "Go": ("go", "go"),
    "Prometheus": ("prometheus", "go"),
    "Grafana": ("grafana", "go"),
    "Node.js/Express": ("express", "nodejs"),
    "React/Next.js": ("next", "nodejs"),
    "Next.js": ("next", "nodejs"),
    "NestJS": ("nestjs", "nodejs"),
    "Nuxt": ("nuxt", "nodejs"),
    "Koa": ("koa", "nodejs"),
    "Fastify": ("fastify", "nodejs"),
    "Socket.IO": ("socket.io", "nodejs"),
    "Vue.js": ("vue", "nodejs"),
    "PHP": ("php", "php"),
    "Laravel": ("laravel", "php"),
    "ThinkPHP": ("thinkphp", "php"),
    "WordPress": ("wordpress", "php"),
    "Drupal": ("drupal", "php"),
    "phpMyAdmin": ("phpmyadmin", "php"),
    "Symfony": ("symfony", "php"),
    "Composer": ("composer", "php"),
    "PHPUnit": ("phpunit", "php"),
    "CodeIgniter": ("codeigniter", "php"),
    "ASP.NET": ("aspnetcore", "dotnet"),
    "ASP.NET Core": ("aspnetcore", "dotnet"),
    ".NET": ("dotnet", "dotnet"),
    "IIS": ("iis", "dotnet"),
    "Blazor": ("aspnetcore", "dotnet"),
    "SignalR": ("signalr", "dotnet"),
    "Umbraco": ("aspnetcore", "dotnet"),
}


def _webscan_primary(server: str, powered_by: str) -> Set[str]:
    """webscan.scan_web 已做过 CVE 匹配的主产品名，避免重复出报告。"""
    result: Set[str] = set()
    for text in (server, powered_by):
        m = re.match(r"\s*([\w-]+)/?([\d.]*)", text or "")
        if m and m.group(2):
            result.add(normalize_product(m.group(1)))
    return result


def scan_remote(
    collector: _Collector,
    ip: str,
    services: Sequence[ServiceInfo],
    web_infos: Sequence[WebInfo],
) -> None:
    # 服务 banner 中的产品/版本（cli 已按 svc.product/version 做过规则匹配，这里只补充组件清单）
    for svc in services:
        if svc.product:
            collector.add(svc.product, svc.version, f"服务指纹 {ip}:{svc.port}",
                          f"{ip}:{svc.port}", emit_findings=False)

    for info in web_infos:
        headers_text = " | ".join(f"{k}: {v}" for k, v in (info.headers or {}).items())
        server_text = " ".join(x for x in (info.server, info.powered_by, headers_text) if x)
        primary = _webscan_primary(info.server, info.powered_by)

        for pattern, product, group in SERVER_PATTERNS:
            match = re.search(pattern, server_text, re.I)
            if not match:
                continue
            version = match.group(group) if group and match.groups() else ""
            # webscan 已对 Server/X-Powered-By 主产品做过匹配，此处只记录组件
            collector.add(product, version, f"响应头 {info.url}", info.url,
                          emit_findings=normalize_product(product) not in primary)
            if normalize_product(product) == "openresty" and version:
                bundled = _openresty_nginx_version(version)
                if bundled:
                    # webscan 只会按 openresty 产品名匹配，捆绑的 Nginx CVE 需在此单独补齐
                    collector.add("nginx", bundled, f"OpenResty {version} 捆绑 Nginx 版本推算",
                                  info.url, stack="nginx")

        # 版本类响应头（x-jenkins / x-aspnet-version 等）
        for key, value in (info.headers or {}).items():
            head_product = HEADER_PRODUCTS.get(key.lower())
            if head_product and value:
                collector.add(head_product, value, f"响应头 {key} {info.url}", info.url)

        for tech in (info.technologies or []):
            if "=" in tech:
                key, value = tech.split("=", 1)
                if key.lower() in ("x-jenkins", "x-aspnet-version",
                                   "x-aspnetmvc-version", "x-runtime"):
                    lower = key.lower()
                    product = ("jenkins" if lower == "x-jenkins" else
                               "dotnet" if lower == "x-aspnet-version" else
                               "aspnetcore" if lower == "x-aspnetmvc-version" else
                               lower.lstrip("x-"))
                    collector.add(product, value, f"响应头 {key} {info.url}", info.url)
                continue
            mapped = TECH_TO_PRODUCT.get(tech)
            if mapped:
                collector.add(mapped[0], "", f"页面技术栈特征 {info.url}", info.url, stack=mapped[1])


# --------------------------------------------------------------------------- #
# 远端：只读暴露面探测
# --------------------------------------------------------------------------- #
# (路径, 命中正则, 标题, 等级, 技术栈, 修复建议)
WEB_PROBES: List[Tuple[str, str, str, str, str, str]] = [
    ("/nginx_status", r"Active connections|server accepts handled requests",
     "Nginx stub_status 状态页未授权暴露", "medium", "nginx",
     "限制 stub_status 仅内网 / 监控机访问，或启用 auth_basic"),
    ("/stub_status", r"Active connections|server accepts handled requests",
     "Nginx stub_status 状态页未授权暴露", "medium", "nginx",
     "限制 stub_status 仅内网 / 监控机访问，或启用 auth_basic"),
    ("/debug/pprof/", r"Types of profiles|goroutine profile|heap profile|/debug/pprof",
     "Go pprof 调试端点未授权暴露（泄露协程栈 / 内存信息）", "high", "go",
     "生产环境关闭 net/http/pprof，或仅绑定回环地址并加鉴权"),
    ("/metrics", r"go_goroutines|go_gc|process_cpu_seconds_total|python_info|jvm_memory",
     "运行时指标端点未授权暴露", "low", "",
     "限制 /metrics 仅采集器访问，避免暴露内部路径与业务标签"),
    ("/console", r"Werkzeug Debugger|InteractiveConsole|Traceback \(most recent|SECRET_KEY",
     "Werkzeug 调试控制台暴露（可远程执行代码）", "critical", "python",
     "立即关闭 debug 模式（FLASK_DEBUG / app.run(debug=False)），生产环境禁用 Werkzeug debugger"),
    ("/druid/index.html", r"Druid|DataSource|Stat Index|SQL Monitoring",
     "Alibaba Druid 监控页未授权访问", "high", "java",
     "关闭 StatViewServlet 或配置 allow/deny 与登录认证"),
    ("/actuator/gateway/routes", r"route_id|predicate|\"filters\"",
     "Spring Cloud Gateway 路由端点暴露", "high", "java",
     "关闭 gateway actuator 端点或限制访问来源"),
    ("/jolokia", r"jolokia|\"type\"\s*:\s*\"(read|list|search)\"",
     "Jolokia JMX-HTTP 桥暴露（可操作 MBean）", "high", "java",
     "限制 /jolokia 访问来源并启用 Jolokia 鉴权策略"),
    ("/eureka/apps", r"<applications>|\"applications\"|\"instance\"",
     "Eureka 服务注册信息未授权暴露", "medium", "java",
     "为 Eureka Server 启用认证并限制来源"),
    ("/swagger-resources", r"\"name\"|swagger|\"location\"",
     "Swagger 资源接口暴露（泄露内部接口清单）", "low", "java",
     "生产环境关闭 Swagger / OpenAPI 文档"),
    ("/WEB-INF/web.xml", r"<web-app|<\?xml",
     "Java WEB-INF/web.xml 可被直接访问", "critical", "java",
     "禁止 Web 根目录访问 WEB-INF / META-INF，检查反向代理路径映射"),
    ("/META-INF/MANIFEST.MF", r"Manifest-Version|Main-Class",
     "Java MANIFEST.MF 可被直接访问", "medium", "java",
     "禁止访问 META-INF 目录"),
    # ---- Node.js 特有暴露面 ----
    ("/package.json", r'"dependencies"|"scripts"|"name"\s*:',
     "package.json 依赖清单泄露", "high", "nodejs",
     "禁止 Web 目录访问 package.json，避免暴露依赖版本与启动脚本"),
    ("/package-lock.json", r'"lockfileVersion"|"packages"',
     "package-lock.json 依赖锁文件泄露", "medium", "nodejs",
     "禁止 Web 目录访问依赖锁文件"),
    ("/npm-shrinkwrap.json", r'"lockfileVersion"|"dependencies"',
     "npm-shrinkwrap.json 依赖锁文件泄露", "medium", "nodejs",
     "禁止 Web 目录访问依赖锁文件"),
    ("/.npmrc", r"registry|_authToken|always-auth",
     ".npmrc 配置或 npm Token 泄露", "critical", "nodejs",
     "禁止 Web 目录访问 .npmrc，并立即轮换其中泄露的 token"),
    ("/server.js", r"require\(|express\(|app\.listen|createServer",
     "Node.js 服务端源码泄露", "high", "nodejs",
     "禁止 Web 目录直接访问服务端源码，检查静态目录映射"),
    ("/app.js", r"require\(|express\(|app\.listen|createServer",
     "Node.js 应用源码泄露", "high", "nodejs",
     "禁止 Web 目录直接访问服务端源码，检查静态目录映射"),
    # ---- PHP 特有暴露面 ----
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version|PHP Credits|Zend Engine",
     "phpinfo 页面泄露 PHP 版本与配置", "high", "php",
     "删除 phpinfo 页面，设置 expose_php=Off，限制仅内网访问诊断脚本"),
    ("/info.php", r"phpinfo\(\)|PHP Version|PHP Credits|Zend Engine",
     "PHP 诊断页面泄露版本与配置", "high", "php",
     "删除诊断页面，设置 expose_php=Off"),
    ("/.env", r"APP_KEY|DB_PASSWORD|APP_ENV|DATABASE_URL|MAIL_PASSWORD",
     ".env 环境配置泄露（含密钥 / 数据库口令）", "critical", "php",
     "禁止 Web 访问 .env，立即轮换其中所有凭据"),
    ("/composer.json", r'"require"|"autoload"|"name"\s*:',
     "composer.json 依赖清单泄露", "medium", "php",
     "禁止 Web 访问 composer.json，避免暴露依赖版本"),
    ("/composer.lock", r'"packages"|"content-hash"',
     "composer.lock 依赖锁文件泄露", "medium", "php",
     "禁止 Web 访问 composer.lock"),
    ("/vendor/composer/installed.json", r'"packages"|"name"\s*:',
     "vendor 依赖清单泄露", "medium", "php",
     "禁止 Web 根目录访问 vendor/，检查静态目录映射"),
    ("/storage/logs/laravel.log", r"\[\d{4}-\d{2}-\d{2}|local\.ERROR|production\.ERROR",
     "Laravel 运行日志泄露（含堆栈与配置）", "high", "php",
     "禁止 Web 访问 storage/，清理已泄露日志中的敏感信息"),
    ("/adminer.php", r"Adminer|Login - Adminer|server\[",
     "Adminer 数据库管理入口对外暴露", "medium", "php",
     "限制管理入口仅内网访问并启用认证，或使用独立管理通道"),
    ("/phpmyadmin/", r"phpMyAdmin|pma_|Welcome to phpMyAdmin",
     "phpMyAdmin 管理入口对外暴露", "medium", "php",
     "限制 phpMyAdmin 访问来源、启用双因素认证并保持版本更新"),
    ("/wp-config.php.bak", r"DB_NAME|DB_PASSWORD|<\?php",
     "WordPress 配置备份文件泄露", "critical", "php",
     "删除配置备份并禁止 Web 访问 .bak/.old/.save 文件，轮换数据库口令"),
    # ---- .NET / ASP.NET 特有暴露面 ----
    ("/elmah.axd", r"Error Log|ELMAH|Errors by|elmah",
     "ELMAH 错误日志未授权访问", "high", "dotnet",
     "为 elmah.axd 启用授权并限制来源，避免泄露堆栈、请求参数与会话信息"),
    ("/trace.axd", r"Application Trace|Trace Information|ASP\.NET Trace",
     "ASP.NET trace.axd 跟踪页暴露", "high", "dotnet",
     "在 web.config 中关闭 tracing（trace enabled=\"false\"）"),
    ("/web.config", r"<configuration|connectionStrings|appSettings",
     "web.config 配置文件泄露（含连接串 / 密钥）", "critical", "dotnet",
     "禁止 Web 访问 web.config，立即轮换其中所有凭据"),
    ("/App_Data/", r"Index of|Directory Listing|Directory: /",
     "App_Data 数据目录可列举 / 可访问", "high", "dotnet",
     "禁止列出 App_Data，检查 IIS 目录浏览与静态文件映射"),
    ("/swagger/v1/swagger.json", r'"swagger"|"openapi"|"paths"',
     "Swagger/OpenAPI 接口文档对外暴露", "low", "dotnet",
     "生产环境关闭 Swagger 或增加鉴权"),
    ("/Hangfire", r"Hangfire|Dashboard|Recurring Jobs",
     "Hangfire 后台任务仪表盘未授权访问", "high", "dotnet",
     "为 Hangfire Dashboard 配置授权过滤器并限制来源"),
]


def scan_web_exposures(
    collector: _Collector,
    ip: str,
    web_infos: Sequence[WebInfo],
    timeout: float,
    deep: bool = True,
    async_limit: int = 64,
    allow_async: bool = True,
) -> int:
    """全量只读暴露面探测，返回实际发起的 GET 数量。

    不再按 ``collector.active`` / 版本是否命中过滤：所有技术栈的所有探针都会执行，
    由 asyncio 协程批量并发发起（``--no-async`` 时回退到同步逐条请求）。
    """
    if not deep or not web_infos:
        return 0
    tasks: List[parallel.HttpTask] = []
    for info in web_infos:
        parsed = urlparse(info.url)
        port = parsed.port or (443 if info.scheme == "https" else 80)
        use_tls = info.scheme == "https"
        vhost = info.vhost or None
        for probe in WEB_PROBES:
            tasks.append(parallel.HttpTask(
                host=ip, port=port, path=probe[0], use_tls=use_tls,
                server_hostname=vhost, timeout=timeout, max_body=4096,
                label=(info.url, probe),
            ))

    if allow_async:
        results = parallel.http_get_batch_sync(tasks, async_limit)
    else:
        results = []
        for task in tasks:
            status, headers, body, err = http_request(
                ip, task.port, task.path, method="GET", use_tls=task.use_tls,
                timeout=timeout, max_body=4096, server_hostname=task.server_hostname,
            )
            results.append(parallel.HttpResult(task=task, status=status,
                                               headers=headers, body=body, error=err))

    for res in results:
        url, (path, pattern, title, severity, stack, fix) = res.task.label
        if res.status != 200:
            continue
        text = safe_text(res.body, 4096)
        if pattern and not re.search(pattern, text, re.I):
            continue
        collector.findings.append(Finding(
            title=title, severity=severity, category=stack or "other",
            target=f"{url}{path}",
            detail=f"只读 GET {path} 返回 HTTP 200 且命中特征，说明该管理/调试入口对外可访问",
            evidence=text[:200].replace("\n", " "),
            remediation=fix,
        ))
    LOGGER.info("技术栈暴露面：%d 个只读 GET 全部执行（不因版本/类别是否命中而跳过），协程并发 %d",
                len(tasks), async_limit if allow_async else 0)
    return len(tasks)


# --------------------------------------------------------------------------- #
# 本地：运行时版本 / 包 / 依赖文件
# --------------------------------------------------------------------------- #
# (命令, 输出正则, 产品名, 说明)
RUNTIME_PROBES: List[Tuple[Sequence[str], str, str, str]] = [
    (("java", "-version"), r'(?:openjdk|java) version "([^"]+)"', "openjdk", "java -version"),
    (("javac", "-version"), r"javac\s+([\d._]+)", "openjdk", "javac -version"),
    (("go", "version"), r"go([\d.]+)", "go", "go version"),
    (("python3", "--version"), r"Python\s+([\d.]+)", "python", "python3 --version"),
    (("python", "--version"), r"Python\s+([\d.]+)", "python", "python --version"),
    (("gcc", "-dumpversion"), r"([\d.]+)", "gcc", "gcc -dumpversion"),
    (("g++", "-dumpversion"), r"([\d.]+)", "gcc", "g++ -dumpversion"),
    (("clang", "--version"), r"clang version ([\d.]+)", "gcc", "clang --version"),
    (("nginx", "-v"), r"nginx/([\d.]+)", "nginx", "nginx -v"),
    (("openresty", "-v"), r"openresty/([\d.]+)", "openresty", "openresty -v"),
    (("mvn", "-version"), r"Apache Maven ([\d.]+)", "maven", "mvn -version"),
    (("gradle", "--version"), r"Gradle ([\d.]+)", "gradle", "gradle --version"),
    (("node", "--version"), r"v?([\d.]+)", "node", "node --version"),
    (("yarn", "--version"), r"([\d.]+)", "yarn", "yarn --version"),
    (("pnpm", "--version"), r"([\d.]+)", "pnpm", "pnpm --version"),
    (("php", "-v"), r"PHP\s+([\d.]+)", "php", "php -v"),
    (("composer", "--version"), r"Composer version\s+([\d.]+)", "composer", "composer --version"),
    (("dotnet", "--version"), r"([\d.]+)", "dotnet", "dotnet --version"),
]


def scan_runtimes(collector: _Collector) -> None:
    for cmd, pattern, product, label in RUNTIME_PROBES:
        code, out, err = run_command(cmd, timeout=15)
        if code in (124, 127):
            continue
        text = f"{out}\n{err}"
        match = re.search(pattern, text, re.I)
        if match:
            # PHP 版本 CVE 统一由 php2shell 模块（含 phpinfo 来源）报告，这里只登记组件
            collector.add(product, match.group(1), label, "localhost",
                          emit_findings=product != "php")

    # 扫描器自身的 Python 解释器（与服务器上的其他 Python 可能不同，单独标注来源）
    collector.add("python", platform.python_version(), "扫描器进程 Python 解释器", "localhost")

    # pip 已安装依赖
    for exe in ("pip3", "pip"):
        code, out, _ = run_command(
            [exe, "list", "--format=freeze", "--disable-pip-version-check"], timeout=45
        )
        if code != 0 or not out:
            continue
        for line in out.splitlines():
            if "==" not in line:
                continue
            name, version = line.split("==", 1)
            if normalize_product(name) in KNOWN_PRODUCTS:
                collector.add(name, version, f"{exe} list", "localhost")
        break

    # Node.js：npm 版本与全局包（Windows 上 npm 是 .cmd，逐个尝试）
    for npm_exe in ("npm", "npm.cmd"):
        code, out, _ = run_command([npm_exe, "--version"], timeout=15)
        if code == 0 and out.strip():
            collector.add("npm", out.strip().splitlines()[0], f"{npm_exe} --version", "localhost")
            break
    for npm_exe in ("npm", "npm.cmd"):
        code, out, _ = run_command([npm_exe, "list", "-g", "--depth=0", "--json"], timeout=45)
        if code != 0 or not out.strip():
            continue
        try:
            data = json.loads(out)
        except ValueError:
            break
        for name, meta in (data.get("dependencies") or {}).items():
            _add_npm_dep(collector, name, str((meta or {}).get("version", "")),
                         f"{npm_exe} list -g")
        break

    # PHP：composer 全局依赖（JSON 输出，缺命令时静默跳过）
    for exe in ("composer", "composer.phar", "composer.bat"):
        code, out, _ = run_command([exe, "global", "show", "--format=json"], timeout=30)
        if code != 0 or not out.strip():
            continue
        try:
            data = json.loads(out)
        except ValueError:
            break
        for item in (data.get("installed") or []):
            _add_dep(collector, item.get("name", ""), item.get("version", ""),
                     f"{exe} global show")
        break

    # .NET：每个已安装运行时单独登记，SDK 版本单独补一条
    code, out, _ = run_command(["dotnet", "--list-runtimes"], timeout=25)
    if code == 0 and out.strip():
        for line in out.splitlines():
            match = re.search(r"Microsoft\.(?:NETCore|AspNetCore)\.App\s+([\d.]+)", line, re.I)
            if match:
                collector.add("dotnet", match.group(1),
                              f"dotnet --list-runtimes: {line.strip()}", "localhost")
    code, out, _ = run_command(["dotnet", "--list-sdks"], timeout=25)
    if code == 0 and out.strip():
        match = re.search(r"([\d.]+)", out)
        if match:
            collector.add("dotnet", match.group(1), "dotnet --list-sdks", "localhost")

    # 系统包管理器（C/C++ 运行库、JDK、Nginx、Python 包等）
    pkgs, manager = installed_packages()
    for pkg, version in pkgs.items():
        if pkg not in KNOWN_PRODUCTS:
            continue
        # 与 osaudit.linux_audit 保持相同的标题/位置格式，便于报告去重
        collector.add(pkg, version, manager, "localhost", package_name=pkg)
    LOGGER.info("本地技术栈采集：包管理器 %s 共 %d 个包", manager, len(pkgs))


DEP_FILE_NAMES = {
    "requirements.txt", "requirements-dev.txt", "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "yarn.lock", "pnpm-lock.yaml",
    # PHP / Composer
    "composer.json", "composer.lock",
    # .NET / NuGet
    "packages.config", "packages.lock.json", "project.assets.json",
    "global.json", "Directory.Packages.props",
}

MSBUILD_SUFFIXES = (".csproj", ".vbproj", ".fsproj", ".props", ".targets")

SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".idea", ".vscode",
             "site-packages", "dist-packages", ".cache", "vendor", "target", "build"}

MAX_DEP_FILES = 300
MAX_WALK_FILES = 30000
MAX_DEPTH = 3


def _candidate_roots(extra: Sequence[str]) -> List[str]:
    roots = [os.getcwd()]
    for path in (
        "/opt", "/srv", "/var/www", "/usr/local", "/home", os.path.expanduser("~"),
        "C:/inetpub", "C:/Program Files/Java",
        "C:/Program Files/Apache Software Foundation",
    ):
        if os.path.isdir(path):
            roots.append(path)
    for path in extra:
        if os.path.isdir(path):
            roots.append(path)
    # 去重（保持顺序）
    return list(dict.fromkeys(os.path.abspath(p) for p in roots))


def _parse_requirements(text: str, collector: _Collector, source: str) -> None:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:===|==|>=|<=|~=|>|<|=)\s*([\d][\w.\-+]*)", line)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        if normalize_product(name) in KNOWN_PRODUCTS:
            collector.add(name, version, source, "localhost")


def _parse_go_deps(text: str, collector: _Collector, source: str) -> None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("//"):
            continue
        # go.sum: module vX.Y.Z h1:...   /   go.mod: require module vX.Y.Z
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v[\d][\w.\-+]*)(?:/go\.mod)?(?:\s|$)", line)
        if not m:
            continue
        module, version = m.group(1), m.group(2)
        short = module.rsplit("/", 1)[-1]
        for candidate in (module, short):
            if normalize_product(candidate) in KNOWN_PRODUCTS:
                collector.add(candidate, version, source, "localhost")
                break


def _parse_pom(text: str, collector: _Collector, source: str) -> None:
    artifact = ""
    for line in text.splitlines():
        m = re.search(r"<artifactId>([^<]+)</artifactId>", line)
        if m:
            artifact = m.group(1).strip()
        m = re.search(r"<version>([\d][\w.\-]*)</version>", line)
        if m and artifact and normalize_product(artifact) in KNOWN_PRODUCTS:
            collector.add(artifact, m.group(1), source, "localhost")


def _parse_gradle(text: str, collector: _Collector, source: str) -> None:
    for m in re.finditer(r"""['"]([\w.\-]+):([\w.\-]+):([\d][\w.\-]*)['"]""", text):
        artifact, version = m.group(2), m.group(3)
        if normalize_product(artifact) in KNOWN_PRODUCTS:
            collector.add(artifact, version, source, "localhost")


def _parse_jar_name(filename: str, collector: _Collector, source: str) -> None:
    m = re.match(r"^(.+?)-(\d[\w.\-]*)\.jar$", filename, re.I)
    if not m:
        return
    artifact = normalize_product(m.group(1))
    if artifact in KNOWN_PRODUCTS:
        collector.add(artifact, m.group(2), source, "localhost")


def _add_npm_dep(collector: _Collector, name: str, version: str, source: str) -> None:
    """登记一个 npm 依赖（排除类型声明包与 git/file 依赖）。"""
    name = (name or "").strip()
    if not name or name.startswith("@types/") or name.startswith(
        ("git+", "http:", "https:", "file:", "link:", "workspace:", "github:")
    ):
        return
    for candidate in (name, name.rsplit("/", 1)[-1]):
        key = normalize_product(candidate)
        if key in KNOWN_PRODUCTS or key in PRODUCT_STACK:
            collector.add(candidate, version, source, "localhost")
            return


def _parse_package_json(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, version in (data.get(section) or {}).items():
            _add_npm_dep(collector, name, str(version), source)


def _parse_package_lock(text: str, collector: _Collector, source: str) -> None:
    """兼容 lockfileVersion 1（dependencies）与 2/3（packages）。"""
    try:
        data = json.loads(text)
    except ValueError:
        return
    for key, meta in (data.get("packages") or {}).items():
        if key and isinstance(meta, dict):
            _add_npm_dep(collector, key.rsplit("node_modules/", 1)[-1],
                         str(meta.get("version", "")), source)
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict):
            _add_npm_dep(collector, name, str(meta.get("version", "")), source)


def _parse_yarn_lock(text: str, collector: _Collector, source: str) -> None:
    current = ""
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            declaration = line.split(":", 1)[0].strip().strip('"')
            first = declaration.split(",")[0].strip().strip('"')
            current = first.rsplit("@", 1)[0] if first.startswith("@") else first.split("@", 1)[0]
        elif current and "version" in line:
            m = re.search(r'version\s+"?([\d][\w.\-+]*)"?', line)
            if m:
                _add_npm_dep(collector, current, m.group(1), source)
                current = ""


def _parse_pnpm_lock(text: str, collector: _Collector, source: str) -> None:
    for m in re.finditer(r"^\s+/?([@\w.\-]+(?:/[\w.\-]+)?)@([\d][\w.\-+]*)\s*:", text, re.M):
        _add_npm_dep(collector, m.group(1), m.group(2), source)


def _add_dep(collector: _Collector, name: str, version: str, source: str) -> None:
    """通用依赖登记：只登记规则库已知产品，避免无关包刷屏。"""
    name = (name or "").strip()
    key = normalize_product(name)
    if key and (key in KNOWN_PRODUCTS or key in PRODUCT_STACK):
        collector.add(name, str(version or ""), source, "localhost", package_name=name)


def _parse_composer_json(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    for section in ("require", "require-dev"):
        for name, version in (data.get(section) or {}).items():
            _add_dep(collector, name, str(version), source)


def _parse_composer_lock(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    for group in ("packages", "packages-dev"):
        for item in (data.get(group) or []):
            if isinstance(item, dict):
                _add_dep(collector, item.get("name", ""), item.get("version", ""), source)


def _parse_packages_config(text: str, collector: _Collector, source: str) -> None:
    for match in re.finditer(r'<package\s+[^>]*\bid="([^"]+)"[^>]*\bversion="([^"]+)"',
                             text, re.I):
        _add_dep(collector, match.group(1), match.group(2), source)


def _parse_packages_lock_json(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    for group in (data.get("dependencies") or {}).values():
        if not isinstance(group, dict):
            continue
        for name, meta in group.items():
            version = str((meta or {}).get("resolved", "")) if isinstance(meta, dict) else ""
            _add_dep(collector, name, version, source)


def _parse_project_assets(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    for key in list((data.get("libraries") or {}).keys())[:500]:
        name, _, version = str(key).partition("/")
        _add_dep(collector, name, version, source)


def _parse_msbuild(text: str, collector: _Collector, source: str) -> None:
    for match in re.finditer(
        r'<(?:PackageReference|PackageVersion)\s+[^>]*\bInclude="([^"]+)"'
        r'[^>]*\bVersion="([^"]+)"', text, re.I,
    ):
        _add_dep(collector, match.group(1), match.group(2), source)
    for match in re.finditer(
        r'<(?:PackageReference|PackageVersion)\s+[^>]*\bInclude="([^"]+)"'
        r'[^>]*>\s*<Version>\s*([^<\s]+)\s*</Version>', text, re.I,
    ):
        _add_dep(collector, match.group(1), match.group(2), source)


def _parse_global_json(text: str, collector: _Collector, source: str) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        return
    version = (data.get("sdk") or {}).get("version")
    if version:
        _add_dep(collector, "dotnet", str(version), source)


def scan_dependency_files(collector: _Collector, extra_dirs: Sequence[str]) -> None:
    dep_count = 0
    jar_count = 0
    walked = 0
    for root in _candidate_roots(extra_dirs):
        base_depth = root.rstrip(os.sep).count(os.sep)
        for current, dirnames, filenames in os.walk(root, topdown=True):
            if walked >= MAX_WALK_FILES or dep_count >= MAX_DEP_FILES:
                break
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not d.startswith(".")
                           and current.count(os.sep) - base_depth < MAX_DEPTH]
            for filename in filenames:
                walked += 1
                if walked >= MAX_WALK_FILES:
                    break
                low = filename.lower()
                if low.endswith(".jar"):
                    jar_count += 1
                    _parse_jar_name(filename, collector, f"Jar 文件 {os.path.join(current, filename)}")
                elif (filename in DEP_FILE_NAMES or low.endswith(MSBUILD_SUFFIXES)) \
                        and dep_count < MAX_DEP_FILES:
                    dep_count += 1
                    path = os.path.join(current, filename)
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read(512 * 1024)
                    except OSError:
                        continue
                    source = f"依赖文件 {path}"
                    if filename.startswith("requirements"):
                        _parse_requirements(text, collector, source)
                    elif filename.startswith("go."):
                        _parse_go_deps(text, collector, source)
                    elif filename == "pom.xml":
                        _parse_pom(text, collector, source)
                    elif filename == "package.json":
                        _parse_package_json(text, collector, source)
                    elif filename in ("package-lock.json", "npm-shrinkwrap.json"):
                        _parse_package_lock(text, collector, source)
                    elif filename == "yarn.lock":
                        _parse_yarn_lock(text, collector, source)
                    elif filename == "pnpm-lock.yaml":
                        _parse_pnpm_lock(text, collector, source)
                    elif filename == "composer.json":
                        _parse_composer_json(text, collector, source)
                    elif filename == "composer.lock":
                        _parse_composer_lock(text, collector, source)
                    elif filename == "packages.config":
                        _parse_packages_config(text, collector, source)
                    elif filename == "packages.lock.json":
                        _parse_packages_lock_json(text, collector, source)
                    elif filename == "project.assets.json":
                        _parse_project_assets(text, collector, source)
                    elif filename == "global.json":
                        _parse_global_json(text, collector, source)
                    elif filename == "Directory.Packages.props" or low.endswith(MSBUILD_SUFFIXES):
                        _parse_msbuild(text, collector, source)
                    else:
                        _parse_gradle(text, collector, source)
    LOGGER.info("本地技术栈采集：扫描 %d 个文件（依赖清单 %d / Jar %d）", walked, dep_count, jar_count)


# --------------------------------------------------------------------------- #
# 本地：Nginx / OpenResty 配置核查
# --------------------------------------------------------------------------- #
NGINX_CONF_PATHS = (
    "/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf", "/etc/nginx/conf.d/default.conf",
    "/usr/local/openresty/nginx/conf/nginx.conf", "/etc/openresty/nginx.conf",
    "C:/nginx/conf/nginx.conf", "C:/openresty/nginx/conf/nginx.conf",
)


def scan_nginx_config(collector: _Collector) -> None:
    # 无论是否识别到 Nginx 版本、无论所选技术栈类别，存在的配置文件一律核查
    for path in NGINX_CONF_PATHS:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(1024 * 1024)
        except OSError:
            continue
        low = text.lower()
        is_openresty = "openresty" in path.lower() or "lua_" in low
        stack = "openresty" if is_openresty else "nginx"

        if "server_tokens" not in low or not re.search(r"server_tokens\s+off\s*;", low):
            collector.findings.append(Finding(
                title="Nginx/OpenResty 未关闭 server_tokens（暴露版本号）", severity="low",
                category=stack, target=path,
                detail="配置中未见 server_tokens off，响应头会暴露中间件精确版本",
                remediation="在 http/server 块添加 server_tokens off; 并 reload",
            ))
        if re.search(r"autoindex\s+on\s*;", low):
            collector.findings.append(Finding(
                title="Nginx/OpenResty 开启 autoindex（目录列表泄露）", severity="medium",
                category=stack, target=path, detail="配置中存在 autoindex on;",
                remediation="关闭 autoindex，仅对确有需要的目录开放",
            ))
        if re.search(r"lua_code_cache\s+off\s*;", low):
            collector.findings.append(Finding(
                title="OpenResty 生产环境关闭了 lua_code_cache", severity="medium",
                category="openresty", target=path,
                detail="lua_code_cache off 会每请求重新加载 Lua 代码，存在性能与代码注入风险",
                remediation="生产环境设置 lua_code_cache on;",
            ))
        protocol = re.search(r"ssl_protocols\s+([^;]+);", low)
        if protocol and re.search(r"tlsv1(?:\.0|_1)?\b|sslv[23]\b", protocol.group(1)):
            collector.findings.append(Finding(
                title="Nginx/OpenResty 启用了已废弃的 TLS 协议", severity="medium",
                category=stack, target=path,
                detail=f"ssl_protocols {protocol.group(1).strip()}",
                remediation="仅保留 TLSv1.2 TLSv1.3，禁用 SSLv3 / TLSv1 / TLSv1.1",
            ))
        if re.search(r"client_max_body_size\s+0\s*;", low):
            collector.findings.append(Finding(
                title="Nginx/OpenResty 未限制请求体大小", severity="low",
                category=stack, target=path, detail="client_max_body_size 0 表示不限制",
                remediation="按业务需要设置合理的 client_max_body_size，缓解大请求 DoS",
            ))


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
READONLY_CHECKS = [
    "Java/JVM：java -version、Jar 文件名、pom.xml / build.gradle 依赖版本与 CVE 匹配",
    "Java 暴露面：Actuator Gateway 路由、Druid 监控页、Jolokia、Eureka、Swagger、WEB-INF/META-INF",
    "Go：go version、go.mod / go.sum 模块版本、容器与编排组件 CVE 匹配",
    "Go 暴露面：/debug/pprof/ 调试端点、/metrics 运行时指标端点",
    "C/C++：gcc/g++/clang、glibc、OpenSSL、zlib、libxml2、curl、libssh2、ImageMagick 等系统库 CVE 匹配",
    "Python：解释器版本、pip list、requirements.txt 依赖版本与 CVE 匹配",
    "Python 暴露面：Werkzeug 调试控制台（/console）、Django/Flask/Werkzeug 等组件版本",
    "Nginx：Server 头版本、nginx -v、stub_status 状态页、全部版本 CVE 与本地配置核查",
    "OpenResty：Server 头版本、捆绑 Nginx 版本推算、Lua 模块 CVE、lua_code_cache 配置核查",
    "Node.js：node/npm 版本、npm 全局包、package.json / package-lock.json / yarn.lock / pnpm-lock.yaml 依赖版本与 CVE 匹配",
    "Node.js 暴露面：package.json / 锁文件 / .npmrc / 服务端源码泄露、9229 inspector 调试端口未授权访问",
    "PHP：php -v、composer 版本与全局包、composer.json / composer.lock 依赖版本与 CVE/EOL 匹配",
    "PHP 暴露面：phpinfo、.env、composer.json/lock、vendor 依赖清单、Laravel 日志、Adminer、phpMyAdmin、wp-config 备份",
    ".NET：dotnet --version / --list-runtimes / --list-sdks、*.csproj / packages.config / packages.lock.json / project.assets.json / Directory.Packages.props 依赖与 EOL 匹配",
    ".NET 暴露面：elmah.axd、trace.axd、web.config、App_Data、Swagger/OpenAPI、Hangfire 仪表盘",
    "远端探测均为只读 GET，不执行代码、不写文件、不做漏洞利用",
]


def scan_stacks(
    ip: str,
    hostname: Optional[str] = None,
    web_infos: Optional[Sequence[WebInfo]] = None,
    services: Optional[Sequence[ServiceInfo]] = None,
    local: bool = False,
    web_timeout: float = 6.0,
    deep: bool = True,
    categories: str = "all",
    jar_dirs: Optional[Sequence[str]] = None,
    async_limit: int = 64,
    allow_async: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Finding], List[str]]:
    """执行全部技术栈扫描，返回 (组件清单, 漏洞发现, 已执行检测项)。"""
    active = parse_stacks(categories)
    collector = _Collector(active)
    scan_remote(collector, ip, services or [], web_infos or [])
    probe_count = scan_web_exposures(
        collector, ip, web_infos or [], web_timeout, deep=deep,
        async_limit=async_limit, allow_async=allow_async,
    )
    if local:
        scan_runtimes(collector)
        scan_dependency_files(collector, jar_dirs or [])
        scan_nginx_config(collector)

    unknown = [c for c in collector.components if c["version"] == "版本未知"]
    if unknown:
        collector.findings.append(Finding(
            title=f"{len(unknown)} 个技术栈组件未暴露版本，无法完成版本 CVE 匹配", severity="info",
            category="other", target=hostname or ip,
            detail="、".join(f"{c['product']}({c['stack_cn']})" for c in unknown[:20])
                   + ("..." if len(unknown) > 20 else ""),
            remediation="在服务器上执行 java -version / go version / python --version / nginx -v，"
                        "或用 --stack-local 与 --jar-dirs 指定依赖目录做本地版本核对",
        ))

    hit_components = [c for c in collector.components if c["cves"]]
    no_hit = [c for c in collector.components
              if not c["cves"] and c["version"] != "版本未知"]
    # 版本是否命中规则都算「已扫描」，单独给一条可见结论，避免未命中组件被当成没扫
    collector.findings.append(Finding(
        title=f"技术栈全量检测完成：{len(collector.components)} 个组件"
              f"（{len(hit_components)} 个命中规则 / {len(no_hit)} 个已比对未命中 / "
              f"{len(unknown)} 个版本未知）",
        severity="info", category="other", target=hostname or ip,
        detail="所有组件无论版本是否命中 CVE/EOL 规则，均已完成版本比对；"
               "所有技术栈的只读暴露面探针与本地配置核查均无条件执行，"
               "未命中仅表示当前离线规则库无匹配项，不代表未扫描或绝对安全。",
        remediation="未命中组件请结合厂商安全公告复核；版本未知组件建议用 "
                    "--stack-local / --jar-dirs 补充本地版本采集",
    ))

    checks = list(READONLY_CHECKS)
    checks.append(f"本次启用技术栈（仅影响组件清单/版本规则匹配）："
                  f"{'、'.join(STACK_CN.get(s, s) for s in sorted(active))}"
                  + ("（含本地运行时/依赖采集）" if local else "（仅远端只读探测）"))
    checks.append(f"识别出 {len(collector.components)} 个组件，"
                  f"命中 {sum(len(c['cves']) for c in collector.components)} 条版本规则；"
                  f"{len(no_hit)} 个已比对未命中、{len(unknown)} 个版本未知同样完成检测")
    checks.append(f"只读暴露面探测：{probe_count} 个 GET 探针全量执行"
                  f"（协程并发 {async_limit if allow_async else 0}，不因版本/类别是否命中跳过）")
    LOGGER.info("技术栈扫描完成：%d 个组件（命中 %d / 未命中 %d / 版本未知 %d），%d 项发现",
                len(collector.components), len(hit_components), len(no_hit), len(unknown),
                len(collector.findings))
    return collector.components, collector.findings, checks
