# -*- coding: utf-8 -*-
"""内置漏洞规则库（离线版本匹配）。

规则说明：
  products : 归一化后的产品名（包名 / 服务名）
  ranges   : 受影响的版本区间 [lo, hi)，'*' 表示任意版本
  confirm  : True 表示该结论可能受发行版补丁向后移植影响，需要二次确认
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Sequence, Tuple

from .stackdb import STACK_CATEGORIES, STACK_CN, STACK_RULES
from .utils import in_ranges


@dataclass(frozen=True)
class VulnRule:
    id: str
    name: str
    severity: str
    category: str
    products: Tuple[str, ...]
    ranges: Tuple[Tuple[str, str], ...] = ()
    remediation: str = ""
    reference: str = ""
    confirm: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


_BASE_RULES: Tuple[VulnRule, ...] = (
    # ---------------------- 操作系统 / 基础组件 ----------------------
    VulnRule("CVE-2021-3156", "sudo 堆溢出提权 (Baron Samedit)", "high", "os",
             ("sudo",), (("1.8.2", "1.8.32"), ("1.9.0", "1.9.5p2")),
             "升级 sudo 至 1.9.5p2 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-3156", confirm=True),
    VulnRule("CVE-2021-4034", "polkit pkexec 本地提权 (PwnKit)", "high", "os",
             ("polkit", "policykit-1", "policykit"), (("0.90", "0.121"),),
             "升级 polkit 至 0.121 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-4034", confirm=True),
    VulnRule("CVE-2022-0847", "Linux 内核脏管道提权 (Dirty Pipe)", "high", "os",
             ("kernel", "linux-kernel", "linux-image"), (("5.8", "5.16.11"),),
             "升级内核至 5.16.11 / 5.15.25 / 5.10.102 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2022-0847", confirm=True),
    VulnRule("CVE-2016-5195", "Linux 内核内存破坏提权 (Dirty COW)", "high", "os",
             ("kernel", "linux-kernel", "linux-image"), (("2.6.22", "4.8.3"),),
             "升级内核或安装发行版安全补丁",
             "https://nvd.nist.gov/vuln/detail/CVE-2016-5195", confirm=True),
    VulnRule("CVE-2024-1086", "Linux nf_tables 释放后重用提权", "high", "os",
             ("kernel", "linux-kernel", "linux-image"), (("5.14", "6.9"),),
             "升级内核至 6.6.15 / 6.7.3 / 6.8 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086", confirm=True),
    VulnRule("CVE-2023-4911", "glibc 栈溢出提权 (Looney Tunables)", "high", "os",
             ("glibc", "libc6", "libc-bin"), (("2.36", "2.39"),),
             "升级 glibc 至 2.39 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2023-4911", confirm=True),
    VulnRule("CVE-2014-6271", "Bash 远程命令执行 (Shellshock)", "critical", "os",
             ("bash",), (("1.14", "4.4"),),
             "升级 bash 至 4.4 及以上或安装发行版补丁",
             "https://nvd.nist.gov/vuln/detail/CVE-2014-6271", confirm=True),
    VulnRule("CVE-2021-44228", "Log4j2 远程代码执行 (Log4Shell)", "critical", "os",
             ("log4j", "log4j-core", "apache-log4j2"), (("2.0", "2.15.0"), ("2.0-beta1", "2.12.2")),
             "升级 Log4j 至 2.17.1 及以上，或移除 JndiLookup 类",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", confirm=True),

    # ---------------------- 加密库 / 传输 ----------------------
    VulnRule("CVE-2014-0160", "OpenSSL 内存泄露 (Heartbleed)", "critical", "os",
             ("openssl", "libssl1.0.0"), (("1.0.1", "1.0.1g"),),
             "升级 OpenSSL >= 1.0.1g，并轮换证书私钥",
             "https://nvd.nist.gov/vuln/detail/CVE-2014-0160", confirm=True),
    VulnRule("CVE-2022-3602", "OpenSSL X.509 Punycode 远程代码执行", "high", "os",
             ("openssl",), (("3.0.0", "3.0.7"),),
             "升级 OpenSSL 至 3.0.7 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2022-3602", confirm=True),
    VulnRule("CVE-2022-0778", "OpenSSL BN_mod_sqrt 无限循环拒绝服务", "medium", "os",
             ("openssl",), (("1.0.2", "1.0.2zd"), ("1.1.1", "1.1.1o"), ("3.0.0", "3.0.2")),
             "升级 OpenSSL 至 1.1.1o / 3.0.2 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2022-0778", confirm=True),
    VulnRule("EOL-OPENSSL-1.0.2", "OpenSSL 1.0.2 已停止维护", "medium", "os",
             ("openssl",), (("1.0.2", "1.1.0"),),
             "升级至 OpenSSL 1.1.1 或 3.x 长期支持版本", "", confirm=True),
    VulnRule("CVE-2024-6387", "OpenSSH 信号处理竞态远程代码执行 (regreSSHion)", "high", "os",
             ("openssh", "openssh-server", "ssh"), (("8.5", "9.8"),),
             "升级 OpenSSH 至 9.8/9.8p1 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2024-6387", confirm=True),
    VulnRule("CVE-2018-15473", "OpenSSH 用户名枚举", "low", "os",
             ("openssh", "openssh-server", "ssh"), (("1.0", "7.8"),),
             "升级 OpenSSH 至 7.8 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2018-15473", confirm=True),
    VulnRule("CVE-2023-38545", "curl SOCKS5 堆缓冲区溢出", "medium", "os",
             ("curl", "libcurl", "libcurl4"), (("7.69.0", "7.88.1"),),
             "升级 curl 至 7.88.1 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2023-38545", confirm=True),
    VulnRule("CVE-2023-38546", "curl Cookie 注入", "medium", "os",
             ("curl", "libcurl", "libcurl4"), (("7.9.1", "7.88.1"),),
             "升级 curl 至 7.88.1 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2023-38546", confirm=True),

    # ---------------------- Web 服务 / 应用 ----------------------
    VulnRule("CVE-2021-41773", "Apache HTTP Server 路径穿越", "critical", "web",
             ("httpd", "apache2", "apache", "apache-httpd"), (("2.4.49", "2.4.50"),),
             "升级 Apache 至 2.4.50 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-41773", confirm=True),
    VulnRule("CVE-2021-42013", "Apache HTTP Server 路径穿越与 RCE", "critical", "web",
             ("httpd", "apache2", "apache", "apache-httpd"), (("2.4.49", "2.4.51"),),
             "升级 Apache 至 2.4.51 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2021-42013", confirm=True),
    VulnRule("CVE-2019-0211", "Apache mod_auth 提权", "high", "web",
             ("httpd", "apache2", "apache", "apache-httpd"), (("2.4.0", "2.4.39"),),
             "升级 Apache 至 2.4.39 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-0211", confirm=True),
    VulnRule("CVE-2019-11043", "PHP-FPM 远程代码执行", "critical", "web",
             ("php", "php-fpm", "php7", "php8"), (("7.0", "7.3.11"),),
             "升级 PHP 至 7.3.11 / 7.4 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-11043", confirm=True),
    VulnRule("EOL-PHP", "PHP 版本已停止维护", "high", "web",
             ("php", "php5", "php7", "php-fpm"), (("5.0", "8.2"),),
             "8.1 及更早版本已停止官方维护，升级至 8.2+ 受支持版本（8.2 也将于 2026-12-31 终止维护）",
             "", confirm=True),
    VulnRule("CVE-2024-4577", "PHP CGI Windows 参数注入远程代码执行", "critical", "web",
             ("php", "php-cgi", "php8", "php8.1", "php8.2", "php8.3"),
             (("8.1", "8.1.29"), ("8.2", "8.2.20"), ("8.3", "8.3.8")),
             "升级 PHP 至 8.3.8 / 8.2.20 / 8.1.29 及以上，或改用非 CGI 方式部署",
             "https://nvd.nist.gov/vuln/detail/CVE-2024-4577", confirm=True),
    VulnRule("CVE-2012-1823", "PHP-CGI 参数注入（源码泄露 / 远程代码执行）", "critical", "web",
             ("php", "php-cgi", "php5", "php5.3", "php5.4"),
             (("5.3", "5.3.13"), ("5.4", "5.4.3")),
             "升级 PHP 或禁用 php-cgi 直接对外，改用 php-fpm / mod_php",
             "https://nvd.nist.gov/vuln/detail/CVE-2012-1823", confirm=True),
    VulnRule("CVE-2018-19518", "PHP imap_open 远程代码执行", "high", "web",
             ("php", "php5", "php7"),
             (("5.6", "5.6.39"), ("7.0", "7.0.33"), ("7.1", "7.1.25"), ("7.2", "7.2.13")),
             "升级 PHP 并禁用 imap 扩展或限制 imap_open 参数",
             "https://nvd.nist.gov/vuln/detail/CVE-2018-19518", confirm=True),
    # PHP2Shell（2026-10-21 官方公告，CVSS v4.0 9.2，UAF / CWE-416，未认证 RCE）
    VulnRule("CVE-2026-109618", "PHP2Shell - OOM 内存破坏远程代码执行", "critical", "web",
             ("php", "php-cgi", "php-fpm", "php7", "php8"),
             (("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35"),
              ("0.0", "8.2")),
             "升级至 PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35；无法立即升级时：memory_limit=-1"
             "（用 php_admin_value 设置，确保应用无法覆盖）、post_max_size=8M（需上传则 32M）、"
             "在反向代理限制请求体大小与字段数/分片数、用 cgroup 做可用性边界",
             "https://www.php.net/archive/2026.php#2026-10-21-5", confirm=True),
    VulnRule("CVE-2026-109619", "PHP2Shell - 失效全局状态远程代码执行", "critical", "web",
             ("php", "php-cgi", "php-fpm", "php7", "php8"),
             (("8.5", "8.5.12"), ("8.4", "8.4.27"), ("8.3", "8.3.36"), ("8.2", "8.2.35"),
              ("0.0", "8.2")),
             "升级至 PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35；无法立即升级时："
             "session.upload_progress.enabled=0 并重启所有 worker（PHP 8.5 另设 fatal_error_backtraces=0），"
             "移除会在初始化前产生诊断的无效/废弃设置，修复可被攻击者触发的 fatal error 与执行超时",
             "https://www.php.net/archive/2026.php#2026-10-21-5", confirm=True),
    VulnRule("CVE-2020-1938", "Tomcat AJP 文件读取/包含 (Ghostcat)", "high", "web",
             ("tomcat", "tomcat7", "tomcat8", "tomcat9", "apache-tomcat"),
             (("6.0", "9.0.31"), ("8.5", "8.5.51"), ("7.0", "7.0.100")),
             "升级 Tomcat 至 9.0.31 / 8.5.51 / 7.0.100 及以上，或关闭 AJP 对外监听",
             "https://nvd.nist.gov/vuln/detail/CVE-2020-1938", confirm=True),
    VulnRule("CVE-2017-5638", "Apache Struts2 远程代码执行", "critical", "web",
             ("struts", "struts2", "struts2-core"),
             (("2.0", "2.3.33"), ("2.5", "2.5.12")),
             "升级 Struts2 至 2.3.33 / 2.5.12 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2017-5638", confirm=True),
    VulnRule("CVE-2022-22965", "Spring 框架远程代码执行 (Spring4Shell)", "critical", "web",
             ("spring-beans", "spring-core", "springframework"),
             (("5.3.0", "5.3.18"), ("5.2.0", "5.2.20")),
             "升级 Spring 至 5.3.18 / 5.2.20 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2022-22965", confirm=True),
    VulnRule("CVE-2019-2725", "Oracle WebLogic 反序列化远程代码执行", "critical", "web",
             ("weblogic",), (("*", "")),
             "安装 Oracle 最新 CPU 补丁并限制 /_async 与 wls-wsat 访问",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-2725", confirm=True),
    VulnRule("EOL-NGINX", "Nginx 版本过旧", "medium", "web",
             ("nginx",), (("0.1", "1.20.0"),),
             "升级 Nginx 至 1.20+ / 1.24+ 稳定版", "", confirm=True),

    # ---------------------- 中间件 / 服务 ----------------------
    VulnRule("CVE-2011-2523", "vsftpd 2.3.4 后门", "critical", "service",
             ("vsftpd",), (("2.3.4", "2.3.5"),),
             "立即升级 vsftpd，排查是否存在异常监听 6200 端口",
             "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
    VulnRule("CVE-2019-12815", "ProFTPD mod_copy 未授权文件复制", "critical", "service",
             ("proftpd", "proftpd-basic"), (("1.3.0", "1.3.6"),),
             "升级 ProFTPD 至 1.3.6 及以上并禁用 mod_copy",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-12815", confirm=True),
    VulnRule("CVE-2019-10149", "Exim 邮件服务器远程命令执行", "critical", "service",
             ("exim", "exim4"), (("4.0", "4.92"),),
             "升级 Exim 至 4.92 及以上",
             "https://nvd.nist.gov/vuln/detail/CVE-2019-10149", confirm=True),
    VulnRule("EOL-REDIS", "Redis 版本过旧，建议升级", "low", "service",
             ("redis", "redis-server"), (("0.1", "6.0"),),
             "升级 Redis 至 6.x / 7.x 并启用 ACL 与 requirepass", ""),
    VulnRule("EOL-MYSQL", "MySQL 版本已停止维护", "medium", "service",
             ("mysql", "mysql-server", "mariadb", "mariadb-server"), (("0.1", "5.7"),),
             "升级至 MySQL 8.0 / MariaDB 10.6 及以上", "", confirm=True),
    VulnRule("EOL-POSTGRES", "PostgreSQL 版本已停止维护", "medium", "service",
             ("postgresql", "postgresql-server"), (("0.1", "12.0"),),
             "升级至 PostgreSQL 12+ 版本", "", confirm=True),
)

# 技术栈规则（Java / Go / C++ / Python / Nginx / OpenResty）由 stackdb.py 维护，
# 在此统一实例化并合并进索引，match_rules / rules_for_category 无需改动。
RULES: Tuple[VulnRule, ...] = _BASE_RULES + tuple(
    VulnRule(**rule) for rule in STACK_RULES
)

# 产品名 -> 规则列表
_INDEX: Dict[str, List[VulnRule]] = {}
for _rule in RULES:
    for _name in _rule.products:
        _INDEX.setdefault(_name.lower(), []).append(_rule)


def normalize_product(name: str) -> str:
    return (name or "").strip().lower().replace("_", "-")


def match_rules(product: str, version: str = "") -> List[VulnRule]:
    """按产品名 + 版本匹配漏洞规则。"""
    key = normalize_product(product)
    if not key:
        return []
    hits: List[VulnRule] = []
    for rule in _INDEX.get(key, []):
        if in_ranges(version, rule.ranges):
            hits.append(rule)
    # 去掉重复（同一规则可能被多个别名命中）
    seen = set()
    unique: List[VulnRule] = []
    for rule in hits:
        if rule.id in seen:
            continue
        seen.add(rule.id)
        unique.append(rule)
    return unique


def rules_for_category(category: str) -> List[VulnRule]:
    return [r for r in RULES if r.category == category]


def stack_rule_counts() -> Dict[str, int]:
    """各技术栈的规则条数（用于 --list-rules 展示）。"""
    counts = {name: 0 for name in STACK_CATEGORIES}
    for rule in RULES:
        if rule.category in counts:
            counts[rule.category] += 1
    return counts
