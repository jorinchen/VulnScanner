# -*- coding: utf-8 -*-
"""操作系统漏洞与配置审计。

本地审计：读取发行版信息、内核版本、已安装软件包版本，与内置 CVE 规则匹配；
同时检查常见高风险系统配置（SSH、防火墙、SMBv1、补丁状态等）。
远程审计：依据服务 banner 推断操作系统，必要时调用已安装的 nmap -O。
"""

from __future__ import annotations

import os
import platform
import re
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding, ServiceInfo
from .utils import LOGGER, run_command
from .vulndb import match_rules

# 已停止维护的发行版（信息仅供参考）
EOL_DISTROS = {
    "centos 6": "CentOS 6 已于 2020-11 停止维护",
    "centos 7": "CentOS 7 已于 2024-06 停止维护",
    "centos 8": "CentOS 8 已于 2021-12 停止维护",
    "ubuntu 14.04": "Ubuntu 14.04 已停止标准维护",
    "ubuntu 16.04": "Ubuntu 16.04 已停止标准维护",
    "ubuntu 18.04": "Ubuntu 18.04 标准维护已结束（可购买 ESM）",
    "debian 8": "Debian 8 (jessie) 已停止维护",
    "debian 9": "Debian 9 (stretch) 已停止维护",
    "debian 10": "Debian 10 (buster) LTS 维护即将结束",
    "windows server 2008": "Windows Server 2008/R2 已停止支持",
    "windows server 2012": "Windows Server 2012/R2 已于 2023-10 停止支持",
    "windows 7": "Windows 7 已停止支持",
    "windows xp": "Windows XP 已停止支持",
}


# --------------------------------------------------------------------------- #
# 软件包枚举
# --------------------------------------------------------------------------- #
def _dpkg_packages() -> Dict[str, str]:
    code, out, _ = run_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
    if code != 0:
        return {}
    pkgs = {}
    for line in out.splitlines():
        if "\t" in line:
            name, version = line.split("\t", 1)
            pkgs[name.strip().lower()] = version.strip()
    return pkgs


def _rpm_packages() -> Dict[str, str]:
    code, out, _ = run_command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=60)
    if code != 0:
        return {}
    pkgs = {}
    for line in out.splitlines():
        if "\t" in line:
            name, version = line.split("\t", 1)
            pkgs[name.strip().lower()] = version.strip()
    return pkgs


def _apk_packages() -> Dict[str, str]:
    code, out, _ = run_command(["apk", "info", "-v"], timeout=30)
    if code != 0:
        return {}
    pkgs = {}
    for line in out.splitlines():
        m = re.match(r"^([\w.\-+]+)-([\d].*)$", line.strip())
        if m:
            pkgs[m.group(1).lower()] = m.group(2)
    return pkgs


def installed_packages() -> Tuple[Dict[str, str], str]:
    """返回 (包名->版本, 包管理器名)。"""
    for func, manager in ((_dpkg_packages, "dpkg"), (_rpm_packages, "rpm"), (_apk_packages, "apk")):
        pkgs = func()
        if pkgs:
            return pkgs, manager
    return {}, "unknown"


# --------------------------------------------------------------------------- #
# Linux 审计
# --------------------------------------------------------------------------- #
def _read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        data[key] = value.strip('"')
            break
        except OSError:
            continue
    return data


def _check_sshd_config() -> List[Finding]:
    findings: List[Finding] = []
    path = "/etc/ssh/sshd_config"
    if not os.path.isfile(path):
        return findings
    try:
        content = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return findings

    def _value(key: str) -> Optional[str]:
        m = re.search(rf"^\s*{key}\s+(\S+)", content, re.M | re.I)
        return m.group(1).lower() if m else None

    permit_root = _value("PermitRootLogin")
    if permit_root in ("yes", "without-password", "prohibit-password") and permit_root == "yes":
        findings.append(Finding(
            title="SSH 允许 root 直接登录", severity="medium", category="os",
            target=path, detail="PermitRootLogin yes",
            remediation="设置 PermitRootLogin no，改用普通用户登录后提权",
        ))
    if _value("PasswordAuthentication") == "yes":
        findings.append(Finding(
            title="SSH 允许口令认证", severity="low", category="os", target=path,
            detail="PasswordAuthentication yes",
            remediation="改用公钥认证并设置 PasswordAuthentication no",
        ))
    if _value("PermitEmptyPasswords") == "yes":
        findings.append(Finding(
            title="SSH 允许空口令登录", severity="critical", category="os", target=path,
            detail="PermitEmptyPasswords yes", remediation="立即设置为 no 并审计账户",
        ))
    if _value("X11Forwarding") == "yes":
        findings.append(Finding(
            title="SSH 开启 X11 转发", severity="low", category="os", target=path,
            remediation="如无需要请设置 X11Forwarding no",
        ))
    return findings


def _check_firewall() -> List[Finding]:
    findings: List[Finding] = []
    code, out, _ = run_command(["ufw", "status"], timeout=15)
    if code == 0 and out:
        if re.search(r"^Status:\s*inactive", out, re.M | re.I):
            findings.append(Finding(
                title="防火墙(ufw)未启用", severity="medium", category="os", target="localhost",
                detail="ufw status: inactive", remediation="启用 ufw 并仅放行必要端口",
            ))
        return findings
    code, out, _ = run_command(["firewall-cmd", "--state"], timeout=15)
    if code == 0:
        if "not running" in out.lower():
            findings.append(Finding(
                title="防火墙(firewalld)未运行", severity="medium", category="os", target="localhost",
                remediation="启动 firewalld 并配置放行策略",
            ))
        return findings
    code, out, _ = run_command(["iptables", "-L", "-n"], timeout=15)
    if code == 0 and out.count("\n") <= 8:
        findings.append(Finding(
            title="iptables 规则为空", severity="medium", category="os", target="localhost",
            remediation="配置 iptables/nftables 默认拒绝策略",
        ))
    return findings


def _check_selinux() -> List[Finding]:
    code, out, _ = run_command(["getenforce"], timeout=10)
    if code == 0 and "disabled" in out.lower():
        return [Finding(
            title="SELinux 已禁用", severity="low", category="os", target="localhost",
            detail=out.strip(), remediation="建议启用 SELinux 或改用 AppArmor 等强制访问控制",
        )]
    code, out, _ = run_command(["aa-status"], timeout=10)
    if code == 0 and "apparmor module is not loaded" in out.lower():
        return [Finding(
            title="AppArmor 未加载", severity="info", category="os", target="localhost",
            remediation="启用 AppArmor 以限制服务权限",
        )]
    return []


def _check_pending_updates() -> List[Finding]:
    """检查是否存在待安装的安全更新。"""
    code, out, _ = run_command(["apt-get", "-s", "upgrade"], timeout=60)
    if code == 0 and out:
        upgraded = re.findall(r"^Inst\s+(\S+)", out, re.M)
        security = [p for p in upgraded if re.search(r"security|ubuntu\d|deb\d+u", p)]
        if upgraded:
            return [Finding(
                title=f"存在 {len(upgraded)} 个待升级软件包（其中疑似安全更新 {len(security)} 个）",
                severity="medium" if security else "info", category="os", target="localhost",
                detail="、".join(upgraded[:20]) + ("..." if len(upgraded) > 20 else ""),
                remediation="执行 apt-get upgrade / yum update 及时修补",
            )]
    code, out, _ = run_command(["dnf", "check-update", "--security"], timeout=90)
    if code == 100 and out.strip():
        return [Finding(
            title="存在待安装的安全更新 (dnf)",
            severity="medium", category="os", target="localhost",
            detail="\n".join(out.strip().splitlines()[:15]),
            remediation="执行 dnf update --security",
        )]
    code, out, _ = run_command(["yum", "check-update", "--security"], timeout=90)
    if code == 100 and out.strip():
        return [Finding(
            title="存在待安装的安全更新 (yum)",
            severity="medium", category="os", target="localhost",
            detail="\n".join(out.strip().splitlines()[:15]),
            remediation="执行 yum update --security",
        )]
    return []


def linux_audit() -> Tuple[Dict[str, Any], List[Finding]]:
    findings: List[Finding] = []
    release = _read_os_release()
    name = release.get("NAME", platform.system())
    version_id = release.get("VERSION_ID", "")
    kernel = platform.release()

    os_info: Dict[str, Any] = {
        "system": "Linux",
        "distribution": f"{name} {version_id}".strip(),
        "kernel": kernel,
        "architecture": platform.machine(),
        "hostname": platform.node(),
    }

    # 发行版 EOL
    key = f"{name} {version_id}".strip().lower()
    for eol_key, message in EOL_DISTROS.items():
        if eol_key in key:
            findings.append(Finding(
                title=f"操作系统已停止维护：{name} {version_id}", severity="high", category="os",
                target="localhost", detail=message,
                remediation="升级到受支持的发行版版本或购买扩展支持",
            ))

    # 内核漏洞
    kernel_clean = re.sub(r"-[a-z].*$", "", kernel)
    for rule in match_rules("kernel", kernel_clean):
        findings.append(Finding(
            title=rule.name, severity=rule.severity, category="os", target="localhost", cve=rule.id,
            detail=f"当前内核 {kernel} 命中规则（发行版可能已向后移植补丁，需二次确认）",
            evidence=f"uname -r => {kernel}",
            remediation=rule.remediation, reference=rule.reference,
        ))

    # 软件包 CVE 匹配
    pkgs, manager = installed_packages()
    os_info["package_manager"] = manager
    os_info["package_count"] = len(pkgs)
    audit_targets = {
        "sudo", "polkit", "policykit-1", "glibc", "libc6", "bash", "openssl", "libssl1.0.0",
        "openssh", "openssh-server", "curl", "libcurl4", "httpd", "apache2", "nginx", "php",
        "php-fpm", "tomcat", "tomcat9", "tomcat8", "redis", "redis-server", "mysql", "mysql-server",
        "mariadb", "mariadb-server", "postgresql", "exim", "exim4", "proftpd", "vsftpd",
        "libssl3", "log4j", "php7", "php8", "kernel",
    }
    for pkg, version in pkgs.items():
        base = re.sub(r"[0-9].*$", "", pkg)  # php7.4 -> php
        if pkg not in audit_targets and base not in audit_targets:
            continue
        for rule in match_rules(pkg, version):
            findings.append(Finding(
                title=f"{rule.name}（{pkg} {version}）", severity=rule.severity, category="os",
                target="localhost", cve=rule.id,
                detail=f"已安装 {pkg}={version}，命中已知漏洞规则"
                       + ("（发行版可能已向后移植补丁，需结合 changelog 二次确认）" if rule.confirm else ""),
                evidence=f"{manager}: {pkg} {version}",
                remediation=rule.remediation, reference=rule.reference,
            ))

    # 配置审计
    findings.extend(_check_sshd_config())
    findings.extend(_check_firewall())
    findings.extend(_check_selinux())
    findings.extend(_check_pending_updates())
    return os_info, findings


# --------------------------------------------------------------------------- #
# Windows 审计
# --------------------------------------------------------------------------- #
def _win_hotfixes() -> List[str]:
    code, out, _ = run_command(
        ["powershell", "-NoProfile", "-Command",
         "(Get-HotFix | Select-Object -ExpandProperty HotFixID) -join ','"],
        timeout=90,
    )
    if code == 0 and out.strip():
        return [h.strip() for h in out.strip().split(",") if h.strip().upper().startswith("KB")]
    code, out, _ = run_command(["wmic", "qfe", "list", "brief"], timeout=90)
    return re.findall(r"KB\d+", out)


def windows_audit() -> Tuple[Dict[str, Any], List[Finding]]:
    findings: List[Finding] = []
    version = platform.version()
    os_info: Dict[str, Any] = {
        "system": "Windows",
        "distribution": platform.platform(),
        "kernel": version,
        "architecture": platform.machine(),
        "hostname": platform.node(),
    }

    build = 0
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if m:
        build = int(m.group(3))
    os_info["build"] = build

    hotfixes = _win_hotfixes()
    os_info["hotfix_count"] = len(hotfixes)
    os_info["hotfixes"] = sorted(hotfixes)[-30:]

    # EOL / 版本判断
    if build and build < 7601:
        findings.append(Finding(
            title="Windows 版本过旧（已停止支持）", severity="critical", category="os",
            target="localhost", detail=f"内部版本 {build}",
            remediation="升级到受支持的 Windows Server 版本",
        ))
    elif 7600 <= build <= 7601:
        findings.append(Finding(
            title="Windows 7 / Server 2008 R2 已停止支持", severity="high", category="os",
            target="localhost", detail=f"内部版本 {build}",
            remediation="升级操作系统或购买 ESU",
        ))
    elif 9200 <= build <= 9600:
        findings.append(Finding(
            title="Windows 8 / Server 2012(R2) 已停止支持", severity="high", category="os",
            target="localhost", detail=f"内部版本 {build}",
            remediation="升级至 Windows Server 2019/2022",
        ))

    # SMBv1 是否启用
    code, out, _ = run_command(
        ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "/v", "SMB1"],
        timeout=20,
    )
    if code == 0 and re.search(r"SMB1\s+REG_DWORD\s+0x1", out):
        findings.append(Finding(
            title="SMBv1 已启用（存在 MS17-010 等蠕虫化攻击风险）", severity="critical", category="os",
            target="localhost", detail="注册表 SMB1 = 1",
            remediation="执行 Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            reference="https://learn.microsoft.com/zh-cn/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1",
        ))

    # Print Spooler（PrintNightmare 相关）
    code, out, _ = run_command(["sc", "query", "Spooler"], timeout=20)
    if code == 0 and "RUNNING" in out.upper():
        if "Server" not in platform.platform():
            findings.append(Finding(
                title="Print Spooler 服务在运行（非打印服务器建议关闭）", severity="medium",
                category="os", target="localhost",
                detail="PrintNightmare (CVE-2021-34527) 等漏洞与该服务相关",
                remediation="非域控/打印服务器请禁用 Spooler 并安装最新补丁",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2021-34527",
            ))
        else:
            findings.append(Finding(
                title="Print Spooler 运行中（需确认 CVE-2021-34527 补丁）", severity="low",
                category="os", target="localhost",
                remediation="安装 KB5004945 及以上补丁，并限制 Point and Print 驱动安装权限",
            ))

    # 防火墙状态
    code, out, _ = run_command(
        ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=30,
    )
    if code == 0 and re.search(r"State\s+OFF", out, re.I):
        findings.append(Finding(
            title="Windows 防火墙部分配置文件已关闭", severity="medium", category="os",
            target="localhost", detail="netsh advfirewall 状态中存在 OFF",
            remediation="启用域/专用/公用三种配置的防火墙",
        ))

    # PowerShell 版本
    code, out, _ = run_command(
        ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], timeout=45,
    )
    if code == 0 and out.strip():
        ps_version = out.strip().splitlines()[-1]
        os_info["powershell"] = ps_version
        try:
            if float(ps_version.split(".")[0]) < 5:
                findings.append(Finding(
                    title="PowerShell 版本过旧", severity="low", category="os", target="localhost",
                    detail=f"PowerShell {ps_version}",
                    remediation="升级到 PowerShell 5.1/7 并启用脚本块日志与 AMSI",
                ))
        except ValueError:
            pass

    # RDP 相关
    code, out, _ = run_command(
        ["reg", "query", r"HKLM\System\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections"],
        timeout=20,
    )
    if code == 0 and re.search(r"fDenyTSConnections\s+REG_DWORD\s+0x0", out):
        findings.append(Finding(
            title="远程桌面已启用", severity="info", category="os", target="localhost",
            detail="fDenyTSConnections = 0",
            remediation="启用网络级别认证(NLA)、限制来源 IP 并配置账户锁定策略",
        ))
    return os_info, findings


# --------------------------------------------------------------------------- #
# macOS 审计
# --------------------------------------------------------------------------- #
def macos_audit() -> Tuple[Dict[str, Any], List[Finding]]:
    code, out, _ = run_command(["sw_vers"], timeout=20)
    os_info: Dict[str, Any] = {
        "system": "macOS",
        "distribution": out.replace("\n", " | ").strip() if code == 0 else platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
    }
    findings: List[Finding] = []
    code, out, _ = run_command(["softwareupdate", "--list"], timeout=120)
    if code == 0 and "recommended" in out.lower():
        findings.append(Finding(
            title="存在未安装的系统更新", severity="medium", category="os", target="localhost",
            detail="\n".join(out.strip().splitlines()[:10]),
            remediation="执行 softwareupdate -i -a",
        ))
    return os_info, findings


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def local_audit() -> Tuple[Dict[str, Any], List[Finding]]:
    system = platform.system()
    LOGGER.info("开始本地操作系统审计（%s）...", system)
    if system == "Linux":
        return linux_audit()
    if system == "Windows":
        return windows_audit()
    if system == "Darwin":
        return macos_audit()
    return ({
        "system": system,
        "distribution": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
    }, [])


def remote_os_guess(host: str, services: List[ServiceInfo], use_nmap: bool = True) -> Dict[str, Any]:
    """依据 banner 推断远端操作系统；若本机安装了 nmap 则尝试调用 nmap -O。"""
    guess: Dict[str, Any] = {"method": "banner", "candidates": []}
    blob = " ".join((s.banner or "") + " " + (s.product or "") for s in services).lower()

    candidates = set()
    if "ubuntu" in blob:
        candidates.add("Linux (Ubuntu)")
    if "debian" in blob:
        candidates.add("Linux (Debian)")
    if "centos" in blob or "cloudlinux" in blob:
        candidates.add("Linux (CentOS/RHEL)")
    if "windows" in blob or "microsoft" in blob or "iis/" in blob:
        candidates.add("Windows")
    if "freebsd" in blob:
        candidates.add("FreeBSD")
    if "openssh" in blob and not candidates:
        candidates.add("Linux/Unix (OpenSSH)")
    guess["candidates"] = sorted(candidates)

    if use_nmap:
        code, out, _ = run_command(["nmap", "-O", "--osscan-guess", "-T4", host], timeout=180)
        if code == 0 and out:
            lines = [ln.strip() for ln in out.splitlines() if re.search(r"(OS:|OS details|Running:|Aggressive OS)", ln)]
            if lines:
                guess["method"] = "nmap"
                guess["nmap"] = lines[:8]
    return guess
