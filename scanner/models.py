# -*- coding: utf-8 -*-
"""扫描结果数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    """一条漏洞/风险发现。"""

    title: str
    severity: str = "info"        # critical / high / medium / low / info
    category: str = "other"       # port / service / web / os / php(PHP) / php2shell(PHP2Shell) / dotnet / config
    target: str = ""
    cve: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PortInfo:
    """端口扫描结果。"""

    port: int
    protocol: str = "tcp"
    state: str = "closed"         # open / closed / filtered
    service: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceInfo:
    """服务指纹 + 试探性连接结果。"""

    port: int
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    unauth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebInfo:
    """Web 应用信息。"""

    url: str = ""
    scheme: str = ""
    vhost: str = ""       # 以该域名/主机名访问（Host 头 + SNI），为空表示直接用 IP 访问
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    tls: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """针对单个目标的完整报告。"""

    target: str = ""
    ip: str = ""
    hostname: Optional[str] = None
    os_info: Dict[str, Any] = field(default_factory=dict)
    ports: List[PortInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    web: List[WebInfo] = field(default_factory=list)
    php2shell: List[Dict[str, Any]] = field(default_factory=list)
    stacks: List[Dict[str, Any]] = field(default_factory=list)
    stack_checks: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    started: str = ""
    finished: str = ""
    duration: float = 0.0

    def add(self, finding: Finding) -> None:
        # 同一目标上的同名同 CVE 条目只保留一条（Web 扫描与 PHP2Shell 检测可能重复命中）
        for exists in self.findings:
            if (exists.title == finding.title
                    and (exists.cve or "") == (finding.cve or "")
                    and exists.target == finding.target):
                if len(finding.detail) > len(exists.detail):
                    exists.detail = finding.detail
                if not exists.evidence and finding.evidence:
                    exists.evidence = finding.evidence
                return
        self.findings.append(finding)

    def sorted_findings(self) -> List[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(self.findings, key=lambda f: (order.get(f.severity, 9), f.category))

    def severity_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "ip": self.ip,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "ports": [p.to_dict() for p in self.ports],
            "services": [s.to_dict() for s in self.services],
            "web": [w.to_dict() for w in self.web],
            "php2shell": self.php2shell,
            "stacks": self.stacks,
            "stack_checks": self.stack_checks,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "summary": self.severity_counts(),
            "started": self.started,
            "finished": self.finished,
            "duration": self.duration,
        }
