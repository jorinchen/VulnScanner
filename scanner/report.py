# -*- coding: utf-8 -*-
"""报告输出：控制台摘要、JSON、HTML。"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any, Dict, List

from .models import ScanReport
from .utils import SEVERITY_CN

SEVERITY_COLOR = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}

SEVERITY_EMOJI_FREE = {
    "critical": "[严重]",
    "high": "[高危]",
    "medium": "[中危]",
    "low": "[低危]",
    "info": "[信息]",
}

CATEGORY_CN = {
    "port": "端口",
    "service": "服务",
    "web": "Web",
    "os": "系统",
    "php": "PHP",
    "php2shell": "PHP2Shell",
    "dotnet": ".NET",
    "config": "配置",
    "java": "Java",
    "go": "Go",
    "cpp": "C/C++",
    "python": "Python",
    "nginx": "Nginx",
    "openresty": "OpenResty",
    "nodejs": "Node.js",
    "other": "其他",
}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def print_console(report: ScanReport) -> None:
    counts = report.severity_counts()
    print()
    print("=" * 78)
    print(f"目标：{report.target}  ({report.ip})" + (f"  主机名：{report.hostname}" if report.hostname else ""))
    if report.os_info:
        distro = report.os_info.get("distribution") or report.os_info.get("system", "")
        print(f"操作系统：{distro}  内核/版本：{report.os_info.get('kernel', '')}")
    opened = [p for p in report.ports if p.state == "open"]
    print(f"开放端口 {len(opened)} 个：" + (", ".join(str(p.port) for p in opened) if opened else "无"))
    print("-" * 78)
    print("风险统计：" + "  ".join(f"{SEVERITY_CN.get(k, k)}={v}" for k, v in counts.items()))
    print("-" * 78)
    if not report.findings:
        print("未发现风险项。")
    for finding in report.sorted_findings():
        cat = CATEGORY_CN.get(finding.category, finding.category)
        print(f"{SEVERITY_EMOJI_FREE.get(finding.severity, '[信息]')}[{cat}] {finding.title}"
              + (f"  ({finding.cve})" if finding.cve else ""))
        print(f"       位置：{finding.target or '-'}")
        if finding.detail:
            print(f"       说明：{finding.detail}")
        if finding.evidence:
            print(f"       证据：{finding.evidence}")
        if finding.remediation:
            print(f"       修复：{finding.remediation}")
        if finding.reference:
            print(f"       参考：{finding.reference}")

    if report.php2shell:
        print("-" * 78)
        print("PHP2Shell 检测（PHP 站点 getshell 入口）：")
        for item in report.php2shell:
            tag = (f"PHP {item.get('php_version') or '版本未知'}" if item.get("php")
                   else "未识别为 PHP 站点（仍执行全量检测）")
            print(f"  · {item.get('url', '')}  {tag}  "
                  + ("已启用无害执行验证" if item.get("verified") else "仅只读检测"))
            rows = item.get("findings", [])
            if not rows:
                print("      - 未发现 PHP2Shell 入口")
            for row in rows:
                print(f"      - [{SEVERITY_CN.get(row.get('severity'), row.get('severity'))}] "
                      f"{row.get('title')}" + (f" ({row.get('cve')})" if row.get("cve") else ""))

    if report.stacks or report.stack_checks:
        print("-" * 78)
        print("技术栈组件漏洞扫描（Java / Go / C++ / Python / Nginx / OpenResty）：")
        hits = [item for item in report.stacks if item.get("cves")]
        print(f"  识别组件 {len(report.stacks)} 个，命中版本规则 {len(hits)} 个")
        for item in hits[:25]:
            cves = "、".join(item.get("cves", [])[:5])
            if len(item.get("cves", [])) > 5:
                cves += "..."
            print(f"  · [{item.get('stack_cn', '')}] {item.get('product')} "
                  f"{item.get('version')}  -> {cves}")
        if len(hits) > 25:
            print(f"  · ... 其余 {len(hits) - 25} 个组件详见报告")
    print("=" * 78)


def to_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=indent)


def to_html(report: ScanReport) -> str:
    counts = report.severity_counts()
    findings = report.sorted_findings()
    opened = [p for p in report.ports if p.state == "open"]

    os_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        for k, v in report.os_info.items()
        if not isinstance(v, (list, dict))
    )

    port_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(p.port), _esc(p.protocol), _esc(p.state), _esc(p.service),
            _esc(next((s.product for s in report.services if s.port == p.port), "")),
            _esc(next((s.version for s in report.services if s.port == p.port), "")),
        )
        for p in opened
    ) or "<tr><td colspan='6'>未发现开放端口</td></tr>"

    web_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(w.url), _esc(w.vhost or "(IP 直接访问)"), _esc(w.status), _esc(w.title),
            _esc(w.server), _esc(w.powered_by), _esc("、".join(w.technologies)),
        )
        for w in report.web
    ) or "<tr><td colspan='7'>未检测到 Web 服务</td></tr>"

    # ---- PHP2Shell 专区 ----
    php_blocks = []
    php_risk = 0
    for item in report.php2shell:
        php_risk += sum(
            1 for f in item.get("findings", []) if f.get("severity") in ("critical", "high")
        )
        f_rows = "".join(
            "<tr>"
            f"<td><span class='badge' style='background:{SEVERITY_COLOR.get(f.get('severity'), '#64748b')}'>"
            f"{_esc(SEVERITY_CN.get(f.get('severity'), f.get('severity')))}</span></td>"
            f"<td>{_esc(f.get('title'))}</td>"
            f"<td>{_esc(f.get('cve'))}</td>"
            f"<td>{_esc(f.get('detail'))}</td>"
            "</tr>"
            for f in item.get("findings", [])
        ) or "<tr><td colspan='4'>未发现 PHP2Shell 入口</td></tr>"
        checks = "".join(f"<li>{_esc(c)}</li>" for c in item.get("checks", []))
        if item.get("php"):
            head = (f"{_esc(item.get('url'))} · PHP {_esc(item.get('php_version') or '版本未知')}"
                    f" · {'已启用无害执行验证' if item.get('verified') else '仅只读检测'}")
        else:
            head = (f"{_esc(item.get('url'))} · 未识别为 PHP 站点（仍执行全量检测）"
                    f" · {'已启用无害执行验证' if item.get('verified') else '仅只读检测'}")
        php_blocks.append(
            "<div class='php-block'>"
            f"<div class='php-head'>{head}</div>"
            f"<div class='php-sub'>已检测项：</div><ul class='checks'>{checks}</ul>"
            "<table>"
            "<tr><th style='width:70px'>等级</th><th>问题</th><th style='width:140px'>CVE/编号</th><th>说明</th></tr>"
            f"{f_rows}</table>"
            "</div>"
        )
    php_html = "".join(php_blocks) or (
        "<div class='note'>目标未检测到 Web 服务，未执行 PHP2Shell 检测。</div>"
    )

    # ---- 技术栈组件专区 ----
    stack_hits = sum(1 for item in report.stacks if item.get("cves"))
    stack_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
        "<td class='evi'>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(item.get("stack_cn")),
            _esc(item.get("product")),
            _esc(item.get("version")),
            _esc(item.get("target")),
            _esc(item.get("source")),
            _esc("、".join(item.get("cves", [])[:8]) or "未命中版本规则"),
            _esc(SEVERITY_CN.get(item.get("max_severity"), item.get("max_severity"))),
            _esc(item.get("check_status", "已检测")),
        )
        for item in report.stacks
    ) or "<tr><td colspan='8'>未识别到技术栈组件</td></tr>"
    stack_checks_html = "".join(f"<li>{_esc(c)}</li>" for c in report.stack_checks)

    find_rows = []
    for f in findings:
        ref_html = (
            f"<a href='{_esc(f.reference)}' target='_blank'>链接</a>" if f.reference else ""
        )
        badge_color = SEVERITY_COLOR.get(f.severity, "#64748b")
        badge_text = SEVERITY_CN.get(f.severity, f.severity)
        find_rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{badge_color}'>{_esc(badge_text)}</span></td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.cve)}</td>"
            f"<td>{_esc(CATEGORY_CN.get(f.category, f.category))}</td>"
            f"<td>{_esc(f.target)}</td>"
            f"<td>{_esc(f.detail)}</td>"
            f"<td class='evi'>{_esc(f.evidence)}</td>"
            f"<td>{_esc(f.remediation)}</td>"
            f"<td>{ref_html}</td>"
            "</tr>"
        )
    find_rows_html = "".join(find_rows) or "<tr><td colspan='9'>未发现风险项</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>漏洞扫描报告 - {_esc(report.target)}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0; background:#f1f5f9; color:#0f172a; }}
  .wrap {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color:#64748b; font-size: 13px; margin-bottom: 20px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
  .card {{ flex:1; min-width:110px; background:#fff; border-radius:10px; padding:14px 16px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ font-size:12px; color:#64748b; }}
  section {{ background:#fff; border-radius:10px; padding:16px 18px; margin-bottom:18px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  h2 {{ font-size:16px; margin:0 0 12px; border-left:4px solid #2563eb; padding-left:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ border-bottom:1px solid #e2e8f0; padding:7px 8px; text-align:left; vertical-align:top; word-break:break-all; }}
  th {{ background:#f8fafc; font-weight:600; }}
  tr:hover td {{ background:#f8fafc; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:12px; white-space:nowrap; }}
  .evi {{ font-family: Consolas, Menlo, monospace; font-size:12px; color:#475569; }}
  .php-block {{ border:1px solid #e2e8f0; border-left:4px solid #7c3aed; border-radius:8px; padding:12px 14px; margin-bottom:14px; }}
  .php-head {{ font-weight:600; font-size:14px; margin-bottom:8px; word-break:break-all; }}
  .php-sub {{ font-size:12px; color:#64748b; margin-bottom:4px; }}
  .checks {{ margin:0 0 12px 18px; padding:0; color:#475569; font-size:12px; }}
  .checks li {{ margin-bottom:2px; }}
  .note {{ background:#fff7ed; border:1px solid #fed7aa; padding:10px 12px; border-radius:8px; font-size:13px; margin-bottom:18px; }}
  footer {{ color:#94a3b8; font-size:12px; text-align:center; padding:16px 0; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>服务器漏洞扫描报告</h1>
  <div class="sub">目标 {_esc(report.target)}（{_esc(report.ip)}） · 开始 {_esc(report.started)} · 结束 {_esc(report.finished)} · 耗时 {report.duration:.1f}s</div>
  <div class="note">本报告由自动化扫描器生成，版本匹配类结论可能受发行版补丁向后移植影响，请结合实际情况复核后再处置。</div>
  <div class="cards">
    {"".join(f"<div class='card'><div class='num' style='color:{SEVERITY_COLOR[k]}'>{counts[k]}</div><div class='lbl'>{SEVERITY_CN[k]}</div></div>" for k in ("critical", "high", "medium", "low", "info"))}
  </div>

  <section>
    <h2>操作系统信息</h2>
    <table><tr><th style="width:220px">项目</th><th>值</th></tr>{os_rows or "<tr><td colspan='2'>未知</td></tr>"}</table>
  </section>

  <section>
    <h2>开放端口与服务指纹</h2>
    <table>
      <tr><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>产品</th><th>版本</th></tr>
      {port_rows}
    </table>
  </section>

  <section>
    <h2>Web 应用</h2>
    <table>
      <tr><th>URL</th><th>访问主机(Host)</th><th>状态码</th><th>标题</th><th>Server</th><th>X-Powered-By</th><th>技术栈</th></tr>
      {web_rows}
    </table>
  </section>

  <section>
    <h2>PHP2Shell 检测（{len(report.php2shell)} 个 Web 入口 / {php_risk} 项高危及以上）</h2>
    <div class="note">对每个 Web 入口（含未识别为 PHP 的站点）都执行以下检测；加 <code>--php2shell-verify</code> 可做无害执行验证。</div>
    {php_html}
  </section>

  <section>
    <h2>技术栈组件与漏洞匹配（{len(report.stacks)} 个组件 / {stack_hits} 个命中）</h2>
    <div class="note">覆盖 Java/JVM、Go、C/C++ 运行库、Python、Nginx、OpenResty：远端指纹、本地运行时与依赖版本、
    只读暴露面探测、Nginx/OpenResty 配置核查，统一与离线 CVE 规则库做版本匹配。版本匹配结论可能受发行版补丁向后移植影响。</div>
    <table>
      <tr><th style="width:90px">技术栈</th><th style="width:150px">组件</th><th style="width:110px">版本</th>
          <th style="width:180px">位置</th><th style="width:200px">识别来源</th><th>命中规则</th>
          <th style="width:70px">最高等级</th><th style="width:170px">检测结论</th></tr>
      {stack_rows}
    </table>
    <div class='php-sub'>已执行检测项：</div><ul class='checks'>{stack_checks_html}</ul>
  </section>

  <section>
    <h2>漏洞与风险明细（{len(findings)} 项）</h2>
    <table>
      <tr><th style="width:70px">等级</th><th>问题</th><th style="width:120px">CVE/编号</th><th style="width:70px">类别</th><th style="width:180px">位置</th><th>说明</th><th style="width:180px">证据</th><th>修复建议</th><th style="width:50px">参考</th></tr>
      {find_rows_html}
    </table>
  </section>

  <footer>Generated by server-vuln-scanner v1.2 · 仅可用于授权资产的合规安全评估</footer>
</div>
</body>
</html>"""


def write_reports(report: ScanReport, out_dir: str) -> Dict[str, str]:
    import os

    os.makedirs(out_dir, exist_ok=True)
    safe = (report.ip or report.target).replace(":", "_").replace("/", "_")
    # 带毫秒，保证连续扫描同一目标时每次都有独立的报告文件与历史记录
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    json_path = os.path.join(out_dir, f"report_{safe}_{stamp}.json")
    html_path = os.path.join(out_dir, f"report_{safe}_{stamp}.html")
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(report))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(to_html(report))
    return {"json": json_path, "html": html_path}
