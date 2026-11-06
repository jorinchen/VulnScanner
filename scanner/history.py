# -*- coding: utf-8 -*-
"""扫描历史记录。

每次扫描自动把摘要追加到 <报告目录>/history.json，并重新生成 <报告目录>/index.html：
一个可直接双击打开的「历史记录索引页」，列出每次扫描的目标、时间、风险统计与报告链接。

  history.json  结构化记录（供程序读取 / 二次分析）
  index.html    可视化索引（供人直接查看，点击即可打开当次 HTML / JSON 报告）
  report_*.html 每次扫描的完整报告

所有文件都放在 exe / 脚本同目录下的 reports 目录，随 exe 一起分发也不会丢记录。
"""

from __future__ import annotations

import html
import json
import os
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanReport
from .utils import LOGGER

HISTORY_FILE = "history.json"
INDEX_FILE = "index.html"
MAX_RECORDS = 1000

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}


def history_path(out_dir: str) -> str:
    return os.path.join(out_dir, HISTORY_FILE)


def index_path(out_dir: str) -> str:
    return os.path.join(out_dir, INDEX_FILE)


def _atomic_write(path: str, text: str) -> None:
    """先写临时文件再替换，避免中断时把索引/记录写坏。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def load_records(out_dir: str) -> List[Dict[str, Any]]:
    """读取历史记录，最新在前；文件损坏时返回空列表而不影响扫描。"""
    path = history_path(out_dir)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        LOGGER.warning("扫描历史文件读取失败（将忽略旧记录）：%s", exc)
        return []
    records = data.get("records", []) if isinstance(data, dict) else []
    return [r for r in records if isinstance(r, dict)]


def _summary(record: Dict[str, Any]) -> Dict[str, int]:
    value = record.get("summary") or {}
    return {k: int(value.get(k, 0) or 0) for k in ("critical", "high", "medium", "low", "info")}


def add_record(
    report: ScanReport,
    paths: Dict[str, str],
    out_dir: str,
    command: str = "",
) -> Dict[str, Any]:
    """归档一次扫描，并刷新 index.html。"""
    html_name = os.path.basename(paths.get("html", ""))
    record: Dict[str, Any] = {
        "id": os.path.splitext(html_name)[0] or datetime.now().strftime("%Y%m%d_%H%M%S"),
        "time": report.finished or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": report.target,
        "ip": report.ip,
        "hostname": report.hostname or "",
        "duration": round(float(report.duration or 0), 1),
        "summary": report.severity_counts(),
        "ports": sum(1 for p in report.ports if p.state == "open"),
        "web": len(report.web),
        "stacks": len(report.stacks),
        "total": len(report.findings),
        "html": html_name,
        "json": os.path.basename(paths.get("json", "")),
        "command": command,
    }
    records = [r for r in load_records(out_dir) if r.get("id") != record["id"]]
    records.insert(0, record)
    records = records[:MAX_RECORDS]
    _atomic_write(
        history_path(out_dir),
        json.dumps({"version": 1, "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "records": records}, ensure_ascii=False, indent=2),
    )
    write_index(out_dir)
    return record


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def write_index(out_dir: str) -> str:
    """生成可直接双击打开的历史记录索引页，返回其绝对路径。"""
    records = load_records(out_dir)
    totals = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for record in records:
        for key, value in _summary(record).items():
            totals[key] += value

    rows = []
    for idx, record in enumerate(records, 1):
        counts = _summary(record)
        html_name = str(record.get("html") or "")
        json_name = str(record.get("json") or "")
        html_exists = bool(html_name) and os.path.isfile(os.path.join(out_dir, html_name))
        json_exists = bool(json_name) and os.path.isfile(os.path.join(out_dir, json_name))
        links = []
        if html_exists:
            links.append(f"<a href='./{_esc(html_name)}' target='_blank'>HTML 报告</a>")
        else:
            links.append("<span class='missing'>HTML 已删除</span>")
        if json_exists:
            links.append(f"<a class='sub' href='./{_esc(json_name)}' target='_blank'>JSON</a>")
        cells = "".join(
            f"<td class='num'>{counts[k] if counts[k] else '-'}</td>" for k in
            ("critical", "high", "medium", "low", "info")
        )
        rows.append(
            "<tr>"
            f"<td class='idx'>{idx}</td>"
            f"<td class='time'>{_esc(record.get('time'))}</td>"
            f"<td><b>{_esc(record.get('target') or '-')}</b></td>"
            f"<td>{_esc(record.get('ip') or '-')}</td>"
            f"<td class='num'>{_esc(record.get('duration', 0))}s</td>"
            f"{cells}"
            f"<td class='num'>{_esc(record.get('total', 0))}</td>"
            f"<td class='num'>{_esc(record.get('ports', 0))} / {_esc(record.get('web', 0))} / "
            f"{_esc(record.get('stacks', 0))}</td>"
            f"<td>{' · '.join(links)}</td>"
            "</tr>"
        )

    rows_html = "".join(rows) or (
        "<tr><td colspan='13' class='empty'>暂无扫描记录。运行扫描后本页会自动生成记录。</td></tr>"
    )
    latest = records[0].get("time") if records else "-"
    cards = "".join(
        f"<div class='card'><div class='num' style='color:{SEVERITY_COLORS[k]}'>{totals[k]}</div>"
        f"<div class='lbl'>累计{label}</div></div>"
        for k, label in (("critical", "严重"), ("high", "高危"), ("medium", "中危"),
                         ("low", "低危"), ("info", "信息"))
    )

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>扫描历史记录 - 服务器漏洞扫描器</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; margin:0; background:#f1f5f9; color:#0f172a; }}
  .wrap {{ max-width:1400px; margin:0 auto; padding:24px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:#64748b; font-size:13px; margin-bottom:18px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:18px; }}
  .card {{ flex:1; min-width:110px; background:#fff; border-radius:10px; padding:14px 16px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ font-size:12px; color:#64748b; }}
  section {{ background:#fff; border-radius:10px; padding:16px 18px; margin-bottom:18px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  h2 {{ font-size:16px; margin:0 0 12px; border-left:4px solid #2563eb; padding-left:8px; }}
  .bar {{ display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:12px; font-size:13px; }}
  input[type=text] {{ padding:7px 10px; border:1px solid #cbd5e1; border-radius:6px; min-width:260px; font-size:13px; }}
  .scroll {{ overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; white-space:nowrap; }}
  th, td {{ border-bottom:1px solid #e2e8f0; padding:7px 8px; text-align:left; }}
  th {{ background:#f8fafc; font-weight:600; position:sticky; top:0; }}
  tr:hover td {{ background:#f8fafc; }}
  td.num, td.idx, td.time {{ font-variant-numeric:tabular-nums; color:#475569; }}
  td b {{ color:#0f172a; }}
  a {{ color:#2563eb; text-decoration:none; }} a:hover {{ text-decoration:underline; }}
  a.sub {{ color:#64748b; font-size:12px; }}
  .missing, .empty {{ color:#94a3b8; }}
  .note {{ background:#eff6ff; border:1px solid #bfdbfe; padding:10px 12px; border-radius:8px; font-size:13px; margin-bottom:18px; }}
  footer {{ color:#94a3b8; font-size:12px; text-align:center; padding:16px 0; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>扫描历史记录</h1>
  <div class="sub">共 {len(records)} 次扫描 · 最近一次 {_esc(latest)} · 记录文件 history.json · 本页每次扫描后自动刷新</div>
  <div class="cards">
    <div class="card"><div class="num" style="color:#2563eb">{len(records)}</div><div class="lbl">扫描次数</div></div>
    {cards}
  </div>
  <div class="note">点击「HTML 报告」查看当次完整报告，或点「JSON」查看结构化数据。输入框可按目标/IP/CVE 摘要快速筛选。</div>
  <section>
    <h2>全部记录（最新在前）</h2>
    <div class="bar">
      <label>筛选：<input type="text" id="q" placeholder="输入目标、IP 或时间关键字" oninput="filterRows()"></label>
      <span id="visible"></span>
    </div>
    <div class="scroll">
      <table>
        <tr>
          <th>#</th><th>扫描时间</th><th>目标</th><th>IP</th><th>耗时</th>
          <th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>信息</th><th>合计</th>
          <th>端口/Web/组件</th><th>报告</th>
        </tr>
        <tbody id="rows">{rows_html}</tbody>
      </table>
    </div>
  </section>
  <footer>server-vuln-scanner · 仅可用于授权资产的合规安全评估</footer>
</div>
<script>
function filterRows() {{
  const q = (document.getElementById('q').value || '').toLowerCase();
  const rows = Array.from(document.querySelectorAll('#rows tr'));
  let shown = 0;
  rows.forEach(function (tr) {{
    if (tr.classList.contains('empty')) return;
    const hit = tr.textContent.toLowerCase().indexOf(q) !== -1;
    tr.style.display = hit ? '' : 'none';
    if (hit) shown++;
  }});
  document.getElementById('visible').textContent = '显示 ' + shown + ' / {len(records)} 条';
}}
filterRows();
</script>
</body>
</html>"""
    path = index_path(out_dir)
    _atomic_write(path, page)
    return os.path.abspath(path)


def print_records(out_dir: str, limit: int = 20) -> None:
    """在控制台打印历史记录摘要。"""
    records = load_records(out_dir)
    print()
    print("=" * 100)
    print(f"扫描历史记录：共 {len(records)} 次（显示最近 {min(limit, len(records))} 次）")
    print(f"索引页：{index_path(os.path.abspath(out_dir))}")
    print("-" * 100)
    if not records:
        print("暂无扫描记录。运行一次扫描后会自动生成。")
    else:
        print(f"{'时间':<20} {'目标':<26} {'严重':>4} {'高危':>4} {'中危':>4} {'低危':>4} "
              f"{'合计':>5} {'耗时':>7}  报告")
        for record in records[:max(1, limit)]:
            c = _summary(record)
            print(f"{str(record.get('time', '')):<20} {str(record.get('target', ''))[:25]:<26} "
                  f"{c['critical']:>4} {c['high']:>4} {c['medium']:>4} {c['low']:>4} "
                  f"{str(record.get('total', 0)):>5} {str(record.get('duration', 0)) + 's':>7}  "
                  f"{record.get('html', '')}")
    print("=" * 100)


def latest_report(out_dir: str) -> Optional[str]:
    """返回最近一次扫描的 HTML 报告绝对路径。"""
    records = load_records(out_dir)
    if not records:
        return None
    name = str(records[0].get("html") or "")
    path = os.path.join(out_dir, name)
    return os.path.abspath(path) if name and os.path.isfile(path) else None


def open_in_browser(path: str) -> bool:
    """用系统默认浏览器打开本地文件（正确处理中文/空格路径）。"""
    try:
        return bool(webbrowser.open(Path(os.path.abspath(path)).as_uri()))
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("打开浏览器失败：%s", exc)
        return False


def open_folder(out_dir: str) -> bool:
    """在文件管理器中打开报告目录。"""
    path = os.path.abspath(out_dir)
    os.makedirs(path, exist_ok=True)
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", path])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception as exc:  # noqa: BLE001
        LOGGER.debug("打开目录失败：%s", exc)
        return False
