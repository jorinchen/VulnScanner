# -*- coding: utf-8 -*-
"""把扫描器生成的单文件 HTML 报告转成 tkinter ``Text`` 可显示的片段。

纯标准库实现（``html.parser``），不依赖浏览器或第三方渲染引擎：

    parse_html(html)          -> 结构化 Block（标题 / 段落 / 表格 / 列表 / 统计卡）
    format_blocks(blocks)     -> [(文本, tag 名), ...]，GUI 按 tag 插入 Text 即可

tkinter 没有 HTML 控件，因此：
* 窄表格按等宽列对齐展示
* 宽表格（如 9 列的漏洞明细）自动改成「字段名: 值」卡片，避免横向拉出几千米
* 风险等级徽章的颜色转成文字颜色 tag，完整保留报告里的每一段内容
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Optional, Sequence, Tuple

_SKIP_CONTAINERS = {"style", "script", "head", "title", "noscript"}
_VOID = {"meta", "link", "input", "img", "br", "hr", "area", "base", "col",
         "embed", "source", "wbr"}
_PARA_STYLES = {"note", "sub", "php-head", "php-sub", "footer", "php-block"}
_HEADINGS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4}

_COLOR_RE = re.compile(r"(?:background|color)\s*:\s*(#[0-9a-fA-F]{3,8})")
_HTTP_RE = re.compile(r"^https?://", re.I)


@dataclass
class Block:
    kind: str                              # heading / para / table / list / stat / sep
    text: str = ""
    style: str = ""
    level: int = 0
    headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    row_colors: List[str] = field(default_factory=list)
    items: List[str] = field(default_factory=list)


def _attr(attrs: Sequence[Tuple[str, Optional[str]]], name: str) -> str:
    for key, value in attrs:
        if key and key.lower() == name:
            return (value or "").strip()
    return ""


def _color(style: str) -> str:
    match = _COLOR_RE.search(style or "")
    return match.group(1) if match else ""


def _clean(parts: List[str]) -> str:
    return " ".join("".join(parts).split())


def _take(parts: List[str]) -> str:
    text = _clean(parts)
    parts.clear()
    return text


def display_width(text: str) -> int:
    """中文/全角按 2 列宽计算，用于等宽列对齐。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
               for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(1, width - display_width(text))


class _ReportParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks: List[Block] = []
        self._buf: List[str] = []
        self._skip_depth = 0
        self._div_stack: List[str] = []
        self._card: dict = {}
        self._heading: Optional[int] = None
        self._table: Optional[Block] = None
        self._row: Optional[List[str]] = None
        self._row_header = False
        self._row_color = ""
        self._cell: Optional[List[str]] = None
        self._cell_color = ""
        self._list_items: Optional[List[str]] = None
        self._li: Optional[List[str]] = None
        self._href = ""

    # -- 文本分流 -------------------------------------------------------- #
    def _put(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)
        elif self._li is not None:
            self._li.append(data)
        else:
            self._buf.append(data)

    def _flush(self, style: str = "") -> None:
        text = _take(self._buf)
        if text:
            self.blocks.append(Block(kind="para", text=text, style=style))

    # -- HTMLParser 回调 ------------------------------------------------- #
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag in _SKIP_CONTAINERS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in _VOID:
            if tag == "br":
                self._put("\n")
            elif tag == "hr":
                self.blocks.append(Block(kind="sep"))
            return

        if tag in _HEADINGS:
            self._flush()
            self._heading = _HEADINGS[tag]
        elif tag == "table":
            self._flush()
            self._table = Block(kind="table")
            self._row = None
        elif tag == "tr":
            self._row = []
            self._row_header = False
            self._row_color = ""
        elif tag in ("td", "th"):
            self._cell = []
            self._cell_color = ""
            if tag == "th":
                self._row_header = True
        elif tag == "span":
            if "badge" in _attr(attrs, "class"):
                self._cell_color = _color(_attr(attrs, "style"))
        elif tag == "a":
            self._href = _attr(attrs, "href")
        elif tag in ("ul", "ol"):
            self._flush()
            self._list_items = []
        elif tag == "li":
            self._li = []
        elif tag == "div":
            self._flush()
            cls = _attr(attrs, "class")
            self._div_stack.append(cls)
            if cls == "card":
                self._card = {"color": ""}
            elif cls == "num":
                self._card["color"] = _color(_attr(attrs, "style"))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _SKIP_CONTAINERS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth or tag in _VOID:
            return

        if tag in _HEADINGS:
            text = _take(self._buf)
            if text:
                self.blocks.append(Block(kind="heading", level=self._heading or 2, text=text))
            self._heading = None
        elif tag in ("td", "th"):
            if self._cell is not None and self._row is not None:
                self._row.append(_take(self._cell))
                if self._cell_color:
                    self._row_color = self._cell_color
            self._cell = None
        elif tag == "tr":
            if self._table is not None and self._row:
                if self._row_header and not self._table.headers:
                    self._table.headers = self._row
                else:
                    self._table.rows.append(self._row)
                    self._table.row_colors.append(self._row_color)
            self._row = None
        elif tag == "table":
            if self._table is not None:
                self.blocks.append(self._table)
            self._table = None
        elif tag == "a":
            if _HTTP_RE.match(self._href):
                self._put(f" ({self._href})")
            self._href = ""
        elif tag == "li":
            if self._li is not None and self._list_items is not None:
                self._list_items.append(_take(self._li))
            self._li = None
        elif tag in ("ul", "ol"):
            if self._list_items:
                self.blocks.append(Block(kind="list", items=list(self._list_items)))
            self._list_items = None
        elif tag == "div":
            cls = self._div_stack.pop() if self._div_stack else ""
            text = _take(self._buf)
            if cls == "num":
                self._card["num"] = text
            elif cls == "lbl":
                self._card["lbl"] = text
            elif cls == "card":
                label = self._card.get("lbl", "")
                num = self._card.get("num", "")
                self.blocks.append(Block(kind="stat", text=f"{label} {num}".strip(),
                                         style=self._card.get("color", "")))
            elif text:
                style = cls if cls in _PARA_STYLES else ""
                self.blocks.append(Block(kind="para", text=text, style=style))
        elif tag == "p":
            self._flush()
        elif tag == "footer":
            self._flush("footer")
        elif tag in ("section", "body", "html"):
            self._flush()

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._put(data)


def parse_html(html: str) -> List[Block]:
    """把报告 HTML / 历史索引 HTML 解析成结构化块。"""
    parser = _ReportParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - 单个标签异常不应导致报告打不开
        pass
    parser._flush()  # noqa: SLF001
    return parser.blocks


Fragment = Tuple[str, Optional[str]]


def _compact_table(block: Block, out: List[Fragment], rule: int) -> None:
    cols = max(len(block.headers), max((len(r) for r in block.rows), default=0))
    widths = []
    for i in range(cols):
        width = display_width(block.headers[i]) if i < len(block.headers) else 0
        for row in block.rows:
            if i < len(row):
                width = max(width, display_width(row[i]))
        widths.append(min(width + 2, 44))

    def emit(cells: Sequence[str], tag: Optional[str]) -> None:
        line = "".join(_pad(cells[i] if i < len(cells) else "", widths[i])
                       for i in range(cols)).rstrip()
        out.append(("  " + line + "\n", tag))

    emit(block.headers, "th")
    out.append(("  " + "─" * min(sum(widths), rule) + "\n", "sep"))
    for idx, row in enumerate(block.rows):
        color = block.row_colors[idx] if idx < len(block.row_colors) else ""
        emit(row, f"c_{color}" if color else None)
    out.append(("\n", None))


def _card_table(block: Block, out: List[Fragment], rule: int) -> None:
    for idx, row in enumerate(block.rows):
        color = block.row_colors[idx] if idx < len(block.row_colors) else ""
        if len(row) >= 2:
            title = f"[{row[0]}] {row[1]}" if row[0] else row[1]
        else:
            title = row[0] if row else ""
        out.append(("\n" + "─" * rule + "\n", "sep"))
        out.append((title + "\n", f"c_{color}" if color else "strong"))
        for i, cell in enumerate(row):
            if i < 2 or not cell or cell == "-":
                continue
            name = block.headers[i] if i < len(block.headers) and block.headers[i] else f"字段 {i + 1}"
            out.append((f"  {name}：", "label"))
            tag = "mono" if name in ("证据", "命中规则", "URL") else "value"
            out.append((cell + "\n", tag))
    out.append(("\n", None))


def format_blocks(blocks: List[Block], rule: int = 66) -> List[Fragment]:
    """转换成 ``[(文本, tag名)]``；tag 名由 GUI 侧配置颜色/字体。"""
    out: List[Fragment] = []
    i = 0
    while i < len(blocks):
        block = blocks[i]
        kind = block.kind

        if kind == "stat":
            out.append(("  风险统计：  ", "label"))
            while i < len(blocks) and blocks[i].kind == "stat":
                stat = blocks[i]
                out.append((f"{stat.text}    ", f"c_{stat.style}" if stat.style else "strong"))
                i += 1
            out.append(("\n\n", None))
            continue

        if kind == "heading":
            if block.level <= 1:
                out.append((block.text + "\n", "h1"))
                out.append(("═" * rule + "\n\n", "sep"))
            else:
                out.append(("\n", None))
                out.append(("  " + block.text + "\n", "h2"))
                out.append(("─" * rule + "\n", "sep"))
        elif kind == "para":
            if block.style == "note":
                out.append(("  [提示] " + block.text + "\n\n", "note"))
            elif block.style in ("sub", "footer"):
                out.append(("  " + block.text + "\n\n", "dim"))
            elif block.style == "php-head":
                out.append(("  " + block.text + "\n", "strong"))
            elif block.style == "php-sub":
                out.append(("  " + block.text + "\n", "dim"))
            else:
                out.append((block.text + "\n\n", None))
        elif kind == "list":
            for item in block.items:
                out.append(("    • " + item + "\n", "dim"))
            out.append(("\n", None))
        elif kind == "table":
            if not block.rows:
                pass
            elif not block.headers:
                for row in block.rows:
                    out.append(("  " + "  ".join(row) + "\n", None))
                out.append(("\n", None))
            else:
                cols = len(block.headers)
                longest = max((display_width(c) for row in block.rows for c in row), default=0)
                compact = cols <= 5 and longest <= 46 and len(block.rows) <= 40
                if compact:
                    _compact_table(block, out, rule)
                else:
                    _card_table(block, out, rule)
        elif kind == "sep":
            out.append(("─" * rule + "\n", "sep"))
        i += 1
    return out
