# 服务器漏洞扫描器（server-vuln-scanner）

一个纯 Python 标准库实现的服务器综合漏洞扫描器，覆盖：

| 模块 | 能力 |
| --- | --- |
| 端口扫描 | TCP connect 并发扫描，识别 open / closed / filtered；内置 **6 大类 227 个端口**（基础 / 邮件 / 数据库 / AI 大模型 / 流媒体直播 / 电商中间件，含 Node.js 调试端口 9229/5858），支持 `--categories` 选择 |
| 服务指纹 | 读 banner + 主动探针，识别 SSH/FTP/SMTP/Postfix/Exim/Dovecot/MySQL/MariaDB/PostgreSQL/Redis/Memcached/MongoDB/Elasticsearch/ClickHouse/InfluxDB/CouchDB/Neo4j、Ollama/vLLM/Ray/Jupyter/ComfyUI/Qdrant/Weaviate/Milvus、RTMP/RTSP/SIP/SRS、Nacos/Solr/Kafka/RabbitMQ/Dubbo 等及版本 |
| 试探性连接 | 只读协议探针（PING/stats/四字命令/RTSP OPTIONS/SIP OPTIONS/RTMP 握手/Dubbo telnet/HTTP GET/匿名登录探测），发现**未授权访问**类风险 |
| 操作系统漏洞 | 本地审计：发行版 EOL、内核 CVE、软件包版本 CVE（sudo/polkit/glibc/OpenSSL/OpenSSH/bash/curl…）、SSH 配置、防火墙、SELinux、待安装更新；Windows：内部版本 EOL、补丁列表、SMBv1、Spooler、防火墙、RDP |
| Web / App 漏洞 | HTTPS/TLS（证书过期、自签名、TLS1.0/1.1、弱套件）、安全响应头、Cookie 属性、CORS、危险 HTTP 方法、目录列表、30+ 敏感路径（.git/.env/actuator/备份文件/管理台）、技术栈识别、中间件版本 CVE 匹配 |
| PHP2Shell 检测 | 对每个 Web 入口的 getshell 检测：PHP2Shell（CVE-2026-109618 / CVE-2026-109619）、php-cgi 参数注入（CVE-2012-1823 / CVE-2024-4577）、PHPUnit eval-stdin.php（CVE-2017-9841）、Laravel Ignition（CVE-2021-3129）、ThinkPHP invokefunction、LFI 与 `php://filter`、phpinfo 与缓解配置核查、PHP 版本 CVE；可加 `--php2shell-verify` 做无害执行验证 |
| 技术栈漏洞扫描 | **Java / Go / C-C++ / Python / Nginx / OpenResty / Node.js / PHP / .NET** 九类全覆盖：远端指纹与响应头版本、本地运行时/依赖版本采集、只读暴露面探测、Nginx/OpenResty 配置核查，统一与 **312 条**离线 CVE/EOL 规则做版本匹配 |
| 报告 | 控制台摘要 + JSON + 单文件 HTML 报告（按严重级别统计与着色，含 **PHP2Shell 专区** 与 **技术栈组件专区**），并可在应用窗口内直接查看详情 |
| 图形界面 | **`漏洞扫描器.exe` 为 `--windowed` 窗口程序（无 cmd 黑窗口）**：填目标 → 开始扫描，日志与风险统计实时刷新；**报告详情直接在应用内查看**（格式化视图 / JSON 原文），历史记录双击即打开 |
| 扫描历史记录 | 每次扫描自动归档 `reports/history.json` 并刷新 `reports/index.html` 索引页，可查看/筛选历次扫描的时间、目标、风险统计并点开当次报告 |
| 并发模型 | **多进程**（端口分片）+ **多线程**（连接/服务/Web 端口）+ **多协程**（只读 HTTP 探针），规模自适应、失败自动降级 |

> 所有探针均为**只读、非破坏性**请求，不会写入、修改或删除目标数据；不做任何漏洞利用。

## 快速开始

**方式 A（最省事，推荐）：直接用打包好的 exe**

1. 进入仓库 `dist/` 目录
2. 双击 **`漏洞扫描器.exe`** —— 打开图形界面窗口，填目标 → 开始扫描，报告详情在窗口内查看
3. 命令行 / 脚本调用可选：**`漏洞扫描器-命令行版.exe <目标>`**

> exe 已内嵌 Tcl/Tk 与全部依赖，**无需安装 Python**、无需联网。

**方式 B：自己重新打包**

1. 确保机器上有 Python 3.8+（图形界面版还需 tkinter）和 PyInstaller（`生成exe.bat` 会自动装 PyInstaller）
2. 双击 **`生成exe.bat`**（或在项目根目录执行 `python build_exe.py`）
3. 产物生成到 `dist/`：`漏洞扫描器.exe`（图形界面）+ `漏洞扫描器-命令行版.exe`（命令行）
   - 只想生成图形界面版（更快）：`python build_exe.py --gui-only`

**方式 C：源码直接运行（需要 Python 3.8+，图形界面还需 tkinter）**

```bash
python scan.py 192.168.1.10          # 命令行全扫
python scan_gui.py                   # 打开图形界面
```

> 图形界面无 cmd 黑窗口；命令行版与 `scan.py` 参数完全一致。更多用法见下文。

## 环境要求

- 运行 **`漏洞扫描器.exe`**（图形界面主程序）：无需 Python、无需任何依赖，双击打开应用窗口
- 运行 `scan_gui.py`（图形界面源码方式）：Python 3.8+ 且包含 tkinter（仅用标准库，无需 pip install）
- 运行 `scan.py` / `漏洞扫描器-命令行版.exe`：命令行方式（同样只用标准库）
- 生成 exe 时：Python 3.8+ 与 PyInstaller（构建脚本会自动安装）
- 可选：`nmap` 已安装时会自动调用 `nmap -O` 增强远端操作系统识别

## 图形界面（推荐）：双击 exe 在应用程序窗口里扫描

> 主程序 **`漏洞扫描器.exe`** 是 PyInstaller `--onefile --windowed` 图形界面程序，
> 双击后直接打开 Windows 应用窗口，**不再出现 cmd 黑窗口**，也不需要在命令行里
> 输入目标或选择菜单；扫描、进度、结果和历次记录都在窗口里完成。

### 生成 exe（只需一次）

> 仓库 `dist/` 目录已附带构建好的 **`漏洞扫描器.exe`**，可直接双击使用；
> 只有在修改过源码、或需要用其他 Python 版本重新打包时才需要执行下面的步骤。

双击 **`生成exe.bat`**（或在命令行执行 `python build_exe.py`）。脚本会自动检查/安装
PyInstaller，并生成：

| 产物 | 打包方式 / 入口 | 用途 |
| --- | --- | --- |
| **`漏洞扫描器.exe`** | `--windowed` / `scan_gui.py` | **主程序**：双击打开图形界面窗口 |
| `漏洞扫描器-命令行版.exe` | `--console` / `scan_exe.py` | 可选：脚本、定时任务、需要命令行参数时使用 |

只想生成图形界面版（更快）：`python build_exe.py --gui-only`。
PyInstaller 中间产物名为 `VulnScanner` / `VulnScannerCLI`，最终对外产物为 `dist/漏洞扫描器.exe` 与 `dist/漏洞扫描器-命令行版.exe`。

### 窗口里怎么用

```
┌─ 扫描设置 ─────────────────────────────────────────────────────────────┐
│ 扫描目标 [ 192.168.1.10                 ]   [开始扫描] [停止]          │
│ 端口范围 [ 留空=内置 227 个端口 ]  并发数 [200]                        │
│ 技术栈 [all ▾]  端口类别 [all ▾]  ☑ 完成后自动在窗口内查看报告      │
│ 并发模型：进程[0=自动] 协程[64]  ☑ 多进程 ☑ 协程（多线程=并发数）      │
│ 高级参数 [ --stack-categories nodejs --web-timeout 3 ]                  │
├─ 状态 ──────────────────────── 本次结果：严重 高危 中危 低危 信息 合计 ─┤
│ [ 扫描日志 ] [ 报告详情（窗口内查看） ]  ← 双击历史记录自动切到这里   │
│ 报告标题 / 视图 [格式化视图|JSON 原文] / [在浏览器中打开]            │
│ 扫描历史记录（双击一行 → 上方直接显示报告详情）                       │
└────────────────────────────────────────────────────────────────────────┘
```

1. 在「扫描目标」填 IP / 域名 / URL（多个用空格或逗号分隔），回车或点 **开始扫描**
2. 扫描在后台线程执行，「扫描日志」实时刷新，上方「本次结果」实时汇总各等级数量
3. 每个目标完成后自动生成 JSON + HTML 报告，并追加一条扫描历史记录
4. **双击**下方「扫描历史记录」任意一行，上方自动切到「报告详情」标签页，**报告内容直接在应用窗口里显示**，不再跳外部浏览器
5. 底部按钮：查看选中报告详情、在窗口内查看历史索引 / 最近报告、打开报告目录、刷新
6. **停止** 是协作式取消：完成当前目标后结束，不再扫描后续目标

### 报告详情在应用程序内查看

主窗口中部的「报告详情」标签页是内置阅读器，用标准库 `html.parser` 解析 HTML 报告后
渲染到窗口里（不依赖浏览器或第三方控件），完整保留**每一条漏洞**的标题、CVE、等级、
位置、说明、证据、修复建议与参考链接：

| 视图 | 内容 |
| --- | --- |
| 格式化视图（默认） | 标题 / 风险统计 / 章节按样式分色；窄表格按列对齐，**宽表格（如 9 列漏洞明细）自动转成「字段名: 值」卡片**，避免横向拉出超宽表格 |
| JSON 原文 | 同一份报告的 `report_*.json`，可查看完整结构化数据 |
| 在浏览器中打开 | 可选：需要原始网页样式时，一键用系统浏览器打开同一 HTML 文件 |

扫描结束时若勾选「完成后自动在窗口内查看报告」，会自动切到该标签页显示当次报告；
历史索引页（`index.html`）也可以在窗口内打开。「在浏览器中打开」只是备选，
**查看报告详情不需要离开应用程序**。

可选设置：端口范围、并发数、技术栈类别（`all` / `java` / `nodejs` / `php` / `dotnet` / 逗号组合）、
端口类别、跳过 Web、浅速扫描、附加本机系统审计、完成后自动在窗口内查看报告；
「高级参数」与命令行参数完全一致（如 `--jar-dirs "C:\opt;C:\apps"`）。

> 图形界面版没有控制台：`print` / `logging` 全部重定向到窗口日志区，
> `java -version`、`node --version`、`nmap` 等本地采集命令带 `CREATE_NO_WINDOW`，
> 所以扫描过程中也不会闪出 cmd 黑窗口。

源码方式同样可以打开图形界面：执行 `python scan_gui.py`（或 `pythonw scan_gui.py`
不弹控制台窗口）。支持 `--target 1.2.3.4` 预填目标、`--scan` 启动后自动开始扫描。

### 命令行版（可选）

`漏洞扫描器-命令行版.exe` 与 `scan.py` 参数完全一致（无参数启动时仍是文字菜单）：

```
漏洞扫描器-命令行版.exe 192.168.1.10
漏洞扫描器-命令行版.exe --history              # 打印历史并打开索引页
漏洞扫描器-命令行版.exe --open-latest          # 打开最近一次报告
漏洞扫描器-命令行版.exe example.com --open-history
```

### 每次扫描的记录保存在哪里

`reports/` 位于 **exe 同目录**（源码运行时为项目根目录），双击 exe 或从任意目录启动都不会写丢：

| 文件 | 说明 |
| --- | --- |
| `index.html` | **历史记录索引页**，双击即可查看；列出时间、目标、IP、耗时、各等级数量、端口/Web/组件数及报告链接，可按关键字筛选；点「历史索引（窗口内）」也能在应用内直接渲染 |
| `history.json` | 结构化历史记录（最多保留 1000 条），每次扫描自动追加并刷新索引 |
| `report_<目标>_<时间>.html` | 每次扫描的完整报告（文件名带毫秒，连续扫描同一目标也不会互相覆盖） |
| `report_<目标>_<时间>.json` | 每次扫描的结构化数据 |

图形界面里的每次扫描都会自动写入上述记录；命令行版相关参数：

```
--history            查看全部历史记录后退出
--open-latest        打开最近一次报告后退出
--open-history       扫描结束后自动打开历史索引页
--records-limit N    --history 打印条数（默认 20）
--no-history         本次不写入历史记录
--no-open            不自动打开报告/索引页
-o, --out DIR        报告与历史记录目录（默认：程序同目录 reports/）
```

## 并发模型与全量检测策略

### 不管版本有没有命中，都全量扫描

* 所有组件（有版本 / 无版本 / 命中规则 / 未命中规则）**都完成版本比对**，报告「技术栈组件与漏洞匹配」专区新增「检测结论」列：`命中 N 条版本规则` / `已比对 349 条规则，未命中` / `版本未知，已做指纹/暴露面检测`。
* 只读暴露面探测（34 个技术栈探针，含 PHP 10 个 / .NET 6 个）与 Nginx / OpenResty 本地配置核查 **不再因技术栈类别或版本是否命中而跳过**，一律执行；`--stack-categories` 只影响「组件清单 / 版本规则匹配」的范围，不裁剪探测项。
* 每次扫描输出一条汇总结论：共 N 个组件（命中 / 已比对未命中 / 版本未知各多少），明确「未命中仅表示当前离线规则库无匹配项，不代表未扫描或绝对安全」。

### 多进程 × 多线程 × 多协程

| 模型 | 承担的工作 | 实现 |
| --- | --- | --- |
| 多进程 | 端口表切片并行扫描 | `ProcessPoolExecutor`，端口数 ≥ 64 时启用；冻结 exe 默认 2 个，最大 8 个 |
| 多线程 | 每个进程内的 TCP connect、服务指纹、多端口 Web 扫描、本地命令采集 | `ThreadPoolExecutor`，默认 200（`-t`） |
| 多协程 | 技术栈暴露面 + Web 敏感路径的批量只读 GET | `asyncio` + `open_connection` + `Semaphore`，默认并发 64 |

* 规模自适应：端口少于 64 个不启动多进程，避免进程开销；进程池在冻结环境不可用时 **自动降级** 为单进程 + 多线程，扫描不会失败。
* 入口脚本均调用 `multiprocessing.freeze_support()`，PyInstaller `--onefile --windowed` 下多进程 spawn 不会额外弹出窗口；本地采集子进程带 `CREATE_NO_WINDOW`，不闪 cmd 黑框。
* 图形界面「扫描设置」里可直接填进程数、协程并发，或用复选框关闭多进程 / 协程；扫描日志会打印本次实际使用的并发模型。

```
--processes N          多进程数（0=自动，最大 8）
--async-limit N        协程并发上限（默认 64）
--no-multiprocessing   禁用多进程，仅多线程 + 协程
--no-async             禁用协程，HTTP 探测回退同步逐条
-t, --threads N        端口扫描线程数（默认 200）
```

## 使用方法

### 方式一：图形界面（窗口程序）

> 推荐直接双击 **`漏洞扫描器.exe`**（无需 Python）；用法见上一节「图形界面」。

源码方式：执行 `python scan_gui.py`（或 `pythonw scan_gui.py` 不弹控制台窗口），
打开的是同一个应用窗口，不会弹出 cmd 黑窗口。需要 Python 3.8+ 且包含 tkinter。

### 方式二：命令行

```bash
# 只给 IP 就自动全扫（端口 -> 服务 -> 试探性连接 -> Web -> 技术栈 -> 系统审计 -> 报告）
python scan.py 192.168.1.10

# 直接给域名或 URL 也一样
python scan.py example.com
python scan.py https://example.com/admin

# 不带参数运行，会提示你输入目标
python scan.py

# 可选：自定义端口 / 扩大端口范围 / 多目标
python scan.py 10.0.0.5 -p 22,80,443
python scan.py example.com --top-ports 500
python scan.py 10.0.0.5 10.0.0.6
```

扫描本机（`127.0.0.1` 或本机 IP）时会自动附加本地操作系统补丁/配置审计；
其他目标自动做远端操作系统识别。

输入**域名**时，Web 扫描会跑两遍：

1. `http(s)://<域名>` —— 连接解析出的 IP，但 Host 头与 TLS SNI 使用域名（拿到正确的虚拟主机）
2. `http(s)://<IP>`   —— 直接用 IP 访问（默认站点 / 默认证书）

两者结果不一致时会产生一条「以域名与以 IP 访问返回不同结果」的提示。
目标里写了端口（如 `example.com:8443`）时，该端口会自动加入扫描列表。

常用参数：

```
-p, --ports          端口列表，如 80,443,8000-8100
--top-ports N        扫描常见端口前 N 个
--categories list    端口类别：base / mail / database / ai / media / ecommerce，默认 all
--list-ports         打印内置端口分类表后退出
-t, --threads        端口扫描线程数（默认 200）
--processes N        多进程数（0=自动，最大 8）
--async-limit N      协程并发上限（默认 64）
--no-multiprocessing 禁用多进程，仅多线程 + 协程
--no-async           禁用协程，HTTP 探测回退同步逐条
--timeout            端口连接超时（默认 1.0s）
--service-timeout    服务探测超时（默认 2.5s）
--web-timeout        Web 请求超时（默认 6.0s）
--skip-port-scan     跳过端口扫描（配合 -p 直接探测）
--skip-web           跳过 Web 扫描
--shallow            Web 不做敏感路径深度探测
--php2shell-verify   PHP2Shell 无害验证：echo md5(随机串) 确认是否可执行 PHP 代码
--aggressive         等价于 --php2shell-verify
--local-audit        强制对本机操作系统做补丁/配置审计
--no-os-guess        不做远端操作系统识别
--stack-categories   技术栈类别：java / go / cpp / python / nginx / openresty / nodejs / php / dotnet，默认 all
--no-stack-scan      跳过技术栈漏洞扫描
--stack-local        强制采集本机运行时与依赖版本（扫描本机目标时默认已开启）
--jar-dirs PATHS     额外扫描的依赖目录，多个用分号分隔（如 C:\opt;C:\apps）
--list-rules         打印内置漏洞规则库（按技术栈分组）后退出
-o, --out            报告与历史记录目录（默认：程序同目录 reports/）
--history            查看全部历史扫描记录后退出
--open-latest        打开最近一次扫描报告后退出
--open-history       扫描结束后自动打开历史记录索引页
--records-limit N    --history 打印的记录条数（默认 20）
--no-history         本次扫描不写入历史记录
--no-html            仅输出 JSON
--no-open            不自动打开报告 / 历史索引页
--no-ask             扫描结束后不询问"是否继续"（脚本 / 定时任务用）
--stdout-json        JSON 报告同时打印到标准输出
-v, --verbose        调试日志
-y, --yes            兼容选项（现在默认即自动开始扫描）
```

`-o` 默认指向程序同目录下的 `reports/`（exe 模式下即 exe 旁边），
可用 `-o D:\scan-reports` 改到别处；历史索引页会生成在对应目录。

## 输出

- `reports/report_<目标>_<时间>.json`：结构化结果（端口、服务、Web、**php2shell**、**stacks / stack_checks**、漏洞明细）
- `reports/report_<目标>_<时间>.html`：可直接用浏览器打开的可视化报告
- `reports/history.json`：历次扫描的结构化记录（自动追加）
- `reports/index.html`：**历史记录索引页**，双击查看所有扫描并点开任意一次报告
- 应用窗口「报告详情」标签页：**直接在应用程序内查看**当次或历史报告（格式化视图 / JSON 原文），无需打开浏览器

HTML 报告包含「PHP2Shell 检测」专区：列出识别到的 PHP 站点、PHP 版本、本次执行的检测项清单
以及每个 getshell 入口的等级/CVE/说明；未检测到 PHP 站点时会明确标注。

HTML 报告还包含「技术栈组件与漏洞匹配」专区：列出每个组件的技术栈、产品、版本、识别位置与来源、
命中的 CVE 编号、最高严重级别、**检测结论**（命中 / 已比对未命中 / 版本未知），
以及本次实际执行的检测项清单（`stack_checks`，含只读探针数量与协程并发数）。
未命中规则的组件同样会列出，不会被当作「没扫到」。

漏洞等级：`critical > high > medium > low > info`。

## PHP2Shell 检测

对**每个 Web 入口都执行**，不再依赖 PHP 识别结果——因为不少 PHP 站点会关闭 `expose_php`、
改写扩展名或挂在反向代理后面，从响应里看不出是 PHP，但入口依然可被利用。
（`X-Powered-By: PHP/x.y`、PHPSESSID、`.php` 链接等识别结果仍会记录在报告里）

**只读探测（默认）**

| 检测项 | 等级 | 说明 |
| --- | --- | --- |
| php-cgi 参数注入 `?-s` 源码泄露 | 严重 | 说明查询串被当作 CGI 参数解析，同一入口可用 `-d auto_prepend_file=php://input` 执行代码 |
| PHPUnit `eval-stdin.php` 可访问 | 严重 | CVE-2017-9841，POST PHP 代码即可执行 |
| Laravel Ignition `/_ignition/health-check` | 高危 | CVE-2021-3129 |
| LFI（15 个常见参数 × 3 种穿越载荷） | 高危 | 可读 `/etc/passwd`，进一步包含日志/session getshell |
| `php://filter` 包装器可用 | 高危 | 可 base64 读源码，配合 filter chain 可转 RCE |
| phpinfo 页面暴露 | 中危 | 泄露绝对路径、扩展、`disable_functions` 等关键信息 |
| **PHP2Shell（CVE-2026-109618 / CVE-2026-109619）** | **严重** | 见下方专节 |
| PHP 版本 CVE 匹配 | 严重/高危 | CVE-2019-11043、CVE-2024-4577、CVE-2012-1823、CVE-2018-19518、EOL-PHP |

### PHP2Shell（CVE-2026-109618 / CVE-2026-109619）

PHP 官方 2026-10-21 公告的两个 critical 漏洞，代号 **php2shell**（CVSS v4.0 9.2，Use After Free / CWE-416，
未认证 RCE）。全部 Web SAPI（PHP-FPM、Apache mod_php、php-cgi、FrankenPHP、LiteSpeed）均受影响，
其中 mod_php 风险最高——演示利用可在应用代码执行之前触发。

| 分支 | 受影响区间 | 修复版本 |
| --- | --- | --- |
| 8.5.x | < 8.5.12 | 8.5.12 |
| 8.4.x | < 8.4.27 | 8.4.27 |
| 8.3.x | < 8.3.36 | 8.3.36 |
| 8.2.x | < 8.2.35 | 8.2.35 |
| 8.1 及更早（含 8.0 / 7.x / 5.x） | 全部受影响，官方不再维护 | 依赖发行版 / LTS 厂商补丁（官方仅为 7.4 / 8.0 / 8.1 提供最小源码补丁），或升级到受支持版本 |

> 规则区间写作 `<8.2`，因此 PHP 5.4、5.6、7.0–7.4、8.0、8.1 都会被判定为受影响；
> 这些分支同时会命中 `EOL-PHP`（已停止官方维护）。

检测方式（全部为只读）：

1. **版本核查**：从 `X-Powered-By: PHP/x.y` 或 phpinfo 中取版本，落在上表区间即报严重，并给出对应修复版本
2. **缓解配置核查**（phpinfo 暴露时）：
   - `session.upload_progress.enabled` 未关闭 → 高危（CVE-2026-109619 已确认利用路径未封堵）
   - `memory_limit` 仍为有限值 → 中危（CVE-2026-109618 官方建议设为 `-1`）
   - `post_max_size` > 32M 或未限制 → 低危（放大 CVE-2026-109618 攻击面）
   - PHP 8.5 上 `fatal_error_backtraces` 未关闭 → 中危（CVE-2026-109619）
3. **SAPI 提示**：识别为 Apache + PHP 时提示可能是 mod_php 部署（官方评估的最高风险场景）
4. **版本未知**：响应不暴露 PHP 版本且无 phpinfo 时，输出信息级提示，要求在服务器上用 `php -v` 核对

> 本工具**不发送**触发 OOM / UAF 的利用载荷（那是攻击行为且有可用性风险），
> 只做版本与配置层面的判定。

**无害执行验证（`--php2shell-verify`）**

仅执行 `echo md5('<随机串>')` 并比对回显，用来证明"可以执行 PHP 代码"：

- php-cgi 参数注入 + `php://input`
- `eval-stdin.php` POST
- ThinkPHP `invokefunction`（仅调用 `md5`，不做命令执行）

> 不会执行系统命令、不会写入任何文件、不会留下 webshell；如未命中会输出一条
> 「未成功」的信息级结果。请仅在自有或已书面授权的站点上启用。

## 技术栈漏洞扫描（Java / Go / C++ / Python / Nginx / OpenResty / Node.js / PHP / .NET）

默认随每次扫描自动执行；`--no-stack-scan` 可关闭，`--stack-categories` 可只选部分技术栈，
`python scan.py --list-rules` 可打印全部规则。当前规则库共 **349 条**，其中技术栈规则 **312 条**
（Java 50 / Go 31 / C-C++ 55 / Python 49 / Nginx 17 / OpenResty 6 / Node.js 66 / PHP 24 / .NET 14）。

| 技术栈 | 覆盖的代表组件 / 漏洞 |
| --- | --- |
| `java` | OpenJDK、Log4j2（Log4Shell 系列）、Spring / Spring Boot / Spring Cloud（Spring4Shell、Gateway RCE）、Struts2、Tomcat / Jetty、Jenkins、XStream、SnakeYAML、Fastjson、Jackson、Shiro、WebLogic、JBoss、Solr、Confluence、ActiveMQ |
| `go` | Go 标准库（net/http、html/template、net/netip、filepath）、`golang.org/x/net` / `x/crypto` / `x/text`、yaml.v3、runc、containerd、etcd、Kubernetes、Grafana（含 HTTP/2 Rapid Reset、Terrapin 等） |
| `cpp` | glibc、OpenSSL、zlib、libxml2、expat、libpng、curl/libcurl、libssh / libssh2、OpenSSH、SQLite、PCRE2、ImageMagick、libwebp、libjpeg-turbo、GnuTLS、Apache httpd、GCC/Clang/libstdc++ 工具链 |
| `python` | CPython、Django、Flask、Werkzeug、Jinja2、requests、urllib3、PyYAML、setuptools、Pillow、aiohttp、NumPy、cryptography、Paramiko、Starlette |
| `nginx` | CVE-2013-4547、CVE-2017-7529、resolver 系列、HTTP/2 DoS 系列、CVE-2021-23017、CVE-2022-41741/41742、CVE-2023-44487、CVE-2024-7347、旧 stable 分支提示 |
| `openresty` | 捆绑 Nginx 版本推算（自动套用**全部** Nginx 规则）、CVE-2018-9230 参数解析绕过、CVE-2020-11724 lua-nginx-module 请求走私、EOL 提示 |
| `nodejs` | Node.js 运行时（HTTP/2 Rapid Reset、请求走私、setuid 提权、证书校验绕过、EOL 分支）、npm、Express / body-parser / path-to-regexp / cookie / send / ws / Socket.IO、Next.js（CVE-2025-29927 中间件鉴权绕过、SSRF、缓存投毒）、lodash、axios、qs、minimist、jsonwebtoken、EJS、Handlebars、vm2、protobufjs、node-tar、semver、moment、braces、follow-redirects 等 60+ 组件 |
| `php` | PHP 运行时（CVE-2024-4577/8929 CGI 参数注入、phar 溢出、password_verify 绕过、EOL 分支）、Composer、Laravel / Ignition、ThinkPHP、Drupal、phpMyAdmin、PHPMailer、PHPUnit、Twig、Yii2、Guzzle、WordPress 配置泄露等 24 条规则 |
| `dotnet` | .NET / .NET Core / .NET Framework 版本 EOL 分支、CVE-2021-26701、CVE-2020-1147、CVE-2017-8759、Newtonsoft.Json（CVE-2024-21907）、Telerik UI for ASP.NET AJAX（CVE-2019-18935 / CVE-2017-11317），并覆盖 ASP.NET Core / Kestrel / NuGet 组件别名 |

### 四路数据来源

1. **远端指纹**：服务 banner、`Server` / `X-Powered-By` / `X-Jenkins` / `X-AspNet-Version` 等响应头、页面技术栈特征。
   可识别 `nginx/1.18.0`、`openresty/1.21.4.1`、`Apache Tomcat/9.0.65`、`Werkzeug/2.0.3 Python/3.9.5`、
   `Java/1.8.0_301`、`Jetty(...)`、`X-Powered-By: Express` / `Next.js` / `Nuxt` / `NestJS`，
   以及 `X-Powered-By: PHP/8.1.2`、`PHPSESSID`、`__VIEWSTATE`、`X-AspNet-Version: 4.0.30319`、
   `X-AspNetMvc-Version`、`Microsoft-IIS/10.0`、`Kestrel`、`Blazor` 等 PHP / .NET 特征。
   OpenResty 会把版本前三段推算为捆绑的 Nginx 版本再匹配一次规则。
2. **远端只读暴露面探测**（`--shallow` 时跳过）：`/nginx_status`、`/stub_status`、`/debug/pprof/`、`/metrics`、
   `/console`（Werkzeug debugger）、`/druid/index.html`、`/actuator/gateway/routes`、`/jolokia`、
   `/eureka/apps`、`/swagger-resources`、`/WEB-INF/web.xml`、`/META-INF/MANIFEST.MF`、
   `/package.json`、`/package-lock.json`、`/.npmrc`、`/server.js`、`/app.js`；
   PHP：`/phpinfo.php`、`/info.php`、`/.env`、`/composer.json`、`/composer.lock`、
   `/vendor/composer/installed.json`、`/storage/logs/laravel.log`、`/adminer.php`、
   `/phpmyadmin/`、`/wp-config.php.bak`；
   .NET：`/elmah.axd`、`/trace.axd`、`/web.config`、`/App_Data/`、`/swagger/v1/swagger.json`、`/Hangfire`；
   另有 `/application.yml`、`/debug/vars`、`/api-docs`、`/nginx.conf` 等敏感路径纳入 Web 深度扫描。
   上述探针**无条件全量执行**：不因组件版本是否命中规则、也不因 `--stack-categories` 只选了某几类技术栈而跳过。
3. **本地运行时与依赖**（扫描本机目标时默认开启，`--stack-local` 可强制开启）：
   `java -version` / `go version` / `python --version` / `gcc -dumpversion` / `nginx -v` /
   `openresty -v` / `node --version` / `npm --version` / `php -v` / `composer --version` /
   `dotnet --version` / `dotnet --list-runtimes` / `dotnet --list-sdks`、
   `pip list`、`npm list -g --depth=0`、`composer global show`、`dpkg` / `rpm` / `apk` 已安装包，
   `requirements.txt` / `go.mod` / `go.sum` / `pom.xml` / `build.gradle` / `*.jar`，
   `package.json` / `package-lock.json` / `npm-shrinkwrap.json` / `yarn.lock` / `pnpm-lock.yaml`，
   以及 `composer.json` / `composer.lock`、`*.csproj` / `*.vbproj` / `packages.config` /
   `packages.lock.json` / `project.assets.json` / `global.json` / `Directory.Packages.props`。
4. **本地 Nginx / OpenResty 配置核查**：`server_tokens off`、`autoindex on`、`lua_code_cache off`、
   `ssl_protocols` 中的 TLSv1/TLSv1.1、`client_max_body_size 0`。

所有远端请求都是只读 GET，不上传、不写入、不执行代码、不做漏洞利用；本地采集只执行
`--version` 一类查询命令并读取文本文件。版本匹配类结论可能受发行版补丁向后移植影响，
报告里会标注「需二次确认」。

> 本地依赖采集会遍历当前目录与常见部署目录（`/opt`、`/srv`、`/var/www`、用户主目录等，
> 深度 3 层、最多 30000 个文件）。可用 `--jar-dirs "C:\opt;C:\apps"` 追加目录，
> 不需要时可用 `--no-stack-scan` 关闭整项扫描。

### Node.js 专项

- **调试端口 9229 / 5858** 已加入内置端口表与高风险端口清单。扫描时只读请求 `/json/list`，
  若返回 DevTools target 列表即判定为「未授权调试端口」——攻击者可通过 DevTools 协议执行任意代码（严重）。
  修复：`--inspect` 仅绑定 `127.0.0.1`，并用防火墙限制来源。
- **依赖采集**：`package.json`（dependencies / devDependencies / peerDependencies）、
  `package-lock.json` 与 `npm-shrinkwrap.json`（兼容 lockfileVersion 1/2/3）、`yarn.lock`、
  `pnpm-lock.yaml`，以及 `npm list -g --depth=0` 全局包；`@types/*` 与 git/file 依赖会自动排除。
- **远端识别**：`X-Powered-By: Express`、`Next.js`、`Nuxt`、`NestJS`、`Koa`、`Fastify`，
  以及 `__NEXT_DATA__`、`__NUXT__`、Socket.IO 等页面特征；同时核对 `/package.json`、
  `/.npmrc`、服务端源码是否对外可访问。
- 只扫 Node.js：`python scan.py 目标 --stack-categories nodejs`
  （也接受 `node` / `npm` / `js` / `javascript` 别名）。

### PHP 专项

- **规则**：PHP 运行时（CVE-2024-4577 / CVE-2024-8929 CGI 参数注入、CVE-2023-3823 phar 溢出、
  CVE-2022-31625/31626、CVE-2024-1874、CVE-2024-5458、各分支 EOL 提示），以及 Composer /
  Laravel / Ignition / ThinkPHP / Drupal / phpMyAdmin / PHPMailer / PHPUnit / Twig / Yii2 / Guzzle 组件 CVE。
- **指纹**：`X-Powered-By: PHP/8.1.2`、`PHPSESSID`、`phpinfo()` 页面特征，
  Laravel / ThinkPHP / WordPress / Drupal / phpMyAdmin / Symfony / CodeIgniter / PHPUnit 页面特征。
- **暴露面**：`/phpinfo.php`、`/info.php`、`/.env`、`composer.json` / `composer.lock`、
  `vendor/composer/installed.json`、Laravel 日志、Adminer / phpMyAdmin、`wp-config.php.bak`。
- **本地采集**：`php -v`、`composer --version`、`composer global show --format=json`，
  以及 `composer.json` / `composer.lock` 中的 require / require-dev 与 packages 锁定版本。
- **分类不冲突**：报告里 `PHP` 是技术栈组件分类，`PHP2Shell` 是独立的 PHP 利用面专区；
  PHP 运行时版本的 CVE 由 php2shell 模块统一报告，本地 `php -v` 只登记组件，避免同一漏洞重复出现。
- 只扫 PHP：`python scan.py 目标 --stack-categories php`（也接受 `composer` / `laravel` 等别名）。

### .NET 专项

- **规则**：.NET / .NET Core / .NET Framework 各分支 EOL 提示、
  CVE-2021-26701（System.Text.Encodings.Web RCE）、CVE-2020-1147（DataSet 反序列化）、
  CVE-2017-8759（WSDL 解析），以及 Newtonsoft.Json（CVE-2024-21907）、
  Telerik UI for ASP.NET AJAX（CVE-2019-18935 / CVE-2017-11317）。
- **指纹**：`X-AspNet-Version`、`X-AspNetMvc-Version`、`X-Powered-By: ASP.NET`、
  `Microsoft-IIS/10.0`、`Kestrel`、`__VIEWSTATE`、`Blazor`、`SignalR`、Umbraco / Sitecore。
- **暴露面**：`/elmah.axd`、`/trace.axd`、`/web.config`、`/App_Data/`、
  `/swagger/v1/swagger.json`、`/Hangfire`。
- **本地采集**：`dotnet --version` / `--list-runtimes` / `--list-sdks`，
  `*.csproj` / `*.vbproj` / `*.fsproj`（PackageReference）、`packages.config`、
  `packages.lock.json`、`project.assets.json`、`global.json`、`Directory.Packages.props`。
- 只扫 .NET：`python scan.py 目标 --stack-categories dotnet`
  （也接受 `.net` / `aspnet` / `asp.net` / `csharp` / `c#` / `nuget` 别名）。

### 按需扩展规则

在 `scanner/stackdb.py` 的 `STACK_RULES` 中追加一条即可，`scanner/vulndb.py` 会自动合并进索引：

```python
_r("CVE-XXXX-YYYY", "某组件远程代码执行", "critical", "java",
   "some-product", (("1.0", "1.2.3"),), "升级至 1.2.3 及以上"),
```

`products` 参数写主产品名，发行版包别名统一放在同文件的 `ALIASES` 中；
`ranges` 为 `[lo, hi)` 版本区间列表，`("*", "")` 表示所有版本。

## 内置端口分类

`python scan.py --list-ports` 可查看完整清单（去重后共 227 个端口）：

| 类别 | 说明 | 代表端口 |
| --- | --- | --- |
| `base` | 基础服务 / 远程管理 / 文件共享 / 通用 Web / Node.js 调试 | 21 22 23 53 80 443 445 3389 5900 5858 8080 8443 9229 |
| `mail` 邮件 | SMTP/POP3/IMAP 及管理口 | 25 110 143 465 587 993 995 2525 4190 7071 10024 |
| `database` 数据库 | 关系型 / 文档 / 时序 / 图 / 内存库 | 1433 1521 3306 5432 5984 6379 7000 7474 8086 8123 8529 9042 9200 11211 26257 27017 50000 |
| `ai` 大模型 | 推理服务 / 训练监控 / 向量库 | 11434 Ollama、1234 LM Studio、8000 vLLM、8001 Triton、8188 ComfyUI、8265 Ray、8888 Jupyter、6006 TensorBoard、9997 Xinference、6333 Qdrant、19530 Milvus、21001 FastChat |
| `media` 短视频直播 | RTMP/RTSP/SIP/WebRTC/SRT/GB28181 | 1935 RTMP、1985 SRS API、554/8554 RTSP、3478 STUN/TURN、5060 SIP、9710 SRT、10008 EasyDarwin |
| `ecommerce` 电商中间件 | 注册中心 / 消息队列 / 检索 / 监控 / 大数据 | 2181 ZK、8848 Nacos、9092 Kafka、9876 RocketMQ、20880 Dubbo、8983 Solr、15672 RabbitMQ、5601 Kibana、9090 Prometheus、50070 HDFS |

示例：`python scan.py 10.0.0.5 --categories mail,database,ai`

## 规则库

内置规则为离线版本匹配规则（CVE 编号 + 受影响版本区间），分两个文件维护：

- `scanner/vulndb.py`：操作系统 / Web / 通用中间件基础规则，并定义 `VulnRule` 与 `match_rules`
- `scanner/stackdb.py`：Java / Go / C++ / Python / Nginx / OpenResty / Node.js / PHP / .NET 技术栈规则（纯数据，自动合并进 `RULES`）

标记为 `confirm=True` 的规则表示结果**可能受发行版补丁向后移植影响**，报告中会提示需二次确认（例如 Ubuntu 在 OpenSSL 1.1.1f 上通过 `1ubuntu2.x` 后缀修复 CVE，而主版本号不变）。

按需扩展：在 `RULES` 中追加一条 `VulnRule` 即可，例如

```python
VulnRule("CVE-XXXX-YYYY", "某组件远程代码执行", "critical", "web",
         ("nginx",), (("1.20.0", "1.20.2"),),
         "升级至 1.20.2 及以上", "https://nvd.nist.gov/..."),
```

## 免责声明

本工具仅可用于您拥有所有权或已获得**书面授权**的资产的安全评估。
未经授权对他人系统进行扫描可能违反《网络安全法》《刑法》等相关法律法规，后果由使用者自行承担。
