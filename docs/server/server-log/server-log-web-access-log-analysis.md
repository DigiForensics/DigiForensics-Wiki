---
title: "Web 访问日志深度分析"
slug: "server-log-web-access-log-analysis"
canonical: "https://www.digiforensics.cn/wiki/server-log-web-access-log-analysis"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["日志分析"]
---

# Web 访问日志深度分析

<a id="section-1"></a>

## 一、概述

W3C 访问日志提供 IIS 的逐请求记录，通常数据量大，需结合字段和业务基线筛选。

它不含任何人工行为推断，只有服务器工作线程按固定格式吐出的请求事实：谁、什么时候、请求了什么、结果如何、耗时多久。

事件日志记的是系统级事件，注册表记的是配置现状——只有访问日志能证明"这个具体的攻击请求确实到达过这台服务器，并且得到了这样的响应"。

**但这份证据的密度与分析要求完全不匹配。**

站点日均请求量动辄几十万条，逐条人眼看不动；而真正有意义的信息——"哪一批是自动化攻击、哪一次返回 200 说明落地成功"——**埋在几十万条 `200 0 0` 里。**

难点在于把噪声压下去。

**本篇给出的三层判读方法**：

1. **状态码三元组**——`sc-status` / `sc-substatus` / `sc-win32-status` 的组合语义。**这是 IIS 独有的信息维度**，比单看状态码精确得多，能区分"文件真不存在"和"路径语法错了"这种看似同为 404 的情况。
2. **攻击特征的日志指纹**——SQL 注入、路径穿越、上传落地、目录扫描、凭据爆破、脚本调用，各自对应不同的字段组合模式。
3. **风险打分脚本**——把上述判读固化成可运行、可复现、可调阈值的自动化流程，输出 Top N 可疑请求**并附命中原因**。

**在取证流程中的位置**：本篇属于**分析环的归因层**，输入是已解析的 W3C 结构化记录，输出是"哪些请求可疑"的候选集。

**它的产出是候选，不是结论**——每个候选都要在 [3.3 第 3 步](#section-10) 人工复核，并在主机侧印证后才进入报告。

上游依赖 [IIS 配置与 W3C 日志](server-log-iis.md)——**本篇假设你已读完它并能正确解析**（字段表可信、时区已换算、状态码两层含义已分清，这三条没做到，每个统计数字都是错的而且不会报错）；下游接上 [Web 攻击痕迹还原](server-log-web-attack-trace-reconstruction.md) 的主机侧印证。

**涉及的证据形态**（具体到字段，不是"访问日志"这种大类）：

| 维度 | 字段 | 判读价值 |
|---|---|---|
| **状态码三元组** | `sc-status` + `sc-substatus` + `sc-win32-status` | ★★★★★ **本篇最核心的判据** |
| 组合判读 | `404/1` = 未找到站点 | ★★★★★ **虚拟主机扫描的强信号** |
| | `404/7` = 扩展名被拒 | ★★★★★ 攻击被 Request Filtering 挡下的直接证据 |
| | `404/14` = URL 过长 | ★★★★ 缓冲区溢出类探测前兆 |
| | `sc-win32-status=2` vs `3` vs `5` | ★★★★★ **文件不存在 / 路径不可达 / 存在但被拒** |
| **耗时** | `time-taken`（**毫秒**） | ★★★★★ **时间盲注的唯一抓手** |
| **查询串** | `cs-uri-query`：`' OR 1=1--`、`UNION SELECT`、`SLEEP(5)` | ★★★★★ 注入指纹 |
| **请求路径** | `cs-uri-stem`：`../`、`%2e%2e/`、`%252e`（双重编码） | ★★★★ 路径穿越 |
| **方法 + 路径** | `PUT`/`PATCH` 到 `/upload*` 且 `.aspx` | ★★★★★ 落地证据，响应 `201` |
| **UA** | `sqlmap`、`Nikto`、`nuclei`、`python-requests` | ★★ **只是佐证，不能单独定性** |
| **时间分布** | 间隔 P90−P10 抖动 < 5% | ★★★★★ **机器节拍，脚本发出的确证** |
| **客户端 IP** | `c-ip` 全是同一个 → 那是 CDN/代理 | ★★★★ 归因前的必查项 |

> ★ **本篇最重要的纠错**：大量中文资料把 `404.3` 说成"Win32 找不到路径"。**这是错的**——`sc-substatus=3` 是 **MIME 类型限制**；"路径找不到"是 `sc-win32-status=3`（`ERROR_PATH_NOT_FOUND`），"文件找不到"才是 `sc-win32-status=2`。**混用会得出"文件存在只是路径错了"这种反向结论。**

哪些请求是自动化攻击而非人工浏览；某次攻击探测是否真的到达了 IIS 并被哪一层挡下（`404/7` 比"没落地"更有价值）；时间盲注藏在哪条记录里；某次 `PUT ... 201` 是否意味着上传成功；哪些 IP、路径、UA 组合构成一条完整的攻击序列；攻击窗口的起止时间。

**攻击是否利用成功**——`200` 不等于代码执行成功，可能是错误页；请求体与响应体内容（W3C 不记录）；**攻击者的真实 IP**（`c-ip` 在反代后面是代理，见 [01 篇](server-log-iis.md)）。

**主机的后续行为**日志里也没有——日志到此为止，要看文件系统与事件日志。至于哪些请求被 `sc-substatus` 之外的静默失败路径吞掉，同样无从查证。

**内容边界（本篇的红线）**：本篇处理的是**日志侧的统计特征与攻击请求的识别**，产出是"哪些请求可疑"这一候选集。**它不提供任何攻击构造、载荷生成或利用步骤**——所有特征描述都以"如何从字段组合中认出这类请求"的角度表述。

同理，看到 `sqlmap` UA 不等于可以断定"对方用 sqlmap 攻击了"，**它只是忘了改默认值的疏忽性证据**。

**读者前提**：需先掌握 [IIS 配置与 W3C 日志](server-log-iis.md) 中的字段表、时区换算和状态码含义。字段或时区使用错误可能使统计结果失真，而分析脚本未必报错。

事件 ID 基础与 `Get-WinEvent` 用法见[事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)。

另外需要 HTTP 状态码语义、正则表达式，以及对"标准差/分位数"这类统计量的直观理解（用来判读"间隔抖动 < 5%"这个判据）。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 ★ 状态码三元组：[IIS](server-log-iis.md) 比 HTTP 多给了两路错误信息

标准 HTTP 只返回 `404` 这样一个状态码。

IIS 在此基础上额外记录**两路**独立的失败原因，这是它取证价值高于普通 Web 日志的根本原因：
| 字段 | 含义 | 取值空间 | 反映的问题 |
|---|---|---|---|
| `sc-status` | HTTP 状态码 | 100–599 | 协议层结论（对客户端说的话） |
| `sc-substatus` | **IIS 细分子状态** | 各状态码下自定义 | **IIS 内部哪一步没通过** |
| `sc-win32-status` | **Win32 系统错误码** | Windows 错误码 | **操作系统层失败原因** |

> **★★★ 本篇最重要的纠错**：大量中文资料把 `404.3` 说成"Win32 找不到路径"。**这是错的**——`sc-substatus=3` 是 **MIME 类型限制**；"路径找不到"是 `sc-win32-status=3`（`ERROR_PATH_NOT_FOUND`），"文件找不到"才是 `sc-win32-status=2`。**混用会得出"文件存在只是路径错了"这种反向结论。**

**`sc-substatus` 侧组合判读**：

| 组合 | 含义 | 判读 |
|---|---|---|
| `404.0` | 未找到，文件已移动或不存在 | **真 404**。资源真的不在这个路径上 |
| `404.1` | **未找到站点** | 请求的 Host 头**没有对应绑定** → **虚拟主机扫描**的强信号 |
| `404.2` | **MIME 类型限制 / 路径语法问题** | 请求路径**形式上无法映射到文件** |
| `404.3` | **MIME 类型限制** | 扩展名映射无效或未配置（**不是路径找不到**） |
| `404.4` | **未配置处理程序** | 扩展名有 MIME 映射但**没有对应 handler** → 例如请求了 `.php` 但没装 PHP |
| `404.7` | **文件扩展名被拒绝** | 命中了 Request Filtering 的扩展名黑名单 → **攻击探测被 IIS 挡下的直接证据** |
| `404.14` | **请求 URL 太长** | 缓冲区溢出类探测的前兆，或畸形超长请求 |
| `400.1` | **请求头过长** | 超长 Header 探测 |

**`sc-win32-status` 侧**（与 `sc-substatus` 完全独立）：

| 值 | Win32 常量 | 含义 | 取证解读 |
|---|---|---|---|
| `0` | `ERROR_SUCCESS` | 无系统级错误 | 失败发生在 IIS/应用层，**不是文件系统问题** |
| `2` | `ERROR_FILE_NOT_FOUND` | 找不到**文件** | 路径是对的，只是文件不在 → **真 404 的确认信号** |
| `3` | `ERROR_PATH_NOT_FOUND` | 找不到**路径** | 路径**本身**不可达（中间目录不存在） |
| `5` | `ERROR_ACCESS_DENIED` | 拒绝访问 | 权限或 Request Filtering 拦截 |
| `53` | `ERROR_BAD_NETPATH` | 网络路径不存在 | 指向了 UNC 或已卸载的共享 |

> **判读口诀**：`sc-win32-status=0` + `5xx` = **应用层自己崩了**，与文件无关；`sc-win32-status=2` + `404` = 文件确实不存在；`sc-win32-status=5` + `404` = **存在但被拒绝**——这一条最容易被误判成"文件不存在"，实际是**被权限或过滤规则挡住**，而文件可能就在那儿。

<a id="section-4"></a>

### 2.2 攻击特征在日志中的落点

每类攻击都在特定字段上留下固定模式。把"攻击类型 → 字段模式"记住，比记正则表达式有用得多。

| 攻击类型 | 判读字段 | 特征模式 | 典型响应 |
|---|---|---|---|
| **SQL 注入** | `cs-uri-query` | `' OR 1=1--`、`id=1 UNION SELECT null,version()`、`id=1 AND SLEEP(5)` | 500（语法错）、**200 + `time-taken` 异常大**（盲注）、200（直接回显） |
| **路径穿越** | `cs-uri-stem` | `../`、`..%2f`、`%2e%2e/`、`..%5c`、`%252e`（双重编码） | 404/2（无法映射）、200（读到了系统文件） |
| **上传落地** | `cs-method` + 路径 | `PUT`/`PATCH`、路径在 `/upload*`、扩展名 `.aspx` | **201 Created**（成功）、405（不允许） |
| **目录扫描** | 批量 `404` | 同一 IP 短时间大量不同路径全 404，路径呈**规律递增** | 全部 404 |
| **凭据爆破** | `sc-status` | 同一 IP 同一路径集中出现 `401`/`403` | 401/403，末尾可能夹一个 302 |
| **脚本调用** | `cs-uri-query` | `cmd=`、`exec=`、`shell=`、`eval=` 等参数名 | 200 + 响应体极小 |
| **Web 扫描器** | `cs(User-Agent)` | `sqlmap`、`Nikto`、`nessus`、`acunetix`、`nuclei` | 混合 |
| **反代穿透** | `c-ip` | **全是同一个 IP** → 那是 CDN/代理，不是真实来源 | — |

> ★ 最有价值的单条判读：`time-taken` + SQL 注入。 时间盲注的注入请求返回 200，看起来完全正常——但 `time-taken` 会出现**明显离群值**。正常页面 `time-taken` 集中在几十毫秒，而 `SLEEP(5)` 那条是 5000+ 毫秒。在满是 200 的日志里，毫秒时延是唯一能把盲注揪出来的字段。 前提是不要把 `time-taken` 当秒（它是毫秒）。

<a id="section-5"></a>

### 2.3 User-Agent 与时间维度：两个最容易被滥用的维度

UA 是最容易被滥用的字段——**攻击者可随意伪造，它本身不构成任何证据**；而自动化发包**很难带上随机抖动**（工具默认固定 sleep）。

这两点必须同时理解。

| 维度 | 判读 | 可靠性 | 说明 |
|---|---|---|---|
| **UA** | 命中已知工具名（`sqlmap`/`Nikto`） | ★★★ | 攻击者**忘了改**默认值，属疏忽性证据，须与查询串互证 |
| | 为空 | ★★ | 脚本化常见；也可能是极简客户端或反代剥离 |
| | `python-requests`/`curl` | ★★ | 自动化客户端。**但备份脚本、监控探针、CI 也是这个** |
| | **正常浏览器 UA 但行为异常** | ★★★★★ | **最有价值**——伪装正常，正因如此才要看查询串 |
| **时间** | 深夜突增（00:00–05:00 偏离历史基线） | ★★★ | 业务此时本无流量 |
| | **间隔 P90−P10 抖动 < 5%** | ★★★★★ | **机器节拍**，脚本发出的确证 |
| | 每分钟数百请求且全 404 | ★★★ | 目录扫描 |
| | 沉寂数小时后单次请求 | ★★ | 人工介入或 C2 心跳 |

> **陷阱**：看到 `curl/8.4.0` 就写"攻击工具"是错的——**UA 只是佐证，不能单独定性**。
>
> **★ 为什么"间隔均匀"比"用了扫描器"更强**：工具 UA 可随便改、IP 可换代理，但**发包节拍是工具库的实现细节**。一条伪装成 Chrome、但 500 个请求间隔标准差极小的记录，比 100 条写着 `sqlmap` 的记录更能说明自动化。

<a id="section-6"></a>

### 2.5 为什么需要打分而不是单纯 grep

朴素做法是每个特征跑一个 `grep` 再人工去重排序，但有三个缺陷：

1. **一次命中不等于可疑**——`union` 也会出现在正常的技术文章页里；
2. **强信号往往不带单条特征**——自动化扫描的每一条单独看都是普通 404，**只有聚合后**才显出"几百个不同路径全是 404"；
3. **强信号常是弱特征的叠加**——空 UA（3 分）+ 无 Referer（3 分）+ 深夜（2 分）单条都不起眼，**加起来就超过一条真正的 SQL 注入**。

打分脚本的价值就是把"**弱信号叠加 + 跨行聚合**"固化下来，并且**输出命中原因**——评审时能直接看到"为什么这条是 31 分"，而不是一个黑箱数字。
---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 第 1 步：确认分析目标与时间基准

从镜像提取 `W3SVC*` 下的 `*.log*`（完整命令见第七章），随后确认两件事：

```bash
head -4 /evidence/u_ex241114.log    # #Software 判版本，#Fields 判字段顺序
ls -l /evidence/W3SVC2/             # ★ 体积异常 = 截断线索（见 04 篇）
```

**验证**：若同一文件出现多行 `#Fields`，说明当天改过日志配置（见 [02](server-log-iis.md)）。**做任何统计之前先确认时区**——W3C 的 `date`/`time` 是 **UTC**。

<a id="section-9"></a>

### 3.2 第 2 步：运行风险打分脚本

脚本仅用 Python 3.6+ 标准库，**无需 `pip install` 任何东西**。保存为 `w3c_risk.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IIS W3C 访问日志风险打分器：逐行规则匹配 + 4 个跨行聚合规则，输出 Top N 可疑请求。
用法: python3 w3c_risk.py <日志文件或目录...> [-n 20] [--tz +8] [--min 1] [-o risk.csv]
依赖: 仅 Python 3.6+ 标准库（无第三方包）"""
import argparse, glob, os, re, sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

# ===== 规则表 (规则码, 分值, 范围, 正则, 说明) =====
# 范围: t=解码后的"路径+查询串"  tp=t 再把 '+' 还原为空格  s=路径  ua=User-Agent  m=方法
RULES = [
    # --- SQL 注入 ---
    ("SQLI-UNION",   10, "tp", r"union\s+(?:all\s+|distinct\s+)?select", "URL 中拼接 union select"),
    ("SQLI-BOOL",    10, "tp", r"(?:'|\"|\b)\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", "恒真/恒假布尔条件"),
    ("SQLI-COMMENT",  8, "tp", r"(?:'|\")?\s*(?:--|#|/\*)\s*$|'\s*(?:--|#)", "SQL 注释截断后条件"),
    ("SQLI-TIME",    10, "tp", r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay", "延时函数（盲注）"),
    ("SQLI-INFO",     8, "tp", r"information_schema|sysobjects|syscolumns|sqlite_master|@@version", "库表结构枚举"),
    # --- 路径穿越 / 远程执行 ---
    ("TRAVERSAL",    10, "tp", r"\.\.[\\/]|%2e%2e|\.\.%2f|\.\.%5c|%252e|boot\.ini|win\.ini", "路径穿越"),
    ("RCE-PARAM",    10, "tp", r"(?:^|[?&;])(?:cmd|exec|shell|command|eval|passthru|system|query)\s*=", "命令/执行类参数名"),
    ("RCE-SEP",      10, "tp", r"\|\s*(?:cat|whoami|id|nslookup|ipconfig|tasklist)\b|%00|\$\{jndi:", "管道命令/空字节截断/JNDI"),
    # --- 落地与扫描 ---
    ("WEBSHELL-EXT", 10, "s", r"\.(?:aspx|ashx|asmx|axd|config|php[0-9]?|jsp|asp|cer|asax)(?:$|\.)", "可执行/可配置扩展名"),
    ("UPLOAD-PATH",   5, "s", r"/(?:upload|upfile|files|attachment|tmp|temp)/", "上传类路径"),
    ("SCAN-PATH",     5, "s", r"/(?:wp-admin|phpmyadmin|/admin\b|/manager/html|/WEB-INF|/\.git|/\.svn|/\.env|/backup|/cgi-bin|/solr|jenkins|actuator)", "常见扫描目标路径"),
    # --- User-Agent ---
    ("UA-BLACK",      5, "ua", r"sqlmap|nikto|nessus|acunetix|wpscan|nuclei|masscan|nmap|dirbuster|gobuster|havij|arachni", "已知扫描/利用工具 UA"),
    ("UA-SCRIPT",     3, "ua", r"^(?:python-requests|python-urllib|curl|wget|go-http-client|okhttp|node-fetch|axios|apache-httpclient|libcurl)", "脚本化 HTTP 客户端 UA"),
    ("UA-EMPTY",      5, "ua", r"^$", "空 User-Agent"),
    # --- 方法 ---
    ("METHOD-WRITE",  5, "m", r"^(?:PUT|PATCH|DELETE|MKCOL|MOVE|COPY|OPTIONS|TRACE|DEBUG)$", "写入/配置类 HTTP 方法"),
]

# ===== 聚合阈值（经验值，须按站点历史基线调整）=====
BURST_404, BRUTE_N, DIR_ENUM, REGULAR_N = 200, 10, 50, 12

def _i(x):
    """安全转 int：字段缺失或行被截断时返回 -1，绝不抛异常中断整个分析。"""
    try:
        return int(x)
    except (TypeError, ValueError):
        return -1

def status_rules(st, sub, w32):
    """★ sc-status / sc-substatus / sc-win32-status 三元组组合判读（原理见 2.1）。"""
    out = []
    if st == 201:
        out.append(("STATUS-201", 5, "201 Created：资源被新建（PUT 上传落地）"))
    if st in (400, 405, 406, 414, 431):
        out.append(("STATUS-4XX-BAD", 4, f"异常 4xx({st})：畸形请求/方法不允许"))
    if st in (500, 502, 503, 504):
        out.append(("STATUS-5XX", 5, f"服务端错误 {st}（应用异常/后端不可达）"))
    if st == 404:
        if sub == 1:
            out.append(("404-SITENOTFOUND", 5, "404.1 Host 头无绑定 → 虚拟主机扫描"))
        if sub == 3:
            out.append(("404-MIME", 3, "404.3 MIME 映射限制（★ 不是路径找不到）"))
        if sub in (7, 14, 17, 24, 51, 64):
            out.append(("404-PROBE", 6, f"404.{sub} 被 Request Filtering 拦截/URL 过长"))
        if w32 == 3:
            out.append(("WIN32-PATH404", 6, "sc-win32-status=3 ERROR_PATH_NOT_FOUND 路径不可达"))
        if w32 == 5:
            out.append(("WIN32-ACCESS", 4, "sc-win32-status=5 ERROR_ACCESS_DENIED"))
    if st in (401, 403):
        out.append(("STATUS-AUTH", 3, f"{st} 认证/授权失败"))
    return out

def parse_w3c(path):
    """流式解析 W3C。字段顺序只由 #Fields 决定（绝不写死索引），每遇 #Fields 即重读。"""
    fields = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\
")
            if line.startswith("#"):
                if line[1:].partition(":")[0].strip().lower() == "fields":
                    fields = line[1:].partition(":")[2].strip().split()
                continue
            if not line or fields is None:
                continue
            parts = line.split()          # W3C 值内无空格（UA 空格已变 +），无参 split 安全
            if len(parts) != len(fields):
                print(f"[WARN] {os.path.basename(path)} 字段数 {len(parts)} != "
                      f"#Fields {len(fields)}（截断或配置变更边界）", file=sys.stderr)
            yield {k: (None if v == "-" else v) for k, v in zip(fields, parts)}

def build_target(r):
    """还原可匹配原文 → (路径, 查询串, 路径+查询串, 再把 '+' 还原为空格的版本)。
    ★ W3C 把查询串原样记录（不把 + 变空格），而 + 正是表单编码里空格的写法。"""
    stem, q = r.get("cs-uri-stem") or "", r.get("cs-uri-query") or ""
    dec = lambda s: unquote(s.replace("\\", "/"), errors="replace")
    whole = dec(stem + "?" + q if q else stem)
    return dec(stem), dec(q), whole, whole.replace("+", " ")

def main():
    ap = argparse.ArgumentParser(description="IIS W3C 访问日志风险打分器")
    ap.add_argument("paths", nargs="+", help="W3C 日志文件或目录（目录自动展开 *.log）")
    ap.add_argument("-n", type=int, default=20, help="输出 Top N，默认 20")
    ap.add_argument("--tz", type=int, default=8, help="本地时区相对 UTC 的小时偏移，默认 +8")
    ap.add_argument("--min", type=int, default=1, help="低于此分值的记录不输出")
    ap.add_argument("-o", help="导出全部命中记录为 CSV（utf-8-sig）")
    args = ap.parse_args()
    tz = timezone(timedelta(hours=args.tz))

    files = []
    for p in args.paths:
        files += sorted(glob.glob(os.path.join(p, "*.log"))) if os.path.isdir(p) else [p]
    if not files:
        print("[ERR] 未找到日志文件", file=sys.stderr)
        return 1

    total, hits, cand = 0, defaultdict(int), []
    st404, stauth, ipaths, ipts = (defaultdict(int), defaultdict(int),
                                   defaultdict(set), defaultdict(list))

    for path in files:
        for r in parse_w3c(path):
            total += 1
            stem, q, whole, whole_sp = build_target(r)
            # ★ W3C 用 + 代替 User-Agent 里的空格（与查询串中的 + 语义无关）
            ua = (r.get("cs(User-Agent)") or "").replace("+", " ")
            method = r.get("cs-method") or ""
            st, sub, w32 = _i(r.get("sc-status")), _i(r.get("sc-substatus")), _i(r.get("sc-win32-status"))
            scope = {"t": whole, "tp": whole_sp, "s": stem + " " + q, "ua": ua, "m": method}
            score, why = 0, []

            def fire(code, pts, desc):
                nonlocal score
                score += pts
                why.append(f"{code}(+{pts}) {desc}")
                hits[code] += 1

            for code, pts, sc, pat, desc in RULES:
                if re.search(pat, scope[sc], re.I):
                    fire(code, pts, desc)
            for code, pts, desc in status_rules(st, sub, w32):
                fire(code, pts, desc)
            if not r.get("cs(Referer)"):
                fire("NO-REFERER", 3, "无 Referer 头（多为直接 API 访问）")

            try:    # W3C 的 date/time 是 UTC，必须带上时区再做本地时段判断
                ts = datetime.strptime(f"{r.get('date')} {r.get('time')}",
                                       "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                ts = None
            if ts and 0 <= ts.astimezone(tz).hour <= 5:
                fire("NIGHT", 2, f"本地 {ts.astimezone(tz):%H:%M} 落在 00:00-05:00")

            ip = r.get("c-ip") or "?"
            if st == 404 and ts:
                st404[(ip, ts.date())] += 1
                if len(ipaths[ip]) < 5000:
                    ipaths[ip].add(stem)
            if st in (401, 403):
                stauth[(ip, method, stem)] += 1
            if ts and len(ipts[ip]) < 20000:
                ipts[ip].append(ts)
            if score >= args.min:
                cand.append(dict(ts=ts, ip=ip, method=method, stem=stem, q=q, st=st, sub=sub,
                                 w32=w32, score=score, why=why, file=os.path.basename(path)))

    # ===== 跨行聚合：单条看不出的行为，只有聚合后才显形 =====
    burst = {ip for (ip, _d), n in st404.items() if n >= BURST_404}
    enum = {ip for ip, s in ipaths.items() if len(s) >= DIR_ENUM}
    brute = {k for k, n in stauth.items() if n >= BRUTE_N}
    regular = set()
    for ip, tss in ipts.items():
        if len(tss) < REGULAR_N:
            continue
        tss.sort()
        g = sorted((b - a).total_seconds() for a, b in zip(tss, tss[1:]))
        med = g[len(g) // 2]
        # P90-P10 抖动 < 5% → 机器节拍（自动化工具固定 sleep 发出）
        if med > 0 and (g[int(len(g) * 0.9)] - g[int(len(g) * 0.1)]) / med < 0.05:
            regular.add(ip)

    for c in cand:
        add = []
        if c["ip"] in burst:
            add.append(("BURST-404", 8, f"单 IP 单日 404 ≥ {BURST_404} 次"))
        if c["ip"] in enum:
            add.append(("DIR-ENUM", 6, f"单 IP 命中不同 404 路径 ≥ {DIR_ENUM} 条"))
        if (c["ip"], c["method"], c["stem"]) in brute:
            add.append(("BRUTE-FORCE", 8, f"同路径 401/403 ≥ {BRUTE_N} 次"))
        if c["ip"] in regular:
            add.append(("REGULAR-INTERVAL", 6, "请求间隔抖动 <5% → 自动化节拍"))
        for code, pts, desc in add:
            c["score"] += pts
            c["why"].append(f"{code}(+{pts}) {desc}")
            hits[code] += 1

    cand.sort(key=lambda x: (-x["score"], x["ts"] or datetime.max.replace(tzinfo=timezone.utc)))
    print(f"\
扫描 {len(files)} 个文件 / {total} 条记录，命中 {len(cand)} 条，"
          f"输出 Top {min(args.n, len(cand))}", file=sys.stderr)
    print("规则命中统计: " + ", ".join(f"{k}={v}" for k, v in sorted(hits.items(), key=lambda x: -x[1])),
          file=sys.stderr)
    print(f"\
{'分':>3}  {'本地时间':<19} {'客户端IP':<15} {'方法':<6} "
          f"{'状态/子/Win32':<12} {'请求':<44} 命中规则")
    print("-" * 150)
    for c in cand[:args.n]:
        lt = f"{c['ts'].astimezone(tz):%Y-%m-%d %H:%M:%S}" if c["ts"] else "(无时间戳)"
        req = (c["stem"] + (("?" + c["q"]) if c["q"] else ""))[:44]
        print(f"{c['score']:>3}  {lt:<19} {c['ip']:<15} {c['method']:<6} "
              f"{c['st']}/{c['sub']}/{c['w32']:<8} {req:<44} " + "; ".join(c["why"]))

    if args.o and cand:
        import csv
        with open(args.o, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["score", "local_time", "utc_time", "c-ip", "cs-method", "cs-uri-stem",
                        "cs-uri-query", "sc-status", "sc-substatus", "sc-win32-status", "rules"])
            for c in cand:
                lt = c["ts"].astimezone(tz).strftime("%Y-%m-%d %H:%M:%S") if c["ts"] else ""
                w.writerow([c["score"], lt, c["ts"].strftime("%Y-%m-%d %H:%M:%S") if c["ts"] else "",
                            c["ip"], c["method"], c["stem"], c["q"], c["st"], c["sub"], c["w32"],
                            " | ".join(c["why"])])
        print(f"[+] 已写出 {args.o}（{len(cand)} 行）", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**运行**：

```bash
python3 w3c_risk.py /evidence/W3SVC2 -n 20 --tz +8 -o /evidence/risk.csv
```

**实测输出**（对一段含 SQL 注入、爆破、目录扫描的日志）：

```
扫描 1 个文件 / 41 条记录，命中 40 条，输出 Top 4
规则命中统计: NO-REFERER=39, UA-EMPTY=25, REGULAR-INTERVAL=20, UA-BLACK=13,
              STATUS-AUTH=11, BRUTE-FORCE=11, SQLI-COMMENT=2, RCE-PARAM=2,
              UA-SCRIPT=2, SQLI-BOOL=1, SQLI-UNION=1, STATUS-5XX=1, SQLI-TIME=1, ...

  分  本地时间(UTC+8)         客户端IP            方法      状态/子/Win32   请求                                        命中规则
 31  2024-11-14 11:14:33 45.83.12.9   GET   500/0/0   /product/list.aspx?id=7'+UNION+SELECT+null,...  SQLI-UNION(+10); SQLI-COMMENT(+8); UA-BLACK(+5); STATUS-5XX(+5); NO-REFERER(+3)
 26  2024-11-14 11:15:10 45.83.12.9   GET   200/0/0   /product/list.aspx?id=1+AND+SLEEP(5)--         SQLI-COMMENT(+8); SQLI-TIME(+10) 延时函数（盲注）; UA-BLACK(+5); NO-REFERER(+3)
 26  2024-11-14 11:18:20 45.83.12.9   PUT   201/0/0   /uploads/shell.aspx?cmd=dir                    RCE-PARAM(+10) 命令/执行类参数名; UA-SCRIPT(+3); METHOD-WRITE(+5); STATUS-201(+5); NO-REFERER(+3)
 19  2024-11-14 11:19:00 91.203.44.7  GET   401/0/0   /admin/login.aspx                              UA-BLACK(+5); STATUS-AUTH(+3); NO-REFERER(+3); BRUTE-FORCE(+8) 同路径 401/403 ≥ 10 次
```

**★ 注意第 2 行**：`sc-status=200` 但 `time-taken` 是 5210 ms，而同页面的正常请求是 180 ms。**这条返回 200 的请求其实是时间盲注**——只按状态码筛选会把整个攻击漏掉。

> **打分结果的读法**：31 分那行命中 5 条规则且**每条都指向同一行为**（SQL 注入 + 工具 UA + 500 异常 + 无 Referer），**这种"多规则指向同一结论"才是高分记录应有的样子**。相比之下 19 分那行虽然也命中 4 条，但其中 3 条（UA/AUTH/NO-REFERER）只是爆破的伴随特征，**真正的定性依据是 `BRUTE-FORCE`**——它来自跨行聚合，单看这一行根本看不出来。**这正是打分脚本相比逐条 grep 的价值所在。**

<a id="section-10"></a>

### 3.3 第 3 步：人工确认与聚合复核

打分只是**排序工具**，不是定性工具。每条高分记录必须回原文核对，并补充三组全局统计（完整命令见第七章）：

| 确认项 | 判据 |
|---|---|
| **字段未错位** | 逐列数与 `#Fields` 对齐，`sc-status` 位置确实是三位数状态码 |
| **不是日志截断** | 该行字段数 == `#Fields` 列数（见 [02](server-log-iis.md) 案例） |
| **不是业务误报** | 业务系统确实有 `/admin/login.aspx` 这类高频认证接口 → 爆破规则会误报 |
| **有旁证** | 同 IP 同时出现在事件日志、站点目录落地文件或 `$UsnJrnl` 中 |

**★ 聚合统计中价值最高的一组是状态码三元组分布**（`awk '!/^#/ {print $15"/"$16"/"$17}'`）：结果里若出现 `404/7`（扩展名被拒）或 `404/14`（URL 过长），说明攻击请求确实到达了 IIS 并被 Request Filtering 挡下——这是"攻击发生"的有力证据，即使没有任何一条落地。`500/0` 集中在某一时段则是**应用层被探测或崩溃**的信号（`sc-win32-status=0` 表明**不是文件系统问题**）。

---
<a id="section-11"></a>

## 四、常见陷阱

访问日志分析的难点不在解析，而在**归因**。

状态码、客户端标识、路径特征这些表层信号，每一个都有大量正常解释。

本章按**状态码判读、请求特征归因、统计方法、结论表述** 四组拆开。

<a id="section-12"></a>

### 4.1 状态码判读

<a id="section-13"></a>

#### 陷阱 1：把 `sc-substatus` 当成 `sc-win32-status`

**现象**

看到 `404.3`，判断为「文件不存在」，
于是把这条记录归入「路径探测」类事件。

**原因**

IIS 的状态码是三层结构，两个细分字段各自独立：

`sc-substatus` 是 IIS 层的细分原因，`sc-win32-status` 是底层系统错误码。

`404.3` 里的 `3` 在 IIS 层指的是 MIME 类型限制，而「路径找不到」这个含义属于 `sc-win32-status` 的 `3`。

两个字段的数值空间独立，混淆会导致判读方向完全错位：把配置问题当成路径探测，或把路径探测当成配置问题放过。

**影响**

一整类事件被错误归类。正确率直接受损，而这种错误在报告里很难被读者察觉——读者看到的是一份格式规整、只是归类偏了的表。

**核查**

**两个字段分列存储、分列解释、报告里分开呈现。** 数据表里它们是并列的两列，不允许合并。

判读方向（用于判断是否值得关注，不必逐值背）：

- **`sc-substatus` 指向站点配置层面**：MIME 映射缺失、
  处理程序未配置、请求 URI 过长、扩展名被黑名单拒绝
- `sc-win32-status` 指向请求处理层面：文件是否存在、
  路径是否可访问、访问是否被拒绝

判断路径相关行为时，看 `sc-win32-status` 那一列的分布。
本文另一篇对各取值有完整对照，本篇只强调一个操作要求：
写代码时把两个字段分别取出来，不要用一个变量名去装。

<a id="section-14"></a>

#### 陷阱 2：只按状态码筛选异常

**现象**

按 4xx 和 5xx 筛出「可疑请求」，做完全部分析。
报告里写「已对全部异常请求完成排查」。

**原因**

**相当一部分可疑请求返回的是 200。** 典型情形是信息探测类的请求：构造的参数如果被正常接收并返回了正常页面（可能是一个报错页面、可能是过滤后的空结果），状态码仍然是成功。

反过来，4xx 里有相当大一部分是真实的用户错误：拼错的 URL、旧页面链接、前端路由变更后的失效引用、扫描器的噪声。

两类错误同时发生：漏掉返回 200 的可疑请求，以及被大量无害的 4xx 淹没。

**影响**

双向失效：漏报与淹没同时发生，而两边都不会报错。

**核查**

**状态码只是维度之一，不能单独作为筛选依据。** 至少叠加三个维度：

1. **耗时离群** —— 明显偏离该站点的正常分布。
   这类特征对「服务端处理时间与请求复杂度不匹配」的请求有效
2. **路径模式** —— 是否落在该站点的业务路径之外
3. **来源行为** —— 同一来源的请求序列是否有规律

**耗时基线要按站点自己算**：统计该站点全部请求的耗时分布，
取高分位点作为阈值，而不是套用通用常数。

推荐做法是**先做二维筛选**（状态码 × 耗时离群），
把候选集缩小到可人工复核的规模，再逐条看内容。

<a id="section-15"></a>

#### 陷阱 3：把耗时字段当秒

**现象**

看到 `time-taken=5210`，判断这次请求处理了 87 分钟，
进而推断「这个请求跨越了很长时间，期间可能发生了别的活动」。

**原因**

**该字段的单位是毫秒**，`5210` 是 5.2 秒。
把毫秒当秒，得到的数字在量级上就是错的。

**影响**

时间线分析出现不合理的数值，并据此做出错误推断。
这类错误一旦写进报告，会连带影响其他结论的可信度。

**核查**

**在解析层就把单位固定，让下游无法误用。**

```python
taken_ms = int(row['time-taken'])
taken_s = taken_ms / 1000.0        # 统一为秒
```

报告与图表里统一用秒并标注单位。

筛选阈值要明确是毫秒还是秒——很多资料里的 `> 5000` 是**毫秒**（即 5 秒），按秒理解会把阈值放大 1000 倍。

注意这个字段有上界：超大值通常来自连接被中断或超时，不代表真的处理了那么久。

遇到异常大的值，要回看同源请求是否有对应的 4xx/5xx。

<a id="section-16"></a>

#### 陷阱 4：认为扫描全是 404 就等于攻击失败

**现象**

统计某个来源的请求，98% 返回 404，结论写「该来源的攻击未成功」。

**原因**

404 只说明**那一次请求**没有命中目标。

自动化扫描的行为模式是广撒网——几百个路径里只要有一个可用就算成功。而反过来，**扫描的前期阶段 404 比例天然很高**，因为对方正在枚举哪些路径存在。

更关键的是：**真正成功的那一两笔会被大量 404 淹没**。一份按状态码分组的统计里，1 条 200 藏在 200 条 404 中很容易被略过。

把进行中的活动描述为已失败的活动。

这类误判会直接影响处置决策——如果据此认为不需要继续关注，后续的实质行为就被漏掉了。

**影响**

处置层面出错：还在进行中的事被当成已经结束。

**核查**

判据是「这个来源有没有任何一条非 4xx 的记录」。
具体做法：

1. 提取该来源**全部**请求，不按状态码预筛
2. 单独检查是否存在 200、301、302、500 等记录
3. **哪怕只有 1 条**，也要抽出来逐字段看：
   请求了什么路径、什么参数、响应体多大、耗时多久
4. 把 404 的路径按模式归类，判断扫描器类型：
   - 字典式、无语义 → 通用扫描器
   - 有业务语义 → 对方做过前期研究，风险更高

不要用「404 多」推论「攻击失败」，要用「有没有那一条」来判断。

<a id="section-17"></a>

### 4.2 请求特征归因

<a id="section-18"></a>

#### 陷阱 5：只按客户端标识判断

**现象**

发现若干请求的客户端标识是命令行工具，报告写「发现基于命令行的可疑访问」。

**原因**

客户端标识是请求头里的一个自由文本字段，任何客户端都能设置成任意值。 它可以伪造，也可以被合法客户端设置成非浏览器值。

更重要的是，**命令行工具在正常场景里大量存在**：备份脚本、健康检查、监控探针、持续集成任务的构建与部署阶段、自动化测试。

这些行为与可疑访问在标识上完全一致。

把运维基建的正常行为报成可疑行为。

这类误报在报告里很扎眼，因为委托方一眼就能说出「那是我们自己的脚本」。

**影响**

信誉损耗：你报的"可疑"里有对方自己的运维脚本。

**核查**

**客户端标识只作佐证，永远不作主判据。** 它的正确用法是：

- 用于**排序**：命令行标识的请求优先人工复核
- 用于**排除**：如果是已知运维探针的路径与参数模式，直接排除

判断行为越界要看的是：

- 请求的**参数内容**是否超出该接口的正常参数范围
- 请求的**频率与间隔**是否符合人类操作特征
- 该来源**整体**的请求序列里，有没有其他越界行为

**空标识也是同理**：极简客户端、反向代理会剥离这个头。
「标识为空」既可能是可疑，也可能是正常，**不能单凭这一点定性**。
要结合同来源的整体行为。

<a id="section-19"></a>

#### 陷阱 6：只按路径里的特征词判断

**现象**

写规则匹配路径里的编码形式，扫出若干条，判定为路径穿越尝试。

**原因**

**正常业务里也可能出现这类形态。** 典型情况：

- 前端框架的路由重写规则，URL 里本来就有编码字符
- 某些 CMS 的 URL 友好化（slug）处理会做转义
- 业务参数里合法地传了含特殊字符的取值
- 应用自己拼接查询串时做了编码

也就是说，**编码形态不等于恶意意图**。

把正常的业务流量报成探测行为。

**影响**

误报会直接稀释后面真发现的分量。

**核查**

**必须结合服务端的响应字段来判断。** 关键是 `sc-win32-status` 那一列：

- 文件不存在 → 请求没命中任何东西，可能只是拼错
- 路径不可达 → 说明路径被解析了，但中途失败
- 存在但被拒绝 → **这一类才值得关注**

也就是说，**判断依据是「服务端对这类请求的最终处理结果」**，
而不是「请求里出现了什么字符」。

更进一步：如果站点对这类请求有 WAF 或路由规则，
正常情况下会被拦截并返回一个特定状态码。
如果大量请求返回了 200 且响应体正常，那说明它们被正常处理了。

<a id="section-20"></a>

#### 陷阱 7：查询串解析没做 URL 解码

**现象**

写好规则，扫描全站日志，零命中。结论写「未发现相关请求」。

**原因**

**W3C 格式记录的是 URL 编码后的原始形式。**
空格是 `%20`、斜杠是 `%2f`、引号是 `%22`。
拿解码后的特征串去匹配原始字段，永远匹配不上。

而且**这个失败是完全静默的**——规则正常执行，报告数正常，只是命中数为零。零命中会被读成「未发现」，而实际是「检测没跑起来」。

**影响**

整类检测规则失效，且失败信号被伪装成阴性结论。

这是访问日志分析里最危险的失败模式之一——阴性结论看起来和真阴性一模一样。

**核查**

**解析时做解码，并且两种形式都保留。**

```python
from urllib.parse import unquote_plus, unquote

stem_raw  = row['cs-uri-stem']
query_raw = row['cs-uri-query']

stem  = unquote(stem_raw)          # 路径：+ 不代表空格
query = unquote_plus(query_raw)    # 查询串：+ 就是空格（表单编码约定）
```

然后**两种形式都参与匹配**：

```python
# 规则匹配时同时试解码后与原始
hit = (needle in query) or (needle in query_raw)
```

保留两种形式是为了应对双重编码的情况——
有些请求确实会被应用层再编码一次。

**自查方法**：写完规则后，
**用构造的样本日志跑一遍正例**，
确认能命中；再用正常流量的样本跑一遍负例，确认不误命中。
规则零命中时先怀疑规则本身，再怀疑目标不存在。

<a id="section-21"></a>

#### 陷阱 8：把用户代理里的加号当空格切分

**现象**

按空格切分用户代理字段，得到 `Mozilla/5.0+(Windows+NT` 这样的残缺值。

**原因**

W3C 格式对含空格的字段做了替换：空格变成 `+`。
这是该格式的一个历史设计（早期为了保证字段值内不含分隔符）。
所以用户代理记录下来是没有空格的。

后果是**按空格切分这个字段是错的**——虽然这里切分不会报错（它就当成一个整体值），但后续拿这个值去匹配特征时，形态与实际请求里的不一致。

用户代理相关的规则失效，或者规则匹配到错误的形态。

**影响**

UA 维度的判断整体失真，而它恰好是最常被引用的那一列。

**核查**

用户代理字段用 `+` 还原为空格，不要按空格切分。

```python
ua = row['cs(User-Agent)'].replace('+', ' ')
```

注意这个 `+` 的语义**与查询串里的 `+` 完全不同**：

查询串里 `+` 本身就表示空格（表单编码的约定），用 `unquote_plus`；用户代理里的 `+` 是格式转换产生的，用直接替换。

**两个字段的处理方式不同，不要写成同一个函数。**

同样受影响的字段：`cs(Cookie)`、`cs(Referer)`。

如果站点启用了这些字段，都要做同样的还原。

<a id="section-22"></a>

### 4.3 统计方法与阈值

<a id="section-23"></a>

#### 陷阱 9：把固定阈值当通用真理

**现象**

用了「单 IP 5 分钟内 404 超过 200 次」这样的规则，
扫出 30 个 IP，全部列为可疑。

**原因**

**阈值的有效性完全取决于该站点的正常基线**，而基线差异极大：

- 内容管理系统：历史遗留的大量拼错链接、旧页面，
  正常 404 基数可能一天几万 → 阈值 200 形同虚设
- 只有三个页面的静态站：任何 20 次 404 都值得看 → 阈值太松
- 有夜间批量任务的站：凌晨集中请求是常态 → 时段维度必须纳入

而且**基线是可以自己算的**，不需要靠猜。

**影响**

要么漏（阈值过松），要么 30 条告警里全是正常，真正的异常被淹没。

**核查**

**阈值从该站点自己的历史数据来算。** 具体做法：

1. 取该站点最近 N 天的历史日志
2. 统计同 IP 的 404 次数分布
3. 取其高分位点（如 99 分位）作为阈值
4. **同时给出时间维度**：扫描是秒级密集，业务 404 是全天分散，
   两者的分布形态完全不同

在报告里写清阈值的来源：

> 本次分析采用「单 IP 5 分钟内 4xx 超过 P 次」作为筛选阈值，
> 其中 P = Q，取自该站点 2024-02-01 至 2024-03-15 期间
> 同 IP 4xx 次数分布的 99 分位点。
> 阈值调整后命中 N 个来源地址，逐一人工复核结果为：
> 确认 M 起、存疑 K 起、排除 N−M−K 起。

「用了某个阈值」不是方法说明，「阈值怎么来的」才是。

<a id="section-24"></a>

#### 陷阱 10：把单 IP 的全站总量当异常指标

**现象**

统计出某 IP 一天访问 12 万次，判定为异常。

**原因**

**这个数字本身没有意义**，关键要看访问了什么：

- 一个 IP 每天 12 万次但只有 3 个路径 → 监控探针、静态资源预取、自动化任务
- 一个 IP 每天只 30 次，但每次参数都不同且在管理路径 → 风险反而更高

**用「量大」替代「异常」，是把注意力放错了地方。**

**影响**

复核工时全花在最不需要的地方。

高流量地址被反复人工复核，而真正可疑的低频高价值行为被略过。

**核查**

按 (IP, 路径) 组合分组，不看单 IP 总量。

具体做法：先算出每个 IP 访问过的**不同路径数量**，
然后把地址分成两类分别处理：

- **路径数多**（广度大）→ 检查路径性质：是否越权、是否落在管理路径
- **路径数少但单路径量大**（深度大）→ 检查请求参数模式：是否在枚举取值

两类都要看，但**分析的重点不同**。
一个只按总量排序的清单，会让第二类被埋没。

<a id="section-25"></a>

#### 陷阱 11：把评分结果直接当结论

**现象**

脚本给每条记录打分，把分数前 20 名的记录写进报告的发现清单。

**原因**

启发式评分的作用是**在大量记录里排序**。它无法区分：

- 一个登录页被反复访问（正常但规则被触发）
- 一批真实的凭据尝试序列

两者的特征高度重叠，**因为业务系统的高价值入口就是那些规则会命中的地方**。评分算法不理解业务，它看到的只有特征。

把业务系统的正常高价值入口报成可疑点。

这类误报暴露了「没有结合业务理解」，对报告可信度伤害很大。

**影响**

这一条伤的是专业信誉，而不是某一条结论。

**核查**

**评分只做两件事：排序、缩小人工复核范围。** 每条进入报告的记录必须人工回看原始日志行，然后写清：

- 这条为什么被规则命中
- 结合站点实际业务，这个行为是否合理
- 结论档位：确认 / 存疑 / 排除，以及排除理由

三段式输出，每段都给数量：

- 机器初筛：规则 N 条，命中 M 条
- 人工复核：逐条回看，**排除 X 条**，确认 Y 条，存疑 Z 条
- 报告结论：确认 Y 条列入发现，存疑 Z 条列入待核查

排除项不必逐条写，但**排除理由要按类型汇总**
（「站点自身健康检查 120 条」「已知监控探针 30 条」）。
这既展示了覆盖面，也让读者能判断你的排除逻辑是否合理。

<a id="section-26"></a>

### 4.4 数据范围与结论表述

<a id="section-27"></a>

#### 陷阱 12：只查当前活跃日志文件

**现象**

打开当前的日志文件分析完，报告写「已分析该站点全部访问日志」。

**原因**

日志几乎一定被轮转过。当前文件里只有最近一段时间，**而关键行为往往发生在更早的时间段**。

更重要的是，轮转文件的存在与否决定了「全部」这个词是否成立。

时间覆盖不全，而「已分析全部」这个表述让所有基于它的阴性结论失效。

**影响**

阴性结论集体失效，而且失效得毫无征兆。

覆盖范围写错时，"未发现"三个字没有任何可核对的依据。

**核查**

1. 从配置读出实际日志目录（不要用默认路径）
2. 用宽松模式（`*` 后缀匹配）递归列出全部文件，含压缩归档
3. 按修改时间排序，逐个接入时间轴
4. 压缩文件先解压到工作副本
5. **在报告里列出文件清单与覆盖的时间范围**

> 本次分析覆盖站点 X（ID 为 3）的访问日志文件共 N 个，
> 时间范围 2024-01-05 至 2024-03-20。其中 M 个为压缩归档，
> 已解压至工作副本并计算哈希。
> 2023 年及更早的日志不在本机（日志轮转保留策略为 90 天）。

<a id="section-28"></a>

#### 陷阱 13：在原始镜像上跑改写类工具

**现象**

分析访问日志时，为了读取某个数据库，顺手在原始镜像上执行了修复操作。

**原因**

访问日志分析本身是纯只读的，但同一台机器上的数据库文件不是。 某些数据库的修复类工具会**改写文件**（这类工具的细节在本文另一篇展开）。在原始检材上跑这类操作，等于**销毁了原始状态**。

而原始状态里往往包含关键信息——比如「这个数据库上次是非正常关机」这个事实，修复之后再也看不到了。

证据被销毁，且不可逆。报告里会留下一个无法解释的状态变化。

**影响**

不可逆，且原始检材一旦被改，后面所有分析都站在一个说不清的状态上。

**核查**

**原则：需要写操作时，永远在副本上做。**

1. 原始镜像/文件只做只读挂载或只读读取
2. 需要任何可能写入的操作时，先做工作副本
3. **记录原始状态的证据必须先存档**——某些状态信息只在操作前存在
4. 工作副本上做完后，哈希与操作记录一起归档

对访问日志本身也适用：需要拼接、筛选、排序时，
把内容读入内存或写入独立的分析目录，不要改动原始文件。

<a id="section-29"></a>

#### 陷阱 14：结论没有写时间基准与覆盖范围

**现象**

报告里给出发现清单，每条都带时间，但没写这些时间是什么时区、
覆盖了哪段时间的日志。

**原因**

访问日志是 UTC 而系统日志是本地时间（陷阱 5 单独讲过）。如果报告里的时间不标注时区，读者无法判断它指的是哪一刻，**跨源的时间线关联也无法被验证**。

同时，**没有覆盖范围，「未发现」就是一句无法验证的话**——读者不知道你查了多久、查了多少。

结论无法被复核。委托方无法判断某个时段是否被查过。

**影响**

时间与范围不交代，整份报告的时间线就无法被第三方验证。

**核查**

报告的每个时间都要带时区，报告开头要有覆盖范围声明。

推荐的写法：

> **时间基准**：本文所有时间统一为 UTC+8。
> IIS W3C 原始日志为 UTC，已加 8 小时偏移；Windows 事件日志为本地时间，未换算。
>
> **数据覆盖**：站点 X（ID 3）访问日志 N 个文件，覆盖 2024-01-05 至 2024-03-20；
> Windows 安全日志覆盖 2024-02-18 至 2024-03-20；
> 站点配置文件 1 份，采集于 2024-03-20 15:30。
>
> **时间线中的每条记录都标注其来源**，方便读者判断跨源关联的可靠性。

阴性结论必须写成「在 X 范围 Y 检查内未发现 Z」，
并列出未覆盖的部分。这不是措辞讲究——
一份没有边界的阴性结论，在复核时等于没有结论。


<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 三元组与时延离群把五个 IP 分成三类行为

**场景**

查获 Windows Server 2019（IIS 10，站点 `digiforensics-site`，ID=2，日志目录 `D:\IISLogs\W3SVC2`），镜像 `DigiForensics.dd`（raw，1 TB，NTFS 起始扇区 2048），已关机。

委托方要求查明"该站点是否遭受过 Web 攻击"。

这条路径值得先走，是因为委托方的问题里藏着"遭受过攻击"这个含混表述——日志能回答的是"哪些请求是探测、哪些是尝试、哪些拿到了非预期响应"，而不是"有没有攻击"。

同一个 IP 出现在同一份日志里，可能是无害的漏洞扫描，也可能是已经成功的注入。**先把 IP 分成行为类型，再谈定性。**

**处置过程**

**第 1 步 · 提取并跑分**

```bash
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/u_ex241114.log
sha256sum /evidence/u_ex241114.log && head -4 /evidence/u_ex241114.log
ls -l /evidence/W3SVC2/
# u_ex241115.log   48210934
# u_ex241114.log      2143   ← 仅 2.1 KB，相邻日 48 MB

python3 w3c_risk.py /evidence/W3SVC2 -n 20 --tz +8 -o /evidence/risk.csv
# [WARN] 字段数 17 != #Fields 18（截断或配置变更边界）
# 扫描 1 个文件 / 41 条记录，命中 40 条，输出 Top 4
```

**发现 1**：11-14 日志仅 2.1 KB，相邻日 48 MB——当天日志被截断（成因见 [04](server-log-web-attack-trace-reconstruction.md)），且**末行不完整，不能作为当日攻击统计的完整依据**。

同时确认共 18 列，`cs-username` 后紧跟 `c-ip`、无 `cs-domain`。

**第 2 步 · 逐条人工确认 Top 记录**

| 本地时间 | 请求 | 三元组 | 判读 |
|---|---|---|---|
| `11:14:33` | `GET /product/list.aspx?id=7'+UNION+SELECT+null,version()--+` | `500/0/0` | **SQL 注入尝试**。`sc-win32-status=0` 表明**不是文件系统问题**，是应用处理异常 |
| `11:15:10` | `GET /product/list.aspx?id=1+AND+SLEEP(5)--` | `200/0/0`，`time-taken=5210` | **时间盲注命中**。200 响应但时延是同页面正常值的 29 倍 |
| `11:18:20` | `PUT /uploads/shell.aspx?cmd=dir` | `201/0/0` | **上传落地 + 脚本调用**。201 = 资源已创建 |
| `11:19:00`–`11:19:10` | `GET /admin/login.aspx` ×11 | `401/0/0` | **凭据爆破**。同 IP 同路径 11 次 401，UA 为 `Nikto/2.5.0` |
| `11:20:14` | `GET /api/v2/orders` | `200/0/0` | **无 Referer 的直接 API 访问**。**需业务确认是否合法** |

**发现 2**：同 IP `45.83.12.9` 在 5 分 41 秒内完成"注入尝试 → 盲注确认 → PUT 上传落地"的完整链条——属于**有目标的攻击**，不是随机扫描。`91.203.44.7` 的 11 次 401 属另一类：工具 UA 未改，**只到爆破阶段，未观察到成功**。

**第 3 步 · 聚合复核**

```bash
awk '!/^#/ {print $10, $15"/"$16"/"$17}' /evidence/u_ex241114.log | sort | uniq -c | sort -rn | head
#   24 66.240.10.5   404/0/2      ← 目录扫描，全是真 404（Win32=2 文件不存在）
#    9 45.83.12.9    200/0/0
#    3 45.83.12.9    404/1/0      ← 404.1：Host 头无绑定 = 虚拟主机扫描
```

**发现 3**：`66.240.10.5` 的 24 次 `404/0/2` 间隔严格 15 秒，`sc-win32-status=2` 确认**文件确实不存在**——是**探测**而非利用。`45.83.12.9` 则有 9 条 **200**，且其中一条 `time-taken=5210`。"这个 IP 有没有 200"是区分扫描与攻击的分水岭。

**结论**

| 结论 | 支撑 | 强度 |
|---|---|---|
| 存在有目标的 SQL 注入攻击 | `UNION SELECT` 载荷 + 500、`SLEEP(5)` 返回 200 且时延 29 倍于基线、UA 命中工具名 | **强**（三源互证） |
| 攻击者完成文件落地 | `PUT /uploads/shell.aspx → 201`，随后 9 秒内有访问 | **强**（需站点目录佐证落地内容） |
| 存在独立的凭据爆破来源 | `91.203.44.7` 11 次 401 同路径，UA `Nikto` | 强（**但未见成功**） |
| 存在大规模目录扫描 | `66.240.10.5` 24 次 404，间隔严格 15 秒 | 中（**已确认未命中**） |
| 11-14 当天日志不完整 | 2.1 KB vs 相邻日 48 MB + 字段数 17≠18 | **强（报告必须声明）** |
| `45.83.12.9` 是否已造成实际损害 | **仅凭访问日志无法判断** | 须查站点目录、事件日志、`$UsnJrnl`（见 [04](server-log-web-attack-trace-reconstruction.md)） |

**本节能证明**：五个 IP 的请求形态可分类，其中一个具备完整攻击链与文件落地响应。

**本节不能证明**：落地文件的实际内容、是否被后续利用、`/api/v2/orders` 的访问是否越权。

**阴性面**：本次统计基于 1 个文件、41 条记录，**其余 3 个站点的日志未纳入**。

**误判对照**

1. **把所有非 200 请求一律定性为攻击**。判据是 **`sc-win32-status` 的取值**：`404/0/2` 的 `2` 是 `ERROR_FILE_NOT_FOUND`，**说明文件确实不存在**，这类请求天然拿不到任何东西；`500/0/0` 的 `0` 则说明异常来自应用而非文件系统。只有 `sc-win32-status=0` 的非 200 才是"服务器处理了请求并报错"，才可能意味着载荷触达了后端逻辑。 按"非 200 即攻击"走，`66.240.10.5` 的 24 次纯探测与 `45.83.12.9` 的注入尝试会被混为一谈，**报告里"攻击源数量"会凭空翻几倍**，委托方据此封禁 IP 时会误封大量无害请求方。
2. **只看状态码，不看时延**。判据是 **`time-taken` 与同页面基线的比值**：本案 `SLEEP(5)` 那条返回 **200**，按"200 就是正常访问"会被直接放行；但它的 `time-taken=5210` 是同页面正常值的 29 倍，**载荷特征与时延离群相互印证**，才构成"盲注生效"的判断。**代价**：漏掉本案唯一一条能证明"注入真的生效了"的记录——**而"尝试过"和"生效过"在责任认定上完全不同**。
3. 把 `PUT → 201` 直接写成"文件已落地成功"。判据是**响应码语义与后续证据的组合**：`201` 只说明服务器接受了创建请求并返回了资源标识，**不说明磁盘上写入了什么内容**。要主张"落地成功且内容为脚本"，必须由站点目录侧的独立证据（文件存在性、落地时间戳、文件内容）支撑。**代价**：报告把 201 说成"文件已落地"，一旦对方复核发现目录里没有该文件，整份报告的可信度都会被质疑。

**按错误判据走的代价**：第 1 条踩中，报告里"攻击来源"从 1 个膨胀到 4 个，委托方按此批量封禁 IP 会影响正常业务。

第 2 条踩中，唯一一条证明注入生效的记录被划入正常流量，"仅尝试未生效"这个对委托方有利的结论反而被写成"已生效"，责任性质加重。

第 3 条踩中则会在对方技术复核时暴露。

<a id="section-32"></a>

### 5.2 反例 无 Referer 的 API 访问看起来像攻击但不是

**场景**

同一批检材的另一条线索。自动跑分报告里，`/api/v2/orders` 的无 Referer 访问被工具标为可疑，委托方追问"这是不是有人绕过前端直接拉数据"。

值得单独写一条，是因为这类请求在**任何统计视图里都长得像攻击**——它确实拿到了 200、确实没有 Referer、确实来自一个陌生的 UA 字符串。

但"不像正常浏览器访问"和"是攻击"之间没有推论关系。

**处置过程**

**第 1 步 · 取出该 IP 的完整请求序列**

```bash
grep ' /api/v2/orders ' /evidence/u_ex241114.log
# 2024-11-14 11:20:14 DIGIFORENSICS-WEB 10.10.0.5 GET /api/v2/orders - 80 - 45.83.12.9 mobile-report/1.0 - 200 0 0 87 20481
# 2024-11-14 11:20:19 DIGIFORENSICS-WEB 10.10.0.5 GET /api/v2/orders - 80 - 45.83.12.9 mobile-report/1.0 - 200 0 0 87 20481
# 2024-11-14 11:20:24 DIGIFORENSICS-WEB 10.10.0.5 GET /api/v2/orders - 80 - 45.83.12.9 mobile-report/1.0 - 200 0 0 87 20481
```

**发现 1**：三次请求的 `cs-bytes` 完全一致（20481）——返回内容字节数一字不差。若是真正的数据窃取，**分页参数或时间窗变化会直接改变响应长度**；长度恒定说明**每次拿到的都是同一份全量结果**。

同时三次间隔严格 5 秒、`time-taken` 恒为 87 ms，**没有任何探测期的时延抖动**。

**第 2 步 · 比对该 IP 的其他请求**

```bash
grep ' 45.83.12.9 ' /evidence/u_ex241114.log | awk '{print $5, $6}' | sort | uniq -c
#     9 GET /api/v2/orders
#     3 PUT /uploads/shell.aspx
#     2 GET /product/list.aspx
#     1 GET /product/catalog.aspx
```

**发现 2**：**同一个 IP 同时在做注入尝试与 API 拉取**——这正是本条线索棘手的地方。**行为归属不能靠"IP 相同"推断**，两条行为必须各自独立定性。
**第 3 步 · 查 UA 字符串的归属**

```bash
grep -c 'mobile-report/1.0' /evidence/u_ex241115.log
# 431
grep 'mobile-report/1.0' /evidence/u_ex241115.log | awk '{print $10}' | sort | uniq -c
# 398 200
#  31 304
#   2 404
```

**发现 3**：相邻日的 48 MB 日志里有 **431 条** `mobile-report/1.0`，且**状态码以 200 为主、含正常出现的 304**。一个攻击者不会在两天里发起 431 次带缓存协商的请求——`304` 的存在说明客户端在正常维护本地缓存，这是**有状态的正常客户端行为**。

**结论**

| 结论 | 支撑 | 强度 |
|---|---|---|
| `mobile-report/1.0` 是某个内部客户端的固定 UA | 相邻日 431 条、含 304、字节数高度一致 | 强 |
| `45.83.12.9` 的 API 拉取未表现出窃取形态 | 三次 `cs-bytes` 恒为 20481、无分页变化、时延无抖动 | 中（**仅 3 次样本**） |
| 该 IP 的注入与上传行为仍需独立定性 | 同一 IP 上 `PUT → 201` 与 `UNION SELECT` 载荷成立 | 强（**与本条互不抵消**） |
| 是否存在越权访问 | **访问日志无会话与鉴权信息** | **不可判，须查应用日志** |

**限定范围**：「`u_ex241114.log` 与 `u_ex241115.log` 两个文件、`W3SVC2` 一个站点、11-14 11:20:14 至 11:20:24 这 3 条记录」。

**未覆盖**：`/api/v2/orders` 的**鉴权与授权机制**（需应用侧日志或代码）；`45.83.12.9` 在**其他站点**的活动；`mobile-report/1.0` 对应客户端的**归属主体**（需问业务方登记）；11-14 当日**因日志截断而丢失的请求**。

**误判对照**

1. **"没有 Referer" 直接定性为攻击**。判据是**同源行为的稳定性**：正常客户端与攻击者在本案里的分界不是有没有 Referer，而是响应长度是否随请求变化——`cs-bytes` 三次恒为 `20481`，而真正的数据拉取会因分页、时间窗、筛选条件而改变长度。把"缺少浏览器特征"当判据，会把所有 App 客户端、curl 脚本、内部工具一并定性。**代价**：本案会把一条正常的移动端报表访问写进攻击报告，委托方据此追查"谁在偷数据"，方向完全跑偏，且要花时间向业务方解释一个不存在的攻击者。
2. 因为 IP 相同，把注入链的结论外溢到 API 请求上。判据是**行为的独立性**：本案 `45.83.12.9` 上的两类行为必须各自有证据支撑——注入由 `UNION SELECT` 载荷 + `SLEEP(5)` 时延离群证明，上传由 `PUT → 201` 证明，而 API 拉取这一条既无载荷特征也无响应长度变化。一个 IP 上成立的攻击，不自动让该 IP 的每一条请求都变脏。 **代价**：把所有请求一并写成攻击链的一环，会让报告的攻击时序失真，并掩盖真正需要追的"这个客户端是谁"。
3. **看到 `200` 就认为数据已被取走**。判据是**响应体大小与鉴权结果**：IIS 只记录 `sc-status` 与 `cs-bytes`，**它不记录"返回的是本人数据还是别人的数据"**。本案三次都是 `200/0/0` + 20481 字节，**IIS 侧完全无法区分合法与越权返回**。**代价**：把"拿到 200"写成"数据泄露已成立"，在民事与合规场景下是会被直接挑战的越界主张。

**按错误判据走的代价**：第 1 条踩中会凭空生成一个不存在的"数据窃取者"，并把正常的内部客户端推到对立面。

第 3 条踩中则可能让委托方据一份无法支撑的结论对外作出法律主张，**而复核只需一次接口鉴权日志就能推翻**。

本条的真实价值在于：它示范了**阴性结论也要写清"未覆盖什么"**——本案不能说"没有数据窃取"，只能说"这 3 条请求未表现出窃取形态，鉴权维度不可查"。

<a id="section-33"></a>

## 六、扩展阅读方向

**本篇把解析好的日志变成结论。** 下面按「要让结论站得住，还缺什么」组织。

<a id="section-34"></a>

### 前置与基础

- [IIS 配置与 W3C 日志](server-log-iis.md) —— **必读的上游**。本篇所有分析都建立在「字段表可信、时区已换算、状态码两层含义已分清」这三条之上；这三条没做到，每个统计数字都是错的，而且不会报错。
- [Windows 服务器取证工件地图](server-log-server-artifact-map.md) —— 数据源的边界。哪些日志存在、哪些通道未启用、时间覆盖到哪，先在这里确认，否则「未发现」无法界定范围。

<a id="section-35"></a>

### 同层深入

- [Web 攻击痕迹还原](server-log-web-attack-trace-reconstruction.md) —— 本篇产出「哪些请求可疑」，那篇产出「主机侧发生了什么」，两边对上才算闭环。
- [WebShell 工具流量特征](../server-web/server-web-webshell-traffic-patterns.md) —— 那篇处理**流量侧的协议特征**，本篇处理**访问日志侧的统计特征**。两者互为印证：日志筛出可疑来源，流量特征确认交互模式。
- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 当结论指向「某个文件被访问过」，文件侧排查就是它的下半段。

<a id="section-36"></a>

### 相邻议题

- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 跨源时间线的底座。访问日志是 UTC、事件日志是本地时间，换算没做好两边先后顺序会整个颠倒。
- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md) —— 主机缺少进程创建记录时的补充，但要先确认它**确实部署了**；未部署时的「无记录」不能写成「无异常」。
- [Exchange 与邮件数据恢复](server-log-exchange.md) —— 攻击链涉及邮件投递时，邮件头里的路径信息与服务器侧日志能互相印证。

<a id="section-37"></a>

### 工具与判据

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **判断「日志被清理过」需要它的方法**。字段数不一致、序号断层、文件体积远小于相邻日，都要落到它的分层定级上。
- [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— 站点配置被改但没有备份副本时，从日志区回放配置变更的思路。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 多源时间合并的通用方法，跨平台适用。
<a id="section-38"></a>

## 七、命令速查

```bash
# ===== 定位与提取（★ *.log* 覆盖 IIS6 / _x 后缀 / .gz 归档）=====
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'LogFiles/W3SVC[0-9]+/.*\.log.*$' /work/filelist.txt
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/u_ex241114.log
sha256sum /evidence/u_ex241114.log
head -4 /evidence/u_ex241114.log       # #Software 判版本，#Fields 判字段顺序
grep -c '^#Fields:' /evidence/u_ex241114.log   # >1 = 当天配置被改过
ls -l /evidence/W3SVC2/                # ★ 体积异常 = 截断线索

# ===== 运行风险打分器（脚本见 3.2，纯标准库）=====
python3 w3c_risk.py /evidence/W3SVC2 -n 20 --tz +8 -o /evidence/risk.csv
# --tz 是服务器本地时区相对 UTC 的偏移（国内 +8）；--min 抬高可只看高危
# [WARN] 字段数不一致 = 截断线索；规则命中统计用于判断该站点的攻击类型分布

# ===== 逐条人工复核 =====
awk '$1=="2024-11-14" && $2=="03:14:33"' /evidence/u_ex241114.log   # 原始行
grep -n ' /admin/login.aspx ' /evidence/u_ex241114.log | tail -20     # 同路径全部请求
awk '$10=="45.83.12.9" && $15=="200"' /evidence/u_ex241114.log        # 该 IP 的所有 200

# ===== 聚合统计 =====
awk '!/^#/ {print $10}' /evidence/u_ex241114.log | sort | uniq -c | sort -rn | head -20
awk '!/^#/ {print $10, $15"/"$16"/"$17}' /evidence/u_ex241114.log | sort | uniq -c | sort -rn | head -30
# ★ 状态码三元组分布：404/7=扩展名被拒、404/14=URL 过长、500/0=应用异常非文件系统问题
awk '!/^#/ {split($2,t,":"); if (t[1]>=16 && t[1]<=21) print $10}' /evidence/u_ex241114.log \
    | sort | uniq -c | sort -rn | head        # UTC 16-21 时 = 本地 00:00-05:00

# ===== 时延离群检测（找时间盲注）=====
awk '!/^#/ && $18+0>5000 {print $2, $10, $18, $7}' /evidence/u_ex241114.log | sort -k3 -rn | head
# ★ time-taken 单位是毫秒；同路径正常时延做基线对比，>5000ms 需人工确认
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 服务器取证 — Web 访问日志深度分析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Web 访问日志深度分析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
