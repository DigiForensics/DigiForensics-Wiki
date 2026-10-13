---
title: "IIS 配置与 W3C 日志"
slug: "server-log-iis"
canonical: "https://www.digiforensics.cn/wiki/server-log-iis"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["日志分析"]
---

# IIS 配置与 W3C 日志

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/server-log-iis)

<a id="section-1"></a>

## 一、概述

**IIS 取证有两个必须先解决的问题**：这台服务器上有哪些站点、各自对应磁盘上哪个目录；以及这些站点的访问日志实际记录了哪些字段、按什么顺序排列。

第二个问题是新手最容易翻车的地方。W3C 日志看起来是"空格分隔的一行文本"，很容易让人写死列索引去取字段。

**但 IIS 的字段集合与顺序是可配置的**——不同版本、不同管理员、不同时间点都不一样。

任何写死下标的解析器遇到非默认配置都会**静默给出错误结果**：把 IP 当成用户名、把状态码当时延。更糟的是它**不报错**，错误会一路流进取证报告。

换句话说，「这条日志说了什么」这个问题，在 IIS 上必须先答「这份日志的字段表是什么」才能回答。

**在取证流程中的位置**：本篇属于**分析环的解析基座层**，产出两件东西：**站点拓扑表**与**可复用的日志解析器**。

它不产出结论，而是决定后面每一篇的统计数字是否成立。

上游依赖 [Windows 服务器取证工件地图](server-log-server-artifact-map.md) 提供的工件边界与 [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md) 的通道检查；

下游直接接上 [Web 访问日志深度分析](server-log-web-access-log-analysis.md) 的归因统计与 [Web 攻击痕迹还原](server-log-web-attack-trace-reconstruction.md) 的主机侧印证。

**涉及的证据形态**（具体到文件与字段，不是"访问日志"这种大类）：

| 形态 | 路径 / 字段 | 取证意义 |
|---|---|---|
| **IIS 7+ 全局配置** | `%windir%\system32\inetsrv\config\applicationHost.config`（XML 明文） | ★★★★★ 站点拓扑的唯一权威来源 |
| **配置备份** | `applicationHost.config.bak` | ★★★★★ **改配置前的版本，diff 即篡改证据** |
| **IIS 6 配置** | `%windir%\system32\inetsrv\MetaBase.xml` + `MBSchema.xml` | ★★★★★ **已经是 XML 明文**，不是二进制 |
| **IIS 4/5 配置** | `MetaBase.bin` | ★★ **二进制且已不含有效配置**，仅占位 |
| **站点配置** | `C:\inetpub\wwwroot\<site>\Web.config`、`App_Offline.htm` | ★★★★★ 含 `machineKey`，攻防焦点 |
| **访问日志** | `C:\inetpub\logs\LogFiles\W3SVC<n>\u_ex*.log` | ★★★★★ 逐请求记录 |
| **`#Fields` 行** | 文件头部 | ★★★★★ **解析的唯一依据，绝不能写死列索引** |
| **关键字段** | `sc-status`/`sc-substatus`/`sc-win32-status` 三元组、`time-taken`、`cs(User-Agent)` | ★★★★★ |
| **自定义字段** | `#Fields` 末尾多出的 `x-forwarded-for` 一列，文件名带 `_x` | ★★★★ 穿透 CDN 的取证手段 |

> ★ **站点 ID 的三个要点**：① 日志目录 `W3SVC2` 里的 `2` 就是 `id="2"`，**与站点名无关**；② ID 由创建顺序决定，站点删过会留下 **ID 空洞**（1、3 存在而 2 不存在），这本身就是站点被删过的线索，且**空洞站点的历史日志常常仍留在磁盘上**；③ `logFile/directory` 可配到任意路径，实际落点须以站点配置的 `logFile/directory` 为准。不读配置就按 `C:\inetpub\logs` 找，会完全找不到日志。

IIS 版本与配置格式（`MetaBase.xml` 还是 `applicationHost.config`）；哪个站点 ID 对应哪个域名与物理路径；日志实际记录了哪些字段、按什么顺序；某次请求的真实状态是"未找到"还是"MIME 拒绝"（三元组才能区分）。

自定义字段是否存在——这一条决定你能否穿透 CDN 取到真实客户端 IP。某个 `W3SVC<n>` 目录里是否藏着已删站点的历史日志，也在答案里。

**请求体与响应体内容**（W3C 不记录）；某次请求是否真的执行了后端代码（`200` 也可能是错误页）；`time-taken` 里有多少是网络耗时（它含在内）。

IIS 4/5 的二进制 `MetaBase.bin` 里的历史配置也拿不到——不含有效数据，不要在这上面浪费时间。至于 `sc-substatus` 之外的静默失败路径，日志根本没记。

**读者前提**：需要 HTTP 请求/响应结构、XML 基础、Windows 服务与配置路径。

**时区是本篇最容易被忽略的硬前提**：W3C 的 `date`/`time` 是 **UTC**，事件日志是**本地时间**。UTC+8 环境直接比对会整体错 8 小时，足以把"先登录后访问"颠倒过来，详见 [00 篇的 4.2 时间基准](server-log-server-artifact-map.md)。

建议严格按 [3.1 第 1 步](#section-10) → [3.2 第 2 步](#section-11) → [3.3 第 3 步](#section-12) → [3.4 第 4 步](#section-13) 的顺序执行。跳步会让后面所有统计静默失真。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 IIS 版本差异：配置体系的两代更替

**这是 IIS 取证第一个必须确认的事实**——配置在哪、什么格式，完全取决于版本。

| 版本 | 配置文件 | 格式 | 站点标识 |
|---|---|---|---|
| **IIS 6.0**（Win2K3） | `%windir%\system32\inetsrv\MetaBase.xml` + `MBSchema.xml` | **XML 明文** | 数字 Site ID |
| IIS 4/5.0 | `%windir%\system32\inetsrv\MetaBase.bin` | **二进制**（难解析） | 数字 Site ID |
| **IIS 7.0+**（Win2008+） | `%windir%\system32\inetsrv\config\applicationHost.config` | **XML 明文** | 字符串 `W3SVC<n>` |
| IIS 7.0+ 缓存 | `.../config\apphost.config` | 二进制缓存 | — |

**三条关键推论**：

1. **IIS 6.0 已经是 XML 明文**（IIS 4/5 的 `MetaBase.bin` 才是二进制）。见到 `MetaBase.xml` 说明该机是 IIS 6 或由 IIS 6 迁移而来，见到它本身不构成"老旧系统"的证据。
2. IIS 6.0 目录里可能还残留 `MetaBase.bin`，但它不含有效配置——那是向后兼容占位文件。"备份 `MetaBase.bin` 即可"是错的，必须备份整个 `inetsrv` 目录。
3. **IIS 7+ 引入自动配置备份**：每次改配置，旧版本存为 `applicationHost.config.bak`。**取证必须一并提取。**

两代配置读站点映射的关键属性完全不同。

IIS 6 的站点是一个 `locsection`，节点名 `W3SVC/1` 里的 `1` 就是 Site ID，绑定、目录、日志路径分别存在 `ServerBindings` / `Root` / `LogFileDirectory` 三个 `property` 里。

IIS 7+ 则是一个 `site` 元素（注意 `logFormat` 是 `logFile` 的**属性**而非子元素）：

```xml
<site name="digiforensics-site" id="2" serverAutoStart="true">
  <application path="/">
    <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\digiforensics-site" />
  </application>
  <binding protocol="https" bindingInformation="*:443:digiforensics.example.com" />
  <logFile logFormat="W3C" enabled="true">
    <directory>D:\IISLogs\W3SVC2</directory>
  </logFile>
</site>
```

对应的 IIS 6 写法是 `<locsection name="W3SVC/1">` 内含 `<property name="Root" type="string" value="C:\inetpub\wwwroot\digiforensics-site" />` 等（完整解析见 3.3）。

这三种属性的名字两代完全不通用。写解析脚本时不要试图用同一段逻辑兼容。

> **★ 站点 ID 的三个要点**：
> 1. 日志目录名 `W3SVC2` 里的 `2` 就是 `id="2"`，**与站点名无关**——`id="2"` 完全可能叫 `Finance`。
> 2. ID 由创建顺序决定，站点删过会留下 **ID 空洞**（1、3、4 存在而 2 不存在），这本身就是站点被删过的线索。
> 3. `logFile/directory` 可配到任意路径，不读配置就按 `C:\inetpub\logs` 找，会完全找不到日志。

<a id="section-4"></a>

### 2.2 ★ W3C 日志的文件结构：先读 `#Fields`

**这是本篇最核心、也最容易出错的知识点。**

W3C 日志是 ASCII 文本，**一行一条 HTTP 请求记录**，文件开头有几行以 `#` 开头的**指令行**。

`#Software:`（软件版本，**判断 IIS 版本**）、`#Version:`（格式版本，通常 `1.0`）、`#Date:`（**判断是否被轮转/重建**）、`#Remark:`（任意注释，应忽略），以及最关键的 `#Fields:`（字段名称与顺序，解析日志的唯一依据）。

```
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2024-11-14 00:00:00
#Fields: date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken cs-bytes cs-host
2024-11-14 03:12:07 DIGIFORENSICS-WEB 10.10.0.5 GET /uploads/up.aspx t=1 443 - 185.220.101.34 - - 200 0 0 1178 66 digiforensics.example.com
```

> ★ 第一条硬规则：任何解析器都必须先读 `#Fields` 行，绝不能写死列索引。 IIS 管理器里勾选"选择字段"就能改集合，管理员、运维脚本、模板站点都可能改过。

<a id="section-5"></a>

### 2.3 ★★ IIS 7+ 的默认字段顺序（本文核心）

IIS 7 及以上全新安装的 W3C 日志，**默认选中字段**的顺序是：

```
#Fields: date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port
         cs-username c-ip cs(User-Agent) cs(Referer)
         sc-status sc-substatus sc-win32-status time-taken cs-bytes cs-host
```

细节一：`cs-username` 之后直接是 `c-ip`，中间没有 `cs-domain`。（`… s-port  cs-username  c-ip  cs(User-Agent) …`）

很多资料（尤其从 IIS 6 时代文档转述来的）会让人以为 `cs-username` 后面是 `cs-domain`（客户端域名），然后才是 `c-ip`。

事实是：W3C 格式的字段列表里没有 `cs-domain` 这个标准字段。

按 `cs-username → cs-domain → c-ip` 去解析，会把 `c-ip` 的值错认成域名，并且**后续所有字段整体错位一列**。

若日志里真出现 `cs-domain`，那一定是管理员配置的[自定义字段](#section-7)，不是标准字段。

**细节二：字段前缀的四段式含义。** `s-` = server（服务器侧）、`c-` = client（客户端侧）、`cs-` = client **s**ent（客户端发给服务器的）、`sc-` = **s**ent to **c**lient（服务器返回给客户端的）。括号形式 `cs(User-Agent)`、`cs(Referer)`、`cs(Cookie)` 同样遵循此规则。

**细节三：IIS 6 的字段顺序不同。** IIS 6.0 默认字段与 IIS 7+ 基本一致但**结尾无 `cs-host`**；而在**最简配置**下（只勾必需项）会短得多：

```
#Fields: date time cs-username c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-substatus sc-win32-status
```

> **绝不能跨版本套用解析器**：IIS 6 最简配置里 `sc-status` 在索引 7，IIS 7+ 默认配置里在索引 14。**同一解析器在两种日志上结果完全不同，且不报错。**

<a id="section-6"></a>

### 2.4 关键字段的判读要点

| 字段 | 判读要点 |
|---|---|
| `date` / `time` | **★ 是 UTC，不是服务器本地时间**。国内服务器常为 UTC+8，与事件日志比对会整体错 8 小时 |
| `cs-uri-stem` / `cs-uri-query` | 请求路径（不含查询串，**部分版本把 `/` 记成 `\`**）/ 查询串（**不带前导 `?`**，无则 `-`） |
| `cs-username` | 认证用户，匿名为 `-`。**出现非常规账号是提权信号** |
| `c-ip` | 客户端 IP。**在 CDN/反代后面这是代理 IP，不是真实来源** |
| `cs(User-Agent)` | **空格被替换为 `+`**，非打印字符也替换为 `+`。还原时 `+` → 空格 |
| `sc-status` | HTTP 状态码（详见 [03](server-log-web-access-log-analysis.md)） |
| `sc-substatus` | **IIS 细分子状态**。`404.0`=资源不存在，`404.1`=站点不存在，`404.3`=MIME 类型限制 |
| `sc-win32-status` | **Windows 系统错误码**，`0` = 成功。`2`=找不到文件、`3`=找不到路径、`5`=拒绝访问 |
| **`time-taken`** | **★ 单位是毫秒**，从收到第一个字节到最后发送完，**含网络耗时** |
| `cs-bytes` / `sc-bytes` | 收/发字节数，**默认不勾选**，未开启时不存在这两列 |

> **`time-taken` 的两个坑**：**单位是毫秒不是秒**（`1841` = 1.8 秒）；**它包含网络耗时**——大文件下载时反映的是客户端网速。判断应用性能应只看动态请求（`.aspx`/`.ashx`/API）。

<a id="section-7"></a>

### 2.5 自定义字段与 `_x` 后缀

管理员可添加**自定义字段**（Custom Field），从请求头/响应头/服务器变量取值，最常见用途是记录 `X-Forwarded-For` 以穿透 CDN。

配了之后 `#Fields` 末尾会多出 `x-forwarded-for` 一列。

| 事项 | 说明 |
|---|---|
| **文件名会变** | 配置自定义字段后，IIS 写出的新日志文件名加 `_x` 后缀（`u_ex241114_x.log`），老文件保持原样 |
| **追加在末尾** | 自定义字段**追加在 `#Fields` 列表末尾**，因此不会挤掉 `cs-username`→`c-ip` 的相对顺序 |
| **不配置就不存在** | 没配 `cs(Cookie)`、`cs-host`、`cs-bytes` 时，这些字段**根本不在 `#Fields` 里** |
| **★ 同一文件内可能变更** | IIS 日志有缓冲写入（`flushByEntryCountW3CLog` 按 64K 条目批量刷新）。若管理员当天改了配置，**同一文件里会出现两行 `#Fields`**，前后段顺序不同 |

> ★ 解析器必须每遇到一次 `#Fields` 就重新读取，不能只在文件开头读一次。 这正是本文解析器的核心设计。

<a id="section-8"></a>

### 2.6 日志轮转与 `W3SVC<n>` 目录

**默认按天轮转**，文件名 `u_exYYMMDD.log`（`YYMMDD` = 两位年 + 月 + 日）：

| 项目 | 说明 |
|---|---|
| **目录名** | `C:\inetpub\logs\LogFiles\W3SVC<站点ID>\`（**可配到别处**） |
| **IIS 7+ 文件名** | `u_ex241114.log`（配自定义字段时为 `u_ex241114_x.log`） |
| **IIS 6 文件名** | `ex241114.log`（**无 `u_` 前缀**） |
| **轮转粒度** | `Daily`（默认）/ `Hourly` / `Weekly` / `Monthly` / `MaxSize`（按大小，默认 20 MB） |
| **IIS 7.5+ 旧格式** | 单个滚动文件 `u_ex.log`（不按天分）；部分部署另有 `.gz` 归档 |
| **IIS 6 默认路径** | `%systemroot%\system32\LogFiles\W3SVC<n>\` |

> ★ 取证必须用通配符 `*.log*` 而非 `u_ex*.log`：会漏掉 IIS 6 的 `ex*.log`、带 `_x` 的自定义字段文件、`.gz` 归档，以及被改到非默认目录的日志。

W3C 日志只覆盖 HTTP 请求这一条线。

站点被改配置、被停用、服务进程崩溃这些动作落在 `evtx` 里。

按事件 ID 抽取并与访问日志合并成同一条时间线的方法见[事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确认 IIS 版本与配置格式

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp\Components' | Select-Object MajorVersion, MinorVersion
Get-ChildItem C:\Windows\System32\inetsrv\config\applicationHost.config*,
             C:\Windows\System32\inetsrv\MetaBase.* | Select-Object FullName, Length, LastWriteTimeUtc
# 最可靠：直接从日志的 #Software 行确认（升级后残留旧日志时以它为准）
Get-Content D:\IISLogs\W3SVC2\u_ex241114.log -TotalCount 3
```

**验证**：`#Software` 版本与注册表 `MajorVersion` 不一致时（升级残留常见），**以日志自身版本为准**——解析行为由产生它的版本决定。

<a id="section-11"></a>

### 3.2 第 2 步：读 `#Fields`，建立字段映射

**这一步是全部后续分析的前提。**

```powershell
# 2.1 每个日志文件的 #Fields（★ 同一文件可能有多行，配置变更会产生新的）
Get-ChildItem D:\IISLogs\W3SVC2\*.log | ForEach-Object {
  Select-String -Path $_.FullName -Pattern '^#Fields:' |
    Select-Object @{n='File';e={$_.Filename}}, LineNumber, Line } | Format-List

# 2.2 人工核对列数与关键字段索引
$fields = ((Select-String -Path $log -Pattern '^#Fields:').Line -replace '^#Fields:\s*','') -split '\s+'
$data   = (Get-Content $log | Where-Object { $_ -notmatch '^#' } | Select-Object -First 1)
"#Fields=$($fields.Count) 数据行=$(($data -split '\s+').Count) " +
"cs-username=$([array]::IndexOf($fields,'cs-username')) c-ip=$([array]::IndexOf($fields,'c-ip'))"
```

**验证**：数据列数必须等于 `#Fields` 列数。**不等就是两条线索之一**——日志被截断（见 [04](server-log-web-attack-trace-reconstruction.md)），或该行正好在字段配置变更的边界上。

<a id="section-12"></a>

### 3.3 第 3 步：还原站点拓扑

```powershell
Get-Website | Select-Object Name, ID, State, PhysicalPath,
  @{n='Bindings';e={($_.Bindings.Collection.bindingInformation) -join '; '}} | Format-List
Get-WebConfiguration -PSPath 'IIS:\' -Filter 'system.applicationHost/sites/site/application' |
  ForEach-Object { [pscustomobject]@{ Site=$_.Attributes['siteName']; AppPath=$_.Attributes['path']
    VDir=($_.SelectNodes('virtualDirectory') | ForEach-Object { $_.Attributes['physicalPath'] })
    AppPool=$_.SelectSingleNode('applicationPool').Attributes['applicationPoolName'] } } | Format-List
# 读出「域名 ↔ 物理路径 ↔ 站点ID ↔ 应用池」的完整映射
```

**IIS 6（`MetaBase.xml`）**——XML 用 Python 解析更直接：

```python
import xml.etree.ElementTree as ET

for sec in ET.parse(r"C:\evidence\MetaBase.xml").getroot().iter("locsection"):
    name = sec.get("name") or ""             # IIS 6 节点名形如 'W3SVC/1'
    if name.startswith("W3SVC/"):
        p = {x.get("name"): (x.get("value") or "") for x in sec.findall("property")}
        print(f"[{name.split('/')[1]}] {p.get('ServerBindings')} | {p.get('Root')} | {p.get('LogFileDirectory')}")
```

**验证**：配置读出的 `LogDir` 必须与磁盘上实际存在的 `W3SVC<n>` 目录对得上。**对不上有两种情况**：配置改了但 IIS 未重启生效，或日志目录被手工搬走——两种都要在报告中说明。

<a id="section-13"></a>

### 3.4 第 4 步：运行 W3C 解析器

下面的脚本**不写死任何字段顺序**，每遇一次 `#Fields` 就重新解析，并标注 `'...'` 截断与 `-` 缺失值。**已实测可运行**（Python 3.6+，无第三方依赖）。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IIS W3C 解析器。核心：字段顺序不写死，每遇一次 #Fields 就重新解析。
用法: parse_w3c.py <文件或目录...> [-o out.csv]"""
import sys, os, csv, glob
from datetime import datetime, timezone

def to_utc(r):
    """date+time 合成 UTC datetime（W3C 的 time 是 UTC，不是服务器本地时间）。"""
    d, t = r.get("date"), r.get("time")
    try:
        return datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def parse_w3c(path):
    """解析单个 W3C 文件，返回 (元信息, 记录列表)。"""
    meta, fields, changes, rows = {}, None, [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for ln, line in enumerate(fh, 1):
            line = line.rstrip("\r\
")
            if line.startswith("#"):                    # 指令行 "#Key: value"
                key, _, val = line[1:].partition(":")
                key, val = key.strip().lower(), val.strip()
                if key == "fields":                     # ★ 字段顺序只由 #Fields 决定
                    fields = val.split()
                    changes.append((ln, list(fields)))
                elif key in ("software", "version", "date"):
                    meta[key] = val
                continue
            if not line:
                continue
            if fields is None:                          # 数据行早于 #Fields = 日志被重写
                print(f"[WARN] {path}:{ln} 数据行早于 #Fields，跳过", file=sys.stderr)
                continue
            parts = line.split()   # W3C 值内无空格（UA 空格已替换为 '+'），无参 split 安全
            if len(parts) != len(fields):
                print(f"[WARN] {path}:{ln} 字段数 {len(parts)} != #Fields {len(fields)}",
                      file=sys.stderr)
            rec = dict(zip(fields, parts))              # 字段数不符时左对齐 = 错位症状可见
            for k, v in rec.items():
                if v == "-":                           # '-' 是 IIS 的缺失值占位符
                    rec[k] = None
            if "..." in rec.values():                   # 超 4096 字节的字段被截成 '...'
                rec["_truncated"] = True
            rec.update(_ts=to_utc(rec), _file=os.path.basename(path), _line=ln)
            rows.append(rec)
    meta.update(path=path, fields=fields, fields_changes=changes)
    return meta, rows

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 1
    out_csv, files = None, []
    if "-o" in args:
        i = args.index("-o")
        out_csv, args = args[i + 1], args[:i] + args[i + 2:]
    for a in args:                                     # 目录参数自动展开为 *.log
        files += sorted(glob.glob(os.path.join(a, "*.log"))) if os.path.isdir(a) else [a]
    if not files:
        print("[ERR] 未找到日志文件", file=sys.stderr)
        return 1

    allrows, cols, dist, tt = [], [], {}, []
    for p in files:
        meta, rows = parse_w3c(p)
        print(f"[+] {os.path.basename(p)}  软件={meta.get('software')} 记录={len(rows)}",
              file=sys.stderr)
        if len(meta["fields_changes"]) > 1:            # 同一文件内改过日志字段配置
            print(f"    [注意] #Fields 变更 {len(meta['fields_changes'])} 次，已分段按各自顺序解析",
                  file=sys.stderr)
            for ln, fs in meta["fields_changes"]:
                print(f"      行 {ln}: {' '.join(fs)}", file=sys.stderr)
        cols += [f for f in (meta["fields"] or []) if f not in cols]
        for r in rows:
            k = r.get("sc-status") or "-"             # 状态码分布 = 最快的错位检测器
            dist[k] = dist.get(k, 0) + 1
            if r.get("time-taken", "").isdigit():
                tt.append(int(r["time-taken"]))
        allrows += rows

    print("\
状态码分布: " + "  ".join(f"{k}:{dist[k]}" for k in sorted(dist, key=lambda x: (len(x), x))),
          file=sys.stderr)
    if tt:
        tt.sort()
        print(f"time-taken(ms): 最小={tt[0]} 中位={tt[len(tt)//2]} 最大={tt[-1]} 共{len(tt)}",
              file=sys.stderr)

    if out_csv:
        with open(out_csv, "w", newline="", encoding="utf-8-sig") as fh:   # utf-8-sig 防 Excel 乱码
            w = csv.DictWriter(fh, fieldnames=["_ts", "_file", "_line"] + cols,
                               extrasaction="ignore")
            w.writeheader()
            for r in allrows:
                r = dict(r)
                r["_ts"] = r["_ts"].isoformat() if r["_ts"] else ""
                w.writerow(r)
        print(f"[+] 已写出 {out_csv}（{len(allrows)} 行）", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

> 对字段数不符的行，脚本用 `dict(zip(...))` 左对齐，让尾部字段自然缺失。 这是**有意设计**——被截断的记录会因此呈现"状态码错位"的典型症状（`sc-status` 被读成 `3`），正是 2.3 节所述"静默给出错误结果"的实证。

**运行**（`stderr` 输出示例）：

```bash
python3 parse_w3c.py D:/evidence/W3SVC2 -o D:/evidence/w3c.csv
```
```
[+] u_ex241114.log  软件=Microsoft Internet Information Services 10.0 记录=6
    [注意] #Fields 变更 2 次，已分段按各自顺序解析
      行 4:  date time s-computername s-ip cs-method ... cs-host
      行 10: date time s-computername s-ip cs-method ... cs-host x-forwarded-for
状态码分布: 200:4  201:1  404:1
time-taken(ms): 最小=8 中位=56 最大=1841 共6
[+] 已写出 D:/evidence/w3c.csv（6 行）
```

| 验证 | 判据 |
|---|---|
| 字段数一致 | 每行数据 `split()` 后的列数 == `#Fields` 列数（脚本已自动告警） |
| 抽样人工核对 | 抽 3–5 行，用 3.2 的索引法确认 `sc-status` 位置的确实是 `200`/`404`/`500` |
| **状态码分布合理性** | 正常 W3C 的 `sc-status` 只能是 100–599。若分布里出现 `1841` 之类的值，说明字段错位了 |

> **★ 状态码分布是最快的错位检测器**。若出现非 HTTP 状态码的值，立刻回去检查 `#Fields`——比逐行核对快得多。

---
<a id="section-14"></a>

## 四、常见陷阱

W3C 扩展日志格式有一个容易被忽视的特性：**它把字段表放在文件里，而不是靠文档约定**。

这既是它的健壮之处，也是它最大的坑——解析失败时不会报错，只会静默地给你错误的数据。

本章按**字段解析、时间处理、路径与编码、字段语义** 四组拆开。

<a id="section-15"></a>

### 4.1 字段解析：列索引是最大的坑

<a id="section-16"></a>

#### 陷阱 1：写死列索引取字段

**现象**

按某个顺序硬编码字段位置：第 9 列是客户端 IP，第 14 列是状态码。
解析在目标机器上跑通了，报告也出了。

**原因**

W3C 格式的字段顺序**由站点配置决定**，而配置是可选项。
IIS 允许在日志里勾选任意字段子集，默认配置只是其中一种。
默认顺序下客户端 IP 恰好在某一列、状态码在另一列，
但**改任何一个勾选项，后续所有字段的索引都会整体移位**。

而这个错误有一个恶劣特性：**解析脚本不会报错**。
它会顺利地从错误的列里取出值——从「引用来源页」那一列取出了「状态码」，
从状态码那一列取出了字节数，取出来的值都「看起来合理」，
因为 HTTP 请求里确实有这些形态的数据。

**影响**

整个分析建立在一列错位一整行的数据上。

更危险的是它**不会自我暴露**——报告里的统计、筛选、时间线全都自洽，但每一条都是错的。复核时如果没有人逐字段核对，会一路错到底。

**核查**

永远先读文件里的 `#Fields` 行，按它解析。 这是唯一可靠的做法。
标准写法是把两行配对成字典：

```python
fields = None
rows = []
with open(log_path, 'r', encoding='utf-8', errors='replace') as fh:
    for raw in fh:
        line = raw.rstrip('\r\
')
        if line.startswith('#'):
            if line.lower().startswith('#fields:'):
                fields = line.split(':', 1)[1].split()
            continue
        if not line.strip():
            continue
        parts = line.split()          # 无参 split，自动处理连续空白
        if fields and len(parts) != len(fields):
            # 字段数不一致的行单独处理，不静默丢弃
            anomalies.append((line, len(parts), len(fields)))
            continue
        rows.append(dict(zip(fields, parts)))
```

**用字典而不是用索引**。这样即使字段表变化，解析结果依然正确。

字段数不一致的行要单独收集并报告，不能静默跳过——原因见陷阱 6。

<a id="section-17"></a>

#### 陷阱 2：以为 `cs-username` 后面是 `cs-domain`

**现象**

按 W3C 字段的常见列表推理，认为 `cs-username` 后面紧跟 `cs-domain`，
解析时按这个顺序取值。

**原因**

W3C 格式的字段列表里根本没有 `cs-domain` 这个字段。
在 IIS 7 及以后的实际输出中，`cs-username` 后面直接是 `c-ip`——
中间没有域名字段。域的概念在其他格式里有，但 W3C 格式不输出它。

这跟陷阱 1 是同一个根因的另一面：**凭格式惯例推理，而不是读字段表。**

**影响**

整行错位。域信息在这个格式里本来就取不到，
如果确实需要域，必须从认证日志或应用日志去取，不能在这里硬凑。

**核查**

同样靠 `#Fields` 行。补充一条判断规则：

> **如果 `#Fields` 里出现了文档标准字段列表之外的字段名，
> 说明站点启用了自定义日志字段。**
> 此时报告里要注明「该站点使用自定义日志字段集，
> 字段定义见文件内 `#Fields` 行，字段语义需结合站点文档确认」，
> 不要假设自定义字段的含义。

<a id="section-18"></a>

#### 陷阱 3：只在文件开头读一次字段表

**现象**

在文件里找到第一行 `#Fields`，解析整个文件时一直用这一份字段表。

**原因**

**IIS 的日志是缓冲写入的。** 如果站点在当天修改了日志字段配置，
那么同一天的这个文件里**会出现两行 `#Fields`**：
前半段是旧配置，后半段是改配置之后重新写入的。
两段的字段顺序不同。

只读第一行，就等于把后半段全部按旧顺序解析——
又是一次静默的整行错位。

**影响**

后半夜的记录全部错位。而这恰恰可能是关键时段。

**核查**

每遇到一行 `#Fields` 就重新解析，并统计它出现了几次。

解析逻辑是流式的：维护一个当前字段表，遇到新的字段表就替换，然后按当前表解析后续行。

同时把字段表变更次数作为**分析结果的一部分**报告出来：

> 站点 X 的日志文件 `u_ex20240318.log` 中出现 2 次 `#Fields` 声明，
> 变更时间为 14:22（依据系统日志中的配置变更记录）。
> 该文件在 14:22 之前的记录按字段集 A 解析，之后按字段集 B 解析。

**字段表在同一文件内变更这件事本身就是有价值的发现**——它说明站点配置在当天被改过，这个改动需要追查。

<a id="section-19"></a>

#### 陷阱 4：把 `sc-substatus` 和 `sc-win32-status` 混为一谈

**现象**

看到 `404.3`，认定为「文件路径不存在」，据此判断攻击者访问了
不存在的后台路径。

**原因**

IIS 的状态码是**三层结构**，三个字段各有含义：

- `sc-status`：HTTP 状态码（404）
- `sc-substatus`：IIS 自己的细分原因（3）
- `sc-win32-status`：底层 Win32 API 的错误码

`404.3` 中的 `3` 是 **IIS 层的细分原因**，它的官方含义是
**请求的扩展名没有有效的 MIME 类型映射**。
而「路径找不到」这个含义对应的是 `sc-win32-status` 的 `3`。

两个字段的数值空间完全独立，`3` 在两个字段里指向不同的事。

中文资料里把 `404.3` 说成路径找不到的相当常见，这个误解会一路传导到分析结论。

**影响**

把一次 MIME 配置问题误读成一次路径探测，
或者反过来，把真正的路径探测当成配置问题放过。

**核查**

**两个字段分开读、分开解释、报告里分列。** 在记录表格里它们必须是两列，不允许合并显示。

各取值的解读方向（用于排除误判，不必逐条背）：

- `sc-substatus` 指向**MIME 映射、处理程序、请求长度、扩展名黑名单**
  → 这些是站点配置层面的问题
- `sc-win32-status` 指向**文件是否存在、路径是否可访问、是否被拒绝**
  → 这些才是路径相关的信息

判断「是否存在针对路径的信息探测」，
必须看 `sc-win32-status` 那一列的分布，不能看 `sc-substatus`。

<a id="section-20"></a>

### 4.2 时间与单位

<a id="section-21"></a>

#### 陷阱 5：忘记时间戳是 UTC

**现象**

把日志里的 `date` 和 `time` 字段直接当作本地时间，
与 Windows 事件日志放在一起做时间线。

**原因**

W3C 格式的 `date`（`2024-03-18`）和 `time`（`14:22:31`）
**是 UTC 时间**，不带时区标识。本地环境通常是 UTC+8。

直接当本地时间用，所有记录都会**整体偏移 8 小时**。

而 8 小时的偏移足以颠倒事件顺序——「先登录后访问」会显示成「先访问后登录」。

**影响**

因果关系判断错误。整条时间线需要重做。

**核查**

**解析时就带上时区，不要留到最后再换算。**
正确做法是让解析器直接产出带时区的 datetime 对象：

```python
from datetime import datetime, timezone, timedelta

# 日志时间戳是 UTC，转成 UTC+8
LOCAL = timezone(timedelta(hours=8))
dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S")
dt = dt.replace(tzinfo=timezone.utc).astimezone(LOCAL)
```

在解析阶段就换算好，后续所有时间线比较都是同一基准，不会在某一步漏加偏移。

报告里必须写明：
`本文所有时间已统一为 UTC+8；IIS 原始日志为 UTC，已加 8 小时偏移。`

**验证方法**：拿一条你有把握的事件（比如系统启动时间）反查换算后是否与事件日志吻合。

<a id="section-22"></a>

#### 陷阱 6：把 `time-taken` 当秒

**现象**

看到 `time-taken=5210`，判定这次请求耗时 87 分钟，
进而认为「这个请求挂了很久，中间发生了什么」。

**原因**

**`time-taken` 的单位是毫秒。** `5210` 是 5.2 秒。

这个字段是 IIS 记录的服务端处理耗时，取值范围通常在几十到几秒之间。把毫秒当秒，会得到一个量级完全错误的数字。

**影响**

时间线分析出现荒谬的数值。如果据此判断「这个请求跨越了很长时间，期间可能有其他活动」，结论方向完全错误。

**核查**

**在解析代码里就把单位固定下来**，让下游无法误用：

```python
# time-taken 单位是毫秒，转换为秒并保留一位小数
taken_ms = int(row['time-taken'])
taken_s = round(taken_ms / 1000, 3)
```

在报告的表格与图里统一用**秒**并标注单位。
如果要设置「慢请求」的筛选阈值，
先确认阈值是按毫秒还是秒设计的——
很多教程里的 `> 5000` 是**毫秒**，即 5 秒。

同时注意这个字段有上界：超大值通常意味着
连接被中断或超时，不代表真的处理了那么久。

<a id="section-23"></a>

#### 陷阱 7：不做字段数一致性检查

**现象**

解析脚本里对每行做 `dict(zip(fields, parts))`，
遇到字段数不一致的行，`zip` 会**静默截断到较短的那个**。

**原因**

这正是最危险的失败模式：**不报错，数据还在，但被截断了。**

截断发生在什么时候？请求在写入过程中被中断（连接断开、服务器异常、磁盘写满）时，最后一行往往不完整。

此时：行末缺字段 → `zip` 丢弃多余部分，已解析的字段是**正确的**；行首缺字段（不太可能，但格式异常时会有）→ 后面全部错位。

更常见的是：日志行里某个字段值本身**包含空格**（比如用户代理字符串、查询串里有空格或 `+`），导致按空白切分得到的片段数**多于**字段数。这时 `zip` 截断，行为记录被切掉一截。

**影响**

**攻击记录凭空消失。** 一条被截断到只剩前几个字段的记录，如果状态码那一列正好被截掉，这条记录就会在状态码筛选里消失。

分析结论会说「没有相关记录」，而记录其实存在。

**核查**

把字段数不一致的行单独收集，作为分析结果报告出来，而不是丢弃。

```python
if len(parts) != len(fields):
    anomalies.append({
        'line_no': line_no,
        'got': len(parts), 'want': len(fields),
        'raw': line[:200],
    })
    continue        # 不进主数据集，但要计数并报告
```

在报告里写：

> 本次解析 N 行，其中 M 行字段数与字段表不一致（占 P%），
> 主要原因为查询串中含空格导致切分片段数偏多。
> 这 M 行已单独提取并人工复核，其中 K 行包含与本次分析相关的请求，
> 已单独列入发现清单。

被丢弃的数据必须报告丢弃了多少、为什么丢弃、复核结果如何。 静默丢弃是日志分析里最不可接受的行为。

<a id="section-24"></a>

### 4.3 路径与编码处理

<a id="section-25"></a>

#### 陷阱 8：忘记查询串的 URL 编码

**现象**

写规则匹配攻击特征，规则里用的是解码后的形式，
直接在日志的 `cs-uri-query` 字段上做匹配，一条都没命中。

**原因**

**W3C 格式记录的是 URL 编码后的原始形式。**

空格是 `%20`、`..` 的斜杠是 `%2f`、引号是 `%22`。直接拿解码后的特征串去匹配原始字段，**永远匹配不上**。

而且这不会报错——规则正常执行，只是零命中。

**影响**

一整类检测规则完全失效。**零命中会被误读为「未发现」**，而实际情况是「检测没跑起来」。

**核查**

**两个字段都要处理，而且处理方式不同**：

- `cs-uri-stem`（路径部分）和 `cs-uri-query`（查询串）→ 做 URL 解码
- `cs(User-Agent)` → 做 `+` 还原（见陷阱 9）

```python
from urllib.parse import unquote_plus, unquote

stem = unquote(row['cs-uri-stem'])
query = unquote_plus(row['cs-uri-query'])
```

**匹配时两种形式都要试**：解码后匹配一次，
原始字段再匹配一次。因为有些请求本身就是双重编码的。

更稳妥的做法是把两种形式都保留在数据结构里，
让下游的每条规则明确声明它匹配的是哪一种。

<a id="section-26"></a>

#### 陷阱 9：把用户代理里的 `+` 当成加号

**现象**

按空格切分用户代理字段，得到「Mozilla/5.0+(Windows+NT」这样被截断的值。

**原因**

W3C 格式对用户代理字段做了空格替换：空格变成 `+`。
这是这个格式的一个历史设计（早期为了保证字段内不含分隔符）。
所以 `Mozilla/5.0 (Windows NT ...)` 记录下来是
`Mozilla/5.0+(Windows+NT+...`。

后果是：**按空格切分这个字段是错的**——它本来就没有空格，切分会把整个字段当成一个值（这本身没错），但如果拿 `+` 去匹配加号特征就会出错。

**影响**

用户代理分析结果错误，规则失效。

**核查**

**用户代理字段用 `+` 还原为空格**，而不是按空格切分：

```python
ua = row['cs(User-Agent)'].replace('+', ' ')
```

注意这个 `+` 的语义**与查询串里的 `+` 无关**：查询串里 `+` 本身就是空格（表单编码的约定），所以查询串用 `unquote_plus`，用户代理用直接替换。

两个字段的处理方式不同，不要写成同一个函数。

同一个道理也适用于 `cs(Cookie)` 和 `cs(Referer)`——这几个字段里含空格的都做了同样的替换。如果站点启用了这些字段，都要按这个规则还原。

<a id="section-27"></a>

### 4.4 路径定位与配置

<a id="section-28"></a>

#### 陷阱 10：默认日志在系统盘

**现象**

到默认路径下找日志，报告写「该站点无日志文件」。

**原因**

日志目录是**可配置项**，在站点配置文件里有对应元素。

日志目录常因磁盘容量规划、审计合规、或避免日志占满系统盘而被改到数据盘或独立的日志卷。

路径猜错 = 结论无效。

**影响**

在错误的位置查找，得出「无日志」的结论，而实际日志好好地躺在另一个盘上。

**核查**

**从配置读路径。** 解析站点配置文件时，
日志相关配置在站点的 `logFile` 元素下，路径是 `directory` 属性。把它读出来，再去那个位置找文件。

流程上应该是：

1. 读站点配置 → 得到站点清单 + 每个站点的日志目录
2. 在各自的日志目录下用 `*.log*` 列出文件
3. 按修改时间排序，确认覆盖范围

**不要用「默认路径 + 常见变体」的试探方式**，那种方式既可能漏掉实际路径，也可能在错误的位置浪费时间。

<a id="section-29"></a>

#### 陷阱 11：把站点 ID 当成站点名

**现象**

在报告里写「对 W3SVC3 的分析显示……」，委托方看不懂这是哪个站点。

**原因**

站点 ID 是创建时分配的整数，与站点名没有可推导的关系。
委托方能对上号的前提是**你把映射关系说清楚**。

**影响**

报告的读者无法判断结论对应哪个业务。
在多站点环境里，这是个严重的可读性问题。

**核查**

先解析配置，建立 ID 到名称的映射表，并把表作为报告附件。
本文另一篇专门讲这个，这里只强调一点：
**分析开始前就把映射表做完**，
后续所有按 ID 组织的证据（不只是日志）都挂到对应的站点名下。

<a id="section-30"></a>

#### 陷阱 12：把 `c-ip` 当成真实客户端 IP

**现象**

站点在 CDN 后面，日志里的 `c-ip` 全是边缘节点地址，
分析时按这些 IP 统计访问来源。

**原因**

`c-ip` 记录的是**与 IIS 建立 TCP 连接的来源地址**。站点前面有 CDN 或反向代理时，这个地址就是代理节点。

**日志里根本没有真实客户端地址**，除非做了额外配置。

如果按这些节点 IP 做统计，得到的是「哪个边缘节点被访问最多」，而不是「哪个客户端访问最多」。

访问来源分析完全无效。而且更严重的是——**据此得出的行为判断全部指向了 CDN 节点**，可能把 CDN 自己的正常轮询行为误判为异常活动。

**影响**

错的不是数字，是分析对象——你以为在追客户端，其实在追 CDN 自己的流量。

**核查**

**先确认这个字段记录的是什么。** 判断依据：

1. 站点前面有没有反代层（从站点配置、CDN 侧记录、或从
   `c-ip` 的取值分布可以看出来——如果取值集中在少数几个地址上，
   基本可以确定是反代）
2. 如果有反代，检查反代是否配置了**转发真实来源**的头字段
3. 站点是否配置了**信任该头字段**（这一步很关键：
   这个头可以被客户端任意伪造，只有当确认它由受控的边缘层覆写时才可信）

三种结论三种写法：

- **未配置转发头** → `日志中不含真实客户端地址，
  本次分析的来源维度仅能定位到代理节点。
  真实来源需从代理侧日志获取。` 写进局限章节
- **配置了转发头且信任它** → 用该头字段作为客户端地址，
  并在报告里注明「该头由受控边缘层覆写」
- **配置了但信任配置可疑** → 只能作为参考，标注为「可能不准确」

<a id="section-31"></a>

#### 陷阱 13：只找一种命名的日志文件

**现象**

在日志目录下按一个模式匹配，报告写「已获取该站点全部访问日志」。

**原因**

日志文件的命名有多个历史形态（详细机制见本文另一篇），
而且可能被压缩、可能被改过路径、可能有残留的历史文件。
一个模式匹配不到全部。

**影响**

时间覆盖不全，而「已获取全部日志」这个表述让后面所有的阴性结论都失去了可信度。

比缺日志更糟的是那句「已获取全部」——它把缺失变成了不可见。

**核查**

在配置给出的实际路径下，用宽松模式递归列出全部文件，然后按修改时间排序，在报告里列出文件清单与各自的时间范围。清单要进附件。

写法示例：

> 本次分析 W3SVC3（站点名：X）目录下共 N 个日志文件：
> u_ex20240301.log 至 u_ex20240318.log（活跃，UTF-8）、
> ex20240201.log 至 ex20240228.log（IIS 6 时期残留，ANSI 编码）、
> u_ex20240301.log.gz 等 M 个压缩归档（已解压至工作副本）。
> 时间覆盖范围：2024-02-01 至 2024-03-18。

**注意编码差异**：不同年代的日志文件编码不同（ANSI 与 UTF-8），统一按 UTF-8 解析会得到乱码，导致字段切分出错。遇到乱码时要用对应编码重读。


<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 非默认日志路径与字段数不一致导致的记录消失

**场景**

查获一台 Windows Server 2012 R2（IIS 8.5，已从 IIS 6 迁移，但保留了历史日志），镜像 `DigiForensics.dd`（raw，500 GB，NTFS 起始扇区 2048），已关机。委托方要求查明"某天凌晨是否有人对站点发起攻击"。

这条路径值得先走，是因为本案有两个**会各自独立地让证据完全消失**的陷阱：一个在**读取层**（不知道日志在哪），一个在**解析层**（读到了但解错）。

两个都不处理，这台机器的日志会给出"那天没有任何攻击"的结论——而实际上攻击请求就躺在文件里。

**处置过程**

**第 1 步 · 确认版本、配置与日志头**

```bash
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'inetsrv/(config/applicationHost\.config(\.bak)?|MetaBase\.xml)$' /work/filelist.txt
# 只有 applicationHost.config 与 .bak，无 MetaBase.xml → IIS 7+，迁移已完成
icat -o 2048 /work/DigiForensics.dd <inode-config>     > /evidence/applicationHost.config
icat -o 2048 /work/DigiForensics.dd <inode-config.bak> > /evidence/applicationHost.config.bak
icat -o 2048 /work/DigiForensics.dd <inode-log>        > /evidence/u_ex241114.log
sha256sum /evidence/*
head -4 /evidence/u_ex241114.log
```

```
#Software: Microsoft Internet Information Services 8.5
#Version: 1.0
#Date: 2024-11-14 00:00:00
#Fields: date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken cs-bytes cs-host
```

**发现 1**：站点 `id="2"` 的 `logFile/directory` 是 **`D:\IISLogs\W3SVC2`**（不是默认 C 盘）。不读配置就按 `C:\inetpub\logs` 找日志，会完全找不到。

同时确认 `cs-username` 后紧跟 `c-ip`、**无 `cs-domain`**，字段数 **18**。

**第 2 步 · 运行解析器**

```bash
python3 parse_w3c.py /evidence/u_ex241114.log -o /evidence/w3c.csv
# [WARN] u_ex241114.log:9 行内容不完整（末尾 cs-host 被切断）
# [+] u_ex241114.log  软件=Microsoft Internet Information Services 8.5  记录=5
# 状态码分布: 200:3  201:1  404:1
```

**发现 2**：**第 9 行的末尾不完整**——`cs-host` 只写到 `78` 就结束了，后续内容缺失。**这正是"行完整性检查"的实际命中。**

**第 3 步 · 人工对齐定位异常行**

```bash
sed -n '9p' /evidence/u_ex241114.log
# 2024-11-14 05:23:02 DIGIFORENSICS-WEB 10.10.0.5 GET /admin/config.aspx - 80 - 185.220.101.34 sqlmap/1.8.2#stable - 404 3 0 12 78
```

把这一行的值与 `#Fields` 的 18 个名字**逐一对应**：

| 字段 | 值 | 说明 |
|---|---|---|
| `cs(User-Agent)` | `sqlmap/1.8.2#stable` | **不含空格**，不破坏切分 |
| `cs(Referer)` | `-` | 空 Referer |
| `sc-status` | **`404`** | **列位正确** |
| `sc-substatus` | `3` | — |
| `sc-win32-status` | `0` | — |
| `time-taken` | `12` | — |
| `cs-bytes` | `78` | — |
| `cs-host` | **缺失** | **行在此处被切断** |

**发现 3**：列位**没有错位**（`404` 正确落在 `sc-status`），但**行尾 `cs-host` 字段缺失**，说明这行记录**没有写完就被切断**。

这类"行尾截断"比"列错位"更危险：解析器读到 17 个值就会停，而若不做行完整性检查，这行会被当成一条字段数偏少但内容正常的记录。

它的 `c-ip` 与 `cs(User-Agent)` 都是有效值，**足以被计入 IP 统计和 UA 统计**——攻击者在 IP 维度会正常出现，却在状态码维度完全隐形。

**第 4 步 · 判断成因：截断**

```bash
ls -l /evidence/W3SVC2/
# -rw-r--r-- 15 Nov 01:02 u_ex241115.log   48210934
# -rw-r--r-- 14 Nov 01:03 u_ex241114.log      2143   ← ★ 仅 2.1 KB，其余 48 MB
```

**发现 4**：`u_ex241114.log` 仅 2.1 KB，相邻日期 48 MB。**这不是解析器的问题——是当天日志被截断了**，写入进行中被切掉，导致最后一行不完整。截断点正好落在 `sqlmap` 扫描请求上。

第 5 步 · 修正：把这条记录纳入统计，并标注来源为"人工对齐"

第 9 行经人工对齐后，`sc-status` 应读作 `404`。把它补回统计：

```bash
# 先数清"声明的字段数"，作为判定基准
grep '^#Fields:' /evidence/u_ex241114.log |
  awk '{print "声明字段数:", NF-1}'
# 声明字段数: 18

# 再数该行实际字段数
sed -n '9p' /evidence/u_ex241114.log | awk '{print "该行字段数:", NF}'
# 该行字段数: 17
```

**这一步本身也是一处需要说明的地方**：`cs(User-Agent)` 的值 `sqlmap/1.8.2#stable` 本身**不含空格**，所以按空格切分得到的 17 个值正好一一落在 `#Fields` 的前 17 个名字上（`404` 落在 `sc-status` 位）——少的是末尾那个 `cs-host`，不是中间某个字段被挤走。判定的关键不是"少了一个"，而是"少了哪一个、在哪一位"。

**因此对齐要靠语义、不是靠数数**：数出 17 与 18 只告诉你"这一行不完整"，不能告诉你"它缺的是最后一位"还是"它从中间开始整体错位了一格"。把 17 个值与 `#Fields` 的前 17 个名字逐一对应、**能对上**，才说明**没有整体错位**，只是**行尾被切**。结论的强度来自这个逐一对应过程，而不是来自"补了个字段"。

```bash
# 修正后的这条记录（人工对齐，来源须在报告中标注）
# 2024-11-14 05:23:02  c-ip=185.220.101.34  cs(User-Agent)=sqlmap/1.8.2#stable
#   cs-method=GET  cs-uri-stem=/admin/config.aspx  sc-status=404  time-taken=12
```

**修正后这条记录的状态码是 `404`**——**不是 200**。这个差别决定了后面整条攻击链的定性。

**结论**

| 结论 | 支撑 | 强度 |
|---|---|---|
| 站点 `id=2` 的日志在 **`D:\IISLogs\W3SVC2`**，非默认路径 | `applicationHost.config` 原文 | 强（配置原文） |
| 站点 `id=2` 使用 18 字段格式，**无 `cs-domain`** | `#Fields` 头 | 强 |
| 存在自动化 SQL 注入扫描 | 第 9 行 `cs(User-Agent)=sqlmap/1.8.2#stable`，`c-ip=185.220.101.34` | 强 |
| 该次扫描**未命中** | 人工对齐后 `sc-status=404`（文件不存在），非 200 | 强 |
| 当天 IIS 日志被截断 | 2.1 KB vs 相邻日 48 MB；末行内容在 `cs-host` 处被截断 | 强（**截断点 = 最后一条记录**） |
| 截断点在攻击请求处，构成刻意反取证 | 末行恰为 sqlmap 请求 + `applicationHost.config` 与 `.bak` 存在差异 | 强（见 [04](server-log-web-attack-trace-reconstruction.md)） |
| 是否有人利用成功 | **仅凭此日志无法判断** | **须查站点目录与事件日志** |

**本节能证明**：扫描行为存在、未命中、日志被截断。

**本节不能证明**：截断的**执行者**（可能是本机工具、可能是外部）、截断**之后**是否还有更多请求、该次扫描是否为某次成功利用的前奏。

**误判对照**

这个案例最容易出的错有两个，第二个是最典型的"**证据自己消失**"。

1. **按默认路径找日志**。判别方法**只有一个，而且必须最先做**：从 `applicationHost.config` 读 `logFile` 配置。`logFile` 有三个独立字段——`directory`（目录）、`fileName`（文件名模板）、`logFormat`（W3C/NCSA/自定义）。**任何一个都可以被改**。本案 `directory` 就是非默认的 `D:\IISLogs\W3SVC2`。若跳过这一步而在 C 盘找不到日志，最自然的下一步是写"该站点未产生日志"——这是完全错误的结论，而且它会一路传递到最终报告里。"找不到文件"永远先问"是不是找错地方了"，而不是"是不是没产生"。
2. **不做行完整性检查，直接信任解析器的输出**。这是本案的精华所在。第 9 行的**列位是对的**（`404` 就在 `sc-status`），**但行尾 `cs-host` 缺失**——这类记录最危险：它不会触发"字段数不对"的显眼告警，而是作为一个"字段略少但内容正常"的记录被接受。它的 `c-ip` 和 `sqlmap` 这个 UA 都能正常进入统计，于是在 IP 维度和 UA 维度里，攻击者清清楚楚地在那里；**只有状态码维度是残缺的**。委托方若按状态码做过滤或只看 4xx/5xx 分布，**这条扫描记录就会被降格成一个普通的 404**。判别方法：每一行都必须与 `#Fields` 声明的字段数比对，且不完整的行要单独列出、标注"该行数据不完整、不得用于字段级断言"——注意它仍可用于 IP/UA 维度的统计，只是不适合做状态码与时延的分析。
3. **判据**："行不完整"与"列错位"是两类不同的问题，处置方式相反：

   **判据**：**404 与"扫描未命中"之间还有距离**。`/admin/config.aspx` 返回 404 只说明**这个具体路径**不存在。判别力来自：`sqlmap` 一次扫描会尝试成百上千个路径，**404 是常态**；而如果某个路径返回 200、500 或 302，才说明有东西被碰到了。本案这一条是孤立的 404，它证明"有人扫了"，不证明"有人得手了"——后者需要站点目录（[02](server-log-web-access-log-analysis.md)）与事件日志的独立证据。

| 成因 | 位置特征 | 判别 |
|---|---|---|
| **列错位** | 某个字段值含空格且未转义 | 该行比声明**多**出字段 | 需看该行是否有引号包裹 |
| **行尾截断** | **最后一行**在末尾字段处中断 | 比声明**少 1**，且位置在末行 | **本案：17 != 18，缺 `cs-host`** |
| 写入中断（磁盘满、IIS 重启） | 通常也在末尾 | 同上 | 查事件查看器的磁盘告警 |
| 自定义 `logFormat` 与声明不符 | **所有行**都少同样的字段 | **全部行**一致地少 | 若是这种，应怀疑是格式声明本身的问题 |

**判别这几种的关键是"不完整行的数量与位置分布"**：只有末行不完整 = 截断；多行不完整且分布随机 = 格式或转义问题；所有行一致地少同样字段 = 声明与实现不一致（不是篡改）。

**按错误判据走的代价**：第 1 条踩中，整台机器的 IIS 证据全部作废——委托方会得到一份"该站点无日志、未发现攻击"的报告，而真实的扫描记录就在 `D:\IISLogs\W3SVC2\u_ex241114.log` 里躺着，**任何人重新查一遍就能推翻它**。

这类错误在交付后被对方技术人员复核时暴露，代价是**整份报告的可信度**。

第 2 条踩中则更隐蔽：报告里的统计数字**每一个都"正确"**（它们确实是解析器算出来的），只是少了一条。**没有任何异常会提示复核者去数一遍**。

<a id="section-34"></a>

### 5.2 反例 IIS 6 历史格式与迁移前的时间下界

**场景**

另一起委托。委托方提供的服务器上，站点 `legacy-digiforensics` 是从 **IIS 6 时代**迁移过来的，这次他们问的是"迁移前有没有人动过这个站"。

这个请求触碰到了两个边界问题：一是 IIS 6 的日志格式与 IIS 7+ 完全不同，二是 IIS 6 时代的日志很可能已经不在镜像里。

这两件事都需要在报告里说清楚，否则委托方会以为"查了没发现"。

**处置过程**

第 1 步 · 先确认迁移是否完成、遗留文件还在不在

```bash
# IIS 6 用 MetaBase.xml，IIS 7+ 用 applicationHost.config
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'inetsrv/(config|MetaBase\.xml)'
# ...\WINDOWS\system32\inetsrv\config\applicationHost.config      ← 现行
# ...\WINDOWS\system32\inetsrv\MetaBase.xml                     ← ★ 遗留，迁移前的配置

# IIS 6 的日志在 %WinDir%\System32\LogFiles\W3SVC1\，与 IIS 7+ 的 C:\inetpub\logs 不同
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'LogFiles/W3SVC[0-9]+' | head
# ...\WINDOWS\system32\LogFiles\W3SVC1\u_ex240301.log
# ...\WINDOWS\system32\LogFiles\W3SVC1\u_ex240302.log
# ...（共 6 份）
```

**发现 1**：**IIS 6 时代的日志目录还在**（`System32\LogFiles\W3SVC1\`），共 6 份，最早的一份是 `u_ex240301.log`（2024-03-01）。

**迁移前 2 月及更早的日志不在镜像里。**

第 2 步 · 识别 IIS 6 格式（与 W3C 完全不同）

```bash
icat -o 2048 /work/DigiForensics.dd <inode-legacy> | head -8
```

```
#Software: Microsoft Internet Information Services 6.0
#Version: 1.0
#Date: 2024-03-01 00:00:00
#Software: Microsoft Internet Information Services 6.0
#Version: 1.0
#Date: 2024-03-02 00:00:00
2024-03-01 10:14:33 W3SVC1 SRV 10.10.0.5 GET /index.asp - - 10.10.0.5 Mozilla/4.0+ 200 0 0 1841 512
```

**IIS 6 的格式有几个关键差异**：

| 特征 | IIS 6 | IIS 7+ (W3C) |
|---|---|---|
| 头部 | **每段最多 4 行，之后可能再出现一组** | 每个文件**只有一个** `#Fields` 组 |
| 字段顺序 | 固定硬编码，**不可配置** | 由 `#Fields` 声明，**可自定义** |
| 客户端 IP | 第 5 列 | `c-ip`，位置**随格式变** |
| 状态码位置 | **第 10 列**（硬编码） | 随 `#Fields` 变 |
| 空值表示 | `-` | `-` |

本案这份日志里有一个必须注意的点：字段数是 13，且没有 `#Fields` 头——**因为 IIS 6 根本不写 `#Fields`**。任何依赖 `#Fields` 解析的脚本，在这里会直接失效或错位。

第 3 步 · IIS 6 格式下的判读（本节只做行为识别）

```bash
# 状态码在第 10 列，IP 在第 5 列
icat -o 2048 /work/DigiForensics.dd <inode-legacy> \
  | grep -v '^#' \
  | awk '{ip[$5]++; st[$10]++} END{for(i in ip) print "IP",i,ip[i]; for(s in st) print "状态",s,st[s]}' \
  | sort
# IP 10.10.0.5   412          ← 全部是内网地址
# IP 185.220.101.34  18       ← ★ 唯一的外网 IP
# 状态 200 401
# 状态 404 18
# 状态 403 11
```

唯一的外网 IP `185.220.101.34` 出现 18 次，全部返回 404/403：

```bash
icat -o 2048 /work/DigiForensics.dd <inode-legacy> | grep '185.220.101.34' | head -4
# 2024-03-02 02:14:07 W3SVC1 SRV 10.10.0.5 GET /admin/login.asp - - 185.220.101.34 Mozilla/4.0+ 404 0 0 274 512
# 2024-03-02 02:14:31 W3SVC1 SRV 10.10.0.5 POST /admin/config.asp - - 185.220.101.34 Mozilla/4.0+ 403 0 0 291 512
# 2024-03-02 02:15:02 W3SVC1 SRV 10.10.0.5 GET /../../winnt/win.ini - - 185.220.101.34 Mozilla/4.0+ 404 0 0 274 512
```

18 次请求全部落在 02:14–02:16 的两分钟内，全部指向 `/admin/` 与路径穿越样式，且无一次成功。

这是扫描行为的形态特征（见 [03](server-log-web-access-log-analysis.md)）。

**第 4 步 · 确认时间下界**

```bash
# 6 份日志覆盖的日期
icat -o 2048 /work/DigiForensics.dd <inode-legacy> | grep '^#Date:' | sort -u
# #Date: 2024-03-01 00:00:00
# #Date: 2024-03-02 00:00:00
# ...（共 6 个日期）
```

覆盖范围：2024-03-01 至 2024-03-06。

**结论**

| 结论 | 依据 | 强度 |
|---|---|---|
| 该机从 **IIS 6 迁移至 IIS 7+**，两代日志目录并存 | `MetaBase.xml` + `System32\LogFiles\` 目录 | 强 |
| IIS 6 时代日志仅存 6 份，覆盖 2024-03-01 至 03-06 | `#Date` 头枚举 | 强 |
| **2024-03-01 之前的访问记录不可查** | 目录内无更早文件 | 强（**局限须写入报告**） |
| 迁移前存在外网扫描（`185.220.101.34`，18 次） | IIS 6 日志第 5 列 IP | 强 |
| **该扫描未成功**（18 次全部 404/403） | 第 10 列状态码 | 强 |
| **IIS 6 日志可解读** | 列位固定（IP 第 5、状态码第 10） | 强（**但需专用解析器**） |
| 该 IP 是否还有其他攻击 | **不可查**（只覆盖 6 天、只有一个站点） | **未决项** |

**限定范围**：「`System32\LogFiles\W3SVC1\` 下 6 个文件、`W3SVC1` 一个站点」。

**未覆盖**：其他站点 ID 的日志（**未确认存在与否**）；`W3SVC1` 中 2024-03-01 之前的内容（**已不存在**）；IIS 6 时代的**应用层日志与事件日志**（Windows 事件日志同样在循环覆盖，早期记录不可查）；`185.220.101.34` 在 03-06 之后的活动（**不在覆盖范围内**）。

**误判对照**

这个反例最容易出的错有两个，第二个是跨代日志分析里非常经典的一个。

1. **用 W3C 解析器去读 IIS 6 日志**。判别方法**只有一个，必须最先做**：**看有没有 `#Fields` 头**。有 → W3C，列位可配置，必须按头解析；无 → IIS 6 或自定义格式，列位硬编码在解析器里，必须用该版本的固定列位表。判错的后果不是"读不出来"，而是**"读出来了但全是错的"**——`awk '{print $10}'` 会在 IIS 6 里正确地取到状态码（因为它恰好就是第 10 列），但在 W3C 上会取到 `sc-substatus`，**两个都"有输出"，没有任何报错提示你搞反了格式**。同一段脚本换一种日志就静默出错，这是取证分析里最需要警惕的失效模式。
2. 把"迁移前的 IIS 6 日志还在"当成"迁移前的时间线完整"。判别力在**文件数量与日期覆盖**，而不在"目录存在"。本案目录里有 6 个文件，**最早 2024-03-01**——**这说明 IIS 6 时代运行了不止 6 天**，更早的日志是在 IIS 6 的默认轮转策略下被删除了。IIS 6 的默认日志保留策略**通常只保留有限份数**，**不像 IIS 10 有明确的"保留 N 天"设置**。正确表述是"现存 6 份日志覆盖 03-01 至 03-06，更早的日志已按 IIS 6 的轮转策略删除，不可恢复"——**而不是"迁移前的日志都在这儿"。**
3. **判据**：`404` 与 `403` 含义不同，不能合并统计。`404` 是"文件不存在"，`403` 是"存在但被拒"。本案 18 次里 11 次 403、7 次 404——403 的存在说明那些路径（`/admin/config.asp` 等）可能真实存在但受保护，这是一个值得追的线索。但要主张"攻击者找到了真实存在的受保护路径"，还需要站点目录侧的独立验证（那个文件到底存不存在）。日志侧的 403 只是"服务器这么说"，不是"确实存在"。

**按错误判据走的代价**：第 1 条踩中，解析器在 IIS 6 日志上会把 `sc-substatus` 当状态码统计——产出的"状态码分布"完全是另一组数字，但格式规整、看不出问题。

委托方拿到这份统计去写损失报告，**每一个数字都错，且没有任何迹象提示复核**。

第 2 条踩中则会让委托方认为"迁移前的记录我们都有，可以放心做完整的时间线"——**而实际上 2 月及以前的入侵痕迹已经永久消失了**。

基于这个前提做的排除性结论（"2 月前没有异常"）会成为一个永远无法被证伪的错误断言。

<a id="section-35"></a>

## 六、扩展阅读方向

本篇的产出是两件东西：站点拓扑表与可复用的日志解析器。 下面按「要把这两件东西真正用起来，还缺什么」组织。

<a id="section-36"></a>

### 前置与基础：先确认数据源边界

没有这一层，后面每一个统计数字都不知道能不能采信。
- [Windows 服务器取证工件地图](server-log-server-artifact-map.md) —— 本篇最直接的上游。它回答"哪些日志存在、哪些审计通道未启用、时间覆盖到哪"，也解释了为什么 IIS 日志目录名是 `W3SVC<n>` 而不是站点名。没读它就直接找日志，最常见的结局是"找错文件名"或"找错目录"。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 跨源时间线的底座。W3C 是 UTC、事件日志是本地时间，换算没做好的话两边的先后顺序会整个颠倒；`Microsoft-Windows-WAS`、`IIS-W3SVC-WP` 通道与应用池回收事件也在那里。

<a id="section-37"></a>

### 同层深入：把解析结果变成结论


- [Web 访问日志深度分析](server-log-web-access-log-analysis.md) —— 本篇解析出的字段（时间、状态码三元组、耗时、查询串）拿去做归因分析。**状态码三元组分布是其中价值最高的一组统计**：出现 `404/7` 说明攻击请求确实到达 IIS 并被 Request Filtering 挡下——即使没有任何一条落地。
- [Web 攻击痕迹还原](server-log-web-attack-trace-reconstruction.md) —— 日志说"某时有一次异常请求"，主机侧说"某时配置文件被改了"，两边对上才构成完整证据链。本篇的站点映射与字段语义是那篇的输入。
- [Nginx 与 Apache 配置取证](../server-web/server-web-nginx-apache.md) —— 对照两者的 `log_format` 与 vhost 语义。你会看到同一个问题（日志字段由配置决定）在两类服务器上的不同表现，理解这一点就不需要死记 IIS 的字段表。

<a id="section-38"></a>

### 相邻议题：配置层与文件层

- [网站目录与 WebShell 检测](../server-web/server-web-webshell-detection.md) —— 站点配置告诉你"哪里能执行、哪里不记日志"，这直接决定目录排查该往哪看、哪些位置是盲区。
- [Windows Server 环境仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-windows-server.md) —— 拿到站点配置之后，下一步常是在本地把环境拉起来复现某个行为。仿真时哪些配置能照搬、哪些绝对不能照搬，那里讲得比本篇细。

<a id="section-39"></a>

### 工具与判据：判断"没记"和"没发生"

- [文件头与文件签名](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md) —— 判断 `W3SVC*` 目录里的文件到底是什么类型（日志、配置、还是伪装成日志的其他文件）时用得上。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **判断"日志被清理过"需要它的方法**。字段数不一致、末行不完整、文件体积远小于相邻日——这些都要用它的分层定级思路落到结论强度上。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) —— 判断多个站点之间是否存在同源植入、备份文件与现网文件是否同源时的工具方法。
<a id="section-40"></a>

## 七、命令速查

```powershell
# ===== 一次性拿到全部关键信息（现场应急用）=====
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp\Components' | Select MajorVersion, MinorVersion
Get-ChildItem C:\Windows\System32\inetsrv\config\applicationHost.config*,
             C:\Windows\System32\inetsrv\MetaBase.* | Select FullName, Length, LastWriteTimeUtc
Get-Website | Select Name, ID, State, PhysicalPath,
  @{n='Bindings';e={($_.Bindings.Collection.bindingInformation) -join '; '}} | Format-List
Get-WebConfigurationProperty -PSPath 'IIS:\' `
  -Filter "system.applicationHost/sites/site[@id='2']/logFile" `
  -Name directory,period,truncateSize,logFormat | Format-List
# IIS6 读 MetaBase.xml（.bin 是无效残留）；IIS7+ 读 applicationHost.config + .bak；日志路径可被改到非 C 盘

# ===== ★ 先读 #Fields，绝不写死列索引 =====
$fields = ((Select-String -Path $log -Pattern '^#Fields:').Line -replace '^#Fields:\s*','') -split '\s+'
"字段数=$($fields.Count) cs-username=$([array]::IndexOf($fields,'cs-username')) c-ip=$([array]::IndexOf($fields,'c-ip'))"
# ★ IIS7+ 实际顺序：cs-username 之后直接是 c-ip，没有 cs-domain
Get-ChildItem D:\IISLogs\W3SVC2\*.log | ForEach-Object {
  "{0} → {1} 条 #Fields" -f $_.Filename, (Select-String -Path $_.FullName -Pattern '^#Fields:').Count
}
# 同一文件出现多行 #Fields → 日志配置当天被改过

# ===== 日志文件完整性（大小异常 = 截断线索）=====
Get-ChildItem D:\IISLogs\W3SVC2\*.log* |
  Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc | Sort-Object Name
# ★ 用 *.log*：IIS6 的 ex*.log、自定义字段的 _x 后缀、.gz 归档都要覆盖
```

```bash
# ===== Linux 侧：定位与提取 =====
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'inetsrv/(config/applicationHost\.config(\.bak)?|MetaBase\.xml)$' /work/filelist.txt
grep -iE 'LogFiles/W3SVC[0-9]+/.*\.log.*$' /work/filelist.txt | head
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/applicationHost.config && sha256sum /evidence/*

head -4 /evidence/u_ex241114.log              # #Software 判版本，#Fields 判字段顺序
grep -c '^#Fields:' /evidence/u_ex241114.log  # >1 表示当天配置被改过

# ===== 运行解析器（脚本见 3.4）=====
python3 parse_w3c.py /evidence/W3SVC2 -o /evidence/w3c.csv
# [WARN] 字段数不一致 = 截断线索或配置变更边界；数据行早于 #Fields = 日志被重写
# 输出 CSV 为 utf-8-sig 编码，Excel 打开不乱码；Windows 上用 py -3 代替 python3
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 服务器取证 — IIS 配置与 W3C 日志」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《IIS 配置与 W3C 日志》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
