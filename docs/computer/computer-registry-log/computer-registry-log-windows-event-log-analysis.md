---
title: "事件日志深度分析"
slug: "computer-registry-log-windows-event-log-analysis"
canonical: "https://www.digiforensics.cn/wiki/computer-registry-log-windows-event-log-analysis"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["注册表与事件日志"]
---

# 事件日志深度分析

<a id="section-1"></a>

## 一、概述

事件日志是 Windows 上少数由系统主动、持续、按审计规则记录的证据。它和注册表、Prefetch 这类「顺手留下的痕迹」有本质区别：注册表与 Prefetch 是**副产品**（为配置和加速而写，可能被清理，也可能因功能未启用而不存在），事件日志则是**专职记录**——存在的目的就是记录「谁在什么时候做了什么」。

这个区别决定了取证分工：**事件日志给出「行为」**（开了什么服务、登录失败几次、程序被启动），**注册表与 Prefetch 只给出「状态」**（配置了什么、缓存里有什么）。在「某人在某时做了什么」这个问题上，它是 Windows 上时间戳最完整、精度最高的来源之一。

但它也是**较容易被针对性清理的工件**，因为攻击者清楚它记录什么。两条硬规则必须先立在脑子里：

1. `1102`（Security 日志被清除）本身是反取证的强证据——日志被清却仍留下 1102 记录，说明清理者没清干净。
2. **日志缺失不等于无活动。** 必须先确认日志是否存在、被谁清过、上限多大，再谈「没发现什么」。

要处理的对象是 `.evtx` 的结构、怎么把它导出成可分析数据，以及那些必须逐条记住的事件 ID。

这条线在流程里的位置是「工件已提取、开始按时间线组织证据」，Windows 时间线大多从这里起头。上游依赖三件事：**活系统导出要走 `wevtutil epl`**（不能直接拷贝正在被写入的文件）；日志配置与保留策略必须先查（**这决定了「能查到什么」**）；Sysmon 若已部署则多出一批默认策略不记录的事件，见[Sysmon 与 Windows 日志聚合](computer-registry-log-sysmon.md)。动作顺序固定：先查 `FileSize` 与 `MaximumSizeInBytes` 判断是否已发生覆盖，再确认哪些通道存在、是否被清过，最后才导出解析。下游支撑整个时间线——事件日志带年份、带时区、精度到毫秒，是 Windows 侧少数高精度时间源之一，它为其它工件（Prefetch、SRUM 的小时粒度）提供锚点。

`.evtx` 是**分块 + 变长记录**结构，不能像 XP 时代的 `.evt`（16 KB 定长）那样按固定偏移读：

| 组成 | 说明 |
|---|---|
| **文件头** | 魔数 `ElfFile\0`、校验和、日志块大小（通常 4096）、chunk 数量 |
| **Chunk（数据块）** | 每块通常 4096 字节，存放已写满的事件数据区 |
| **String table** | 各事件的用户名、对象名等**变长字符串集中存放，记录里只存偏移** |
| **BinXML 片段** | 事件数据体通常以 BinXML 编码，描述字段名、类型和值 |
| **整体布局** | `ElfFile\0 → 头 → [Chunk0]…[ChunkN] → [String Table][BinXML] → 尾部校验` |
| **取值方式** | **`ToXml()`** | 
| **落点** | `%SystemRoot%\System32\winevt\Logs\*.evtx`，按通道分文件 | 
| **配置判据** | `FileSize` ≈ `MaximumSizeInBytes` 表示**已写满、正在循环覆盖**；`LogMode` = `Circular` 为默认 | 

**三条关键推论**（展开与命令见 2.1）：**不能字节偏移定位第 N 条事件**（必须顺序解析块与记录链表）；**字符串表是分离的**（部分工具字段空/乱码往往源于字符串表未完整提取）；**文件尾部有校验**（截断或损坏的 `.evtx` 用 `wevtutil` 打开可能直接报损坏）。

据此能回答的是：登录成功与失败的具体记录（含账号、来源、登录类型）、服务与驱动的安装与启动、策略变更、计划任务创建、用户与组变更、审计策略本身的变更、以及**日志被清除的时刻与操作者**。

回答不了的部分有六条：

- 取事件数据不能写死 `Properties[N]`。 必须**用 `ToXml()`**（2.2 给出四个原因与正确写法）。`Properties[N]` 的字段顺序随事件类型与版本变化，写死索引会取到错位的值，**而错误的数据比没有数据更危险**。
- **已覆盖的时段无法判断。** 事件日志是**固定大小循环覆盖**的，满了就覆盖最旧的；`Security.evtx` / `System.evtx` / `Application.evtx` 默认上限均为 20 MB，**高频环境下几小时就可能覆盖掉数天前的记录**，Sysmon 日志覆盖更快。**一旦被覆盖，磁盘上不会留下任何痕迹**——这是「日志缺失」最常见的技术原因，而非人为清理。委托方问「3 个月前有没有人登录」而日志只有 4 MB 几百条记录时，**正确回答是「该时段已被系统自动覆盖，无法判断」**。
- `.evt` 与 `.evtx` 的解析方式不能通用。 16 KB 定长与分块变长是两种结构，**用错解析器只会得到垃圾或「文件损坏」的错误结论**。
- **字段空或乱码不代表数据缺失。** **多数情况是字符串表未被完整提取**，需要换工具或换解析路径。
- **非审计策略覆盖的行为。** 日志只记录策略要求记录的，**策略没开的行为不会出现在任何日志里**。
- **Sysmon 特有事件的含义。** **若系统未部署 Sysmon，就不存在这些事件**，「没找到」是预期状态。

往下读之前先确认你已经理解 `.evtx` 的分块与 BinXML 结构（**这是判断「文件损坏」还是「解析器不对」的前提**）、Windows 审计策略的语义（**事件 ID 的意义依赖策略上下文**）、时间戳的纪元与时区处理（**事件日志的时间精度是毫秒级且带时区信息**），并且会用 PowerShell 的 `Get-WinEvent` 与 `wevtutil`，**活系统导出与离线解析走的是不同命令**。还有一点决定结论强度：`FileSize` 与 `MaximumSizeInBytes` 的关系必须在分析前确认，**否则所有否定性结论都是无根据的**。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 `.evtx` 的结构：为什么不能像 `.evt` 那样按固定偏移读

XP 时代的 `.evt` 是 **16 KB 定长记录**——第 N 条事件就在第 `N × 16384` 字节。Win7 引入的 `.evtx` 换成了**分块 + 变长记录**，这条捷径直接失效：

| 组成 | 说明 |
|---|---|
| **文件头** | 魔数 `ElfFile\0`、校验和、日志块大小（通常 4096）、chunk 数量 |
| **Chunk（数据块）** | 每块通常 4096 字节，存放已写满的事件数据区 |
| **String table** | 各事件的用户名、对象名等**变长字符串集中存放**，记录里只存偏移 |
| **BinXML 片段** | 事件数据体通常以 BinXML 编码，描述字段名、类型和值 |

```
ElfFile\0 → 头 → [Chunk0][Chunk1]…[ChunkN] → [String Table][BinXML 片段] → 尾部校验
```

**三条关键推论**：不能字节偏移定位第 N 条事件（必须顺序解析块与记录链表）；字符串表是分离的（部分工具字段空/乱码往往源于字符串表未完整提取）；文件尾部有校验（截断或损坏的 `.evtx` 用 `wevtutil` 打开可能直接报损坏）。

> 这也是为什么不该用文本编辑器或 hexdump 直接看 `.evtx`：它是二进制 + BinXML，hexdump 只能看到零散可读字符串。必须用能解析 BinXML 的工具。

<a id="section-4"></a>

### 2.2 ★ 取事件数据必须用 `ToXml()`，不要写死 `Properties[N]`

错位取值不会报错，只会静默返回语义错误的数据，详见陷阱 1。
```powershell
# ✗ 错误：下标随事件 ID/版本错位；Message 依赖系统语言与消息资源，离线常为空
$e.Properties[8].Value
$e.Message

# ✓ 正确：ToXml() 后按字段名取
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
[xml]$x = $e.ToXml()
$x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
$x.Event.EventData.Data | ForEach-Object { "$($_.Name) = $($_.'#text')" }   # 列出全部字段
$x.System.EventID; $x.System.TimeCreated.SystemTime                          # 事件元信息
$x.System.Execution.ProcessID  # 产生该事件的进程 ID
```

**`Properties[N]` 不可靠的四个原因**：

| 原因 | 说明 |
|---|---|
| **字段数随事件 ID/版本变化** | 同一个 4624，不同版本/场景下 `EventData` 字段数不同，下标会错位 |
| **`Message` 受语言影响** | 它需要「消息资源 DLL」，离线环境常缺失，可能返回空或本地化文本 |
| **字段名被丢弃** | `Properties` 只给值不给名字，出了错无从判断 |
| **改一次版本就错** | Windows 升级后事件模板微调，下标全部平移 |

**离线场景**（从镜像提取的 `.evtx`）：同样按 `EventData` 字段名取值——`EvtxECmd` 之类工具输出的键值 CSV 正是这一思路的离线实现，**这才是可引用的证据格式**。

<a id="section-5"></a>

### 2.3 关键事件 ID 清单

下面这份清单是 Windows 取证中最常用的部分之一。

A. 登录 / 账户（`Security.evtx`）

| ID | 含义 | 取证意义 |
|---|---|---|
| **4624** | 登录成功 | `LogonType` 区分类型（见 3.4 对照表） |
| **4625** | 登录失败 | **暴力破解/凭据填充信号**。看 `TargetUserName` + `IpAddress` + 频率 |
| **4648** | **用显式凭据登录** | `LogonType = 9`（New Credentials），典型为 `runas` 提权，运维场景也常见（判读见陷阱 10） |
| **4672** | 特殊权限分配 | 管理员登录的确认 |
| **4634 / 4647** | 注销 / 主动注销 | 会话结束时间 |
| 4720 / 4722 / 4724 / 4726 | 创建 / 启用 / 重置密码 / 删除账户 | 破坏性账号操作 |
| **4728 / 4732 / 4756** | 加入安全组（管理员/本地/全局） | **提权到管理员的关键事件** |
| **4776** | NTLM 认证尝试 | 网络认证；DC 侧另有 4777 |
| **4768 / 4769 / 4771** | Kerberos TGT / 服务票据 / 预认证失败 | 域环境认证分析 |

**B. 服务（`System.evtx`）**

| ID | 含义 | 取证意义 |
|---|---|---|
| **7045** | **安装了新服务** | 持久化指标之一，但合法软件安装同样会产生，判读见陷阱 10。对应注册表 `Services` 新键 |
| **7034 / 7036** | 关键服务意外终止 / 状态变更 | 服务崩溃、被杀、生命周期 |
| **7000 / 7001** | 服务启动失败 | 配置损坏或被篡改 |
| **7040 / 4697** | 服务启动类型被修改 | 禁用或延迟启动的篡改 |

**C. 日志与审计（反取证必查）**

| ID | 通道 | 含义 | 取证意义 |
|---|---|---|---|
| **1102** | Security | **Security 日志被清除** | ★ 反取证强指标（判读见陷阱 4） |
| **104** | System | 事件日志被清除（EventLog 服务） | 旧系统（XP/2003）对应的清除事件 |
| **4719** | Security | **系统审计策略被修改** | 有人改了审计规则，通常是为规避记录 |
| **4616** | System | 系统时间被更改 | 时间戳完整性受损，影响全案时间线可信度 |

**D. 系统与应用**

| ID | 通道 | 含义 | 取证意义 |
|---|---|---|---|
| **6005 / 6006 / 6008** | System | 日志启动 / 正常关机 / **异常关机** | **6008 = 非正常关机**（断电/强制重启） |
| **12 / 13** | System | 操作系统启动 / 关闭 | 启动与关闭时间 |
| **20001 / 20003** | System | USB 设备安装 / 首次连接 | 外接设备接入 |
| **4104 / 4103** | PowerShell | 脚本块记录 / 模块记录 | **命令行执行**（需事先启用审计） |
| **1 / 2 / 3** | Sysmon | 进程创建 / 网络连接 / 注册表等 | 见 [04](computer-registry-log-sysmon.md) |

> **★ 6008 与 ShimCache 的依赖关系**：它直接告诉你「这台机器上次是**异常关机**」，从而决定当前会话的 ShimCache、内存态工件是否可信（见 [06](../computer-execution/computer-execution-shimcache-amcache.md)，推演见陷阱 5）。**每次做 Windows 取证都应先查 6008。**

<a id="section-6"></a>

### 2.4 日志配置与保留策略决定「能查到什么」

事件日志是**固定大小循环覆盖**的，满了就覆盖最旧的。`Security.evtx` / `System.evtx` / `Application.evtx` 默认上限均为 20 MB（可用组策略放大），高频环境下**几小时就可能覆盖掉数天前的记录**；Sysmon 日志若不主动调大上限，覆盖速度更快。

**一旦被覆盖，磁盘上不会留下任何痕迹。** 这是「日志缺失」最常见的技术原因，而非人为清理。

```powershell
# 查当前大小、最大大小与记录数（判断是否可能已覆盖）
Get-WinEvent -ListLog * |
  Select-Object LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode |
  Where-Object { $_.RecordCount -gt 0 } | Sort-Object FileSize -Descending
```

| 判断 | 含义 |
|---|---|
| `FileSize` ≈ `MaximumSizeInBytes` | **日志已写满，正在循环覆盖**——更早事件已被冲掉 |
| `LogMode` = `Circular` | 循环覆盖（默认）；`Retain` 才是保留模式 |

> **实战意义**：委托方问「3 个月前有没有人登录」，而 Security 日志只有 4 MB、记录数只有几百条时，**正确回答是「该时段已被系统自动覆盖，无法判断」**，而不是「没发现登录记录」。

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 第 1 步：提取事件日志

```bash
# 列出所有 .evtx（Win10/11 常见路径 /Windows/System32/winevt/Logs）
# Sysmon 日志文件名含 %4 编码（Microsoft-Windows-Sysmon%4Operational.evtx），勿漏
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE '\.evtx$' > /evidence/evtx-list.txt

# 批量提取：inode 在第 2 列，落到同名文件
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE '\.evtx$' | grep -E '^r/r' \
| awk '{print $2}' | while read -r ino; do
    name=$(echo "$ino" | sed 's/.*-//')
    icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/logs/$name.evtx"
  done
```

**验证**：`wevtutil` 能正常打开且不报损坏，`EvtxECmd` 能解析出记录数。

<a id="section-9"></a>

### 3.2 第 2 步：活系统上导出（`wevtutil epl`）

`wevtutil epl` 把日志导出为 XML，是**归档和跨机器转移**的标准手段：

```powershell
wevtutil el                                        # 列出所有日志
wevtutil gl Security                               # 查看某日志配置
wevtutil epl Security C:\evidence\Security.xml -lf:true -sq   # 真实格式、静默
wevtutil epl System Application C:\evidence\logs.xml -lf:true -sq
# 只导出指定时间范围（XPath 过滤，注意用的是 UTC）
wevtutil epl Security C:\evidence\
ov.xml -lf:true `
  -q:"*[System[TimeCreated[@SystemTime>='2024-11-01T00:00:00.000Z' and @SystemTime<='2024-11-16T00:00:00.000Z']]]"
```

> ⚠️ 导出的是**当时快照**，不含被覆盖的历史；XML 不便统计，做时间线前应转成 CSV 等结构化格式。

<a id="section-10"></a>

### 3.3 第 3 步：解析为结构化数据（推荐 `EvtxECmd`）

```powershell
EvtxECmd.exe -f C:\evidence\Security.evtx --csv C:\evidence\evtx_out   # 单文件
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\evtx_out           # 递归整目录
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\out --offset +8    # 本地时间 → UTC
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\out --maps .\Maps # 自定义 maps
```

**关键 CSV 列**：`TimeCreated`（事件创建时间，按 `--offset` 换算）、`Id` / `Provider` / `Channel` / `Computer`（事件 ID、日志来源、通道、主机名），以及**按 `EventData` 字段名成列**的各列——这正是 `ToXml()` 思路的离线实现。

CSV 便于 `Import-Csv` 统计，且不依赖分析机语言。

<a id="section-11"></a>

### 3.4 第 4 步：活系统用 `Get-WinEvent` 精准查询

```powershell
# 4.1 取关键字段：ToXml + 按字段名，FilterHashtable 走服务端过滤（快）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date '2024-11-15')} |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d['TargetUserName'];
                       LogonType=$d['LogonType']; SourceIP=$d['IpAddress']; Process=$d['ProcessName'] }
  } | Format-Table -AutoSize

# 4.2 暴力破解检测：4625 按「用户+IP」聚合
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5000 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ User=$d['TargetUserName']; IP=$d['IpAddress'] }
  } | Group-Object User,IP | Sort-Object Count -Descending | Select-Object Count,Name
```

**关键：登录类型（`LogonType`）的判读**

| LogonType | 含义 | 取证价值 |
|---|---|---|
| **2** | 交互式（本地登录） | 有人坐在机器前 |
| **3** | 网络（访问共享/远程服务） | 可能是横向移动 |
| **4** | 批量（计划任务、脚本） | 自动化任务 |
| **5** | 服务 | 服务账户 |
| **7** | 解锁（解除工作站锁定） | 桌面会话活动 |
| **8** | **网络明文** | 凭据可能以明文传输，风险高 |
| **9** | 新凭据（New Credentials，`runas`） | 提权操作 |
| **10** | **远程桌面（RDPInteractive）** | 远程会话 |
| **11** | 缓存凭据 | 离线解锁 |

<a id="section-12"></a>

### 3.5 第 5 步：Sysmon 日志（若系统部署了 Sysmon）

Sysmon 写在独立通道 `Microsoft-Windows-Sysmon/Operational`，**默认不存在**；涉及入侵的案件应优先检查，详见 [04](computer-registry-log-sysmon.md)。

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 20 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  $($d['Image'])  <- $($d['ParentImage'])"
  }
```
<a id="section-13"></a>

## 四、常见陷阱

<a id="section-14"></a>

### 4.1 取值方式与字段语义

<a id="section-15"></a>

#### 陷阱 1：写死 `Properties[N]` 取事件字段

**现象**

用 `$e.Properties[8].Value` 取登录用户，得到的却是 `-\-`，或取到 IP 地址、进程名等完全无关的值。报告里的 `TargetUserName`、`IpAddress` 全部错位。

**原因**

`Properties` 集合只给值不给字段名，且下标会随事件 ID 与版本变化。四个原因叠加：

| 原因 | 说明 |
| --- | --- |
| **字段数随事件 ID/版本变化** | 同一个 `4624`，不同版本/场景下 `EventData` 字段数不同，下标整体错位 |
| **字段名被丢弃** | `Properties` 不含名字，出了错无从判断哪个是哪个 |
| **改一次版本就全错** | Windows 升级后事件模板微调，下标全部平移 |
| **不同事件类型的结构不同** | `4624` / `4625` / `7045` 的字段集合完全不同，共用一套下标必然出错 |

更隐蔽的情形是：**下标错位后取到的仍然是一个"有意义的值"** —— 从一个事件里取出另一个事件的字段，看起来完全正常，但语义全错。这类错误不会报错，只会在交叉验证时被发现。
**影响**

- **报告里的关键字段全部错位**，而表面上格式规整、看不出问题
- 若报告里写「`TargetUserName` = `jsmith`」而实际那是 `SubjectUserName`，归属判断就是错的
- 质证时无法自证字段来源，因为报告里没有字段名

**核查**

**用 `ToXml()` 后按字段名取值**：

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
[xml]$x = $e.ToXml()
$d = @{}
$x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }

"用户: $($d['TargetUserName'])   来源: $($d['IpAddress'])   LogonType: $($d['LogonType'])"
```

批量处理时先转成哈希表，避免重复解析：

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date '2024-11-15')} |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d['TargetUserName'];
                       LogonType=$d['LogonType']; SourceIP=$d['IpAddress'];
                       Process=$d['ProcessName'] }
  } | Format-Table -AutoSize
```

**离线场景的等价实现**：`EvtxECmd` 输出的 CSV 正是这一思路的离线版本 —— **按 `EventData` 字段名成列**，这才是可引用的证据格式：
```powershell
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\out
# 关键列：TimeCreated / Id / Provider / Channel / Computer + 各 EventData 字段名成列
```

**报告里引用事件字段时，必须同时给出字段名与取值**，不允许出现只有值没有名字的引用。

<a id="section-16"></a>

#### 陷阱 2：依赖 `Message` 字段取事件内容

**现象**

用 `$e.Message` 取事件描述，得到空字符串或一段英文，本地化环境下又是中文。报告里写「根据事件描述，登录类型为交互式登录」。

**原因**

`Message` 需要"消息资源 DLL"才能生成，这带来两个问题：

- **离线环境常缺失资源文件**，返回空或残缺文本
- **受分析机语言与系统版本影响** —— 同一份 `.evtx` 在中文机与英文机上输出不同文本

更关键的是：`Message` 是一段自然语言描述，不是结构化数据。它无法用于统计、排序、跨源关联，也无法作为可复核的引用。
**影响**

- 离线分析时大量事件取不到内容，被误读为"这些事件没有价值"
- 报告中引用自然语言描述，**无法被第三方独立复核** —— 换台机器跑就变了
- 若按 `Message` 文本做匹配统计（如 grep "登录成功"），会因语言差异漏掉大量事件

**核查**

`Message` 只用于人工阅读，结论一律基于 `EventData` 字段：

```powershell
# ✗ 不可作为证据
$e.Message

# ✓ 可作为证据
[xml]$x = $e.ToXml()
$x.Event.EventData.Data | ForEach-Object { "$($_.Name) = $($_.'#text')" }
```

| 用途 | 该用 |
| --- | --- |
| 快速人工浏览 | `Message`（**不作为引用来源**） |
| 报告中的字段引用 | `EventData` 的 `Data` 节点 + 字段名 |
| 统计与聚合 | `EventData` 字段（CSV 化后可 `Import-Csv`） |
| 跨机复现 | `EventData` 字段（**与语言无关**） |

**报告标准写法**：

> 事件 `4624`（`Security`，`TimeCreated` 2024-11-15 08:12:33）：`TargetUserName` = `jsmith`，`LogonType` = `3`，`IpAddress` = `10.20.30.41`，`WorkstationName` = `DWS-0427`。

全部字段名 + 取值，不引用 `Message` 文本。

<a id="section-17"></a>

### 4.2 覆盖机制与缺失解释

<a id="section-18"></a>

#### 陷阱 3：把"没找到事件"当"没发生"

**现象**

委托方问"3 个月前有没有人登录"，Security 日志里搜不到对应记录，报告写「未发现该时段登录记录」。

**原因**

**事件日志是固定大小循环覆盖的，满了就覆盖最旧的。** 默认上限：

| 日志 | 默认上限 | 覆盖速度 |
| --- | --- | --- |
| `Security.evtx` | **20 MB** | **高频环境下几小时到数天** |
| `System.evtx` | 20 MB | 视事件密度 |
| `Application.evtx` | 20 MB | 视应用日志量 |
| **Sysmon 日志** | 默认更小 | **若不主动调大，覆盖极快** |

**一旦被覆盖，磁盘上不会留下任何痕迹。** 这是"日志缺失"**最常见的技术原因，而非人为清理**。

判断方法与 2.4 相同（`FileSize` ≈ `MaximumSizeInBytes`、`LogMode` = `Circular`、`RecordCount` 很少但 `FileSize` 接近上限三项），此处不再重复。

**影响**

- 把"已被系统自动覆盖"读成"没有发生"，方向性错误：委托方据此认为无人登录，而正确答案应该是"该时段已被系统自动覆盖，**无法判断**"
- 报告里"未发现"这种措辞在法律语境下容易被读成"确认没有"

**核查**

**先查日志配置，再决定结论强度**：

```powershell
Get-WinEvent -ListLog * |
  Select-Object LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode |
  Where-Object { $_.RecordCount -gt 0 } | Sort-Object FileSize -Descending
```

| 委托方问题 | 正确回答 |
| --- | --- |
| "3 个月前有没有登录？" | 「该时段**已被系统自动覆盖**（`Security.evtx` 已达 `MaximumSizeInBytes` = 20 MB，`LogMode` = `Circular`）。**无法判断**。可查证的最早时间为 `T0`。」 |
| "3 个月前有没有**清理日志**？" | 「`Security.evtx` 中未见 `1102` 事件。但因该时段已被覆盖，**无法排除清理动作**。需转向 `System.evtx` 的 `104` 事件与文件时间戳。」 |

**结论必须用「未能验证」替代「没有」。**

<a id="section-19"></a>

#### 陷阱 4：忽略 `1102`（日志被清除）事件

**现象**

Security 日志只覆盖到案发前一天，报告写「案发时段无活动记录」。而该通道的末尾其实有 `1102` 事件。

**原因**

`1102`（Security 日志被清除）本身是反取证的强证据 —— 这条事件记录的是"**有人清除了日志**"这个动作本身。

它的价值在于一个悖论：日志被清，却仍留下 1102 记录，说明清理者没清干净。而清除 Security 日志需要相应权限，所以清理动作可把范围收敛到"持有该权限的账户或进程"，但具体是谁仍需由审计线索、进程创建记录或登录会话另行确定。

配套的清除与规避类事件（ID 与通道见 2.3 C 表）各自指向不同的规避行为：

- `4719` → 为了让某些事件**不再被记录**
- `4616` → 为了让时间线**不可信**
- `104` → 旧系统上的日志清除

**影响**

- **方向完全颠倒**：篡改信号被写成阴性结论
- 委托方据此认为没有入侵，而实际上有人刻意销毁了记录
- 错过该追问："**谁在 23:51 有权限清日志？**"

**核查**

**每次必查四类事件，结果写入报告**：

```bash
EvtxECmd.exe -f /evidence/logs/Security.evtx --csv /evidence/evtx_out
# 1102：Security 日志被清除
grep -E 'Id.*1102' /evidence/evtx_out/Security*.csv
# → 3 条：2024-11-14 23:51 / 2024-11-15 01:12 / 2024-11-15 06:33

# 4719：审计策略被修改
grep -E 'Id.*4719' /evidence/evtx_out/Security*.csv

# System 通道：104（日志清除）、4616（时间更改）
grep -E 'Id.*(104|4616)' /evidence/evtx_out/System*.csv
```

| 观察 | 报告表述 |
| --- | --- |
| 有 `1102` | 「Security 日志被人为清空 3 次（`1102`，时间为…），**此为独立的篡改信号，指向人为反取证**」 |
| 有 `4719` | 「系统审计策略在 `T` 被修改，**部分事件类型的记录可能因此缺失**」 |
| 有 `4616` | 「系统时间在 `T` 被更改，**本时段之后的时间戳完整性受损，相关推论需谨慎**」 |
| 无清除事件但日志截断 | 「未见清空事件，成因可能为**大小上限循环覆盖**或异常关机导致未落盘」 |

<a id="section-20"></a>

#### 陷阱 5：不查 `6008` 就直接使用 ShimCache 或内存态工件

**现象**

直接用 ShimCache 做执行时间线，报告写「`cleanup.exe` 于 2024-11-15 03:20 未被执行」，而实际上系统在该时段是强制断电状态。

**原因**

`6008`（异常关机）直接告诉你"这台机器上次是**异常关机**"，从而决定当前会话的 ShimCache、内存态工件是否可信（依赖关系见 2.3 D 表下说明）。

`6008` 的 `EventData` 字段 `Time` 给的是**意外关机时刻**（通常是系统最后记录的心跳时间），不是实际断电时刻，两者可能有分钟级差异。

| ID | 含义 | 判读 |
|---|---|---|
| **6005** | 日志服务启动 | 正常启动 |
| **6006** | **正常关机** | 有序关机，数据已落盘 |
| **6008** | **异常关机** | 断电 / 强制重启，**内存态与未落盘数据丢失** |
| 12 / 13 | 操作系统启动 / 关闭 | 启动与关闭时间 |

ShimCache 只在正常关机/重启时写入 hive，所以：

```text
最后一次正常关机 T0（6006 或 ShutdownTime）
    ↓
案发时段 T1 > T0，且期间发生 6008 异常关机
    ↓
T0 之后启动的程序不会出现在盘上的 ShimCache 中
    ↓
这是落盘机制造成的空白，不是"没执行"的证据
```

**影响**

- **把"证据没落盘"读成"行为没发生"**
- 案发时段若落在最后正常关机之后，该错误尤其容易发生
- 其他内存态工件（NetScan、剪贴板、浏览器会话）同样受影响

**核查**

`6008` 是每次 Windows 取证的必查项：

```powershell
# 活系统
Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -MaxEvents 5 |
  ForEach-Object { [xml]$x=$_.ToXml(); "{0}  {1}" -f $_.TimeCreated, ($x.Event.EventData.Data | ? {$_.Name -eq 'Time'}).'#text' }

# 离线：同时查注册表的 ShutdownTime 做交叉
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# \ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 23:40
```

| `6008` 情况 | 报告表述 |
| --- | --- |
| **案发时段前有 `6008`** | 「系统于 `T` 异常关机（`6008`）。`T` 之后启动的程序不会落到 ShimCache，属未落盘造成的机制性空白，无法据此判断。」 |
| 最后是 `6006` 正常关机 | 「最后正常关机 `T0`。`T0` 之前可正常依赖 ShimCache。」 |
| 无 `6008` | 「未见异常关机记录，**ShimCache 有效边界为最后正常关机时刻**。」 |

<a id="section-21"></a>

### 4.3 通道覆盖与结论表述

<a id="section-22"></a>

#### 陷阱 6：只看 `Security`，忽略 `System` / `Application` / `PowerShell`

**现象**

只解析 `Security.evtx`，报告写「事件日志分析已完成」。而服务安装、异常关机、驱动加载、命令行执行的证据全在其他通道。

**原因**

**不同通道记录的是完全不同的东西**：

| 通道 | 记录什么 | 关键事件 |
| --- | --- | --- |
| **Security** | 登录、账户、策略、服务安装、审计变更 | `4624` / `4625` / `4648` / `4672` / `4720` / `4728` / `4732` / `4756` / `4776` / `4768` / `4769` / `4771` / `7045` / `1102` / `4719` |
| **System** | 服务与驱动、硬件、**关机状态**、设备安装、**时间更改** | `7000`-`7045` / `6005` / `6006` / **`6008`** / `12` / `13` / `20001` / `20003` / **`4616`** / **`104`** |
| **Application** | 应用错误、崩溃、MSI 安装 | `1000`（应用崩溃）/ `1001` / `11707` / `1033` |
| **PowerShell** | **脚本块与模块记录** | `4104` / `4103`（需事先启用审计） |
| **Sysmon** | 进程创建、**网络连接**、文件创建、注册表 | `1` / `2` / `3` / `11` / `12` / `13`（见 Sysmon 篇） |

关键在于 PowerShell 的 `4104`（脚本块记录） —— 它是命令行执行的直接证据，但**需要事先启用审计**，未启用时该通道不会出现记录。

**影响**

- 漏掉 `6008` 就没有系统关机状态（见陷阱 5）
- 漏掉 `7045` 就漏掉服务持久化
- 漏掉 `4104` 就漏掉命令行执行的直接证据 —— 在存在 PowerShell 执行的案件里，这往往是关键一环
- 报告写「事件日志分析已完成」，实际覆盖度远低于声明

**核查**

**至少四类通道，Sysmon 存在时第五类**：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE '\.evtx$' | grep -E '^r/r' \
| awk '{print $2}' | while read -r ino; do
    name=$(echo "$ino" | sed 's/.*-//')
    icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/logs/$name.evtx"
  done
# 注意：Sysmon 日志文件名含 %4 编码（Microsoft-Windows-Sysmon%4Operational.evtx），勿漏

EvtxECmd.exe -d /evidence/logs --csv /evidence/evtx_out
ls /evidence/evtx_out/    # 确认各通道 CSV 齐全
```

**报告里列出实际分析的通道清单**：

```text
已分析事件日志通道

| 通道 | 记录数 | 时间范围 | 关键发现 |
|---|---|---|---|
| Security | 1,842 | 2024-11-08 ~ 2024-11-16 | 1102 × 3（清理） |
| System | 5,213 | 2024-11-02 ~ 2024-11-16 | 6008 × 1（异常关机） |
| Application | 890 | 2024-11-01 ~ 2024-11-16 | 1000 × 2（应用崩溃） |
| PowerShell | **0（通道不存在或未启用审计）** | — | 未能获取命令行记录 |
| Sysmon/Operational | 未部署 | — | 需说明 |
```

<a id="section-23"></a>

#### 陷阱 7：以为 `4688`（进程创建）默认开启

**现象**

在日志里找不到 `4688` 事件，报告写「案发时段无进程创建记录，未执行可疑程序」。

**原因**

**进程创建审计（`4688`）默认未开启。** 它属于"审核策略"，需要显式配置：

| 审核策略 | 对应事件 | 默认状态 |
| --- | --- | --- |
| **进程创建** | `4688` | **默认未开启** |
| 登录/注销 | `4624` / `4634` | 默认开启 |
| 账户管理 | `4720` 等 | 默认开启 |
| **命令行参数记录**（含在进程创建中） | `4688` 的 `CommandLine` 字段 | **需另外启用"包含命令行"选项** |

所以"找不到 `4688`"有三种可能，**结论强度完全不同**：

| 可能 | 报告表述 |
| --- | --- |
| 策略未开启 | 「**进程创建审计未启用**，本通道无记录，**进程执行侧未验证**」 |
| 已开启但被清除 | 「策略已启用，但该时段无 `4688` 记录。**存在清理可能**」 |
| 确实无进程创建 | 「策略已启用，时段完整，**未见该进程创建**」 |

**影响**

- **用一个从未开启的审计通道做否定结论**，是过度推论的典型形态
- 委托方据此认为案发时段没有程序执行，而这恰恰是案件最需要证明的部分
- 更糟的是，它可能被解读为"程序确实没运行"，而不是"我们没这条记录"

**核查**

**先查审计策略状态，再决定结论**：

```powershell
auditpol /get /subcategory:"Process Creation"
# 或离线查注册表
# HKLM\SECURITY\Policy\PolAdtEv  ← 审计策略二进制
# HKLM\SECURITY\Policy\EvtAuditPol  ← 另一处
```

| 策略状态 | 替代来源 |
| --- | --- |
| 已开启 | `4688` + `CommandLine` 字段 |
| **未开启** | **Sysmon 事件 `1`**（若部署）、EDR、Prefetch、Amcache、SRUM |

**报告写法**：「`Process Creation` 审核策略**未启用**（`auditpol /get /subcategory:"Process Creation"` 返回 `Failure`，未配置），本机无 `4688` 记录。**进程创建侧未能验证**，已改用 Prefetch（`Run Count` 与最近 8 次时间）、Amcache（首次运行）与 SRUM（小时级用量）三方交叉。」

<a id="section-24"></a>

#### 陷阱 8：时区不统一，跨源时间线整体错位

**现象**

Security 日志的 `TimeCreated` 与 Prefetch 的执行时间、Linux 工件的时间放在一起排序，事件与行为对不上，报告写「日志显示登录发生在 14:22，文件在 14:20 被访问」。

**原因**

**事件日志记录的是本地时间**，而不同来源的时间基准各不相同：

| 来源 | 时间类型 | 基准 |
| --- | --- | --- |
| `.evtx` `TimeCreated` | **本地时间**（无时区标识） | 事件所在机器的本地时区 |
| Prefetch | FILETIME | **UTC**（FILETIME 本身是 UTC） |
| LNK 头三个 FILETIME | FILETIME | **UTC** |
| `InstallDate`（注册表） | Unix 时间 | **UTC** |
| Chrome `visit_time` | 微秒 | **1601 纪元** |
| Chrome `date_created`（`logins`） | 微秒 | **1601 纪元** |
| Firefox `visit_date` | 微秒 | **1970 纪元** |
| `$UsnJrnl` | FILETIME | **UTC** |
| macOS `visit_time` | 秒 | **2001 纪元** |
| Quarantine xattr | 十六进制 Unix 秒 | **UTC** |

**最关键的一点**：`wevtutil epl` 的 XPath 过滤用的 `SystemTime` 是 **UTC**，而 `Get-WinEvent` 的 `StartTime`/`EndTime` 是**本地时间**。用错会导致过滤区间整体偏移。

**影响**

- **时间线整体错位**，看起来"对不上"的结果会被误判为"证据不可靠"
- 反向更糟：某些巧合会让错误的时间线"看起来能对上"，从而掩盖真实错位
- 涉及"非工作时间""凌晨"这类时段判断时，会同时错两个维度
- `4616`（系统时间被更改）存在时，这种错位可能是**被刻意制造**的

**核查**

**记录原系统时区，统一换算为 UTC，再合并**：

```powershell
# 1) 先记录检材的时区与时钟设置
reged -x /evidence/hives/SYSTEM "ControlSet001\Control\TimeZoneInformation"
# TimeZoneKeyName : China Standard Time
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1} -MaxEvents 1   # 开机时间，用于对时

# 2) 离线解析时用 --offset 换算
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\out --offset +8

# 3) 注意 wevtutil 的 XPath 用 UTC
wevtutil epl Security C:\evidence\
ov.xml -lf:true `
  -q:"*[System[TimeCreated[@SystemTime>='2024-11-01T00:00:00.000Z' and @SystemTime<='2024-11-16T00:00:00.000Z']]]"
```

**时间线合并的三条纪律**：

1. **每行必须有来源列**，否则无法复核
2. **统一时区后再跨源比较**，并保留原始值（转换前的十六进制、微秒值另存一列）
3. **报告里写明检材时区与换算方式**

同时检查 `4616`：

| 情况 | 处置 |
| --- | --- |
| 有 `4616`（系统时间被更改） | **该时刻之后的时间戳完整性受损**，相关推论需降级 |
| 无 `4616` | 时间戳可信度正常 |

<a id="section-25"></a>

#### 陷阱 9：用文本编辑器或 `strings` 看 `.evtx`

**现象**

用 `strings Security.evtx` 提取可读字符串，看到 `jsmith`、`DWS-0427` 等，报告写「日志中可见该用户活动」。用十六进制查看器打开后同样报"格式不可读"。

**原因**

**`.evtx` 是二进制 + BinXML 结构**，不是文本：

```text
ElfFile\0 → 文件头（魔数 ElfFile\0、校验和、日志块大小、chunk 数）
          → [Chunk0][Chunk1]…[ChunkN]   每块通常 4096 字节，存放已写满的事件数据区
          → [String Table]               用户名、对象名等变长字符串集中存放，记录里只存偏移
          → [BinXML 片段]                 事件数据体以 BinXML 编码
          → 尾部校验
```

`strings` 提取出来的内容有几个致命问题：

| 问题 | 后果 |
| --- | --- |
| **字符串表是分离存放的** | 取到的字符串与所属事件**之间没有可见关联** |
| **丢失事件时间** | 不知道哪个字符串属于哪条事件、什么时间 |
| **丢失事件 ID** | 无法区分 `4624` 与 `4625` |
| **无法区分字段** | 不知道是 `SubjectUserName` 还是 `TargetUserName` |
| **中文名乱码** | UTF-16LE 存储，`strings` 默认按 ASCII 提取 |

第三条推论也说明为什么不能用 `hexdump` 定位：**不能字节偏移定位第 N 条事件**（必须顺序解析块与记录链表），所以"第 160 字节处是用户名"这种做法根本不成立。
**影响**

- 从 `strings` 输出里取出的"证据"无法复核 —— 报告里写的东西第三方无法验证
- 字符串与事件的关联全靠猜，可能把不同事件的内容混成一条不存在的记录
- 中文用户名的日志会**完全提取不出来**，被误判为"日志中没有该用户"

**核查**

**用能解析 BinXML 的工具，按事件为单位导出**：

```powershell
# 离线
EvtxECmd.exe -f C:\evidence\Security.evtx --csv C:\evidence\evtx_out
# 验证：wevtutil 能打开且不报损坏，EvtxECmd 能解析出记录数
wevtutil gli C:\evidence\Security.evtx

# 活系统导出归档
wevtutil el                                          # 列出所有日志
wevtutil gl Security                                 # 查看配置
wevtutil epl Security C:\evidence\Security.xml -lf:true -sq
```

**验证通过的标准**：`wevtutil` 能正常打开且不报损坏，`EvtxECmd` 能解析出与 `RecordCount` 一致的记录数。**这两个验证都要做** —— 报损坏的 `.evtx` 可能是截断或尾部校验失败，需要记录这个事实并注明覆盖范围。

<a id="section-26"></a>

#### 陷阱 10：把 `7045` 一律当成入侵，或把 `4648` 当普通登录

**现象**

看到 `7045`（服务安装）就写「发现恶意服务持久化」；看到大量 `4648`（显式凭据登录）只当作普通登录记录。

**原因**

**这两个事件都很常见，但判读方向很重要**：

| ID | 事件 | 常见成因 | 需要核对什么 |
| --- | --- | --- | --- |
| **7045** | 系统日志中安装了服务 | **合法软件安装极常见** | `ServiceName` / `ImagePath` 是否合理、是否位于已知软件目录、签名 |
| **4648** | 用显式凭据登录（`LogonType = 9`，New Credentials） | 运维人员的 `runas` 提权**非常普遍** | 目标账户是否合理、`ProcessName` 是否为 `runas.exe`、来源 IP |

其中 `4648` 更值得注意 —— 它对应 `LogonType = 9`（`New Credentials`，即 `runas` 传凭据登录），在**攻击场景中是横向移动与提权的常用手段**，但在运维场景中也很常见。
**`LogonType` 判读表**（这是判断登录性质的基础）：

| LogonType | 含义 | 取证价值 |
|---|---|---|
| **2** | 交互式（本地登录） | 有人坐在机器前 |
| **3** | 网络（访问共享/远程服务） | 可能是横向移动 |
| **4** | 批量（计划任务、脚本） | 自动化任务 |
| **5** | 服务 | 服务账户 |
| **7** | 解锁（解除工作站锁定） | 桌面会话活动 |
| **8** | 网络明文 | 凭据可能以明文传输，**风险高** |
| **9** | **新凭据（`runas`）** | **提权操作，典型为 `runas`** |
| **10** | 远程桌面（RDPInteractive） | 远程会话 |
| **11** | 缓存凭据 | 离线解锁 |

**影响**

- 把正常的软件安装写成"恶意服务持久化"，会误导整个调查方向
- 漏掉 `4648` 的提权含义，则会低估攻击者的能力
- 误判为入侵可能让委托方对某软件/某员工产生不当怀疑

**核查**

**逐条核对字段，不做批量定性**：

```powershell
# 7045：核对服务名与路径
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    "{0}  {1}  {2}" -f $_.TimeCreated, $d['ServiceName'], $d['ImagePath']
  } | Sort-Object -Unique
# 判读：路径是否在已知软件目录？是否在 Temp/Users 下？是否有数字签名？

# 4648：核对提权目标与来源
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} -MaxEvents 50 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    "{0}  target={1}  process={2}  ip={3}" -f `
      $_.TimeCreated, $d['TargetUserName'], $d['ProcessName'], $d['IpAddress']
  }
```

| `7045` 的 `ImagePath` | 判读 |
|---|---|
| 位于已知软件目录、有合法签名 | 正常软件安装 |
| 位于 `C:\Users\...\Temp\`、Public 目录 | **可疑，需深挖** |
| 指向 `.exe` 外的文件（脚本、bat） | 高度可疑 |
| 服务名伪装成系统组件但路径不符 | **伪装型持久化** |

**报告写法**：「检出 `7045` 事件 N 条。其中 M 条 `ImagePath` 指向 `C:\Program Files\<Vendor>\` 下的合法软件（已验证签名），属正常安装。其中 1 条为 `ServiceName = WinDefendHelper`、`ImagePath = C:\Users\jsmith\AppData\Local\Temp\svc.exe`，路径与名称明显不符，判定为伪装型服务持久化。」
<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 4719 改审计策略、1102 清日志与 6008 异常关机构成反取证链

**场景**

查获一台 Windows 10 企业版笔记本（`Security` 日志上限 20 MB），委托方要求查明「2024-11-14 夜间是否有人尝试入侵，以及是否有人清除了日志」。

镜像 `DigiForensics.dd`（raw，500 GB），NTFS 起始扇区 2048，已关机。

**处置过程**

第一步，提取日志并先问「元问题」——日志状态、审计策略、关机状态：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE '\.evtx$'
icat -o 2048 /work/DigiForensics.dd <inode-Security> > /evidence/Security.evtx
icat -o 2048 /work/DigiForensics.dd <inode-System>   > /evidence/System.evtx
```

```powershell
foreach ($id in 1102,4719) {                      # Security：清日志、改审计策略
  Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=$id} |
    Select-Object @{n='Id';e={$id}},TimeCreated
}
Get-WinEvent -Path C:\evidence\System.evtx -FilterHashtable @{Id=6008} -MaxEvents 3 |
  Select-Object TimeCreated
```

```text
4719  2024-11-14 22:10:47   审计策略被修改
1102  2024-11-14 23:51:03   Security 日志被清除
6008  2024-11-14 23:58:02   系统意外关机
```

第二步，量化日志容量与覆盖状况，判断历史是否还在：

```powershell
Get-WinEvent -Path C:\evidence\Security.evtx -MaxEvents 1 |
  ForEach-Object { $_.RecordId }
Get-WinEvent -Path C:\evidence\Security.evtx |
  Sort-Object TimeCreated | Select-Object -First 1 TimeCreated, RecordId
```

```text
最新 RecordId = 418327
最早 RecordId = 391552，最早时间 = 2024-11-14 21:47:12
→ 20 MB 上限下仅保留约 2.7 万条，1102 之前的更早历史已被循环覆盖
```

第三步，在被清空之前的日志里聚合失败登录（用 `ToXml` + 字段名，不写死 `Properties[N]`）：

```powershell
Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4625} -MaxEvents 5000 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($d['TargetUserName'])|$($d['IpAddress'])"
  } | Group-Object | Sort-Object Count -Descending | Select Count,Name
```

```text
47  administrator|185.220.101.34
 3  administrator|10.0.2.55
 2  ADMINISTRATOR|192.168.1.77
```

第四步，检查该 IP 是否有成功的网络登录：

```powershell
Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4624} |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    if ($d['LogonType'] -in '3','9','10') {
      "$($_.TimeCreated) $($d['TargetUserName']) $($d['LogonType']) $($d['IpAddress'])" } } |
  Select-Object -First 10
```

```text
2024-11-14 23:12:04  administrator  3  185.220.101.34
2024-11-14 23:12:41  administrator  3  185.220.101.34
```

第五步，确认 4719 修改的具体子类别：

```powershell
Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4719} |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  Subcategory=$($d['Subcategory'])  Changes=$($d['AuditPolicyChanges'])" }
```

```text
2024-11-14 22:10:47  Subcategory=Audit Credential Validation (9)
2024-11-14 22:10:47  Subcategory=Other Object Access Events (32)
→ 失败登录与对象访问的审计被关闭，恰好覆盖即将发生的爆破
```

**结论**

`Security` 日志最新 `RecordId` 418327、最早 391552（2024-11-14 21:47:12），20 MB 上限下仅保留约 2.7 万条，**1102 之前的更早历史已被循环覆盖，不可恢复**。

三源时间链清晰：4719 于 22:10:47 修改审计策略（子类别 9「Audit Credential Validation」与 32「Other Object Access Events」，恰好覆盖即将发生的失败登录与对象访问审计）→ 1102 于 23:51:03 清除 `Security` 日志 → 6008 于 23:58:02 记录异常关机。

4719 尤其严重，**审计策略被关闭意味着后续行为可能根本没被记录**。

失败登录聚合显示 `administrator|185.220.101.34` 共 47 次，为最大来源；而同 IP 在 23:12:04 与 23:12:41 存在 `LogonType=3` 的成功登录，时间晚于 22:10 的审计策略修改。

「关审计 → 爆破 → 得手 → 清日志 → 异常关机」在时间上构成连续序列；其中「关审计」与「清日志」有直接的事件记录，「得手」由 `LogonType=3` 的 4624 支撑，五者之间尚缺直接证明因果关系的记录（如执行 4719 变更的进程与账户）。

**误判对照**

最容易遗漏的是把 4719 当成一条无关的策略变更记录跳过。正确判据是 4719（审计策略被修改）是**反取证链条的起点**：它记录了 `Subcategory` 与 `AuditPolicyChanges`，能明确指出哪些审计类别被关闭；本案关闭的「Audit Credential Validation」恰好覆盖即将发生的失败登录，被关闭的「Other Object Access Events」覆盖对象访问——时间与内容都对得上。

按错误判据跳过 4719，反取证链就只剩「清日志」与「异常关机」两环，攻击者的主动规避意图大幅削弱，委托方可能把它当作一次普通的日志轮转。

第二处易错点是看到 1102 就写「攻击者清除了全部入侵痕迹」，从而认为无法判断入侵是否发生。正确判据是 1102 只清除 `Security` 日志，**其它通道不受影响**——`System` 日志中的 7045（服务安装）、6008（异常关机）依然完整；且清除动作之前的日志内容仍保留在同一个文件中（本案 4625/4624 记录仍在）。

按错误判据认为痕迹全失，会在最关键的入侵判定上放弃分析；正确做法是清除事件本身作为强证据使用，同时转向未被清除的通道。

第三处易错点是把 47 次失败登录直接写成「暴力破解成功」。正确判据是「成功」的判据是存在 `LogonType` 为 3（网络）、9（NewCredentials）、10（RemoteInteractive）且 `LogonType` 不为 2 的 4624 记录，且账号与来源 IP 与爆破目标一致；`LogonType = 2`（交互式）是本地控制台登录，不算远程爆破成果。

按错误判据把失败次数当成功证据，会在没有 4624 支持时得出入侵结论；而正确结论必须分两句写：47 次失败是爆破尝试的强证据，同 IP 的 `LogonType=3` 成功登录是入侵成功的强证据，二者不可互相替代。

<a id="section-29"></a>

### 5.2 同 IP 从失败爆破到成功登录的完整时间链

**场景**

委托方要求确认「47 次失败登录之后是否真的登录成功，以及登录后做了什么」。需要把 4625 与 4624 的记录按同一账号、同一 IP 串联，并延伸出登录后的行为。

**处置过程**

第一步，按账号 + IP 维度做双向匹配，确认爆破与成功的目标一致：

```powershell
$fail = Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4625} |
  ForEach-Object { [xml]$x=$_.ToXml(); $d=@{}
    $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{T=$_.TimeCreated; U=$d['TargetUserName']; IP=$d['IpAddress']} }
$succ = Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4624} |
  ForEach-Object { [xml]$x=$_.ToXml(); $d=@{}
    $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{T=$_.TimeCreated; U=$d['TargetUserName']; IP=$d['IpAddress']
                       Type=$d['LogonType']; Id=$d['TargetLogonId']} }
"失败时间跨度 : $($fail[0].T) → $($fail[-1].T)"
"失败次数     : $($fail.Count)"
"同 IP 成功   : $(($succ | ? { $_.IP -eq '185.220.101.34' -and $_.Type -ne '2' }).Count) 次"
```

```text
失败时间跨度 : 2024-11-14 22:14:33 → 2024-11-14 23:11:47
失败次数     : 47
同 IP 成功   : 2 次
```

第二步，做间隔分析判断爆破节奏：

```bash
python3 - <<'PY'
from datetime import datetime
t = ["22:14:33","22:15:02","22:15:29","22:16:11","22:17:03","22:18:22","22:19:14","22:20:41"]
def s(x):
    h,m,sec = map(int, x.split(":")); return h*3600+m*60+sec
gaps = [s(b)-s(a) for a,b in zip(t, t[1:])]
print("前 8 次间隔(秒):", gaps)
print("平均间隔:", round(sum(gaps)/len(gaps), 1), "秒 → 约每 30 秒一次，机器化尝试")
print("首次失败 22:14:33 晚于 4719(22:10:47) 约 226 秒")
PY
```

```text
前 8 次间隔(秒): [29, 27, 42, 52, 79, 52, 87]
平均间隔: 52.6 秒 → 约每 30 秒一次，机器化尝试
```

第三步，用 `LogonId` 把登录后的行为与该会话关联：

```powershell
Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4624} |
  ForEach-Object { [xml]$x=$_.ToXml(); $d=@{}
    $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    if ($d['IpAddress'] -eq '185.220.101.34') {
      "$($_.TimeCreated)  LogonId=$($d['TargetLogonId'])  Type=$($d['LogonType'])" } }
```

```text
2024-11-14 23:12:04  LogonId=0x3F7A12C  Type=3
2024-11-14 23:12:41  LogonId=0x3F7A12C  Type=3
→ 同一 LogonId，说明是同一会话的两次认证，非两个独立来源
```

第四步，在 `System` 通道延伸登录后的行为：

```powershell
Get-WinEvent -Path C:\evidence\System.evtx -FilterHashtable @{Id=7045} -MaxEvents 20 |
  ForEach-Object { [xml]$x=$_.ToXml(); $d=@{}
    $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  $($d['ServiceName'])  $($d['ImagePath'])" }
```

```text
2024-11-14 23:20:11  WinDefendHelper  C:\Users\Public\winsvc.exe
→ 位于 C:\Users\Public（所有用户可写），服务名伪装成 defender 组件
```

第五步，提取样本并与 Prefetch 交叉：

```bash
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/winsvc.exe
sha256sum /evidence/winsvc.exe
# → 7a3e9c1b…（送情报库）
PECmd.exe -d /evidence/Prefetch --csv /evidence/out
```

```text
WINSVC.EXE-4C7D8E9F.PF | runs = 1 | last = 2024-11-14 23:20:58
   path: C:\Users\Public\winsvc.exe
→ 7045(23:20:11) 与 Prefetch(23:20:58) 相差 47 秒，顺序合理：先注册服务，随后启动
```

**结论**

失败登录的时间跨度为 2024-11-14 22:14:33 至 23:11:47 共 47 次，前 8 次平均间隔 52.6 秒（约每 30–90 秒一次），呈机器化尝试特征。首次失败 22:14:33 晚于 4719 审计策略修改（22:10:47）约 226 秒。

同 IP `185.220.101.34` 存在 2 次 `LogonType=3` 成功登录，且两条记录的 `LogonId` 同为 `0x3F7A12C`，说明是同一会话内的两次认证而非两个独立来源。

登录后 `System` 通道的 7045 于 23:20:11 记录服务 `WinDefendHelper` 安装，`ImagePath = C:\Users\Public\winsvc.exe`（位于所有用户可写目录、服务名伪装成 Defender 组件）；提取样本计算 SHA-256 为 `7a3e9c1b…`；

Prefetch 中 `WINSVC.EXE-4C7D8E9F.pf` 的 `Run Count = 1`、末次运行 23:20:58，与 7045 相差 47 秒，顺序合理——先注册服务，随后启动。

行为链（按时间排列）：改审计策略 → 爆破 → 得手（同一会话）→ 安装持久化服务 → 清日志 → 异常关机。链中各环节均有对应事件记录，环节之间的因果关系（是否同一主体所为）尚需进程创建记录或审计线索补齐。

**误判对照**

最容易出错的是看到两条 `4624` 成功登录记录就写「攻击者登录了两次」，暗示两个不同的攻击者或两次独立的入侵。正确判据是 `TargetLogonId` 标识的是**登录会话实例**，本案两条记录的 `LogonId` 完全相同（`0x3F7A12C`），说明是同一会话中发生的两次网络认证请求（例如先尝试某协议再切换到另一协议），而非两次独立登录。

按错误判据写成两次入侵，会让委托方误判攻击规模并启动多线排查；正确表述是「同一会话内完成认证，最终获得一个可用会话」。

第二处易错点是把 47 次失败的平均间隔（约 52.6 秒）当作人的手工尝试。可用的判据是节奏分布：本案前 8 次间隔为 29、27、42、52、79、52、87 秒，集中在几十秒量级；人工输入通常夹杂更长的停顿与重试间隔。这一分布只支持「节奏规整、疑似自动化」，不能单独排除熟练人员或脚本化半自动尝试，定性仍需结合来源 IP、账号目标与后续成功登录的一致性。

按错误判据判断为「员工忘记密码导致多次尝试」，会把一起外部入侵降格为内部操作失误——这个差别决定了事件定级与后续响应是否启动。

第三处易错点是把 `C:\Users\Public\winsvc.exe` 的存在直接写成「已安装恶意服务」。正确判据是 7045 记录的是服务注册这一事实，服务名的伪装性与路径的可写性都是**强指示**，但服务本身不必然恶意——同一路径也可能被合法的自更新组件使用；定性必须依赖样本本体分析、哈希情报库比对、以及 `ImagePath` 指向文件的签名情况。

按错误判据直接定性为恶意，会把定性结论建立在一个文件名（`winsvc.exe` 听起来像 defender）上，而文件名恰恰是攻击者最容易伪造的部分；本案已提取样本并送情报库，结论强度就落在这份样本分析上。

<a id="section-30"></a>

### 5.3 日志循环覆盖造成的证据局限必须明示

**场景**

委托方要求「还原 2024-11-14 当天全天入侵过程」。但 `Security` 日志上限仅 20 MB，且已在 23:51 被清除。需要明确这条证据链能支撑到哪一步。

**处置过程**

第一步，量化日志容量与实际保留范围：

```bash
python3 - <<'PY'
CAP = 20 * 1024 * 1024
first_rid, last_rid = 391552, 418327
print(f"配置上限 : {CAP:,} 字节（20 MB）")
print(f"RecordId : {first_rid} → {last_rid}，实际保留 {last_rid-first_rid+1:,} 条")
print(f"最早记录 : 2024-11-14 21:47:12")
print(f"→ 21:47 之前的历史已被循环覆盖，不在本文件内")
PY
```

第二步，检查是否存在更早的日志轮转副本或 GPO 备份：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd 2>/dev/null | grep -iE 'evtx|security.*\.(bak|old)'
# → 无轮转副本
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EventLog"
# → 无 GPO 强制配置（说明 20 MB 是默认上限，非刻意调小）
```

第三步，界定三类不同性质的「无记录」：

```bash
python3 - <<'PY'
cases = [
 ("循环覆盖", "21:47 之前的记录已被新记录挤出",
  "受 20 MB 上限约束，与行为无关；可通过增大上限缓解"),
 ("1102 清除", "23:51 之后的行为若已被审计策略关闭，则根本不会产生记录",
  "受 4719 影响；4719(22:10) 之后关闭的审计类别永远无记录"),
 ("未审计", "未纳入审计策略的操作类型从来就不记录",
  "需先查 4719 的 Subcategory 才能判断哪些类别已关闭"),
]
for k, what, why in cases:
    print(f"【{k}】\
  无记录的原因: {what}\
  成因: {why}\
")
PY
```

第四步，列出当前仍可用的替代工件：

```bash
python3 - <<'PY'
alts = [
 ("System.evtx", "7045 服务安装、6008 异常关机、7040/7036 服务状态变更"),
 ("Security.evtx", "1102/4719 本身；22:14 之后的 4625/4624"),
 ("$UsnJrnl",    "文件创建/删除/改名，与日志上限无关"),
 ("Prefetch",    "执行痕迹，逐次即时落盘，不依赖关机"),
 ("NTFS MFT",    "文件时间戳与目录项"),
]
for a, b in alts:
    print(f"{a:16s} → {b}")
PY
```

第五步，把结论与局限分别写成可核查的条目：

```bash
python3 - <<'PY'
print("【可认定】")
print("  2024-11-14 22:10:47  审计策略被修改（子类别 9、32）")
print("  2024-11-14 22:14–23:11  同 IP 失败登录 47 次")
print("  2024-11-14 23:12      同 IP 成功网络登录（同一 LogonId）")
print("  2024-11-14 23:20      服务 WinDefendHelper 安装于 C:\\Users\\Public")
print("  2024-11-14 23:51      Security 日志被清除")
print("  2024-11-14 23:58      异常关机")
print()
print("【不可认定】")
print("  21:47 之前的任何活动（循环覆盖）")
print("  4719 之后被关闭审计类别的操作（不会产生记录）")
print("  23:51 之后至关机之间的行为（1102 已清除）")
print("  入侵的初始入口（需防火墙/EDR/外侧日志补齐）")
PY
```

**结论**

`Security` 日志配置上限 20 MB，`RecordId` 区间 391552–418327（实际保留约 2.68 万条），最早记录为 2024-11-14 21:47:12，**21:47 之前的历史已被循环覆盖**。`fls` 未发现任何轮转副本，注册表中亦无 GPO 强制配置，说明 20 MB 是系统默认值而非刻意调小。

报告须区分三类性质不同的「无记录」：循环覆盖（受容量约束）、1102 清除（23:51 之后）、以及**4719 关闭审计导致的从未记录**（22:10:47 之后被关闭的类别永远不会有记录）——第三类最容易被忽略，也最需要明示，因为它是攻击者主动造成的取证盲区。

替代工件仍然可用：`System.evtx`（7045/6008 完整保留）、`$UsnJrnl`、Prefetch（不依赖关机落盘）、NTFS MFT。结论中「可认定」与「不可认定」必须分列。

**误判对照**

最容易产生的误判是把「日志里没有」直接写成「没有发生」。正确判据是「无记录」在本案中有三种完全不同的成因——容量循环覆盖、1102 主动清除、4719 关闭审计——各自的处置方式与预防措施都不同：前者可由调大日志上限缓解，第二、三类是人为行为。

按错误判据笼统写「未发现」，报告在复核时会暴露出未区分成因；而更严重的是，若把 4719 关闭审计造成的那段记录也当作「未发现异常」，就会漏掉攻击者主动规避的意图——这是本案最需要防守的点。

第二处易错点是认为 1102 之前的日志「都是可信的」因而可以作为入侵全貌。正确判据是即使在 1102 之前，22:10:47 之后被 4719 关闭审计的那部分记录同样不存在；本案能拿到的 4625 记录始于 22:14:33，晚于 4719，说明「关闭审计」在这台机上并未完全阻止事件生成（可能存在策略叠加或子类别覆盖差异），但这一偶然性不可依赖。

按错误判据认为 1102 之前的日志完整，会高估证据覆盖范围，把「恰好有记录」误当作「一定被记录」。

第三处易错点是在报告里写「入侵入口为暴力破解」而不加限定。正确判据是 47 次失败 + 成功登录证明的是**一次凭据爆破攻击**，但它回答的是「凭据如何获得」，不是「如何触达该主机」——触达路径需要防火墙日志、VPN 日志、EDR 告警或外侧流量记录；攻击 IP `185.220.101.34` 只能证明来源地址，不能证明入口向量。

按错误判据写成完整入口分析，会让委托方误以为已封闭漏洞入口；正确表述应区分「凭据获取方式（已证实）」与「触达路径（待补齐）」两层。

---
<a id="section-31"></a>

## 六、扩展阅读方向

<a id="section-32"></a>

### 前置基础：能读到、能读对，才有结论

- [Windows 取证工件地图](computer-registry-log-windows-artifact-map.md) —— 日志通道的分布、版本差异与提取范围。XP 的 `.evt` 与 Win7 起的 `.evtx` 是两种结构，版本判定在前面。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— 事件日志带年份与时区，它是 Windows 侧少数高精度时间源之一，跨工件对齐时以它为锚。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 离线读取前提；活系统上则要走 `wevtutil epl` 导出而不是直接拷贝。

<a id="section-33"></a>

### 同层深入：同一批日志的其它读法

- [Sysmon 与 Windows 日志聚合](computer-registry-log-sysmon.md) —— 若系统部署了 Sysmon，它把进程创建、模块加载、网络连接等记成结构化事件，补上默认审计策略未覆盖的部分，**与本篇的 Security 通道互补而非替代**。
- [注册表取证](computer-registry-log-registry-forensics.md) —— **注册表记配置、事件日志记行为**，这个分工是理解 Windows 证据体系的基础。
- [用户行为痕迹](computer-registry-log-user-activity-artifacts.md) —— 注册表里的行为痕迹，与事件日志的行为记录是两条独立线索。

<a id="section-34"></a>

### 相邻议题：行为证据的其它来源

- [Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md) —— 执行侧的时间源。事件日志给「谁执行」，Prefetch 给「跑了多少次、什么时候」，两者合并才完整。
- [ShimCache 与 Amcache](../computer-execution/computer-execution-shimcache-amcache.md) —— **不受审计策略影响**的执行证据，但 ShimCache 依赖正常关机落盘（见陷阱 5），Amcache 的 `FirstRun` 不依赖关机。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— **小时级粒度但带用户 SID**，在事件日志缺失时能提供另一条时间线。
- [Windows 11 与 Recall](../computer-browser-behavior/computer-browser-behavior-windows11-recall.md) —— 屏幕侧的行为记录，**与事件日志的「行为」在维度上不同**。

<a id="section-35"></a>

### 工具与规范：导出与保全

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 导出产物的归档封装。
- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 活系统上的 `wevtutil epl` 属于主动操作，执行前应先固定原始文件。
- [Windows Server 环境仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-windows-server.md) —— 离线解析的环境准备。

<a id="section-36"></a>

### 判据与反例：哪些缺失不能读成阴性结论

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— `1102` 这类「越抹越明显」的自证记录是这一篇的核心判据，而它的成因分析在该篇。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **本篇 4.3 的结论表述纪律来源**：涉及「未发现」的表述必须限定通道、时段与未覆盖范围。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 事件日志分析属于基础层能力，**它答不了「做了什么」和「为什么」**。
<a id="section-37"></a>

## 七、命令速查

```powershell
# ===== 活系统：归档 =====
wevtutil el                # 列出所有日志
wevtutil gl Security       # 查看日志配置（上限/模式）
wevtutil epl Security C:\evidence\Security.xml -lf:true -sq
# 仅导出时间范围（XPath 用的是 UTC）
wevtutil epl Security C:\evidence\
ov.xml -lf:true `
  -q:"*[System[TimeCreated[@SystemTime>='2024-11-01T00:00:00.000Z' and @SystemTime<='2024-11-16T00:00:00.000Z']]]"

# ===== ★ 每次必查：反取证与系统状态 =====
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 | Select TimeCreated  # 日志被清
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -MaxEvents 20 | Select TimeCreated  # 审计策略被改
Get-WinEvent -FilterHashtable @{LogName='System';   Id=6008} -MaxEvents 5  | Select TimeCreated  # 异常关机
Get-WinEvent -FilterHashtable @{LogName='System';   Id=7045} -MaxEvents 20 | Select TimeCreated  # 新服务安装

# ===== 覆盖判断：FileSize ≈ MaximumSizeInBytes → 更早事件已丢 =====
Get-WinEvent -ListLog * |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode |
  Where-Object RecordCount -gt 0 | Sort-Object FileSize -Descending

# ===== ★ ToXml() + 按字段名取（不要写死 Properties[N]）=====
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date '2024-11-15')} |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d['TargetUserName'];
                       LogonType=$d['LogonType']; IP=$d['IpAddress'] }
  } | Format-Table -AutoSize

# 暴力破解聚合：同 IP 对同账号的失败次数
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5000 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($d['TargetUserName'])|$($d['IpAddress'])"
  } | Group-Object | Sort-Object Count -Descending | Select Count,Name

# ===== 离线解析为 CSV（EventData 按字段名成列，不依赖系统语言）=====
EvtxECmd.exe -d C:\evidence\logs --csv C:\evidence\evtx_out --offset +8
```

```bash
# ===== Linux：从镜像提取 .evtx（-o 偏移按实际 mmls 结果替换）=====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE '\.evtx$'
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/Security.evtx
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 取证 — 事件日志深度分析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《事件日志深度分析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
