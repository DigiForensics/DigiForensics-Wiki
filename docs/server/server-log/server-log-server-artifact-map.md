---
title: "工件地图"
slug: "server-log-server-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/server-log-server-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "server"
space: "服务器与云取证"
node_path: ["日志分析"]
---

# 工件地图

<a id="section-1"></a>

## 一、概述

拿到 Windows Server 镜像，最容易犯的错误是套用桌面 Windows 的思路。

去 `Users\<用户名>\AppData` 里翻浏览器记录、跳转列表、剪贴板——这些在服务器上大量不存在。跑的是 IIS、SQL Server、Exchange，`AppData` 里可能只有几个自动化服务的目录。

把它们查不到写成"未发现用户活动痕迹"，等于用错误的工具得出错误的结论。

**真正决定事实的工件在服务器上恰恰是另一批**：站点配置、站点级访问日志、认证与系统日志、计划任务与注册表。本篇给出这张全景图，以及"百 GB 镜像先提哪一类"的优先级排序。

**六条结构性差异**（理解差异比记路径重要）：

| 维度 | 桌面 PC | Windows Server | 对取证的影响 |
|---|---|---|---|
| **运行状态** | 现场常在运行 | **7×24 常驻** | 采集难；采集瞬间日志仍在写 |
| **用户活动** | 有交互痕迹 | **无人值守**，`AppData` 基本为空 | 桌面行为工件基本失效 |
| **日志量级** | Security 够用 | 服务/驱动/任务全天刷屏 | **几天即可覆盖** |
| **登录类型** | 交互式（Type 2） | 网络(3)、服务(5)、批处理(4)、RDP(10) | `LogonType=3` 不等于"有人上班" |
| **凭据强度** | 域账号 + 本地账号 | 大量服务账号、IIS AppPool 身份 | 横向移动优先找这些 |
| **加密** | BitLocker 常开 | **BitLocker 覆盖很低** | 拿到镜像往往能直接读 |

**在取证流程中的位置**：本篇属于**采集环节的前置规划层**。它不产出结论，而是决定"能得出什么结论"与"先取什么"。

`Security.evtx` 一旦写满就循环覆盖——先做元问题检查，再谈入侵（见 [3.1 第 1 步](#section-11)）。

上游依赖 [Windows 取证工件地图](../../computer/computer-registry-log/computer-registry-log-windows-artifact-map.md) 的通用体系与 [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) 的定位能力；下游是本板块其余四篇的具体分析。

**涉及的证据形态**（按优先级，具体到路径）：

| 优先级 | 工件 | 路径 / 形态 | 典型大小 |
|---|---|---|---|
| **P0** | IIS 访问日志 | `C:\inetpub\logs\LogFiles\W3SVC<n>\u_ex*.log` | 日增几十 MB |
| **P0** | IIS 全局配置 | `%windir%\system32\inetsrv\config\applicationHost.config` **+ `.bak`** | KB 级 |
| **P0** | 站点配置 | `C:\inetpub\wwwroot\<site>\Web.config`、`App_Offline.htm` | KB 级 |
| **P0** | 事件日志 | `%windir%\system32\winevt\Logs\*.evtx` | 几十 MB |
| **P1** | 站点目录 | `C:\inetpub\wwwroot\<site>\`（含 `bin\`） | 站点大小 |
| **P1** | 注册表 hive | `SYSTEM`、`SOFTWARE` | 数十 MB |
| **P1** | 计划任务 | `C:\Windows\System32\Tasks\*` + `SYSTEM` 下的 `TaskCache\Tree` | 几十 MB |
| **P2** | Prefetch、SRUDB | `Prefetch\*.pf`、`SRUDB.dat` | 数十 MB |
| **P3** | Exchange `.edb` | **体积巨大，单独规划** | **数十至数百 GB** |

> ★ 最易被忽略的高价值工件是 `applicationHost.config.bak`。 IIS 改配置时先备份原文件，若主配置被改过（关闭脚本执行、改应用池身份），`.bak` 保留改之前的版本——**两者 diff 直接给出配置级篡改证据**，可与时间戳分析交叉核对。前提是你记得去拿这个文件。

哪些高价值通道真的存在（`NOT PRESENT` 是**结论**而非失败）；每条日志的覆盖时间窗与循环覆盖风险；哪个 `W3SVC<n>` 对应哪个域名与物理路径；站点目录里哪些文件是部署后新增的；PowerShell 4104 里有哪些脚本块内容；新增服务与计划任务落在哪。

还有一条经常被漏问的：**这份检材能支撑的时间范围有多长**。

**没部署的组件给不了数据**。Sysmon 通道不存在时，"无异常进程创建"这个结论根本不成立（见 [4.1 工件选择](#section-16)）。

**超出覆盖期的历史**同样无解。`FileSize ≈ MaximumSizeInBytes` 意味着更早记录已被冲掉，这必须写进报告局限。

异常关机前的内存态工件也不能用（Prefetch 依赖正常关机落盘，见 [4.4 在线操作](#section-28)）。至于 `cs-username` 之外的请求体内容，W3C 日志根本不记。

**读者前提**：需要 Windows 目录结构与 NTFS 基础（见 [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)）、HTTP 与 W3C 日志格式概念、PowerShell 基础命令。事件 ID 的基础含义见[事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)，**本篇只讲服务器侧的增量**。

Linux 上定位与提取的命令见 [07 命令速查](#section-36) 的 `fls` / `icat` 部分。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 ★ 服务器 vs 桌面 PC：六条结构性差异

理解差异比记住路径重要。这六条决定取证策略要整体调整。

六条里最贵的两条是「日志量级」和「加密」——一条决定你能回溯多久，一条决定你能不能读。

| 维度 | 桌面 PC | Windows Server | 对取证的影响 |
|---|---|---|---|
| **运行状态** | 现场常在运行 | **7×24 常驻**，多在机房/云上 | 采集难；日志持续产生，采集瞬间仍在写 |
| **用户活动** | 有交互痕迹（LNK、Recent、剪贴板） | **无人值守**，`AppData` 基本为空 | 桌面那套行为工件基本失效 |
| **日志量级** | Security 够用 | 服务/驱动/任务全天刷屏，**几天即可覆盖** | 必须先查 `MaximumSizeInBytes` |
| **登录类型** | 交互式（Type 2）为主 | 网络（3）、服务（5）、批处理（4）、RDP（10）为主 | `LogonType=3` 不等于"有人上班了" |
| **凭据强度** | 域账号 + 本地账号 | 大量服务账号、IIS AppPool 身份、`NETWORK SERVICE` | 横向移动优先找这些 |
| **加密** | BitLocker 常开 | **BitLocker 覆盖很低** | 拿到镜像往往能直接读 |

> **推论 1**：「事件日志没有记录」的第一解释是**被循环覆盖**，不是"没发生"。`Security.evtx` 默认 20 MB 上限，有 IIS 的服务器配合应用池回收，**几天就能冲掉几周前的内容**。
>
> **推论 2**：「无人登录」的结论要小心。按 `(用户, IP, LogonType)` 聚合看，而不是按总量看。

<a id="section-4"></a>

### 2.2 IIS 工件地图：三个层次

| 层次 | 文件 | 核查内容 |
|---|---|---|
| 站点/应用绑定 | `applicationHost.config` | 哪个域名 → 哪个物理路径 |
| 应用配置 | 各站点 `Web.config` | 这个应用能执行什么、连哪个库 |
| 请求记录 | `W3SVC<n>\u_ex*.log` | 谁在什么时候访问了什么、结果如何 |

| 文件 | 路径 | 价值 |
|---|---|---|
| 全局配置 | `%windir%\system32\inetsrv\config\applicationHost.config` | ★★★★★ **XML 明文**，IIS 7+ 全部站点/应用池/绑定 |
| 配置备份 | `%windir%\system32\inetsrv\config\applicationHost.config.bak` | ★★★★ **改配置前的版本** |
| 站点配置 | `C:\inetpub\wwwroot\digiforensics-site\Web.config` | ★★★★★ 含 `machineKey` |
| 访问日志 | `C:\inetpub\logs\LogFiles\W3SVC<n>\u_ex*.log` | ★★★★★ 见 [02](server-log-iis.md) |
| 元数据库 | `%windir%\system32\inetsrv\MetaBase.xml` | ★★★★★ **仅 IIS 6** |

> **★ `.bak` 是最易被忽略的高价值工件**：IIS 改配置时先备份原文件。若 `applicationHost.config` 被改过（关闭脚本执行、改应用池身份），`.bak` 保留着改之前的版本，**两者 diff 直接给出配置级篡改证据**。前提是你记得去拿这个文件。

<a id="section-5"></a>

### 2.3 事件日志：服务器场景的增量

事件 ID 基础表见[事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)。服务器上**必须额外关注**：

| 工件 | 通道 | 服务器场景意义 |
|---|---|---|
| **`System.evtx`** | `Security/System/Application` 同目录 | 驱动加载、**7045 新服务**（持久化首选） |
| **`Security.evtx`** | 同上 | 4624/4625、**4648 显式凭据登录**、4728/4732 加组 |
| **`Application.evtx`** | 同上 | **IIS / ASP.NET / SQL 的错误**，应用崩溃留痕 |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | **4104 记录脚本内容** |
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | **需事先安装启用，默认不存在** |

```powershell
# 先确认哪些高价值通道真的存在
foreach ($ch in 'Security','System','Application','Microsoft-Windows-PowerShell/Operational',
                'Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-TaskScheduler/Operational') {
  $l = Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue
  if ($l) { "{0,-52} Rec={1,-8} {2,-10} Max={3}KB" -f $ch,$l.RecordCount,$l.LogMode,($l.MaximumSizeInBytes/1KB) }
  else    { "$ch  ==>  NOT PRESENT" }
}
```

> `NOT PRESENT` 是**结论**而非失败：说明从未部署 Sysmon。报告应写"该主机无 Sysmon 部署"，而非"未发现异常进程创建"。

<a id="section-6"></a>

### 2.4 PowerShell 4104：把"可疑请求"推进到"具体行为"

W3C 日志能告诉你"有人在 `03:12:07` 请求了 `/upload/x.aspx` 且返回 200"。

但它说不出他上传了什么、之后干了什么。4104 记录脚本块**完整文本**，补上这一跳。

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 2000 |
  ForEach-Object { [xml]$x = $_.ToXml()
    [pscustomobject]@{
      Time = $_.TimeCreated
      User = ($x.Event.UserData.Data | Where-Object Name -eq 'UserId').'#text'
      Text = ($x.Event.UserData.Data | Where-Object Name -eq 'ScriptBlockText').'#text' } } |
  Export-Csv C:\evidence\ps4104.csv -NoTypeInformation -Encoding UTF8
```

| 检查点 | 说明 |
|---|---|
| **是否启用** | 需组策略开启"脚本块日志记录"，**默认关闭**——没开就是没有 |
| 有 4103 没 4104 | 只开了模块日志，脚本内容未记录 |
| 内容被截断 | 长脚本分段记录，序号在 `MessageNumber` |
| `-EncodedCommand` | 4104 里仍是**解码后的脚本文本**，可读 |

> **★ 关联技巧**：在 4104 文本里搜 W3C 中出现的可疑路径。同一路径同时出现在 4104 脚本和 W3C 日志中，是把"网络行为"与"主机行为"钉死在同一行为体上的强证据。

<a id="section-7"></a>

### 2.5 计划任务与注册表：服务器侧的两个增量

服务器上没有"桌面"，攻击者做持久化更倾向**计划任务**而非 Run 键。

| 工件 | 路径 | 说明 |
|---|---|---|
| 任务定义 | `C:\Windows\System32\Tasks\*` | XML，含触发器与操作 |
| 任务缓存 | `SYSTEM` → `Services\Schedule\TaskCache\Tree` | 元数据、注册时间、**执行次数** |
| 任务事件 | `Microsoft-Windows-TaskScheduler/Operational` | **默认需启用** |
| 注册表：RDP | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | **RDP 端口**（非 3386 本身是线索） |
| 注册表：IIS | `HKLM\SOFTWARE\Microsoft\InetStp\Components` | IIS 版本与安装选项 |

```powershell
# 列出动作指向非微软/非 Windows 目录的任务（可疑持久化）
Get-ScheduledTask | ForEach-Object { $t = $_
  $t.Actions | Where-Object { $_.Execute -and $_.Execute -notmatch '\\Microsoft\\|^[Cc]:\\Windows\\' } |
    ForEach-Object { [pscustomobject]@{ TaskPath=$t.TaskPath; TaskName=$t.TaskName
      Execute=$_.Execute; Arguments=$_.Arguments; Author=$t.Author } } } | Format-List
```

<a id="section-8"></a>

### 2.6 `C:\inetpub` 与远程桌面痕迹

| 工件 | 路径 | 价值 |
|---|---|---|
| 站点根目录 | `C:\inetpub\wwwroot\digiforensics-site\` | 落地文件、webshell |
| `bin\` 目录 | `...\digiforensics-site\bin\` | **新增 DLL 是高危信号**（无源码的托管代码） |
| `App_Offline.htm` | 应用根目录 | ASP.NET 停池时显示，**可能被用于短暂屏蔽站点** |
| 编译临时文件 | `%windir%\Temp\` | ASP.NET 预编译产物 |
| RDP 目标缓存 | `HKCU\...\Terminal Server Client\Servers` | 曾连接过的目标主机 |
| 端口重定向 DLL | `C:\Windows\System32\	sserver\*.dll` | RDP 会话与重定向痕迹 |

<a id="section-9"></a>

### 2.7 ★ 取证优先级排序

镜像上百 GB 时不能无差别提取。**按证据密度排序**：

| 优先级 | 工件 | 理由 | 典型大小 |
|---|---|---|---|
| **P0** | `W3SVC*\*.log` | 唯一逐请求记录，**体积相对小** | 日增几十 MB |
| **P0** | `applicationHost.config` + `.bak` | 站点映射 + 配置篡改对照 | KB 级 |
| **P0** | 各站点 `Web.config`、`App_Offline.htm` | 攻防焦点 | KB 级 |
| **P0** | `winevt\Logs\*.evtx` | 系统/安全/PowerShell | 几十 MB |
| **P1** | `wwwroot\digiforensics-site\` 全目录 | 落地文件、webshell、DLL | 站点大小 |
| **P1** | `SYSTEM` / `SOFTWARE` hive | 服务、驱动、任务、ShimCache | 数十 MB |
| **P1** | `System32\Tasks\*` | 计划任务 | 几十 MB |
| **P2** | `SRUDB.dat`、`Prefetch\*.pf` | 长期资源使用、程序执行 | 数十 MB |
| **P3** | Exchange `.edb` | **体积巨大，单独规划**（见 [05](server-log-exchange.md)） | **数十至数百 GB** |

提取时**必须记录 inode 与文件偏移**，报告要能指回镜像中的具体位置（`fls`/`icat` 命令见第七章）。

---

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：先问"元问题"，再谈入侵

**这一步决定报告的可信度上限。** 委托方问"有没有人被入侵"时，第一反应不是搜攻击痕迹，而是确认**这台机器的记录能覆盖到什么时间范围**。

```powershell
# 3.1.1 覆盖风险判断：FileSize ≈ MaximumSizeInBytes → 更早记录已丢
Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-PowerShell/Operational' |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode,
    @{n='覆盖风险';e={ if ($_.FileSize -ge ($_.MaximumSizeInBytes * 0.9)) {'HIGH'} else {'OK'} }}

# 3.1.2 ★ 反取证三件套
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 | Select TimeCreated  # 日志被清
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -MaxEvents 20 | Select TimeCreated  # 审计策略被改
Get-WinEvent -FilterHashtable @{LogName='System';   Id=6008} -MaxEvents 5  | Select TimeCreated  # 异常关机
```

**验证**：把覆盖窗口写进"证据局限"章节。示例：`Security.evtx` 上限 20 MB、当前 19.8 MB → 结论是"仅能回溯约 9 天，更早历史已被系统自动覆盖，无法判断"。

<a id="section-12"></a>

### 3.2 第 2 步：读 IIS 配置，还原站点拓扑

**必须先做这一步再读日志**——不知道哪个 `W3SVC<n>` 对应哪个站点，日志分析就是无根之木。

```powershell
# 活系统：站点 ID ↔ 名称 ↔ 物理路径 ↔ 绑定
Get-Website | Select Name, ID, State, PhysicalPath,
  @{n='Bindings';e={($_.Bindings.Collection.bindingInformation) -join '; '}} | Format-List
# 日志格式确认：W3C 之外（IIS/NCSA）解析方式完全不同
Get-WebConfigurationProperty -PSPath 'IIS:\' `
  -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name logFormat,directory
```

离线解析 `applicationHost.config`（XML 明文，无第三方依赖）：

```python
import xml.etree.ElementTree as ET

# ★ applicationHost.config 本身没有 XML 命名空间前缀，标签名直接用点号路径
root = ET.parse(r"C:\evidence\applicationHost.config").getroot()
for site in root.iterfind("system.applicationHost/sites/site"):
    lf = site.find("logFile")                 # logFormat/enabled 是属性，directory 才是子元素
    print(f"[{site.get('id')}] {site.get('name')}")
    for app in site.iterfind("application"):   # 一个站点可有多个应用/虚拟目录
        for vd in app.iterfind("virtualDirectory"):
            print(f"   app={app.get('path'):<6} -> {vd.get('physicalPath')}")
    print("   bind=", [b.get("bindingInformation") for b in site.iterfind("binding")])
    print("   log =", lf.get("logFormat"), lf.findtext("directory"),
          "enabled=", lf.get("enabled"))
```

**验证**：本文件无命名空间，**`iterfind` 不能带 `ns` 参数**（否则静默返回空）；`logFormat`/`enabled` 是 `logFile` 的**属性**（用 `.get()`），`directory` 才是子元素（用 `.findtext()`）。输出为 `W3C` 才走 W3C 解析；`IIS`/`NCSA` 见 [02](server-log-iis.md) 陷阱章。

<a id="section-13"></a>

### 3.3 第 3 步：建立"域名 ↔ 目录 ↔ 站点 ID"三向映射

```powershell
# 3.3.1 站点根目录内容（找落地文件）
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Select FullName, Length, CreationTimeUtc, LastWriteTimeUtc |
  Sort LastWriteTimeUtc -Descending | Select -First 40

# 3.3.2 ★ 按天分组：正常 CMS 文件时间戳高度聚集，落地文件孤立成簇
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') } |
  Sort Name | Select Count, Name
```

**验证**：某天只有 1–2 个文件而其余天各有几百个，那天就是重点排查日；把该日期与 W3C 日志中可疑路径首次出现时间对齐。

<a id="section-14"></a>

### 3.4 第 4 步：三源交叉验证

单一日志源的结论都偏弱，服务器上可做到**W3C + 事件日志 + 文件时间戳**三源交叉。**每个结论必须至少两源支撑**：

| 待验证假设 | W3C 侧 | 事件日志侧 | 文件系统侧 |
|---|---|---|---|
| 上传了脚本 | `PUT` 或对 `/upload/` 的 `POST` 且非 4xx | 4688/Sysmon 1：`w3wp.exe` 写文件 | 上传目录新增文件，时间戳对齐 |
| webshell 被执行 | 对该文件请求返回 `200` 且带查询串 | 无（脚本执行不写事件日志） | 文件存在且含服务端代码特征 |
| 提权 | `cs-username` 出现非常规账号 | 4648（Type=9）、4732（加管理员组） | 新增服务（对应 7045） |
| 反取证 | 某些日期日志**整体缺失** | 1102 / 4719 / 6008 | `$UsnJrnl` 中的删除记录 |
| 更早历史不可查 | — | `FileSize ≈ MaximumSizeInBytes` | **→ 报告局限项** |

---
<a id="section-15"></a>

## 四、常见陷阱

服务器侧的工件选择与桌面终端差别很大：桌面端最丰富的痕迹（最近文档、跳转列表、
剪贴板）在服务器上几乎为空，而服务器上真正决定事实的几类工件
（站点配置、站点级日志、认证日志、系统级时间基准）反倒常被忽略。
本章按**工件选择、时间基准、配置前置、在线操作** 四组拆开。
<a id="section-16"></a>

### 4.1 工件选择：套用错误的心智模型

<a id="section-17"></a>

#### 陷阱 1：套用桌面终端的工件清单

**现象**

按桌面 Windows 的取证经验去服务器上找痕迹：查最近文档列表、查跳转列表、
查剪贴板历史、查缩略图缓存，最后报告写「未发现用户活动痕迹」。

**原因**

这几类工件的产生依赖于桌面环境的交互组件，而服务器安装通常**不包含这些组件**
（精简安装、Server Core、容器基础镜像）。

找不到不是没活动，而是**这些工件在这类系统上根本不产生**。
把「不存在这类工件」当作「没有活动」，等于用错误的工具得出错误的结论。

**影响**

报告出现大段「未发现」，看起来像什么都没发生，实际是取证方向错了。这类空结论会误导后续的调查方向。

**核查**

**先按角色定工件优先级，再动手。** 服务器侧建议的优先级：

- **P0（几乎必有且最关键）**：站点配置、站点级访问日志、系统认证日志
- **P1（视角色而定）**：应用自身日志、数据库审计、定时任务配置
- **P2（补充）**：文件修改时间、Prefetch、用户配置文件目录
- **不适用**：最近文档、跳转列表、剪贴板、缩略图、回收站

在报告里写明这个优先级模型，**并明确列出「本机不适用」的工件类型**。

这样即使某类工件为空，读者也知道这是环境决定的，不是遗漏。

<a id="section-18"></a>

#### 陷阱 2：把「Sysmon 无记录」写成「无异常」

**现象**

分析进程创建行为，Sysmon 日志里没有对应记录，报告写「未发现异常进程创建行为」。

**原因**

Sysmon 是**需要单独部署**的系统组件，需先安装并启用才有该通道；通道不存在时，Sysmon 日志为空是**必然结果，与系统里有没有异常行为无关**。

把「没有这个数据源」等同于「数据源里没有发现」，
是阴性结论里最严重的一类逻辑错误。

**影响**

报告给出了一个实际上不成立的阴性结论。

这类结论一旦被采信，后续即使在其他证据里发现了痕迹，
这份报告就成了「明知而未发现」的反面材料。

**核查**

**先确认数据源是否存在，再谈里面有什么。**
具体两步：

1. `Get-WinEvent -ListLog * | Where-Object LogName -match 'Sysmon'`
   确认日志通道是否存在
2. 通道存在时，再检查该通道的**已启用状态**与**最大容量**
   （可能是存在但被禁用，或容量已满导致旧记录被覆盖）

在报告里区分三种表述：

- 通道存在且有记录，检查后未发现 → 可写阴性结论
- **通道存在但未启用** → 「该主机未启用进程创建审计，未获取进程创建记录」
- **通道不存在** → 「该主机未部署相关审计组件，
  在现有数据源条件下无法获取进程创建记录」

后两种必须进「取证局限」章节，并列出**本应部署该组件但未部署**这一管理发现。

<a id="section-19"></a>

#### 陷阱 3：假设某类日志一定存在

**现象**

在报告里写「经分析 PowerShell 脚本块日志，未发现可疑脚本」，
但从未确认该日志通道是否启用。

**原因**

这类细粒度的审计通道**在 Windows 上默认全部关闭**，
需要通过组策略显式开启。默认值与「有记录」是两件事。

更麻烦的是，开启之后它们还有容量上限，长期未轮转的主机可能只有最近几天的数据。

**影响**

同陷阱 2——用一个不存在的通道支撑阴性结论。

**核查**

逐个通道先做存在性与状态检查，再决定能否用它做结论。
检查要记录三项：通道存在 / 已启用 / 记录覆盖的时间范围。
第三项尤其重要：通道有记录不代表覆盖了你需要的时间段。

同时注意版本差异：**不同 Windows 版本提供的通道集合不同**。
Server 2012 R2 与 Server 2022 的可用通道列表不一样，
不能用一份跨版本的清单去套所有目标机。

<a id="section-20"></a>

### 4.2 时间基准：先定基准，再谈时间线

<a id="section-21"></a>

#### 陷阱 4：把站点日志时间与事件日志时间直接比对

**现象**

站点访问日志显示某时有一次异常请求，事件日志显示同一时段有登录记录，
两者时间「对不上」，于是推翻了一个初步结论。

**原因**

**两者的默认时区不同。** IIS 写入的 W3C 格式日志里，
`date` 与 `time` 字段是 **UTC**，而 Windows 事件日志用的是**服务器本地时间**。

在 UTC+8 的环境里，两者直接比对会**整体错 8 小时**。而 8 小时的错位足以把因果关系完全颠倒：「先登录后访问」看起来会变成「先访问后登录」。

**影响**

时间线顺序错误，因果判断随之错误。

这类错误不会产生任何报错，因为两个时间戳格式都是合法的，工具都能正常解析。

**核查**

**合并时间线前，先建立一张时区对照表**：

| 数据源 | 原始时区 | 换算方式 | 覆盖范围 |
|---|---|---|---|
| IIS W3C 访问日志 | UTC | +08:00 | 站点 ID n 下的文件 |
| Windows 安全日志 | 本地 | 无需换算 | 主机名 + 通道 |
| 应用日志 | 待确认 | 需验证 | 应用名 |

换算后统一到一个基准时区（通常选本地时区，便于与委托方沟通），
并在报告里**显式说明换算关系**：
`本文所有时间已统一为 UTC+8；IIS 原始日志为 UTC，已加 8 小时偏移。`

验证方法：拿一条你有把握的事件（比如刚重启的记录）反查，
看换算后的时间是否与事件日志中的记录吻合。

<a id="section-22"></a>

#### 陷阱 5：不知道站点 ID 就开始分析

**现象**

在日志目录里看到 `W3SVC1`、`W3SVC2` 多个目录，
直接挑了一个开始分析，报告里称其为「目标站点」。

**原因**

**目录名里的数字是站点 ID，不是站点名**，两者之间没有可推导的关系。
ID 是创建时分配的，与站点的域名、创建顺序、名称都无关联。

而且站点被删除后 ID 不会回收，会留下**空洞**。
看到 `W3SVC1` 和 `W3SVC3` 并不表示中间没有 `W3SVC2`，只表示 `W3SVC2` 对应的站点已被删除。

**影响**

分析了一个错误的站点，得出与目标业务无关的结论。

更糟的情况是：目标站点的 ID 恰好是那个被删掉的空洞，你会得出「目标站点无日志」的结论。

**核查**

**先解析站点配置文件，建立 ID 到名称的映射。**
配置在 `applicationHost.config` 里（位于系统目录的 IIS 配置路径下），
站点元素里包含 `name` 属性与 `id` 属性。解析后产出一张对照表：

| 站点 ID | 站点名称 | 绑定的主机名 | 日志目录 | 是否存在 |
|---|---|---|---|---|

这张表本身就应该作为报告的附件。后续所有按 ID 组织的日志目录，
都要在这张表里找到对应的站点名才能进入分析。
遇到 ID 空洞时在表里标注「对应站点已删除，其历史日志可能仍留在磁盘上」——
这类残留日志常常包含有价值的历史记录。

<a id="section-23"></a>

### 4.3 配置前置与字段判读

<a id="section-24"></a>

#### 陷阱 6：只按 `u_ex*.log` 找日志文件

**现象**

在日志目录下只找 `u_ex*.log` 命名的文件，报告写「该站点无访问日志」。

**原因**

IIS 的日志文件名有多个历史形态：

- **IIS 6 时代**：`exYYMMDD.log`（按天命名，没有 `u_` 前缀）
- **默认配置**：`u_exYYMMDD.log`（`u` 表示 UTF-8 编码）
- **自定义字段后缀**：文件名尾部带 `_x` 与字段名（本文另一篇有专门说明）
- **压缩归档**：轮转后可能变成 `.gz` 或带数字后缀
- **改过日志目录**：日志目录可被改到数据盘，配置里能看到实际路径

只按一个模式匹配，漏掉的可能正是最关键的时间段。

**影响**

关键时段完全无证据，基于该时段的阴性结论不可信。

**核查**

路径从配置读，不靠默认约定；文件名用宽松模式匹配。

1. 从站点配置里读出 `logFile` 元素的 `directory` 属性，得到实际路径
2. 在该路径下用 `*.log*` 递归列出全部文件
3. 按修改时间排序，明确每个文件覆盖的时间范围
4. 归档文件先解压到工作副本，解压动作记录在案

在报告里写明：`本次分析覆盖 W3SVC3（站点名：X）的日志文件共 N 个，
时间范围 X 至 Y；W3SVC2 对应站点已删除，其历史日志文件
ex20231101.log 至 ex20231231.log 仍留在磁盘上，已一并分析。`

<a id="section-25"></a>

#### 陷阱 7：把 IIS 的 500 错误当作入侵迹象

**现象**

日志里出现多条 500 状态码，报告写「站点存在大量服务端错误，疑似异常」。

**原因**

500 是最常见的服务端错误状态码，绝大多数原因与安全无关：
应用代码抛出未处理的异常、连接池耗尽、
后端依赖超时、配置文件语法错误。

**它是一个「有问题的信号」，不是「有安全的信号」。**

**影响**

把普通的应用故障报成安全事件，误导委托方的处置方向。

**核查**

**看细分状态码**。IIS 的 `sc-substatus` 字段给出了 500 的具体原因，
不同取值指向完全不同的成因。可以据此区分：

- 指向**配置或应用逻辑**的子状态 → 运维问题，走常规排障
- 指向**请求处理链异常**的子状态 → 需要看具体请求特征，
  但仍然不能直接等同于入侵

报告中按子状态分组统计 500，而不是只给一个总数。
**「500 里有多少是配置 XML 错误、多少是应用内部错误」，
这个分布比总数有信息量得多。**

如果要判断是否存在针对该错误的信息探测行为，
需要叠加其他维度：来源 IP 的行为模式、请求的路径分布、
是否有对应的文件系统或认证日志痕迹。单一状态码不能定性。

<a id="section-26"></a>

#### 陷阱 8：把某字段的时间当唯一依据

**现象**

以文件的 `LastWriteTime` 作为判断配置是否被篡改的唯一依据。

**原因**

`LastWriteTime`（以及其 UTC 版本）在很多非篡改场景下都会被刷新：

- 复制部署（从测试环境复制配置文件到生产）
- 备份还原
- 批量修改权限时连带触发
- 某些系统组件启动时的自检行为

它是一个受多种非恶意因素影响的指标，单独使用无法支撑「被篡改」的结论。

**影响**

把正常的运维操作报成篡改。而且这种误判一旦被对方反驳，
会连带削弱报告里其他基于时间证据的结论。

**核查**

**时间证据要三源对照**，用差异来定性：

1. 文件的创建时间（`CreationTimeUtc`）——反映文件最初落盘的时刻
2. 文件的修改时间（`LastWriteTimeUtc`）——反映内容最后变化
3. **变更日志**（`$UsnJrnl`）——记录文件每一次变更的真实操作，
   包括是谁的进程触发的

判断逻辑：
- 创建时间晚于站点部署时间 → 这个文件是部署之后新增的，需要追查来源
- 修改时间远晚于创建时间 → 中间发生过改动，但改动原因可能正常
- **变更日志里有对应记录但文件系统时间对不上** → 有人在改时间，
  这才是真正的篡改信号

变更日志的判断要谨慎：它的记录是变长的，
**不能按固定偏移手工解析**，必须用支持该格式的工具；
自行解析的结果不可作为结论依据。

<a id="section-27"></a>

#### 陷阱 9：忽略配置文件的备份副本

**现象**

只提取了主配置文件，报告中给出配置的内容作为证据。

**原因**

配置目录里通常会有一个备份副本（`.bak` 后缀或类似命名）。
它的价值在于：**当主文件被改动时，备份保留的是改动前的版本。**
两份文件的时间戳差异 + 内容差异，
本身就是「配置发生过改动」的直接证据——这是纯粹的哈希对比，
可与时间戳分析交叉核对。

**影响**

放弃了现成的对照物，退而依赖容易出错的时间戳推理。

**核查**

配置类文件**连同其备份副本一起提取**，然后：

1. 计算两份文件的哈希
2. 做内容差异比对
3. 比较两份文件的修改时间
4. 若存在差异，在报告中作为**配置改动证据**单独列出

注意备份副本本身也可能是攻击者留下的干扰——
比如改完主配置后同步改了备份，让两者看起来一致。
所以备份副本的价值在于「提供了对照的可能」，
真要下结论时，还要用变更日志、文件内容的技术特征做交叉验证。

<a id="section-28"></a>

### 4.4 在线操作：改变系统状态的动作

<a id="section-29"></a>

#### 陷阱 10：在运行中的服务器上清理或修改日志

**现象**

为了「减少干扰」，把旧日志移到别处；或者出于某种考虑删除了不再需要的日志文件。

**原因**

**这是不可逆操作，且性质严重。** 移动日志改变了文件的原始位置与访问时间；
删除则永久销毁证据。更关键的是，在运行中的系统上操作会**改变系统状态**——
文件系统变更日志会记录这次操作，而这个记录本身会出现在你后续的分析中，
形成自指的混乱。

**影响**

**证据被销毁，且销毁动作被记录。** 在报告里无法解释这个变更从何而来。
如果委托方后续发现日志有缺口，这份报告会成为不利证据。

**核查**

**在线采集的原则是：只读、固定优先、记录在前。**

1. **先固定**：在任何操作前，对要采集的文件做哈希并记录采集时间
2. **只读挂载或只读复制**：使用只读方式访问，不通过文件系统写入
3. **不移动、不改名、不删除**：需要筛选内容时，在工作副本上做
4. **记录每一次在线操作**：谁、什么时间、对什么文件、做了什么、
   采集前后的哈希

如果确实需要调整采集范围（比如日志太大需要筛时间窗），
**先记录完整清单与哈希，再说明筛选规则**，让未采集的部分可追溯。

<a id="section-30"></a>

#### 陷阱 11：不查异常关机就直接用内存态工件

**现象**

直接读取 Prefetch、注册表的用户活动痕迹、最近访问记录，
作为「用户在这段时间使用过系统」的证据。

**原因**

异常关机（断电、强制重启）会让一部分内存态工件不可信。
Prefetch 依赖系统正常关机时对文件使用情况的落盘更新；
用户活动相关的注册表项也依赖正常的会话结束流程。
非正常关机时，这些数据可能是**关机前某个时刻的旧值**，
而不是关机前的最新状态。

**影响**

把过时数据当作最新证据，时间线错位。

**核查**

**先查关机事件，再决定能不能用这些工件。**
两个事件 ID 是关键：

- **6008**（意外关机）——上一次的意外关机记录，含异常关机时间
- **12**（系统启动）——本次启动时间

判断逻辑：

- 查到 6008 → 上一次是非正常关机，
  内存态工件只反映**异常关机之前**的状态，
  报告里必须注明这个时间上限
- 没有 6008 → 上一次是正常关机，内存态工件相对可靠
  （但仍需注意长时间未关机导致的数据滞后）

这个判断应该放在分析的前面做，因为它决定了后续能用哪些证据。

<a id="section-31"></a>

#### 陷阱 12：结论里没有「证据局限」章节

**现象**

报告把发现清单写完就结束了，没有一节说明哪些地方查不了、为什么查不了。

**原因**

服务器侧的限制是客观存在且无法消除的：
日志有覆盖期限、审计通道可能未启用、
循环写入的日志覆盖了更早的数据、部分内容在重启后消失。
一份没有说明边界的报告，读者无法判断结论的适用范围，
只能按「报告说的都对」或「报告说的都不对」来理解。

**影响**

结论被过度外推。而且在复核或质证环节，
没有自我限定的报告一旦有一处结论被推翻，
其余所有结论的可信度都会受影响。

**核查**

**「证据局限」是与「发现清单」平级的独立章节**，逐项写清：

- **本机不部署的组件**：如进程创建审计未启用，据此无法获取的记录类型
- **时间覆盖限制**：日志最早到 X（轮转保留策略 Y 天）、变更日志覆盖近 N 天
- **未检查的位置及原因**：为什么没查某个位置（无权限、已损坏、超出授权范围）
- **未覆盖的检测维度**：例如未做内容层面的深度特征匹配
- **阴性结论的边界**：所有「未发现」都写明检查范围与方法

推荐的表述结构：

> 本次分析未发现 X 类型的活动。该结论的范围限于：
> 已获取的 N 个日志文件（覆盖 X 至 Y）、已解析的 M 项配置。
> 未覆盖：Z 位置的日志（超出本次授权范围）、
> W 类型记录（该主机未部署相应审计组件）、
> X 时段（该时段日志已被轮转覆盖）。


<a id="section-32"></a>

## 五、案例示例

<a id="section-33"></a>

### 5.1 日志容量上限先于取证动作确定的证据边界

**场景**

查获一台 Windows Server 2019（IIS 10，承载 `digiforensics.example.com`），镜像 `DigiForensics.dd`（raw，1 TB，NTFS 起始扇区 2048），已关机。委托方要求查明"该站点是否被入侵、攻击者做了什么"。

这条路径值得先走，是因为Windows 的事件日志有一个 Linux 上没有的特性：它默认是循环覆盖的。

Security 日志默认上限 20 MB，写满就从头覆盖。

**在开始任何分析之前，必须先确认这个上限**，否则会得出"某时段没有事件 = 没发生过"的假阴性。

**处置过程**

**第 1 步 · 元问题先行**

```powershell
Get-WinEvent -ListLog Security,'Microsoft-Windows-Sysmon/Operational' |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode
# Security                          32710  20.00MB  20.00MB  Circular  ← 已写满，持续覆盖
# Microsoft-Windows-Sysmon/Operational  ——  NOT PRESENT                    ← 从未部署
```

**发现 0**：`Security` 已写满 → **只能回溯约 11 天**；Sysmon 不存在 → 进程创建无独立记录。两条必须写进报告局限。

**这两行输出里有三个字段各管一件事，缺一不可**：

| 字段 | 本案值 | 含义 |
|---|---|---|
| `RecordCount` | 32710 | 当前留存的事件条数 |
| `FileSize` vs `MaximumSizeInBytes` | 20.00MB = 20.00MB | **已写满**——**这是"正在被覆盖"的唯一直接证据** |
| `LogMode` | `Circular` | 循环模式，**覆盖而非停止记录** |

`LogMode` 还有另一个取值 `Retain`（不覆盖，但新事件被丢弃）。**两种模式的取证后果完全不同**——`Retain` 意味着日志**已停止记录**，那么最新事件反而不是最新的攻击。

第 2 步 · 反推精确的时间下界（不能只说"11 天"）

```powershell
# 取当前留存的最老一条事件
$oldest = Get-WinEvent -Path C:\evidence\Security.evtx -Oldest -MaxEvents 1
$oldest.TimeCreated
# 2024-11-03 08:14:22

# 与最新一条对比，确认覆盖仍在进行
$newest = Get-WinEvent -Path C:\evidence\Security.evtx -MaxEvents 1
"{0}  →  {1}" -f $oldest.TimeCreated, $newest.TimeCreated
# 2024-11-03 08:14:22  →  2024-11-15 11:47:03
```

精确下界是 2024-11-03 08:14:22。

这个数字必须出现在报告里。"只能回溯 11 天"是估计，"最早可查事件为 2024-11-03 08:14:22"是事实。委托方需要的是后者。

第 3 步 · 确认 IIS 侧是否有独立的留存策略

```powershell
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC2\ | Select Name, Length, LastWriteTimeUtc
# Name              Length    LastWriteTimeUtc
# u_ex241114.log    2140      2024-11-14 03:44:58    ← ★ 2.1 KB，异常小
# u_ex241113.log    52428800  2024-11-13 23:59:59    ← 50 MB
# u_ex241112.log    61361152  2024-11-12 23:59:59    ← 58.5 MB
```

IIS 的 W3C 日志不受 Security 日志的 20 MB 上限约束（它们是独立文件，由 IIS 自己的配置控制）。

**这意味着两个证据面的时间覆盖范围不同。**

必须分别计算，不能合并成一句"日志只到某天"。

**第 4 步 · 把边界写进交付物**

```markdown
证据时间边界说明：

1. Windows Security 事件日志：LogMode=Circular，FileSize 已达 MaximumSizeInBytes
   (20MB/20MB)，处于持续覆盖状态。当前留存范围为
   2024-11-03 08:14:22 至 2024-11-15 11:47:03。
   该范围之前的登录、提权、进程创建事件不可恢复。

2. Sysmon 未部署，进程创建无独立记录。进程层面证据仅能依赖
   Security 事件 4688（若审计策略启用了"进程创建"子项）。

3. IIS W3C 日志（站点 2）不受上述上限约束，但 2024-11-14 当日文件
   仅 2.1 KB，判定为异常截断（详见附件三）。
```

**结论**

| 结论 | 依据 | 强度 |
|---|---|---|
| `Security` 日志为 `Circular` 且**已写满** | `FileSize` = `MaximumSizeInBytes` = 20.00MB | **强（覆盖正在进行的直接证据）** |
| 最早可查事件为 **2024-11-03 08:14:22** | `Get-WinEvent -Oldest` | 强 |
| 2024-11-03 08:14:22 之前的事件永久不可查 | 循环覆盖机制 | 强（**局限，须写入报告**） |
| Sysmon 从未部署 | `Get-WinEvent -ListLog` 返回 NOT PRESENT | 强 |
| IIS 日志与 Security 日志**时间覆盖范围不同** | 两者留存机制独立 | 强（**不可合并陈述**） |
| IIS 2024-11-14 日志仅 2.1 KB，判定被截断 | 与相邻日期 50–58 MB 对比 | 强 |

**本节能证明**：每个证据面的时间覆盖边界，以及哪些时段的结构性不可查。
**本节不能证明**：被覆盖时段内是否发生过任何事件——**这正是必须明示的局限**。

**误判对照**

这个案例最容易出的错，是**不查 `LogMode` 就直接分析**。它的后果在报告里会变成一条超出日志记录范围的结论。

1. **判据**：**"某事件类型在日志中不存在"有两个完全不同的原因**——(a) 它没发生；(b) **日志没记它**。区分方法必须先查三件事：**该子项是否被审计策略启用**（`auditpol /get /subcategory:"Process Creation",/option:Failure`）、**日志是否循环覆盖**、**Sysmon 之类是否部署**。本案三项全部不利，所以任何"未发现进程创建"的表述都是无效结论。
2. **判据**："11 天"与"11 月 3 日 08:14:22"不是等价表述。前者是估算（基于日志大小与增长速率的推测），后者是事实（`Get-WinEvent -Oldest` 的直接输出）。在需要划定责任范围的场景（"这次入侵有没有波及上个月"）里，只有精确时间点才能回答这个问题——委托方会拿"11 月 3 日之前不可查"去决定要不要继续查上游系统。
3. **判据**：**`LogMode` 必须看，不能默认**。`Circular`（覆盖）与 `Retain`（丢弃新事件）在本案里的后果完全相反：前者是"**旧数据没了、新数据还在**"，后者是"**新数据没进来、旧数据还在**"。判断"最近有没有攻击"在前一种模式下看最新事件，在后一种模式下要看你能拿到的最后一条是不是就是最后一条。 本案是 `Circular`，所以看最新事件是对的——**但这个结论依赖于读了这个字段**。
4. **判据**："日志被截断"与"日志被循环覆盖"是两个不同的反取证行为。前者是**主动的、针对性的**（`u_ex241114.log` 只剩 2.1 KB，而相邻日期是 50–58 MB——**这是人为迹象**）；后者是**被动的、自动的**（`Security` 写满 20MB 就覆盖，与攻击者无关）。把两者混为一谈，会把"日志轮转配置不当"误报成"攻击者反取证"——这是冤枉系统管理员的典型方式。判别方法：**看截断是否只发生在特定日期**（人为 = 特定日期；轮转 = 均匀分布）。

**按错误判据走的代价**：第 1 条踩中，报告会写"未发现任何进程创建事件"。委托方会理解为"攻击者没有启动过新进程"——而实际上 `winsvc.exe` 这个进程很可能确实被创建了，只是没有独立记录。这个错误结论会直接削弱后面"已取得管理员权限"那条结论的说服力（因为它依赖 7045 事件，而不是 4688）。第 4 条踩中则会让"Security 日志写满"被写成"攻击者清除了日志"——**委托方会去追查运维，而真相只是默认配置没改**。在合规审计场景里，这种误报会让整个报告的可信度归零。

<a id="section-34"></a>

### 5.2 落地到持久化的九秒间隔与自动化操作链

**场景**

承接 5.1。委托方在看到站点文件时间线后问："上传到执行只隔了 9 秒，后面又接了提权和计划任务。这是一人手工做的，还是工具做的？"

这个问题决定了报告的**行为定性**。

"一次熟练的人工渗透"与"一次自动化的批量打点"，在风险评估与后续处置上是完全不同的两件事。

**处置过程**

**第 1 步 · 还原站点拓扑**

```powershell
# 用 3.2 的 Python 脚本解析 applicationHost.config
```

```
[2] digiforensics-site
  path=[C:\inetpub\wwwroot\digiforensics-site]
  bind=['digiforensics.example.com:80:', 'digiforensics.example.com:443:']
  log =W3C
```

**发现 1**：涉事站点 **ID = 2**，日志在 `C:\inetpub\logs\LogFiles\W3SVC2\`。后续分析全部限定该目录。

**第 2 步 · 落地文件时间线**

```powershell
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') } | Sort Name | Select Count, Name
#  312 2024-11-01   ...   308 2024-11-15
#    1 2024-11-14                  ← 孤立的一天

Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\uploads -File |
  Select Name, Length, CreationTimeUtc, LastWriteTimeUtc
# report.docx  284512  2024-11-14 03:09:41Z  2024-11-14 03:09:41Z
# up.aspx         114  2024-11-14 03:11:58Z  2024-11-14 03:11:58Z   ← 唯一 .aspx
```

**发现 2**：`uploads\up.aspx` 出现在一个"其余 300+ 文件都是文档"的目录里，**扩展名与目录功能完全不符**。

**第 3 步 · W3C 日志印证**（详见 [03](server-log-web-access-log-analysis.md)）—— 站点 2 日志在 `03:09`–`03:20` 集中出现：

| 时间 | 请求 | 判读 |
|---|---|---|
| `03:09:41` | `POST /uploads/report.docx → 200` | 正常业务上传 |
| `03:11:58` | `PUT /uploads/up.aspx → 201` | **PUT + 直接落 `.aspx`**，业务系统不会这么传 |
| `03:12:07` | `GET /uploads/up.aspx?t=1 → 200` | **首次访问返回 200 → 已被执行** |
| `03:12`–`03:40` | 214 次带 `?t=` 参数，UA 为 `-` | **空 UA，自动化** |

**发现 3**：上传 `03:11:58` → 首次执行 `03:12:07`，**间隔 9 秒**。该间隔明显低于本机正常人工操作间隔（基准见第 6 步），符合自动化工具完成"上传—验证—使用"三步的形态。

**第 4 步 · 提权与持久化**

```powershell
# Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=7045}
```

```
2024-11-14 03:26:44  WinDefendHelper  C:\Users\Public\winsvc.exe
System32\Tasks 另发现新增任务 MicrosoftUpdateHealthCheck（03:31:02Z）
```

**发现 4**：落地（03:12）→ 新服务（03:26）→ 新计划任务（03:31），**14 分钟三条持久化**，是自动化流程而非手工操作。

**第 5 步 · 反取证**——`4719`（03:02:11 改审计策略）→ `1102`（03:44:58 清 Security），且 `W3SVC2\u_ex241114.log` **仅 2.1 KB**（其他日期 15–60 MB），即当天 IIS 日志也被截断（详见 [04](server-log-web-attack-trace-reconstruction.md)）。

第 6 步 · 把 9 秒这个数字算清楚（这是定性的核心）

判断"是不是人工"，**不能靠感觉，要给出可对比的基准**：

```bash
# 同一个用户/同一台机器上，正常人工的相邻操作间隔分布
# 从 Security 事件 4688 抽取该机所有进程创建，计算相邻间隔
$ev = Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4688} |
      Sort-Object TimeCreated
$gap = for ($i=1; $i -lt $ev.Count; $i++) {
        ($ev[$i].TimeCreated - $ev[$i-1].TimeCreated).TotalSeconds }
$gap | Measure-Object -Average -Minimum -Maximum |
  Select Average, Minimum, Maximum
# Average: 412.7  Minimum: 0.3  Maximum: 8944.2
```

| 对比项 | 数值 | 判读 |
|---|---|---|
| 本机正常人工操作间隔均值 | **412.7 秒**（约 7 分钟） | 基准 |
| 本机最快的一次间隔 | 0.3 秒 | 存在自动化场景的先例 |
| **`up.aspx` 上传 → 首次执行** | **9 秒** | 远低于人工均值 |
| 落地 → 建服务 | **约 14 分钟** | 略高于人工均值，**但符合"分阶段执行"** |
| 建服务 → 建计划任务 | **4 分 18 秒** | 远低于人工均值 |

结论的依据是"相对本机基线的偏离"，而不是"绝对时间"。

9 秒和 4 分 18 秒都远低于 412.7 秒的均值，而落在"最快 0.3 秒"与均值之间——这正是脚本在多步操作间的间隔分布特征。

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 站点被入侵并落地脚本 | 文件时间戳 + `PUT /uploads/up.aspx → 201`，9 秒后 200 | 强 |
| 攻击者已取得管理员权限 | 7045 新服务 `C:\Users\Public\winsvc.exe` | 强 |
| 存在计划任务持久化 | `System32\Tasks` 新增 03:31 | 中（**需内容佐证**） |
| **操作链为自动化执行，非人工交互** | 9 秒与 4 分 18 秒间隔 vs 本机 412.7 秒均值 | 强（**相对基线，非绝对值**） |
| 存在刻意反取证 | 4719 → 1102 → IIS 日志截断 + `$UsnJrnl` 删除记录 | 强 |
| `up.aspx` 的具体功能 | 磁盘上 114 字节，**本案未做内容分析** | **不可确定** |
| 11-03 之前登录历史不可查 | `Security` 写满已循环覆盖 | **局限，已明示** |

> **报告要点**：最有价值的产出是**行为链 + 反取证链两条闭合时间线**，比"抓到了脚本"本身更有分量。

行为链（落地 03:12 → 提权 03:26 → 持久化 03:31）证明入侵深度；反取证链（03:02 改审计 → 03:44 清日志）证明是有意为之。

必须明确写"11-03 之前的登录历史因日志循环覆盖不可查"，避免给出超出证据能力的结论。

**误判对照**

这个案例最容易出的错，是**用"9 秒"这个绝对数字直接下"自动化"的结论**。

数字很有说服力，但**它依赖一个本节尚未建立的基准**。

1. **判据**：判断"人工 vs 自动"必须用相对基准，不能用绝对印象。9 秒在人类看来"显然不是人做的"，但这个判断的可靠性来自"与本机正常操作分布的对比"，而不是来自"9 秒这个数很小"。判别方法：从同一台机器的历史事件里算出正常间隔的均值与中位数，**再看观测值落在分布的哪个位置**。若本案那台机器本来就是自动化运维环境（大量脚本任务），9 秒就不构成任何异常。 报告里写"该间隔显著低于本机正常操作均值 412.7 秒"比写"间隔仅 9 秒"专业得多，**且经得起复核**。
2. **判据**：`PUT` 返回 201 证明的是"文件被创建"，不是"脚本被执行"。三次请求的时序（PUT 201 → GET 200 → 后续 214 次）构成"上传—验证—使用"的**强推断**，但**200 只说明 IIS 返回了成功响应**——它不能单独证明 `up.aspx` 被 ASP.NET 成功编译执行（也可能是静态文件被返回、或一个 200 的错误页）。**严格确认需要的是**：(a) 磁盘上该文件确实是 ASP.NET 可执行内容，(b) `applicationHost.config` 的 handler 映射确实把 `.aspx` 交给 ASP.NET，(c) 响应体长度与内容形态。本案 (a)(b) 已满足，(c) 因 W3C 日志不含响应体而不可得——所以结论应写"**已被成功访问并返回 200，其执行结果未确认**"。
3. **判据**：**"新建计划任务"不等于"该任务被用于持久化"**。`System32\Tasks` 下出现新任务，只证明任务被创建。它是否指向攻击者的文件、是否被启用、是否真的执行过——这三条本案都未验证（需要读任务 XML 的 Action 路径 + 查任务执行历史）。正确表述是"存在新增计划任务，其是否为攻击者持久化待内容确认"，强度为**中**。
4. **判据**：`up.aspx` 只有 114 字节，这个尺寸本身就是一条信息，但不能替代分析。114 字节的 `.aspx` 通常是极简的转发器或一行 `Response.Write`。**但"通常"不是"必然"**——**不读内容就描述功能，是在编造**。本案**未做内容分析**，因此报告里不写它实现了什么。这类空白应当显式标注为"待分析项"，而不是用"疑似…"含糊带过。

**按错误判据走的代价**：第 1 条踩中，如果那台机器本身是自动化运维环境，报告里的"自动化操作链"结论会被委托方的技术人员一句话推翻——**而这条结论是本案定性的核心之一**。第 4 条踩中则会让报告出现"该 aspx 为一句话转发器"之类的描述，**委托方照此清理后可能发现行为完全不是这样**。在报告里把没做的事写得像做过，是取证写作里最容易被抓住、也最伤害专业声誉的一类错误。

<a id="section-35"></a>

## 六、扩展阅读方向

**先补通用 Windows 取证的地基。** 本篇只讲服务器增量，注册表、事件日志、进程痕迹的通用读法都在这一组。

- [Windows 取证工件地图](../../computer/computer-registry-log/computer-registry-log-windows-artifact-map.md)：服务器之外还需要固定哪些系统工件，以及卷影副本与回收站的取用方式。
- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md)：事件 ID 基础表、XML 结构与查询技巧。本篇的 4624/4648/4719/7045/1102 都在这里有完整语义。
- [注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md)：`TaskCache\Tree`、`Services`、`RDP-Tcp` 端口、`InetStp\Components` 的解析方法。
- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md)：通道不存在时如何写结论，以及部署后能补上哪一类证据缺口。

**再补文件层。** 服务器侧的时间线锚点大量落在文件系统上。

- [UsnJrnl 与文件操作时间线](../../computer/computer-execution/computer-execution-usn-journal-timeline.md)：判断"配置是否被篡改"的最可靠手段——变更日志里有记录但文件系统时间对不上，才是真正的篡改信号。
- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)：`$MFT` 定位、`$UsnJrnl` 所在位置，以及从镜像里 `fls` / `icat` 提取的具体做法。
- [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md)：需要更早的文件时间线时的替代来源。
- [NTFS 数据流与隐藏数据](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-alternate-data-streams.md)：ADS 与备用数据流——站点目录里的文件可能不止一个流。

**然后是本板块的具体分析。** 这四篇是本篇地图上的展开。

- [IIS 配置与日志](server-log-iis.md)：IIS 6 `MetaBase.xml` 与 IIS 7+ `applicationHost.config` 的差异、W3C 字段顺序、自定义字段后缀。
- [Web 访问日志深度分析](server-log-web-access-log-analysis.md)：SQL 注入、目录穿越、爆破的日志特征与风险打分。
- [Web 攻击痕迹还原](server-log-web-attack-trace-reconstruction.md)：`Web.config` 篡改、`bin` 目录新增 DLL、时间戳重置与清理痕迹。
- [Exchange 与邮件数据恢复](server-log-exchange.md)：`.edb` 体积巨大，ESE 数据库结构与在副本上使用 `esentutl` 的注意事项。

**最后是判据与反例。** 阴性发现与结论分寸是这一组的核心。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md)：1102/4719/6008 三件套的**识别特征**，以及时间戳被重置的判定方法。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)：证据的关联性、解释力、可采性，用来给"存在持久化"这类判断定强度。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)：镜像挂载、哈希固定与在线操作留痕的硬要求。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)：Exchange 邮件内容涉及高敏感个人信息，取用与呈现的合规要求。

<a id="section-36"></a>

## 七、命令速查

```powershell
# ===== 元问题：高价值通道是否存在、是否已覆盖 =====
Get-WinEvent -ListLog Security,System,Application,
  'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode
# FileSize ≈ MaximumSizeInBytes → 循环覆盖中（写入报告局限）

# ===== ★ 反取证三件套（每次必查）=====
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 | Select TimeCreated
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -MaxEvents 20 | Select TimeCreated
Get-WinEvent -FilterHashtable @{LogName='System';   Id=6008} -MaxEvents 5  | Select TimeCreated
Get-WinEvent -FilterHashtable @{LogName='System';   Id=7045} -MaxEvents 20 | Select TimeCreated

# ===== 站点拓扑：域名 ↔ 物理路径 ↔ 站点ID =====
Get-Website | Select Name, ID, State, PhysicalPath,
  @{n='Bindings';e={($_.Bindings.Collection.bindingInformation) -join '; '}} | Format-List
Get-WebConfigurationProperty -PSPath 'IIS:\' `
  -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name logFormat,directory
# 日志默认 C:\inetpub\logs\LogFiles\W3SVC<站点ID>\ ，文件 u_exYYMMDD.log（自定义字段时带 _x）

# ===== 站点落地文件时间线 =====
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site -Recurse -File |
  Group-Object { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd') } | Sort Name | Select Count, Name
Get-ChildItem C:\inetpub\wwwroot\digiforensics-site\uploads -File |
  Select Name, Length, CreationTimeUtc, LastWriteTimeUtc

# ===== PowerShell 4104 脚本块内容 =====
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 2000 |
  ForEach-Object { [xml]$x=$_.ToXml()
    [pscustomobject]@{ Time=$_.TimeCreated
      User=($x.Event.UserData.Data | Where-Object Name -eq 'UserId').'#text'
      Text=($x.Event.UserData.Data | Where-Object Name -eq 'ScriptBlockText').'#text' } } |
  Export-Csv C:\evidence\ps4104.csv -NoTypeInformation -Encoding UTF8

# ===== 可疑计划任务（动作指向非微软/非 Windows 目录）=====
Get-ScheduledTask | ForEach-Object { $t=$_
  $t.Actions | Where-Object { $_.Execute -and $_.Execute -notmatch '\\Microsoft\\|^[Cc]:\\Windows\\' } |
    ForEach-Object { [pscustomobject]@{ TaskPath=$t.TaskPath; TaskName=$t.TaskName
      Execute=$_.Execute; Arguments=$_.Arguments; Author=$t.Author } } } | Format-List

# ===== 注册表：RDP 端口（非 3386 需在报告中说明）=====
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' |
  Select PortNumber
```

```bash
# ===== Linux 侧：从镜像定位与提取（P0 工件）=====
fls -o 2048 -r -p /work/DigiForensics.dd > /work/filelist.txt
grep -iE 'LogFiles/W3SVC[0-9]+/.*\.log$'             /work/filelist.txt | head
grep -iE 'inetsrv/config/applicationHost\.config'    /work/filelist.txt
grep -iE 'wwwroot/digiforensics-site/.*/Web\.config$' /work/filelist.txt
grep -icE '\.evtx$'                                   /work/filelist.txt

icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/applicationHost.config
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/W3SVC2_u_ex241114.log
sha256sum /evidence/applicationHost.config /evidence/W3SVC2_u_ex241114.log
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 服务器取证 — 工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
