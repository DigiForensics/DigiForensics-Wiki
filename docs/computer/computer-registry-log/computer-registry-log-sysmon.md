---
title: "Sysmon 与 Windows 日志聚合"
slug: "computer-registry-log-sysmon"
canonical: "https://www.digiforensics.cn/wiki/computer-registry-log-sysmon"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["注册表与事件日志"]
---

# Sysmon 与 Windows 日志聚合

<a id="section-1"></a>

## 一、概述

自带事件日志撑不起入侵检测。缺陷有两头：

1. **默认什么都不记**。`4688`（进程创建）要先开「审计进程创建」，而 Windows 默认不开。命令行、哈希、父子链，一样都没有。
2. **记了就留不住**。日志定长循环覆盖，Security 默认 20 MB，活动多的机器几小时就冲干净。

Sysmon（Sysinternals 的工具）以驱动形式常驻内核，把进程创建（带完整命令行与哈希）、网络连接、DLL 加载、注册表操作写进独立通道 `Microsoft-Windows-Sysmon/Operational`。

这一篇解决三件事：**它记什么**、**怎么配**（配错等于没开）、**怎么集中采集**（把易覆盖的日志变成远端副本）。

| 维度 | 原生事件日志 | Sysmon |
|---|---|---|
| 进程命令行 | 4688 需开启审计，且**参数可能截断** | **默认记录，完整命令行** |
| 进程哈希 | 无 | SHA-1/SHA-256/MD5/IMPHASH |
| 父子关系 | 需交叉查询 | 每条自带 `ParentImage`/`ParentCommandLine` |
| 网络连接 | 需开启审计防火墙规则 | **默认记录（IPv4/IPv6/DNS）** |
| 持久化位置 | 无对应事件 | **服务、计划任务、启动项、驱动** |
| 保留策略 | 20 MB 循环 | **可配置，且支持远程转发** |

**在取证流程中的位置**：本篇横跨**部署期与取证期**两个阶段，这一点和同板块其他文章不同。取证期它是一次性证据解析（导出 `.evtx` 后离线分析，与 [事件日志深度分析](computer-registry-log-windows-event-log-analysis.md) 的方法完全一致）；部署期它是一套需要提前落地的采集设施，**错过事发时点就永远补不回来**。所以如果检材上没有 Sysmon 通道，3.1 会在很短时间内给出阴性结论，此时 Sysmon 相关的所有结论都不成立，必须换成原生日志加 MFT 加 Prefetch 的组合。**上游依赖**是事件日志的解析基础与注册表持久化位置（[注册表取证](computer-registry-log-registry-forensics.md)），Sysmon 事件 12/13/14 的判读直接建立在 Run 键与服务键的知识上。

**本篇处理的证据形态**，是一个通道加一份 XML 配置：

| 证据 | 位置或字段 | 说明 |
|---|---|---|
| 事件通道 | `Microsoft-Windows-Sysmon/Operational` | 默认不启用，要先装 Sysmon 再用 `-i` 写入注册表 |
| 单条事件 | `EventData` 里的 `RuleName`、`UtcTime`、`ProcessGuid`、`Image`、`CommandLine`、`Hashes`、`ParentImage`、`ParentCommandLine`、`User`、`LogonId` | `ProcessGuid` 是把同一进程的多条事件串起来的关键 |
| 配置文件 | `Sysmon64.xml` 或 `Sysmon.xml` | 决定 `<EventFiltering>` 里哪些 `<ProcessCreate onmatch="include">` 生效 |
| 转发配置 | 订阅管理器里的 WEF 订阅，落地在 `.evtx` 汇聚文件 | `MaxSize`、`MaxEventTime`、是否启用 |
| 版本标识 | 事件里的 `Version` 字段与配置里的 `schemaVersion` | **报告里必须写明，不同版本事件集不同** |

配置文件是本篇最容易出事的地方：一个 `<ProcessCreate>` 里既能写 `<Image path="...">`，也能写 `<CommandLine condition="contains">` 和 `<ParentImage>`，条件之间是与关系，`<Image>` 支持 `is` / `contains` / `begin with` / `end with` 及 `exclude` 变体。排除项写错一个进程名，就等于给它开了一扇免检门——第二章 2.2 之后会把这套匹配语义讲透。

某个时间窗内系统上执行过哪些程序、命令行与哈希是什么、父子链是否合理、DNS 与出站连接指向哪里、注册表持久化位置被写过什么、文件创建时间是否被篡改、某个进程是否被远程线程注入。

**Sysmon 没有部署就是没有**，此时所有阴性结论都不成立，而且**原生日志无法补上缺失的部分**——4688 不带哈希，SRUM 的粒度与保留期都不同。Sysmon 是**存在性日志**：它只记录"配置范围内发生过的事件"，配置里被 `<exclude>` 掉的对象等于不存在，而且**被排除的记录不会留痕**，你事后无法判断某类事件是没发生还是被过滤了；日志被清空或被配置改成不记录后，仍会继续产生"正常"的新事件，**只有时间戳断层，没有"清空"这个事件本身**。另外命令行与哈希证明的是"这样一件程序跑起来了"，**证明不了它做了什么**，后续行为要看文件、注册表、网络三类事件；`GrantedAccess` 判读也不能替代对目标进程内存的实际分析。

**读者前提**：需要先掌握 `.evtx` 的导出与字段解析（能读 `EventData` 的 XML 结构、知道 `Properties` 集合只给值不给字段名这件事），否则拿到 Sysmon 日志也只能干瞪眼；需要理解 `LogonId` 与 `ProcessGuid` 这两个关联字段的含义——前者把事件挂到登录会话上，后者把同一进程的多条事件串起来，这一步做不对，父子链和注入结论全部断裂；还需要知道审计策略与 Sysmon 过滤器是两套独立的开关，前者管原生日志，后者管 Sysmon，两者不通。
---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Sysmon 的工作方式

```
sysmon.exe（用户态 CLI） → 发送配置 XML → SysmonDrv.sys（内核驱动）
                                              ↓ ETW
                        Microsoft-Windows-Sysmon/Operational.evtx
```

- **驱动**在系统调用层捕获行为；**用户态进程本身是攻击面**（rootkit 可挂钩它）。
- **配置**是 XML，经 `sysmon.exe -c config.xml` 下发。**配置变更通常需要重启**（是否支持热重载以实际版本为准）。
- **日志**落在 `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`（注意 `%4` 是通道分隔符的编码，勿漏）。

推论只有一条，但很实用：Sysmon 日志和 Security 是两个独立文件，`wevtutil cl Security` 清不掉 Sysmon 日志；只清了 Security 的攻击者若没意识到 Sysmon 存在，这份证据就留在了原地。

<a id="section-4"></a>

### 2.2 ★ 事件 ID 清单

Sysmon 沿用 WMI 事件编号（1–25），但**不是每个编号都会产生数据，集合还随版本变**。下面按取证价值分类。

报告中必须写明所用的 Sysmon 版本与 `schemaVersion`。

**A. 进程与线程（最核心）**

| ID | 事件 | 关键字段 | 取证价值 |
|---|---|---|---|
| **1** | 进程创建 | `Image`、`CommandLine`、`ParentImage`、`ParentCommandLine`、`User`、`Hashes`、`LogonId` | **★★★** 一切执行的完整记录，含命令行与哈希 |
| **2** | 文件创建时间被修改 | `Image`、`NewTime`、`PreviousTime` | **★★★** **时间戳篡改的直接证据**（timestomp） |
| **3** | 网络连接 | `Image`、`DestinationIp/Port/Hostname`、`Protocol`、`Initiated` | **★★★** 出站历史，含 `Initiated=false` 的**入站** |
| **8** | **CreateRemoteThread** | `SourceImage`、`TargetImage`、`StartModule` | **★★★** **进程注入**（DLL 注入、进程镂空） |
| **10** | **ProcessAccess** | `SourceImage`、`TargetImage`、`GrantedAccess`、`CallTrace` | **★★** 凭据窃取：LSASS 被 `PROCESS_VM_READ` 打开 |
| **15** | 进程流哈希 | `Image`、`Hashes`、`Length` | **★★★** **内存加载 PE（fileless）** |
| **22** | **DNS 查询** | `QueryName`、`QueryResults`、`Image` | **★★** 域名级 C2 证据 |

**B. 文件、镜像与内核**

| ID | 事件 | 取证价值 |
|---|---|---|
| **7** | 映像加载 | **★★★** DLL 注入/侧载；`Signed=false` + 位于 `Temp` 是强信号 |
| **11 / 23** | 文件创建 / 文件删除 | ★★ 落地与清理痕迹（`TargetFilename`） |
| **12 / 13 / 14** | 注册表对象创建 / 值设置 / 键重命名 | **★★★** 持久化检测（Run 键、服务注册） |
| **6** | 驱动加载 | **★★★** 加载未签名驱动 = rootkit 强信号 |
| **5** | 进程终止 | ★ 存活时长（短命进程可能是一次性利用） |
| **17 / 18 / 19 / 20 / 21** | WMI 事件 / 命名管道 / 永久事件订阅 | ★★ 域内横向与隐蔽信道 |
| **24** | 剪贴板内容更改 | ★ 密码搬运行为 |

<a id="section-5"></a>

### 2.3 与原生日志的互补关系

**没有任何单一工件能证明入侵**。Sysmon 的价值在与原生日志互补：

| 场景 | 只有原生日志 | 只有 Sysmon | 两者结合 |
|---|---|---|---|
| 进程执行 | 4688 未开启则无；开启也缺哈希 | 完整命令行 + 哈希 | **可哈希比对威胁库** |
| 登录 | 4624 有 `TargetLogonId` | 事件 1 也带 `LogonId` | **用 `LogonId` 把进程归属到具体登录会话** |
| 服务持久化 | 7045（安装时） | 事件 12/13（注册表写入时） | **两条独立时间线互证** |
| 文件落地 | 无 | 事件 11 | 与 Prefetch（[05](../computer-execution/computer-execution-prefetch.md)）交叉 |
| 时间戳篡改 | MFT 可见但无上下文 | **事件 2 直接报告新旧时间** | **强证据** |
| 网络外联 | 需开审计 | 事件 3 + 22 | 与防火墙、SRUM（[09](../computer-browser-behavior/computer-browser-behavior-srum.md)）对照 |

> `LogonId` 是整篇的**关联枢纽**。4624 告诉你「用户 X 在 23:12 以类型 3 登录，`LogonId=0x3E7`」，Sysmon 事件 1 告诉你「这个 `LogonId` 下启动了哪些进程」。把两者按 `LogonId` 串起来，得到的是一条完整的攻击会话。

<a id="section-6"></a>

### 2.4 集中化采集：为什么必须转发

单机 Sysmon 日志照样会被覆盖——上限有限，而攻击者只要知道通道名就能清。

所以企业环境的做法是双写：

```
Sysmon 驱动
    ├─→ 本地 .evtx（缓冲，便于单机取证）
    └─→ Windows Event Forwarding（WEF）→ 远程订阅源（日志服务器 / SIEM）
```

WEF 是 Windows 内置的转发机制：日志通道订阅 `Microsoft-Windows-Sysmon/Operational`，经 WinRM 推给远程 Collector，**终端上不用装 EDR agent**。

取证上的意义很直接：**只要日志已经推到远端，本地被清空也不影响结论**。

---

<a id="section-7"></a>

## 三、操作步骤

<a id="section-8"></a>

### 3.1 第 1 步：先确认系统是否部署了 Sysmon

**这一步必须最先做**。绝大多数终端默认没有 Sysmon，查不到不是异常。

```powershell
# 活系统：查通道是否存在及其上限
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode
```

```bash
# 离线：从镜像定位日志、驱动与用户态程序
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'Sysmon'
# → /Windows/System32/sysmon64.exe            （Win8+ 无 32 位版）
# → /Windows/System32/drivers/SysmonDrv.sys
# → /Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx
```

| 检查结果 | 结论 |
|---|---|
| `.evtx` + 驱动 + 服务注册项齐全 | 已部署，继续 3.3 |
| 只有 `.evtx` 无驱动文件 | 曾部署后卸载，日志残留仍可分析 |
| 全无 | **该机从未部署 Sysmon**，改用 4688 / EDR / 其他工件 |

<a id="section-9"></a>

### 3.2 第 2 步：配置 Sysmon（现场部署的正确做法）

**配置不当等于白开**：默认配置只记事件 1 和 6，网络、注册表、DNS 全无。

```xml
<Sysmon schemaVersion="4.60">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="is not contains">\WmiPrvSE.exe</CommandLine>
    </ProcessCreate>
    <NetworkConnect onmatch="exclude">
      <DestinationIp condition="is any of">127.0.0.1;192.168.0.0/16;10.0.0.0/8;172.16.0.0/12;fe80::/10;::1</DestinationIp>
    </NetworkConnect>
    <FileCreate onmatch="exclude">
      <TargetFilename condition="is any of">%SystemRoot%\Prefetch\*;%SystemRoot%\Temp\*</TargetFilename>
    </FileCreate>
    <RegistryEvent onmatch="exclude">
      <TargetObject condition="is any of">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\*</TargetObject>
    </RegistryEvent>
  </EventFiltering>
  <Hashes>sha256,sha1,md5,imphash</Hashes>
  <ProcessAccess onmatch="exclude">
    <GrantedAccess condition="is any of">0x1000;0x1010;0x100000;0x100010;0x100020;0x100038</GrantedAccess>
  </ProcessAccess>
  <FileCreateStreamHash>on</FileCreateStreamHash>
  <DNSQuery onmatch="exclude">
    <QueryName condition="is any of">\*.microsoft.com;*.windowsupdate.com;*.msftconnecttest.com</QueryName>
  </DNSQuery>
</Sysmon>
```

| 字段 | 作用 | 建议 |
|---|---|---|
| `EventFiltering` | 各事件类型的包含/排除规则 | **必配**。不配则全是系统噪声，硬盘几天就满 |
| `Hashes` | 记录哪些哈希 | `sha256,sha1,md5,imphash` 全开，匹配不同威胁库 |
| `ProcessAccess` 的 `GrantedAccess` | 排除正常查询权限 | 排除 `0x1010`（VM_READ\|QUERY）之类，否则真信号被淹没 |
| `FileCreateStreamHash` | 计算内存流哈希 | **`on`** —— fileless 只能靠这个抓 |
| `DNSQuery` | DNS 查询日志 | 开，但排除微软域名降噪 |

```powershell
sysmon64.exe -accepteula -i Sysmon.xml     # 安装并加载配置
sysmon64.exe -c Sysmon.xml                 # 更改配置（部分版本需重启）
sysmon64.exe -d                            # 卸载（先归档日志！）
sysmon64.exe -h                            # 版本与支持的 schema
sysmon64.exe -z                            # 检查配置是否被 hash 锁定
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456   # 调大到 256 MB
```

> ⚠️ 不调大日志上限，繁忙终端的 Sysmon 日志同样会被循环覆盖。

<a id="section-10"></a>

### 3.3 第 3 步：解析 Sysmon 日志

```powershell
# 3.3.1 转 CSV：EventData 字段名成列，便于统计
EvtxECmd.exe -f C:\evidence\Sysmon.evtx --csv C:\evidence\sysmon_out
# → Sysmon_Operational.csv，列为 TimeCreated / Id / Image / CommandLine /
#   ParentImage / User / Hashes / TargetFilename / DestinationIp ...

# 3.3.2 活系统直查：★ 用 ToXml 按字段名取（见第 03 篇）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5000 |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; Image=$d['Image']; Cmd=$d['CommandLine'];
                       Parent=$d['ParentImage']; Hashes=$d['Hashes'] }
  } | Format-Table -AutoSize -Wrap
```

**核心查询场景**（CSV 版，列号以实际表头为准）：

```bash
# 事件分布：先看全局，快速定位异常类型
awk -F',' 'NR>1{print $2}' sysmon_Operational.csv | sort -n | uniq -c | sort -rn
# 临时目录执行（1进程创建）
awk -F',' '$2==1' sysmon_Operational.csv | grep -iE '\\Temp\\|\\AppData\\Local\\Temp'
# LOLBin 滥用：Office/浏览器派生子进程
grep -iE 'Image.*(winword|excel|outlook|chrome|msedge)\.exe' sysmon_Operational.csv | grep -iE 'ParentImage.*(explorer|powershell|winword)'
# 凭据窃取（10ProcessAccess）
awk -F',' '$2==10' sysmon_Operational.csv | grep -i lsass | grep -v '0x1010'
# fileless（15进程流哈希）
awk -F',' '$2==15' sysmon_Operational.csv | sort -u
# C2 域名（22DNS）
awk -F',' '$2==22' sysmon_Operational.csv | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -30
```

<a id="section-11"></a>

### 3.4 第 4 步：集中化采集（WEF 配置）

终端侧只需要一个推送源订阅，把 Sysmon 日志经 WinRM 送到远端 Collector：

```powershell
# 1) Collector 侧（Windows Server，管理员）：允许 WEF 推送
wevtutil set subscriptionmanager "https://collector.example.com:5986/subscription" /refresh:60 /d:Latency:30

# 2) 客户端侧：创建指向 Collector 的推送源
New-WinEvent -SubscriptionName 'WEF-Sysmon' -Forwarded `
  -LogName 'Microsoft-Windows-Sysmon/Operational' -Destination 'collector.example.com' `
  -Protocol HTTPS -PortNumber 5986 -EventSourceName 'WEF-Sysmon-Push' `
  -PublisherName 'DigiForensics' -MessageFilePath '%SystemRoot%\System32\winevt\Messages.dll' -Force

# 3) 验证：订阅数非0 且 ForwardedEvents 有记录数
Get-WinEvent -ListPublisher | Where-Object { $_.EventSubscriptions } | Select PublisherName,EventSubscriptions
Get-WinEvent -ListLog ForwardedEvents | Select LogName,RecordCount,FileSize
```

> WEF 落地后，**本地 Sysmon 日志被清空也不影响结论**。分析远端副本时仍要用 `ToXml()` 按字段名取（见 [03](computer-registry-log-windows-event-log-analysis.md)），并核对推送源的部署时间以界定覆盖范围。
<a id="section-12"></a>

## 四、常见陷阱

本章按部署前提 → 采集提取 → 字段判读 → 集中化与结论边界归组，每条给出：现象、为什么会误判、误判代价、正确做法。

★ 标记表示该操作会**导致原始检材永久灭失或对目标系统造成不可逆改变**，执行前必须停下来确认。

<a id="section-13"></a>

### 4.1 部署前提与检材状态

<a id="section-14"></a>

#### 陷阱 1：★ 在目标机上卸载或重装 Sysmon

**现象**

在仍在线的目标机上执行 `sysmon64.exe -d` 卸载 Sysmon 以「排除干扰」。卸载完成后本地 `Microsoft-Windows-Sysmon/Operational` 通道被清空，本地证据彻底消失。

**原因**

`sysmon64.exe -d` 是**卸载命令，不是归档命令**。驱动被移除时，正在写入的日志文件一并失效。

很多人把它当成「先关掉，日志已经拷出来了」。可导出日志的时间点与卸载之间只要插入任何别的采集动作，或者导出本身因权限、未刷盘而失败，这段数据就再也取不回来了。

**影响**

卸载之后，事件 1/3/7/10 里那些**原生日志根本不存在的字段**——完整命令行、哈希、`ParentImage`、`GrantedAccess`——**永久灭失**，任何其他工件都补不回来。案件里「命令行到底是 `-enc` 还是 `-encodedcommand`」这类问题，答案可能就此永远定不下来。这是本篇唯一会直接销毁证据的操作。

**核查**

**卸载前必须完成三件事，缺一不可**：

```powershell
# 1) 确认日志当前状态并记录
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode, IsEnabled

# 2) 先归档并验证归档件可解析（不是"复制成功"就算完）
wevtutil epl 'Microsoft-Windows-Sysmon/Operational' D:\evidence\Sysmon_20241118.evtx
Get-WinEvent -Path D:\evidence\Sysmon_20241118.evtx -MaxEvents 3 | Select TimeCreated, Id

# 3) 记录驱动与配置指纹，作为"未被改动"的旁证
(Get-Item C:\Windows\System32\drivers\SysmonDrv.sys).VersionInfo.FileVersion
sysmon64.exe -z            # 若配置被 hash 锁定，会拒绝热重载
```

系统**已经离线**的话，正确做法是**根本不要执行卸载**。直接对镜像做只读提取：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'Sysmon'
# 目标文件：C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

只有在活系统上、且归档件已被独立验证可解析之后，才考虑卸载。默认选择是不卸载。

<a id="section-15"></a>

#### 陷阱 2：把"通道不存在"读成"未被入侵"

**现象**

镜像里搜不到 `SysmonDrv.sys` 与 `Microsoft-Windows-Sysmon%4Operational.evtx`，报告就写「该终端未部署 Sysmon，未发现异常进程创建记录」。

**原因**

**绝大多数终端默认就没有 Sysmon。** 它不是 Windows 内置组件，要用 `sysmon.exe -i` 显式安装。查不到只说明**这台机器没开这扇观察窗口**，与是否发生过入侵没有因果关系。

若同时 `4688` 的审计策略也没开，整条执行链路上就只剩 Prefetch、Amcache、ShimCache、SRUM 这些**不记录完整命令行**的旁证。

**影响**

方向性最糟的一种错：把**「没有观察」写成「没有发生」**。委托方据此认为该终端干净，而实际可能连一条进程创建记录都不存在。

**核查**

**先做部署判定，再定结论强度**：

| 判定结果 | 该终端的执行证据来源 | 报告前提句 |
| --- | --- | --- |
| Sysmon + `4688` + Prefetch 齐全 | 三条独立链路 | 「本终端执行记录具备完整命令行、哈希与父子关系」 |
| 无 Sysmon，有 Prefetch/Amcache | 启动与装入，无命令行 | 「**无法还原命令行与父子关系**；阴性结论只覆盖"未见程序启动"」 |
| 全无 | 无 | 「**本终端无进程级执行记录工件**，不作任何执行类阴性结论」 |

对应命令：

```bash
# 逐项确认，禁止只查一项就下结论
fls -r -p /work/DigiForensics.dd | grep -icE 'SysmonDrv\.sys'
fls -r -p /work/DigiForensics.dd | grep -ic 'winevt/Logs/Microsoft-Windows-Sysmon'
# 4688 审计策略：0 = 未开启
```

没有部署的终端，结论只能写「该工件不适用」，不是「未见异常」。

<a id="section-16"></a>

#### 陷阱 3：忽略事件集合随 Sysmon 版本变化

**现象**

拿一份从 Sysmon v13 导出的 CSV 查事件 22（DNS 查询）没有结果，报告就写「该时段无 DNS 外联行为」。

**原因**

Sysmon 的事件 ID 集合随版本演进，字段名也在改。 各版本可用的事件类型、配置 XML 的 `schemaVersion`、部分事件的字段名并不一致。

拿一份**版本来源不明的 CSV**，你分不清「没有结果」是真的没发生，还是下面三种情况之一：

- 采集时该版本尚未提供此类事件；
- 配置文件里对应 `<EventFiltering>` 段根本没开；
- 解析器对该版本字段解析失败，被当成空值。

**影响**

**把解析失败当成没有数据。** 这是字段驱动分析最典型的静默失效——CSV 里没有行，不等于系统里没有事件，而这句判断本身不带任何信息量。

**核查**

**三件事写进工作记录，任何一件缺失都不得出阴性结论**：

```bash
# 1) 事件分布：确认这份文件里到底有哪些 ID，先看全局
awk -F',' 'NR>1{print $2}' sysmon_Operational.csv | sort -n | uniq -c | sort -rn

# 2) 确认 CSV 列头，字段名以实际表头为准，不要照抄文档
head -1 sysmon_Operational.csv | tr ',' '\
' | nl

# 3) 原始 .evtx 里的版本与通道元数据
wevtutil gli 'Microsoft-Windows-Sysmon/Operational'
```

| 观察 | 正确表述 |
| --- | --- |
| 事件 22 在该文件中为 0 条，且确认该版本支持 | 「该时段无 DNS 查询事件记录」 |
| 事件 22 在该文件中为 0 条，版本/配置未确认 | 「**该工件不覆盖 DNS 查询**，不作 DNS 行为结论」 |
| 某事件有行但关键字段为空 | 「**字段解析异常**，需回到 .evtx 用 `ToXml()` 复核」 |

<a id="section-17"></a>

### 4.2 采集与提取环节

<a id="section-18"></a>

#### 陷阱 4：只导出 Sysmon 通道，丢掉 ForwardedEvents 与 WEF 远端副本

**现象**

在企业环境取证，只从终端提取了本机 `Microsoft-Windows-Sysmon/Operational.evtx`（32 MB，`MaximumSizeInBytes` 为 32 MB），而该终端配置了 WEF 转发。分析后得出「该时段内无异常外联」，报告未提及远端日志。

**原因**

**本地通道是环形缓冲区，转发源是另一份独立数据。** 本地 `.evtx` 满了会覆盖最旧记录，远端 Collector 里可能还留着更早、更完整的副本。反过来也成立：本地被清空但远端有完整记录。

只取本地一份，等于**主动放弃了信息量更大、且不受本地覆盖影响的那一份**。

**影响**

本地覆盖的时间窗被误读成「系统未产生日志」，而实际是事件产生过、已推送、只是本地这一份被冲掉了——**这是「日志缺失」最容易被忽略的技术成因**。

**核查**

**取证范围必须显式列出所有可能的数据落点**：

| 数据落点 | 路径/获取方式 | 取证价值 |
| --- | --- | --- |
| 本地 Sysmon 通道 | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` | 端点原始，含部署后全部 |
| 本地转发落地 | `C:\Windows\System32\winevt\Logs\ForwardedEvents.evtx` | 二次聚合，时间可能重复 |
| 推送源配置 | 注册表 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Subscriptions` | **部署时间与通道范围** |
| WEF 远端副本 | 向委托方单独调取，需带时间窗 | **覆盖最完整，不受本地覆盖影响** |

```bash
# 拉取转发源配置，判断部署边界与订阅了哪些通道
rip.exe -p /work/DigiForensics.dd -a wef.txt wef
# 关注 SubscriptionName / EventSource / ForwardedEvents / 其注册时间（MFT 时间）
```

**向委托方书面说明调取范围**，并把「本地通道 `LogMode` = `Circular` 且 `FileSize` ≈ `MaximumSizeInBytes`」这一事实写进覆盖度评估。

<a id="section-19"></a>

#### 陷阱 5：把 ForwardedEvents 与本地 Sysmon 事件去重后当作全量

**现象**

把 `ForwardedEvents.evtx` 与本地 `Sysmon.evtx` 合并统计，同一进程创建被计为两次。报告称「该时段进程创建事件 12,480 条」，实际事件数约 6,200。

**原因**

`ForwardedEvents` 记录的**本来就是从本地通道转发来的同一批事件**。两者不是互补关系，而是**同源的两份副本**。WEF 订阅一旦建立，本地日志与转发日志里的事件在时间、`EventRecordID`、内容上高度重叠。

**影响**

- **事件计数翻倍**，任何基于频次的统计（进程创建数、外联数、DNS 查询数）全部偏高；
- 更糟的情况是为避免重复做了"更保守"的去重规则，把同名但不同 `EventRecordID` 的真实多次执行合并成一次，反而**低报**了执行次数。

**核查**

**按事件唯一性而非文件名去重**：

```bash
# 1) 先看两边各有多少、以及 ID 分布
awk -F',' 'NR>1{print $2}' sysmon_Operational.csv  | sort -n | uniq -c | sort -rn
awk -F',' 'NR>1{print $2}' forwardedevents.csv   | sort -n | uniq -c | sort -rn

# 2) 用「时间 + ID + Image + 关键字段」做复合指纹去重，不要只按时间戳
awk -F',' 'NR>1{print $1","$2","$4}' sysmon_Operational.csv | sort -u > /tmp/a.ids
awk -F',' 'NR>1{print $1","$2","$4}' forwardedevents.csv  | sort -u > /tmp/b.ids
comm -23 /tmp/b.ids /tmp/a.ids | wc -l    # 仅远端有的记录数
```

报告里写明去重口径：

> 统计基于 `Sysmon.evtx` 与 `ForwardedEvents.evtx` 的**并集**，按 `时间 + 事件 ID + Image` 去重，共 N 条；本地通道覆盖 `[T0, T1]`，远端副本覆盖 `[T0', T1']`。

<a id="section-20"></a>

#### 陷阱 6：在检材上直接用 `wevtutil` 或活系统 PowerShell 解析

**现象**

把镜像分区挂载为可写后，直接在该挂载点上运行 `Get-WinEvent -Path ...`，或用 `EvtxECmd` 对原始 `.evtx` 做修复型操作。分析后 `$UsnJrnl` 中出现大量本不该有的写入记录。

**原因**

Windows 事件日志是**有状态的二进制格式**，`.evtx` 解析要做分页读取与偏移修正。可写挂载下，光是访问就会更新目录项时间戳、触发 USN 日志写入、改变文件 `$SI` 时间。

这类改动**不改变证据内容，却污染元数据与时间线**，而元数据正是很多结论的依据。

**影响**

- 元数据污染，报告里的"文件创建/修改时间"不再可信；
- 若曾用 `esentutl /y` 之类做过修复，**原文件被改写**，失去唯一原件；
- 污染无法回退——**这是不可逆改变**。

**核查**

**原始镜像只读挂载，所有解析在副本上做**：

```bash
# 只读挂载
sudo mount -o loop,ro /work/DigiForensics.dd /mnt/ro
# 提取到工作副本（保留原始件不动）
mkdir -p /work/case/Sysmon
cp /mnt/ro/Windows/System32/winevt/Logs/'Microsoft-Windows-Sysmon%4Operational.evtx' \
   /work/case/Sysmon/Sysmon.evtx

# 挂载前后各算一次源镜像哈希，证明分析过程未改检材
sha256sum /work/DigiForensics.dd
```

需要修复或回放时，**只在副本上做**：

```powershell
# 副本上修 ESE，原始 .evtx 保持不动
esentutl /y D:\work\case\Sysmon\Sysmon.evtx "D:\work\case\Sysmon\Sysmon_repaired.evtx" /v
# 校验魔数确认是 EVTX 而不是别的
Format-Hex D:\work\case\Sysmon\Sysmon_repaired.evtx -Count 8
# → 45 6C 66 45 76 74 78 = "ElfEvtx"
```

<a id="section-21"></a>

### 4.3 字段判读

<a id="section-22"></a>

#### 陷阱 7：把 `ParentImage` 当作"父进程当前仍存活"

**现象**

Sysmon 事件 1 记录 `Image=C:\Windows\System32\cmd.exe`、`ParentImage=C:\Users\victim\Downloads\doc.exe`，报告写「`doc.exe` 创建了 `cmd.exe`」并进一步推断「`doc.exe` 是攻击者投放的样本」。

**原因**

`ParentImage` 是**创建那一刻父进程可执行文件路径的快照**，不含后续状态。四个方向都有问题：

| 问题 | 说明 |
| --- | --- |
| **无存活证明** | 父进程创建完子进程后完全可能立刻退出（如自删除启动器） |
| **无父子会话证明** | PID 会被系统复用，不同时间的同 PID 不代表同一进程 |
| **无路径证明** | 字段是字符串，不含文件哈希，无法确认那个路径上的文件当时是什么 |
| **无落地证明** | 事件 1 只说"执行了"，不说明文件何时落地、由谁落地 |

而且**方向可能反了**：常见的 Office 钓鱼里 `doc.exe` 是宏启动的父，`winword.exe` 才是入口。`ParentImage` 只给"创建者"，不给"源头"。

**影响**

把启动链的一环当成完整攻击链，**凭空造出一个并不存在的投放环节**；或反过来把真正的入口文件（`winword.exe`）排除在分析范围外。

**核查**

`ParentImage` 只用于"构建进程树"，所有结论都要落到具体工件上：

```bash
# 1) 进程树：以 (时间, PID) 建树，看异常父子组合
awk -F',' '$2==1{print $1","$7","$5","$6}' sysmon_Operational.csv | sort | head -50
#   注意列号以实际表头为准：TimeCreated / Image / ParentImage / CommandLine

# 2) LOLBin 父子组合：入口在 Office/浏览器，子进程是解释器或系统工具
grep -iE 'Image.*(winword|excel|outlook|chrome|msedge)\.exe' sysmon_Operational.csv \
  | grep -iE 'ParentImage.*(explorer|powershell|cmd|wscript|mshta)'

# 3) 父进程是否真的落地过这个文件——去事件 11 找，而不是从事件 1 推
awk -F',' '$2==11' sysmon_Operational.csv | grep -i 'Downloads\\doc\.exe'
```

用事件 1 讲"执行关系"，用事件 11 讲"落地"，用事件 7 讲"装入"——三者分开表述，不要合成一句"攻击者投放并运行了 X"。

<a id="section-23"></a>

#### 陷阱 8：把事件 11（文件创建）当"文件被修改"

**现象**

`C:\Users\victim\AppData\Roaming\config.dat` 在日志里出现了事件 11（FileCreate），报告写「攻击者于 X 时间修改了该配置文件，配置被篡改」。

**原因**

Sysmon 的文件相关事件是分开的三类，语义不重叠：

| 事件 | 语义 | 时间字段含义 |
| --- | --- | --- |
| **11** `FileCreate` | **文件被创建** | 落地时刻 |
| **23** `FileDelete` | 文件被删除 | 清除时刻 |
| **2** `FileCreateTimeChange` | **文件时间戳被改动** | 事件时间 + `NewTime` / `PreviousTime` |

事件 11 只说明"这个路径上出现了新文件"，不涉及既有内容的修改。

真正的内容修改在 Sysmon 中**没有对应的独立事件**——Sysmon 不做文件内容级监控。

**影响**

把"新建"讲成"篡改"，等于凭空构造了一个**技术过程**（改了内容），而证据只支持"写了文件"。若该路径上原本就存在同名文件，事件 11 甚至可能来自另一次覆盖式写入。

**核查**

**按你要证明的东西选事件**：

| 要证明 | 用什么 |
| --- | --- |
| 文件被落地 | 事件 11 的 `TargetFilename` + 时间；配合 MFT 的 `$SI` 与创建时间 |
| 文件被删除 | 事件 23 |
| **时间戳被篡改** | 事件 2 的 `PreviousTime` vs `NewTime` |
| **文件内容被改** | **Sysmon 不支持**——需 MFT `$LogFile`/USN、EDR 文件监控或哈希比对 |

时间戳篡改的表述模板：

> 事件 2 于 `T` 报告 `C:\...\payload.exe` 的时间戳由 `T_prev` 改为 `T_new`，二者间隔 N 天。Sysmon 事件 1 记录该文件于 `T_exec` 被执行。**内容是否被同时修改，Sysmon 无法证明。**

<a id="section-24"></a>

### 4.4 集中化与结论边界

<a id="section-25"></a>

#### 陷阱 9：把 `Initiated=false` 的网络连接当成噪声过滤

**现象**

统计外联时按 `Initiated=true` 过滤，得出「该主机仅在案发后向 185.x.x.x 发起 3 次外联」。而回连（beacon）场景的关键证据恰好在 `Initiated=false` 那一侧。

**原因**

Sysmon 事件 3 同时记录**出站发起连接**（`Initiated=true`）与**入站接受连接**（`Initiated=false`）。两者含义完全不同：

| 取值 | 含义 | 取证含义 |
| --- | --- | --- |
| `true` | 本机是连接的**发起方** | 下载、payload 拉取、上传 |
| `false` | 本机**接受**了入站连接 | **远控回连、反向 shell、横向移动的接收端** |

很多基线配置会排除内网与环回地址，这本身合理。但不能顺手把 `Initiated=false` 一并过滤——那正是入侵检测里信息量最大的一半。

**影响**

**只统计发起方向，会把"被控制"读成"没被控制"。** 恶意软件通过 DNS 隧道或被动等待指令时，本机可能几乎不主动外联，全靠入站。

**核查**

**两个方向分开统计，并在报告中并列呈现**：

```bash
# 发起与接受分别计数
awk -F',' '$2==3' sysmon_Operational.csv | grep -c 'Initiated=true'
awk -F',' '$2==3' sysmon_Operational.csv | grep -c 'Initiated=false'

# 提取接受连接的对端 IP，异常点通常在这里
awk -F',' '$2==3 && /Initiated=false/' sysmon_Operational.csv \
  | awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /DestinationIp|DestinationPort|DestinationHostname/) printf "%s ", $i; print ""}' \
  | sort | uniq -c | sort -rn | head -30
```

外联分析结论模板：

> 案发窗口 `[T0, T1]` 内，本机记录出站发起连接 N 次（对端 K 个），入站接受连接 M 次（对端 J 个）。**入站接受连接的对端 IP 与端口须单独说明**，因其指向"是否已被远端接入"，与出站流量不等价。

`DestinationHostname` 只有在配置开启 DNS 相关记录、且确实用 hostname 连接时才有值。

**为空不代表"没有域名"，只代表该字段没采到。**

> 补一条常见误判：**"看不到域名"≠"没连外部"**。多数程序直接用 IP 连接，此时 `DestinationHostname` 天然为空；DNS 查询要看事件 22 而不是事件 3。

<a id="section-26"></a>

#### 陷阱 10：把集中化采集当成"防篡改"保证

**现象**

企业已部署 WEF 转发，报告写「Sysmon 采用集中化采集，攻击者无法清除痕迹，本结论可靠」。

**原因**

WEF 确实解决了**本地覆盖**问题，但它**不是不可篡改的存储**：

- 转发链路依赖 WinRM 与 Collector 可达性，**离线、端口阻断、证书过期都会让推送静默中断**，终端上看不出任何异常；
- 远端副本最终落在 Collector 的 `.evtx` 里，**同样是可写文件**，`wevtutil cl` 或直接删文件同样有效；
- 订阅配置在**终端注册表里**，攻击者有本机管理员权限时可以删除订阅源，**让日志不再产生**。

所以 WEF 提高的是**数据留存概率与时间跨度**，不是**完整性**。

**影响**

把"提高了可获取性"当成"保证了真实性"，**在证据完整性层面引入未经论证的假设**——差一个字，结论就站不住了。

**核查**

**报告里对集中化只做事实陈述，不做安全承诺**：

| 应写 | 不应写 |
| --- | --- |
| 「订阅源 `WEF-Sysmon` 部署于 `T_sub`，订阅通道为 `Microsoft-Windows-Sysmon/Operational`」 | 「Sysmon 无法被清除」 |
| 「远端副本覆盖 `[T0', T1']`，本地通道覆盖 `[T0, T1]`」 | 「日志不会丢失」 |
| 「推送中断期间本地通道仍为环形覆盖，超过 `MaximumSizeInBytes` 后**存在覆盖缺口**」 | 「有远端备份所以完整」 |

必须核对的两个事实：

```powershell
# 1) 订阅是否存在、订阅了哪些通道、部署时间（注册表键的 MFT 时间）
#    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Subscriptions\<Name>
# 2) 推送是否真的在工作：ForwardedEvents 是否有新增记录、最后记录时间
Get-WinEvent -ListLog ForwardedEvents | Select RecordCount, FileSize
Get-WinEvent -Path ForwardedEvents.evtx -MaxEvents 1 | Select TimeCreated
```

「最后一条远端记录时间」与「案发时间」的先后关系，是覆盖度评估的直接依据——远端记录早于案发很久，就说明案发时段之后的推送可能已经中断。
<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 覆盖边界确认后 Sysmon 事件分布勾出攻击链指纹

**场景**

某企业怀疑一台 Windows 11 员工机遭钓鱼入侵。委托方提供磁盘镜像 `DigiForensics.dd`（raw，500 GB，NTFS 起始扇区 2048），并已导出**部署了 Sysmon v15** 的终端日志 `Sysmon.evtx`（32 MB）。事发日期 2024-11-18，系统已正常关机。

**处置过程**

第一步，确认部署时间与覆盖边界——没有这一步，后面所有否定性结论都无从谈起：

```powershell
Get-WinEvent -Path C:\evidence\Sysmon.evtx | Sort-Object TimeCreated |
  Select-Object -First 1 TimeCreated
# → 2024-11-02 08:14:22
Get-WinEvent -Path C:\evidence\Sysmon.evtx |
  Sort-Object TimeCreated | Select-Object -Last 1 TimeCreated
# → 2024-11-18 11:41:55
```

| 发现 | 值 |
|---|---|
| Sysmon 部署日期 | 2024-11-02（日志最早记录） |
| 事发日期 | 2024-11-18 |
| 覆盖范围 | **11-02 至关机全程覆盖**，可放心下结论 |
| 日志大小 | 32 MB / 上限 256 MB，**未覆盖** |

第二步，看事件类型全局分布：

```bash
EvtxECmd.exe -f C:\evidence\Sysmon.evtx --csv C:\evidence\sysmon_out
awk -F',' 'NR>1{print $2}' sysmon_Operational.csv | sort -n | uniq -c | sort -rn
```

```text
 48213  1  进程创建          1207  7  映像加载         3  15  进程流哈希（fileless 信号）
  3104  3  网络连接            486 11  文件创建         1  2   文件时间被修改（timestomp）
    42 10  ProcessAccess        12  8  远程线程         1 22   DNS 查询
```

第三步，把近乎为零的事件类型视为异常信号，而不是噪音：

```bash
python3 - <<'PY'
base = {1:48213, 3:3104, 7:1207, 11:486, 10:42, 8:12, 15:3, 2:1, 22:1}
rare = {2:"文件时间被修改 → timestomp", 8:"远程线程 → 进程注入",
        10:"ProcessAccess → 凭据访问", 15:"进程流哈希 → 无文件执行",
        22:"DNS 查询"}
print("正常终端近乎为 0 的事件类型：")
for k in sorted(rare):
    print(f"  EventID {k:2d}  出现 {base[k]:3d} 次   → {rare[k]}")
print(f"\
五类同时出现（{len(rare)}/5）→ 不是巧合，是完整攻击链的指纹")
PY
```

第四步，确认这五类事件的实际内容形成时序：

```bash
awk -F',' '$2==8 || $2==10 || $2==15 || $2==2 || $2==22' sysmon_Operational.csv \
  | sort -t',' -k1 | awk -F',' '{print $1, "EventID="$2, $NF}' | head -8
```

```text
2024-11-18 10:31:05  EventID=22  Query=cdn-update-check[.]com
2024-11-18 10:31:07  EventID=2   pdfview.exe NewTime=2019-03-11
2024-11-18 10:42:07  EventID=8   pdfview.exe -> svchost.exe
2024-11-18 10:43:55  EventID=10  pdfview.exe -> lsass.exe GrantedAccess=0x1410
2024-11-18 10:44:31  EventID=15  Process=lsass.exe HashSHA256=…
2024-11-18 10:52:30  EventID=2   pdfview.exe PreviousTime=2024-11-18 10:31:07
```

第五步，把覆盖边界写入报告的固定表述：

```bash
python3 - <<'PY'
print("「Sysmon 于 2024-11-02 部署，本报告的否定性结论仅在 2024-11-02 至")
print(" 2024-11-18 11:41:55（日志末记录）区间内成立；该区间之前的活动需以")
print(" Prefetch、LNK、注册表等工件佐证，本报告未就该时段作否定性结论。」")
PY
```

**结论**

`Sysmon.evtx` 最早记录 2024-11-02 08:14:22、最晚 2024-11-18 11:41:55，日志大小 32 MB / 上限 256 MB 未覆盖，事发日期 11-18 完整落在覆盖区间内，可放心下结论。

事件分布上，48213 条事件 1（进程创建）、3104 条事件 3（网络连接）、1207 条事件 7（映像加载）、486 条事件 11（文件创建）属正常量级。

另一头是五类在正常终端近乎为 0 的事件同时出现：事件 10（ProcessAccess，42 次）、事件 8（远程线程，12 次）、事件 15（进程流哈希，3 次）、事件 2（文件时间被修改，1 次）、事件 22（DNS 查询，1 次）。

按时间排开，内容依次为 DNS 解析（10:31:05）→ 载荷落地与时间戳伪造（10:31:07）→ 进程注入（10:42:07）→ LSASS 访问（10:43:55）→ 内存流哈希（10:44:31）→ 时间戳二次篡改（10:52:30）。**五类同时出现不是巧合，而是完整攻击链的指纹。**

**误判对照**

最容易出错的判断，是把事件 2、8、10、15、22 这五类「数量少」的事件当成日志噪音，或者认为它们「太少说明没有实质影响」。

正确判据是把绝对数量放进基线里比。正常终端上事件 2 几乎不出现——出现即意味着有程序调用了设置文件时间的 API。事件 22 在本机只出现 **1 次**，而这一次恰好在载荷落地前 2 秒，单条即构成强信号。

按错误判据按数量排序，看「事件 1 有 48213 条才是重点」，会完全错过攻击链中最不可伪造的那几个环节。

第二处易错点是在未确认覆盖边界前就下否定性结论。正确判据是 Sysmon 的覆盖起点由**部署时间**决定（本案 2024-11-02），日志最早记录即为部署时刻；此前的任何活动**根本没有被记录**，与「没有发生」完全是两回事。按错误判据直接写「未发现更早的异常活动」，实际上只是「未部署日志，无法观测」。正确表述必须限定区间，并声明「本报告未就该时段作否定性结论」。

第三处易错点是看到「5 类稀有事件齐现」就立刻定性为 APT。定性依据不在事件种类，而在行为细节——`GrantedAccess` 的具体值（0x1410 是否包含读取内存的权限）、注入目标是否为系统进程、外联是否加密、C2 通信是否具备固定间隔。用「事件类型多」替代「行为特征分析」，在需要给出威胁等级判断时会给出过高或过低的评级。

<a id="section-29"></a>

### 5.2 DNS 落地、C2 心跳与事件 2 双时间戳证据

**场景**

已确认五类稀有事件同时出现。委托方要求重建攻击链的时序，并确认「下载先于执行」这一关键顺序，以及 C2 外传通道的规模。

**处置过程**

第一步，取全机唯一一次 DNS 查询：

```bash
awk -F',' '$2==22' sysmon_Operational.csv
```

```text
2024-11-18 10:31:05  Query=cdn-update-check[.]com  Result=185.234.219.14  Status=Success
```

第二步，取该 IP 的全部外联记录，统计节奏：

```bash
awk -F',' '$2==3' sysmon_Operational.csv | grep -i '185.234.219.14' \
  | awk -F',' '{print $1, $(NF-3), $(NF-2)}' > /evidence/c2.txt
head -3 /evidence/c2.txt; echo "..."; tail -1 /evidence/c2.txt; wc -l < /evidence/c2.txt
```

```text
2024-11-18 10:31:05   Dest=185.234.219.14:443  Initiated=true   ← 下载载荷
2024-11-18 10:31:40   Dest=185.234.219.14:443  Initiated=true
2024-11-18 10:32:20   Dest=185.234.219.14:443  Initiated=true
...
2024-11-18 11:04:12   Dest=185.234.219.14:443  Initiated=true
53
```

第三步，做间隔的统计分析以确认心跳特征：

```bash
python3 - <<'PY'
from datetime import datetime
import statistics
ts = ["10:31:05","10:31:40","10:32:20","10:32:55","10:33:31","10:34:07"]
def s(x):
    h,m,sec = map(int, x.split(":")); return h*3600+m*60+sec
gaps = [s(b)-s(a) for a, b in zip(ts, ts[1:])]
print("间隔(秒):", gaps)
print("均值:", round(statistics.mean(gaps),1), " 标准差:", round(statistics.pstdev(gaps),1))
span = s("11:04:12") - s("10:31:05")
print(f"跨度 {span} 秒 = {span/60:.1f} 分钟，共 53 次")
print("→ 低标准差 + 固定 40 秒间隔 = 心跳式外传通道")
PY
```

```text
间隔(秒): [35, 40, 35, 36, 36]
均值: 36.4  标准差: 2.0
跨度 1987 秒 = 33.1 分钟，共 53 次
```

第四步，取事件 2 的双时间戳——这是唯一直接证明 timestomp 的证据：

```bash
awk -F',' '$2==2' sysmon_Operational.csv
```

```text
2024-11-18 10:31:07  Image=C:\Users\jdoe\Downloads\pdfview.exe
                      PreviousTime=2024-11-18 10:31:07  NewTime=2019-03-11 02:14:55
2024-11-18 10:52:30  Image=C:\Users\jdoe\Downloads\pdfview.exe
                      PreviousTime=2024-11-18 10:31:07  NewTime=2019-03-11 02:14:55
```

第五步，与 NTFS 层面对照，说明为何单靠文件系统看不出来：

```bash
istat -o 2048 /work/DigiForensics.dd <inode>
```

```text
Created  : 2024-11-18 10:31:07     ← 真实
Modified : 2019-03-11 02:14:55     ← 已被改写，NTFS 层面完全看不出异常
MFT Changed : 2024-11-18 10:31:07
```

第六步，验证下载先于执行的时间顺序：

```bash
python3 - <<'PY'
seq = [("10:31:05", "EventID=22 DNS 解析 cdn-update-check[.]com"),
       ("10:31:05", "EventID=3  连接 185.234.219.14:443（下载）"),
       ("10:31:07", "EventID=11 文件创建 …\\Downloads\\pdfview.exe"),
       ("10:31:07", "EventID=1  父进程 chrome.exe（带 PDF 参数）"),
       ("10:31:40", "EventID=3  心跳外联开始"),
       ("11:04:12", "EventID=3  心跳外联结束，共 53 次")]
for t, d in seq: print(f"{t}  {d}")
print("\
★ 下载(10:31:05) → 落地(10:31:07) → 执行(10:31:07)：顺序自洽")
PY
```

**结论**

全机唯一一次 DNS 查询发生于 2024-11-18 10:31:05，域名 `cdn-update-check[.]com`（伪装成更新检查）、解析结果 `185.234.219.14`。

该 IP 的 53 次外联全部为 `Dest=185.234.219.14:443`、`Initiated=true`，从 10:31:05 持续至 11:04:12，跨度 33.1 分钟，间隔均值 36.4 秒、标准差 2.0。**固定间隔的低波动，是心跳式外传通道的典型特征。**

事件 2 两次记录都显示 `PreviousTime=2024-11-18 10:31:07`、`NewTime=2019-03-11 02:14:55`。`PreviousTime` 与 `NewTime` 这个双时间，是唯一直接证明 timestomp 的证据。

`istat` 那边看到的却是：NTFS 层 `Created` 为 2024-11-18 10:31:07、`Modified` 为 2019-03-11 02:14:55——文件系统层面完全看不出异常。

时序验证下来是自洽的：DNS 解析与下载连接（10:31:05）→ 文件创建（10:31:07，父进程 `chrome.exe` 带 PDF 参数）→ 执行（10:31:07）→ 心跳外传开始（10:31:40）→ 结束（11:04:12）。**下载先于执行。**

**误判对照**

最关键的误判，是把 `NewTime = 2019-03-11` 当成文件的真实修改时间。

正确判据是：事件 2 专门记录 `FileTime` 的变更，同时携带 `PreviousTime`（变更前）与 `NewTime`（变更后）。只要 `PreviousTime` 存在，就说明该时间被显式改写过；没有发生改动的文件不会产生事件 2 记录。

按错误判据把 2019 年当真实修改时间，会得出「该文件是 2019 年的老程序，与本次入侵无关」这个错误判断，从而放过唯一的 timestomp 直接证据。

而 `istat` 看到的 `Created = 2024-11-18 10:31:07` 与 `Modified = 2019-03-11` 的倒挂，正是需要靠事件 2 才能确证的篡改。

第二处易错点是把 53 次外联直接写成「外传了 53 份数据」或「外传了 33 分钟的数据量」。事件 3 记录的是**网络连接**，`Initiated=true` 只说明由本机发起；每次连接传输了多少字节、传了什么内容，Sysmon 里**完全不可见**。53 次心跳的流量规模可能极小（仅回传几个字节的心跳包），也可能承载大量数据。按错误判据写成具体的外传量，等于凭空生成一个数字。

正确表述是「33 分钟内建立 53 次固定间隔的加密外联，构成持续外传通道，具体传输内容与量级需由防火墙流量日志或网关侧记录补齐」。

第三处易错点是看到「下载先于执行」就认为这证明攻击者先下载、再手动运行。时间顺序只说明**先后关系**，不说明**因果机制**。本案 10:31:05 下载、10:31:07 落地并执行，只隔 2 秒，是自动化投递工具的典型行为——人手动双击至少要数十秒。解读为「人工下载后手动运行」，会误判操作主体的性质，也说明不了钓鱼附件的自动化释放机制。正确解读是「2 秒间隔表明由自动化投递工具完成下载、落地与启动，非人工交互」。

<a id="section-30"></a>

### 5.3 注入与 LSASS 访问的 GrantedAccess 判读

**场景**

委托方要求确认「凭据是否已被窃取、窃取方式是什么」。事件 10 有 42 条记录需要筛选，事件 8 有 12 条远程线程需要判断性质。

**处置过程**

第一步，筛出指向 `lsass.exe` 的进程访问并提取关键字段：

```powershell
Get-WinEvent -Path C:\evidence\Sysmon.evtx -FilterHashtable @{Id=10} |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    if ($d['TargetImage'] -match 'lsass') {
      "$($_.TimeCreated)  $($d['SourceImage'])  GrantedAccess=$($d['GrantedAccess'])" } }
```

```text
2024-11-18 10:43:55  C:\Users\jdoe\Downloads\pdfview.exe  GrantedAccess=0x1410
```

第二步，把 `GrantedAccess` 按位拆解，判断是否含读取内存权限：

```bash
python3 - <<'PY'
a = 0x1410
# Windows SDK winnt.h PROCESS_* Access Rights
# 注意 0x0400 是别名位：PROCESS_SUSPEND_RESUME 与 PROCESS_QUERY_INFORMATION 同值
rights = [(0x1000,"PROCESS_QUERY_LIMITED_INFORMATION"),
          (0x0200,"PROCESS_SET_INFORMATION"),
          (0x0400,"PROCESS_QUERY_INFORMATION"),
          (0x0100,"PROCESS_SET_QUOTA"),
          (0x0010,"PROCESS_VM_READ"),
          (0x0008,"PROCESS_VM_OPERATION"),
          (0x0020,"PROCESS_VM_WRITE"),
          (0x0040,"PROCESS_DUP_HANDLE"),
          (0x0001,"PROCESS_TERMINATE")]
seen = {}
for m, n in rights:
    if a & m: seen[m] = n
print(f"GrantedAccess = 0x{a:04X} = {a:016b}")
for m, n in sorted(seen.items()):
    print(f"  {hex(m):8s} {n}")
print("\
含 PROCESS_VM_READ(0x0010)?     ", bool(a & 0x0010))
print("含 PROCESS_VM_WRITE(0x0020)?    ", bool(a & 0x0020))
print("含 PROCESS_VM_OPERATION(0x0008)?", bool(a & 0x0008))
print("★ 0x1410 含读(0x10) → 具备读取 LSASS 内存中明文凭据的能力")
PY
```

```text
GrantedAccess = 0x1410 = 0001010000010000
  0x10     PROCESS_VM_READ
  0x400    PROCESS_QUERY_INFORMATION
  0x1000   PROCESS_QUERY_LIMITED_INFORMATION
含 PROCESS_VM_READ(0x0010)?      True
含 PROCESS_VM_WRITE(0x0020)?     False
含 PROCESS_VM_OPERATION(0x0008)? False
```

第三步，用事件 15 确认内存流被哈希，佐证实际读取：

```bash
awk -F',' '$2==15' sysmon_Operational.csv
```

```text
2024-11-18 10:44:31  Process=lsass.exe  HashSHA256=9f2a7c11…  HashType=SHA256
2024-11-18 10:45:02  Process=lsass.exe  HashSHA256=9f2a7c11…（同一内容再次被读取）
2024-11-18 10:46:18  Process=lsass.exe  HashSHA256=c41d8e05…（不同内容）
→ 连续三次对 LSASS 内存取哈希，说明在扫描凭据区域而非一次性读取
```

第四步，逐条判读 12 条远程线程，区分注入与正常行为：

```powershell
Get-WinEvent -Path C:\evidence\Sysmon.evtx -FilterHashtable @{Id=8} |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  $($d['SourceImage']) -> $($d['TargetImage'])  StartModule=$($d['StartModule'])" } |
  Sort-Object | Get-Unique
```

```text
10:42:07  …\Downloads\pdfview.exe -> svchost.exe     StartModule=（空）
10:42:19  …\Downloads\pdfview.exe -> explorer.exe    StartModule=（空）
…（其余 10 条目标均为系统进程，SourceImage 均为 pdfview.exe）
```

第五步，把两类证据的证明力分级：

```bash
python3 - <<'PY'
lv = [
 ("对 LSASS 发起含 VM_READ 的进程访问", "事件 10 GrantedAccess=0x1410", "强"),
 ("具备读取凭据的技术能力",          "权限位按位拆解确认", "强"),
 ("实际读取了 LSASS 内存内容",       "事件 15 三次连续哈希", "强"),
 ("已窃取到具体账号密码",            "—", "★ 不可认定：哈希值非凭据内容"),
 ("实施了进程注入",                  "事件 8 × 12 → 系统进程", "强"),
 ("注入目的为提权",                  "—", "待定：需看令牌/权限变化证据"),
]
for a,b,c in lv: print(f"{a:34s} | {b:30s} | {c}")
PY
```

**结论**

事件 10 中指向 `lsass.exe` 的记录为 2024-11-18 10:43:55，源进程 `C:\Users\jdoe\Downloads\pdfview.exe`，`GrantedAccess = 0x1410`。

按位拆解显示该值置位了三项：`PROCESS_VM_READ`（0x0010）、`PROCESS_QUERY_INFORMATION`（0x0400）、`PROCESS_QUERY_LIMITED_INFORMATION`（0x1000）。含 `PROCESS_VM_READ` 即具备读取 LSASS 内存中明文凭据的能力。

值得单独指出的是 `0x0010` 这一位：它是唯一与凭据读取直接相关的位，其余两项都只涉及查询。位域分析的价值就在这里——`0x1410` 是个 20 位的数字，肉眼看不出它带了内存读权限。

事件 15 记录 10:44:31、10:45:02、10:46:18 三次对 `lsass.exe` 取 `HashSHA256`（前两次为同一内容 `9f2a7c11…`，第三次为不同内容 `c41d8e05…`），说明在**连续扫描凭据区域**，而不是一次性读取。

事件 8 的 12 条远程线程源进程均为 `pdfview.exe`，目标为 `svchost.exe`、`explorer.exe` 等系统进程。

证明力分级结果：具备读取能力为强证据、实际读取为强证据、**「已窃取到具体账号密码」不可认定**（哈希值不是凭据内容）。

**误判对照**

最容易出现的错误，是把 `GrantedAccess = 0x1410` 当成一个不透明的数字，直接写「具有完全访问权限」。

正确判据是：`GrantedAccess` 是位域，必须按位拆解后逐项判读。`0x1410` 置位的是 `PROCESS_VM_READ`（读内存，本案关键）、`PROCESS_QUERY_INFORMATION`、`PROCESS_QUERY_LIMITED_INFORMATION`，而**不含** `PROCESS_VM_WRITE`（0x0020）与 `PROCESS_VM_OPERATION`（0x0008）。

笼统写成「完全访问」会失去判读精度。更危险的是在别的案件里遇到带 `0x0020` 的值（例如 `0x1430`，即在 `0x1410` 基础上加写权限）却误判为与本案同等——读写内存的定性完全不同，写入 LSASS 内存意味着还可能注入凭据或篡改。

顺带说清一个容易搞混的点：`0x1418` 与 `0x1410` 差的两位是 `0x0008` 和 `0x0001`，落在 `PROCESS_VM_OPERATION` 和 `PROCESS_TERMINATE` 上，**不是** `PROCESS_VM_WRITE`。差一个十六进制位就把「只读」定性错，这在位域判读里很常见。

第二处易错点，是把「对 LSASS 发起含 VM_READ 的访问」直接等同于「凭据已被窃取」。**能力与结果是两个层次**：访问权限只说明技术上可以读取；实际读没读、读到了什么，要靠事件 15（进程流哈希）或内存镜像佐证。

直接写「凭据已被窃取」，就是在没有内容证据的情况下把结论说满了。一旦复核人要求出示窃取到的具体凭据，报告拿不出来。正确结论分两级：「具备读取能力」与「实际读取了内存内容」均为强证据，「窃取到具体账号密码」标记为不可认定。

第三处易错点是看到 12 条远程线程就写「攻击者进行了提权」。注入到系统进程确实是提权的**前提条件**，但提权本身发生，还需要令牌窃取、令牌模拟或漏洞利用等行为的证据——事件 8 只记录线程创建，不记录其后续行为。

把注入等同于提权，等于把「具备提权条件」误报成「已完成提权」。在需要精确描述攻击链阶段的报告里，这是个关键区别，也是最容易被对方攻击的地方。

---

<a id="section-31"></a>

## 六、扩展阅读方向

**前置与基础。** Sysmon 不是原生日志的替代品，而是它的超集：
4688、4624、7045 三个事件与 Sysmon 事件的字段对应关系和差异，
要先和 [《事件日志深度分析》](computer-registry-log-windows-event-log-analysis.md) 对齐一遍。
搞混两套字段名，后面所有的聚合与检索都会建在错的前提上。

**同层深入。** 拿到原始事件之后，关联分析才是产出线索的地方：
`LogonId` 用来把登录会话与进程创建串起来，`Image` 字段的哈希拿去比对威胁库，
再把各通道的时间线合并成一条。没有 `LogonId` 这根线，
孤立的进程创建事件几乎无法回答「谁跑的」。

**相邻议题。** 集中化平台解决的是采集覆盖面与留存时长，
WEF Collector 的部署、WinRM 通道的加固、Kafka 到 Elastic 的管道各有各的
失效面。检测规则是另一层，Sigma 的编写思路要贴合 Sysmon 的字段特性，
直接套用别的数据源的规则几乎必然漏报。旁路遥测也值得并排看：
EDR agent、Defender for Endpoint 的高级狩猎、ETW 消费者，
三者的覆盖面与 Sysmon 高度重叠但采样策略不同。

**工具与判据。** Sysmon 事件 15 的流哈希是主机与网络两侧的接榫，
它要和内存取证的结果配合才能定位流量的实际内容。Sysmon 给的是
主机侧的过程与文件事件，网络侧要靠连接与流量工件补齐，
见 [《网络连接与流量痕迹》](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md)。

**判据与反例。** 「Sysmon 没有记录」几乎从不等于「行为未发生」：
配置是否真正下发到端点、日志是否被轮转丢弃、采集是否在某次重启后失效，
都要先排除。目标若实际是服务器，IIS/Nginx 侧的访问与错误日志有
独立的字段体系，不要把 W3C 格式硬套进 Sysmon 的字段模型，
见 [《Web访问日志深度分析》](../../server/server-log/server-log-web-access-log-analysis.md)。

---

<a id="section-32"></a>

## 七、命令速查

```powershell
# ===== 确认部署状态 =====
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue |
  Select LogName, RecordCount, FileSize, MaximumSizeInBytes, LogMode
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sysmon.txt services   # 离线查服务注册项

# ===== 部署 / 配置 / 卸载（完整命令见 3.2）=====
sysmon64.exe -accepteula -i Sysmon.xml     # 安装并加载配置
sysmon64.exe -c Sysmon.xml                 # 更改配置（部分版本需重启）
sysmon64.exe -d                            # 卸载（先归档日志！）
sysmon64.exe -h                            # 版本与支持的 schema
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456   # 调大到 256 MB

# ===== 解析与查询（★ ToXml 按字段名取，不依赖系统语言）=====
EvtxECmd.exe -f C:\evidence\Sysmon.evtx --csv C:\evidence\sysmon_out
Get-WinEvent -Path C:\evidence\Sysmon.evtx | Group-Object Id | Select Count,Name
Get-WinEvent -Path C:\evidence\Sysmon.evtx -FilterHashtable @{Id=1} -MaxEvents 100 |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    "$($_.TimeCreated)  $($d['Image'])  <= $($d['ParentImage'])"
  }
# 事件 ID：1进程创建 2时间戳改 3网络 5进程终止 6驱动加载 7映像加载 8远程线程
#           10进程访问 11文件创建 12/13/14注册表 15内存流 17/18 WMI
#           19/20命名管道/WMI订阅 22 DNS 23文件删除 24剪贴板

# ===== 集中化 WEF 验证（配置命令见 3.4）=====
Get-WinEvent -ListPublisher | Where-Object { $_.EventSubscriptions } | Select PublisherName,EventSubscriptions
Get-WinEvent -ListLog ForwardedEvents | Select LogName,RecordCount,FileSize
```

```bash
# ===== Linux：定位与提取 =====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'Sysmon'
# → /Windows/System32/sysmon64.exe（Win8+ 无 32 位版）
# → /Windows/System32/drivers/SysmonDrv.sys
# → /Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/Sysmon.evtx

# ===== CSV 快速统计（列号以实际表头为准）=====
awk -F',' 'NR>1{print $2}' sysmon_Operational.csv | sort -n | uniq -c | sort -rn   # 事件分布
awk -F',' '$2==1'  sysmon_Operational.csv | grep -iE '\\Temp\\|\\AppData\\'   # 临时目录执行
awk -F',' '$2==10' sysmon_Operational.csv | grep -i lsass                        # 凭据窃取
awk -F',' '$2==15' sysmon_Operational.csv | sort -u                               # fileless
awk -F',' '$2==22' sysmon_Operational.csv | awk -F',' '{print $5}' | sort -u      # C2 域名
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 取证 — Sysmon 与日志聚合」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Sysmon 与日志聚合》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`Sysmon.xml` 等均为示例文件名，指向虚构或已脱敏的检材，与真实案件无关。
