---
title: "远程勘验与在线取证"
slug: "imaging-acquire-remote-evidence-collection"
canonical: "https://www.digiforensics.cn/wiki/imaging-acquire-remote-evidence-collection"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "imaging"
space: "磁盘镜像与仿真"
node_path: ["镜像采集"]
---

# 远程勘验与在线取证

<a id="section-1"></a>

## 一、概述

离线镜像是主战场，但有一类案子没有关机的那一刻：服务器还在跑、勒索还在加密、业务还在被入侵者登录。

此时任何关机动作都会**永久销毁正在发生的犯罪现场**——内存中的凭据、已解密的数据、正在运行的恶意进程。

于是产生了在线取证这个两难命题：

| 诉求 | 冲突 |
|---|---|
| **保住现场** | 需要立即采集，尤其内存 |
| **不破坏现场** | 登录、读文件、跑命令**本身就是破坏** |

关键认知：**在线取证不存在"零影响"操作**。你每敲一条命令，目标主机就多一条日志、一次登录记录、一个被更新的 `atime`。本篇要处理的问题是：

> 如何让每一处不可避免的痕迹都可解释、可归因、可在报告中明确定位。

这决定了本篇的写作取向：它不是一份"在线取证操作手册"，而是一份**"哪些痕迹是我造成的，怎么说清楚"的方法论**。技术命令在第三章，但那只是骨架；真正决定结论能不能被采信的是第四章。

**本篇处理的证据形态**（按易失程度排序，这个顺序就是采集顺序）：

| 证据 | 位置 | 采集窗口 | 手段 |
|---|---|---|---|
| **物理内存** | RAM | **秒级**（断电即失） | `WinPmem` / `LiME` / `AVML`；或 AFU、USB/PCIe 直连采集器 |
| 页面文件 | `pagefile.sys` / `swapfile.sys` | 分钟级 | 与内存镜像同期导出 |
| 运行中进程与网络连接 | 进程表、连接表、监听端口 | 秒级 | `Get-CimInstance` / `Get-NetTCPConnection` / `ss` |
| 易失日志 | 事件日志、`journalctl`、Sysmon | 小时级 | 导出 `.evtx` / 文本 |
| 临时目录与回收站 | 各类临时路径 | 分钟级 | 归档导出 |
| 远程接入通道自身的日志 | RDP 客户端日志、`OpenSSH/Operational`、WinRM 活动 | 天级 | **既是痕迹也是证据** |

**最后一行值得特别说明**：你选择什么通道接入，就在目标机上留下了什么日志。RDP 会产生 4624 类型 10 的登录事件、SSH 相对最干净、WinRM 留痕最多，而商用远控工具留下的痕迹是黑盒——法庭上很难解释"这次连接是不是勘验行为"。通道选择不是技术偏好，是证据能力的选择。

**还有一种痕迹几乎所有人都会漏**：若你用**共享的管理员凭据**登录，会更新域控上的 `lastLogonTimestamp`、触发 Kerberos 票据签发，并留下"有人正在使用这台机器"这个事实——而这本身可能触发攻击者的自毁逻辑或反取证行为。

一条登录动作改变了现场的状态，而现场还在被对方控制。

**本篇的操作主链**是七步，顺序本身就是纪律：

| 步骤 | 动作 | 关键约束 |
|---|---|---|
| 1 | 前置准备与授权留痕 | **书面授权先于任何连接** |
| 2 | 先观察，后操作 | 不登录就拿不到的先想清楚；能观察就不要动手 |
| 3 | **优先采内存** | 采集窗口以秒计，**这一步永远排第一** |
| 4 | 抽取易失日志 | 事件日志、journal、系统状态 |
| 5 | 远程录屏与命令留痕 | **每条命令都要有可回溯的记录** |
| 6 | 在线检查项清单 | 按"只读、低扰动、可解释"排序逐项执行 |
| 7 | 收工、验证与归档 | 校验所有导出文件、记录目标机最终状态 |

第 2 步"先观察、后操作"是本篇最有价值的一条经验：很多信息在你登录之前通过委托方配合就能拿到（比如让对方管理员导出日志、提供带外访问方式），而不需要你亲手在目标机上留下痕迹。**能用带外方式拿到的，就不要登录进去拿。**

**在取证流程中的位置**：本篇是**采集**环节的一条并行路径，与[镜像制作](imaging-acquire-disk-imaging-and-evidence-preservation.md)平级。**上游**是授权与接入准备（远程通道怎么开、委托方配合义务、以及跨境取证的司法边界），见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)与[证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)。**下游**是内存分析，本篇的操作直接产出 `DigiForensics-mem.raw`，分析入口见[内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md)与[内存采集方法](../../memory/memory-acquire/memory-acquire-memory-acquisition-methods.md)；网络连接侧的分析见[网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md)。**最终还要回到离线镜像做文件系统与元数据分析**——在线不能替代离线，本篇的结论只能作为补充，两类证据必须分节陈述。

系统当前有哪些进程、父子关系是什么、有哪些网络连接与监听端口、有哪些计划任务与自启动项、此刻在场的登录会话是谁、内存里有什么（已解密凭据、注入代码、明文数据）、以及远程接入者在本次勘验之前做过什么。

**在线证据无法证明"未发生的行为"**。你只能证明"此刻是这个状态"，不能证明"某件事没发生过"——系统在全程在线运行，攻击者可以随时删除证据再重建。

其次，在线采集的完整性无法验证（没有可复算的原始态哈希），可重复性也差（状态已改变，不能重来）。这两条限制必须在报告里明写，否则整个在线部分会在质证环节被整体推翻。

**读者前提**：你需要先掌握远程接入的操作能力（SSH / RDP / WinRM 至少一种）、**命令执行的证据留痕习惯**（录屏、命令日志、每条操作的时间戳），以及最关键的一条——清楚"只读"指的是"不改变被取证对象的状态语义"，而不是"零副作用"。内存采集的具体工具与完整性验证见[内存采集方法](../../memory/memory-acquire/memory-acquire-memory-acquisition-methods.md)。如果你还没拿到书面授权，本篇第三章不应该开始执行。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 远程操作会改变什么

远程接入后，以下变化会在**秒级**内发生且多数不可撤回：

| 痕迹 | 产生方式 | 对取证的影响 |
|---|---|---|
| 登录事件 | RDP/SSH/WinRM 会话建立 | 4624/4625 事件、登录类型 10 |
| 会话与授权 | `LogonSession`、Kerberos TGT 签发 | 新增的域凭据使用记录 |
| 文件 `atime` | 读取文件即更新访问时间（NTFS 默认延迟更新） | 破坏"最后访问时间"证据 |
| 内存转储 | 写文件会分配页、污染空闲列表 | 内存布局变化、部分内存残留 |
| 远程工具留痕 | 服务、计划任务、注册表 Run | 新增"非原始"痕迹 |
| 事件日志 | 每次查询都产生事件 | 4625 失败登录、`Microsoft-Windows-Sysmon` 若已装 |
| 网络状态 | 建立连接、会话保活 | 攻击者的现有连接可能被打断 |

最隐蔽的一种：若用**共享的管理员凭据**登录，会更新域控上的 `lastLogonTimestamp`、触发 Kerberos 票据签发，并留下"有人正在使用这台机器"的事实。这本身可能触发攻击者的**自毁逻辑或反取证**。

<a id="section-4"></a>

### 2.2 只读命令也未必只读

"我只用了 `tasklist` 和 `netstat`"是常见辩解，但二者都可能有害：

- `netstat`/`Get-NetTCPConnection` 枚举连接**不打断**连接，但向对方暴露了枚举行为，某些攻击者会据此判断"有人在查"。
- **进程枚举** 会为每个进程创建句柄，某些自保护驱动会响应。
- **读取 `MFT`/目录** 更新 `atime`（NTFS 延迟写入，但无法撤销已发生的更新）。

因此"只读"应理解为**不改变被取证对象的状态语义**，而不是"零副作用"。

<a id="section-5"></a>

### 2.3 内存是最易失的证据

| 介质 | 内容 | 采集窗口 |
|---|---|---|
| 物理内存 | 运行进程、解密后的密钥、注入代码、网络连接 | **秒级**（断电即失） |
| 页面文件 | 已被换出的部分内容 | 分钟级 |
| 休眠文件 `hiberfil.sys` | 休眠前内存快照 | 持久 |

**采集内存的代价**：写大文件会污染空闲内存池、可能覆盖尚未换出的页。缓解手段是**先固定证据再采**——用 AFU 或 USB 直连采集器先拷走关键区域，采完立刻做**物理内存镜像**而非仅转储。

<a id="section-6"></a>

### 2.4 远程接入通道本身也是证据

选择什么通道，决定了你留下什么痕迹：

| 通道 | 客户端留痕 | 服务端留痕 | 适用性 |
|---|---|---|---|
| **RDP** | `TerminalServices` 客户端日志、`ClientCore` 日志 | 4624 类型 10、`TSRemote*` 日志 | 需图形界面与录屏 |
| **SSH（OpenSSH）** | `OpenSSH/Operational` 事件 | 4624 类型 5、`.bash_history` | 最干净，Linux 首选 |
| **WinRM/PSRemoting** | `Microsoft-Windows-WinRM/Operational` | 大量 WMI/WSMan 活动 | 留痕最多，不建议 |
| **商用远控**（向日葵/TeamViewer 等） | 工具自身日志 | 服务项、驱动、日志 | **举证时难解释，慎用** |

**原则**：优先使用**操作系统自带、有文档、可逐条对应**的通道。商用远控工具的痕迹往往是黑盒，法庭上难以说明"这次连接是不是勘验行为"。

<a id="section-7"></a>

### 2.5 证据效力：在线 vs 离线

| 维度 | 在线采集 | 离线镜像 |
|---|---|---|
| 完整性可验证 | 弱（无法与原始态比对） | 强（哈希可复算） |
| 采集时点可证明 | 依赖操作日志与录屏 | 弱（无法知道取证前发生过什么） |
| 内存与易失数据 | ✅ 唯一来源 | ❌ 完全丧失 |
| 可重复性 | 差（状态已改变） | 强（可反复分析） |
| 抗辩能力 | 中（取决于留痕质量） | 高 |

**结论**：在线采集**不能替代**离线镜像，只是**补充**。两者必须分节陈述，并明确"系统全程在线运行，不存在对'未发生行为'的证明力"。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：前置准备与授权留痕

远程勘验的前提是**书面的、范围明确的授权**。开始前必须固定：目标主机、时间窗、允许与禁止的操作、授权人。

每条远程操作都要记录，且与会话录屏时间戳对齐。远程环境的记录要求比本地更严，因为操作人和设备往往不在同一现场，格式见 [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)。

```bash
cat > /lab/remote-session-log.md <<'EOF'
# 远程勘验操作日志 CASE-2026-0142
- 操作人 / 授权人：<姓名 + 授权文书编号>    - 目标：DigiForensics-FIN-01 (10.20.5.30)
- 通道：RDP over VPN，全程录屏             - 原则：只读优先；不安装软件；不重启；不修改文件
EOF
```

> **录屏从连接前就开始**：授权确认、目标确认、每条命令的输入与输出都要在画面里。

<a id="section-10"></a>

### 3.2 第 2 步：先观察，后操作

连接后的**前 60 秒不要敲任何命令**：先看屏幕、桌面、告警弹窗、有没有正在传输的进度条。

这本身就是高价值信息，且不产生任何日志。

```powershell
# 只读基线快照：时间、用户、启动项、会话
Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
whoami /all
query user
Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime,LocalDateTime

Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,OwningProcess
```

<a id="section-11"></a>

### 3.3 第 3 步：优先采内存

内存采集必须**最先做**，因为它最易失。用工具前先确认它是否写盘到目标机。

```powershell
# 方案 A：AVML（微软官方，内存不足时自动分块写入，兼容性最好）
.\WinPmem.exe /acquiresetting .\DigiForensics-mem.raw 2>&1 | Tee-Object .\acquire-mem.log
# 方案 B：WinPmem（需签名驱动）
.\winpmem_mini_x64_rc2.exe .\DigiForensics-mem.raw
```

采集后**立刻做三件事**：计算哈希、记录文件大小、保留采集工具本身的哈希。

```bash
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/DigiForensics-mem.raw.sha256
# 立即把内存镜像复制到干净介质，再继续在线操作
```

**顺序要求**：内存 → 关键日志 → 进程/网络信息 → 最后才考虑全盘。反过来做，内存里的东西就说不清了。

<a id="section-12"></a>

### 3.4 第 4 步：抽取易失日志

不要试图"导出全部日志"——那会产生大量新事件。**只取关键项，且用 `-Path` 精确指定**。

```powershell
# 安全日志：登录与提权（远程接入的核心痕迹）
wevtutil epl Security D:\Forensics\Security.evtx /ow:true
# 系统日志：服务与网络
wevtutil epl System D:\Forensics\System.evtx /ow:true
# 远程会话专用日志（判断"谁、何时、从哪来"）
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational D:\Forensics\TSLocal.evtx /ow:true
wevtutil epl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" D:\Forensics\RdpCore.evtx /ow:true

# 当前登录会话：按字段名取值，不用 Properties[18] 这类魔法下标（下标随版本变化，靠不住）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 | ForEach-Object {
  $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [PSCustomObject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; SrcIP=$d.IpAddress; Type=$d.LogonType }
} | Format-Table -AutoSize
```

> **`epl` 是导出而非渲染**，不会像 `Get-WinEvent` 那样在渲染过程中产生额外事件——这是"在线取证"与"事后离线取证"必须分开的根本原因。

<a id="section-13"></a>

### 3.5 第 5 步：远程录屏与命令留痕

SSH 用客户端侧 `script` 记录输入输出；RDP 用宿主机侧录屏。

```bash
# SSH：客户端侧记录全部输入输出，不在目标机安装任何东西
ssh -tt dgf-incident@10.20.5.30 |& tee -a /lab/ssh-session.log
# RDP：宿主机侧录屏，帧率 15 足够，文件可控
vlc --intf dummy --sout '#transcode{vcodec=h264,vb=2000}:std{access=file,mux=mp4,dst=/lab/remote-session.mp4}' screen:// --screen-fps 15
```

<a id="section-14"></a>

### 3.6 第 6 步：在线检查项清单

按"只读、低扰动、可解释"排序，逐项执行并记录：

```powershell
# 进程与父子关系（找异常命名、找注入）
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine |
  Sort-Object ParentProcessId | Format-Table -AutoSize

# 网络连接与监听端口（不打断）
Get-NetTCPConnection -State Established,Listen |
  Select-Object LocalPort,RemoteAddress,State,OwningProcess

# 持久化（在线视角的启动项）
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskPath,TaskName
Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue

# 登录会话（在线在场的人）
query user
Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object Id,ProcessName,MainWindowTitle

# 转储与抓包须单独授权（会挂起进程 / 产生巨量数据）
# procdump -ma <pid> D:\Forensics\proc.dmp
# dumpcap -i eth0 -w D:\Forensics\	raffic.pcap
```

<a id="section-15"></a>

### 3.7 第 7 步：收工、验证与归档

**结束判定**：主要线索已固定、继续在线的风险已大于收益，收工时按序执行：

```bash
# 1) 收工瞬间再次采内存（可选）  2) 校验所有导出文件  3) 记录目标机最终运行状态
sha256sum /evidence/DigiForensics-mem.raw /evidence/DigiForensics-*.evtx > /evidence/remote-hashes.txt
```

**报告中必须写明**：在线期间逐条执行了哪些命令；哪些痕迹由勘验行为产生（登录事件、`atime`、工具服务）；哪些结论**受在线操作影响而存在局限**；后续**是否、何时、以何种方式**做了关机镜像（若做，需说明两次状态的时间差）。

---
<a id="section-16"></a>

## 四、常见陷阱

在线取证的核心认知在一章已经写定：**在线取证不存在"零影响"操作**。所以本章的陷阱不是"如何避免改变系统"——那做不到——而是如何让每一处不可避免的痕迹都可解释、可归因、可在报告中明确定位。归组按时间顺序展开：接入前、接入时、采集时、结论时。

★ 标记只给三处会销毁或污染正在消失的现场的动作：录屏晚于登录、内存采集晚于检查、在目标机安装工具。

<a id="section-17"></a>

### 4.1 接入前：授权与留痕

<a id="section-18"></a>

#### 陷阱 1：★ 先登录再开始录屏

**现象**：先建立 RDP 连接、登上机器、看一眼屏幕确认"是这台"，然后才开始录屏或才开始写操作日志。

**原因**：授权确认与目标确认是两件必须可证的事，而它们都发生在连接动作里。先登录再录屏，会在这两件事上留下一个空档——录屏里没有的那几十秒，正是最需要证明"我确实是在获得授权后才动手"的那一段。而这个空档在事后无法补：录屏没有就是没有，不是"没录清楚"。这一条与离线流程里"拍照记录封条"是同一类要求，只是远程场景下更隐蔽，因为**人已经看到目标了，会觉得"确认过了"**。

**影响**：**勘验行为与攻击者行为无法切分**。2.4 的原则是"优先使用操作系统自带、有文档、可逐条对应的通道"，而通道留痕的价值全部建立在"从哪一秒开始"这个问题上。案例第 1 步的做法是明确的：**录屏从 VPN 拨号前开始，RDP 全程录制**——**拨号前**，不是登录前。

**核查**：**录屏从连接动作之前就开始，覆盖授权确认与目标确认**：

```bash
# 录屏在宿主机侧进行，覆盖拨号、确认、输入、输出全过程
vlc --intf dummy --sout '#transcode{vcodec=h264,vb=2000}:std{access=file,mux=mp4,dst=/lab/remote-session.mp4}' screen:// --screen-fps 15

# 操作日志在建连之前建好
cat > /lab/remote-session-log.md <<'EOF'
# 远程勘验操作日志 CASE-2026-0142
- 操作人 / 授权人：<姓名 + 授权文书编号>    - 目标：DigiForensics-FIN-01 (10.20.5.30)
- 通道：RDP over VPN，全程录屏             - 原则：只读优先；不安装软件；不重启；不修改文件
EOF
```

**远程环境的记录要求比本地更严**，因为操作人和设备往往不在同一现场——**没有录屏的远程操作，等于没有操作记录**。

<a id="section-19"></a>

#### 陷阱 2：用共享域管理员凭据登录

**现象**：手里有域管账号，直接用它登录目标服务器采集。

**原因**：2.1 把这一条单列为"最隐蔽的一种"：若用共享的管理员凭据登录，会更新域控上的 `lastLogonTimestamp`、触发 Kerberos 票据签发，并留下"有人正在使用这台机器"的事实——这本身可能触发攻击者的自毁逻辑或反取证。隐蔽之处在于这三条痕迹看起来像"正常的运维活动"，而此时你正在调查的正是入侵事件。攻击者如果还在系统内，他看到的是"域管登录了"——这可能直接触发清理逻辑。

**影响**：**可能触发自毁，而这类损失是不可逆的**。而且域控上的 `lastLogonTimestamp` 被改之后，后续用这个字段做时间线分析的结论全部要打折——它本来是"该账户最后一次交互"的证据，现在它记录的是你。

**核查**：**用独立专用账号**（3.1 的操作日志里那句 `dgf-incident@10.20.5.30` 就是这个设计）：

```powershell
# 确认当前登录身份是专用勘验账号，而不是域管
whoami /all
# 确认登录类型与来源可被区分
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 5 |
  ForEach-Object {
    $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [PSCustomObject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; SrcIP=$d.IpAddress; Type=$d.LogonType }
  } | Format-Table -AutoSize
```

**专用账号的价值在事后才显现**：案例第 4 步的判定表里，`11:40:02` / 隔离跳板 / 类型 10 这一行之所以能干净地标为"勘验行为（本次）"，前提就是它与 `10.20.5.77` 那条攻击者登录在来源 IP 与账号两个维度上都不相干。而"用域管账号登录"会让这个区分变得需要额外解释。

<a id="section-20"></a>

### 4.2 接入时：先观察还是先动手

<a id="section-21"></a>

#### 陷阱 3：★ 连接后立刻敲命令，内存采集排在后面

**现象**：连上 RDP 后马上跑一遍"标准检查脚本"，采完进程和网络信息才想起来做内存镜像。

**原因**：2.3 讲得很直接：物理内存的采集窗口是秒级（断电即失），而页面文件是分钟级、休眠文件才是持久。而"先做一轮常规检查再采内存"这个顺序的自我理由是"先摸清情况好决定采什么"——但内存里到底有什么，正是你还没摸清的那件事。

更实际的问题是：跑检查脚本的过程本身就在消耗采集窗口，而这个消耗不产生任何记录。

**影响**：**内存中被覆盖的内容永远拿不回来**。2.3 讲采集内存的代价是"写大文件会污染空闲内存池、可能覆盖尚未换出的页"——而在这之前跑的那些命令已经在改变进程布局了。缓解手段是"先固定证据再采"，而"先固定"的含义就是第一个动作。

**核查**：**内存永远第一个采**（3.3 的顺序要求：内存 → 关键日志 → 进程/网络信息 → 最后才考虑全盘）：

```powershell
# 连接后的前 60 秒不敲任何命令：先看屏幕、桌面、告警弹窗、传输进度条
# 屏幕信息本身不产生任何日志 —— 案例中的勒索进度 62% 和向日葵快捷方式就是这么来的

# 然后立刻采内存
.\WinPmem.exe /acquiresetting .\DigiForensics-mem.raw 2>&1 | Tee-Object .\acquire-mem.log
```

**采完立刻做三件事**：计算哈希、记录文件大小、保留采集工具本身的哈希：

```bash
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/DigiForensics-mem.raw.sha256
# 立即把内存镜像复制到干净介质，再继续在线操作
```

**顺序反了，内存里的东西就说不清了**——这是 3.3 那句"顺序要求"的完整含义。

<a id="section-22"></a>

#### 陷阱 4：用 `Get-WinEvent` 逐屏浏览事件日志

**现象**：在目标机上用 `Get-WinEvent` 一屏一屏翻 Security 日志，看到想看的就复制粘贴出来。

**原因**：3.4 的理由是"`epl` 是导出而非渲染，不会像 `Get-WinEvent` 那样在渲染过程中产生额外事件——这是'在线取证'与'事后离线取证'必须分开的根本原因"。这句话听起来是技术细节，实际上是**取证有效性的分界线**：在目标机上渲染事件的过程本身会生成新事件，而这些新事件会混进你正在读的那份日志里。

更隐蔽的是它对结论的影响方向——新生成的渲染事件通常带 4663 之类的对象访问事件，看起来就像有人访问了那些对象。

**影响**：**日志被自己污染，而你正在用它做判断**。这类污染的特征是时间戳集中在你操作的那几分钟，且事件类型单一（渲染相关），事后能识别——但如果没意识到它，你会把"我访问过"读成"攻击者访问过"。

**核查**：**用 `wevtutil epl` 导出后离线看**：

```powershell
# 安全日志：登录与提权（远程接入的核心痕迹）
wevtutil epl Security D:\Forensics\Security.evtx /ow:true
# 系统日志：服务与网络
wevtutil epl System D:\Forensics\System.evtx /ow:true
# 远程会话专用日志（判断"谁、何时、从哪来"）
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational D:\Forensics\TSLocal.evtx /ow:true
wevtutil epl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" D:\Forensics\RdpCore.evtx /ow:true
```

**不要试图"导出全部日志"**——那会产生大量新事件（3.4 原话），且导出的东西大部分用不上。

只取关键项，且用 `-Path` 精确指定。分析在离线副本上做。

<a id="section-23"></a>

#### 陷阱 5：★ 在目标机上安装远控或记录工具

**现象**：为了"方便操作"或"记录得清楚些"，在目标机装 TeamViewer、向日葵，或装一个自制的记录脚本。

**原因**：2.4 把商用远控那一行的适用性直接写成"举证时难解释，慎用"——而它之所以难解释，是因为痕迹是黑盒：装完之后多了一个服务、一个驱动、一条计划任务、若干自签名证书、可能还有它自己的更新行为。这些痕迹与攻击者的持久化痕迹在形态上是同类的，而你现在的工作恰恰是判断哪些持久化是攻击者留下的。

**影响**：**新增"非原始"痕迹**（2.1 表格里这一行的原话），而且自证困难——你无法用一个不可解释的痕迹体系去证明另一些痕迹的性质。案例第 2 步"桌面上有向日葵的快捷方式"是**用户自己装的**（属于要查的对象）；你现在再装一个，观察者视角就分不清了。

**核查**：**用自带工具，客户端侧记录**——目标机上不留任何东西：

```bash
# SSH：客户端侧记录全部输入输出，不在目标机安装任何东西
ssh -tt dgf-incident@10.20.5.30 |& tee -a /lab/ssh-session.log

# RDP：宿主机侧录屏
vlc --intf dummy --sout '#transcode{vcodec=h264,vb=2000}:std{access=file,mux=mp4,dst=/lab/remote-session.mp4}' screen:// --screen-fps 15
```

**通道选择本身也是证据设计**。2.4 那张表里 SSH 被评为"最干净，Linux 首选"，WinRM/PSRemoting 是"留痕最多，不建议"——原因是它产生大量 WMI/WSMan 活动，而这些活动与入侵检测系统关注的活动同源。

商用远控那一行标注的不是"不安全"，而是"不可解释"，这个区别在质证时是决定性的。

<a id="section-24"></a>

### 4.3 采集时：只读不等于零副作用

<a id="section-25"></a>

#### 陷阱 6：用 `netstat`、进程枚举这类"只读"命令后不作任何声明

**现象**：报告里写"使用 `Get-NetTCPConnection` 检查了网络连接"，但既没说这条命令会产生什么痕迹，也没说读取文件会更新 `atime`。

**原因**：2.2 的整段就是针对这个误解写的："'我只用了 tasklist 和 netstat'是常见辩解，但二者都可能有害"。而"只读"这个词在取证语境里有个明确的重定义——只读应理解为不改变被取证对象的状态语义，而不是零副作用。

这个区分看起来是措辞问题，实际后果很具体：`netstat` 枚举不打断连接，但向对方暴露了枚举行为，某些攻击者会据此判断有人在查；进程枚举会为每个进程创建句柄，某些自保护驱动会响应；读取 MFT/目录更新 `atime`。

**影响**：**报告里的过程描述与实际产生的痕迹不匹配**。委托方或复核方对照 `atime`、对照驱动日志，会发现"有人在那个时间点访问过这些文件"——而报告没说这是自己做的。

这类不一致比"没做检查"更难解释。

**核查**：已读取的文件清单和已执行的操作清单都要落到记录里，并在报告中声明：

```text
记录格式：
- 时间 + 命令全文 + 输出摘要 + 产生的已知痕迹类型
- 读取了哪些文件（按路径列出）→ 对应 atime 更新
- 枚举了哪些对象（进程/连接/服务）→ 对应句柄创建与枚举痕迹
```

**报告中的声明写法**：

> "**本次在线勘验产生的痕迹**：① RDP 登录 2 条（见第四节登录事件表）；② `TSLocal` 事件 6 条；③ 读取 `<列出路径>`，对应文件 `atime` 更新；④ 执行 `WinPmem` 采集内存，目标机本地生成 `DigiForensics-mem.raw`。
> **上述痕迹均由本次勘验行为产生，与被调查行为无关。**"

**案例第 6 步的收尾就是这个格式**：报告明确列出本次勘验产生的痕迹为"2 条 RDP 登录记录、`TSLocal` 日志 6 条、若干文件的 `atime` 更新"——注意"若干"这个词不够好，实际执行时应该写出具体文件清单。

<a id="section-26"></a>

#### 陷阱 7：采集后不立即哈希

**现象**：内存镜像和日志先放在目标机上或网络盘上，打算"收工前一起算"。

**原因**：这个习惯的动机通常是把哈希集中到收尾阶段，看起来整齐。而 3.3 的要求是采集后立刻做三件事：计算哈希、记录文件大小、保留采集工具本身的哈希——"立刻"是实质要求，不是排版偏好。

在线环境里采集物面临的变数比离线多：其他进程可能占用同一目录、目标机可能重启、传输可能中断，而这些都不会发出告警。

**影响**：**无法证明文件未被改动；结论被当作"事实"推翻**。更具体的后果是——如果采集物在未哈希的状态下被改动过，你连改动这件事都不知道，因为你没有基准值可以比。

**核查**：采集完立刻哈希，并立即把内存镜像复制到干净介质，再继续在线操作：

```bash
# 采集后立即固定
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/DigiForensics-mem.raw.sha256

# 收工时统一校验所有导出文件
sha256sum /evidence/DigiForensics-mem.raw /evidence/DigiForensics-*.evtx > /evidence/remote-hashes.txt
```

**"立即复制到干净介质"这一步也常被跳过**，理由是"内存镜像很大，等会儿一起拷"。而 3.3 那句"再继续在线操作"的意思是：复制完成之前不要在目标机上做别的操作，因为那些操作会继续改变状态。

<a id="section-27"></a>

### 4.4 结论时：证据效力与局限声明

<a id="section-28"></a>

#### 陷阱 8：忘记导出远程会话日志，无法区分攻击者与勘验行为

**现象**：采集了内存、系统日志、进程列表，但没取 `TSLocal` / `RdpCore` / `OpenSSH` 这些远程会话专用日志。

**原因**：这些日志的用途非常具体——**判断"谁、何时、从哪来"**（3.4 的注释）。而它们的必要性在勘验结束后才会显现：你需要用"攻击者的登录"和"我的登录"在同一条日志流里做对比，才能把勘验行为从被调查行为中切出去。

少取它们，切割就无法完成，而不是"证据少一点"。

**影响**：**同一条 4624 事件无法归因**。委托方看到日志里有 RDP 登录，既可能是攻击者，也可能是你——没有远程会话日志做交叉，这个歧义无法消除。而这正是远程勘验最容易被质疑的地方。

**核查**：`TSLocal` / `RdpCore` / `OpenSSH` 必取，并按来源 IP 与登录类型做双重比对：

```powershell
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational D:\Forensics\TSLocal.evtx /ow:true
wevtutil epl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" D:\Forensics\RdpCore.evtx /ow:true
```

案例第 4 步的判定表就是这个比对的结果，也是本案例的**证据核心**：

| 时间 | 来源 | 登录类型 | 判定 |
|---|---|---|---|
| 03:12:44 | `10.20.5.77` | 10 (RDP) | 攻击者（与已知跳板一致） |
| 11:40:02 | 隔离跳板 | 10 (RDP) | 勘验行为（本次） |

**两个维度缺一不可**：只有登录类型不能区分（同为 RDP），只有来源 IP 不能排除（跳板机可能也是攻击路径）。**案例这一节的判读写法值得照抄到报告里。**

<a id="section-29"></a>

#### 陷阱 9：在线取证后直接关机镜像，两份证据的时间差未说明

**现象**：在线采集结束后，等攻击者活动平息或按业务方要求关机，然后做离线镜像；报告把两份材料并列陈述但不说明时间差。

**原因**：**2.5 讲清了在线与离线在五个维度上的差异**，其中"可重复性"一行是"差（状态已改变）"——而在线与离线的结论在证据性质上是不同的。把它们并列而不作区分，等于让读者以为两者证明力相当。

而它们之间还隔着一段时间：这段时间里系统仍在运行、攻击者可能仍在活动、你无法知道发生了什么。

**影响**：**两份证据的时间差未说明**，而这正是委托方会追问的第一个问题——"你 online 看到的东西，关机后还在吗？"。更实质的问题是：在线阶段的观察结论与离线阶段的磁盘结论如果矛盾，以哪个为准，报告不说明就成了分析员的自由裁量。

**核查**：分节陈述，并明确"系统全程在线运行，不存在对'未发生行为'的证明力"（2.5 的结论原话）：

> "第二节 在线采集（时间窗 `<起>` 至 `<止>`，期间系统未重启）：取得内存镜像 11.4 GB，其中存在已解密文件内容与 3 组明文凭据。**本节结论仅反映该时间窗内的系统状态。**
> "第三节 关机后镜像（关机时间 `<时刻>`，与在线阶段相隔 `<N>` 小时）：`<主要磁盘发现>`。
> "**两阶段的时间差与影响**：关机操作在 `<时刻>` 执行。该时刻之后、关机之前的时间窗内系统仍处于运行状态，本报告未对该时段进行独立采集。"

**阴性发现的限定在这个场景尤其重要**：2.5 的结论已经写明在线采集"不能替代离线镜像，只是补充"——所以"未发现 X"在在线阶段是一个弱得多的结论，而报告必须让读者看到这层差别。

<a id="section-30"></a>

#### 陷阱 10：用 `Get-WinEvent` 的魔法下标取字段，字段错位却不报错

**现象**：用 `Properties[18]` 这样的下标去取 4624 事件里的用户名、来源 IP，取出来的值看起来像那么回事，直接写进报告。

**原因**：3.4 已经给了正确写法并说明了理由：按字段名取值，不用 `Properties[18]` 这类魔法下标（下标随版本变化，靠不住）。这个陷阱的隐蔽之处在于它不会明显报错——下标越界会报错，但下标落在合法范围内的另一个字段上不会：`Properties[8]` 可能是 `LogonType`，`Properties[12]` 可能是 `WorkstationName`，取出来的是合法值，只是不是你要的那个。

**影响**：**字段错位后，整张"登录来源"表都是错的**——而这张表恰恰是区分攻击者与勘验行为的核心证据（陷阱 8）。**错位的来源 IP 会让归因完全失效**，且因为值看起来合理，复核时很难被发现。

**核查**：**按字段名取值**，并对关键字段做一次合理性验证：

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 | ForEach-Object {
  $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [PSCustomObject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; SrcIP=$d.IpAddress; Type=$d.LogonType }
} | Format-Table -AutoSize
```

**验证方法很简单**：拿一条你已知来源的登录（通常是当前这次勘验）来对——你的源 IP 应该等于 `SrcIP`，你的用户名应该等于 `User`。对不上就是取错字段了。

这一步花十秒，能避免整张表作废。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 不得关机的勒索现场：先看屏幕再采内存

**场景**

某企业财务服务器疑似被勒索软件横向移动。`DigiForensics-FIN-01`（IP `10.20.5.30`）**仍在线运行**，且攻击者可能仍在活动。业务方要求立即处置、不得关机。委托方的问题是：攻击者现在还在系统里吗。

选择这一路径的依据是**"不得关机"这个约束把在线取证变成了唯一选项**，而在线取证的第一个动作不是敲命令，是看。

**处置过程**

**第 1 步 · 授权与前置**：按 3.1 建立操作日志，授权文书编号 `AUTH-2026-0087`，范围限定为"只读采集，不得重启、不得安装软件"；录屏从 VPN 拨号前开始，RDP 全程录制。

**第 2 步 · 观察（60 秒，不敲命令）**：屏幕上存在一个**正在运行的勒索加密进度窗口**（显示已完成 62%），桌面有向日葵的快捷方式。

这两点都是不发一条命令就获得的关键信息，且完全无副作用。

**那 60 秒的观察比后续几小时的命令更有价值**。加密进度停在 62% 这个数字，直接决定了处置顺序：不是"取证做完了再断网"，而是"先判断是让它跑完再隔离，还是现在就隔离"。如果当时直接按流程先断开网络，勒索程序会立即转入终止或销毁分支，62% 这个状态就永远看不到；如果按兵不动让它跑完，毁损面积又会扩大。

实际决策是第三条路：不停加密、不断网、不干预，只做观察与内存采集，把"何时隔离"作为一条明确建议交给委托方决策。取证人给出事实与选项，不替业务方承担停机损失——**这个边界在在线取证里比在任何其他环节都重要**。

延后处置的代价必须同时写进报告，让委托方在知情的前提下决策：勒索进度从 62% 到 100% 意味着受影响文件数从约 4.1 万涨到 6.6 万，而备份系统的最近一次完整验证是 37 天前。这个权衡不该由分析员替业务方做，也不该在报告里被省略。

**第 3 步 · 内存优先**：用 AVML 采集 `DigiForensics-mem.raw`（11.4 GB），立即哈希并复制到干净介质。

**关键发现**：内存中存在**已解密的文件内容与 3 组明文凭据**，以及 `lsass.exe` 中异常加载的 DLL。

这是磁盘镜像**永远拿不到**的信息——加密和解密都发生在内存里，磁盘上只有密文。

**第 4 步 · 关键日志与远程痕迹**：导出 `Security.evtx`、`System.evtx`、`TSLocal.evtx`、`RdpCore.evtx` 后，对 `4624` 按时间排序：

| 时间 | 来源 | 登录类型 | 判定 |
|---|---|---|---|
| 03:12:44 | `10.20.5.77` | 10 (RDP) | 攻击者（与已知跳板一致） |
| 11:40:02 | 隔离跳板 | 10 (RDP) | 勘验行为（本次） |

**第 5 步 · 在线检查项**：进程树显示加密进程为 `svhost1.exe`（父进程为未知计划任务），`Win32_StartupCommand` 与任务列表均发现该任务；`root\subscription` 未发现 WMI 持久化；`Get-NetTCPConnection` 显示 3 条到 `10.20.5.77` 的已建立连接——**在线取证动作没有打断攻击者的现有会话**。

进程名的伪装在这里值得停一下。`svhost1.exe` 与系统真实的 `svchost.exe` 只差一个字母，而 Windows 的进程列表默认把 `svchost.exe` 排在一长串同名进程中间，`svhost1.exe` 混进去并不显眼。取证的第一个观察动作应该是拉一份完整进程列表并逐条过，而不是搜索可疑关键字——按关键字搜"svchost"会把真的全捞出来，按"不在预期内的名字"看才能发现它。

另外两项阴性发现同样要按限定范围写：`root\subscription` 扫描未发现 WMI 事件订阅，这只覆盖**当前时刻的内存状态**——勒索程序若已把订阅写进注册表持久化而此刻不在内存里，扫描看不到；而任务列表的阴性只覆盖已存在的计划任务，不覆盖即将被创建的新任务。

**第 6 步 · 收工与后续**：导出文件全部哈希固定，目标机保持运行未做变更（除本次登录与导出）。

**收工前有一步最容易省掉、也最不该省**：复核自己一共动了多少台机器。本案是单台，但勒索现场的横向移动意味着取证范围随时可能扩到 `DigiForensics-FIN-01` 之外的主机。逐台列出"已采集 / 未采集 / 计划采集"并写明理由，比事后被问"还有哪台没动"要好。

同时把采集产物与目标机的对应关系固化成一张表：

```text
DigiForensics-mem.raw        <- 10.20.5.30  11:38  11,4xx,xxx,xxx 字节
DigiForensics-Security.evtx  <- 10.20.5.30  11:42  84 MB
DigiForensics-TSLocal.evtx   <- 10.20.5.30  11:42  2.1 MB
DigiForensics-RdpCore.evtx   <- 10.20.5.30  11:42  1.6 MB
DigiForensics-System.evtx    <- 10.20.5.30  11:43  12 MB
```

每行都带来源 IP 与采集时刻，这张表在后续每一条结论里都要被引用——没有这张表，"某条日志显示 X"这句话就无法验证它来自哪台机器。

**采集顺序也要记进去，因为它决定了能得出哪类结论**。内存先于日志导出，这不只是因为内存更易失——还因为一旦对目标机做任何主动操作（哪怕是导出日志本身），都可能触发攻击程序的自检逻辑。本案的处置顺序是"观察 → 内存 → 日志 → 进程/连接"，全程没有一个步骤主动终止或修改了攻击者的进程，就是为了避免把 62% 这个状态破坏掉。

反过来，如果先跑了 `taskkill` 再采内存，可能失去检查加密进程内存中密钥的机会，影响后续解密恢复。

**结论**

能证明：①内存采集取得磁盘上不存在的明文凭据，构成独立证据项并已哈希固定；②通过 `RdpCore` / `TSLocal` 的**来源 IP 与登录类型双重比对**，明确区分攻击者会话与勘验会话，满足"勘验行为可解释"的要求；③加密进程与持久化任务的存在已被在线观察记录。

**不能证明**：全程在线且未重启，**无法排除"加密完成后痕迹又被内存擦除"的可能**——内存是易失介质，运行了几个小时的应用可能已自行清理。这条局限必须写进报告。

还须限定两条阴性发现的覆盖范围，否则它们会被读成"攻击者没有做 X"：

- `root\subscription` 未发现 WMI 持久化：覆盖**观察时刻的内存状态**。若订阅已写入注册表并在采集前随进程退出而不再驻留，本次扫描看不到；对应检查应针对注册表，而注册表的完整检查属于后续离线镜像的工作范围。
- 任务列表未见其他异常计划任务：覆盖**当时已存在的任务定义**。勒索程序在内存采集完成后新建的任务不会出现在本次导出中。

这两条写法上的差别不是吹毛求疵：一句"未发现 WMI 持久化"和一句"在观察时刻的内存中未发现活动的 WMI 事件订阅"，后者在复核时经得起追问。限定范围不是削弱结论，是把结论从不可辩护变成可辩护。

还有一类阴性发现特别容易越界：**"未发现外传行为"**。在线观察能看到的只是这台机器当前的网络连接，本案的三条连接记录并不覆盖其他网段的主机。勒索程序若在 03:12 之前就用 `10.20.5.77` 把文件传走了、此刻连接已关闭，本次观察完全看不到。

所以这份报告里没有"未发现外传"这句话，取而代之的是：

```text
在 10.20.5.30 本机、观察时刻的内存与网络连接中，未发现
指向互联网的未加密外传连接。
未覆盖：其他网段主机、已关闭的历史连接、代理与 VPN 日志、
        以及本次观察窗口（11:40–12:05）之前的所有外传行为。
```

**判据**：一个"未发现"如果要成立，必须能回答"我没看哪里"。上面这段话把没看的地方一次列全，比写十句"进行了充分排查"有用。

对照同一份报告里另一条阴性发现——"未发现加密文件外传至互联网"——就能看出限定的分量。取证过程中确实在内存里看到了上传线程的代码段，但没有任何一条**已完成**的传输记录，而已完成与否恰恰无法从单点快照判断。写成"未发现已完成外传记录"是准确的；写成"未发生外传"就把一个观测问题偷换成了事实问题。

三档表述的分界线在报告里最好用表格列出来，一眼就能看出哪条结论需要限定：

| 表述 | 证据状态 | 复核风险 |
|---|---|---|
| 发现了 X | 有直接证据，可复现 | 低 |
| 未发现 X（限定范围） | 检项明确，未覆盖项已列出 | 中，可辩护 |
| 未发生 X | 无观测支持，纯推定 | 高，必被推翻 |

第三档在实务中并不少见，危害也不在于那一句话本身——在于它常常被当成第一档来引用，随后整条论证都建立在一个没人验证过的否定之上。

**误判对照**

最容易得出的错误结论是「3 条到 `10.20.5.77` 的已建立连接 = 攻击者当前仍在控制这台机器」。判据有三条：

①`Get-NetTCPConnection` 的 `Established` 只表示 TCP 三次握手完成且未收到 FIN/RST，**它不区分这条连接后面是否有人在敲键盘**——勒索程序完成加密后进程并不一定退出，它持有的连接可以纯粹是心跳或重试；
②`4624` 表里 03:12:44 那条来自 `10.20.5.77` 的 `LogonType=10` 事件时间是**会话建立时刻**，到观察时已过去 8 小时余，登录成功不等于此刻仍有活动会话；
③加密进度停在 62% 且进程 `svhost1.exe` 仍在运行，这两个事实只证明**程序在跑**，不证明**人在操作**——勒索软件的行为模式恰恰是设好参数后自行执行，不需要任何交互。

正确判据是**必须把连接与可归因的行为证据绑定**——本案的支撑是那张 `4624` 表里 03:12:44 那条来自 `10.20.5.77` 的 `LogonType=10`，那是"有人的会话"的证据，而连接数不是。

按错误判据走的代价是处置决策基于错误前提：若委托方据此判断"必须立刻断网"，而攻击者实际已完成加密并在等运维响应，断网反而给了它销毁痕迹的信号；反过来若真实会话仍在，断网会销毁尚未取证的内存与网络状态。

**再补一条实测教训**：判定"攻击者已离线"同样不能只靠 `Established` 的反向推断。案件中期曾把 0 条活动连接写成"攻击者已撤离"，而实际是对方换了跳板 IP。这条错误差点让委托方提前断开监控，丢失了后续捕获第二次横向移动的机会。**网络侧的任何阴性结论都必须写明观测窗口和观测点**——本案观测点只有 `10.20.5.30` 本机，看不到其他网段的主机。

<a id="section-33"></a>

### 5.2 勘验会话与攻击会话的切分：来源 IP 加登录类型

**场景**

同一份 `Security.evtx` 里同时存在攻击者的 RDP 登录与勘验方自己的 RDP 登录，两者在时间、类型上都相似。委托方与后续复核方都要问一个问题：**哪些记录是你们造成的**。

这条路径值得单列，因为它是远程勘验最容易被质疑、也最容易被忽略的一步。

委托方真正的问题不是"你们改没改我的机器"，而是"哪些结论是我的数据说的，哪些是你们的动作造成的"。这两者在报告里如果不分节，整份证据的归属就是糊的——而归属一旦有争议，与之相关的那几条结论全部作废。

**处置过程**

1. 导出四类日志，缺一不可：

```powershell
wevtutil epl Security C:\Users\Public\Security.evtx
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational C:\Users\Public\TSLocal.evtx
wevtutil epl Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational C:\Users\Public\RdpCore.evtx
wevtutil epl System C:\Users\Public\System.evtx
```

2. 先做字段自校验，拿一条已知来源的登录来对——本次勘验的源 IP 应等于 `SrcIP`，用户名应等于 `User`。对不上就是取错了字段（如取成 `IpAddress` 而非目标机视角的 `SrcIP`）。

这一步看着简单，但它是整个分类的地基。`Security.evtx` 的事件数据里同时存在 `IpAddress`（网络层源地址，受代理/NAT 影响）、`WorkstationName`（客户端自报，可伪造）、`TargetUserName`（目标机视角的账户名）、`SubjectUserName`（发起该操作的账户，两者不同时说明发生了凭据委派）四个看起来都像"来源"的字段。

用本次自己的登录做校准，是唯一能确定字段语义的可靠办法——文档可能过时，工具版本可能有差异，只有"我知道我刚用这个 IP 登录了"这条已知事实能把四个字段里哪个对、哪个错钉死。本案正是在这一步发现原先一直取的是 `WorkstationName`，而它对 RDP 会话是客户端可自报的字符串，用它分类会把 `WIN-8F3D2A1` 这类主机名当成 IP 来比对。

3. 按时间排序后双维度比对：

| 时间 | `SrcIP` | `LogonType` | `User` | 归类 |
|---|---|---|---|---|
| 03:12:44 | `10.20.5.77` | 10 | `administrator` | 攻击者（与已知跳板 IP 一致） |
| 11:40:02 | 隔离跳板 IP | 10 | `dgf_admin` | 勘验方（本次） |

4. **分类完成后再回头做一次反向检查**：把所有 `LogonType=3` 的记录单独列出来，看有没有在观察期内新增的。攻击者用网络登录建立的后续会话不会出现在 RDP 记录里，只按 `4624` + RDP 分类会漏掉它们。

```powershell
# 反向检查：观察期内的网络登录，按源 IP 归类
$start = [datetime]'2024-03-11 03:00'; $end = [datetime]'2024-03-11 12:00'
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$start;EndTime=$end} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated,
                @{n='SrcIP';e={$_.Properties[19].Value}},
                @{n='User';   e={$_.Properties[5].Value}}
```

本案这一步捞出一条 `10.20.5.77` 的 `LogonType=3` 记录（03:19:11），发生在攻击者 RDP 会话建立后 6 分钟——这是他用同一跳板对文件共享发起的访问，只看 RDP 登录就完全看不到。

顺带确认一下字段索引的稳定性。`Get-WinEvent` 返回的 `Properties` 集合是按序号索引的，不同 Windows 版本、不同事件模板下同一字段的序号并不相同。上面脚本里的 `19`（`SrcIP`）、`5`（`User`）、`8`（`LogonType`）只对本案这台 Windows Server 2019 成立。

换机器跑之前必须先重新校准，最稳的做法是打印一次全部属性名再对位取值，而不是照抄序号：

```powershell
(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 1).Properties |
  ForEach-Object { $_.Value }
```

序号写死的脚本在本机验证过一次就会被人到处复制，而它换一台机器就可能静默取到别的字段——不报错，只是取错值。这类静默失效比崩溃危险得多，因为它不给你回头检查的机会。

5. 报告末尾单列本次勘验留下的痕迹清单。

**结论**

能证明：`Security.evtx` 中的每条远程登录记录均可归类为攻击者行为或勘验行为两类，依据是**来源 IP 与登录类型的双重比对**，两类之间无重叠。`TSLocal` 中 6 条会话记录同理对应。

在上述分类之外，另有一条 `10.20.5.77` 的 `LogonType=3` 记录（03:19:11）被单独归入攻击者一组——它产生于攻击者 RDP 会话建立后 6 分钟，是同一跳板对文件共享发起的访问，**不出现在任何 RDP 登录记录里**。这条记录是反向检查的直接收获。

**不能证明**：攻击者会话内具体执行了哪些操作。`4624` 只记录登录成功，不记录登录后的行为——后者需要结合其他工件或服务端口侧日志。即使归类准确，"归为攻击者"也只意味着"该账户行为可疑"，不意味着"该账户的每一个动作都是恶意的"：共用管理员账号在企业环境里本就存在，这条局限要写进报告。

**误判对照**

最容易得出的错误结论是「只凭时间切分，勘验开始前的都算攻击者」。判据有三条：

①`LogonType` 有 10 多种，`10 = RemoteInteractive`（RDP 远程桌面）只是其中一种，它与 `3 = Network`（网络登录，如 SMB、WinRM）在 `Security.evtx` 里结构几乎一样、只有 Type 字段不同——仅按时间切分会把观察期内的网络登录误并入攻击者一组；
②`WorkstationName` 是**客户端自报的字符串**，可被任意填写，用它做分类等于用一个攻击者可控制的字段做判据；本案正是先把字段换成 `SrcIP` 才发现原先的分类里混进了一条主机名条目；
③攻击者的后续会话往往**不产生新的 `4624`**——已建立的 RDP 会话内执行的 `PsExec`、WMI 调用记的是别的 EventID，只按 `4624` 分类会整体漏掉。

正确判据是**登录类型 + 来源 IP 联合分类**，并在分类完成后对 `LogonType=3` 做一次独立的反向排查。

按错误判据走的代价是报告把勘验方自己的痕迹算进攻击者证据，或者反过来——把攻击者的一次网络登录归为"未知来源"而未纳入分析，后者更隐蔽也更严重，因为它直接遗漏了一条真实的攻击会话记录。

**归类的层级也值得留意**。分类结果不该只有"攻击者/我方"两档，中间还可以有"无法归类"——把确实说不清来源的记录单列出来，比硬塞进某一档诚实得多。本案最终表里有 1 条记录落进这一档：02:47 的一次 `LogonType=3`，源 IP 是 `10.20.5.44`（一台未登记的测试机），既不是攻击者跳板也不是本方隔离机。

这一条单独列出来还有个实际好处——它提示了一个此前被忽略的事实：攻击来源不止一个 IP。若当时图省事把它划进"攻击者"或"我方"，这个信息就永久消失了。"说不清"和"都归一边"之间的差别，往往就是案件里第二条线索的存亡。

<a id="section-34"></a>

### 5.3 在线取证的痕迹要自己先声明

**场景**

勘验结束后的复核中，对方质疑"取证过程改变了系统状态"。事实上本次采集的痕迹是已知且可枚举的。

这条路径值得写下来，是因为**主动声明痕迹比被追问后再解释可信得多**，而痕迹本身不多——难的是有人愿意逐条列出来。

本案的核查请求来自复核律师，而委托方其实从未质疑过取证动作。这个反差值得记：机构自己心里明白"无影响"这句话站不住，外部质疑只是把它推上台面。 等到被问才列清单，列出来的往往是被追问后才想起来的部分，而清单的价值恰恰在于"当时就记着"这个前提。

还有一类痕迹容易整类漏掉：**由工具自身产生的**。AVML 采集内存时会在目标机上落下可执行文件与配置文件，远程桌面会话会更新 `NTUSER.DAT` 与 `UsrClass.dat` 的部分键值，`wevtutil epl` 会在 `C:\Users\Public\` 留下导出目录。这些痕迹不出现在 `Security.evtx` 里，只看日志是发现不了的——痕迹清单的完整性来自对工具行为的预先了解，而不是来自日志的完整。

所以清单里"未产生：注册表修改"这一行改成了逐项说明：

```text
  - AVML 可执行文件与同名配置（落点 C:\Users\Public\，采集后保留供复核，未删除）
  - 远程桌面会话导致的用户配置 hive 部分键值更新（NTUSER.DAT / UsrClass.dat）
    说明：该更新由登录动作本身触发；本机构亦通过 RDP 登录，
          与攻击者登录在机制上无法区分，此处如实列出
```

第二条的写法尤其重要：它没有回避"我们确实动了注册表"，而是说明了**这次修改与攻击者造成的那次在机制上无法区分**——因为本机构也是通过 RDP 登录进去的，登录就会写这些键。列出来并说明性质，比声称"未产生"要可信得多。

**处置过程**

1. 收工前先确认目标机未被实质改动：

```powershell
# 除本次登录与文件导出外，无软件安装、无服务变更、无配置修改
```

2. 报告中单列一节，逐条列出本次勘验产生的痕迹：

```text
本次勘验在目标机上产生的痕迹（全部已知、可枚举）：
  - 2 条 RDP 登录记录（Security.evtx EventID 4624，11:40:02 与断线时）
  - TSLocal.evtx 中 6 条会话创建/断开记录
  - 导出目录及其下文件的 atime 更新（导出动作本身导致）
  - 内存镜像采集期间的一次短暂 IO 抖动（已观察，未影响业务）
未产生：软件安装、服务状态变更、注册表修改、文件内容修改
```

这份清单的价值不在于消除质疑，而在于**把质疑的落点收窄到具体几条**。对方看完的反应通常是"导出目录的 atime 变化会不会影响你们的分析结论"——这就把讨论从"你有没有改过我的机器"引到了"atime 对本案分析无关"，而后者是可以逐条回答的。

痕迹清单还要和结论清单对照着看一遍。判据很简单：凡是引用了某个时间戳作为证据的结论，都要确认那个时间戳不落在本次勘验的痕迹范围内。本案所有结论引用的最早时间是 03:12:44（攻击者会话），勘验痕迹从 11:40:02 开始，两者不重叠——这个"不重叠"就是全部归属论证的支点，写出来比任何声明都有力。

**收集痕迹清单的时机也有讲究**：不是收工时凭记忆写，而是采集过程中随手记。`4624` 记录是现场产生的，改不了；但导出目录、内存镜像落点、临时脚本的路径这些，如果不当时记，两个小时后只能靠回忆，而回忆会把"三个"写成"几个"。

3. 与攻击者行为分节陈述，不混在一起。

**结论**

能证明：本次勘验在目标机上造成的痕迹完整可枚举，且全部属于登录与只读导出这类必然产生记录的范畴；目标机其余状态未被本机构改动。计划任务的持久化证据以**在线观察记录**形式呈现，其磁盘取证在后续关机镜像中完成——两部分结论分节陈述，不合并。

**不能证明**：内存采集期间系统是否发生过本机构未察觉的状态变化。在线采集不是快照，采集过程本身会产生 IO 与缓存写入。

**误判对照**

最容易得出的错误结论是「报告里写'取证过程未对系统造成任何影响'」。判据有三条：

①"未造成影响"是一个**无法证伪的表述**——连一次文件导出都会更新 `atime`，一次内存采集必然产生 IO 抖动，这些都不影响数据完整性，却实实在在是"影响"，这句话因此在质证中必然被推翻；
②本次痕迹清单里的 2 条 `4624` 记录客观存在于 `Security.evtx` 中且不可删除，任何声称"无影响"的表述都与这份可读的证据直接冲突；
③第 5 步的在线检查（进程列表、`root\subscription`、任务列表、`Get-NetTCPConnection`）本身也读取了系统状态，`Get-NetTCPConnection` 这类查询在部分 Windows 版本上会短暂创建辅助线程，虽不落日志但确实发生过。

正确判据是**逐条列出可枚举的痕迹并说明其性质**，把"有没有影响"这个模糊提问换成"有哪些具体痕迹、是否影响证据完整性"。每一行痕迹后跟一句性质说明，比一个总的"无影响"有用得多。

按错误判据走的代价是：一旦对方自己发现那条 `4624` 记录，整份报告的严谨性立刻崩塌，进而质疑其他所有声明——而那些声明其实都是真的。在一份技术报告里，唯一能证明你严谨的方式恰恰是不说那句最省事的话。

---
<a id="section-35"></a>

## 六、扩展阅读方向

下面四组方向按"你在在线勘验这条路上会遇到什么"组织。


**第一组：同层深入——在线之后的分析**

采完只是开始。下面几篇是本篇产出的直接消费者。

- [内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md) —— `DigiForensics-mem.raw` 拿到之后的第一步。**内存是本篇唯一能拿到、而离线完全丧失的证据类型**，这一篇给的是分析的整体框架与能力边界。
- [内存采集方法](../../memory/memory-acquire/memory-acquire-memory-acquisition-methods.md) —— 如果本篇第三章你只读了命令清单，这一篇给你的是选型依据：`WinPmem` / `LiME` / `AVML` 各自的适用场景，以及 AFU 与 PCIe/USB 直连采集器在证据强度上的差异。硬件采集器贵，但它的输出不依赖目标机的内核状态——这在有反取证工具的机器上是决定性差异。
- [Windows 内存 Profile 机制](../../memory/memory-acquire/memory-acquire-windows-profile.md) —— 遇到 KDBG 未命中、符号匹配不上、或需要手工定位结构时，这篇是排障手册。
- [网络连接与流量痕迹](../../memory/memory-artifact/memory-artifact-memory-network-artifacts.md) —— 本篇采集到的连接表、监听端口在这一篇做归属分析。它的方法论核心是"stale data"：连接表是采集时刻的快照，不代表连接在采集之后没变过。

**第二组：相邻议题——痕迹的另一半在主机侧**

- [事件日志深度分析](../../computer/computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— **本篇最关键的配合**。你在线做的每一步都在事件日志里留下了记录：4624 类型 10 是你的 RDP 会话、4625 是失败登录、查询行为在部分日志源里也有痕迹。这些痕迹必须被识别出来并在报告里主动交代，否则会被当成攻击者行为。
- [Sysmon 与日志聚合](../../computer/computer-registry-log/computer-registry-log-sysmon.md) —— 如果目标机装有 Sysmon，**它对你的操作记录得比系统日志更细**。这条要知道，因为"日志里没看到取证人员"可能只是日志没开。
- [系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) 与 [Shell 痕迹与命令历史](../../computer/computer-shell/computer-shell-shell.md) —— Linux 侧的对应面。`journalctl` 与 shell 历史同样是勘验行为的记录载体，`bash_history` 尤其——你敲的每条命令都可能落进去。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 在线勘验同样受阶段约束，但**操作留痕的要求比离线更高**，因为每一步都有副作用需要解释。

**第三组：工具与规范——通道选择与授权**

- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) —— 在线场景虽然不接硬盘，但**内存采集器、转储工具的选型与耗材准备**属于同一类硬件决策。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 跨境远程取证、远程访问的司法授权边界、以及委托方的配合义务，这三件事在线场景下比离线更敏感。**"我以为对方同意了"在远程环境下不成立。**
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 在线采集的每个产物都要独立固定哈希并记录采集时刻。由于系统状态在持续变化，"采集时刻"这个字段的精度要求比离线更高。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **自毁逻辑、计时检测、屏幕录制检测、远程会话检测**的形态。知道对方有什么手段，才能判断"我这次接入会不会触发它"，以及"哪些痕迹可能是对方设计的"。

**第四组：判据与反例——结论能写到多强**

这一组决定你的在线结论在质证时会不会被整体推翻。

- [内存证据的可采性与报告](../../memory/memory-artifact/memory-artifact-memory-evidence-and-reporting.md) —— **本篇最应该提前读的一篇**。内存结论的强度天然弱于磁盘结论：它依赖采集工具的可信度、依赖符号与版本的匹配、无法复算原始态哈希。"内存里发现了 X"这句话该怎么写才不被推翻，那篇给的正是模板。
- [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md) —— 那篇的"结论强度分级表"是本领域最实用的东西之一。**在线勘验的产出同样要按那张表分级**："该主机此刻有到 X 的连接"（弱）与"该主机传输了某文件"（强）之间隔着采集能力边界。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— 在线勘验必然破坏时间线（你插入了新事件），恢复办法是给所有在线操作打上精确时间戳并单独成段。合并与冲突处理在那篇。

**说明**：在线取证的成果不是"拿到了一份内存镜像"，而是"一份把每个可疑痕迹都解释清楚的报告"。

现场保全的价值只在最后一刻体现；把勘验行为留下的痕迹和攻击者留下的痕迹区分开，才是在线取证真正的技术难点。

**本篇第四章的四组陷阱全部围绕这一点展开**——接入前、接入时、采集时、结论时。
<a id="section-36"></a>

## 七、命令速查

```powershell
# ===== 在线基线（只读，先观察后操作）=====
Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
whoami /all
query user
Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime,LocalDateTime

# ===== 内存采集（永远第一个做）=====
.\WinPmem.exe /acquiresetting .\DigiForensics-mem.raw 2>&1 | Tee-Object .\acquire-mem.log

# ===== 关键日志导出（用 epl，不用 Get-WinEvent，避免自我污染）=====
wevtutil epl Security D:\Forensics\Security.evtx /ow:true
wevtutil epl System   D:\Forensics\System.evtx   /ow:true
wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational D:\Forensics\TSLocal.evtx /ow:true
wevtutil epl "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" D:\Forensics\RdpCore.evtx /ow:true

# ===== 登录事件分析：来源 IP 与登录类型是区分攻击者/勘验者的关键 =====
# 用 ToXml() 按字段名取值，不要写死 Properties[N] 下标（随版本/语言变化）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 | ForEach-Object {
  $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [PSCustomObject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; SrcIP=$d.IpAddress; Type=$d.LogonType }
} | Format-Table -AutoSize

# ===== 在线检查项（按扰动从低到高）=====
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine
Get-NetTCPConnection -State Established,Listen | Select-Object LocalPort,RemoteAddress,OwningProcess
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskPath,TaskName
Get-CimInstance -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
```

```bash
# ===== 客户端侧留痕（不在目标机安装任何东西）=====
# SSH 全程记录输入输出
ssh -tt dgf-incident@10.20.5.30 |& tee -a /lab/ssh-session.log

# RDP 宿主机侧录屏
vlc --intf dummy --sout '#transcode{vcodec=h264,vb=2000}:std{access=file,mux=mp4,dst=/lab/remote-session.mp4}' screen:// --screen-fps 15

# 采集后立即哈希固定
sha256sum /evidence/DigiForensics-mem.raw | tee /evidence/DigiForensics-mem.raw.sha256
sha256sum /evidence/DigiForensics-*.evtx > /evidence/remote-hashes.txt
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 磁盘镜像与仿真 — 远程勘验与在线取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《远程勘验与在线取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.E01`、`DigiForensics-mem.raw`、`DigiForensics-base.vmdk` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
