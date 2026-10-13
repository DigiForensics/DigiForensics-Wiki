---
title: "Windows Server 环境仿真"
slug: "imaging-mount-simulate-windows-server"
canonical: "https://www.digiforensics.cn/wiki/imaging-mount-simulate-windows-server"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "imaging"
space: "磁盘镜像与仿真"
node_path: ["只读挂载与仿真"]
---

# Windows Server 环境仿真

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/imaging-mount-simulate-windows-server)

<a id="section-1"></a>

## 一、概述

普通 PC 的仿真风险是"一个可疑程序跑起来了"。**服务器仿真的风险是"半个企业内网醒过来了"。**

一台域控启动的瞬间会自动发生这些事：

| 自动行为 | 会造成什么 |
|---|---|
| 启动 `NTDS` 服务 | 主动向配置好的 DC 发起 Netlogon，**把本机对象复制到整个域** |
| 启动 DNS 服务 | 以**原 IP** 注册到 DNS，域内客户端开始向它解析 |
| 启动 IIS | 按 `applicationHost.config` 恢复**站点绑定与应用程序池**，对外发布原本已下线的站点 |
| 执行计划任务 | 备份、补丁、归档任务立刻跑，**可能覆盖关键数据** |
| 加载 `Run` 键与服务 | 攻击者持久化被激活 |
| Defender 实时保护 | 更新病毒库、写文件，**可能隔离甚至删除检材样本** |
| 连接 WSUS / PXE | 向真实更新源注册；DHCP/TFTP 层面产生广播 |
| 启动 SQL Server | 连接生产库，触发备份或作业 |

这些行为的共同点：**开机后几分钟内自动完成**，而且大部分在你反应过来之前就结束了。

所以要处理的问题是：

> 如何在系统还没启动的时候，就让它的身份、地址、时间、信任关系全部"变成一个不存在的服务器"。

**在取证流程中的位置**：本篇属于**分析**环节的仿真执行阶段，位置在"镜像已就绪"之后、"提取具体工件"之前。**它的第一个动作发生在开机之前**——所有隔离配置都必须在首次启动前完成，启动后再补就已经晚了（开机那一瞬间 `NTDS` 已经握手、DNS 已经注册）。所以它是本板块里唯一一个**必须照着顺序做、不能跳步、不能事后补救**的流程。差分盘（overlay）与快照点选在基础镜像之上，是为了任何一步做错都能整体回滚。**上游依赖**是 [只读挂载与安全接入](imaging-mount-simulate-read-only-mounting.md)（隔离网段的做法、只读挂载与写风险的边界）与 [虚拟机仿真](imaging-mount-simulate-virtual-machine-emulation.md)（差分盘与快照机制）；**下游**是工件提取——IIS 的 `applicationHost.config`、计划任务、`Run` 键、服务配置、AD 的 `ntds.dit` 都要在系统跑起来之后才拿得到，提取手法分别见 [注册表取证](../../computer/computer-registry-log/computer-registry-log-registry-forensics.md) 与 [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)。

**本篇处理的证据形态**，不是待解析的文件，而是**必须改动的身份标识**：

| 身份线 | 具体载体 | 处置动作 |
|---|---|---|
| 网络身份 | 网卡与 IP、`ARP` 缓存、`route print` 的路由表 | **首选移除虚拟网卡**；必须联网时用隔离网段 + 改 IP + 删默认路由 |
| 目录身份 | `SYSTEM` hive 里的域成员信息、机器 SID、Kerberos 票据缓存 | **不要动**——改注册表不会真的脱离域，反而制造不一致状态 |
| 名称身份 | 主机名、`NetBIOS` / LLMNR 广播、DNS 缓存文件 | 离线阶段改主机名 + 清 DNS 缓存，**这是最安全的一项改动** |
| 时间身份 | 时区 ID、系统时钟、事件日志时间戳 | 记录**原始时区 ID**，仿真统一 UTC；三项（原始时区 ID、仿真时区 ID、系统 UTC 时间）必须齐全 |
| 引导状态 | `BCD`（系统保留分区）、`manage-bde -status` 的 BitLocker 状态 | **改 BCD 前必须先查 BitLocker**——TPM 绑定时改 BCD 会改变引导测量值，可能触发恢复模式，无密钥则系统彻底起不来 |
| 差分盘 | 基础镜像 + 差分层 | **BCD 与所有改动都在差分盘内**，绝不在基础镜像上做 |

机器 SID 这一项要单独说：SID 本身不产生网络流量，**危险的是"带着 SID 联网"**。所以正确做法是保持 SID 不变加断网，而不是伪造；`sysprep /generalize` 是为生成可部署新实例设计的，对已存在系统不适用。

这台服务器上配置过哪些 IIS 站点与应用程序池、有哪些计划任务与服务被注册、`Run` 键里放了哪些持久化项、`ntds.dit` 里有哪些域对象、启动瞬间实际触发了哪些自动行为及其顺序与时间。

仿真环境给不出"这台机器当时真的对外提供服务"这类结论——仿真机的网络行为是被切断的，它证明的是"配置里写着什么"，而不是"生产环境里实际响应了什么"。反过来，**仿真中没触发的行为不能推断生产环境也没发生**：隔离网段里 DNS 注册失败、`NTDS` 握手超时，都会让某些服务停在不同的状态机上。机器 SID 与域关系**不可伪造也就不可验证**——断网期间机器凭据行为完全不会被记录。三段快照（A 隔离态 / B 登录态 / C 实验态）只覆盖到你主动操作为止，**被隔离掉的那部分网络行为永远没有证据**，所以"未发现对外连接"这句话在报告里的正确写法是"在隔离环境中启动期间未观察到外联"，不是"该机器无外联行为"。另外时间对位一旦做错（仿真 UTC 对本地日志），**全部时间线结论作废**，而这个错误在结果上很难自查，只能靠事先记录原始时区来防。

**读者前提**：需要先掌握虚拟机与差分盘快照的基本操作，否则"回滚"这个动作做不到，前面所有隔离措施就没有兜底；需要理解域环境里 Netlogon、DNS 注册、PDC Emulator 授时这些角色与行为，才能判断哪些服务"一开机就会动"；需要能读注册表 hive 里的机器 SID、域成员与主机名字段；还要接受一个前提：**仿真需要评估风险与适用条件**——Apple Silicon、BitLocker 绑定、域控这三类检材在某些条件下根本无法安全启动，这时正确决定是不仿。

---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 必须提前切断的四条"身份线"

PC 是**匿名的**，服务器是**有身份的**——IP、DNS 记录、域成员、主机名、证书。

仿真一台服务器，等于在真实世界里短暂复活了这个身份：

| 身份线 | 危害 | 应对手段 |
|---|---|---|
| **网络身份**（IP/MAC） | 抢占真实 IP，ARP 冲突、客户端连错 | **移除虚拟网卡**；必须联网时用隔离网段 + 改 IP + 删默认路由 |
| **目录身份**（域/SID） | 加入域、污染 AD 复制、触发信任 | 移除网卡 + 不做域相关修改 |
| **名称身份**（主机名） | NetBIOS/LLMNR 广播、DNS 反查命中真实记录 | 离线阶段改主机名 + 清 DNS 缓存文件 |
| **时间身份**（时区/时钟） | 日志时间错位、C2 心跳异常、证书失效 | 记录原始时区 + 仿真统一 UTC |

<a id="section-4"></a>

### 2.2 域控仿真的三重特殊性（风险最高）

一，**它会主动"找"其他域控**。Netlogon 握手成功后，**NTDS 会把本机对象复制到整个域**——包括被攻击者改过的对象。

二，**DNS 是 AD 的命脉**。DC 用真实 IP 上线，等于整个域的解析被劫持到虚拟机。

三，**它可能是时间源**。PDC Emulator 上线授时，会让全域机器的日志时间被拉偏。

> **结论：域控检材绝不能让它正常完成启动。** 标准做法是"离线预处理"——在系统能启动之前切断网络，让它以"孤岛"方式运行，连自己的 DNS 都只服务本机。

<a id="section-5"></a>

### 2.3 IIS 与其他自动恢复的危险判定

IIS 的"自动恢复"看起来像正常业务，最容易被低估。

`W3SVC` 启动后按 `applicationHost.config` 恢复**所有站点绑定**。绑定若是 `*:80`，虚拟机 80 端口就上线了。

应用程序池默认 `AlwaysRunning` 会**预加载程序集**，相当于自动跑一遍站点代码。`web.config` 里的数据库连接串会在启动时**真的去连数据库**。

**判定标准**：IIS 危不危险，取决于**绑定配置与后端依赖**，而不是站点内容。

<a id="section-6"></a>

### 2.4 自启动项的执行顺序是系统定的

| 位置 | 触发时机 | 危险等级 |
|---|---|---|
| 服务（`services.exe`） | 启动阶段，**优先于 Run 键**，常以 SYSTEM 运行 | ★★★★★ |
| `Task Scheduler`（`\Microsoft\Windows\`） | 系统启动时并行触发 | ★★★★★ |
| `HKLM\...\Run` | 用户登录前 | ★★★★★ |
| WMI 事件订阅 | 触发式，**平时完全不显形** | ★★★★★ |
| `HKCU\...\Run` / `Startup` 文件夹 | 用户登录后 | ★★★ |

**WMI 持久化最隐蔽**：它没有"启动项"外观，触发式运行、平时完全不显形。

它的实体存在 WMI repository——`%SystemRoot%\System32\wbem\Repository\` 下的 ESENT 数据库。运行时通过 `root\subscription` 命名空间暴露为 `__EventConsumer`、`__EventFilter`、`__FilterToConsumerBinding` 三类对象。

**在磁盘镜像里必须去解析这个数据库。**只看注册表或任务管理器都看不到它。

<a id="section-7"></a>

### 2.5 杀软的双向困境

保持启用会写文件、**隔离甚至删除检材样本**、可能上传云端（**外泄**）。完全卸载会破坏系统状态。

**推荐**：在基础镜像阶段就通过差分盘一次性配置——关实时保护、关云提交、设排除路径。让每次回滚都带着这套配置，**不要每次分析时临时改**。

第三方杀软（Symantec / CrowdStrike / 深信服等）行为各异，必须**逐个确认"会不会把样本传出去"**。

<a id="section-8"></a>

### 2.6 PXE / WSUS 残留的真实风险排序

| 配置 | 残留位置 | 启动时可能发生什么 |
|---|---|---|
| **WSUS** | `HKLM\...\WindowsUpdate\AU` | 向真实 WSUS 注册、拉取安装补丁 |
| **PXE / 网络安装** | `BCD` 引导配置、`boot.wim` 路径、DHCP/TFTP 下发记录 | DHCP 广播、TFTP 拉镜像 |
| **无人值守应答** | `WINDOWS\Panther\Unattend.xml` | 首次登录时执行额外配置 |

PXE 引导文件本身不主动外联。真正的风险是链路层的 DHCP 广播与 ARP 冲突，所以**"删网卡"的优先级远高于"删 PXE 文件"**。

<a id="section-9"></a>

### 2.7 身份伪造的技术边界

| 项目 | 能否安全修改 | 说明 |
|---|---|---|
| **主机名** | ✅ 可以 | 改后不影响系统文件，**最安全的一项** |
| **IP / MAC** | ✅ 可以 | 前提是**使用隔离网段**且无真实路由 |
| **机器 SID** | ⚠️ 谨慎 | `sysprep /generalize` 是为**生成可部署新实例**设计的，**对已存在系统不适用**；强改破坏 AD 信任、DPAPI、证书 |
| **域成员身份** | ❌ 不要动 | 改注册表 `DomainName` 不会真的脱离域，反而制造不一致状态 |

> **SID 的正确处置**：SID 本身不产生网络流量，**危险的是"带着 SID 联网"**。正确做法是**保持 SID 不变 + 断网**，而非伪造。

<a id="section-10"></a>

### 2.8 `bcdedit` 的用途边界与 BitLocker 风险

一，**BCD 修改属于客户机磁盘写入**（通常在系统保留分区），必须在差分盘内进行并纳入快照，绝不能在基础镜像上做。

二，BitLocker 环境下改 BCD 可能触发恢复模式。若系统盘启用了 BitLocker（尤其 TPM 绑定），修改 BCD 会改变引导测量值，**可能要求输入恢复密钥**——无密钥则系统彻底无法启动。动手前必须先 `manage-bde -status`。

三，**不要用 `bcdedit` 去"禁用恶意启动项"**。恶意持久化通常在 Run 键、计划任务、服务里，`bcdedit` 管不到；而且你并不知道恶意程序是否往 BCD 写过东西。**更安全的做法是在差分盘内改 Run 键/服务。**

<a id="section-11"></a>

### 2.9 时间对位与快照点选择

**时区最容易出错**。仿真机保持 UTC 而日志按本地时间记录，**所有时间戳会差 8 小时**，时间线结论直接错误。

原始时区 ID、仿真时区 ID、系统时间（UTC）三项必须齐全。

快照策略分三段：

**A · 隔离态**——断网、改名、改 IP、关杀软**之后**，首次启动前。
**B · 登录态**——首次登录后、运行可疑程序前。
**C · 实验态**——每轮深度操作后。

**A 快照必须包含全部隔离配置**，否则回滚后系统会重新带着真实身份上线——这是服务器仿真最危险的操作失误。

---
<a id="section-12"></a>

## 三、操作步骤

<a id="section-13"></a>

### 3.1 第 1–2 步：基础隔离与 BitLocker 确认

按第 04 篇完成 VMDK 转换与哈希基线后：**移除虚拟网卡**（不是 `Not connected`，是移除设备）、删除光驱/打印机/串口/USB 控制器、Guest Isolation 全关；域控建议内存 ≥ 4 GB、CPU ≥ 2 核。

Server 镜像常带 BitLocker 或未知管理员密码，用 WinPE 挂载离线注册表更可靠：

```batch
diskpart   :: 交互内依次执行 list volume / select volume 3 / assign letter=W / exit
reg load HKLM\SYSLIVE  W:\Windows\System32\config\SYSTEM
reg load HKLM\SYSLIVE_SW W:\Windows\System32\config\SOFTWARE
manage-bde -status W:     :: 关键：先看 BitLocker，Locked 就不要碰 BCD
```

若 `Lock Status: Unlocked`，可安全改注册表；若 `Percentage Encrypted: 100%` 且 Locked，**立刻停止，不要动任何东西**。

> **命名必须统一**：注册表一律写 `HKLM\SYSLIVE`（SYSTEM hive），SOFTWARE 分支才用 `HKLM\SYSLIVE_SW`——混用会导致"改了一个键、开机后毫无变化"的假象。

<a id="section-14"></a>

### 3.2 第 3 步：改主机名与清 DNS 身份

```batch
reg add "HKLM\SYSLIVE\ControlSet001\Control\ComputerName\ActiveComputerName" /v ComputerName /t REG_SZ /d "DGFORENSICS-01" /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\Tcpip\Parameters" /v Domain /t REG_SZ /d "" /f
del /f W:\Windows\System32\config\
etlogon.dns 2>nul
```

改后重启生效，**原名不会出现在任何广播中**。

原名与新名必须记入勘验日志——机器身份是证据链的一部分。

> **为什么写 `ControlSet001`**：`CurrentControlSet` 是离线环境下指向 `ControlSet00X` 的**符号链接**，在未启动的 SYSTEM hive 里可能解析不到，必须显式写入实际存在的 `ControlSet001`。

<a id="section-15"></a>

### 3.3 第 4 步：改 IP 与 DNS（仅隔离网段内）

无网卡时本步跳过——**这是最理想的状态**；确需联网时：

```powershell
Get-NetIPConfiguration | Format-List InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer  # 记录原始值
# New-NetIPAddress 是"追加"，不会替换已存在的地址，所以先删再增
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
  Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.77.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
```

**三个要点缺一不可**：DNS 指向 `127.0.0.1`（只服务自己）、**删默认路由**（没有网关就没有出网路径）、改 MAC 要在虚拟化平台侧改（`.vmx` 里 `ethernet0.address`）而非系统内。

<a id="section-16"></a>

### 3.4 第 5 步：切断外部依赖与高危服务

```batch
:: 禁用 WSUS 自动更新（防止向真实 WSUS 注册）——写在 SOFTWARE 分支
reg add "HKLM\SYSLIVE_SW\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
:: 服务改手动（3=手动，优于 4=禁用，4 会让依赖组件报错）
:: 注意：WinPE 的 sc config 改的是 WinPE 自己，不影响已加载的目标 hive
reg add "HKLM\SYSLIVE\ControlSet001\Services\WDSsvc"   /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\wuauserv" /v Start /t REG_DWORD /d 3 /f
:: IIS 需 WAS 与 W3SVC 一起处理，否则仍可能部分启动
reg add "HKLM\SYSLIVE\ControlSet001\Services\WAS"   /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f
ren "W:\Windows\Panther\Unattend.xml" "W:\Windows\Panther\Unattend.xml.disabled"
```

<a id="section-17"></a>

### 3.5 第 6–7 步：关闭杀软、时区对位与日志预启用

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,CloudProtectionEnabled,IsTamperProtected
Set-MpPreference -DisableRealtimeMonitoring $true -SubmitSamplesConsent 0 -MAPSReporting 0
Add-MpPreference -ExclusionPath "D:\Forensics\Samples"    # 防止样本被隔离 = 证据损坏
Set-Service -Name WinDefend -StartupType Manual -ErrorAction SilentlyContinue
Get-TimeZone | Select-Object Id,DisplayName    # 记录原始时区
Set-TimeZone -Id "UTC"
Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"         # 记录系统时间（UTC）
:: TaskScheduler Operational 日志默认关闭，必须在快照 A 之前启用
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

> **Defender 处置的三级降级**：① 正常 `Set-MpPreference` 关闭；② 被 Tamper Protection 拦截 → 改为**排除整个仿真盘**并接受实时保护存在；③ 仍不行 → 在**差分盘内**删签名库与策略键。

**任何一级都要记入快照并写入报告的"仿真限制"节**——防御组件在运行是真实状态的一部分，隐瞒它比保留它更有害。

<a id="section-18"></a>

### 3.6 第 8 步：拍基线快照并首次启动

确认基础盘哈希未变后，拍**快照 A（隔离态）**（勾选 Include memory）再首次启动。

**启动后先观察，再登录**：有无自动弹窗、服务启动顺序、DNS 是否绑定真实 IP、IIS 是否上线（访问 `http://127.0.0.1`）。

<a id="section-19"></a>

### 3.7 第 9 步：采集启动瞬间的自动行为

```powershell
# 服务启动/停止事件（谁在启动时做了什么）
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 200 |
  Select-Object TimeCreated,Message | Format-List
# 计划任务实际执行记录（依赖 3.5 步已启用日志）
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=100,102,200,201} -MaxEvents 100 |
  Select-Object TimeCreated,Message | Format-List
# WMI 永久事件订阅（最隐蔽的持久化）+ DNS 与关键服务状态
Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
Get-DnsServerZone -ErrorAction SilentlyContinue | Select-Object ZoneName,Type
Get-Service DNS,W3SVC,NTDS | Select-Object Name,Status,StartType
```

> **采集顺序很重要**：这些查询本身会写日志和访问时间，**必须先拍快照 A 再采集**，让"系统启动时的真实状态"被快照固定，后续采集的变化不污染基线。

---
<a id="section-20"></a>

## 四、常见陷阱

服务器仿真的陷阱与 PC 仿真有一个本质区别：**PC 出事改的是证据，服务器出事改的是别人。**

概述那张表里每一行都带着外部对象——`NTDS` 把本机对象复制到整个域、DNS 以原 IP 注册、Defender 把样本上传云端。

而这些行为在开机后几分钟内自动完成，且大部分在你反应过来之前就结束。

2.1 把要处理的东西归纳成四条身份线：**网络身份、目录身份、名称身份、时间身份**。本章按这四条线以及"操作层"分四组。

核心问题就是概述里那一句：如何在系统还没启动的时候，让它的身份、地址、时间、信任关系全部变成一个不存在的服务器。

★ 标记表示该操作会不可逆地污染真实环境、损坏证据镜像或使系统无法启动，执行前必须停下来确认。

<a id="section-21"></a>

### 4.1 身份线：四条线必须全部切断

<a id="section-22"></a>

#### 陷阱 1：★ 只做快照就启动，网卡还在，域控以原 IP 上线

**现象**：导入镜像、拍好快照、启动观察。磁盘是安全的，但虚拟机里那张网卡的 `Not connected` 忘了设，或者设了 `Not connected` 就以为等价于"没有网卡"。

**原因**：2.1 的"网络身份"一栏把应对手段写成了"移除虚拟网卡；必须联网时用隔离网段 + 改 IP + 删默认路由"——"移除"排在第一位，"Not connected" 不在其中。3.1 重复了一遍这个措辞：移除虚拟网卡（不是 `Not connected`，是移除设备）。

这个区别在 Bridged 模式下影响尤其明显。`Not connected` 只是断开了链路，而**虚拟网卡设备仍然存在于虚拟机硬件中**，桥接层依然会处理它的帧。

**影响**：**如果这是域控检材，代价不在虚拟机内。**

2.2 列的三条特殊性里第一条是：它会主动"找"其他域控——通过 Netlogon 握手成功后，`NTDS` 会把本机对象复制到整个域，包括被攻击者改过的对象。

也就是说**攻击者篡改过的 AD 对象会被复制回生产域**。2.2 的结论没有任何回旋余地：**域控检材绝不能让它正常完成启动**。

**核查**：**无网卡是本篇的默认且最优状态**（3.3：**无网卡时本步跳过——这是最理想的状态**）：

```text
VMware / VirtualBox 侧：删除虚拟网卡设备（不是 Not connected，不是禁用）
PVE 侧：qm create ... --net0 none
导入后配置清单（3.1）：移除虚拟网卡、删除光驱/打印机/串口/USB 控制器、Guest Isolation 全关
```

**配置完要能验证**。案例第 4 步的判定就是靠这个：

```powershell
Get-NetAdapter | Select-Object Name,Status,MacAddress
# 期望：查不到任何物理网卡的 Up 状态条目
Get-Service DNS,W3SVC,NTDS | Select-Object Name,Status,StartType
```

**确实需要联网时**（3.3 的完整形式，且只在隔离网段内）：

```powershell
Get-NetIPConfiguration | Format-List InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer  # 先记录原始值
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
  Remove-NetIPAddress -Confirm:$false      # New-NetIPAddress 只是追加，不会替换
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.77.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
```

**三个要点缺一不可**：DNS 指向 `127.0.0.1`（只服务自己）、**删默认路由**（没有网关就没有出网路径）、**改 MAC 要在虚拟化平台侧改**（`.vmx` 里 `ethernet0.address`）而不是在系统内。

**原始 IP、主机名、时区必须先记录再改**（3.3 的第一条命令就是"记录原始值"）——**没有原始值，报告里就写不出"这台机器原来是谁"。**

<a id="section-23"></a>

#### 陷阱 2：域控上线后授时，把整个域的日志时间拉偏

**现象**：把域控的网卡"限制"在隔离网段后启动，`NTDS` 正常加载，PDC Emulator 角色上线，开始对域内授时。

**原因**：2.2 的第二条特殊性被很多人当成"DNS 问题"，它其实是另一条线：它可能是时间源——PDC Emulator 上线授时，会让全域机器的日志时间被拉偏。

2.1 把这单列为"时间身份"一行，危害写的是"**日志时间错位、C2 心跳异常、证书失效**"。

这一条的危险在于**它不表现为任何异常**。域控照常工作，客户端也照常认证，**只有事后对时间线时才会发现所有日志对不上**。

**影响**：**污染的是别人的日志。**

而且这类偏差通常在分析其它案件时才被发现，**那时候已经无法还原当时的真实时间**。

**核查**：把时间身份当成 2.1 表格里独立的一行来切断，不要只依赖"断网"。

断网后 PDC Emulator 只对本机授时，影响被限制在虚拟机内。但如果做了任何形式的联网，就必须确认 PDC Emulator 不会对外授时：

```text
无网卡（本篇默认）：影响限于本机，安全
有网卡 + 隔离网段：确认 192.168.77.0/24 之外没有任何机器
保留 3.5 步的三项时间记录（见陷阱 9），作为授时影响的判定依据
```

**与陷阱 9 联动**：时区对位做的是"仿真机这一侧"，而 PDC Emulator 授时影响的是"其它机器那一侧"。前者你能改，后者只能靠断网避免——**所以顺序是：先断网，再对时**。

<a id="section-24"></a>

#### 陷阱 3：★ 用 `sysprep /generalize` 或改注册表 `DomainName` 来"脱域 / 改 SID"

**现象**：为了避免域控去"找"域成员，把 `sysprep /generalize` 当成脱域手段；或者直接编辑注册表里的域信息，指望机器开机后不再是域成员。

**原因**：2.7 的表格把这两项的判定写得很死。机器 SID 是"⚠️ 谨慎"，`sysprep /generalize` 是为生成可部署新实例设计的，对已存在系统不适用，强改会**破坏 AD 信任、DPAPI、证书**；域成员身份是"❌ 不要动"，改注册表 `DomainName` 不会真的脱离域，反而制造不一致状态。

引用块给出了正确的思路：SID 本身不产生网络流量，危险的是"带着 SID 联网"——正确做法是保持 SID 不变 + 断网，而非伪造。

**影响**：**伪造身份可能同时破坏三样东西**——AD 信任关系（生产侧）、DPAPI 保护的凭据（影响你后续能读到的数据）、证书链（TLS 校验）。

而它想解决的问题——机器去联网——本来用"拔网卡"就能彻底解决。

**核查**：**保持 SID 不变，靠断网隔离**（2.7 引用块）。

2.7 还给了一张可改/不可改的清单，**唯一两项"✅ 可以"的是主机名和 IP**。**改主机名是"最安全的一项"（改后不影响系统文件）**，改 IP 的前提是"使用隔离网段且无真实路由"。

**改主机名在离线阶段做**（3.2）：

```batch
reg add "HKLM\SYSLIVE\ControlSet001\Control\ComputerName\ActiveComputerName" /v ComputerName /t REG_SZ /d "DGFORENSICS-01" /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\Tcpip\Parameters" /v Domain /t REG_SZ /d "" /f
del /f W:\Windows\System32\config\
etlogon.dns 2>nul
```

**改后重启生效，原名不会出现在任何广播中**（3.2）——原名与新名必须记入勘验日志，机器身份是证据链的一部分。

<a id="section-25"></a>

### 4.2 离线预处理：写哪张 hive、写到哪个控制集

<a id="section-26"></a>

#### 陷阱 4：隔离配置直接写在基础镜像上

**现象**：用 WinPE 挂载了系统卷，`reg load` 完 SYSTEM hive，直接把主机名、服务 Start 值、防火墙规则改掉，改完关机，准备"回头再配差分盘"。

**原因**：所有这些改动都是对客户机磁盘的写入，而基础镜像是原始证据的仿真副本。

2.8 把它列为第一条并写得很明确：BCD 修改属于客户机磁盘写入（通常在系统保留分区），必须在差分盘内进行并纳入快照，绝不能在基础镜像上做。

这条原则不只适用于 BCD。注册表 hive、服务 Start 值、`Unattend.xml` 重命名，全部同理。它们看起来像"配置"，**但配置落在证据上就是修改证据**。

**影响**：基础镜像哈希变化，"未修改任何原始数据"这个结论作废。

案例结论要点里那句"基础 VMDK 哈希在导入后、仿真结束后两次比对完全一致"是整份报告风险控制结论的支撑。**哈希一变，后面所有隔离相关的结论都要重写**。

**核查**：**离线改动的载体是差分盘，基础镜像保持只读**（3.1 与第 04 篇的规范）：

```bash
# 基础镜像在宿主侧锁只读
chmod 444 /lab/vm/DigiForensics/DigiForensics-base.vmdk
chattr +i /lab/vm/DigiForensics/DigiForensics-base.vmdk

# 所有离线预处理（改注册表、禁服务、改 BCD）都在差分盘里做，并纳入快照
cd /lab/vm/DigiForensics
vmware-vdiskmanager -r DigiForensics-base.vmdk -t 0 DigiForensics-delta.vmdk
```

**每次离线操作前后的哈希都要确认**：

```bash
sha256sum /lab/vm/DigiForensics/DigiForensics-base.vmdk    # 与 3.1 步基线比对，必须一致
```

**如果已经改到了基础镜像上**：立即停止，从原始 E01/主副本重新转换并重做往返验证。基础镜像没有"撤销"这个操作。

<a id="section-27"></a>

#### 陷阱 5：离线编辑时写 `CurrentControlSet`，改完开机没变化

**现象**：`reg add "HKLM\SYSLIVE\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f` 执行成功（返回"操作成功完成"），开机后 `W3SVC` 照常启动，站点照常上线。

**原因**：3.2 的引用块解释了这个现象：`CurrentControlSet` 是离线环境下指向 `ControlSet00X` 的符号链接，在未启动的 SYSTEM hive 里可能解析不到，必须显式写入实际存在的 `ControlSet001`。

**这是本章最隐蔽的一类错误。**`reg add` 不报错、退出码为 0、没有任何警告，**唯一的表现是"配置没生效"**——而这恰恰会被误读成"服务没禁成功，所以要用别的方法"。

**影响**：**把一次成功的编辑误判为失败**，进而用更激进的方式（`Start=4`、直接改文件、删服务注册项）去处理，**在差分盘上制造出与真实系统不一致的状态**。

**核查**：**离线阶段一律写 `ControlSet001`**（第七章速查的命令栏注释已经写死这条规则：统一用 SYSLIVE / SYSLIVE_SW，禁止写 CurrentControlSet）：

```batch
:: 对：显式控制集
reg add "HKLM\SYSLIVE\ControlSet001\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f

:: 错：符号链接在离线 hive 里可能解析不到
reg add "HKLM\SYSLIVE\CurrentControlSet\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f
```

**确认这台系统实际是哪个控制集**，不要默认是 001：

```powershell
# 确认控制集数量与当前值（SYSTEM hive 挂载后）
reg query "HKLM\SYSLIVE\Select" /v Current
# 期望：Current = 0x1 表示 ControlSet001
```

**改完立刻验证 hive 里的值确实写进去了**：

```batch
reg query "HKLM\SYSLIVE\ControlSet001\Services\W3SVC" /v Start
:: 期望输出：Start    REG_DWORD    0x3
```

**收尾必须卸载 hive**（第七章速查的收尾两行）：

```batch
reg unload HKLM\SYSLIVE_SW
reg unload HKLM\SYSLIVE
```

不卸载就关机，会留下一个"hive 正在被使用"的状态。下次在别的会话里 `reg load` 同名键会失败，**而失败信息与"键名写错"长得一样**。

<a id="section-28"></a>

#### 陷阱 6：`HKLM\SYSLIVE` 与 `HKLM\SYSLIVE_SW` 混用，改了一个键开机毫无变化

**现象**：改 `WindowsUpdate\AU\NoAutoUpdate` 时写进了 `HKLM\SYSLIVE\...`，开机后 WSUS 照旧向真实更新源注册；或者改服务时写进了 `HKLM\SYSLIVE_SW\...`，服务照常自启。

**原因**：3.1 的引用块把这条单独标了出来：注册表一律写 `HKLM\SYSLIVE`（SYSTEM hive），SOFTWARE 分支才用 `HKLM\SYSLIVE_SW`——混用会导致"改了一个键、开机后毫无变化"的假象。

Windows 自身的结构是：`Services`、`ControlSet001`、`ComputerName` 全在 **SYSTEM**；`Policies\Microsoft\Windows\WindowsUpdate` 在 SOFTWARE。

两个分支的内容看起来都是"注册表"，凭直觉写错分支的概率很高。

**影响**：**同样是"没报错、没变化"**。

后果在概述的表里逐条对应：WSUS 项失败 → 向真实更新源注册、拉取安装补丁（这会改变系统状态，且外部看得见）。

**核查**：**按内容选分支，照 3.4 的分类来**：

```batch
:: WSUS 自动更新 → SOFTWARE 分支
reg add "HKLM\SYSLIVE_SW\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

:: 服务 Start 值 → SYSTEM 分支的 ControlSet001
reg add "HKLM\SYSLIVE\ControlSet001\Services\wuauserv" /v Start /t REG_DWORD /d 3 /f
```

**一项配置改完就验证一次**：

```batch
reg query "HKLM\SYSLIVE_SW\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate
reg query "HKLM\SYSLIVE\ControlSet001\Services\wuauserv" /v Start
```

**改完后的整体验收在启动瞬间做**（3.6：**启动后先观察，再登录**），案例第 4 步的判定表就是这么用的：

| 观察项 | 实际情况 | 判定 |
|---|---|---|
| DNS 服务 | `Running`，但仅监听回环（无网卡所致） | ✅ 未污染真实 DNS |
| IIS (`W3SVC`) | `Stopped`（快照 A 中已设手动） | ✅ 未对外发布站点 |

<a id="section-29"></a>

### 4.3 服务、BCD 与 BitLocker

<a id="section-30"></a>

#### 陷阱 7：★ 用 `bcdedit` 去"禁用恶意启动项"

**现象**：想阻止恶意持久化启动，用 `bcdedit /set` 调整引导项，或者用 `/set {default} recoveryenabled no` 之类的方式"关掉可疑启动"。

**原因**：2.8 的第三条把这件事的荒谬处说清楚了：不要用 `bcdedit` 去"禁用恶意启动项"——恶意持久化通常在 Run 键、计划任务、服务里，`bcdedit` 管不到；而且你并不知道恶意程序是否往 BCD 写过东西。

2.4 那张执行顺序表列出的自启动位置是服务、Task Scheduler、`HKLM\...\Run`、WMI 事件订阅、`HKCU\...\Run`——**BCD 不在表里**。

所以这条操作**既达不到目的，又引入了新的风险**。

**影响**：**风险是不可逆的。**

2.8 的第二条：BitLocker 环境下改 BCD 可能触发恢复模式——若系统盘启用了 BitLocker（尤其 TPM 绑定），修改 BCD 会改变引导测量值，可能要求输入恢复密钥，无密钥则系统彻底无法启动。

而你要达到的目的（阻止持久化）一个也没达到。

**核查**：**更安全的做法是在差分盘内改 Run 键/服务**（2.8 明确推荐）。动手前必须先 `manage-bde -status`（2.8 第二条的加粗）：

```batch
:: 先看 BitLocker，这是本篇的第一个分叉点
manage-bde -status W:
```

**按输出分叉**（3.1 与案例第 2 步）：

```text
Lock Status: Unlocked
  → 可安全改注册表
  → 仍然不要动 BCD（改了可能重新触发锁）

Percentage Encrypted: 100% 且 Lock Status: Locked
  → 立刻停止，不要动任何东西
  → 无恢复密钥的条件下，任何引导相关改动都可能让系统无法启动
```

**案例第 2 步正是这个分叉点**：`Percentage Encrypted: 100%` 但 `Lock Status: Unlocked`——**已加密但已解锁**，据此决定"**可改注册表，但不动 BCD**"。

**要阻止的自启动项，按 2.4 的执行顺序逐个处理**（都在差分盘内）：

```batch
:: 服务：改手动，不是禁用
reg add "HKLM\SYSLIVE\ControlSet001\Services\<服务名>" /v Start /t REG_DWORD /d 3 /f
:: 计划任务与 WMI 订阅不在注册表常规模拟范围内，见 3.7 的运行时采集与离线解析
```

WMI 持久化只能从 WMI repository 解析（2.4：它的实体存在 `%SystemRoot%\System32\wbem\Repository\` 下的 ESENT 数据库，运行时通过 `root\subscription` 暴露为三类对象）——**注册表里没有它**。

<a id="section-31"></a>

#### 陷阱 8：服务用 `Start=4` 禁用，或只禁 `W3SVC` 不禁 `WAS`

**现象**：把服务改成"禁用"（`/d 4`）以求彻底；或者只处理了 `W3SVC`，没管 `WAS`，结果 IIS 仍然部分启动。

**原因**：3.4 的注释给出了取值理由：服务改手动（3=手动，优于 4=禁用，4 会让依赖组件报错）。

`Start=4` 的问题不是"不管用"，而是"太不管用"——依赖该服务的其它组件在启动时会因服务不存在而报错，**结果是系统状态与真实系统不一致**。

而 `Start=3`（手动）保留了服务存在、只是不自动启动，**这是取证仿真需要的状态**。

`WAS` 那一半则来自 3.4 的注释：IIS 需 WAS 与 W3SVC 一起处理，否则仍可能部分启动。

WAS（Web 应用程序服务）是 IIS 的基础组件。只禁上层服务而留着底座，等于留了一条可能自行拉起 IIS 的路径。

**影响**：**状态不一致本身就是失真**。

而 2.3 判定 IIS 危险的依据是"**绑定配置与后端依赖**，而不是站点内容"——如果站点真的上线了（哪怕只起了 WAS），对外发布原本已下线的站点这个后果就成立。

**核查**：**服务改手动，IIS 两个服务一起处理**：

```batch
:: 服务改手动：3=手动，优于 4=禁用
reg add "HKLM\SYSLIVE\ControlSet001\Services\WDSsvc" /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\wuauserv" /v Start /t REG_DWORD /d 3 /f
:: IIS 需 WAS + W3SVC 一起处理，否则仍可能部分启动
reg add "HKLM\SYSLIVE\ControlSet001\Services\WAS"   /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f
```

**顺带把无人值守应答处理掉**（3.4 最后一行、2.6 的第三行）：

```batch
ren "W:\Windows\Panther\Unattend.xml" "W:\Windows\Panther\Unattend.xml.disabled"
```

**改名而不是删除**——它本身是检材内容，**改名保留了可取证的原文件**。

**PXE / WSUS 的风险排序不要搞反**（2.6：PXE 引导文件本身不主动外联，真正的风险是链路层的 DHCP 广播与 ARP 冲突，所以"删网卡"的优先级远高于"删 PXE 文件"）：

| 做法 | 优先级 | 理由 |
|---|---|---|
| 移除虚拟网卡 | **最高** | 同时切断 ARP 与 DHCP 广播 |
| 禁用 `WDSsvc` / `wuauserv` | 中 | 防止向真实更新源注册 |
| 删/改 PXE 引导文件 | 低 | 引导文件本身不外联 |

花时间删 PXE 分区文件而不拔网卡，是这一组里最常见的无用功。

<a id="section-32"></a>

### 4.4 启动瞬间：日志、采集顺序与结论

<a id="section-33"></a>

#### 陷阱 9：不记录原始时区，仿真统一 UTC 后所有时间戳差 8 小时

**现象**：把仿真机时区设为 UTC（这本身是正确做法），但没记录原始时区；分析日志时按本地时间理解事件，**时间线整体偏差 8 小时**，与其它工件交叉验证时对不上。

**原因**：2.9 把时区单列为最容易出错的一项：仿真机保持 UTC 而日志按本地时间记录，所有时间戳会差 8 小时，时间线结论直接错误。

问题的隐蔽之处在于**差值是固定的**。8 小时的偏移不会让日志看起来"不对"，它看起来完全正常——直到与 `$UsnJrnl`、事件日志、浏览器历史交叉验证时才暴露。

而 2.1 把"时间身份"的危害写成"**日志时间错位、C2 心跳异常、证书失效**"。

**影响**：**时间线结论整体作废**。

这是取证分析里最基础也最昂贵的一类错误——**它不会让某个证据消失，而是让所有证据之间失去关联**。

**核查**：原始时区 ID、仿真时区 ID、系统时间（UTC）三项必须齐全（2.9 的加粗原话），顺序是先记录后改：

```powershell
Get-TimeZone | Select-Object Id,DisplayName    # 记录原始时区
Set-TimeZone -Id "UTC"
Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"        # 记录系统时间（UTC）
```

**三项都要进报告**，缺一项就补不回来：

> "**时间对位**：检材原始时区为 `<原始 Id>`，仿真时区为 `UTC`，仿真启动时系统时间为 `<yyyy-MM-ddTHH:mm:ssK>`。报告内所有仿真产生的时间戳均为 UTC；与检材内既有工件交叉对比时已按上述三项完成换算。"

案例结论要点里"原始主机名、IP、时区均已记录"就是这条的落点——仿真环境里的机器身份是证据链的一部分，不是环境配置。

<a id="section-34"></a>

#### 陷阱 10：TaskScheduler Operational 日志默认是关的，误判"计划任务没跑过"

**现象**：启动后查 `Microsoft-Windows-TaskScheduler/Operational`，查不到任何执行记录，结论写"该机无计划任务自动执行"。

**原因**：3.5 的命令注释直接点明：TaskScheduler Operational 日志默认关闭，必须在快照 A 之前启用。

**这是一次典型的"方法不匹配导致的假阴性"。**日志通道本身是关的，`Get-WinEvent` 返回空**不代表没有任务执行，只代表没有记录**。

而 3.7 里查询计划任务执行记录的过滤条件（`Id=100,102,200,201`）写得很完整，**在日志未启用的前提下，那条命令必然返回空**。

**影响**：**结论方向完全相反**。

概述那张表里"执行计划任务：备份、补丁、归档任务立刻跑，**可能覆盖关键数据**"——"没有记录"会被写成"没有执行"，而真实情况可能是"执行了但没留下记录"。

**核查**：**日志预启用必须在快照 A 之前**（3.5、3.6、3.7 三处的顺序约束）：

```powershell
# 快照 A 之前启用（离线预处理阶段）
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

**这条命令的位置是整个流程的硬约束**。3.7 的引用块把整条链的顺序写死了：这些查询本身会写日志和访问时间，必须先拍快照 A 再采集，让"系统启动时的真实状态"被快照固定，后续采集的变化不污染基线。

```powershell
# 启动后采集（此时日志已启用）
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 200 |
  Select-Object TimeCreated,Message | Format-List
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=100,102,200,201} -MaxEvents 100 |
  Select-Object TimeCreated,Message | Format-List
```

**阴性结论按范围限定写**：

> "**计划任务执行检查**：在 `Microsoft-Windows-TaskScheduler/Operational` 日志（快照 A 前已通过 `wevtutil sl ... /e:true` 启用）范围内，查询事件 ID 100/102/200/201，未匹配到记录。该结论不表明本机无自动执行的计划任务——未覆盖范围包括日志启用之前的任何执行、已被轮转覆盖的历史记录，以及以非 TaskScheduler 方式触发的等价行为。"

**案例第 4 步的观察结果正好是这条的反面**：`ServerManager` 任务确实触发了（事件 100/102），判定为"⚠️ 有企业任务在跑"——如果日志没预启用，这一格会是空的，整张判定表都会失真。

<a id="section-35"></a>

#### 陷阱 11：先采集再拍快照，采集动作本身污染了基线状态

**现象**：启动之后先跑一遍 `Get-WinEvent`、`Get-WMIObject`、导出进程树，之后才想起来拍基线快照；或者快照拍了，但快照点选在了"配置完成之后、首次启动之前"以外的时机。

**原因**：3.7 的引用块把原因写清楚了：这些查询本身会写日志和访问时间，必须先拍快照 A 再采集。

而 2.9 定义的三段快照策略里，A 是"隔离态"——断网、改名、改 IP、关杀软之后、首次启动前。

**A 快照必须包含全部隔离配置**，2.9 对违反这一点的定性是：**这是服务器仿真最危险的操作失误**——因为回滚后系统会**重新带着真实身份上线**。

**影响**：**两种失误后果不同，但都不可接受**。

先采集再快照的问题是基线被污染（快照点晚了）。配置不全就快照的问题严重得多——回滚回去的是"裸机状态"，回滚动作本身会把机器带回危险状态。

**核查**：严格的顺序是：配置 → 快照 A → 启动 → 采集（旧表格最后一行"顺序必须是"给的就是这一句）：

```text
① WinPE 离线预处理：挂载、manage-bde -status、reg load、改主机名/服务/杀软/时区、日志预启用
② 确认基础镜像哈希未变
③ 拍快照 A（隔离态，勾选 Include memory）
④ 首次启动 → 先观察，再登录
⑤ 采集启动行为
```

**"先观察，再登录"是一个独立要求**（3.6）：有无自动弹窗、服务启动顺序、DNS 是否绑定真实 IP、IIS 是否上线（访问 `http://127.0.0.1`）——**这些观察必须在登录之前做**，因为登录本身就是一次状态改变（`HKCU\...\Run`、用户配置加载）。

**快照 A 的验收标准是可检查的**，不是"我记得都改了"：

```powershell
Get-Service DNS,W3SVC,NTDS | Select-Object Name,Status,StartType
Get-DnsServerZone -ErrorAction SilentlyContinue | Select-Object ZoneName,Type
Get-TimeZone | Select-Object Id
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,CloudProtectionEnabled,IsTamperProtected
```

**杀软那一项不要期望它一定是关的**（3.5 的引用块给了三级降级）：① 正常 `Set-MpPreference` 关闭；② 被 Tamper Protection 拦截 → 改为**排除整个仿真盘**并接受实时保护存在；③ 仍不行 → 在**差分盘内**删签名库与策略键。

**任何一级都要记入快照并写入报告的"仿真限制"节**——防御组件在运行是真实状态的一部分，隐瞒它比保留它更有害。

**第三方杀软要逐个确认**（2.5：必须逐个确认"会不会把样本传出去"）。旧表格里那条"企业杀静默上传样本到云端"对应的现象在 Defender 上是 `CloudProtectionEnabled` 与 `SubmitSamplesConsent`：

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,CloudProtectionEnabled,IsTamperProtected
Set-MpPreference -DisableRealtimeMonitoring $true -SubmitSamplesConsent 0 -MAPSReporting 0
Add-MpPreference -ExclusionPath "D:\Forensics\Samples"    # 防止样本被隔离 = 证据损坏
Set-Service -Name WinDefend -StartupType Manual -ErrorAction SilentlyContinue
```

<a id="section-36"></a>

#### 陷阱 12：只查 Run 键、服务和计划任务，漏掉 WMI 永久事件订阅

**现象**：按 2.4 的自启动项清单逐项检查——服务、Task Scheduler、`HKLM\...\Run`、`HKCU\...\Run`、Startup 文件夹——全部干净，结论写"未发现攻击者持久化"。

**原因**：2.4 的段落专门讲了 WMI 持久化为什么最隐蔽：**它没有"启动项"外观，触发式运行、平时完全不显形**。

它的实体在 `%SystemRoot%\System32\wbem\Repository\` 下的 ESENT 数据库里，运行时才通过 `root\subscription` 命名空间暴露为 `__EventConsumer`、`__EventFilter`、`__FilterToConsumerBinding` 三类对象。

在磁盘镜像里必须去解析这个数据库。只看注册表或任务管理器都看不到它。

**影响**：**直接漏掉攻击者的持久化手段**。

这不是"少查了一项"的问题——**它会让整个"该机被控"或"该机未被控"的判断翻转**。

**核查**：运行时查三类对象，离线时解析 WMI repository：

```powershell
# 运行时：root\subscription 命名空间
Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
```

离线时（WMI repository 位置来自 2.4）：

```text
%SystemRoot%\System32\wbem\Repository\  —— ESENT 数据库
在磁盘镜像上离线解析该数据库，提取三类对象
```

**案例第 4 步的结果就是这条的价值证明**：`__EventConsumer` 中存在 `CommandLineEventConsumer`，`Name: DGFORENSICS_1_CONSUMER`，`CommandLineTemplate: powershell -nop -w hidden -enc SQBFAFgA...`，在 `EventID 1` 触发执行——它完全没有出现在 Run 键、服务列表或计划任务中。只做一次"启动项检查"必然漏掉它。

**这个发现的处理方式值得照抄**（案例第 4、5 步与结论要点）：**回滚快照 A 两次，重复采集确认结论可复现**；WMI 订阅的编码命令单独提取并哈希固定，作为独立证据提交——理由是它是镜像中原本存在的静态数据，不受仿真环境影响。

**最后一步照例不可省**：再次计算基础镜像哈希确认与第 1 步一致（**基础盘零改动**），`Power Off` 后归档基础镜像 + `.vmsd` + `.vmsn` + 录屏 + 采集输出。

<a id="section-37"></a>

## 五、案例示例

<a id="section-38"></a>

### 5.1 域控仿真：一次启动项检查会漏掉的 WMI 订阅

**场景**

查获一台 Windows Server 2012 R2 域控（IP `10.20.5.30`，主机名 `DC-FIN-01`），该机被控后发生凭据窃取。检材 `DigiForensics.E01`（500 GB）。需观察启动时的自动行为，重点是 AD/DNS/IIS 三个服务。委托方的问题是：它上还有没有残留的自动执行。

选择这一路径的依据是域控启动会加载 AD 数据库并试图做 AD 复制与 DNS 解析。直接启动一台被控过的域控，可能把污染带出实验室；而逐项检查启动项则会漏掉 WMI 订阅这一类。

**处置过程**

**第 1 步 · 转换与基础隔离**：按 04 篇 3.1 节把 `DigiForensics.dd` 转为 `DigiForensics-base.vmdk` 并完成往返哈希验证。虚拟机移除网卡、移除光驱/打印机/串口、Guest Isolation 全关、内存 6 GB、CPU 4 核。

第 2 步 · BitLocker 状态确认（关键分叉点）：在 WinPE 中挂载系统卷后执行 `manage-bde -status W:`，输出 `Percentage Encrypted: 100%` 但 `Lock Status: Unlocked`——已加密但已解锁。

**据此决定：可改注册表，但不动 BCD。**

第 3 步 · 离线改身份 + 时区 + 日志预启用：按 3.2、3.4、3.5 节执行——主机名改 `DGFORENSICS-01`、NetBIOS 域清空、WSUS 禁用、`W3SVC`/`WAS` 改手动、Defender 关实时保护并排除样本目录、时区设 UTC、启用 TaskScheduler 日志。

**第 4 步 · 拍快照 A 并首次启动**，确认基础镜像哈希与第 1 步一致后拍 `A-isolated`（Include memory），启动后 90 秒内的实际观察：

| 观察项 | 实际情况 | 判定 |
|---|---|---|
| DNS 服务 | `Running`，但**仅监听回环**（无网卡所致） | 未污染真实 DNS |
| `NTDS` | `Running`，日志出现 `DsRole=Owner` | 已加载 AD 数据库 |
| IIS (`W3SVC`) | `Stopped`（快照 A 中已设手动） | 未对外发布站点 |
| 计划任务 | 事件 100/102 显示 `ServerManager` 任务触发 | 有企业任务在跑 |
| WMI 订阅 | `__EventConsumer` 中存在 `CommandLineEventConsumer` | **确认持久化** |

**关键发现**：该 DC 被控后留下一个 **WMI 永久事件订阅**——`Name: DGFORENSICS_1_CONSUMER`，`CommandLineTemplate: powershell -nop -w hidden -enc SQBFAFgA...`，在 `EventID 1` 触发执行。

它完全没有出现在 Run 键、服务列表或计划任务中。

**第 5 步 · 收工与可复现性验证**：再次计算基础镜像哈希确认与第 1 步一致（**基础盘零改动**）；回滚快照 A 两次，重复采集 WMI 订阅确认结论可复现；最后 `Power Off`，归档基础镜像 + `.vmsd` + `.vmsn` + 录屏 + 采集输出。

**结论**

能证明：因采用**无网卡启动**，AD 复制与 DNS 污染**物理上不可能发生**——这是本案例最重要的风险控制结论。WMI 订阅的编码命令已单独提取并哈希固定，作为**独立证据**提交：它是镜像中原本存在的静态数据，不受仿真环境影响。原始主机名、IP、时区均已记录。

**不能证明**：IIS 未启动，因此**无法观察站点恢复行为**，这属于本次仿真的设计取舍，须在报告中标注为局限。

**误判对照**

最像的误判是把"Run 键、服务列表、计划任务都干净"当成"没有持久化"。

判据在 WMI 订阅的存储位置上：它存放在 WMI 仓库的 `root\subscription` 下，是一个绑定了事件过滤器的永久事件消费者（`__EventConsumer`），而不是注册表 Run 键、也不是计划任务。

传统的"启动项三查"在数据模型上就覆盖不到它。

正确判据是`__EventConsumer` / `__FilterToConsumerBinding` / `__EventFilter` 三个类必须成组检查，且它们在离线状态下可读，不必启动系统。

按错误判据走的代价，是这份结论直接关系到"被控域控是否已被彻底清理"。若据此签发清场证明，那条订阅会继续在真实域控上以 `EventID 1` 触发执行——而它的载荷是 `powershell -nop -w hidden -enc`，正是凭据窃取的典型形态。

<a id="section-39"></a>

### 5.2 BitLocker 的 Unlocked 状态如何决定改什么

**场景**

同一批检材中，另一台 Server 2012 R2 的 `manage-bde -status` 输出与上一台不同：`Lock Status: Locked`。委托方要求按同样的方案处理。

将此情形单列的原因是同一类检材在 BitLocker 这一步会分出两条完全不同的处置路线，而判断依据就是一个字段。

**处置过程**

1. 在 WinPE 中挂载系统卷并查状态，两台机器输出对照：

```text
DC-FIN-01（5.1 检材）：
  Conversion Status:    Fully Encrypted
  Percentage Encrypted: 100%
  Lock Status:          Unlocked      → 可改注册表

SR-APP-02（本节检材）：
  Conversion Status:    Fully Encrypted
  Percentage Encrypted: 100%
  Lock Status:          Locked        → 不可改注册表
```

2. 分叉判断：`Unlocked` 意味着卷密钥在当前启动周期内已被解锁，改注册表不影响其可读性；`Locked` 意味着改注册表等于写入密文数据区，**写进去的内容在本环境里不可读，等于损坏镜像**。

3. `SR-APP-02` 的处置改为：不改任何注册表，只做 `manage-bde -unlock W: -rk <恢复密钥文件>` 后重新评估；若恢复密钥不可得，则该机的仿真到此为止，仅提交离线取证结论。

**结论**

能证明：`DC-FIN-01` 的身份隔离改写（主机名、NetBIOS 域、WSUS、服务启动类型）是安全的，因为卷处于 Unlocked 状态。`SR-APP-02` 的 BitLocker 处于 Locked，未做任何改写，检材保持原状。

**不能证明**：`SR-APP-02` 上是否存在持久化——因为该机仿真未进行，其启动行为未观察。这属于**因技术约束而未覆盖的范围**，必须在报告中列明，不能用"未发现问题"表述。

**误判对照**

最像的误判是把"Percentage Encrypted: 100%"当作"可以正常挂载修改"。

判据要划清这两个字段的含义：加密率 100% 只说明卷内所有扇区都被加密，不说明此刻密钥是否可用。

`Lock Status` 才是决定能否写入的那个字段。`Locked` 状态下你甚至可能连挂载都失败，或挂载成功后写入的内容无法解密。

正确判据是每次改任何东西之前，先确认 `Lock Status: Unlocked`，这个顺序不能省。

按错误判据走的代价，是往密文数据区写入注册表 hive——**这类损坏在离线状态下完全不可见**：哈希会变但看不出变了什么，直到有人尝试解锁时才暴露，而那时原始注册表内容已经不可恢复。

<a id="section-40"></a>

### 5.3 反例：仿真前没改主机名就启动域控

**场景**

某次域控仿真中，团队跳过身份隔离步骤直接启动。系统以原主机名 `DC-FIN-01` 完成了 AD 数据库加载，事件日志出现 `DsRole=Owner` 记录。虽然无网卡导致复制请求无法发出，但仿真机的系统身份已与真实域控重名。

该批仿真记录被归档前做了复盘。这条列为反例，是因为**它看上去没造成任何实际损害**——没有网卡，什么都没发出去。

**处置过程**

对照点在于身份信息的三个必改项：

```bash
# 漏改的后果不是"发出去了"，而是"它曾经以真实身份存在过"
# 三项都要离线改：
#   主机名      -> DGFORENSICS-01
#   NetBIOS 域  -> 清空
#   WSUS        -> 禁用（避免向真实更新源发起请求）
```

日志中的具体表现：

```text
EventLog: NTDS 启动记录出现 DsRole=Owner
EventLog: Kerberos 记录中出现原 NetBIOS 域成员身份
时间线： 与该 DC 真实的最后在线时间（关机前）落在同一台机器的启动序列中
```

**结论**

阴性发现：该次仿真**未发生**任何对外网络请求（无网卡），因此未污染真实环境。

**但该批仿真的启动序列证据不可采信**——系统身份未经隔离，机器与真实域控同名。

**误判对照**

最像的误判是"没有网卡，所以什么都没发生，安全"。

判据要指出无网卡挡得住什么、挡不住什么：无网卡能阻断网络请求，但阻断不了系统加载与身份生效。

`NTDS` 照样启动、域成员身份照样注册进本地 SAM 与 Kerberos 票据缓存、主机名照样出现在事件日志与日志来源名称里。

按错误判据走的代价，是这个案例真正的问题：归档后的仿真记录一旦被当作"该 DC 在受控状态下的启动表现"引用，而记录里明写着原主机名，对方无法判断这段启动日志到底来自真实机器还是仿真机。

证据的可采性取决于身份隔离这一步，而不是取决于"没有实际损害"这个自我评估。

---

---
<a id="section-41"></a>

## 六、扩展阅读方向

**前置与基础。** 仿真之前得先有隔离规范。基础盘、差分盘与快照
三者的职责不能混，差分盘一旦被写坏就回不到原始证据的状态，
前提条件见 [《虚拟机仿真》](imaging-mount-simulate-virtual-machine-emulation.md)。

**同层深入。** NTDS 是这批工件里分量最重的。`ntds.dit` 的离线解析、
DNS 记录与 AD 对象的对应关系、Replication Metadata 里留下的删改痕迹，
三者要放在一起读——单独看到一条记录往往只是快照时刻的正常状态。
IIS 侧同样成体系：`web.config` 的解析、应用程序池状态、
`inetpub\logs` 的日志格式与时区设置都要确认，
时区设错会让整条时间线整体偏移。

**相邻议题。** WMI 持久化是域控上的常驻手段，
`CommandLineEventConsumer` 的各种变体、FilterToConsumer 绑定关系、
Event ID 1 至 19 各自的触发条件都需要逐条核对。
PXE 与引导取证涉及 `BCD` 结构解析、`boot.wim` 的无人值守配置、
`bootmgr` 引导记录，它们决定了域控是怎么被引导起来的。
身份与证书同样关键，AD CS 证书模板、机器账户证书、
`SIDHistory` 与跨域信任关系，能解释一个账号为什么出现在它不该出现的位置。

**工具与判据。** 时间线对位是本篇的收口工作：
事件日志的时区处理、`$UsnJrnl` 与事件日志的交叉验证，
再加上域控授时偏差的估算，三者缺一都会让时间线站不住。
服务器侧工件的取证优先级见
[《Windows Server 工件地图》](../../server/server-log/server-log-server-artifact-map.md)，
其中 IIS、W3C 日志、PowerShell 4104 的位置各不相同。

**判据与反例。** 域控上的时间戳不能单独作为定案依据。
域控授时本身可能偏差几秒到几分钟，未校正就直接对齐事件顺序，
会得出「先下载后执行」这类完全颠倒的因果。
同理，Replication Metadata 中的删除记录只说明对象被删过，
不说明删除者身份——那要另找审计日志来支撑。

---

<a id="section-42"></a>

## 七、命令速查

```batch
:: ===== WinPE 离线阶段（统一用 SYSLIVE / SYSLIVE_SW，禁止写 CurrentControlSet）=====
diskpart
list volume
select volume 3
assign letter=W
exit
manage-bde -status W:                :: 先确认 BitLocker，再决定能不能动 BCD
reg load HKLM\SYSLIVE    W:\Windows\System32\config\SYSTEM
reg load HKLM\SYSLIVE_SW W:\Windows\System32\config\SOFTWARE

:: 改主机名（下次启动生效）+ 清 NetBIOS 域标识
reg add "HKLM\SYSLIVE\ControlSet001\Control\ComputerName\ActiveComputerName" /v ComputerName /t REG_SZ /d "DGFORENSICS-01" /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\Tcpip\Parameters" /v Domain /t REG_SZ /d "" /f

:: 禁用 WSUS 自动更新（SOFTWARE 分支）
reg add "HKLM\SYSLIVE_SW\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
:: 服务改手动（3=手动，优于 4=禁用）；IIS 需 WAS + W3SVC 一起处理
reg add "HKLM\SYSLIVE\ControlSet001\Services\WDSsvc" /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\WAS"   /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SYSLIVE\ControlSet001\Services\W3SVC" /v Start /t REG_DWORD /d 3 /f
ren "W:\Windows\Panther\Unattend.xml" "W:\Windows\Panther\Unattend.xml.disabled"

reg unload HKLM\SYSLIVE_SW
reg unload HKLM\SYSLIVE
```

```powershell
# ===== 网络身份（仅隔离网段内需要）=====
Get-NetIPConfiguration | Format-List InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
  Remove-NetIPAddress -Confirm:$false      # 先删原地址；New-NetIPAddress 只是追加
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.77.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue

# ===== 杀软（先记录状态再改；被 Tamper Protection 拦截属预期）=====
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,CloudProtectionEnabled,IsTamperProtected
Set-MpPreference -DisableRealtimeMonitoring $true -SubmitSamplesConsent 0 -MAPSReporting 0
Add-MpPreference -ExclusionPath "D:\Forensics\Samples"
Set-Service -Name WinDefend -StartupType Manual -ErrorAction SilentlyContinue

# ===== 时区与日志预启用 =====
Get-TimeZone | Select-Object Id,DisplayName
Set-TimeZone -Id "UTC"
Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true   # 快照 A 之前启用

# ===== 启动行为采集 =====
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 200 |
  Select-Object TimeCreated,Message | Format-List
# WMI 永久订阅：磁盘实体在 wbem\Repository，运行时才在此暴露
Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
Get-DnsServerZone -ErrorAction SilentlyContinue | Select-Object ZoneName,Type
Get-Service DNS,W3SVC,NTDS | Select-Object Name,Status,StartType
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 磁盘镜像与仿真 — Windows Server 环境仿真」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Windows Server 环境仿真》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.E01`、`DigiForensics-base.vmdk` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
