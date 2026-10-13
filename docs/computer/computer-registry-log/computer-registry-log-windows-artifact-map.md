---
title: "取证工件地图"
slug: "computer-registry-log-windows-artifact-map"
canonical: "https://www.digiforensics.cn/wiki/computer-registry-log-windows-artifact-map"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["注册表与事件日志"]
---

# 取证工件地图

<a id="section-1"></a>

## 一、概述

拿到一台 Windows 主机镜像，第一个问题是：**证据在哪里？**

Windows **不给你一个集中的审计日志**。「谁在什么时候做了什么」散落在几十个互不相干的位置——注册表 hive、`.evtx` 文件、目录里的二进制缓存、SQLite 数据库、隐藏的 NTFS 数据流。这些工件分属不同子系统，各有自己的生命周期、保留策略和清除方式。有的重启就重建，有的删掉就再也回不来。

两类处置错误都源于此：

- 查获了一台**运行中的机器**，直接拔电关机。**结果丢失当前会话的内存态工件**（ShimCache 未落盘条目、浏览器会话、剪贴板、网络连接），**且改变了系统状态**。
- 只提取了「看得见」的文件（`Users\` 下的文档），**漏掉了 `C:\Windows` 下的系统工件**——而执行痕迹、登录记录、持久化证据几乎全在后者里。

要回答的问题只有一个：每类工件在哪里、值多少、活多久、怎么被清掉。分类的依据是「谁记录的」——因为清除难度决定了**攻击者会先清哪里、因此哪里残留得最可信**。

这张地图卡在「拿到设备」到「逐工件分析」之间，是**采集阶段的决策依据**。上游是镜像制作与接入，它不产出证据，决定的是能不能拿到证据。地图本身要产出三样：Windows 版本判定（**决定用哪个解析器**）、工件存在性清点、接入未污染证据的验证。下游支撑所有具体篇目——有了地图，才知道哪个方向有料、哪个方向是空的，而**「空的」往往也是结论**。

工件全景按证据类型组织如下：

| 类别 | 记录者 | 典型工件 | 清除难度 |
|---|---|---|---|
| **显式审计** | Windows 安全/审计子系统 | `Security.evtx`、`System.evtx`、Sysmon | ★★★★ 可被 `wevtutil cl` 清除 |
| **性能优化副产品** | 内核为加速启动而缓存 | Prefetch、ShimCache、Amcache | ★★★ 需清缓存/删文件，重启后重建 |
| **Shell 便利功能** | 资源管理器为 UX 记录 | LNK、JumpList、RecentDocs、UserAssist | ★★ 用户可在设置里一键关闭 |
| **应用自身数据** | 各应用自己的数据库 | 浏览器、邮件、聊天软件、Office | ★ 用户可自删历史 |
| **文件系统元数据** | NTFS 驱动 | `$MFT`、`$LogFile`、`$UsnJrnl` | ★★★★ 需占用空闲区，极难 |
| **一个容易被忽略的层级** | 卷影副本（VSS） | 每个快照是某时刻的**完整文件系统视图** | 取证入口 `mklink /d X: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`，**每个快照对应唯一卷** |

同一份工件，XP 和 Win11 上可能根本不叫同一个名字、也不在同一个位置。选错解析器，读出来的是垃圾。

| 差异点 | XP/2003 | Vista/7 | 8/8.1 | 10/11 |
|---|---|---|---|---|
| **事件日志格式** | `.evt`（16KB 定长） | `.evtx` | `.evtx` | `.evtx` |
| **Prefetch** | v17，1 个时间戳 | v23，1 个时间戳 | v26，8 个时间戳 | v30/v31，MAM 压缩 |
| **Prefetch 条目上限** | 128 | 128 | 128 | 1024 |
| **ShimCache 容量** | 96 | 512 | 512 | 1024 |
| **Amcache** | `RecentFileCache.bcf` | `RecentFileCache.bcf` | `Amcache.hve` | `Amcache.hve` |
| **Jump List / SRUM** | 无 / 无 | 有限 / 无 | 有 / 有 | 有 / 有 |
| **Sysmon** | 不支持 | 不支持 | 支持 | 支持 |
| **ShimCache 路径** | `Session Manager\AppCompatCache`（**无内层子键**） | `Session Manager\AppCompatCache\AppCompatCache` | 同 | 同 |

**读法：拿到镜像先确定版本，再决定用哪个解析器。**

据此能判断的是：这台机器的 Windows 版本、哪些工件实际存在、每个工件的位置与取证价值、以及**各类工件的清除难度与被清理的可能性**。

判断不了的有六条：

- **按「清除难度」分类的价值在于反推。** 攻击者的反取证会**从易到难**清——先清浏览器历史，再清事件日志，再删 Prefetch。`$UsnJrnl` 与 `$LogFile` 因为清理需要占用空闲区并可能被占用空间保护，**通常被放弃**。因此「事件日志缺失」本身就是值得记录的发现，不能直接读成「没有活动」。
- **任何具体行为。** 地图只标注位置与价值，**不解释任何单个工件的语义**。
- **存在性之外的可用性。** 工件存在不代表数据完整——是否被覆盖、是否超出保留期、是否被清理，要在具体篇目里判断。
- **VSS 里的内容。** 快照存在与否要靠 `vssadmin list shadows` 揭示，**默认保留空间有限，快照可能很少或很小**。
- **跨主机的关联。** 单台主机的地图回答不了「它连着谁」。
- **已删除数据。** 地图基于现存文件，**已删除内容需要卷层面的恢复能力**。

往下读之前先确认你已经完成镜像制作与完整性校验，**并且理解「为什么先验证哈希再分析」**；具备 Windows 的基础结构认知——注册表 hive、事件日志、`%SystemRoot%` 与用户配置文件的位置；了解 NTFS 的基本概念（MFT、备用数据流），见[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)；熟悉只读挂载与仿真环境，**VSS 与挂载都是在仿真环境里做的**，见[虚拟机仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md)。同时清楚**绝不可逆的操作清单**：VSS 枚举是只读的，但绝不要用 `vssadmin delete shadows` 清空间——那是直接销毁证据。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 工件按"谁记录的"分为五类

每类痕迹由哪个子系统写入、在什么时候写入，直接决定了它的可信度和清除难度。

| 类别 | 记录者 | 典型工件 | 清除难度 |
|---|---|---|---|
| **显式审计** | Windows 安全/审计子系统 | `Security.evtx`、`System.evtx`、Sysmon | ★★★★ 可被 `wevtutil cl` 清除 |
| **性能优化副产品** | 内核为加速启动而缓存 | Prefetch、ShimCache、Amcache | ★★★ 需清缓存/删文件，重启后重建 |
| **Shell 便利功能** | 资源管理器为 UX 记录 | LNK、JumpList、RecentDocs、UserAssist | ★★ 用户可在设置里一键关闭 |
| **应用自身数据** | 各应用自己的数据库 | 浏览器、邮件、聊天软件、Office | ★ 用户可自删历史 |
| **文件系统元数据** | NTFS 驱动 | `$MFT`、`$LogFile`、`$UsnJrnl` | ★★★★ 需占用空闲区，极难 |

> **实战推论**（第一章已述，此处不再展开）：攻击者的反取证会**从易到难**清，`$UsnJrnl` 和 `$LogFile` 因清理成本高通常被放弃。因此"事件日志缺失"本身就是值得记录的发现，不能直接读成"没有活动"；逐类缺失的表述强度见陷阱 4。

<a id="section-4"></a>

### 2.2 工件目录结构总览

下表是 Windows 取证的**核心索引**。路径以 Windows 10/11 为基准，其他版本差异见 2.4。

**系统级（`C:\Windows\`）**

| 路径 | 工件 | 价值 | 参见 |
|---|---|---|---|
| `System32\config\SYSTEM` | 硬件/服务/控制集/ShimCache | ★★★★★ | [02](computer-registry-log-registry-forensics.md)、[06](../computer-execution/computer-execution-shimcache-amcache.md) |
| `System32\config\SOFTWARE` | 已安装软件、SRUM 配置、卸载残留 | ★★★★★ | [02](computer-registry-log-registry-forensics.md)、[09](../computer-browser-behavior/computer-browser-behavior-srum.md) |
| `System32\config\SAM` / `SECURITY` | 本地账户与密码哈希 / LSA 秘密 | ★★★★★ | [02](computer-registry-log-registry-forensics.md) |
| `System32\sru\SRUDB.dat` | **SRUM 资源使用数据库** | ★★★★★ | [09](../computer-browser-behavior/computer-browser-behavior-srum.md) |
| `System32\winevt\Logs\*.evtx` | 事件日志（含 Sysmon） | ★★★★★ | [03](computer-registry-log-windows-event-log-analysis.md)、[04](computer-registry-log-sysmon.md) |
| `Prefetch\*.pf` | **程序执行证据** | ★★★★★ | [05](../computer-execution/computer-execution-prefetch.md) |
| `AppCompat\Programs\Amcache.hve` | 程序哈希/编译时间 | ★★★★ | [06](../computer-execution/computer-execution-shimcache-amcache.md) |
| `System32\Tasks\` / `inf\setupapi.dev.log` | 计划任务 / 设备安装历史 | ★★★★ | — |

**用户级（`C:\Users\<用户名>\`）**

| 路径 | 工件 | 价值 | 参见 |
|---|---|---|---|
| `NTUSER.DAT` | **用户注册表**：RecentDocs、UserAssist、RunMRU、TypedPaths | ★★★★★ | [10](computer-registry-log-user-activity-artifacts.md) |
| `AppData\Roaming\Microsoft\Windows\Recent\*.lnk` | **快捷方式（含 TrackerDataBlock）** | ★★★★★ | [07](../computer-execution/computer-execution-lnk-jumplist.md) |
| `...\Recent\AutomaticDestinations\*.automaticDestinations-ms` | **Jump List** | ★★★★★ | [07](../computer-execution/computer-execution-lnk-jumplist.md) |
| `AppData\Local\Google\Chrome\User Data\Default\` | Chrome 密码/历史/Cookie | ★★★★★ | [08](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) |
| `AppData\Local\Microsoft\Edge\User Data\` | Edge 同上 | ★★★★★ | [08](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) |
| `AppData\Roaming\Mozilla\Firefox\Profiles\` | Firefox `logins.json`/`key4.db` | ★★★★★ | [08](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) |
| `AppData\Local\Microsoft\Recall\` 或 `AppData\Local\CoreAIPlatform.00\` | **Recall 相关** | ★★★★★ | [12](../computer-browser-behavior/computer-browser-behavior-windows11-recall.md) |
| `AppData\Local\Microsoft\Windows\INetCache\` | IE/Edge Legacy 缓存 | ★★★ | [08](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) |

**系统元数据（NTFS 层，不在目录树中正常显示）**

| 对象 | 位置 | 价值 |
|---|---|---|
| `$UsnJrnl:$J` | `$Extend` 目录 | ★★★★★ |
| `$MFT` | 见 `fsstat` 输出 | ★★★★★ |
| `$LogFile` | NTFS 根 | ★★★★ |
| `$Recycle.Bin\<SID>\$I*` | 回收站元数据 | ★★★★ |
| 卷影副本 `System Volume Information\` | **历史版本文件** | ★★★★★ |
| `hiberfil.sys` / `pagefile.sys` | 休眠镜像 / 可搜字符串 | ★★★★ |

> `$UsnJrnl` 与 `$MFT` 的解析参见本板块[第 11 篇](../computer-execution/computer-execution-usn-journal-timeline.md)与《文件系统分析》板块。

**回收站（`$Recycle.Bin`）**

`$I` 文件是 8 字节版本头 + 8 字节文件大小 + 8 字节删除时间（FILETIME）+ 路径长度 + UTF-16 路径；`$R` 是被删内容原件。

删除时间来自 `$I` 文件，而非 `$R` 的 MFT 时间戳。 两条时间线冲突时，这是关键区分点。

<a id="section-5"></a>

### 2.3 一个容易被忽略的层级：卷影副本（VSS）

**卷影副本是"时间机器"**，但只有知道快照存在才能用。

- 每个快照是某时刻的卷快照，包含当时的**完整文件系统视图**。
- 快照数量与大小由 `vssadmin list shadows` 揭示；默认保留空间有限，快照可能很少或很小。
- **取证入口**：`mklink /d X: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`，每个快照对应**唯一卷**，需与 `vssadmin` 输出的 Original Volume 对应。

```powershell
vssadmin list shadows        # 列出所有卷影副本（管理员权限）
vssadmin list shadowstorage  # 查看影子副本存储占用
```

> ⚠️ VSS 枚举是只读操作，对运行中的机器相对安全。但绝不要用 `vssadmin delete shadows` 清空间——那是直接销毁证据。

<a id="section-6"></a>

### 2.4 Windows 版本差异对取证的实际影响

选错解析器会得到错误结论，而不只是"报个错"。用 v17 解析器读 v31 的 Prefetch，或用 16K `.evt` 解析器读 `.evtx`，出来的是垃圾或「文件损坏」。

| 差异点 | XP/2003 | Vista/7 | 8/8.1 | 10/11 |
|---|---|---|---|---|
| **事件日志格式** | `.evt`（16KB 定长） | `.evtx` | `.evtx` | `.evtx` |
| **Prefetch** | v17，1 个时间戳 | v23，1 个时间戳 | v26，8 个时间戳 | v30/v31，MAM 压缩 |
| **Prefetch 条目上限** | 128 | 128 | 128 | 1024 |
| **ShimCache 容量** | 96 | 512 | 512 | 1024 |
| **Amcache** | `RecentFileCache.bcf` | `RecentFileCache.bcf` | `Amcache.hve` | `Amcache.hve` |
| **Jump List / SRUM** | 无 / 无 | 有限 / 无 | 有 / 有 | 有 / 有 |
| **Sysmon** | 不支持 | 不支持 | 支持 | 支持 |
| **ShimCache 路径** | `Session Manager\AppCompatCache`（**无内层子键**） | `Session Manager\AppCompatCache\AppCompatCache` | 同 | 同 |

读法同第一章：拿到镜像先确定版本，再决定用哪个解析器。

<a id="section-7"></a>

### 2.5 取证工作站配置

分析环境本身也是证据链的一环——**分析工具的行为可能改变你读到的数据**。

| 要求 | 理由 |
|---|---|
| **只读挂载，永不写回** | 挂载点设为只读；写保护器最保险 |
| **关闭 AutoPlay** | 挂载可能触发自动运行、缩略图生成、journal 回放 |
| **不改系统时区/时钟** | 事件日志时间是本地时间，时区错误会导致全盘时间线错位 |
| **记录工具版本与哈希** | 同名工具不同版本解析结果可能不同，报告需可复现 |

> 任何"我打开看了一下"的操作，如果是在原始镜像上做的，都可能因 atime 更新、journal 回放、预览生成缩略图而**改变证据**（逐项影响见陷阱 2）。**先复制，后分析。**

---

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：镜像结构确认与工件存在性清点

```bash
mmls DigiForensics.dd                                    # 分区布局
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'cluster|mft|serial|volume name'
fls -o 2048 -r -p /work/DigiForensics.dd > /evidence/fls-all.txt

# 工件存在性（"缺失"本身是发现）
grep -ic 'prefetch' /evidence/fls-all.txt     # Prefetch 文件数
grep -ic 'amcache'  /evidence/fls-all.txt     # Amcache 是否存在
grep -icE '\.evtx$' /evidence/fls-all.txt     # 事件日志数量
grep -i  'usnjrnl'  /evidence/fls-all.txt     # UsnJrnl 位置
```

<a id="section-10"></a>

### 3.2 第 2 步：判断版本与 Prefetch 格式

**先看 `.pf` 头部 4 字节**——这一步决定后续所有解析器选择：

```bash
icat -o 2048 /work/DigiForensics.dd <pf-inode> > /evidence/sample.pf
xxd -l 16 /evidence/sample.pf
```

| 输出开头 | 含义 | 应对 |
|---|---|---|
| `4D 41 4D 04`（`MAM\x04`） | **Win10/11 MAM 压缩** | 必须先用 PECmd 等工具解压 |
| `1F 00 00 00` / `1E 00 00 00` | v31 / v30 | 高版本解析器 |
| `1A 00 00 00` / `17 00 00 00` / `11 00 00 00` | v26 / v23 / v17 | 对应版本解析器 |
| 偏移 4 处 `53 43 43 41`（`SCCA`） | 未压缩，签名在固定位置 | 常规解析 |

<a id="section-11"></a>

### 3.3 第 3 步：提取注册表 hive、事件日志与元数据

```bash
mkdir -p /evidence/hives
# hive 路径以实际系统为准，常见 /Windows/System32/config
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  ino=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\$" | head -1 | cut -d' ' -f2)
  icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/hives/$h"
done
for h in /evidence/hives/*; do echo -n "$h: "; xxd -l 4 -p "$h"; done   # 期望 72656766

# 用户 hive / 事件日志：先用 fls 定位 inode，再逐个 icat
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'NTUSER\.DAT$|UsrClass\.dat$|\.evtx$'

# SRUM 数据库（ESE 头 89 ABCD EF）与 $LogFile
icat -o 2048 /work/DigiForensics.dd <srum-inode> > /evidence/SRUDB.dat
icat -o 2048 /work/DigiForensics.dd 2-0-0 > /evidence/LogFile.bin
```

> ⚠️ `grep -E "config/$h\$"` 精确匹配，避免误取 `SYSTEM.LOG1` 事务日志；`$UsnJrnl:$J` 是**稀疏流**，`icat` 会补零成完整声明大小（可能几十 GB），应改用 `ExtractUsnJrnl` 之类只导出实际数据的工具。

<a id="section-12"></a>

### 3.4 第 4 步：VSS 快照与验证

VSS 快照无法从 raw 镜像直接读取：需用 FTK Imager、X-Ways 等挂载后访问，或用专用工具解析 `System Volume Information`。

**验证环节（每一步都要做）**：

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 分区定位 | `fsstat` 的 Volume Serial | 与 `$MFT` 读出的序列号一致 |
| hive 完整性 | `xxd -l 4` | 输出 `72656766`（`regf`） |
| SRUM 完整性 | `xxd -l 4` | 输出 `89abcdef`（ESE 魔数） |
| `.pf` 格式 | 头部魔数 | 与判定的系统版本一致 |
| 提取文件 | `stat -c %s` | 长度等于 `istat` 报告的 Size |

---
<a id="section-13"></a>

## 四、常见陷阱

<a id="section-14"></a>

### 4.1 现场处置与接入方式

<a id="section-15"></a>

#### 陷阱 1：★ 查获运行中的机器，直接拔电关机

**现象**

扣押到一台正在运行的 Windows 主机，为"保护数据"直接拔掉电源。报告里写「为保护证据已立即关机」。

**原因**

关机这个动作**本身在销毁证据**，销毁的是最难事后替代的一类（内存态无法从磁盘重建）。

Windows 上多类工件**只在内存中或只在运行时落盘**：

| 工件 | 落盘时机 | 关机后 |
| --- | --- | --- |
| ShimCache（AppCompatCache） | **常驻内存，正常关机/重启时才写入 hive** | 尚未落盘的条目**永久丢失** |
| 内存态 NetScan（`NetStat` 驱动数据） | 仅内存 | 永久丢失 |
| 剪贴板内容 | 内存 | 永久丢失 |
| 浏览器会话、Cookie 会话态 | 内存 + 缓存 | 丢失 |
| 当前网络连接、NetBIOS 缓存 | 内存 | 丢失 |
| 页面文件中的可恢复残留 | 运行时持续写入 | 随回收丢失 |

ShimCache 这一条尤其关键 —— 在上表这些执行相关工件里，它不依赖 `EnablePrefetcher` 这类功能开关，但依赖正常关机才落盘；硬断电会让关机前尚未刷盘的条目消失（推演见 5.3）。

**影响**

- 「立即关机保护证据」的表述本身就是**事实性错误**，关机恰恰是改写证据状态的动作
- 内存态工件永久失去，报告里出现无法闭合的证据缺口
- 复核人看的是"当时的信息支撑下这个决策是否合理"。没记录 `ShutdownTime`、登录状态、内存态价值就直接关机，**决策缺少依据**

**核查**

**关机是一个需要记录依据的权衡决策**：

```bash
# 决策前必须采集的判断依据
systeminfo | findstr /B /C:"System Boot Time"     # 等价 uptime
fdesetup status 2>/dev/null; manage-bde -status C: # 磁盘加密状态
query user                                          # 是否有用户在线
```

| 现场状态 | 处置 | 记录要求 |
| --- | --- | --- |
| 近期有使用且内存态工件有价值 | **先做内存采集 → 正常关机 → 镜像** | 写明采集清单、采集时刻、决策人 |
| 长期闲置、内存态无价值 | 正常关机 → 镜像 | 写明"因启动时间显示长期无活动，内存态采集价值低" |
| 疑似作案进行中 | **保持现状，立即记录全部现场状态** | 录像、拍照、记录连接状态，不做任何操作 |

即使决定不采集内存，也必须在现场记录里写清"评估过、判断价值为低、理由是 XXX" —— 省略这一步在复核时与"没想过"无法区分。

**内存采集优先级**（关机前）：

| 优先级 | 内容 | 工具 |
| --- | --- | --- |
| **P0** | 进程、网络连接、NetScan | FTK Imager / Magnet RAM Capture / DumpIt |
| **P0** | 已登录用户与会话 | 同上（`who` / `quser`） |
| **P1** | 剪贴板、已打开文件句柄 | 同上 + `lsof` 类 |
| P1 | 内存中的 ShimCache 镜像 | 内存镜像留存，离线再解析 |

<a id="section-16"></a>

#### 陷阱 2：用资源管理器浏览挂载点，或在分析机上把镜像挂成可写

**现象**

把镜像挂载后在文件管理器里双击目录查看，发现 Prefetch 文件"打不开"，于是挂成可写再试。报告里写「已浏览镜像确认工件存在」。

**原因**

**在挂载点上做的每一个"看一眼"都可能改写证据**，这是本篇最需要反复强调的一点：

| 操作 | 实际影响 |
| --- | --- |
| 双击目录 / 打开文件 | 更新 MFT 中的 `atime`（最后访问时间），**这是元数据的实际写入** |
| 资源管理器生成缩略图 | **会在文件系统里创建新文件** |
| 自动播放 / AutoPlay | 可能执行镜像内的程序 |
| journal 回放 | 挂载时可能重放日志，改写文件状态 |
| 挂成可写 | 任何工具产生的辅助文件都留在检材里 |

`atime` 的影响是连锁的：LNK 头里的 `AccessTime` 快照需要与目标文件的 `atime` 对照，时间戳类分析全部依赖 `atime` 的原始值。

**影响**

- **破坏证据同一性**，与"全程未改写证据"的声明直接冲突
- `atime` 被更新后，时间线分析出现无法解释的偏移
- 这类问题在质证时才暴露，届时无法自证

**核查**

**用命令行工具 + 写保护器 + 基线哈希三重保险**：

```bash
# 1) 挂载前算基线
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256

# 2) 只读挂载 + 关闭 AutoPlay
mount -o ro,loop,noatime /work/DigiForensics.dd /mnt/ev
#       noatime 进一步避免访问时间更新（部分挂载选项支持）
mount | grep ' /mnt/ev '          # 必须确认 ro

# 3) 全部用命令行工具，不用资源管理器
fls -o 2048 -r -p /work/DigiForensics.dd > /evidence/fls-all.txt
icat  -o 2048 /work/DigiForensics.dd <inode> > /evidence/xxx.dat

# 4) 卸载后复核
umount /mnt/ev
shasum -a 256 -c /evidence/baseline.sha256      # 必须输出 OK
```

分析工作站的配置要求见 2.5（四条：只读挂载 + 写保护器、关闭 AutoPlay、不改系统时区 / 时钟、记录工具版本与哈希）。原则一句话：先复制，后分析。任何"我打开看了一下"都不该在原始镜像上做。

<a id="section-17"></a>

### 4.2 工件清点与完整性校验

<a id="section-18"></a>

#### 陷阱 3：忘记 `regf` / ESE 魔数校验，把空文件或事务日志当 hive 分析

**现象**

按路径提取注册表 hive，脚本里 `grep -E "config/$h$"` 匹配到 `SYSTEM.LOG1`，提取后直接用 `rip.exe` 打开，报一堆错。或者是提取出了 0 字节文件，工具报"文件格式错误"，报告写"该 hive 已损坏"。

**原因**

**注册表目录里不只有 hive 本体，还有事务日志**：

```text
C:\Windows\System32\config\
├── SYSTEM            ← hive 本体
├── SYSTEM.LOG1       ← 事务日志 1
├── SYSTEM.LOG2       ← 事务日志 2
├── SOFTWARE
├── SOFTWARE.LOG1
├── SAM  SECURITY  DEFAULT  ...
```

用宽松匹配会把 `SYSTEM.LOG1` 当成 `SYSTEM` 取走。取到事务日志后：

- 头部不是 `regf`，解析器报"格式错误"
- 内容确实是注册表相关的记录，容易被误认为"hive 的一部分"
- 实际上它与 hive 本体是不同文件，不能互相替代

提取到空文件的情况更隐蔽：脚本没有检查退出码，文件已创建但是 0 字节，后续步骤才报错。

**每个 hive 都要先做魔数校验**：

| 对象 | 期望魔数 | 命令 |
| --- | --- | --- |
| 注册表 hive | `72656766`（ASCII `regf`） | `xxd -l 4 -p "$h"` |
| SRUM / ESE 数据库 | `89abcdef`（ESE 魔数） | `xxd -l 4 -p "$f"` |
| Prefetch（MAM 封装） | `4d414d04`（`MAM\x04`） | `xxd -l 4 -p "$f"` |

**影响**

- 「hive 损坏」是**关于镜像获取过程的事实性指控**，一旦复核发现只是取错了文件，报告可信度受严重影响
- 事务日志被当 hive 分析，得到的注册表内容是残缺且错位的
- 0 字节文件没被发现，后续所有基于该 hive 的结论都建立在空数据上

**核查**

**精确匹配 + 逐个校验 + 失败即停**：

```bash
mkdir -p /evidence/hives
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  # 精确匹配，避免误取 SYSTEM.LOG1 等事务日志
  ino=$(fls -o 2048 -r -p /work/DigiForensics.dd \
        | grep -E "/Windows/System32/config/$h\$" | head -1 | awk '{print $2}')
  [ -z "$ino" ] && { echo "缺失: $h"; continue; }
  icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/hives/$h"
  # 逐个校验
  printf '%-12s ' "$h"
  xxd -l 4 -p "/evidence/hives/$h"        # 期望 72656766
  stat -c '%s bytes' "/evidence/hives/$h"  # 期望非 0
done
```

校验表与 3.4 相同（分区定位、hive / SRUM / `.pf` 魔数、提取长度），此处不再重复。

**注意 `fls -p` 的列序**：`mode`(1) `inode`(2) `name`(3) `size`(4)，**inode 在第 2 列**。取错列会把带空格的路径当 inode 传给 `icat`，得到空文件且不报错。

<a id="section-19"></a>

#### 陷阱 4：把"工件缺失"直接写成否定结论

**现象**

Prefetch 目录为空，报告写「该机在案发时段未执行可疑程序」。Security 日志只到案发前一天，报告写「案发时段无登录记录」。

**原因**

缺失至少有四类技术性成因，每类对应的结论强度完全不同：

| 缺失类型 | 典型情形 | 正确表述 |
| --- | --- | --- |
| **从未启用** | `EnablePrefetcher=0`（**服务器版默认值**）；Sysmon 未部署；审计策略未配置 | 「该机制在本机未启用，**此类记录本就不存在**」 |
| **已覆盖 / 已淘汰** | Prefetch 达到容量上限（10/11 为 1024 项）；日志达到大小上限轮转；SRUM 窗口 30–60 天 | 「超出保留窗口/容量上限，**更早记录已被覆盖**」 |
| **已清理** | 目录被删；`wevtutil cl`；反取证行为 | 「**存在清理迹象**，需寻找清理动作本身留下的痕迹」 |
| **未落盘** | 系统硬断电；内存态工件未采集 | 「**属证据未落盘，无法判断**」 |

第四类尤其容易被忽略，而它恰恰是硬断电案件里最常见的。

由此得到「按清除难度分类」的实际用途：缺失原因未查清之前，任何一类工件为空都只能写成「该机制未启用 / 已覆盖 / 已清理 / 未落盘」四选一，不能写成行为否定（判据见 2.1 的成本阶梯）。

**影响**

- **结论方向错误**：「未执行可疑程序」可能被推翻，而委托方已据此做出决策
- 混淆了"证据没落盘"与"行为没发生"，掩盖了真实的取证能力边界
- 漏掉"缺失本身就是发现"这个视角 —— 日志被清空是比"日志里没有"更强的信号

**核查**

**逐个工件说明缺失原因，再给结论强度**：

```bash
# Prefetch：先查是否启用
rip.exe -p /evidence/hives/SYSTEM -a /tmp/pf.txt prefetchparameters
# ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
#   EnablePrefetcher = 0     ← 服务器版默认值，缺失非人为

# Security 日志：查是否被清空
evtx_dump.py /evidence/logs/Security.evtx | grep 'EventID.*1102'
# 1102 = 日志被清除事件，本身是被篡改的证据
```

| 查到的成因 | 报告表述 |
| --- | --- |
| `EnablePrefetcher = 0` | 「本机 Prefetch **从未启用**（`EnablePrefetcher=0`），**其缺失不构成"被清理"的证据**」 |
| 有 1102 事件 | 「Security 日志被人为清空 3 次（`1102`，时间为…），**此为独立的篡改信号**」 |
| `ShutdownTime` 早于案发时段 | 「因强制断电，该时段执行痕迹**未落盘，无法据此判断**」 |
| 容量上限 / 窗口期 | 「超出保留窗口/容量上限，**更早记录已被覆盖**」 |

**报告里把"证据局限"与"事实结论"分成两节陈述**，不要混在同一段里。

<a id="section-20"></a>

#### 陷阱 5：把 Amcache 缺失当成"Win8 以下"

**现象**

在一台 Windows 7 机器上没找到 `Amcache.hve`，报告写「该机为 Win7，使用的是 `RecentFileCache.bcf`」。而这台机器其实装过 KB2952664，那是有 `Amcache.hve` 的。

**原因**

**用版本推断替代存在性检查**，而实际部署情况经常与版本默认值不一致：

| 系统版本 | 默认工件 | 例外 |
| --- | --- | --- |
| XP/2003 | 无 | — |
| **Vista / 7** | `RecentFileCache.bcf` | Win7 装过 KB2952664 也有 `Amcache.hve` |
| 8/8.1/10/11 | `Amcache.hve` | 可能被删除或从未生成 |

**影响**

- 选错提取路径，漏掉实际存在的工件
- 更根本的问题是**方法论错误**：用版本推断替代事实检查，会在所有工件上重演

**核查**

**以实际文件存在为准，不靠版本推断**：

```bash
# 两个路径都试，并做全盘兜底
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -iE 'AppCompat/Programs/(Amcache\.hve|RecentFileCache\.bcf)$'

# 兜底
fls -o 2048 -r /work/DigiForensics.dd | grep -iE 'AppCompat|Amcache|RecentFileCache'
```

**报告写法**：「该检材为 Windows 7（`CurrentBuild` 7601）。`AppCompat\Programs\` 下实际存在 `Amcache.hve`，已按 Win8+ 格式解析。**工件类型以实际文件存在为准，未按版本推断。**」

<a id="section-21"></a>

### 4.3 元数据工件与阴性结论

<a id="section-22"></a>

#### 陷阱 6：★ `$UsnJrnl` 用 `icat` 导出撑爆磁盘

**现象**

按普通文件的方式用 `icat` 导出 `$UsnJrnl:$J`，磁盘被写满，分析中断。

**原因**

`$UsnJrnl:$J` 是稀疏流（sparse stream）。逻辑大小可能是几十 GB，实际分配的数据量远小于此。`icat` 会**补零成完整声明大小** —— 导出的文件里绝大部分是零字节填充。

| 属性 | 值 |
| --- | --- |
| 逻辑大小（`fls` 报告） | 可能几十 GB |
| 实际分配 | 通常几十到几百 MB |
| `icat` 行为 | **补零到逻辑大小** |

这与"导出失败"完全不同 —— 它会**成功**产出一个巨大的文件，占满磁盘。

**影响**

- **磁盘写满导致分析中断**，其他正在进行的提取也受影响
- 前面已经完成的工作可能因磁盘满而无法保存
- 严重时可能波及系统盘，影响分析工作站稳定性

**核查**

**先看声明大小，再用只导出实际数据的工具**：

```bash
# 1) 先看 fls 报告的声明大小
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'usnjrnl'
# 记下 Size 字段（这是逻辑大小）

# 2) 用只导出实际数据的工具，不要用 icat
#    ExtractUsnJrnl / usnjrnl_carver 之类
#    目标磁盘空间需求 = 实际数据量，不是逻辑大小
df -h /evidence
```

**报告里要记录 `$UsnJrnl` 的两项数据**：

| 项 | 用途 |
| --- | --- |
| 逻辑大小 | 判断日志容量与轮转周期 |
| 实际导出量 | 证明导出完整 |

**同类问题**：`$LogFile` 也是稀疏的，但相对小，通常可以正常导出。`hiberfil.sys` / `pagefile.sys` 则是正常文件（不是稀疏流），可直接提取。

<a id="section-23"></a>

#### 陷阱 7：忘换算分区偏移，`-o` 直接传 0 或猜值

**现象**

`fls -o 2048` 改成 `fls` 或 `-o 0`，列出的文件混乱，或 grep 不到预期路径，报告写"该目录下无相关工件"。

**原因**

**`-o` 偏移是基于分区而非磁盘。** raw 镜像的前若干扇区是 MBR/GPT 等引导结构，NTFS 分区从某个扇区开始。这个偏移值必须确认，不能猜。

```bash
# 1) 先列分区布局
mmls /work/DigiForensics.dd
# 输出示例：
#       Offset      Sector         Size
# 0x00000000             0          1MB  (MBR)
# 0x00000800          2048       476GB  (NTFS, OSDisk)

# 2) 用 fsstat 确认该偏移确实是 NTFS
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'File System Type|Cluster Size|Volume Serial'
#   File System Type: NTFS
#   Volume Serial: 9a3f21c4
```

**影响**

- **产生一整批虚假阴性结论** —— 所有"未找到 X"都可能只是偏移错了
- 而这批假阴性结论一旦写进报告，很难被发现
- 多卷或 GPT 布局的磁盘上，猜偏移会连正确的卷都定位不到

**核查**

**偏移必须两步确认，并做交叉验证**：

```bash
# 1) mmls 拿到候选偏移
mmls /work/DigiForensics.dd

# 2) fsstat 确认文件系统类型与序列号
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'File System Type|Volume Serial'

# 3) 交叉验证：序列号应与 $MFT 读出的一致
#    试列出顶层目录，结果应符合预期
fls -o 2048 /work/DigiForensics.dd / | head -20
# 期望看到 /Users /Windows /Program Files 等
```

**报告里写明偏移的来源与验证方式**：「卷偏移 `2048` 由 `mmls` 读取，`fsstat` 确认该位置为 NTFS 且 `Volume Serial` 为 `9a3f21c4`，与 `$MFT` 读出的序列号一致，目录列表符合预期。」

<a id="section-24"></a>

#### 陷阱 8：先查 SQLite 浏览器库，未先复制 `-journal` / `-wal`

**现象**

把镜像挂载后直接对挂载点里的 `History`、`Login Data` 执行 `sqlite3` 查询，得到结果就以为正确。报告写「已查询浏览历史」。

**原因**

SQLite 在写入过程中，主库可能处于不一致状态：

- rollback journal 模式（`-journal`）：事务进行中，主库有未提交的改动，直接读会读到中间态
- **WAL 模式（`-wal` / `-shm`）**：最新事务在 `-wal` 里，**主库本身可能看不到**
- 这两种状态下 `sqlite3` 打开**不一定报错**，可能返回一个看起来完整但内容偏旧或偏新的结果

而且对**挂载点**里的数据库直接查询，还可能因为写锁、journal 回放而影响检材（见陷阱 2）。
**影响**

- 拿到的是**不一致快照**，条数、最后访问时间都可能不对
- 报告会写「访问历史已完整提取」，而实际缺失了最近事务
- 更麻烦的是这类错误**不报错**，无法通过异常发现

**核查**

先复制 DB + journal + wal 三个文件，再在副本上查询：

```bash
# 1) 定位三个文件（-wal / -shm / -journal 是独立文件，需分别定位 inode）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'User Data/Default/History(-wal|-shm|-journal)?$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/browser/$(echo "$ino" | sed 's/.*-//')"
    done

# 2) 在副本上用 immutable 模式只读打开，sqlite 不会回写
sqlite3 "file:/evidence/browser/History.db?immutable=1" ".tables"

# 3) 若 -wal 存在且 mtime 晚于主库，报告中必须写明
ls -la /evidence/browser/History.db*
```

**报告里要交代**：

| 情形 | 报告表述 |
| --- | --- |
| 三件套齐全且 `-wal` 已随主库组装 | 「主库与 `-wal` / `-shm` 一并提取，查询结果为一致态」 |
| `-wal` `mtime` 晚于主库 | 「存在未 checkpoint 事务，**完整边界以 `-wal` 内容为准**」 |
| 三件套不存在 | 「已正常关闭或已 checkpoint，主库自洽，**无未落盘记录**」 |

<a id="section-25"></a>

#### 陷阱 9：把 VSS 当备份，用 `vssadmin delete shadows` 清空间

**现象**

分析过程中磁盘空间不足，执行 `vssadmin delete shadows /all /quiet` 释放空间。继续分析时发现"历史版本文件"全部消失。

**原因**

**卷影副本是"时间机器"**，每个快照包含当时的**完整文件系统视图**（结构见 2.3）。它的取证价值在于：

- 案件时段的文件**已被删除但快照里还在**
- 文件**被篡改前的原始版本**可能只在快照里
- 快照能覆盖日志轮转、文件覆盖导致的所有数据丢失

`vssadmin delete shadows` 是**直接销毁**，不可逆。而清理空间这个动作动机往往是完全无害的（磁盘满了），但后果是永久的。
**影响**

- **历史版本文件永久灭失**，可能正是证明文件被篡改的唯一来源
- 这一步之后，报告里所有关于"文件是否被改"的论证都失去了主要证据来源
- 若委托方后续需要追责，销毁证据的性质远比磁盘空间问题严重

**核查**

VSS 只读枚举，绝不删除；需要空间时先导出快照内容：

```powershell
# 只读枚举（对运行中的机器相对安全）
vssadmin list shadows        # 列出所有卷影副本
vssadmin list shadowstorage  # 查看影子副本存储占用

# 访问快照：每个快照对应唯一卷，需与 Original Volume 对应
mklink /d X: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\
```

**注意**：VSS **无法从 raw 镜像直接读取** —— 需用 FTK Imager、X-Ways 等挂载后访问，或用专用工具解析 `System Volume Information`。

**报告写法**：「检出 N 个卷影副本，最早快照 `T0`、最新快照 `T1`。已只读访问并导出与案件相关的历史版本文件（清单见附录 X）。**未执行任何删除操作，卷影副本存储保持原状。**」

<a id="section-26"></a>

#### 陷阱 10：把"日志被清空"当"无活动"

**现象**

Security 日志只覆盖到案发前一天，报告写「案发时段无登录记录，未发生未授权访问」。

**原因**

日志被清空本身就是应当优先追查的发现，而不是"没有活动"的证据。关键在找清空动作留下的痕迹：

| 机制 | 说明 |
| --- | --- |
| **`1102` 事件** | **Security 日志被清除事件** —— `wevtutil cl` 会留下这条记录，它在**被清除前**写入的日志末尾 |
| **`104` 事件** | 事件日志被清除（`System` 通道，`EventLog` 类别） |
| `ClearEventLog` API | 与 `wevtutil cl` 类似 |
| 日志文件大小突变 | 结合 `MFT` 时间戳可见异常 |

`1102` 事件的存在是决定性的 —— **它记录的是"有人清除了日志"这个动作本身**。而"没有活动"是与之完全相反的解读。

结合反取证的成本阶梯来看这个信号的强度（阶梯本身的成因见 2.1）：

```text
攻击者清理成本：浏览器历史（易） < 事件日志（中） < Prefetch（中）
                 < $UsnJrnl（难，需占用空闲区） < $LogFile（难）
```

事件日志位于"中"等成本区间，在成本与收益的权衡下被清理往往意味着日志里有值得清理的内容。这一推论只支持"优先追查"，不单独支撑"日志里必有入侵行为"——日志被清空也可能是合规基线轮换、软件卸载残留或日志大小上限自然轮转，需要结合相邻记录的时间连续性判断。

**影响**

- **方向完全颠倒**：强篡改信号被写成阴性结论
- 委托方据此认为没有入侵，而实际上有人刻意销毁了记录
- 错过追问"谁在 23:51 有权限清日志"这个关键问题

**核查**

**先查清空事件，再定结论**：

```bash
# Security 通道的日志清除事件
evtx_dump.py /evidence/logs/Security.evtx | grep -c 'EventID.*1102'
# → 3 条 1102 事件，时间：2024-11-14 23:51 / 2024-11-15 01:12 / 2024-11-15 06:33

# System 通道的日志清除事件（更早的痕迹）
evtx_dump.py /evidence/logs/System.evtx | grep -E 'EventID.*(104|103)'
```

| 观察 | 结论表述 |
| --- | --- |
| 有 `1102` / `104` 事件 | 「**Security 日志被人为清空 3 次**（`1102`，时间为…），**此为独立的篡改信号，指向人为反取证**」 |
| 无清空事件但日志截断 | 「日志末条记录为 `T1`，此后无记录。未发现清空事件，成因可能为日志大小上限轮转或异常关机导致未落盘」 |
| 日志完整覆盖案发时段 | 「日志完整覆盖案发时段，**未见异常**」 |

**关键区分**：「**日志缺失**」与「**日志中有清除记录**」是完全不同的两件事，后者是发现，前者需要进一步查明成因。
<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 Prefetch 缺失的三种成因区分与注册表定案

**场景**

查获一台 Windows 11 专业版笔记本（1 TB NVMe）。委托方要求还原「2024-11-15 前后该机是否外接过存储设备、是否被人为清理过痕迹」。

镜像 `DigiForensics.dd`（raw，1 TB），NTFS 分区起始扇区 2048，簇大小 4096，卷序列号 `9a3f21c4`。系统为**现场断电状态**，有强制关机痕迹。

**处置过程**

第一步，确认卷结构与系统版本（版本决定 Prefetch 格式预期）：

```bash
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'cluster size|mft cluster|serial|volume name'
# Cluster Size: 4096   MFT Cluster: 0x40000
# Volume Serial: 9a3f21c4   Volume Name: OSDisk

rip.exe -p /evidence/hives/SOFTWARE -a /tmp/sw.txt currentversion
# → Build 22631 (Win11 23H2)  → Prefetch 预期为 v31 + MAM 压缩
```

第二步，清点工件存在性（这一步本身就有价值）：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd > /evidence/fls-all.txt
python3 - <<'PY'
t = open("/evidence/fls-all.txt", encoding="utf-8", errors="replace").read().lower()
print("Prefetch 文件数:", t.count("prefetch"))
print("Amcache 存在   :", t.count("amcache"))
print("evtx 数量      :", sum(1 for l in t.split("\
") if l.endswith(".evtx")))
PY
```

```text
Prefetch 文件数: 0
Amcache 存在   : 1
evtx 数量      : 34
```

第三步，到注册表找 Prefetch 缺失的原因——陷阱 4 列出的四类成因里，是否启用由这个值直接判定：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/mem.txt prefetch
```

```text
ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
  EnablePrefetcher = 0
```

第四步，穷举「Prefetch 为何缺失」的全部候选并逐条排除：

```bash
python3 - <<'PY'
cands = [
 ("版本不产生 Prefetch", "Win11 23H2 默认 v31+MAM，本应产生", "排除"),
 ("目录被手动删除",      "Directory 存在但为空/缺失，且 EnablePrefetcher>0", "本案不符"),
 ("被安全软件清理",      "Prefetch 目录内容被反取证工具批量删除", "本案不符"),
 ("策略/组策略禁用",     "EnablePrefetcher 被设为 0", "★ 命中"),
 ("磁盘被加密/虚拟化",   "无 BitLocker/TPM 时全盘加密不启用，Prefetch 不降级", "排除"),
]
for a, b, c in cands:
    print(f"{a:22s} {b:44s} {c}")
PY
```

第五步，独立检查日志侧的篡改信号：

```bash
evtx_dump.py /evidence/logs/Security.evtx | grep -c 'EventID.*1102'
```

```text
3 条 1102 事件：
  2024-11-14 23:51:07
  2024-11-15 01:12:44
  2024-11-15 06:33:19
```

**结论**

`fls -r` 全卷递归显示 Prefetch 相关文件数为 **0**，但 `SYSTEM` hive 的 `ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher = 0`，证明本机本就不记录 Prefetch，其缺失不构成「被清理」的证据。

把「目录为空」直接写成「有人清理了痕迹」，会凭空制造一条不存在的篡改行为，并误导委托方把调查方向指向反取证工具。

Amcache 存在 1 处、evtx 共 34 个，工件基础正常。真正独立的篡改信号来自 Security 日志：事件 ID 1102（日志被清除）共出现 **3 次**，时间分别为 2024-11-14 23:51:07、2024-11-15 01:12:44、2024-11-15 06:33:19，**指向明确的人为反取证行为**。该结论与 Prefetch 缺失完全无关，不受其影响。

**误判对照**

最容易出错的地方是把「Prefetch 目录为空」直接读成「有人清理了痕迹」。正确判据是先查 `EnablePrefetcher` 这个注册表原始值来区分成因：取值为 0 或 1 时系统本就不产生 EXE 级 Prefetch 条目，取值为 2 或 3 时才产生；本案 `EnablePrefetcher = 0` 说明缺失是系统配置所致。

按错误判据写成「Prefetch 被清理」，会得出「攻击者清理了执行痕迹」这一虚构结论。委托方据此排查员工反取证软件、追查内鬼方向，全部基于一条不存在的事实；而真正存在的篡改证据（1102 事件）反而被这条错误结论掩盖了。

第二处易错点是把「Prefetch 为空」与「1102 事件」合并成一条「痕迹被清理」的复合结论。正确判据是两者的成因、指向与强度完全不同：Prefetch 缺失由系统配置决定，是**常态**；1102 是 Security 日志被清除，是**异常**且带精确时间戳。

按错误判据合并，会把一条强证据（1102，明确的人为清除）稀释成一条弱证据（「Prefetch 为空 + 日志被清，二者疑似同一原因」），反而降低了两条各自独立的价值。

第三处易错点是看到 `EnablePrefetcher = 0` 就认为「没有任何执行痕迹」，转而放弃执行类分析。正确判据是 Prefetch 只是执行痕迹的一种载体，且 Windows Server 与部分安全加固策略的默认值为 0；执行痕迹仍可由 Amcache（`InstallDate`、`SHA-1`、`First Run`）、ShimCache（路径登记）、LNK、UserAssist、Sysmon 事件 ID=1 等多处获得。

按错误判据放弃执行分析，会漏掉本案 USB 接入后程序的运行情况，而那恰恰是委托方最关心的问题。

<a id="section-29"></a>

### 5.2 USBSTOR 与 System.evtx 双源印证外接存储

**场景**

Security 日志在事发前后被清空 3 次，常规的 `20001`/`20003` 设备安装事件在 `Security` 通道已不可用。需要在日志被清除的条件下，仍然确定「是否外接过存储设备、何时接入」。

**处置过程**

第一步，绕开被清空的日志，从注册表 `USBSTOR` 枚举设备：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor
```

```text
USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\60A44C4128AF
  FirstInstallDate = 2024-11-15 01:07:44
  LastArrivalDate   = 2024-11-16 09:22:11
  LastRemovalDate   = 2024-11-16 09:24:03
```

第二步，到 `System` 通道找独立印证（`System` 日志未被清除）：

```bash
EvtxECmd.exe -f /evidence/logs/System.evtx --csv /evidence/evtx_out
grep -iE '20001|20003' /evidence/evtx_out/System*.csv | grep -i '60A44C4128AF'
```

```text
2024-11-15 01:07:44  20001  \Device\HarddiskVolume3  首次连接  序列号 60A44C4128AF
2024-11-15 01:09:02  20003  \Device\HarddiskVolume3  安装媒体已挂载
2024-11-16 09:22:11  20003  \Device\HarddiskVolume3  媒体移除
```

第三步，把两源时间做精确比对：

```bash
python3 - <<'PY'
reg  = {"FirstInstallDate": "2024-11-15 01:07:44", "LastArrivalDate": "2024-11-15 01:09:02",
        "LastRemovalDate":   "2024-11-16 09:24:03"}
evtx = {"20001 首次连接": "2024-11-15 01:07:44", "20003 挂载": "2024-11-15 01:09:02",
        "20003 移除":     "2024-11-16 09:22:11"}
print("注册表 FirstInstallDate:", reg["FirstInstallDate"])
print("System.evtx 20001      :", evtx["20001 首次连接"])
print("是否秒级一致:", reg["FirstInstallDate"] == evtx["20001 首次连接"])
PY
```

```text
是否秒级一致: True
```

第四步，确认该设备是否有卷标或盘符等可归属特征：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/mnt.txt mounteddevices
# → \DosDevices\F:  →  \Device\HarddiskVolume3
fls -o 2048 /work/DigiForensics.dd 0x0 2>/dev/null | head -3
```

第五步，把 USB 时间点与日志清除时间做交叉分析：

```bash
python3 - <<'PY'
ev = [("2024-11-14 23:40:22", "ShutdownTime（最后正常关机）"),
      ("2024-11-14 23:51:07", "1102 Security 日志第 1 次清除"),
      ("2024-11-15 01:07:44", "USBSTOR 首次安装 / 20001"),
      ("2024-11-15 01:09:02", "卷 F: 挂载"),
      ("2024-11-15 01:12:44", "1102 Security 日志第 2 次清除"),
      ("2024-11-15 06:33:19", "1102 Security 日志第 3 次清除")]
for t, d in sorted(ev):
    print(f"{t}  {d}")
PY
```

**结论**

`SYSTEM` hive 的 `USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0\60A44C4128AF` 记录 `FirstInstallDate = 2024-11-15 01:07:44`，与 `System.evtx` 中事件 20001 的时间**精确到秒一致**，构成双源印证。

可认定该机在 2024-11-15 01:07 接入过 Kingston DataTraveler 3.0 U 盘，序列号 `60A44C4128AF`，并在 01:09:02 挂载为盘符 `F:`。`LastArrivalDate = 2024-11-15 01:09:02`、`LastRemovalDate = 2024-11-16 09:24:03` 说明设备在跨越近 32 小时后仍有再次接入与移除记录。

时间线交叉显示：最后正常关机 2024-11-14 23:40:22 → 第 1 次日志清除 23:51:07 → USB 接入 01:07:44 → 卷挂载 01:09:02 → 第 2 次日志清除 01:12:44（USB 接入后 5 分钟）→ 第 3 次清除 06:33:19。

**误判对照**

最容易产生的误判是「`Security` 日志被清空了，USB 接入查不到了」。正确判据是 USB 设备枚举信息不只存在于 `Security` 通道——`SYSTEM` hive 的 `USBSTOR` 子键持久保存设备型号、序列号与首次安装/最后到达/最后移除时间，属于注册表而非事件日志，不受日志清除影响；`System` 通道的 20001/20003 设备安装事件同样是独立通道。

按错误判据认为「查不到了」，会漏掉本案能锁定 USB 接入时刻的双源证据，而委托方最核心的问题恰恰是「是否外接过存储设备」。

第二处易错点是把 `LastArrivalDate` 当成「首次接入时间」。正确判据是三个字段语义不同——`FirstInstallDate` 是该设备在本机**第一次**被枚举的时间且终身不变，`LastArrivalDate` 是**最近一次**被系统检测到的时间，`LastRemovalDate` 是最近一次移除时间；本案 `FirstInstallDate = 2024-11-15 01:07:44` 与 `LastArrivalDate = 2024-11-15 01:09:02` 相差 78 秒，正好对应「首次插入 → 系统完成枚举并开始工作」的过程。

按错误判据用 `LastArrivalDate` 作为首次接入时间，会丢掉「该设备是首次出现在本机」这一关键属性——在多台机器共用同一 U 盘的场景中，这一步的区别决定了「这台机器上的行为」与「那台机器上的行为」能否区分。

第三处易错点是把 USB 接入写成「发生了数据拷贝」。正确判据是 `USBSTOR` 与 20001/20003 事件只证明**设备被枚举并挂载**，不涉及任何数据流；是否发生读写必须由该 U 盘自身的文件系统证据（`$MFT`、文件时间、目录内容）或端点日志支撑，本案 U 盘未作为检材提交。

按错误判据写「数据已拷贝至 U 盘」，是把设备接入这一间接线索说成已证事实；而正确的时间线陈述还应指出：第 2 次日志清除（01:12:44）发生在 USB 接入后 5 分钟，这一时间关系本身就是需要解释的异常，但不能直接写成「复制完就清日志」，因为日志清除可能针对其它目的。

<a id="section-30"></a>

### 5.3 断电导致 ShimCache 时间缺口必须写成局限

**场景**

委托方询问：「USB 接入之后，该机上都运行过哪些程序？」需要明确 ShimCache 这条证据路线在本案中能支撑到什么程度，以及为什么。

**处置过程**

第一步，确定最后一次正常关机时间：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# \ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 23:40:22
```

第二步，把 USB 时间与关机时间对齐，判断时间窗：

```bash
python3 - <<'PY'
sd = "2024-11-14 23:40:22"
usb_first = "2024-11-15 01:07:44"
usb_rm = "2024-11-16 09:24:03"
print("最后正常关机 :", sd)
print("USB 首次接入 :", usb_first, " 晚于关机 →", usb_first > sd)
print("USB 最后移除 :", usb_rm)
print("→ 整个 USB 使用窗口完全落在最后一次正常关机之后")
PY
```

```text
USB 首次接入 : 2024-11-15 01:07:44  晚于关机 → True
→ 整个 USB 使用窗口完全落在最后一次正常关机之后
```

第三步，解析 ShimCache 并确认其中确实无 USB 相关条目：

```powershell
AppCompatCacheParser.exe -f C:\evidence\hives\SYSTEM --csv C:\evidence\out
```

```text
ShimCache 共 634 条，最新 InsertedTime = 2024-11-14 23:31:55
检索 F:\ 与 Kingston 相关路径 → 0 条
```

第四步，做假设推演，验证「无条目」是机制必然而非人为清除：

```bash
python3 - <<'PY'
print("假设 A（本案，断电）  : ShimCache 停留在 23:40 关机时的 634 条，最新 23:31:55")
print("假设 B（若 11-16 09:24 正常关机）: 应包含 F:\\ 与 USB 程序的登记")
print("实际：最新 InsertedTime=23:31:55，与假设 A 一致、与假设 B 矛盾")
print("★ 断电由 ShutdownTime=23:40:22 + 现场断电状态双重佐证")
PY
```

第五步，改从可落盘的工件补齐该时段：

```bash
# Amcache 不依赖关机
AmcacheParser.exe -f /evidence\hives\Amcache.hve --csv C:\evidence\out
```

```text
F:\	ools\backup_copy.exe  SHA1=7d3e2f1a…  FirstRun=2024-11-15 01:11:37
```

第六步，把局限与事实分开陈述：

```bash
python3 - <<'PY'
print("【事实结论】")
print("  USB 于 2024-11-15 01:07:44 接入（USBSTOR + System.evtx 20001 双源）")
print("  Amcache 显示 F:\\	ools\\backup_copy.exe 首次运行 01:11:37")
print()
print("【证据局限】")
print("  ShimCache 中无 F:\\ 相关条目 —— 因断电未落盘，属机制性缺失，")
print("  不能据此判断『未执行』；也无法确定该时段运行的其它程序。")
PY
```

**结论**

`ShutdownTime = 2024-11-14 23:40:22`，而 USB 首次接入为 2024-11-15 01:07:44、最后移除为 2024-11-16 09:24:03。整个 USB 使用窗口完全落在最后一次正常关机之后。

磁盘上的 ShimCache 常驻内存、仅在正常关机时刷盘，因此该 USB 窗口内程序的登记不会落到盘上的 `AppCompatCache`。解析所得 ShimCache 共 634 条、最新 `InsertedTime = 2024-11-14 23:31:55`（早于关机时间），检索 `F:\` 与 Kingston 相关路径为 0 条——假设推演确认这与断电假设一致、与正常关机假设矛盾，断电事实由 `ShutdownTime` 与现场状态双重佐证。

**报告必须将此项写为证据局限而非事实结论**：不能据「ShimCache 无相关条目」判断「未执行相关程序」，也无法确定该时段运行的其它程序。

改从不依赖关机的 Amcache 入手，取得 `F:\	ools\backup_copy.exe` 的 `FirstRun = 2024-11-15 01:11:37`（位于 USB 接入后 3 分 53 秒），作为该时段程序运行的替代证据。

**误判对照**

本案例的核心误判是把「ShimCache 中无 USB 相关条目」写成「未执行 USB 上的程序」。正确判据是 ShimCache 的落盘时机决定了它的可见范围——它常驻内存，仅在正常关机时批量写回 `SYSTEM` hive 的 `AppCompatCache`；本案最后一次正常关机在 23:40:22，而 USB 使用窗口是 01:07 之后，这些登记在内存中存在了 30 多小时，最终随断电全部丢失。

按错误判据写「未执行」，会把一条纯粹由落盘机制造成的空白当成否定性证据；而实际上 Amcache 的 `FirstRun = 01:11:37` 证明该时段确实有程序运行，两份工件在本案中的结论直接冲突，正是断电机制造成的。

第二处易错点是把这条局限当作「无法分析」，直接放弃该时段的程序执行分析。正确判据是执行类证据中只有 ShimCache 高度依赖关机落盘，Amcache 的 `FirstRun`、Prefetch 的逐次即时写入、Sysmon 事件 ID=1、`UserAssist` 的注册表值都不依赖正常关机，仍然可用。

按错误判据整段放弃，会漏掉 `F:\	ools\backup_copy.exe` 这条恰好落在 USB 窗口内的执行证据——而它的存在时刻（01:11:37，USB 接入后 3 分 53 秒）恰恰是最值得深究的时间关系。

第三处易错点是把「ShimCache 无条目」与「Security 日志被清空 3 次」合并论证为「有人刻意清理了执行痕迹」。正确判据是二者机制不同、成因不同：ShimCache 的空白由断电造成，是**物理性丢失**；1102 事件是有人调用 `ClearEventLog` 主动清除，是**人为行为**。

按错误判据合并论证，会把断电这一中性事件纳入人为反取证的证据链；一旦委托方追问「为什么断电」，而断电原因只是意外或强制关机，整条论证就崩塌了。正确做法是分别陈述：1102 是强证据，人为清除；ShimCache 是局限，机制性缺失。

---
<a id="section-31"></a>

## 六、扩展阅读方向

<a id="section-32"></a>

### 前置基础：地图成立的前提

- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 写入阻断与哈希校验。Windows 镜像必须包含未分配空间与卷影副本，否则地图上有三类工件会直接缺失。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 接入方式决定了哪些工件能读到。
- [虚拟机仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md) —— VSS 快照的挂载与注册表 hive 的加载都需要仿真环境，这是本篇 2.3 的技术前提。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 镜像与哈希的标准化承载。

<a id="section-33"></a>

### 同层深入：把地图上的每一类展开

- [注册表取证](computer-registry-log-registry-forensics.md) —— hive 提取与键值语义。「Shell 便利功能」与「显式审计」两类工件的很大一部分都在这里。
- [事件日志深度分析](computer-registry-log-windows-event-log-analysis.md) —— 显式审计类的主体。`Security.evtx` 是 Windows 上最接近「集中入口」的工件（其余工件分散，无同类集中点）。
- [用户行为痕迹](computer-registry-log-user-activity-artifacts.md) —— Shell 便利功能类的主体。
- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— Linux 侧对照。两边对照能立刻理解「有集中日志入口」对排查成本的影响。
- [取证工件地图](../computer-security/computer-security-security-artifact-map.md) —— macOS 侧对照，`~/Library` 的分层与 `C:\Windows` 的分层并不对应。

<a id="section-34"></a>

### 相邻议题：执行侧与浏览器侧

- [Prefetch 深度解析](../computer-execution/computer-execution-prefetch.md) —— 性能优化副产品类。
- [ShimCache 与 Amcache](../computer-execution/computer-execution-shimcache-amcache.md) —— 同类，**不受 `EnablePrefetcher` 这类功能开关影响，但 ShimCache 依赖正常关机落盘（见本篇 5.3）。**
- [LNK 快捷方式与 Jump List 跳转列表](../computer-execution/computer-execution-lnk-jumplist.md) —— Shell 便利功能类。
- [UsnJrnl 与文件操作时间线](../computer-execution/computer-execution-usn-journal-timeline.md) —— **文件系统元数据类，清理成本高于事件日志与 Prefetch（见本篇 2.1）。**
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— 应用自身数据类。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— 系统级资源统计。
- [Sysmon 与 Windows 日志聚合](computer-registry-log-sysmon.md) —— 若系统部署了 Sysmon，可补齐默认审计策略未覆盖的进程创建等事件，是「显式审计」类中覆盖面更广的一层。

<a id="section-35"></a>

### 工具与规范：分析环境本身是证据链的一环

- [Windows Server 环境仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-windows-server.md) —— 分析工具的行为可能改变你读到的数据，仿真环境的选择要考虑这一点。
- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 活系统勘验与离线分析的能力差异。

<a id="section-36"></a>

### 判据与反例：哪些缺失值得追问

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **本篇「按清除难度分类」的方法论在这一篇被完整展开**：痕迹被清之后如何识别。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **阴性结论的表述纪律**：按地图清点后，「某类工件不存在」必须写明检查了哪些位置。
<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 环境（Ubuntu）=====
sudo apt install sleuthkit xxd file

# ===== 1. 镜像结构确认 =====
mmls DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'cluster size|mft cluster|serial|volume name'

# ===== 2. 全量文件清单（工件存在性基线）=====
fls -o 2048 -r -p /work/DigiForensics.dd > /evidence/fls-all.txt
grep -ic 'prefetch' /evidence/fls-all.txt      # Prefetch 文件数
grep -ic 'amcache'  /evidence/fls-all.txt      # Amcache 是否存在
grep -icE '\.evtx$' /evidence/fls-all.txt      # 事件日志数量

# ===== 3. 注册表 hive 提取 =====
# 路径以实际系统为准，Win10/11 常见 /Windows/System32/config
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  ino=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\$" | head -1 | cut -d' ' -f2)
  icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/hives/$h"
done
for h in /evidence/hives/*; do echo -n "$h: "; xxd -l 4 -p "$h"; done
# 期望 72656766（"regf"）

# ===== 4. NTFS 元数据工件 =====
icat -o 2048 /work/DigiForensics.dd 2-0-0 > /evidence/LogFile.bin     # $LogFile
# $UsnJrnl:$J —— 先用 fls 找 inode（名称含 ADS），再用专用工具导出以免补零撑爆磁盘

# ===== 5. 关键文件魔数速查 =====
xxd -l 4 /evidence/sample.pf        # Prefetch：MAM=4d414d04 / 版本号 / SCCA
xxd -l 4 /evidence/SRUDB.dat        # ESE：89abcdef
xxd -l 4 /evidence/hives/SYSTEM     # hive：72656766 ("regf")
```

```powershell
# ===== Windows 侧：VSS 与系统信息 =====

# 列出卷影副本（管理员）
vssadmin list shadows
vssadmin list shadowstorage

# 挂载某个快照为盘符（只读用途，勿用于写入）
mklink /d X: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# 确认 Prefetch 是否启用（决定"缺失"是否异常）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" | Select EnablePrefetcher

# 从事件日志确认日志被清除（1102 = Security 日志被清空）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 | Format-List TimeCreated,Id
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 取证 — 取证工件地图」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《取证工件地图》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
