---
title: "注册表取证"
slug: "computer-registry-log-registry-forensics"
canonical: "https://www.digiforensics.cn/wiki/computer-registry-log-registry-forensics"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw", "https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["注册表与事件日志"]
---

# 注册表取证

<a id="section-1"></a>

## 一、概述

注册表保存 Windows 的系统与用户配置，也包含设备连接、程序使用、软件安装和账户信息等取证工件。分析时应确认 hive 来源、用户归属和事务日志状态，再将相关键值与文件、事件日志等证据交叉核对。

三个特点让取证师既依赖它又提防它：

1. 服务、驱动、启动项和账户配置可从相关 hive 中提取；必要时应结合事件日志与磁盘文件验证。
2. 时间信息包括键的 LastWrite 时间、特定值中的时间字段，以及 hive 文件的文件系统时间。它们的含义不同，应分别判读；键的 LastWrite 表示该键或其值条目最后被修改的时刻。参见 [Microsoft：RegQueryInfoKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw)。
3. **它极易被反取证工具清理。** 多数反取证软件的第一件事就是删 `Run` 键、删 USBSTOR 历史、清 UserAssist。

必须先建立的认知是：注册表在运行时是「活」的（内存中有句柄、事务日志在回放），在离线镜像里则是一堆**看起来完好但可能不一致的 hive 文件**。怎么处理这样一批离线 hive，尤其是 `ControlSet001` 这个高频卡点，是这一层最实际的难点。

读取 hive 之前的位置在「逐工件判读」的最前面。上游依赖 hive 的正确提取，**必须连同事务日志一起提取**（`.LOG1` / `.LOG2`），原因见下；提取方式见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。开工前先做三件事：**确认当前控制集编号**（`Select\Current`）；**确认用户 hive 的归属**（每个用户一份 `NTUSER.DAT`）；**判断是否需要回放事务日志**。下游支撑多处，几乎所有 Windows 篇目都依赖它：ShimCache 读的是 `SYSTEM` hive、DPAPI 主密钥的 SID 关联需要 `SAM`、UserAssist 读的是 `NTUSER.DAT`、SRUM 的 `UserId` 要关联用户名。

**五个逻辑根键不是五个独立文件**，而是不同 hive 内的子树视图：

| 逻辑根键 | 实际物理位置 | 说明 |
|---|---|---|
| **HKLM** | 跨 SYSTEM / SOFTWARE / SAM / SECURITY / DEFAULT 多个 hive | 机器级配置，**无单一对应文件** |
| **HKCU** | `C:\Users\<用户名>\NTUSER.DAT` | 当前登录用户配置（**离线时需逐用户选**） |
| **HKU** | 各用户的 `NTUSER.DAT` + `.DEFAULT` | 所有加载过的用户配置 |
| **HKCR** | HKLM\SOFTWARE\Classes + HKCU\Software\Classes 的**合并视图** | **无独立文件，是逻辑合并** |
| **HKCC** | HKLM\SYSTEM\...\ControlSet 的**当前控制集别名** | **无独立文件，指向 ControlSet00X** |

关键理解：HKCR 与 HKCC 是运行时动态组装的。在离线 hive 里找不到这两棵子树——它们是 Windows 启动时在内存里拼出来的；分析文件关联（HKCR）时，离线要去看 `HKLM\SOFTWARE\Classes`。

时间戳的三个来源必须分清：

| 来源 | 含义 | 可靠性 |
|---|---|---|
| 键内的值自带时间 | `InstallDate` 存 Unix 时间、`ShutdownTime` 存 FILETIME | **精确，是时间线的硬证据** |
| hive 文件的 MFT 时间戳 | 该文件被写入的时刻 | **只说明「这台机器的注册表在这个时刻有写入」** |
| 事务日志 `.LOG1` / `.LOG2` | 尚未合并进主 hive 的近期修改 | **异常断电时部分修改仍在这里** |

据此能回答的是：机器上装了什么服务与驱动、启动项配置、账户与 SID 清单、插过的 USB 设备及其序列号、用户运行过哪些程序、软件安装日期、以及**系统最后一次正常关机与异常关机的时间**（`ShutdownTime` 与其类型值是关键判据）。

回答不了的部分有五条，后两条是必须先纠正的误解：

- `CurrentControlSet` 在离线 hive 里是一个内容为空的符号链接。 在运行中的 Windows 上它是真实存在的键，但在磁盘上的 hive 里它只是指向 `ControlSet001` / `ControlSet002` 的符号链接。用离线工具查 `CurrentControlSet\Services\...` 却一无所获，通常是你查了一个空符号链接，与服务是否真的存在无关。正确做法是两步：先查 `Select\Current` 确认编号，再显式用 `ControlSet00X`。不同工具对符号链接的处理不一致，不要依赖工具行为**。
- 「hive 文件修改时间」不等于「这个键被改的时间」。 注册表键有自己的 LastWrite 时间；hive 文件的 MFT 时间戳属于文件系统时间，不能替代键的 LastWrite 时间。**不要把前者当作后者。**
- **异常断电后主 hive 的最新变更。** Windows 写注册表时先写事务日志，再周期性合并；若系统异常断电，部分近期修改仍在 `.LOG1` / `.LOG2` 里没合并，直接读主 hive 可能丢失最新变更——比如刚删的 `Run` 键其实还在日志里。
- **历史残留的删除。** 键被删后值可能仍留在 hive 的空闲空间中，**但要用专用的残留数据提取手段，常规读取方式给不出**。
- **用户当时是否在场。** hive 记录的是配置状态，**不记录交互行为**，那属于[用户行为痕迹](computer-registry-log-user-activity-artifacts.md)。

往下读之前先确认你已经掌握 NTFS 的 MFT 与文件时间戳概念（**hive 是普通文件，它的四时间戳来自 NTFS**，见[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)）、注册表的事务日志机制（**否则会在主 hive 与日志之间选错读取对象**）、SID 与用户名的对应关系（**这是账户类证据落到具体人的前提**），并且会用专用的 hive 解析工具（如 RegRipper），**而不是把 hive 当文本搜索**。还有一条取舍必须先明确：合并事务日志会**修改 hive 副本**，务必在副本上操作、保留原始 hive 作为证据原件，并记录合并动作。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 五大根键与它们的物理归属

注册表逻辑上有五个根键，但**它们不是独立的文件**，而是不同 hive 内的子树视图（2.1 有完整对照表）。

| 逻辑根键 | 实际物理位置 | 说明 |
|---|---|---|
| **HKLM**（`HKEY_LOCAL_MACHINE`） | 跨 SYSTEM / SOFTWARE / SAM / SECURITY / DEFAULT 多个 hive | 机器级配置，无单一对应文件 |
| **HKCU**（`HKEY_CURRENT_USER`） | `C:\Users\<用户名>\NTUSER.DAT` | 当前登录用户的配置（离线时需逐用户选） |
| **HKU**（`HKEY_USERS`） | 各用户的 `NTUSER.DAT` + `.DEFAULT` | 所有加载过的用户配置 |
| **HKCR**（`HKEY_CLASSES_ROOT`） | 是 HKLM\SOFTWARE\Classes + HKCU\Software\Classes 的**合并视图** | **无独立文件**，是逻辑合并 |
| **HKCC**（`HKEY_CURRENT_CONFIG`） | 是 HKLM\SYSTEM\...\ControlSet 的**当前控制集别名** | **无独立文件**，指向 ControlSet00X |

> **关键理解**：HKCR 和 HKCC 是**运行时动态组装**的。在离线 hive 里你**找不到** `HKEY_CLASSES_ROOT` 和 `HKEY_CURRENT_CONFIG` 这两个真实子树——它们是 Windows 启动时在内存中拼出来的。所以分析 `.lnk` 文件关联（HKCR）时，离线要去看 `HKLM\SOFTWARE\Classes`。
<a id="section-4"></a>

### 2.2 hive 文件在磁盘上的位置

**系统 hive**（路径以实际系统为准，Win10/11 常见位置）：

| hive | 路径 | 主要内容 |
|---|---|---|
| `SYSTEM` | `%SystemRoot%\System32\config\SYSTEM` | 硬件枚举、**服务/驱动**、控制集、**ShimCache**、USB/Bus、启动配置 |
| `SOFTWARE` | `%SystemRoot%\System32\config\SOFTWARE` | 已安装软件、**SRUM 配置**、卸载残留、`Run` 键（机器级）、网络配置 |
| `SAM` | `%SystemRoot%\System32\config\SAM` | **本地账户**、密码哈希、登录次数、组成员 |
| `SECURITY` | `%SystemRoot%\System32\config\SECURITY` | **LSA 秘密**（缓存的域凭据）、策略 |
| `DEFAULT` | `%SystemRoot%\System32\config\DEFAULT` | 新用户模板（对应 HKU\.DEFAULT） |

**用户 hive**：

| hive | 路径 | 主要内容 |
|---|---|---|
| `NTUSER.DAT` | `C:\Users\<用户名>\NTUSER.DAT` | UserAssist、RecentDocs、RunMRU、TypedPaths、MountPoints2、用户环境变量 |
| `UsrClass.dat` | `C:\Users\<用户名>\UsrClass.dat` | 用户注册表类（文件关联、缩略图缓存等） |

每个 hive 通常还有配套的事务日志 `SYSTEM.LOG1`、`SYSTEM.LOG2`——**它们是待回放的日志，不是备份**，见 2.6。

<a id="section-5"></a>

### 2.3 ★ 离线注册表必须用 `ControlSet001`（高频失败点）

在**运行中的** Windows 上，`HKLM\SYSTEM\CurrentControlSet` 是一个真实存在的键。但在**磁盘上的 hive 里，它只是一个符号链接**——内容为空，指向一个具体编号的控制集：
```text
SYSTEM\CurrentControlSet← 符号链接（离线读取时内容为空）
SYSTEM\ControlSet001        ← 真实数据（当前启动所用）
SYSTEM\ControlSet002        ← 真实数据（上次已知良好配置）
```

**后果**：用离线工具查 `CurrentControlSet\Services\...` 却一无所获，通常是**你查了一个空符号链接**，与服务是否真的存在无关。

**正确做法两步走**：

```bash
# 第 1 步：查 SYSTEM\Select，确认当前是哪个控制集
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current      : 1     ← 即 ControlSet001
# \Select\LastKnownGood : 1

# 第 2 步：改用 ControlSet001 查询
rip.exe -p /evidence/hives/SYSTEM -a /tmp/svc.txt svcscan
```

> **为什么这条这么重要**：不同工具加载离线 hive 时对符号链接的处理不一致（有的跟随、有的不跟随）。**不要依赖工具行为**——养成习惯：离线分析一律显式用 `ControlSet00X`，编号以 `Select\Current` 为准。

<a id="section-6"></a>

### 2.4 常用键值清单（按取证目的分组）

实战中最常查的位置如下（**每条都在后续文章展开**，此处作索引）。

离线一律用 `ControlSet00X` 代替 `CurrentControlSet`。

A. 系统身份与时间线（hive: SOFTWARE，键根 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`）

| 键/值 | 取证意义 |
|---|---|
| `ProductName` / `CurrentBuild` / `UBR` | 系统版本（先查这个） |
| `InstallDate`（REG_DWORD Unix 时间） | 系统安装/升级时间 |
| `RegisteredOwner` / `RegisteredOrganization` | 注册信息（案件归属线索） |
| `NetworkList\Profiles\*` 的 `ProfileName` / `DateLastConnected` | WiFi SSID → 地理位置 |
| `SRUM\Extensions`（GUID → DLL） | SRUM 数据源说明（见 [09](../computer-browser-behavior/computer-browser-behavior-srum.md)） |

B. 关机与启动（hive: SYSTEM，键根 `ControlSet001\Control`）

| 键/值 | 取证意义 |
|---|---|
| `Windows\ShutdownTime`（FILETIME） | **最后正常关机时间**——判断是否断电的关键 |
| `Windows\SystemStartOptions` | 是否进入安全模式 |
| `Session Manager\BootExecute` | 被篡改的启动项（反取证标志） |
| `Session Manager\AppCompatCache\AppCompatCache`（REG_BINARY） | **ShimCache**（见 [06](../computer-execution/computer-execution-shimcache-amcache.md)） |

C. USB / 外接设备（hive: SYSTEM）

| 键/值 | 取证意义 |
|---|---|
| `ControlSet001\Enum\USBSTOR\Disk&Ven_*`：设备名、**序列号**、厂商 | **U 盘身份**（序列号唯一） |
| 属性 `0064`(首次安装) / `0066`(最后连接) / `0067`(最后移除) | **设备时间线** |
| `ControlSet001\Enum\USB`（HID）、`Enum\SCSI`/`NVMe`（硬盘序列号） | 外设与磁盘身份 |
| `HKLM\SYSTEM\MountedDevices` | 驱动器 → 卷序列号映射（曾挂载的卷） |

> `Enum` 键的设备属性值以 `0064`/`0066` 这类数字命名，需在注册表查看器里**把「名称」列设为「属性名」**才能读懂。

D. 持久化 / 启动项（hive: SOFTWARE 或 NTUSER）

| 键 | 取证意义 |
|---|---|
| `...\CurrentVersion\Run` / `RunOnce`（HKLM 与 HKCU 各一份） | 机器级 / 用户级自启动 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell` / `Userinit`——被篡改的 shell 加载 |
| `ControlSet001\Services\*` | `ImagePath` / `Start`——**服务持久化**（对应 7045 事件） |
| `...\CurrentVersion\Image File Execution Options\*` | `Debugger`——**无文件落地执行**（IFEO 劫持） |

E. 已安装软件与卸载残留（hive: SOFTWARE）

| 键 | 取证意义 |
|---|---|
| `...\CurrentVersion\Uninstall\*` | 已装软件（`DisplayName`/`InstallDate`/`Publisher`） |
| `HKLM\SOFTWARE\Wow6432Node\...\Uninstall\*` | 32 位软件清单（见陷阱节） |
| `...\CurrentVersion\Installer\UserData\*` | **已卸载软件仍留痕**（常被忽视） |

> **实战价值**：「卸载残留」是反取证软件的死角——**卸载不会清 `UserData` 子键**，嫌疑人装过什么、用过什么破解工具，即使已卸载，痕迹常在此。

F. 用户行为（hive: NTUSER.DAT，详见 [10](computer-registry-log-user-activity-artifacts.md)）

均在 `...\Software\Microsoft\Windows\CurrentVersion\Explorer\` 下：`RecentDocs`（最近打开文档）、`RunMRU`（**Win+R 历史**）、`TypedPaths`（**地址栏手输路径**）、`UserAssist\{CEBFF5CD-...}\Count`（**GUI 执行，ROT13 编码**）、`MountPoints2`（曾挂载的卷/共享）、`WordWheelQuery`（搜索框关键词）。

**G. 账户（hive: SAM）**

| 键 | 取证意义 |
|---|---|
| `SAM\Domains\Account\Users\Names` | 账户名清单（`\<RID>` 内有登录次数、最后登录） |
| `SAM\Domains\Builtin\Administrators` | 管理员组成员 RID |
| `SAM\Domains\Account\Users` 二进制值 `V` | **NTLM 哈希**（结构化二进制），也是 EFS 解密的起点（见 [EFS 文件系统加密取证](../../crypto/crypto-volume/crypto-volume-efs.md)） |

<a id="section-7"></a>

### 2.5 注册表的时间戳从哪来

注册表键本身没有内嵌的修改时间字段——**它来自 NTFS**。hive 是普通文件，其 MFT 记录带标准四时间戳。

**但键内的值可以自己带时间**（`InstallDate` 存 Unix 时间、`ShutdownTime` 存 FILETIME）——**这些才是精确的**。

> **推论**：不要把「hive 文件修改时间」当作「这个键被改的时间」。它只说明「这台机器的注册表在这个时刻有写入」。

<a id="section-8"></a>

### 2.6 事务日志（`.LOG1`/`.LOG2`）与「脏」hive

Windows 写注册表时先写事务日志，再周期性合并进主 hive。**若系统异常断电，主 hive 可能落后于日志**——此时部分近期修改**仍在 `.LOG1`/`.LOG2` 里没合并**，直接读主 hive 可能丢失最新变更（比如刚删的 `Run` 键还在日志里）。用支持日志回放的工具（如 Registry Explorer）可自动合并。

> **取证取舍**：合并日志会**修改 hive 副本**。务必在**副本**上操作，保留原始 hive 作为证据原件，并记录合并动作。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：从镜像提取 hive（含事务日志）

```bash
# 路径以实际系统为准；分区起始扇区 2048 需按实际 mmls 结果替换
mkdir -p /evidence/hives

# 3.1.1 系统 hive + 事务日志（保留原始证据，供需要时回放）
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  base=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\$" | head -1 | cut -d' ' -f2)
  icat -o 2048 /work/DigiForensics.dd "$base" > "/evidence/hives/$h"
  for lg in LOG1 LOG2; do
    li=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\.$lg\$" | head -1 | cut -d' ' -f2)
    [ -n "$li" ] && icat -o 2048 /work/DigiForensics.dd "$li" > "/evidence/hives/$h.$lg"
  done
done

# 3.1.2 用户 hive：先定位，再逐个用户导出
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'NTUSER\.DAT$|UsrClass\.dat$'

# 3.1.3 验证：文件头必须是 regf（72656766）
for h in /evidence/hives/SYSTEM /evidence/hives/SOFTWARE; do printf '%s: ' "$h"; xxd -l 4 -p "$h"; done
```

<a id="section-11"></a>

### 3.2 第 2 步：确认当前控制集（★ 必做，ControlSet 坑）

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current         : 1
```

**判读**：`Current = 1` → 后续所有手工路径写 `ControlSet001`。若 `Current = 2`，则当前生效的是 `ControlSet002`（此时 `ControlSet001` 是「上次已知良好」）。

<a id="section-12"></a>

### 3.3 第 3 步：用 RegRipper 做批量提取

`rip.exe` 是插件化提取器——**对每个 hive 跑一批相关插件**，输出文本报告。`-a` 跑全部插件，`-p hive -p 插件名` 跑单插件，`-aT` 跑全部时间线插件（输出 CSV，可直接进时间线工具）。

```bash
# SYSTEM hive
rip.exe -p /evidence/hives/SYSTEM -a /tmp/svc.txt svcscan      # 全部服务与驱动
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor      # USBSTOR 设备
rip.exe -p /evidence/hives/SYSTEM -a /tmp/mem.txt prefetch     # Prefetch 开关状态
rip.exe -p /evidence/hives/SYSTEM -a /tmp/net.txt netstat      # 网络配置

# SOFTWARE hive
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/sw.txt  uninstall # 已装/残留软件
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/srum.txt srum      # SRUM 配置（见第 09 篇）

# NTUSER.DAT（逐用户）
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/ua.txt userassist
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/rd.txt recentdocs
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/rm.txt runmru
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/tp.txt typedpaths
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/mp.txt mountpoints2
```

**关于 `reged`**：开源注册表查看器（GUI），能加载多个 hive、支持导出、支持按属性名显示（解读 `0064`/`0066` 这类值必备）；`rip.exe` 偏自动化提取。**两者互补**：先用 `reged` 定位可疑键，再用 `rip` 批量导出。

<a id="section-13"></a>

### 3.4 第 4 步：SAM 账户与 USB 设备交叉验证

```bash
# SAM：账户名与 RID 映射、登录次数
rip.exe -p /evidence/hives/SAM -a /tmp/sam.txt samparse
# 与 Security.evtx 的 4624/4720 事件、实际存在的用户目录三方比对

# USB：A. USBSTOR 拿设备序列号与时间
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor
# → \Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler\60A44C4128AF
#    首次安装 2024-11-15 01:07 / 最后连接 2024-11-15 02:31

# USB：B. 在 U 盘镜像上找 Windows 写回的快捷方式（见第 07 篇）
LECmd.exe -d /evidence/usb_lnk --csv /evidence/out
# LNK 中的 MachineID / 卷序列号与 USBSTOR 交叉比对

# USB：C. 事件日志印证
EvtxECmd.exe -f /evidence/logs/System.evtx --csv /evidence/evtx
grep -iE '20001|20003' /evidence/evtx/System*.csv | grep -i '60A44C4128AF'
```

---
<a id="section-14"></a>

## 四、常见陷阱

<a id="section-15"></a>

### 4.1 键值语义与路径解析

<a id="section-16"></a>

#### 陷阱 1：★ 离线查 `CurrentControlSet` 查不到，误判"服务/配置不存在"

**现象**

用离线工具查 `HKLM\SYSTEM\CurrentControlSet\Services\某服务`，返回空。报告写「该服务在本机不存在，未发现服务持久化」。

**原因**

在磁盘上的 hive 里，`CurrentControlSet` 只是一个符号链接，内容为空：

```text
SYSTEM\CurrentControlSet  ← 符号链接（离线读取时内容为空）
SYSTEM\ControlSet001      ← 真实数据（当前启动所用）
SYSTEM\ControlSet002      ← 真实数据（上次已知良好配置）
```

在**运行中的** Windows 上，`CurrentControlSet` 是真实存在的键，所以很容易形成错误的肌肉记忆。离线时查它一无所获，通常是你查了一个空符号链接，与服务是否真的存在无关。

这个错误会系统性地影响一批注册表取证动作：

| 查询目标 | 错误路径 | 正确路径 |
| --- | --- | --- |
| 服务与驱动 | `CurrentControlSet\Services\*` | `ControlSet00X\Services\*` |
| 启动配置 | `CurrentControlSet\Control\*` | `ControlSet00X\Control\*` |
| `Select\Current` 本身 | 直接写在 `CurrentControlSet` 下 | `SYSTEM\Select`（不在控制集下） |

**影响**

- 这是离线注册表查询的高频失败点，新人几乎必踩
- 一次查询落空会让人怀疑整个 hive 是否提取正确，进而做出"注册表已损坏"的错误结论
- 若这条查询恰好是用来排查持久化服务的，落空就等于**漏掉整条服务持久化检查线**

**核查**

**两步走，先定编号再查询**：

```bash
# 第 1 步：确认当前是哪个控制集
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current         : 1
# \Select\LastKnownGood   : 1

# 第 2 步：改用 ControlSet001 查询
rip.exe -p /evidence/hives/SYSTEM -a /tmp/svc.txt svcscan
```

判读规则：

| `Select\Current` | 当前生效控制集 | `ControlSet001` 的角色 |
| --- | --- | --- |
| `1` | `ControlSet001` | 当前启动所用 |
| **`2`** | **`ControlSet002`** | **上次已知良好** |

`Current = 2` 时容易出错 —— 此时 `ControlSet001` 是"上次已知良好配置"，**里面的服务配置可能与当前生效的不同**（比如故障回滚后遗留）。

必须按 `Select\Current` 的值来选，不是习惯性写 001。

**报告里写明**：「`SYSTEM\Select\Current` = `1`，故本报告所有 `ControlSet` 路径均使用 `ControlSet001`。`CurrentControlSet` 为符号链接，离线读取内容为空，**未使用该别名**。」

<a id="section-17"></a>

#### 陷阱 2：把 `HKCR` / `HKCC` 当独立 hive 去找

**现象**

在离线 hive 里找 `HKEY_CLASSES_ROOT` 和 `HKEY_CURRENT_CONFIG`，报告写「这两个根键在本机 hive 中不存在」。

**原因**

**这两个根键没有独立的物理文件**，它们是 Windows 启动时在内存中动态组装的视图：

| 逻辑根键 | 实际物理位置 | 是否有独立文件 |
| --- | --- | --- |
| **HKCR**（`HKEY_CLASSES_ROOT`） | `HKLM\SOFTWARE\Classes` + `HKCU\Software\Classes` 的**合并视图** | **无** |
| **HKCC**（`HKEY_CURRENT_CONFIG`） | `HKLM\SYSTEM\...\ControlSet00X` 的**当前控制集别名** | **无** |

所以离线分析文件关联时，要去看 `HKLM\SOFTWARE\Classes`；查当前硬件配置时，要去看 `ControlSet00X\Hardware Profiles\Current`。

同样容易误解的还有根键与 hive 的多对一关系：

| 逻辑根键 | 实际物理位置 |
| --- | --- |
| **HKLM** | 跨 `SYSTEM` / `SOFTWARE` / `SAM` / `SECURITY` / `DEFAULT` **多个 hive** |
| **HKCU** | `C:\Users\<用户名>\NTUSER.DAT`（离线时需**逐用户选**） |
| **HKU** | 各用户的 `NTUSER.DAT` + `.DEFAULT` |

**HKLM 跨多个 hive，没有单一对应文件** —— 这意味着"HKLM 有问题"这句话必须落到具体是哪个 hive。

**影响**

- 报告写"根键不存在"是关于系统机制的**事实性错误**
- 文件关联（HKCR）类分析如果因此跳过，恶意文件关联的持久化就查不到
- 逐用户分析时若只取一个 `NTUSER.DAT` 当成 HKCU，会漏掉其他用户的全部痕迹

**核查**

**逻辑根键映射到物理路径**：

| 要查的 | 离线实际查 |
| --- | --- |
| `HKCR\<扩展名>` | `SOFTWARE\Classes\<扩展名>` |
| `HKCR\CLSID\{...}` | `SOFTWARE\Classes\CLSID\{...}` |
| `HKCC\System\CurrentControlSet\Control\Class\{...}` | `ControlSet00X\Hardware Profiles\Current\System\CurrentControlSet\Control\Class\{...}` |
| `HKLM\SYSTEM\...` | `SYSTEM` hive 的 `ControlSet00X\...` |
| `HKLM\SOFTWARE\...` | `SOFTWARE` hive |
| `HKCU\...` | **逐个** `NTUSER.DAT` |

**HKCU 必须逐用户处理**：

```bash
# 先定位所有用户 hive
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'NTUSER\.DAT$|UsrClass\.dat$'

# 再逐个导出与提取
for u in jsmith Administrator; do
  icat -o 2048 /work/DigiForensics.dd <inode> > "/evidence/hives/$u.NTUSER.DAT"
  rip.exe -p "/evidence/hives/$u.NTUSER.DAT" -a "/tmp/${u}_ua.txt" userassist
  rip.exe -p "/evidence/hives/$u.NTUSER.DAT" -a "/tmp/${u}_rd.txt" recentdocs
  rip.exe -p "/evidence/hives/$u.NTUSER.DAT" -a "/tmp/${u}_rm.txt" runmru
  rip.exe -p "/evidence/hives/$u.NTUSER.DAT" -a "/tmp/${u}_tp.txt" typedpaths
done
```

<a id="section-18"></a>

#### 陷阱 3：忘记 32/64 位注册表重定向

**现象**

查 `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` 列出已装软件，发现某个可疑程序不在清单里，报告写「该软件未安装」。而它其实装在 32 位路径下。

**原因**

64 位 Windows 上，32 位应用的注册表项被重定向到：

```text
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```

这意味着**同一个逻辑位置在 64 位系统上有两套物理存储**。同样需要两处都查的位置：

| 目标 | 64 位视图 | **32 位视图（易漏）** |
| --- | --- | --- |
| 卸载清单 | `SOFTWARE\Microsoft\...\Uninstall\*` | `SOFTWARE\Wow6432Node\Microsoft\...\Uninstall\*` |
| 机器级自启动 | `SOFTWARE\Microsoft\...\Run` | `SOFTWARE\Wow6432Node\Microsoft\...\Run` |
| 已安装软件 | 同上 | 同上 |
| 用户级自启动 | `NTUSER\Software\...\Run` | `NTUSER\Software\Wow6432Node\...\Run` |

**影响**

- 盗号软件、破解工具有相当一部分是 32 位 —— 这个错误在实践中命中率高
- 漏掉 `Wow6432Node` 会让整份软件清单不完整，而"未安装"的结论会被推翻
- 持久化检查若漏 32 位 `Run` 键，会漏掉常见的自启动持久化

**核查**

**软件清单与启动项一律两处都查**：

```bash
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/uninst64.txt uninstall
# 32 位视图需要显式指定
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/uninst32.txt \
  "Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

# 机器级 Run 键两处都查
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/run64.txt run
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/run32.txt \
  "Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
```

**报告里必须写明覆盖范围**：「已安装软件清单同时检索了 64 位 `SOFTWARE\...\Uninstall` 与 32 位 `SOFTWARE\Wow6432Node\...\Uninstall` 两个位置，未发现 `CredentialHarvest` 条目。」

<a id="section-19"></a>

#### 陷阱 4：只看 `Uninstall` 清单，漏掉 `Installer\UserData` 卸载残留

**现象**

`Uninstall` 清单里没有可疑程序，报告写「该机未安装过该软件」。而 `Installer\UserData` 子键里有它完整的安装记录与 `InstallDate`。

**原因**

Windows Installer 的卸载不会清 `Installer\UserData` 子键，这是反取证软件的典型死角：

| 位置 | 卸载后的状态 |
| --- | --- |
| `...\CurrentVersion\Uninstall\*` | **条目被删除** |
| `...\CurrentVersion\Installer\UserData\*` | **残留完整记录**（含 `DisplayName`、`InstallDate`、`InstallLocation`） |

也就是说：嫌疑人装过什么、用过什么破解工具，即使已卸载，痕迹常在 `UserData` 里。

这与 Prefetch、Amcache 形成一条完整的"卸载后仍可追"链：
```text
软件装过  →  Installer\UserData 残留（证明装过，含安装日期）
          →  Prefetch 条目（证明执行过，含次数与时间）
          →  Amcache 条目（证明文件身份，含 SHA-1 与编译时间，即使文件已删）
          →  MFT 无对应条目（证明文件已删除）
```

四层各自独立，任何一层缺失都还有其他层补。

**影响**

- 「未安装过该软件」是**方向完全错误**的结论，而反取证软件卸载后正是这个状态
- 这类误判看起来像"查了清单没找到"，实际上查的位置不完整
- 委托方据此认为没有安装行为，而实际上完整安装记录就在注册表里

**核查**

`Uninstall` 与 `Installer\UserData` 必须都查：

```bash
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/uninst.txt uninstall
# Uninstall 常规清单：DisplayName "AnyDesk"  InstallDate 20241105（现存）

# ★ 卸载残留：反取证死角
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/ud.txt \
  "Microsoft\Windows\CurrentVersion\Installer\UserData"
# UserData 残留：DisplayName "CredentialHarvest"  InstallDate 20241112
```

发现差异时的判读：

| `Uninstall` | `UserData` | 结论 |
| --- | --- | --- |
| 有 | 有 | 正常安装 |
| 无 | **有** | **已卸载或刻意不留 —— 安装事实成立** |
| 有 | 无 | 可能是绿色版或手工清理 |
| 无 | 无 | 需转向 Prefetch / Amcache / 用户目录 / 文件系统 |

报告表述：

> `CredentialHarvest` **不在 `Uninstall` 常规清单中**（说明已卸载或刻意未登记），但在 `Installer\UserData` 卸载残留中有完整安装记录（`DisplayName = CredentialHarvest`，`InstallDate = 20241112`，`InstallLocation = C:\Users\Admin\AppData\Local\Temp\`）。可认定该机曾安装该程序，安装日期 2024-11-12。

<a id="section-20"></a>

### 4.2 时间字段与历史残留

<a id="section-21"></a>

#### 陷阱 5：把 hive 文件的 MFT 修改时间当作"键被修改的时间"

**现象**

`SOFTWARE` hive 文件的 MFT `Modified` 是 2024-11-15 03:20，而 `Run` 键下有一个可疑条目，报告写「该启动项于 2024-11-15 03:20 被创建」。

**原因**

**注册表键本身没有内嵌的修改时间字段** —— 键的"时间"来自 NTFS，而 hive 是**一个普通文件**，它的 MFT 记录带标准四时间戳。

这四时间戳反映的是"**这个 hive 文件在何时被写盘**"，而不是"某个键在何时被改"。

这个 hive 的 `Modified` 时间可能来自：

- 任何一次注册表写入（哪怕改的是完全无关的键）
- 系统启动时的配置加载
- 软件安装、驱动安装
- 组策略刷新

所以"`Run` 键在该时刻被创建"这个断言**没有依据**。

**而键内的值可以自带精确时间** —— **这些才是可靠的**：

| 值 | 存储格式 | 位置 |
| --- | --- | --- |
| `InstallDate` | **Unix 时间** | `Uninstall` / `UserData` 下 |
| `ShutdownTime` | **FILETIME** | `ControlSet00X\Control\Windows\ShutdownTime` |
| USB 首次/最后连接时间 | 二进制时间结构 | `Enum\USBSTOR` 下 |

**影响**

- **"键被改的时间"这个命题本身不存在**，用文件时间代它是一个范畴错误
- 时间点被推到 hive 刷盘时刻，与实际修改时刻可能差很久
- 而键内自带的 `InstallDate` 恰恰是精确的，不用就浪费了更可靠的证据

**核查**

只信值内自带的时间，文件时间只用于说明"这台机器的注册表在这个时刻有写入"：

```bash
# 精确时间从值内取
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/ud.txt \
  "Microsoft\Windows\CurrentVersion\Installer\UserData"
# → InstallDate 20241112   ← Unix 时间，精确到安装那一刻

rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# \ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 23:40
```

**时间字段的来源分级**：

| 时间 | 来源 | 可靠性 |
| --- | --- | --- |
| `InstallDate` | 键内值（Unix 时间） | **高，精确** |
| `ShutdownTime` | 键内值（FILETIME） | **高，精确** |
| USB 首末连接时间 | 键内值（二进制时间） | **高，精确** |
| LNK 头三个 FILETIME | 目标文件 MAC 时间快照 | 高，但是**目标文件**的时间 |
| Prefetch 时间槽 | 文件内容 | 高，但仅最近 8 次 |
| **hive 文件 MFT 时间** | NTFS | **低，只能说明"有写入"** |

报告里绝不写「该键于 X 被修改」，只能写「该 hive 文件的最后写入时间为 X，说明该时刻注册表有写入活动；该键的修改时间无法从注册表结构中获取」。

<a id="section-22"></a>

#### 陷阱 6：把 `.LOG1` / `.LOG2` 当备份，或对原始 hive 做日志回放

**现象**

看到 `SYSTEM.LOG1` 有 2 MB，觉得是备份，直接打开查看；或用支持回放的工具在从镜像直接提取的 hive 上回放事务日志。

**原因**

**两个独立的问题**。

其一，`.LOG1` / `.LOG2` 不是备份。 Windows 写注册表时**先写事务日志，再周期性合并进主 hive**。所以：

| 文件 | 性质 | 单独打开的价值 |
| --- | --- | --- |
| `SYSTEM` | 主 hive，**可能落后于日志** | 基础内容 |
| `SYSTEM.LOG1` / `.LOG2` | **待回放的事务日志** | **单独打开无意义** |

若系统异常断电，主 hive 可能落后于日志 —— 此时部分近期修改仍在 `.LOG1` / `.LOG2` 里没合并，直接读主 hive 会**丢失最新变更**（比如刚删的 `Run` 键在日志里，主 hive 里已经没有痕迹，看起来像"从未存在过"）。

**其二，回放会修改文件。** 合并日志的动作会**改写 hive 副本**。在原始提取文件上做，等于改证据。

**影响**

- 把 `.LOG1` 当备份单独看，读到的是无法独立理解的中间状态
- 不回放主 hive → 丢失最近的注册表变更，**这恰恰是案件最关心的部分**
- 对原始文件回放 → **破坏检材原始性**，与"未改写证据"的声明冲突

**核查**

主 hive 与事务日志一起提取，只在副本上回放，两个哈希都记录：

```bash
# 提取主 hive + 事务日志
for h in SYSTEM SOFTWARE SAM SECURITY DEFAULT; do
  base=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\$" | head -1 | cut -d' ' -f2)
  icat -o 2048 /work/DigiForensics.dd "$base" > "/evidence/hives/$h"
  # 原始文件立即记哈希
  shasum -a 256 "/evidence/hives/$h" | tee "/evidence/hives/$h.sha256"
  for lg in LOG1 LOG2; do
    li=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\.$lg\$" | head -1 | cut -d' ' -f2)
    [ -n "$li" ] && icat -o 2048 /work/DigiForensics.dd "$li" > "/evidence/hives/$h.$lg"
  done
done

# 副本上回放（Registry Explorer 等支持回放的工具）
cp /evidence/hives/SYSTEM /evidence/hives/work/SYSTEM-merged

# 回放后复核原件哈希未变
shasum -a 256 -c /evidence/hives/SYSTEM.sha256      # 必须 OK
```

**报告里写明**：

> `SYSTEM.LOG1` / `SYSTEM.LOG2` 与主 hive 一并提取，**原文件 SHA-256 已记录**。事务日志回放**仅在工作副本上进行**，原件哈希在回放前后一致。回放过程可能合并了未落盘的近期变更，合并内容见回放日志。

<a id="section-23"></a>

#### 陷阱 7：把 `Enum\USBSTOR` 的序列号直接当结论

**现象**

`SYSTEM\ControlSet001\Enum\USBSTOR` 下有 Kingston 设备、序列号 `60A44C4128AF`，报告直接写「该 U 盘于案发当晚插入本机，序列号 `60A44C4128AF`」并作为唯一证据。

**原因**

**USB 序列号可以伪造，也可能重复**：

| 风险 | 说明 |
| --- | --- |
| **序列号可伪造** | 具备管理员权限可用工具改写 USB 设备的序列号 |
| **克隆盘重复** | 批量采购的同型号 U 盘，固件序列号可能完全相同 |
| **枚举不等于实际使用** | 枚举记录的是"曾被系统识别"，不是"曾被用于传输数据" |
| **时间字段有历史残留** | 该键的设备属性值可能包含过期的安装时间 |

另外，`Enum` 键下设备属性值以 `0064` / `0066` 这类数字命名，在注册表查看器里要把"名称"列设为"属性名"才能读懂 —— 数字名不解读就等于没看到。

**影响**

- 用单一来源认定设备接入，**证据强度不足**，一旦序列号被质疑整条链都塌
- 序列号重复会导致误认设备，把无关的 U 盘算进案情
- 「曾被识别」与「曾被使用」的差距被忽略，推论跨越过大

**核查**

**至少三源交叉**：

```bash
# A. USBSTOR 注册表：设备序列号与首末连接时间
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor
# → \Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler\60A44C4128AF
#    首次安装 2024-11-15 01:07 / 最后连接 2024-11-15 02:31

# B. MountedDevices：曾挂载的卷标识（注册表 + MountedDevices 二进制值）
rip.exe -p /evidence/hives/SYSTEM -a /tmp/md.txt mounteddevices

# C. 事件日志印证
EvtxECmd.exe -f /evidence/logs/System.evtx --csv /evidence/evtx
grep -iE '20001|20003' /evidence/evtx/System*.csv | grep -i '60A44C4128AF'
# → 2024-11-15 01:07:44  设备 \Device\HarddiskVolume3 首次连接

# D. LNK 侧：卷序列号与 MachineID 反查是否该设备
LECmd.exe -d /evidence/usb_lnk --csv /evidence/out
```

**证据链的标准表述**：

> `2024-11-15 01:07:44` 接入过 Kingston DataTraveler 3.0，序列号 `60A44C4128AF`。该结论由 USBSTOR 注册表（首装时间 01:07）与 `System.evtx` 事件 `20001`（01:07:44）双源印证，两源时间精确到分钟一致。
>
> **限制**：`USBSTOR` 枚举记录的是系统曾识别该设备，**不直接证明数据曾通过该设备传输**。序列号存在被伪造或同型号重复的可能，本案未取得该 U 盘实物，未做 `MountPoints2` 与 LNK 卷序列号的进一步比对。

<a id="section-24"></a>

### 4.3 提取流程与阴性结论

<a id="section-25"></a>

#### 陷阱 8：只查 `SYSTEM` 不查 `NTUSER.DAT`

**现象**

提取了 `SYSTEM`、`SOFTWARE`、`SAM` 三个系统 hive，报告写「已完成注册表取证」。而 `RunMRU`（Win+R 历史）、`TypedPaths`（手输路径）、`RecentDocs` 全在用户 hive 里。

**原因**

用户级痕迹与系统级痕迹的分界线是 hive 文件，不是"注册表"这个整体：

| hive | 典型痕迹 |
| --- | --- |
| `SYSTEM` | 硬件枚举、**服务/驱动**、控制集、**ShimCache**、USB/Bus、启动配置 |
| `SOFTWARE` | 已安装软件、**SRUM 配置**、卸载残留、机器级 `Run` 键、网络配置 |
| `SAM` | **本地账户**、密码哈希、登录次数、组成员 |
| `SECURITY` | **LSA 秘密**（缓存的域凭据）、策略 |
| `NTUSER.DAT` | UserAssist、RecentDocs、RunMRU、TypedPaths、MountPoints2、用户环境变量 |
| `UsrClass.dat` | 用户注册表类（文件关联、缩略图缓存等） |

取证价值较高的一批用户级键全在 `NTUSER.DAT`：

| 键 | 记录什么 |
| --- | --- |
| `...\Explorer\RunMRU` | **Win+R 运行历史**（执行工具的经典入口） |
| `...\Explorer\TypedPaths` | **地址栏手工输入的路径** |
| `...\Explorer\RecentDocs` | 最近打开的文档 |
| `...\Explorer\UserAssist\{CEBFF5CD-…}\Count` | **GUI 程序执行记录，ROT13 编码** |
| `...\Explorer\MountPoints2` | 曾挂载的卷与网络共享 |
| `...\Explorer\WordWheelQuery` | 搜索框关键词 |

而且 **HKCU 离线没有单一来源，必须逐个用户提取** —— 多用户机器上只看一个会漏掉其余全部。

**影响**

- 「Win+R 里没有可疑命令」这个结论若基于未提取的用户 hive，就是**没有查过**
- `MountPoints2` 缺失会让"曾挂载网络共享"这类问题无法回答
- 报告声明"已完成注册表取证"但实际只覆盖了系统 hive，**完整性声明不成立**

**核查**

系统 hive 与用户 hive 都要提取，且逐用户处理：

```bash
# 1) 定位所有用户 hive（含已删除用户目录）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'NTUSER\.DAT$|UsrClass\.dat$'
# 注意：不可只 grep /Users/，已删除用户目录也要找

# 2) 逐个提取并跑全套行为键
for u in jsmith Administrator; do
  icat -o 2048 /work/DigiForensics.dd <ino> > "/evidence/hives/$u.NTUSER.DAT"
  for plug in userassist recentdocs runmru typedpaths mountpoints2 wordwheelquery; do
    rip.exe -p "/evidence/hives/$u.NTUSER.DAT" -a "/tmp/${u}_${plug}.txt" "$plug"
  done
done
```

**报告里列出实际处理的用户 hive 清单**，让覆盖度可核查。

<a id="section-26"></a>

#### 陷阱 9：在活系统上直接用 RegRipper 读 hive

**现象**

在正在运行的 Windows 上，直接对 `C:\Windows\System32\config\SYSTEM` 跑 `rip.exe`，解析出一堆配置并写进报告。

**原因**

**运行中的注册表是"活"的**，直接读有两重风险：

| 风险 | 说明 |
| --- | --- |
| **hive 被锁定** | 运行时 hive 被系统持有，多数工具会报错或只能读到部分内容 |
| **可能触发回放改写** | 某些工具打开 hive 时会触发事务日志回放，**修改文件内容** |
| **读到的是中间态** | 系统正在写注册表时，磁盘上的 hive 可能处于不一致状态 |
| **不覆盖未落盘数据** | 内存中的最新修改可能还没刷盘 |

正确路径是**先复制到分析机，再离线分析** —— 这样 hive 是静止的、可复现的、可计算哈希的。

**影响**

- 部分读取成功会给出**不完整但看起来正常**的输出
- 若触发了回放改写，等于**在委托方设备上动了注册表**
- 结果不可复现，报告无法被独立验证

**核查**

**先复制，再离线分析；分析对象是静态副本**：

```bash
# 活系统上：只做只读复制
robocopy "C:\Windows\System32\config" "E:\evidence\hives" SYSTEM SOFTWARE SAM SECURITY DEFAULT *.LOG? /R:0 /W:0

# 校验复制的 hive
for h in E:\evidence\hives\SYSTEM E:\evidence\hives\SOFTWARE; do
  printf '%-28s ' "$h"; xxd -l 4 -p "$h"     # 期望 72656766
done

# 分析在副本上进行，每个 hive 单独跑一次 rip
rip.exe -p "E:\evidence\hives\SYSTEM" -a C:\out\svc.txt svcscan
rip.exe -p "E:\evidence\hives\SOFTWARE" -a C:\out\uninst.txt uninstall
```

**RegRipper 一次只吃一个 hive** —— 重复传 `-p` 参数不会叠加，会取最后一个。**每个 hive 单独跑一次命令。**

<a id="section-27"></a>

#### 陷阱 10：把 `Uninstall` 缺失、键不存在一律写成否定结论

**现象**

`Uninstall` 里没有某软件，报告写「未安装」；`Run` 键里没有可疑项，报告写「无启动项持久化」；`UserAssist` 里没有某程序，报告写「未运行过该程序」。

**原因**

**注册表的"缺失"至少有六种成因**，每种的结论强度完全不同：

| 成因 | 正确表述 |
| --- | --- |
| **真未安装** | 「在 `Uninstall`、`UserData`、Prefetch、SRUM、用户目录五处均未检出，**可认定未安装**」 |
| **绿色版 / 便携程序** | 「无注册表记录，**不排除为免安装程序**」 |
| **已卸载，残留未查** | 「`Uninstall` 无条目，但 `Installer\UserData` 未检查」 |
| **32 位视图未查** | 「64 位视图无条目，**32 位 `Wow6432Node` 未检查**」 |
| **可被清除** | 「反取证软件通常优先清 `Run` 键、清 UserAssist，**缺失可能为清理所致**」 |
| **权限 / 提取问题** | 「该 hive 提取不完整或该键未成功解析」 |

最后一条特别重要 —— 注册表**极易被反取证工具清理**：多数反取证软件的第一件事就是删 `Run` 键、删 USBSTOR 历史、清 UserAssist。所以"注册表里没有"在反取证语境下的证明力本身就偏低。

**影响**

- 单点缺失推出强否定结论，是最常见的过度推论
- 反取证场景下尤其危险 —— 缺失恰恰是反取证成功的**预期结果**
- 委托方据此排除嫌疑，而实际上痕迹被清掉了

**核查**

**阴性结论必须多点交叉，并显式考虑反取证因素**：

```bash
# 五处交叉：注册表两处 + 执行两处 + 文件系统一处
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/u.txt uninstall
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/ud.txt \
  "Microsoft\Windows\CurrentVersion\Installer\UserData"
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/u32.txt \
  "Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
PECmd.exe -d /evidence/Prefetch --csv /evidence/out       # 4
AmcacheParser.exe -f /evidence/hives/Amcache.hve --csv /evidence/out   # 5
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'progname'          # 6
```

| 交叉结果数 | 结论强度 |
| --- | --- |
| 0 处命中，且**已确认 Prefetch 已启用** | 「五处交叉均未检出，**可认定未安装/未运行**」 |
| 0 处命中，但 `EnablePrefetcher=0` | 「**执行侧未验证**（Prefetch 未启用），注册表与文件系统侧未检出，结论强度受限」 |
| 0 处命中，但**有反取证迹象**（如 1102 事件） | 「**无法排除痕迹被定向清理**」 |

统一表述原则：用「未检出」替代「没有」，并列出已检查的位置。
<a id="section-28"></a>

## 五、案例示例

<a id="section-29"></a>

### 5.1 Installer UserData 残留证明卸载软件曾被安装

**场景**

查获一台 Windows 10 专业版台式机（NTFS，簇 4096），委托要求查明「是否安装了盗号软件，事后是否试图卸载销毁痕迹」。

镜像 `DigiForensics.dd`（raw，500 GB），NTFS 起始扇区 2048。系统为**正常关机状态**。

**处置过程**

第一步，提取 hive 并验证完整性——魔数不是 `regf` 说明提取错位：

```bash
mkdir -p /evidence/hives
for h in SYSTEM SOFTWARE SAM; do
  base=$(fls -o 2048 -r -p /work/DigiForensics.dd | grep -E "config/$h\\$" | head -1 | cut -d' ' -f2)
  icat -o 2048 /work/DigiForensics.dd "$base" > "/evidence/hives/$h"
done
xxd -l 4 -p /evidence/hives/SYSTEM      # → 72656766 ("regf")，完整性通过
```

第二步，确认控制集——不确认就直接用 `CurrentControlSet` 会在多控制集机器上读错值：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current : 1  → 后续手工路径均用 ControlSet001
```

第三步，分别查询常规卸载清单与卸载残留：

```bash
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/uninst.txt uninstall
```

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
  {8A2F…-C4D1}  DisplayName "AnyDesk"          InstallDate 20241105   （现存）
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8A2F…-C4D1}
  UninstallString  "C:\\Program Files\\AnyDesk\\unins000.exe"

SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\  ← 无 CredentialHarvest
```

```bash
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/userdata.txt userdata
```

```text
SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-21-…-1001\Product\{2C7E9B4A-…}
  DisplayName   "CredentialHarvest"
  InstallDate   20241112
  InstallSource "C:\\Users\\Admin\\Downloads\\chsetup.msi"
  UninstallString  "C:\\Program Files\\CredentialHarvest\\unins000.exe"
  PSChildName  {2C7E9B4A-3D5F-4A82-9E1C-7B6D8F0A2C34}
```

第四步，检查键与值的最后写入时间：

```bash
python3 - <<'PY'
import struct, datetime
# regf 主头 4096（0x1000）字节，第一个 hbin 紧接其后。
# regf 主头 + hbin 块头(32=0x20) + nk 签名(2) = 0x1020，
# 所以 nk 的 last-written 落在文件偏移 0x1024 —— 不是 0x24。
# FILETIME 是 100ns 单位、1601 纪元。换算走 Unix 纪元偏移做整数除法：
#   unix_sec = ft / 10^7 - 11644473600
# 直接用 timedelta(microseconds=ft) 会溢出，用 ft*10 更会溢出到 4 万多年。
b = open("/evidence/hives/SOFTWARE","rb").read()
NK = 0x1000 + 0x20                              # 根键 nk 起点
assert b[NK:NK+2] == b"nk", b[NK:NK+2]            # 先确认这是根键单元
ft = struct.unpack_from("<Q", b, NK + 4)[0]       # FILETIME（nk 签名后紧跟 last-written）
unix_sec = ft // 10**7 - 11644473600
print("SOFTWARE 根键最后写入(UTC):",
      datetime.datetime.fromtimestamp(unix_sec, datetime.timezone.utc))
PY
```

第五步，查 `Installer\Products` 与 `Installer\Folders` 确认产品存在：

```bash
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/prod.txt products
# → {2C7E9B4A-3D5F-4A82-9E1C-7B6D8F0A2C34}
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/folders.txt "installer folders"
# → C:\Program Files\CredentialHarvest\  记录仍在
```

**结论**

`Uninstall` 常规清单中只有 `AnyDesk`（`InstallDate 20241105`），**不存在 `CredentialHarvest`**，说明该程序已从常规清单移除。

但在 `SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-21-…-1001\Product\{2C7E9B4A-3D5F-4A82-9E1C-7B6D8F0A2C34}\` 下存在**完整安装元数据**：`DisplayName = CredentialHarvest`、`InstallDate = 20241112`、`InstallSource = C:\Users\Admin\Downloads\chsetup.msi`、`UninstallString = C:\Program Files\CredentialHarvest\unins000.exe`。`Installer\Products` 与 `Installer\Folders` 中亦保留对应记录。该 SID 后缀 `-1001` 对应 `Admin` 用户的配置文件。

可认定：2024-11-12 曾通过 `Downloads` 目录中的 MSI 安装包安装 `CredentialHarvest`，事后执行了卸载动作使常规 `Uninstall` 条目消失。

**「常规清单没有」与「从未安装」是两回事。**

**误判对照**

本案例最需要防守的错误结论是「`Uninstall` 清单里没有 `CredentialHarvest`，说明该机从未安装过此软件」。正确判据是 Windows Installer 维护两套独立的键——`CurrentVersion\Uninstall` 供「程序和功能」界面显示，正常卸载会连同 `UninstallString` 一起删除该条目；而 `CurrentVersion\Installer\UserData\<SID>\Product\<ProductCode>` 是安装引擎自身的数据库，**卸载动作通常只标记或保留部分键值，不做同等清理**。

按错误判据写「从未安装」，会把本案唯一的安装物证直接排除，委托方据此认为内控不存在问题——而恰恰是「清单被清空但 UserData 还在」这个矛盾，最能说明卸载是有意为之。

第二处易错点是把 `Installer\UserData\<SID>\` 下的条目一律当作可信。正确判据是该键下的元数据可以被任意程序直接写入注册表伪造，其证明力低于文件系统与事件日志；它的价值在于与其它独立证据（Prefetch 的执行记录、Amcache 的哈希、NTFS 的目录项）相互印证。

按错误判据只凭 UserData 一项就断定「该软件运行过并采集了凭据」，是把安装记录等同于执行记录；正确结论分两级——「已安装」为强证据，「已运行并产生效果」需要执行类证据支撑。

第三处易错点是看到 `InstallSource` 指向 `Downloads` 目录就断定「用户主动下载并安装」。正确判据是 `InstallSource` 记录的 MSI 源路径，既可能来自用户手动双击，也可能来自 IT 部署脚本、静默安装参数 `/qn`、组策略软件分发或自动化工具；路径在 `Downloads` 只说明安装包最初落在那里。

按错误判据写「用户主动安装」，把部署行为与个人行为混为一谈；而本案真正需要回答的是「安装来源」，正确表述是「安装包来自该用户 Downloads 目录，具体分发渠道需结合 4688 进程创建事件或部署系统日志确认」。

<a id="section-30"></a>

### 5.2 Prefetch 与 Amcache 双源确认曾执行且文件已删除

**场景**

已确认 `CredentialHarvest` 曾于 2024-11-12 安装。委托方进一步要求确认「它是否真的被运行过、程序本体现在何处」。

**处置过程**

第一步，确认 Prefetch 是否启用并解析：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/pf.txt prefetchparameters
# → EnablePrefetcher = 3
PECmd.exe -d /evidence/Prefetch --csv /evidence/out
```

```text
CRDCRED~1.EXE-9F3E2D1C.PF | runs = 4 | last = 2024-11-13 22:07:41
   prev: 2024-11-13 21:55:08, 2024-11-12 23:41:55, 2024-11-12 22:19:03
   path: C:\Program Files\CredentialHarvest\credhelper.exe
```

第二步，从 Amcache 取文件身份，即使文件已删哈希仍在：

```bash
AmcacheParser.exe -f /evidence/hives/Amcache.hve --csv /evidence/out
```

```text
Path          : C:\Users\Admin\AppData\Local\Temp\credhelper.exe
SHA-1         : 3f2a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1
Compile Time  : 2024-11-12 03:41:19
First Run     : 2024-11-12 22:18:47
```

第三步，与系统关机时间对照，确认时间线自洽：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# \ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 23:40:22
```

```python
runs = ["2024-11-12 22:19:03", "2024-11-12 23:41:55", "2024-11-13 21:55:08", "2024-11-13 22:07:41"]
print("末次运行:", max(runs), " 关机:", "2024-11-14 23:40:22")
print("末次运行早于关机:", max(runs) < "2024-11-14 23:40:22", "→ 系统正常关机，时间线自洽")
```

第四步，确认程序本体已从磁盘删除：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd 2>/dev/null | grep -i 'credentialharvest\|credhelper'
# → 无匹配（目录已不存在，MFT 条目已复用）
```

第五步，从 MFT 未分配空间中尝试找回残留并核对哈希：

```bash
# 1) 列出曾经存在的目录条目
icat -o 2048 /work/DigiForensics.dd 0 2>/dev/null | strings | grep -i 'CredentialHarvest' | head -5
# "C:\Program Files\CredentialHarvest\"  （残留于未分配簇的目录索引中）

# 2) 若数据区未被覆盖，提取并核对
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/credhelper.exe
sha1sum /evidence/credhelper.exe
# → 3f2a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1  ← 与 Amcache 记录一致
```

**结论**

`EnablePrefetcher = 3`，`PECmd` 解析 `CRDCRED~1.EXE-9F3E2D1C.pf` 得 `Run Count = 4`，四个时间槽为 2024-11-12 22:19:03、22:23:41、11-13 21:55:08、22:07:41，路径 `C:\Program Files\CredentialHarvest\credhelper.exe`。

`Run Count = 4 ≤ 8`，**四次执行时间全部可见，无环形损失**。

Amcache 独立记录 `C:\Users\Admin\AppData\Local\Temp\credhelper.exe` 的 SHA-1 `3f2a9c8d…`、编译时间 2024-11-12 03:41:19、`First Run = 2024-11-12 22:18:47`，与 Prefetch 首槽 22:19:03 相差仅 16 秒，两件独立工件在时间与程序身份上互证。

末次运行 22:07:41 早于 `ShutdownTime = 2024-11-14 23:40:22`，系统正常关机，时间线自洽。

程序目录当前已不存在于卷上，但未分配簇中的目录索引仍留有 `C:\Program Files\CredentialHarvest\` 残留。可认定：该程序被实际执行 4 次，执行后其安装目录与安装记录均被清除。

**误判对照**

最容易出的错误是「文件已经不在磁盘上了，所以无法证明它运行过」。正确判据是执行痕迹与文件本体存在于**完全不同的载体**：Prefetch 的 `.pf` 文件记录的是运行次数与时间，Amcache 记录的是文件身份（SHA-1、编译时间、首次运行），两者都不依赖目标程序本身是否仍在卷上；卸载与删除只移除程序目录，不触及这两个工件。

按错误判据因文件消失而放弃举证，会在最需要证据的环节交白卷——而本案恰恰因为文件已删，反而更依赖这些旁证。

第二处易错点是看到 Amcache 的路径在 `Temp` 目录、Prefetch 的路径在 `Program Files`，就认为两者指向不同程序。正确判据是 `credhelper.exe` 与 `CRDCRED~1.EXE` 的 8.3 短名映射成立（`CREDHELPER.EXE` → `CRDCRED~1.EXE`），两条路径可能分别是安装前后的同名副本或更新版本；

判定关联的依据是 `First Run`（22:18:47）与 Prefetch 首槽（22:19:03）相差 16 秒这一时间紧邻关系，以及哈希比对是否一致。

按错误判据当成两个独立程序，会凭空多出一个「Temp 目录下另有未知程序」的问号；若不深究，反而可能放过真正的那一个。

第三处易错点是把 4 次执行直接等同于「采集了 4 批凭据」。正确判据是 Prefetch 记录的是**映像被加载**的时刻，程序是否成功完成凭据采集取决于其逻辑、权限与目标应用当时是否运行；本案只有两次执行（11-12 22:19 与 11-13 21:55）落在夜间工作时段，其余两次时间不明。

按错误判据写「4 次采集」，在需要确认实际影响面时会给出夸大的数字；正确表述是「被启动 4 次，其中 2 次发生在夜间，具体采集结果需以目标应用的日志或数据变化佐证」。

<a id="section-31"></a>

### 5.3 卸载残留与日志清空之间不作因果推断

**场景**

委托方将两条线索并列：「11-12 至 11-13 运行了凭据收集程序，11-12 至 11-13 卸载痕迹」，以及「11-15 前后 Security 日志被清空 3 次」，要求回答「是否有人在事后销毁证据」。需要判断两者能否建立因果关系。

**处置过程**

第一步，把全部时间点排成一张时序表：

```bash
python3 - <<'PY'
ev = [
 ("2024-11-12 03:41:19", "Amcache Compile Time       程序编译"),
 ("2024-11-12 22:18:47", "Amcache First Run          首次运行"),
 ("2024-11-12 22:19:03", "Prefetch 槽1               执行"),
 ("2024-11-12 22:23:41", "Prefetch 槽2               执行"),
 ("2024-11-12        —", "Installer UserData InstallDate 20241112"),
 ("2024-11-13 21:55:08", "Prefetch 槽3               执行"),
 ("2024-11-13 22:07:41", "Prefetch 槽4               末次执行（末次<关机，自洽）"),
 ("2024-11-14 23:40:22", "ShutdownTime               正常关机"),
 ("2024-11-15 01:07:44", "USBSTOR 首次安装           外接存储"),
 ("2024-11-15 01:12:44", "1102 第 2 次日志清除"),
]
for t, d in ev:
    print(f"{t}  {d}")
PY
```

第二步，检查是否存在能把两者连接起来的中间环节：

```bash
python3 - <<'PY'
links = [
 ("Uninstall 时间戳",      "卸载键的最后写入时间能否覆盖到具体日期？"),
 ("4688 进程创建事件",     "System 通道是否有 msiexec / unins000.exe 的创建记录？"),
 ("MFT 时间戳",            "unins000.exe 文件的创建/修改时间？"),
 ("1102 事件的执行身份",   "日志清除由哪个账户发起（4624/4698 关联）？"),
 ("两者时间间隔",          "卸载在 11-13 之前还是之后？1102 在 11-15 01:12"),
]
for a, b in links:
    print(f"[需核查] {a:20s} → {b}")
PY
```

第三步，核查 `System` 通道是否有卸载相关进程记录：

```bash
EvtxECmd.exe -f /evidence/logs/System.evtx --csv /evidence/evtx_out
grep -iE 'msiexec|unins000|MsiInstaller' /evidence/evtx_out/System*.csv | head
# → 2024-11-14 22:50:11  MsiInstaller  产品 {2C7E9B4A-…} 卸载完成
```

第四步，评估 1102 事件的可归属性：

```bash
evtx_dump.py /evidence/logs/Security.evtx | grep 'EventID.*1102'
```

```text
2024-11-15 01:12:44  1102  日志被清除
（1102 事件本身不含发起者 SID，需靠前后 4624/4688 关联，
  而 Security 通道已被清除 → 本案无法归因到具体账户）
```

第五步，明确写入报告的结论边界：

```bash
python3 - <<'PY'
print("【可认定】")
print("  2024-11-12 安装 CredentialHarvest")
print("  2024-11-12 至 11-13 被执行 4 次（Prefetch + Amcache 双源）")
print("  卸载动作发生在 2024-11-14 22:50:11（System 通道 MsiInstaller 记录）")
print("  2024-11-15 01:12:44 Security 日志被清除（人为）")
print()
print("【不可认定】")
print("  两者之间是否存在因果关系 —— 时间相隔逾 22 小时，")
print("  且缺少能把『卸载』与『清日志』关联到同一人的证据。")
print("  日志清除的实际动机、目标范围（是否含卸载痕迹）均无法确定。")
PY
```

**结论**

完整时序为：编译 11-12 03:41:19 → 首运 22:18:47 → 执行 4 次（11-12 22:19:03、22:23:41，11-13 21:55:08、22:07:41）→ 安装日期 11-12 → 正常关机 11-14 23:40:22 → 外接存储 11-15 01:07:44 → 1102 第 2 次日志清除 11-15 01:12:44。

`System` 通道存在 `MsiInstaller` 事件，记录 2024-11-14 22:50:11 产品 `{2C7E9B4A-…}` 卸载完成，为卸载动作提供了独立于注册表的时间证据。

**但 1102 事件本身不含发起者 SID**，需通过前后 4624/4688 关联归因，而 `Security` 通道已被清除，本案无法归因到具体账户；卸载与日志清除相隔逾 22 小时，且无任何中间环节可把两者连接到同一人。

可认定的结论为「安装、运行、卸载」三件事各自的成立；**不可认定两者之间存在因果关系**，报告不作因果推断。

**误判对照**

最常见的错误是「有人在 11-13 卸载了恶意程序，11-15 又清除了日志，说明是同一人在系统性销毁证据」。正确判据是因果推断必须具备可追溯的连接环节——时间邻近、同一执行身份、或一方记录了另一方的目的；本案两条线索相隔逾 22 小时，卸载有 `MsiInstaller` 独立记录而日志清除的发起者完全无法归因（1102 不含 SID，`Security` 通道本身已被清除），连接环节**完全缺失**。

按错误判据作因果推断，会把两个可能互不相关的独立事件串成一条「系统性反取证」叙事；而一旦对方说明日志清除是 IT 部门的安全基线任务或日志轮转策略，整条论证就会崩塌并损害报告的整体可信度。

第二处易错点是把「Security 日志被清除」理解成「删除痕迹的行为没有被记录」。正确判据是清除动作本身**必定留痕**——1102 事件正是清除行为的记录，且它被写入的是被清除的同一日志中，因此可在日志尾部被发现；本案 3 条 1102 即是。

按错误判据认为清除动作无痕，会得出「无法判断是否有人动过日志」这一比实际更弱的结论，并可能因此错失本案中强度最高的一条人为篡改证据。

第三处易错点是发现 1102 之后，就把注意力全部放在日志上而忽略它无法归因这一限制。正确判据是 1102 提供的是「时间」与「事件类型」，不提供「执行者」；要归因必须依靠同一时间窗内的 `4624`（谁登录）、`4688`（谁启动了 `wevtutil` 或 PowerShell）、`4672`（特权分配）以及 `System` 通道的进程创建，而本案 `Security` 通道已被清除，只有 `System` 可用。

按错误判据忽视归因限制，会在报告中写出「日志由 XX 账户清除」这类无证据支撑的表述；正确写法是「日志清除由未知账户发起，Security 通道相关记录已不可得，无法归因」。

---
<a id="section-32"></a>

## 六、扩展阅读方向

<a id="section-33"></a>

### 前置基础：读离线 hive 的两个硬前提

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— hive 必须连同 `.LOG1` / `.LOG2` 一起提取，漏了日志就可能丢掉异常断电前的最新变更。
- [取证工件地图](computer-registry-log-windows-artifact-map.md) —— hive 的磁盘位置与 Windows 版本差异。**版本决定了路径与可用的键值范围。**
- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— **hive 是普通文件，它的时间戳来自 NTFS**，理解这一点才不会被「文件修改时间」误导。

<a id="section-34"></a>

### 同层深入：注册表里其它两类高价值内容

- [用户行为痕迹](computer-registry-log-user-activity-artifacts.md) —— **同一批 hive 的另一类读法**。UserAssist、TypedPaths、Shellbags 都在 `NTUSER.DAT` 里，本篇负责「怎么正确读」，那一篇负责「这些键值分别意味着什么」。
- [ShimCache 与 Amcache](../computer-execution/computer-execution-shimcache-amcache.md) —— ShimCache 就存在 `SYSTEM` hive 的注册表值里，本篇的提取与路径判定是那一篇的前提。
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— DPAPI 主密钥的 SID 归属需要从注册表确认，凭据可解性判断建立在本篇之上。
- [事件日志深度分析](computer-registry-log-windows-event-log-analysis.md) —— 同板块的姊妹篇。注册表记配置、事件日志记行为，两者的分工是「静态状态」与「动态事件」。

<a id="section-35"></a>

### 相邻议题：跨平台与跨层的对照

- [浏览器密码库与 Token 解密](../../crypto/crypto-app/crypto-app-browser-passwords-and-tokens.md) —— DPAPI 是 Windows 特有的凭据保护机制，其它平台的模型对照见该篇。
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) 的加密链依赖 `Local State` 的 `os_crypt` 键值，**这是一个注册表式配置参与凭据保护的例子**。
- [Linux 取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— Linux 没有注册表，同类配置散落在 `/etc` 与用户目录的文本文件里，两边对照能看清「集中式配置库」这个设计的取舍。

<a id="section-36"></a>

### 工具与规范：处置纪律

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— hive 的归档封装。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— SAM 与 SECURITY hive 含口令哈希与策略，属高敏感材料。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— **口令哈希只做复制与记录，不做破解；**相关要求见该篇。

<a id="section-37"></a>

### 判据与反例：哪些推论不能成立

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 注册表键被修改时，只有 hive 文件时间戳在动，而键内自带的时间值改不掉——这个不对称是该篇判据的来源。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **阴性结论的表述纪律**：某个键不存在时，必须写明查的是哪个控制集编号、哪个用户 hive。
<a id="section-38"></a>

## 七、命令速查

```bash
# ===== 提取 hive（-o 偏移按实际 mmls 结果替换）=====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'config/(SYSTEM|SOFTWARE|SAM|SECURITY|DEFAULT)$'
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E 'NTUSER\.DAT$|UsrClass\.dat$'
icat -o 2048 /work/DigiForensics.dd <inode> > /evidence/hives/SYSTEM
xxd -l 4 -p /evidence/hives/SYSTEM        # 期望 regf = 72656766

# ===== ★ 确认控制集编号（离线查询前必做）=====
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select     # 看 \Select\Current
# Current=1 → 用 ControlSet001；=2 → 用 ControlSet002

# ===== SYSTEM hive常用插件 =====
rip.exe -p /evidence/hives/SYSTEM -a /tmp/svc.txt svcscan        # 全部服务与驱动
rip.exe -p /evidence/hives/SYSTEM -a /tmp/usb.txt usbstor        # USBSTOR 设备与时间
rip.exe -p /evidence/hives/SYSTEM -a /tmp/mem.txt prefetchparameters   # Prefetch 开关
rip.exe -p /evidence/hives/SYSTEM -a /tmp/net.txt netstat        # 网络配置

# ===== SOFTWARE / SAM / NTUSER =====
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/sw.txt uninstall    # 已装与残留软件
rip.exe -p /evidence/hives/SOFTWARE -a /tmp/srum.txt srum        # SRUM 配置
rip.exe -p /evidence/hives/SAM -a /tmp/sam.txt samparse         # 账户、RID、登录次数
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/ua.txt userassist
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/rm.txt runmru
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/tp.txt typedpaths
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/mp.txt mountpoints2
rip.exe -p /evidence/hives/Administrator.NTUSER.DAT -a /tmp/rd.txt recentdocs
rip.exe -p /evidence/hives/SYSTEM -a /tmp/timeline.csv -aT      # 时间线插件（CSV）

# ===== 交叉验证 =====
LECmd.exe -d /evidence/usb_lnk --csv /evidence/out             # LNK 的 MachineID 对照 USBSTOR
EvtxECmd.exe -f /evidence/logs/System.evtx --csv /evidence/evtx # 20001/20003 USB 事件
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Windows 取证 — 注册表取证」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《注册表取证》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
