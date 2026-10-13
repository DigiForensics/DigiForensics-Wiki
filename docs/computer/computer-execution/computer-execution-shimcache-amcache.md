---
title: "ShimCache 与 Amcache"
slug: "computer-execution-shimcache-amcache"
canonical: "https://www.digiforensics.cn/wiki/computer-execution-shimcache-amcache"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["执行痕迹"]
---

# ShimCache 与 Amcache

<a id="section-1"></a>

## 一、概述

Prefetch 有一个严重弱点：**它是可选的**。被显式关闭、被清理、或只记录路径哈希，都会让执行证据链断掉。

Windows 还提供了两个**不依赖功能开关**的执行相关工件：

| 工件 | 位置 | 记录什么 | 独立性 |
|---|---|---|---|
| **ShimCache**（AppCompatCache） | `SYSTEM` hive 的注册表值 | 程序兼容性缓存中的路径及相关时间字段；**单条记录不能独立证明执行** | **系统必开，普通设置无法关闭** |
| **Amcache** | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | 程序的路径、SHA-1、PE 编译时间、首次执行时间 | Windows 8+ 默认开启 |

三者形成**三角验证**：Prefetch 给次数与精确时间、ShimCache 给「系统看到过它启动」、Amcache 给「文件身份与首次运行时刻」。**任何一个单独用都有缺口，交叉才能收敛。**

这两个工件各有一个极易导致错误结论的陷阱：**ShimCache 的时间戳不是执行时间**（是目标 exe 的文件修改时间，见 2.2），以及**硬断电会丢失尚未落盘的条目**（它常驻内存，正常关机/重启时才写入 hive，见 2.3）。

它与 [Prefetch 深度解析](computer-execution-prefetch.md) 并列，属于**分析**环节的执行侧证据，但独特价值在**现场状态**这个维度：

- **上游依赖** 注册表 hive 的正确提取。**离线 SYSTEM hive 应先解析 `Select` 键并对应选择 `ControlSet00x`**；不能假定当前控制集总是 `ControlSet001`，这是本领域最高频的坑，方法见[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)；Amcache 则是独立文件，接入方式见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)。
- **它自己**要先判断现场状态。系统运行中 / 正常关机 / 硬断电，三种状态下 ShimCache 的可用性完全不同，这个判断必须在分析之前做完。
- **下游支撑** 两处。**Amcache 的 SHA-1 是文件身份的锚点**，可用于判断「这个可执行文件是否被替换过」；**内存里的 ShimCache 覆盖了磁盘版的缺口**，从内存读取的方法见 3.3。

落到具体形态上：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| ShimCache | `HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache` | `REG_BINARY` 形式的注册表值，不是独立文件；条目有序排列，**有容量上限，满了之后新条目挤掉最旧的** |
| 路径历史 | Windows 2000/XP/2003 为 `...\Session Manager\AppCompatCache`（**无内层子键**），Vista 及以后多一层 | **用错版本路径是常见的「读不到」原因** |
| 格式版本 | Win7 及以前旧格式**有 `0x01` Executed 标志位**，可区分「枚举过」与「执行过」 | **Win8 起该标志位被移除**，改为 AVL 树式新结构，所有条目格式上等价 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | 完整路径、**SHA-1（只覆盖前 30 MB）**、PE 编译时间戳、首次执行时间、文件大小 |
| 内存中的 ShimCache | 活系统或内存镜像 | **数据主要常驻内存，会话注销与正常关机时才落盘** |

三个判定要点：**ShimCache 与功能开关无关**、**Win8 起无法区分「枚举过」与「执行过」**、Amcache 的 SHA-1 只覆盖前 30 MB。

据此能回答的是：系统是否尝试启动过某个路径的程序（**不受 Prefetch 开关影响**）、某个可执行文件的 SHA-1 与 PE 自称的编译时间、以及它在系统上的**首次**执行时刻。

回答不了的是这些，外加两个必须写进报告的结论：

- **ShimCache 的时间戳不是执行时间。** 目标 exe 的 `$STANDARD_INFORMATION` 最后修改时间是系统登记条目时读文件信息（为判断版本与兼容性）顺手记下的，**它不记录「你什么时候点了这个 exe」**——兼容性缓存不需要这个信息。把文件修改时间当执行时间，是本领域最常见的技术性错误（详见 2.2）。同样，硬断电机器上磁盘 ShimCache 的「缺失」是技术必然而非证据：数据常驻内存，硬断电（拔电源、崩溃、长按电源键）会使尚未落盘的更新丢失，磁盘上的 ShimCache 停留在上一次成功写入时。写成「未发现相关程序执行痕迹」是错误表述，正确写法是「因系统异常断电，该时段执行痕迹未落盘，无法据此判断」。
- **Win8/10/11 上不能证明执行成功。** 旧格式的 `0x01` Executed 标志位已被移除，所有条目在格式上等价，只能证明「系统尝试启动过该路径的程序」。
- **完整的文件哈希。** Amcache 的 SHA-1 **只覆盖前 30 MB**（为性能做的设计），比对时必须标注范围，**不能当作完整文件哈希**。
- **文件的真实编译时间。** PE 编译时间戳**可被伪造**，只作「程序自称的编译时间」。
- **执行次数。** ShimCache 与 Amcache 都不记次数，次数只有 Prefetch 的 `Run Count` 可靠。

本章依赖的前置知识：NTFS 的 `$STANDARD_INFORMATION` 四个时间戳语义，否则无法理解 ShimCache 时间戳的真实含义，见[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)；注册表 hive 的离线提取方法，**特别是 `ControlSet001` 的选择**，见[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)；[Prefetch 深度解析](computer-execution-prefetch.md)的结论，后面的可信度对比表需要拿它作对照；Windows 的关机语义与内存落盘机制，**这是判断现场状态的前提**；以及内存取证的基本概念（从内存读注册表键值），见[内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md)。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 ShimCache 是什么、为什么必然存在

Windows 需要知道「这台机器上曾跑过哪些程序」来解决**应用程序兼容性**问题：老程序在新系统上跑不起来时，系统需要找到可能让它跑起来的垫片（shim）。

为加速这个查找，系统维护一个有序的路径缓存，这就是 ShimCache。

关键特性：

- **与功能开关无关**。删掉注册表值后，重启时系统会重新建表。
- **有容量上限**，满了之后新条目会挤掉最旧的。
- **以 `REG_BINARY` 形式存放在注册表里**，不是独立文件。

注册表位置（离线必须用 `ControlSet001`）：

```text
HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache
```

> **路径历史**：Windows 2000 / XP / 2003 是 `...\Session Manager\AppCompatCache`（无 `AppCompatCache` 子键层）；Vista 及以后多了一层。用错版本路径是常见的「读不到」原因。

**格式随版本变化**：Windows 7 及以前的旧格式条目中**有 `0x01` `Executed` 标志位**，可区分「文件被枚举过」与「文件被执行过」；**Windows 8 起该标志位被移除**，改为 AVL 树式新结构，所有条目在格式上等价。因此在 Win8/10/11 上，ShimCache 只能证明「系统尝试启动过该路径的程序」，不能证明执行成功。

<a id="section-4"></a>

### 2.2 ★ 陷阱一：时间戳不是执行时间

大量二手资料把 ShimCache 的时间戳描述为「执行时间」，**这是错的**。

ShimCache 条目中记录的时间，语义是：

> 目标 exe 文件本身的 `$STANDARD_INFORMATION` 最后修改时间（NTFS MFT 记录里的「修改时间」）

系统登记条目时读的是文件信息（为判断版本与兼容性），顺手把文件修改时间记了下来。

**它不记录「你什么时候点了这个 exe」**——兼容性缓存不需要这个信息。

**可能造成的误判**：

```text
对 exe 执行 timestomp（把文件修改时间改为 2019-01-01）
    ↓ ShimCache 中对应条目的时间也变成 2019-01-01
    ↓ 分析师看到 ShimCache 说「2019 年运行过 notepad.exe」→ 错误结论
```

| ShimCache 时间显示 | 真实含义 | 不能推断 |
| --- | --- | --- |
| 2019-03-11 02:14:55 | **那个 exe 文件**的修改时间是 2019-03-11 | **不能**推断「2019 年运行过它」 |
| 2024-11-10 08:22:41 | 该 exe 在 2024-11-10 被修改/编译 | **不能**推断「当天运行过它」 |
| 无时间 | 条目存在，但文件已删或时间不可解析 | **不能**推断「从未运行过」 |

> **报告表述模板**：
> - 错误：「ShimCache 显示 `malware.exe` 于 2019-03-11 被执行过。」
> - 正确：「ShimCache 中存在 `C:\...\malware.exe` 的条目，表示系统曾尝试启动过该路径下的程序。条目时间 2019-03-11 02:14:55 **是该文件的最后修改时间**（经 MFT 记录核对一致），不构成执行时间证据。」

真正执行时间的正确来源：

| 需求 | 正确来源 |
| --- | --- |
| 程序执行时间 | Prefetch、事件日志 4688、Sysmon 事件 1 |
| 文件访问时间 | `$STANDARD_INFORMATION` 的 Access（易被关闭或延迟更新） |
| 文件修改时间 | MFT `$STANDARD_INFORMATION`（ShimCache 里就是这个） |

<a id="section-5"></a>

### 2.3 ★ 陷阱二：硬断电可能丢失尚未落盘的条目

```text
程序启动 → 兼容性服务把路径加入【内存中的 ShimCache】
                                  ↓ 内存中持续更新
        【会话注销 / 系统正常关机重启】→ 写入 SYSTEM hive（磁盘）
```

- **数据主要常驻内存**，在**会话注销与系统正常关机/重启时**写入 `SYSTEM` hive 的 `AppCompatCache` 值。
- 硬断电（拔电源、崩溃、长按电源键）会使尚未落盘的更新丢失，磁盘上的 ShimCache 停留在**上一次成功写入时**的状态（具体粒度随 Windows 版本与内存压力而异，无法精确到「丢失最后几条」）。

```text
最后正常关机：2024-11-14 23:40；案发：2024-11-15 01:07（USB 接入并运行程序）
→ 磁盘 ShimCache 很可能没有 01:07 之后运行的程序条目
→ 这不是「没执行」，而是「证据未落盘」
```

| 现场状态 | 处置 |
| --- | --- |
| 系统运行中 | **先做内存采集**再关机，用内存插件读 ShimCache |
| 正常关机 | 磁盘 ShimCache 基本完整，可直接用 |
| **硬断电/崩溃** | 磁盘 ShimCache 只反映上次成功写入的状态，**必须记录此局限** |

> **要反复强调的一句话**：遇到硬断电的机器，磁盘 ShimCache 的「缺失」是技术必然，不是证据。 写成「未发现相关程序执行痕迹」是错误表述；正确写法是「因系统异常断电，该时段执行痕迹未落盘，无法据此判断」。

<a id="section-6"></a>

### 2.4 Amcache：另一个独立工件

Amcache（Application Compatibility Cache）是 Windows 8 引入的独立注册表 hive，位于 `C:\Windows\AppCompat\Programs\Amcache.hve`，记录程序的**完整路径**、**SHA-1 哈希**、**PE 编译时间戳**、**首次执行时间**与文件大小。

> **两条重要限制**：SHA-1 **只覆盖文件前 30 MB**（为性能做的设计），比对时必须标注范围，**不能当作完整文件哈希**；PE 编译时间**可被伪造**，只作「程序自称的编译时间」。

**独立性价值**：即使 Prefetch 被关闭、即使 ShimCache 因断电丢失，Amcache 作为独立文件仍可用。

局限是只记录**首次**执行时间，文件从未运行过则不在其中。

<a id="section-7"></a>

### 2.5 三者的可信度对比

| 维度 | Prefetch | ShimCache | Amcache |
| --- | --- | --- | --- |
| 记录「执行尝试」 | 是 | 是 | 是（首次） |
| 记录「执行次数」 | 是（`Run Count`） | 否 | 否 |
| 记录「精确执行时间」 | 是（8 槽内） | **否（是文件修改时间）** | 仅首次 |
| 记录「完整路径」 | 是 | 是 | 是 |
| 记录「文件哈希」 | 否 | 否 | SHA-1（前 30MB） |
| 记录「PE 编译时间」 | 否 | 否 | 是（可伪造） |
| 可被功能开关关闭 | 是 | 否 | 否 |
| 硬断电丢失未落盘条目 | 否（运行时写盘） | **可能** | 部分 |
| 独立文件 | 否 | 否（在 SYSTEM hive 内） | 是 |

**推荐组合策略**：先查 `EnablePrefetcher` 确认 Prefetch 是否可用；再查 `ShutdownTime` 判断是否异常关机（正常则 ShimCache 可用，异常则需内存采集或记录局限）。无论前两步如何，Amcache 作为独立文件均可用于建立路径与哈希基线；最后三者加事件日志与 LNK 交叉验证形成结论。

<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 提取并解析

```bash
mkdir -p /evidence/hives
# SYSTEM hive 与 Amcache.hve（Win8+；Win7 用 RecentFileCache.bcf）
for h in SYSTEM Amcache.hve; do
  fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE "config/SYSTEM$|AppCompat/Programs/$h$" \
    | grep -E '^r/r' | awk '{print $2}' | head -1 \
    | while read -r ino; do icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/hives/$h"; done
  printf '%s: ' "$h"; xxd -l 4 -p "/evidence/hives/$h"      # 期望 72656766（regf）
done

# 确认控制集编号（离线必做）
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current : 1     → 路径写 ControlSet001
```

```powershell
# 解析 ShimCache：自动识别 2000~11 各种格式，版本判断交给工具
AppCompatCacheParser.exe -f C:\evidence\hives\SYSTEM --csv C:\evidence\out
# → Path / ModifiedTime / InsertedTime / Executed（仅 Win7 有 Executed）
AmcacheParser.exe -f C:\evidence\hives\Amcache.hve --csv C:\evidence\out
# → Path / SHA1 / Compile Time / First Run Time / File Size
```

| 工具 | 输入 | 输出 | 适用 |
| --- | --- | --- | --- |
| RegRipper `appcompatcache` | SYSTEM hive | 文本/十六进制 | 快速查看，二进制需另解析 |
| **AppCompatCacheParser** | SYSTEM hive | **CSV（自动识别版本）** | **首选** |
| Volatility 3 | **内存镜像** | CSV/TXT | 运行中 / 断电前机器 |

<a id="section-10"></a>

### 3.2 核对时间戳语义（必做）

拿到 ShimCache 条目后，**必须**核对它的时间到底是什么：

```bash
# 从 ShimCache CSV 中挑一个可疑路径
grep -i 'suspicious' /evidence/out/AppCompatCacheParser_*.csv
# → Path: C:\Users\admin\AppData\Local\Temp\suspicious.exe
#   ModifiedTime: 2019-03-11 02:14:55

# 拿这个时间与文件的 MFT 时间戳对照
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'suspicious.exe'
istat -o 2048 /work/DigiForensics.dd <inode>
# Modified: 2019-03-11 02:14:55     ← 与 ShimCache 一致
# Created : 2024-11-10 08:22:41
# Accessed: 2024-11-14 21:30:44
```

| 对照结果 | 结论 |
| --- | --- |
| ShimCache 时间 **= MFT Modified** | **证实是文件修改时间**，不是执行时间 |
| ShimCache 时间 ≠ MFT Modified | 文件可能已被 timestomp，或时间字段解析有误，需进一步核实 |
| 文件已删除，无法对照 | 用 Amcache 的 `Compile Time` 互证；或从 VSS/备份找旧版本 |

> **这个核对只需做一次**。一旦确认「ShimCache 时间 = MFT Modified」，后续所有条目都按这个语义解读。

<a id="section-11"></a>

### 3.3 从内存读取 ShimCache

机器**运行中**时磁盘 ShimCache 可能未落盘，**硬断电**时未落盘部分已丢失；运行中可从内存读当前会话条目。

Volatility 3 插件：`windows.shimcachemem.ShimcacheMem`，从对应版本的内存结构中读取。

```bash
vol -f /evidence/DigiForensics-mem.raw windows.shimcachemem.ShimcacheMem
vol -f /evidence/DigiForensics-mem.raw windows.info      # 先确认内核符号可用
vol -f /evidence/DigiForensics-mem.raw windows.amcache.Amcache
```

| 情形 | 该怎么做 |
| --- | --- |
| 系统**运行中** | 先做内存采集，再用本节命令 |
| 系统**硬断电** | 内存已丢，未落盘部分**无法恢复**，必须记录局限 |
| 系统**正常关机** | 用 3.1 的磁盘路线即可 |

<a id="section-12"></a>

### 3.4 三者交叉验证

```bash
# 1. Prefetch：执行次数 + 精确时间
PECmd.exe -d C:\evidence\Prefetch --csv C:\evidence\out
# 2. ShimCache：系统见过它启动
AppCompatCacheParser.exe -f C:\evidence\hives\SYSTEM --csv C:\evidence\out
# 3. Amcache：文件身份 + 首次运行
AmcacheParser.exe -f C:\evidence\hives\Amcache.hve --csv C:\evidence\out

# 交叉比对：三份 CSV 的 Path 列转小写、统一分隔符后排序，看哪些路径出现在几个工件里
```
<a id="section-13"></a>

## 四、常见陷阱

<a id="section-14"></a>

### 4.1 ShimCache 时间语义

<a id="section-15"></a>

#### 陷阱 1：★ 把 ShimCache 的时间戳当"执行时间"

**现象**

ShimCache 中 `C:\Users\admin\AppData\Local\Temp\cleanup.exe` 的 `ModifiedTime` 显示 `2019-03-11 02:14:55`，报告写「ShimCache 显示该程序于 2019 年被执行过，与本案无关」。

**原因**

大量二手资料把 ShimCache 的时间戳描述为「执行时间」，这是错的。

它的实际语义是：

> 目标 exe 文件本身的 `$STANDARD_INFORMATION` 最后修改时间（NTFS MFT 里的「修改时间」）

系统登记条目时读的是**文件信息**（为判断版本与兼容性），顺手把文件修改时间记了下来。

**它不记录「你什么时候点了这个 exe」** —— 兼容性缓存不需要这个信息。

由此产生的误判映射：

| ShimCache 时间显示 | 真实含义 | **不能**推断 |
| --- | --- | --- |
| 2019-03-11 02:14:55 | **那个 exe 文件**的修改时间是 2019-03-11 | **不能**推断「2019 年运行过它」 |
| 2024-11-10 08:22:41 | 该 exe 在该时刻被修改/编译 | **不能**推断「当天运行过它」 |
| 无时间 | 条目存在，但文件已删或时间不可解析 | **不能**推断「从未运行过」 |

**影响**

这是 ShimCache 相关的**最严重错误**，因为它会**系统性地把案发时段的证据推到很久以前**：

- 案件关注 2024-11-15，条目时间却是 2019 年 → 被判为「与本案无关」而排除
- 排除之后，这条路径上的其他线索（Amcache、Prefetch、文件系统痕迹）也不会被追查
- 结论方向完全错误，且因为表面上「有数据支撑」而很难被质疑

**核查**

**用 MFT 时间戳做一次核对，确认语义后统一适用**：

```bash
# 从 ShimCache CSV 挑一条可疑路径
grep -i 'suspicious' /evidence/out/AppCompatCacheParser_*.csv
# Path: C:\Users\admin\AppData\Local\Temp\cleanup.exe
#   ModifiedTime: 2019-03-11 02:14:55

# 拿这个时间与文件的 MFT 时间戳对照
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'cleanup.exe'
istat -o 2048 /work/DigiForensics.dd <inode>
# Modified: 2019-03-11 02:14:55    ← 与 ShimCache 一致
# Created : 2024-11-15 21:57:30
# Accessed: 2024-11-14 21:30:44
```

| 对照结果 | 结论 |
| --- | --- |
| ShimCache 时间 **= MFT Modified** | **证实是文件修改时间**，不是执行时间 |
| ShimCache 时间 ≠ MFT Modified | 文件可能已被 timestomp，或解析有误，需进一步核实 |
| 文件已删除 | 用 Amcache `Compile Time` 互证，或从 VSS/备份找旧版本 |

**这个核对只需做一次**，确认后所有条目按同一语义解读。执行时间的正确来源：

| 需求 | 正确来源 |
| --- | --- |
| 程序执行时间 | Prefetch、事件日志 `4688`、Sysmon 事件 `1` |
| 文件访问时间 | `$STANDARD_INFORMATION` 的 Access（易被关闭或延迟更新） |
| **文件修改时间** | MFT `$STANDARD_INFORMATION`（ShimCache 里就是这个） |

<a id="section-16"></a>

#### 陷阱 2：把"时间戳被改"当成执行时间伪造

**现象**

看到 ShimCache 条目时间是 2019 年，而文件创建时间是 2024-11-15，报告写「攻击者伪造了执行时间，将执行痕迹回推到 5 年前」。

**原因**

timestomp 改的是文件修改时间，ShimCache 只是被动跟着变。

改文件修改时间这个动作本身是常见的操作，但它的语义是「隐藏文件的新鲜度」，不是「伪造执行记录」。

时间戳篡改的三个时间位各有不同的用途与可信度：

| 时间位 | 可以用来做什么 | 篡改的典型目的 |
| --- | --- | --- |
| `Created`（MFT 记录） | 文件**落地**时间 | 较少被改（改它需要改 MFT 记录本身） |
| `Modified`（MFT 记录） | 文件**内容最后修改**时间 | **timestomp 的主要目标** |
| `Access`（MFT 记录） | 最后访问 | 经常被关闭或延迟更新，不可靠 |

关键在于：改 `Modified` 影响的是「这个文件有多新」，而不是「它什么时候被执行」。

攻击者改它通常是为了让新投放的文件看起来像旧文件，从而混入系统目录的老文件堆里。

**影响**

- 把 timestomp 误判为「伪造执行时间」，会把调查方向引向不存在的痕迹伪造行为
- 更实际的问题：这样定性会让分析者**忽略真正的执行时间来源**（Prefetch、事件日志），而那些地方才有答案
- 若报告断言「存在痕迹伪造」，对方可以立刻用 MFT `Created` 与文件内容细节反驳

**核查**

**先认定时间位，再描述篡改目的**：

```bash
# 三个时间位一起看
istat -o 2048 /work/DigiForensics.dd <inode>
# Created : 2024-11-15 21:57:30    ← 文件落地时间，通常未被改
# Modified: 2019-03-11 02:14:55    ← 被改到 2019，timestomp 目标
# Accessed: 2024-11-14 21:30:44
```

| 观察到的模式 | 结论 |
| --- | --- |
| `Created` 近、`Modified` 远 | **timestomp：文件新但修改时间被改旧**，目的是伪装文件年龄 |
| `Modified` == ShimCache 条目时间 | 证实 ShimCache 记的是文件修改时间 |
| `Modified` 与 Amcache `Compile Time` 差距悬殊 | 需与程序内部信息交叉，判断编译工具是否自定义时间戳 |

报告表述：

> `cleanup.exe` 的 MFT `Created` 为 2024-11-15 21:57:30（文件落地），`Modified` 为 2019-03-11 02:14:55，二者不一致，符合 timestomp 特征：文件为新投放，修改时间被改至 2019 年，意图伪装文件年龄。ShimCache 条目时间 2019-03-11 02:14:55 与 MFT `Modified` **完全一致**，再次证实该字段记录的是文件修改时间，**不构成执行时间证据**。真实首次运行时间见 Amcache `First Run Time`：2024-11-15 21:58:02。

<a id="section-17"></a>

### 4.2 注册表路径与版本

<a id="section-18"></a>

#### 陷阱 3：用错注册表路径，或离线查 `CurrentControlSet`

**现象**

按 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` 去读，得到空结果。换成不带 `AppCompatCache` 子键层的路径，报告写「该机不存在 ShimCache」。

**原因**

**两个独立的版本差异叠加在一起**：

**其一，路径层次随版本变化**：

| 系统版本 | 路径 |
| --- | --- |
| Windows 2000 / XP / 2003 | `...\Session Manager\AppCompatCache`（**无** `AppCompatCache` 子键层） |
| Vista 及以后 | `...\Session Manager\AppCompatCache\AppCompatCache`（**多一层**） |

**其二，控制集编号会变**：

离线读取时 `HKLM\SYSTEM\CurrentControlSet` **是符号链接，离线状态下为空**。必须用具体编号 `ControlSet001`，而编号本身要读出来：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current : 1     → 路径写 ControlSet001
```

所以「读不到」可能来自三个独立原因：路径层次不对、控制集编号不对、符号链接在离线为空。

**每一条都会产生同样的「空结果」。**

**影响**

- 「该机不存在 ShimCache」是一个关于**系统机制存在性**的错误断言，而 ShimCache 是系统必开组件
- 基于这个错误断言，后续可能认为「ShimCache 这条线索不可用」，从而放弃交叉验证
- 更麻烦的是它看起来像「取证没找到东西」，而不是「路径写错了」，很难自我纠正

**核查**

**先确认控制集，再按系统版本选路径，两步都记录**：

```bash
# 1. 确认控制集编号
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current : 1

# 2. 两个版本路径都试，并记录命中情况
for cs in ControlSet001 ControlSet002; do
  for sub in "AppCompatCache\\AppCompatCache" "AppCompatCache"; do
    k="ControlSet001\\Control\\Session Manager\\$sub"
    printf '%s\\%s : ' "$cs" "$sub"
    rip.exe -p /evidence/hives/SYSTEM -a /tmp/k.txt "$k" 2>/dev/null | wc -l
  done
done
```

报告写法：

> `SYSTEM` hive 中 `Select\Current` = 1，故控制集为 `ControlSet001`。该系统为 Windows 10，ShimCache 路径为 `ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache`（Vista 及以后多一层子键），**已确认命中**。`CurrentControlSet` 为符号链接，离线状态下为空，**未使用该别名**。

<a id="section-19"></a>

#### 陷阱 4：硬断电后写"ShimCache 无相关条目 → 未执行"

**现象**

检材是强制断电状态，ShimCache 里没找到可疑程序条目，报告写「ShimCache 中无该程序记录，判定其未被执行」。

**原因**

ShimCache 常驻内存，正常关机/重启时才写入 hive。

硬断电时，内存中尚未落盘的条目**已经永久丢失**。

所以在硬断电检材上：

```text
ShimCache 缺失 = 时间未知
              ≠ 从未启动
```

必须先确认关机状态，因为它决定整个工具有效性：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# ControlSet001\Control\Windows\ShutdownTime : 2024-11-15 22:14:03
```

对比案发时段：

| 关机时间 vs 案发时段 | ShimCache 有效性 |
| --- | --- |
| 正常关机在案发时段**之前** | **磁盘 ShimCache 只反映关机前状态**，案发时段的缺失是技术必然 |
| 正常关机在案发时段**之后** | 案发时段在覆盖范围内，可正常依赖 |
| **硬断电** | 案发时段未落盘部分**无法从磁盘恢复**；需内存镜像，缺失即不可知 |

**影响**

- **用「证据未落盘」当成「没有发生」**，方向性错误
- 时段边界很容易被忽略：`ShutdownTime` 是 11-15 22:14，而案发是 11-16 03:22，两者之间的空白很容易被分析者当成「无活动」
- 这个错误与陷阱 1 叠加时：条目时间被误当执行时间排除一次，条目缺失又被误当未执行排除一次，**同一条线索被双重排除**

**核查**

**关机状态是判定前置，缺失即「不可知」**：

| 情形 | 该怎么做 | 报告表述 |
| --- | --- | --- |
| 系统**运行中** | **先做内存采集**，再读内存 ShimCache | 「运行中采集内存，用 `windows.shimcachemem.ShimcacheMem` 读取会话内条目」 |
| 系统**正常关机** | 用磁盘路线（3.1 节） | 「磁盘 ShimCache 反映至 `ShutdownTime`（`T0`）之前的状态」 |
| **系统硬断电** | 内存已丢 | 「`T0` 之后未落盘的条目已丢失，无法判断。本案未提供内存镜像，该时段不可恢复。」 |

```bash
# 运行中才有意义：先确认内核符号可用
vol -f /evidence/DigiForensics-mem.raw windows.info
vol -f /evidence/DigiForensics-mem.raw windows.shimcachemem.ShimcacheMem
vol -f /evidence/DigiForensics-mem.raw windows.amcache.Amcache
```

硬断电检材上的 ShimCache 分析，报告里必须有一段专门的局限说明，写明有效时间边界与不可恢复区间。

<a id="section-20"></a>

#### 陷阱 5：用 Win7 的 `Executed` 标志逻辑判断 Win10/11

**现象**

按 Win7 的分析思路，在 Win10 检材上寻找 `0x01 Executed` 标志位来区分「文件被枚举过」与「文件被执行过」，找不到该字段，报告写「ShimCache 数据不完整，解析失败」。

**原因**

**该标志位在 Windows 8 起被移除**：

| 系统版本 | 条目结构 | 能证明什么 |
| --- | --- | --- |
| **Windows 7 及以前** | 旧格式，条目中**有 `0x01` `Executed` 标志位** | 可区分「文件被枚举过」与「文件被执行过」 |
| **Windows 8 / 10 / 11** | 改为 AVL 树式新结构，**该标志位被移除** | **只能证明「系统尝试启动过该路径的程序」** |

所以在 Win8+ 上：

- 找 `Executed` 字段找不到是**正常**，不是数据不完整
- 所有条目在格式上**等价**，不存在「枚举」与「执行」的区分
- **不能证明执行成功** —— 启动即崩溃、缺 DLL 依赖同样会入表

解析器输出里的 `Executed` 列在 Win8+ 检材上会为空或统一取值，这属于格式决定的，不是解析问题。

**影响**

- 把正常的格式演进当成「数据不完整」，可能导致整个 ShimCache 分析被放弃
- 更严重的是，若在 Win10 检材上「按 Win7 逻辑」分析，可能会误用某些工具的默认判断，产出错误的「已执行/未执行」分类
- 「不能证明执行成功」这一边界若被忽略，报告会从「启动过」跳到「运行了」

**核查**

**先确认系统版本，再选判读标准**：

```bash
reged -x /evidence/hives/SOFTWARE.hive "Microsoft\Windows NT\CurrentVersion" | \
  grep -iE 'ProductName|CurrentBuild|DisplayVersion'
```

| 系统版本 | 判读标准 |
| --- | --- |
| Windows 7 及以前 | 可用 `Executed` 标志位区分枚举与执行 |
| **Windows 8 / 10 / 11** | 只表述「启动尝试」；`Executed` 列为空属正常格式 |

报告表述：

> 该检材为 Windows 10（`CurrentBuild` 19045）。ShimCache 采用 Windows 8 起的 AVL 树式条目结构，**无 `Executed` 标志位**。因此本报告对 ShimCache 条目的表述一律为「系统曾尝试启动过该路径下的程序」，**不据此推断执行成功与否**。执行结果需由事件日志 `4688`、Sysmon 事件 `1` 与文件落地痕迹佐证。

<a id="section-21"></a>

#### 陷阱 6：条目数少于预期就断言"被清理"

**现象**

ShimCache 解析出 512 条，而系统运行了两年，报告写「条目数量明显偏少，疑似攻击者清理过兼容性缓存」。

**原因**

ShimCache 有容量上限，满了之后新条目会挤掉最旧的。 这是设计行为，不是清理行为。条目数低于容量上限是常态。

与"被清理"需要区分的成因至少有四种：

| 成因 | 判别方法 |
| --- | --- |
| **容量上限挤出** | 条目数恰好接近上限值，且最旧的条目恰好是长期未运行的常见程序 |
| **正常关机前的自然状态** | 磁盘内容反映 `ShutdownTime` 之前，条目数正常 |
| **硬断电丢失未落盘部分** | `ShutdownTime` 与案发时段的关系 |
| **确实被清理** | 条目数**异常偏低**（远低于上限），且缺失集中于特定类别 |

**影响**

- 「被清理」是一个指向主动反取证行为的结论，需要额外证据支撑
- 若确系容量挤出却被写成"被清理"，会浪费大量时间去追查不存在的清理动作
- 反向风险：若确系清理却写成"容量挤出"，就漏掉了一个重要发现

**核查**

**先看条目数与容量上限的关系，再看缺失的分布**：

```bash
# 注册表值大小（反映实际占用）
rip.exe -p /evidence/hives/SYSTEM -a /tmp/ac.txt \
  "ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache"
# 输出的二进制值长度即缓存占用

# 统计条目数与最早/最新插入时间
python3 - <<'PY'
import csv, glob
f = glob.glob(r'C:\evidence\out\AppCompatCacheParser_*.csv')[0]
rows = list(csv.DictReader(open(f, encoding='utf-8', errors='replace')))
print('条目数', len(rows))
ins = sorted(r.get('InsertedTime','') for r in rows if r.get('InsertedTime'))
print('最早插入', ins[0] if ins else 'n/a')
print('最新插入', ins[-1] if ins else 'n/a')
PY
```

| 观察 | 结论 |
| --- | --- |
| 条目数接近上限，最旧条目为常见老程序 | **容量挤出，预期行为** |
| 条目数**远低于**上限 | 需排查清理或未落盘，**结合 `ShutdownTime` 判断** |
| 缺失集中在某一时间段插入的条目 | 疑似定向清理，值得深挖 |

报告必须写明依据：

> ShimCache 条目共 N 条，与注册表值占用 XXX 字节对照，接近该配置的容量上限，最旧条目为长期未运行的系统程序，符合容量挤出特征，未发现定向清理迹象。条目缺失不作为反取证行为的证据。

<a id="section-22"></a>

### 4.3 Amcache 字段语义与结论边界

<a id="section-23"></a>

#### 陷阱 7：把 Amcache 的 SHA-1 当全文件哈希

**现象**

Amcache 中某文件的 SHA-1 为 `8b1a9947c3e2f5d6a0b9c8d7e6f5a4b3c2d1e0f9`，在 VirusTotal 上查询无命中，报告写「该文件为未知程序，风险待评估」。

**原因**

Amcache 的 SHA-1 只覆盖文件的前 30 MB。 这带来两个方向的问题：

- **大文件不完整**：一个 200 MB 的安装包，只算了前 30 MB，与完整哈希完全不同。Virus Total 上按完整哈希检索自然无命中
- **理论上可碰撞**：只用前 30 MB 意味着不同文件可能有相同哈希值

反过来，小于 30 MB 的文件其 SHA-1 就是完整哈希，可以正常检索 —— 这一点经常被误认为"Amcache 的哈希总是不可信"。

**影响**

- 用不完整哈希做情报库检索，**必然无命中**，于是被写成"未知程序"或"恶意"（两种极端都危险）
- 「Virus Total 无命中」是常见的良性信号，被误读为可疑会冤枉正常程序
- 反过来若因为"哈希不完整所以不可信"就放弃检索，会漏掉真正的情报命中

**核查**

**按文件大小判断，并标注哈希覆盖范围**：

```bash
AmcacheParser.exe -f C:\evidence\hives\Amcache.hve --csv C:\evidence\out
# 输出含 File Size 与 SHA1 两列，先比大小
```

| `File Size` | SHA-1 覆盖 | 处置 |
| --- | --- | --- |
| **≤ 30 MB** | 完整文件 | 可直接用于情报库检索与比对 |
| **> 30 MB** | 仅前 30 MB | **需另算完整哈希**；报告标注「SHA-1 为前 30 MB 摘要」 |

报告写法：

> Amcache 记录 `File Size` = 3.2 MB，**小于 30 MB，该 SHA-1 为文件完整哈希**，可直接用于情报库检索。检索结果无命中。
>
> 另一文件 `File Size` = 187 MB，Amcache 记录的 SHA-1 仅覆盖前 30 MB，非完整哈希，情报库检索无命中不具结论意义。已对完整文件计算 SHA-256（`…`）并另行检索。

**标注范围是硬性要求** —— 不标注会让读者误以为那是完整哈希。

<a id="section-24"></a>

#### 陷阱 8：把 PE 编译时间当可信时间

**现象**

Amcache 显示某程序 `Compile Time` 为 `2019-03-11 02:14:55`，与该文件的 MFT `Modified` 完全一致，报告写「该程序编译于 2019 年，是老程序，判定无害」。

**原因**

PE 头的 `TimeDateStamp` 是编译工具可以任意指定的字段。 攻击者可以：

- 用工具把它设成任意时间（包括伪造的老时间）
- 用它**匹配目标文件的 `Modified`**，让两个"2019"看起来互相印证，制造"老文件"的假象
- 用它设成未来时间，让程序看起来更新

在上面的案例里，"Compile Time 与 MFT Modified 一致"恰恰是可疑信号而非佐证 —— 因为攻击者有意让它们一致。

真实编译时间需要内部信息佐证：

| 交叉来源 | 提供什么 |
| --- | --- |
| PDB 路径 | 常含构建机的项目路径与分支名，含时间语义 |
| 链接器版本资源 | `VS_VERSION_INFO` 中的编译器版本 |
| 节区布局与链接时间戳 | `.reloc` 节去重后含链接时间 |
| 文件内部版本资源 | 产品版本、构建号 |
| 签名时间 | 代码签名证书的签署时间 |

**影响**

- 把伪造的"老编译时间"当可信时间，会**直接放过真正的新投放恶意程序**
- 报告若写「编译于 2019 年，判定为老程序无害」，这个结论会在复核时被推翻
- 更糟的是这类"两个时间一致"看起来像双重印证，实质是同一伪造值的重复

**核查**

把 Compile Time 定位为"程序自称的编译时间"，并主动寻找内部佐证：

```bash
# PE 头时间戳与其内部信息一起看
python3 - <<'PY'
import pefile
pe = pefile.PE(r'C:\evidence\extracted\cleanup.exe')
ts = pe.FILE_HEADER.TimeDateStamp
import datetime
print('TimeDateStamp :', datetime.datetime.utcfromtimestamp(ts))
# 与 MFT Modified / Amcache Compile Time 对比，一致性本身是信号
for entry in pe.DIRECTORY_ENTRY_RESOURCE:
    print('resource dir', entry.name or entry.struct.Id)
PY
```

| 观察 | 判读 |
| --- | --- |
| `Compile Time` == MFT `Modified` | **可疑：可能是刻意对齐以制造"老文件"假象** |
| `Compile Time` 早于文件 `Created` 数小时至数天 | 正常（先编译后投放） |
| `Compile Time` 晚于 `Created` | 不合常理，需排查 |
| PDB 路径含其他主机名/分支 | 佐证构建来源 |

报告写法：

> Amcache 记录 `Compile Time` = 2019-03-11 02:14:55，该值为 PE 头 `TimeDateStamp`，可由编译工具任意指定。其与 MFT `Modified` **完全一致**，这一致性不构成相互印证，反而符合攻击者刻意对齐以伪装文件年龄的情形。程序内部 PDB 路径显示为 `Z:\build\release\cleanup\cleanup.pdb`，与 2019 年无关。本报告不将 Compile Time 作为时间证据。

<a id="section-25"></a>

#### 陷阱 9：在 Win7 检材上找 `Amcache.hve`

**现象**

按 `%SystemRoot%\AppCompat\Programs\Amcache.hve` 提取，在一台 Windows 7 机器上找不到该文件，报告写「该机无 Amcache 记录」。

**原因**

Amcache 是 Windows 8+ 才有的工件。 Windows 7 上的对应文件是：

```text
C:\Windows\AppCompat\Programs\RecentFileCache.bcf
```

两者是完全不同的文件、不同格式、不同工具。Win7 检材上找 `Amcache.hve` 找不到是**版本差异，不是工件缺失**。

**影响**

- 少一个独立执行证据源，三角验证退化为两者
- 在 Win7 案件中这条线完全断掉，而 Win7 在企业环境里仍有一定存量

**核查**

**先确认系统版本，再选对应工件**：

```bash
reged -x /evidence/hives/SOFTWARE.hive "Microsoft\Windows NT\CurrentVersion" | \
  grep -iE 'ProductName|CurrentBuild|DisplayVersion'

# 提取时两个路径都试
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -iE 'AppCompat/Programs/(Amcache\.hve|RecentFileCache\.bcf)$'
```

| 系统版本 | 工件 | 解析工具 |
| --- | --- | --- |
| **Windows 8 / 10 / 11** | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | `AmcacheParser` |
| **Windows 7** | `%SystemRoot%\AppCompat\Programs\RecentFileCache.bcf` | `RecentFileCache` 类工具 |

<a id="section-26"></a>

#### 陷阱 10：看到 ShimCache 条目就写"程序运行成功"

**现象**

ShimCache 中存在 `cleanup.exe` 的条目，报告结论写「该程序在 2024-11-15 21:58 被执行，完成清理操作」。

**原因**

两个方向的错误叠加：

**其一，条目只证明"启动尝试"**。Win8+ 已移除 `Executed` 标志位（见陷阱 5），所有条目在格式上等价。启动即崩溃、缺 DLL 依赖、架构不匹配、被杀、被拦，**都会一样入表**。

**其二，"完成了清理操作"是完全跨越的推论**。ShimCache 记录的是**路径**，不是行为。要证明"完成了清理操作"，需要的是目标文件消失、痕迹被删、后续 Prefetch 条目被清除等具体证据。

| 层次 | ShimCache 能否支撑 |
| --- | --- |
| 系统曾尝试启动该路径的程序 | **能** |
| 启动成功完成初始化 | **不能** |
| 程序执行了某项特定操作 | **不能** |
| 操作已完成、达成预期效果 | **不能** |

**影响**

- 报告的结论句里包含了工件完全无法支撑的内容，一旦被质证，整个结论都要重新论证
- 在"程序是否恶意"的定性上，ShimCache 提供**零信息** —— 它只是路径缓存
- 「完成了清理」这类断言如果成为结论，会掩盖真正的未解决问题

**核查**

**三档表述，逐层加证据**：

```bash
# 第一档：ShimCache 单独能给什么
# → 「系统曾尝试启动过该路径下的程序」

# 第二档：需要"执行成功"
grep -iE 'cleanup' /evidence/out/Prefetch_*.csv       # Prefetch 有记录
rip.exe -p /evidence/hives/SYSTEM -a /tmp/e.txt eventlog  # 事件日志 4688 / Sysmon 1

# 第三档：需要"执行了某项操作"
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'cleanup.*\.(log|txt|dat)$'
# 事件日志中该进程的写入、子进程、网络连接
```

报告标准表述：

> **ShimCache**：存在 `C:\Users\admin\AppData\Local\Temp\cleanup.exe` 的条目，`InsertedTime` 2024-11-15 21:58:02。该工件记录的是程序路径与文件修改时间，不含执行结果，不能证明执行成功。
>
> **Amcache**：`First Run Time` 2024-11-15 21:58:02，`Compile Time` 2024-11-15 21:44:12，`File Size` 3.2 MB（SHA-1 为完整哈希，情报库检索无命中）。
>
> **Prefetch**：存在对应 `.pf` 条目，`Run Count` 与执行时间可读。
>
> **综合**：「该可执行文件于 2024-11-15 21:58 被启动」可由 Amcache `First Run` 与 ShimCache `InsertedTime` 独立印证。「该程序运行成功并完成了 X 操作」**本次未确认** —— 需通过输出文件落地、子进程、网络连接或 DLP 告警补齐证据。程序性质需以哈希送情报库结果加行为证据综合判定，ShimCache 与 Amcache 均不含善恶判断信息。
<a id="section-27"></a>

## 五、案例示例

<a id="section-28"></a>

### 5.1 timestomp 伪造 Modified 时间导致执行时间误判

**场景**

查获一台 Windows 10 专业版台式机，委托方要求查明「2024-11-14 至 11-16 期间是否有人运行过可疑程序并尝试清理痕迹」。镜像 `DigiForensics.dd`（raw，500 GB，NTFS 起始扇区 2048）。**系统为强制断电状态。**

**处置过程**

第一步，提取工件并确认系统状态——这一步决定后续全部策略：

```bash
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select
# \Select\Current : 1
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime
# ControlSet001\Control\Windows\ShutdownTime : 2024-11-15 22:14:03
```

```text
最后正常关机 : 2024-11-15 22:14:03
异常关机     : 2024-11-16 03:22
```

第二步，解析 ShimCache 并逐字段核对时间语义：

```powershell
AppCompatCacheParser.exe -f C:\evidence\hives\SYSTEM --csv C:\evidence\out
```

| Path | ModifiedTime | InsertedTime |
| --- | --- | --- |
| `C:\Users\admin\AppData\Local\Temp\cleanup.exe` | **2019-03-11 02:14:55** | 2024-11-15 21:58:02 |
| `C:\Windows\System32\notepad.exe` | 2010-07-13 23:57:32 | 2024-11-15 09:12:44 |

第三步，与 MFT 时间戳对照，验证 `ModifiedTime` 的真实含义：

```bash
istat -o 2048 /work/DigiForensics.dd <inode>
```

```text
Modified: 2019-03-11 02:14:55     ← 与 ShimCache 完全一致
Created : 2024-11-15 21:57:30     ← 但文件是当天晚上才创建的
```

第四步，用 Python 判定时间关系的可能性：

```bash
python3 - <<'PY'
c = "2024-11-15 21:57:30"; m = "2019-03-11 02:14:55"; ins = "2024-11-15 21:58:02"
print("mTime 早于 cTime :", m < c, "  ← 时间逻辑上不可能自然产生")
print("mTime 距 InsertedTime:", (m[:4], ins[:4]), " 相差约 5.7 年")
print("若把 mTime 当执行时间 → 结论『5 年前运行过，与本案无关』")
PY
```

```text
mTime 早于 cTime : True  ← 时间逻辑上不可能自然产生
```

第五步，横向检查其它条目以确认不是解析器问题：

```bash
python3 - <<'PY'
rows = [("notepad.exe", "2010-07-13 23:57:32", "2024-11-15 09:12:44"),
        ("cleanup.exe", "2019-03-11 02:14:55", "2024-11-15 21:58:02")]
for n, m, i in rows:
    print(f"{n:14s} mTime={m}  Inserted={i}  mTime<Inserted: {m < i}")
print("→ notepad.exe 的 mTime(2010) 早于 Inserted(2024-15) 是正常的（软件本就老）")
print("→ 关键差异：cleanup.exe 的 mTime 与 cTime(21:57:30) 倒挂，属异常")
PY
```

**结论**

`ShutdownTime = 2024-11-15 22:14:03`、异常关机 2024-11-16 03:22，磁盘 ShimCache 只反映 11-15 22:14 之前的状态，委托方询问的 22:14 至次日 03:22 时段任何 ShimCache 缺失都是技术必然，本案未提供内存镜像，该时段无法恢复，此为必须明示的证据局限。`cleanup.exe` 的 `ModifiedTime = 2019-03-11 02:14:55` 与 MFT `$SI$mTime` 完全一致，证实该字段即文件修改时间；而该文件 `Created = 2024-11-15 21:57:30`，`mTime` 早于 `cTime` 达 5.7 年，时间逻辑上不可能自然产生，**判定为 timestomp 伪造**。横向对照可见 `notepad.exe` 的 `mTime`（2010）早于其 `Inserted` 属正常，但与 `cTime` 不存在倒挂，二者可区分。`InsertedTime = 2024-11-15 21:58:02` 才是系统登记该程序启动的时间。

**误判对照**

本案例影响较大的错误结论是「`cleanup.exe` 的 `ModifiedTime` 是 2019 年，说明它是 2019 年的老程序，与本案无关」。

正确判据是 ShimCache 的 `ModifiedTime` 取自文件的 MFT `$SI$mTime`，即**文件内容最后被写入**的时间，该字段可被任意程序通过 `SetFileTime()` 显式设置；而程序实际运行的时间对应的是 `InsertedTime`（系统登记它启动的时刻）。

两者语义完全不同且可被分离篡改。

按错误判据处理，本案最关键的可疑程序会被以「2019 年的老文件」为由排除——而恰恰是这个 mTime 倒挂，构成了 timestomp 的直接证据。

第二处易错点是把 `InsertedTime` 也当成「运行时间」并声称它精确到秒。

正确判据是 `InsertedTime` 是系统**首次把该路径登记进 ShimCache** 的时刻，登记后条目常驻内存并长期保留（至多 1024 条，按最近使用淘汰），后续每次运行**不会刷新该字段**。

本案 `cleanup.exe` 在 22:12:37 与次日 02:41:03、02:58:41 还有三次执行（Prefetch 可见），但 ShimCache 的 `InsertedTime` 始终停在 21:58:02。

按错误判据把 `InsertedTime` 当运行时间，会得出「该程序只运行过一次」的结论，与 Prefetch 的 4 次执行记录直接冲突。

第三处易错点是看到 mTime 倒挂就断定「文件系统被整体篡改」。

正确判据是 timestomp 通常是**逐文件、逐字段**的定向操作，由投递工具只针对自身及其载荷设置时间；判定应建立在单个文件的 `mTime < cTime` 倒挂、并且该文件位于 Temp 等投放目录这一组合上。

本案 `notepad.exe` 等系统程序的 mTime 保持真实，说明篡改是有选择的。

按错误判据扩大为「整盘时间被篡改」，会引发对全部时间线的无端怀疑，也低估了对手的处置水平。

<a id="section-29"></a>

### 5.2 Amcache First Run 与 ShimCache InsertedTime 秒级互证

**场景**

承接上一步，已确定 `cleanup.exe` 存在时间戳伪造。需要确定「真实执行时间」并解决 Amcache 与 ShimCache、Prefetch 之间的时间关系问题。

**处置过程**

第一步，提取并解析 Amcache：

```bash
mkdir -p /evidence/hives
icat -o 2048 /work/DigiForensics.dd <Amcache.hve MFT entry> > /evidence/hives/Amcache.hve
AmcacheParser.exe -f C:\evidence\hives\Amcache.hve --csv C:\evidence\out
```

```text
SHA1         : 8b1a9947c3e2f5d6a0b9c8d7e6f5a4b3c2d1e0f9
Path         : C:\Users\admin\AppData\Local\Temp\cleanup.exe
Compile Time : 2024-11-15 21:44:12
First Run    : 2024-11-15 21:58:02
```

第二步，把五处时间按语义与先后排成一张表：

```bash
python3 - <<'PY'
rows = [
 ("2024-11-15 21:44:12", "Amcache Compile Time", "程序编译（编译者机器的时间）"),
 ("2024-11-15 21:57:30", "MFT Created",         "文件落地到本机"),
 ("2024-11-15 21:58:02", "Amcache First Run",   "首次运行"),
 ("2024-11-15 21:58:02", "ShimCache Inserted",  "系统登记启动"),
 ("2019-03-11 02:14:55", "ShimCache Modified",  "假时间（被 timestomp）"),
]
for t, src, note in sorted(rows):
    print(f"{t}  {src:22s} {note}")
PY
```

第三步，做时序合理性校验：

```bash
python3 - <<'PY'
c, comp, first = "21:57:30", "21:44:12", "21:58:02"
def s(t):
    h, m, x = map(int, t.split(":")); return h*3600+m*60+x
print("Compile → Created :", s(c)-s(comp), "秒  编译早于落地，合理")
print("Created → FirstRun:", s(first)-s(c), "秒  落地后 32 秒首启，合理")
PY
```

```text
Compile → Created : 798 秒  编译早于落地，合理
Created → FirstRun: 32 秒  落地后 32 秒首启，合理
```

第四步，与 Prefetch 的多次执行对照，解释 Amcache 的字段语义：

```bash
python3 - <<'PY'
print("Amcache First Run = 2024-11-15 21:58:02  ← 仅记录首次，后续运行不更新")
print("Prefetch 时间槽  : 21:58:02 / 22:12:37 / 02:41:03 / 02:58:41")
print("→ Amcache 与 ShimCache 都只有『首次』语义，Prefetch 才有全部 4 次")
PY
```

第五步，用 SHA-1 关联文件本体，闭合身份链：

```bash
icat -o 2048 /work/DigiForensics.dd <cleanup.exe MFT entry> > /evidence/cleanup.exe
md5 /evidence/cleanup.exe; sha1sum /evidence/cleanup.exe; sha256sum /evidence/cleanup.exe
```

```text
SHA1 = 8b1a9947c3e2f5d6a0b9c8d7e6f5a4b3c2d1e0f9   ← 与 Amcache 记录完全一致
```

**结论**

Amcache 记录的 `Compile Time = 2024-11-15 21:44:12`、`First Run Time = 2024-11-15 21:58:02`。五处时间按时序排列为：编译 21:44:12 → 文件落地 21:57:30（编译后 798 秒）→ 首次运行 21:58:02（落地后 32 秒）→ ShimCache 登记 21:58:02 → `Modified` 假时间 2019 年。

Amcache `First Run Time` 与 ShimCache `InsertedTime` 精确到秒完全一致，两个完全独立的工件互证，2024-11-15 21:58:02 是经双源确认的真实执行时间。 提取的文件本体 SHA-1 为 `8b1a9947c3e2f5d6a0b9c8d7e6f5a4b3c2d1e0f9`，与 Amcache 记录完全一致，身份链闭合，可交情报库定性。

需明确 Amcache 与 ShimCache 均只有「首次」语义，无法反映 22:12:37 与次日 02:41:03、02:58:41 的后续三次执行。

**误判对照**

最容易出现的错误是拿 ShimCache 的 `InsertedTime` 与 Prefetch 的时间槽做「一致性核对」，发现不一致就判定某个工件被篡改。

正确判据是这两个字段语义本就不同：`InsertedTime` 是首次登记、终身不刷新，而 Prefetch 的时间槽逐次记录每次执行。

本案 `InsertedTime = 21:58:02` 与 Prefetch 首槽 21:58:02 一致、后续三槽不同，恰恰是**两者都正常工作**的表现。

按错误判据把这种正常差异判为篡改，会凭空产生一条「有人修改了 ShimCache 或 Prefetch」的结论，而实际取证动作毫无异常。

第二处易错点是把 Amcache 的 `Compile Time` 当成程序在本机的运行时间。

正确判据是 PE 头部的 `TimeDateStamp` 记录的是**编译者机器上的编译时刻**，其时钟、时区都由编译环境决定，与本案主机的时间无关。

本案 `Compile Time = 2024-11-15 21:44:12` 早于文件落地 21:57:30 仅 798 秒，说明编译者机器与本案主机时钟基本同步，这是巧合性的一致而非因果关系。

按错误判据把编译时间当运行时间，在攻击者跨时区编译、或编译后长时间才投放的场景下会产生数小时甚至数天的偏差，直接打乱整个时间线。

第三处易错点是把 `First Run` 写成「最后运行时间」并据此描述行为频次。

正确判据是该字段在程序首次执行时被写入，之后无论运行多少次都不再变化。

本案 Prefetch 明确记录了 4 次执行（21:58:02、22:12:37、02:41:03、02:58:41），其中后三次发生在正常关机之后，属于强制断电导致 ShimCache 未落盘的时间窗。

按错误判据写成「只在 21:58:02 运行过 1 次」，会把三次关键执行——尤其是断电前两小时内的那两次——从行为链中删除，而它们恰恰是委托方询问的时间窗。

<a id="section-30"></a>

### 5.3 Prefetch 四次与 ShimCache 一条的矛盾解释

**场景**

委托方审阅时提出直接质疑：「Prefetch 说运行了 4 次，ShimCache 只有 1 条记录，这两者互相矛盾，是不是有一条数据不可信？」需要给出机制层面的解释，而不是含糊带过。

**处置过程**

第一步，把 Prefetch 的 4 个时间槽与系统事件按时间排列：

```bash
python3 - <<'PY'
ev = [
 ("2024-11-15 21:58:02", "Prefetch 槽1 + ShimCache 登记", "执行 → 新增 ShimCache 条目"),
 ("2024-11-15 22:12:37", "Prefetch 槽2", "执行 → 同一路径已在内存，不新增"),
 ("2024-11-15 22:14:03", "ShutdownTime", "正常关机 → ShimCache 刷盘"),
 ("2024-11-16 02:41:03", "Prefetch 槽3", "执行 → ShimCache 在内存中更新"),
 ("2024-11-16 02:58:41", "Prefetch 槽4", "执行 → 同上"),
 ("2024-11-16 03:22:41", "异常关机", "内存丢失 → 未落盘的登记永久丢失"),
]
for t, src, note in ev:
    print(f"{t}  {src:26s} {note}")
PY
```

第二步，验证「只有 1 条」确实符合刷盘时点：

```bash
python3 - <<'PY'
print("关机 22:14:03 时，内存中的 ShimCache 只有 cleanup.exe 一条本机 Temp 程序")
print("→ 刷盘后磁盘上即为 1 条，与观测一致")
print("→ 若为 3 条或更多，反而说明关机遇理异常或存在其它登记")
PY
```

第三步，验证 Prefetch 自身在断电后仍保有 4 条的原因：

```bash
python3 - <<'PY'
print("Prefetch：每次执行即写 .pf 文件（延迟数秒落盘），不依赖关机")
print("→ 02:58:41 的第 4 次执行在 03:22 断电前已写入磁盘")
print("→ ShimCache：仅在关机/注销时批量刷盘，不依赖单次执行")
print("两者落盘机制不同 → 计数不一致是必然，不是矛盾")
PY
```

第四步，做「若正常关机」的假设推演，验证机制解释的自洽性：

```bash
python3 - <<'PY'
print("假设 A（本案，实际）  : 03:22 硬断电 → ShimCache 停留在 22:14 的 1 条")
print("假设 B（若 03:22 正常关机）: ShimCache 应包含全部 4 条登记 → 磁盘上 4 条")
print("实际观测 1 条 → 与假设 A 一致、与假设 B 矛盾 → 异常关机得到反证")
print("★ 断电事实由 ShutdownTime(22:14:03) + 断电时间(03:22) 双重佐证")
PY
```

第五步，把这条矛盾写入报告时的正确表述：

```bash
python3 - <<'PY'
txt = ("Prefetch 记录 4 次执行，ShimCache 仅 1 条登记。二者不矛盾："
       "Prefetch 逐次即时落盘，ShimCache 于 2024-11-15 22:14:03 正常关机时刷盘，"
       "其后两次执行（02:41:03、02:58:41）因 03:22 强制断电未能落盘。"
       "该差异本身即为异常断电的佐证。")
print(txt)
PY
```

**结论**

「Prefetch 4 次 vs ShimCache 1 条」**不是数据造假或解析错误，而是落盘机制的必然结果**：Prefetch 在每次执行后延迟数秒即写入对应 `.pf` 文件，不依赖关机，因此断电前的第 4 次执行（02:58:41）仍完整保留；ShimCache 常驻内存，仅在 2024-11-15 22:14:03 正常关机时批量刷盘，其后 02:41:03 与 02:58:41 两次执行带来的登记随 03:22 强制断电永久丢失。假设推演进一步反证：若 03:22 为正常关机，ShimCache 应含 4 条，实际仅 1 条，与正常关机假设矛盾而与断电假设一致。断电事实由 `ShutdownTime`（22:14:03）与异常关机时间（03:22）双重佐证。报告应把该差异作为**独立佐证**写入，而非回避或含糊表述。

**误判对照**

本案例的核心误判是把两个工件的计数差异当作「其中一个被篡改」，从而选择相信其中一个、丢弃另一个。

正确判据是 Prefetch 与 ShimCache 的写入时机、落盘策略、失效模式三者都不同，计数本来就不应相等——要求它们一致本身就误解了这两个工件的定位。

按错误判据选择丢弃 ShimCache（因为只有 1 条、显得信息量不足），会同时丢掉 `ModifiedTime` 这个 timestomp 的直接证据；而丢弃 Prefetch 则会丢掉 4 次执行的事实。

正确做法是先解释机制、再判断哪个工件的结论可用。

第二处易错点是反过来把这条差异当作「断电的证据」直接写进报告而不给出机制解释。

正确判据是差异本身有多重成因——除了断电，还可能是 ShimCache 的 1024 条容量上限导致条目被淘汰、注册表 `EnablePrefetcher=0` 或兼容性设置使登记未生成、以及程序路径在登记时为长路径而后续转为短路径造成不匹配。

必须逐条排除后才能归因于断电。

按错误判据直接归因，一旦对方提供「该机曾触发 Prefetch 容量上限」或「存在策略禁用」的说明，这条佐证就会失效，并连带削弱报告中所有基于 ShimCache 的结论。

第三处易错点是把「Prefetch 有 4 次执行」直接写成「程序运行了 4 次并完成其行为」。正确判据是 Prefetch 记录的是映像加载，启动后可能因缺依赖立即失败、被安全软件拦截、或在用户态逻辑执行前就被终止；四次执行的时间跨度长达 5 小时（21:58 至次日 02:58），且全部发生在非工作时间，本身就是需要解释的异常模式。按错误判据写成「恶意程序运行 4 次并完成数据外泄」，把执行记录直接等同于效果达成，在需要证明实际影响的场景下无法支撑。

---
<a id="section-31"></a>

## 六、扩展阅读方向

<a id="section-32"></a>

### 前置基础：读懂这两个工件的前提

- [注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md) —— hive 提取与路径解析。「离线必须用 `ControlSet001`」这条规则是本领域最高频的坑，方法在这一篇。
- [Prefetch 深度解析](computer-execution-prefetch.md) —— **三角验证里的第一顺位**。本篇的可信度对比表以那篇的结论为参照，**两篇必须对着读。**
- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— `$STANDARD_INFORMATION` 的字段语义。ShimCache 时间戳的真实含义就是这个字段的值，不懂它就一定会误读。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— Amcache 作为独立文件的接入前提。

<a id="section-33"></a>

### 同层深入：三角验证的第三个成员

- [LNK 快捷方式与 Jump List 跳转列表](computer-execution-lnk-jumplist.md) —— **同组的第四个执行侧工件**，且它自带用户目录归属，能补上 ShimCache 与 Amcache 都没有的主体信息。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— **它的 `UserId` 字段能把执行落到具体用户**，这是本篇两个工件都做不到的。
- [事件日志深度分析](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 登录与进程创建事件，**带用户名的执行记录来源**。

<a id="section-34"></a>

### 相邻议题：内存侧与时间线

- [内存取证总览](../../memory/memory-acquire/memory-acquire-memory-forensics-overview.md) —— 从内存读 ShimCache 是本篇 3.3 的方法来源；内存里的版本不受「未落盘」限制。
- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— 内存侧的进程证据，**与磁盘侧执行记录互补**。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— ShimCache 时间戳（文件 mtime）可以被 `touch` 改，而它的存在本身改不到，这个不对称正是本篇陷阱一的辨析基础。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) —— Amcache 的 SHA-1 只覆盖前 30 MB，**「文件是否被替换过」需要另找完整样本做比对**，这是该篇能补上的能力。

<a id="section-35"></a>

### 工具与规范：现场状态决定处置

- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— **「系统运行中」这一状态下应先做内存采集再关机**，处置决策在这一篇。
- [内存采集方法](../../memory/memory-acquire/memory-acquire-memory-acquisition-methods.md) —— 采集方法的具体实现。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 解析结果的归档格式。

<a id="section-36"></a>

### 判据与反例：哪些缺失不能当成阴性结论

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **本篇 4.3 的结论表述纪律来源**：「因断电未落盘」与「未执行」必须写成两句不同的话。
- [取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— **系统状态（正常关机 / 硬断电）本身的记录与判定**，这决定了本篇的结论能写到多强。
<a id="section-37"></a>

## 七、命令速查

```bash
# ===== 提取工件（-o 偏移按实际 mmls 结果替换）=====
mkdir -p /evidence/hives
for h in SYSTEM Amcache.hve; do
  fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE "config/SYSTEM$|AppCompat/Programs/$h$" \
    | grep -E '^r/r' | awk '{print $2}' | head -1 \
    | while read -r ino; do icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/hives/$h"; done
  printf '%s: ' "$h"; xxd -l 4 -p "/evidence/hives/$h"       # 期望 72656766（regf）
done
rip.exe -p /evidence/hives/SYSTEM -a /tmp/select.txt select   # ★ 确认控制集编号
rip.exe -p /evidence/hives/SYSTEM -a /tmp/sd.txt shutdowntime  # ★ 最后正常关机时间

# ===== 解析 =====
AppCompatCacheParser.exe -f C:\evidence\hives\SYSTEM --csv C:\evidence\out
AmcacheParser.exe -f C:\evidence\hives\Amcache.hve --csv C:\evidence\out
PECmd.exe -d C:\evidence\Prefetch --csv C:\evidence\out

# ===== 核对 ShimCache 时间语义（防 timestomp 误判）=====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i 'target.exe'   # 找 inode
istat -o 2048 /work/DigiForensics.dd <inode>                      # 看 MFT 四时间
# ShimCache 的 ModifiedTime 应等于 MFT 的 Modified —— 不等即 timestomp 迹象
```

```powershell
# ===== 从内存读 ShimCache（运行中 / 断电前的机器）=====
vol -f C:\evidence\DigiForensics-mem.raw windows.shimcachemem.ShimcacheMem
vol -f C:\evidence\DigiForensics-mem.raw windows.info               # 先确认符号可用
vol -f C:\evidence\DigiForensics-mem.raw windows.amcache.Amcache

# ===== 查异常关机（6008）与执行参数（4688，需已开启审计）=====
Get-WinEvent -Path C:\evidence\System.evtx -FilterHashtable @{Id=6008} | Select-Object TimeCreated
Get-WinEvent -Path C:\evidence\Security.evtx -FilterHashtable @{Id=4688} |
  ForEach-Object {
    [xml]$x=$_.ToXml(); $d=@{}; $x.Event.EventData.Data | %{ $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; Proc=$d['NewProcessName']; Cmd=$d['CommandLine'] }
  } | Where-Object { $_.Proc -match 'target' }
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — ShimCache 与 Amcache」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《ShimCache 与 Amcache》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
