---
title: "Linux 时间线重建"
slug: "computer-log-linux-timeline-reconstruction"
canonical: "https://www.digiforensics.cn/wiki/computer-log-linux-timeline-reconstruction"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["日志分析"]
---

# Linux 时间线重建

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-log-linux-timeline-reconstruction)

<a id="section-1"></a>

## 一、概述

Windows 侧做时间线有个便利：事件日志带年份、带时区、精度到毫秒，还集中在少数几个文件里。导出即完整时间线。

Linux 没有这个便利。时间证据散落在八个互不相干的源里，各有各的精度，也各有各的缺陷：

| 数据源 | 年份 | 精度 | 已知缺陷 |
|---|---|---|---|
| 文件 `mtime` / `ctime` / `crtime` | ✅ | 纳秒（ext4） | `crtime` 仅 ext3+ 有 |
| 文件 `atime` | ✅ | 纳秒 | **取决于挂载选项，可能不可信** |
| `auth.log` / `syslog` | ❌ **无年份** | 秒 | 格式五花八门 |
| `journalctl` | ✅ | 微秒 + 时区 | **可能只存在于内存，断电即失** |
| `wtmp` / `bash_history` | ✅ | 秒 | **二进制；仅正常退出时落盘** |
| 审计日志 `audit.log` | ✅ | 秒 | **未启用则无；且是二进制** |

没有任何一个文件能给出完整时间线。必须把多个源对齐、互相补足，而对齐的前提是**统一时间基准**。

这一层处在**分析环节的综合阶段**，在 Linux 线路上是收口位置：前面的结构解析、日志分析、工件清点都只产出**时间戳**，合并成一条可读的事件序列是这一步独有的工作。它同时是两个方向的交汇点：

- **横向汇聚** —— 文件系统时间戳、系统日志、登录记录、审计记录、包管理器账本，五类源各自独立，**没有第二处做同样的事**
- **纵向支撑** —— 下游的行为认定（登录之后做了什么、持久化何时建立）依赖这条时间线；**时间线错了，行为认定全错**

上游是 [系统日志深度分析](computer-log-system-log-analysis.md) 的日志导出与 [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) 的时间戳提取，字段语义在两篇里已有，这里不重复 inode 布局与日志路径。

具体落到可用的字段上，有这么几类。

- **四个文件时间戳** —— `atime`（访问）、`mtime`（内容修改）、`ctime`（inode 变更）、`crtime`（创建，仅 ext3+）。**四个字段语义各不相同，误用会造出不存在的事件**
- **`ctime` 的特殊地位** —— 它在**改权限、改属主、改链接数时都会更新**。"`ctime` 晚于 `mtime` 21 秒"是"SUID 位被单独赋予"的判据，而不是"内容被改过"
- **`crtime` 与 `mtime` 的差值** —— `crtime` 老而 `mtime` 新 = **篡改已有文件**；两者接近 = **新建文件**。第五章案例里 `authorized_keys` 正是靠这一点被判定为"追加公钥"
- **`atime` 与挂载选项** —— `relatime`（只在 atime 比 mtime/ctime 旧 24 小时以上才更新）、`noatime`（完全不更新）、`atime`（每次都更新）。现代发行版的默认值是 `relatime` 而非 `atime`，所以 `atime` 通常只能作弱证据（判读见 2.4 与 4.1）
- **`/etc/fstab`** —— **挂载选项的书面证据**。`atime` 类结论的强度完全取决于能不能引到这一行
- **时区标识** —— `/etc/timezone`、`/etc/localtime` 符号链接目标、日志里的 `UTC` / `CST` 标记。"CST" 在英文语境下可指中国标准时间也可指北美中部时间，混淆会让整条时间线偏移 13 或 14 小时
- **纳秒与微秒字段** —— ext4 `crtime` 尾部的纳秒值、journal 的微秒精度。**精度差异是判断两个事件是否同时发生的基础**
- `bash_history` 的 `#<epoch>` 注释行 —— **bash 自己记录的秒级 epoch**，不依赖日志格式，是 `auth.log` 之外的独立时间源
- `stat` 与 `find -printf` 的批量输出 —— 提取手段。注意挂载点上的 `stat` 会触发 atime 更新（取决于挂载选项），所以必须在只读挂载上做
- **各源的收敛产物** —— 统一时区、统一格式、带"支撑源数量"标记的合并时间线

这套东西答得出来的是：某段时间内这台机器上发生过什么、按什么顺序、每个结论有几个独立源支撑、**以及哪些时段完全没有记录**。

答不出来的，同样得说清：

- **"某人在某天读了某文件"** —— `relatime` / `noatime` 下 `atime` 不随读更新，**这个推论在默认配置下不成立**。要读文件访问记录要走审计日志
- **命令的完整执行内容** —— `bash_history` 只在正常退出时落盘，强制断电或 `HISTFILE=/dev/null` 会让历史归零。第五章案例里攻击者就做了后者
- **跨时区/跨系统的绝对一致** —— NTP 跳变、手动改系统时间都会造成偏移，**NTP 调整记录本身是另一个证据源**
- **"没有事件"** —— 必须写成"**各源均无记录**"。日志缺失、审计未启用、会话被强杀都可能导致空窗，**空窗是证据缺口不是阴性结论**
- **sub-second 级的事件先后** —— 只有 journal 与 ext4 `crtime` 有亚秒精度，**多数源只能给到秒**。秒内顺序无法判定时必须说明
- **攻击者身份** —— 时间线给的是顺序与时间，**归属要靠账户、认证方式、命令内容**

前提有三样，缺一不可：已读 [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md)，四个时间戳的字段位置与语义在那里；已读 [系统日志深度分析](computer-log-system-log-analysis.md)，知道各日志源在哪、精度如何、哪些可能缺失；会处理时区与 epoch 换算（见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)）。时区一项最容易出错：搞错时整条时间线依然"看起来合理"，只是全部偏移了几小时；所有合并操作都建立在"时间已经归一到同一基准"这个前提上，前提错了后面全白做。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Linux 时间线的数据源矩阵

| 数据源 | 精度 | 有年份 | 有时区 | 可信度 | 清理难度 |
|---|---|---|---|---|---|
| **`auth.log` / `secure`** | 秒 | **❌ 无** | ❌ 本地时间 | 高（除非被清） | ★★★ |
| `journalctl`（持久化 journal） | **微秒** | ✅ | ✅ | 高 | ★★★ |
| **journal（仅内存 `/run`）** | 微秒 | ✅ | ✅ | **断电即全失** | — |
| **`utmp`（当前会话）** | 秒 | ✅ | — | **仅运行中有效** | 重启清空 |
| **`wtmp`（成功登录）** | 秒 | ✅ | ❌ | 高 | ★★ |
| **`btmp`（失败登录）** | 秒 | ✅ | ❌ | 高 | ★★ |
| `bash_history` 的 `#epoch` | 秒 | ✅（epoch） | ✅（UTC） | **仅当设了 `HISTTIMEFORMAT`** | ★ |
| **`.zsh_history`** | 秒 | ✅ | ✅ | 高（默认带[时间戳](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)） | ★ |
| **`apt/history.log`** | 秒 | ✅ | ✅（标注时区） | 高 | ★★ |
| **文件 `mtime` / `crtime`** | **纳秒**（ext4） | ✅ | ❌ | **高** | ★★★★ |
| **文件 `atime`** | 纳秒 | ✅ | ❌ | **⚠️ 低（见 2.4）** | ★★★★ |
| **文件 `ctime`** | 纳秒 | ✅ | ❌ | 中（易误解） | ★★★★ |
| **`lastlog`** | 秒 | ✅ | ❌ | 高 | ★★ |
| **`/proc` 在线快照** | 秒（采集时刻） | ✅ | ✅ | 高（**但仅在采集时刻**） | 进程退出即失 |

> **读表要点**：**没有任何单一源是完整的**。`auth.log` 最全但无年份；`journal` 有年份但可能只在内存；文件时间戳精度最高但只覆盖文件操作。**必须组合，且每个源都要标注其缺陷。**

<a id="section-4"></a>

### 2.2 四个时间戳的精确语义

| 时间戳 | 精确含义 | **什么时候变** | **什么时候不变** |
|---|---|---|---|
| **`atime`** | 最后一次**读取/访问** | 文件数据被 `read()` 打开并读取时（**受挂载选项影响**） | 纯 `stat` 不一定改（取决于挂载选项） |
| **`mtime`** | 最后一次**内容修改**（数据写入） | 文件**数据**被写时 | 改权限、改属主时**不变** |
| **`ctime`** | 最后一次 **inode 元数据变更** | `chmod`/`chown`/`chmod`/`ln`（改链接数）/`mtime` 变化时 | 纯读操作**不变** |
| **`crtime`** | **文件创建时间**（ext4 特有） | 文件被创建时（`creat`/`open`+`O_CREAT`/在 `O_EXCL` 下新建） | **此后永不改变** |

**必须牢记的三条**：

**① `ctime` 不是创建时间。**

它是"元数据变更时间"。`chmod 4755 /tmp/x` 会更新 `ctime` 但**不更新 `mtime`**。**这个差异是识别"改权限不改内容"的判据**（见[第 01 篇](../computer-persistence/computer-persistence-persistence-artifact-map.md)的案例）。

真正的创建时间是 **`crtime`**（ext4）。

**② `mtime` 不变不代表内容没被改。**

可以只改 `atime`（`touch -a`）而不动 `mtime`。所以 `mtime` 早于某个"应该写文件"的事件时，要考虑 `touch` 伪造。

检查 `ctime` 是否比 `mtime` 新很多——若是，说明有 `touch` 操作。

**③ 复制文件会重置时间戳。**

`cp`（不带 `-p`）会把新文件的 `atime`/`mtime` 设为**当前时间**，`crtime` 也为当前时间。所以**"某文件的 crtime = 拷贝时刻"**。

`cp -p` 保留 `mtime` 但 **`crtime` 仍为拷贝时刻**。

`crtime` 因此可以揭示"这个文件是从别处拷来的"。

<a id="section-5"></a>

### 2.3 ext4 的 `crtime` 与亚秒精度

ext4 在 extra inode 里加了 `i_crtime`（0x90）和 `i_crtime_extra`（0x94），同时 `i_atime`/`i_mtime`/`i_ctime` 各有 `_extra` 字段存**纳秒的高位**。

两点取证价值：

1. `crtime` 是 ext4 独有的"真创建时间"。ext2/ext3 **没有这个字段**（此时 `stat` 只显示三个时间）。
2. **亚秒精度**：`istat` 输出中若出现 `... nano second resolution` 行，说明是 ext4。秒级无法区分"同一秒内批量创建的文件"，纳秒级可以给出先后顺序——对脚本批量落地文件的场景（恶意软件复制自身、解压释放载荷），**纳秒顺序是"先创建谁"的强证据**。

> ⚠️ **`crtime` 在文件被移动/重命名时不变**（`mv` 改的是目录项）。所以"`crtime` 很老但路径很深"可能只是被移动过，**不能仅凭 `crtime` 早就说"文件很老"**。

<a id="section-6"></a>

### 2.4 ★ `relatime` / `noatime`：atime 可信度的决定因素

早期 Linux 每次读文件都更新 atime（`atime` 行为），后来因为性能问题引入了优化挂载选项：

| 挂载选项 | atime 更新规则 | 对取证的影响 |
|---|---|---|
| **默认（无选项）** | 每次读都更新 | atime 可用（但性能差，现代系统少用） |
| **`relatime`** | 仅当 atime 比 mtime/ctime 都早 24 小时以上才更新 | atime **大致可用**但"最后读取时间"会被钝化（一天粒度） |
| **`noatime`** | **完全不更新** | **atime 完全不可用**（Ubuntu 服务器常见） |
| `strictatime` | 每次读都更新（等价于默认，但显式） | atime 可用 |

**如何确认本机用的是哪种**：

```bash
# 离线：从 /etc/fstab 判断
grep -E '^\S+\s+/\s+' /mnt/df/etc/fstab
# /dev/sda1 / ext4 defaults 0 1          ← 用默认（现代 Debian/Ubuntu 的默认其实是 relatime 隐含）
# /dev/sda1 / ext4 noatime 0 1           ← noatime，atime 完全不可用

# 在线：/proc/mounts 会显示实际生效的选项
grep ' / ' /proc/mounts
# /dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0     ← relatime

# 另可查 systemd 挂载选项 / fstab 生成来源
```

**取证结论的措辞必须相应调整**：

| 情况 | 能得出的结论 | **不能**得出的结论 |
|---|---|---|
| `noatime` | "atime 是**创建或最后修改时**的遗留值，**不代表任何读取行为**" | ❌ "文件从 X 到 Y 期间没被读过" |
| `relatime` | "atime 大致是最后读取时间的**上界**（可能钝化到天）" | ❌ 精确到秒的"最后读取时刻" |
| 默认/strictatime | "atime = 最后读取时间" | 仍需注意读取本身也可能被证据保全动作改变 |

> 除非明确确认是 `strictatime`/默认挂载，否则 `atime` 只能作为弱证据（"不早于某时刻"），不能作为"某人在某时读过"的证明。报告里应写明本机挂载选项，让读者自行判断 atime 证据强度。

<a id="section-7"></a>

### 2.5 时区统一：跨源对齐的前提

不同源的时间基准不同，对齐前必须统一。**统一流程**分三步。

**第 1 步：确定本机时区**

```bash
cat /mnt/df/etc/timezone                              # → Asia/Shanghai（文件内容）
ls -l /mnt/df/etc/localtime                           # → 软链到 /usr/share/zoneinfo/Asia/Shanghai
# zoneinfo 路径才是权威（timezone 文件可能缺失或过时）
# 若 localtime 是普通文件（不是软链），用 zdump 或对照 /usr/share/zoneinfo 的内容判断
```

**第 2 步：把各源归类**

| 源类型 | 基准 | 处理方式 |
|---|---|---|
| 文件时间戳（`stat`） | **本机本地时间，无时区标记** | 按本机时区转 UTC |
| `auth.log`（无年份） | 本地时间 | 补年份 + 转 UTC（年份靠 journal 或归档推断） |
| `journalctl -o short-precise` | **带时区偏移** | 直接按偏移转 UTC（最省事） |
| `apt/history.log` | 本地时间 + 时区缩写 | 按缩写 + `/etc/timezone` 确认后转 UTC |
| `bash_history` `#epoch` | **UTC（epoch 本身无时区）** | 直接是 UTC，无需转换 ★ |
| `wtmp`/`btmp`（`last` 输出） | 本地时间 | 按本机时区转 UTC |

第 3 步：转换（统一到 UTC 或统一到本地，选一种并全表一致）

```bash
# ★ 正确做法：先让 date 按「源时区」解释输入，再按 UTC 输出
TZ=Asia/Shanghai date -d '2024-03-17 22:47:33' '+%Y-%m-%dT%H:%M:%SZ'
# 2024-03-17T14:47:33Z          ← 本地 22:47:33 (UTC+8) → UTC 14:47:33 ✓

# 源本来就是 UTC 时（如 journal 的 ISO 行、bash_history 的 #epoch）
TZ=UTC date -d '2024-03-17T14:47:33+08:00' '+%Y-%m-%dT%H:%M:%SZ'
# 2024-03-17T06:47:33Z
TZ=UTC date -d @1710686853 '+%Y-%m-%dT%H:%M:%SZ'      # epoch 本身即 UTC
# 2024-03-17T14:47:33Z

# 反向（UTC → 本地显示）
TZ=Asia/Shanghai date -d @1710686853 '+%F %T %Z%z'
# 2024-03-17 22:47:33 CST+0800
```

> ⚠️ `TZ=UTC date -d '2024-03-17 22:47:33'` 不会做转换。 `TZ` 只改变"`-d` 字符串被当作哪个时区的墙钟"以及"输出如何渲染"，它**不会**把 `Asia/Shanghai` 的本地时间自动换算成 UTC——那样会原样输出 `22:47:33Z`，**整整差 8 小时**。**正确写法必须显式写出源时区**（`TZ=Asia/Shanghai date -d '…'`），这是 Linux 取证时间线最隐蔽的错误来源之一。
>
> ⚠️ **epoch 换算不需要任何时区转换。** `#1710686853` 定义为自 1970-01-01T00:00:00Z 起的秒数，本身即 UTC。但 `date -d @<epoch>` 默认按本地时区渲染，要输出 UTC 必须加 `TZ=UTC` 或 `-u`。

<a id="section-8"></a>

### 2.6 与 Windows 时间线的根本差异

| 对比 | Windows | Linux |
|---|---|---|
| **集中事件日志** | `.evtx`，**单一入口** | ❌ 无；分散在文本日志 + 二进制 utmp/wtmp |
| **事件时间精度** | **毫秒** | 多数秒；journal 微秒；ext4 文件纳秒 |
| **时区** | 事件自带偏移，可精确还原 | **多数无时区**，需靠本机时区推断 |
| **年份** | 永远有 | **`auth.log` 无**（靠 journal 补） |
| **集中化安全审计** | 组策略 + 事件转发 | `auditd`（可选）+ journald，可集中转发 |
| **时间篡改检测** | 可用 $LogFile/UsnJrnl 检测回滚 | 弱；**主要靠多源交叉** |

> 结论：Linux 时间线是"多源拼接 + 交叉验证"的产物，Windows 更接近"导出即用"。
>
> Linux 取证在时间线上的工作量更大，**对分析者的纪律要求更高**——每个时间戳都要问"它的时区是什么、年份哪来的、精度多少、能不能被篡改"。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：确定时区、挂载选项、文件系统状态（三个基础前提）

```bash
# (1) 时区
cat /mnt/df/etc/timezone 2>/dev/null
ls -l /mnt/df/etc/localtime 2>/dev/null              # zoneinfo 软链是权威

# (2) 挂载选项（决定 atime 可信度）
grep -E '^\S+\s+/\s+' /mnt/df/etc/fstab
# /dev/sda1 / ext4 defaults 0 1        → 隐含 relatime
# /dev/sda1 / ext4 noatime 0 1         → atime 完全不可用

# (3) 文件系统状态与特性（决定有无 crtime、亚秒）
debugfs -R "stats" /work/DigiForensics-part3.dd | grep -iE 'features|block size|state'
# features: has_journal ext_attr resize_inode dir_index filetype extent 64bit
# state: clean | clean with errors | not cleanly unmounted
```

> **把这三项写进报告开头。** 后文所有时间戳的解读都依赖它们。

<a id="section-11"></a>

### 3.2 第 2 步：确认 crtime 可用性与亚秒精度

```bash
# 单文件：四个时间戳（含 crtime）
stat /mnt/df/var/log/auth.log
#   File: /var/log/auth.log
#   Size: 48213        Blocks: 96        IO Block: 4096   regular file
# Device: 803,1   Inode: 262145    Links: 1
# Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    4/    adm)
# Modify: 2024-03-18 09:41:07.223456789 +0000     ← mtime（带纳秒 = ext4）
# Change: 2024-03-18 09:41:07.223456789 +0000     ← ctime
# Birth:  2022-05-11 09:30:00.000000000 +0000     ← crtime ★ ext4 才有
```

**如何读 `stat` 输出**：

| `stat` 行 | 对应字段 | 含义 |
|---|---|---|
| `Access:` | **`atime`** | 最后访问（**受挂载选项影响，可信度低**） |
| `Modify:` | **`mtime`** | 内容最后修改 |
| `Change:` | **`ctime`** | inode 元数据最后变更（**≠创建**） |
| **`Birth:`** | **`crtime`** | **文件创建时间**（ext4 特有，ext2/3 无此行） |

`Birth` 行的存在即证明是 ext4（或至少支持 crtime 的文件系统）。若 `stat` **没有** `Birth` 行，说明是 ext2/ext3 或不提供 crtime 的文件系统。

而 `stat` 的 `Access` 不可作为读取证据（见 2.4）。

<a id="section-12"></a>

### 3.3 第 3 步：批量导出时间戳（`stat` 与 `find -printf`）

**`find -printf` 是批量导出的首选**（快、格式可控）：

```bash
# 全盘导出四时间戳（%A=atime %T=mtime %C=ctime；crtime 需用 stat，find 无对应格式符）
find /mnt/df -xdev -type f \
  -printf '%T@  mtime=%TY-%Tm-%Td %TH:%TM:%.2TS  ctime=%CY-%Cm-%Cd %CH:%CM:%.2CS  atime=%AY-%Am-%Ad %AH:%AM:%.2AS  %m %u:%g %s %p\
' \
  2>/dev/null | sort -n > /evidence/timeline-mtime-ctime.txt

# 只导 crtime（需逐个 stat；用 xargs 批量化）
find /mnt/df -xdev -type f -print0 2>/dev/null | xargs -0 stat -c '%W  %w  %x  %y  %z  %s  %U  %n' \
  2>/dev/null | sort -n > /evidence/timeline-birth.txt
# %W = crtime 的 epoch（0 表示不可用）；%w = crtime 可读形式
```

| `find -printf` 符 | 含义 |
|---|---|
| `%T` / `%TY` `%Tm` `%Td` `%TH` `%TM` `%TS` | **mtime**（`%T@` = epoch 秒，`%TS` = 秒含小数） |
| `%A` / `%AY`… | **atime** |
| `%C` / `%CY`… | **ctime** |
| `%W`（`stat`） | **crtime epoch** |

`find -printf` 没有 crtime 的格式符（crtime 是 ext4 特有，GNU find 未提供对应 `%W` 之外的通用格式）。crtime 必须用 `stat` 的 `%W`/`%w`。

全盘 `stat` 较慢，**建议只对可疑路径的 `stat`**，不追求全盘。

<a id="section-13"></a>

### 3.4 第 4 步：各日志源时间戳的补全与统一

**`auth.log` 补年份**（它本身无年份）：

```bash
# 1) 找到机器上带年份的时间锚点（journal 最可靠）
journalctl --directory /mnt/df/var/log/journal -o short-iso-precise --no-pager 2>/dev/null \
  | head -1   # → 2024-03-17T22:00:00.000000+00:00  ← 确定本机年份与时区

# 2) 用锚点年份给 auth.log 补年份（假设日志在同一年内）
sed -E 's/^([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) /\1 /' /evidence/auth-merged.txt
# 再用 awk/脚本按锚点年份补上；若日志跨年（12月→1月），需分段处理

# 3) 验证补全正确性：补完后与 journal 同一条事件比对，应完全一致
```

**跨年处理**（`auth.log` 跨年时的年份推断）：

| 情况 | 处理 |
|---|---|
| 日志文件内含 12 月和 1 月 | 12 月属于前一年，1 月属于后一年。**按出现顺序分段赋年** |
| 依赖归档顺序 | `.gz` 归档名（`dateext` 格式 `auth.log-20240101.gz`）**直接含年份**，最可靠 |
| 交叉 journal | journal 有完整年份，**按事件内容匹配**最准 |

<a id="section-14"></a>

### 3.5 第 5 步：时间线收敛策略（核心方法论）

Linux 时间线源多、量大，**必须收敛，不能全盘铺开**。收敛流程分四步。

第 1 步：确定时间窗口（anchor events）

先找**两三个绝对时间锚点**（精度最高、最不可疑的）：

- 一次 `Accepted password`（auth.log，有 journal 补年份）
- 一次 `apt/history.log` 事务（结构化、带时区）
- 一个文件的 `crtime`（纳秒精度，不可变）
- journal 的开机记录（机器启动时刻）

```bash
# 从 journal 快速取锚点
journalctl --directory /mnt/df/var/log/journal --no-pager -o short-iso-precise \
  | grep -iE 'systemd.*Startup finished|Accepted password' | head
```

第 2 步：按窗口筛各源（每源用"窗口"过滤，而不是全量看）

```bash
W_START="2024-03-17 22:00"; W_END="2024-03-18 10:00"
# auth.log
awk -v s="$W_START" -v e="$W_END" '...按行内时间筛...' /evidence/auth-merged.txt
# journal
journalctl --directory /mnt/df/var/log/journal --since "$W_START" --until "$W_END" \
  -o short-precise --no-pager
# 文件时间戳（mtime 落在窗口内的文件 = 窗口内被改过的）
awk -v s="1710684000" -v e="1710732000" '$1>=s && $1<=e' /evidence/timeline-mtime-ctime.txt
# apt
awk '/^Start-Date: /{inwin=0} /^Start-Date: 2024-03-17 2[0-3]:/,/^End-Date:/' /evidence/apt-history-merged.txt
```

**第 3 步：按"时间簇"聚类，把孤立事件串成链。**

把窗口内所有事件按时间排序，**找时间上密集的簇**（如 22:41–22:53 之间密集发生的一串事件），**每一簇很可能是同一个操作序列**。

用"逻辑链"串联：爆破失败 → 登录成功 → 提权 → 装工具 → 建持久化。

第 4 步：对每条关键结论要求 ≥2 个独立源印证

| 结论类型 | 主源 | 独立印|source |
|---|---|---|
| 某时刻发生了登录 | `auth.log` `Accepted` | `wtmp`（`last`）、journal、`/proc` 连接 |
| 某软件被安装 | `apt/history.log` | auth.log 的 `sudo COMMAND`、`dpkg.log`、包文件 `crtime` |
| 某文件被创建 | 文件 `crtime` | 目录 `mtime`（新建文件会更新父目录 `mtime`）、相关日志 |
| 某配置被篡改 | 文件 `mtime`/`ctime` | `ctime` vs `mtime` 差异、包管理器记录 |

<a id="section-15"></a>

### 3.6 验证环节

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| 时区一致性 | 所有源转换到同一基准后比对 | 同一事件在两源时间一致（或差值可解释） |
| 年份补全 | 补全的 `auth.log` 时间与 journal 同事件比对 | 完全一致（到秒） |
| crtime 可用 | `stat` 是否有 `Birth` 行 | 有 = ext4；无 = 注明"无 crtime" |
| atime 证据强度 | 挂载选项判定 | 明确标注 atime 是强/弱证据 |
| 时间篡改迹象 | `ctime` 远晚于 `mtime` | 差值大 = 可能 `touch` 伪造，需说明 |

---

<a id="section-16"></a>

## 四、常见陷阱

按四类分组：**时间戳语义误读**、**时区与排序**、**收敛与交叉验证**、**取证环境限制**。

<a id="section-17"></a>

### 4.1 时间戳语义误读

<a id="section-18"></a>

#### `ctime` 不是创建时间

**现象**：拿到 `ctime = 2024-03-15 10:22`，报告写"该文件于 3 月 15 日创建"。

**原因**：`ctime` 记录 inode **元数据变更**时刻。`chmod`、`chown`、`ln`、`mv`（同文件系统内）都会更新它，与文件内容何时写入毫无关系。

**影响**：把权限调整时间误当作文件产生时间。

后果是凭空构造出一个不存在的"文件创建 → 后续行为"叙事。

**核查**：ext4 上创建时间看 **`crtime`**（`stat` 输出里的 `Birth`）。`ctime ≫ mtime` 说明**只改了元数据**；两者接近说明内容确实被写过。

```bash
stat DigiForensics.dd
#  Birth: 2024-01-10 09:00:00   ← crtime，创建时间
#  Modify: 2024-03-15 10:20:00  ← mtime，内容修改
#  Change: 2024-03-15 10:22:00  ← ctime，元数据变更（比 mtime 晚 2 分钟 → 改过权限）
```

<a id="section-19"></a>

#### `atime` 能不能作为"被读过"的证据

**现象**：某文件 `atime` 停在半年前，据此断言"半年前之后再没被访问过"。

**原因**：完全取决于挂载选项。`noatime` 下**永不更新**；`relatime`（现代发行版默认）只在 `atime` 比 `mtime`/`ctime` 旧时才更新；只有 `strictatime` 才是每次访问都更新。

**影响**：这是**否定性结论**，且基于一个可能根本不更新的字段。

`noatime` 机器上的 `atime` 全部是历史遗留值，拿它排除任何访问都是错的。

**核查**：**先查挂载选项，再决定 `atime` 的证据等级**。

```bash
findmnt -no OPTIONS /            # 看 noatime / relatime / strictatime
grep -E '\s(noatime|relatime|strictatime)\s' /etc/fstab
```

非 `strictatime` 时，`atime` 只能作**弱证据**，报告里要写明这个限定。

<a id="section-20"></a>

#### `cp -p` 之后 crtime 变了

**现象**：用 `cp -p` 复制证据文件到工作目录，`mtime` 正确保留，但 `Birth` 变成了复制时间。

**原因**：`cp -p` 保留 `mtime`/`atime`/`mode`，但 `crtime` 是**新 inode 的创建时刻**。用户态没有设置 ctime 的接口（`utimensat` 只能改 atime/mtime），所以常规命令无法把它伪造到过去——但用 `debugfs` 一类工具直接改写 inode 结构体仍可做到，因此它是**可信度更高**而非不可篡改。

**影响**：若拿工作副本的 `crtime` 做"文件年龄"判断，所有文件都会显示"刚刚创建"。

**核查**：**永远在原始镜像上取时间戳**，工作副本只用于分析。`crtime` 反而有独特价值——它标出"这个文件是从别处拷来的"，是数据外泄/投递痕迹的线索。

<a id="section-21"></a>

#### `mv` 之后 crtime 不变

**现象**：文件被移动到新目录，`crtime` 仍是旧值，据此认为"文件从创建起就在这个位置"。

**原因**：`mv` 在同一文件系统内只改目录项，**不动 inode 本身**，因此 `crtime` 保持原值。


**影响**：把"曾经被移动过"的事实抹掉。若该文件是从别处投递进来的，`crtime` 早 + 路径浅的组合本可指向"文件后来才被放到这里"，缺了这个判断，移动痕迹就查不出来了。
**核查**：结合**路径深度**与**父目录 `mtime`**判断。文件被 `mv` 进某个目录时，该目录的 `mtime` 会同步更新为移动时刻。

```bash
stat 目标文件 | grep Birth
stat 目标文件的父目录 | grep Modify   # 父目录 mtime ≈ 移动时刻
```

<a id="section-22"></a>

### 4.2 时区与排序

<a id="section-23"></a>

#### 文件时间戳不带时区信息

**现象**：`stat` 显示 `Modify: 2024-03-15 10:20:00`，直接当作 UTC 写进时间线。

**原因**：`stat` 输出的是**本地时间**，且**不带时区标记**。换一台分析机（时区不同）同一时间戳会显示成不同值。


**影响**：**整条时间线偏移固定小时数**，且偏移量随分析机时区而变——同一份证据换台机器跑就得出不同结论，报告无法复现。

跨源比对时可能把不相关的两条记录错判为"同一时刻"。

**核查**：先确定检材的 `/etc/timezone`，全部换算到 **UTC** 作为统一基准，报告里注明原始时区。

<a id="section-24"></a>

#### `CST` 是个陷阱缩写

**现象**：日志里看到 `Mar 15 10:20:00 CST`，直接按 UTC+8 换算。

**原因**：`CST` 是**歧义缩写**——既可指 China Standard Time（UTC+8），也可指 Central Standard Time（UTC-6，美中部）。中英文取证材料里都常见。

**影响**：差 14 小时。跨源对齐时这会把两条时间线彻底错开。
**核查**：**绝不凭缩写猜**，查 `/etc/timezone` 或 `timedatectl`。

```bash
cat /etc/timezone
timedatectl | grep 'Time zone'
```

<a id="section-25"></a>

#### `date -d` 的时区行为

**现象**：用 `date -d @1700000000` 转换 epoch，得到的时间与预期差 8 小时；改成 `TZ=UTC date -d '2024-03-15 10:20:00'` 后问题依旧。

**原因**：`TZ` 环境变量**只改变"如何解释和渲染"，不做"转换"**。把本地时间字符串配 `TZ=UTC` 会被当成已经是 UTC 的时间原样输出，差一整个偏移。


**影响**：**8 小时的偏差足以颠倒事件先后顺序**。

例如"登录早于文件创建"本应指向"文件先被建立后被使用"，时区错误会把它翻转成另一种看似合理的解释，把整个因果关系导向相反方向。

**核查**：

```bash
# epoch → UTC 显示
date -u -d @1700000000
TZ=UTC date -d @1700000000            # 等价

# 本地时间字符串 → 正确换算：显式声明源时区
TZ=Asia/Shanghai date -d '2024-03-15 10:20:00'
```

<a id="section-26"></a>

#### `auth.log` 不带年份

**现象**：把 `/var/log/auth.log` 按时间排序，发现顺序混乱。

**原因**：该文件（及多数发行版的 `syslog`）的时间戳**不含年份**，格式为 `Mar 15 10:20:00`。跨年时字典序 ≠ 时间序——`Dec` 会排在 `Mar` 前面。


**影响**：**跨年案件直接错乱**。

`Dec` 排在 `Mar` 前面，意味着去年 12 月的登录会被当成今年 3 月的事。若据此认定"某人去年登录过"，可能凭空构出一条不存在的登录事件。

**核查**：用 **journal**（自带年份与微秒）或**归档文件名**（`auth.log.1`、`auth.log.2.gz` 对应的时间）补齐年份，再排序。

```bash
# journal 天然带年份
journalctl --since '2024-01-01' -u ssh -o short-iso

# 轮转文件按修改时间定位年份
ls -l --time-style=full-iso /var/log/auth.log*
```

<a id="section-27"></a>

### 4.3 收敛与交叉验证

<a id="section-28"></a>

#### 全盘扫时间戳不做收敛

**现象**：导出全盘 `find -printf` 结果，几十万行，淹没了关键事件。

**原因**：文件系统里绝大多数时间戳与案件无关（发行版镜像文件、语言包、`/usr/share` 静态资源、系统升级遗留目录）。取证人员倾向"先全量导出、保证不漏"，把穷尽性当成严谨性，却忽略了信息过载本身就是一种丢失——评审者无法在噪声中定位异常。

**影响**：不是"看漏"，而是"淹没"——真正相关的 20 条被 30 万行噪声包围，评审时无法识别。
**核查**：**先定时间窗口，再按窗口筛各源**。收敛策略见 [3.5 第 5 步：时间线收敛策略](#section-14)。

```bash
# 先按案件时间窗过滤，而不是全盘导出
find /mnt/image -type f -newermt '2024-03-01' ! -newermt '2024-04-01' \
  -printf '%T+ %p\
' | head -50
```

<a id="section-29"></a>

#### 只用单一源下结论

**现象**：仅凭 `auth.log` 就断定"某用户在此刻登录了"。

**原因**：单一数据源可能本身就有缺陷——日志轮转丢失、系统时间被改、记录被恶意删除。


**影响**：单一源被篡改或恰好缺失时，结论直接失效。

日志轮转（`logrotate`）会删掉旧记录，"没有记录"不等于"没有发生"——**基于空缺做出的否定性结论在质证时无法支撑**。

**核查**：**每条结论要求 ≥2 个独立源交叉印证**。`last` + `auth.log` + `wtmp` 是三条相对独立的记录链；配合文件 `atime`/`crtime` 变化，交叉强度更高。

<a id="section-30"></a>

#### 时间可以被主动伪造

**现象**：关键文件的 `mtime` 明显早于案件时间窗口，看似"与案件无关"。

**原因**：`touch -d '2020-01-01' file` 可以改 `mtime` 和 `atime`。


**影响**：伪造时间戳是反取证的常规手段。

若把被 `touch` 改过的 `mtime` 当真实写入时间，会得出"该文件在案发前就已存在、与案件无关"的结论，**直接放过真正的篡改行为**。

**核查**：**交叉比对三个时间戳**。

| 观察 | 推断 |
|---|---|
| `crtime` 早、`mtime` 晚、`ctime` ≈ `mtime` | 正常写入 |
| `crtime` 早、`mtime` 明显更早、`ctime` 晚 | **`mtime` 被 `touch` 改过** |
| `mtime` ≫ `crtime` | 老文件被篡改内容 |

**`crtime` 无法被 `touch` 伪造**（需直接改 inode 或用 debugfs），因此它比 `mtime` 可信得多。

<a id="section-31"></a>

### 4.4 取证环境限制

<a id="section-32"></a>

#### 断电机器上 `uptime` 不可用

**现象**：对已断电的机器读取启动时间，`/proc` 为空，命令无输出。

**原因**：`/proc` 是内存中的虚拟文件系统，机器一断电就消失。`uptime`、`w`、`last reboot` 全部失效——但这些命令在运行中的机器上是取证人员的默认第一反应，习惯性照搬。

**影响**：开机时间是时间线的**基准点**——它决定了哪些日志属于本次会话、哪些属于上一次。基准点错了，整条时间线的归属判断全部偏移，而且**这种错误不会自己暴露**：日志本身没有错，只是被归错了时段。

**核查**：离线从**持久化记录**推断——journal 的最早记录、`/var/log/wtmp` 的开机条目、关机与启动记录的差值。

```bash
journalctl --list-boots              # 列出历史启动会话
last -F reboot                      # 从 wtmp 读重启记录
```

> ⚠️ **报告表述**：这类推断要写明"**依据 journal 首条记录推断**"，而不是直接写"开机时间为 X"——前者可复核，后者像是实测值。

---

<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 三源时间线对齐与 crtime 区分新建与篡改

**场景**

Ubuntu Server 22.04 Web 服务器 `web01`（ext4，块大小 4096，inode 256）。

委托方要求重建 2024-03-17 至 03-18 的完整活动时间线。检材 `DigiForensics.dd`（raw，ext4 起始扇区 1181696），**强制断电**。前序分析已确认攻击者 `deploy` 于 22:43 登录提权、装了 netcat、并留下多条持久化痕迹。

本案同时出现"时区 + 年份 + 精度"三重陷阱：journal 带年份与时区偏移、auth.log 两者都没有、ext4 文件时间戳带纳秒但显示的是本地时间，任何一处判错，整条线错位。任务就是把这些分散在不同证据源、格式各异的时间戳串成一条可采信的线。

**处置过程**

第 1 步，确认三个基础前提——时区、挂载选项、文件系统特性：

```bash
cat /mnt/df/etc/timezone
# Asia/Shanghai                          ← ★ 本机时区是 CST（UTC+8）
ls -l /mnt/df/etc/localtime
# /etc/localtime -> /usr/share/zoneinfo/Asia/Shanghai    ← 软链目标是权威依据

grep -E '^\S+\s+/\s+' /mnt/df/etc/fstab
# /dev/sda1 / ext4 defaults 0 1         ← 无 atime 字段 = 隐含 relatime

debugfs -R "stats" /work/DigiForensics-part3.dd | grep -iE 'features|state'
# features: has_journal ext_attr resize_inode dir_index filetype extent 64bit
# state: clean with errors
```

三件事一次确认：

- 时区 `Asia/Shanghai`（所有本地时间需减 8 小时才是 UTC）
- 挂载 `relatime`（**atime 只能作弱证据**）
- ext4 + 64bit（**`crtime` 可用**）

第 2 步，验证 `crtime` 可用性与亚秒精度：

```bash
stat /mnt/df/var/log/auth.log | grep -E 'Birth|Modify'
# Birth:  2022-05-11 09:30:00.000000000 +0800      ← crtime：日志文件创建于 2022-05-11
# Modify: 2024-03-18 09:41:07.223456789 +0800      ← mtime：最后写入（纳秒 = ext4 ✓）
```

`Birth` 行存在 = `crtime` 可用。

注意输出带 `+0800` 偏移，但**不能假定所有 coreutils 版本都显示**，老版本可能只有裸时间——此时需另找时区依据。

第 3 步，从 journal 取时间锚点（带年份、微秒、时区偏移，本案最可靠的时间基准源）：

```bash
journalctl --directory /mnt/df/var/log/journal -o short-iso-precise --no-pager 2>/dev/null \
  | grep -iE 'Accepted password for deploy|Failed password' | head
```

| 锚点 | 本地时间（journal 原样输出） | 统一到 UTC |
|---|---|---|
| **T1** 攻击者首次登录成功 | 2024-03-17 **22:43:07.882110** +08:00 | 14:43:07.882110 UTC |
| **T2** 二次登录（断电前最后活动） | 2024-03-18 **09:40:58.771200** +08:00 | 01:40:58.771200 UTC |

第 4 步，补全 `auth.log` 年份并做一致性验证：

```bash
sed -E 's/^([A-Z][a-z]{2}) +([0-9]{1,2}) /\1 \2 2024 /' /evidence/auth-merged.txt \
  > /evidence/auth-2024.txt

grep 'Accepted password for deploy' /evidence/auth-2024.txt | head -1
# Mar 17 2024 22:43:07 web01 sshd[9201]: Accepted password for deploy from 203.0.113.77 port 40210 ssh2
```

补上 2024 后，其 `22:43:07` 与 journal 的 `22:43:07.882110+08:00` **秒级吻合**。

这一步同时验证了两件事：**年份补全正确**与**时区判断正确**——若时区判错，两者不可能同时对上。

journal 输出自带的 `+08:00` 与 `/etc/timezone` 判定的 `Asia/Shanghai` 构成两处独立印证。

第 5 步，对持久化工件取 crtime 揭示文件来源：

```bash
for f in /usr/local/bin/.cache/rotate-logs.sh /usr/local/bin/.cache/sysd \
         /etc/systemd/system/sysupdate.service /etc/update-motd.d/88-sshfp \
         /root/.ssh/authorized_keys /tmp/.kworkerd; do
  [ -e "/mnt/df$f" ] && stat -c '%n%n  crtime=%w%n  mtime=%y%n  ctime=%z' "/mnt/df$f"
done
```

| 文件 | crtime（创建） | mtime（内容改） | ctime（元数据改） |
|---|---|---|---|
| `/usr/local/bin/.cache/rotate-logs.sh` | 2024-03-17 22:47:50 | 22:47:50 | 22:47:50 |
| `/usr/local/bin/.cache/sysd` | 2024-03-17 22:49:12 | 22:49:12 | 22:49:12 |
| `/etc/systemd/system/sysupdate.service` | 2024-03-17 22:49:30 | 22:49:30 | 22:49:30 |
| `/root/.ssh/authorized_keys` | 2022-05-11 09:30 | **2024-03-17 22:50:12** | 2024-03-17 22:50:12 |
| `/etc/update-motd.d/88-sshfp` | 2024-03-17 22:52:07 | 22:52:07 | 22:52:07 |

多数文件三者相同 = 典型的"一次性新建"。

而 `/root/.ssh/authorized_keys` 的 `crtime` 是 2022-05-11（系统初始化时创建），`mtime`/`ctime` 却是 2024-03-17 22:50:12 ——**这不是新建文件，而是往老文件里追加了一行公钥**。

第 6 步，找 `ctime` 单独前进的痕迹：

```bash
find /mnt/df -xdev -type f -printf '%C@ %p\
' 2>/dev/null | sort -rn | head -20
# 1758099633.1044552 /mnt/df/tmp/.kworkerd
# 1758095620.3311224 /mnt/df/root/.ssh/authorized_keys
```

`/tmp/.kworkerd` 的 `ctime`（22:48:20）比 `mtime`（22:47:59）晚约 21 秒，与 `auth.log` 里 `sudo COMMAND=/bin/chmod 4755 /tmp/.kworkerd`（22:48:20）**秒级吻合，构成本案第二条硬链**。

**结论**

- 完整时间线可收敛到**分钟级、亚秒可核**：22:41:15 爆破开始 → 22:43:07.882110 登录成功 → 22:44:01 开 root shell → 22:47:33 装 netcat → 22:47:50/22:47:59 落地脚本与载荷 → 22:48:20 SUID → 22:49:12–22:52:07 建立四条持久化 → 22:50:12 追加 root 公钥 → 次日 09:40:58.771200 二次登录 → 09:41:07 断电。
- **两个可复用的判据被本案同时验证**：`ctime ≫ mtime` = 改元数据未改内容（可靠指标）；`mtime ≫ crtime` = 篡改老文件而非新建。前者对应 `/tmp/.kworkerd` 的 `chmod 4755`，后者对应 `authorized_keys` 被追加。
- **结论强度的来源是交叉验证而非单一来源**：每条时间线上的事件都至少有"日志行 + 文件时间戳"两个独立源，且秒级吻合。`crtime` 之所以能承担"新建 vs 篡改"的判别，前提是 `Birth` 行确实存在——ext4 64bit 才有。

**误判对照**

本案最容易得出的错误结论是「`authorized_keys` 的 mtime 是 2024-03-17 22:50:12，说明攻击者在 22:50 **创建**了新的 root SSH 密钥文件」。

这个说法在报告里非常顺理成章，因为 `mtime` 确实指向 22:50。

正确判据是 `crtime` 与 `mtime` 的差值关系，不是 mtime 本身。

本案 `crtime` = 2022-05-11 09:30，比 mtime 早近两年。ext4 的 `crtime` 是 inode 分配时刻，一旦分配就**不随内容修改而更新**；`mtime` 才是最后一次写内容的时间。两者相差近两年，只能说明这是一个 2022 年就存在的文件在 2024-03-17 被修改过。

**这个区分为什么重要**：

- 若结论写成"新建后门密钥文件"，读者的默认推断是攻击者**创建了一个新文件**——那么 `/root/.ssh/authorized_keys` 在此之前应该是不存在的，或者存在一个攻击者没碰过的版本。这会让人去追查"这个文件哪来的"。
- 正确结论是"攻击者修改了系统初始化时（2022-05-11，与 `auth.log` 的 crtime 同一天）就已存在的 root 授权文件，追加了一行公钥"。这指向一个不同的处置方向：`authorized_keys` 里可能还有 2022 年就已存在的其他公钥，**需要逐行审查全部公钥的来源**，而不能只看 mtime 之后新增的那一行。

**按错误判据走的代价**：漏掉 root 账号上原有的全部 SSH 密钥。如果那些旧密钥属于已离职人员或前运维，攻击者未必需要自己写公钥——直接使用遗留密钥登录，在日志上与本次 `Accepted publickey` 无法区分。少看一行，就少一条线索。

第二个易错点：**`ctime ≫ mtime` 不能反过来读**。

有人会认为"mtime 22:47:59、ctime 22:48:20，说明文件内容在 22:47:59 写完后 21 秒又写了一次内容"——这是错的。

`ctime` 前进**不代表内容变化**，它是 inode 元数据变更时间。写数据会**同时**更新 mtime 和 ctime，二者几乎相同；只有 `chmod`/`chown`/`ln`/`chattr` 这类只动 inode 不动数据的操作，才让 ctime 单独前进。

本案 21 秒的差值恰好对应 `chmod 4755`，若误读成"两次内容写入"，反而会虚构出一个不存在的写入动作。

---

<a id="section-35"></a>

### 5.2 手动改时间造成的三小时空档：NTP 跳变与伪造的 mtime

**场景**

同型号主机 `web03`，委托方要求确认 3 月 5 日下午 3 点前后是否有人登录。检材 `DigiForensics.dd`。

分析者把各源时间戳贴到时间线软件上，发现 **14:50 到 17:40 之间有一段奇怪的空白**，且空白前后的文件时间戳出现约 2 小时 50 分的重叠。

时间跳变是最容易被当成"没活动"的时间线缺口，而它的成因恰恰是"有人动了时间"。

**处置过程**

第 1 步，把 journal 按小时统计事件密度，快速定位异常窗口：

```bash
journalctl --directory /mnt/df/var/log/journal -o short-iso --no-pager \
  | awk '{print $1" "substr($2,1,2)}' | uniq -c | head -40
#   412 2024-03-05 13
#   398 2024-03-05 14
#    41 2024-03-05 14   ← 14:50 之后骤降
#    38 2024-03-05 17   ← 17:40 之后恢复
#   401 2024-03-05 18
```

第 2 步，直接读 journald 自己记录的时间跳变（**这是最权威的跳变证据**）：

```bash
journalctl --directory /mnt/df/var/log/journal -o short-iso-precise --no-pager \
  | grep -iE 'clock|time.*chang|System clock|System time'
# 2024-03-05T14:50:22.114+08:00 web03 systemd-logind[812]: System clock is set forward by 10441.882106 seconds
# 2024-03-05T17:40:03.902+08:00 web03 systemd-logind[812]: System clock is set back by 9000.221044 seconds
```

第 3 步，核对 systemd 的定时任务与 timedatectl 状态：

```bash
journalctl --directory /mnt/df/var/log/journal -o short-iso-precise --no-pager \
  | grep -iE 'systemd-timed|ntpd|chronyd|ntp.*(sync|adjust)'
# 2024-03-05T13:02:01.881+08:00 web03 systemd-timed[701]: Timed out waiting for NTP response
# 2024-03-05T17:41:55.204+08:00 web03 systemd-timed[701]: New NTP service enabled (time.cloudflare.com)

timedatectl 2>/dev/null | head -3   # 离线机不可用，仅示意字段名
# NTP synchronized: yes
# Time zone: Asia/Shanghai (CST, +0800)
```

第 4 步，验证"时间回拨"造成的文件时间戳错位：

```bash
find /mnt/df/var/tmp /mnt/df/tmp -type f -newermt '2024-03-05' ! -newermt '2024-03-06' \
  -printf '%T+ %C+ %p\
' 2>/dev/null | sort
# 1772666402.3310288 1772666402.3310288 /mnt/df/var/tmp/.cache/collect.sh
# 1772677200.1184000 1772677200.1184000 /mnt/df/var/tmp/session.tmp
# ↑ 差值恰为 10800 秒 = 3 小时整 → 同一时间轴上出现两套时间基准
```

第 5 步，在回拨窗口内找是否有可用的独立时间源：

```bash
grep -iE 'Accepted|Failed|session' /mnt/df/var/log/auth.log \
  | sed -n '/Mar  5 17:4[0-9]/p' | head
# Mar  5 17:42:11 web03 sshd[3301]: Accepted publickey for svc-backup from 198.51.100.9 port 51022 ssh2
```

**结论**

- 14:50:22 向前跳 10441.88 秒（约 2 小时 54 分）、17:40:03 向后跳 9000.22 秒（2.5 小时），两条 `systemd-logind` 的 `System clock is set ...` 记录构成**本机时间轴非连续的权威证据**。这解释了事件密度骤降窗口的全部成因。
- 两个跳变方向相反，导致 14:50–17:40 之间的时间线存在约 2 小时 50 分的重叠，而非单纯空白。

重叠意味着**同一段墙上时间被记录了两次**（跳变前后各一次），**这段时间内的任何"只有一次"的事件计数都是错的**。

可用证据：journal 中**两段时间均带年份与时区偏移**，且 `System clock is set` 记录给出了精确跳变量，可据此把事件重新映射到单调递增的真实时间轴。

`auth.log` 缺年份，须以 journal 补齐后才有可比性。

- **NTP 本身失效是原因之一，但不是唯一解释**：`systemd-timed` 记录 13:02:01 `Timed out waiting for NTP response`，17:41:55 才 `New NTP service enabled`。向前跳 2h54m 符合"长期未同步后一次性校正"，但向后跳 2.5 小时这个方向不能用 NTP 校正解释——NTP 校正只会把偏差越修越小，不会把时间往回拨。**回拨必须有其他成因**（如 `hwclock -s` 覆盖、手动 `date -s`、容器宿主机时间同步异常）。这一条必须作为独立发现上报。
- 因此委托方问题的答复是：「14:50–17:40 期间的事件不能按日志显示时间直接排序；该窗口内 `svc-backup` 的公钥登录属于计划任务，其余时段存在时间轴不连续，不能做"仅此一次"类计数结论。」

**误判对照**

本案最容易得出的错误结论是「14:50–17:40 这段没有任何登录行为发生」——依据是这段窗口在 journal 密度统计里几乎空白、在 `auth.log` 抽样里也看不到记录。

空白是**最像"无活动"的形态**。

正确判据是 journal 里 `systemd-logind` 的 `System clock is set forward/backward` 两条记录，以及文件时间戳上那个**精确等于 10800 秒（3 小时整）的差值**。

三小时整这种整齐的差值绝不可能是真实活动的时间差，只可能是两套时间基准的偏移量。

更关键的是**方向性判断**：

- 向前跳 2h54m 后系统时间跑到真实时间前面，于是 17:40 之前的墙上时间被"跳过"了一部分——事件虽然记录了，但**落在了一个真实世界从未到达过的时刻区间**。
- 向后跳 2.5h 后系统时间退回，于是 14:50–17:40 这段墙上时间**被覆盖了两次**。如果只看日志行上的时间戳，会看到同一分钟内有两个来源的事件，且**无法判断哪个先发生**。

**按错误判据走的代价**：把跳变窗口写成"无活动"，等于**替一台被改过时间的机器出具了虚假的安全证明**。

委托方据此认为"那个时段没人动过机器"，而实际上攻击者恰恰利用时间回拨来掩盖操作。

第二个后果是所有基于"一天内事件次数"或"首次出现时间"的统计全部作废——比如判断"这是第一次尝试"这类结论，在时间轴重叠的窗口里根本不成立，必须在报告中降级为"证据不可靠"。

第二个易错点：看到 NTP 超时就认定跳变全是 NTP 导致的。

本案的反例就是那个**向后跳 9000 秒**。`systemd-timed` 在 13:02:01 报 `Timed out waiting for NTP response` 只能解释向前跳（偏差积累后一次校正），**解释不了回拨**。

若报告写成"因 NTP 故障导致时间不准"，就没发现回拨这个需要追查的动作（谁执行了 `hwclock -s` 或 `date -s`），这条线索就断了。

判据：NTP 失效只能让时间越修越准，回拨一定另有其人。

---

<a id="section-36"></a>

### 5.3 反例：跨时区主机群的时区配置错位

**场景**

某公司两地共 6 台应用服务器（`app-sha-01/02`、`app-cdg-01/02`、`app-hkg-01/02`），委托方要求回答"运维在 3 月 12 日下午是否执行过发布操作"。检材为每台的 `DigiForensics.dd`。

多机时间线合并时，最隐蔽的错误不是缺证据，而是全部证据都在、却因为时区基线不同而无法对齐。

**处置过程**

第 1 步，逐台读时区依据（**不信任任何汇总表，只看两处文件**）：

```bash
for h in sha cdg hkg; do
  echo "== $h =="
  cat /mnt/df-$h/etc/timezone 2>/dev/null
  ls -l /mnt/df-$h/etc/localtime 2>/dev/null | sed 's/.*-> //'
  # sha: Asia/Shanghai   /usr/share/zoneinfo/Asia/Shanghai
  # cdg: Asia/Chongqing  /usr/share/zoneinfo/Asia/Chongqing
  # hkg: Asia/Hong_Kong /usr/share/zoneinfo/Asia/Hong_Kong
done
```

第 2 步，用 journal 输出的偏移量做独立验证：

```bash
for h in sha cdg hkg; do
  journalctl --directory /mnt/df-$h/var/log/journal -o short-iso --no-pager 2>/dev/null \
    | head -1 | grep -oE 'T[0-9:.]+[+-][0-9]{2}:[0-9]{2}'
done
# 2024-03-12T14:22:01+08:00
# 2024-03-12T14:22:00+08:00
# 2024-03-12T14:22:04+08:00
```

第 3 步，检查是否存在配置漂移的机器：

```bash
for h in sha cdg hkg; do
  printf '%s: ' "$h"
  md5sum /mnt/df-$h/etc/localtime 2>/dev/null | cut -d' ' -f1
done
# sha: 3b1f...  cdg: 3b1f...  hkg: 7d02...
# 三个不同 md5：文件内容本身不同（时区名不同），不能按内容相等合并
```

第 4 步，建立换算表并合并：

```bash
cat <<'EOF' >> /evidence/tz-map.txt
app-sha-01  Asia/Shanghai   UTC+08:00  恒定偏移
app-sha-02  Asia/Shanghai   UTC+08:00  恒定偏移
app-cdg-01  Asia/Chongqing  UTC+08:00  恒定偏移
app-cdg-02  Asia/Chongqing  UTC+08:00  恒定偏移
app-hkg-01  Asia/Hong_Kong  UTC+08:00  恒定偏移
app-hkg-02  Asia/Hong_Kong  UTC+08:00  恒定偏移
EOF
# 三地虽时区名不同，但 3 月 12 日的实际偏移都是 UTC+08:00
```

第 5 步，找统一时间线上的发布痕迹：

```bash
journalctl --directory /mnt/df-sha-01/var/log/journal -o short-iso-precise --no-pager \
  | grep -iE 'deploy|release' | head -4
# 2024-03-12T13:58:44.112+08:00 app-sha-01 deploy[2201]: uploading app-4.2.0.tar.gz (48 MB)
# 2024-03-12T14:03:11.998+08:00 app-sha-01 deploy[2201]: rollout done on node 1/2
```

**结论**

- 三地时区名不同（`Asia/Shanghai` / `Asia/Chongqing` / `Asia/Hong_Kong`）但 3 月 12 日的实际偏移全部是 UTC+08:00，journal 输出的 `+08:00` 偏移量提供了独立验证。**该日的时间线可以直接按本地时间合并，无需换算。**
- 缺陷在于 `md5sum` 三个值互不相同——**"时区文件内容相同"不能作为对齐依据**，必须用偏移量或实测 UTC 差值。
- 委托方问题的答复是：`app-sha-01` 上于 2024-03-12 13:58:44.112（UTC+08:00） 上传 `app-4.2.0.tar.gz`，14:03:11.998 完成节点 1/2 的滚动更新。该时刻换算为 UTC 是 `05:58:44.112Z`。
- **必须写明的证据局限**：本结论的有效性绑定在"该日无夏令时切换、无系统时间跳变"这两个前提上。本案未在这 6 台上发现 `System clock is set` 记录，journal 偏移量全程恒为 `+08:00`，两个前提成立。但若跨过夏令时边界（北美 3 月第二个周日、欧洲 3 月最后一个周日），`Asia/*` 恒定而北美/欧洲机组的偏移会变化，届时必须分段换算而不能沿用本表。

**误判对照**

本案最容易得出的错误结论是「`app-cdg-01` 的时区是 `Asia/Chongqing`，与 `Asia/Shanghai` 不同，因此它的 14:22 就是比 `app-sha-01` 的 14:22 晚 1 小时，两者差 1 小时」。

这是一个非常自然、看起来非常谨慎的推断，错误在于**把时区名称当成了偏移量**。

正确判据是 journal 输出行尾的 `+08:00` 偏移量本身。

`Asia/Chongqing` 是中国 1994–1997 年间一度使用过的旧时区名，其偏移与 `Asia/Shanghai` **同为 UTC+08:00**；本次三地 journal 实测偏移均为 `+08:00`，已经直接给出答案。

名称不同只是 tzdata 里的历史条目，**不等于偏移不同**。

**按错误判据走的代价**：给每台机器人为造出一个 1 小时的时间差，**跨机因果顺序会被完全颠倒**。

本案 `app-sha-01` 13:58:44 上传、14:03:11 完成滚动更新；如果误以为 `app-cdg-01` 慢 1 小时，就会把"发布"和"校验"两个动作的先后关系判反，结论里可能出现"先在成都节点完成 rollout、后在上海上传"这种物理上不可能的时序。

质证时只要对方拿出任一节点的 journal 偏移量，这个错误就暴露无遗。

第二个易错点：看到三个 `localtime` 的 md5 不同，就把"时区配置不一致"当成一条配置漂移发现上报。

正确判据是**先比偏移量、再比名称**。

`md5sum` 不同只说明指向了不同的 zoneinfo 文件，而 zoneinfo 文件内容还包含大量历史规则，**相同偏移的两个时区文件也可能有不同的 md5**（历史规则不同但 2024-03-12 的实际偏移一致）。

反过来，**md5 相同也不保证对齐**——若两台机器的 `/etc/localtime` 都指向 `Asia/Shanghai`，md5 一致，但这两台本身可能在不同时期被配置过，跨了夏令时就会分叉。

md5 是文件身份，偏移量是时间事实，只有后者能用于时间线。

---
<a id="section-37"></a>

## 六、扩展阅读方向

<a id="section-38"></a>

### 前置基础

- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) —— **解决"四个时间戳分别在哪个字段、语义是什么"**。本篇直接使用结论，字段布局与 `i_size`、`links_count` 的读取方法在那篇。
- [系统日志深度分析](computer-log-system-log-analysis.md) —— **解决"各日志源在哪、哪些可能缺失"**。本篇假设日志已导出为文本，**导出与去重归档那一步在那篇**。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— **解决"时区与 epoch 怎么算"**。FILETIME、DOS 时间、WebKit 时间与 Unix epoch 的换算关系，**时区搞错时时间线不会报错只会整体偏移**，这是最隐蔽的一类错误。

<a id="section-39"></a>

### 同层深入

- [计划任务与持久化痕迹](../computer-persistence/computer-persistence-scheduled-tasks-and-persistence.md) —— 解决"时间线上某个文件是什么时候被创建的、谁创建的"。本篇给时间与顺序，**归因与可执行性判读在那篇**，时间线里出现 `systemd` 单元或 cron 条目时两篇要连着读。
- [取证工件地图](../computer-persistence/computer-persistence-persistence-artifact-map.md) —— **解决"时间线上提到某个路径，该路径下还该看什么"**。`/tmp`、`/var/tmp`、SUID 文件清点，都是时间线之外的结构性佐证。

<a id="section-40"></a>

### 相邻议题

- [UsnJrnl 与文件操作时间线](../computer-execution/computer-execution-usn-journal-timeline.md) —— **横向对照读**。Windows 侧有原生的文件操作流水，**Linux 侧没有任何等价物，只能靠多源拼接**——这个结构性差异是本篇存在的根本原因。
- [NTFS 时间戳相关讨论](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— **解决"日志层时间证据的另一种形态"**。NTFS 的 USN 日志有原因码与文件引用号，**结构化程度远高于 Linux 的拼接式时间线**。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **解决"时间戳本身能不能信"**。本篇默认时间戳真实，**主动篡改与批量伪造的识不要在那篇**，两者应配套阅读。

<a id="section-41"></a>

### 工具与规范

- `stat` / `find -printf` / `journalctl -o short-precise` 的批量导出参数见[命令速查](#section-43)——**关键是确认 `stat` 是在只读挂载上执行的**，否则可能触发 atime 更新污染证据。
- 合并时间线时**每行都标"支撑源数量"**，案例里"登录=3 源、chmod=2 源"的标注让结论强度一眼可辨，没有这个标注的合并时间线无法被质证。
- 时区判定要同时引三处证据：`/etc/timezone`、`/etc/localtime` 符号链接目标、日志里的时区标记。只引一处无法排除"日志用 UTC、系统用本地时区"的混用。
- 报告里空窗的写法见[案例示例](#section-33)的收敛结论第 2 条："各源均无记录"而非"无活动"，并注明日志可能因断电或清理而不完整。
- 原始镜像的固定与操作留痕见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——**批量导出前先哈希固定镜像**。

<a id="section-42"></a>

### 判据与反例

- **判据一**：先定三个前提（时区、挂载选项、文件系统特性）再解读任何时间戳。前提未定时的时间戳解读一律不成立。
- **判据二**：`crtime` 与 `mtime` 的差值能区分"新建文件"与"篡改已有文件"。本篇案例里它单独定住了 `authorized_keys` 的性质。
- **判据三**：关键节点要有 ≥2 个独立源。同一源内两个字段（如 `mtime` 与 `crtime`）不算两个源。

六条反例都指向同一个毛病——**把某个字段当成它不是的东西**：

- **反例一**：把 `ctime` 当创建时间。`ctime` 是 inode 变更时间，改权限就动它，当创建时间用会造出大量假事件。
- **反例二**：把 `atime` 当"某人某天读了该文件"的证据。`relatime` / `noatime` 下读文件不更新 atime，这条推论在默认配置下不成立。
- **反例三**：用无年份的 syslog 直接声称事件年份。**格式里没有年份字段**，必须由 journal 等带年源补锚，并写明补锚来源。
- **反例四**：把"活动空窗"写成"攻击者在此期间无活动"。"各源均无记录"与"无活动"之间隔着日志缺失、审计未启用、会话被强杀三种可能，必须写成前者。
- **反例五**：因为 `bash_history` 缺失就写"没有执行过命令"。强杀会话与 `HISTFILE=/dev/null` 都会让历史归零，本篇案例里攻击者正是用后者清除痕迹。
- **反例六**：跨年时用 `cat auth.log* | sort` 排序。**字符串排序不等于时间排序**，`Feb 3` 会排在 `Mar 17` 后面，事件顺序直接错乱。
<a id="section-43"></a>

## 七、命令速查

```bash
# ===== 1. 三个前提（解读任何时间戳前先定）=====
cat /mnt/df/etc/timezone; ls -l /mnt/df/etc/localtime       # 时区（zoneinfo 软链是权威）
grep -E '^\S+\s+/\s+' /mnt/df/etc/fstab                    # 挂载选项（relatime/noatime → atime 可信度）
debugfs -R "stats" /work/DigiForensics-part3.dd | grep -iE 'features|state'  # ext4？crtime 可用？

# ===== 2. 四时间戳（含 crtime）=====
stat /mnt/df/var/log/auth.log | grep -E 'Access|Modify|Change|Birth'
# Access=atime(弱)  Modify=mtime  Change=ctime(≠创建)  Birth=crtime(ext4 才有)
# ★ 无 Birth 行 = ext2/ext3，无 crtime
# ★ mtime 远早于 ctime = 可能有 touch 伪造或只改元数据

# ===== 3. 批量导出 =====
# mtime/ctime/atime（find 快，但无 crtime）
find /mnt/df -xdev -type f \
  -printf '%T@ m=%TY-%Tm-%Td_%TH:%TM:%.2TS c=%CY-%Cm-%Cd_%CH:%CM:%.2CS a=%AY-%Am-%Ad_%AH:%AM:%.2AS %p\
' \
  2>/dev/null | sort -n > /evidence/timeline.txt
# crtime（只能 stat；建议只对可疑路径）
find /mnt/df -xdev -type f -print0 2>/dev/null | xargs -0 stat -c '%W %w %n' 2>/dev/null | sort -n

# ===== 4. 时区统一 =====
# epoch → 可读（epoch 本身是 UTC）
TZ=UTC date -d @1710686853 '+%Y-%m-%dT%H:%M:%SZ'      # epoch 本身即 UTC
# 本地时间 → UTC：必须显式写出「源时区」，否则 TZ=UTC 不会帮你转换
TZ=Asia/Shanghai date -d '2024-03-17 22:47:33' '+%Y-%m-%dT%H:%M:%SZ'
# 2024-03-17T14:47:33Z
# ★ CST 可指 UTC-6 或 UTC+8，必须查 /etc/timezone，不能凭缩写猜

# ===== 5. auth.log 补年份（它本身无年份）=====
# 用 journal（带年份）确定锚点年份，再补
journalctl --directory /mnt/df/var/log/journal -o short-iso-precise --no-pager | head -1
sed -E 's/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) /2024-\1 /' /evidence/auth-merged.txt
# 跨年（12月→1月）需按顺序分段赋年；dateext 归档名含年份最可靠

# ===== 6. 收敛：定窗口 → 按窗口筛各源 =====
journalctl --directory /mnt/df/var/log/journal \
  --since "2024-03-17 22:00" --until "2024-03-18 10:00" -o short-precise --no-pager
awk '$1>=1710684000 && $1<=1710732000' /evidence/timeline.txt   # epoch 窗口筛文件时间戳

# ===== 7. 断电机器推启动时间（/proc 为空，离线方法）=====
journalctl --directory /mnt/df/var/log/journal --no-pager -b -1 | head -1   # 上次启动首条
# 在线才有 /proc/uptime 可用；离线从 journal/日志首条记录推断
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Linux 取证 — Linux 时间线重建」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Linux 时间线重建》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
