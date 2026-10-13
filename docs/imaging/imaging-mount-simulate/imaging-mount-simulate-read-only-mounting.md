---
title: "只读挂载与安全接入"
slug: "imaging-mount-simulate-read-only-mounting"
canonical: "https://www.digiforensics.cn/wiki/imaging-mount-simulate-read-only-mounting"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "imaging"
space: "磁盘镜像与仿真"
node_path: ["只读挂载与仿真"]
---

# 只读挂载与安全接入

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/imaging-mount-simulate-read-only-mounting)

<a id="section-1"></a>

## 一、概述

拿到镜像之后，最自然的想法是"挂载起来看看里面有什么"。这个想法在便利性上无可指摘，在**证据安全**上却极其危险——因为操作系统的挂载过程本身就会写盘。

即使加了 `-o ro`，某些文件系统仍会在挂载瞬间修改超级块、回放日志、更新访问时间：

| 后果 | 严重程度 |
|---|---|
| **原始哈希被破坏**，镜像无法再证明与检材一致 | ★★★★★ 证据灭失 |
| `$MFT` / inode 时间戳被更新，污染时间线分析 | ★★★★★ 破坏核心证据 |
| 损坏或恶意构造的文件系统可触发内核漏洞 | ★★★★ 安全风险 |
| 挂载产生的新文件让文件系统状态与镜像初始状态不符 | ★★★ 逻辑不自洽 |

更严重的是，Autopsy、X-Ways、FTK Imager 在设计时就假设"挂载会破坏证据"，所以它们根本不提供直接挂载。这一取舍反映了取证学科对挂载风险的共识——这不是工具功能缺失，是刻意的设计。

**本篇给出的三条路径，按安全等级排序**：

| 路径 | 是否经过内核 | 是否可能写盘 | 适用场景 |
|---|---|---|---|
| **Sleuth Kit 直接解析** | ❌ 否 | **绝无** | 取证分析的首选，绝大多数场景够用 |
| **只读环设备 + 内核挂载** | ✅ 是 | **有条件**（`noload` + `noatime` + `blockdev --setro` 三层） | 需要 `ls` / `cp` / `grep` 等常规工具时 |
| **Windows 侧写保护器 + 挂载** | ✅ 是 | **几乎必然** | 只在必要时，且**必须**有硬件写保护 |

核心原则一句话：能不挂载就不挂载。

Sleuth Kit 直接读镜像文件、自己解析数据结构，完全不经过内核文件系统驱动，因此在物理上不可能触发任何写入——这不是"风险较低"，是"风险为零"。

**为什么内核挂载挡不住写入**是本篇最需要先理解的一件事：`-o ro` 只保证文件系统层不主动写，而内核 VFS 之外的机制仍会绕过它。

典型翻车场景是 ext4 报告 `needs journal recovery`（断电后的正常现象），你挂上去，内核照常回放日志，把几十 MB 的元数据改动写进镜像——挂完算一下哈希，已经和采集时完全不同了。

**绕过 `-o ro` 的四类机制**（具体对应第四章 4.1 组）：

| 机制 | 触发条件 | 写入内容 | 对策 |
|---|---|---|---|
| **日志回放** | ext3/ext4 标记为 dirty、XFS 有未完成日志 | 把日志里的元数据操作重做一遍 | ext 用 `-o noload`，XFS 用 `-o norecovery` |
| **超级块修复** | 文件系统检测到不一致 | 修正 `s_state`、空闲块计数 | 只能靠**块层锁死**（`blockdev --setro`）挡住 |
| **atime 更新** | 读取文件时（除非显式 `noatime`） | inode 的访问时间 | `-o noatime` |
| **relatime 重算** | 相对时间戳重算 | 最多每 24 小时一次 | 同上 |

**atime 这一条值得单独强调**：读取证据文件会改变被读取文件的时间戳，而用 `find` 遍历目录、用反取证工具扫未分配空间时，几百上千个文件的访问时间会被一次性改掉。

而"最后访问时间"恰恰是取证里最有用的字段之一——不改 atime 不是保守，是保护证据。只要没有显式指定 `noatime`，现代内核的 `relatime` 默认也仍然会更新它。

**在取证流程中的位置**：本篇是**分析**环节的第一道关卡，处在镜像制作（[镜像制作](../imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)）之后、任何实际内容分析之前。**上游**是格式问题——E01 需要 EWF 库或先转 RAW，见[证据格式与转换](../imaging-acquire/imaging-acquire-evidence-image-formats.md)；**它自己**的前置是挂载前的哈希校验，**镜像在被接入之前应该先确认哈希与采集记录一致**，否则你连"自己有没有毁掉证据"都判断不了。

**下游**分两条：静态解析路线直接进[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)、[ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md)；需要观察运行态行为的走[虚拟机仿真](imaging-mount-simulate-virtual-machine-emulation.md)。

两条路线的关键区别是：挂载给你文件系统视图，仿真给你程序执行能力——后者风险高一个量级。

镜像里有哪些分区、每个分区的起止扇区与文件系统类型、目录树长什么样、某个文件的元数据与内容是什么、删除文件与未分配空间里有什么、以及**接入操作之后镜像是否还是原样**（这是必须自己回答的问题）。

**挂载不等于能读**——加密卷挂上去也只是一堆随机字节，解密是另一条线（[BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md)）；**挂载给不了你程序运行态**——正在运行的进程、内存里的凭据、网络连接的当前状态，静态挂载一个都看不到；以及**挂载也不能替代仿真**——恶意程序的行为、加密密钥的运行时驻留、自毁逻辑的触发条件，都必须在受控环境里实际运行才观察得到。

**读者前提**：你需要能读懂 `mmls` 的分区表输出（本篇 2.5 逐列解释了每个字段，不掌握它后面每一步都会算错偏移）、理解扇区与字节的换算（`offset = Start × 512`）、并清楚**"只读"是三层机制叠加的结果而不是一个参数**。

如果你还没做镜像或者还没确认镜像哈希，先回[镜像制作](../imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)。Linux 内核安全机制（Landlock、SELinux）的内容在扩展阅读里有指向，本篇不展开。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 三条接入路径的安全等级

| 路径 | 是否调用内核文件系统驱动 | 是否写盘 | 适用 |
|---|---|---|---|
| **Sleuth Kit 直接解析** | ❌ 否 | **绝无** | 取证分析的首选 |
| **只读环设备 + 内核挂载** | ✅ 是 | 有条件（见 2.2） | 需要 `ls`/`cp` 等常规工具时 |
| **Windows 写保护器 + 挂载** | ✅ 是 | **几乎必然** | 只在必要时，且必须用硬件写保护 |

**核心原则：能不挂载就不挂载。** Sleuth Kit 直接读取镜像文件、自己解析数据结构，完全不经过内核，因此在物理上不可能触发任何写入。

<a id="section-4"></a>

### 2.2 为什么"只读挂载"仍然会写盘

这是本篇最重要的原理，也是最多人误解的地方。`mount -o ro` 只保证文件系统层不主动写，并不禁止一切写入。 内核的 VFS 层把超级块标记为只读，但以下机制仍可能绕过：

| 机制 | 触发条件 | 写入内容 |
|---|---|---|
| **日志回放（journal replay）** | ext3/ext4 标记为 dirty，XFS 有未完成日志 | 把日志中的元数据操作重做一遍 |
| **超级块修复** | 文件系统检测到不一致 | 修正 `s_state`、空闲块计数等 |
| **atime 更新** | 读取文件时（除非 `noatime`） | inode 的访问时间 |
| **relatime 更新** | 相对时间戳的重算 | 最多每 24 小时一次 |

**最典型的翻车场景**：`fsck` 报告 ext4 "needs journal recovery"（断电时的正常现象），你用 `mount -o ro` 挂上去——内核照常回放日志，把几十 MB 的元数据改动写进镜像。挂完 `sha256sum` 一算，哈希和采集时完全不同了。

**解决办法**：ext 用 `-o noload`（不加载/回放 journal），XFS 用 `-o norecovery`（不回放 log），再叠加 `blockdev --setro` 从块层锁死只读。

<a id="section-5"></a>

### 2.3 为什么必须禁用 atime

Linux 传统上每次读文件都更新访问时间（atime）。现代内核默认使用 `relatime`（一天最多更新一次），但只要没有显式指定 `noatime`，这个行为就仍然存在。

对取证来说这是不可接受的：读取证据文件会**改变被读取文件的时间戳**；如果还用了 `find` 遍历目录、用反取证工具扫描未分配空间，几百上千个文件的 atime 会被改。而"访问时间"恰恰是取证分析中最有用的字段之一——它能证明"谁在什么时候碰过这个文件"。

不改 atime 不是保守，是保护证据。

> **规范做法**：所有取证挂载一律加 `noatime`。如果环境里 `/etc/fstab` 配了 `relatime`，命令行参数也要显式覆盖。

<a id="section-6"></a>

### 2.4 Sleuth Kit 分层架构

TSK 的设计本身就是"不挂载"的产物——它把磁盘解析分成五层，每层工具只做一件事：

| 层 | 工具 | 职责 |
|---|---|---|
| Image | `img_stat` | 镜像格式、扇区大小 |
| Volume | `mmls` / `mmstat` / `mmcat` | 分区表解析，提取卷 |
| File System | `fsstat` / `fls` / `icat` / `istat` | 目录树、文件元数据、文件内容 |
| Data Unit | `blkcat` / `blkls` | 按块号提取 |
| Journal | `jls` / `jcat` | 日志分析 |

**这个架构带来三个直接好处**：

1. **零写入**：所有工具都是 `open()` + `pread()` 模式
2. **能访问内核不给看的东西**：删除文件、未分配空间、文件系统元数据
3. **能精确定位**：每个文件有唯一的 inode/MFT 编号，可作为证据引用

<a id="section-7"></a>

### 2.5 mmls 输出格式详解

`mmls` 的输出是后续所有操作的基础，必须读懂每一列：

```
Slot      Start        End          Length       Description
00: Meta  0000000000   0000000000   0000000001   Primary Table (#0)
01: ----- 0000000000   0000000062   0000000063   Unallocated
02: 00:00 0000000063   0009510479   0009510417   NTFS (0x07)
03: ----- 0009510480   0009514259   0000003780   Unallocated
```

| 列 | 含义 | 用法 |
|---|---|---|
| `Slot` | 槽位编号 | **提取卷时作为参数**（`mmcat ... 02`） |
| `Start` / `End` / `Length` | 起止扇区与长度 | 全部以 **512 字节**为单位（除非另有提示） |
| `Description` | 卷类型 | MBR/GPT 类型代码 + 文件系统识别结果 |

**`00: 00:00` 的含义**：第一段 `00:` 是**分区表序号**（第几个分区表），第二段是**该表内的槽位号**。`00:00` = 第一个分区表的第一项。嵌套的 DOS 扩展分区会出现 `01:00` 这样的二级编号。

**Unallocated 行的价值**：它们是分区表未占用的空间。**这是反取证软件的默认藏身点**，必须用 `blkls` 或关键字搜索专门检查。

**关于 `[ntfs]` 这类方括号标记**：TSK 工具在不同输出位置使用方括号表示"推测/强制"的类型，而 `mmls` 的 `Description` 列用的是 `NTFS (0x07)` 这种"类型名 + MBR 类型码"格式。写脚本解析时不要混淆这两种表示法。

**换算偏移**：`offset_bytes = Start × 512`。例如 `Start = 0000000063` 对应 `32256` 字节。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：Sleuth Kit 不挂载访问（首选）

```bash
sudo apt install sleuthkit

img_stat /evidence/DigiForensics.dd     # Image type: raw  Sector size: 512
mmls /evidence/DigiForensics.dd         # 分区布局
fsstat -o 63 /evidence/DigiForensics.dd # 簇大小、$MFT 位置、卷序列号

# 递归全部目录，完整路径（-r 递归，-p 显示完整路径）
fls -o 63 -r -p /evidence/DigiForensics.dd > /evidence/full-listing.txt

# 提取文件（inode 编号从 fls 输出中获取）
icat -o 63 /evidence/DigiForensics.dd 1234-128-3 > /evidence/extracted-file.bin

# 提取文件系统内未分配块做关键字搜索（-o 是文件系统起始扇区，不是 Slot 号）
blkls -o 63 /evidence/DigiForensics.dd | strings | grep -i 'target-string'

# 按 Slot 提取整个卷
mmcat /evidence/DigiForensics.dd 2 > /evidence/partition2.dd
```

**inode 编号格式**：`元数据地址-序列号-类型`。NTFS 中 `11443-128-4` 表示 MFT 条目 11443、属性序列 128、类型 4（`$DATA`）。

这个编号本身就是证据引用坐标——报告里写清"文件 X 对应 MFT 条目 11443"，比"某文件夹里有个文件"精确得多。

**整个流程零写入**，可以在原始主副本上直接运行，无需制作工作副本。

<a id="section-10"></a>

### 3.2 第 2 步：只读环设备挂载

当确实需要用 `ls`/`cp`/`grep` 等常规工具浏览文件内容时才用。核心是**三层只读防护**：

```bash
# ① 建立只读环设备（-r 只读，-P 扫分区生成 /dev/loop0p1、p2 ...）
sudo losetup -r --find --show -P /evidence/DigiForensics.dd   # 输出：/dev/loop0

# ② 在块层锁死只读（双保险）
sudo blockdev --setro /dev/loop0
blockdev --getro /dev/loop0        # 输出 1 = 已只读
```

> **`losetup -r` 的关键意义**：它让**块设备层**拒绝一切写请求，即使后续想 `mount -o rw` 也会失败——这是防止"手滑"最有效的技术手段。

**挂载、浏览、卸载（必须完整走完）**：

```bash
sudo mkdir -p /mnt/evidence

# 挂载：noload / norecovery / noatime 三者缺一不可
sudo mount -t ext4  -o ro,noload,noatime,noexec     /dev/loop0p1 /mnt/evidence
sudo mount -t xfs   -o ro,norecovery,noatime,noexec /dev/loop0p2 /mnt/evidence
sudo mount -t ntfs3 -o ro,noatime,noexec            /dev/loop0p3 /mnt/evidence
# NTFS 备选：装 ntfs-3g 后用 -t ntfs-3g
# 裸文件系统镜像（无分区表）：sudo mount -o ro,noload,noatime,loop 镜像文件 /mnt/evidence

# 浏览结束后立即卸载并分离环设备
sudo umount /mnt/evidence
sudo blockdev --setrw /dev/loop0        # 解除块层只读
sudo losetup -d /dev/loop0              # 分离，否则环设备泄漏
```

<a id="section-11"></a>

### 3.3 第 3 步：挂载后立即验证哈希

**这是整个流程中不可省略的一步。** 挂载前后各算一次：

```bash
sha256sum /evidence/DigiForensics.dd     # 挂载前
# ...执行挂载与浏览，卸载后...
sha256sum /evidence/DigiForensics.dd     # 卸载后
```

**两个哈希必须一致。** 不一致意味着挂载过程修改了镜像，此时立即停止所有操作，记录修改前后的哈希值，从主副本重新制作工作副本，并在报告中如实记录这一事件——隐瞒比事件本身更严重。

<a id="section-12"></a>

### 3.4 第 4 步：挂载 E01 镜像

E01 是压缩容器，不能直接 `losetup`，需先用 FUSE 桥接（命令见第七节）。`ewfmount` 暴露为原始镜像文件供 TSK 读取；`xmount` 支持更多格式且输出**虚拟可写**的 dd——所有写入只落在内存缓存中，源文件不受影响，这让它特别适合挂载**疑似恶意或损坏的镜像**：即使镜像内的文件系统或恶意程序试图写入，也碰不到真实数据。

<a id="section-13"></a>

### 3.5 第 5 步：Windows 侧挂载

Windows 没有等价的"不挂载直接浏览"命令行工具（FTK Imager 内部有自己的解析器）。若必须在 Windows 上访问：

| 方式 | 安全性 | 说明 |
|---|---|---|
| FTK Imager `Image Mounting` | ★★★★★ | 选 `Block Device / Read Only`，输出只读盘符 |
| **Arsenal Image Mounter** | ★★★★ | 支持 FUSE，能读 E01/AFF4/VMDK |
| **写保护器 + 内置读卡器** | ★★★★ | 硬件层阻断写入 |
| **直接双击/右键打开 E01** | ☆ | **会写盘，绝对禁止** |

**FTK Imager 只读挂载**：`File` → `Image Mounting...` → 挂载类型选 `Block Device / Read Only`（不要选 File System）→ 选 `DigiForensics.E01` → `Mount`。卸载：同菜单选已挂载项 → `Dismount`。

挂载后盘符在资源管理器中显示为只读，且**拒绝所有写入操作**——双击文件提示"拒绝访问"属正常现象，不是故障。

**重要提醒**：即使标注 "Read Only"，Windows 仍可能因某些驱动或服务行为产生写入。在任何情况下都不应把 E01/RAW 放在唯一的存储上直接操作，主副本必须与工作副本分离。

---
<a id="section-14"></a>

## 四、常见陷阱

这一章的陷阱有一个共同结构：每一条的"正确做法"看起来都已经在原文里写过了，但实际操作时会被跳过。跳过之后不会立刻报错——镜像照样能列出目录、文件照样能打开、`mount` 照样返回成功——而证据完整性已经在无人注意的片刻里被改掉了。

第一章那张后果表里最重的一档是"证据灭失"，本章讲的就是它是怎么在几分钟内发生的。

三条接入路径（2.1）的安全等级不同，但**没有一条路径是零风险**：TSK 路径是物理上零写入，只读环设备是"有条件"写入，Windows 侧是"几乎必然"写入。下面按"只读机制为什么失效 → 坐标参数为什么错 → 非 RAW 与 Windows 接入 → 流程与留痕"四组展开。

★ 标记表示该操作会不可逆地改写原始检材，执行前必须停下来确认。

<a id="section-15"></a>

### 4.1 只读机制的三层防护与失效路径

<a id="section-16"></a>

#### 陷阱 1：★ 只加 `mount -o ro`，就认为镜像不会被写

**现象**：`mount -t ext4 -o ro /dev/loop0p2 /mnt/evidence` 挂载成功，`ls`、`cp` 都正常，卸载后没有报错，认为这一轮是安全的。

**原因**：2.2 是本篇最重要的一节，它把这层侥幸直接否掉了：`mount -o ro` 只保证文件系统层不主动写，并不禁止一切写入——内核 VFS 把超级块标记为只读，但日志回放、超级块修复、atime、relatime 这四个机制仍可能绕过。

2.2 给出的最典型翻车场景是断电后的 ext4 被 `fsck` 判定 `needs journal recovery`，此时用 `mount -o ro` 挂上去，内核照常回放日志，把几十 MB 的元数据改动写进镜像，卸载后 `sha256sum` 与采集时完全不同。

**影响**：**原始哈希被永久改变**。此时镜像已经不能再证明与检材一致，而如果这是主副本，**整条证据链的起点就丢了**——重新采集未必可行（设备已归还、已上缴或已复勘）。

**核查**：**只读必须三层叠加，缺一层就等于没做**（3.2 的标准写法）：

```bash
# 第 1 层：块设备层拒绝一切写请求
sudo losetup -r --find --show -P /evidence/DigiForensics.dd   # → /dev/loop0

# 第 2 层：块层显式锁只读（双保险）
sudo blockdev --setro /dev/loop0
blockdev --getro /dev/loop0        # 输出 1 = 已只读

# 第 3 层：文件系统层，并按类型关掉各自会写盘的机制
sudo mount -t ext4  -o ro,noload,noatime,noexec     /dev/loop0p1 /mnt/evidence
sudo mount -t xfs   -o ro,norecovery,noatime,noexec /dev/loop0p2 /mnt/evidence
sudo mount -t ntfs3 -o ro,noatime,noexec            /dev/loop0p3 /mnt/evidence
```

`noload` / `norecovery` 不是"优化项"，是这一层唯一能挡住日志回放的开关。ext4 挂 ext3 也要写 `noload`，理由见陷阱 4。

<a id="section-17"></a>

#### 陷阱 2：漏掉 `noatime`，把"访问时间"这个证据字段读没了

**现象**：为了找关键字，`grep -r 'password' /mnt/evidence` 全盘扫了一遍，扫完继续按 atime 排时间线，写出"该文件最后被访问于 X 时间"。

**原因**：**2.3 把这条单独列一节，因为它最隐蔽**。现代内核默认用 `relatime`（一天最多更新一次），只要没有显式指定 `noatime`，这个行为就仍然存在。而 atime 恰恰是取证分析中最有用的字段之一——它能证明"谁在什么时候碰过这个文件"。

2.3 的结论说得直接：不改 atime 不是保守，是保护证据。一次全盘 `grep` 遍历会改掉几百上千个文件的 atime，而后续分析用的正是这些字段。

**影响**：**证据字段被自己的检索行为污染，且不可恢复**。

更糟的是它制造了一个自指的循环：分析动作本身改写了它要读的数据，结论看起来仍然"有据可依"，实际依据已被破坏。

**核查**：**所有取证挂载一律显式加 `noatime`**，并注意命令行参数要覆盖 `/etc/fstab` 里的 `relatime`：

```bash
# /etc/fstab 里即便写了 relatime，命令行也要显式覆盖
sudo mount -t ext4 -o ro,noload,noatime,noexec /dev/loop0p1 /mnt/evidence

# 核对：/proc/mounts 里应当是 noatime 而不是 relatime
grep ' /mnt/evidence ' /proc/mounts
# 期望：... /mnt/evidence ext4 ro,noatime,noload,noexec,...
```

**已经污染了怎么办**：如果已经用带 atime 的挂载读过主副本，**不要再在同一个副本上继续做时间线分析**。从主副本重新制作工作副本（`cp --reflink=auto`），并在报告中说明原副本的 atime 字段已不可作为访问时间证据。

<a id="section-18"></a>

#### 陷阱 3：`losetup` 不加 `-r`，只靠 `mount -o ro` 兜底

**现象**：习惯性地写 `sudo losetup --find --show -P DigiForensics.dd`，然后 `mount -o ro`；或者挂载失败后想"改成 rw 重挂一次看看"，一敲就成功了。

**原因**：3.2 把 `-r` 的意义单独立了引用块：`losetup -r` 让块设备层拒绝一切写请求，即使后续想 `mount -o rw` 也会失败——这是防止"手滑"最有效的技术手段。

省掉它之后，`-o ro` 只剩文件系统层那一道可以被操作者自己撤掉的防护。它防的是人，不是文件系统——而本篇所有风险里有相当一部分正是人造成的。

**影响**：**把"意图"当成了"机制"**。一旦后续任何一步需要改写（例如临时 `mount -o remount,rw`、某个工具自己尝试修复、误把设备号写错到 `dd if=... of=/dev/loop0`），块层不会拦，而拦截本来是可以零成本获得的。

**核查**：**`-r` 与 `-P` 同时给**，`-P` 让内核扫描分区表生成 `/dev/loop0p1`、`p2` 等分区设备：

```bash
sudo losetup -r --find --show -P /evidence/DigiForensics.dd
# 输出 /dev/loop0，并生成 /dev/loop0p1 ...

# 卸载时顺序不能颠倒
sudo umount /mnt/evidence
sudo blockdev --setrw /dev/loop0     # 解除块层只读
sudo losetup -d /dev/loop0           # 分离，否则环设备泄漏
```

**卸载顺序本身也是陷阱的一部分**：3.2 的三行清理命令是完整流程，`losetup -d` 漏掉之后设备号会被下一个环设备复用，而此时旧的 `/dev/loop0p1` 仍然指向证据镜像——后续任何针对 `/dev/loop0*` 的 `dd` 都会打到证据上。

<a id="section-19"></a>

#### 陷阱 4：ext3 用 `noload` 挂不上，于是把 `noload` 去掉重挂

**现象**：`mount -t ext3 -o ro,noload,noatime /dev/loop0p1` 报 noload 相关错误，改成 `-t ext3 -o ro,noatime` 就挂上了；或者改用 `-t ext4` 才挂上，顺手把 `noload` 也去掉了。

**原因**：旧表格里那条"ext3 用 `noload` 挂载失败"的正确处置是**换驱动，不是换开关**——ext3 驱动把"无日志"当作错误，而 ext4 驱动向后兼容 ext3。这个知识看起来很轻，但它决定了你会往哪个方向修。

而 `-o ro,noatime` 挂上去时，日志回放的开关是开着的：如果这个 ext3 分区存在未回放的日志（断电的正常后果），内核会照常回放并写入元数据，而 `mount` 正常返回、`ls` 正常列出目录。

**影响**：一个"挂载失败"的告警被换成了一个"挂载成功"的假象。而与陷阱 1 不同的是，这一次的风险是**主动的**——操作者亲手移除了唯一的防护，且事后从命令历史里看不出现场已经提示过异常。

**核查**：**换驱动类型，保留 `noload`**：

```bash
# 错：去掉 noload 换 ext3 驱动
sudo mount -t ext3 -o ro,noatime /dev/loop0p1 /mnt/evidence

# 对：ext4 驱动向后兼容 ext3，noload 必须保留
sudo mount -t ext4 -o ro,noload,noatime,noexec /dev/loop0p1 /mnt/evidence
```

**挂载参数有疑问时先看文件系统类型，不要靠试**：

```bash
fsstat -o 2048 /evidence/DigiForensics.dd | head -30
# 看 Feature flags 与 Filesystem type，确认是不是 ext 系列
```

**发现挂载参数改错了怎么办**：**立刻停止，从主副本重新制作工作副本**，并按 3.3 重新算哈希、在报告中记录这次事件。**在哈希已被改变的文件上"补救"没有意义**——补救动作本身只会再改一次。

<a id="section-20"></a>

### 4.2 Sleuth Kit 的坐标与参数

<a id="section-21"></a>

#### 陷阱 5：把 `mmls` 给的偏移当字节用

**现象**：`mmls` 输出 `02: 00:00  0000000063  0009510479`，直接写 `mount -o offset=63` 或在脚本里用 `63` 做 `seek`，挂上去看到的是一堆乱码或别的分区内容。

**原因**：2.5 把这个换算写成了明文公式：`offset_bytes = Start × 512`，并且明确 `Start / End / Length` 三列全部以 512 字节为单位（除非另有提示）。

而 `mmls` 的数字是十位补零的扇区号（`0000000063`），看起来像一个普通的、可以直接当字节数用的整数——63 字节这个数量级小到会让人怀疑自己是不是理解错了，而实际上是 32256 字节。

**影响**：**挂到一个错误位置，读到完全无关的内容**。这类错误不会崩，也不会给出明显的错误信息——它给出一个看起来合法的目录树，而后来的分析全部建立在错误的分区上。

**核查**：**换算后再用，并保留换算依据**：

```bash
mmls /evidence/DigiForensics.dd
# Slot     Start        End          Length       Description
# 02: 00:00 0000000063   0009510479   0009510417   NTFS (0x07)

# 换算：Start = 63 → 63 × 512 = 32256 字节
# 交给 TSK 工具的 -o 接受扇区号，所以 63 可以直接用；
# 交给 mount 的 offset= 或 dd 的 skip=（配合 bs=512）才需要换算
sudo mount -o ro,loop,offset=32256 /evidence/DigiForensics.dd /mnt/evidence

# 若 media 的扇区大小不是 512，必须按实际值换算
img_stat /evidence/DigiForensics.dd | grep -i 'sector size'
```

**报告里写坐标时把两个数都写上**：`MFT 条目 11443，位于分区槽 02:00:00，卷内起始扇区 63（绝对偏移 32256 字节）`。**只写其中一个数，下一个接手的人就可能犯同一个错**。

<a id="section-22"></a>

#### 陷阱 6：`icat` / `blkls` 漏掉或误解 `-o`

**现象**：`icat /evidence/DigiForensics.dd 1234-128-3 > out.bin` 提取出来的文件打不开、是别的文件的内容；或者用 `blkls -o 2` 想提 slot 2，得到一堆看似有数据实则错位的输出。

**原因**：这是两个方向相反、但根因相同的错误，3.1 的注释把它们并排写在了一起：**`-o` 是文件系统起始扇区，不是 Slot 号**。

`icat` 漏掉 `-o` 时，工具从镜像的 0 扇区也就是**分区表所在位置**开始读，而分区表的字节当然不是文件内容。反过来，`blkls -o 2` 把 slot 号当成了扇区偏移，工具老老实实去读了第 2 扇区。

两者都不会报错——`icat` 照样输出一个文件，`blkls` 照样输出数据。

**影响**：**提取物被当成有效证据写进报告**。而提取物的"文件名、大小、甚至部分内容"可能都看着合理，哈希却是错的——这个错误在后面很难被发现。

**核查**：提卷用 `mmcat <image> <slot>`，在文件系统内取数据一律带 `-o <起始扇区>`：

```bash
# 错：-o 缺省，从 0 扇区（分区表）开始读
icat /evidence/DigiForensics.dd 1234-128-3 > out.bin

# 对：从该文件系统所在分区的起始扇区读
icat -o 63 /evidence/DigiForensics.dd 1234-128-3 > out.bin

# 错：把 slot 号塞进 -o
blkls -o 2 /evidence/DigiForensics.dd

# 对：-o 是该文件系统的起始扇区
blkls -o 63 /evidence/DigiForensics.dd > unalloc.bin
# 或者整个卷提出来再当作裸文件系统处理
mmcat /evidence/DigiForensics.dd 2 > partition2.dd
```

3.1 补的那句"整个流程零写入，可以在原始主副本上直接运行"值得单独强调：用 TSK 工具时不涉及内核文件系统驱动，`open()` + `pread()` 模式在物理上不可能触发写入（2.4）。

所以**能用 `icat` 就不该先挂载**——挂载是为"需要 `ls`/`cp`/`grep`"准备的妥协，不是默认路径。

<a id="section-23"></a>

#### 陷阱 7：把 Unallocated 空间当成一处，只查了文件系统内部

**现象**：对 NTFS 分区跑了 `blkls -o 2048 | strings | grep -iE 'password|api[_-]?key|token'`，零命中，写进报告"未发现密钥类残留"。

**原因**：**分区间隙和文件系统内未分配块是两回事**，案例第 2 步专门为此拆成了 ①② 两步。2.5 只说了"`Unallocated` 行的价值：它们是分区表未占用的空间，这是反取证软件的默认藏身点"——但那一行说的是分区表层面的空洞，不是分区内部的空闲块。

反取证工具把数据放在分区表之后第一个分区之前、或两个分区之间的间隙里，这些字节根本不属于任何文件系统，`blkls` 永远看不到它们。

**影响**：**一次范围不足的阴性结论**。而"未发现密钥残留"这种表述在报告里往往会被委托方直接引用。

**核查**：**两层都要查，并分别取数据**（案例第 2 步的完整形式）：

```bash
# ① 分区间隙：按 mmls 给出的起止扇号直接切，不经过任何文件系统解析
mmls /work/DigiForensics.dd
dd if=/work/DigiForensics.dd of=/tmp/gap.bin bs=512 skip=951048 count=3780 status=none
strings -n 20 /tmp/gap.bin | grep -iE 'password|api[_-]?key|token'

# ② 文件系统内未分配块：-o 是该文件系统的起始扇区
blkls -o 2048 /work/DigiForensics.dd > /tmp/ntfs-unalloc.bin
strings -n 20 /tmp/ntfs-unalloc.bin | grep -iE 'password|api[_-]?key|token'
```

**阴性结论按 SPEC 形式写**：

> "**关键字检索**：在 `DigiForensics.dd`（500 GB，GPT + MBR 混合布局）范围内，对每一个 `mmls` 报出的 Unallocated 扇区区间以及**每个文件系统的 `blkls` 未分配块**分别执行，匹配式为 `password|api[_-]?key|token`，最小匹配长度 20 字节（UTF-8/ASCII 可见字符）。上述两类范围内均未匹配到目标内容。本结论不表明检材内不存在该内容，未覆盖范围包括：文件系统内已分配但未引用的簇外区域、未被 `blkls` 覆盖的元数据区、以及压缩/加密容器内部。"

**顺带一条命名规范**：3.1 的 `fls -o 63 -r -p ... > full-listing.txt` 这种先落盘再分析的做法要保持——`fls` 的输出是后续所有 `icat` 的 inode 编号来源，直接管道给下一个命令会丢掉 inode 号，届时无法复现提取过程。

<a id="section-24"></a>

#### 陷阱 8：报告里只写文件路径，不写 inode / MFT 编号

**现象**：报告写"在 `Users/Public/Documents/合同.docx` 中发现内容"，但没有给出 TSK 编号。复核人重新跑一遍 `fls`，目录树已经和当初不同（或者操作的是另一个分区），无法定位到同一个对象。

**原因**：3.1 结尾那句"这个编号本身就是证据引用坐标"是本条的全部依据——NTFS 中 `11443-128-4` 表示 MFT 条目 11443、属性序列 128、类型 4（`$DATA`），而且 2.4 把它列为 TSK 架构的第三个直接好处：每个文件有唯一的 inode/MFT 编号，可作为证据引用。

路径是**可变的**（重命名、移动、目录项重用都会改），**MFT 编号在同一个卷内是稳定的**。

**影响**：**结论无法被独立复核**。委托方或鉴定人拿着报告去复查时定位不到同一对象，整份报告的证明力因此下降——而这不是数据问题，是引用方式问题。

**核查**：**路径与编号成对记录，编号作为主引用**：

```bash
# 列表时保存完整映射，不要只留路径
fls -o 63 -r -p /evidence/DigiForensics.dd > /evidence/full-listing.txt
# 输出形如：r/r 1234-128-4:	Users/Public/Documents/合同.docx
#                            ^^^^^^^^^^^^  这个编号才是引用坐标

# 报告写法：编号 + 路径 + 该编号的提取哈希，三者绑定
```

> "`DigiForensics.dd` 分区槽 `02:00:00`（起始扇区 2048）内，MFT 条目 `45231-128-4`（路径 `Users/Public/Documents/合同.docx`）的内容中包含目标字符串，提取件 SHA-256 = `<哈希>`。"

**编号还能反过来用**：`icat` 只接受编号，一旦路径变了、目录项被覆盖，编号仍能取到原内容——这也是 2.4 说的"能访问内核不给看的东西"的实际价值。

<a id="section-25"></a>

### 4.3 E01 与 Windows 侧接入

<a id="section-26"></a>

#### 陷阱 9：把 `ewfmount` 的挂载点当成镜像本身

**现象**：`sudo ewfmount /evidence/DigiForensics.E01 /mnt/ewf` 之后，对 `/mnt/ewf` 跑 `grep -a 'target'`，零命中；对 `/mnt/ewf` 跑 `mmls` 报无分区。

**原因**：第七章速查里那行注释是关键线索：`ewfmount /evidence/DigiForensics.E01 /mnt/ewf   # 出现 /mnt/ewf/ewf1`。

`ewfmount` 挂的是一个**目录**，真实的数据流是挂载点下的 `ewf1` 文件。它不是把镜像映射到目录本身——这一点与 `mount` 的直觉相反，而 `ewfmount` 平时不常被用到，错误认知很容易带进来。第七章紧接着的 `sudo mmls /mnt/ewf/ewf1` 就是正确的传参形式。

**影响**：**又一次"方法不匹配导致的假阴性"**。在挂载点上做的每一次检索都是无效的，而命令本身不产生任何错误提示。

**核查**：**先 `ls` 确认挂载产出，再决定传哪个路径**：

```bash
sudo ewfmount /evidence/DigiForensics.E01 /mnt/ewf
ls -l /mnt/ewf                        # 应看到 ewf1

mmls /mnt/ewf/ewf1                    # 对：数据流文件
img_stat /mnt/ewf/ewf1

# 清理
sudo ewfumount /mnt/ewf
```

**E01 桥接有两条路，选哪条取决于场景**（3.4）：`ewfmount` 供 TSK 读取；`xmount` 输出的 dd 是"虚拟可写"的，所有写入只落在内存缓存中，源文件不受影响。

```bash
# 需要内核挂载浏览时用 xmount：即使镜像内的文件系统或恶意程序试图写入，也碰不到真实数据
sudo xmount --in ewf /evidence/DigiForensics.E01 --out raw /mnt/xmount
```

**注意"虚拟可写"不等于不安全**——3.4 这句才是它适合**疑似恶意或损坏镜像**的原因：**写入被隔离在内存层**。所以这里可以放心 `mount` 挂 xmount 的输出，而不必再叠加三层只读防护。

但源 E01 与工作副本仍要分离，因为内存缓存是临时的、且一次崩溃就全部丢失。

<a id="section-27"></a>

#### 陷阱 10：★ Windows 上双击或右键打开 E01；挂载类型选成 File System

**现象**：把 E01 拷到 Windows 分析机上，资源管理器里双击；或者用 FTK Imager 的 `Image Mounting` 时选了 `File System` 而不是 `Block Device / Read Only`。

**原因**：3.5 那张表里 `直接双击/右键打开 E01` 的安全评级是唯一的 ☆，其余三种都是 ★★★★ 以上。

原因不在 E01 本身，而在于双击会触发系统的文件关联与卷影复制（shadow copy）服务——这些行为发生在取证工具的视野之外，操作者既看不到，也拦不住。

而 FTK Imager 的 `File System` 挂载类型意味着**交给内核文件系统驱动去解析**，那正是 2.2 讲的那一类会写盘的行为；`Block Device / Read Only` 则是把分区结构呈现为只读块设备，风险等级完全不同。

**影响**：**在唯一的存储上发生了不受控的写入**。3.5 那句提醒是硬约束："在任何情况下都不应把 E01/RAW 放在唯一的存储上直接操作"。如果这里是主副本，它已经不再是原始检材了。

**核查**：优先走 FTK Imager 的块设备只读挂载，或 Arsenal Image Mounter；任何情况下主副本与工作副本分离。

```text
FTK Imager（安全性 ★★★★★）
  File → Image Mounting...
  挂载类型：Block Device / Read Only     ← 不要选 File System
  选择：DigiForensics.E01
  Mount
  # 用完：同一菜单选中已挂载项 → Dismount
```

**两个正常现象不要当成故障去"修"**：

- 3.5 明确：**挂载后双击文件提示"拒绝访问"属正常现象**——盘符是只读的，不要为了"能打开"去掉只读属性。
- 即使标注 `Read Only`，3.5 仍提醒 Windows 可能因某些驱动或服务行为产生写入——所以"只读挂载"是降低风险，不是消除风险，主副本分离才是兜底。

**挂载前后照例要算哈希**（见陷阱 11），Windows 侧用 `Get-FileHash`：

```powershell
Get-FileHash -Algorithm SHA256 'E:\evidence\DigiForensics.E01'
```

<a id="section-28"></a>

### 4.4 流程留痕与工作副本

<a id="section-29"></a>

#### 陷阱 11：不做挂载前后哈希验证，或哈希变了仍继续并隐瞒

**现象**：直接开始挂载分析，过程中没算过哈希；卸载后随手一算发现不一致，把工作副本重新 `cp` 一份，接着往下做，报告里不提这件事。

**原因**：3.3 用加粗写死了这一条的地位："这是整个流程中不可省略的一步"。它的必要性来自前面所有陷阱的共同后果——挂载可能写盘，而且写盘往往不产生任何提示。

而不一致意味着什么，3.3 也写明了："不一致意味着挂载过程修改了镜像"，不是"哈希工具版本不同"、"不是稀疏文件差异"。

**影响**：**隐瞒比事件本身更严重**（3.3 原话）。哈希不一致却继续作业，后续所有基于该副本的结论都失去了可复核的起点；而在报告中隐瞒，则把一次操作失误升级为职业责任问题。

**核查**：**挂载前后各算一次，两个值必须一致；不一致立即停止**：

```bash
sha256sum /work/DigiForensics.dd     # 挂载前，写进记录
# ...挂载、浏览、卸载...
sha256sum /work/DigiForensics.dd     # 卸载后
# 不一致 → 停止全部操作，记录前后哈希，从主副本重做工作副本，报告中如实记录
```

**哈希验证不是一次性动作**——每一次接触 E01、每一次 `mount`、每一次 `qemu-img` 转换之后都要重算。案例第 1 步算一次、第 3 步卸载后再算一次，中间隔了一次完整的挂载浏览，这个间隔就是验证的粒度。

**阴性结论的写法**（陷阱 7 已给格式），这里补一条关于路径区分的要求：

> "本次分析区分两条取证路径：**路径 A（TSK 直接提取）**用于已删除文件，`fls`/`icat` 全程不挂载，镜像哈希 `A`；**路径 B（只读挂载浏览）**用于活跃文件，挂载参数 `-o ro,noload,noatime,noexec`，挂载前后哈希均为 `A`。路径 B 的时间线字段已按 2.3 排除 atime 依据；未覆盖范围包括 xmount 内存缓存层崩溃后未落盘的浏览内容。"

<a id="section-30"></a>

#### 陷阱 12：★ 在主副本上直接挂载，理由是"TSK 反正零写入"

**现象**：因为 3.1 说 TSK 流程零写入、可以"在原始主副本上直接运行"，于是把同一份 `DigiForensics.dd` 先用 TSK 分析（安全），再直接 `losetup` + `mount` 挂同一份文件。

**原因**：**这句话的适用范围被悄悄放大了**。

3.1 那句"整个流程零写入，可以在原始主副本上直接运行"，指的是**3.1 里的 TSK 流程**（`img_stat`/`mmls`/`fsstat`/`fls`/`icat`/`blkls`/`mmcat`），依据是 2.4 的"`open()` + `pread()` 模式"。**它不覆盖 3.2 的挂载流程**——2.1 的对照表把这两条路径的安全等级明确区分开：TSK 直接解析"是否写盘：绝无"，只读环设备 + 内核挂载"有条件"。

"同一份文件先被安全工具读过"不会改变它随后进入内核驱动管辖的事实。

**影响**：**主副本不可逆地失去原始性**。而主副本的全部价值就在于**它没被任何东西碰过**——复核、重新分析、应对质证，全部依赖这一点。

**核查**：**主副本只读封存，所有需要挂载的操作在工作副本上做**（案例第 1 步的 `cp --reflink=auto` 就是这个动作）：

```bash
# 主副本：只读封存，不参与任何分析操作
ls -l /evidence/master/DigiForensics.dd
# 挂权限位、封条、登记编号；分析期间不挂载、不转换、不计算写入型操作

# 工作副本：所有可能触发写入的操作都在这里
sudo cp --reflink=auto /evidence/master/DigiForensics.dd /work/DigiForensics.dd
sha256sum /work/DigiForensics.dd
# 核验工作副本与主副本一致，再开始分析
```

**层级要跟着走**：挂载、格式转换（E01 ↔ RAW ↔ VMDK）、仿真运行——这些都应该发生在工作副本或仿真产生的差分盘上，主副本永远停在链的起点。

**收尾三步同样不能省**（3.2 与陷阱 3 已强调）：

```bash
sudo umount /mnt/evidence
sudo blockdev --setrw /dev/loop0
sudo losetup -d /dev/loop0        # 漏掉这步，设备号会被复用
```

**卸载后确认环设备确实消失**：

```bash
losetup -a | grep DigiForensics    # 应无输出
```

**有输出就说明还有镜像被挂在系统上**——在证据保管环境中，这本身就是一条必须写进交接记录的状态。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 混合分区镜像：空闲空间必须分两层查

**场景**

查获笔记本，镜像为 `DigiForensics.dd`（500 GB SATA SSD，Windows 10 + ext4 数据分区混合布局）。需提取特定文件并做全盘关键字搜索，主副本只读封存。委托方的问题是"有没有凭据被删除后残留"。

选择这一路径的依据是"空闲空间"在混合分区镜像上不是一块，而是两个互不重叠的区域——只查一层就会漏掉另一层。

**处置过程**

第 1 步 · 制作工作副本（主副本不动）并读取分区布局：

```bash
sudo cp --reflink=auto /evidence/master/DigiForensics.dd /work/DigiForensics.dd
sha256sum /work/DigiForensics.dd
mmls /work/DigiForensics.dd
```

输出显示：`02: 00:00` 为 NTFS 系统分区（Start 2048），`03: 00:01` 为 ext4 数据分区（Start 258048），两者之间有 3780 个扇区的 Unallocated 间隙。`fsstat -o 258048` 进一步给出 `Last Mount Time`、`Journal Inode: 8` 等信息。

**第 2 步 · 分两层检查空闲空间（全程不挂载）**——分区间隙和文件系统内未分配块是两回事，必须分别提取：

```bash
# ① 分区间隙：按 mmls 给出的起止扇号直接切，不经过任何文件系统解析
dd if=/work/DigiForensics.dd of=/tmp/gap.bin bs=512 skip=951048 count=3780 status=none
strings -n 20 /tmp/gap.bin | grep -iE 'password|api[_-]?key|token'

# ② 文件系统内未分配块：-o 是该文件系统的起始扇区
blkls -o 2048 /work/DigiForensics.dd > /tmp/ntfs-unalloc.bin
strings -n 20 /tmp/ntfs-unalloc.bin | grep -iE 'password|api[_-]?key|token'
```

两层共命中 2 条：`api_key=AKIA****`（AWS 格式）与 `-----BEGIN PRIVATE KEY-----`，均为已删除的脚本残留。

第 3 步 · 确实需要浏览目录树时才挂载，并验证未破坏镜像：

```bash
sudo losetup -r --find --show -P /work/DigiForensics.dd
sudo blockdev --setro /dev/loop0
sudo mkdir -p /mnt/evidence
sudo mount -t ext4 -o ro,noload,noatime,noexec /dev/loop0p2 /mnt/evidence
# ...浏览完成后：
sudo umount /mnt/evidence && sudo losetup -d /dev/loop0
sha256sum /work/DigiForensics.dd      # 与第 1 步完全一致
```

**结论**

能证明：AWS 访问密钥与私钥内容存在于镜像的空闲区域中，属已删除数据，用提取出的原始数据块加独立哈希固定。`sha256sum` 前后一致证明挂载浏览未改动工作副本。报告中应区分两条路径——TSK 直接提取用于已删除文件，挂载浏览用于活跃文件。

**不能证明**：这些密钥被使用过。密钥存在于空闲空间只说明"曾写入过"，不说明"曾被调用"；使用痕迹要去网络日志、云平台审计日志里找。

**误判对照**

最像的误判是把 `blkls` 出的未分配块当作"整盘的空闲空间"，因此在 NTFS 侧未命中后就写"未发现凭据残留"。

判据要落到扇区算术上：`blkls -o 2048` 只处理从扇区 2048 开始的 NTFS 分区范围，ext4 分区（Start 258048）内部被删除文件的残留、以及两者之间 3780 个扇区的分区间隙，两块区域它都完全没覆盖；本案的两条命中恰好一处在间隙、一处在某个文件系统内部，只查一层必然漏掉一半。

正确判据是以 `mmls` 的分区表为索引，逐个分区列出空闲区域：每个分区内用 `blkls -o <起始扇区>`，间隙用 `dd` 按扇区直接切。

按错误判据走的代价是报告给出假阴性——委托方据此认为凭据未泄露，密钥实际仍在镜像里，一旦它仍然有效，后果由委托方承担。

<a id="section-33"></a>

### 5.2 挂载前后的哈希对得上：把副作用关在选项里

**场景**

同一案件中，分析员需要浏览 ext4 分区的目录树来定位一份文件。他知道 TSK 能免挂载提取，但他更熟悉 `ls`。

选择这一路径的依据是**挂载本身不必然危险，但默认选项会写**——真正要做的是把每一种可能的写入都显式关掉。

**处置过程**

关键在于四个选项各自挡掉一件事，缺一个就可能留下痕迹：

```bash
sudo losetup -r --find --show -P /work/DigiForensics.dd   # ① -r：loop 设备层只读
sudo blockdev --setro /dev/loop0                          # ② 块设备层再设只读
sudo mount -t ext4 -o ro,noload,noatime,noexec /dev/loop0p2 /mnt/evidence
```

```text
ro      禁止写入；这是基础，但仅靠它 ext4 的挂载仍可能写 journal inode
noload  跳过 journal 回放——这一条是关键，不回放就不会因恢复日志而改动数据
noatime  不更新访问时间，否则每读一个文件就在 inode 上留一次写入
noexec  阻止执行镜像内的文件，防止挂载即触发
```

2. 浏览完成后按顺序卸载并解绑，然后**必须复核哈希**：

```bash
sudo umount /mnt/evidence && sudo losetup -d /dev/loop0
sha256sum /work/DigiForensics.dd
```

3. 交接前确认没有残留挂载——**有输出就说明还有镜像被挂在系统上**，这本身就是一条必须写进交接记录的状态：

```bash
losetup -a
mount | grep evidence
```

**结论**

能证明：挂载前后 `DigiForensics.dd` 的 SHA-256 完全一致，即这次只读浏览未改动工作副本。四个选项的组合与卸载顺序均有记录，可复现。

**不能证明**：哈希一致只覆盖镜像这一个文件。本案若用了 Linux LVM 快照或 AUFS 叠加层，覆盖区的写入不体现在镜像哈希里——所以本例坚持直接对镜像文件操作。

**误判对照**

最像的误判是只加 `ro` 就认为安全。判据要落到 ext4 的行为上：ext4 挂载时会检查 journal 状态，若判定需要恢复，它会写入 journal inode（inode 8）——这个动作由文件系统代码在挂载阶段触发，不是应用层写文件，而 `noload` 选项的作用正是"不挂载 journal、不触发恢复"。

另一个常见的疏漏是漏掉 `noatime`：默认挂载会更新读取文件的访问时间，`ls` 看目录、读一个文件，就是在 inode 上留下真实的写入痕迹。

按错误判据走的代价：案例级表现为"我只用了 ro，哈希没变"，实际漏了 `noatime` 时哈希会变，需要重做工作副本；主副本虽未被动过，但这次分析的可信度要打折，且要向委托方解释清楚。

<a id="section-34"></a>

### 5.3 反例：在挂载点里直接打开 SQLite

**场景**

某次分析中，分析员挂载 NTFS 分区后，为了查浏览记录直接在挂载点内执行 `sqlite3 .../Default/History "SELECT ..."`。查询正常返回了数据，当晚哈希复核时发现镜像哈希变化，SQLite 抱怨文件被锁但查询仍出了结果。

这条列为反例，是因为**它的表现是"看起来完全正常"**——不报错、结果正确，只有事后比对哈希才发现问题。

**处置过程**

对照点在于"只读挂载"与"工具以为可写"这两件事的区别：

```bash
# 错误：挂载点是 ro，但 SQLite 以读写方式打开它
sudo mount -o ro,loop /work/DigiForensics.dd /mnt/case
sqlite3 /mnt/case/Users/x/Default/History "SELECT * FROM urls LIMIT 5;"

# 正确：先复制出镜像之外，且 WAL/SHM 一并复制
cp "/mnt/case/Users/x/Default/History"      /tmp/History
cp "/mnt/case/Users/x/Default/History-wal"  /tmp/ 2>/dev/null
cp "/mnt/case/Users/x/Default/History-shm"  /tmp/ 2>/dev/null
sqlite3 /tmp/History "PRAGMA integrity_check;"
```

**结论**

能证明：该次查询在镜像内的 SQLite 数据库上产生了实际写入，且当晚哈希复核已发现镜像哈希与采集记录不一致。写操作本身可由哈希变化证实。

**不能证明**：这次写入具体影响了哪些页。理论上包含 WAL 回放写入与 `-shm` 索引重建，该范围内的内容无法与原有数据区分，也就无法断言查询返回的内容等于镜像被挂载前的状态。

**误判对照**

最像的误判是"挂载点加了 `ro`，所以里面的一切都是只读操作"。

判据在 SQLite 的行为上：它以读写方式打开数据库文件时，会按 journal 模式在旁边创建 `-journal` / `-wal` / `-shm`，并可能回放 WAL。它不会因为所在文件系统被挂成 `ro` 就自己转成只读。回放被内核拒绝时，它报的也只是 "database is locked" 这类提示，查询照样返回缓存里的数据——数据看着是对的，写入已经发生。

正确判据：**任何数据库类工具的输入都必须是镜像之外的副本**。

按错误判据走的代价有两层。本案要重做工作副本；更麻烦的是那份"查询成功返回"的结果本身来路不明，它可能混着 WAL 回放前后的不一致状态，写进报告就是一条不可靠证据。

---
<a id="section-35"></a>

## 六、扩展阅读方向

四组方向，按你在只读接入这条路上会撞到什么排。


**第一组：前置基础——本篇所需的三项基础**

- [证据格式与转换](../imaging-acquire/imaging-acquire-evidence-image-formats.md) —— **E01 挂载的坑在这一篇**。EWF 库不是内核模块，`mount` 之前得先解决 E01 的读取路径；分段文件组完整性、转换后哈希验证都在那里。本篇假设你的输入已经是一个可读的镜像文件，格式问题在那篇解决。
- [镜像制作](../imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— **接入前的哈希校验是本篇的第一个动作**。镜像哈希和采集记录对不上时，你没法判断"自己有没有毁掉证据"。**这句话不是形式，是本篇所有安全措施的前提。**
- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) —— **第三条路径（Windows 侧挂载）的前提**。那一层几乎必然写盘，唯一的补偿是硬件写保护器。**没有写保护器就不要走那条路。**

**第二组：同层深入——各文件系统的深挖**

本篇给的是怎么安全接进去。"接进去之后怎么读"按文件系统分。

- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— `fls` / `istat` / `icat` 在 NTFS 上的完整用法，MFT 记录号与文件引用号的换算、`$DATA` 与 `$FILE_NAME` 的区别，都在那里。本篇讲怎么安全地进去，那篇讲进去之后 `$MFT` 怎么读。
- [NTFS 数据流与隐藏数据](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-alternate-data-streams.md) —— **"接入了文件系统视图"不等于"看到了全部数据"**。命名流、`$I30` 索引、slack、未分配空间这四层，普通挂载下的 `ls` 一个都看不见。"我能打开这个分区"和"我看到了所有内容"之间隔着的就是那篇。
- [ext4 结构与 inode](../../filesystem/filesystem-unix/filesystem-unix-ext4-inode.md) 与 [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— 前者给 `debugfs` 的只读操作链，后者处理 journal 与 dirty 位。本篇 2.2 讲"日志回放会写盘"，那篇讲日志里有什么，同一份数据的两个角度。
- [APFS 容器与快照](../../filesystem/filesystem-apple-fs/filesystem-apple-fs-apfs.md) 与 [F2FS 结构](../../filesystem/filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md) —— 另两种文件系统作对照。APFS 的容器 + 卷 + 快照三层结构意味着"一个分区"不是分析单位，F2FS 的日志机制又有自己的回放规则。

**第三组：相邻议题——另一种接入方式**

- [虚拟机仿真](imaging-mount-simulate-virtual-machine-emulation.md) —— **本篇和那一篇的分工，是这一节最需要分清的一件事**。本篇给你文件系统视图：静态、安全、成本低。那一篇给你程序执行能力：动态、危险、能观察到运行态。大部分案件本篇就够；只有当问题必须"跑起来才知道"时才上仿真。
- [远程勘验与在线取证](../imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 第三种接入方式：**系统根本没关机**。那条路上每个操作都会留痕，本篇的"只读"到了那里被放大成"每处不可避免的痕迹都可解释"。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 接入操作同样有留痕要求：什么时候挂的、用什么参数、哈希校验结果如何。**本篇第四章 4.4 组专门处理这个。**
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— 接入前后的哈希比对是本篇的核心判据，那篇讲判据背后的原理与语义。

**第四组：判据与反例——"只读"这个保证有多强**

最需要警惕的不是参数写错，而是**对"只读"的过度信任**。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **两层含义**。其一，被检系统上运行的恶意驱动可能在你挂载的时候就响应了，本篇第四章 4.1 组"安全风险"那一档讲的就是这个；其二，本篇依赖的文件系统元数据，在有技术能力的对手面前需要独立印证。**挂载成功不等于读到的内容可信。**
- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— 对位思考：**分析工作站一旦接着网，恶意软件就可能横向移动**。本篇讲的是"不让目标盘被写"，那篇讲的是"不让分析环境被攻"。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— **"派生镜像"这个概念正是在这一步产生的**：从 E01 转出的 RAW、为分析做的切片，都是派生物。**它们不是原始检材，提交时要说明来源关系。**

最后压一句本篇最想说的事：**"只读"不是一个参数，是三层机制叠出来的结果**——`blockdev --setro` 锁死块层、`noload` / `norecovery` 不回放日志、`noatime` 不更新访问时间。**少任何一层，镜像哈希都可能变。** 而这三层都只是内核层的约束：Sleuth Kit 那条路根本不需要它们，因为它压根不经过内核。
<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install sleuthkit ewf-tools xmount ntfs-3g

# ===== Sleuth Kit：零写入访问（首选）=====
img_stat /evidence/DigiForensics.dd                 # 镜像类型与扇区大小
mmls /evidence/DigiForensics.dd                     # 分区表（Slot 即后续参数）
fsstat -o 63 /evidence/DigiForensics.dd             # 文件系统详情（-o 为起始扇区）
fls -o 63 -r -p /evidence/DigiForensics.dd          # 递归列目录（含删除）
icat -o 63 /evidence/DigiForensics.dd 11443-128-3 > out.bin   # 提取文件
blkls -o 63 /evidence/DigiForensics.dd | strings | grep -i 'key'  # 未分配空间搜索
mmcat /evidence/DigiForensics.dd 2 > part2.dd       # 按 Slot 提取整个卷

# ===== 只读环设备（三层防护）=====
sudo losetup -r --find --show -P /evidence/DigiForensics.dd  # -r 只读，-P 扫分区
sudo blockdev --setro /dev/loop0                   # 块层锁死只读
blockdev --getro /dev/loop0                        # 输出 1 = 已只读

# 挂载：注意 noload / norecovery / noatime 缺一不可
sudo mkdir -p /mnt/evidence
sudo mount -t ext4  -o ro,noload,noatime,noexec     /dev/loop0p1 /mnt/evidence
sudo mount -t xfs   -o ro,norecovery,noatime,noexec /dev/loop0p2 /mnt/evidence
sudo mount -t ntfs3 -o ro,noatime,noexec            /dev/loop0p3 /mnt/evidence
sudo mount -o ro,noload,noatime,loop /evidence/DigiForensics-part1.dd /mnt/evidence

# 卸载与清理（必须执行）
sudo umount /mnt/evidence
sudo blockdev --setrw /dev/loop0
sudo losetup -d /dev/loop0

# ===== 挂载前后必做：哈希验证 =====
sha256sum /evidence/DigiForensics.dd     # 挂载前后各一次，必须一致

# ===== E01 桥接 =====
sudo ewfmount /evidence/DigiForensics.E01 /mnt/ewf   # → /mnt/ewf/ewf1
sudo xmount --in ewf /evidence/DigiForensics.E01 --out raw /mnt/xmount
sudo mmls /mnt/ewf/ewf1
```

```powershell
# ===== Windows：FTK Imager 只读挂载 =====
# File → Image Mounting... → Block Device / Read Only → 选 E01 → Mount
# 挂载后盘符只读，双击文件提示"拒绝访问"属正常现象
# File → Image Mounting... → 选中 → Dismount 卸载

# ===== Windows：计算镜像哈希 =====
Get-FileHash -Algorithm SHA256 'E:\evidence\DigiForensics.dd'
Get-FileHash -Algorithm MD5    'E:\evidence\DigiForensics.dd'
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 磁盘镜像与仿真 — 只读挂载与安全接入」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《只读挂载与安全接入》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.E01` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
