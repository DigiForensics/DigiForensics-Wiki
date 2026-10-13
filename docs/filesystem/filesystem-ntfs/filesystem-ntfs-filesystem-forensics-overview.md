---
title: "文件系统取证总览"
slug: "filesystem-ntfs-filesystem-forensics-overview"
canonical: "https://www.digiforensics.cn/wiki/filesystem-ntfs-filesystem-forensics-overview"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "filesystem"
space: "文件系统分析"
node_path: ["NTFS"]
---

# 文件系统取证总览

<a id="section-1"></a>

## 一、概述

拿到一块镜像，问"里面有什么"表面上是文件恢复，实际拆开是三层：镜像 → 卷（分区 / LVM / RAID）→ 文件系统。只有第三层才决定"文件叫什么、多大、什么时候改过、删到哪里去了"。

文件系统是数据在磁盘上的组织约定。它规定字节如何被解释成目录、文件、簇、inode，**也决定了空间何时被复用**——删除痕迹之所以能残留，根源就在这里。反取证软件的藏身点几乎都建立在"复用的时机"上，而那个时机由文件系统定义。

同一块磁盘，用 NTFS 解析和用 ext4 解析，得到的目录树可以完全不同。**选错文件系统等于全部结论作废**，不是"效果差一点"，是归零。

这一层判定落在**分析环节的最前端**。上游输入是卷层：镜像格式（E01 还是 raw，转换见[证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md)）与接入方式（见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)）。判定完成后按类型分流——NTFS 进 [NTFS 结构与 MFT 解析](filesystem-ntfs-ntfs-master-file-table.md)、[NTFS 数据流与隐藏数据](filesystem-ntfs-ntfs-alternate-data-streams.md)、[Steady-State 与 LogFile 还原](filesystem-ntfs-steady-state-logfile.md)，ext4 进 [ext4 结构与 inode](../filesystem-unix/filesystem-unix-ext4-inode.md)，FAT 进 [FAT 系列结构](../filesystem-mobile-fs/filesystem-mobile-fs-fat.md)，APFS 进 [APFS 容器与快照](../filesystem-apple-fs/filesystem-apple-fs-apfs.md)，F2FS 进 [F2FS 结构](../filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md)，内容识别进 [文件头与文件签名](filesystem-ntfs-file-headers-and-signatures.md)。这一层负责判定"这是什么"，各分支负责"把它读透"。

判定依据是有确定偏移的特征字段，不是抽象分类：

- **`NTFS    ` 在卷起始偏移 3** —— Boot sector 的 OEM ID（`55 4F 46 53 20 20 20`）
- `0xEF53` 在卷起始偏移 1024（0x400） —— ext2/3/4 超级块的 `s_magic`。**前面 1024 字节是引导区**，所以偏移是 1024 不是 0，这是最常记错的一个
- **`NXSB` 在分区 + 32（0x20）** —— APFS 容器头。**注意是分区偏移，不是卷偏移**
- **`APSB` 在卷首偏移 0** —— 每个 APFS 卷各自一份
- `FAT12` / `FAT16` / `FAT32` 文本 preceded by 跳转指令 `0xE9` / `0xEB` —— FAT 家族
- **`EXFAT   ` 在偏移 3** —— exFAT。**它没有标准 BPB**，别按 FAT32 的 BPB 去读
- **`H+`（`0x482B`）在偏移 1024** —— HFS+（嵌入式场景 +18）
- `SWAPSPACE2` / `SWAP-SPACE` —— Linux swap，**swap 也要单独 dump**
- **`LABELONE`** —— LVM2 元数据区
- `mmls` 的 Unallocated 行 vs `blkls` 的未分配簇 —— **卷层的"未分配"与文件系统层的"未分配"是两回事**，前者是分区表没占的区间，后者是文件系统内部还没分配的簇。反取证软件最常见的藏身点就是这两处
- **第三章 3.6 的熵检测** —— `ent -b` 的 Shannon 熵接近 8.0 通常对应加密或已随机化填充的数据。压缩数据与部分二进制格式同样高熵，熵值只能作筛选条件，需配合卷层证据定性

判定之后能回答的是这些：卷上跑的是什么文件系统（靠魔数、靠结构区，**不靠扩展名也不靠体积**）、一块盘上有多套系统该怎么逐卷处理，以及——**最关键的**——**怎么判断自己是不是解析错了**。

最后一条来自 2.5 那句"部分正确、部分错误最危险"：判断标准应是目录数量和文件数量是否合理，而不是"命令有没有报错"。偏移少加一个扇区时，工具偶尔仍能出目录名，**这种"看起来成功"比明确报错危害大得多**——它让人以为已经检查过了。

有几件事不归这一层管：**任何一种文件系统的具体结构**，解析在分支篇里；**LVM / 动态磁盘 / RAID 的重组**，2.4 表格里写了"需 `mmstat` 或专有工具重组"；**加密卷的内容**，识别出 BitLocker 之后怎么解是加密篇的事；**时间戳怎么读**，这里只判定"这是 NTFS"，`$STANDARD_INFORMATION` 里四个时间戳的语义在时间戳篇。

往下读之前，需要**分区表（MBR / GPT）与卷层概念**，以及基本的十六进制读取能力——全程都在"相对卷起始的偏移"上计算，而最容易出的错就是**偏移的基址搞混**（分区起始 vs 卷起始 vs 磁盘起始）。

另外强烈建议先读一遍[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)的检验阶段：这里的全部命令都是在工作副本上跑的，不是原始介质。 第三章步骤 5 那个"卷清单"登记表之所以要记 Slot、起始扇区、文件系统类型、目录条目数四项，就是为了让复核者能重走一遍——**登记格式本身就是可追溯性**。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 三层结构与工具对应

| 层 | 回答的问题 | Sleuth Kit 工具 | 典型失败模式 |
|---|---|---|---|
| **Image** | 镜像格式、扇区大小 | `img_stat` | E01 当 raw 读，全盘乱码 |
| **Volume** | 分区表、LVM、RAID | `mmls` / `mmstat` | 把分区间隙当数据 |
| **File System** | 目录树、元数据、内容 | `fsstat` / `fls` / `icat` | 偏移错位、类型误判 |

**关键点**：卷层的"未分配"和文件系统层的"未分配"是两回事。前者是分区表没占用的区间（`mmls` 的 Unallocated 行），后者是文件系统内部还没分配的簇/块（需 `blkls`）。

**反取证软件最常见的藏身点就是这两处。**

<a id="section-4"></a>

### 2.2 三大主流系统对比

| 维度 | **NTFS** | **ext4** | **APFS** |
|---|---|---|---|
| 平台 | Windows / Linux 双系统 | Linux | macOS / iOS |
| 核心数据库 | `$MFT`（每文件一条 1024 字节记录） | inode 表（分散于块组） | APFS B-tree（对象容器） |
| 元数据集中度 | **极高**，几乎全在 `$MFT` | 中，inode + 目录散落 | **极高**，单一 B-tree |
| 删除痕迹 | `$FILE_NAME` 保留原名+父引用 | inode 保留时间戳+大小，文件名易丢 | B-tree 中对象可残留 |
| 内建版本机制 | 卷影副本（快照） | 无（日志 + 备份工具） | **原生快照 + checkpoint** |
| 加密支持 | BitLocker / EFS（卷级/文件级） | LUKS/dm-crypt（卷级） | 原生整容器加密 |
| 时间戳 | 4 个（创建/修改/访问/变更） | 常见 3–4 个（纳秒精度） | `created` / `modified` |
| 日志/日志还原 | `$LogFile`（可回放元数据） | journal（可回放） | checkpoint 映射 + B-tree 事务 |
| 取证友好度 | ★★★★★ 工具最全 | ★★★★ 工具成熟 | ★★★ 工具少、加密普遍 |
| 恢复难度 | 低（有明确元数据记录） | 中 | 高（加密 + 工具少） |

**一个反直觉但重要的点**：APFS 在"元数据集中度"上比 NTFS 更高——它把所有文件、目录、符号链接的属性统一塞进 B-tree 节点。

这理论上更利于完整解析，实际却因为**加密默认开启 + 公开解析工具少**而更难取证。

<a id="section-5"></a>

### 2.3 文件系统识别：靠魔数，不靠扩展名或体积

判别顺序永远是**先看结构区，再看特征字段**。以下为各系统在卷起始处的签名（偏移均相对卷/文件系统起始，**不是磁盘起始**）：

| 文件系统 | 相对偏移 | 签名/特征 | 备注 |
|---|---|---|---|
| **NTFS** | 偏移 3 | `NTFS    ` （55 4F 46 53 20 20 20） | Boot sector OEM ID |
| **ext2/3/4** | 偏移 **1024**（0x400） | 超级块 `s_magic = 0xEF53` | 前面 1024 字节是引导区 |
| **APFS 容器** | 偏移 32（0x20） | `NXSB` | 容器头 magic；`APSB` 是卷超级块 |
| **APFS 超级块** | 偏移 0（卷首） | `APSB` | 每个 APFS 卷各自一份 |
| **FAT12/16/32** | 偏移 0 | 跳转指令 + `FAT12`/`FAT16`/`FAT32` 文本 | 0xE9/0xEB 开头 |
| **exFAT** | 偏移 3 | `EXFAT   ` | Boot sector |
| **HFS+** | 偏移 1024（0x400） | `H+` (0x482B) | 嵌入式场景 +18 |
| **swap** | 偏移 0/页尾 | `SWAPSPACE2` / `SWAP-SPACE` | Linux swap |
| **LVM2** | 元数据区 | `LABELONE` | 卷组元数据区 |

**判不要用命令**：

```bash
mmls /evidence/DigiForensics.dd              # ① 卷层：TSK 直接给出类型判断
fsstat -o 63 /evidence/DigiForensics.dd      # ② 文件系统层：读超级块
xxd -l 1024 -s $((63*512)) /evidence/DigiForensics.dd | head -20   # ③ 兜底：看魔数
sudo blkid -p -o full /evidence/DigiForensics.dd                   # ④ Linux 侧独立判定
```

> **注意区分**：`file` 只能识别整个镜像文件，**不能识别镜像内的分区**。要判断分区类型必须用 `blkid -p`（探测模式）或 TSK 的 `fsstat`。

<a id="section-6"></a>

### 2.4 多卷 / 多分区场景

| 布局 | 典型来源 | 处理要点 |
|---|---|---|
| EFI + 系统 + 数据（3 分区） | Windows 现代安装 | 每个分区独立 `fsstat`/`fls` |
| 共享 + 家庭 + 恢复（3 分区） | Windows OEM | 恢复分区可能是 FAT32 小卷 |
| GPT + ESP(FAT32) + root(ext4) + swap | Linux | swap 也要单独 dump |
| APFS 容器（1 分区内多卷） | macOS | 见 [06](../filesystem-apple-fs/filesystem-apple-fs-apfs.md) |
| LVM 逻辑卷 / 动态磁盘 / RAID | 服务器 | 需 `mmstat` 或专有工具重组 |

处理原则：逐卷独立解析，结果用「卷标识 + 元数据坐标」双重引用。

例如"卷 2（NTFS）MFT 条目 11443"比"某文件"精确得多，且可复核。

<a id="section-7"></a>

### 2.5 为什么"选错文件系统"是灾难性错误

| 误判 | 表现 | 危害 |
|---|---|---|
| 把 APFS 容器当 ext4 | 目录树全空 + 大量 I/O 错误 | **误判为"已擦除"而结案** |
| 把 BitLocker 卷当 NTFS | 文件名全乱码 | 误判"文件已损坏" |
| 偏移少加一个扇区 | 偶尔能出目录名 | **最危险**：部分正确、部分错误，结论互相矛盾 |
| 用 FAT 解析器读 exFAT | 只能列出根目录 | 漏掉深层数据 |

**最后一条最危险**：部分解析成功会给人"已经检查过"的错觉。判断依据应是**目录数量和文件数量是否合理**，而不是"命令有没有报错"。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：确认镜像本身

```bash
# 镜像格式、扇区大小、总容量
img_stat /evidence/DigiForensics.dd

# 分配 E01 → raw
ewfverify /evidence/DigiForensics.E01        # 先验证完整性
ewfexport -t raw -u /tmp/ewf1 /evidence/DigiForensics.E01 -f /work/DigiForensics.dd
img_stat /work/DigiForensics.dd
```

<a id="section-10"></a>

### 3.2 第 2 步：解析分区表（卷层）

```bash
# MBR/GPT 通吃
mmls /work/DigiForensics.dd

# 输出示例（务必逐列记录）
# Slot      Start        End          Length       Description
# 00: Meta  0000000000   0000000000   0000000001   Primary Table (#0)
# 01: ----- 0000000000   0000000062   0000000063   Unallocated
# 02: 00:00 0000000063   0009510479   0009510417   NTFS (0x07)
# 03: ----- 0009510480   0009514259   0000003780   Unallocated
```

> **记录规范**：把 `mmls` 完整输出作为附件存档，后续所有操作都引用 Slot 与起始扇区。

<a id="section-11"></a>

### 3.3 第 3 步：逐卷判定文件系统类型

对每个非 Unallocated 的 Slot 逐一执行：

```bash
# 以 Slot 02（起始扇区 63）为例
fsstat -o 63 /work/DigiForensics.dd

# 关键字段：
#   NTFS  → File System Type: NTFS / MFT Cluster / Boot Sector Cluster
#   ext4  → File System Type: Ext4 / Block Size / Inode Size / Journal Inode
#   FAT   → File System Type: FAT / Cluster Size / Root Directory Sector
#   APFS  → APFS 容器需用专门工具（见 06 篇）
```

若 `fsstat` 报"Cannot determine file system type"，按下列顺序排查：

```bash
xxd -l 64 -s $((63*512)) /work/DigiForensics.dd            # ① 偏移是否算错
blkcat -o 63 /work/DigiForensics.dd 1000 | file -          # ② 是否加密卷（高熵随机字节）
blkcat -o 63 /work/DigiForensics.dd 0 | xxd | head         # ③ 是否根本没格式化
sudo blkid -p -o full -O $((63*512)) /work/DigiForensics.dd  # ④ 独立工具复核
```

<a id="section-12"></a>

### 3.4 第 4 步：确认类型后展开目录树

```bash
# NTFS：递归 + 完整路径 + 包含已删除（-r 递归 -p 全路径）
fls -o 63 -r -p /work/DigiForensics.dd > /evidence/fls-vol2.txt
wc -l /evidence/fls-vol2.txt        # 行数量级是否合理？0 或 1 行 = 解析失败
fls -o 258048 -r -p /work/DigiForensics.dd > /evidence/fls-vol3.txt   # ext4 同上
fls -o 2048 -r /work/DigiForensics.dd                                # FAT 无 Unix 权限，可省 -p
```

**验证环节（不可省略）**：

```bash
# ① 抽查根目录：能否列出 Windows 的 Users / Windows，或 Linux 的 /home /etc
head -40 /evidence/fls-vol2.txt

# ② 随机抽 3 个文件，提取内容并确认魔数与文件名相符
icat -o 63 /work/DigiForensics.dd 11443-128-3 > /tmp/t1.bin
file /tmp/t1.bin

# ③ 文件系统类型与卷标/序列号是否与预期一致
fsstat -o 63 /work/DigiForensics.dd | grep -iE 'volume|serial|label'
```

只有当"目录树合理 + 抽查文件可读 + 魔数相符"三者同时成立，才认定解析成功。

<a id="section-13"></a>

### 3.5 第 5 步：登记卷清单

把每个卷的判定结果整理成表，作为后续所有文章的索引：

| Slot | 起始扇区 | 大小 | 判定文件系统 | 目录条目数 | 备注 |
|---|---|---|---|---|---|
| 02 | 63 | 487 MB | NTFS | 48,213 | 系统盘 |
| 03 | 258048 | 512 GB | ext4 | 190,442 | 数据盘，journal 待回放 |
| 04 | 1053184 | 1.1 GB | FAT32 | 132 | ESP |
| — | 951048 | 14,200 | 未分配 | — | **必须单独搜索** |

<a id="section-14"></a>

### 3.6 第 6 步：不能挂载时的新兴文件系统

APFS、F2FS 的成熟 TSK 支持有限，可改用魔数确认 + 专用工具（见 [06](../filesystem-apple-fs/filesystem-apple-fs-apfs.md)/[07](../filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md)）：

```bash
mmcat /work/DigiForensics.dd 5 > /work/DigiForensics-apfs.dd
xxd -s 32   -l 4 /work/DigiForensics-apfs.dd   # APFS 容器期望 4e58 5342 = "NXSB"
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd  # F2FS 期望 f2f5 2010
dd if=/work/DigiForensics-apfs.dd bs=1M count=64 2>/dev/null | ent -b   # 熵≈8.0 疑似加密
```

> `ent` 来自 `entropy` 包（`apt install entropy`），Shannon 熵接近 8.0 通常说明数据高度随机，压缩数据与部分二进制格式同样如此，需配合卷层证据定性。

---
<a id="section-15"></a>

## 四、常见陷阱

本章按「镜像与卷层 → 文件系统类型判定 → 目录树展开与验证 → 结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 镜像与卷层

<a id="section-17"></a>

#### 陷阱 1：把 E01 当 raw 直接读，全盘乱码

**现象**：用 `fls`/`fsstat` 直接作用于 `DigiForensics.E01`，报无法识别；换成十六进制查看全是零散字节，判为"镜像损坏"。

**原因**：E01（EWF）是封装格式，raw 是裸扇区流，两者不是同一件事。E01 内部按数据段压缩存储并带元数据头，**它的字节布局与裸扇区完全不同**。

`mmls`/`fsstat`/`fls` 这些 TSK 工具默认按 raw 解释输入，遇到 E01 时它们读到的是压缩段数据与元数据，自然无法解析出分区表。

而"输出是一堆乱码"这个现象，在直觉上很容易被归因于镜像损坏或读取失败。

**影响**：**"镜像损坏"是一个关于证据可用性的严重结论**。一旦写进报告，委托方可能要求重新扣押、重新成像——而设备可能已经发还。**实际上镜像完好无损**，只是用错了读取方式。

**核查**：E01 先验证完整性再导出 raw，之后所有分析都在 raw 上进行（3.1）：

```bash
img_stat /evidence/DigiForensics.E01
# 先验证——E01 的压缩段可能记录了分段哈希
ewfverify /evidence/DigiForensics.E01
# 导出为 raw（-u 分块、-f 指定输出）
ewfexport -t raw -u /tmp/ew1 /evidence/DigiForensics.E01 -f /work/DigiForensics.dd
img_stat /work/DigiForensics.dd
```

**如果 TSK 版本支持 E01 直读**（部分工具有 `-t ewf` 之类的选项），也仍建议保留导出的 raw——后续工具链对 raw 的兼容性最好，且导出过程本身是一次完整性验证。

`ewfverify` 一定要在 `ewfexport` 之前跑。顺序反了，你会在不知道镜像是否完好的前提下开始分析。

<a id="section-18"></a>

#### 陷阱 2：漏读分区间隙，把最大的藏身点跳过了

**现象**：`mmls` 输出里有一大段 `Unallocated`，直接跳过，只对有类型的 Slot 做解析，报告结论"未发现反取证软件"。

**原因**：**卷层的"未分配"和文件系统层的"未分配"是两回事**（2.1 的关键点）。前者是**分区表没占用的区间**（`mmls` 的 Unallocated 行），后者是文件系统内部还没分配的簇/块（需 `blkls`）。

**反取证软件最常见的藏身点就是这两处**，而**卷层的间隙往往比任何文件系统的空闲区都大**——案例里 15,340 个扇区（约 7.5 MB）的间隙完全独立于任何文件系统。

卷层间隙体积大，是因为它不受任何文件系统管理。

**影响**：这是一个关于"不存在"的结论，而它建立在"没查"之上。"未发现反取证软件"在委托方语境下常被理解为"这台机器没有反取证行为"，而实际上那个 780 GB 分区的间隙从未被看过。

**核查**：把 `mmls` 的每一行都处理掉，Unallocated 也要切出来搜：

```bash
# mmls 完整输出存档，后续所有操作引用 Slot 与起始扇区
mmls /work/DigiForensics.dd | tee /evidence/mmls.txt
# 切出间隙并做关键字搜索
dd if=/work/DigiForensics.dd of=/tmp/gap.bin bs=512 \
   skip=169558016 count=15340 status=none
strings -n 20 /tmp/gap.bin | grep -icE 'document|confidential'
```

**结论里要分清两句话**："在卷层间隙（`<起>`–`<止>`，`<大小>`）内搜索未发现目标关键字"和"未发现反取证软件"。

**前者是可辩护的，后者超出了证据范围**——同一镜像上还有 NTFS 与 ext4 各自的空闲区没查。

<a id="section-19"></a>

#### 陷阱 3：★ 在原始镜像上做挂载或写入类操作

**现象**：为方便浏览，把 `DigiForensics.dd` 挂载到 `/mnt/image`，用完忘记卸载；或让解析工具直接在原始镜像路径上输出结果文件。

**原因**：**"只读挂载"在直觉上是安全的**——命令里的 `ro` 参数也确实存在。但**是否被遵守取决于挂载参数与文件系统实现的实际行为**，而且不同文件系统、不同驱动对"只读"的实现程度并不一致。

更隐蔽的是**很多工具的默认输出路径就是当前工作目录**——在原始镜像旁边写 `fls.txt` 之类的文件，可能触发所在目录文件系统（ext4 的延迟分配、`lost+found` 更新）的写入。

**影响**：**原始检材被污染，且污染难以被察觉**。它不会产生明显的错误，只会让原始状态无法自证——而"该镜像是否与扣押时一致"这个问题一旦被提出，**当时没做基线记录，事后就没有证据了**。

**核查**：主副本只读封存，永不挂载；所有操作在独立的工作副本上进行（案例开篇就明确了这一点）：

```bash
# 主副本：只读封存，不挂载、不写入
chmod 444 /evidence/DigiForensics-master.dd
chattr +i /evidence/DigiForensics-master.dd
# 工作副本：分析全在这里做
cp --reflink=auto /evidence/DigiForensics-master.dd /work/DigiForensics.dd
# 挂载前打基线，挂载后校验
sha256sum /work/DigiForensics.dd > /evidence/baseline.sha256
# …… 挂载与读取 ……
sha256sum -c /evidence/baseline.sha256
```

**输出路径要显式指定到工作区**，不要依赖工具的默认相对路径。

这条没有技术含量，但违反的频率最高。

<a id="section-20"></a>

### 4.2 文件系统类型判定

<a id="section-21"></a>

#### 陷阱 4：把 `mmls` 的 Description 当作文件系统类型

**现象**：`mmls` 显示 Slot 03 为 `EFI System Partition`，直接按 GPT 类型理解为"EFI 相关"，不再独立判定它是 FAT32 还是别的。

**原因**：`mmls` 的 Description 反映的是分区表里的类型 ID，不是文件系统。GPT 的 `EFI System Partition` 类型标识确实约定用 FAT 格式，**但这是约定而非强制**——工具创建、分区工具行为、跨平台改写都可能留下不符合约定的卷。

案例里那个 1 MB 的槽位，`mmls` 只标了类型没标文件系统，**必须用 `fsstat` 独立确认**才是 FAT32。

**影响**：**类型误判会连锁影响所有后续操作**——用错解析器会让目录列表为空或报错，而这又容易被误读为"该分区是空的"。

案例里第 4 个 130 MB 分区正是这种情况：**判定为 ext4 但目录条目仅 2 项**，如果不深究就会得出"隐藏系统"的错误结论。

**核查**：对每个非 Unallocated 的 Slot 逐一独立判定，并把结果记进卷清单（3.5）：

```bash
fsstat -o 2048      /work/DigiForensics.dd     # → NTFS
fsstat -o 1053184   /work/DigiForensics.dd     # → FAT32（mmls 未标 FS，必须独立确认）
fsstat -o 1064960   /work/DigiForensics.dd     # → ext4
# 兜底：直接看魔数（偏移相对卷起始，不是磁盘起始）
xxd -l 64 -s $((2048*512)) /work/DigiForensics.dd
```

**判别顺序永远是先看结构区、再看特征字段**（2.3）：`NTFS    ` 在卷起始 +3、`0xEF53` 在 +1024、`NXSB` 在 +32、`EXFAT   ` 在 +3。

**这些偏移全是相对卷/文件系统起始的**——**相对磁盘起始是本条陷阱最常见的变形**。

<a id="section-22"></a>

#### 陷阱 5：`fsstat` 报 "Cannot determine file system type" 就判为未格式化

**现象**：对某卷执行 `fsstat` 报错，报告写"该分区未格式化或数据已被清除"。

**原因**：**同一句报错至少对应四种成因**（3.3 的排查顺序）：偏移算错、**卷已加密**（高熵随机字节，超级块读不出来）、根本没格式化、以及新兴文件系统 TSK 暂不支持。

**加密卷是最容易被误判的一种**——它的扇区全是随机数据，超级块位置自然读不出有效的 `0xEF53`。而"读不出超级块"与"没有超级块"在报错上完全一致。

**影响**：**"未格式化或已清除"是关于数据存在与否的强结论**。若真相是 BitLocker/LUKS 加密，委托方接下来会走"找密钥"的方向，而"数据已被清除"这个结论可能已经写进了对外文件。

更严重的是——**一个加密分区里的数据往往正是案件核心**。

**核查**：**按四步顺序排查，不要跳步**：

```bash
# ① 偏移是否算错——用 mmcat 取出该槽位再判
mmcat /work/DigiForensics.dd 5 > /tmp/vol5.dd
fsstat /tmp/vol5.dd
# ② 是否加密卷（看熵）
blkcat -o 63 /work/DigiForensics.dd 1000 | file -        # 高熵随机字节
dd if=/work/DigiForensics.dd bs=1M count=64 skip=$((63*2048)) 2>/dev/null | ent -b
# ③ 是否根本没格式化（看是否有引导特征）
blkcat -o 63 /work/DigiForensics.dd 0 | xxd | head
# ④ 独立工具复核
sudo blkid -p -o full -O $((63*512)) /work/DigiForensics.dd
```

**注意熵值只能作辅助**：`ent` 接近 8.0 说明"高度随机"，压缩数据、部分二进制格式同样高熵。

**它是筛选器不是结论**，定性加密要配合卷层证据（分区类型 GUID、卷头标识）。

<a id="section-23"></a>

#### 陷阱 6：用 `file` 判断镜像内的分区类型

**现象**：对镜像执行 `file DigiForensics.dd`，输出的类型与实际分区不符（显示为 "DOS MBR executable" 或 "data"），据此认为分区类型判定失败。

**原因**：`file` 只能识别整个镜像文件，不能识别镜像内的分区（2.3 的明确提示）。它的判据是文件头部魔数——对一张含分区表的磁盘镜像，它看到的是 MBR/GPT 的引导结构，而不是里面的文件系统。

而 `blkid` 在不加 `-p` 时同样有这个问题：它默认扫描块设备，在普通文件上会尝试按偏移探测，可能给出错误结果或什么都不输出。

**影响**：误以为"识别工具不适用"，转而手工判断，效率低且容易出错。更麻烦的是它可能给出一个"看起来合理但错误"的类型——报告里写"该分区为 DOS MBR executable"会让读者困惑。

**核查**：**用带探测模式的工具，或用 TSK 逐槽位判定**：

```bash
mmls /work/DigiForensics.dd                      # TSK 直接给出分区类型判断
fsstat -o 63 /work/DigiForensics.dd              # 文件系统层
sudo blkid -p -o full -O $((63*512)) /work/DigiForensics.dd   # -p 探测模式 + -O 指定偏移
# file 只能告诉你镜像容器是什么
file /work/DigiForensics.dd
```

`-p`（探测模式）与 `-O`（偏移）两个参数在 `blkid` 上是必需的，缺任何一个都可能给出与实际不符的输出。

`-p` 是探测，`-O` 是告诉它从哪儿开始探测。

<a id="section-24"></a>

### 4.3 目录树展开与验证

<a id="section-25"></a>

#### 陷阱 7：★ `fls` 输出只有 0–1 行却继续后续步骤

**现象**：`fls -o 63 -r -p` 的输出文件只有一行（通常是元数据行），分析员认为该卷内容极少，直接进入内容提取阶段。

**原因**：`fls` 输出 0 或 1 行是解析失败的典型特征，不是"卷是空的"（3.4 的验证环节）。TSK 在无法正确解析时会输出极少内容而**不报错或只给出警告**。

而"这个卷里的文件很少"与"我没能解析这个卷"在现象上完全一致——**前者是关于数据的事实，后者是关于工具的状态**。这类工具静默失败的情况很常见，尤其是对新兴文件系统或加密卷。

**影响**：一个"内容极少"的卷如果实际有几十万文件，报告里"该卷仅含 X 个文件"就是完全错误的结论。而这种错误在后续分析中不会被发现——你会基于一个空目录树做关键词搜索、做时间线，**得到一片空白并把它当成"没有发现"**。

**核查**：目录树、抽查文件、魔数相符三项必须同时成立才算解析成功（3.4）：

```bash
fls -o 63 -r -p /work/DigiForensics.dd > /evidence/fls-vol2.txt
wc -l /evidence/fls-vol2.txt        # 行数量级是否合理？0 或 1 行 = 解析失败
# ① 抽查根目录：能否列出 Windows 的 Users/Windows 或 Linux 的 /home /etc
head -40 /evidence/fls-vol2.txt
# ② 随机抽 3 个文件，提取内容并确认魔数与文件名相符
icat -o 63 /work/DigiForensics.dd 11443-128-3 > /tmp/t1.bin && file /tmp/t1.bin
# ③ 文件系统类型与卷标/序列号是否与预期一致
fsstat -o 63 /work/DigiForensics.dd | grep -iE 'volume|serial|label'
```

**量级合理性检查是最快的第一道闸**——一个 Windows 系统盘的目录条目在数万量级是正常的，**如果得到个位数，先怀疑解析而不是先写结论**。

一条命令，零成本。

<a id="section-26"></a>

#### 陷阱 8：只用 `fls` 不看空闲区，漏掉已删除文件

**现象**：用 `fls` 递归列目录（含 `-d` 看删除项），据此写"该卷无相关文档"，未分配空间完全没查。

**原因**：**`fls` 只能列出文件系统元数据中可寻址的项**——**已删除但元数据尚未被复用的内容不在其中**。

而在 NTFS 上，删除是把数据簇放回 `$MFT` 的空闲位图，**数据本身往往还在原处**；ext4 上删除会释放 inode 与数据块，**内容通常也还在**。

反取证软件的第一件事就是删文件，而删除不会立刻抹掉内容。

**影响**："未发现相关文档"是委托方最常依赖、也最脆弱的一个结论。在涉及文件删除的案件里，空闲区往往是唯一的证据来源。

**核查**：空闲区必须单独提取并搜索，且关键词要覆盖文件名与内容**：

```bash
# NTFS：blkls 提取未分配簇；ext4：blkls 或直接按块组
blkls -o 63 /work/DigiForensics.dd > /work/unalloc-ntfs.bin
# 关键字搜索（文件名型）
strings -n 6 /work/unalloc-ntfs.bin | grep -iE '合同|报告|project|proposal'
# 按内容签名定位
foremost -i -t all -o /work/carved /work/unalloc-ntfs.bin
# 关键：carving 结果必须按哈希去重后再统计
find /work/carved -type f -exec sha256sum {} \; | sort -u | wc -l
```

**报告里要分清三种"未发现"**（这是本篇的核心纪律）：

| 结论类型 | 覆盖范围 | 表述 |
|---|---|---|
| 目录树内未发现 | 活动文件的目录项 | "在卷 `<标识>` 的目录树中未发现……" |
| 空闲区未发现 | 未分配空间（文件名型关键字） | "在卷 `<标识>` 未分配空间中以 `<关键字>` 搜索，未发现……" |
| 全卷未发现 | 活动 + 空闲 + 间隙 | "在 `DigiForensics.dd` 全卷范围（含空闲区与卷间隙）内搜索，未发现……" |

**这三句话的可信度完全不同**，混用会让委托方高估"未发现"的强度。

<a id="section-27"></a>

### 4.4 结论表述

<a id="section-28"></a>

#### 陷阱 9：★ 把"格式化后未使用"当成"隐藏系统"或反过来

**现象**：某个分区目录条目极少，报告在"格式化后基本未使用"与"存在隐藏系统"之间二选一，措辞为"该分区已格式化但基本未使用，不是隐藏系统"。

**原因**：**一个 98% 空闲的分区，其状态有多种可能**——格式化后未使用、格式化前被完整擦除、文件系统已格式化但数据被移走、系统装在别处而这个分区是遗留的。

"目录条目 2 项 + 空闲率 98% + 无大文件"这三项一致的证据，支持"格式化后未使用"这个判断——但**支持某一种解释不等于排除了所有其他解释**。

案例里那句"此判断因'目录数 + 空闲率 + 无大文件'三项一致才成立"，**关键在"三项一致"而不是"结论唯一"**。

**影响**：两种方向都错。**把格式化分区说成隐藏系统**，会引导委托方重点排查一个空分区，浪费资源并可能忽略真正的目标；**把隐藏系统说成格式化分区**，则直接漏掉了整套证据。

后者在双系统、混合环境的笔记本上并不罕见——Linux 装在另一分区时，前一个残留分区看起来就像"格式化后未使用"。

**核查**：**三项独立证据交叉，并写明未覆盖的范围**：

```bash
# 证据 1：目录条目数
fls -o 1064960 -r -p /work/DigiForensics.dd | wc -l          # → 2（仅 / 与 /lost+found）
# 证据 2：空闲率
fsstat -o 1064960 /work/DigiForensics.dd | grep -iE 'free|block'  # → 98% 空闲
# 证据 3：无大文件
blkls -o 1064960 /work/DigiForensics.dd > /tmp/vol4-unalloc.bin
strings -n 20 /tmp/vol4-unalloc.bin | grep -icE 'linux|grub|systemd'   # → 0
```

**报告写法**："该分区（Slot 04，起始扇区 1064960）判定为 ext4，目录条目仅 2 项，空闲率 98%，空闲空间内未检出系统相关关键字。**三项证据一致支持'格式化后基本未使用'的判断。** 本次未对该分区做全量文件雕刻与日志分析，若需进一步确认，建议补充 `<具体手段>`。"

**注意报告里每个分区都要有结论**——留空白的分区会在复核时被追问，而"没写"与"没有"在委托方眼里是同一件事。

哪怕结论是"本分区未做进一步分析"。

<a id="section-29"></a>

#### 陷阱 10：卷清单里缺关键字段，后续所有结论无法归属

**现象**：报告正文提到"该 ext4 分区中发现目标文件"，但没有写是哪个 Slot、哪个起始扇区、哪个卷序列号。

**原因**：**一个镜像上常有多个同类文件系统**——案例里就有两个 ext4 分区（130 MB 与 780 GB），还有一个 FAT32 ESP。

"该 ext4 分区"这个指代在双系统或多卷场景下是有歧义的，而"在其中一个里发现"与"在另一个里也发现"对案件的意义完全不同。

**影响**：**报告失去可复核性**。复核者不知道该去哪个分区核对，只能全部重查——**而这在质证环节是致命的**，因为复核者找不到你说的东西就等于你的结论不成立。

**核查**：**卷清单是所有后续文章的索引，必须先建好再往下做**（3.5）：

| Slot | 起始扇区 | 大小 | 判定文件系统 | 目录条目数 | 备注 |
|---|---|---|---|---|---|
| 02 | 2048 | 524 MB | NTFS | 51,882 | Windows 系统盘 |
| 03 | 1053184 | 1 MB | FAT32 | 3 | 正常 ESP |
| 04 | 1064960 | 130 MB | ext4（98% 空闲） | 2 | 格式化后未使用 |
| 05 | 1181696 | 780 GB | ext4 | 213,776 | Linux 主分区 |
| 06 | 169558016 | 未分配 | — | — | 已提取并关键字搜索 |

**正文中每一次引用都要带全标识**："在 Slot 05（起始扇区 1181696，ext4）中……"。

**卷序列号要一并记录**（`fsstat | grep -iE 'serial|volume'`）——它是文件系统级别的卷标识，在同类型卷并存时是唯一可靠的区分依据。

<a id="section-30"></a>

#### 陷阱 11：把"该卷无 X"扩大为"该设备无 X"

**现象**：在 Windows 系统卷上搜索某类文档无结果，报告结论"该设备内不存在涉案文档"。

**原因**：**单个卷的结论只覆盖那个卷**。一个多分区设备上，未搜索的部分包括：其他分区的活动区、各文件系统内部的空闲区、卷层的间隙、以及**已删除但元数据仍可寻址的项**（`fls` 需配合相应参数）。

"在一个卷里没找到"与"在整台设备里不存在"之间隔着一整份搜索范围清单。案例里那句"分区间隙 15,340 扇区（约 7.5 MB）已独立搜索，未发现文档类残留"，就是这种范围声明的具体形态。

**影响**：这是取证报告里最常见、也最容易被对方攻击的过度概括。委托方读到"该设备不存在涉案文档"，可能据此停止排查其他载体（云盘、移动硬盘、邮箱），而实际搜索范围远小于问题涉及的范围。

**核查**：**结论句里必须嵌入范围限定词**，把"在什么范围内、用什么方法、搜了什么"写全：

> "在 Slot 02（NTFS）的目录树内（51,882 个活动条目）与 Slot 06（卷间隙，15,340 扇区）中，以 `<关键字列表>` 搜索，**未发现**匹配文档。
> **本次未覆盖**：Slot 03/04/05 的活动区、各文件系统的未分配空间（NTFS/ext4 空闲区）、其他存储介质。
> 本结论仅适用于上述范围，不构成'该设备不存在涉案文档'的认定。"

**最后那句"不构成……的认定"是这类结论的标准写法**，它把否定性结论的效力限制在证据能支撑的范围内。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 双系统笔记本：那个 130 MB 的 ext4 分区不是第三套系统

**场景**

查获一台 Windows 10 + Linux 双系统笔记本，1 TB HDD。镜像为 `DigiForensics.dd`（931 GB，raw）。委托要求：确认是否存在第二套系统，并全面提取文档类证据。主副本只读封存。

委托方明确提出"此前有人提醒这台机器上可能有隐藏系统"。选择这一路径的依据是委托方的怀疑指向一个具体目标，而分区表里恰好有一个看起来可疑的分区——判定它是不是，必须靠多项证据而不是印象。

**处置过程**

**第 1 步 · 镜像与分区层**：

```bash
img_stat /work/DigiForensics.dd
mmls /work/DigiForensics.dd
```

输出确认 GPT 分区表，含 6 个非分配槽位：

| Slot | Start | Length | mmls 的 Description |
|---|---|---|---|
| 02:00:00 | 2048 | 524 MB | `NTFS (0x07)` |
| 03:00:01 | 1053184 | 1 MB | `EFI System Partition` |
| 04:00:02 | 1064960 | 130 MB | `Linux (0x83)` |
| 05:00:03 | 1181696 | 780 GB | `Linux (0x83)` |
| 06 | 169558016 | 15,340 | `Unallocated` |

**第 2 步 · 逐卷判定，注意两个易误判的槽位**：

```bash
fsstat -o 2048      /work/DigiForensics.dd     # → NTFS
fsstat -o 1053184   /work/DigiForensics.dd     # → FAT32（1 MB，mmls 只标了类型没标 FS）
fsstat -o 1064960   /work/DigiForensics.dd     # → ext4
fsstat -o 1181696   /work/DigiForensics.dd     # → ext4
```

第 3 个槽位（1 MB）被 `mmls` 标为 EFI，**必须独立确认它是不是 FAT32**——`fsstat` 确认后目录仅 3 项（`EFI/boot/`），属正常 ESP。

第 4 个 130 MB 分区被判定为 ext4 且**目录条目仅 2 项**，高度可疑：

```bash
fls -o 1064960 -r -p /work/DigiForensics.dd          # 输出仅 2 行：/ 与 /lost+found
debugfs -R "stats" -o 1064960 /work/DigiForensics.dd 2>/dev/null | head -20
```

`fsstat` 显示该分区 **98% 空闲**。结论：这是一个**被格式化但基本未使用的 ext4**，不是隐藏系统。此判断因"目录数 + 空闲率 + 无大文件"三项一致才成立。

**第 3 步 · 完整登记并检查未分配区**：

| Slot | 起始扇区 | 判定 | 目录条目 | 结论 |
|---|---|---|---|---|
| 02 | 2048 | NTFS | 51,882 | Windows 系统盘 |
| 03 | 1053184 | FAT32 | 3 | 正常 ESP |
| 04 | 1064960 | ext4（98% 空闲） | 2 | 格式化后未使用 |
| 05 | 1181696 | ext4 | 213,776 | Linux 主分区 |
| 06 | 169558016 | 未分配 | — | 提取并关键字搜索 |

```bash
dd if=/work/DigiForensics.dd of=/tmp/gap.bin bs=512 skip=169558016 count=15340 status=none
strings -n 20 /tmp/gap.bin | grep -icE 'document|confidential'   # → 0
```

**结论**

能证明：该机为 Windows 10 + Linux 双系统，**不存在**被刻意隐藏的第三套系统——"格式化后未使用"的判断基于目录条目仅 2 项、98% 空闲率、无大文件三项独立证据，而非单一表象；1 MB 的 ESP 是正常 EFI 分区，**未发现** OEM 恢复分区；分区间隙 15,340 扇区（约 7.5 MB）已独立搜索，未发现文档类残留。

每个卷的判定均记录了 Slot、起始扇区、文件系统类型、目录条目数，可供复核。

**不能证明**：分区间隙关键字搜索只用了 `document` 与 `confidential` 两个词。**未覆盖范围**包括：使用其他词汇命名的文档、中文文件名、以及未分配空间中已被覆盖的内容。这一局限须在报告中列出。

**误判对照**

最像的误判是把那个 130 MB 分区判为"隐藏的第二套 Linux"，理由是"它也是 ext4"。

判据要落在三项可量化的数据上：目录条目只有 2 项（`/` 与 `/lost+found`，这是格式化后未写入任何文件的典型状态）、空闲率 98%、且全卷无任何大文件——一套真正在使用中的系统不可能是这组数据。

相比之下，同类型的第 5 分区（780 GB ext4）有 **213,776 个目录条目**，两者差距是四个数量级。

正确判据是用目录条目数与空闲率这类可量化指标区分"空分区"与"系统分区"，而不是看文件系统类型标签。按错误判据走的代价是编造出一个不存在的隐藏系统：委托方可能据此追查一个从未存在的人，而真正需要关注的地方（第 5 分区里 21 万个条目中的文档类文件）反而没被重视——**一个假阳性会挤占掉真阳性的注意力**。

<a id="section-33"></a>

### 5.2 `mmls` 报的 Description 为什么不能直接采信

**场景**

同一镜像中，`mmls` 对第 3 个槽位报 `EFI System Partition`、对第 4 个槽位报 `Linux (0x83)`。委托方拿到这份分区清单后要求逐项确认。

将此情形单列的原因是 `mmls` 的 Description 来自 GPT 分区表的类型 GUID，而 GUID 与实际内容不是一回事。

**处置过程**

1. 分清 `mmls` 给的是什么：

```bash
mmls /work/DigiForensics.dd
# 03:00:01  1053184  2048  EFI System Partition     ← 这是 GPT 里的 PartitionType GUID
```

```text
GPT 描述能说明的：分区被标记成什么类型
GPT 描述不能说明的：里面实际装的是什么文件系统、有什么内容
```

2. 逐槽位用文件系统层工具独立确认：

```bash
fsstat -o 1053184  /work/DigiForensics.dd | head -5   # → FAT32（GUID 说 EFI，实际确实是 ESP）
fsstat -o 1064960  /work/DigiForensics.dd | head -5   # → ext4（GUID 只说 Linux，没说是系统）
fls   -o 1053184  -r -p /work/DigiForensics.dd        # → 3 项，正常 ESP 内容
```

**结论**

能证明：第 3 槽位的 GUID 标注与实际内容一致（FAT32 且仅含 `EFI/boot/`，属正常 ESP）；第 4 槽位的 GUID 标注为 Linux 但不足以判断其性质，需另由目录条目数与空闲率判定。

这一判定链的每一步都有独立工具输出支撑。

**不能证明**：不能因为 GUID 与内容一致，就认为其他槽位的 GUID 也可信——本案的第 4 槽位恰好就是"GUID 正确但内容无信息量"的例子。

**误判对照**

最像的误判是把 `mmls` 输出直接当成"分区性质认定表"写进报告。

判据要落在 GPT 类型 GUID 的作用范围上：GUID 是装机时写入的元数据，它可以由分区工具任意修改，也可以与实际内容脱节——`0x83`（Linux）这个标签适用于 ext2/3/4、XFS、btrfs 乃至一个空分区；它对"这是不是一套系统"这个问题一个字都没说。

正确判据是GPT 类型 GUID 只作线索，文件系统签名（`0xEF53` 等）+ 超级块 + 目录内容才作结论。按错误判据走的代价：报告里会出现"分区 4 为 Linux 系统分区"这样的表述，而复核方一翻目录就看到只有 `/` 和 `/lost+found`——**这类不一致比不做判定更伤**，因为它会让复核方怀疑整份分区清单的严谨性。

<a id="section-34"></a>

### 5.3 反例：只搜未分配空间的英文关键词

**场景**

同一案件的委托方补充要求：分区间隙中若藏有中文命名的合同扫描件也要一并提取。分析员在 7.5 MB 的间隙中用 `strings -n 20 | grep -icE 'document|confidential'` 得到 0，报告中写「未发现文档类残留」。

这条列为反例，是因为这个 0 只能证明"没有含这两个英文词的 20 字符串以上的内容"，而委托方问的是中文文件名。

**处置过程**

对照点在于关键词覆盖与编码处理：

```bash
# 原始做法：只有 ASCII 英文词
strings -n 20 /tmp/gap.bin | grep -icE 'document|confidential'   # → 0

# 需要补的维度：
strings -n 6  -e l /tmp/gap.bin | grep -icE '合同|扫描|协议|机密'   # UTF-16LE 中文
strings -n 6  -e b /tmp/gap.bin | grep -icE '合同|扫描|协议|机密'   # UTF-16BE 中文
strings -n 6  -e S /tmp/gap.bin | grep -icE '合同|扫描|协议|机密'   # UTF-8 中文
```

```text
注意：GAP 文件仅 7.5 MB，上述搜索完整覆盖了整个间隙，
      不是抽样——所以"0 命中"是一个完整覆盖下的阴性结果，
      前提是关键词与编码维度覆盖到位。
```

**结论**

阴性发现：在上述关键词与三种编码覆盖下，**7.5 MB 的分区间隙中未发现文档类残留**。

未覆盖范围：关键词之外的命名方式（如以编号、拼音缩写命名的文件）、以及内容已随覆盖丢失的部分。

**误判对照**

最像的误判是把「未发现文档类残留」当作对委托方问题的完整回答。

判据要拆成两问：第一问"间隙里有没有内容"——7.5 MB 全量扫过，这一问回答了；第二问"有没有文档类内容"——需要关键词命中才算回答，而关键词覆盖到什么程度，报告里必须写明。

本案原做法只用了两个英文词，且只用 ASCII 提取，中文文件名在任何情况下都不可能被 `strings` 默认编码命中。

正确判据是阴性结论的强度等于检项的覆盖度，而不是等于检项执行得多认真。按错误判据走的代价：若间隙里确实存着一个 UTF-16LE 编码的中文合同名，委托方据此认为文件已彻底排除而销毁了相关设备；而报告里那句无条件的「未发现」会让人无法判断这个结论到底覆盖了什么。

---

---
<a id="section-35"></a>

## 六、扩展阅读方向

本篇是文件系统板块的入口，所以它的扩展方向主要是**分流**——判定完之后该往哪走。下面按"你在哪一步"分组。

<a id="section-36"></a>

### 分流：判定完之后，各走各的路

本篇 2.2 那张对比表列出了五个系统的取舍。做完判定后按类型进入对应分支：

- [NTFS 结构与 MFT 解析](filesystem-ntfs-ntfs-master-file-table.md) —— `$MFT` 记录结构、Fixup（Update Sequence Array）、`$FILE_NAME` 还原完整路径。**NTFS 取证工具最全，从这里入门效率最高**
- [NTFS 数据流与隐藏数据](filesystem-ntfs-ntfs-alternate-data-streams.md) —— ADS、`$I30`、slack 与未分配空间。本篇 2.1 说"两处未分配是最常见藏身点"，那篇讲怎么把它们挖出来
- [Steady-State 与 LogFile 还原](filesystem-ntfs-steady-state-logfile.md) —— 从"现状"追到"过程"。**这是 NTFS 独有的能力**，别的文件系统做不到
- [ext4 结构与 inode](../filesystem-unix/filesystem-unix-ext4-inode.md) —— inode、extent、journal。**注意超级块在偏移 1024 而不是 0**，这是本篇 2.3 表格里最容易记错的一条
- [FAT 系列结构](../filesystem-mobile-fs/filesystem-mobile-fs-fat.md) —— FAT12/16/32 与 exFAT。ESP 分区是 FAT32，启动项篡改类案件的核心目标在那里
- [APFS 容器与快照](../filesystem-apple-fs/filesystem-apple-fs-apfs.md) —— 本篇 3.6 说的"成熟 TSK 支持有限"就是那篇要解决的问题。注意 APFS 要先读容器再读卷，跳过这一步等于全错
- [F2FS 结构](../filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md) —— 移动端。判定靠魔数 `f2f5 2010`（偏移 1024）
- [文件头与文件签名](filesystem-ntfs-file-headers-and-signatures.md) —— 文件系统判定完了，**卷里的东西是什么格式**是下一个问题。这一篇也是本库 L1 底层"编码"那块能力的入口

<a id="section-37"></a>

### 前置基础：跑本篇之前需要的东西

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— `losetup` 与 offset。本篇全程用 `-o` 参数指定卷起始扇区，**基址错了后面全错**
- [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md) —— 镜像是 E01 还是 raw 决定你要不要先挂载。**E01 直接当 raw 读会全盘乱码**，这是本篇 2.1 表格里第一层的典型失败模式
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 第三章步骤 5 那个"卷清单"登记表为什么要有四项字段，答案在可追溯性那一节
- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 坏扇区策略与分区表损伤。**分区表坏了，`mmls` 会给不出分区列表**

<a id="section-38"></a>

### 判据与反例：卷层判定的常见失误

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 本篇 2.1 那句"两处未分配是最常见藏身点"在 NTFS 侧的完整展开。MFT 一致性检查能判存疑，但要坐实必须引入独立时钟
- [BitLocker 全卷加密取证](../../crypto/crypto-volume/crypto-volume-bitlocker.md) —— 本篇 2.5 表格里"把 BitLocker 卷当 NTFS → 文件名全乱码 → 误判文件已损坏"这一行。**识别出加密之后是它的事**
- [EFS 文件系统加密取证](../../crypto/crypto-volume/crypto-volume-efs.md) —— 与卷级 BitLocker 不同，**EFS 是文件级的**，所以同一卷上可能有明文文件也有加密文件
- LVM 重组缺口 —— **LVM 逻辑卷的重组本库暂无专篇**。遇到需要 `mmstat` 重组的场景，以 LVM2 元数据区（`LABELONE`）的布局文档为准；本篇 2.4 只把"需专有工具重组"这一点标出来
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 本篇对应 L1 底层"文件系统"模块的第一站。2.3 那句"哪些地方没数据其实是没解析"，在本篇有具体形态：把 APFS 容器当 ext4
- [术语查表](https://www.digiforensics.cn/wiki/digiforensics-glossary)—— `NTFS` / `MFT` / `inode` / `Superblock` / `Volume` 的定义。`卷` 与 `分区` 在术语表里是两个词，本篇三层结构的第一层区分就在这两者。
<a id="section-39"></a>

## 七、命令速查

```bash
# ===== 环境准备 =====
sudo apt install sleuthkit e2fsprogs util-linux file xxd entropy
sudo cp --reflink=auto /evidence/master/DigiForensics.dd /work/DigiForensics.dd

# ===== 第一层：镜像 =====
img_stat /work/DigiForensics.dd                       # 格式、扇区大小、容量

# ===== 第二层：卷 =====
mmls /work/DigiForensics.dd                           # 分区表（Slot / Start / Length）
mmcat /work/DigiForensics.dd 2 > /work/part2.dd      # 按 Slot 提取整卷
sudo blkid -p -o full /work/DigiForensics.dd          # Linux 侧独立判定

# ===== 第三层：文件系统 =====
fsstat -o 63 /work/DigiForensics.dd                   # 超级块详情（-o = 起始扇区）
fls -o 63 -r -p /work/DigiForensics.dd > /evidence/fls-vol2.txt   # 递归目录树
icat -o 63 /work/DigiForensics.dd 11443-128-3 > /tmp/t1.bin       # 提取文件
file /tmp/t1.bin                                      # 验证魔数与文件名相符

# ===== 魔数人工确认 =====
xxd -l 64  -s $((63*512))   /work/DigiForensics.dd   # NTFS: +3 "NTFS    "
xxd -s 1024 -l 4            /work/DigiForensics.dd   # ext*: 0xEF53
xxd -s 32   -l 4            /work/DigiForensics-apfs.dd  # APFS 容器: "NXSB"
xxd -s 1024 -l 4            /work/DigiForensics-f2fs.dd  # F2FS: f2f5 2010

# ===== 加密与高熵检测 =====
dd if=/work/part2.dd bs=1M count=64 2>/dev/null | ent -b    # 熵≈8.0 → 疑似加密

# ===== 未分配空间（反取证必查）=====
blkls -o 63 /work/DigiForensics.dd | strings | grep -i 'keyword'
dd if=/work/DigiForensics.dd of=/tmp/gap.bin bs=512 skip=169558016 count=15340 status=none

# ===== 挂载前后哈希验证（任何操作后都要做）=====
sha256sum /work/DigiForensics.dd
```

---

> 
📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 文件系统分析 — 文件系统取证总览」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《文件系统取证总览》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
