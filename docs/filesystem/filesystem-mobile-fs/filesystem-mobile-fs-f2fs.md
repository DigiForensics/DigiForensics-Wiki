---
title: "F2FS 结构"
slug: "filesystem-mobile-fs-f2fs"
canonical: "https://www.digiforensics.cn/wiki/filesystem-mobile-fs-f2fs"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "filesystem"
space: "文件系统分析"
node_path: ["移动文件系统"]
---

# F2FS 结构

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/filesystem-mobile-fs-f2fs)

<a id="section-1"></a>

## 一、概述

F2FS 是三星为 NAND 闪存设计的文件系统，Android 手机上见到的多半是它。

取证上的麻烦不在字段多，而在它的每个设计决定都来自闪存的物理限制。

| 闪存特性 | 后果 | F2FS 的应对 |
|---|---|---|
| **不能原地覆盖** | 已有数据不能改写，只能擦除后重写 | **日志型结构**：新版本写到别处，旧版本等 GC 才擦除 |
| **擦除以"块"为单位** | 擦除粒度远大于写入粒度 | **段（Segment）** 作为擦除单位，固定 2 MB |
| **擦写次数有限** | 频繁擦写会损坏闪存 | **冷热数据分离**：高频更新的元数据单独放 |
| **顺序写远快于随机写** | 随机写代价高 | **主区顺序写，日志区承接随机写** |

把这四条代进去，F2FS 取证最核心的一个问题就浮出来了：

> 文件"当前"的内容不写在原位置，而是写在最近一次更新写入的位置。旧版本在垃圾回收（GC）执行前一直留在盘上。

这意味着 F2FS 上"删除"的文件数据可能完整保留——但其位置由 NAT 和当前 checkpoint 决定，不能像 ext4 那样靠 inode 列表直接枚举已删文件。

跟 ext4 对照一下差异所在：

| 维度 | ext4 | F2FS |
|---|---|---|
| 元数据形态 | inode 数组 + 间接块 | **日志型元数据 + 映射表** |
| 已删文件枚举 | `debugfs lsdel` 直接列出 | **无直接等价命令**，需解析 NAT + checkpoint |
| 旧版本数据 | 通常被覆盖或仅剩残留 | **GC 前完整保留旧版本** |
| 工具成熟度 | 高（e2fsprogs + TSK） | **低，以专用工具为主** |

---

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 分区布局：六个区域

F2FS 把整个分区切成六个区域，每一块的起始块地址都在超级块里明写。

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────────┐
│ 超级块区   │ 检查点区  │ 段信息区  │ 元数据区  │ 汇总区    │  主数据区     │
│ (SB)     │ (CP)     │ (SIT)    │ (NAT)    │ (SSA)    │ (Main Area)  │
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────────┤
│ 1 段 2MB  │ 2 段 4MB │ 2 段 4MB │ 2~34 段  │ 1 段 2MB │  剩余全部    │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────────┘
```

| 区域 | 全称 | 作用 | 取证价值 |
|---|---|---|---|
| **SB** | Superblock | 魔数、版本、各区域块地址、块大小 | **定位一切的起点** |
| **CP** | Checkpoint | 文件系统当前状态快照 | **决定"当前"文件映射** |
| **SIT** | Segment Information Table | 每段的有效块数、类型、有位图 | **段类型揭示冷热分离** |
| **NAT** | Node Address Table | **inode 号 → node 块地址** | **恢复文件内容的核心映射** |
| **SSA** | Summary Area | 段内块摘要、当前写指针 | 定位段内最新数据 |
| **MA** | Main Area | 实际的用户数据与元数据 | 提取文件内容的区域 |

段（Segment）是擦除单位，**固定 2 MB**（512 个 4 KB 块）。段的划分让"擦除"这件事有了明确边界。

<a id="section-4"></a>

### 2.2 超级块：魔数 `0xF2F52010`

主超级块位于文件系统起始 + 1024 字节（0x400），与 ext 系列的偏移习惯一致。魔数为 `F2FS_MAGIC = 0xF2F52010`（小端读作 `10 20 F5 F2`）。

```
偏移  长度  字段                   取证意义
0x00  4    magic = 0xF2F52010      文件系统确认
0x04  4    major_ver               主版本号（与工具兼容性相关）
0x08  4    minor_ver               次版本号
0x0C  4    log_sectorsize          log2 扇区大小，典型 9（512 字节）
0x10  4    log_sectors_per_block   log2 每块扇区数
0x14  4    log_blocksize           log2 块大小，典型 12（4096 字节）
0x18  4    log_blocks_per_seg      log2 每段块数，典型 9（512 块 = 2 MB）
0x1C  4    segs_per_sec            每区段数
0x20  4    secs_per_zone           每区扇区数
0x24  4    checksum_offset         校验和偏移
0x28  8    block_count             用户块总数（**全表只有这一项是 8 字节**）
0x30  4    section_count           区总数
0x34  4    segment_count           段总数
0x38  4    segment_count_ckpt      检查点区段数（通常 2）
0x3C  4    segment_count_sit       SIT 段数
0x40  4    segment_count_nat       NAT 段数
0x44  4    segment_count_ssa       SSA 段数
0x48  4    segment_count_main      主区段数
0x4C  4    segment0_blkaddr        segment 0 起始块
0x50  4    cp_blkaddr              检查点区起始块
0x54  4    sit_blkaddr             SIT 起始块
0x58  4    nat_blkaddr             NAT 起始块
0x5C  4    ssa_blkaddr             SSA 起始块
0x60  4    main_blkaddr            主区起始块
0x64  4    root_ino                根 inode 号
0x68  4    node_ino                node inode 号
0x6C  4    meta_ino                meta inode 号
```

> **换算公式**：`块大小 = 2^log_blocksize`，`段大小 = 2^log_blocks_per_seg × 块大小`。这三个 `log_` 字段必须实测，不能假设——典型值是扇区 512 / 块 4096 / 段 2 MB，但格式化参数可改。部分实现还在后续块（如 0x1400）放第二份超级块，备份位置依版本而异，需结合实际实现验证。

```bash
xxd -s 1024 -l 16 /work/DigiForensics.dd
# 00000400: 1020 f5f2 0100 1000 0900 0000  .. .....   ← 0xF2F52010 ✓
```

<a id="section-5"></a>

### 2.3 Checkpoint：定义"当前"状态

| 内容 | 作用 |
|---|---|
| `checkpoint_ver` | 检查点版本号，每次更新递增——比对两个 checkpoint 即可知道文件系统发生过写入 |
| `user_block_count` / `valid_block_count` | 块总量与有效块量，差值反映垃圾量 |
| `free_segment_count` | 空闲段数，偏小说明 GC 压力存在 |
| `cur_node_segno` / `cur_node_blkoff` | 当前 node 写位置（node = 元数据块） |
| `cur_data_segno` / `cur_data_blkoff` | 当前数据写位置 |
| `ckpt_flags` | 是否需要恢复、是否需要回滚 |
| `next_free_nid` | 下一个可用 node ID，累计分配量，可作"曾创建过多少文件对象"的量级参考 |

F2FS 用的是双 checkpoint 机制，两个区交替写，每个 checkpoint 自带版本号和 CRC。

这带来一个很实用的性质：拿到两个 checkpoint 就能判断哪个更新、哪个损坏，也能看出两次写入之间文件系统发生了多大变化。

`valid_block_count` 下降说明期间发生了删除或覆盖。

`ckpt_flags` 里出现"需要恢复"标志，说明上次没有正常卸载。此时元数据里可能有未完成的写入，结论须标注"可能存在未完成操作"。

<a id="section-6"></a>

### 2.4 NAT：inode 到物理块的映射表

**NAT 是 F2FS 取证最核心的结构**，把 inode 号（ino）映射到该 inode 所在的物理块地址。每条 `f2fs_nat_entry` 为 9 字节：`version(1) | ino(4) | block_addr(4)`。

**从 inode 到内容的完整链条**：

```
目录项 → ino
  ↓ 查 NAT
block_addr（inode 所在块）
  ↓ 读块
f2fs_inode：i_inline? → 内联数据 或 i_addr[0..11] 直接块 + i_nid 间接节点
  ↓ 逐级解析
direct_node / indirect_node / double_indirect_node
  ↓
全部数据块地址 → 按序读出 → 拼回文件
```

> **链条中任一环缺失即无法还原**。恢复文件时要把 NAT 命中情况、inode 是否内联、间接节点是否完整都记录下来——这些就是判断"文件能否完整恢复"的依据。
>
> NAT 里的映射是"当前有效版本"的映射。旧版本的映射在旧 checkpoint 对应的旧 NAT 页里——这正是"GC 前旧数据仍在"的技术原因，也是找回旧版本文件的入口。

<a id="section-7"></a>

### 2.5 SIT 与段类型：冷热分离的证据

SIT 的每条 `f2fs_sit_entry` 记录一个段的状态：`vblocks(2)`（低 10 位 = 有效块数，高 6 位 = 段类型）、`valid_map(64)`（512 位位图，标记段内哪些块有效）、`mtime(8)`（该段最后一次 GC 时间）。

| 段类型 | 含义 | 取证含义 |
|---|---|---|
| `SUM` | 汇总段（SSA） | 系统元数据 |
| `NODE` | 元数据段（inode、目录） | 文件频繁被改的区域 |
| `DATA` | 数据段（文件内容） | 用户文件主体 |
| `COLD` | 冷数据段 | 长期未改的数据（旧照片、视频） |
| `WARM` / `HOT` | 温 / 热数据段 | 近期被频繁读写 |
| `UNUSED` | 空闲段 | 可能已 GC 或待写入 |

`mtime` 尤其值得看。某段 `mtime` 很旧但仍被引用，说明该数据长期未变动；某段 `mtime` 突然很新，说明该段近期被 GC 过，原有内容已被迁移或擦除。

某段变成 `UNUSED`，其上的数据很可能已被擦除。`valid_map` 位为 0 的块已经不是该文件的数据了。

**SSA** 的每条 `f2fs_summary` 为 7 字节（`nid(4) | version(1) | ofs_in_node(2)`），作用是"给定一个段，就能知道段内哪一块属于哪个文件、是第几块"——这是把散落块重新拼回文件的关键索引。段摘要区末尾还有 footer（段类型与 CRC），footer 损坏会导致该段摘要全部不可用。

<a id="section-8"></a>

### 2.6 针对闪存的设计带来的取证局限

| 局限 | 原因 | 实际影响 |
|---|---|---|
| 旧数据会被 GC 抹除 | 空间不足时 GC 迁移有效块并擦除段 | 回收越彻底，旧版本越不可得；无"永久保存"保证 |
| 无等价的"已删文件列表" | 没有 `lsdel` 这样的现成结构 | 必须自行解析 NAT + checkpoint，成本高 |
| inline data 藏在小对象里 | 小文件/小目录项直接存在 inode 或 dentry 中 | 容易漏检；小于约 4 KB 的文件默认内联 |
| node 与 data 分段 | 元数据与数据不在同一段 | 只扫数据区会漏掉全部元数据 |
| 工具支持有限 | TSK 对 F2FS 支持很弱 | 以 f2fs-tools 与专用解析器为主 |
| 移动端镜像常不完整 | 逻辑分区起始位置常需自行搜索 | 不能假设超级块在分区起始 |

> GC 时机由空间压力驱动，不由"用户删除"直接驱动。 所以"删除时间"与"GC 时间"不是一回事——GC 只是让旧数据消失的过程，把 GC 时间当作删除时间是错误的推理。

---
<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：定位并验证 F2FS 超级块

移动设备镜像常是整块闪存转储，F2FS 分区起点未知，需要搜索魔数：

```bash
grep -aob $'\x10\x20\xf5\xf2' /work/DigiForensics.dd | head -5
# 1258291200                          ← 命中点 1
# 26843545600                        ← 命中点 2（需逐一验证）
```

命中之后必须验证上下文，因为这 4 字节在随机数据中也可能出现：

```bash
xxd -s 1258291200 -l 16 /work/DigiForensics.dd
# 00480000: 1020 f5f2 0100 0e00 0900 0000  .. .....   ← magic + 版本 + log_sectorsize=9
xxd -s $((1258291200+0x14)) -l 16 /work/DigiForensics.dd
# 00480014: 0c00 0000 0900 0000  ...                ← log_blocksize=12(4096)
```

> **验证要点**：`log_sectorsize` 应为 9（512 字节）；`log_blocksize` 通常 12（4096）；`log_blocks_per_seg` 通常 9（512 块 = 2 MB）。出现 0 或明显异常值就是误命中。

<a id="section-11"></a>

### 3.2 第 2 步：切出 F2FS 分区

```bash
SB_SECTOR=$((1258291200 / 512))                      # 2457600
dd if=/work/DigiForensics.dd of=/work/DigiForensics-f2fs.dd \
   bs=512 skip=$((SB_SECTOR - 2)) count=52428800 status=none
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd          # 期望 1020f5f2
```

> **换算注意**：超级块在**文件系统起始 + 1024 字节**，不是文件系统起始本身。**分区起始扇区 = 超级块所在扇区 - 2**（1024 / 512）。这个 -2 的偏移错误是 F2FS 定位最常见的坑。

<a id="section-12"></a>

### 3.3 第 3 步：使用 f2fs-tools

```bash
sudo apt install f2fs-tools
dump.f2fs -g /work/DigiForensics-f2fs.dd              # 导出全局元数据（最常用入口）
dump.f2fs -i /work/DigiForensics-f2fs.dd 1544321 > /tmp/node.bin   # 按 inode 导出
dump.f2fs -s /work/DigiForensics-f2fs.dd 882 > /tmp/seg.bin        # 按段导出
fsck.f2fs /work/DigiForensics-f2fs.dd                 # 只读检查（不加 -a / -r）
```

> ⚠️ `fsck.f2fs` 绝不能加 `-a`（自动修复）或 `-r`（修复并重排）——**那会直接改写证据镜像**。即便默认只读模式，也**必须在工作副本上执行**。

<a id="section-13"></a>

### 3.4 第 4 步：解析 checkpoint

```bash
dump.f2fs -g /work/DigiForensics-f2fs.dd | grep -iE 'checkpoint|valid_block|free_seg|next_free_nid|ckpt_flags'
# checkpoint_ver: 8821   user_block_count: 65536000   valid_block_count: 41283776
# free_segment_count: 214 next_free_nid: 1873422      ckpt_flags: 0x0000
```

| 字段 | 判读 |
|---|---|
| `checkpoint_ver` | **版本号，界定文件系统经历了多少次状态更新** |
| `valid_block_count` | **明显低于总量 = 大量删除或 GC** |
| `next_free_nid` | **累计分配的 node ID**；推进量大 = 曾批量创建文件对象 |
| `ckpt_flags` | **非 0 = 未正常卸载或有未完成写入**，结论须加限定 |

<a id="section-14"></a>

### 3.5 第 5 步：NAT 映射与文件恢复

```bash
dump.f2fs -i /work/DigiForensics-f2fs.dd 1544321 > /tmp/node-1544321.bin
file /tmp/node-1544321.bin && xxd -l 32 /tmp/node-1544321.bin
# 00000000: a41e 0000 ...    ← i_mode 0x81a4 = 普通文件 0644
```

**判读要点**：`i_mode = 0x81A4` 确认为普通文件；**`i_inline` 未置位**时指向直接块 + 间接节点，需逐级解析 `i_nid`；**`i_inline` 置位**时内容直接存在 inode 结构内（**小于约 4 KB 的文件默认如此**），**不占独立数据块**——此时用 `icat` 式思路按块提取会一无所获。

<a id="section-15"></a>

### 3.6 第 6 步：SIT 分析与 GC 痕迹判断

```bash
dump.f2fs -s /work/DigiForensics-f2fs.dd 882 > /tmp/seg882.bin
# 解析每条 sit_entry：vblocks（有效块数）+ 段类型 + valid_map + mtime
```

| 观察 | 判读 |
|---|---|
| 段类型 = `NODE` 且 `mtime` 近期 | **元数据热点区**——**删除/改名概率最高** |
| 段类型 = `COLD` 且仍被引用 | 长期未改的旧数据（照片、归档文件） |
| 段类型 = `UNUSED` | **原数据很可能已被擦除**，残留不可期 |
| `valid_map` 大面积为 0 | 该段多数块已不是本文件内容 |
| `mtime` 集中变新 | **某时段发生过批量 GC**——删除动作可能就在这个时段 |

---
<a id="section-16"></a>

## 四、常见陷阱

本章按「格式识别 → 结构解析 → 取证语义 → 误报来源与结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-17"></a>

### 4.1 格式识别

<a id="section-18"></a>

#### 陷阱 1：★ 把超级块所在扇区当分区起始，切出偏移错 1024 字节的镜像

**现象**：`grep` 搜到 F2FS 魔数在偏移 `1258291200`，直接 `dd skip=$((1258291200/512))` 切出分区，切完 `xxd -s 1024` 读不到魔数，判为"切分失败"。

**原因**：主超级块位于文件系统起始 + 1024 字节（0x400），不是文件系统起始本身（2.2）。1024 / 512 = 2 扇区，所以分区起始扇区 = 超级块所在扇区 − 2。 少了这个减法，切出来的镜像整体前移了 1024 字节——而这个错误的表现是"魔数读不到"，很容易被误读为"定位方法错了"，于是去换搜索方式、而不是回头检查换算。

**影响**：定位失败会浪费大量时间在错误的方向上。

更糟的情况是**用错了偏移却仍然"成功"切出镜像**——如果前面的分区表或设备布局恰好让前移 1 KB 仍能解析，后续所有文件的偏移都会偏 1024 字节。**而这类错误在数据读取时不会报错，只会让内容错位**。

**核查**：**切分后必须回验魔数**，用于验证切分偏移是否正确：

```bash
SB_OFFSET=1258291200
dd if=/work/DigiForensics.dd of=/work/DigiForensics-f2fs.dd \
   bs=512 skip=$(( SB_OFFSET/512 - 2 )) count=52428800 status=none
# 回验：超级块应在 +1024 处
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd
# 期望：1020 f5f2
```

这条规则对所有"超级块带固定偏移"的嵌入式文件系统通用——ext 系列同理。**任何偏移换算之后都要回验，不要相信推导。**

<a id="section-19"></a>

#### 陷阱 2：只按魔数搜索就下结论，不验证上下文

**现象**：`grep -aob` 搜 `F2F52010` 命中两处，直接取第一处作为分区起点开始解析，工具输出的元数据全是异常值。

**原因**：**这 4 字节在随机数据里出现的概率并不低**。案例里第二处命中（偏移 `26843545600`）就是数据巧合。**魔数搜索的原理是字节序列匹配，它不验证上下文**——而 F2FS 的其余字段提供了大量可交叉验证的约束：`log_sectorsize` 应为 9、`log_blocksize` 通常 12、`log_blocks_per_seg` 通常 9。在随机数据里，连续多个字段同时落在合理值域的概率极低，这才是判真的依据。

**影响**：从一个假超级块出发，后面每一步都在错误的对象上操作——`dump.f2fs` 可能输出看似结构化实则无意义的内容。**"解析失败"与"解析出了错误的东西"在直觉上很像**，而后者危险得多，因为它不报错。

**核查**：**命中后必须逐字段验证**：

```bash
for off in $(grep -aob $'\x10\x20\xf5\xf2' /work/DigiForensics.dd | cut -d: -f1); do
  echo "=== 候选 $off"
  xxd -s "$off" -l 20 /work/DigiForensics.dd    # magic + 版本 + log_sectorsize
  xxd -s $((off+0x14)) -l 16 /work/DigiForensics.dd  # log_blocksize + log_blocks_per_seg
done
# 判据：log_sectorsize=9、log_blocksize=12、log_blocks_per_seg=9 同时成立
#       任一为 0 或明显异常 → 误命中
```

**多个候选都"看起来合理"时的处理**：用**下游结构交叉验证**——按各候选分别切出分区跑 `dump.f2fs -g`，能输出自洽 checkpoint（版本号、块计数、区段计数互相吻合）的那个才是真的。

<a id="section-20"></a>

### 4.2 结构解析

<a id="section-21"></a>

#### 陷阱 3：★ `fsck.f2fs` 加了 `-a` 或 `-r`，直接改写证据镜像

**现象**：为了"检查文件系统一致性"，执行了 `fsck.f2fs -a /work/DigiForensics-f2fs.dd`，工具报告修复了若干错误，随后在此镜像上继续取证。

**原因**：`-a`（自动修复）与 `-r`（修复并重排）会实际写入文件系统——修正指针、重建索引、整理段布局。直觉上"fsck 是检查工具、跑一下没坏处"是极其普遍的认知偏差，但fsck 的本质是一个修复工具，检查只是它的前置行为。而且修复通常是"成功"的，**不会报错**，这让污染更难被发现。

**影响**：**这是本篇最严重的错误**。

修复动作会重写元数据映射，**而元数据正是"这个文件曾存在"的唯一证据来源**。修复之后，原始的段布局、inode 映射、时间戳线索可能已被改变——未修复前的镜像能恢复的数据，修复后可能恢复不出来了。

而且这个改动只有对比原始哈希才能发现。

**核查**：**只在工作副本上跑只读模式，且明确记录基线哈希**：

```bash
# 基线
sha256sum /work/DigiForensics-f2fs.dd | tee /evidence/f2fs-baseline.sha256
# 只读检查——不加 -a、不加 -r、不加任何写入类选项
fsck.f2fs /work/DigiForensics-f2fs.dd
# 结束后校验
sha256sum -c /evidence/f2fs-baseline.sha256
```

**判断标准很简单**：`fsck` 的任何输出如果包含"修复/fix/repaired/relocate"字样，就说明发生了写入，**该次结果不可用于证据提取**，应从原始镜像重新开始。

<a id="section-22"></a>

#### 陷阱 4：只扫主数据区，漏掉全部元数据

**现象**：在主数据区按签名 carving，只找到媒体文件，得出"该卷只有这些内容"的结论；报告里完全没有目录结构。

**原因**：**F2FS 把 node 与 data 分段存放**（2.6 的局限表）——inode、目录项等元数据在 `NODE` 类型的段里，用户文件内容在 `DATA` 类型的段里。**只扫主数据区里的文件内容，等于跳过了整个元数据层**。而目录结构、文件名、路径、属主、时间戳全都在元数据段里——没有元数据就无法建立任何路径，无法把文件归到用户或时间线上。

**影响**：**这是一条彻底的否定性结论错误**——"该卷只有这些文件"完全站不住。委托方据此认为数据已被清理，而实际内容只是没有被正确寻址。

**核查**：**先解析元数据，再按映射提取内容**。F2FS 没有"按路径 ls"的现成工具，**必须自己走 NAT → inode → 节点链**（2.4）：

```bash
# 1) 全局元数据（NAT、checkpoint、SIT 索引）
dump.f2fs -g /work/DigiForensics-f2fs.dd > /tmp/f2fs-global.txt
# 2) 目录遍历：inode → dentry（可能在 inode 内联或 NAT 指向的 node 中）
# 3) 由 ino 查 NAT 得 block_addr，读 inode 判断 i_inline / i_addr / i_nid
# 4) 逐级解析 direct / indirect / double_indirect 节点
# 5) 按序读取全部数据块并拼接
```

**每个文件的恢复链条状态都要记录**：NAT 是否命中、是否内联、间接节点是否完整。**链条中任一环缺失就意味着内容不完整**，这个判断本身就是有价值的结论（"该文件仅前 3 个数据块可读，共 12 个数据块缺失"）。

<a id="section-23"></a>

#### 陷阱 5：漏掉 inline data，小文件集体消失

**现象**：解析出的文件清单里缺失大量小文件，恰好是那些几 KB 的图片、日志、配置文件。

**原因**：小于约 4 KB 的文件默认以 inline data 形式直接存在 inode 或 dentry 里（2.6）。**它的内容根本不在数据段上**——没有"数据块地址"可查。一个只按 NAT → inode → `i_addr[]` 取块的解析流程，**会在遇到内联数据时取到空值或者错误的内容**，而这个失败往往表现得像"该文件已损坏"或"块已回收"。

**影响**：**系统性的漏检**。小文件恰恰是价值密度高的一类——配置片段、日志行、临时凭证、聊天记录碎片。而且**漏检是无声的**：清单里没有它们，而清单本身看起来完整。

**核查**：解析 inode 时先判 `i_inline` 标志位，两种布局都要处理：

```bash
# i_mode 判文件类型；随后必须检查 i_inline
# i_inline = 1  → 内容在 inode 结构末尾的 inline 区域，无数据块
# i_inline = 0  → 走 i_addr[0..11] + i_nid 间接节点
# 目录项内联同理：目录记录可能直接存在 dentry 里
```

**报告里要说明 inline 数据的处理方式**，因为它影响清单的可复核性——复核者需要知道小文件是从哪读出来的。

<a id="section-24"></a>

### 4.3 取证语义

<a id="section-25"></a>

#### 陷阱 6：★ 把 GC 时间当作删除时间

**现象**：SIT 中某段 `mtime` 为 2024-05-18 03:22:41 且类型为 `UNUSED`，报告据此写"该视频于 2024-05-18 被删除"。

**原因**：GC 时机由空间压力驱动，不由"用户删除"直接驱动（2.6 的明确警示）。GC 迁移有效块并擦除段，它可能是在删除发生很久之后，因为空间不足才被触发的——中间可能隔着任意长时间。**"擦除时刻"与"删除时刻"之间没有固定关系**，而一个精确到秒的时间戳在报告里极具说服力，极易被当成删除时间接受。

**影响**：**一个虚构的精确时间点会被当作事实使用**。

"谁在什么时候删除了文件"是本类案件的核心问题之一，**一个错误的时间点会直接指向错误的人**。而且这类错误在报告里完全看不出来——数字精确、来源字段真实、只是推理错了。

**核查**：**两者严格分开表述，删除时间只能给区间**：

> "该段（SIT entry，`mtime` = 2024-05-18 03:22:41）已被标记为 `UNUSED`，表明其内容在**不晚于该时刻**被 GC 擦除。GC 时间反映的是空间回收时机，与用户删除动作无固定对应关系，因此本项发现不构成对删除时间的认定。"

**若要界定删除时间，需要另找独立时钟**：文件系统上的删除本身不留时间戳，可用的替代证据包括应用层日志、上层目录的访问记录、拍摄文件的 EXIF/MediaInfo 时间、以及该目录最后一次被修改的时间。每条替代证据都要说明它记录的是哪个动作，不能直接等同于"删除"。

<a id="section-26"></a>

#### 陷阱 7：★ 看到"文件已回收"就认为旧版本不可得，放弃追查

**现象**：在 SIT 中发现目标段类型为 `UNUSED`，判定"旧数据已被 GC 抹除，该文件已不可恢复"，报告结束。

**原因**：**GC 之前的旧数据仍在**，这是 2.4 明确指出的入口——"NAT 里的映射是当前有效版本的映射；旧版本的映射在旧 checkpoint 对应的旧 NAT 页里"。而 F2FS 的**双 checkpoint 机制**（两个区交替写，每个 checkpoint 自带版本号和 CRC）意味着**同时存在两份不同时间点的映射快照**。一个被当前映射指向的段失效了，不等于另一份映射下它没有内容。

**影响**：**把"当前视角看不到"当成"不存在"**，这是一条会关闭整条调查路线的否定性结论。而且**丢失的是最可能成功的那条路**——双 checkpoint 机制的价值正在于此，用了它成本极低（只是多解析一个 checkpoint）。

**核查**：**双 checkpoint 都要读，并明确对比**：

```bash
dump.f2fs -g /work/DigiForensics-f2fs.dd | grep -iE 'checkpoint|ver|valid_block|next_free_nid'
# 得到两个 checkpoint：ver 较高的是较新的一份
```

**对比维度**：

| 维度 | 用途 |
|---|---|
| `checkpoint_ver` | 界定两次写入之间的状态更新量 |
| `valid_block_count` | 下降说明期间发生了删除或覆盖 |
| `ckpt_flags` | 非 0 = 上次未正常卸载，**元数据可能存在未完成的写入** |
| NAT 页内容差异 | **旧版本映射的入口**——对同一 ino，看两份 NAT 的 `block_addr` 是否不同 |

**结论表述**："该 inode 在 checkpoint 8821（较新）下映射到块 X，在 checkpoint 8806（较旧）下映射到块 Y，两者内容不同，说明**该文件在两次 checkpoint 之间被修改过**。"——**这本身就是一个可用的时间线发现。**

<a id="section-27"></a>

#### 陷阱 8：`ckpt_flags` 非 0 时仍按当前映射下确定性结论

**现象**：checkpoint 输出中 `ckpt_flags` 非 0，但报告未提及，继续把当前映射作为准确状态引用。

**原因**：`ckpt_flags` 非 0 意味着上次没有正常卸载，即设备在写入过程中断电、被强制重启、或被直接读取转储。此时**元数据可能存在未完成的写入**——某些块已被改写而对应的映射还没来得及提交。基于当前 checkpoint 的映射做出的"文件存在/不存在""块指向何处"这类判断，在这种情况下都带有不确定性。 而 `dump.f2fs` 不会因为这个情况给出任何警告。

**影响**：**未限定的不确定性会在报告里被当成事实**。

"某文件存在于块 X"这句话，在未正常卸载的镜像上可能只是"文件系统打算把它放在块 X，但那次写入可能没完成"。

**核查**：**先判 `ckpt_flags`，再决定结论的强度**：

```bash
dump.f2fs -g /work/DigiForensics-f2fs.dd | grep -iE 'ckpt_flags|valid_block|next_free_nid'
# ckpt_flags = 0 → 正常卸载，可依据当前映射下结论（案例即此情形）
# ckpt_flags ≠ 0 → 必须加限定
```

**报告写法**："该镜像的 checkpoint 标志显示文件系统上次未正常卸载，**元数据存在可能未完成的写入**。以下映射关系基于当前 checkpoint，**在未完成写入的范围内不能排除偏差**。"

**判断方向很重要**：`ckpt_flags` 影响的是**正向结论的确定性**（"存在"要加限定），而**否定性结论同样要加限定**——"不存在"在这个前提下尤其不能断言。

<a id="section-28"></a>

### 4.4 误报来源与结论表述

<a id="section-29"></a>

#### 陷阱 9：把 TSK 的 F2FS 解析结果当成有效数据

**现象**：用 `fls`/`fsstat` 对 F2FS 镜像操作，目录列表几乎为空且报错不断，判为"该卷无有效文件"。

**原因**：**TSK 对 F2FS 的支持很弱**（2.6 的局限表）——它依赖的模型是"从一张 inode 表按序号取记录"，而 F2FS 的 inode 分布在 NAT 指向的分散块里，**两者结构上不匹配**。工具读不出内容**不是数据不存在，而是它找不到数据结构**。"目录空 + 大量报错"这个现象组合很容易被归到"数据被清空"，**而报错信息只说明工具不适用**。

**影响**：**这是一个关于数据存在与否的结论**，而它的真实来源是工具能力问题。

这类结论一旦写进报告，在对方用 f2fs-tools 正确解析后，你的报告会显得非常不专业。

**核查**：F2FS 一律以 f2fs-tools 与专用解析器为主，TSK 只在能提供交叉验证时使用：

```bash
sudo apt install f2fs-tools
dump.f2fs -g /work/DigiForensics-f2fs.dd    # 正确的入口
# TSK 的作用仅限于：确认分区偏移、某些场景的交叉印证
fsstat -o $((SB_SECTOR-2)) /work/DigiForensics.dd | head
```

**判读纪律**：**工具报错不是关于数据状态的证据**。当同一命令在另一镜像上正常工作时，先怀疑工具适用性。

<a id="section-30"></a>

#### 陷阱 10：把 "整块闪存转储" 当成分区镜像处理

**现象**：拿到手机 raw 转储后直接对整镜像跑 `dump.f2fs`，报"文件系统损坏"；或反过来，切出分区后仍用整镜像的偏移去取块。

**原因**：移动设备镜像常常是整块闪存的 raw 转储，不含分区表（2.6、3.1、案例开篇）——F2FS 的逻辑分区起点未知，需要自行搜索魔数。而**切出分区镜像之后，偏移体系就变了**：分区内的块地址是相对分区起点的，而原始闪存镜像里是相对闪存起点的。**两套偏移混用，取到的块内容会完全错位**，而这类错误的表现通常是"取出来的数据不像预期格式"，容易被误判为"内容已损坏"。

**影响**：一是分区级工具报"损坏"，二是手工取块取到错位内容。**两者都会导向"数据不可用"这个错误结论**，而实际数据完好。

**核查**：**先固定"我在操作哪一层"，偏移体系必须全程一致**：

```bash
# 1) 整镜像上搜索魔数定位起点
grep -aob $'\x10\x20\xf5\xf2' /work/DigiForensics.dd
# 2) 切出分区（-2 偏移）
dd if=/work/DigiForensics.dd of=/work/DigiForensics-f2fs.dd \
   bs=512 skip=$((SB/512 - 2)) count=<分区块数> status=none
# 3) 确认后续所有块地址都相对 DigiForensics-f2fs.dd 计算
dd if=/work/DigiForensics-f2fs.dd of=/tmp/block1.bin bs=4096 skip=$BLOCK1 count=1 status=none
#   ↑ 必须是分区镜像，不是整镜像
```

**自查方法**：取出第一个块后立即验证它是不是**文件内容**（`file` 命令 + 魔数），还是**元数据**（inode 魔数/裸 NID）。**开头就错位的话，后面全错。**

<a id="section-31"></a>

#### 陷阱 11：报告里把"内容完整"与"映射正确"混为一谈

**现象**：恢复出一个 MP4，`file` 显示格式正常、能解码，报告直接写"该文件已完整恢复"。

**原因**：**"可解码"和"完整"是两个不同的判断**。MP4 有大量可选 box，**一个被截断的 MP4 常常仍能被识别和部分解码**；一个缺少尾部索引的 MP4 可能连拖动进度条都正常。判断完整性要对比 inode 声明的 `i_size`（案例做法）与实际提取到的字节数，而"格式能被识别"只证明头部信息完整。

**影响**：**内容不完整的证据一旦被当成完整的交付出去**，后续所有基于它的分析（内容分析、时间线、关联）都建立在残缺数据上。而这类错误的隐蔽性很强——文件能打开、内容能看，肉眼难以发现缺失。

**核查**：**三项交叉验证，缺一不可**：

```bash
# 1) 实际字节数 vs inode 声明的 i_size
ls -l /tmp/recovered.mp4                              # 案例：与 i_size 一致 ✓
# 2) 文件头 magic 与容器完整性
file /tmp/recovered.mp4                                # ISO Media, MP4/M4A ...
# 3) 内容哈希固定，供后续复核
sha256sum /tmp/recovered.mp4
# 对媒体文件还可加：容器是否含完整 moov 索引
```

**报告写法**："该文件提取字节数与 inode 声明的 `i_size`（`<值>`）一致，文件头 `ftyp` box 正常，内容可解码，**支持内容完整**。"——**把每项验证依据写出来，结论才有支撑**。若字节数不一致，写"提取到 `<X>` 字节，inode 声明 `<Y>` 字节，**缺失 `<Y−X>` 字节，内容不完整**"。

<a id="section-32"></a>

#### 陷阱 12：把 `next_free_nid` 推进量解读为"文件数量"

**现象**：`next_free_nid` 为 1873422，报告写"该卷曾创建约 187 万个文件"。

**原因**：`next_free_nid` 是累计分配的 node ID 计数（3.4 的判读表）——**node 不等于文件**。inode 是 node，目录项（dentry）是 node，扩展属性块、匿名文件（FUSE 挂载点、`/proc`、`/sys` 类的虚拟 inode）、以及文件系统自身的内联结构**都占用 node ID**。把 node 计数当作文件计数，会高估一个量级以上，而这个数字在报告里看起来非常具体。

**影响**：一个夸大的文件数量会强化"该设备使用极其频繁""存在海量文件"这类不成立的叙事，**也可能被对方用来质疑报告的整体严谨性**。在需要说明"某文件是否属于本卷"时，node 号的语义不清也会导致归属判断出错。

**核查**：**明确区分"node ID 空间"与"文件数"**，后者只能通过实际遍历统计：

> "`next_free_nid` = 1873422，表示该文件系统累计分配过的 node ID 数量已至此。node 涵盖 inode、目录项、扩展属性与匿名 inode，不等于文件数量。 实际文件数需遍历目录树统计，本案遍历结果为 `<N>` 个。"

**这个量级差本身是有意义的**：`next_free_nid` 相对当前文件数若显著更大，说明**存在大量已删除的对象**——**这是寻找已删除文件的线索方向**（对每个候选 node ID 尝试在 NAT 与两个 checkpoint 中查找）。
<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 手机 F2FS 上被删视频的恢复：GC 时间不是删除时间

**场景**

查获一台 Android 手机（Samsung，出厂文件系统为 F2FS），委托要求确认 `/sdcard/DCIM/Camera` 下某段视频是否被删除。

镜像 `DigiForensics.dd` 为**整块闪存 raw 转储**，**不含分区表**，F2FS 逻辑分区起点未知。

委托方要的是两件事：视频是否被删了，以及删掉的内容能否恢复。

选择这一路径的依据是**没有分区表意味着超级块位置未知，只能靠魔数搜索**——而魔数搜索的误判率并不低。这一步的验证方式决定了后面所有偏移的正确性。

**处置过程**

第 1 步 · 搜索并验证超级块（含 -2 偏移切分）：

```bash
grep -aob $'\x10\x20\xf5\xf2' /work/DigiForensics.dd | head -5
# 1258291200      ← 命中点 1        26843545600  ← 命中点 2（需逐一验证）

xxd -s 1258291200 -l 16 /work/DigiForensics.dd
# 00480000: 1020 f5f2 0100 0e00 0900 0000  .. .....   ← magic + 版本 + log_sectorsize=9
xxd -s $((1258291200+0x14)) -l 16 /work/DigiForensics.dd
# 00480014: 0c00 0000 0900 0000  ...                ← log_blocksize=12(4096) log_blocks_per_seg=9(2MB段)

SB_SECTOR=$((1258291200 / 512))          # 2457600
dd if=/work/DigiForensics.dd of=/work/DigiForensics-f2fs.dd \
   bs=512 skip=$((SB_SECTOR - 2)) count=52428800 status=none    # -2：减去 1024 字节偏移
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd
# 00000400: 1020 f5f2  ..              ← 切分正确
```

`log_sectorsize = 9`、`log_blocksize = 12`、`log_blocks_per_seg = 9` 全部合理 → 命中点 1 确认为真超级块；命中点 2 的后续字段异常，**判定为数据巧合命中，予以排除**。

若忘记 -2，`xxd -s 1024` 会读到错误位置——见「陷阱 1」。

第 2 步 · 读 checkpoint，判断写入历史：

```bash
dump.f2fs -g /work/DigiForensics-f2fs.dd | grep -iE 'checkpoint|valid_block|free_seg|next_free_nid|ckpt_flags'
# checkpoint_ver: 8821   user_block_count: 65536000   valid_block_count: 41283776
# free_segment_count: 214 next_free_nid: 1873422      ckpt_flags: 0x0000
```

`ckpt_flags = 0` 表示文件系统正常卸载、元数据一致——这是可以放心依据 checkpoint 下结论的前提；若非 0，所有基于当前映射的判断都需附加"可能存在未完成写入"的限定。`valid_block_count` 明显低于总量，配合 `free_segment_count = 214`，说明**卷内空间偏紧、GC 压力存在**。

**第 3 步 · NAT 映射与内容提取**：

```bash
dump.f2fs -i /work/DigiForensics-f2fs.dd 1544321 > /tmp/node-1544321.bin
file /tmp/node-1544321.bin && xxd -l 32 /tmp/node-1544321.bin
# 00000000: a41e 0000 ...    ← i_mode 0x81a4 = 普通文件 0644
```

`i_mode = 0x81A4` 确认为普通文件；`i_inline` 未置位，指向 3 个直接块 + 1 个 indirect 节点。**逐级解析 indirect 节点**得到全部数据块地址后按序提取拼接：

```bash
dd if=/work/DigiForensics.dd of=/tmp/block1.bin bs=4096 skip=$BLOCK1 count=1 status=none
cat /tmp/block*.bin > /tmp/recovered.mp4
file /tmp/recovered.mp4 && ls -l /tmp/recovered.mp4 && sha256sum /tmp/recovered.mp4
# ISO Media, MP4/M4A, MOV, 3G, AAC, mpeg-4, avc1     ← 文件头完整
```

MP4 的 `ftyp` box 正常、大小与 inode 声明的 `i_size` 一致、内容可解码——支持"内容完整"的判断。

**第 4 步 · SIT 分析 GC 痕迹**：

```bash
dump.f2fs -s /work/DigiForensics-f2fs.dd 882 > /tmp/seg882.bin
# sit_entry：vblocks=3  type=UNUSED  mtime=2024-05-18 03:22:41
```

该段 `mtime` 集中在 2024-05-18 03:22，且已被标记 `UNUSED`。

**结论**

能证明：目标视频 inode **1544321** 在文件系统元数据中已不存在（NAT 无有效映射、目录索引无该项），**支持"已被删除"**；其数据块尚未被 GC 擦除，内容成功提取且容器结构完整。全程只读导出，`fsck.f2fs` 仅以默认只读模式运行，未做任何修复写操作，原始镜像哈希已固定。

**不能证明**：①`UNUSED` 段的数据很可能已被 GC 物理擦除，本次能恢复是因为该段尚未被擦除，**属于幸存而非必然**；②文件系统的段状态变更发生在 **2024-05-18 03:22** 前后，但**删除动作的精确时间无法仅凭文件系统结构确定**，需结合相机 App 日志、`/data/system/` 日志等应用层证据交叉印证。

**误判对照**

最像的误判是把 `mtime=2024-05-18 03:22` 写成"视频于 2024-05-18 03:22 被删除"。判据要落在 `mtime` 的语义上：F2FS 的 segment SIT 表里的 `mtime` 记录的是该段的最后更新时间，不是删除时间——段被标记 `UNUSED` 是垃圾回收（GC）的结果，而 GC 是由**空间压力**驱动的后台行为（本案 `free_segment_count = 214`，空间确实偏紧），它可以在文件删除后的任意时刻运行，与删除动作之间没有因果上的紧邻关系。正确判据是**把 GC 时间当作一个时间参考点而不是事件时刻**，报告应写「文件系统层面可确定的最后存在时间与 GC 时间，删除时间需其他证据佐证」。按错误判据走的代价是时间线错位：委托方拿 5 月 18 日去查手机的使用记录，而真正的删除动作可能在数周之后；更糟的是若对方成功举证"该时刻手机在本人手中"，这条基于错误时间的结论会被推翻，连带影响整条时间线的可信度。

<a id="section-35"></a>

### 5.2 魔数搜索的两个命中点：为什么必须验证后续字段

**场景**

同一检材的超级块搜索返回了两个命中点，第二个偏移在 26,843,545,600 字节处。

将此情形单列的原因是 4 字节魔数在几百 GB 的数据里出现两次完全不算意外——而取错一个会导致后面每一个偏移都错位。

**处置过程**

1. 不看魔数本身，看紧随其后的字段是否合理：

```bash
# 命中点 1
xxd -s 1258291200 -l 32 /work/DigiForensics.dd
# 1020 f5f2  0100 0e00 0900 0000  0c00 0000 0900 0000   ← 各字段均有意义

# 命中点 2
xxd -s 26843545600 -l 32 /work/DigiForensics.dd
# 1020 f5f2  ffff ffff 0100 0000  ...                     ← 后续字段异常
```

2. F2FS 超级块的关键字段要逐个自证：

```text
magic              0xF2F52010      ← 匹配，不足以说明问题
major_version      1               ← 必须是已知版本
minor_version      14
log_sectorsize     9               ← 扇区 = 2^9 = 512 字节，必须成立
log_blocksize      12              ← 块 = 2^12 = 4096 字节，必须成立
log_blocks_per_seg 9               ← 段 = 2^9 块 × 4096 = 512 块 = 2 MB，量级须合理
```

3. 切分后做回环确认：切出来的镜像里，超级块必须落在偏移 1024 处。

```bash
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd
# 00000400: 1020 f5f2  ..              ← 切分正确
```

**结论**

能证明：命中点 1 为真超级块——`log_sectorsize = 9`（扇区 512 字节）与"切分时用 `bs=512`"这一前提互相印证，`log_blocksize = 12`（块 4096 字节）、`log_blocks_per_seg = 9`（段 2 MB）均为常见合理值，且切分后回环校验位置正确。命中点 2 被排除，理由记录在案。

**不能证明**：不能证明命中点 2 一定是数据巧合——它也可能是某个结构区域被擦除后残留的旧魔数。排除的依据是"后续字段不合理"，这已足够，但结论的表述应是"排除"而非"证伪"。

**误判对照**

最像的误判是取 `head` 的第一条命中就开始切分。判据要落在 F2FS 超级块的字段结构上：`magic` 只占 4 字节，而它后面紧跟的 `log_sectorsize` 与 `log_blocksize` 是两个必须互相配合的幂次字段（`blocksize = 2^log_blocksize`），任何一个不合理都能立刻否定这个位置；而 4 字节序列在 128 GB 的数据里自然会出现偶然匹配。正确判据是魔数命中只产生候选，字段自洽才产生结论，切分后还要回环确认。按错误判据走的代价：切分起点错了 512 字节或错了几百 MB，后续所有 inode 号、块地址、checkpoint 读取都会给出看似合理实则错误的结果——**更麻烦的是不会报错**，`dump.f2fs` 对着错误偏移可能照样输出一堆结构，只是全错的。

<a id="section-36"></a>

### 5.3 反例：把空间压力当成文件删除的证据

**场景**

某次分析中，检查点显示 `valid_block_count` 远低于 `user_block_count`，分析员据此推断"该手机近期删除过大量文件"。委托方要求删除清单。这条列为反例，是因为**空间占用高可能有完全无关的解释**——而"删除大量文件"是最容易被顺手当成事实的那一个。

**处置过程**

对照点在同一组数字的两种解释上：

```bash
dump.f2fs -g /work/DigiForensics-f2fs.dd | grep -iE 'valid_block|free_seg|user_block'
# user_block_count:    65536000
# valid_block_count:   41283776      ← 约 63%
# free_segment_count:  214           ← 空间偏紧
```

```text
解释 A（本案采信）：手机长期使用中产生大量缓存/临时文件，
                    正常 GC 未及时回收，空间被占用但并非"被删除"。
解释 B（错误判据）：用户删除了约 2400 万个块的数据。
区分关键：valid_block 统计的是"当前被有效节点占用的块"，
          其中绝大部分是仍然存在的文件，不是空闲。
```

**结论**

阴性发现：`valid_block_count` 与 `user_block_count` 的差距**只反映当前空间占用状况**，本身不指示删除行为。**未覆盖范围**是"到底删除了什么"——该问题需通过目录索引与 SIT 表逐一比对，属于本次未做的检查。

**误判对照**

最像的误判是把"空闲块占比高"直接翻译成"大量文件被删"。判据要落在这两个计数的定义上：`valid_block_count` 统计的是被有效节点引用的块，其中绝大部分是现存**文件的数据块**——它和"空闲块"是两个不同的集合，把差值当成"被删除的数据量"在定义上就错了。真正的删除证据只能来自两处：目录索引中已消失但仍可定位的 inode，或 SIT 中 `type=UNUSED` 的段（且如 5.1 所述，UNUSED 段的时间不等于删除时间）。正确判据是先分清"占用"与"删除"这两个概念，再看是否有指向删除的具体记录。按错误判据走的代价是报告凭空编造出"约 24 GB 数据被删除"的结论，委托方据此追查却找不到任何一条对应记录，整份 F2FS 分析的可信度被连带否定——而真正的目标视频是否被删，反而因为这个错误结论变得无人关注。

---

---
<a id="section-37"></a>

## 六、扩展阅读方向

**前置与基础。** GC 机制决定了这个文件系统「删除之后还剩什么」。
段选择策略、冷热段如何分离、以及 GC 影响到删除痕迹的边界在哪，
这些不清楚就无法判断一份看似完好的 F2FS 镜像里还剩多少历史。
inline 机制同样需要区分清楚，`i_inline`、inline xattr、inline dentry
三种内联方式的差别与各自的检索方法不同，漏掉任一种都会造成文件漏列。

**同层深入。** Android 供应链是绕不开的前置条件。
`/data` 的加密元数据（cryptfs 与 FBE 两套机制）、
`userdata` 分区布局，以及 metadata 加密对 F2FS 解析造成的具体阻断，
决定了镜像拿到手之后究竟能不能解析。
移动镜像的获取质量直接设定了上限：整闪存转储中的稀疏区识别、
逻辑分区边界推断，以及多次覆盖导致的历史数据丢失，
都是必须在提取阶段就解决的问题，事后无法补救。

**相邻议题。** NILFS、JFFS2、UBI/UBIFS 这些日志型文件系统
与 F2FS 在结构和取证方法上差异明显，
放在一起对照能看清 F2FS 哪些设计是独有的。
Android 侧的 `userdata` 分区、FBE 与 SELinux 共同构成的三重阻断，
见 [《Android数据存储总览》](../../mobile/mobile-android/mobile-android-android-data-storage-overview.md)。

**工具与判据。** 交叉验证是 F2FS 取证的主要手段：
F2FS 元数据给出位置，carving 补齐无法映射的残留内容，
配合方式见 [《文件雕刻与签名恢复》](../filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)。
残留数据经签名识别后的格式判定与提取规则见
[《文件头与文件签名》](../filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md)。

**判据与反例。** 「F2FS 里没找到这个文件」往往被误读成「文件不存在」，
而实际原因可能是数据仍在 GC 的旧段里、可能落在 inline 区未被索引、
也可能因 metadata 加密而根本不可读。
iOS 侧没有 F2FS，但沙盒结构与备份提取的对应关系值得对照阅读，
见 [《iOS备份与沙盒提取》](../../mobile/mobile-ios/mobile-ios-ios-backup-and-sandbox-extraction.md)。

---

<a id="section-38"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install f2fs-tools sleuthkit file xxd   # TSK 对 F2FS 支持很弱，以 f2fs-tools 为主

# ===== 定位与切分（关键：魔数 + 1024 偏移 → 分区起始 = 超级块扇区 - 2）=====
grep -aob $'\x10\x20\xf5\xf2' /work/DigiForensics.dd | head -5   # 搜索魔数
xxd -s $OFFSET -l 32 /work/DigiForensics.dd         # 校验 log_* 字段是否合理
# 期望：log_sectorsize=9(512B) log_blocksize=12(4096B) log_blocks_per_seg=9(2MB段)
dd if=/work/DigiForensics.dd of=/work/DigiForensics-f2fs.dd \
   bs=512 skip=$((OFFSET/512 - 2)) count=$((容量/512)) status=none
xxd -s 1024 -l 4 /work/DigiForensics-f2fs.dd          # 期望 1020f5f2

# ===== f2fs-tools（只读！绝不用 -a / -r）=====
dump.f2fs -g /work/DigiForensics-f2fs.dd             # 全局元数据（checkpoint/NAT/SIT）
dump.f2fs -i /work/DigiForensics-f2fs.dd 1544321 > /tmp/node.bin    # 按 inode 导出
dump.f2fs -s /work/DigiForensics-f2fs.dd 882 > /tmp/seg.bin         # 按段导出
fsck.f2fs /work/DigiForensics-f2fs.dd                # 只读检查（不加 -a / -r）

# ===== checkpoint 判读 =====
# ckpt_flags 非 0      → 未正常卸载，结论需加限定
# valid_block_count 明显偏低 → 大量删除或 GC；next_free_nid 推进量大 → 曾批量创建文件

# ===== SIT GC 痕迹 =====
# UNUSED + mtime 集中变新 → 该时段批量 GC（注意：GC 时间 ≠ 删除时间）
# i_inline 置位 → 小文件内容在元数据段，只扫主数据区会漏检

# ===== 安全要求 =====
# 原始镜像只读封存 + 哈希固定；所有分析（含 fsck）在工作副本上进行
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 文件系统分析 — F2FS 结构」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《F2FS 结构》（CC BY-SA 4.0）`

文中 `DigiForensics.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
