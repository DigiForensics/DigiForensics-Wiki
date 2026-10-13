---
title: "文件雕刻与签名恢复"
slug: "filesystem-unix-file-carving-and-signature-recovery"
canonical: "https://www.digiforensics.cn/wiki/filesystem-unix-file-carving-and-signature-recovery"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "filesystem"
space: "文件系统分析"
node_path: ["Unix 文件系统"]
---

# 文件雕刻与签名恢复

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/filesystem-unix-file-carving-and-signature-recovery)

<a id="section-1"></a>

## 一、概述

文件雕刻（file carving）是在完全不使用文件系统元数据的前提下，仅凭文件内容的字节模式（魔数与结束标记）从磁盘中"切"出文件。 它解决的问题很具体：文件的目录项被删了、文件系统损坏了、元数据库被格式化了——**但数据块还在盘上，而且它们的字节排列没变**。

**为什么值得做**：文件系统层面的删除只改元数据，**数据块的内容在真正被覆盖之前是完好的**。这给了一个"绕过文件系统直接读数据"的路径。

在文件系统被恶意破坏、加密卷已解密、数据库被清空的场景下，carving 常常是唯一的路径。

但必须先建立一个正确的心理预期，否则整个流程会走向错误的结论：

> carving 产出的是"符合某格式签名的字节区间"，与完整文件有本质区别。这道差距就是本篇要讲透的核心。

差距具体体现在四处：

| 丢失的东西 | 后果 |
|---|---|
| **原始文件名** | 产物叫 `00012345.jpg`，**无从得知它原来叫什么、在哪个目录、谁改过它** |
| **时间戳** | 文件系统里那个文件"何时创建、何时修改"**完全不可得**（除非格式内嵌） |
| **边界精度** | 尾簇残留、填充字节都会导致**多切或少切**，**多数情况下哈希与原文件对不上** |
| **上下文** | **它属于哪个用户、哪个案件、哪个软件**——这些恰恰是取证最需要回答的 |

工具宣传通常强调"恢复了多少个文件"，很少提最后这条证据效力问题。另外，恢复出来的图片能不能当庭出示，取决于 EXIF 是否完整——**尾标记切不准时 EXIF 往往跟着一起坏掉**，剩下的只是一个能看的 JPEG。

本篇把它作为核心：carving 产物是重建产物（reconstructed artifact），不是原件（original），**在证据提交和司法鉴定中有明确的效力边界**。

**在取证流程中的位置**：本篇是**恢复手段，不是默认路径**。它排在最后——只有在元数据路径全部走不通（文件系统损坏、目录项被清除、`$MFT` 不可解析）时才开始，第一步永远是"先尝试定位元数据"。定位策略上，先从未分配空间与空闲块找起，而不是全盘 carve：全盘 carve 会把系统文件也切出来，产出量淹没真正相关的东西，这是 2.4 与 2.7 要讲的事。**上游依赖**是 [文件头与文件签名](../filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md)（魔数与结束标记的判据表）与 [NTFS 结构与 MFT 解析](../filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)（元数据可用时优先走元数据）；未分配空间的提取方式见 [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)；产物后续的去重与验证按 [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) 做。

**本篇处理的证据形态**：carving 的输入不是文件而是**字节区间**，按来源分三类：

| 来源 | 特点 | 注意 |
|---|---|---|
| **未分配空间 / 空闲块** | 已删除文件残留的聚集区，**carving 的主战场** | 内容可能交错，**同一文件的多段可能不连续**，尾簇常有残留数据 |
| 镜像的连续原始区域 | 全盘 carve 的对象 | 会连系统文件一起切出来，需要按路径与内容过滤 |
| **分页文件与内存镜像** | 内存里存的是解页后的内容，**跨页/跨页表边界的文件内容会被打断** | 必须按页大小对齐处理，否则 carve 出的大文件全是碎片 |

按格式分，产物能否成功取决于该格式有没有可用签名：**有魔数 + 有尾标记**的（ZIP、DOCX/XLSX/PPTX、PDF、GZIP、JPEG）基础 carving 就能切；**只有魔数没有尾标记**的（TIFF、MP4、部分容器格式）必须靠大小约束、页结构或邻接关系推断，切不准的概率很高；**完全无签名**的（纯文本碎片、部分数据库页）只能靠特征提取（`bulk_extractor` 那条路子），这时产物连"是不是一个完整文件"都无法判断。

某类文件的内容在这块盘上是否还存在、大致的字节范围与内容片段、删除前的部分内容（聊天记录片段、文档段落、照片缩略）、在元数据彻底不可用时保住一部分可读内容。

**"carve 到了"不等于"这就是原来的文件"**——没有文件名、没有路径、没有归属用户、没有原始时间戳（除非格式内嵌，比如 JPEG 的 EXIF、部分 PDF 的元数据），也就无法建立它与案件事实的联系。carve 产物的哈希通常与原文件对不上，**所以不能把它当成原文件的指纹用于威胁库比对**，只能用于去重和一致性自检。阴性结果覆盖范围极窄："在未分配空间 carve 中未见某格式"只说明那块区域里没有该格式的完整签名区间，被覆盖、被分区表划走、不带签名的格式、部分残留的碎片，全都在覆盖之外。carving 也**无法证明某个文件从未存在**——它只能证明"这些字节现在不在可搜索的区域里"。**而且 carving 本身会污染证据**：全盘 carve 会产生海量与案件无关的产物，报告里堆上几千个无归属的碎片，会让真正相关的两三个文件被淹没。

**读者前提**：需要能读十六进制并理解魔数在文件头的具体位置（不是"看到关键字"就行，得知道偏移与字节序）；需要理解未分配空间、簇、slack 空间这些概念，明白文件系统删除只改元数据而数据块还在；需要接受"carve 产物是边界推定的重建件、哈希通常对不上"这个事实，并能在报告里按标准表述写清楚它——不具备这个判读能力的读者，carve 出来的文件很容易被当成原件上报，会使复核者误判文件来源。
---
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 carving 的两种策略

```
策略 A：头尾定界（header/footer carving）——foremost / scalpel
  扫描 → 找到头 FF D8 FF → 找到下一个尾 FF D9 → [头, 尾] 切出
  优点：快、简单、边界较准
  缺点：需要尾标记；无尾标记的格式无法用

策略 B：定长切分（size/fragment carving）——photorec
  扫描 → 找到头 → 依据该格式的"典型大小/结构规则"向后切
  优点：不需要尾标记，能处理无尾格式
  缺点：边界靠猜，必然过度切分

策略 C：特征提取（feature extraction）——bulk_extractor
  不追求"文件"，只提取"特征"：邮箱、URL、IP、卡号、EXIF 坐标
  优点：能发现不成其为文件的痕迹；能钻进压缩包内部
  缺点：产出是文本/坐标列表，不是可提交的文件
```

**策略选择的实务逻辑**：

| 目标 | 选择 |
|---|---|
| 恢复有明确头尾的图片/文档 | A（foremost/scalpel） |
| 恢复无尾标记的格式（Office、文本、碎片） | B（photorec） |
| 找联系方式、URL、地理位置、密钥线索 | C（bulk_extractor） |
| **元数据完好，只是想批量导出** | **都不用，用 `tsk_recover`**（见 2.7） |

<a id="section-4"></a>

### 2.2 基础 carving 的三大局限（必须写进报告）

**这是本篇的核心内容。** 每一条都直接决定 carving 结论能走多远。

<a id="section-5"></a>

#### 局限一：碎片化（Fragmentation）——**原理上无法克服**

carving 假设"文件的字节在盘上是连续的"。一旦文件被碎片化存放到不连续的簇上，这个假设就不成立了。

```
真实存储（4 个碎片）：
簇 1024 [文件前 8 KB]  簇 99840 [中间]  簇 55 [中间]  簇 300200 [末尾]

carving 看到的：
簇 1024 [文件前 8 KB]  簇 1025 [其他文件的数据]  ← 边界就在这里断了
                          工具在此处判定"文件结束"，产出截断的残片
```

问题的严重性要算一下：现代文件系统普遍碎片化。**一个 20 MB 的视频通常已经是碎片化的**——它有 4 万个簇，分散在整个卷上。**基础 carving 能恢复的部分往往很有限。**

> **必须说清的技术事实**：这不是"工具不够好"的问题，是 carving 这种方法论本身的限制。 常见的补救是碎片重组（file carving with defragmentation）——利用已知的前后片段特征（如 JPEG 的重启标记、MP4 的 `moov` 原子、ZIP 的局部头）尝试重新拼接。但重组结果的正确性无法证明，只能靠内容合理性判断。

<a id="section-6"></a>

#### 局限二：内容被覆盖——**数据真的没了**

删除文件后，其数据簇进入空闲池。**后续任何写入都可能覆盖它们。** 覆盖一旦发生，**原内容彻底消失，没有任何技术手段可以恢复**（除非涉及闪存物理层的磨损分析，属专业实验室范畴）。

| 情形 | 可恢复性 |
|---|---|
| 刚删除，未做大量写入 | **可恢复** |
| 删除后设备持续使用数天 | **覆盖风险很高** |
| 删除后被 TRIM/闪存 GC | **数据通常已不可得** |

> **特别提醒闪存设备**：手机、平板、现代 SSD 的 TRIM 与垃圾回收（GC）会**在删除后很短时间内回收块**——eMMC/UFS 上的 TRIM 可能几秒内就完成。这是"从手机恢复已删照片"成功率远低于电脑的根本原因，不是技术问题。

**评估必做**：carving 之前必须问清**"删除后设备使用时长"**。这直接决定预期，不能事后才发现。

<a id="section-7"></a>

#### 局限三：无尾标记或无格式 —— **根本识别不了**

**不是所有数据都有可识别的魔数。** 这些内容 carving 完全无能为力：

| 类型 | 为什么识别不了 |
|---|---|
| 纯文本、CSV、代码 | **无魔数**（`file` 报 ASCII text，靠内容而非签名） |
| SQLite 数据库片段 | 有魔数，但**必须完整才能解析**，半截库文件打不开 |
| 未写完的文档 | 无完整结构 |
| 加密后的数据 | **密文无魔数**（见 [BitLocker 与 VeraCrypt](../../crypto/crypto-volume/crypto-volume-bitlocker.md)） |
| 已损坏/被部分覆盖的文件 | 头可能已被覆盖 |

**实务结论**：carving 的召回率远低于 100%，且无法事先知道漏了什么。 报告里**绝不能写"已恢复所有删除的文件"**。

<a id="section-8"></a>

### 2.3 证据效力：为什么哈希通常对不上（本篇的灵魂）

这是最容易被忽视、后果却最严重的问题。核心事实只有一句：

> carving 是**按签名边界**切出来的，不是按文件系统的原始长度切的。只要边界判断与原始边界不完全一致，产物的字节流就与原文件不同，哈希自然对不上。

**哈希是"逐字节"的指纹。** 只要有一个字节对不上，`sha256sum` 就完全不同。

需要说清一个例外，否则这条判据会被用得过严：**哈希不同是常态，不是必然**。如果文件在镜像中连续存放、carving 的头尾边界恰好与原始边界完全吻合、且没有把同簇残留数据并进来，那么切出的字节流可以与原文件完全一致，此时哈希也一致。但这个前提无法事先证明——你必须切完、比对成功之后才知道。所以实务中的结论仍然是：**carving 产物不能仅凭"哈希与已知原文件一致"就认定同一性**，因为一致可能来自真实提取成功，也可能来自巧合或已知哈希的泄露；反之，哈希不一致也不能直接推断提取失败，先要排除后面 2.4 节的五种原因。

**造成哈希不同的五个具体原因**：

| 原因 | 机制 | 例证 |
|---|---|---|
| **① 尾部过度切分** | carving 切到下一个魔数之前，**包含了同簇/后续簇的残留数据** | 应为 48 KB，实际切出 64 KB（多 16 KB 垃圾） |
| **② 头部过度切分** | 头向前一个无关结构之后开始，**包含了前导垃圾** | 文件前多出 1 KB 无关数据 |
| **③ 碎片化截断** | 文件分散在多个簇，工具在第一个非连续处停止 | 应为 20 MB，得到 8 KB 片段 |
| **④ 填充/对齐字节** | 文件系统可能填充簇尾，carving 把填充也算进文件 | 末尾多出 `00` 填充 |
| **⑤ 原始文件本身带元数据** | 部分格式在文件尾存储私有元数据，carving 可能截掉或截多 | PDF 的增量更新区、ZIP 的注释区 |

一个具体的对照。这是必须在报告中呈现的形态：

```
原始文件（真实内容 48,000 字节，存于 12 个簇，末簇只用了 9,056 字节）：
┌──────────────────────────────────────────────┐
│ [真正的 48,000 字节内容]        │ 9,056 字节  │ 9,600 字节的簇
│                                  │ 残留 9,600 │ ← 下一个文件的数据
└──────────────────────────────────────────────┘

foremost 切出的结果：
┌──────────────────────────────────────────────┐
│ [48,000 字节内容]                │ 9,600 字节 │ ← 尾部混入了别的文件
└──────────────────────────────────────────────┘
   实际大小 = 57,600 字节

sha256sum 原始文件  = a3f5...9c2e
sha256sum carving件 = 7b1d...4e88     ← 完全不同！无法与原文件哈希匹配
```

因此，"用 carving 结果的哈希去和嫌疑人电脑上的文件哈希比对"是行不通的——两者本来就不可能相等。

<a id="section-9"></a>

#### 那 carving 产物到底是什么？

法律与取证实务中的定位是"重建产物"（reconstructed artifact）：

| 维度 | 原件（original） | carving 产物（reconstructed） |
|---|---|---|
| 字节级同一性 | ✅ | ❌ 边界靠推定，多数情况下有偏差 |
| 哈希 | 唯一、权威 | **只是这个重建件的指纹，不能代表原文件** |
| 文件名 | 已知 | **完全丢失** |
| 时间戳 | 完整 | **丢失**（除非格式内嵌） |
| 归属/上下文 | 完整 | **完全丢失** |
| **可提交为"该文件的原件"吗** | ✅ | ❌ **不能** |

**正确的处置方式**（必须写进报告）：

1. **明确标注性质**："以下文件为 carving 重建产物，非原件；其哈希值仅代表该重建件本身。"
2. **记录完整坐标**：文件名（工具生成）、**在镜像中的起始偏移与长度**、提取时间、工具版本、配置（审计文件）。
3. **内容层面的结论**可以采信，但必须表述为**内容特征**而非文件身份："该区域存在一段 JPEG 图像数据，可解码为 1920×1080，内容为……"——而不是"恢复了原始照片 X.jpg"。
4. **绝不与原件哈希混用**：不要把 carving 产物的哈希填进"证据文件哈希表"而不加区分。
5. **作为线索而非结论**：carving 的价值是**发现**（发现这里有可疑内容），**后续需要用其他证据（元数据、日志、供述）来印证**它的身份和来源。

> **一句话总结**：carving 告诉你"盘上这里有东西"，但它无法告诉你"这东西曾经叫什么、属于谁、何时产生"。 后者必须靠文件系统元数据、用户活动记录、时间线交叉分析来补（见 [计算机取证](../../computer/computer-browser-behavior/computer-browser-behavior-srum.md) 与 [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)）。把 carving 产物当原件提交，是取证流程中性质最严重的错误之一。

<a id="section-10"></a>

### 2.4 目标选择：carve 什么、carve 哪里

盲目对整盘 carve 会产出海量垃圾（GB 级 jpeg），淹没真正有价值的内容。必须有策略：

**（1）按目标格式**（最基本）

```bash
foremost -t jpg,pdf,doc -i /work/DigiForensics.dd -o /evidence/carve
```

**（2） carve 未分配空间（而非整盘）**

整盘 carve 会把**当前存在的所有文件也切一遍**——它们本身完好，用 `tsk_recover` 导出更完整（保留文件名和路径）。carve 的价值只在于捞出"元数据已失、但数据还在"的东西。

```bash
# 用 blkls 提取未分配空间，再对这块 carve
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd
# 然后对 unalloc.dd carve
foremost -t jpg -i /evidence/unalloc.dd -o /evidence/carve-unalloc
```

> **这是很多流程做错的一步**：直接对整盘 `foremost`，然后花大量时间筛选"哪些是已删除的"——实际上当前文件用 `tsk_recover` 导出（保留完整元数据），carve 只管未分配空间。 两者定位不同、产物性质不同，**报告里必须分开呈现。**

**（3）按格式特性选择区域**（进阶，参考 [07](../filesystem-mobile-fs/filesystem-mobile-fs-f2fs.md) 的段类型分析）

大媒体文件（视频）在碎片少的大簇区域；小文件（日志、配置）在热区。F2FS 上可按段类型、C/APFS 上可按 CoW 旧块来缩小范围。

<a id="section-11"></a>

### 2.5 未分配空间：carve 的主战场

分区空间构成：
```
┌──────────────────┬──────────────────┬──────────────────┐
│  已分配（文件占用）│  未分配（空闲池）   │ 元数据区          │
│  → 用 tsk_recover  │  → ★ 用 carving  │ → 用 fsstat 解析  │
│  （保留文件名）     │  （数据还在这）    │                  │
└──────────────────┴──────────────────┴──────────────────┘
       ↓
  被删除文件的数据落在这里，直到被新数据覆盖
```

**提取未分配空间的工具**：

```bash
# TSK：提取未分配簇（blkls = block listing）
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd

# 或用 fls 的未分配视图（slack 等）
```

> **注意区分"未分配"与"Slack"**：Slack 是**已分配簇的尾部未使用空间**（文件大小小于簇大小的剩余），`blkls` 默认也会导出。Slack 里常有小文件的残片（如被删除的小配置、注册表碎片），**有时比整个未分配池更有针对性**。

**未分配空间的数量本身是取证指标**：一个正常使用一段时间的系统，未分配空间占比应在合理范围；如果几乎为 0，可能说明设备刚做过 TRIM/安全擦除，或被反取证工具清理过。

<a id="section-12"></a>

### 2.6 分页（page）问题：内存镜像与大文件的特殊处理

"分页"在 carving 语境下指两类不同的分页问题，容易混淆：

**（1）工具内部的分页读取**：大镜像不可能一次读入内存，工具按固定块（如 16 MB）分块读取，逐块扫描。**跨块的魔数**（正好在块边界）必须被正确处理，否则会漏检或重复。

**（2）运行分页文件（page file）**：内存镜像和 Windows/Linux 的交换文件（`pagefile.sys`、`swapfile.sys`）是**分页存储**的——内存内容被切块写入这些文件。**这与普通文件不同，carving 需要特殊处理**：

```bash
# Windows 交换文件（不释放内存内容 → 大量已关闭程序的残留）
icat -o 2048 /work/DigiForensics.dd 263 -r > /evidence/pagefile.bin
# 然后对 pagefile.bin carve
foremost -t doc,zip,pdf -i /evidence/pagefile.bin -o /evidence/carve-page
```

**swap 文件的特殊价值**：**swap 里可能有"已加密卷的明文"**——用户在 BitLocker 卷中打开文件，数据在内存中被加密前曾驻留 swap。这是破解加密卷的一条现实途径（见 [BitLocker 与 VeraCrypt](../../crypto/crypto-volume/crypto-volume-bitlocker.md)）。

**bulk_extractor 对分页有专门支持**：

```bash
# -G <页大小>：指定分页大小（字节），让工具在正确的页边界上匹配
# （许多"特征"跨页出现，页大小不对会导致漏检）
bulk_extractor -o /evidence/be-out -G 4096 /work/DigiForensics.dd
```

**分页文件 carving 的注意事项**：

| 事项 | 说明 |
|---|---|
| **不按"文件大小"切** | 交换文件里的"内容"没有完整文件边界，**按魔数切会切出大量碎片** |
| **关注"散落"的证据** | 关键可能只是一个 URL、一段命令行——用 `bulk_extractor` 而非 `foremost` |
| **重复是常态** | 同一页面多次换入换出会产生重复，**必须去重** |
| **不要期待完整性** | 绝大多数"文件"是残片，**任何"恢复出完整文件"的表述都需极度谨慎** |

<a id="section-13"></a>

### 2.7 定位策略：优先元数据，其次 carving

**这是流程层面的核心建议**：carving 不适用于所有恢复情形，可作为**文件系统路径失败后的补充方法**。正确顺序：

```
第 1 优先：文件系统元数据完整时
  tsk_recover（保留文件名、路径、时间戳）
  ↓ 失效？↓
第 2 优先：文件系统部分损坏时
  fls/istat/icat 定向提取已删除项（保留尽可能多的元数据）
  ↓ 失效？↓
第 3 优先：文件系统完全不可解析时
  carving（★ 只有内容，丢失全部上下文）
```

**`tsk_recover` 的正确用法**（很多流程直接跳过它跑 foremost，是本末倒置）：

```bash
# 只提取已删除文件（默认行为）
tsk_recover -o 2048 /work/DigiForensics.dd /evidence/recover-deleted/

# 提取所有文件（含已分配）
tsk_recover -e -o 2048 /work/DigiForensics.dd /evidence/recover-all/

# 保留目录结构（默认行为，优于扁平化）
```

> `tsk_recover` 产物与 carving 产物的证据效力完全不同：前者**保留了原始文件名、路径、部分时间戳**（因为这些来自未被覆盖的元数据），**其性质接近原件**；后者是纯重建产物。**报告里必须分别标注，不能混为一谈。**

---
<a id="section-14"></a>

## 三、操作步骤

<a id="section-15"></a>

### 3.1 第 1 步：评估可行性（决定是否 carve）

**carve 之前必须先回答四个问题**，否则可能在无意义的工序上消耗大量时间：

```bash
# ① 文件系统是否还能解析？（决定优先用 tsk_recover 还是 carving）
fsstat -o 2048 /work/DigiForensics.dd | head -20
fls -o 2048 /work/DigiForensics.dd | wc -l        # 能列出多少项

# ② 未分配空间有多大？（决定 carve 的产出规模）
blkls -o 2048 /work/DigiForensics.dd | wc -c       # 字节数
# 若为 0 → 设备可能已 TRIM / 擦除，carving 无意义

# ③ 卷层是否有未分配区间（另一处藏身点）
mmls /work/DigiForensics.dd                        # 看 Unallocated 行

# ④ 元数据优先：能直接恢复的先恢复
tsk_recover -o 2048 /work/DigiForensics.dd /evidence/recover-deleted/
find /evidence/recover-deleted -type f | wc -l
```

**决策表**：

| 情况 | 策略 |
|---|---|
| `fls` 能列出大量文件，`blkls` 体积正常 | **优先 `tsk_recover`**，carve 作为补充 |
| `fsstat` 报错或文件数为 0，但 `blkls` 有大量数据 | **文件系统损坏 → 以 carve 为主** |
| `blkls` 输出接近 0 | 数据已被覆盖/TRIM → carve 无用，应转向日志、云端、其他设备 |

<a id="section-16"></a>

### 3.2 第 2 步：提取未分配空间并 carve

```bash
# ① 提取未分配空间
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd
ls -lh /evidence/unalloc.dd

# ② foremost 雕刻（-i 输入，-o 输出目录，-t 类型，-v 详细）
#    注意拼写是 foremost（前置 f），不是 formost
foremost -t jpg,pdf,doc,zip,png -i /evidence/unalloc.dd -o /evidence/carve-fm -v
# 完成后生成：
#   /evidence/carve-fm/audit.txt   ← 审计文件（★ 必看）
#   /evidence/carve-fm/jpg/00000000.jpg
#   /evidence/carve-fm/pdf/00000001.pdf
#   ...

# ③ 关键：先读 audit.txt，它记录了每个产物的偏移和大小
head -30 /evidence/carve-fm/audit.txt
# Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
# Audit File
# Foremost started at ...
# Invocation: foremost -t jpg,pdf,doc,zip,png -i /evidence/unalloc.dd -o /evidence/carve-fm
# Num  Name (bs=512)  Size  File Offset  Comment
# 0:   00000000.jpg   24576  8192
# 1:   00000064.jpg   128000  131072
# ...
# Finish: ...
# 2 FILES EXTRACTED
# jpg:= 2  pdf:= 0  doc:= 0  zip:= 0
```

**`audit.txt` 是报告的必备材料**：它记录了工具版本、**完整命令行**、配置、每个产物的**偏移量与大小**——**这些是让第三方复核的唯一依据**。

<a id="section-17"></a>

### 3.3 第 3 步：scalpel（更快的替代）

```bash
# scalpel 是 foremost 0.69 的重写版，速度快、内存占用低
# ★ 关键：scalpel.conf 中所有类型默认被注释掉，必须先启用！
sudo nano /etc/scalpel/scalpel.conf
# 取消注释需要的行，例如：
#   jpg   y 20000000 \xff\xd8\xff\xe0 \xff\xd9
#   pdf   y 10000000 \x25\x50\x44\x46 \x25\x25\x45\x4f\x46
#   doc   y 20000000 \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 \x00\x00\x00\x00

# 预览模式（不实际提取，先看会切出什么）——强烈建议先跑这个
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out \
        -p /evidence/unalloc.dd
# 检查 audit.txt 后再正式提取

# 正式提取
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out \
        /evidence/unalloc.dd
ls -lh /evidence/scalpel-out/
```

**scalpel 的关键选项**：

| 选项 | 作用 | 取证价值 |
|---|---|---|
| `-c <conf>` | 指定配置文件 | **必须显式指定**，默认所有类型关闭 |
| `-o <dir>` | 输出目录 | **必须为空或不存在** |
| `-p` | **预览模式，不提取** | **先看 audit 再决定，避免产出垃圾** |
| `-v` | 详细模式 | 观察进度 |
| `-b` | **即使找不到尾标记也提取（到上限大小）** | **恢复"只有头、尾被覆盖"的文件** |
| `-q <簇大小>` | 只在簇边界处切 | **显著降低误报**（不找内嵌文件时用） |
| `-e` | 嵌套头尾匹配 | 处理容器中内嵌的同类文件 |

**`-b` 选项的取证意义值得单独说明**：文件头还在、尾标记被覆盖是常见情形（文件尾部所在簇被复用）。`-b` 让工具在找不到尾标记时按配置的最大大小切出，这类产物通常带有尾部垃圾数据，必须在报告中标注"尾标记缺失，边界为工具推定上限"。

<a id="section-18"></a>

### 3.4 第 4 步：photorec（无尾标记格式的补救）

```bash
# photorec 支持命令行模式（与 testdisk 同包）
# 先列出支持的分区
photorec /log /d /evidence/photorec-out /cmd /evidence/unalloc.dd \
         partition_none,fileopt,everything,enable,freespace
#  /log            → 生成 photorec.log（★ 报告需要）
#  /d <dir>        → 输出目录（必须为空）
#  /cmd            → 命令行模式（无 GUI）
#  partition_none  → 不做分区扫描（输入已是未分配空间块）
#  fileopt,everything,enable → 启用全部文件类型
#  freespace       → 只处理空闲空间

# 实际运行中会询问交互式问题，建议用 -q 或预设配置
# 完成后输出：/evidence/photorec-out/recup_dir.1/ 等
ls /evidence/photorec-out/
find /evidence/photorec-out -type f | wc -l
```

**photorec 的特性**：

| 特性 | 说明 |
|---|---|
| **不依赖尾标记** | **对 Office、数据库、碎片等无尾格式更有效** |
| **按格式内部结构判断边界** | 会解析文件结构决定切到哪 |
| **文件名带序号** | `f0001234.jpg`，**无原始文件名** |
| **产出量大、噪声高** | **必须后处理筛选** |
| 依赖运行时库 | 部分版本需 `libqt5*` 或 `libewf` 等 |

> photorec 的产物性质与 foremost 完全相同：纯重建产物。 且它的边界判定依赖"格式结构规则"而非尾标记，边界误差可能更大。报告中同样必须标注为重建产物。

<a id="section-19"></a>

### 3.5 第 5 步：bulk_extractor（特征提取，思路不同）

```bash
# bulk_extractor 不追求"文件"，提取的是"特征"
# 基本用法：-o 输出目录（必须），最后跟输入
bulk_extractor -o /evidence/be-out /work/DigiForensics.dd
# 生成多个特征文件：
#   email.txt  url.txt  ip.txt  ccn.txt  domain.txt
#   telephone.txt  json.txt  wordlist.txt  exif.txt  histogram/  report.xml
```

**常用选项**：

| 选项 | 作用 | 取证价值 |
|---|---|---|
| `-o <dir>` | 输出目录（**必填**） | |
| `-e <scanner>` | **只启用**指定扫描器 | `-e email`、`-e exif`（提速减噪） |
| `-x <scanner>` | 禁用指定扫描器 | |
| `-E <scanner>` | **只跑这一个**（其余全禁） | 专项提取时最干净 |
| `-f <pattern>` | **搜索自定义正则** | **找自定义标记，如 `INTERNAL-TAG:`** |
| `-F <file>` | 从文件读一批正则 | 批量搜索 |
| `-R` | 递归（进入 ZIP/PDF/GZIP 内部） | **能钻进压缩包** |
| `-G <size>` | **分页大小（字节）** | **跨页特征必须设对，否则漏检** |
| `-S <name>=<val>` | 高级配置 | 如 `-S jpeg_carve_mode=2` 雕刻所有连续 JPEG |
| `-H` | 列出所有扫描器及其信息 | 了解可用扫描器 |

**常用场景**：

```bash
# ① 提取邮件/URL（社交工程与外泄线索）
bulk_extractor -o /evidence/be-comm /evidence/unalloc.dd -e email -e url

# ② 提取 EXIF（照片的 GPS 与拍摄时间——即使照片本身恢复不了）
bulk_extractor -o /evidence/be-exif /work/DigiForensics.dd -E exif
# 优势：EXIF 扫描器能从部分 JPEG 中提取 GPS，
#      即使该 JPEG 残缺到无法作为完整图片恢复 ★

# ③ 递归钻进压缩包
bulk_extractor -R -o /evidence/be-recurse /evidence/unalloc.dd

# ④ 搜索自定义标记（针对性最强）
bulk_extractor -o /evidence/be-custom -f 'CASE-2024-\d{4}' /work/DigiForensics.dd
# 在碎片化的未分配空间里找案件编号——这类"特征"永远不可能被完整文件恢复覆盖
```

bulk_extractor 的独特价值（必须理解）：

> **它能找到"根本不成其为文件"的证据。** 一个邮箱地址躺在 200 字节的未分配空间里，周围没有头也没有尾——没有任何 carving 工具能把它"恢复成文件"，但 bulk_extractor 能提取它。而**这类痕迹往往才是案件的关键**（一个外泄的邮箱、一条 URL、一次 GPS 定位）。

**它的局限也必须写明**：

- **产出是"特征列表"，不是"文件"**——`email.txt` 里的一行**不能作为"邮件原件"提交**，它只是"该位置存在这个字符串"的事实
- **误报率高**——正则匹配会把随机字节组合成"看似合法"的邮箱/IP，**必须逐条人工核实**（如检查上下文）
- **无文件边界概念**——无法回答"这个特征属于哪个文件"

<a id="section-20"></a>

### 3.6 第 6 步：后处理（清洗、去重、验证）

**carve 完成后，直接提交是严重错误。** 必须清洗：

```bash
cd /evidence/carve-fm

# ① 全部产物先做类型核验（不要信工具给的扩展名）
file -r --mime-type . > /evidence/carve-mime.txt
# 找出"工具说是 jpg、实际不是"的
grep -v 'image/jpeg' /evidence/carve-mime.txt | grep '/jpg/' | head

# ② 哈希 + 去重（碎片化与重复必然产生大量冗余）
find . -type f -exec sha256sum {} \; > /evidence/carve-hashes.txt
total=$(wc -l < /evidence/carve-hashes.txt)
uniq_out=$(awk '{print $1}' /evidence/carve-hashes.txt | sort -u | wc -l)
echo "总产物 $total 个，去重后 $uniq_out 个（重复 $((total-uniq_out)) 个）"
# ↑ "重复数量"本身就是取证指标：说明该区域有多份相同数据（CoW/换入换出/多次拷贝）

# ③ 完整性验证（分格式）
#   图片：能否解码
for f in jpg/*.jpg; do identify "$f" 2>/dev/null || echo "损坏: $f"; done | head
#   ZIP/OOXML：能否列出条目
for f in doc/*.doc zip/*.zip; do unzip -t "$f" >/dev/null 2>&1 || echo "损坏: $f"; done | head
#   PDF：能否解析
for f in pdf/*.pdf; do pdfinfo "$f" >/dev/null 2>&1 || echo "损坏: $f"; done | head

# ④ 尺寸/大小合理性筛查（过滤碎片与垃圾）
find . -type f -size -1k -exec ls -la {} \; | head    # 极小的多半是噪声
find . -type f -size +100M | head                     # 异常大的检查是否过度切分

# ⑤ 按内容聚类，挑出真正相关的（用 bulk_extractor 的特征做交叉）
#   例如：目标案件关键词相关的
grep -l 'CASE-2024' jpg/*.jpg 2>/dev/null | head
```

**清洗后的报告必须包含**：

| 项目 | 示例 |
|---|---|
| 原始产物总数 | `4,812 个` |
| 去重后 | `1,203 个` |
| 通过完整性验证 | `387 个` |
| 与案件相关的 | `6 个`（附筛选依据） |
| 验证方法 | `identify 全部可解码` / `unzip -t 全部 CRC 通过` |

<a id="section-21"></a>

### 3.7 第 7 步：报告中的标准表述（证据效力）

**这一节是本篇的落点。** 报告里对 carving 产物的表述必须精确：

**（1）产物清单的表头**：

```markdown
| 产物编号 | 文件名 | 起始偏移 | 大小 | 格式（file 判定） | 完整性验证 | 重建方式 | 性质 |
|---|---|---|---|---|---|---|---|
| C-001 | 00000128.jpg | 0x1A4000 | 24576 | JPEG 1920×1080 | 完整可解码 | foremost 头尾定界 | 重建产物 |
| C-002 | 00000640.pdf | 0x8C2000 | 1048576 | PDF 3 页 | 完整可解析 | foremost 头尾定界 | 重建产物 |
| C-003 | 00001296.zip | 0x1200000 | 4812 | ZIP(OOXML) | 7 项 CRC 全通过 | foremost 头尾定界 | 重建产物 |
```

**注意每行都记录了"起始偏移"和"大小"**——这是让第三方能回到原始镜像复核的唯一坐标。

**（2）必须写明的性质声明**（逐字使用）：

> 本节所列文件均为通过文件雕刻（carving）从检材未分配空间中提取的重建产物，并非原始文件。
>
> - 其**字节边界由工具依据格式签名推定**，可能包含前导或尾部的无关数据，其**哈希值与原始文件必然不同**，不能用于与原文件哈希比对；
> - 雕刻过程**不保留原始文件名、路径、时间戳、所属用户等信息**，上述信息已随文件系统元数据一同丢失或不可得；
> - 上述文件**不能作为"该原始文件"的原件提交**，其证据性质为"该检材未分配空间区域存在相应格式的内容，且内容特征为……"；
> - 上述内容的原始身份、来源与形成时间，需结合文件系统元数据、用户活动记录、系统日志等其他证据另行认定。

**（3）对比：tsk_recover 产物的表述**（元数据保留，性质接近原件）：

> 以下文件通过 `tsk_recover` 从检材的已删除文件项中导出，**保留了原始文件名与目录结构**，其**哈希值与原始文件一致**，可作为对应文件的证据副本提交。

<a id="section-22"></a>

### 3.8 第 8 步：分页文件与内存镜像的 carve

```bash
# ① Windows 交换文件（inode 需从 fls 获取，263 常为 pagefile.sys）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'pagefile|swapfile'
icat -o 2048 /work/DigiForensics.dd 263 -r > /evidence/pagefile.bin
ls -lh /evidence/pagefile.bin

# ② 对 swap carve（碎片多，预期大量残片）
foremost -t doc,pdf,zip -i /evidence/pagefile.bin -o /evidence/carve-swap

# ③ 内存镜像：用 bulk_extractor 效果远好于 foremost
bulk_extractor -o /evidence/be-mem /work/DigiForensics-mem.raw
# 内存 carve 的特殊价值：
#   - 加密卷中已解密的内容可能仍在内存
#   - 已关闭程序的代码与数据
#   - 凭证、会话令牌
ls /evidence/be-mem/ | head -20

# ④ 分页大小敏感的特征（跨页结构的扫描器）
bulk_extractor -o /evidence/be-page -G 4096 /work/DigiForensics.dd
# -G 是 bulk_extractor 特有的分页选项，页大小设错会导致跨页特征漏检
```

**内存与 swap 雕刻的额外注意**：

| 事项 | 说明 |
|---|---|
| **重复率极高** | 同一页面多次换入换出，**去重是必需步骤** |
| **无"文件边界"** | swap 里的内容没有完整文件边界，**产物几乎都是残片** |
| **敏感度高** | 可能包含凭证、会话、加密内容——**处置需按敏感证据管理** |
| **只能表述为"特征"** | 不能说"恢复了邮件"，只能说"该区域存在此邮箱地址字符串" |

---
<a id="section-23"></a>

## 四、常见陷阱

本章按「方法选择 → 工具参数与执行 → 产物判定与清洗 → 证据效力与结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-24"></a>

### 4.1 方法选择：carving 什么时候是错误答案

<a id="section-25"></a>

#### 陷阱 1：元数据可用还跑整盘 carve，或者干脆对原始设备 carve

**现象**：拿到镜像就开始 `foremost -t all -i /work/DigiForensics.dd`，产出数万个文件，花几天时间筛选"哪些是已删除的"；或者为省时间把 `/dev/sdb` 直接作为 `foremost -i` 的输入。

**原因**：这里叠了两层错误。

第一层是**方法选择**。carving 假设"文件的字节在盘上是连续的"，而当前存在的文件往往完全连续——它们本来就被完整地存在盘上，签名扫描会把它们原样切一遍，产出与 `tsk_recover` 的结果字节相同，但丢掉了文件名、路径、时间戳。

2.4 已经点明："carving 的价值只在于捞出元数据已失、但数据还在的东西"。

而"哪些是已删除的"这个问题，**文件系统自己就有答案**（`fls` 能列出已删除项），不需要靠产物特征去猜。

第二层是**输入选错**。**"只读打开块设备"看起来是安全的**——carving 确实只读。

但**读的是活的生产设备**：设备在被读取期间仍在运行、仍在被系统使用、swap 与日志仍在写入。**"我没有写"不等于"检材没有变"。**

**影响**：**未优先使用已有的文件系统元数据**。

整盘 carve 产出 GB 级垃圾，而真正有价值的 1 个文件淹没在里面；证据效力还被自己降低——`tsk_recover` 产物保留元数据、哈希与原件一致，carve 产物不保留，**而后者本来根本不需要**。

案例第 1 步的关键判断就是这一条：`fls` 直接列出了已删除的 `合同扫描件.pdf`（inode 44902-256-3），这种情况下 carving 是错误的工具选择。

对活设备操作则更严重：**破坏证据的时间连续性**——你记录的是"某个时间点的镜像"，**实际上不存在这样一个时间点**；而且原始设备无法复制备份，**一旦出问题没有第二次机会**。

**核查**：**四级定位顺序，先元数据后 carving**（2.7 的决策图），**输入永远在镜像层**：

```bash
# ① 评估：文件系统能否解析
fsstat -o 2048 /work/DigiForensics.dd | head -20
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'deleted' | grep -iE '合同|contract'

# ② 定向提取已删除项 —— 保留文件名、时间戳，哈希与原件一致
icat -o 2048 /work/DigiForensics.dd 44902-256-3 > /evidence/合同扫描件.pdf
istat -o 2048 /work/DigiForensics.dd 44902-256-3 | grep -E 'Size|Modified'

# ③ 只有元数据确实不可用时才上 carving，且只对未分配空间
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd
foremost -t jpg,pdf -i /evidence/unalloc.dd -o /evidence/carve-fm
```

| `fls` / `blkls` 结果 | 正确路径 |
|---|---|
| `fls` 列出大量已删除项 | **`icat` 定向提取**，carve 仅作补充 |
| `fsstat` 报错但 `blkls` 有大量数据 | 以未分配空间 carve 为主 |
| `blkls` 接近 0 | **数据已被覆盖/TRIM，carve 无用**，转向日志、云端、其他设备 |

**每次 carve 前记录输入的哈希**，让"产物来自哪个版本的检材"可追溯：

```bash
sha256sum /work/DigiForensics.dd > /evidence/source-hash.txt
cat /evidence/source-hash.txt
```

大镜像内存不足时（2.6 的分页问题）也要靠镜像侧解决——工具内部按块读取，**跨块魔数必须被正确处理**，但输入仍然是镜像文件。

<a id="section-26"></a>

#### 陷阱 2：把 carving 产物当原件提交

**现象**：carve 出 `00000128.jpg`，报告产物清单表头写"证据文件"，`sha256sum` 填进"证据文件哈希表"，与 `tsk_recover` 导出的文件混在同一张表里。

**原因**：carving 产物是重建产物（reconstructed artifact），不是原件——这是 2.3 整节的内容。哈希是逐字节指纹，**只要有一个字节对不上就完全不同**，而边界误差是方法论层面的必然（2.3 列了五个原因：尾部过度切分、头部过度切分、碎片化截断、填充字节、原文件自带元数据）。混在一张表里之所以危险，是因为表格形式本身就暗示了"这些是同质的证据"。

**影响**：2.3 把它称为"取证流程中性质最严重的错误之一"。具体后果有三层：

① 委托方的哈希比对会直接失败，而失败原因（提取方式不对）容易被误读为"文件内容有差异"，进而怀疑检材被替换；

② 若已提交，对方只需打开文件就能发现边界处的残留数据，整份报告的可信度受牵连；

③ 在争议程序中，**把重建件当作原件陈述，是事实陈述层面的错误**。

**核查**：**两类产物必须分表呈现，且表头就写明性质**（3.7 的清单格式）：

| 产物编号 | 文件名 | 起始偏移 | 大小 | 格式（file 判定） | 完整性验证 | 重建方式 | 性质 |
|---|---|---|---|---|---|---|---|
| R-001 | 合同扫描件.pdf | 0x1A4000 | 1843200 | PDF 12 页 | `pdfinfo` 可解析 | `icat` 按 MFT 簇链 | **元数据保留，接近原件** |
| C-001 | 00000128.jpg | 0x1A4000 | 24576 | JPEG 1920×1080 | 完整可解码 | foremost 头尾定界 | **重建产物** |

**`audit.txt` 是必备材料**——它记录工具版本、完整命令行、每个产物的偏移与大小，**这是让第三方复核的唯一坐标**：

```bash
head -30 /evidence/carve-fm/audit.txt
# Num  Name (bs=512)  Size  File Offset
# 0:   00000000.jpg   24576  8192
```

<a id="section-27"></a>

#### 陷阱 3：用 carving 产物哈希去比对原文件哈希

**现象**：委托方给出目标文件的 SHA-256，carve 产物哈希不匹配，报告写"检材中不存在该文件"。

**原因**：**这两者本来就不可能相等**（2.3 的结论句）。案例第 3 步把这件事做成了正面对照：原件 1,843,200 字节、`icat` 提取后哈希完全一致；`foremost` 切出 1,925,120 字节（多 81,920 字节 = 18 个簇的残留数据），**哈希完全不同**。而"哈希不匹配"这个现象**容易被读成"东西不对"**，它很少被读成"我的提取方式不对"。

**影响**：**一个彻底的假阴性**。

委托方会据此认定文件不存在于检材中，从而排除一整条线索——**而真相是文件在盘上，只是提取方式错了**。

案例明确写道："若案卷中提交的是 carving 产物，委托方的哈希比对将直接失败，原因是提取方式不对，而非文件内容有差异。"

**核查**：**哈希在 carving 流程里只有一个用途：去重**。

```bash
# ✅ 正确用途：去重（重复数量本身是取证指标）
find . -type f -exec sha256sum {} \; > /evidence/carve-hashes.txt
total=$(wc -l < /evidence/carve-hashes.txt)
uniq_out=$(awk '{print $1}' /evidence/carve-hashes.txt | sort -u | wc -l)
echo "总产物 $total，去重后 $uniq_out，重复 $((total-uniq_out))"

# ❌ 错误用途：carve 件哈希 vs 委托方给定哈希 → 必然不匹配
```

**需要哈希匹配时的正确路径**是元数据定向提取：

```bash
icat -o 2048 /work/DigiForensics.dd 44902-256-3 > /evidence/合同扫描件.pdf
sha256sum /evidence/合同扫描件.pdf
# 与委托方给定值一致 → 这才是有效的同一性证明
```

**报告写法**："`icat` 按 `$MFT` 簇链定向提取 inode 44902-256-3，提取 1,843,200 字节（与 `istat` 的 `Size` 一致），SHA-256 与委托方给定值**逐位一致**。该文件可作为对应原始文件的证据副本提交。**对比**：对同一目标区域做 foremost carving 切出 1,925,120 字节，哈希不同——该差异源于边界推定误差，不构成"文件内容有差异"的证据。"

<a id="section-28"></a>

### 4.2 工具参数与执行

<a id="section-29"></a>

#### 陷阱 4：scalpel 不改配置直接跑，carve 出 0 个文件

**现象**：`scalpel -o /evidence/scalpel-out /evidence/unalloc.dd` 跑完，输出目录空，`audit.txt` 里各类型计数全为 0。

**原因**：`scalpel.conf` 中所有类型默认被注释掉（3.3 的 ★ 标注）。而"命令正常执行、正常结束、产出为空"这个组合**看起来像"未分配空间里确实没有目标格式"**——它与"配置没生效"在现象上几乎无法区分。**0 产出是一个极易被当作阴性发现的结果。**

**影响**：**一个范围完全不足的阴性结论**。委托方读到"未分配空间中未发现 PDF"，会推断"未分配空间里没有被删的 PDF"——**而实际上一次都没启用过 PDF 规则**。

**核查**：**改配置 → 预览 → 正式提取，三步不可省**：

```bash
# ① 启用需要的类型（取消注释）
#   jpg   y 20000000 \xff\xd8\xff\xe0 \xff\xd9
#   pdf   y 10000000 \x25\x50\x44\x46 \x25\x25\x45\x4f\x46
sudo nano /etc/scalpel/scalpel.conf

# ② 预览模式：不提取，只看会切出什么 —— 强烈建议先跑
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out \
        -p /evidence/unalloc.dd
cat /evidence/scalpel-out/audit.txt

# ③ 正式提取
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out \
        /evidence/unalloc.dd
```

**预览模式是 0 产出场景的标准排查动作**——它能立刻区分"配置没生效"与"确实没有"。

<a id="section-30"></a>

#### 陷阱 5：输出目录非空，被旧结果或工具拒绝污染

**现象**：`/evidence/carve-fm` 里已有上一轮的文件，重新运行时工具报"目录已存在"或直接把新产物混进去。

**原因**：**scalpel 要求输出目录为空或不存在**（3.3 的选项表），foremost 在目录已存在时会复用它。**而"目录里有东西"这个状态在取证工作区里是常态**——上一轮的产物、审计文件、类型统计都还在。混进去的结果是**产物与 `audit.txt` 不对应**：目录里有 100 个文件，审计文件只记了这次跑出的 5 个。

**影响**：**产物清单与审计记录脱节**。而 `audit.txt` 是"让第三方复核的唯一依据"（3.2），记录与实物对不上，整个 carving 环节的可复核性就失去了。

**核查**：**每次运行一个独立的新目录，并立刻固定审计文件**：

```bash
# 目录带序号与时间戳，永不复用
OUT="/evidence/carve-run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
foremost -t jpg,pdf,doc -i /evidence/unalloc.dd -o "$OUT" -v

# 立刻把审计文件与工具版本固定进证据记录
cp "$OUT/audit.txt" /evidence/carve-audit-$(date +%Y%m%d-%H%M%S).txt
head -5 "$OUT/audit.txt" | tee /evidence/carve-tool-version.txt
```

**旧目录不要删，标记为已归档**——重新跑一轮可能是必要的，而上一轮的产出本身也是过程记录。

<a id="section-31"></a>

#### 陷阱 6：用 `foremost` 的"FILES EXTRACTED"计数当作恢复成果

**现象**：`foremost` 结束时报 `2 FILES EXTRACTED`，报告写"恢复 2 个文件"，并把这 2 个列入成果。

**原因**：这个计数只表示"切出了 2 个符合签名的字节区间"，完全不表示这两个文件是完整的。碎片化、尾标记缺失、边界偏移都会导致内容不完整，而**这些都不会让计数减少**。反过来，计数为 0 也可能是配置问题（陷阱 4）。**这个数字的含义被系统性地高估了。**

**影响**：**"恢复"二字与证据强度不匹配**。委托方看到"恢复 2 个文件"，会预期拿到 2 份可用的完整文件；而打开后发现是残片，信任成本比一开始就说"提取到 2 段图像数据"高得多。

**核查**：完整性只能由功能验证判定，且验证结果必须与计数分开报：

```bash
# 计数：来自 audit.txt
grep 'FILES EXTRACTED' /evidence/carve-fm/audit.txt
# 2 FILES EXTRACTED

# 功能验证：分格式
for f in /evidence/carve-fm/jpg/*.jpg; do
  identify "$f" 2>/dev/null || echo "损坏: $f"
done
for f in /evidence/carve-fm/zip/*.zip; do
  unzip -t "$f" >/dev/null 2>&1 || echo "损坏: $f"
done
for f in /evidence/carve-fm/pdf/*.pdf; do
  pdfinfo "$f" >/dev/null 2>&1 || echo "损坏: $f"
done
```

**两个数字必须分别出现**：签名命中数、完整可解码数。案例第 4 步的清洗后清单就是这个形态（原始产物总数 → 去重后 → 通过完整性验证 → 与案件相关的）。

<a id="section-32"></a>

#### 陷阱 7：不精修边界，把尾部垃圾算进文件

**现象**：`foremost` 切出 1,925,120 字节的"PDF"，而元数据显示真实文件只有 1,843,200 字节，分析员直接使用。

**原因**：foremost 切到下一个魔数之前，会把同簇/后续簇的残留数据一并纳入（2.3 原因①）。案例把 2.3 的图完全复现了：真实内容 48,000 字节存于 12 个簇，末簇只用了 9,056 字节，其余是下一个文件的数据；foremost 按整簇切出，**末尾混入 9,600 字节**。**这个产物能通过 `pdfinfo`**（PDF 解析器读到 `%%EOF` 就停），**能通过功能验证，但边界是错的**。

**影响**：**引入无关内容 + 哈希错误**。而"能正常打开"这个现象让人很难意识到边界有问题——**报告里的文件大小会是错的，且与文件系统元数据矛盾**。

**核查**：**用元数据交叉定界，元数据可用时优先用元数据**：

```bash
# ① 元数据里的大小是权威边界
istat -o 2048 /work/DigiForensics.dd 44902-256-3 | grep -E 'Size'
# Size: 1843200

# ② carve 产物大小与之比较，差值即为边界误差
stat -c '%s' /evidence/carve-fm/pdf/00000012.pdf
# 1925120  −  1843200  =  81920 字节 = 18 个簇

# ③ 报告必须记录这个差值，而不是把 1925120 当文件大小
```

**`-b` 选项提取的产物尤其必须标注**：它允许"即使找不到尾标记也提取（到上限大小）"，这类产物的边界是工具推定的上限，末尾几乎必然带垃圾。报告写法："尾标记缺失，边界为工具推定上限（配置上限 `<N>` 字节），实际内容边界不可知，**该产物不用于任何内容层面的定量结论**。"


<a id="section-33"></a>

### 4.3 产物判定与清洗

<a id="section-34"></a>

#### 陷阱 8：信工具给的扩展名，不做类型核验

**现象**：`/jpg/00000000.jpg` 出现在产物目录里，统计为 18432 个 image/jpeg，报告写"该分区存在 18432 张 JPEG 图片"。

**原因**：**扩展名是工具按签名"猜"的结果，不构成独立证据**。而 18432 这个数字是**签名命中的数量，不是有效图片的数量**——**碎片、重复、过切产物全部计入**。3.6 的第①步就是"全部产物先做类型核验（不要信工具给的扩展名）"，第④步还要做尺寸筛查过滤碎片。

**影响**：**把碎片统计当成资产清点**。18432 写进报告后，它看起来客观、实则无意义，而真正要回答的问题——"其中多少是完整可解码的有效图片"——完全没答。

**核查**：**清洗流水线，四道筛子**：

```bash
cd /evidence/carve-fm

# ① 类型核验
file -r --mime-type . > /evidence/carve-mime.txt
grep -v 'image/jpeg' /evidence/carve-mime.txt | grep '/jpg/' | head

# ② 哈希去重（重复数量本身是取证指标：CoW/换入换出/多次拷贝）
find . -type f -exec sha256sum {} \; > /evidence/carve-hashes.txt
awk '{print $1}' /evidence/carve-hashes.txt | sort -u | wc -l

# ③ 完整性验证
for f in jpg/*.jpg; do identify "$f" 2>/dev/null || echo "损坏: $f"; done

# ④ 尺寸合理性筛查
find . -type f -size -1k | wc -l      # 极小的多半是噪声
find . -type f -size +100M            # 异常大的检查是否过度切分
```

**报告必须给四个数字**（3.6 的表）：原始产物总数、去重后、通过完整性验证的、与案件相关的（附筛选依据）。

<a id="section-35"></a>

#### 陷阱 9：忘 CoW 与 swap 的重复，不去重

**现象**：内存镜像 carve 产出 12 万个文件，报告写"发现 12 万个文件残留"。

**原因**：**内存镜像与 swap 文件的重复率极高**——同一页面多次换入换出会产生大量相同副本（2.6、3.8 的注意事项表都写了"重复是常态"、"必须去重"）。APFS 这类 CoW 文件系统上，同一份内容还会有多个物理副本。而"文件数量"这个统计在没有去重的情况下与内容量之间没有任何关系。

**影响**：**数量级误导**。12 万这个数字会让委托方高估数据量、低估确定性，而它掩盖了"去掉重复后其实只有几百个唯一内容"这个事实。

**核查**：**内存与 swap 产物去重是必需步骤，不是优化**：

```bash
# swap：先按 inode 提取（263 常为 pagefile.sys，实际值从 fls 取）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'pagefile|swapfile'
icat -o 2048 /work/DigiForensics.dd 263 -r > /evidence/pagefile.bin

# 内存：优先 bulk_extractor 而不是 foremost
bulk_extractor -o /evidence/be-mem /work/DigiForensics-mem.raw

# 去重（两种情况同等必需）
cd /evidence/carve-swap && find . -type f -exec sha256sum {} \; \
  | sort -k1,1 | uniq -w64 -D > /evidence/swap-duplicates.txt
wc -l /evidence/swap-duplicates.txt
```

**`-G` 分页大小也要设对**：跨页出现的特征页大小不对会漏检（2.6、3.5 都强调）：

```bash
bulk_extractor -o /evidence/be-page -G 4096 /work/DigiForensics.dd
```

<a id="section-36"></a>

#### 陷阱 10：把 bulk_extractor 的特征当"文件"，且不核实误报

**现象**：`/evidence/be-out/email.txt` 里有 400 行邮箱地址，报告写"恢复了 400 封邮件的收发件人"；`ccn.txt` 里出现 400 个"信用卡号"，据此写"发现 400 张被盗用信用卡"。

**原因**：这是**两个叠在一起的错误**。

第一，bulk_extractor 不追求"文件"，只提取"特征"（2.1 的策略 C，3.5 的定位表）。`email.txt` 里的一行不能作为"邮件原件"提交——它只是"该位置存在这个字符串"的事实。它**无文件边界概念**，无法回答"这个特征属于哪个文件"。而 `email.txt` 这个文件名本身极具暗示性，读起来就像一份邮件列表。

第二，正则匹配会把随机字节组合成"看似合法"的邮箱/IP/卡号（3.5 的局限原文："必须逐条人工核实"）。未分配空间里全是无结构的随机字节，**其中出现 16 位数字的组合概率相当高**，而校验位规则、常见卡号前缀这些约束在实际随机数据里经常被碰巧满足。

**影响**：把"存在字符串"表述成"存在邮件"，中间差的是整个通信内容——委托方据此会去追查这批邮箱对应的通信记录，而那些记录可能根本不存在。更棘手的是信噪比：400 条命中里即使真有一条，它的存在率也只有 0.25%，真阳性几乎不可能被识别出来；而"发现 400 张被盗卡"一旦写进报告，**责任指向就是错的**。

**核查**：**特征只能表述为特征、标注位置，并逐条核实误报**：

```bash
# 位置信息是特征的必要组成
grep -n 'target@' /evidence/be-out/email.txt

# 上下文窗口核实：前后字节是否构成合理的邮件头/记录结构
bulk_extractor -o /evidence/be-v -C 25 -e ccn -e email /work/DigiForensics.dd
```

| 上下文形态 | 判读 |
|---|---|
| 前后有结构化分隔、连续同类记录 | 真实数据（可能来自某个文本文件） |
| 前后是随机字节、无分隔 | **高度可疑为误报** |
| 数字串出现在 PE/压缩流内部 | 大概率是常量表或压缩数据的巧合 |

**报告写法必须同时给出定位与核实工作量**：

> "在 `/work/DigiForensics.dd` 全镜像范围内，以 `bulk_extractor` 邮件扫描器（含 15 字节上下文窗口）检索，命中 400 条，**逐条核实 400 条**，其中 3 条通过上下文核实（`<列出上下文特征>`），397 条判定为随机字节巧合。
> 该结果为特征提取，不构成邮件原件，未包含邮件正文、收发时间与完整头部。本报告采用 3 条结果。"

**EXIF 是这类工具的独特价值所在**：即使 JPEG 残缺到无法作为完整图片恢复，EXIF 扫描器仍可能提取出 GPS 与拍摄时间（3.5 的场景②）。但表述方式与邮箱相同——是"该位置存在此坐标"，不是"恢复了这张照片"。

<a id="section-37"></a>

### 4.4 证据效力与结论表述

<a id="section-38"></a>

#### 陷阱 11：写"已恢复所有删除的文件"

**现象**：carve 完成，清洗后报告一段写"已恢复全部被删除的文档，共 6 个"。

**原因**：carving 的召回率远低于 100%，且无法事先知道漏了什么（2.2 局限三的实务结论："报告里绝不能写'已恢复所有删除的文件'"）。三类内容 carving 完全无能为力：**纯文本/CSV/代码（无魔数）**、**必须完整才能解析的数据库片段**、**已加密数据**。而这在真实检材里占比很高——日志、配置、CSV 导出、源码、密钥文件全都在这个盲区里。

**影响**：**这是一个关于案件可行性的错误结论**。

委托方据此认为数据已完整取回，可以结案或向数据主体作出不再追查的决定。

**而实际上有整类内容从未被检查过**——这个缺口在几周后委托方发现关键日志缺失时才会显现。

**核查**：阴性范围必须写清，并显式列出 carving 的盲区：

> "**恢复范围**：在 `DigiForensics.dd` 的 NTFS 未分配空间（`blkls` 提取，412,663,838,528 字节）内，以 foremost 对 jpg / pdf / doc / zip 四类格式做头尾定界雕刻，共命中 2 个 PDF 与 1 个 doc，经功能验证（`pdfinfo` 可解析 12 页、`unzip -t` CRC 通过）全部可用。
> **本次未覆盖的范围**：① 无魔数格式（纯文本、CSV、源代码、配置文件、日志）；② 需完整才能解析的结构（SQLite 等数据库）；③ 加密或压缩二次封装的内容；④ 碎片化程度高、尾标记已被覆盖的内容；⑤ 已分配区域（该区域当前文件由 `tsk_recover` 导出，不经 carving）；⑥ 闪存设备上已被 TRIM / GC 回收的块。
> **本结论不表明检材中不存在其他已删除内容。**上述范围内的可用路径为文件系统元数据定向提取（`fls` / `icat`）。"

**最后一句是必需的**——它把"技术上做不到"与"不存在"这两件事分开。

<a id="section-39"></a>

#### 陷阱 12：把 carve 产物的坐标与大小写错或漏记

**现象**：产物清单里只有文件名与大小，没有起始偏移；或者写的是**在 `unalloc.dd` 里的偏移**，而不是**在原始镜像中的偏移**。

**原因**：3.7 明确指出"每行都记录了起始偏移和大小"——这是让第三方能回到原始镜像复核的唯一坐标。而偏移来源有**两级**：`blkls` 提取未分配空间时，各簇在 `unalloc.dd` 里是**按未分配簇顺序连续排列**的，`audit.txt` 记录的是在输入文件（`unalloc.dd`）中的偏移——**它不是原镜像偏移**。而"偏移量看起来像个大数字"这个形态很容易被直接当成镜像偏移写进报告。

**影响**：**结论无法被复核**。委托方或第三方拿着报告里的坐标回原始镜像找，什么都找不到——**这会让人怀疑整个 carving 环节的真实性**，而实际原因只是一个坐标换算没做。

**核查**：**报告坐标必须写明基准文件，而基准文件要能被复核**：

```bash
# audit.txt 的偏移是相对输入文件的，不是原镜像偏移
head -30 /evidence/carve-fm/audit.txt
# Num  Name (bs=512)  Size  File Offset
# 12:  00000012.pdf   1925120  62914560
#   ^ 这个 62914560 是在 /evidence/unalloc.dd 中的字节偏移

# 保留 unalloc.dd 作为坐标基准，并记录它的哈希 —— 复核者靠这两项回到同一坐标
sha256sum /evidence/unalloc.dd > /evidence/unalloc-hash.txt

# 溯源闭环：用偏移从基准文件回读，比对哈希确认指向同一段字节
dd if=/evidence/unalloc.dd bs=1 skip=62914560 count=1925120 status=none \
  | sha256sum
# 与产物哈希一致 → 坐标与产物的对应关系成立
```

"未分配簇序号 → 原镜像块号"这个映射 `blkls` 不会输出——它把未分配块按序拼接成一条数据流，命令本身不产出映射表。所以有两条路，**必须选一条并在报告里说明**：

| 做法 | 坐标基准 | 适用 |
|---|---|---|
| **对 `unalloc.dd` carve**（上例） | `unalloc.dd` + 其哈希 | 大多数场景，溯源靠上面的回读比对闭环 |
| **按已知未分配块号从镜像直接 carve** | **原镜像**，块号 × 块大小 | 需要给出原镜像绝对偏移时，坐标天然可复核 |

```bash
# 第二种：对已知的未分配块号逐块提取，块号 × 块大小即原镜像偏移
# 块大小与未分配块清单从 fsstat / blkstat 取，不要假设 512
blkstat -o 2048 /work/DigiForensics.dd | head
# 块 131073 起始偏移 = 131073 × 块大小
```

**清单表头建议增加两列**：

| 产物编号 | 文件名 | 偏移（基准文件） | 基准文件哈希 | 大小 | 格式 | 完整性验证 | 工具与版本 | 性质 |
|---|---|---|---|---|---|---|---|---|
| C-001 | 00000012.pdf | 62914560 | `unalloc.dd` `3a7f…` | 1925120 | PDF 12 页 | `pdfinfo` 通过 | foremost 1.5.7 | 重建产物 |

**性质声明逐字使用**（3.7 已给全文，核心是这四层）：

> 本节所列文件均为通过文件雕刻（carving）从检材未分配空间中提取的重建产物，并非原始文件。
> - 其**字节边界由工具依据格式签名推定**，可能包含前导或尾部的无关数据，其**哈希值与原始文件必然不同**，不能用于与原文件哈希比对；
> - 雕刻过程**不保留原始文件名、路径、时间戳、所属用户等信息**；
> - 上述文件**不能作为"该原始文件"的原件提交**，其证据性质为"该检材未分配空间区域存在相应格式的内容，且内容特征为……"；
> - 上述内容的原始身份、来源与形成时间，需结合文件系统元数据、用户活动记录、系统日志等其他证据另行认定。
<a id="section-40"></a>

## 五、案例示例

**场景**

查获一台 Windows 10 工作站（NTFS，簇大小 4096），委托要求恢复**已删除的敏感合同扫描件**。

委托方提供了目标文件在另一台机器上的 SHA-256，要求确认检材中是否存在该文件。

镜像 `DigiForensics.dd`（raw，500 GB），NTFS 分区起始扇区 2048。

委托方明确要求：该文件哈希须与给定值一致方可采信。

> **这个委托要求本身是有问题的**——本案例的核心正是要说明为什么，以及正确做法是什么。

第 1 步 · 评估可行性（决定不用 foremost）

```bash
# ① 文件系统是否可解析？
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'cluster|state|mft'
# Cluster Size: 4096    File System Type: NTFS
fls -o 2048 /work/DigiForensics.dd | wc -l
# 2,847,193                                       ← 文件系统完全正常！

# ② 未分配空间体积
blkls -o 2048 /work/DigiForensics.dd | wc -c
# 412,663,838,528                                  ← 约 384 GB 可挖

# ③ 元数据优先路径：直接找已删除项（可能根本不需要 carve）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'deleted' | grep -iE 'contract|扫描|合同'
# r/r  44902-256-3:  $FILE_NAME  1843200  2024-05-11 09:33:02  2024-06-20 22:10:03  合同扫描件.pdf
```

**关键判断**：文件系统完好，且 `fls` 直接列出了已删除的 `合同扫描件.pdf`（inode 44902-256-3）。**这种情况下，carving 是错误的工具选择**——应该用 `icat` 定向提取，它**保留文件名、时间戳、路径**，且**字节与原始文件完全一致（哈希可逐位比对）**。

**第 2 步 · 定向提取（正确路径）**

```bash
icat -o 2048 /work/DigiForensics.dd 44902-256-3 > /evidence/合同扫描件.pdf

# 验证 1：长度与元数据一致
istat -o 2048 /work/DigiForensics.dd 44902-256-3 | grep -E 'Size|Modified'
# Size: 1843200
# Modified: 2024-06-20 22:10:03
stat -c '%s' /evidence/合同扫描件.pdf
# 1843200                                                    ← 一致 ✓

# 验证 2：内容完整性
file /evidence/合同扫描件.pdf
pdfinfo /evidence/合同扫描件.pdf | head
# Pages: 12    Page size: 595 x 842 pts (A4)
# Producer: ScanToPDF 4.2
#  ↑ 扫描件特征吻合 ✓

# 验证 3：★ 哈希比对（委托方要求的核心验证）
sha256sum /evidence/合同扫描件.pdf
# 3f9a1c7e5b2d8046fa1e9c3b7d2a5f8e1c4b6d9a2f5e8c1b4d7a0f3e6c9b2d5a  合同扫描件.pdf
# 与委托方给定值逐一比对 → 一致 ✓
```

**哈希完全匹配。**

因为 `icat` 是从文件系统元数据（$MFT 的簇链）出发，按原始文件边界精确提取的——**提取的是原件的精确字节副本**，不是重建产物。

第 3 步 · 反向验证：为什么 carving 在此场景会失败

为说明问题，对同一目标做 carving 对比：

```bash
# 对未分配空间 carve PDF
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd
foremost -t pdf -i /evidence/unalloc.dd -o /evidence/carve-fm -v
cat /evidence/carve-fm/audit.txt | grep -i pdf
# Num  Name (bs=512)  Size  File Offset
# 12:  00000012.pdf   1925120  62914560
# ↑ 注意：切出 1,925,120 字节，而真实文件只有 1,843,200 字节
#   多出 81,920 字节 = 18 个簇 = carving 无法确定边界，包含了后续残留数据
```

```bash
# 提取并对比哈希
cp /evidence/carve-fm/pdf/00000012.pdf /tmp/carved-pdf.pdf
stat -c '%s' /tmp/carved-pdf.pdf
# 1925120                                              ← 比原件大 81920 字节
sha256sum /tmp/carved-pdf.pdf
# 8c2e5b1a9f7d3e6c4a8b0f2d5c7e9a1b3f6d8c0e4a7b2d5f8c1e6a9b3d7f0c4  ← 与原件完全不同
```

**这就是本案例的核心结论**：

| 提取方式 | 大小 | 哈希 vs 委托方给定值 | 性质 |
|---|---|---|---|
| **`icat` 定向提取** | 1,843,200 | **✅ 完全一致** | 原始文件的精确副本，可采信 |
| **`foremost` carving** | 1,925,120 | **❌ 完全不同** | 重建产物，含 81,920 字节残留 |

若案卷中提交的是 carving 产物，委托方的哈希比对将直接失败，原因是提取方式不对，而非文件内容有差异。 这就是必须讲透证据效力的现实意义。

第 4 步 · 仍需 carving 的场景（未分配空间中的未知内容）

虽然目标文件已通过 `icat` 恢复，但**未分配空间中可能还有其他与案件相关的内容**（如自动删除的中间稿）：

```bash
# carve 并清洗（后处理不可省）
foremost -t doc,pdf,xls,zip -i /evidence/unalloc.dd -o /evidence/carve-fm -v
cat /evidence/carve-fm/audit.txt | tail -5
# 2 FILES EXTRACTED  (doc:= 1  pdf:= 1)

cd /evidence/carve-fm
file -r --mime-type . > /evidence/carve-mime.txt          # ① 类型核验
find . -type f -exec sha256sum {} \; > /evidence/carve-hashes.txt   # ② 哈希
awk '{print $1}' /evidence/carve-hashes.txt | sort -u | wc -l          # ③ 去重
# 完整性与内容核验：
for f in doc/*.doc pdf/*.pdf; do
  echo "--- $f ---"; file "$f"; ls -l "$f"
done
```

输出：

```text
--- doc/00000000.doc ---
Microsoft Word Document, 97-2003, OLE2
-rw-r--r-- 1 root root 63488 Jun  2 14:33
--- pdf/00000012.pdf ---
PDF document, version 1.4, 12 pages
-rw-r--r-- 1 root root 1925120 Jun  2 14:33
```

```bash
# 内容检查（判断是否与本案相关）
antiword /evidence/carve-fm/doc/00000000.doc 2>/dev/null | head -15
# 项目验收报告（草稿）
# 供应商：华东精密机械有限公司
# 备注：金额待财务复核，暂不提交      ← 与目标合同同一供应商，疑似关联
pdfinfo /evidence/carve-fm/pdf/00000012.pdf | head -8
# Producer: ScanToPDF 4.2              ← 与目标文件同一生产工具
#  ↑ 但 12 页 1.9MB，是 00000012.pdf（尾部有残留）
```

第 5 步 · 报告中的标准表述（体现证据效力区分）

```markdown
# 敏感合同扫描件的恢复与认定

### 5.1 目标文件（原件级恢复）
文件 `合同扫描件.pdf` 通过 Sleuth Kit `icat` 工具从 NTFS 卷的已删除
文件项（inode 44902-256-3）提取。该方式依据文件系统元数据（MFT 中的
簇链）确定文件边界，提取结果为原始文件的精确字节副本。

- 提取大小：1,843,200 字节（与 MFT 记录大小一致）
- SHA-256：3f9a1c7e5b2d8046…（与委托方给定值完全一致）
- 保留元数据：文件名 `合同扫描件.pdf`、创建 2024-05-11 09:33:02、
  修改 2024-06-20 22:10:03
- 完整性验证：PDF 12 页，可完整解析，生产工具 ScanToPDF 4.2
- **性质认定：可作为该文件的证据副本提交**

### 5.2 未分配空间中的关联内容（重建产物）
使用 `foremost` 对未分配空间（412,663,838,528 字节）进行雕刻，
获得 2 个候选对象，经内容核验与本案相关（同一供应商、同一生产工具）：

| 编号 | 产物 | 偏移 | 大小 | 格式 | 完整性 | 性质 |
|---|---|---|---|---|---|---|
| C-001 | 00000000.doc | 0x3C00000 | 63,488 | Word 97-2003 | 可读，内容完整 | 重建产物 |
| C-002 | 00000012.pdf | 0x3C00000+ | 1,925,120 | PDF 12 页 | **尾部多 81,920 字节残留** | 重建产物 |

**性质声明**：
以上 C-001、C-002 为通过文件雕刻提取的**重建产物，非原始文件**。
其字节边界由工具依据格式签名推定，C-002 明确包含 81,920 字节的尾部
残留数据，其哈希值与对应原始文件必然不同，不能用于哈希比对，亦不能
作为该原始文件的原件提交。

上述内容**可用于支持"该检材未分配空间中存在与本案相关的文档内容"
这一事实**，其原始文件名、精确边界、来源与形成时间需结合其他证据
另行认定。
```

**结论要点**：

1. **目标文件已按原件级恢复**：通过 `icat` 定向提取，大小与 MFT 记录一致、哈希与委托方给定值完全匹配、文件名与时间戳完整保留。**这是委托方要求的正确达成方式。**
2. **carving 在本案中既非必要也不适用**：文件系统完好时，`icat` 能提供**字节精确、含元数据、哈希可验证**的提取；carving 只能提供**边界不确定、元数据全失、哈希不可验证**的重建产物。
3. **carving 产物与原件的差别是量化的**：`00000012.pdf` 切出 1,925,120 字节 vs 真实 1,843,200 字节，**多出 81,920 字节（18 个簇）的尾部残留**，其 SHA-256 为 `8c2e5b1a…`，与原件 `3f9a1c7e…` 完全不同。这个对照是本案例最有说服力的技术内容。
4. **关联内容已发现但效力受限**：雕刻出的 Word 草稿含"华东精密机械有限公司"（与目标合同同一供应商），**这一内容关联是有效的线索**，但**受制于重建产物的性质**——可用于指向调查方向，不可作为该文档原件。
5. **后处理不可省**：类型核验（`file`）、哈希去重（`sha256sum`+`sort -u`）、内容核验（`antiword`/`pdfinfo`）三步均已执行并记录在案，**去重后候选数、相关性筛选依据均已量化**。

---

<a id="section-41"></a>

## 六、扩展阅读方向

**前置与基础。** 碎片重组的判据要先说清，否则恢复出来的文件只是运气。
JPEG 认的是 `SOI`（`FF D8`）与 `FFD0` 标记对，MP4 认 `moov` 原子的位置，
ZIP 认局部头序列的连续性——每一个重组动作都需要给出正确性论证，
而不是「能打开就算成功」。

**同层深入。** 智能雕刻（Smart Carving）走的是另一条路，
基于数据结构推断边界，Fr carving 与 block-based carving 的原理
和准确率评估决定了它在碎片化严重时是否还值得一试。
工具侧 PhotoRec 与 TestDisk 的文件家族机制要理解清楚，
`tsk_recover` 与 carving 的适用边界也常被混为一谈：
前者按分配状态取文件，后者从空闲空间里捞。

**相邻议题。** 内存与 swap 是另一片挖掘面，内存镜像 carving、
swap 残留、凭证提取各自的合法边界需要单独确认。
闪存与 TRIM 则是恢复率的硬上限，discard 语义与闪存 GC 会让数据
在逻辑上还在、物理上已被抹除，这直接决定移动设备数据能否被
认定为「物理不可恢复」。

**工具与判据。** 数字证据的完整性验证该怎么做、哈希比对与内容认定
差在哪一层、鉴定意见里的局限性声明该怎么写，这三点构成产物的准入门槛。
签名库的构建、误报甄别与产物清洗规则见
[《文件头与文件签名》](../filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md)，雕刻产物要经它过一遍。

**判据与反例。** 哈希比对通过不等于内容被认定——它只证明
「与某个已知样本一致」，不证明这份文件在该案中扮演了什么角色。
carving 产物的哈希比对失败时，报告不能用「未匹配」一笔带过，
而应按 [《取证流程与原则》](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)
的五阶段要求，把局限性明确写进鉴定意见的声明部分。

---

<a id="section-42"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install sleuthkit foremost scalpel testdisk bulk-extractor file xxd
sudo apt install libimage-exiftool-perl   # EXIF 提取
sudo apt install poppler-utils imagemagick unzip
# 注意拼写：foremost（前置 f），不是 formost

# ===== 第 1 步：评估可行性（决定是否 carve）=====
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'cluster|state'
fls -o 2048 /work/DigiForensics.dd | wc -l          # 能解析出多少项
blkls -o 2048 /work/DigiForensics.dd | wc -c         # 未分配空间字节数（为0→TRIM/已擦除）
mmls /work/DigiForensics.dd                          # 卷层未分配区间
# ★ 元数据优先：文件系统可用时先走这条（保留文件名/时间戳/哈希可验证）
tsk_recover -o 2048 /work/DigiForensics.dd /evidence/recover-deleted/
tsk_recover -e -o 2048 /work/DigiForensics.dd /evidence/recover-all/    # 含已分配文件
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i deleted
icat -o 2048 /work/DigiForensics.dd 44902-256-3 > /evidence/target.pdf # 定向提取
sha256sum /evidence/target.pdf                       # ★ 哈希可与委托方比对

# ===== 第 2 步：提取未分配空间并 foremost =====
blkls -o 2048 /work/DigiForensics.dd > /evidence/unalloc.dd
foremost -t jpg,pdf,doc,zip,png -i /evidence/unalloc.dd -o /evidence/carve-fm -v
head -30 /evidence/carve-fm/audit.txt                # ★ 审计文件：偏移/大小/工具版本/命令行
# 常用选项：-i 输入 -o 输出目录 -t 类型 -v 详细 -c 配置 -a 写所有头
#           -b 块大小 -k 块大小(chunk) -s 跳过块数 -q 快速模式 -w 只写审计不提取
# 输出目录必须为空或不存在的全新目录

# ===== 第 3 步：scalpel（更快；配置文件默认全注释）=====
sudo nano /etc/scalpel/scalpel.conf
#   取消注释需要的行，例如：
#   jpg   y 20000000 \xff\xd8\xff\xe0 \xff\xd9
#   pdf   y 10000000 \x25\x50\x44\x46 \x25\x25\x45\x4f\x46
#   doc   y 20000000 \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 \x00\x00\x00\x00
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out -p /evidence/unalloc.dd  # -p 预览
scalpel -c /etc/scalpel/scalpel.conf -o /evidence/scalpel-out    /evidence/unalloc.dd
# 常用选项：-c 配置 -o 输出 -p 预览(不提取) -v 详细 -b 无尾标记也提取(到上限)
#           -q <簇大小> 仅在簇边界切(降误报) -e 嵌套头尾 -n 不加扩展名 -O 不分子目录

# ===== 第 4 步：photorec（无尾标记格式）=====
photorec /log /d /evidence/photorec-out /cmd /evidence/unalloc.dd \
         partition_none,fileopt,everything,enable,freespace
#  /log → photorec.log(报告需要)  /d <dir> 输出目录(必须为空)  /cmd 命令行模式
ls /evidence/photorec-out/; find /evidence/photorec-out -type f | wc -l

# ===== 第 5 步：bulk_extractor（特征提取，思路不同）=====
bulk_extractor -o /evidence/be-out /work/DigiForensics.dd        # 产出 email/url/ip/ccn/exif 等
bulk_extractor -o /evidence/be-comm /evidence/unalloc.dd -e email -e url   # 只启用指定扫描器
bulk_extractor -o /evidence/be-exif /work/DigiForensics.dd -E exif           # 只跑 exif
bulk_extractor -R -o /evidence/be-recurse /evidence/unalloc.dd               # 递归进 ZIP/PDF/GZIP
bulk_extractor -o /evidence/be-custom -f 'CASE-2024-\d{4}' /work/DigiForensics.dd  # 自定义正则
bulk_extractor -o /evidence/be-page -G 4096 /work/DigiForensics.dd           # -G 分页大小(跨页特征必设)
bulk_extractor -o /evidence/be-out2 -S jpeg_carve_mode=2 /work/DigiForensics.dd
bulk_extractor -H                                                     # 列出所有扫描器信息
# 常用选项：-o 输出(必填) -e 启用 -x 禁用 -E 仅此一个 -f 自定义正则 -F 正则文件
#           -R 递归 -G <size> 分页大小 -C <size> 上下文窗口(核实误报用) -S name=val
# ⚠ 产出是"特征列表"，不是文件；误报高，须用 -C 看上下文逐条核实

# ===== 第 6 步：后处理（清洗/去重/验证，不可省）=====
cd /evidence/carve-fm
file -r --mime-type . > /evidence/carve-mime.txt                 # ① 类型核验（不信工具扩展名）
find . -type f -exec sha256sum {} \; > /evidence/carve-hashes.txt  # ② 哈希
awk '{print $1}' /evidence/carve-hashes.txt | sort -u | wc -l     # ③ 去重计数
# ④ 完整性验证（唯一能证明"完整"的方法）：
for f in jpg/*.jpg; do identify "$f" 2>/dev/null || echo "损坏: $f"; done
for f in doc/*.doc zip/*.zip; do unzip -t "$f" >/dev/null 2>&1 || echo "损坏: $f"; done
for f in pdf/*.pdf; do pdfinfo "$f" >/dev/null 2>&1 || echo "损坏: $f"; done
# ⑤ 合理性筛查：
find . -type f -size -1k | head          # 极小多为噪声
find . -type f -size +100M               # 异常大→疑似过度切分
# ⑥ 内容相关性：
antiword doc/00000000.doc | head -15
grep -l 'CASE-2024' */*.jpg 2>/dev/null | head

# ===== 第 7 步：报告表述（证据效力，务必照此写）=====
# 每个产物必须记录：产物编号/文件名/起始偏移/大小/file 判定格式/完整性验证/重建方式/性质
# 必须声明（逐字）：
#   "本节所列文件均为通过文件雕刻从检材未分配空间提取的重建产物，并非原始文件。
#    其字节边界由工具依据格式签名推定，可能包含前导或尾部无关数据，
#    哈希值与原始文件必然不同，不能用于哈希比对；
#    雕刻不保留原始文件名、路径、时间戳与归属信息；
#    不能作为该原始文件的原件提交。"
# 对比：tsk_recover / icat 产物保留元数据、哈希可验证 → 性质接近原件，分开呈现

# ===== 第 8 步：分页文件与内存镜像 =====
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'pagefile|swapfile'
icat -o 2048 /work/DigiForensics.dd 263 -r > /evidence/pagefile.bin
foremost -t doc,pdf,zip -i /evidence/pagefile.bin -o /evidence/carve-swap
bulk_extractor -o /evidence/be-mem /work/DigiForensics-mem.raw     # 内存用 BE 远好于 foremost
# 分页/内存 carve 特殊注意：重复率极高(必须去重)、无完整文件边界(产物几乎都是残片)、
#   可能含凭证与加密内容(按敏感证据管理)、只能表述为"该区域存在此内容"而非"恢复出某文件"

# ===== 禁止事项 =====
# ✗ 对原始设备（非镜像）carve —— 永远对镜像文件操作
# ✗ 跳过 tsk_recover/icat 直接整盘 foremost —— 丢失全部元数据
# ✗ 把 carving 产物哈希填入证据文件哈希表而不区分性质
# ✗ 宣称"已恢复所有删除文件" —— 召回率未知且无法事后确定
```

---

> 
📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 文件系统分析 — 文件雕刻与签名恢复」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《文件雕刻与签名恢复》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
