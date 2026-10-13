---
title: "证据文件格式：DD、E01 与 AFF4"
slug: "fundamentals-chain-dd-e01-aff4-evidence-formats"
canonical: "https://www.digiforensics.cn/wiki/fundamentals-chain-dd-e01-aff4-evidence-formats"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "fundamentals"
space: "取证基础与规范"
node_path: ["证据保管链"]
---

# 证据文件格式：DD、E01 与 AFF4

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/fundamentals-chain-dd-e01-aff4-evidence-formats)

<a id="section-1"></a>

## 一、概述

把一块 2 TB 硬盘完整复制下来，产出的那个 2 TB 文件就是 DD 镜像。

它最通用，最没有争议，也最脆弱。写到第 900 GB 断电，前面的成果全部作废。每做一次跨机拷贝，就多一次静默损坏的机会。更要命的是，**它不记得自己是谁、从哪来、谁做的**。

镜像文件不像案件卷宗那样装在档案袋里，它就是检材的副本。可副本和检材在法庭上是两件事——检材是原件，副本得自己说清"我是从哪个编号的检材、在谁的见证下、什么时候、用什么设备、以什么哈希复制出来的"。DD 做不到，E01 和 AFF4 可以。

要解决的无非三件事：用什么格式落盘，这个格式能不能自证没被改动，以及被打散成几十个文件之后还拼不拼得回去。

格式选择发生在**采集环节的最后一步**，位置很尴尬，它决定了后面所有分析步骤的输入形态。选成 E01，后面拿到的是压缩分段容器，任何只认裸流的工具都得先 `ewfmount`。选成 DD，后面一切直接，但交付时"这个文件凭什么可信"这个问题得你自己扛。

上游依赖两件事：[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) 决定了采集时的读取参数与坏扇区策略，[取证装备与写保护器](../fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) 决定了读出这些字节的通道是否可信。

下游支撑两件事：只读挂载与虚拟机仿真直接消费容器，而[证据保管链与委托证明](fundamentals-chain-chain-of-custody-and-authorization.md)记录的一切哈希值，都依赖于"你哈希的到底是哪一层字节"这个问题有明确答案。

哈希这件事第四章陷阱 4 会展开：E01 内嵌的哈希针对解压后的原始字节流，对 E01 文件本身算哈希得到的是压缩后容器的指纹。这两个值不是一回事。混淆的代价是报告里出现一个指向不明、实际指控了错误对象的"完整性问题"。

落盘的容器长这样：

- `DigiForensics.E01` — EnCase 6 格式，文件头以 `EVF` 加 6 字节序列起始，内含 table / hash / x64 等 section，单块压缩默认 64 扇区 × 512 字节 = 32 KB
- `DigiForensics.E02` … `.E99` … `.zzz` — **续段**。1 TB 介质通常产出约 26 个段文件，段序内嵌在文件头偏移 0x09
- `DigiForensics.L01` — 同一个容器家族的不压缩变体，用于源介质已损坏、可能多次重读的场景
- `DigiForensics.dd` — 无文件头的裸比特流，没有自校验能力
- `DigiForensics-sim.vmdk` — 仿真用虚拟磁盘，文件头 `KDMV`，**不含取证元数据**
- `.rdf` 旁文件 — AFF4 的 RDF/XML 描述，承载案件编号、采集人、扩展属性
- `DigiForensics_E01.tar` — 交付包。它的哈希与 E01 内嵌哈希是两个不同的值，作用完全不同

拿到一个容器，能判断的是这些：段数对不对（完整性）、内嵌哈希能不能复现（内容有没有被动过）、`.E01` 与 `.L01` 在损坏源上的行为差异（能否安全地重复读取）、以及归档件应该交哪一个文件。

有几件事不归这里管。**采集通道本身可不可信**——写保护器是否真的阻断写入、坏扇区怎么处理，是[镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md)与装备篇的事。**容器里装的字节对不对**——分段和压缩都不改变原始内容，格式正确不等于内容正确。**仿真跑出来的结果算不算检材**——仿真是分析员主动制造的状态，第四章陷阱 8 讲清它必须单独登记，不能混进检材引用。**怎么把 2 TB 跨机搬完**——传输中断、断点续传、跨网段完整性是工程问题，这里只管搬完之后怎么验。

往下读之前，先确认你已经知道扇区与簇的层级关系（不然读不懂分段和 chunk）、哈希能证明什么不能证明什么（见[哈希与完整性校验](../fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)）、以及"只读接入"是纪律不是偏好（见[只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)）。

其中"哈希算的是哪一段字节"是三者中最关键的前置，缺失时第四章陷阱 4 会失去判断基础。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 格式总览

| 格式 | 文件头特征 | 压缩 | 内嵌哈希 | 元数据 | 典型用途 |
|---|---|---|---|---|---|
| **DD / RAW** | 无（裸比特流） | 无 | 无 | 无 | 实验室内部、大容量转存 |
| **E01** | `EVF` 起始 | zlib/bzip2 | MD5+SHA-1/SHA-256 | 有 | 正式交付、跨机构流转 |
| **VMDK** | `KDMV` 起始 | 无 | 无 | 有 | 挂载到虚拟机做仿真 |
| **AFF4** | `AFF4\\x00` 起始 | 可变/zlib | 可配置 | 强（XML 描述） | 新型综合场景 |
| **L01** | `LVF`/`EVF` | 不压缩 | 有 | 有 | 超大镜像，规避 2 GB 分段限制 |

<a id="section-4"></a>

### 2.2 DD/RAW：裸比特流的本质

DD 镜像**没有文件头**。它就是按顺序排列的扇区。

好处是任何工具都能读，兼容性拉满。代价同样直接：镜像文件头部 512 字节一坏，整盘在工具眼里就是空的，而且未必告警。完整性只能靠你在外部记录的哈希——镜像自己不会说话。

```bash
# 确认它确实是裸流：前若干字节应直接呈现分区表特征
xxd -l 64 DigiForensics.dd
# 典型 MBR 签名：偏移 0x1FE 处为 55 AA
```

<a id="section-5"></a>

### 2.3 E01 的分段机制

E01 的核心设计是**把一个大镜像拆成多个不超过约 2 GB 的段文件**：

```text
DigiForensics.E01   ← 第 1 段
DigiForensics.E02   ← 第 2 段
DigiForensics.E03   ← 第 3 段
...
DigiForensics.E99   ← 第 99 段
DigiForensics.EAA   ← 之后改用字母后缀
DigiForensics.zzz   ← 理论上限
```

每个段文件开头都是 13 字节的文件头：

```
偏移 0x00  8 字节  签名 "EVF" + 09 0D 0A FF 00
偏移 0x08  1 字节  0x01（字段区起始标记）
偏移 0x09  2 字节  段序号（从 1 开始）
偏移 0x0B  2 字节  0x0000（字段区结束标记）
```

> ⚠️ **关键点**：**一个 section 不能跨段文件**。因此每段边界会形成一个"接缝"，压缩数据在接缝处结束。理解了这一点，才能解释为什么 E01 转换回 DD 后，某些偏移上的压缩块大小不连续。

<a id="section-6"></a>

### 2.4 E01 的 chunk、压缩与 CRC

| 概念 | 说明 |
|---|---|
| **Chunk（块）** | 每块默认 64 个扇区 × 512 字节 = **32 KB 原始数据** |
| **压缩** | 每块独立压缩（zlib/bzip2），因此可**随机访问任意偏移**而无需解压全文 |
| **CRC32** | 每个 section 带 CRC32；压缩块用最高位标记是否压缩 |
| **Table section** | 记录每个 chunk 在哪个段文件的哪个偏移，实现快速随机读取 |
| **Hash section** | 存放采集时计算的 MD5 / SHA-1 / SHA-256，**针对解压后的原始字节流** |

正因为每块独立压缩，E01 才能随机访问——直接跳到偏移 0x10000000 那一块读，不用解压前面所有数据。DD 做不到这点。

压缩比不如整体压缩，是这个设计要付的账。

E01 的元数据以制表符和换行分隔的文本形式存在（zlib 压缩后放在 header section），常见字段：

```
c   案件编号
n   证据编号
e   鉴定人/操作者
a   唯一描述
m   采集日期
av  生成程序与版本
```

<a id="section-7"></a>

### 2.5 VMDK 的定位

VMDK 是虚拟磁盘格式。取证场景里主要两个用途：

1. **把镜像挂进虚拟机仿真**，让系统"自己跑起来"以触发应用加载数据
2. 作为**中间交换格式**，在工具链之间传递

但它**不适合作为最终归档格式**：没有内嵌取证元数据，也不内嵌采集哈希。归档仍应落到 E01 或 AFF4。

<a id="section-8"></a>

### 2.6 AFF4：面向未来的容器

AFF4 的设计哲学不同。它不规定"镜像长什么样"，而是提供一个**描述数据流的框架**：

- 图像被抽象为 `ImageStream`（体积/哈希/压缩方式都可配置）
- 元数据用 **RDF/XML（.rdf 旁文件）** 表达，可携带任意扩展属性
- 天然支持"一个证据容器里有多个流"（如同时包含磁盘镜像、内存镜像、pcap）

<a id="section-9"></a>

### 2.7 实际选择的决策表

| 约束条件 | 建议格式 | 理由 |
|---|---|---|
| 需要交付给对方/跨机构流转 | **E01** | 内嵌哈希+元数据，通用可验证 |
| 实验室内部、存储充裕、追求速度 | DD | 写入最快，无压缩开销 |
| 需要挂载进虚拟机 | VMDK（或 E01 后转 VMDK） | 虚拟化软件直接可用 |
| 需要同时存多路数据 + 强元数据 | AFF4 | 可扩展容器 |
| 原始介质已损坏、可能读出不同结果 | **L01** 或带 `hashconv` 的 E01 | 不压缩，支持多次校验 |
| 对端设备明确只认 RAW | 先存 E01，再导出 DD | 保留归档同时满足兼容 |

---
<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 步骤 1：采集时直接产出 E01

```bash
# ewfacquire：libewf 套件的命令行采集工具
# 环境：Ubuntu，apt install ewf-tools
sudo ewfacquire -t /case/DigiForensics \
     -f encase6 -c deflate:best -d sha256 \
     -C "2024-DG-001" -E "01" -e "Examiner" \
     -D "Laptop SSD 1TB" \
     /dev/sdX
```

产出 `DigiForensics.E01` 及后续段文件。`-d sha256` 让它同时记录哈希。

<a id="section-12"></a>

### 步骤 2：查看与验证 E01

```bash
# 查看容器信息（段数、尺寸、采集元数据）
ewfinfo DigiForensics.E01

# 验证完整性——对照容器内嵌的哈希重算
ewfverify DigiForensics.E01
```

`ewfverify` 是"证据文件自检"的标准动作。输出里会分别给出 MD5 与 SHA-256 的校验结果。

<a id="section-13"></a>

### 步骤 3：挂载为裸流以使用只读工具

```bash
# ewfmount 把 E01 呈现为一个可读的裸镜像文件
sudo mkdir -p /mnt/ewf
sudo ewfmount DigiForensics.E01 /mnt/ewf
# 挂载后裸流位于 /mnt/ewf/ewf1

# 现在任何只认 raw 的工具都能直接用
sudo fdisk -l /mnt/ewf/ewf1

# 用完后必须正常卸载
sudo umount /mnt/ewf/ewf1 && sudo rmdir /mnt/ewf
```

<a id="section-14"></a>

### 步骤 4：格式转换

```bash
# E01 → DD（导出裸流，体积会显著变大）
sudo ewfexport -t /case/DigiForensics-dd -f raw DigiForensics.E01

# DD → E01（Linux 侧）
sudo ewfimage -t /case/DigiForensics -f encase6 -c deflate:fast -d sha256 \
     -C "2024-DG-001" -E "01" -e "Examiner" -D "Converted" \
     DigiForensics.dd

# 分段或合并 E01（调整单段大小）
sudo ewfexport -t /case/Split -f encase6 -S 4G -C "2024-DG-001" \
     -E "01" -e "Examiner" DigiForensics.E01
```

<a id="section-15"></a>

### 步骤 5：验证转换的正确性

```bash
# 关键：转换前后哈希必须一致（哈希是针对原始字节流的）
sha256sum /case/DigiForensics-dd /mnt/ewf/ewf1
```

对不上，说明转换引入了数据改变，**必须查明原因**。通常是读到了损坏的源段，不是转换本身出错。

<a id="section-16"></a>

### 步骤 6：记录格式决策

在案件日志中写清：

```text
格式选择依据：
- 原始介质 1 TB，预计 2.5 小时完成
- 需交付至省厅，选用 E01 + deflate:best
- 对端工具已确认支持 E01
- 转换校验：源 SHA-256 与 ewfverify 结果一致
```

---
<a id="section-17"></a>

## 四、常见陷阱

分四组看：格式与分段、哈希与验证、转换与仿真、归档与记录。每条还是四段——现象、为什么会误判、误判代价、正确做法。

★ 标记的意思是：这个操作会让原始检材永久灭失，或者产生不可逆的改变。碰到就先停下来确认。

<a id="section-18"></a>

### 4.1 格式与分段

<a id="section-19"></a>

#### 陷阱 1：只复制了 `.E01` 一个段文件

**现象**：把 `/case/DigiForensics.E01` 拷到目标机器，`ewfinfo` 报出容器信息但尺寸不对，或 `ewfverify` 在中途失败，报告写"镜像损坏"。

**原因**：E01 是分段的。核心设计就是把大镜像拆成多个不超过约 2 GB 的段文件（`DigiForensics.E01`、`.E02`……`.zzz`），案例里 1 TB 介质产出**约 26 个段文件**。只拷第一段就是数据残缺。

问题是残缺不会立刻报错。工具照样打得开，坏的表现是后面一串怪现象：某个分区读不出，`fls` 只列出部分文件，某个时间戳看着不对。这些全会被归到文件系统损坏或工具 bug 头上，没人会想到"文件是不是没拷全"。

**影响**：目标机器上的全部分析都建立在残缺数据上，而这个事实可能被掩盖很久。

更麻烦的是，它跟"检材本身损坏"从现象上根本分不开——两者都是读不出内容。

**核查**：整目录打包，交付物是一个归档，不是一串散文件：

```bash
# ✅ 正确：整目录打包，打包后校验
tar -cf /case/DigiForensics_E01.tar DigiForensics.E*
sha256sum /case/DigiForensics_E01.tar
ls -lh /case/DigiForensics.E* | wc -l      # 核对段数是否与 ewfinfo 报告的一致

# 接收端先核对段数，再验证完整性
ls DigiForensics.E* | wc -l
ewfinfo DigiForensics.E01
ewfverify DigiForensics.E01
```

**交付记录里必须写明段数与打包文件的哈希**。这是接收方能做的第一道检查。

注意 `DigiForensics_E01.tar` 自身的哈希与 E01 内嵌哈希是两个不同的东西：前者证明"这个 tar 包没在传输中损坏"，后者证明"这个镜像的内容是什么"。两者都要报，用途不同。

<a id="section-20"></a>

#### 陷阱 2：用 E01 的压缩率倒推介质真实使用量

**现象**：E01 采集出 430 GB（1 TB 介质），分析员写"该盘已使用约 430 GB 数据"。

**原因**：压缩比完全取决于数据内容。大量空闲扇区（全 0 或全 `FF`）能压到极低，已使用的加密数据、压缩数据、媒体文件几乎压不动。E01 压缩后的体积与"已使用数据量"之间没有稳定关系。

而 430 GB 这个数字偏偏长得像一个有意义的容量值，于是很容易被顺手赋予含义。

**影响**：一个关于数据量的错误结论。委托方会拿它评估"这台机器存了多少敏感数据"、"要不要扩大调查范围"。可介质上有多少数据这个问题本来有专门的答案——`fsstat` 报的空闲块统计，跟压缩比毫无关系。

**核查**：容量问题问文件系统，不问压缩：

```bash
# 已分配 / 空闲的真实分布
fsstat -o 2048 /work/DigiForensics.dd | grep -iE 'block|free'

# 未分配空间总量（carving 的可行性前提）
blkls -o 2048 /work/DigiForensics.dd | wc -c
```

**E01 体积的正确表述**："E01 归档占用 430 GB，源介质容量 1 TB。**压缩后体积与介质已使用数据量无对应关系**，实际已分配空间为 `<X>`（`fsstat` 统计），未分配空间为 `<Y>`。"

**唯一能从 E01 体积得出结论的场景是反过来的**：若压缩比异常低（接近 1:1），说明盘上几乎全是不可压缩数据。这可能意味着大量加密内容——是一个线索，但结论方向是"加密内容比例高"，不是"数据量大"。

<a id="section-21"></a>

#### 陷阱 3：把 L01 当 E01 处理

**现象**：拿到后缀为 `.L01` 的镜像，用 E01 的压缩参数去做转换，或者拿 E01 的文档来解释它的行为。

**原因**：E01 可压缩，L01（EWF-L01）不压缩。容器结构同源，但这是两个格式。2.7 的决策表把 L01 放在"原始介质已损坏、可能读出不同结果"这个场景：不压缩，支持多次校验。

这不是性能差别，是能力差别。不压缩意味着每次读取都是逐字节直出，对损坏源的重复读取是稳定的；压缩流的某个块一旦损坏，重算哈希就会依赖其他块的状态。

**影响**：工具识别错误，或者对行为理解错位。更现实的问题是报告里把 L01 写成"E01 格式"，这属于格式描述错误。接收方按 E01 的假设（比如"可以重算并覆盖"）去处理，风险不可控。

**核查**：格式判断用工具输出，不靠后缀：

```bash
ewfinfo /case/DigiForensics.L01
# 输出中的 "Format" 字段会明确给出 EWF-E01 / EWF-L01
file /case/DigiForensics.L01
# L01/E01 的文件头起始相同，靠文件头无法区分——必须用 ewfinfo
```

**报告里的格式标识必须精确到变体**："EWF-E01（EnCase 6，`deflate:best` 压缩，SHA-256）" 而不是 "E01 文件"。

<a id="section-22"></a>

### 4.2 哈希与验证

<a id="section-23"></a>

#### 陷阱 4：以为 E01 内嵌哈希是"压缩后"的

**现象**：对 E01 文件本身算 `sha256sum`，与采集记录里的哈希一比，不一致，判为"采集有问题"。

**原因**：E01 内嵌的哈希针对解压后的原始字节流（2.4 的 Hash section 行已经写了）。对 E01 文件本身算哈希，得到的是压缩后容器的指纹。

这不是工具问题，是层次混淆。而"哈希不匹配"这个现象指向性太强，几乎必然被读成"数据出问题了"。

**影响**：一个关于采集完整性的错误指控。案例第 5 步的记录方式是对的：原始介质 SHA-256 = X，E01 内嵌 SHA-256 = X，两者一致，因为它们指的是同一段字节。`DigiForensics_E01.tar` 的哈希是第三个值，作用不同。

**核查**：**三个哈希各归其位**：

```bash
# ① E01 内嵌哈希 vs 采集时从源介质算的哈希 → 证明内容一致
ewfverify /case/DigiForensics.E01

# ② 转换后裸流的哈希 vs 上述值 → 证明转换无损
sudo ewfexport -t /case/DigiForensics-dd -f raw /case/DigiForensics.E01
sha256sum /case/DigiForensics-dd
# 必须等于 E01 内嵌的 SHA-256

# ③ 打包文件的哈希 → 证明传输未损坏，与内容身份无关
sha256sum /case/DigiForensics_E01.tar
```

| 哈希对象 | 证明什么 | 放在报告哪一栏 |
|---|---|---|
| 源介质采集时哈希 | 采集内容的身份 | 检材基本信息 |
| E01 内嵌哈希（`ewfverify`） | 容器内容与源一致 | 完整性验证 |
| 转换后 DD 的哈希 | 转换无损 | 转换记录 |
| tar 包哈希 | 传输未损坏 | 交付/移交记录 |

**"对 E01 文件直接算哈希"这个动作本身没必要**——它的值不进入证据链，只会在记录里制造混乱。

<a id="section-24"></a>

#### 陷阱 5：转换后只比对体积，不比对哈希

**现象**：`ewfexport` 导出 DD，检查文件大小与源介质容量一致，就写"转换完成"，交付。

**原因**：**体积一致不代表内容一致**。压缩块损坏、读取错误、稀疏区域处理差异，都可能在**总字节数不变**的情况下改变内容。

3 步 5 明确要求"转换前后哈希必须一致"，理由是"哈希是针对原始字节流的"——**只有哈希能证明逐字节相同**。而"体积一致"这个验证**看起来已经做了事**，它满足了"我检查过了"的心理需求。

**影响**：转换环节引入了没被发现的差异。而转换后的 DD 是后面所有分析的输入，差异要到几百个分析步骤之后才显现，那时已经定位不出是哪一步引入的。

**核查**：转换必须哈希对齐，并把验证结果写进转换记录：

```bash
sudo ewfexport -t /case/DigiForensics-dd -f raw /case/DigiForensics.E01
sha256sum /case/DigiForensics-dd
# 与 ewfverify 报告的 SHA-256 逐一比对

# 或用挂载法交叉验证
sudo ewfmount /case/DigiForensics.E01 /mnt/ewf
sha256sum /mnt/ewf/ewf1
sudo umount /mnt/ewf/ewf1
```

**不一致时的处置顺序**（3 步 5 已给）：多半是读到了损坏的源段，不是转换本身出错。所以第一步不是重跑转换，而是 `ewfverify` 源容器：

```bash
ewfverify /case/DigiForensics.E01        # 源容器自检
# 若源容器校验失败 → 问题在采集阶段，返回去核实采集记录与坏扇区处理
```

**报告写法**："转换记录：`ewfexport -t … -f raw` 于 `<时间>` 执行，输出 1,843,200,000,000 字节（与源容量一致）。SHA-256 = `<值>`，与转换前 E01 内嵌 SHA-256 逐位一致，转换未引入数据改变。"

<a id="section-25"></a>

### 4.3 转换与仿真

<a id="section-26"></a>

#### 陷阱 6：★ 在检材原机上打开 E01

**现象**：把检材笔记本开机，在它本机跑取证工具打开 E01 做初步查看。

**原因**：部分工具打开 E01 时会尝试写回索引——这就是这条警示的核心。

而"我只是打开看一眼"在意识里完全是被动动作，它的写入是工具行为的副产品，不是你显式做的。同时原机开机本身就在改变检材状态：系统写日志、更新访问时间、可能有自启程序在跑。

**影响**：同时破坏两样东西：E01 容器可能被写回索引，原机的运行时状态被改变。两者都直接削弱"检材保持原始状态"这个前提，而这个前提在争议程序里是要单独证明的事实。

**核查**：**分析一律在取证工作站上做，原机保持关机与封存**：

```bash
# 正确位置：取证工作站
sudo ewfmount /case/DigiForensics.E01 /mnt/ewf
fdisk -l /mnt/ewf/ewf1
sudo umount /mnt/ewf/ewf1 && sudo rmdir /mnt/ewf

# 挂载后先给裸流加写保护（防止后续工具意外写入）
sudo blockdev --setro /dev/loop2
```

**挂载必正常卸载**（3 步 3 的收尾动作）：`umount` 之后 `rmdir` 挂载点。**跳过卸载会留下 FUSE 挂载残留**，下一个操作者可能看到一个"已经挂载"的假象。

<a id="section-27"></a>

#### 陷阱 7：用 VMDK 作为归档格式

**现象**：仿真需要，把镜像转成 VMDK，然后把这个 VMDK 直接归档、交付。

**原因**：VMDK 是虚拟磁盘格式，设计目标是让虚拟化软件能挂载它，不是承载取证元数据。2.5 写得很清楚：它没有内嵌取证元数据，也不内嵌采集哈希，归档仍应落到 E01 或 AFF4。

而"VMDK 能被虚拟机直接打开"这个能力看起来比 E01 更实用——E01 还得先转一道。于是"能用"压倒了"该用"。

**影响**：归档件丢失全部来源信息。没有案件编号、没有采集人、没有采集时间、没有采集时哈希，这份文件日后无法自证来源。而它恰恰是委托方最容易直接使用的那个文件。案例第 5 步的记录方式正是应对："仿真用 VMDK 的哈希仅作内部参考、不作为证据哈希"。

**核查**：两种格式职责不同，不能互换：

```bash
# 归档：E01（自验证 + 元数据）
sudo ewfacquire -f encase6 -c deflate:best -d sha256 ... /dev/sdX
ewfverify /case/DigiForensics.E01

# 仿真：VMDK（临时）
sudo ewfmount /case/DigiForensics.E01 /mnt/ewf
sudo qemu-img convert -f raw -O vmdk /mnt/ewf/ewf1 /case/DigiForensics-sim.vmdk
sudo umount /mnt/ewf/ewf1
```

**VMDK 必须在报告里单独登记并标注用途**：

> "仿真用虚拟磁盘 `DigiForensics-sim.vmdk` 由 E01 转换而来，该文件不含取证元数据，不作为归档件，不作为证据哈希来源，仅用于 `<仿真目的>`。归档件为 `DigiForensics.E01`（26 段，打包后 SHA-256 = `<值>`）。"

**顺带一个易错点**：`qemu-img convert` 的输入是挂载出来的裸流，不是 E01 容器。必须先 `ewfmount` 再 convert。直接 `qemu-img convert DigiForensics.E01` 会失败或产出错误结果，而报错信息往往只说"格式不支持"。

<a id="section-28"></a>

#### 陷阱 8：VMDK 转换后不回写 E01，仿真结果无处归档

**现象**：仿真过程中在 VMDK 上做了大量操作（挂载、启动系统、跑脚本），结束后没把任何东西回写。仿真结论只存在于分析员的笔记里。

**原因**：仿真的价值在于让系统自己跑起来以触发应用加载数据（2.5 的用途一），而这个过程中新产生的数据——系统生成的配置文件、缓存、注册表变化、Prefetch 更新——只在 VMDK 上。

"VMDK 是临时的"这个定位容易让人以为它不重要。可它承载了仿真的全部产出。

**影响**：仿真做完了，产出丢了。

而且这类产出的证据性质很特殊：它们是分析员的行为产生的数据，提交时必须说明"该文件由本次仿真过程中系统自动生成，非检材原始内容"。漏掉这句说明，仿真产出就会被当成检材内容。

**核查**：仿真产出的归档与定性：

```bash
# ① 仿真完成后先固定 VMDK 本身（记录它当时的哈希）
sha256sum /case/DigiForensics-sim.vmdk > /evidence/sim-vmdk-hash.txt

# ② 需要仿真产出的文件时，导出到独立目录
mkdir -p /evidence/sim-output
cp -r /sim/snapshot/Users /evidence/sim-output/ 2>/dev/null

# ③ 回写为 E01 归档（2.5 的明确要求）
sudo ewfimage -t /case/SimOutput -f encase6 -c deflate:best -d sha256 \
     -C "<案件号>" -E "SIM-01" -e "Examiner" \
     -D "仿真环境产出，非检材原始内容" \
     /evidence/sim-output
```

**报告里必须单列一节**：

> "**仿真产出说明**：本节所列文件由仿真过程中目标系统自动生成，**产生于取证工作站，不属于检材原始内容**。仿真环境配置见第 X 节，VMDK 在仿真开始与结束时的哈希分别为 `<h1>` / `<h2>`。本节内容仅用于辅助理解与交叉验证，不作为检材内容引用的依据。"

<a id="section-29"></a>

### 4.4 归档与记录

<a id="section-30"></a>

#### 陷阱 9：格式转换不记入保管链

**现象**：采集出 E01 后转成 DD 做全部分析，转换这一步在案件日志里没有任何记录。

**原因**：转换看起来就是读个文件、另存一个文件，不碰检材本体，天然被归成"分析动作"而不是"证据处理动作"。

可保管链记录的是证据的转移与处理，而转换产出的 DD 恰恰是后面所有引用的来源。

**影响**：报告里引用的每一个数据，实际都来自那个未被记录的 DD。

一旦有人质疑"分析用的镜像是否与检材一致"，没有任何记录能回答。转换记录就是那个答案。

**核查**：**转换是独立记录项，四要素齐全**：

```text
转换记录（Conversion Record）
- 时间：<时间>
- 操作者：<姓名/编号>
- 输入：/case/DigiForensics.E01（26 段，tar 包 SHA-256 = <值>）
- 命令：sudo ewfexport -t /case/DigiForensics-dd -f raw /case/DigiForensics.E01
- 输出：/case/DigiForensics-dd，SHA-256 = <值>
- 验证：与 E01 内嵌 SHA-256 逐位一致
```

**原则很简单**：凡是产生新文件的操作都要入保管链——转换、导出、恢复、carve、解密，全部适用。没有产生新文件的操作（比如只读查看）不进。

<a id="section-31"></a>

#### 陷阱 10：用 `dd` 追加写入破坏容器结构

**现象**：对已有的 DD 或 E01 用 `dd conv=notrunc` 追加数据，文件变大后工具报错或读取异常。

**原因**：DD 是裸比特流，追加会让镜像"看起来"变大——工具读到的仍是有效的前段内容，前若干扇区的分区表、超级块全都正常。

E01 那边更隐蔽：Table section 记录每个 chunk 的位置，追加的数据不会被登记进 Table，容器内部就成了"有数据但没索引"的状态。

这两种破坏都不产生立即报错。

**影响**：一个大小变了但内容看起来正常的镜像。若在重新采集前发现并删除，影响有限；若已经基于它出了一份报告，报告引用的镜像与归档件大小不一致，而这个不一致要到移交时才被注意到。

**核查**：**重新采集前先删旧文件，且核验归档尺寸**：

```bash
# 采集前清空目标，避免混入
rm -f /case/DigiForensics.E*
ls /case/DigiForensics.* 2>/dev/null && echo "警告：残留文件"

# 采集后核对尺寸与段数
ls -l /case/DigiForensics.E01
ewfinfo /case/DigiForensics.E01 | head -20
# 报告的 "Medium size" 应与实际采集的介质容量一致
```

**裸流没有自校验能力**（2.2 说的）。DD 的尺寸核对完全依赖 `ewfinfo` 或人工比对——E01 至少还能用 `ewfinfo` 自报容量，DD 什么都没有。这是"正式归档选 E01"的一个具体理由。

<a id="section-32"></a>

#### 陷阱 11：交付前只打包不校验段数完整性

**现象**：`tar -cf` 打包完成，记录了 tar 的哈希，交付。接收方打开发现少段。

**原因**：打包成功和打包完整是两件事。`tar` 退出码为 0 只说明"读取这些文件并写入 tar 成功"，它不检查所有段是否都在。

案例里段数是 26——一个需要人工核对的数字，打包命令里没有任何东西会检查它。

**影响**：接收方拿到残缺镜像，而移交记录里的哈希是对的不完整 tar 的哈希。

更麻烦的是这个错误在移交时不会被发现，要等接收方做完一轮分析。

**核查**：打包前后各核一次段数：

```bash
# 打包前
BEFORE=$(ls /case/DigiForensics.E* | wc -l)
ewfinfo /case/DigiForensics.E01 | grep -iE 'media size|sectors'

# 打包
tar -cf /case/DigiForensics_E01.tar /case/DigiForensics.E*
sha256sum /case/DigiForensics_E01.tar

# 打包后：解开到临时目录核对段数（关键动作）
mkdir -p /tmp/verify && tar -xf /case/DigiForensics_E01.tar -C /tmp/verify
AFTER=$(ls /tmp/verify/DigiForensics.E* | wc -l)
echo "打包前 $BEFORE 段，解包后 $AFTER 段"   # 必须相等

# 内容验证（接收方也要做这一步）
ewfverify /tmp/verify/DigiForensics.E01
```

**交付记录模板**：

> "交付件：`DigiForensics_E01.tar`，SHA-256 = `<值>`，内含 `DigiForensics.E01`–`.E26` 共 **26** 个段文件（打包前后段数核对一致），tar 包解包后 `ewfverify` 校验通过（MD5 与 SHA-256 均匹配）。"

最后那句"解包后 ewfverify 通过"是接收方独立可做的验证。只给 tar 哈希而不给段数与自检结果，接收方仍然无法确认完整性。

<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 1 TB NVMe 采集为 E01 并转 VMDK 做虚拟机仿真

**场景**

查获一块 1 TB NVMe SSD。既要向上级机关技术部门交付一份可自证的证据容器，同时本地需要挂载它做 Windows 环境仿真。

委托方问了两件事：交付件能否自己证明没被改过，以及本地那份仿真文件算不算证据。

选择这一路径的依据是 E01 同时解决了"自验证"和"案件元数据随容器走"两个问题，裸 raw 只能满足后者。

**处置过程**

1. 用 `ewfacquire` 采集为 E01，`deflate:best` 压缩，采集时同步写入 SHA-256：

```bash
sudo ewfacquire -t /case/DigiForensics -f encase6 -c deflate:best -d sha256 \
     -C "2024-DG-001" -E "01" -e "Examiner" -D "NVMe 1TB" /dev/sdX
```

产出 26 个段文件（`DigiForensics.E01` … `DigiForensics.E26`）。总占用 430 GB。

2. 自检，确认容器内部自洽：

```bash
ewfverify -f sha256 /case/DigiForensics.E01
```

3. 仿真需要可挂载镜像，把 E01 挂出后转换，**输出文件单独命名**，一眼能看出不是证据：

```bash
sudo ewfmount DigiForensics.E01 /mnt/ewf
sudo qemu-img convert -f raw -O vmdk /mnt/ewf/ewf1 /case/DigiForensics-sim.vmdk
```

4. 交付前把段文件整体打包留一份哈希，方便交接时核对：

```bash
tar -cf /case/DigiForensics_E01.tar DigiForensics.E*
sha256sum /case/DigiForensics_E01.tar
```

5. 记录三处哈希并标明各自用途：原始介质 SHA-256 = X，E01 内嵌 SHA-256 = X，仿真用 VMDK 的哈希仅作内部参考。

**结论**

能证明：交付用 E01 的内嵌 SHA-256 与采集时一致，`ewfverify` 独立通过，容器自洽。

仿真用 VMDK 是从该容器派生的中间产物，其哈希只用于本次仿真前后自检。**VMDK 本身不具备交付资格**——它经过格式转换，既不自带案件元数据也不自带自验证数据。

**误判对照**

本案最容易出的错，是把 `DigiForensics-sim.vmdk` 的 SHA-256 填进报告的「证据哈希」栏。

判据要落到机制上：E01 的哈希是内嵌在容器里的，由 `ewfverify` 从段文件数据重算得出；VMDK 的哈希是对转换后的文件算的，两者数值本来就不相等。

正确做法是报告里为两者各留一行，并显式标注「VMDK 哈希仅作内部参考，不作为证据哈希」。

按错误判据走的代价：对方机构拿报告里的 VMDK 哈希去验 E01，对不上，反过来质疑整个采集环节的真实性——而实际采集完全合规。

<a id="section-35"></a>

### 5.2 段文件少一段，对方报告容器损坏

**场景**

同一批 E01 通过快递送达委托方技术部门。对方解压后执行 `ewfverify`，报段读取失败。委托方要求说明是采集出问题还是运输出问题。

这条路径值得走，因为段文件缺失与数据被改是两种完全不同的结论。混起来会毁掉整批检材的可采性。

**处置过程**

1. 先取容器自报的段信息，与实际文件列表逐段比对：

```bash
ewfinfo /case/DigiForensics.E01 | head -30
ls -l /case/DigiForensics.E*
```

`ewfinfo` 报告 26 段，实际只有 25 段。缺 `DigiForensics.E26`。

2. 反向确认缺段的位置：末段 `E26` 是 tar 包里的最后一个条目，说明**打包时它就在**——问题发生在打包之后、运输途中。

3. 核对打包文件自身的哈希，与交接记录里留的值比对：

```bash
sha256sum /case/DigiForensics_E01.tar
```

4. 结论落到运输环节，要求对方重新接收完整 tar 包。

**结论**

能证明：采集环节完整，缺失发生在打包之后的运输环节——因为 tar 包内的条目清单里 `E26` 存在。

**不能证明数据内容没被改**。段文件不在手上，就无法重算容器内嵌哈希，也就无法给出完整性结论，只能重新交付后补做。

**误判对照**

对方技术人员的默认判断是"采集时写保护器没接好，源盘读不干净"。

判据很具体：**段缺失的位置在末尾、且 tar 打包清单里有它**。这说明数据在采集时已经完整落盘并写进了 tar，缺的是运输环节的文件搬运，不是介质读取。

若按"采集有问题"这条错误判据走，结论会写成「采集过程存疑，该批检材建议重新扣押」——把一次文件传输事故升级成对整个采集流程的否定。而现场早已封存，重新扣押既不可能也无必要。

<a id="section-36"></a>

### 5.3 反例：裸 raw 镜像交付且校验值靠外部文本承载

**场景**

某次委托只交付了一个裸 `DigiForensics.dd` 与一份手写的 SHA-256 文本。对方在半年后重新校验时，无法确认该文本对应的就是手上的镜像。

之所以列为反例，是因为它**看起来是成功交付了**，实质上把校验责任推给了对方。

**处置过程**

对照点在于校验值与文件的绑定方式：

```bash
# raw 的做法：校验值靠外部文本承载，两者可以各自丢失
ls -l DigiForensics.dd sha256.txt

# E01 的做法：校验值在容器内部，丢不掉
ewfverify -f sha256 DigiForensics.E01
```

**结论**

阴性发现：在本次交付范围内，裸镜像**不具备自验证能力**。未覆盖范围是运输与存储环节——那个手写文本是否与镜像同时到达、是否被替换过，本机构无从证明。

**误判对照**

容易把「手写文本里的 SHA-256 与当前 `DigiForensics.dd` 算出来一致」当成镜像完好。

判据是这份一致只能证明"现在这个文件和当初算值时一样"，证明不了"当初算值的就是委托方收到的那份"。两者之间的运输与暂存环节完全没有记录。

按这个判据走，报告会给出一句看似有力实则无效的「镜像哈希校验通过」。代价是复核方复算出同样结果却仍然不采信，因为整个论证链条上最关键的一环——值的来源——是空的。

---
<a id="section-37"></a>

## 六、扩展阅读方向

镜像格式是取证流程里少数几个"选错了要几个月后才发现"的决定。下面这几组按实际会遇到的疑问分组。

<a id="section-38"></a>

### 前置基础：不理解这几件事，格式选择只能靠背决策表

- [哈希与完整性校验](../fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— 本篇反复强调"内嵌哈希针对解压后的原始字节流"，这句话的依据在这里。没有它，第四章陷阱 4 讲的三个哈希值你分不清谁是谁。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— `ewfmount` 挂出来的裸流仍可能被子进程写入。**挂载不等于只读**，这正是有人 `mount -o loop,ro` 就以为万事大吉的原因。
- [取证流程与原则](../fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 格式选择发生在采集环节末尾，决定的却是全程。把"为什么选这个格式"写进记录属于流程纪律，不是文档美化。

<a id="section-39"></a>

### 同层深入：其他容器格式与转换实操

- [证据格式与转换](../../imaging/imaging-acquire/imaging-acquire-evidence-image-formats.md) —— 本篇讲格式自身的结构，那篇讲怎么在 E01 / RAW / AFF4 之间转、转换记录怎么写、转换哈希怎么对。第四章陷阱 5 与陷阱 9 的动作都在那里。
- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 格式选择的上游。`ewfacquire` 只是一行参数，真正决定归档质量的是读取参数、坏扇区策略和采集时的哈希算法。
- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— 现场不具备离线采集条件时，格式选择多一层约束：不稳定的链路下分段粒度与断点续传要一起设计，否则重传的不是漏掉的段而是全部。

<a id="section-40"></a>

### 相邻议题：格式选定之后，数据往哪走

- [虚拟机仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md) —— VMDK 唯一的正当用途在这条线上：仿真环境怎么隔离、产出怎么登记，与第四章陷阱 8 呼应。
- [证据保管链与委托证明](fundamentals-chain-chain-of-custody-and-authorization.md) —— 转换记录、仿真产出登记，这些"产生新文件的操作"要往哪里入链。本篇陷阱 9 只给了单条记录模板，完整规则在那篇。
- [取证装备与写保护器](../fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) —— 如果镜像是在争议设备上直接读的，格式再好也补不回一个被写坏的源。**这是格式能力的上限。**

<a id="section-41"></a>

### 交付与移交：格式决定了这套流程什么时候算闭合

- [赛事与靶场](fundamentals-chain-forensics-competitions-and-practice.md) —— CTF 与靶场环境里的镜像通常没有真实案件约束，格式可以随意。**但那套习惯带到真实案件会出事**——这正是本篇与那篇的分野。
- [Windows-Server 环境仿真](../../imaging/imaging-mount-simulate/imaging-mount-simulate-windows-server.md) —— 需要目标系统自己跑起来时，容器要一路转成虚拟磁盘。转出来的 VMDK 不带元数据，所以归档件和仿真件必须分两个文件走。

<a id="section-42"></a>

### 判据与反例：怎么知道自己已经选错了

- [反取证手法与时间戳篡改检测](../fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— 与本篇的直接交点在 AFF4：元数据存在容器之外，`DigiForensics.E01` 加一份 `.rdf` 才是完整一组。**只归档 `.E01` 会丢掉 RDF。**
- [文件系统取证总览](../../filesystem/filesystem-ntfs/filesystem-ntfs-filesystem-forensics-overview.md) —— 镜像只是外壳，里面是分区表和文件系统。卷层魔数识别与本篇 2.3 "裸流首字节可能是分区表"是同一件事的两面。
- AFF4 实操缺口 —— 本库目前没有专讲 AFF4 实操的文章。本篇 2.6 只够帮你理解它的设计意图，多流容器的落地用法要回到 libewf 与 Autopsy 的官方文档。
- [术语查表](https://www.digiforensics.cn/wiki/digiforensics-glossary)—— `EWF` / `EnCase 6` / `EWF-L01` / `AFF4` / `ImageStream` 的定义边界，特别是 `EWF-E01` 与 `EWF-L01` 必须精确到变体，这是陷阱 3 的结论依据。
<a id="section-43"></a>

## 七、命令速查

```bash
# 环境：Ubuntu/Debian，apt install ewf-tools sleuthkit

# 采集为 E01
sudo ewfacquire -t /case/DigiForensics -f encase6 -c deflate:best -d sha256 \
     -C "2024-DG-001" -E "01" -e "Examiner" -D "Description" /dev/sdX

# 查看容器信息
ewfinfo DigiForensics.E01

# 验证完整性（对照内嵌哈希）
ewfverify DigiForensics.E01

# 挂载为裸流
sudo mkdir -p /mnt/ewf
sudo ewfmount DigiForensics.E01 /mnt/ewf
fdisk -l /mnt/ewf/ewf1
sudo umount /mnt/ewf/ewf1 && sudo rmdir /mnt/ewf

# E01 → DD
sudo ewfexport -t /case/DigiForensics-dd -f raw DigiForensics.E01

# DD → E01
sudo ewfimage -t /case/DigiForensics -f encase6 -c deflate:best -d sha256 \
     -C "2024-DG-001" -E "01" -e "Examiner" -D "Desc" DigiForensics.dd

# 转 VMDK 用于仿真
sudo qemu-img convert -f raw -O vmdk /mnt/ewf/ewf1 DigiForensics-sim.vmdk

# 全量打包（务必整目录）
tar -cf DigiForensics_E01.tar DigiForensics.E*
sha256sum DigiForensics_E01.tar
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 取证基础 — 证据文件格式：DD、E01 与 AFF4」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《证据文件格式：DD、E01 与 AFF4》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
