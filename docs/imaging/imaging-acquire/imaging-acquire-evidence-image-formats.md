---
title: "证据文件格式与格式转换"
slug: "imaging-acquire-evidence-image-formats"
canonical: "https://www.digiforensics.cn/wiki/imaging-acquire-evidence-image-formats"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "imaging"
space: "磁盘镜像与仿真"
node_path: ["镜像采集"]
---

# 证据文件格式与格式转换

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/imaging-acquire-evidence-image-formats)

<a id="section-1"></a>

## 一、概述

同一个物理磁盘的逐位副本，可以被包装成十几种完全不同的文件。选错格式影响的是**证据可用性**：数据可能无法被检验方打开、压缩后无法证明原始哈希、或者存储开销直接压垮预算。

格式选择的核心矛盾只有三个：

| 矛盾 | 说明 |
|---|---|
| **通用性 vs 效率** | RAW 任何工具都能读但体积 1:1；E01 自带压缩与元数据但需要 EWF 库 |
| **自证性 vs 简洁性** | E01/AFF4 内置哈希与采集元数据；RAW 什么都没有 |
| **可移植 vs 可管理** | 单文件便于传输；分段文件便于分卷与并行 |

**为什么这件事值得单独成篇**：镜像制作（[01-镜像制作](imaging-acquire-disk-imaging-and-evidence-preservation.md)）在采集端就要决定输出格式，而那个决定的后果要到几周后才显现——当检验方打不开你的文件、或者你在转换过程中丢了哈希链时，返工成本极高。

格式不是采集时的技术细节，它直接决定这份检材在别人手上还有没有证据价值。在委托方要求"把检材直接交给我们分析"、或者需要通过邮件/网盘把几百 GB 的镜像传出去时，这个选择就是决定性的。

**本篇处理的五种格式与它们的实质差别**：

| 格式 | 结构要点 | 自带哈希 | 体积 | 谁需要它 |
|---|---|---|---|---|
| **RAW / dd** | 裸字节流，无任何元数据 | ❌ | 1:1 | 通用工具链、体积充足的外场场景 |
| **E01（EWF）** | 分段（Segment）结构，每段独立压缩 | ✅ 每段 + 整体 | 可压缩 | **法庭交付的主流选择** |
| **AFF4** | 段模型 + 任意元数据扩展 | ✅ | 可压缩 | 需要挂载为挂载点的场景 |
| **VMDK** | 两种形态：稀疏（extent 列表）/ 扁平（整块） | 视形态而定 | 稀疏省空间 | 虚拟机仿真 |
| **VHDX** | 块级表 + 每块 CRC32 | ✅ 块级 | 动态增长 | Hyper-V / 虚拟化平台 |

这张表里最容易被误解的一行是 E01 的"加密"。E01 内置的"加密"字段默认是弱加密，作用是阻止误读，不是保护机密——这一点必须先讲清楚，否则会有人以为"用了 E01 就安全了"，或者反过来以为"没设强密码就不专业"。相关技术在 2.4。

同一行的另一面是 VMDK 的两种形态：稀疏型只记录哪些块被占用（省空间，但依赖 backing file 链，**链断了整个镜像就废了**），扁平型是整块文件（简单直接，体积 1:1）。这个选择决定了仿真环境能不能被安全地"退场"——相关机制见[虚拟机仿真](../imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md)。

**另一条必须提前知道的规则**：转换不改变数据内容，任何转换都必须能用哈希证明转换前后完全一致。

E01 → RAW 之后，RAW 文件的哈希应当等于原始采集时记录的哈希；不相等就说明转换过程出了问题（丢段、错位、编码问题），这个算式是本篇第四章 4.3 组的核心判据。

**分段与哈希的连续性是本篇最需要提前想清楚的一层。** E01 把数据切成多个段（Segment），每段独立压缩、每段自带哈希、**段有顺序**。这带来一个实践后果：**一个 500 GB 的镜像会是几百个文件**，而"一个证据文件"这个概念在 E01 上是不成立的——正确的是"一个文件组"。

只拷贝其中一个 `.E01` 文件（常见于分段边界写错、或者用邮件/IM 传大文件时的分包错误），得到的是一段无法解释的碎片。**本篇第四章 4.1 组专门处理这个**，判定方法比"文件数对不对"要复杂，因为合法分段数取决于分段大小设置。

VMDK 的 backing file 链是同一类问题的另一种形态。 稀疏 VMDK 只记录"哪些块被写过"，未写入的部分指向一个父盘文件。**父盘一旦移动或丢失，子盘就完全无法打开**，而这在"把差分盘拷给别人分析"的场景里极易发生。

这两种格式的共同教训是：它们优化的都是存储效率，代价是"文件集合必须作为一个整体流转"。

**在取证流程中的位置**：本篇是**采集**与**分析之间的转换层**。**上游**是[镜像制作](imaging-acquire-disk-imaging-and-evidence-preservation.md)——采集端可以直接输出 E01，也可以先出 RAW 再转，两条路径的记录要求不同。**下游**是所有读取环节：RAW 任何工具都能直接读，E01 需要 EWF 库或先转成 RAW，而转换本身是本篇要处理的证据链问题。读完之后进[只读挂载与安全接入](../imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)，需要动态行为观察则走[虚拟机仿真](../imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md)（**VMDK 格式正是那一篇的主要输入**）。格式本身的规范定义在[证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md)。

这个转换层的关键特点是：它是全流程里唯一一个"合法地主动改写检材副本"的环节。

其它环节要么只读（分析），要么根本不该碰原始检材（采集阶段用写保护器隔离）。只有转换，你明知道在做字节层面的改动，还要证明改动没改变内容。

五种格式的内部结构差异、E01 的分段与压缩机制、VMDK 两种形态的区别、如何用 `ewfinfo` 读出 E01 的元数据与采集信息、如何验证 E01 完整性、以及**如何在转换后证明数据未变**。

**格式不能替代证据链**——一个 E01 文件里没有采集者的身份、采集时间、工具版本，这些元数据齐备也不意味着证据链完整；**内置哈希也不能替代外部记录**——它只能证明"文件内部自洽"，不能证明"这个文件是从哪台设备来的"；以及**格式本身在法庭上的可接受性**，那是工具验证报告（CFTT / NIST 层面）的问题，不是文件结构的问题。

**还有一个反向的能力边界值得写明**：**本篇的任何操作都不能恢复已经丢失的数据。** 如果采集时 E01 分段参数设错导致丢段、或者压缩算法在转换时被误选，那部分数据在源文件里就已经不存在了——转换层能做的只是发现"对不上"，而发现之后的补救必须回到采集环节重新镜像。

本篇的方法论由此归为一条原则：**每个可验证的环节都要留下可验证的记录。**

**读者前提**：你需要先理解哈希在证据链中的作用（[哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md)），并能分辨"校验和"与"密码学哈希"在用途上的差别。格式选择的决策点在[镜像制作](imaging-acquire-disk-imaging-and-evidence-preservation.md)，本篇讲的是**选择之后如何处理**。如果你还没做采集，直接读本篇第三章的第 1、2 步就够了——把 E01 转 RAW 和验证完整性是最常用的两个动作。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 五种格式的底层结构对比

| 维度 | RAW / DD | E01 (EWF-E01) | VMDK | AFF4 | QCOW2 |
|---|---|---|---|---|---|
| 本质 | 裸扇区流 | 压缩分块 + 表文件 | 虚拟磁盘描述 + 扩展文件 | 容器 + 段 + 元数据 | 稀疏 + 快照链 |
| 压缩 | 无 | deflate / bzip2 | 无（可稀疏） | 可选 | 可选 |
| 内置哈希 | 无 | MD5 + 可选 SHA-1/256 | 无 | 有 | 无 |
| 采集元数据 | 无 | **有**（案件号、勘验员、时间） | 无 | 有 | 无 |
| 分段 | 手工 split | **原生分段** | 稀疏扩展文件 | 段文件 | 后备链 |
| 加密 | 无 | 弱（见 2.4） | 无 | 可选 | AES（不推荐） |
| 工具支持 | ★★★★★ | ★★★★ | 仅虚拟化软件 | ★★ | ★★★ |
| 存储开销 | 1:1 | 约 0.3–0.6:1 | 视稀疏度 | 视压缩 | 视稀疏度 |

**关键认知**：RAW 之所以仍是"最通用"的格式，恰恰因为它**什么包装都没有**——它就是数据本身。任何格式转换出问题时，RAW 是最后的可信基准。

<a id="section-4"></a>

### 2.2 E01 的分段（Segment）机制

这是 E01 最重要的设计。E01 实际是一组 `.E01`、`.E02`、`.E03`… 文件的集合，而非单个文件。第一个分段保存**表数据（table data）**，后续分段保存**数据块（table sections）**。

```
DigiForensics.E01   ← 第 1 段：文件头 + 卷/表元数据 + 存储桶索引
DigiForensics.E02   ← 第 2 段：续表的表数据
DigiForensics.E03   ← 第 3 段：压缩后的数据块
DigiForensics.E04   ← 第 4 段：续续
...
```

**分段大小（`-S`）的常见取值与用意**：

| 取值 | 用意 | 适用 |
|---|---|---|
| **2 GB**（业界默认/习惯值） | 兼容老工具与老文件系统 | **绝大多数案件的推荐值** |
| 4 GB | 在兼容与效率间折中 | 大容量盘，工具版本较新 |
| 1.4 GB（libewf 默认） | 保守兼容 | 不指定时的工具默认 |
| 任意（EnCase 6/7） | >2 GB 分段 | 仅 encase6/encase7 格式支持 |

> **为什么 2 GB 成了默认约定**：1990 年代末 FAT32 文件系统的单文件上限是 4 GB（更早是 2 GB）。分段设计让 E01 集合能跨越这个限制——拷到 FAT32 介质上不会因为单文件超限而失败。虽然现在很少有人用 FAT32 存证据，但 **EnCase 等商业工具的兼容习惯被继承了下来**，所以 2 GB 至今仍是安全选择。

**分段带来的三个实际好处**：

1. **分卷传输**：可以用 U 盘、光盘等介质分批搬运，途中某一段损坏只需重传该段
2. **并行处理**：`ewfverify`/`e01hash` 可多线程并发校验多段
3. **细粒度归档**：归档时按段粒度打包，不必动整个证据集

**分段带来的一个坑**：`DigiForensics.E03` 单独存在时毫无意义——它依赖 `.E01` 中的索引才能定位数据。传输或归档时**必须整组一起处理**。只拷走某个中间段，得到的是损坏的证据。

<a id="section-5"></a>

### 2.3 E01 的压缩与编码

| 压缩方式 | 说明 |
|---|---|
| `none` | 不压缩，体积 1:1，但速度快 |
| `empty-block` | 只压缩全零块（已删除的空间常是全零），压缩率一般但极快 |
| `fast` | deflate 快速档 |
| `best` | deflate 最大压缩率，**取证默认首选** |

压缩是**逐 chunk 独立进行**的（chunk 由 `-b` 指定，默认 64 扇区 = 32 KB）。这带来一个重要性质：**支持随机访问**。读取某个偏移时，只需解压它所在的 chunk，不必从头解压整个镜像。

这也是 E01 比"把整个盘 gzip 一下"快得多的原因。

<a id="section-6"></a>

### 2.4 E01 的"加密"：一个必须说清的事实

**E01 的密码功能不是加密。** EnCase 的 legacy password 只是一个存储在文件头中的校验值，用于阻止非授权工具**修改** E01，不提供任何**机密性**。

绕开取证工具直接处理文件即可读取内容；设密码反而降低可审计性——他人无法用工具验证你的镜像。

> **结论：不要给证据文件设置密码。** 它不提供安全价值，只制造麻烦。需要保护介质时用磁盘级加密（LUKS / BitLocker To Go），并单独记录密钥保管流程。

<a id="section-7"></a>

### 2.5 VMDK 的两种形态

| 形态 | 结构 | 陷阱 |
|---|---|---|
| **单体 VMDK** | 一个 `.vmdk` 文件，含描述符+数据 | 简单，但无压缩 |
| **分裂 VMDK（split）** | 一个几 KB 的**描述符** `.vmdk` + 多个 `-s001.vmdk` 扩展文件 | 只拷描述符 = 只拷了个 2 KB 的文本清单，磁盘数据全在扩展文件里 |

分裂 VMDK 的 2 GB 分片同样是 FAT32 时代的遗产。取证时**必须拷贝整个目录**。

<a id="section-8"></a>

### 2.6 转换时哈希的连续性

转换是**最容易破坏证据链**的操作，因为原始哈希是基于源格式的。正确做法是建立一条链：

```
原始检材 ──制作时计算──> DigiForensics.E01（内置 MD5 + SHA-256）
                              │ ewfexport
                              ▼
                      DigiForensics.dd（独立复算 SHA-256）
```

只有当两端 SHA-256 相同时，才能说"转换保持了数据完整性"。 "文件能打开""大小一致"都不构成验证。

---
<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：用 ewfinfo 查看 E01 元数据

```bash
sudo apt install ewf-tools        # Ubuntu / Debian
ewfinfo -d iso8601 /evidence/DigiForensics.E01
```

典型输出与解读：

```
Acquiry information
Case number:        CASE-2026-0142
Description:        Dell OptiPlex 7010 512GB SSD
Examiner name:      勘验员姓名
Acquisition date:   2026-09-28T14:32:07+00:00
EWF information
File format:        EnCase 6
Sectors per chunk:  64                ← chunk = 32 KB
Compression method: deflate
Compression level:  best compression
Set identifier:     869910fc-e143-4908-9328-afedf4a7be1e
Media information
Media type:         fixed disk
Is physical:        yes
Bytes per sector:   512
Number of sectors:  1000215216
Media size:         478.9 GiB (514110344448 bytes)
Digest hash information
MD5:                ae1ce8f5ac079d3ee93f97fe3792bda3
SHA-1:              3b1e...
```

`Set identifier` 是同一个采集任务的全集标识——同一台机器的多块盘会有**相同的 Set identifier**。这个字段在多盘案件中用来证明"这几块盘是在同一次采集任务中获取的"，很有价值。

常用选项：`-m` 只看介质信息、`-i` 只看采集信息、`-e` 只看读错误信息、`-f dfxml` 输出 DFXML。

<a id="section-11"></a>

### 3.2 第 2 步：验证 E01 完整性

```bash
# 校验镜像与其内置哈希（libewf 标准工具）
ewfverify /evidence/DigiForensics.E01
```

输出会逐项报告 MD5/SHA-1/SHA-256 的校验结果，"success" 才是通过。不同 libewf 版本支持的参数略有差异，脚本化前先跑 `ewfverify --help` 确认本机能力。

<a id="section-12"></a>

### 3.3 第 3 步：E01 → RAW 导出

完整命令见第七节。关键点：

| 参数 | 含义 |
|---|---|
| `-f raw` | 输出格式：`raw` / `files` / `ewf` / `encase6` / `encase7` / `ftk` / `ewfx` 等 |
| `-t` | 目标文件名（不带扩展名）；填 `-` 可写 stdout（仅 raw 支持） |
| `-S` | 分段大小，**libewf 默认 1.4 GiB** |
| `-b` | 每 chunk 读取扇区数（16–32768，默认 64） |
| `-o` / `-B` | 起始偏移 / 导出字节数，用于只导出部分卷 |
| `-u` | 无交互模式 |
| `-l` | 日志（**同时记录 MD5 摘要**） |
| `-d sha1` | 追加摘要，但 `raw` 与 `files` 格式下该值不生效 |

**`-d` 在 `raw` 下无效**——RAW 本身不存储摘要元数据，只有 EWF 系格式才有。导出后必须**在外部**独立计算哈希。`ewfexport` 还有一个易被忽略的 `-w`：校验出错时把扇区清零，模拟 EnCase 的行为；取证中**不要加**，它会掩盖真实差异。

**导出后立即验证**：`sha256sum` 算出的值与 `ewfinfo -m` 报告的 E01 内置 SHA-256 必须逐字符一致。不一致说明导出过程有问题（磁盘满、传输损坏、源 E01 本身损坏），必须查明原因后才能继续。

<a id="section-13"></a>

### 3.4 第 4 步：RAW → E01 转换

把已有 dd 镜像包装成 E01（用于压缩归档或交付检验方），源参数用**文件路径**：

```bash
ewfacquire -u \
  -t /evidence/DigiForensics-archived \
  -f encase6 -c deflate:best -d sha256 -S 2G \
  -C "CASE-2026-0142" -E "E-001" \
  -D "由 DigiForensics.dd 转换而来" -e "勘验员姓名" \
  -l /evidence/convert.log \
  /evidence/DigiForensics.dd
```

转换后必须验证：先 `ewfverify` 新 E01，再确认它的内置 MD5 与原 dd 的 `md5sum` 一致。

<a id="section-14"></a>

### 3.5 第 5 步：其他转换路径与归档记录

`qemu-img` 与 `xmount` 的完整调用见第七节（VMDK 拆分时需指定具体扩展文件）。`qemu-img` 会**就地修改**目标文件，永远不要对正在被虚拟机使用的镜像执行；取证场景应当"源只读 → 目标新建"。

无论怎么转，都应产出一份**格式无关的清单**，让后续任何人都能理解证据的来龙去脉：

```bash
# 生成证据清单
{
  echo "=== 证据转换记录 ==="
  echo "日期(UTC): $(date -u +%FT%TZ)"
  echo "原始检材: /dev/sdb  序列号 S3Z2NB0K"
  echo "制作工具: dcfldd 1.3.4-7"
  echo "源哈希 SHA-256: $(cat /evidence/DigiForensics.dd.sha256)"
  echo "E01 内置 MD5:   $(ewfinfo -m /evidence/DigiForensics.E01 | awk '/MD5/{print $2}')"
  echo "RAW 复算 SHA-256: $(sha256sum /evidence/DigiForensics.dd | awk '{print $1}')"
  echo "分段列表:"; ls -l /evidence/DigiForensics.E0*
} > /evidence/format-conversion-record.txt
```

---
<a id="section-15"></a>

## 四、常见陷阱

证据格式的失误有一个共同点：**它们大多不会报错**。分段少拷了照样能打开，压缩后体积变小了看着像优化，`ewfverify` 报 success 看着像通过——而这些"正常现象"恰恰是陷阱的掩护。

全篇的核心原则在概述里已经给定：转换不改变数据内容，任何转换都必须能用哈希证明转换前后完全一致。本章按四个环节展开：分段与文件组、格式误用、哈希链、验证边界。

★ 标记表示该操作会销毁原始检材或使证据集永久残缺，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 分段与文件组

<a id="section-17"></a>

#### 陷阱 1：★ 只拷贝中间分段，或分段顺序被打乱

**现象**：传输 E01 时只拷了 `DigiForensics.E05` 到 `E24`（因为 `E01`–`E04` "已经有了"）；或者从不同来源分别拿到各段，归位时按某种顺序排列。

**原因**：2.2 把这件事讲得很完整：E01 实际是一组 `.E01`、`.E02`、`.E03`… 文件的集合，而非单个文件——第一个分段保存表数据（table data），后续分段保存数据块（table sections）。

而"哪些段已经有了"这个问题在实际操作中非常容易答错：多盘案件里几块盘的 E01 会同时存在于同一目录，命名规则又是自动递增的，`E03` 可能是另一块盘的第三段。

分段编号靠顺序定位，交换会导致解析失败或读到错位数据——而"解析失败"还算好的结果，"读到错位数据"是有效但错误的。

**影响**：**得到的是损坏的证据，且损坏方式可能是静默的**。2.2 那句"DigiForensics.E03 单独存在时毫无意义——它依赖 .E01 中的索引才能定位数据"描述的就是这个依赖关系。

如果段集不全，工具可能报读错误，也可能用零填充继续——后者得到的是一份"看起来有数据、实际缺段"的镜像。

**核查**：**必须整组一起处理，顺序不能乱**。归档时用目录整体打包，不用通配符逐个筛：

```bash
# ① 确认段集完整且连续
ls -l /evidence/DigiForensics.E0* | awk '{print $NF}' | sort
# 期望：E01 E02 E03 ... E24 连续无缺口

# ② 打包时整组带上，不做筛选
tar -cf /delivery/DigiForensics-E01-set.tar -C /evidence DigiForensics.E0*

# ③ 送达方先验段集，再验内容
ewfinfo /delivery/DigiForensics.E01
ewfverify /delivery/DigiForensics.E01
```

**段数要写进交接记录**。案例第 1 步的做法是把"分段文件为 `DigiForensics.E01` 至 `DigiForensics.E24`"这句话写进记录——这个句子的作用是让对方能在第一时间判断自己拿到的是不是完整的 24 段。

顺带一条：`Set identifier` 在这里有用。3.1 说明它是同一个采集任务的全集标识，同一台机器的多块盘会有**相同的 Set identifier**——段集搞混时，这个字段能立刻暴露问题。

```bash
# Set identifier 出现在 EWF information 段，不在 -i 的采集信息段里
ewfinfo /evidence/DigiForensics.E01 | grep -i 'set identifier'
# 用它确认这一组段属于同一次采集任务
```

<a id="section-18"></a>

### 4.2 格式误用

<a id="section-19"></a>

#### 陷阱 2：★ 给证据文件设置密码

**现象**：交付前给 E01 设了密码，"防止别人打开"；或者从别处拿到一个设了密码的 E01，试着破解。

**原因**：2.4 的标题就是答案："E01 的密码功能不是加密"。它讲清了机制：EnCase 的 legacy password 只是一个存储在文件头中的校验值，用于阻止非授权工具修改 E01，不提供任何机密性。

所以两条路都是通的：绕开取证工具直接处理文件即可读取内容；设密码反而降低可审计性——他人无法用工具验证你的镜像。

**影响**：**用一个假的安全感换掉了真实的能力**。设了密码之后，`ewfverify` 跑不了、`ewfinfo` 受限、检验方打不开——而内容本来就能被别人读到。

这一条列入"绝对不要做"是因为它的损失不可逆：**交付件一旦发出就收不回来**，检验方拿到的可能是一份谁也验证不了的文件。

**核查**：**不要给证据文件设置密码**。需要保护介质时用磁盘级加密（LUKS / BitLocker To Go），并单独记录密钥保管流程：

```bash
# 保护介质，而不是给证据文件加密码
cryptsetup luksFormat --type luks2 /dev/sdX1
cryptsetup open /dev/sdX1 evidence_volume
# 密钥保管流程单独记录，与证据记录分离
```

**判断某个 E01 是不是设了密码**：跑 `ewfverify`，报需要密码就是设了。此时**不要尝试破解**——正确动作是向制作方索取无密码版本或密钥，**因为设密码这个行为本身就说明制作流程有问题**。

<a id="section-20"></a>

#### 陷阱 3：用 `dd` 把 E01 当 RAW 读

**现象**：为了快速在 E01 里找某个字符串，执行 `dd if=DigiForensics.E01 bs=1M count=100 | strings`，什么都没找到，于是判断"镜像里没有这段内容"。

**原因**：E01 不是裸数据流，它存的是压缩后的 chunk。用 `dd` 读出来的是压缩后的字节流，`strings` 在压缩数据里当然搜不到——"完全是垃圾"不是比喻。

这个操作的危险之处不在于结果无用，而在于**它产生了一个可以写进报告的假阴性结论**。

**影响**：**把"格式不匹配"读成"内容不存在"**。而这是最坏的一类误判：结论看起来像一次完整的检查，实际上连数据格式都没打开。

**核查**：必须先 `ewfexport` 或 `ewfmount` 桥接，让常规 Unix 工具能读到真实数据：

```bash
# 方式一：FUSE 挂载（只读），挂载点下会出现 /mnt/ewf/ewf1
sudo ewfmount /evidence/DigiForensics.E01 /mnt/ewf
ls -l /mnt/ewf/ewf1                       # 这个文件才是原始数据流
grep -a -n 'target' /mnt/ewf/ewf1
sudo ewfumount /mnt/ewf

# 方式二：xmount 桥接，语法与第七章速查一致
xmount --in ewf /evidence/DigiForensics.E01 --out raw /mnt/xmount

# 方式三：导出为 RAW 后再搜（需要额外空间时最直接）
ewfexport -u -f raw -t /work/DigiForensics /evidence/DigiForensics.E01
grep -a -n 'target' /work/DigiForensics.dd
```

**注意 `ewfmount` 的挂载点不是镜像本身**：挂到 `/mnt/ewf` 后，**真实的数据流是目录下的 `ewf1` 文件**。直接在 `/mnt/ewf` 上跑 `grep` 会只搜到一个空目录的元数据，同样是"方法不匹配、结论无效"。

2.1 末尾那句"RAW 之所以仍是最通用，恰恰因为它什么包装都没有——它就是数据本身"，就是这个操作的正解：需要用常规工具直接操作时，导出 RAW 是最可靠的一步，代价是体积 1:1。

<a id="section-21"></a>

#### 陷阱 4：★ `ewfexport` 的目标名与源同名，覆盖原始证据

**现象**：执行 `ewfexport -f raw -t /evidence/DigiForensics /evidence/DigiForensics.E01`，而 `/evidence/DigiForensics.dd` 已经存在（比如是上次转换的产物）。

**原因**：`-t` 指定的是**不带扩展名的目标文件基名**，而工具会自动加 `.dd`。`DigiForensics.E01` 与 `DigiForensics.dd` 的基名完全一样，这在同一个目录下时非常容易撞上。操作的动机通常很单纯——"导出到当前目录方便"，而这个便利的代价没有在命令里体现。

**影响**：**原始证据被覆盖**。如果 `DigiForensics.dd` 是上次的转换产物，覆盖它只是丢一份中间件；**如果它是源文件或唯一副本，则不可逆**。

而更常见的情况是这个目录里同时躺着 E01 和它的导出件，操作者已经分不清哪个是源、哪个是导出。

**核查**：**导出前确认目标路径，源与目标分目录**：

```bash
# 源与目标分目录存放，物理隔离
ls -l /evidence/source/ /evidence/export/
# 导出前检查目标是否已存在
test -e /export/DigiForensics.dd && echo "[-] 目标已存在，先改名或删除"

# 导出后立即验证
sha256sum /export/DigiForensics.dd
ewfinfo -m /evidence/source/DigiForensics.E01 | grep -i sha
```

**转换动作本身要进记录**（3.5 的清单格式就是为此设计的）——"谁在什么时候把什么转成了什么"是保管链的一部分，而覆盖操作会让这份记录失真。

<a id="section-22"></a>

### 4.3 哈希链与格式认知

<a id="section-23"></a>

#### 陷阱 5：以为 E01 压缩后哈希变了

**现象**：对比 E01 内置的 MD5 和 dd 的 `md5sum`，发现不一致，判定"转换过程损坏了数据"；或者反过来，看到 E01 体积只有 RAW 的 40%，怀疑"少了 60% 的数据"。

**原因**：2.6 讲清了链的结构：E01 内置的 MD5 是对解压后的原始数据计算的，与 dd 的 MD5 一致。而"压缩后哈希不同"这个直觉来自一个真实但被误用的规则——文件哈希是对文件字节算的，而 E01 的字节是压缩后的。

两件事都对，但它们说的不是同一个对象：E01 内置哈希的对象是原始数据，文件哈希的对象是容器。

**影响**：**要么误判转换失败，要么误判数据缺失**。后者更隐蔽：E01 体积小是压缩的正常结果，而"少了 60% 数据"这个判断如果写进报告，会直接推翻整个交付。

**核查**：**区分三层哈希，各有各的对象**：

| 哈希 | 对象 | 用途 |
|---|---|---|
| E01 内置 MD5/SHA | **解压后的原始数据** | 证明原始数据未变 |
| E01 文件本身的哈希 | 压缩后的容器 | 证明容器文件未变（归档用） |
| 导出 RAW 的哈希 | 原始数据 | 与内置哈希比对，证明转换无损 |

```bash
# 正确：两端比的都是原始数据
sha256sum /delivery/DigiForensics.dd
ewfinfo -m /evidence/DigiForensics.E01 | grep -i sha
# 逐字符一致 → 转换无损
```

2.6 末尾那句"只有当两端 SHA-256 相同时，才能说转换保持了数据完整性。'文件能打开''大小一致'都不构成验证"，是这一条的全部判据。

<a id="section-24"></a>

#### 陷阱 6：转换后不验证哈希，只看"能打开、大小一致"

**现象**：`ewfexport` 跑完，RAW 文件大小与 `Media size` 一致，用 `mmls` 能读出分区表，报告写"转换成功"。

**原因**：2.6 的结论把验证方式限定死了：只有两端 SHA-256 相同才能说转换保持了数据完整性。"能打开"和"大小一致"这两项的检验力都极低：**大小一致只证明文件长度对，不证明内容对**；能打开只证明头部结构可解析，不证明中后段数据完整。

而导出失败的方式恰恰是"部分写入"——磁盘满、传输损坏、源 E01 本身有坏道，这几种都会产生一个大小正确但内容有缺口的文件。

**影响**：2.6 说得直接：转换是最容易破坏证据链的操作，因为原始哈希是基于源格式的。跳过这一步，链就断在中间——而断掉的这一段恰好是委托方最关心的部分（他们拿到的是 RAW，需要确认它与 E01 等价）。

**核查**：**导出后立即验证，两端哈希逐字符比对**：

```bash
# 导出
ewfexport -u -f raw -t /delivery/DigiForensics \
  -l /evidence/DigiForensics-export.log \
  /evidence/DigiForensics.E01

# 立即验证：导出件复算 vs E01 内置
sha256sum /delivery/DigiForensics.dd | awk '{print $1}'
ewfinfo -m /evidence/DigiForensics.E01 | grep -i sha
```

**不一致时不要重试覆盖，要先查明原因**（3.3 明确：不一致说明导出过程有问题——磁盘满、传输损坏、源 E01 本身损坏）。**三种原因对应三种不同的处置**，混在一起重试会掩盖真正的问题。

顺带两个易错参数：

- `-d sha256` 在 `-f raw` 下不生效——RAW 本身不存储摘要元数据，只有 EWF 系格式才有。所以哈希必须在外部算。
- **`-w` 不要加**：它会在校验出错时把扇区清零以模拟 EnCase 行为，这会掩盖真实差异。

```bash
# 正确：不加 -w
ewfexport -u -f raw -t /delivery/DigiForensics /evidence/DigiForensics.E01
# 禁止：ewfexport -w ...   ← 掩盖差异
```

<a id="section-25"></a>

### 4.4 验证边界与结论

<a id="section-26"></a>

#### 陷阱 7：`ewfverify` 报 success 就认为数据完整

**现象**：`ewfverify` 输出 MD5 success、SHA-1 success，报告写"镜像完整性验证通过，采集质量良好"。

**原因**：2.6 与 3.2 之间有一条界线常被忽略：`ewfverify` 只证明文件内部自洽。它验证的是"这个 E01 的内容与它自己记录的内置哈希一致"——**而内置哈希是在采集时针对已经读到的数据算的**。如果采集时源盘就有坏道，读失败的位置被填零或跳过，**这些零同样被纳入哈希计算**，验证依然通过。

**影响**：**把"容器完整"读成"数据完整"**。这两者之间隔着的正是采集质量这个变量，而采集质量恰恰是委托方最关心的（"有没有丢数据、丢了多少"）。

**核查**：完整性验证要分两层，且采集时的读错误记录必须单独查：

```bash
# 第一层：容器自洽
ewfverify /evidence/DigiForensics.E01

# 第二层：采集时有没有读失败（ewfinfo 的 -e 选项专门输出读错误信息）
ewfinfo -e /evidence/DigiForensics.E01
# 输出中的读错误扇区数与范围，直接对应"哪些数据没拿到"
```

如果采集用了 `ddrescue`，mapfile 是额外的必需材料——它记录了哪些块失败了、重试了几次、最终哪些块不可读。这一层是"数据完整性"的唯一证据来源。

**报告写法要分层**：

> "**容器完整性**：`ewfverify` 校验 MD5/SHA-1 全部 success，证明 E01 文件内部自洽、未发生存储层损坏。
> **采集完整性**：`ewfinfo -e` 报告读错误 0 处；本次采集使用 `dcfldd`，未使用重试机制。本报告不就'源盘是否存在未被读出的物理坏道'作出结论——该判断需依赖采集时的设备健康信息。"

<a id="section-27"></a>

#### 陷阱 8：拿 `split`/`raw` 文件组去找 `e01import`

**现象**：手上有一组文件（某个 `.vmdk` + 若干 `-s001.vmdk`，或若干个 `.raw` 分片），想"导入成 E01"，执行 `e01import` 得到 command not found，然后以为自己少装了工具。

**原因**：libewf 没有 `e01import` 这个工具。而这个名字看起来非常合理——它符合 `ewfxxx` 的命名直觉，也符合"导入"这个语义。找不到它之后，人容易往"环境问题"上想（换源、加仓库、找非官方包），**而真正的问题是要做的操作被记错了**。

**影响**：**时间浪费在装不存在的东西上**，而真正的操作一直没做。转换这一步悬空，后面所有基于新格式的工作都停住了。

**核查**：**按 libewf 的实际工具分工来选命令**：

| 你要做的 | 正确工具 |
|---|---|
| 打包 raw 为 E01 | **`ewfacquire`** |
| 从损坏 EWF 中抢救数据 | **`ewfrecover`** |
| 导出 EWF 为其他格式 | `ewfexport` |
| 校验、查看、挂载 | `ewfverify` / `ewfinfo` / `ewfmount` |

```bash
# raw → E01（3.4 的完整形式，源参数用文件路径）
ewfacquire -u \
  -t /evidence/DigiForensics-archived \
  -f encase6 -c deflate:best -d sha256 -S 2G \
  -C "CASE-2026-0142" -E "E-001" \
  -D "由 DigiForensics.dd 转换而来" -e "勘验员姓名" \
  -l /evidence/convert.log \
  /evidence/DigiForensics.dd

# 转换后验证：先 ewfverify 新 E01，再确认内置 MD5 与原 dd 的 md5sum 一致
```

**判断本机能力的通用方法**：`ewfacquire --help`、`ewfexport --help`。3.2 那句"不同 libewf 版本支持的参数略有差异，脚本化前先跑 `ewfverify --help` 确认本机能力"，对所有 `ewf*` 工具都适用。

<a id="section-28"></a>

#### 陷阱 9：VMDK 只拷描述符，或 `qemu-img` 操作在用中的镜像

**现象**：仿真时拷了一个 `.vmdk` 文件过去，发现只有 2 KB——那是描述符；或者对正在被某台虚拟机使用的镜像文件执行 `qemu-img convert`。

**原因**：2.5 把 VMDK 的两种形态讲得很清楚：分裂 VMDK 是一个几 KB 的描述符 `.vmdk` + 多个 `-s001.vmdk` 扩展文件，只拷描述符 = 只拷了个 2 KB 的文本清单，磁盘数据全在扩展文件里。

2 KB 这个体积本身是个信号——它明显不像一份 478 GB 的镜像，但如果你知道它是 VMDK，可能会误以为"压缩率这么高"。

而 `qemu-img` 那边，3.5 直接给了警告：它会就地修改目标文件，永远不要对正在被虚拟机使用的镜像执行。

**影响**：**前者是仿真失败，数据一份都没带过去**；后者是**正在使用的虚拟机磁盘被损坏**，而那可能是一台正在运行的分析机。

**核查**：拷贝整个目录；对 qemu-img 采取"源只读、目标新建"：

```bash
# ① 仿真的 VMDK 整目录拷贝
tar -cf /lab/DigiForensics-vmdk.tar -C /lab DigiForensics.vmdk DigiForensics-s*.vmdk
# 或生成单体 VMDK，避免分裂形态
qemu-img convert -f raw -O vmdk /delivery/DigiForensics.dd /lab/DigiForensics.vmdk
qemu-img info /lab/DigiForensics.vmdk     # 确认 virtual size 正确

# ② 操作前确认没有进程持有
sudo fuser -v /lab/DigiForensics.vmdk
sudo lsof /lab/DigiForensics.vmdk
# 有输出 = 有进程在用，换时间或换副本
```

**仿真的中间格式不进最终归档**。3.5 最后的清单要求产出**格式无关的记录**——VMDK 是仿真用的中间件，不是证据交付格式；它应当在仿真完成后与差分盘一起销毁，**保留的应当是源 E01 与必要的交付副本**。

<a id="section-29"></a>

#### 陷阱 10：以为所有工具都读 E01，用 `strings` 搜不到就下结论

**现象**：为了快速在证据里找关键字，直接对 `.E01` 文件跑 `strings`/`grep`，无结果，写进报告"未发现"。

**原因**：与陷阱 3 是同一类错误的两个表现：`strings`、`grep`、常规 Unix 工具都不认 E01（2.1 的工具支持行给 E01 四颗星、RAW 五颗星，差距就在这里）。**E01 里的内容是压缩的、且分 chunk 存储**，即使某个 chunk 里恰好有一段可打印字节，那也只是压缩流的碎片。**"搜不到"这个结果与方法不匹配**。

**影响**：**又是一个范围不足的阴性结论**。而且这个错误比陷阱 3 更隐蔽——陷阱 3 用 `dd` 至少还打开了文件，而 `strings` 走的是一条看起来完全正常的路径。

**核查**：**常规工具要在 RAW 或挂载点上跑**：

```bash
# 方式一：xmount 桥接为普通文件（推荐，无需额外空间）
xmount --in ewf /evidence/DigiForensics.E01 --out raw /mnt/xmount
ls -l /mnt/xmount                          # 桥接出的文件名沿用源名
grep -a -n 'target' /mnt/xmount/DigiForensics.E01
strings -e l -n 4 /mnt/xmount/DigiForensics.E01 | grep -i 'target'
sudo xmount -u /mnt/xmount/DigiForensics.E01 /mnt/xmount

# 方式二：ewfmount 挂载，注意数据流是挂载点下的 ewf1
sudo ewfmount /evidence/DigiForensics.E01 /mnt/ewf
strings -e l -n 4 /mnt/ewf/ewf1 | grep -i 'target'
sudo ewfumount /mnt/ewf

# 方式三：导出 RAW 后处理（需要额外空间时更直接）
```

**阴性结论要写清方法与范围**：

> "**关键字检索**：在 `/mnt/xmount/DigiForensics.E01`（E01 经 `xmount` 桥接为 RAW 后只读挂载）范围内，以 UTF-8、UTF-16LE 双编码对全镜像执行。两种编码下均未匹配到 `<关键字>`。本结论不表明检材内不存在该内容，仅表明在上述桥接与编码范围内未匹配。"

同一份检材在 RAW 与 E01 上的搜索结果必须一致——不一致就说明方法环节有问题，而不是内容有差异。
<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 E01 转 RAW 交付：两端 SHA-256 必须逐字符一致

**场景**

某数据泄露案件已完成取证，原始镜像为 FTK Imager 制作的 `DigiForensics.E01`（478 GB，EnCase 6，deflate best，MD5 = `ae1ce8f5ac079d3ee93f97fe3792bda3`）。检察机关要求交付**可被通用工具直接读取的裸镜像**，同时实验室内部需要压缩归档以节省存储。委托方的问题是：交出去的裸镜像是不是原来那份。

这条路径值得走，因为**格式转换本身不引入错误，但也不自动提供证据**——交付件必须自己证明与主副本同源。

委托方真正的问题只有一个："这份裸镜像是不是原来那份。" 这个问题不能用"我们转换过程没出错"来回答——过程不出错和结果可追溯是两件事，本案的全部工作都落在后者上。

**处置过程**

**第 1 步 · 确认 E01 结构与元数据**：

```bash
ewfinfo -d iso8601 /evidence/DigiForensics.E01
```

确认 EnCase 6 格式、Sectors per chunk 64（32 KB）、deflate best 压缩、Media size 478.9 GiB、MD5 与勘验日志记录一致；分段文件为 `DigiForensics.E01` 至 `DigiForensics.E24`。

**分段编号的连续性要单独确认**。`ewfinfo` 会列出全部段，但更可靠的是核对实际文件数与最大段号：

```bash
ls /evidence/DigiForensics.E* | wc -l        # 应为 24
ls /evidence/DigiForensics.E* | tail -1       # 应为 ...E24
```

段数少于最大编号说明中间有缺口；段数多于最大编号说明有陈旧段残留（比如上一次采集的 `E25` 没删）。**这两种情况 `ewfverify` 都可能通过**——它按段文件的实际连续性读取，缺口若不落在有效数据范围内就不影响校验。

**第 2 步之前还要确认段文件的权限**。E01 目录里的段文件若可写，"内嵌哈希"这个自验证机制在被人为篡改时是可以跟着改的。把 24 个段文件一并设成只读，成本是一条 `chmod`，效果是让自验证真正有意义：

```bash
chmod 444 /evidence/DigiForensics.E*
```

**第 2 步 · 交付前完整性验证**：

```bash
ewfverify /evidence/DigiForensics.E01
```

MD5 校验 success，SHA-1 success（采集时已用 `-d sha256` 额外计算了 SHA-256）。

**`ewfverify` 的三种输出要分清**。它会依次报 MD5、SHA-1、以及采集时用 `-d` 显式要求计算的其他摘要，每一项的输出是 `success` 或失败信息。本案三项都通过，但报告里要写清是哪三项——只写"校验通过"而复算人发现 SHA-256 那项其实没跑，会直接质疑是不是漏检了。

```text
MD5      success
SHA-1    success
SHA-256  success
```

**第 3 步 · 导出为 RAW 交付件**：

```bash
ewfexport -u -f raw -t /delivery/DigiForensics \
  -l /evidence/DigiForensics-export.log \
  /evidence/DigiForensics.E01
```

第 4 步 · 关键验证：比对两端 SHA-256：

```bash
sha256sum /delivery/DigiForensics.dd
ewfinfo -m /evidence/DigiForensics.E01 | grep -i sha
```

两者输出 `b8f2a1c94d7e3...`（示例值，64 位十六进制），**逐字符一致**。这一步是整个交付的证据基石。

**这一步的顺序不能反**。先算 E01 的 SHA-256、再导出、再算 RAW 的 SHA-256，然后比对——如果先导出再从 E01 取哈希，两次操作之间 E01 理论上可以被改动。实际执行时更稳的做法是在导出前后各取一次 E01 的内嵌摘要，两次一致才能说明导出期间源没变：

```bash
ewfinfo -m /evidence/DigiForensics.E01 | grep -i sha256 | tee /tmp/before.txt
ewfexport -u -f raw -t /delivery/DigiForensics -l /evidence/DigiForensics-export.log /evidence/DigiForensics.E01
ewfinfo -m /evidence/DigiForensics.E01 | grep -i sha256 | tee /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt    # 应无差异
```

多这两条命令换来的是"导出过程没有修改源"这个额外结论，而不只是"导出结果等于源"。

**导出后的第一件事是核对容量**。RAW 没有容器，所以体积应该与 E01 头里记录的 Media size 完全一致（478.9 GiB）。如果 `ewfexport` 中途出错但返回了 0，容量会是一个"看起来差不多"的数——**精确到字节的容量比对是截断最可靠的探针**：

```bash
stat -c%s /delivery/DigiForensics.dd        # 应 = 478,9xx,xxx,xxx（与 ewfinfo 的 Media size 逐字节相等）
```

这条检查放在哈希比对之前：容量不对就不用算了，省下读一遍 478 GB 的时间。

**第 5 步 · 制作 VMDK 供仿真使用**：

```bash
qemu-img convert -f raw -O vmdk /delivery/DigiForensics.dd /lab/DigiForensics.vmdk
qemu-img info /lab/DigiForensics.vmdk
```

**结论**

能证明：`/delivery/DigiForensics.dd` 与 `DigiForensics.E01` 内嵌 SHA-256 逐字符一致，两者内容等价。三条独立路径（`ewfverify` 内置校验、`ewfexport` 导出后复算、重新包装后的内置摘要）指向同一哈希，证据链闭合。原始 E01 保留为主副本封存，RAW 为交付副本并单独计算哈希，两者关系有书面记录。

**不能证明**：原始数据的完整性——那取决于采集环节。本次采集为在线热镜像，文件系统一致性存在理论限制（第 01 篇已记录），格式转换无损不代表采集无损。

还有一个格式层面特有的陷阱值得点出：**E01 的压缩是分块独立的**（chunk 级 deflate），这意味着**单个 chunk 的损坏不会导致整个文件无法解压**，而是只影响那 32 KB 的内容。所以一次成功的 `ewfexport` 并不保证导出的 RAW 每一块都正确——它保证了"能导出来"，而 `ewfverify` 保证了"哈希匹配"，两者合起来才覆盖完整性。

**RAW 交付件也有它自己的注意事项**。它没有任何内置元数据，所以交付时必须附一份说明文件，写明它由哪个 E01、于何时、经何工具导出，以及 E01 的哈希。否则三年后没人能证明这个 `.dd` 是从哪来的——**裸镜像的溯源成本全部转移到了人工记录上**。

**误判对照**

最容易得出的错误结论是「把 E01 内嵌的 MD5（`ae1ce8f5...`）与 RAW 交付件的 SHA-256 放在一起比对」。判据有三条：

①**MD5 与 SHA-256 是两套完全独立的算法**，输出长度分别为 32 与 64 个十六进制字符，永远不可能相等——它们不存在"一致"或"不一致"的关系，只是各自算出了不同的值；
②E01 内嵌摘要的默认算法是 MD5（`-d sha256` 是在采集时额外要求计算的），不指定算法去比对，等于拿两个不同函数的输出做相等性判断；
③正确路径是同算法对同算法：RAW 用 `sha256sum` 算的值，只能与 `ewfinfo -m` 取出的那 64 位 SHA-256 比。

按错误判据走的代价：报告里会出现"哈希比对不一致"的表述，对方据此质疑导出过程有数据损坏，而实际上两个值都对、只是算法不同——这类错误一旦写进正式交付说明，会把一个成功的转换变成一场需要额外验证的争议。

<a id="section-32"></a>

### 5.2 段文件缺失一位：ewfexport 中途失败留下的半份交付件

**场景**

另一批次中，`ewfexport` 执行到 40% 时因目标磁盘空间不足中断，目标路径下留下了一个大小约为 190 GB 的 `DigiForensics.dd`。操作员注意到退出码非零，删除残件后重跑并成功，但复核时对方质疑"是否有一次失败的交付件曾被发出"。

这条路径值得写下来，因为**失败残留件是交付流程里最难自证清白的一类痕迹**。

**处置过程**

1. 先确认残件的性质：它是一个完整的、可被误用的镜像：

```bash
ls -l /delivery/DigiForensics.dd          # 190 GB，导出被截断
sha256sum /delivery/DigiForensics.dd      # 与 E01 内嵌 SHA-256 必然不同
```

2. 关键动作是**记录而非删除**——把残件的存在、大小、哈希、以及重跑结果一并记入操作日志：

```text
14:22  ewfexport 中断（ENOSPC，目标卷剩余 0）
14:22  残件 /delivery/DigiForensics.dd，190,237,486,592 字节
       SHA-256 = 7c3e...（与 E01 内嵌值不同，确认其为截断件）
14:25  残件安全擦除，记录于操作日志第 3 页
15:40  扩容后重跑 ewfexport 完成，SHA-256 与 E01 内嵌值逐字符一致
```

3. 交付清单中只列成功的那一份，并注明残件从未离开实验室。

4. 把"会不会被误发"这件事用外部事实证明，而不是用内部声明。复核方真正担心的不是残件存在，而是"这份残件有没有以任何形式离开过实验室"。这个问题靠自查答不了，得靠交接单和挂载记录：

```bash
# 交接介质清单：确认交接对象是重跑后的完整件，/delivery 目录从未列入
grep -A5 'delivery' /evidence/介质交接单.csv

# 交接期间的挂载记录：/delivery 若从未被挂载，残件在物理上无法被拷出
# 注意 /proc/mounts 是内核的实时视图，进程退出即失效，必须靠采集期抓的快照
grep -c '/delivery' /evidence/mount-snapshot-2024-11-12.log
```

第四条最关键：**介质交接单是外部可核验的凭证**，它比任何一句"我们没有发出过"都管用。而"残件所在目录全程未挂载"这条如果成立，等于从物理上排除了"被拷走"这条路径——**两种证明叠加，复核方就没有追问的立足点了**。

`mount-snapshot` 这类日志得在采集期就抓：挂载信息只存在于 `/proc/mounts` 这个内核视图里，机器一关机就没了，`/proc` 下面也不存在任何持久化的历史。所以"全程未挂载"这句话能不能说出口，取决于采集当天有没有留这一行。

**顺带说一个取证人自己的习惯问题**。这类残件属于"证据的衍生物"，比原件低一个层级，很多人会下意识觉得它不重要、不值得记。但从复核的角度看，**越是"不重要"的痕迹，越要主动交代**——因为复核方不知道它重要不重要，他会按"你没说的东西都可疑"来处理。

主动列出来的那一条，代价是三行日志；没列出来的那一条，代价是整份交付件的清白。**这个不对称是这条纪律的核心理由。**

但 `df` 显示的可用空间里，有一部分是给 root 预留的。本案第一次导出就是在剩余空间看起来还够的情况下失败的，因为 `df` 报的 `Avail` 已经扣掉了保留块，而 `ewfexport` 在写 E01 时还需要额外空间做临时 chunk 缓冲。

判断"够不够"的经验值是：目标卷可用空间至少是 E01 压缩后体积的 1.1 倍。本案 190 GB 的残件说明实际写入了 190 GB，而当时判断的可用空间是 205 GB——看起来有 15 GB 余量，实际却在 40% 处失败，差额来自临时缓冲与文件系统开销。

**更稳的做法是改用分段输出**。`ewfexport` 支持 `-t` 配合分段大小，把结果写成 RAW 的分片，这样每片写完就落盘，中断时损失可控：

```bash
ewfexport -u -f raw -S 2G -t /delivery/part/DigiForensics \
  -l /evidence/DigiForensics-export.log /evidence/DigiForensics.E01
```

**结论**

能证明：残件在生成后 3 分钟内即被安全擦除，从未交付或离开实验室；正式交付件是扩容后重跑产生的、与 E01 内嵌哈希一致的完整镜像。**能证明的是过程可追溯，而不是残件从未存在**。

不能证明：`/delivery` 所在介质在实验室内部是否曾被其他项目访问过——本案的记录只覆盖本项目的时间窗，跨项目的介质使用记录不在本次核对范围内。

**这个案子的真正收获在流程而不在线索**。190 GB 的残件里有多少数据、日志里写的时间是哪一分钟，这些都不影响最终结论——它是一个纯粹关于"过程能不能被说清楚"的案例。而这一类案例在实务中出现频率很高，出错时也不产生任何技术上的警报，所以特别依赖有人愿意按规矩记录。

**残留件这类痕迹还有一个共同特征**：它们的出现总是因为某个外部原因（磁盘满、权限不足、被中断），而这些原因**在事后看起来都很无辜**——正因如此，复核方看到"曾有一个 190 GB 文件"时，第一反应必然是怀疑。主动记录的作用就是把"一次无害的失败"和"一次可疑的删除"区分开，而这两者从文件系统状态上是分不出来的。

**误判对照**

最像的误判是把残件悄悄删掉、不留任何记录。判据有三条：

①"它没被交付过"是一个关于**过程**的断言，而这个断言唯一的支撑就是日志——删除残件并不删除日志，但如果日志里也没提，那这条断言就退化成了无法核验的口头声明；
②文件系统层面会留下痕迹：一个 190 GB 文件的目录项即使被 `rm`，其 inode 的 `ctime` 仍可恢复，而它的 mtime 就在交付前不久，**这个时间点本身就是提问的起点**；
③"删除"与"安全擦除"不是一回事——普通 `rm` 只解除目录项，数据块仍在介质上可恢复，而交接过的磁盘若被回收，对方用 `blkls` 在未分配空间里就能读出那 190 GB 的头部内容。

正确判据是**记录 + 安全擦除 + 用交接单做外部佐证**三者缺一不可：日志说明内部过程，交接单说明外部事实，挂载记录排除物理路径。

按错误判据走的代价：复核方发现文件系统层面存在一个被删除的大文件（时间戳就在交付前），必然追问那次删除是什么；此时若日志空白，解释成本极高，且会牵连整个交付件的清白。

**反过来也有个坑**。如果报告里写了"残件已删除"而没写"已安全擦除"，对方会追问"删除后的数据是否还在介质上"——这个追问本身是合理的，答不上来就又是新的把柄。在涉及敏感数据的场景下，"已删除"和"已安全擦除"是两句话，混用等于给自己制造一个无法回答的问题。

<a id="section-33"></a>

### 5.3 反例：用 VMDK 当交付件

**场景**

某次交付中，实验室直接转出 `DigiForensics.vmdk` 作为交付格式，交付清单上写了它的 SHA-256。接收方用该哈希校验通过，但随后发现无法用他们既有的 EnCase / TSK 流程直接读取，需要额外申请转换，交付周期延长两周。

这条列为反例，是因为它**校验上完全成立，只是格式选错了**——这类错误不会被任何哈希检查发现。

**处置过程**

对照点在于格式承担的三项职责：

```bash
# 交付件应当同时满足：可被通用工具读取 / 自带自验证 / 自带案件元数据
ewfverify -f sha256 /evidence/DigiForensics.E01    # E01：三者兼有
sha256sum /lab/DigiForensics.vmdk                  # VMDK：只有外部哈希
qemu-img info /lab/DigiForensics.vmdk              # VMDK：内部无案件元数据
```

**这三项职责是可以在交付前 5 分钟内验证完的**，而本案漏掉了这一步。做法是找一份接收方现有的交付件清单或工具环境文档，核对其工具链能否打开 E01——现代 TSL、FTK、XMount 都能读 E01，VMDK 需要额外的转换环节。

**更稳妥的做法是提前问接收方要格式要求**。这个电话花 3 分钟，而它能避免本案的两周延误。格式选择不该由"我们实验室有什么工具能导出"来决定——**交付格式的决策权在接收方，不在生产方**。

还有一层本案当时没意识到的考虑：**格式的向后兼容性**。E01 从 EnCase 5 到 EnCase 7 的兼容性一直很好，而 VMDK 的变体（monolithic / split / streamOptimized）之间转换后可能需要修复，QEMU 生成的 VMDK 在某些 VMware 版本里还会提示 UUID 冲突。

这意味着选 E01 不只是"对方能打开"，还包含"对方三年后还能打开"。**交付件的寿命通常比办理它的案件更长**——这个时间尺度在选格式时值得想一想。

**结论**

阴性发现：该 VMDK 在本次交付中**未被受理**，理由是格式不满足接收方的工具要求。哈希一致只能证明字节没变，证明不了格式可用。未覆盖范围是接收方的实际处理结论——本机构无从得知他们最终如何处理这份被退回的文件。

**误判对照**

最容易得出的错误结论是「哈希校验通过就是合格的交付件」。判据有三条：

①VMDK 是虚拟机磁盘格式，设计目标是能被 QEMU/VMware 挂载，不包含 EWF 的 `header` / `table` / `data` 三段结构，因此既无内嵌哈希也无 case metadata——它的自验证能力为零；
②交付件的合格性有**两个彼此独立的维度**：内容正确（哈希可验）与格式可用（对方能打开），本案只验证了前者——前者通过对后者没有任何证明力，两个维度必须分别核对；
③`qemu-img info` 输出的 VMDK 内部只有几何信息（虚拟大小、磁盘大小），**没有任何案件标识字段**——即便对方能打开，也无法从文件本身知道它属于哪起案件。

正确判据是**交付格式必须由接收方的工具链反推确定**，而不是由"本实验室转得出来"决定。判据的落点是：**先问对方用什么工具，再决定转成什么格式**。

按错误判据走的代价是往返两周加一次重新交接，而这类延误在司法交付里有实际期限——更麻烦的是它不留错误痕迹，所有检查都通过，问题只在对方打开时暴露。

这个案例最值得记的一点是：错误发生在决策环节，而不是技术环节。整个转换过程没有出任何错，两份文件的哈希都对，实验室的自检全部通过。问题出在"我们选择交付 VMDK"这个动作上，而那个动作的依据仅仅是"我们转得出来"。

格式选择的正确依据是接收方的能力，而不是生产方的能力。 这句话在任何交付场景里都成立——包括把 E01 交给只装了开源工具的第三方实验室。

**最后一条实用的做法**：把"格式确认"做成一张交付前检查表，贴在实验室的工位上。上面只有三行——

```text
□ 接收方的工具链能否打开我要交付的格式？（问，不是猜）
□ 交付件是否自带可独立验证的完整性信息？（E01 是，RAW/VMDK 否）
□ 若否，我是否附了来源说明与哈希清单？
```

三行全部打勾才允许封装。它防的不是技术错误，而是那种所有自检都通过、唯独对方打不开的错误——这类错误不会在任何本地检查里暴露，只能靠交付前问一句接收方来避免。

这张表后来又加了一行，来源是 5.2 的残件：

```text
□ 交付目录里只有一份正式件？（重名、带后缀备份、截断残件都会混进来）
```

第 4 行针对的不是格式，而是目录状态。哈希校验的对象是"某一个具体文件"，而交付事故里有一类根本不在哈希层面——实验室自己清楚交付的是哪一份，对方收到的是哪一份。

---
<a id="section-34"></a>

## 六、扩展阅读方向

下面四组方向按"你在格式这条路上会撞到什么"组织。


**第一组：前置基础——三块必须先有的规范知识**

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— **本篇的结构对照表的出处**。EWF 段结构、AFF4 的段模型、内置哈希与元数据字段的规范定义在那里，本篇讲的是"怎么用"和"怎么选"，那篇讲的是"它应该长什么样"。要向法庭论证格式的合规性，引用规范而不是引用本篇。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— **本篇第四章 4.3 组的判据来源**。转换前后哈希不相等时，排查顺序（全量比对 → 定位差异偏移 → 判断是丢段还是错位）需要哈希语义基础；"格式内置摘要与外部记录哈希不一致"这类问题的正确处理也在那篇。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— **本篇最想强调的一条：格式不是证据链。** E01 里写满了采集元数据，但那些元数据是**工具写的**，不是**证据本身**。谁在什么时间用什么设备采的、原始检材现在在哪——这些记录在保管链文档里，不在文件里。

**第二组：同层深入——虚拟化格式与工具链**

- [虚拟机仿真](../imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md) —— **VMDK 格式的主要消费者**。稀疏 VMDK 的 backing file 链、快照的文件级真相、"退场方式"三种形态的差异（合并 / 保留 / 丢弃）都在那篇。本篇告诉你怎么把 E01 转成 VMDK，那篇告诉你转完之后怎么用而不弄坏证据。
- [Windows Server 环境仿真](../imaging-mount-simulate/imaging-mount-simulate-windows-server.md) —— VHDX 格式的直接使用场景。域控与 IIS 检材的隔离启动、**为什么必须在差分盘里做而不能碰基础镜像**，方法与理由在那里。
- [Docker 镜像层与 overlay2 解析](../../server/server-docker/server-docker-overlay2.md) —— **另一类"分层格式"的对照**。容器的分层逻辑与 E01 的分段逻辑在概念上相似（都是"段 + 顺序 + 校验"），但语义完全不同：**E01 的分段是存储策略，容器的分层是语义边界**。放在一起看能理解"段"这个抽象的两个方向。

**第三组：工具与规范——交换与可采性**

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 转换动作本身也是一次证据操作，**它有自己的记录要求**：谁转的、用什么工具版本、转换前后的哈希、转换耗时。第五章的"其他转换路径与归档记录"就是这套要求的落地。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— 检材在不同司法辖区、不同机构之间流转时的格式要求。E01 的通用性是它的主要优势，而这份通用性在跨辖区送检时直接影响成本。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— E01 与 AFF4 都内置采集时间字段。这些字段的时间基准（UTC 还是本地）、时区标注是否完整，直接影响它们能否进入时间线。 用 `ewfinfo` 读出来的采集时间要怎么处理，那篇有规范。

**第四组：判据与反例——怎么证明"转换没改数据"

这一组是本篇的结论支撑。**转换是最容易悄悄破坏证据链的动作**：它看起来只是一个技术操作，但它是唯一一个"你在合法授权下主动改写检材副本"的环节，而改写之后的文件很容易被误当成原始检材流转出去。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **E01 的元数据字段是"可以被任何人改写"的一层**。采集时间、工具名称、序列号都在文件头里，而文件头不在哈希覆盖范围的语义之外。"文件头显示采集于 3 月"这句话需要与保管链文档交叉验证。
- [只读挂载与安全接入](../imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— **转换的目的地通常就是挂载**。为什么"加了 `-o ro` 仍然会写盘"、为什么 Sleuth Kit 的不挂载读取是首选，那篇是本篇下游最直接的邻居。
- [取证概念与分类](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md) —— 镜像文件、派生镜像、转换产物在工作流中的分类与可采性差异。"你手上这个文件是原始检材还是派生件"决定了你能不能把它当原始证据提交——这个区分在转换动作之后就变得格外重要。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 格式处理在整条技能链上的位置：它是一个"必须会但不需要精通"的环节，你需要的是知道什么时候该停下来换路径，而不是把每种格式都学透。

**一句话收尾这四组**：第一组给你规范依据（论证格式合规性时引用规范，不引用本篇）；第二组给你格式的下游消费场景（VMDK 仿真、VHDX Windows 容器、overlay2 的分层对照）；第三组给你流转与记录的要求（跨辖区、换手、归档）；第四组给你结论的强度边界（**元数据字段可被改写、转换产物不是原始检材**）。

**说明**：转换本身不改变数据内容——但你必须能证明它没改变。

那个算式（E01 转出 RAW 的哈希 == 采集时记录的原始哈希）是本篇全部方法论的落点。算式对得上，转换是透明的；对不上，你手上就多了一个来源不明的新文件。
<a id="section-35"></a>

## 七、命令速查

```bash
# ===== 环境 =====
sudo apt install ewf-tools qemu-utils xmount

# ===== 查看 E01 元数据 =====
ewfinfo -d iso8601 /evidence/DigiForensics.E01
ewfinfo -m /evidence/DigiForensics.E01        # 仅介质信息
ewfinfo -i /evidence/DigiForensics.E01        # 仅采集信息
ewfinfo -e /evidence/DigiForensics.E01        # 仅读错误信息
ewfinfo -f dfxml /evidence/DigiForensics.E01 # DFXML 输出

# ===== 验证 =====
ewfverify /evidence/DigiForensics.E01         # 以 "success" 为通过

# ===== E01 → RAW =====
ewfexport -u -f raw -t /delivery/DigiForensics \
  -l /evidence/DigiForensics-export.log \
  /evidence/DigiForensics.E01
sha256sum /delivery/DigiForensics.dd         # 与 ewfinfo 的 SHA-256 比对

# ===== RAW → E01 =====
ewfacquire -u -t /evidence/DigiForensics-archived \
  -f encase6 -c deflate:best -d sha256 -S 2G \
  -C "CASE-2026-0142" -E "E-001" \
  -D "由 DigiForensics.dd 转换" -e "勘验员姓名" \
  -l /evidence/convert.log \
  /evidence/DigiForensics.dd
ewfverify /evidence/DigiForensics-archived.E01
md5sum /evidence/DigiForensics.dd              # 与新 E01 内置 MD5 比对

# ===== qemu-img 格式互转 =====
qemu-img convert -f raw -O vmdk  /evidence/DigiForensics.dd /lab/DigiForensics.vmdk
qemu-img convert -f raw -O qcow2 /evidence/DigiForensics.dd /lab/DigiForensics.qcow2
qemu-img convert -f vmdk -O raw  /lab/DigiForensics-s001.vmdk /evidence/from-vmdk.dd
qemu-img info /lab/DigiForensics.qcow2
qemu-img info --backing-chain /lab/DigiForensics.qcow2   # 递归列快照链

# ===== 不落地挂载 =====
ewfmount /evidence/DigiForensics.E01 /mnt/ewf   # 出现 /mnt/ewf/ewf1
xmount --in ewf /evidence/DigiForensics.E01 --out raw /mnt/xmount

# ===== 分段管理 =====
ls -l /evidence/DigiForensics.E0*       # 必须整组拷贝，顺序不可乱
du -sh /evidence/                        # 确认存储开销
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 磁盘镜像与仿真 — 证据文件格式与格式转换」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《证据文件格式与格式转换》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.E01` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
