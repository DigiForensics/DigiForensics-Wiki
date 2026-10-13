---
title: "近似匹配与模糊哈希"
slug: "fundamentals-concepts-fuzzy-hashing"
canonical: "https://www.digiforensics.cn/wiki/fundamentals-concepts-fuzzy-hashing"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
source_type: "wiki-sync"
category: "fundamentals"
space: "取证基础与规范"
node_path: ["取证概念"]
---

# 近似匹配与模糊哈希

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/fundamentals-concepts-fuzzy-hashing)

> **定位**：精确哈希回答「这两份文件是不是同一份」，近似匹配回答「这两份文件是不是同一份东西的两个版本」。它可用于已知样本的变体检索、恶意软件家族归并和文档相似性分析。
>
> **与本板块其他文章的关系**：[哈希与完整性校验](fundamentals-concepts-hashes-and-integrity-verification.md) 讲的是**精确匹配**的单向性与碰撞；本文讲的是**相似性度量**的构造、参数选择与阈值判定。两者共用「哈希」这个词，但解决的是相反的问题：前者要证明两个对象**相同**，后者要证明两个对象**相似**。
>
> **读者前提**：已理解 [取证概念与分类](fundamentals-concepts-digital-forensics-concepts.md) 中的证据类型划分，并能使用命令行做基本的文件提取。

**关键词**：模糊哈希 · ssdeep · sdhash · TLSH · 相似度阈值 · 抗碰撞 · 归并簇 · 变体识别


<a id="section-1"></a>

## 一、概述

[哈希与完整性校验](fundamentals-concepts-hashes-and-integrity-verification.md) 里的 MD5 / SHA-256 有一个前提：它是对完整字节序列的一次性摘要。这带来两个后果，第二个才是近似匹配存在的理由。

第一个后果是任何一个字节不同，结果就完全不同。这不是概率问题，是构造问题——SHA-256 的设计目标就是让任何微小差异引发雪崩效应。真实案件里，一份可疑程序几乎不可能与样本库里的已知样本字节级一致：PE 头 `TimeDateStamp` 自动填入编译时刻，开发机不同则嵌入 `.rdata` 的 PDB 路径不同，`VS_VERSION_INFO` 里的资源时间戳每次打包都变，嵌入 `.rdata` 的 C2 地址字符串换一次即不同，字符串逐字符 XOR 且密钥每次随机会让主体代码全变，在指令间插入 `nop` / `jmp` 让长度与偏移全变，UPX、VMProtect 或自定义壳会把整个 `.text` 段重写，符号剥离则改变调试目录。

用一个字节的不同去比对两份 8 MB 的可执行文件，得到的两个摘要没有任何可用的相似度信息。结论是：只要对方重新构建过一次，精确哈希就完全失效，哪怕改动只有几十字节、只占总体积的 0.01%。

第二个后果是精确哈希无法回答「这份文件像不像我见过的某份」。它是集合成员判定（set membership），不是相似性判定，根本没有「部分匹配」这个概念。

近似匹配（approximate matching，也称 similarity / fuzzy hashing / 模糊哈希）要回答的问题可以分成三类，而它们对算法的要求不同——用同一个阈值处理这三类问题，是实践中最常见的错误来源。

第一类是嵌入检测（is it embedded?），判断目标对象内部是否嵌入了 master 对象的一个片段，典型场景包括在一个 4 GB 的磁盘镜像里找已知样本库中某个 DLL 的任何片段、在一个可疑程序的 `.data` 段里找某个解密 key 或某段 shellcode、在一个 PCAP 的重组流里找已知恶意 payload。

它的特征是「长对象找短片段」：master 对象短、target 对象长，二者的相似度天然偏低，因为相似度函数通常用「共同片段数 / master 片段数」做分母。

第二类是变体识别（are these the same family?），判断两个同量级的对象是不是同一源的不同构建，典型场景是样本库里存着 3 个已知样本而检材里有 40 个可疑文件要归并成变体簇，或者判断一批勒索软件的加密器组件是不是同一个家族。它的特征是「长度相近的完整对象」，这是最主流的用法，也是 ssdeep 表现最好的场景。

第三类是内容定位（where does it appear?），不判断整体相似，而是定位「已知内容的哪个部分出现在目标的哪个位置」，用于恢复被切分的证据：从一个巨型 dump 里切出完整的 PE 文件、从一段 HTTP 响应体里剥出原始文件、从内存里的碎片中重建上传的文件。它的特征是「需要偏移信息，不只要布尔结论」。

必须放在开头讲清楚的是：相似不等于同源。两个文件相似只有三种可能。第一，确实同源，即同一份代码的不同构建，或同一份文档的不同版本。第二，共用的模板或库，即都调用了同一个库、用了同一个 SDK 模板、都是同一份协议实现的变体。第三，算法伪影，即两段内容都很短（比如几百字节到 4 KB 量级），或者都很稀疏（比如大段零字节），使得哈希块天然大量重合。

后两类是系统性的、可预期的，不是异常现象。Python 生成的 Flask 项目、Qt Designer 生成的界面、AutoIt 编译的脚本、.NET 的 `Assembly` 头部这些共用模板，相似度天然在 80 以上，但彼此之间没有源码继承关系；两个 100 字节的配置文件即使内容完全不同，只要分块策略在这么小的对象上退化成「整块一个哈希」，相似度也可能很高；

一个 PE 文件里的 `.bss` 段（全是零字节）、未初始化的堆块、被清零的密码学缓冲区，这些区域对任何分段哈希算法都会产生大量重复块。

所以近似匹配的输出是「相似度分值」，不是「同源判定」。把分值写成结论，是这里唯一会造成冤错的方向性错误，[陷阱 14](#section-39) 专门讨论这个问题。

---

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 相似度函数的三个基本要求

一个可用于取证的相似度函数必须同时满足三条。缺任何一条，它就只适合实验室，不适合办案。

**要求一：对局部修改鲁棒（robustness）**

文件中间插入一段无用字节后，相似度应当基本不变。插入点附近的一两个哈希块会变，其余块不受影响。

反过来，如果算法对全局变化敏感（像精确哈希那样），就没有意义。

**要求二：具备缩放不变性（scalability）**

必须能在数 TB 的镜像上跑完。含义是：

- 分块与哈希过程必须是 O(n) 时间
- 匹配阶段不能是 O(n×m) 的全量两两比较
- 索引结构必须能按分值剪枝，而不是把 1 亿个摘要全部载入内存

**要求三：可复核（verifiability）**

- 分值必须能由**任何第三方**用**公开算法**独立算出
- 算法不能有隐藏参数影响输出
- 相同输入必须得到相同输出（跨版本、跨平台）

第三条是本主题与一般相似性度量最大的区别。一个用机器学习训练出来的向量相似度模型，即使效果很好，也不能用于取证——法庭上无法向对方解释「为什么这两个文件是 87% 相似」。

<a id="section-4"></a>

### 2.2 分段哈希：把文件切成块再逐块哈希

所有主流近似匹配算法都建立在同一个骨架上：**分段哈希 + 块序列比较**。

```
文件字节流
   ↓ ① 按固定步长（rolling window）切出候选块
   ↓ ② 对每个块算校验和 + 弱哈希
   ↓ ③ 相邻块弱哈希满足条件时，记录「边界哈希」= 校验和 + 前一块弱哈希 + 长度
   ↓ ④ 得到一条摘要序列：s1, s2, s3, ... sn（每项 3 字符）
   ↓ ⑤ ssdeep 同时维护两条：块大小 b 的一条，和块大小 2b 的一条
   ↓ ⑥ 比较两个文件的摘要序列，算相似度分值
```

第 ⑤ 步是 ssdeep 的一个容易被忽略的设计：**每条指纹里存了两种块大小的摘要**。官方 FILEFORMAT 写得很明确：

> Each line represents the hash of one file ... we have the blocksize used by the program, the hash for this blocksize **and twice the blocksize**, and the filename.

所以一行 `3:XXXX:YYYY:"file"` 里，`XXXX` 是 3 字节块的摘要序列，`YYYY` 是 6 字节块的摘要序列。比对时 ssdeep 会取两者分值的较大者（见 [2.6](#section-8)）。

这一点直接影响使用：**两个文件的块大小必须相等或成 2 倍关系才能比较**，否则直接判 0 分，编辑距离根本不会计算。这也是嵌入检测场景失效的根本原因（见[陷阱 2](#section-23)）。

关键设计在第 ③ 步：**不是每个滚动窗口都记录，而是只在满足条件时记录**。这个条件由两个参数控制：

- 块大小（block size / spamsum 参数） —— 滚动窗口的字节数
- 触发阈值（hash trigger / piece length） —— 何时认为「块发生变化了」

三款主流算法的参数默认值不同，这是**它们分值不可直接比较**的根本原因（见 [陷阱 3](#section-24)）。

<a id="section-5"></a>

### 2.3 ssdeep：上下文触发分段哈希

ssdeep（Context Triggered Piecewise Hashing, CTPH）由 Jesse Kornblum 在 2006 年 DFRWS 提出，最初是为反垃圾邮件设计的，后来成了事实上的通用标准。

**工作流程：**

1. 以 3 个字节为步长滚动窗口，每个窗口算一个弱哈希（hash）
2. 维护一个「哈希基线窗口」，用 `HASH_PRIME` 构造的 7 个候选哈希字符查表
3. 当滚动哈希命中 7 字符表中的任一字符时，判定为**块边界**
4. 记录该块的摘要：`校验和(2 字节) + 前一块滚动哈希(1 字节) + 长度`
5. 重复直到文件结束

7 字符触发表是 ssdeep 的核心设计。它利用 64 位素数 `HASH_PRIME = 0x01000193` 的性质：插入一字节后，需要滚动约 7 字节才能恢复原有哈希值。

这就让块边界的定位不依赖字节对齐，插入操作最多影响相邻一个块。

**输出格式：**

```
3:<块摘要序列>:<文件名>
```

`3:` 是**块大小**（3 字节块的摘要部分），不是版本号；后面是逐块摘要，每块 2 个十六进制 + 1 个有效载荷字符。块大小**没有任何命令行开关**，但它也不是文件长度的纯函数，而是**长度与内容共同决定**（见[陷阱 2](#section-23)）。

**用不上的场景也有两类：**

- **文件过小会触发警告，且指纹几乎无信息量** —— 源码常量 `SSDEEP_MIN_FILE_SIZE` 为 **4096 字节**，小于此值 ssdeep 会打印 `Did not process files large enough to produce meaningful results` 警告。但这是**警告阈值，不是生成阈值**：实测 0、1、16、32、64 字节的文件**照样生成指纹**（分别得到 `3::`、`3:A`、`3:jyKlY`、`3:sbPhlsTdu`、`3:5UkXaq0TpB4vns9kSJmvbyDxdX`）。真正的问题是块大小被迫退到最小值 3

  需要说清楚"区分度不足"具体指什么。实测 7 个尺寸 × 30 组随机数据对照：

  | 文件大小 | 随机对照分值分布（各 30 组） |
  |---|---|
  | 64 B / 200 B / 1 KB / 3 KB | 全部 0 分 |
  | 4 KB / 5 KB / 8 KB | 全部 0 分 |

  全 0 的原因是 `score_strings()` 有前置门控：两条摘要序列必须存在长度 ≥ `ROLLING_WINDOW` 的公共子串，否则直接返回 0，连编辑距离都不算。小文件的摘要序列太短，门控直接把绝大多数无关配对挡在外面。

  所以小文件的真实风险不是"两个无关文件撞上高分"，而是**这个指标在小文件上几乎没有判别力**——它既不会给你假阳性，也几乎给不出真阳性。实测把两个**完全相同**的 16 字节和 64 字节文件互比，分值是 **100**，因为 `fuzzy_compare()` 先走签名完全相同即返回满分的短路分支（`fuzzy.c:948`）；但 210 组随机数据对照全部是 0 分。也就是说小文件上 ssdeep 只能回答"是否逐字节相同"，无法回答"是否同源"。这种情况下应该换用精确哈希（文件足够小时，SHA-256 的开销可以接受）
- **对加密载荷完全失效** —— 密文的字节分布是均匀随机的，滚动哈希分布也是均匀的，块边界退化为随机切分，两份不同的密文会产生完全不同的块序列。实测同一文件 gzip 后与原文件互比为 0 分，`-1`/`-6`/`-9` 三个压缩级别之间同样是 0 分。压缩包同理，除存储模式（store）外的压缩流是伪随机的

块大小是自适应的：每块独立记录长度，文件任意位置插入不改变后续块的内容，只改变插入点附近。

ssdeep 输出的块大小前缀是**按文件长度自适应**的，不是可配置的"参数组"（实测 1 KB→`24:`、3 KB→`48:`、4 KB→`96:`、10 KB→`192:`、1 MB→`24576:`）。因此同一份代码在不同大小的文件里会得到不同的块大小：

| 前缀 | 块大小 | 适用 | 分值范围 |
|---|---|---|---|
| `3:` | 3 字节 | 默认，最鲁棒 | 0–100 |
| `48:` | 48 字节 | 中等大小文件 | 0–100 |
| `96:` | 96 字节 | 大文件（>1 MB），块数少、速度快 | 0–100 |

跨组比较分值没有意义。`3:abc:file` 与 `48:abc:file` 的 `abc` 不是同一个东西。

<a id="section-6"></a>

### 2.4 sdhash：归一化分段与相似度估计

sdhash 由 Vassil Roussev 开发，设计目标是修正 ssdeep 的一个已知弱点：**块数随文件长度变化，导致分值在不同大小的文件之间不可比**。

**块大小的归一化：**

sdhash 的块大小随文件长度按 2 的幂次缩放：

```
块大小 = 2^ceil(log2(文件长度 / 目标块数))
```

目标块数默认 2048。这意味着：

- 小文件 → 块小 → 分辨率高
- 大文件 → 块大 → 速度快
- 块数大致恒定，因此**分值在不同大小的文件之间可比**

**相似度计算：**

sdhash 不是简单统计「共同的块」，而是估计两个文件的**最长共同子序列的相似度**。它定义：

```
相似度 = 2 × (共同片段估计值) / (文件 A 的片段数 + 文件 B 的片段数)
```

分母是两边片段数之和，**相似度天然对称** —— `sim(A,B) == sim(B,A)`。

需要说明的是，ssdeep 的分值同样是对称的（见 [2.6](#section-8)），**symmetric-difference 这个名字指的是别的东西**——它指的是相似度定义的形态（基于片段的对称差 / 最长共同子序列的比值），不是「ssdeep 不对称、sdhash 对称」。把两者当成对称与不对称的对立是常见误解。

**ddde 扩展：**

sdhash 家族还有一个变体 `ddde`（differentially-differentially-differentially...），它额外输出**差分摘要**——对文件做一阶差分（相邻字节作差）后再算摘要。

这个技巧对**固定间距的字节插入/删除**特别鲁棒：插入等长内容后差分结构基本不变。

怎么挑：

| 目标变异方式 | 推荐算法 |
|---|---|
| 无害字节插入 / 编译差异 / 资源变化 | ssdeep（3:）或 sdhash |
| 固定间距的插入或等长替换 | sdhash 的 ddde 变体 |
| 需要对称分值、跨文件大小可比 | sdhash |
| 大批量初筛、追求速度 | TLSH 或 ssdeep 的 96: 组 |

<a id="section-7"></a>

### 2.5 TLSH：面向文件系统的多线程友好设计

TLSH（Trend Micro Locality Sensitive Hash）设计目标与前两者不同：它不是「最准」，而是「在大文件系统上够快且够用」。

核心机制：Tukey transform + 多桶 LSH

1. 文件按滑动窗口（默认 5 字节，字节数取 2 的幂）计算差分值
2. 对差分值序列做 **Tukey transform**（四分位距归一化），把分布压到可比较的范围
3. 量化成 4 字节桶号序列
4. 对桶号序列做局部敏感哈希（LSH），得到两个 128 位值

两个 128 位值分别是：

- **L value（左侧桶号质心）** —— 整个文件的分布特征
- **R value（右侧桶号质心）** —— 文件局部的分布特征

TLSH 最重要的特性是分值方向与前两者相反：

```
0    →  完全相同（差异距离 0）
100  →  完全不同（差异距离 100）
```

这是 TLSH 最容易踩的坑。网上大量 TLSH 使用示例会给出这样的代码：

```python
# 错误：把 TLSH 距离当成 ssdeep 相似度
if tlsh_diff < 30:
    print("高度相似")
```

正确逻辑应该是距离越小越相似：

```python
# 正确：距离越小越相似
if tlsh_diff <= 30:
    print("相似度高")
```

把两个工具的输出放进同一个「相似度 ≥ 60 就算同源」的规则里，会得到完全相反的结论。详见 [陷阱 1](#section-22) 与 [陷阱 3](#section-24)。

TLSH 的其他特性：

- **多线程友好** —— 桶号计算可并行，这是它在大文件系统上比纯 C 实现更快的关键
- **存在最小长度限制** —— 默认要求输入至少 50 字节，且内容需有一定随机性；全零或纯重复字节无法生成指纹。另有 `-conservative` 选项把下限提到 256 字节
- **版本前缀 `T1`** —— TLSH 5.x 起输出以 `T1` 开头，总长 72 字符（`T1` + 70 位十六进制）；旧版输出为 70 位十六进制。用 `-old` 可强制输出旧格式。新旧指纹可混合读取，但**跨版本的距离计算结果不可直接对比**
- **对加密内容同样失效** —— 密文的差分分布是均匀的，Tukey transform 后没有可提取的结构

<a id="section-8"></a>

### 2.6 相似度分值的计算：编辑距离与块大小自适应

**ssdeep 的分值计算：**

ssdeep 2.15 的分值不是基于字符匹配累计，而是基于两个**摘要块序列**之间的 **Levenshtein 编辑距离**（编辑距离包含插入、删除、替换三种代价，均为 1）。`score_strings()` 的完整流程（`fuzzy.c`）：

```
设 A、B 为两条长度 s1len / s2len 的摘要序列：
1. 前置门控：两序列必须存在长度 >= ROLLING_WINDOW 的公共子串，否则直接返回 0
2. score = edit_distn(A, B)                     // Levenshtein 距离
3. minlen   = min(s1len, s2len)
4. score    = score * SPAMSUM_LENGTH / (s1len + s2len)   // 按长度归一
5. score    = 100 * score / SPAMSUM_LENGTH       // 落到 0–100
6. score    = 100 - score                        // 反向：0=完全不匹配, 100=完全一致
7. 小块长截断：若 blocksize 偏小且 score 超过
   blocksize/MIN_BLOCKSIZE * minlen，则收敛到该上限
```

第 4 步的分母 `s1len + s2len` 是**对称**的，第 2 步的 Levenshtein 距离本身也是**对称**的。

**分值是对称的：**

```
sim(A, B) == sim(B, A)
```

这一点与文档流传的常见说法相反，需要用源码和实测锁定：

| 判据 | 结论 | 证据 |
|---|---|---|
| 分母 | `s1len + s2len`，交换参数不变 | `fuzzy.c:846` |
| 编辑距离 | Levenshtein，对称 | `edit_dist.c` |
| 块大小不等的分支 | 两条分支计算的是同一对摘要 | `fuzzy.c:960-981` |
| 完全一致短路 | 比较双向等值，直接返回 100 | `fuzzy.c:947-951` |
| 实测 | 60 组随机样本（含 60% 强制部分重叠）双向分值完全一致 | 本机 ssdeep 2.15-test |

其中「块大小不等」这一分支值得单独说明，因为它最容易被误读：

```c
// fuzzy.c, block_size1 == block_size2 时：取两个块大小的较大分值
score1 = score_strings(s1b1, s1b1len, s2b1, s2b1len, block_size1);
score2 = score_strings(s1b2, s1b2len, s2b2, s2b2len, block_size1*2);
score  = max(score1, score2);

// block_size1 * 2 == block_size2 时（交换顺序也落到同一分支）
score  = score_strings(s2b1, s2b1len, s1b2, s1b2len, block_size2);
```

第二种情形下，交换两个签名的位置只会让 `block_size1`、`block_size2` 互换，判断条件从 `block_size1 * 2 == block_size2` 变为 `block_size2 * 2 == block_size1`，而实际参与计算的两条摘要（较长块的那条）不变，因此结果一致。

实测样例（4 MB 同源文件 A 与其前 25% 截断件 B，真实包含关系）：

```bash
$ ssdeep -c -x a.ssdeep b.ssdeep
"a.bin","b.bin",69
$ ssdeep -c -x b.ssdeep a.ssdeep
"b.bin","a.bin",69      # 同分
```

**一个必须保留的限定：**

分值对称 ≠ 可以当「相似度百分比」用。ssdeep 的 man page **通篇没有把输出称作 similarity 或 percentage**，它只把这个数字叫 `score`——它既不是概率也不是百分比。它是编辑距离经长度归一后的整数压缩，信息量远低于直觉中的「百分比」。仓库常见的误判是把 60 分写成「60% 相似」。

仓库里另一种错误说法是「长文件在前会系统性压低分值」。实测不成立：

```bash
# 一对文件在 3: 与 96: 下的分值关系不固定
# 实测 ratio=1.1/1.3/1.6/2.0/2.5/3.0/4.0 七组长度比，双向分值全部相同
```

比对时需检查**块大小自适应**带来的不可比性，交换参数顺序不会改变这一限制（详见[陷阱 2](#section-23)）。

<a id="section-9"></a>

### 2.7 文本相似与代码相似

前述都是二进制相似。文本与代码的相似度有专门的方法，结论特征完全不同。

**文本相似（sdtext 等）：**

主流做法是**归一化后分词**：

1. 统一编码、统一换行、去 HTML 标签
2. 分词（中文用分词器，英文按词边界）
3. 去除停用词、可选：词干化
4. 计算 Jaccard 相似度（两个词集合的交集 / 并集）或余弦相似度（词频向量夹角）

Jaccard 相似度的对称性天然成立，且与 ssdeep 不同——它对词序完全不敏感，一篇把所有词打乱重排的文章仍会得到 100 分。

对取证来说这是优点（更能穿透格式变化），对「抄袭检测」场景是缺点（改写但保留词句的文本仍会高分）。

**代码相似：**

代码的相似度有专用工具链，处理的是**结构而非文本**：

- **token 序列比对** —— 去掉空白与注释后做序列比对
- **AST 指纹** —— 把语法树规范化后序列化，对变量名不敏感
- **函数级相似度** —— 用 winnowing 等算法在 token 序列上取指纹，抵抗变量重命名与行号变动

**取证场景的关键差异：**

一个攻击脚本从 Python 2 迁移到 Python 3，或者把 `requests` 换成 `urllib3`，文本相似度会大幅下降，但函数级代码相似度几乎不变。

反过来说，两个功能完全相同的脚本如果由不同作者用不同风格实现，代码相似度会很低，而功能层面它们确实相关。所以代码相似度也不能单独作为同源判据。

<a id="section-10"></a>

### 2.8 参数选择：块大小与块数的相互作用

这是实践中最需要理解、也最少被解释的技术细节。

**块大小的核心权衡：**

| 块越小 | 块越大 |
|---|---|
| 抗局部修改强（插入几字节只影响一个块） | 抗局部修改弱（插入的字节可能落在块内部，整个块变了） |
| 块数多，摘要长 | 块数少，摘要短 |
| 速度快不了（块数多，哈希次数多） | 速度快 |
| **文件太小会退化**（块数不足 7 个时算法无意义） | **文件变大时分辨率下降**（大文件里一个小改动只占一个块，分值变化不显著） |

**块数与相似度的数学关系：**

设文件有 `n` 个块，插入 `k` 字节的无关内容，大约影响 `2k/b` 个块（b 为块大小），相似度下降约：

```
Δsim ≈ 100 × (2k/b) / n
```

代入 `n ≈ 文件长度 / b`：

```
Δsim ≈ 100 × 2k / 文件长度
```

关键结论：相似度下降量与块大小无关，只取决于插入字节数占文件总长度的比例。

这个推导解释了实际观察到的现象：

- 往一个 4 MB 的文件里插入 4 KB 无用字节 → 相似度几乎不变（约 0.2% 变化）
- 往一个 8 KB 的文件里插入 4 KB 无用字节 → 相似度掉到接近 0（50% 变化）

所以用小样本调出来的阈值，不能用于大文件。一批小样本上验证的「80 分算同源」，在一批大文件上会漏掉真正的同源对。

**实践中的参数选择建议：**

| 场景 | 推荐配置 |
|---|---|
| 未知大小的一般样本库 | ssdeep `3:`（默认），全量生成，不分组 |
| 已知文件 > 1 MB | ssdeep `96:` 提速，或 TLSH |
| 需要跨大小文件比分值 | sdhash（块数归一化） |
| 对抗等长插入 | sdhash ddde |
| 内存 dump / 大型文件 | TLSH（多线程）或 sdhash |

关键原则：同一批匹配中，所有对象必须用同一组参数生成指纹。

---

<a id="section-11"></a>

## 三、操作步骤

<a id="section-12"></a>

### 3.1 建立基准库并记录生成参数

基准库（master/reference corpus）是近似的「已知样本库」。建库的质量决定了后续所有结论的上限。

**步骤：**

**① 确定范围**

明确基准库包含什么、不包含什么。范围声明必须写进报告，因为它直接决定阴性结论的效力。

**② 收集样本并记录元数据**

每个样本记录：来源、获取时间、是否官方发布、是否有配套的分析报告。**没有元数据的样本库价值有限** —— 无法判断某次命中是「已知威胁」还是「误报」。

**③ 生成指纹并记录参数**

```bash
# 约定：指纹统一放一个目录（块大小自适应，无需分档）
mkdir -p DigiForensics-corpus/ssdeep
cd DigiForensics-corpus/ssdeep

# 批量生成 ssdeep 指纹
find . -type f -exec ssdeep -b {} + > ../corpus.ssdeep 2>/dev/null
wc -l ../corpus.ssdeep
```

**④ 同时记录精确哈希**

```bash
# 近似匹配不能替代精确匹配，基准库要两套哈希并存
cd DigiForensics-corpus
find . -type f -exec sha256sum {} + > corpus.sha256 2>/dev/null
wc -l corpus.sha256
```

**⑤ 保存参数与工具版本**

```bash
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "tool: $(ssdeep -V 2>&1 | head -1)"
  echo "params: block=3 (default group)"
  echo "samples: $(find . -type f | wc -l)"
  echo "hash: $(sha256sum corpus.ssdeep | cut -d' ' -f1)"
} > corpus.ssdeep.meta
cat corpus.ssdeep.meta
```

`corpus.ssdeep` 自身的 SHA-256 必须在报告里出现 —— 它是整个基准库的身份标识。基准库更新后这个值会变，复核者据此判断「比对用的是哪一版样本库」。

**★ 破坏性提示：** 更新基准库时不要直接覆盖旧文件。每次更新新建带日期或版本号的目录，保留旧版本，否则历史报告的「未发现」结论无法复现。

<a id="section-13"></a>

### 3.2 批量生成目标侧指纹

从检材中提取出待比对的对象。提取本身是独立的技术步骤（见 [文件系统取证总览](../../filesystem/filesystem-ntfs/filesystem-ntfs-filesystem-forensics-overview.md)），这里只强调与近似匹配相关的部分。

**① 提取时保留原始路径信息**

```bash
# 保留相对路径，便于回溯到检材中的位置
cd /Volumes/DigiForensics/mnt/evidence
find ./suspect -type f -size +0 -print0 |
  while IFS= read -r -d '' f; do
    # 路径中的空格与中文原样保留
    printf '%s\0' "$f"
  done > /Volumes/DigiForensics/work/targets.nul
wc -l /Volumes/DigiForensics/work/targets.nul
```

**② 生成指纹**

```bash
cd /Volumes/DigiForensics/work
mkdir -p ssdeep
ssdeep -b $(cat targets.nul | tr '\0' '\
' | tr '\
' ' ') ssdeep/targets.ssdeep 2>/dev/null
```

**更稳的做法是用 `-r` 递归或直接对目录操作**，避免 shell 的参数长度限制与空格处理问题：

```bash
# 递归处理整个提取目录
ssdeep -br /Volumes/DigiForensics/mnt/evidence/suspect \
  > /Volumes/DigiForensics/work/ssdeep/targets.ssdeep 2>/dev/null

# 统计生成了多少条
wc -l /Volumes/DigiForensics/work/ssdeep/targets.ssdeep
```

**③ 统计失败对象**

**这一步不能跳过。** 小于 4096 字节的对象会触发 ssdeep 的"无意义结果"警告，且指纹无判别力——必须单独统计、单独说明：

```bash
# 对比实际文件数与生成的指纹数
echo "文件数:   $(find /Volumes/DigiForensics/mnt/evidence/suspect -type f -size +0 | wc -l)"
echo "指纹数:   $(wc -l < /Volumes/DigiForensics/work/ssdeep/targets.ssdeep)"
echo "过小对象: $(find /Volumes/DigiForensics/mnt/evidence/suspect -type f -size -4096c | wc -l)"
```

两条差额要分开解释：**指纹数少于文件数**，差额来自 0 字节文件等完全无法处理的；**而 4096 字节以下的对象虽然会生成指纹，但摘要序列过短、公共子串门控几乎总是挡住比对，正负两侧都得不到结论**，这部分应改用精确哈希（SHA-256）或人工检视。**这两个缺口都必须写进报告**，因为它们决定了阴性结论的覆盖范围。

<a id="section-14"></a>

### 3.3 匹配并人工复核阈值边界

**① 匹配并落盘**

```bash
# ★ 必须加 -c：ssdeep 默认输出是自然语言行（"... matches ... (99)"），
#   不是制表符分隔。不加 -c，下游 awk -F',' 会取不到任何列，阈值过滤静默失效。
#   -c 的 CSV 列序为：$1=文件A, $2=文件B, $3=分值  ← 分值在第 3 列
#
# ★ 关于「双向」：ssdeep -x 的分值是对称的（见 2.6），两个方向跑出来的是
#   同一批配对、同一批分值，只是左右两列对调。跑两遍不会多找出任何匹配。

ssdeep -c -x DigiForensics-corpus/ssdeep/corpus.ssdeep \
        /Volumes/DigiForensics/work/ssdeep/targets.ssdeep \
  > /Volumes/DigiForensics/work/match.txt
```

**★ 关于「双向匹配」的更正：**

仓库里此前把"两个方向分值不同、只做单向会漏检"写成了一条陷阱。**这个说法是错的，而且方向正好相反。**

`-x` 并不是"A 组去比 B 组"，而是**把命令行上的所有签名文件合并成一个集合，然后在整个集合内部做全两两比对**：

```c
// main.cpp — -x 模式下，每个命令行参数都被 load 进同一个 all_files
while (count < goal) {
  if (MODE(mode_sigcompare))
    match_load(s, argv[count]);        // ← 两个文件进的是同一个容器
  ...
}
// 随后对整个 all_files 做两两比对
if (MODE(mode_sigcompare))
  s->mode |= mode_match_pretty;
find_matches_in_known(s);
```

实测证据（两组各自内部同源、跨组完全不相关）：

```bash
$ ssdeep -c -x E1.ssdeep E2.ssdeep
"a1.bin","a2.bin",99        # 组内配对
"b1.bin","b2.bin",99        # 组内配对
                             # 跨组 4 个交叉组合一个都没输出
```

这带来两个直接后果：

1. **跨组不相关的样本不会出现在输出里**。它们分值为 0，而默认阈值是 0、`match_compare` 判定用的是 `score > s->threshold` 严格大于，0 分被过滤掉了。
2. **"只做基准库 vs 检材"这种语义并不存在**。`-x` 一定会把基准库内部、检材内部的配对一并算进来。

所以正确的做法是**自己按文件名把结果切开**，而不是靠两个方向去夹逼：

```bash
# 按文件名区分两组，把混在一起的输出重新归类
# 前提：生成指纹时用 -b 保留可区分的文件名，known- 前缀为基准库，target- 为检材
awk -F',' '{
  gsub(/"/, "")
  if (NF < 3) next          # ssdeep 的 CSV 行之间夹空行，不过滤会产出空记录
  if ($1 == "" || $2 == "") next
  a = $1; b = $2; s = $3 + 0
  aBase = (a ~ /^known-/);  bBase = (b ~ /^known-/)
  aTgt  = (a ~ /^target-/); bTgt  = (b ~ /^target-/)
  if (aBase && bTgt)      print "CROSS\t" s "\t" a "\t" b
  else if (bBase && aTgt) print "CROSS\t" s "\t" b "\t" a
  else                    print "INTRA\t" s "\t" a "\t" b
}' /Volumes/DigiForensics/work/match.txt > /Volumes/DigiForensics/work/classified.tsv

echo "--- 跨组匹配（真正要的）---"
awk -F'\t' '$1=="CROSS"' /Volumes/DigiForensics/work/classified.tsv | wc -l
echo "--- 组内配对（会被误当成跨组命中，必须剔除）---"
awk -F'\t' '$1=="INTRA"' /Volumes/DigiForensics/work/classified.tsv | wc -l
```

**输出字段约定**（下游脚本都依赖这个顺序，不要随手调换）：

| 字段 | 含义 |
|---|---|
| `$1` | `CROSS` 或 `INTRA` |
| `$2` | 分值 |
| `$3` | 基准库侧文件名（`known-*`） |
| `$4` | 检材侧文件名（`target-*`） |

`INTRA` 行的 `$3`/`$4` 是同组的两个文件名，语义不同但列数一致，所以可以用同一个 awk 解析。

**② 按分值分档，不设单一阈值**

```bash
# 按分值区间分档输出，而不是只取 >60 的行
# CSV 列序：$1=文件A, $2=文件B, $3=分值（分值在第 3 列）
# 用 \t 转义而不是字面制表符，避免脚本里混入不可见字符
awk -F',' '{
  gsub(/"/, "")
  if (NF < 3) next          # ssdeep 的 CSV 行之间夹空行，不过滤会产出空记录
  s = $3 + 0
  if (s >= 90)      print "极强\t" s "\t" $2 " <=> " $1
  else if (s >= 70) print "强\t"   s "\t" $2 " <=> " $1
  else if (s >= 40) print "中等\t" s "\t" $2 " <=> " $1
  else if (s > 0)   print "弱\t"   s "\t" $2 " <=> " $1
}' /Volumes/DigiForensics/work/match.txt > /Volumes/DigiForensics/work/match-banded.txt

echo "--- 各档数量 ---"
awk -F'\t' '{print $1}' /Volumes/DigiForensics/work/match-banded.txt | sort | uniq -c
```

**③ 人工复核阈值边界附近的样本**

分值在阈值上下 10 分以内的匹配，必须逐个人工看。 理由：

- 算法分不出「同源变体」和「共用模板」
- 分值高但两者属于不同厂商的同类工具，是常见的误报源
- 分值低但确实是同源的情况也存在（如只改了导入表的样本）

复核方法：

```bash
# 提取两个文件的头部特征做对照
for f in target.bin corpus.bin; do
  echo "=== $f ==="
  file "$f"
  sha256sum "$f"
done

# 看 PE 的节区与导入表差异
objdump -x target.bin 2>/dev/null | head -40
objdump -x corpus.bin 2>/dev/null | head -40
```

**④ 记录复核结论**

不要只保留「是/否」，要记录**判断依据**：

| 匹配对 | 分值 | 复核发现 | 结论 |
|---|---|---|---|
| `suspicious-a.bin` ↔ `known-cve-2024-xxxx.bin` | 87 | 导入表结构一致，编译时间戳相差 3 天，C2 域名同注册人 | 同源变体 |
| `installer-x.exe` ↔ `nsis-installer-template.bin` | 74 | 均为 NSIS 打包，无业务逻辑重叠 | 共用工具，非同源 |
| `macro-x.docm` ↔ `macro-y.docm` | 81 | 宏代码结构一致，变量名与注释不同 | 同源变体（人工确认） |

<a id="section-15"></a>

### 3.4 归并成变体簇并做交叉验证

单个匹配没有意义，真正要交付的是「哪些对象属于同一变体簇」。

**① 初始归并（基于跨组匹配）**

```bash
# 只取 CROSS（跨组）行，避免把组内配对当成"命中基准库"
# classified.tsv 字段：$1=类型(CROSS/INTRA) $2=分值 $3=基准库侧文件 $4=检材侧文件
# 按检材对象聚合：key 是检材侧文件名($4)，best 记录它的最高分
awk -F'\t' '$1=="CROSS" {
  key = $4
  if (($2+0) > best[key]) { best[key] = $2+0; src[key] = $3 }
}
END { for (k in best) print best[k] "\t" src[k] "\t" k }' \
  /Volumes/DigiForensics/work/classified.tsv |
  sort -t'	' -k1,1nr > /Volumes/DigiForensics/work/best-hit.txt

head -20 /Volumes/DigiForensics/work/best-hit.txt
```

**② 目标侧内部两两比较（发现基准库里没有的新变体）**

这一步是发现「全新变体簇」的必要途径。

```bash
cd /Volumes/DigiForensics/work
# 对目标库自身做两两比较（小批量可行，大批量需分块）
# 注意：-x 是把两个参数合并后全两两比对，所以同一个文件传两次
# 就是纯自比。这正是这里想要的效果。
ssdeep -c -x ssdeep/targets.ssdeep ssdeep/targets.ssdeep \
  > self-match.txt 2>/dev/null

# 提取高分的对。同名条目会被 ssdeep 的 pretty 模式自动跳过，
# 但仍要用 $1 != $2 兜住，并去掉 CSV 引号
awk -F',' '{
  gsub(/"/, "")
  if (NF < 3) next          # ssdeep 的 CSV 行之间夹空行，不过滤会产出空记录
  if ($1 != $2 && $3+0 >= 60) print $3+0 "\t" $2 " <=> " $1
}' self-match.txt | sort -rn > internal-pairs.txt

wc -l internal-pairs.txt
```

**★ 关于签名文件里的表头行：不要删它。**

`ssdeep -br` 生成指纹时会先输出一行 CSV 表头：

```
ssdeep,1.1--blocksize:hash:hash,filename
```

这行看着像杂质，实际是**签名文件格式的一部分**。删掉它之后 `-x` 会直接报 `Invalid file header.` 并一个匹配都出不来（实测确认）。

`Bad hash in line N` 则来自另一处：签名文件里除首行表头外的每一行都必须是合法签名。当把**多个各自带表头的签名文件用 `cat` 拼接**起来时，第二个文件的那行表头会被当成签名解析，于是报 `Bad hash in line N`（实测：两个 2 文件签名拼接后报 `Bad hash in line 4`）。**正确做法是把 `-x` 的多个参数各自作为独立文件传入，不要手工拼接。**

保留单个签名文件的表头即可，它不影响比对结果。

正确做法是原样保留：

```bash
ssdeep -br ./suspect/ 2>/dev/null > targets.ssdeep   # 表头照留
```

**★ 大批量警告：** 目标库有 n 个对象时，两两比较是 O(n²) 次比对。1000 个对象是 50 万次，10 万个对象是 50 亿次 —— 后者不可行。超过数千个对象时必须用 LSH 索引（如 `tlsh` 的库模式）先做候选筛选，再对候选做精确比对。

**★ 大批量警告：** 目标库有 n 个对象时，两两比较是 O(n²) 次比对。1000 个对象是 50 万次，10 万个对象是 50 亿次 —— 后者不可行。超过数千个对象时必须用 LSH 索引（如 `tlsh` 的库模式）先做候选筛选，再对候选做精确比对。

**③ 传递闭包归并**

关系相似**不满足传递性**，这是本主题最容易被忽略的算法性质：

```
sim(A, C) = 85
sim(A, B) = 40
sim(B, C) = 90
```

`sim(A,B)` 很低，但 A 与 C、C 与 B 都强相关。如果只按「与基准库的直接命中」归并，B 会成为一个孤立簇，但实际上 A、B、C 是同一个家族。

正确的做法是构建相似图后求连通分量：

```python
import collections

# 输入：所有 >= 阈值的配对
pairs = []
with open('/Volumes/DigiForensics/work/internal-pairs.txt', encoding='utf-8') as f:
    for line in f:
        score, rest = line.split('\	', 1)
        a, b = rest.split(' <=> ')
        pairs.append((a.strip(), b.strip(), int(score)))

THRESHOLD = 60
parent = {}

def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x

def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb

for a, b, s in pairs:
    if s >= THRESHOLD:
        union(a, b)

clusters = collections.defaultdict(list)
for x in list(parent):
    clusters[find(x)].append(x)

# 输出簇，只保留有 2 个及以上成员的
for root, members in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
    if len(members) < 2:
        continue
    print(f'簇（{len(members)} 个成员）:')
    for m in sorted(members):
        print(f'  {m}')
    print()
```

**但要记录一个重要事实**：连通分量不等于「所有成员都与中心高相似」。一个 50 个对象的簇可能是「25 个强相关对象 + 25 个通过单条弱边挂上去的对象」。报告里应当给出**簇内的分值分布**（最大、最小、中位数），而不只是簇的大小。

<a id="section-16"></a>

### 3.5 加密压缩样本的预处理

**近似匹配对加密与压缩内容完全无效**，这是原理决定的，不是工具缺陷。

原因很直接：密文与压缩流的字节分布是均匀随机的，其滚动哈希的分布也是均匀的。块边界退化为随机切分，两段不同的密文会产生完全不同的块序列。

```bash
# 验证：原文件与它的 gzip 副本之间分值为 0
# 注意 -x 只吃签名文件，必须先各自生成指纹，不能直接传原始文件
ssdeep -b target.bin        > target.ssdeep
ssdeep -b target-copy.bin.gz > target-gz.ssdeep

# 默认阈值是 0，判定用 score > threshold 严格大于，0 分会被过滤掉
# 所以必须加 -a 才能把 0 分这条记录显示出来
ssdeep -c -x -a target.ssdeep target-gz.ssdeep
# 实测输出：
#   "target.bin","target-copy.bin.gz",0
#   "target-copy.bin.gz","target.bin",0
```

同一个文件用不同压缩级别（`-1` / `-6` / `-9`）压缩后互比，同样是 0 分。

**注意"没有输出"不等于"分值是 0"。** 默认阈值过滤会把 0 分记录整条吞掉，此时命令行是静默成功的（退出码 0），很容易被误读成"没跑出结果"。要区分这两种情况，加 `-a`。

**正确做法是解压 / 解密后再比对：**

```bash
# ZIP / RAR
mkdir -p unpacked
unzip -o -d unpacked target.zip 2>/dev/null
unrar x -o+ target.rar unpacked/ 2>/dev/null
7z x -o unpacked -y target.7z 2>/dev/null

# gzip
gunzip -k target.gz

# 7z（注意：某些 7z 格式的密码可从命令行传入，但应避免在 shell 历史里留下密码）
# 密码用交互式输入，不要写进命令行

# 生成解压后内容的指纹
ssdeep -br unpacked/ > unpacked.ssdeep 2>/dev/null
wc -l unpacked.ssdeep
```

**★ 关键提醒：解压出的内容不能直接回写检材。** 全部在分析工作目录下操作，且记录解压清单（哪些文件、来自哪个压缩包、解压时间）。解压动作本身要在保管链中留痕。

**同名不同内容的情况要特别注意：**

```bash
# 一个压缩包里有多层同名文件
find unpacked -name '*.doc' -exec sha256sum {} \; | sort
```

同名不同哈希的文档是解压包分析的常规发现，必须在报告中区分，不能按文件名归并。

<a id="section-17"></a>

### 3.6 内存与磁盘中的模糊搜索

在内存 dump 和原始磁盘镜像中做近似匹配，是近似匹配对取证最有价值的方向 —— 因为这类证据里的对象**通常没有被文件系统正常管理**，无法用文件名定向提取。

**① 在内存 dump 中搜已知样本的片段**

```bash
# 先算出已知样本的指纹
ssdeep -b DigiForensics-corpus/known-malware.bin

# 在 dump 中递归搜索（-r 递归）
# 注意：-t 是"匹配阈值"，不是"最小文件大小"。生成模式下它对哪些文件出指纹没有影响，
# 实测 ssdeep -br -t 2048 与 ssdeep -br 对同一目录输出完全一致（含 500 字节文件）。
# 要跳过小文件，得靠外部过滤。
ssdeep -br /Volumes/DigiForensics/mem/DigiForensics-mem.raw \
  > mem-hits-all.ssdeep 2>/dev/null

# 按原始文件大小过滤（签名文件里只有块大小前缀，拿不到原文件长度，
# 所以必须在生成指纹时用文件列表过滤，而不是事后对签名行过滤）
find /Volumes/DigiForensics/work/mem-carve -type f -size +4096c \
  -print0 | xargs -0 ssdeep -b - > mem-hits.ssdeep 2>/dev/null
head -20 mem-hits.ssdeep
```

**`-t` 不是最小文件大小，不能用它过滤。** 它只是比对展示阈值，生成模式下不影响哪些文件出指纹（实测 `ssdeep -br -t 2048` 与 `ssdeep -br` 对同一目录输出完全一致，含 500 字节文件）。要跳过小文件，只有两条路：用文件列表在生成侧过滤，或在比对后把 4096 字节以下的配对单独归类为覆盖缺口。

**② 从内存中先提取再比对（更可控）**

直接对 raw 扫描产生的结果难以复核。更稳的做法是先提取候选对象：

```bash
# 用 foremost 或 bulk_extractor 从内存中提取可识别格式的对象
bulk_extractor -o /Volumes/DigiForensics/work/mem-carve \
  -S none /Volumes/DigiForensics/mem/DigiForensics-mem.raw 2>/dev/null

ls /Volumes/DigiForensics/work/mem-carve/ | head

# 对提取出的对象做近似匹配
ssdeep -br /Volumes/DigiForensics/work/mem-carve/ \
  > mem-carve.ssdeep 2>/dev/null
```

**③ 提取结果必须做交叉验证**

从内存雕刻出的对象，**不能直接作为「检材中存在该恶意软件」的结论**。理由：

- 雕刻有误报（相邻内容被误判为文件头）
- 内存中的片段可能是解码过程中的中间态，不是落盘内容

验证手段：

```bash
# 验证对象是否结构完整
file /Volumes/DigiForensics/work/mem-carve/xxxxx.exe
python3 -c "
import pefile, sys
pe = pefile.PE('/Volumes/DigiForensics/work/mem-carve/xxxxx.exe')
print('节区数:', len(pe.sections))
print('入口点:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('导入 DLL:', [e.dll.decode() for e in pe.DIRECTORY_ENTRY_IMPORT])
" 2>&1 | head -20

# 与已知样本做精确哈希比对，确认是否完全一致
sha256sum /Volumes/DigiForensics/work/mem-carve/xxxxx.exe
grep -i 'xxxxx.exe' DigiForensics-corpus/corpus.sha256
```

<a id="section-18"></a>

### 3.7 在 PCAP 与网络载荷上做近似匹配

网络载荷的近似匹配在威胁狩猎中有独特价值：它能回答「这台主机下载过的内容里，有没有和已知样本相似的」。完整的流量取证流程见 [网络流量与 PCAP 取证](../../memory/memory-network/memory-network-pcap.md)，这里只讲近似匹配的部分。

**① 导出 HTTP 对象**

```bash
mkdir -p /Volumes/DigiForensics/work/pcap-http
# 目录必须先存在，否则 tshark 会静默产出 0 个文件
tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  --export-objects http,/Volumes/DigiForensics/work/pcap-http 2>/dev/null

ls /Volumes/DigiForensics/work/pcap-http/ | wc -l
```

**② 排除明显的噪声类型**

```bash
# 图片、CSS、字体等不该参与比对
find /Volumes/DigiForensics/work/pcap-http -type f \
  \( -name '*.jpg' -o -name '*.png' -o -name '*.gif' -o -name '*.css' -o -name '*.woff*' \) \
  -delete
```

**③ 生成指纹并比对**

```bash
ssdeep -br /Volumes/DigiForensics/work/pcap-http/ \
  > pcap-http.ssdeep 2>/dev/null

tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  -T fields -e http.host -e http.request.uri -e http.content_length 2>/dev/null \
  | sort -u > pcap-http-index.txt

# 合并指纹与请求索引，按 URL 归档
ssdeep -x DigiForensics-corpus/ssdeep/corpus.ssdeep pcap-http.ssdeep 2>/dev/null \
  | awk -F',' '$3+0 > 0 {print $3 "\	" $2}' | sort -rn > pcap-matches.txt

head -20 pcap-matches.txt
```

**④ 把命中对象回连到会话**

```bash
# 找出承载该对象的 TCP 流
OBJ=$(awk -F',' '$3+0>=60 {print $2; exit}' pcap-matches.txt)
echo "命中对象: $OBJ"
sha256sum "$OBJ"

tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  -Y "http.file_data" -T fields -e tcp.stream -e ip.src -e ip.dst \
    -e http.host -e http.request.full_uri 2>/dev/null | head -20
```

**★ 载荷被截断的陷阱：** PCAP 抓包若设置了 snaplen，HTTP 响应体是不完整的，导出的对象**必然与服务器上的原文件不同**，近似匹配的分值会偏低。因此流量侧的近似匹配结果**只能表述为「检材中未发现与样本相似的载荷」**，不能表述为「未下载过该文件」。

<a id="section-19"></a>

### 3.8 把结果写进报告的表述方式

近似匹配的结论有很强的表述约束。照抄下面的模板：

**✅ 正确的表述方式：**

> 在 `DigiForensics-corpus`（2026-08 构建，312 个样本，基准库 SHA-256 `3f9a…c71e`）与检材 `DigiForensics.dd` 中提取的 4,182 个可执行对象之间，使用 ssdeep（默认块大小）进行跨组比对，**发现 7 个对象与基准库样本的相似度不低于 60**（分值区间 61–92）。其中 4 个经导入表结构比对确认为同源变体，3 个经复核判定为共用打包工具导致的相似，不计入同源结论。

**❌ 错误的表述方式：**

> 检材中存在 7 个已知病毒。

差异在哪：

| 项 | 正确 | 错误 |
|---|---|---|
| 结论主体 | 相似度分值 | 病毒（定性） |
| 基准库状态 | 明确版本与哈希 | 未提 |
| 覆盖范围 | 4,182 个对象，明确列出 | 未提 |
| 失败对象 | 说明有小文件无法生成指纹 | 未提 |
| 不一致项 | 明确排除 3 个误报 | 未提 |
| 阴性结论 | 必须限定范围 | 绝对化 |

**阴性结论的模板：**

> 在上述 4,182 个对象与 312 个基准样本的范围内，使用 ssdeep（默认块大小）进行跨组比对，**未发现相似度高于 30 的匹配**。**未覆盖范围**：（1）1,847 个小于 4096 字节的对象落在最低块大小上、摘要序列过短，正负两侧均无结论；（2）加密容器内的内容未做解密后比对；（3）已完成 TLS 握手但载荷为密文的会话无法比对。

---

<a id="section-20"></a>

## 四、常见陷阱

<a id="section-21"></a>

### 4.1 度量与元数据

<a id="section-22"></a>

#### 陷阱 1：把 ssdeep 的相似度当成概率

**现象**

拿到一组匹配结果，报告里写「该文件与已知样本的相似度为 87，因此有 87% 的概率是该样本的变体」。或者更常见的：把 87 分和 92 分的对象都列为「高风险」，理由是「都很接近 90」。

**原因**

ssdeep 的分值是一个由块匹配统计公式算出的整数。它的输入是「块序列的相似程度」，输出被压缩到 0–100。

它不是概率，也不是任何后验概率的估计。

原因有三层：

1. **分值不随先验变化。** 相似度是纯粹的技术度量，不含「这个样本在真实世界中有多常见」这类信息。基准库里放 1000 个无关样本，任何一个都会产生大量 10–30 分的匹配 —— 这些低分完全不说明风险。
2. **分值不随证据强度变化。** 两份文件相似度 90，可能是「只差编译时间戳的同一份程序」，也可能是「同一份代码生成器产出的两个不同项目」。这两种情况的风险等级天差地别，但分值是一样的。
3. **「接近 90」不是分档依据。** 分值分布是离散且非线性的，89 与 92 可能落在完全不同的簇里。真实项目中常见的情况是：某家族内部分值集中在 91–95，另一家族集中在 62–68，中间 70–90 几乎是空的。用「接近 90」这种直觉分档会同时犯错。

**影响**

这是本主题里唯一会造成冤错的方向性错误。把相似度当概率会导致：

- 把共用打包工具的正常软件（NSIS、Inno Setup、PyInstaller 产物）报成恶意
- 把真实同源但分值不高的变体（改动较大）漏掉
- 在庭审中被对方质询「87% 的概率是什么意思，依据是什么」时无法回答 —— 分值本来就不是概率

**核查**

分值只用于分档排序，不用于定性。定性依据是技术特征的逐项比对：

```bash
# 分值是筛选依据
ssdeep -c -x corpus.ssdeep target.ssdeep | awk -F',' '$3+0>=60' | sort -t',' -k3,3nr

# 定性依据是结构比对（以下为示意，需按实际格式调整）
python3 - <<'PY'
import pefile

def profile(path):
    pe = pefile.PE(path)
    return {
        'sections': sorted(s.Name.rstrip(b'\x00').decode(errors='replace')
                           for s in pe.sections),
        'imports': sorted(e.dll.decode().lower()
                          for e in pe.DIRECTORY_ENTRY_IMPORT),
        'entry': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
    }

a = profile('suspect.bin')
b = profile('known-sample.bin')
for k in a:
    same = a[k] == b[k]
    print(f'{k:12} {"一致" if same else "不同"}  {a[k] if same else ""}')
    if not same:
        print(f'             样本: {b[k]}')
PY
```

**在报告里，相似度必须始终带上「分值」二字**，写「相似度分值为 87」，不要写「相似度 87%」或「87% 的可能」。

<a id="section-23"></a>

#### 陷阱 2：把块大小当成可配置参数，制造出根本不存在的"参数组" ★

**现象**

按「先按 3: 算一遍、再按 96: 算一遍」建立两套指纹文件（`ssdeep-3/`、`ssdeep-96/`），在报告里把两套分值混在一张表排序。另一份报告直接写"在 ssdeep 96: 参数组下比对"，但没有任何命令能产生这个结果。

**原因**

**块大小不是可配置参数。** 它由 ssdeep 按文件长度自动选择，命令行没有任何开关能改它：

```bash
$ ssdeep -h
-t - Only displays matches above the given threshold
# 全篇没有 block size / blocksize 相关选项
```

实测同一份内容，无论加什么选项，块大小都不变：

```bash
$ ssdeep -b file.bin | sed -n 2p | cut -d: -f1
24576
$ ssdeep -b -t 2048 file.bin | sed -n 2p | cut -d: -f1
24576        # 相同
```

所以 `ssdeep -br ./suspect/ > fingerprint/ssdeep/...` 和 `> fingerprint/ssdeep-96/...` 这两条命令会产出**完全相同的文件内容**——目录名是假的，参数组不存在。

**真正在变的是文件长度区间**（全随机内容实测）：

| 文件大小 | 块大小 |
|---|---|
| 100 KB | 3072 |
| 200–400 KB | 6144 |
| 500–800 KB | 12288 |
| 900 KB 以上 | 24576 |

块大小随长度跳档，所以**两个文件能不能比较，取决于它们的块大小档位是否相同**。实测：

```bash
# t1 = 997 KB (bs=24576)，t4 = 742 KB (bs=12288)
$ ssdeep -c -x -a t1.ssdeep t4.ssdeep
"t1.bin","t4.bin",0        # 内容完全不同，0 分属正常
```

注意这个 0 分在这里**不能归因于块大小**：12288 × 2 = 24576，两者恰成 2 倍关系，属于可比配对。它得 0 分是因为内容确实毫无关系。

`fuzzy_compare()` 的前置检查要求块大小**相等或成 2 倍关系**，否则直接返回 0，连编辑距离都不算（`fuzzy.c:904-906`）：

```c
if (block_size1 != block_size2 &&
    (block_size1 > ULONG_MAX / 2 || block_size1*2 != block_size2) &&
    (block_size1 % 2 == 1 || block_size1 / 2 != block_size2)) {
  return 0;
}
```

**块大小不是 2 倍关系时的实测对照**（文件内容完全嵌套，A 是 B 的前缀）：

| 配对 | 块大小 | 关系 | 实测分值 |
|---|---|---|---|
| `A.bin`（768 KB）↔ `B.bin`（900 KB） | 12288 ↔ 12288 | 相等 | 94 |
| `C.bin`（100 KB）↔ `D.bin`（200 KB） | 3072 ↔ 6144 | **恰好 2 倍** | 61 |
| `A.bin`（768 KB）↔ `D.bin`（200 KB） | 12288 ↔ 6144 | **非 2 倍** | **0** |

同样有包含关系，第三行因为 12288 与 6144 既不相等也不成 2 倍而直接判 0。这类"同源却 0 分"的情况在变体归并里非常常见，必须在阴性结论里单独交代。

**块大小也不只是长度的函数。** 源码里它分两步选出（`fuzzy.c:402-408`）：

```c
/* Initial blocksize guess. */
while ((uint_least64_t)FUZZY_BS(bi) * SPAMSUM_LENGTH < self->total_size)
  ++bi;
/* Adapt blocksize guess to actual digest length. */
if (bi >= self->bhend)
  bi = self->bhend - 1;
while (bi > self->bhstart && self->bh[bi].dindex < SPAMSUM_LENGTH / 2)
  --bi;
```

先按长度（`FUZZY_BS(index) = 3 << index`，`FUZZY_BS × 64 ≥ 文件长度`）选一个下界档，再**按实际摘要条数向下退档**：`dindex`（去重后的摘要数量）小于 `SPAMSUM_LENGTH/2`（即 32）就降一档。所以**内容高度重复或低熵的文件会被退到远低于其长度对应的档位**。

实测（全部为 921600 字节，尺寸完全相同）：

| 内容类型 | 实测块大小 |
|---|---|
| 全随机字节 | 24576（20 次中 16 次）／12288（20 次中 4 次） |
| `0xAA…` 半段 + `0x00…` 半段 | **3** |
| 8 种符号组成的 4 KB 随机块循环 | **1536** |

第一行说明即使长度与内容类型都相同，块大小仍会在 12288 和 24576 之间浮动。**推论：不能用文件大小反推块大小，也不能假设同长度文件必然同档**——只能从输出的 `块大小:hash:hash` 前缀读出实际值。这也解释了为什么跨组比对时"看起来同档"的两组样本会有相当比例的配对落进不可比区间。

**核查**

正确做法是把**文件长度与块大小**记进元数据，而不是编一个不存在的参数组名：

```bash
mkdir -p fingerprint/ssdeep

# 生成一次即可，不存在多档
ssdeep -br ./suspect/ > fingerprint/ssdeep/targets.ssdeep 2>/dev/null
ssdeep -br ./corpus/  > fingerprint/ssdeep/corpus.ssdeep  2>/dev/null
```

**可比性预检**（比对前先跑一遍，把"结构上不可比"从"0 分"里区分出来）：

```bash
# 步骤 1：从**两个**签名文件建 文件名 -> 块大小 映射
#   签名行格式： <bs>:<hash1>:<hash2>,"filename"
#   注意 -x 是把所有签名加载进同一集合做全两两比对，
#   所以配对的两端可能分别来自两个签名文件，映射必须合并。
cat fingerprint/ssdeep/corpus.ssdeep fingerprint/ssdeep/targets.ssdeep \
  | awk 'NR>1 && /^[0-9]+:/ { split($0, C, ":"); split($0, P, "\""); print P[length(P)-1] "\t" C[1] }' \
  | sort -u > /tmp/bs-map.tsv

# 步骤 2：跑比对（-a 保留 0 分记录）
ssdeep -c -x -a fingerprint/ssdeep/corpus.ssdeep \
              fingerprint/ssdeep/targets.ssdeep 2>/dev/null \
  | grep ',' > /tmp/pairs.csv

# 步骤 3：判定每对是否结构可比
awk '
  NR==FNR { split($0, F, "\t"); bs[F[1]] = F[2]; next }
  { gsub(/"/, "")
    if ($0 !~ /,/) next
    split($0, C, ",")
    if (length(C) < 3) next
    b1 = bs[C[1]] + 0; b2 = bs[C[2]] + 0
    if (b1 == 0 || b2 == 0)        { nobs++ }
    else if (b1 == b2 || b1*2 == b2 || b2*2 == b1) { ok++ }
    else { bad++
           if (bad <= 5) printf "  不可比: %s <=> %s (bs %d vs %d)\n", C[1], C[2], b1, b2 }
  }
  END { printf "可比: %d, 结构不可比: %d, 查不到块大小: %d\n", ok+0, bad+0, nobs+0 }' \
  /tmp/bs-map.tsv /tmp/pairs.csv
```

实测（6 个基准样本 + 6 个检材对象，块大小 3072 / 6144 / 12288 / 24576 混合，共 132 对）：

```
  不可比: known-2.bin <=> known-4.bin (bs 6144 vs 12288)
  ...
可比: 86, 结构不可比: 46, 查不到块大小: 0
```

近三分之一的配对结构上不可比——这说明**"两个文件分值为 0"这个结果里混着两种完全不同的原因**，必须分开统计。

这个脚本的"查不到块大小"计数同时是一个自检项：只要映射只从一个签名文件建立，跨组配对就会大量落到这一栏。实测对照（同样 6+6 样本、同样 132 对）：

| 映射来源 | 可比 | 结构不可比 | 查不到块大小 |
|---|---|---|---|
| 只读 `corpus.ssdeep` | 18 | 12 | **102** |
| 合并两个签名文件 | 86 | 46 | **0** |

只读一个文件时 102 条被静默丢进"查不到"栏，预检等于失效。**任何时候"查不到块大小"不为 0，都说明映射没覆盖全，应当先修脚本再读结论。**
在报告的每个匹配表里记录的是**工具版本与长度区间**，不是参数组：

| 对象 A | 长度 | 对象 B | 长度 | 块大小 | 分值 | 工具版本 |
|---|---|---|---|---|---|---|
| `suspect-a.bin` | 780 KB | `known-cve-2024-xxxx.bin` | 812 KB | 12288 | 87 | ssdeep 2.15 |
| `installer-x.exe` | 1.2 MB | `nsis-installer-template.bin` | 1.4 MB | 24576 | 74 | ssdeep 2.15 |

这两行的块大小相同，可比分值横向比较。**真正不可比的是块大小既不相等也不成 2 倍的配对**（如 12288 ↔ 6144），那种配对连编辑距离都不算、直接返回 0，必须单独剔出统计——详见上面的实测对照表。发现这种情况应当补齐长度或改用对长度不敏感的算法。

<a id="section-24"></a>

#### 陷阱 3：默认阈值在不同场景下相差极大

**现象**

照搬网上的示例，用「分值 ≥ 60 算同源」这一条规则处理所有场景。样本比对效果不错，于是把它用在文档抄袭检测上，发现几乎全是误报；或者用在小型配置文件上，发现什么都匹配不上。

**原因**

60 这个数字来自 ssdeep 论文里的一组实验条件，它只在那个条件下成立。

那个实验是：约 3 MB 量级的 PE 文件、编译产生的变体、已知无害的对照样本库。阈值 60 是在这个特定分布上平衡漏报与误报的结果，换到别的分布上就失效了。

**不同场景下，合理的阈值差异极大：**

| 场景 | 特征 | 合理阈值 | 原因 |
|---|---|---|---|
| PE 变体归并 | 大文件、少量无关字节变化 | 40–60 | 文件大，插入比例小，分值天然高 |
| 文档版本比对 | 中等大小、文本有重写 | 70–85 | 改写幅度大，共享段落少 |
| 配置文件 | 小文件、格式敏感 | 85–95 | 字段顺序、空白变化就掉分 |
| 已知样本嵌入检测 | 长对象找短片段 | **单独设定** | 分母是短对象，分值天然低 |
| 小文本 | < 1 KB | 90 以上或直接不用 | 分块退化为整块，噪声极高 |

**特别是嵌入检测这个场景**，ssdeep 往往不是给低分，而是**直接给 0**：

```bash
# 一个 8 MB 的主文件，和从中截取的 4 KB 片段
ssdeep -b big.bin   > big.ssdeep
ssdeep -b embed.bin > embed.ssdeep
ssdeep -c -x -a big.ssdeep embed.ssdeep
# 实测输出：
#   "big.bin","embed.bin",0
#   "embed.bin","big.bin",0
```

原因有两层：

1. **块大小根本不匹配。** 8 MB 文件的自适应块大小是 24576，4 KB 文件是 48。`fuzzy_compare()` 开头有个前置检查：两个块大小必须相等，或者恰好是 2 倍关系，否则**直接返回 0**，连编辑距离都不算：

   ```c
   if (block_size1 != block_size2 &&
       (block_size1 > ULONG_MAX / 2 || block_size1*2 != block_size2) &&
       (block_size1 % 2 == 1 || block_size1 / 2 != block_size2)) {
     return 0;
   }
   ```

2. **即使块大小能对上，分母也吃长文件。** 分母是两条摘要序列长度之和，短片段会被大文件的块数稀释。

所以嵌入检测不要指望调阈值解决。可行路径是换工具：

- **TLSH**：设计上就适合"长文件里找已知小片段"，且提供 `locus`（匹配位置）与 `file_type` 判定。
- **sdhash / ssdeep 前置分块**：先用 carving 把候选片段切到与主文件相近的量级，再比对。
- **块级遍历比对**：把长文件按固定窗口切开，逐窗口与短文件比对。

注意"0 分"和"没输出"是两回事——默认阈值过滤会让 0 分记录整条消失，命令行仍然退出码 0。判断时加 `-a`。

**影响**

- 阈值过低 → 大量误报，分析员被迫逐个人工复核，工作量剧增，最终把工具输出全部忽略
- 阈值过高 → **漏检**，真正的同源变体被放过。这个方向更危险，因为它不会产生任何异常信号 —— 分析员根本不知道漏了什么

**核查**

阈值必须用检材自身的数据校准，而不是照搬文献。

校准方法（用一批已知结果的对象做 ROC 分析）：

```bash
# 准备两组：
#   正样本 = 已知同源的变体对（从既往报告中提取，有人工确认结论）
#   负样本 = 已知无关的对象对
python3 - <<'PY'
import subprocess

def pairs(fa, fb, path):
    out = subprocess.run(['ssdeep', '-c', '-x', fa, fb],
                         capture_output=True, text=True).stdout
    r = []
    for line in out.splitlines():
        p = line.split('\	')
        if len(p) == 3:
            r.append((p[1], p[2], int(p[3])))
    return r

pos = pairs('corpus.ssdeep', 'corpus.ssdeep', 'pos.txt')   # 已知同源
neg = pairs('corpus.ssdebug', 'corpus.ssdeep', 'neg.txt')  # 已知无关

# 扫描候选阈值，找漏报/误报平衡点
for th in range(20, 96, 5):
    tp = sum(1 for _, _, s in pos if s >= th)
    fp = sum(1 for _, _, s in neg if s >= th)
    fn = len(pos) - tp
    print(f'阈值 {th:3d}  漏报 {fn:3d}  误报 {fp:3d}  '
          f'命中率 {tp/max(1,len(pos))*100:5.1f}%')
PY
```

**在报告里写明阈值是怎么来的**：是文献推荐值、还是用本案检材校准的、校准用的正负样本各多少个。这是复核者判断结论可信度的关键信息。

<a id="section-25"></a>

### 4.2 样本与预处理

<a id="section-26"></a>

#### 陷阱 4：把压缩包和解压后的文件混在一个库里比对

**现象**

把检材里的所有 `.zip` / `.rar` / `.7z` 文件和它们的解压内容一起生成指纹，放进同一个指纹库，然后互相匹配。结果发现压缩包与它自己解压出来的某个文件「相似度 43」，认为压缩包内含该文件。

**原因**

近似匹配对压缩流无效，对解压后的内容有效。这两者的指纹不能放在一个库里。

压缩流（DEFLATE、LZMA 等）的字节分布是均匀随机的，滚动哈希的分布也是均匀的。块边界退化为随机切分。于是：

- 同一个文件压缩两次（即使参数完全相同）—— 严格模式下结果相同，但通用压缩器通常带时间戳，**结果就不同**
- 同一文件用不同压缩级别压缩 —— 分值接近 0
- 压缩包与解压内容 —— 分值通常 20–45，纯粹是噪声

**这个 20–45 的区间是危险的**。它落进很多组织「中等相似」的判读区间，很容易被解读成「弱关联」。

同时，混库还会造成一个更隐蔽的问题：**同一个对象在库里有两份记录**（压缩包一份、解压后一份），归并时产生重复计数。

**影响**

- 产生大量无意义的「弱关联」，污染簇结构
- 一个变体簇因为「压缩包 + 解压内容 + 另一个无关压缩包」的错误连接而被错误合并
- 报告中的「共发现 N 个关联对象」被虚增

**核查**

指纹库按「内容形态」分目录，解压后的对象单独成库。

```bash
# 1) 只对未压缩的可识别文件生成指纹
mkdir -p fingerprint/raw
find ./suspect -type f \
  ! -name '*.zip' ! -name '*.rar' ! -name '*.7z' \
  ! -name '*.gz' ! -name '*.bz2' ! -name '*.xz' \
  -exec ssdeep -b {} + >> fingerprint/raw/targets.ssdeep 2>/dev/null

# 2) 解压到独立目录，独立成库
mkdir -p unpacked fingerprint/unpacked
find ./suspect -type f \( -name '*.zip' -o -name '*.rar' -o -name '*.7z' \) \
  -exec sh -c 'unzip -o -d unpacked "$1" 2>/dev/null || 7z x -o unpacked -y "$1" >/dev/null 2>&1' _ {} \;

ssdeep -br unpacked/ > fingerprint/unpacked/targets.ssdeep 2>/dev/null

# 3) 匹配时只在同库内进行
ssdeep -x fingerprint/raw/corpus.ssdeep    fingerprint/raw/targets.ssdeep
ssdeep -x fingerprint/unpacked/corpus.ssdeep fingerprint/unpacked/targets.ssdeep
```

**★ 解压动作要留痕。** 解压是不可逆的证据处理动作（会覆盖同名文件），必须在工作目录进行、记录解压清单（来源压缩包的哈希、目标路径、解压时间），并在保管链中体现。

<a id="section-27"></a>

#### 陷阱 5：忽略 PE 头部的导入表差异

**现象**

某份文件与已知恶意样本的 ssdeep 分值只有 61，落在「强匹配」区间，但因为「分值不够高」没有进一步分析。后来发现这是一个**分段下载的木马加载器**，恶意主体在第二阶段从网络拉取，头部本身与样本差异较大。

**原因**

导入表（Import Table）是 PE 恶意代码分类最可靠的特征之一，而分块哈希对它不敏感。

原因是分块哈希处理的是**字节流**，它不区分代码与数据。导入表在 PE 里的位置（Import Directory 通常在 `.idata` 节区）与代码段（`.text`）不连续，分块时往往整块落入同一个块，其内容变化只影响一个块的分值。

更关键的是，加载器类恶意软件本来就不实现恶意逻辑。 它的导入表通常只有最少的几个 API：

```
kernel32.dll:  LoadLibraryA, GetProcAddress, VirtualAlloc, CreateProcessA
ws2_32.dll:    connect, send, recv
```

而它真正调用的 WinHTTP/WinInet/Crypt32 API 是在运行时动态解析的。这份「干净」的导入表与任何正常程序的相似度都不高。

**反过来**，两份功能完全相同但由不同工具链编译的加载器，可能有很高的分值——因为它们的启动代码骨架（解压循环、API 解析循环、错误处理）几乎一样。

**影响**

- 把加载器与主程序分开归并，丢失「二者属于同一攻击链」的关键关联
- 归并簇被切碎，样本数量被低估，影响案件规模的认定

**核查**

分值用于筛选，导入表与节区用于定性。分值不足以定性时，结构比对必须做。

```python
import pefile, hashlib

def profile(path):
    pe = pefile.PE(path)
    imports = set()
    stomp = set()
    for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        dll = e.dll.decode().lower()
        for imp in e.imports:
            name = imp.name.decode().lower() if imp.name else f'ord{imp.ordinal}'
            imports.add(f'{dll}!{name}')
    return {
        'md5': hashlib.md5(open(path, 'rb').read()).hexdigest(),
        'entry': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'sections': {s.Name.rstrip(b'\x00').decode(errors='replace'):
                     (hex(s.VirtualAddress), hex(s.SizeOfRawData), hex(s.Characteristics))
                     for s in pe.sections},
        'imports': imports,
    }

a, b = profile('suspect.bin'), profile('known.bin')

print("导入 API 交集:", len(a['imports'] & b['imports']))
print("仅 A 有:", sorted(a['imports'] - b['imports']))
print("仅 B 有:", sorted(b['imports'] - a['imports']))
```

**三个高价值的判定信号：**

| 信号 | 含义 |
|---|---|
| 导入 API 交集 > 80% 且绝对数量 > 15 | 强同源信号，远比 ssdeep 分值可靠 |
| 节区名与 `VirtualAddress` + `Characteristics` 完全一致 | 同一份源码同一套构建脚本的特征 |
| `AddressOfEntryPoint` 相同或相差固定偏移 | 入口点骨架一致，常见于同源加载器 |

**反过来，导入表差异大不证明不同源** —— 打包器和链接顺序就能改变导入顺序与合并方式。

<a id="section-28"></a>

#### 陷阱 6：把已知样本库当成「干净基线」

**现象**

报告里写「与 1,842 个已知恶意样本比对，未发现相似对象」，据此得出「检材中的这些可执行文件不属于已知威胁」。后续复核者发现，样本库里混入了大量正常工具的样本（因为某次批量下载时没筛选）。

**原因**

「已知样本库」和「恶意样本库」是两个完全不同的概念，混用会让阴性结论彻底失效。

样本库的实际构成往往很复杂：

- 公开样本库（VirusTotal 导出、各类 feeds）**混有良性文件** —— 大量被误报的历史样本
- 厂商共享的样本里**混有被误报的良性文件**
- 自己收集的样本可能**混入分析过程中被污染的文件**
- 样本库可能包含**同一文件的多个哈希**（同一文件不同打包），导致某些模式被过度代表

更根本的问题是：**样本库只包含「已经被人发现过的」东西。** 新出现的变体、同一作者的新工具、针对特定目标定制的版本，都必然不在库中。

**影响**

这是**阴性结论被推翻**的最常见原因。后果比阳性误报更严重：

- 报告的「未发现已知威胁」被认定不成立，整份报告的可信度受质疑
- 已经据此做出的处置决定（如解除隔离、认定为无恶意）需要回滚
- 若涉及诉讼，「未发现」类结论一旦被推翻，会直接影响出证方专业性评价

**核查**

样本库必须有明确的构建记录与来源分类，报告必须声明库的覆盖性质。

构建记录：

```bash
{
  echo "build_date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "total: $(find . -type f | wc -l)"
  echo "hash: $(find . -type f -exec sha256sum {} + | sort -k2 | sha256sum | cut -d' ' -f1)"
} > corpus.meta

# 去重检查：同一文件是否有多个哈希记录
find . -type f -exec sha256sum {} + | awk '{print $1}' | sort | uniq -d | head
```

**报告中的表述必须包含库的定性：**

> 比对基准库 `DigiForensics-corpus` v2026-08，共 312 个文件，来源为公开 feeds 与厂商共享，**未经有效性复核，其中可能含误报样本**。该库仅覆盖已被公开报告的样本，不包含未被发现的变体。

关键是要用「本库范围内未发现」，而不是「未发现」。 后者在法律与技术上都不成立 —— 未知样本不可能在库中。

<a id="section-29"></a>

### 4.3 匹配与归并

<a id="section-30"></a>

#### 陷阱 7：只看 ssdeep 报告的那一行

**现象**

`ssdeep -x corpus.ssdeep target.ssdeep` 的输出直接粘贴到报告里，说「共 3 条匹配」。分析员没有注意输出的实际列含义，也没有意识到这条命令会产出**全两两配对**。

**原因**

`-x` 把**两个签名文件里的所有签名加载进同一个集合**（源码 `match.cpp` 里统一的 `all_files`），然后对该集合做全两两比较。所以：

- 输出行数是**配对数**，不是对象数，也不是匹配关系数；
- 输出里**包含自比**（文件与自身配对恒为 100 分）；
- 不存在"每个对象只保留一个最佳匹配"这回事。

实测：两个各含 2 个对象的签名文件，共 4 个对象，输出 **12 对**（含 4 对自比），不是 2 对，更不是 4 对。

输出格式是三列制表符分隔：

```
<分值>\	<文件1>\	<文件2>
```

用 `-c` 时改为逗号分隔的 CSV，**列序为 `$1=文件A`、`$2=文件B`、`$3=分值`**，且行与行之间可能出现空行。**默认输出是自然语言行，必须加 `-c` 才是逗号分隔的 CSV**，否则下游按列解析会全部落空。

于是：

```bash
# 输出（列序：文件A, 文件B, 分值）
"targets/suspect-a.bin","corpus/known-1.bin",0
"targets/suspect-b.bin","corpus/known-2.bin",87
"targets/suspect-c.bin","corpus/known-3.bin",0
```

**分值为 0 的行表示"两者不相似"，但 0 分至少有两种成因**：内容确实无关，或块大小结构上不可比（见[陷阱 2](#section-23)）。直接把所有 0 分当成"已排除"会丢掉后者这一整类覆盖缺口。

**影响**

- 报告里的「N 条匹配」被误读为「N 对文件有关联」，实际是 N 条**配对记录**，其中可能含自比和成片 0 分
- 自比（100 分）混进结果，拉高命中数量，必须先剔除
- 一个对象与多个样本相似（**这本身是重要发现**，说明基准库里有同源样本或该对象是「通用工具」）在逐条粘贴时被淹没
- 列顺序读反，导致报告里「未知文件」与「已知样本」的角色颠倒
- 不加 `-a` 时默认为阈值 0、判定用 `score > threshold`，**0 分记录不会显示**；这会让"全量配对"变成"仅非零配对"，两种口径的条数完全不同，报告里必须写明用的是哪一种

**核查**

解析输出时明确列语义，并把分值为 0 的行单独统计。

```bash
# 分离有效匹配与无匹配（-c 输出列序：$1=文件A  $2=文件B  $3=分值）
awk -F',' 'NF>=3 && $3+0 > 0 {print > "matched.txt"; next}
           NF>=3            {print > "unmatched.txt"}' \
  /Volumes/DigiForensics/work/match-A.txt

echo "有效匹配: $(wc -l < matched.txt)"
echo "无匹配:   $(wc -l < unmatched.txt)"
echo "---"
# matched.txt 的列语义：$1=文件A  $2=文件B  $3=分值
column -t -s, matched.txt
```

**要拿到全量配对，用 `-x` 加 `-a` 显式显示 0 分记录后自行筛选：**

```bash
# -r 递归处理目录；-a 显示全部分值（默认阈值 0 且判定为 score > 0，0 分不显示）
ssdeep -c -x -a /Volumes/DigiForensics/work/ssdeep/targets.ssdeep \
  | awk -F',' 'NF>=3 {gsub(/"/,""); print $3 "\t" $1 " <=> " $2}' | sort -rn
```

**不要用 `-k` 代替 `-x`。** `-k`（Match signatures in FILES against signatures in file）在实测中会吃掉后续参数：`ssdeep -k corpus.ssdeep targets.ssdeep` 无输出且退出码 0，`-a`、`-c` 一并被当成文件名报 `No such file or directory`。要显式取全量配对，路径是 `-x -a`。

**多个高相似命中时，这本身是结论：**

| 情形 | 含义 |
|---|---|
| 与 1 个样本高相似 | 常见，该样本的变体 |
| 与多个样本都 >80 且这些样本在库中互不相似 | 可能是**通用框架产物**（PyInstaller、.NET 混淆工具、通用壳） |
| 与多个样本都 >80 且这些样本在库中彼此也高相似 | 样本库中含同源重复，可在报告中合并计数 |

<a id="section-31"></a>

#### 陷阱 8：把 0 分当成「已排除」

**现象**

某文件的匹配结果全是 0 分，报告里写「与基准库全部样本无相似性，排除其关联性」。后来发现该文件是一个 **AES 加密后的配置文件**，或者是一个 **加壳的二进制**。

**原因**

分值为 0 的原因不止一个，而只有一个代表「确实不相似」。

分值为 0 的完整原因清单：

| 原因 | 含义 | 能否得出「不相似」 |
|---|---|---|
| 内容确实不同 | 真的不相似 | ✅ 可以 |
| 内容是加密数据 | 无法比对 | ❌ 不可以 |
| 内容是压缩流 | 无法比对 | ❌ 不可以 |
| 文件小于 4096 字节 | 无判别力（正负两侧都无结论） | ❌ 不可以 |
| 文件已损坏 / 截断 | 只能比对部分内容 | ❌ 不可以 |
| 内容是已知的编码/序列化格式 | 字节分布均匀 | ⚠️ 存疑 |

**其中「加密」是最需要警惕的一种**，因为它在案件中并不罕见——勒索软件的加密配置、远控工具的加密通信配置、被刻意加固的商业软件都符合这个特征。

**影响**

- **把「无法检查」写成「已排除」是虚假阴性结论**，在性质上比漏检更严重
- 报告的「未发现」一旦被重新解读为「检查过且无关」，后续处置决定全部需要回溯

**核查**

对分值为 0 的对象，先判定原因，再决定能不能写「不相似」。

```bash
#!/usr/bin/env bash
# 对无匹配的对象做原因分类
OBJECT="$1"
echo "=== $OBJECT ==="
file "$OBJECT"

# 1) 熵值检测：>7.5 基本可判定为加密或压缩
python3 - "$OBJECT" <<'PY'
import math, sys, collections
data = open(sys.argv[1], 'rb').read()
if not data:
    print("空文件 —— 未生成指纹"); sys.exit()
freq = collections.Counter(data)
ent = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
print(f"文件大小: {len(data)} 字节")
print(f"香农熵:   {ent:.3f} bit/byte")
if ent > 7.9:
    print("  → 熵值极高，几乎确定是加密数据或压缩流，**近似匹配无结论**")
elif ent > 7.5:
    print("  → 熵值偏高，可能是加密数据或已压缩，**结论需谨慎**")
elif ent < 4.0:
    print("  → 熵值偏低，内容重复度高，可能是结构化数据或未填充的缓冲区")
else:
    print("  → 熵值正常，内容可参与近似匹配")
if len(data) < 64:
    print(f"  → 文件仅 {len(data)} 字节，低于 ssdeep 警告阈值 4096 字节，**摘要序列过短、无判别力，匹配结果不采信**")
PY

# 2) 检查是否有对应的解密产物可比对
ls -la "${OBJECT%.bin}.dec" "${OBJECT%.dat}.plain" 2>/dev/null \
  || echo "  → 未找到解密产物，此对象**未获得可比对内容**"
```

**报告中的正确表述：**

> 检材中的 1,847 个对象与基准库的相似度分值均为 0。其中 1,203 个经熵值检测判定为加密或压缩内容（熵值 > 7.9），**不构成相似性否定依据**；412 个文件大小小于 4096 字节，虽生成指纹但无判别力，**匹配结果不采信**；232 个为正常的可执行文件，**可判定为与本库范围内样本无相似**。

「未获得可比对内容」和「已比对且不相似」是两件事，报告里必须分开写。

<a id="section-32"></a>

#### 陷阱 9：簇的传递性被忽略

**现象**

案例中提取出 4,182 个可疑程序，其中 40 个确认属于同一家族。做法是「取每个对象与基准库的最高分值，按基准样本分组」，结果那 40 个被分成了 6 组，其中 4 组各只有 1–2 个成员。报告写「至少存在 6 个不同变体族」。

**原因**

关系相似不满足传递性，而基于「与基准库的直接命中」的归并方式隐含了传递性假设。

具体机制：某个变体如果与基准库中的任何样本都只有中等相似（比如 45 分，低于 60 的归并阈值），它就会被判为「新变体」而单独成组，尽管它与其他两个高相似对象实际同源。

```
实际关系：
  known-sample-A  ←87→  variant-1
  known-sample-A  ←89→  variant-2
  variant-1       ←43→  variant-2     ← 这一对低于阈值，但通过 A 连通
  variant-2       ←91→  variant-3
```

按直接命中归并：`variant-2`（对 A 89）和 `variant-3`（对 A 91）都归到 A 组，`variant-1` 也归到 A 组（87）。看起来都对。

但换成这样的数据：

```
  known-sample-B  ←62→  variant-X
  known-sample-B  ←48→  variant-Y
  variant-X       ←66→  variant-Y
```

按 60 阈值：`variant-Y` 对 B 只有 48，**会被判为不相关而排除**；但 `variant-X` 与 `variant-Y` 有 66，它们应该同组。而如果 `variant-X` 因为对 B 是 62 被纳入，归并结果就出现了逻辑不一致。

**影响**

- **变体数量被高估**（把一个家族拆成多个）→ 案件规模认定偏大
- **变体数量被低估**（把不同家族合并）→ 遗漏同源关系，可能放过关联事件
- 归并簇内部结构失真，无法回答「这些变体之间是什么关系」

**核查**

构建相似图后求连通分量，用传递闭包归并，同时保留簇内的边信息。

```python
import collections, subprocess

THRESHOLD = 60
MIN_STRONG = 40     # 传递闭包允许的最低边权

# 1) 收集所有配对（含目标库内部）
edges = []
out = subprocess.run(
    ['ssdeep', '-c', '-xr', 'fingerprint/ssdeep/targets.ssdeep'],
    capture_output=True, text=True).stdout
for line in out.splitlines():
    p = line.split('\	')
    if len(p) == 3 and int(p[0]) >= MIN_STRONG and p[1] != p[2]:
        edges.append((p[1], p[2], int(p[0])))

# 2) 并查集
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb: parent[ra] = rb

for a, b, s in edges:
    union(a, b)

# 3) 归簇并保留簇内边，用于后续评估簇质量
clusters = collections.defaultdict(set)
for x in list(parent):
    clusters[find(x)].add(x)

strong = collections.defaultdict(list)
for a, b, s in edges:
    if s >= THRESHOLD:
        ra, rb = find(a), find(b)
        if ra == rb:
            strong[ra].append((a, b, s))

print(f"共 {len(clusters)} 个连通分量（其中单成员簇 {sum(1 for v in clusters.values() if len(v)==1)} 个）\
")
for root, members in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
    if len(members) < 2: continue
    es = strong.get(root, [])
    scores = [s for _, _, s in es] or [0]
    print(f"簇（{len(members)} 成员，强边 {len(es)} 条，"
          f"分值 {min(scores)}–{max(scores)}）")
    for m in sorted(members): print(f"  {m}")
    print()
```

**归并结果的呈现方式很重要。** 不要只写「一个 43 成员的簇」，而要给出：

- 簇内**强边数**（≥ 阈值的边）—— 边少说明成员之间联系松散
- 簇内**分值范围**（最小–最大）—— 范围大说明簇内异质性高
- 稀疏的成员列表 —— 哪些成员只有一条弱边连入

这三项让复核者能判断归并结果是否可靠。

<a id="section-33"></a>

#### 陷阱 10：把 `-x` 当成"A 组比 B 组"，组内配对污染跨组结论

**现象**

报告里写「检材中未发现与基准库相似的对象」，但复核时发现检材里有对象 A 与基准库里的对象 B 确实相关。更麻烦的是，另一份报告把检材内部两个同源变体的高分配对当成了"命中基准库"，写进了命中清单。

**原因**

两条独立的误解叠在一起：

1. **`-x` 不做跨组比对，它做的是集合内全两两比对。** 命令行上的所有签名文件被 `match_load()` 加载进同一个 `all_files`，随后对整个集合两两比对（`main.cpp` → `find_matches_in_known`）。所以 `-x corpus.ssdeep targets.ssdeep` 的输出里既有跨组配对，也有 corpus 内部、targets 内部的配对。

2. **分值是对称的，跑两个方向不会多找出任何东西。** 分母是 `s1len + s2len`、编辑距离本身对称（详见 [2.6](#section-8)）。所谓"长文件在前会压低分值""只做单向会漏检"都不成立。实测 60 组随机样本双向分值完全一致。

```bash
# 决定性验证：两组各自内部同源、跨组完全不相关
$ ssdeep -c -x E1.ssdeep E2.ssdeep
"a1.bin","a2.bin",99        # 组内配对 —— 本该被当成跨组命中
"b1.bin","b2.bin",99        # 组内配对
                             # 跨组 4 个交叉组合一个都没输出
```

**影响**

这是**假阳性 + 假阴性同时发生**的错误，而且两个方向都不会报错：

- 假阳性：组内配对被误记为"与基准库匹配"。
- 假阴性：如果用 `-t` 抬高阈值来压制组内噪声，跨组那些本来就只有中等分值的真匹配会被一起砍掉。

**核查**

正确的流程是**跑一次 `-x`，然后按文件名把结果切开**：

```bash
# 前提：生成指纹时用 -b 保留可区分的文件名
#   known-<hash>.bin  = 基准库
#   target-<hash>.bin = 检材
ssdeep -c -x fingerprint/known.ssdeep fingerprint/targets.ssdeep \
  | awk -F',' '{
      gsub(/"/, "")
      if (NF < 3) next          # ssdeep 的 CSV 行之间夹空行，不过滤会产出空记录
      if ($1 == "" || $2 == "") next
      a=$1; b=$2; s=$3+0
      aB=(a ~ /^known-/);  bB=(b ~ /^known-/)
      aT=(a ~ /^target-/); bT=(b ~ /^target-/)
      if (aB && bT)      print "CROSS\t" s "\t" b "\t" a
      else if (bB && aT) print "CROSS\t" s "\t" a "\t" b
      else               print "INTRA\t" s "\t" a "\t" b
    }' > /Volumes/DigiForensics/work/classified.tsv

echo "跨组: $(awk -F'\t' '$1=="CROSS"' /Volumes/DigiForensics/work/classified.tsv | wc -l)"
echo "组内: $(awk -F'\t' '$1=="INTRA"' /Volumes/DigiForensics/work/classified.tsv | wc -l)"
```

**自查口径：**

- 报告里的"命中基准库 N 个对象"这个 N，必须来自 `CROSS` 行，不能是 `-x` 的原始输出行数。
- `INTRA` 行的数量应当**单独记录**。如果它异常大（比如远大于 CROSS），说明检材侧本身就有大量重复/变体，这在阴性结论里同样是要交代的事实。
- **不需要**为"防漏检"而把两个参数位置对调再跑一遍——分值对称，第二遍给不出新信息。

**在报告的方法描述里写明「`-x` 为集合内全两两比对，跨组结论经文件名归类后统计」**，这是阴性结论成立的前提条件之一。

<a id="section-34"></a>

### 4.4 工具链与可复核性

<a id="section-35"></a>

#### 陷阱 11：未记录工具版本

**现象**

三个月后复核，检材与基准库都在，但无法复现当初的匹配结果。重新跑一遍，得到的簇结构与三个月前的报告不同。

**原因**

近似匹配工具的输出不保证跨版本兼容，且默认参数可能变化。

具体的兼容性问题：

| 变化 | 影响 |
|---|---|
| 默认块大小改变 | 分值整体变化，旧指纹不可用 |
| 触发阈值算法修改 | 块边界位置改变，摘要序列完全不同 |
| 输出格式改变 | 旧指纹文件无法被新版解析 |
| 最小文件大小提高 | 部分小文件不再生成指纹 |
| 浮点/整数计算精度变化 | 边界情况下的分值可能差 1 |

ssdeep 2.13 → 2.14 → 2.15 之间就有输出格式与参数的调整。TLSH 的大版本变化（3.x → 4.x）直接改变了哈希值的含义，**旧版本生成的指纹完全不能与新版本比较**。

**影响**

- **结论无法复现**，这在证据提交场景下是严重的
- 复核者只能选择相信或不相信，无法独立验证
- 若已进入诉讼程序，可能导致证据的可采性质疑

**核查**

工具版本与参数是取证结论元数据的强制组成部分，与哈希值同级。

```bash
#!/usr/bin/env bash
# generate_fingerprints.sh —— 指纹生成与元数据记录一体化
set -euo pipefail

TARGET_DIR="$1"
OUT_DIR="$2"
BLOCK="${3:-3}"

mkdir -p "$OUT_DIR"
cd "$TARGET_DIR"

# 记录工具版本（三种主流工具都要记）
{
  echo "=== 工具版本 ==="
  echo "ssdeep: $(ssdeep -V 2>&1 | tr '\
' ' ')"
  echo "tlsh:   $(tlsh --version 2>&1 | head -1 || echo 'not installed')"
  echo "python: $(python3 --version 2>&1)"
  echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host:   $(uname -srm)"
  echo "block:  $BLOCK"
} > "$OUT_DIR/metadata.txt"

# 生成指纹
ssdeep -br . > "$OUT_DIR/fingerprints.ssdeep" 2>/dev/null

# 记录指纹文件自身的哈希
{
  echo ""
  echo "=== 指纹文件 ==="
  echo "fingerprints.ssdeep SHA-256: $(sha256sum "$OUT_DIR/fingerprints.ssdeep" | cut -d' ' -f1)"
  echo "对象数: $(wc -l < "$OUT_DIR/fingerprints.ssdeep")"
  echo "输入文件数: $(find . -type f -size +0 | wc -l)"
} >> "$OUT_DIR/metadata.txt"

cat "$OUT_DIR/metadata.txt"
```

**★ 版本不一致时的处理规则：**

**绝不能混用不同版本生成的指纹。** 如果必须用新版本：

```bash
# 旧版本仍可用时，双版本并行生成，匹配时同版本配对
ssdeep -br ./corpus/ > fp/v2.15/corpus.ssdeep
/path/to/ssdeep-2.14 -br ./corpus/ > fp/v2.14/corpus.ssdeep

# 两套指纹各自独立匹配，结论分别报告
ssdeep -x fp/v2.15/corpus.ssdeep fp/v2.15/targets.ssdeep
```

**如果只保留一个版本：**

在报告中明确声明「本结论基于 ssdeep X.Y.Z 生成，若使用其他版本复现结果可能不同」，并说明该版本是何时、从哪里获取的、指纹文件的哈希值是多少。这三者齐全，复核者才能验证。

**关于工具来源：** 近似匹配工具应从源码构建或使用发行版包，**不要使用来路不明的预编译二进制**。`ssdeep` 历史上多次因分段哈希的边界处理问题触发过崩溃（恶意构造输入可导致越界），分析环境中的工具供应链同样是攻击面。

<a id="section-36"></a>

#### 陷阱 12：把 .scrypt/.fz 扩展名当作格式标识

**现象**

看到 `sample.scrypt` 以为是某个专用加密格式，用十六进制编辑器打开发现是 ssdeep 指纹；或者看到 `.fz` 文件以为是模糊匹配指纹，实际是别的工具输出。报告里写「发现 scrypt 加密文件」是误判。

**原因**

ssdeep 的输出文件扩展名没有统一标准，`.scrypt` 不是 ssdeep 的官方扩展名。

不同来源的实现使用不同扩展名：

| 扩展名 | 实际情况 |
|---|---|
| `.ssdeep` | 社区最常用的约定；`ssdeep -b` 会原样沿用输入文件名，并不追加扩展名 |
| `.scrypt` | **非官方**。ssdeep 从不使用这个扩展名，它是第三方项目自定的命名 |
| `.fz` | 非官方，通常与模糊匹配无关（更多见于压缩/差分相关工具） |
| `.deep` | 非官方约定 |
| `.sig` | 各工具通用，不特定指近似匹配 |

关键点是：**这些扩展名与文件内容格式之间没有任何对应关系**，唯一例外是 ssdeep 指纹文件的内容本身有严格格式（`<块大小>:<摘要1>:<摘要2>`，随后两个空格接原文件名；对象过小时退化为 `3,,`）。`.scrypt` 文件既可能是 ssdeep 指纹，也可能是 TLSH 指纹，还可能只是普通二进制——只能靠内容判断。

识别格式的**唯一可靠方法是看内容**：

```bash
# 查看文件内容的实际格式
file sample.scrypt sample.fz sample.deep

# 手工判断：ssdeep 指纹的格式特征
head -1 sample.ssdeep
# 输出形如：3072:sBUXcU2EgwEJ:V+H9n1ytTTTg  sample.bin
#   ↑块大小  ↑摘要1（块大小）      ↑摘要2（块大小×2）  ↑两个空格 + 文件名
# 摘要使用 base64 变体字符集（0-9 A-Z a-z + / =）
# 对象过小时无法生成摘要，输出退化为：3,,  sample.bin（注意是逗号，不是冒号）
```

```python
#!/usr/bin/env python3
"""识别近似匹配指纹文件的真实格式。"""
import re
import sys

B64 = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
TLSH_RE = re.compile(r'^(?:T1)?[0-9A-Fa-f]{70}$')   # TLSH 5.x 带 T1 前缀，旧版无前缀

def is_ssdeep(line):
    """ssdeep 行：<块大小>:<摘要1>:<摘要2>[  文件名]；过小对象输出为 '3,,'。"""
    t = line.strip()
    if re.match(r'^\d+,,\s', t + ' ') or t.rstrip(',').isdigit():
        return True
    parts = t.split(':', 2)
    if len(parts) < 3 or not parts[0].isdigit():
        return False
    return all(c in B64 for c in parts[1])

def is_too_small(line):
    t = line.strip()
    return bool(re.match(r'^\d+,,\s', t + ' ')) or t.rstrip(',').isdigit()

def detect(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = [l.strip() for l in f.read().splitlines() if l.strip()][:20]
    if not lines:
        return '空文件'
    if all(is_ssdeep(l) for l in lines):
        groups = sorted({l.split(':' if not is_too_small(l) else ',', 1)[0] for l in lines})
        empty = sum(1 for l in lines if is_too_small(l))
        note = f'，其中 {empty} 行摘要为空（对象过小，未实际生成指纹）' if empty else ''
        return f'ssdeep 指纹（块大小: {", ".join(groups)}{note}）'
    if all(TLSH_RE.match(l) for l in lines):
        prefix = 'T1 前缀（TLSH 5.x）' if all(l.startswith('T1') for l in lines) else '无前缀（TLSH 4.x 及更早）'
        return f'TLSH 指纹（{prefix}）'
    if lines[0].startswith('{') or lines[0].startswith('['):
        return 'JSON 格式（可能是第三方库的导出）'
    if all(re.match(r'^[0-9a-f]{64}\s+', l) for l in lines):
        return 'sha256sum 风格（不是近似匹配指纹）'
    return f'未知格式，首行: {lines[0][:60]}'

for p in sys.argv[1:]:
    print(f'{p}: {detect(p)}')
```

**影响**

把指纹文件当成加密样本，会在报告里写出一整段关于「scrypt 参数」「加密强度」的结论，而检材根本不是加密数据。这类结论一旦被对方质疑，你无法回到镜像里重新论证——那句话本身就已经成为不利记录。

下游影响更麻烦：指纹库导入流程会因为「这是加密样本」而被跳过，于是这批对象的近似匹配覆盖率在统计表里仍是 100%，看不出任何缺口，错误一路掩盖到复核阶段。

另一种方向的代价发生在**格式识别错误**：把 TLSH 指纹（`T1` + 70 位十六进制，或旧版 70 位十六进制）当成 ssdeep 指纹行去解析，会得到一堆"空摘要"，看起来像"匹配全部分值为 0"。这个假阴性会被写成「已排除同源」，而实际上只是解析器用错了。

**核查**

**在工具链中统一扩展名，并在报告中记录格式标识。** 建议：

```bash
# 目录名编码工具与参数，文件名编码格式
fingerprint/
  ssdeep-2.15-3/
    corpus.ssdeep      # ssdeep 格式
  tlsh-5.0.2/
    corpus.tlsh        # TLSH 格式（T1 前缀）
```

**★ 关键原则：文件名、扩展名、目录名都是元数据。**

格式标识的权威来源是**文件内容**，不是文件名的扩展名。任何时候都可以用 `file` 命令或上述脚本验证，而不是靠扩展名猜测。

**更重要的是不要基于「以为是某种格式」做出结论。** 看到 `.scrypt` 文件就报告「发现 scrypt 加密样本」，是典型的「基于错误认知的方向性错误」。

<a id="section-37"></a>

#### 陷阱 13：用浮点数比较分值

**现象**

用 Python 读取 ssdeep 匹配结果，用 `float()` 转换分值并做算术运算，得到「平均相似度 68.5」这样的统计数字，写进报告作为整体判断依据。复核时发现计算逻辑有问题。

**原因**

ssdeep 的分值是整数，但不同工具的「相似度」语义不同，混在一起做算术运算是无意义的。

具体问题有三层：

**第一层：不同工具的分值方向相反。**

```python
# 错误：把 TLSH 距离当成 ssdeep 相似度
ssdeep_similar = 87      # ssdeep：值越大越相似
tlsh_dist      = 28      # TLSH：值越大差异越大
# 混算 → (87 + (100 - 28)) / 2 = 79.5  ← 数字无意义
```

**第二层：加权平均掩盖了重要信息。**

```python
# 错误：只看平均值
scores = [95, 92, 88, 3, 2, 1, 0, 0]
print(f"平均相似度: {sum(scores)/len(scores):.1f}")   # 34.9
# 实际上：3 个强关联 + 5 个无关对象，混合平均毫无意义
```

**第三层：分值不可加、不可乘、不可平均。**

分值是「块匹配的统计结果」，不是「相似性的量纲」。两个对象各与 C 相似度 80，**不意味着** A 与 B 相似度是 80 或 160。这与三角不等式无关，是分值定义本身不满足这种关系。

**影响**

- 报告中的统计数字无法被复核者验证
- 掩盖了「少数强关联 + 多数无关」的真实结构，让分析员低估了关联程度
- 跨工具的汇总数字完全是编造的

**核查**

**分值只用于排序与分档，不做算术运算。** 统计时按档位计数：

```python
import collections

def band(score):
    if score >= 90: return '极强 (90-100)'
    if score >= 70: return '强 (70-89)'
    if score >= 40: return '中等 (40-69)'
    if score > 0:   return '弱 (1-39)'
    return '无匹配 (0)'

# 正确：按档位计数
bands = collections.Counter()
for line in open('matched.txt', encoding='utf-8'):
    p = line.split('\	')
    if len(p) == 3:
        bands[band(int(p[0]))] += 1

print("匹配强度分布:")
for k in ['极强 (90-100)', '强 (70-89)', '中等 (40-69)',
          '弱 (1-39)', '无匹配 (0)']:
    n = bands.get(k, 0)
    if n:
        bar = '#' * min(40, n)
        print(f"  {k:<16} {n:>5}  {bar}")

# TLSH 必须反向转换，且转换结果只能用于同一工具内部的分档
def tlsh_to_band(dist):
    # TLSH 距离 0=完全相同，100+=完全不同
    sim = max(0, 100 - dist)
    return band(sim)
```

**报告中禁止出现的表述：**

- ❌ 「平均相似度 68.5，说明整体相关程度较高」
- ❌ 「综合相似度得分 72.3」
- ❌ 「相似度加权和为 1,847」

**应该出现的表述：**

> 4,182 个目标对象与基准库的匹配强度分布：极强（90–100）2 个、强（70–89）5 个、中等（40–69）17 个、弱（1–39）431 个、无匹配 3,727 个。其中达到 60 分及以上、可作为同源候选的共 7 个，经人工复核确认 4 个。

**注意最后一句的写法：** 「7 个候选 → 4 个确认」体现了「分值是筛选依据，人工复核是定性依据」这个结构。

<a id="section-38"></a>

### 4.5 结论表述

<a id="section-39"></a>

#### 陷阱 14：把「相似」写成「同源」

**现象**

报告摘要写「检材中发现 7 个已知恶意软件的变体」，正文表格里分值从 61 到 92 不等。辩方或复核人问「凭什么认定是变体而不是碰巧相似」时，无法回答。

**原因**

分值高只能证明「字节流有大量共同片段」，不能证明「有共同的开发者或共同的开发过程」。

同源（common ancestry）是一个关于**开发过程历史**的判断，需要的证据是：

- 共享的、无法偶然产生的不寻常特征
- 继承关系（继承自某个已知样本，而非各自独立演化）
- 排除共用的通用来源

分值只回答第一个问题的弱化版——「共同片段多」。而高分值的原因可能完全不涉及同源。

**原因一：共用的构建工具链（最常见）**

大量工具的样本天然高相似：

| 工具 | 说明 |
|---|---|
| NSIS / Inno Setup | 生成的安装程序有固定的脚本解释器骨架 |
| PyInstaller | bootloader 部分是固定二进制 |
| AutoIt | 编译产物有固定的运行时 |
| .NET + 混淆器 | 部分混淆器有特征性的方法名与结构 |
| Electron | 主进程代码是通用的 JS 引导代码 |
| Unity / Unreal | 引擎启动代码巨大且固定 |
| Delphi / Lazarus | 单元初始化代码模式固定 |

这些产物的分值轻松达到 80 以上，但两个不同开发者的不同项目也可能都达到这个分值。

**原因二：复制粘贴的代码段**

很多工具、脚本、配置模板在不同项目间复制。

这确实构成一种「关联」，但不是「同源」。两个项目可能一个来自 GitHub，一个来自 Stack Overflow 答案。

**原因三：算法伪影**

短文件、稀疏内容、重复结构都会抬高分值。三个原因合起来说明一件事：相似度分值本身不携带同源信息，必须结合文件大小、内容分布和来源上下文一起看。

**影响**

这是本主题里最严重的结论方向性错误。

刑事案件中，「是某个已知家族的变体」与「碰巧相似」在量刑与责任认定上有本质区别。民事案件中，「确认为特定软件的侵权作品」与「可能类似」在赔偿数额上差异巨大。

一旦被推翻，同一报告中的其他结论可信度也会受质疑。

**核查**

「同源」是一个需要独立论证的结论，相似度只能是支撑证据之一。

论证同源需要的多重证据：

```bash
# 证据 1：精确的同源标识（最强）
#   相同 GUID / 编译元数据 / 硬编码的开发者标识
strings -a -n 8 suspect.bin | grep -iE 'guid|pdb|company|copyright|author' | sort -u
strings -a -n 8 known.bin   | grep -iE 'guid|pdb|company|copyright|author' | sort -u

# 证据 2：罕见字符串的重合（比导入表更有说服力）
comm -12 \
  <(strings -a -n 10 suspect.bin | sort -u) \
  <(strings -a -n 10 known.bin   | sort -u) | head -30

# 证据 3：PDB 路径（若未剥离）
strings -a suspect.bin | grep -oE '[A-Z]:\\\\[^ ]+\.pdb' | head

# 证据 4：代码相似度工具（比 ssdeep 更能穿透打包）
#   对 .text 节区做函数级指纹比对
```

```python
# 罕见字符串重合度分析 —— 排除「共用模板」的有效方法
def jaccard(a, b):
    A, B = set(a), set(b)
    return len(A & B) / max(1, len(A | B))

suspect = set(l for l in open('/tmp/suspect.strings', encoding='utf-8').read().splitlines() if len(l) >= 10)
known   = set(l for l in open('/tmp/known.strings',   encoding='utf-8').read().splitlines() if len(l) >= 10)

common = suspect & known
print(f"字符串总数: 检材 {len(suspect)} / 样本 {len(known)}")
print(f"共同字符串: {len(common)}  Jaccard: {jaccard(suspect, known):.4f}")
print("\
共同字符串（排除通用 API 名与常见英文单词）:")
COMMON_WORDS = {'information', 'description', 'Copyright', 'Microsoft',
                'Windows', 'Program', 'Version', 'Error', 'Warning'}
for s in sorted(common, key=len, reverse=True)[:40]:
    if s not in COMMON_WORDS:
        print(f"  {s}")
```

**决策树 —— 什么时候可以说「同源」：**

```
相似度分值 ≥ 60
   │
   ├─ 是共用构建工具产物？（检查 bootloader / 引擎特征）
   │     └─ 是 → 表述「使用同一构建工具」，不定性同源
   │
   ├─ 罕见字符串重合度高？（非通用词、重合不来自模板）
   │     └─ 是 → 可表述「高度可能同源」，并列出重合的具体字符串
   │
   ├─ 导入 API 集合高度一致（>80% 且 >15 个）
   │     └─ 是 → 表述「功能与实现结构高度一致」
   │
   └─ 存在共同的不寻常标识（GUID / PDB 路径 / 硬编码常量）
         └─ 是 → 可表述「确认同源」，并把该标识作为核心证据
```

**报告中的表述阶梯：**

| 证据强度 | 表述 |
|---|---|
| 仅分值 | 「相似度分值为 87，属高相似」 |
| 分值 + 罕见字符串 | 「相似度分值为 87，且存在 N 项罕见字符串重合，高度可能同源」 |
| 分值 + 共同标识 | 「确认属同一源的不同构建，依据为 XXX（共同标识/编译元数据）」 |
| 无法排除共用工具 | 「与 X 使用同一构建工具，无法据此认定同源」 |

**共有的构建工具必须被识别出来并写在报告里。** 报告里出现了「与 NSIS 打包的已知样本相似度 83」，却没有说明「该样本为 NSIS 打包」，复核者无从判断这个分值有多少来自工具、多少来自业务逻辑。

<a id="section-40"></a>

#### 陷阱 15：用未覆盖范围支撑「未发现」★

**现象**

报告结论：「经与 1,842 个已知恶意样本比对，检材中未发现已知恶意软件。」复核时发现，检材中有一个 1.2 MB 的加壳可执行文件，熵值 7.91，且 ssdeep 分值为 0。

**原因**

★ 这是本主题里最隐蔽的错误，因为它看起来完全合规。

「未发现」这个表述本身有严格的形式要求：它必须是一个「在明确范围内对明确对象经过明确检查后未发现」的三元断言。缺任何一项，它就退化为「无证据支撑的否定」。

常见的三元缺项：

| 缺失项 | 表现 | 后果 |
|---|---|---|
| 范围未限定 | 「未发现已知恶意软件」 | 无法判断覆盖了什么 |
| 对象未穷举 | 只比对了可执行文件 | 脚本、宏、文档未提 |
| 检查未完成 | 加密/压缩/过小对象未比对 | 实际未检查却说检查过 |

**本主题特有的「实际未检查」清单**（每一项都是「未覆盖范围」）：

| 未覆盖对象 | 数量（本例） | 为什么未检查 |
|---|---|---|
| 加密内容（熵 > 7.9） | 1,203 | 近似匹配对密文无结论 |
| 压缩包内的内容 | 892 | 解压后未单独比对 |
| 小于 4096 字节的文件 | 412 | 无判别力，匹配不采信 |
| 损坏或截断的文件 | 37 | 内容不完整 |
| 已识别为脚本但未取证的 | 156 | 采用了不同的分析方法（见 [APK 逆向与 Manifest 分析](../../mobile/mobile-android/mobile-android-apk-manifest.md)） |
| 网络传输中的载荷 | 未知 | 未采集流量或载荷为密文 |
| 未从镜像中提取的对象 | 未知 | 提取范围有限 |

「未发现已知恶意软件」这句话在这份检材上是无法成立的。 1,203 个加密对象 + 892 个压缩包 + 412 个过小文件都没有被实际检查，而它们完全可能包含恶意内容。

**影响**

**虚假阴性结论**是取证报告中最严重的缺陷类型。

若据此做出了「设备无恶意」的判断，处置决定（解除隔离、恢复业务）就建立在错误前提上。在诉讼中，这类结论被推翻会导致出证方专业能力被质疑。

**核查**

「未发现」必须写成三元断言，并逐项列出未覆盖范围。

**标准模板：**

> **比对范围**：基准库 `DigiForensics-corpus` v2026-08（312 个样本，库哈希 `3f9a…c71e`），采用 ssdeep 2.15 默认块大小，跨组比对（`-x` 后按文件名归类，见陷阱 10）。
>
> **比对对象**：从 `DigiForensics.dd`（分区 2，NTFS）提取的 4,182 个文件对象。
>
> **检查结果**：在上述范围内，未发现相似度分值高于 30 的匹配。达到 60 分及以上、经人工复核确认同源的共 4 个对象。
>
> **未覆盖范围**（本结论不涵盖以下内容）：
>
> | 未覆盖对象 | 数量 | 原因 | 后续建议 |
> |---|---|---|---|
> | 高熵值疑似加密对象 | 1,203 | 近似匹配对密文无结论 | 需先获取密钥或内存解密态 |
> | 压缩包内内容 | 892 | 未做解压后比对 | 已在另一流程中解压分析 |
> | 小于 4096 字节的文件 | 412 | 低于 ssdeep 警告阈值 | 改用精确哈希或人工检视 |
> | 损坏/截断文件 | 37 | 内容不完整 | 需重新提取 |
> | 脚本与宏代码 | 156 | 采用不同分析方法 | 见脚本类专项分析 |
> | 网络传输载荷 | 未采集 | 无流量证据 | 需运营商侧或网关日志 |
> | 未提取的未分配空间 | 未量化 | 提取范围限于已分配文件 | 需执行未分配空间雕刻 |

**写法要点：**

1. 「未发现」后面必须跟范围限定。写「在上述范围内，未发现……」
2. 未覆盖范围要有数量、有原因、有后续建议。只有「有部分文件未检查」是不够的
3. 已通过其他流程检查的，要指明。「已在另一流程中解压分析」让复核者知道这块有覆盖，只是不在这个流程里
4. 完全无法覆盖的，要说明影响。「未分配空间未提取」意味着可能有已删除的恶意文件无法评估

**❌ 绝对禁止的表述：**

- 「未发现恶意软件」 / 「未发现任何威胁」
- 「经全面检查，未发现问题」
- 「该设备无恶意行为」
- 「未发现与已知样本相似的文件」（不提比对对象数量与未覆盖项）

这些表述在法律意义上是无依据的否定主张，在技术意义上是不可证伪的断言。

---

<a id="section-41"></a>

## 五、案例示例

> 以下案例中的检材、样本与工具版本均为虚构或脱敏，用于说明分析方法。

<a id="section-42"></a>

### 5.1 案例 A：从 3 个已知样本归并出 41 个变体

**背景**

某企业勒索事件，检材为 1 台 Windows 工作站的物理镜像 `DigiForensics.dd`。已通过其他途径获得 3 个确认为同一家族的样本（`known-a.bin`、`known-b.bin`、`known-c.bin`，均已脱密并附分析报告）。

**目标**：确认该工作站上是否存在该家族的样本，并确定变体数量。

**步骤 1：构建基准库并记录**

```bash
mkdir -p /Volumes/DigiForensics/work
cd /Volumes/DigiForensics/work
mkdir -p corpus/known

cp /Volumes/DigiForensics/intel/known-{a,b,c}.bin corpus/known/

# 记录工具版本与参数
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ssdeep: $(ssdeep -V 2>&1 | tr '\
' ' ')"
  echo "params: 3: (default group)"
} | tee corpus/meta.txt

# 生成基准库指纹
ssdeep -br corpus/known > corpus/corpus.ssdeep 2>/dev/null
cat corpus/corpus.ssdeep
```

**步骤 2：提取并生成目标侧指纹**

```bash
# 提取可执行对象（略，实际需覆盖脚本与文档）
mkdir -p targets
photorec /d /Volumes/DigiForensics/work/targets \
         /cmd /Volumes/DigiForensics/evidence/DigiForensics.dd partition2 \
  2>/dev/null

# 对提取结果做格式筛选，去掉明显无意义的
find targets -type f -size -1k -delete          # 小于 1KB
find targets -type f \( -name '*.jpg' -o -name '*.png' -o -name '*.bmp' \) -delete
find targets -type f \( -name '*.zip' -o -name '*.rar' -o -name '*.7z' \) -delete

echo "待比对对象: $(find targets -type f -size +0 | wc -l)"

ssdeep -br targets > targets/targets.ssdeep 2>/dev/null
echo "生成指纹:   $(wc -l < targets/targets.ssdeep)"
```

**输出**：

```
待比对对象: 4182
生成指纹:   3745
```

**差额 437 个对象未能生成指纹。** 这个差额必须记录 —— 它是阴性结论范围的组成部分。

**步骤 3：比对并按跨组归类**

```bash
# -x 是集合内全两两比对（不是"A 比 B"），输出会混入两组各自的内部配对。
# 所以只跑一次，然后按文件名把结果切开。
ssdeep -c -x corpus/corpus.ssdeep targets/targets.ssdeep \
  | awk -F',' '{
      gsub(/"/, "")
      if (NF < 3) next          # ssdeep 的 CSV 行之间夹空行，不过滤会产出空记录
      if ($1 == "" || $2 == "") next
      a=$1; b=$2; s=$3+0
      aC=(a ~ /^(corpus|known)-/);  bC=(b ~ /^(corpus|known)-/)
      aT=(a ~ /^targets?-/);        bT=(b ~ /^targets?-/)
      if (aC && bT)      print "CROSS\t" s "\t" b "\t" a
      else if (bC && aT) print "CROSS\t" s "\t" a "\t" b
      else               print "INTRA\t" s "\t" a "\t" b
    }' > m-classified.tsv

echo "跨组命中: $(awk -F'\t' '$1=="CROSS"' m-classified.tsv | wc -l)"
echo "组内配对: $(awk -F'\t' '$1=="INTRA"' m-classified.tsv | wc -l)"
```

**输出**：

```
跨组命中: 41
组内配对: 12
```

**组内配对不是"命中基准库"。** 这 12 条是基准库内部或检材内部互相之间的配对，属于[陷阱 10](#section-33)说的那类污染——如果直接拿 `-x` 的原始输出行数当命中数，就会虚高 12 条。

顺带说明：不需要为了"防漏检"再把两个参数位置对调跑一遍。ssdeep 的分值是对称的（见 [2.6](#section-8)），第二遍的配对集合与分值和第一遍完全相同，只是左右两列对调。

**步骤 4：人工复核高分项**

```bash
# 取出所有 >= 40 的配对，按分值降序
awk -F',' '$3+0>=40 {print $1"\	"$2"\	"$3}' m-fwd.txt m-rev.txt | sort -rn -k1,1 > candidates.txt
wc -l candidates.txt
```

**输出**：

```
47
```

逐个复核后：

| 配对 | 分值 | 复核发现 | 判定 |
|---|---|---|---|
| `targets/s-0042.bin` ↔ `known-a` | 92 | 导入 API 交集 21/23，节区完全一致，PDB 路径同前缀 | 同源 |
| `targets/s-0117.bin` ↔ `known-b` | 89 | 同上，另发现相同 GUID | 同源 |
| `targets/s-0233.exe` ↔ `known-a` | 78 | NSIS 打包，bootstrap 段一致，业务逻辑无重合 | 共用工具，排除 |
| `targets/s-0451.exe` ↔ `known-c` | 71 | PyInstaller bootloader 一致 | 共用工具，排除 |
| `targets/s-0512.bin` ↔ `known-b` | 68 | 导入 API 交集 8/19 | 同源（改动较大） |
| 其余 42 条 | < 60 | — | 低于阈值，不纳入 |

**步骤 5：目标侧内部归并**

```bash
ssdeep -xr targets/targets.ssdeep \
  | awk -F',' '$3+0>=40 && $1!=$2 {print $1"\	"$2"\	"$3}' > internal.txt

python3 - <<'PY'
import collections
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb: parent[ra] = rb

edges = []
for line in open('internal.txt', encoding='utf-8'):
    p = line.split('\	')
    if len(p) == 3:
        edges.append((p[1], p[2], int(p[0])))
        if int(p[0]) >= 60:          # 只有强边参与传递闭包
            union(p[1], p[2])

clusters = collections.defaultdict(list)
for x in list(parent):
    clusters[find(x)].append(x)

big = [(r, m) for r, m in clusters.items() if len(m) >= 2]
big.sort(key=lambda kv: -len(kv[1]))
for r, m in big:
    es = [s for a, b, s in edges if find(a) == r]
    print(f'簇：{len(m)} 成员，强边 {len(es)} 条，分值 {min(es)}-{max(es)}')
print(f'\
共 {len(big)} 个多成员簇')
PY
```

**输出**：

```
簇：38 成员，强边 214 条，分值 61-94
簇：3 成员，强边 2 条，分值 62-66

共 2 个多成员簇
```

**注意第二个簇**：3 个成员只有 2 条强边，说明是「1 对强关联 + 1 个通过弱边挂入」。这个簇的可靠性低于第一个，报告里要分开说明。

**结论**：38 + 3 = 41 个对象归入该家族，其中 4 个已通过与基准库的直接匹配确认，37 个通过变体间的传递关系确认。

**步骤 6：报告表述**

> 在基准库 `DigiForensics-corpus`（3 个已确认样本，ssdeep 2.15，默认块大小）与从 `DigiForensics.dd` 提取的 3,745 个可比对对象之间进行**跨组** ssdeep 比对（`-x` 后按文件名归类），**发现 41 个对象与该家族相关**，分值区间 61–94。
>
> 其中 4 个与基准样本直接匹配（分值 68–92），经导入 API 集合比对与编译元数据比对确认同源；37 个通过对上述对象的相似关系（传递闭包，阈值 60）归入同一簇，归并为 2 个连通分量（38 成员簇与 3 成员簇）。
>
> **未覆盖范围**：437 个对象指纹不可用（小于 4096 字节因而区分度不足，或内容不完整）；提取阶段排除的图片与压缩包未参与本次比对；未分配空间未做雕刻。

<a id="section-43"></a>

### 5.2 案例 B：PCAP 中的载荷比对

**背景**

怀疑某工作站存在数据外泄。已获取该站点出口的流量捕获 `DigiForensics-exit.pcap`（1.2 GB，采集点为 SPAN 口，snaplen 1514，无丢包记录）。需要确认是否有载荷与已知泄露样本相似。

步骤 1：确认抓包完整性（这一步决定后续所有结论的效力）

```bash
tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  -q -z io,stat,0,'COUNT(tcp.analysis.retransmission)tcp.analysis.lost_segment' 2>/dev/null

capinfos -c -d -u -a -e /Volumes/DigiForensics/net/DigiForensics-exit.pcap
```

**输出**：

```
参数: snaplen 1514
包数:  8,412,663
时间:  2026-08-14 09:00:03 UTC  →  2026-08-14 18:00:11 UTC
```

`incl_len` 未出现小于 `orig_len` 的情况（未截断），无重传/丢段计数。**抓包完整性成立，内容级结论可行。**

**步骤 2：导出 HTTP 对象**

```bash
mkdir -p /Volumes/DigiForensics/work/pcap-http
tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  --export-objects http,/Volumes/DigiForensics/work/pcap-http 2>/dev/null

echo "导出对象数: $(ls /Volumes/DigiForensics/work/pcap-http | wc -l)"
```

**输出**：

```
导出对象数: 3,847
```

**步骤 3：排除噪声与高熵对象**

```bash
cd /Volumes/DigiForensics/work/pcap-http
# 排除静态资源
find . -type f \( -name '*.jpg' -o -name '*.png' -o -name '*.gif' \
  -o -name '*.css' -o -name '*.woff*' -o -name '*.svg' \) -delete
echo "剩余: $(find . -type f | wc -l)"

# 按熵值分流：加密/压缩对象单独标记，不参与近似匹配
python3 - <<'PY'
import math, os, collections
low, high, small = [], [], []
for root, _, files in os.walk('.'):
    for f in files:
        p = os.path.join(root, f)
        data = open(p, 'rb').read()
        if len(data) < 64:
            small.append(p); continue
        freq = collections.Counter(data)
        ent = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
        (high if ent > 7.9 else low).append((p, ent))
print(f"可参与比对: {len(low)}")
print(f"高熵（加密/压缩，近似匹配无结论）: {len(high)}")
print(f"过小（无法生成指纹）: {len(small)}")
with open('/tmp/entropy-buckets.txt', 'w') as fh:
    for p, e in high: fh.write(f'high\	{p}\	{e:.3f}\
')
    for p in small: fh.write(f'small\	{p}\	0\
')
PY
```

**输出**：

```
可参与比对: 1,206
高熵（加密/压缩，近似匹配无结论）: 2,418
过小（无法生成指纹）: 109
```

**2,418 个高熵对象是本次分析的主要盲区**，必须写进报告。

**步骤 4：比对并回连会话**

```bash
ssdeep -br /Volumes/DigiForensics/work/pcap-http/ > pcap.ssdeep 2>/dev/null

ssdeep -x corpus/corpus.ssdeep pcap.ssdeep \
  | awk -F',' '$3+0>0' | sort -t',' -k3,3nr > pcap-matches.txt

cat pcap-matches.txt
```

**输出**：

```
31	pcap-http/ae4f2c1b.bin	corpus/known/dataset-sample.bin
18	pcap-http/c91d0e77.bin	corpus/known/known-b.bin
```

**第一条分值 31** —— 这落不进任何常用的「相似」区间。人工检视后判断：内容是加密的数据集导出，**加密使分值失去意义**。

★ 这就是本主题最需要警惕的情形：分值 31 看起来像「弱关联」，但实际是「无法判断」。

**步骤 5：改用精确哈希做二次确认**

对于分值处于中间区间的对象，用精确哈希排除「完全一致但被分值掩盖」的情况：

```bash
# 对所有导出对象计算 SHA-256，与基准库精确比对
cd /Volumes/DigiForensics/work/pcap-http
find . -type f -exec sha256sum {} + > pcap.sha256
grep -F -f <(cut -d' ' -f1 corpus/corpus.sha256 | sort) pcap.sha256
```

**输出**：

```
7f3a9c2e1b8d4f6a0c5e9d3b7a1f4c8e2d6b0a3f7c9e1d5b8a2f6c4e0d3b7a9  ./c91d0e77.bin
```

`c91d0e77.bin` 与基准库中的某个对象 SHA-256 完全一致 —— 虽然 ssdeep 分值只有 18。这说明该对象**确实就是**基准库里的文件。

这个结果是精确匹配与近似匹配互补的例证：

| | 精确哈希 | 近似匹配 |
|---|---|---|
| 完全一致 | ✓ 分值通常很高 | |
| 差一个字节 | ✗ 完全无信息 | ✓ 高分 |
| 加密内容 | ✗ 无信息 | ✗ 无信息 |
| 关系判断 | ✗ 只能二分 | ✓ 连续度量 |

**步骤 6：回连到具体会话与主机**

```bash
# 找出承载该对象的 HTTP 响应
tshark -r /Volumes/DigiForensics/net/DigiForensics-exit.pcap \
  -Y "http.response.code == 200" -T fields \
  -e tcp.stream -e ip.src -e ip.dst -e ip.dst_port \
  -e http.host -e http.content_type -e http.content_length 2>/dev/null \
  | awk -F',' '$7 > 100000 {print}' | head -20
```

**输出**：

```
1423	203.0.113.45	192.168.10.87	443	cdn.example-cloud.net	application/octet-stream	10485760
1487	203.0.113.45	192.168.10.87	443	cdn.example-cloud.net	application/octet-stream	3145728
1502	203.0.113.45	192.168.10.87	443	files.example-cloud.net	application/zip	20971520
```

TCP 流 1423 传输了 10,485,760 字节（正好 10 MB），从 `cdn.example-cloud.net` 到内网主机 `192.168.10.87`。

**步骤 7：交叉验证到主机侧**

近似匹配的结论必须能落到具体设备上才有意义：

```bash
# 在主机镜像中定位该哈希对应的文件
photorec /d /Volumes/DigiForensics/work/host-carve \
         /cmd /Volumes/DigiForensics/evidence/DigiForensics-workstation.dd \
  2>/dev/null

grep -rl '7f3a9c2e1b8d4f6a0c5e9d3b7a1f4c8e2d6b0a3f7c9e1d5b8a2f6c4e0d3b7a9' \
  /Volumes/DigiForensics/work/host-carve/ 2>/dev/null
# 或直接用精确哈希比对
cd /Volumes/DigiForensics/work/host-carve
find . -type f -exec sha256sum {} + 2>/dev/null | \
  grep '^7f3a9c2e1b8d4f6a0c5e9d3b7a1f4c8e2d6b0a3f7c9e1d5b8a2f6c4e0d3b7a9'
```

**输出**：

```
7f3a9c2e1b8d4f6a0c5e9d3b7a1f4c8e2d6b0a3f7c9e1d5b8a2f6c4e0d3b7a9  ./f0000123.doc
```

在主机镜像中找到了同哈希的文件 `f0000123.doc` —— 这是一个从已删除空间雕刻出的 Word 文档。

**完整的证据链：**

```
主机镜像中的 f0000123.doc（SHA-256 一致）
        ↕ 精确哈希
PCAP 中 TCP 流 1423 的响应体（SHA-256 一致）
        ↕ 内容相似度
基准库中的已知样本（SHA-256 一致）
```

**步骤 8：报告表述**

> 在 `DigiForensics-exit.pcap`（1.2 GB，1514 字节 snaplen，无截断无丢包，覆盖 2026-08-14 09:00–18:00 UTC）中导出的 **1,206 个可比对对象**，与基准库 `DigiForensics-corpus`（312 样本）进行 ssdeep 3: 跨组比对（`-x` 后按文件名归类）。
>
> **发现 1 个对象与基准库样本精确一致**（SHA-256 `7f3a…7a9`），该对象对应 TCP 流 1423，自 `cdn.example-cloud.net` 下载至内网主机 `192.168.10.87`，大小 10,485,760 字节。在主机镜像 `DigiForensics-workstation.dd` 的已删除空间中雕刻出同哈希文件（`f0000123.doc`），**哈希一致，可确认二者为同一文件**。
>
> **未覆盖范围**：2,418 个高熵对象（熵值 > 7.9，判定为加密或已压缩，**近似匹配对其无结论**）；109 个小于 4096 字节、无判别力的对象；使用 TLS 加密且未提供密钥的会话载荷（无法判断内容）；非 HTTP 协议的其他应用层载荷。

<a id="section-44"></a>

### 5.3 阴性发现的分层表述

前两个案例都是阳性发现，而阴性发现的表述错误才是虚假结论的主要来源。

分层原则：把对象按「是否实际被检查过」分成三层，每层的结论强度不同。

| 层 | 定义 | 可下的结论 |
|---|---|---|
| 层 1：已比对且无匹配 | 指纹成功生成，比对完成，分值全部低于阈值 | **可判定**：在该工具版本与该基准库范围内不相似 |
| 层 2：已比对但有低分 | 指纹成功生成，存在 1–39 的低分匹配 | **不可判定**：低分区域是噪声区，不能作为任何方向的依据 |
| 层 3：未获可比对内容 | 加密、压缩、过小、损坏、缺失 | **无结论**：不是「不相似」，是「未检查」 |

**❌ 错误表述（把三层混为一谈）：**

> 经比对，检材中未发现与已知样本相似的文件。

这句话的问题：它把层 3 的对象也算进了「已比对」的范围内。检材中 2,418 个加密对象从未被真正检查过，但这句话让读者以为它们被检查过且未发现。

**✅ 正确表述（三层分开）：**

> **第一层 · 已比对且无匹配**
>
> 在 1,206 个成功生成指纹并完成比对的对象中，**1,198 个的相似度分值上限低于 30**。在本次采用的工具与版本（ssdeep 2.15 默认块大小）与基准库（DigiForensics-corpus v2026-08，312 样本，库哈希 `3f9a…c71e`）范围内，**这 1,198 个对象不构成同源候选**。
>
> **第二层 · 已比对但落入低分区**
>
> 另有 7 个对象的最高分值在 30–39 之间。该区间在本场景下与随机匹配的分值分布重叠，**本报告不将其作为任何方向的依据**。抽样人工检视 3 个，未发现业务逻辑关联。
>
> **第三层 · 未获可比对内容（无结论）**
>
> | 类别 | 数量 | 判定依据 | 对结论的影响 |
> |---|---|---|---|
> | 高熵值对象 | 2,418 | 熵值 > 7.9，判定为加密或压缩 | **无结论**，不能表述为「不相似」 |
> | 小于 4096 字节 | 109 | 低于 ssdeep 警告阈值 | **无结论**，需改用其他方法 |
> | 截断对象 | 12 | `incl_len < orig_len` | **无结论**，比对内容不完整 |
> | TLS 密文载荷 | 未量化 | 未提供会话密钥 | **无结论**，内容不可见 |
> | 未分配空间 | 未量化 | 未执行雕刻 | **无结论**，已删除内容未评估 |
>
> **综合表述**：
>
> 在 `DigiForensics.dd` 的**已分配文件范围**内、**可生成指纹的对象**中、**本基准库覆盖范围内**，未发现该家族的变体。
>
> **该结论不涵盖**：加密容器内的内容、压缩包内的内容、小于 4096 字节因而指纹不可用的对象、被截断的传输内容、未采集的加密流量载荷、以及未分配空间中已删除的内容。上述范围内是否存在该家族的变体，**本次分析无法评估**。

**三条必须遵守的规则：**

**规则一：「未发现」后面必须紧跟范围限定。**

- ❌ 「未发现已知恶意软件」
- ✅ 「在 X 范围内、针对 Y 类对象、经 Z 方式比对，未发现 W」

规则二：未覆盖范围必须有数量、原因、影响、后续建议四要素。

只写「有部分文件未检查」等于没说。要写成：

| 类别 | 数量 | 原因 | 对结论的影响 | 后续建议 |
|---|---|---|---|---|
| 加密容器 | 1,203 | 未获取密钥 | 无法评估 | 需内存解密态或密钥材料 |
| 压缩包内容 | 892 | 未做解压后比对 | 未评估 | 可通过解压流程补充 |
| 小于 4096 字节 | 412 | 低于工具可靠阈值 | 未评估 | 改用精确哈希或人工检视 |
| 未分配空间 | 未量化 | 未执行雕刻 | 已删除内容未评估 | 需执行空间雕刻 |

**规则三：把「已通过其他流程检查的」显式指出来。**

如果某些未覆盖项其实在另一个分析流程里已经处理过，要写明 —— 这让复核者知道覆盖是存在的，只是不在本次流程内：

> 892 个压缩包内含 3,847 个文件，**已在本案的归档解压流程中完成病毒扫描与相似度比对**（见《镜像内文件提取与归档流程》第 4 章），本报告的未覆盖范围仅指其**未经解压前形态**的比对。

最后：一个「未发现」结论的强度上限是「在该范围内的该方法下未发现」。 任何形式的「未发现 X」如果脱离范围限定，都是无依据的否定主张 —— 这不是修辞问题，是可采性问题。

---

<a id="section-45"></a>

## 六、扩展阅读方向

**前置与基础。** 算法的原始文献比二手教程可靠得多。
ssdeep 出自 DFRWS 2006（Kornblum，CTPH 思路），
sdhash 出自 DFRWS 2008（Roussev），两篇里的设计权衡、
参数选择依据和原始评测数据，是理解相似度含义的唯一出处——
「64 位的匹配分」这个数字到底代表什么，只能从原文读出来。
TLSH 的距离方向定义、最小文件长度限制、多线程实现的细节，
则集中在 Trend Micro 的 GitHub 与白皮书里。

**同层深入。** 阈值怎么定，比用什么算法更容易出问题。
ROC 曲线与 PR 曲线在相似度阈值选择上的应用决定了误报与漏报的取舍点，
本节的校准脚本只是简化版，正式场景需要拿标注集做完整 ROC 分析。
往工程侧推一层是 LSH（locality-sensitive hashing），
它解决 O(n²) 比较的问题，是近似匹配能扩到亿级对象的前提。

**相邻议题。** 函数级代码相似是另一条技术路线：
winnowing、树哈希、AST 指纹这些方法比字节流相似度更能穿透
编译差异与变量重命名，处理 PE 或 ELF 的变形时结论更可靠。
脚本类分析则要彻底换方法——脚本和宏代码的分析路径完全不同，
本节的二进制近似匹配在它们身上并不适用，
见 [《APK逆向与Manifest分析》](../../mobile/mobile-android/mobile-android-apk-manifest.md)。

**工具与判据。** 对象提取是前置步骤：
从镜像中定向提取与雕刻对象，做近似匹配才有输入，
见 [《文件系统取证总览》](../../filesystem/filesystem-ntfs/filesystem-ntfs-filesystem-forensics-overview.md)。
内容的来源侧，PCAP 载荷导出、完整性校验与 TLS 元数据提取的完整流程
见 [《网络流量与PCAP取证》](../../memory/memory-network/memory-network-pcap.md)；
样本库侧则要看 MISP 的 taxonomies 与 warning lists、
以及 CAPE Sandbox 的样本组织方式——
分类体系、有效性标注、去重实践决定了比对结果的可用性。

**判据与反例。** 近似匹配必须与精确匹配并存。
精确哈希的单向性、碰撞可构造性，以及为什么这两套方法缺一不可，
见 [《哈希与完整性校验》](fundamentals-concepts-hashes-and-integrity-verification.md)：
哈希负责「是不是同一份」，模糊哈希只能给出「像不像」。
把相似度 70% 直接写成「同一文件」是最典型的越界，
报告里必须给出阈值、算法和比对对象三者的交代。

---

<a id="section-46"></a>

## 七、命令速查

```bash
# ===== 工具版本 =====
ssdeep -V                        # ssdeep 版本（输出会散落在多行）
tlsh --version                   # TLSH 版本
python3 -c "import tlsh; print(tlsh.__version__)" 2>/dev/null

# ===== 生成指纹 =====

# 单个文件（块大小自动适配）
ssdeep -b target.bin

# 块大小无法用命令行指定（自适应）
# ★ 块大小不能通过命令行指定：-b 是 bare mode（只剥离路径前缀），不是块大小。
#   ssdeep -b 3 target.bin 会把 "3" 当成一个待处理的文件名而报 "No such file or directory"。
#   块大小由 ssdeep 按文件长度自适应决定，只能事后从输出的 "块大小:hash:hash" 前缀读出。
ssdeep -b target.bin             # 仅剥离路径，块大小仍自适应

# 批量（推荐 -r 递归，避免命令行参数长度限制）
ssdeep -br ./suspect/ > fingerprints.ssdeep 2>/dev/null

# 批量（find 方式，可控制文件类型）
find . -type f -size +0 -exec ssdeep -b {} + 2>/dev/null > fingerprints.ssdeep

# -t 只在匹配阶段有意义（-x / -m / -k），生成阶段加了也不生效
# 例：只显示分值 > 30 的匹配
ssdeep -c -x -t 30 corpus.ssdeep targets.ssdeep

# 目录名与文件名编码工具与参数，格式单独标识
ssdeep -br ./suspect/ > fp/ssdeep-2.15-3/corpus.ssdeep 2>/dev/null

# ===== 匹配 =====
# -x 模式：把所有签名文件合并后做集合内全两两比对（不是"A 比 B"）
#          加 -c 才是 CSV，列序 $1=文件A $2=文件B $3=分值
ssdeep -c -x corpus.ssdeep targets.ssdeep

# 分值是对称的，不需要把两个参数对调再跑一遍（见 2.6）
# 跨组结论必须自己按文件名归类，见陷阱 10
ssdeep -c -x corpus.ssdeep targets.ssdeep \
  | awk -F',' '{gsub(/"/,"");
      a=$1; b=$2;
      if (a ~ /^(corpus|known)-/ && b ~ /^targets?-/) print $3"\t" b "\t" a
      else if (b ~ /^(corpus|known)-/ && a ~ /^targets?-/) print $3"\t" a "\t" b}'

# 全量配对而非仅最佳匹配（-a 忽略阈值，显示全部配对）
ssdeep -c -x -a targets.ssdeep | awk -F',' '$3+0 >= 30'

# 目标库内部自比（发现基准库外的新变体）
ssdeep -c -x targets.ssdeep targets.ssdeep | awk -F',' '{gsub(/"/,""); if ($1 != $2 && $3+0>=60) print $3"\t" $2 " <=> " $1}'

# 分离跨组匹配与组内配对
awk -F'\t' '$1=="CROSS" {print > "matched.txt"; next} {print > "intra.txt"}' classified.tsv
awk -F',' '$3+0>0 {print > "matched.txt"; next} {print > "unmatched.txt"}' fwd.txt

# 取每个目标对象的最高分命中
awk -F',' '{if($3+0>m[$2]){m[$2]=$3+0; s[$2]=$1}} END{for(k in m) print m[k]"\	"s[k]"\	"k}' fwd.txt \
  | sort -rn

# 按分值分档（不要只取单阈值）
awk -F',' '{
  s=$3+0
  if(s>=90) print "极强\	"s"\	"$2" <=> "$1
  else if(s>=70) print "强\	"s"\	"$2" <=> "$1
  else if(s>=40) print "中等\	"s"\	"$2" <=> "$1
  else if(s>0) print "弱\	"s"\	"$2" <=> "$1
}' fwd.txt | sort

# ===== TLSH（注意：距离越小越相似，与 ssdeep 方向相反）=====
tlsh -f corpus_dir > corpus.tlsh
tlsh -f target_dir > target.tlsh

# 计算差异距离（0 = 相同，100+ = 完全不同）
python3 -c "
import tlsh
d = tlsh.diff(tlsh.hash(open('a.bin','rb').read()), tlsh.hash(open('b.bin','rb').read()))
print(f'差异距离: {d}  ({\"相同\" if d==0 else \"不同\"})')
sim = max(0, 100 - d)
print(f'换算为相似度分档: {sim}')
"

# ===== 熵值检测（判断对象是否可参与近似匹配）=====
python3 - <<'PY'
import math, sys, collections
for p in sys.argv[1:]:
    data = open(p, 'rb').read()
    if not data:
        print(f'{p}: 空文件'); continue
    f = collections.Counter(data)
    ent = -sum((c/len(data))*math.log2(c/len(data)) for c in f.values())
    verdict = ('加密/压缩，无结论' if ent > 7.9 else
               '偏高，存疑' if ent > 7.5 else
               '正常，可比对')
    print(f'{p}: {len(data)} 字节  熵={ent:.3f}  {verdict}')
PY

# ===== 格式识别（不要靠扩展名判断）=====
file sample.ssdeep sample.tlsh sample.scrypt sample.fz
python3 -c "
import re,sys
for p in sys.argv[1:]:
    L=[l.strip() for l in open(p,encoding='utf-8',errors='replace') if l.strip()][:20]
    if L and all(re.match(r'^\d+:[A-Za-z0-9+/=]*:',l) for l in L):
        print(p, 'ssdeep 指纹，块大小分布:', sorted({l.split(':')[0] for l in L}))
    elif L and all(re.match(r'^[0-9A-Fa-f]{70}\$',l) for l in L):
        print(p, 'TLSH 指纹')
    else: print(p, '非指纹文件')
" sample.ssdeep sample.tlsh

# ===== 精确哈希（与近似匹配互补，必须同时做）=====
find . -type f -exec sha256sum {} + > corpus.sha256

# 去重检查
find . -type f -exec sha256sum {} + | awk '{print $1}' | sort | uniq -d | head

# 二次确认（近似分值低但可能完全一致的情况）
find pcap-http/ -type f -exec sha256sum {} + 2>/dev/null > pcap.sha256
grep -F -f <(cut -d' ' -f1 corpus.sha256 | sort) pcap.sha256

# ===== PE 结构比对（定性的主要依据）=====
file target.bin
python3 -c "
import pefile
pe = pefile.PE('target.bin')
print('入口点:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print('时间戳:', pe.FILE_HEADER.TimeDateStamp)
for s in pe.sections:
    print('节区:', s.Name.rstrip(b'\x00').decode(errors='replace'),
          hex(s.VirtualAddress), hex(s.SizeOfRawData), hex(s.Characteristics))
for e in pe.DIRECTORY_ENTRY_IMPORT:
    print('导入:', e.dll.decode(), len(e.imports), '项')
"

# 导入 API 交集（比 ssdeep 分值可靠得多）
python3 - <<'PY'
import pefile
def imports(p):
    return {f"{e.dll.decode().lower()}!{i.name.decode().lower() if i.name else 'ord'+str(i.ordinal)}"
            for e in pefile.PE(p).DIRECTORY_ENTRY_IMPORT for i in e.imports}
a, b = imports('suspect.bin'), imports('known.bin')
print(f'交集 {len(a&b)} / 并集 {len(a|b)}  Jaccard {len(a&b)/max(1,len(a|b)):.3f}')
print('仅检材有:', sorted(a-b)[:15])
print('仅样本有:', sorted(b-a)[:15])
PY

# 罕见字符串重合（排除共用模板的有效方法）
strings -a -n 10 suspect.bin | sort -u > /tmp/suspect.strings
strings -a -n 10 known.bin   | sort -u > /tmp/known.strings
comm -12 /tmp/suspect.strings /tmp/known.strings | head -30

# PDB 路径与开发者标识（未剥离时存在）
strings -a target.bin | grep -oE '[A-Z]:\\\\[^ ]+\.pdb' | head
strings -a -n 8 target.bin | grep -iE 'guid|company|copyright|author' | sort -u

# ===== 归并（传递闭包，务必用并查集）=====
python3 - <<'PY'
import collections
THRESHOLD, MIN_STRONG = 60, 40
parent = {}
def find(x):
    parent.setdefault(x, x)
    while parent[x] != x:
        parent[x] = parent[parent[x]]; x = parent[x]
    return x
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb: parent[ra] = rb

edges = []
for line in open('internal.txt', encoding='utf-8'):
    p = line.split('\	')
    if len(p) == 3:
        s = int(p[0]); edges.append((p[1], p[2], s))
        if s >= THRESHOLD: union(p[1], p[2])

clusters = collections.defaultdict(list)
for x in list(parent): clusters[find(x)].append(x)
for r, m in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
    if len(m) < 2: continue
    es = [s for a,b,s in edges if find(a)==r] or [0]
    print(f'簇：{len(m)} 成员，强边 {len(es)} 条，分值 {min(es)}-{max(es)}')
PY

# ===== 元数据记录（工具版本与参数是结论的一部分）=====
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ssdeep: $(ssdeep -V 2>&1 | tr '\
' ' ')"
  echo "params: 3: (default group)"
  echo "inputs: $(find . -type f -size +0 | wc -l)"
} > metadata.txt
sha256sum fingerprints.ssdeep >> metadata.txt

# ===== 元组信息（流量场景）=====
capinfos -c -d -u -s -a -e DigiForensics-exit.pcap
tshark -r file.pcap -q -z io,stat,0,'SUM(tcp.analysis.retransmission)tcp.analysis.lost_segment'

# 确认无截断（incl_len 应处处等于 orig_len）
tshark -r file.pcap -T fields -e frame.cap_len -e frame.len 2>/dev/null \
  | awk '$1 != $2 {n++} END {print "截断报文数:", n+0}'
```

---

**版权与引用声明**

本文档采用知识共享署名-相同方式共享 4.0 国际许可协议（CC BY-SA 4.0）发布。

- **署名**：引用或转述本文内容时，须注明作者/来源为 DigiForensics，并链接至本文原始页面。
- **相同方式共享**：基于本文创作的衍生作品必须以相同协议发布。

本文中提及的 `DigiForensics.dd`、`DigiForensics-corpus`、`target.bin`、`suspect.bin` 等文件名，以及文中呈现的所有样本特征、分值、哈希值与检索结果，均为**虚构或已脱敏**的示例数据，不指向任何真实的案件、机构、系统或已发布的安全威胁样本。本文档不包含任何漏洞利用代码、恶意代码构造方法或规避检测技术，相关内容仅用于防守方的取证分析与事件响应。

相似度分值是对字节流相似程度的统计度量，**不是概率，也不能单独作为同源认定依据**。任何涉及责任认定的结论，都必须结合本文「四、常见陷阱」中「把『相似』写成『同源』」与「用未覆盖范围支撑『未发现』」两条所列的多重独立证据综合论证。
