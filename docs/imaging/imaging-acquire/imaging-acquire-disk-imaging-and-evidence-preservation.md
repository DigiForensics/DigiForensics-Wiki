---
title: "磁盘镜像制作与证据固定"
slug: "imaging-acquire-disk-imaging-and-evidence-preservation"
canonical: "https://www.digiforensics.cn/wiki/imaging-acquire-disk-imaging-and-evidence-preservation"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:52+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "imaging"
space: "磁盘镜像与仿真"
node_path: ["镜像采集"]
---

# 磁盘镜像制作与证据固定

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/imaging-acquire-disk-imaging-and-evidence-preservation)

<a id="section-1"></a>

## 一、概述

只有这一步会物理接触原始检材。

后续分析受镜像采集范围和完整性限制。镜像阶段丢了数据、混进了写操作、或者哈希链断了，后面再精巧的结论都站不住。

目标很直白：不改变检材状态，尽可能忠实地复制出每一位（bit）。三个关键词缺一不可：

| 目标 | 含义 | 保障手段 |
|---|---|---|
| **完整** | 全盘逐扇区复制，含分区表、未分配空间、删除文件残留 | 全盘而非分区、不启用稀疏跳过 |
| **忠实** | 不引入任何非原始数据的写入 | 硬件写保护器、只读接入 |
| **可证** | 能证明镜像与原始检材逐位一致 | 制作时同步计算哈希 + 日志 |

翻车都集中在这三处：选错源设备（系统盘当数据盘，或者 `if=` 与 `of=` 写反直接把检材覆盖掉）、裸拷贝不做哈希（事后补不回来）、忽略源盘正在被系统使用（在线制作时文件系统还在写，镜像内部自相矛盾）。

`if=` 与 `of=` 写反会改变读写方向。命令行上这两个参数长得几乎一样，写反了就是把镜像内容直接写进原始检材。这不是"镜像做得不对"，是检材被永久销毁。这条属不可逆操作，本篇 4.1 组专门处理它——命令里没有第二个确认机制能救你。

**本篇处理的证据形态**是"原始介质 → 镜像文件"这一段，产出物通常是 `DigiForensics.dd`（RAW 裸镜像）或它的 E01 封装形式。RAW 与 E01 的差别不只是容器：E01 分段存储、每段自带哈希、支持压缩，代价是普通字节工具读不了。选哪个不是格式偏好，是后面工具链的事，见[证据格式与转换](imaging-acquire-evidence-image-formats.md)。

**在取证流程中的位置**：本篇是**采集**环节的主干，处在整个流程的最上游——后面所有环节的结论都建立在"这份镜像与原始检材一致"这个前提上，而这个前提只有本篇能建立。**上游依赖**是硬件层面的准备，见[取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md)（接驳顺序、型号选型、耗材）；授权与委托手续见[合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md)与[证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md)。**下游**分两条路：离线场景直接进[只读挂载与安全接入](../imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)；在线场景（系统还在跑）走本板块的[远程勘验与在线取证](imaging-acquire-remote-evidence-collection.md)——关机动作会销毁内存里的一切，这条岔路必须在动手前就想清楚。

**本篇的处置主链**是六步，其中第 5 步不可跳过：

| 步骤 | 动作 | 产出 | 什么时候就该停 |
|---|---|---|---|
| 1 | 环境准备与源设备识别 | 设备型号、容量、序列号、分区表 | 设备数量与预期不符时先停下来核对 |
| 2 | 图形化工具制作（Windows 首选） | 带哈希的镜像 | — |
| 3 | 命令行制作（Linux 首选） | 同上，`dcfldd` 可断点续做 | — |
| 4 | E01 格式制作 | 分段镜像 + 每段哈希 | — |
| 5 | **验证** | 镜像哈希、坏扇区统计、抽样比对 | **哈希对不上就不要进入分析阶段** |
| 6 | 记录与封存 | 保管链记录、原始检材处置 | — |

第 5 步是唯一不能妥协的一步。它不只是"算一下哈希"，还包括坏扇区数量的统计、镜像头部与原始设备分区表的比对、以及至少一次内容抽样。

哈希对不上却继续做完整分析，是这个领域最昂贵的错误之一：你会花几天得出一个基于损坏数据的所有结论，然后在报告阶段发现全部作废。

第 1 步也值得单说：**源设备识别错一次的代价，远大于后面每一步的总和。** 笔记本有几块盘、RAID 有几个成员、SD 卡插在读卡器上还是直接挂载、NVMe 会不会被识别成普通块设备——动手前用 `lsblk` / `fdisk -l` 核对一遍，成本是三分钟。

原始检材的完整内容、逐扇区无遗漏、镜像与原件逐位一致、镜像的哈希值与制作时间线、以及镜像里有多少坏扇区（及其分布规律——连续坏簇通常指向物理损伤，零散坏扇可能来自写入时已存在的老化）。

**做不出时间线**——镜像是时点快照，它记录"关机那一刻是什么样"，不记录"这半年里发生过什么"；**拿不到易失证据**——内存、页交换、运行中的进程状态、当前网络连接、磁盘缓存，这些在关机瞬间就消失了，需要在线手段（见[远程勘验与在线取证](imaging-acquire-remote-evidence-collection.md)）；**RAID 阵列必须拆开处理**，把它当单盘只会得到一堆无意义的碎片；以及**闪存的逻辑块与物理块不对应**（FTL 映射与磨损均衡），这意味着"扇区号"在闪存介质上不是一个稳定的物理地址概念。

**读者前提**：你需要熟悉 `fdisk -l` / `mmls` 的分区表输出、能读懂设备命名（`/dev/sd*` vs `/dev/nvme*` vs `/dev/mapper/*`），并且清楚 `if=` 与 `of=` 写反会直接销毁证据。第一次做实体检材之前，建议先在虚拟磁盘上把整条命令链跑一遍。镜像做出来之后，接下来的只读分析见[只读挂载与安全接入](../imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md)与[虚拟机仿真](../imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md)。

镜像是**时点快照**，它能证明"关机那一刻盘上是什么样"，不能证明"这半年里发生过什么"。时间线的绝大部分内容需要从元数据、日志、注册表里重建，而不是从镜像的拍摄时间推断。那些需要跨源合并、归一化基准、标注置信度的工作，见[时间线重建](../../computer/computer-log/computer-log-linux-timeline-reconstruction.md)。

最后一条，也是本篇唯一不能妥协的纪律：**哈希必须在制作时算。** 事后对镜像文件算一遍哈希，只能证明"这个文件现在没变"，证明不了"它采集时就是完整的"——因为你不知道采集过程中是不是已经有扇区读不出来、被工具跳过了。这两句话在法庭上的分量完全不同，而区分它们只需要在制作时多按一个参数。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 物理镜像 vs 逻辑镜像

| 维度 | 物理镜像（Physical） | 逻辑镜像（Logical） |
|---|---|---|
| 采集对象 | 整块设备的扇区序列 | 某个卷 / 文件 / 目录 |
| 包含分区表 | 是 | 否 |
| 包含未分配空间 | 是 | 否 |
| 包含删除文件残留 | 是（视文件系统而定） | 否 |
| 丢失分区间隙 | 否 | **是** |
| 取证价值 | 最高，可做全盘时间线 | 有限，工具兼容性差 |

> **实战原则：默认永远做物理镜像。** 只有在特殊场景（虚拟化、存储池、单卷容量远超可用存储）才考虑逻辑镜像，且必须在报告中明确标注这是逻辑镜像。

逻辑镜像会丢掉"分区之间的间隙"（gap between partitions）。攻击者藏数据的经典位置恰恰包括 MBR 末尾到第一个分区之间、分区表之间的空隙、以及分区末尾到磁盘末尾。未分配空间是反取证软件的默认藏身处。

<a id="section-4"></a>

### 2.2 写保护的三种层次

| 层次 | 手段 | 可靠性 | 说明 |
|---|---|---|---|
| **硬件写保护** | 写保护器（Write Blocker） | ★★★★★ | SATA/USB/PCIe 专用型号，物理层面阻断写信号 |
| **系统只读** | `losetup -r`、`blockdev --setro` | ★★★★ | 依赖 OS 与驱动，无法防御恶意代码 |
| **软件约定** | "我们小心点不写" | ☆ | **不可依赖** |

关键认识：如果原始检材已被挂载过、或电脑上运行过未知程序，那么软件层面的只读就失去意义——恶意代码可能已在内核驻留。此时唯一补救是：立刻断电、停止使用该机、用硬件写保护器保护"剩余状态"，并在报告中如实记录"检材固定前已被使用"。

**主控也是一条污染路径**：SSD 主控会记录访问日志（下单时间、常用软件，甚至残留的快递面单信息），有时比磁盘内容更能证明设备来源。这就是新购专用硬盘盒比现成 USB-SATA 桥接芯片更可靠的原因。

<a id="section-5"></a>

### 2.3 直连方式的选择

| 方式 | 适用 | 风险 | 说明 |
|---|---|---|---|
| **主板直连** | SATA / M.2 / NVMe | 最低 | 需拆机，速度与稳定性最佳 |
| **专用硬盘盒（信封盒）** | 已封存设备的临时读取 | 低 | 确认盒容量与协议支持；**主控可能有缓存** |
| **USB 转 SATA 廉价桥接** | 2.5" 小容量 SATA | 中高 | **主控可能延迟落盘**，掉电即数据不一致 |
| **USB 直连移动硬盘** | 移动盘/U盘 | 中 | 容量多在 2 TB 以下；桥接行为不可控 |

**识别不可靠桥接的关键**：制作完成后断开重连，再次验证哈希。两次读到的内容不同，说明设备内部有缓存或落盘问题，该介质不可信。

**NVMe 注意**：SATA 写保护器接不了 NVMe（协议不同，不是接口外形问题），需 PCIe 转接 + NVMe 专用写保护方案。

<a id="section-6"></a>

### 2.4 多盘与 RAID：绝对不能当作单盘

服务器和台式机常见双盘、RAID 0/5/10，这是**新手最容易造成无法挽回损失**的场景。

| 阵列类型 | 制作方式 | 能否逐盘分析 |
|---|---|---|
| RAID 0 / 10 | 逐盘制作，**必须记录盘序** | 需重组后分析 |
| RAID 1 | 任意一盘可单独使用（内容相同） | **可以** |
| RAID 5 | 逐盘制作，记录 N+1 全部盘 | 需重组 |
| 硬件 RAID（带缓存+BBU） | ⚠️ **先断电再拆**，否则缓存未落盘 | 需厂商工具重建 |
| SSD 阵列 | 每块盘可能是独立卷或 RAID 分区 | 用 `mmls` 逐盘确认 |

**硬件 RAID 卡的严重陷阱**：RAID 卡通常带 512 MB–4 GB 写缓存，靠电池（BBU）或电容维持。断电前取下硬盘，缓存中的数据全部丢失且不可恢复——这些数据往往正是最近几分钟的写入。正确做法：接上 RAID 卡并正常关机，让缓存安全刷盘；确认缓存已 flush（LED 状态或厂商工具）后再拆盘。软件 RAID（mdraid / ZFS / btrfs） 的处理见第 10 篇服务器取证。

<a id="section-7"></a>

### 2.5 制作时机与哈希计算

| 场景 | 做法 | 内存证据 | 一致性风险 |
|---|---|---|---|
| 可关机且有授权 | 正常关机后断电 | 丢失 | 低（有干净关机记录） |
| 可关机但要求保内存 | 休眠（hibernate）后搬走 | **保留** | 中（`hiberfil.sys` 存在） |
| 不可关机（如服务器在跑业务） | 热插拔/在线镜像 | 保留 | **高**（文件系统持续变更） |
| 现场服务器 | 内存采集 + 热镜像 + 逻辑采集 | 保留 | 最高 |

**休眠是关机与保持内存之间的最佳折中**：系统把内存完整写入 `hiberfil.sys` 后断电，既保住内存内容，又避免非正常断电对文件系统一致性的破坏，事后可从 `hiberfil.sys` 还原。注意 Windows Server 2008 R2 及更早版本默认禁用休眠。

**哈希必须在制作时同步算**。对 500 GB 磁盘单独跑一次 SHA-256 需完整读盘一遍；先 `dd` 再 `sha256sum` 就是读盘两次。`dcfldd` 的价值在于数据从源盘读进内存块的那一刻同步计算哈希再写出——磁盘 I/O 是瓶颈，内存运算几乎免费，哈希等于白送。

`hashconv=before` 表示对**源数据**（转换前）计算，取证场景应始终用它，因为要证明的是原始检材的指纹。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：环境准备与源设备识别（Ubuntu/Debian）

在动手前把"哪个设备是检材"确认三遍。**接入前**先跑一遍 `lsblk` 作为基线，**接入后**再跑一遍做对比——这样能证明"我接入的设备就是新出现的那个"：

```bash
# 1) 安装工具
sudo apt update && sudo apt install dcfldd ewf-tools sleuthkit

# 2) 接入前基线快照
lsblk -o NAME,SIZE,MODEL,SERIAL,RO,TYPE,MOUNTPOINTS | tee /evidence/lsblk-before.txt

# 3) 接入检材（通过写保护器）

# 4) 接入后再次快照并与基线 diff
lsblk -o NAME,SIZE,MODEL,SERIAL,RO,TYPE,MOUNTPOINTS | tee /evidence/lsblk-after.txt
diff /evidence/lsblk-before.txt /evidence/lsblk-after.txt
```

`RO` 列是关键。显示 `1` 说明内核已把该设备标记为只读；若显示 `0`，说明写保护器没有正确工作。容量、型号、**序列号**三者与勘验记录全一致后，再确认它没有被挂载——`findmnt --source /dev/sdb` 应该输出为空。

<a id="section-10"></a>

### 3.2 第 2 步：FTK Imager 图形化制作（Windows 首选）

FTK Imager 是司法鉴定领域使用最广的采集工具之一（**闭源、免费分发**，商业公司维护），优势在于**操作留痕完整**（自动生成日志）和**多设备并发采集**。

1. `File` → `Add Disk Image...` → 选 `Device` 类型 → 选中物理盘（**选 `Physical Drive`，不是分区**）
2. 填写 `Case Number`、`Evidence Number`、`Unique Description`、`Examiner`——**不要留默认值**，这四项是案件报告的直接引用源
3. `Destination Path` 选证据目录，`Image Type` 选 `Raw Device (dd)` 或 `E01`
4. 勾选 `Verify image after creation`（**必勾**），然后 `Start`

设备列表里物理盘显示为 `PhysicalDrive0`、`PhysicalDrive1`，分区则显示为盘符，**选错是新手最常见的事故**。在 `Evidence Device Information` 区域勾选 `Create evidence image of multiple devices`，单个 capture 任务即可采集多块盘并自动编号（`DigiForensics.E01`、`DigiForensics_1.E01`）——这对多盘服务器和 RAID 阵列尤其有价值。

制作完成后还可用 `File` → `Verify Disk Image` 单独再验一次，该操作重读镜像并与 E01 头中存储的哈希比对。

<a id="section-11"></a>

### 3.3 第 3 步：dcfldd 命令行制作（Linux 首选）

**基础制作（健康介质）**：

```bash
sudo dcfldd if=/dev/sdb of=/evidence/DigiForensics.dd \
  bs=4M hash=sha256 hashlog=/evidence/DigiForensics.dd.sha256 statusinterval=256
```

`bs=4M` 是现代介质的合理起点。健康介质用大块（1M–8M）提升吞吐；**有坏道的介质必须降到 512 或 4k**，否则一次坏道会连带丢掉周围 4 MB。

| 参数 | 作用 | 关键点 |
|---|---|---|
| `conv=noerror` | 遇读错误继续，不中止 | **不写这个参数，盘一坏就整个中断** |
| `conv=sync` | 出错块补零，保持输出**偏移对齐** | 不写会导致后续所有数据错位 |
| `errlog=` | 错误详情写入日志 | 这是**唯一的坏道位置记录** |
| `vf=` | 事后逐字节复验源盘与镜像 | 替代"再跑一遍 sha256sum"，可发现所有差异 |

> **`conv=sync` 为什么必须加**：dcfldd 以 `bs` 为单位搬运。若 `bs=4M` 时第 100 MB 处有 1 个坏扇区，不加 `sync` 它可能只读了 4 MB − 1 扇区就跳过，结果是**输出从这一处整体前移 511 字节**，后面所有数据的偏移全部错误。`sync` 保证失败块被补零写满，输出长度与输入严格一致。这不是可选优化，是数据正确性的前提。

**纯 GNU `dd` 备选方案**：`dcfldd` 未安装时可用 `dd`，但要手动补齐它的三项核心能力——续错、补齐、记录错误：

```bash
sudo dd if=/dev/sdb of=/evidence/DigiForensics.dd bs=4M \
  conv=noerror,sync status=progress \
  iflag=direct 2>>/evidence/DigiForensics-dd.err
sha256sum /evidence/DigiForensics.dd | tee /evidence/DigiForensics.dd.sha256
```

`conv=sync` 的语义与 `dcfldd` 完全一致；`iflag=direct` 让内核**绕过页缓存、直接读块设备**，避免读到已被缓存的旧数据。但它挡不住其他进程同时写这个设备——写保护器才是唯一的保证。

代价是 dd 无法在采集过程中算哈希，只能事后补一次读盘。`dcfldd` 存在的意义就在这里。坏道多时优先用 `ddrescue`。

分区镜像与双份同时制作（`of=` 可出现多次，只读源盘一次，显著拖慢速度）的命令见第七节。

<a id="section-12"></a>

### 3.4 第 4 步：ewfacquire 制作 E01 格式

当案件需要压缩、分段、元数据规范化时用 E01。完整调用见第七节，此处只解释关键参数：

| 参数 | 含义 | 要点 |
|---|---|---|
| `-t` | 目标文件名（**不带扩展名**） | 工具自动加 `.E01` |
| `-f encase6` | EWF 格式版本 | EnCase 6/7 支持 >2 GB 的分段 |
| `-c deflate:best` | 压缩算法与级别 | 可选 `none`/`empty-block`/`fast`/`best` |
| `-d sha256` | 额外计算 SHA-256 | MD5 是 E01 默认摘要，**建议两个都算** |
| `-S 2G` | 分段大小 | 见第 02 篇详解 |
| `-m` / `-M` | 介质类型 / 逻辑物理 | 物理盘用 `physical` |
| `-b 64` | 每块读取扇区数（×512 B = 32 KB） | 这就是 E01 的 chunk 大小 |
| `-g 64` | 错误粒度（扇区） | 读失败时补零的范围 |
| `-r 3` | 读错误重试次数 | 默认 2，老盘建议加大 |
| `-l` | 日志（**同时记录哈希**） | 事后审计依据 |
| `-u` | 无交互模式 | 所有参数必须给全，否则报错 |

**`-u` 的坑**：无交互模式下任何参数缺失都会直接失败，而不是提示默认值。报参数错误时，去掉 `-u` 手动跑一遍，把被问到的项补上再切回无交互。

从已有 dd 镜像转 E01 时（见第七节命令），源参数用**文件路径**而非设备路径，转换后必须验证两边哈希一致。格式选择的取舍见[证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md)。

<a id="section-13"></a>

### 3.5 第 5 步：验证（不可跳过）

三条验证命令见第七节。**通过标准是三条同时满足**：命令返回 0、复算哈希与制作时的 `hashlog` 字符串完全一致、`ewfverify` 报告 MD5/SHA-256 均为 success。

**坏道介质要特别注意**：源盘存在读错误时，重读一次得到的数据**可能与第一次不同**——扇区是"间歇性坏"而不是"永久坏"。这属于介质的物理状态，与你的操作无关。正确做法是以第一次的采集结果为准（它有完整哈希记录），并把 `errlog` 中的坏扇区位置作为"该区域数据不可靠"记录在案。

<a id="section-14"></a>

### 3.6 第 6 步：记录与封存

```bash
sudo chmod 444 /evidence/DigiForensics.dd
sha256sum /evidence/DigiForensics.dd > /evidence/case-manifest.txt

# 勘验日志必记项：
#   证据编号 / 源设备序列号 / 容量 / 制作时间（UTC）/ 工具与版本
#   写保护器型号 / 源哈希 MD5+SHA-256 / 坏扇区数量 / 保管人交接签字
```

---
<a id="section-15"></a>

## 四、常见陷阱

本章按**操作阶段**归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会**导致原始检材永久灭失或不可逆改变**，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 命令与方向：把检材写没了

<a id="section-17"></a>

#### 陷阱 1：`if=` 与 `of=` 写反 ★★★

**现象**：执行 `dd` 或 `dcfldd` 之后，原始硬盘变成全零或一片空白，原本盘上的数据不复存在。

**原因**：`dd if=源 of=目标` 的语义是**从源读到目标**。两个参数的视觉位置完全对称，写反了在语法上没有任何报错——`dd` 照常执行、照常输出进度、照常在结尾打印「记录了 8388608+0 字节」。程序不会告诉你写反了。更隐蔽的情况是有人用 `if=/dev/zero of=/dev/sdb` 来「清零」某块盘，这确实会写坏目标盘，但它与取证需要的操作恰好方向相反。

**影响**：这是镜像制作环节唯一会直接销毁检材的错误，且不可逆。 硬盘被覆写后，原始数据在物理上不再存在，案件证据永久灭失。

写保护器接在源盘上，保护的是**源**盘。如果误把 `of=` 指向了源设备（比如把 `/dev/sdb` 和 `/dev/sdc` 记混），写保护器根本不起作用——它挡不住「你主动往它身上写」。

**核查**：**执行前把整条命令当成句子念一遍**——「从 `/dev/sdb` 读取，写到 `/mnt/evidence/case01.E01`」。念顺了再执行。实测有效的三道防线：

```bash
# 1) 核对源设备：容量 + 型号 + 序列号三项全对才动手
lsblk -o NAME,SIZE,MODEL,SERIAL,ROTA,TYPE
#    只读命令，不碰数据；ROTA=1 是旋转盘，USB 移动硬盘常为 0

# 2) 核对目标：必须是文件路径，绝不能是块设备
readlink -f /mnt/evidence/case01.E01     # 确认解析后不在 /dev 下

# 3) 先小容量试跑：用 count=1 跑一个块，确认方向正确再跑全盘
dcfldd if=/dev/sdb of=/tmp/probe.E01 bs=512 count=1 hash=sha256
file /tmp/probe.E01                        # 应显示磁盘镜像特征而非全零
```

**记住一项要求**：`of=` 的值**永远是文件路径**。如果命令里 `of=` 后面是 `/dev/` 开头的设备节点，那就是在往裸设备上写，必须停下来。

<a id="section-18"></a>

#### 陷阱 2：把已挂载的源盘直接做成镜像

**现象**：镜像做完了，但源盘在制作期间仍在运行、仍在被系统使用。做出来的镜像内部自相矛盾——目录项说有某个文件，数据区却读不到对应内容。

**原因**：**文件系统是活的。** 镜像制作要几十分钟到几十小时，这期间源盘上的数据库在写、日志在追加、临时文件在创建。

`dd` 逐扇区读出来的不是某个时刻的一致快照，而是一段时间内不同扇区的混合体。最典型的是 ext4 的 journal 提交点：日志区可能已经反映了第 N 次事务，数据区还是第 N−1 次的状态。结果是一份内部不一致的镜像，解析器读出看似合理但实际错误的内容。

**影响**：**这类镜像的欺骗性极强**——它不报错，`fsstat` 能正常识别文件系统，文件能列出，只是内容可能是错的。分析人员基于它做的所有结论都不可靠，而报告中没有任何地方标明这份镜像存在一致性问题。

更糟的是，若原本打算写进报告的「未发现 X」结论来自这份镜像，那就是一个无法辩护的错误阴性结论。

**核查**：**制作前确认源盘没有挂载、没有正在运行的文件系统。** Linux 侧：

```bash
# 确认目标设备未被挂载
findmnt -S /dev/sdb
# 有输出 = 已挂载，必须先卸载

# 确认没有进程占用（lsof 最直接）
sudo lsof /dev/sdb
sudo fuser -vm /dev/sdb

# 若确实无法卸载（在线系统），改用热镜像方案并记录不确定性
```

**在线场景的替代方案**：使用文件系统级快照（LVM snapshot、ZFS snapshot、Btrfs subvolume snapshot）先冻结出一个一致点，再对快照做镜像。这仍然不是"物理证据"，报告里必须明确说明取证时源系统处于在线状态、镜像是应用层一致性而非物理一致性。

<a id="section-19"></a>

### 4.2 源设备识别与接入

<a id="section-20"></a>

#### 陷阱 3：只按容量和型号选盘，漏了序列号

**现象**：接了两块同型号同容量的硬盘，取了"看起来对"的那块，事后发现取错了。

**原因**：**同型号同容量是常见组合，不是唯一标识。** 两个 1 TB 的同型号笔记本硬盘在 `lsblk` 里除了序列号之外几乎一样。而在真实的取证场景里，"这块盘是 A 机器的"这个判断，往往**只有序列号能证明**。

容量相同的两块盘（甚至是不同品牌的）都在同一批采购清单上时，仅凭容量和型号做出选择，本质上是猜测。

**影响**：**镜像了错误的检材，且往往要到分析阶段才会发现。** 浪费的不只是几小时的镜像时间——如果原检材被这次操作改变了状态（比如挂载过、或者后续分析中被写），而真正的检材还没镜像，就已经产生了证据污染。

更严重的情况是：两块盘都做了镜像，但因为标识混乱，报告里把 A 盘的证据归到了 B 盘名下，**证据与主体的对应关系整体错乱**。

**核查**：容量 + 型号 + 序列号三项全对才动手，并在工作记录里留下 `lsblk` 的原始输出。 三项的作用不同，缺一不可：

| 项 | 能证明什么 | 不能证明什么 |
|---|---|---|
| 容量 | 大致排除明显不匹配的盘 | 无法区分同容量盘 |
| 型号 | 设备类别一致 | 同一型号有多个个体 |
| **序列号** | **唯一标识这块物理盘** | 需要有可信来源可比对 |

**序列号的可信来源**：委托方提供的设备照片、采购记录、设备标签、此前一次采集的记录。没有任何外部来源可比对时，序列号只能作为内部标识，不能作为归属证明。这条限制要写进报告。

<a id="section-21"></a>

#### 陷阱 4：USB 直连与硬盘盒接错，镜像静默截断

**现象**：镜像制作中途 USB 连接断开，`dcfldd` 报了错误但制作流程被当作"已完成"继续，或者更糟——没有报错，但镜像文件比源盘小。

**原因**：USB 供电不足、线材规格不够、硬盘盒掉盘，都会导致传输中断。命令行的失败模式依工具而异：`dd` 会在读错误时输出统计信息但默认继续；`dcfldd` 有更完善的错误处理但也不是所有情况都会中止。

更隐蔽的是"静默截断"——某些情况下连接断开后进程已经退出，输出文件就是"到断开为止那部分"，而命令的退出码可能仍为 0。

**影响**：**一份不完整的镜像比没有镜像更危险。** 没有镜像，分析人员知道要重新采集；一份少了几百 GB 的镜像会被正常打开、正常解析、正常分析，直到某处需要读取尾部数据时才失败。

更糟的是，如果截断部分正好是被删除文件所在的位置，报告会得出「该区域无数据」的结论——而实际是「没采到」。

**核查**：**制作后用容量与哈希两道验证**：

```bash
# 1) 容量核对：镜像字节数应等于源盘容量（dcfldd 会自动填充末尾）
lsblk -b -o NAME,SIZE /dev/sdb
stat -c%s /mnt/evidence/case01.E01

# 2) 复验哈希：这是唯一可靠的完整性判据
dcfldd if=/mnt/evidence/case01.E01 of=/dev/null bs=1M hash=sha256
#    与制作时记录的 hashlog 比对，不一致必须重做

# 3) USB 稳定性不足时的加固
#    - 换电源供电的硬盘盒（不要用总线供电）
#    - 用带屏蔽的线材，缩短线长，避免 USB 集线器
#    - dcfldd 相比 dd 对 USB 断连的处理更完善，优先选它
```

关键认知：哈希复验是唯一能证明"镜像完整"的手段。容量相同只说明"读到了那么多字节"，不证明"读到的内容正确"。

<a id="section-22"></a>

### 4.3 坏扇区与介质缺陷

<a id="section-23"></a>

#### 陷阱 5：坏道盘用大 `bs` 且忘了 `sync`

**现象**：对有坏扇区的老盘做镜像，镜像文件出现整体错位——文件结构解析出来是乱的，字符串在错误的位置。

**原因**：`dd` 默认遇到读错误时会**跳过该块并继续**，且不做任何标记。默认 `bs=512` 时跳过 512 字节，勉强能保持后续数据不错位；但很多教程为了提速建议用 `bs=4M`——当 4 MB 的块里某一扇区坏了，`dd` 会跳过整个 4 MB，后续所有数据**整体前移 4 MB**，镜像完全错位。

`conv=noerror,sync` 中的 `sync` 正是用来补齐这块空缺的，但很多人在 `bs` 改大后忘了加 `conv`。

**影响**：一份错位的镜像，其内容看起来是"另一块盘的数据"。 解析器不会报错——它只是把错位后的字节当作文件结构来读，产出大量看似合理的垃圾。

报告中如果基于它写了「未发现目标文件」，实际是「该区域被跳过了」。跳过的数据量在坏盘上可能相当可观。

**核查**：有坏扇区一律用 `bs=512 conv=noerror,sync`，并且记录坏扇区数量。

```bash
# 标准写法
dcfldd if=/dev/sdb of=/mnt/evidence/case01.E01 \
       bs=512 conv=noerror,sync hash=sha256 hashlog=/mnt/evidence/case01.hashlog

# bs 必须保持 512：conv=sync 的补齐是以块为单位，块大于扇区就会错位
# conv=noerror  读错误时继续，不中止
# conv=sync     读错误后补零到块边界，保证后续数据不错位
```

**坏扇区数量必须进报告**：制作完成后读哈希日志，统计其中记录的坏区数量：

```bash
grep -c '^bad' /mnt/evidence/case01.hashlog
```

报告里要写明：「采集过程中检出 N 个不可读扇区（占 0.00X%），已用 `conv=noerror,sync` 跳过并补零。涉及这些扇区的数据区域无法恢复。」 这是一个必须交代的证据缺口，不是可以略过的技术细节。

<a id="section-24"></a>

### 4.4 RAID 与多盘系统

<a id="section-25"></a>

#### 陷阱 6：把 RAID 当单盘做 / 带电拆盘

**现象**：镜像数据是乱的，文件完全无法解析；或者拆盘后某个盘再也无法初始化。

**原因**：RAID 阵列对外呈现为一个逻辑设备，但数据是**条带化分散**在多个物理盘上的。单独读一块盘拿到的是碎片。

更关键的是硬件 RAID 卡的写缓存：正常关机时，缓存里的数据会回写到物理盘；带电拔盘或强制断电，缓存里的数据永久丢失——即使数据"在 RAID 层面已经写成功"。

**影响**：**缓存未落盘导致的数据丢失是完全不可逆的。** 这是"物理灭失"级别的损失，且发生在你以为已经成功导出数据之后。此外，把阵列当单盘采集得到的碎片镜像，会让分析人员浪费大量时间去"修复"一个根本不可能修复的东西。

**核查**：**先判断是否 RAID，再决定采集策略：**

```bash
# 1) 识别阵列类型
cat /proc/mdstat                    # Linux 软件 RAID（mdadm）
lspci | grep -i raid               # 硬件 RAID 卡
storcli /c0 show all               # Broadcom MegaRAID
megacli -LDInfo -Lall -aAll        # LSI
```

```bash
# 2) 硬件 RAID：正常关机让缓存落盘，绝不热插拔
sync
#   逐盘关机（各厂商工具命令不同），等待缓存清零
storcli /c0/v0 shutdown all
#   确认 BBU/缓存状态为 Clean 或 Safe to replace 后再拆

# 3) 软件 RAID（mdadm）：可以在线逐盘镜像，但要按同一时刻采集
#    采集后用 mdadm --assemble 重组，或用 mdadm 导出后在离线环境重组
mdadm --detail /dev/md0
mdadm --examine --scan
```

**软件 RAID 的替代方案**：如果任务是"看到文件内容"而非"重建原始阵列"，可以只读挂载阵列并用工具做文件级提取（`photorec`、Sleuth Kit 的逻辑提取），这能得到可用数据但不是物理证据，报告里要说明采集方式。

<a id="section-26"></a>

### 4.5 验证与记录

<a id="section-27"></a>

#### 陷阱 7：漏掉 verify 就交付 ★

**现象**：镜像做完直接交付分析，直到司法程序或复核环节才被问起「怎么证明镜像与检材一致」。

**原因**：镜像制作是一个**长耗时、跨设备、跨驱动的复制过程**——源盘读、总线传输、内存缓冲、目标盘写，任何一环都可能出问题。跳过验证等于假设"没报错就是成功了"，而复制过程里最典型的失败模式恰恰是不报错。

很多工具在制作时会自动算哈希，但"记录了哈希"和"验证了哈希"是两件事——前者只是把一个数写下来，后者才是把这个数和原始检材重新比一遍。

**影响**：在需要举证的场景下，一份未经验证的镜像的证据价值接近于零。 更具体的风险是：当分析结论被质疑时，你无法回答"镜像数据是否与原始检材一致"这个最基本的问题，而这个问题一旦被提出来，无法事后补救——当时没做，事后就没有证据了。

**核查**：验证是交付前的强制步骤，且必须用独立工具重新读一遍镜像：

```bash
# E01：ewfverify 完整回读校验
ewfverify -q /mnt/evidence/case01.E01

# raw（dcfldd 制作）：重新读一遍并重算哈希
dcfldd if=/mnt/evidence/case01.E01 of=/dev/null bs=1M hash=sha256
#   与 hashlog 中的值比对

# 一次通过才算合格；报告里写明验证时间与结果
```

**验证记录必须包含**：镜像文件名、哈希算法、哈希值、制作时间、验证时间、验证工具与版本、验证结果。这六项缺一不可——只有哈希值没有验证时间，无法证明"验证过"；只有验证时间没有工具版本，无法复现。

<a id="section-28"></a>

#### 陷阱 8：事后才做哈希

**现象**：镜像制作完成后再单独跑一遍 `sha256sum` 计算哈希。

**原因**：**单独计算哈希需要把整个镜像文件再完整读一遍**，对于一块 2 TB 的盘，读取本身就是几十分钟到几小时的耗时，且占满 I/O。更重要的是，事后计算哈希证明的是"镜像文件现在的哈希"，而制作过程中的哈希日志记录的是"从源盘读出、写入镜像的每个块的实际内容"——后者才是证明采集过程未出错的依据。

两者目标不同：前者防镜像文件被改动，后者防采集过程出错。

**影响**：**多花一整轮完整读盘的时间**，在批量案件中这是可观的成本。更实质的问题是**丢失了过程级证据**：`dcfldd` 的 hashlog 记录了每块的读写情况，如果过程中出现过读错误，hashlog 里会留下痕迹，而事后计算的哈希完全看不出这些。

**核查**：制作时同步计算哈希，把 hashlog 当作交付物的一部分：

```bash
dcfldd if=/dev/sdb of=/mnt/evidence/case01.E01 \
       bs=4M hash=sha256 \
       hashlog=/mnt/evidence/case01.hashlog      # 关键：过程记录
```

`hashlog` 里除了最终哈希，还有每块的详细信息。这个文件本身就是"采集过程未出错"的证明材料，必须与镜像一起归档，不能只留最终哈希值。

<a id="section-29"></a>

#### 陷阱 9：只做一份镜像就开始分析

**现象**：把唯一一份镜像直接挂载、提取、跑分析工具，之后需要复核时已经无法回到原始状态。

**原因**：**分析过程几乎必然产生写入。** 挂载可能更新访问时间、文件系统检查可能修复结构、某些工具会写临时文件到挂载点、carving 工具的错误恢复可能在源文件系统上留下痕迹。

很多人以为"只读挂载就安全"，但"只读"这个属性会不会被遵守，取决于挂载参数和文件系统实现——某些情况下降级为读写。

**影响**：丧失复核能力是次要的，最严重的是原始镜像被污染后无法自证。 当案件进入对抗环节（申诉、庭审、上级审计），你需要重新提供"未经分析的原始镜像"来验证结论。只有一份镜像且已被分析过，你手上就不再有符合要求的证据。

这个错误在案件早期几乎必然发生，因为"省事"的压力最大。

**核查**：**主副本 + 工作副本双份，从一开始就分开**：

```bash
# 主副本：只读封存，永不挂载
mount -o ro,loop,noatino /mnt/evidence/case01.E01 /mnt/readonly
chmod 444 /mnt/evidence/case01.E01
chattr +i /mnt/evidence/case01.E01     # 防误删（ext 系列）

# 工作副本：所有分析都在这里做
cp --reflink=auto /mnt/evidence/case01.E01 /mnt/work/case01-work.E01
#   reflink 在支持的文件系统（Btrfs/XFS）上几乎是瞬时的，不占额外空间

# 制作时直接产出两份，也可以在源头就分开
dcfldd if=/dev/sdb of=/mnt/evidence/case01-master.E01 hash=sha256
dcfldd if=/dev/sdb of=/mnt/work/case01-work.E01      hash=sha256
#   两份的哈希应完全相同，这个比对本身也是一次验证
```

**主副本存在的意义不是"备胎"，而是"自证"**——它证明你分析时看到的是原始状态，而不是被分析过程污染过的状态。没有主副本，任何复核都无从下手。

<a id="section-30"></a>

#### 陷阱 10：休眠状态下直接搬硬盘

**现象**：笔记本休眠后直接拆下硬盘，硬盘不认、报错，或后续读取时数据错乱。

**原因**：**休眠不是关机。** 休眠时系统把内存内容写入硬盘的休眠文件（Hiberfil.sys），并在此期间持续对硬盘进行读写——包括断电前的最后几次写入。

指示灯熄灭也不代表写入已经完成，缓存刷盘的时机由固件决定，不是由操作系统指示灯决定的。此时拔盘等于在写入过程中断电，可能损坏休眠文件，也可能损坏文件系统元数据。

**影响**：**这会损坏的是检材本身，不是你的镜像。** 笔记本的休眠文件与文件系统结构可能因此受损，导致数据不可读甚至完全无法挂载。如果这是唯一的检材，损失不可挽回。

**核查**：**优先级顺序是「关机」优于「休眠」：**

```text
第一选择：正常关机，等电源指示灯完全熄灭后再拆
    - 关机时系统会主动刷盘并给固件足够时间完成缓存回写
    - 部分机型还需按住电源键 10 秒强制断电以完全断电（见厂商说明）

第二选择：若必须休眠，休眠后至少等待 60 秒再拆
    - 观察所有指示灯（含电源、电池、硬盘活动灯）全部熄灭
    - 有条件的话，休眠后先唤醒一次确认能正常开机，再关机、等待、拆

绝对不要做：休眠状态下直接拔盘
```

**拆装前的最后检查**：电池电量充足（有些机型拆盘会断电）；准备好防静电措施；记录拆卸前的设备外观状态并拍照。
<a id="section-31"></a>

## 五、案例示例

<a id="section-32"></a>

### 5.1 不能停机的台式机：内存优先加在线热镜像

**场景**

查获一台企业台式机（Dell OptiPlex 7010，512 GB SATA SSD，Windows 10 Pro），涉及数据泄露需固定全部数据。企业要求保持运行以避免业务中断。委托方的问题有两个：内存里有没有还没落盘的东西，以及不停机做的镜像能不能用。

选择这一路径的依据是**内存采集必须在磁盘采集之前做**——业务一旦继续运行，最易失的东西会先消失，而停机要求又恰恰堵死了关机后补做的路。

委托方这两个问题其实是同一个约束下的死结：要内存就得不停机，不停机就只能做热镜像。分开回答会得到两份互相打架的证据。

**处置过程**

**第 0 步 · 先尝试只读锁定，失败也是证据**。不停机不等于不能只读，先把能关的门关上：

```bash
sudo blockdev --setro /dev/sdb      # 尝试置只读
findmnt --source /dev/sdb           # 挂载中的卷依然可写，只读标志不阻止文件系统写入
mount -o remount,ro /               # 对系统盘会因 busy 失败，失败输出留档
```

三条命令的输出无论成功与否都写进勘验记录。委托方事后多半会问"为什么不直接只读采集"，这段记录就是答案。

`blockdev --setro` 成功只说明**块设备层**拒绝写入，对已挂载文件系统不起作用——内核的页缓存与日志回写照旧。这条命令的真正价值是当证据：它证明你在采集前尝试过降低风险，而不是拿到设备直接开始拷。

同理，`mount -o remount,ro /` 对系统盘几乎必然失败（`target is busy`），失败信息同样要留档。三次尝试里两次失败、一次部分生效，这个结果本身就是"我们做了能做的"的最佳证明——比一次都没试、也没记，差距不在技术层面，在可辩护性上。

**第 1 步 · 现场固定**：记录设备序列号 `S3Z2NB0K`，拍照记录主机外观与线缆状态，用 `lsblk -o NAME,SIZE,MODEL,SERIAL` 确认 `SERIAL` 与勘验单一致。

**第 2 步 · 内存采集（先做，内存最易失）**，用预置 U 盘运行 WinPmem，输出到外接 USB，**绝不能写到被调查盘**：

```powershell
.\winpmem_mini_x64_rc2.exe D:\DigiForensics-mem.raw
certutil -hashfile D:\DigiForensics-mem.raw SHA256
```

**第 3 步 · 磁盘热镜像并同步计算哈希**，对已挂载的系统盘做在线镜像：

```bash
sudo dcfldd if=/dev/sdb of=/evidence/DigiForensics.dd \
  bs=4M conv=noerror,sync hash=md5,sha256 \
  md5log=/evidence/DigiForensics.dd.md5 \
  sha256log=/evidence/DigiForensics.dd.sha256 \
  statusinterval=1024 2>&1 | tee /evidence/DigiForensics-acquire.log
```

**第 4 步 · 验证**，用两条独立路径复核同一份镜像：

```bash
sudo dcfldd if=/dev/sdb vf=/evidence/DigiForensics.dd
sha256sum /evidence/DigiForensics.dd      # 与 sha256log 比对，必须完全一致
stat -c%s /evidence/DigiForensics.dd      # 与 lsblk -b 报出的 SIZE 比对
```

三条各自证明不同的东西，缺一条就留一个可争的口子：前两条证明内容一致，第三条证明没有静默截断——2 TB 盘少采 300 GB 时，哈希当然"一致"（因为算的就是这份不完整的文件），只有容量比对能发现。

**第 4b 步 · 内存的可用性也要当场验**，采完内存立刻抽一个已知结构验一下，别等分析阶段才发现采了个空壳：

```bash
python3 -m volatility3 -f DigiForensics-mem.raw windows.info
# 命中：Kernel 10.0.19041 / NtSystemRoot \Device\HarddiskVolume2\Windows
```

能报出 `windows.info` 的系统信息，说明 KDBG/DTB 块被正确识别，内存镜像不是一页黑。640 GB 内存一次 WinPmem 采集通常 20–40 GB，压缩后再测。

**第 5 步 · 对在线状态留下可复核的痕迹**。采集前后各取一次 USN 日志的状态，两份哈希都记录下来：

```bash
fsutil usn readjournal C: > /evidence/usn-head-before.txt
# ... 采集过程 96 分钟 ...
fsutil usn readjournal C: > /evidence/usn-head-after.txt
diff /evidence/usn-head-before.txt /evidence/usn-head-after.txt
```

`diff` 的输出长度本身就是"这 96 分钟里系统写了多少"的可量化证据。它也是后面判断镜像内部是否自相矛盾的参照物。

**第 6 步 · 报告里把两类证据分开列**。这份案子的产出物是四类东西，证据效力完全不同，混在一段里写是复核时最先被挑的地方：

| 产出物 | 载体 | 能支撑的结论类型 |
|---|---|---|
| `DigiForensics-mem.raw` | 内存，采自某一刻 | 运行态事实：进程、连接、句柄 |
| `DigiForensics.dd` | 热镜像，跨 96 分钟 | 已落盘文件的内容 |
| `usn-head-before/after.txt` | 两点快照 | 采集期间源盘确实在写 |
| `lsblk-before/after.txt` | 接入前后 | 检材标识未被误认 |

把这张表放进报告，比写一句"已完成内存与磁盘采集"有用得多——它同时告诉对方你知道自己拿到的不是什么。

**热镜像内部的自相矛盾是可检出的**。既然知道存在一致性问题，就该主动去找它的痕迹，而不是等复核方指出来。典型的矛盾形态是元数据指向了数据区里不存在的内容：目录项里有 `report.docx`，`icat` 取它的数据流却报越界。出现这种情况不要解释成"文件损坏"，先考虑它是不是采集窗口内刚被写入又删除的中间状态。

```bash
# 对可疑文件尝试取内容，越界即为不一致信号
icat DigiForensics.dd 894512 > /tmp/out.docx 2>/tmp/err.txt; cat /tmp/err.txt
```

这类记录同样有证据价值——它是"该文件在采集窗口内处于活动状态"的正面证据。

**这类"异常"要成对记录才有意义**。单独看到一个 `icat` 越界，可能是文件系统损坏、可能是解析器版本问题、也可能是热镜像的不一致。判断力来自成对的观察：一份正常文件（能取出内容）与一份越界文件（取不出）出现在同一个目录、同一个时间窗，这个组合的指向就清楚了。

```text
09:42  report.docx      icat 成功，内容可读，时间戳落在采集窗口内
09:43  temp_1a9f.tmp    icat 越界（数据运行块已释放）
09:43  ledger.db        icat 成功
```

一份可读、一份越界、夹在中间——**这比单独说"有个文件读不出来"要多出整整一层信息**，它指向的是"目录正在被写入"而不是"文件坏了"。

**结论**

能证明：`DigiForensics-mem.raw` 与 `DigiForensics.dd` 均有独立哈希，制作过程可复核，镜像字节数与源设备容量一致。

**不能证明**：**文件系统一致性**。在线镜像时系统盘处于挂载活动状态，读取过程中文件系统仍在演进，因此 `$UsnJrnl` 存在时间线断层——部分写入可能未落盘，个别目录项可能处于中间状态。

这一限制限制的是**依赖全局一致性的推论**，而非所有提取物；后者只要自身带独立哈希即可成立。实践中的分界线是：能落到具体文件内容上的结论照常下，需要断言"某一时刻全盘不存在某物"的结论要单独标注。

**误判对照**

最容易得出的错误结论是「热镜像哈希一致，说明这份镜像与检材状态完全对应，不存在一致性问题」。判据有三条：

①`vf=` 通过只比对 `dcfldd` 读出的字节流与 sha256log 中同一次读取的记录——两个值同源，都来自那次非事务性读取，不含任何"某一时刻全盘状态"的承诺；
②`conv=noerror,sync` 的作用域是**读取失败时的输出补齐**，它保证输出偏移不错位，与源盘上多个文件系统的并发写入毫无关系；
③采集耗时 96 分钟，USN 日志在首尾两个 `fsutil usn readjournal` 之间有新增记录，`diff` 输出非空即证明源盘在这段时间内确实在写。

按「哈希一致即状态一致」走，代价是把依赖全盘瞬时状态的推论写进报告——典型的是「该时刻目录下不存在此文件」。复核方只需指出热镜像特性与那份非空的 `diff`，整条推论即失去支撑，而"文件已删除"这类结论正是靠这类推论搭起来的。

**把结论分成三档写，是这类案子最省事的自保方式**：可以下的（单个已落盘文件的内容）、需要限定的（文件在此后某个时点存在过，依据 USN）、不能下的（全盘瞬时状态）。写报告前先给自己这三档分个类，比写完再被人挑出漏洞再回头改要快得多。

这三档的界线其实只有一个问题：这条结论依赖的观测，是在一个确定时刻做的吗？ 是的，进第一档；不是但有旁证，进第二档；两者都不是，就老实留在第三档别写。问自己一遍，比套用任何模板都管用。

<a id="section-33"></a>

### 5.2 未分配空间的 SQL 残留：用内存补上已丢失的路径

**场景**

同一案件的委托方想知道三段 SQL 备份残留是从哪里导出的、导出时间是什么时候。

选择这一路径的依据是**未分配空间里的数据只有内容，没有元数据**——要回答"从哪来、何时导出"，必须引入磁盘之外的时间线来源，而内存镜像恰好提供。

委托方真正要的是三段 SQL 残留的来源，而未分配空间里能给出的只有表结构和数据行。缺口是"谁在什么时候用哪台机器导出的"，这三点磁盘侧一个字都没写。

**处置过程**

1. 从未分配空间切出目标区域，不经过文件系统解析：

```bash
blkls -o 2048 /evidence/DigiForensics.dd > /tmp/ntfs-unalloc.bin
strings -n 20 /tmp/ntfs-unalloc.bin | grep -iE 'insert into|customer|backup'
```

2. 提取的内容里不含路径与时间，这两项都是缺失的——备份文件头不携带源库路径。

3. 转内存镜像找对应的命令行上下文：

```bash
python3 -m volatility3 -f DigiForensics-mem.raw windows.cmdline
# 命中：sqlcmd -S 10.20.3.21 -Q "BACKUP DATABASE crm TO DISK 'D:\jli\Downloads\crm_full.bak'"
```

4. 命令行只证明"尝试过"，还要在内存里找执行痕迹来确认它真的跑起来过：

```bash
python3 -m volatility3 -f DigiForensics-mem.raw windows.filescan | grep -i 'crm_full'
python3 -m volatility3 -f DigiForensics-mem.raw windows.pstree | grep -i sqlcmd
# 命中：DigiForensics... \Device\HarddiskVolume3\jli\Downloads\crm_full.bak 存在且句柄未关闭
```

5. `10.20.3.21` 是内网地址，"从哪来"还差一步——与本机的网络痕迹对齐，确认这台机器主动发起过连接：

```bash
python3 -m volatility3 -f DigiForensics-mem.raw windows.netscan
# 命中：10.20.3.21:1433  状态 ESTABLISHED  所属 sqlcmd.exe
```

6. 两类证据拼合：内存给出导出动作、源库标识、目标路径与网络对端，磁盘给出数据内容，缺的四项被补齐。

**这一步的价值在于两个来源的独立性**。内存与磁盘是两套独立的采集物，采集时间不同、采集机制不同、失败模式也不同。`crm_full.bak` 的数据内容在磁盘侧、`sqlcmd` 的命令行与连接在内存侧，两者要凑成同一个叙事必须先确认指向同一个文件名——本案的交叉点正是 `crm_full.bak` 这个字符串，它在 `windows.filescan` 里的路径与 `blkls` 提取物的内容特征一致。

如果只有磁盘证据，能证明的止于"盘上存在一段 SQL 数据"；如果只有内存证据，能证明的止于"有人执行过一条备份命令"。两条合起来才构成"这些数据是从 `crm` 库导出到这个路径的"。

**结论**

能证明：未分配空间中的 3 段 SQL 备份内容，来自对 `crm` 数据库的 `BACKUP DATABASE` 操作，导出目标路径为 `D:\jli\Downloads\crm_full.bak`，且该次导出曾建立到 `10.20.3.21:1433` 的连接。数据内容由磁盘提取物承载（含独立哈希），操作与路径由内存镜像支撑，两条来源独立。

**不能证明**：这三次导出是否成功完成。`sqlcmd` 出现在命令行历史里只说明**尝试过**——`pstree` 只能证明进程还活着、句柄还开着，无法区分"写完了"与"写到一半"。

**误判对照**

最容易得出的错误结论是「未分配空间里有一段完整的 SQL 表数据，这些数据属于本机数据库」。判据有三条：

①`BACKUP` 产生的备份文件带独立页结构与文件头，其中**不含源数据库的任何路径信息**——恢复出来的表里只有 `crm` 这一个名字，它既可能是源库名，也可能是目标文件名；
②`crm` 这个标识在磁盘上只有一个出现位置，而命令行里 `-S 10.20.3.21` 指向的是另一台主机，说明执行动作发生在远程，源库大概率不在本机；
③`netscan` 中该连接的属主是 `sqlcmd.exe` 而非浏览器或邮件客户端，工具形态与 `BACKUP DATABASE` 吻合，排除了"从外网下载的 SQL 脚本"这一竞争解释。

按「未分配空间里有数据 = 数据属于这台机器」走，代价是数据归属错误：本案若 `crm` 实为外部供应商的数据库，最终会把一份外购数据误判为本公司的客户资料泄露，直接影响责任认定方向；更麻烦的是这个错误方向很难自查——它不会在数据里留任何可推翻自己的痕迹。

<a id="section-34"></a>

### 5.3 反例：把采集输出直接写到被调查盘

**场景**

某次在线采集中，操作员把 `dcfldd` 的输出路径设在被调查盘所在设备上，采集运行 2 小时无异常，哈希日志也正常生成。事后复查才发现镜像文件就写在被调查盘的数据区内。这条列为反例，是因为**它不会产生任何报错**——采集看起来完全成功。

同类事故还有第二种形态：`of=` 指向了一个**符号链接**，而链接最终解析回源盘所在分区。命令里看不出问题，只有 `readlink -f` 才能揭穿。

**处置过程**

对照点在于输出路径的落点：

```bash
# 错误：输出落在被调查盘内
sudo dcfldd if=/dev/sdb of=/evidence/DigiForensics.dd   # /evidence 实际是 sdb 上的分区

# 危险变体：of= 是个链接，解析后仍回到源盘
readlink -f /evidence/current
# 输出 /dev/sdb2 —— 真实落点在被调查盘上，但路径本身看不出来

# 正确：输出到独立介质，采集前先确认两者不是同一设备
df -h /evidence /mnt/usb
readlink -f /mnt/usb/DigiForensics.dd | grep -q '^/dev/' && echo "危险：目标解析到块设备" && exit 1
sudo dcfldd if=/dev/sdb of=/mnt/usb/DigiForensics.dd
```

`df -h` 比对两块路径的挂载点是发现这类问题的最低成本手段：如果 `/evidence` 和 `/dev/sdb` 显示同一个挂载源，那输出就落在检材上。这条检查放在采集脚本的第一行，成本远低于事后排查。

还有第三种形态值得警惕：**同名镜像文件已存在**。`dcfldd` 默认覆盖输出，上一轮的镜像会被这一轮截断重写。如果上一轮是委托方自己做的、哈希还在他们手上，那么新镜像做出来之后，"原始那次采集"的凭据就没了——销毁证据不需要任何恶意，只要重跑一次。

```bash
# 采集前检查目标是否已存在
ls -l /mnt/usb/DigiForensics.dd 2>/dev/null && echo "目标已存在，确认是否覆盖" && exit 1
# 或指定新名字，保留旧件
sudo dcfldd if=/dev/sdb of=/mnt/usb/DigiForensics-2.dd
```

**结论**

阴性发现：该次采集的输出与源盘同处一个设备，**采集过程对被调查盘产生了写入**，写入量等于镜像体积——原文件系统状态已被覆盖。已镜像的部分（`blkls` 之前读过的扇区）内容与原件一致，这部分可用；被覆盖区域（通常从文件分配表中段起）数据不可恢复。

未覆盖范围是"哪些具体文件落在被覆盖区域"——判断这一点需要镜像制作前的目录快照，本案没有，因此这份缺口无法回填，报告里只能以"自采集起约 N GB 区域状态不明"表述。

**事故的真正教训不在技术层**。这次事故里，`dcfldd` 报的进度、耗时、字节数全部正常，`hashlog` 完整，`vf=` 通过，采集人员没有任何一个界面上的信号能提示出错。把"命令成功返回"当成"操作正确"是这类事故的共同根因——而唯一能防住它的动作，发生在按下回车之前。

**误判对照**

最容易得出的错误结论是「哈希验证通过说明镜像没问题」。判据有三条：

①`sha256log` 记录的是 `dcfldd` 读出并写入输出的那段字节流，**它不包含源盘被覆盖区域的信息**——源盘上发生的是"读旧数据、覆盖新数据"，哈希能证明前者，读不出后者；
②`vf=` 复验比对的两个对象同源，一个是镜像文件，一个是采集时的日志字符串，它们都在采集**完成之后**产生，对采集期间的写入副作用完全无知；
③`df -h` 会显示 `/evidence` 与 `/dev/sdb` 指向同一挂载源，而操作日志里没有这条命令的输出——说明采集前根本没做过落点确认，这是流程缺口而非偶发手误。

按「哈希通过即采集干净」走，代价是：被调查盘上大片数据区被自己的镜像覆盖，而因为哈希验证通过、操作日志完整、镜像可用，整个采集看起来毫无破绽——**这类破坏是没有报警信号的**。本案的真实损失不是镜像不可用，而是那些被自己覆盖掉的、未分配空间里尚未回收的数据，它们本来可能是下一条线索。

---
<a id="section-35"></a>

## 六、扩展阅读方向

下面四组方向按"你在镜像这条路上会撞到什么"组织。


**第一组：前置基础——动手之前必须对齐的两件事**

- [取证装备与写保护器](../../fundamentals/fundamentals-practice/fundamentals-practice-forensics-equipment-and-write-blockers.md) —— 本篇的硬件底座。**写保护器不是可选项**："先接上再确认"这个顺序一旦错了，你已经向检材写入了。接驳顺序、桥接器与直连的取舍、耗材成本都在那篇，本篇的操作步骤默认你已经具备这些条件。
- [证据保管链与委托证明](../../fundamentals/fundamentals-chain/fundamentals-chain-chain-of-custody-and-authorization.md) —— 镜像这一步同时是**保管链的起点**。谁在什么时间、用什么设备、从哪台机器读到了哪个序列号，这些记录必须在动作发生时写，事后补记的可信度完全不同。本篇步骤 6 的记录要求来自这里。
- [合规授权与法律边界](../../fundamentals/fundamentals-practice/fundamentals-practice-legal-authorization-and-boundaries.md) —— **拆机、开机、接管设备本身可能都需要明确授权**。委托书里哪些字句覆盖物理接触，值得在接设备之前逐句确认。

**第二组：相邻议题——这三种情况镜像做法完全不同**

镜像制作看着是单一动作，实际上是三种不同处境。用错方式，产出物可能根本没有证据价值。

- [远程勘验与在线取证](imaging-acquire-remote-evidence-collection.md) —— **系统还在跑的时候怎么办**。这时关机是破坏而不是保全：内存里的凭据、已解密的数据、运行中的进程全部消失。本篇讲的是"已经关机"的处置，那篇讲的是"不能关机"的处置，两者的技术栈与留痕要求完全不同。
- [TWRP 恢复分区取证与物理镜像提取](../../mobile/mobile-android/mobile-android-twrp.md) —— 移动设备上最直接的对应场景。**闪存的 FTL 映射让"扇区号"不等于物理位置**，而恢复分区 + 物理镜像提取是绕开这个问题的常规路线。逻辑提取与物理提取的取舍在那篇。
- [证据格式与转换](imaging-acquire-evidence-image-formats.md) —— RAW 与 E01 的选择不是格式偏好：E01 分段自带哈希、支持压缩，代价是普通字节工具读不了。这直接决定了后面所有分析工具的可用性。转换后的哈希验证方法也在那篇。

**第三组：工具与规范——数据接完之后怎么用**

镜像做完不是结束。**能不能在分析阶段保持"只读"，取决于你用什么接。**

- [只读挂载与安全接入](../imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— 本篇镜像的默认下游。挂载参数里的写保护选项、Linux 侧的 loop 设备与 `ro,noload` 组合、以及"为什么某些文件系统没法只读挂载只能靠解析器"，都在那篇。
- [虚拟机仿真](../imaging-mount-simulate/imaging-mount-simulate-virtual-machine-emulation.md) —— 另一种接法：把镜像挂进隔离环境。代价是启动过程本身会写盘（日志、预读、swap），所以必须在快照里操作而不是动原镜像。Windows Server 侧的仿真需求见[Windows Server 环境仿真](../imaging-mount-simulate/imaging-mount-simulate-windows-server.md)。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 镜像制作的阶段定位、以及"采集—固定—分析—报告"这条主线的纪律依据。
- [哈希与完整性校验](../../fundamentals/fundamentals-concepts/fundamentals-concepts-hashes-and-integrity-verification.md) —— 制作时同步算哈希这件事的原理：为什么"事后对镜像算哈希"和"制作时算哈希"在证据效力上不是一回事。

**第四组：判据与反例——怎么证明"镜像没问题"**

这一组决定你的镜像在质证环节能不能站住。"我做了镜像"这句话需要证据支撑。

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— **需要警惕的判据脆弱性**：时间戳类证据在有技术能力的对手面前需要独立印证。本篇的镜像给了你"完整且未被改动的字节流"这个前提，而这恰恰是所有元数据结论能被采信的基础——没有可信的原始镜像，后面读什么都是在读一个不知道真假的东西。
- [坏扇区与介质缺陷的处理](#section-22) —— 本篇第四章 4.3 组专门处理这个。**坏扇区的分布模式本身就是证据**（连续簇状 = 物理损伤、零散 = 写入时已老化），而"跳坏块继续拷"必须留记录，否则镜像不再是"原始检材的忠实副本"这个定义就破了。
- [RAID 与多盘系统的识别](#section-24) —— 本篇 2.4 与第四章 4.4 组。**阵列当单盘做，得到的是一堆无法解释的碎片**——这不是"没找到数据"，是方法错了。

**说明**：镜像制作需保留验证记录，使后续人员能够核对采集结果。

全盘复制花了几小时，做完之后才发现没有同步计算哈希、无法证明与原件一致——这时无论后面分析得多细致，整份检材在争议程序里都站不住。

哈希必须在制作时算，这条纪律的完整判据见第四章陷阱 8。
<a id="section-36"></a>

## 七、命令速查

```bash
# ===== 环境（Ubuntu / Debian）=====
sudo apt update && sudo apt install dcfldd ewf-tools sleuthkit

# ===== 源设备确认（RO=1 且 SERIAL 与勘验单一致）=====
lsblk -o NAME,SIZE,MODEL,SERIAL,RO,TYPE,MOUNTPOINTS
findmnt --source /dev/sdb     # 应为空，确认未挂载
sudo fdisk -l /dev/sdb

# ===== dcfldd：健康介质，全盘（hashconv=before 才对源数据算哈希）=====
sudo dcfldd if=/dev/sdb of=/evidence/DigiForensics.dd \
  bs=4M hash=md5,sha256 hashconv=before \
  md5log=/evidence/DigiForensics.dd.md5 \
  sha256log=/evidence/DigiForensics.dd.sha256 \
  statusinterval=256 2>&1 | tee /evidence/DigiForensics-acquire.log

# ===== dcfldd：坏扇区介质（bs 必须降到 512，sync 不可省）=====
sudo dcfldd if=/dev/sdb of=/evidence/DigiForensics.dd \
  bs=512 conv=noerror,sync hash=sha256 \
  hashlog=/evidence/DigiForensics.dd.sha256 \
  errlog=/evidence/DigiForensics.dd.err

# ===== dcfldd：分区镜像 / 双份输出（of= 可出现多次）=====
sudo dcfldd if=/dev/sdb1 of=/evidence/DigiForensics-part1.dd \
  bs=4M hash=sha256 hashlog=/evidence/DigiForensics-part1.dd.sha256
sudo dcfldd if=/dev/sdb of=/evidence/primary/DigiForensics.dd \
  of=/evidence/backup/DigiForensics.dd \
  bs=4M hash=sha256 hashlog=/evidence/DigiForensics.dd.sha256

# ===== ewfacquire：E01 制作（-t 不带扩展名，-u 要求参数给全）=====
sudo ewfacquire -t /evidence/DigiForensics -f encase6 \
  -c deflate:best -d sha256 -S 2G \
  -C "CASE-2026-0142" -E "E-001" \
  -D "Dell OptiPlex 7010 512GB SSD" -e "勘验员姓名" \
  -N "现场扣押，热镜像" -m fixed -M physical \
  -b 64 -g 64 -r 3 -l /evidence/DigiForensics-acquire.log -u \
  /dev/sdb

# ===== 验证（三条都要过）=====
sudo dcfldd if=/dev/sdb vf=/evidence/DigiForensics.dd   # 源 vs 镜像逐字节比对
sha256sum /evidence/DigiForensics.dd                    # 与 sha256log 比对
ewfverify /evidence/DigiForensics.E01                   # E01 内置哈希校验

# ===== 提取分区（不重读源盘）=====
mmls /evidence/DigiForensics.dd
mmcat /evidence/DigiForensics.dd 2 > /evidence/DigiForensics-part2.dd

# ===== 封存 =====
sudo chmod 444 /evidence/DigiForensics.dd
```

```powershell
# ===== Windows：内存采集（先于磁盘，输出到外接介质）=====
.\winpmem_mini_x64_rc2.exe D:\DigiForensics-mem.raw
certutil -hashfile D:\DigiForensics-mem.raw SHA256

# ===== Windows：镜像哈希（FTK 制作后）=====
Get-FileHash -Algorithm SHA256 'E:\evidence\DigiForensics.dd'
Get-FileHash -Algorithm MD5    'E:\evidence\DigiForensics.dd'
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 磁盘镜像与仿真 — 磁盘镜像制作与证据固定」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《磁盘镜像制作与证据固定》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.E01` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
