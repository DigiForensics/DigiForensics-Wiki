---
title: "存储寻址基础：扇区、LBA、分区与偏移"
slug: "storage-addressing-sectors-lba-offsets"
canonical: "https://github.com/DigiForensics/DigiForensics-Wiki/blob/main/docs/filesystem/storage-addressing/storage-addressing-sectors-lba-offsets.md"
license: "CC-BY-SA-4.0"
author: "用户提供，DigiForensics 整理"
updated_at: "2026-11-11"
source_type: "platform_original"
source_url: null
category: "文件系统分析, 存储结构与寻址"
space: {"slug": "filesystem", "name": "文件系统分析"}
node_path: ["存储结构与寻址"]
site_publication: "pending"
---

# 存储寻址基础：扇区、LBA、分区与偏移

> 适用范围：只读证据副本上的地址解释与文件定位。本文算例为教学数据；工具输出必须结合具体版本和检材核验。

<details>
<summary>本文目录</summary>

- [1. 地址空间：先确认偏移相对于谁](#section-1)
- [2. 物理扇区、逻辑扇区和 LBA](#section-2)
- [3. 常用地址与偏移术语](#section-3)
- [4. 单位、进制和编号](#section-4)
- [5. 地址换算的基本公式](#section-5)
- [6. 分区表与卷起点](#section-6)
- [7. 镜像格式与“镜像偏移”的歧义](#section-7)
- [8. 十六进制检查与字节序](#section-8)
- [9. 只读核验命令](#section-9)
- [10. 不应省略的核验事项](#section-10)
- [11. 推荐的记录表述](#section-11)
- [12. 术语对照](#section-12)
- [13. 可复算示例：同一 LBA 在不同扇区大小下](#section-13)
- [参考资料](#section-14)

</details>

文件系统取证中的“位置”必须落在明确的地址空间中。一个在十六进制视图中看到的偏移值，可能相对于完整磁盘镜像，也可能相对于某个分区、卷或单独导出的文件。缺少起点、单位和编号约定时，数值本身无法用来定位数据，更谈不上复核。

本文集中讨论设备级寻址、分区边界、字节偏移、扇区换算和证据坐标的记录。文件如何在 FAT、exFAT、NTFS 和 ext4 中映射到这些地址，另见[文件系统中的文件定位：簇、数据运行区与取证验证](./filesystem-file-location-and-verification.md)。

<a id="section-1"></a>
## 1. 地址空间：先确认偏移相对于谁

存储对象通常按以下顺序组织：

```text
取证镜像中的设备逻辑字节流
├── 设备级元数据、分区表、未分配区域
├── 分区 1（起始于设备上的某个字节位置）
│   └── 文件系统／卷（可能与分区起点相同，也可能不同）
│       ├── 文件系统元数据
│       └── 数据区
└── 分区 2 / 其他空间
```

这是最常见的简单模型，并非所有设备都采用它。文件系统可以直接建在整个设备上，也可能位于 RAID、LVM、动态磁盘、Storage Spaces、加密卷和虚拟磁盘提供的逻辑设备之上。**每一层都可能定义新的第 0 字节。**

记录一个可复核地址，至少需要六项：

| 要素 | 应记录的内容 |
|---|---|
| 对象 | 哪个磁盘、镜像、分区、逻辑卷或文件 |
| 坐标空间 | 设备绝对地址、分区相对地址、文件系统相对地址等 |
| 原点 | 从该对象的哪个位置开始计数 |
| 单位 | 字节、逻辑扇区、簇或文件系统块 |
| 表示 | 十进制或十六进制；是否采用从零编号 |
| 来源 | 工具字段、元数据结构或人工计算依据 |

<a id="section-2"></a>
## 2. 物理扇区、逻辑扇区和 LBA

### 2.1 逻辑扇区

逻辑扇区（Logical Sector）是块设备对主机呈现的可寻址单位。常见大小是 512 B 或 4096 B。设备报告的逻辑扇区大小，决定其 LBA 转换成字节位置时应乘以多少字节。

### 2.2 物理扇区

物理扇区（Physical Sector）描述设备底层组织或物理读写粒度，可能与逻辑扇区大小不同：

| 设备形式 | 逻辑扇区 | 物理扇区 | 说明 |
|---|---:|---:|---|
| 512n | 512 B | 512 B | 原生 512 字节扇区 |
| 512e | 512 B | 4096 B | 以 512 字节逻辑扇区模拟 4 KiB 物理扇区 |
| 4Kn | 4096 B | 4096 B | 原生 4 KiB 逻辑寻址 |

以上是典型配置，不代表所有存储设备都只存在这三种模式。**使用 LBA 计算字节偏移，应采用对应地址空间的逻辑扇区大小，而非机械套用 512 或物理扇区大小。**

### 2.3 LBA：主机可见的逻辑块编号

LBA（Logical Block Addressing）把设备公开的逻辑块连续编号，通常从 0 开始。LBA 0 是第一个逻辑扇区；LBA 1 是第二个逻辑扇区。

一些取证软件把相对于完整磁盘的 LBA 显示为 `Physical Sector`、`1st Physical Sector` 或“实体扇区号”。这通常意在与分区内相对编号区分；**不意味着找到了硬盘磁头的固定位置或闪存芯片上的实际 NAND 页面**。磁盘坏块替换、SSD/SD 卡的闪存转换层（FTL）等都可能重映射底层位置。

### 2.4 CHS 与 LBA 不可混用

传统 CHS（Cylinder–Head–Sector）使用柱面、磁头和扇区三元组定位，扇区字段通常从 1 起算。现代设备与 GPT/MBR 分析以 LBA 为主。不能直接把 CHS 中的 `Sector 1` 当成设备 LBA 1；换算 CHS 还需要明确几何参数，而现代设备显示的几何参数可能是兼容性表示。

<a id="section-3"></a>
## 3. 常用地址与偏移术语

| 名称 | 常见英文 | 起点与语义 |
|---|---|---|
| 设备绝对字节偏移 | Disk Absolute Byte Offset | 完整设备逻辑字节流的字节 0 |
| 设备绝对 LBA | Disk LBA | 完整设备的逻辑扇区 0 |
| 分区起始 LBA | Partition Start LBA | 分区首扇区在整盘中的编号 |
| 分区相对偏移 | Partition-relative Offset | 分区首字节为 0 |
| 卷相对偏移 | Volume-relative Offset | 卷逻辑起点为 0 |
| 文件系统相对偏移 | Filesystem-relative Offset | 文件系统起点为 0 |
| 扇区内偏移 | Offset Within Sector | 当前扇区首字节为 0 |
| 文件逻辑偏移 | File Offset | 文件或特定数据流首字节为 0 |
| 镜像内偏移 | Image Offset | 必须注明是还原后的设备数据流，还是镜像容器文件本身 |

**“FS offset”没有跨软件统一的唯一含义。** 在某些输出中它指文件系统相对于镜像的起始位置；另一些输出中可能表示文件系统内部某个对象的相对字节偏移。报告不能只写 `FS offset = 2048`，必须写出含义与单位。

<a id="section-4"></a>
## 4. 单位、进制和编号

- `B` 为字节；`bit` 为比特，8 bit = 1 B。
- `KB`、`MB`、`GB` 按十进制分别为 1000、1000²、1000³ B。
- `KiB`、`MiB`、`GiB` 按二进制分别为 1024、1024²、1024³ B。
- 十六进制通常记为 `0x...`；换算进制不会改变它表示的字节数量。
- 编号是一个无单位序数；偏移通常是从某个起点量出的字节数。二者不可直接相加。

十六进制视图中的列标题、行地址和字节索引可能采用不同显示方式。应先检查编辑器设置中地址基数及视图类型，再进行计算。

<a id="section-5"></a>
## 5. 地址换算的基本公式

以下公式均假定已经确认对应层级的逻辑扇区大小，且所用位置与数据范围在同一线性逻辑字节流中。

设：

- `S`：逻辑扇区大小，单位 B/sector。
- `L`：设备绝对 LBA，从 0 开始。
- `D`：设备绝对字节偏移，单位 B。
- `P`：分区起始设备 LBA。
- `R`：分区内相对字节偏移，单位 B。

### 5.1 LBA 转字节偏移

```text
D = L × S
L = floor(D / S)
扇区内字节偏移 = D mod S
```

若 `D mod S = 0`，当前位置恰好处于扇区边界；如果余数非零，它仍位于 `floor(D/S)` 号扇区内。除法结果不能直接向上取整作为“所在扇区”。

### 5.2 分区相对偏移转设备绝对偏移

```text
分区起始字节偏移 = P × S
D = P × S + R
R = D - P × S
```

以上要求 `P` 与 `D` 使用同一设备逻辑字节流的坐标。如果分区前还有其他抽象层（如 RAID、LVM、加密映射），应逐层转换，不能跳过中间映射。

### 5.3 相对扇区与绝对 LBA

当分区与设备使用同一种逻辑扇区粒度，且分区边界按该粒度对齐时：

```text
设备绝对 LBA = 分区起始 LBA + 分区相对扇区号
```

如果文件系统自己的扇区大小与底层设备逻辑扇区不一致，先转换为字节偏移，再转换为设备 LBA，不应直接把不同单位的扇区号相加。

### 5.4 文件系统起点不一定等于分区起点

若文件系统实际起始于分区内偏移 `F` 字节，则：

```text
设备绝对字节偏移 = 分区起始字节偏移 + F + 文件系统相对字节偏移
```

常见简单分区中 `F = 0`，但嵌套卷、容器、部分恢复场景可能不成立。只在证据支持时使用该简化假设。

### 5.5 从字节范围确定首尾扇区

一个长度为 `N > 0` 字节、始于 `D` 的连续范围，占用：

```text
第一个扇区 LBA = floor(D / S)
最后一个扇区 LBA = floor((D + N - 1) / S)
覆盖扇区数量 = 最后一个 LBA - 第一个 LBA + 1
```

这些扇区可能只被该范围部分覆盖。**文件长度除以扇区大小并取整，不总等于其覆盖的扇区数量。**

### 5.6 半开区间与边界

取证时建议采用 `[start, end)` 的半开区间：包含 `start`，不包含 `end`。这样 `length = end - start`，相邻范围不会重叠。若工具给出包含末尾的 `Last LBA`，则扇区数为 `Last LBA - First LBA + 1`。

必须验证：值非负、范围未超过地址空间、逻辑扇区大小已确认、分区长度与结束位置一致、整数转换没有溢出。

<a id="section-6"></a>
## 6. 分区表与卷起点

### 6.1 MBR

经典 MBR 扇区包含引导代码区域、位于偏移 `0x1BE` 的四条 16 B 分区表项，以及位于字节偏移 510、511 的签名字节 `55 AA`（按小端整数读取为 `0xAA55`；即使逻辑块大于 512 B，也不能移到逻辑块末尾）。每条分区项包含类型、起始 LBA 和扇区数量等字段。

分区项中的 `Starting LBA` 是**设备绝对逻辑扇区号**，而 `Number of Sectors` 是分区长度。不要把“分区在表中的第几个条目”与“分区起始扇区”混淆。扩展分区与 EBR 还涉及相对基址，须按其结构逐层解释。

### 6.2 GPT

GPT 常见结构包括保护性 MBR、主 GPT Header、分区项数组、备份分区项数组和备份 GPT Header。GPT Header 通常位于 LBA 1（设备采用该布局时），但解析必须依据介质的逻辑扇区大小及实际字段，而不是固定字节位置。

常用字段：

| 字段 | 作用 |
|---|---|
| `MyLBA` | 当前 GPT Header 所在 LBA |
| `AlternateLBA` | 另一份 GPT Header 所在 LBA |
| `FirstUsableLBA` / `LastUsableLBA` | 可用于普通分区的区间 |
| `PartitionEntryLBA` | 分区项数组起点 |
| `StartingLBA` / `EndingLBA` | 单个分区首尾 LBA（包含两端） |
| `PartitionTypeGUID` / `UniquePartitionGUID` | 类型与分区标识，不是地址 |
| Header CRC / Entry Array CRC | 用于检查结构完整性 |

GPT 分区长度（单位为逻辑扇区）为 `EndingLBA - StartingLBA + 1`。主备表、CRC 和设备容量应交叉核验。损坏或不一致时，不能仅依据其中一份结构宣布绝对位置。

### 6.3 卷与分区不是同义词

简单场景下，一个分区承载一个卷。但卷也可能跨越多个分区、磁盘或逻辑设备；可经过动态磁盘、Storage Spaces、LVM、RAID、BitLocker、LUKS 等层级。卷相对位置不能在没有映射信息时直接转化为单个物理磁盘 LBA。

<a id="section-7"></a>
## 7. 镜像格式与“镜像偏移”的歧义

| 取证对象 | 地址解释要点 |
|---|---|
| RAW / DD 整盘镜像 | 文件第 0 字节通常对应被采集设备逻辑字节流第 0 字节 |
| RAW 分区镜像 | 文件第 0 字节对应分区首字节，不是整盘首字节 |
| E01 / Ex01 | 证据容器可能分块、压缩并保存元数据；容器文件字节偏移不等于还原后的设备偏移 |
| AFF / AFF4 | 经容器/流抽象提供设备逻辑数据，需明确被选择的数据流 |
| VHD / VHDX、VMDK、QCOW2 | 虚拟磁盘内的客户机 LBA 与宿主容器文件的字节偏移是不同坐标空间 |
| RAID / 分层卷 | 逻辑 LBA 到成员盘条带及偏移需使用具体布局、顺序、条带大小与奇偶校验信息 |

对压缩、稀疏、分段或差分格式，不应使用 `LBA × 512` 直接在容器文件内定位客户机数据。先由支持该格式的只读解析器暴露逻辑字节流，然后在该逻辑流内计算。

<a id="section-8"></a>
## 8. 十六进制检查与字节序

查看原始字节时，首先核对编辑器是否加载了整盘、单个分区、导出文件还是镜像容器。确认地址栏的进制、起始原点和当前选区长度。

常见二进制字段可能采用小端序（Little-endian），但不是所有文件格式都如此。例如 MBR 分区项的 LBA 字段按小端整数解释；GPT 字段也有规定的字节序。**显示字节序列、字段数值和最终地址是三个不同步骤**，不能凭肉眼将字节顺序照抄成整数。

文件头标识能够辅助识别数据类型，但不能独立证明数据完整性、所属文件或分配状态。定位文件还需要结合文件系统元数据和文件逻辑映射。

<a id="section-9"></a>
## 9. 只读核验命令

下面的命令用于查看结构，不包含修改分区或挂载读写的操作。取证分析应针对只读映射的证据副本；在原始在线系统上执行查询也可能留下操作日志。

### 9.1 Linux

```bash
lsblk -o NAME,TYPE,SIZE,LOG-SEC,PHY-SEC,FSTYPE,START,MOUNTPOINTS
sudo fdisk -l /dev/sdX
sudo blockdev --getss /dev/sdX
sudo blockdev --getpbsz /dev/sdX
```

`/dev/sdX` 仅为占位符。`lsblk` 的 `START` 与其他列单位并不完全相同，必须查看工具帮助和版本说明。`fdisk -l` 展示的是设备结构推断，不应取代原始扇区解析。

### 9.2 Windows PowerShell

```powershell
Get-Disk | Select-Object Number,FriendlyName,LogicalSectorSize,PhysicalSectorSize,Size
Get-Partition | Select-Object DiskNumber,PartitionNumber,Offset,Size,Type
Get-Volume | Select-Object DriveLetter,FileSystem,FileSystemLabel,Size
```

`Get-Partition` 的 `Offset` 通常为字节偏移；它不是扇区编号。在线系统给出的布局也不应自动当成离线镜像中同名设备的布局。

### 9.3 The Sleuth Kit

```bash
img_stat evidence.raw
mmls -b SECTOR_BYTES evidence.raw
fsstat -b SECTOR_BYTES -o START_LBA evidence.raw
```

`mmls` 用于分区布局分析；`fsstat -o` 的 `-o` 是相对于镜像所表示的设备逻辑地址空间的**扇区偏移**，一般使用经核实的文件系统起点扇区号。若工具依据不同扇区大小解释偏移，应先查阅当前版本参数说明。不能把字节偏移直接填入 `-o`。

<a id="section-10"></a>
## 10. 不应省略的核验事项

1. 证据来源、采集方式、镜像格式及哈希是否已记录。
2. 打开的是整盘逻辑流、分区镜像、卷映射还是容器文件本身。
3. 逻辑扇区大小及其来源是否明确，是否与工具假设一致。
4. 分区首尾 LBA、分区长度、文件系统起点是否交叉核对。
5. 十六进制字段的字节序、单位、起点和编号基数是否确认。
6. 连续范围是否越界；末尾扇区是否按包含端点计算。
7. 是否存在加密、动态卷、虚拟磁盘或其他映射层。
8. 工具字段为 `Offset` 或 `Sector` 时是否保存原始语义和工具版本。

<a id="section-11"></a>
## 11. 推荐的记录表述

不要只写“偏移：`0x...`”。建议采用下列模板：

```text
证据对象：<设备或镜像标识>
对象层级：<整盘逻辑流 / 分区 / 文件系统 / 文件>
坐标原点：<设备第 0 字节 / 分区起点 / 文件系统起点>
偏移单位与数值：<字节 / 扇区；十进制及十六进制>
逻辑扇区大小：<B/sector>
分区起始位置：<设备 LBA；若不适用则说明>
范围：<[start,end)；单位>
数据来源：<元数据字段 / 工具 / 版本 / 操作>
核验状态：<已交叉核验 / 单一来源 / 尚不确定>
```

<a id="section-12"></a>
## 12. 术语对照

| 英文 | 中文建议用语 | 注意 |
|---|---|---|
| `Sector Number` | 扇区编号 | 需区分设备绝对与卷相对 |
| `Physical Sector` | 物理扇区／工具所称实体扇区 | 不必然等于介质内部物理位置 |
| `LBA` | 逻辑块地址 | 通常从 0 编号 |
| `Start LBA` | 起始逻辑扇区号 | 不是字节偏移 |
| `Byte Offset` | 字节偏移 | 标明原点 |
| `Partition Offset` | 分区偏移 | 可能是分区起点，也可能是分区内相对位置 |
| `FS Offset` | 文件系统偏移 | 必须按工具上下文释义 |
| `Image Offset` | 镜像偏移 | 区分容器文件与重建后的逻辑流 |
| `File Offset` | 文件逻辑偏移 | 不可直接当磁盘绝对偏移 |

<a id="section-13"></a>
## 13. 可复算示例：同一 LBA 在不同扇区大小下

下列数字是教学示例，不代表真实检材。设分区从 LBA 2048 开始，目标位于分区内字节偏移 `0x12345 = 74565`：

| 逻辑扇区大小 S | 分区起始字节 | 目标设备字节偏移 D | 所在设备 LBA | 扇区内偏移 |
| --- | ---: | ---: | ---: | ---: |
| 512 B | 1048576 | 1123141（0x112345） | 2193 | 325 |
| 4096 B | 8388608 | 8463173（0x812345） | 2066 | 837 |

每行都满足 `D = 2048 × S + 74565`、`D = LBA × S + 扇区内偏移`。这说明不能把已知的 LBA 脱离扇区大小使用。512 B 情况下，从 D 开始取 1000 B 覆盖 LBA 2193 至 2195，共 3 个扇区，而不是简单按 1000/512 向上取整得到的 2 个。

在 TSK 中使用 `SECTOR_BYTES` 明确实际设备逻辑扇区大小；例如确认是 4096 B 时替换为 `4096`。这些占位符和 `START_LBA` 必须一起核实，不能直接复制运行。

<a id="section-14"></a>
## 参考资料

- [UEFI 2.10：GPT 与 MBR 布局、固定偏移和 CRC](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html)。
- [TSK fsstat 参数说明](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)；[mmls](https://www.sleuthkit.org/sleuthkit/man/mmls.html)。
- [Microsoft Get-Disk](https://learn.microsoft.com/en-us/powershell/module/storage/get-disk)；[Get-Partition](https://learn.microsoft.com/en-us/powershell/module/storage/get-partition)。

核对日期：2026-11-11。规范与工具参数按链接版本核查，具体检材仍需记录实际版本。

---

**延伸阅读：** [文件系统中的文件定位：簇、数据运行区与取证验证](./filesystem-file-location-and-verification.md)。本文负责建立地址坐标；延伸篇负责从具体文件元数据追踪数据所在位置。
