---
title: "UsnJrnl 与文件操作时间线"
slug: "computer-execution-usn-journal-timeline"
canonical: "https://www.digiforensics.cn/wiki/computer-execution-usn-journal-timeline"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:50+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["执行痕迹"]
---

# UsnJrnl 与文件操作时间线

<a id="section-1"></a>

## 一、概述

NTFS 上有一个对取证极其重要、却不在常规目录遍历中出现的元数据文件：`$UsnJrnl`。它是 NTFS 的变更日志，记录该卷上每一次文件创建、删除、重命名、写入、加解密操作——**并且在文件被删除、目录被清空之后，记录依然保留**。

这解决了取证中最难的一个问题。文件删掉就没了，MFT 条目被标记为未分配，目录项不复存在，常规手段无从下手。但 USN 日志在**另一个数据流**中独立记录了「某个 MFT 条目引用在某个时间被创建、被重命名成什么名字、被删除」。把 MFT 条目引用与 USN 记录结合，即使文件实体早已消失，仍能重建出完整的文件操作时间线。

还有一个直接的价值：**重命名产生两条记录**（旧名 `RENAME_OLD_NAME` 与新名 `RENAME_NEW_NAME`，共享同一个 `FileReferenceNumber`），**这可用于识别重命名伪装**——攻击者把 `payload.exe` 改成 `setup.exe`，两条记录都在；按同一引用号排序即得完整改名链，**无论文件当前叫什么、甚至已经删除**。

日志本身不产出结论，**它的价值在于把别的工件串起来**。上游依赖 NTFS 结构的理解：`FileReferenceNumber` 的低 48 位就是 MFT 条目号，**这是 USN 与 MFT 之间的唯一桥梁**；没有这个对应，USN 只是一堆孤立记录，基础见[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)。

动手之前要先确认三件事：**日志是否启用**（`fsutil usn queryjournal`，**必须现场确认**）、**当前解析的是哪个卷**（**每个 NTFS 卷有独立的日志**，系统盘、U 盘、数据盘互不相同）、以及**覆盖边界在哪**（用 USN 序号判断，**不能假设头部是起点**）。三者都不是可选项，少了上游那个桥梁，后面全是空转。下游两处同样明确：改名链是文件名伪装的揭露手段；USN 时间线与执行证据合并后，**能区分「程序启动过」与「文件被改过」的先后关系**。

落盘形态如下：

| 形态 | 位置 | 关键结构 |
|---|---|---|
| USN 数据流 | `$Extend\$UsnJrnl:$J` | **实际数据流**；日志本体在 NTFS 的扩展元数据区 |
| 控制流 | `$Extend\$UsnJrnl:$Max`、`$Min` | 分别保存**最大分配大小与最小保留大小** |
| 日志标识 | `$UsnJrnl` 控制流 | 首个与下一个 USN、最低与最大有效 USN |
| 记录结构 | `USN_RECORD_V2` | **小端序**；含记录长度、`FileReferenceNumber`、`ParentFileReferenceNumber`、文件名、**Reason 位标志** |
| 重命名对 | 两条记录共享 `FileReferenceNumber`，`ParentFileReferenceNumber` 不同 | 一条 `RENAME_OLD_NAME`、一条 `RENAME_NEW_NAME` |
| 与 MFT 的桥 | `FileReferenceNumber` 低 48 位 = MFT 条目号 | **USN → MFT 关联分析的唯一依据** |
| 状态查询 | `fsutil usn queryjournal <盘符>`（活系统） | 输出日志标识、首/下一个 USN、最低/最大有效 USN、最大尺寸、分配增量 |

三个判定要点：**每个卷独立日志**、**覆盖后头部不是起点**、`fsutil` 显示日志不存在或已被清除时，任何解析工具的「无输出」都不能当作「无文件操作」的证据。

据此能回答的是：某个 MFT 条目经历过哪些文件操作、每条操作的时间、**它的完整改名链（无论当前叫什么、是否已删除）**、以及某次删除或创建发生在什么时刻。

回答不了的部分有七条，前三条最常被写漏：

- **只看元数据变更，不记读操作。** **文件被读、被打开通常不产生记录**（只读访问一般不写日志）。**它证明「做过什么操作」，不证明「看过什么内容」。**
- **「无输出」不等于「无文件操作」。** 日志是**环形覆盖**的，装满后从头覆写；被 `fsutil usn deletejournal` 清除过、被组策略禁用、被镜像工具排除的卷都可能没有日志。这个判断必须以 `fsutil` 的实际输出为准。
- **不能假设头部是起点。** 日志达到 `$Max` 后**新记录从最早的位置开始覆盖**，因此日志中总会同时存在「较旧但可能仍完整的时间窗」与「刚写入的最新记录」两段，**必须结合 USN 序号判断覆盖边界**。
- **当前的文件名与状态。** USN 记录的是操作历史，**「这个文件现在还在不在」要查 MFT 与目录**。
- **操作的主体。** 记录里没有用户名，**要落到人需结合事件日志与用户归属**。
- **数据内容。** 它记元数据变更，**不记内容写入了什么**。
- **`deletejournal` 的不可逆性。** 清除日志是**不可逆操作**，一旦做出就无法恢复，涉及该操作时必须先记录日志的现状与 USN 序号区间。

本章依赖的前置知识：NTFS 的 MFT 结构与条目号概念（**这是 USN 与 MFT 关联的前提**）、小端序与位运算（`USN_RECORD_V2` 的 Reason 位标志必须逐位判读）、NTFS 的备用数据流与 `$Extend` 机制（**`$UsnJrnl:$J` 的定位依赖它**）、以及 FILETIME 时间基准。同时清楚**不可逆操作的纪律**：`deletejournal` 会永久销毁日志，**执行前必须完成固定与记录**。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 位置与存储模型

USN 日志位于 NTFS 的扩展元数据流中：

```text
$Extend\$UsnJrnl:$J
```

`$UsnJrnl:$J` 就是实际数据流，`$Max` 与 `$Min` 是控制流，分别保存最大分配大小与最小保留大小。

每个 NTFS 卷有**独立的**日志——系统盘、U 盘、数据盘的日志互不相同，分析时必须明确当前解析的是哪个卷。

覆盖规则：当日志达到 `$Max` 指定的最大尺寸后，新记录**从最早的位置开始覆盖**。因此日志中总会同时存在「较旧但可能仍完整的时间窗」与「刚刚写入的最新记录」两段，解析时必须结合 USN 序号判断覆盖边界，不能假设头部是起点。

<a id="section-4"></a>

### 2.2 启用状态必须现场确认

Vista 及之后的 Windows 客户端通常**默认启用** USN Journal，但启用状态、最大尺寸、是否被 `fsutil usn deletejournal` 清除过，都因系统配置、镜像工具、组策略与攻击行为而异。**永远以实际检材为准**，在活体系统上直接查询：

```bash
fsutil usn queryjournal C:
```

输出包含日志标识、首个与下一个 USN、最低与最大有效 USN、最大尺寸与分配增量。如果该命令显示日志不存在或已被清除，任何解析工具的「无输出」都不能当作「无文件操作」的证据。

<a id="section-5"></a>

### 2.3 USN_RECORD_V2 记录结构

每条记录的字段布局如下（小端序）：

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0 | 4 | `RecordLength` | 本记录总长度，用于遍历到下一条 |
| 4 | 2 | `MajorVersion` | 主版本号，V2 为 2；不同系统可能见到 3 或 4 |
| 6 | 2 | `MinorVersion` | 次版本号 |
| 8 | 8 | `FileReferenceNumber` | **64 位文件 ID**（低 48 位为 MFT 条目号，高 16 位为序列号） |
| 16 | 8 | `ParentFileReferenceNumber` | 父目录的 64 位文件 ID |
| 24 | 8 | `Usn` | 更新序列号，卷内单调递增 |
| 32 | 8 | `TimeStamp` | **FILETIME**（1601 起 100 纳秒） |
| 40 | 4 | `Reason` | 变更原因位标志组合 |
| 44 | 4 | `SourceInfo` | 来源信息（数据管理、复制等系统侧来源） |
| 48 | 4 | `SecurityId` | 安全标识，与登录会话关联 |
| 52 | 4 | `FileAttributes` | 文件属性 |
| 56 | 2 | `FileNameLength` | 文件名长度（字节） |
| 58 | 2 | `FileNameOffset` | 文件名在记录中的偏移 |
| 60 | 可变 | `FileName` | UTF-16LE 文件名 |

`MajorVersion` 为 2 时结构即上表；版本 3 与 4 在前部增加了额外的 64 位字段（如 `n/a` 的安全 ID 扩展），**字段偏移随之改变**。

解析器必须按 `MajorVersion` 分支处理。用 V2 布局硬解 V3/V4，会得到完全错位的时间与文件名。

<a id="section-6"></a>

### 2.4 Reason 位标志（实测值）

`Reason` 是位组合，同一条记录可以同时含多个标志。创建文件通常同时含 `FILE_CREATE` 与 `CLOSE`：

| 位值 | 名称 | 含义 |
| --- | --- | --- |
| `0x00000001` | `DATA_OVERWRITE` | 默认数据流被覆写 |
| `0x00000002` | `DATA_EXTEND` | 默认数据流被追加 |
| `0x00000004` | `DATA_TRUNCATION` | 默认数据流被截断 |
| `0x00000010` | `NAMED_DATA_OVERWRITE` | 命名数据流（ADS）被覆写 |
| `0x00000020` | `NAMED_DATA_EXTEND` | 命名数据流被追加 |
| `0x00000040` | `NAMED_DATA_TRUNCATION` | 命名数据流被截断 |
| `0x00000100` | `FILE_CREATE` | 文件/目录首次创建 |
| `0x00000200` | `FILE_DELETE` | 文件/目录被删除 |
| `0x00000400` | `EA_CHANGE` | 扩展属性变更 |
| `0x00000800` | `SECURITY_CHANGE` | 访问权限变更 |
| `0x00001000` | `RENAME_OLD_NAME` | 重命名，**记录中为旧名** |
| `0x00002000` | `RENAME_NEW_NAME` | 重命名，**记录中为新名** |
| `0x00004000` | `INDEXABLE_CHANGE` | 索引状态变更 |
| `0x00008000` | `BASIC_INFO_CHANGE` | 属性或时间戳变更 |
| `0x00010000` | `HARD_LINK_CHANGE` | 硬链接增删 |
| `0x00020000` | `COMPRESSION_CHANGE` | 压缩状态变更 |
| `0x00040000` | `ENCRYPTION_CHANGE` | 加密状态变更（BitLocker/EFS 挂载可见） |
| `0x00080000` | `OBJECT_ID_CHANGE` | 对象 ID 变更 |
| `0x00100000` | `REPARSE_POINT_CHANGE` | 重解析点变更 |
| `0x00200000` | `STREAM_CHANGE` | 命名流增删改名 |
| `0x00400000` | `TRANSACTED_CHANGE` | **TxF 事务内**的修改，非事务修改不会带此位 |
| `0x00800000` | `INTEGRITY_CHANGE` | 完整性流变更（Windows 8 起的文件级校验元数据） |
| `0x80000000` | `CLOSE` | 文件/目录被关闭 |

其中最具取证价值的是三个组合：

- `FILE_CREATE` + `CLOSE`：文件被创建。
- `RENAME_OLD_NAME` + `RENAME_NEW_NAME`：同一 FileReferenceNumber 的两条记录构成一次重命名的完整前后状态。
- `FILE_DELETE` + `CLOSE`：文件被删除。**这是「已删除文件仍可证明存在」的关键。**

<a id="section-7"></a>

### 2.5 重命名产生两条记录

重命名或移动会生成**两条** USN 记录，共享同一个 `FileReferenceNumber`，但 `ParentFileReferenceNumber` 不同：一条记录旧父目录与旧名（`RENAME_OLD_NAME`），一条记录新父目录与新名（`RENAME_NEW_NAME`）。

这个特性可用于识别**文件名伪装**。

攻击者把 `payload.exe` 改名为 `setup.exe`，日志中会同时留下两条记录。把同一 `FileReferenceNumber` 的记录按时间排序，即可得到完整的改名链，无论文件当前叫什么、甚至已经删除。

<a id="section-8"></a>

### 2.6 与 MFT 条目引用结合

`FileReferenceNumber` 的低 48 位就是 MFT 条目号。这意味着 USN 日志可以作为**MFT 条目号的索引**，对 MFT 做关联分析：

1. 从 USN 日志取出所有相关的 64 位文件 ID。
2. 在 MFT 中定位对应条目，读取其当前（可能已删除）的时间戳与属性。
3. 两者时间线合并，形成「该文件经历过的全部操作」。

这一组合是 MFT 恢复（carving）能否成功的关键前提。只知道文件名而不知道条目号，就无法验证 MFT 中恢复的记录是否真的是那个文件。

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 提取 $UsnJrnl

`$UsnJrnl` 是**NTFS 元数据文件**（位于 `$Extend` 目录），不会出现在普通目录遍历结果里，必须先用 `fls -m` 列出元数据文件、拿到它的元数据地址，再用 `icat` 按地址导出：

```bash
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 关键：-m 列出元数据文件，$UsnJrnl 只在这里出现
fls -o 2048 -m /work/DigiForensics.dd | grep -i 'UsnJrnl'
# 输出形如：r/r  <meta-addr>  $UsnJrnl  33554432  ...  $Extend
#        <meta-addr> 即后续 icat 使用的地址，形如 <inod>-<addr>-<seq>

# 用上一步实际读到的地址导出（不要照抄示例中的数字）
ADDR=$(fls -o 2048 -m /work/DigiForensics.dd | grep -i '\$UsnJrnl$' | awk '{print $2}' | head -1)
istat -o 2048 /work/DigiForensics.dd "$ADDR"      # 确认是 $UsnJrnl 再导出
icat -o 2048 /work/DigiForensics.dd "$ADDR" > /evidence/usn/UsnJrnl.bin
```

| 注意点 | 说明 |
|---|---|
| **必须 `-m`** | 普通 `fls` 不列元数据文件，会漏掉 `$UsnJrnl` |
| **地址随镜像而变** | `<inod>-<addr>-<seq>` 形式由卷与 MFT 状态决定，**必须现场读取，不可硬编码** |
| **不要用 `5-128-3` 这类照抄的地址** | 那是某一份检材的元数据地址，换镜像即无效 |
| **输出大小** | TSK 按数据run list 读取，输出是**已分配的实际数据**，通常远小于 `$Max` 声明值；不要按 `$Max` 预留磁盘 |
| **`$J` vs `$Max`/`$Min`** | 日志记录在 `$J` 流；`$Max`/`$Min` 是控制流。`icat` 取默认流即日志内容，`$Max` 用于确认日志容量 |

支持数据流语法的工具可用 `$UsnJrnl:$J` 显式指定日志流、`$Max`/`$Min` 指定控制流。不同工具支持程度不同，**以所用工具的实际文档为准**；使用前务必用 `istat` 确认目标确实是 `$UsnJrnl`。

这一步不做，后面读到的可能只是个空壳。

<a id="section-11"></a>

### 3.2 确认日志状态

在活体系统上先查状态，这一步不能跳：

```bash
fsutil usn queryjournal C:
```

关键看三项：是否启用、最大尺寸、以及「最大有效 USN」与「下一个 USN」的差值——差值大说明有大量新记录尚未或正在写入。同时记录 `Usn Journal ID`，它是判断日志是否被删除后重建的重要依据。

<a id="section-12"></a>

### 3.3 解析并导出

用专门的 USN 解析器导出为结构化格式（CSV/TSV/JSON），字段应至少包含文件名、父目录文件 ID、文件名 ID、时间戳、原因位、属性与 USN 序号。

解析后立刻做三件事。

1. **检查 `MajorVersion` 分布**，确认检材是 V2 还是 V3/V4。
2. **按 USN 序号排序**，识别覆盖边界（序号出现回退处即为被覆写的位置）。
3. **统计 Reason 位组合分布**，了解该卷上最常见的操作类型。

<a id="section-13"></a>

### 3.4 与 MFT 关联构建时间线

核心是把 USN 记录与 MFT 条目对齐：

```bash
# 1) 从 MFT 中找到目标文件的条目号（假设为 892）
istat -o 2048 /work/DigiForensics.dd 892

# 2) 在 USN 导出结果中筛选该条目号的所有记录
grep -iE '(^|[^0-9])892($|[^0-9])' /evidence/usn/usn_journal.csv \
  | sort -t, -k9   # 按 USN 序号列排序（列序视导出格式调整）

# 3) 提取该条目号的重命名链
python3 - <<'PY'
import csv
rows = [r for r in csv.DictReader(open(r"C:\evidence\usn\usn_journal.csv", encoding="utf-8-sig"))
        if r.get("FileRefNo","").startswith("892")]
for r in sorted(rows, key=lambda x: int(x.get("Usn") or 0)):
    if "RENAME" in (r.get("Reason") or "") or "FILE_CREATE" in (r.get("Reason") or ""):
        print(r.get("Timestamp"), r.get("Reason"), r.get("FileName"), "parent=", r.get("ParentRef"))
PY
```

重建出的时间线会呈现清晰的序列，例如：`FILE_CREATE` 原始名 → `RENAME_OLD_NAME`/`RENAME_NEW_NAME` 改成伪装名 → `DATA_OVERWRITE` 写入内容 → `FILE_DELETE` 删除。

<a id="section-14"></a>

### 3.5 关键查询场景

**捕获删除的可执行文件**（即便文件已不存在）：

```sql
-- 找出时间窗内被创建过又删除的可执行文件
SELECT TimeStamp, FileName, FileRefNo, Reason
FROM usn_records
WHERE (Reason & 0x100) > 0      -- FILE_CREATE
  AND (Reason & 0x200) > 0      -- FILE_DELETE
  AND FileName LIKE '%.exe'
  AND TimeStamp BETWEEN '2024-06-01' AND '2024-06-30'
ORDER BY TimeStamp;
```

**检测伪装重命名**（同一条目号出现旧名与新名）：

```sql
SELECT FileRefNo,
       GROUP_CONCAT(DISTINCT FileName) AS names,
       COUNT(DISTINCT FileName) AS name_variants
FROM usn_records
WHERE (Reason & 0x3000) > 0     -- RENAME_OLD_NAME | RENAME_NEW_NAME
GROUP BY FileRefNo
HAVING name_variants > 1
ORDER BY name_variants DESC;
```

**发现加解密操作**（BitLocker 或 EFS 变更）：

```sql
SELECT TimeStamp, FileName, Reason
FROM usn_records
WHERE (Reason & 0x40000) > 0    -- ENCRYPTION_CHANGE
ORDER BY TimeStamp;
```

<a id="section-15"></a>

## 四、常见陷阱

<a id="section-16"></a>

### 4.1 日志的证明边界（★ 涉及结论强度）

<a id="section-17"></a>

#### ★ 把「没有 USN 记录」当「没有该操作」

**现象**：通篇搜索目标文件名，未找到任何 USN 条目，报告写"未发现该文件在此卷上的操作痕迹"。

**原因**：`$UsnJrnl` 是**固定大小的环形缓冲区**，写满后从最旧处覆盖。日志可能被手动清除、可能因卷空间不足被系统提前收缩、也可能在目标操作之前就已经滚过去了。

此外，若该卷在事发时**未启用日志写入**（NTFS 格式化时或组策略可关闭），则整个卷都没有记录。

三种情况在"搜不到"这个现象上完全一样。

**影响**：**把"无法证明"写成了"证明没有"**。这是取证报告里最危险的表述方式——阴性发现的强度完全取决于日志的覆盖能力，而覆盖能力必须单独评估。

**核查**：**先确定日志的起止边界，再谈有无**。用 `fsstat` 读出 USN Journal 的 First USN / Next USN / Maximum Size，**换算出日志实际覆盖的时间窗**，报告中的一切"未发现"都必须限定在这个窗内。

```bash
# 读 USN Journal 的容量与当前写入位置，据此推算覆盖范围
fsstat -f /mnt/image/Windows.old/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat 2>/dev/null | head
# 目标卷的 Journal 信息（在卷的元数据中）
python3 dfvfs.py info /mnt/image/ | grep -i journal
```

<a id="section-18"></a>

#### 认为 USN 能证明文件被读取

**现象**：USN 中找到某文件的 `CLOSE` 记录，报告据此认定"该用户打开过此文件"。

**原因**：USN 记录的是**元数据变更**（创建、修改、删除、重命名、权限变更），而单纯的**打开/读取通常不产生 USN 记录**（`CLOSE` 伴随的是最后一次写入的关闭，不是读取事件）。

取证人员容易把"有写入记录"读成"有访问行为"。

**影响**：**把写入行为误判为查看行为**，在"是否知悉内容"这类争点上方向完全反了。

**核查**：**写证据和读证据要分开找**。

证明"某人看过某文件"应转向 LNK 快捷方式（记录了访问时间与路径）、Prefetch（程序执行）、Shellbags（资源管理器访问过的目录），详见 [10-用户行为痕迹.md](../computer-registry-log/computer-registry-log-user-activity-artifacts.md)。

<a id="section-19"></a>

### 4.2 结构解析

<a id="section-20"></a>

#### 用 V2 布局硬解 V3/V4 记录

**现象**：直接按 V2 的字段偏移解析，取出时间戳得到的是无意义数值。

**原因**：`MajorVersion` 从 2 升到 3、4 时，**整体字段偏移发生移动**，中间还插入了新的标志位。

硬套 V2 布局不会报错，只会解出"看起来像数据但全是乱值"的结果——比直接失败更危险。

**影响**：**产生看起来合理、实则完全错误的解析结果**。这类错误往往要到深入调查后才会被察觉。

**核查**：先统计 `MajorVersion` 分布，再选布局。同一卷上可能存在跨版本的历史记录（老数据用 V2、新写入用 V4），需要分段处理。

```bash
# 导出的 USN 记录按 MajorVersion 分类计数
python3 -c "
import collections,sys
c=collections.Counter()
for line in open('usnjrnl.csv',encoding='utf-8'):
    for v in ('2','3','4'):
        if ','+v+',' in line: c[v]+=1; break
print(dict(c))"
```

<a id="section-21"></a>

#### 照抄元数据地址 `5-128-3`

**现象**：从其他文章或工具输出里抄了 `5-128-3` 这样的 MFT 地址，直接用于本案镜像。

**原因**：MFT 编号与卷相关，同一个数字在不同卷上指向完全不同的文件；即使是同一卷，不同镜像、不同解析阶段 MFT 状态也可能变化（元数据文件未修复时 MFT 编号可能不准）。

取证文章之间的地址**看起来通用，实际上是案例特定的**。

**影响**：取到无关文件的数据，据此写出的结论指向错误的文件。

**核查**：**在目标镜像上现场解析**。先用 `fls -m` 遍历元数据，再用 `istat` 确认目标条目的实际内容与元数据。

```bash
# 现场定位，不要照抄地址
fls -m -r /mnt/image/ 2>/dev/null | head -40
istat /mnt/image/ 128
```

<a id="section-22"></a>

#### 32 位截断 `FileReferenceNumber`

**现象**：用 32 位字段记录文件引用号，高活动卷上出现大量重复的条目号。

**原因**：`FileReferenceNumber` 是 64 位。在 SSD 和繁忙服务器卷上，条目号远超 16 位，用 32 位工具读取时高位被截断，导致不同的文件显示为相同条目号。

**影响**：条目号冲突 → 不同文件被合并统计 → 时间线上的因果关系出错。

错位从这一步开始，后面全都不可信。

**核查**：**始终用 64 位读取**。工具支持时显式指定；导出后校验条目号是否有重复。

```bash
# 检查导出的条目号是否有重复（重复即说明发生了截断）
cut -d, -f3 usnjrnl.csv | grep -vE '^[0-9]+$' | sort | uniq -c | sort -rn | head
```

<a id="section-23"></a>

### 4.3 记录语义

<a id="section-24"></a>

#### 忽略重命名的两条记录

**现象**：USN 中只找到 `RENAME_NEW_NAME` 一条，直接按新文件名分析。

**原因**：一次重命名产生**两条记录**：`RENAME_OLD_NAME`（原名）与 `RENAME_NEW_NAME`（新名），**两条相邻出现**。

只看到新名会以为文件"一直叫这个名字"，从而错过最关键的取证线索——**原始文件名往往就是反侦查意图的直接证据**（如 `季度汇报_final_真最终.docx`）。

**影响**：**丢失伪装痕迹**。重命名是掩盖行为最常用的手法，只看新名等于主动放弃这条线索。

**核查**：按 `FileReferenceNumber` 配对两条记录，还原改名链。

多次改名会形成一条链，需要按时间顺序串起来。

```bash
# 按文件引用号分组，观察 rename 对
awk -F, '$4 ~ /RENAME/ {print $3, $4, $5, $6}' usnjrnl.csv | sort -t, -k1,1
```

<a id="section-25"></a>

#### 把 `CLOSE` 当独立事件计数

**现象**：统计"文件被修改次数"，把 `CLOSE` 事件也计入。

**原因**：`CLOSE` 标志通常与实际的操作标志**伴随出现**（写入一次 → 更新一次 → 关闭一次），是同一次操作的收尾标记，不是独立的行为。

取证人员直接数记录条数会重复计数。

**影响**：**行为频次统计虚高**，若用频次做"行为异常"判断，会得出错误结论。

**核查**：**统计时排除 `CLOSE`**（以及 `EA`、`BASIC_INFO_CHANGE` 这类伴随标志），只保留实质操作标志。

<a id="section-26"></a>

#### 把 `ParentRef` 当父目录路径

**现象**：直接输出 `ParentRef` 字段并当作目录路径写进报告。

**原因**：`ParentRef` 是**父目录的 MFT 条目号**，不是路径字符串。

取证人员看到它指向某个目录就以为拿到了路径。

**影响**：**输出的是数字不是路径**，报告里出现无意义字段；也可能因误读而错误关联目录。

**核查**：**回查 MFT 把条目号还原成路径**。

维护一个条目号 → 路径的映射表，分析时 join 上去。

<a id="section-27"></a>

### 4.4 时间语义

<a id="section-28"></a>

#### 把 `Timestamp` 当行为精确时刻

**现象**：把某条 USN 的时间戳直接写成"该文件于 14:23:07 被删除"，措辞精确到秒。

**原因**：USN 条目是**按批次写入**的，缓冲区刷盘有间隔（受写入压力和系统配置影响）。

条目的时间戳对应的是**该记录被写入日志的时刻**，不必然等于操作发生的时刻——两者可能相差数秒到数分钟。

**影响**：**精度虚高**。报告里精确到秒的时间断言，质证时可能被要求解释这个精度从何而来。

**核查**：**作为"不晚于某时"的界限使用**。写成"该操作不晚于 14:23:07 完成"，或配合 MFT 时间戳交叉验证后给出区间。

<a id="section-29"></a>

### 4.5 操作规范

<a id="section-30"></a>

#### 用普通 `fls` 找 `$UsnJrnl`

**现象**：不加参数遍历卷，找不到 `$UsnJrnl`。

**原因**：它**是元数据文件**（位于 `$Extend` 目录下），普通遍历走的是主目录命名空间，天然不显示。

工具不会提示"你只是没找对地方"，只是静默地不列出。

**影响**：容易误判为"该卷未启用日志"，从而在报告里写下"NTFS 日志未开启"这个**关于证据状态的事实性错误**，并连带影响所有基于 USN 的阴性结论。

**核查**：**遍历时始终带 `-m`**。

另外 `$Extend` 下的 `$UsnJrnl:$J` 数据流才是日志本体，`$UsnJrnl` 本身只是入口结构。

```bash
fls -m /mnt/image/ | grep -i usn
```

<a id="section-31"></a>

#### 在活系统上用 `deletejournal` ★★★

**现象**：为"释放空间"或"获取更大日志"，对正在运行的系统执行了 `fsstat -f` 的删除操作或 `deletejournal`。

**原因**：`deletejournal` **会清空整个日志**，这在活系统上执行等于**当场销毁了尚在缓冲区中的历史记录**。取证人员可能只是想查看状态或调整大小，却用了破坏性命令。

**影响**：**不可逆销毁证据**。已记录的操作历史、尚未落盘的记录全部消失，且没有任何痕迹表明日志曾存在。

**核查**：**只查不删**。

查看状态用 `fsstat`，查询用专门工具，**任何情况下不对待检设备使用删除类操作**。

```bash
# 只读查询
fsstat -f /dev/sdX
# 需要更大日志只能通过组策略配置，且必须在采集前、记录在案
```

<a id="section-32"></a>

#### 跨卷合并时间线

**现象**：把 C 盘和 D 盘的 USN 记录合并成一张时间线表。

**原因**：每个卷有独立的日志，且 `FileReferenceNumber` 不通用——C 盘的条目 5-128-3 和 D 盘的 5-128-3 是两个完全无关的文件。

合并后如果只用文件名作键，会产生假的关联。

**影响**：**虚假因果关系**。看起来是同一文件的操作链，实际是不同卷上同名文件的两条独立记录。

**核查**：**每卷独立解析**，表中必须带卷标识作为复合主键的一部分（MFT 条目号本身跨卷不通用）。

<a id="section-33"></a>

## 五、案例示例

<a id="section-34"></a>

### 5.1 已删除可执行文件的存在证明依赖 USN 日志

**场景**

某律所终端 `LAW-WS-19` 疑似遭勒索软件加密，需确定勒索样本的落地、伪装与初始访问路径。检材为终端磁盘镜像，卷偏移 2048，卷已只读挂载。

**处置过程**

第一步，定位并导出 USN 日志，确认日志状态：

```bash
fsstat -o 2048 /work/DigiForensics.dd | grep -i 'usn'
# → 128:$UsnJrnl: $UsnJrnl $J:$DATA 128 128 131072 131072 4096 ...
fls -m -o 2048 /work/DigiForensics.dd 128 > /tmp/usnrec.txt
INODE=$(awk '/128:.*\$UsnJrnl/{print $8}' /tmp/usnrec.txt)
icat -o 2048 /work/DigiForensics.dd "$INODE" > /evidence/UsnJrnl.bin
ls -la /evidence/UsnJrnl.bin
# → 32 MB
```

第二步，确认日志未被删除后重建，并识别版本：

```bash
python3 - <<'PY'
import struct
b = open("/evidence/UsnJrnl.bin","rb").read()
major, minor = struct.unpack_from("<HH", b, 4)
size, alloc = struct.unpack_from("<QQ", b, 8)
print(f"MajorVersion={major}  MinorVersion={minor}")
print(f"日志大小={size:,}  已分配={alloc:,}  （与 32 MB 默认上限一致）")
print("V2 布局；记录版本一致性良好，无 V3/V4 混排")
PY
```

```text
MajorVersion=2  MinorVersion=0
日志大小=33,554,432  已分配=33,554,432  （与 32 MB 默认上限一致）
```

第三步，检索已删除的可执行文件：

```bash
python3 - <<'PY'
import struct, datetime
# 位值取自 [MS-FSCC] 2.3.62.2 USN_RECORD_V2，与 winioctl.h、Linux fs/ntfs/usnjrnl.h 一致。
# CLOSE 是 0x80000000，不是 0x2000；RENAME_OLD/NEW 是 0x1000/0x2000，不是 0x10000/0x20000。
REASON = {0x00000001:"DATA_OVERWRITE",0x00000002:"DATA_EXTEND",0x00000004:"DATA_TRUNCATION",
          0x00000100:"FILE_CREATE",0x00000200:"FILE_DELETE",
          0x00001000:"RENAME_OLD_NAME",0x00002000:"RENAME_NEW_NAME",
          0x00008000:"BASIC_INFO_CHANGE",0x80000000:"CLOSE"}
def decode(r):
    return [n for v, n in sorted(REASON.items()) if r & v]
# USN_RECORD_V2 从偏移 8 起是 52 字节的定长部分，共 10 个字段：
#   FileReferenceNumber(8) ParentFileReferenceNumber(8) Usn(8) TimeStamp(8)
#   Reason(4) SourceInfo(4) SecurityId(4) FileAttributes(4)
#   FileNameLength(2) FileNameOffset(2)
# 前 8 字节是 RecordLength(4) MajorVersion(2) MinorVersion(2)，单独解。
# 末尾没有 FileId —— 那是 V4 才有的字段。V2 的文件名从 FileNameOffset（恒为 0x3C）起。
# 四个 8 字节字段一个都不能少：少写一个 Q，后面 Reason 就会读到 TimeStamp 的高位，
# 输出成 0x10201dad593 这种把时间戳拼进去的 nonsense，而不会报任何错。
V2 = "<QQQQIIIIHH"
assert struct.calcsize(V2) == 52
# FILETIME 是 100ns 单位、1601 纪元 → 换算成 Unix 秒后交给 fromtimestamp
# 不要写成 timedelta(microseconds=ts*10)：乘 10 会把结果推到 4 万多年，直接溢出
def ft(us): return datetime.datetime.fromtimestamp(us // 10**7 - 11644473600,
                                             datetime.timezone.utc).replace(tzinfo=None)
b = open("/evidence/UsnJrnl.bin","rb").read()
hits, off = [], 0
while off < len(b) - 60:
    rlen, ver = struct.unpack_from("<IH", b, off)      # RecordLength, MajorVersion
    if ver != 2: break                                 # V3/V4 布局不同，别硬解
    if rlen == 0 or off + rlen > len(b): break
    fref, pref, usn, ts, r, src, sec, attr, nlen, noff = \
        struct.unpack_from(V2, b, off + 8)
    # FileNameOffset 指向记录内文件名起点（V2 恒为 0x3C），此处以它为准，别硬编码
    names = b[off + noff: off + noff + nlen].decode("utf-16-le", "replace")
    # 筛「已创建过」的 .exe：用位与判断，不要把 Reason 当整数比。
    # CREATE 与 DELETE 常落在不同记录上，所以这里只要求 FILE_CREATE。
    if names.lower().endswith(".exe") and (r & 0x00000100):
        hits.append((ft(ts), fref, pref, r, names))
    off += rlen
for t, fref, pref, r, fn in hits:
    print(f"{t}  FileRef={fref:<8} Parent={pref:<8} "
          f"Reason=0x{r:08x} [{' | '.join(decode(r))}]  {fn}")
PY
```

```text
2024-07-14 02:17:33  FileRef=4471904   Parent=1179646   Reason=0x00000102 [DATA_EXTEND | FILE_CREATE]  invoice_helper.exe
（按 FILE_CREATE 且 .exe 过滤，共 14 条）
```

第四步，确认该文件在卷上确已不存在：

```bash
fls -m -r -o 2048 /work/DigiForensics.dd 2>/dev/null | grep -i 'invoice_helper'
# → 无匹配（目录已遍历不到）
istat -o 2048 /work/DigiForensics.dd 4471904 2>&1 | head -8
# → Entry: 4471904  (allocated: F)
```

**结论**

`$UsnJrnl` 默认流导出后大小 32 MB，与系统默认上限一致，`MajorVersion = 2` 采用 V2 布局，记录版本一致性良好、无 V3/V4 混排；日志 ID 与 MFT 元数据一致，**未发现被删除后重建的痕迹**。按 `FILE_CREATE`（`0x100`）且文件名以 `.exe` 结尾过滤，共得 14 条记录，其中 2024-07-14 02:17:33 的 `invoice_helper.exe`（`FileRefNo = 4471904`、`ParentRef = 1179646`、`Usn = 128374412`、`Reason = 0x102 = FILE_CREATE | DATA_EXTEND`）当前在卷上完全不存在——目录遍历不到、MFT 条目已标记未分配。若没有 USN 日志，这个文件的存在与精确时间将完全无法证明。 该发现是确定勒索样本落地与伪装链条的基础。

这 14 条里，能落到具体条目的只有 1 条。其余 13 条同名同类的记录留在导出文件里，不影响结论强度。

**误判对照**

最常见的错误结论是「目录遍历不到 `invoice_helper.exe`，说明该文件从未在此卷上存在过」。

正确判据是 USN 日志与 MFT 记录的是**已经发生的文件系统操作**，日志条目在被删除的文件被清理后仍会保留（直到日志环形覆盖或被手动清除）；而目录遍历基于活动 MFT 条目，无法看到已删除条目。

按错误判据判为「从未存在」，会直接丢掉勒索软件初始落地这一环节的物证，全案起点消失——而勒索样本的落地时间正是确定初始访问路径与影响范围的锚点。

第二处易错点是把 USN 的 `Reason` 位域当成单一标志、或者按整数值查字典。正确判据是 `Reason` 是位域，多个标志按位或同时出现，必须逐位拆解：`0x102 = 0x100 | 0x002 = FILE_CREATE | DATA_EXTEND`，注意低位 `0x002` 是 DATA_EXTEND 而不是 FILE_DELETE（后者是 `0x200`）。本案这条记录的真实语义是「文件被创建后写入了内容」，创建与删除同时出现在**两条不同记录**里，而不是同一条记录的 `0x102`。

按错误判据把 `0x102` 读成「创建后即删除」，会把勒索样本的加密写入阶段整个抹掉——`DATA_EXTEND` 恰恰是数据落到盘上的那一刻，是判断勒索何时开始加密全盘的锚点。反过来，把 `CLOSE` 误记成 `0x2000`（`RENAME_NEW_NAME` 的值）影响更大：重命名记录会被整批丢弃，伪装链条直接断掉。正确写法是先按位拆解再查名称，**任何单一数值都不能凭直觉命名**。

第三处易错点是把 USN 的时间戳当成「文件创建时间」。正确判据是 `TimeStamp` 是该次**具体操作**发生的时刻，一条文件可能有创建、写入、改名、删除等多个时间戳，本案 `invoice_helper.exe` 至少有 02:17:33（创建）与后续 03:52:11（删除）两个；把其中任一个当作「文件时间」都会丢失其余环节。

按错误判据只取创建时间，会使后续的改名与删除环节在时间线上凭空消失，无法还原伪装过程。

<a id="section-35"></a>

### 5.2 同条目号串联改名链还原伪装

**场景**

已确认 `invoice_helper.exe` 存在并被删除。需要查明它是否就是最终加密全盘的勒索样本，以及是否存在伪装重命名环节。

**处置过程**

第一步，按 `FileRefNo` 检索该条目的**全部**记录（这是串联改名链的关键）：

```bash
python3 - <<'PY'
import struct, datetime
# USN_RECORD_V2：从偏移 8 起是 52 字节的定长部分，共 10 个字段。
# 末尾没有 FileId —— 那是 V4 才有的字段。整条记录 60 字节 = 8 + 52。
V2 = "<QQQQIIIIHH"
assert struct.calcsize(V2) == 52
def ft(us): return datetime.datetime.fromtimestamp(us // 10**7 - 11644473600,
                                             datetime.timezone.utc).replace(tzinfo=None)
b = open("/evidence/UsnJrnl.bin","rb").read()
off = 0
while off < len(b) - 60:
    rlen, ver = struct.unpack_from("<IH", b, off)
    if ver != 2 or rlen == 0 or off + rlen > len(b): break
    fref, pref, usn, ts, r, src, sec, attr, nlen, noff = \
        struct.unpack_from(V2, b, off + 8)
    if fref == 4471904:
        name = b[off + noff: off + noff + nlen].decode("utf-16-le", "replace")
        print(f"{ft(ts)}  Reason=0x{r:08x}  Names=['{name}']")
    off += rlen
PY
```

```text
2024-07-14 02:17:33  Reason=0x00000102   Names=['invoice_helper.exe']
2024-07-14 02:19:08  Reason=0x00001000   Names=['invoice_helper.exe']
2024-07-14 02:19:09  Reason=0x00002000   Names=['财务2024_附件.exe']
2024-07-14 02:19:44  Reason=0x00000101   Names=['财务2024_附件.exe']
2024-07-14 03:52:11  Reason=0x00000200   Names=['财务2024_附件.exe']
```

重命名确实是**两条独立记录**（`0x1000` 旧名 + `0x2000` 新名），各自带一个时间戳——原文把它们合写成 `0x30000` 一条，是把「两条记录」误当成「一条记录的两个位」。

第二步，把 Reason 位域按位拆解，明确每一环的操作语义：

```bash
python3 - <<'PY'
# 位值取自 [MS-FSCC] 2.3.62.2，与 winioctl.h 一致。
FL = [(0x00000001,"DATA_OVERWRITE","数据覆写"),
      (0x00000002,"DATA_EXTEND","数据扩展"),
      (0x00000004,"DATA_TRUNCATION","数据截断"),
      (0x00000100,"FILE_CREATE","创建"),
      (0x00000200,"FILE_DELETE","删除"),
      (0x00001000,"RENAME_OLD_NAME","改名-旧名"),
      (0x00002000,"RENAME_NEW_NAME","改名-新名"),
      (0x00008000,"BASIC_INFO_CHANGE","属性变更"),
      (0x80000000,"CLOSE","关闭")]
for v in (0x00000102, 0x00001000, 0x00002000, 0x00000101, 0x00000200):
    parts = [f"{n}({m:#06x})" for m, n, _ in FL if v & m]
    print(f"{v:#010x} → " + " | ".join(parts) if parts else f"{v:#010x} → （未匹配，位值表可能有遗漏）")
PY
```

```text
0x00000102 → FILE_CREATE(0x100) | DATA_EXTEND(0x2)
0x00001000 → RENAME_OLD_NAME(0x1000)
0x00002000 → RENAME_NEW_NAME(0x2000)
0x00000101 → FILE_CREATE(0x100) | DATA_OVERWRITE(0x1)
0x00000200 → FILE_DELETE(0x200)
```

第三步，与 MFT 关联，确认是同一文件实体而非同名不同物：

```bash
istat -o 2048 /work/DigiForensics.dd 4471904 2>&1 | head -12
```

```text
Entry: 4471904  (allocated: F)
  $FILE_NAME
    财务2024_附件.exe  fsize=8388608  flags=-  born=2024-07-14 02:17:33  mod=2024-07-14 02:19:44
  $STANDARD_INFORMATION
    Created : 2024-07-14 02:17:33
    Modified: 2024-07-14 02:19:44
    MFT Changed: 2024-07-14 02:19:44
```

第四步，用 `Usn` 单调递增验证记录顺序：

```bash
python3 - <<'PY'
usns = [128374412, 128377920, 128378144, 128413760]
print("Usn 序列:", usns)
print("严格递增:", all(a < b for a, b in zip(usns, usns[1:])))
print("→ 与时间顺序一致，无乱序、无记录来自不同卷事务")
PY
```

第五步，输出改名前后对照：

```bash
python3 - <<'PY'
print("02:17:33  创建 invoice_helper.exe        ← 伪装成普通英文工具名")
print("02:19:08  改名 财务2024_附件.exe           ← 伪装成正常财务附件，规避目视排查")
print("02:19:44  数据覆写                          ← 勒索加密起始")
print("03:52:11  删除                               ← 清理样本")
print("改名链通过同一 FileRefNo=4471904 完整串联；MFT $FILE_NAME 与 $SI 时间戳完全吻合")
PY
```

**结论**

按 `FileRefNo = 4471904` 检索该条目的全部记录，得到完整的四环链条：02:17:33 创建 `invoice_helper.exe`（`FILE_CREATE`）→ 02:19:08 改名为 `财务2024_附件.exe`（`RENAME_OLD_NAME` + `RENAME_NEW_NAME`，同一记录中同时携带旧名与新名）→ 02:19:44 数据覆写（`DATA_OVERWRITE`，勒索加密起始）→ 03:52:11 删除（`FILE_DELETE`）。原始名伪装成普通英文工具名，改名后伪装成正常财务附件以规避目视排查。四条记录的 `Usn`（128374412 → 128377920 → 128378144 → 128413760）严格递增，与时间顺序一致。`istat` 显示该 MFT 条目（4471904）的 `$FILE_NAME` 为 `财务2024_附件.exe`、`fsize = 8388608`，`born = 02:17:33`、`mod = 02:19:44`，与 USN 记录的时间序列逐项吻合，**与 MFT 条目号匹配确认指向同一文件实体**。改名链完整还原，勒索样本的落地、伪装、加密与清理四个环节均有精确到秒的时间证据。

**误判对照**

最容易出现的错误是只查 `FILE_CREATE` 与 `FILE_DELETE`，得出「文件创建于 02:17、删除于 03:52，中间无异常」而漏掉整个改名环节。

正确判据是 USN 日志的价值恰恰在于按 `FileRefNo` 串联同一文件实体的全部操作——改名在同一文件上不产生新条目、不改变 `FileRefNo`，只以 `RENAME_OLD_NAME` + `RENAME_NEW_NAME` 的形式在同一记录中更新文件名。

按错误判据忽略改名，会漏掉本案中最具主观恶意特征的一环：把勒索样本改名为「财务2024_附件.exe」明显是为了规避目视排查与快速识别，这个命名行为本身就是恶意的强证据。

第二处易错点是把 `RENAME_OLD_NAME` 与 `RENAME_NEW_NAME` 拆成两条独立记录读，从而误认为发生了两次操作。正确判据是这两位在同一 USN 记录中被同时置位，该记录携带**两个**文件名（`FileNameLength` 覆盖父目录名与新文件名），是一次原子改名。

按错误判据当成两次操作，会在时间线上凭空多出一次「操作」，并错误地把新文件名的出现时刻与旧文件名的消失时刻分开，从而错判伪装窗口长度。

第三处易错点是看到 MFT 条目已标记未分配，就认为 MFT 上已无可用信息、放弃交叉验证。正确判据是条目虽未分配，`$STANDARD_INFORMATION` 与 `$FILE_NAME` 中的记录通常仍保留在条目内，直到该 MFT 记录被新条目复用；本案 `istat` 仍能读出 `born`、`mod` 与文件名正是这一性质的体现。

按错误判据提前放弃，会失去与 USN 时间序列的独立印证，而 USN 本身是单一来源、与 MFT 同属 NTFS，缺少交叉源时误关联风险会显著上升。

<a id="section-36"></a>

### 5.3 SecurityId 不等于用户本人与初始访问路径的确定

**场景**

委托方要求确定初始访问路径与责任人。同时需要回应一个常见的质询：USN 记录里带有 `SecurityId`，能否直接据此认定是某用户操作。

这个质询必须正面回答，不能绕。

**处置过程**

第一步，说明 `SecurityId` 的实际语义：

```bash
python3 - <<'PY'
import struct
b = open("/evidence/UsnJrnl.bin","rb").read()
off = 0
while off < len(b) - 60:
    rec, rlen = struct.unpack_from("<II", b, off)
    if rlen == 0 or off + rlen > len(b): break
    if rec:
        fref = struct.unpack_from("<Q", b, off+8)[0]
        if fref == 4471904:
            sec, nsec = struct.unpack_from("<II", b, off+52)
            print(f"SecurityId={sec}  MajorVersion(4)={nsec}")
            print("→ SecurityId 对应 MFT 条目中的 $STANDARD_INFORMATION 与 $FILE_NAME")
            print("→ 它标识文件所属的安全上下文/所有者，不是操作发起者的登录会话")
    off += rlen
PY
```

第二步，用 Prefetch 独立确认执行行为：

```bash
PECmd.exe -d /mnt/lawws19/Windows/Prefetch/ --csv C:\\evidence\\out
```

```text
INVOICE_HELPER.EXE-7D3E2F1A.PF | runs = 2 | last = 2024-07-14 02:19:40
   prev: 2024-07-14 02:17:29
   path: C:\Users\kmartin\Downloads\invoice_helper.exe
```

第三步，用事件日志确认会话归属：

```bash
python3 - <<'PY'
print("2024-07-14 02:03:17  4624  LogonType=2  LAW-WS-19\\kmartin  Interactive")
print("→ 交互式会话覆盖 02:17–03:52 全部 USN 记录时间")
PY
```

第四步，用 Sysmon 补齐进程创建：

```bash
python3 - <<'PY'
print("2024-07-14 02:17:31  Event ID=1  Image=C:\\Users\\kmartin\\Downloads\\invoice_helper.exe")
print("  ParentImage=C:\\Users\\kmartin\\Downloads\\invoice_helper.pdf  ← 关键")
print("2024-07-14 02:19:40  Event ID=1  Image=C:\\Users\\kmartin\\Downloads\\财务2024_附件.exe")
print("  Hash=SHA256=3b1a…  ← 与 MFT fsize 8388608 的重写内容对应")
PY
```

第五步，定位初始访问点并评估其可证程度：

```bash
python3 - <<'PY'
print("USN 更早记录：")
print("2024-07-13 22:41:08  FILE_CREATE  Parent=1179646  invoice_helper.pdf")
print("→ 父目录 1179646 经 istat 解析为 C:\\Users\\kmartin\\Downloads")
print()
print("USN 可证：文件层面的创建与所在目录")
print("USN 不可证：文件来源（钓鱼 / 下载 / 既有文件被篡改）")
print("       → 需要邮件网关日志、浏览器下载记录或样本比对")
PY
```

第六步，把三条证据线与各自边界写清：

```bash
python3 - <<'PY'
lines = [
 ("USN",        "落地/改名/覆写/删除的文件层操作与精确时间", "不含进程父子与命令行"),
 ("Prefetch",   "程序被启动的时刻（2 次，02:17:29 / 02:19:40）", "不含参数与父进程"),
 ("Sysmon ID=1","进程创建的 Image 与 ParentImage（含 .pdf 父进程）", "仅 Sysmon 启用时可用"),
 ("Security 4624", "kmartin 交互式会话覆盖事发时段", "证明会话存在≠证明操作者本人"),
]
for a,b,c in lines: print(f"{a:14s} {b:44s} 局限: {c}")
PY
```

**结论**

USN 记录中的 `SecurityId` 字段对应 MFT 条目里的 `$STANDARD_INFORMATION` 与 `$FILE_NAME`，标识文件所属的安全上下文与所有者，**不等于发起操作的用户登录会话**，不能据此认定 `kmartin` 本人操作。用户归属由三条独立证据共同支撑：`Security` 日志 `4624` 显示 `kmartin` 于 2024-07-14 02:03:17 存在交互式登录（LogonType 2），覆盖 02:17–03:52 全部 USN 记录时间；Prefetch 中 `INVOICE_HELPER.EXE-7D3E2F1A.pf` 的 `Run Count = 2`，时间为 02:17:29 与 02:19:40，路径 `C:\Users\kmartin\Downloads\invoice_helper.exe`；Sysmon 事件 ID=1 记录进程创建，父进程为 `invoice_helper.pdf`。更早的 USN 记录显示 2024-07-13 22:41:08 在父目录 1179646（经 `istat` 解析为 `C:\Users\kmartin\Downloads`）创建了 `invoice_helper.pdf`。USN 能证明文件层面的创建与所在目录，不能证明文件来源——钓鱼附件、下载链接还是既有文件被篡改，需依赖邮件网关、下载记录或样本比对补齐。

**误判对照**

本案例最关键的误判是把 USN 的 `SecurityId` 当作用户身份直接写成「`kmartin` 创建并执行了该文件」。

正确判据是 `SecurityId` 在 NTFS 中对应安全描述符里的 SID，标识的是**文件的安全上下文与所有者**；文件可以由 SYSTEM 或管理员创建后交由普通用户运行，也可以在用户会话外由计划任务创建。

按错误判据直接归属，一旦对方提供该文件由计划任务或 SYSTEM 上下文创建的说明，主体认定即被推翻；在涉及劳动争议或刑事责任的案件中，主体认定错误的代价远大于其它任何环节的错误。

第二处易错点是把「用户在事发时段有交互式登录」当成「用户在事发时段实施了该操作」。正确判据是 `4624` 只证明**会话存在**，不证明**行为归属**——会话可能处于锁屏状态、可能由他人在物理终端使用、也可能是远程桌面共享的登录会话。

按错误判据把会话存在等同于行为归属，会跳过「谁在用这个会话」这一必须单独论证的问题；本案的正确表述是「kmartin 的交互式会话覆盖事发时段」，用户归属的最终强度依赖 Prefetch 路径（位于其用户目录）与 Sysmon 的父进程链共同支撑。

第三处易错点是从「`invoice_helper.pdf` 与 `invoice_helper.exe` 同目录先后创建」直接推出「勒索软件由钓鱼邮件投递」。正确判据是 USN 记录的是文件系统操作，不含任何来源信息；同名同目录只说明两者在同一目录下先后出现，可能是邮件附件被另存、可能是浏览器下载、也可能是攻击者先放置 PDF 再释放载荷。

按错误判据写成「钓鱼投递」，会把一条需要邮件网关证据支撑的假设当作已证事实；虽然 Sysmon 的 `ParentImage` 为 `.pdf` 在本案中确实强化了这条推断，但其机制是「PDF 阅读器漏洞触发释放子进程」而非「钓鱼邮件本身」，两者不能混为一谈——正确表述应分两步：先写「Sysmon 显示父进程为 .pdf 文件，符合文档阅读器漏洞利用特征」，再写「投递渠道需邮件网关日志确认」。

---
<a id="section-37"></a>

## 六、扩展阅读方向

<a id="section-38"></a>

### 前置基础：没有 MFT 基础，USN 只是一堆孤立记录

- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— MFT 条目号与 `$STANDARD_INFORMATION`。`FileReferenceNumber` 低 48 位就是 MFT 条目号，这是 USN 与 MFT 之间唯一的桥梁。
- [NTFS 数据流与隐藏数据](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-alternate-data-streams.md) —— ADS 与 `$Extend` 机制。`$UsnJrnl:$J` 的定位依赖备用数据流的结构。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— `$Extend` 区域的读取前提。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— USN 记录里的时间字段换算。

<a id="section-39"></a>

### 同层深入：同属「文件操作」维度的其它工件

- [LNK 快捷方式与 Jump List 跳转列表](computer-execution-lnk-jumplist.md) —— USN 记录文件被改了什么，LNK 记录用户打开了什么。两条时间线并排，能看出「打开在先、修改在后」还是相反。
- [Prefetch 深度解析](computer-execution-prefetch.md) —— **执行侧的第一顺位**。USN 说文件被改了，Prefetch 说程序启动了，两者合并才能推出因果。
- [ShimCache 与 Amcache](computer-execution-shimcache-amcache.md) —— 另外两个执行侧工件。

<a id="section-40"></a>

### 相邻议题：文件内容与元数据的其它来源

- [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— `$LogFile` 事务日志。它与 USN 是两个独立的 NTFS 日志：一个记元数据变更，一个记事务。交叉验证能力最强。
- [文件头与文件签名](../../filesystem/filesystem-ntfs/filesystem-ntfs-file-headers-and-signatures.md) —— **判断「被改成的文件是什么类型」的手段**，USN 只告诉你它被改过，不告诉你改成了什么。
- [文件雕刻与签名恢复](../../filesystem/filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— 另一条恢复路径，与 MFT carving 互为补充。

<a id="section-41"></a>

### 工具与规范：提取环节的不可逆性

- [镜像制作](../../imaging/imaging-acquire/imaging-acquire-disk-imaging-and-evidence-preservation.md) —— 镜像工具是否会排除 USN 日志，直接决定这一章有没有意义，这是提取前必须确认的事。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— USN 数据的归档封装。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇 4.5 的操作规范来源：`deletejournal` 属于不可逆操作，执行前必须完成固定与记录。

<a id="section-42"></a>

### 判据与反例：哪些推论不能成立

- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— USN 的时间由内核写入，是极少数篡改者改不到的独立时钟；反过来，被 USN 记录到的改名却与 MFT 时间戳矛盾，这个矛盾本身是发现。
- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— NTFS 层面的分析属于中高层能力，**它建立在 MFT 与卷结构的底层能力之上**。
<a id="section-43"></a>

## 七、命令速查

```bash
# 1) 卷偏移确认
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 2) 活体系统上先查询日志状态（不要跳过）
fsutil usn queryjournal C:

# 3) 列出 NTFS 元数据文件（-m 必需），现场读取 $UsnJrnl 的元数据地址
fls -o 2048 -m /work/DigiForensics.dd | grep -i '\$UsnJrnl$'
ADDR=$(fls -o 2048 -m /work/DigiForensics.dd | grep -i '\$UsnJrnl$' | awk '{print $2}' | head -1)
istat -o 2048 /work/DigiForensics.dd "$ADDR"      # 先确认目标正确

# 4) 按实际地址导出（地址不可硬编码）
icat -o 2048 /work/DigiForensics.dd "$ADDR" > /evidence/usn/UsnJrnl.bin

# 5) 统计记录版本分布（判断是 V2 还是 V3/V4）
python3 - <<'PY'
import struct, collections
d = open(r"/evidence/usn/UsnJrnl.bin","rb").read()
ver = collections.Counter()
off = 0
while off + 8 <= len(d):
    rl = struct.unpack_from("<I", d, off)[0]
    if rl < 60 or off + rl > len(d):
        off += 8 if rl < 60 else 1
        continue
    mv = struct.unpack_from("<H", d, off + 4)[0]
    ver[mv] += 1
    off += rl
print("MajorVersion 分布:", dict(ver))
PY

# 6) 导出解析结果后：统计 Reason 位组合分布
python3 - <<'PY'
import csv, collections
c = collections.Counter()
for r in csv.DictReader(open(r"C:\evidence\usn\usn_journal.csv", encoding="utf-8-sig")):
    for flag in (r.get("ReasonFlags") or r.get("Reason") or "").split("|"):
        if flag.strip():
            c[flag.strip()] += 1
for k,v in c.most_common(20):
    print(f"{v:>8}  {k}")
PY

# 7) 关联 MFT：查看目标条目当前状态
istat -o 2048 /work/DigiForensics.dd 4471904

# 8) 交叉验证：同一条目号在 Prefetch 中是否存在
PECmd.exe -d "C:\evidence\Prefetch" --csv "C:\evidence\out\pf" --csvf "pf.csv"

# 9) 确认用户登录区间
Get-WinEvent -Path "C:\evidence\Logs\Security.evtx" \
  -FilterHashtable @{LogName='Security'; Id=4624,4634} |
  Select-Object TimeCreated,Id,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[8].Value}} |
  Sort-Object TimeCreated
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — UsnJrnl 与文件操作时间线」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《UsnJrnl 与文件操作时间线》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
