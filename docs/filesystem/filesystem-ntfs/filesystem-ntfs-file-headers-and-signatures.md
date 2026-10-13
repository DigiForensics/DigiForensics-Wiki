---
title: "文件头与文件签名"
slug: "filesystem-ntfs-file-headers-and-signatures"
canonical: "https://www.digiforensics.cn/wiki/filesystem-ntfs-file-headers-and-signatures"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:51+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "filesystem"
space: "文件系统分析"
node_path: ["NTFS"]
---

# 文件头与文件签名

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/filesystem-ntfs-file-headers-and-signatures)

<a id="section-1"></a>

## 一、概述

用户和操作系统看到的是"这是一个 `.jpg`"，但磁盘上真正决定它"是什么"的，是**文件开头那几个字节**。扩展名是文件名的属性，不是文件的属性。

这两个依据一旦分离，差异会直接变成结论差异：

| 场景 | 靠扩展名判断 | 靠文件头判断 |
|---|---|---|
| 检材是磁盘镜像 | ✗ 目录项里的名字可被任意伪造 | ✓ 头几字节是格式定义写死的 |
| 检材是 carving 产物 | ✗ 工具按签名分配扩展名 | ✓ 同一依据，循环论证 |
| 可疑文件定性 | ✗ `发票.pdf` 实际是 PE | ✓ **头不同 = 结论不同** |
| 篡改后缀伪装 | ✗ 完全失效 | ✓ **可被识破** |

所以要处理的就是这个分离带来的判定问题：怎么读头、怎么交叉比对、怎么把"看起来是什么"变成"结构上是什么"。

这件事落在**分析环节的类型判定阶段**，几乎是每个案件都会经过的通用动作，在流程里承担两个不同角色：

- **入口判据**：从磁盘里提取出来的字节（`icat` 结果、carving 产物、附件）首先需要类型判定，否则后续所有内容分析都用错工具
- **出口校验**：认定某个文件"是什么"之后，还要反向验证它"没被改动过"——**头尾成对、内部校验和自洽**才是强依据

上游是提取动作（拿到字节）与文件系统元数据（拿到大小与时间戳）；下游是内容解读、隐写与容器结构检查、**以及元数据与内容的时间一致性比对**。第五章案例里"文件系统 `Created` 早于文档内部创建时间 2 分 44 秒"这种发现，只有在类型判定正确之后才可能被发现。

落到具体证据上：

- **魔数（magic number）** —— 格式开头的固定字节。三种形态：可打印字符串（`PK\x03\x04`、`%PDF`、`GIF89a`）、固定十六进制（PNG `\x89PNG\r\
\x1a\
`、ELF `\x7fELF`）、**定长数值 + 二次跳转**（PE 的 `MZ` + 偏移 0x3C 处的 `PE\0\0`，**头不连续**）
- **结束标记** —— JPEG 的 `FFD9`（EOI）、PNG 的 `IEND`、GIF 的 `0x3B`、PDF 的 `%%EOF`。**头尾成对是结构完整性的最低门槛**
- **内部校验和** —— ZIP 与 GZIP 的 CRC32、OOXML 的关系文件。**`unzip -t` 全通过比"能打开"强得多**
- **EOCD 与中央目录** —— ZIP 尾部的目录记录。中央目录偏移 + 大小 + 22 字节是否等于文件实际大小，是判断"尾部被追加数据"的关键算式
- **容器与成员的层级** —— `.docx` / `.xlsx` / `.pptx` 实际是 ZIP，内含 `[Content_Types].xml`、`_rels/.rels`、`xl/workbook.xml`。这三个条目同时存在才是真 OOXML，仅有 `PK` 头只能证明是 ZIP
- **字节序标记** —— PE 的 PE32/PE32+、ELF 的 EI_CLASS、Mach-O 的 magic。同为 32 位/64 位可执行文件，字节序不同会让所有偏移解释反过来
- **声明尺寸与实际尺寸的差** —— BMP 头声明宽高小于文件实际大小、图片元数据声明尺寸与像素数据不匹配。**这类"结构自相矛盾"是隐写与截断的常见指示**
- `file` / `file -b --mime-type` / `file -r` 的输出 —— 类型判定工具输出。注意 `--mime-type` 常给通用类型（`application/zip`），不是工具失灵而是它确实区分不了
- `xxd` / `od` 的十六进制首 64 字节 —— 人工复核的最终依据
- `DigiForensics.dd` 中提取出的可疑文件 —— 这里的输入。**必须先固定哈希再看头**，否则分析的不是证据而是副本

走完这一层能回答的是这些：这个文件在结构上是什么格式、它的头尾与内部校验是否自洽、扩展名与实际类型是否一致、**以及某个容器里装了哪些成员**。

**回答不了的几件事要说清**：

- **文件的来源与作者** —— 文档元数据里的作者字段**可由生成方任意填写**。`core.xml` 的 `dc:creator` 不是身份证据
- **内容是否被改过** —— 校验和通过只证明"与写入时一致"，**不证明"写入时就是原始内容"**。判定篡改要靠多源时间比对
- **是否存在任何隐藏内容** —— 签名扫描扫的是"已知形状"，**检测不到加密、变形、刻意规避签名的载荷**。polyglot 文件就是签名扫描的盲区
- **carving 产物的有效性** —— 头尾齐全的碎片和真实文件在签名层面无法区分。清洗与功能验证在 [文件雕刻与签名恢复](../filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)
- **文件的具体内容语义** —— 类型对了不等于内容可读（还可能是加密的，见 [EFS 文件系统加密取证](../../crypto/crypto-volume/crypto-volume-efs.md)）

前提只有两条：**会看十六进制**、**知道字节序这个概念**。不需要提前读 [NTFS 结构与 MFT 解析](filesystem-ntfs-ntfs-master-file-table.md)——对文件系统只提出"用 `icat` 把文件提取出来"这一个要求。但如果已经读了那篇，会更清楚"声明长度"与"簇大小"的差值如何影响提取结果，那是 [NTFS 数据流与隐藏数据](filesystem-ntfs-ntfs-alternate-data-streams.md) 里 slack 话题的入口。

各类格式的魔数与结构约束在[核心原理](#section-2)，`file` / `xxd` / `binwalk` 的组合用法与验证流程在[操作步骤](#section-8)。

最容易被误用的地方是把工具输出直接当结论，[常见陷阱](#section-13)的 4.2 与 4.3 组专门处理这件事——`application/zip` 不是失灵、CRC 全通过不等于没被篡改。完整判定流程见[案例示例](#section-30)，常用签名的十六进制速查见[命令速查](#section-40)。

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 魔数：格式为什么要写死自己的名字

**魔数（magic number）** 是文件开头的固定字节序列，等同于格式的"身份证"。它存在的理由很朴素：读取方必须在读任何内容之前就知道这是什么格式，而文件名和扩展名都可以被改。魔数有三种形态：可打印字符串（`PK\x03\x04`、`%PDF`、`GIF89a`，直观易人工识别）、**固定十六进制**（PNG `\x89PNG\r\
\x1a\
`、ELF `\x7fELF`，有时含不可打印字节）、**定长数值 + 偏移**（PE 的 `MZ` + 0x3C 处的 `PE\0\0`，**头不是连续的，需二次跳转**）。

一个必须知道的现实：魔数不是标准，是各格式的"事实约定"。因此同一个字节序列可能被多种格式占用（见 2.4）；有些格式根本没有魔数（纯文本、CSV、某些日志）；有些格式的魔数在文件中间或尾部（PDF 的 `%%EOF`、ZIP 的中央目录与 EOCD）。必须用工具判断，不要凭记忆。`file` 报 "data" 也不是"无价值"，只是**需要人工介入**。

<a id="section-4"></a>

### 2.2 常用文件签名对照表

偏移列是相对文件开头的字节偏移；尾部标记另见 2.3。

| 格式 | 偏移 | 魔数（十六进制） | 格式 | 偏移 | 魔数（十六进制） |
|---|---|---|---|---|---|
| **PNG** | 0 | `89 50 4E 47 0D 0A 1A 0A` | **OLE2** (Office 97-03) | 0 | `D0 CF 11 E0 A1 B1 1A E1` |
| **JPEG** | 0 | `FF D8 FF`（第 3 字节随版本变） | **SQLite 3** | 0 | `53 51 4C 69 74 65 20 66 6F`…`33 00` |
| **GIF87a / 89a** | 0 | `47 49 46 38 37 61` / `…38 39 61` | **Windows LNK** | 0 | `4C 00 00 00`（偏移 4 起是 GUID） |
| **PDF** | 0 | `25 50 44 46 2D` | **PCAP / PCAPNG** | 0 | `D4 C3 B2 A1`（含字节序）/ `0A 0D 0D 0A` |
| **ZIP** | 0 | `50 4B 03 04` | **RTF** | 0 | `7B 5C 72 74 66 31`（`{\rtf1`） |
| **RAR 4.x / 5.x** | 0 | `52 61 72 21 1A 07 00` / `…07 01 00` | **RIFF** (AVI/WAV) | 0 | `52 49 46 46`（偏移 8 是类型） |
| **7-Zip / GZIP** | 0 | `37 7A BC AF 27 1C` / `1F 8B 08` | **MP4/MOV (ftyp)** | **4** | `66 74 79 70`（moov/mdat 原子） |
| **BZIP2 / XZ** | 0 | `42 5A 68` / `FD 37 7A 58 5A 00` | **PE/EXE (DOS 头)** | 0 | `4D 5A` |
| **ELF** | 0 | `7F 45 4C 46` | **PE/EXE (PE 头)** | **0x3C 处指向** | `50 45 00 00`（Mach-O 见 2.5） |

> **两个必须记住的例外**：`%PDF-` **前面可能有一段垃圾字节**（某些生成器会在文件前加 BOM 或空白），严格解析时应允许在**前 1024 字节内**搜索 `%PDF`，这也是 carving 工具对 PDF 采用宽松匹配的原因。PE 则是"两头"结构：`MZ` 在偏移 0，真正的 `PE\0\0` 在**偏移 0x3C 指向的位置**——只看 `MZ` 会把任何 DOS 可执行文件（含许多老程序）误判为现代 PE，解析器必须做二次跳转验证。

<a id="section-5"></a>

### 2.3 头尾成对：结构完整性的验证

**只认头不认尾，等于只验证了一半。** 常用配对：PNG `89 PNG…` ↔ `IEND….`；JPEG `FFD8FF` ↔ `FFD9`；GIF `GIF89a` ↔ `003B`；PDF `%PDF` ↔ `%%EOF`（可能多个）；ZIP `PK\x03\x04` ↔ `PK\x05\x06`（**EOCD 存在且中央目录偏移正确才算可列目录**）；GZIP `1F8B08` ↔ 末 8 字节的 **CRC32 + ISIZE**。

**但最严格的验证是"功能验证"，不是"标记验证"**——`pngcheck` 会走完全部 chunk CRC 校验，`pdfinfo` 能解析出页数，`identify` 能解码出尺寸。

头尾标记齐全但内部 CRC 失败的文件，必须在报告里记为"内容损坏"：它在证据上是"存在但不可用"，与"不存在"是完全不同的结论。GZIP 则相反——它的尾部 CRC32 + ISIZE 就是功能校验，能完整解压即证明通过。

<a id="section-6"></a>

### 2.4 ZIP 家族：一个魔数，多种格式

**这是最容易误判的一类**，因为 Office 2007+、OpenDocument、Java JAR、APK、EPub、Python wheel 全都是 ZIP。判定方法只有一个：**列出内部条目，看目录结构**。

它们魔数全是 `PK 03 04`，只能靠内部条目区分：OOXML 有 `[Content_Types].xml` + `word/` `xl/` `ppt/`；OpenDocument 有 `mimetype`（**必须位于偏移 0**）；JAR/APK 有 `META-INF/MANIFEST.MF` / `AndroidManifest.xml`；EPUB 与 Python wheel 则是 `mimetype`+`META-INF` / `*.dist-info/`。

**这些路径是规范强制的**——一个真正的 docx 必然同时具备 `[Content_Types].xml` 与 `word/document.xml`，xlsx 则是 `[Content_Types].xml` + `xl/workbook.xml`；手工改扩展名造出的假 docx 内部不会有这些结构，`unzip -l` 一眼识破。
>
> **为什么"改扩展名"骗不过 `file`**：`.docx` 与任意 ZIP 的头部**字节完全相同**，`--mime-type` 只会给出通用的 `application/zip` 而非 `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`。**这是正常的，不是工具失灵**——必须进容器内部才能定案。

**OOXML 的三个取证优势**：① 内容是明文 XML，可直接全文搜索（`unzip -p report.docx word/document.xml`，在 OLE2 的 `.doc` 上这样做无效）；② 内部条目名与时间是独立元数据来源（`unzip -l`，但条目时间是写入时的本地时间，可被改，只能作旁证）；③ 宏与外链可精确定位（`vbaProject.bin`、`.rels` 里的 `Target`）。

**局限**：XML 压缩存储，`strings` 未必命中，必须先 `unzip -p` 取出再搜；批注在 `word/comments.xml`，数字签名在 `_xmlsignatures/`。

**ZIP 的结构性事实与一个取证要点**：EOCD 记录中央目录的偏移与大小，中央目录又记录每个条目数据区的绝对偏移。"尾部追加数据"因此可被精确检出，见 3.2 的 `zipcheck.py`。

注意 `zip -T` 只做 CRC 测试、不报告尾随数据，报告尾随数据的是 `unzip` 的 `extra bytes at beginning or within zipfile` 告警。ZIP 格式本身允许在归档前后附加任意数据而不影响解压，所以"能正常打开"绝不等于"未被改过"。

<a id="section-7"></a>

### 2.5 可执行文件头：PE / ELF / Mach-O 的字节序陷阱

三类可执行格式是**识别恶意样本、判断跨平台文件**的基础，但**字节序是最大的误判来源**：

```
PE（Windows）：  [0x00] 4D 5A "MZ"
                [0x3C] PE 偏移量(4字节, LE) → 该处必须是 50 45 00 00 "PE\0\0"
ELF（Linux）：   7F 45 4C 46 "\x7fELF"，第 5 字节 EI_CLASS 01=32位 02=64位
                第 6 字节 EI_DATA  01=LE 02=BE   ← 字节序标记
```

Mach-O 的四个变体，取决于"看到的字节"和"按什么顺序解释成整数"：

| 磁盘上的前 4 字节 | 小端解释为 | 常量 | 含义 |
|---|---|---|---|
| `CE FA ED FE` | `0xFEEDFACE` | `MH_MAGIC` | 32 位，本机序小端 |
| `FE ED FA CE` | `0xCEFAEDFE` | `MH_CIGAM` | 32 位，本机序大端（字节序需交换） |
| `CF FA ED FE` | `0xFEEDFACF` | `MH_MAGIC_64` | **64 位，本机序小端** |
| `FE ED FA CF` | `0xCFFAEDFE` | `MH_CIGAM_64` | 64 位，本机序大端 |

> **为什么这张表反直觉**：Mach-O 的魔数是一个按宿主字节序解释的整数。`CF FA ED FE` 按小端解释得 `0xFEEDFACF`，落在 `MH_MAGIC_64` 上，所以是 64 位小端；而看起来更整齐的 `FE ED FA CF` 解释出来是 `MH_CIGAM_64`，反而是大端。记不住就查表，不要凭字节排列的直觉判断。

另一个歧义是 `CA FE BA BE`，它同时是 Mach-O 通用二进制（fat）和 Java class 文件的头，区分靠偏移 4 之后：Java 存放大端版本号（`00 00 00 34` = 52 → Java 8），fat 二进制则是架构描述符个数等结构，遇到它不能直接下结论。

`file` 是首选，它会直接给出架构；只有当 `file` 不可用或需要取证级精确时，才手工做 PE 的二次跳转。

---
<a id="section-8"></a>

## 三、操作步骤

<a id="section-9"></a>

### 3.1 第 1 步：查看文件头，用 `file` 判定并交叉比对

```bash
xxd -l 64 /evidence/mystery.bin
# 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG..........IHR
# 00000010: 0000 01f4 0000 03e8 08 02 00 00 00 8d 0a24 64  .......h..¤$d
xxd -s $((0x3C)) -l 4 /evidence/prog.exe     # 先读 PE 的 e_lfanew
xxd -s $((0x80)) -l 64 /evidence/prog.exe     # 再跳到 PE 头验证 50 45 00 00
xxd -l 64 -p /evidence/mystery.bin            # 纯十六进制，无 ASCII 栏
file /evidence/mystery.bin       # PNG image data, 1920 x 1080, 8-bit/color RGB, non-interlaced
file -b --mime-type /evidence/mystery.bin    # 简要类型 / MIME（-i 会连 charset 一起给）
# 批量分类：carving 产物
file -r --mime-type /evidence/carved/ | cut -d: -f2- | sort | uniq -c | sort -rn | head
#  18432 image/jpeg      3210 image/png      847 application/zip ← 需再区分 docx/xlsx/jar
# 与扩展名交叉比对，找出"不符"的文件（核心步骤，见 3.3）
cd /evidence/carved && for f in *; do
  ext="${f##*.}"; ft=$(file -b --mime-type "$f")
  case "$ext:$ft" in
    jpg:image/jpeg|png:image/png|pdf:application/pdf) ;;
    jpg:*|png:*|pdf:*|docx:*|xlsx:*) echo "不符: $f  扩展名=$ext  实际=$ft" ;;
  esac
done > /evidence/mismatch.txt
```

**读十六进制的三个技巧**：① 看前 8–16 字节，绝大多数格式的魔数都在这里（见 2.2）；② 找 `00` 密集区——`00 00 00 00` 常是版本号或填充，连续 `00` 之后突然出现版本号，是"版本-时间"式结构的典型；③ 找不可打印字节——大量 `FF`、`00`、`8D`、`9C` 混杂 = 压缩或加密数据**，可打印字符连续则是文本。

<a id="section-10"></a>

### 3.2 第 2 步补：验证完整性（头尾成对 + 功能验证 + 尾随数据）

```bash
# ① 头尾成对检查
head -c 8  /evidence/x.png | xxd -p      # 期望 89504e470d0a1a0a
tail -c 12 /evidence/x.png | xxd -p      # 期望 49454e44ae426082 (IEND)
# ② 功能验证（按类型）—— 缺一不可
pngcheck -v /evidence/x.png              # PNG 全 chunk CRC
unzip -t  /evidence/x.docx               # ZIP 全项 CRC（-t 不解压）
pdfinfo    /evidence/x.pdf               # 能否解析出页数
identify   /evidence/x.jpg               # 能否解码出尺寸
# ③ ZIP 尾随数据检查（zip -T 不做这件事，必须自己比对 EOCD）
python3 /evidence/zipcheck.py /evidence/x.docx
# [OK]    期望 48216 字节，实际 48216 字节 → 无追加数据
# [追加]  4286 + 2526 + 22 = 6834，实际 84000 → 尾部多出 77166 字节
```

**`zipcheck.py` 的原理**（EOCD 固定 22 字节，以 `PK\x05\x06` 开头，位于文件末尾，注释最长 65535 字节）：

```python
import struct, sys
d = open(sys.argv[1], "rb").read()
i = d.rfind(b"PK\x05\x06")                            # 从尾部反查 EOCD
if i < 0: sys.exit("[-] 未找到 EOCD：文件被截断或不是 ZIP")
cdoff, cdsize = struct.unpack_from("<II", d, i + 8)     # 偏移 8=目录大小, 12=目录偏移
expect = cdoff + cdsize + 22 + struct.unpack_from("<H", d, i + 20)[0]   # +22=EOCD, +注释长
print(f"期望 {expect} 字节，实际 {len(d)} 字节" + ("" if expect==len(d) else f" → 差 {len(d)-expect}"))
# 差值 > 0 = 尾部有附加数据（追加/伪装载荷）；差值 < 0 = 结构自相矛盾（中央目录被改写）
```

> **`unzip -t` 通过 ≠ 文件未被改过**：它只逐项校验 CRC，**不检查尾部是否被追加数据**，而 ZIP 格式**允许**在归档前后附加任意数据而仍能正常解压，因此**追加型伪装恰恰能通过 `unzip -t`**。追加数据在取证中意义重大（隐藏在合法文档尾部的第二份文档、宏载荷等），**必须用上面的 EOCD 自洽性检查单独排除**。

<a id="section-11"></a>

### 3.3 第 3 步：识别"头与扩展名不符"（伪装检测）

**伪装分四类**：A 单纯改扩展名（`file` 报 `image/jpeg` 但扩展名是 `txt`）、B 首部注入（前面插入 shellcode 再接原头，靠搜索 0–512 字节范围内的魔数偏移检出）、C 格式内嵌（PE 内嵌 PDF/图片，用 `binwalk` 扫）、D 双扩展名（`合同.pdf.exe`，看实际头并查杀软告警）。对 A/B 类的系统化检测脚本见 `/evidence/disguise.py`：

```python
import os, sys
SIG = {b'\x89PNG\r\
\x1a\
':'PNG', b'\xff\xd8\xff':'JPEG', b'%PDF-':'PDF', b'PK\x03\x04':'ZIP',
       b'\x7fELF':'ELF', b'MZ':'PE/DOS', b'GIF89a':'GIF', b'\x1f\x8b\x08':'GZIP',
       b'\xd0\xcf\x11\xe0':'OLE2', b'\xca\xfe\xba\xbe':'FAT/Java'}
EXT = {'png':'PNG','jpg':'JPEG','pdf':'PDF','zip':'ZIP','exe':'PE/DOS','dll':'PE/DOS',
       'doc':'OLE2','docx':'ZIP','xlsx':'ZIP','pptx':'ZIP','elf':'ELF','gif':'GIF','gz':'GZIP'}
for dirpath,_,files in os.walk(sys.argv[1]):
    for fn in files:
        p = os.path.join(dirpath, fn)
        ext = fn.rsplit('.',1)[-1].lower() if '.' in fn else ''
        with open(p,'rb') as f: data = f.read(4096)
        name, off = next(((n,i) for s,n in SIG.items() if (i:=data.find(s)) != -1), (None,-1))
        if not name: print(f"[未知] {fn}  扩展名={ext or '(无)'}  → 需人工查看"); continue
        exp = EXT.get(ext)
        if exp and name != exp: print(f"[伪装] {fn}  声称={ext}({exp})  实际={name}  魔数偏移={off}")
        elif off > 0:        print(f"[注入] {fn}  {name} 位于偏移 {off}  ← 头前有 {off} 字节数据")
        else:                print(f"[一致] {fn}  {name}")
```

**输出解读（报告里直接可用的技术细节）**：

| 输出 | 报告写法 |
|---|---|
| `[伪装] 发票.pdf` 实际 JPEG，偏移 0 | "扩展名为 .pdf，实际格式为 JPEG（魔数 `FFD8FF` 位于偏移 0），**内容非 PDF 文档**" |
| `[注入] update.exe` 实际 PE，偏移 884 | "该文件前 884 字节为注入代码，PE 头位于 884；**首字节 `MZ` 缺失，无法被系统正常执行**" |
| `[伪装] 报表.xlsx` 实际 ZIP 但非 OOXML | "扩展名 .xlsx，实际为普通 ZIP（`unzip -l` 无 `[Content_Types].xml`），**并非 Excel 文档**" |
| `[未知]` | `head -c 100` + `strings` 人工判定；**不要直接归为"无价值"** |

<a id="section-12"></a>

### 3.4 第 4–5 步：`binwalk` 探测内嵌结构并建立类型清单

```bash
binwalk /evidence/prog.exe
# DECIMAL    HEXADECIMAL    DESCRIPTION
# 0          0x0            7zXZ data
# 100        0x64           PNG image data, 1920 x 1080
# ⚠ 4660    0x1234         Zip archive data, at least v2.0 to extract
# ⚠ binwalk -e 会向当前目录写大量文件，务必隔离在专用目录
mkdir -p /evidence/binwalk-out && cd /evidence/binwalk-out && binwalk -e /evidence/prog.exe
# 精确提取指定偏移区间（更可控，推荐）
dd if=/work/DigiForensics.dd bs=1 skip=$((0x64)) count=4096 of=/tmp/embedded.png status=none
file /tmp/embedded.png
cd /evidence/carved   # 建立类型清单，进入 carving 流程
file -r --mime-type . | cut -d: -f2- | sort | uniq -c | sort -rn > /evidence/type-inventory.txt
sha256sum * > /evidence/carved-hashes.txt
sort -k1,1 /evidence/carved-hashes.txt | uniq -w64 -D > /evidence/duplicates.txt
wc -l /evidence/duplicates.txt   # 重复数量是"碎片/重复"的量化指标
```

> **`binwalk` 的定位是"发现"而非"判定"**：它的输出只告诉你"某偏移处有个像 PNG 的东西"，**那可能只是巧合的字节序列**。**必须用 `file` 或功能验证二次确认**——不能把 `binwalk` 的匹配直接写成"内嵌了一个 PNG 文件"。
>
> **"类型分布 vs 预期数量"的交叉验证是必需的**：carving 产物的数量远超系统实际文件数，**说明绝大多数是碎片或重复**。**不清洗就直接提交，是取证流程的重大缺陷**（详见 [10](../filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)）。

---
<a id="section-13"></a>

## 四、常见陷阱

本章按「类型判定 → 完整性与篡改 → 容器与内容 → 结论表述」归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-14"></a>

### 4.1 类型判定：扩展名、偏移、字节序

<a id="section-15"></a>

#### 陷阱 1：把扩展名或 `file` 的一行输出当作类型定性

**现象**：`file 对账单.xlsx` 输出 "Microsoft Excel 2007+"，分析员写"该文件是 Excel 文档，格式正确"。

**原因**：`.docx` / `.xlsx` / `.pptx` 实际都是 ZIP 容器（2.4），而 `--mime-type` 对它们给出的正是通用 `application/zip`——**这不是工具失灵，是头部字节完全相同**。

`file` 能识别出"这是一个 ZIP 容器"，它没有任何信息能告诉你容器里装的是 Excel 还是 Java JAR。而扩展名更是可以任意改写的东西（一章的对照表：扩展名是文件名的属性，不是文件的属性）。

**影响**：一个把任意 ZIP 改名为 .xlsx 的文件，会被这条判据完整放行。案例里第 1 步的输出正是这个形态——`file` 报了 "Microsoft Excel 2007+"，`--mime-type` 报 `application/zip`，两个信号都存在，真正定案的是第 3 步的 `unzip -l`。

跳过容器内检，结论就停在"看起来是"。

**核查**：**判定分两层，头部只能给第一层**：

```bash
file -b --mime-type /evidence/对账单.xlsx     # 第一层：只是 ZIP
unzip -l /evidence/对账单.xlsx                # 第二层：容器内结构才定案
#  必须同时具备：[Content_Types].xml + xl/workbook.xml  → 真实 xlsx
#  必须同时具备：[Content_Types].xml + word/document.xml → 真实 docx
#  无 [Content_Types].xml → 是 ZIP，但不是 OOXML
```

**报告写法**：定性依据必须是容器内条目，**不是 `file` 的一行输出**——

> "该文件魔数 `50 4B 03 04`，为 ZIP 容器；`--mime-type` 输出 `application/zip`。经 `unzip -l` 确认存在 `[Content_Types].xml`、`_rels/.rels`、`xl/workbook.xml` **三项 OOXML 强制结构**，判定为真实 Excel 文档。"

同一枚硬币的另一面：`file` 报 `data` 也不能当作剔除依据（2.1 已明确"`file` 报 data 时也不是无价值，只是需要人工介入"）。

**`data` 只意味着"我的魔数库里没有匹配项"**——未收录格式、变种格式、头部被破坏的文件、本身就以数据形式存储的容器（某些数据库、固件、序列化对象）都会落进这一类。

把 `[未知]` 读成"无价值"，删掉的可能恰恰是价值最高的那批：

```bash
# 报 data 时先看头，再看可打印内容的形态
head -c 100 /evidence/mystery.bin | xxd
head -c 200 /evidence/mystery.bin | strings
# 大量 FF/00/8D/9C 混杂 = 压缩或加密数据；可打印字符连续 = 文本或未收录文本格式
binwalk /evidence/mystery.bin     # 看是否有嵌套签名
```

报告写法："批量分类中 `<N>` 个文件 `file` 输出为 `data`，已逐个以 `xxd` 前 64 字节与 `strings` 前 200 字节人工查看，其中 `<M>` 个识别为 `<格式>`，`<K>` 个判定为 `<加密数据 / 已损坏 / 未识别格式>`。**未识别部分未做进一步结构解析。**"

<a id="section-16"></a>

#### 陷阱 2：只判断魔数在不在，不看它的偏移

**现象**：`update.exe` 前 884 字节是注入代码，PE 头在 884；分析员按"在文件里搜到 MZ"的方式确认，报告写"该文件是可执行程序"。

**原因**：2.3 与 3.3 的检测脚本都把**偏移**作为判据而非"是否命中"。

偏移 0 命中意味着"这个文件以该格式开头"，偏移大于 0 意味着"文件头之前有别的东西"——后者是完全不同的两种情形：一个是正常文件，一个是注入型伪装（伪装类型 B）。

而 `grep -c MZ` 这类做法**丢掉了偏移这个维度**，两种情形被合并成同一个"命中"。

**影响**：**把注入型伪装判成了正常文件**。案例的输出解读表里，这一项的正确表述是"该文件前 884 字节为注入代码，PE 头位于 884；**首字节 `MZ` 缺失，无法被系统正常执行**"——后半句是这个偏移值**最有价值的信息**，丢掉偏移就等于丢掉它。

**同时它也提示另一种可能：文件是被截断的**（真实 PE 前面不该有东西）。

**核查**：**命中即记录偏移，并对非零偏移单独定性**：

```bash
python3 /evidence/disguise.py /evidence/suspect
# [注入] update.exe  PE/DOS  位于偏移 884  ← 头前有 884 字节数据
# [一致] photo.jpg   JPEG    位于偏移 0
```

**2.2 的两个例外必须给宽松窗口**——PDF 的 `%PDF-` 允许**前 1024 字节内**存在垃圾字节（某些生成器加 BOM 或空白），所以"偏移 0–1024 内命中"对 PDF 属正常。

但对 PNG、ZIP、ELF 这类必须以 0 为准的格式，非零偏移就是异常。

**报告写法**：非零偏移一律写明"魔数位于偏移 `<N>`，文件前 `<N>` 字节为 `<已提取内容 / 未提取内容>`"。

<a id="section-17"></a>

#### 陷阱 3：看到 `MZ` 就认定是现代 PE

**现象**：在 carve 出的文件里看到 `4D 5A`，直接归类为 "Windows PE 可执行文件"，据此做恶意性研判。

**原因**：**`MZ` 只是 DOS 可执行头**，它存在的原因是 DOS 时代的兼容性，现代 Windows PE 保留它只是为了这个历史包袱。任何 DOS 时代的可执行文件、许多老程序都以 `MZ` 开头。

**真正的判据是二次跳转**：偏移 `0x3C` 处存的是 PE 头的偏移量（小端 4 字节），跳到该位置必须读到 `50 45 00 00`（`PE\0\0`），才算现代 PE。

**影响**：**格式定性错误会直接传染到后续所有研判**。一批"PE 文件"里混进老 DOS 程序与被截断的文件，而"可执行文件数量"这个统计值本身就不可信了。

**在恶意样本场景下更麻烦**：把非可执行数据报成可执行文件，会引导分析员去做无意义的动态分析。

**核查**：**两步走，缺一不可**：

```bash
xxd -s $((0x3C)) -l 4 /evidence/prog.exe    # ① 先读 e_lfanew（小端）
# 输出 80 00 00 00 → PE 头在偏移 0x80
xxd -s $((0x80)) -l 64 /evidence/prog.exe   # ② 跳过去验证 50 45 00 00
file /evidence/prog.exe                      # 首选：它会做这个判断
```

**`file` 不可用时才手工做二次跳转。** 若 `0x3C` 处跳过去不是 `PE\0\0`，正确结论是"DOS 可执行文件（无 PE 头）"，**不是"PE 文件"**。

<a id="section-18"></a>

#### 陷阱 4：Mach-O 字节序按字节排列的直觉判断

**现象**：看到 `CF FA ED FE` 判定为"Mach-O 64 位大端"，据此在取证报告中写"样本为 64 位大端 Mach-O"。

**原因**：**Mach-O 的魔数是一个按宿主字节序解释的整数**（2.5 的表格就是这个意思）。

`CF FA ED FE` **按小端解释**得 `0xFEEDFACF`，落在 `MH_MAGIC_64` 上——**所以它是 64 位本机序小端**。而看起来更"整齐"的 `FE ED FA CF` 解释出来是 `MH_CIGAM_64`，反而是大端。

**按字节排列的顺序感去判断，四个变体会判反两个。**

**影响**：**架构结论错误会误导整条分析路径**——大端/小端决定了后续的解析工具选择、反汇编器配置与内存布局假设。这类错误在报告里通常不会被质疑，因为字节本身是看得见的，**错的是解释环节**。

**核查**：**按"小端解释出的整数"对照常量表，不看字节排列**：

| 磁盘前 4 字节 | 小端解释 | 常量 | 结论 |
|---|---|---|---|
| `CE FA ED FE` | `0xFEEDFACE` | `MH_MAGIC` | 32 位小端 |
| `FE ED FA CE` | `0xCEFAEDFE` | `MH_CIGAM` | 32 位大端 |
| `CF FA ED FE` | `0xFEEDFACF` | `MH_MAGIC_64` | **64 位小端** |
| `FE ED FA CF` | `0xCFFAEDFE` | `MH_CIGAM_64` | 64 位大端 |

**首选仍是 `file`**——它直接给出架构。表格只在需要取证级精确、且 `file` 不可用时使用。

<a id="section-19"></a>

#### 陷阱 5：用 `CA FE BA BE` 断定是 Mach-O 通用二进制

**现象**：`file` 或十六进制里看到 `CA FE BA BE`，直接写"这是 Mach-O fat 二进制，内含多架构"。

**原因**：**这个魔数同时是 Java class 文件的头**（2.5 的歧义说明）。区分靠**偏移 4 之后的结构**：Java 存放大端版本号（`00 00 00 34` = 52 → Java 8），fat 二进制则是架构描述符个数与各架构描述。

两者的后续结构完全不同，但头部 4 字节完全一致。

**影响**：**把 Java 字节码当成多架构原生代码**，后续会用反汇编器去啃完全错误的对象。案例里 `binwalk` 提取出的 128 字节被判为 `data` 就是这一类现象的缩影——**只看了头，没看结构**。

**核查**：**遇到这个头就往下多读几个字段再定性**：

```bash
file /evidence/x.class                    # 首选：它会区分 Java class / Mach-O fat
xxd -l 16 /evidence/x.bin
# 偏移4 = 00 00 00 34  → Java class，版本 52（Java 8）
# 偏移4 = 大端架构计数 → Mach-O fat
```

**"头相同、结构不同"是格式识别的常态**——**遇到歧义魔数，正确动作是往下读，不是二选一。**

<a id="section-20"></a>

### 4.2 完整性与篡改检验

<a id="section-21"></a>

#### 陷阱 6：头尾成对齐全就判"文件完整"

**现象**：PNG 的头 `89504E470D0A1A0A` 与尾 `IEND` 都在，JPEG 的 `FFD8FF` 与 `FFD9` 都齐，分析员写"文件结构完整，内容未被改动"。

**原因**：头尾标记只证明"开头像一个 PNG、结尾像一个 PNG 的结尾"，不证明中间的任何一块数据是对的（2.3 的原话："只认头不认尾，等于只验证了一半"——而**只认头尾本身也只是比一半多一点点**）。

PNG 内部由多个 chunk 组成，每个 chunk 都有自己的长度与 CRC32；**改掉像素数据后，头尾依然齐全**。JPEG 的内部熵编码段同理。

**"标记齐全"与"内容完整"之间隔着一整套内部校验**。

**影响**：**把篡改过的文件判为完整**，而这份文件是证据的核心物证。案例中"`Changed` 晚于 `Modified`"这类元数据异常与文件内容完整性是两件事——内容层结论必须由内容层验证支撑，不能靠标记齐全推断。

**核查**：**功能验证是必需步骤，不是可选项**（2.3 的清单）：

```bash
pngcheck -v /evidence/x.png        # 走完全部 chunk CRC
unzip -t  /evidence/x.docx         # ZIP 全项 CRC（-t 不解压）
pdfinfo    /evidence/x.pdf         # 能否解析出页数
identify   /evidence/x.jpg         # 能否解码出尺寸
ffprobe -v error -show_format /evidence/x.mp4
```

**三种结果必须分开表述**：

| 验证结果 | 报告写法 |
|---|---|
| 头尾齐全 + 内部 CRC 全部通过 | "结构完整，内部校验全部通过" |
| 头尾齐全 + 内部 CRC 失败 | "**存在但内容损坏**（非篡改推断，损坏位置为 `<chunk/条目>`）" |
| 缺尾标记 | "**文件被截断**，缺失尾标记，最后可读单位为 `<偏移>`" |

**"存在但不可用"与"不存在"是完全不同的结论**——一份被截断的报告和一份从未存在的报告，在案件里的意义相差一个量级。

<a id="section-22"></a>

#### 陷阱 7：用 `unzip -t` 或 `zip -T` 通过来证明"文件未被改过"

**现象**：`unzip -t 对账单.xlsx` 报 "No errors detected"，报告据此写"该文档未被篡改"。

**原因**：ZIP 格式本身允许在归档前后附加任意数据而仍然能正常解压（2.4 的最后一句："能正常打开"绝不等于"未被改过"）。

`unzip -t` 只逐项校验归档内各条目的 CRC，**它不检查 EOCD 之前是否有追加数据**；`zip -T` 同理。

**追加型伪装恰恰能通过这两个命令**——这正是 2.4 把它列为取证要点的原因：隐藏在合法文档尾部的第二份文档、宏载荷，都属于这类。

**影响**：**尾部藏着的第二份文档会被漏掉**。这类手法的特点就是"用一份完全合法的外层文档掩护内层载荷"，而 CRC 校验对它是完全通过的。报告里"未被篡改"这句话一旦写错，委托方会据此排除伪装可能。

**核查**：必须单独做 EOCD 自洽性检查，这是 `unzip -t` 做不到的（3.2 的 `zipcheck.py`）：

```bash
# 从尾部反查 EOCD（固定 22 字节，注释最长 65535 字节）
python3 - <<'PY'
import struct
d = open('/evidence/对账单.xlsx','rb').read()
i = d.rfind(b'PK\x05\x06')
if i < 0:
    print('[-] 未找到 EOCD：文件被截断或不是 ZIP'); raise SystemExit
cdoff, cdsize = struct.unpack_from('<II', d, i+8)
clen = struct.unpack_from('<H', d, i+20)[0]
expect = cdoff + cdsize + 22 + clen
print(f'EOCD@{i}  期望 {expect}  实际 {len(d)}  差 {len(d)-expect}')
PY
# 差 > 0 → 尾部有追加数据（追加/伪装载荷）
# 差 < 0 → 结构自相矛盾（中央目录被改写）
```

**注意判读方向**：`unzip -t` 报 CRC 通过而 EOCD 检查报"差 > 0"，**这两个结果不矛盾**——前者是归档内完整，后者是归档外有东西。**两个都要做，缺一不可。**

顺带一条：把 `unzip -t` 或 `zip -T` 通过当成"内容没被换过"更靠不住。CRC 是内容指纹，不是来源证明——ZIP 可以被完整重打包：把全部条目解压、改掉其中一个、重新生成一个合法归档，新归档 CRC 全部通过、EOCD 全部自洽、扩展名可以完全不改。

案例里的 `对账单.xlsx` 就是这种形态（`dcterms:created` 与文件系统 `Created` 差 2 分 44 秒），而**任何 ZIP 级校验都发现不了这件事**。

所以校验要分两层写，结构层说"完整"，溯源层只能说"不认定"：

```bash
# ① 文档内部属性时间（可被生成方任意填写，仅作线索）
unzip -p /evidence/对账单.xlsx docProps/core.xml

# ② 与文件系统元数据交叉（案例中这一步给出两项独立发现）
istat -o 2048 /work/DigiForensics.dd 88214-128-3
# Created 13:48:22 / Modified 14:07:19 / Changed 14:07:22
```

> "**结构层**：EOCD 中央目录偏移与大小之和加 22 字节等于实际大小（48216 = 48216），全项 CRC 通过，**结构完整且无尾部附加数据**。
> **内容溯源层**：`docProps/core.xml` 的 `dc:creator` 为 `<值>`，**该字段可由生成方任意填写，不可独立采信**；文件系统 `Created` 早于文档内部创建时间 2 分 44 秒，**表明条目先创建、内容后写入**。因此本报告不认定文档未被重新生成，仅认定其结构完整且元数据存在两处改动。"

<a id="section-23"></a>

### 4.3 容器与内容提取

<a id="section-24"></a>

#### 陷阱 8：用 `strings` 直接在 OOXML 文档里搜内容

**现象**：在 `报告.docx` 上跑 `strings | grep -i 某某`，0 命中，写"文档中未出现该内容"。

**原因**：OOXML 的 XML 是压缩存储在 ZIP 条目里的（2.4 的局限原文："XML 压缩存储，`strings` 未必命中"）。

`strings` 扫的是原始字节流，而正文在 deflate 之后是不可读的。`strings` 0 命中在这里是格式的正常表现，不是内容不存在的证据——而 0 命中的外观恰恰最像"确实没有"。

**影响**：**这是一个范围不足的否定性结论**，而它会直接支撑"该文档不含此内容"的判断。**这类结论在争议程序里最需要证据支撑**。

**核查**：**先取出条目再搜，路径要写对**：

```bash
# 有效路径：先解压出条目，再搜
unzip -p /evidence/报告.docx word/document.xml | grep -i 某某
unzip -p /evidence/报告.docx word/comments.xml          # 批注
unzip -p /evidence/报告.docx word/_rels/document.xml.rels | grep -oE 'Target="[^"]*"' | grep -iE 'http|file'
unzip -l /evidence/报告.docx | grep -iE 'vbaProject|\.bin'   # 宏检测

# 无效路径：在 .doc（OLE2）上这样做——OLE2 不是 ZIP，解不出条目
```

**报告写法**："在 `<列出实际搜索的条目路径清单>` 中检索关键词 `<关键词>`，未命中。该检索覆盖范围为上述条目，不含 `<未覆盖的条目 / 二进制载荷 / 图片内文字>`。"

<a id="section-25"></a>

#### 陷阱 9：把 ZIP 条目时间戳当作文档创作时间

**现象**：`unzip -l` 显示条目时间 `2024-06-02 13:51:07`，报告写"该文档创作于 2024-06-02 13:51"。

**原因**：**ZIP 条目时间是"数据被写入归档时的本地时间"**（2.4 已注明"可被改，只能作旁证"）。

它既不是文档创建时间，也不是文档修改时间——它是**打包动作发生的时间**，而且**重打包时全部条目时间会被统一重写为打包时刻**。

案例中条目时间 13:51:07–13:51:10 与 `dcterms:created` 13:51:06 自洽，这个自洽恰恰说明它们来自同一次生成动作，而不是相互独立印证。

**影响**：**把一个高度可伪造的字段当作时间证据**。而时间证据一旦被采信，它会进入超时间线与其他来源合并——**一旦错误，就会污染整条时间线**。

**核查**：**区分三类时间，各自的证据地位写明**：

| 时间类型 | 载体 | 证据地位 |
|---|---|---|
| 文档内部创建/修改时间 | `docProps/core.xml` 的 `dcterms:*` | 可由生成方填写，**线索级** |
| 归档写入时间 | `unzip -l` 条目时间 | 可被重打包统一改写，**旁证级** |
| 文件系统时间 | `$MFT` 四时间戳 | 系统维护，但可被工具改写，**需交叉** |

```bash
# 三者并列输出，差异本身才是信息
unzip -p /evidence/对账单.xlsx docProps/core.xml | sed -e 's/<[^>]*>/ /g' -e 's/  */ /g'
unzip -l /evidence/对账单.xlsx | head -12
istat -o 2048 /work/DigiForensics.dd 88214-128-3
```

**案例的结论写法示范**："`dcterms:created` 为 13:51:06，ZIP 条目时间为 13:51:07–13:51:10，**两者相差 1–4 秒且同源（同一生成动作）**，不构成独立印证。文件系统 `Created` 13:48:22 早于二者 2 分 44 秒，**该项为独立时间源**。"

<a id="section-26"></a>

#### 陷阱 10：★ 在证据目录里直接跑 `binwalk -e`

**现象**：在 `/evidence/` 下执行 `binwalk -e prog.exe`，工具在当前目录生成大量提取文件，覆盖了此前手工提取的同名文件。

**原因**：`binwalk -e` 是写盘操作，而它的默认行为是在当前目录写（3.4 的警示行）。

`/evidence/` 是证据工作区，里面已经有按偏移精确提取的、比自动提取更可靠的产物——自动提取按签名猜测边界，会产出大量名为 `image.png`、`archive.zip` 的重复文件。

而"文件已存在"这个常态让覆盖几乎不会被察觉。

**影响**：**已归档的提取件被自动提取的碎片覆盖**。那些碎片是没有经过 `file` 二次确认、偏移不精确、可能相互重名的产物——它们一旦覆盖了经过验证的原件，此前记录下来的偏移、哈希、功能验证结果**全部失去对应对象**。

而且**混在一起的同名文件让"哪个是哪个"变得无法追溯**。

**核查**：**自动提取必须隔离在专用目录，且先后顺序固定**：

```bash
# ① 精确提取优先，落到证据目录（可控、可复现）
dd if=/work/DigiForensics.dd bs=1 skip=$((0x64)) count=4096 of=/tmp/embedded.png status=none
file /tmp/embedded.png && sha256sum /tmp/embedded.png

# ② 自动提取隔离到专用目录，绝不落在 /evidence/ 里
mkdir -p /tmp/binwalk-out && cd /tmp/binwalk-out && binwalk -e /evidence/prog.exe

# ③ 自动提取物一律视为"待验证碎片"，验证后才进证据目录
for f in /tmp/binwalk-out/*; do file "$f"; done
```

`binwalk` 的定位是"发现"而不是"判定"——它的输出只说明"某偏移处有个像 PNG 的东西"，**那可能只是巧合的字节序列**（3.4 的提醒）。案例中偏移 2500 处的 "Executable Intel 80386" 提取后是 `<style` 开头的 XML 片段，**是假阳性**。

**报告写法**：对每一次 `binwalk` 告警，记录"已提取 + 已验证 + 判定为假阳性"或"已提取 + 验证为真实载荷"——**只记告警不记验证，是把未验证的观察当成发现。**

<a id="section-27"></a>

### 4.4 结论表述

<a id="section-28"></a>

#### 陷阱 11：用 carving 产物的扩展名或数量下结论

**现象**：carving 产出 22000 多个文件，工具按签名分配了 `.jpg` / `.png` / `.docx` 扩展名，分析员写"该分区存在 18432 张 JPEG 图片"。

**原因**：carving 工具分配扩展名的动作本身就基于签名——它"猜"是 JPEG 才给 `.jpg`，**这个扩展名不构成独立证据**（3.4 的类型清单流程正是"建立清单 → 算哈希 → 找重复"，而不是"统计扩展名"）。

而 carving 产物的总量远超系统实际文件数，3.4 已经明确："**说明绝大多数是碎片或重复**"。

`file -r --mime-type` 的统计（18432 image/jpeg）是签名命中的数量，不是有效图片的数量。

**影响**：**把碎片统计当成资产清点**。18432 这个数字一旦写进报告，它就是一个看起来很客观、实则毫无意义的量。而真正的结论——"其中多少是完整可解码的有效图片"——完全没有回答。

**不清洗就直接提交，是取证流程的缺陷**（详见 [10](../filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md)）。

**核查**：**建立可核对的清单，清洗后再统计**：

```bash
cd /evidence/carved
# ① 哈希去重——重复是碎片的主要形态
sha256sum * > /evidence/carved-hashes.txt
sort -k1,1 /evidence/carved-hashes.txt | uniq -w64 -D > /evidence/duplicates.txt
wc -l /evidence/duplicates.txt

# ② 功能验证筛掉"头尾齐全但内容损坏"的碎片
mkdir -p /evidence/carved-valid
for f in *.jpg; do identify "$f" >/dev/null 2>&1 && mv "$f" /evidence/carved-valid/; done
ls /evidence/carved-valid | wc -l

# ③ 与文件系统已知文件集做交叉
```

**报告写法**："carving 共产出 `<N>` 个签名匹配产物，经 SHA-256 去重后剩 `<M>` 个唯一哈希，经功能验证（`identify` / `pdfinfo` / `unzip -t`）通过者 `<K>` 个。**扩展名由工具按签名分配，不作为类型判定依据**；类型结论以 `file` 与功能验证为准。"

<a id="section-29"></a>

#### 陷阱 12：把"未发现内嵌载荷"写成绝对结论

**现象**：`binwalk` 扫过某文件，只报了几条已验证为假阳性的告警，报告写"该文件不含任何内嵌可执行内容"。

**原因**：`binwalk` 是签名扫描器，扫的是"已知形状"。它检测不到经过变形、加密、压缩二次包装的自定义格式，也检测不到刻意规避签名的载荷。

3.4 的原则是"`binwalk` 的定位是发现而非判定"——**反过来说，没发现也不构成否定**。

而 polyglot 文件这个补充现象正好说明这一点：一个既是合法图片又是可执行脚本的文件，`file` 报"合法图片"、`identify` 也能解码，只有主动扫描内嵌结构（`binwalk`、搜 shebang、搜 `<?php`）才可能发现。

**影响**：**否定性结论的范围超出了实际检查范围**，而这类结论往往被委托方直接引用为"已排除伪装可能"。

**核查**：阴性发现必须写成"在 X 范围 Y 检查内未发现 Z"并列出未覆盖范围：

> "在 `对账单.xlsx`（48216 字节）范围内，以 `binwalk` 签名扫描（覆盖 PNG / PE / ZIP / 压缩流等已知签名）、`unzip -l` 容器条目列举、全文关键字检索三种方法检查，**未发现内嵌可执行文件或第二份文档**。`binwalk` 于偏移 2500 处的告警经提取验证为 XML 片段（`<style` 开头），**判定为假阳性**。
> **本次未覆盖的范围**：图片等二进制条目内嵌内容（需 OCR）、加密条目（若有）、非已知签名的自定义格式、OOXML 各 XML 条目中的脚本片段。
> **本结论不表明该文件不含任何形式的隐藏内容。**"

"签名扫描未命中"与"不存在"之间隔着整个未知格式空间——这个距离必须在报告里写出来，否则它会被无声地填平。
<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 对账单 xlsx 的真伪与篡改认定：靠容器结构不靠扩展名

**场景**

查获一个可疑的"财务对账单"压缩包，同时在目标主机上发现一个命名为 `对账单.xlsx` 的文件。委托要求确认该文件**是否为真正的 Excel 文档**，以及**是否被篡改过**。镜像 `DigiForensics.dd`（raw），工作站 NTFS。

委托方的问题是"这文件能不能当证据用"。选择这一路径的依据是 `.xlsx` 扩展名**不提供任何保证**——改扩展名只要一秒，而判定真伪需要看容器内部。

**处置过程**

第 1–3 步 · 提取、判定类型、进入容器内部（决定性一步）：

```bash
fls -o 2048 -r -p /work/DigiForensics.dd | grep -i '对账单'
# r/r  88214-128-3:  48216  2024-06-02 14:07:19  2024-06-02 14:07:22  对账单.xlsx
icat -o 2048 /work/DigiForensics.dd 88214-128-3 > /evidence/对账单.xlsx
sha256sum /evidence/对账单.xlsx && stat -c '%s' /evidence/对账单.xlsx   # 48216 字节
file /evidence/对账单.xlsx            # Microsoft Excel 2007+  ← 是 ZIP/OOXML，但未区分真假
file -b --mime-type /evidence/对账单.xlsx   # application/zip  ← 非 OOXML 专用类型
unzip -l /evidence/对账单.xlsx
#   Length      Date    Time    Name
#     4286  2024-06-02 13:51:07   [Content_Types].xml          ← 关键 1
#      612  2024-06-02 13:51:07   _rels/.rels                  ← 关键 2
#     3104  2024-06-02 13:51:08   xl/workbook.xml              ← 关键 3
#     9182  2024-06-02 13:51:09   xl/worksheets/sheet1.xml
#     2204  2024-06-02 13:51:09   xl/sharedStrings.xml
#     6714  2024-06-02 13:51:10   xl/styles.xml
#     1288  2024-06-02 13:51:10   docProps/core.xml     (共 7 files)
```

**第一个疑点**：`--mime-type` 给出通用 `application/zip` 而非 OOXML 专用类型。

**这不是工具失灵**——`file` 的魔数库无法区分"真 Excel"和"任意 ZIP"，因为二者头部完全相同。

而三个关键项全部存在：真实 xlsx 必然包含 `[Content_Types].xml`、`_rels/.rels`、`xl/workbook.xml`，**该文件在容器层面确实是有效的 Excel 文档**。

第 4–5 步 · 提取内容并与文件系统元数据交叉比对：

```bash
unzip -p /evidence/对账单.xlsx docProps/core.xml | sed -e 's/<[^>]*>/ /g' -e 's/  */ /g'
#  dc:creator 财务部-王某某   dcterms:created 2024-06-02T13:51:06Z
unzip -p /evidence/对账单.xlsx xl/sharedStrings.xml | sed -e 's/<[^>]*>/\
/g' | grep -v '^$' | head -20
# 2024年第二季度供应商对账明细 / 华东精密机械有限公司 ...
istat -o 2048 /work/DigiForensics.dd 88214-128-3
# Created 13:48:22 / Modified 14:07:19 / Accessed 14:33:55 / Changed 14:07:22
```

| 时间源 | 时间 | 说明 |
|---|---|---|
| `core.xml` dcterms:created | **13:51:06** | 文档内部创建时间（ZIP 条目时间 13:51:07–10 与之自洽） |
| 文件系统 `Created` | **13:48:22** | 比文档创建**早 2 分 44 秒** |
| 文件系统 `Modified` | **14:07:19** | 比文档修改（13:51:10）**晚 16 分 9 秒** |
| 文件系统 `Changed` | **14:07:22** | **晚于 Modified 3 秒** |

**两个独立发现**：①`Changed` 晚于 `Modified` 3 秒——这是元数据被改动的特征（重命名、权限变更、附加数据流），内容本身未变；②`Created`（13:48:22）早于文档内部创建时间（13:51:06）2 分 44 秒——说明该文件条目先被创建（可能是空文件或占位），3 分钟后其内容才被写入真正的对账单，这是"先建空文件、后填充内容"的痕迹。

**两项均只涉及元数据。**

**第 6 步 · 验证完整性与排除伪装**：

```bash
unzip -t /evidence/对账单.xlsx
# No errors detected in compressed data of 对账单.xlsx.   ← 全部 CRC 通过 ✓
python3 /evidence/zipcheck.py /evidence/对账单.xlsx   # [OK] 48216 = 48216，无追加数据
binwalk /evidence/对账单.xlsx
# 2500   0x9c4   128   Executable Intel 80386 ...
dd if=/evidence/对账单.xlsx bs=1 skip=2500 count=128 of=/tmp/emb.bin status=none
file /tmp/emb.bin && xxd -l 16 /tmp/emb.bin
# /tmp/emb.bin: data   ← 非可执行文件；00000000: 3c73 7479 6c65 <style  ← XML 片段，假阳性
```

**结论**

能证明：①**文件是真实的 Excel 文档**，依据是三项独立的容器结构特征加两项功能验证（`unzip -t` 全部 CRC 通过、EOCD 自洽性检查通过），而非"扩展名是 .xlsx"或"`file` 报 Microsoft Excel 2007+"；②扩展名未被篡改，文件未被追加数据——EOCD 的中央目录偏移与大小之和加 22 字节恰好等于文件实际大小，排除尾部附加数据与自解压前缀，且 `sharedStrings.xml` 的内容语义与"对账单"一致，这是一项独立的内容一致性验证；③元数据层面存在两处改动，**均不改变文件内容本身**；④无内嵌恶意载荷——`binwalk` 匹配经提取验证**为 XML 内容片段的假阳性**，报告中记录了排除过程。

四条里，第四条最容易被略过，也最该写。

**不能证明**：文档属性的作者字段 `dc:creator 财务部-王某某` **可由生成方任意填写，不可独立采信**；操作人认定应结合 MFT 记录与其他证据。

**误判对照**

最像的误判是把 `file` 报的 `Microsoft Excel 2007+` 当成真伪判据，或反过来，把 `--mime-type` 给出的 `application/zip` 当成"这是伪装的"。

判据要落到容器结构上：两者都不是判据，因为 `[Content_Types].xml`、`_rels/.rels`、`xl/workbook.xml` 这三项才是 OOXML 的定义性组成部分——真 xlsx 必然有，任意 ZIP 必然没有；同时它们的中央目录与 EOCD 必须自洽（CRC 全通过 + 偏移量算术闭合）。

正确判据是**三项关键部件存在 + 两项功能验证通过**这五个条件的组合。按错误判据走的代价有两种方向：信 `file` 的输出，则任何改过扩展名的 ZIP 都能冒充证据；信 `--mime-type` 的输出，则会把一个完全正常的 xlsx 判成伪装文件——后者更隐蔽，因为它需要有人刻意推翻一个正确结论，而推翻正确结论在复核中同样要承担后果。

<a id="section-32"></a>

### 5.2 `binwalk` 报出 PE 头：提取验证是唯一出路

**场景**

同一文件中，`binwalk` 在偏移 `0x9c4`（2500）处报出 `Executable Intel 80386`。委托方安全部门已看到这份内部通报，要求立即说明是否为木马。

将此情形单列的原因是 `binwalk` 报出可执行文件头时，最响应的动作往往是最错的——直接写"含木马"的代价远大于多花两分钟提取验证。

**处置过程**

1. 不下结论，先把命中区域切出来看它到底是什么：

```bash
dd if=/evidence/对账单.xlsx bs=1 skip=2500 count=128 of=/tmp/emb.bin status=none
file /tmp/emb.bin
# /tmp/emb.bin: data                          ← 不是可执行文件
xxd -l 16 /tmp/emb.bin
# 00000000: 3c73 7479 6c65 3e73 7479 6c3c  <style><styl<
```

2. 命中的字节是 `<style><styl` —— 这是 ZIP 内的 `xl/styles.xml`（压缩流）恰好在字节层面形成了 `MZ` 起始特征被扫描器匹配，而 `file` 判定为 `data` 正是反证。

压缩流没有对齐保证，这类误匹配几乎必然出现。

3. 把排除过程写进报告，而**不是只写结论**：

```text
binwalk 于偏移 0x9c4 报出 Intel 80386 头，经 dd 提取该区域 128 字节后：
  file 判定为 data（非 PE），起始字节 3c 73 74 79 6c 65 = "<style"
判定为 ZIP 压缩流偶然形成的字节序列，属假阳性。
排除方法与提取件哈希均记录在附件。
```

**结论**

能证明：该文件**不含内嵌的可执行载荷**，命中的 `0x9c4` 偏移对应的是 `xl/styles.xml` 的压缩数据流，其字节序列被扫描器误匹配为 PE 头。排除过程可复现——任何人按记录的命令重跑都会得到同样结果。

**不能证明**：不能证明该文档**打开时**不会触发外部行为（例如通过远程模板或公式引用加载外部内容），这需要文档内容层面的专项检查，本次未做。

**误判对照**

最像的误判是把 `binwalk` 的告警直接写成"文件内含木马可执行文件"。

判据要区分**"字节匹配"与"结构成立"**：`binwalk` 报的是魔数匹配——任意位置出现 `MZ` 或 `4D 5A` 后跟上看起来像 PE 头的字节都会命中，而 ZIP 压缩流中偶然出现这样的字节序列的概率并不低；真正构成可执行文件的是**完整的 DOS 头 + PE 头 + 节表**这一整套结构，`file` 判定为 `data` 已经说明它不成立。

正确判据是**提取该区域后用 `file` 与十六进制双重确认**，而不是看告警行。按错误判据走的代价是报告出现一条危言耸听的木马结论，安全部门据此隔离全网、通知相关方处置，而事后证明是假阳性——**误报的处置成本往往是真报的数倍**，因为召回成本由报告的措辞强度决定。

<a id="section-33"></a>

### 5.3 反例：把 `Changed` 晚于 `Modified` 当作内容被篡改

**场景**

某次分析中，分析员看到 `Changed`（14:07:22）比 `Modified`（14:07:19）晚 3 秒，直接写入报告"该文档内容在 14:07 被修改过"。委托方据此怀疑事后编辑。

这条列为反例，是因为**这条推断在方向上恰好与事实相反**——它把一个纯粹的元数据变更说成了内容变更。

**处置过程**

对照点在于四个时间字段各自由什么触发：

```bash
istat -o 2048 /work/DigiForensics.dd 88214-128-3
# Created  13:48:22   ← 条目创建
# Modified 14:07:19   ← 数据流内容最后写入
# Changed  14:07:22   ← 元数据最后改动（不含数据流内容）
# Accessed 14:33:55   ← 最后读取
```

关键在于 **`Changed` 的语义不包括数据流内容**——重命名、改权限、添加 ADS、调整链接数都会更新它，而内容写入更新的是 `Modified`。

**结论**

阴性发现：本案 `Changed` 晚于 `Modified` 3 秒，该 3 秒对应元数据变更（最可能是重命名或权限调整），不构成内容被修改的证据。

内容是否被修改要看 `Modified` 与文档内部时间的一致性——本案的 `Modified`（14:07:19）晚于文档内部 `dcterms:created`（13:51:06）16 分钟，属正常的编辑后另存，与篡改无关。

**误判对照**

最像的误判是"`Changed` 比 `Modified` 晚 = 内容被改过"。

判据在字段语义上：NTFS 的 `Changed`（`$STANDARD_INFORMATION` 的 MFT 变更时间）更新条件是元数据变更，`Modified` 更新条件是数据流写入，两者互不覆盖——`Changed` 晚于 `Modified` 是元数据先动、内容没动的常见表现，若真是内容篡改，典型形态反而是 `Modified` 明显晚于文档内部时间。

正确判据是**先判断这个差值符合哪种变更模式**，而不是看到差值就选最严重的解释。按错误判据走的代价是把"改了个权限"上升为"篡改证据"，委托方据此做出一系列处置；而当真相是"只是重命名"时，这份报告会因为一个 3 秒的差值而整体失去可信度。

---

---
<a id="section-34"></a>

## 六、扩展阅读方向

按"解决什么问题"分成五组。

<a id="section-35"></a>

### 前置基础

- [NTFS 结构与 MFT 解析](filesystem-ntfs-ntfs-master-file-table.md) —— **解决"文件怎么从镜像里完整取出来"**。本篇的输入是提取物，提取时取多少字节、会不会被 slack 截断，那篇讲得比本篇细。
- [NTFS 数据流与隐藏数据](filesystem-ntfs-ntfs-alternate-data-streams.md) —— **解决"格式尾部藏了东西怎么算"**。PNG 的 `IEND` 之后有数据是本篇认定的"结构异常"，那篇给出这类异常的完整提取流程与四层覆盖写法。

<a id="section-36"></a>

### 同层深入

- [文件雕刻与签名恢复](../filesystem-unix/filesystem-unix-file-carving-and-signature-recovery.md) —— **解决"没有文件系统记录怎么办"**。本篇的判定对象是已提取的文件，那篇处理按签名从裸数据里重建文件；清洗与功能验证的判据在那里，本篇只负责类型识别这一步。
- [Steady-State 与 $LogFile 还原](filesystem-ntfs-steady-state-logfile.md) —— **解决"元数据改动和内容改动哪个先发生"**。本篇案例里 `Changed` 晚于 `Modified` 3 秒这个发现，要准确解读需要那篇的判读规则。

<a id="section-37"></a>

### 相邻议题

- [内存中的凭据与密钥](../../memory/memory-artifact/memory-artifact-memory-credentials-and-keys.md) —— **解决"从内存里捞出的东西怎么定类型"**。内存提取物没有文件名也没有目录项，本篇的判据在那边要换成"内存结构 + 签名"双依据。
- [进程与注入检测](../../memory/memory-analyze/memory-analyze-process-and-injection-detection.md) —— **解决"内存里那个 PE 是谁的"**。签名能证明"是什么格式"，证明不了"是哪个模块"，**类型判定与主体归属是两件事**。
- [EFS 文件系统加密取证](../../crypto/crypto-volume/crypto-volume-efs.md) —— **解决"文件头正常但内容读不了"**。加密流在属性层有标志位，不在文件层；两者混谈会得出"文件损坏"的错误结论。

<a id="section-38"></a>

### 工具与规范

- 常用签名的十六进制速查见[命令速查](#section-40)——建议在真正上手前先把 PE / ELF / PNG / ZIP 四组字节背下来，剩下的都能用 `file` 补。
- `binwalk` 的告警必须**提取验证后才能写进报告**。本篇案例里偏移 2500 的 "Intel 80386" 告警经提取是 `<style` 开头的 XML 片段，**假阳性必须写明排除过程**，否则读者会以为有载荷。
- 提取物固定与哈希留痕见[取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md)——**先 `sha256sum` 再 `file`**，顺序反了就没法证明分析对象是证据。
- 报告里"阴性发现"的写法模板见[案例示例](#section-30)第 6 步：列出方法、范围、未覆盖项、**并明写"本结论不表明不存在"**。

<a id="section-39"></a>

### 判据与反例

- **判据一**：类型结论必须**结构 + 功能**双验证。`file` 报 Microsoft Excel 2007+ 只是"是 ZIP"；只有 `unzip -t` 通过且三个关键成员齐备，才敢写"是有效 Excel 文档"。
- **判据二**：完整性判断用 EOCD 算式（中央目录偏移 + 大小 + 22 = 实际大小），**这是可复现的算术，比"打开没报错"强**。
- **反例一**：把 `file` 给的通用 MIME 类型当成工具失灵或当成"不是 Excel"。**`application/zip` 是正确答案**，区分要靠容器成员。
- **反例二**：用 `binwalk` 未命中就写"不含任何内嵌内容"。签名扫描的阴性结果与"不存在"之间隔着整个未知格式空间，必须限定范围表述。
- **反例三**：拿 carving 产物的扩展名统计当资产清点。**扩展名由工具按签名分配，不构成独立证据**；正确口径是"签名命中 N 个，唯一哈希 M 个，功能验证通过 K 个"。
- **反例四**：用 `dc:creator` 认定文件作者。**该字段任意可填**，可作为线索，**不可单独采信为身份结论**。
- **反例五**：把"CRC 全部通过"直接写成"文件未被篡改"。**校验和只保证与写入时一致**，不保证写入时即为原始状态；篡改后重新打包的 ZIP 一样 CRC 全通过。
<a id="section-40"></a>

## 七、命令速查

```bash
sudo apt install file xxd binwalk unzip zip imagemagick poppler-utils pngcheck

# ===== 判类型 =====
xxd -l 64 /evidence/mystery.bin              # 十六进制+ASCII 双栏（最常用）
xxd -l 64 -p /evidence/mystery.bin           # 纯十六进制
xxd -s $((0x3C)) -l 4 /evidence/prog.exe     # 先读 PE 的 e_lfanew
xxd -s $((0x80)) -l 64 /evidence/prog.exe    # 再跳到 PE 头验证 50 45 00 00
head -c 100 /evidence/mystery.bin | strings  # 头部的可读内容
file /evidence/mystery.bin                   # 完整类型（含尺寸/编码）
file -b /evidence/mystery.bin                # 仅简要类型
file --mime-type /evidence/mystery.bin       # MIME（-i 会连 charset 一起给）
file -r --mime-type /evidence/carved/ | cut -d: -f2- | sort | uniq -c | sort -rn
python3 /evidence/disguise.py /evidence/suspect   # ★ 批量伪装检测（3.3）

# ===== 验完整性 =====
head -c 8 /evidence/x.png | xxd -p         # 头 89504e470d0a1a0a
tail -c 12 /evidence/x.png | xxd -p        # 尾 49454e44ae426082 (IEND)
pngcheck -v /evidence/x.png                 # PNG 全 chunk CRC
unzip -t /evidence/x.docx                  # ZIP 全项 CRC（★ 不查尾部附加数据）
python3 /evidence/zipcheck.py /evidence/x.docx   # ★ EOCD 自洽性（zip -T 做不到）
pdfinfo /evidence/x.pdf                     # 能否解析页数
identify /evidence/x.jpg                    # 能否解码尺寸（ImageMagick）
ffprobe -v error -show_format /evidence/x.mp4

# ===== 内嵌结构（3.4）=====
binwalk /evidence/prog.exe                  # 只扫描不提取
mkdir -p /evidence/binwalk-out && cd /evidence/binwalk-out && binwalk -e /evidence/prog.exe
dd if=/work/DigiForensics.dd bs=1 skip=$((0x64)) count=4096 of=/tmp/emb.png status=none
file /tmp/emb.png                           # ★ 必须二次确认，binwalk 会假阳性

# ===== ZIP/OOXML 专项（2.4）=====
unzip -l /evidence/x.docx   # 真 docx 必有 [Content_Types].xml + word/document.xml
                             # 真 xlsx 必有 [Content_Types].xml + xl/workbook.xml
unzip -p /evidence/x.docx docProps/core.xml | sed -e 's/<[^>]*>/ /g'      # 作者/创建时间
unzip -p /evidence/x.docx word/_rels/document.xml.rels | grep -oE 'Target="[^"]*"' | grep -iE 'http|file'
unzip -l /evidence/x.docx | grep -iE 'vbaProject|\.bin'   # 宏检测（.docx 伪装 .docm）

# ===== 可执行格式（2.5）=====
file /evidence/prog.exe      # PE32+ executable ... / ELF 64-bit LSB pie executable ...
# PE: 偏移 0=4D5A(MZ)，0x3C 指向处必须是 50 45 00 00 (PE\0\0)
# ELF: 7F454C46，第5字节 EI_CLASS(01=32/02=64)，第6字节 EI_DATA(01=LE/02=BE)
# Mach-O: CE FA ED FE=32小 / FE ED FA CE=32大 / CF FA ED FE=64小 / FE ED FA CF=64大
#         CA FE BA BE=fat 或 Java .class
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — 文件系统分析 — 文件头与文件签名」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《文件头与文件签名》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics.vc` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
