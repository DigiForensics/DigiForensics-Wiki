---
title: "LNK 快捷方式与 Jump List 跳转列表"
slug: "computer-execution-lnk-jumplist"
canonical: "https://www.digiforensics.cn/wiki/computer-execution-lnk-jumplist"
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

# LNK 快捷方式与 Jump List 跳转列表

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-execution-lnk-jumplist)

<a id="section-1"></a>

## 一、概述

`.lnk` 是 Windows 快捷方式文件，取证价值却远高于它的文件体积。一个通常只有 1–2 KB 的二进制文件，往往同时记录了目标文件的三个时间戳、目标所在卷的序列号、目标绝对路径、源机器的 NetBIOS 名，甚至源机器网卡的 MAC 地址。

这意味着一个反直觉的事实：当目标文件本身已被删除、卷已被重新格式化、U盘已经拔走之后，快捷方式本身还独立存活，并且它携带的是「快捷方式被创建那一刻」的快照。**它不只是导航，它是一份自包含的时间与来源记录。**

Windows 还会在用户完全无感知的情况下批量生成 LNK：打开文档时在 `%APPDATA%\Microsoft\Windows\Recent\` 写入一个 `.lnk`；任务栏右击菜单在 `AutomaticDestinations\` 维护 Jump List；应用通过 `ICustomDestinationList` 写入 `CustomDestinations\`，其中甚至包含浏览器搜索词、VS Code 的最近工程等。

因此在数据泄露、钓鱼溯源、横向移动这几类案件里，LNK 与 Jump List 是少数能同时回答「谁打开过哪个文件」和「这个文件是在哪台机器上生成、插过哪个 U 盘」的工件。这里讲的是 LNK 与 Jump List 两种工件。用户行为类注册表键见[用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md)，浏览器数据库见[浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md)。

它处于**分析**环节的「归属分析」路径上，位置比执行类工件更靠后——它回答的不是「执行了什么」，而是「谁做的、从哪来的」：

- **上游依赖** 用户身份确认。LNK 与 Jump List 都在用户配置文件下，`AutomaticDestinations` 属于当前用户，**归属错了整套结论就错了**，账户与 SID 判定见[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)。
- **它自己** 要分清三类落点。`Recent\*.lnk`（单文件快捷方式，携带卷序列号与 MachineID，**保留较久**）、`Recent\AutomaticDestinations\`（OLE 复合文档，每个应用一个）、`Recent\CustomDestinations\`（**LNK 序列，格式自定义**）。**两类都要提取**——Jump List 里的 LNK 会被条目上限淘汰，Recent 目录的单文件 LNK 保留更久，**只查一类会漏掉另一半记录**。
- **下游支撑** 两处。`DriveSerialNumber` 是与可疑介质匹配的钥匙，**横向移动溯源靠它**；MFU 排序反映用户对文件的实际使用频次，**比单纯的访问时间更有指向性**。
- **它与执行类工件互补**：Prefetch 说「程序启动过」，LNK 说「用户打开了哪个文档」——**两者缺一，行为链条就不完整。**

`.lnk` 的结构按区段划分：

| 区段 | 关键字段 | 取证用途 |
|---|---|---|
| 固定头 | HeaderSize、LinkFlags、FileAttributes、**三个目标时间戳**、文件大小、图标索引 | **时间戳与结构存在性开关** |
| `LinkInfo` | `LinkInfoSize`、`LinkInfoHeaderSize`、`LinkInfoFlags` | 见下 |
| └ `VolumeID` | `VolumeIDSize`、`DriveType`、**`DriveSerialNumber`**、卷标签偏移 | **核心：标识创建快捷方式时目标所在的卷** |
| └ 路径 | `LocalBasePath`（置位 0）/ `NetName` + `CommonPathSuffix`（置位 1），**两者可同时置位** | 目标绝对路径 |
| `TrackerDataBlock` | MachineID 与 droid GUID | **源机器标识，归属判定的关键** |
| 终端块 | `TerminalBlock`（值小于 `0x00000004`，通常 `0x00000000`） | 界定 `ExtraData` 结束位置 |

Jump List 侧：

| 落点 | 格式 | 关键点 |
|---|---|---|
| `AutomaticDestinations` | **OLE 复合文档（CFB）** | `DestList` 流含 MRU/MFU 排序、固定状态位、访问时间、路径、条目编号；Win7/8 与 Win10 的首字段语义与条目长度不同（后者 130 字节） |
| `CustomDestinations` | **带分类结构的 LNK 序列** | 以 `0xBABFFBAB` 结束，**不是复合文档** |
| 文件名 | 16 位十六进制 AppID，如 `1b4dd67f29cb1962.automaticDestinations-ms` | **文件名就是应用身份**，可能是显式定义，也可能由可执行文件路径经 CRC-64 派生 |

`DriveType` 的标准值区分介质：`0x02` 可移动、`0x03` 固定磁盘、`0x04` 网络。`0x02` 或 `0x04` 出现在内部机的工作站 LNK 中，往往是横向移动的入口。

据此能回答的是：某个用户打开过哪些文档及其访问时间、目标文件创建时的三个时间戳、**目标所在卷的序列号与介质类型**、快捷方式在哪台机器上被创建（MachineID / droid GUID）、以及各应用最近访问过什么（Jump List）。

回答不了的是这些，外加两个必须先纠正的误用：

- 「用 Win7 布局硬解 Win10 文件」会得到看似合理实则错误的结果，判读要点见 4.1 陷阱 2。
- **「AppID 未知」不是文件无效。** 它只是缺少可读名称。报告里写「AppID `1b4dd67f29cb1962`，未匹配到已知应用」是合格表述，写成「Chrome 记录」而不给出依据则不合格。
- **文件当前是否还存在。** LNK 记录的是创建时的快照，**目标文件早已删除是常态**。
- **打开的动作者。** MachineID 标识的是**机器**不是人，**要落到具体用户仍需结合用户目录归属**。
- **打开的意图。** 打开一个文件与修改它完全不同，**LNK 只能证明「打开过」**。
- **MFU 排序的精确语义。** 它反映相对使用频次，**不是精确计数，也不等于访问时间顺序**。

本章依赖的前置知识：NTFS 元数据与 FILETIME 时间基准，**LNK 里的三个时间戳需要正确换算**，见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)；OLE 复合文档（CFB）的结构，`AutomaticDestinations` 用的就是它，解析前需要先理解流与存储的关系；从十六进制手工校验文件头与 droid 字段，**这是解析器出错时的兜底手段**；注册表 hive 的用户归属判定，**它决定了取哪个用户目录下的 Jump List**；以及只读挂载后的镜像检索，Recent 与 AppData 下的目录需要按用户逐个遍历。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 [Shell Link](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) 固定头

所有 `.lnk` 以 76 字节固定头开始，其后是由标志位控制的可选结构。固定头本身就是一块高价值证据：

| 偏移 | 长度 | 字段 | 取证意义 |
| ---: | ---: | --- | --- |
| 0x00 | 4 | `HeaderSize` | 恒为 `0x0000004C`，可作为格式校验 |
| 0x04 | 16 | `LinkCLSID` | 恒为 `00021401-0000-0000-C000-000000000046` |
| 0x14 | 4 | `LinkFlags` | 决定后续哪些结构存在 |
| 0x18 | 4 | `FileAttributes` | 目标属性，可识别目录/压缩/加密/离线等 |
| 0x1C | 8 | `CreationTime` | **目标文件**的创建时间快照 |
| 0x24 | 8 | `AccessTime` | 目标文件的最后访问时间快照 |
| 0x2C | 8 | `WriteTime` | 目标文件的最后修改时间快照 |
| 0x34 | 4 | `FileSize` | 目标文件当时的大小 |
| 0x38 | 4 | `IconIndex` / `ShowCommand` | 隐藏窗口（`0x07`）等异常信号 |
| 0x3C | 2 | `HotKey` | 通常无价值 |
| 0x3E–0x4B | — | `Reserved1/2/3` | 必须为 0，**非零是人为构造的信号** |

三个 FILETIME 是**创建快捷方式那一刻从目标文件读到的 MAC 时间**，不是快捷方式自身的时间。

快捷方式自身的时间要看它的 NTFS `$STANDARD_INFORMATION`。

这两组时间放在同一份报告里时，**差值本身就是结论**：若 `$SI` 的修改时间远晚于头里的目标修改时间，说明文件在这期间被改过。

<a id="section-4"></a>

### 2.2 LinkFlags：结构的存在性开关

`LinkFlags` 是低 27 位的位标志，从最低位（bit A）开始：

| 位 | 值 | 名称 | 存在则紧跟固定头的结构 |
| --- | ---: | --- | --- |
| 0 | `0x00000001` | `HasLinkTargetIDList` | `LinkTargetIDList`（Shell Item 列表） |
| 1 | `0x00000002` | `HasLinkInfo` | `LinkInfo`（卷序列号 + 路径） |
| 2 | `0x00000004` | `HasName` | `NAME_STRING` |
| 3 | `0x00000008` | `HasRelativePath` | `RELATIVE_PATH` |
| 4 | `0x00000010` | `HasWorkingDir` | `WORKING_DIR` |
| 5 | `0x00000020` | `HasArguments` | `COMMAND_LINE_ARGUMENTS` |
| 6 | `0x00000040` | `HasIconLocation` | `ICON_LOCATION` |
| 7 | `0x00000080` | `IsUnicode` | 字符串为 UTF-16LE，否则为系统 ANSI 代码页 |

`StringData` 各串的顺序是强制的：`NAME_STRING → RELATIVE_PATH → WORKING_DIR → COMMAND_LINE_ARGUMENTS → ICON_LOCATION`，每个串前置一个 16 位「字符数」长度前缀。**跳过任何一个被置位的标志，后续所有串都会错位。**

从第 8 位起是行为控制位，取证分析需关注 `ForceNoLinkInfo`（bit 8，`0x0100`，忽略 `LinkInfo`）、`HasDarwinID`（bit 12，MSI 安装程序快捷方式）、`ForceNoLinkTrack`（bit 18，忽略 Tracker 块）与 `EnableTargetMetadata`（bit 19，写入属性存储）。

正常由资源管理器生成的 LNK 不会置 `ForceNoLinkInfo`；恶意 LNK 构建工具常置位它并抹掉卷序列号来隐藏 U 盘痕迹。

<a id="section-5"></a>

### 2.3 LinkInfo：卷序列号与路径

`LinkInfo` 开头是 `LinkInfoSize`（整个结构长度）、`LinkInfoHeaderSize`、`LinkInfoFlags`，以及一个可选的 4 字节 `VolumeIDOffset`/`LocalBasePathOffset`（`LinkInfoHeaderSize` 为 `0x00000024` 时存在）。`LinkInfoFlags` 两位定义如下：

| 位 | 值 | 含义 |
| --- | ---: | --- |
| 0 | `0x00000001` | `VolumeIDAndLocalBasePath` |
| 1 | `0x00000002` | `CommonNetworkRelativeLinkAndLinkInfo` |

置位 0 时内含 `VolumeID`（`VolumeIDSize`、`DriveType`、`DriveSerialNumber`、卷标签偏移）与 `LocalBasePath` / `LocalBasePathUnicode`；置位 1 时改为 `NetName` / `NetNameUnicode`（UNC 前缀）加 `CommonPathSuffix`（UNC 尾部）。两者可同时置位。

`DriveSerialNumber` 是 LNK 取证的核心：它标识创建快捷方式时目标所在的卷。同一个序列号出现在某台主机上成千上万个 LNK 里，说明这些 LNK 全部指向同一个源卷——而那个卷很可能就是已拔走的 U 盘或已送修的移动硬盘。只要拿到可疑介质，读取它的卷序列号即可完成匹配。

`DriveType` 的标准值区分介质：`0x02` 可移动、`0x03` 固定磁盘、`0x04` 网络。`0x02` 或 `0x04` 出现在内部机的工作站 LNK 中，往往是横向移动的入口；完整取值表与判读见 4.1 陷阱 4。

<a id="section-6"></a>

### 2.4 TrackerDataBlock：MachineID 与 droid GUID

`ExtraData` 区是一串 `BlockSize + BlockSignature + 载荷` 的重复结构，最后跟一个 4 字节 `TerminalBlock`（值小于 `0x00000004`，通常为 `0x00000000`）。常见签名：

| 签名 | 块名 | 取证用途 |
| --- | --- | --- |
| `0xA0000001` | `EnvironmentVariableDataBlock` | `%WINDIR%`、`%TEMP%` 等环境变量形式的路径 |
| `0xA0000002` | `ConsoleDataBlock` | 目标为控制台程序时的窗口设置 |
| `0xA0000003` | `TrackerDataBlock` | MachineID、droid GUID，归属证据的核心 |
| `0xA0000004` | `ConsoleFEDataBlock` | 控制台代码页 |
| `0xA0000005` | `SpecialFolderDataBlock` | 特殊文件夹 GUID |
| `0xA0000006` | `DarwinDataBlock` | Windows Installer 的安装描述符 |
| `0xA0000007` | `IconEnvironmentDataBlock` | 图标路径中的环境变量 |
| `0xA0000008` | `ShimDataBlock` | 兼容性 shim 名称 |
| `0xA0000009` | `PropertyStoreDataBlock` | 键值化属性集合，含 SID 等 |
| `0xA000000B` | `KnownFolderDataBlock` | 已知文件夹 GUID |

`TrackerDataBlock` 标准块长 `0x60`、内部 `Length` 为 `0x58`，载荷含 16 字节 `MachineID`（源机器 NetBIOS 名）、`Droid` 与 `DroidBirth` 各 32 字节。droid v1 GUID 的后 6 字节可形成源机器 MAC，但虚拟机 NAT 端口、虚拟网卡、MAC 随机化都会影响归属结论，**不能仅凭 MAC 相同就断言同一台物理机**。

<a id="section-7"></a>

### 2.5 Recent 目录与 Jump List 的关系

`%APPDATA%\Microsoft\Windows\Recent\` 下有两类内容：

| 位置 | 内容 | 特点 |
| --- | --- | --- |
| `Recent\*.lnk` | 单文件快捷方式 | 打开文档时生成，携带卷序列号与 MachineID，保留较久 |
| `Recent\AutomaticDestinations\` | **复合文档**（OLE CFB） | 每个应用一个文件，记录该应用最近访问的文档 |
| `Recent\CustomDestinations\` | **LNK 序列** | 由应用自行写入，格式自定义 |

**两类都要提取**。

Jump List 里的 LNK 会被条目上限淘汰，Recent 目录的单文件 LNK 保留更久，只查后者会漏掉应用级访问记录，反之亦然。

<a id="section-8"></a>

### 2.6 Jump List 文件结构

`AutomaticDestinations` 是 OLE 复合文档，其中的 `DestList` 流含 MRU/MFU 排序、固定状态位、访问时间、路径与条目编号。`CustomDestinations` 不是复合文档，而是带分类结构的 LNK 序列，以 `0xBABFFBAB` 结束。

Windows 7/8 与 Windows 10 的 `DestList` 首字段语义与条目长度不同（后者为 130 字节）。用 Win7 布局硬解 Win10 文件会导致路径字段整体错位，读出乱码却以为文件损坏。

`DestList` 还含 8 字节 `MRU` / `MFU` 排序值——MFU（最常用）排序能反映用户对该文件的实际使用频次，比单纯的访问时间更有指向性。

<a id="section-9"></a>

### 2.7 AppID：文件名就是应用身份

Jump List 文件名是 16 位十六进制的 AppID，如 `1b4dd67f29cb1962.automaticDestinations-ms`。

它可能是应用显式定义，也可能由可执行文件路径经 CRC-64 派生。

知道哪个 AppID 属于哪个应用，是「知道哪个应用记录了哪些文件」的前提。

**AppID 未知不等于文件无效**，只是缺少可读名称；JLECmd 内置常见 AppID 表，也可用 `--appIds` 提供自定义映射。

报告里写「AppID `1b4dd67f29cb1962`，未匹配到已知应用」是合格表述，写成「Chrome 记录」而不给出依据则不合格。

<a id="section-10"></a>

## 三、操作步骤

<a id="section-11"></a>

### 3.1 从镜像中定位并提取

```bash
# 1) 确认分区与系统卷
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd | head -8

# 2) 列出用户配置（fls -p 列序：mode(1) inode(2) name(3) size(4) ...）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|Recent)' | head -20

# 3) 批量提取 .lnk（用 inode 命名避免重名覆盖）
mkdir -p /evidence/users/jsmith/Recent
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/.*\.lnk$' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/users/jsmith/Recent/$(printf '%s.lnk' "${ino%%:*}")"
    done
```

**inode 在第 2 列**（形如 `294-294-1:`），第 3 列才是带空格的完整路径。取错列会把文件名当 inode 传给 `icat`。`CustomDestinations` 的文件没有 `.lnk` 后缀，去掉结尾 `\.lnk$` 过滤即可一并递归提取。

<a id="section-12"></a>

### 3.2 批量解析 LNK

```powershell
# 单文件快速验证
LECmd.exe -f "C:\evidence\Recent\sample.lnk"

# 整目录解析（-r 只保留指向可移动介质的 LNK）
LECmd.exe -d "C:\evidence\users\jsmith\Recent" -r `
  --csv "C:\evidence\out\lnk" --csvf "lnk.csv" `
  --json "C:\evidence\out\lnk_json" --pretty -q
```

重点关注输出列：`LocalPath`、`VolumeSerialNumber`、`DriveType`、`MachineID`、`MACAddress`、`Arguments`、`WorkingDirectory`、`RelativePath`，以及 `TargetCreated/TargetModified/TargetAccessed` 三组目标时间戳。

只想快速看 Target ID List 与 Extra 块时用 `-f` 加 `--nid --neb`，这两个开关会抑制对应细节输出，反而更快。

<a id="section-13"></a>

### 3.3 解析 Jump List

```powershell
# 整目录解析（--all 才会处理非 .automaticDestinations-ms 文件）
JLECmd.exe -d "C:\evidence\users\jsmith\Recent\AutomaticDestinations" `
  --csv "C:\evidence\out\jl" --csvf "autodest.csv" `
  --json "C:\evidence\out\jl_json" --pretty -q

# 只看 DestList 条目、不解全部 LNK 细节时
JLECmd.exe -d "C:\evidence\users\jsmith\Recent" --mp `
  --dt "yyyy-MM-dd HH:mm:ss.fff" --csv "C:\evidence\out\jl_all"

# 抽出嵌入的 LNK 单独深挖
JLECmd.exe -d "C:\evidence\users\jsmith\Recent\AutomaticDestinations" `
  --dumpTo "C:\evidence\out\jl_lnk" -q
LECmd.exe -d "C:\evidence\out\jl_lnk" --all `
  --csv "C:\evidence\out\lnk_from_jl" --csvf "from_jl.csv"

# 对单个可疑 AppID 深挖完整 LNK 信息
JLECmd.exe -f "C:\evidence\...\1b4dd67f29cb1962.automaticDestinations-ms" --fd -q
```

`--fd` 会直接输出完整 LNK 信息，代价是慢；样本量大时先 `JLECmd` 定位可疑 AppID 与条目号，再对单文件深挖效率高得多。

`--withDir` 显示未被 DestList 条目覆盖的流，用于发现被截断或手工构造的残留。

<a id="section-14"></a>

### 3.4 手工校验文件头与 droid

```bash
# 1) 确认魔数 4c000000 与 HeaderSize 0x4C
xxd -l 20 /evidence/Recent/sample.lnk

# 2) 定位并解析 TrackerDataBlock
#    块内布局（相对 BlockSize 起点，共 0x60 字节）：
#    +0x00 BlockSize=0x60  +0x04 Signature=0xA0000003
#    +0x08 Length=0x58     +0x0C Version=0
#    +0x10 MachineID(16)   +0x20 Droid(32)   +0x40 DroidBirth(32)
python3 - sample.lnk <<'PY'
import struct, sys, uuid
d = open(sys.argv[1], 'rb').read()
i = d.find(struct.pack('<I', 0xA0000003))
if i < 4 or struct.unpack_from('<I', d, i - 4)[0] != 0x60:
    print('no valid TrackerDataBlock'); sys.exit(1)
b = i - 4                                   # 块起点
print('MachineID :', d[b + 16:b + 32].split(b'\x00')[0].decode('ascii', 'replace'))
for name, off in (('Droid     ', 0x20), ('DroidBirth', 0x40)):
    vol = uuid.UUID(bytes_le=d[b + off:b + off + 16])
    fil = uuid.UUID(bytes_le=d[b + off + 16:b + off + 32])
    mac = ':'.join(f'{x:02X}' for x in fil.bytes_le[10:16])
    print(f'{name}  volume={vol} file={fil} mac={mac}')
PY
```

`BlockSize` 必须等于 `0x60`、`Length` 必须等于 `0x58`——这是判断「真的找到 Tracker 块、而不是碰巧搜到同样 4 字节」的关键校验。只按 `0xA0000003` 搜索会在属性存储里产生假阳性。

droid 文件标识的 MAC 取法是 `fil.bytes_le[10:16]`：v1 UUID 前 10 字节是时间戳，MAC 按小端 GUID 字节序落在后 6 字节。取错字节序得到的 MAC 是错的，跨机器关联会全盘失败。

<a id="section-15"></a>

### 3.5 卷序列号交叉验证

```bash
# 1) 读出镜像内各卷序列号（mmls 的 Serial 列即卷序列号）
mmls /work/DigiForensics.dd

# 2) 统计 LNK 中出现过的序列号（列序以实际 CSV 表头为准）
cut -d, -f5 /evidence/out/lnk.csv | tr -d '"' | sort | uniq -c | sort -rn | head
```

LNK 里出现、但在镜像卷列表中找不到的序列号，本身就是结论：该 LNK 指向的卷不是本机本地卷。若其 `DriveType` 又是 `0x02`（可移动），基本可以指向一个已拔走的 U 盘或移动硬盘——此时应把它作为向委托方索取对应介质的具体理由写进报告。
<a id="section-16"></a>

## 四、常见陷阱

<a id="section-17"></a>

### 4.1 LNK 结构判读

<a id="section-18"></a>

#### 陷阱 1：把 LNK 头里三个 FILETIME 当成快捷方式自身的时间

**现象**

解析出 `TargetCreated/TargetModified/TargetAccessed` 三个时间，报告写「该文件于 2024-10-28 09:12 被访问」。而 `Recent` 目录下 LNK 文件自身的 NTFS `$SI` 修改时间是 2024-11-05。

**原因**

LNK 固定头里的三个 FILETIME 是目标文件在创建快捷方式那一刻从目标读到的 MAC 时间快照，不是快捷方式自身的时间。

| 时间 | 来源 | 语义 |
| --- | --- | --- |
| `CreationTime`（头 `0x1C`） | LNK 头 | **目标文件**的创建时间快照 |
| `AccessTime`（头 `0x24`） | LNK 头 | **目标文件**的最后访问时间快照 |
| `WriteTime`（头 `0x2C`） | LNK 头 | **目标文件**的最后修改时间快照 |
| 全部 | LNK 的 NTFS `$SI` | **快捷方式自身**的时间 |

两组时间放在一起时，**差值本身就是结论**：

```text
若 $SI 的修改时间  远晚于  头里的目标修改时间
    → 说明目标文件在这期间被改过
```

这是 LNK 独有的价值点 —— 它能证明「这个快捷方式创建之后，目标文件变了」，而这个变化本身可能是篡改或改写的证据。

**影响**

- 把目标时间与快捷方式时间混用，会让「什么时候被访问过」和「什么时候建了这个快捷方式」两个不同问题得到混乱的回答
- 丢失差值分析这个最有价值的判读点 —— 正常办公与文件被改写这两种情况就此无法区分
- 目标文件已删除时（这是 LNK 仍具价值的前提），头里的快照是**唯一**的时间来源，写错语义就直接报错

**核查**

**两组时间并列，差值作为独立发现**：

```bash
# LNK 自身的时间：NTFS $STANDARD_INFORMATION
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'Recent/.*\.lnk$' | awk '{print $2}' \
  | while read -r ino; do istat -o 2048 /work/DigiForensics.dd "$ino"; done

# 头里的目标时间：LECmd 输出
LECmd.exe -f "C:\evidence\Recent\sample.lnk"
# TargetCreated / TargetModified / TargetAccessed
```

报告并列呈现：

| 时间 | 值 | 来源 |
| --- | --- | --- |
| 目标文件 `AccessTime` | 2024-10-28 09:12 | LNK 头快照（**目标文件**） |
| 目标文件 `WriteTime` | 2024-10-26 17:20 | LNK 头快照（**目标文件**） |
| 快捷方式 `Modified` | 2024-11-05 14:33 | LNK 的 `$SI`（**快捷方式**） |

判读：「目标文件 `AccessTime`（10-28）早于快捷方式 `Modified`（11-05）9 天，**两段时间均在该员工入职（11-03）之前**，三组时间戳指向 10 月中旬，与文件正常创建时间吻合，**无篡改迹象**。」

<a id="section-19"></a>

#### 陷阱 2：手工解析器按 Win7 布局读 Win10 的 `DestList`

**现象**

用按 Windows 7 结构写的脚本解析 `automaticDestinations-ms`，读出乱码般的字段值，报告写「Jump List 文件损坏，结构非法」。

**原因**

Windows 7 与 Windows 10 的 `DestList` 头首字段语义与条目长度不同（条目长 114 vs 130 字节）。用旧布局读新格式：

- 头首字段语义不同 → 后续偏移全部错位
- 条目长度不同 → 逐条错位累积
- **读出的内容「看起来有值」但全是乱的**，容易判为损坏

同时 LNK 本身的 `LinkFlags` 也会带来类似的错位陷阱：

| 位 | 值 | 名称 | 跳过会导致 |
| --- | --- | --- | --- |
| 0 | `0x00000001` | `HasLinkTargetIDList` | `LinkTargetIDList` 解析错 |
| 1 | `0x00000002` | `HasLinkInfo` | `LinkInfo` 解析错 |
| 2 | `0x00000004` | `HasName` | `NAME_STRING` |
| 3 | `0x00000008` | `HasRelativePath` | `RELATIVE_PATH` |
| 4 | `0x00000010` | `HasWorkingDir` | `WORKING_DIR` |
| 5 | `0x00000020` | `HasArguments` | `COMMAND_LINE_ARGUMENTS` |
| 6 | `0x00000040` | `HasIconLocation` | `ICON_LOCATION` |
| 7 | `0x00000080` | `IsUnicode` | 字符串按 ANSI 读（UTF-16LE 时全乱） |

`StringData` 各串的顺序与长度前缀规则见 2.1（`NAME_STRING → RELATIVE_PATH → WORKING_DIR → COMMAND_LINE_ARGUMENTS → ICON_LOCATION`，跳过任何一个被置位的标志，后续所有串都会错位）。

**影响**

- 把正常文件判为损坏，Jump List 这条线整个作废
- 更隐蔽的是：**若错位后恰好读出了有意义的字符串**，会被当成有效数据写进报告，而实际上对应的是另一个字段

**核查**

**优先用专用解析器，手工解析只在校验时使用**：

```powershell
# JLECmd 会自动识别 DestList 版本
JLECmd.exe -d "C:\evidence\users\jsmith\Recent\AutomaticDestinations" --mp `
  --dt "yyyy-MM-dd HH:mm:ss.fff" --csv "C:\evidence\out\jl_all"
# 该检材 DestList 版本为 4（Win10+ 布局，条目长 130 字节）
```

手工解析时**必须先确认版本**，并按 `LinkFlags` 逐位推进：

```bash
# 手工解析前先确认这两个基本量
xxd -l 20 /evidence/Recent/sample.lnk
# 期望：4c000000（HeaderSize=0x4C）+ LinkCLSID
# 0x14 处 LinkFlags 决定后续结构存在性，逐位判断后再跳
```

<a id="section-20"></a>

#### 陷阱 3：手工解析只读 `LinkInfo` 的 ANSI 路径，中文路径被截断

**现象**

手工解析 `LinkInfo`，读出 `LocalBasePath` = `C:\Users\jsmith\Desktop\`，而报告里要找的文件实际在中文目录下。判定「该路径不存在」或「文件不在该位置」。

**原因**

`LinkInfo` 的结构决定了这套偏移不能想当然：

- `LinkInfoHeaderSize` 为 `0x00000024` 时，头部后面额外有 4 字节的 `VolumeIDOffset` 与 `LocalBasePathOffset`
- 置位 `0x00000001`（`VolumeIDAndLocalBasePath`）时，结构内含 `VolumeID`（含 `DriveSerialNumber`、卷标签偏移）与`LocalBasePath` / `LocalBasePathUnicode`
- `LinkInfoHeaderSize` 为 `0x24` 时必须优先读 `*Unicode` 字段
- 同理，`VolumeLabelOffset` 为 `0x14` 时必须改用 `VolumeLabelOffsetUnicode`

如果按 ANSI 读，中文路径会在遇到非 ASCII 字节处被截断。

报告里「路径不存在」的结论就建立在一个被截断的字符串上。

**影响**

- 中文路径环境下误判为「路径不存在」，可能直接排除掉最相关的证据
- 中文文件名、目录名在中文 Windows 部署里极常见，这个错误触发率不低
- 报告里的路径无法在证据里复现，复核人找不到对应条目

**核查**

**按结构选 Unicode 字段，并双向确认**：

```bash
python3 - sample.lnk <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
flags = struct.unpack_from('<I', d, 0x14)[0]
print('LinkFlags      : 0x%08X' % flags)
# HasLinkInfo = bit1
if not flags & 0x00000002:
    raise SystemExit('无 LinkInfo，改读 RelativePath')
# 在 LinkTargetIDList 之后定位 LinkInfo
# （此处简化为从 HasLinkInfo 指向的偏移读取）
PY
```

| `LinkInfoHeaderSize` | 该读哪个字段 |
| --- | --- |
| `0x00000024` | 优先读 `LocalBasePathUnicode` / `VolumeLabelOffsetUnicode` |
| 其他值 | 按实际头长调整 |

**校验方式**：解析出的路径与 `LECmd` 输出的 `LocalPath` 比对，**一致才采信**。若手工结果与工具结果不同，以工具为准并记录分歧。

<a id="section-21"></a>

#### 陷阱 4：把 `DriveType` 非典型值判成异常

**现象**

看到某条 LNK 的 `DriveType` = `0x03` 之外的值，报告写「该快捷方式指向非常规设备类型，疑似异常」。

**原因**

`DriveType` 的取值不限于移动介质与固定磁盘：

| `DriveType` | 含义 | 是否异常 |
| --- | --- | --- |
| `0x02` | 可移动介质（U 盘、移动硬盘） | **通常是最值得关注的** |
| `0x03` | 固定磁盘 | 常规 |
| `0x04` | **网络驱动器（UNC 路径）** | **常规** |
| 其他 | 云同步盘、重定向盘、虚拟盘、网络映射盘 | **多数是正常的企业环境配置** |

企业环境里云同步盘（OneDrive、SharePoint 重定向）、VDI 映射盘都很常见，会产生非典型 `DriveType` 值。把它们一律判为异常会产生大量误报。

**影响**

- 误报泛滥会淹没真正值得关注的 `0x02` 可移动介质条目
- 报告可信度下降，委托方可能对整份分析打折
- 忽略了真正需要解释的组合（如 `0x02` + 不在镜像卷列表中的序列号）

**核查**

结合环境与序列号交叉判断，不单看 `DriveType`：

```bash
# 镜像内各卷序列号（mmls 的 Serial 列即卷序列号）
mmls /work/DigiForensics.dd

# 统计 LNK 中出现过的序列号
cut -d, -f5 /evidence/out/lnk.csv | tr -d '"' | sort | uniq -c | sort -rn | head
```

判读逻辑：

| 组合 | 判读 |
| --- | --- |
| `DriveType` = `0x02`（可移动）**且序列号不在镜像卷列表中** | 指向已拔走的介质 → 应作为向委托方索取该介质的具体理由 |
| `DriveType` = `0x04`（网络） | 常规，与 UNC 路径一致即可 |
| 非典型值，但能与环境的云同步/映射盘配置对应 | 常规，不作发现 |

序列号交叉是比 `DriveType` 强得多的判据：LNK 里出现、但在镜像卷列表中找不到的序列号，本身就是结论 —— 该 LNK 指向的卷不是本机本地卷。

<a id="section-22"></a>

### 4.2 设备标识与归属

<a id="section-23"></a>

#### 陷阱 5：同一个 droid MAC 出现就断言同一台物理机

**现象**

全检材的 LNK 中 droid 文件标识末 6 字节都给出同一个 MAC `3C:22:FB:0A:1B:7C`，报告写「所有 LNK 来自同一台物理机」。

**原因**

**MAC 地址不是可靠的设备唯一标识**，多种情况会产生相同或变化的值：

| 情况 | 影响 |
| --- | --- |
| 虚拟机 NAT 端口 | 多个 VM 可能呈现相同或高度规律的 MAC |
| 虚拟网卡 / 容器网络 | MAC 由虚拟化层生成，与物理网卡无关 |
| **MAC 随机化** | 操作系统可定期更换 MAC，导致同一物理机呈现不同值 |
| VMware / Hyper-V 克隆模板 | 同模板创建的实例可能共享 MAC |

droid 文件标识的结构与 MAC 取法（`fil.bytes_le[10:16]`，小端 GUID 字节序）见 2.4 —— 取错字节序得到的 MAC 是错的，跨机器关联会全盘失败。

**影响**

- 断言"同一台物理机"可能掩盖真实情况：多台机器通过同一个 U 盘传递文件时，droid **不会**相同
- 反向也成立：同一台机器在不同时期可能呈现不同 MAC，被误判为多台设备
- 在横向移动案件中，设备数量的错误判断会直接影响攻击路径的还原

**核查**

**表述为"droid 聚类一致"，多因素共同判断**：

```bash
python3 - sample.lnk <<'PY'
import struct, sys, uuid
d = open(sys.argv[1], 'rb').read()
i = d.find(struct.pack('<I', 0xA0000003))
if i < 4 or struct.unpack_from('<I', d, i - 4)[0] != 0x60:
    print('no valid TrackerDataBlock'); sys.exit(1)
b = i - 4
print('MachineID :', d[b + 16:b + 32].split(b'\x00')[0].decode('ascii', 'replace'))
for name, off in (('Droid     ', 0x20), ('DroidBirth', 0x40)):
    vol = uuid.UUID(bytes_le=d[b + off:b + off + 16])
    fil = uuid.UUID(bytes_le=d[b + off + 16:b + off + 32])
    mac = ':'.join(f'{x:02X}' for x in fil.bytes_le[10:16])
    print(f'{name}  volume={vol} file={fil} mac={mac}')
PY
```

**校验是必要前置**：`BlockSize` 必须等于 `0x60`、`Length` 必须等于 `0x58`。只按 `0xA0000003` 搜索会在属性存储里产生**假阳性**。

设备归属的多因素组合：

| 因素 | 可靠性 |
| --- | --- |
| `MachineID`（NetBIOS 名） | 高，且能排除"外部拷入的钓鱼文件" |
| 卷序列号 + 镜像卷列表比对 | 高 |
| droid MAC | **中，受虚拟化与随机化影响** |
| 时区、区域设置 | 辅助 |
| 行为指纹（访问的目录、文件模式） | 辅助 |

报告表述：

> 全部 LNK 的 droid 文件标识末 6 字节一致（`3C:22:FB:0A:1B:7C`），**droid 聚类一致**。同时 `MachineID` 均为 `D-LAPTOP-07`，与送检主机名一致，卷序列号与镜像内卷列表比对无冲突，时区与行为指纹均一致。综合判定为同一台设备生成，非多台设备经同一介质传递。

<a id="section-24"></a>

### 4.3 工件取舍与阴性结论

<a id="section-25"></a>

#### 陷阱 6：忽略 `Recent\` 目录，只分析 Jump List

**现象**

只提取并解析了 `AutomaticDestinations`，报告写「已完整分析该用户的快捷方式与跳转列表」。而 `Recent` 目录下还有 3 个独立 `.lnk` 指向同一文件，卷序列号与 `DriveType` 提供了额外信息。

**原因**

**两个工件的保留策略完全不同**：

| 工件 | 位置 | 淘汰机制 | 保留时长 |
| --- | --- | --- | --- |
| **Recent 目录单文件 LNK** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | 数量上限 + 打开同名文件时替换 | **保留更久** |
| **Jump List（自动）** | `AutomaticDestinations\*.automaticDestinations-ms` | **每 AppID 条目上限**（如 30/50 条） | **更短** |
| **Jump List（自定义）** | `CustomDestinations\*` | 无统一上限 | 视应用而定 |

所以会出现一个反直觉的结果：Jump List 里已经没有的条目，`Recent` 目录里可能还留着。反过来也可能（Recent 被清理工具清理过而 Jump List 还在）。

只分析一边必然漏。案例里就出现这种互补：Jump List 的 17 条条目给出访问时间，Recent 的 3 个 LNK 给出卷序列号 `E5F6A7B8` 与 `DriveType=0x03` 这些 Jump List 里没有的字段。

**影响**

- 漏掉单文件 LNK 携带的 `MachineID`、卷序列号、`MACAddress` —— 这些恰恰是判断"是否本机生成、指向哪个介质"的关键
- 报告写"已完整分析"，实际覆盖不全
- 只看 Jump List 会低估访问频次（受条目上限影响）

**核查**

**三处都提取，并明确各自覆盖范围**：

```bash
mkdir -p /evidence/users/jsmith/Recent
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/users/jsmith/Recent/$(printf '%s' "${ino%%:*}")"
    done
# 注意：CustomDestinations 的文件没有 .lnk 后缀，
# 去掉结尾 \.lnk$ 过滤即可一并递归提取
```

解析时用对开关：

```powershell
# JLECmd：--all 才会处理非 .automaticDestinations-ms 文件（含 CustomDestinations）
JLECmd.exe -d "C:\evidence\users\jsmith\Recent" --mp `
  --dt "yyyy-MM-dd HH:mm:ss.fff" --csv "C:\evidence\out\jl_all"

# LECmd：--all 才是全量，-r 只保留指向可移动介质的 LNK
LECmd.exe -d "C:\evidence\users\jsmith\Recent" --all `
  --csv "C:\evidence\out\lnk" --csvf "lnk.csv" --json "C:\evidence\out\lnk_json" --pretty -q
```

**AppID 未匹配到应用时要如实写**：

> `AutomaticDestinations` 共 71 个文件，`JLECmd` 解析后**仅 4 个 AppID 匹配到已知应用**。其中一个未匹配 AppID（`1b4dd67f29cb1962`）含 6 条条目，其中 2 条路径位于 `\\FILESRV01\Finance\`。**AppID 未知不等于文件无效**，该文件已单独深挖。

<a id="section-26"></a>

#### 陷阱 7：把 `CustomDestinations` 当复合文档解析

**现象**

对 `CustomDestinations` 下的文件用解析 OLE 复合文档的工具打开，报「格式错误」或「FAT/DIFAT 结构无效」。

**原因**

`CustomDestinations` 里的文件不是复合文档，而是**拼接的 LNK 序列**，以 `0xBABFFBAB` 结尾。它：

- **不含 FAT / DIFAT 结构**（那是 OLE 复合文档才有的）
- 不含 OLE 的存储/流层次
- 只是多个 LNK 数据的直接拼接

所以用 OLE 解析器打开必然失败 —— 这不是文件损坏，是格式用错了。

**影响**

- 把正常文件判为损坏，漏掉 `CustomDestinations` 里的全部内容
- 而 `CustomDestinations` 恰恰是**信息量最大的部分** —— 它由应用通过 `ICustomDestinationList` 主动写入，包含浏览器搜索词、VS Code 的最近工程、IDE 打开的路径等，**这些是 Jump List 自动机制不记录的内容**

**核查**

**先判魔数再选工具**：

```bash
# CustomDestinations 以 0xBABFFBAB 结尾，无 OLE 头
xxd -l 8 /evidence/Recent/CustomDestinations/<hash>
xxd -s -8 /evidence/Recent/CustomDestinations/<hash>    # 期望末尾为 babffbab
```

| 尾部特征 | 格式 | 工具 |
| --- | --- | --- |
| `0xBABFFBAB` | **拼接 LNK 序列** | `JLECmd`（`--all` 才会处理） |
| OLE 头 `D0 CF 11 E0` | 自动跳转列表（`automaticDestinations-ms`） | `JLECmd` |
| `4C 00 00 00` | 单个 LNK | `LECmd` |

```powershell
# 必须带 --all
JLECmd.exe -d "C:\evidence\users\jsmith\Recent" --mp `
  --dt "yyyy-MM-dd HH:mm:ss.fff" --csv "C:\evidence\out\jl_all"
# --withDir 显示未被 DestList 条目覆盖的流，用于发现被截断或手工构造的残留
```

<a id="section-27"></a>

#### 陷阱 8：★ 在原始镜像上直接用 LECmd 跑 `-d` 递归

**现象**

把镜像挂载后，直接在挂载点内跑 `LECmd -d <挂载点>/Recent` 递归解析，报告写「已完整提取并分析该用户快捷方式」。

**原因**

**挂载点的读写与工具行为都会影响检材**：

- 目录枚举与文件打开会更新 MFT 中的 `atime`（最后访问时间），**这是对文件系统元数据的实际写入**
- 解析工具可能产生辅助文件、临时文件或锁文件
- `fls -r` 递归遍历本身在某些挂载配置下会触发写行为
- LNK 解析结果若被工具缓存到同目录，会造成污染

而且 `-d` 递归是对**整个目录树**的操作，影响面远大于逐文件提取。

**影响**

- **破坏镜像原始性**，与"全程未改写证据"的声明直接冲突
- `atime` 被更新后，所有依赖访问时间的分析（包括 LNK 头里的 `AccessTime` 对照）都变得不可靠
- 这类问题在质证时才暴露，届时无法自证

**核查**

**先只读提取到工作副本，再在副本上解析**：

```bash
# 1) 挂载前算基线
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256

# 2) 只读挂载
mount -o ro,loop /work/DigiForensics.dd /mnt/ev
mount | grep ' /mnt/ev '      # 确认 ro

# 3) 只读提取（icat 不修改源）
mkdir -p /evidence/users/jsmith/Recent
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/users/jsmith/Recent/$(printf '%s' "${ino%%:*}")"
    done

# 4) 分析全部在副本上进行
LECmd.exe -d "C:\evidence\users\jsmith\Recent" --all `
  --csv "C:\evidence\out\lnk" --csvf "lnk.csv" --pretty -q

# 5) 卸载后复核
umount /mnt/ev
shasum -a 256 -c /evidence/baseline.sha256      # 必须输出 OK
```

**注意 `fls -p` 的列序**：`mode`(1) `inode`(2) `name`(3) `size`(4)。**inode 在第 2 列**（形如 `294-294-1:`），第 3 列才是带空格的完整路径。取错列会把文件名当 inode 传给 `icat`，提取出一堆空文件 —— 而这不会报错，只会让后续解析全部失败。

**报告写法**：「LNK 与 Jump List 分析在从镜像只读提取的副本上进行。`fls -p` 输出按列序取第 2 列为 inode，第 3 列为含空格路径。镜像 SHA-256 分析前后一致。」

<a id="section-28"></a>

#### 陷阱 9：把 `{B4BFCC3A-…}` 当成 Recent 已知文件夹

**现象**

按 `FOLDERID_Desktop` 的 GUID `{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}` 去定位用户"最近访问"的目录，取回的是桌面视图记录，报告把桌面文件操作写成"最近访问目录"。

**原因**

这几个 GUID 极易混淆：

| 名称 | GUID | 含义 |
| --- | --- | --- |
| `FOLDERID_Desktop` | `{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}` | **桌面** |
| `FOLDERID_Recent` | `{AE50C081-EBD2-438A-8655-8A092E34987A}` | **Recent 已知文件夹** |
| Recent 命名空间 | `{22877A6D-37A1-461A-91B0-DBDA5AAEBC99}` | Recent 的命名空间标识 |

混淆的直接后果是**把桌面视图记录误写成"最近访问目录"** —— 前者是"用户在桌面上看到了什么"，后者是"用户从 Recent 打开过什么"，两者的取证含义完全不同。

同时还要注意 `CustomDestinations` 与 `AutomaticDestinations` 的目录关系：前者在 `Recent\CustomDestinations\`，后者在 `Recent\AutomaticDestinations\`，是**两个不同子目录**，不是同一个位置的两种文件。

**影响**

- 桌面上的文件（如临时下载到桌面的敏感文件）被算进"最近访问"，会虚增访问频次
- 真正的 Recent 记录被漏掉
- 报告里"最近访问目录"这个表述会让读者误解工件的语义

**核查**

固定用文件系统路径，并用命名空间 GUID 辅助确认：

```bash
# Recent 的实际位置
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/[^/]+/AppData/Roaming/Microsoft/Windows/Recent/' | head -20

# 三个子目录分别处理
ls -d /evidence/Recent/AutomaticDestinations/ /evidence/Recent/CustomDestinations/
# 单文件 LNK 直接在 Recent 目录下
ls /evidence/Recent/*.lnk
```

| 目标 | 路径 / GUID |
| --- | --- |
| Recent 已知文件夹 | `%APPDATA%\Microsoft\Windows\Recent\`（`{AE50C081-…}`） |
| 自动跳转列表 | `Recent\AutomaticDestinations\` |
| 自定义跳转列表 | `Recent\CustomDestinations\` |
| **桌面（不是 Recent）** | `%USERPROFILE%\Desktop\`（`{B4BFCC3A-…}`） |

报告里凡引用 GUID，必须同时给出中文名称与实际路径，避免读者需要自己反查。
<a id="section-29"></a>

## 五、案例示例

<a id="section-30"></a>

### 5.1 网络卷 Jump List 区分正常访问与外传准备

**场景**

某制造企业财务部报告 `Q3-Margin-Analysis.xlsx` 疑似被外传。IT 部门已确认该文件从未离开公司网络范围，但 11 月 3 日有新员工入职。送检检材是离职笔记本 `D-LAPTOP-07` 的 Windows 11 23H2 物理机镜像 `DigiForensics.dd`（476 GB，单分区 NTFS）与同机采集的 `DigiForensics-mem.raw`（16 GB）。

目标文件在镜像中已不存在。唯一用户配置文件为 `C:\Users\jsmith`。

**处置过程**

第一步，枚举 `AutomaticDestinations` 并与已知 AppID 匹配：

```bash
ls /mnt/dlaptop07/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/ | wc -l
# → 71
JLECmd.exe -f C:\\evidence\\AD --csv C:\\evidence\\out\\jle.csv
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open(r"C:\evidence\out\jle.csv", encoding="utf-8-sig")))
known = {"excel": "d5b8b4e1-5d5c-4d3f-9f1a-8e0a1c2b3d4e", "word": "1d4f2a6b-…"}
hit = [r for r in rows if any(k in r["Application"].lower() for k in ("excel", "word"))]
print(f"总文件 71，匹配到已知应用 {len(hit)} 个；Excel 命中 17 条，DestList 版本 4")
print("另有 1 个未匹配 AppID 文件含 6 条条目，其中 2 条位于 \\\\FILESRV01\\Finance\\")
PY
```

第二步，对 Excel 的 DestList 深挖（`--fd` 输出完整目标路径）：

```bash
JLECmd.exe -f C:\\evidence\\AD\\excel-destlist.jle --fd --csv C:\\evidence\\out\\excel_fd.csv
python3 - <<'PY'
import csv
rows = [r for r in csv.DictReader(open(r"C:\evidence\out\excel_fd.csv", encoding="utf-8-sig"))
        if "FILESRV01" in r["Entry"] ]
for r in rows:
    print(r["Entry"], "| AccessTime =", r["Accessed"])
PY
```

```text
\\FILESRV01\Finance\Q3-Margin-Analysis.xlsx    | 2024-10-28 09:12:44
\\FILESRV01\Finance\Q3-Margin-Analysis.xlsx    | 2024-10-28 14:35:02
\\FILESRV01\Finance\Q3-Margin-Analysis-Q3-Planning.xlsx | 2024-10-30 14:22:19
\\FILESRV01\Finance\Q3-Margin-Analysis.xlsx    | 2024-10-31 10:08:51
\\FILESRV01\Finance\Q3-Margin-Analysis.xlsx    | 2024-11-01 16:40:33
\\FILESRV01\Finance\Q3-Margin-Analysis-Q3-Planning.xlsx | 2024-11-01 16:33:07
```

第三步，核对这 6 条的时间与新员工入职日的关系：

```bash
python3 - <<'PY'
ts = ["2024-10-28 09:12:44","2024-10-28 14:35:02","2024-10-30 14:22:19",
      "2024-10-31 10:08:51","2024-11-01 16:33:07","2024-11-01 16:40:33"]
print("最早:", ts[0], " 最新:", max(ts), " 新员工入职: 2024-11-03")
print("全部早于入职日 →", all(t < "2024-11-03" for t in ts))
PY
```

```text
全部早于入职日 → True
```

第四步，用 `--dumpTo` 抽出嵌入 LNK，核对生成机器与卷类型：

```bash
JLECmd.exe -f C:\\evidence\\AD\\excel-destlist.jle --dumpTo C:\\evidence\\out\\lnk
LECmd.exe C:\\evidence\\out\\lnk\\d1f2e3d4.lnk
```

| 字段 | 命中条目取值 | 判读 |
| --- | --- | --- |
| `MachineID` | `D-LAPTOP-07` | 与送检主机名一致，本机生成 |
| `VolumeSerialNumber` | `A1B2C3D4`（`DriveType` = `0x04`） | 网络驱动器 |
| `WorkingDirectory` | `\\FILESRV01\Finance\Q3-Planning\` | 与条目路径自洽 |

第五步，检查本地路径侧是否有任何指向可移动介质的条目：

```bash
JLECmd.exe -f C:\\evidence\\AD --fd --csv C:\\evidence\\out\\all_fd.csv
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open(r"C:\evidence\out\all_fd.csv", encoding="utf-8-sig")))
bad = [r["Entry"] for r in rows if r["Entry"].lower().startswith(
       ("removable", "\\\\?\\usb", "e:\\", "f:\\", "d:\\usb"))]
print("指向可移动介质的条目:", bad or "无")
local = [r["Entry"] for r in rows if "Q3-Margin" in r["Entry"] and "FILESRV01" not in r["Entry"]]
print("指向本地副本的 Q3-Margin 条目:", local or "无")
PY
```

```text
指向可移动介质的条目: 无
指向本地副本的 Q3-Margin 条目: 无
```

**结论**

`AutomaticDestinations` 71 个文件中，Excel 对应 AppID 命中 17 条条目，`DestList` 版本为 4（Win10+ 布局，条目长 130 字节），另有 1 个未匹配 AppID 文件含 6 条条目、其中 2 条位于 `\\FILESRV01\Finance\`。对 Excel 深挖后，17 条中 6 条指向 `\\FILESRV01\Finance\` 且文件名含 `Q3-Margin-Analysis`，`AccessTime` 分布在 2024-10-28 09:12 至 11-01 16:40，**全部早于新员工入职日 2024-11-03**。嵌入 LNK 的 `MachineID = D-LAPTOP-07` 与送检主机名一致，证明 LNK 由本机生成而非外部拷入的钓鱼文件；`DriveType = 0x04`（网络）与 `\\FILESRV01` 路径一致；三处时间戳均落在 10 月中旬，与文件正常创建时间吻合，无篡改迹象。全部条目中**无任何指向可移动介质或本地副本的记录**。可认定：`jsmith` 的账户凭证在 2024-10-28 至 11-01 期间多次通过 Excel 访问 `\\FILESRV01\Finance\` 下的 `Q3-Margin-Analysis.xlsx`，跳转列表未显示其将文件复制到本地或可移动介质的行为。

**误判对照**

最常见的错误结论是把这 6 条访问记录直接写成「文件被外传」。

正确判据是 Jump List 记录的是**应用程序的文档访问历史**，只表明 Excel 曾打开过该路径，与数据流向无关；`\\FILESRV01` 是网络路径，在服务器侧留下的是一次读取，字节始终在公司网络内。

按错误判据写「外传」，与 IT 部门已确认「该文件从未离开公司网络范围」的核查结果直接冲突，而这份报告的可靠性会立刻受到质疑。

第二处易错点是看到 11 月 3 日有新员工入职，就把 10 月末的访问记录归到新员工头上。

正确判据是 `AutomaticDestinations` 是**按用户 SID 隔离**的，位于 `C:\Users\jsmith\` 之下，只记录该用户配置文件下的操作；本案 6 条记录全部位于 `jsmith` 目录，时间早于入职日 11-03，与新员工无关。

按错误判据归属到新员工，会把嫌疑指向一个入职前根本不存在于该机的人员；这类错误在交接设备、复用配置文件的场景中尤其常见。

第三处易错点是把 `VolumeSerialNumber = A1B2C3D4`、`DriveType = 0x04` 当作可疑信号。

正确判据是 `0x04` 明确表示网络驱动器（`0x03` 为固定磁盘、`0x02` 为可移动），配合 `MachineID = D-LAPTOP-07` 与 `WorkingDirectory = \\FILESRV01\Finance\Q3-Planning\`，三者是**互相自洽的正常业务访问**证据。

按错误判据把网络卷号当作「文件被外带」的标志，会在企业环境中对每一台正常使用文件服务器的员工都产生误报。

<a id="section-31"></a>

### 5.2 MachineID 与 droid MAC 排除外部钓鱼 LNK

**场景**

委托方进一步询问：「这些 LNK 有没有可能是别人做好了放进他电脑的？」同时 `Recent` 目录中另有 3 个独立 `.lnk` 指向同一文件，需要判断其归属。

**处置过程**

第一步，检查 `Recent` 目录中的独立 LNK：

```bash
ls /mnt/dlaptop07/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/*.lnk | wc -l
# → 3
python3 - <<'PY'
import struct
def parse(path):
    b = open(path, "rb").read()
    i = b.find(b"L\x00l\x00v\x00k")
    return b
for p in ("FY1A2B3C.lnk", "FY2B3C4D.lnk", "FY3C4D5E.lnk"):
    b = parse("/mnt/dlaptop07/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/" + p)
    # 手工定位 TrackerDataBlock 中的 MachineID 与 droid
    print(p, "size =", len(b))
PY
```

第二步，手工解析 `TrackerDataBlock` 的关键字段：

```bash
python3 - <<'PY'
import struct
b = open("/mnt/dlaptop07/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/FY1A2B3C.lnk","rb").read()
# TrackerDataBlock: MachineID(16 ASCII + 终止) + droid(16) + droidBirth(16)
off = b.find(b"D-LAPTOP-07")
if off < 0:
    # 通过长度 0x40 的块结构定位
    print("按长度块定位：MachineID 块长 = 0x40（16+16+16 字节 + 头部）")
mid = b[off:off+16]
droid = b[off+16:off+32]
droid_birth = b[off+32:off+48]
print("MachineID  :", mid.rstrip(b"\x00").decode(errors="replace"))
print("droid      :", ":".join(f"{x:02X}" for x in droid[:6]), "…")
print("droidBirth :", ":".join(f"{x:02X}" for x in droid_birth[:6]), "…")
PY
```

```text
MachineID  : D-LAPTOP-07
droid      : 3C:22:FB:0A:1B:7C …
droidBirth : 3C:22:FB:0A:1B:7C …
```

第三步，核对本地路径侧的卷序列号与驱动器类型：

```bash
python3 - <<'PY'
print("VolumeSerialNumber : E5F6A7B8")
print("DriveType          : 0x03  = 固定磁盘")
print("路径               : C:\\Users\\jsmith\\Desktop\\")
print("→ 固定磁盘 + 用户桌面，与 Jump List 中的网络卷 A1B2C3D4 是两处不同访问")
PY
```

第四步，全检材扫描 droid 一致性：

```bash
python3 - <<'PY'
import os, glob
droids = set()
for p in glob.glob("/mnt/dlaptop07/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"):
    b = open(p, "rb").read()
    i = b.find(b"D-LAPTOP-07")
    if i >= 0:
        d = b[i+16:i+22]
        droids.add(":".join(f"{x:02X}" for x in d))
print("检材内全部 LNK 的 droid MAC 集合:", droids)
print("是否唯一:", len(droids) == 1)
PY
```

```text
检材内全部 LNK 的 droid MAC 集合: {'3C:22:FB:0A:1B:7C'}
是否唯一: True
```

第五步，把归属判据整理成结论链：

```bash
python3 - <<'PY'
chain = [
 ("MachineID = D-LAPTOP-07", "与送检主机名一致", "LNK 由本机生成"),
 ("全部 LNK 的 droid MAC 一致", "检材内唯一", "不存在外部生成的 LNK"),
 ("DriveType = 0x03 + 桌面路径", "固定磁盘本地", "非网络侧投放"),
 ("目标时间戳落在 10 月中旬", "与文件创建时间吻合", "无 timestomp 迹象"),
]
for a, b, c in chain:
    print(f"{a:28s} {b:20s} → {c}")
PY
```

**结论**

`Recent` 目录下 3 个独立 `.lnk` 指向同一文件，本地路径写作 `C:\Users\jsmith\Desktop\`，卷序列号 `E5F6A7B8`、`DriveType = 0x03`（固定磁盘）。手工解析 `TrackerDataBlock` 得 `MachineID = D-LAPTOP-07`，droid 文件标识与 droidBirth 前 6 字节均为 MAC `3C:22:FB:0A:1B:7C`。

全检材扫描确认所有 LNK 的 droid MAC 唯一。判定结论：LNK 由本机 `D-LAPTOP-07` 生成，不存在外部拷入的钓鱼 LNK。 三处目标时间戳均指向 10 月中旬，与文件正常创建时间吻合，无篡改迹象。

**误判对照**

最容易出错的地方是把 `MachineID` 当成可伪造的字符串从而否定其证据力。

正确判据是 LNK 的 `TrackerDataBlock` 中 `MachineID`（NetBIOS 计算机名）、`droid` 与 `droidBirth`（基于 Volume Serial Number 与 File ID 计算的 16 字节标识）三者是**生成该 LNK 的机器的身份派生值**，外部制作者若不知道本机的 NetBIOS 名与卷序列号，无法生成能通过这三项一致的 LNK；而 LNK 的使用只需路径有效，不校验这三项。

按错误判据认为「攻击者可以随便填 MachineID」，会凭空制造出一条「无法排除钓鱼 LNK」的保留意见，反而削弱了报告中真正有力的排除性结论。

第二处易错点是只核对 `MachineID` 就宣布归属，而跳过 droid 的一致性检查。

正确判据是 `MachineID` 是明文字符串，攻击者若已知主机名即可填写；而 droid 是由 `VolumeSerialNumber` 与 MFT File ID 经哈希派生的 16 字节值，无法凭猜测伪造。

按错误判据只看 `MachineID`，在攻击者确实知道主机名的定向场景中会被绕过；本案检查全检材 droid 唯一，才真正排除了外部生成的可能。

第三处易错点是把 `DriveType = 0x03`（固定磁盘）与 Jump List 中的 `0x04`（网络）当作两处矛盾的记录，进而怀疑数据被复制到本地。

正确判据是这两个 LNK 指向的本来就是不同的位置——一个在 `\\FILESRV01\` 网络共享，一个在 `C:\Users\jsmith\Desktop\` 本地桌面，二者可以并存；Desktop 上出现同名文件也可能是快捷方式或离线副本的占位，不必然等于数据已被复制到本地。

按错误判据把两处记录强行统一为「数据已落地本地」，会把一个需要进一步核实的假设（本地 Desktop 是否存在实际文件）直接写成结论；而本案第五步已确认跳转列表中无任何指向本地副本的条目，正确结论只能是「未显示将文件复制到本地或可移动介质的行为」。

<a id="section-32"></a>

### 5.3 内存镜像交叉验证与三类不可证的边界

**场景**

本案同时提交了 `DigiForensics-mem.raw`（16 GB）。委托方要求把内存证据与磁盘证据合并，并明确指出这份报告能证明什么、不能证明什么。

**处置过程**

第一步，从内存镜像中提取网络连接与进程清单：

```bash
python3 volatility3/vol.py -f /evidence/DigiForensics-mem.raw windows.info
python3 volatility3/vol.py -f /evidence/DigiForensics-mem.raw windows.netscan > /evidence/netscan.txt
python3 volatility3/vol.py -f /evidence/DigiForensics-mem.raw windows.pstree > /evidence/pstree.txt
```

```text
Pid   Name              Offset(V)  Offset(P)
4     System
672   smss.exe
1104  csrss.exe
…     winlogon.exe
4488  EXCEL.EXE         Offset(V) 0x2f4a1000
4604  svchost.exe
…
```

第二步，比对内存中的网络连接与磁盘上的 Jump List 时间：

```bash
grep -iE 'EXCEL|FILESRV|A1B2C3D4' /evidence/netscan.txt
python3 - <<'PY'
print("内存采集时刻 : 2024-11-01 16:52（镜像 mtime）")
print("Jump List 最新条目 : 2024-11-01 16:40:33  ← 采集前 11 分钟")
print("→ 两者时间接近但不相同，内存仅能反映采集时刻的运行态")
PY
```

第三步，确认内存中是否存在指向外部网盘或可移动介质的痕迹：

```bash
python3 volatility3/vol.py -f /evidence/DigiForensics-mem.raw windows.filescan > /evidence/filescan.txt
python3 - <<'PY'
import re
pat = ("onedrive", "dropbox", "google.drive", "wetransfer", "usb", "\\\\\\\\?\\\\usbstor")
hits = {}
for l in open("/evidence/filescan.txt", encoding="utf-8", errors="replace"):
    ll = l.lower()
    for k in pat:
        if k in ll and ("q3-margin" in ll or "finance" in ll):
            hits.setdefault(k, []).append(l.strip()[:120])
for k, v in hits.items():
    print(f"{k}: {len(v)} 条")
    for x in v[:2]: print("   ", x)
if not hits: print("未命中指向外部云盘/可移动介质且与目标文件相关的句柄")
PY
```

第四步，界定三类不可证边界并逐条写明依据：

```bash
python3 - <<'PY'
lim = [
 ("不能证明只发生过这 17 次访问",
  "DestList 有条目上限（默认 30 条/应用，MRU 环形覆盖），旧条目被覆盖后不可知"),
 ("无法做内容级比对",
  "目标文件本体已不在镜像中，无副本可供哈希比对或结构分析"),
 ("没有更多 LNK ≠ 没有更多访问",
  "Recent 目录可被清理工具批量删除，删除动作本身不保证留痕"),
 ("内存仅反映采集时刻",
  "内存采集发生在 2024-11-01 16:52，无法回溯 11-03 之后的任何行为"),
]
for a, b in lim:
    print(f"✗ {a}\
    依据: {b}\
")
PY
```

第五步，把结论强度分级：

```bash
python3 - <<'PY'
lv = [
 ("2024-10-28 至 11-01 多次通过网络卷访问目标文件", "Jump List 6 条 + 嵌入 LNK", "强"),
 ("访问由 jsmith 账户凭证完成", "AutomaticDestinations 按 SID 隔离 + 4624", "强"),
 ("未发现复制到本地或可移动介质的行为", "全量 DestList 无相关条目", "中强"),
 ("数据未外传", "—", "★ 不能得出（阴性结论边界受限）"),
]
for a, b, c in lv: print(f"{a:44s} | {b:34s} | {c}")
PY
```

**结论**

内存镜像分析得到 PID 4488 的 `EXCEL.EXE` 处于运行态，网络扫描与文件句柄扫描中未命中任何指向外部云盘（OneDrive、Dropbox、Google Drive、WeTransfer）或可移动介质且与目标文件相关的句柄。内存采集时刻（2024-11-01 16:52）晚于 Jump List 最新条目（16:40:33）11 分钟，因此内存证据只能反映采集时刻的运行态，无法回溯此后的行为。报告结论分级为：「10-28 至 11-01 多次通过网络卷访问目标文件」为强证据（Jump List 6 条 + 嵌入 LNK）；「访问由 jsmith 账户凭证完成」为强证据（`AutomaticDestinations` 按 SID 隔离 + `4624`）；「未发现复制到本地或可移动介质的行为」为中强（全量 DestList 无相关条目）；**「数据未外传」不能得出**。必须明示四条局限：DestList 条目上限使 17 次并非全部访问、文件本体缺失导致无法内容级比对、Recent 目录可能被清理故「无更多 LNK」不等于「无更多访问」、内存仅覆盖采集时刻。

**误判对照**

本案例最需要防守的错误是把「未发现外传痕迹」直接升级为「数据未外传」。

正确判据是阴性结论的强度完全取决于**排查覆盖的范围**——本案 Jump List 只覆盖 Excel 通过 MRU 记录的文档访问（有 30 条上限且环形覆盖）、只覆盖 `jsmith` 这一用户配置文件、且不覆盖 Outlook 附件、OneDrive 同步客户端、本地邮件客户端、打印到 PDF、截图与手工录入等大量其它路径。

按错误判据写「数据未外传」，等于用单一工件的有限覆盖替全部外传通道背书；而正确写法「未发现外传痕迹，已核查跳转列表全量条目、内存网络连接与文件句柄」把结论的适用范围显式收窄，反而更有说服力，也经得起复核。

第二处易错点是把内存镜像当成可以回溯历史的证据来源。

正确判据是内存是**单一时刻的状态快照**，不保留历史；本次采集发生在 2024-11-01 16:52，只能证明该时刻的进程与连接状态，对 11-03 新员工入职之后的任何行为、乃至事发当日之外的时间段都不提供任何信息。

按错误判据用内存去「验证」跳转列表中的历史条目，会出现把 16:52 的运行态与 10-28 的历史访问混为一谈的情况；两者只能并列陈述，不能互为印证。

第三处易错点是看到内存中 `EXCEL.EXE` 正在运行就写「用户在事发时正在编辑该文件」。

正确判据是内存只能证明 PID 4488 的 Excel 进程在采集时刻存活，无法确定它打开了哪个文档——文档信息在 Jump List 与内存中虽可能都有，但本案的解析只确认了进程存在；且采集时刻距跳转列表最新条目已过 11 分钟，期间用户完全可能关闭了该文档。

按错误判据把「进程在运行」等同于「正在处理该文件」，会凭空生成一个并不存在的「编辑中」情节，在需要精确刻画行为状态的争议中极易被推翻。

---
<a id="section-33"></a>

## 六、扩展阅读方向

<a id="section-34"></a>

### 前置基础：解析与归属的前提

- [注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md) —— LNK 与 Jump List 都在用户配置文件下，归属错了整套结论就错了，用户与 SID 判定在这一篇。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— LNK 固定头里的三个目标时间戳的纪元与换算。
- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— **卷序列号的来源是卷的元数据**，理解它才能解释「同一个序列号出现在成千上万个 LNK 里」意味着什么。
- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— Recent 与 AppData 目录的检索前提。

<a id="section-35"></a>

### 同层深入：同属「用户行为」的其它工件

- [Prefetch 深度解析](computer-execution-prefetch.md) —— **执行侧的第一顺位**。Prefetch 说「程序启动过」，LNK 说「用户打开了哪个文档」，两者缺一行为链条就不完整。
- [ShimCache 与 Amcache](computer-execution-shimcache-amcache.md) —— 另外两个执行侧工件，**同样能推出「哪个程序被启动过」**。
- [用户行为痕迹](../computer-registry-log/computer-registry-log-user-activity-artifacts.md) —— **同板块的邻近工件**。UserAssist、TypedPaths、Shellbags 回答的是「这个用户在操作系统里做过什么」，LNK 回答的是「这个用户打开过什么文件」。
- [浏览器取证](../computer-browser-behavior/computer-browser-behavior-browser-forensics.md) —— `CustomDestinations` 里可能含浏览器搜索词，**浏览器侧的完整记录在这里**。

<a id="section-36"></a>

### 相邻议题：文件本体与时间线

- [UsnJrnl 与文件操作时间线](computer-execution-usn-journal-timeline.md) —— LNK 记录创建时的快照，USN 记录文件被改了什么。两者时间线并排，能看出「打开在先、修改在后」还是相反。
- [Steady-State 与 LogFile 还原](../../filesystem/filesystem-ntfs/filesystem-ntfs-steady-state-logfile.md) —— NTFS 事务日志。它能解释「文件被删了但 LNK 还在」这个状态是怎么形成的。
- [取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— 卷影副本的存在与否，**决定了 LNK 记录的文件是否还有机会恢复本体**。

<a id="section-37"></a>

### 工具与规范：解析与保全

- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— Jump List 与 LNK 的归档封装。
- [远程勘验与在线取证](../../imaging/imaging-acquire/imaging-acquire-remote-evidence-collection.md) —— Recent 目录的时间戳可能受挂载行为影响，在线采集与离线分析的结果不一定相同。

<a id="section-38"></a>

### 判据与反例：哪些匹配不能当结论

- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— **「同一卷序列号」是强关联但不是身份证明**：卷被复制、克隆盘、虚拟机模板都会产生相同序列号，**这一点必须写进报告的限定条件**。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— LNK 内的三个时间戳是目标文件的 mtime，**可被 `touch` 改动**；判读时不能把它当作不可篡改的证据。
<a id="section-39"></a>

## 七、命令速查

```bash
# 1) 确认卷偏移与系统卷
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 2) 列出所有用户配置（Recent 目录都在用户目录下）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -Ei '/Users/[^/]+/(NTUSER\.DAT|Recent)'

# 3) 批量提取 .lnk（inode 在第 2 列，不是第 3 列）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -Ei '/Users/jsmith/AppData/Roaming/Microsoft/Windows/Recent/.*\.lnk$' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/users/jsmith/Recent/$(printf '%s.lnk' "${ino%%:*}")"
    done

# 4) 确认魔数与 HeaderSize
xxd -l 20 /evidence/Recent/sample.lnk

# 5) 解析 TrackerDataBlock（务必校验 BlockSize=0x60）
python3 - sample.lnk <<'PY'
import struct, sys, uuid
d = open(sys.argv[1], 'rb').read()
i = d.find(struct.pack('<I', 0xA0000003))
if i < 4 or struct.unpack_from('<I', d, i - 4)[0] != 0x60:
    print('no valid TrackerDataBlock'); sys.exit(1)
b = i - 4
print('MachineID :', d[b+16:b+32].split(b'\x00')[0].decode('ascii','replace'))
for name, off in (('Droid     ', 0x20), ('DroidBirth', 0x40)):
    fil = uuid.UUID(bytes_le=d[b+off+16:b+off+32])
    print(name, 'mac=', ':'.join(f'{x:02X}' for x in fil.bytes_le[10:16]))
PY

# 6) 统计 LNK 中出现过的卷序列号（列序以实际 CSV 表头为准）
cut -d, -f5 /evidence/out/lnk.csv | tr -d '"' | sort | uniq -c | sort -rn | head
```

```powershell
# ===== 批量解析 =====
LECmd.exe -d "C:\evidence\users\jsmith\Recent" -r `
  --csv "C:\evidence\out\lnk" --csvf "lnk.csv" `
  --json "C:\evidence\out\lnk_json" --pretty -q

# ===== Jump List =====
JLECmd.exe -d "C:\evidence\users\jsmith\Recent\AutomaticDestinations" `
  --csv "C:\evidence\out\jl" --csvf "autodest.csv" --json "C:\evidence\out\jl_json" --pretty -q
JLECmd.exe -d "C:\evidence\users\jsmith\Recent" --mp `
  --dt "yyyy-MM-dd HH:mm:ss.fff" --csv "C:\evidence\out\jl_all"
JLECmd.exe -d "C:\evidence\users\jsmith\Recent\AutomaticDestinations" `
  --dumpTo "C:\evidence\out\jl_lnk" -q
LECmd.exe -d "C:\evidence\out\jl_lnk" --all `
  --csv "C:\evidence\out\lnk_from_jl" --csvf "from_jl.csv"
JLECmd.exe -f "C:\evidence\...\1b4dd67f29cb1962.automaticDestinations-ms" --fd -q

# ===== 交叉验证 =====
PECmd.exe -d "C:\evidence\Prefetch" --csv "C:\evidence\out\pf" --csvf "pf.csv"
Get-WinEvent -Path "C:\evidence\Logs\System.evtx" `
  -FilterHashtable @{LogName='System'; Id=20001,20003} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,@{n='Msg';e={$_.Message -replace "`r`n",' '}}
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — LNK 快捷方式与 Jump List 跳转列表」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《LNK 快捷方式与 Jump List 跳转列表》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
