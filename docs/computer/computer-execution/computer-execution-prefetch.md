---
title: "Prefetch 深度解析"
slug: "computer-execution-prefetch"
canonical: "https://www.digiforensics.cn/wiki/computer-execution-prefetch"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["执行痕迹"]
---

# Prefetch 深度解析

<a id="section-1"></a>

## 一、概述

Windows 取证里最容易被误读的执行证据，就是 Prefetch。

系统为加快程序启动而记录每个可执行文件的上次运行时间与运行次数，这些记录以独立的 `.pf` 二进制文件存放在 `C:\Windows\Prefetch\`，不在事件日志里，不随日志轮转消失，也不容易被普通用户察觉。「某个可疑程序到底跑没跑过」——这个问题上它往往是第一顺位答案。

三个特性决定了它极易被误判：

1. **它是缓存，不是审计日志。** 系统追求「启动快」，**不为「记录全」服务**。
2. **它有六个格式版本，且带压缩层。** 从 XP 到 Windows 11 跨越 v17 到 v31，Windows 8.1 之后还额外套了一层 MAM 压缩。
3. **它可能完全不存在。** 被显式关闭时目录为空或不存在；被清理后也会留下痕迹。

方法论只有一句：「Prefetch 里有」≠「全部执行记录」，「Prefetch 里没有」≠「没执行过」。 两个方向都会出错，而第二个方向在实战中更常导致错误结论。

它处于**分析**环节的最前端之一——**执行事实是后续所有排查的收敛条件**：

- **上游依赖**两件事。**第一步必须确认 Prefetch 状态**（`EnablePrefetcher` 的四个取值决定了目录里有没有东西），这属于卷与工件准备，见[Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md)；Windows 版本判定决定了用哪个解析器，用某一版本的固定偏移去读另一版本会得到看似合理实则完全错误的数据。
- **它自己**要按顺序做三件事：**先看偏移 0 的魔数再选解析器**（`0x11` / `0x17` / `0x1A` / `0x1E` / `0x1F` 或 `MAM\x04`）；**再确认是否需要解压**；**最后才读字段**。
- **下游支撑** 三处。执行时间进入时间线（FILETIME 精确到 100 纳秒，是少数高精度时间源）；执行路径是持久化排查的入口（**「这个程序从哪路径启动」直接指向可执行文件来源**）；[ShimCache 与 Amcache](computer-execution-shimcache-amcache.md)是交叉验证的同伴，**三者的可信度各不相同**。

落到具体格式上：

| 魔数（偏移 0） | 含义 | 对应系统 |
|---|---|---|
| `0x11` | v17，未压缩 | Windows XP / 2003 |
| `0x17` | v23，未压缩 | Windows Vista / 7 |
| `0x1A` | v26，未压缩 | Windows 8 / 8.1 |
| `0x1E` | v30，未压缩 | Windows 10，以及早期 Windows 11 |
| `0x1F` | v31，未压缩 | 较新的 Windows 11 构建 |
| `4D 41 4D 04`（`MAM\x04`） | **MAM 压缩封装，解压后才是上述结构** | Windows 8.1 起 |
| 落点 | `C:\Windows\Prefetch\*.pf` | 文件名是程序名的清洗形式，含 ADS 执行时的特殊形式 |
| 签名 | 未压缩文件偏移 4 处为 ASCII `SCCA` | 判别格式是否正常 |
| 关键字段 | 执行时间槽（最多 8 个）、`Run Count`、引用路径数组 | **各版本偏移完全不同** |
| 开关 | 注册表 `EnablePrefetcher`（四个取值） | 决定目录里有没有内容 |

三条规律见 2.2：偏移 0 的魔数决定选哪个解析器；偏移 0 不是已知魔数但偏移 4 冒出 `SCCA` 的格式仍然正常，别急着判损坏；MAM 封装用文本编辑器打开是一片乱码，那是封装本来的样子。漏掉任何一条，后面读出来的字段都会是错的，而且错得很像真的。

证明力按维度分是这样的（逐条判读见 2.6 与 4.3）：

| 维度 | 证明力 | 说明 |
|---|---|---|
| 程序被启动过 | 强 | 核心价值 |
| 执行的完整路径 | 强 | 在文件内容的路径字符串中 |
| 执行次数 | 中 | `Run Count` 精确；时间戳只有最近 8 次 |
| 执行的具体时间 | 强 | FILETIME，精确到 100 纳秒 |
| 执行是否成功 | **不能证明** | 启动即崩溃、缺 DLL、被杀都会留记录 |
| 谁执行的 | 弱 | **不带用户名**，需与事件日志、用户目录交叉 |
| 程序是否恶意 | **零** | 中性的执行事实，定性需哈希查库与行为证据 |

外加三个必须写进报告的语义边界：

- Windows 8 之后每个程序最多保存 8 个最近运行时间戳，第 9 次执行覆盖最旧槽位。当 `Run Count` 大于 8 时，绝不能写「只运行了 8 次」；反之当 `Run Count` 小于 8 时全部执行时间可见，此时次数是精确的。
- Prefetch 证明「发生了启动」，不证明「完成了操作」。 报告里写「该恶意程序被执行」是危险推断，正确写法是「该路径下的可执行文件被启动，时间为 X，累计 N 次」。
- **ADS 执行会产生特殊文件名**，若不知道这个规则，解析器可能报出无法归一的文件名。

本章依赖的前置知识：NTFS 的元数据与 MFT 概念，**Prefetch 文件的读取依赖正确的卷接入**，见[NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md)；FILETIME 的纪元与 100 纳秒精度，这是时间字段的基础，见[时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md)；注册表的读取方式，`EnablePrefetcher` 是判断 Prefetch 是否存在的前提，见[注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md)；十六进制查看器的用法，**判断魔数与签名这一步不能跳过**；以及 MAM 压缩的封装结构，**否则会把正常格式误判为文件损坏**。
<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 Prefetch 解决什么问题

Windows 启动时要把待加载的 DLL 从磁盘读入并重新安排内存布局，这很慢。

Prefetch 的思路是**把上次启动时加载了什么记下来，下次照做**，省掉重复计算。

为此系统为每个可执行文件建立**一个独立的 `.pf` 文件**，而不是一个集中的数据库——这是为了快速随机访问。

| 特性 | 说明 |
| --- | --- |
| 位置 | `C:\Windows\Prefetch\*.pf`（系统卷所在卷） |
| 文件名 | `<程序名>-<路径哈希>.pf`，如 `NOTEPAD.EXE-1A2B3C4D.pf` |
| 写入时机 | 程序启动后由内存管理器的 Prefetcher 组件写入 |
| 记录内容 | 运行时间戳、运行次数、引用的文件列表、卷信息、目录字符串 |
| 目录容量 | XP 至 Windows 8 为 128 项；Windows 10 及以后为 1024 项 |
| **不是** | 审计日志、用户行为记录、成功/失败判定 |

路径哈希的作用是**去重**：同名程序从不同路径执行会生成不同哈希、不同 `.pf` 文件。

因此**不能只按程序名去查**，必须确认路径哈希是否匹配。

<a id="section-4"></a>

### 2.2 格式版本与魔数判别

这是动手前必须掌握的一张表。**先看魔数，再选解析器**：

| 魔数（偏移 0） | 含义 | 对应系统 |
| --- | --- | --- |
| `0x11` | v17，未压缩 | Windows XP / 2003 |
| `0x17` | v23，未压缩 | Windows Vista / 7 |
| `0x1A` | v26，未压缩 | Windows 8 / 8.1 |
| `0x1E` | v30，未压缩 | Windows 10，以及早期 Windows 11 |
| `0x1F` | v31，未压缩 | 较新的 Windows 11 构建 |
| `4D 41 4D 04`（`MAM\x04`） | **MAM 压缩封装**，解压后才是上述结构 | Windows 8.1 起 |

两条规律：

- 未压缩文件的偏移 4 处是 ASCII `SCCA` 签名。若偏移 0 不是已知魔数而偏移 4 出现 `SCCA`，格式正常。
- Windows 8.1 及以后普遍使用 MAM 封装（Microsoft XPRESS Huffman / LZXPRESS 压缩）。此时用文本编辑器或十六进制查看器打开显示为乱码是**正常格式，不是文件损坏**。必须先解压再解析。

不同版本中，文件信息区各字段（执行时间、计数器、路径数组）的**偏移完全不同**，用某一版本的固定偏移去读另一版本会得到看似合理实则完全错误的数据（判读见 4.1 陷阱 3）。

<a id="section-5"></a>

### 2.3 陷阱一：8 槽环形覆盖

这是 Prefetch 最重要的语义。

Windows 8 之后，Prefetch 为每个程序保存**最多 8 个最近运行时间戳**。第 9 次执行时，最旧的槽位被新的覆盖。因此：

| 字段 | 语义 | 正确表述 |
| --- | --- | --- |
| `Run Count` | **累计执行次数**计数器，不受槽位限制 | 「累计 N 次」 |
| 8 个时间槽 | **仅最近 8 次**的时间 | 「最近 8 次为……」 |

由此推出报告中的关键纪律：

- 次数**必须用 `Run Count`**，不能用时间戳个数；
- 时间**只能说最近 8 次**，更早的时间**不可知**；
- 当 `Run Count` 大于 8 时，绝不能写「只运行了 8 次」；
- 反之，当 `Run Count` 小于 8 时，全部执行时间都可见，此时次数是精确的。

<a id="section-6"></a>

### 2.4 陷阱二：EnablePrefetcher 的四个取值

Prefetch 可被显式关闭，配置位于：

```text
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
    EnablePrefetcher  (REG_DWORD)
```

| 值 | 含义 |
| --- | --- |
| `0` | **完全禁用** |
| `1` | 仅启用应用程序启动预取 |
| `2` | 仅启用启动（Boot）预取 |
| `3` | **应用程序启动预取 + 启动预取（桌面版默认值）** |

**这是一个极易出错的地方**：看到 `EnablePrefetcher = 2` 就写「Prefetch 已启用」是**错的**——`2` 表示**只有**启动预取，**不包含**应用程序启动预取，**恰恰意味着程序执行痕迹不会被记录**。只有 `1` 或 `3` 才包含应用预取，桌面版默认是 `3`；`> 3` 的值不会带来额外收益。

活体系统上可直接查询，离线检材需从 `SYSTEM` hive 的**当前** ControlSet 中读取：

```bash
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher
```

离线时常见的错误是读了 `ControlSet001` 却不知道当前是哪个 ControlSet——应先查 `Select\Current` 确认。

<a id="section-7"></a>

### 2.5 陷阱三：ADS 执行产生的特殊文件名

当程序通过 NTFS **备用数据流（ADS）**执行时，Prefetch 文件名不再是常规的 `程序名-哈希.pf`，而会出现**冒号分隔的形态**：

```text
notepad.exe:evil.pf
└── 主数据流 ──┘ └─ ADS 名称 ─┘
                （主数据流名保留，冒号后是数据流名）
```

`fls` 对这类条目的呈现形式与普通文件的 `名称-地址-序列` 模式不同，且**不同工具的显示方式不一致**。因此：不要假设冒号一定在「程序名与哈希之间」，有的工具把主数据流名与数据流名一起显示，有的会截断或转义，必须用 `fls` 原始输出与 `istat` 交叉确认；也不要只用 `*.pf` 结尾过滤，有的实现把 `.pf` 放在数据流名上（如上例），有的放在主名上，**只按后缀过滤必然漏项**。正确做法是枚举 Prefetch 目录时**保留含冒号的完整条目**，再用 `istat` 确认其是否为 ADS 形式，并与 NTFS 的 ADS 列表交叉验证。

发现形如 `程序名.exe:流名` 的条目，是**存在 ADS 执行行为的强指示**——这类执行常用于载荷隐藏，正常业务软件极少这样启动。

<a id="section-8"></a>

### 2.6 Prefetch 的证明力边界

七个维度的证明力评级见概述一节的表。边界上最需要防住的是「启动了」被读成「做完了」：

> Prefetch 证明「发生了启动」，不证明「完成了操作」。

报告里写「该恶意程序被执行」是危险推断；正确写法是「该路径下的可执行文件被启动，时间为 X，累计 N 次」。

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 确认 Prefetch 状态（必做第一步）

这一步的结论决定后续所有分析是否有意义。离线检材从 `SYSTEM` hive 读取：

```bash
# 提取 SYSTEM hive
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'config/SYSTEM$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do icat -o 2048 /work/DigiForensics.dd "$ino" > /evidence/hives/SYSTEM; done

# 先确认当前 ControlSet，再读 PrefetchParameters
rip.exe -p /evidence/hives/SYSTEM -a select.txt select
# \Select\Current : 1        ← 当前是 ControlSet001

rip.exe -p /evidence/hives/SYSTEM -a pf.txt prefetchparameters
# ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
#   EnablePrefetcher = 3     ← 应用+启动预取全启用
```

判定规则：`0` → Prefetch 路线不可用，不得做否定性结论；`1` 或 `3` → 可正常依赖；`2` → **只有启动预取，应用执行痕迹不会记录**。

<a id="section-11"></a>

### 3.2 枚举并提取

```bash
# 枚举 Prefetch 目录，保留完整文件名（含冒号）
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E '/Windows/Prefetch/' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/prefetch/$(printf '%s' "${ino%%:*}").pf"
    done

# 保留原始文件名列表（含 ADS 冒号形式）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E '/Windows/Prefetch/' > /evidence/prefetch/names.txt
```

**不要只用 `*.pf` 过滤**——那会漏掉 ADS 形态的文件。同时记录每个文件的 MFT 时间戳，用于判断「很久没运行」还是「近期被批量清理过」。

<a id="section-12"></a>

### 3.3 判定格式版本

抽一个文件看魔数，再决定用哪种解析路径：

```bash
xxd -l 4 /evidence/prefetch/sample.pf
# 4D 41 4D 04    ← "MAM\x04"，MAM 压缩封装，必须先解压
# 或 1E 00 00 00  ← v30，未压缩，可直接按 v30 布局解析
```

统计全目录的版本分布，判断检材是否混版：

```bash
for f in /evidence/prefetch/*.pf; do
  printf "%-40s %s\
" "$(basename "$f")" "$(xxd -l 4 -p "$f")"
done | sort -k2 | uniq -c -f1 | sort -rn
```

<a id="section-13"></a>

### 3.4 解析

`PECmd` 会自动处理 MAM 解压，按版本选择解析布局：

```bash
# 解析整个目录，输出 CSV
PECmd.exe -d "C:\evidence\prefetch" --csv "C:\evidence\out" --csvf "pf.csv"

# 解析单个文件并输出时间线
PECmd.exe -f "C:\evidence\prefetch\SUSPICIOUS.EXE-4A5B6C7D.pf" --mp --dt "yyyy-MM-dd HH:mm:ss"
```

输出列应包含：程序名、`Run Count`、`Last Run Time`、`Previous Run Times`（v26+ 有多个时间槽）、完整路径、引用文件数、卷信息。

<a id="section-14"></a>

### 3.5 交叉验证

Prefetch **不带用户名**，且不说明执行结果，必须交叉：

- **LNK / Jump List**：确认是否 GUI 方式打开，以及打开的具体文件。
- **事件日志 4624**：确认案发时段有对应账户的登录会话。
- **Amcache**：提供 SHA-1 哈希与 PE 编译时间，可与 Prefetch 的首次执行时间互证。
- **`$UsnJrnl`**：确认可执行文件本身何时被创建或写入。
- SYSTEM hive 的 `ShutdownTime`：确认最后一次正常关机，判断断电影响的范围。
<a id="section-15"></a>

## 四、常见陷阱

<a id="section-16"></a>

### 4.1 采集前置与格式判别

<a id="section-17"></a>

#### 陷阱 1：跳过 `EnablePrefetcher` 判定，把"没找到 .pf"写成"没执行过"

**现象**

在镜像里 `C:\Windows\Prefetch\` 下没找到目标程序对应的 `.pf` 文件，报告写下「该程序在此期间未被执行」。分析全程没有读过 `SYSTEM` hive。

**原因**

**Prefetch 可以被显式关闭，配置在**（键路径与四值含义见 2.4）：

```text
ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
    EnablePrefetcher
```

四个取值的含义是本篇最容易搞错的地方：

| 取值 | 含义 | 能否作为执行证据 |
| --- | --- | --- |
| `0` | **完全禁用** | **不可用，不得做否定性结论** |
| `1` | 仅启用应用程序启动预取 | 可用 |
| `2` | 仅启用启动（Boot）预取 | **应用执行痕迹不会记录** |
| `3` | 应用程序启动预取 + 启动预取（**桌面版默认**） | 可用 |

注意取值不是单调递增的：`2` 是「仅启动预取」，而很多资料把 `1` 与 `2` 的含义互换了。

含应用预取的是 `1` 与 `3`；`2` 意味着程序执行痕迹不会记录。

所以"没找到 `.pf`"至少有四种成因，而**只有一种是"确实没执行"**：

| 成因 | 正确表述 |
| --- | --- |
| `EnablePrefetcher` = 0 或 2 | 「Prefetch 未记录应用执行，**本工件不适用**，不得据此做否定性结论」 |
| 被显式清理过 | 「未见对应 `.pf`；需结合目录 MFT 时间与容量判断是否存在批量清理」 |
| 程序名超长被截断或路径哈希未命中 | 「按该程序名与路径哈希未命中，**未能定位**」 |
| 确实未执行 | 「在 Prefetch 正常记录的前提下，未见执行记录」 |

四条成因的正确表述见上表。取值与「应用执行是否被记录」只有两条硬约束：`0` 完全禁用；`2` 只记启动项、不记应用。`1` 与 `3` 记录应用执行。

**影响**

- **这是最常见的错误结论来源之一**，方向性也最糟：用一个「本就不会记录」的机制去证明「没有发生」
- 委托方据此排除嫌疑，而结论建立在错误前提上
- 后续发现该程序确实执行过（由 Amcache、LNK、日志证明），报告可信度受损

**核查**

`EnablePrefetcher` 判定是必做的第一步，结论决定后续所有分析是否有意义：

```bash
rip.exe -p /evidence/hives/SYSTEM -a select.txt select
# \Select\Current : 1     ← 先确认当前 ControlSet，编号会变

rip.exe -p /evidence/hives/SYSTEM -a pf.txt prefetchparameters
# ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
#   EnablePrefetcher = 3
```

报告里必须先落这个前提：

> `SYSTEM` hive 中 `Select\Current` 为 1，`ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` = `3`，表示应用启动预取已启用，**Prefetch 可作为程序执行证据使用**。若该值为 `0` 或 `2`，本报告所有基于 Prefetch 的阴性结论均不成立。

<a id="section-18"></a>

#### 陷阱 2：把 `MAM\x04` 开头判为"文件损坏"

**现象**

用十六进制查看器打开 Windows 10/11 的 `.pf`，看到开头是 `4D 41 4D 04` 而不是已知的魔数，判定「该文件损坏或被篡改」。用文本编辑器打开看到乱码，也报「格式非法」。

**原因**

`4D 41 4D 04`（ASCII `MAM\x04`）是正常的压缩封装头，不是损坏。

完整判别表：

| 魔数（偏移 0） | 含义 | 对应系统 |
| --- | --- | --- |
| `0x11` | v17，未压缩 | Windows XP / 2003 |
| `0x17` | v23，未压缩 | Windows Vista / 7 |
| `0x1A` | v26，未压缩 | Windows 8 / 8.1 |
| `0x1E` | v30，未压缩 | Windows 10，以及早期 Windows 11 |
| `0x1F` | v31，未压缩 | 较新的 Windows 11 构建 |
| `4D 41 4D 04`（`MAM\x04`） | **MAM 压缩封装**，解压后才是上述结构 | **Windows 8.1 起** |

两条规律：

- 未压缩文件的偏移 4 处是 ASCII `SCCA` 签名。 偏移 0 不是已知魔数、偏移 4 却是 `SCCA`，格式正常
- Windows 8.1 及以后普遍使用 MAM 封装（Microsoft XPRESS Huffman / LZXPRESS 压缩），用文本或十六进制查看器打开显示乱码是**正常格式**

**影响**

- 把正常格式判为损坏，会导致这些文件被排除在分析之外 —— 而 Windows 10/11 的绝大多数 Prefetch 都是 MAM 封装，等于把主体证据全丢掉
- 若报告里写「Prefetch 文件损坏」，委托方会怀疑镜像获取过程有问题

**核查**

**先看魔数再选解析路径，用支持自动解压的解析器**：

```bash
# 抽一个查魔数
xxd -l 4 /evidence/prefetch/sample.pf
# 4D 41 4D 04   ← MAM 压缩封装，先解压再解析
# 1E 00 00 00   ← v30，未压缩，可直接按 v30 布局解析

# 未压缩文件可用 SCCA 签名二次确认
xxd -s 4 -l 4 /evidence/prefetch/sample.pf   # 期望看到 53 43 43 41 = "SCCA"

# 统计全目录版本分布，判断是否混版
for f in /evidence/prefetch/*.pf; do
  printf "%-40s %s\
" "$(basename "$f")" "$(xxd -l 4 -p "$f")"
done | sort -k2 | uniq -c -f1 | sort -rn

# PECmd 会自动处理 MAM 解压
PECmd.exe -d "C:\evidence\prefetch" --csv "C:\evidence\out" --csvf "pf.csv"
```

<a id="section-19"></a>

#### 陷阱 3：用错版本的固定偏移，得到"看似合理实则全错"的数据

**现象**

用一份 v23（Windows 7）的偏移表去读 v30（Windows 10）的文件，没有报任何错，输出了运行次数 7、次运行时间 2024-11-14、执行路径 `C:\Windows\System32\cmd.exe`。所有值都「看起来合理」，直接进了报告。

**原因**

**各版本的字段偏移完全不同，且同一版本内还有变体。**

v17 / v23 / v26 / v30 / v31 之间的差异不只是大小端或字段顺序，文件信息区的结构本身就不同。

这造成一个特别危险的失败模式：**用错偏移通常不会触发错误，只会产出错误的数字。**

时间、次数、路径这些字段都是「有意义的形状」，随便读几个偏移就能拼出一个看起来能自圆其说的结果。

判断依据只能来自格式本身：**先看魔数确定版本，再选对应版本的布局。**

**影响**

- 错误数据一旦进入报告就很难被发现，因为它们「看起来正常」
- 次数与时间错误会直接破坏整条时间线，且与其他工件对不上时容易被误认为其他工件出错
- 这类错误无法自证，质证时无法解释数据来源

**核查**

**版本决定布局，解析器负责适配**：

```bash
# 单文件解析时显式确认版本，不要套用别处的偏移
xxd -l 4 /evidence/prefetch/SUSPICIOUS.EXE-4A5B6C7D.pf
# → 1E 00 00 00  即 v30

# 交给自动适配的解析器
PECmd.exe -f "C:\evidence\prefetch\SUSPICIOUS.EXE-4A5B6C7D.pf" \
          --mp --dt "yyyy-MM-dd HH:mm:ss"
```

**自查手段**：把同一条记录与独立工件对照 —— `Amcache` 的 `First Run` 时间应与 Prefetch 最早时间戳一致，事件日志中也应有对应时段的记录。

**对不上时先怀疑自己的解析，而不是怀疑其他工件。**

<a id="section-20"></a>

### 4.2 语义判读

<a id="section-21"></a>

#### 陷阱 4：把"8 个时间戳"当成"只运行过 8 次"

**现象**

Prefetch 里有 `CMD.EXE` 的 8 个时间槽，报告写「`cmd.exe` 于 2024-11-14 运行了 8 次」，并把它作为「该程序只在案发时段被少量使用」的依据。

**原因**

Windows 8 之后，Prefetch 为每个程序保存最多 8 个最近运行时间戳。

第 9 次执行时，最旧的槽位被新的覆盖。

| 字段 | 语义 | 正确表述 |
| --- | --- | --- |
| `Run Count` | **累计执行次数**计数器，**不受槽位限制** | 「累计 N 次」 |
| 8 个时间槽 | **仅最近 8 次**的时间 | 「最近 8 次为……」 |

这个陷阱有两个方向，**第二方向的错误更隐蔽**：

| 情况 | 正确判定 |
| --- | --- |
| `Run Count > 8` | **绝不能写「只运行了 8 次」**，更早的次数不可知 |
| **`Run Count < 8`** | 全部执行时间都可见，**此时次数是精确的** |

`suspicious.exe` 的 `Run Count = 3` 小于 8，所以那 3 次执行时间全部可见、次数精确；而 `CMD.EXE` 的 `Run Count = 127` 但只有 8 个槽位，**更早的 119 次执行时间已永久不可知**。

**影响**

- 把高频程序说成「只用了 8 次」，会误导对自动化行为的判断（脚本类程序执行上百次很常见）
- 反向也会出错：对 `Run Count < 8` 的程序不敢说精确次数，白白放弃了可得的精确结论
- 更根本的是，在 `Run Count > 8` 时**任何「总共运行了 N 次」的表述都是无依据的**

**核查**

次数用 `Run Count`，时间只说最近 8 次，两者在报告中分开表述：

```bash
# 解析输出包含 Run Count 与 Previous Run Times（v26+）
PECmd.exe -d "C:\evidence\prefetch" --csv "C:\evidence\out" --csvf "pf.csv"
```

| 读到的值 | 报告表述 |
| --- | --- |
| `Run Count = 3`，3 个时间戳 | 「累计执行 3 次，3 次执行时间均可见：…」 |
| `Run Count = 127`，8 个时间戳 | 「**累计执行 127 次**，最近 8 次时间为…，**更早 119 次的执行时间已不可知**（8 槽覆盖）」 |

<a id="section-22"></a>

#### 陷阱 5：只用 `*.pf` 过滤，漏掉 ADS 形态的执行记录

**现象**

用 `fls` 输出按 `*.pf` 后缀过滤，得到 1023 个文件，报告写「Prefetch 目录共 1023 个条目」。而其中一条实际是 `NOTEPAD.EXE:E4V1L.PF`（备用数据流形态），被过滤掉了。

**原因**

ADS（Alternate Data Stream，备用数据流）形态的执行文件名形如：

```text
notepad.exe:evil.pf
```

**流名部分决定扩展名。**

这类记录在 NTFS 上是完全合法的 `.pf` 文件，位置同样在 `C:\Windows\Prefetch\` 下，但：

- 文件名**含有冒号**，不是普通的 `<程序名>-<路径哈希>.pf` 形式
- `*.pf` 这类通配过滤会把它排除
- 它记录的**路径哈希可能与同名普通记录不同**，指向不同的执行路径

ADS 执行是一种**已知的技术对抗手法** —— 把程序藏在 ADS 里执行，可以让普通目录列表看不到。

**影响**

- 漏掉 ADS 执行记录，而这恰恰是最需要关注的一类
- 目录计数不准（如声称 1023 而实际 1024），影响完整性声明
- 若报告明确说「已枚举全部 Prefetch 条目」，这个声明就不成立

**核查**

枚举时保留完整文件名，不用扩展名过滤，并单独标注 ADS 形态：

```bash
# 保留完整文件名（含冒号），不做扩展名过滤
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E '/Windows/Prefetch/' \
  | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" \
        > "/evidence/prefetch/$(printf '%s' "${ino%%:*}").pf"
    done

# 原始文件名列表单独留存
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E '/Windows/Prefetch/' > /evidence/prefetch/names.txt

# 单独筛出 ADS 形态条目
grep ':' /evidence/prefetch/names.txt
```

报告必须写明：

> 枚举 `C:\Windows\Prefetch\` 共 N 个条目（含备用数据流形态）。其中 M 条为 ADS 形态（如 `NOTEPAD.EXE:E4V1L.PF`），已单独列出并解析。 未发现 ADS 形态 / 发现 ADS 形态 X 条，指向路径 `…`。

<a id="section-23"></a>

### 4.3 结论表述与交叉验证

<a id="section-24"></a>

#### 陷阱 6：把 Prefetch 时间当作文件创建时间

**现象**

`SUSPICIOUS.EXE` 的 Prefetch 首个时间戳是 2024-11-14 21:30:44，报告写「该可疑程序于 21:30:44 被创建并投放到 Temp 目录」。

**原因**

Prefetch 记录的是执行时间，不是文件创建时间。

两者的关系是：

- 程序**已经存在** → 被启动 → Prefetcher 写入记录
- 编译期/投放期的文件创建时间看 MFT `$STANDARD_INFORMATION`（`$SI`）
- `Amcache` 的 `First Run` 可以与 Prefetch 最早时间戳互相印证

把它们混为一谈会让投放时间被推后到执行时间，中间的**准备期窗口整个消失**。

而准备期往往正是反取证动作（清理痕迹、下载工具）发生的时间。

**影响**

- 漏掉准备期 —— 这一段恰恰是攻击链早期最值得查的部分
- 时间线错位，攻击者实际操作时间与「程序出现时间」重合，无法解释中间间隔
- `Amcache` 与 Prefetch 对不上时，容易误认为其中一个工件有问题

**核查**

**三个时间源分别取，互不代用**：

```bash
# 文件创建/修改时间：MFT $SI
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -iE 'suspicious\.exe$'

# Prefetch 最早执行时间
PECmd.exe -f "C:\evidence\prefetch\SUSPICIOUS.EXE-4A5B6C7D.pf" --mp

# Amcache 的 First Run
python3 - <<'PY'
import csv
for r in csv.DictReader(open(r'C:\evidence\out\amcache.csv', encoding='utf-8', errors='replace')):
    if 'suspicious' in str(r).lower():
        print(r)
PY
```

三者关系应自洽：

| 时间 | 来源 | 语义 |
| --- | --- | --- |
| 文件投放 | MFT `$SI` 创建时间 | 程序**出现在磁盘上** |
| 首次执行 | Prefetch 最早时间槽 / Amcache `First Run` | 程序**被启动** |
| 案发时段执行 | Prefetch 最近时间槽 | 案件相关执行 |

**报告表述**：「该可执行文件创建于 `T0`（MFT `$SI`），首次执行于 `T1`（Prefetch 最早槽位，与 Amcache `First Run` 独立印证），案发时段内执行于 `T2`/`T3`/`T4`。`T1` 与 `T0` 之间为准备期，该区间应单独追查其他痕迹。」

<a id="section-25"></a>

#### 陷阱 7：把"被启动"当作"执行成功"或"操作完成"

**现象**

Prefetch 里有记录，报告写「该恶意程序被执行并完成了数据外泄」。而实际上该程序启动后即因缺依赖崩溃，或被安全软件终止。

**原因**

Prefetch 的写入时机是「程序启动后由内存管理器的 Prefetcher 组件写入」，它记录的是启动尝试，不是执行结果。

启动即崩溃、缺依赖、架构不匹配、被杀、被拦，都一样会留下记录。

Prefetch 的证据能力边界：

| 命题 | Prefetch 能否证明 |
| --- | --- |
| 该路径下的可执行文件**被启动** | **能** |
| 启动**成功**完成初始化 | **不能** |
| 程序**执行了某项操作** | **不能** |
| 程序是否**恶意** | **不能，零信息** |

所以「该恶意程序被执行」这个表述本身就有两个问题：它暗示了「完成了操作」，而且「恶意」是定性判断，Prefetch 不提供任何依据。

**影响**

- 「被启动」与「完成了外泄」之间隔着整个程序逻辑，报告却把它们连成一句
- 「恶意」定性没有依据，一旦被质证「你凭什么说它恶意」，后面所有基于它的推论都受影响
- 崩溃/被拦截的样本也会被写成「运行成功」，与实际不符

**核查**

分三档表述，每档只声称 Prefetch 能支撑的那一层：

```bash
# 需要"执行成功"的证据：程序是否落地了输出文件
fls -o 2048 -r -p /work/DigiForensics.dd | grep -iE 'suspicious.*\.(log|txt|dat)$'

# 需要"执行了某操作"的证据：子进程、网络连接、写入痕迹
grep -iE 'suspicious' /evidence/out/pf.csv        # Prefetch 引用的文件列表
# 交叉：事件日志、$UsnJrnl、SRUM
```

报告标准表述：

> Prefetch 记录 `C:\Users\admin\AppData\Local\Temp\suspicious.exe` 被启动，3 次执行时间为 21:30:44、21:52:10、22:17:33（`Run Count = 3`，次数精确）。LNK 目录中未检出相关条目，**说明非 GUI 双击方式执行**。
>
> 该程序**是否成功完成其预期功能，本次未确认**：需通过输出文件落地、子进程、网络连接或 DLP 告警补齐证据。Prefetch 证明「发生了启动」，不证明「完成了操作」。 程序性质需以 SHA-1/SHA-256 查情报库结果与行为证据综合判定。

<a id="section-26"></a>

#### 陷阱 8：忽略用户归属，把系统级 Prefetch 直接归给登录用户

**现象**

Prefetch 里某程序有执行记录，报告直接写「该用户在案发时段运行了此程序」，而没有做任何归属分析。

**原因**

**Prefetch 不带用户名。**

它记录的是系统级的执行事实，而 Windows 上存在多个并行执行主体：

- 多个交互式用户（快速用户切换 / RDP 多会话）
- 服务账户（`SYSTEM`、本地服务、网络服务）
- 计划任务、组策略、后台服务
- **上一次登录的用户残留数据**（若未正常关机，Prefetch 不会被清）

所以「某程序被启动」与「某人启动了某程序」之间有真实的推断距离。

归属需要外部证据：

| 归属手段 | 提供的关联 |
| --- | --- |
| **LNK / Jump List** | 目录属用户配置目录；Jump List 记录打开的目标路径 |
| **事件日志 `4624`** | 确认该时段有对应账户的登录会话（LogonId） |
| **事件日志 `4688`** | 进程创建事件带 LogonId，**可直接归属** |
| **`$UsnJrnl`** | 文件创建者 SID |
| **`ShutdownTime`** | 判断 Prefetch 是否含上次会话的残留 |

最后一条特别重要：系统**未正常关机**时，Prefetch 目录**不会在启动时被清理**，所以其中可能包含上一次会话甚至更早的记录。

**影响**

- **错误归属到具体个人**，在内部调查案件里后果严重
- 忽略关机状态的影响，把上次会话的记录算到本次
- 若要证明「是本人操作」，实际只有系统级证据，归属无法自证

**核查**

归属必须靠交叉，报告里分开写「执行事实」与「归属结论」：

```bash
# 1. 确认案发时段有无该用户的登录会话
rip.exe -p /evidence/hives/SYSTEM -a sd.txt shutdowntime
# ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 19:50:22

# 2. 事件日志 4624 / 4688 提供 LogonId 级归属
# 3. LNK 目录提供用户侧打开动作
```

| 层次 | 报告表述 |
| --- | --- |
| 执行事实 | 「`suspicious.exe` 于 21:30:44、21:52:10、22:17:33 被启动（Prefetch，双源印证）」 |
| 关机前提 | 「`ShutdownTime` 为 19:50:22，最后一次正常关机在案发时段之前；系统为强制断电，Prefetch 目录未被启动清理」 |
| 会话前提 | 「事件日志 `4624` 显示 `admin` 于 20:05:12 有交互式登录（LogonType 2），覆盖全部三次执行时间」 |
| 归属结论 | 「Prefetch 本身不含用户名。上述归属结论基于登录会话时段覆盖 + LNK 目录未检出（非 GUI 执行）+ 用户配置目录下无相关访问记录，属推定，非 Prefetch 直接给出。」 |

<a id="section-27"></a>

#### 陷阱 9：在原始镜像上直接处理 Prefetch 目录

**现象**

把镜像挂载后，在挂载点内直接跑 Prefetch 解析工具与导出脚本，报告里写「Prefetch 目录已完整分析」。

**原因**

工具与分析过程都可能对检材产生作用：

- 解析工具可能生成辅助文件、临时文件或锁文件
- SQLite 类工具与部分 Windows 解析器会在**同目录**创建 `-wal` / `-shm` 之类的伴随文件
- 目录枚举、文件打开会更新 MFT 中的 `atime`（最后访问时间），**这是对文件系统元数据的实际写入**
- `atime` 的变化会影响后续所有依赖时间戳的分析

Prefetch 目录在多数组织策略下是**受保护的**（连管理员默认也无写权限），所以工具报「无法写入」往往被忽略 —— 但**能读到已提权的工作副本就足以造成影响**。

**影响**

- 挂载点内的任何写入都会**破坏镜像的原始性**，与「全程未改写证据」的声明冲突
- `atime` 被更新后，报告中关于访问时间的分析全部不可靠
- 这类问题在质证时才暴露，届时无法自证

**核查**

**先复制到工作区，再在副本上分析，原始镜像只读**：

```bash
# 只读挂载前算基线
shasum -a 256 /work/DigiForensics.dd > /evidence/baseline.sha256
apfs-fuse -r "<key>" -o vol=2,ro /dev/loop0 /mnt/mac-data   # 或 Linux 侧只读挂载
mount | grep -E 'ro,'      # 确认 ro

# 从镜像中只读提取 Prefetch 文件（icat 不修改源）
mkdir -p /evidence/prefetch
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E '/Windows/Prefetch/' \
  | awk '{print $2}' | while read -r ino; do
      icat -o 2048 /work/DigiForensics.dd "$ino" > "/evidence/prefetch/$(printf '%s' "${ino%%:*}").pf"
    done

# 分析全部在副本上进行
PECmd.exe -d "C:\evidence\prefetch" --csv "C:\evidence\out" --csvf "pf.csv"

# 卸载后复核
umount /mnt/mac-data
shasum -a 256 -c /evidence/baseline.sha256     # 必须输出 OK
```

报告里写明：「Prefetch 分析在从镜像只读提取的副本上进行，镜像哈希分析前后一致。」 只写"只读挂载"而没有哈希对比，等于没有证明。
<a id="section-28"></a>

## 五、案例示例

<a id="section-29"></a>

### 5.1 Run Count 与时间槽位数量决定执行次数结论的边界

**场景**

委托方提供一台 Windows 11 企业笔记本的镜像 `DigiForensics.dd`（raw，1 TB，NTFS 起始扇区 2048），要求查明「2024-11-14 晚间是否有人运行了可疑程序」。系统处于**强制断电**状态，卷已只读挂载。

**处置过程**

第一步，确认 Prefetch 是否启用——不启用则整条路线失效：

```bash
regipacker -p /evidence/hives/SYSTEM -o /tmp/select.txt select
# \Select\Current : 1
regipacker -p /evidence/hives/SYSTEM -o /tmp/prefetch.txt prefetchparameters
```

```text
ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters
  EnablePrefetcher = 3
```

第二步，枚举 `.pf` 文件并确认格式版本：

```bash
ls /mnt/wsl11/Windows/Prefetch/*.pf | wc -l
# → 1024
xxd -l 4 /mnt/wsl11/Windows/Prefetch/SUSPICIOUS.EXE-4A5B6C7D.pf
# → 4D 41 4D 04      ← "MAM\x04"
ls /mnt/wsl11/Windows/Prefetch/ | grep -c ':'
# → 0    无 ADS 形态条目
```

第三步，批量解析并筛出常规项：

```bash
PECmd.exe -d /mnt/wsl11/Windows/Prefetch/ --csv /evidence/out
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open("/evidence/out/PECmd_Output.csv", encoding="utf-8-sig")))
sysdir = ("\\windows\\", "\\program files\\")
sus = [r for r in rows if not r["Path"].lower().startswith(sysdir)]
for r in sus:
    print(r["Name"], "| runs =", r["Run Count"], "| last =", r["Last Run Time"])
    print("   prev:", r["Previous Run Times"])
    print("   path:", r["Path"])
PY
```

```text
SUSPICIOUS.EXE-4A5B6C7D.PF | runs = 3 | last = 2024-11-14 22:17:33
   prev: 2024-11-14 21:52:10, 2024-11-14 21:30:44
   path: C:\Users\admin\AppData\Local\Temp\suspicious.exe
CMD.EXE-9E8D7C6B.PF | runs = 127 | last = 2024-11-14 22:19:01
   prev: 2024-11-14 21:55:33, 2024-11-14 21:44:08, 2024-11-14 21:31:55, 2024-11-14 21:20:02,
         2024-11-14 21:08:47, 2024-11-14 20:57:11, 2024-11-14 20:45:36
   path: C:\Windows\System32\cmd.exe
```

第四步，把运行次数与时间槽位数量做显式比对：

```bash
python3 - <<'PY'
for name, runs, slots in (("SUSPICIOUS.EXE", 3, 3), ("CMD.EXE", 127, 8)):
    if runs <= 8:
        print(f"{name:16s} runs={runs:3d} ≤ 8 槽 → {runs} 次时间全部可见，无环形损失")
    else:
        lost = runs - 8
        print(f"{name:16s} runs={runs:3d} > 8 槽 → 仅最近 8 次可见，更早 {lost} 次时间不可知")
PY
```

```text
SUSPICIOUS.EXE   runs=  3 ≤ 8 槽 → 3 次时间全部可见，无环形损失
CMD.EXE          runs=127 > 8 槽 → 仅最近 8 次可见，更早 119 次时间不可知
```

第五步，交叉验证归属与执行方式：

```bash
# LNK 侧：是否 GUI 双击
ls /mnt/wsl11/Users/admin/AppData/Roaming/Microsoft/Windows/Recent/ | grep -i suspicious
# → 无匹配

# 事件日志 4624
python3 - <<'PY'
print("2024-11-14 20:05:12  4624  LogonType=2  admin  Interactive  覆盖 21:30–22:17 全部三次执行")
PY

# Amcache 独立记录同一路径
python3 - <<'PY'
print("Amcache.hve: SHA1=3f2a9c…  First Run=2024-11-14 21:30:44  ← 与 Prefetch 首个时间戳一致")
PY
```

第六步，确定断电影响的时间边界：

```bash
regipacker -p /evidence/hives/SYSTEM -o /tmp/sd.txt shutdowntime
```

```text
ControlSet001\Control\Windows\ShutdownTime : 2024-11-14 19:50:22
```

**结论**

`EnablePrefetcher = 3`（应用启动预取与启动预取均启用），确认 Prefetch 在本案中可用；若为 0 或 2，本案 Prefetch 路线直接失效。枚举得到 1024 个 `.pf` 文件（已达 Windows 10+ 目录容量上限），抽样魔数为 `4D 41 4D 04`（`MAM\x04`），确认需使用支持自动解压的解析器。

`SUSPICIOUS.EXE-4A5B6C7D.pf` 的 `Run Count = 3 < 8`，三次执行时间（21:30:44、21:52:10、22:17:33）全部可见且次数精确，路径为 `C:\Users\admin\AppData\Local\Temp\suspicious.exe`；

Amcache 独立记录的 `First Run 21:30:44` 与 Prefetch 首个时间戳完全一致，双源印证。`CMD.EXE` 的 `Run Count = 127` 但只有 8 个时间槽，更早的 119 次执行时间不可知。`ShutdownTime = 19:50:22`，最后一次正常关机在 21:30 之前，21:30 之后的数据未正常落盘。

归属 `admin` 账户（用户路径 + `4624` LogonType 2 于 20:05:12 的交互式登录覆盖全部执行时间），强度为中，因 Prefetch 本身不含用户名。

**误判对照**

本案例最具破坏性的错误结论，是把 8 槽环形结构读成「当天只运行了 8 次」。

正确判据是 Windows Vista 之后的 Prefetch 固定保留最近 8 个执行时间（Windows 10 为 8 个槽），运行次数单独累加在头部；`Run Count` 为 127 时最近 8 槽会被不断覆盖，更早的 119 次执行时间永久丢失。

按错误判据写「当天仅运行 cmd.exe 8 次」，等于凭空抹掉 119 次执行记录——若这 119 次中包含实际的恶意命令执行，整条时间线会被彻底改写。

正确表述必须是「累计 127 次，最近 8 次时间为……，更早执行时间不可知」，并把「不可知」显式列入局限。

第二处易错点是看到 `Run Count = 3` 就写「该程序只运行过 3 次，无害」。

正确判据是次数少与威胁程度之间没有因果关系；真正值得关注的是执行位置——`C:\Users\admin\AppData\Local\Temp\` 是用户可写目录，落在 Temp 下的可执行文件属于典型的落地投递位置。

按错误判据得出「无害」，会让本案最核心的信号（Temp 目录执行未知程序）被直接忽略。

这也是必须明确写进报告的判断：在 Temp 目录执行未知程序本身就是需要深入分析的强信号，不能因为次数少而降低权重。

第三处易错点是把 Prefetch 的时间直接当作「程序产生效果的时间」。正确判据是 Prefetch 记录的是**映像被加载执行**的时刻，不包含任何后续行为；程序是否成功完成载荷投递、是否因缺依赖而立即崩溃、是否被沙盒拦截，Prefetch 全都无法回答。

本案 `SUSPICIOUS.EXE` 末次运行 22:17:33，而 `ShutdownTime` 为 19:50:22，说明这三次执行都发生在非正常关机之后——这些记录能写入磁盘本身就依赖 Prefetch 的即时落盘机制，但也因此存在**最后一次执行记录可能不完整**的风险。按错误判据写「已执行并生效」，在没有内存镜像或端点日志支撑时属于超范围结论。

<a id="section-30"></a>

### 5.2 Prefetch 计数缺失与容量上限的甄别

**场景**

委托方进一步提出疑问：「如果有人运行了程序又删除了 `.pf` 文件，或者 Prefetch 计数本身不准，这份报告的结论还能用吗？」需要明确 Prefetch 的三类不可见边界。

**处置过程**

第一步，确认 Prefetch 目录已达容量上限——这意味着最旧条目会被系统自行淘汰：

```bash
ls /mnt/wsl11/Windows/Prefetch/*.pf | wc -l
# → 1024
```

```python
# Windows 10 / 11 的 Prefetch 目录上限
PREFETCH_MAX_ENTRIES = 1024
print("当前条目 =", 1024)
print("是否触及上限:", 1024 >= PREFETCH_MAX_ENTRIES)
print("→ 最旧的条目会被新条目挤出目录，时间跨度随系统使用强度而变")
```

第二步，检查 Prefetch 引导文件，确认机制确实在工作：

```bash
ls -la /mnt/wsl11/Windows/Prefetch/PREFETCH.{DB,DFT} 2>/dev/null
stat -f '%N  mtime=%Sm' -t '%Y-%m-%d %H:%M:%S' /mnt/wsl11/Windows/Prefetch/SUSPICIOUS.EXE-4A5B6C7D.pf
# → mtime=2024-11-14 22:17:33（与末次运行时间一致）
```

第三步，与 Prefetch 关闭或损坏的情形做对照：

```bash
python3 - <<'PY'
# 若 EnablePrefetcher=0 或 1：只剩启动预取（BOOT），EXE 级文件不产生条目
# 若 Prefetch 被策略禁用或磁盘加密阻断：目录为空或仅有 PREFETCH.*
# 本案：EnablePrefetcher=3 且条目丰富 → 机制正常
print("机制状态判定: 正常（EnablePrefetcher=3 + 1024 条目 + 引导文件存在）")
print("因此本案的『未发现』才有意义")
PY
```

第四步，界定「被删除的 .pf」这一情形的可查性：

```bash
python3 - <<'PY'
# .pf 文件位于 $MFT 记录在 %SystemRoot%\\Prefetch 下
# 删除后：文件消失，但 MFT 条目可能仍可解析（含时间戳）
python3 - <<'PY'
PY
fls -m -r /mnt/wsl11 > /evidence/fsrec.txt 2>/dev/null
# 检索被删除但仍可解析的条目
grep -i 'suspicious' /evidence/fsrec.txt | head
# → 输出为空：卷上不存在该 .pf 条目的活动记录
```

第五步，明确三类边界的具体影响：

```bash
python3 - <<'PY'
b = [
 ("容量淘汰", "1024 上限下最旧条目被挤出，时间跨度不可知"),
 ("断电未落盘", "ShutdownTime=19:50:22 之后的数据未正常落盘"),
 ("条目被删除", "删除后本卷可查性取决于 MFT 是否可解析，本案查无此条目"),
]
for k, v in b: print(f"{k:10s} → {v}")
PY
```

**结论**

Prefetch 目录条目数为 1024，恰为 Windows 10/11 的容量上限，意味着最旧条目会被新条目挤出目录，历史时间跨度随系统使用强度而变，本案无法界定 Prefetch 记录覆盖的完整时间范围。`EnablePrefetcher = 3`、`PREFETCH.DB` 引导文件存在、`SUSPICIOUS.EXE-4A5B6C7D.pf` 的 mtime（22:17:33）与末次运行时间一致，三者共同确认 Prefetch 机制在检材中正常工作——**这一确认是本案所有「未发现」类表述成立的前提**。对「被删除的 `.pf`」这一情形，`fls -m -r` 全卷递归未检出相关条目，说明本卷上不存在该条目的可解析 MFT 残留。报告须明示三类边界：容量上限导致的旧条目淘汰、`ShutdownTime = 19:50:22` 之后因断电未落盘的数据、以及条目被删除时本卷可查性取决于 MFT 是否仍可解析。

**误判对照**

最常见的错误结论是「Prefetch 里没有可疑程序，因此该时段未运行过可疑程序」。

正确判据是这一表述只在**明确列出检查范围后**才成立——本案至少存在三条使「未发现」不等于「不存在」的边界：1024 条目上限会持续淘汰最旧条目，21:30 之后断电导致数据未正常落盘，以及条目被删除后本卷可查性受限。

按错误判据写成无限定的「未运行过」，一旦委托方提供该时段的网络流量或 EDR 日志显示存在其他进程启动，整份报告的结论即被推翻。

正确写法是「在 Prefetch 覆盖的时间范围（可从最早 `.pf` 的 mtime 推算）内，未检出除 `SUSPICIOUS.EXE` 与 `CMD.EXE` 之外的条目」，并把上述三条边界列入局限。

第二处易错点是把「Prefetch 目录满 1024 条」当成程序运行量极大的证据。

正确判据是 1024 是**系统硬上限**，条目数达到该值只说明条目已被挤出过，与运行频率没有换算关系；换算需要结合最早 `.pf` 的 mtime 与最晚 `.pf` 的 mtime 之差、以及这期间创建的新条目数。

按错误判据写「该机运行过上千个程序」，会把 Prefetch 的容量设计当成行为统计，得出完全错误的活跃度画像。

第三处易错点是发现某个 `.pf` 不存在就直接写「该程序未运行过」，而不检查它是否被 Prefetch 机制排除。

正确判据是 Prefetch 只记录成功加载映像的可执行文件；脚本（`.bat`/`.ps1`/`.vbs`）、由其它解释器加载的文件、以及启动即失败的进程都可能不产生条目。

本案若某程序通过 `cmd.exe` 调用脚本，Prefetch 中只会有 `CMD.EXE` 的条目而无对应条目；若误把 `CMD.EXE` 的 127 次直接归因于可疑脚本，则又落入了上一节所述的环形覆盖陷阱。

<a id="section-31"></a>

### 5.3 timestomp 伪造 Modified 时间与 Last Run 分离

**场景**

委托方要求就 `SUSPICIOUS.EXE` 的程序身份给出定性依据，并确认 Prefetch 中的时间是否可信。需要判断时间字段是否存在伪造，以及如何识别。

**处置过程**

第一步，取 Prefetch 头部结构，区分各时间槽的语义：

```bash
python3 - <<'PY'
import struct, datetime
d = open("/mnt/wsl11/Windows/Prefetch/SUSPICIOUS.EXE-4A5B6C7D.pf","rb").read()
# MAM 压缩，需先解压；此处展示解压后的字段布局
hdr = d  # 实际使用时先用 pecmd --json 导出结构化结果
runs, = struct.unpack_from("<I", hdr, 84)
slots = struct.unpack_from("<8I", hdr, 92)
base = datetime.datetime(1601,1,1)
ts = [base + datetime.timedelta(microseconds=s*10) for s in slots[:runs] if s]
for i, t in enumerate(ts):
    print(f"槽 {i+1}: {t}  ← 执行时间")
PY
```

```text
槽 1: 2024-11-14 21:30:44  ← 执行时间
槽 2: 2024-11-14 21:52:10  ← 执行时间
槽 3: 2024-11-14 22:17:33  ← 执行时间
```

第二步，与 MFT 与 `$STANDARD_INFORMATION` 的四个时间戳逐项对照：

```bash
istat -o 2048 /work/DigiForensics.dd 4711
```

```text
Entry: 4711
  Created  : 2024-11-14 21:28:55     ← MFT $SI$cTime
  Modified : 2019-03-11 02:14:55     ← MFT $SI$mTime  ★ 早于 Created
  Accessed : 2024-11-14 21:30:40
  MFT Changed : 2024-11-14 21:28:55  ← MFT $SI$cTime（变更时间）
```

第三步，识别不可能的时间关系：

```bash
python3 - <<'PY'
created  = "2024-11-14 21:28:55"
modified = "2019-03-11 02:14:55"
pf_last  = "2024-11-14 22:17:33"
print("mTime 早于 cTime:", modified < created, "→ 时间上不可能，除非被显式设置")
print("mTime 距执行时间:", (pf_last[:10], modified[:10]), "→ 相差约 5.7 年")
print("若误把 mTime 当执行时间，会得出『2019 年运行过，与本案无关』")
PY
```

```text
mTime 早于 cTime: True → 时间上不可能，除非被显式设置
```

第四步，检查 Prefetch 的 Last Run 与 Amcache First Run 的一致性：

```bash
python3 - <<'PY'
print("Prefetch  槽1(最早执行) : 2024-11-14 21:30:44")
print("Amcache   First Run     : 2024-11-14 21:30:44   ← 独立工件，秒级一致")
print("MFT       Created       : 2024-11-14 21:28:55   ← 早于执行 101 秒，合理")
print("MFT       Modified      : 2019-03-11 02:14:55   ← 唯一异常项")
PY
```

第五步，确认文件是否已被删除以判断取证路径：

```bash
fls -m -r /mnt/wsl11 2>/dev/null | grep -i 'suspicious.exe'
# → C:\Users\admin\AppData\Local\Temp\suspicious.exe（当前仍存在）
icat -o 2048 /work/DigiForensics.dd 4711 > /evidence/suspicious.exe
shasum -a 256 /evidence/suspicious.exe
# → e3c0…b19a（与 Amcache SHA1 8b1a… 对应的文件一致）
```

**结论**

Prefetch 的 8 个时间槽记录的均为**执行时间**，本案 3 个槽位（21:30:44、21:52:10、22:17:33）语义明确。MFT 的 `$STANDARD_INFORMATION` 显示 `Created = 2024-11-14 21:28:55`、`Modified = 2019-03-11 02:14:55`、`Accessed = 2024-11-14 21:30:40`，其中 `Modified` 早于 `Created` 达 5.7 年，在时间逻辑上不可能自然产生，判定为 timestomp 伪造。Prefetch 最早执行时间 21:30:44 与 Amcache `First Run` 秒级一致，两件独立工件互证；MFT Created 早于执行 101 秒，顺序合理。文件当前仍存在于 `C:\Users\admin\AppData\Local\Temp\`，已提取并计算 SHA-256，可交情报库定性。结论：执行时间应采信 Prefetch/Amcache 的 21:30:44–22:17:33，`Modified` 字段的 2019 年值为伪造，不得用于任何时间线。

**误判对照**

本案例最典型的致命错误，是把 Prefetch 的时间槽与文件系统 `Modified` 时间混为一谈。

正确判据是二者来源完全不同：Prefetch 的时间槽由系统在**程序启动时**写入，落盘于 `C:\Windows\Prefetch\*.pf`；文件系统的 `Modified`（`$SI$mTime`）反映文件**内容最后被写入**的时间，可被任意程序通过 `SetFileTime()` 显式设置。

本案 `Modified = 2019-03-11` 早于文件 `Created = 2024-11-14`，这种倒挂本身就是伪造的铁证。

按错误判据把 2019 年当作执行时间，会得出「该程序 5 年前运行过，与本案无关」并据此结案，把唯一的强证据当成无关数据丢弃；而真实的执行时间 21:30:44 与 Amcache 首启时间完全吻合，恰恰是最有力的证据。

第二处易错点是把 Prefetch 的时间槽当成「文件写入时间」。

正确判据是时间槽记录的是**映像加载执行**的时刻，与文件内容何时被修改无关；本案程序是否在运行后改写了自身或释放其它载荷，Prefetch 的 22:17:33 无法回答。

按错误判据把「22:17:33 执行」改写成「22:17:33 文件被修改」，会把执行行为与文件操作混为一谈，在需要重建勒索或投毒时间线时导致环节错位。

第三处易错点是发现 `Modified` 被伪造后，就把该文件的**所有**时间字段一并当作伪造处理。

正确判据是伪造是**逐字段**的——`SetFileTime()` 可以只指定部分时间戳，`Created`、`Accessed`、`MFT Changed` 完全可能保持真实。

本案 `Created = 21:28:55` 早于执行 101 秒、顺序合理，`Accessed = 21:30:40` 与 Prefetch 首槽 21:30:44 相隔 4 秒，均符合真实行为。

按错误判据认定「整组时间全部伪造」，等于主动放弃 `Created` 提供的「程序在执行前 101 秒落地」这一关键环节，会丢掉投放与执行之间的准备时间窗口。

---
<a id="section-32"></a>

## 六、扩展阅读方向

<a id="section-33"></a>

### 前置基础：动手之前必须先确认的几件事

- [Windows 取证工件地图](../computer-registry-log/computer-registry-log-windows-artifact-map.md) —— 「Prefetch 目录为空」这个观察，需要先知道它本来该有什么、版本差异在哪里。
- [注册表取证](../computer-registry-log/computer-registry-log-registry-forensics.md) —— `EnablePrefetcher` 的四个取值读取自注册表，这是本篇 3.1「确认 Prefetch 状态」的技术前提。
- [NTFS 结构与 MFT 解析](../../filesystem/filesystem-ntfs/filesystem-ntfs-ntfs-master-file-table.md) —— 文件读取与 ADS 的底层机制。ADS 执行产生的特殊文件名规则在 NTFS 侧。
- [时间戳换算](../../fundamentals/fundamentals-concepts/fundamentals-concepts-timestamps-and-timezones.md) —— FILETIME 纪元与精度换算。

<a id="section-34"></a>

### 同层深入：三个执行侧工件的分工

- [ShimCache 与 Amcache](computer-execution-shimcache-amcache.md) —— **同组的第一顺位搭档**。ShimCache 是兼容性层维护的启动记录，Amcache 是安装与执行痕迹的汇总，**三者的时间语义与覆盖范围都不同，交叉才能收敛**。
- [LNK 快捷方式与 Jump List 跳转列表](computer-execution-lnk-jumplist.md) —— 另两个执行侧工件。Jump List 记录用户主动打开过的文档与程序，且自带用户目录归属，这一点补上了 Prefetch「不带用户名」的短板。
- [SRUM 数据库分析](../computer-browser-behavior/computer-browser-behavior-srum.md) —— 资源使用统计。它的 `UserId` 能把执行落到具体用户，Prefetch 不能。

<a id="section-35"></a>

### 相邻议题：文件操作与时间线

- [UsnJrnl 与文件操作时间线](computer-execution-usn-journal-timeline.md) —— Prefetch 说「程序启动了」，USN 说「文件被改了」，两条线合起来才能推出「这个程序改了这个文件」。
- [反取证手法与时间戳篡改检测](../../fundamentals/fundamentals-concepts/fundamentals-concepts-anti-forensics-and-timestamp-tampering.md) —— Prefetch 的执行时间由内核写入，篡改者改不到，这正是它作为独立时钟的价值。
- [事件日志深度分析](../computer-registry-log/computer-registry-log-windows-event-log-analysis.md) —— 事件日志提供**带用户名的执行与登录记录**，是给 Prefetch 补上主体信息的来源。

<a id="section-36"></a>

### 工具与规范：解析与保全

- [只读挂载与安全接入](../../imaging/imaging-mount-simulate/imaging-mount-simulate-read-only-mounting.md) —— `.pf` 文件的读取前提。
- [证据文件格式](../../fundamentals/fundamentals-chain/fundamentals-chain-dd-e01-aff4-evidence-formats.md) —— 解析结果的归档格式。
- [取证流程与原则](../../fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) —— 本篇的方法论纪律来源：「启动过」与「完成了操作」在报告里必须是两句不同的话。

<a id="section-37"></a>

### 判据与反例：哪些方向不能推

- [取证技能树](../../fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) —— 执行侧工件属于基础层，**它答不了「谁」与「做了什么」**，技能树能定位这些能力分别在哪一层。
- [近似匹配与模糊哈希](../../fundamentals/fundamentals-concepts/fundamentals-concepts-fuzzy-hashing.md) —— Prefetch 本身不携带文件内容哈希，所以「这个可执行文件是不是被替换过」这个问题要靠另找样本做比对，这是该篇能补上的能力。
<a id="section-38"></a>

## 七、命令速查

```bash
# 1) 确认卷偏移
mmls /work/DigiForensics.dd
fsstat -o 2048 /work/DigiForensics.dd

# 2) 提取 SYSTEM hive
fls -o 2048 -r -p /work/DigiForensics.dd \
  | grep -E 'config/SYSTEM$' | grep -E '^r/r' | awk '{print $2}' \
  | while read -r ino; do icat -o 2048 /work/DigiForensics.dd "$ino" > /evidence/hives/SYSTEM; done

# 3) 活体系统直接查（离线用 rip 从 hive 读）
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher
# 0=禁用  1=应用预取  2=仅启动预取  3=应用+启动（桌面默认）

# 4) 离线读取：先确认当前 ControlSet
rip.exe -p SYSTEM -a select.txt select
rip.exe -p SYSTEM -a pf.txt prefetchparameters

# 5) 枚举 Prefetch 目录（保留含冒号的完整文件名，不要只按 *.pf 过滤）
fls -o 2048 -r -p /work/DigiForensics.dd | grep -E '/Windows/Prefetch/' | grep -E '^r/r' | awk '{print $2}'

# 6) 判定格式版本：先看魔数
xxd -l 4 sample.pf
# 4D414D04=MAM压缩(需先解压) | 11=v17 | 17=v23 | 1A=v26 | 1E=v30 | 1F=v31

# 7) 统计全目录版本分布，判断是否混版
for f in /evidence/prefetch/*.pf; do xxd -l 4 -p "$f"; done | sort | uniq -c

# 8) 解析整个目录
PECmd.exe -d "C:\evidence\prefetch" --csv "C:\evidence\out" --csvf "pf.csv"

# 9) 解析单个文件并格式化时间输出
PECmd.exe -f "SUSPICIOUS.EXE-4A5B6C7D.pf" --mp --dt "yyyy-MM-dd HH:mm:ss"

# 10) 交叉验证：登录会话与关机时间
Get-WinEvent -Path "C:\evidence\Security.evtx" -FilterHashtable @{Id=4624} |
  Select-Object TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='Type';e={$_.Properties[8].Value}}
rip.exe -p SYSTEM -a sd.txt shutdowntime
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — Prefetch 深度解析」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Prefetch 深度解析》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。

---
