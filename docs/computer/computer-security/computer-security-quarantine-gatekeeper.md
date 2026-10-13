---
title: "Quarantine 与 Gatekeeper"
slug: "computer-security-quarantine-gatekeeper"
canonical: "https://www.digiforensics.cn/wiki/computer-security-quarantine-gatekeeper"
license: "CC-BY-SA-4.0"
author: "DigiForensics"
updated_at: "2026-10-09T12:51:49+08:00"
source_url: null
references: ["https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans"]
source_type: "wiki-sync"
category: "computer"
space: "计算机取证"
node_path: ["安全与权限"]
---

# Quarantine 与 Gatekeeper

> 原文链接：[DigiForensics Wiki · 在线阅读](https://www.digiforensics.cn/wiki/computer-security-quarantine-gatekeeper)

<a id="section-1"></a>

## 一、概述

macOS 上有一样 Windows 没有的元数据：扩展属性（extended attributes）。

它不占数据块，`ls -l` 里的文件大小也不包含它，却能回答"这个文件是怎么来的"。

其中与下载行为直接相关的一条是 `com.apple.quarantine`。浏览器下载文件时会自动打上这个属性，格式固定：

```
0083;5f56283b;Safari;0123ABCD-0123-ABCD-0123-0123ABCD4567
```

四段分别是：

| 段 | 内容 | 说明 |
|---|---|---|
| 1 | `0083` | **旗标值**（十六进制），控制 Gatekeeper 的检查行为 |
| 2 | `5f56283b` | **下载时间的 Unix 秒，以十六进制编码** |
| 3 | `Safari` | **下载该文件的应用名** |
| 4 | `0123ABCD-…` | **本次下载的唯一标识 UUID** |

**第 2 段是最容易写错的一处。**

它不是十进制字符串，而是**用十六进制编码的 Unix 秒**。实测验证：

```bash
printf '%d\
' 0x5f56283b
# → 1599551515  →  UTC 2020-09-07 12:31:55
```

把它当十进制读会怎样？多数情况下根本走不到「算错」这一步——`5f56283b` 里带 `f`，`int()` 直接抛 `ValueError`。更麻烦的是那些**恰好只由数字组成**的十六进制值：`sqlite3` 的 `CAST('66d94e21' AS INTEGER)` 静默返回 **66**，`awk` 的 `+0` 返回 **660**，都不报错，直接给出 1970 年附近的时间。这才是取证里真正会漏过去的那种错。

**报告里写出的下载时间必须来自这一步十六进制解码。**

还有一条线索是 Gatekeeper 的绕过痕迹：Quarantine 属性被删掉，是一个需要解释的现象，可能来自有人执行过 `xattr -d com.apple.quarantine`，也可能在提示框里选了"打开"绕过检查；非人为成因见 2.4。

**这种"缺失"本身就是需要解释的痕迹，但成因不能由缺失本身推出。**

---

<a id="section-2"></a>

## 二、核心原理

<a id="section-3"></a>

### 2.1 扩展属性与 `xattr` 命令

扩展属性（xattr）是 APFS/HFS+ 支持的元数据扩展机制。取证相关的主要有：

| 属性名 | 含义 |
|---|---|
| **`com.apple.quarantine`** | ★ 下载来源与时间（Gatekeeper 依据） |
| `com.apple.metadata:*` | Finder 标签、颜色、排序等 |
| `com.apple.FinderInfo` | Finder 图标位置与文件类型 |
| `com.apple.provenance` | 文件来源链路（较新系统引入） |
| `com.apple.ResourceFork` | 资源分支数据 |

```bash
xattr -l <file>              # 列出全部扩展属性名与长度
xattr -p com.apple.quarantine <file>    # 打印某个属性的值
xattr -w com.apple.quarantine "…" <file>  # 写入属性（⚠ 改证据）
xattr -d com.apple.quarantine <file>     # 删除单个属性（⚠ 改证据）
xattr -c <file>              # 清除全部扩展属性（⚠ 改证据）
xattr -r <file>              # 递归（对目录有效）
```

> `-w` / `-d` / `-c` 都是**改写**操作，作用在原始检材上等同于篡改证据。分析阶段只读；要"试写"就在工作副本上做，并记录副本哈希。

批量导出全机 Quarantine 的价值在于它一次给出"哪些文件走过下载路径"，并为"某个文件为什么没有该属性"提供同批对照基准：

```bash
# 只读方式：逐文件读取，不改动任何属性
find /mnt/mac-data/Users -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv
```

`xattr` 打印值时保留原样（十六进制字符串）。

顺带说一句，`xattr -r` 不是"递归读取属性"——它是"递归作用于文件"，主要对目录有用。要遍历全机取属性，得靠 `find` 逐文件调 `xattr -p`。

<a id="section-4"></a>

### 2.2 Quarantine 旗标值的含义

第一段 `0083` 是十六进制，即 `0x83`。**默认值随版本变化**（常见的有 `0083`、`0085`、`0177`），各个二进制位控制"是否来自网络""是否已由用户确认"之类的行为。

**两条判读规则**：**（1）** 有 Quarantine 属性 = 该文件曾经经过网络下载路径，是"来源为网络"的直接证据；它证明的是属性被打上的那一刻走过下载通道，不等于该属性至今未被改写；**（2）** 没有该属性 ≠ 文件不是下载来的（原因见 2.4）。

**不要因为旗标值不同就判定"被篡改"**——它随系统版本与用户操作变化，**差异本身不构成结论**。

<a id="section-5"></a>

### 2.3 Gatekeeper 的三道检查

macOS 10.15 之后 Gatekeeper 是三道叠加：

| 检查 | 作用 | 绕过方式（★ 只讲现象） |
|---|---|---|
| **代码签名** | 验证开发者身份与完整性 | 伪造/移除签名 |
| **公证（notarization）** | Apple 记录该软件已扫描无恶意 | 使用未公证的开发者工具 |
| **Quarantine 触发** | 只有带 Quarantine 的文件才受前两道约束 | **删除 Quarantine 属性** |

```bash
codesign -dv --verbose=4 /Applications/Some.app 2>&1 | grep -E 'Identifier|TeamIdentifier|Authority|Timestamp'
codesign --verify --deep --strict --verbose=2 /Applications/Some.app 2>&1 | head -5
spctl --assess --type execute --verbose /Applications/Some.app
# → /Applications/Some.app: accepted
#   source=Notarized Developer ID
# → /Applications/Some.app: rejected
#   source=no usable signature
```

实测行为：`spctl --assess --type install --verbose /Applications/Safari.app` 返回 `rejected`；`spctl --status` 输出 `assessments enabled`。

> `spctl --assess` 对普通文件（如 `.txt`）返回 `rejected / no usable signature` 是正常结果，不是异常。真正决定 Gatekeeper 行为的是对**应用包**（`.app`）的评估。

<a id="section-6"></a>

### 2.4 为什么 Quarantine 会"消失"

这一点要格外小心：Quarantine 的缺失，不能直接等同于"文件不是下载的"。

| 原因 | 是否人为 | 说明 |
|---|---|---|
| 文件由程序生成（非下载） | 否 | `curl`/程序写出、`cp` 本地复制，**`cp` 不复制 xattr** |
| 拖入邮件附件后另存 | 否 | 附件被解压/重写，属性不继承 |
| 解压归档 | 否 | **解压工具默认不还原 xattr** |
| **用户显式删除** | ★ 是 | `xattr -d com.apple.quarantine` |
| **右键"打开"绕过** | ★ 是 | 一次确认后系统清除该文件的 Quarantine |
| 挂载到不保留 xattr 的文件系统 | 否 | FAT32/exFAT 会丢弃扩展属性 |
| 复制到 `DigiForensics.dd` 之外的中转介质 | 否 | 取决于中转格式 |

结论：Quarantine 存在 = 支持网络来源与下载时刻的直接证据（属性值本身仍可被手工改写，改写痕迹的判断见 2.3）。Quarantine 缺失 = 弱线索（需要解释，但不能定性）。

<a id="section-7"></a>

### 2.5 `securityd` 日志

Gatekeeper 的实际校验动作由 `securityd` 记录在统一日志中：

```bash
/usr/bin/log show --last 30d --info --style json \
  --predicate 'subsystem == "com.apple.securityd"' > /evidence/securityd.log

# Gatekeeper 评估与隔离属性处理
/usr/bin/log show --last 7d --info --style compact \
  --predicate 'subsystem == "com.apple.security" OR process == "syspolicyd"' | head -60
```

**应重点检索的关键词**：

```bash
grep -niE 'quarantine|notariz|gatekeeper|assessment|reject' /evidence/securityd.log | head -40
```

| 日志线索 | 含义 |
|---|---|
| `Gatekeeper` + `rejected` | 某次 Gatekeeper 校验未通过 |
| `quarantine attribute` | Quarantine 相关处理记录 |
| `notarization` | 公证状态查询 |
| 同一文件在短时间内多次评估 | 可能存在反复尝试打开 |

> **采集现实必须交代**：统一日志属于**运行系统的私有数据存储**，现场可用 `/usr/bin/log show` 导出。离线镜像里的 `/var/db/diagnostics/` 虽然会随数据卷一起被 `dd` 进来，但它是**二进制索引库**，直接解析困难，日志本身也会被时间轮转覆盖。所以 `securityd` 日志的证据强度取决于"是否现场采集"，以及所导出时间窗是否覆盖案件时段（覆盖边界的写法见 5.3）。详见[02](../computer-log-persistence/computer-log-persistence-macos-unified-logs-and-launch-agents.md)。

<a id="section-8"></a>

### 2.6 `.DS_Store` 与 AppleDouble：三者常被混淆

这三样都和"文件的外围信息"有关，但作用完全不同：

| 工件 | 实际内容 | 是否含下载来源 |
|---|---|---|
| `.DS_Store` | **Finder 目录视图状态**：文件名、图标位置、显示方式、窗口大小。实测文件头 `0000 0001 4275 6431`（`Bud1` 块标识） | **否，不含 URL** |
| `._filename`（AppleDouble） | 资源分支与 Finder 信息的**伴生文件**，用于不支持 xattr 的文件系统 | 否 |
| `com.apple.quarantine` | 下载来源应用 + 下载时间 | **是，本篇重点** |

`.DS_Store` 的取证价值有限，但不为零：

| 它能证明 | 它不能证明 |
|---|---|
| 某文件曾存在于某目录并被 Finder 浏览 | 文件从哪下载、什么时候下载 |
| 目录的浏览顺序（弱线索） | 文件的创建/修改时间 |
| 某些情况下残留已删除文件的目录项 | 文件当前是否还存在 |

> **常见错误**：把 `.DS_Store` 当成"下载历史"。它记的是**视图状态**，与文件来源无关。要证明文件来源只能靠 `com.apple.quarantine` 与 `kMDItemWhereFroms`（见[04](../computer-plist-spotlight/computer-plist-spotlight-spotlight.md)）。

---

<a id="section-9"></a>

## 三、操作步骤

<a id="section-10"></a>

### 3.1 第 1 步：定位带 Quarantine 的文件

```bash
EV=/mnt/mac-data/Users/liwei
# 快速抽样：Downloads 是默认下载目录，通常命中率较高
for f in "$EV/Downloads"/*; do
  [ -f "$f" ] && xattr -p com.apple.quarantine "$f" 2>/dev/null && echo "  ← $f"
done

# 全量导出（只读，不改属性）
find "$EV" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv
wc -l /evidence/quarantine-all.tsv
```

<a id="section-11"></a>

### 3.2 第 2 步：解码（四段解析）

```bash
# 单文件解码
decode_q() {
  q=$(xattr -p com.apple.quarantine "$1" 2>/dev/null) || return 1
  IFS=';' read -r flag ts app uuid <<< "$q"
  printf 'flags=%s  time=%s  app=%s  uuid=%s\
' \
    "$flag" "$(date -u -r "$(printf '%d' "0x$ts")" '+%Y-%m-%d %H:%M:%S UTC')" "$app" "$uuid"
}
decode_q ~/Downloads/客户名单.xlsx
# → flags=0083  time=2020-09-07 12:31:55 UTC  app=Safari  uuid=0123ABCD-0123-ABCD-0123-0123ABCD4567
```

| 字段 | 提取方式 | 陷阱 |
|---|---|---|
| 旗标 | `${q%%;*}` | 十六进制字符串，**不要当十进制解读** |
| 时间 | `${q#*;}` 后取到下一个 `;`，再 `printf '%d' 0x…` | ★ **十六进制，不是十进制** |
| 应用名 | 第 3 段 | 可能是 `Safari`、`com.google.Chrome`、`Safari.Downloads` |
| UUID | 第 4 段 | 每次下载唯一，**可用于关联同一次下载事件** |

<a id="section-12"></a>

### 3.3 第 3 步：来源应用分布统计

```bash
cut -f2 /evidence/quarantine-all.tsv | cut -d';' -f3 | sort | uniq -c | sort -rn
#     41 Safari
#     12 com.google.Chrome
#      3 Slack
#      1 com.google.Chrome.dn0crl0dhlcpm   ← 扩展来源，可见具体扩展 ID
```

**分布统计的取证价值**：

| 现象 | 可能含义 |
|---|---|
| 绝大多数来自 `Safari` | 常规下载 |
| 出现 `com.google.Chrome.dn0crl0dhlcpm` 形态 | 应用名带 bundle ID 后缀，通常表示下载由该扩展进程发起（云盘、翻译类扩展等），应结合扩展清单核实 |
| 出现未知应用名 | 可能自研客户端、脚本或恶意程序 |
| 某应用只有 1 条且时间孤立 | 需单独核实 |

<a id="section-13"></a>

### 3.4 第 4 步：绕过痕迹检测

```bash
# 4.1 与 Spotlight 来源交叉（见第 4 篇）
grep -f <(cut -f1 /evidence/quarantine-all.tsv | xargs -d'\
' mdfind -onlyin /Users/liwei 2>/dev/null) \
  /evidence/quarantine-all.tsv 2>/dev/null | head

# 4.2 Gatekeeper 全局策略状态
spctl --status                 # → assessments enabled
spctl --disable-status         # → 全局禁用状态（本机实测：当前版本已不支持该开关）

# 4.3 应用评估结果
codesign -dv --verbose=4 /Applications/Target.app 2>&1 | grep -E 'Identifier|TeamIdentifier|Authority'
spctl --assess --type execute --verbose /Applications/Target.app
```

> `spctl --add` 在现代 macOS 已被移除（实测返回 `This operation is no longer supported.`）。所以"曾经 `spctl --add` 过"**在现代系统上不会留下可查的痕迹**，只能从 `spctl --status`（`assessments enabled` 表示未被全局禁用）与 `securityd` 日志间接判断。不要在报告里写"通过 `spctl --add` 添加信任"这种在现代系统上无法验证的话。

<a id="section-14"></a>

### 3.5 第 5 步：验证

| 验证对象 | 方法 | 通过标准 |
|---|---|---|
| Quarantine 值完整 | 四段都以 `;` 分隔 | 段数为 4 |
| 时间解码正确 | `date -u -r` 回环验证 | 与文件 mtime 差值可解释 |
| 未改动检材 | 分析前后 `shasum -a 256` 比对 | 完全一致 |
| 旗标值未被篡改 | 与同批文件对比分布 | 异常值单独说明 |
| 日志与属性印证 | `securityd` 日志 + Quarantine | 时间窗口吻合 |

---
<a id="section-15"></a>

## 四、常见陷阱

这些陷阱按属性读写 → 字段解码 → 缺失的解释 → 结论表述归组，每条给出：现象、为什么会误判、误判代价、正确做法。
★ 标记表示该操作会导致原始检材永久灭失或不可逆改变，执行前必须停下来确认。

<a id="section-16"></a>

### 4.1 属性读写

<a id="section-17"></a>

#### 陷阱 1：★ 用 `xattr -w` / `-d` / `-c` 在检材上"试一下"效果

**现象**：想弄清某个 Quarantine 值的具体含义，在挂载点内对某个文件执行 `xattr -w com.apple.quarantine "0083;..." file` 或 `xattr -d com.apple.quarantine file`，或者用 `xattr -c` 清理"脏"属性。

**原因**：`-w` / `-d` / `-c` 是改写操作，在原始检材上等同于篡改证据。

**动机往往还很合理**——"先清掉属性看看文件行为有没有变化"，或者"这个属性格式看不懂，写一个标准的进去对比"。

但**这会直接销毁证据本身**。

**影响**：**不可逆，销毁的正是本主题的核心证据。**

Quarantine 属性一旦被 `-d` 或 `-c` 清除，**该文件的下载来源与下载时间永久消失**——这两个值在磁盘上没有任何其他副本。

它们是"文件来自网络、什么时候下的、通过什么应用下的"这三重信息的唯一载体。案件里"竞争对手客户名单的下载时间与来源"整个定案链条都建立在它上面。

**核查**：**分析时只能读**。要"试写"就在工作副本上做，并记录副本哈希：

```bash
# 只读：逐文件读取，绝不写入
xattr -l <file>                              # 列出全部属性名与长度
xattr -p com.apple.quarantine <file>        # 打印某个属性的值

# 需要试写时：先复制
cp -p <file> /evidence/testfile
xattr -w com.apple.quarantine "0083;..." /evidence/testfile   # 只在副本上写
shasum -a 256 <file> /evidence/testfile                       # 记录两者哈希，证明原文件未变
```

**批量提取用只读循环**（与 2.1 相同）：

```bash
find /mnt/mac-data/Users -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv
```

**注意 `-r` 的语义**（2.1 已说明）：它不是"递归打印所有属性"，因此想遍历全机取属性，得靠 `find` 逐文件 `xattr -p`；写成 `xattr -r -p` 期望遍历时通常什么都没有输出。

<a id="section-18"></a>

#### 陷阱 2：把 `xattr` 命令读取失败当成"文件没有该属性"

**现象**：批量脚本里 `xattr -p com.apple.quarantine "$f"` 对某个文件无输出，报告写「该文件无 Quarantine 属性，非下载所得」。

**原因**：命令失败有多种原因，而"确实没有该属性"只是其中一种：文件不在挂载点内（路径拼错）、权限不足（xattr 读取受文件权限与属主限制）、`apfs-fuse` 挂载实现对 xattr 的支持有限、文件名含特殊字符导致变量展开出错。

而脚本里 `2>/dev/null` 把所有错误输出都吞掉了，你无法区分这些情况。

**影响**：这是"工具静默失败"的典型。

批量脚本 `|| continue` 加 `2>/dev/null` 的组合让所有失败都变成"跳过"，最终你得到一份"有属性的文件清单"——它看起来是完整的，实际上可能漏掉了大批文件。

而**这份清单的完整性正是"属性缺失"类结论的基础**（陷阱 9 会讲为什么"缺失"需要多源交叉）。

**核查**：**区分"无输出"与"读取失败"**：

```bash
# 严格模式：区分「不存在」与「读不到」
if v=$(xattr -p com.apple.quarantine "$f" 2>/tmp/xerr); then
  [ -n "$v" ] && echo -e "HAS\	$f\	$v"
else
  echo -e "ERR\	$f\	$(cat /tmp/xerr)"      # 记录错误原因
fi
```

**清单要标注覆盖率**：

> 「本次扫描 `~/Users` 下 N 个文件，其中 M 个带 `com.apple.quarantine` 属性，K 个读取失败（错误原因：权限不足 / 挂载实现限制，见附件）。**"无该属性"的文件数 = N − M − K。**」

**并对失败原因归类的文件做抽样复测**——如果是权限问题，用 `sudo` 复测一小批；如果是挂载实现限制，要在报告里写明"该挂载方式下 xattr 读取不完整，属性统计结果可能偏低"。

<a id="section-19"></a>

### 4.2 字段解码

<a id="section-20"></a>

#### 陷阱 3：把 Quarantine 的第二段当十进制 Unix 秒读

**现象**：看到 `0083;66D94E21;Safari;…`，把第二段直接丢给十进制解析，拿到一个时间就写进报告。本案里正确解码是 `2024-09-05 06:22:25 UTC`（= 14:22:25 +0800），而实际发生的是解析器**静默截断到前导数字**：

```text
sqlite> SELECT CAST('66d94e21' AS INTEGER);
66
# awk 同样： BEGIN{print "66d94e21"+0}  →  660
```

两种写法都不报错、不告警，直接产出 1970 年 1 月 1 日附近的时间。

**原因**：**第二段是十六进制编码的 Unix 秒**，而十进制解析遇到 `d`、`e` 这类字符时的行为是「读到第一个非法字符为止」。整串里恰好只由 `0-9` 组成的十六进制值（`66d94e21` 就不是，但 `65920080` 是）连这个静默截断都不会触发，`int()` 反而能成功，于是错得更彻底——`65920080` 被当成 Unix 秒是 1972-02-02，而它的正确含义是 2024-01-01。

**最危险的不是解析失败，而是解析「成功」了。** `printf '%d' 0x…` 与 `CAST(… AS INTEGER)` 都能通过，报告里也写出了一个格式完好的日期，审阅者没有理由怀疑——错误只在与其他工件对时间的时候才暴露。

**影响**：整条时间线落到 1970 年，所有跨源交叉验证全部作废。

这不是局部误差，它会污染所有基于这个时间的推断：与 Spotlight 的 `kMDItemFSCreationDate` 交叉验证必然失败（本来应该吻合）、与 FSEvents 事件对照会错开几十年、文件时间聚簇分析全部失效。更麻烦的是它不像「早几天」那样容易归因给时钟漂移，落到 1970 年的时间通常会被当成「这台机器没设对时」而顺手带过。

案例第 2 步用循环逐个显式写 `0x$v`，正是为了把这个转换变成不可省略的一步——如果哪天有人图省事写成 `date -u -r "$v"`，`date` 会直接报 usage 错误而不是给出一个假时间。

**核查**：**一律按十六进制解码，并把两种时间并列写出**：

```bash
for v in 66D94E18 66D94E21 66D94DA0 66D94D62; do
  printf '%s → %s\
' "$v" "$(date -u -r "$(printf '%d' "0x$v")" '+%Y-%m-%d %H:%M:%S UTC')"
done
# 66D94E21 → 2024-09-05 06:22:25 UTC = 2024-09-05 14:22:25 +0800
```

**报告会里同时给 UTC 和本地时间**，并注明"第二段为十六进制 Unix 秒"。

再加一道自检：解码出的时间应当与该文件的 `stat -f %SB`（创建时间）量级一致。若相差数月以上，通常是解码方式错了；但两者一致也不构成互证——`btime` 与下载时刻本就可以很接近，解码正确性最终以命令可复现为准。

<a id="section-21"></a>

#### 陷阱 4：把 `spctl --assess` 对普通文件的 `rejected` 当成异常

**现象**：对一个 `.txt` 或 `.csv` 执行 `spctl --assess --type execute --verbose`，返回 `rejected / no usable signature`，报告写「该文件未通过 Gatekeeper 校验，判定为不可信文件」。

**原因**：2.3 说过：对普通文件（如 `.txt`）返回 `rejected / no usable signature` 是正常结果，不是异常；真正决定 Gatekeeper 行为的是对应用包（`.app`）的评估。 Gatekeeper 那三道检查（代码签名、公证、Quarantine 触发）针对的是**可执行代码**，一个纯文本文件根本没有签名可言。

**影响**：会产生一批无意义的"高危文件"发现，淹没真正的异常；且这类结论在复核时容易被指出"对文本文件做 Gatekeeper 评估没有意义"。

**核查**：**按文件类型选择评估方式**：

```bash
# 应用包：完整评估
spctl --assess --type execute --verbose /Applications/Some.app
# → accepted  source=Notarized Developer ID
# → rejected  source=no usable signature
spctl --assess --type install --verbose /Applications/Some.app     # 安装包类型

# 签名检查
codesign -dv --verbose=4 /Applications/Some.app 2>&1 \
  | grep -E 'Identifier|TeamIdentifier|Authority|Timestamp'
codesign --verify --deep --strict --verbose=2 /Applications/Some.app 2>&1 | head -5
```

只对 `.app`、`.pkg`、`.dmg`、可执行二进制做 Gatekeeper 相关评估。

文本、数据类文件不适用——在报告里说明"该文件类型不适用 Gatekeeper 评估，故不作评估"，**而不是贴一个 `rejected` 的输出当发现**。

另外 `spctl --status` 要单独记录；`assessments enabled` 只说明执行该命令这一刻全局未被禁用，是评估结论有效性的前提，不说明历史时段的状态（见 5.3）。

<a id="section-22"></a>

### 4.3 属性缺失的解释

<a id="section-23"></a>

#### 陷阱 5：把 Quarantine 缺失直接写成"文件不是下载的"

**现象**：某文件没有 `com.apple.quarantine` 属性，报告结论写「该文件非网络下载所得，为本机生成或手动创建」。

**原因**：2.4 说过：Quarantine 的缺失不能直接等同于"文件不是下载的"。 那张表列了六种成因，其中**只有两种是人为的**：用户显式 `xattr -d` 删除、右键"打开"绕过（一次确认后系统清除该文件的 Quarantine）。**其余四种都是正常机制**：文件由程序生成（`cp` **不复制 xattr**）、拖入邮件附件后另存（属性不继承）、解压归档（**解压工具默认不还原 xattr**）、挂载到不保留 xattr 的文件系统（FAT32/exFAT 丢弃扩展属性）。

**影响**：这是不可辩护的阳性/阴性结论。而且它的危害是双向的。

若真实成因是"右键打开绕过"，你漏掉了一次 Gatekeeper 绕过行为；若真实成因是"解压归档不还原属性"，你却在报告里指控用户删除属性。

**核查**：**把六种成因作为标准清单逐项排除并记录**，且**只在有独立证据时才归因到人为**：

| 成因 | 排除方法 |
|---|---|
| 程序生成 | 查该目录是否有程序输出痕迹、同批文件是否都无属性 |
| `cp` 不复制 xattr | 查是否有同内容的另一路径文件带属性 |
| 解压不还原 | 查是否存在同名归档文件（`.zip`/`.tar`），该归档本身是否带属性 |
| 挂载到 FAT32/exFAT | 查文件来源卷类型 |
| 用户显式删除 | **需独立证据**（如 `securityd` 日志中的相关操作记录） |
| 右键"打开"绕过 | `securityd` 日志中的 assessment 记录 + 时间邻近 |

**报告写法（案例的标准做法）**：

> 「`RemoteTool-installer.pkg` 当前不带 Quarantine 属性，而同目录下 2024-09-05 14:19–14:22 下载的五个文件均带该属性。`securityd` 日志在 **2024-09-05 14:22:40** 有一条 `assessment` 记录，与 Quarantine 时间相差 15 秒。两条独立线索指向同一方向：用户下载后很快执行了打开/绕过操作，导致该文件的隔离属性被清除。」

注意案例的措辞是「**提示可能执行了绕过操作**」，而且专门加了写入约束：即使 `pkg` 的 `mtime` 是 14:25（晚于日志的 14:22:40），也只能写"属性缺失 + 时间邻近的评估记录，提示可能执行了绕过操作"，不能写"已确认用户删除了属性"。

<a id="section-24"></a>

#### 陷阱 6：把"属性缺失 + 时间邻近"直接定性为"已确认绕过"

**现象**：`securityd` 日志里有一条 14:22:40 的 `assessment` 记录，Quarantine 时间是 14:22:25，报告写「已确认用户在 14:22:40 执行了绕过操作」。

**原因**：**时间邻近是相关性，不是因果。** 两条记录属于同一时段，但"某文件触发了评估"与"用户主动删除了属性"之间仍有多种可能：系统的自动评估流程可能在其它条件下也触发；评估的对象可能不是这个文件；属性消失也可能有非人为成因（表格里的四种正常机制）。**"缺失 + 时间邻近"只能支撑"提示"这一档。**

**影响**：这是需要承担举证责任的定性。

案例那句写入约束就是为了防这一条——"已确认"三个字，会让对方只要找一个非人为成因就能推翻你的定性，而你基于它建立的所有推演（"用户故意规避 Gatekeeper""用户知晓风险"）一起失效。

**核查**：**定级与措辞严格对应证据强度**：

| 证据组合 | 允许的表述 |
|---|---|
| 仅"属性缺失" | 「未见 Quarantine 属性；成因见 2.4 清单，**不推断来源**」 |
| 属性缺失 + 时间邻近的 `securityd` 记录 | 「**提示**可能执行了打开/绕过操作」 |
| 属性缺失 + 日志明确记录了该文件的操作 + 独立的用户动作证据 | 「该 Quarantine 属性在 T 时刻被清除，**与用户 X 的操作时间吻合**」 |

`securityd` 的查询要注意用对参数（这是统一日志，默认只有 default/error 级别）：

```bash
/usr/bin/log show --last 30d --info --style json \
  --predicate 'subsystem == "com.apple.securityd"' \
  | grep -niE 'quarantine|assessment'
```

**`--info` 不能省**——大量 assessment 相关记录在 info 级别。

<a id="section-25"></a>

#### 陷阱 7：只查 `Downloads` 目录就写"已完成下载文件排查"

**现象**：`~/Downloads` 目录逐文件查完 Quarantine，报告写「已排查该用户全部下载文件」。

**原因**：`~/Downloads` 只是默认下载位置，不是全部。 文件可以从浏览器直接"另存为"到任意目录、从邮件客户端存到 Mail 目录、从聊天软件存到其容器目录，也可以落到桌面或文稿目录。而 Quarantine 属性是**跟着文件走的**——文件移到哪，属性就在哪。

**影响**：漏掉的目标文件可能正是关键物证。

案例里那个 `RemoteTool-installer.pkg` 就是在 `~/Downloads` 里被发现的，但如果没有 Downloads 之外的排查，"属性缺失"这个对比基准就无从建立——因为"同目录下五个文件带属性、一个不带"这个对比需要同目录其它文件作参照。

**核查**：**全机扫描，用 2.1 的只读循环**：

```bash
# 全机 Quarantine 提取（性价比最高的一步）
find /mnt/mac-data/Users -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv
wc -l /evidence/quarantine-all.tsv
```

**同时针对性搜可执行类文件**（5.1 步的做法），这类文件是"缺失属性"筛查的最佳对象——一个下载来的 `.dmg`/`.pkg`/`.app` 不带 Quarantine 才是真正需要解释的：

```bash
find /mnt/mac-data/Users \( -name '*.dmg' -o -name '*.pkg' -o -name '*.app' -o -name '*.app.tar.gz' \) -print0 \
| while IFS= read -r -d '' f; do
    xattr -p com.apple.quarantine "$f" >/dev/null 2>&1 || echo "无 Quarantine: $f"
  done > /evidence/no-quarantine-exec.txt
```

**报告里要给出扫描范围与文件数**，让"已排查"这个表述可验证。

<a id="section-26"></a>

### 4.4 结论表述

<a id="section-27"></a>

#### 陷阱 8：把 Quarantine 时间当文件创建时间

**现象**：从 Quarantine 解出 14:22:25，报告写「该文件创建于 14:22:25」。

**原因**：Quarantine 的时间戳是"下载时刻"，既不是"文件创建时刻"，也不是"文件内容修改时刻"。 文件下载后可能被解压（产生新文件）、重命名、移动、被编辑，这些操作都会让文件系统时间与 Quarantine 时间分叉。案例第 2 步的数据就是例子：五个文件的 Quarantine 时间集中在 14:19:14–14:22:25，而后续 `RemoteTool-installer.pkg` 的 `mtime` 是 14:25。

**影响**：三种时间混用会让时间线错乱，而"文件是什么时候产生的"往往是委托方最关心的问题之一。

**核查**：**四个时间分列，各自标注来源**：

| 时间 | 来源 | 语义 |
|---|---|---|
| 下载时刻 | Quarantine 第二段（十六进制解码） | 经网络下载路径的时刻 |
| 创建时刻 | `stat -f %SB`（`btime`） | 文件在文件系统上创建 |
| 内容修改时刻 | `stat -f %Sm`（`mtime`） | 文件内容最后修改 |
| 索引收录时刻 | `mdls -name kMDItemFSCreationDate` | Spotlight 记录的创建时间 |

**这四个时间之间的差值本身就是有价值的信息**——差值大说明文件下载后被多次处理。

**报告会里把四列并排列出**，而不是挑一个当"创建时间"。

<a id="section-28"></a>

#### 陷阱 9：把"同 UUID"与"同时间"两种聚类模式混用

**现象**：拿到一批 Quarantine 记录，用 UUID 聚类时发现 `客户名单-2024Q3.csv` 与其 `.zip` 的 UUID 不同，就判定"这是两次独立的下载"。

**原因**：UUID 是"每次下载"的唯一标识，但"同 UUID"与"同时间"代表的是两种不同的操作模式，含义几乎相反。 案例第 3 步的解读是标准：两个文件**UUID 不同但时间完全相同（14:22:25）**，说明"这是一个先压缩再下载、或下载后立即压缩的事件"；而同一 UUID 的多个文件 = 一次下载事件产生多个文件。把"UUID 不同"读成"两次独立下载"，就会漏掉"同一次会话内的连续操作"这个关键模式。

**影响**：误读聚类模式，这一整层推断就没了。

聚类模式能说明的是文件之间的关系形态（一次下载产生多个文件，还是同一时段内的多个独立动作），本身不包含行为意图；把它直接翻译成"准备外发"，还需要 `WhereFroms`、压缩包内容、统一日志与外发痕迹支撑（见 5.1 的 `WhereFroms` 判据）。

**核查**：**两种模式分别解读，报告里明确写出模式含义**：

```bash
awk -F'|' '{split($2,a,";"); print a[4], $1}' /evidence/q-dl.tsv | sort
# uuid=B2C3D4E5-…  客户名单-2024Q3.csv
# uuid=C3D4E5F6-…  客户名单-2024Q3.csv.zip      ← UUID 不同、时间相同
```

| 观察 | 正确的操作模式解读 |
|---|---|
| **同 UUID**，多文件 | **一次下载产生多个文件**（如 Safari 下载含多个资源的页面） |
| **不同 UUID，相同/相近时间** | **同一次会话内的连续或并行操作**（如下载后立即压缩） |
| 不同 UUID，明显不同时间 | 独立的下次行为 |

"不同 UUID + 相同时间"提示同一时段内存在连续或并行的多次下载，可作为继续核查的入口；它本身不指向任何具体意图。

<a id="section-29"></a>

#### 陷阱 10：把"存在 Quarantine 属性"当成"文件内容可信"

**现象**：一批文件都带 Quarantine 属性，报告据此认为"这些文件是正常下载的、内容可信"。

**原因**：Quarantine 记录的是"这个文件怎么到这台机器上来的"，不是"这个文件的内容是什么"。 来源可以是任意站点——包括被入侵的网站、被 DNS 劫持的域名、被投毒的下载页。属性正常只说明"走了正常的下载路径"，不说明"来源是安全的"。

**影响**：把"传输路径正常"读成"文件可信"，会放过恰恰最需要检查的一类文件——**从被入侵或仿冒站点下载的文件**。

案例里来源域名是 `portal.rival-exim.example`（竞争对手），属性完全正常，但文件内容恰恰是敏感的客户名单。

**核查**：Quarantine 属性与来源可信度是两个独立维度，报告里分开评估：

> 「该文件经 Safari 下载（Quarantine 属性存在，`0083;66D94E21;Safari;…`，下载时刻 2024-09-05 14:22:25 +0800）。来源 URL 为 `https://portal.rival-exim.example/api/export?type=customer`，系竞争对手域名。」

Quarantine 属性的作用是**证明该文件经过下载通道并给出下载时刻**，来源域名则回答"来源是否可信"，两者配合才完整。

域名本身的性质（是否竞争对手、是否仿冒知名站点、是否新注册域名）需要单独分析，这属于委托方业务判断的范围。但**取证方有责任把 URL 完整呈现出来**，不做筛选。

<a id="section-30"></a>

## 五、案例示例

<a id="section-31"></a>

### 5.1 十六进制解码与 UUID 聚类还原下载序列

**场景**

MacBook Pro（Apple Silicon M2，macOS 13.6，FileVault 已解锁）。委托方为外贸公司，怀疑员工私自下载竞争对手的客户名单并转发。检材 `DigiForensics.dd`（raw APFS 容器镜像）。

这里的关键在于 `com.apple.quarantine` 的第 2 段是十六进制 Unix 时间戳，而它与第 4 段的下载 UUID 组合起来，能同时还原"什么时候"和"哪几次"。

**处置过程**

第 1 步，Downloads 目录抽样：

```bash
EV=/mnt/mac-data/Users/chenhao
for f in "$EV/Downloads"/*; do
  [ -f "$f" ] && { v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null); \
    [ -n "$v" ] && echo "$f|$v"; }
done
```

```
# /Users/chenhao/Downloads/客户名单-2024Q3.csv|0083;66D94E18;Safari;B2C3D4E5-…
# /Users/chenhao/Downloads/客户名单-2024Q3.zip|0083;66D94E21;Safari;C3D4E5F6-…
# /Users/chenhao/Downloads/invoice_A.pdf|0083;66D94DA0;Safari;A4B5C6D7-…
# /Users/chenhao/Downloads/setup-remote-tool.dmg|0083;66D94D62;Chrome;A5B6C7D8-…
```

第 2 步，**解码（第 2 段必须按十六进制处理）**：

```bash
for v in 66D94E18 66D94E21 66D94DA0 66D94D62; do
  printf '%s → %s\
' "$v" "$(date -u -r "$(printf '%d' "0x$v")" '+%Y-%m-%d %H:%M:%S UTC')"
done
# 66D94E18 → 2024-09-05 06:22:16 UTC = 2024-09-05 14:22:16 +0800
# 66D94E21 → 2024-09-05 06:22:25 UTC = 2024-09-05 14:22:25 +0800
# 66D94DA0 → 2024-09-05 06:20:16 UTC = 2024-09-05 14:20:16 +0800
# 66D94D62 → 2024-09-05 06:19:14 UTC = 2024-09-05 14:19:14 +0800
```

四个文件集中在 2024-09-05 14:19:14 – 14:22:25 的 3 分 11 秒内下载，三个来自 Safari、一个来自 Chrome。

第 3 步，**UUID 聚类（本案的关键分析手法）**：

```bash
awk -F'|' '{split($2,a,";"); print a[4], $1}' /evidence/q-dl.tsv \
  | while read -r uuid f; do
      ep=$(xattr -p com.apple.quarantine "/mnt/mac-data$f" | cut -d';' -f2)
      printf '%s  %s  %s\
' "$uuid" "$(date -r "$(printf '%d' "0x$ep")" '+%H:%M:%S')" "$(basename "$f")"
    done | sort -k2
# B2C3D4E5-2222-…  14:22:16  客户名单-2024Q3.csv
# C3D4E5F6-3333-…  14:22:25  客户名单-2024Q3.zip
# A4B5C6D7-4444-…  14:20:16  invoice_A.pdf
# A5B6C7D8-5555-…  14:19:14  setup-remote-tool.dmg
```

**UUID 全部互不相同** —— 说明这是 4 次独立的下载事件，不是一次下载产生多个文件。

第 4 步，与 Spotlight 来源配对：

```bash
mdls -name kMDItemWhereFroms -name kMDItemFSCreationDate \
  /Users/chenhao/Downloads/客户名单-2024Q3.csv
# kMDItemWhereFroms = ("https://portal.rival-exim.example/api/export?type=customer")
# kMDItemFSCreationDate = 2024-09-05 14:22:25 +0800
```

两处时间需要分开写：Quarantine 解码给出下载时刻 14:22:16，Spotlight `kMDItemFSCreationDate` 给出索引记录的创建时间 14:22:25。两者语义不同，差 9 秒不构成矛盾，但也不能当作互相印证——`kMDItemFSCreationDate` 与文件系统 `btime` 同源，且 `kMDItemWhereFroms` 与 Quarantine 都由同一下载栈在写入时打上，属于同一环节的两处记录。真正独立的是解压复制品上的属性验证（第 5 步）与后续的 `WhereFroms` 判别。

域名 `rival-exim` 的性质由 URL 字面呈现，判定该域名属于竞争对手的业务判断由委托方确认。

第 5 步，检查文件内容与压缩包的关系（**判别下载 vs 压缩**）：

```bash
unzip -l /mnt/mac-data/Users/chenhao/Downloads/客户名单-2024Q3.zip
#   1 file, 2.1 MB
#   客户名单-2024Q3.csv
# → 压缩包内只有一个文件，就是同目录下那个 CSV

md5sum /mnt/mac-data/Users/chenhao/Downloads/客户名单-2024Q3.csv
md5sum <(unzip -p /mnt/mac-data/Users/chenhao/Downloads/客户名单-2024Q3.zip 客户名单-2024Q3.csv)
# 7c8d9e0f1a2b…  （两者一致）
# → ★ zip 内的 CSV 与同目录的 CSV 内容完全相同

stat -f 'btime=%SB  mtime=%Sm  %N' -t '%Y-%m-%d %H:%M:%S' \
  /mnt/mac-data/Users/chenhao/Downloads/客户名单-2024Q3.zip
# btime=2024-09-05 14:22:25   mtime=2024-09-05 14:22:25
```

CSV 的 Quarantine 下载时间 14:22:16，zip 的 `btime` 14:22:25 —— zip 晚 9 秒，且其内容是 CSV 的精确副本。时间与内容两项都只与"同一次会话内先后处理了这两个文件"相容，"下载后立即压缩"是其中一种解释，第 6 步用来判别。

第 6 步，**查外发证据（这一步的结果决定了结论能到哪一档）**：

```bash
# 浏览器下载记录里有没有 zip 的 URL（若有，说明 zip 也是下载来的而非本地生成）
mdls -name kMDItemWhereFroms /Users/chenhao/Downloads/客户名单-2024Q3.zip
# kMDItemWhereFroms = ("https://files.rival-exim.example/pub/customer-list-q3.zip")
# → ★ zip 也有来源 URL！说明 zip 本身也是下载的

# 本地压缩不会有 WhereFroms
# 统一日志里有无传输记录
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2024-09-05 14:00" --end "2024-09-05 15:00" --style compact \
  --predicate 'subsystem == "com.apple.network"' | grep -iE 'upload|POST' | head -5
# （无记录）→ 无上传类事件
```

**结论**

| 结论 | 支撑证据 | 强度 |
|---|---|---|
| 2024-09-05 14:22:16 下载客户名单 CSV | Quarantine 解码 + `WhereFroms` + Quarantine UUID | 强 |
| 来源为 `portal.rival-exim.example` | `WhereFroms` URL；域名性质由委托方业务判断确认 | 强（URL 事实）/ 域名定性需委托方确认 |
| CSV 与 zip 在同一时段内先后出现，zip 内容为 CSV 的副本 | zip `btime` 14:22:25 晚 9 秒 + zip 内 MD5 与 CSV 一致 | 强（文件关系成立），但**不足以判定"本地压缩"** |
| zip 本身亦来自 `files.rival-exim.example` 的文件服务器 | zip 的 `WhereFroms` = `files.rival-exim.example/pub/customer-list-q3.zip` | 强 |
| 文件已外发 | — | **无证据，不作此结论**（统一日志在该时段未见上传类事件，但统一日志的覆盖边界须先按 5.3 交代） |

**本案有一条容易被跳过的核查**：zip 的 `kMDItemWhereFroms` 是存在的。

因此准确结论是「该机下载了 CSV 与其 zip 两种格式（相隔 9 秒，来自同一对手的两个端点）」，**而不是**"用户下载 CSV 后本地压缩"。

带 `WhereFroms` 的 zip 是下载产物，不带才是本地压缩产物——这个判据必须先查，它直接改变行为的定性。

**误判对照**

本案最容易得出的错误结论是「CSV 下载于 14:22:16，zip 下载于 14:22:25，两者 UUID 不同但时间接近，说明用户先下载 CSV、在本地压缩成 zip（间隔仅 9 秒，正是手工操作压缩所需的时间），这是"准备外发"的间接证据」。

正确判据是 `kMDItemWhereFroms` 在 zip 上是否存在，这是区分"本地压缩"与"下载所得"的决定性字段：

1. 本地生成的文件没有 `kMDItemWhereFroms`。这个属性由系统的下载栈（Safari/Chrome/curl 等）在文件**写入时**打上，**只有经过下载通道的文件才会有**。用户用 Archive Utility 或 `zip` 命令在本地压缩出的文件，其 `WhereFroms` 为空。
2. 本案 zip 的 `WhereFroms` 指向 `https://files.rival-exim.example/pub/customer-list-q3.zip`，且 zip 的 Quarantine UUID 与 CSV 不同、时间晚 9 秒。这两个事实共同说明：**zip 是从对手的另一个文件服务器路径下载的**，用户（或页面脚本）几乎同时取了两种格式。
3. 9 秒的间隔在"下载两个文件"与"手工压缩"两种解释下都成立，**仅靠时间无法区分**——这正是必须查 `WhereFroms` 的原因。手工压缩 CSV 为 289KB 的文件通常在 1–2 秒内完成（9 秒更像是切换下载目标的时间），但这个推断**不如 `WhereFroms` 可靠**。

**按错误判据走的代价**：会得出"下载后立刻本地压缩，说明正在准备外发"的行为定性，**并据此推断一个后续的外发动作**。而实际上 zip 也是下载的，**用户并没有执行任何本地加工动作**。这个差别很关键：

- "下载后压缩" = 主动的加工行为；
- "同时下载两种格式" = 获取行为，也可能是页面或脚本一次性发起的请求，未必对应两次独立的人工操作。

误判会把一个"获取"行为升级为"准备外发"的预备动作，性质与法律含义都不同；而且后续若找不到外发证据，报告里那句"准备外发"就成了无支撑的推断，质证时会被直接推翻。

第二个易错点：把 Quarantine 的第 2 段当十进制解读。

正确判据是它的编码形式——**十六进制**，且不能省略 `0x` 前缀。

漏掉前缀的后果分两种，都不报错：`date -u -r 66D94E18` 会报 usage 用法错误（这个还算幸运），但 `sqlite` 的 `CAST('66D94E18' AS INTEGER)` 会**静默返回 66**，`awk` 的 `+0` 返回 660——直接给出 1970 年附近的时间。值里恰好没有 `a`–`f` 时（`65920080` 就是），连静默截断都不会发生，`int()` 顺利返回，错得更彻底。

**必须显式指定十六进制转换**（`printf '%d' "0x$ep"`），并在报告中附上解码命令让复核人能复现。

**按这个区分，误判代价是整条时间线错位**：本案的正确时间是 2024-09-05，若漏掉 `0x` 前缀则会落到 1970 年附近，与 `btime` 这类独立时间来源立刻对不上。

**这类错误通常能被时间量级对照发现**；真正危险的是"错得刚好对得上"的情况，所以解码命令必须写进报告以便复核。

---

<a id="section-32"></a>

### 5.2 Quarantine 属性缺失的五种成因排查

**场景**

同系列 MacBook（macOS 13.6），委托方在分析中发现 `~/Downloads/RemoteTool-installer.pkg` **不带 Quarantine 属性**，而同目录其他下载文件都带，怀疑该文件是"本地生成以规避 Gatekeeper"。检材 `DigiForensics.dd`（APFS 容器镜像）。

Quarantine 属性缺失有多种成因（2.4 列了七类，本案按可核查的五类排查），它们的取证含义不同**——把"缺失"直接读成"人为清除"会把阴性现象升格为定性指控**。

**处置过程**

第 1 步，先建立"应该有却有"的基线（**这是判定的起点**）：

```bash
EV=/mnt/mac-data/Users/chenhao
# 同目录其他下载文件的 Quarantine 状态
for f in "$EV/Downloads"/*; do
  [ -f "$f" ] || continue
  case "$f" in
    *.dmg|*.pkg|*.app)
      q=$(xattr -p com.apple.quarantine "$f" 2>/dev/null)
      printf '%-46s %s\
' "$(basename "$f")" "${q:-★ 无 Quarantine}";;
  esac
done
# setup-remote-tool.dmg        0083;66D94D62;Chrome;A5B6C7D8-…
# RemoteTool-installer.pkg    ★ 无 Quarantine
# 另两个 .dmg 均有属性
```

第 2 步，查**五种成因的逐一证据**，而不是直接下结论：

```bash
# 成因①：从压缩包/外接盘解出（解包会清除隔离标记）
xattr -l "$EV/Downloads/RemoteTool-installer.pkg" | head
# com.apple.metadata:com_apple_backup_exclude_item:BEGIN
# → 无 com.apple.quarantine

# 该 pkg 是否与某个 zip 同批产生？
ls -l --time-style=long-iso "$EV/Downloads" | grep -E 'zip|pkg'
# -rw-r--r-- 1720320 2024-09-05 14:22:25  tools-bundle.zip
# -rw-r--r--  884736 2024-09-05 14:25:11  RemoteTool-installer.pkg
# → ★ pkg 晚于 zip 2 分 46 秒

# 成因②：由程序生成（下载器/解压器写出）
xattr -l "$EV/Downloads/tools-bundle.zip" | grep -c quarantine
# 1   → zip 自己带 Quarantine（它是下载的）

# 成因③：经 exFAT/移动盘中转（属性不随文件复制）
diskutil info /Volumes/EVIDENCE-USB 2>/dev/null | grep -E 'File System Personality|Type'
# msdos/exfat；External Device: Yes
# → ★ 存在外接 exFAT 卷

# 成因④：属性被显式清除（xattr -c / 绕过操作）
# 成因⑤：本来就在白名单路径（系统应用、临时目录等）
ls -d /tmp/*RemoteTool* "$EV/Library/Caches"/*RemoteTool* 2>/dev/null
# （无输出）→ 不在白名单路径
```

第 3 步，查 `securityd` 的评估日志（**这是"曾经被打开过"的独立证据**）：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2024-09-05 14:20" --end "2024-09-05 14:35" --style compact \
  --predicate 'subsystem == "com.apple.securityd"' \
  | grep -iE 'assessment|quarantine|RemoteTool' | head -6
# 2024-09-05 14:22:40.118  securityd[881]: Client (Safari) trying to access assessment for RemoteTool-installer.pkg
# 2024-09-05 14:25:09.774  securityd[881]: assessment failed for RemoteTool-installer.pkg (reason=source not notarized)
# → ★ 两条记录：14:22:40 评估请求、14:25:09 评估失败
```

第 4 步，用文件时间戳把序列拼起来（**关键：分清哪个时间支持哪个结论**）：

```bash
stat -f 'btime=%SB  mtime=%Sm  ctime=%Sc  %N' -t '%Y-%m-%d %H:%M:%S' \
  "$EV/Downloads/RemoteTool-installer.pkg"
# btime=2024-09-05 14:25:11   mtime=2024-09-05 14:25:11   ctime=2024-09-05 14:25:11
# ★ 三者相同 → 该文件在 14:25:11 这个时刻被一次性写入（创建或整体替换）
```

**关键推理**：`btime` = `mtime` = `ctime` = 14:25:11，说明该路径上的这一份文件是在 14:25:11 整体创建的。

这个形态与"先有文件、其后单独清除属性"不一致（后一种情形下 `ctime` 会晚于 `btime`），与"整体写入一份本来就不带该属性的文件"一致——但两者的区分还需要第 5 步的内容验证，不能只靠时间戳形态定案。

而 `securityd` 在 **14:25:09** 记录了对**同名文件**的评估失败（早 2 秒）。

第 5 步，验证 zip 与 pkg 的内容关系（**这将定性定案**）：

```bash
unzip -l "$EV/Downloads/tools-bundle.zip"
#   3 files, 3.1 MB
#   RemoteTool/RemoteTool-installer.pkg        884736
#   RemoteTool/README.txt                         1024
#   RemoteTool/launch.sh                            412
# → ★ zip 内确实含同名 pkg，大小 884736 = 与 Downloads 下完全一致

mkdir -p /tmp/vfy && cd /tmp/vfy
unzip -o -q "$EV/Downloads/tools-bundle.zip" RemoteTool/RemoteTool-installer.pkg
shasum -a 256 /tmp/vfy/RemoteTool/RemoteTool-installer.pkg
shasum -a 256 "$EV/Downloads/RemoteTool-installer.pkg"
# b1c2d3…  （两者一致）
xattr -l /tmp/vfy/RemoteTool/RemoteTool-installer.pkg | grep -c quarantine
# 0   → ★ 解压出来的副本同样不带 Quarantine
```

决定性结果：从 zip 解压出来的副本，天然不带 Quarantine 属性。

而 zip 本身是 14:22:25 下载的（带 Quarantine）。

这就完整解释了 14:25:11 这个文件的来源与属性状态。

**结论**

- **成因确定为"从压缩包解压"**，证据链完整：`tools-bundle.zip`（14:22:25 下载、带 Quarantine、UUID `D3E4F5A6-…`）→ 内含同名同大小的 `RemoteTool-installer.pkg`（884736 字节）→ 14:25:11 解压到 `~/Downloads/`（`btime`=`mtime`=`ctime`）→ **解压产物天然不带 Quarantine**（`unzip` 到临时目录的副本验证为 0 个属性）。
- `securityd` 的两条日志（14:22:40 评估请求、14:25:09 评估失败 `source not notarized`）只记录了文件名，没有记录文件实例标识；14:25:09 早于该路径上文件的 14:25:11 创建时间，因此这两条记录不能用来证明 14:25:11 这一份文件被评估过，更不能串成"用户打开并绕过了 Gatekeeper"。
- 因此**不成立**的结论有两个：「用户手动清除了 Quarantine 属性」（无证据，且 `btime`=`ctime` 与"属性后被清除"的形态不符）与「用户执行了 Gatekeeper 绕过操作」（本案未采集到 `xattr -c` 类操作的日志，也没有指向该份文件的评估记录；`spctl --status` 只能反映执行该命令时刻的全局状态，不能用于证明历史时段）。
- 对委托方问题的准确答复：「`RemoteTool-installer.pkg` 不带 Quarantine 属性，成因是该文件由 `tools-bundle.zip` 于 2024-09-05 14:25:11 解压产生（已通过解压副本属性为 0 与内容哈希一致双重验证）。

本案无证据表明该属性被手动清除，也无证据表明用户执行了 Gatekeeper 绕过操作。」

**误判对照**

本案最容易得出的错误结论是「`RemoteTool-installer.pkg` 没有任何 Quarantine 属性，而同目录其他下载文件都有，说明用户在下载后主动执行了 `xattr -c` 清除了隔离标记，这是明确的 Gatekeeper 绕过反取证行为」。

正确判据是 `btime` 与 `ctime` 的关系，配合内容验证：

1. **如果属性是被事后清除的，文件必须先存在**。清除 `com.apple.quarantine` 是一个**元数据操作**，它会**推进 `ctime` 但不改变 `btime`**。因此该形态应为 `btime` < `ctime`。需要注意 `ctime` 也可能被移动、改权限等其它元数据操作推进，因此 `ctime ≫ btime` 只是必要条件，不是充分证据。
2. 本案三个时间戳完全相同（`btime` = `mtime` = `ctime` = 14:25:11），这与"属性后被清除"的形态不符，更符合"文件以不带该属性的状态被整体创建"。
3. **成因①的验证是可复现的**。`unzip` 出一个副本，`xattr -l` 查属性——**结果为 0**，同时内容哈希与目标一致。这把"缺失"归因到一个可复现的机制，而不是推测。把"缺失"归因于一个可验证的机制，比归因于"人为清除"更可靠。

**按错误判据走的代价**：会得出一个**明确的绕过行为指控**，指向"主动规避安全机制"这一严重的合规问题。后果是：

- 委托方可能据此对该员工启动纪律处分，因为"手动清除 Quarantine"在 macOS 安全基线里属于明确的高危操作；
- **而实际上该文件只是解压产物**，用户甚至可能不知道它"本来应该有"这个属性（`tools-bundle.zip` 里的 `README.txt` 甚至可能说明了这是给终端用户的安装包）；
- 更实际的是，**这条错误结论会掩盖真正值得核查的问题**——那个 zip 包里除了 pkg 还有 `launch.sh`（一个 412 字节的脚本），脚本内容才是判断"这个工具打算做什么"的关键，而它被一个错误的定性盖过去了。

**五种成因的排查顺序（本案的实际路径）**：

| 成因 | 判据 | 本案结果 |
|---|---|---|
| ① 从压缩包/外接盘解出 | 同名文件在 zip/iso 中存在；解压副本属性为 0 | ✅ **成立** |
| ② 程序生成 | 下载器写出；无 `WhereFroms` 且无 Quarantine | 排除（有 zip 载体） |
| ③ exFAT/移动盘中转 | 存在外接 exFAT 卷；中转会丢属性 | 存在外接卷，但**无证据表明走了这条路** |
| ④ 属性被显式清除 | `ctime` ≫ `btime`；`securityd`/`xattr` 操作日志 | 排除（三时间戳相等） |
| ⑤ 白名单路径 | 位于系统应用目录/临时目录 | 排除（在 `~/Downloads`） |

第二个易错点：因为发现了外接 exFAT 卷 `EVIDENCE-USB`，就把成因③当成结论。 正确判据是**"存在外接卷"与"本文件经过该卷"是两件事**。要成立需要：文件内容与外接卷上某个文件哈希一致、或外接卷的访问时间与 14:25:11 吻合、或该文件的 `btime` 与外接卷上的副本 `btime` 呈现拷贝关系。本案三者均未验证，因此成因③只能列为"待排除项"，不能写成结论。 正确写法是「本机存在外接 exFAT 卷 `EVIDENCE-USB`，该卷会导致 Quarantine 属性丢失，但**本案无证据表明本文件经由该卷**，故成因③未成立亦未排除。」

---

<a id="section-33"></a>

### 5.3 反例：Gatekeeper 全局状态与评估日志的时间覆盖边界

**场景**

某台 MacBook Air（macOS 14.5），委托方要求判断"这台机器上的 Gatekeeper 保护在事发时是否被关闭过"。检材 `DigiForensics.dd`（APFS 容器镜像）。Gatekeeper 的策略状态本身会变，而取证能看到的只是"当前状态"与"日志覆盖期内的事件"，两者都不是历史状态**——这个边界不划清，就会写出无法支撑的结论。

**处置过程**

第 1 步，取**当前**策略状态（**这一步只能说明"现在"，不能说明"当时"**）：

```bash
spctl --status
# System integrity protection status: enabled.
# assessed by the vendor in the latest system receipt: enabled
# Gatekeeper is enabled on this Mac.

# 读取策略数据库的 plist（策略变更会写入这里）
plutil -p /Library/Preferences/com.apple.security.plist 2>/dev/null | head
#（该文件在新版本 macOS 上不存在，策略内建于 SIP 保护的系统卷）
```

第 2 步，**查策略变更的日志记录**（这才是"是否被改过"的证据）：

```bash
/usr/bin/log show --directory /mnt/mac-data/var/db/diagnostics \
  --start "2024-01-01" --end "2025-03-18" --style compact \
  --predicate 'process == "syspolicyd" OR process == "taskgated-helper" OR process == "spctl"' \
  > /evidence/gk-events.txt
wc -l /evidence/gk-events.txt
# 88241 条

# 关键：有没有"策略被修改"的事件
grep -iE 'spctl.*(disable|enable)|policy.*(changed|updated)|assessments (enabled|disabled)' /evidence/gk-events.txt | head
# 2024-03-02 11:22:08  syspolicyd[901]: Gatekeeper assessments disabled by user request (MDSetSetup: kMDMSetGatekeeperDisabled)
# → ★ 2024-03-02 有关闭事件
```

第 3 步，**确定这次关闭持续了多久、何时恢复**：

```bash
grep -nE 'assessments (disabled|enabled)' /evidence/gk-events.txt
# 8841: 2024-03-02 11:22:08  assessments disabled by user request
# 10233: 2024-03-02 11:48:55  assessments enabled (previous disable expired after 15 minutes)
# → ★ 仅持续 26 分 47 秒，且日志明说是"15 分钟后自动过期"

# 关闭期间发生的评估
awk '/2024-03-02 11:2[2-4]/ && /assessment/' /evidence/gk-events.txt | head -5
# 2024-03-02 11:23:14  syspolicyd[901]: assessment skipped (Gatekeeper disabled) for /Users/xiaomi/Downloads/Tool.dmg
# 2024-03-02 11:29:41  syspolicyd[901]: assessment skipped (Gatekeeper disabled) for /Users/xiaomi/Downloads/Update.pkg
# → ★ 有 2 个文件在关闭期间被"跳过评估"直接放行
```

第 4 步，确认 SIP 状态（这决定了策略能否被持久化篡改）：

```bash
csrutil status
# System Integrity Protection status: enabled.
```

第 5 步，**查日志本身的覆盖边界（这是本案例的核心）**：

```bash
DIAG=/mnt/mac-data/var/db/diagnostics
ls -1 $DIAG/Persist/*.tracev3 | wc -l
# 1102
stat -f '%Sm' -t '%Y-%m-%d' $DIAG/Persist/0000000000000a1f.tracev3
# 2024-01-08        ← 日志最早只到 2024-01-08

# 该机首次开机时间（从检材）
last -f /mnt/mac-data/private/var/log/wtmp reboot | tail -1
# reboot   boot   Fri Jan  5 09:12:11 2024   still running
# → ★ 机器 01-05 开机，日志最早 01-08 → 前 3 天空白
```

**结论**

- Gatekeeper 在 2024-03-02 11:22:08 被关闭过一次，但仅持续 26 分 47 秒（11:48:55 自动恢复），日志明确写明原因是 `previous disable expired after 15 minutes`（这是 macOS 的设计：允许用户临时关闭 15 分钟用于安装非商店应用，到期自动恢复）。
- **关闭期间有 2 个文件被跳过评估**：`Tool.dmg`（11:23:14）与 `Update.pkg`（11:29:41）。日志能证明的是这两个文件在 Gatekeeper 未生效时跳过了评估，**不能证明它们随后被运行或安装**；是否真的被执行需要执行类证据（执行痕迹、日志、后续文件变化）另行确认。
- **SIP 全程 enabled**，说明未发现通过修改受保护系统卷文件来长期关闭 Gatekeeper 的迹象；这限定的是该路径的可行性，不等于排除其它持久化方式。
- **必须写明的三条覆盖边界**：
  1. `spctl --status` 只反映当前状态（enabled），不能证明事发时（2024-03-02）也是 enabled。 本案的历史状态结论**来自 `syspolicyd` 日志**，不是来自 `spctl`。
  2. 统一日志最早只到 2024-01-08，而机器 01-05 首次开机——2024-01-05 至 01-08 共 3 天的策略变更事件不可查。
  3. 本机曾使用过 U 盘 `EVIDENCE-USB`（exFAT），若曾从该盘运行未签名程序，其评估事件可能因路径豁免而不记入 syspolicyd 日志。该路径未覆盖。
- 对委托方问题的答复：「在统一日志可查区间（2024-01-08 至 2025-03-18）内，Gatekeeper 被关闭 1 次（2024-03-02 11:22:08–11:48:55，系统 15 分钟自动过期机制所致，非持久篡改），期间 2 个文件跳过评估直接放行。2024-01-05 至 01-08 的 3 天因日志覆盖限制不可查。SIP 全程启用。」

**误判对照**

本案最容易得出的错误结论有两个，方向相反但都源于**用当前状态回答历史问题**。

误判 A：「`spctl --status` 显示 Gatekeeper is enabled，因此事发时（2024-03-02）Gatekeeper 也是启用的，保护没有被绕过。」 正确判据是 **`syspolicyd` 日志里那条明确记录**：`2024-03-02 11:22:08 assessments disabled by user request`，且 11:23:14 与 11:29:41 有两个文件 `assessment skipped (Gatekeeper disabled)`。`spctl --status` 查的是**执行该命令那一刻的状态**（今天是 enabled），它**对 2024-03-02 的状态一无所知**。

**按误判 A 走的代价**：会得出"保护未被绕过"的结论，从而**漏掉两个在无保护状态下被跳过评估的文件**。这类错误危险之处在于结论看起来很干净。

误判 B（反向，同样源于此处）：「发现 2024-03-02 有 Gatekeeper 被关闭，就说明攻击者曾长期关闭系统安全机制进行渗透，具备系统级攻击能力。」 正确判据是**三条具体字段**：

1. 关闭持续 26 分 47 秒，且日志明写 `previous disable expired after 15 minutes` —— 这是 **macOS 的标准用户操作路径**（在"系统设置 → 隐私与安全性"里点"仍要打开"时系统提供的临时豁免），**不是持久化篡改**。
2. **SIP 全程 enabled** —— 未发现系统卷受保护文件被改写的迹象，因此"通过修改系统文件长期维持 Gatekeeper 关闭"这一路径不成立。
3. **关闭是 `by user request`** —— 日志字面标明是用户请求来源；这描述的是发起方，不排除发起者身份仍需另证。要主张"攻击者所为"，需要额外的证据（如该时段有远程访问痕迹），**本案没有**。

**按误判 B 走的代价**：会把一次可能是常规的非商店软件安装操作升级为"具备系统级攻击能力的攻击者行为"，高估威胁等级；风险评级错位会让委托方投入不必要的反制资源。

第二个易错点：忽略日志覆盖期，把"2024-01-08 之前无策略变更事件"当成"2024-01-08 之前 Gatekeeper 未被改动"。 正确判据是**先确认日志的起点，再用机器的开机时间做对照**：

- 机器首次开机 2024-01-05 09:12:11；
- 日志最早记录 2024-01-08；
- **二者相差 3 天，这 3 天的策略状态不可知。**

**必须写进报告的措辞**：「统一日志覆盖期为 2024-01-08 至 2025-03-18；该机 2024-01-05 首次开机，故 2024-01-05 至 01-08 的 3 天内无日志记录，该时段的 Gatekeeper 状态不可查。」**而不是**"日志中未发现更早的策略变更"。这两个表述在质证时的分量完全不同。

---

<a id="section-34"></a>

## 六、扩展阅读方向

**前置与基础。** Quarantine 落在扩展属性上，所以先要弄清 APFS 的 xattr
存在哪里，以及 `com.apple.provenance` 的语义在不同系统版本上如何演化。
公证机制是另一半地基：notarization ticket、stapled ticket 的区别，
以及离线校验流程在没有网络时怎么走完。

**同层深入。** 签名体系决定了判定结果，Developer ID 与 Gatekeeper 策略文件的
位置、优先级要理清——策略被企业 MDM 下发时，它与本地配置的冲突规则
直接改变 `spctl` 的输出。AppleDouble 的 `._*` 文件结构与资源分支
则提供了一条旁路痕迹，很多被重新封装过的文件在那里留下旁证。

**相邻议题。** Gatekeeper 自身在 10.15 前后经历过策略切换，
`spctl` 工具的演进与部分子命令的废弃，会让老文章里的命令在新系统上
静默失效。多源互校是这一层实用的方法：Quarantine 属性、
`kMDItemWhereFroms`、浏览器下载记录相互校正。但要按写入方区分独立性——
`WhereFroms` 与 Quarantine 都由下载栈在同一次下载写入时打上，属同一环节的两处记录（见 5.1），浏览器侧的历史记录才是另一条线；单靠任何一源都会漏掉「经由另一台机器中转」的情况。

**工具与判据。** Quarantine 属性向 `LSQuarantineEventURL` 追溯真实来源，
配合 Spotlight 可以还原文件的完整流转路径，
见 [《Spotlight索引与元数据》](../computer-plist-spotlight/computer-plist-spotlight-spotlight.md)；
属性本身的解析方法见 [《plist与偏好设置》](../computer-plist-spotlight/computer-plist-spotlight-plist.md)。

**判据与反例。** 属性缺失是这条线上最常见的假阴性：
手工清除过属性的文件不会有任何记录，用户直接从网络卷复制的文件
也可能根本不写 Quarantine。判定证据强度时要显式套用
[《取证概念与分类》](../../fundamentals/fundamentals-concepts/fundamentals-concepts-digital-forensics-concepts.md)
里的「痕迹缺失不等于事实未发生」——无记录只能支持
「无法证明发生过」，不能支持「未发生」。

---

<a id="section-35"></a>

## 七、命令速查

```bash
# ===== 1. 读取（★ 只读，禁止 -w/-d/-c）=====
xattr -l <file>                            # 列出全部属性名与长度
xattr -p com.apple.quarantine <file>       # 打印 Quarantine 值
find "$EV" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
  v=$(xattr -p com.apple.quarantine "$f" 2>/dev/null) || continue
  [ -n "$v" ] && printf '%s\	%s\
' "$f" "$v"
done > /evidence/quarantine-all.tsv

# ===== 2. 四段解码（★ 第 2 段是十六进制 Unix 秒）=====
q=$(xattr -p com.apple.quarantine "$f")
IFS=';' read -r flag ts app uuid <<< "$q"
printf 'flags=%s time=%s app=%s uuid=%s\
' "$flag" \
  "$(date -u -r "$(printf '%d' "0x$ts")" '+%Y-%m-%d %H:%M:%S UTC')" "$app" "$uuid"
# 0083;5f56283b;Safari;<UUID>  →  0x5f56283b = 1599551515 = 2020-09-07 12:31:55 UTC

# ===== 3. 分布统计 =====
cut -f2 /evidence/quarantine-all.tsv | cut -d';' -f3 | sort | uniq -c | sort -rn

# ===== 4. 签名与评估 =====
codesign -dv --verbose=4 /Applications/App.app 2>&1 | grep -E 'Identifier|TeamIdentifier|Authority'
codesign --verify --deep --strict --verbose=2 /Applications/App.app
spctl --assess --type execute --verbose /Applications/App.app   # accepted / rejected
spctl --status                                                     # assessments enabled
codesign -d --entitlements - /Applications/App.app 2>&1 | head -20

# ===== 5. Gatekeeper 日志 =====
/usr/bin/log show --last 30d --info --style json \
  --predicate 'subsystem == "com.apple.securityd"' > /evidence/securityd.log
grep -niE 'quarantine|notariz|gatekeeper|assessment|reject' /evidence/securityd.log | head -40

# ===== 6. Spotlight 配对（见第 4 篇）=====
mdls -name kMDItemWhereFroms -name kMDItemFSCreationDate <file>

# ===== 7. 禁止 / 谨慎 =====
# xattr -w / -d / -c  ← 改写检材，等同篡改证据
# spctl --add       ← 现代 macOS 已移除该选项（实测 "no longer supported"）
# 注意：.DS_Store 不含 URL，AppleDouble（._*）是资源分支，二者都不是下载记录
```

---

📌 **版权与引用声明**

本文为 DigiForensics 独立创作的知识条目，采用 [知识共享 署名-相同方式共享 4.0 国际](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 许可协议发布。

- **署名**：引用本文时请注明「DigiForensics Wiki — macOS 取证 — Quarantine 与 Gatekeeper」
- **相同方式共享**：衍生作品须采用相同协议发布

示例：`本文内容参考自 DigiForensics Wiki《Quarantine 与 Gatekeeper》（CC BY-SA 4.0）`

文中 `DigiForensics.dd`、`DigiForensics-mem.raw` 等均为示例证据文件名，指向虚构或已脱敏的检材，与真实案件无关。
